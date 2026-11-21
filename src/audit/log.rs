//! The node's audit log: files in its data dir (`audit/`), appended to by
//! a thread of their own, and shipped (see `ship`) once they're closed.
//!
//! Unlike the access logs' spool, an append is durable before it returns:
//! the writer group-commits, writing what's queued and then `fdatasync`ing
//! the file once for all of it, and only then answers each append. So a
//! request that waits for its record (see `Audit::record`) is answered only
//! once the record survives the machine's crash, at the cost of a sync
//! shared by every request in its batch. An append that the writer can't
//! make durable fails; nothing is dropped silently, and a request never
//! waits on a full queue for long: it waits its turn, as the writer drains
//! the queue.
//!
//! A file is `<millis>-<seq>-<nonce>.open` while it's written (`nonce` is
//! the process's, so that two processes' files never share a name), and
//! renamed to `.closed` once it's a few seconds old or large enough, or by
//! the next process to start if this one ended first. A file that failed
//! to write or sync is cut back to what was synced, and closed: what's
//! past that, its appends were told failed. Each line is a record (see
//! `Line`).

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tokio::sync::oneshot;

/// How many appends may wait for the writer before more wait to be queued.
const QUEUE: usize = 16 * 1024;
/// The most bytes written (and synced) at once.
const BATCH: usize = 4 << 20;
/// How often the writer looks at whether its file is old enough to close.
const TICK: Duration = Duration::from_millis(250);

/// When a file is closed.
#[derive(Clone, Copy, Debug)]
pub struct Rotation {
    /// Once it's this old…
    pub age: Duration,
    /// …or this large.
    pub bytes: u64,
}

impl Default for Rotation {
    /// A few seconds, so that records reach the cluster's storage soon.
    fn default() -> Rotation {
        Rotation {
            age: Duration::from_secs(5),
            bytes: 64 << 20,
        }
    }
}

/// Why a record wasn't made durable.
#[derive(Clone, Debug, PartialEq)]
pub struct Failed(pub String);

impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the audit log can't record it: {}", self.0)
    }
}

impl std::error::Error for Failed {}

/// What a record is: an intent, written before a request that changes
/// something does it, or an event, written once a request is done.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Intent,
    Event,
}

impl Kind {
    fn tag(self) -> u8 {
        match self {
            Kind::Intent => b'I',
            Kind::Event => b'E',
        }
    }
}

/// A logged record: its kind, and the event (CloudTrail's JSON record).
#[derive(Debug, PartialEq)]
pub struct Line<'a> {
    pub kind: Kind,
    pub record: &'a [u8],
}

impl Line<'_> {
    /// As the log has it: `I` or `E`, a tab, the record (JSON, which has no
    /// line breaks of its own), and a line break.
    pub fn encode(kind: Kind, record: &str) -> Vec<u8> {
        debug_assert!(!record.contains('\n'));
        let mut out = Vec::with_capacity(record.len() + 3);
        out.push(kind.tag());
        out.push(b'\t');
        out.extend_from_slice(record.as_bytes());
        out.push(b'\n');
        out
    }

    /// A file's lines, skipping any that aren't one (a line cut short by a
    /// crash, say).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn parse_all(data: &[u8]) -> impl Iterator<Item = Line<'_>> {
        data.split(|&b| b == b'\n').filter_map(Line::parse)
    }

    fn parse(line: &[u8]) -> Option<Line<'_>> {
        let (kind, record) = match line {
            [b'I', b'\t', record @ ..] => (Kind::Intent, record),
            [b'E', b'\t', record @ ..] => (Kind::Event, record),
            _ => return None,
        };
        // A line cut short isn't JSON: its object isn't closed.
        (record.first() == Some(&b'{') && record.last() == Some(&b'}'))
            .then_some(Line { kind, record })
    }
}

/// An append, and who's waiting for it.
struct Entry {
    line: Vec<u8>,
    done: oneshot::Sender<Result<(), Failed>>,
}

/// Where a node's records go.
pub struct Log {
    dir: PathBuf,
    queue: SyncSender<Entry>,
}

impl Log {
    /// Starts the log in `dir`: closes the files a previous process left
    /// open, and starts its writer.
    pub fn start(dir: PathBuf, rotation: Rotation) -> io::Result<Log> {
        fs::create_dir_all(&dir)?;
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "open") {
                fs::rename(&path, path.with_extension("closed"))?;
            }
        }
        sync_dir(&dir)?;
        let mut nonce = [0u8; 4];
        getrandom::fill(&mut nonce).expect("the OS random number generator failed");
        let nonce: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let (queue, entries) = mpsc::sync_channel(QUEUE);
        let writing = dir.clone();
        std::thread::Builder::new()
            .name("audit-log".to_owned())
            .spawn(move || write(&writing, &nonce, &entries, rotation))?;
        Ok(Log { dir, queue })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Appends a line (one `Line::encode` made), once it's durable.
    pub async fn append(&self, line: Vec<u8>) -> Result<(), Failed> {
        let stopped = || Failed("its writer has stopped".to_owned());
        let (done, answer) = oneshot::channel();
        match self.queue.try_send(Entry { line, done }) {
            Ok(()) => {}
            Err(TrySendError::Full(entry)) => {
                // Behind: wait for room, off the runtime's threads.
                let queue = self.queue.clone();
                tokio::task::spawn_blocking(move || queue.send(entry))
                    .await
                    .map_err(|_| stopped())?
                    .map_err(|_| stopped())?;
            }
            Err(TrySendError::Disconnected(_)) => return Err(stopped()),
        }
        answer.await.unwrap_or_else(|_| Err(stopped()))
    }

    /// The closed files, oldest first.
    pub fn closed(dir: &Path) -> io::Result<Vec<PathBuf>> {
        let mut files: Vec<PathBuf> = fs::read_dir(dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|e| e == "closed"))
            .collect();
        files.sort();
        Ok(files)
    }

    /// When a file of the log was opened, by its name.
    pub fn opened(path: &Path) -> Option<SystemTime> {
        let millis = path
            .file_stem()?
            .to_str()?
            .split('-')
            .next()?
            .parse()
            .ok()?;
        Some(UNIX_EPOCH + Duration::from_millis(millis))
    }
}

/// Makes a directory's entries (a file made or renamed in it) durable.
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Complains at most once a minute, so a failing disk doesn't flood the log.
fn complain(what: &dyn std::fmt::Display) {
    static LAST: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
    if last.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
        *last = Some(Instant::now());
        eprintln!("audit log: {what}");
    }
}

/// The file being written.
struct Open {
    file: File,
    path: PathBuf,
    opened: Instant,
    /// How much of it is synced.
    synced: u64,
}

impl Open {
    fn create(dir: &Path, nonce: &str, seq: &mut u64) -> io::Result<Open> {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        *seq += 1;
        let path = dir.join(format!("{millis:013}-{seq}-{nonce}.open"));
        let file = OpenOptions::new()
            .append(true)
            .create_new(true)
            .open(&path)?;
        // So that a crash doesn't lose the file, and what's synced in it.
        sync_dir(dir)?;
        Ok(Open {
            file,
            path,
            opened: Instant::now(),
            synced: 0,
        })
    }

    fn close(self) {
        drop(self.file);
        if let Err(e) = fs::rename(&self.path, self.path.with_extension("closed")) {
            complain(&format_args!("closing {}: {e}", self.path.display()));
        }
    }
}

/// The writer: appends what's queued, a batch a write and a sync, answers
/// the batch's appends, and closes files as `rotation` says, until the log
/// is dropped.
fn write(dir: &Path, nonce: &str, entries: &Receiver<Entry>, rotation: Rotation) {
    let mut open: Option<Open> = None;
    let mut seq = 0;
    loop {
        match entries.recv_timeout(TICK) {
            Ok(first) => {
                let mut bytes = first.line.len();
                let mut batch = vec![first];
                while bytes < BATCH {
                    match entries.try_recv() {
                        Ok(more) => {
                            bytes += more.line.len();
                            batch.push(more);
                        }
                        Err(_) => break,
                    }
                }
                let result = append_batch(dir, nonce, &mut open, &mut seq, &batch);
                if let Err(e) = &result {
                    complain(e);
                }
                for entry in batch {
                    let _ = entry.done.send(result.clone());
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                if let Some(o) = open.take() {
                    o.close();
                }
                return;
            }
        }
        if open
            .as_ref()
            .is_some_and(|o| o.opened.elapsed() >= rotation.age || o.synced >= rotation.bytes)
        {
            open.take().expect("just checked").close();
        }
    }
}

/// Writes and syncs `batch` to the open file (opening one if there's none).
fn append_batch(
    dir: &Path,
    nonce: &str,
    open: &mut Option<Open>,
    seq: &mut u64,
    batch: &[Entry],
) -> Result<(), Failed> {
    if open.is_none() {
        let created = Open::create(dir, nonce, seq)
            .map_err(|e| Failed(format!("opening a file in {}: {e}", dir.display())))?;
        *open = Some(created);
    }
    let o = open.as_mut().expect("just opened");
    let data: Vec<u8> = batch.iter().flat_map(|e| e.line.iter().copied()).collect();
    match o.file.write_all(&data).and_then(|()| o.file.sync_data()) {
        Ok(()) => {
            o.synced += data.len() as u64;
            Ok(())
        }
        Err(e) => {
            // What's past the synced part may or may not be there, and a
            // failed sync may have lost it: cut it off, and go on in a new
            // file.
            let o = open.take().expect("just written");
            let why = format!("writing {}: {e}", o.path.display());
            let _ = o.file.set_len(o.synced).and_then(|()| o.file.sync_data());
            o.close();
            Err(Failed(why))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_are_read_back() {
        let mut data = Line::encode(Kind::Intent, r#"{"eventID":"1"}"#);
        data.extend(Line::encode(Kind::Event, r#"{"eventID":"1","a":"b\tc"}"#));
        // Cut short by a crash.
        data.extend_from_slice(br#"E	{"eventID":"2","#);
        let lines: Vec<Line> = Line::parse_all(&data).collect();
        assert_eq!(
            lines,
            [
                Line {
                    kind: Kind::Intent,
                    record: br#"{"eventID":"1"}"#
                },
                Line {
                    kind: Kind::Event,
                    record: br#"{"eventID":"1","a":"b\tc"}"#
                },
            ]
        );
    }

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("cairn-audit-{}", uuid::Uuid::new_v4()))
    }

    /// Appends are in the file once they return, many at once share a
    /// sync, and files are closed when they're old, and by the next
    /// process to start.
    #[tokio::test]
    async fn appends_are_durable_and_files_closed() {
        let dir = temp_dir();
        let rotation = Rotation {
            age: Duration::from_secs(3600),
            bytes: u64::MAX,
        };
        let log = std::sync::Arc::new(Log::start(dir.clone(), rotation).unwrap());
        let mut appends = tokio::task::JoinSet::new();
        for i in 0..200 {
            let log = log.clone();
            appends.spawn(async move {
                let line = Line::encode(Kind::Event, &format!(r#"{{"n":{i}}}"#));
                log.append(line).await
            });
        }
        while let Some(done) = appends.join_next().await {
            done.unwrap().unwrap();
        }
        // All in the open file, before it's closed.
        let open: Vec<PathBuf> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(open.len(), 1, "{open:?}");
        assert!(open[0].extension().is_some_and(|e| e == "open"));
        let data = fs::read(&open[0]).unwrap();
        assert_eq!(Line::parse_all(&data).count(), 200);
        drop(log);

        // The writer closes its file as it stops.
        let deadline = Instant::now() + Duration::from_secs(10);
        while Log::closed(&dir).unwrap().is_empty() {
            assert!(Instant::now() < deadline, "the writer didn't stop");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Left open, as by a crash: closed by the next start.
        let closed = Log::closed(&dir).unwrap().remove(0);
        fs::rename(&closed, &open[0]).unwrap();
        let log = Log::start(dir.clone(), Rotation::default()).unwrap();
        assert_eq!(Log::closed(&dir).unwrap(), std::slice::from_ref(&closed));
        assert!(Log::opened(&closed).unwrap() <= SystemTime::now());
        drop(log);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn old_files_are_closed() {
        let dir = temp_dir();
        let rotation = Rotation {
            age: Duration::from_millis(1),
            bytes: u64::MAX,
        };
        let log = Log::start(dir.clone(), rotation).unwrap();
        log.append(Line::encode(Kind::Event, "{}")).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Log::closed(&dir).unwrap().is_empty() {
            assert!(Instant::now() < deadline, "the file wasn't closed");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // The next append goes to a new file.
        log.append(Line::encode(Kind::Event, "{}")).await.unwrap();
        drop(log);
        // The writer may still be closing its file.
        let _ = fs::remove_dir_all(&dir);
    }

    /// An append that can't be made durable fails, rather than passing.
    #[tokio::test]
    async fn appends_fail_when_they_cant_be_written() {
        let dir = temp_dir();
        let log = Log::start(dir.clone(), Rotation::default()).unwrap();
        fs::remove_dir_all(&dir).unwrap();
        let failed = log.append(Line::encode(Kind::Event, "{}")).await;
        assert!(failed.is_err(), "{failed:?}");
    }
}
