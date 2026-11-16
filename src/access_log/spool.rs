//! The node's spool of access log records: files in its data dir
//! (`access-logs/`), appended to by a thread of their own, and delivered
//! (see `delivery`) once they're closed.
//!
//! Records reach the file with a `write` each batch, not through a buffer
//! of the process, and aren't synced: so they survive Cairn's crash or
//! restart, but not the machine's, which S3's best-effort delivery allows.
//! A request never waits for the spool: when it's behind (its queue full),
//! records are dropped.
//!
//! A file is `<millis>-<seq>.open` while it's written, and renamed to
//! `.closed` once it's old or large enough, or by the next process to start
//! if this one ended first. Each line is a record of one source bucket:
//! `<bucket>\t<seconds since the epoch>\t<record>\n` (see `Line`).

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// How many records may wait for the writer before more are dropped.
const QUEUE: usize = 64 * 1024;
/// The most bytes written at once.
const BATCH: usize = 1 << 20;

/// When a file is closed.
#[derive(Clone, Copy, Debug)]
pub struct Rotation {
    /// Once it's this old…
    pub age: Duration,
    /// …or this large.
    pub bytes: u64,
}

impl Default for Rotation {
    fn default() -> Rotation {
        Rotation { age: Duration::from_secs(300), bytes: 64 << 20 }
    }
}

/// Where a node's records go.
pub struct Spool {
    dir: PathBuf,
    queue: SyncSender<Vec<u8>>,
}

/// A spooled record.
#[derive(Debug, PartialEq)]
pub struct Line<'a> {
    pub bucket: &'a str,
    /// When its request was received, in seconds since the epoch.
    pub time: i64,
    pub record: &'a [u8],
}

impl Line<'_> {
    /// As the spool has it, line break included.
    pub fn encode(bucket: &str, time: SystemTime, record: &str) -> Vec<u8> {
        let secs = time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let mut out = Vec::with_capacity(bucket.len() + record.len() + 24);
        out.extend_from_slice(bucket.as_bytes());
        out.push(b'\t');
        out.extend_from_slice(secs.to_string().as_bytes());
        out.push(b'\t');
        out.extend_from_slice(record.as_bytes());
        out.push(b'\n');
        out
    }

    /// A file's lines, skipping any that aren't one (a line cut short by a
    /// crash, say).
    pub fn parse_all(data: &[u8]) -> impl Iterator<Item = Line<'_>> {
        data.split(|&b| b == b'\n').filter_map(Line::parse)
    }

    fn parse(line: &[u8]) -> Option<Line<'_>> {
        let mut fields = line.splitn(3, |&b| b == b'\t');
        let bucket = std::str::from_utf8(fields.next()?).ok()?;
        let time = std::str::from_utf8(fields.next()?).ok()?.parse().ok()?;
        let record = fields.next().filter(|r| !r.is_empty())?;
        (!bucket.is_empty()).then_some(Line { bucket, time, record })
    }
}

impl Spool {
    /// Starts the spool in `dir`: closes the files a previous process left
    /// open, and starts its writer.
    pub fn start(dir: PathBuf, rotation: Rotation) -> io::Result<Spool> {
        fs::create_dir_all(&dir)?;
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "open") {
                fs::rename(&path, path.with_extension("closed"))?;
            }
        }
        let (queue, records) = mpsc::sync_channel(QUEUE);
        let writing = dir.clone();
        std::thread::Builder::new()
            .name("access-log-spool".to_owned())
            .spawn(move || write(&writing, &records, rotation))?;
        Ok(Spool { dir, queue })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Spools a record (a line `Line::encode` made), unless the writer is
    /// behind.
    pub fn append(&self, line: Vec<u8>) {
        match self.queue.try_send(line) {
            Ok(()) | Err(TrySendError::Disconnected(_)) => {}
            Err(TrySendError::Full(_)) => complain(&format_args!("the spool is behind; dropping records")),
        }
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

    /// When a file of the spool was opened, by its name.
    pub fn opened(path: &Path) -> Option<SystemTime> {
        let millis = path.file_stem()?.to_str()?.split('-').next()?.parse().ok()?;
        Some(UNIX_EPOCH + Duration::from_millis(millis))
    }
}

/// Complains at most once a minute, so a full disk doesn't flood the log.
fn complain(what: &dyn std::fmt::Display) {
    static LAST: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
    if last.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
        *last = Some(Instant::now());
        eprintln!("access logs: {what}");
    }
}

/// The file being written.
struct Open {
    file: File,
    path: PathBuf,
    opened: Instant,
    written: u64,
}

impl Open {
    fn create(dir: &Path, seq: &mut u64) -> io::Result<Open> {
        let millis = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis());
        *seq += 1;
        let path = dir.join(format!("{millis:013}-{seq}.open"));
        let file = OpenOptions::new().append(true).create_new(true).open(&path)?;
        Ok(Open { file, path, opened: Instant::now(), written: 0 })
    }

    fn close(self) {
        drop(self.file);
        if let Err(e) = fs::rename(&self.path, self.path.with_extension("closed")) {
            complain(&format_args!("closing {}: {e}", self.path.display()));
        }
    }
}

/// The writer: appends what's queued, a batch a `write`, and closes files
/// as `rotation` says, until the spool is dropped.
fn write(dir: &Path, records: &Receiver<Vec<u8>>, rotation: Rotation) {
    let mut open: Option<Open> = None;
    let mut seq = 0;
    loop {
        match records.recv_timeout(Duration::from_secs(1)) {
            Ok(first) => {
                let mut batch = first;
                while batch.len() < BATCH {
                    match records.try_recv() {
                        Ok(more) => batch.extend_from_slice(&more),
                        Err(_) => break,
                    }
                }
                if open.is_none() {
                    match Open::create(dir, &mut seq) {
                        Ok(created) => open = Some(created),
                        Err(e) => complain(&format_args!("opening a spool file in {}: {e}", dir.display())),
                    }
                }
                if let Some(o) = open.as_mut() {
                    match o.file.write_all(&batch) {
                        Ok(()) => o.written += batch.len() as u64,
                        Err(e) => {
                            complain(&format_args!("writing {}: {e}", o.path.display()));
                            // What it has is delivered; the rest is lost.
                            open.take().expect("just written").close();
                        }
                    }
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
        if open.as_ref().is_some_and(|o| o.opened.elapsed() >= rotation.age || o.written >= rotation.bytes) {
            open.take().expect("just checked").close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_are_read_back() {
        let time = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let mut data = Line::encode("bucket", time, "a record");
        data.extend(Line::encode("other", time, "another\trecord"));
        // Cut short by a crash.
        data.extend_from_slice(b"bucket\t17000");
        let lines: Vec<Line> = Line::parse_all(&data).collect();
        assert_eq!(
            lines,
            [
                Line { bucket: "bucket", time: 1_700_000_000, record: b"a record" },
                Line { bucket: "other", time: 1_700_000_000, record: b"another\trecord" },
            ]
        );
    }

    #[test]
    fn files_are_closed_when_old_and_by_the_next_process() {
        let dir = std::env::temp_dir().join(format!("cairn-spool-{}", uuid::Uuid::new_v4()));
        let rotation = Rotation { age: Duration::from_millis(1), bytes: u64::MAX };
        let spool = Spool::start(dir.clone(), rotation).unwrap();
        spool.append(Line::encode("bucket", SystemTime::now(), "one"));
        // Closed within a second or so of being written.
        let deadline = Instant::now() + Duration::from_secs(10);
        while Spool::closed(&dir).unwrap().is_empty() {
            assert!(Instant::now() < deadline, "the file wasn't closed");
            std::thread::sleep(Duration::from_millis(20));
        }
        let closed = Spool::closed(&dir).unwrap();
        let data = fs::read(&closed[0]).unwrap();
        let records: Vec<&[u8]> = Line::parse_all(&data).map(|l| l.record).collect();
        assert_eq!(records, [b"one".as_slice()]);
        assert!(Spool::opened(&closed[0]).unwrap() <= SystemTime::now());
        drop(spool);

        // One left open, as by a crash, is closed by the next start.
        fs::write(dir.join("0000000000001-1.open"), b"").unwrap();
        let _spool = Spool::start(dir.clone(), Rotation::default()).unwrap();
        assert!(dir.join("0000000000001-1.closed").exists());
        fs::remove_dir_all(&dir).unwrap();
    }
}
