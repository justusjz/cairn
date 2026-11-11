//! Scrubbing: checking stored data against its checksums in the background,
//! before a client finds it damaged.
//!
//! Every node checks its own copies, the blobs the catalog places on it,
//! reading its local files only: intact data costs no network traffic, and no
//! coordination. A copy is checked as a whole: its identity (length and blob
//! ID, as reads check it), every block against the checksum table, and the
//! CRC64/NVME of the whole file against the catalog's. The last one is in the
//! catalog rather than the file, so it also catches a file that's wrong but
//! consistent with its own table, which only a bug would write.
//!
//! The scrubber reads at a fixed rate (`--scrub-rate`), copies that have gone
//! unchecked longest first, as `blob_locations.checked_at` orders them: set
//! when a replica writes its copy, and by every check. It doesn't check a copy
//! again within [`MIN_INTERVAL`]. So a node checks everything it holds every
//! held bytes / rate, or every week if that's shorter. A read that finds a
//! copy damaged or missing flags it (`suspect`), and the copy's node checks it
//! next.
//!
//! What it finds goes to `scrub_findings`, and to the log as `CORRUPTION:`.
//! Repairing is yet to come. Blobs from before checksums can't be checked, and
//! are skipped.

use std::{
    fs::File,
    io,
    os::unix::fs::FileExt,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crc32c::crc32c;
use uuid::Uuid;

use crate::db::Cached;
use crate::{App, checksum::BlockLayout};

/// The least time between two checks of a copy. A node that holds little
/// would otherwise reread all of it every few hours, for nothing.
pub const MIN_INTERVAL: Duration = Duration::from_secs(7 * 24 * 3600);
/// How long the scrubber waits before looking again once nothing is due.
const IDLE: Duration = Duration::from_secs(60);
/// How many copies the scrubber takes from the catalog at a time.
const BATCH: i64 = 64;
/// How much of a file is read at once, at least: the blocks it holds are
/// checked together.
const CHUNK: u64 = 1024 * 1024;
/// How much reading time the pacer saves up while the scrubber has nothing to
/// read, to read in a burst after.
const BURST: Duration = Duration::from_secs(1);
/// Resolved findings are dropped after this long.
const KEEP_FINDINGS_DAYS: i32 = 90;

/// Parses a rate in bytes per second: a number, optionally with a unit (`B`,
/// `KB`, `MB`, `GB`, `TB` in powers of 1000, `KiB`, `MiB`, `GiB`, `TiB` in
/// powers of 1024; any case) and `/s`. `0` turns scrubbing off.
pub fn parse_rate(s: &str) -> Result<u64, String> {
    let lower = s.trim().to_ascii_lowercase();
    let lower = lower.strip_suffix("/s").unwrap_or(&lower).trim_end();
    let split = lower
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(lower.len());
    let (number, unit) = lower.split_at(split);
    let number: f64 = number
        .parse()
        .map_err(|_| format!("{s:?} isn't a rate, such as 25MiB"))?;
    let unit: u64 = match unit.trim() {
        "" | "b" => 1,
        "kb" => 1000,
        "mb" => 1000 * 1000,
        "gb" => 1000 * 1000 * 1000,
        "tb" => 1000 * 1000 * 1000 * 1000,
        "kib" => 1 << 10,
        "mib" => 1 << 20,
        "gib" => 1 << 30,
        "tib" => 1 << 40,
        other => return Err(format!("unknown unit {other:?} in {s:?}; use B, KiB, MiB, GiB, ...")),
    };
    Ok((number * unit as f64).round() as u64)
}

/// Spaces reads out to a rate. Shared by the reads of a pass, which run on
/// blocking threads.
pub struct Pacer {
    /// Bytes per second; `None` for as fast as the disk goes.
    rate: Option<u64>,
    /// When the reads so far are paid for: reading may go on once it's past.
    next: Instant,
}

impl Pacer {
    pub fn new(rate: Option<u64>) -> Arc<Mutex<Pacer>> {
        let now = Instant::now();
        Arc::new(Mutex::new(Pacer {
            rate,
            next: now.checked_sub(BURST).unwrap_or(now),
        }))
    }

    /// Accounts for reading `bytes`; how long to wait before reading them.
    fn delay(&mut self, bytes: u64) -> Duration {
        let Some(rate) = self.rate.filter(|&r| r > 0) else {
            return Duration::ZERO;
        };
        let now = Instant::now();
        if let Some(earliest) = now.checked_sub(BURST)
            && self.next < earliest
        {
            self.next = earliest;
        }
        self.next += Duration::from_secs_f64(bytes as f64 / rate as f64);
        self.next.saturating_duration_since(now)
    }
}

/// Waits until `bytes` may be read.
fn pace(pacer: &Mutex<Pacer>, bytes: u64) {
    let delay = pacer.lock().unwrap().delay(bytes);
    if !delay.is_zero() {
        std::thread::sleep(delay);
    }
}

/// Which copies a pass checks.
#[derive(Clone, Copy, Debug)]
pub enum Scope {
    /// Those not checked within `MIN_INTERVAL`, and those reads flagged.
    Due,
    /// All of them, once.
    Everything,
}

/// A copy of a blob on this node, to check.
struct Copy {
    blob_id: Uuid,
    /// `None` for a blob from before checksums.
    layout: Option<BlockLayout>,
    /// The catalog's CRC64/NVME of the whole file.
    crc: Option<u64>,
    /// `checked_at` as the pass found it, in seconds since the epoch (NULL,
    /// or -infinity for a copy a read flagged), so that recording the check
    /// doesn't overwrite a flag that a read set meanwhile.
    checked_at: Option<f64>,
}

/// What checking a copy found.
#[derive(Debug, PartialEq)]
pub enum Verdict {
    Intact,
    /// A blob from before checksums, which can't be checked.
    Legacy,
    /// The catalog places the blob here, but there's no file.
    Missing,
    Damaged {
        /// The blocks that failed; `None` if the whole file is at fault.
        bad_blocks: Option<Vec<i64>>,
        detail: String,
    },
}

/// What a pass checked, and found.
#[derive(Default, Debug)]
pub struct Report {
    pub copies: u64,
    pub bytes: u64,
    pub damaged: u64,
    pub missing: u64,
    pub legacy: u64,
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "checked {} copies ({} bytes): {} damaged, {} missing; skipped {} from before checksums",
            self.copies, self.bytes, self.damaged, self.missing, self.legacy
        )
    }
}

/// The background scrubber: checks this node's due copies at `app.scrub_rate`,
/// for as long as the node runs. Does nothing if the rate is 0.
pub async fn run(app: Arc<App>) {
    if app.scrub_rate == 0 {
        eprintln!("scrub: off (--scrub-rate 0)");
        return;
    }
    let pacer = Pacer::new(Some(app.scrub_rate));
    loop {
        let (task_app, task_pacer) = (app.clone(), pacer.clone());
        // A task of its own, so that a panic (a bug) fails this pass, rather
        // than ending scrubbing on this node.
        let result = tokio::spawn(async move {
            let result = pass(&task_app, Scope::Due, &task_pacer).await;
            tidy_findings(&task_app).await?;
            result
        })
        .await;
        let failure = match result {
            Ok(Ok(_)) => None,
            Ok(Err(e)) => Some(format!("{e:#}")),
            Err(e) => Some(e.to_string()),
        };
        if let Some(e) = failure {
            eprintln!("scrub: pass failed: {e}");
            app.metrics.scrub_failed(format!("pass failed: {e}"));
        }
        tokio::time::sleep(IDLE).await;
    }
}

/// Checks the copies of `scope` on this node, records what it finds, and
/// returns once there are none left that were due when it started.
pub async fn pass(app: &Arc<App>, scope: Scope, pacer: &Arc<Mutex<Pacer>>) -> anyhow::Result<Report> {
    let client = app.pool.get().await?;
    // Due are the copies last checked before `until`: all before the pass
    // started, or a week before. A copy the pass checks gets a later time
    // than that, so it isn't taken twice.
    let started: f64 = client
        .query_one_cached("SELECT extract(epoch FROM NOW())::float8", &[])
        .await?
        .get(0);
    let until = match scope {
        Scope::Due => started - MIN_INTERVAL.as_secs_f64(),
        Scope::Everything => started,
    };
    drop(client);
    let mut report = Report::default();
    loop {
        let (now, copies) = due(app, until).await?;
        if copies.is_empty() {
            return Ok(report);
        }
        for copy in copies {
            let verdict = check(app, &copy, pacer).await?;
            record(app, &copy, now, &verdict, &mut report).await?;
        }
    }
}

/// The next batch of due copies on this node: first those reads flagged,
/// then those last checked before `until`, least recently checked first.
/// Also returns the time the batch was taken, which is what the checks
/// record: the copies are known intact as of then (at the latest).
async fn due(app: &App, until: f64) -> anyhow::Result<(f64, Vec<Copy>)> {
    let client = app.pool.get().await?;
    let select = "SELECT bl.blob_id, b.size, b.block_size, b.crc64nvme,
                         extract(epoch FROM bl.checked_at)::float8,
                         extract(epoch FROM NOW())::float8
                  FROM blob_locations bl JOIN blobs b ON b.blob_id = bl.blob_id";
    // Two queries, so that each reads the index in order: flagged copies
    // would otherwise wait behind those never checked.
    let mut rows = client
        .query_cached(
            &format!(
                "{select} WHERE bl.node = $1 AND bl.checked_at = '-infinity'
                   AND b.state = 'committed'
                 LIMIT $2"
            ),
            &[&app.node, &BATCH],
        )
        .await?;
    if rows.is_empty() {
        rows = client
            .query_cached(
                &format!(
                    "{select} WHERE bl.node = $1
                       AND (bl.checked_at IS NULL OR bl.checked_at < to_timestamp($2))
                       AND b.state = 'committed'
                     ORDER BY bl.checked_at NULLS FIRST
                     LIMIT $3"
                ),
                &[&app.node, &until, &BATCH],
            )
            .await?;
    }
    let now = rows.first().map_or(0.0, |r| r.get(5));
    let copies = rows
        .iter()
        .map(|r| Copy {
            blob_id: r.get(0),
            layout: r.get::<_, Option<i32>>(2).map(|block_size| BlockLayout {
                block_size: block_size as u64,
                blob_size: r.get::<_, i64>(1) as u64,
            }),
            crc: r.get::<_, Option<i64>>(3).map(|crc| crc as u64),
            checked_at: r.get(4),
        })
        .collect();
    Ok((now, copies))
}

/// Checks this node's copy of a blob.
async fn check(app: &App, copy: &Copy, pacer: &Arc<Mutex<Pacer>>) -> anyhow::Result<Verdict> {
    let (Some(layout), Some(crc)) = (copy.layout, copy.crc) else {
        return Ok(Verdict::Legacy);
    };
    let path = app.store.blob_path(copy.blob_id);
    let (blob_id, pacer) = (copy.blob_id, pacer.clone());
    Ok(tokio::task::spawn_blocking(move || check_file(path, blob_id, layout, crc, &pacer)).await?)
}

/// Checks a blob file against what the catalog says of it: its layout and
/// its CRC64/NVME. Reads at the pacer's rate, from the disk rather than the
/// page cache. Any I/O error is damage too: the copy can't be read.
pub fn check_file(
    path: PathBuf,
    blob_id: Uuid,
    layout: BlockLayout,
    crc: u64,
    pacer: &Mutex<Pacer>,
) -> Verdict {
    let whole = |detail: String| Verdict::Damaged {
        bad_blocks: None,
        detail,
    };
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Verdict::Missing,
        Err(e) => return whole(format!("can't open the file: {e}")),
    };
    // Whatever of the file is cached would be checked instead of the disk.
    drop_cached(&file, 0, 0);
    let BlockLayout {
        block_size,
        blob_size,
    } = layout;
    let blocks = blob_size.div_ceil(block_size);
    let expected_len = blob_size + 4 * blocks + 16;
    match file.metadata() {
        Ok(m) if m.len() == expected_len => {}
        Ok(m) => {
            return whole(format!(
                "the file is {} bytes long, not {expected_len}",
                m.len()
            ));
        }
        Err(e) => return whole(format!("can't stat the file: {e}")),
    }
    let mut trailer = vec![0u8; (4 * blocks + 16) as usize];
    if let Err(e) = file.read_exact_at(&mut trailer, blob_size) {
        return whole(format!("can't read the checksum table: {e}"));
    }
    let (table, id) = trailer.split_at(4 * blocks as usize);
    if id != blob_id.as_bytes() {
        return whole("the file ends in another blob's ID".to_owned());
    }

    let mut digest = crc64fast_nvme::Digest::new();
    let mut bad: Vec<i64> = Vec::new();
    let mut first_error = None;
    let chunk = block_size * CHUNK.div_ceil(block_size);
    let mut buf = vec![0u8; chunk as usize];
    let mut offset = 0;
    while offset < blob_size {
        let len = chunk.min(blob_size - offset);
        pace(pacer, len);
        let data = &mut buf[..len as usize];
        let whole_read = file.read_exact_at(data, offset);
        for (i, start) in (offset..offset + len).step_by(block_size as usize).enumerate() {
            let block = start / block_size;
            let at = i * block_size as usize;
            let block_len = layout.block_len(start) as usize;
            let intact = match &whole_read {
                Ok(()) => true,
                // Find out which of the chunk's blocks can't be read.
                Err(_) => match file.read_exact_at(&mut data[at..at + block_len], start) {
                    Ok(()) => true,
                    Err(e) => {
                        first_error.get_or_insert_with(|| format!("{e} at offset {start}"));
                        false
                    }
                },
            };
            let expected = &table[4 * block as usize..4 * block as usize + 4];
            if !intact || crc32c(&data[at..at + block_len]).to_be_bytes() != expected {
                bad.push(block as i64);
            }
        }
        digest.write(data);
        // Leave the page cache to the data clients read.
        drop_cached(&file, offset, len);
        offset += len;
    }
    if let Some(&first) = bad.first() {
        let mut detail = format!(
            "{} of {blocks} blocks failed their checksums, the first at offset {}",
            bad.len(),
            first as u64 * block_size
        );
        if let Some(e) = first_error {
            detail.push_str(&format!(" (read error: {e})"));
        }
        return Verdict::Damaged {
            bad_blocks: Some(bad),
            detail,
        };
    }
    digest.write(&trailer);
    let actual = digest.sum64();
    if actual != crc {
        return whole(format!(
            "every block is intact, but the file's CRC64/NVME is {actual:016x}, not {crc:016x}"
        ));
    }
    Verdict::Intact
}

/// Drops the clean cached pages of a range of `file` (all of it, with
/// `len` 0). Best effort: it only affects what gets read from where.
fn drop_cached(file: &File, offset: u64, len: u64) {
    use std::os::fd::AsRawFd;
    // SAFETY: posix_fadvise takes no pointers, and the fd is open.
    unsafe {
        libc::posix_fadvise(
            file.as_raw_fd(),
            offset as libc::off_t,
            len as libc::off_t,
            libc::POSIX_FADV_DONTNEED,
        );
    }
}

/// Records what checking a copy found, as of `now`: that the copy was
/// checked, and what's wrong with it, if anything. Nothing is recorded if
/// the copy changed since the pass found it: if its location is gone (the
/// blob was deleted, and with it its file, so it's no wonder it's missing),
/// or a read flagged it meanwhile (then it's checked again next).
async fn record(
    app: &App,
    copy: &Copy,
    now: f64,
    verdict: &Verdict,
    report: &mut Report,
) -> anyhow::Result<()> {
    let client = app.pool.get().await?;
    // The location as the pass found it, marked checked.
    let checked = "UPDATE blob_locations SET checked_at = to_timestamp($3)
                   WHERE blob_id = $1 AND node = $2
                     AND extract(epoch FROM checked_at)::float8 IS NOT DISTINCT FROM $4::float8
                   RETURNING blob_id, node";
    let bytes = copy.layout.map_or(0, |l| l.blob_size);
    let (problem, bad_blocks, detail) = match verdict {
        Verdict::Intact | Verdict::Legacy => {
            // Intact again: whatever was found before has been put right.
            client
                .execute_cached(
                    &format!(
                        "WITH checked AS ({checked})
                         UPDATE scrub_findings f SET outcome = 'repaired', resolved_at = NOW()
                         FROM checked
                         WHERE f.blob_id = checked.blob_id AND f.node = checked.node
                           AND f.resolved_at IS NULL"
                    ),
                    &[&copy.blob_id, &app.node, &now, &copy.checked_at],
                )
                .await?;
            if *verdict == Verdict::Legacy {
                report.legacy += 1;
            } else {
                report.copies += 1;
                report.bytes += bytes;
                app.metrics.scrub_checked(bytes, None);
            }
            return Ok(());
        }
        Verdict::Missing => ("missing", None, "the file is missing".to_owned()),
        Verdict::Damaged { bad_blocks, detail } => ("damaged", bad_blocks.clone(), detail.clone()),
    };
    let recorded = client
        .query_cached(
            &format!(
                "WITH checked AS ({checked})
                 INSERT INTO scrub_findings (blob_id, node, found_at, problem, bad_blocks, detail)
                 SELECT blob_id, node, NOW(), $5, $6, $7 FROM checked
                 ON CONFLICT (blob_id, node) WHERE resolved_at IS NULL DO UPDATE
                     SET problem = EXCLUDED.problem, bad_blocks = EXCLUDED.bad_blocks,
                         detail = EXCLUDED.detail
                 RETURNING id"
            ),
            &[
                &copy.blob_id,
                &app.node,
                &now,
                &copy.checked_at,
                &problem,
                &bad_blocks,
                &detail,
            ],
        )
        .await?;
    if recorded.is_empty() {
        return Ok(());
    }
    report.copies += 1;
    report.bytes += bytes;
    match verdict {
        Verdict::Missing => report.missing += 1,
        _ => report.damaged += 1,
    }
    let message = format!("blob {} on node {} (scrub): {detail}", copy.blob_id, app.node);
    eprintln!("CORRUPTION: {message}");
    app.metrics.scrub_checked(bytes, Some(message));
    Ok(())
}

/// Resolves the open findings of this node whose copies are gone (their blob
/// deleted), and drops findings resolved long ago.
async fn tidy_findings(app: &App) -> anyhow::Result<()> {
    let client = app.pool.get().await?;
    client
        .execute_cached(
            "UPDATE scrub_findings f SET outcome = 'gone', resolved_at = NOW()
             WHERE f.node = $1 AND f.resolved_at IS NULL
               AND NOT EXISTS (SELECT 1 FROM blob_locations bl
                               WHERE bl.blob_id = f.blob_id AND bl.node = f.node)",
            &[&app.node],
        )
        .await?;
    client
        .execute_cached(
            "DELETE FROM scrub_findings
             WHERE resolved_at < NOW() - make_interval(days => $1)",
            &[&KEEP_FINDINGS_DAYS],
        )
        .await?;
    Ok(())
}

/// Flags a copy that a read found damaged or missing, so that its node
/// checks it next. In the background: the read mustn't wait for it. A copy
/// already known to be damaged isn't flagged again, or every read of it would
/// have it checked again.
pub fn suspect(app: &App, blob_id: Uuid, node: i32) {
    let pool = app.pool.clone();
    tokio::spawn(async move {
        let result = async {
            pool.get()
                .await?
                .execute_cached(
                    "UPDATE blob_locations SET checked_at = '-infinity'
                     WHERE blob_id = $1 AND node = $2
                       AND checked_at IS DISTINCT FROM '-infinity'
                       AND NOT EXISTS (SELECT 1 FROM scrub_findings f
                                       WHERE f.blob_id = $1 AND f.node = $2
                                         AND f.resolved_at IS NULL)",
                    &[&blob_id, &node],
                )
                .await?;
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = result {
            eprintln!("flagging blob {blob_id} on node {node} for a scrub failed: {e:#}");
        }
    });
}

#[cfg(test)]
mod e2e;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates() {
        assert_eq!(parse_rate("25MiB"), Ok(25 << 20));
        assert_eq!(parse_rate("25 MiB/s"), Ok(25 << 20));
        assert_eq!(parse_rate("100mb"), Ok(100_000_000));
        assert_eq!(parse_rate("1.5GiB"), Ok(3 << 29));
        assert_eq!(parse_rate("4096"), Ok(4096));
        assert_eq!(parse_rate("0"), Ok(0));
        assert!(parse_rate("fast").is_err());
        assert!(parse_rate("25 furlongs").is_err());
    }

    #[test]
    fn the_pacer_keeps_to_the_rate() {
        let pacer = Pacer::new(Some(1000));
        let mut pacer = pacer.lock().unwrap();
        // A second's worth may go at once, saved up; then it's paced.
        assert!(pacer.delay(500) < Duration::from_millis(100));
        let waited: Duration = (0..10).map(|_| pacer.delay(500)).max().unwrap();
        assert!(waited > Duration::from_secs(3), "{waited:?}");
        let unpaced = Pacer::new(None);
        assert_eq!(unpaced.lock().unwrap().delay(u64::MAX), Duration::ZERO);
    }

    fn write(path: &std::path::Path, id: Uuid, data: &[u8], bs: u32) -> u64 {
        let mut summer = crate::checksum::BlobSummer::new(bs);
        summer.update(data);
        let mut bytes = data.to_vec();
        bytes.extend(crate::blob_file::trailer(id, &summer.finish()));
        std::fs::write(path, &bytes).unwrap();
        let mut digest = crc64fast_nvme::Digest::new();
        digest.write(&bytes);
        digest.sum64()
    }

    #[test]
    fn checks_files() {
        let dir = std::env::temp_dir().join(format!("cairn-scrub-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("blob");
        let id = Uuid::now_v7();
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
        let layout = BlockLayout {
            block_size: 256,
            blob_size: 1000,
        };
        let crc = write(&path, id, &data, 256);
        let pacer = Pacer::new(None);
        let check = |crc| check_file(path.clone(), id, layout, crc, &pacer);
        assert_eq!(check(crc), Verdict::Intact);
        assert!(matches!(
            check(crc ^ 1),
            Verdict::Damaged { bad_blocks: None, .. }
        ));

        // A flipped bit in data, and one in the table: each fails its block.
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[300] ^= 1;
        bytes[1000 + 4 * 3] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        let Verdict::Damaged { bad_blocks, .. } = check(crc) else {
            panic!("not damaged")
        };
        assert_eq!(bad_blocks, Some(vec![1, 3]));

        // The wrong length, or another blob's ID: the whole file.
        std::fs::write(&path, &bytes[..bytes.len() - 1]).unwrap();
        assert!(matches!(check(crc), Verdict::Damaged { bad_blocks: None, .. }));
        write(&path, Uuid::now_v7(), &data, 256);
        let Verdict::Damaged { bad_blocks, detail } = check(crc) else {
            panic!("not damaged")
        };
        assert_eq!(bad_blocks, None);
        assert!(detail.contains("another blob's ID"), "{detail}");

        std::fs::remove_file(&path).unwrap();
        assert_eq!(check(crc), Verdict::Missing);

        // An empty blob is just its ID.
        let crc = write(&path, id, &[], 256);
        let empty = BlockLayout {
            block_size: 256,
            blob_size: 0,
        };
        assert_eq!(check_file(path.clone(), id, empty, crc, &pacer), Verdict::Intact);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
