//! Scrubbing: checking stored data against its checksums in the background,
//! before a client finds it damaged.
//!
//! Every node checks its own copies, the shards of blobs the catalog places
//! on it, reading its local files only: intact data costs no network
//! traffic, and no coordination. A copy is checked as a whole: its identity
//! (length, shard index and blob ID, as reads check it), every block of its
//! shard against the shard's checksum table, and the CRC64/NVME of the whole
//! file against the catalog's for its shard. The last one is in the catalog
//! rather than the file, so it also catches a file that's wrong but
//! consistent with its own table, which only a bug would write, and damage to
//! the other shards' tables, which a coded shard's file holds too.
//!
//! The scrubber reads at a fixed rate (`--scrub-rate`), copies that have gone
//! unchecked longest first, as `blob_locations.checked_at` orders them: set
//! when a replica writes its copy, and by every check. It doesn't check a copy
//! again within [`MIN_INTERVAL`]. So a node checks everything it holds every
//! held bytes / rate, or every week if that's shorter. A read that finds a
//! copy damaged or missing flags it (`suspect`), and the copy's node checks it
//! next.
//!
//! A damaged or missing copy is repaired from intact blocks: its own, and the
//! other shards' (see `repair`). Bytes of the blob that no shard can provide
//! intact are lost: their ranges go to `lost_ranges`, until some shard turns
//! out to hold them after all (a node that was down comes back, say), and the
//! others are then repaired from it. What the scrubber finds goes to `scrub_findings`, and to
//! the log as `CORRUPTION:`. Blobs from before checksums can't be checked, and
//! are skipped, until the packer upgrades them (see `packer`).

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
use crate::{
    App,
    blob_file::{self, ShardFile},
    blobs::{LAYOUT_COLUMNS, layout_at},
    shards::Layout,
};

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
/// How soon a copy is checked again when that may go better: its repair
/// failed, or the nodes that may hold its lost blocks were down.
const RETRY: Duration = Duration::from_secs(3600);
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

/// A copy of a blob's shard on this node, to check.
struct Copy {
    blob_id: Uuid,
    /// `None` for a blob from before checksums.
    layout: Option<Layout>,
    /// Which shard it is.
    shard: u32,
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
    /// Of the damaged and missing copies, those repaired, and those with
    /// blocks that are intact nowhere.
    pub repaired: u64,
    pub lost: u64,
    pub legacy: u64,
}

impl Copy {
    /// Its file, as the catalog describes it.
    fn file(&self) -> Option<ShardFile> {
        self.layout.map(|layout| ShardFile {
            blob_id: self.blob_id,
            layout,
            shard: self.shard,
        })
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "checked {} copies ({} bytes): {} damaged, {} missing, of which {} repaired, \
             {} with lost data; skipped {} from before checksums",
            self.copies,
            self.bytes,
            self.damaged,
            self.missing,
            self.repaired,
            self.lost,
            self.legacy
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
            let repaired = match (&verdict, copy.file(), copy.crc) {
                (Verdict::Missing, Some(file), Some(crc)) => {
                    Some(repair::repair(app, &file, crc, None, pacer).await)
                }
                (Verdict::Damaged { bad_blocks, .. }, Some(file), Some(crc)) => {
                    let bad = bad_blocks.as_deref();
                    Some(repair::repair(app, &file, crc, bad, pacer).await)
                }
                _ => None,
            };
            let repaired = repaired.map(|r| r.map_err(|e| format!("{e:#}")));
            record(app, &copy, now, scope, &verdict, repaired, &mut report).await?;
        }
    }
}

/// The next batch of due copies on this node: first those reads flagged,
/// then those last checked before `until`, least recently checked first.
/// Also returns the time the batch was taken, which is what the checks
/// record: the copies are known intact as of then (at the latest).
async fn due(app: &App, until: f64) -> anyhow::Result<(f64, Vec<Copy>)> {
    let client = app.pool.get().await?;
    let select = format!(
        "SELECT bl.blob_id, bl.shard, b.shard_crcs[bl.shard + 1],
                extract(epoch FROM bl.checked_at)::float8,
                extract(epoch FROM NOW())::float8, {LAYOUT_COLUMNS}
         FROM blob_locations bl JOIN blobs b ON b.blob_id = bl.blob_id"
    );
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
    let now = rows.first().map_or(0.0, |r| r.get(4));
    let copies = rows
        .iter()
        .map(|r| Copy {
            blob_id: r.get(0),
            shard: r.get::<_, i16>(1) as u32,
            crc: r.get::<_, Option<i64>>(2).map(|crc| crc as u64),
            checked_at: r.get(3),
            layout: layout_at(r, 5),
        })
        .collect();
    Ok((now, copies))
}

/// Checks this node's copy of a blob's shard.
async fn check(app: &App, copy: &Copy, pacer: &Arc<Mutex<Pacer>>) -> anyhow::Result<Verdict> {
    let (Some(file), Some(crc)) = (copy.file(), copy.crc) else {
        return Ok(Verdict::Legacy);
    };
    let path = app.store.blob_path(copy.blob_id);
    let pacer = pacer.clone();
    Ok(tokio::task::spawn_blocking(move || check_file(path, &file, crc, &pacer)).await?)
}

/// Checks a shard file against what the catalog says of it: its layout and
/// its CRC64/NVME. Reads at the pacer's rate, from the disk rather than the
/// page cache. Any I/O error is damage too: the copy can't be read.
pub fn check_file(
    path: PathBuf,
    expected: &ShardFile,
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
    let layout = expected.blocks_of(expected.shard);
    let (block_size, blob_size) = (layout.block_size, layout.blob_size);
    let blocks = blob_size.div_ceil(block_size);
    let expected_len = expected.len();
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
    let mut trailer = vec![0u8; (expected_len - blob_size) as usize];
    if let Err(e) = file.read_exact_at(&mut trailer, blob_size) {
        return whole(format!("can't read the checksum tables: {e}"));
    }
    let Some((tables, tail)) = blob_file::split_trailer(expected, &trailer) else {
        return whole("the checksum tables don't fit the blob".to_owned());
    };
    if let Err(reason) = blob_file::check_tail(expected, tail) {
        return whole(reason.to_owned());
    }
    let table = tables[if expected.layout.replicated() { 0 } else { expected.shard as usize }];

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
        // No block of the shard's data is known bad: the damage is in the
        // rest of the file (another shard's table, in a coded shard's file),
        // or the file is wrong but consistent with its own table. The repair
        // keeps the data, and rebuilds the whole file only if that fails.
        return Verdict::Damaged {
            bad_blocks: Some(Vec::new()),
            detail: format!(
                "every block is intact, but the file's CRC64/NVME is {actual:016x}, not {crc:016x}"
            ),
        };
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
/// checked, what's wrong with it, if anything, and how its repair went.
/// Nothing is recorded if the copy changed since the pass found it: if its
/// location is gone (the blob was deleted, and with it its file, so it's no
/// wonder it's missing), or a read flagged it meanwhile (then it's checked
/// again next).
async fn record(
    app: &App,
    copy: &Copy,
    now: f64,
    scope: Scope,
    verdict: &Verdict,
    repaired: Option<Result<repair::Outcome, String>>,
    report: &mut Report,
) -> anyhow::Result<()> {
    let client = app.pool.get().await?;
    // The location as the pass found it, marked checked as of `$3`.
    let checked = "UPDATE blob_locations SET checked_at = to_timestamp($3)
                   WHERE blob_id = $1 AND node = $2
                     AND extract(epoch FROM checked_at)::float8 IS NOT DISTINCT FROM $4::float8
                   RETURNING blob_id, node";
    let bytes = copy.file().map_or(0, |f| f.data_len());
    let (problem, bad_blocks, detail) = match verdict {
        Verdict::Intact | Verdict::Legacy => {
            // Intact again: whatever was found before has been put right.
            let rows = client
                .query_cached(
                    &format!(
                        "WITH checked AS ({checked}),
                         resolved AS (
                             UPDATE scrub_findings f SET outcome = 'repaired', resolved_at = NOW()
                             FROM checked
                             WHERE f.blob_id = checked.blob_id AND f.node = checked.node
                               AND f.resolved_at IS NULL
                         )
                         SELECT 1 FROM checked"
                    ),
                    &[&copy.blob_id, &app.node, &now, &copy.checked_at],
                )
                .await?;
            drop(client);
            if *verdict == Verdict::Legacy {
                report.legacy += 1;
                return Ok(());
            }
            report.copies += 1;
            report.bytes += bytes;
            app.metrics.scrub_checked(bytes, None);
            if !rows.is_empty() {
                found_intact(app, copy).await?;
            }
            return Ok(());
        }
        Verdict::Missing => ("missing", None, "the file is missing".to_owned()),
        Verdict::Damaged { bad_blocks, detail } => ("damaged", bad_blocks.clone(), detail.clone()),
    };
    // What became of it. A retry comes within the hour, rather than in its
    // turn, when it may fare better then: when a repair failed, or nodes that
    // may hold the lost blocks are down. (Not in a pass over everything, which
    // would retry it right away.)
    let (problem, detail, outcome, resolved, retry, lost) = match &repaired {
        Some(Ok(repair::Outcome::Repaired)) => {
            (problem, format!("{detail}; repaired"), Some("repaired"), true, false, None)
        }
        Some(Ok(repair::Outcome::Lost {
            ranges,
            provisional,
        })) => {
            let bytes: i64 = ranges.iter().map(|(start, stop)| stop - start).sum();
            let mut detail = if ranges.is_empty() {
                format!("{detail}; some of it can't be rebuilt from the other shards")
            } else {
                format!("{detail}; {bytes} bytes of the blob can be read intact from no shard")
            };
            if *provisional {
                detail.push_str(" that's up");
            }
            (problem, detail, Some("lost"), false, *provisional, Some(ranges.as_slice()))
        }
        Some(Ok(repair::Outcome::Mismatch(mismatch))) => {
            ("catalog", format!("{detail}; {mismatch}"), None, false, false, None)
        }
        Some(Err(e)) => (problem, format!("{detail}; repair failed: {e}"), None, false, true, None),
        None => (problem, detail, None, false, false, None),
    };
    let checked_at = match scope {
        Scope::Due if retry => now - MIN_INTERVAL.as_secs_f64() + RETRY.as_secs_f64(),
        _ => now,
    };
    let recorded = client
        .query_cached(
            &format!(
                "WITH checked AS ({checked})
                 INSERT INTO scrub_findings
                     (blob_id, node, found_at, problem, bad_blocks, detail, outcome)
                 SELECT blob_id, node, NOW(), $5, $6, $7, $8 FROM checked
                 ON CONFLICT (blob_id, node) WHERE resolved_at IS NULL DO UPDATE
                     SET problem = EXCLUDED.problem, bad_blocks = EXCLUDED.bad_blocks,
                         detail = EXCLUDED.detail, outcome = EXCLUDED.outcome
                 RETURNING id"
            ),
            &[
                &copy.blob_id,
                &app.node,
                &checked_at,
                &copy.checked_at,
                &problem,
                &bad_blocks,
                &detail,
                &outcome,
            ],
        )
        .await?;
    let Some(finding) = recorded.first() else {
        return Ok(());
    };
    // Upserted open, then resolved, since a resolved row isn't in the
    // partial index that the upsert finds an open finding by.
    if resolved {
        client
            .execute_cached(
                "UPDATE scrub_findings SET resolved_at = NOW() WHERE id = $1",
                &[&finding.get::<_, i64>(0)],
            )
            .await?;
    }
    drop(client);
    report.copies += 1;
    report.bytes += bytes;
    match verdict {
        Verdict::Missing => report.missing += 1,
        _ => report.damaged += 1,
    }
    if resolved {
        report.repaired += 1;
        found_intact(app, copy).await?;
    }
    if let Some(ranges) = lost {
        report.lost += 1;
        match copy.layout {
            // Each data shard of a coded blob finds the losses in its own
            // cells, and only those.
            Some(layout) if !layout.replicated() => {
                set_lost_in_shard(app, copy.blob_id, layout, copy.shard, ranges).await?
            }
            _ => {
                set_lost(app, copy.blob_id, ranges).await?;
            }
        }
    }
    let message = format!("blob {} on node {} (scrub): {detail}", copy.blob_id, app.node);
    eprintln!("CORRUPTION: {message}");
    app.metrics.scrub_checked(bytes, Some(message));
    match outcome {
        Some("repaired") => app.metrics.scrub_repaired(),
        Some("lost") => app.metrics.scrub_lost(),
        _ => {}
    }
    Ok(())
}

/// Records that a shard of a blob is intact: whatever of the blob was lost
/// in it isn't. That's all of the lost bytes for a replicated blob, and those
/// in the shard's own cells for a coded one. Its other shards may have been
/// found damaged, but not repaired for want of intact blocks: they're
/// flagged, so that their nodes repair them next.
async fn found_intact(app: &App, copy: &Copy) -> anyhow::Result<()> {
    let blob_id = copy.blob_id;
    let client = app.pool.get().await?;
    let any = "SELECT EXISTS (SELECT 1 FROM lost_ranges WHERE blob_id = $1)";
    // Almost always nothing is lost: that's one cheap query.
    if !client.query_one_cached(any, &[&blob_id]).await?.get::<_, bool>(0) {
        return Ok(());
    }
    let Some(layout) = copy.layout.filter(|l| !l.replicated()) else {
        drop(client);
        if set_lost(app, blob_id, &[]).await? {
            app.pool
                .get()
                .await?
                .execute_cached(
                    "UPDATE blob_locations SET checked_at = '-infinity'
                     WHERE blob_id = $1 AND node <> $2",
                    &[&blob_id, &app.node],
                )
                .await?;
        }
        return Ok(());
    };
    // A coded blob's lost ranges each lie in one data cell (see `add_lost`).
    let rows = client
        .query_cached(
            "SELECT start, extract(epoch FROM found_at)::float8 FROM lost_ranges WHERE blob_id = $1",
            &[&blob_id],
        )
        .await?;
    drop(client);
    let newest = rows.iter().map(|r| r.get::<_, f64>(1)).fold(f64::MIN, f64::max);
    let ours: Vec<i64> = rows
        .iter()
        .map(|r| r.get::<_, i64>(0))
        .filter(|&start| layout.cell_at(start as u64).shard == copy.shard)
        .collect();
    drop_lost(app, blob_id, &ours).await?;
    // The others that haven't been checked since the newest loss was found
    // are checked next: they may be repaired now, or hold their lost cells
    // after all. Each is flagged once per loss, however often this runs.
    app.pool
        .get()
        .await?
        .execute_cached(
            "UPDATE blob_locations SET checked_at = '-infinity'
             WHERE blob_id = $1 AND node <> $2 AND checked_at IS DISTINCT FROM '-infinity'
               AND (checked_at IS NULL OR checked_at < to_timestamp($3))",
            &[&blob_id, &app.node, &newest],
        )
        .await?;
    Ok(())
}

/// Replaces the lost ranges of a coded blob in shard `shard`'s cells with
/// `ranges` (byte offsets of the blob, [start, stop), each in one of its
/// cells), leaving the other shards' alone: what the shard's repair found
/// lost now, which may be less than before (rows that couldn't be decoded
/// then can be now). Under the blob's row lock (X shared, see `catalog.sql`),
/// as `set_lost`.
async fn set_lost_in_shard(
    app: &App,
    blob_id: Uuid,
    layout: Layout,
    shard: u32,
    ranges: &[(i64, i64)],
) -> anyhow::Result<()> {
    let mut client = app.pool.get().await?;
    let tx = client.transaction().await?;
    let blob = tx
        .query_opt("SELECT 1 FROM blobs WHERE blob_id = $1 FOR KEY SHARE", &[&blob_id])
        .await?;
    if blob.is_none() {
        return Ok(());
    }
    let (starts, stops): (Vec<i64>, Vec<i64>) = ranges.iter().copied().unzip();
    let gone: Vec<i64> = tx
        .query("SELECT start FROM lost_ranges WHERE blob_id = $1", &[&blob_id])
        .await?
        .iter()
        .map(|r| r.get::<_, i64>(0))
        .filter(|&start| layout.cell_at(start as u64).shard == shard && !starts.contains(&start))
        .collect();
    tx.execute(
        "DELETE FROM lost_ranges WHERE blob_id = $1 AND start = ANY($2)",
        &[&blob_id, &gone],
    )
    .await?;
    tx.execute(
        "INSERT INTO lost_ranges (blob_id, start, stop, found_at)
         SELECT $1, s, e, NOW() FROM unnest($2::bigint[], $3::bigint[]) AS t(s, e)
         ON CONFLICT (blob_id, start) DO UPDATE SET stop = EXCLUDED.stop",
        &[&blob_id, &starts, &stops],
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Drops the lost ranges of a blob that start at `starts`. Under the blob's
/// row lock, as `set_lost`.
async fn drop_lost(app: &App, blob_id: Uuid, starts: &[i64]) -> anyhow::Result<()> {
    if starts.is_empty() {
        return Ok(());
    }
    let mut client = app.pool.get().await?;
    let tx = client.transaction().await?;
    let blob = tx
        .query_opt("SELECT 1 FROM blobs WHERE blob_id = $1 FOR KEY SHARE", &[&blob_id])
        .await?;
    if blob.is_none() {
        return Ok(());
    }
    tx.execute(
        "DELETE FROM lost_ranges WHERE blob_id = $1 AND start = ANY($2)",
        &[&blob_id, &starts],
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Replaces the lost ranges of a blob with `ranges` (byte offsets, [start,
/// stop)). Whether any were dropped. Under the blob's row lock (X shared, see
/// `catalog.sql`), so that it can't interleave with the blob's deletion.
pub(crate) async fn set_lost(app: &App, blob_id: Uuid, ranges: &[(i64, i64)]) -> anyhow::Result<bool> {
    let mut client = app.pool.get().await?;
    let tx = client.transaction().await?;
    let blob = tx
        .query_opt("SELECT 1 FROM blobs WHERE blob_id = $1 FOR KEY SHARE", &[&blob_id])
        .await?;
    if blob.is_none() {
        return Ok(false);
    }
    let (starts, stops): (Vec<i64>, Vec<i64>) = ranges.iter().copied().unzip();
    let dropped = tx
        .execute(
            "DELETE FROM lost_ranges WHERE blob_id = $1 AND start <> ALL($2)",
            &[&blob_id, &starts],
        )
        .await?;
    tx.execute(
        "INSERT INTO lost_ranges (blob_id, start, stop, found_at)
         SELECT $1, s, e, NOW() FROM unnest($2::bigint[], $3::bigint[]) AS t(s, e)
         ON CONFLICT (blob_id, start) DO UPDATE SET stop = EXCLUDED.stop",
        &[&blob_id, &starts, &stops],
    )
    .await?;
    tx.commit().await?;
    Ok(dropped > 0)
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
/// have it checked again. Only as far as a statement can tell, though: one
/// that waits for the scrubber recording a finding for the copy re-checks the
/// location row, but not the finding (F2 in `catalog.sql`), so it flags the
/// copy anyway, which is then checked once more. That's harmless.
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

mod repair;

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

    /// Writes the file of shard `shard` of a blob whose shards are `shards`
    /// (one for a replicated blob); its CRC.
    fn write(path: &std::path::Path, file: &ShardFile, shards: &[&[u8]]) -> u64 {
        // A replicated blob's shards share their one table.
        let tables = if file.layout.replicated() { 1 } else { shards.len() };
        let tables: Vec<_> = shards[..tables]
            .iter()
            .map(|data| {
                let mut summer = crate::checksum::BlobSummer::new(file.layout.block_size as u32);
                summer.update(data);
                summer.finish()
            })
            .collect();
        let mut bytes = shards[(file.shard as usize).min(shards.len() - 1)].to_vec();
        bytes.extend(blob_file::trailer(file, &tables));
        std::fs::write(path, &bytes).unwrap();
        let mut digest = crc64fast_nvme::Digest::new();
        digest.write(&bytes);
        digest.sum64()
    }

    fn replicated(id: Uuid, size: u64) -> ShardFile {
        ShardFile {
            blob_id: id,
            layout: Layout {
                size,
                block_size: 256,
                data_shards: 1,
                parity_shards: 1,
                stripe_unit: 256,
            },
            shard: 1,
        }
    }

    #[test]
    fn checks_files() {
        let dir = std::env::temp_dir().join(format!("cairn-scrub-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("blob");
        let id = Uuid::now_v7();
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
        let file = replicated(id, 1000);
        let crc = write(&path, &ShardFile { shard: 0, ..file }, &[&data]);
        let pacer = Pacer::new(None);
        let check = |crc| check_file(path.clone(), &file, crc, &pacer);
        assert_eq!(check(crc), Verdict::Intact);
        assert!(matches!(
            check(crc ^ 1),
            Verdict::Damaged { bad_blocks: Some(bad), .. } if bad.is_empty()
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
        write(&path, &replicated(Uuid::now_v7(), 1000), &[&data, &data]);
        let Verdict::Damaged { bad_blocks, detail } = check(crc) else {
            panic!("not damaged")
        };
        assert_eq!(bad_blocks, None);
        assert!(detail.contains("another blob's ID"), "{detail}");

        std::fs::remove_file(&path).unwrap();
        assert_eq!(check(crc), Verdict::Missing);

        // An empty blob is just its ID.
        let empty = replicated(id, 0);
        let crc = write(&path, &empty, &[&[], &[]]);
        assert_eq!(check_file(path.clone(), &empty, crc, &pacer), Verdict::Intact);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn checks_coded_shards() {
        let dir = std::env::temp_dir().join(format!("cairn-scrub-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("blob");
        // 2+1, stripe unit 512, blocks of 256: shard sizes 788, 512, 1024.
        let layout = Layout {
            size: 1300,
            block_size: 256,
            data_shards: 2,
            parity_shards: 1,
            stripe_unit: 512,
        };
        let shards: Vec<Vec<u8>> = (0..3).map(|s| vec![s as u8 + 1; layout.shard_size(s) as usize]).collect();
        let refs: Vec<&[u8]> = shards.iter().map(Vec::as_slice).collect();
        let file = ShardFile { blob_id: Uuid::now_v7(), layout, shard: 1 };
        let crc = write(&path, &file, &refs);
        let pacer = Pacer::new(None);
        assert_eq!(check_file(path.clone(), &file, crc, &pacer), Verdict::Intact);

        // A block of its own data, and one of another shard's table, which
        // only the file's CRC catches.
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[300] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        let Verdict::Damaged { bad_blocks, .. } = check_file(path.clone(), &file, crc, &pacer) else {
            panic!("not damaged")
        };
        assert_eq!(bad_blocks, Some(vec![1]));
        bytes[300] ^= 1;
        bytes[512 + 2] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            check_file(path.clone(), &file, crc, &pacer),
            Verdict::Damaged { bad_blocks: Some(bad), .. } if bad.is_empty()
        ));

        // Another shard's file of the same length, read as this one.
        let other = ShardFile { shard: 0, ..file };
        let mut bytes = shards[1].clone();
        let tables: Vec<_> = refs
            .iter()
            .map(|data| {
                let mut summer = crate::checksum::BlobSummer::new(256);
                summer.update(data);
                summer.finish()
            })
            .collect();
        bytes.extend(blob_file::trailer(&other, &tables));
        std::fs::write(&path, &bytes).unwrap();
        let Verdict::Damaged { detail, .. } = check_file(path.clone(), &file, crc, &pacer) else {
            panic!("not damaged")
        };
        assert!(detail.contains("another shard"), "{detail}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
