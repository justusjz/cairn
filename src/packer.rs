//! The packer: moves parts between blobs, so that the cluster doesn't end up
//! with a file per small object, or with packed blobs that are mostly garbage.
//!
//! Every blob costs a row in the catalog, plus one per replica, and is the unit
//! that repair and rebalancing move around. So the packer keeps blobs large: it
//! packs the data of smaller blobs into blobs of 256 MiB.
//!
//! A packing job claims a set of source blobs, copies their live parts into
//! new blobs of about equal size (as few as hold them), verifies the copies, and
//! then, in one transaction, commits the new blobs, re-points the parts at them,
//! and drops the sources. There are two kinds of job:
//!
//! - **Consolidation** packs blobs up to [`SMALL_SIZE`] together, once
//!   there's enough of them to fill a blob. Packing costs a second write of the
//!   data, so each byte is consolidated only once: the new blobs hold at least
//!   half a blob's worth, more than twice the size of a candidate. Only when as
//!   many candidates wait as a job may take ([`Config::max_sources`]) are they
//!   packed without filling a blob, so that lots of tiny files are packed long
//!   before they add up to one.
//! - **Compaction** rewrites blobs once a large enough fraction of them is
//!   garbage (a quarter, by default), to free that space. Bytes become garbage
//!   when their part is deleted; `blobs.dead_size` counts them. A job takes
//!   several such blobs at once, so their survivors are packed into fewer,
//!   fuller blobs.
//!
//! Within a job, parts are laid out by age band, then bucket, then age. Data
//! that has lived long is likely to live on (the generational hypothesis), so
//! keeping parts of a similar age together means that the parts which do get
//! deleted tend to be concentrated in a few blobs, which compaction then frees
//! cheaply. Bands double in width, so the ordering matters most among young
//! data, where lifetimes differ most.
//!
//! Packing is coordinated through the catalog, not between replicas: a job
//! reads the sources from any replica and writes the new blob to replicas of
//! its own, like an upload. Every node runs a packer, and they claim blobs with
//! a lease (`blobs.pack_lease_until`), so they don't duplicate work. The lease
//! isn't needed for correctness: a part is only moved if it's still where the
//! job found it, so a job racing another (or a delete) just leaves some garbage
//! in its new blob. A failed job's sources stay leased until the lease runs out,
//! which keeps the packer from retrying a broken blob in a tight loop.
//!
//! The cleanup invariant holds throughout: the new blob is pending until the
//! commit, so the GC reclaims it if the job dies, and a lease expires by itself.

use std::{collections::HashMap, sync::Arc, time::Duration};

use deadpool_postgres::Object;
use hyper::body::Bytes;
use md5::{Digest, Md5};
use tokio::sync::mpsc;
use tokio_postgres::{IsolationLevel, error::SqlState};
use uuid::Uuid;

use crate::{
    App, BlobWriter, Written,
    blobs::{BlobSlice, Location, ReapTarget, drop_unreferenced_blobs, reap_blobs, stream_blob_range},
    checksum::{self, BlockLayout},
};

/// Blobs up to this size are consolidated. Must match the `blobs_small` index
/// (migration 5), which covers the candidates; tests may only lower it.
pub(crate) const SMALL_SIZE: u64 = 64 * 1024 * 1024;
/// How many new blobs' worth of live data a job takes at most.
const OUTPUTS_PER_JOB: u64 = 4;
/// How often a node runs a packing pass.
const PASS_INTERVAL: Duration = Duration::from_secs(60);
/// How long a job may hold its source blobs.
const LEASE: Duration = Duration::from_secs(3600);
/// The most jobs a pass runs, so that a pass ends even under a steady stream of
/// new small blobs.
const MAX_JOBS_PER_PASS: usize = 64;
const MAX_COMMIT_ATTEMPTS: usize = 10;

/// What to pack, and into what. Fixed, so that the rest of Cairn can be tuned
/// for it; tests use smaller sizes. The sizes must keep a consolidation's new
/// blobs from being candidates themselves: a consolidation writes at least half
/// a blob's worth into each, so a candidate may be at most a quarter of one.
#[derive(Clone, Debug)]
pub(crate) struct Config {
    /// Size of the blobs the packer writes. Its new blobs are as close to it as
    /// their parts allow.
    pub target_size: u64,
    /// Blobs up to this size are consolidated.
    pub small_size: u64,
    /// Compact a blob once this fraction of it is garbage.
    pub compact_threshold: f64,
    /// The most blobs a job takes, which bounds the size of its transactions.
    /// When this many candidates for consolidation wait, they're packed even if
    /// they don't fill a blob.
    pub max_sources: i64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            target_size: 256 * 1024 * 1024,
            small_size: SMALL_SIZE,
            compact_threshold: 0.25,
            max_sources: 10_000,
        }
    }
}

/// Points in a packing job where a test can step in (see `App::pack_hook`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    /// The job knows its parts, and hasn't copied any yet.
    Loaded,
    /// The new blob is written, but not yet verified.
    Copied,
    /// The new blob is verified, but not yet committed.
    Verified,
}

#[cfg(test)]
pub(crate) type Hook = Arc<
    dyn Fn(Arc<App>, Stage) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync,
>;

/// Runs the test hook, if any, at `stage`. Does nothing outside of tests.
async fn reached(app: &Arc<App>, stage: Stage) {
    #[cfg(test)]
    if let Some(hook) = &app.pack_hook {
        hook(app.clone(), stage).await;
    }
    #[cfg(not(test))]
    let _ = (app, stage);
}

/// Runs a packing pass every [`PASS_INTERVAL`], forever.
pub async fn run(app: Arc<App>) {
    loop {
        tokio::time::sleep(PASS_INTERVAL).await;
        match pass(&app).await {
            Ok(jobs) => {
                for job in jobs {
                    eprintln!("packer: {job}");
                }
            }
            Err(e) => eprintln!("packer: pass failed: {e:#}"),
        }
    }
}

/// What a job did, for the log.
pub struct JobReport {
    kind: Kind,
    sources: usize,
    parts: usize,
    bytes: u64,
    outputs: Vec<Uuid>,
}

impl std::fmt::Display for JobReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self.kind {
            Kind::Compact => "compacted",
            Kind::Consolidate => "consolidated",
        };
        write!(
            f,
            "{kind} {} blobs into {}: moved {} parts ({} bytes)",
            self.sources,
            self.outputs.len(),
            self.parts,
            self.bytes
        )
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Compact,
    Consolidate,
}

/// Runs packing jobs until there's nothing left worth packing (or the pass hits
/// its limit). Compaction goes first, since it frees space. A failed job is
/// logged, and the pass moves on to other blobs.
pub async fn pass(app: &Arc<App>) -> anyhow::Result<Vec<JobReport>> {
    fold_garbage(app).await?;
    let mut reports = Vec::new();
    for _ in 0..MAX_JOBS_PER_PASS {
        let claimed = match claim(app, Kind::Compact).await? {
            Some(sources) => Some((Kind::Compact, sources)),
            None => claim(app, Kind::Consolidate)
                .await?
                .map(|sources| (Kind::Consolidate, sources)),
        };
        let Some((kind, sources)) = claimed else {
            break;
        };
        match run_job(app, kind, &sources).await {
            Ok(report) => reports.push(report),
            Err(e) => eprintln!("packer: packing {} blobs failed: {e:#}", sources.len()),
        }
    }
    Ok(reports)
}

/// Adds the garbage logged since the last fold to `blobs.dead_size`. Folds
/// running concurrently on several nodes each take different log rows.
async fn fold_garbage(app: &App) -> anyhow::Result<()> {
    let client = app.pool.get().await?;
    client
        .execute(
            "WITH taken AS (DELETE FROM blob_garbage RETURNING blob_id, size),
                  sums AS (SELECT blob_id, sum(size)::bigint AS size FROM taken GROUP BY blob_id)
             UPDATE blobs b SET dead_size = b.dead_size + sums.size
             FROM sums WHERE b.blob_id = sums.blob_id",
            &[],
        )
        .await?;
    Ok(())
}

/// Claims the source blobs for a job of `kind`, if there's one worth running:
/// as many candidates as fit into one new blob, by their live bytes.
async fn claim(app: &App, kind: Kind) -> anyhow::Result<Option<Vec<Uuid>>> {
    let config = &app.pack;
    let mut client = app.pool.get().await?;
    let tx = client.transaction().await?;
    // Skip blobs that a concurrent claim has locked: it's about to lease them.
    let rows = match kind {
        // Least live data first: that's the cheapest space to free.
        Kind::Compact => {
            tx.query(
                "SELECT blob_id, size - dead_size FROM blobs
                 WHERE dead_size > 0 AND state = 'committed' AND dead_size >= size * $1::float8
                   AND (pack_lease_until IS NULL OR pack_lease_until < NOW())
                 ORDER BY size - dead_size
                 LIMIT $2 FOR UPDATE SKIP LOCKED",
                &[&config.compact_threshold, &config.max_sources],
            )
            .await?
        }
        // Oldest first. The index's size bound is repeated as a literal, so
        // that the planner can use the partial index.
        Kind::Consolidate => {
            tx.query(
                &format!(
                    "SELECT blob_id, size FROM blobs
                     WHERE state = 'committed' AND size <= {SMALL_SIZE} AND size <= $1
                       AND (pack_lease_until IS NULL OR pack_lease_until < NOW())
                     ORDER BY created_at
                     LIMIT $2 FOR UPDATE SKIP LOCKED"
                ),
                &[&(config.small_size as i64), &config.max_sources],
            )
            .await?
        }
    };
    let budget = OUTPUTS_PER_JOB * config.target_size;
    let mut sources = Vec::new();
    let mut total = 0;
    for row in &rows {
        let live = row.get::<_, i64>(1) as u64;
        if total + live > budget && !sources.is_empty() {
            break;
        }
        total += live;
        sources.push(row.get::<_, Uuid>(0));
    }
    let worth_it = match kind {
        Kind::Compact => !sources.is_empty(),
        Kind::Consolidate => {
            total >= config.target_size || sources.len() as i64 >= config.max_sources
        }
    };
    if !worth_it {
        // Dropping `tx` rolls it back, releasing the row locks.
        return Ok(None);
    }
    tx.execute(
        "UPDATE blobs SET pack_lease_until = NOW() + make_interval(secs => $2)
         WHERE blob_id = ANY($1)",
        &[&sources, &LEASE.as_secs_f64()],
    )
    .await?;
    tx.commit().await?;
    Ok(Some(sources))
}

/// A live part to move: where it is, where it's going, and the checksum that
/// its bytes must still match once they're there.
struct Part {
    id: i64,
    blob_id: Uuid,
    offset: u64,
    size: u64,
    /// The new blob it goes to (the job's first, second, ...), and where.
    output: usize,
    new_offset: u64,
    /// The part's CRC64/NVME, or for a part from before checksums, its MD5
    /// (which is its ETag).
    crc64nvme: Option<u64>,
    etag: String,
}

/// A contiguous range of a source blob, copied in one read: one or more parts
/// that sit back to back in the source and stay that way in a new blob.
struct Run {
    output: usize,
    blob_id: Uuid,
    offset: u64,
    length: u64,
    /// The parts it holds, as a range of the job's parts.
    parts: std::ops::Range<usize>,
}

/// Runs a job on the claimed `sources`. On failure, the new blobs are deleted
/// (left to the GC if that fails too), and the sources stay leased.
async fn run_job(app: &Arc<App>, kind: Kind, sources: &[Uuid]) -> anyhow::Result<JobReport> {
    let mut outputs = Vec::new();
    let result = pack(app, kind, sources, &mut outputs).await;
    if result.is_err() {
        for blob_id in outputs {
            if let Err(e) = abandon(app, blob_id).await {
                eprintln!("packer: deleting abandoned blob {blob_id} failed: {e:#}");
            }
        }
    }
    result
}

/// The body of [`run_job`]. Adds each new blob to `outputs` once it exists.
async fn pack(
    app: &Arc<App>,
    kind: Kind,
    sources: &[Uuid],
    outputs: &mut Vec<Uuid>,
) -> anyhow::Result<JobReport> {
    let client = app.pool.get().await?;
    let mut parts = load_parts(&client, sources).await?;
    let blobs = load_blobs(&client, app.node, sources).await?;
    drop(client);
    // Parts must not overlap: each is copied on its own, and gets its own range
    // in the new blob. Parts never share bytes yet; should a blob hold any that
    // do, it's left alone.
    let overlapping = overlapping_blobs(&parts);
    parts.retain(|p| !overlapping.contains(&p.blob_id));
    let report = |parts: &[Part], written: &[Written]| JobReport {
        kind,
        sources: sources.len(),
        parts: parts.len(),
        bytes: parts.iter().map(|p| p.size).sum(),
        outputs: written.iter().map(|w| w.blob_id).collect(),
    };
    if parts.is_empty() {
        // Nothing left to move: the sources are garbage already (or all hold
        // overlapping parts, which then just get their lease released).
        commit(app, sources, &[], &[]).await?;
        return Ok(report(&parts, &[]));
    }
    let runs = lay_out(&mut parts, app.pack.target_size);
    reached(app, Stage::Loaded).await;

    // The new blobs, in order: `written[i]` is output `i`.
    let mut written = Vec::new();
    // Runs whose source vanished while the job ran (all its parts were
    // deleted), and whose place in a new blob is padding.
    let mut vanished = Vec::new();
    for output in runs.chunk_by(|a, b| a.output == b.output) {
        let mut writer = BlobWriter::begin(app).await?;
        outputs.push(writer.blob_id);
        for run in output {
            let (layout, locations) = &blobs[&run.blob_id];
            match copy_run(app, run, *layout, locations, &mut writer).await {
                Ok(true) => {}
                Ok(false) => vanished.push(run.parts.clone()),
                Err(e) => {
                    writer.abort(&format!("{e:#}")).await;
                    return Err(e);
                }
            }
        }
        written.push(writer.finish().await?);
    }
    for range in vanished.into_iter().rev() {
        parts.drain(range);
    }
    reached(app, Stage::Copied).await;
    for (i, output) in written.iter().enumerate() {
        // The parts are in order of their new blobs.
        let start = parts.partition_point(|p| p.output < i);
        let end = parts.partition_point(|p| p.output <= i);
        verify(app, output, &parts[start..end]).await?;
    }
    reached(app, Stage::Verified).await;
    commit(app, sources, &written, &parts).await?;
    Ok(report(&parts, &written))
}

/// Loads the parts of `sources` in the order they're to be laid out: by age
/// band (the oldest first), then bucket, then age.
async fn load_parts(client: &Object, sources: &[Uuid]) -> anyhow::Result<Vec<Part>> {
    // A part's age band is log2 of its age in minutes: the first band holds
    // the parts younger than two minutes, the next those up to four, and so on.
    // The last keys keep a blob's parts together when they're the same age.
    let rows = client
        .query(
            "SELECT p.id, p.blob_id, p.blob_offset, p.size, p.crc64nvme, p.etag
             FROM parts p
             LEFT JOIN objects o ON o.id = p.object_id
             LEFT JOIN multipart_uploads u ON u.upload_id = p.upload_id
             WHERE p.blob_id = ANY($1)
             ORDER BY floor(log(2, greatest(extract(epoch FROM NOW() - p.created_at) / 60, 1))) DESC,
                      coalesce(o.bucket, u.bucket), p.created_at, p.blob_id, p.blob_offset",
            &[&sources],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| Part {
            id: r.get(0),
            blob_id: r.get(1),
            offset: r.get::<_, i64>(2) as u64,
            size: r.get::<_, i64>(3) as u64,
            output: 0,
            new_offset: 0,
            crc64nvme: r.get::<_, Option<i64>>(4).map(|crc| crc as u64),
            etag: r.get(5),
        })
        .collect())
}

/// Each source blob's block layout (`None` for a blob from before checksums)
/// and its replicas, this node first, then the freshest.
async fn load_blobs(
    client: &Object,
    node: i32,
    sources: &[Uuid],
) -> anyhow::Result<HashMap<Uuid, (Option<BlockLayout>, Vec<Location>)>> {
    let rows = client
        .query(
            "SELECT b.blob_id, b.size, b.block_size, bl.node, n.peer_url
             FROM blobs b
             JOIN blob_locations bl ON bl.blob_id = b.blob_id
             JOIN nodes n ON n.id = bl.node
             WHERE b.blob_id = ANY($1)
             ORDER BY bl.node = $2 DESC, n.last_seen DESC",
            &[&sources, &node],
        )
        .await?;
    let mut blobs: HashMap<Uuid, (Option<BlockLayout>, Vec<Location>)> = HashMap::new();
    for row in &rows {
        let (_, locations) = blobs.entry(row.get(0)).or_insert_with(|| {
            let layout = row.get::<_, Option<i32>>(2).map(|block_size| BlockLayout {
                block_size: block_size as u64,
                blob_size: row.get::<_, i64>(1) as u64,
            });
            (layout, Vec::new())
        });
        locations.push((row.get(3), row.get(4)));
    }
    Ok(blobs)
}

/// The blobs in which two of `parts` overlap.
fn overlapping_blobs(parts: &[Part]) -> Vec<Uuid> {
    let mut ranges: Vec<(Uuid, u64, u64)> = parts
        .iter()
        .map(|p| (p.blob_id, p.offset, p.offset + p.size))
        .collect();
    ranges.sort();
    let mut overlapping: Vec<Uuid> = ranges
        .windows(2)
        .filter(|w| w[0].0 == w[1].0 && w[1].1 < w[0].2)
        .map(|w| w[0].0)
        .collect();
    overlapping.dedup();
    overlapping
}

/// Splits `parts`, in their order, among as few new blobs as hold them at
/// `target` bytes each, about the same amount in each, and gives each part its
/// place: back to back in its new blob. Groups them into runs that can each be
/// copied in one read.
fn lay_out(parts: &mut [Part], target: u64) -> Vec<Run> {
    let total: u64 = parts.iter().map(|p| p.size).sum();
    let shares = total.div_ceil(target).max(1);
    let mut runs: Vec<Run> = Vec::new();
    // Where the part starts in all the data back to back, which equal share of
    // it that is, and which new blob that share went to. A part goes to the
    // share it starts in, so the blobs differ in size by at most a part. A part
    // larger than a share leaves the next one empty, so a blob can hold more
    // than one share.
    let mut start = 0;
    let mut share = 0;
    let mut output = 0;
    let mut cursor = 0;
    for (i, part) in parts.iter_mut().enumerate() {
        // Empty parts at the very end start at `total`, past the last share.
        let part_share = (start * shares / total.max(1)).min(shares - 1);
        if part_share != share {
            share = part_share;
            output += 1;
            cursor = 0;
        }
        part.output = output;
        part.new_offset = cursor;
        cursor += part.size;
        start += part.size;
        match runs.last_mut() {
            Some(run)
                if run.output == output
                    && run.blob_id == part.blob_id
                    && run.offset + run.length == part.offset =>
            {
                run.length += part.size;
                run.parts.end = i + 1;
            }
            _ => runs.push(Run {
                output,
                blob_id: part.blob_id,
                offset: part.offset,
                length: part.size,
                parts: i..i + 1,
            }),
        }
    }
    runs
}

/// Copies a run from its source blob into `writer`, verified against the
/// source's block checksums on the way. If the source can't be read because it
/// has been deleted in the meantime, pads the run with zeros instead, and
/// returns false: its parts are gone, so nothing will point at those bytes.
async fn copy_run(
    app: &App,
    run: &Run,
    layout: Option<BlockLayout>,
    locations: &[Location],
    writer: &mut BlobWriter,
) -> anyhow::Result<bool> {
    let mut slice = BlobSlice {
        blob_id: run.blob_id,
        layout,
        locations: locations.to_vec(),
        offset: run.offset,
        length: run.length,
        part: None,
    };
    let (tx, mut rx) = mpsc::channel(4);
    let read = async move {
        let result = stream_blob_range(app, &mut slice, &tx).await;
        drop(tx);
        result
    };
    let forward = async {
        let mut copied = 0;
        while let Some(Ok(frame)) = rx.recv().await {
            if let Ok(data) = frame.into_data() {
                copied += data.len() as u64;
                writer.write(data).await;
            }
        }
        copied
    };
    let (read, copied) = tokio::join!(read, forward);
    let Err(e) = read else {
        return Ok(true);
    };
    let client = app.pool.get().await?;
    let exists = client
        .query_opt("SELECT 1 FROM blobs WHERE blob_id = $1", &[&run.blob_id])
        .await?
        .is_some();
    if exists {
        return Err(e.into());
    }
    let mut padding = run.length - copied;
    while padding > 0 {
        let len = padding.min(checksum::BLOCK_SIZE as u64);
        writer.write(Bytes::from(vec![0; len as usize])).await;
        padding -= len;
    }
    Ok(false)
}

/// Reads the new blob back through the normal read path, and checks that each
/// part's bytes, at the very offset it's about to be committed with, still
/// match the part's own checksum. Independent of how the blob was assembled, so
/// it also catches the packer's own mistakes.
async fn verify(app: &App, written: &Written, parts: &[Part]) -> anyhow::Result<()> {
    let mut locations = written.replicas.clone();
    locations.sort_by_key(|(node, _)| *node != app.node);
    let mut slice = BlobSlice {
        blob_id: written.blob_id,
        layout: Some(BlockLayout {
            block_size: checksum::BLOCK_SIZE as u64,
            blob_size: written.size,
        }),
        locations,
        offset: 0,
        length: written.size,
        part: None,
    };
    let (tx, mut rx) = mpsc::channel(4);
    let read = async move {
        let result = stream_blob_range(app, &mut slice, &tx).await;
        drop(tx);
        result
    };
    let check = async {
        let mut verifier = Verifier::new(parts);
        while let Some(Ok(frame)) = rx.recv().await {
            if let Ok(data) = frame.into_data() {
                verifier.update(&data);
            }
        }
        verifier.finish()
    };
    let (read, checked) = tokio::join!(read, check);
    read?;
    checked.map_err(|e| anyhow::anyhow!("blob {}: {e}", written.blob_id))
}

/// Checks the parts in a stream of the new blob's bytes. The parts must be in
/// order of their new offsets, and not overlap.
struct Verifier<'a> {
    parts: &'a [Part],
    /// The next part to check, and the hash of what's been seen of it.
    next: usize,
    hash: PartHash,
    /// Offset of the next byte in the blob.
    pos: u64,
}

enum PartHash {
    Crc(crc64fast_nvme::Digest),
    Md5(Md5),
}

impl PartHash {
    fn new(part: Option<&Part>) -> PartHash {
        match part {
            Some(Part {
                crc64nvme: None, ..
            }) => PartHash::Md5(Md5::new()),
            _ => PartHash::Crc(crc64fast_nvme::Digest::new()),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            PartHash::Crc(digest) => digest.write(data),
            PartHash::Md5(md5) => md5.update(data),
        }
    }

    fn matches(self, part: &Part) -> bool {
        match (self, part.crc64nvme) {
            (PartHash::Crc(digest), Some(crc)) => digest.sum64() == crc,
            (PartHash::Md5(md5), None) => {
                let hex: String = md5.finalize().iter().map(|b| format!("{b:02x}")).collect();
                hex == part.etag
            }
            _ => false,
        }
    }
}

impl<'a> Verifier<'a> {
    fn new(parts: &'a [Part]) -> Verifier<'a> {
        Verifier {
            parts,
            next: 0,
            hash: PartHash::new(parts.first()),
            pos: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        if self.failed() {
            return;
        }
        while let Some(part) = self.parts.get(self.next) {
            // Skip to the part's start (past padding).
            let skip = (part.new_offset.saturating_sub(self.pos)).min(data.len() as u64);
            self.pos += skip;
            data = &data[skip as usize..];
            if self.pos < part.new_offset {
                return;
            }
            let take = (part.new_offset + part.size - self.pos).min(data.len() as u64);
            self.hash.update(&data[..take as usize]);
            self.pos += take;
            data = &data[take as usize..];
            if self.pos < part.new_offset + part.size {
                return;
            }
            self.end_part();
            if self.failed() {
                return;
            }
        }
    }

    fn end_part(&mut self) {
        let hash = std::mem::replace(&mut self.hash, PartHash::new(self.parts.get(self.next + 1)));
        if hash.matches(&self.parts[self.next]) {
            self.next += 1;
        } else {
            // Stop checking; `finish` reports this part.
            self.parts = &self.parts[..=self.next];
            self.pos = u64::MAX;
        }
    }

    fn failed(&self) -> bool {
        self.pos == u64::MAX
    }

    fn finish(mut self) -> Result<(), String> {
        // Empty parts at the very end see no data, so they end here.
        while !self.failed()
            && let Some(part) = self.parts.get(self.next)
            && part.size == 0
            && part.new_offset == self.pos
        {
            self.end_part();
        }
        match self.parts.get(self.next) {
            None => Ok(()),
            Some(part) if self.failed() => Err(format!(
                "part {} doesn't match its checksum at offset {}",
                part.id, part.new_offset
            )),
            Some(part) => Err(format!("part {} is cut short", part.id)),
        }
    }
}

/// The transaction that ends a job: commits the new blobs, moves each part
/// that's still where the job found it into its new blob, and drops the sources
/// and new blobs that nothing references anymore. A source that something
/// still references (nothing can, yet) keeps the bytes that moved out of it as
/// garbage. Releases the leases on the sources that remain.
async fn commit(
    app: &Arc<App>,
    sources: &[Uuid],
    written: &[Written],
    parts: &[Part],
) -> anyhow::Result<()> {
    let mut client = app.pool.get().await?;
    for _ in 0..MAX_COMMIT_ATTEMPTS {
        match try_commit(&mut client, sources, written, parts).await {
            Ok(reap) => {
                reap_blobs(app, reap);
                return Ok(());
            }
            Err(CommitError::Db(e)) if e.code() == Some(&SqlState::T_R_SERIALIZATION_FAILURE) => {
                continue;
            }
            Err(CommitError::Db(e)) => return Err(e.into()),
            Err(CommitError::MissingLocations(present)) => {
                anyhow::bail!("only {present} replicas of a new blob reported a location");
            }
        }
    }
    anyhow::bail!("commit aborted after {MAX_COMMIT_ATTEMPTS} serialization retries")
}

enum CommitError {
    Db(tokio_postgres::Error),
    MissingLocations(i64),
}

impl From<tokio_postgres::Error> for CommitError {
    fn from(e: tokio_postgres::Error) -> Self {
        CommitError::Db(e)
    }
}

async fn try_commit(
    client: &mut Object,
    sources: &[Uuid],
    written: &[Written],
    parts: &[Part],
) -> Result<Vec<ReapTarget>, CommitError> {
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()
        .await?;
    for output in written {
        output.commit(&tx).await?.map_err(CommitError::MissingLocations)?;
    }
    let ids: Vec<i64> = parts.iter().map(|p| p.id).collect();
    let old_blobs: Vec<Uuid> = parts.iter().map(|p| p.blob_id).collect();
    let old_offsets: Vec<i64> = parts.iter().map(|p| p.offset as i64).collect();
    let new_blobs: Vec<Uuid> = parts.iter().map(|p| written[p.output].blob_id).collect();
    let new_offsets: Vec<i64> = parts.iter().map(|p| p.new_offset as i64).collect();
    let moved = tx
        .query(
            "UPDATE parts p SET blob_id = m.new_blob, blob_offset = m.new_offset
             FROM unnest($1::bigint[], $2::uuid[], $3::bigint[], $4::uuid[], $5::bigint[])
                 AS m(id, old_blob, old_offset, new_blob, new_offset)
             WHERE p.id = m.id AND p.blob_id = m.old_blob AND p.blob_offset = m.old_offset
             RETURNING m.old_blob, m.new_blob, p.size",
            &[&ids, &old_blobs, &old_offsets, &new_blobs, &new_offsets],
        )
        .await?;
    let mut moved_from: HashMap<Uuid, i64> = HashMap::new();
    let mut moved_to: HashMap<Uuid, i64> = HashMap::new();
    for row in &moved {
        let size: i64 = row.get(2);
        *moved_from.entry(row.get(0)).or_default() += size;
        *moved_to.entry(row.get(1)).or_default() += size;
    }
    // In the new blobs, whatever didn't move in (its part was deleted
    // meanwhile) is garbage.
    let new_ids: Vec<Uuid> = written.iter().map(|w| w.blob_id).collect();
    let live: Vec<i64> = new_ids
        .iter()
        .map(|id| moved_to.get(id).copied().unwrap_or(0))
        .collect();
    tx.execute(
        "UPDATE blobs b SET dead_size = b.size - m.live
         FROM unnest($1::uuid[], $2::bigint[]) AS m(blob_id, live)
         WHERE b.blob_id = m.blob_id",
        &[&new_ids, &live],
    )
    .await?;
    let mut unreferenced = sources.to_vec();
    unreferenced.extend(&new_ids);
    let reap = drop_unreferenced_blobs(&tx, &unreferenced).await?;
    let moved: Vec<i64> = sources
        .iter()
        .map(|s| moved_from.get(s).copied().unwrap_or(0))
        .collect();
    tx.execute(
        "UPDATE blobs b SET dead_size = b.dead_size + m.moved, pack_lease_until = NULL
         FROM unnest($1::uuid[], $2::bigint[]) AS m(blob_id, moved)
         WHERE b.blob_id = m.blob_id",
        &[&sources, &moved],
    )
    .await?;
    tx.commit().await?;
    Ok(reap)
}

/// Deletes a failed job's new blob, while it's still pending, and reaps its
/// files.
async fn abandon(app: &Arc<App>, blob_id: Uuid) -> anyhow::Result<()> {
    let client = app.pool.get().await?;
    // The outer SELECT still sees the locations that the DELETE cascades away.
    let rows = client
        .query(
            "WITH gone AS (
                 DELETE FROM blobs WHERE blob_id = $1 AND state = 'pending' RETURNING blob_id
             )
             SELECT bl.blob_id, bl.node, n.peer_url
             FROM gone
             JOIN blob_locations bl ON bl.blob_id = gone.blob_id
             JOIN nodes n ON n.id = bl.node",
            &[&blob_id],
        )
        .await?;
    reap_blobs(app, crate::blobs::reap_targets(&rows));
    Ok(())
}

#[cfg(test)]
mod e2e;

#[cfg(test)]
mod tests {
    use super::*;

    fn part(id: i64, blob: u128, offset: u64, data: &[u8], md5: bool) -> Part {
        let mut crc = crc64fast_nvme::Digest::new();
        crc.write(data);
        Part {
            id,
            blob_id: Uuid::from_u128(blob),
            offset,
            size: data.len() as u64,
            output: 0,
            new_offset: 0,
            crc64nvme: (!md5).then(|| crc.sum64()),
            etag: Md5::digest(data).iter().map(|b| format!("{b:02x}")).collect(),
        }
    }

    #[test]
    fn small_size_matches_the_index() {
        let index = format!("size <= {SMALL_SIZE};");
        assert!(crate::db::PACKING.contains(&index));
    }

    #[test]
    fn runs_join_adjacent_parts_of_a_blob() {
        let mut parts = vec![
            part(1, 1, 0, b"aaaa", false),
            part(2, 1, 4, b"bb", false),
            part(3, 2, 10, b"ccc", false),
            part(4, 1, 20, b"d", false),
            part(5, 1, 21, b"", false),
        ];
        let runs = lay_out(&mut parts, 100);
        let offsets: Vec<u64> = parts.iter().map(|p| p.new_offset).collect();
        assert_eq!(offsets, [0, 4, 6, 9, 10]);
        let shape: Vec<(u128, u64, u64, std::ops::Range<usize>)> = runs
            .iter()
            .map(|r| (r.blob_id.as_u128(), r.offset, r.length, r.parts.clone()))
            .collect();
        assert_eq!(shape, [(1, 0, 6, 0..2), (2, 10, 3, 2..3), (1, 20, 1, 3..5)]);
    }

    #[test]
    fn parts_are_split_evenly_among_new_blobs() {
        // 25 parts of 10 bytes: 250 bytes, so 3 blobs of at most 100.
        let mut parts: Vec<Part> = (0..25)
            .map(|i| part(i, 1, i as u64 * 10, &[i as u8; 10], false))
            .collect();
        let runs = lay_out(&mut parts, 100);
        let mut sizes = [0; 3];
        for p in &parts {
            assert_eq!(p.new_offset, sizes[p.output]);
            sizes[p.output] += p.size;
        }
        assert_eq!(sizes, [90, 80, 80]);
        // The source is contiguous, but a run never spans two new blobs.
        let shape: Vec<(usize, u64, u64)> =
            runs.iter().map(|r| (r.output, r.offset, r.length)).collect();
        assert_eq!(shape, [(0, 0, 90), (1, 90, 80), (2, 170, 80)]);
    }

    #[test]
    fn a_part_larger_than_a_share_skips_one() {
        let mut parts = vec![
            part(1, 1, 0, &[1; 10], false),
            part(2, 2, 0, &[2; 200], false),
            part(3, 3, 0, &[3; 40], false),
        ];
        // 250 bytes, so three shares of about 83: the large part starts in the
        // first and runs past the second, so the last part starts in the third,
        // and a second blob.
        lay_out(&mut parts, 100);
        let placed: Vec<(usize, u64)> = parts.iter().map(|p| (p.output, p.new_offset)).collect();
        assert_eq!(placed, [(0, 0), (0, 10), (1, 0)]);
    }

    #[test]
    fn overlaps_are_found_per_blob() {
        let parts = vec![
            part(1, 1, 0, b"aaaa", false),
            part(2, 1, 4, b"bb", false),
            part(3, 2, 0, b"aaaa", false),
            part(4, 2, 3, b"bb", false),
        ];
        assert_eq!(overlapping_blobs(&parts), [Uuid::from_u128(2)]);
    }

    /// Lays `parts` out and feeds the resulting blob (with `data` as the
    /// content) to a verifier, `chunk` bytes at a time.
    fn check(parts: &[Part], data: &[u8], chunk: usize) -> Result<(), String> {
        let mut verifier = Verifier::new(parts);
        for piece in data.chunks(chunk) {
            verifier.update(piece);
        }
        verifier.finish()
    }

    #[test]
    fn verifier_checks_every_part() {
        let mut parts = vec![
            part(1, 1, 0, b"", false),
            part(2, 1, 0, b"hello", false),
            part(3, 2, 0, b"world!", true),
            part(4, 3, 0, b"", true),
        ];
        lay_out(&mut parts, 100);
        let blob = b"helloworld!";
        for chunk in [1, 2, 5, 100] {
            assert_eq!(check(&parts, blob, chunk), Ok(()), "chunk {chunk}");
        }
        let mut bad = blob.to_vec();
        bad[7] ^= 1;
        assert!(check(&parts, &bad, 3).unwrap_err().contains("part 3"));
        assert!(check(&parts, &blob[..8], 3).unwrap_err().contains("cut short"));
    }

    #[test]
    fn verifier_skips_padding() {
        // A vanished run's padding sits between the parts that are checked.
        let mut parts = vec![
            part(1, 1, 0, b"abc", false),
            part(2, 2, 0, b"zz", false),
            part(3, 3, 0, b"def", false),
        ];
        lay_out(&mut parts, 100);
        parts.remove(1);
        assert_eq!(check(&parts, b"abc\0\0def", 2), Ok(()));
        assert!(check(&parts, b"abczzdeg", 2).is_err());
    }
}
