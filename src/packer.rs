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
//!   data, so it's normally done once per byte: the new blobs hold at least
//!   half a blob's worth, more than twice the size of a candidate. Only when as
//!   many candidates wait as a job may take ([`Config::max_sources`]) are they
//!   packed without filling a blob, so that lots of tiny files are packed long
//!   before they add up to one. Such a blob can be small enough to be packed
//!   again, together with others, once there are enough to fill one.
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
use tokio_postgres::IsolationLevel;
use uuid::Uuid;

use crate::{
    App, BlobWriter, Written,
    db,
    blobs::{
        BlobSlice, Location, ReapTarget, drop_unreferenced_blobs, reap_blobs, refresh_dead_size,
        stream_blob_range,
    },
    checksum::{self, BlockLayout},
};

/// Blobs up to this size are consolidated. Must match the `blobs_small` index
/// (migration 5), which covers the candidates; tests may only lower it.
pub(crate) const SMALL_SIZE: u64 = 64 * 1024 * 1024;
/// How many new blobs' worth of live data a job takes at most.
const OUTPUTS_PER_JOB: u64 = 4;
/// How long a job may hold its source blobs.
const LEASE: Duration = Duration::from_secs(3600);
/// The most jobs a pass runs, so that a pass ends even under a steady stream of
/// new small blobs.
const MAX_JOBS_PER_PASS: usize = 64;

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

/// What a job did, for the log.
pub struct JobReport {
    kind: Kind,
    sources: usize,
    parts: usize,
    bytes: u64,
    outputs: Vec<Uuid>,
}

impl JobReport {
    /// How many blobs the job packed, and how many parts and bytes it moved.
    pub fn counts(&self) -> (usize, usize, u64) {
        (self.sources, self.parts, self.bytes)
    }
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
            Err(e) => {
                let message = format!("packing {} blobs failed: {e:#}", sources.len());
                eprintln!("packer: {message}");
                app.metrics.pack_failed(message);
            }
        }
    }
    Ok(reports)
}

/// Takes the garbage log: the blobs that parts were deleted from since the
/// last fold. Drops those that no part references anymore, and updates the
/// `dead_size` of the rest. Folds running concurrently on several nodes each
/// take different log rows.
///
/// This is how a blob is dropped when its last part is deleted by a path that
/// leaves it (a packed blob), or a crash gets in the way. Every deleted part is
/// logged, by the trigger, so nothing else needs to look for such blobs. Should
/// a part be attached to a blob being dropped meanwhile (a copy of it), the
/// parts FK fails the fold, which rolls back, and the next pass tries again.
async fn fold_garbage(app: &Arc<App>) -> anyhow::Result<()> {
    let mut client = app.pool.get().await?;
    let tx = client.transaction().await?;
    let logged: Vec<Uuid> = tx
        .query("DELETE FROM blob_garbage RETURNING blob_id", &[])
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let reap = drop_unreferenced_blobs(&tx, &logged).await?;
    // The log's sizes would count bytes that another part still shares as
    // garbage, so the blobs' garbage is worked out afresh.
    refresh_dead_size(&tx, &logged).await?;
    tx.commit().await?;
    reap_blobs(app, reap);
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
    /// The run it's copied with.
    run: usize,
    /// The part's CRC64/NVME, or for a part from before checksums, its MD5
    /// (which is its ETag).
    crc64nvme: Option<u64>,
    etag: String,
}

/// A byte range of a source blob that's copied as a whole: the bytes its parts
/// point at, combined where two parts point at the same bytes (as a copy's part
/// and its source's do). So those bytes are copied once, and both parts point
/// at the one copy afterwards.
struct Extent {
    blob_id: Uuid,
    offset: u64,
    length: u64,
    /// The first of its parts, in the order the parts are laid out by.
    first: usize,
}

/// A contiguous range of a source blob, copied in one read: one or more
/// extents that sit back to back in the source and stay that way in a new blob.
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
    let report = |parts: &[Part], runs: &[Run], written: &[Written]| JobReport {
        kind,
        sources: sources.len(),
        parts: parts.len(),
        bytes: runs.iter().map(|r| r.length).sum(),
        outputs: written.iter().map(|w| w.blob_id).collect(),
    };
    if parts.is_empty() {
        // Nothing left to move: the sources are garbage already.
        commit(app, sources, &[], &[]).await?;
        return Ok(report(&parts, &[], &[]));
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
            // A source missing here was deleted after its parts were loaded,
            // or has no replica left. Either way, reading it fails, and
            // `copy_run` tells which.
            let (layout, locations) = blobs.get(&run.blob_id).cloned().unwrap_or_default();
            match copy_run(app, run, layout, &locations, &mut writer).await {
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
    Ok(report(&parts, &runs, &written))
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
            run: 0,
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

/// Lays out `parts`, given in the order to lay them out by. Combines the byte
/// ranges they point at into extents, and splits those, in the order of their first parts, among as few
/// new blobs as hold them at `target` bytes each, about the same amount in each,
/// back to back. Each part keeps its distance from its extent's start. Groups
/// the extents into runs that can each be copied in one read, and sorts the
/// parts by run, and so by new blob and place in it.
fn lay_out(parts: &mut [Part], target: u64) -> Vec<Run> {
    // Each blob's parts, by offset; the ranges of those that overlap are
    // combined into one extent.
    let mut by_offset: Vec<usize> = (0..parts.len()).collect();
    by_offset.sort_by_key(|&i| (parts[i].blob_id, parts[i].offset));
    let mut extents: Vec<Extent> = Vec::new();
    let mut extent_of = vec![0; parts.len()];
    for i in by_offset {
        let part = &parts[i];
        match extents.last_mut() {
            Some(e) if e.blob_id == part.blob_id && part.offset < e.offset + e.length => {
                e.length = e.length.max(part.offset + part.size - e.offset);
                e.first = e.first.min(i);
            }
            _ => extents.push(Extent {
                blob_id: part.blob_id,
                offset: part.offset,
                length: part.size,
                first: i,
            }),
        }
        extent_of[i] = extents.len() - 1;
    }
    let mut order: Vec<usize> = (0..extents.len()).collect();
    order.sort_by_key(|&e| extents[e].first);

    let total: u64 = extents.iter().map(|e| e.length).sum();
    let shares = total.div_ceil(target).max(1);
    let mut runs: Vec<Run> = Vec::new();
    // Each extent's run, and its new place.
    let mut placed = vec![(0, 0); extents.len()];
    // Where the extent starts in all the data back to back, which equal share
    // of it that is, and which new blob that share went to. An extent goes to
    // the share it starts in, so the blobs differ in size by at most an extent.
    // One larger than a share leaves the next one empty, so a blob can hold more
    // than one share.
    let (mut start, mut share, mut output, mut cursor) = (0, 0, 0, 0);
    for e in order {
        let extent = &extents[e];
        // Empty extents at the very end start at `total`, past the last share.
        let extent_share = (start * shares / total.max(1)).min(shares - 1);
        if extent_share != share {
            share = extent_share;
            output += 1;
            cursor = 0;
        }
        match runs.last_mut() {
            Some(run)
                if run.output == output
                    && run.blob_id == extent.blob_id
                    && run.offset + run.length == extent.offset =>
            {
                run.length += extent.length;
            }
            _ => runs.push(Run {
                output,
                blob_id: extent.blob_id,
                offset: extent.offset,
                length: extent.length,
                parts: 0..0,
            }),
        }
        placed[e] = (runs.len() - 1, cursor);
        cursor += extent.length;
        start += extent.length;
    }
    for (i, part) in parts.iter_mut().enumerate() {
        let e = extent_of[i];
        let (run, new_offset) = placed[e];
        part.run = run;
        part.output = runs[run].output;
        part.new_offset = new_offset + (part.offset - extents[e].offset);
    }
    parts.sort_by_key(|p| (p.run, p.new_offset, p.size));
    let mut next = 0;
    for (r, run) in runs.iter_mut().enumerate() {
        let first = next;
        while parts.get(next).is_some_and(|p| p.run == r) {
            next += 1;
        }
        run.parts = first..next;
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
/// order of their new offsets; they may overlap.
struct Verifier<'a> {
    parts: &'a [Part],
    /// The next part to start checking.
    next: usize,
    /// The parts being checked, and the hash of what's been seen of each.
    open: Vec<(usize, PartHash)>,
    /// Offset of the next byte in the blob.
    pos: u64,
    /// The part that failed its check, if one has.
    failed: Option<usize>,
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
            open: Vec::new(),
            pos: 0,
            failed: None,
        }
    }

    /// Takes the next `data` of the blob.
    fn update(&mut self, data: &[u8]) {
        if self.failed.is_some() {
            return;
        }
        let parts = self.parts;
        let (start, end) = (self.pos, self.pos + data.len() as u64);
        // Open the parts that start by the end of `data` (an empty part at its
        // very end too, so that it ends here).
        while let Some(part) = parts.get(self.next)
            && part.new_offset <= end
        {
            self.open.push((self.next, PartHash::new(Some(part))));
            self.next += 1;
        }
        for (i, hash) in &mut self.open {
            let part = &parts[*i];
            let from = part.new_offset.max(start);
            let to = (part.new_offset + part.size).min(end);
            if from < to {
                hash.update(&data[(from - start) as usize..(to - start) as usize]);
            }
        }
        // Check the parts that end by the end of `data`.
        let mut k = 0;
        while k < self.open.len() {
            let part = &parts[self.open[k].0];
            if part.new_offset + part.size > end {
                k += 1;
                continue;
            }
            let (i, hash) = self.open.remove(k);
            if !hash.matches(part) {
                self.failed = Some(i);
                return;
            }
        }
        self.pos = end;
    }

    fn finish(mut self) -> Result<(), String> {
        // Empty parts at the very end see no data, so they end here.
        self.update(&[]);
        if let Some(i) = self.failed {
            let part = &self.parts[i];
            return Err(format!(
                "part {} doesn't match its checksum at offset {}",
                part.id, part.new_offset
            ));
        }
        match self.open.first().map(|(i, _)| *i).or_else(|| {
            (self.next < self.parts.len()).then_some(self.next)
        }) {
            None => Ok(()),
            Some(i) => Err(format!("part {} is cut short", self.parts[i].id)),
        }
    }
}

/// The transaction that ends a job: commits the new blobs, moves each part
/// that's still where the job found it into its new blob, and drops the sources
/// and new blobs that nothing references anymore. A source that something
/// still references (a copy made meanwhile) keeps the bytes that moved out of
/// it as garbage. Releases the leases on the sources that remain.
async fn commit(
    app: &Arc<App>,
    sources: &[Uuid],
    written: &[Written],
    parts: &[Part],
) -> anyhow::Result<()> {
    let mut client = app.pool.get().await?;
    for attempt in 0..db::MAX_TX_ATTEMPTS {
        db::backoff(attempt).await;
        match try_commit(&mut client, sources, written, parts).await {
            Ok(reap) => {
                reap_blobs(app, reap);
                return Ok(());
            }
            Err(CommitError::Db(e)) if db::is_conflict(&e) => continue,
            Err(CommitError::Db(e)) => return Err(e.into()),
            Err(CommitError::MissingLocations(present)) => {
                anyhow::bail!("only {present} replicas of a new blob reported a location");
            }
        }
    }
    anyhow::bail!("commit kept conflicting with concurrent ones")
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
    tx.execute(
        "UPDATE parts p SET blob_id = m.new_blob, blob_offset = m.new_offset
         FROM unnest($1::bigint[], $2::uuid[], $3::bigint[], $4::uuid[], $5::bigint[])
             AS m(id, old_blob, old_offset, new_blob, new_offset)
         WHERE p.id = m.id AND p.blob_id = m.old_blob AND p.blob_offset = m.old_offset",
        &[&ids, &old_blobs, &old_offsets, &new_blobs, &new_offsets],
    )
    .await?;
    // Whatever didn't move into a new blob (its part was deleted meanwhile) is
    // garbage there, and so is whatever moved out of a source that remains.
    let mut touched = sources.to_vec();
    touched.extend(written.iter().map(|w| w.blob_id));
    refresh_dead_size(&tx, &touched).await?;
    let reap = drop_unreferenced_blobs(&tx, &touched).await?;
    tx.execute(
        "UPDATE blobs SET pack_lease_until = NULL WHERE blob_id = ANY($1)",
        &[&sources],
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
            run: 0,
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
    fn shared_bytes_are_laid_out_once() {
        // Part 2 is a copy of part 1, and part 3 of the end of it.
        let mut parts = vec![
            part(1, 1, 0, b"abcd", false),
            part(4, 2, 0, b"xyz", false),
            part(2, 1, 0, b"abcd", false),
            part(3, 1, 2, b"cd", false),
        ];
        let runs = lay_out(&mut parts, 100);
        let placed: Vec<(i64, u64)> = parts.iter().map(|p| (p.id, p.new_offset)).collect();
        // Sorted by place; the copies share the bytes of part 1.
        assert_eq!(placed, [(1, 0), (2, 0), (3, 2), (4, 4)]);
        let shape: Vec<(u128, u64, u64, std::ops::Range<usize>)> = runs
            .iter()
            .map(|r| (r.blob_id.as_u128(), r.offset, r.length, r.parts.clone()))
            .collect();
        assert_eq!(shape, [(1, 0, 4, 0..3), (2, 0, 3, 3..4)]);
    }

    #[test]
    fn verifier_checks_overlapping_parts() {
        let mut parts = vec![
            part(1, 1, 0, b"abcd", false),
            part(2, 1, 0, b"abcd", true),
            part(3, 1, 2, b"cd", false),
            part(4, 2, 0, b"xyz", false),
        ];
        lay_out(&mut parts, 100);
        for chunk in [1, 2, 3, 100] {
            assert_eq!(check(&parts, b"abcdxyz", chunk), Ok(()), "chunk {chunk}");
        }
        assert!(check(&parts, b"abcexyz", 2).unwrap_err().contains("doesn't match"));
        assert!(check(&parts, b"abcdxy", 2).unwrap_err().contains("cut short"));
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
