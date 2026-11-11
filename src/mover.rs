//! The mover: moves shards off nodes that are gone, or going, onto other
//! nodes, so that every blob keeps all of its shards (see `shards`).
//!
//! A shard moves when its node is being removed (an operator ran `cairn node
//! remove`: its state isn't `active`), or has been down for longer than the
//! `repair-after` setting, if that's on. A node being removed gets no new
//! shards; once it holds none, it's `removed`. A node that comes back before
//! its shards moved keeps them; the files of those that did move are reaped,
//! or left to the GC's sweep.
//!
//! Every node runs a mover, as it runs a scrubber: it claims a batch of blobs
//! with shards to move, the blobs with the fewest live shards beyond those
//! their data needs first, under the packer's lease (so that packing and
//! moving never work on one blob at once), and moves their shards one by one,
//! as fast as it can: data at risk comes first.
//!
//! A shard moves to an active, live node that holds no shard of its blob, the
//! one with the most free space. Its bytes come from its node while that's
//! live (draining it), else from the blob's other shards: a replicated blob's
//! are copies of it, a coded blob's rows are decoded (`blobs::reconstruct`).
//! Either way they're verified on the way. The new node stores the shard as a
//! writer's sink does, and then moves the location to itself, in one
//! transaction that checks the file is the one the catalog describes
//! (`cairn_move_shard`). A crash leaves the old location as it was, and an
//! orphan file for the GC. Then the mover reaps the old file.
//!
//! Blobs from before checksums can't be verified as they're moved: the
//! packer's upgrade rewrites them instead, onto active nodes.
//!
//! The mover also gives every replicated blob as many copies as the
//! `parity-shards` setting says, once it's set (nodes that go by their own
//! `--replication-factor` may disagree): it adds copies, those with the
//! fewest first, as a move does, and drops those beyond, from nodes being
//! removed or down first, then from the fullest. A coded blob's parity
//! shards can't be added or dropped like that (the code's parity shards
//! differ with their number), so the packer rewrites it instead, and the
//! replicated blobs it's about to code too (see `packer::Layouts`).

use std::sync::Arc;
use std::time::Duration;

use hyper::body::{Bytes, Frame};
use uuid::Uuid;

use crate::db::Cached;
use crate::{
    App, Placement, ShardWrite,
    blob_file::{self, ShardFile},
    blobs::{BlobSlice, LAYOUT_COLUMNS, LOCATION_COLUMNS, Location, layout_at, location_at},
    body::{FrameSender, channel_body},
    checksum::BlobSummer,
    shards::Layout,
};

/// How many blobs the mover claims at a time.
const BATCH: i32 = 16;
/// How long a claim holds a blob: as long as moving its shards may take.
const LEASE: Duration = Duration::from_secs(3600);
/// How soon a blob whose shards couldn't all be moved is tried again: when a
/// node was missing to move one to, or a move failed.
const RETRY: Duration = Duration::from_secs(60);
/// How long the mover waits before looking again once there's nothing to do.
const IDLE: Duration = Duration::from_secs(60);

/// What a pass did.
#[derive(Default, Debug)]
pub struct Report {
    /// Shards moved, and copies added; their bytes.
    pub moved: u64,
    pub added: u64,
    pub bytes: u64,
    /// Copies dropped.
    pub dropped: u64,
    /// Shards left where they are for want of a node to move them to.
    pub waiting: u64,
    /// Moves that failed, which are tried again.
    pub failed: u64,
    /// Blobs from before checksums, rewritten by the packer's upgrade.
    pub upgraded: u64,
    /// Nodes that finished being removed.
    pub removed: u64,
}

impl Report {
    pub fn is_empty(&self) -> bool {
        self.moved + self.added + self.dropped + self.waiting + self.failed + self.upgraded + self.removed == 0
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "moved {} shards and added {} copies ({} bytes), dropped {} copies, \
             {} waiting for a node, {} failed; \
             upgraded {} blobs from before checksums; {} nodes removed",
            self.moved, self.added, self.bytes, self.dropped, self.waiting, self.failed, self.upgraded,
            self.removed
        )
    }
}

/// The background mover: moves shards for as long as the node runs.
pub async fn run(app: Arc<App>) {
    loop {
        let task_app = app.clone();
        // A task of its own, so that a panic (a bug) fails this pass, rather
        // than ending the mover on this node.
        let result = tokio::spawn(async move { pass(&task_app).await }).await;
        match result {
            Ok(Ok(report)) if !report.is_empty() => eprintln!("mover: {report}"),
            Ok(Ok(_)) => {}
            Ok(Err(e)) => eprintln!("mover: pass failed: {e:#}"),
            Err(e) => eprintln!("mover: pass failed: {e}"),
        }
        tokio::time::sleep(IDLE).await;
    }
}

/// Moves the shards there are to move, and then adds and drops the copies
/// there are to add and drop, until every blob with some has been claimed
/// (those still with some are claimed again a minute later, by the next
/// pass).
pub async fn pass(app: &Arc<App>) -> anyhow::Result<Report> {
    let mut report = Report::default();
    report.removed += finish_removals(app).await?;
    let client = app.pool.get().await?;
    let minutes = crate::settings::REPAIR_AFTER.get(&client).await?;
    let parity_shards = crate::settings::PARITY_SHARDS.get_set(&client).await?.map(|m| m as u32);
    drop(client);
    // NULL: never, for a node that's merely down.
    let after = (minutes > 0).then_some(minutes as f64 * 60.0);
    loop {
        let blobs: Vec<Uuid> = app
            .pool
            .get()
            .await?
            .query_one_cached(
                "SELECT pg_temp.cairn_claim_moves($1, $2, $3)",
                &[&after, &BATCH, &LEASE.as_secs_f64()],
            )
            .await?
            .get(0);
        if blobs.is_empty() {
            break;
        }
        for blob_id in blobs {
            let done = move_blob(app, blob_id, after, parity_shards, &mut report).await;
            release(app, blob_id, done, &mut report).await?;
        }
    }
    copies(app, &mut report).await?;
    report.removed += finish_removals(app).await?;
    Ok(report)
}

/// Lets go of a blob the mover claimed once it's `done` with it, or else
/// leases it for a while, to try it again then.
async fn release(app: &App, blob_id: Uuid, done: anyhow::Result<bool>, report: &mut Report) -> anyhow::Result<()> {
    let done = match done {
        Ok(done) => done,
        Err(e) => {
            eprintln!("mover: blob {blob_id}: {e:#}");
            report.failed += 1;
            false
        }
    };
    let retry = (!done).then(|| RETRY.as_secs_f64());
    app.pool
        .get()
        .await?
        .execute_cached(
            "UPDATE blobs SET pack_lease_until = NOW() + make_interval(secs => $2)
             WHERE blob_id = $1",
            &[&blob_id, &retry],
        )
        .await?;
    Ok(())
}

/// Adds and drops copies of replicated blobs, until each has as many as the
/// `parity-shards` setting says, if it's set: but for those the packer is
/// to code (see `packer::Layouts`), which it rewrites with their parity
/// shards anyway.
async fn copies(app: &Arc<App>, report: &mut Report) -> anyhow::Result<()> {
    let client = app.pool.get().await?;
    let setting = crate::settings::PARITY_SHARDS.get_set(&client).await?;
    drop(client);
    let Some(parity_shards) = setting else {
        return Ok(());
    };
    let parity_shards = parity_shards as u32;
    let layouts = crate::packer::layouts(app).await?;
    let coded_above = layouts.and_then(|l| l.coding()).map(|_| app.pack.small_size as i64);
    loop {
        let blobs: Vec<Uuid> = app
            .pool
            .get()
            .await?
            .query_one_cached(
                "SELECT pg_temp.cairn_claim_copies($1, $2, $3, $4)",
                &[&(parity_shards as i16), &coded_above, &BATCH, &LEASE.as_secs_f64()],
            )
            .await?
            .get(0);
        if blobs.is_empty() {
            return Ok(());
        }
        for blob_id in blobs {
            let done = adjust_copies(app, blob_id, parity_shards, report).await;
            release(app, blob_id, done, report).await?;
        }
    }
}

/// Adds or drops copies of replicated blob `blob_id` until it has
/// `parity_shards` besides the first. Whether it has.
async fn adjust_copies(app: &Arc<App>, blob_id: Uuid, parity_shards: u32, report: &mut Report) -> anyhow::Result<bool> {
    let Some((layout, crcs, mut holders)) = load(app, blob_id, None).await? else {
        return Ok(true); // deleted meanwhile
    };
    let Some(mut layout) = layout.filter(Layout::replicated) else {
        return Ok(true); // rewritten meanwhile
    };
    let crc = crcs[0] as u64;
    while layout.parity_shards < parity_shards {
        let taken: Vec<i32> = holders.iter().map(|h| h.location.node).collect();
        let Some(target) = choose_target(app, &taken, layout.shards()).await? else {
            report.waiting += 1;
            return Ok(false);
        };
        let Some(source) = holders.iter().position(|h| h.live) else {
            anyhow::bail!("no copy is on a live node");
        };
        let placement = Placement::Add {
            parity_shards: layout.parity_shards,
        };
        if let Err(e) = place_shard(app, blob_id, layout, &holders, source, &target, crc, placement).await {
            eprintln!("mover: blob {blob_id}: adding a copy: {e:#}");
            report.failed += 1;
            return Ok(false);
        }
        eprintln!("mover: blob {blob_id}: added copy {} on node {}", target.shard, target.node);
        report.added += 1;
        report.bytes += layout.size;
        layout.parity_shards += 1;
        holders.push(Holder {
            location: target,
            live: true,
            moving: false,
        });
    }
    while layout.parity_shards > parity_shards {
        // A copy on a node being removed, or down, first: it would be moved
        // otherwise. Then the fullest node's.
        let node: i32 = app
            .pool
            .get()
            .await?
            .query_one_cached(
                "SELECT bl.node FROM blob_locations bl JOIN nodes n ON n.id = bl.node
                 WHERE bl.blob_id = $1
                 ORDER BY n.state <> 'active' DESC, n.last_seen > NOW() - INTERVAL '10 seconds',
                          n.free_space, n.id
                 LIMIT 1",
                &[&blob_id],
            )
            .await?
            .get(0);
        if !drop_copy(app, blob_id, node, layout.parity_shards, report).await? {
            return Ok(false);
        }
        layout.parity_shards -= 1;
    }
    Ok(true)
}

/// Drops node `node`'s copy of replicated blob `blob_id`, which has
/// `parity_shards` parity shards, and reaps its file. Whether it was
/// dropped: if the blob changed meanwhile, it's read afresh when it's tried
/// again.
async fn drop_copy(app: &Arc<App>, blob_id: Uuid, node: i32, parity_shards: u32, report: &mut Report) -> anyhow::Result<bool> {
    let row = app
        .pool
        .get()
        .await?
        .query_one_cached(
            "SELECT status, reap_peer FROM pg_temp.cairn_drop_copy($1, $2, $3)",
            &[&blob_id, &node, &(parity_shards as i16)],
        )
        .await?;
    let status: String = row.get(0);
    if status != "dropped" {
        eprintln!("mover: blob {blob_id}: the copy on node {node} wasn't dropped: {status}");
        return Ok(false);
    }
    eprintln!("mover: blob {blob_id}: dropped the copy on node {node}");
    report.dropped += 1;
    crate::blobs::reap_blobs(app, vec![(blob_id, node, row.get(1))]);
    Ok(true)
}

/// A blob's layout (`None` from before checksums) and shards' CRCs, and its
/// shards, in order: `None` if it's gone. Those to move are those on nodes
/// being removed, or down for longer than `after` seconds, if given.
async fn load(
    app: &App,
    blob_id: Uuid,
    after: Option<f64>,
) -> anyhow::Result<Option<(Option<Layout>, Vec<i64>, Vec<Holder>)>> {
    let client = app.pool.get().await?;
    // The lease runs from now: the batch's earlier blobs may have taken long.
    client
        .execute_cached(
            "UPDATE blobs SET pack_lease_until = NOW() + make_interval(secs => $2) WHERE blob_id = $1",
            &[&blob_id, &LEASE.as_secs_f64()],
        )
        .await?;
    let Some(blob) = client
        .query_opt_cached(
            &format!("SELECT {LAYOUT_COLUMNS}, b.shard_crcs FROM blobs b WHERE b.blob_id = $1"),
            &[&blob_id],
        )
        .await?
    else {
        return Ok(None);
    };
    let holders: Vec<Holder> = client
        .query_cached(
            &format!(
                "SELECT {LOCATION_COLUMNS}, n.last_seen > NOW() - INTERVAL '10 seconds',
                        n.state <> 'active'
                            OR coalesce(n.last_seen < NOW() - make_interval(secs => $2), false)
                 FROM blob_locations bl JOIN nodes n ON n.id = bl.node
                 WHERE bl.blob_id = $1
                 ORDER BY bl.shard"
            ),
            &[&blob_id, &after],
        )
        .await?
        .iter()
        .map(|r| Holder {
            location: location_at(r, 0),
            live: r.get(3),
            moving: r.get(4),
        })
        .collect();
    // None for a blob from before checksums.
    let crcs: Option<Vec<i64>> = blob.get(5);
    Ok(Some((layout_at(&blob, 0), crcs.unwrap_or_default(), holders)))
}

/// Marks the nodes being removed that hold no shard anymore as removed. How
/// many. A node holds none only once the uploads that may have chosen it
/// before it was being removed are done: their shards' locations are only
/// recorded once they're written. (Pending blobs are deleted after a day.)
async fn finish_removals(app: &App) -> anyhow::Result<u64> {
    let client = app.pool.get().await?;
    Ok(client
        .execute_cached(
            "UPDATE nodes SET state = 'removed', state_since = NOW()
             WHERE state = 'removing'
               AND NOT EXISTS (SELECT 1 FROM blob_locations bl WHERE bl.node = nodes.id)
               AND NOT EXISTS (SELECT 1 FROM blobs b WHERE b.state = 'pending'
                               AND b.created_at < nodes.state_since + INTERVAL '1 minute')",
            &[],
        )
        .await?)
}

/// A shard of the blob, where it is, and whether its node is live, and
/// whether the shard is to move.
struct Holder {
    location: Location,
    live: bool,
    moving: bool,
}

/// Moves the shards of `blob_id` that are to move (on nodes being removed, or
/// down for longer than `after` seconds). Whether all of them moved. A
/// replicated blob with more copies than `parity_shards` (the setting, if
/// it's set) has those to move dropped instead, as many as it has too many.
async fn move_blob(
    app: &Arc<App>,
    blob_id: Uuid,
    after: Option<f64>,
    parity_shards: Option<u32>,
    report: &mut Report,
) -> anyhow::Result<bool> {
    let Some((layout, mut crcs, mut holders)) = load(app, blob_id, after).await? else {
        return Ok(true); // deleted meanwhile
    };
    let Some(mut layout) = layout else {
        crate::packer::upgrade_blob(app, blob_id).await?;
        report.upgraded += 1;
        return Ok(true);
    };
    if layout.replicated()
        && let Some(parity_shards) = parity_shards
    {
        let surplus = layout.parity_shards.saturating_sub(parity_shards);
        let leaving: Vec<i32> = holders.iter().filter(|h| h.moving).map(|h| h.location.node).take(surplus as usize).collect();
        for node in leaving {
            if !drop_copy(app, blob_id, node, layout.parity_shards, report).await? {
                return Ok(false);
            }
            layout.parity_shards -= 1;
        }
        // The copies have new numbers.
        let Some((_, now_crcs, now_holders)) = load(app, blob_id, after).await? else {
            return Ok(true);
        };
        (crcs, holders) = (now_crcs, now_holders);
    }
    let mut done = true;
    // Nodes that shards left in this job: none moves back to one, whose file
    // of the blob may still be on its way to being reaped.
    let mut left: Vec<i32> = Vec::new();
    for i in 0..holders.len() {
        if !holders[i].moving {
            continue;
        }
        let taken: Vec<i32> = holders.iter().map(|h| h.location.node).chain(left.iter().copied()).collect();
        let Some(target) = choose_target(app, &taken, holders[i].location.shard).await? else {
            report.waiting += 1;
            done = false;
            continue;
        };
        let crc = crcs[holders[i].location.shard as usize] as u64;
        let placement = Placement::Move {
            from: holders[i].location.node,
        };
        match place_shard(app, blob_id, layout, &holders, i, &target, crc, placement).await {
            Ok(()) => {
                let from = holders[i].location.clone();
                eprintln!(
                    "mover: blob {blob_id}: moved shard {} from node {} to node {}",
                    from.shard, from.node, target.node
                );
                report.moved += 1;
                report.bytes += layout.shard_size(from.shard);
                left.push(from.node);
                crate::blobs::reap_blobs(app, vec![(blob_id, from.node, from.peer_url)]);
                holders[i] = Holder {
                    location: target,
                    live: true,
                    moving: false,
                };
            }
            Err(e) => {
                // It may have moved after all (an answer lost on the way
                // back): what's where is read afresh when the blob is tried
                // again.
                eprintln!("mover: blob {blob_id}: moving shard {}: {e:#}", holders[i].location.shard);
                report.failed += 1;
                return Ok(false);
            }
        }
    }
    Ok(done)
}

/// The node to move shard `shard` of a blob to: an active, live one that
/// holds none of the blob's (`taken`), the one with the most free space.
async fn choose_target(app: &App, taken: &[i32], shard: u32) -> anyhow::Result<Option<Location>> {
    let client = app.pool.get().await?;
    let row = client
        .query_opt_cached(
            "SELECT id, peer_url FROM nodes
             WHERE state = 'active' AND last_seen > NOW() - INTERVAL '10 seconds'
               AND id <> ALL($1)
             ORDER BY free_space DESC LIMIT 1",
            &[&taken],
        )
        .await?;
    Ok(row.map(|r| Location {
        node: r.get(0),
        peer_url: r.get(1),
        shard,
    }))
}

/// Places the shard of `holders[i]` on `target`, as `placement` says (it's
/// moved there, or is a further copy): streams its bytes there, verified,
/// where it's stored and its location recorded. `crc` is the catalog's CRC
/// of the shard's file.
#[allow(clippy::too_many_arguments)]
async fn place_shard(
    app: &Arc<App>,
    blob_id: Uuid,
    layout: Layout,
    holders: &[Holder],
    i: usize,
    target: &Location,
    crc: u64,
    placement: Placement,
) -> anyhow::Result<()> {
    let shard = target.shard;
    let write = if layout.replicated() {
        ShardWrite::Replica { blob_id, shard }
    } else {
        ShardWrite::Coded(ShardFile { blob_id, layout, shard })
    };
    let (tx, body) = channel_body();
    let store = async {
        if target.node == app.node {
            crate::write_blob_streaming(app, &write, placement, body).await
        } else {
            crate::upload_to_peer(&app.peers, &target.peer_url, &write, placement, body).await
        }
    };
    let feed = async {
        let result = feed(app, blob_id, layout, holders, i, crc, &tx).await;
        if let Err(e) = &result {
            // The new node mustn't keep a shard cut short.
            let _ = tx.send(Err(std::io::Error::other(format!("{e:#}")))).await;
        }
        drop(tx);
        result
    };
    let (stored, fed) = tokio::join!(store, feed);
    fed?;
    stored?;
    Ok(())
}

/// Sends the shard of `holders[i]`, verified, to `tx`: its data, and for a
/// coded blob, the tables of every shard after it (see `ShardWrite::Coded`).
async fn feed(
    app: &Arc<App>,
    blob_id: Uuid,
    layout: Layout,
    holders: &[Holder],
    i: usize,
    crc: u64,
    tx: &FrameSender,
) -> anyhow::Result<()> {
    let from = &holders[i];
    let shard = from.location.shard;
    // The shard itself first, while its node is live, then the others.
    let mut live: Vec<Location> = holders.iter().filter(|h| h.live).map(|h| h.location.clone()).collect();
    live.sort_by_key(|l| l.node != from.location.node);
    if layout.replicated() {
        // Every shard is the blob.
        let mut slice = BlobSlice {
            blob_id,
            layout: Some(layout),
            locations: live,
            offset: 0,
            length: layout.size,
            part: None,
        };
        crate::blobs::stream_blob_range(app, &mut slice, tx).await?;
        return Ok(());
    }
    let su = layout.stripe_unit;
    let file = ShardFile { blob_id, layout, shard };
    let mut summer = BlobSummer::new(layout.block_size as u32);
    let mut digest = crc64fast_nvme::Digest::new();
    for row in 0..layout.rows() {
        let len = layout.row_len_on(row, shard);
        if len == 0 {
            continue;
        }
        let direct = if from.live {
            crate::blobs::fetch_range(app, &from.location, &file, row * su, len).await.ok()
        } else {
            None
        };
        let cell = match direct {
            Some(cell) => cell,
            None => crate::blobs::reconstruct(app, blob_id, layout, &live, row, shard, (0, len)).await?,
        };
        summer.update(&cell);
        digest.write(&cell);
        if tx.send(Ok(Frame::data(Bytes::from(cell)))).await.is_err() {
            anyhow::bail!("the new node stopped taking the shard");
        }
    }
    let others: Vec<Location> = live.iter().filter(|l| l.shard != shard).cloned().collect();
    let trailer = crate::scrub::repair::trailer(app, &file, &others, summer.finish(), &digest, crc).await?;
    // The new node adds the shard's index and the blob ID itself.
    let tables = trailer[..trailer.len() - blob_file::tail(&file).len()].to_vec();
    if tx.send(Ok(Frame::data(Bytes::from(tables)))).await.is_err() {
        anyhow::bail!("the new node stopped taking the shard");
    }
    Ok(())
}

#[cfg(test)]
mod e2e;
