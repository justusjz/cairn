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

use std::sync::Arc;
use std::time::Duration;

use hyper::body::{Bytes, Frame};
use uuid::Uuid;

use crate::db::Cached;
use crate::{
    App, ShardWrite,
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
    /// Shards moved, and their bytes.
    pub moved: u64,
    pub bytes: u64,
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
        self.moved + self.waiting + self.failed + self.upgraded + self.removed == 0
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "moved {} shards ({} bytes), {} waiting for a node to move to, {} failed; \
             upgraded {} blobs from before checksums; {} nodes removed",
            self.moved, self.bytes, self.waiting, self.failed, self.upgraded, self.removed
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

/// Moves the shards there are to move, until every blob with some has been
/// claimed (those still with shards to move are claimed again a minute
/// later, by the next pass).
pub async fn pass(app: &Arc<App>) -> anyhow::Result<Report> {
    let mut report = Report::default();
    report.removed += finish_removals(app).await?;
    let client = app.pool.get().await?;
    let minutes = crate::settings::REPAIR_AFTER.get(&client).await?;
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
            let done = match move_blob(app, blob_id, after, &mut report).await {
                Ok(done) => done,
                Err(e) => {
                    eprintln!("mover: blob {blob_id}: {e:#}");
                    report.failed += 1;
                    false
                }
            };
            // Done: let go of it; else try it again in a while.
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
        }
    }
    report.removed += finish_removals(app).await?;
    Ok(report)
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
/// down for longer than `after` seconds). Whether all of them moved.
async fn move_blob(app: &Arc<App>, blob_id: Uuid, after: Option<f64>, report: &mut Report) -> anyhow::Result<bool> {
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
        return Ok(true); // deleted meanwhile
    };
    let mut holders: Vec<Holder> = client
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
    drop(client);
    let Some(layout) = layout_at(&blob, 0) else {
        crate::packer::upgrade_blob(app, blob_id).await?;
        report.upgraded += 1;
        return Ok(true);
    };
    let crcs: Vec<i64> = blob.get(5);
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
        match move_shard(app, blob_id, layout, &holders, i, &target, crc).await {
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

/// Moves the shard of `holders[i]` to `target`: streams its bytes there,
/// verified, where it's stored and its location moved. `crc` is the
/// catalog's CRC of the shard's file.
async fn move_shard(
    app: &Arc<App>,
    blob_id: Uuid,
    layout: Layout,
    holders: &[Holder],
    i: usize,
    target: &Location,
    crc: u64,
) -> anyhow::Result<()> {
    let from = &holders[i];
    let shard = from.location.shard;
    let write = if layout.replicated() {
        ShardWrite::Replica { blob_id, shard }
    } else {
        ShardWrite::Coded(ShardFile { blob_id, layout, shard })
    };
    let (tx, body) = channel_body();
    let replaces = Some(from.location.node);
    let store = async {
        if target.node == app.node {
            crate::write_blob_streaming(app, &write, replaces, body).await
        } else {
            crate::upload_to_peer(&app.peers, &target.peer_url, &write, replaces, body).await
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
