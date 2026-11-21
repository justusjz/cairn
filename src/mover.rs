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
//! A shard moves to an active, live node that has the blob's pool (see
//! `classes`) and holds no shard of its blob, where the blob stays spread
//! over the nodes' locations (see `placement`), the one with the most free
//! space in that pool among equals. Its bytes come from its node while that's
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
//! The mover also gives every replicated blob as many copies as its storage
//! class says (its own parity shards, or the `parity-shards` setting), once
//! that's settled (nodes that go by their own `--replication-factor` may
//! disagree): it adds copies, those with the
//! fewest first, as a move does, and drops those beyond, from nodes being
//! removed or down first, then from the fullest. A coded blob's parity
//! shards can't be added or dropped like that (the code's parity shards
//! differ with their number), so the packer rewrites it instead, and the
//! replicated blobs it's about to code too (see `packer::Layouts`). A copy
//! to drop is one on a node that's being removed or down, else in the most
//! crowded domain, so that the rest stays spread.
//!
//! And it spreads uneven blobs (see `placement`): those that couldn't be
//! spread over the nodes when they were placed (a region was down), and
//! those that a check of every blob of a pool found uneven, which runs
//! whenever the pool's nodes change (one is added, or removed, or moves):
//! a shard at a time, out of the most crowded domain, while that makes the
//! blob more even, copied from its node as a move from a live node is.
//! What can't be spread yet (the domain it would go to is down) waits,
//! until the live nodes change.

use std::sync::Arc;
use std::time::Duration;

use hyper::body::{Bytes, Frame};
use uuid::Uuid;

use crate::db::Cached;
use crate::{
    App, Placement, PoolNode, ShardWrite,
    blob_file::{self, ShardFile},
    blobs::{BlobSlice, LAYOUT_COLUMNS, LOCATION_COLUMNS, Location, layout_at, location_at},
    body::{FrameSender, channel_body},
    checksum::BlobSummer,
    placement,
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
    /// Shards moved to spread their blobs (see `placement`), and blobs found
    /// uneven by a check of every blob.
    pub spread: u64,
    pub uneven: u64,
}

impl Report {
    pub fn is_empty(&self) -> bool {
        self.moved
            + self.added
            + self.dropped
            + self.waiting
            + self.failed
            + self.upgraded
            + self.removed
            + self.spread
            + self.uneven
            == 0
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "moved {} shards and added {} copies ({} bytes), dropped {} copies, \
             {} waiting for a node, {} failed; \
             upgraded {} blobs from before checksums; {} nodes removed; \
             moved {} shards to spread blobs, found {} blobs uneven",
            self.moved,
            self.added,
            self.bytes,
            self.dropped,
            self.waiting,
            self.failed,
            self.upgraded,
            self.removed,
            self.spread,
            self.uneven
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
    // The classes and settings as they are now.
    crate::refresh_settings(app).await?;
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
            let done = move_blob(app, blob_id, after, &mut report).await;
            release(app, blob_id, done, &mut report).await?;
        }
    }
    copies(app, &mut report).await?;
    spread(app, &mut report).await?;
    report.removed += finish_removals(app).await?;
    Ok(report)
}

/// Lets go of a blob the mover claimed once it's `done` with it, or else
/// leases it for a while, to try it again then.
async fn release(
    app: &App,
    blob_id: Uuid,
    done: anyhow::Result<bool>,
    report: &mut Report,
) -> anyhow::Result<()> {
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

/// Adds and drops copies of replicated blobs, until each has as many as its
/// storage class says, where that's settled (see `App::parity_settled`):
/// but for those the packer is to code (see `packer::Layouts`), which it
/// rewrites with their parity shards anyway.
async fn copies(app: &Arc<App>, report: &mut Report) -> anyhow::Result<()> {
    for class in app.classes.all().values() {
        if app.parity_settled(class) {
            class_copies(app, class, report).await?;
        }
    }
    Ok(())
}

/// `copies`, of class `class`'s blobs.
async fn class_copies(
    app: &Arc<App>,
    class: &crate::classes::Class,
    report: &mut Report,
) -> anyhow::Result<()> {
    let parity_shards = app.parity_shards_of(class);
    let layouts = crate::packer::layouts(app, class).await?;
    let coded_above = layouts
        .and_then(|l| l.coding())
        .map(|_| app.pack.small_size as i64);
    loop {
        let blobs: Vec<Uuid> = app
            .pool
            .get()
            .await?
            .query_one_cached(
                "SELECT pg_temp.cairn_claim_copies($1, $2, $3, $4, $5)",
                &[
                    &class.name,
                    &(parity_shards as i16),
                    &coded_above,
                    &BATCH,
                    &LEASE.as_secs_f64(),
                ],
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
async fn adjust_copies(
    app: &Arc<App>,
    blob_id: Uuid,
    parity_shards: u32,
    report: &mut Report,
) -> anyhow::Result<bool> {
    let Some(Loaded {
        layout,
        crcs,
        mut holders,
        pool,
        ..
    }) = load(app, blob_id, None).await?
    else {
        return Ok(true); // deleted meanwhile
    };
    let Some(mut layout) = layout.filter(Layout::replicated) else {
        return Ok(true); // rewritten meanwhile
    };
    let crc = crcs[0] as u64;
    while layout.parity_shards < parity_shards {
        let taken: Vec<i32> = holders.iter().map(|h| h.location.node).collect();
        let Some(target) = choose_target(app, &pool, &taken, &taken, layout.shards()).await? else {
            report.waiting += 1;
            return Ok(false);
        };
        let Some(source) = holders.iter().position(|h| h.live) else {
            anyhow::bail!("no copy is on a live node");
        };
        let placement = Placement::Add {
            parity_shards: layout.parity_shards,
        };
        if let Err(e) = place_shard(
            app, blob_id, layout, &holders, source, &target, crc, placement,
        )
        .await
        {
            eprintln!("mover: blob {blob_id}: adding a copy: {e:#}");
            report.failed += 1;
            return Ok(false);
        }
        eprintln!(
            "mover: blob {blob_id}: added copy {} on node {}",
            target.shard, target.node
        );
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
        let nodes = Nodes::load(app, &pool).await?;
        let node = copy_to_drop(&nodes, &holders);
        if !drop_copy(app, blob_id, node, layout.parity_shards, report).await? {
            return Ok(false);
        }
        layout.parity_shards -= 1;
        holders.retain(|h| h.location.node != node);
    }
    mark_if_uneven(app, blob_id, &pool, &holders).await?;
    Ok(true)
}

/// Drops node `node`'s copy of replicated blob `blob_id`, which has
/// `parity_shards` parity shards, and reaps its file. Whether it was
/// dropped: if the blob changed meanwhile, it's read afresh when it's tried
/// again.
async fn drop_copy(
    app: &Arc<App>,
    blob_id: Uuid,
    node: i32,
    parity_shards: u32,
    report: &mut Report,
) -> anyhow::Result<bool> {
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

/// A blob as the mover finds it.
struct Loaded {
    /// `None` from before checksums.
    layout: Option<Layout>,
    /// Its shards' CRCs.
    crcs: Vec<i64>,
    /// Its shards, in order.
    holders: Vec<Holder>,
    /// Its storage class, and the pool its shards are in.
    class: String,
    pool: String,
}

/// A blob, as the mover finds it: `None` if it's gone. The shards to move
/// are those on nodes being removed, or down for longer than `after`
/// seconds, if given.
async fn load(app: &App, blob_id: Uuid, after: Option<f64>) -> anyhow::Result<Option<Loaded>> {
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
            &format!("SELECT {LAYOUT_COLUMNS}, b.shard_crcs, b.storage_class, b.pool FROM blobs b WHERE b.blob_id = $1"),
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
                 JOIN blobs b ON b.blob_id = bl.blob_id
                 WHERE bl.blob_id = $1
                 ORDER BY bl.shard"
            ),
            &[&blob_id, &after],
        )
        .await?
        .iter()
        .map(|r| Holder {
            location: location_at(r, 0),
            live: r.get(4),
            moving: r.get(5),
        })
        .collect();
    // None for a blob from before checksums.
    let crcs: Option<Vec<i64>> = blob.get(5);
    Ok(Some(Loaded {
        layout: layout_at(&blob, 0),
        crcs: crcs.unwrap_or_default(),
        holders,
        class: blob.get(6),
        pool: blob.get(7),
    }))
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
/// replicated blob with more copies than its class's parity shards (where
/// that's settled) has those to move dropped instead, as many as it has too
/// many.
async fn move_blob(
    app: &Arc<App>,
    blob_id: Uuid,
    after: Option<f64>,
    report: &mut Report,
) -> anyhow::Result<bool> {
    let Some(Loaded {
        layout,
        mut crcs,
        mut holders,
        class,
        pool,
    }) = load(app, blob_id, after).await?
    else {
        return Ok(true); // deleted meanwhile
    };
    let class = app.classes.get(&class);
    let parity_shards = app
        .parity_settled(&class)
        .then(|| app.parity_shards_of(&class));
    let Some(mut layout) = layout else {
        crate::packer::upgrade_blob(app, blob_id).await?;
        report.upgraded += 1;
        return Ok(true);
    };
    if layout.replicated()
        && let Some(parity_shards) = parity_shards
    {
        let surplus = layout.parity_shards.saturating_sub(parity_shards);
        let leaving: Vec<i32> = holders
            .iter()
            .filter(|h| h.moving)
            .map(|h| h.location.node)
            .take(surplus as usize)
            .collect();
        for node in leaving {
            if !drop_copy(app, blob_id, node, layout.parity_shards, report).await? {
                return Ok(false);
            }
            layout.parity_shards -= 1;
        }
        // The copies have new numbers.
        let Some(now) = load(app, blob_id, after).await? else {
            return Ok(true);
        };
        (crcs, holders) = (now.crcs, now.holders);
    }
    let mut done = true;
    // Nodes that shards left in this job: none moves back to one, whose file
    // of the blob may still be on its way to being reaped.
    let mut left: Vec<i32> = Vec::new();
    for i in 0..holders.len() {
        if !holders[i].moving {
            continue;
        }
        let taken: Vec<i32> = holders
            .iter()
            .map(|h| h.location.node)
            .chain(left.iter().copied())
            .collect();
        // Spread among the shards that stay.
        let staying: Vec<i32> = holders
            .iter()
            .filter(|h| !h.moving)
            .map(|h| h.location.node)
            .collect();
        let shard = holders[i].location.shard;
        let Some(target) = choose_target(app, &pool, &staying, &taken, shard).await? else {
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
                eprintln!(
                    "mover: blob {blob_id}: moving shard {}: {e:#}",
                    holders[i].location.shard
                );
                report.failed += 1;
                return Ok(false);
            }
        }
    }
    mark_if_uneven(app, blob_id, &pool, &holders).await?;
    Ok(done)
}

/// The nodes of a pool (see `pool_nodes`), as the mover places shards
/// on them.
struct Nodes {
    all: Vec<PoolNode>,
    /// The active ones, which blobs are spread over.
    active: Vec<placement::Node>,
}

impl Nodes {
    async fn load(app: &App, pool: &str) -> anyhow::Result<Nodes> {
        let all = crate::pool_nodes(&app.pool.get().await?, pool).await?;
        let active = crate::active_nodes(&all);
        Ok(Nodes { all, active })
    }

    /// Node `id`, as placement sees it: one that's lost the pool meanwhile
    /// has no location, and is down.
    fn get(&self, id: i32) -> placement::Node {
        self.all
            .iter()
            .find(|n| n.node.id == id)
            .map(|n| n.node.clone())
            .unwrap_or_else(|| placement::Node::new(id, String::new(), "", false, 0))
    }

    /// The nodes of `ids`, as placement sees them.
    fn of(&self, ids: impl IntoIterator<Item = i32>) -> Vec<placement::Node> {
        ids.into_iter().map(|id| self.get(id)).collect()
    }
}

/// The node to place shard `shard` of a blob in pool `pool` on: an active,
/// live one with the pool that isn't one of `exclude` (those holding the
/// blob's shards, and that shards left), where the blob stays spread with
/// its shards on `held` (see `placement::choose`); among equals, the one
/// with the most free space in the pool.
async fn choose_target(
    app: &App,
    pool: &str,
    held: &[i32],
    exclude: &[i32],
    shard: u32,
) -> anyhow::Result<Option<Location>> {
    let nodes = Nodes::load(app, pool).await?;
    let held = nodes.of(held.iter().copied());
    let held: Vec<&placement::Node> = held.iter().collect();
    Ok(
        placement::choose(&nodes.active, &held, exclude).map(|n| Location {
            node: n.id,
            peer_url: n.peer_url.clone(),
            shard,
            pool: pool.to_owned(),
        }),
    )
}

/// The copy of a replicated blob to drop, of those on `holders`: one on a
/// node being removed, or down, first, since it would be moved otherwise;
/// else one in the most crowded domain (see `placement::crowded_copy`),
/// the fullest node's among equals.
fn copy_to_drop(nodes: &Nodes, holders: &[Holder]) -> i32 {
    let state = |id: i32| nodes.all.iter().find(|n| n.node.id == id);
    let leaving = holders
        .iter()
        .map(|h| h.location.node)
        .min_by_key(|&id| match state(id) {
            Some(n) if !n.active => 0,
            Some(n) if !n.node.live => 1,
            None => 1,
            Some(_) => 2,
        })
        .filter(|&id| !matches!(state(id), Some(n) if n.active && n.node.live));
    if let Some(id) = leaving {
        return id;
    }
    let mut held = nodes.of(holders.iter().map(|h| h.location.node));
    held.sort_by_key(|n| n.free_space);
    let held: Vec<&placement::Node> = held.iter().collect();
    placement::crowded_copy(&held).expect("a blob with copies to drop has copies")
}

/// Marks blob `blob_id`, in pool `pool` with its shards on `holders`,
/// uneven if it isn't spread over the pool's nodes (see `placement`):
/// after shards moved, which may not have been spread for want of nodes.
async fn mark_if_uneven(
    app: &App,
    blob_id: Uuid,
    pool: &str,
    holders: &[Holder],
) -> anyhow::Result<()> {
    let nodes = Nodes::load(app, pool).await?;
    let held = nodes.of(holders.iter().map(|h| h.location.node));
    let held: Vec<&placement::Node> = held.iter().collect();
    if placement::uneven(&nodes.active, &held) {
        app.pool
            .get()
            .await?
            .execute_cached(
                "UPDATE blobs SET uneven = true WHERE blob_id = $1",
                &[&blob_id],
            )
            .await?;
    }
    Ok(())
}

/// How many blobs a check of every blob's spread reads at a time.
const CHECK_BATCH: i64 = 1000;

/// Checks the spread of every blob of every pool whose nodes changed since
/// its blobs were last checked, and then spreads the uneven blobs of
/// every pool (see `placement`).
async fn spread(app: &Arc<App>, report: &mut Report) -> anyhow::Result<()> {
    let pools: Vec<String> = app
        .pool
        .get()
        .await?
        .query_cached("SELECT DISTINCT pool FROM node_pools ORDER BY pool", &[])
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    for pool in pools {
        report.uneven += check_pool(app, &pool).await?;
        spread_pool(app, &pool, report).await?;
    }
    Ok(())
}

/// Checks the spread of the blobs of pool `pool` against its active nodes,
/// unless they were all checked against these nodes already, and marks
/// those that aren't spread uneven. How many it marked. One node checks
/// a pool at a time, a batch at a time, each with the progress it records;
/// a node that finds another at it leaves it be.
///
/// Pending blobs are marked as they're found, whatever their spread: they
/// were placed for the nodes as they were, and their shards may not all be
/// recorded yet. They're checked again once committed.
async fn check_pool(app: &App, pool: &str) -> anyhow::Result<u64> {
    let mut marked = 0;
    loop {
        let mut client = app.pool.get().await?;
        client
            .execute_cached(
                "INSERT INTO placement_checks (pool) VALUES ($1) ON CONFLICT DO NOTHING",
                &[&pool],
            )
            .await?;
        let tx = client.transaction().await?;
        let Some(check) = tx
            .query_opt_cached(
                "SELECT checked, checking, cursor FROM placement_checks
                 WHERE pool = $1 FOR UPDATE SKIP LOCKED",
                &[&pool],
            )
            .await?
        else {
            return Ok(marked); // another node is at it
        };
        let nodes = crate::pool_nodes(&tx, pool).await?;
        let active = crate::active_nodes(&nodes);
        let topology = placement::topology(&active);
        if check.get::<_, Option<String>>(0).as_deref() == Some(&topology) {
            return Ok(marked);
        }
        let cursor: Option<Uuid> =
            if check.get::<_, Option<String>>(1).as_deref() == Some(&topology) {
                check.get(2)
            } else {
                None
            };
        let blobs = tx
            .query_cached(
                "WITH batch AS (
                     SELECT blob_id, state FROM blobs
                     WHERE pool = $1 AND blob_id > $2 AND state IN ('pending', 'committed')
                     ORDER BY blob_id LIMIT $3
                 )
                 SELECT b.blob_id, b.state = 'pending',
                        ARRAY(SELECT bl.node FROM blob_locations bl WHERE bl.blob_id = b.blob_id)
                 FROM batch b ORDER BY b.blob_id",
                &[&pool, &cursor.unwrap_or(Uuid::nil()), &CHECK_BATCH],
            )
            .await?;
        let by_id = Nodes {
            all: nodes,
            active: Vec::new(),
        };
        let uneven: Vec<Uuid> = blobs
            .iter()
            .filter(|b| {
                let held = by_id.of(b.get::<_, Vec<i32>>(2));
                let held: Vec<&placement::Node> = held.iter().collect();
                b.get::<_, bool>(1) || placement::uneven(&active, &held)
            })
            .map(|b| b.get(0))
            .collect();
        if !uneven.is_empty() {
            // Locked in order of their ids, as every transaction locks blobs.
            tx.execute_cached(
                "UPDATE blobs SET uneven = true WHERE blob_id IN (
                     SELECT blob_id FROM blobs WHERE blob_id = ANY($1)
                     ORDER BY blob_id FOR NO KEY UPDATE)",
                &[&uneven],
            )
            .await?;
            marked += uneven.len() as u64;
        }
        let last: Option<Uuid> = blobs.last().map(|b| b.get(0));
        if (blobs.len() as i64) < CHECK_BATCH {
            tx.execute_cached(
                "UPDATE placement_checks SET checked = $2, checking = NULL, cursor = NULL
                 WHERE pool = $1",
                &[&pool, &topology],
            )
            .await?;
            tx.commit().await?;
            return Ok(marked);
        }
        tx.execute_cached(
            "UPDATE placement_checks SET checking = $2, cursor = $3 WHERE pool = $1",
            &[&pool, &topology, &last],
        )
        .await?;
        tx.commit().await?;
    }
}

/// The nodes of each pool, live ones apart (`placement::topology` of both),
/// as they were when this node last found the pool's uneven blobs
/// impossible to spread any further, by node and pool: until they change,
/// they still are, and aren't tried again.
static STUCK: std::sync::Mutex<Vec<((i32, String), String)>> = std::sync::Mutex::new(Vec::new());

/// Spreads the uneven blobs of pool `pool` (see `spread_blob`), unless
/// that came to nothing for the same live nodes before.
async fn spread_pool(app: &Arc<App>, pool: &str, report: &mut Report) -> anyhow::Result<()> {
    let nodes = Nodes::load(app, pool).await?;
    let live: Vec<placement::Node> = nodes.active.iter().filter(|n| n.live).cloned().collect();
    let now = format!(
        "{}/{}",
        placement::topology(&nodes.active),
        placement::topology(&live)
    );
    let key = (app.node, pool.to_owned());
    if STUCK
        .lock()
        .unwrap()
        .iter()
        .any(|(k, nodes)| *k == key && *nodes == now)
    {
        return Ok(());
    }
    let (spread, waiting) = (report.spread, report.waiting + report.failed);
    loop {
        let blobs: Vec<Uuid> = app
            .pool
            .get()
            .await?
            .query_one_cached(
                "SELECT pg_temp.cairn_claim_spread($1, $2, $3)",
                &[&pool, &BATCH, &LEASE.as_secs_f64()],
            )
            .await?
            .get(0);
        if blobs.is_empty() {
            break;
        }
        for blob_id in blobs {
            let done = spread_blob(app, blob_id, report).await;
            release(app, blob_id, done, report).await?;
        }
    }
    let mut stuck = STUCK.lock().unwrap();
    stuck.retain(|(k, _)| *k != key);
    if report.spread == spread && report.waiting + report.failed > waiting {
        stuck.push((key, now));
    }
    Ok(())
}

/// Spreads uneven blob `blob_id` (see `placement`): moves its shards, one
/// at a time, to the live nodes where that spreads it best, while that
/// spreads it better (see `placement::improvement`). Whether it's spread, and no longer uneven.
async fn spread_blob(app: &Arc<App>, blob_id: Uuid, report: &mut Report) -> anyhow::Result<bool> {
    let Some(Loaded {
        layout,
        crcs,
        mut holders,
        pool,
        ..
    }) = load(app, blob_id, None).await?
    else {
        return Ok(true); // deleted meanwhile
    };
    // A blob from before checksums is placed anew by the packer's upgrade.
    if let Some(layout) = layout {
        // Nodes that shards left in this job, as in `move_blob`.
        let mut left: Vec<i32> = Vec::new();
        loop {
            let nodes = Nodes::load(app, &pool).await?;
            let held = nodes.of(holders.iter().map(|h| h.location.node));
            let held: Vec<&placement::Node> = held.iter().collect();
            let Some(better) = placement::improvement(&nodes.active, &held, &left, true) else {
                if placement::uneven(&nodes.active, &held) {
                    // Only a node that's down would make it better.
                    report.waiting += 1;
                    return Ok(false);
                }
                break;
            };
            let i = holders
                .iter()
                .position(|h| h.location.node == better.from)
                .expect("the shard to move is one of the blob's");
            let to = nodes.get(better.to);
            let from = holders[i].location.clone();
            let target = Location {
                node: to.id,
                peer_url: to.peer_url.clone(),
                shard: from.shard,
                pool: pool.clone(),
            };
            let crc = crcs[from.shard as usize] as u64;
            let placement = Placement::Move { from: from.node };
            if let Err(e) =
                place_shard(app, blob_id, layout, &holders, i, &target, crc, placement).await
            {
                eprintln!(
                    "mover: blob {blob_id}: spreading shard {}: {e:#}",
                    from.shard
                );
                report.failed += 1;
                return Ok(false);
            }
            eprintln!(
                "mover: blob {blob_id}: moved shard {} from node {} to node {}, to spread it",
                from.shard, from.node, target.node
            );
            report.spread += 1;
            report.bytes += layout.shard_size(from.shard);
            left.push(from.node);
            crate::blobs::reap_blobs(app, vec![(blob_id, from.node, from.peer_url)]);
            holders[i] = Holder {
                location: target,
                live: true,
                moving: false,
            };
        }
    }
    app.pool
        .get()
        .await?
        .execute_cached(
            "UPDATE blobs SET uneven = false WHERE blob_id = $1",
            &[&blob_id],
        )
        .await?;
    Ok(true)
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
        ShardWrite::Coded(ShardFile {
            blob_id,
            layout,
            shard,
        })
    };
    let (tx, body) = channel_body();
    let store = async {
        if target.node == app.node {
            crate::write_blob_streaming(app, &write, &target.pool, placement, body).await
        } else {
            crate::upload_to_peer(
                &app.peers,
                &target.peer_url,
                &write,
                &target.pool,
                placement,
                body,
            )
            .await
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
    let mut live: Vec<Location> = holders
        .iter()
        .filter(|h| h.live)
        .map(|h| h.location.clone())
        .collect();
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
    let file = ShardFile {
        blob_id,
        layout,
        shard,
    };
    let mut summer = BlobSummer::new(layout.block_size as u32);
    let mut digest = crc64fast_nvme::Digest::new();
    for row in 0..layout.rows() {
        let len = layout.row_len_on(row, shard);
        if len == 0 {
            continue;
        }
        let direct = if from.live {
            crate::blobs::fetch_range(app, &from.location, &file, row * su, len)
                .await
                .ok()
        } else {
            None
        };
        let cell = match direct {
            Some(cell) => cell,
            None => {
                crate::blobs::reconstruct(app, blob_id, layout, &live, row, shard, (0, len)).await?
            }
        };
        summer.update(&cell);
        digest.write(&cell);
        if tx.send(Ok(Frame::data(Bytes::from(cell)))).await.is_err() {
            anyhow::bail!("the new node stopped taking the shard");
        }
    }
    let others: Vec<Location> = live.iter().filter(|l| l.shard != shard).cloned().collect();
    let trailer =
        crate::scrub::repair::trailer(app, &file, &others, summer.finish(), &digest, crc).await?;
    // The new node adds the shard's index and the blob ID itself.
    let tables = trailer[..trailer.len() - blob_file::tail(&file).len()].to_vec();
    if tx.send(Ok(Frame::data(Bytes::from(tables)))).await.is_err() {
        anyhow::bail!("the new node stopped taking the shard");
    }
    Ok(())
}

#[cfg(test)]
mod e2e;
