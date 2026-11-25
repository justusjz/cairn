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
//! `classes`), holds no shard of its blob, and crowds no failure domain
//! beyond its class's caps (see `placement`): of those, the one in the least
//! crowded domains, then the one with the most free space in that pool. Its bytes come from its node while that's
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
//! replicated blobs it's about to code too (see `packer::Layouts`).
//!
//! And it moves the shards of blobs that don't keep to their class's caps
//! (see `placement`), as those changed, or nodes' labels did: each such
//! change starts a sweep through the class's blobs (`cairn_claim_spread`),
//! a step at a time, shared by the nodes. As many of a blob's shards stay
//! where they are as keep to the caps, and the others move.

use std::sync::Arc;
use std::time::Duration;

use hyper::body::{Bytes, Frame};
use uuid::Uuid;

use crate::db::Cached;
use crate::placement;
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
    /// Shards (of those moved) moved to keep to their class's caps.
    pub respread: u64,
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
            == 0
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "moved {} shards ({} to keep to their class's caps) and added {} copies ({} bytes), \
             dropped {} copies, {} waiting for a node, {} failed; \
             upgraded {} blobs from before checksums; {} nodes removed",
            self.moved,
            self.respread,
            self.added,
            self.bytes,
            self.dropped,
            self.waiting,
            self.failed,
            self.upgraded,
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

/// How many blobs a step of a class's sweep for blobs whose shards don't
/// keep to its caps reads (see `cairn_claim_spread`).
const SPREAD_SCAN: i32 = 512;

/// Moves the shards of blobs that don't keep to their class's caps (see
/// `placement`): after the caps changed, or nodes' labels did, a class's
/// sweep reads through its blobs, and claims those (see
/// `cairn_claim_spread`). A class whose live nodes can't take as many
/// shards as its blobs have, as its caps allow, isn't swept until they can:
/// there'd be nowhere to move them.
async fn spread(app: &Arc<App>, report: &mut Report) -> anyhow::Result<()> {
    for class in app.classes.all().values() {
        let needed = 1 + app.parity_shards_of(class) as usize;
        if !class.max_per.is_empty() && crate::placeable(app, class).await? < needed {
            continue;
        }
        loop {
            let row = app
                .pool
                .get()
                .await?
                .query_one_cached(
                    "SELECT claimed, more FROM pg_temp.cairn_claim_spread($1, $2, $3)",
                    &[&class.name, &SPREAD_SCAN, &LEASE.as_secs_f64()],
                )
                .await?;
            let (claimed, more): (Vec<Uuid>, bool) = (row.get(0), row.get(1));
            for blob_id in claimed {
                let done = respread(app, blob_id, report).await;
                if !matches!(done, Ok(true)) {
                    // Swept again once the sweep is through.
                    app.pool
                        .get()
                        .await?
                        .execute_cached(
                            "UPDATE storage_classes SET spread_again = true,
                                 spread_from = coalesce(spread_from, '00000000-0000-0000-0000-000000000000'::uuid)
                             WHERE name = $1",
                            &[&class.name],
                        )
                        .await?;
                }
                release(app, blob_id, done, report).await?;
            }
            if !more {
                break;
            }
        }
    }
    Ok(())
}

/// Moves shards of `blob_id` until they keep to its class's caps (see
/// `placement`): as many as can stay where they are do, and the others move
/// to the nodes that, with those, spread them the most evenly. Whether they
/// keep to them now (or the blob is gone, or not one to move).
async fn respread(app: &Arc<App>, blob_id: Uuid, report: &mut Report) -> anyhow::Result<bool> {
    let Some(Loaded {
        layout,
        crcs,
        mut holders,
        class,
        pool,
    }) = load(app, blob_id, None).await?
    else {
        return Ok(true); // deleted meanwhile
    };
    let Some(layout) = layout else {
        return Ok(true); // from before checksums: the upgrade rewrites it
    };
    let caps = app.classes.get(&class).max_per;
    let live: Vec<crate::LiveNode> = crate::live_nodes(&app.pool.get().await?, &pool)
        .await?
        .into_iter()
        .filter(|n| !holders.iter().any(|h| h.location.node == n.id))
        .collect();
    let candidates: Vec<&placement::Location> = holders
        .iter()
        .map(|h| &h.place)
        .chain(live.iter().map(|n| &n.location))
        .collect();
    let count = holders.len();
    let chosen = placement::place(&candidates, count, &caps, count);
    if chosen.len() < count {
        report.waiting += 1;
        return Ok(false);
    }
    let mut leaving: Vec<usize> = (0..count).filter(|i| !chosen.contains(i)).collect();
    let mut left = Vec::new();
    for new in chosen.into_iter().filter(|&c| c >= count) {
        let node = &live[new - count];
        // The leaving shard nearest the new node, so that the move crowds
        // its domains no more than the shard did (the catalog counts the
        // ones still to leave, see `cairn_crowds`).
        let (at, &i) = leaving
            .iter()
            .enumerate()
            .max_by_key(|&(at, &i)| {
                (
                    placement::shared_depth(&holders[i].place, &node.location),
                    std::cmp::Reverse(at),
                )
            })
            .expect("as many leave as there are new nodes");
        leaving.remove(at);
        let shard = holders[i].location.shard;
        let target = Target {
            location: Location {
                node: node.id,
                peer_url: node.peer_url.clone(),
                shard,
                pool: pool.clone(),
            },
            place: node.location.clone(),
        };
        let crc = crcs[shard as usize] as u64;
        if !move_shard(
            app,
            blob_id,
            layout,
            &mut holders,
            i,
            target,
            crc,
            &mut left,
            report,
        )
        .await
        {
            return Ok(false);
        }
        report.respread += 1;
    }
    Ok(true)
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
        class,
    }) = load(app, blob_id, None).await?
    else {
        return Ok(true); // deleted meanwhile
    };
    let Some(mut layout) = layout.filter(Layout::replicated) else {
        return Ok(true); // rewritten meanwhile
    };
    let caps = app.classes.get(&class).max_per;
    let crc = crcs[0] as u64;
    while layout.parity_shards < parity_shards {
        let taken: Vec<i32> = holders.iter().map(|h| h.location.node).collect();
        let held: Vec<&placement::Location> = holders.iter().map(|h| &h.place).collect();
        let Some(target) = choose_target(app, &pool, &caps, &held, &taken, layout.shards()).await?
        else {
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
            app,
            blob_id,
            layout,
            &holders,
            source,
            &target.location,
            crc,
            placement,
        )
        .await
        {
            eprintln!("mover: blob {blob_id}: adding a copy: {e:#}");
            report.failed += 1;
            return Ok(false);
        }
        eprintln!(
            "mover: blob {blob_id}: added copy {} on node {}",
            target.location.shard, target.location.node
        );
        report.added += 1;
        report.bytes += layout.size;
        layout.parity_shards += 1;
        holders.push(Holder {
            location: target.location,
            live: true,
            moving: false,
            place: target.place,
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
                            OR coalesce(n.last_seen < NOW() - make_interval(secs => $2), false),
                        n.continent, n.region, n.az, n.rack, n.host
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
            place: crate::location_from(r, 6),
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
    /// Where its node is (see `placement`).
    place: placement::Location,
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
    let caps = class.max_per;
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
        // The blob's other shards stay where they are, as the catalog
        // counts them (`cairn_crowds`).
        let held: Vec<&placement::Location> = holders
            .iter()
            .enumerate()
            .filter(|&(j, _)| j != i)
            .map(|(_, h)| &h.place)
            .collect();
        let shard = holders[i].location.shard;
        let Some(target) = choose_target(app, &pool, &caps, &held, &taken, shard).await? else {
            report.waiting += 1;
            done = false;
            continue;
        };
        let crc = crcs[shard as usize] as u64;
        if !move_shard(
            app,
            blob_id,
            layout,
            &mut holders,
            i,
            target,
            crc,
            &mut left,
            report,
        )
        .await
        {
            return Ok(false);
        }
    }
    Ok(done)
}

/// Moves the shard of `holders[i]` of blob `blob_id` to `target`, and
/// reaps the file it leaves (whose node goes in `left`). Whether it moved:
/// if it didn't, why is logged, and the blob is read afresh when it's
/// tried again.
#[allow(clippy::too_many_arguments)]
async fn move_shard(
    app: &Arc<App>,
    blob_id: Uuid,
    layout: Layout,
    holders: &mut [Holder],
    i: usize,
    target: Target,
    crc: u64,
    left: &mut Vec<i32>,
    report: &mut Report,
) -> bool {
    let placement = Placement::Move {
        from: holders[i].location.node,
    };
    match place_shard(
        app,
        blob_id,
        layout,
        holders,
        i,
        &target.location,
        crc,
        placement,
    )
    .await
    {
        Ok(()) => {
            let from = holders[i].location.clone();
            eprintln!(
                "mover: blob {blob_id}: moved shard {} from node {} to node {}",
                from.shard, from.node, target.location.node
            );
            report.moved += 1;
            report.bytes += layout.shard_size(from.shard);
            left.push(from.node);
            crate::blobs::reap_blobs(app, vec![(blob_id, from.node, from.peer_url)]);
            holders[i] = Holder {
                location: target.location,
                live: true,
                moving: false,
                place: target.place,
            };
            true
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
            false
        }
    }
}

/// A node to place a shard on, and where it is.
struct Target {
    location: Location,
    place: placement::Location,
}

/// The node to place shard `shard` of a blob in pool `pool` on, whose other
/// shards are on nodes at `held`: an active, live one with the pool that
/// holds none of the blob's (`taken`), and crowds no domain beyond `caps`
/// (see `placement`); of those, the one in the least crowded domains, then
/// the one with the most free space in the pool.
async fn choose_target(
    app: &App,
    pool: &str,
    caps: &placement::Caps,
    held: &[&placement::Location],
    taken: &[i32],
    shard: u32,
) -> anyhow::Result<Option<Target>> {
    let live: Vec<crate::LiveNode> = crate::live_nodes(&app.pool.get().await?, pool)
        .await?
        .into_iter()
        .filter(|n| !taken.contains(&n.id))
        .collect();
    let candidates: Vec<&placement::Location> = live.iter().map(|n| &n.location).collect();
    Ok(placement::next(held, &candidates, caps).map(|i| {
        let node = &live[i];
        Target {
            location: Location {
                node: node.id,
                peer_url: node.peer_url.clone(),
                shard,
                pool: pool.to_owned(),
            },
            place: node.location.clone(),
        }
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
