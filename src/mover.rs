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
//! `classes`) and holds no shard of its blob: where it breaks its class's
//! tolerance least (see `topology`), the one with the most free space in
//! that pool of those. Repair doesn't wait for a place that keeps the
//! tolerance: it takes the best there is. Its bytes come from its node while that's
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
//! is added where a moved shard would go; the one dropped is the one whose
//! loss keeps the tolerance best.
//!
//! Last, each node sweeps its blobs (those whose first shard it holds), a
//! batch a pass, for those that break their class's tolerance: placed by a
//! repair that had no better place, by an older node, or before the class
//! or a node's location changed. It plans the placement on the live nodes
//! that breaks the tolerance least (keeps it, if any does), moving the
//! fewest shards, and moves them there one after the other, from where they
//! are (all live), each copied before its old file goes (`spread`). A blob
//! that keeps it stays where it is: Cairn spreads no further than asked.

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
    topology::{self, Candidate, Domains, Tolerance},
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
/// How many of its blobs a node checks the spread of in a pass (see
/// `spread`).
const SPREAD_BATCH: i64 = 10_000;

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
    /// Shards moved so that their blobs keep their classes' tolerance.
    pub spread: u64,
    /// Blobs from before checksums, rewritten by the packer's upgrade.
    pub upgraded: u64,
    /// Nodes that finished being removed.
    pub removed: u64,
}

impl Report {
    pub fn is_empty(&self) -> bool {
        self.moved
            + self.added
            + self.dropped
            + self.waiting
            + self.failed
            + self.spread
            + self.upgraded
            + self.removed
            == 0
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "moved {} shards and added {} copies ({} bytes), dropped {} copies, \
             {} waiting for a node, {} failed; moved {} shards to spread them as their classes \
             take; upgraded {} blobs from before checksums; {} nodes removed",
            self.moved,
            self.added,
            self.bytes,
            self.dropped,
            self.waiting,
            self.failed,
            self.spread,
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

/// Checks the next of this node's blobs (those whose first shard it holds,
/// so that each is checked by one node), up to `SPREAD_BATCH` of them, for
/// shards that break their class's tolerance (see `topology`): placed so
/// by a repair that had no better place, by an older node, or before the
/// class or a node's location changed. It plans where their shards are to
/// be on the live nodes, and moves them there (see `spread_blob`), from
/// live nodes (where a shard is on a node that's down or leaving, the moves
/// come first). Once it has been through all of them, it starts again.
async fn spread(app: &Arc<App>, report: &mut Report) -> anyhow::Result<()> {
    let classes = app.classes.all();
    if !classes.values().any(|c| c.tolerance.any()) {
        return Ok(());
    }
    let from = *app.spread_from.lock().unwrap();
    let client = app.pool.get().await?;
    let batch: Vec<Uuid> = client
        .query_cached(
            "SELECT blob_id FROM blob_locations
             WHERE node = $1 AND shard = 0 AND blob_id > $2
             ORDER BY blob_id LIMIT $3",
            &[&app.node, &from, &SPREAD_BATCH],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    // From the start again once it's through.
    *app.spread_from.lock().unwrap() = match batch.len() as i64 {
        n if n < SPREAD_BATCH => Uuid::nil(),
        _ => batch.last().copied().unwrap_or_default(),
    };
    let rows = client
        .query_cached(
            "SELECT b.blob_id, b.storage_class, b.parity_shards,
                    array_agg(bl.node ORDER BY bl.shard)
             FROM blobs b JOIN blob_locations bl ON bl.blob_id = b.blob_id
             WHERE b.blob_id = ANY($1) AND b.state = 'committed' AND b.block_size IS NOT NULL
             GROUP BY b.blob_id ORDER BY b.blob_id",
            &[&batch],
        )
        .await?;
    let domains = topology::all_domains(&client).await?;
    drop(client);
    for r in rows {
        let (blob_id, class, parity, nodes): (Uuid, String, i16, Vec<i32>) =
            (r.get(0), r.get(1), r.get(2), r.get(3));
        let tolerance = app.classes.get(&class).tolerance;
        let Some(shards) = nodes
            .iter()
            .map(|n| domains.get(n))
            .collect::<Option<Vec<&Domains>>>()
        else {
            continue;
        };
        if topology::excess(shards, &tolerance, parity as u32) == [0; 5] {
            continue;
        }
        let claimed: bool = app
            .pool
            .get()
            .await?
            .query_one_cached(
                "SELECT pg_temp.cairn_claim_spread($1, $2)",
                &[&blob_id, &LEASE.as_secs_f64()],
            )
            .await?
            .get(0);
        if claimed {
            let done = spread_blob(app, blob_id, report).await;
            release(app, blob_id, done, report).await?;
        }
    }
    Ok(())
}

/// Moves the shards of blob `blob_id` where its class's tolerance takes
/// them (see `spread`): to the placement on the live nodes that breaks it
/// least, moving the fewest shards (see `topology::plan`), one shard after
/// the other. Each is copied before its old file goes, so the blob never
/// has fewer shards on the way. Whether it's done: if a move fails, the
/// blob is planned afresh when it's tried again.
async fn spread_blob(app: &Arc<App>, blob_id: Uuid, report: &mut Report) -> anyhow::Result<bool> {
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
    let class = app.classes.get(&class);
    // The packer moves it into its class's pool, the moves come first, and
    // blobs from before checksums are upgraded first.
    let Some(layout) = layout else {
        return Ok(true);
    };
    if pool != class.pool || holders.iter().any(|h| !h.live || h.moving) {
        return Ok(true);
    }
    let nodes = topology::candidates(&app.pool.get().await?, &pool).await?;
    let held: Vec<bool> = nodes
        .iter()
        .map(|n| holders.iter().any(|h| h.location.node == n.node))
        .collect();
    if held.iter().filter(|h| **h).count() != holders.len() {
        return Ok(true); // a holder isn't a candidate anymore
    }
    let (target, excess) = topology::plan(&nodes, &held, &class.tolerance, layout.parity_shards);
    let arriving: Vec<usize> = target.iter().copied().filter(|&n| !held[n]).collect();
    if arriving.is_empty() {
        return Ok(true);
    }
    // The shards on nodes that aren't in the plan, one for each arriving.
    let leaving: Vec<usize> = (0..holders.len())
        .filter(|&i| {
            !target
                .iter()
                .any(|&n| nodes[n].node == holders[i].location.node)
        })
        .collect();
    if excess != [0; 5] {
        eprintln!(
            "mover: blob {blob_id}: no placement on the live nodes keeps {}'s tolerance ({}): \
             moving its shards where it breaks it least",
            class.name, class.tolerance
        );
    }
    for (i, n) in leaving.into_iter().zip(arriving) {
        let target = Location {
            node: nodes[n].node,
            peer_url: nodes[n].peer_url.clone(),
            shard: holders[i].location.shard,
            pool: pool.clone(),
        };
        if !move_shard(app, blob_id, layout, &crcs, &mut holders, i, target, report).await {
            return Ok(false);
        }
        report.spread += 1;
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
    let tolerance = app.classes.get(&class).tolerance;
    let crc = crcs[0] as u64;
    while layout.parity_shards < parity_shards {
        let taken: Vec<i32> = holders.iter().map(|h| h.location.node).collect();
        let target = choose_target(
            app,
            &pool,
            &tolerance,
            parity_shards,
            &taken,
            &taken,
            layout.shards(),
        );
        let Some(target) = target.await? else {
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
        // A copy on a node being removed, or down, first: it would be moved
        // otherwise. Then one whose loss keeps the class's tolerance best
        // (see `topology`), the fullest node's of those.
        let client = app.pool.get().await?;
        let rows = client
            .query_cached(
                "SELECT bl.node, n.state <> 'active', n.last_seen > NOW() - INTERVAL '10 seconds',
                        n.free_space
                 FROM blob_locations bl JOIN nodes n ON n.id = bl.node
                 WHERE bl.blob_id = $1",
                &[&blob_id],
            )
            .await?;
        let domains = topology::all_domains(&client).await?;
        drop(client);
        let nodes: Vec<i32> = rows.iter().map(|r| r.get(0)).collect();
        let left = layout.parity_shards - 1;
        let Some(node) = rows
            .iter()
            .min_by_key(|r| {
                let node: i32 = r.get(0);
                let rest = nodes
                    .iter()
                    .filter(move |n| **n != node)
                    .filter_map(|n| domains.get(n));
                let excess = topology::excess(rest, &tolerance, left);
                let (leaving, live, free): (bool, bool, i64) = (r.get(1), r.get(2), r.get(3));
                (!leaving, live, excess, free, node)
            })
            .map(|r| r.get::<_, i32>(0))
        else {
            return Ok(false);
        };
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
        let others: Vec<i32> = holders
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, h)| h.location.node)
            .collect();
        let Some(target) = choose_target(
            app,
            &pool,
            &class.tolerance,
            layout.parity_shards,
            &others,
            &taken,
            holders[i].location.shard,
        )
        .await?
        else {
            report.waiting += 1;
            done = false;
            continue;
        };
        let from = holders[i].location.node;
        if !move_shard(app, blob_id, layout, &crcs, &mut holders, i, target, report).await {
            return Ok(false);
        }
        report.moved += 1;
        left.push(from);
    }
    Ok(done)
}

/// Moves shard `holders[i]` of blob `blob_id` to `target`, and reaps its
/// old file. Whether it moved: if not, it's read afresh when the blob is
/// tried again. `holders[i]` is where it is now.
#[allow(clippy::too_many_arguments)]
async fn move_shard(
    app: &Arc<App>,
    blob_id: Uuid,
    layout: Layout,
    crcs: &[i64],
    holders: &mut [Holder],
    i: usize,
    target: Location,
    report: &mut Report,
) -> bool {
    let crc = crcs[holders[i].location.shard as usize] as u64;
    let from = holders[i].location.clone();
    let placement = Placement::Move { from: from.node };
    match place_shard(app, blob_id, layout, holders, i, &target, crc, placement).await {
        Ok(()) => {
            eprintln!(
                "mover: blob {blob_id}: moved shard {} from node {} to node {}",
                from.shard, from.node, target.node
            );
            report.bytes += layout.shard_size(from.shard);
            crate::blobs::reap_blobs(app, vec![(blob_id, from.node, from.peer_url)]);
            holders[i] = Holder {
                location: target,
                live: true,
                moving: false,
            };
            true
        }
        Err(e) => {
            // It may have moved after all (an answer lost on the way
            // back): what's where is read afresh when the blob is tried
            // again.
            eprintln!("mover: blob {blob_id}: moving shard {}: {e:#}", from.shard);
            report.failed += 1;
            false
        }
    }
}

/// The node to place shard `shard` of a blob in pool `pool` on, whose
/// other shards are on `others`: an active, live one with the pool that
/// holds none of the blob's (`taken`), where it breaks the class's
/// `tolerance` least for `parity` parity shards (see `topology`), the one
/// with the most free space in the pool of those. If it breaks it all the
/// same, the blob is spread again later (see `spread`).
async fn choose_target(
    app: &App,
    pool: &str,
    tolerance: &Tolerance,
    parity: u32,
    others: &[i32],
    taken: &[i32],
    shard: u32,
) -> anyhow::Result<Option<Location>> {
    let client = app.pool.get().await?;
    let candidates: Vec<Candidate> = topology::candidates(&client, pool)
        .await?
        .into_iter()
        .filter(|c| !taken.contains(&c.node))
        .collect();
    let domains = topology::all_domains(&client).await?;
    let fixed: Vec<Domains> = others
        .iter()
        .filter_map(|n| domains.get(n).cloned())
        .collect();
    let Some((i, excess)) = topology::best(&candidates, &fixed, tolerance, parity) else {
        return Ok(None);
    };
    if excess != [0; 5] {
        eprintln!(
            "mover: no node keeps the tolerance ({tolerance}) for shard {shard}: it goes to node {}, \
             where it breaks it least, until there's a better place",
            candidates[i].node
        );
    }
    let target = &candidates[i];
    Ok(Some(Location {
        node: target.node,
        peer_url: target.peer_url.clone(),
        shard,
        pool: pool.to_owned(),
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
