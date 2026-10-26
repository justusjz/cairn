//! Garbage collection: reclaims what a crash or a failed upload left behind.
//!
//! Every path that deletes data deletes its blobs, and their files, right away.
//! GC is the backstop that makes sure anything left over is reclaimed in the
//! end, wherever a node died. It runs on every node, as part of its maintenance
//! pass once a minute, in three parts, so that no single pass is expensive:
//!
//! - **Pending blobs** that have been pending for a day are deleted, with
//!   their files: their upload (or packing job) has died. A day comfortably
//!   exceeds the longest upload. Cheap, through an index of the pending blobs.
//! - **Orphaned files**: each pass sweeps a slice of this node's shard
//!   directories, so that a full sweep takes a day, and deletes the files of
//!   blobs that the catalog doesn't place on this node (and then any shard
//!   directory left empty).
//! - **Unreferenced blobs**: once a day, one node checks the whole catalog for
//!   committed blobs that no part references, and deletes them, with their
//!   files. This is the expensive part, and leftovers are rare.

use std::{collections::HashSet, ops::Range, sync::Arc, time::Duration};

use deadpool_postgres::Object;
use tokio_postgres::{IsolationLevel, types::ToSql};
use uuid::Uuid;

use crate::{
    App,
    blobs::{ReapTarget, reap_blobs},
    db,
    store::SHARDS,
};

/// How long a blob may stay pending before it's deleted.
const PENDING_TIMEOUT: Duration = Duration::from_secs(24 * 3600);
/// How many shard directories a pass sweeps: all of them in about a day, at a
/// pass a minute.
const SHARDS_PER_PASS: u32 = SHARDS.div_ceil(24 * 60);
/// How often the catalog is checked for unreferenced blobs.
const UNREFERENCED_INTERVAL: Duration = Duration::from_secs(24 * 3600);

/// What a pass covers.
pub struct Scope {
    /// The shard directories to sweep.
    shards: Range<u32>,
    /// Check for unreferenced blobs even if it isn't due.
    force_unreferenced: bool,
}

impl Scope {
    /// Everything at once, as tests want it.
    pub fn everything() -> Scope {
        Scope {
            shards: 0..SHARDS,
            force_unreferenced: true,
        }
    }
}

/// Where a node's background passes are in their sweep: a slice per pass,
/// round and round, from a random start, so that nodes restarting often still
/// get around.
pub struct Sweep {
    next: u32,
}

impl Sweep {
    pub fn new() -> Sweep {
        Sweep {
            next: (Uuid::new_v4().as_u128() % SHARDS as u128) as u32,
        }
    }

    /// The scope of the next background pass.
    pub fn next_scope(&mut self) -> Scope {
        let start = self.next;
        let end = (start + SHARDS_PER_PASS).min(SHARDS);
        self.next = end % SHARDS;
        Scope {
            shards: start..end,
            force_unreferenced: false,
        }
    }
}

/// What a pass reclaimed.
#[derive(Default)]
pub struct Report {
    pending: usize,
    unreferenced: usize,
    files: usize,
    dirs: usize,
}

impl Report {
    pub fn is_empty(&self) -> bool {
        self.pending + self.unreferenced + self.files + self.dirs == 0
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "deleted {} stale pending blobs, {} unreferenced blobs, {} orphaned files, {} empty directories",
            self.pending, self.unreferenced, self.files, self.dirs
        )
    }
}

/// Runs a GC pass over `scope`.
pub async fn pass(app: &Arc<App>, scope: Scope) -> anyhow::Result<Report> {
    let mut client = app.pool.get().await?;
    let mut report = Report::default();

    // Deleting a pending blob row is guarded by its still being pending, and
    // serializable, so that it's ordered against a commit that counts its
    // locations. An upload still writing to it fails to record its location
    // once the row is gone, and its file is swept as an orphan.
    let pending_secs = PENDING_TIMEOUT.as_secs_f64();
    let (count, reap) = delete_blobs(
        &mut client,
        "b.state = 'pending' AND b.created_at < NOW() - make_interval(secs => $1)",
        &[&pending_secs],
    )
    .await?;
    report.pending = count;
    reap_blobs(app, reap);

    if unreferenced_check_due(&client, scope.force_unreferenced).await? {
        // A blob is committed together with its first part, so a committed
        // blob that no part references is garbage, whatever its age. The parts
        // FK stops a concurrent attach to a blob being deleted.
        let (count, reap) = delete_blobs(
            &mut client,
            "b.state = 'committed'
             AND NOT EXISTS (SELECT 1 FROM parts p WHERE p.blob_id = b.blob_id)",
            &[],
        )
        .await?;
        report.unreferenced = count;
        reap_blobs(app, reap);
    }

    for shard in scope.shards {
        report.files += sweep_shard(app, &client, shard).await?;
        report.dirs += app.store.remove_shard_if_empty(shard).await;
    }
    Ok(report)
}

/// Whether this node gets to check for unreferenced blobs now: if the last
/// check (by any node) is a day ago, it claims this one by recording it. With
/// `force`, it always does.
async fn unreferenced_check_due(client: &Object, force: bool) -> anyhow::Result<bool> {
    let interval = UNREFERENCED_INTERVAL.as_secs_f64();
    let claimed = client
        .execute(
            "UPDATE gc_runs SET unreferenced_check = NOW()
             WHERE $2 OR unreferenced_check < NOW() - make_interval(secs => $1)",
            &[&interval, &force],
        )
        .await?;
    Ok(claimed == 1)
}

/// Deletes the blobs matching `condition` (on `blobs b`), in a serializable
/// transaction retried on a conflict. Returns how many it deleted, and their
/// locations, to reap.
async fn delete_blobs(
    client: &mut Object,
    condition: &str,
    params: &[&(dyn ToSql + Sync)],
) -> anyhow::Result<(usize, Vec<ReapTarget>)> {
    // All parts of a statement see the same snapshot, so the outer SELECT still
    // sees the locations that the DELETE cascades away. A blob without any
    // still counts.
    let sql = format!(
        "WITH gone AS (DELETE FROM blobs b WHERE {condition} RETURNING b.blob_id)
         SELECT gone.blob_id, bl.node, n.peer_url
         FROM gone
         LEFT JOIN blob_locations bl ON bl.blob_id = gone.blob_id
         LEFT JOIN nodes n ON n.id = bl.node"
    );
    let mut attempt = 0;
    loop {
        db::backoff(attempt).await;
        attempt += 1;
        let result: Result<_, tokio_postgres::Error> = async {
            let tx = client
                .build_transaction()
                .isolation_level(IsolationLevel::Serializable)
                .start()
                .await?;
            let rows = tx.query(&sql, params).await?;
            tx.commit().await?;
            Ok(rows)
        }
        .await;
        let rows = match result {
            Err(e) if db::is_conflict(&e) && attempt < db::MAX_TX_ATTEMPTS => continue,
            result => result?,
        };
        let deleted: HashSet<Uuid> = rows.iter().map(|r| r.get(0)).collect();
        let reap = rows
            .iter()
            .filter_map(|r| Some((r.get(0), r.get::<_, Option<i32>>(1)?, r.get(2))))
            .collect();
        return Ok((deleted.len(), reap));
    }
}

/// Deletes the files in shard `shard` whose blobs the catalog doesn't place on
/// this node. Returns how many it deleted.
async fn sweep_shard(app: &App, client: &Object, shard: u32) -> anyhow::Result<usize> {
    // A file being written has no location yet. A writer leaves the writing
    // set only after its location is committed, so checking the set before
    // the catalog never mistakes a new blob for an orphan.
    let files: Vec<Uuid> = app
        .store
        .list_shard(shard)
        .await?
        .into_iter()
        .filter(|&blob_id| !app.writing.contains(blob_id))
        .collect();
    if files.is_empty() {
        return Ok(0);
    }
    let held: HashSet<Uuid> = client
        .query(
            "SELECT blob_id FROM blob_locations WHERE node = $1 AND blob_id = ANY($2)",
            &[&app.node, &files],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let mut deleted = 0;
    for blob_id in files {
        if !held.contains(&blob_id) {
            eprintln!("gc: deleting orphaned file of blob {blob_id}");
            app.store.remove_blob(blob_id).await?;
            deleted += 1;
        }
    }
    Ok(deleted)
}

#[cfg(test)]
mod e2e;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sweep_goes_round() {
        let mut sweep = Sweep { next: SHARDS - 10 };
        assert_eq!(sweep.next_scope().shards, SHARDS - 10..SHARDS);
        assert_eq!(sweep.next_scope().shards, 0..SHARDS_PER_PASS);
        // A full sweep takes about a day of passes.
        let passes = SHARDS.div_ceil(SHARDS_PER_PASS);
        assert!((1400..=1440).contains(&passes), "{passes} passes");
    }
}
