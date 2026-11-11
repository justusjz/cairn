//! Garbage collection: reclaims what a crash left behind, or a cleanup that
//! failed itself.
//!
//! Every path that deletes data deletes its blobs, and their files, right away,
//! and so does every upload or packing job that fails.
//! GC is the backstop that makes sure anything left over is reclaimed in the
//! end, wherever a node died. It runs on every node, as part of its maintenance
//! pass once a minute, in two parts, so that no single pass is expensive:
//!
//! - **Pending blobs** that have been pending for a day are deleted, with
//!   their files: their upload (or packing job) has died. A day comfortably
//!   exceeds the longest upload. Cheap, through an index of the pending blobs.
//! - **Orphaned files**: each pass sweeps a slice of this node's shard
//!   directories, so that a full sweep takes a day, and deletes the files of
//!   blobs that the catalog doesn't place on this node, and the repaired
//!   copies of blobs that a crashed repair left (see `scrub::repair`), and
//!   then any shard directory left empty.
//!
//! Committed blobs that no part references anymore don't need looking for: a
//! blob can only become one by its parts being deleted, which the garbage log
//! records, and the packer drops the blobs it points at once they're
//! unreferenced (see `packer::fold_garbage`).

use std::{collections::HashSet, ops::Range, sync::Arc, time::Duration};

use deadpool_postgres::Object;
use tokio_postgres::types::ToSql;
use uuid::Uuid;

use crate::db::Cached;
use crate::{
    App,
    blobs::{ReapTarget, reap_blobs},
    db,
    store::SHARDS,
};

/// How long a blob may stay pending before it's deleted.
const PENDING_TIMEOUT: Duration = Duration::from_secs(24 * 3600);
/// How old a repaired copy that never replaced its blob's file must be for the
/// sweep to delete it: a crash left it behind (see `scrub::repair`).
const STALE_REPAIR: Duration = Duration::from_secs(24 * 3600);
/// How many shard directories a pass sweeps: all of them in about a day, at a
/// pass a minute.
const SHARDS_PER_PASS: u32 = SHARDS.div_ceil(24 * 60);
/// What a pass covers: the shard directories it sweeps.
pub struct Scope {
    shards: Range<u32>,
}

impl Scope {
    /// Everything at once, as tests want it.
    pub fn everything() -> Scope {
        Scope { shards: 0..SHARDS }
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
        Scope { shards: start..end }
    }

    /// The shard the next pass starts at.
    pub fn position(&self) -> u32 {
        self.next
    }
}

/// What a pass reclaimed, and what went wrong.
#[derive(Default)]
pub struct Report {
    pending: usize,
    files: usize,
    dirs: usize,
    errors: Vec<String>,
}

impl Report {
    pub fn is_empty(&self) -> bool {
        self.pending + self.files + self.dirs == 0 && self.errors.is_empty()
    }

    /// How many stale pending blobs, orphaned files and empty directories the
    /// pass deleted.
    pub fn counts(&self) -> (usize, usize, usize) {
        (self.pending, self.files, self.dirs)
    }

    pub fn error_count(&self) -> usize {
        self.errors.len()
    }

    #[cfg(test)]
    pub fn errors(&self) -> &[String] {
        &self.errors
    }

    /// Records the error of one part of the pass, which goes on with the rest.
    fn record(&mut self, what: &str, result: anyhow::Result<()>) {
        if let Err(e) = result {
            self.errors.push(format!("{what}: {e:#}"));
        }
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "deleted {} stale pending blobs, {} orphaned files, {} empty directories",
            self.pending, self.files, self.dirs
        )?;
        for error in &self.errors {
            write!(f, "; failed {error}")?;
        }
        Ok(())
    }
}

/// Runs a GC pass over `scope`. Its parts are independent: one failing doesn't
/// keep the others from running, and its error ends up in the report.
pub async fn pass(app: &Arc<App>, scope: Scope) -> Report {
    let mut report = Report::default();
    let result = delete_stale_pending(app, &mut report).await;
    report.record("deleting stale pending blobs", result);
    for shard in scope.shards {
        let result = sweep_shard(app, shard, &mut report).await;
        report.record(&format!("sweeping shard {shard:04x}"), result);
    }
    report
}

async fn delete_stale_pending(app: &Arc<App>, report: &mut Report) -> anyhow::Result<()> {
    let mut client = app.pool.get().await?;
    // Deleting a pending blob row is guarded by its still being pending. A
    // commit holds the row locked while it counts the locations and commits
    // it, and the GC skips locked rows, and re-checks the condition on the
    // rows it locks, so it never deletes a committed blob (I5 in
    // `catalog.sql`). An upload still
    // writing to it fails to record its location once the row is gone, and
    // deletes its file itself (left to the sweep only if its connection to the
    // database broke, since the location may have been recorded then).
    let pending_secs = PENDING_TIMEOUT.as_secs_f64();
    let (count, reap) = delete_blobs(
        &mut client,
        "b.state = 'pending' AND b.created_at < NOW() - make_interval(secs => $1)",
        &[&pending_secs],
    )
    .await?;
    report.pending += count;
    reap_blobs(app, reap);
    Ok(())
}

/// Deletes the blobs matching `condition` (on `blobs b`, and only on its own
/// columns: it's re-checked when a row is locked, but subqueries aren't),
/// retried on a conflict. Returns how many it deleted, and their locations,
/// to reap. Blobs that another transaction has locked (a commit, say) are
/// skipped, and left to a later pass: the GC never waits for a lock, so it
/// can't deadlock (see `catalog.sql`).
async fn delete_blobs(
    client: &mut Object,
    condition: &str,
    params: &[&(dyn ToSql + Sync)],
) -> anyhow::Result<(usize, Vec<ReapTarget>)> {
    // All parts of a statement see the same snapshot, so the outer SELECT still
    // sees the locations that the DELETE cascades away. A blob without any
    // still counts.
    let sql = format!(
        "WITH doomed AS (
             SELECT b.blob_id FROM blobs b WHERE {condition}
             ORDER BY b.blob_id FOR UPDATE SKIP LOCKED
         ),
         gone AS (
             DELETE FROM blobs b USING doomed WHERE b.blob_id = doomed.blob_id
             RETURNING b.blob_id
         )
         SELECT gone.blob_id, bl.node, n.peer_url
         FROM gone
         LEFT JOIN blob_locations bl ON bl.blob_id = gone.blob_id
         LEFT JOIN nodes n ON n.id = bl.node"
    );
    let mut attempt = 0;
    loop {
        db::backoff(attempt).await;
        attempt += 1;
        // One statement, and so its own transaction.
        let rows = match client.query_cached(&sql, params).await {
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
/// this node, then the shard's directory if that leaves it empty.
async fn sweep_shard(app: &App, shard: u32, report: &mut Report) -> anyhow::Result<()> {
    // A file being written has no location yet. A writer leaves the writing
    // set only after its location is committed, so checking the set before
    // the catalog never mistakes a new blob for an orphan.
    let listing = app.store.list_shard(shard).await?;
    let files: Vec<Uuid> = listing
        .blobs
        .into_iter()
        .filter(|&blob_id| !app.writing.contains(blob_id))
        .collect();
    if !files.is_empty() {
        delete_orphans(app, files, report).await?;
    }
    for (blob_id, modified) in listing.repairs {
        if modified.elapsed().is_ok_and(|age| age > STALE_REPAIR) {
            eprintln!("gc: deleting the repaired copy of blob {blob_id} a crash left");
            app.store.remove_stale_repair(shard, blob_id).await?;
            report.files += 1;
        }
    }
    report.dirs += app.store.remove_shard_if_empty(shard).await;
    Ok(())
}

/// Deletes those of `files` (local blob files) whose blobs the catalog doesn't
/// place on this node.
async fn delete_orphans(app: &App, files: Vec<Uuid>, report: &mut Report) -> anyhow::Result<()> {
    let client = app.pool.get().await?;
    let held: HashSet<Uuid> = client
        .query_cached(
            "SELECT blob_id FROM blob_locations WHERE node = $1 AND blob_id = ANY($2)",
            &[&app.node, &files],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    for blob_id in files {
        if !held.contains(&blob_id) {
            eprintln!("gc: deleting orphaned file of blob {blob_id}");
            app.store.remove_blob(blob_id).await?;
            report.files += 1;
        }
    }
    Ok(())
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
