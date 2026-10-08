use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use deadpool_postgres::Object;
use hyper::body::{Bytes, Frame};
use tokio_postgres::{IsolationLevel, error::SqlState, types::ToSql};
use uuid::Uuid;

use crate::{App, body::FrameSender};

/// How long a blob may stay `pending` before a replica drops its own location
/// for it (phase 1). This reclaims disk, so it's kept fairly tight.
const PENDING_TIMEOUT: Duration = Duration::from_secs(3600); // 1h
/// How long a location-less `pending` blob row lingers before it's reaped (phase
/// 4). Rows are tiny, and this must comfortably exceed the longest plausible
/// upload, so a just-started upload that hasn't announced a location isn't reaped.
const REAPER_TIMEOUT: Duration = Duration::from_secs(24 * 3600); // 24h

/// Runs a prune on this node, streaming a line-per-action report to `tx`. Errors
/// are reported as a final line rather than aborting the connection.
pub async fn run(app: Arc<App>, apply: bool, tx: FrameSender) {
    if let Err(e) = run_inner(&app, apply, &tx).await {
        line(&tx, format!("error: {e:#}")).await;
    }
}

async fn line(tx: &FrameSender, mut s: String) {
    s.push('\n');
    let _ = tx.send(Ok(Frame::data(Bytes::from(s)))).await;
}

async fn run_inner(app: &App, apply: bool, tx: &FrameSender) -> anyhow::Result<()> {
    let self_id = app.store.get_node_id().to_string();
    let mode = if apply { "APPLY" } else { "dry-run" };
    line(tx, format!("prune [{mode}] node={self_id}")).await;
    let mut client = app.pool.get().await?;

    // ── Phase 1: drop our location for blobs pending past the short timeout ──
    // `b.state = 'pending'` is the "only while pending" guard; serializable orders
    // the drop against a commit counting that location.
    let pending_secs = PENDING_TIMEOUT.as_secs_f64();
    let dropped = collect_ids(
        &mut client,
        apply,
        "DELETE FROM blob_locations bl USING blobs b
         WHERE bl.blob_id = b.blob_id AND bl.node = $1 AND b.state = 'pending'
           AND b.created_at < NOW() - make_interval(secs => $2)
         RETURNING bl.blob_id",
        "SELECT bl.blob_id FROM blob_locations bl JOIN blobs b ON b.blob_id = bl.blob_id
         WHERE bl.node = $1 AND b.state = 'pending'
           AND b.created_at < NOW() - make_interval(secs => $2)",
        &[&app.node, &pending_secs],
    )
    .await?;
    for blob_id in &dropped {
        line(tx, format!("phase1 drop-location blob={blob_id} reason=pending-too-long")).await;
    }

    // ── Phase 2: drop committed blobs that no part references anymore ──
    // Every path that deletes parts drops their blobs too, so these are leftovers
    // of a crash or a race (e.g. a part uploaded while its upload was aborted).
    // A blob is committed together with its first part, so no age guard is
    // needed, and the parts FK stops a concurrent attach to a blob we're dropping.
    // This is catalog-wide, not just this node's; dropping the row cascades its
    // locations, so phase 3 (here, and on each other node) then deletes the files.
    let unreferenced = collect_ids(
        &mut client,
        apply,
        "DELETE FROM blobs b
         WHERE b.state = 'committed'
           AND NOT EXISTS (SELECT 1 FROM parts p WHERE p.blob_id = b.blob_id)
         RETURNING b.blob_id",
        "SELECT b.blob_id FROM blobs b
         WHERE b.state = 'committed'
           AND NOT EXISTS (SELECT 1 FROM parts p WHERE p.blob_id = b.blob_id)",
        &[],
    )
    .await?;
    for blob_id in &unreferenced {
        line(tx, format!("phase2 drop-blob blob={blob_id} reason=unreferenced")).await;
    }

    // ── Phase 3: delete local files with no location for us ──
    // `held` is loaded *after* phases 1 and 2 (so their drops are reflected) and
    // used only as a fast path: a file we hold a location for is kept cheaply. A
    // file that isn't in `held` is merely a *candidate* — `held` is a snapshot and
    // a concurrent upload may have announced a location since — so we confirm
    // with a fresh check before deleting.
    let held: HashSet<Uuid> = client
        .query("SELECT blob_id FROM blob_locations WHERE node = $1", &[&app.node])
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let mut deleted_files = 0usize;
    for blob_id in app.store.list_local_blobs().await? {
        // Fast path: we hold it, or it's an in-flight write (the announce gap).
        if held.contains(&blob_id) || app.writing.contains(blob_id) {
            continue;
        }
        // Suspected orphan. The writing-set check above runs *before* this fresh
        // location check, and a writer leaves the set only after committing its
        // location — so "not in the set" means its location (if any) is already
        // visible here. A location that's still present means it isn't an orphan.
        if has_location(&client, blob_id, app.node).await? {
            continue;
        }
        deleted_files += 1;
        line(tx, format!("phase3 delete-file blob={blob_id} reason=no-local-location")).await;
        if apply {
            app.store.remove_blob(blob_id).await?;
        }
    }

    // ── Phase 4: reap pending blob rows with no locations past the long timeout ──
    let reaper_secs = REAPER_TIMEOUT.as_secs_f64();
    let reaped = collect_ids(
        &mut client,
        apply,
        "DELETE FROM blobs b
         WHERE b.state = 'pending' AND b.created_at < NOW() - make_interval(secs => $1)
           AND NOT EXISTS (SELECT 1 FROM blob_locations WHERE blob_id = b.blob_id)
         RETURNING b.blob_id",
        "SELECT b.blob_id FROM blobs b
         WHERE b.state = 'pending' AND b.created_at < NOW() - make_interval(secs => $1)
           AND NOT EXISTS (SELECT 1 FROM blob_locations WHERE blob_id = b.blob_id)",
        &[&reaper_secs],
    )
    .await?;
    for blob_id in &reaped {
        line(tx, format!("phase4 reap-blob blob={blob_id} reason=abandoned-pending")).await;
    }

    // ── Phase 5: rmdir empty shard directories left behind by file deletions ──
    // Pure filesystem cleanup: rmdir only removes an *empty* directory, so it can
    // never touch a blob, and writes recreate shards on demand.
    let removed_dirs = app.store.prune_empty_dirs(apply).await?;
    for dir in &removed_dirs {
        line(tx, format!("phase5 remove-dir path={dir} reason=empty-shard")).await;
    }

    line(
        tx,
        format!(
            "done: phase1-locations={} phase2-blobs={} phase3-files={} phase4-blobs={} phase5-dirs={}",
            dropped.len(),
            unreferenced.len(),
            deleted_files,
            reaped.len(),
            removed_dirs.len()
        ),
    )
    .await;
    Ok(())
}

/// Fresh check of whether this node still holds a location for `blob_id`.
async fn has_location(client: &Object, blob_id: Uuid, node: i32) -> anyhow::Result<bool> {
    Ok(client
        .query_opt(
            "SELECT 1 FROM blob_locations WHERE blob_id = $1 AND node = $2",
            &[&blob_id, &node],
        )
        .await?
        .is_some())
}

/// For a single-statement phase: in apply mode runs `delete_sql` (a serializable
/// `DELETE … RETURNING <id>`, retried on a serialization conflict); in dry-run
/// runs `select_sql`. Returns the affected ids for the report. Serializable
/// so the delete orders correctly against concurrent commits and location
/// announces.
async fn collect_ids(
    client: &mut Object,
    apply: bool,
    delete_sql: &str,
    select_sql: &str,
    params: &[&(dyn ToSql + Sync)],
) -> anyhow::Result<Vec<Uuid>> {
    if !apply {
        return Ok(client
            .query(select_sql, params)
            .await?
            .iter()
            .map(|r| r.get(0))
            .collect());
    }
    let mut attempt = 0;
    loop {
        attempt += 1;
        let result: Result<Vec<Uuid>, tokio_postgres::Error> = async {
            let db = client
                .build_transaction()
                .isolation_level(IsolationLevel::Serializable)
                .start()
                .await?;
            let rows = db.query(delete_sql, params).await?;
            let ids: Vec<Uuid> = rows.iter().map(|r| r.get(0)).collect();
            db.commit().await?;
            Ok(ids)
        }
        .await;
        match result {
            Ok(ids) => return Ok(ids),
            Err(e) if e.code() == Some(&SqlState::T_R_SERIALIZATION_FAILURE) && attempt < 5 => {
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
}
