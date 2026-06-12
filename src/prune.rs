use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use deadpool_postgres::Object;
use hyper::body::{Bytes, Frame};
use tokio_postgres::{IsolationLevel, error::SqlState, types::ToSql};
use uuid::Uuid;

use crate::{App, body::FrameSender};

/// How long a part may stay `pending` before a replica drops its own location for
/// it (phase 1). This reclaims disk, so it's kept fairly tight.
const PENDING_TIMEOUT: Duration = Duration::from_secs(3600); // 1h
/// How long a location-less `pending` row lingers before it's reaped (phase 3).
/// Rows are tiny, and this must comfortably exceed the longest plausible upload,
/// so a just-started upload that hasn't announced a location isn't reaped.
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

    // ── Phase 1: drop our location for parts pending past the short timeout ──
    // `p.state = 'pending'` is the "only while pending" guard; serializable orders
    // the drop against a commit counting that location.
    let pending_secs = PENDING_TIMEOUT.as_secs_f64();
    let dropped = collect_ids(
        &mut client,
        apply,
        "DELETE FROM part_locations pl USING parts p
         WHERE pl.part_id = p.part_id AND pl.node_id = $1 AND p.state = 'pending'
           AND p.created_at < NOW() - make_interval(secs => $2)
         RETURNING pl.part_id",
        "SELECT pl.part_id FROM part_locations pl JOIN parts p ON p.part_id = pl.part_id
         WHERE pl.node_id = $1 AND p.state = 'pending'
           AND p.created_at < NOW() - make_interval(secs => $2)",
        &[&self_id, &pending_secs],
    )
    .await?;
    for part_id in &dropped {
        line(tx, format!("phase1 drop-location part={part_id} reason=pending-too-long")).await;
    }

    // ── Phase 2: delete local files with no location for us ──
    // `held` is loaded *after* phase 1 (so its drops are reflected) and used only
    // as a fast path: a file we hold a location for is kept cheaply. A file that
    // isn't in `held` is merely a *candidate* — `held` is a snapshot and a
    // concurrent upload may have announced a location since — so we confirm with a
    // fresh check before deleting.
    let held: HashSet<Uuid> = client
        .query("SELECT part_id FROM part_locations WHERE node_id = $1", &[&self_id])
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let mut deleted_files = 0usize;
    for part_id in app.store.list_local_parts().await? {
        // Fast path: we hold it, or it's an in-flight write (the announce gap).
        if held.contains(&part_id) || app.writing.contains(part_id) {
            continue;
        }
        // Suspected orphan. The writing-set check above runs *before* this fresh
        // location check, and a writer leaves the set only after committing its
        // location — so "not in the set" means its location (if any) is already
        // visible here. A location that's still present means it isn't an orphan.
        if has_location(&client, part_id, &self_id).await? {
            continue;
        }
        deleted_files += 1;
        line(tx, format!("phase2 delete-file part={part_id} reason=no-local-location")).await;
        if apply {
            app.store.remove_part(part_id).await?;
        }
    }

    // ── Phase 3: reap pending rows with no locations past the long timeout ──
    let reaper_secs = REAPER_TIMEOUT.as_secs_f64();
    let reaped = collect_ids(
        &mut client,
        apply,
        "DELETE FROM parts p
         WHERE p.state = 'pending' AND p.created_at < NOW() - make_interval(secs => $1)
           AND NOT EXISTS (SELECT 1 FROM part_locations WHERE part_id = p.part_id)
         RETURNING p.part_id",
        "SELECT p.part_id FROM parts p
         WHERE p.state = 'pending' AND p.created_at < NOW() - make_interval(secs => $1)
           AND NOT EXISTS (SELECT 1 FROM part_locations WHERE part_id = p.part_id)",
        &[&reaper_secs],
    )
    .await?;
    for part_id in &reaped {
        line(tx, format!("phase3 reap-part part={part_id} reason=abandoned-pending")).await;
    }

    line(
        tx,
        format!(
            "done: phase1-locations={} phase2-files={} phase3-parts={}",
            dropped.len(),
            deleted_files,
            reaped.len()
        ),
    )
    .await;
    Ok(())
}

/// Fresh check of whether this node still holds a location for `part_id`.
async fn has_location(client: &Object, part_id: Uuid, self_id: &str) -> anyhow::Result<bool> {
    Ok(client
        .query_opt(
            "SELECT 1 FROM part_locations WHERE part_id = $1 AND node_id = $2",
            &[&part_id, &self_id],
        )
        .await?
        .is_some())
}

/// For a single-statement phase: in apply mode runs `delete_sql` (a serializable
/// `DELETE … RETURNING part_id`, retried on a serialization conflict); in dry-run
/// runs `select_sql`. Returns the affected part ids for the report. Serializable
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
