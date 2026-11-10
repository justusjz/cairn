//! Lifecycle rules: expiring objects, noncurrent versions and incomplete
//! uploads, as a bucket's lifecycle configuration says (see `rules`, and
//! `s3::buckets::lifecycle` for how it's set).
//!
//! Like S3, Cairn applies the rules in the background, not as objects are
//! read: an expired object stays readable until a run gets to it. Every node
//! looks for due buckets once a minute (`pass`); a bucket's run is due when
//! its configuration was set, and then at every midnight UTC, when versions
//! become due (see `rules::Day`). A node claims a bucket's run by moving its
//! due time an hour ahead (a lease, which it extends as it goes), so that each
//! run happens on one node, and is picked up again by another if that node
//! dies. Then it walks the bucket's versions in key order, a page at a time,
//! and expires the due ones (`cairn_lifecycle_expire`), checking each again
//! under the locks a delete takes: a version written meanwhile is never
//! mistaken for one that was due. A run stops when the bucket's configuration
//! changes under it, and starts over with the new one.
//!
//! Expirations are deletes, as DeleteObject's: an expired current version in
//! a versioned bucket gets a delete marker, and stays as a noncurrent version
//! until a rule (or a role with `delete-version`) removes it.

use std::{collections::BTreeMap, sync::Arc, time::{Duration, SystemTime}};

use deadpool_postgres::Object;
use uuid::Uuid;

use crate::db::Cached;
use crate::{
    App,
    blobs::{reap_blobs, reap_columns},
    db,
    s3::versions::new_version_id,
};

pub mod rules;

use rules::{Configuration, Day, Due, Kind, Version};

/// How long a claim on a bucket's run lasts, unless the run extends it.
const LEASE: Duration = Duration::from_secs(3600);
/// How many versions a run reads at a time.
const PAGE: i64 = 1000;
/// How many versions a run expires in one transaction. More than 8 keys lock
/// their stripes, as a large DeleteObjects does (see `cairn_lock_keys`).
const BATCH: usize = 100;

/// What a run did in a bucket.
#[derive(Debug, Default, PartialEq)]
pub struct Report {
    pub bucket: String,
    /// Current versions expired.
    pub expired: usize,
    /// Noncurrent versions and lone delete markers removed.
    pub removed: usize,
    /// Uploads aborted.
    pub aborted: usize,
    /// Whether the configuration changed under the run, which then stopped.
    pub interrupted: bool,
}

impl Report {
    pub fn is_empty(&self) -> bool {
        self.expired + self.removed + self.aborted == 0 && !self.interrupted
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "bucket {}: expired {} objects, removed {} noncurrent versions and delete markers, aborted {} uploads",
            self.bucket, self.expired, self.removed, self.aborted
        )?;
        if self.interrupted {
            write!(f, " (its configuration changed; starting over)")?;
        }
        Ok(())
    }
}

/// Runs every bucket's lifecycle that's due as of `now`, one after the
/// other, as long as there are any. The result of each run, with the
/// bucket's name if it failed.
pub async fn pass(app: &Arc<App>, now: SystemTime) -> Vec<Result<Report, (String, anyhow::Error)>> {
    let mut results = Vec::new();
    loop {
        let claimed = match claim(app, now).await {
            Ok(Some(claimed)) => claimed,
            Ok(None) => return results,
            Err(e) => {
                results.push(Err((String::new(), e)));
                return results;
            }
        };
        let (bucket, config) = claimed;
        let result = run(app, &bucket, &config, now).await;
        // A failed run is tried again when its lease runs out; one that
        // finished, at the next midnight; one interrupted, right away.
        let next = match &result {
            Ok(report) if report.interrupted => Some(now),
            Ok(_) => Some(Day(Day::of(now).0 + 1).midnight()),
            Err(_) => None,
        };
        if let Some(next) = next
            && let Err(e) = reschedule(app, &bucket, &config, next).await
        {
            results.push(Err((bucket.clone(), e)));
        }
        results.push(result.map_err(|e| (bucket, e)));
    }
}

/// Claims the run of a bucket that's due, if there's one, as of `now`: its
/// name and configuration. Skips the buckets whose rows are locked, so that
/// it never waits.
async fn claim(app: &App, now: SystemTime) -> anyhow::Result<Option<(String, String)>> {
    let lease_end = now + LEASE;
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached(
            "UPDATE buckets SET lifecycle_due = $2
             WHERE name = (
                 SELECT name FROM buckets
                 WHERE lifecycle IS NOT NULL AND lifecycle_due <= $1
                 ORDER BY lifecycle_due LIMIT 1
                 FOR NO KEY UPDATE SKIP LOCKED
             )
             RETURNING name, lifecycle",
            &[&now, &lease_end],
        )
        .await?;
    Ok(row.map(|row| (row.get(0), row.get(1))))
}

/// Makes the bucket's next run due at `next`, unless its configuration
/// changed (which made a run due now).
async fn reschedule(app: &App, bucket: &str, config: &str, next: SystemTime) -> anyhow::Result<()> {
    app.pool
        .get()
        .await?
        .execute_cached(
            "UPDATE buckets SET lifecycle_due = $3 WHERE name = $1 AND lifecycle = $2",
            &[&bucket, &config, &next],
        )
        .await?;
    Ok(())
}

/// Extends the claim on the bucket's run, as long as its configuration is
/// still `config`. Whether it is.
async fn extend(client: &Object, bucket: &str, config: &str, now: SystemTime) -> anyhow::Result<bool> {
    // The lease runs from the real time: a run can take a while.
    let lease_end = SystemTime::now().max(now) + LEASE;
    let updated = client
        .execute_cached(
            "UPDATE buckets SET lifecycle_due = $3 WHERE name = $1 AND lifecycle = $2",
            &[&bucket, &config, &lease_end],
        )
        .await?;
    Ok(updated > 0)
}

/// Runs the bucket's lifecycle `config` (as stored) as of `now`.
async fn run(app: &Arc<App>, bucket: &str, config: &str, now: SystemTime) -> anyhow::Result<Report> {
    let rules = Configuration::from_json(config).map_err(|e| {
        anyhow::anyhow!("its lifecycle configuration isn't one this Cairn knows (written by a newer one?): {e}")
    })?;
    let today = Day::of(now);
    let mut report = Report { bucket: bucket.to_owned(), ..Report::default() };
    let client = app.pool.get().await?;
    if rules.expires_objects() {
        let mut after = String::new();
        loop {
            let Some((versions, last)) = page(&client, bucket, &after).await? else { break };
            let due: Vec<(String, Due)> = versions
                .iter()
                .flat_map(|(key, versions)| rules.due(key, versions, today).into_iter().map(|due| (key.clone(), due)))
                .collect();
            for batch in due.chunks(BATCH) {
                if !expire(app, &client, bucket, config, batch, &mut report).await? {
                    report.interrupted = true;
                    return Ok(report);
                }
            }
            if !extend(&client, bucket, config, now).await? {
                report.interrupted = true;
                return Ok(report);
            }
            after = last;
        }
    }
    if rules.aborts_uploads() {
        let mut after = (String::new(), Uuid::nil());
        loop {
            let rows = client
                .query_cached(
                    "SELECT key, upload_id, initiated_at FROM multipart_uploads
                     WHERE bucket = $1 AND (key, upload_id) > ($2, $3)
                     ORDER BY key, upload_id LIMIT $4",
                    &[&bucket, &after.0, &after.1, &PAGE],
                )
                .await?;
            let Some(last) = rows.last() else { break };
            after = (last.get(0), last.get(1));
            for row in &rows {
                let (key, upload_id): (String, Uuid) = (row.get(0), row.get(1));
                if rules.aborts(&key, row.get(2), today) && abort(app, &client, bucket, &key, upload_id).await? {
                    report.aborted += 1;
                }
            }
            if !extend(&client, bucket, config, now).await? {
                report.interrupted = true;
                return Ok(report);
            }
        }
    }
    Ok(report)
}

/// The next page of the bucket's versions after the key `after`: each key's,
/// newest first, and the last key in it. `None` past the last key. A page
/// holds whole keys only, so it ends before a key it can't hold all of, or
/// holds just that one, whole, if it's the first.
async fn page(
    client: &Object,
    bucket: &str,
    after: &str,
) -> anyhow::Result<Option<(BTreeMap<String, Vec<Version>>, String)>> {
    const COLUMNS: &str = "key, id, version_id, is_latest, is_delete_marker, size, last_modified";
    let rows = client
        .query_cached(
            &format!(
                "SELECT {COLUMNS} FROM objects WHERE bucket = $1 AND key > $2
                 ORDER BY key, id DESC LIMIT $3"
            ),
            &[&bucket, &after, &PAGE],
        )
        .await?;
    fn add(versions: &mut BTreeMap<String, Vec<Version>>, row: &tokio_postgres::Row) {
        versions.entry(row.get(0)).or_default().push(Version {
            id: row.get(1),
            version_id: row.get(2),
            is_latest: row.get(3),
            delete_marker: row.get(4),
            size: row.get(5),
            last_modified: row.get(6),
        })
    }
    let mut versions = BTreeMap::new();
    rows.iter().for_each(|row| add(&mut versions, row));
    if rows.len() as i64 == PAGE {
        let (last, _) = versions.pop_last().expect("a full page has keys");
        if versions.is_empty() {
            // One key with a page of versions or more: all of them.
            let rows = client
                .query_cached(
                    &format!("SELECT {COLUMNS} FROM objects WHERE bucket = $1 AND key = $2 ORDER BY id DESC"),
                    &[&bucket, &last],
                )
                .await?;
            rows.iter().for_each(|row| add(&mut versions, row));
        }
    }
    Ok(versions.last_key_value().map(|(last, _)| last.clone()).map(|last| (versions, last)))
}

/// Expires a batch of due versions (`cairn_lifecycle_expire`), counting
/// those that still were in `report`. Whether the bucket's configuration was
/// still `config` (and its bucket still there).
async fn expire(
    app: &Arc<App>,
    client: &Object,
    bucket: &str,
    config: &str,
    batch: &[(String, Due)],
    report: &mut Report,
) -> anyhow::Result<bool> {
    let keys: Vec<&str> = batch.iter().map(|(key, _)| key.as_str()).collect();
    let ids: Vec<i64> = batch.iter().map(|(_, due)| due.version.id).collect();
    let version_ids: Vec<&str> = batch.iter().map(|(_, due)| due.version.version_id.as_str()).collect();
    let kinds: Vec<&str> = batch.iter().map(|(_, due)| due.kind.as_db()).collect();
    let (successors, newer): (Vec<Option<i64>>, Vec<Option<i32>>) = batch
        .iter()
        .map(|(_, due)| match due.kind {
            Kind::Noncurrent { successor, newer } => (Some(successor), Some(newer)),
            _ => (None, None),
        })
        .unzip();
    let marker_ids: Vec<String> = batch.iter().map(|_| new_version_id()).collect();
    for attempt in 0..db::MAX_TX_ATTEMPTS {
        db::backoff(attempt).await;
        let result = client
            .query_one_cached(
                "SELECT status, applied, reap_blob, reap_node, reap_peer
                 FROM pg_temp.cairn_lifecycle_expire($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                &[&bucket, &config, &keys, &ids, &version_ids, &kinds, &successors, &newer, &marker_ids],
            )
            .await;
        let row = match result {
            Ok(row) => row,
            Err(e) if db::is_conflict(&e) => continue,
            Err(e) => return Err(e.into()),
        };
        match row.get::<_, &str>(0) {
            "expired" => {}
            "changed" | "no_such_bucket" => return Ok(false),
            status => unreachable!("cairn_lifecycle_expire: unknown status {status}"),
        }
        let applied: Vec<bool> = row.get(1);
        for ((_, due), applied) in batch.iter().zip(applied) {
            match (applied, due.kind) {
                (false, _) => {}
                (true, Kind::Current) => report.expired += 1,
                (true, _) => report.removed += 1,
            }
        }
        reap_blobs(app, reap_columns(&row, 2));
        return Ok(true);
    }
    Err(crate::Contended("a lifecycle run kept conflicting with other requests".to_owned()).into())
}

/// Aborts an upload (`cairn_abort_upload`). Whether it was still there.
async fn abort(app: &Arc<App>, client: &Object, bucket: &str, key: &str, upload_id: Uuid) -> anyhow::Result<bool> {
    for attempt in 0..db::MAX_TX_ATTEMPTS {
        db::backoff(attempt).await;
        let result = client
            .query_one_cached(
                "SELECT existed, reap_blob, reap_node, reap_peer FROM pg_temp.cairn_abort_upload($1, $2, $3)",
                &[&upload_id, &bucket, &key],
            )
            .await;
        match result {
            Ok(row) => {
                reap_blobs(app, reap_columns(&row, 1));
                return Ok(row.get(0));
            }
            Err(e) if db::is_conflict(&e) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(crate::Contended("a lifecycle run kept conflicting with other requests".to_owned()).into())
}

#[cfg(test)]
mod e2e;
