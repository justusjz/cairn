//! Lifecycle rules: expiring objects, noncurrent versions and incomplete
//! uploads, as a bucket's lifecycle configuration says (see `rules`, and
//! `s3::buckets::lifecycle` for how it's set).
//!
//! Like S3, Cairn applies the rules in the background, not as objects are
//! read: an expired object stays readable until a sweep gets to it.
//!
//! A bucket with rules is swept continuously, a day at a time: a sweep walks
//! the bucket's versions in key order and expires the due ones, in small
//! steps, a minute apart, each a few pages of versions. As many pages as it
//! takes for the sweep to get through the bucket in `SWEEP_STEPS` minutes
//! (20 hours), going by how many versions the last sweep found, so that its
//! load is spread across the day, rather than coming at once. The next sweep
//! starts a day after the last one did, or right after it ends, if it took
//! longer. A version is expired when the sweep gets to it, so up to a day
//! after it became due, as S3 too takes its time.
//!
//! Every node looks for due steps once a minute (`pass`), and claims one by
//! moving its bucket's due time ahead (a lease), so that each step happens
//! on one node, and is taken up by another if that one dies. Where the sweep
//! has got to is saved after every page, so it carries on from there, and
//! never starts over but for a new configuration. Each step expires the due
//! versions of its pages (`cairn_lifecycle_expire`), checking each again
//! under the locks a delete takes: a version written meanwhile is never
//! mistaken for one that was due. A sweep stops when the bucket's
//! configuration changes under it, and a new one starts with the new one.
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

/// How long a claim on a step lasts: how long until another node takes it
/// up if its node dies. Each page extends it.
const LEASE: Duration = Duration::from_secs(600);
/// How long after a step the next one is due.
const STEP: Duration = crate::MAINTENANCE_INTERVAL;
/// How long after a sweep started the next one starts (unless it took
/// longer).
const SWEEP: Duration = Duration::from_secs(24 * 3600);
/// How many steps a sweep is spread over: 20 hours' worth, leaving some of
/// the day for steps that come late.
const SWEEP_STEPS: i64 = 1200;
/// How many pages a step of a bucket's first sweep (of its rules) reads,
/// before there's a last sweep to go by: 10,000 versions a minute, about 14
/// million a day, and more once it has taken longer (see `Sweep::pages`).
const FIRST_SWEEP_PAGES: i64 = 10;
/// How many versions a sweep reads at a time.
const PAGE: i64 = 1000;
/// How many versions a sweep expires in one transaction. More than 8 keys
/// lock their stripes, as a large DeleteObjects does (see `cairn_lock_keys`).
const BATCH: usize = 100;

/// What a step of a sweep did in a bucket.
#[derive(Debug, Default, PartialEq)]
pub struct Report {
    pub bucket: String,
    /// Current versions expired.
    pub expired: usize,
    /// Noncurrent versions and lone delete markers removed.
    pub removed: usize,
    /// Uploads aborted.
    pub aborted: usize,
    /// Whether it ended the sweep.
    pub finished: bool,
    /// Whether the configuration changed under it, which ended the sweep
    /// (and started a new one).
    pub interrupted: bool,
}

impl Report {
    /// Whether it changed nothing worth reporting.
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

/// A bucket's sweep, as a step claims it.
struct Sweep {
    bucket: String,
    /// Its configuration, as stored.
    config: String,
    /// When it started, and the key it has got to; `None` if it's yet to.
    started: Option<(SystemTime, String)>,
    /// How many versions it has read so far.
    seen: i64,
    /// How many versions the last whole sweep read.
    size: Option<i64>,
}

impl Sweep {
    /// How many pages a step taken at `now` reads, for the sweep to take
    /// `SWEEP_STEPS`. Going by the last sweep's size, if there was one, and
    /// faster the longer the sweep has taken beyond that: once more for every
    /// `SWEEP_STEPS` minutes it has run, so that it catches up, however far
    /// off that size was (or the first sweep's guess).
    fn pages(&self, now: SystemTime) -> i64 {
        let base = match self.size {
            None => FIRST_SWEEP_PAGES,
            Some(size) => size / (PAGE * SWEEP_STEPS) + 1,
        };
        let pace = (SWEEP_STEPS as u64) * STEP.as_secs();
        let elapsed = self.started.as_ref().and_then(|(started, _)| now.duration_since(*started).ok());
        let overdue = elapsed.map_or(0, |elapsed| elapsed.as_secs() / pace) as i64;
        base.saturating_mul(1 + overdue)
    }
}

/// Takes the steps of buckets' sweeps that are due as of `now` (the
/// database's clock), one after the other, as long as there are any. What
/// each did, with the bucket's name if it failed.
pub async fn pass(app: &Arc<App>, now: SystemTime) -> Vec<Result<Report, (String, anyhow::Error)>> {
    let mut results = Vec::new();
    loop {
        let sweep = match claim(app, now).await {
            Ok(Some(sweep)) => sweep,
            Ok(None) => return results,
            Err(e) => {
                results.push(Err((String::new(), e)));
                return results;
            }
        };
        // A failed step is taken up again from where it got to, when its
        // lease runs out.
        let bucket = sweep.bucket.clone();
        results.push(step(app, sweep, now).await.map_err(|e| (bucket, e)));
    }
}

/// The time by the database's clock.
pub async fn database_time(app: &App) -> anyhow::Result<SystemTime> {
    Ok(app.pool.get().await?.query_one_cached("SELECT now()", &[]).await?.get(0))
}

/// Claims a step that's due, if there's one, as of `now`. Skips the buckets
/// whose rows are locked, so that it never waits.
async fn claim(app: &App, now: SystemTime) -> anyhow::Result<Option<Sweep>> {
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
             RETURNING name, lifecycle, lifecycle_started, lifecycle_cursor, lifecycle_seen, lifecycle_size",
            &[&now, &lease_end],
        )
        .await?;
    Ok(row.map(|row| {
        let started: Option<SystemTime> = row.get(2);
        let cursor: Option<String> = row.get(3);
        Sweep {
            bucket: row.get(0),
            config: row.get(1),
            started: started.map(|started| (started, cursor.unwrap_or_default())),
            seen: row.get(4),
            size: row.get(5),
        }
    }))
}

/// Saves where the sweep has got to, and when its next step is due (`None`
/// to extend the lease), as long as the bucket's configuration is still the
/// one it follows. Whether it is.
async fn save(
    client: &Object,
    sweep: &Sweep,
    started: SystemTime,
    cursor: &str,
    due: Option<SystemTime>,
    now: SystemTime,
) -> anyhow::Result<bool> {
    // A lease runs from the database's clock, as `now` is from, when it's
    // later: a step may take a while.
    let lease = LEASE.as_secs_f64();
    let updated = client
        .execute_cached(
            "UPDATE buckets SET lifecycle_started = $3, lifecycle_cursor = $4, lifecycle_seen = $5,
                 lifecycle_due = coalesce($6, greatest(now(), $7) + make_interval(secs => $8))
             WHERE name = $1 AND lifecycle = $2",
            &[&sweep.bucket, &sweep.config, &started, &cursor, &sweep.seen, &due, &now, &lease],
        )
        .await?;
    Ok(updated > 0)
}

/// Ends the sweep, recording its `size` (the versions it read, if it read
/// them), and makes the next one due a day after it started, or `now` if
/// that's past, as long as the bucket's configuration is still the one it
/// followed. Whether it is.
async fn finish(
    client: &Object,
    sweep: &Sweep,
    started: SystemTime,
    size: Option<i64>,
    now: SystemTime,
) -> anyhow::Result<bool> {
    let next = (started + SWEEP).max(now);
    let updated = client
        .execute_cached(
            "UPDATE buckets SET lifecycle_started = NULL, lifecycle_cursor = NULL, lifecycle_seen = 0,
                 lifecycle_size = coalesce($3, lifecycle_size), lifecycle_due = $4
             WHERE name = $1 AND lifecycle = $2",
            &[&sweep.bucket, &sweep.config, &size, &next],
        )
        .await?;
    Ok(updated > 0)
}

/// Takes a step of the bucket's sweep as of `now`.
async fn step(app: &Arc<App>, mut sweep: Sweep, now: SystemTime) -> anyhow::Result<Report> {
    let rules = Configuration::from_json(&sweep.config).map_err(|e| {
        anyhow::anyhow!("its lifecycle configuration isn't one this Cairn knows (written by a newer one?): {e}")
    })?;
    let today = Day::of(now);
    let mut report = Report { bucket: sweep.bucket.clone(), ..Report::default() };
    let client = app.pool.get().await?;
    let (started, mut after) = sweep.started.clone().unwrap_or((now, String::new()));
    let interrupted = |mut report: Report| {
        report.interrupted = true;
        Ok(report)
    };
    if rules.expires_objects() {
        // Only the keys some rule may expire.
        let prefixes = rules.prefixes();
        let mut end = false;
        for _ in 0..sweep.pages(now) {
            let Some((versions, last, last_page)) = page(&client, &sweep.bucket, &after, &prefixes).await? else {
                end = true;
                break;
            };
            let due: Vec<(String, Due)> = versions
                .iter()
                .flat_map(|(key, versions)| rules.due(key, versions, today).into_iter().map(|due| (key.clone(), due)))
                .collect();
            for batch in due.chunks(BATCH) {
                if !expire(app, &client, &sweep.bucket, &sweep.config, batch, &mut report).await? {
                    return interrupted(report);
                }
            }
            sweep.seen += versions.values().map(|v| v.len() as i64).sum::<i64>();
            after = last;
            if !save(&client, &sweep, started, &after, None, now).await? {
                return interrupted(report);
            }
            if last_page {
                end = true;
                break;
            }
        }
        if !end {
            if !save(&client, &sweep, started, &after, Some(now + STEP), now).await? {
                return interrupted(report);
            }
            return Ok(report);
        }
    }
    // Uploads are few: all of them at the end of the sweep.
    if rules.aborts_uploads() {
        let mut after = (String::new(), Uuid::nil());
        loop {
            let rows = client
                .query_cached(
                    "SELECT key, upload_id, initiated_at FROM multipart_uploads
                     WHERE bucket = $1 AND (key, upload_id) > ($2, $3)
                     ORDER BY key, upload_id LIMIT $4",
                    &[&sweep.bucket, &after.0, &after.1, &PAGE],
                )
                .await?;
            let Some(last) = rows.last() else { break };
            after = (last.get(0), last.get(1));
            for row in &rows {
                let (key, upload_id): (String, Uuid) = (row.get(0), row.get(1));
                if rules.aborts(&key, row.get(2), today) && abort(app, &client, &sweep.bucket, &key, upload_id).await? {
                    report.aborted += 1;
                }
            }
        }
    }
    let size = rules.expires_objects().then_some(sweep.seen);
    if !finish(&client, &sweep, started, size, now).await? {
        return interrupted(report);
    }
    report.finished = true;
    Ok(report)
}

/// The versions in a page: each key's, newest first.
type Page = BTreeMap<String, Vec<Version>>;

/// The next page of the bucket's versions after the key `after`, under
/// `prefixes` (in order, none under another, as `Configuration::prefixes`
/// gives them), the last key in it, and whether it's the last page. `None`
/// past the last key. A page holds whole keys only, so it ends before a key
/// it can't hold all of, or holds just that one, whole, if it's the first.
async fn page(
    client: &Object,
    bucket: &str,
    after: &str,
    prefixes: &[String],
) -> anyhow::Result<Option<(Page, String, bool)>> {
    const COLUMNS: &str = "key, id, version_id, is_latest, is_delete_marker, size, last_modified";
    // The ranges of keys under the prefixes, from the first that isn't
    // behind `after`: on to the next once one has no keys left.
    let ranges: Vec<(&String, Option<String>)> =
        prefixes.iter().map(|prefix| (prefix, rules::prefix_end(prefix))).collect();
    let mut next = ranges.iter().position(|(_, end)| end.as_deref().is_none_or(|end| end > after));
    let (rows, last_range) = loop {
        let Some(i) = next.filter(|&i| i < ranges.len()) else { return Ok(None) };
        next = Some(i + 1);
        let (prefix, end) = &ranges[i];
        let rows = match &end {
            Some(end) => {
                client
                    .query_cached(
                        &format!(
                            "SELECT {COLUMNS} FROM objects
                             WHERE bucket = $1 AND key > $2 AND key >= $3 AND key < $4
                             ORDER BY key, id DESC LIMIT $5"
                        ),
                        &[&bucket, &after, prefix, end, &PAGE],
                    )
                    .await?
            }
            None => {
                client
                    .query_cached(
                        &format!(
                            "SELECT {COLUMNS} FROM objects WHERE bucket = $1 AND key > $2 AND key >= $3
                             ORDER BY key, id DESC LIMIT $4"
                        ),
                        &[&bucket, &after, prefix, &PAGE],
                    )
                    .await?
            }
        };
        if !rows.is_empty() {
            break (rows, i + 1 == ranges.len());
        }
    };
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
    let last_page = last_range && (rows.len() as i64) < PAGE;
    Ok(versions.last_key_value().map(|(last, _)| last.clone()).map(|last| (versions, last, last_page)))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweeps_that_run_late_catch_up() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let sweep = |size: Option<i64>, started: Option<SystemTime>| Sweep {
            bucket: String::new(),
            config: String::new(),
            started: started.map(|started| (started, String::new())),
            seen: 0,
            size,
        };
        let pace = STEP * SWEEP_STEPS as u32;
        // 20 hours of steps for its size.
        assert_eq!(sweep(Some(10), None).pages(start), 1);
        assert_eq!(sweep(Some(PAGE * SWEEP_STEPS * 3), None).pages(start), 4);
        assert_eq!(sweep(None, None).pages(start), FIRST_SWEEP_PAGES);
        // Then once more for every 20 hours it's been going.
        assert_eq!(sweep(Some(10), Some(start)).pages(start + pace / 2), 1);
        assert_eq!(sweep(Some(10), Some(start)).pages(start + pace), 2);
        assert_eq!(sweep(None, Some(start)).pages(start + pace * 3), FIRST_SWEEP_PAGES * 4);
    }
}
