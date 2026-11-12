//! Lifecycle rules: expiring objects, noncurrent versions and incomplete
//! uploads, as a bucket's lifecycle configuration says (see `rules`, and
//! `s3::buckets::lifecycle` for how it's set).
//!
//! Like S3, Cairn applies the rules in the background, not as objects are
//! read: an expired object stays readable until a sweep gets to it.
//!
//! A bucket with rules is swept once a day: a sweep walks the versions under
//! the rules' prefixes in key order, and expires the due ones. Sweeps go at a
//! rate the admin sets for the whole cluster (`settings::LIFECYCLE_RATE`,
//! versions read per hour), so that however much there is to sweep, they
//! never take more of the database than that. If a day isn't enough for every
//! bucket's sweep at that rate, they take longer, and expirations come late;
//! the console shows how long a round of them takes, so that the admin can
//! raise the rate.
//!
//! Sweeps take turns: there's one step at a time in the whole cluster, about
//! once a minute, on whichever node claims it first (`cairn_lifecycle_claim`,
//! a lease, which another node takes over if that one dies). A step reads the
//! rate's share of the time since the last step began, from the buckets due,
//! the one that has waited longest first, and moves each it gets to the back
//! of the line, so that a huge bucket doesn't hold up small ones. Where a
//! sweep has got to is saved after every page, so that it carries on from
//! there; it only starts over for a new configuration. A bucket's next sweep
//! is due a day after its last one started, or right away, if that took
//! longer.
//!
//! Each step expires the due versions of its pages (`cairn_lifecycle_expire`),
//! checking each again under the locks a delete takes: a version written
//! meanwhile is never mistaken for one that was due. A sweep stops when the
//! bucket's configuration changes under it, and a new one starts with the new
//! one.
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
    settings::LIFECYCLE_RATE,
};

pub mod rules;

use rules::{Configuration, Day, Due, Kind, Version};

/// How long a claim on a step lasts: how long until another node takes it
/// up if its node dies. Each page extends it.
const LEASE: Duration = Duration::from_secs(600);
/// How long after a step began the next one may.
const STEP: Duration = crate::MAINTENANCE_INTERVAL;
/// The most time a step reads the rate's share of: after a pause (the whole
/// cluster down, say), sweeps carry on at the rate, rather than making up for
/// it all at once.
const MAX_SHARE: Duration = Duration::from_secs(300);
/// How long after a sweep started the next one starts (unless it took
/// longer).
const SWEEP: Duration = Duration::from_secs(24 * 3600);
/// The most versions a sweep reads at a time.
const PAGE: i64 = 1000;
/// How many versions a sweep expires in one transaction. More than 8 keys
/// lock their stripes, as a large DeleteObjects does (see `cairn_lock_keys`).
const BATCH: usize = 100;

/// What a turn of a bucket's sweep did.
#[derive(Debug, Default, PartialEq)]
pub struct Report {
    pub bucket: String,
    /// Versions (and uploads) read.
    pub read: i64,
    /// Current versions expired.
    pub expired: i64,
    /// Noncurrent versions and lone delete markers removed.
    pub removed: i64,
    /// Uploads aborted.
    pub aborted: i64,
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

/// A bucket's last whole sweep, as `lifecycle_sweeps.last` keeps it. Times
/// are seconds since the Unix epoch.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct LastSweep {
    pub started: f64,
    pub finished: f64,
    /// Versions (and uploads) read.
    pub read: i64,
    pub expired: i64,
    pub removed: i64,
    pub aborted: i64,
}

/// A bucket's sweep, as a step gets to it.
struct Sweep {
    bucket: String,
    /// Its configuration, as stored, and its generation.
    config: String,
    generation: i64,
    /// When it started, and the key it has got to; `None` if it's yet to.
    started: Option<(SystemTime, String)>,
    /// What it had done before this turn: read, expired, removed, aborted.
    before: [i64; 4],
}

/// Takes the cluster's next lifecycle step, if it's due as of `now` (the
/// database's clock), and no other node is taking it: reads the rate's share
/// of the time since the last step began, from the buckets due. What it did
/// in each, with the bucket's name if that failed.
pub async fn pass(app: &Arc<App>, now: SystemTime) -> Vec<Result<Report, (String, anyhow::Error)>> {
    match take_step(app, now).await {
        Ok(results) => results,
        Err(e) => vec![Err((String::new(), e))],
    }
}

async fn take_step(app: &Arc<App>, now: SystemTime) -> anyhow::Result<Vec<Result<Report, (String, anyhow::Error)>>> {
    let client = app.pool.get().await?;
    let rate = LIFECYCLE_RATE.get(&client).await?;
    if rate == 0 {
        return Ok(Vec::new());
    }
    let Some(previous) = claim(&client, now).await? else { return Ok(Vec::new()) };
    let began = std::time::Instant::now();
    let share = previous.and_then(|previous| now.duration_since(previous).ok()).unwrap_or(STEP).min(MAX_SHARE);
    let mut budget = (((rate as f64) * share.as_secs_f64() / 3600.0) as i64).max(1);
    let mut results = Vec::new();
    let mut visited = Vec::new();
    let mut read = 0;
    // Whatever happens, the claim is let go of after, rather than holding up
    // every step until its lease runs out.
    let walked: anyhow::Result<()> = async {
        while budget > 0 {
            let Some(sweep) = next_sweep(&client, now, &visited).await? else { break };
            visited.push(sweep.bucket.clone());
            let bucket = sweep.bucket.clone();
            let result = turn(app, &client, sweep, now, &mut budget).await;
            read += result.as_ref().map_or(0, |report| report.read);
            results.push(result.map_err(|e| (bucket, e)));
        }
        Ok(())
    }
    .await;
    // A step that had more to do than its share shows the rate steps reach:
    // its share, or less, if it took longer than the time it was the share of.
    let busy = budget <= 0;
    let secs = share.max(began.elapsed()).as_secs_f64();
    release(&client, busy.then_some((read, secs)), now).await?;
    walked?;
    Ok(results)
}

/// Lets go of the claim on the step, and if it was `busy` (the versions it
/// read, and over how many seconds), counts it into the rate reached: an
/// average weighted by time, which mostly forgets what was over an hour ago.
async fn release(client: &Object, busy: Option<(i64, f64)>, now: SystemTime) -> anyhow::Result<()> {
    let Some((read, secs)) = busy else {
        client.execute_cached("UPDATE lifecycle_runs SET lease_until = NULL WHERE id", &[]).await?;
        return Ok(());
    };
    let reached = read as f64 / secs * 3600.0;
    let weight = (secs / 3600.0).min(1.0);
    client
        .execute_cached(
            "UPDATE lifecycle_runs SET lease_until = NULL, reached_at = $3,
                 reached_rate = CASE WHEN reached_rate IS NULL THEN $1::float8
                                     ELSE reached_rate * (1 - $2::float8) + $1::float8 * $2::float8 END
             WHERE id",
            &[&reached, &weight, &now],
        )
        .await?;
    Ok(())
}

/// The time by the database's clock.
pub async fn database_time(app: &App) -> anyhow::Result<SystemTime> {
    Ok(app.pool.get().await?.query_one_cached("SELECT now()", &[]).await?.get(0))
}

/// Claims the cluster's next step (`cairn_lifecycle_claim`), if it's due as
/// of `now`, and no other node holds it: when the last step began (`None`
/// before the first). `None` if it didn't.
async fn claim(client: &Object, now: SystemTime) -> anyhow::Result<Option<Option<SystemTime>>> {
    let row = client
        .query_one_cached(
            "SELECT claimed, previous FROM pg_temp.cairn_lifecycle_claim($1, $2, $3)",
            &[&now, &LEASE.as_secs_f64(), &STEP.as_secs_f64()],
        )
        .await?;
    Ok(row.get::<_, bool>(0).then(|| row.get(1)))
}

/// Extends the claim on the step.
async fn extend(client: &Object, now: SystemTime) -> anyhow::Result<()> {
    client
        .execute_cached(
            "UPDATE lifecycle_runs SET lease_until = greatest(now(), $1) + make_interval(secs => $2) WHERE id",
            &[&now, &LEASE.as_secs_f64()],
        )
        .await?;
    Ok(())
}

/// The sweep due as of `now` that has waited longest, but for the buckets
/// `visited` this step already.
async fn next_sweep(client: &Object, now: SystemTime, visited: &[String]) -> anyhow::Result<Option<Sweep>> {
    let row = client
        .query_opt_cached(
            "SELECT b.name, b.lifecycle, s.started, s.cursor, s.seen, s.expired, s.removed, s.aborted,
                    s.generation
             FROM lifecycle_sweeps s JOIN buckets b ON b.name = s.bucket
             WHERE s.due <= $1 AND NOT (s.bucket = ANY($2))
               AND b.lifecycle IS NOT NULL AND b.lifecycle_generation = s.generation
             ORDER BY s.due LIMIT 1",
            &[&now, &visited],
        )
        .await?;
    Ok(row.map(|row| {
        let started: Option<SystemTime> = row.get(2);
        let cursor: Option<String> = row.get(3);
        Sweep {
            bucket: row.get(0),
            config: row.get(1),
            generation: row.get(8),
            started: started.map(|started| (started, cursor.unwrap_or_default())),
            before: [row.get(4), row.get(5), row.get(6), row.get(7)],
        }
    }))
}

/// Saves where the sweep has got to, and what it has done, as long as the
/// bucket's configuration is still the one it follows. Whether it is.
async fn save(
    client: &Object,
    sweep: &Sweep,
    started: SystemTime,
    cursor: &str,
    report: &Report,
) -> anyhow::Result<bool> {
    let [read, expired, removed, aborted] = sweep.before;
    let updated = client
        .execute_cached(
            "UPDATE lifecycle_sweeps SET started = $3, cursor = $4, seen = $5,
                 expired = $6, removed = $7, aborted = $8
             WHERE bucket = $1 AND generation = $2",
            &[
                &sweep.bucket,
                &sweep.generation,
                &started,
                &cursor,
                &(read + report.read),
                &(expired + report.expired),
                &(removed + report.removed),
                &(aborted + report.aborted),
            ],
        )
        .await?;
    Ok(updated > 0)
}

/// Sends the sweep to the back of the line, as of `now`, as long as the
/// bucket's configuration is still the one it follows. Whether it is.
async fn yield_turn(client: &Object, sweep: &Sweep, now: SystemTime) -> anyhow::Result<bool> {
    let updated = client
        .execute_cached(
            "UPDATE lifecycle_sweeps SET due = $3 WHERE bucket = $1 AND generation = $2",
            &[&sweep.bucket, &sweep.generation, &now],
        )
        .await?;
    Ok(updated > 0)
}

/// Ends the sweep: records it as the last whole one, and makes the next one
/// due a day after it started, or `now` if that's past, as long as the
/// bucket's configuration is still the one it followed. Whether it is.
async fn finish(
    client: &Object,
    sweep: &Sweep,
    started: SystemTime,
    report: &Report,
    now: SystemTime,
) -> anyhow::Result<bool> {
    let secs = |t: SystemTime| t.duration_since(SystemTime::UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64());
    let [read, expired, removed, aborted] = sweep.before;
    let last = LastSweep {
        started: secs(started),
        finished: secs(now),
        read: read + report.read,
        expired: expired + report.expired,
        removed: removed + report.removed,
        aborted: aborted + report.aborted,
    };
    let last = serde_json::to_string(&last)?;
    let next = (started + SWEEP).max(now);
    let updated = client
        .execute_cached(
            "UPDATE lifecycle_sweeps SET started = NULL, cursor = NULL, seen = 0,
                 expired = 0, removed = 0, aborted = 0, last = $3, due = $4
             WHERE bucket = $1 AND generation = $2",
            &[&sweep.bucket, &sweep.generation, &last, &next],
        )
        .await?;
    Ok(updated > 0)
}

/// Takes the bucket's sweep as far as `budget` (versions to read) allows,
/// taking off what it reads.
async fn turn(
    app: &Arc<App>,
    client: &Object,
    sweep: Sweep,
    now: SystemTime,
    budget: &mut i64,
) -> anyhow::Result<Report> {
    let rules = Configuration::from_json(&sweep.config).map_err(|e| {
        anyhow::anyhow!("its lifecycle configuration isn't one this Cairn knows (written by a newer one?): {e}")
    })?;
    let today = Day::of(now);
    let mut report = Report { bucket: sweep.bucket.clone(), ..Report::default() };
    let (started, mut after) = sweep.started.clone().unwrap_or((now, String::new()));
    let interrupted = |mut report: Report| {
        report.interrupted = true;
        Ok(report)
    };
    if rules.expires_objects() {
        // Only the keys some rule may expire.
        let prefixes = rules.prefixes();
        let mut end = false;
        while *budget > 0 {
            let limit = (*budget).min(PAGE);
            let Some((versions, last, last_page)) = page(client, &sweep.bucket, &after, &prefixes, limit).await?
            else {
                end = true;
                break;
            };
            let due: Vec<(String, Due)> = versions
                .iter()
                .flat_map(|(key, versions)| rules.due(key, versions, today).into_iter().map(|due| (key.clone(), due)))
                .collect();
            for batch in due.chunks(BATCH) {
                if !expire(app, client, &sweep.bucket, sweep.generation, batch, &mut report).await? {
                    return interrupted(report);
                }
            }
            let read = versions.values().map(|v| v.len() as i64).sum::<i64>();
            report.read += read;
            *budget -= read;
            after = last;
            if !save(client, &sweep, started, &after, &report).await? {
                return interrupted(report);
            }
            extend(client, now).await?;
            if last_page {
                end = true;
                break;
            }
        }
        if !end {
            if !yield_turn(client, &sweep, now).await? {
                return interrupted(report);
            }
            return Ok(report);
        }
    }
    // Uploads are few: all of them at the end of the sweep, whatever is left
    // of the budget.
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
            report.read += rows.len() as i64;
            *budget -= rows.len() as i64;
            for row in &rows {
                let (key, upload_id): (String, Uuid) = (row.get(0), row.get(1));
                if rules.aborts(&key, row.get(2), today) && abort(app, client, &sweep.bucket, &key, upload_id).await? {
                    report.aborted += 1;
                }
            }
        }
    }
    if !finish(client, &sweep, started, &report, now).await? {
        return interrupted(report);
    }
    report.finished = true;
    Ok(report)
}

/// The versions in a page: each key's, newest first.
type Page = BTreeMap<String, Vec<Version>>;

/// The next page of up to `limit` of the bucket's versions after the key
/// `after`, under
/// `prefixes` (in order, none under another, as `Configuration::prefixes`
/// gives them), the last key in it, and whether it's the last page. `None`
/// past the last key. A page holds whole keys only, so it ends before a key
/// it can't hold all of, or holds just that one, whole, if it's the first.
async fn page(
    client: &Object,
    bucket: &str,
    after: &str,
    prefixes: &[String],
    limit: i64,
) -> anyhow::Result<Option<(Page, String, bool)>> {
    const COLUMNS: &str = "key, id, version_id, is_latest, is_delete_marker, size, last_modified, tags";
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
                        &[&bucket, &after, prefix, end, &limit],
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
                        &[&bucket, &after, prefix, &limit],
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
            tags: row.get(7),
        })
    }
    let mut versions = BTreeMap::new();
    rows.iter().for_each(|row| add(&mut versions, row));
    if rows.len() as i64 == limit {
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
    let last_page = last_range && (rows.len() as i64) < limit;
    Ok(versions.last_key_value().map(|(last, _)| last.clone()).map(|last| (versions, last, last_page)))
}

/// Expires a batch of due versions (`cairn_lifecycle_expire`), counting
/// those that still were in `report`. Whether the bucket's configuration was
/// still of `generation` (and its bucket still there).
async fn expire(
    app: &Arc<App>,
    client: &Object,
    bucket: &str,
    generation: i64,
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
    // The tags each had as it was read, which it must still have.
    let tags: Vec<&str> = batch.iter().map(|(_, due)| due.version.tags.as_str()).collect();
    for attempt in 0..db::MAX_TX_ATTEMPTS {
        db::backoff(attempt).await;
        let result = client
            .query_one_cached(
                "SELECT status, applied, reap_blob, reap_node, reap_peer
                 FROM pg_temp.cairn_lifecycle_expire($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                &[&bucket, &generation, &keys, &ids, &version_ids, &kinds, &successors, &newer, &marker_ids, &tags],
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
