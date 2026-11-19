//! The maintenance S3 Tables does itself, in the background, on every
//! table with metadata: each job a row (`table_maintenance_runs`), due at
//! its time, taken by one node at a time, its outcome what
//! GetTableMaintenanceJobStatus tells.
//!
//! - **Snapshot management** (a table's `icebergSnapshotManagement`),
//!   hourly: as Iceberg's `ExpireSnapshots`, the snapshots of `main` beyond
//!   the newest `minSnapshotsToKeep`, and older than `maxSnapshotAgeHours`,
//!   expire (a snapshot is kept if either keeps it), and so do snapshots
//!   off `main` that old. The expiry is a commit as any other: a new
//!   metadata file, the table's pointer swapped to it against its version
//!   token (a client's commit in between makes it try again later). It
//!   fails, as AWS's does, for a table with branches or tags other than
//!   `main`, or `history.expire.*` properties, or `gc.enabled=false`.
//! - **Unreferenced file removal** (a table bucket's
//!   `icebergUnreferencedFileRemoval`), daily: what a table references is
//!   its metadata files (the current one and its log), its statistics
//!   files, and every file of every snapshot (manifest lists, manifests,
//!   and the data and delete files they list, whatever their status), read
//!   from the manifests (with the `iceberg` crate's readers). A file of its storage
//!   nothing references is noted; after `unreferencedDays` of that, it's
//!   noncurrent, and after `nonCurrentDays` more, deleted. A file that's
//!   referenced again meanwhile is forgotten. If anything can't be read,
//!   nothing is deleted: the job fails, and says why. Not for a table with
//!   `gc.enabled=false`.
//! - **Compaction** (a table's `icebergCompaction`), hourly: see
//!   `compaction`.
//!
//! As AWS's, files that only expired snapshots referenced are noncurrent at
//! once (they're noted when the expiry commits). Maintenance acts as
//! Cairn, which can open SSE-S3 files but not SSE-KMS ones: on a table
//! with SSE-KMS, its jobs fail, saying so.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ::iceberg::TableUpdate;
use ::iceberg::spec::{TableMetadata, TableMetadataBuilder};
use hyper::body::Bytes;
use serde_json::Value;
use uuid::Uuid;

use super::{
    Table, TableBucket,
    buckets::bucket_maintenance,
    iceberg::{self, FileError},
    table::table_maintenance,
};
use crate::App;

pub const SNAPSHOTS: &str = "icebergSnapshotManagement";
pub const UNREFERENCED: &str = "icebergUnreferencedFileRemoval";

/// How often each job runs on a table (compaction as often as snapshot
/// management), and how soon one that couldn't finish (a commit raced it,
/// a node died), or that has more to do, runs again.
const SNAPSHOTS_EVERY: Duration = Duration::from_secs(3600);
const UNREFERENCED_EVERY: Duration = Duration::from_secs(24 * 3600);
const RETRY_AFTER: Duration = Duration::from_secs(300);
/// How long a node has a job it took.
const CLAIM: Duration = Duration::from_secs(1800);
/// How often a node looks for jobs that are due, and how many it takes.
const PASS_EVERY: Duration = Duration::from_secs(60);
const JOBS_PER_PASS: i64 = 20;

/// How a job went.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    Successful(String),
    Failed(String),
    /// Its configuration has it disabled.
    Disabled,
    /// It couldn't finish now (a commit raced it): soon again.
    Retry,
    /// It went well, and there's more to do: soon again.
    More(String),
}

fn ms(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

/// Runs due jobs, forever.
pub async fn run(app: Arc<App>) {
    loop {
        tokio::time::sleep(PASS_EVERY).await;
        let task_app = app.clone();
        let pass = tokio::spawn(async move { pass(&task_app, SystemTime::now()).await });
        match pass.await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => eprintln!("tables: maintenance failed: {e:#}"),
            Err(e) => eprintln!("tables: maintenance panicked: {e}"),
        }
    }
}

/// Takes the jobs due at `now`, and runs them: how many.
pub async fn pass(app: &Arc<App>, now: SystemTime) -> anyhow::Result<usize> {
    let client = app.pool.get().await?;
    client
        .execute(
            "INSERT INTO table_maintenance_runs (table_id, kind)
             SELECT t.id, k.kind FROM tables t
             CROSS JOIN (VALUES ('icebergSnapshotManagement'), ('icebergUnreferencedFileRemoval'),
                                ('icebergCompaction')) k (kind)
             WHERE t.metadata_location IS NOT NULL
             ON CONFLICT DO NOTHING",
            &[],
        )
        .await?;
    let until = now + CLAIM;
    let jobs = client
        .query(
            "UPDATE table_maintenance_runs r SET claimed_until = $2
             FROM (SELECT table_id, kind FROM table_maintenance_runs
                   WHERE next_due <= $1 AND (claimed_until IS NULL OR claimed_until < $1)
                   ORDER BY next_due LIMIT $3 FOR UPDATE SKIP LOCKED) due
             WHERE r.table_id = due.table_id AND r.kind = due.kind
             RETURNING r.table_id, r.kind",
            &[&now, &until, &JOBS_PER_PASS],
        )
        .await?;
    drop(client);
    for row in &jobs {
        let (table, kind): (Uuid, String) = (row.get(0), row.get(1));
        let outcome = match run_job(app, table, &kind, now).await {
            Ok(outcome) => outcome,
            Err(e) => Outcome::Failed(format!("{e:#}")),
        };
        if let Outcome::Failed(why) = &outcome {
            eprintln!("tables: {kind} of table {table} failed: {why}");
        }
        record(app, table, &kind, now, &outcome).await?;
    }
    Ok(jobs.len())
}

/// Notes how a job went, and when it's next due.
async fn record(
    app: &App,
    table: Uuid,
    kind: &str,
    now: SystemTime,
    outcome: &Outcome,
) -> anyhow::Result<()> {
    let every = match kind {
        SNAPSHOTS | super::compaction::COMPACTION => SNAPSHOTS_EVERY,
        _ => UNREFERENCED_EVERY,
    };
    let (status, failure, next): (Option<&str>, Option<&str>, SystemTime) = match outcome {
        Outcome::Successful(_) => (Some("Successful"), None, now + every),
        Outcome::Failed(why) => (Some("Failed"), Some(why.as_str()), now + every),
        Outcome::Disabled => (None, None, now + every),
        Outcome::Retry => (None, None, now + RETRY_AFTER),
        Outcome::More(_) => (Some("Successful"), None, now + RETRY_AFTER),
    };
    let client = app.pool.get().await?;
    match status {
        Some(status) => {
            client
                .execute(
                    "UPDATE table_maintenance_runs SET status = $3, failure = $4, last_run = $5,
                            next_due = $6, claimed_until = NULL
                     WHERE table_id = $1 AND kind = $2",
                    &[&table, &kind, &status, &failure, &now, &next],
                )
                .await?
        }
        None => {
            client
                .execute(
                    "UPDATE table_maintenance_runs SET next_due = $3, claimed_until = NULL
                     WHERE table_id = $1 AND kind = $2",
                    &[&table, &kind, &next],
                )
                .await?
        }
    };
    Ok(())
}

/// Runs job `kind` of table `id`, as of `now`.
pub async fn run_job(
    app: &Arc<App>,
    id: Uuid,
    kind: &str,
    now: SystemTime,
) -> anyhow::Result<Outcome> {
    let storage: Option<String> = app
        .pool
        .get()
        .await?
        .query_opt("SELECT storage FROM tables WHERE id = $1", &[&id])
        .await?
        .map(|r| r.get(0));
    let Some(storage) = storage else {
        return Ok(Outcome::Disabled);
    };
    let Some((bucket, table)) = Table::by_storage(&app.pool.get().await?, &storage).await? else {
        return Ok(Outcome::Disabled);
    };
    match kind {
        SNAPSHOTS => expire_snapshots(app, &table, now).await,
        UNREFERENCED => remove_unreferenced(app, &bucket, &table, now).await,
        super::compaction::COMPACTION => super::compaction::compact(app, &table, now).await,
        _ => Ok(Outcome::Disabled),
    }
}

/// A configuration's status and settings (`kind`'s, of `configuration`).
fn settings(configuration: &Value, kind: &str) -> Option<Value> {
    let value = &configuration[kind];
    (value["status"] == "enabled").then(|| value["settings"][kind].clone())
}

/// The table's current metadata, as Cairn reads it, and where it is.
pub(super) async fn current(
    app: &Arc<App>,
    table: &Table,
) -> anyhow::Result<Result<(String, TableMetadata), String>> {
    let Some(location) = &table.metadata_location else {
        return Ok(Err("The table has no metadata.".into()));
    };
    if table.sse_algorithm == "aws:kms" {
        return Ok(Err(
            "Maintenance can't open tables encrypted with SSE-KMS.".into()
        ));
    }
    Ok(match iceberg::read(app, table, None, location).await? {
        Ok(m) => Ok((location.clone(), m)),
        Err(FileError::Unusable(why) | FileError::Refused(why)) => Err(why),
    })
}

fn property<'a>(metadata: &'a TableMetadata, name: &str) -> Option<&'a str> {
    metadata.properties().get(name).map(String::as_str)
}

/// The names of the table's refs (its branches and tags).
fn refs(metadata: &TableMetadata) -> Vec<String> {
    serde_json::to_value(metadata)
        .ok()
        .and_then(|m| m["refs"].as_object().map(|r| r.keys().cloned().collect()))
        .unwrap_or_default()
}

/// The snapshots that expire, of `metadata`'s, as of `now` (ms), keeping
/// the newest `keep` of `main`'s and those younger than `max_age` (ms).
pub fn expiring(metadata: &TableMetadata, keep: usize, max_age: i64, now: i64) -> Vec<i64> {
    let mut ancestry = Vec::new();
    let mut next = metadata.snapshot_for_ref("main").map(|s| s.snapshot_id());
    while let Some(id) = next {
        if ancestry.contains(&id) {
            break;
        }
        ancestry.push(id);
        next = metadata
            .snapshot_by_id(id)
            .and_then(|s| s.parent_snapshot_id());
    }
    let kept: HashSet<i64> = ancestry.iter().take(keep.max(1)).copied().collect();
    metadata
        .snapshots()
        .filter(|s| !kept.contains(&s.snapshot_id()) && s.timestamp_ms() < now - max_age)
        .map(|s| s.snapshot_id())
        .collect()
}

async fn expire_snapshots(
    app: &Arc<App>,
    table: &Table,
    now: SystemTime,
) -> anyhow::Result<Outcome> {
    let Some(settings) = settings(&table_maintenance(&table.maintenance), SNAPSHOTS) else {
        return Ok(Outcome::Disabled);
    };
    let keep = settings["minSnapshotsToKeep"].as_i64().unwrap_or(1).max(1) as usize;
    let max_age = settings["maxSnapshotAgeHours"].as_i64().unwrap_or(120) * 3600 * 1000;
    let (location, current) = match current(app, table).await? {
        Ok(current) => current,
        Err(why) => return Ok(Outcome::Failed(why)),
    };
    if refs(&current).iter().any(|name| name != "main") {
        return Ok(Outcome::Failed(
            "Snapshot management isn't supported for tables with branches or tags other than main."
                .into(),
        ));
    }
    if current
        .properties()
        .keys()
        .any(|k| k.starts_with("history.expire."))
    {
        return Ok(Outcome::Failed(
            "Snapshot management isn't supported when the table has history.expire.* properties."
                .into(),
        ));
    }
    if property(&current, "gc.enabled") == Some("false") {
        return Ok(Outcome::Failed(
            "Snapshot management is not supported when 'gc.enabled' table property is false."
                .into(),
        ));
    }
    let expired = expiring(&current, keep, max_age, ms(now));
    if expired.is_empty() {
        return Ok(Outcome::Successful("no snapshot expired".into()));
    }
    let before = referenced(app, table, &location, &current).await?;
    let builder = TableMetadataBuilder::new_from_metadata(current, Some(location.clone()));
    let update = TableUpdate::RemoveSnapshots {
        snapshot_ids: expired.clone(),
    };
    let built = match update.apply(builder).and_then(|b| b.build()) {
        Ok(built) => built.metadata,
        Err(e) => return Ok(Outcome::Failed(e.message().to_owned())),
    };
    let file = iceberg::next_file(
        &table.warehouse_location(),
        Some(&location),
        &Uuid::new_v4().to_string(),
    );
    if let Err(FileError::Unusable(why) | FileError::Refused(why)) =
        iceberg::write(app, table, None, &file, &built).await?
    {
        return Ok(Outcome::Failed(why));
    }
    let swapped = app
        .pool
        .get()
        .await?
        .query_opt(
            "UPDATE tables SET metadata_location = $3, version_token = $4, modified_at = now()
             WHERE id = $1 AND version_token = $2 RETURNING id",
            &[
                &table.id,
                &table.version_token,
                &file,
                &super::version_token(),
            ],
        )
        .await?;
    if swapped.is_none() {
        // A client committed meanwhile: on its metadata, soon.
        return Ok(Outcome::Retry);
    }
    // The files only the expired snapshots referenced are noncurrent at
    // once, as AWS's are.
    if let Ok(before) = before {
        let after = referenced(app, table, &file, &built).await?;
        if let Ok(after) = after {
            let gone: Vec<String> = before.difference(&after).cloned().collect();
            app.pool
                .get()
                .await?
                .execute(
                    "INSERT INTO table_unreferenced_files (table_id, key, unreferenced_since, noncurrent_since)
                     SELECT $1, k, $3, $3 FROM unnest($2::text[]) k
                     ON CONFLICT (table_id, key) DO UPDATE SET noncurrent_since = $3",
                    &[&table.id, &gone, &now],
                )
                .await?;
        }
    }
    Ok(Outcome::Successful(format!(
        "{} snapshot(s) expired",
        expired.len()
    )))
}

/// The key of a path (`s3://`, `s3a://` or `s3n://`) in `table`'s storage.
fn key_of(table: &Table, path: &str) -> Option<String> {
    let rest = ["s3://", "s3a://", "s3n://"]
        .iter()
        .find_map(|scheme| path.strip_prefix(scheme))?;
    rest.strip_prefix(table.storage.as_str())?
        .strip_prefix('/')
        .filter(|k| !k.is_empty())
        .map(str::to_owned)
}

/// The keys of everything `metadata` (at `location`) references in
/// `table`'s storage: its metadata files, statistics, manifest lists,
/// manifests, and the data and delete files they list (whatever their
/// status); `Err` with why, if some of it can't be read.
async fn referenced(
    app: &Arc<App>,
    table: &Table,
    location: &str,
    metadata: &TableMetadata,
) -> anyhow::Result<Result<HashSet<String>, String>> {
    let io = iceberg::io::file_io(app, table, None);
    let reader = match ::iceberg::table::Table::builder()
        .metadata(metadata.clone())
        .identifier(::iceberg::TableIdent::from_strs(["maintenance", "table"])?)
        .file_io(io)
        .runtime(::iceberg::Runtime::current())
        .readonly(true)
        .build()
    {
        Ok(reader) => reader,
        Err(e) => return Ok(Err(e.message().to_owned())),
    };
    let mut paths: Vec<String> = vec![location.to_owned()];
    paths.extend(
        metadata
            .metadata_log()
            .iter()
            .map(|l| l.metadata_file.clone()),
    );
    paths.extend(
        metadata
            .statistics_iter()
            .map(|s| s.statistics_path.clone()),
    );
    paths.extend(
        metadata
            .partition_statistics_iter()
            .map(|s| s.statistics_path.clone()),
    );
    let mut manifests = Vec::new();
    for snapshot in metadata.snapshots() {
        paths.push(snapshot.manifest_list().to_owned());
        let list = match reader.manifest_list_reader(snapshot).load().await {
            Ok(list) => list,
            Err(e) => {
                return Ok(Err(format!(
                    "{} can't be read: {}",
                    snapshot.manifest_list(),
                    e.message()
                )));
            }
        };
        for manifest in list.entries() {
            if !manifests
                .iter()
                .any(|m: &::iceberg::spec::ManifestFile| m.manifest_path == manifest.manifest_path)
            {
                manifests.push(manifest.clone());
            }
        }
    }
    for manifest in manifests {
        let read = match reader.manifest_reader().read(&manifest).await {
            Ok(read) => read,
            Err(e) => {
                return Ok(Err(format!(
                    "{} can't be read: {}",
                    manifest.manifest_path,
                    e.message()
                )));
            }
        };
        paths.extend(read.entries().iter().map(|e| e.file_path().to_owned()));
        paths.push(manifest.manifest_path);
    }
    Ok(Ok(paths.iter().filter_map(|p| key_of(table, p)).collect()))
}

async fn remove_unreferenced(
    app: &Arc<App>,
    bucket: &TableBucket,
    table: &Table,
    now: SystemTime,
) -> anyhow::Result<Outcome> {
    let Some(settings) = settings(&bucket_maintenance(&bucket.maintenance), UNREFERENCED) else {
        return Ok(Outcome::Disabled);
    };
    let day = 24 * 3600;
    let unreferenced_days = settings["unreferencedDays"].as_i64().unwrap_or(3).max(1) as u64;
    let noncurrent_days = settings["nonCurrentDays"].as_i64().unwrap_or(10).max(1) as u64;
    let (location, current) = match current(app, table).await? {
        Ok(current) => current,
        Err(why) => return Ok(Outcome::Failed(why)),
    };
    if property(&current, "gc.enabled") == Some("false") {
        return Ok(Outcome::Failed(
            "Unreferenced file removal is not supported when 'gc.enabled' table property is false."
                .into(),
        ));
    }
    let referenced = match referenced(app, table, &location, &current).await? {
        Ok(referenced) => referenced,
        Err(why) => return Ok(Outcome::Failed(why)),
    };
    let client = app.pool.get().await?;
    let keys: Vec<String> = client
        .query(
            "SELECT DISTINCT key FROM objects WHERE bucket = $1 AND is_latest AND NOT is_delete_marker",
            &[&table.storage],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let unreferenced: Vec<String> = keys
        .into_iter()
        .filter(|k| !referenced.contains(k))
        .collect();
    let noncurrent_from = now - Duration::from_secs(unreferenced_days * day);
    let delete_from = now - Duration::from_secs(noncurrent_days * day);
    // Forgotten if referenced again (or gone); noted if new; noncurrent
    // after the days unreferenced.
    client
        .execute(
            "DELETE FROM table_unreferenced_files WHERE table_id = $1 AND NOT key = ANY($2)",
            &[&table.id, &unreferenced],
        )
        .await?;
    client
        .execute(
            "INSERT INTO table_unreferenced_files (table_id, key, unreferenced_since)
             SELECT $1, k, $3 FROM unnest($2::text[]) k ON CONFLICT DO NOTHING",
            &[&table.id, &unreferenced, &now],
        )
        .await?;
    let marked = client
        .execute(
            "UPDATE table_unreferenced_files SET noncurrent_since = $3
             WHERE table_id = $1 AND noncurrent_since IS NULL AND unreferenced_since <= $2",
            &[&table.id, &noncurrent_from, &now],
        )
        .await?;
    let due: Vec<String> = client
        .query(
            "SELECT key FROM table_unreferenced_files
             WHERE table_id = $1 AND noncurrent_since <= $2 ORDER BY key",
            &[&table.id, &delete_from],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    drop(client);
    for chunk in due.chunks(1000) {
        let body: String = chunk
            .iter()
            .map(|k| {
                format!(
                    "<Object><Key>{}</Key></Object>",
                    crate::s3::util::xml_escape(k)
                )
            })
            .collect();
        let response = crate::s3::objects::delete::delete_objects(
            app,
            &table.storage,
            Bytes::from(format!("<Delete><Quiet>true</Quiet>{body}</Delete>")),
            &|_, _| true,
            &|_| false,
            crate::mfa::Presented::Absent,
        )
        .await?;
        if !response.status().is_success() {
            anyhow::bail!("deleting the table's files: {}", response.status());
        }
        app.pool
            .get()
            .await?
            .execute(
                "DELETE FROM table_unreferenced_files WHERE table_id = $1 AND key = ANY($2)",
                &[&table.id, &chunk],
            )
            .await?;
    }
    Ok(Outcome::Successful(format!(
        "{} file(s) unreferenced, {marked} newly noncurrent, {} deleted",
        unreferenced.len(),
        due.len()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A table's metadata, with these snapshots (ID, parent, when), `main`
    /// at `main`.
    fn table(snapshots: &[(i64, Option<i64>, i64)], main: i64) -> TableMetadata {
        let creation = iceberg::Creation {
            schema: json!({ "type": "struct", "fields": [{ "id": 1, "name": "id", "required": true, "type": "long" }] }),
            ..Default::default()
        };
        let mut builder = TableMetadataBuilder::new_from_metadata(
            iceberg::new_table(&creation, "s3://t").unwrap(),
            None,
        );
        for (sequence, (id, parent, at)) in snapshots.iter().enumerate() {
            let update: TableUpdate = serde_json::from_value(json!({ "action": "add-snapshot", "snapshot": {
                "snapshot-id": id, "parent-snapshot-id": parent, "sequence-number": sequence + 1,
                "timestamp-ms": at, "manifest-list": format!("s3://t/metadata/snap-{id}.avro"),
                "summary": { "operation": "append" }, "schema-id": 0,
            }}))
            .unwrap();
            builder = update.apply(builder).unwrap();
        }
        let main = ::iceberg::spec::SnapshotReference::new(
            main,
            ::iceberg::spec::SnapshotRetention::branch(None, None, None),
        );
        builder
            .set_ref("main", main)
            .unwrap()
            .build()
            .unwrap()
            .metadata
    }

    #[test]
    fn what_expires() {
        let hour = 3_600_000;
        // Snapshots can't be from before their table's last change: they're
        // from after now, and expire at a later now.
        let t0 = ms(SystemTime::now());
        let now = t0 + 100 * hour;
        let m = table(
            &[
                (1, None, t0 + 50 * hour),
                // Off main, and old.
                (9, Some(1), t0 + 55 * hour),
                (2, Some(1), t0 + 60 * hour),
                (3, Some(2), t0 + 95 * hour),
                (4, Some(3), t0 + 99 * hour),
            ],
            4,
        );
        // Keep 1, up to 10 hours old: 1, 2 and 9 go.
        let mut gone = expiring(&m, 1, 10 * hour, now);
        gone.sort();
        assert_eq!(gone, [1, 2, 9]);
        // Keep 3 of main's: only 1 and 9.
        let mut gone = expiring(&m, 3, 10 * hour, now);
        gone.sort();
        assert_eq!(gone, [1, 9]);
        // Up to 100 hours old: none.
        assert!(expiring(&m, 1, 100 * hour, now).is_empty());
        // The current one stays, however old.
        let old = table(&[(1, None, t0)], 1);
        assert!(expiring(&old, 1, hour, now).is_empty());
    }
}
