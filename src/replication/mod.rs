//! S3's replication, within the cluster: a bucket's replication
//! configuration (see `config`, and `s3::buckets::replication` for how
//! it's set) names other buckets of the cluster, and each version written
//! to the bucket that one of its rules picks is replicated to the bucket
//! the rule names, as S3 replicates it: a replica with the same key,
//! version ID, last-modified time, ETag, metadata, tags and Object Lock,
//! marked `REPLICA`, while the source version is `PENDING`, then
//! `COMPLETED` (or `FAILED`), as `x-amz-replication-status` tells. (Not to
//! be confused with the replication factor of blobs, which is how many
//! nodes hold each: see `shards`.)
//!
//! A replica is a copy (see `s3::objects::copy`): it shares its source's
//! bytes, which are written again only for a replica of another storage
//! class (as the rule's destination may name), so replicating within the
//! cluster takes metadata only. It isn't a copy of its source's
//! durability: both are on the same blobs. What it gives is a version of
//! its own, in a bucket of its own (another account's, perhaps), which
//! deleting the source, or overwriting it, leaves alone; and, with Object
//! Lock in the destination, one that can't be deleted.
//!
//! Which versions are replicated is decided as they're written: the write's
//! own transaction queues each (`replication_queue`) for each destination
//! a rule sends it to (`cairn_replicate` in `catalog.sql`, which says
//! which). So a version that commits is queued, and one that doesn't
//! isn't. The worker on every node takes queued versions (leased, as
//! notifications' deliveries are), a key's to each destination in the
//! order they were written, and replicates them, as the configuration's
//! role, as S3 assumes it (as `s3.amazonaws.com`, which the role's trust
//! policy must allow, with `aws:SourceAccount` and `aws:SourceArn` the
//! bucket's account and ARN): the role must be allowed
//! `s3:GetObjectVersionForReplication` on the source,
//! `s3:ReplicateObject` (`s3:ReplicateDelete` for a delete marker) on the
//! destination, `s3:ReplicateTags` too for a version with tags, and
//! `s3:ObjectOwnerOverrideToBucketOwner` for a rule that asks for that, by
//! its policies and the buckets' (another account's bucket's policy must
//! allow them). A replica of an SSE-KMS object is sealed under the rule's
//! KMS key, asked as the role.
//!
//! A version that can't be replicated (the role may not, the destination
//! is gone or not versioned, the rule is gone) is FAILED, as in S3, and
//! isn't tried again. What may pass (the database, the KMS) is tried
//! again, later each time, `MAX_ATTEMPTS` times. A node that dies while it
//! replicates a version leaves it to another, once its lease runs out; the
//! replica lands once whatever happens (it's checked for, and its write
//! refuses a second).
//!
//! As in S3: replicas aren't replicated again; nor are versions that were
//! there before their rule, delete markers a lifecycle rule makes, deletes
//! of versions (by version ID), or later changes to a version's tags or
//! Object Lock. A Batch Replication job (see `batch`) queues versions that
//! are there (replicas too) as writes queue theirs, whatever their status.
//!
//! A replica keeps its source's last-modified time, and a key's versions
//! are ordered by it (see `cairn_version_time`), so it lands below the
//! destination's versions of its key that are newer, written there
//! directly, or replicas of newer versions that a Batch Replication job
//! replicated before it: whichever version of the key is newest is current,
//! in whatever order they land.
//!
//! An SSE-C version can't be opened without its client's key, so its
//! replica keeps its sealed key and checksum as they are, sealed for the
//! source's name, which the replica records (see
//! `s3::objects::copy::replicate_sealed`): the client's key opens it as it
//! opens its source. Its data can't be read either, so it can't be written
//! again into another storage class: an SSE-C version whose rule names
//! another class than its own fails.

pub mod config;

use std::{collections::HashMap, sync::Arc, time::Duration};

use hyper::{HeaderMap, Method, StatusCode};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

use crate::{
    App,
    db::{self, Cached},
    s3::{
        access::{Access, Origin},
        actions::{Check, On},
        conditional::Preconditions,
        object_lock::{Lock, Mode},
        objects::copy::{CopyKeys, copy_object},
        sse::{KmsRequest, Wanted},
    },
    users::Principal,
};

use config::{Configuration, Rule};

/// The service the role is assumed as, as S3 replicates.
pub const SERVICE: &str = "s3.amazonaws.com";
/// The name of the role sessions replication acts as.
const SESSION_NAME: &str = "s3-replication";
/// The most versions a node replicates at once.
const BATCH: i64 = 32;
/// How long a version is leased while it's replicated.
const LEASE: &str = "10 minutes";
/// How often the worker looks for work when it found none.
const IDLE: Duration = Duration::from_secs(1);
/// How many times a version that fails for what may pass is tried.
const MAX_ATTEMPTS: i32 = 8;

/// The account of the role `arn`, if it's a role's ARN.
pub fn role_account(arn: &str) -> Option<&str> {
    let (account, rest) = arn.strip_prefix("arn:aws:iam::")?.split_once(':')?;
    let path_name = rest.strip_prefix("role/")?;
    (!account.is_empty() && !path_name.is_empty() && !path_name.ends_with('/')).then_some(account)
}

/// The worker: replicates what's queued, until the process ends.
pub async fn run(app: Arc<App>) {
    loop {
        let task_app = app.clone();
        // A task of its own, so that a panic (a bug) fails this round, not
        // the worker.
        let round = tokio::spawn(async move { round(&task_app).await });
        match round.await {
            Ok(Ok(0)) => {}
            Ok(Ok(_)) => continue,
            Ok(Err(e)) => eprintln!("replication: round failed: {e:#}"),
            Err(e) => eprintln!("replication: round failed: {e}"),
        }
        tokio::time::sleep(IDLE).await;
    }
}

/// A version to replicate, as it's queued.
#[derive(Clone, Debug)]
struct Queued {
    seq: i64,
    bucket: String,
    key: String,
    version_id: String,
    destination: String,
    rule_id: String,
    /// How many times it's been taken, this time included.
    attempt: i32,
}

/// A source bucket, as its versions are replicated.
struct Source {
    config: Option<Configuration>,
    /// Its role's session, or why it can't be had.
    principal: Result<Principal, String>,
}

/// How replicating a version went.
#[derive(Debug, PartialEq)]
enum Outcome {
    /// Replicated, or nothing's left to: its replica is there, or it's gone.
    Done,
    /// It can't be: FAILED, why.
    Failed(String),
    /// It may yet be: tried again later, why not now.
    Retry(String),
}

/// Takes up to `BATCH` due versions and replicates them; how many it took.
pub async fn round(app: &Arc<App>) -> anyhow::Result<usize> {
    let client = app.pool.get().await?;
    let rows = client
        .query_cached(
            &format!(
                "UPDATE replication_queue q SET next_at = now() + interval '{LEASE}', attempt = q.attempt + 1
                 FROM (SELECT r.seq FROM replication_queue r
                       WHERE r.next_at <= now()
                         AND NOT EXISTS (SELECT 1 FROM replication_queue e
                                         WHERE e.bucket = r.bucket AND e.key = r.key
                                           AND e.destination = r.destination AND e.seq < r.seq)
                       ORDER BY r.next_at, r.seq LIMIT $1 FOR UPDATE SKIP LOCKED) c
                 WHERE q.seq = c.seq
                 RETURNING q.seq, q.bucket, q.key, q.version_id, q.destination, q.rule_id, q.attempt"
            ),
            &[&BATCH],
        )
        .await?;
    let queued: Vec<Queued> = rows
        .iter()
        .map(|r| Queued {
            seq: r.get(0),
            bucket: r.get(1),
            key: r.get(2),
            version_id: r.get(3),
            destination: r.get(4),
            rule_id: r.get(5),
            attempt: r.get(6),
        })
        .collect();
    let taken = queued.len();
    // Each bucket's configuration and role session, once.
    let mut sources: HashMap<String, Option<Arc<Source>>> = HashMap::new();
    for q in &queued {
        if !sources.contains_key(&q.bucket) {
            let source = source(&client, &q.bucket).await?.map(Arc::new);
            sources.insert(q.bucket.clone(), source);
        }
    }
    drop(client);
    let mut tasks = tokio::task::JoinSet::new();
    for q in queued {
        let app = app.clone();
        let source = sources.get(&q.bucket).cloned().flatten();
        tasks.spawn(async move {
            let outcome = match &source {
                // Gone, and its versions with it.
                None => Ok(Outcome::Done),
                Some(source) => replicate(&app, source, &q).await,
            };
            if let Err(e) = conclude(&app, &q, outcome).await {
                eprintln!("replication: version {} of {}/{}: {e:#}", q.version_id, q.bucket, q.key);
            }
        });
    }
    while let Some(joined) = tasks.join_next().await {
        if let Err(e) = joined {
            eprintln!("replication: a version's task failed: {e}");
        }
    }
    Ok(taken)
}

/// The bucket `name`'s configuration and role session; `None` if there's
/// no such bucket.
async fn source(client: &deadpool_postgres::Object, name: &str) -> anyhow::Result<Option<Source>> {
    let Some(row) = client.query_opt_cached("SELECT replication, account_id FROM buckets WHERE name = $1", &[&name]).await?
    else {
        return Ok(None);
    };
    let config = match row.get::<_, Option<String>>(0) {
        None => None,
        Some(json) => Some(Configuration::from_json(&json).map_err(|e| {
            anyhow::anyhow!("bucket {name}'s replication configuration doesn't parse (written by a newer Cairn?): {e}")
        })?),
    };
    let account: String = row.get(1);
    let principal = match &config {
        None => Err("isn't there".to_owned()),
        Some(config) => {
            crate::batch::assume(client, &account, &config.role, SERVICE, &format!("arn:aws:s3:::{name}"), SESSION_NAME)
                .await?
                .map_err(|why| format!("The role {} {why}.", config.role))
        }
    };
    Ok(Some(Source { config, principal }))
}

/// The source version, as replicating it needs it.
struct Version {
    marker: bool,
    /// ISO 8601, to the microsecond, as Postgres reads it back.
    last_modified: String,
    etag: Option<String>,
    tags: String,
    /// For an SSE-C version, the bucket its sealed key is sealed for: its
    /// own, unless it's a replica itself.
    customer: Option<String>,
    s3: bool,
    kms: bool,
    lock: Lock,
    storage_class: String,
}

/// Replicates the queued version `q` of `source`'s, as its rule says.
async fn replicate(app: &Arc<App>, source: &Source, q: &Queued) -> anyhow::Result<Outcome> {
    let Some(config) = &source.config else {
        return Ok(Outcome::Failed("the bucket has no replication configuration any more".to_owned()));
    };
    let Some(rule) = config.rule(&q.rule_id).filter(|r| r.destination.bucket == q.destination) else {
        return Ok(Outcome::Failed(format!("its rule {} is gone", q.rule_id)));
    };
    let principal = match &source.principal {
        Ok(principal) => principal,
        Err(why) => return Ok(Outcome::Failed(why.clone())),
    };
    let Some(version) = read_version(app, q).await? else {
        // Deleted before it was replicated: there's nothing to replicate.
        return Ok(Outcome::Done);
    };
    let client = app.pool.get().await?;
    let dest = client
        .query_opt_cached("SELECT versioning, account_id FROM buckets WHERE name = $1", &[&q.destination])
        .await?;
    let Some(dest) = dest else {
        return Ok(Outcome::Failed(format!("the destination bucket {} doesn't exist", q.destination)));
    };
    if dest.get::<_, &str>(0) != "enabled" {
        return Ok(Outcome::Failed(format!("the destination bucket {} isn't versioned", q.destination)));
    }
    if rule.destination.account.as_deref().is_some_and(|a| a != dest.get::<_, &str>(1)) {
        return Ok(Outcome::Failed(format!("the destination bucket {} isn't the rule's account's", q.destination)));
    }
    // Replicated already, by an attempt that didn't get to say so.
    let there = client
        .query_opt_cached(
            "SELECT 1 FROM objects WHERE bucket = $1 AND key = $2 AND version_id = $3",
            &[&q.destination, &q.key, &q.version_id],
        )
        .await?;
    if there.is_some() {
        return Ok(Outcome::Done);
    }
    drop(client);
    if let Some(denied) = authorize(app, principal, rule, q, &version).await? {
        return Ok(Outcome::Failed(denied));
    }
    let etag = version.etag.clone().filter(|_| !(version.s3 || version.kms || version.customer.is_some()));
    let last_modified = version.last_modified.clone();
    crate::notifications::scope(async {
        crate::notifications::set_requester(Some(principal.unique_id()), None);
        crate::notifications::set_replica(&q.version_id, &last_modified, etag.as_deref(), version.customer.as_deref());
        match version.marker {
            true => replicate_marker(app, q).await,
            false => replicate_object(app, principal, rule, q, &version).await,
        }
    })
    .await
}

/// The queued version, if it's still there.
async fn read_version(app: &App, q: &Queued) -> anyhow::Result<Option<Version>> {
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached(
            "SELECT is_delete_marker, to_char(last_modified AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                    etag, tags, CASE WHEN sse_c_key IS NOT NULL THEN coalesce(sse_c_bucket, bucket) END, coalesce(sse_s3, false),
                    sse_kms_key_id IS NOT NULL AND NOT coalesce(sse_s3, false),
                    retain_mode, retain_until, legal_hold, storage_class
             FROM objects WHERE bucket = $1 AND key = $2 AND version_id = $3",
            &[&q.bucket, &q.key, &q.version_id],
        )
        .await?;
    let Some(row) = row else { return Ok(None) };
    let retention = match (row.get::<_, Option<&str>>(7).and_then(Mode::parse), row.get::<_, Option<std::time::SystemTime>>(8)) {
        (Some(mode), Some(until)) if until > std::time::SystemTime::now() => Some((mode, until)),
        _ => None,
    };
    Ok(Some(Version {
        marker: row.get(0),
        last_modified: row.get(1),
        etag: row.get(2),
        tags: row.get::<_, Option<String>>(3).unwrap_or_default(),
        customer: row.get(4),
        s3: row.get(5),
        kms: row.get(6),
        lock: Lock { retention, legal_hold: row.get::<_, Option<bool>>(9).filter(|hold| *hold) },
        storage_class: row.get::<_, Option<String>>(10).unwrap_or_default(),
    }))
}

/// Why the role's session may not replicate the version, if it may not.
async fn authorize(app: &App, principal: &Principal, rule: &Rule, q: &Queued, version: &Version) -> anyhow::Result<Option<String>> {
    let on_source = || On::Object(q.bucket.clone(), q.key.clone());
    let on_dest = || On::Object(q.destination.clone(), q.key.clone());
    let mut checks = vec![Check { action: "s3:GetObjectVersionForReplication", on: on_source() }];
    match version.marker {
        true => checks.push(Check { action: "s3:ReplicateDelete", on: on_dest() }),
        false => checks.push(Check { action: "s3:ReplicateObject", on: on_dest() }),
    }
    if !version.tags.is_empty() {
        checks.push(Check { action: "s3:ReplicateTags", on: on_dest() });
    }
    if rule.destination.owner_override {
        checks.push(Check { action: "s3:ObjectOwnerOverrideToBucketOwner", on: on_dest() });
    }
    let origin = Origin { peer: None, trusted_proxies: &[], signed: None, form: false };
    let mut access = Access::new(Some(principal), &principal.account, &Method::PUT, &HeaderMap::new(), "", &origin)?;
    access.load_all(app, &checks).await?;
    Ok(access.first_denied(&checks).map(|(check, _)| {
        format!("{} is not authorized to perform: {} on resource: \"{}\"", principal.arn(), check.action, check.on.arn())
    }))
}

/// Replicates an object's version: a copy of it, of the version ID it has
/// (see `notifications::set_replica`, which the task has set).
async fn replicate_object(app: &Arc<App>, principal: &Principal, rule: &Rule, q: &Queued, version: &Version) -> anyhow::Result<Outcome> {
    let storage_class = match &rule.destination.storage_class {
        None => None,
        Some(name) => match crate::classes::resolve(app, Some(name)).await? {
            Ok(class) => Some(class),
            Err(name) => return Ok(Outcome::Failed(format!("there's no storage class {name}"))),
        },
    };
    if version.customer.is_some() {
        if storage_class.as_ref().is_some_and(|class| *class != version.storage_class) {
            return Ok(Outcome::Failed(
                "an SSE-C version can't be replicated into another storage class: its data can't be read without its \
                 client's key"
                    .to_owned(),
            ));
        }
        let response =
            crate::s3::objects::copy::replicate_sealed(app, &q.bucket, &q.key, &q.version_id, &q.destination, version.lock)
                .await?;
        return outcome_of(response).await;
    }
    let kms;
    let dest = if version.kms {
        let Some(key_id) = rule.destination.kms_key.as_deref().and_then(crate::kms::KeyId::parse) else {
            return Ok(Outcome::Failed("its rule names no KMS key for SSE-KMS replicas".to_owned()));
        };
        kms = KmsRequest { key_id, context: None };
        Wanted::Kms(&kms)
    } else if version.s3 {
        Wanted::S3
    } else {
        Wanted::Plain
    };
    let keys = CopyKeys {
        dest,
        role: Some(principal.id),
        lock: version.lock,
        storage_class: storage_class.as_deref(),
        replica: true,
        ..CopyKeys::default()
    };
    let encode = |s: &str| utf8_percent_encode(s, NON_ALPHANUMERIC).to_string();
    let copy_source = format!("{}/{}?versionId={}", encode(&q.bucket), encode(&q.key), encode(&q.version_id));
    let response =
        copy_object(app, &q.destination, &q.key, &copy_source, None, "", "", None, &Preconditions::default(), keys).await?;
    outcome_of(response).await
}

/// What a replica's write answered comes to.
async fn outcome_of(response: hyper::Response<http_body_util::Full<hyper::body::Bytes>>) -> anyhow::Result<Outcome> {
    if response.status() == StatusCode::OK {
        return Ok(Outcome::Done);
    }
    let retry = response.status().is_server_error();
    let why = crate::inventory::refusal(response).await;
    Ok(if retry { Outcome::Retry(why) } else { Outcome::Failed(why) })
}

/// Replicates a delete marker: one of the version ID it has, in the
/// destination (see `notifications::set_replica`).
async fn replicate_marker(app: &Arc<App>, q: &Queued) -> anyhow::Result<Outcome> {
    let client = app.pool.get().await?;
    let notify = crate::notifications::delete_context();
    let keys = vec![q.key.clone()];
    let version_ids: Vec<Option<String>> = vec![None];
    let marker_ids = vec![q.version_id.clone()];
    let bypass = vec![false];
    let expected: Vec<i64> = Vec::new();
    for attempt in 0..db::MAX_TX_ATTEMPTS {
        db::backoff(attempt).await;
        let result = client
            .query_one_cached(
                "SELECT status, reap_blob, reap_node, reap_peer
                 FROM pg_temp.cairn_delete_objects($1, $2, $3, $4, $5, $6, $7)",
                &[&q.destination, &keys, &version_ids, &marker_ids, &bypass, &expected, &notify],
            )
            .await;
        match result {
            Ok(row) => {
                return Ok(match row.get::<_, &str>(0) {
                    "deleted" => {
                        crate::blobs::reap_blobs(app, crate::blobs::reap_columns(&row, 1));
                        Outcome::Done
                    }
                    "no_such_bucket" => Outcome::Failed(format!("the destination bucket {} doesn't exist", q.destination)),
                    status => Outcome::Failed(format!("the destination refused the delete marker ({status})")),
                });
            }
            Err(e) if db::is_conflict(&e) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(Outcome::Retry("the delete marker kept conflicting with concurrent requests".to_owned()))
}

/// How long a version waits after its `attempt`th try failed for what may
/// pass: ten seconds, doubling, an hour at most.
fn backoff(attempt: i32) -> Duration {
    Duration::from_secs((10u64 << attempt.clamp(0, 16) as u32).min(3600))
}

/// Settles the queued version `q` as `outcome` says: done or FAILED
/// (T68), or due again later.
async fn conclude(app: &App, q: &Queued, outcome: anyhow::Result<Outcome>) -> anyhow::Result<()> {
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(e) => Outcome::Retry(format!("{e:#}")),
    };
    let failed = match outcome {
        Outcome::Done => false,
        Outcome::Retry(why) if q.attempt < MAX_ATTEMPTS => {
            let wait = backoff(q.attempt).as_secs_f64();
            app.pool
                .get()
                .await?
                .execute_cached(
                    "UPDATE replication_queue SET next_at = now() + make_interval(secs => $2), failure = $3 WHERE seq = $1",
                    &[&q.seq, &wait, &why],
                )
                .await?;
            return Ok(());
        }
        Outcome::Retry(why) | Outcome::Failed(why) => {
            eprintln!(
                "replication: version {} of {}/{} to bucket {} failed: {why}",
                q.version_id, q.bucket, q.key, q.destination
            );
            true
        }
    };
    let client = app.pool.get().await?;
    for attempt in 0..db::MAX_TX_ATTEMPTS {
        db::backoff(attempt).await;
        match client.query_one_cached("SELECT pg_temp.cairn_replication_done($1, $2)", &[&q.seq, &failed]).await {
            Ok(_) => return Ok(()),
            Err(e) if db::is_conflict(&e) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    // Left leased: it's taken again once the lease runs out.
    Err(crate::Contended("settling a replicated version kept conflicting".to_owned()).into())
}

#[cfg(test)]
mod e2e;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_are_named_by_their_arns() {
        assert_eq!(role_account("arn:aws:iam::123456789012:role/replication"), Some("123456789012"));
        assert_eq!(role_account("arn:aws:iam::123456789012:role/ops/replication"), Some("123456789012"));
        assert_eq!(role_account("arn:aws:iam::123456789012:user/replication"), None);
        assert_eq!(role_account("arn:aws:iam::123456789012:role/"), None);
        assert_eq!(role_account("replication"), None);
    }

    #[test]
    fn retries_back_off() {
        assert_eq!(backoff(1), Duration::from_secs(20));
        assert_eq!(backoff(20), Duration::from_secs(3600));
    }
}
