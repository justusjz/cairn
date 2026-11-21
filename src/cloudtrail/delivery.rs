//! Delivering trails' log files: each trail's events (see
//! `Trail::delivers`), from what the nodes shipped into the internal bucket
//! (see `audit::ship`), to its bucket, as CloudTrail's files
//!
//! ```text
//! <prefix>/AWSLogs/<account>/CloudTrail/<region>/<y>/<m>/<d>/<account>_CloudTrail_<region>_<yyyymmddThhmmZ>_<unique>.json.gz
//! ```
//!
//! gzipped JSON, `{"Records":[...]}`, written as the
//! `cloudtrail.amazonaws.com` service, which the bucket's policy must let
//! write them (with `aws:SourceArn` the trail's), as in AWS.
//!
//! What's to be delivered is queued: as a node ships an object of the
//! audit log, it adds a row for each trail of the accounts it has records
//! of (see `queue`), so the database has a row per object and trail until
//! it's delivered, a few at a time, and no row per event. One node at a
//! time delivers (it holds a lease), about 30 seconds after each
//! five-minute mark of the clock, when every node has shipped its records
//! of the five minutes before (a node that's slow, or down, has its records
//! delivered with the next): so an event is delivered within about five
//! and a half minutes of it, under three on average. It reads the shipped
//! objects, not other nodes' disks, so a node that's down doesn't hold the
//! others' records up.
//!
//! A row is removed once its object's records are written: so they're
//! delivered at least once (twice, if the node delivering ended between
//! the write and the removal; readers deduplicate by `eventID`, as
//! CloudTrail's must). A trail whose bucket doesn't take its files (it's
//! gone, its policy doesn't allow it, the cluster's storage is down) is
//! tried again each time, for 30 days, as CloudTrail does, its last error
//! in `GetTrailStatus`; then its records of then are dropped.

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use http_body_util::{BodyExt, Full};
use hyper::{StatusCode, body::Bytes};
use serde_json::Value;
use uuid::Uuid;

use super::trails::Trail;
use crate::{
    App,
    audit::{log, lookup, ship},
    db::Cached,
    kms::Caller,
    lifecycle::rules::Day,
    payload::Payload,
    policy::Context,
    s3::{
        conditional::Preconditions,
        object_lock::Lock,
        service::Destination,
        sse::{KmsRequest, ServerSide, Wanted},
        util::MAX_UPLOAD,
    },
};

/// The service trails' files are written as.
pub const SERVICE: &str = "cloudtrail.amazonaws.com";
/// The encryption context of an SSE-KMS log file, besides S3's: the
/// trail's ARN, as CloudTrail's has it (and key policies check).
pub const CONTEXT_KEY: &str = "aws:cloudtrail:arn";
/// How long after a five-minute mark delivery starts.
const AFTER_MARK: Duration = Duration::from_secs(30);
/// How often delivery runs: as often as the nodes ship.
const PERIOD: u64 = 300;
/// How long a node's lease lasts, unless it's renewed.
const LEASE_SECS: f64 = 120.0;
/// How often a node renews its lease while it delivers.
const RENEW: Duration = Duration::from_secs(30);
/// How long a trail's objects are tried before they're dropped: 30 days.
const KEEP_SECS: f64 = 30.0 * 86400.0;
/// How long after a trail stops logging it still gets objects queued: its
/// nodes' records of before it stopped, shipped late.
const AFTER_STOP_SECS: f64 = 3600.0;
/// How many objects are read at a time, for a file (or several).
const BATCH: i64 = 20;
/// The most bytes of records a file holds, before it's gzipped.
const MAX_FILE: usize = 32 << 20;

/// Queues the object `key` of the audit log, just shipped, for the trails
/// of `accounts` (its records'): those logging, or that stopped lately.
pub async fn queue(app: &App, key: &str, accounts: &[String]) -> anyhow::Result<()> {
    if accounts.is_empty() {
        return Ok(());
    }
    app.pool
        .get()
        .await?
        .execute_cached(
            "INSERT INTO cloudtrail_pending (account_id, trail, key)
             SELECT account_id, name, $1 FROM cloudtrail_trails
             WHERE account_id = ANY($2)
               AND (logging OR stopped_at > now() - make_interval(secs => $3))
             ON CONFLICT DO NOTHING",
            &[&key, &accounts, &AFTER_STOP_SECS],
        )
        .await?;
    Ok(())
}

/// Queues for a trail that just started logging (at `started`, in seconds)
/// the objects already shipped that may have its account's records since:
/// those of files opened in the five minutes it started in, or after. (One
/// shipped as it started, the shipper queues: it queues an object once
/// it's written, for the trails logging then, and those that started
/// later find it here.)
pub async fn backfill(
    client: &impl Cached,
    account: &str,
    name: &str,
    started: f64,
) -> anyhow::Result<()> {
    let from = lookup::key_at(lookup::window_of((started * 1000.0) as i64));
    // Past every key of the log's: `audit0` is just after `audit/`.
    let after = format!("{}0", ship::PREFIX.trim_end_matches('/'));
    client
        .execute_cached(
            &format!(
                "INSERT INTO cloudtrail_pending (account_id, trail, key)
                 SELECT $1, $2, key FROM objects
                 WHERE bucket = $3 AND key >= $4 AND key < $5 AND is_latest
                   AND (metadata NOT LIKE '%{0}: %' OR strpos(metadata, ',' || $1 || ',') > 0)
                 ON CONFLICT DO NOTHING",
                ship::ACCOUNTS
            ),
            &[&account, &name, &crate::internal::BUCKET, &from, &after],
        )
        .await?;
    Ok(())
}

/// Delivers, on every node: about 30 seconds after each five-minute mark,
/// if no other node holds the lease.
pub async fn run(app: Arc<App>) {
    let token = Uuid::new_v4();
    loop {
        tokio::time::sleep(until_next(SystemTime::now())).await;
        let task_app = app.clone();
        // A task of its own, so that a panic (a bug) fails this pass only.
        let pass = tokio::spawn(async move { deliver_leased(&task_app, token).await });
        match pass.await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => eprintln!("cloudtrail: delivery failed: {e:#}"),
            Err(e) => eprintln!("cloudtrail: delivery failed: {e}"),
        }
    }
}

/// How long from `now` until the next delivery: 30 seconds after the next
/// five-minute mark (or this one's, if that's still to come).
fn until_next(now: SystemTime) -> Duration {
    let since = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let mark = since.as_secs() / PERIOD * PERIOD;
    let mut next = Duration::from_secs(mark) + AFTER_MARK;
    if next <= since {
        next += Duration::from_secs(PERIOD);
    }
    next - since
}

/// Renews a lease until it's dropped.
struct Renewal(tokio::task::JoinHandle<()>);

impl Drop for Renewal {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Delivers, if this node (`token`) may: `None` if another holds the lease.
pub async fn deliver_leased(app: &Arc<App>, token: Uuid) -> anyhow::Result<Option<Report>> {
    let client = app.pool.get().await?;
    // Nothing to do: no need for the lease.
    let pending = client
        .query_opt_cached("SELECT 1 FROM cloudtrail_pending LIMIT 1", &[])
        .await?;
    if pending.is_none() {
        return Ok(None);
    }
    let leased = client
        .query_opt_cached(
            "UPDATE cloudtrail_delivery
             SET holder = $1, lease_until = now() + make_interval(secs => $2)
             WHERE holder IS NULL OR holder = $1 OR lease_until < now()
             RETURNING true",
            &[&token, &LEASE_SECS],
        )
        .await?;
    if leased.is_none() {
        return Ok(None);
    }
    drop(client);
    let _renewal = Renewal(tokio::spawn({
        let app = app.clone();
        async move {
            loop {
                tokio::time::sleep(RENEW).await;
                if let Ok(client) = app.pool.get().await {
                    let _ = client
                        .execute(
                            "UPDATE cloudtrail_delivery
                             SET lease_until = now() + make_interval(secs => $2) WHERE holder = $1",
                            &[&token, &LEASE_SECS],
                        )
                        .await;
                }
            }
        }
    }));
    let report = deliver(app).await;
    // Whoever's first, next time.
    app.pool
        .get()
        .await?
        .execute_cached(
            "UPDATE cloudtrail_delivery SET holder = NULL, lease_until = NULL WHERE holder = $1",
            &[&token],
        )
        .await?;
    report.map(Some)
}

/// What a delivery did.
#[derive(Debug, Default, PartialEq)]
pub struct Report {
    /// The files written, by trail (`account/name`), and their records.
    pub files: Vec<(String, String, usize)>,
    /// The trails that failed, and why.
    pub failed: Vec<(String, String)>,
    /// How many queued objects were dropped, having failed for 30 days.
    pub dropped: u64,
}

/// Delivers what's queued, for every trail. Only the lease's holder does
/// (see `deliver_leased`), but two at once would merely deliver twice.
pub async fn deliver(app: &Arc<App>) -> anyhow::Result<Report> {
    let mut report = Report::default();
    let client = app.pool.get().await?;
    report.dropped = client
        .execute_cached(
            "DELETE FROM cloudtrail_pending
             WHERE added_at < now() - make_interval(secs => $1)",
            &[&KEEP_SECS],
        )
        .await?;
    if report.dropped > 0 {
        eprintln!(
            "cloudtrail: dropping {} objects' records that failed to be delivered for 30 days",
            report.dropped
        );
    }
    let trails = client
        .query_cached(
            "SELECT DISTINCT account_id, trail FROM cloudtrail_pending ORDER BY 1, 2",
            &[],
        )
        .await?;
    drop(client);
    for row in trails {
        let (account, name): (String, String) = (row.get(0), row.get(1));
        let client = app.pool.get().await?;
        // Deleted meanwhile: its rows went with it.
        let Some(trail) = Trail::load(&client, &account, &name).await? else {
            continue;
        };
        drop(client);
        let label = format!("{account}/{name}");
        match deliver_trail(app, &trail).await? {
            Ok(files) => report
                .files
                .extend(files.into_iter().map(|(key, n)| (label.clone(), key, n))),
            Err(why) => {
                eprintln!("cloudtrail: delivering trail {label}'s log files failed: {why}");
                report.failed.push((label, why));
            }
        }
    }
    Ok(report)
}

/// Delivers what's queued for `trail`: the files written (their keys, and
/// how many records each has), or why they couldn't be.
async fn deliver_trail(
    app: &Arc<App>,
    trail: &Trail,
) -> anyhow::Result<Result<Vec<(String, usize)>, String>> {
    let mut written = Vec::new();
    let mut after = String::new();
    loop {
        let keys: Vec<String> = app
            .pool
            .get()
            .await?
            .query_cached(
                "SELECT key FROM cloudtrail_pending
                 WHERE account_id = $1 AND trail = $2 AND key > $3
                 ORDER BY key LIMIT $4",
                &[&trail.account, &trail.name, &after, &BATCH],
            )
            .await?
            .iter()
            .map(|r| r.get(0))
            .collect();
        let Some(last) = keys.last() else {
            return Ok(Ok(written));
        };
        after = last.clone();
        // Their records, into files.
        let mut files: Vec<(Vec<u8>, usize)> = Vec::new();
        for key in &keys {
            let data = match read(app, key).await {
                Ok(Some(data)) => data,
                // Expired, as the audit log does after 90 days.
                Ok(None) => continue,
                // The cluster's storage down, say: tried again next time.
                Err(e) => {
                    let why = format!("InternalFailure: reading the audit log's {key}: {e:#}");
                    status(app, trail, Some(&why)).await?;
                    return Ok(Err(why));
                }
            };
            for record in log::records(&data) {
                let Ok(event) = serde_json::from_slice::<Value>(record) else {
                    continue;
                };
                if !trail.delivers(&event) {
                    continue;
                }
                match files.last_mut() {
                    Some((body, n)) if body.len() + record.len() < MAX_FILE => {
                        body.push(b',');
                        body.extend_from_slice(record);
                        *n += 1;
                    }
                    _ => {
                        let mut body = b"{\"Records\":[".to_vec();
                        body.extend_from_slice(record);
                        files.push((body, 1));
                    }
                }
            }
        }
        for (mut body, n) in files {
            body.extend_from_slice(b"]}");
            let now = SystemTime::now();
            let key = file_key(trail, now);
            let outcome = write(app, trail, &key, body).await;
            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(e) => Err(format!("{e:#}")),
            };
            status(app, trail, outcome.as_ref().err()).await?;
            if let Err(why) = outcome {
                return Ok(Err(why));
            }
            written.push((key, n));
        }
        app.pool
            .get()
            .await?
            .execute_cached(
                "DELETE FROM cloudtrail_pending
                 WHERE account_id = $1 AND trail = $2 AND key = ANY($3)",
                &[&trail.account, &trail.name, &keys],
            )
            .await?;
    }
}

/// An object of the audit log's records: none if it's gone.
async fn read(app: &Arc<App>, key: &str) -> anyhow::Result<Option<Arc<Vec<u8>>>> {
    lookup::read_object(app, key).await
}

/// Records how `trail`'s delivery went: well, or with the error `failed`.
async fn status(app: &App, trail: &Trail, failed: Option<&String>) -> anyhow::Result<()> {
    let client = app.pool.get().await?;
    match failed {
        None => {
            client
                .execute_cached(
                    "UPDATE cloudtrail_trails
                     SET delivered_at = now(), attempted_at = now(), attempt_ok = true,
                         delivery_error = NULL
                     WHERE account_id = $1 AND name = $2",
                    &[&trail.account, &trail.name],
                )
                .await?
        }
        Some(why) => {
            client
                .execute_cached(
                    "UPDATE cloudtrail_trails
                     SET attempted_at = now(), attempt_ok = false, delivery_error = $3
                     WHERE account_id = $1 AND name = $2",
                    &[&trail.account, &trail.name, why],
                )
                .await?
        }
    };
    Ok(())
}

/// The key of a log file of `trail`'s, delivered at `now`.
pub fn file_key(trail: &Trail, now: SystemTime) -> String {
    let day = Day::of(now);
    let (year, month, date) = day.civil();
    let secs = now
        .duration_since(day.midnight())
        .map_or(0, |d| d.as_secs());
    let mut unique = [0u8; 8];
    getrandom::fill(&mut unique).expect("the OS random number generator failed");
    let unique: String = unique.iter().map(|b| format!("{b:02X}")).collect();
    let region = crate::s3::buckets::head::REGION;
    format!(
        "{}{year:04}/{month:02}/{date:02}/{}_CloudTrail_{region}_{year:04}{month:02}{date:02}T{:02}{:02}Z_{unique}.json.gz",
        trail.key_prefix(),
        trail.account,
        secs / 3600,
        secs / 60 % 60,
    )
}

/// The service, writing `trail`'s files.
fn caller(trail: &Trail) -> Caller {
    Caller::Service {
        name: SERVICE,
        account: trail.account.clone(),
        source: Some(trail.arn()),
    }
}

/// What `trail`'s files are encrypted with: its KMS key, if it has one,
/// else its bucket's default encryption; or why they can't be.
pub async fn encryption(
    app: &App,
    trail: &Trail,
) -> anyhow::Result<Result<Option<ServerSide>, String>> {
    if let Some(key) = &trail.kms_key_id {
        let context = BTreeMap::from([(CONTEXT_KEY.to_owned(), trail.arn())]);
        return Ok(Ok(Some(ServerSide::Kms(KmsRequest {
            key_id: Some(key.clone()),
            context: Some(context),
        }))));
    }
    Ok(
        match crate::s3::buckets::encryption::default_request(app, &trail.bucket).await? {
            Ok(server) => Ok(server),
            Err(_) => Err(format!(
                "the default encryption of bucket {} needs a KMS, and Cairn has none",
                trail.bucket
            )),
        },
    )
}

/// Whether the policy of `bucket` lets `trail`'s files be written to it
/// with `prefix` (CloudTrail's checks of a trail's bucket: its ACL may be
/// read, and its files written, with `bucket-owner-full-control`); if not,
/// why not.
pub fn allowed(
    bucket: &Destination,
    trail_arn: &str,
    account: &str,
    key: &str,
) -> Result<(), String> {
    let name = &bucket.name;
    if !bucket.allows(
        SERVICE,
        "s3:GetBucketAcl",
        None,
        trail_arn,
        account,
        Context::default(),
    ) {
        return Err(format!(
            "the policy of bucket {name} doesn't allow {SERVICE} s3:GetBucketAcl"
        ));
    }
    let mut context = Context::default();
    context.set("s3:x-amz-acl", "bucket-owner-full-control");
    if !bucket.allows(
        SERVICE,
        "s3:PutObject",
        Some(key),
        trail_arn,
        account,
        context,
    ) {
        return Err(format!(
            "the policy of bucket {name} doesn't allow {SERVICE} to write {key}"
        ));
    }
    Ok(())
}

/// Writes one of `trail`'s files: why not, if it couldn't be.
async fn write(
    app: &Arc<App>,
    trail: &Trail,
    key: &str,
    records: Vec<u8>,
) -> anyhow::Result<Result<(), String>> {
    let Some(bucket) = Destination::load(app, &trail.bucket).await? else {
        return Ok(Err(format!(
            "NoSuchBucket: bucket {} doesn't exist",
            trail.bucket
        )));
    };
    if let Err(why) = allowed(&bucket, &trail.arn(), &trail.account, key) {
        return Ok(Err(format!("AccessDenied: {why}")));
    }
    let server = match encryption(app, trail).await? {
        Ok(server) => server,
        Err(why) => return Ok(Err(why)),
    };
    let body = tokio::task::spawn_blocking(move || {
        use std::io::Write;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&records)?;
        gz.finish()
    })
    .await??;
    let payload = Payload::unchecked()
        .at_most(MAX_UPLOAD)
        .map_err(|_| anyhow::anyhow!("an unchecked payload has no length"))?;
    let response = crate::s3::objects::put::put_object(
        app,
        &trail.bucket,
        key,
        "application/json",
        "",
        "",
        Full::new(Bytes::from(body)),
        payload,
        &Preconditions::default(),
        Wanted::new(None, server.as_ref()),
        Some(caller(trail)),
        Lock::default(),
        crate::classes::STANDARD,
    )
    .await?;
    let status = response.status();
    if status == StatusCode::OK {
        return Ok(Ok(()));
    }
    let answer = response
        .into_body()
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let answer = String::from_utf8_lossy(&answer);
    // S3's error code, as CloudTrail reports it, and what it says.
    let code = answer
        .split_once("<Code>")
        .and_then(|(_, rest)| rest.split_once("</Code>"))
        .map_or(status.as_str(), |(code, _)| code);
    let message = answer
        .split_once("<Message>")
        .and_then(|(_, rest)| rest.split_once("</Message>"))
        .map_or("", |(message, _)| message);
    Ok(Err(format!(
        "{code}: writing {key} to bucket {}: {message}",
        trail.bucket
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deliveries_follow_the_marks() {
        let at = |secs: u64| UNIX_EPOCH + Duration::from_secs(secs);
        // 2026-11-16T05:05:00Z is a mark.
        let mark = 1_794_805_500;
        assert_eq!(until_next(at(mark)), Duration::from_secs(30));
        assert_eq!(until_next(at(mark + 29)), Duration::from_secs(1));
        assert_eq!(until_next(at(mark + 30)), Duration::from_secs(300));
        assert_eq!(until_next(at(mark + 200)), Duration::from_secs(130));
    }
}
