//! Delivering a node's spooled records (see `spool`): each closed file's
//! records, by their source bucket, as log objects in the bucket its
//! logging configuration names, written as S3 writes them, as the
//! `logging.s3.amazonaws.com` service.
//!
//! Records are dropped, as S3 drops them, when their bucket no longer logs,
//! or its target is gone, isn't the bucket's account's, has no policy
//! letting the service write them, or would encrypt them with SSE-KMS or
//! keep them under a default Object Lock retention. Those that fail for any
//! other reason (the database or the storage nodes down, say) are kept, and
//! tried again with the next pass, for up to a day.

use std::{
    collections::BTreeMap,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime},
};

use http_body_util::{BodyExt, Full};
use hyper::{StatusCode, body::Bytes};

use super::{
    SERVICE,
    spool::{Line, Spool},
};
use crate::{
    App,
    db::Cached,
    lifecycle::rules::Day,
    payload::Payload,
    policy::Context,
    s3::{
        buckets::logging::{DateSource, KeyFormat, Logging},
        conditional::Preconditions,
        object_lock::Lock,
        service::Destination,
        sse::{ServerSide, Wanted},
        util::MAX_UPLOAD,
    },
};

/// How long records that keep failing are kept.
const KEEP: Duration = Duration::from_secs(24 * 3600);

/// Delivers every closed file in the spool `dir`.
pub async fn deliver_all(app: &Arc<App>, dir: &Path) -> anyhow::Result<()> {
    let files = {
        let dir = dir.to_owned();
        tokio::task::spawn_blocking(move || Spool::closed(&dir)).await??
    };
    for file in files {
        if let Err(e) = deliver_file(app, &file).await {
            eprintln!("access logs: delivering {} failed: {e:#}", file.display());
        }
    }
    Ok(())
}

/// Delivers a closed file's records: removes it once they're all
/// delivered (or dropped); else keeps only the rest.
async fn deliver_file(app: &Arc<App>, path: &Path) -> anyhow::Result<()> {
    let data = tokio::fs::read(path).await?;
    let mut buckets: BTreeMap<&str, Vec<Line>> = BTreeMap::new();
    for line in Line::parse_all(&data) {
        buckets.entry(line.bucket).or_default().push(line);
    }
    let mut kept: Vec<u8> = Vec::new();
    for (bucket, lines) in buckets {
        for line in deliver_bucket(app, bucket, lines).await {
            kept.extend_from_slice(line.bucket.as_bytes());
            kept.extend_from_slice(format!("\t{}\t", line.time).as_bytes());
            kept.extend_from_slice(line.record);
            kept.push(b'\n');
        }
    }
    let expired = Spool::opened(path).is_some_and(|t| t + KEEP < SystemTime::now());
    if kept.is_empty() || expired {
        if !kept.is_empty() {
            eprintln!("access logs: dropping records of {} that failed for a day", path.display());
        }
        tokio::fs::remove_file(path).await?;
    } else if kept.len() < data.len() {
        let partial = path.with_extension("partial");
        tokio::fs::write(&partial, &kept).await?;
        tokio::fs::rename(&partial, path).await?;
    }
    Ok(())
}

/// Delivers the records of `bucket`: those it couldn't (and may yet).
async fn deliver_bucket<'a>(app: &Arc<App>, bucket: &str, lines: Vec<Line<'a>>) -> Vec<Line<'a>> {
    let target = match target(app, bucket).await {
        Ok(Some(target)) => target,
        Ok(None) => return Vec::new(),
        Err(e) => {
            eprintln!("access logs: bucket {bucket}'s logging configuration: {e:#}");
            return lines;
        }
    };
    let now = SystemTime::now();
    // The objects: one, unless their keys are dated by the records' days.
    let mut objects: BTreeMap<Day, Vec<Line>> = BTreeMap::new();
    for line in lines {
        let day = match target.logging.key_format {
            Some(KeyFormat::Partitioned(None | Some(DateSource::EventTime))) => {
                Day::of(SystemTime::UNIX_EPOCH + Duration::from_secs(line.time.max(0) as u64))
            }
            _ => Day::of(now),
        };
        objects.entry(day).or_default().push(line);
    }
    let mut kept = Vec::new();
    for (day, lines) in objects {
        let key = key(&target, bucket, day, now);
        let mut body = Vec::new();
        for line in &lines {
            body.extend_from_slice(line.record);
            body.push(b'\n');
        }
        match write(app, &target, bucket, &key, body).await {
            Ok(Ok(())) => {}
            Ok(Err(why)) => eprintln!("access logs: dropping bucket {bucket}'s records: {why}"),
            Err(e) => {
                eprintln!("access logs: writing bucket {bucket}'s records to {key} failed: {e:#}");
                kept.extend(lines);
            }
        }
    }
    kept
}

/// Where a bucket's logs go.
struct Target {
    logging: Logging,
    /// The source bucket's account.
    account: String,
    destination: Destination,
    /// How the target encrypts what's written to it, by default.
    server: Option<ServerSide>,
}

/// Where `bucket`'s logs go: `None` if they go nowhere (it doesn't log,
/// or its target doesn't take them).
async fn target(app: &App, bucket: &str) -> anyhow::Result<Option<Target>> {
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached("SELECT logging, account_id FROM buckets WHERE name = $1", &[&bucket])
        .await?;
    let Some((Some(json), account)) = row.map(|r| (r.get::<_, Option<String>>(0), r.get::<_, String>(1))) else {
        return Ok(None);
    };
    let logging = Logging::from_json(&json).map_err(|e| anyhow::anyhow!("doesn't parse: {e}"))?;
    let name = &logging.target_bucket;
    let drop = |why: String| {
        eprintln!("access logs: dropping bucket {bucket}'s records: {why}");
        Ok(None)
    };
    let Some(destination) = Destination::load(app, name).await? else {
        return drop(format!("its target bucket {name} doesn't exist"));
    };
    if destination.owner != account {
        return drop(format!("its target bucket {name} isn't its account's"));
    }
    let locked: bool = app
        .pool
        .get()
        .await?
        .query_opt_cached("SELECT lock_mode IS NOT NULL FROM buckets WHERE name = $1", &[name])
        .await?
        .is_some_and(|r| r.get(0));
    if locked {
        return drop(format!("its target bucket {name} has a default Object Lock retention"));
    }
    let server = match crate::s3::buckets::encryption::default_request(app, name).await? {
        Ok(Some(ServerSide::Kms(_))) => return drop(format!("its target bucket {name} encrypts with SSE-KMS by default")),
        Ok(server) => server,
        Err(_) => return drop(format!("its target bucket {name}'s default encryption needs a KMS")),
    };
    Ok(Some(Target { logging, account, destination, server }))
}

/// A log object's key, as S3 makes it: the target prefix, then for a
/// partitioned one the source's account, region, bucket and the day
/// (`day`), and the time it's delivered (`now`) and a unique string.
fn key(target: &Target, bucket: &str, day: Day, now: SystemTime) -> String {
    let today = Day::of(now);
    let (year, month, date) = today.civil();
    let secs = now.duration_since(today.midnight()).map_or(0, |d| d.as_secs());
    let mut unique = [0u8; 8];
    getrandom::fill(&mut unique).expect("the OS random number generator failed");
    let unique: String = unique.iter().map(|b| format!("{b:02X}")).collect();
    let name = format!(
        "{year:04}-{month:02}-{date:02}-{:02}-{:02}-{:02}-{unique}",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    );
    let prefix = &target.logging.target_prefix;
    match target.logging.key_format {
        Some(KeyFormat::Partitioned(_)) => {
            let (year, month, date) = day.civil();
            let region = crate::s3::buckets::head::REGION;
            format!("{prefix}{}/{region}/{bucket}/{year:04}/{month:02}/{date:02}/{name}", target.account)
        }
        _ => format!("{prefix}{name}"),
    }
}

/// Writes a log object: why not, if the target doesn't take it.
async fn write(app: &Arc<App>, target: &Target, bucket: &str, key: &str, body: Vec<u8>) -> anyhow::Result<Result<(), String>> {
    let name = &target.destination.name;
    if !target.destination.allows_put(SERVICE, bucket, &target.account, key, Context::default()) {
        return Ok(Err(format!("the policy of its target bucket {name} doesn't allow {SERVICE} to write {key}")));
    }
    let payload = Payload::unchecked().at_most(MAX_UPLOAD).map_err(|_| anyhow::anyhow!("an unchecked payload has no length"))?;
    let response = crate::s3::objects::put::put_object(
        app,
        name,
        key,
        "text/plain",
        "",
        "",
        Full::new(Bytes::from(body)),
        payload,
        &Preconditions::default(),
        Wanted::new(None, target.server.as_ref()),
        None,
        Lock::default(),
    )
    .await?;
    let status = response.status();
    if status == StatusCode::OK {
        return Ok(Ok(()));
    }
    let answer = response.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
    let why = format!("writing {key} to bucket {name}: {status}: {}", String::from_utf8_lossy(&answer));
    // A server error may pass; a refusal won't.
    match status.is_server_error() {
        true => Err(anyhow::anyhow!(why)),
        false => Ok(Err(why)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_s3s() {
        let target = |key_format| Target {
            logging: Logging { target_bucket: "logs".to_owned(), target_prefix: "p/".to_owned(), key_format },
            account: "111122223333".to_owned(),
            destination: Destination::detached("logs", "111122223333"),
            server: None,
        };
        // 2026-11-16T05:06:07Z, records of the day before.
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_794_805_567);
        let day = Day::of(now - Duration::from_secs(24 * 3600));
        let simple = key(&target(None), "src", day, now);
        assert!(simple.starts_with("p/2026-11-16-05-06-07-"), "{simple}");
        assert_eq!(simple.len(), "p/2026-11-16-05-06-07-".len() + 16);
        let partitioned = key(&target(Some(KeyFormat::Partitioned(None))), "src", day, now);
        let region = crate::s3::buckets::head::REGION;
        assert!(
            partitioned.starts_with(&format!("p/111122223333/{region}/src/2026/11/15/2026-11-16-05-06-07-")),
            "{partitioned}"
        );
    }
}
