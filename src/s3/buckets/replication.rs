//! A bucket's replication configuration: PutBucketReplication,
//! GetBucketReplication and DeleteBucketReplication (`?replication`). What
//! it is, `replication::config`'s; what replicating by it does,
//! `replication`'s.
//!
//! As in S3, the bucket must be versioned (and then stays so: see I15 in
//! `catalog.sql`), and so must every destination, which must be another
//! bucket of the cluster: one of the bucket's account, or of another, whose
//! policy lets the role replicate to it (which is checked as versions are
//! replicated, not here). A bucket with Object Lock replicates only to
//! buckets with it too. The role must be the bucket's account's, and the
//! caller must be allowed to pass it to S3 (`iam:PassRole`).
//!
//! Kept as JSON in the bucket's row, set under it (T67).

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::{
    App, db,
    db::Cached,
    policy::{Context, Verdict},
    replication::config::{Configuration, Invalid},
    s3::{
        access::Access,
        actions::{Check, On},
        util::{format_s3_error, xml_ok},
    },
};

/// The largest configuration document taken.
const MAX_DOCUMENT: usize = 2 << 20;

fn no_such_bucket() -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::NOT_FOUND, "NoSuchBucket", "The specified bucket does not exist")
}

fn not_found() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::NOT_FOUND,
        "ReplicationConfigurationNotFoundError",
        "The replication configuration was not found",
    )
}

fn invalid_request(message: &str) -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::BAD_REQUEST, "InvalidRequest", message)
}

/// The bucket's replication configuration: `None` if there's no such
/// bucket, `Some(None)` if it has none.
pub async fn load(app: &App, bucket: &str) -> anyhow::Result<Option<Option<Configuration>>> {
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached("SELECT replication FROM buckets WHERE name = $1", &[&bucket])
        .await?;
    let Some(row) = row else { return Ok(None) };
    let Some(json) = row.get::<_, Option<String>>(0) else { return Ok(Some(None)) };
    let config = Configuration::from_json(&json).map_err(|e| {
        anyhow::anyhow!("bucket {bucket}'s replication configuration doesn't parse (written by a newer Cairn?): {e}")
    })?;
    Ok(Some(Some(config)))
}

/// GetBucketReplication: `GET /{bucket}?replication`. S3's 404
/// (`ReplicationConfigurationNotFoundError`) for a bucket without one.
pub async fn get(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    Ok(match load(app, bucket).await? {
        None => no_such_bucket(),
        Some(None) => not_found(),
        Some(Some(config)) => xml_ok(config.xml()),
    })
}

/// PutBucketReplication: `PUT /{bucket}?replication` with a
/// `<ReplicationConfiguration>` body, checked against its integrity
/// headers (see `Payload`). Replaces the bucket's configuration, checked
/// as the module's docs say; `access` is the caller's, which must be
/// allowed to pass the role.
pub async fn put(app: &App, bucket: &str, body: Bytes, access: &Access) -> anyhow::Result<Response<Full<Bytes>>> {
    if body.len() > MAX_DOCUMENT {
        return Ok(format_s3_error(StatusCode::BAD_REQUEST, "MaxMessageLengthExceeded", "Your request was too big."));
    }
    let parsed = std::str::from_utf8(&body).map_err(|_| Invalid::Malformed("not UTF-8".to_owned())).and_then(Configuration::parse);
    let config = match parsed {
        Ok(config) => config,
        Err(invalid) => return Ok(invalid.response()),
    };
    let client = app.pool.get().await?;
    let mut names: Vec<&str> = vec![bucket];
    names.extend(config.destinations().iter().map(|d| d.bucket.as_str()));
    let rows = client
        .query_cached(
            "SELECT name, account_id, versioning, object_lock FROM buckets WHERE name = ANY($1)",
            &[&names],
        )
        .await?;
    let find = |name: &str| rows.iter().find(|r| r.get::<_, &str>(0) == name);
    let Some(source) = find(bucket) else { return Ok(no_such_bucket()) };
    let (owner, versioning, locked): (String, String, bool) = (source.get(1), source.get(2), source.get(3));
    if versioning != "enabled" {
        return Ok(not_versioned());
    }
    if crate::replication::role_account(&config.role) != Some(owner.as_str()) {
        return Ok(Invalid::Argument("Invalid ReplicationConfiguration Role".to_owned()).response());
    }
    for destination in config.destinations() {
        let name = destination.bucket.as_str();
        if name == bucket {
            return Ok(invalid_request("Destination bucket cannot be the same as the source bucket."));
        }
        if crate::s3::directory::is_directory(name) {
            return Ok(invalid_request("Replication to a directory bucket isn't supported."));
        }
        let Some(row) = find(name) else {
            return Ok(invalid_request("Destination bucket must exist."));
        };
        if destination.account.as_deref().is_some_and(|account| account != row.get::<_, &str>(1)) {
            return Ok(invalid_request("Destination bucket owner account ID does not match the bucket's owner."));
        }
        if row.get::<_, &str>(2) != "enabled" {
            return Ok(invalid_request("Destination bucket must have versioning enabled."));
        }
        if locked && !row.get::<_, bool>(3) {
            return Ok(invalid_request("Object Lock is enabled on the source bucket, so it must be on the destination too."));
        }
        if let Some(class) = &destination.storage_class
            && crate::classes::resolve(app, Some(class)).await?.is_err()
        {
            return Ok(crate::classes::invalid(class));
        }
    }
    drop(client);
    // As in S3: the caller passes the role to the service.
    let mut context = Context::default();
    context.set("iam:PassedToService", crate::replication::SERVICE);
    let check = Check { action: "iam:PassRole", on: On::Arn(config.role.clone()) };
    match access.verdict_with(&check, &context) {
        Verdict::Allow => {}
        verdict => return Ok(access.denied(&check, verdict)),
    }
    Ok(match set(app, bucket, Some(&config.to_json())).await? {
        Set::Done => Response::builder().status(StatusCode::OK).body(Full::new(Bytes::new())).unwrap(),
        Set::NotVersioned => not_versioned(),
        Set::NoSuchBucket => no_such_bucket(),
        Set::Contended => crate::s3::util::slow_down(),
    })
}

/// DeleteBucketReplication: `DELETE /{bucket}?replication`. Versions
/// queued already are replicated still, by the rules that queued them,
/// while the configuration lasts: without it, they fail (see
/// `replication`).
pub async fn delete(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    Ok(match set(app, bucket, None).await? {
        Set::Done => Response::builder().status(StatusCode::NO_CONTENT).body(Full::new(Bytes::new())).unwrap(),
        Set::NotVersioned => unreachable!("removing a configuration doesn't need versioning"),
        Set::NoSuchBucket => no_such_bucket(),
        Set::Contended => crate::s3::util::slow_down(),
    })
}

fn not_versioned() -> Response<Full<Bytes>> {
    invalid_request("Versioning must be 'Enabled' on the bucket to apply a replication configuration")
}

enum Set {
    Done,
    NotVersioned,
    NoSuchBucket,
    Contended,
}

/// Sets (or, with `None`, removes) the bucket's configuration (T67).
async fn set(app: &App, bucket: &str, config: Option<&str>) -> anyhow::Result<Set> {
    let client = app.pool.get().await?;
    for attempt in 0..db::MAX_TX_ATTEMPTS {
        db::backoff(attempt).await;
        match client.query_one_cached("SELECT pg_temp.cairn_set_replication($1, $2)", &[&bucket, &config]).await {
            Ok(row) => {
                return Ok(match row.get::<_, &str>(0) {
                    "set" => Set::Done,
                    "not_versioned" => Set::NotVersioned,
                    _ => Set::NoSuchBucket,
                });
            }
            Err(e) if db::is_conflict(&e) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(Set::Contended)
}
