//! What a bucket's lifecycle rules have in store for an object or an
//! upload, as S3 tells it in responses (probed, `plans/probes/expiration_probe.py`):
//!
//! - `x-amz-expiration: expiry-date="<HTTP date>", rule-id="<ID>"`: on
//!   PutObject, CopyObject, CompleteMultipartUpload, and a GetObject or
//!   HeadObject (a 304 too) of a key's current version that names no
//!   version. Not for a version named by ID, even the current one, nor for
//!   noncurrent versions' expiration, nor delete markers.
//! - `x-amz-abort-date` and `x-amz-abort-rule-id`: on CreateMultipartUpload
//!   and ListParts. Not on UploadPart.
//!
//! The date is the day the rule takes effect on (see `lifecycle::rules`),
//! the earliest of the rules that apply.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hyper::{Response, header::HeaderValue};

use crate::db::Cached;
use crate::{App, lifecycle::rules::Configuration};

pub const EXPIRATION: &str = "x-amz-expiration";
pub const ABORT_DATE: &str = "x-amz-abort-date";
pub const ABORT_RULE_ID: &str = "x-amz-abort-rule-id";

/// A bucket's stored configuration (`buckets.lifecycle`), if it has one that
/// parses. (One that doesn't is a newer Cairn's: its sweep is that one's, so
/// telling nothing of it is as good as anything.)
fn configuration(lifecycle: Option<&str>) -> Option<Configuration> {
    Configuration::from_json(lifecycle?).ok()
}

/// A time from seconds since the epoch, as Postgres's `extract(epoch …)`.
pub fn from_epoch(seconds: f64) -> SystemTime {
    if seconds >= 0.0 {
        UNIX_EPOCH + Duration::from_secs_f64(seconds)
    } else {
        UNIX_EPOCH - Duration::from_secs_f64(-seconds)
    }
}

/// `x-amz-expiration` for the current version of `key`, of `size` and
/// `tags` (stored form), written at `written`, under the bucket's stored
/// configuration `lifecycle`; `None` if no rule expires it.
pub fn expiration(lifecycle: Option<&str>, key: &str, size: i64, tags: &str, written: SystemTime) -> Option<HeaderValue> {
    let config = configuration(lifecycle)?;
    let (day, rule) = config.expiry(key, size, tags, written)?;
    // An ID is any text; one that can't be a header's isn't told.
    HeaderValue::from_str(&format!("expiry-date=\"{}\", rule-id=\"{rule}\"", day.to_http())).ok()
}

/// `x-amz-expiration` for a version just written to `bucket`: its
/// last-modified time as the write reports it (ISO 8601).
pub async fn of_write(
    app: &App,
    bucket: &str,
    key: &str,
    size: i64,
    tags: &str,
    last_modified: &str,
) -> anyhow::Result<Option<HeaderValue>> {
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached(
            "SELECT lifecycle, extract(epoch FROM $2::text::timestamptz)::float8 FROM buckets WHERE name = $1",
            &[&bucket, &last_modified],
        )
        .await?;
    Ok(row.and_then(|row| expiration(row.get(0), key, size, tags, from_epoch(row.get(1)))))
}

/// `x-amz-expiration` for the version of `bucket`/`key` that completed
/// `upload` (none if it's been replaced already).
pub async fn of_completed<C: deadpool_postgres::GenericClient>(
    client: &C,
    bucket: &str,
    key: &str,
    upload: &uuid::Uuid,
) -> anyhow::Result<Option<HeaderValue>> {
    let row = client
        .query_opt_cached(
            "SELECT b.lifecycle, o.size, o.tags, extract(epoch FROM o.last_modified)::float8
             FROM objects o JOIN buckets b ON b.name = o.bucket
             WHERE o.bucket = $1 AND o.key = $2 AND o.upload_id = $3 AND o.is_latest LIMIT 1",
            &[&bucket, &key, upload],
        )
        .await?;
    Ok(row.and_then(|row| expiration(row.get(0), key, row.get(1), row.get(2), from_epoch(row.get(3)))))
}

/// Adds `x-amz-expiration`, if there's one.
pub fn onto<B>(mut response: Response<B>, expiration: Option<HeaderValue>) -> Response<B> {
    if let Some(value) = expiration {
        response.headers_mut().insert(EXPIRATION, value);
    }
    response
}

/// Adds `x-amz-abort-date` and `x-amz-abort-rule-id` for the upload of
/// `key` begun at `initiated`, if a rule of the bucket's stored
/// configuration `lifecycle` aborts it.
pub fn abort_onto<B>(mut response: Response<B>, lifecycle: Option<&str>, key: &str, initiated: SystemTime) -> Response<B> {
    let Some(config) = configuration(lifecycle) else { return response };
    let Some((day, rule)) = config.abort_date(key, initiated) else { return response };
    if let Ok(rule) = HeaderValue::from_str(rule) {
        let headers = response.headers_mut();
        headers.insert(ABORT_DATE, HeaderValue::from_str(&day.to_http()).unwrap());
        headers.insert(ABORT_RULE_ID, rule);
    }
    response
}
