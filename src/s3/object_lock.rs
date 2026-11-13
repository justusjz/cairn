//! Object Lock, as in S3: write-once-read-many protection of object
//! versions.
//!
//! A bucket has it enabled when it's created (`x-amz-bucket-object-lock-
//! enabled: true`, which also enables versioning), or later, if it's
//! versioned, by PutObjectLockConfiguration; it can't be disabled again, and
//! the bucket's versioning can't be suspended. Its configuration may give a
//! default retention (a mode, and a number of days or years), which every new
//! version that asks for none gets, from the time it's written.
//!
//! A version may have a retention: a mode and the time it lasts until. While
//! it lasts, the version can't be deleted (a delete without a version ID
//! still stacks a delete marker, as ever), nor expired by lifecycle rules,
//! and the retention can only be lengthened:
//!
//! - in GOVERNANCE mode, whom `s3:BypassGovernanceRetention` is allowed may,
//!   with `x-amz-bypass-governance-retention: true`, delete the version, or
//!   shorten or remove its retention; it may also be changed to COMPLIANCE;
//! - in COMPLIANCE mode, no one can, not even the bucket's account's root
//!   or a superadmin: the catalog refuses it too (see `db::OBJECT_LOCK`).
//!
//! And a version may have a legal hold, independently, which keeps it until
//! it's lifted (`s3:PutObjectLegalHold`), whatever its retention.
//!
//! Writes set both with `x-amz-object-lock-mode`,
//! `x-amz-object-lock-retain-until-date` and `x-amz-object-lock-legal-hold`
//! (PutObject, CopyObject, which doesn't copy its source's, and
//! CreateMultipartUpload, whose upload completes with them), and
//! PutObjectRetention and PutObjectLegalHold change them in place; GET and
//! HEAD tell them, to whom may read them. Errors and messages are S3's.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http_body_util::Full;
use hyper::{HeaderMap, Response, StatusCode, body::Bytes, header};

use crate::db::{self, Cached};
use crate::{
    App,
    policy::Context,
    s3::objects::get::{Missing, lookup_version, no_such_version},
    s3::util::{format_s3_error, slow_down, with_delete_marker, with_version_id, xml_escape, xml_ok},
    s3::versions::Versioning,
};

pub const MODE: &str = "x-amz-object-lock-mode";
pub const RETAIN_UNTIL: &str = "x-amz-object-lock-retain-until-date";
pub const LEGAL_HOLD: &str = "x-amz-object-lock-legal-hold";
/// A delete's or PutObjectRetention's ask to bypass GOVERNANCE mode.
pub const BYPASS: &str = "x-amz-bypass-governance-retention";
/// CreateBucket's ask for Object Lock.
pub const BUCKET_ENABLED: &str = "x-amz-bucket-object-lock-enabled";

const XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
const XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// S3's limits of a default retention.
const MAX_DAYS: i32 = 36_500;
const MAX_YEARS: i32 = 100;

/// A retention's mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Governance,
    Compliance,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Mode::Governance => "GOVERNANCE",
            Mode::Compliance => "COMPLIANCE",
        }
    }

    /// As S3 takes it: uppercase.
    pub fn parse(text: &str) -> Option<Mode> {
        match text {
            "GOVERNANCE" => Some(Mode::Governance),
            "COMPLIANCE" => Some(Mode::Compliance),
            _ => None,
        }
    }
}

/// What a write asks for: a retention, and a legal hold. Neither is the
/// bucket's default retention (if it has one), and no legal hold.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Lock {
    pub retention: Option<(Mode, SystemTime)>,
    pub legal_hold: Option<bool>,
}

impl Lock {
    /// What a write's headers ask for, or S3's 400 for what it can't be.
    #[allow(clippy::result_large_err)]
    pub fn from_headers(headers: &HeaderMap) -> Result<Lock, Response<Full<Bytes>>> {
        let header = |name| headers.get(name).map(|v| v.to_str().unwrap_or("\u{0}"));
        let retention = match (header(MODE), header(RETAIN_UNTIL)) {
            (None, None) => None,
            (Some(mode), Some(until)) => {
                let Some(mode) = Mode::parse(mode) else {
                    return Err(invalid_argument("Unknown wormMode directive."));
                };
                let Some(until) = parse_date(until) else {
                    return Err(invalid_argument("The retain until date must be provided in ISO 8601 format"));
                };
                if until <= SystemTime::now() {
                    return Err(in_the_past());
                }
                Some((mode, until))
            }
            _ => {
                return Err(invalid_argument(
                    "x-amz-object-lock-retain-until-date and x-amz-object-lock-mode must both be supplied",
                ));
            }
        };
        let legal_hold = match header(LEGAL_HOLD) {
            None => None,
            Some("ON") => Some(true),
            Some("OFF") => Some(false),
            Some(_) => return Err(invalid_argument("Legal Hold must be either of 'ON' or 'OFF'")),
        };
        Ok(Lock { retention, legal_hold })
    }

    pub fn is_empty(&self) -> bool {
        self.retention.is_none() && self.legal_hold.is_none()
    }

    /// As the catalog's functions take it (see `cairn_put_version`).
    pub fn columns(&self) -> (Option<&'static str>, Option<SystemTime>, Option<bool>) {
        (self.retention.map(|(mode, _)| mode.name()), self.retention.map(|(_, until)| until), self.legal_hold)
    }
}

/// A retain-until date: ISO 8601, with a time (`2030-01-01T00:00:00Z`, with
/// fractions or an offset), to the millisecond.
pub fn parse_date(text: &str) -> Option<SystemTime> {
    if !text.contains(['T', 't']) {
        return None;
    }
    let seconds = crate::policy::date(text)?;
    let millis = (seconds * 1000.0).round();
    (millis >= 0.0 && millis < 1e15).then(|| UNIX_EPOCH + Duration::from_millis(millis as u64))
}

/// Days left until `until`, rounded up, as `s3:object-lock-remaining-
/// retention-days` tells them.
fn remaining_days(until: SystemTime) -> u64 {
    let left = until.duration_since(SystemTime::now()).unwrap_or_default().as_secs_f64();
    (left / 86_400.0).ceil() as u64
}

/// The condition keys of what a request asks for (as its headers, or its
/// body, have it), which policies may test.
pub fn set_context(context: &mut Context, mode: Option<&str>, until: Option<&str>, legal_hold: Option<&str>) {
    if let Some(mode) = mode {
        context.set("s3:object-lock-mode", mode);
    }
    if let Some(until) = until {
        context.set("s3:object-lock-retain-until-date", until);
        if let Some(date) = parse_date(until) {
            context.set("s3:object-lock-remaining-retention-days", remaining_days(date).to_string());
        }
    }
    if let Some(hold) = legal_hold {
        context.set("s3:object-lock-legal-hold", hold);
    }
}

/// The lock of a version, as it's stored.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stored {
    pub mode: Option<String>,
    /// ISO 8601, to the millisecond.
    pub until: Option<String>,
    pub legal_hold: Option<bool>,
}

/// The columns of a version's lock that `Stored::from_row` reads.
pub const COLUMNS: &str = "o.retain_mode, \
     to_char(o.retain_until AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), o.legal_hold";

impl Stored {
    /// From `COLUMNS`, starting at column `at`.
    pub fn from_row(row: &tokio_postgres::Row, at: usize) -> Stored {
        Stored { mode: row.get(at), until: row.get(at + 1), legal_hold: row.get(at + 2) }
    }

    /// GET's and HEAD's headers of it, which `strip` takes away from whom
    /// may not read them.
    pub fn headers(&self, mut builder: hyper::http::response::Builder) -> hyper::http::response::Builder {
        if let (Some(mode), Some(until)) = (&self.mode, &self.until) {
            builder = builder.header(MODE, mode).header(RETAIN_UNTIL, until);
        }
        if let Some(hold) = self.legal_hold {
            builder = builder.header(LEGAL_HOLD, if hold { "ON" } else { "OFF" });
        }
        builder
    }
}

/// Takes the headers of a version's retention (unless `retention` may be
/// read: `s3:GetObjectRetention`) and legal hold (`legal_hold`,
/// `s3:GetObjectLegalHold`) off a response, as S3 tells them only to whom may.
pub fn strip<B>(mut response: Response<B>, retention: bool, legal_hold: bool) -> Response<B> {
    if !retention {
        response.headers_mut().remove(MODE);
        response.headers_mut().remove(RETAIN_UNTIL);
    }
    if !legal_hold {
        response.headers_mut().remove(LEGAL_HOLD);
    }
    response
}

/// Whether a CreateBucket asks for Object Lock.
pub fn asks_for_bucket(headers: &HeaderMap) -> bool {
    headers.get(BUCKET_ENABLED).is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"true"))
}

/// Whether a request asks to bypass GOVERNANCE mode.
pub fn asks_to_bypass(headers: &HeaderMap) -> bool {
    headers.get(BYPASS).is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"true"))
}

/// Whether `bucket` has Object Lock enabled; `None` if there's no such
/// bucket. Once it has, it always will.
async fn enabled(app: &App, bucket: &str) -> anyhow::Result<Option<bool>> {
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached("SELECT object_lock FROM buckets WHERE name = $1", &[&bucket])
        .await?;
    Ok(row.map(|row| row.get(0)))
}

/// Refuses a write that asks for a lock in a bucket without Object Lock, as
/// S3 does; `None` if it may go ahead (also if there's no such bucket, which
/// the write reports itself). Enabled once, Object Lock stays, so this holds
/// when the write lands.
pub async fn check_write(app: &App, bucket: &str, lock: &Lock) -> anyhow::Result<Option<Response<Full<Bytes>>>> {
    if lock.is_empty() || enabled(app, bucket).await? != Some(false) {
        return Ok(None);
    }
    Ok(Some(missing_configuration()))
}

/// Whether a PutObject of `lock` to `bucket` must declare a checksum of its
/// body, as S3 requires of one that's retained: it asks for a lock, or the
/// bucket has a default retention.
pub async fn needs_checksum(app: &App, bucket: &str, lock: &Lock) -> anyhow::Result<bool> {
    if !lock.is_empty() {
        return Ok(true);
    }
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached("SELECT lock_mode IS NOT NULL FROM buckets WHERE name = $1", &[&bucket])
        .await?;
    Ok(row.is_some_and(|row| row.get(0)))
}

/// Whether a PutObject declares a checksum of its body: Content-MD5, an
/// `x-amz-checksum-*` header, or one in its trailer.
pub fn declares_checksum(headers: &HeaderMap) -> bool {
    crate::payload::has_body_checksum(headers)
        || headers.contains_key("x-amz-sdk-checksum-algorithm")
        || headers
            .get("x-amz-trailer")
            .is_some_and(|v| v.to_str().is_ok_and(|v| v.trim().to_ascii_lowercase().starts_with("x-amz-checksum-")))
}

/// S3's 400 for a retained PutObject without a checksum of its body.
pub fn missing_checksum() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::BAD_REQUEST,
        "InvalidRequest",
        "Content-MD5 OR x-amz-checksum- HTTP header is required for Put Object requests with Object Lock parameters",
    )
}

fn invalid_argument(message: &str) -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::BAD_REQUEST, "InvalidArgument", message)
}

fn in_the_past() -> Response<Full<Bytes>> {
    invalid_argument("The retain until date must be in the future!")
}

fn malformed() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::BAD_REQUEST,
        "MalformedXML",
        "The XML you provided was not well-formed or did not validate against our published schema",
    )
}

/// S3's 400 for a lock in a bucket without Object Lock.
pub fn missing_configuration() -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::BAD_REQUEST, "InvalidRequest", "Bucket is missing Object Lock Configuration")
}

/// S3's 403 for deleting a locked version, or changing its retention as it
/// may not be.
pub fn locked() -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::FORBIDDEN, "AccessDenied", LOCKED_MESSAGE)
}

pub const LOCKED_MESSAGE: &str = "Access Denied because object protected by object lock.";

fn no_such_bucket() -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::NOT_FOUND, "NoSuchBucket", "the specified bucket does not exist")
}

fn no_such_key() -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::NOT_FOUND, "NoSuchKey", "The specified key does not exist.")
}

fn no_configuration() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::NOT_FOUND,
        "NoSuchObjectLockConfiguration",
        "The specified object does not have a ObjectLock configuration",
    )
}

/// S3's answer for a delete marker's: 405, as for any method but DELETE on
/// a marker.
fn delete_marker(version_id: Option<&str>) -> Response<Full<Bytes>> {
    let mut response = format_s3_error(
        StatusCode::METHOD_NOT_ALLOWED,
        "MethodNotAllowed",
        "The specified method is not allowed against this resource.",
    );
    response.headers_mut().insert(header::ALLOW, header::HeaderValue::from_static("DELETE"));
    with_delete_marker(with_version_id(response, version_id))
}

/// A bucket's default retention.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Period {
    Days(i32),
    Years(i32),
}

/// The only child of `node` named `name`, if it has one; S3's 400 if it has
/// several.
#[allow(clippy::result_large_err)]
fn child<'a, 'input>(
    node: roxmltree::Node<'a, 'input>,
    name: &str,
) -> Result<Option<roxmltree::Node<'a, 'input>>, Response<Full<Bytes>>> {
    let mut found = node.children().filter(|n| n.tag_name().name() == name);
    match (found.next(), found.next()) {
        (Some(n), None) => Ok(Some(n)),
        (None, _) => Ok(None),
        _ => Err(malformed()),
    }
}

/// What a `<ObjectLockConfiguration>` asks for: Object Lock, with this
/// default retention (none if `None`). `Err` is S3's 400.
#[allow(clippy::result_large_err)]
fn parse_configuration(body: &[u8]) -> Result<Option<(Mode, Period)>, Response<Full<Bytes>>> {
    let text = std::str::from_utf8(body).map_err(|_| malformed())?;
    let doc = roxmltree::Document::parse(text).map_err(|_| malformed())?;
    let root = doc.root_element();
    if root.tag_name().name() != "ObjectLockConfiguration" {
        return Err(malformed());
    }
    let text = |node: roxmltree::Node<'_, '_>| node.text().unwrap_or("").trim().to_owned();
    match child(root, "ObjectLockEnabled")? {
        Some(enabled) if text(enabled) == "Enabled" => {}
        _ => return Err(malformed()),
    }
    let Some(rule) = child(root, "Rule")? else { return Ok(None) };
    let Some(retention) = child(rule, "DefaultRetention")? else { return Err(malformed()) };
    let Some(mode) = child(retention, "Mode")?.and_then(|m| Mode::parse(&text(m))) else {
        return Err(malformed());
    };
    let number = |node| text(node).parse::<i64>().map_err(|_| malformed());
    let period = match (child(retention, "Days")?, child(retention, "Years")?) {
        (Some(days), None) => (number(days)?, MAX_DAYS, Period::Days as fn(i32) -> Period),
        (None, Some(years)) => (number(years)?, MAX_YEARS, Period::Years as fn(i32) -> Period),
        _ => return Err(malformed()),
    };
    let (n, max, make) = period;
    if n <= 0 {
        return Err(invalid_argument("Default retention period must be a positive integer value."));
    }
    if n > i64::from(max) {
        return Err(invalid_argument("Default retention period is too large."));
    }
    Ok(Some((mode, make(n as i32))))
}

/// GetObjectLockConfiguration: `GET /{bucket}?object-lock`.
pub async fn get_object_lock_configuration(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached("SELECT object_lock, lock_mode, lock_days, lock_years FROM buckets WHERE name = $1", &[&bucket])
        .await?;
    let Some(row) = row else { return Ok(no_such_bucket()) };
    if !row.get::<_, bool>(0) {
        return Ok(format_s3_error(
            StatusCode::NOT_FOUND,
            "ObjectLockConfigurationNotFoundError",
            "Object Lock configuration does not exist for this bucket",
        ));
    }
    let rule = match (row.get::<_, Option<&str>>(1), row.get::<_, Option<i32>>(2), row.get::<_, Option<i32>>(3)) {
        (Some(mode), Some(days), _) => {
            format!("<Rule><DefaultRetention><Mode>{mode}</Mode><Days>{days}</Days></DefaultRetention></Rule>")
        }
        (Some(mode), None, Some(years)) => {
            format!("<Rule><DefaultRetention><Mode>{mode}</Mode><Years>{years}</Years></DefaultRetention></Rule>")
        }
        _ => String::new(),
    };
    Ok(xml_ok(format!(
        "{XML}<ObjectLockConfiguration xmlns=\"{XMLNS}\"><ObjectLockEnabled>Enabled</ObjectLockEnabled>{rule}\
         </ObjectLockConfiguration>"
    )))
}

/// PutObjectLockConfiguration: `PUT /{bucket}?object-lock` with an
/// `<ObjectLockConfiguration>` body, checked against its integrity headers
/// (see `Payload`), of which S3 requires one. Enables Object Lock (on a
/// versioned bucket only, as S3 does), and sets or (without a `<Rule>`)
/// removes its default retention.
pub async fn put_object_lock_configuration(
    app: &App,
    bucket: &str,
    body: Bytes,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let rule = match parse_configuration(&body) {
        Ok(rule) => rule,
        Err(refused) => return Ok(refused),
    };
    let mode = rule.map(|(mode, _)| mode.name());
    let (days, years) = match rule.map(|(_, period)| period) {
        Some(Period::Days(days)) => (Some(days), None),
        Some(Period::Years(years)) => (None, Some(years)),
        None => (None, None),
    };
    let client = app.pool.get().await?;
    for attempt in 0..db::MAX_TX_ATTEMPTS {
        db::backoff(attempt).await;
        let status: String = match client
            .query_one_cached("SELECT pg_temp.cairn_set_object_lock($1, $2, $3, $4)", &[&bucket, &mode, &days, &years])
            .await
        {
            Ok(row) => row.get(0),
            Err(e) if db::is_conflict(&e) => continue,
            Err(e) => return Err(e.into()),
        };
        return Ok(match status.as_str() {
            "set" => Response::builder().status(StatusCode::OK).body(Full::new(Bytes::new())).unwrap(),
            "not_versioned" => format_s3_error(
                StatusCode::CONFLICT,
                "InvalidBucketState",
                "Versioning must be 'Enabled' on the bucket to apply a Object Lock configuration",
            ),
            "no_such_bucket" => no_such_bucket(),
            other => anyhow::bail!("cairn_set_object_lock: unexpected status {other}"),
        });
    }
    Ok(slow_down())
}

/// What a `<Retention>` document holds, as it's written: its mode and its
/// retain-until date (neither, to remove a retention); `None` if it isn't one.
pub fn parse_retention(body: &[u8]) -> Option<(Option<String>, Option<String>)> {
    let doc = roxmltree::Document::parse(std::str::from_utf8(body).ok()?).ok()?;
    let root = doc.root_element();
    if root.tag_name().name() != "Retention" {
        return None;
    }
    let child = |name| {
        root.children().find(|n| n.tag_name().name() == name).map(|n| n.text().unwrap_or("").trim().to_owned())
    };
    Some((child("Mode"), child("RetainUntilDate")))
}

/// What a `<LegalHold>` document holds, as it's written: its status;
/// `None` if it isn't one.
pub fn parse_legal_hold(body: &[u8]) -> Option<String> {
    let doc = roxmltree::Document::parse(std::str::from_utf8(body).ok()?).ok()?;
    let root = doc.root_element();
    if root.tag_name().name() != "LegalHold" {
        return None;
    }
    root.children().find(|n| n.tag_name().name() == "Status").map(|n| n.text().unwrap_or("").trim().to_owned())
}

/// The version a GetObjectRetention or GetObjectLegalHold reads, and its
/// version ID to report; or the response that tells why there's none.
async fn read_lock(
    app: &App,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
) -> anyhow::Result<Result<(Stored, Option<String>), Response<Full<Bytes>>>> {
    match enabled(app, bucket).await? {
        None => return Ok(Err(no_such_bucket())),
        Some(false) => return Ok(Err(missing_configuration())),
        Some(true) => {}
    }
    let client = app.pool.get().await?;
    Ok(match lookup_version(&client, bucket, key, version_id).await? {
        Ok(version) => Ok((version.lock, version.version_id)),
        Err(Missing::NoSuchKey) => Err(no_such_key()),
        Err(Missing::NoSuchVersion) => Err(no_such_version()),
        Err(Missing::DeleteMarker { version_id, .. }) => Err(delete_marker(version_id.as_deref())),
    })
}

/// GetObjectRetention: `GET /{bucket}/{key}?retention`.
pub async fn get_object_retention(
    app: &App,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let (lock, version_id) = match read_lock(app, bucket, key, version_id).await? {
        Ok(read) => read,
        Err(refused) => return Ok(refused),
    };
    let (Some(mode), Some(until)) = (lock.mode, lock.until) else { return Ok(no_configuration()) };
    let body = format!(
        "{XML}<Retention xmlns=\"{XMLNS}\"><Mode>{mode}</Mode><RetainUntilDate>{until}</RetainUntilDate></Retention>"
    );
    Ok(with_version_id(xml_ok(body), version_id.as_deref()))
}

/// GetObjectLegalHold: `GET /{bucket}/{key}?legal-hold`.
pub async fn get_object_legal_hold(
    app: &App,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let (lock, version_id) = match read_lock(app, bucket, key, version_id).await? {
        Ok(read) => read,
        Err(refused) => return Ok(refused),
    };
    let Some(hold) = lock.legal_hold else { return Ok(no_configuration()) };
    let status = if hold { "ON" } else { "OFF" };
    let body = format!("{XML}<LegalHold xmlns=\"{XMLNS}\"><Status>{status}</Status></LegalHold>");
    Ok(with_version_id(xml_ok(body), version_id.as_deref()))
}

/// PutObjectRetention: `PUT /{bucket}/{key}?retention` with a `<Retention>`
/// body (see `parse_retention`), checked against its integrity headers, of
/// which S3 requires one. `bypass` is whether the request may bypass
/// GOVERNANCE mode: it asks to, and `s3:BypassGovernanceRetention` is
/// allowed it.
pub async fn put_object_retention(
    app: &App,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    body: &[u8],
    bypass: bool,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let retention = match parse_retention(body) {
        None => return Ok(malformed()),
        Some((None, None)) => None,
        Some((Some(mode), Some(until))) => {
            let (Some(mode), Some(until)) = (Mode::parse(&mode), parse_date(&until)) else {
                return Ok(malformed());
            };
            if until <= SystemTime::now() {
                return Ok(in_the_past());
            }
            Some((mode, until))
        }
        Some(_) => return Ok(malformed()),
    };
    let mode = retention.map(|(mode, _)| mode.name());
    let until = retention.map(|(_, until)| until);
    let client = app.pool.get().await?;
    for attempt in 0..db::MAX_TX_ATTEMPTS {
        db::backoff(attempt).await;
        let row = match client
            .query_one_cached(
                "SELECT status, versioning, version_id FROM pg_temp.cairn_set_retention($1, $2, $3, $4, $5, $6)",
                &[&bucket, &key, &version_id, &mode, &until, &bypass],
            )
            .await
        {
            Ok(row) => row,
            Err(e) if db::is_conflict(&e) => continue,
            Err(e) => return Err(e.into()),
        };
        return answer(&row, "cairn_set_retention");
    }
    Ok(slow_down())
}

/// PutObjectLegalHold: `PUT /{bucket}/{key}?legal-hold` with a
/// `<LegalHold>` body, checked against its integrity headers, of which S3
/// requires one.
pub async fn put_object_legal_hold(
    app: &App,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    body: &[u8],
) -> anyhow::Result<Response<Full<Bytes>>> {
    let hold = match parse_legal_hold(body).as_deref() {
        Some("ON") => true,
        Some("OFF") => false,
        _ => return Ok(malformed()),
    };
    let client = app.pool.get().await?;
    for attempt in 0..db::MAX_TX_ATTEMPTS {
        db::backoff(attempt).await;
        let row = match client
            .query_one_cached(
                "SELECT status, versioning, version_id FROM pg_temp.cairn_set_legal_hold($1, $2, $3, $4)",
                &[&bucket, &key, &version_id, &hold],
            )
            .await
        {
            Ok(row) => row,
            Err(e) if db::is_conflict(&e) => continue,
            Err(e) => return Err(e.into()),
        };
        return answer(&row, "cairn_set_legal_hold");
    }
    Ok(slow_down())
}

/// The response to PutObjectRetention's or PutObjectLegalHold's
/// transaction (status, versioning, version ID).
fn answer(row: &tokio_postgres::Row, function: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let reported = row
        .get::<_, Option<&str>>(1)
        .zip(row.get::<_, Option<&str>>(2))
        .and_then(|(versioning, id)| Versioning::from_db(versioning).reported(id));
    Ok(match row.get::<_, &str>(0) {
        "set" => Response::builder().status(StatusCode::OK).body(Full::new(Bytes::new())).unwrap(),
        "locked" => locked(),
        "delete_marker" => delete_marker(reported.as_deref()),
        "no_such_version" => no_such_version(),
        "no_such_key" => no_such_key(),
        "no_object_lock" => missing_configuration(),
        "no_such_bucket" => no_such_bucket(),
        other => anyhow::bail!("{function}: unexpected status {other}"),
    })
}

/// A DeleteObjects `<Error>` for a version Object Lock keeps.
pub fn locked_error(key: &str, version_id: Option<&str>) -> String {
    let version = version_id.map(|v| format!("<VersionId>{}</VersionId>", xml_escape(v))).unwrap_or_default();
    format!("<Error><Key>{}</Key>{version}<Code>AccessDenied</Code><Message>{LOCKED_MESSAGE}</Message></Error>", xml_escape(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(), value.parse().unwrap());
        }
        headers
    }

    #[test]
    fn parses_dates() {
        assert_eq!(parse_date("2030-01-01T00:00:00Z"), Some(UNIX_EPOCH + Duration::from_secs(1_893_456_000)));
        assert_eq!(parse_date("2030-01-01T00:00:00.250Z"), Some(UNIX_EPOCH + Duration::from_millis(1_893_456_000_250)));
        assert_eq!(parse_date("2030-01-01T01:00:00+01:00"), parse_date("2030-01-01T00:00:00Z"));
        assert_eq!(parse_date("2030-01-01"), None);
        assert_eq!(parse_date("1893456000"), None);
        assert_eq!(parse_date("tomorrow"), None);
    }

    #[test]
    fn reads_write_headers() {
        assert_eq!(Lock::from_headers(&HeaderMap::new()).unwrap(), Lock::default());
        let lock = Lock::from_headers(&headers(&[
            (MODE, "COMPLIANCE"),
            (RETAIN_UNTIL, "2999-01-01T00:00:00Z"),
            (LEGAL_HOLD, "ON"),
        ]))
        .unwrap();
        assert_eq!(lock.retention.map(|(m, _)| m), Some(Mode::Compliance));
        assert_eq!(lock.legal_hold, Some(true));
        assert_eq!(lock.columns().0, Some("COMPLIANCE"));
        let refused = |pairs: &[(&str, &str)]| Lock::from_headers(&headers(pairs)).unwrap_err().status();
        assert_eq!(refused(&[(MODE, "GOVERNANCE")]), StatusCode::BAD_REQUEST);
        assert_eq!(refused(&[(RETAIN_UNTIL, "2999-01-01T00:00:00Z")]), StatusCode::BAD_REQUEST);
        assert_eq!(refused(&[(MODE, "governance"), (RETAIN_UNTIL, "2999-01-01T00:00:00Z")]), StatusCode::BAD_REQUEST);
        assert_eq!(refused(&[(MODE, "GOVERNANCE"), (RETAIN_UNTIL, "2000-01-01T00:00:00Z")]), StatusCode::BAD_REQUEST);
        assert_eq!(refused(&[(LEGAL_HOLD, "on")]), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn parses_configurations() {
        let parse = |rule: &str| {
            parse_configuration(
                format!("<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled>{rule}</ObjectLockConfiguration>")
                    .as_bytes(),
            )
        };
        assert_eq!(parse("").unwrap(), None);
        assert_eq!(
            parse("<Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>3</Days></DefaultRetention></Rule>").unwrap(),
            Some((Mode::Governance, Period::Days(3)))
        );
        assert_eq!(
            parse("<Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Years>1</Years></DefaultRetention></Rule>").unwrap(),
            Some((Mode::Compliance, Period::Years(1)))
        );
        let code = |rule: &str| parse(rule).unwrap_err().status();
        for rule in [
            "<Rule></Rule>",
            "<Rule><DefaultRetention><Mode>GOVERNANCE</Mode></DefaultRetention></Rule>",
            "<Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days><Years>1</Years></DefaultRetention></Rule>",
            "<Rule><DefaultRetention><Mode>OTHER</Mode><Days>1</Days></DefaultRetention></Rule>",
            "<Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>0</Days></DefaultRetention></Rule>",
            "<Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Years>101</Years></DefaultRetention></Rule>",
        ] {
            assert_eq!(code(rule), StatusCode::BAD_REQUEST, "{rule}");
        }
        assert!(parse_configuration(b"<ObjectLockConfiguration/>").is_err());
        assert!(
            parse_configuration(b"<ObjectLockConfiguration><ObjectLockEnabled>Disabled</ObjectLockEnabled></ObjectLockConfiguration>")
                .is_err()
        );
    }

    #[test]
    fn parses_retentions_and_holds() {
        assert_eq!(
            parse_retention(b"<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2030-01-01T00:00:00Z</RetainUntilDate></Retention>"),
            Some((Some("GOVERNANCE".to_owned()), Some("2030-01-01T00:00:00Z".to_owned())))
        );
        assert_eq!(parse_retention(b"<Retention/>"), Some((None, None)));
        assert_eq!(parse_retention(b"<Tagging/>"), None);
        assert_eq!(parse_legal_hold(b"<LegalHold><Status>ON</Status></LegalHold>").as_deref(), Some("ON"));
        assert_eq!(parse_legal_hold(b"<LegalHold/>"), None);
    }

    #[test]
    fn tells_remaining_days() {
        assert_eq!(remaining_days(SystemTime::now() + Duration::from_secs(86_400 + 60)), 2);
        assert_eq!(remaining_days(SystemTime::now() - Duration::from_secs(60)), 0);
        let mut context = Context::default();
        set_context(&mut context, Some("GOVERNANCE"), Some("2999-01-01T00:00:00Z"), Some("ON"));
        assert_eq!(context.get("s3:object-lock-mode"), Some(&["GOVERNANCE".to_owned()][..]));
        assert_eq!(context.get("s3:object-lock-legal-hold"), Some(&["ON".to_owned()][..]));
        assert!(context.get("s3:object-lock-remaining-retention-days").is_some());
    }
}
