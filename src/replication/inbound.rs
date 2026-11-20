//! Replication into the cluster from another one: Cairn's, MinIO's or
//! RustFS's (see `remote` for the other way), by the requests MinIO's
//! bucket replication makes, which RustFS makes too. They're S3's own
//! requests, marked as replication's (`x-amz-replication-status: REPLICA`,
//! or `x-minio-source-replication-request: true`), with what the replica
//! keeps of its source in headers of MinIO's: RustFS sends each as
//! `x-rustfs-…` too, and either is read (RustFS's first, as RustFS reads
//! them).
//!
//! - **PutObject**: the version ID is the query's `versionId` (MinIO's), or
//!   `x-minio-source-version-id` (RustFS's); the last-modified time
//!   `x-minio-source-mtime` (RFC 3339), and the ETag
//!   `x-minio-source-etag`. The write is a replica, as one written within
//!   the cluster is (see `replication`): it keeps them, is marked `REPLICA`,
//!   and lands among the key's versions by its time. A version that's there
//!   already is answered as written, again, so that a sender that didn't
//!   hear the first answer finds it done.
//! - **CreateMultipartUpload**, with the version ID; **UploadPart**; and
//!   **CompleteMultipartUpload**, with the time and ETag: the upload keeps
//!   the version ID until it completes (`multipart_uploads`).
//! - **DeleteObject** of a version ID, with `x-minio-source-deletemarker:
//!   true`: a delete marker of that ID, at the time given. Without it, the
//!   version is deleted (MinIO's `DeleteReplication`, see `config`). A
//!   UUID names the version of Cairn's own that's known by it (see
//!   `s3::versions::uuid_form`), if there's no version of that ID itself:
//!   how a MinIO or RustFS replica of a Cairn version names it.
//! - **CopyObject** of a version onto itself, of the same ID: the version's
//!   tags (`x-amz-tagging-directive: REPLACE`), retention and legal hold
//!   are set to the request's, as MinIO replicates later changes to them.
//!
//! MinIO's health checks of its targets are answered too (see `health`).
//!
//! They're authorized as replication's: `s3:ReplicateObject` instead of
//! `s3:PutObject` (and of the retention, legal hold and ACL a write sets),
//! `s3:ReplicateTags` instead of `s3:PutObjectTagging`, and
//! `s3:ReplicateDelete` instead of `s3:DeleteObject` and
//! `s3:DeleteObjectVersion`, as AWS has a replication role's destination
//! allow them. MinIO's check of a target's permissions
//! (`x-minio-source-replication-check`) is answered as MinIO answers it,
//! once the request is authorized: `400 ReplicationPermissionCheck`.
//!
//! Replicas aren't replicated again (see `cairn_replicate`), so two
//! clusters may replicate to each other.

use http_body_util::Full;
use hyper::{HeaderMap, Response, StatusCode, body::Bytes};

use crate::{
    App,
    db::Cached,
    s3::{
        actions::{Check, Operation},
        util::{format_s3_error, query_param},
        versions::{is_uuid, is_version_id, matches_uuid},
    },
};

/// The answer to MinIO's health checks, `GET` (or `HEAD`)
/// `/minio/health/live` and `/minio/health/ready`, unsigned and on the
/// endpoint itself (not a bucket's host), which MinIO and RustFS make of
/// their replication targets every few seconds, and stop replicating to
/// one that fails them: 200, as a node that's serving requests is live
/// and ready. `None` for any other request, which includes those of a
/// bucket `minio`'s keys `health/…`, if they're signed.
pub fn health<B>(
    req: &hyper::Request<B>,
    route: &crate::s3::hosting::Route,
) -> Option<Response<Full<Bytes>>> {
    let checks = matches!(*req.method(), hyper::Method::GET | hyper::Method::HEAD)
        && !route.virtual_host
        && !route.website
        && matches!(
            req.uri().path(),
            "/minio/health/live" | "/minio/health/ready"
        )
        && !req.headers().contains_key(hyper::header::AUTHORIZATION)
        && !req.uri().query().is_some_and(|q| q.contains("Signature"));
    checks.then(|| {
        Response::builder()
            .status(StatusCode::OK)
            .header("x-minio-server-status", "online")
            .body(Full::new(Bytes::new()))
            .unwrap()
    })
}

/// The prefixes of the headers replication's requests carry, in the order
/// they're read.
const PREFIXES: [&str; 2] = ["x-rustfs-", "x-minio-"];

/// Header `x-rustfs-{suffix}`, or else `x-minio-{suffix}`.
fn header<'a>(headers: &'a HeaderMap, suffix: &str) -> Option<&'a str> {
    PREFIXES.iter().find_map(|prefix| {
        headers
            .get(format!("{prefix}{suffix}"))
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
    })
}

/// The names of header `suffix`, as the requests replication sends carry
/// it: both of them.
pub fn header_names(suffix: &str) -> [String; 2] {
    PREFIXES.map(|prefix| format!("{prefix}{suffix}"))
}

/// What a replication request says of its replica.
#[derive(Debug, Default, PartialEq)]
pub struct Inbound {
    /// The version ID it keeps.
    pub version_id: Option<String>,
    /// Its last-modified time, ISO 8601 to the microsecond, as Postgres
    /// reads it.
    pub last_modified: Option<String>,
    /// Its ETag, unquoted.
    pub etag: Option<String>,
    /// A delete of `version_id` that's a delete marker of it.
    pub delete_marker: bool,
    /// MinIO's check of the target's permissions: authorized, and refused.
    pub check: bool,
}

/// Whether the request is replication's.
pub fn is_request(headers: &HeaderMap) -> bool {
    headers
        .get("x-amz-replication-status")
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"REPLICA"))
        || header(headers, "source-replication-request").is_some_and(|v| v == "true")
        || header(headers, "source-replication-check").is_some()
}

/// What the replication request with `headers` and `query` says, if it's
/// one; 400 InvalidArgument for what it says that can't be.
pub fn parse(headers: &HeaderMap, query: &str) -> Result<Option<Inbound>, Response<Full<Bytes>>> {
    if !is_request(headers) {
        return Ok(None);
    }
    let invalid = |what: &str| {
        format_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            &format!("Invalid replication request: {what}"),
        )
    };
    let version_id = query_param(query, "versionId")
        .or_else(|| header(headers, "source-version-id").map(str::to_owned))
        .filter(|v| !v.is_empty());
    if let Some(id) = &version_id
        && !is_version_id(id)
    {
        return Err(invalid("not a version ID"));
    }
    let last_modified = match header(headers, "source-mtime") {
        None | Some("") => None,
        Some(text) => Some(rfc3339(text).ok_or_else(|| invalid("not an RFC 3339 time"))?),
    };
    let etag = match header(headers, "source-etag") {
        None | Some("") => None,
        Some(etag) => {
            let etag = etag.trim_matches('"');
            if etag.is_empty() || !etag.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return Err(invalid("not an ETag"));
            }
            Some(etag.to_owned())
        }
    };
    let delete_marker = header(headers, "source-deletemarker").is_some_and(|v| v == "true");
    Ok(Some(Inbound {
        version_id,
        last_modified,
        etag,
        delete_marker,
        check: header(headers, "source-replication-check").is_some(),
    }))
}

/// An RFC 3339 time (`2024-05-06T07:08:09.123456789Z`, or with an offset),
/// as Postgres reads one: its fraction cut to the microsecond. `None` if
/// it isn't one.
fn rfc3339(text: &str) -> Option<String> {
    let b = text.as_bytes();
    let digits = |range: std::ops::Range<usize>| {
        b.get(range.clone())
            .is_some_and(|d| d.iter().all(u8::is_ascii_digit))
    };
    let shape = digits(0..4)
        && b.get(4) == Some(&b'-')
        && digits(5..7)
        && b.get(7) == Some(&b'-')
        && digits(8..10)
        && matches!(b.get(10), Some(b'T' | b't'))
        && digits(11..13)
        && b.get(13) == Some(&b':')
        && digits(14..16)
        && b.get(16) == Some(&b':')
        && digits(17..19);
    if !shape {
        return None;
    }
    let mut rest = &text[19..];
    let mut fraction = "";
    if let Some(after) = rest.strip_prefix('.') {
        let end = after
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(after.len());
        if end == 0 {
            return None;
        }
        fraction = &after[..end.min(6)];
        rest = &after[end..];
    }
    let zone = match rest {
        "Z" | "z" => "Z".to_owned(),
        _ => {
            let z = rest.as_bytes();
            let ok = z.len() == 6
                && matches!(z[0], b'+' | b'-')
                && z[1..3].iter().all(u8::is_ascii_digit)
                && z[3] == b':'
                && z[4..6].iter().all(u8::is_ascii_digit);
            if !ok {
                return None;
            }
            rest.to_owned()
        }
    };
    let (month, day): (u32, u32) = (text[5..7].parse().ok()?, text[8..10].parse().ok()?);
    let (hour, minute, second): (u32, u32, u32) = (
        text[11..13].parse().ok()?,
        text[14..16].parse().ok()?,
        text[17..19].parse().ok()?,
    );
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let fraction = match fraction {
        "" => String::new(),
        f => format!(".{f}"),
    };
    Some(format!("{}T{}{fraction}{zone}", &text[..10], &text[11..19]))
}

/// Makes `operation` replication's (see the module's docs): its writes'
/// actions `s3:ReplicateObject`, `s3:ReplicateTags` and
/// `s3:ReplicateDelete`.
pub fn authorize(operation: &mut Operation) {
    let writes = matches!(
        operation.name,
        "PutObject"
            | "CopyObject"
            | "CreateMultipartUpload"
            | "UploadPart"
            | "CompleteMultipartUpload"
            | "DeleteObject"
    );
    if !writes {
        return;
    }
    let mut checks: Vec<Check> = Vec::new();
    for check in operation.checks.drain(..) {
        let action = match check.action {
            "s3:PutObject"
            | "s3:PutObjectRetention"
            | "s3:PutObjectLegalHold"
            | "s3:PutObjectAcl" => "s3:ReplicateObject",
            "s3:PutObjectTagging" => "s3:ReplicateTags",
            "s3:DeleteObject" | "s3:DeleteObjectVersion" => "s3:ReplicateDelete",
            // A copy's source is read as any copy's.
            other => other,
        };
        if !checks
            .iter()
            .any(|c| c.action == action && c.on == check.on)
        {
            checks.push(Check {
                action,
                on: check.on,
            });
        }
    }
    operation.checks = checks;
}

/// MinIO's answer to its check of a target's permissions, which it
/// expects of a target that would let it replicate.
fn checked() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::BAD_REQUEST,
        "ReplicationPermissionCheck",
        "X-Minio-Source-Replication-Check cannot be specified in request. Request cannot be completed",
    )
}

/// What `prepare` decided.
pub enum Prepared {
    /// The request is answered so, without going further.
    Answer(Response<Full<Bytes>>),
    /// The request goes on as it would, as a replica (the task's writes
    /// are, see `notifications::set_replica`); naming the version
    /// `version_id` instead of the query's, if it's `Some`.
    Proceed { version_id: Option<Option<String>> },
}

/// Readies the authorized replication request `inbound`, operation
/// `name` on `key` of `bucket`, to go on as a replica's; `query` and
/// `headers` are the request's.
pub async fn prepare(
    app: &std::sync::Arc<App>,
    bucket: &str,
    key: &str,
    name: &str,
    inbound: &Inbound,
    query: &str,
    headers: &HeaderMap,
) -> anyhow::Result<Prepared> {
    let proceed = Prepared::Proceed { version_id: None };
    if inbound.check {
        return Ok(match name {
            "PutObject" | "CopyObject" | "CreateMultipartUpload" | "DeleteObject" => {
                Prepared::Answer(checked())
            }
            _ => proceed,
        });
    }
    let replica = |version_id: &str, etag: Option<&str>| {
        crate::notifications::set_replica(version_id, inbound.last_modified.as_deref(), etag, None);
    };
    match name {
        "PutObject" | "CreateMultipartUpload" | "CopyObject" => {
            let Some(version_id) = &inbound.version_id else {
                // Not a replica of a version: a write as any other.
                return Ok(proceed);
            };
            if let Some(refused) = refuse_version(app, bucket, version_id).await? {
                return Ok(Prepared::Answer(refused));
            }
            if name == "CopyObject"
                && let Some(answer) =
                    copy_onto_itself(app, bucket, key, version_id, headers).await?
            {
                return Ok(Prepared::Answer(answer));
            }
            if name == "PutObject"
                && let Some(etag) = existing(app, bucket, key, version_id).await?.flatten()
            {
                // There already: as it was written.
                return Ok(Prepared::Answer(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("etag", format!("\"{etag}\""))
                        .header("x-amz-version-id", version_id.as_str())
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                ));
            }
            replica(version_id, inbound.etag.as_deref());
            Ok(proceed)
        }
        "CompleteMultipartUpload" => {
            // The version ID its upload was started with, if it was.
            let Some(upload_id) =
                query_param(query, "uploadId").and_then(|id| uuid::Uuid::parse_str(&id).ok())
            else {
                return Ok(proceed);
            };
            let row = app
                .pool
                .get()
                .await?
                .query_opt_cached(
                    "SELECT replica_version_id FROM multipart_uploads WHERE upload_id = $1 AND bucket = $2 AND key = $3",
                    &[&upload_id, &bucket, &key],
                )
                .await?;
            if let Some(version_id) = row.and_then(|r| r.get::<_, Option<String>>(0)) {
                replica(&version_id, inbound.etag.as_deref());
            }
            Ok(proceed)
        }
        "DeleteObject" => {
            let Some(version_id) = &inbound.version_id else {
                return Ok(proceed);
            };
            if inbound.delete_marker {
                if let Some(refused) = refuse_version(app, bucket, version_id).await? {
                    return Ok(Prepared::Answer(refused));
                }
                if existing(app, bucket, key, version_id).await?.is_some() {
                    return Ok(Prepared::Answer(
                        Response::builder()
                            .status(StatusCode::NO_CONTENT)
                            .header("x-amz-delete-marker", "true")
                            .header("x-amz-version-id", version_id.as_str())
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    ));
                }
                replica(version_id, None);
                // A marker, of the ID given (see `cairn_delete_key`).
                return Ok(Prepared::Proceed {
                    version_id: Some(None),
                });
            }
            // The deletion of a version, which isn't replicated again.
            replica(version_id, None);
            Ok(Prepared::Proceed {
                version_id: Some(Some(resolve(app, bucket, key, version_id).await?)),
            })
        }
        _ => Ok(proceed),
    }
}

/// Why a replica of version `version_id` can't be written into `bucket`,
/// if it can't: the bucket isn't versioned, or the version is the null
/// version, which only an unversioned source has.
async fn refuse_version(
    app: &App,
    bucket: &str,
    version_id: &str,
) -> anyhow::Result<Option<Response<Full<Bytes>>>> {
    if version_id == "null" {
        return Ok(Some(format_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "A null version can't be replicated: only versions with IDs can.",
        )));
    }
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached("SELECT versioning FROM buckets WHERE name = $1", &[&bucket])
        .await?;
    Ok(match row {
        None => Some(format_s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
        )),
        Some(row) if row.get::<_, &str>(0) != "enabled" => Some(format_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "Versioning must be 'Enabled' on the bucket to take replicas.",
        )),
        Some(_) => None,
    })
}

/// Whether version `version_id` of `key` is there: `Some` if it is, with
/// its stored ETag (`None` for a delete marker).
async fn existing(
    app: &App,
    bucket: &str,
    key: &str,
    version_id: &str,
) -> anyhow::Result<Option<Option<String>>> {
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached(
            "SELECT etag FROM objects WHERE bucket = $1 AND key = $2 AND version_id = $3",
            &[&bucket, &key, &version_id],
        )
        .await?;
    Ok(row.map(|r| r.get(0)))
}

/// The version of `key` that `version_id` names: that ID's, if there's
/// one, or else, for a UUID, the version known by it (see
/// `s3::versions::uuid_form`), if there's one; else `version_id`.
async fn resolve(app: &App, bucket: &str, key: &str, version_id: &str) -> anyhow::Result<String> {
    if !is_uuid(version_id) || existing(app, bucket, key, version_id).await?.is_some() {
        return Ok(version_id.to_owned());
    }
    let rows = app
        .pool
        .get()
        .await?
        .query_cached(
            "SELECT version_id FROM objects WHERE bucket = $1 AND key = $2",
            &[&bucket, &key],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| r.get::<_, String>(0))
        .find(|id| matches_uuid(id, version_id))
        .unwrap_or_else(|| version_id.to_owned()))
}

/// A CopyObject of version `version_id` of `key` onto itself, as MinIO
/// replicates changes to a version's tags and Object Lock: sets the
/// version's (as `resolve` finds it) to the request's, and answers as a
/// copy does. `None` if the request isn't one.
async fn copy_onto_itself(
    app: &std::sync::Arc<App>,
    bucket: &str,
    key: &str,
    version_id: &str,
    headers: &HeaderMap,
) -> anyhow::Result<Option<Response<Full<Bytes>>>> {
    use crate::s3::object_lock::{Change, Lock, Outcome as LockOutcome, change_lock};
    use crate::s3::objects::tagging::{Outcome, Tagging, set_tags};
    let Some((source_bucket, source_key, source_version)) = headers
        .get("x-amz-copy-source")
        .and_then(|v| v.to_str().ok())
        .and_then(crate::s3::objects::copy::parse_copy_source)
    else {
        return Ok(None);
    };
    if source_bucket != bucket || source_key != key {
        return Ok(None);
    }
    let named = source_version.as_deref().unwrap_or(version_id);
    let target = resolve(app, bucket, key, named).await?;
    if existing(app, bucket, key, &target)
        .await?
        .flatten()
        .is_none()
    {
        return Ok(Some(format_s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchVersion",
            "The specified version does not exist.",
        )));
    }
    let refused = |what: &str| {
        Some(format_s3_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "SlowDown",
            &format!("The replica's {what} couldn't be changed; try again."),
        ))
    };
    let replaces_tags = headers
        .get("x-amz-tagging-directive")
        .is_some_and(|v| v.as_bytes() == b"REPLACE");
    if replaces_tags {
        let value = headers
            .get(crate::s3::tags::HEADER)
            .map(|v| v.as_bytes())
            .unwrap_or_default();
        let tags = match crate::s3::tags::Tags::from_header(value) {
            Ok(tags) => tags,
            Err(refused) => return Ok(Some(refused)),
        };
        let tagging = if tags.is_empty() {
            Tagging::Delete
        } else {
            Tagging::Put
        };
        match set_tags(app, bucket, key, Some(&target), &tags, tagging).await? {
            Outcome::Tagged(_) => {}
            Outcome::Contended => return Ok(refused("tags")),
            _ => {
                return Ok(Some(format_s3_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchVersion",
                    "The specified version does not exist.",
                )));
            }
        }
    }
    let lock = match Lock::from_headers(headers) {
        Ok(lock) => lock,
        Err(refused) => return Ok(Some(refused)),
    };
    let mut changes = Vec::new();
    let says_retention = headers.contains_key(crate::s3::object_lock::MODE)
        || headers.contains_key(crate::s3::object_lock::RETAIN_UNTIL);
    if says_retention {
        changes.push(Change::Retention {
            retention: lock.retention,
            bypass: true,
        });
    }
    if headers.contains_key(crate::s3::object_lock::LEGAL_HOLD) {
        changes.push(Change::LegalHold(lock.legal_hold.unwrap_or(false)));
    }
    for change in changes {
        match change_lock(app, bucket, key, Some(&target), change).await? {
            // Taken as it is: a bucket without Object Lock has none to
            // set, and a retention that can't be shortened stays.
            LockOutcome::Set | LockOutcome::Locked | LockOutcome::NoObjectLock => {}
            LockOutcome::Contended => return Ok(refused("Object Lock")),
            _ => {
                return Ok(Some(format_s3_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchVersion",
                    "The specified version does not exist.",
                )));
            }
        }
    }
    let row = app
        .pool
        .get()
        .await?
        .query_one_cached(
            "SELECT etag, to_char(last_modified AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')
             FROM objects WHERE bucket = $1 AND key = $2 AND version_id = $3",
            &[&bucket, &key, &target],
        )
        .await?;
    let (etag, modified): (Option<String>, String) = (row.get(0), row.get(1));
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <CopyObjectResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <LastModified>{modified}</LastModified><ETag>&quot;{}&quot;</ETag></CopyObjectResult>",
        etag.unwrap_or_default()
    );
    let mut response = crate::s3::util::xml_ok(body);
    if let Ok(value) = target.parse() {
        response.headers_mut().insert("x-amz-version-id", value);
    }
    Ok(Some(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        headers
    }

    #[test]
    fn times_are_read_as_rfc_3339() {
        assert_eq!(
            rfc3339("2024-05-06T07:08:09.123456789Z").as_deref(),
            Some("2024-05-06T07:08:09.123456Z")
        );
        assert_eq!(
            rfc3339("2024-05-06T07:08:09Z").as_deref(),
            Some("2024-05-06T07:08:09Z")
        );
        assert_eq!(
            rfc3339("2024-05-06T07:08:09.5+02:00").as_deref(),
            Some("2024-05-06T07:08:09.5+02:00")
        );
        for bad in [
            "",
            "2024-05-06",
            "2024-05-06 07:08:09Z",
            "2024-13-06T07:08:09Z",
            "2024-05-06T07:08:09.Z",
            "2024-05-06T07:08:09+0200",
            "2024-05-06T07:08:09Z'; --",
        ] {
            assert_eq!(rfc3339(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn minio_and_rustfs_requests_are_read() {
        assert_eq!(parse(&headers(&[]), "versionId=x").unwrap(), None);
        let minio = parse(
            &headers(&[
                ("x-minio-source-replication-request", "true"),
                ("x-minio-source-mtime", "2024-05-06T07:08:09.123Z"),
                ("x-minio-source-etag", "abc-2"),
                ("x-amz-replication-status", "REPLICA"),
            ]),
            "versionId=0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b",
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            minio.version_id.as_deref(),
            Some("0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b")
        );
        assert_eq!(
            minio.last_modified.as_deref(),
            Some("2024-05-06T07:08:09.123Z")
        );
        assert_eq!(minio.etag.as_deref(), Some("abc-2"));
        assert!(!minio.delete_marker && !minio.check);
        // RustFS names the version in a header, and its own come first.
        let rustfs = parse(
            &headers(&[
                ("x-rustfs-source-replication-request", "true"),
                (
                    "x-rustfs-source-version-id",
                    "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b",
                ),
                ("x-rustfs-source-deletemarker", "true"),
                ("x-minio-source-deletemarker", "false"),
            ]),
            "",
        )
        .unwrap()
        .unwrap();
        assert!(rustfs.version_id.is_some() && rustfs.delete_marker);
        // Malformed IDs and times are refused.
        let replica = [("x-amz-replication-status", "REPLICA")];
        assert!(parse(&headers(&replica), "versionId=..%2F").is_err());
        let bad_time = [
            ("x-amz-replication-status", "REPLICA"),
            ("x-minio-source-mtime", "yesterday"),
        ];
        assert!(parse(&headers(&bad_time), "").is_err());
    }

    #[test]
    fn writes_are_authorized_as_replication() {
        use crate::s3::actions::On;
        let on = || On::Object("b".to_owned(), "k".to_owned());
        let mut put = Operation {
            name: "PutObject",
            checks: vec![
                Check {
                    action: "s3:PutObject",
                    on: on(),
                },
                Check {
                    action: "s3:PutObjectTagging",
                    on: on(),
                },
                Check {
                    action: "s3:PutObjectRetention",
                    on: on(),
                },
            ],
        };
        authorize(&mut put);
        let actions: Vec<_> = put.checks.iter().map(|c| c.action).collect();
        assert_eq!(actions, ["s3:ReplicateObject", "s3:ReplicateTags"]);
        let mut delete = Operation {
            name: "DeleteObject",
            checks: vec![Check {
                action: "s3:DeleteObjectVersion",
                on: on(),
            }],
        };
        authorize(&mut delete);
        assert_eq!(delete.checks[0].action, "s3:ReplicateDelete");
        let mut get = Operation {
            name: "GetObject",
            checks: vec![Check {
                action: "s3:GetObject",
                on: on(),
            }],
        };
        authorize(&mut get);
        assert_eq!(get.checks[0].action, "s3:GetObject");
    }
}
