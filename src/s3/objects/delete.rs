use std::sync::Arc;

use deadpool_postgres::Object;
use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use tokio_postgres::{IsolationLevel, error::SqlState};

use crate::{
    App, ReapTarget,
    auth::BodyChecksum,
    reap_parts,
    s3::util::{format_s3_error, with_delete_marker, with_version_id, xml_escape, xml_ok},
    s3::versions::{Deleted, bucket_versioning, delete_key},
};

/// Bounded retry for the serializable delete, mirroring the commit paths.
const MAX_DELETE_ATTEMPTS: usize = 10;

/// What a delete addresses: a key, and optionally one specific version of it.
struct Target {
    key: String,
    version_id: Option<String>,
}

enum DeleteStatus {
    /// One outcome per target, in order.
    Deleted(Vec<Deleted>),
    NoSuchBucket,
    Unavailable,
}

/// One serializable attempt: read the bucket's versioning state (which doubles
/// as the existence check), then delete each target the way that state dictates,
/// capturing the removed parts' replica locations for immediate reaping. The raw
/// postgres error is returned so the caller can retry on a serialization failure.
/// Runs at the same isolation as the put/complete/GC transactions that also touch
/// `objects`/`parts`, so the delete can't undermine their guarantees — and the
/// bucket check shares the snapshot, so there's no check-then-delete race.
async fn try_delete(
    client: &mut Object,
    bucket: &str,
    targets: &[Target],
) -> Result<(DeleteStatus, Vec<ReapTarget>), tokio_postgres::Error> {
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()
        .await?;
    let Some(versioning) = bucket_versioning(&tx, bucket).await? else {
        return Ok((DeleteStatus::NoSuchBucket, Vec::new())); // tx rolls back on drop
    };
    let mut reap = Vec::new();
    let mut outcomes = Vec::with_capacity(targets.len());
    for t in targets {
        let version_id = t.version_id.as_deref();
        outcomes.push(delete_key(&tx, bucket, &t.key, versioning, version_id, &mut reap).await?);
    }
    tx.commit().await?;
    Ok((DeleteStatus::Deleted(outcomes), reap))
}

/// Deletes `targets` from `bucket` in a serializable transaction, retrying on a
/// serialization conflict (e.g. a concurrent overwrite or GC). On success, reaps
/// the removed parts' files in the background.
async fn delete_targets(
    app: &Arc<App>,
    bucket: &str,
    targets: &[Target],
) -> anyhow::Result<DeleteStatus> {
    let mut client = app.pool.get().await?;
    for _ in 0..MAX_DELETE_ATTEMPTS {
        match try_delete(&mut client, bucket, targets).await {
            Ok((status, reap)) => {
                reap_parts(app, reap);
                return Ok(status);
            }
            Err(e) if e.code() == Some(&SqlState::T_R_SERIALIZATION_FAILURE) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(DeleteStatus::Unavailable)
}

/// DeleteObject: `DELETE /{bucket}/{key}`, optionally `?versionId=V` to remove one
/// version for good. Reports the version concerned (the removed one, or the delete
/// marker just created) in `x-amz-version-id` / `x-amz-delete-marker`.
pub async fn delete_object(
    app: &Arc<App>,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let target = Target {
        key: key.to_owned(),
        version_id: version_id.map(str::to_owned),
    };
    // Idempotent: deleting a key or version that isn't there still returns 204,
    // per S3.
    match delete_targets(app, bucket, &[target]).await? {
        DeleteStatus::Deleted(outcomes) => {
            let deleted = &outcomes[0];
            let resp = Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Full::new(Bytes::new()))
                .unwrap();
            let resp = with_version_id(resp, deleted.version_id.as_deref());
            Ok(if deleted.delete_marker {
                with_delete_marker(resp)
            } else {
                resp
            })
        }
        DeleteStatus::NoSuchBucket => Ok(format_s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "the specified bucket does not exist",
        )),
        DeleteStatus::Unavailable => Ok(format_s3_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            "delete aborted after serialization retries",
        )),
    }
}

/// S3 caps a batch delete at 1000 keys per request.
const MAX_DELETE_KEYS: usize = 1000;

/// Parses a DeleteObjects body into the targets to delete (each a key with an
/// optional version ID) and the Quiet flag. Namespace-agnostic like the other
/// parsers; returns None on malformed XML.
fn parse_delete_request(body: &str) -> Option<(Vec<Target>, bool)> {
    let doc = roxmltree::Document::parse(body).ok()?;
    let mut targets = Vec::new();
    for obj in doc.descendants().filter(|n| n.tag_name().name() == "Object") {
        let child = |name| {
            obj.children()
                .find(|n| n.tag_name().name() == name)
                .and_then(|n| n.text())
        };
        targets.push(Target {
            key: child("Key")?.to_owned(),
            version_id: child("VersionId").map(str::to_owned),
        });
    }
    // Quiet mode (default false): suppress the per-key <Deleted> entries, leaving
    // only <Error>s in the response.
    let quiet = doc
        .descendants()
        .find(|n| n.tag_name().name() == "Quiet")
        .and_then(|n| n.text())
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("true"));
    Some((targets, quiet))
}

/// DeleteObjects (batch): `POST /{bucket}?delete` with a `<Delete>` body listing
/// keys, each optionally with a version ID. `checksum` is the request's
/// body-integrity headers. Authorization is per entry, as in S3: an entry naming
/// a version needs `may_delete_versions`, any other needs `may_write`; a denied
/// entry is reported as an AccessDenied `<Error>` and the rest still proceed.
pub async fn delete_objects(
    app: &Arc<App>,
    bucket: &str,
    body: Bytes,
    checksum: BodyChecksum,
    may_write: bool,
    may_delete_versions: bool,
) -> anyhow::Result<Response<Full<Bytes>>> {
    // Integrity first: this operation is destructive and the body *is* the list of
    // things to destroy, so a corrupted body must never delete the wrong objects.
    // S3 requires an integrity header here — Content-MD5 (minio-go) or an
    // x-amz-checksum-* (aws-cli). Require at least one and verify it.
    if !checksum.is_present() {
        return Ok(format_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "missing required integrity header: Content-MD5 or x-amz-checksum-*",
        ));
    }
    if !checksum.matches(&body) {
        return Ok(format_s3_error(
            StatusCode::BAD_REQUEST,
            "BadDigest",
            "the integrity checksum you specified did not match what we received",
        ));
    }

    let Ok(body_str) = std::str::from_utf8(&body) else {
        return Ok(format_s3_error(
            StatusCode::BAD_REQUEST,
            "MalformedXML",
            "request body is not valid UTF-8",
        ));
    };
    let (targets, quiet) = match parse_delete_request(body_str) {
        Some((targets, quiet)) if !targets.is_empty() => (targets, quiet),
        _ => {
            return Ok(format_s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "could not parse the delete request",
            ));
        }
    };
    if targets.len() > MAX_DELETE_KEYS {
        return Ok(format_s3_error(
            StatusCode::BAD_REQUEST,
            "MalformedXML",
            "a delete request may contain at most 1000 keys",
        ));
    }

    // One serializable transaction deletes every permitted target. Absent keys and
    // versions are no-ops, so — like the single-key delete — every permitted
    // target is reported deleted (delete is idempotent).
    let (permitted, denied): (Vec<Target>, Vec<Target>) =
        targets.into_iter().partition(|t| match t.version_id {
            Some(_) => may_delete_versions,
            None => may_write,
        });
    let outcomes = match delete_targets(app, bucket, &permitted).await? {
        DeleteStatus::Deleted(outcomes) => outcomes,
        DeleteStatus::NoSuchBucket => {
            return Ok(format_s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchBucket",
                "the specified bucket does not exist",
            ));
        }
        DeleteStatus::Unavailable => {
            return Ok(format_s3_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                "delete aborted after serialization retries",
            ));
        }
    };

    let mut out = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    // S3's per-entry report: the requested VersionId is echoed back, and when the
    // entry concerns a delete marker (one just created, or the one removed), so is
    // that marker's version ID.
    if !quiet {
        for (t, deleted) in permitted.iter().zip(&outcomes) {
            out.push_str("<Deleted>");
            out.push_str(&format!("<Key>{}</Key>", xml_escape(&t.key)));
            if let Some(v) = &t.version_id {
                out.push_str(&format!("<VersionId>{}</VersionId>", xml_escape(v)));
            }
            if deleted.delete_marker {
                out.push_str("<DeleteMarker>true</DeleteMarker>");
                if let Some(v) = &deleted.version_id {
                    out.push_str(&format!(
                        "<DeleteMarkerVersionId>{}</DeleteMarkerVersionId>",
                        xml_escape(v)
                    ));
                }
            }
            out.push_str("</Deleted>");
        }
    }
    // Errors are reported even in quiet mode.
    for t in &denied {
        out.push_str("<Error>");
        out.push_str(&format!("<Key>{}</Key>", xml_escape(&t.key)));
        if let Some(v) = &t.version_id {
            out.push_str(&format!("<VersionId>{}</VersionId>", xml_escape(v)));
        }
        out.push_str("<Code>AccessDenied</Code><Message>Access Denied</Message></Error>");
    }
    out.push_str("</DeleteResult>");
    Ok(xml_ok(out))
}
