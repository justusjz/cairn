use std::sync::Arc;

use deadpool_postgres::Object;
use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::db::Cached;
use crate::{
    App,
    blobs::{ReapTarget, reap_blobs, reap_columns},
    db,
    s3::util::{
        format_s3_error, slow_down, with_delete_marker, with_version_id, xml_escape, xml_ok,
    },
    s3::versions::{Deleted, is_version_id, new_version_id},
};

/// What a delete addresses: a key, and optionally one specific version of it.
struct Target {
    key: String,
    version_id: Option<String>,
    /// Whether it may bypass a GOVERNANCE retention (see `s3::object_lock`).
    bypass: bool,
}

enum DeleteStatus {
    /// One outcome per target, in order: `None` for a version Object Lock
    /// keeps.
    Deleted(Vec<Option<Deleted>>),
    NoSuchBucket,
    /// It kept conflicting with concurrent requests.
    Contended,
}

/// One attempt (`cairn_delete_objects`): read the bucket's versioning state
/// (which doubles as the existence check), then delete each target the way
/// that state dictates, capturing the freed blobs' replica locations for
/// immediate reaping. It follows the same lock protocol as the writes that also
/// touch `objects`/`parts` (see `catalog.sql`), so the delete can't undermine
/// their guarantees. The raw postgres error is returned so the caller can retry
/// on a conflict.
async fn try_delete(
    client: &mut Object,
    bucket: &str,
    targets: &[Target],
) -> Result<(DeleteStatus, Vec<ReapTarget>), tokio_postgres::Error> {
    let keys: Vec<&str> = targets.iter().map(|t| t.key.as_str()).collect();
    let version_ids: Vec<Option<&str>> = targets.iter().map(|t| t.version_id.as_deref()).collect();
    // A fresh version ID for each target, should it need a delete marker.
    let marker_ids: Vec<String> = targets.iter().map(|_| new_version_id()).collect();
    let bypass: Vec<bool> = targets.iter().map(|t| t.bypass).collect();
    let row = client
        .query_one_cached(
            "SELECT status, version_ids, delete_markers, locked, reap_blob, reap_node, reap_peer
             FROM pg_temp.cairn_delete_objects($1, $2, $3, $4, $5)",
            &[&bucket, &keys, &version_ids, &marker_ids, &bypass],
        )
        .await?;
    match row.get::<_, &str>(0) {
        "deleted" => {}
        // The function changed nothing.
        "no_such_bucket" => return Ok((DeleteStatus::NoSuchBucket, Vec::new())),
        status => unreachable!("cairn_delete_objects: unknown status {status}"),
    }
    let version_ids: Vec<Option<String>> = row.get(1);
    let delete_markers: Vec<bool> = row.get(2);
    let locked: Vec<bool> = row.get(3);
    let outcomes = version_ids
        .into_iter()
        .zip(delete_markers)
        .zip(locked)
        .map(|((version_id, delete_marker), locked)| (!locked).then_some(Deleted { version_id, delete_marker }))
        .collect();
    let reap = reap_columns(&row, 4);
    Ok((DeleteStatus::Deleted(outcomes), reap))
}

/// Deletes `targets` from `bucket` in one transaction, retrying on a conflict
/// (a deadlock, say). On success, reaps
/// the freed blobs' files in the background.
async fn delete_targets(
    app: &Arc<App>,
    bucket: &str,
    targets: &[Target],
) -> anyhow::Result<DeleteStatus> {
    let mut client = app.pool.get().await?;
    for attempt in 0..db::MAX_TX_ATTEMPTS {
        db::backoff(attempt).await;
        match try_delete(&mut client, bucket, targets).await {
            Ok((status, reap)) => {
                reap_blobs(app, reap);
                return Ok(status);
            }
            Err(e) if db::is_conflict(&e) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(DeleteStatus::Contended)
}

/// DeleteObject: `DELETE /{bucket}/{key}`, optionally `?versionId=V` to remove one
/// version for good. Reports the version concerned (the removed one, or the delete
/// marker just created) in `x-amz-version-id` / `x-amz-delete-marker`. A
/// version that Object Lock keeps is S3's 403, unless it's in GOVERNANCE
/// mode and the request may bypass that (`bypass`).
pub async fn delete_object(
    app: &Arc<App>,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    bypass: bool,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let target = Target {
        key: key.to_owned(),
        version_id: version_id.map(str::to_owned),
        bypass,
    };
    // Idempotent: deleting a key or version that isn't there still returns 204,
    // per S3.
    match delete_targets(app, bucket, &[target]).await? {
        DeleteStatus::Deleted(outcomes) => {
            let Some(deleted) = &outcomes[0] else { return Ok(crate::s3::object_lock::locked()) };
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
        DeleteStatus::Contended => Ok(slow_down()),
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
            bypass: false,
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
/// keys, each optionally with a version ID. The body has been checked against
/// its integrity headers (see `Payload`), of which S3 requires one here
/// ([`missing_checksum`]). Authorization is per entry, as in S3: whether
/// `allowed` the entry's key, and whether it names a version
/// (`s3:DeleteObjectVersion`, else `s3:DeleteObject`); a denied entry is
/// reported as an AccessDenied `<Error>` and the rest still proceed. So is a
/// version that Object Lock keeps, unless it's in GOVERNANCE mode and
/// `bypass` its key (the request asks to, and may).
/// The error for a DeleteObjects without an integrity header. The body *is*
/// the list of things to destroy, so S3 requires one: Content-MD5 (minio-go)
/// or an x-amz-checksum-* (aws-cli).
pub fn missing_checksum() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::BAD_REQUEST,
        "InvalidRequest",
        "Missing required header for this request: Content-MD5 OR x-amz-checksum-*",
    )
}

pub async fn delete_objects(
    app: &Arc<App>,
    bucket: &str,
    body: Bytes,
    allowed: &(dyn Fn(&str, bool) -> bool + Sync),
    bypass: &(dyn Fn(&str) -> bool + Sync),
) -> anyhow::Result<Response<Full<Bytes>>> {
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

    // One transaction deletes every permitted target. Absent keys and
    // versions are no-ops, so — like the single-key delete — every permitted
    // target is reported deleted (delete is idempotent). A version ID that
    // can't be one names no version, which S3 reports as such.
    let (malformed, targets): (Vec<Target>, Vec<Target>) = targets
        .into_iter()
        .partition(|t| t.version_id.as_deref().is_some_and(|v| !is_version_id(v)));
    let (mut permitted, denied): (Vec<Target>, Vec<Target>) =
        targets.into_iter().partition(|t| allowed(&t.key, t.version_id.is_some()));
    for target in &mut permitted {
        target.bypass = target.version_id.is_some() && bypass(&target.key);
    }
    let outcomes = match delete_targets(app, bucket, &permitted).await? {
        DeleteStatus::Deleted(outcomes) => outcomes,
        DeleteStatus::NoSuchBucket => {
            return Ok(format_s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchBucket",
                "the specified bucket does not exist",
            ));
        }
        DeleteStatus::Contended => return Ok(slow_down()),
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
            let Some(deleted) = deleted else { continue };
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
    for (t, _) in permitted.iter().zip(&outcomes).filter(|(_, deleted)| deleted.is_none()) {
        out.push_str(&crate::s3::object_lock::locked_error(&t.key, t.version_id.as_deref()));
    }
    let errors = denied
        .iter()
        .map(|t| (t, "AccessDenied", "Access Denied"))
        .chain(malformed.iter().map(|t| (t, "NoSuchVersion", "The specified version does not exist.")));
    for (t, code, message) in errors {
        out.push_str("<Error>");
        out.push_str(&format!("<Key>{}</Key>", xml_escape(&t.key)));
        if let Some(v) = &t.version_id {
            out.push_str(&format!("<VersionId>{}</VersionId>", xml_escape(v)));
        }
        out.push_str(&format!("<Code>{code}</Code><Message>{message}</Message></Error>"));
    }
    out.push_str("</DeleteResult>");
    Ok(xml_ok(out))
}
