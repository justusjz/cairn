use std::sync::Arc;

use deadpool_postgres::Object;
use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use tokio_postgres::IsolationLevel;

use crate::db::Cached;
use crate::{
    App,
    auth::BodyChecksum,
    blobs::{ReapTarget, reap_blobs, reap_columns},
    db,
    s3::util::{
        format_s3_error, slow_down, with_delete_marker, with_version_id, xml_escape, xml_ok,
    },
    s3::versions::{Deleted, new_version_id},
};

/// What a delete addresses: a key, and optionally one specific version of it.
struct Target {
    key: String,
    version_id: Option<String>,
}

enum DeleteStatus {
    /// One outcome per target, in order.
    Deleted(Vec<Deleted>),
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
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .start()
        .await?;
    let keys: Vec<&str> = targets.iter().map(|t| t.key.as_str()).collect();
    let version_ids: Vec<Option<&str>> = targets.iter().map(|t| t.version_id.as_deref()).collect();
    // A fresh version ID for each target, should it need a delete marker.
    let marker_ids: Vec<String> = targets.iter().map(|_| new_version_id()).collect();
    let row = tx
        .query_one_cached(
            "SELECT status, version_ids, delete_markers, reap_blob, reap_node, reap_peer
             FROM pg_temp.cairn_delete_objects($1, $2, $3, $4)",
            &[&bucket, &keys, &version_ids, &marker_ids],
        )
        .await?;
    match row.get::<_, &str>(0) {
        "deleted" => {}
        // The function changed nothing; dropping `tx` rolls it back.
        "no_such_bucket" => return Ok((DeleteStatus::NoSuchBucket, Vec::new())),
        status => unreachable!("cairn_delete_objects: unknown status {status}"),
    }
    let version_ids: Vec<Option<String>> = row.get(1);
    let delete_markers: Vec<bool> = row.get(2);
    let outcomes = version_ids
        .into_iter()
        .zip(delete_markers)
        .map(|(version_id, delete_marker)| Deleted {
            version_id,
            delete_marker,
        })
        .collect();
    let reap = reap_columns(&row, 3);
    tx.commit().await?;
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

    // One transaction deletes every permitted target. Absent keys and
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
