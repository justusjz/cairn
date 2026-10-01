use std::sync::Arc;

use deadpool_postgres::Object;
use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use tokio_postgres::{IsolationLevel, error::SqlState};

use crate::{
    App, ReapTarget,
    auth::BodyChecksum,
    reap_parts, reap_targets,
    s3::util::{format_s3_error, xml_escape, xml_ok},
};

/// Bounded retry for the serializable delete, mirroring the commit paths.
const MAX_DELETE_ATTEMPTS: usize = 10;

enum DeleteStatus {
    Deleted,
    NoSuchBucket,
    Unavailable,
}

/// One serializable attempt: confirm the bucket exists, capture the removed
/// parts' replica locations (for immediate reaping), then drop the keys' `null`
/// versions (cascading their parts/part_locations away). That is a complete
/// delete in an unversioned bucket, the only kind there is so far: such a bucket
/// holds nothing but `null` versions. The raw postgres error is
/// returned so the caller can retry on a serialization failure. Runs at the same
/// isolation as the put/complete/GC transactions that also touch `objects`/
/// `parts`, so the delete can't undermine their guarantees — and the bucket
/// check shares the snapshot, so there's no check-then-delete race.
async fn try_delete(
    client: &mut Object,
    bucket: &str,
    keys: &[&str],
) -> Result<(DeleteStatus, Vec<ReapTarget>), tokio_postgres::Error> {
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()
        .await?;
    if tx
        .query_opt("SELECT 1 FROM buckets WHERE name = $1", &[&bucket])
        .await?
        .is_none()
    {
        return Ok((DeleteStatus::NoSuchBucket, Vec::new())); // tx rolls back on drop
    }
    let removed = tx
        .query(
            "SELECT pl.part_id, pl.node_id, n.peer_url
             FROM objects o
             JOIN parts p ON p.object_id = o.id
             JOIN part_locations pl ON pl.part_id = p.part_id
             JOIN nodes n ON n.node_id = pl.node_id
             WHERE o.bucket = $1 AND o.key = ANY($2) AND o.version_id = 'null'",
            &[&bucket, &keys],
        )
        .await?;
    let targets = reap_targets(&removed);
    tx.execute(
        "DELETE FROM objects WHERE bucket = $1 AND key = ANY($2) AND version_id = 'null'",
        &[&bucket, &keys],
    )
    .await?;
    tx.commit().await?;
    Ok((DeleteStatus::Deleted, targets))
}

/// Deletes `keys` from `bucket` in a serializable transaction, retrying on a
/// serialization conflict (e.g. a concurrent overwrite or GC). On success, reaps
/// the removed parts' files in the background.
async fn delete_keys(app: &Arc<App>, bucket: &str, keys: &[&str]) -> anyhow::Result<DeleteStatus> {
    let mut client = app.pool.get().await?;
    for _ in 0..MAX_DELETE_ATTEMPTS {
        match try_delete(&mut client, bucket, keys).await {
            Ok((DeleteStatus::Deleted, targets)) => {
                reap_parts(app, targets);
                return Ok(DeleteStatus::Deleted);
            }
            Ok((status, _)) => return Ok(status),
            Err(e) if e.code() == Some(&SqlState::T_R_SERIALIZATION_FAILURE) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(DeleteStatus::Unavailable)
}

pub async fn delete_object(
    app: &Arc<App>,
    bucket: &str,
    key: &str,
) -> anyhow::Result<Response<Full<Bytes>>> {
    // Idempotent: deleting a key that isn't there still returns 204, per S3.
    match delete_keys(app, bucket, &[key]).await? {
        DeleteStatus::Deleted => Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Full::new(Bytes::new()))
            .unwrap()),
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

/// Parses a DeleteObjects body into the keys to delete and the Quiet flag.
/// Namespace-agnostic like the other parsers; returns None on malformed XML.
fn parse_delete_request(body: &str) -> Option<(Vec<String>, bool)> {
    let doc = roxmltree::Document::parse(body).ok()?;
    let mut keys = Vec::new();
    for obj in doc.descendants().filter(|n| n.tag_name().name() == "Object") {
        let key = obj
            .children()
            .find(|n| n.tag_name().name() == "Key")
            .and_then(|n| n.text())?
            .to_owned();
        keys.push(key);
    }
    // Quiet mode (default false): suppress the per-key <Deleted> entries, leaving
    // only <Error>s in the response.
    let quiet = doc
        .descendants()
        .find(|n| n.tag_name().name() == "Quiet")
        .and_then(|n| n.text())
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("true"));
    Some((keys, quiet))
}

/// DeleteObjects (batch): `POST /{bucket}?delete` with a `<Delete>` body listing
/// keys. `checksum` is the request's body-integrity headers.
pub async fn delete_objects(
    app: &Arc<App>,
    bucket: &str,
    body: Bytes,
    checksum: BodyChecksum,
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
    let (keys, quiet) = match parse_delete_request(body_str) {
        Some((keys, quiet)) if !keys.is_empty() => (keys, quiet),
        _ => {
            return Ok(format_s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "could not parse the delete request",
            ));
        }
    };
    if keys.len() > MAX_DELETE_KEYS {
        return Ok(format_s3_error(
            StatusCode::BAD_REQUEST,
            "MalformedXML",
            "a delete request may contain at most 1000 keys",
        ));
    }

    // One serializable statement removes every requested key. Absent keys are
    // no-ops, so — like the single-key delete — every requested key is reported
    // deleted (delete is idempotent; there are no per-key failure modes here).
    let key_refs: Vec<&str> = keys.iter().map(String::as_str).collect();
    match delete_keys(app, bucket, &key_refs).await? {
        DeleteStatus::Deleted => {}
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
    }

    let mut out = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    if !quiet {
        for key in &keys {
            out.push_str(&format!("<Deleted><Key>{}</Key></Deleted>", xml_escape(key)));
        }
    }
    out.push_str("</DeleteResult>");
    Ok(xml_ok(out))
}
