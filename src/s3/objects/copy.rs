use std::sync::Arc;

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use uuid::Uuid;

use crate::{
    App, AttachTarget, UploadResult,
    auth::ContentSha256,
    body::channel_body,
    s3::{
        conditional::{Precondition, Preconditions},
        objects::get::{
            parse_range, resolve_object_parts, select_parts_in_range, spawn_range_stream,
        },
        util::{decode_path_param, format_s3_error, xml_ok},
    },
};

/// The 412 response returned when a copy-source precondition isn't met.
fn copy_precondition_failed() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::PRECONDITION_FAILED,
        "PreconditionFailed",
        "the source object did not satisfy the copy conditions",
    )
}

/// CopyObject (deep copy): `PUT /{dest_bucket}/{dest_key}` with an
/// `x-amz-copy-source` header. Streams the source object's bytes into a fresh,
/// independently-replicated part and attaches it to the destination — reusing the
/// same replicate-then-commit path as a normal PUT. The copy owns its own parts,
/// so deleting either object never affects the other.
///
/// `metadata_directive` is `x-amz-metadata-directive` (COPY, the default, or
/// REPLACE). Under COPY the destination inherits the source's content-type; under
/// REPLACE it takes `request_content_type` (the request's own Content-Type).
pub async fn copy_object(
    app: &Arc<App>,
    dest_bucket: &str,
    dest_key: &str,
    copy_source: &str,
    metadata_directive: Option<&str>,
    request_content_type: &str,
    preconditions: &Preconditions,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let (src_bucket, src_key) = match parse_copy_source(copy_source) {
        Some(pair) => pair,
        None => {
            return Ok(format_s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "the x-amz-copy-source header is malformed",
            ));
        }
    };

    // COPY (the default) keeps the source metadata; only REPLACE substitutes new.
    let replace = metadata_directive
        .map(|d| d.eq_ignore_ascii_case("REPLACE"))
        .unwrap_or(false);
    // S3 rejects a copy of an object onto itself that changes nothing, guarding
    // against a client accidentally issuing a destructive no-op.
    if src_bucket == dest_bucket && src_key == dest_key && !replace {
        return Ok(format_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "this copy request is illegal because it is trying to copy an object to \
             itself without changing the object's metadata",
        ));
    }

    // Reject up front if the destination bucket is gone, so we don't replicate a
    // part only to fail the FK at commit time (as put_object does).
    let mut client = app.pool.get().await?;
    if client
        .query_opt("SELECT 1 FROM buckets WHERE name = $1", &[&dest_bucket])
        .await?
        .is_none()
    {
        return Ok(format_s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "the specified bucket does not exist",
        ));
    }

    // Read the source's content-type, its ordered parts, and each part's locations
    // in one RepeatableRead snapshot, so a concurrent overwrite of the source can't
    // tear the view (same as get_object). Freshest location first per part.
    let tx = client
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
        .start()
        .await?;
    let (src_content_type, src_etag, src_epoch): (String, String, i64) = match tx
        .query_opt(
            "SELECT content_type, etag, floor(extract(epoch FROM last_modified))::bigint
             FROM objects WHERE bucket = $1 AND key = $2",
            &[&src_bucket, &src_key],
        )
        .await?
    {
        Some(row) => (row.get(0), row.get(1), row.get(2)),
        None => {
            return Ok(format_s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                "the specified source key does not exist",
            ));
        }
    };
    // Honour x-amz-copy-source-if-* conditions on the source; any failure (a 304
    // for a read maps to 412 here) aborts the copy before any data is moved.
    if preconditions.evaluate(&src_etag, src_epoch, true) != Precondition::Proceed {
        return Ok(copy_precondition_failed());
    }
    // Resolve the source's ordered parts and their locations from the same
    // snapshot (an empty object simply has none, and streams as a zero-byte body).
    let parts = resolve_object_parts(&tx, &src_bucket, &src_key).await?;
    tx.commit().await?;
    drop(client);

    // Stream the whole source (every part, in order) through a channel-backed body:
    // a background task pulls each from a replica — locally if that's us — and
    // forwards its chunks, exactly as get_object does. That body is then fed to the
    // normal upload path, which replicates and commits it as the destination's part.
    let total: u64 = parts.iter().map(|(_, size, _)| *size).sum();
    let (sender, source_body) = channel_body();
    spawn_range_stream(app.clone(), select_parts_in_range(parts, 0, total), sender);

    let attach = AttachTarget::Object {
        bucket: dest_bucket.to_owned(),
        key: dest_key.to_owned(),
        content_type: if replace {
            request_content_type.to_owned()
        } else {
            src_content_type
        },
        // Copy conditions gate on the source (checked above); the destination
        // carries no write guard.
        conditions: Preconditions::default(),
    };
    // The source stream is trusted internal data, so it carries no content-sha256
    // claim (Unsigned) and no aws-chunked framing — only Committed is reachable.
    let etag = match crate::upload_part(
        app,
        source_body,
        &attach,
        false,
        ContentSha256::Unsigned,
        None,
    )
    .await?
    {
        UploadResult::Committed(etag) => etag,
        UploadResult::ContentSha256Mismatch
        | UploadResult::ChunkSignatureMismatch
        | UploadResult::PreconditionFailed => {
            return Ok(format_s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "the copy failed an integrity check",
            ));
        }
    };

    // CopyObject reports the result in the body (not just the ETag header): read
    // back the destination's freshly-stamped last-modified in ISO 8601.
    let client = app.pool.get().await?;
    let last_modified: String = client
        .query_one(
            "SELECT to_char(last_modified AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\".000Z\"')
             FROM objects WHERE bucket = $1 AND key = $2",
            &[&dest_bucket, &dest_key],
        )
        .await?
        .get(0);
    Ok(xml_ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <CopyObjectResult>\
         <LastModified>{last_modified}</LastModified>\
         <ETag>\"{etag}\"</ETag>\
         </CopyObjectResult>"
    )))
}

/// UploadPartCopy: `PUT /{bucket}/{key}?partNumber=N&uploadId=U` with an
/// `x-amz-copy-source` header (and optional `x-amz-copy-source-range`). Copies a
/// byte range of the source object into a part staged under the upload — the
/// large-object counterpart to CopyObject, letting a client assemble a copy out of
/// parts bigger than a single CopyObject would allow. Returns the new part's ETag.
///
/// This is the clean path for large copies: the client owns the multipart upload's
/// lifecycle and aborts it on failure, so there's no server-side state to orphan.
pub async fn copy_part(
    app: &Arc<App>,
    upload_id: &str,
    part_number: &str,
    copy_source: &str,
    copy_source_range: Option<&str>,
    preconditions: &Preconditions,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let upload_id = match Uuid::parse_str(upload_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(format_s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchUpload",
                "the specified multipart upload does not exist",
            ));
        }
    };
    let part_number: i32 = match part_number.parse() {
        Ok(n) if (1..=10_000).contains(&n) => n,
        _ => {
            return Ok(format_s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "partNumber must be an integer in 1..=10000",
            ));
        }
    };
    let (src_bucket, src_key) = match parse_copy_source(copy_source) {
        Some(pair) => pair,
        None => {
            return Ok(format_s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "the x-amz-copy-source header is malformed",
            ));
        }
    };

    // Reject up front if the upload is gone, so we don't replicate a part we'd only
    // fail to stage at commit (the FK would reject it anyway) — as put_part does.
    let mut client = app.pool.get().await?;
    if client
        .query_opt(
            "SELECT 1 FROM multipart_uploads WHERE upload_id = $1",
            &[&upload_id],
        )
        .await?
        .is_none()
    {
        return Ok(format_s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "the specified multipart upload does not exist",
        ));
    }

    // Read the source's total size, last-modified, and its ordered parts from one
    // RepeatableRead snapshot, so a concurrent overwrite can't tear the view
    // (mirrors get_object).
    let tx = client
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
        .start()
        .await?;
    let row = tx
        .query_opt(
            "SELECT size, to_char(last_modified AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\".000Z\"'),
                    etag, floor(extract(epoch FROM last_modified))::bigint
             FROM objects WHERE bucket = $1 AND key = $2",
            &[&src_bucket, &src_key],
        )
        .await?;
    let (size, last_modified, src_etag, src_epoch): (i64, String, String, i64) = match row {
        Some(row) => (row.get(0), row.get(1), row.get(2), row.get(3)),
        None => {
            return Ok(format_s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                "the specified source key does not exist",
            ));
        }
    };
    // Honour x-amz-copy-source-if-* conditions on the source before copying.
    if preconditions.evaluate(&src_etag, src_epoch, true) != Precondition::Proceed {
        return Ok(copy_precondition_failed());
    }
    let size = size as u64;
    let parts = resolve_object_parts(&tx, &src_bucket, &src_key).await?;
    tx.commit().await?;
    drop(client);

    // Resolve the copy range against the source size (absent header → whole
    // object). Reuses GET's range parser; an unsatisfiable range is a 400.
    let (start, end) = match parse_range(copy_source_range, size) {
        Ok(Some((start, end))) => (start, end),
        Ok(None) => (0, size),
        Err(()) => {
            return Ok(format_s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "the x-amz-copy-source-range is not satisfiable",
            ));
        }
    };

    // Stream the selected byte range of the source into one part staged under the
    // upload, reusing the normal replicate-then-commit path (which computes the new
    // part's ETag as it streams).
    let (sender, source_body) = channel_body();
    spawn_range_stream(app.clone(), select_parts_in_range(parts, start, end), sender);
    let attach = AttachTarget::MultipartPart {
        upload_id,
        part_number,
    };
    let etag = match crate::upload_part(
        app,
        source_body,
        &attach,
        false,
        ContentSha256::Unsigned,
        None,
    )
    .await?
    {
        UploadResult::Committed(etag) => etag,
        UploadResult::ContentSha256Mismatch
        | UploadResult::ChunkSignatureMismatch
        | UploadResult::PreconditionFailed => {
            return Ok(format_s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "the copy failed an integrity check",
            ));
        }
    };
    Ok(xml_ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <CopyPartResult>\
         <LastModified>{last_modified}</LastModified>\
         <ETag>\"{etag}\"</ETag>\
         </CopyPartResult>"
    )))
}

/// Parses an `x-amz-copy-source` value ("/bucket/key" or "bucket/key", optionally
/// with a "?versionId=…" suffix, percent-encoded) into (bucket, key). Strips a
/// leading slash and the (unsupported) version qualifier, then splits bucket/key
/// at the first slash and decodes each half — mirroring how the request path is
/// parsed. Returns None if malformed (no key separator, or an empty component).
fn parse_copy_source(copy_source: &str) -> Option<(String, String)> {
    let raw = copy_source.trim_start_matches('/');
    let raw = raw.split('?').next().unwrap_or(raw);
    let (bucket, key) = raw.split_once('/')?;
    let (bucket, key) = (decode_path_param(bucket), decode_path_param(key));
    if bucket.is_empty() || key.is_empty() {
        return None;
    }
    Some((bucket, key))
}
