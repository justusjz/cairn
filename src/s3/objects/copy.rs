use std::sync::Arc;

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::{
    App, AttachTarget, UploadResult,
    auth::ContentSha256,
    body::channel_body,
    s3::{
        objects::get::{resolve_object_parts, stream_part},
        util::{decode_path_param, format_s3_error, xml_ok},
    },
};

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
) -> anyhow::Result<Response<Full<Bytes>>> {
    // Parse `x-amz-copy-source`: "/bucket/key" or "bucket/key", optionally with a
    // "?versionId=..." suffix, percent-encoded. Strip a leading slash and the
    // (unsupported) version qualifier, then split bucket/key at the first slash and
    // decode each half — mirroring how the request path itself is parsed.
    let raw = copy_source.trim_start_matches('/');
    let raw = raw.split('?').next().unwrap_or(raw);
    let (src_bucket, src_key) = match raw.split_once('/') {
        Some((bucket, key)) => (decode_path_param(bucket), decode_path_param(key)),
        None => {
            return Ok(format_s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "the x-amz-copy-source header is malformed",
            ));
        }
    };
    if src_bucket.is_empty() || src_key.is_empty() {
        return Ok(format_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "the x-amz-copy-source header is malformed",
        ));
    }

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
    let src_content_type: String = match tx
        .query_opt(
            "SELECT content_type FROM objects WHERE bucket = $1 AND key = $2",
            &[&src_bucket, &src_key],
        )
        .await?
    {
        Some(row) => row.get(0),
        None => {
            return Ok(format_s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                "the specified source key does not exist",
            ));
        }
    };
    // Resolve the source's ordered parts and their locations from the same
    // snapshot (an empty object simply has none, and streams as a zero-byte body).
    let parts = resolve_object_parts(&tx, &src_bucket, &src_key).await?;
    tx.commit().await?;
    drop(client);

    // Stream the source parts (in order, each whole) through a channel-backed body:
    // a background task pulls each from a replica — locally if that's us — and
    // forwards its chunks, exactly as get_object does. That body is then fed to the
    // normal upload path, which replicates and commits it as the destination's part.
    let (sender, source_body) = channel_body();
    let stream_app = app.clone();
    let self_id = app.store.get_node_id().to_string();
    tokio::spawn(async move {
        // The whole part is copied, so its size (used only for range math in GET)
        // is irrelevant here.
        for (part_id, _size, locations) in parts {
            if let Err(e) = stream_part(&stream_app, part_id, None, &locations, &self_id, &sender).await
            {
                let _ = sender.send(Err(e)).await;
                return;
            }
        }
    });

    let attach = AttachTarget::Object {
        bucket: dest_bucket.to_owned(),
        key: dest_key.to_owned(),
        content_type: if replace {
            request_content_type.to_owned()
        } else {
            src_content_type
        },
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
        UploadResult::ContentSha256Mismatch | UploadResult::ChunkSignatureMismatch => {
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
