use std::sync::Arc;

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes, body::Incoming, header};

use crate::{
    App, AttachTarget, UploadResult,
    auth::{ContentSha256, StreamingChunkVerifier},
    s3::conditional::Preconditions,
    s3::util::format_s3_error,
};

pub async fn put_object(
    app: &Arc<App>,
    bucket: &str,
    key: &str,
    content_type: &str,
    body: Incoming,
    aws_chunked: bool,
    content_sha256: ContentSha256,
    chunk_verifier: Option<StreamingChunkVerifier>,
    conditions: &Preconditions,
) -> anyhow::Result<Response<Full<Bytes>>> {
    // Reject up front if the bucket doesn't exist, so we don't replicate a part
    // only to fail the FK at commit time. (There's still the objects -> buckets
    // FK as a backstop against a concurrent bucket delete.)
    let client = app.pool.get().await?;
    if client
        .query_opt("SELECT 1 FROM buckets WHERE name = $1", &[&bucket])
        .await?
        .is_none()
    {
        return Ok(format_s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "the specified bucket does not exist",
        ));
    }
    // Fast-fail a conditional write (If-Match / If-None-Match) before streaming the
    // body, so a client "create if absent" against an existing key doesn't upload
    // the whole object just to be rejected. This is only an optimization — the
    // authoritative, race-free check runs inside the commit transaction.
    if conditions.has_write_conditions() {
        let current: Option<String> = client
            .query_opt(
                "SELECT etag FROM objects WHERE bucket = $1 AND key = $2",
                &[&bucket, &key],
            )
            .await?
            .map(|row| row.get(0));
        if !conditions.allows_write(current.as_deref()) {
            return Ok(precondition_failed());
        }
    }
    drop(client);

    // Stream the body into one replicated, committed part and atomically point
    // (bucket, key) at it. `upload_part` computes the ETag (hex MD5) as it streams.
    let attach = AttachTarget::Object {
        bucket: bucket.to_owned(),
        key: key.to_owned(),
        content_type: content_type.to_owned(),
        conditions: conditions.clone(),
    };
    match crate::upload_part(app, body, &attach, aws_chunked, content_sha256, chunk_verifier).await?
    {
        UploadResult::Committed(etag) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::ETAG, format!("\"{etag}\""))
            .body(Full::new(Bytes::new()))
            .unwrap()),
        UploadResult::ContentSha256Mismatch => Ok(format_s3_error(
            StatusCode::BAD_REQUEST,
            "XAmzContentSHA256Mismatch",
            "the provided x-amz-content-sha256 does not match the calculated hash",
        )),
        UploadResult::ChunkSignatureMismatch => Ok(format_s3_error(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "the request signature we calculated does not match the signature you provided",
        )),
        // A concurrent writer won the race between the fast-fail check and commit.
        UploadResult::PreconditionFailed => Ok(precondition_failed()),
    }
}

/// The 412 returned when a conditional-write guard (If-Match / If-None-Match)
/// doesn't hold.
fn precondition_failed() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::PRECONDITION_FAILED,
        "PreconditionFailed",
        "at least one of the preconditions you specified did not hold",
    )
}
