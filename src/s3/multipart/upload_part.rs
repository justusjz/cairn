use std::sync::Arc;

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes, body::Incoming, header};
use uuid::Uuid;

use crate::db::Cached;
use crate::{
    App, AttachTarget, UploadResult,
    payload::Payload,
    s3::sse_c::{self, CustomerKey},
    s3::util::{format_s3_error, rejection_response},
};

/// UploadPart: `PUT /{bucket}/{key}?partNumber=N&uploadId=U`. Streams the part
/// and stages it under the upload (the live object is untouched); returns its
/// ETag. The part of an SSE-C upload needs the upload's key, and is encrypted
/// with it.
#[allow(clippy::too_many_arguments)]
pub async fn put_part(
    app: &Arc<App>,
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: &str,
    body: Incoming,
    payload: Payload,
    customer_key: Option<&CustomerKey>,
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
    // Reject up front if the upload is gone, so we don't replicate a part we'd
    // only fail to stage at commit (the FK would reject it anyway). It must also
    // belong to the request's bucket/key: authorization only checked that bucket.
    // Its key check, if it's SSE-C, never changes, so it's checked here, once.
    let client = app.pool.get().await?;
    let Some(upload) = client
        .query_opt_cached(
            "SELECT sse_c_key FROM multipart_uploads WHERE upload_id = $1 AND bucket = $2 AND key = $3",
            &[&upload_id, &bucket, &key],
        )
        .await?
    else {
        return Ok(format_s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "the specified multipart upload does not exist",
        ));
    };
    drop(client);
    let check: Option<Vec<u8>> = upload.get(0);
    if let Err(refused) = sse_c::check_read(check.as_deref(), customer_key) {
        return Ok(refused);
    }

    // `upload_part` streams the body, computing the part's ETag (hex MD5, or,
    // encrypted, its salt) as it goes.
    match crate::upload_part(
        app,
        body,
        &AttachTarget::MultipartPart {
            upload_id,
            part_number,
            key: customer_key.map(|key| zeroize::Zeroizing::new(*key.key())),
        },
        payload,
    )
    .await?
    {
        UploadResult::Committed { etag, .. } => {
            let mut builder = Response::builder()
                .status(StatusCode::OK)
                .header(header::ETAG, format!("\"{etag}\""));
            if let Some(key) = customer_key {
                builder = key.echo(builder);
            }
            Ok(builder.body(Full::new(Bytes::new())).unwrap())
        }
        UploadResult::Rejected(rejection) => Ok(rejection_response(&rejection)),
        // The upload was completed or aborted while the body streamed.
        UploadResult::NoSuchUpload => Ok(format_s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "the specified multipart upload does not exist",
        )),
        // UploadPart carries no conditional-write guard, and has no bucket to
        // check (its upload is checked instead), so these can't occur.
        UploadResult::PreconditionFailed | UploadResult::NoSuchKey | UploadResult::NoSuchBucket => {
            unreachable!("UploadPart has no conditions, and no bucket check")
        }
    }
}
