use std::sync::Arc;

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes, body::Incoming, header};
use uuid::Uuid;

use crate::{
    App, AttachTarget, UploadResult,
    payload::Payload,
    s3::multipart::upload,
    s3::sse,
    s3::sse_c::CustomerKey,
    s3::util::{format_s3_error, rejection_response},
};

/// UploadPart: `PUT /{bucket}/{key}?partNumber=N&uploadId=U`. Streams the part
/// and stages it under the upload (the live object is untouched); returns its
/// ETag. The part of an SSE-C upload needs the upload's key, and is encrypted
/// with it; that of an SSE-KMS upload is encrypted with the upload's key,
/// which the KMS opens.
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
    role: Option<Uuid>,
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
    // Its encryption never changes, so it's checked here, once.
    let Some(upload) = upload(app, &upload_id, bucket, key).await? else {
        return Ok(format_s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "the specified multipart upload does not exist",
        ));
    };
    // An upload of an algorithm takes parts with checksums of it only (S3
    // requires them; MinIO's 400).
    if let Some((algorithm, _)) = upload.checksum
        && payload.declared_algorithm() != Some(algorithm)
    {
        let got = payload.declared_algorithm().map_or("", |a| a.name());
        return Ok(format_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            &format!(
                "Invalid arguments provided for {bucket}/{key}: (checksum missing, want \"{}\", got \"{got}\")",
                algorithm.name()
            ),
        ));
    }
    let encryption = upload.encryption.clone();
    if let Err(refused) = sse::check(&encryption, customer_key) {
        return Ok(refused);
    }
    let upload_key = match sse::open(app, &encryption, customer_key, role, bucket, key).await? {
        Ok(upload_key) => upload_key,
        Err(refused) => return Ok(refused),
    };

    // `upload_part` streams the body, computing the part's ETag (hex MD5, or,
    // encrypted, its salt) as it goes.
    match crate::upload_part(
        app,
        body,
        &AttachTarget::MultipartPart {
            upload_id,
            part_number,
            key: upload_key,
            sse_s3: matches!(encryption, sse::Stored::S3(_)),
            checksum: upload.part_checksum(),
        },
        payload,
    )
    .await?
    {
        UploadResult::Committed { etag, sent, .. } => {
            let builder = Response::builder()
                .status(StatusCode::OK)
                .header(header::ETAG, format!("\"{etag}\""));
            // The checksum the client sent, as S3 echoes it.
            let builder = match &sent {
                Some(sent) => builder.header(sent.algorithm.header(), &sent.value),
                None => builder,
            };
            let builder = sse::echo(builder, &encryption, customer_key);
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
        UploadResult::PreconditionFailed
        | UploadResult::NoSuchKey
        | UploadResult::NoSuchBucket
        | UploadResult::Refused(_) => {
            unreachable!("UploadPart has no conditions, and no bucket check")
        }
    }
}
