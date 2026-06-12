use std::sync::Arc;

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes, body::Incoming, header};
use uuid::Uuid;

use crate::{App, AttachTarget, s3::util::format_s3_error};

/// UploadPart: `PUT /{bucket}/{key}?partNumber=N&uploadId=U`. Streams the part
/// and stages it under the upload (the live object is untouched); returns its
/// ETag.
pub async fn put_part(
    app: &Arc<App>,
    upload_id: &str,
    part_number: &str,
    body: Incoming,
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
    // only fail to stage at commit (the FK would reject it anyway).
    let client = app.pool.get().await?;
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
    drop(client);

    // `upload_part` streams the body, computing the part's ETag (hex MD5) as it
    // goes.
    let etag = crate::upload_part(
        app,
        body,
        &AttachTarget::MultipartPart {
            upload_id,
            part_number,
        },
    )
    .await?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::ETAG, format!("\"{etag}\""))
        .body(Full::new(Bytes::new()))
        .unwrap())
}
