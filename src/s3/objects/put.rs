use std::sync::Arc;

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes, header};
use md5::{Digest, Md5};

use crate::{App, AttachTarget, s3::util::format_s3_error};

pub async fn put_object(
    app: &Arc<App>,
    bucket: &str,
    key: &str,
    content_type: &str,
    data: Bytes,
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

    // The S3 ETag of a single-part PUT is the hex MD5 of the body.
    let etag: String = Md5::digest(&data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    // Store the data as one replicated, committed part and atomically point
    // (bucket, key) at it.
    let attach = AttachTarget::Object {
        bucket: bucket.to_owned(),
        key: key.to_owned(),
        size: data.len() as i64,
        etag: etag.clone(),
        content_type: content_type.to_owned(),
    };
    crate::upload_part(app, data, &attach).await?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::ETAG, format!("\"{etag}\""))
        .body(Full::new(Bytes::new()))
        .unwrap())
}
