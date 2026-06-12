use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use uuid::Uuid;

use crate::{
    App,
    s3::util::{format_s3_error, xml_escape, xml_ok},
};

/// CreateMultipartUpload: `POST /{bucket}/{key}?uploads`. Stages an upload and
/// hands back its UploadId. Nothing about the live object changes until
/// CompleteMultipartUpload.
pub async fn create_multipart_upload(
    app: &App,
    bucket: &str,
    key: &str,
    content_type: &str,
) -> anyhow::Result<Response<Full<Bytes>>> {
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
    // The content type is captured now and applied to the object at completion.
    let upload_id = Uuid::new_v4();
    client
        .execute(
            "INSERT INTO multipart_uploads (upload_id, bucket, key, content_type, initiated_at)
             VALUES ($1, $2, $3, $4, NOW())",
            &[&upload_id, &bucket, &key, &content_type],
        )
        .await?;
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId>\
         </InitiateMultipartUploadResult>",
        xml_escape(bucket),
        xml_escape(key),
        upload_id
    );
    Ok(xml_ok(body))
}
