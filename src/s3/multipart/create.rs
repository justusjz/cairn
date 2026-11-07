use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use uuid::Uuid;

use crate::db::Cached;
use crate::{
    App,
    s3::sse::{self, Wanted},
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
    metadata: &str,
    wanted: Wanted<'_>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let client = app.pool.get().await?;
    if client
        .query_opt_cached("SELECT 1 FROM buckets WHERE name = $1", &[&bucket])
        .await?
        .is_none()
    {
        return Ok(format_s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "the specified bucket does not exist",
        ));
    }
    drop(client);
    // The content type and metadata are captured now and applied to the object
    // at completion; so is its encryption, which its parts need: the check of
    // an SSE-C upload's key, or the sealed key of an SSE-KMS one (see `sse`).
    let upload_id = Uuid::now_v7();
    let stored = match sse::seal(app, wanted, bucket, key).await? {
        Ok(sealing) => sealing.map_or(sse::Stored::Plain, |sealing| sealing.stored),
        Err(refused) => return Ok(refused),
    };
    let sse = stored.columns();
    app.pool
        .get()
        .await?
        .execute_cached(
            "INSERT INTO multipart_uploads (upload_id, bucket, key, content_type, metadata,
                                            sse_c_key, sse_kms_key_id, sse_kms_data_key,
                                            sse_kms_sealed, sse_kms_context, initiated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())",
            &[
                &upload_id,
                &bucket,
                &key,
                &content_type,
                &metadata,
                &sse.sse_c_key,
                &sse.kms_key_id,
                &sse.kms_data_key,
                &sse.kms_sealed,
                &sse.kms_context,
            ],
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
    let customer_key = wanted.customer();
    Ok(sse::echo_onto(xml_ok(body), &stored, customer_key))
}
