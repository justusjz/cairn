use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use uuid::Uuid;

use crate::{App, s3::util::format_s3_error};

/// AbortMultipartUpload: `DELETE /{bucket}/{key}?uploadId=U`. Drops the upload,
/// cascading its staged parts (and their part_locations) away; the on-disk bytes
/// are left dangling for the GC. The live object is untouched. The upload must
/// belong to `bucket`/`key`, so a role can't reach an upload in another bucket
/// by its ID.
pub async fn abort_multipart_upload(
    app: &App,
    bucket: &str,
    key: &str,
    upload_id: &str,
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
    let client = app.pool.get().await?;
    let affected = client
        .execute(
            "DELETE FROM multipart_uploads WHERE upload_id = $1 AND bucket = $2 AND key = $3",
            &[&upload_id, &bucket, &key],
        )
        .await?;
    if affected == 0 {
        return Ok(format_s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "the specified multipart upload does not exist",
        ));
    }
    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Full::new(Bytes::new()))
        .unwrap())
}
