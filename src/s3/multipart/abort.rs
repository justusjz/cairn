use std::sync::Arc;

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use uuid::Uuid;

use crate::{
    App,
    blobs::{blob_ids, drop_unreferenced_blobs, reap_blobs},
    s3::util::format_s3_error,
};

/// AbortMultipartUpload: `DELETE /{bucket}/{key}?uploadId=U`. Drops the upload
/// and its staged parts, then the parts' blobs, and reaps their files. The live object is untouched. The upload must belong to `bucket`/`key`,
/// so a role can't reach an upload in another bucket by its ID.
pub async fn abort_multipart_upload(
    app: &Arc<App>,
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
    // Delete the staged parts, the upload, and the freed blobs in one
    // transaction. A part committed to the upload in between is cascaded away
    // with the upload, leaving its blob unreferenced; the GC drops it.
    let mut client = app.pool.get().await?;
    let tx = client.transaction().await?;
    let staged = tx
        .query(
            "DELETE FROM parts p USING multipart_uploads u
             WHERE p.upload_id = u.upload_id
               AND u.upload_id = $1 AND u.bucket = $2 AND u.key = $3
             RETURNING p.blob_id",
            &[&upload_id, &bucket, &key],
        )
        .await?;
    let affected = tx
        .execute(
            "DELETE FROM multipart_uploads WHERE upload_id = $1 AND bucket = $2 AND key = $3",
            &[&upload_id, &bucket, &key],
        )
        .await?;
    let reap = drop_unreferenced_blobs(&tx, &blob_ids(&staged)).await?;
    tx.commit().await?;
    reap_blobs(app, reap);
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
