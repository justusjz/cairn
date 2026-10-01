use std::sync::Arc;

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use uuid::Uuid;

use crate::{App, reap_parts, reap_targets, s3::util::format_s3_error};

/// AbortMultipartUpload: `DELETE /{bucket}/{key}?uploadId=U`. Drops the upload,
/// cascading its staged parts (and their part_locations) away, then reaps their
/// files. The live object is untouched. The upload must belong to `bucket`/`key`,
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
    // Capture the staged parts' locations, then drop the upload, in one
    // transaction. A part committed to the upload in between is cascaded away
    // without being captured; its file is simply left for `cairn prune`.
    let mut client = app.pool.get().await?;
    let tx = client.transaction().await?;
    let staged = tx
        .query(
            "SELECT pl.part_id, pl.node_id, n.peer_url
             FROM multipart_uploads u
             JOIN parts p ON p.upload_id = u.upload_id
             JOIN part_locations pl ON pl.part_id = p.part_id
             JOIN nodes n ON n.node_id = pl.node_id
             WHERE u.upload_id = $1 AND u.bucket = $2 AND u.key = $3",
            &[&upload_id, &bucket, &key],
        )
        .await?;
    let affected = tx
        .execute(
            "DELETE FROM multipart_uploads WHERE upload_id = $1 AND bucket = $2 AND key = $3",
            &[&upload_id, &bucket, &key],
        )
        .await?;
    tx.commit().await?;
    reap_parts(app, reap_targets(&staged));
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
