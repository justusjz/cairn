use std::sync::Arc;

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use uuid::Uuid;

use crate::db::Cached;
use crate::{
    App,
    blobs::{reap_blobs, reap_columns},
    db,
    s3::util::{format_s3_error, slow_down},
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
    // Retried on a conflict: a staged part moved by the packer meanwhile.
    let client = app.pool.get().await?;
    let mut attempt = 0;
    let row = loop {
        db::backoff(attempt).await;
        attempt += 1;
        match client
            .query_one_cached(
                "SELECT existed, reap_blob, reap_node, reap_peer
                 FROM pg_temp.cairn_abort_upload($1, $2, $3)",
                &[&upload_id, &bucket, &key],
            )
            .await
        {
            Ok(row) => break row,
            Err(e) if db::is_conflict(&e) && attempt < db::MAX_TX_ATTEMPTS => continue,
            Err(e) if db::is_conflict(&e) => return Ok(slow_down()),
            Err(e) => return Err(e.into()),
        }
    };
    let existed: bool = row.get(0);
    let reap = reap_columns(&row, 1);
    reap_blobs(app, reap);
    if !existed {
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
