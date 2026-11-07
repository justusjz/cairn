pub mod abort;
pub mod complete;
pub mod create;
pub mod list;
pub mod list_parts;
pub mod upload_part;

use uuid::Uuid;

use crate::{App, db::Cached, s3::sse::Stored};

/// How an upload is encrypted (see `s3::sse`), or `None` if there's no such
/// upload of `bucket`/`key` (authorization only checked the bucket).
pub(crate) async fn upload_encryption(
    app: &App,
    upload_id: &Uuid,
    bucket: &str,
    key: &str,
) -> anyhow::Result<Option<Stored>> {
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached(
            "SELECT sse_c_key, sse_kms_key_id, sse_kms_data_key, sse_kms_sealed, sse_kms_context
             FROM multipart_uploads WHERE upload_id = $1 AND bucket = $2 AND key = $3",
            &[upload_id, &bucket, &key],
        )
        .await?;
    Ok(row.map(|row| Stored::from_row(&row, 0)))
}
