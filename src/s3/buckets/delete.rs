use deadpool_postgres::Object;
use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use tokio_postgres::{IsolationLevel, error::SqlState};

use crate::{App, s3::util::format_s3_error};

/// Bounded retry for the serializable delete, mirroring the object-delete path.
const MAX_DELETE_ATTEMPTS: usize = 10;

enum DeleteStatus {
    Deleted,
    NoSuchBucket,
    NotEmpty,
    Unavailable,
}

/// One serializable attempt: confirm the bucket exists and is empty (no live
/// objects and no in-progress multipart uploads), then drop the bucket row.
///
/// The emptiness check is the whole point: `objects`/`multipart_uploads`
/// reference `buckets(name)` with `ON DELETE CASCADE`, so without this guard a
/// single DeleteBucket would silently wipe every object — unlike S3, which
/// refuses with `BucketNotEmpty`. Serializable isolation shares one snapshot
/// across the existence check, the emptiness check, and the delete, so a
/// concurrent PUT can't slip an object in between the check and the DELETE: the
/// conflicting transaction fails serialization and the caller retries.
async fn try_delete(
    client: &mut Object,
    bucket: &str,
) -> Result<DeleteStatus, tokio_postgres::Error> {
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()
        .await?;
    if tx
        .query_opt("SELECT 1 FROM buckets WHERE name = $1", &[&bucket])
        .await?
        .is_none()
    {
        return Ok(DeleteStatus::NoSuchBucket); // tx rolls back on drop
    }
    let non_empty = tx
        .query_opt(
            "SELECT 1 WHERE EXISTS (SELECT 1 FROM objects WHERE bucket = $1)
                          OR EXISTS (SELECT 1 FROM multipart_uploads WHERE bucket = $1)",
            &[&bucket],
        )
        .await?
        .is_some();
    if non_empty {
        return Ok(DeleteStatus::NotEmpty); // tx rolls back on drop
    }
    tx.execute("DELETE FROM buckets WHERE name = $1", &[&bucket])
        .await?;
    tx.commit().await?;
    Ok(DeleteStatus::Deleted)
}

pub async fn delete_bucket(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let mut client = app.pool.get().await?;
    let mut status = DeleteStatus::Unavailable;
    for _ in 0..MAX_DELETE_ATTEMPTS {
        match try_delete(&mut client, bucket).await {
            Ok(s) => {
                status = s;
                break;
            }
            Err(e) if e.code() == Some(&SqlState::T_R_SERIALIZATION_FAILURE) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    match status {
        DeleteStatus::Deleted => Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Full::new(Bytes::new()))
            .unwrap()),
        DeleteStatus::NoSuchBucket => Ok(format_s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "the specified bucket does not exist",
        )),
        DeleteStatus::NotEmpty => Ok(format_s3_error(
            StatusCode::CONFLICT,
            "BucketNotEmpty",
            "the bucket you tried to delete is not empty",
        )),
        DeleteStatus::Unavailable => Ok(format_s3_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            "delete aborted after serialization retries",
        )),
    }
}
