use deadpool_postgres::Object;
use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::db::Cached;
use crate::{
    App, db,
    s3::util::{format_s3_error, slow_down},
};

enum DeleteStatus {
    Deleted,
    NoSuchBucket,
    NotEmpty,
    /// It kept conflicting with concurrent requests.
    Contended,
}

/// One attempt (`cairn_delete_bucket`): confirm the bucket exists and is empty
/// (no live objects and no in-progress multipart uploads), then drop the bucket
/// row.
///
/// The emptiness check is the whole point: `objects`/`multipart_uploads`
/// reference `buckets(name)` with `ON DELETE CASCADE`, so without this guard a
/// single DeleteBucket would silently wipe every object — unlike S3, which
/// refuses with `BucketNotEmpty`. The function locks the bucket row before it
/// checks, and every write into the bucket holds that row locked too, so a
/// concurrent PUT can't slip an object in between the check and the DELETE (I3
/// in `catalog.sql`).
async fn try_delete(
    client: &mut Object,
    bucket: &str,
) -> Result<DeleteStatus, tokio_postgres::Error> {
    let status = client
        .query_one_cached("SELECT pg_temp.cairn_delete_bucket($1)", &[&bucket])
        .await?;
    // On anything but a delete, the function changed nothing.
    match status.get::<_, &str>(0) {
        "deleted" => {}
        "no_such_bucket" => return Ok(DeleteStatus::NoSuchBucket),
        "not_empty" => return Ok(DeleteStatus::NotEmpty),
        status => unreachable!("cairn_delete_bucket: unknown status {status}"),
    }
    Ok(DeleteStatus::Deleted)
}

pub async fn delete_bucket(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let mut client = app.pool.get().await?;
    let mut status = DeleteStatus::Contended;
    for attempt in 0..db::MAX_TX_ATTEMPTS {
        db::backoff(attempt).await;
        match try_delete(&mut client, bucket).await {
            Ok(s) => {
                status = s;
                break;
            }
            Err(e) if db::is_conflict(&e) => continue,
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
        DeleteStatus::Contended => Ok(slow_down()),
    }
}
