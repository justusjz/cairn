use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::App;

pub async fn delete_object(
    app: &App,
    bucket: &str,
    key: &str,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let client = app.pool.get().await?;
    // Removing the object cascades its part rows away (and, in turn, their
    // part_locations); the on-disk bytes are left dangling for the GC to reclaim.
    // Idempotent: deleting a key that isn't there still returns 204, per S3.
    client
        .execute(
            "DELETE FROM objects WHERE bucket = $1 AND key = $2",
            &[&bucket, &key],
        )
        .await?;
    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Full::new(Bytes::new()))
        .unwrap())
}
