use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::App;

pub async fn delete_object(
    app: &App,
    bucket: &str,
    key: &str,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let client = app.pool.get().await?;
    // Removing the object cascades its object_parts rows away, leaving the
    // part(s) committed-but-unreferenced for the GC to reclaim. Idempotent:
    // deleting a key that isn't there still returns 204, per S3.
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
