use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::App;

/// HeadBucket: `HEAD /{bucket}`. 200 if the bucket exists, 404 otherwise; no body.
/// Used by S3 clients (e.g. minio-go's `BucketExists`) to probe a bucket.
pub async fn head_bucket(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let client = app.pool.get().await?;
    let exists = client
        .query_opt("SELECT 1 FROM buckets WHERE name = $1", &[&bucket])
        .await?
        .is_some();
    let status = if exists {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    };
    Ok(Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .unwrap())
}
