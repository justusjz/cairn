use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::db::Cached;
use crate::App;

/// HeadBucket: `HEAD /{bucket}`. 200 if the bucket exists, 404 otherwise; no body.
/// Used by S3 clients (e.g. minio-go's `BucketExists`) to probe a bucket.
pub async fn head_bucket(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let client = app.pool.get().await?;
    let exists = client
        .query_opt_cached("SELECT 1 FROM buckets WHERE name = $1", &[&bucket])
        .await?
        .is_some();
    let status = if exists {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    };
    let builder = Response::builder().status(status);
    // Its region, as S3 tells it (probed): Cairn has none, which S3 clients
    // take as us-east-1 (see GetBucketLocation's stub). And that the bucket
    // isn't an access point's alias.
    let builder = match exists {
        true => builder.header(REGION_HEADER, REGION).header("x-amz-access-point-alias", "false"),
        false => builder,
    };
    Ok(builder.body(Full::new(Bytes::new())).unwrap())
}

/// The header S3 tells a bucket's region in, on HeadBucket and listings.
pub const REGION_HEADER: &str = "x-amz-bucket-region";

/// The region Cairn's buckets are told to be in: none, which S3 clients take
/// as us-east-1, as an empty LocationConstraint is.
pub const REGION: &str = "us-east-1";
