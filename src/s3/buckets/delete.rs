use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::{App, s3::util::format_s3_error};

pub async fn delete_bucket(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let client = app.pool.get().await?;
    let result = client
        .execute("DELETE FROM buckets WHERE name = $1", &[&bucket])
        .await?;
    if result == 0 {
        Ok(format_s3_error(StatusCode::NOT_FOUND, "NoSuchBucket", ""))
    } else {
        Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Full::new(Bytes::new()))
            .unwrap())
    }
}
