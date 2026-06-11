use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::App;

pub async fn delete_bucket(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let client = app.pool.get().await?;
    client
        .execute("DELETE FROM buckets WHERE name = $1", &[&bucket])
        .await?;
    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Full::new(Bytes::new()))
        .unwrap())
}
