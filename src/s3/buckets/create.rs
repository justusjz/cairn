use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::App;

pub async fn create_bucket(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let client = app.pool.get().await?;
    client
        .execute(
            "INSERT INTO buckets (name) VALUES ($1) ON CONFLICT DO NOTHING",
            &[&bucket],
        )
        .await?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("location", format!("/{bucket}"))
        .body(Full::new(Bytes::new()))
        .unwrap())
}
