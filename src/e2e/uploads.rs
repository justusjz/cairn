//! End-to-end tests of concurrent writes.

use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use tokio::task::JoinSet;

use super::{BUCKET, get, node_with};
use crate::{
    App, AttachTarget, UploadResult, auth::ContentSha256, packer,
    s3::conditional::Preconditions,
};

/// Uploads `data` to `key`, returning the error a client would get.
async fn try_put(app: &Arc<App>, key: &str, data: Vec<u8>) -> anyhow::Result<()> {
    let attach = AttachTarget::Object {
        bucket: BUCKET.to_owned(),
        key: key.to_owned(),
        content_type: "application/octet-stream".to_owned(),
        conditions: Preconditions::default(),
    };
    let body = Full::new(Bytes::from(data));
    let result = crate::upload_part(app, body, &attach, false, ContentSha256::Unsigned, None).await?;
    assert!(matches!(result, UploadResult::Committed { .. }));
    Ok(())
}

/// Runs `n` uploads at once, the `i`th of `data(i)` to `key(i)`, and fails if
/// any of them does.
async fn put_concurrently(
    app: &Arc<App>,
    n: usize,
    key: impl Fn(usize) -> String,
    data: impl Fn(usize) -> Vec<u8>,
) {
    let mut uploads = JoinSet::new();
    for i in 0..n {
        let (app, key, data) = (app.clone(), key(i), data(i));
        uploads.spawn(async move { try_put(&app, &key, data).await });
    }
    let mut failed = Vec::new();
    while let Some(result) = uploads.join_next().await {
        if let Err(e) = result.unwrap() {
            failed.push(format!("{e:#}"));
        }
    }
    assert!(failed.is_empty(), "{} of {n} uploads failed: {failed:?}", failed.len());
}

/// Uploads to neighbouring keys of a bucket that already holds objects don't
/// fail each other, though their transactions touch the same index pages.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_uploads_to_different_keys_all_succeed() {
    let Some(app) = node_with(packer::Config::default(), None).await else { return };
    put_concurrently(&app, 50, |i| format!("before/{i}"), |i| vec![i as u8; 100]).await;
    for round in 0..3 {
        put_concurrently(&app, 50, |i| format!("r{round}/{i}"), |i| vec![i as u8; 100]).await;
    }
    for i in 0..50 {
        assert_eq!(get(&app, &format!("r2/{i}")).await, Some(vec![i as u8; 100]));
    }
}

/// Concurrent uploads to the same key all succeed, and one of them wins.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_uploads_to_one_key_all_succeed() {
    let Some(app) = node_with(packer::Config::default(), None).await else { return };
    put_concurrently(&app, 30, |_| "same".to_owned(), |i| vec![i as u8; 100]).await;
    let read = get(&app, "same").await.unwrap();
    assert!((0..30).any(|i| read == vec![i as u8; 100]));
}
