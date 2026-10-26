//! A harness for end-to-end tests against a real Postgres, on a single node.
//!
//! Each test gets a fresh database, created through the server that
//! `CAIRN_TEST_DATABASE` points at (a URL naming any existing database, e.g.
//! `postgres://user:pass@127.0.0.1:15432/postgres`). Without it, the tests skip
//! themselves. `db-test.sh` runs them against a throwaway container.

use std::{sync::Arc, time::Duration};

use http_body_util::{BodyExt, Full};
use hyper::{StatusCode, body::Bytes};
use tokio_postgres::NoTls;
use uuid::Uuid;

use crate::{
    App, AttachTarget, UploadResult,
    auth::ContentSha256,
    packer::{Config, Hook},
    s3::{conditional::Preconditions, objects},
    store::Store,
    writing::WritingSet,
};

mod concurrency;
mod copies;

/// The bucket every test node has.
pub const BUCKET: &str = "bucket";

/// A node of its own, on a fresh database, with the packer's `pack` config and
/// test `hook`. `None` if there's no database to test against.
pub async fn node_with(pack: Config, hook: Option<Hook>) -> Option<Arc<App>> {
    let Ok(url) = std::env::var("CAIRN_TEST_DATABASE") else {
        eprintln!("skipped: set CAIRN_TEST_DATABASE to run the end-to-end tests");
        return None;
    };
    let (admin, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(connection);
    let name = format!("cairn_test_{}", Uuid::new_v4().simple());
    admin
        .execute(&format!("CREATE DATABASE {name}"), &[])
        .await
        .unwrap();
    let (server, _) = url.rsplit_once('/').expect("the URL names a database");
    let pool = crate::db::connect(&format!("{server}/{name}")).await.unwrap();
    let dir = std::env::temp_dir().join(format!("cairn-e2e-{}", Uuid::new_v4()));
    let store = Store::new(dir.to_string_lossy().into_owned()).unwrap();
    // A single node holds every blob, so peers never contact it.
    let node = crate::register_node(&pool, &store, "http://127.0.0.1:1")
        .await
        .unwrap();
    pool.get()
        .await
        .unwrap()
        .execute("INSERT INTO buckets (name) VALUES ($1)", &[&BUCKET])
        .await
        .unwrap();
    Some(Arc::new(App {
        pool,
        store,
        node,
        replication_factor: 1,
        writing: WritingSet::default(),
        pack,
        metrics: Arc::default(),
        pack_hook: hook,
    }))
}

pub async fn put(app: &Arc<App>, key: &str, data: Vec<u8>) {
    let attach = AttachTarget::Object {
        bucket: BUCKET.to_owned(),
        key: key.to_owned(),
        content_type: "application/octet-stream".to_owned(),
        conditions: Preconditions::default(),
    };
    let body = Full::new(Bytes::from(data));
    let result = crate::upload_part(app, body, &attach, false, ContentSha256::Unsigned, None)
        .await
        .unwrap();
    assert!(matches!(result, UploadResult::Committed { .. }));
}

/// Reads an object through GetObject; `None` if it doesn't exist.
pub async fn get(app: &Arc<App>, key: &str) -> Option<Vec<u8>> {
    let response = objects::get::get_object(app, BUCKET, key, None, None, &Preconditions::default())
        .await
        .unwrap();
    if response.status() == StatusCode::NOT_FOUND {
        return None;
    }
    assert_eq!(response.status(), StatusCode::OK);
    Some(response.into_body().collect().await.unwrap().to_bytes().to_vec())
}

pub async fn delete(app: &Arc<App>, key: &str) {
    let response = objects::delete::delete_object(app, BUCKET, key, None)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

pub async fn query_i64(app: &App, sql: &str) -> i64 {
    let client = app.pool.get().await.unwrap();
    client.query_one(sql, &[]).await.unwrap().get(0)
}

/// Waits for background reaps until exactly `n` blob files are left on disk.
pub async fn assert_files(app: &App, n: usize) {
    for _ in 0..100 {
        if app.store.list_local_blobs().await.unwrap().len() == n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let left = app.store.list_local_blobs().await.unwrap().len();
    panic!("expected {n} blob files, found {left}");
}

/// Waits for a background reap to delete a blob's file.
pub async fn assert_reaped(app: &App, blob_id: Uuid) {
    for _ in 0..100 {
        if app.store.open_blob(blob_id).await.unwrap().is_none() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("blob {blob_id} wasn't reaped");
}
