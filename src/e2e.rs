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
    payload::Payload,
    packer::{Config, Hook},
    s3::{conditional::Preconditions, objects},
    store::Store,
    writing::WritingSet,
};

mod checksums;
mod concurrency;
mod cleanup;
mod copies;
mod deadlocks;
mod encrypted;
mod kms;
mod limits;
mod listing;
mod locking;
mod metadata;
mod multipart;
mod post_object;

/// The bucket every test node has.
pub const BUCKET: &str = "bucket";

/// The checksum an object written as a PUT is stored with, and a part of an
/// upload without an algorithm (see `s3::checksums`).
pub const OBJECT_CHECKSUM: crate::s3::checksums::Wanted =
    crate::s3::checksums::Wanted::ClientsOr(crate::s3::checksums::Algorithm::Crc64Nvme);
pub const PART_CHECKSUM: crate::s3::checksums::Wanted =
    crate::s3::checksums::Wanted::Exactly(crate::s3::checksums::Algorithm::Crc64Nvme);

/// A node of its own, on a fresh database, with the packer's `pack` config and
/// test `hook`. `None` if there's no database to test against.
pub async fn node_with(pack: Config, hook: Option<Hook>) -> Option<Arc<App>> {
    node_replicating(pack, hook, 1).await
}

/// Like `node_with`, writing `replication_factor` replicas of every blob. The
/// test has to register the other nodes.
pub async fn node_replicating(
    pack: Config,
    hook: Option<Hook>,
    replication_factor: usize,
) -> Option<Arc<App>> {
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
    let peer_url = "http://127.0.0.1:1";
    let node = crate::register_node(&pool, &store, peer_url)
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
        replication_factor,
        writing: WritingSet::default(),
        pack,
        metrics: Arc::default(),
        dashboard: crate::dashboard::Dashboard::new(peer_url),
        peers: crate::peer::PeerClient::new(),
        allow_sse_c_over_http: false,
        kms: None,
        pack_hook: hook,
    }))
}

/// A node with a KMS: the OpenBao that `CAIRN_TEST_OPENBAO` points at (see
/// `db-test.sh`), whose JWT auth mount `cairn` trusts the key in
/// `CAIRN_TEST_OPENBAO_JWT_KEY`, with `transit/cairn-sse-s3` its SSE-S3 key.
/// `None` if there's no database or OpenBao to test against.
pub async fn kms_node() -> Option<Arc<App>> {
    let address = std::env::var("CAIRN_TEST_OPENBAO").ok()?;
    let app = node_with(Config::default(), None).await?;
    let mut app = Arc::into_inner(app).expect("a new node isn't shared");
    app.kms = crate::kms::Kms::new(&crate::kms::KmsArgs {
        kms_address: Some(address),
        kms_jwt_key: Some(std::env::var("CAIRN_TEST_OPENBAO_JWT_KEY").unwrap().into()),
        kms_auth_mount: "cairn".to_owned(),
        kms_auth_role: "s3".to_owned(),
        kms_sse_s3_key: Some("cairn-sse-s3".to_owned()),
        kms_ca_cert: None,
    })
    .unwrap();
    Some(Arc::new(app))
}

pub async fn put(app: &Arc<App>, key: &str, data: Vec<u8>) {
    let attach = AttachTarget::Object {
        bucket: BUCKET.to_owned(),
        key: key.to_owned(),
        content_type: "application/octet-stream".to_owned(),
        metadata: String::new(),
        conditions: Preconditions::default(),
        sealing: None,
        checksum: crate::e2e::OBJECT_CHECKSUM,
    };
    let body = Full::new(Bytes::from(data));
    let result = crate::upload_part(app, body, &attach, Payload::unchecked())
        .await
        .unwrap();
    assert!(matches!(result, UploadResult::Committed { .. }));
}

/// Reads an object through GetObject; `None` if it doesn't exist.
pub async fn get(app: &Arc<App>, key: &str) -> Option<Vec<u8>> {
    let response = objects::get::get_object(app, BUCKET, key, None, None, &Preconditions::default(), None, None, false)
        .await
        .unwrap();
    if response.status() == StatusCode::NOT_FOUND {
        return None;
    }
    assert_eq!(response.status(), StatusCode::OK);
    Some(response.into_body().collect().await.unwrap().to_bytes().to_vec())
}

/// A client's SSE-C key, as a request over HTTPS supplies it.
pub fn customer_key(key: &crate::encryption::Key) -> crate::s3::sse_c::CustomerKey {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use md5::Digest;
    use crate::s3::sse_c::HEADERS;
    let mut headers = hyper::HeaderMap::new();
    for (name, value) in [
        ("x-amz-server-side-encryption-customer-algorithm", "AES256".to_owned()),
        ("x-amz-server-side-encryption-customer-key", STANDARD.encode(key)),
        ("x-amz-server-side-encryption-customer-key-md5", STANDARD.encode(md5::Md5::digest(key))),
    ] {
        headers.insert(name, value.parse().unwrap());
    }
    crate::s3::sse_c::requested(&headers, &HEADERS, true).ok().flatten().unwrap()
}

/// Writes `data` as `key`, encrypted with the SSE-C `customer` key. Its ETag.
pub async fn put_sealed(app: &Arc<App>, key: &str, data: Vec<u8>, customer: &crate::s3::sse_c::CustomerKey) -> String {
    let attach = AttachTarget::Object {
        bucket: BUCKET.to_owned(),
        key: key.to_owned(),
        content_type: "application/octet-stream".to_owned(),
        metadata: String::new(),
        conditions: Preconditions::default(),
        sealing: Some(crate::Sealing {
            key: zeroize::Zeroizing::new(*customer.key()),
            stored: crate::s3::sse::Stored::Customer { check: customer.new_check() },
        }),
        checksum: crate::e2e::OBJECT_CHECKSUM,
    };
    let result = crate::upload_part(app, Full::new(Bytes::from(data)), &attach, Payload::unchecked())
        .await
        .unwrap();
    let UploadResult::Committed { etag, .. } = result else { panic!("not committed") };
    etag
}

/// Reads (the `range` of) an SSE-C object through GetObject: its status and body.
pub async fn get_sealed(
    app: &Arc<App>,
    key: &str,
    range: Option<&str>,
    customer: Option<&crate::s3::sse_c::CustomerKey>,
) -> (StatusCode, Vec<u8>) {
    let response = objects::get::get_object(app, BUCKET, key, None, range, &Preconditions::default(), customer, None, false)
        .await
        .unwrap();
    let status = response.status();
    (status, response.into_body().collect().await.unwrap().to_bytes().to_vec())
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
