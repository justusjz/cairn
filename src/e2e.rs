//! A harness for end-to-end tests against a real Postgres, on a single node.
//!
//! Each test gets a fresh database, created through the server that
//! `CAIRN_TEST_DATABASE` points at (a URL naming any existing database, e.g.
//! `postgres://user:pass@127.0.0.1:15432/postgres`). Without it, the tests skip
//! themselves. `db-test.sh` runs them against a throwaway container.

use std::{sync::Arc, time::Duration};

use deadpool_postgres::Pool;
use http_body_util::{BodyExt, Full};
use hyper::{StatusCode, body::Bytes};
use tokio_postgres::NoTls;
use uuid::Uuid;

use crate::{
    App, AttachTarget, UploadResult,
    packer::{Config, Hook},
    payload::Payload,
    s3::{conditional::Preconditions, objects},
    store::Store,
    writing::WritingSet,
};

mod abac;
mod acls;
mod checksums;
mod cleanup;
mod concurrency;
mod copies;
mod cors;
mod deadlocks;
mod directory;
mod encrypted;
pub(crate) mod kms;
mod limits;
mod listing;
mod locking;
mod logging;
mod metadata;
mod mfa_delete;
mod multipart;
mod object_lock;
mod post_object;
mod public_access;
mod roles;
mod tagging;
mod users;
mod website;

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
    let pool = fresh_database().await?;
    // A single node holds every blob, so peers never contact it.
    let app = node_on(&pool, "http://127.0.0.1:1", pack, hook, replication_factor).await;
    keep_alive(&app);
    create_bucket(&app).await;
    Some(app)
}

/// Keeps a single test node live, as `cairn serve`'s heartbeat does: a node
/// unseen for 10 seconds takes no new data, which a test outlasts when the
/// whole suite runs at once. Only this node: the tests' other ones stay as
/// they're registered.
fn keep_alive(app: &Arc<App>) {
    let app = Arc::downgrade(app);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let Some(app) = app.upgrade() else { return };
            if let Ok(client) = app.pool.get().await {
                let _ = client
                    .execute(
                        "UPDATE nodes SET last_seen = NOW() WHERE id = $1",
                        &[&app.node],
                    )
                    .await;
            }
        }
    });
}

/// A pool of connections to a fresh database. `None` if there's no database
/// to test against.
async fn fresh_database() -> Option<Pool> {
    fresh_database_through(usize::MAX).await
}

/// As `fresh_database`, with the schema migrated up to step `last` only
/// (see `db::connect_through`).
pub async fn fresh_database_through(last: usize) -> Option<Pool> {
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
    Some(
        crate::db::connect_through(&format!("{server}/{name}"), last)
            .await
            .unwrap(),
    )
}

/// A node with a data dir of its own, the pool `default`, registered in
/// the database of `pool` as reachable at `peer_url`.
async fn node_on(
    pool: &Pool,
    peer_url: &str,
    pack: Config,
    hook: Option<Hook>,
    replication_factor: usize,
) -> Arc<App> {
    node_with_pools(
        pool,
        peer_url,
        pack,
        hook,
        replication_factor,
        &[crate::classes::DEFAULT_POOL],
    )
    .await
}

/// As `node_on`, with a data dir of its own for each of `pools`.
pub(crate) async fn node_with_pools(
    pool: &Pool,
    peer_url: &str,
    pack: Config,
    hook: Option<Hook>,
    replication_factor: usize,
    pools: &[&str],
) -> Arc<App> {
    let dirs = pools
        .iter()
        .map(|name| (name.to_string(), data_dir()))
        .collect();
    let store = Store::new(dirs).unwrap();
    let node = crate::register_node(pool, &store, peer_url).await.unwrap();
    let app = Arc::new(App {
        pool: pool.clone(),
        store,
        node,
        replication_flag: replication_factor,
        parity_setting: std::sync::atomic::AtomicI64::new(-1),
        data_setting: std::sync::atomic::AtomicI64::new(1),
        scrub_rate: 0,
        writing: WritingSet::default(),
        pack,
        metrics: Arc::default(),
        console: crate::console::Shared::new(None),
        peers: crate::peer::PeerClient::new(),
        peer_host: crate::peer::url_host(peer_url),
        allow_sse_c_over_http: false,
        trusted_proxies: Vec::new(),
        domain: None,
        website_domain: None,
        kms: None,
        sessions: Default::default(),
        access_logs: Default::default(),
        audit: Default::default(),
        classes: Default::default(),
        pack_hook: hook,
    });
    crate::refresh_settings(&app).await.unwrap();
    app
}

/// The data dirs of the nodes the tests made, all removed as the tests'
/// process exits: a test's node may well outlive it (in a task it spawned),
/// and the dirs would add up in the temp dir (often in memory) otherwise.
static DATA_DIRS: std::sync::Mutex<Vec<std::path::PathBuf>> = std::sync::Mutex::new(Vec::new());

/// A fresh data dir for a node, removed when the tests are done.
fn data_dir() -> std::path::PathBuf {
    static ON_EXIT: std::sync::Once = std::sync::Once::new();
    extern "C" fn remove_data_dirs() {
        let dirs = std::mem::take(&mut *DATA_DIRS.lock().unwrap_or_else(|e| e.into_inner()));
        for dir in dirs {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
    // SAFETY: registers a function that only removes files; it runs once,
    // as `exit` does, after the tests are done.
    ON_EXIT.call_once(|| unsafe {
        libc::atexit(remove_data_dirs);
    });
    let dir = std::env::temp_dir().join(format!("cairn-e2e-{}", Uuid::new_v4()));
    DATA_DIRS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(dir.clone());
    dir
}

async fn create_bucket(app: &App) {
    app.pool
        .get()
        .await
        .unwrap()
        .execute("INSERT INTO buckets (name) VALUES ($1)", &[&BUCKET])
        .await
        .unwrap();
}

/// Nodes on one database, each serving its peer endpoint (on a port of its
/// own), and heartbeating, as `cairn serve` does.
pub struct Cluster {
    pub nodes: Vec<Arc<App>>,
    tasks: Vec<Vec<tokio::task::JoinHandle<()>>>,
}

/// A cluster of `n` nodes writing `replication_factor` replicas of every
/// blob. `None` if there's no database to test against.
pub async fn cluster(n: usize, replication_factor: usize) -> Option<Cluster> {
    cluster_with(n, replication_factor, Config::default(), None).await
}

/// Like `cluster`, with the packer's `pack` config on every node, and the
/// packer's test `hook` on the first.
pub async fn cluster_with(
    n: usize,
    replication_factor: usize,
    pack: Config,
    hook: Option<Hook>,
) -> Option<Cluster> {
    let pools = vec![&[crate::classes::DEFAULT_POOL][..]; n];
    cluster_of_pools(&pools, replication_factor, pack, hook).await
}

/// Like `cluster_with`, of a node for each of `pools`, with those pools (see
/// `classes`).
pub async fn cluster_of_pools(
    pools: &[&[&str]],
    replication_factor: usize,
    pack: Config,
    mut hook: Option<Hook>,
) -> Option<Cluster> {
    let pool = fresh_database().await?;
    let mut cluster = Cluster {
        nodes: Vec::new(),
        tasks: Vec::new(),
    };
    for node_pools in pools {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_url = format!("http://{}", listener.local_addr().unwrap());
        let app = node_with_pools(
            &pool,
            &peer_url,
            pack.clone(),
            hook.take(),
            replication_factor,
            node_pools,
        )
        .await;
        let router = crate::peer::router(app.clone());
        let serving = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let beating = tokio::spawn(crate::heartbeat(app.clone(), peer_url));
        cluster.nodes.push(app);
        cluster.tasks.push(vec![serving, beating]);
    }
    create_bucket(&cluster.nodes[0]).await;
    Some(cluster)
}

impl Cluster {
    /// Takes node `i` down: it stops serving and heartbeating, and is last
    /// seen a minute ago.
    pub async fn stop(&self, i: usize) {
        for task in &self.tasks[i] {
            task.abort();
        }
        while !self.tasks[i].iter().all(|task| task.is_finished()) {
            tokio::task::yield_now().await;
        }
        // A heartbeat the abort cut short may still have its statement on
        // the way to the database, to land after the first of these: the
        // second, a moment later, has the last word.
        let app = &self.nodes[i];
        let client = app.pool.get().await.unwrap();
        for _ in 0..2 {
            client
                .execute(
                    "UPDATE nodes SET last_seen = NOW() - INTERVAL '1 minute' WHERE id = $1",
                    &[&app.node],
                )
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        for task in self.tasks.iter().flatten() {
            task.abort();
        }
    }
}

/// A node with a KMS whose root key is a file's (random, the test's own).
/// `None` if there's no database to test against.
pub async fn kms_node() -> Option<Arc<App>> {
    let app = node_with(Config::default(), None).await?;
    let mut app = Arc::into_inner(app).expect("a new node isn't shared");
    let mut root = [0u8; 32];
    getrandom::fill(&mut root).unwrap();
    let kms = crate::kms::Kms::with_root(crate::kms::Root::File(zeroize::Zeroizing::new(root)));
    kms.check_root(&app.pool).await.unwrap();
    app.kms = Some(Arc::new(kms));
    Some(Arc::new(app))
}

/// Writes an object as PutObject does, with a body that doesn't declare its
/// length (in chunked transfer encoding), so that its blob is replicated.
pub async fn put(app: &Arc<App>, key: &str, data: Vec<u8>) {
    put_with(app, key, data, Payload::unchecked()).await
}

/// Like `put`, with a body that declares its length, as most do: a large one
/// is coded as it's written, while coding is on.
pub async fn put_sized(app: &Arc<App>, key: &str, data: Vec<u8>) {
    let payload = Payload::unchecked_of(data.len() as u64);
    put_with(app, key, data, payload).await
}

async fn put_with(app: &Arc<App>, key: &str, data: Vec<u8>, payload: Payload) {
    put_into(app, BUCKET, key, data, payload).await;
}

/// Like `put`, into `bucket`; the version ID it reports, if any.
pub async fn put_to(app: &Arc<App>, bucket: &str, key: &str, data: Vec<u8>) -> String {
    put_into(app, bucket, key, data, Payload::unchecked())
        .await
        .unwrap_or_default()
}

async fn put_into(
    app: &Arc<App>,
    bucket: &str,
    key: &str,
    data: Vec<u8>,
    payload: Payload,
) -> Option<String> {
    let attach = AttachTarget::Object {
        storage_class: crate::classes::STANDARD.to_owned(),
        bucket: bucket.to_owned(),
        key: key.to_owned(),
        content_type: "application/octet-stream".to_owned(),
        metadata: String::new(),
        conditions: Preconditions::default(),
        sealing: None,
        checksum: crate::e2e::OBJECT_CHECKSUM,
        tags: String::new(),
        lock: Default::default(),
    };
    let body = Full::new(Bytes::from(data));
    let result = crate::upload_part(app, body, &attach, payload)
        .await
        .unwrap();
    match result {
        UploadResult::Committed { version_id, .. } => version_id,
        _ => panic!("the write wasn't committed"),
    }
}

/// Reads an object through GetObject; `None` if it doesn't exist.
pub async fn get(app: &Arc<App>, key: &str) -> Option<Vec<u8>> {
    let response = objects::get::get_object(
        app,
        BUCKET,
        key,
        None,
        None,
        None,
        &Preconditions::default(),
        None,
        None,
        false,
    )
    .await
    .unwrap();
    if response.status() == StatusCode::NOT_FOUND {
        return None;
    }
    assert_eq!(response.status(), StatusCode::OK);
    Some(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
}

/// A client's SSE-C key, as a request over HTTPS supplies it.
pub fn customer_key(key: &crate::encryption::Key) -> crate::s3::sse_c::CustomerKey {
    use crate::s3::sse_c::HEADERS;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use md5::Digest;
    let mut headers = hyper::HeaderMap::new();
    for (name, value) in [
        (
            "x-amz-server-side-encryption-customer-algorithm",
            "AES256".to_owned(),
        ),
        (
            "x-amz-server-side-encryption-customer-key",
            STANDARD.encode(key),
        ),
        (
            "x-amz-server-side-encryption-customer-key-md5",
            STANDARD.encode(md5::Md5::digest(key)),
        ),
    ] {
        headers.insert(name, value.parse().unwrap());
    }
    crate::s3::sse_c::requested(&headers, &HEADERS, true)
        .ok()
        .flatten()
        .unwrap()
}

/// Writes `data` as `key`, encrypted with the SSE-C `customer` key. Its ETag.
pub async fn put_sealed(
    app: &Arc<App>,
    key: &str,
    data: Vec<u8>,
    customer: &crate::s3::sse_c::CustomerKey,
) -> String {
    put_sealed_with(app, key, data, customer, Payload::unchecked()).await
}

/// Like `put_sealed`, with a body that declares its length (see `put_sized`).
pub async fn put_sealed_sized(
    app: &Arc<App>,
    key: &str,
    data: Vec<u8>,
    customer: &crate::s3::sse_c::CustomerKey,
) -> String {
    let payload = Payload::unchecked_of(data.len() as u64);
    put_sealed_with(app, key, data, customer, payload).await
}

async fn put_sealed_with(
    app: &Arc<App>,
    key: &str,
    data: Vec<u8>,
    customer: &crate::s3::sse_c::CustomerKey,
    payload: Payload,
) -> String {
    let attach = AttachTarget::Object {
        storage_class: crate::classes::STANDARD.to_owned(),
        bucket: BUCKET.to_owned(),
        key: key.to_owned(),
        content_type: "application/octet-stream".to_owned(),
        metadata: String::new(),
        conditions: Preconditions::default(),
        sealing: Some(crate::s3::sse::seal_customer(customer, BUCKET, key)),
        checksum: crate::e2e::OBJECT_CHECKSUM,
        tags: String::new(),
        lock: Default::default(),
    };
    let result = crate::upload_part(app, Full::new(Bytes::from(data)), &attach, payload)
        .await
        .unwrap();
    let UploadResult::Committed { etag, .. } = result else {
        panic!("not committed")
    };
    etag
}

/// Reads (the `range` of) an SSE-C object through GetObject: its status and body.
pub async fn get_sealed(
    app: &Arc<App>,
    key: &str,
    range: Option<&str>,
    customer: Option<&crate::s3::sse_c::CustomerKey>,
) -> (StatusCode, Vec<u8>) {
    let response = objects::get::get_object(
        app,
        BUCKET,
        key,
        None,
        range,
        None,
        &Preconditions::default(),
        customer,
        None,
        false,
    )
    .await
    .unwrap();
    let status = response.status();
    (
        status,
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
}

pub async fn delete(app: &Arc<App>, key: &str) {
    let response = objects::delete::delete_object(
        app,
        BUCKET,
        key,
        None,
        false,
        None,
        crate::mfa::Presented::Absent,
    )
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
