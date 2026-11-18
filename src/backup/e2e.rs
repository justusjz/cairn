//! End-to-end tests of backups and restores: a node backs up to another
//! node's S3 API (so the client's requests are checked as S3 checks them),
//! and a new database is restored from that.

use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{StatusCode, body::Bytes};
use tokio_postgres::NoTls;
use uuid::Uuid;

use super::restore::{RestoreArgs, restore_main, restore_one};
use crate::admin::e2e::cairn;
use crate::e2e::{BUCKET, delete, get, node_with, node_with_pools, put, query_i64};
use crate::s3::conditional::Preconditions;
use crate::{App, packer};

/// A node serving its S3 API on a port of its own, with an admin's key:
/// the target. Stops serving when the returned sender is dropped.
struct Target {
    app: Arc<App>,
    address: std::net::SocketAddr,
    key_id: String,
    secret: String,
    _stop: tokio::sync::oneshot::Sender<()>,
}

async fn target() -> Option<Target> {
    let app = node_with(packer::Config::default(), None).await?;
    let out = cairn(&app, &["user", "create", "backups", "--admin", "--key"]).await;
    let key_id = out.stdout.lines().find_map(|l| l.strip_prefix("access key: ")).unwrap().to_owned();
    let secret = out.stdout.lines().find_map(|l| l.strip_prefix("secret key: ")).unwrap().to_owned();
    let address = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    {
        let app = app.clone();
        // On a runtime of its own, whose threads have the stack a debug
        // build's request needs.
        std::thread::Builder::new()
            .stack_size(64 << 20)
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .thread_stack_size(64 << 20)
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(crate::serve_client(address, 64, app, async {
                    let _ = stopped.await;
                }))
            })
            .unwrap();
    }
    // Until it listens.
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(address).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Some(Target { app, address, key_id, secret, _stop: stop })
}

/// A new, empty database's URL.
async fn empty_database() -> String {
    let url = std::env::var("CAIRN_TEST_DATABASE").unwrap();
    let (admin, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(connection);
    let name = format!("cairn_test_{}", Uuid::new_v4().simple());
    admin.execute(&format!("CREATE DATABASE {name}"), &[]).await.unwrap();
    let (server, _) = url.rsplit_once('/').unwrap();
    format!("{server}/{name}")
}

fn content(i: usize, len: usize) -> Vec<u8> {
    (0..len).map(|j| (i * 31 + j * 7 + j / 251) as u8).collect()
}

/// Turns the backup on, to `prefix` of the target's bucket.
async fn enable(app: &Arc<App>, target: &Target, prefix: &str, extra: &[&str]) -> String {
    let endpoint = format!("http://{}", target.address);
    let mut args = vec![
        "backup", "enable", "--endpoint", &endpoint, "--bucket", BUCKET, "--prefix", prefix, "--path-style",
        "--access-key-id", &target.key_id, "--secret-access-key", &target.secret, "--pack-size", "5MiB",
    ];
    args.extend_from_slice(extra);
    let out = cairn(app, &args).await;
    assert_eq!(out.error, None, "{}", out.stderr);
    out.stdout.lines().find_map(|l| l.strip_prefix("key: ")).unwrap().to_owned()
}

/// Runs what's due of the backup, now.
async fn cycle(app: &Arc<App>, token: Uuid) -> super::Report {
    let out = cairn(app, &["backup", "now"]).await;
    assert_eq!(out.error, None);
    match super::step(app, token).await {
        Ok(report) => report.expect("a cycle was due"),
        Err(e) => panic!("{e:?}"),
    }
}

fn restore_args(database: &str, target: &Target, prefix: &str, key: &str, at: Option<i64>) -> RestoreArgs {
    RestoreArgs {
        database: database.to_owned(),
        location: super::LocationArgs {
            endpoint: format!("http://{}", target.address),
            region: "us-east-1".to_owned(),
            bucket: BUCKET.to_owned(),
            prefix: prefix.to_owned(),
            path_style: true,
            access_key_id: target.key_id.clone(),
            secret_access_key: target.secret.clone(),
        },
        key: key.to_owned(),
        at,
        list: false,
    }
}

/// A node on a restored database.
async fn restored_node(database: &str) -> Arc<App> {
    let pool = crate::db::connect(database).await.unwrap();
    let app = node_with_pools(&pool, "http://127.0.0.1:1", packer::Config::default(), None, 1, &[crate::classes::DEFAULT_POOL])
        .await;
    crate::refresh_settings(&app).await.unwrap();
    app
}

async fn copy(app: &Arc<App>, source: &str, key: &str) {
    let source = format!("{BUCKET}/{source}");
    let response = crate::s3::objects::copy::copy_object(
        app, BUCKET, key, &source, None, "text/plain", "", None, &Preconditions::default(), Default::default(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// A cluster's objects, users and settings come back from its backup: read
/// from the backup at once, and copied into the new cluster after.
#[tokio::test]
async fn a_cluster_comes_back_from_its_backup() {
    let Some(target) = target().await else { return };
    let app = node_with(packer::Config::default(), None).await.unwrap();
    // What's there before the backup begins, and what comes after.
    for i in 0..20 {
        put(&app, &format!("before/{i}"), content(i, 1000 + i * 100)).await;
    }
    put(&app, "large", content(99, 7 << 20)).await;
    let out = cairn(&app, &["user", "create", "ada", "--key"]).await;
    assert_eq!(out.error, None);
    let key = enable(&app, &target, "cluster", &[]).await;
    let token = Uuid::new_v4();

    let report = cycle(&app, token).await;
    assert!(report.base.is_some(), "the first cycle takes a base");
    // The data from before was copied, more than a pack's worth: into packs.
    let objects = query_i64(&target.app, "SELECT count(*) FROM objects WHERE key LIKE 'cluster/pack/%'").await;
    assert!(objects >= 1);
    assert_eq!(query_i64(&app, "SELECT count(*) FROM parts p WHERE NOT EXISTS (SELECT 1 FROM backup_parts bp WHERE bp.part_id = p.id)").await, 0);

    for i in 0..10 {
        put(&app, &format!("after/{i}"), content(100 + i, 500 + i)).await;
    }
    copy(&app, "before/3", "copied").await;
    delete(&app, "before/0").await;
    cairn(&app, &["config", "set", "lifecycle-rate", "1234"]).await;
    let report = cycle(&app, token).await;
    assert!(report.base.is_none());
    let journal = &report.cycles[0];
    assert!(journal.changes > 0);
    assert_eq!(journal.parts, 11);
    // The copy shares its source's bytes, which were backed up already.
    let shared = query_i64(
        &app,
        "SELECT count(DISTINCT (bp.object, bp.\"offset\")) FROM backup_parts bp
         JOIN parts p ON p.id = bp.part_id JOIN objects o ON o.id = p.object_id
         WHERE o.key IN ('copied', 'before/3')",
    )
    .await;
    assert_eq!(shared, 1);
    // Changes after the last journal aren't in the backup.
    put(&app, "too-late", content(7, 10)).await;

    // Restore into a new database.
    let database = empty_database().await;
    restore_main(restore_args(&database, &target, "cluster", &key, None)).await.unwrap();
    let restored = restored_node(&database).await;
    // Readable at once, from the backup.
    assert!(query_i64(&restored, "SELECT count(*) FROM blobs WHERE state = 'restoring'").await > 0);
    assert_eq!(query_i64(&restored, "SELECT count(*) FROM blob_locations").await, 0);
    for i in 1..20 {
        assert_eq!(get(&restored, &format!("before/{i}")).await, Some(content(i, 1000 + i * 100)), "before/{i}");
    }
    assert_eq!(get(&restored, "before/0").await, None);
    assert_eq!(get(&restored, "copied").await, Some(content(3, 1300)));
    assert_eq!(get(&restored, "large").await, Some(content(99, 7 << 20)));
    assert_eq!(get(&restored, "too-late").await, None);
    let out = cairn(&restored, &["config", "get", "lifecycle-rate"]).await;
    assert!(out.stdout.contains("1234"), "{}", out.stdout);
    assert_eq!(query_i64(&restored, "SELECT count(*) FROM users WHERE name = 'ada'").await, 1);
    let out = cairn(&restored, &["backup", "status"]).await;
    assert!(out.stdout.contains("copying the data into the cluster"), "{}", out.stdout);

    // Then copied into the cluster.
    while restore_one(&restored).await.unwrap() {}
    assert_eq!(query_i64(&restored, "SELECT count(*) FROM blobs WHERE state = 'restoring'").await, 0);
    assert_eq!(query_i64(&restored, "SELECT count(*) FROM restore_source WHERE state = 'done'").await, 1);
    for i in 0..10 {
        assert_eq!(get(&restored, &format!("after/{i}")).await, Some(content(100 + i, 500 + i)), "after/{i}");
    }
    assert_eq!(get(&restored, "copied").await, Some(content(3, 1300)));
    assert_eq!(get(&restored, "large").await, Some(content(99, 7 << 20)));
    // New writes work, and new ids don't collide with restored ones.
    put(&restored, "new", content(5, 5)).await;
    assert_eq!(get(&restored, "new").await, Some(content(5, 5)));
}

/// A restore goes back to the journal it's asked for, and the backup
/// deletes what nothing needs once the retention is over.
#[tokio::test]
async fn restores_to_a_point_in_time_and_sweeps() {
    let Some(target) = target().await else { return };
    let app = node_with(packer::Config::default(), None).await.unwrap();
    let key = enable(&app, &target, "pitr", &["--retention", "0s"]).await;
    let token = Uuid::new_v4();
    put(&app, "a", content(1, 6 << 20)).await;
    cycle(&app, token).await;
    let first = super::cycle::now_millis();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    delete(&app, "a").await;
    put(&app, "b", content(2, 100)).await;
    cycle(&app, token).await;
    // The pack of `a` is unneeded now: with no retention, it's deleted.
    let packs = || query_i64(&target.app, "SELECT count(*) FROM objects WHERE key LIKE 'pitr/pack/%'");
    let report = cycle(&app, token).await;
    let _ = report;
    assert_eq!(packs().await, 0);

    // As of the latest journal: b, but not a.
    let database = empty_database().await;
    restore_main(restore_args(&database, &target, "pitr", &key, None)).await.unwrap();
    let restored = restored_node(&database).await;
    assert_eq!(get(&restored, "a").await, None);
    assert_eq!(get(&restored, "b").await, Some(content(2, 100)));

    // As of the first: a, whose pack was deleted, so it's lost.
    let database = empty_database().await;
    restore_main(restore_args(&database, &target, "pitr", &key, Some(first))).await.unwrap();
    let restored = restored_node(&database).await;
    assert_eq!(get(&restored, "b").await, None);
    let response = crate::s3::objects::get::get_object(
        &restored, BUCKET, "a", None, None, None, &Preconditions::default(), None, None, false,
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR, "its bytes are lost");
    let _ = response.into_body().collect().await;
}

/// The journals of a quiet cluster are packed after a while, and a pack
/// that's mostly garbage is rewritten.
#[tokio::test]
async fn journals_are_packed_and_garbage_rewritten() {
    let Some(target) = target().await else { return };
    let app = node_with(packer::Config::default(), None).await.unwrap();
    enable(&app, &target, "seal", &["--retention", "0s"]).await;
    let token = Uuid::new_v4();
    cycle(&app, token).await;
    for i in 0..3 {
        put(&app, &format!("small/{i}"), content(i, 2 << 20)).await;
        cycle(&app, token).await;
    }
    let live_journals = "SELECT count(*) FROM backup_objects WHERE kind = 'journal' AND refs > 0";
    assert_eq!(query_i64(&app, live_journals).await, 3);
    // Six MiB in journals: more than a pack's worth, so they're packed.
    put(&app, "trigger", content(9, 10)).await;
    cycle(&app, token).await;
    assert_eq!(query_i64(&app, live_journals).await, 1, "only the last cycle's journal holds data");
    assert_eq!(query_i64(&app, "SELECT sum(refs)::bigint FROM backup_objects WHERE kind = 'pack'").await, 3);
    for i in 0..3 {
        delete(&app, &format!("small/{i}")).await;
    }
    cycle(&app, token).await;
    // Unneeded, and no retention: deleted.
    assert_eq!(query_i64(&app, "SELECT count(*) FROM backup_objects WHERE kind = 'pack'").await, 0);
    assert_eq!(query_i64(&target.app, "SELECT count(*) FROM objects WHERE key LIKE 'seal/pack/%'").await, 0);

    // A pack's worth, exactly: one pack. Once less than a tenth of it is
    // left, that's rewritten.
    put(&app, "big", content(3, (5 << 20) - (200 << 10))).await;
    put(&app, "keep", content(4, 200 << 10)).await;
    cycle(&app, token).await;
    assert_eq!(query_i64(&app, "SELECT count(*) FROM backup_objects WHERE kind = 'pack'").await, 1);
    let first: Uuid = app
        .pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT id FROM backup_objects WHERE kind = 'pack'", &[])
        .await
        .unwrap()
        .get(0);
    delete(&app, "big").await;
    cycle(&app, token).await;
    cycle(&app, token).await;
    let rows = app
        .pool
        .get()
        .await
        .unwrap()
        .query("SELECT id, refs FROM backup_objects WHERE kind = 'pack'", &[])
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_ne!(rows[0].get::<_, Uuid>(0), first, "the pack was rewritten");
    assert_eq!(rows[0].get::<_, i64>(1), 1);
    assert_eq!(query_i64(&app, "SELECT count(*) FROM backup_parts").await, 2, "keep and trigger");
    let _ = (Bytes::new(), Full::new(Bytes::new()));
}
