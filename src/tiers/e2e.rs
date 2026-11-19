//! End-to-end tests of remote tiers (see `crate::e2e`): a class's data moved
//! into a tier (another node's S3 API, as in the backup's tests), read back
//! from it, compacted and deleted there, brought back, and backed up and
//! restored without being copied.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::{StatusCode, body::Bytes};
use uuid::Uuid;

use crate::admin::e2e::cairn;
use crate::backup::e2e::{Target, empty_database, enable, keep_alive, restore_args, restored_node, settle, target};
use crate::e2e::{BUCKET, OBJECT_CHECKSUM, delete, get, node_with, put, query_i64};
use crate::payload::Payload;
use crate::s3::conditional::Preconditions;
use crate::{App, AttachTarget, UploadResult, packer};

/// Packing on a small scale, with nothing waiting: data goes into the tier
/// at the first pass, and what's unneeded there is deleted at once.
fn config() -> packer::Config {
    packer::Config {
        target_size: 20_000,
        small_size: 5_000,
        offload_after: Duration::ZERO,
        tier_hold: Duration::ZERO,
        ..packer::Config::default()
    }
}

fn content(i: usize, len: usize) -> Vec<u8> {
    (0..len).map(|j| (i * 37 + j * 11 + j / 253) as u8).collect()
}

/// Adds tier `name` at `prefix` of the target's bucket, and the class
/// `class` that keeps its data there.
async fn add_tier(app: &Arc<App>, target: &Target, name: &str, prefix: &str, class: &str) {
    let endpoint = format!("http://{}", target.address);
    let out = cairn(
        app,
        &[
            "tier", "add", name, "--endpoint", &endpoint, "--bucket", BUCKET, "--prefix", prefix, "--path-style",
            "--access-key-id", &target.key_id, "--secret-access-key", &target.secret,
        ],
    )
    .await;
    assert_eq!(out.error, None, "{}", out.stderr);
    let out = cairn(app, &["class", "set", class, "--tier", name]).await;
    assert_eq!(out.error, None, "{}", out.stderr);
    crate::refresh_settings(app).await.unwrap();
}

/// Writes `key` in class `class`, as PutObject does.
async fn put_in(app: &Arc<App>, key: &str, class: &str, body: Vec<u8>) {
    let attach = AttachTarget::Object {
        storage_class: class.to_owned(),
        bucket: BUCKET.to_owned(),
        key: key.to_owned(),
        content_type: "application/octet-stream".to_owned(),
        metadata: String::new(),
        conditions: Preconditions::default(),
        sealing: None,
        checksum: OBJECT_CHECKSUM,
        tags: String::new(),
        lock: Default::default(),
    };
    let result = crate::upload_part(app, Full::new(Bytes::from(body)), &attach, Payload::unchecked()).await.unwrap();
    assert!(matches!(result, UploadResult::Committed { .. }));
}

/// Bytes [`start`, `end`] of `key`, through a ranged GetObject.
async fn get_range(app: &Arc<App>, key: &str, start: u64, end: u64) -> Vec<u8> {
    let range = format!("bytes={start}-{end}");
    let response = crate::s3::objects::get::get_object(
        app, BUCKET, key, None, Some(&range), None, &Preconditions::default(), None, None, false,
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    response.into_body().collect().await.unwrap().to_bytes().to_vec()
}

/// The names of the objects under `prefix` in the target's bucket.
async fn tier_objects(target: &Target, prefix: &str) -> Vec<String> {
    let client = target.app.pool.get().await.unwrap();
    client
        .query(
            "SELECT key FROM objects WHERE bucket = $1 AND key LIKE $2 || '%' AND is_latest AND NOT is_delete_marker
             ORDER BY key",
            &[&BUCKET, &prefix],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect()
}

/// Runs packer passes until one does nothing (or ten did something).
async fn settle_packer(app: &Arc<App>) -> Vec<packer::JobReport> {
    let mut all = Vec::new();
    for _ in 0..10 {
        let reports = packer::pass(app).await.unwrap();
        if reports.is_empty() {
            break;
        }
        all.extend(reports);
    }
    all
}

/// The keys of the objects with parts in blob `blob`.
async fn keys_in(app: &App, blob: Uuid) -> Vec<String> {
    app.pool
        .get()
        .await
        .unwrap()
        .query(
            "SELECT DISTINCT o.key FROM parts p JOIN objects o ON o.id = p.object_id WHERE p.blob_id = $1 ORDER BY 1",
            &[&blob],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect()
}

/// A class's data goes into its tier, encrypted and packed; it's read from
/// there, whole and in ranges; what's deleted is compacted away there; a
/// read-only tier is left alone; and a class taken off its tier gets its
/// data back.
#[tokio::test]
async fn a_class_keeps_its_data_in_a_tier() {
    let Some(target) = target().await else { return };
    let Some(app) = node_with(config(), None).await else { return };
    keep_alive(&app);
    add_tier(&app, &target, "archive", "tier/", "COLD").await;

    let cold: Vec<(String, Vec<u8>)> = (0..20).map(|i| (format!("cold/{i:02}"), content(i, 3000))).collect();
    for (key, data) in &cold {
        put_in(&app, key, "COLD", data.clone()).await;
    }
    put(&app, "warm", content(99, 3000)).await;
    // Written into the cluster first, as STANDARD would be.
    assert_eq!(
        query_i64(&app, "SELECT count(*) FROM blobs WHERE storage_class = 'COLD' AND state = 'committed'").await,
        20
    );

    // Moved into the tier: 60 kB, in blobs of 20 kB.
    let reports = settle_packer(&app).await;
    assert!(reports.iter().any(|r| r.kind == packer::Kind::Offload), "nothing moved into the tier");
    assert_eq!(
        query_i64(&app, "SELECT count(*) FROM blobs WHERE storage_class = 'COLD' AND state = 'committed'").await,
        0
    );
    let remote = query_i64(&app, "SELECT count(*) FROM blobs WHERE state = 'remote'").await;
    assert_eq!(remote, 3);
    assert_eq!(
        query_i64(&app, "SELECT count(*) FROM blob_locations bl JOIN blobs b USING (blob_id) WHERE b.state = 'remote'")
            .await,
        0
    );
    assert_eq!(query_i64(&app, "SELECT count(*) FROM blobs WHERE storage_class = 'STANDARD'").await, 1);
    let objects = tier_objects(&target, "tier/blobs/").await;
    assert_eq!(objects.len(), 3);
    // Sealed: nothing of the data shows.
    let stored = get(&target.app, &objects[0]).await.unwrap();
    assert!(stored.starts_with(b"CAIRNBK1"));
    for (_, data) in &cold {
        assert!(!stored.windows(64).any(|w| w == &data[1000..1064]));
    }

    // Read from the tier, whole and in ranges.
    for (key, data) in &cold {
        assert_eq!(get(&app, key).await.as_deref(), Some(&data[..]), "{key}");
    }
    let (key, data) = &cold[7];
    assert_eq!(get_range(&app, key, 100, 2099).await, data[100..2100]);
    assert_eq!(get_range(&app, key, 2999, 2999).await, data[2999..]);
    let listed = cairn(&app, &["tier", "list"]).await;
    assert!(listed.stdout.contains("archive: s3://bucket/tier/"), "{}", listed.stdout);
    assert!(listed.stdout.contains("classes: COLD; 3 objects, 60000 bytes live"), "{}", listed.stdout);

    // A remote blob mostly deleted is compacted into a new one, and its
    // object is deleted from the tier.
    let blob: Uuid = app
        .pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT blob_id FROM blobs WHERE state = 'remote' ORDER BY blob_id LIMIT 1", &[])
        .await
        .unwrap()
        .get(0);
    let keys = keys_in(&app, blob).await;
    assert!(keys.len() > 2);
    for key in &keys[1..] {
        delete(&app, key).await;
    }
    let reports = settle_packer(&app).await;
    assert!(reports.iter().any(|r| r.kind == packer::Kind::Offload), "nothing compacted");
    assert_eq!(query_i64(&app, &format!("SELECT count(*) FROM blobs WHERE blob_id = '{blob}'")).await, 0);
    assert_eq!(query_i64(&app, "SELECT count(*) FROM tier_garbage").await, 0);
    let objects = tier_objects(&target, "tier/blobs/").await;
    assert_eq!(objects.len(), 3);
    assert!(!objects.contains(&crate::tiers::object_name(blob).replace("blobs/", "tier/blobs/")));
    let kept = &keys[0];
    let index: usize = kept.trim_start_matches("cold/").parse().unwrap();
    assert_eq!(get(&app, kept).await.unwrap(), cold[index].1);

    // A read-only tier gets nothing new, and keeps what's deleted.
    let out = cairn(&app, &["tier", "set", "archive", "--writable", "false"]).await;
    assert_eq!(out.error, None, "{}", out.stderr);
    put_in(&app, "cold/late", "COLD", content(50, 3000)).await;
    delete(&app, kept).await;
    settle_packer(&app).await;
    assert_eq!(
        query_i64(&app, "SELECT count(*) FROM blobs WHERE storage_class = 'COLD' AND state = 'committed'").await,
        1
    );
    assert_eq!(query_i64(&app, "SELECT count(*) FROM tier_garbage").await, 1);
    assert_eq!(tier_objects(&target, "tier/blobs/").await.len(), 3);
    // Writable again: both go ahead.
    let out = cairn(&app, &["tier", "set", "archive", "--writable", "true"]).await;
    assert_eq!(out.error, None, "{}", out.stderr);
    settle_packer(&app).await;
    assert_eq!(
        query_i64(&app, "SELECT count(*) FROM blobs WHERE storage_class = 'COLD' AND state = 'committed'").await,
        0
    );
    assert_eq!(query_i64(&app, "SELECT count(*) FROM tier_garbage").await, 0);
    assert_eq!(tier_objects(&target, "tier/blobs/").await.len(), 3);
    assert_eq!(get(&app, "cold/late").await.unwrap(), content(50, 3000));

    // Taken off the tier: its data comes back into the cluster, and the
    // tier is emptied.
    let out = cairn(&app, &["class", "set", "COLD", "--pool", "default"]).await;
    assert_eq!(out.error, None, "{}", out.stderr);
    crate::refresh_settings(&app).await.unwrap();
    settle_packer(&app).await;
    assert_eq!(query_i64(&app, "SELECT count(*) FROM blobs WHERE state = 'remote'").await, 0);
    assert!(tier_objects(&target, "tier/").await.is_empty());
    let deleted: Vec<&String> = keys.iter().collect();
    for (key, data) in &cold {
        if deleted.contains(&key) {
            assert_eq!(get(&app, key).await, None);
        } else {
            assert_eq!(get(&app, key).await.as_deref(), Some(&data[..]), "{key}");
        }
    }
    assert_eq!(get(&app, "cold/late").await.unwrap(), content(50, 3000));
    assert_eq!(get(&app, "warm").await.unwrap(), content(99, 3000));
    // Now the tier can go, since nothing is in it, and no class names it.
    let out = cairn(&app, &["tier", "delete", "archive"]).await;
    assert_eq!(out.error, None, "{}", out.stderr);
    assert_eq!(query_i64(&app, "SELECT count(*) FROM tiers").await, 0);
}

/// A tier can't be deleted while a class keeps its data there, or it holds
/// objects.
#[tokio::test]
async fn a_tier_in_use_stays() {
    let Some(target) = target().await else { return };
    let Some(app) = node_with(config(), None).await else { return };
    keep_alive(&app);
    add_tier(&app, &target, "archive", "tier/", "COLD").await;
    let out = cairn(&app, &["tier", "delete", "archive"]).await;
    assert!(out.error.as_deref().is_some_and(|e| e.contains("still has classes")), "{:?}", out.error);
    put_in(&app, "cold", "COLD", content(1, 3000)).await;
    settle_packer(&app).await;
    assert_eq!(query_i64(&app, "SELECT count(*) FROM blobs WHERE state = 'remote'").await, 1);
    // Pointing the class elsewhere isn't enough while its data is there.
    let out = cairn(&app, &["class", "set", "COLD", "--pool", "default"]).await;
    assert_eq!(out.error, None, "{}", out.stderr);
    let out = cairn(&app, &["tier", "delete", "archive"]).await;
    assert!(out.error.is_some(), "the tier still holds an object");
    // A tier's class has no layout of its own.
    let out = cairn(&app, &["class", "set", "OTHER", "--tier", "archive", "--parity-shards", "1"]).await;
    assert!(out.error.as_deref().is_some_and(|e| e.contains("STANDARD's layout")), "{:?}", out.error);
    let out = cairn(&app, &["class", "set", "OTHER", "--tier", "nowhere"]).await;
    assert!(out.error.as_deref().is_some_and(|e| e.contains("no tier nowhere")), "{:?}", out.error);
}

/// The backup points the parts in a tier at its objects, rather than
/// copying them, and a restore reads them from there, read-only, until the
/// tier is given to it.
#[tokio::test]
async fn backups_leave_tiers_data_where_it_is() {
    let Some(target) = target().await else { return };
    let Some(app) = node_with(config(), None).await else { return };
    keep_alive(&app);
    add_tier(&app, &target, "archive", "tier/", "COLD").await;
    let key = enable(&app, &target, "backup/", &["--retention", "0s"]).await;
    let token = Uuid::new_v4();

    // Backed up as they're written, while they're in the cluster.
    let early: Vec<(String, Vec<u8>)> = (0..10).map(|i| (format!("cold/early-{i}"), content(i, 3000))).collect();
    for (key, data) in &early {
        put_in(&app, key, "COLD", data.clone()).await;
    }
    put(&app, "warm", content(99, 3000)).await;
    settle(&app, token).await;
    let in_packs = "SELECT count(*) FROM backup_parts bp JOIN backup_objects o ON o.id = bp.object WHERE o.kind <> 'tier'";
    let in_tiers = "SELECT count(*) FROM backup_parts bp JOIN backup_objects o ON o.id = bp.object WHERE o.kind = 'tier'";
    assert_eq!(query_i64(&app, in_packs).await, 11);

    // Moved into the tier: the backup points them there, and lets go of
    // its own copies.
    settle_packer(&app).await;
    assert!(query_i64(&app, "SELECT count(*) FROM backup_tier_moves").await > 0);
    let report = super::super::backup::e2e::cycle(&app, token).await;
    assert!(!report.cycles.is_empty());
    assert_eq!(query_i64(&app, "SELECT count(*) FROM backup_tier_moves").await, 0);
    assert_eq!(query_i64(&app, in_tiers).await, 10);
    assert_eq!(query_i64(&app, in_packs).await, 1);

    // Written and moved between cycles: never copied.
    let late: Vec<(String, Vec<u8>)> = (10..20).map(|i| (format!("cold/late-{i}"), content(i, 3000))).collect();
    for (key, data) in &late {
        put_in(&app, key, "COLD", data.clone()).await;
    }
    settle_packer(&app).await;
    let before = query_i64(&app, "SELECT coalesce(sum(size), 0)::bigint FROM backup_objects WHERE kind <> 'tier'").await;
    super::super::backup::e2e::cycle(&app, token).await;
    assert_eq!(query_i64(&app, in_tiers).await, 20);
    let after = query_i64(&app, "SELECT coalesce(sum(size), 0)::bigint FROM backup_objects WHERE kind <> 'tier'").await;
    assert!(after - before < 20_000, "the late parts' bytes were copied into the backup ({before} → {after})");
    let status = cairn(&app, &["backup", "status"]).await;
    assert!(status.stdout.contains("in tiers, not copied"), "{}", status.stdout);

    // Restored: read from the tier, which is read-only.
    let database = empty_database().await;
    crate::backup::restore::restore_main(restore_args(&database, &target, "backup/", &key, None)).await.unwrap();
    let restored = restored_node(&database).await;
    assert_eq!(query_i64(&restored, "SELECT count(*) FROM blobs WHERE state = 'remote'").await, query_i64(&app, "SELECT count(*) FROM blobs WHERE state = 'remote'").await);
    assert_eq!(query_i64(&restored, "SELECT count(*) FROM tiers WHERE writable").await, 0);
    for (key, data) in early.iter().chain(&late) {
        assert_eq!(get(&restored, key).await.as_deref(), Some(&data[..]), "{key}");
    }
    assert_eq!(get(&restored, "warm").await.unwrap(), content(99, 3000));

    // It writes nothing there, and deletes nothing from there.
    let objects = tier_objects(&target, "tier/blobs/").await;
    put_in(&restored, "cold/restored", "COLD", content(77, 3000)).await;
    for (key, _) in &early {
        delete(&restored, key).await;
    }
    settle_packer(&restored).await;
    // (Its tier's hold is an hour: as if it had passed.)
    restored.pool.get().await.unwrap().execute("UPDATE tier_garbage SET dropped_at = now() - interval '2 hours'", &[]).await.unwrap();
    settle_packer(&restored).await;
    assert_eq!(tier_objects(&target, "tier/blobs/").await, objects);
    assert_eq!(
        query_i64(&restored, "SELECT count(*) FROM blobs WHERE storage_class = 'COLD' AND state = 'committed'").await,
        1
    );
    // The original still reads everything.
    for (key, data) in early.iter().chain(&late) {
        assert_eq!(get(&app, key).await.as_deref(), Some(&data[..]), "{key}");
    }

    // Given the tier: what it doesn't need goes, what it wrote moves there.
    let out = cairn(&restored, &["tier", "set", "archive", "--writable", "true"]).await;
    assert_eq!(out.error, None, "{}", out.stderr);
    restored.pool.get().await.unwrap().execute("UPDATE tier_garbage SET dropped_at = now() - interval '2 hours'", &[]).await.unwrap();
    // (Its offloads wait a day: as if it had passed.)
    restored
        .pool
        .get()
        .await
        .unwrap()
        .execute("UPDATE blobs SET created_at = now() - interval '2 days' WHERE state = 'committed'", &[])
        .await
        .unwrap();
    settle_packer(&restored).await;
    restored.pool.get().await.unwrap().execute("UPDATE tier_garbage SET dropped_at = now() - interval '2 hours'", &[]).await.unwrap();
    settle_packer(&restored).await;
    assert_eq!(
        query_i64(&restored, "SELECT count(*) FROM blobs WHERE storage_class = 'COLD' AND state = 'committed'").await,
        0
    );
    assert_eq!(query_i64(&restored, "SELECT count(*) FROM tier_garbage").await, 0);
    assert_ne!(tier_objects(&target, "tier/blobs/").await, objects);
    for (key, data) in &late {
        assert_eq!(get(&restored, key).await.as_deref(), Some(&data[..]), "{key}");
    }
    assert_eq!(get(&restored, "cold/restored").await.unwrap(), content(77, 3000));
}

/// Cold remote classes are refused: their objects can't be read without a
/// restore.
#[tokio::test]
async fn cold_tiers_are_refused() {
    let Some(target) = target().await else { return };
    let app = target.app.clone();
    let endpoint = format!("http://{}", target.address);
    let out = cairn(
        &app,
        &[
            "tier", "add", "deep", "--endpoint", &endpoint, "--bucket", BUCKET, "--prefix", "deep/", "--path-style",
            "--access-key-id", &target.key_id, "--secret-access-key", &target.secret, "--remote-class", "DEEP_ARCHIVE",
        ],
    )
    .await;
    assert!(out.error.as_deref().is_some_and(|e| e.contains("restoring")), "{:?}", out.error);
    // A prefix that holds objects isn't a tier's own.
    put(&app, "taken/x", vec![1, 2, 3]).await;
    let out = cairn(
        &app,
        &[
            "tier", "add", "taken", "--endpoint", &endpoint, "--bucket", BUCKET, "--prefix", "taken/", "--path-style",
            "--access-key-id", &target.key_id, "--secret-access-key", &target.secret,
        ],
    )
    .await;
    assert!(out.error.as_deref().is_some_and(|e| e.contains("prefix of its own")), "{:?}", out.error);
}
