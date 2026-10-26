//! End-to-end tests of the packer (see `crate::e2e`).
//!
//! The races are staged with `App::pack_hook`, which runs a test's code at set
//! points of a packing job.

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use http_body_util::BodyExt;
use uuid::Uuid;

use super::{Config, Hook, Kind, Stage, pass};
use crate::{
    App,
    body::channel_body,
    e2e::{BUCKET, assert_files, assert_reaped, delete, get, node_with, put, query_i64},
    gc,
    s3::objects,
};

/// Packing on a small scale: new blobs of 100 KB, from blobs up to 25 KB. The
/// first 100 test objects (`data`) add up to about 193 KB, so packing them
/// writes two new blobs.
fn config() -> Config {
    Config {
        target_size: 100_000,
        small_size: 25_000,
        ..Config::default()
    }
}

/// A node of its own, on a fresh database, with the test config. `None` if
/// there's no database to test against.
async fn node(hook: Option<Hook>) -> Option<Arc<App>> {
    node_with(config(), hook).await
}

/// A hook that runs `f` at `stage`, the first time the stage is reached.
fn at<F, Fut>(stage: Stage, f: F) -> Hook
where
    F: Fn(Arc<App>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let done = AtomicBool::new(false);
    Arc::new(move |app, reached| -> Pin<Box<dyn Future<Output = ()> + Send>> {
        if reached == stage && !done.swap(true, Ordering::SeqCst) {
            Box::pin(f(app))
        } else {
            Box::pin(async {})
        }
    })
}

/// The content of the `i`th test object: sizes vary, and so do the bytes.
fn data(i: usize) -> Vec<u8> {
    content(i, 100 + i * 37)
}

fn content(i: usize, len: usize) -> Vec<u8> {
    (0..len).map(|j| (i * 7 + j * 13) as u8).collect()
}

fn key(i: usize) -> String {
    format!("o{i}")
}

/// Uploads objects 0..n.
async fn put_many(app: &Arc<App>, n: usize) {
    for i in 0..n {
        put(app, &key(i), data(i)).await;
    }
}

/// Every object 0..n except `deleted` reads back intact; the deleted are gone.
async fn assert_objects(app: &Arc<App>, n: usize, deleted: &[usize]) {
    for i in 0..n {
        let expected = (!deleted.contains(&i)).then(|| data(i));
        assert_eq!(get(app, &key(i)).await, expected, "object {i}");
    }
}

async fn blob_of(app: &App, key: &str) -> Uuid {
    let client = app.pool.get().await.unwrap();
    client
        .query_one(
            "SELECT p.blob_id FROM parts p JOIN objects o ON o.id = p.object_id
             WHERE o.bucket = $1 AND o.key = $2 AND o.is_latest",
            &[&BUCKET, &key],
        )
        .await
        .unwrap()
        .get(0)
}

/// Every byte of every referenced blob is a live part or counted as garbage.
/// Holds right after a pass, which folds the garbage log.
async fn assert_accounting(app: &App) {
    let blobs = query_i64(
        app,
        "SELECT coalesce(sum(b.size - b.dead_size), 0)::bigint FROM blobs b
         WHERE b.state = 'committed'
           AND EXISTS (SELECT 1 FROM parts p WHERE p.blob_id = b.blob_id)",
    )
    .await;
    let parts = query_i64(app, "SELECT coalesce(sum(size), 0)::bigint FROM parts").await;
    assert_eq!(blobs, parts, "live bytes in blobs vs. parts");
}

/// A blob that a packing job is writing.
async fn pending_blob(app: &App) -> Uuid {
    let client = app.pool.get().await.unwrap();
    client
        .query_one("SELECT blob_id FROM blobs WHERE state = 'pending' LIMIT 1", &[])
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
async fn consolidates_and_reads_back() {
    let Some(app) = node(None).await else { return };
    put_many(&app, 100).await;
    let reports = pass(&app).await.unwrap();
    assert_eq!(reports.len(), 1);
    assert!(matches!(reports[0].kind, Kind::Consolidate));
    assert_eq!((reports[0].sources, reports[0].parts), (100, 100));
    assert_eq!(reports[0].outputs.len(), 2);
    assert_eq!(query_i64(&app, "SELECT count(*) FROM blobs").await, 2);
    // About the same size, and far too large to be candidates again.
    let smallest = query_i64(&app, "SELECT min(size) FROM blobs").await;
    assert!(smallest > 90_000, "smallest new blob: {smallest} bytes");
    assert_files(&app, 2).await;
    assert_accounting(&app).await;
    assert_objects(&app, 100, &[]).await;
    // Nothing is left to do.
    assert!(pass(&app).await.unwrap().is_empty());
}

/// Small blobs that don't fill a new blob wait for more.
#[tokio::test]
async fn too_little_to_fill_a_blob_stays() {
    let Some(app) = node(None).await else { return };
    // About 50 KB.
    put_many(&app, 50).await;
    assert!(pass(&app).await.unwrap().is_empty());
    assert_files(&app, 50).await;
}

/// As many small blobs as a job may take are packed even if they don't fill a
/// new blob.
#[tokio::test]
async fn many_tiny_blobs_are_packed_anyway() {
    let pack = Config {
        max_sources: 30,
        ..config()
    };
    let Some(app) = node_with(pack, None).await else { return };
    put_many(&app, 40).await;
    let reports = pass(&app).await.unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!((reports[0].sources, reports[0].outputs.len()), (30, 1));
    // The other 10 wait.
    assert_files(&app, 11).await;
    assert_accounting(&app).await;
    assert_objects(&app, 40, &[]).await;
}

#[tokio::test]
async fn compacts_once_enough_is_garbage() {
    let Some(app) = node(None).await else { return };
    put_many(&app, 100).await;
    pass(&app).await.unwrap();
    // Objects 0-70 went to the first new blob, 71-99 to the second.
    let first = blob_of(&app, &key(0)).await;
    let second = blob_of(&app, &key(99)).await;
    assert_eq!(blob_of(&app, &key(70)).await, first);
    assert_eq!(blob_of(&app, &key(71)).await, second);
    // The 20 smallest objects are well under a quarter of the first blob.
    let mut deleted: Vec<usize> = (0..20).collect();
    for &i in &deleted {
        delete(&app, &key(i)).await;
    }
    assert!(pass(&app).await.unwrap().is_empty());
    assert_accounting(&app).await;
    // 30 more take it past a quarter.
    for i in 40..70 {
        delete(&app, &key(i)).await;
        deleted.push(i);
    }
    let reports = pass(&app).await.unwrap();
    assert_eq!(reports.len(), 1);
    assert!(matches!(reports[0].kind, Kind::Compact));
    assert_eq!((reports[0].sources, reports[0].parts), (1, 21));
    assert_ne!(blob_of(&app, &key(20)).await, first);
    assert_eq!(blob_of(&app, &key(99)).await, second);
    assert_eq!(query_i64(&app, "SELECT sum(dead_size)::bigint FROM blobs").await, 0);
    assert_files(&app, 2).await;
    assert_accounting(&app).await;
    assert_objects(&app, 100, &deleted).await;
}

/// Blobs that are each too full to fit two into a new blob are still packed
/// together: four blobs two-thirds live become three.
#[tokio::test]
async fn sparse_blobs_are_packed_into_fewer() {
    let Some(app) = node(None).await else { return };
    // 100 objects of 4000 bytes: four new blobs of 25 objects each.
    for i in 0..100 {
        put(&app, &key(i), content(i, 4000)).await;
    }
    let reports = pass(&app).await.unwrap();
    assert_eq!(reports[0].outputs.len(), 4);
    // Every third object: a third of each blob.
    let deleted: Vec<usize> = (0..100).step_by(3).collect();
    for &i in &deleted {
        delete(&app, &key(i)).await;
    }
    let reports = pass(&app).await.unwrap();
    assert_eq!(reports.len(), 1);
    assert!(matches!(reports[0].kind, Kind::Compact));
    assert_eq!((reports[0].sources, reports[0].outputs.len()), (4, 3));
    assert_eq!(query_i64(&app, "SELECT count(*) FROM blobs").await, 3);
    assert_files(&app, 3).await;
    assert_accounting(&app).await;
    for i in 0..100 {
        let expected = (!deleted.contains(&i)).then(|| content(i, 4000));
        assert_eq!(get(&app, &key(i)).await, expected, "object {i}");
    }
}

/// A part deleted after it was copied isn't moved, and its bytes in the new
/// blob are garbage.
#[tokio::test]
async fn part_deleted_mid_job_becomes_garbage() {
    let hook = at(Stage::Copied, |app| async move { delete(&app, &key(7)).await });
    let Some(app) = node(Some(hook)).await else { return };
    put_many(&app, 100).await;
    let reports = pass(&app).await.unwrap();
    assert_eq!(reports.len(), 1);
    let dead = query_i64(&app, "SELECT sum(dead_size)::bigint FROM blobs").await;
    assert_eq!(dead, data(7).len() as i64);
    assert_files(&app, 2).await;
    assert_accounting(&app).await;
    assert_objects(&app, 100, &[7]).await;
}

/// A source blob deleted (and reaped) before it was copied leaves padding in
/// the new blob, and the job goes on.
#[tokio::test]
async fn source_vanished_mid_job_is_padded() {
    let hook = at(Stage::Loaded, |app| async move {
        let blob_id = blob_of(&app, &key(42)).await;
        delete(&app, &key(42)).await;
        // The delete reaps the file in the background.
        assert_reaped(&app, blob_id).await;
    });
    let Some(app) = node(Some(hook)).await else { return };
    put_many(&app, 100).await;
    let reports = pass(&app).await.unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].parts, 99);
    let dead = query_i64(&app, "SELECT sum(dead_size)::bigint FROM blobs").await;
    assert_eq!(dead, data(42).len() as i64);
    assert_files(&app, 2).await;
    assert_accounting(&app).await;
    assert_objects(&app, 100, &[42]).await;
}

/// A part whose bytes don't match its checksum after the copy stops the job:
/// nothing moves, the new blob is deleted, and the sources stay leased.
#[tokio::test]
async fn failed_verification_moves_nothing() {
    let Some(app) = node(None).await else { return };
    put_many(&app, 100).await;
    let before = blob_of(&app, &key(3)).await;
    // The catalog's checksum no longer matches the part's (intact) bytes.
    app.pool
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE parts SET crc64nvme = crc64nvme # 1 WHERE blob_id = $1",
            &[&before],
        )
        .await
        .unwrap();
    assert!(pass(&app).await.unwrap().is_empty());
    assert_eq!(blob_of(&app, &key(3)).await, before);
    assert_eq!(query_i64(&app, "SELECT count(*) FROM blobs").await, 100);
    let leased = "SELECT count(*) FROM blobs WHERE pack_lease_until > NOW()";
    assert_eq!(query_i64(&app, leased).await, 100);
    assert_files(&app, 100).await;
    assert_objects(&app, 100, &[]).await;
}

/// A new blob damaged on disk after it was written fails its read-back.
#[tokio::test]
async fn damaged_copy_moves_nothing() {
    let hook = at(Stage::Copied, |app| async move {
        let blob_id = pending_blob(&app).await;
        let path = app.store.blob_path(blob_id);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[500] ^= 1;
        std::fs::write(&path, bytes).unwrap();
    });
    let Some(app) = node(Some(hook)).await else { return };
    put_many(&app, 100).await;
    assert!(pass(&app).await.unwrap().is_empty());
    assert_eq!(query_i64(&app, "SELECT count(*) FROM blobs").await, 100);
    assert_files(&app, 100).await;
    assert_objects(&app, 100, &[]).await;
}

/// While one pass holds its sources, a concurrent pass finds nothing to do.
#[tokio::test]
async fn concurrent_passes_pack_each_blob_once() {
    let hook = at(Stage::Loaded, |app| async move {
        // Mid-job: another pass, as on another node.
        assert!(pass(&app).await.unwrap().is_empty());
    });
    let Some(app) = node(Some(hook)).await else { return };
    put_many(&app, 100).await;
    let reports = pass(&app).await.unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].parts, 100);
    assert_files(&app, 2).await;
    assert_accounting(&app).await;
    assert_objects(&app, 100, &[]).await;
}

/// Leases only save work: when one runs out mid-job, a second job packs the
/// same blobs, and the first one's commit then moves nothing and drops its own
/// blobs.
#[tokio::test]
async fn racing_jobs_keep_data_intact() {
    let hook = at(Stage::Verified, |app| async move {
        app.pool
            .get()
            .await
            .unwrap()
            .execute("UPDATE blobs SET pack_lease_until = NULL", &[])
            .await
            .unwrap();
        let reports = pass(&app).await.unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].parts, 100);
    });
    let Some(app) = node(Some(hook)).await else { return };
    put_many(&app, 100).await;
    let reports = pass(&app).await.unwrap();
    assert_eq!(reports.len(), 1);
    // The losing job found its parts moved, so its blobs are gone again.
    assert_eq!(query_i64(&app, "SELECT count(*) FROM blobs").await, 2);
    assert_files(&app, 2).await;
    assert_accounting(&app).await;
    assert_objects(&app, 100, &[]).await;
}

/// A packer that dies mid-job leaves state the GC cleans up: its new blobs
/// pending, nothing moved. Once the leases expire, the blobs are packed again.
#[tokio::test]
async fn crash_mid_job_is_recoverable() {
    let (crashed, mut crash) = tokio::sync::mpsc::channel::<()>(1);
    let hook = at(Stage::Copied, move |_| {
        let crashed = crashed.clone();
        async move {
            crashed.send(()).await.unwrap();
            std::future::pending::<()>().await;
        }
    });
    let Some(app) = node(Some(hook)).await else { return };
    put_many(&app, 100).await;
    tokio::select! {
        _ = pass(&app) => panic!("the pass should hang in the hook"),
        _ = crash.recv() => {}
    }
    // Dropping the pass is the crash.
    assert_eq!(query_i64(&app, "SELECT count(*) FROM blobs WHERE state = 'pending'").await, 2);
    assert_objects(&app, 100, &[]).await;
    assert_files(&app, 102).await;

    // The GC reclaims the dead job's blobs, once they're old enough.
    app.pool
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE blobs SET created_at = NOW() - INTERVAL '2 days' WHERE state = 'pending'",
            &[],
        )
        .await
        .unwrap();
    gc::pass(&app, gc::Scope::everything()).await.unwrap();
    assert_eq!(query_i64(&app, "SELECT count(*) FROM blobs").await, 100);
    assert_files(&app, 100).await;

    // The sources stay leased until the lease runs out.
    assert!(pass(&app).await.unwrap().is_empty());
    app.pool
        .get()
        .await
        .unwrap()
        .execute("UPDATE blobs SET pack_lease_until = NOW() - INTERVAL '1 second'", &[])
        .await
        .unwrap();
    assert_eq!(pass(&app).await.unwrap().len(), 1);
    assert_files(&app, 2).await;
    assert_objects(&app, 100, &[]).await;
}

/// A read that resolved its parts before they were packed (and their old blobs
/// reaped) follows them to the new blob.
#[tokio::test]
async fn read_follows_moved_part() {
    let Some(app) = node(None).await else { return };
    put_many(&app, 100).await;
    let mut client = app.pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    let Ok(version) = objects::get::lookup_version(&tx, BUCKET, &key(9), None).await.unwrap() else {
        panic!("object 9 exists");
    };
    let parts = objects::get::resolve_object_parts(&tx, version.id).await.unwrap();
    tx.commit().await.unwrap();
    drop(client);
    let old = parts[0].blob_id;

    assert_eq!(pass(&app).await.unwrap().len(), 1);
    assert_reaped(&app, old).await;

    // A range from the middle of the part, as a ranged GET would read it.
    let len = data(9).len() as u64;
    let slices = objects::get::select_parts_in_range(parts, 10, len - 10);
    let (sender, body) = channel_body();
    objects::get::spawn_range_stream(app.clone(), slices, sender);
    let read = body.collect().await.unwrap().to_bytes();
    assert_eq!(read.as_ref(), &data(9)[10..len as usize - 10]);
}
