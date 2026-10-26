//! End-to-end tests of the GC (see `crate::e2e`).

use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use super::{Scope, Sweep, pass};
use crate::{
    App,
    e2e::{assert_files, assert_reaped, get, node_with, put, query_i64},
    packer,
};

/// Runs a GC pass, which must not run into any errors.
async fn pass_ok(app: &Arc<App>, scope: Scope) -> super::Report {
    let report = pass(app, scope).await;
    assert!(report.errors().is_empty(), "{report}");
    report
}

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

/// Writes a blob's file on this node, as a replica would (contents don't
/// matter here).
async fn write_file(app: &App, blob_id: Uuid) {
    let mut file = app.store.create_blob(blob_id).await.unwrap();
    file.write_all(b"leftover").await.unwrap();
    file.sync_all().await.unwrap();
}

/// A blob in `state`, created `age` ago, with a file on this node and the
/// location for it, but no part.
async fn leftover_blob(app: &App, state: &str, age: &str) -> Uuid {
    let blob_id = Uuid::now_v7();
    write_file(app, blob_id).await;
    let client = app.pool.get().await.unwrap();
    client
        .execute(
            "INSERT INTO blobs (blob_id, size, state, created_at)
             VALUES ($1, 8, $2, NOW() - $3::text::interval)",
            &[&blob_id, &state, &age],
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO blob_locations (blob_id, node) VALUES ($1, $2)",
            &[&blob_id, &app.node],
        )
        .await
        .unwrap();
    blob_id
}

async fn blob_exists(app: &App, blob_id: Uuid) -> bool {
    let client = app.pool.get().await.unwrap();
    client
        .query_opt("SELECT 1 FROM blobs WHERE blob_id = $1", &[&blob_id])
        .await
        .unwrap()
        .is_some()
}

async fn file_exists(app: &App, blob_id: Uuid) -> bool {
    app.store.open_blob(blob_id).await.unwrap().is_some()
}

/// A pending blob is deleted, with its file, once it's been pending for a
/// day: its upload has died.
#[tokio::test]
async fn stale_pending_blobs_are_deleted() {
    let Some(app) = node().await else { return };
    let stale = leftover_blob(&app, "pending", "2 days").await;
    let uploading = leftover_blob(&app, "pending", "1 hour").await;
    let report = pass_ok(&app, Scope::everything()).await;
    assert_eq!(report.pending, 1);
    assert!(!blob_exists(&app, stale).await);
    assert_reaped(&app, stale).await;
    assert!(blob_exists(&app, uploading).await);
    assert!(file_exists(&app, uploading).await);
}

/// A file whose blob the catalog doesn't place on this node is deleted, and
/// its shard directory with it once that's empty. A file still being written
/// (and so without a location yet) and the files of stored objects stay.
#[tokio::test]
async fn orphaned_files_are_swept() {
    let Some(app) = node().await else { return };
    put(&app, "kept", b"stored".to_vec()).await;
    let orphan = Uuid::now_v7();
    write_file(&app, orphan).await;
    let writing = Uuid::now_v7();
    let _guard = app.writing.begin(writing);
    write_file(&app, writing).await;

    let report = pass_ok(&app, Scope::everything()).await;
    assert_eq!(report.files, 1);
    assert!(!file_exists(&app, orphan).await);
    assert!(!app.store.blob_path(orphan).parent().unwrap().exists());
    assert!(file_exists(&app, writing).await);
    assert_eq!(get(&app, "kept").await.as_deref(), Some(&b"stored"[..]));
}

/// The background passes sweep a slice of the shards each.
#[tokio::test]
async fn a_background_pass_sweeps_its_slice() {
    let Some(app) = node().await else { return };
    let mut sweep = Sweep::new();
    // Find the shard that the next pass covers, and put an orphan there.
    let scope_start = sweep.next;
    let orphan = loop {
        let id = Uuid::now_v7();
        let shard = u32::from_str_radix(&id.simple().to_string()[28..32], 16).unwrap();
        if shard == scope_start {
            break id;
        }
    };
    write_file(&app, orphan).await;
    pass_ok(&app, sweep.next_scope()).await;
    assert!(!file_exists(&app, orphan).await);
}

/// A blob whose last part is deleted any which way (here, by deleting objects
/// in the catalog directly, so their parts go by cascade) is dropped by the
/// next packing pass, which the garbage log points at it. Empty blobs too,
/// which compaction never takes.
#[tokio::test]
async fn blobs_without_parts_are_dropped() {
    let Some(app) = node().await else { return };
    put(&app, "full", b"some data".to_vec()).await;
    put(&app, "empty", Vec::new()).await;
    put(&app, "kept", b"stored".to_vec()).await;
    app.pool
        .get()
        .await
        .unwrap()
        .execute("DELETE FROM objects WHERE key IN ('full', 'empty')", &[])
        .await
        .unwrap();
    assert_eq!(query_i64(&app, "SELECT count(*) FROM blobs").await, 3);
    packer::pass(&app).await.unwrap();
    assert_eq!(query_i64(&app, "SELECT count(*) FROM blobs").await, 1);
    assert_files(&app, 1).await;
    assert_eq!(get(&app, "kept").await.as_deref(), Some(&b"stored"[..]));
}
