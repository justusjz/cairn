//! End-to-end tests of the lock protocol (see `catalog.sql`). Each holds one
//! transaction open at the point an invariant depends on, and checks that the
//! transaction racing it waits, and then does the right thing.

use std::{sync::Arc, time::Duration};

use deadpool_postgres::Object;
use hyper::StatusCode;
use tokio::{sync::oneshot, task::JoinHandle};
use tokio_postgres::Transaction;
use uuid::Uuid;

use super::{BUCKET, delete, get, node_with, put, query_i64};
use crate::{
    App, AttachTarget, UploadResult,
    payload::Payload,
    gc,
    packer::{self, Stage},
    s3::{
        buckets::delete::delete_bucket, multipart::create::create_multipart_upload,
        objects::delete::delete_object,
    },
};

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

/// How long a transaction is given to finish before it counts as waiting.
const WAIT: Duration = Duration::from_millis(300);

/// Asserts that `task` is still running after a while: it waits for a lock.
async fn assert_waits<T>(task: &JoinHandle<T>) {
    tokio::time::sleep(WAIT).await;
    assert!(!task.is_finished(), "it should wait for the lock");
}

/// A pending blob with its location on this node, as an upload leaves it just
/// before its commit, created `age_hours` ago. It has no file.
async fn pending_blob(app: &App, age_hours: f64) -> Uuid {
    let blob = Uuid::now_v7();
    let client = app.pool.get().await.unwrap();
    client
        .execute(
            "INSERT INTO blobs (blob_id, size, state, created_at)
             VALUES ($1, 0, 'pending', NOW() - $2 * interval '1 hour')",
            &[&blob, &age_hours],
        )
        .await
        .unwrap();
    client
        .execute("INSERT INTO blob_locations (blob_id, node) VALUES ($1, $2)", &[&blob, &app.node])
        .await
        .unwrap();
    blob
}

/// Runs `cairn_commit_object` for `blob` as `key` in `tx`, returning its status.
async fn commit_object(tx: &Transaction<'_>, app: &App, blob: Uuid, key: &str) -> String {
    tx.query_one(
        "SELECT status FROM pg_temp.cairn_commit_object(
             $1, ARRAY[$2::int], 0, 0, 65536, 0, 'd41d8cd98f00b204e9800998ecf8427e',
             $3, $4, 'application/octet-stream', NULL, NULL, $5)",
        &[&blob, &app.node, &BUCKET, &key, &crate::s3::versions::new_version_id()],
    )
    .await
    .unwrap()
    .get(0)
}

/// A pooled connection, for a transaction to be held open on.
async fn connection(app: &App) -> Object {
    app.pool.get().await.unwrap()
}

/// The row id of the key's current version, and its parts' ids and sizes: what
/// a copy of it reads.
async fn source(app: &App, key: &str) -> (i64, Vec<i64>, Vec<i64>) {
    let client = app.pool.get().await.unwrap();
    let id: i64 = client
        .query_one(
            "SELECT id FROM objects WHERE bucket = $1 AND key = $2 AND is_latest",
            &[&BUCKET, &key],
        )
        .await
        .unwrap()
        .get(0);
    let rows = client
        .query("SELECT id, size FROM parts WHERE object_id = $1 ORDER BY part_number", &[&id])
        .await
        .unwrap();
    (id, rows.iter().map(|r| r.get(0)).collect(), rows.iter().map(|r| r.get(1)).collect())
}

/// Runs `cairn_copy_object` of `source` to `key` in `tx`, returning its status.
async fn copy_object(
    tx: &Transaction<'_>,
    source: &(i64, Vec<i64>, Vec<i64>),
    key: &str,
) -> String {
    let size: i64 = source.2.iter().sum();
    tx.query_one(
        "SELECT status FROM pg_temp.cairn_copy_object($1, $2, $3, $4, $5, $6, 'etag', 'text/plain', $7)",
        &[&source.0, &source.1, &source.2, &BUCKET, &key, &size, &crate::s3::versions::new_version_id()],
    )
    .await
    .unwrap()
    .get(0)
}

/// I3: DeleteBucket waits for a PUT into the bucket, and then sees its object.
#[tokio::test]
async fn delete_bucket_waits_for_a_put() {
    let Some(app) = node().await else { return };
    let blob = pending_blob(&app, 0.0).await;
    let mut held = connection(&app).await;
    let tx = held.transaction().await.unwrap();
    assert_eq!(commit_object(&tx, &app, blob, "k").await, "committed");

    let app2 = app.clone();
    let deleting = tokio::spawn(async move { delete_bucket(&app2, BUCKET).await.unwrap() });
    assert_waits(&deleting).await;
    tx.commit().await.unwrap();
    assert_eq!(deleting.await.unwrap().status(), StatusCode::CONFLICT);
}

/// I3: a PUT that waited for a DeleteBucket finds the bucket gone.
#[tokio::test]
async fn a_put_after_delete_bucket_finds_no_bucket() {
    let Some(app) = node().await else { return };
    let blob = pending_blob(&app, 0.0).await;
    let mut held = connection(&app).await;
    let tx = held.transaction().await.unwrap();
    let deleted: String = tx
        .query_one("SELECT status FROM pg_temp.cairn_delete_bucket($1)", &[&BUCKET])
        .await
        .unwrap()
        .get(0);
    assert_eq!(deleted, "deleted");

    let app2 = app.clone();
    let putting = tokio::spawn(async move {
        let mut client = connection(&app2).await;
        let tx = client.transaction().await.unwrap();
        commit_object(&tx, &app2, blob, "k").await
    });
    assert_waits(&putting).await;
    tx.commit().await.unwrap();
    assert_eq!(putting.await.unwrap(), "no_such_bucket");
}

/// I2: a PUT waits for a change of the bucket's versioning state, and then
/// lands in the new state.
#[tokio::test]
async fn a_put_waits_for_versioning_to_change() {
    let Some(app) = node().await else { return };
    put(&app, "k", b"one".to_vec()).await;
    let mut held = connection(&app).await;
    let tx = held.transaction().await.unwrap();
    let changed: bool = tx
        .query_one("SELECT pg_temp.cairn_set_versioning($1, 'enabled')", &[&BUCKET])
        .await
        .unwrap()
        .get(0);
    assert!(changed);

    let app2 = app.clone();
    let putting = tokio::spawn(async move { put(&app2, "k", b"two".to_vec()).await });
    assert_waits(&putting).await;
    tx.commit().await.unwrap();
    putting.await.unwrap();
    // Enabled: the second write kept the first as the null version.
    let versions = "SELECT count(*) FROM objects WHERE key = 'k'";
    assert_eq!(query_i64(&app, versions).await, 2);
    assert_eq!(get(&app, "k").await, Some(b"two".to_vec()));
}

/// I1: writes to the same key wait for each other; the later one wins.
#[tokio::test]
async fn puts_to_one_key_wait_for_each_other() {
    let Some(app) = node().await else { return };
    let (first, second) = (pending_blob(&app, 0.0).await, pending_blob(&app, 0.0).await);
    let mut held = connection(&app).await;
    let tx = held.transaction().await.unwrap();
    assert_eq!(commit_object(&tx, &app, first, "k").await, "committed");

    let app2 = app.clone();
    let putting = tokio::spawn(async move {
        let mut client = connection(&app2).await;
        let tx = client.transaction().await.unwrap();
        let status = commit_object(&tx, &app2, second, "k").await;
        tx.commit().await.unwrap();
        status
    });
    assert_waits(&putting).await;
    tx.commit().await.unwrap();
    assert_eq!(putting.await.unwrap(), "committed");
    let current = "SELECT count(*) FROM objects o JOIN parts p ON p.object_id = o.id
                   WHERE o.key = 'k' AND o.is_latest";
    assert_eq!(query_i64(&app, current).await, 1);
    let winner = format!(
        "SELECT count(*) FROM parts p JOIN objects o ON o.id = p.object_id
         WHERE o.key = 'k' AND p.blob_id = '{second}'"
    );
    assert_eq!(query_i64(&app, &winner).await, 1);
    // The first one's blob was replaced, and dropped.
    let first_left = format!("SELECT count(*) FROM blobs WHERE blob_id = '{first}'");
    assert_eq!(query_i64(&app, &first_left).await, 0);
}

/// Writes to different keys don't wait for each other.
#[tokio::test]
async fn puts_to_different_keys_dont_wait() {
    let Some(app) = node().await else { return };
    let (first, second) = (pending_blob(&app, 0.0).await, pending_blob(&app, 0.0).await);
    let mut held = connection(&app).await;
    let tx = held.transaction().await.unwrap();
    assert_eq!(commit_object(&tx, &app, first, "a").await, "committed");

    let mut other = connection(&app).await;
    let tx2 = other.transaction().await.unwrap();
    let status = tokio::time::timeout(WAIT, commit_object(&tx2, &app, second, "b"))
        .await
        .expect("it shouldn't wait");
    assert_eq!(status, "committed");
    tx2.commit().await.unwrap();
    tx.commit().await.unwrap();
}

/// I5: a copy holds its source's blob, so a delete of the source that comes
/// meanwhile waits, and then leaves the blob to the copy.
#[tokio::test]
async fn a_copy_keeps_its_source_blob_from_a_delete() {
    let Some(app) = node().await else { return };
    put(&app, "src", b"data".to_vec()).await;
    let src = source(&app, "src").await;
    let mut held = connection(&app).await;
    let tx = held.transaction().await.unwrap();
    assert_eq!(copy_object(&tx, &src, "dst").await, "committed");

    let app2 = app.clone();
    let deleting = tokio::spawn(async move { delete_object(&app2, BUCKET, "src", None).await.unwrap() });
    assert_waits(&deleting).await;
    tx.commit().await.unwrap();
    assert_eq!(deleting.await.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(get(&app, "src").await, None);
    assert_eq!(get(&app, "dst").await, Some(b"data".to_vec()));
}

/// I5: a copy that comes while its source is being deleted waits, then finds
/// the source changed.
#[tokio::test]
async fn a_copy_after_a_delete_finds_the_source_changed() {
    let Some(app) = node().await else { return };
    put(&app, "src", b"data".to_vec()).await;
    let src = source(&app, "src").await;
    let mut held = connection(&app).await;
    let tx = held.transaction().await.unwrap();
    let deleted: Vec<Uuid> = tx
        .query_one(
            "SELECT reap_blob FROM pg_temp.cairn_delete_objects($1, '{src}', '{NULL}', '{x}')",
            &[&BUCKET],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(deleted.len(), 1, "the delete drops the source's blob");

    let app2 = app.clone();
    let copying = tokio::spawn(async move {
        let mut client = connection(&app2).await;
        let tx = client.transaction().await.unwrap();
        copy_object(&tx, &src, "dst").await
    });
    assert_waits(&copying).await;
    tx.commit().await.unwrap();
    assert_eq!(copying.await.unwrap(), "source_changed");
}

/// Creates an upload for `key`, returning its ID.
async fn create_upload(app: &App, key: &str) -> Uuid {
    let response = create_multipart_upload(app, BUCKET, key, "text/plain").await.unwrap();
    let body = http_body_util::BodyExt::collect(response.into_body()).await.unwrap().to_bytes();
    let body = String::from_utf8(body.to_vec()).unwrap();
    let start = body.find("<UploadId>").unwrap() + "<UploadId>".len();
    let end = body.find("</UploadId>").unwrap();
    Uuid::parse_str(&body[start..end]).unwrap()
}

/// Uploads `data` as part `number` of the upload.
async fn upload_part(app: &Arc<App>, upload_id: Uuid, number: i32, data: &[u8]) -> UploadResult {
    let attach = AttachTarget::MultipartPart {
        upload_id,
        part_number: number,
    };
    let body = http_body_util::Full::new(hyper::body::Bytes::from(data.to_vec()));
    crate::upload_part(app, body, &attach, Payload::unchecked())
        .await
        .unwrap()
}

/// I4: a part uploaded while its upload completes waits, then finds the upload
/// gone.
#[tokio::test]
async fn a_part_upload_waits_for_complete() {
    let Some(app) = node().await else { return };
    let upload_id = create_upload(&app, "k").await;
    let UploadResult::Committed { etag, .. } = upload_part(&app, upload_id, 1, b"one").await else {
        panic!("the part should be committed");
    };
    let mut held = connection(&app).await;
    let tx = held.transaction().await.unwrap();
    let status: String = tx
        .query_one(
            "SELECT status FROM pg_temp.cairn_complete_upload($1, $2, 'k', '{1}', $3, NULL, NULL, 'x')",
            &[&upload_id, &BUCKET, &vec![etag]],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(status, "done");

    let app2 = app.clone();
    let uploading = tokio::spawn(async move { upload_part(&app2, upload_id, 1, b"two").await });
    assert_waits(&uploading).await;
    tx.commit().await.unwrap();
    assert!(matches!(uploading.await.unwrap(), UploadResult::NoSuchUpload));
    assert_eq!(get(&app, "k").await, Some(b"one".to_vec()));
}

/// I4: a part uploaded while its upload is aborted waits, then finds the
/// upload gone.
#[tokio::test]
async fn a_part_upload_waits_for_abort() {
    let Some(app) = node().await else { return };
    let upload_id = create_upload(&app, "k").await;
    let mut held = connection(&app).await;
    let tx = held.transaction().await.unwrap();
    let existed: bool = tx
        .query_one(
            "SELECT existed FROM pg_temp.cairn_abort_upload($1, $2, 'k')",
            &[&upload_id, &BUCKET],
        )
        .await
        .unwrap()
        .get(0);
    assert!(existed);

    let app2 = app.clone();
    let uploading = tokio::spawn(async move { upload_part(&app2, upload_id, 1, b"one").await });
    assert_waits(&uploading).await;
    tx.commit().await.unwrap();
    assert!(matches!(uploading.await.unwrap(), UploadResult::NoSuchUpload));
}

/// I5: the GC never deletes a stale pending blob that's being committed: it
/// waits, and then leaves the committed blob alone.
#[tokio::test]
async fn gc_spares_a_blob_being_committed() {
    let Some(app) = node().await else { return };
    let blob = pending_blob(&app, 48.0).await;
    let mut held = connection(&app).await;
    let tx = held.transaction().await.unwrap();
    assert_eq!(commit_object(&tx, &app, blob, "k").await, "committed");

    let app2 = app.clone();
    let collecting = tokio::spawn(async move { gc::pass(&app2, gc::Scope::everything()).await });
    assert_waits(&collecting).await;
    tx.commit().await.unwrap();
    let report = collecting.await.unwrap();
    assert_eq!(report.counts().0, 0, "{report}");
    let committed = format!("SELECT count(*) FROM blobs WHERE blob_id = '{blob}' AND state = 'committed'");
    assert_eq!(query_i64(&app, &committed).await, 1);
}

/// I5, I7: a copy made of a source the packer is about to move holds the
/// source's blob, so the packer's commit waits, then moves the source's part
/// but keeps the blob for the copy.
#[tokio::test]
async fn the_packer_keeps_a_blob_that_a_copy_references() {
    let pack = packer::Config {
        target_size: 100_000,
        small_size: 25_000,
        ..packer::Config::default()
    };
    // Once the job has loaded its parts, a copy of `o0` is made, and held
    // uncommitted until the test lets it go.
    let (locked_tx, locked_rx) = oneshot::channel::<()>();
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let hook_state = Arc::new(std::sync::Mutex::new(Some((locked_tx, release_rx))));
    let hook: packer::Hook = Arc::new(move |app: Arc<App>, stage: Stage| {
        let state = hook_state.clone();
        Box::pin(async move {
            if stage != Stage::Loaded {
                return;
            }
            let Some((locked, release)) = state.lock().unwrap().take() else { return };
            let src = source(&app, "o0").await;
            tokio::spawn(async move {
                let mut client = connection(&app).await;
                let tx = client.transaction().await.unwrap();
                assert_eq!(copy_object(&tx, &src, "copy").await, "committed");
                locked.send(()).unwrap();
                release.await.unwrap();
                tx.commit().await.unwrap();
            });
        })
    });
    let Some(app) = node_with(pack, Some(hook)).await else { return };
    for i in 0..100 {
        put(&app, &format!("o{i}"), vec![i as u8; 1200]).await;
    }
    let source_blob: Uuid = {
        let client = app.pool.get().await.unwrap();
        client
            .query_one(
                "SELECT p.blob_id FROM parts p JOIN objects o ON o.id = p.object_id
                 WHERE o.key = 'o0'",
                &[],
            )
            .await
            .unwrap()
            .get(0)
    };

    let app2 = app.clone();
    let packing = tokio::spawn(async move { packer::pass(&app2).await.unwrap() });
    locked_rx.await.unwrap();
    assert_waits(&packing).await;
    release_tx.send(()).unwrap();
    let reports = packing.await.unwrap();
    assert_eq!(reports.len(), 1);

    // The original moved; the copy still references the old blob, which stays.
    let on_source = format!("SELECT count(*) FROM parts WHERE blob_id = '{source_blob}'");
    assert_eq!(query_i64(&app, &on_source).await, 1);
    assert_eq!(get(&app, "o0").await, Some(vec![0; 1200]));
    assert_eq!(get(&app, "copy").await, Some(vec![0; 1200]));
    delete(&app, "copy").await;
    // Then the copy's delete drops it.
    let left = format!("SELECT count(*) FROM blobs WHERE blob_id = '{source_blob}'");
    assert_eq!(query_i64(&app, &left).await, 0);
}

/// A PUT into a bucket that doesn't exist is rejected before anything is
/// written: not even a pending blob is left for the GC.
#[tokio::test]
async fn a_put_into_a_missing_bucket_writes_nothing() {
    let Some(app) = node().await else { return };
    let attach = AttachTarget::Object {
        bucket: "missing".to_owned(),
        key: "k".to_owned(),
        content_type: "text/plain".to_owned(),
        conditions: crate::s3::conditional::Preconditions::default(),
    };
    let body = http_body_util::Full::new(hyper::body::Bytes::from_static(b"data"));
    let result = crate::upload_part(&app, body, &attach, Payload::unchecked())
        .await
        .unwrap();
    assert!(matches!(result, UploadResult::NoSuchBucket));
    assert_eq!(query_i64(&app, "SELECT count(*) FROM blobs").await, 0);
    assert!(app.store.list_local_blobs().await.unwrap().is_empty());
}

/// The most advisory locks a transaction may take (see `cairn_lock_keys`).
const MAX_KEY_LOCKS: i64 = 16;

/// How many advisory locks `tx` holds.
async fn advisory_locks(tx: &Transaction<'_>) -> i64 {
    tx.query_one(
        "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid()",
        &[],
    )
    .await
    .unwrap()
    .get(0)
}

/// Runs `cairn_delete_objects` for `keys` in `tx`, returning its status.
async fn delete_keys(tx: &Transaction<'_>, keys: &[String]) -> String {
    let versions: Vec<Option<&str>> = keys.iter().map(|_| None).collect();
    let markers: Vec<String> = keys.iter().map(|_| crate::s3::versions::new_version_id()).collect();
    tx.query_one(
        "SELECT status FROM pg_temp.cairn_delete_objects($1, $2, $3, $4)",
        &[&BUCKET, &keys, &versions, &markers],
    )
    .await
    .unwrap()
    .get(0)
}

/// I1: a DeleteObjects of many keys locks their stripes instead of each key,
/// so it takes few locks however many keys it has, and still holds every one
/// of its keys against a write.
#[tokio::test]
async fn a_large_delete_takes_few_locks_and_holds_its_keys() {
    let Some(app) = node().await else { return };
    let keys: Vec<String> = (0..1000).map(|i| format!("k{i}")).collect();
    let mut held = connection(&app).await;
    let tx = held.transaction().await.unwrap();
    assert_eq!(delete_keys(&tx, &keys).await, "deleted");
    assert!(advisory_locks(&tx).await <= MAX_KEY_LOCKS);

    let app2 = app.clone();
    let putting = tokio::spawn(async move { put(&app2, "k500", b"data".to_vec()).await });
    assert_waits(&putting).await;
    tx.commit().await.unwrap();
    putting.await.unwrap();
    assert_eq!(get(&app, "k500").await, Some(b"data".to_vec()));
}

/// I1: a DeleteObjects of a few keys locks just those, so writes to other
/// keys go ahead, even in the same stripes, while it holds them.
#[tokio::test]
async fn a_small_delete_locks_only_its_keys() {
    let Some(app) = node().await else { return };
    let keys: Vec<String> = (0..8).map(|i| format!("k{i}")).collect();
    let mut held = connection(&app).await;
    let tx = held.transaction().await.unwrap();
    assert_eq!(delete_keys(&tx, &keys).await, "deleted");
    assert!(advisory_locks(&tx).await <= MAX_KEY_LOCKS);

    // Forty other keys cover every stripe.
    for i in 100..140 {
        tokio::time::timeout(WAIT * 10, put(&app, &format!("k{i}"), b"x".to_vec()))
            .await
            .expect("it shouldn't wait");
    }
    let app2 = app.clone();
    let putting = tokio::spawn(async move { put(&app2, "k3", b"data".to_vec()).await });
    assert_waits(&putting).await;
    tx.commit().await.unwrap();
    putting.await.unwrap();
}

/// A session that doesn't follow the lock protocol (a node of an older
/// Cairn) can still read the catalog, but not write a thing to it.
#[tokio::test]
async fn an_old_session_cant_write() {
    let Some(app) = node().await else { return };
    put(&app, "k", b"data".to_vec()).await;
    let database: String = connection(&app)
        .await
        .query_one("SELECT current_database()", &[])
        .await
        .unwrap()
        .get(0);
    let url = std::env::var("CAIRN_TEST_DATABASE").unwrap();
    let (server, _) = url.rsplit_once('/').unwrap();
    let (old, connection) = tokio_postgres::connect(&format!("{server}/{database}"), tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(connection);

    let objects: i64 = old.query_one("SELECT count(*) FROM objects", &[]).await.unwrap().get(0);
    assert_eq!(objects, 1);
    for write in [
        "UPDATE buckets SET versioning = 'enabled'",
        "DELETE FROM objects",
        "INSERT INTO blobs (blob_id, size, state, created_at) VALUES (gen_random_uuid(), 0, 'pending', NOW())",
        "UPDATE nodes SET last_seen = NOW()",
        // Even a statement that changes no rows.
        "DELETE FROM parts WHERE false",
    ] {
        let e = old.batch_execute(write).await.unwrap_err();
        assert!(format!("{e:?}").contains("too old"), "{write}: {e:?}");
    }
    assert_eq!(get(&app, "k").await, Some(b"data".to_vec()));
}

/// A fold takes the garbage log in batches of the size it's given, and says
/// whether there may be more.
#[tokio::test]
async fn folds_take_the_garbage_log_in_batches() {
    let Some(app) = node().await else { return };
    for i in 0..5 {
        put(&app, &format!("k{i}"), vec![i; 10]).await;
    }
    let client = connection(&app).await;
    client
        .execute("INSERT INTO blob_garbage (blob_id, size) SELECT blob_id, 0 FROM blobs", &[])
        .await
        .unwrap();
    for (more, left) in [(true, 3), (true, 1), (false, 0)] {
        let row = client
            .query_one("SELECT more FROM pg_temp.cairn_fold_garbage(2)", &[])
            .await
            .unwrap();
        assert_eq!(row.get::<_, bool>(0), more);
        assert_eq!(query_i64(&app, "SELECT count(*) FROM blob_garbage").await, left);
    }
    // They're all still referenced, so they stay.
    assert_eq!(query_i64(&app, "SELECT count(*) FROM blobs").await, 5);
}
