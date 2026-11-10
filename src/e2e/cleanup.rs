//! End-to-end tests of uploads that fail: each deletes what it stored right
//! away, so nothing is left for the GC, whose job is only what a crash leaves.

use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{
    HeaderMap, StatusCode,
    body::{Bytes, Frame},
};
use tokio::task::JoinSet;
use uuid::Uuid;

use super::{BUCKET, assert_files, node_replicating, node_with, put, query_i64};
use crate::{
    App, AttachTarget, UploadResult,
    payload::Payload,
    body::channel_body,
    packer,
    s3::{
        buckets::delete::delete_bucket, conditional::Preconditions,
        multipart::create::create_multipart_upload,
    },
};
use crate::s3::sse::Wanted;

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

fn object(key: &str, conditions: Preconditions) -> AttachTarget {
    AttachTarget::Object {
        bucket: BUCKET.to_owned(),
        key: key.to_owned(),
        content_type: "text/plain".to_owned(),
        metadata: String::new(),
        conditions,
        sealing: None,
        checksum: crate::e2e::OBJECT_CHECKSUM,
    }
}

/// Uploads `data` to `attach`, checked as `payload` says.
async fn upload(
    app: &Arc<App>,
    attach: &AttachTarget,
    data: &'static [u8],
    payload: Payload,
) -> anyhow::Result<UploadResult> {
    let body = Full::new(Bytes::from_static(data));
    crate::upload_part(app, body, attach, payload).await
}

/// Checks that exactly `blobs` blobs are left, in the catalog and on disk
/// (waiting for the background reaps).
async fn assert_left(app: &App, blobs: i64) {
    assert_eq!(query_i64(app, "SELECT count(*) FROM blobs").await, blobs);
    assert_eq!(query_i64(app, "SELECT count(*) FROM blob_locations").await, blobs);
    assert_files(app, blobs as usize).await;
}

/// A body that doesn't match the hash the client claimed for it.
#[tokio::test]
async fn a_body_that_fails_its_checksum_leaves_nothing() {
    let Some(app) = node().await else { return };
    let mut headers = HeaderMap::new();
    headers.insert("x-amz-content-sha256", "0".repeat(64).parse().unwrap());
    let wrong = Payload::new(&headers, "", true).unwrap();
    let result = upload(&app, &object("k", Preconditions::default()), b"data", wrong).await;
    assert!(matches!(
        result.unwrap(),
        UploadResult::Rejected(rejection) if rejection.code == "XAmzContentSHA256Mismatch"
    ));
    assert_left(&app, 0).await;
}

/// A conditional write whose condition doesn't hold, at commit.
#[tokio::test]
async fn a_failed_precondition_leaves_nothing() {
    let Some(app) = node().await else { return };
    put(&app, "k", b"first".to_vec()).await;
    let mut headers = HeaderMap::new();
    headers.insert("if-none-match", "*".parse().unwrap());
    let create_only = object("k", Preconditions::from_headers(&headers));
    let result = upload(&app, &create_only, b"second", Payload::unchecked()).await;
    assert!(matches!(result.unwrap(), UploadResult::PreconditionFailed));
    // Only the first object's blob.
    assert_left(&app, 1).await;
}

/// A part whose upload is gone by the time it commits.
#[tokio::test]
async fn a_part_of_a_vanished_upload_leaves_nothing() {
    let Some(app) = node().await else { return };
    // Aborted, or completed, while the part streamed.
    let attach = AttachTarget::MultipartPart {
        upload_id: Uuid::now_v7(),
        part_number: 1,
        key: None,
        sse_s3: false,
        checksum: crate::e2e::PART_CHECKSUM,
    };
    let result = upload(&app, &attach, b"data", Payload::unchecked()).await;
    assert!(matches!(result.unwrap(), UploadResult::NoSuchUpload));
    assert_left(&app, 0).await;
}

/// A client body that breaks off midway: the sinks are faulted, and the
/// local replica deletes its partial file.
#[tokio::test]
async fn a_body_that_breaks_off_leaves_nothing() {
    let Some(app) = node().await else { return };
    let (tx, body) = channel_body();
    tokio::spawn(async move {
        tx.send(Ok(Frame::data(Bytes::from_static(b"the start")))).await.unwrap();
        tx.send(Err(std::io::Error::other("the client went away"))).await.unwrap();
    });
    let attach = object("k", Preconditions::default());
    let result = crate::upload_part(&app, body, &attach, Payload::unchecked()).await;
    assert!(result.is_err());
    assert_left(&app, 0).await;
}

/// Registers a second node, which looks live but can't be reached.
async fn unreachable_node(app: &App) {
    app.pool
        .get()
        .await
        .unwrap()
        .execute(
            "INSERT INTO nodes (node_id, peer_url, last_seen, free_space)
             VALUES ('unreachable', 'http://127.0.0.1:1', NOW(), 9223372036854775807)",
            &[],
        )
        .await
        .unwrap();
}

/// A replica that fails: what the others stored is deleted too.
#[tokio::test]
async fn a_failed_replica_leaves_nothing() {
    let Some(app) = node_replicating(packer::Config::default(), None, 2).await else { return };
    unreachable_node(&app).await;
    let result = upload(&app, &object("k", Preconditions::default()), b"data", Payload::unchecked()).await;
    assert!(result.is_err());
    assert_left(&app, 0).await;
}

/// Too few live nodes to write the replicas to.
#[tokio::test]
async fn too_few_nodes_leave_nothing() {
    let Some(app) = node_replicating(packer::Config::default(), None, 2).await else { return };
    let result = upload(&app, &object("k", Preconditions::default()), b"data", Payload::unchecked()).await;
    assert!(result.is_err());
    assert_left(&app, 0).await;
}

/// A replica that finishes writing after its blob was given up fails to
/// record its location, and deletes its file.
#[tokio::test]
async fn a_replica_of_a_given_up_blob_deletes_its_file() {
    let Some(app) = node().await else { return };
    let body = Full::new(Bytes::from_static(b"data"));
    let result = crate::write_blob_streaming(&app, Uuid::now_v7(), body).await;
    assert!(result.is_err(), "there's no such blob to record a location for");
    assert_left(&app, 0).await;
}

/// Waits for a background discard to delete every blob.
async fn eventually_no_blobs(app: &App) {
    for _ in 0..250 {
        if query_i64(app, "SELECT count(*) FROM blobs").await == 0 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("the blob was never discarded");
}

/// An upload whose request is dropped (the client hung up) while its body
/// streams: the writer, dropped, gives the blob up in the background.
#[tokio::test]
async fn an_upload_dropped_while_streaming_leaves_nothing() {
    let Some(app) = node().await else { return };
    let (tx, body) = channel_body();
    let uploading = {
        let app = app.clone();
        tokio::spawn(async move {
            let attach = object("k", Preconditions::default());
            crate::upload_part(&app, body, &attach, Payload::unchecked()).await
        })
    };
    tx.send(Ok(Frame::data(Bytes::from_static(b"the start")))).await.unwrap();
    // The blob exists, and its replica is being written.
    while query_i64(&app, "SELECT count(*) FROM blobs").await == 0 {
        tokio::task::yield_now().await;
    }
    uploading.abort();
    let _ = uploading.await;
    eventually_no_blobs(&app).await;
    assert_left(&app, 0).await;
}

/// A blob written for an upload whose request is dropped before its commit:
/// the guard that `upload_part` holds over it discards it.
#[tokio::test]
async fn a_written_blob_dropped_before_its_commit_is_discarded() {
    let Some(app) = node().await else { return };
    let mut writer = crate::BlobWriter::begin(&app).await.unwrap();
    writer.write(Bytes::from_static(b"data")).await;
    let written = writer.finish().await.unwrap();
    assert_left(&app, 1).await;
    drop(crate::blobs::DiscardOnDrop::new(&app, written.blob_id));
    eventually_no_blobs(&app).await;
    assert_left(&app, 0).await;
}

/// An upload whose request is dropped while its commit statement runs: the
/// discard and the commit race, and whichever wins, what's left is
/// consistent. Either the object is committed, with its blob, or neither is
/// there. (The discard usually loses: it gets the dropped commit's connection
/// from the pool, and so waits for the statement already sent on it.)
#[tokio::test]
async fn an_upload_dropped_while_committing_leaves_nothing_unreferenced() {
    let Some(app) = node().await else { return };
    // Hold the key's lock (K in `catalog.sql`), so the commit waits for it.
    let key = format!("{BUCKET}/k");
    let holder = app.pool.get().await.unwrap();
    holder.execute("SELECT pg_advisory_lock(hashtextextended($1, 0))", &[&key]).await.unwrap();
    let uploading = {
        let app = app.clone();
        tokio::spawn(async move {
            upload(&app, &object("k", Preconditions::default()), b"data", Payload::unchecked()).await
        })
    };
    let waiting = "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted";
    while query_i64(&app, waiting).await == 0 {
        tokio::task::yield_now().await;
    }
    uploading.abort();
    let _ = uploading.await;
    holder.execute("SELECT pg_advisory_unlock(hashtextextended($1, 0))", &[&key]).await.unwrap();
    // Until the commit and the discard are through.
    let busy = "SELECT count(*) FROM pg_stat_activity
                WHERE datname = current_database() AND state = 'active'
                  AND pid <> pg_backend_pid()";
    while query_i64(&app, busy).await > 0 {
        tokio::task::yield_now().await;
    }
    let objects = query_i64(&app, "SELECT count(*) FROM objects").await;
    let committed = query_i64(&app, "SELECT count(*) FROM blobs WHERE state = 'committed'").await;
    assert_eq!(committed, objects, "a committed object has its blob, and only then");
    assert_left(&app, objects).await;
}

/// DeleteBucket aborts the bucket's incomplete uploads, as S3 does, and frees
/// their parts' blobs right away, including those of parts that commit while
/// it runs. A part that comes after finds its upload gone, and leaves nothing
/// either. Objects still keep a bucket from being deleted.
#[tokio::test]
async fn delete_bucket_aborts_its_uploads() {
    let Some(app) = node().await else { return };
    let create = |key: &'static str| {
        let app = app.clone();
        async move {
            let response = create_multipart_upload(&app, BUCKET, key, "x", "", Wanted::Plain, None, None).await.unwrap();
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let body = String::from_utf8(body.to_vec()).unwrap();
            let start = body.find("<UploadId>").unwrap() + "<UploadId>".len();
            body[start..body.find("</UploadId>").unwrap()].parse::<Uuid>().unwrap()
        }
    };
    let uploads = [create("a").await, create("b").await];
    for (i, upload_id) in uploads.iter().enumerate() {
        let attach = AttachTarget::MultipartPart { upload_id: *upload_id, part_number: i as i32 + 1, key: None, sse_s3: false, checksum: crate::e2e::PART_CHECKSUM };
        let result = upload(&app, &attach, b"staged", Payload::unchecked()).await.unwrap();
        assert!(matches!(result, UploadResult::Committed { .. }));
    }
    put(&app, "k", b"object".to_vec()).await;
    assert_eq!(delete_bucket(&app, BUCKET).await.unwrap().status(), StatusCode::CONFLICT);
    super::delete(&app, "k").await;
    assert_left(&app, 2).await;

    // Parts of both uploads race the delete.
    let mut parts = JoinSet::new();
    for n in 0..16 {
        let (app, upload_id) = (app.clone(), uploads[n % 2]);
        parts.spawn(async move {
            let attach = AttachTarget::MultipartPart { upload_id, part_number: 10 + n as i32, key: None, sse_s3: false, checksum: crate::e2e::PART_CHECKSUM };
            upload(&app, &attach, b"racing", Payload::unchecked()).await.unwrap()
        });
    }
    assert_eq!(delete_bucket(&app, BUCKET).await.unwrap().status(), StatusCode::NO_CONTENT);
    while let Some(result) = parts.join_next().await {
        let result = result.unwrap();
        assert!(
            matches!(result, UploadResult::Committed { .. } | UploadResult::NoSuchUpload),
            "a part either made it in before the delete, or found its upload gone"
        );
    }
    assert_eq!(query_i64(&app, "SELECT count(*) FROM buckets").await, 0);
    assert_eq!(query_i64(&app, "SELECT count(*) FROM multipart_uploads").await, 0);
    assert_eq!(query_i64(&app, "SELECT count(*) FROM parts").await, 0);
    assert_left(&app, 0).await;
}

/// A plain object's ETag is its MD5: the one its Content-MD5 declares, once
/// the body is checked against it, or else the one worked out beside the
/// writing. A body that doesn't match its Content-MD5 leaves nothing.
#[tokio::test]
async fn an_etag_is_the_md5_declared_or_worked_out() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use md5::Digest;
    let Some(app) = node().await else { return };
    let data: &'static [u8] = b"some data for its MD5";
    let md5 = md5::Md5::digest(data);
    let hex: String = md5.iter().map(|b| format!("{b:02x}")).collect();
    let payload = |content_md5: Option<String>| {
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-content-sha256", "UNSIGNED-PAYLOAD".parse().unwrap());
        if let Some(content_md5) = content_md5 {
            headers.insert("content-md5", content_md5.parse().unwrap());
        }
        Payload::new(&headers, "", true).unwrap()
    };
    for (key, declared) in [("declared", Some(STANDARD.encode(md5))), ("worked-out", None)] {
        let result = upload(&app, &object(key, Preconditions::default()), data, payload(declared)).await;
        let UploadResult::Committed { etag, .. } = result.unwrap() else {
            panic!("{key} wasn't committed");
        };
        assert_eq!(etag, hex, "{key}");
    }
    let wrong = STANDARD.encode(md5::Md5::digest(b"other data"));
    let result = upload(&app, &object("wrong", Preconditions::default()), data, payload(Some(wrong))).await;
    assert!(matches!(result.unwrap(), UploadResult::Rejected(rejection) if rejection.code == "BadDigest"));
    assert_left(&app, 2).await;
}
