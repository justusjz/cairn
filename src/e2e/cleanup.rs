//! End-to-end tests of uploads that fail: each deletes what it stored right
//! away, so nothing is left for the GC, whose job is only what a crash leaves.

use std::sync::Arc;

use http_body_util::Full;
use hyper::{
    HeaderMap,
    body::{Bytes, Frame},
};
use uuid::Uuid;

use super::{BUCKET, assert_files, node_replicating, node_with, put, query_i64};
use crate::{
    App, AttachTarget, UploadResult,
    payload::Payload,
    body::channel_body,
    packer,
    s3::conditional::Preconditions,
};

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

fn object(key: &str, conditions: Preconditions) -> AttachTarget {
    AttachTarget::Object {
        bucket: BUCKET.to_owned(),
        key: key.to_owned(),
        content_type: "text/plain".to_owned(),
        conditions,
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
