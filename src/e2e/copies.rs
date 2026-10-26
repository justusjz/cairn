//! End-to-end tests of copies, which share their source's bytes.

use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{StatusCode, body::Bytes};
use md5::{Digest, Md5};
use uuid::Uuid;

use super::{BUCKET, assert_files, delete, get, node_with, put};
use crate::{
    App, AttachTarget, UploadResult,
    auth::ContentSha256,
    packer,
    s3::{
        conditional::Preconditions,
        multipart::{complete::complete_multipart_upload, create::create_multipart_upload},
        objects::copy::{copy_object, copy_part},
    },
};

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

fn content(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

fn md5_hex(data: &[u8]) -> String {
    Md5::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

async fn body_text(response: hyper::Response<Full<Bytes>>) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// The text of the first `<tag>` in `xml`.
fn xml_field(xml: &str, tag: &str) -> String {
    let start = xml.find(&format!("<{tag}>")).unwrap() + tag.len() + 2;
    let end = xml[start..].find(&format!("</{tag}>")).unwrap() + start;
    xml[start..end].trim_matches('"').to_owned()
}

/// Copies `source` (a key of the bucket) to `key`; returns the copy's ETag.
async fn copy(app: &Arc<App>, source: &str, key: &str, replace: bool) -> String {
    let directive = replace.then_some("REPLACE");
    let source = format!("{BUCKET}/{source}");
    let response = copy_object(app, BUCKET, key, &source, directive, "text/plain", &Preconditions::default())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    xml_field(&body_text(response).await, "ETag")
}

/// Uploads `key` in several parts.
async fn put_multipart(app: &Arc<App>, key: &str, parts: &[Vec<u8>]) {
    let upload_id = create_upload(app, key).await;
    let mut listed = String::new();
    for (number, data) in (1..).zip(parts) {
        let etag = put_part(app, upload_id, number, data.clone()).await;
        listed.push_str(&format!("<Part><PartNumber>{number}</PartNumber><ETag>{etag}</ETag></Part>"));
    }
    complete(app, key, upload_id, &listed).await;
}

async fn create_upload(app: &Arc<App>, key: &str) -> Uuid {
    let response = create_multipart_upload(app, BUCKET, key, "application/octet-stream")
        .await
        .unwrap();
    Uuid::parse_str(&xml_field(&body_text(response).await, "UploadId")).unwrap()
}

async fn put_part(app: &Arc<App>, upload_id: Uuid, part_number: i32, data: Vec<u8>) -> String {
    let attach = AttachTarget::MultipartPart {
        upload_id,
        part_number,
    };
    let body = Full::new(Bytes::from(data));
    match crate::upload_part(app, body, &attach, false, ContentSha256::Unsigned, None)
        .await
        .unwrap()
    {
        UploadResult::Committed { etag, .. } => etag,
        _ => panic!("the part wasn't committed"),
    }
}

async fn complete(app: &Arc<App>, key: &str, upload_id: Uuid, parts: &str) {
    let body = format!("<CompleteMultipartUpload>{parts}</CompleteMultipartUpload>");
    let response = complete_multipart_upload(
        app,
        BUCKET,
        key,
        &upload_id.to_string(),
        Bytes::from(body),
        &Preconditions::default(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// Each part of the key's current version: its blob, offset and size.
async fn parts_of(app: &App, key: &str) -> Vec<(Uuid, i64, i64)> {
    let client = app.pool.get().await.unwrap();
    client
        .query(
            "SELECT p.blob_id, p.blob_offset, p.size FROM parts p
             JOIN objects o ON o.id = p.object_id
             WHERE o.bucket = $1 AND o.key = $2 AND o.is_latest
             ORDER BY p.part_number",
            &[&BUCKET, &key],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect()
}

/// A copy is a new object on the source's bytes: no new blob. Deleting either
/// leaves the other intact, and the bytes go once both are gone.
#[tokio::test]
async fn a_copy_shares_its_source_bytes() {
    let Some(app) = node().await else { return };
    let data = content(5000, 1);
    put(&app, "source", data.clone()).await;
    let etag = copy(&app, "source", "copy", false).await;
    assert_eq!(etag, md5_hex(&data));
    assert_eq!(parts_of(&app, "copy").await, parts_of(&app, "source").await);
    assert_files(&app, 1).await;

    delete(&app, "source").await;
    assert_eq!(get(&app, "copy").await, Some(data));
    assert_files(&app, 1).await;
    delete(&app, "copy").await;
    assert_files(&app, 0).await;
}

/// A copy of a multipart object shares all its parts, and gets the MD5 of the
/// whole data as its ETag, like a single PUT.
#[tokio::test]
async fn a_copy_of_a_multipart_object_shares_every_part() {
    let Some(app) = node().await else { return };
    let parts = [content(3000, 1), content(2000, 2), content(1000, 3)];
    put_multipart(&app, "source", &parts).await;
    let etag = copy(&app, "source", "copy", false).await;
    let whole = parts.concat();
    assert_eq!(etag, md5_hex(&whole));
    assert_eq!(parts_of(&app, "copy").await, parts_of(&app, "source").await);
    assert_files(&app, 3).await;
    assert_eq!(get(&app, "copy").await, Some(whole));
}

/// Copying an object onto itself (to change its metadata) replaces the version
/// whose bytes it shares, but keeps the bytes.
#[tokio::test]
async fn a_copy_onto_itself_keeps_its_bytes() {
    let Some(app) = node().await else { return };
    let data = content(4000, 7);
    put(&app, "same", data.clone()).await;
    let before = parts_of(&app, "same").await;
    copy(&app, "same", "same", true).await;
    assert_eq!(parts_of(&app, "same").await, before);
    assert_eq!(get(&app, "same").await, Some(data));
    assert_files(&app, 1).await;
}

/// A ranged UploadPartCopy within one part of the source is a part on its
/// bytes, with the range's own MD5 as its ETag.
#[tokio::test]
async fn a_part_copy_within_one_part_shares_its_bytes() {
    let Some(app) = node().await else { return };
    let data = content(1000, 5);
    put(&app, "source", data.clone()).await;
    let upload_id = create_upload(&app, "assembled").await;
    let response = copy_part(
        &app,
        BUCKET,
        "assembled",
        &upload_id.to_string(),
        "1",
        &format!("{BUCKET}/source"),
        Some("bytes=100-299"),
        &Preconditions::default(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let etag = xml_field(&body_text(response).await, "ETag");
    assert_eq!(etag, md5_hex(&data[100..300]));
    complete(&app, "assembled", upload_id, &format!(
        "<Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part>"
    ))
    .await;
    let (source_blob, _, _) = parts_of(&app, "source").await[0];
    assert_eq!(parts_of(&app, "assembled").await, [(source_blob, 100, 200)]);
    assert_files(&app, 1).await;
    assert_eq!(get(&app, "assembled").await, Some(data[100..300].to_vec()));

    // Without the source, most of the blob is garbage, so it's compacted. The
    // packer checks the part against its CRC, which must be the range's.
    delete(&app, "source").await;
    let reports = packer::pass(&app).await.unwrap();
    assert_eq!(reports.len(), 1);
    assert_ne!(parts_of(&app, "assembled").await[0].0, source_blob);
    assert_files(&app, 1).await;
    assert_eq!(get(&app, "assembled").await, Some(data[100..300].to_vec()));
}

/// A range over two parts of the source can't be one part on their bytes, so
/// it's copied as data.
#[tokio::test]
async fn a_part_copy_across_parts_copies_data() {
    let Some(app) = node().await else { return };
    let parts = [content(1000, 1), content(1000, 2)];
    put_multipart(&app, "source", &parts).await;
    let upload_id = create_upload(&app, "assembled").await;
    let response = copy_part(
        &app,
        BUCKET,
        "assembled",
        &upload_id.to_string(),
        "1",
        &format!("{BUCKET}/source"),
        Some("bytes=900-1099"),
        &Preconditions::default(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let etag = xml_field(&body_text(response).await, "ETag");
    let whole = parts.concat();
    assert_eq!(etag, md5_hex(&whole[900..1100]));
    complete(&app, "assembled", upload_id, &format!(
        "<Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part>"
    ))
    .await;
    assert_files(&app, 3).await;
    assert_eq!(get(&app, "assembled").await, Some(whole[900..1100].to_vec()));
}

/// Copies racing deletes of their source either copy it or find it gone, but
/// never leave a copy without its bytes.
#[tokio::test]
async fn copies_racing_deletes_of_their_source_stay_whole() {
    let Some(app) = node().await else { return };
    for round in 0..20 {
        let data = content(3000, round);
        put(&app, "source", data.clone()).await;
        let (source, conditions) = (format!("{BUCKET}/source"), Preconditions::default());
        let (copied, ()) = tokio::join!(
            copy_object(&app, BUCKET, "copy", &source, None, "", &conditions),
            delete(&app, "source"),
        );
        match copied.unwrap().status() {
            StatusCode::OK => {
                assert_eq!(get(&app, "copy").await, Some(data), "round {round}");
                delete(&app, "copy").await;
            }
            StatusCode::NOT_FOUND => assert_eq!(get(&app, "copy").await, None),
            status => panic!("round {round}: {status}"),
        }
        assert_files(&app, 0).await;
    }
}
