//! Multipart uploads, through their handlers.

use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{StatusCode, body::Bytes};
use uuid::Uuid;

use super::{BUCKET, node_with, query_i64};
use crate::{
    App, AttachTarget, UploadResult, packer,
    payload::Payload,
    s3::{
        conditional::Preconditions,
        multipart::{complete::complete_multipart_upload, create::create_multipart_upload},
        objects::delete::delete_object,
    },
};

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

/// A new upload of `key`, with parts 1 and 2 staged; its ID and the parts' ETags.
async fn staged(app: &Arc<App>, key: &str) -> (String, [String; 2]) {
    staged_with(app, key, "").await
}

/// Like `staged`, the upload to give its object the stored `metadata`.
async fn staged_with(app: &Arc<App>, key: &str, metadata: &str) -> (String, [String; 2]) {
    let response = create_multipart_upload(app, BUCKET, key, "x", metadata, None).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = std::str::from_utf8(&body).unwrap();
    let start = body.find("<UploadId>").unwrap() + "<UploadId>".len();
    let upload_id = body[start..body.find("</UploadId>").unwrap()].to_owned();
    let mut etags = [String::new(), String::new()];
    for (i, etag) in etags.iter_mut().enumerate() {
        let attach = AttachTarget::MultipartPart {
            upload_id: upload_id.parse::<Uuid>().unwrap(),
            part_number: i as i32 + 1,
            key: None,
        };
        let body = Full::new(Bytes::from(vec![i as u8; 100]));
        let UploadResult::Committed { etag: e, .. } =
            crate::upload_part(app, body, &attach, Payload::unchecked()).await.unwrap()
        else {
            panic!("the part wasn't committed");
        };
        *etag = e;
    }
    (upload_id, etags)
}

/// Completes the upload with the listed parts: the status, the ETag, and the
/// version ID reported.
async fn complete(
    app: &Arc<App>,
    key: &str,
    upload_id: &str,
    parts: &[(i32, &str)],
) -> (StatusCode, Option<String>, Option<String>) {
    let listed: String = parts
        .iter()
        .map(|(n, etag)| format!("<Part><PartNumber>{n}</PartNumber><ETag>\"{etag}\"</ETag></Part>"))
        .collect();
    let body = Bytes::from(format!("<CompleteMultipartUpload>{listed}</CompleteMultipartUpload>"));
    let response =
        complete_multipart_upload(app, BUCKET, key, upload_id, body, &Preconditions::default(), None)
            .await
            .unwrap();
    let status = response.status();
    let version_id = response
        .headers()
        .get("x-amz-version-id")
        .map(|v| v.to_str().unwrap().to_owned());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = std::str::from_utf8(&body).unwrap();
    let etag = body
        .find("<ETag>")
        .map(|start| body[start + 6..body.find("</ETag>").unwrap()].to_owned());
    (status, etag, version_id)
}

/// A retried completion (its response lost, say) is answered as the first
/// was, once its upload is gone, as long as the version it made is still
/// there and the retry lists the same parts. It changes nothing.
#[tokio::test]
async fn a_retried_completion_succeeds_again() {
    let Some(app) = node().await else { return };
    // Unversioned: no version ID to report.
    let (upload_id, [e1, e2]) = staged(&app, "k").await;
    let parts = [(1, e1.as_str()), (2, e2.as_str())];
    let first = complete(&app, "k", &upload_id, &parts).await;
    assert_eq!((first.0, first.2.as_deref()), (StatusCode::OK, None));
    assert!(first.1.as_deref().unwrap().ends_with("-2\""));
    assert_eq!(complete(&app, "k", &upload_id, &parts).await, first);
    assert_eq!(query_i64(&app, "SELECT count(*) FROM objects").await, 1);

    // A different part list isn't a retry, nor is an ETag that can't be one.
    let not_found = (StatusCode::NOT_FOUND, None, None);
    assert_eq!(complete(&app, "k", &upload_id, &parts[..1]).await, not_found);
    assert_eq!(complete(&app, "k", &upload_id, &[(1, &e1), (2, "nothex")]).await, not_found);
    // Nor is one of another key's upload.
    assert_eq!(complete(&app, "other", &upload_id, &parts).await, not_found);

    // Versioned: the version ID made the first time, while that version is
    // there, even once it's no longer the current one.
    app.pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT pg_temp.cairn_set_versioning($1, 'enabled')", &[&BUCKET])
        .await
        .unwrap();
    let (upload_id, [e1, e2]) = staged(&app, "v").await;
    let parts = [(1, e1.as_str()), (2, e2.as_str())];
    let first = complete(&app, "v", &upload_id, &parts).await;
    let version_id = first.2.clone().unwrap();
    assert_eq!(complete(&app, "v", &upload_id, &parts).await, first);
    super::put(&app, "v", b"newer".to_vec()).await;
    assert_eq!(complete(&app, "v", &upload_id, &parts).await, first);
    let response = delete_object(&app, BUCKET, "v", Some(&version_id)).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(complete(&app, "v", &upload_id, &parts).await, not_found);
}

/// Two completions of one upload at once, as a client's retry can race its
/// first attempt: one completes it, and the other, having waited for the
/// upload's lock, finds what it made.
#[tokio::test]
async fn racing_completions_both_succeed() {
    let Some(app) = node().await else { return };
    for round in 0..10 {
        let key = format!("k{round}");
        let (upload_id, [e1, e2]) = staged(&app, &key).await;
        let run = || {
            let (app, key, upload_id, e1, e2) =
                (app.clone(), key.clone(), upload_id.clone(), e1.clone(), e2.clone());
            tokio::spawn(async move { complete(&app, &key, &upload_id, &[(1, &e1), (2, &e2)]).await })
        };
        let (a, b) = (run(), run());
        let (a, b) = (a.await.unwrap(), b.await.unwrap());
        assert_eq!(a.0, StatusCode::OK, "round {round}");
        assert_eq!(a, b, "round {round}");
    }
    assert_eq!(query_i64(&app, "SELECT count(*) FROM objects").await, 10);
}

/// The metadata an upload was created with is its object's.
#[tokio::test]
async fn a_completed_upload_has_its_metadata() {
    let Some(app) = node().await else { return };
    let metadata = super::metadata::stored(&[("x-amz-meta-from", "upload"), ("content-language", "de")]);
    let (upload_id, [e1, e2]) = staged_with(&app, "k", &metadata).await;
    assert_eq!(complete(&app, "k", &upload_id, &[(1, &e1), (2, &e2)]).await.0, StatusCode::OK);
    let headers = super::metadata::read_headers(&app, "k").await;
    assert_eq!(headers["x-amz-meta-from"], "upload");
    assert_eq!(headers["content-language"], "de");
}

/// An SSE-C upload: its parts are encrypted with its key, its object has its
/// key check, and reads back with the key, also in ranges across segments and
/// parts. A completion needs no key, but one it's given must be the upload's.
#[tokio::test]
async fn an_sse_c_upload_makes_an_sse_c_object() {
    let Some(app) = node().await else { return };
    let customer = super::customer_key(&[3; 32]);
    let response = create_multipart_upload(&app, BUCKET, "k", "x", "", Some(&customer)).await.unwrap();
    assert_eq!(response.headers()["x-amz-server-side-encryption-customer-algorithm"], "AES256");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = std::str::from_utf8(&body).unwrap();
    let start = body.find("<UploadId>").unwrap() + "<UploadId>".len();
    let upload_id = body[start..body.find("</UploadId>").unwrap()].to_owned();
    let lens = [70_000usize, 5, 65_536];
    let data: Vec<Vec<u8>> = lens.iter().enumerate().map(|(i, len)| vec![i as u8 + 1; *len]).collect();
    let mut etags = Vec::new();
    for (i, part) in data.iter().enumerate() {
        let attach = AttachTarget::MultipartPart {
            upload_id: upload_id.parse().unwrap(),
            part_number: i as i32 + 1,
            key: Some(zeroize::Zeroizing::new(*customer.key())),
        };
        let body = Full::new(Bytes::from(part.clone()));
        let UploadResult::Committed { etag, .. } =
            crate::upload_part(&app, body, &attach, Payload::unchecked()).await.unwrap()
        else {
            panic!("part {i} wasn't committed");
        };
        etags.push(etag);
    }
    let parts: Vec<(i32, &str)> = etags.iter().enumerate().map(|(i, e)| (i as i32 + 1, e.as_str())).collect();
    // Another key is refused; none will do.
    let listed: String = parts
        .iter()
        .map(|(n, etag)| format!("<Part><PartNumber>{n}</PartNumber><ETag>\"{etag}\"</ETag></Part>"))
        .collect();
    let request = Bytes::from(format!("<CompleteMultipartUpload>{listed}</CompleteMultipartUpload>"));
    let other = super::customer_key(&[4; 32]);
    let response = complete_multipart_upload(&app, BUCKET, "k", &upload_id, request, &Preconditions::default(), Some(&other))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let (status, etag, _) = complete(&app, "k", &upload_id, &parts).await;
    assert_eq!(status, StatusCode::OK);
    assert!(etag.unwrap().ends_with("-3\""));

    let whole: Vec<u8> = data.concat();
    assert_eq!(super::get_sealed(&app, "k", None, Some(&customer)).await, (StatusCode::OK, whole.clone()));
    for (start, end) in [(65_530, 70_003), (69_999, 70_006), (70_004, 135_541), (0, 135_541)] {
        let range = format!("bytes={start}-{}", end - 1);
        let (status, body) = super::get_sealed(&app, "k", Some(&range), Some(&customer)).await;
        assert_eq!(status, StatusCode::PARTIAL_CONTENT, "{range}");
        assert_eq!(body, &whole[start..end], "{range}");
    }
    assert_eq!(super::get_sealed(&app, "k", None, None).await.0, StatusCode::BAD_REQUEST);
}
