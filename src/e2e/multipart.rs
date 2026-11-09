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
use crate::s3::sse::Wanted;

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

/// A new upload of `key`, with parts 1 (5 MiB, as small as a part that isn't
/// the last may be) and 2 staged; its ID and the parts' ETags.
async fn staged(app: &Arc<App>, key: &str) -> (String, [String; 2]) {
    staged_with(app, key, "").await
}

/// Like `staged`, the upload to give its object the stored `metadata`.
async fn staged_with(app: &Arc<App>, key: &str, metadata: &str) -> (String, [String; 2]) {
    let response = create_multipart_upload(app, BUCKET, key, "x", metadata, Wanted::Plain, None).await.unwrap();
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
            sse_s3: false,
        };
        let len = if i == 0 { crate::s3::util::MIN_PART as usize } else { 100 };
        let body = Full::new(Bytes::from(vec![i as u8; len]));
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
    let response = create_multipart_upload(&app, BUCKET, "k", "x", "", Wanted::Customer(&customer), None).await.unwrap();
    assert_eq!(response.headers()["x-amz-server-side-encryption-customer-algorithm"], "AES256");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = std::str::from_utf8(&body).unwrap();
    let start = body.find("<UploadId>").unwrap() + "<UploadId>".len();
    let upload_id = body[start..body.find("</UploadId>").unwrap()].to_owned();
    // Every part but the last at least 5 MiB; the first ends 3 bytes into a
    // segment, so the parts' boundaries and the segments' don't line up.
    let min = crate::s3::util::MIN_PART as usize;
    let lens = [min + 3, min, 1000];
    let data: Vec<Vec<u8>> = lens.iter().enumerate().map(|(i, len)| vec![i as u8 + 1; *len]).collect();
    let mut etags = Vec::new();
    for (i, part) in data.iter().enumerate() {
        let attach = AttachTarget::MultipartPart {
            upload_id: upload_id.parse().unwrap(),
            part_number: i as i32 + 1,
            key: Some(zeroize::Zeroizing::new(*customer.key())),
            sse_s3: false,
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
    let total = whole.len();
    for (start, end) in [
        (65_530, 65_545),
        (min - 2, min + 5),
        (2 * min, 2 * min + 10),
        (2 * min + 1, total),
        (0, total),
    ] {
        let range = format!("bytes={start}-{}", end - 1);
        let (status, body) = super::get_sealed(&app, "k", Some(&range), Some(&customer)).await;
        assert_eq!(status, StatusCode::PARTIAL_CONTENT, "{range}");
        assert_eq!(body, &whole[start..end], "{range}");
    }
    assert_eq!(super::get_sealed(&app, "k", None, None).await.0, StatusCode::BAD_REQUEST);
}

/// Every part but the last must be at least 5 MiB, as in S3; the upload stays,
/// for the client to complete with other parts. The last may be any size.
#[tokio::test]
async fn parts_but_the_last_must_be_5_mib() {
    let Some(app) = node().await else { return };
    let (upload_id, [_, e2]) = staged(&app, "k").await;
    // Part 1 again, now 4 bytes.
    let attach = AttachTarget::MultipartPart {
        upload_id: upload_id.parse().unwrap(),
        part_number: 1,
        key: None,
        sse_s3: false,
    };
    let body = Full::new(Bytes::from_static(b"tiny"));
    let UploadResult::Committed { etag: tiny, .. } =
        crate::upload_part(&app, body, &attach, Payload::unchecked()).await.unwrap()
    else {
        panic!("the part wasn't committed");
    };
    let listed = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"{tiny}\"</ETag></Part>\
         <Part><PartNumber>2</PartNumber><ETag>\"{e2}\"</ETag></Part></CompleteMultipartUpload>"
    );
    let response = complete_multipart_upload(&app, BUCKET, "k", &upload_id, Bytes::from(listed), &Preconditions::default(), None)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(std::str::from_utf8(&body).unwrap().contains("<Code>EntityTooSmall</Code>"));
    // The upload is still there, and part 1 on its own (the last) completes it.
    assert_eq!(complete(&app, "k", &upload_id, &[(1, &tiny)]).await.0, StatusCode::OK);
    assert_eq!(super::get(&app, "k").await, Some(b"tiny".to_vec()));
}

/// One page of ListParts: its parts (number, ETag, size), and the next marker
/// if it's truncated.
async fn parts_page(
    app: &Arc<App>,
    key: &str,
    upload_id: &str,
    marker: i32,
    max_parts: i64,
) -> (StatusCode, Vec<(i32, String, u64)>, Option<i32>) {
    let response = crate::s3::multipart::list_parts::list_parts(app, BUCKET, key, upload_id, marker, max_parts)
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = std::str::from_utf8(&body).unwrap().to_owned();
    let field = |s: &str, name: &str| {
        let open = format!("<{name}>");
        let start = s.find(&open)? + open.len();
        Some(s[start..start + s[start..].find(&format!("</{name}>"))?].to_owned())
    };
    let parts = body
        .split("<Part>")
        .skip(1)
        .map(|p| {
            (
                field(p, "PartNumber").unwrap().parse().unwrap(),
                field(p, "ETag").unwrap().trim_matches('"').to_owned(),
                field(p, "Size").unwrap().parse().unwrap(),
            )
        })
        .collect();
    let next = (field(&body, "IsTruncated").as_deref() == Some("true"))
        .then(|| field(&body, "NextPartNumberMarker").unwrap().parse().unwrap());
    (status, parts, next)
}

/// ListParts pages through an upload's parts by number, each with the ETag
/// it was last uploaded with and the size of its data; only for the upload's
/// own bucket and key.
#[tokio::test]
async fn lists_an_uploads_parts() {
    let Some(app) = node().await else { return };
    let customer = super::customer_key(&[7; 32]);
    let response = create_multipart_upload(&app, BUCKET, "k", "x", "", Wanted::Customer(&customer), None).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = std::str::from_utf8(&body).unwrap();
    let start = body.find("<UploadId>").unwrap() + "<UploadId>".len();
    let upload_id = body[start..body.find("</UploadId>").unwrap()].to_owned();
    // Parts 3, 1 and 2, and 2 again: the second upload of it counts.
    let mut etags = std::collections::BTreeMap::new();
    for (number, len) in [(3, 30), (1, 10), (2, 20), (2, 25)] {
        let attach = AttachTarget::MultipartPart {
            upload_id: upload_id.parse().unwrap(),
            part_number: number,
            key: Some(zeroize::Zeroizing::new(*customer.key())),
            sse_s3: false,
        };
        let body = Full::new(Bytes::from(vec![number as u8; len]));
        let UploadResult::Committed { etag, .. } =
            crate::upload_part(&app, body, &attach, Payload::unchecked()).await.unwrap()
        else {
            panic!("part {number} wasn't committed");
        };
        etags.insert(number, (etag, len as u64));
    }
    let all: Vec<(i32, String, u64)> = etags.iter().map(|(n, (e, len))| (*n, e.clone(), *len)).collect();
    // Sizes are the data's, not the ciphertext's.
    assert_eq!(parts_page(&app, "k", &upload_id, 0, 1000).await, (StatusCode::OK, all.clone(), None));
    assert_eq!(parts_page(&app, "k", &upload_id, 0, 2).await, (StatusCode::OK, all[..2].to_vec(), Some(2)));
    assert_eq!(parts_page(&app, "k", &upload_id, 2, 2).await, (StatusCode::OK, all[2..].to_vec(), None));
    // Another key's upload, or none, is no such upload.
    assert_eq!(parts_page(&app, "other", &upload_id, 0, 1000).await.0, StatusCode::NOT_FOUND);
    assert_eq!(parts_page(&app, "k", "not-an-upload", 0, 1000).await.0, StatusCode::NOT_FOUND);
}

/// A completion with If-Match, where the key has no object, is S3's 404
/// NoSuchKey; the upload stays.
#[tokio::test]
async fn if_match_without_an_object_is_no_such_key() {
    let Some(app) = node().await else { return };
    let (upload_id, [e1, e2]) = staged(&app, "k").await;
    let mut headers = hyper::HeaderMap::new();
    headers.insert("if-match", "*".parse().unwrap());
    let listed = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"{e1}\"</ETag></Part>\
         <Part><PartNumber>2</PartNumber><ETag>\"{e2}\"</ETag></Part></CompleteMultipartUpload>"
    );
    let conditions = Preconditions::from_headers(&headers);
    let response = complete_multipart_upload(&app, BUCKET, "k", &upload_id, Bytes::from(listed), &conditions, None)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(std::str::from_utf8(&body).unwrap().contains("<Code>NoSuchKey</Code>"));
    assert_eq!(complete(&app, "k", &upload_id, &[(1, &e1), (2, &e2)]).await.0, StatusCode::OK);
}
