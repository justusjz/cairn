//! An object's metadata (see `s3::metadata`): stored by its write, returned by
//! GET and HEAD, and kept or replaced by a copy.

use std::sync::Arc;

use http_body_util::Full;
use hyper::{HeaderMap, StatusCode, body::Bytes};

use super::{BUCKET, node_with};
use crate::{
    App, AttachTarget, UploadResult, packer,
    payload::Payload,
    s3::{
        conditional::Preconditions,
        metadata,
        objects::{copy::copy_object, get::get_object, get::head_object},
    },
};

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

/// The metadata `pairs` of request headers give an object.
pub(super) fn stored(pairs: &[(&str, &str)]) -> String {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        headers.append(
            hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
    }
    metadata::from_request(&headers).unwrap()
}

/// Writes `key` with the stored `metadata`, as PutObject does.
async fn put_with(app: &Arc<App>, key: &str, metadata: String) {
    let attach = AttachTarget::Object {
        bucket: BUCKET.to_owned(),
        key: key.to_owned(),
        content_type: "text/plain".to_owned(),
        metadata,
        conditions: Preconditions::default(),
        sealing: None,
        checksum: crate::e2e::OBJECT_CHECKSUM,
    };
    let body = Full::new(Bytes::from_static(b"data"));
    let result = crate::upload_part(app, body, &attach, Payload::unchecked()).await.unwrap();
    assert!(matches!(result, UploadResult::Committed { .. }));
}

/// The headers of a GET and a HEAD of `key`, which must be the same.
pub(super) async fn read_headers(app: &Arc<App>, key: &str) -> HeaderMap {
    let none = Preconditions::default();
    let got = get_object(app, BUCKET, key, None, None, &none, None, None, false).await.unwrap();
    let head = head_object(app, BUCKET, key, None, None, &none, None, None, false).await.unwrap();
    assert_eq!(got.status(), StatusCode::OK);
    assert_eq!(got.headers(), head.headers(), "a HEAD answers as a GET does");
    got.headers().clone()
}

#[tokio::test]
async fn a_write_stores_metadata_that_reads_return() {
    let Some(app) = node().await else { return };
    put_with(
        &app,
        "k",
        stored(&[
            ("x-amz-meta-color", "blue"),
            ("x-amz-meta-empty", ""),
            ("cache-control", "max-age=60"),
            ("content-disposition", "attachment; filename=\"k.txt\""),
            ("content-encoding", "aws-chunked, gzip"),
            ("expires", "Thu, 01 Dec 2094 16:00:00 GMT"),
        ]),
    )
    .await;
    let headers = read_headers(&app, "k").await;
    assert_eq!(headers["x-amz-meta-color"], "blue");
    assert_eq!(headers["x-amz-meta-empty"], "");
    assert_eq!(headers["cache-control"], "max-age=60");
    assert_eq!(headers["content-disposition"], "attachment; filename=\"k.txt\"");
    assert_eq!(headers["content-encoding"], "gzip");
    assert_eq!(headers["expires"], "Thu, 01 Dec 2094 16:00:00 GMT");
    assert_eq!(headers["content-type"], "text/plain");

    // An overwrite replaces it all.
    put_with(&app, "k", String::new()).await;
    let headers = read_headers(&app, "k").await;
    assert!(!headers.contains_key("x-amz-meta-color"));
    assert!(!headers.contains_key("cache-control"));
}

#[tokio::test]
async fn a_copy_keeps_or_replaces_metadata() {
    let Some(app) = node().await else { return };
    put_with(&app, "src", stored(&[("x-amz-meta-a", "1"), ("cache-control", "no-cache")])).await;
    let source = format!("{BUCKET}/src");
    let none = Preconditions::default();
    let replacement = stored(&[("x-amz-meta-b", "2")]);

    // COPY (the default): the source's, whatever the request says.
    let response = copy_object(&app, BUCKET, "kept", &source, None, "a/b", &replacement, &none, Default::default())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let headers = read_headers(&app, "kept").await;
    assert_eq!(headers["x-amz-meta-a"], "1");
    assert_eq!(headers["cache-control"], "no-cache");
    assert!(!headers.contains_key("x-amz-meta-b"));
    assert_eq!(headers["content-type"], "text/plain");

    // REPLACE: the request's, all of it; a copy onto the source itself too.
    for dest in ["replaced", "src"] {
        let response =
            copy_object(&app, BUCKET, dest, &source, Some("REPLACE"), "a/b", &replacement, &none, Default::default())
                .await
                .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{dest}");
        let headers = read_headers(&app, dest).await;
        assert_eq!(headers["x-amz-meta-b"], "2", "{dest}");
        assert!(!headers.contains_key("x-amz-meta-a"), "{dest}");
        assert!(!headers.contains_key("cache-control"), "{dest}");
        assert_eq!(headers["content-type"], "a/b", "{dest}");
    }
}
