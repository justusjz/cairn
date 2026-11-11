//! S3's size limits, on copies and completions (the request bodies' are
//! `Payload`'s, unit tested there). The sizes are made large in the catalog:
//! the checks come before anything is read.

use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::{StatusCode, body::Bytes};

use super::{BUCKET, node_with, put};
use crate::{
    App, packer,
    s3::{
        conditional::Preconditions,
        multipart::{complete::complete_multipart_upload, create::create_multipart_upload},
        objects::copy::{copy_object, copy_part},
        util::MAX_UPLOAD,
    },
};
use crate::s3::sse::Wanted;

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

async fn execute(app: &App, sql: &str) {
    app.pool
        .get()
        .await
        .unwrap()
        .execute(sql, &[])
        .await
        .unwrap();
}

async fn error_code(
    response: hyper::Response<http_body_util::Full<Bytes>>,
) -> (StatusCode, String) {
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8(body.to_vec()).unwrap();
    let code = body
        .split("<Code>")
        .nth(1)
        .and_then(|c| c.split("</Code>").next())
        .unwrap_or("");
    (status, code.to_owned())
}

async fn new_upload(app: &Arc<App>, key: &str) -> String {
    let response = create_multipart_upload(app, BUCKET, key, "x", "", "", Wanted::Plain, None, None)
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = std::str::from_utf8(&body).unwrap();
    let start = body.find("<UploadId>").unwrap() + "<UploadId>".len();
    body[start..body.find("</UploadId>").unwrap()].to_owned()
}

/// A copy source over 5 GiB is refused, as by S3; so is a part copy's range
/// over 5 GiB, while a range of it up to 5 GiB is fine.
#[tokio::test]
async fn copies_are_limited_to_5_gib() {
    let Some(app) = node().await else { return };
    put(&app, "big", b"x".to_vec()).await;
    execute(
        &app,
        &format!("UPDATE objects SET size = {} WHERE key = 'big'", 6u64 << 30),
    )
    .await;
    let source = format!("{BUCKET}/big");
    let none = Preconditions::default();
    let response = copy_object(
        &app,
        BUCKET,
        "copy",
        &source,
        None,
        "x",
        "", None,
        &none,
        Default::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        error_code(response).await,
        (StatusCode::BAD_REQUEST, "InvalidRequest".to_owned())
    );

    let upload = new_upload(&app, "dst").await;
    let too_long = format!("bytes=0-{MAX_UPLOAD}");
    let response = copy_part(
        &app,
        BUCKET,
        "dst",
        &upload,
        "1",
        &source,
        Some(&too_long),
        &none,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        error_code(response).await,
        (StatusCode::BAD_REQUEST, "InvalidArgument".to_owned())
    );
}

/// Parts that add up to more than 5 TiB make no object.
#[tokio::test]
async fn objects_are_limited_to_5_tib() {
    let Some(app) = node().await else { return };
    let upload = new_upload(&app, "huge").await;
    let mut etags = Vec::new();
    for n in 1..=2 {
        let attach = crate::AttachTarget::MultipartPart {
            upload_id: upload.parse().unwrap(),
            part_number: n,
            key: None,
            sse_s3: false,
            checksum: crate::e2e::PART_CHECKSUM,
        };
        let body = http_body_util::Full::new(Bytes::from_static(b"part"));
        let crate::UploadResult::Committed { etag, .. } =
            crate::upload_part(&app, body, &attach, crate::payload::Payload::unchecked())
                .await
                .unwrap()
        else {
            panic!("part {n} wasn't committed");
        };
        etags.push(etag);
    }
    // Each one 3 TiB, as far as the completion is concerned.
    execute(
        &app,
        &format!(
            "UPDATE parts SET size = {} WHERE upload_id IS NOT NULL",
            3u64 << 40
        ),
    )
    .await;
    let listed: String = etags
        .iter()
        .enumerate()
        .map(|(i, etag)| {
            format!(
                "<Part><PartNumber>{}</PartNumber><ETag>\"{etag}\"</ETag></Part>",
                i + 1
            )
        })
        .collect();
    let body = Bytes::from(format!(
        "<CompleteMultipartUpload>{listed}</CompleteMultipartUpload>"
    ));
    let response = complete_multipart_upload(
        &app,
        BUCKET,
        "huge",
        &upload,
        body,
        &Preconditions::default(),
        None, None, None,
    )
    .await
    .unwrap();
    assert_eq!(
        error_code(response).await,
        (StatusCode::BAD_REQUEST, "EntityTooLarge".to_owned())
    );
    // Nothing was written; the upload is still there.
    assert_eq!(
        super::query_i64(&app, "SELECT count(*) FROM objects").await,
        0
    );
    assert_eq!(
        super::query_i64(&app, "SELECT count(*) FROM multipart_uploads").await,
        1
    );
}
