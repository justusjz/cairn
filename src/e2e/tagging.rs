//! Tags (see `s3::tags`): an object version's, kept in place, and a
//! bucket's, as S3 answers for them (observed on S3; see
//! `plans/tagging.md`).

use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{HeaderMap, Response, StatusCode, body::Bytes};
use uuid::Uuid;

use super::{BUCKET, customer_key, node_with, put, put_sealed};
use crate::{
    App, AttachTarget, UploadResult,
    packer,
    payload::Payload,
    s3::{
        buckets::{
            tagging::{delete_bucket_tagging, get_bucket_tagging, put_bucket_tagging},
            versioning::put_bucket_versioning,
        },
        conditional::Preconditions,
        multipart::{complete::complete_multipart_upload, create::create_multipart_upload},
        objects::{
            copy::{CopyKeys, copy_object},
            delete::delete_object,
            get::head_object,
            tagging::{delete_object_tagging, get_object_tagging, put_object_tagging},
        },
        sse::Wanted,
        tags::{On, Tags},
    },
};

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

async fn text(response: Response<Full<Bytes>>) -> (StatusCode, HeaderMap, String) {
    let (parts, body) = response.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    (parts.status, parts.headers, String::from_utf8(body.to_vec()).unwrap())
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).map(|v| v.to_str().unwrap())
}

/// A `<Tagging>` document of `pairs`.
fn tagging(pairs: &[(&str, &str)]) -> Bytes {
    let tags: String =
        pairs.iter().map(|(k, v)| format!("<Tag><Key>{k}</Key><Value>{v}</Value></Tag>")).collect();
    Bytes::from(format!("<Tagging xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><TagSet>{tags}</TagSet></Tagging>"))
}

/// The stored form of `x-amz-tagging: header`.
fn stored(header: &str) -> String {
    Tags::from_header(header.as_bytes()).unwrap().stored()
}

/// Writes `key` with the tags of `x-amz-tagging: header`.
async fn put_tagged(app: &Arc<App>, key: &str, data: Vec<u8>, header: &str) -> Option<String> {
    let attach = AttachTarget::Object {
        bucket: BUCKET.to_owned(),
        key: key.to_owned(),
        content_type: "application/octet-stream".to_owned(),
        metadata: String::new(),
        conditions: Preconditions::default(),
        sealing: None,
        checksum: crate::e2e::OBJECT_CHECKSUM,
        tags: stored(header),
    };
    let result = crate::upload_part(app, Full::new(Bytes::from(data)), &attach, Payload::unchecked()).await.unwrap();
    let UploadResult::Committed { version_id, .. } = result else { panic!("not committed") };
    version_id
}

/// GetObjectTagging's answer: its status, `x-amz-version-id`, and the tags,
/// as `k=v&k=v` (empty for none), or the error code.
async fn tags_of(app: &App, key: &str, version: Option<&str>) -> (StatusCode, Option<String>, String) {
    let (status, headers, body) = text(get_object_tagging(app, BUCKET, key, version).await.unwrap()).await;
    let version_id = header(&headers, "x-amz-version-id").map(str::to_owned);
    if !status.is_success() {
        let code = body.split("<Code>").nth(1).unwrap().split("</Code>").next().unwrap().to_owned();
        return (status, version_id, code);
    }
    assert!(body.contains("<Tagging xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><TagSet"), "{body}");
    let tags = Tags::from_xml(body.as_bytes(), On::Object).unwrap();
    let pairs: Vec<String> = tags.iter().map(|(k, v)| format!("{k}={v}")).collect();
    (status, version_id, pairs.join("&"))
}

/// The `x-amz-tagging-count` a HEAD tells.
async fn count(app: &App, key: &str) -> Option<String> {
    let response = head_object(app, BUCKET, key, None, None, None, &Preconditions::default(), None, None, false).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    header(response.headers(), "x-amz-tagging-count").map(str::to_owned)
}

async fn enable_versioning(app: &App, state: &str) {
    let body = format!("<VersioningConfiguration><Status>{state}</Status></VersioningConfiguration>");
    let response = put_bucket_versioning(app, BUCKET, Bytes::from(body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// The version's ETag and last-modified time, as stored, and how many
/// versions the key has.
async fn row(app: &App, key: &str) -> (Option<String>, String, i64) {
    let client = app.pool.get().await.unwrap();
    let row = client
        .query_one(
            "SELECT etag, last_modified::text, (SELECT count(*) FROM objects WHERE bucket = $1 AND key = $2)
             FROM objects WHERE bucket = $1 AND key = $2 AND is_latest",
            &[&BUCKET, &key],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1), row.get(2))
}

#[tokio::test]
async fn writes_store_tags_that_reads_count() {
    let Some(app) = node().await else { return };
    put_tagged(&app, "a", vec![1; 10], "z=1&a=2").await;
    // Sorted by key, as S3 hands them back.
    assert_eq!(tags_of(&app, "a", None).await, (StatusCode::OK, None, "a=2&z=1".to_owned()));
    assert_eq!(count(&app, "a").await.as_deref(), Some("2"));
    let response = crate::e2e::get(&app, "a").await;
    assert_eq!(response, Some(vec![1; 10]));
    let get = crate::s3::objects::get::get_object(
        &app, BUCKET, "a", None, Some("bytes=0-0"), None, &Preconditions::default(), None, None, false,
    )
    .await
    .unwrap();
    assert_eq!(get.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(header(get.headers(), "x-amz-tagging-count"), Some("2"));
    // None: no count.
    put(&app, "b", vec![2]).await;
    assert_eq!(count(&app, "b").await, None);
    assert_eq!(tags_of(&app, "b", None).await, (StatusCode::OK, None, String::new()));
}

#[tokio::test]
async fn tagging_changes_a_version_in_place() {
    let Some(app) = node().await else { return };
    enable_versioning(&app, "Enabled").await;
    let version = put_tagged(&app, "a", vec![1], "a=1").await.unwrap();
    let before = row(&app, "a").await;
    let response = put_object_tagging(&app, BUCKET, "a", None, tagging(&[("m", "1"), ("b", "")])).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(header(response.headers(), "x-amz-version-id"), Some(version.as_str()));
    // No new version, the same ETag and last-modified time.
    assert_eq!(row(&app, "a").await, before);
    assert_eq!(tags_of(&app, "a", None).await, (StatusCode::OK, Some(version.clone()), "b=&m=1".to_owned()));
    // An empty TagSet empties it.
    let response = put_object_tagging(&app, BUCKET, "a", None, tagging(&[])).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(tags_of(&app, "a", None).await.2, "");
    put_object_tagging(&app, BUCKET, "a", None, tagging(&[("c", "3")])).await.unwrap();
    let response = delete_object_tagging(&app, BUCKET, "a", None).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(header(response.headers(), "x-amz-version-id"), Some(version.as_str()));
    assert_eq!(tags_of(&app, "a", None).await.2, "");
    assert_eq!(count(&app, "a").await, None);
    // Again, without tags: still 204.
    assert_eq!(delete_object_tagging(&app, BUCKET, "a", None).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(row(&app, "a").await, before);
    // A document S3 doesn't take changes nothing.
    put_object_tagging(&app, BUCKET, "a", None, tagging(&[("c", "3")])).await.unwrap();
    let (status, _, body) =
        text(put_object_tagging(&app, BUCKET, "a", None, tagging(&[("a", "1"), ("a", "2")])).await.unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("<Code>InvalidTag</Code>"), "{body}");
    assert_eq!(tags_of(&app, "a", None).await.2, "c=3");
}

#[tokio::test]
async fn each_version_has_its_own_tags() {
    let Some(app) = node().await else { return };
    // Unversioned: no version ID, but `null` names the version.
    put_tagged(&app, "u", vec![1], "a=1").await;
    let response = put_object_tagging(&app, BUCKET, "u", None, tagging(&[("b", "2")])).await.unwrap();
    assert_eq!(header(response.headers(), "x-amz-version-id"), None);
    assert_eq!(tags_of(&app, "u", Some("null")).await, (StatusCode::OK, None, "b=2".to_owned()));
    // Suspended: the null version reports itself as such.
    enable_versioning(&app, "Suspended").await;
    put_tagged(&app, "n", vec![1], "a=1").await;
    assert_eq!(tags_of(&app, "n", None).await, (StatusCode::OK, Some("null".to_owned()), "a=1".to_owned()));
    enable_versioning(&app, "Enabled").await;
    let old = put_tagged(&app, "v", vec![1], "v=a").await.unwrap();
    let new = put_tagged(&app, "v", vec![2], "v=b").await.unwrap();
    assert_eq!(tags_of(&app, "v", Some(&old)).await, (StatusCode::OK, Some(old.clone()), "v=a".to_owned()));
    let response = put_object_tagging(&app, BUCKET, "v", Some(&old), tagging(&[("v", "a2")])).await.unwrap();
    assert_eq!(header(response.headers(), "x-amz-version-id"), Some(old.as_str()));
    assert_eq!(tags_of(&app, "v", Some(&old)).await.2, "v=a2");
    assert_eq!(tags_of(&app, "v", None).await, (StatusCode::OK, Some(new.clone()), "v=b".to_owned()));
    // A delete marker has none: 405, named or current, as S3 answers.
    let deleted = delete_object(&app, BUCKET, "v", None).await.unwrap();
    let marker = header(deleted.headers(), "x-amz-version-id").unwrap().to_owned();
    for version in [None, Some(marker.as_str())] {
        for response in [
            get_object_tagging(&app, BUCKET, "v", version).await.unwrap(),
            put_object_tagging(&app, BUCKET, "v", version, tagging(&[("a", "1")])).await.unwrap(),
            delete_object_tagging(&app, BUCKET, "v", version).await.unwrap(),
        ] {
            let (status, headers, body) = text(response).await;
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
            assert!(body.contains("<Code>MethodNotAllowed</Code>"), "{body}");
            assert_eq!(header(&headers, "allow"), Some("DELETE"));
            assert_eq!(header(&headers, "x-amz-delete-marker"), Some("true"));
            assert_eq!(header(&headers, "x-amz-version-id"), Some(marker.as_str()));
        }
    }
    assert_eq!(tags_of(&app, "v", Some("null")).await.2, "NoSuchVersion");
    assert_eq!(tags_of(&app, "missing", None).await.2, "NoSuchKey");
    for response in [
        put_object_tagging(&app, BUCKET, "missing", None, tagging(&[("a", "1")])).await.unwrap(),
        delete_object_tagging(&app, BUCKET, "missing", None).await.unwrap(),
    ] {
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    let response = put_object_tagging(&app, BUCKET, "v", Some("null"), tagging(&[("a", "1")])).await.unwrap();
    assert_eq!(text(response).await.0, StatusCode::NOT_FOUND);
    let (status, _, body) = text(delete_object_tagging(&app, "nope", "v", None).await.unwrap()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("<Code>NoSuchBucket</Code>"), "{body}");
}

#[tokio::test]
async fn an_sse_c_objects_tags_need_no_key() {
    let Some(app) = node().await else { return };
    let customer = customer_key(&[7; 32]);
    put_sealed(&app, "s", vec![1; 10], &customer).await;
    let response = put_object_tagging(&app, BUCKET, "s", None, tagging(&[("e", "1")])).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(tags_of(&app, "s", None).await.2, "e=1");
    let head =
        head_object(&app, BUCKET, "s", None, None, None, &Preconditions::default(), Some(&customer), None, false).await.unwrap();
    assert_eq!(header(head.headers(), "x-amz-tagging-count"), Some("1"));
}

#[tokio::test]
async fn copies_keep_or_replace_tags() {
    let Some(app) = node().await else { return };
    put_tagged(&app, "src", vec![1; 100], "s=1").await;
    let source = format!("{BUCKET}/src");
    let none = Preconditions::default();
    let copy = |dest: &'static str, tags: Option<&'static str>, keys: CopyKeys<'static>| {
        let (app, source) = (app.clone(), source.clone());
        async move {
            let tags = tags.map(stored);
            copy_object(&app, BUCKET, dest, &source, None, "", "", tags.as_deref(), &Preconditions::default(), keys)
                .await
                .unwrap()
        }
    };
    // Sharing the source's bytes, or written again (encrypted with another
    // key): either way, the source's tags, unless they're replaced.
    assert_eq!(copy("kept", None, CopyKeys::default()).await.status(), StatusCode::OK);
    assert_eq!(tags_of(&app, "kept", None).await.2, "s=1");
    assert_eq!(copy("replaced", Some("n=1&m=2"), CopyKeys::default()).await.status(), StatusCode::OK);
    assert_eq!(tags_of(&app, "replaced", None).await.2, "m=2&n=1");
    assert_eq!(copy("emptied", Some(""), CopyKeys::default()).await.status(), StatusCode::OK);
    assert_eq!(tags_of(&app, "emptied", None).await.2, "");
    let customer: &'static _ = Box::leak(Box::new(customer_key(&[9; 32])));
    let sealed = CopyKeys { dest: Wanted::Customer(customer), ..CopyKeys::default() };
    assert_eq!(copy("sealed", None, sealed).await.status(), StatusCode::OK);
    assert_eq!(tags_of(&app, "sealed", None).await.2, "s=1");
    // Onto itself: replacing its tags is a change, as in S3.
    let unchanged = copy_object(&app, BUCKET, "src", &source, None, "", "", None, &none, CopyKeys::default()).await;
    assert_eq!(unchanged.unwrap().status(), StatusCode::BAD_REQUEST);
    let new_tags = stored("n=2");
    let retagged = copy_object(&app, BUCKET, "src", &source, None, "", "", Some(&new_tags), &none, CopyKeys::default());
    assert_eq!(retagged.await.unwrap().status(), StatusCode::OK);
    assert_eq!(tags_of(&app, "src", None).await.2, "n=2");
    // And replacing its metadata keeps them.
    let metadata = copy_object(&app, BUCKET, "src", &source, Some("REPLACE"), "a/b", "", None, &none, CopyKeys::default());
    assert_eq!(metadata.await.unwrap().status(), StatusCode::OK);
    assert_eq!(tags_of(&app, "src", None).await.2, "n=2");
}

#[tokio::test]
async fn an_upload_gives_its_tags_to_its_object() {
    let Some(app) = node().await else { return };
    let response =
        create_multipart_upload(&app, BUCKET, "m", "x", "", &stored("m=1"), Wanted::Plain, None, None).await.unwrap();
    let (_, _, body) = text(response).await;
    let start = body.find("<UploadId>").unwrap() + "<UploadId>".len();
    let upload_id = body[start..body.find("</UploadId>").unwrap()].to_owned();
    let attach = AttachTarget::MultipartPart {
        upload_id: upload_id.parse::<Uuid>().unwrap(),
        part_number: 1,
        key: None,
        sse_s3: false,
        checksum: crate::e2e::PART_CHECKSUM,
    };
    let result = crate::upload_part(&app, Full::new(Bytes::from(vec![1; 10])), &attach, Payload::unchecked()).await;
    let UploadResult::Committed { etag, .. } = result.unwrap() else { panic!("not committed") };
    let body = format!("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"{etag}\"</ETag></Part></CompleteMultipartUpload>");
    let response = complete_multipart_upload(
        &app, BUCKET, "m", &upload_id, Bytes::from(body), &Preconditions::default(), None, None, None, None,
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(tags_of(&app, "m", None).await.2, "m=1");
    assert_eq!(count(&app, "m").await.as_deref(), Some("1"));
}

#[tokio::test]
async fn buckets_have_tags_of_their_own() {
    let Some(app) = node().await else { return };
    let get = || async {
        let (status, _, body) = text(get_bucket_tagging(&app, BUCKET).await.unwrap()).await;
        (status, body)
    };
    let (status, body) = get().await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("<Code>NoSuchTagSet</Code><Message>The TagSet does not exist</Message>"), "{body}");
    assert_eq!(delete_bucket_tagging(&app, BUCKET).await.unwrap().status(), StatusCode::NO_CONTENT);
    let response = put_bucket_tagging(&app, BUCKET, tagging(&[("c", "2"), ("b", "")])).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let (status, body) = get().await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.ends_with(
            "<TagSet><Tag><Key>b</Key><Value></Value></Tag><Tag><Key>c</Key><Value>2</Value></Tag></TagSet></Tagging>"
        ),
        "{body}"
    );
    // Its limits are a bucket's: 50, and `aws:` with its own message.
    let fifty: Vec<(String, String)> = (0..50).map(|i| (format!("k{i}"), "v".to_owned())).collect();
    let fifty: Vec<(&str, &str)> = fifty.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    assert_eq!(put_bucket_tagging(&app, BUCKET, tagging(&fifty)).await.unwrap().status(), StatusCode::NO_CONTENT);
    let (status, _, body) = text(put_bucket_tagging(&app, BUCKET, tagging(&[("aws:x", "1")])).await.unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("System tags cannot be added/updated by requester"), "{body}");
    // An empty set is none.
    assert_eq!(put_bucket_tagging(&app, BUCKET, tagging(&[])).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(get().await.0, StatusCode::NOT_FOUND);
    put_bucket_tagging(&app, BUCKET, tagging(&[("a", "1")])).await.unwrap();
    assert_eq!(delete_bucket_tagging(&app, BUCKET).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(get().await.0, StatusCode::NOT_FOUND);
    // No such bucket.
    assert_eq!(get_bucket_tagging(&app, "nope").await.unwrap().status(), StatusCode::NOT_FOUND);
    assert_eq!(put_bucket_tagging(&app, "nope", tagging(&[])).await.unwrap().status(), StatusCode::NOT_FOUND);
}
