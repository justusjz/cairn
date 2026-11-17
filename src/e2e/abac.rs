//! ABAC (see `s3::buckets::abac`, `s3::abac`, `plans/abac.md`): a bucket's
//! tags in policies with its ABAC enabled, S3 Control's tagging of it, and
//! the object tag keys, decided against a real Postgres.

use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{HeaderMap, Method, Response, StatusCode, body::Bytes};

use super::node_with;
use crate::{
    App, AttachTarget, UploadResult, packer,
    payload::Payload,
    s3::{
        abac, access,
        actions,
        buckets::{
            abac::{get_bucket_abac, put_bucket_abac},
            create,
            policy::put_bucket_policy,
            resource_tags::{self, Change},
            tagging::{delete_bucket_tagging, get_bucket_tagging, put_bucket_tagging},
            versioning::put_bucket_versioning,
        },
        conditional::Preconditions,
        multipart::create::create_multipart_upload,
        sse::Wanted,
        tags::Tags,
    },
    users::Principal,
};

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

async fn text(response: Response<Full<Bytes>>) -> (StatusCode, String) {
    let (parts, body) = response.into_parts();
    (parts.status, String::from_utf8(body.collect().await.unwrap().to_bytes().to_vec()).unwrap())
}

/// A new bucket of the account's, with a fresh name.
async fn bucket(app: &App, prefix: &str) -> String {
    let account = crate::users::account(&app.pool.get().await.unwrap()).await.unwrap();
    let bucket = format!("{prefix}-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    assert!(matches!(create::create(app, &bucket, &account, false).await.unwrap(), create::Creation::Created));
    bucket
}

/// A user named `name` (unique), with the identity policy `statements`,
/// and `tags`.
async fn user(app: &App, name: &str, statements: &str, tags: &[(&str, &str)]) -> Principal {
    let client = app.pool.get().await.unwrap();
    let account = crate::users::account(&client).await.unwrap();
    let name = format!("{name}-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let (key, _) = crate::users::create_for(&client, &account, &name, None, false).await.unwrap();
    let policy = format!(r#"{{"Version":"2012-10-17","Statement":[{statements}]}}"#);
    crate::users::put_policy(&client, &account, &name, "p", &policy).await.unwrap();
    if !tags.is_empty() {
        let id = crate::users::id_of(&client, &account, &name).await.unwrap();
        let tags: Vec<_> = tags.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        crate::users::tag(&client, id, &tags).await.unwrap();
    }
    Principal::load(&client, &key).await.unwrap().unwrap()
}

/// Whether `principal` may make the request (`method`, `key`, `query`,
/// `headers`) on `bucket`: all its checks, with its tags looked up as
/// `s3::handle_request` looks them up.
async fn may(app: &App, principal: &Principal, method: Method, bucket: &str, key: &str, query: &str, headers: &HeaderMap) -> bool {
    let account = crate::users::account(&app.pool.get().await.unwrap()).await.unwrap();
    let origin = access::Origin { peer: None, trusted_proxies: &[], signed: None, form: false };
    let mut access = access::Access::new(Some(principal), &account, &method, headers, query, &origin).unwrap();
    let operation = actions::operation(&method, bucket, key, query, headers).unwrap();
    access.load(app, bucket).await.unwrap();
    access.load_all(app, &operation.checks).await.unwrap();
    abac::prepare(app, &mut access, &operation, bucket, key, query, headers).await.unwrap();
    access.first_denied(&operation.checks).is_none()
}

/// Whether `principal` may read `bucket`'s `k`.
async fn reads(app: &App, bucket: &str, principal: &Principal) -> bool {
    may(app, principal, Method::GET, bucket, "k", "", &HeaderMap::new()).await
}

fn tagging(pairs: &[(&str, &str)]) -> Bytes {
    let tags: String = pairs.iter().map(|(k, v)| format!("<Tag><Key>{k}</Key><Value>{v}</Value></Tag>")).collect();
    Bytes::from(format!("<Tagging><TagSet>{tags}</TagSet></Tagging>"))
}

fn abac_status(status: &str) -> Bytes {
    Bytes::from(format!("<AbacStatus><Status>{status}</Status></AbacStatus>"))
}

fn tags(pairs: &[(&str, &str)]) -> Tags {
    Tags::from_header(pairs.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&").as_bytes()).unwrap()
}

/// A bucket's tags are its and its objects' `aws:ResourceTag`s and
/// `s3:BucketTag`s only with its ABAC enabled, in identity and bucket
/// policies; then only TagResource and UntagResource change them.
#[tokio::test]
async fn bucket_tags_decide_with_abac() {
    let Some(app) = node().await else { return };
    let bucket = bucket(&app, "abac").await;
    let gated = |key: &str, value: &str| {
        format!(
            r#"{{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::{bucket}","arn:aws:s3:::{bucket}/*"],
                "Condition":{{"StringEquals":{{"{key}":"{value}"}}}}}}"#
        )
    };
    let rt = user(&app, "rt", &gated("aws:ResourceTag/team", "red"), &[]).await;
    let bt = user(&app, "bt", &gated("s3:BucketTag/team", "red"), &[]).await;
    let case = user(&app, "case", &gated("aws:ResourceTag/TEAM", "red"), &[]).await;
    let pt = user(&app, "pt", &gated("aws:ResourceTag/team", "${aws:PrincipalTag/team}"), &[("team", "red")]).await;
    let absent = format!(
        r#"{{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::{bucket}/*","Condition":{{"Null":{{"aws:ResourceTag/team":"true"}}}}}}"#
    );
    let null = user(&app, "null", &absent, &[]).await;

    // Off, untagged and tagged: absent.
    assert_eq!(text(get_bucket_abac(&app, &bucket).await.unwrap()).await.1.contains("<Status>Disabled</Status>"), true);
    assert_eq!(put_bucket_tagging(&app, &bucket, tagging(&[("team", "red")])).await.unwrap().status(), StatusCode::NO_CONTENT);
    for principal in [&rt, &bt, &case, &pt] {
        assert!(!reads(&app, &bucket, principal).await);
    }
    assert!(reads(&app, &bucket, &null).await);

    // On: present, on bucket and object checks alike.
    assert_eq!(put_bucket_abac(&app, &bucket, abac_status("Enabled")).await.unwrap().status(), StatusCode::OK);
    assert!(text(get_bucket_abac(&app, &bucket).await.unwrap()).await.1.contains("<Status>Enabled</Status>"));
    for principal in [&rt, &bt, &case, &pt] {
        assert!(reads(&app, &bucket, principal).await);
        assert!(may(&app, principal, Method::GET, &bucket, "", "list-type=2", &HeaderMap::new()).await);
    }
    assert!(!reads(&app, &bucket, &null).await);
    assert_eq!(put_bucket_abac(&app, &bucket, abac_status("enabled")).await.unwrap().status(), StatusCode::BAD_REQUEST);
    assert_eq!(put_bucket_abac(&app, &bucket, Bytes::new()).await.unwrap().status(), StatusCode::BAD_REQUEST);

    // Only S3 Control's requests change its tags now.
    let (status, body) = text(put_bucket_tagging(&app, &bucket, tagging(&[("team", "blue")])).await.unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("initiate a TagResource request"), "{body}");
    assert_eq!(delete_bucket_tagging(&app, &bucket).await.unwrap().status(), StatusCode::BAD_REQUEST);
    let status = resource_tags::apply(&app, &bucket, Change::Add(tags(&[("team", "blue"), ("env", "dev")]))).await.unwrap().status();
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(text(get_bucket_tagging(&app, &bucket).await.unwrap()).await.1.contains("<Key>env</Key>"));
    for principal in [&rt, &bt, &pt] {
        assert!(!reads(&app, &bucket, principal).await);
    }
    let remove = Change::Remove(vec!["team".to_owned(), "nope".to_owned()]);
    assert_eq!(resource_tags::apply(&app, &bucket, remove).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert!(reads(&app, &bucket, &null).await);
    let remove = Change::Remove(vec!["env".to_owned()]);
    assert_eq!(resource_tags::apply(&app, &bucket, remove).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(get_bucket_tagging(&app, &bucket).await.unwrap().status(), StatusCode::NOT_FOUND);
    let (status, body) = text(resource_tags::list(&app, &bucket).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<Tags></Tags>"), "{body}");
    // (More than an object may have: built from their stored form.)
    let fifty: String = (0..50).map(|i| format!("k{i}=v")).collect::<Vec<_>>().join("&");
    let add = Change::Add(Tags::from_stored(&fifty));
    assert_eq!(resource_tags::apply(&app, &bucket, add).await.unwrap().status(), StatusCode::NO_CONTENT);
    let one_more = Change::Add(tags(&[("team", "red")]));
    assert_eq!(text(resource_tags::apply(&app, &bucket, one_more).await.unwrap()).await.0, StatusCode::BAD_REQUEST);
    let gone = Change::Add(tags(&[("a", "b")]));
    assert_eq!(resource_tags::apply(&app, "abac-no-such-bucket", gone).await.unwrap().status(), StatusCode::NOT_FOUND);

    // A bucket policy tests them too.
    let all: Vec<String> = (0..50).map(|i| format!("k{i}")).collect();
    assert_eq!(resource_tags::apply(&app, &bucket, Change::Remove(all)).await.unwrap().status(), StatusCode::NO_CONTENT);
    let add = Change::Add(tags(&[("team", "red")]));
    assert_eq!(resource_tags::apply(&app, &bucket, add).await.unwrap().status(), StatusCode::NO_CONTENT);
    let deny = format!(
        r#"{{"Statement":[{{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::{bucket}/*",
            "Condition":{{"StringEquals":{{"aws:ResourceTag/team":"red"}}}}}}]}}"#
    );
    assert_eq!(put_bucket_policy(&app, &bucket, Bytes::from(deny)).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert!(!reads(&app, &bucket, &rt).await);
    // Off again: the Deny's key is absent, and so are the Allow's.
    assert_eq!(put_bucket_abac(&app, &bucket, abac_status("Disabled")).await.unwrap().status(), StatusCode::OK);
    assert!(!reads(&app, &bucket, &rt).await);
    assert!(reads(&app, &bucket, &null).await);
    assert_eq!(put_bucket_tagging(&app, &bucket, tagging(&[("team", "red")])).await.unwrap().status(), StatusCode::NO_CONTENT);
}

/// CreateBucket's tags are its new bucket's, and only then.
#[tokio::test]
async fn created_buckets_take_their_tags() {
    let Some(app) = node().await else { return };
    let account = crate::users::account(&app.pool.get().await.unwrap()).await.unwrap();
    let name = format!("abac-new-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let red = tags(&[("team", "red")]);
    assert_eq!(create::create_bucket(&app, &name, &account, false, Some(&red)).await.unwrap().status(), StatusCode::OK);
    let blue = tags(&[("team", "blue")]);
    assert_eq!(create::create_bucket(&app, &name, &account, false, Some(&blue)).await.unwrap().status(), StatusCode::OK);
    let (_, body) = text(get_bucket_tagging(&app, &name).await.unwrap()).await;
    assert!(body.contains("<Value>red</Value>"), "{body}");
    assert!(text(get_bucket_abac(&app, &name).await.unwrap()).await.1.contains("Disabled"));
}

/// Writes `key` to `bucket` with the tags of `x-amz-tagging: header`; its
/// version ID.
async fn put_tagged(app: &Arc<App>, bucket: &str, key: &str, header: &str) -> Option<String> {
    let attach = AttachTarget::Object {
        bucket: bucket.to_owned(),
        key: key.to_owned(),
        content_type: "application/octet-stream".to_owned(),
        metadata: String::new(),
        conditions: Preconditions::default(),
        sealing: None,
        checksum: crate::e2e::OBJECT_CHECKSUM,
        tags: Tags::from_header(header.as_bytes()).unwrap().stored(),
        lock: Default::default(),
    };
    let result = crate::upload_part(app, Full::new(Bytes::from_static(b"x")), &attach, Payload::unchecked()).await.unwrap();
    let UploadResult::Committed { version_id, .. } = result else { panic!("not committed") };
    version_id
}

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        headers.insert(hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(), value.parse().unwrap());
    }
    headers
}

/// `s3:ExistingObjectTag` is the addressed version's tags (none for a
/// delete marker), `s3:RequestObjectTag` the tags a write gives, or its
/// upload has.
#[tokio::test]
async fn object_tags_decide() {
    let Some(app) = node().await else { return };
    let bucket = bucket(&app, "abac-obj").await;
    let versioning = Bytes::from_static(b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>");
    put_bucket_versioning(&app, &bucket, versioning, crate::mfa::Presented::Absent).await.unwrap();
    let existing = user(
        &app,
        "eot",
        &format!(
            r#"{{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion","s3:GetObjectTagging","s3:PutObjectTagging"],
                "Resource":"arn:aws:s3:::{bucket}/*","Condition":{{"StringEquals":{{"s3:ExistingObjectTag/team":"red"}}}}}},
               {{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::{bucket}"}}"#
        ),
        &[],
    )
    .await;
    let v1 = put_tagged(&app, &bucket, "v", "team=red").await.unwrap();
    let v2 = put_tagged(&app, &bucket, "v", "team=blue").await.unwrap();
    put_tagged(&app, &bucket, "red", "team=red").await;
    put_tagged(&app, &bucket, "case", "TEAM=red").await;
    put_tagged(&app, &bucket, "none", "").await;
    let none = HeaderMap::new();
    let get = |key: &'static str, query: &'static str| {
        let (app, existing, bucket, none) = (&app, &existing, &bucket, &none);
        async move { may(app, existing, Method::GET, bucket, key, query, none).await }
    };
    assert!(get("red", "").await);
    assert!(may(&app, &existing, Method::HEAD, &bucket, "red", "", &none).await);
    assert!(get("case", "").await);
    assert!(!get("none", "").await);
    assert!(!get("v", "").await);
    assert!(may(&app, &existing, Method::GET, &bucket, "v", &format!("versionId={v1}"), &none).await);
    assert!(!may(&app, &existing, Method::GET, &bucket, "v", &format!("versionId={v2}"), &none).await);
    assert!(!get("missing", "").await);
    assert!(get("red", "tagging").await);
    // PutObjectTagging: the tags it replaces.
    assert!(may(&app, &existing, Method::PUT, &bucket, "red", "tagging", &none).await);
    assert!(!may(&app, &existing, Method::PUT, &bucket, "none", "tagging", &none).await);

    let request = user(
        &app,
        "rot",
        &format!(
            r#"{{"Effect":"Allow","Action":["s3:PutObject","s3:PutObjectTagging"],"Resource":"arn:aws:s3:::{bucket}/*",
                "Condition":{{"StringEquals":{{"s3:RequestObjectTag/team":"red"}},
                              "ForAllValues:StringEquals":{{"s3:RequestObjectTagKeys":["team","env"]}}}}}},
               {{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::{bucket}/*"}}"#
        ),
        &[],
    )
    .await;
    let put = |pairs: &'static [(&'static str, &'static str)]| {
        let (app, request, bucket) = (&app, &request, &bucket);
        async move { may(app, request, Method::PUT, bucket, "w", "", &headers(pairs)).await }
    };
    assert!(put(&[("x-amz-tagging", "team=red")]).await);
    assert!(put(&[("x-amz-tagging", "team=red&env=dev")]).await);
    assert!(!put(&[("x-amz-tagging", "team=red&x=1")]).await);
    assert!(!put(&[("x-amz-tagging", "team=blue")]).await);
    assert!(!put(&[]).await);
    assert!(!put(&[("x-amz-tagging", "")]).await);
    let copy = |directive: &'static str| {
        let source = format!("{bucket}/red");
        let (app, request, bucket) = (&app, &request, &bucket);
        async move {
            let headers = headers(&[
                ("x-amz-copy-source", &source),
                ("x-amz-tagging", "team=red"),
                ("x-amz-tagging-directive", directive),
            ]);
            may(app, request, Method::PUT, bucket, "c", "", &headers).await
        }
    };
    assert!(copy("REPLACE").await);
    assert!(!copy("COPY").await);
    let tagged = headers(&[("x-amz-tagging", "team=red")]);
    assert!(may(&app, &request, Method::POST, &bucket, "m", "uploads", &tagged).await);

    // UploadPart and CompleteMultipartUpload: the upload's tags.
    let upload = |stored: String| {
        let (app, bucket) = (&app, &bucket);
        async move {
            let response = create_multipart_upload(app, bucket, "m", "x", "", &stored, Wanted::Plain, None, None, Default::default(), None)
                .await
                .unwrap();
            let (_, body) = text(response).await;
            let start = body.find("<UploadId>").unwrap() + "<UploadId>".len();
            body[start..body.find("</UploadId>").unwrap()].to_owned()
        }
    };
    let red = upload(tags(&[("team", "red")]).stored()).await;
    let blue = upload(tags(&[("team", "blue")]).stored()).await;
    let untagged = upload(String::new()).await;
    for (id, allowed) in [(&red, true), (&blue, false), (&untagged, false)] {
        let part = format!("uploadId={id}&partNumber=1");
        assert_eq!(may(&app, &request, Method::PUT, &bucket, "m", &part, &none).await, allowed, "{id}");
        let complete = format!("uploadId={id}");
        assert_eq!(may(&app, &request, Method::POST, &bucket, "m", &complete, &none).await, allowed, "{id}");
    }
    // A check that's not about tags isn't decided by them.
    assert!(may(&app, &request, Method::GET, &bucket, "none", "", &none).await);
}
