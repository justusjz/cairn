//! SSE-KMS end to end, against a real OpenBao (see `db-test.sh`): objects
//! whose keys are sealed under data keys from its Transit engine, read back,
//! assembled from parts, and copied, sharing their parts or not.

use std::{collections::BTreeMap, sync::Arc};

use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::{BodyExt, Full};
use hyper::{Response, StatusCode, body::Bytes};
use md5::Digest;
use uuid::Uuid;

use super::{BUCKET, KmsAuth, customer_key, get_sealed, kms_node, kms_node_with, put, put_sealed};
use crate::{
    App, AttachTarget, UploadResult,
    payload::Payload,
    s3::{
        conditional::Preconditions,
        multipart::{complete::complete_multipart_upload, create::create_multipart_upload, upload_encryption},
        objects::{
            copy::{CopyKeys, copy_object, copy_part},
            get::{get_object, head_object},
        },
        sse::{self, KmsRequest, Stored, Wanted},
        sse_c::CustomerKey,
    },
};

fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

/// An SSE-KMS request for `key_id` (the default key if `None`), with
/// `context`.
fn kms(key_id: Option<&str>, context: &[(&str, &str)]) -> KmsRequest {
    KmsRequest {
        key_id: key_id.map(str::to_owned),
        context: (!context.is_empty())
            .then(|| context.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<BTreeMap<_, _>>()),
    }
}

/// Writes `data` as `key`, encrypted as `request` asks, as PutObject does.
/// Its ETag, or the response refusing it.
async fn put_kms(app: &Arc<App>, key: &str, data: Vec<u8>, request: &KmsRequest) -> Result<String, Response<Full<Bytes>>> {
    let sealing = sse::seal(app, Wanted::Kms(request), BUCKET, key).await.unwrap()?;
    assert!(matches!(sealing, Some(sse::Sealing { stored: Stored::Kms(_), .. })));
    let attach = AttachTarget::Object {
        bucket: BUCKET.to_owned(),
        key: key.to_owned(),
        content_type: "application/octet-stream".to_owned(),
        metadata: String::new(),
        conditions: Preconditions::default(),
        sealing,
    };
    let result = crate::upload_part(app, Full::new(Bytes::from(data)), &attach, Payload::unchecked())
        .await
        .unwrap();
    let UploadResult::Committed { etag, .. } = result else { panic!("not committed") };
    Ok(etag)
}

/// GetObject of (the `range` of) `key`: its status, SSE headers and body.
async fn get(app: &Arc<App>, key: &str, range: Option<&str>) -> (StatusCode, Headers, Vec<u8>) {
    let response = get_object(app, BUCKET, key, None, range, &Preconditions::default(), None)
        .await
        .unwrap();
    let (status, headers) = (response.status(), Headers::of(response.headers()));
    (status, headers, response.into_body().collect().await.unwrap().to_bytes().to_vec())
}

/// The headers a response tells an object's encryption with.
#[derive(Debug, PartialEq)]
struct Headers {
    encryption: Option<String>,
    key_id: Option<String>,
    context: Option<String>,
}

impl Headers {
    fn of(headers: &hyper::HeaderMap) -> Headers {
        let get = |name| headers.get(name).map(|v: &hyper::header::HeaderValue| v.to_str().unwrap().to_owned());
        Headers {
            encryption: get(sse::ENCRYPTION),
            key_id: get(sse::KMS_KEY_ID),
            context: get(sse::KMS_CONTEXT).map(|c| String::from_utf8(STANDARD.decode(c).unwrap()).unwrap()),
        }
    }

    fn kms(key_id: &str, context: Option<&str>) -> Headers {
        Headers {
            encryption: Some("aws:kms".to_owned()),
            key_id: Some(format!("arn:aws:kms:{key_id}")),
            context: context.map(str::to_owned),
        }
    }

    fn none() -> Headers {
        Headers { encryption: None, key_id: None, context: None }
    }
}

/// The S3 error code of a response.
async fn code<B: hyper::body::Body>(response: Response<B>) -> (StatusCode, String)
where
    B::Error: std::fmt::Debug,
{
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8(body.to_vec()).unwrap();
    let code = body
        .split_once("<Code>")
        .and_then(|(_, rest)| rest.split_once("</Code>"))
        .map(|(code, _)| code.to_owned())
        .unwrap_or_default();
    (status, code)
}

/// The latest version of `key`'s row: its blob and salt, and its SSE-KMS
/// key ID and data key.
async fn stored(app: &App, key: &str) -> (Uuid, Option<Vec<u8>>, Option<String>, Option<String>) {
    let row = app
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT p.blob_id, p.enc_salt, o.sse_kms_key_id, o.sse_kms_data_key
             FROM parts p JOIN objects o ON o.id = p.object_id
             WHERE o.key = $1 AND o.is_latest ORDER BY p.part_number LIMIT 1",
            &[&key],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1), row.get(2), row.get(3))
}

/// An SSE-KMS object reads back whole and in ranges, telling its key; it's
/// stored encrypted, with only the KMS's ciphertext of its data key.
#[tokio::test]
async fn objects_round_trip_through_the_kms() {
    let Some(app) = kms_node().await else { return };
    let plain = data(200_000);
    let etag = put_kms(&app, "k", plain.clone(), &kms(None, &[])).await.unwrap();
    // Not an MD5 of the data, which would give it away.
    let md5: String = md5::Md5::digest(&plain).iter().map(|b| format!("{b:02x}")).collect();
    assert_ne!(etag, md5);

    let (status, headers, body) = get(&app, "k", None).await;
    assert_eq!((status, headers), (StatusCode::OK, Headers::kms("cairn-test", None)));
    assert!(body == plain);
    let (status, _, body) = get(&app, "k", Some("bytes=65530-140000")).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert!(body == plain[65530..=140000]);

    let head = head_object(&app, BUCKET, "k", None, None, &Preconditions::default(), None).await.unwrap();
    assert_eq!(Headers::of(head.headers()), Headers::kms("cairn-test", None));

    let (_, salt, key_id, data_key) = stored(&app, "k").await;
    assert!(salt.is_some());
    assert_eq!(key_id.as_deref(), Some("cairn-test"));
    assert!(data_key.unwrap().starts_with("vault:v1:"));

    // SSE-C headers don't apply to it.
    let (status, _) = get_sealed(&app, "k", None, Some(&customer_key(&[1; 32]))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// The encryption context is told back, and bound to the data key at the
/// KMS: with any other, as with another object's name, it doesn't open.
#[tokio::test]
async fn data_keys_open_only_for_their_context_and_object() {
    let Some(app) = kms_node().await else { return };
    let plain = data(1000);
    put_kms(&app, "a", plain.clone(), &kms(Some("cairn-other"), &[("project", "x"), ("a", "1")])).await.unwrap();
    put_kms(&app, "b", plain.clone(), &kms(Some("cairn-other"), &[("project", "x"), ("a", "1")])).await.unwrap();
    let (status, headers, body) = get(&app, "a", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers, Headers::kms("cairn-other", Some(r#"{"a":"1","project":"x"}"#)));
    assert!(body == plain);

    let client = app.pool.get().await.unwrap();
    // b with a's keys: the same context, but another object.
    client
        .execute(
            "UPDATE objects b SET sse_kms_data_key = a.sse_kms_data_key, sse_kms_sealed = a.sse_kms_sealed
             FROM objects a WHERE a.key = 'a' AND b.key = 'b'",
            &[],
        )
        .await
        .unwrap();
    assert!(get_object(&app, BUCKET, "b", None, None, &Preconditions::default(), None).await.is_err());
    // a with another context.
    client
        .execute("UPDATE objects SET sse_kms_context = '{\"a\":\"2\",\"project\":\"x\"}' WHERE key = 'a'", &[])
        .await
        .unwrap();
    assert!(get_object(&app, BUCKET, "a", None, None, &Preconditions::default(), None).await.is_err());
}

/// A key the KMS doesn't have is S3's KMS.NotFoundException; one Cairn's
/// policy doesn't let it use, AccessDenied. Nothing is written either way.
#[tokio::test]
async fn unknown_and_forbidden_keys_are_refused() {
    let Some(app) = kms_node().await else { return };
    let refused = put_kms(&app, "k", data(10), &kms(Some("cairn-nonexistent"), &[])).await.unwrap_err();
    assert_eq!(code(refused).await, (StatusCode::BAD_REQUEST, "KMS.NotFoundException".to_owned()));
    let refused = put_kms(&app, "k", data(10), &kms(Some("forbidden"), &[])).await.unwrap_err();
    assert_eq!(code(refused).await, (StatusCode::FORBIDDEN, "AccessDenied".to_owned()));
    assert_eq!(super::query_i64(&app, "SELECT count(*) FROM objects").await, 0);
}

/// Writes part `part_number` of `upload_id` with `data`, as UploadPart does:
/// encrypted with the upload's key.
async fn put_part(app: &Arc<App>, upload_id: Uuid, key: &str, part_number: i32, data: Vec<u8>) -> String {
    let encryption = upload_encryption(app, &upload_id, BUCKET, key).await.unwrap().unwrap();
    let upload_key = sse::open(app, &encryption, None, BUCKET, key).await.unwrap().ok().unwrap();
    assert!(upload_key.is_some() == !encryption.is_plain());
    let attach = AttachTarget::MultipartPart { upload_id, part_number, key: upload_key };
    let result = crate::upload_part(app, Full::new(Bytes::from(data)), &attach, Payload::unchecked())
        .await
        .unwrap();
    let UploadResult::Committed { etag, .. } = result else { panic!("not committed") };
    etag
}

async fn create(app: &Arc<App>, key: &str, wanted: Wanted<'_>) -> (Uuid, Headers) {
    let response = create_multipart_upload(app, BUCKET, key, "x", "", wanted).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let headers = Headers::of(response.headers());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8(body.to_vec()).unwrap();
    let start = body.find("<UploadId>").unwrap() + "<UploadId>".len();
    (body[start..body.find("</UploadId>").unwrap()].parse().unwrap(), headers)
}

async fn complete(app: &Arc<App>, key: &str, upload_id: Uuid, etags: &[String]) -> (StatusCode, Headers) {
    let parts: String = etags
        .iter()
        .enumerate()
        .map(|(i, etag)| format!("<Part><PartNumber>{}</PartNumber><ETag>\"{etag}\"</ETag></Part>", i + 1))
        .collect();
    let body = Bytes::from(format!("<CompleteMultipartUpload>{parts}</CompleteMultipartUpload>"));
    let id = upload_id.to_string();
    let response = complete_multipart_upload(app, BUCKET, key, &id, body, &Preconditions::default(), None)
        .await
        .unwrap();
    (response.status(), Headers::of(response.headers()))
}

/// An SSE-KMS upload's parts are encrypted with its key, which its object
/// keeps; Create and Complete tell its encryption, a retried Complete too.
#[tokio::test]
async fn multipart_uploads_under_the_kms() {
    let Some(app) = kms_node().await else { return };
    let request = kms(Some("cairn-other"), &[("c", "d")]);
    let (upload_id, headers) = create(&app, "k", Wanted::Kms(&request)).await;
    let told = Headers::kms("cairn-other", Some(r#"{"c":"d"}"#));
    assert_eq!(headers, told);
    let (first, second) = (data(5 << 20), data(70_000));
    let etags = vec![
        put_part(&app, upload_id, "k", 1, first.clone()).await,
        put_part(&app, upload_id, "k", 2, second.clone()).await,
    ];
    assert_eq!(complete(&app, "k", upload_id, &etags).await, (StatusCode::OK, Headers::kms("cairn-other", Some(r#"{"c":"d"}"#))));
    // A retry, whose upload is gone.
    assert_eq!(complete(&app, "k", upload_id, &etags).await, (StatusCode::OK, told));
    let (status, headers, body) = get(&app, "k", None).await;
    assert_eq!((status, headers), (StatusCode::OK, Headers::kms("cairn-other", Some(r#"{"c":"d"}"#))));
    assert!(body == [first, second].concat());
}

async fn copy(app: &Arc<App>, src: &str, dst: &str, source: Option<&CustomerKey>, dest: Wanted<'_>) -> (StatusCode, Headers) {
    let response = copy_object(
        app,
        BUCKET,
        dst,
        &format!("{BUCKET}/{src}"),
        None,
        "x",
        "",
        &Preconditions::default(),
        CopyKeys { source, dest },
    )
    .await
    .unwrap();
    (response.status(), Headers::of(response.headers()))
}

/// A copy between SSE-KMS objects shares the source's parts, under any key
/// and context, with keys of its own; any other change of encryption copies
/// the data. Each reads back as it should.
#[tokio::test]
async fn copies_to_from_and_between_kms_objects() {
    let Some(app) = kms_node().await else { return };
    let plain = data(150_000);
    let k1 = customer_key(&[1; 32]);
    put_kms(&app, "src", plain.clone(), &kms(None, &[])).await.unwrap();
    put(&app, "plain", plain.clone()).await;
    put_sealed(&app, "sse-c", plain.clone(), &k1).await;
    let (src_blob, src_salt, ..) = stored(&app, "src").await;

    // To another KMS key and context: shared parts, a data key of its own.
    let request = kms(Some("cairn-other"), &[("x", "y")]);
    let told = Headers::kms("cairn-other", Some(r#"{"x":"y"}"#));
    assert_eq!(copy(&app, "src", "rewrapped", None, Wanted::Kms(&request)).await, (StatusCode::OK, told));
    let (blob, salt, key_id, data_key) = stored(&app, "rewrapped").await;
    assert_eq!((blob, &salt, key_id.as_deref()), (src_blob, &src_salt, Some("cairn-other")));
    assert_ne!(data_key, stored(&app, "src").await.3);
    for key in ["rewrapped", "src"] {
        let (status, _, body) = get(&app, key, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body == plain, "{key}");
    }

    // Decrypted, to a plain object; and plain or SSE-C, to SSE-KMS: the data
    // is copied.
    assert_eq!(copy(&app, "src", "decrypted", None, Wanted::Plain).await, (StatusCode::OK, Headers::none()));
    let to_kms = kms(None, &[]);
    for (src, source_key) in [("plain", None), ("sse-c", Some(&k1))] {
        let dst = format!("{src}-to-kms");
        assert_eq!(
            copy(&app, src, &dst, source_key, Wanted::Kms(&to_kms)).await,
            (StatusCode::OK, Headers::kms("cairn-test", None))
        );
        let (blob, salt, ..) = stored(&app, &dst).await;
        assert!(blob != src_blob && salt.is_some());
        let (status, _, body) = get(&app, &dst, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body == plain, "{dst}");
    }
    let (blob, salt, key_id, _) = stored(&app, "decrypted").await;
    assert!(blob != src_blob && salt.is_none() && key_id.is_none());
    assert!(get(&app, "decrypted", None).await.2 == plain);
    // To SSE-C.
    assert_eq!(copy(&app, "src", "to-sse-c", None, Wanted::Customer(&k1)).await.0, StatusCode::OK);
    assert_eq!(get_sealed(&app, "to-sse-c", None, Some(&k1)).await, (StatusCode::OK, plain.clone()));
    // An SSE-C source still needs its key.
    assert_eq!(copy(&app, "sse-c", "x", None, Wanted::Kms(&to_kms)).await.0, StatusCode::BAD_REQUEST);

    // Onto itself: SSE-KMS again is a change, as is decrypting it; a plain
    // object copied plainly onto itself still isn't.
    assert_eq!(copy(&app, "src", "src", None, Wanted::Kms(&request)).await.0, StatusCode::OK);
    assert_eq!(stored(&app, "src").await.2.as_deref(), Some("cairn-other"));
    assert_eq!(copy(&app, "src", "src", None, Wanted::Plain).await.0, StatusCode::OK);
    assert!(stored(&app, "src").await.2.is_none());
    assert!(get(&app, "src", None).await.2 == plain);
    assert_eq!(copy(&app, "plain", "plain", None, Wanted::Plain).await.0, StatusCode::BAD_REQUEST);
}

/// UploadPartCopy decrypts an SSE-KMS source's range, and encrypts it with
/// an SSE-KMS upload's key.
#[tokio::test]
async fn part_copies_of_and_into_kms() {
    let Some(app) = kms_node().await else { return };
    let plain = data(6 << 20);
    put_kms(&app, "src", plain.clone(), &kms(Some("cairn-other"), &[])).await.unwrap();
    let request = kms(None, &[]);
    let (upload_id, _) = create(&app, "dst", Wanted::Kms(&request)).await;
    let id = upload_id.to_string();
    let source = format!("{BUCKET}/src");
    let mut etags = Vec::new();
    for (part, range) in [("1", "bytes=0-5242879"), ("2", "bytes=5242880-6291455")] {
        let response =
            copy_part(&app, BUCKET, "dst", &id, part, &source, Some(range), &Preconditions::default(), None, None)
                .await
                .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(Headers::of(response.headers()), Headers::kms("cairn-test", None));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(body.to_vec()).unwrap();
        let start = body.find("<ETag>\"").unwrap() + 7;
        etags.push(body[start..start + 32].to_owned());
    }
    assert_eq!(complete(&app, "dst", upload_id, &etags).await.0, StatusCode::OK);
    let (status, headers, body) = get(&app, "dst", None).await;
    assert_eq!((status, headers), (StatusCode::OK, Headers::kms("cairn-test", None)));
    assert!(body == plain);
}

/// Asks the test OpenBao, as root, to `method` `path` with `body`: its answer.
async fn bao(method: hyper::Method, path: &str, body: serde_json::Value) -> serde_json::Value {
    use hyper_util::{client::legacy::Client, rt::TokioExecutor};
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let address = std::env::var("CAIRN_TEST_OPENBAO").unwrap();
    let request = hyper::Request::builder()
        .method(method)
        .uri(format!("{address}/v1/{path}"))
        .header("X-Vault-Token", "root")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap();
    let response = client.request(request).await.unwrap();
    assert!(response.status().is_success(), "{path}: {}", response.status());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null)
}

/// Cairn logs in again only when the KMS no longer takes its token, not
/// when it refuses a key: else asking for keys it may not use again and
/// again would use up a secret ID that allows only so many logins.
#[tokio::test]
async fn refused_keys_dont_log_in_again() {
    if std::env::var("CAIRN_TEST_OPENBAO").is_err() {
        return;
    }
    let answer = bao(hyper::Method::POST, "auth/approle/role/cairn/secret-id", serde_json::json!({ "num_uses": 1 })).await;
    let secret_id = answer["data"]["secret_id"].as_str().unwrap().to_owned();
    let Some(app) = kms_node_with(KmsAuth::AppRole(secret_id)).await else { return };
    put_kms(&app, "k", data(10), &kms(None, &[])).await.unwrap();
    for _ in 0..3 {
        let refused = put_kms(&app, "x", data(10), &kms(Some("forbidden"), &[])).await.unwrap_err();
        assert_eq!(code(refused).await, (StatusCode::FORBIDDEN, "AccessDenied".to_owned()));
    }
    put_kms(&app, "k2", data(10), &kms(None, &[])).await.unwrap();
}

/// A revoked token is replaced by the one its file holds now.
#[tokio::test]
async fn revoked_tokens_are_read_again() {
    if std::env::var("CAIRN_TEST_OPENBAO").is_err() {
        return;
    }
    let token = |answer: serde_json::Value| answer["auth"]["client_token"].as_str().unwrap().to_owned();
    let create = || bao(hyper::Method::POST, "auth/token/create", serde_json::json!({ "policies": ["cairn"] }));
    let first = token(create().await);
    let file = std::env::temp_dir().join(format!("cairn-e2e-token-{}", Uuid::new_v4()));
    std::fs::write(&file, &first).unwrap();
    let Some(app) = kms_node_with(KmsAuth::TokenFile(file.clone())).await else { return };
    put_kms(&app, "k", data(10), &kms(None, &[])).await.unwrap();

    bao(hyper::Method::POST, "auth/token/revoke", serde_json::json!({ "token": first })).await;
    std::fs::write(&file, token(create().await)).unwrap();
    put_kms(&app, "k2", data(10), &kms(None, &[])).await.unwrap();
    assert!(get(&app, "k", None).await.2 == data(10));
}
