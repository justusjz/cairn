//! SSE-KMS end to end, against a real OpenBao (see `db-test.sh`): objects
//! whose keys are sealed under data keys from its Transit engines, read back,
//! assembled from parts, and copied, sharing their parts or not; all as the
//! roles that ask, which may use only the keys OpenBao lets them.

use std::{collections::BTreeMap, sync::Arc};

use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::{BodyExt, Full};
use hyper::{Response, StatusCode, body::Bytes};
use md5::Digest;
use uuid::Uuid;

use super::{BUCKET, customer_key, get_sealed, kms_node, put, put_sealed};
use crate::{
    App, AttachTarget, UploadResult,
    kms::KeyId,
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

/// An SSE-KMS request for `key_id` (`transit/cairn-test` if `None`), with
/// `context`.
fn kms(key_id: Option<&str>, context: &[(&str, &str)]) -> KmsRequest {
    KmsRequest {
        key_id: KeyId::parse(key_id.unwrap_or("cairn-test")).unwrap(),
        context: (!context.is_empty())
            .then(|| context.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<BTreeMap<_, _>>()),
    }
}

/// Writes `data` as `key`, encrypted as `request` asks, as PutObject does.
/// Its ETag, or the response refusing it.
async fn put_kms(
    app: &Arc<App>,
    role: Uuid,
    key: &str,
    data: Vec<u8>,
    request: &KmsRequest,
) -> Result<String, Response<Full<Bytes>>> {
    let sealing = sse::seal(app, Wanted::Kms(request), Some(role), BUCKET, key).await.unwrap()?;
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

/// GetObject of (the `range` of) `key`, as `role`: its status, SSE headers
/// and body.
async fn get(app: &Arc<App>, role: Option<Uuid>, key: &str, range: Option<&str>) -> (StatusCode, Headers, Vec<u8>) {
    let response = get_object(app, BUCKET, key, None, range, &Preconditions::default(), None, role)
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
    let r = role(&app, "alice", ALL).await;
    let plain = data(200_000);
    let etag = put_kms(&app, r, "k", plain.clone(), &kms(None, &[])).await.unwrap();
    // Not an MD5 of the data, which would give it away.
    let md5: String = md5::Md5::digest(&plain).iter().map(|b| format!("{b:02x}")).collect();
    assert_ne!(etag, md5);

    let (status, headers, body) = get(&app, Some(r), "k", None).await;
    assert_eq!((status, headers), (StatusCode::OK, Headers::kms("transit/cairn-test", None)));
    assert!(body == plain);
    let (status, _, body) = get(&app, Some(r), "k", Some("bytes=65530-140000")).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert!(body == plain[65530..=140000]);

    let head = head_object(&app, BUCKET, "k", None, None, &Preconditions::default(), None).await.unwrap();
    assert_eq!(Headers::of(head.headers()), Headers::kms("transit/cairn-test", None));

    let (_, salt, key_id, data_key) = stored(&app, "k").await;
    assert!(salt.is_some());
    assert_eq!(key_id.as_deref(), Some("transit/cairn-test"));
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
    let r = role(&app, "alice", ALL).await;
    let plain = data(1000);
    put_kms(&app, r, "a", plain.clone(), &kms(Some("cairn-other"), &[("project", "x"), ("a", "1")])).await.unwrap();
    put_kms(&app, r, "b", plain.clone(), &kms(Some("cairn-other"), &[("project", "x"), ("a", "1")])).await.unwrap();
    let (status, headers, body) = get(&app, Some(r), "a", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers, Headers::kms("transit/cairn-other", Some(r#"{"a":"1","project":"x"}"#)));
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
    assert!(get_object(&app, BUCKET, "b", None, None, &Preconditions::default(), None, Some(r)).await.is_err());
    // a with another context.
    client
        .execute("UPDATE objects SET sse_kms_context = '{\"a\":\"2\",\"project\":\"x\"}' WHERE key = 'a'", &[])
        .await
        .unwrap();
    assert!(get_object(&app, BUCKET, "a", None, None, &Preconditions::default(), None, Some(r)).await.is_err());
}

/// A key the KMS doesn't have (but would let the role use) is S3's
/// KMS.NotFoundException; one it doesn't let the role use, AccessDenied.
/// Nothing is written either way.
#[tokio::test]
async fn unknown_and_forbidden_keys_are_refused() {
    let Some(app) = kms_node().await else { return };
    let r = role(&app, "alice", ALL).await;
    let refused = put_kms(&app, r, "k", data(10), &kms(Some("cairn-missing"), &[])).await.unwrap_err();
    assert_eq!(code(refused).await, (StatusCode::BAD_REQUEST, "KMS.NotFoundException".to_owned()));
    let refused = put_kms(&app, r, "k", data(10), &kms(Some("forbidden"), &[])).await.unwrap_err();
    assert_eq!(code(refused).await, (StatusCode::FORBIDDEN, "AccessDenied".to_owned()));
    assert_eq!(super::query_i64(&app, "SELECT count(*) FROM objects").await, 0);
}

/// Writes part `part_number` of `upload_id` with `data`, as UploadPart does:
/// encrypted with the upload's key.
async fn put_part(app: &Arc<App>, role: Uuid, upload_id: Uuid, key: &str, part_number: i32, data: Vec<u8>) -> String {
    let encryption = upload_encryption(app, &upload_id, BUCKET, key).await.unwrap().unwrap();
    let upload_key = sse::open(app, &encryption, None, Some(role), BUCKET, key).await.unwrap().ok().unwrap();
    assert!(upload_key.is_some() == !encryption.is_plain());
    let attach = AttachTarget::MultipartPart { upload_id, part_number, key: upload_key };
    let result = crate::upload_part(app, Full::new(Bytes::from(data)), &attach, Payload::unchecked())
        .await
        .unwrap();
    let UploadResult::Committed { etag, .. } = result else { panic!("not committed") };
    etag
}

async fn create(app: &Arc<App>, role: Uuid, key: &str, wanted: Wanted<'_>) -> (Uuid, Headers) {
    let response = create_multipart_upload(app, BUCKET, key, "x", "", wanted, Some(role)).await.unwrap();
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
    let r = role(&app, "alice", ALL).await;
    let request = kms(Some("cairn-other"), &[("c", "d")]);
    let (upload_id, headers) = create(&app, r, "k", Wanted::Kms(&request)).await;
    let told = Headers::kms("transit/cairn-other", Some(r#"{"c":"d"}"#));
    assert_eq!(headers, told);
    let (first, second) = (data(5 << 20), data(70_000));
    let etags = vec![
        put_part(&app, r, upload_id, "k", 1, first.clone()).await,
        put_part(&app, r, upload_id, "k", 2, second.clone()).await,
    ];
    assert_eq!(complete(&app, "k", upload_id, &etags).await, (StatusCode::OK, Headers::kms("transit/cairn-other", Some(r#"{"c":"d"}"#))));
    // A retry, whose upload is gone.
    assert_eq!(complete(&app, "k", upload_id, &etags).await, (StatusCode::OK, told));
    let (status, headers, body) = get(&app, Some(r), "k", None).await;
    assert_eq!((status, headers), (StatusCode::OK, Headers::kms("transit/cairn-other", Some(r#"{"c":"d"}"#))));
    assert!(body == [first, second].concat());
}

async fn copy(
    app: &Arc<App>,
    role: Uuid,
    src: &str,
    dst: &str,
    source: Option<&CustomerKey>,
    dest: Wanted<'_>,
) -> (StatusCode, Headers) {
    let response = copy_object(
        app,
        BUCKET,
        dst,
        &format!("{BUCKET}/{src}"),
        None,
        "x",
        "",
        &Preconditions::default(),
        CopyKeys { source, dest, role: Some(role) },
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
    let r = role(&app, "alice", ALL).await;
    let plain = data(150_000);
    let k1 = customer_key(&[1; 32]);
    put_kms(&app, r, "src", plain.clone(), &kms(None, &[])).await.unwrap();
    put(&app, "plain", plain.clone()).await;
    put_sealed(&app, "sse-c", plain.clone(), &k1).await;
    let (src_blob, src_salt, ..) = stored(&app, "src").await;

    // To another KMS key and context: shared parts, a data key of its own.
    let request = kms(Some("cairn-other"), &[("x", "y")]);
    let told = Headers::kms("transit/cairn-other", Some(r#"{"x":"y"}"#));
    assert_eq!(copy(&app, r, "src", "rewrapped", None, Wanted::Kms(&request)).await, (StatusCode::OK, told));
    let (blob, salt, key_id, data_key) = stored(&app, "rewrapped").await;
    assert_eq!((blob, &salt, key_id.as_deref()), (src_blob, &src_salt, Some("transit/cairn-other")));
    assert_ne!(data_key, stored(&app, "src").await.3);
    for key in ["rewrapped", "src"] {
        let (status, _, body) = get(&app, Some(r), key, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body == plain, "{key}");
    }

    // Decrypted, to a plain object; and plain or SSE-C, to SSE-KMS: the data
    // is copied.
    assert_eq!(copy(&app, r, "src", "decrypted", None, Wanted::Plain).await, (StatusCode::OK, Headers::none()));
    let to_kms = kms(None, &[]);
    for (src, source_key) in [("plain", None), ("sse-c", Some(&k1))] {
        let dst = format!("{src}-to-kms");
        assert_eq!(
            copy(&app, r, src, &dst, source_key, Wanted::Kms(&to_kms)).await,
            (StatusCode::OK, Headers::kms("transit/cairn-test", None))
        );
        let (blob, salt, ..) = stored(&app, &dst).await;
        assert!(blob != src_blob && salt.is_some());
        let (status, _, body) = get(&app, Some(r), &dst, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body == plain, "{dst}");
    }
    let (blob, salt, key_id, _) = stored(&app, "decrypted").await;
    assert!(blob != src_blob && salt.is_none() && key_id.is_none());
    assert!(get(&app, Some(r), "decrypted", None).await.2 == plain);
    // To SSE-C.
    assert_eq!(copy(&app, r, "src", "to-sse-c", None, Wanted::Customer(&k1)).await.0, StatusCode::OK);
    assert_eq!(get_sealed(&app, "to-sse-c", None, Some(&k1)).await, (StatusCode::OK, plain.clone()));
    // An SSE-C source still needs its key.
    assert_eq!(copy(&app, r, "sse-c", "x", None, Wanted::Kms(&to_kms)).await.0, StatusCode::BAD_REQUEST);

    // Onto itself: SSE-KMS again is a change, as is decrypting it; a plain
    // object copied plainly onto itself still isn't.
    assert_eq!(copy(&app, r, "src", "src", None, Wanted::Kms(&request)).await.0, StatusCode::OK);
    assert_eq!(stored(&app, "src").await.2.as_deref(), Some("transit/cairn-other"));
    assert_eq!(copy(&app, r, "src", "src", None, Wanted::Plain).await.0, StatusCode::OK);
    assert!(stored(&app, "src").await.2.is_none());
    assert!(get(&app, Some(r), "src", None).await.2 == plain);
    assert_eq!(copy(&app, r, "plain", "plain", None, Wanted::Plain).await.0, StatusCode::BAD_REQUEST);
}

/// UploadPartCopy decrypts an SSE-KMS source's range, and encrypts it with
/// an SSE-KMS upload's key.
#[tokio::test]
async fn part_copies_of_and_into_kms() {
    let Some(app) = kms_node().await else { return };
    let r = role(&app, "alice", ALL).await;
    let plain = data(6 << 20);
    put_kms(&app, r, "src", plain.clone(), &kms(Some("cairn-other"), &[])).await.unwrap();
    let request = kms(None, &[]);
    let (upload_id, _) = create(&app, r, "dst", Wanted::Kms(&request)).await;
    let id = upload_id.to_string();
    let source = format!("{BUCKET}/src");
    let mut etags = Vec::new();
    for (part, range) in [("1", "bytes=0-5242879"), ("2", "bytes=5242880-6291455")] {
        let response =
            copy_part(&app, BUCKET, "dst", &id, part, &source, Some(range), &Preconditions::default(), None, None, Some(r))
                .await
                .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(Headers::of(response.headers()), Headers::kms("transit/cairn-test", None));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(body.to_vec()).unwrap();
        let start = body.find("<ETag>\"").unwrap() + 7;
        etags.push(body[start..start + 32].to_owned());
    }
    assert_eq!(complete(&app, "dst", upload_id, &etags).await.0, StatusCode::OK);
    let (status, headers, body) = get(&app, Some(r), "dst", None).await;
    assert_eq!((status, headers), (StatusCode::OK, Headers::kms("transit/cairn-test", None)));
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

/// The keys the role `alice` of most tests may use: two in the mount
/// `transit`, one in another, and one that doesn't exist.
const ALL: &[&str] = &["transit/cairn-test", "transit/cairn-other", "team-transit/invoices", "transit/cairn-missing"];

/// A new role `name` (with a suffix of its own: tests share OpenBao), with
/// its identity in OpenBao, which may use `keys` (see `allow`).
async fn role(app: &Arc<App>, name: &str, keys: &[&str]) -> Uuid {
    let name = format!("{name}-{}", &Uuid::new_v4().simple().to_string()[..8]);
    let client = app.pool.get().await.unwrap();
    crate::roles::create(&client, &name, None, false).await.unwrap();
    crate::roles::identify(app).await.unwrap();
    let row = client.query_one("SELECT id, kms_entity_id FROM roles WHERE name = $1", &[&name]).await.unwrap();
    let (id, entity): (Uuid, Option<String>) = (row.get(0), row.get(1));
    assert!(entity.is_some(), "identify gives every role its entity");
    allow(app, id, keys).await;
    id
}

/// Lets the role `role` use exactly `keys` (`<mount>/<key>`), as a key owner
/// would: a policy, on the role's entity in OpenBao.
async fn allow(app: &App, role: Uuid, keys: &[&str]) {
    let entity: String = app
        .pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT kms_entity_id FROM roles WHERE id = $1", &[&role])
        .await
        .unwrap()
        .get(0);
    let policy: String = keys
        .iter()
        .map(|key| {
            let (mount, name) = key.rsplit_once('/').unwrap();
            format!(
                "path \"{mount}/datakey/plaintext/{name}\" {{ capabilities = [\"update\"] }}\n\
                 path \"{mount}/decrypt/{name}\" {{ capabilities = [\"update\"] }}\n"
            )
        })
        .collect();
    let name = format!("e2e-{role}");
    // An empty policy isn't one: no keys is no policy at all.
    if !policy.is_empty() {
        bao(hyper::Method::POST, &format!("sys/policies/acl/{name}"), serde_json::json!({ "policy": policy })).await;
    }
    let policies: Vec<&str> = if policy.is_empty() { vec![] } else { vec![&name] };
    bao(hyper::Method::POST, &format!("identity/entity/id/{entity}"), serde_json::json!({ "policies": policies })).await;
}

/// Each role gets an identity of its own in OpenBao before it uses a key,
/// and may use only the keys OpenBao lets it; grants and revocations take
/// effect at once. A request of no role (the dashboard's) can't open an
/// SSE-KMS object.
#[tokio::test]
async fn roles_use_the_keys_openbao_lets_them() {
    let Some(app) = kms_node().await else { return };
    let alice = role(&app, "alice", &["transit/cairn-test"]).await;
    let bob = role(&app, "bob", &[]).await;
    let entities = super::query_i64(&app, "SELECT count(DISTINCT kms_entity_id) FROM roles").await;
    assert_eq!(entities, 2);
    // Identifying a role again finds the same entity.
    let entity: String = app
        .pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT kms_entity_id FROM roles WHERE id = $1", &[&bob])
        .await
        .unwrap()
        .get(0);
    assert_eq!(app.kms.as_ref().unwrap().identify(bob).await.unwrap(), entity);

    let plain = data(1000);
    put_kms(&app, alice, "k", plain.clone(), &kms(None, &[])).await.unwrap();
    let refused = put_kms(&app, bob, "k2", plain.clone(), &kms(None, &[])).await.unwrap_err();
    assert_eq!(code(refused).await, (StatusCode::FORBIDDEN, "AccessDenied".to_owned()));
    assert_eq!(get(&app, Some(bob), "k", None).await.0, StatusCode::FORBIDDEN);
    // A key in another mount, which alice may not use.
    let refused = put_kms(&app, alice, "k3", plain.clone(), &kms(Some("team-transit/invoices"), &[])).await.unwrap_err();
    assert_eq!(code(refused).await, (StatusCode::FORBIDDEN, "AccessDenied".to_owned()));

    allow(&app, bob, &["transit/cairn-test", "team-transit/invoices"]).await;
    let (status, _, body) = get(&app, Some(bob), "k", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body == plain);
    put_kms(&app, bob, "k3", plain.clone(), &kms(Some("team-transit/invoices"), &[])).await.unwrap();
    let (status, headers, _) = get(&app, Some(bob), "k3", None).await;
    assert_eq!((status, headers), (StatusCode::OK, Headers::kms("team-transit/invoices", None)));
    allow(&app, bob, &[]).await;
    assert_eq!(get(&app, Some(bob), "k", None).await.0, StatusCode::FORBIDDEN);

    // No role: the dashboard's download.
    assert_eq!(get(&app, None, "k", None).await.0, StatusCode::FORBIDDEN);
    // Copies ask as their role, for the source as for the destination.
    let request = kms(None, &[]);
    assert_eq!(copy(&app, bob, "k", "k4", None, Wanted::Kms(&request)).await.0, StatusCode::FORBIDDEN);
    assert_eq!(copy(&app, alice, "k", "k4", None, Wanted::Kms(&request)).await.0, StatusCode::OK);
}

/// What the dashboard tells about the KMS: Cairn's public key, as OpenBao is
/// to trust it (the one openssl made for `db-test.sh`), OpenBao's health,
/// and how logins went, with what's wrong if they failed.
#[tokio::test]
async fn the_kms_tells_how_it_is() {
    let Some(app) = kms_node().await else { return };
    let kms = app.kms.as_ref().unwrap();
    let key = std::path::PathBuf::from(std::env::var("CAIRN_TEST_OPENBAO_JWT_KEY").unwrap());
    let public = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    assert_eq!(kms.public_key_pem(), public);

    let health = kms.health().await;
    assert!(health.reachable && health.sealed == Some(false), "{:?}", health.error);
    assert!(health.version.is_some());

    assert!(kms.logins().last.is_none());
    let r = role(&app, "alice", &[]).await;
    let logins = kms.logins();
    let last = logins.last.unwrap();
    assert_eq!((last.role, last.error.is_none()), (r, true));
    assert_eq!(logins.last_success, Some(last.at));

    // The wrong mount, the wrong role: refused, saying what's wrong.
    for (mount, role, why) in [
        ("nope", "s3", "no JWT auth method at auth/nope"),
        ("cairn", "nope", "has no role \"nope\""),
    ] {
        let misconfigured = crate::kms::Kms::new(&crate::kms::KmsArgs {
            kms_address: std::env::var("CAIRN_TEST_OPENBAO").ok(),
            kms_jwt_key: Some(key.clone()),
            kms_auth_mount: mount.to_owned(),
            kms_auth_role: role.to_owned(),
            kms_ca_cert: None,
        })
        .unwrap()
        .unwrap();
        let e = misconfigured.identify(r).await.unwrap_err();
        assert!(matches!(e, crate::kms::KmsError::LoginRefused(_)) && e.to_string().contains(why), "{e}");
        assert!(misconfigured.logins().last.unwrap().error.unwrap().contains(why));
        assert!(misconfigured.logins().last_success.is_none());
    }

    // A KMS that isn't there.
    let gone = crate::kms::Kms::new(&crate::kms::KmsArgs {
        kms_address: Some("http://127.0.0.1:1".to_owned()),
        kms_jwt_key: Some(key),
        kms_auth_mount: "cairn".to_owned(),
        kms_auth_role: "s3".to_owned(),
        kms_ca_cert: None,
    })
    .unwrap()
    .unwrap();
    assert!(!gone.health().await.reachable);
}

/// A PutBucketEncryption body for SSE-KMS under `key`.
fn default_config(key: &str) -> Bytes {
    Bytes::from(format!(
        "<ServerSideEncryptionConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Rule>\
         <ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm>\
         <KMSMasterKeyID>{key}</KMSMasterKeyID></ApplyServerSideEncryptionByDefault>\
         </Rule></ServerSideEncryptionConfiguration>"
    ))
}

/// A bucket's default encryption: set (with a key the KMS has, which the
/// admin setting it needn't be allowed to use), read back, applied to writes
/// that ask for no encryption of their own (as their role, which must be
/// allowed to use the key), and removed.
#[tokio::test]
async fn buckets_have_default_keys() {
    use crate::s3::buckets::encryption::{
        default_request, delete_bucket_encryption, get_bucket_encryption, put_bucket_encryption,
    };
    let Some(app) = kms_node().await else { return };
    let admin = role(&app, "admin", &["transit/cairn-missing"]).await;
    let (alice, bob) = (role(&app, "alice", &["transit/cairn-test"]).await, role(&app, "bob", &[]).await);

    let response = get_bucket_encryption(&app, BUCKET).await.unwrap();
    assert_eq!(code(response).await, (StatusCode::NOT_FOUND, "ServerSideEncryptionConfigurationNotFoundError".to_owned()));
    assert_eq!(default_request(&app, BUCKET).await.unwrap().unwrap(), None);
    // A key the KMS doesn't have.
    let response = put_bucket_encryption(&app, BUCKET, default_config("cairn-missing"), admin).await.unwrap();
    assert_eq!(code(response).await, (StatusCode::BAD_REQUEST, "KMS.NotFoundException".to_owned()));
    // One the admin may not use, but writers may.
    let response = put_bucket_encryption(&app, BUCKET, default_config("arn:aws:kms:cairn-test"), admin).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = get_bucket_encryption(&app, BUCKET).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.contains("<SSEAlgorithm>aws:kms</SSEAlgorithm>"), "{body}");
    assert!(body.contains("<KMSMasterKeyID>arn:aws:kms:transit/cairn-test</KMSMasterKeyID>"), "{body}");
    assert!(body.contains("<BucketKeyEnabled>false</BucketKeyEnabled>"), "{body}");

    // A write that asks for nothing gets it, as its own role.
    let request = default_request(&app, BUCKET).await.unwrap().unwrap().unwrap();
    assert_eq!(request, kms(None, &[]));
    put_kms(&app, alice, "k", data(100), &request).await.unwrap();
    let (status, headers, body) = get(&app, Some(alice), "k", None).await;
    assert_eq!((status, headers), (StatusCode::OK, Headers::kms("transit/cairn-test", None)));
    assert!(body == data(100));
    let refused = put_kms(&app, bob, "k2", data(100), &request).await.unwrap_err();
    assert_eq!(code(refused).await, (StatusCode::FORBIDDEN, "AccessDenied".to_owned()));

    let response = delete_bucket_encryption(&app, BUCKET).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(default_request(&app, BUCKET).await.unwrap().unwrap(), None);
    // What was written stays as it was.
    assert_eq!(get(&app, Some(alice), "k", None).await.1, Headers::kms("transit/cairn-test", None));
    let response = get_bucket_encryption(&app, "nope").await.unwrap();
    assert_eq!(code(response).await, (StatusCode::NOT_FOUND, "NoSuchBucket".to_owned()));
}
