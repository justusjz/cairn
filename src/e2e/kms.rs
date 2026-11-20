//! SSE-KMS and SSE-S3 end to end, with Cairn's KMS (a file root key): objects
//! whose keys are sealed under data keys of KMS keys, read back, assembled
//! from parts, and copied, sharing their parts or not; all as the users that
//! ask, which may use only the keys their policies and the keys' let them.

use std::{collections::BTreeMap, sync::Arc};

use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::{BodyExt, Full};
use hyper::{Response, StatusCode, body::Bytes};
use md5::Digest;
use uuid::Uuid;

use super::{BUCKET, customer_key, get_sealed, kms_node, put, put_sealed};
use crate::{
    App, AttachTarget, UploadResult,
    kms::Caller,
    payload::Payload,
    s3::{
        conditional::Preconditions,
        multipart::{
            complete::complete_multipart_upload, create::create_multipart_upload, upload_encryption,
        },
        objects::{
            copy::{CopyKeys, copy_object, copy_part},
            get::{get_object, head_object},
        },
        sse::{self, KmsRequest, ServerSide, Stored, Wanted},
        sse_c::CustomerKey,
    },
};

/// Who asks, in these tests: a user, as a `Caller` that lives as long as the
/// tests.
type Role = &'static Caller;

fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

/// An SSE-KMS request for the key `alias/<key_id>` (`cairn-test` if
/// `None`), with `context`.
fn kms(key_id: Option<&str>, context: &[(&str, &str)]) -> KmsRequest {
    KmsRequest {
        key_id: Some(format!("alias/{}", key_id.unwrap_or("cairn-test"))),
        context: (!context.is_empty()).then(|| {
            context
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>()
        }),
    }
}

/// Writes `data` as `key`, encrypted as `request` asks, as PutObject does.
/// Its ETag, or the response refusing it.
async fn put_kms(
    app: &Arc<App>,
    role: Role,
    key: &str,
    data: Vec<u8>,
    request: &KmsRequest,
) -> Result<String, Response<Full<Bytes>>> {
    let sealing = sse::seal(app, Wanted::Kms(request), Some(role), BUCKET, key)
        .await
        .unwrap()?;
    assert!(matches!(
        sealing,
        Some(sse::Sealing {
            stored: Stored::Kms(_),
            ..
        })
    ));
    let attach = AttachTarget::Object {
        storage_class: crate::classes::STANDARD.to_owned(),
        bucket: BUCKET.to_owned(),
        key: key.to_owned(),
        content_type: "application/octet-stream".to_owned(),
        metadata: String::new(),
        conditions: Preconditions::default(),
        sealing,
        checksum: crate::e2e::OBJECT_CHECKSUM,
        tags: String::new(),
        lock: Default::default(),
    };
    let result = crate::upload_part(
        app,
        Full::new(Bytes::from(data)),
        &attach,
        Payload::unchecked(),
    )
    .await
    .unwrap();
    let UploadResult::Committed { etag, .. } = result else {
        panic!("not committed")
    };
    Ok(etag)
}

/// GetObject of (the `range` of) `key`, as `role`: its status, SSE headers
/// and body.
async fn get(
    app: &Arc<App>,
    role: Option<Role>,
    key: &str,
    range: Option<&str>,
) -> (StatusCode, Headers, Vec<u8>) {
    let response = get_object(
        app,
        BUCKET,
        key,
        None,
        range,
        None,
        &Preconditions::default(),
        None,
        role.cloned(),
        false,
    )
    .await
    .unwrap();
    let (status, headers) = (response.status(), Headers::of(response.headers()));
    (
        status,
        headers,
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
}

/// The headers a response tells an object's encryption with.
#[derive(Clone, Debug, PartialEq)]
struct Headers {
    encryption: Option<String>,
    key_id: Option<String>,
    context: Option<String>,
}

impl Headers {
    fn of(headers: &hyper::HeaderMap) -> Headers {
        let get = |name| {
            headers
                .get(name)
                .map(|v: &hyper::header::HeaderValue| v.to_str().unwrap().to_owned())
        };
        Headers {
            encryption: get(sse::ENCRYPTION),
            key_id: get(sse::KMS_KEY_ID),
            context: get(sse::KMS_CONTEXT)
                .map(|c| String::from_utf8(STANDARD.decode(c).unwrap()).unwrap()),
        }
    }

    fn kms(key_arn: &str, context: Option<&str>) -> Headers {
        Headers {
            encryption: Some("aws:kms".to_owned()),
            key_id: Some(key_arn.to_owned()),
            context: context.map(str::to_owned),
        }
    }

    fn none() -> Headers {
        Headers {
            encryption: None,
            key_id: None,
            context: None,
        }
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
    let etag = put_kms(&app, r, "k", plain.clone(), &kms(None, &[]))
        .await
        .unwrap();
    // Not an MD5 of the data, which would give it away.
    let md5: String = md5::Md5::digest(&plain)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_ne!(etag, md5);

    let (status, headers, body) = get(&app, Some(r), "k", None).await;
    assert_eq!(
        (status, headers),
        (
            StatusCode::OK,
            Headers::kms(&arn(&app, "cairn-test").await, None)
        )
    );
    assert!(body == plain);
    let (status, _, body) = get(&app, Some(r), "k", Some("bytes=65530-140000")).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert!(body == plain[65530..=140000]);

    let head = head_object(
        &app,
        BUCKET,
        "k",
        None,
        None,
        None,
        &Preconditions::default(),
        None,
        None,
        false,
    )
    .await
    .unwrap();
    assert_eq!(
        Headers::of(head.headers()),
        Headers::kms(&arn(&app, "cairn-test").await, None)
    );

    let (_, salt, key_id, data_key) = stored(&app, "k").await;
    assert!(salt.is_some());
    assert_eq!(key_id, Some(arn(&app, "cairn-test").await));
    let blob = STANDARD.decode(data_key.unwrap()).unwrap();
    let (id, version) = crate::kms::keys::blob_key(&blob).unwrap();
    assert_eq!(
        (
            arn(&app, "cairn-test").await.ends_with(&id.to_string()),
            version
        ),
        (true, 1)
    );

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
    put_kms(
        &app,
        r,
        "a",
        plain.clone(),
        &kms(Some("cairn-other"), &[("project", "x"), ("a", "1")]),
    )
    .await
    .unwrap();
    put_kms(
        &app,
        r,
        "b",
        plain.clone(),
        &kms(Some("cairn-other"), &[("project", "x"), ("a", "1")]),
    )
    .await
    .unwrap();
    let (status, headers, body) = get(&app, Some(r), "a", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers,
        Headers::kms(
            &arn(&app, "cairn-other").await,
            Some(r#"{"a":"1","project":"x"}"#)
        )
    );
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
    assert!(
        get_object(
            &app,
            BUCKET,
            "b",
            None,
            None,
            None,
            &Preconditions::default(),
            None,
            Some(r.clone()),
            false
        )
        .await
        .is_err()
    );
    // a with another context.
    client
        .execute("UPDATE objects SET sse_kms_context = '{\"a\":\"2\",\"project\":\"x\"}' WHERE key = 'a'", &[])
        .await
        .unwrap();
    assert!(
        get_object(
            &app,
            BUCKET,
            "a",
            None,
            None,
            None,
            &Preconditions::default(),
            None,
            Some(r.clone()),
            false
        )
        .await
        .is_err()
    );
}

/// A key the KMS doesn't have is S3's KMS.NotFoundException; one the user
/// may not use, AccessDenied.
/// Nothing is written either way.
#[tokio::test]
async fn unknown_and_forbidden_keys_are_refused() {
    let Some(app) = kms_node().await else { return };
    let r = role(&app, "alice", ALL).await;
    let refused = put_kms(&app, r, "k", data(10), &kms(Some("cairn-missing"), &[]))
        .await
        .unwrap_err();
    assert_eq!(
        code(refused).await,
        (StatusCode::BAD_REQUEST, "KMS.NotFoundException".to_owned())
    );
    // A key that's there, but not Alice's to use.
    arn(&app, "forbidden").await;
    let refused = put_kms(&app, r, "k", data(10), &kms(Some("forbidden"), &[]))
        .await
        .unwrap_err();
    assert_eq!(
        code(refused).await,
        (StatusCode::FORBIDDEN, "AccessDenied".to_owned())
    );
    assert_eq!(
        super::query_i64(&app, "SELECT count(*) FROM objects").await,
        0
    );
}

/// Writes part `part_number` of `upload_id` with `data`, as UploadPart does:
/// encrypted with the upload's key.
async fn put_part(
    app: &Arc<App>,
    role: Role,
    upload_id: Uuid,
    key: &str,
    part_number: i32,
    data: Vec<u8>,
) -> String {
    let encryption = upload_encryption(app, &upload_id, BUCKET, key)
        .await
        .unwrap()
        .unwrap();
    let upload_key = sse::open(app, &encryption, None, Some(role), BUCKET, key)
        .await
        .unwrap()
        .ok()
        .unwrap();
    assert!(upload_key.is_some() == !encryption.is_plain());
    let attach = AttachTarget::MultipartPart {
        storage_class: crate::classes::STANDARD.to_owned(),
        upload_id,
        part_number,
        key: upload_key,
        sse_s3: matches!(encryption, Stored::S3(_)),
        checksum: crate::e2e::PART_CHECKSUM,
    };
    let result = crate::upload_part(
        app,
        Full::new(Bytes::from(data)),
        &attach,
        Payload::unchecked(),
    )
    .await
    .unwrap();
    let UploadResult::Committed { etag, .. } = result else {
        panic!("not committed")
    };
    etag
}

async fn create(app: &Arc<App>, role: Role, key: &str, wanted: Wanted<'_>) -> (Uuid, Headers) {
    let response = create_multipart_upload(
        app,
        BUCKET,
        key,
        "x",
        "",
        "",
        wanted,
        Some(role.clone()),
        None,
        Default::default(),
        None,
        crate::classes::STANDARD,
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let headers = Headers::of(response.headers());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8(body.to_vec()).unwrap();
    let start = body.find("<UploadId>").unwrap() + "<UploadId>".len();
    (
        body[start..body.find("</UploadId>").unwrap()]
            .parse()
            .unwrap(),
        headers,
    )
}

async fn complete(
    app: &Arc<App>,
    role: Role,
    key: &str,
    upload_id: Uuid,
    etags: &[String],
) -> (StatusCode, Headers) {
    let parts: String = etags
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
        "<CompleteMultipartUpload>{parts}</CompleteMultipartUpload>"
    ));
    let id = upload_id.to_string();
    let response = complete_multipart_upload(
        app,
        BUCKET,
        key,
        &id,
        body,
        &Preconditions::default(),
        None,
        Some(role.clone()),
        None,
        None,
    )
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
    let told = Headers::kms(&arn(&app, "cairn-other").await, Some(r#"{"c":"d"}"#));
    assert_eq!(headers, told);
    let (first, second) = (data(5 << 20), data(70_000));
    let etags = vec![
        put_part(&app, r, upload_id, "k", 1, first.clone()).await,
        put_part(&app, r, upload_id, "k", 2, second.clone()).await,
    ];
    assert_eq!(
        complete(&app, r, "k", upload_id, &etags).await,
        (
            StatusCode::OK,
            Headers::kms(&arn(&app, "cairn-other").await, Some(r#"{"c":"d"}"#))
        )
    );
    // A retry, whose upload is gone.
    assert_eq!(
        complete(&app, r, "k", upload_id, &etags).await,
        (StatusCode::OK, told)
    );
    let (status, headers, body) = get(&app, Some(r), "k", None).await;
    assert_eq!(
        (status, headers),
        (
            StatusCode::OK,
            Headers::kms(&arn(&app, "cairn-other").await, Some(r#"{"c":"d"}"#))
        )
    );
    assert!(body == [first, second].concat());
}

async fn copy(
    app: &Arc<App>,
    role: Role,
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
        None,
        &Preconditions::default(),
        CopyKeys {
            lock: Default::default(),
            source,
            dest,
            role: Some(role),
            checksum: None,
            conditions: None,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    (response.status(), Headers::of(response.headers()))
}

/// A copy between SSE-KMS and SSE-C objects shares the source's parts, under
/// any key and context, with keys of its own; any other change of encryption
/// copies the data. Each reads back as it should.
#[tokio::test]
async fn copies_to_from_and_between_kms_objects() {
    let Some(app) = kms_node().await else { return };
    let r = role(&app, "alice", ALL).await;
    let plain = data(150_000);
    let k1 = customer_key(&[1; 32]);
    put_kms(&app, r, "src", plain.clone(), &kms(None, &[]))
        .await
        .unwrap();
    put(&app, "plain", plain.clone()).await;
    put_sealed(&app, "sse-c", plain.clone(), &k1).await;
    let (src_blob, src_salt, ..) = stored(&app, "src").await;

    // To another KMS key and context: shared parts, a data key of its own.
    let request = kms(Some("cairn-other"), &[("x", "y")]);
    let told = Headers::kms(&arn(&app, "cairn-other").await, Some(r#"{"x":"y"}"#));
    assert_eq!(
        copy(&app, r, "src", "rewrapped", None, Wanted::Kms(&request)).await,
        (StatusCode::OK, told)
    );
    let (blob, salt, key_id, data_key) = stored(&app, "rewrapped").await;
    assert_eq!(
        (blob, &salt, key_id),
        (src_blob, &src_salt, Some(arn(&app, "cairn-other").await))
    );
    assert_ne!(data_key, stored(&app, "src").await.3);
    for key in ["rewrapped", "src"] {
        let (status, _, body) = get(&app, Some(r), key, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body == plain, "{key}");
    }

    // Decrypted, to a plain object; and plain, to SSE-KMS: the data is
    // copied. From SSE-C, the parts are shared, as the object key is: the
    // copy seals it under a data key of its own.
    assert_eq!(
        copy(&app, r, "src", "decrypted", None, Wanted::Plain).await,
        (StatusCode::OK, Headers::none())
    );
    let to_kms = kms(None, &[]);
    for (src, source_key) in [("plain", None), ("sse-c", Some(&k1))] {
        let dst = format!("{src}-to-kms");
        assert_eq!(
            copy(&app, r, src, &dst, source_key, Wanted::Kms(&to_kms)).await,
            (
                StatusCode::OK,
                Headers::kms(&arn(&app, "cairn-test").await, None)
            )
        );
        let (blob, salt, ..) = stored(&app, &dst).await;
        let (from_blob, from_salt, ..) = stored(&app, src).await;
        match source_key {
            None => assert!(blob != from_blob && salt.is_some()),
            Some(_) => assert_eq!((blob, &salt), (from_blob, &from_salt), "{dst}"),
        }
        let (status, _, body) = get(&app, Some(r), &dst, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body == plain, "{dst}");
    }
    let (blob, salt, key_id, _) = stored(&app, "decrypted").await;
    assert!(blob != src_blob && salt.is_none() && key_id.is_none());
    assert!(get(&app, Some(r), "decrypted", None).await.2 == plain);
    // To SSE-C: shared parts too, the object key sealed under the client's.
    assert_eq!(
        copy(&app, r, "src", "to-sse-c", None, Wanted::Customer(&k1))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(stored(&app, "to-sse-c").await.0, src_blob);
    assert_eq!(
        get_sealed(&app, "to-sse-c", None, Some(&k1)).await,
        (StatusCode::OK, plain.clone())
    );
    assert_eq!(
        get_sealed(&app, "to-sse-c", None, None).await.0,
        StatusCode::BAD_REQUEST
    );
    // An SSE-C source still needs its key.
    assert_eq!(
        copy(&app, r, "sse-c", "x", None, Wanted::Kms(&to_kms))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );

    // Onto itself: SSE-KMS again is a change, as is decrypting it; a plain
    // object copied plainly onto itself still isn't.
    assert_eq!(
        copy(&app, r, "src", "src", None, Wanted::Kms(&request))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        stored(&app, "src").await.2,
        Some(arn(&app, "cairn-other").await)
    );
    assert_eq!(
        copy(&app, r, "src", "src", None, Wanted::Plain).await.0,
        StatusCode::OK
    );
    assert!(stored(&app, "src").await.2.is_none());
    assert!(get(&app, Some(r), "src", None).await.2 == plain);
    assert_eq!(
        copy(&app, r, "plain", "plain", None, Wanted::Plain).await.0,
        StatusCode::BAD_REQUEST
    );
}

/// UploadPartCopy decrypts an SSE-KMS source's range, and encrypts it with
/// an SSE-KMS upload's key.
#[tokio::test]
async fn part_copies_of_and_into_kms() {
    let Some(app) = kms_node().await else { return };
    let r = role(&app, "alice", ALL).await;
    let plain = data(6 << 20);
    put_kms(
        &app,
        r,
        "src",
        plain.clone(),
        &kms(Some("cairn-other"), &[]),
    )
    .await
    .unwrap();
    let request = kms(None, &[]);
    let (upload_id, _) = create(&app, r, "dst", Wanted::Kms(&request)).await;
    let id = upload_id.to_string();
    let source = format!("{BUCKET}/src");
    let mut etags = Vec::new();
    for (part, range) in [("1", "bytes=0-5242879"), ("2", "bytes=5242880-6291455")] {
        let response = copy_part(
            &app,
            BUCKET,
            "dst",
            &id,
            part,
            &source,
            Some(range),
            &Preconditions::default(),
            None,
            None,
            Some(r.clone()),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            Headers::of(response.headers()),
            Headers::kms(&arn(&app, "cairn-test").await, None)
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(body.to_vec()).unwrap();
        let start = body.find("<ETag>\"").unwrap() + 7;
        etags.push(body[start..start + 32].to_owned());
    }
    assert_eq!(
        complete(&app, r, "dst", upload_id, &etags).await.0,
        StatusCode::OK
    );
    let (status, headers, body) = get(&app, Some(r), "dst", None).await;
    assert_eq!(
        (status, headers),
        (
            StatusCode::OK,
            Headers::kms(&arn(&app, "cairn-test").await, None)
        )
    );
    assert!(body == plain);
}

/// The keys the user `alice` of most tests may use: three that are there,
/// and one that isn't.
const ALL: &[&str] = &["cairn-test", "cairn-other", "invoices", "cairn-missing"];

/// The ARN of the test account's key `alias/<name>`, which it makes (with
/// the default policy) if it isn't there yet; but `cairn-missing`, which is
/// never there.
pub(crate) async fn arn(app: &Arc<App>, name: &str) -> String {
    use crate::kms::keys;
    let client = app.pool.get().await.unwrap();
    let account = crate::users::account(&client).await.unwrap();
    if name == "cairn-missing" {
        return keys::key_arn(&account, Uuid::nil());
    }
    let alias = format!("alias/{name}");
    let named = keys::KeyRef::parse(&alias).unwrap();
    if let Some(key) = keys::resolve(&client, &account, &named).await.unwrap() {
        return key.arn();
    }
    let policy = crate::policy::Policy::parse(
        &keys::default_policy(&account),
        crate::policy::Kind::Key("*"),
    )
    .unwrap();
    let new = keys::NewKey {
        account: &account,
        description: name,
        policy: policy.normalized(),
        aws_managed: false,
        tags: &[],
    };
    let key = keys::create(app.kms.as_ref().unwrap(), &client, &new)
        .await
        .unwrap()
        .unwrap();
    client
        .execute(
            "INSERT INTO kms_aliases (account_id, name, key_id) VALUES ($1, $2, $3)",
            &[&account, &alias, &key.id],
        )
        .await
        .unwrap();
    key.arn()
}

/// The identity policy that lets a principal use exactly `keys` (their
/// names), through S3; `None` for no keys.
async fn key_policy(app: &Arc<App>, keys: &[&str]) -> Option<String> {
    let mut arns = Vec::new();
    for key in keys {
        arns.push(format!("\"{}\"", arn(app, key).await));
    }
    (!arns.is_empty()).then(|| {
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":["kms:GenerateDataKey","kms:Decrypt"],"Resource":[{}]}}]}}"#,
            arns.join(",")
        )
    })
}

/// A new user `name` (with a suffix of its own), which its identity policy
/// lets use `keys` (their names; the test account's keys, whose policies
/// leave it to the account's identity policies), as a caller.
async fn role(app: &Arc<App>, name: &str, keys: &[&str]) -> Role {
    Box::leak(Box::new(Caller::of(&user(app, name, keys).await).unwrap()))
}

/// A new user `name` (with a suffix of its own), which may use `keys`.
async fn user(app: &Arc<App>, name: &str, keys: &[&str]) -> crate::users::Principal {
    let client = app.pool.get().await.unwrap();
    let account = crate::users::account(&client).await.unwrap();
    let name = format!("{name}-{}", &Uuid::new_v4().simple().to_string()[..8]);
    let (key, _) = crate::users::create_for(&client, &account, &name, None, false)
        .await
        .unwrap();
    if let Some(policy) = key_policy(app, keys).await {
        crate::users::put_policy(&client, &account, &name, "kms", &policy)
            .await
            .unwrap();
    }
    crate::users::Principal::load(&client, &key)
        .await
        .unwrap()
        .unwrap()
}

/// Lets the IAM role `name` (its sessions: a batch job's, say) use exactly
/// `keys`, as `role` lets a user.
pub(crate) async fn allow_iam_role(app: &Arc<App>, name: &str, keys: &[&str]) {
    let client = app.pool.get().await.unwrap();
    let account = crate::users::account(&client).await.unwrap();
    let role = crate::roles::Role::load(&client, &account, name)
        .await
        .unwrap()
        .unwrap();
    let policy = key_policy(app, keys).await.unwrap();
    crate::roles::put_policy(&client, &role, "kms", &policy)
        .await
        .unwrap();
}

/// Writes `data` as `key` with SSE-S3, as a user of no keys would: for
/// other modules' tests.
pub(crate) async fn put_sse_s3(app: &Arc<App>, key: &str, data: Vec<u8>) {
    let writer = role(app, "writer", &[]).await;
    put_s3(app, writer, key, data).await;
}

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
    let (alice, bob) = (
        role(&app, "alice", &["cairn-test"]).await,
        role(&app, "bob", &[]).await,
    );

    let response = get_bucket_encryption(&app, BUCKET).await.unwrap();
    assert_eq!(
        code(response).await,
        (
            StatusCode::NOT_FOUND,
            "ServerSideEncryptionConfigurationNotFoundError".to_owned()
        )
    );
    assert_eq!(default_request(&app, BUCKET).await.unwrap().unwrap(), None);
    // What isn't a key's ID, ARN or alias.
    let response = put_bucket_encryption(&app, BUCKET, default_config("transit/k"))
        .await
        .unwrap();
    assert_eq!(
        code(response).await,
        (StatusCode::BAD_REQUEST, "MalformedXML".to_owned())
    );
    // A key that isn't there is taken, as S3 takes it: writes find out.
    let response = put_bucket_encryption(&app, BUCKET, default_config("alias/cairn-missing"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let refused = put_kms(&app, alice, "k0", data(1), &kms(Some("cairn-missing"), &[]))
        .await
        .unwrap_err();
    assert_eq!(
        code(refused).await,
        (StatusCode::BAD_REQUEST, "KMS.NotFoundException".to_owned())
    );
    let response = put_bucket_encryption(&app, BUCKET, default_config("alias/cairn-test"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = get_bucket_encryption(&app, BUCKET).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        body.contains("<SSEAlgorithm>aws:kms</SSEAlgorithm>"),
        "{body}"
    );
    assert!(
        body.contains("<KMSMasterKeyID>alias/cairn-test</KMSMasterKeyID>"),
        "{body}"
    );
    assert!(
        body.contains("<BucketKeyEnabled>false</BucketKeyEnabled>"),
        "{body}"
    );

    // A write that asks for nothing gets it, as its own role.
    let request = default_request(&app, BUCKET)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let ServerSide::Kms(request) = request else {
        panic!("not SSE-KMS")
    };
    assert_eq!(request, kms(None, &[]));
    put_kms(&app, alice, "k", data(100), &request)
        .await
        .unwrap();
    let (status, headers, body) = get(&app, Some(alice), "k", None).await;
    assert_eq!(
        (status, headers),
        (
            StatusCode::OK,
            Headers::kms(&arn(&app, "cairn-test").await, None)
        )
    );
    assert!(body == data(100));
    let refused = put_kms(&app, bob, "k2", data(100), &request)
        .await
        .unwrap_err();
    assert_eq!(
        code(refused).await,
        (StatusCode::FORBIDDEN, "AccessDenied".to_owned())
    );

    let response = delete_bucket_encryption(&app, BUCKET).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(default_request(&app, BUCKET).await.unwrap().unwrap(), None);
    // What was written stays as it was.
    assert_eq!(
        get(&app, Some(alice), "k", None).await.1,
        Headers::kms(&arn(&app, "cairn-test").await, None)
    );
    let response = get_bucket_encryption(&app, "nope").await.unwrap();
    assert_eq!(
        code(response).await,
        (StatusCode::NOT_FOUND, "NoSuchBucket".to_owned())
    );
}

/// Writes `data` as `key` with SSE-S3, as PutObject does: Cairn's key, as
/// Cairn, whatever role writes.
async fn put_s3(app: &Arc<App>, role: Role, key: &str, data: Vec<u8>) {
    let sealing = sse::seal(app, Wanted::S3, Some(role), BUCKET, key)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        sealing,
        Some(sse::Sealing {
            stored: Stored::S3(_),
            ..
        })
    ));
    let attach = AttachTarget::Object {
        storage_class: crate::classes::STANDARD.to_owned(),
        bucket: BUCKET.to_owned(),
        key: key.to_owned(),
        content_type: "application/octet-stream".to_owned(),
        metadata: String::new(),
        conditions: Preconditions::default(),
        sealing,
        checksum: crate::e2e::OBJECT_CHECKSUM,
        tags: String::new(),
        lock: Default::default(),
    };
    let result = crate::upload_part(
        app,
        Full::new(Bytes::from(data)),
        &attach,
        Payload::unchecked(),
    )
    .await
    .unwrap();
    assert!(matches!(result, UploadResult::Committed { .. }));
}

/// SSE-S3: under data keys the root key wraps, so anyone that may read an
/// object (or anonymously) reads it. A node reuses its data key for many
/// objects; each object's key is bound to its name. Copies to and from
/// SSE-KMS share their parts, multipart uploads and bucket defaults work.
/// A node that just started unwraps the data key again; one with another
/// root key can't.
#[tokio::test]
async fn sse_s3_uses_cairns_own_key() {
    let Some(app) = kms_node().await else { return };
    let alice = role(&app, "alice", &["cairn-test"]).await;
    let bob = role(&app, "bob", &[]).await;
    let s3 = Headers {
        encryption: Some("AES256".to_owned()),
        key_id: None,
        context: None,
    };

    put_s3(&app, bob, "a", data(100_000)).await;
    put_s3(&app, bob, "b", data(1000)).await;
    let ((blob_a, salt_a, key_id, key_a), (_, _, _, key_b)) =
        (stored(&app, "a").await, stored(&app, "b").await);
    assert!(salt_a.is_some());
    assert_eq!(key_id.as_deref(), Some(sse::SSE_S3_KEY_ID));
    assert_eq!(
        key_a, key_b,
        "a node seals an hour's objects under one data key"
    );
    for (role, key, len) in [
        (None, "a", 100_000),
        (Some(alice), "b", 1000),
        (Some(bob), "a", 100_000),
    ] {
        let (status, headers, body) = get(&app, role, key, None).await;
        assert_eq!((status, &headers), (StatusCode::OK, &s3));
        assert!(body == data(len));
    }
    // As a node that just started, which unwraps it again.
    app.kms.as_ref().unwrap().forget();
    assert!(get(&app, None, "a", None).await.2 == data(100_000));
    let head = head_object(
        &app,
        BUCKET,
        "a",
        None,
        None,
        None,
        &Preconditions::default(),
        None,
        None,
        false,
    )
    .await
    .unwrap();
    assert_eq!(Headers::of(head.headers()), s3);

    // b with a's sealed key: the same data key, but another object.
    let client = app.pool.get().await.unwrap();
    client
        .execute(
            "UPDATE objects SET sse_kms_sealed = (SELECT sse_kms_sealed FROM objects WHERE key = 'a')
             WHERE key = 'b'",
            &[],
        )
        .await
        .unwrap();
    assert!(
        get_object(
            &app,
            BUCKET,
            "b",
            None,
            None,
            None,
            &Preconditions::default(),
            None,
            None,
            false
        )
        .await
        .is_err()
    );

    // Copies: to SSE-S3 share the parts; to SSE-KMS and back, or to plain,
    // they don't (an SSE-S3 object's ETag is its MD5, which takes reading).
    assert_eq!(
        copy(&app, bob, "a", "s3", None, Wanted::S3).await,
        (StatusCode::OK, s3.clone())
    );
    assert_eq!(stored(&app, "s3").await.0, blob_a);
    assert_eq!(etag_of(&app, "s3").await, md5_hex(&data(100_000)));
    let to_kms = kms(None, &[]);
    assert_eq!(
        copy(&app, alice, "a", "kms", None, Wanted::Kms(&to_kms))
            .await
            .0,
        StatusCode::OK
    );
    assert!(stored(&app, "kms").await.0 != blob_a);
    assert_eq!(
        copy(&app, alice, "kms", "back", None, Wanted::S3).await,
        (StatusCode::OK, s3.clone())
    );
    assert!(get(&app, None, "back", None).await.2 == data(100_000));
    assert_eq!(etag_of(&app, "back").await, md5_hex(&data(100_000)));
    assert_eq!(
        copy(&app, bob, "a", "plain", None, Wanted::Plain).await.0,
        StatusCode::OK
    );
    let (blob, salt, ..) = stored(&app, "plain").await;
    assert!(blob != blob_a && salt.is_none());

    // Multipart.
    let (upload_id, headers) = create(&app, bob, "multi", Wanted::S3).await;
    assert_eq!(headers, s3);
    let etags = vec![
        put_part(&app, bob, upload_id, "multi", 1, data(5 << 20)).await,
        put_part(&app, bob, upload_id, "multi", 2, data(10)).await,
    ];
    assert_eq!(
        complete(&app, bob, "multi", upload_id, &etags).await,
        (StatusCode::OK, s3.clone())
    );
    assert!(get(&app, None, "multi", None).await.2 == [data(5 << 20), data(10)].concat());

    // As a bucket's default.
    use crate::s3::buckets::encryption::{
        default_request, get_bucket_encryption, put_bucket_encryption,
    };
    let aes = Bytes::from(
        "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault>\
         <SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule>\
         </ServerSideEncryptionConfiguration>",
    );
    assert_eq!(
        put_bucket_encryption(&app, BUCKET, aes)
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        default_request(&app, BUCKET).await.unwrap().unwrap(),
        Some(ServerSide::S3)
    );
    let body = get_bucket_encryption(&app, BUCKET)
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert!(
        String::from_utf8(body.to_vec())
            .unwrap()
            .contains("<SSEAlgorithm>AES256</SSEAlgorithm>")
    );

    // Another root key doesn't unwrap it.
    let other =
        crate::kms::Kms::with_root(crate::kms::Root::File(zeroize::Zeroizing::new([3; 32])));
    let wrapped = STANDARD.decode(key_a.unwrap()).unwrap();
    assert!(matches!(
        other.sse_s3_open(&wrapped).await,
        Err(crate::kms::RootError::Failed(_))
    ));
    assert!(
        app.kms
            .as_ref()
            .unwrap()
            .sse_s3_open(&wrapped)
            .await
            .is_ok()
    );
}

fn md5_hex(data: &[u8]) -> String {
    md5::Md5::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The ETag a GetObject of `key` answers with (unquoted).
async fn etag_of(app: &Arc<App>, key: &str) -> String {
    let response = get_object(
        app,
        BUCKET,
        key,
        None,
        None,
        None,
        &Preconditions::default(),
        None,
        None,
        false,
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.headers()[hyper::header::ETAG]
        .to_str()
        .unwrap()
        .trim_matches('"')
        .to_owned()
}

/// An SSE-S3 object's ETag is its content's MD5, as in S3, and a multipart
/// one's S3's combined one: told in GET, HEAD, the listings and by the write,
/// and stored sealed (never the same twice). Conditional writes and reads go
/// by it.
#[tokio::test]
async fn sse_s3_etags_are_md5s_stored_sealed() {
    use crate::s3::objects::{
        list::ListVersion, list::list_objects, list_versions::list_object_versions,
    };
    let Some(app) = kms_node().await else { return };
    let bob = role(&app, "bob", &[]).await;
    let plain = data(100_000);
    put_s3(&app, bob, "k", plain.clone()).await;
    let md5 = md5_hex(&plain);
    assert_eq!(etag_of(&app, "k").await, md5);
    let head = head_object(
        &app,
        BUCKET,
        "k",
        None,
        None,
        None,
        &Preconditions::default(),
        None,
        None,
        false,
    )
    .await
    .unwrap();
    assert_eq!(
        head.headers()[hyper::header::ETAG].to_str().unwrap(),
        format!("\"{md5}\"")
    );
    // Stored sealed: not the MD5, and not the same for the same content.
    put_s3(&app, bob, "k2", plain.clone()).await;
    let stored_etag = |key: &'static str| {
        let app = app.clone();
        async move {
            let client = app.pool.get().await.unwrap();
            client
                .query_one("SELECT etag FROM objects WHERE key = $1", &[&key])
                .await
                .unwrap()
                .get::<_, String>(0)
        }
    };
    let (sealed, sealed2) = (stored_etag("k").await, stored_etag("k2").await);
    assert!(!sealed.contains(&md5) && sealed != sealed2);
    for listing in [
        list_objects(
            &app,
            BUCKET,
            "",
            None,
            "",
            1000,
            ListVersion::V2 {
                continuation_token: None,
                start_after: None,
                fetch_owner: false,
            },
            Default::default(),
        )
        .await
        .unwrap(),
        list_object_versions(&app, BUCKET, "", None, "", None, 1000, Default::default())
            .await
            .unwrap(),
    ] {
        let body = String::from_utf8(
            listing
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert_eq!(
            body.matches(&format!("<ETag>\"{md5}\"</ETag>")).count(),
            2,
            "{body}"
        );
    }

    // Conditional reads and writes, by the MD5.
    let conditional = |name: &str, value: &str| {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
        Preconditions::from_headers(&headers)
    };
    let read = get_object(
        &app,
        BUCKET,
        "k",
        None,
        None,
        None,
        &conditional("if-none-match", &format!("\"{md5}\"")),
        None,
        None,
        false,
    )
    .await
    .unwrap();
    assert_eq!(read.status(), StatusCode::NOT_MODIFIED);
    let write = |conditions: Preconditions| {
        let app = app.clone();
        async move {
            let sealing = sse::seal(&app, Wanted::S3, Some(bob), BUCKET, "k")
                .await
                .unwrap()
                .unwrap();
            let attach = AttachTarget::Object {
                storage_class: crate::classes::STANDARD.to_owned(),
                bucket: BUCKET.to_owned(),
                key: "k".to_owned(),
                content_type: "x".to_owned(),
                metadata: String::new(),
                conditions,
                sealing,
                checksum: crate::e2e::OBJECT_CHECKSUM,
                tags: String::new(),
                lock: Default::default(),
            };
            crate::upload_part(
                &app,
                Full::new(Bytes::from(data(10))),
                &attach,
                Payload::unchecked(),
            )
            .await
            .unwrap()
        }
    };
    assert!(matches!(
        write(conditional(
            "if-match",
            "\"0123456789abcdef0123456789abcdef\""
        ))
        .await,
        UploadResult::PreconditionFailed
    ));
    assert!(matches!(
        write(conditional("if-none-match", "*")).await,
        UploadResult::PreconditionFailed
    ));
    assert!(matches!(
        write(conditional("if-match", &format!("\"{md5}\""))).await,
        UploadResult::Committed { .. }
    ));
    assert_eq!(etag_of(&app, "k").await, md5_hex(&data(10)));

    // Multipart: S3's ETag of the parts' MD5s, told back and listed.
    let (upload_id, _) = create(&app, bob, "multi", Wanted::S3).await;
    let (first, second) = (data(5 << 20), data(10));
    let etags = vec![
        put_part(&app, bob, upload_id, "multi", 1, first.clone()).await,
        put_part(&app, bob, upload_id, "multi", 2, second.clone()).await,
    ];
    assert_eq!(etags, vec![md5_hex(&first), md5_hex(&second)]);
    let parts = crate::s3::multipart::list_parts::list_parts(
        &app,
        BUCKET,
        "multi",
        &upload_id.to_string(),
        0,
        1000,
        None,
        None,
    )
    .await
    .unwrap();
    let body = String::from_utf8(
        parts
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(
        body.contains(&format!("<ETag>\"{}\"</ETag>", etags[1])),
        "{body}"
    );
    // A part listed with a wrong ETag is no part of it.
    let wrong = vec![etags[0].clone(), md5_hex(b"other")];
    let response = complete_multipart_upload(
        &app,
        BUCKET,
        "multi",
        &upload_id.to_string(),
        complete_body(&wrong),
        &Preconditions::default(),
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        code(response).await,
        (StatusCode::BAD_REQUEST, "InvalidPart".to_owned())
    );
    let combined = {
        let mut md5 = md5::Md5::new();
        md5.update(md5::Md5::digest(&first));
        md5.update(md5::Md5::digest(&second));
        format!(
            "{}-2",
            md5.finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
    };
    for _ in 0..2 {
        // The second time, a retry: its upload is gone, its version tells.
        let response = complete_multipart_upload(
            &app,
            BUCKET,
            "multi",
            &upload_id.to_string(),
            complete_body(&etags),
            &Preconditions::default(),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(
            body.contains(&format!("<ETag>\"{combined}\"</ETag>")),
            "{body}"
        );
    }
    assert_eq!(etag_of(&app, "multi").await, combined);

    // A copy shares its source's object key, and its ETag is sealed again,
    // as its own: its source's, moved over in the catalog, doesn't open.
    assert_eq!(
        copy(&app, bob, "multi", "copy", None, Wanted::S3).await.0,
        StatusCode::OK
    );
    assert_eq!(etag_of(&app, "copy").await, combined);
    let client = app.pool.get().await.unwrap();
    client
        .execute("UPDATE objects SET etag = (SELECT etag FROM objects WHERE key = 'multi') WHERE key = 'copy'", &[])
        .await
        .unwrap();
    let read = get_object(
        &app,
        BUCKET,
        "copy",
        None,
        None,
        None,
        &Preconditions::default(),
        None,
        None,
        false,
    )
    .await;
    assert!(
        read.is_err(),
        "another object's sealed ETag opened as the copy's"
    );
}

/// A CompleteMultipartUpload body listing `etags` as parts 1, 2, ...
fn complete_body(etags: &[String]) -> Bytes {
    let parts: String = etags
        .iter()
        .enumerate()
        .map(|(i, etag)| {
            format!(
                "<Part><PartNumber>{}</PartNumber><ETag>\"{etag}\"</ETag></Part>",
                i + 1
            )
        })
        .collect();
    Bytes::from(format!(
        "<CompleteMultipartUpload>{parts}</CompleteMultipartUpload>"
    ))
}

/// An SSE-KMS object's checksum is stored sealed under its key, which a HEAD
/// asks the KMS for only to tell it, as the role asking.
#[tokio::test]
async fn checksums_under_the_kms() {
    use crate::s3::checksums::{self, Algorithm};
    let Some(app) = kms_node().await else { return };
    let r = role(&app, "alice", ALL).await;
    let plain = data(70_000);
    put_kms(&app, r, "k", plain.clone(), &kms(None, &[]))
        .await
        .unwrap();
    let crc64 = checksums::encode(&checksums::digest(Algorithm::Crc64Nvme, &plain));
    let stored: String = app
        .pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT checksum FROM objects WHERE key = 'k'", &[])
        .await
        .unwrap()
        .get(0);
    assert_ne!(stored, crc64, "stored sealed");
    let head = |role: Option<Role>| {
        let app = app.clone();
        let role = role.cloned();
        async move {
            head_object(
                &app,
                BUCKET,
                "k",
                None,
                None,
                None,
                &Preconditions::default(),
                None,
                role,
                true,
            )
            .await
            .unwrap()
        }
    };
    let told = head(Some(r)).await;
    assert_eq!(told.status(), StatusCode::OK);
    assert_eq!(
        told.headers()[Algorithm::Crc64Nvme.header()],
        crc64.as_str()
    );
    assert_eq!(told.headers()[checksums::TYPE], "FULL_OBJECT");
    // A user that may not use the key can't have it.
    let other = role(&app, "bob", &[]).await;
    assert_eq!(head(Some(other)).await.status(), StatusCode::FORBIDDEN);
}

/// UpdateObjectEncryption (Batch Operations'; see `sse::update_encryption`):
/// an SSE-S3 multipart object becomes SSE-KMS in place, keeping its data,
/// ETag (its MD5s', now stored in the clear, as are its parts') and
/// checksum; an SSE-KMS one goes under another key, as a user that may
/// use both. Plain objects, and roles that may not use the keys, are
/// refused. Checksums are worked out of its data at rest, of the whole or
/// of its parts.
#[tokio::test]
async fn encryption_is_updated_in_place() {
    use crate::s3::checksums::{self, Algorithm, Type};
    let Some(app) = kms_node().await else { return };
    let alice = role(&app, "alice", &["cairn-test", "cairn-other"]).await;
    let bob = role(&app, "bob", &["cairn-test"]).await;
    let (upload_id, _) = create(&app, alice, "m", Wanted::S3).await;
    let (first, second) = (data(5 << 20), data(70_000));
    let part_etags = vec![
        put_part(&app, alice, upload_id, "m", 1, first.clone()).await,
        put_part(&app, alice, upload_id, "m", 2, second.clone()).await,
    ];
    assert_eq!(part_etags[0], md5_hex(&first));
    assert_eq!(
        complete(&app, alice, "m", upload_id, &part_etags).await.0,
        StatusCode::OK
    );
    let etag = etag_of(&app, "m").await;
    assert!(etag.ends_with("-2"), "{etag}");
    let stored = |key: &'static str| {
        let app = app.clone();
        async move {
            let client = app.pool.get().await.unwrap();
            let row = client
                .query_one(
                    "SELECT etag, sse_kms_key_id, sse_s3, checksum,
                            (SELECT array_agg(p.etag ORDER BY p.part_number) FROM parts p WHERE p.object_id = o.id)
                     FROM objects o WHERE key = $1 AND is_latest",
                    &[&key],
                )
                .await
                .unwrap();
            let r: (String, Option<String>, bool, Option<String>, Vec<String>) =
                (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4));
            r
        }
    };
    let before = stored("m").await;
    assert_ne!(before.0, etag, "sealed");

    let to = |key: &str| kms(Some(key), &[]);
    sse::update_encryption(&app, BUCKET, "m", None, &to("cairn-other"), Some(alice))
        .await
        .unwrap()
        .unwrap();
    let after = stored("m").await;
    assert_eq!(after.0, etag, "the ETag, in the clear");
    assert_eq!(after.1, Some(arn(&app, "cairn-other").await));
    assert!(!after.2);
    assert_eq!(after.3, before.3, "the checksum, sealed as it was");
    assert_eq!(after.4, part_etags, "the parts' ETags, in the clear");
    let (status, headers, body) = get(&app, Some(alice), "m", None).await;
    assert_eq!(
        (status, headers),
        (
            StatusCode::OK,
            Headers::kms(&arn(&app, "cairn-other").await, None)
        )
    );
    assert!(body == [first.clone(), second.clone()].concat());
    // Bob may not use the old key.
    let refused = sse::update_encryption(&app, BUCKET, "m", None, &to("cairn-test"), Some(bob))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(code(refused).await.0, StatusCode::FORBIDDEN);
    sse::update_encryption(&app, BUCKET, "m", None, &to("cairn-test"), Some(alice))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored("m").await.0, etag);
    let (status, headers, _) = get(&app, Some(bob), "m", None).await;
    assert_eq!(
        (status, headers),
        (
            StatusCode::OK,
            Headers::kms(&arn(&app, "cairn-test").await, None)
        )
    );

    // Its checksums, worked out of its data, as Bob.
    let compute = |algorithm, kind| {
        let app = app.clone();
        async move {
            crate::s3::objects::copy::compute_checksum(
                &app,
                BUCKET,
                "m",
                None,
                algorithm,
                kind,
                Some(bob.clone()),
            )
            .await
            .unwrap()
            .unwrap()
        }
    };
    let whole = compute(Algorithm::Sha256, Type::FullObject).await;
    let all = [first.clone(), second.clone()].concat();
    assert_eq!(whole.raw, checksums::digest(Algorithm::Sha256, &all));
    assert_eq!(whole.etag, etag);
    let parts = vec![
        checksums::digest(Algorithm::Crc32, &first),
        checksums::digest(Algorithm::Crc32, &second),
    ];
    let composite = compute(Algorithm::Crc32, Type::Composite).await;
    assert_eq!(composite.checksum.kind, Type::Composite);
    assert_eq!(
        composite.checksum.value,
        checksums::composite(Algorithm::Crc32, &parts)
    );
    assert_eq!(
        composite.raw,
        checksums::digest(Algorithm::Crc32, &parts.concat())
    );

    // A plain object has no encryption to update; a missing one, nothing.
    put(&app, "plain", data(10)).await;
    let refused =
        sse::update_encryption(&app, BUCKET, "plain", None, &to("cairn-test"), Some(alice))
            .await
            .unwrap()
            .unwrap_err();
    assert_eq!(
        code(refused).await,
        (StatusCode::BAD_REQUEST, "InvalidRequest".to_owned())
    );
    let refused = sse::update_encryption(
        &app,
        BUCKET,
        "missing",
        None,
        &to("cairn-test"),
        Some(alice),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(
        code(refused).await,
        (StatusCode::NOT_FOUND, "NoSuchKey".to_owned())
    );
    // A single PUT's COMPOSITE checksum is of the whole object.
    let single = crate::s3::objects::copy::compute_checksum(
        &app,
        BUCKET,
        "plain",
        None,
        Algorithm::Crc32,
        Type::Composite,
        None,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(single.checksum.kind, Type::FullObject);
    assert_eq!(single.raw, checksums::digest(Algorithm::Crc32, &data(10)));
    assert_eq!(single.etag, md5_hex(&data(10)));
}
