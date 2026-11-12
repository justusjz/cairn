//! POST Object: forms signed with a policy, uploaded to a node (see
//! `s3::objects::post`).

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit, Mac};
use http_body_util::{BodyExt, Full};
use hyper::{
    Request, Response, StatusCode,
    body::{Body, Bytes, Frame},
};
use md5::Digest;
use sha2::Sha256;
use uuid::Uuid;

use super::{BUCKET, assert_files, customer_key, get, get_sealed, kms_node, node_with};
use crate::{
    App, packer,
    roles::Permission,
    s3::{conditional::Preconditions, objects::get::get_object, objects::post::post_object},
};

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

/// A new role (its access key and secret), which may write to `BUCKET` if
/// `write`.
async fn role(app: &App, write: bool) -> (String, String) {
    let name = format!("poster-{}", &Uuid::new_v4().simple().to_string()[..8]);
    let client = app.pool.get().await.unwrap();
    let secret = crate::roles::create(&client, &name, None, false).await.unwrap();
    let permissions = match write {
        true => &[Permission::Write][..],
        false => &[Permission::Read][..],
    };
    crate::roles::grant(&client, &name, BUCKET, permissions).await.unwrap();
    (name, secret)
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

/// `t` (Unix seconds) as an ISO 8601 time, and as an `x-amz-date`.
fn times(t: i64) -> (String, String) {
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let (h, m, s) = (secs / 3600, secs / 60 % 60, secs % 60);
    (
        format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.000Z"),
        format!("{year:04}{month:02}{day:02}T{h:02}{m:02}{s:02}Z"),
    )
}

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// A form's signed fields, as botocore's `generate_presigned_post` makes
/// them: its policy (expiring at `expires`) has `conditions` and those on
/// the fields it adds itself, and is signed with `secret`.
fn signed(access_key: &str, secret: &str, conditions: &str, expires: i64) -> Vec<(String, String)> {
    let (expiration, _) = times(expires);
    let (_, date) = times(now());
    let credential = format!("{access_key}/{}/us-east-1/s3/aws4_request", &date[..8]);
    let policy = format!(
        r#"{{"expiration": "{expiration}", "conditions": [{conditions}{}{{"x-amz-algorithm": "AWS4-HMAC-SHA256"}},
           {{"x-amz-credential": "{credential}"}}, {{"x-amz-date": "{date}"}}]}}"#,
        if conditions.is_empty() { "" } else { ", " },
    );
    let policy = STANDARD.encode(policy);
    let key = [&date[..8], "us-east-1", "s3", "aws4_request"]
        .iter()
        .fold(format!("AWS4{secret}").into_bytes(), |key, part| hmac(&key, part));
    let signature: String = hmac(&key, &policy).iter().map(|b| format!("{b:02x}")).collect();
    [
        ("x-amz-algorithm", "AWS4-HMAC-SHA256".to_owned()),
        ("x-amz-credential", credential),
        ("x-amz-date", date),
        ("policy", policy),
        ("x-amz-signature", signature),
    ]
    .into_iter()
    .map(|(n, v)| (n.to_owned(), v))
    .collect()
}

const BOUNDARY: &str = "----cairnformboundary";

/// A form of `fields`, then the file `name` holding `data`, then `after`.
fn form(fields: &[(String, String)], name: &str, data: &[u8], after: &[(&str, &str)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (n, v) in fields {
        body.extend(format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{n}\"\r\n\r\n{v}\r\n").bytes());
    }
    body.extend(
        format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n\
             Content-Type: application/x-ignored\r\n\r\n"
        )
        .bytes(),
    );
    body.extend_from_slice(data);
    body.extend(b"\r\n");
    for (n, v) in after {
        body.extend(format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{n}\"\r\n\r\n{v}\r\n").bytes());
    }
    body.extend(format!("--{BOUNDARY}--\r\n").bytes());
    body
}

/// Posts `body` to `path` with the request headers `headers`.
async fn post_to<B>(app: &Arc<App>, path: &str, headers: &[(&str, &str)], body: B) -> Response<Full<Bytes>>
where
    B: Body<Data = Bytes> + Unpin + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("/{path}"))
        .header("host", "cairn.test")
        .header("content-type", format!("multipart/form-data; boundary={BOUNDARY}"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    post_object(app, request.body(body).unwrap(), path, false, None).await.unwrap()
}

async fn post(app: &Arc<App>, body: Vec<u8>) -> Response<Full<Bytes>> {
    post_to(app, BUCKET, &[], Full::new(Bytes::from(body))).await
}

/// A response's status and S3 error code (or body).
async fn outcome(response: Response<Full<Bytes>>) -> (StatusCode, String) {
    let status = response.status();
    let body = String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    let code = match body.find("<Code>") {
        Some(start) => body[start + 6..body.find("</Code>").unwrap()].to_owned(),
        None => body,
    };
    (status, code)
}

fn fields(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect()
}

/// A form for `key` under a policy of `conditions` (and the key's), with
/// `extra` fields, signed by the role.
fn keyed(signer: &(String, String), key: &str, conditions: &str, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let conditions = match conditions {
        "" => format!(r#"{{"bucket": "{BUCKET}"}}, ["starts-with", "$key", ""]"#),
        _ => format!(r#"{{"bucket": "{BUCKET}"}}, ["starts-with", "$key", ""], {conditions}"#),
    };
    let mut form = fields(&[("key", key)]);
    form.extend(fields(extra));
    form.extend(signed(&signer.0, &signer.1, &conditions, now() + 600));
    form
}

#[tokio::test]
async fn uploads_a_file() {
    let Some(app) = node().await else { return };
    let signer = role(&app, true).await;
    let mut signed_form = fields(&[
        ("Key", "uploads/${filename}"),
        ("Content-Type", "text/plain"),
        ("x-amz-meta-origin", "server-a"),
        ("x-ignore-this", "anything"),
    ]);
    let conditions = format!(
        r#"{{"bucket": "{BUCKET}"}}, ["starts-with", "$key", "uploads/"], ["starts-with", "$Content-Type", "text/"],
           {{"x-amz-meta-origin": "server-a"}}, ["content-length-range", 0, 100]"#
    );
    signed_form.extend(signed(&signer.0, &signer.1, &conditions, now() + 600));
    let data = b"hello, form";
    let response = post(&app, form(&signed_form, "C:\\Users\\x\\note.txt", data, &[])).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let md5: String = md5::Md5::digest(data).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(response.headers()["etag"], format!("\"{md5}\"").as_str());
    assert_eq!(response.headers()["location"], "http://cairn.test/bucket/uploads/note.txt");
    assert!(response.headers().contains_key("x-amz-checksum-crc64nvme"));
    let read = get_object(&app, BUCKET, "uploads/note.txt", None, None, None, &Preconditions::default(), None, None, false)
        .await
        .unwrap();
    assert_eq!(read.headers()["content-type"], "text/plain");
    assert_eq!(read.headers()["x-amz-meta-origin"], "server-a");
    assert_eq!(get(&app, "uploads/note.txt").await.unwrap(), data);
}

/// A form posted to the bucket's host (see `s3::hosting`), whose object's URL
/// is on that host too.
#[tokio::test]
async fn uploads_to_a_virtual_host() {
    let Some(app) = node().await else { return };
    let signer = role(&app, true).await;
    let request = Request::builder()
        .method("POST")
        .uri("/")
        .header("host", format!("{BUCKET}.cairn.test"))
        .header("content-type", format!("multipart/form-data; boundary={BOUNDARY}"));
    let body = Full::new(Bytes::from(form(&keyed(&signer, "k", "", &[]), "f", b"hosted", &[])));
    let response = post_object(&app, request.body(body).unwrap(), BUCKET, true, None).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(response.headers()["location"], format!("http://{BUCKET}.cairn.test/k").as_str());
    assert_eq!(get(&app, "k").await.unwrap(), b"hosted");
}

#[tokio::test]
async fn limits_the_size() {
    let Some(app) = node().await else { return };
    let signer = role(&app, true).await;
    let range = r#"["content-length-range", 3, 5]"#;
    for (size, expected) in [
        (3, (StatusCode::NO_CONTENT, "")),
        (5, (StatusCode::NO_CONTENT, "")),
        (2, (StatusCode::BAD_REQUEST, "EntityTooSmall")),
        (6, (StatusCode::BAD_REQUEST, "EntityTooLarge")),
    ] {
        let key = format!("sized-{size}");
        let response = post(&app, form(&keyed(&signer, &key, range, &[]), "f", &vec![b'x'; size], &[])).await;
        assert_eq!(outcome(response).await, (expected.0, expected.1.to_owned()), "{size} bytes");
        assert_eq!(get(&app, &key).await.is_some(), expected.0.is_success());
    }
    // Nothing's left of the refused ones.
    assert_files(&app, 2).await;
    // [0, 0]: only an empty file.
    let range = r#"["content-length-range", 0, 0]"#;
    let response = post(&app, form(&keyed(&signer, "empty", range, &[]), "f", b"", &[])).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = post(&app, form(&keyed(&signer, "not-empty", range, &[]), "f", b"x", &[])).await;
    assert_eq!(outcome(response).await.1, "EntityTooLarge");
}

/// A body that's sent as `rx` receives it, until it's closed.
struct ChannelBody(tokio::sync::mpsc::Receiver<Bytes>);

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        self.0.poll_recv(cx).map(|data| data.map(|data| Ok(Frame::data(data))))
    }
}

/// A file over the policy's size is refused as soon as it's over, before
/// the client has sent all of it.
#[tokio::test]
async fn refuses_a_large_file_before_its_end() {
    let Some(app) = node().await else { return };
    let signer = role(&app, true).await;
    let body = form(&keyed(&signer, "big", r#"["content-length-range", 0, 1000]"#, &[]), "f", &[b'x'; 2000], &[]);
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    // All but the end: the file isn't over, and the form isn't either.
    tx.send(Bytes::copy_from_slice(&body[..body.len() - 100])).await.unwrap();
    let response = tokio::time::timeout(Duration::from_secs(10), post_to(&app, BUCKET, &[], ChannelBody(rx)))
        .await
        .expect("refused before the body ended");
    assert_eq!(outcome(response).await.1, "EntityTooLarge");
    drop(tx);
    assert!(get(&app, "big").await.is_none());
    assert_files(&app, 0).await;
}

#[tokio::test]
async fn checks_the_policy_and_signature() {
    let Some(app) = node().await else { return };
    let signer = role(&app, true).await;
    let reader = role(&app, false).await;
    let refused = |code: &str| (StatusCode::FORBIDDEN, code.to_owned());
    // The key's prefix.
    let form_of = |key: &str| keyed(&signer, key, r#"["starts-with", "$key", "in/"]"#, &[]);
    assert_eq!(outcome(post(&app, form(&form_of("in/a"), "f", b"x", &[])).await).await.0, StatusCode::NO_CONTENT);
    assert_eq!(outcome(post(&app, form(&form_of("out/a"), "f", b"x", &[])).await).await, refused("AccessDenied"));
    // Expired.
    let mut expired = fields(&[("key", "k")]);
    expired.extend(signed(&signer.0, &signer.1, r#"["starts-with", "$key", ""]"#, now() - 1));
    assert_eq!(outcome(post(&app, form(&expired, "f", b"x", &[])).await).await, refused("AccessDenied"));
    // A field the policy doesn't name.
    let extra = keyed(&signer, "k", "", &[("x-amz-meta-sneaky", "1")]);
    assert_eq!(outcome(post(&app, form(&extra, "f", b"x", &[])).await).await, refused("AccessDenied"));
    // Fields after the file are never read.
    let after = keyed(&signer, "after", "", &[]);
    let response = post(&app, form(&after, "f", b"x", &[("x-amz-meta-late", "1")])).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    // Signed with another secret, or by a role that doesn't exist.
    let forged = keyed(&(signer.0.clone(), "not-the-secret".to_owned()), "k", "", &[]);
    assert_eq!(outcome(post(&app, form(&forged, "f", b"x", &[])).await).await, refused("SignatureDoesNotMatch"));
    let nobody = keyed(&("nobody".to_owned(), "secret".to_owned()), "k", "", &[]);
    assert_eq!(outcome(post(&app, form(&nobody, "f", b"x", &[])).await).await, refused("InvalidAccessKeyId"));
    // A role that may only read; a bucket that isn't there.
    let read_only = keyed(&reader, "k", "", &[]);
    assert_eq!(outcome(post(&app, form(&read_only, "f", b"x", &[])).await).await, refused("AccessDenied"));
    let mut elsewhere = fields(&[("key", "k")]);
    elsewhere.extend(signed(&signer.0, &signer.1, r#"["starts-with", "$key", ""]"#, now() + 600));
    let response = post_to(&app, "nope", &[], Full::new(Bytes::from(form(&elsewhere, "f", b"x", &[])))).await;
    assert_eq!(outcome(response).await, (StatusCode::NOT_FOUND, "NoSuchBucket".to_owned()));
    // The policy's bucket isn't the one posted to.
    let response = post_to(&app, "nope", &[], Full::new(Bytes::from(form(&form_of("in/a"), "f", b"x", &[])))).await;
    assert_eq!(outcome(response).await, refused("AccessDenied"));
    // A policy that isn't one.
    let mut broken = keyed(&signer, "k", "", &[]);
    let at = broken.iter().position(|(n, _)| n == "policy").unwrap();
    broken[at].1 = "not base64!".to_owned();
    assert_eq!(outcome(post(&app, form(&broken, "f", b"x", &[])).await).await.1, "SignatureDoesNotMatch");
    // No signature at all.
    let unsigned = fields(&[("key", "k")]);
    assert_eq!(outcome(post(&app, form(&unsigned, "f", b"x", &[])).await).await, refused("AccessDenied"));
    assert_eq!(get(&app, "k").await, None);
}

#[tokio::test]
async fn answers_as_the_form_asks() {
    let Some(app) = node().await else { return };
    let signer = role(&app, true).await;
    let status = |s: &'static str| {
        let condition = format!(r#"{{"success_action_status": "{s}"}}"#);
        keyed(&signer, "k", &condition, &[("success_action_status", s)])
    };
    assert_eq!(post(&app, form(&status("200"), "f", b"x", &[])).await.status(), StatusCode::OK);
    assert_eq!(post(&app, form(&status("204"), "f", b"x", &[])).await.status(), StatusCode::NO_CONTENT);
    assert_eq!(post(&app, form(&status("418"), "f", b"x", &[])).await.status(), StatusCode::NO_CONTENT);
    let response = post(&app, form(&status("201"), "f", b"x", &[])).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let etag = response.headers()["etag"].to_str().unwrap().to_owned();
    let body = outcome(response).await.1;
    assert!(body.contains("<PostResponse><Location>http://cairn.test/bucket/k</Location><Bucket>bucket</Bucket>"), "{body}");
    assert!(body.contains(&format!("<Key>k</Key><ETag>{etag}</ETag>")), "{body}");
    // A redirect, with what was uploaded in its query.
    let redirect = |url: &str| {
        let condition = r#"["starts-with", "$success_action_redirect", ""]"#;
        keyed(&signer, "a b", condition, &[("success_action_redirect", url)])
    };
    let response = post(&app, form(&redirect("https://example.com/done?x=1"), "f", b"x", &[])).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()["location"].to_str().unwrap();
    assert!(location.starts_with("https://example.com/done?x=1&bucket=bucket&key=a%20b&etag=%22"), "{location}");
    // One that isn't a URL is as none.
    assert_eq!(post(&app, form(&redirect("/done"), "f", b"x", &[])).await.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn checks_the_files_checksums() {
    let Some(app) = node().await else { return };
    let signer = role(&app, true).await;
    let data = b"checked";
    let md5 = STANDARD.encode(md5::Md5::digest(data));
    let crc = STANDARD.encode(crc32fast::hash(data).to_be_bytes());
    let upload = |field: &'static str, value: String| {
        let condition = format!(r#"{{"{field}": "{value}"}}"#);
        let body = form(&keyed(&signer, "c", &condition, &[(field, &value)]), "f", data, &[]);
        post(&app, body)
    };
    assert_eq!(upload("Content-MD5", md5).await.status(), StatusCode::NO_CONTENT);
    let wrong = STANDARD.encode([0u8; 16]);
    assert_eq!(outcome(upload("Content-MD5", wrong).await).await.1, "BadDigest");
    let response = upload("x-amz-checksum-crc32", crc.clone()).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(response.headers()["x-amz-checksum-crc32"], crc.as_str());
    assert_eq!(outcome(upload("x-amz-checksum-crc32", "AAAAAA==".to_owned()).await).await.1, "BadDigest");
    // An algorithm without its checksum.
    assert_eq!(outcome(upload("x-amz-checksum-algorithm", "CRC32".to_owned()).await).await.1, "InvalidRequest");
}

#[tokio::test]
async fn encrypts_with_the_clients_key() {
    let Some(app) = node().await else { return };
    let signer = role(&app, true).await;
    let key = [7u8; 32];
    // SSE-C's fields need no condition.
    let sse_c = [
        ("x-amz-server-side-encryption-customer-algorithm", "AES256".to_owned()),
        ("x-amz-server-side-encryption-customer-key", STANDARD.encode(key)),
        ("x-amz-server-side-encryption-customer-key-MD5", STANDARD.encode(md5::Md5::digest(key))),
    ];
    let sse_c: Vec<(&str, &str)> = sse_c.iter().map(|(n, v)| (*n, v.as_str())).collect();
    let body = || Full::new(Bytes::from(form(&keyed(&signer, "secret", "", &sse_c), "f", b"sealed", &[])));
    // Only over HTTPS.
    let response = post_to(&app, BUCKET, &[], body()).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = post_to(&app, BUCKET, &[("x-forwarded-proto", "https")], body()).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(response.headers()["location"], "https://cairn.test/bucket/secret");
    assert_eq!(response.headers()["x-amz-server-side-encryption-customer-algorithm"], "AES256");
    assert_eq!(get_sealed(&app, "secret", None, None).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(get_sealed(&app, "secret", None, Some(&customer_key(&key))).await, (StatusCode::OK, b"sealed".to_vec()));
}

#[tokio::test]
async fn encrypts_with_cairns_key() {
    let Some(app) = kms_node().await else { return };
    super::kms::allow_cairn(&app, &["transit/cairn-sse-s3"]).await;
    let signer = role(&app, true).await;
    let condition = r#"{"x-amz-server-side-encryption": "AES256"}"#;
    let body = form(&keyed(&signer, "s3", condition, &[("x-amz-server-side-encryption", "AES256")]), "f", b"x", &[]);
    let response = post(&app, body).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(response.headers()["x-amz-server-side-encryption"], "AES256");
    assert_eq!(get(&app, "s3").await.unwrap(), b"x");
    // The KMS key to use is the signer's to say.
    let kms = [("x-amz-server-side-encryption", "aws:kms"), ("x-amz-server-side-encryption-aws-kms-key-id", "transit/other")];
    let condition = r#"{"x-amz-server-side-encryption": "aws:kms"}"#;
    let response = post(&app, form(&keyed(&signer, "kms", condition, &kms), "f", b"x", &[])).await;
    assert_eq!(outcome(response).await, (StatusCode::FORBIDDEN, "AccessDenied".to_owned()));
}

#[tokio::test]
async fn refuses_malformed_forms() {
    let Some(app) = node().await else { return };
    let signer = role(&app, true).await;
    let malformed = (StatusCode::BAD_REQUEST, "MalformedPOSTRequest".to_owned());
    // No file.
    let mut body = Vec::new();
    for (n, v) in keyed(&signer, "k", "", &[]) {
        body.extend(format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{n}\"\r\n\r\n{v}\r\n").bytes());
    }
    body.extend(format!("--{BOUNDARY}--\r\n").bytes());
    assert_eq!(outcome(post(&app, body).await).await, malformed);
    // A file that doesn't end.
    let whole = form(&keyed(&signer, "k", "", &[]), "f", &[b'x'; 1000], &[]);
    let cut = whole[..whole.len() - 30].to_vec();
    assert_eq!(outcome(post(&app, cut).await).await, malformed);
    assert_files(&app, 0).await;
    // No key; a field twice.
    let mut keyless = keyed(&signer, "k", "", &[]);
    keyless.retain(|(n, _)| n != "key");
    assert_eq!(outcome(post(&app, form(&keyless, "f", b"x", &[])).await).await, malformed);
    let twice = keyed(&signer, "k", "", &[("KEY", "k")]);
    assert_eq!(outcome(post(&app, form(&twice, "f", b"x", &[])).await).await, malformed);
    // Too much before the file.
    let long = "x".repeat(21 * 1024);
    let padded = keyed(&signer, "k", "", &[("x-ignore-pad", &long)]);
    let response = post(&app, form(&padded, "f", b"x", &[])).await;
    assert_eq!(outcome(response).await, (StatusCode::BAD_REQUEST, "MaxPostPreDataLengthExceededError".to_owned()));
    // Not a form: no boundary.
    let request = Request::builder().method("POST").uri("/bucket").header("content-type", "multipart/form-data");
    let response = post_object(&app, request.body(Full::new(Bytes::new())).unwrap(), BUCKET, false, None).await.unwrap();
    assert_eq!(outcome(response).await, malformed);
    // To an object, or signed twice.
    let ok = || Full::new(Bytes::from(form(&keyed(&signer, "k", "", &[]), "f", b"x", &[])));
    let response = post_to(&app, "bucket/k", &[], ok()).await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    let response = post_to(&app, BUCKET, &[("authorization", "AWS4-HMAC-SHA256 ...")], ok()).await;
    assert_eq!(outcome(response).await, (StatusCode::BAD_REQUEST, "InvalidArgument".to_owned()));
    assert_eq!(post_to(&app, BUCKET, &[], ok()).await.status(), StatusCode::NO_CONTENT);
}

/// A form is signed as `POST` (`s3:authType`), which a bucket policy may
/// deny uploads by.
#[tokio::test]
async fn bucket_policies_see_forms_as_posted() {
    let Some(app) = node().await else { return };
    let signer = role(&app, true).await;
    let deny = |auth_type: &str| {
        Bytes::from(format!(
            r#"{{"Statement":[{{"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::{BUCKET}/*",
                "Condition":{{"StringEquals":{{"s3:authType":"{auth_type}","s3:signatureversion":"AWS4-HMAC-SHA256"}}}}}}]}}"#
        ))
    };
    let set = crate::s3::buckets::policy::put_bucket_policy(&app, BUCKET, deny("POST")).await.unwrap();
    assert_eq!(set.status(), StatusCode::NO_CONTENT);
    let (status, code) = outcome(post(&app, form(&keyed(&signer, "denied.txt", "", &[]), "f", b"x", &[])).await).await;
    assert_eq!((status, code.as_str()), (StatusCode::FORBIDDEN, "AccessDenied"));
    assert!(get(&app, "denied.txt").await.is_none());

    crate::s3::buckets::policy::put_bucket_policy(&app, BUCKET, deny("REST-HEADER")).await.unwrap();
    let response = post(&app, form(&keyed(&signer, "allowed.txt", "", &[]), "f", b"x", &[])).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

/// A form without any signature is anonymous, as in S3: refused, unless the
/// bucket's policy allows anyone to upload there. One that's only partly
/// signed is refused as unsigned.
#[tokio::test]
async fn takes_unsigned_forms_where_a_bucket_policy_allows_them() {
    let Some(app) = node().await else { return };
    let unsigned = |key: &str| form(&fields(&[("key", key), ("Content-Type", "text/plain")]), "f", b"anon", &[]);
    let (status, code) = outcome(post(&app, unsigned("drop/a.txt")).await).await;
    assert_eq!((status, code.as_str()), (StatusCode::FORBIDDEN, "AccessDenied"));

    let policy = format!(
        r#"{{"Statement":[{{"Effect":"Allow","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::{BUCKET}/drop/*"}}]}}"#
    );
    let set = crate::s3::buckets::policy::put_bucket_policy(&app, BUCKET, Bytes::from(policy)).await.unwrap();
    assert_eq!(set.status(), StatusCode::NO_CONTENT);
    let response = post(&app, unsigned("drop/a.txt")).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(get(&app, "drop/a.txt").await.unwrap(), b"anon");
    // Only where it allows.
    let (status, code) = outcome(post(&app, unsigned("elsewhere.txt")).await).await;
    assert_eq!((status, code.as_str()), (StatusCode::FORBIDDEN, "AccessDenied"));
    // A policy without a signature isn't anonymous: it's not signed.
    let half = form(&fields(&[("key", "drop/b.txt"), ("policy", "e30=")]), "f", b"x", &[]);
    let (status, code) = outcome(post(&app, half).await).await;
    assert_eq!((status, code.as_str()), (StatusCode::FORBIDDEN, "AccessDenied"));
    assert!(get(&app, "drop/b.txt").await.is_none());
}
