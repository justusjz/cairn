//! Object Lock (see `s3::object_lock`): buckets' configurations, versions'
//! retentions and legal holds, and what they keep from being deleted, as S3
//! answers for them.

use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use http_body_util::{BodyExt, Full};
use hyper::{HeaderMap, Response, StatusCode, body::Bytes};
use uuid::Uuid;

use super::{BUCKET, node_with, put};
use crate::{
    App, AttachTarget, UploadResult,
    packer,
    payload::Payload,
    s3::{
        buckets::versioning::put_bucket_versioning,
        conditional::Preconditions,
        multipart::{complete::complete_multipart_upload, create::create_multipart_upload},
        object_lock::{
            self, Lock, Mode, get_object_legal_hold, get_object_lock_configuration, get_object_retention,
            put_object_legal_hold, put_object_lock_configuration, put_object_retention,
        },
        objects::{
            copy::{CopyKeys, copy_object},
            delete::{delete_object, delete_objects},
            get::head_object,
            put::put_object,
        },
        sse::Wanted,
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

fn code(body: &str) -> &str {
    body.split("<Code>").nth(1).map_or("", |rest| rest.split("</Code>").next().unwrap())
}

const DAY: Duration = Duration::from_secs(86_400);

fn in_days(days: u64) -> SystemTime {
    SystemTime::now() + DAY * days as u32
}

/// ISO 8601, as clients send it.
fn iso(time: SystemTime) -> String {
    let millis = time.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as i64;
    let days = millis.div_euclid(86_400_000);
    let rest = millis.rem_euclid(86_400_000);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let (h, m, s, ms) = (rest / 3_600_000, rest / 60_000 % 60, rest / 1000 % 60, rest % 1000);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{ms:03}Z")
}

async fn set_versioning(app: &App, state: &str) -> StatusCode {
    let body = format!("<VersioningConfiguration><Status>{state}</Status></VersioningConfiguration>");
    put_bucket_versioning(app, BUCKET, Bytes::from(body)).await.unwrap().status()
}

async fn configure(app: &App, rule: &str) -> (StatusCode, String) {
    let body = format!("<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled>{rule}</ObjectLockConfiguration>");
    let (status, _, body) = text(put_object_lock_configuration(app, BUCKET, Bytes::from(body)).await.unwrap()).await;
    (status, code(&body).to_owned())
}

/// Enables Object Lock on the test bucket, with no default retention.
async fn lock_bucket(app: &App) {
    assert_eq!(set_versioning(app, "Enabled").await, StatusCode::OK);
    assert_eq!(configure(app, "").await.0, StatusCode::OK);
}

/// Writes `key` asking for `lock`; its version ID.
async fn put_locked(app: &Arc<App>, key: &str, lock: Lock) -> String {
    let attach = AttachTarget::Object {
        bucket: BUCKET.to_owned(),
        key: key.to_owned(),
        content_type: "application/octet-stream".to_owned(),
        metadata: String::new(),
        conditions: Preconditions::default(),
        sealing: None,
        checksum: crate::e2e::OBJECT_CHECKSUM,
        tags: String::new(),
        lock,
    };
    let result = crate::upload_part(app, Full::new(Bytes::from(vec![7; 10])), &attach, Payload::unchecked()).await.unwrap();
    let UploadResult::Committed { version_id, .. } = result else { panic!("not committed") };
    version_id.expect("a versioned bucket's")
}

fn retained(mode: Mode, until: SystemTime) -> Lock {
    Lock { retention: Some((mode, until)), legal_hold: None }
}

async fn delete_version(app: &Arc<App>, key: &str, version: &str, bypass: bool) -> (StatusCode, String) {
    let (status, _, body) = text(delete_object(app, BUCKET, key, Some(version), bypass).await.unwrap()).await;
    (status, code(&body).to_owned())
}

async fn set_retention(app: &App, key: &str, version: &str, mode: &str, until: SystemTime, bypass: bool) -> (StatusCode, String) {
    let body = format!("<Retention><Mode>{mode}</Mode><RetainUntilDate>{}</RetainUntilDate></Retention>", iso(until));
    let (status, _, body) = text(put_object_retention(app, BUCKET, key, Some(version), body.as_bytes(), bypass).await.unwrap()).await;
    (status, code(&body).to_owned())
}

async fn set_hold(app: &App, key: &str, version: Option<&str>, status: &str) -> StatusCode {
    let body = format!("<LegalHold><Status>{status}</Status></LegalHold>");
    put_object_legal_hold(app, BUCKET, key, version, body.as_bytes()).await.unwrap().status()
}

async fn head(app: &App, key: &str, version: Option<&str>) -> HeaderMap {
    let response =
        head_object(app, BUCKET, key, version, None, None, &Preconditions::default(), None, None, false).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.headers().clone()
}

async fn versions(app: &App, key: &str) -> i64 {
    crate::e2e::query_i64(app, &format!("SELECT count(*) FROM objects WHERE key = '{key}'")).await
}

#[tokio::test]
async fn object_lock_needs_and_keeps_versioning() {
    let Some(app) = node().await else { return };
    // Nothing configured: S3's 404.
    let (status, _, body) = text(get_object_lock_configuration(&app, BUCKET).await.unwrap()).await;
    assert_eq!((status, code(&body)), (StatusCode::NOT_FOUND, "ObjectLockConfigurationNotFoundError"));
    // Only on a versioned bucket.
    assert_eq!(configure(&app, "").await, (StatusCode::CONFLICT, "InvalidBucketState".to_owned()));
    assert_eq!(set_versioning(&app, "Enabled").await, StatusCode::OK);
    let rule = "<Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>2</Days></DefaultRetention></Rule>";
    assert_eq!(configure(&app, rule).await.0, StatusCode::OK);
    let (status, _, body) = text(get_object_lock_configuration(&app, BUCKET).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>2</Days>"), "{body}");
    // Which can't be suspended now.
    assert_eq!(set_versioning(&app, "Suspended").await, StatusCode::CONFLICT);
    assert_eq!(set_versioning(&app, "Enabled").await, StatusCode::OK);
    // A configuration without a rule removes the default retention, but
    // not Object Lock, which no one can disable.
    assert_eq!(configure(&app, "").await.0, StatusCode::OK);
    let (_, _, body) = text(get_object_lock_configuration(&app, BUCKET).await.unwrap()).await;
    assert!(!body.contains("<Rule>"), "{body}");
    let client = app.pool.get().await.unwrap();
    let refused = client.execute("UPDATE buckets SET object_lock = false WHERE name = $1", &[&BUCKET]).await;
    assert!(refused.is_err());
    let refused = client.execute("UPDATE buckets SET versioning = 'suspended' WHERE name = $1", &[&BUCKET]).await;
    assert!(refused.is_err());
}

#[tokio::test]
async fn a_bucket_can_be_created_with_object_lock() {
    let Some(app) = node().await else { return };
    let account: String = app.pool.get().await.unwrap().query_one("SELECT id FROM accounts WHERE NOT operator LIMIT 1", &[]).await.unwrap().get(0);
    let response = crate::s3::buckets::create::create_bucket(&app, "locked-bucket", &account, true).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let (status, _, body) = text(get_object_lock_configuration(&app, "locked-bucket").await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _, body) = text(crate::s3::buckets::versioning::get_bucket_versioning(&app, "locked-bucket").await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<Status>Enabled</Status>"), "{body}");
}

#[tokio::test]
async fn locks_need_object_lock() {
    let Some(app) = node().await else { return };
    put(&app, "plain", vec![1]).await;
    let lock = retained(Mode::Governance, in_days(1));
    let (status, _, body) = text(
        put_object(
            &app, BUCKET, "k", "x", "", "", Full::new(Bytes::from_static(b"x")), Payload::unchecked(),
            &Preconditions::default(), Wanted::Plain, None, lock,
        )
        .await
        .unwrap(),
    )
    .await;
    assert_eq!((status, code(&body)), (StatusCode::BAD_REQUEST, "InvalidRequest"));
    let response = create_multipart_upload(&app, BUCKET, "k", "x", "", "", Wanted::Plain, None, None, lock).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let (status, _, body) = text(get_object_retention(&app, BUCKET, "plain", None).await.unwrap()).await;
    assert_eq!((status, code(&body)), (StatusCode::BAD_REQUEST, "InvalidRequest"));
    assert_eq!(set_hold(&app, "plain", None, "ON").await, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn governance_mode_can_be_bypassed() {
    let Some(app) = node().await else { return };
    lock_bucket(&app).await;
    let until = in_days(10);
    let version = put_locked(&app, "g", retained(Mode::Governance, until)).await;
    // GET and HEAD tell it.
    let headers = head(&app, "g", None).await;
    assert_eq!(headers.get(object_lock::MODE).unwrap(), "GOVERNANCE");
    let told = headers.get(object_lock::RETAIN_UNTIL).unwrap().to_str().unwrap().to_owned();
    assert_eq!(object_lock::parse_date(&told), object_lock::parse_date(&iso(until)));
    assert!(headers.get(object_lock::LEGAL_HOLD).is_none());
    let (status, _, body) = text(get_object_retention(&app, BUCKET, "g", Some(&version)).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<Mode>GOVERNANCE</Mode><RetainUntilDate>"), "{body}");
    // Not deleted, but a delete marker goes on top, as ever.
    assert_eq!(delete_version(&app, "g", &version, false).await, (StatusCode::FORBIDDEN, "AccessDenied".to_owned()));
    assert_eq!(delete_object(&app, BUCKET, "g", None, false).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(versions(&app, "g").await, 2);
    // Not shortened or removed, but lengthened, or made COMPLIANCE.
    assert_eq!(set_retention(&app, "g", &version, "GOVERNANCE", in_days(5), false).await.0, StatusCode::FORBIDDEN);
    let removal = put_object_retention(&app, BUCKET, "g", Some(&version), b"<Retention/>", false).await.unwrap();
    assert_eq!(removal.status(), StatusCode::FORBIDDEN);
    assert_eq!(set_retention(&app, "g", &version, "GOVERNANCE", in_days(20), false).await.0, StatusCode::OK);
    // With a bypass: shortened, and deleted.
    assert_eq!(set_retention(&app, "g", &version, "GOVERNANCE", in_days(1), true).await.0, StatusCode::OK);
    assert_eq!(delete_version(&app, "g", &version, true).await.0, StatusCode::NO_CONTENT);
    assert_eq!(versions(&app, "g").await, 1);
    // A retention can also be removed with a bypass, and then there's none.
    let version = put_locked(&app, "r", retained(Mode::Governance, in_days(1))).await;
    let removal = put_object_retention(&app, BUCKET, "r", Some(&version), b"<Retention/>", true).await.unwrap();
    assert_eq!(removal.status(), StatusCode::OK);
    let (status, _, body) = text(get_object_retention(&app, BUCKET, "r", Some(&version)).await.unwrap()).await;
    assert_eq!((status, code(&body)), (StatusCode::NOT_FOUND, "NoSuchObjectLockConfiguration"));
    assert_eq!(delete_version(&app, "r", &version, false).await.0, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn compliance_mode_is_kept_from_everyone() {
    let Some(app) = node().await else { return };
    lock_bucket(&app).await;
    let version = put_locked(&app, "c", retained(Mode::Compliance, in_days(10))).await;
    assert_eq!(delete_version(&app, "c", &version, true).await, (StatusCode::FORBIDDEN, "AccessDenied".to_owned()));
    assert_eq!(set_retention(&app, "c", &version, "COMPLIANCE", in_days(5), true).await.0, StatusCode::FORBIDDEN);
    assert_eq!(set_retention(&app, "c", &version, "GOVERNANCE", in_days(30), true).await.0, StatusCode::FORBIDDEN);
    assert_eq!(set_retention(&app, "c", &version, "COMPLIANCE", in_days(30), false).await.0, StatusCode::OK);
    // Governance can become compliance, without a bypass.
    let other = put_locked(&app, "c", retained(Mode::Governance, in_days(10))).await;
    assert_eq!(set_retention(&app, "c", &other, "COMPLIANCE", in_days(10), false).await.0, StatusCode::OK);
    assert_eq!(delete_version(&app, "c", &other, true).await.0, StatusCode::FORBIDDEN);
    // Nor can the catalog be made to: the triggers refuse.
    let client = app.pool.get().await.unwrap();
    let id: i64 = client
        .query_one("SELECT id FROM objects WHERE bucket = $1 AND key = 'c' AND version_id = $2", &[&BUCKET, &version])
        .await
        .unwrap()
        .get(0);
    assert!(client.execute("DELETE FROM objects WHERE id = $1", &[&id]).await.is_err());
    assert!(client.execute("UPDATE objects SET retain_until = now() WHERE id = $1", &[&id]).await.is_err());
    assert!(client.execute("UPDATE objects SET retain_mode = 'GOVERNANCE' WHERE id = $1", &[&id]).await.is_err());
    assert_eq!(versions(&app, "c").await, 2);
    // Its retention over, it may go: once it is.
    client
        .execute("ALTER TABLE objects DISABLE TRIGGER objects_locked", &[])
        .await
        .unwrap();
    client
        .execute("UPDATE objects SET retain_until = now() - interval '1 second' WHERE id = $1", &[&id])
        .await
        .unwrap();
    client.execute("ALTER TABLE objects ENABLE TRIGGER objects_locked", &[]).await.unwrap();
    assert_eq!(delete_version(&app, "c", &version, false).await.0, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn legal_holds_keep_versions_until_lifted() {
    let Some(app) = node().await else { return };
    lock_bucket(&app).await;
    let version = put_locked(&app, "h", Lock { retention: None, legal_hold: Some(true) }).await;
    assert_eq!(head(&app, "h", None).await.get(object_lock::LEGAL_HOLD).unwrap(), "ON");
    let (status, _, body) = text(get_object_legal_hold(&app, BUCKET, "h", None).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<Status>ON</Status>"), "{body}");
    assert_eq!(delete_version(&app, "h", &version, true).await.0, StatusCode::FORBIDDEN);
    assert!(app.pool.get().await.unwrap().execute("DELETE FROM objects WHERE key = 'h'", &[]).await.is_err());
    assert_eq!(set_hold(&app, "h", Some(&version), "OFF").await, StatusCode::OK);
    assert_eq!(head(&app, "h", None).await.get(object_lock::LEGAL_HOLD).unwrap(), "OFF");
    assert_eq!(delete_version(&app, "h", &version, false).await.0, StatusCode::NO_CONTENT);
    // A version without one has none to tell; a malformed one is refused.
    let version = put_locked(&app, "n", Lock::default()).await;
    let (status, _, body) = text(get_object_legal_hold(&app, BUCKET, "n", Some(&version)).await.unwrap()).await;
    assert_eq!((status, code(&body)), (StatusCode::NOT_FOUND, "NoSuchObjectLockConfiguration"));
    let refused = put_object_legal_hold(&app, BUCKET, "n", None, b"<LegalHold><Status>on</Status></LegalHold>").await.unwrap();
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert_eq!(set_hold(&app, "missing", None, "ON").await, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn new_versions_get_the_default_retention() {
    let Some(app) = node().await else { return };
    assert_eq!(set_versioning(&app, "Enabled").await, StatusCode::OK);
    let rule = "<Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Years>1</Years></DefaultRetention></Rule>";
    assert_eq!(configure(&app, rule).await.0, StatusCode::OK);
    let version = put_locked(&app, "d", Lock::default()).await;
    let headers = head(&app, "d", Some(&version)).await;
    assert_eq!(headers.get(object_lock::MODE).unwrap(), "COMPLIANCE");
    let until = object_lock::parse_date(headers.get(object_lock::RETAIN_UNTIL).unwrap().to_str().unwrap()).unwrap();
    assert!(until > in_days(364) && until < in_days(367));
    assert_eq!(delete_version(&app, "d", &version, true).await.0, StatusCode::FORBIDDEN);
    // A write's own retention wins.
    let version = put_locked(&app, "e", retained(Mode::Governance, in_days(1))).await;
    assert_eq!(head(&app, "e", Some(&version)).await.get(object_lock::MODE).unwrap(), "GOVERNANCE");
}

#[tokio::test]
async fn delete_objects_reports_locked_versions() {
    let Some(app) = node().await else { return };
    lock_bucket(&app).await;
    let kept = put_locked(&app, "kept", retained(Mode::Governance, in_days(1))).await;
    let free = put_locked(&app, "free", Lock::default()).await;
    let body = format!(
        "<Delete><Object><Key>kept</Key><VersionId>{kept}</VersionId></Object>\
         <Object><Key>free</Key><VersionId>{free}</VersionId></Object></Delete>"
    );
    let response = delete_objects(&app, BUCKET, Bytes::from(body.clone()), &|_, _| true, &|_| false).await.unwrap();
    let (status, _, text) = text(response).await;
    assert_eq!(status, StatusCode::OK);
    assert!(text.contains(&format!("<Deleted><Key>free</Key><VersionId>{free}</VersionId></Deleted>")), "{text}");
    assert!(
        text.contains(&format!(
            "<Error><Key>kept</Key><VersionId>{kept}</VersionId><Code>AccessDenied</Code><Message>{}</Message></Error>",
            object_lock::LOCKED_MESSAGE
        )),
        "{text}"
    );
    assert_eq!(versions(&app, "kept").await, 1);
    // With a bypass, it goes.
    let response = delete_objects(&app, BUCKET, Bytes::from(body), &|_, _| true, &|_| true).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(versions(&app, "kept").await, 0);
}

#[tokio::test]
async fn uploads_and_copies_take_their_own_locks() {
    let Some(app) = node().await else { return };
    lock_bucket(&app).await;
    // An upload completes with what it asked for.
    let lock = Lock { retention: Some((Mode::Governance, in_days(3))), legal_hold: Some(true) };
    let response = create_multipart_upload(&app, BUCKET, "m", "x", "", "", Wanted::Plain, None, None, lock).await.unwrap();
    let (status, _, body) = text(response).await;
    assert_eq!(status, StatusCode::OK);
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
    let headers = head(&app, "m", None).await;
    assert_eq!(headers.get(object_lock::MODE).unwrap(), "GOVERNANCE");
    assert_eq!(headers.get(object_lock::LEGAL_HOLD).unwrap(), "ON");
    // A copy doesn't take its source's.
    let response = copy_object(&app, BUCKET, "copy", &format!("{BUCKET}/m"), None, "", "", None, &Preconditions::default(), CopyKeys::default())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let headers = head(&app, "copy", None).await;
    assert!(headers.get(object_lock::MODE).is_none() && headers.get(object_lock::LEGAL_HOLD).is_none());
    // But one of its own.
    let keys = CopyKeys { lock: retained(Mode::Compliance, in_days(2)), ..CopyKeys::default() };
    let response = copy_object(&app, BUCKET, "copy", &format!("{BUCKET}/m"), None, "", "", None, &Preconditions::default(), keys)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(head(&app, "copy", None).await.get(object_lock::MODE).unwrap(), "COMPLIANCE");
}

#[tokio::test]
async fn deleted_markers_and_missing_versions_have_no_lock() {
    let Some(app) = node().await else { return };
    lock_bucket(&app).await;
    put_locked(&app, "k", Lock::default()).await;
    let (status, _, body) = text(get_object_retention(&app, BUCKET, "k", None).await.unwrap()).await;
    assert_eq!((status, code(&body)), (StatusCode::NOT_FOUND, "NoSuchObjectLockConfiguration"));
    let (status, _, body) = text(get_object_retention(&app, BUCKET, "nope", None).await.unwrap()).await;
    assert_eq!((status, code(&body)), (StatusCode::NOT_FOUND, "NoSuchKey"));
    assert_eq!(delete_object(&app, BUCKET, "k", None, false).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(set_hold(&app, "k", None, "ON").await, StatusCode::METHOD_NOT_ALLOWED);
    // A retention must lie ahead.
    let past = put_object_retention(
        &app,
        BUCKET,
        "nope",
        None,
        format!("<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>{}</RetainUntilDate></Retention>", iso(SystemTime::now() - DAY)).as_bytes(),
        false,
    )
    .await
    .unwrap();
    let (status, _, body) = text(past).await;
    assert_eq!((status, code(&body)), (StatusCode::BAD_REQUEST, "InvalidArgument"));
}
