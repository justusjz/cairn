//! MFA delete (see `mfa`), against a real Postgres: the root's virtual MFA
//! device, as `cairn account root-mfa` makes it; whose `x-amz-mfa` is a
//! valid code (the root's, of its device, over HTTPS); and what a bucket
//! with MFA delete refuses without one: deleting versions, changing its
//! versioning, and a lifecycle configuration.

use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::{HeaderMap, StatusCode, body::Bytes};

use super::{BUCKET, node_with, put};
use crate::{
    App,
    admin::e2e::cairn,
    mfa::{self, Presented},
    packer,
    s3::{
        buckets::{
            lifecycle::{delete_bucket_lifecycle, put_bucket_lifecycle},
            versioning::{get_bucket_versioning, put_bucket_versioning},
        },
        objects::delete::{delete_object, delete_objects},
    },
    users::{self, Principal},
};

const LIFECYCLE: &str = "<LifecycleConfiguration><Rule><ID>r</ID><Filter/><Status>Enabled</Status>\
     <Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule></LifecycleConfiguration>";

async fn text(response: hyper::Response<http_body_util::Full<Bytes>>) -> (StatusCode, String) {
    let status = response.status();
    (status, String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap())
}

/// The root user, as `cairn account root-key`'s credentials authenticate.
async fn root(app: &Arc<App>) -> Principal {
    let out = cairn(app, &["account", "root-key"]).await;
    let var = |name: &str| {
        let prefix = format!("export {name}=");
        out.stdout.lines().find_map(|l| l.strip_prefix(&prefix)).unwrap().to_owned()
    };
    let client = app.pool.get().await.unwrap();
    let token = var("AWS_SESSION_TOKEN");
    Principal::authenticate(&client, &app.sessions, &var("AWS_ACCESS_KEY_ID"), Some(&token)).await.unwrap().unwrap()
}

/// A request's headers with `x-amz-mfa: value`, over HTTPS (as a proxy
/// says) or not.
fn headers(value: &str, https: bool) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(mfa::HEADER, value.parse().unwrap());
    if https {
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
    }
    headers
}

/// What `x-amz-mfa` (in `headers`) comes to for `principal`.
async fn presented(
    app: &Arc<App>,
    principal: &Principal,
    headers: HeaderMap,
) -> Result<Presented, hyper::Response<http_body_util::Full<Bytes>>> {
    mfa::presented(app, Some(principal), &headers).await.unwrap()
}

/// The root's device's current code.
async fn code(app: &App, account: &str) -> String {
    let client = app.pool.get().await.unwrap();
    let secret: Vec<u8> =
        client.query_one("SELECT secret FROM root_mfa_devices WHERE account_id = $1", &[&account]).await.unwrap().get(0);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    mfa::code(&secret, now)
}

async fn versioning(app: &App, body: &str, mfa: Presented) -> (StatusCode, String) {
    let body = format!("<VersioningConfiguration>{body}</VersioningConfiguration>");
    text(put_bucket_versioning(app, BUCKET, Bytes::from(body), mfa).await.unwrap()).await
}

/// The version IDs of `key`, oldest first.
async fn versions(app: &App, key: &str) -> Vec<String> {
    let client = app.pool.get().await.unwrap();
    let rows = client
        .query("SELECT version_id FROM objects WHERE bucket = $1 AND key = $2 ORDER BY id", &[&BUCKET, &key])
        .await
        .unwrap();
    rows.iter().map(|r| r.get(0)).collect()
}

/// DeleteObjects of `entries` (a key, and a version ID or none).
async fn delete_batch(app: &Arc<App>, entries: &[(&str, Option<&str>)], mfa: Presented) -> (StatusCode, String) {
    let objects: String = entries
        .iter()
        .map(|(key, version)| match version {
            Some(v) => format!("<Object><Key>{key}</Key><VersionId>{v}</VersionId></Object>"),
            None => format!("<Object><Key>{key}</Key></Object>"),
        })
        .collect();
    let body = Bytes::from(format!("<Delete>{objects}</Delete>"));
    text(delete_objects(app, BUCKET, body, &|_, _| true, &|_| false, mfa).await.unwrap()).await
}

#[tokio::test]
async fn the_root_makes_its_device_on_a_node() {
    let Some(app) = node_with(packer::Config::default(), None).await else { return };
    let account = users::account(&app.pool.get().await.unwrap()).await.unwrap();
    let serial = mfa::serial(&account);
    assert_eq!(serial, format!("arn:aws:iam::{account}:mfa/root-account-mfa-device"));

    let out = cairn(&app, &["account", "root-mfa"]).await;
    assert_eq!(out.error, None);
    assert!(out.stdout.contains(&format!("\nserial: {serial}\n")), "{}", out.stdout);
    let secret = out.stdout.lines().find_map(|l| l.strip_prefix("secret: ")).unwrap().to_owned();
    assert_eq!(secret.len(), 32, "20 bytes, in base32: {secret}");
    assert!(out.stdout.contains(&format!("otpauth://totp/Cairn:root%40{account}?secret={secret}&issuer=Cairn")));
    assert!(out.stderr.contains("isn't shown again"), "{}", out.stderr);

    // Not again, unless it's to replace it.
    let again = cairn(&app, &["account", "root-mfa"]).await;
    assert!(again.error.unwrap().contains("--replace"));
    let replaced = cairn(&app, &["account", "root-mfa", "--replace"]).await;
    assert_eq!(replaced.error, None);
    let new = replaced.stdout.lines().find_map(|l| l.strip_prefix("secret: ")).unwrap();
    assert_ne!(new, secret);
}

#[tokio::test]
async fn only_the_roots_code_is_valid_and_only_over_https() {
    let Some(app) = node_with(packer::Config::default(), None).await else { return };
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let serial = mfa::serial(&account);
    let root = root(&app).await;
    // Nothing to check without the header.
    assert_eq!(presented(&app, &root, HeaderMap::new()).await.unwrap(), Presented::Absent);
    // No device yet: no code is valid.
    assert_eq!(presented(&app, &root, headers(&format!("{serial} 123456"), true)).await.unwrap(), Presented::Invalid);

    assert_eq!(cairn(&app, &["account", "root-mfa"]).await.error, None);
    let valid = format!("{serial} {}", code(&app, &account).await);
    assert_eq!(presented(&app, &root, headers(&valid, true)).await.unwrap(), Presented::Valid);
    // Percent-encoded, as AWS's docs say signed headers with spaces are.
    assert_eq!(presented(&app, &root, headers(&valid.replace(' ', "%20"), true)).await.unwrap(), Presented::Valid);

    // Over plain HTTP, refused whatever it holds.
    let (status, body) = text(presented(&app, &root, headers(&valid, false)).await.unwrap_err()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("<Code>InvalidRequest</Code>"), "{body}");

    // Another code, another serial number, or nonsense.
    let wrong = if code(&app, &account).await == "000000" { "111111" } else { "000000" };
    for value in [format!("{serial} {wrong}"), format!("arn:aws:iam::{account}:mfa/ada {}", code(&app, &account).await), "nonsense".to_owned()] {
        assert_eq!(presented(&app, &root, headers(&value, true)).await.unwrap(), Presented::Invalid, "{value}");
    }

    // An admin's request with the root's code: only the root's is the root's.
    users::create(&client, "boss", None, true).await.unwrap();
    let boss = Principal::load_user(&client, users::id_of(&client, &account, "boss").await.unwrap()).await.unwrap().unwrap();
    assert!(boss.admin);
    assert_eq!(presented(&app, &boss, headers(&valid, true)).await.unwrap(), Presented::Invalid);
}

#[tokio::test]
async fn mfa_delete_wants_the_roots_code() {
    let Some(app) = node_with(packer::Config::default(), None).await else { return };
    let (status, _) = versioning(&app, "<Status>Enabled</Status>", Presented::Absent).await;
    assert_eq!(status, StatusCode::OK);
    put(&app, "k", b"one".to_vec()).await;
    put(&app, "k", b"two".to_vec()).await;
    let [first, second] = <[String; 2]>::try_from(versions(&app, "k").await).unwrap();

    // Never configured: not reported. Disabled, by anyone: reported.
    let (_, got) = text(get_bucket_versioning(&app, BUCKET).await.unwrap()).await;
    assert!(got.ends_with("<Status>Enabled</Status></VersioningConfiguration>"), "{got}");
    assert_eq!(versioning(&app, "<MfaDelete>Disabled</MfaDelete>", Presented::Absent).await.0, StatusCode::OK);
    let (_, got) = text(get_bucket_versioning(&app, BUCKET).await.unwrap()).await;
    assert!(got.ends_with("<Status>Enabled</Status><MfaDelete>Disabled</MfaDelete></VersioningConfiguration>"), "{got}");

    // Enabling it takes the root's code, and a Status.
    let enable = "<Status>Enabled</Status><MfaDelete>Enabled</MfaDelete>";
    for mfa in [Presented::Absent, Presented::Invalid] {
        let (status, body) = versioning(&app, enable, mfa).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{mfa:?}");
        assert!(body.contains("<Code>AccessDenied</Code><Message>Mfa Authentication must be used for this request"), "{body}");
    }
    assert_eq!(versioning(&app, "<MfaDelete>Enabled</MfaDelete>", Presented::Valid).await.0, StatusCode::BAD_REQUEST);
    // Not on a bucket with a lifecycle configuration, which it can't have.
    assert_eq!(put_bucket_lifecycle(&app, BUCKET, Bytes::from(LIFECYCLE), None).await.unwrap().status(), StatusCode::OK);
    let (status, body) = versioning(&app, enable, Presented::Valid).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body.contains("<Code>InvalidBucketState</Code>"), "{body}");
    assert_eq!(delete_bucket_lifecycle(&app, BUCKET).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(versioning(&app, enable, Presented::Valid).await.0, StatusCode::OK);
    let (_, got) = text(get_bucket_versioning(&app, BUCKET).await.unwrap()).await;
    assert!(got.ends_with("<Status>Enabled</Status><MfaDelete>Enabled</MfaDelete></VersioningConfiguration>"), "{got}");
    let (status, body) = text(put_bucket_lifecycle(&app, BUCKET, Bytes::from(LIFECYCLE), None).await.unwrap()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body.contains("<Code>InvalidBucketState</Code>"), "{body}");

    // A version is deleted only with the code; a delete marker is made
    // without one, but not with one that isn't valid.
    let delete = |version: Option<String>, mfa| {
        let app = app.clone();
        async move { text(delete_object(&app, BUCKET, "k", version.as_deref(), false, None, mfa).await.unwrap()).await }
    };
    for mfa in [Presented::Absent, Presented::Invalid] {
        let (status, body) = delete(Some(first.clone()), mfa).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.contains("Mfa Authentication must be used"), "{body}");
    }
    assert_eq!(versions(&app, "k").await, [first.clone(), second.clone()]);
    assert_eq!(delete(Some(first.clone()), Presented::Valid).await.0, StatusCode::NO_CONTENT);
    assert_eq!(versions(&app, "k").await, std::slice::from_ref(&second));
    assert_eq!(delete(None, Presented::Invalid).await.0, StatusCode::FORBIDDEN);
    assert_eq!(delete(None, Presented::Absent).await.0, StatusCode::NO_CONTENT);
    let [_, marker] = <[String; 2]>::try_from(versions(&app, "k").await).unwrap();

    // DeleteObjects fails whole: without the code if it names a version,
    // with one that isn't valid whatever it names.
    put(&app, "other", b"o".to_vec()).await;
    let (status, body) = delete_batch(&app, &[("other", None), ("k", Some(&second))], Presented::Absent).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("Mfa Authentication must be used"), "{body}");
    assert_eq!(delete_batch(&app, &[("other", None)], Presented::Invalid).await.0, StatusCode::FORBIDDEN);
    assert_eq!(versions(&app, "other").await.len(), 1, "nothing was deleted");
    assert_eq!(versions(&app, "k").await, [second.clone(), marker.clone()]);
    let (status, body) = delete_batch(&app, &[("other", None)], Presented::Absent).await;
    assert_eq!((status, body.contains("<DeleteMarker>true</DeleteMarker>")), (StatusCode::OK, true), "{body}");
    let (status, body) = delete_batch(&app, &[("k", Some(&marker))], Presented::Valid).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(&format!("<Deleted><Key>k</Key><VersionId>{marker}</VersionId>")), "{body}");
    assert_eq!(versions(&app, "k").await, std::slice::from_ref(&second));

    // Its versioning changes only with the code; so does MFA delete.
    assert_eq!(versioning(&app, "<Status>Suspended</Status>", Presented::Absent).await.0, StatusCode::FORBIDDEN);
    assert_eq!(versioning(&app, "<Status>Enabled</Status>", Presented::Absent).await.0, StatusCode::FORBIDDEN);
    let disable = "<Status>Enabled</Status><MfaDelete>Disabled</MfaDelete>";
    assert_eq!(versioning(&app, disable, Presented::Absent).await.0, StatusCode::FORBIDDEN);
    assert_eq!(versioning(&app, disable, Presented::Valid).await.0, StatusCode::OK);
    let (_, got) = text(get_bucket_versioning(&app, BUCKET).await.unwrap()).await;
    assert!(got.ends_with("<MfaDelete>Disabled</MfaDelete></VersioningConfiguration>"), "{got}");

    // Then as before: versions are deleted, and lifecycle configured,
    // without it.
    assert_eq!(delete(Some(second.clone()), Presented::Absent).await.0, StatusCode::NO_CONTENT);
    assert!(versions(&app, "k").await.is_empty());
    assert_eq!(put_bucket_lifecycle(&app, BUCKET, Bytes::from(LIFECYCLE), None).await.unwrap().status(), StatusCode::OK);
}
