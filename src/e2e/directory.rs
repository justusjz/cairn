//! Directory buckets (see `s3::directory`), against a real Postgres: who
//! may make their zonal and regional operations, and what their sessions
//! are good for.

use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::{HeaderMap, Method, StatusCode};

use super::node_with;
use crate::{
    App, packer,
    s3::{access, actions, buckets::create, directory},
    users::{Principal, Unknown},
};

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

async fn account(app: &App) -> String {
    crate::users::account(&app.pool.get().await.unwrap()).await.unwrap()
}

/// A new directory bucket of the account's, with a fresh name.
async fn directory_bucket(app: &App) -> String {
    let bucket = format!("d{}--use1-az4--x-s3", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    assert!(matches!(create::create_directory(app, &bucket, &account(app).await).await.unwrap(), create::Creation::Created));
    bucket
}

/// A user named `name` (unique), with the identity policy `statements`
/// (none, if empty).
async fn user(app: &App, name: &str, statements: &str) -> Principal {
    let client = app.pool.get().await.unwrap();
    let account = crate::users::account(&client).await.unwrap();
    let name = format!("{name}-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let (key, _) = crate::users::create_for(&client, &account, &name, None, false).await.unwrap();
    if !statements.is_empty() {
        let policy = format!(r#"{{"Version":"2012-10-17","Statement":[{statements}]}}"#);
        crate::users::put_policy(&client, &account, &name, "p", &policy).await.unwrap();
    }
    Principal::load(&client, &key).await.unwrap().unwrap()
}

/// A statement allowing `action` on `resource`, if `condition` (if any).
fn allow(action: &str, resource: &str, condition: &str) -> String {
    let condition = match condition {
        "" => String::new(),
        condition => format!(r#","Condition":{condition}"#),
    };
    format!(r#"{{"Effect":"Allow","Action":"{action}","Resource":"{resource}"{condition}}}"#)
}

const READ_ONLY: &str = r#"{"StringEquals":{"s3express:SessionMode":"ReadOnly"}}"#;

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        headers.insert(hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(), value.parse().unwrap());
    }
    headers
}

/// Whether `principal` may make the request (`method`, `key`, `query`,
/// `headers`) on `bucket`, without a session, as `s3::handle_request`
/// decides it.
async fn may(app: &App, principal: &Principal, method: Method, bucket: &str, key: &str, query: &str, headers: &HeaderMap) -> bool {
    let account = account(app).await;
    let origin = access::Origin { peer: None, trusted_proxies: &[], signed: None, form: false };
    let mut access = access::Access::new(Some(principal), &account, &method, headers, query, &origin).unwrap();
    let mut operation = actions::operation(&method, bucket, key, query, headers).unwrap();
    match directory::is_directory(bucket) {
        true => {
            if directory::prepare(&mut operation, bucket, &account, query, headers).unwrap() == directory::Kind::Writes {
                access.writes(bucket);
            }
        }
        false => operation.checks = operation.checks.into_iter().map(|c| directory::source_check(c, &account)).collect(),
    }
    access.load(app, bucket).await.unwrap();
    access.load_all(app, &operation.checks).await.unwrap();
    access.first_denied(&operation.checks).is_none()
}

/// The credentials (access key ID, secret, token) of a CreateSession by
/// `principal` of `bucket`, in `mode` (the default, if `None`); or its
/// refusal's status.
async fn create_session(app: &App, principal: &Principal, bucket: &str, mode: Option<&str>) -> Result<(String, String, String), StatusCode> {
    let account = account(app).await;
    let headers = headers(&mode.map(|m| ("x-amz-create-session-mode", m)).into_iter().collect::<Vec<_>>());
    let origin = access::Origin { peer: None, trusted_proxies: &[], signed: None, form: false };
    let mut access = access::Access::new(Some(principal), &account, &Method::GET, &headers, "session", &origin).unwrap();
    let response = directory::create_session(app, Some(principal), &mut access, bucket, &account, &headers).await.unwrap();
    if response.status() != StatusCode::OK {
        return Err(response.status());
    }
    let body = String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    let field = |name: &str| body.split(&format!("<{name}>")).nth(1).unwrap().split("</").next().unwrap().to_owned();
    Ok((field("AccessKeyId"), field("SecretAccessKey"), field("SessionToken")))
}

/// A zonal operation needs `s3express:CreateSession` on its bucket: to
/// write, in `ReadWrite` mode; to read, in either. `s3:` actions don't
/// grant it. A regional operation needs its own action, which only identity
/// policies grant; a bucket policy grants sessions only.
#[tokio::test]
async fn directory_operations_take_s3express_actions() {
    let Some(app) = node().await else { return };
    let bucket = directory_bucket(&app).await;
    let account = account(&app).await;
    let arn = directory::arn(&account, &bucket);
    let none = HeaderMap::new();

    let rw = user(&app, "rw", &allow("s3express:CreateSession", &arn, "")).await;
    let ro = user(&app, "ro", &allow("s3express:CreateSession", &arn, READ_ONLY)).await;
    let s3 = user(&app, "s3", &allow("s3:*", "*", "")).await;
    let regional = user(&app, "regional", &allow("s3express:PutBucketPolicy", &arn, "")).await;
    let reads = |p| may(&app, p, Method::GET, &bucket, "k", "", &none);
    assert!(reads(&rw).await);
    assert!(reads(&ro).await);
    assert!(!reads(&s3).await);
    assert!(!reads(&regional).await);
    let writes = |p| may(&app, p, Method::PUT, &bucket, "k", "", &none);
    assert!(writes(&rw).await);
    assert!(!writes(&ro).await);
    assert!(!writes(&s3).await);
    assert!(may(&app, &ro, Method::GET, &bucket, "", "list-type=2", &none).await);
    assert!(!may(&app, &ro, Method::POST, &bucket, "", "delete", &none).await);
    // Regional: its own action, not a session's.
    assert!(may(&app, &regional, Method::PUT, &bucket, "", "policy", &none).await);
    assert!(!may(&app, &rw, Method::PUT, &bucket, "", "policy", &none).await);
    assert!(!may(&app, &rw, Method::DELETE, &bucket, "", "", &none).await);

    // The bucket's policy grants sessions, but not regional operations.
    let other = user(&app, "other", "").await;
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{}"}},
            "Action":["s3express:CreateSession","s3express:PutBucketPolicy"],"Resource":"{arn}"}}]}}"#,
        other.arn()
    );
    let response = crate::s3::buckets::policy::put_bucket_policy(&app, &bucket, policy.into()).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(writes(&other).await);
    assert!(!may(&app, &other, Method::PUT, &bucket, "", "policy", &none).await);

    // A copy from it to a general purpose bucket reads it as a session
    // would, and a copy into it from one reads that as S3 does.
    let general = format!("g{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    assert!(matches!(create::create(&app, &general, &account, false).await.unwrap(), create::Creation::Created));
    let copier = user(
        &app,
        "copier",
        &[
            allow("s3express:CreateSession", &arn, READ_ONLY),
            allow("s3:PutObject", &format!("arn:aws:s3:::{general}/*"), ""),
        ]
        .join(","),
    )
    .await;
    let from_directory = headers(&[("x-amz-copy-source", &format!("/{bucket}/k"))]);
    assert!(may(&app, &copier, Method::PUT, &general, "k", "", &from_directory).await);
    let from_general = headers(&[("x-amz-copy-source", &format!("/{general}/k"))]);
    assert!(!may(&app, &copier, Method::PUT, &bucket, "k", "", &from_general).await);
    assert!(may(&app, &s3, Method::GET, &general, "k", "", &none).await);
}

/// What a directory bucket doesn't have is refused, whoever asks.
#[tokio::test]
async fn directory_buckets_refuse_what_they_dont_have() {
    let Some(app) = node().await else { return };
    let bucket = directory_bucket(&app).await;
    let account = account(&app).await;
    let refused = |method: Method, key: &str, query: &str, pairs: &[(&str, &str)]| {
        let headers = headers(pairs);
        let mut operation = actions::operation(&method, &bucket, key, query, &headers).unwrap();
        directory::prepare(&mut operation, &bucket, &account, query, &headers).err().map(|r| r.status())
    };
    let not_implemented = Some(StatusCode::NOT_IMPLEMENTED);
    assert_eq!(refused(Method::GET, "", "versioning", &[]), not_implemented);
    assert_eq!(refused(Method::GET, "", "", &[]), not_implemented);
    assert_eq!(refused(Method::GET, "", "versions", &[]), not_implemented);
    assert_eq!(refused(Method::PUT, "", "cors", &[]), not_implemented);
    assert_eq!(refused(Method::GET, "k", "tagging", &[]), not_implemented);
    assert_eq!(refused(Method::PUT, "k", "", &[("x-amz-tagging", "a=b")]), not_implemented);
    assert_eq!(refused(Method::PUT, "k", "", &[("x-amz-object-lock-legal-hold", "ON")]), not_implemented);
    assert_eq!(refused(Method::PUT, "k", "", &[("x-amz-server-side-encryption-customer-algorithm", "AES256")]), not_implemented);
    assert_eq!(refused(Method::PUT, "k", "", &[("x-amz-write-offset-bytes", "0")]), not_implemented);
    assert_eq!(refused(Method::PUT, "k", "", &[("content-md5", "1B2M2Y8AsgTpgAmY7PhCfg==")]), not_implemented);
    assert_eq!(refused(Method::PUT, "k", "", &[("x-amz-storage-class", "STANDARD")]), Some(StatusCode::BAD_REQUEST));
    assert_eq!(refused(Method::GET, "", "list-type=2&prefix=a", &[]), Some(StatusCode::BAD_REQUEST));
    assert_eq!(refused(Method::PUT, "k", "", &[("x-amz-storage-class", "EXPRESS_ONEZONE")]), None);
    assert_eq!(refused(Method::GET, "", "list-type=2&prefix=a%2F&delimiter=%2F", &[]), None);
    assert_eq!(refused(Method::PUT, "", "encryption", &[]), None);
    // The console doesn't manage them, nor does its bucket creation make
    // them.
    assert!(matches!(create::create(&app, "c--use1-az4--x-s3", &account, false).await.unwrap(), create::Creation::InvalidName));
    assert!(matches!(create::create_directory(&app, "plain", &account).await.unwrap(), create::Creation::InvalidName));
}

/// A session is good for its own bucket's zonal operations, in its mode,
/// and nothing else: its token isn't an STS session's. Its principal is
/// known from its token alone, without the database; with it, as its
/// credentials' principal, with its policies.
#[tokio::test]
async fn sessions_are_their_bucket_s() {
    let Some(app) = node().await else { return };
    let bucket = directory_bucket(&app).await;
    let account = account(&app).await;
    let arn = directory::arn(&account, &bucket);
    let ro = user(&app, "ro", &allow("s3express:CreateSession", &arn, READ_ONLY)).await;
    assert_eq!(create_session(&app, &ro, &bucket, None).await.unwrap_err(), StatusCode::FORBIDDEN);
    assert_eq!(create_session(&app, &ro, &bucket, Some("ReadWrite")).await.unwrap_err(), StatusCode::FORBIDDEN);
    assert_eq!(create_session(&app, &ro, &bucket, Some("Everything")).await.unwrap_err(), StatusCode::BAD_REQUEST);
    let (key, secret, token) = create_session(&app, &ro, &bucket, Some("ReadOnly")).await.unwrap();
    assert!(crate::sessions::is_temporary(&key));

    let client = app.pool.get().await.unwrap();
    let session = app.sessions.open(&client, &token).await.unwrap().unwrap();
    assert_eq!(session.secret, secret);
    assert!(session.expires <= crate::sessions::now() + directory::SESSION_SECONDS);
    let of = session.directory.as_ref().unwrap();
    assert_eq!((of.bucket.as_str(), of.read_only, of.unauthorized), (bucket.as_str(), true, false));

    // Not as an STS session's token.
    let as_sts = Principal::authenticate(&client, &app.sessions, &key, Some(&token)).await.unwrap();
    assert_eq!(as_sts.err(), Some(Unknown::Token));
    // As its own, for its bucket only.
    let signed = |key: &str| crate::auth::Signed {
        access_key: key.to_owned(),
        service: "s3express".to_owned(),
        region: "us-east-1".to_owned(),
        presigned: false,
        date: None,
        token: None,
        directory_token: Some(token.clone()),
        sigv2: false,
    };
    let principal = directory::authenticate(&app.sessions, &client, &signed(&key), &token, &bucket).await.unwrap().unwrap();
    assert_eq!((principal.arn(), principal.id, principal.secret.as_str()), (ro.arn(), ro.id, secret.as_str()));
    assert!(principal.policies.is_empty());
    let elsewhere = directory::authenticate(&app.sessions, &client, &signed(&key), &token, "other--use1-az4--x-s3").await.unwrap();
    assert_eq!(elsewhere.err().map(|r| r.status()), Some(StatusCode::FORBIDDEN));
    let another = directory::authenticate(&app.sessions, &client, &signed("ASIAAAAAAAAAAAAAAAAA"), &token, &bucket).await.unwrap();
    assert_eq!(another.err().map(|r| r.status()), Some(StatusCode::FORBIDDEN));
    // Its principal as its credentials make it.
    let full = Principal::of_session(&client, principal.session.unwrap().session).await.unwrap().unwrap();
    assert_eq!((full.arn(), full.policies.len()), (ro.arn(), 1));

    // Of a bucket that isn't there yet (as SDKs make one before
    // CreateBucket): its requests are authorized as if it were none.
    let nobody = user(&app, "nobody", "").await;
    assert_eq!(create_session(&app, &nobody, &bucket, None).await.unwrap_err(), StatusCode::FORBIDDEN);
    let (_, _, token) = create_session(&app, &nobody, "new--use1-az4--x-s3", None).await.unwrap();
    let session = app.sessions.open(&client, &token).await.unwrap().unwrap();
    assert!(session.directory.unwrap().unauthorized);
    // Not with a session's own credentials.
    let (key, _, token) = create_session(&app, &ro, &bucket, Some("ReadOnly")).await.unwrap();
    let principal = directory::authenticate(&app.sessions, &client, &signed(&key), &token, &bucket).await.unwrap().unwrap();
    assert_eq!(create_session(&app, &principal, &bucket, Some("ReadOnly")).await.unwrap_err(), StatusCode::FORBIDDEN);
}
