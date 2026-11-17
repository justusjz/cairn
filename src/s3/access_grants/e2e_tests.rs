//! S3 Access Grants against a real Postgres: what's kept and refused, and
//! what the sessions GetDataAccess vends may do.

use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::{HeaderMap, Method, StatusCode, body::Bytes};

use super::*;
use crate::{
    e2e::node_with,
    packer, roles,
    s3::access::{Access, Origin},
    users::{self, Principal},
};

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

async fn account(app: &App) -> String {
    users::account(&app.pool.get().await.unwrap()).await.unwrap()
}

/// A user named `name` (made unique), with the identity policy
/// `statements` (none, if empty).
async fn user(app: &App, name: &str, statements: &str) -> Principal {
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let name = format!("{name}-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let (key, _) = users::create_for(&client, &account, &name, None, false).await.unwrap();
    if !statements.is_empty() {
        let policy = format!(r#"{{"Version":"2012-10-17","Statement":[{statements}]}}"#);
        users::put_policy(&client, &account, &name, "p", &policy).await.unwrap();
    }
    Principal::load(&client, &key).await.unwrap().unwrap()
}

const ADMIN: &str = r#"{"Effect":"Allow","Action":"*","Resource":"*"}"#;
const DATA_ACCESS: &str = r#"{"Effect":"Allow","Action":["s3:GetDataAccess","s3:ListCallerAccessGrants"],"Resource":"*"}"#;

/// A role trusting `trust`'s statement, allowed `allowed` (S3 actions).
async fn role(app: &App, trust: &str, allowed: &str) -> roles::Role {
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let trust = format!(r#"{{"Version":"2012-10-17","Statement":[{trust}]}}"#);
    let trust = roles::check_trust(&client, &account, &trust).await.unwrap();
    let name = format!("ag-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let new = roles::New { name: &name, path: "/", trust: &trust, description: "", max_session_duration: 3600, boundary: None, tags: &[] };
    let id = roles::create(&client, &account, &new).await.unwrap();
    let role = roles::Role::load_id(&client, id).await.unwrap().unwrap();
    let policy = format!(r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"{allowed}","Resource":"*"}}]}}"#);
    roles::put_policy(&client, &role, "s3", &policy).await.unwrap();
    role
}

fn trusting_access_grants(condition: &str) -> String {
    let condition = match condition {
        "" => String::new(),
        c => format!(r#","Condition":{c}"#),
    };
    format!(r#"{{"Effect":"Allow","Principal":{{"Service":"{SERVICE}"}},"Action":"sts:AssumeRole"{condition}}}"#)
}

/// What `principal` was answered for `op` on its own account's instance:
/// its status, and its body.
async fn call(app: &App, principal: &Principal, op: Op, query: &str, body: &str) -> (StatusCode, String) {
    let account = principal.account.clone();
    call_in(app, principal, &account, op, query, body).await
}

/// What `principal` was answered for `op` on `account`'s instance (another
/// account's, if it's not its own).
async fn call_in(app: &App, principal: &Principal, account: &str, op: Op, query: &str, body: &str) -> (StatusCode, String) {
    let origin = Origin { peer: None, trusted_proxies: &[], signed: None, form: false };
    let mut access = Access::new(Some(principal), &principal.account, &Method::GET, &HeaderMap::new(), query, &origin).unwrap();
    let body = (!body.is_empty()).then(|| Bytes::from(body.to_owned()));
    let response = answer(app, op, principal, account, &mut access, query, body).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

fn field(xml: &str, name: &str) -> String {
    let start = xml.find(&format!("<{name}>")).unwrap_or_else(|| panic!("no {name} in {xml}")) + name.len() + 2;
    let end = xml[start..].find(&format!("</{name}>")).unwrap() + start;
    xml[start..end].replace("&amp;", "&")
}

fn code(xml: &str) -> String {
    field(xml, "Code")
}

fn location(scope: &str, role: &str) -> String {
    format!("<CreateAccessGrantsLocationRequest><LocationScope>{scope}</LocationScope><IAMRoleArn>{role}</IAMRoleArn></CreateAccessGrantsLocationRequest>")
}

fn grant(location: &str, sub: Option<&str>, grantee: &str, permission: &str, object: bool) -> String {
    let sub = sub.map_or(String::new(), |s| format!("<AccessGrantsLocationConfiguration><S3SubPrefix>{s}</S3SubPrefix></AccessGrantsLocationConfiguration>"));
    let object = if object { "<S3PrefixType>Object</S3PrefixType>" } else { "" };
    format!(
        "<CreateAccessGrantRequest><AccessGrantsLocationId>{location}</AccessGrantsLocationId>{sub}\
         <Grantee><GranteeType>IAM</GranteeType><GranteeIdentifier>{grantee}</GranteeIdentifier></Grantee>\
         <Permission>{permission}</Permission>{object}</CreateAccessGrantRequest>"
    )
}

/// The principal of a vended session's credentials (`GetDataAccessResult`).
async fn session_of(app: &App, xml: &str) -> Principal {
    let client = app.pool.get().await.unwrap();
    let key = field(xml, "AccessKeyId");
    let token = field(xml, "SessionToken");
    Principal::authenticate(&client, &app.sessions, &key, Some(&token)).await.unwrap().unwrap()
}

/// Whether `principal` may take `action` on `on`, as a request would.
async fn may(app: &App, principal: &Principal, action: &'static str, on: On, prefix: Option<&str>) -> bool {
    let account = account(app).await;
    let query = prefix.map_or(String::new(), |p| format!("prefix={p}"));
    let origin = Origin { peer: None, trusted_proxies: &[], signed: None, form: false };
    let mut access = Access::new(Some(principal), &account, &Method::GET, &HeaderMap::new(), &query, &origin).unwrap();
    let check = Check { action, on };
    access.load_all(app, std::slice::from_ref(&check)).await.unwrap();
    if let Some(bucket) = check.on.bucket() {
        access.load(app, bucket).await.unwrap();
    }
    access.allows(&check)
}

fn object(bucket: &str, key: &str) -> On {
    On::Object(bucket.to_owned(), key.to_owned())
}

/// An instance, its locations and grants: kept, listed, and deleted in
/// order, as S3 does it.
#[tokio::test]
async fn instances_locations_and_grants_keep_each_other() {
    let Some(app) = node().await else { return };
    let admin = user(&app, "admin", ADMIN).await;
    let alice = user(&app, "alice", DATA_ACCESS).await;
    let role = role(&app, &trusting_access_grants(""), "s3:*").await;
    let account = account(&app).await;

    // Nothing before an instance.
    let (status, xml) = call(&app, &admin, Op::CreateLocation, "", &location("s3://", &role.arn())).await;
    assert_eq!((status, code(&xml)), (StatusCode::NOT_FOUND, "AccessGrantsInstanceNotExistsError".into()));
    let (status, xml) = call(&app, &admin, Op::ListInstances, "", "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!xml.contains("<AccessGrantsInstance>"), "{xml}");

    let (status, xml) = call(&app, &admin, Op::CreateInstance, "", "").await;
    assert_eq!(status, StatusCode::OK, "{xml}");
    assert_eq!(field(&xml, "AccessGrantsInstanceArn"), instance_arn(&account));
    let (status, xml) = call(&app, &admin, Op::CreateInstance, "", "").await;
    assert_eq!((status, code(&xml)), (StatusCode::CONFLICT, "AccessGrantsInstanceAlreadyExists".into()));

    // `s3://` is `default`; another scope gets an ID of its own, once.
    let (status, xml) = call(&app, &admin, Op::CreateLocation, "", &location("s3://", &role.arn())).await;
    assert_eq!(status, StatusCode::OK, "{xml}");
    assert_eq!(field(&xml, "AccessGrantsLocationId"), "default");
    let (_, xml) = call(&app, &admin, Op::CreateLocation, "", &location("s3://data/logs/", &role.arn())).await;
    let logs = field(&xml, "AccessGrantsLocationId");
    assert_ne!(logs, "default");
    let (status, xml) = call(&app, &admin, Op::CreateLocation, "", &location("s3://data/logs/", &role.arn())).await;
    assert_eq!((status, code(&xml)), (StatusCode::CONFLICT, "AccessGrantsLocationAlreadyExistsError".into()));
    for bad in ["data/", "s3://data/*"] {
        let (status, xml) = call(&app, &admin, Op::CreateLocation, "", &location(bad, &role.arn())).await;
        assert_eq!((status, code(&xml)), (StatusCode::BAD_REQUEST, "InvalidRequest".into()), "{bad}");
    }
    let nobody = format!("arn:aws:iam::{account}:role/nobody");
    let (status, _) = call(&app, &admin, Op::CreateLocation, "", &location("s3://other/", &nobody)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Grants: to an IAM user or role of the account only, once each.
    let body = grant("default", Some("data/logs/*"), &alice.arn(), "READ", false);
    let (status, xml) = call(&app, &admin, Op::CreateGrant, "", &body).await;
    assert_eq!(status, StatusCode::OK, "{xml}");
    assert_eq!(field(&xml, "GrantScope"), "s3://data/logs/*");
    let id = field(&xml, "AccessGrantId");
    let (status, xml) = call(&app, &admin, Op::CreateGrant, "", &body).await;
    assert_eq!((status, code(&xml)), (StatusCode::CONFLICT, "AccessGrantAlreadyExists".into()));
    let (_, xml) = call(&app, &admin, Op::CreateGrant, "", &grant(&logs, None, &alice.arn(), "WRITE", false)).await;
    assert_eq!(field(&xml, "GrantScope"), "s3://data/logs/*");
    let ghost = format!("arn:aws:iam::{account}:user/ghost");
    let (status, _) = call(&app, &admin, Op::CreateGrant, "", &grant("default", None, &ghost, "READ", false)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let directory = body.replace(">IAM<", ">DIRECTORY_USER<");
    let (status, _) = call(&app, &admin, Op::CreateGrant, "", &directory).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    let (status, xml) = call(&app, &admin, Op::CreateGrant, "", &grant("nowhere", None, &alice.arn(), "READ", false)).await;
    assert_eq!((status, code(&xml)), (StatusCode::NOT_FOUND, "AccessGrantsLocationNotExistsError".into()));

    // Listed, by filters, a page at a time.
    let (_, xml) = call(&app, &admin, Op::ListGrants, "permission=WRITE", "").await;
    assert_eq!(xml.matches("<AccessGrant>").count(), 1, "{xml}");
    let (_, xml) = call(&app, &admin, Op::ListGrants, "maxResults=1", "").await;
    assert_eq!(xml.matches("<AccessGrant>").count(), 1);
    let token = field(&xml, "NextToken");
    let (_, xml) = call(&app, &admin, Op::ListGrants, &format!("maxResults=1&nextToken={token}"), "").await;
    assert_eq!(xml.matches("<AccessGrant>").count(), 1);
    assert!(!xml.contains("<NextToken>"), "{xml}");
    let (_, xml) = call(&app, &alice, Op::ListCallerGrants, "grantscope=s3://data/logs/2026/*", "").await;
    assert_eq!(xml.matches("<AccessGrant>").count(), 2, "{xml}");
    let (_, xml) = call(&app, &alice, Op::ListCallerGrants, "grantscope=s3://other/*", "").await;
    assert_eq!(xml.matches("<AccessGrant>").count(), 0, "{xml}");

    // Kept by what's in them.
    let (status, xml) = call(&app, &admin, Op::DeleteLocation("default".into()), "", "").await;
    assert_eq!((status, code(&xml)), (StatusCode::CONFLICT, "AccessGrantsLocationNotEmptyError".into()));
    let (status, xml) = call(&app, &admin, Op::DeleteInstance, "", "").await;
    assert_eq!((status, code(&xml)), (StatusCode::CONFLICT, "AccessGrantsInstanceNotEmptyError".into()));
    assert_eq!(call(&app, &admin, Op::DeleteGrant(id.clone()), "", "").await.0, StatusCode::NO_CONTENT);
    assert_eq!(call(&app, &admin, Op::DeleteGrant(id), "", "").await.0, StatusCode::NOT_FOUND);
    assert_eq!(call(&app, &admin, Op::DeleteLocation("default".into()), "", "").await.0, StatusCode::NO_CONTENT);
    let (_, xml) = call(&app, &admin, Op::ListGrants, "", "").await;
    let other = field(&xml, "AccessGrantId");
    assert_eq!(call(&app, &admin, Op::DeleteGrant(other), "", "").await.0, StatusCode::NO_CONTENT);
    assert_eq!(call(&app, &admin, Op::DeleteLocation(logs), "", "").await.0, StatusCode::NO_CONTENT);
    assert_eq!(call(&app, &admin, Op::DeleteInstance, "", "").await.0, StatusCode::NO_CONTENT);
    assert_eq!(call(&app, &admin, Op::GetInstance, "", "").await.0, StatusCode::NOT_FOUND);
}

/// Each operation needs its action; a location's role needs
/// `iam:PassRole`, and a grant's scope is `s3:AccessGrantScope`.
#[tokio::test]
async fn operations_need_their_actions() {
    let Some(app) = node().await else { return };
    let admin = user(&app, "admin", ADMIN).await;
    let alice = user(&app, "alice", "").await;
    let role = role(&app, &trusting_access_grants(""), "s3:*").await;
    call(&app, &admin, Op::CreateInstance, "", "").await;

    let nothing = user(&app, "nothing", "").await;
    let (status, xml) = call(&app, &nothing, Op::GetInstance, "", "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(xml.contains("s3:GetAccessGrantsInstance"), "{xml}");

    let no_pass = user(&app, "nopass", r#"{"Effect":"Allow","Action":"s3:*","Resource":"*"}"#).await;
    let (status, xml) = call(&app, &no_pass, Op::CreateLocation, "", &location("s3://", &role.arn())).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(xml.contains("iam:PassRole"), "{xml}");
    let (status, _) = call(&app, &admin, Op::CreateLocation, "", &location("s3://", &role.arn())).await;
    assert_eq!(status, StatusCode::OK);

    // Grants on `logs/` only.
    let logs_only = user(
        &app,
        "logsonly",
        r#"{"Effect":"Allow","Action":"s3:CreateAccessGrant","Resource":"*","Condition":{"StringLike":{"s3:AccessGrantScope":"s3://data/logs/*"}}}"#,
    )
    .await;
    let (status, xml) = call(&app, &logs_only, Op::CreateGrant, "", &grant("default", Some("data/logs/a*"), &alice.arn(), "READ", false)).await;
    assert_eq!(status, StatusCode::OK, "{xml}");
    let (status, _) = call(&app, &logs_only, Op::CreateGrant, "", &grant("default", Some("data/*"), &alice.arn(), "READ", false)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// GetDataAccess vends a session of the location's role, which may do
/// what the narrowest matching grant allows on its scope (or the target,
/// with `privilege=Minimal`), within what the role's policies allow, and
/// carries the instance's ARN.
#[tokio::test]
async fn data_access_vends_sessions_of_the_grants() {
    let Some(app) = node().await else { return };
    let admin = user(&app, "admin", ADMIN).await;
    let alice = user(&app, "alice", DATA_ACCESS).await;
    let bob = user(&app, "bob", DATA_ACCESS).await;
    let account = account(&app).await;
    // The role allows reading anything, but writing only where the
    // session's requests carry the instance.
    let instance = instance_arn(&account);
    let role = role(&app, &trusting_access_grants(""), "s3:Get*").await;
    let client = app.pool.get().await.unwrap();
    let write = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":["s3:PutObject","s3:List*"],"Resource":"*","Condition":{{"StringEquals":{{"s3:AccessGrantsInstanceArn":"{instance}"}}}}}}]}}"#
    );
    roles::put_policy(&client, &role, "write", &write).await.unwrap();
    call(&app, &admin, Op::CreateInstance, "", "").await;
    call(&app, &admin, Op::CreateLocation, "", &location("s3://", &role.arn())).await;
    call(&app, &admin, Op::CreateGrant, "", &grant("default", Some("data/*"), &alice.arn(), "READ", false)).await;
    call(&app, &admin, Op::CreateGrant, "", &grant("default", Some("data/logs/*"), &alice.arn(), "READWRITE", false)).await;

    // Not without a grant, nor beyond it.
    let (status, _) = call(&app, &bob, Op::GetDataAccess, "target=s3://data/*&permission=READ", "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call(&app, &alice, Op::GetDataAccess, "target=s3://data/*&permission=WRITE", "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call(&app, &alice, Op::GetDataAccess, "target=s3://other/*&permission=READ", "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Reading the bucket: the broader grant.
    let (status, xml) = call(&app, &alice, Op::GetDataAccess, "target=s3://data/reports/*&permission=READ", "").await;
    assert_eq!(status, StatusCode::OK, "{xml}");
    assert_eq!(field(&xml, "MatchedGrantTarget"), "s3://data/*");
    let session = session_of(&app, &xml).await;
    assert_eq!(session.principal_arn(), role.arn());
    assert!(may(&app, &session, "s3:GetObject", object("data", "anything"), None).await);
    assert!(may(&app, &session, "s3:ListBucket", On::Bucket("data".into()), None).await);
    assert!(!may(&app, &session, "s3:GetObject", object("other", "k"), None).await);
    assert!(!may(&app, &session, "s3:PutObject", object("data", "logs/x"), None).await);
    // Alice herself may do none of it.
    assert!(!may(&app, &alice, "s3:GetObject", object("data", "anything"), None).await);

    // Writing logs: the narrower grant, whose session carries the
    // instance, which the role's policy asks for.
    let (_, xml) = call(&app, &alice, Op::GetDataAccess, "target=s3://data/logs/2026/*&permission=READWRITE", "").await;
    assert_eq!(field(&xml, "MatchedGrantTarget"), "s3://data/logs/*");
    let session = session_of(&app, &xml).await;
    assert!(may(&app, &session, "s3:PutObject", object("data", "logs/old/x"), None).await);
    assert!(!may(&app, &session, "s3:PutObject", object("data", "x"), None).await);
    assert!(may(&app, &session, "s3:ListBucket", On::Bucket("data".into()), Some("logs/")).await);
    assert!(!may(&app, &session, "s3:ListBucket", On::Bucket("data".into()), Some("other/")).await);
    // Minimal: the target only.
    let (_, xml) = call(&app, &alice, Op::GetDataAccess, "target=s3://data/logs/2026/*&permission=WRITE&privilege=Minimal", "").await;
    let session = session_of(&app, &xml).await;
    assert!(may(&app, &session, "s3:PutObject", object("data", "logs/2026/x"), None).await);
    assert!(!may(&app, &session, "s3:PutObject", object("data", "logs/old/x"), None).await);
    // An object target matches a grant on its prefix.
    let (_, xml) = call(&app, &alice, Op::GetDataAccess, "target=s3://data/logs/a.txt&targetType=Object&permission=READ", "").await;
    assert_eq!(field(&xml, "MatchedGrantTarget"), "s3://data/logs/*");

    // Durations: within STS's, and the role's.
    let (status, _) = call(&app, &alice, Op::GetDataAccess, "target=s3://data/*&permission=READ&durationSeconds=7200", "").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(&app, &alice, Op::GetDataAccess, "target=s3://data/*&permission=READ&durationSeconds=60", "").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, xml) = call(&app, &alice, Op::GetDataAccess, "target=s3://data/*&permission=READ&durationSeconds=900", "").await;
    assert_eq!(status, StatusCode::OK);
    let expires = field(&xml, "Expiration");
    assert!(expires <= sessions::iso(sessions::now() + 901), "{expires}");
}

/// Access Grants assumes a location's role only if its trust policy lets
/// the service in, with the instance's account and ARN as
/// `aws:SourceAccount` and `aws:SourceArn`.
#[tokio::test]
async fn roles_must_trust_access_grants() {
    let Some(app) = node().await else { return };
    let admin = user(&app, "admin", ADMIN).await;
    let alice = user(&app, "alice", DATA_ACCESS).await;
    let account = account(&app).await;
    call(&app, &admin, Op::CreateInstance, "", "").await;

    let confused = r#"{"StringEquals":{"aws:SourceAccount":"999999999999"}}"#;
    let guarded = format!(r#"{{"StringEquals":{{"aws:SourceAccount":"{account}"}},"ArnEquals":{{"aws:SourceArn":"{}"}}}}"#, instance_arn(&account));
    let cases = [
        (r#"{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}"#.to_owned(), false),
        (trusting_access_grants(confused), false),
        (trusting_access_grants(&guarded), true),
    ];
    for (n, (trust, trusted)) in cases.into_iter().enumerate() {
        let role = role(&app, &trust, "s3:*").await;
        let scope = format!("s3://bucket{n}/");
        call(&app, &admin, Op::CreateLocation, "", &location(&scope, &role.arn())).await;
        let (_, xml) = call(&app, &admin, Op::ListLocations, &format!("locationscope={scope}"), "").await;
        let id = field(&xml, "AccessGrantsLocationId");
        call(&app, &admin, Op::CreateGrant, "", &grant(&id, None, &alice.arn(), "READ", false)).await;
        let (status, xml) = call(&app, &alice, Op::GetDataAccess, &format!("target={scope}*&permission=READ"), "").await;
        assert_eq!(status == StatusCode::OK, trusted, "{trust}: {xml}");
    }
}

/// Another account's principals use an instance as its resource policy
/// lets them, if their own policies do too: GetDataAccess for a grant
/// naming them, in the instance's account (whose role it vends).
#[tokio::test]
async fn other_accounts_use_an_instance_as_its_policy_allows() {
    let Some(app) = node().await else { return };
    let admin = user(&app, "admin", ADMIN).await;
    let management = account(&app).await;
    let client = app.pool.get().await.unwrap();
    let made = crate::organizations::create(&client, &management, "Team C", "team-c@example.com", "OrganizationAccountAccessRole").await.unwrap();
    let member = made.account_id.unwrap();
    // Carol of the member account, allowed GetDataAccess on the instance.
    let carol = {
        let (key, _) = users::create_for(&client, &member, "carol", None, false).await.unwrap();
        let policy = format!(r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"s3:GetDataAccess","Resource":"{}"}}]}}"#, instance_arn(&management));
        users::put_policy(&client, &member, "carol", "p", &policy).await.unwrap();
        Principal::load(&client, &key).await.unwrap().unwrap()
    };
    let dave = {
        let (key, _) = users::create_for(&client, &member, "dave", None, false).await.unwrap();
        Principal::load(&client, &key).await.unwrap().unwrap()
    };
    let role = role(&app, &trusting_access_grants(""), "s3:Get*").await;
    call(&app, &admin, Op::CreateInstance, "", "").await;
    call(&app, &admin, Op::CreateLocation, "", &location("s3://", &role.arn())).await;
    // A grant may name another account's user (not one that isn't there).
    let (status, xml) = call(&app, &admin, Op::CreateGrant, "", &grant("default", Some("shared/*"), &carol.arn(), "READ", false)).await;
    assert_eq!(status, StatusCode::OK, "{xml}");
    let ghost = format!("arn:aws:iam::{member}:user/ghost");
    assert_eq!(call(&app, &admin, Op::CreateGrant, "", &grant("default", None, &ghost, "READ", false)).await.0, StatusCode::BAD_REQUEST);
    call(&app, &admin, Op::CreateGrant, "", &grant("default", Some("shared/*"), &dave.arn(), "READ", false)).await;

    // Without the instance's resource policy: no.
    let target = "target=s3://shared/*&permission=READ";
    assert_eq!(call_in(&app, &carol, &management, Op::GetDataAccess, target, "").await.0, StatusCode::FORBIDDEN);
    let (status, xml) = call(&app, &admin, Op::GetPolicy, "", "").await;
    assert_eq!((status, xml.contains("<Policy>")), (StatusCode::OK, false), "{xml}");

    // Its policy names the instance, Access Grants' actions, and accounts
    // of the organization's.
    let put = |statement: String| {
        let policy = format!(r#"{{"Version":"2012-10-17","Statement":[{statement}]}}"#).replace('&', "&amp;").replace('<', "&lt;");
        format!("<PutAccessGrantsInstanceResourcePolicyRequest><Policy>{policy}</Policy></PutAccessGrantsInstanceResourcePolicyRequest>")
    };
    let allow = |who: &str, action: &str, resource: &str| {
        format!(r#"{{"Effect":"Allow","Principal":{{"AWS":"{who}"}},"Action":"{action}","Resource":"{resource}"}}"#)
    };
    let instance = instance_arn(&management);
    let (status, xml) = call(&app, &admin, Op::PutPolicy, "", &put(allow(&member, "s3:GetObject", &instance))).await;
    assert_eq!((status, code(&xml)), (StatusCode::BAD_REQUEST, "MalformedPolicy".to_owned()));
    let (status, xml) = call(&app, &admin, Op::PutPolicy, "", &put(allow(&member, "s3:GetDataAccess", "arn:aws:s3:::shared/*"))).await;
    assert_eq!((status, code(&xml)), (StatusCode::BAD_REQUEST, "MalformedPolicy".to_owned()));
    let (status, xml) = call(&app, &admin, Op::PutPolicy, "", &put(allow("999999999999", "s3:GetDataAccess", &instance))).await;
    assert_eq!((status, code(&xml)), (StatusCode::BAD_REQUEST, "MalformedPolicy".to_owned()));
    let (status, xml) = call(&app, &admin, Op::PutPolicy, "", &put(allow(&member, "s3:GetDataAccess", &instance))).await;
    assert_eq!(status, StatusCode::OK, "{xml}");
    assert!(field(&xml, "Policy").contains("s3:GetDataAccess"), "{xml}");
    let (_, xml) = call(&app, &admin, Op::GetPolicy, "", "").await;
    assert!(field(&xml, "Policy").contains(&member), "{xml}");

    // Now Carol may: a session of the instance account's role.
    let (status, xml) = call_in(&app, &carol, &management, Op::GetDataAccess, target, "").await;
    assert_eq!(status, StatusCode::OK, "{xml}");
    let session = session_of(&app, &xml).await;
    assert_eq!((session.account.as_str(), session.principal_arn()), (management.as_str(), role.arn()));
    // Dave's own policies don't allow it.
    assert_eq!(call_in(&app, &dave, &management, Op::GetDataAccess, target, "").await.0, StatusCode::FORBIDDEN);
    // Nor what the policy doesn't allow.
    assert_eq!(call_in(&app, &carol, &management, Op::ListGrants, "", "").await.0, StatusCode::FORBIDDEN);

    // Deleted, it's no again.
    let (status, _) = call(&app, &admin, Op::DeletePolicy, "", "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(call_in(&app, &carol, &management, Op::GetDataAccess, target, "").await.0, StatusCode::FORBIDDEN);
}
