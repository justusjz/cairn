//! The account's root user's temporary credentials (`cairn account
//! root-key`), end to end, against a real Postgres: as a node takes them,
//! and what IAM, STS and S3 make of them. They're the root, whom no identity
//! policy restricts; IAM refuses to act on "its own" user, STS makes no
//! sessions of it, and `cairn sessions revoke-all` ends them.

use std::collections::HashMap;
use std::sync::Arc;

use hyper::{HeaderMap, Method};

use super::{Iam, Params};
use crate::{
    App,
    admin::e2e::cairn,
    e2e::BUCKET,
    policy::Verdict,
    s3::{
        access::{Access, Origin},
        actions::{Check, On},
    },
    users::{self, Principal},
};

/// The credentials `cairn account root-key` prints: key ID, secret, token.
async fn root_key(app: &Arc<App>) -> (String, String, String) {
    let out = cairn(app, &["account", "root-key"]).await;
    assert_eq!(out.error, None);
    assert!(out.stderr.contains("revoke-all"), "{}", out.stderr);
    let var = |name: &str| {
        let prefix = format!("export {name}=");
        out.stdout.lines().find_map(|l| l.strip_prefix(&prefix)).unwrap_or_else(|| panic!("no {name}: {}", out.stdout)).to_owned()
    };
    (var("AWS_ACCESS_KEY_ID"), var("AWS_SECRET_ACCESS_KEY"), var("AWS_SESSION_TOKEN"))
}

/// `action` with `params`, signed by `principal`: its answer, or its
/// error's code and message.
async fn call(app: &Arc<App>, principal: &Principal, action: &str, params: &[(&str, &str)]) -> Result<String, (String, String)> {
    let client = app.pool.get().await.unwrap();
    let trusted = Vec::new();
    let origin = Origin { peer: Some("127.0.0.1".parse().unwrap()), trusted_proxies: &trusted, signed: None, form: false };
    let mut access = Access::new(Some(principal), &principal.account, &Method::POST, &HeaderMap::new(), "", &origin).unwrap();
    let mut iam = Iam { app, client: &client, principal, access: &mut access };
    let params = Params(params.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<HashMap<_, _>>());
    let answered = match action {
        "GetCallerIdentity" => Ok(iam.get_caller_identity()),
        "CreateAccessKey" => iam.create_access_key(&params).await,
        "ListAccessKeys" => iam.list_access_keys(&params).await,
        "DeleteUserPermissionsBoundary" => iam.delete_user_permissions_boundary(&params).await,
        "GetSessionToken" => iam.get_session_token(&params).await,
        "GetFederationToken" => iam.get_federation_token(&params).await,
        "AssumeRole" => iam.assume_role(&params).await,
        other => panic!("no {other} here"),
    };
    match answered {
        Ok(xml) => Ok(xml.unwrap_or_default()),
        Err(e) => Err((e.code.to_owned(), e.message)),
    }
}

#[tokio::test]
async fn the_root_key_is_the_root_until_revoked() {
    let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else { return };
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let (key, secret, token) = root_key(&app).await;
    assert!(key.starts_with("ASIA"), "{key}");

    // A node takes them as the root's.
    let root = Principal::authenticate(&client, &app.sessions, &key, Some(&token)).await.unwrap().unwrap();
    assert!(root.root);
    assert_eq!(root.secret, secret);
    assert_eq!(root.arn(), format!("arn:aws:iam::{account}:root"));
    let me = call(&app, &root, "GetCallerIdentity", &[]).await.unwrap();
    assert!(me.contains(&format!("<Arn>arn:aws:iam::{account}:root</Arn><UserId>{account}</UserId>")), "{me}");

    // No identity policy restricts it: it takes an admin's boundary off.
    users::create(&client, "boss", None, true).await.unwrap();
    let boss = users::id_of(&client, &account, "boss").await.unwrap();
    users::set_boundary(&client, &account, boss, Some(&users::BoundaryRef::Aws("AmazonS3ReadOnlyAccess"))).await.unwrap();
    call(&app, &root, "DeleteUserPermissionsBoundary", &[("UserName", "boss")]).await.unwrap();
    assert!(Principal::load_user(&client, boss).await.unwrap().unwrap().boundary.is_none());

    // It's no user: what acts on the signer's own user must name one, even
    // with a user named `root` there (as migration 46 made them).
    users::create(&client, "root", None, true).await.unwrap();
    for action in ["CreateAccessKey", "ListAccessKeys"] {
        let (code, _) = call(&app, &root, action, &[]).await.unwrap_err();
        assert_eq!(code, "ValidationError", "{action}");
    }
    let keys = call(&app, &root, "ListAccessKeys", &[("UserName", "root")]).await.unwrap();
    assert_eq!(keys.matches("<AccessKeyId>").count(), 1, "only the key `create` made: {keys}");

    // STS makes no sessions of it.
    assert!(call(&app, &root, "GetSessionToken", &[]).await.is_err());
    assert!(call(&app, &root, "GetFederationToken", &[("Name", "x")]).await.is_err());
    let trust = format!(r#"{{"Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{account}:root"}},"Action":"sts:AssumeRole"}}]}}"#);
    let trust = crate::roles::check_trust(&client, &account, &trust).await.unwrap();
    let new = crate::roles::New { name: "ops", path: "/", trust: &trust, description: "", max_session_duration: 3600, boundary: None, tags: &[] };
    crate::roles::create(&client, &account, &new).await.unwrap();
    let role = format!("arn:aws:iam::{account}:role/ops");
    let (code, _) = call(&app, &root, "AssumeRole", &[("RoleArn", &role), ("RoleSessionName", "fix-it")]).await.unwrap_err();
    assert_eq!(code, "AccessDenied");

    // A bucket policy that denies everyone denies it, but for the policy.
    let deny = format!(r#"{{"Statement":[{{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::{BUCKET}","arn:aws:s3:::{BUCKET}/*"]}}]}}"#);
    client.execute("UPDATE buckets SET policy = $1 WHERE name = $2", &[&deny, &BUCKET]).await.unwrap();
    let origin = Origin { peer: None, trusted_proxies: &[], signed: None, form: false };
    let mut access = Access::new(Some(&root), &account, &Method::GET, &HeaderMap::new(), "", &origin).unwrap();
    access.load(&app, BUCKET).await.unwrap();
    let get = Check { action: "s3:GetObject", on: On::Object(BUCKET.to_owned(), "k".to_owned()) };
    assert_eq!(access.verdict(&get), Verdict::ExplicitDeny { identity: false });
    assert!(access.allows(&Check { action: "s3:DeleteBucketPolicy", on: On::Bucket(BUCKET.to_owned()) }));

    // `cairn sessions revoke-all` ends them.
    assert_eq!(cairn(&app, &["sessions", "revoke-all"]).await.error, None);
    assert!(Principal::authenticate(&client, &app.sessions, &key, Some(&token)).await.unwrap().is_err());
}
