//! AssumeRoleWithWebIdentity end to end, against a real Postgres and an
//! OIDC issuer over HTTPS with a certificate of a private CA (the mock's):
//! the provider trusts it by its thumbprint, the token's claims are the
//! trust policy's condition keys, and the credentials are a role session's,
//! whose requests carry the provider (`aws:FederatedProvider`).

use std::collections::HashMap;
use std::sync::Arc;

use hyper::{HeaderMap, Method};
use serde_json::json;

use super::{Params, sts::Sts};
use crate::{
    App, iam_oidc,
    oidc::{self, Reach, mock::{CA_THUMBPRINT, Mock}},
    roles,
    s3::access::{Access, Origin},
    users,
};

const AUDIENCE: &str = "sts.amazonaws.com";

fn now() -> u64 {
    oidc::now()
}

/// What the request answered: its result, or its error's code and message.
async fn assume(app: &Arc<App>, role_arn: &str, token: &str, extra: &[(&str, &str)]) -> Result<String, (String, String)> {
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let mut params: HashMap<String, String> = [
        ("Action", "AssumeRoleWithWebIdentity"),
        ("RoleArn", role_arn),
        ("RoleSessionName", "ci-run"),
        ("WebIdentityToken", token),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect();
    params.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    let trusted = Vec::new();
    let origin = Origin { peer: Some("127.0.0.1".parse().unwrap()), trusted_proxies: &trusted, signed: None, form: false };
    let access = Access::new(None, &account, &Method::POST, &HeaderMap::new(), "", &origin).unwrap();
    let sts = Sts { app, client: &client, account: &account };
    match sts.assume_role_with_web_identity(&access, &Params(params)).await {
        Ok(xml) => Ok(xml.unwrap()),
        Err(e) => Err((e.code.to_owned(), e.message)),
    }
}

fn element<'a>(xml: &'a str, name: &str) -> &'a str {
    let start = xml.find(&format!("<{name}>")).unwrap_or_else(|| panic!("no {name} in {xml}")) + name.len() + 2;
    let end = xml[start..].find(&format!("</{name}>")).unwrap() + start;
    &xml[start..end]
}

async fn make_role(app: &Arc<App>, name: &str, trust: &serde_json::Value) -> roles::Role {
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let trust = roles::check_trust(&client, &account, &trust.to_string()).await.unwrap();
    let new = roles::New { name, path: "/", trust: &trust, description: "", max_session_duration: 3600, boundary: None, tags: &[] };
    let id = roles::create(&client, &account, &new).await.unwrap();
    roles::Role::load_id(&client, id).await.unwrap().unwrap()
}

#[tokio::test]
async fn web_identities_assume_roles_that_trust_their_provider() {
    let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else { return };
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let mock = Mock::start_https().await;
    let url = mock.issuer.strip_prefix("https://").unwrap().to_owned();

    // Reached only at public addresses, an issuer on loopback isn't; with
    // private ones allowed, its certificate (a private CA's) is trusted by
    // the CA's thumbprint only.
    let pinned = vec![iam_oidc::check_thumbprint(CA_THUMBPRINT).unwrap()];
    let public = Reach { public_only: true, thumbprints: pinned.clone() };
    assert!(oidc::check_issuer(&mock.issuer, &public).await.is_err());
    let localhost = format!("https://localhost:{}", mock.port);
    let e = oidc::check_issuer(&localhost, &public).await.unwrap_err();
    assert!(format!("{e:#}").contains("public address"), "{e:#}");
    let unpinned = Reach { public_only: false, thumbprints: Vec::new() };
    assert!(oidc::check_issuer(&mock.issuer, &unpinned).await.is_err());
    let wrong = Reach { public_only: false, thumbprints: vec![[7; 20]] };
    assert!(oidc::check_issuer(&mock.issuer, &wrong).await.is_err());
    let private = Reach { public_only: false, thumbprints: pinned };
    oidc::check_issuer(&mock.issuer, &private).await.unwrap();

    crate::settings::OIDC_PRIVATE_ISSUERS.set(&client, 1).await.unwrap();
    let new = iam_oidc::New {
        url: &url,
        client_ids: &[AUDIENCE.to_owned()],
        thumbprints: &[CA_THUMBPRINT.to_owned()],
        tags: &[],
    };
    iam_oidc::create(&client, &account, &new).await.unwrap();
    let provider_arn = iam_oidc::provider_arn(&account, &url);

    let trust = json!({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Principal": {"Federated": provider_arn},
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {
            "StringEquals": {format!("{url}:aud"): AUDIENCE},
            "StringLike": {format!("{url}:sub"): "repo:cairn/*"},
        },
    }]});
    let role = make_role(&app, "ci", &trust).await;
    let role_arn = role.arn();
    let claims = |sub: &str| json!({"sub": sub, "aud": AUDIENCE, "exp": now() + 300, "iat": now(), "amr": ["pwd"]});

    let xml = assume(&app, &role_arn, &mock.id_token(claims("repo:cairn/main")), &[]).await.unwrap();
    assert_eq!(element(&xml, "SubjectFromWebIdentityToken"), "repo:cairn/main");
    assert_eq!(element(&xml, "Audience"), AUDIENCE);
    assert_eq!(element(&xml, "Provider"), mock.issuer);
    assert_eq!(element(&xml, "Arn"), format!("arn:aws:sts::{account}:assumed-role/ci/ci-run"));
    // The credentials are the role's session, of the provider.
    let key = element(&xml, "AccessKeyId");
    let token = element(&xml, "SessionToken");
    let principal = users::Principal::authenticate(&client, &app.sessions, key, Some(token)).await.unwrap().unwrap();
    assert!(principal.is_role_session());
    assert_eq!(principal.session.as_ref().unwrap().session.provider.as_deref(), Some(provider_arn.as_str()));
    assert_eq!(principal.secret, element(&xml, "SecretAccessKey"));

    // The trust policy's conditions decide.
    let e = assume(&app, &role_arn, &mock.id_token(claims("repo:other/main")), &[]).await.unwrap_err();
    assert_eq!(e, ("AccessDenied".into(), "Not authorized to perform sts:AssumeRoleWithWebIdentity".into()));
    // Tokens that aren't right.
    let mut other_audience = claims("repo:cairn/main");
    other_audience["aud"] = json!("cairn-console");
    let e = assume(&app, &role_arn, &mock.id_token(other_audience), &[]).await.unwrap_err();
    assert_eq!(e, ("InvalidIdentityToken".into(), "Incorrect token audience".into()));
    let mut expired = claims("repo:cairn/main");
    expired["exp"] = json!(now() - 3600);
    let e = assume(&app, &role_arn, &mock.id_token(expired), &[]).await.unwrap_err();
    assert_eq!(e.0, "ExpiredTokenException");
    let mut elsewhere = claims("repo:cairn/main");
    elsewhere["iss"] = json!("https://issuer.invalid");
    let e = assume(&app, &role_arn, &mock.id_token(elsewhere), &[]).await.unwrap_err();
    assert_eq!(e, ("InvalidIdentityToken".into(), "No OpenIDConnect provider found in your account for https://issuer.invalid".into()));
    let e = assume(&app, &role_arn, "not-a-jwt", &[]).await.unwrap_err();
    assert_eq!(e.0, "InvalidIdentityToken");
    let good = mock.id_token(claims("repo:cairn/main"));
    let (signed, sig) = good.rsplit_once('.').unwrap();
    let forged = format!("{signed}.{}", if sig.starts_with('A') { sig.replacen('A', "B", 1) } else { format!("A{}", &sig[1..]) });
    let e = assume(&app, &role_arn, &forged, &[]).await.unwrap_err();
    assert_eq!(e.0, "InvalidIdentityToken");
    // A role that isn't there is refused as one that's not trusted.
    let missing = format!("arn:aws:iam::{account}:role/nobody");
    let e = assume(&app, &missing, &mock.id_token(claims("repo:cairn/main")), &[]).await.unwrap_err();
    assert_eq!(e.0, "AccessDenied");
    // Longer than the role allows.
    let e = assume(&app, &role_arn, &mock.id_token(claims("repo:cairn/main")), &[("DurationSeconds", "7200")]).await.unwrap_err();
    assert_eq!(e.0, "ValidationError");

    // Session tags in the token need sts:TagSession.
    let mut tagged = claims("repo:cairn/main");
    tagged["https://aws.amazon.com/tags"] = json!({"principal_tags": {"team": ["storage"]}, "transitive_tag_keys": ["team"]});
    let e = assume(&app, &role_arn, &mock.id_token(tagged.clone()), &[]).await.unwrap_err();
    assert_eq!(e, ("AccessDenied".into(), "Not authorized to perform sts:TagSession".into()));
    let tagging = json!({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Principal": {"Federated": provider_arn},
        "Action": ["sts:AssumeRoleWithWebIdentity", "sts:TagSession"],
    }]});
    let role = make_role(&app, "tagged", &tagging).await;
    let xml = assume(&app, &role.arn(), &mock.id_token(tagged), &[]).await.unwrap();
    let principal =
        users::Principal::authenticate(&client, &app.sessions, element(&xml, "AccessKeyId"), Some(element(&xml, "SessionToken")))
            .await
            .unwrap()
            .unwrap();
    assert!(principal.tags.contains(&("team".to_owned(), "storage".to_owned())), "{:?}", principal.tags);

    // Trust in the account (or anyone as `AWS`) doesn't let web identities
    // in; a Deny of everyone keeps them out.
    let account_trust = json!({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": format!("arn:aws:iam::{account}:root")}, "Action": "sts:AssumeRoleWithWebIdentity",
    }]});
    let role = make_role(&app, "accounts", &account_trust).await;
    let e = assume(&app, &role.arn(), &mock.id_token(claims("repo:cairn/main")), &[]).await.unwrap_err();
    assert_eq!(e.0, "AccessDenied");
    let denying = json!({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Federated": provider_arn}, "Action": "sts:AssumeRoleWithWebIdentity"},
        {"Effect": "Deny", "Principal": "*", "Action": "sts:AssumeRoleWithWebIdentity",
         "Condition": {"ForAnyValue:StringEquals": {format!("{url}:amr"): "pwd"}}},
    ]});
    let role = make_role(&app, "denying", &denying).await;
    let e = assume(&app, &role.arn(), &mock.id_token(claims("repo:cairn/main")), &[]).await.unwrap_err();
    assert_eq!(e.0, "AccessDenied");

    // Deleting the provider ends it all.
    let provider = iam_oidc::Provider::load(&client, &account, &url).await.unwrap().unwrap();
    assert!(iam_oidc::delete(&client, provider.id).await.unwrap());
    let e = assume(&app, &role_arn, &mock.id_token(claims("repo:cairn/main")), &[]).await.unwrap_err();
    assert_eq!(e.0, "InvalidIdentityToken");
}

/// A provider's client IDs, thumbprints and tags, as IAM keeps them.
#[tokio::test]
async fn providers_keep_their_lists() {
    let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else { return };
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let new = iam_oidc::New {
        url: "issuer.example/tenant",
        client_ids: &["a".to_owned(), "b".to_owned()],
        thumbprints: &[],
        tags: &[("team".to_owned(), "x".to_owned())],
    };
    iam_oidc::create(&client, &account, &new).await.unwrap();
    let e = iam_oidc::create(&client, &account, &new).await.unwrap_err();
    assert_eq!(e.to_string(), "Provider with url https://issuer.example/tenant already exists.");
    let arn = iam_oidc::provider_arn(&account, "issuer.example/tenant");
    let provider = iam_oidc::Provider::load_arn(&client, &account, &arn).await.unwrap().unwrap();
    assert_eq!(provider.client_ids, ["a", "b"]);
    assert_eq!(provider.tags, [("team".to_owned(), "x".to_owned())]);

    iam_oidc::add_client_id(&client, &provider, "c").await.unwrap();
    iam_oidc::add_client_id(&client, &provider, "a").await.unwrap();
    iam_oidc::remove_client_id(&client, provider.id, "b").await.unwrap();
    for n in 0..98 {
        iam_oidc::add_client_id(&client, &provider, &format!("n{n}")).await.unwrap();
    }
    let e = iam_oidc::add_client_id(&client, &provider, "one-too-many").await.unwrap_err();
    assert_eq!(e.to_string(), "Cannot exceed quota for ClientIdsPerOpenIdConnectProvider: 100");
    let thumbprints = ["0".repeat(40), "A".repeat(40)];
    iam_oidc::set_thumbprints(&client, &provider, &thumbprints).await.unwrap();
    iam_oidc::tag(&client, &provider, &[("TEAM".to_owned(), "y".to_owned())]).await.unwrap();
    let provider = iam_oidc::Provider::load_arn(&client, &account, &arn).await.unwrap().unwrap();
    assert_eq!(provider.client_ids[..2], ["a", "c"]);
    assert_eq!(provider.client_ids.len(), 100);
    assert_eq!(provider.thumbprints, thumbprints);
    assert_eq!(provider.tags, [("TEAM".to_owned(), "y".to_owned())]);
    assert_eq!(iam_oidc::list(&client, &account).await.unwrap().len(), 1);
    assert!(iam_oidc::delete(&client, provider.id).await.unwrap());
    assert!(iam_oidc::list(&client, &account).await.unwrap().is_empty());
}
