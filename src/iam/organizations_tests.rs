//! Member accounts (see `organizations`), end to end, against a real
//! Postgres: made from the management account with
//! `OrganizationAccountAccessRole`, which the management account's
//! principals assume (if their own policies allow it); a member account's
//! own buckets, cluster and organization (none of either); Identity
//! Center's permission sets provisioned there; and closing one.

use std::collections::HashMap;
use std::sync::Arc;

use hyper::{HeaderMap, Method};
use serde_json::{Value, json};

use super::{Iam, Params};
use crate::{
    App,
    identity_center as ic,
    organizations as org,
    policy::Verdict,
    s3::{
        access::{Access, Origin},
        actions::{Check, On},
    },
    users::{self, Principal},
};

const ADMIN: &str = r#"{"Effect":"Allow","Action":"*","Resource":"*"}"#;

async fn node() -> Option<Arc<App>> {
    crate::e2e::node_with(crate::packer::Config::default(), None).await
}

/// A user `name` of `account`, with the identity policy `statements`
/// (none, if empty).
async fn user(app: &App, account: &str, name: &str, statements: &str) -> Principal {
    let client = app.pool.get().await.unwrap();
    let (key, _) = users::create_for(&client, account, name, None, false).await.unwrap();
    if !statements.is_empty() {
        let policy = format!(r#"{{"Version":"2012-10-17","Statement":[{statements}]}}"#);
        users::put_policy(&client, account, name, "p", &policy).await.unwrap();
    }
    Principal::load(&client, &key).await.unwrap().unwrap()
}

/// STS's AssumeRole of `role`, by `principal`: the session's principal, or
/// the error's code.
async fn assume(app: &Arc<App>, principal: &Principal, role: &str) -> Result<Principal, String> {
    let client = app.pool.get().await.unwrap();
    let origin = Origin { peer: None, trusted_proxies: &[], signed: None, form: false };
    let mut access = Access::new(Some(principal), &principal.account, &Method::POST, &HeaderMap::new(), "", &origin).unwrap();
    let mut iam = Iam { app, client: &client, principal, access: &mut access };
    let params = [("RoleArn", role), ("RoleSessionName", "ops")];
    let params = Params(params.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<HashMap<_, _>>());
    let xml = iam.assume_role(&params).await.map_err(|e| e.code.to_owned())?.unwrap_or_default();
    let element = |name: &str| xml.split(&format!("<{name}>")).nth(1).and_then(|r| r.split('<').next()).unwrap().to_owned();
    let session = Principal::authenticate(&client, &app.sessions, &element("AccessKeyId"), Some(&element("SessionToken"))).await.unwrap();
    Ok(session.expect("the new session's"))
}

/// The verdict on `action` on `on` by `principal`, with the management
/// account `management` owning the cluster.
async fn verdict(app: &App, principal: &Principal, management: &str, action: &'static str, on: On) -> Verdict {
    let origin = Origin { peer: None, trusted_proxies: &[], signed: None, form: false };
    let mut access = Access::new(Some(principal), &principal.account, &Method::GET, &HeaderMap::new(), "", &origin).unwrap();
    access.set_management(management);
    if let On::Bucket(bucket) = &on {
        access.load(app, bucket).await.unwrap();
    }
    access.verdict(&Check { action, on })
}

/// An Organizations operation by `principal`: its answer, or its error's
/// code.
async fn call(app: &App, principal: &Principal, operation: &str, input: Value) -> Result<Value, String> {
    org::call(app, principal, operation, input).await
}

#[tokio::test]
async fn member_accounts_are_made_entered_and_closed() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let management = users::account(&client).await.unwrap();
    let admin = user(&app, &management, "admin", ADMIN).await;

    let organization = call(&app, &admin, "DescribeOrganization", json!({})).await.unwrap();
    assert_eq!(organization["Organization"]["MasterAccountId"], json!(management));
    assert_eq!(organization["Organization"]["Id"], json!(org::organization_id(&management)));

    // Made, as CreateAccount makes them: an e-mail is one account's only.
    let bad = json!({ "AccountName": "Team A", "Email": "nope" });
    assert_eq!(call(&app, &admin, "CreateAccount", bad).await.unwrap_err(), "InvalidInputException");
    let input = json!({ "AccountName": "Team A", "Email": "team-a@example.com" });
    let made = call(&app, &admin, "CreateAccount", input.clone()).await.unwrap();
    assert_eq!(made["CreateAccountStatus"]["State"], "SUCCEEDED", "{made}");
    let member = made["CreateAccountStatus"]["AccountId"].as_str().unwrap().to_owned();
    let again = call(&app, &admin, "CreateAccount", input).await.unwrap();
    assert_eq!((&again["CreateAccountStatus"]["State"], &again["CreateAccountStatus"]["FailureReason"]), (&json!("FAILED"), &json!("EMAIL_ALREADY_EXISTS")));
    let request = json!({ "CreateAccountRequestId": made["CreateAccountStatus"]["Id"] });
    assert_eq!(call(&app, &admin, "DescribeCreateAccountStatus", request).await.unwrap()["CreateAccountStatus"]["AccountId"], json!(member));
    let failed = call(&app, &admin, "ListCreateAccountStatus", json!({ "States": ["FAILED"] })).await.unwrap();
    assert_eq!(failed["CreateAccountStatuses"].as_array().unwrap().len(), 1);
    let accounts = call(&app, &admin, "ListAccounts", json!({})).await.unwrap();
    let ids: Vec<&str> = accounts["Accounts"].as_array().unwrap().iter().map(|a| a["Id"].as_str().unwrap()).collect();
    assert_eq!(ids, [management.as_str(), member.as_str()]);
    let described = call(&app, &admin, "DescribeAccount", json!({ "AccountId": member })).await.unwrap();
    assert_eq!((&described["Account"]["Name"], &described["Account"]["Status"]), (&json!("Team A"), &json!("ACTIVE")));

    // Its access role trusts the management account, whose principals'
    // own policies must allow assuming it too.
    let role = format!("arn:aws:iam::{member}:role/{}", org::ACCESS_ROLE);
    let session = assume(&app, &admin, &role).await.unwrap();
    assert_eq!(session.account, member);
    let nobody = user(&app, &management, "nobody", "").await;
    assert_eq!(assume(&app, &nobody, &role).await.err().unwrap(), "AccessDenied");
    // A role of an account that isn't there is none.
    assert_eq!(assume(&app, &admin, "arn:aws:iam::000000000000:role/x").await.err().unwrap(), "AccessDenied");

    // The member account's principals: its own things, not the cluster,
    // nor the organization's accounts, nor Identity Center's instance.
    assert_eq!(verdict(&app, &admin, &management, "cairn:GetCluster", On::Cluster).await, Verdict::Allow);
    assert_ne!(verdict(&app, &session, &management, "cairn:GetCluster", On::Cluster).await, Verdict::Allow);
    assert_eq!(call(&app, &session, "ListAccounts", json!({})).await.unwrap_err(), "AccessDeniedException");
    assert!(call(&app, &session, "DescribeOrganization", json!({})).await.is_ok());
    crate::s3::buckets::create::create(&app, "team-a-data", &member, false).await.unwrap();
    let bucket = || On::Bucket("team-a-data".into());
    assert_eq!(verdict(&app, &session, &management, "s3:ListBucket", bucket()).await, Verdict::Allow);
    assert_ne!(verdict(&app, &admin, &management, "s3:ListBucket", bucket()).await, Verdict::Allow);
    assert_eq!(crate::s3::util::bucket_owner(&client, "team-a-data").await.unwrap(), member);

    // Identity Center: a permission set assigned there is provisioned there.
    let set = ic::create(&client, &management, &ic::New { name: "Ops", description: "", session_duration: 3600, relay_state: None, tags: None })
        .await
        .unwrap();
    ic::attach(&client, &set, "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess", true).await.unwrap();
    let profile = json!({ "Name": { "GivenName": "Grace" } });
    let grace = ic::create_user(&client, &ic::OwnUser { user_name: "grace", display_name: "Grace", email: None, profile: &profile }).await.unwrap();
    assert_eq!(ic::assign(&client, &set, &member, ic::PrincipalType::User, grace.id).await.unwrap(), Ok(()));
    let provisioned: Vec<String> = ic::provisions(&client, &set).await.unwrap().into_iter().map(|p| p.account).collect();
    assert_eq!(provisioned, [member.clone()]);
    let there = crate::roles::Role::load(&client, &member, &set.role_name()).await.unwrap().unwrap();
    assert_eq!(crate::roles::attached(&client, there.id).await.unwrap().len(), 1);
    let eligible = ic::eligible(&client, &management, grace.id).await.unwrap();
    assert_eq!((eligible.len(), eligible[0].account.as_str()), (1, member.as_str()));

    // Closed: not with buckets, nor the management account; at once, and
    // its principals are no one from then on.
    let close = |id: &str| json!({ "AccountId": id });
    assert_eq!(call(&app, &admin, "CloseAccount", close(&member)).await.unwrap_err(), "ConstraintViolationException");
    crate::s3::buckets::delete::delete_bucket(&app, "team-a-data").await.unwrap();
    assert_eq!(call(&app, &admin, "CloseAccount", close(&management)).await.unwrap_err(), "ConstraintViolationException");
    assert_eq!(call(&app, &session, "CloseAccount", close(&member)).await.unwrap_err(), "AccessDeniedException");
    call(&app, &admin, "CloseAccount", close(&member)).await.unwrap();
    assert_eq!(call(&app, &admin, "CloseAccount", close(&member)).await.unwrap_err(), "AccountAlreadyClosedException");
    let described = call(&app, &admin, "DescribeAccount", json!({ "AccountId": member })).await.unwrap();
    assert_eq!(described["Account"]["Status"], "SUSPENDED");
    assert!(crate::roles::principal(&client, there.id).await.unwrap().is_none());
    assert_eq!(assume(&app, &admin, &role).await.err().unwrap(), "AccessDenied");
    assert!(ic::eligible(&client, &management, grace.id).await.unwrap().is_empty());
}

/// Migration 68 (`db::ORGANIZATIONS`) makes the account there is the
/// management account, and lets the operator account's empty row go.
#[tokio::test]
async fn the_account_becomes_the_management_account() {
    let Some(pool) = crate::e2e::fresh_database_through(67).await else { return };
    let client = pool.get().await.unwrap();
    let before: i64 = client.query_one("SELECT count(*) FROM accounts", &[]).await.unwrap().get(0);
    let account: String = client.query_one("SELECT id FROM accounts WHERE NOT operator", &[]).await.unwrap().get(0);
    crate::db::init(&pool, usize::MAX).await.unwrap();
    let rows: Vec<(String, bool)> =
        client.query("SELECT id, management FROM accounts", &[]).await.unwrap().iter().map(|r| (r.get(0), r.get(1))).collect();
    assert_eq!(rows, [(account.clone(), true)], "{before} before");
    assert_eq!(users::account(&client).await.unwrap(), account);
}
