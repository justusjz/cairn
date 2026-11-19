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
    App, identity_center as ic, organizations as org,
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
    let (key, _) = users::create_for(&client, account, name, None, false)
        .await
        .unwrap();
    if !statements.is_empty() {
        let policy = format!(r#"{{"Version":"2012-10-17","Statement":[{statements}]}}"#);
        users::put_policy(&client, account, name, "p", &policy)
            .await
            .unwrap();
    }
    Principal::load(&client, &key).await.unwrap().unwrap()
}

/// STS's AssumeRole of `role`, by `principal`: the session's principal, or
/// the error's code.
async fn assume(app: &Arc<App>, principal: &Principal, role: &str) -> Result<Principal, String> {
    let client = app.pool.get().await.unwrap();
    let origin = Origin {
        peer: None,
        trusted_proxies: &[],
        signed: None,
        form: false,
    };
    let mut access = Access::new(
        Some(principal),
        &principal.account,
        &Method::POST,
        &HeaderMap::new(),
        "",
        &origin,
    )
    .unwrap();
    let mut iam = Iam {
        app,
        client: &client,
        principal,
        access: &mut access,
    };
    let params = [("RoleArn", role), ("RoleSessionName", "ops")];
    let params = Params(
        params
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<HashMap<_, _>>(),
    );
    let xml = iam
        .assume_role(&params)
        .await
        .map_err(|e| e.code.to_owned())?
        .unwrap_or_default();
    let element = |name: &str| {
        xml.split(&format!("<{name}>"))
            .nth(1)
            .and_then(|r| r.split('<').next())
            .unwrap()
            .to_owned()
    };
    let session = Principal::authenticate(
        &client,
        &app.sessions,
        &element("AccessKeyId"),
        Some(&element("SessionToken")),
    )
    .await
    .unwrap();
    Ok(session.expect("the new session's"))
}

/// The verdict on `action` on `on` by `principal`, with the management
/// account `management` owning the cluster.
async fn verdict(
    app: &App,
    principal: &Principal,
    management: &str,
    action: &'static str,
    on: On,
) -> Verdict {
    let origin = Origin {
        peer: None,
        trusted_proxies: &[],
        signed: None,
        form: false,
    };
    let mut access = Access::new(
        Some(principal),
        &principal.account,
        &Method::GET,
        &HeaderMap::new(),
        "",
        &origin,
    )
    .unwrap();
    access.set_management(management);
    // As a request does: its bucket loaded first (an object's too).
    if let Some(bucket) = on.bucket() {
        access.load(app, bucket).await.unwrap();
    }
    access.verdict(&Check { action, on })
}

/// An Organizations operation by `principal`: its answer, or its error's
/// code.
async fn call(
    app: &App,
    principal: &Principal,
    operation: &str,
    input: Value,
) -> Result<Value, String> {
    org::call(app, principal, operation, input).await
}

#[tokio::test]
async fn member_accounts_are_made_entered_and_closed() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let management = users::account(&client).await.unwrap();
    let admin = user(&app, &management, "admin", ADMIN).await;

    let organization = call(&app, &admin, "DescribeOrganization", json!({}))
        .await
        .unwrap();
    assert_eq!(
        organization["Organization"]["MasterAccountId"],
        json!(management)
    );
    assert_eq!(
        organization["Organization"]["Id"],
        json!(org::organization_id(&management))
    );

    // Made, as CreateAccount makes them: an e-mail is one account's only.
    let bad = json!({ "AccountName": "Team A", "Email": "nope" });
    assert_eq!(
        call(&app, &admin, "CreateAccount", bad).await.unwrap_err(),
        "InvalidInputException"
    );
    let input = json!({ "AccountName": "Team A", "Email": "team-a@example.com" });
    let made = call(&app, &admin, "CreateAccount", input.clone())
        .await
        .unwrap();
    assert_eq!(made["CreateAccountStatus"]["State"], "SUCCEEDED", "{made}");
    let member = made["CreateAccountStatus"]["AccountId"]
        .as_str()
        .unwrap()
        .to_owned();
    let again = call(&app, &admin, "CreateAccount", input).await.unwrap();
    assert_eq!(
        (
            &again["CreateAccountStatus"]["State"],
            &again["CreateAccountStatus"]["FailureReason"]
        ),
        (&json!("FAILED"), &json!("EMAIL_ALREADY_EXISTS"))
    );
    let request = json!({ "CreateAccountRequestId": made["CreateAccountStatus"]["Id"] });
    assert_eq!(
        call(&app, &admin, "DescribeCreateAccountStatus", request)
            .await
            .unwrap()["CreateAccountStatus"]["AccountId"],
        json!(member)
    );
    let failed = call(
        &app,
        &admin,
        "ListCreateAccountStatus",
        json!({ "States": ["FAILED"] }),
    )
    .await
    .unwrap();
    assert_eq!(failed["CreateAccountStatuses"].as_array().unwrap().len(), 1);
    let accounts = call(&app, &admin, "ListAccounts", json!({})).await.unwrap();
    let ids: Vec<&str> = accounts["Accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["Id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [management.as_str(), member.as_str()]);
    let described = call(
        &app,
        &admin,
        "DescribeAccount",
        json!({ "AccountId": member }),
    )
    .await
    .unwrap();
    assert_eq!(
        (
            &described["Account"]["Name"],
            &described["Account"]["Status"]
        ),
        (&json!("Team A"), &json!("ACTIVE"))
    );

    // Its access role trusts the management account, whose principals'
    // own policies must allow assuming it too.
    let role = format!("arn:aws:iam::{member}:role/{}", org::ACCESS_ROLE);
    let session = assume(&app, &admin, &role).await.unwrap();
    assert_eq!(session.account, member);
    let nobody = user(&app, &management, "nobody", "").await;
    assert_eq!(
        assume(&app, &nobody, &role).await.err().unwrap(),
        "AccessDenied"
    );
    // A role of an account that isn't there is none.
    assert_eq!(
        assume(&app, &admin, "arn:aws:iam::000000000000:role/x")
            .await
            .err()
            .unwrap(),
        "AccessDenied"
    );

    // The member account's principals: its own things, not the cluster,
    // nor the organization's accounts, nor Identity Center's instance.
    assert_eq!(
        verdict(&app, &admin, &management, "cairn:GetCluster", On::Cluster).await,
        Verdict::Allow
    );
    assert_ne!(
        verdict(&app, &session, &management, "cairn:GetCluster", On::Cluster).await,
        Verdict::Allow
    );
    assert_eq!(
        call(&app, &session, "ListAccounts", json!({}))
            .await
            .unwrap_err(),
        "AccessDeniedException"
    );
    assert!(
        call(&app, &session, "DescribeOrganization", json!({}))
            .await
            .is_ok()
    );
    crate::s3::buckets::create::create(&app, "team-a-data", &member, false)
        .await
        .unwrap();
    let bucket = || On::Bucket("team-a-data".into());
    assert_eq!(
        verdict(&app, &session, &management, "s3:ListBucket", bucket()).await,
        Verdict::Allow
    );
    assert_ne!(
        verdict(&app, &admin, &management, "s3:ListBucket", bucket()).await,
        Verdict::Allow
    );
    assert_eq!(
        crate::s3::util::bucket_owner(&client, "team-a-data")
            .await
            .unwrap(),
        member
    );

    // Identity Center: a permission set assigned there is provisioned there.
    let set = ic::create(
        &client,
        &management,
        &ic::New {
            name: "Ops",
            description: "",
            session_duration: 3600,
            relay_state: None,
            tags: None,
        },
    )
    .await
    .unwrap();
    ic::attach(
        &client,
        &set,
        "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
        true,
    )
    .await
    .unwrap();
    let profile = json!({ "Name": { "GivenName": "Grace" } });
    let grace = ic::create_user(
        &client,
        &ic::OwnUser {
            user_name: "grace",
            display_name: "Grace",
            email: None,
            profile: &profile,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        ic::assign(&client, &set, &member, ic::PrincipalType::User, grace.id)
            .await
            .unwrap(),
        Ok(())
    );
    let provisioned: Vec<String> = ic::provisions(&client, &set)
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.account)
        .collect();
    assert_eq!(provisioned, [member.as_str()]);
    let there = crate::roles::Role::load(&client, &member, &set.role_name())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        crate::roles::attached(&client, there.id)
            .await
            .unwrap()
            .len(),
        1
    );
    let eligible = ic::eligible(&client, &management, grace.id).await.unwrap();
    assert_eq!(
        (eligible.len(), eligible[0].account.as_str()),
        (1, member.as_str())
    );

    // Closed: not with buckets, nor the management account; at once, and
    // its principals are no one from then on.
    let close = |id: &str| json!({ "AccountId": id });
    assert_eq!(
        call(&app, &admin, "CloseAccount", close(&member))
            .await
            .unwrap_err(),
        "ConstraintViolationException"
    );
    crate::s3::buckets::delete::delete_bucket(&app, "team-a-data")
        .await
        .unwrap();
    assert_eq!(
        call(&app, &admin, "CloseAccount", close(&management))
            .await
            .unwrap_err(),
        "ConstraintViolationException"
    );
    assert_eq!(
        call(&app, &session, "CloseAccount", close(&member))
            .await
            .unwrap_err(),
        "AccessDeniedException"
    );
    call(&app, &admin, "CloseAccount", close(&member))
        .await
        .unwrap();
    assert_eq!(
        call(&app, &admin, "CloseAccount", close(&member))
            .await
            .unwrap_err(),
        "AccountAlreadyClosedException"
    );
    let described = call(
        &app,
        &admin,
        "DescribeAccount",
        json!({ "AccountId": member }),
    )
    .await
    .unwrap();
    assert_eq!(described["Account"]["Status"], "SUSPENDED");
    assert!(
        crate::roles::principal(&client, there.id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        assume(&app, &admin, &role).await.err().unwrap(),
        "AccessDenied"
    );
    assert!(
        ic::eligible(&client, &management, grace.id)
            .await
            .unwrap()
            .is_empty()
    );
}

/// Migration 68 (`db::ORGANIZATIONS`) makes the account there is the
/// management account, and lets the operator account's empty row go.
#[tokio::test]
async fn the_account_becomes_the_management_account() {
    let Some(pool) = crate::e2e::fresh_database_through(67).await else {
        return;
    };
    let client = pool.get().await.unwrap();
    let before: i64 = client
        .query_one("SELECT count(*) FROM accounts", &[])
        .await
        .unwrap()
        .get(0);
    let account: String = client
        .query_one("SELECT id FROM accounts WHERE NOT operator", &[])
        .await
        .unwrap()
        .get(0);
    crate::db::init(&pool, usize::MAX).await.unwrap();
    let rows: Vec<(String, bool)> = client
        .query(
            "SELECT id, management FROM accounts WHERE NOT internal",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    assert_eq!(rows, [(account.clone(), true)], "{before} before");
    assert_eq!(users::account(&client).await.unwrap(), account);
}

/// Another account's bucket, as S3's: what its bucket policy allows that
/// account, if the caller's own policies allow it too; never its policy.
#[tokio::test]
async fn other_accounts_use_buckets_as_their_policies_allow() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let management = users::account(&client).await.unwrap();
    let made = org::create(
        &client,
        &management,
        "Team E",
        "team-e@example.com",
        org::ACCESS_ROLE,
    )
    .await
    .unwrap();
    let member = made.account_id.unwrap();
    crate::s3::buckets::create::create(&app, "shared-data", &management, false)
        .await
        .unwrap();
    let reads =
        r#"{"Effect":"Allow","Action":["s3:GetObject","s3:GetBucketPolicy"],"Resource":"*"}"#;
    let erin = user(&app, &member, "erin", reads).await;
    let fred = user(&app, &member, "fred", "").await;
    let object = || On::Object("shared-data".into(), "report.csv".into());
    assert_ne!(
        verdict(&app, &erin, &management, "s3:GetObject", object()).await,
        Verdict::Allow
    );

    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{member}:root"}},"Action":["s3:GetObject","s3:GetBucketPolicy"],"Resource":["arn:aws:s3:::shared-data","arn:aws:s3:::shared-data/*"]}}]}}"#
    );
    let response =
        crate::s3::buckets::policy::put_bucket_policy(&app, "shared-data", policy.into())
            .await
            .unwrap();
    assert!(response.status().is_success(), "{:?}", response.status());
    assert_eq!(
        verdict(&app, &erin, &management, "s3:GetObject", object()).await,
        Verdict::Allow
    );
    // Both must allow it: Fred's own policies don't.
    assert_ne!(
        verdict(&app, &fred, &management, "s3:GetObject", object()).await,
        Verdict::Allow
    );
    assert_ne!(
        verdict(&app, &erin, &management, "s3:PutObject", object()).await,
        Verdict::Allow
    );
    // A bucket's policy is its own account's, whatever it allows (S3's 405).
    let origin = Origin {
        peer: None,
        trusted_proxies: &[],
        signed: None,
        form: false,
    };
    let mut access = Access::new(
        Some(&erin),
        &erin.account,
        &Method::GET,
        &HeaderMap::new(),
        "",
        &origin,
    )
    .unwrap();
    access.load(&app, "shared-data").await.unwrap();
    assert!(access.foreign(&Check {
        action: "s3:GetBucketPolicy",
        on: On::Bucket("shared-data".into())
    }));
}

/// Organizational units and service control policies, as AWS
/// Organizations has them: a member account in a unit, under SCPs at every
/// level from the root; the management account under none.
#[tokio::test]
async fn service_control_policies_cap_member_accounts() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let management = users::account(&client).await.unwrap();
    let admin = user(&app, &management, "admin", ADMIN).await;
    let made = org::create(
        &client,
        &management,
        "Team F",
        "team-f@example.com",
        org::ACCESS_ROLE,
    )
    .await
    .unwrap();
    let member = made.account_id.unwrap();
    let gina = user(&app, &member, "gina", ADMIN).await;
    crate::s3::buckets::create::create(&app, "team-f-data", &member, false)
        .await
        .unwrap();
    let reload = |p: &Principal| {
        let (app, id) = (app.clone(), p.id);
        async move {
            Principal::load_user(&app.pool.get().await.unwrap(), id)
                .await
                .unwrap()
                .unwrap()
        }
    };
    let get = || On::Object("team-f-data".into(), "k".into());
    let delete = || On::Bucket("team-f-data".into());

    // The root, and units under it.
    let roots = call(&app, &admin, "ListRoots", json!({})).await.unwrap();
    let root = roots["Roots"][0]["Id"].as_str().unwrap().to_owned();
    assert_eq!(roots["Roots"][0]["PolicyTypes"], json!([]));
    let unit = |name: &str, parent: &str| json!({ "Name": name, "ParentId": parent });
    let teams = call(
        &app,
        &admin,
        "CreateOrganizationalUnit",
        unit("Teams", &root),
    )
    .await
    .unwrap();
    let teams = teams["OrganizationalUnit"]["Id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        call(
            &app,
            &admin,
            "CreateOrganizationalUnit",
            unit("Teams", &root)
        )
        .await
        .unwrap_err(),
        "DuplicateOrganizationalUnitException"
    );
    let prod = call(
        &app,
        &admin,
        "CreateOrganizationalUnit",
        unit("Prod", &teams),
    )
    .await
    .unwrap();
    assert!(
        prod["OrganizationalUnit"]["Path"]
            .as_str()
            .unwrap()
            .ends_with(&format!(
                "{root}/{teams}/{}/",
                prod["OrganizationalUnit"]["Id"].as_str().unwrap()
            ))
    );
    let prod = prod["OrganizationalUnit"]["Id"]
        .as_str()
        .unwrap()
        .to_owned();
    // Five deep at most.
    let mut parent = prod.clone();
    for depth in 3..=5 {
        parent = call(
            &app,
            &admin,
            "CreateOrganizationalUnit",
            unit(&format!("L{depth}"), &parent),
        )
        .await
        .unwrap()["OrganizationalUnit"]["Id"]
            .as_str()
            .unwrap()
            .to_owned();
    }
    assert_eq!(
        call(
            &app,
            &admin,
            "CreateOrganizationalUnit",
            unit("L6", &parent)
        )
        .await
        .unwrap_err(),
        "ConstraintViolationException"
    );

    // The member account moves into Prod.
    let moving = |from: &str, to: &str| json!({ "AccountId": member, "SourceParentId": from, "DestinationParentId": to });
    assert_eq!(
        call(&app, &admin, "MoveAccount", moving(&teams, &prod))
            .await
            .unwrap_err(),
        "SourceParentNotFoundException"
    );
    call(&app, &admin, "MoveAccount", moving(&root, &prod))
        .await
        .unwrap();
    let parents = call(&app, &admin, "ListParents", json!({ "ChildId": member }))
        .await
        .unwrap();
    assert_eq!(
        parents["Parents"],
        json!([{ "Id": prod, "Type": "ORGANIZATIONAL_UNIT" }])
    );
    let children = call(
        &app,
        &admin,
        "ListChildren",
        json!({ "ParentId": prod, "ChildType": "ACCOUNT" }),
    )
    .await
    .unwrap();
    assert_eq!(
        children["Children"],
        json!([{ "Id": member, "Type": "ACCOUNT" }])
    );
    assert_eq!(
        call(
            &app,
            &admin,
            "DeleteOrganizationalUnit",
            json!({ "OrganizationalUnitId": prod })
        )
        .await
        .unwrap_err(),
        "OrganizationalUnitNotEmptyException"
    );

    // SCPs: none until enabled; then FullAWSAccess everywhere.
    let deny_delete = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"}]}"#;
    let new_policy = |name: &str, content: &str| json!({ "Name": name, "Description": "", "Type": "SERVICE_CONTROL_POLICY", "Content": content });
    let made = call(
        &app,
        &admin,
        "CreatePolicy",
        new_policy("NoDeletes", deny_delete),
    )
    .await
    .unwrap();
    let no_deletes = made["Policy"]["PolicySummary"]["Id"]
        .as_str()
        .unwrap()
        .to_owned();
    let attach = |policy: &str, target: &str| json!({ "PolicyId": policy, "TargetId": target });
    assert_eq!(
        call(&app, &admin, "AttachPolicy", attach(&no_deletes, &prod))
            .await
            .unwrap_err(),
        "PolicyTypeNotEnabledException"
    );
    let enable = json!({ "RootId": root, "PolicyType": "SERVICE_CONTROL_POLICY" });
    let enabled = call(&app, &admin, "EnablePolicyType", enable.clone())
        .await
        .unwrap();
    assert_eq!(enabled["Root"]["PolicyTypes"][0]["Status"], "ENABLED");
    assert_eq!(
        call(&app, &admin, "EnablePolicyType", enable.clone())
            .await
            .unwrap_err(),
        "PolicyTypeAlreadyEnabledException"
    );
    let on = |target: &str| json!({ "TargetId": target, "Filter": "SERVICE_CONTROL_POLICY" });
    for target in [&root, &teams, &prod, &member] {
        let listed = call(&app, &admin, "ListPoliciesForTarget", on(target))
            .await
            .unwrap();
        assert_eq!(listed["Policies"][0]["Id"], "p-FullAWSAccess", "{target}");
    }
    assert_eq!(
        verdict(
            &app,
            &reload(&gina).await,
            &management,
            "s3:DeleteBucket",
            delete()
        )
        .await,
        Verdict::Allow
    );

    // A Deny on a unit on the way denies, whatever IAM allows.
    call(&app, &admin, "AttachPolicy", attach(&no_deletes, &teams))
        .await
        .unwrap();
    assert_eq!(
        call(&app, &admin, "AttachPolicy", attach(&no_deletes, &teams))
            .await
            .unwrap_err(),
        "DuplicatePolicyAttachmentException"
    );
    let gina = reload(&gina).await;
    assert_eq!(
        verdict(&app, &gina, &management, "s3:DeleteBucket", delete()).await,
        Verdict::ScpDeny
    );
    assert_eq!(
        verdict(&app, &gina, &management, "s3:GetObject", get()).await,
        Verdict::Allow
    );
    // The management account is under none.
    assert_eq!(
        verdict(
            &app,
            &admin,
            &management,
            "s3:DeleteBucket",
            On::Bucket("anything".into())
        )
        .await,
        Verdict::Allow
    );
    // Nor may its sessions assume past them.
    let assumed = assume(
        &app,
        &admin,
        &format!("arn:aws:iam::{member}:role/{}", org::ACCESS_ROLE),
    )
    .await
    .unwrap();
    assert_eq!(
        verdict(&app, &assumed, &management, "s3:DeleteBucket", delete()).await,
        Verdict::ScpDeny
    );

    // An allow-list: Prod's FullAWSAccess replaced by S3 reads only.
    let reads = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:Get*","s3:List*"],"Resource":"*"}]}"#;
    assert_eq!(
        call(&app, &admin, "CreatePolicy", new_policy("NoDeletes", reads))
            .await
            .unwrap_err(),
        "DuplicatePolicyException"
    );
    let bad = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::x"}]}"#;
    assert_eq!(
        call(&app, &admin, "CreatePolicy", new_policy("Bad", bad))
            .await
            .unwrap_err(),
        "MalformedPolicyDocumentException"
    );
    let made = call(&app, &admin, "CreatePolicy", new_policy("ReadsOnly", reads))
        .await
        .unwrap();
    let reads_only = made["Policy"]["PolicySummary"]["Id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        call(
            &app,
            &admin,
            "DetachPolicy",
            attach("p-FullAWSAccess", &prod)
        )
        .await
        .unwrap_err(),
        "ConstraintViolationException"
    );
    call(&app, &admin, "AttachPolicy", attach(&reads_only, &prod))
        .await
        .unwrap();
    call(
        &app,
        &admin,
        "DetachPolicy",
        attach("p-FullAWSAccess", &prod),
    )
    .await
    .unwrap();
    let gina = reload(&gina).await;
    assert_eq!(
        verdict(&app, &gina, &management, "s3:GetObject", get()).await,
        Verdict::Allow
    );
    assert_eq!(
        verdict(&app, &gina, &management, "s3:PutObject", get()).await,
        Verdict::OutsideScp
    );
    let targets = call(
        &app,
        &admin,
        "ListTargetsForPolicy",
        json!({ "PolicyId": reads_only }),
    )
    .await
    .unwrap();
    assert_eq!(
        (
            &targets["Targets"][0]["TargetId"],
            &targets["Targets"][0]["Type"]
        ),
        (&json!(prod), &json!("ORGANIZATIONAL_UNIT"))
    );
    assert_eq!(
        call(
            &app,
            &admin,
            "DeletePolicy",
            json!({ "PolicyId": reads_only })
        )
        .await
        .unwrap_err(),
        "PolicyInUseException"
    );

    // Disabled, all of them come off.
    call(&app, &admin, "DisablePolicyType", enable)
        .await
        .unwrap();
    let gina = reload(&gina).await;
    assert!(gina.scps.is_empty());
    assert_eq!(
        verdict(&app, &gina, &management, "s3:PutObject", get()).await,
        Verdict::Allow
    );
    call(
        &app,
        &admin,
        "DeletePolicy",
        json!({ "PolicyId": reads_only }),
    )
    .await
    .unwrap();
    // A member account's principals may not change the organization.
    assert_eq!(
        call(&app, &gina, "ListRoots", json!({})).await.unwrap_err(),
        "AccessDeniedException"
    );
}
