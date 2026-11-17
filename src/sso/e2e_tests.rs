//! sso-admin and identitystore against a real Postgres: the identity store
//! as sign-ins fill it, permission sets and their policies as their roles,
//! assignments by principal ID, and who may do what.

use std::sync::Arc;

use hyper::{HeaderMap, Method};
use serde_json::{Value, json};

use super::*;
use crate::{e2e::node_with, packer, users};

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

/// A user named `name` (made unique), with the identity policy
/// `statements` (none, if empty).
async fn user(app: &App, name: &str, statements: &str) -> Principal {
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let name = format!("{name}-{}", &Uuid::new_v4().simple().to_string()[..8]);
    let (key, _) = users::create_for(&client, &account, &name, None, false).await.unwrap();
    if !statements.is_empty() {
        let policy = format!(r#"{{"Version":"2012-10-17","Statement":[{statements}]}}"#);
        users::put_policy(&client, &account, &name, "p", &policy).await.unwrap();
    }
    Principal::load(&client, &key).await.unwrap().unwrap()
}

/// What `principal` was answered for `operation` of `service` with `input`:
/// its answer, or its error's code.
async fn call(app: &App, principal: &Principal, service: &str, operation: &str, input: Value) -> std::result::Result<Value, String> {
    let client = app.pool.get().await.unwrap();
    let origin = Origin { peer: None, trusted_proxies: &[], signed: None, form: false };
    let mut access = Access::new(Some(principal), &principal.account, &Method::POST, &HeaderMap::new(), "", &origin).unwrap();
    let ops = if service == "sso" { SSO } else { IDENTITY_STORE };
    let (operation, action) = *ops.iter().find(|(op, _)| *op == operation).unwrap_or_else(|| panic!("no {operation}"));
    dispatch(&client, principal, &mut access, service, operation, action, &input).await.map_err(|e| e.code.to_owned())
}

/// An identity source, `mock`, as an operator would set one up (unchecked:
/// these tests don't sign in through it).
async fn source(app: &App) {
    let client = app.pool.get().await.unwrap();
    client
        .execute(
            "INSERT INTO oidc_providers (name, label, issuer, client_id) VALUES ('mock', 'Mock', 'https://idp.example', 'c')",
            &[],
        )
        .await
        .unwrap();
}

const ADMIN: &str = r#"{"Effect":"Allow","Action":"*","Resource":"*"}"#;

/// The identity store is what sign-ins said: users by their user name or
/// external ID, groups by their name, memberships replaced at each sign-in.
#[tokio::test]
async fn the_identity_store_is_what_sign_ins_said() {
    let Some(app) = node().await else { return };
    source(&app).await;
    let client = app.pool.get().await.unwrap();
    let admin = user(&app, "admin", ADMIN).await;
    let account = admin.account.clone();
    let store = ic::identity_store_id(&account);
    let ada = ic::signed_in(&client, "mock", "sub-ada", "Ada", Some("ada"), Some("ada@example.com"), &["data".into(), "ops".into()])
        .await
        .unwrap();
    // Another with the same preferred user name gets the next free one.
    let other = ic::signed_in(&client, "mock", "sub-other", "Other", Some("ada"), Some("other@example.com"), &[]).await.unwrap();
    let ids = |v: &Value, field: &str| v[field].as_str().unwrap().to_owned();

    let by_name = |name: &str| json!({ "IdentityStoreId": store, "AlternateIdentifier": { "UniqueAttribute": { "AttributePath": "UserName", "AttributeValue": name } } });
    assert_eq!(ids(&call(&app, &admin, "identitystore", "GetUserId", by_name("ada")).await.unwrap(), "UserId"), ada.to_string());
    assert_eq!(ids(&call(&app, &admin, "identitystore", "GetUserId", by_name("other@example.com")).await.unwrap(), "UserId"), other.to_string());
    let external = json!({ "IdentityStoreId": store, "AlternateIdentifier": { "ExternalId": { "Issuer": "https://idp.example/", "Id": "sub-ada" } } });
    assert_eq!(ids(&call(&app, &admin, "identitystore", "GetUserId", external).await.unwrap(), "UserId"), ada.to_string());
    assert_eq!(call(&app, &admin, "identitystore", "GetUserId", by_name("nobody")).await.unwrap_err(), "ResourceNotFoundException");
    let elsewhere = json!({ "IdentityStoreId": "d-0000000000", "UserId": ada.to_string() });
    assert_eq!(call(&app, &admin, "identitystore", "DescribeUser", elsewhere).await.unwrap_err(), "ResourceNotFoundException");
    let described = call(&app, &admin, "identitystore", "DescribeUser", json!({ "IdentityStoreId": store, "UserId": ada.to_string() })).await.unwrap();
    assert_eq!((&described["UserName"], &described["Emails"][0]["Value"]), (&json!("ada"), &json!("ada@example.com")));
    assert_eq!(described["ExternalIds"], json!([{ "Issuer": "https://idp.example", "Id": "sub-ada" }]));

    let group = |name: &str| json!({ "IdentityStoreId": store, "AlternateIdentifier": { "UniqueAttribute": { "AttributePath": "DisplayName", "AttributeValue": name } } });
    let data = ids(&call(&app, &admin, "identitystore", "GetGroupId", group("data")).await.unwrap(), "GroupId");
    let ops = ids(&call(&app, &admin, "identitystore", "GetGroupId", group("ops")).await.unwrap(), "GroupId");
    let members = call(&app, &admin, "identitystore", "ListGroupMemberships", json!({ "IdentityStoreId": store, "GroupId": data })).await.unwrap();
    assert_eq!(members["GroupMemberships"][0]["MemberId"]["UserId"], json!(ada.to_string()));
    // Signing in again, in `data` only: no longer in `ops`.
    ic::signed_in(&client, "mock", "sub-ada", "Ada L.", None, Some("ada@example.com"), &["data".into()]).await.unwrap();
    let check = json!({ "IdentityStoreId": store, "MemberId": { "UserId": ada.to_string() }, "GroupIds": [data, ops] });
    let results = call(&app, &admin, "identitystore", "IsMemberInGroups", check).await.unwrap();
    assert_eq!(results["Results"][0]["MembershipExists"], true);
    assert_eq!(results["Results"][1]["MembershipExists"], false);
    // Its user name stays as it was made.
    let described = call(&app, &admin, "identitystore", "DescribeUser", json!({ "IdentityStoreId": store, "UserId": ada.to_string() })).await.unwrap();
    assert_eq!((&described["UserName"], &described["DisplayName"]), (&json!("ada"), &json!("Ada L.")));

    // Only to whom identitystore's actions are allowed.
    let nobody = user(&app, "nobody", "").await;
    assert_eq!(call(&app, &nobody, "identitystore", "ListUsers", json!({ "IdentityStoreId": store })).await.unwrap_err(), "AccessDeniedException");
}

/// sso-admin's permission sets are their roles, and its assignments decide
/// who may use them; what it does is done when it answers.
#[tokio::test]
async fn permission_sets_and_assignments() {
    let Some(app) = node().await else { return };
    source(&app).await;
    let client = app.pool.get().await.unwrap();
    let admin = Arc::new(user(&app, "admin", ADMIN).await);
    let account = admin.account.clone();
    let instance = ic::instance_arn(&account);
    let sso = |operation: &'static str, input: Value| {
        let (app, admin) = (app.clone(), admin.clone());
        async move { call(&app, &admin, "sso", operation, input).await }
    };
    let ada = ic::signed_in(&client, "mock", "sub-ada", "Ada", None, None, &["data".into()]).await.unwrap();
    let data = ic::groups(&client, Some(Lookup::Name("data"))).await.unwrap().pop().unwrap().id;

    let made = sso("CreatePermissionSet", json!({ "InstanceArn": instance, "Name": "Readers", "SessionDuration": "PT2H" })).await.unwrap();
    let set = made["PermissionSet"]["PermissionSetArn"].as_str().unwrap().to_owned();
    assert_eq!(made["PermissionSet"]["SessionDuration"], "PT2H");
    let on = |extra: Value| {
        let mut input = json!({ "InstanceArn": instance, "PermissionSetArn": set });
        input.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        input
    };
    assert_eq!(sso("CreatePermissionSet", json!({ "InstanceArn": instance, "Name": "Readers" })).await.unwrap_err(), "ConflictException");
    assert_eq!(sso("CreatePermissionSet", json!({ "InstanceArn": "arn:aws:sso:::instance/ssoins-0000000000000000", "Name": "X" })).await.unwrap_err(), "ResourceNotFoundException");
    assert_eq!(sso("UpdatePermissionSet", on(json!({ "SessionDuration": "PT13H" }))).await.unwrap_err(), "ValidationException");

    // Its policies are its own: AWS's managed, customer managed by
    // reference, inline, and a boundary. Made, it's provisioned nowhere.
    assert_eq!(sso("ListAccountsForProvisionedPermissionSet", on(json!({}))).await.unwrap()["AccountIds"], json!([]));
    sso("AttachManagedPolicyToPermissionSet", on(json!({ "ManagedPolicyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess" }))).await.unwrap();
    let aws = json!({ "ManagedPolicyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess" });
    assert_eq!(sso("AttachManagedPolicyToPermissionSet", on(aws)).await.unwrap_err(), "ConflictException");
    let unknown = json!({ "ManagedPolicyArn": "arn:aws:iam::aws:policy/NoSuchPolicy" });
    assert_eq!(sso("AttachManagedPolicyToPermissionSet", on(unknown)).await.unwrap_err(), "ResourceNotFoundException");
    let own = format!("arn:aws:iam::{account}:policy/teams/list");
    let document = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}"#;
    crate::managed::create(&client, &account, "list", "/teams/", document, "").await.unwrap();
    assert_eq!(sso("AttachManagedPolicyToPermissionSet", on(json!({ "ManagedPolicyArn": own }))).await.unwrap_err(), "ValidationException");
    let reference = json!({ "CustomerManagedPolicyReference": { "Name": "list", "Path": "/teams/" } });
    sso("AttachCustomerManagedPolicyReferenceToPermissionSet", on(reference.clone())).await.unwrap();
    assert_eq!(sso("AttachCustomerManagedPolicyReferenceToPermissionSet", on(reference)).await.unwrap_err(), "ConflictException");
    sso("PutInlinePolicyToPermissionSet", on(json!({ "InlinePolicy": document }))).await.unwrap();
    assert_eq!(sso("PutInlinePolicyToPermissionSet", on(json!({ "InlinePolicy": "{" }))).await.unwrap_err(), "ValidationException");
    sso("PutPermissionsBoundaryToPermissionSet", on(json!({ "PermissionsBoundary": { "CustomerManagedPolicyReference": { "Name": "list", "Path": "/teams/" } } })))
        .await
        .unwrap();
    let boundary = sso("GetPermissionsBoundaryForPermissionSet", on(json!({}))).await.unwrap();
    assert_eq!(boundary["PermissionsBoundary"]["CustomerManagedPolicyReference"], json!({ "Name": "list", "Path": "/teams/" }));
    let references = sso("ListCustomerManagedPolicyReferencesInPermissionSet", on(json!({}))).await.unwrap();
    assert_eq!(references["CustomerManagedPolicyReferences"], json!([{ "Name": "list", "Path": "/teams/" }]));
    let managed = sso("ListManagedPoliciesInPermissionSet", on(json!({}))).await.unwrap();
    assert_eq!(managed["AttachedManagedPolicies"][0]["Name"], "AmazonS3ReadOnlyAccess");
    let read = ic::load_arn(&client, &account, &set).await.unwrap().unwrap();
    assert!(ic::provisions(&client, &read).await.unwrap().is_empty());

    // A reference needn't name a policy until the set is provisioned: the
    // account must have it then, or the assignment that provisions it fails.
    let missing = json!({ "CustomerManagedPolicyReference": { "Name": "nope" } });
    sso("AttachCustomerManagedPolicyReferenceToPermissionSet", on(missing.clone())).await.unwrap();
    let target = |kind: &str, id: String| on(json!({ "TargetId": account, "TargetType": "AWS_ACCOUNT", "PrincipalType": kind, "PrincipalId": id }));
    let failed = sso("CreateAccountAssignment", target("GROUP", data.to_string())).await.unwrap();
    assert_eq!(failed["AccountAssignmentCreationStatus"]["Status"], "FAILED");
    assert!(failed["AccountAssignmentCreationStatus"]["FailureReason"].as_str().unwrap().contains("/nope"), "{failed}");
    assert!(ic::assignments(&client, &account, None, None, None).await.unwrap().is_empty());
    assert!(ic::provisions(&client, &read).await.unwrap().is_empty());
    sso("DetachCustomerManagedPolicyReferenceFromPermissionSet", on(missing.clone())).await.unwrap();
    assert_eq!(sso("DetachCustomerManagedPolicyReferenceFromPermissionSet", on(missing)).await.unwrap_err(), "ResourceNotFoundException");

    // Assigned to a group, by its ID: done when answered, and provisioned
    // to the account, its role there holding what the set does.
    let made = sso("CreateAccountAssignment", target("GROUP", data.to_string())).await.unwrap();
    let request = made["AccountAssignmentCreationStatus"]["RequestId"].as_str().unwrap().to_owned();
    assert_eq!(made["AccountAssignmentCreationStatus"]["Status"], "SUCCEEDED");
    let status = sso("DescribeAccountAssignmentCreationStatus", json!({ "InstanceArn": instance, "AccountAssignmentCreationRequestId": request })).await.unwrap();
    assert_eq!(status["AccountAssignmentCreationStatus"]["PrincipalId"], json!(data.to_string()));
    // Again: still done.
    assert_eq!(sso("CreateAccountAssignment", target("GROUP", data.to_string())).await.unwrap()["AccountAssignmentCreationStatus"]["Status"], "SUCCEEDED");
    assert_eq!(sso("CreateAccountAssignment", target("USER", data.to_string())).await.unwrap_err(), "ResourceNotFoundException");
    let mut elsewhere = target("GROUP", data.to_string());
    elsewhere["TargetId"] = json!("111111111111");
    assert_eq!(sso("CreateAccountAssignment", elsewhere).await.unwrap_err(), "ValidationException");
    // In the account it targeted, as the set's role there.
    assert_eq!(status["AccountAssignmentCreationStatus"]["TargetId"], json!(account));
    let provisions = ic::provisions(&client, &read).await.unwrap();
    assert_eq!((provisions.len(), provisions[0].latest), (1, true));
    let role = crate::roles::Role::load_id(&client, provisions[0].role_id).await.unwrap().unwrap();
    assert_eq!(role.name, read.role_name());
    assert_eq!(role.max_session_duration, 7200);
    assert_eq!(role.boundary.as_deref(), Some(own.as_str()));
    assert_eq!(crate::roles::attached(&client, role.id).await.unwrap().len(), 2);
    assert_eq!(crate::roles::get_policy(&client, role.id, ic::INLINE_POLICY).await.unwrap().as_deref(), Some(document));
    let eligible = ic::eligible(&client, &account, ada).await.unwrap();
    let pairs: Vec<(&str, &str)> = eligible.iter().map(|e| (e.account.as_str(), e.set.name.as_str())).collect();
    assert_eq!(pairs, [(account.as_str(), "Readers")]);
    assert_eq!(eligible[0].role_id, role.id);
    let listed = sso("ListAccountAssignments", on(json!({ "AccountId": account }))).await.unwrap();
    assert_eq!(listed["AccountAssignments"][0]["PrincipalType"], "GROUP");
    assert_eq!(listed["AccountAssignments"][0]["AccountId"], json!(account));
    let principal = json!({ "InstanceArn": instance, "PrincipalType": "GROUP", "PrincipalId": data.to_string() });
    let mine = sso("ListAccountAssignmentsForPrincipal", principal.clone()).await.unwrap();
    assert_eq!(mine["AccountAssignments"].as_array().unwrap().len(), 1);
    let mut filtered = principal;
    filtered["Filter"] = json!({ "AccountId": "111111111111" });
    assert_eq!(sso("ListAccountAssignmentsForPrincipal", filtered).await.unwrap()["AccountAssignments"], json!([]));
    let provisioned = sso("ListPermissionSetsProvisionedToAccount", json!({ "InstanceArn": instance, "AccountId": account })).await.unwrap();
    assert_eq!(provisioned["PermissionSets"], json!([set]));
    let accounts = sso("ListAccountsForProvisionedPermissionSet", on(json!({}))).await.unwrap();
    assert_eq!(accounts["AccountIds"], json!([account]));

    // Changed, its role keeps what it held until it's provisioned again.
    sso("UpdatePermissionSet", on(json!({ "SessionDuration": "PT3H" }))).await.unwrap();
    sso("DeleteInlinePolicyFromPermissionSet", on(json!({}))).await.unwrap();
    sso("DeletePermissionsBoundaryFromPermissionSet", on(json!({}))).await.unwrap();
    let stale = json!({ "InstanceArn": instance, "AccountId": account, "ProvisioningStatus": "LATEST_PERMISSION_SET_NOT_PROVISIONED" });
    assert_eq!(sso("ListPermissionSetsProvisionedToAccount", stale.clone()).await.unwrap()["PermissionSets"], json!([set]));
    let role = crate::roles::Role::load_id(&client, role.id).await.unwrap().unwrap();
    assert_eq!((role.max_session_duration, role.boundary.is_some()), (7200, true));
    assert!(crate::roles::get_policy(&client, role.id, ic::INLINE_POLICY).await.unwrap().is_some());
    let provision = sso("ProvisionPermissionSet", on(json!({ "TargetType": "AWS_ACCOUNT", "TargetId": account }))).await.unwrap();
    assert_eq!(provision["PermissionSetProvisioningStatus"]["Status"], "SUCCEEDED");
    assert_eq!(provision["PermissionSetProvisioningStatus"]["AccountId"], json!(account));
    let role = crate::roles::Role::load_id(&client, role.id).await.unwrap().unwrap();
    assert_eq!((role.max_session_duration, role.boundary), (10800, None));
    assert!(crate::roles::get_policy(&client, role.id, ic::INLINE_POLICY).await.unwrap().is_none());
    assert_eq!(sso("ListPermissionSetsProvisionedToAccount", stale).await.unwrap()["PermissionSets"], json!([]));
    let provision = sso("ProvisionPermissionSet", on(json!({ "TargetType": "ALL_PROVISIONED_ACCOUNTS" }))).await.unwrap();
    assert_eq!(provision["PermissionSetProvisioningStatus"]["Status"], "SUCCEEDED");

    // Tags, and pages.
    sso("TagResource", json!({ "InstanceArn": instance, "ResourceArn": set, "Tags": [{ "Key": "team", "Value": "data" }] })).await.unwrap();
    let tags = sso("ListTagsForResource", json!({ "InstanceArn": instance, "ResourceArn": set })).await.unwrap();
    assert_eq!(tags["Tags"], json!([{ "Key": "team", "Value": "data" }]));
    sso("CreatePermissionSet", json!({ "InstanceArn": instance, "Name": "Admins" })).await.unwrap();
    let page = sso("ListPermissionSets", json!({ "InstanceArn": instance, "MaxResults": 1 })).await.unwrap();
    assert_eq!(page["PermissionSets"].as_array().unwrap().len(), 1);
    let rest = sso("ListPermissionSets", json!({ "InstanceArn": instance, "MaxResults": 1, "NextToken": page["NextToken"] })).await.unwrap();
    assert!(rest.get("NextToken").is_none());

    // Unassigned: its users lose it; deleted: its role goes.
    let deleted = sso("DeleteAccountAssignment", target("GROUP", data.to_string())).await.unwrap();
    assert_eq!(deleted["AccountAssignmentDeletionStatus"]["Status"], "SUCCEEDED");
    assert!(ic::eligible(&client, &account, ada).await.unwrap().is_empty());
    sso("DeletePermissionSet", on(json!({}))).await.unwrap();
    assert!(crate::roles::Role::load_id(&client, role.id).await.unwrap().is_none());
    assert_eq!(sso("DescribePermissionSet", on(json!({}))).await.unwrap_err(), "ResourceNotFoundException");

    // Only to whom sso's actions are allowed: on the instance, or the set.
    let viewer = user(&app, "viewer", r#"{"Effect":"Allow","Action":["sso:ListPermissionSets","sso:ListInstances"],"Resource":"*"}"#).await;
    assert!(call(&app, &viewer, "sso", "ListPermissionSets", json!({ "InstanceArn": instance })).await.is_ok());
    let create = json!({ "InstanceArn": instance, "Name": "Mine" });
    assert_eq!(call(&app, &viewer, "sso", "CreatePermissionSet", create).await.unwrap_err(), "AccessDeniedException");
}

/// Migration 65 (`db::PERMISSION_SET_ACCOUNTS`) provisions each permission
/// set to its own account, as the role it had, and has its assignments,
/// the console's sessions acting as it and sso-admin's requests target that
/// account; migration 66 (`db::PERMISSION_SET_DEFINITIONS`) has the set
/// hold what its role did, as its latest version.
#[tokio::test]
async fn permission_sets_are_provisioned_to_their_account() {
    let Some(pool) = crate::e2e::fresh_database_through(64).await else { return };
    let client = pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    client
        .batch_execute(&format!(
            "INSERT INTO oidc_providers (name, label, issuer, client_id) VALUES ('mock', 'Mock', 'https://idp.example', 'c');
             INSERT INTO identity_users (id, provider, subject, user_name, display_name)
                 VALUES ('00000000-0000-4000-8000-000000000001', 'mock', 'sub-ada', 'ada', 'Ada');
             INSERT INTO iam_roles (id, account_id, name, path, trust_policy)
                 VALUES ('00000000-0000-4000-8000-000000000002', '{account}', 'AWSReservedSSO_Readers_0123456789abcdef',
                         '/aws-reserved/sso.amazonaws.com/',
                         '{{\"Version\":\"2012-10-17\",\"Statement\":[{{\"Effect\":\"Allow\",\"Principal\":{{\"Service\":\"sso.amazonaws.com\"}},\"Action\":\"sts:AssumeRole\"}}]}}');
             INSERT INTO permission_sets (id, account_id, short_id, name, session_duration, role_id)
                 VALUES ('00000000-0000-4000-8000-000000000003', '{account}', '0123456789abcdef', 'Readers', 3600,
                         '00000000-0000-4000-8000-000000000002');
             INSERT INTO iam_role_policies (role_id, name, document)
                 VALUES ('00000000-0000-4000-8000-000000000002', 'AwsSSOInlinePolicy',
                         '{{\"Version\":\"2012-10-17\",\"Statement\":[{{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"*\"}}]}}');
             INSERT INTO iam_role_attached_policies (role_id, aws_policy)
                 VALUES ('00000000-0000-4000-8000-000000000002', 'AmazonS3ReadOnlyAccess');
             UPDATE iam_roles SET boundary_aws = 'AmazonS3ReadOnlyAccess' WHERE id = '00000000-0000-4000-8000-000000000002';
             INSERT INTO permission_set_assignments (permission_set_id, user_id)
                 VALUES ('00000000-0000-4000-8000-000000000003', '00000000-0000-4000-8000-000000000001');
             INSERT INTO console_directory_sessions (token_hash, account_id, user_id, permission_set_id, expires_at)
                 VALUES ('\\x01', '{account}', '00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000003',
                         now() + interval '1 hour'),
                        ('\\x02', '{account}', '00000000-0000-4000-8000-000000000001', NULL, now() + interval '1 hour');
             INSERT INTO sso_operations (request_id, account_id, kind, permission_set_arn, status)
                 VALUES ('00000000-0000-4000-8000-000000000004', '{account}', 'PROVISION', 'arn', 'SUCCEEDED');"
        ))
        .await
        .unwrap();
    crate::db::init(&pool, usize::MAX).await.unwrap();

    let set = ic::load(&client, &account, "Readers").await.unwrap().unwrap();
    let role = Uuid::parse_str("00000000-0000-4000-8000-000000000002").unwrap();
    let provisions = ic::provisions(&client, &set).await.unwrap();
    let provisioned: Vec<(&str, Uuid, bool)> = provisions.iter().map(|p| (p.account.as_str(), p.role_id, p.latest)).collect();
    assert_eq!(provisioned, [(account.as_str(), role, true)]);
    assert!(ic::inline_policy(&client, &set).await.unwrap().unwrap().contains("s3:ListAllMyBuckets"));
    let attached: Vec<String> = ic::managed_policies(&client, &set).await.unwrap().into_iter().map(|a| a.name).collect();
    assert_eq!(attached, ["AmazonS3ReadOnlyAccess"]);
    assert_eq!(ic::boundary(&client, &set).await.unwrap().as_deref(), Some("arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"));
    // Provisioned again, its role holds the same.
    assert_eq!(ic::provision(&client, &set, &account).await.unwrap(), Ok(()));
    assert_eq!(crate::roles::attached(&client, role).await.unwrap().len(), 1);
    let assigned: Vec<String> = ic::assignments(&client, &account, None, None, None).await.unwrap().into_iter().map(|a| a.account).collect();
    assert_eq!(assigned, std::slice::from_ref(&account));
    let user = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
    assert_eq!(ic::eligible(&client, &account, user).await.unwrap()[0].role_id, role);
    let sessions: Vec<(Option<Uuid>, Option<String>)> = client
        .query("SELECT permission_set_id, target_account_id FROM console_directory_sessions ORDER BY token_hash", &[])
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    assert_eq!(sessions, [(Some(set.id), Some(account.clone())), (None, None)]);
    let ops = ic::operations(&client, &account, OperationKind::Provision, None, None).await.unwrap();
    assert_eq!(ops[0].target.as_deref(), Some(account.as_str()));

    // Deleted, the set's sessions act as nothing, in no account.
    ic::delete(&client, &set).await.unwrap();
    let left: (Option<Uuid>, Option<String>) = client
        .query_one("SELECT permission_set_id, target_account_id FROM console_directory_sessions WHERE token_hash = '\\x01'", &[])
        .await
        .map(|r| (r.get(0), r.get(1)))
        .unwrap();
    assert_eq!(left, (None, None));
}

/// identitystore's writes make and change Cairn's own directory's users,
/// groups and memberships, as Identity Center's; an identity source's are
/// what its sign-ins say.
#[tokio::test]
async fn own_directory_users_and_groups() {
    let Some(app) = node().await else { return };
    source(&app).await;
    let client = app.pool.get().await.unwrap();
    let admin = Arc::new(user(&app, "admin", ADMIN).await);
    let store = ic::identity_store_id(&admin.account);
    let ids = |operation: &'static str, input: Value| {
        let (app, admin, store) = (app.clone(), admin.clone(), store.clone());
        async move {
            let mut input = input;
            input["IdentityStoreId"] = json!(store);
            call(&app, &admin, "identitystore", operation, input).await
        }
    };

    // Users: UserName, DisplayName and Name are required, some names reserved.
    let ada = json!({ "UserName": "ada", "DisplayName": "Ada Lovelace", "Name": { "GivenName": "Ada", "FamilyName": "Lovelace" },
                      "Emails": [{ "Value": "ada@example.com", "Type": "work", "Primary": true }] });
    assert_eq!(ids("CreateUser", json!({ "UserName": "x", "DisplayName": "X" })).await.unwrap_err(), "ValidationException");
    let mut reserved = ada.clone();
    reserved["UserName"] = json!("Administrator");
    assert_eq!(ids("CreateUser", reserved).await.unwrap_err(), "ValidationException");
    let mut spaced = ada.clone();
    spaced["UserName"] = json!("ada l");
    assert_eq!(ids("CreateUser", spaced).await.unwrap_err(), "ValidationException");
    let made = ids("CreateUser", ada.clone()).await.unwrap();
    assert_eq!(made["Revision"], "1");
    let ada_id = made["UserId"].as_str().unwrap().to_owned();
    assert_eq!(ids("CreateUser", ada).await.unwrap_err(), "ConflictException");
    let described = ids("DescribeUser", json!({ "UserId": ada_id })).await.unwrap();
    assert_eq!(described["Name"]["GivenName"], "Ada");
    assert_eq!(described["Emails"][0]["Type"], "work");
    assert!(described.get("ExternalIds").is_none(), "{described}");
    let found = ids("GetUserId", json!({ "AlternateIdentifier": { "UniqueAttribute": { "AttributePath": "emails.value", "AttributeValue": "ada@example.com" } } }))
        .await
        .unwrap();
    assert_eq!(found["UserId"], json!(ada_id));

    // Updated by attribute paths; a missing value removes one; Revision guards.
    let ops = |ops: Value| json!({ "UserId": ada_id, "Operations": ops });
    let updated = ids("UpdateUser", ops(json!([
        { "AttributePath": "nickName", "AttributeValue": "Countess" },
        { "AttributePath": "name.familyName", "AttributeValue": "King" },
        { "AttributePath": "aws:identitystore:enterprise.department", "AttributeValue": "Analytics" },
    ])))
    .await
    .unwrap();
    assert_eq!(updated["Revision"], "2");
    let mut stale = ops(json!([{ "AttributePath": "title", "AttributeValue": "Dr" }]));
    stale["Revision"] = json!("1");
    assert_eq!(ids("UpdateUser", stale).await.unwrap_err(), "ConflictException");
    ids("UpdateUser", ops(json!([{ "AttributePath": "nickName" }]))).await.unwrap();
    assert_eq!(ids("UpdateUser", ops(json!([{ "AttributePath": "displayName" }]))).await.unwrap_err(), "ValidationException");
    assert_eq!(ids("UpdateUser", ops(json!([{ "AttributePath": "shoeSize", "AttributeValue": "9" }]))).await.unwrap_err(), "ValidationException");
    let described = ids("DescribeUser", json!({ "UserId": ada_id })).await.unwrap();
    assert_eq!((&described["Name"]["FamilyName"], &described["Name"]["GivenName"]), (&json!("King"), &json!("Ada")));
    assert_eq!(described["Extensions"][ENTERPRISE]["department"], "Analytics");
    assert!(described.get("NickName").is_none(), "{described}");
    assert_eq!(described["Revision"], "3");

    // A source's users and groups are what its sign-ins say.
    let bob = ic::signed_in(&client, "mock", "sub-bob", "Bob", Some("bob"), None, &["data".into()]).await.unwrap();
    let data = ic::groups(&client, Some(Lookup::Name("data"))).await.unwrap().pop().unwrap().id;
    let rename = json!({ "UserId": bob.to_string(), "Operations": [{ "AttributePath": "nickName", "AttributeValue": "B" }] });
    assert_eq!(ids("UpdateUser", rename).await.unwrap_err(), "ValidationException");
    assert_eq!(ids("DeleteUser", json!({ "UserId": bob.to_string() })).await.unwrap_err(), "ValidationException");

    // Groups of its own, unique by name whatever the case, with members of
    // its own or a source's.
    let made = ids("CreateGroup", json!({ "DisplayName": "Analysts", "Description": "Look at things" })).await.unwrap();
    let analysts = made["GroupId"].as_str().unwrap().to_owned();
    assert_eq!(ids("CreateGroup", json!({ "DisplayName": "analysts" })).await.unwrap_err(), "ConflictException");
    let group_ops = |ops: Value| json!({ "GroupId": analysts, "Operations": ops });
    ids("UpdateGroup", group_ops(json!([{ "AttributePath": "description" }]))).await.unwrap();
    let described = ids("DescribeGroup", json!({ "GroupId": analysts })).await.unwrap();
    assert!(described.get("Description").is_none() && described.get("ExternalIds").is_none(), "{described}");
    let member = |group: &str, user: &str| json!({ "GroupId": group, "MemberId": { "UserId": user } });
    let joined = ids("CreateGroupMembership", member(&analysts, &ada_id)).await.unwrap();
    ids("CreateGroupMembership", member(&analysts, &bob.to_string())).await.unwrap();
    assert_eq!(ids("CreateGroupMembership", member(&analysts, &ada_id)).await.unwrap_err(), "ConflictException");
    assert_eq!(ids("CreateGroupMembership", member(&data.to_string(), &ada_id)).await.unwrap_err(), "ValidationException");
    // Bob signing in again keeps him in a group of Cairn's own.
    ic::signed_in(&client, "mock", "sub-bob", "Bob", Some("bob"), None, &[]).await.unwrap();
    let analysts_id = Uuid::parse_str(&analysts).unwrap();
    assert_eq!(ic::memberships(&client, Some(analysts_id), None).await.unwrap().len(), 2);
    assert!(ic::memberships(&client, Some(data), None).await.unwrap().is_empty());

    ids("DeleteGroupMembership", json!({ "MembershipId": joined["MembershipId"] })).await.unwrap();
    assert_eq!(ic::memberships(&client, Some(analysts_id), None).await.unwrap().len(), 1);
    ids("DeleteGroup", json!({ "GroupId": analysts })).await.unwrap();
    ids("DeleteUser", json!({ "UserId": ada_id })).await.unwrap();
    assert_eq!(ids("DescribeUser", json!({ "UserId": ada_id })).await.unwrap_err(), "ResourceNotFoundException");

    // Only to whom identitystore's writes are allowed.
    let reader = user(&app, "reader", r#"{"Effect":"Allow","Action":"identitystore:List*","Resource":"*"}"#).await;
    let input = json!({ "IdentityStoreId": store, "UserName": "eve", "DisplayName": "Eve", "Name": { "GivenName": "Eve" } });
    assert_eq!(call(&app, &reader, "identitystore", "CreateUser", input).await.unwrap_err(), "AccessDeniedException");
}
