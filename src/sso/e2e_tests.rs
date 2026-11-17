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

    // Its policies are its role's: AWS's managed, the account's by
    // reference, inline, and a boundary.
    sso("AttachManagedPolicyToPermissionSet", on(json!({ "ManagedPolicyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess" }))).await.unwrap();
    let own = format!("arn:aws:iam::{account}:policy/teams/list");
    let document = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}"#;
    crate::managed::create(&client, &account, "list", "/teams/", document, "").await.unwrap();
    assert_eq!(sso("AttachManagedPolicyToPermissionSet", on(json!({ "ManagedPolicyArn": own }))).await.unwrap_err(), "ValidationException");
    let reference = json!({ "CustomerManagedPolicyReference": { "Name": "list", "Path": "/teams/" } });
    sso("AttachCustomerManagedPolicyReferenceToPermissionSet", on(reference.clone())).await.unwrap();
    assert_eq!(sso("AttachCustomerManagedPolicyReferenceToPermissionSet", on(reference)).await.unwrap_err(), "ConflictException");
    let missing = json!({ "CustomerManagedPolicyReference": { "Name": "nope" } });
    assert_eq!(sso("AttachCustomerManagedPolicyReferenceToPermissionSet", on(missing)).await.unwrap_err(), "ResourceNotFoundException");
    sso("PutInlinePolicyToPermissionSet", on(json!({ "InlinePolicy": document }))).await.unwrap();
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
    let role = read.role(&client).await.unwrap();
    assert_eq!(role.max_session_duration, 7200);
    assert_eq!(role.boundary.as_deref(), Some(own.as_str()));
    assert_eq!(crate::roles::attached(&client, role.id).await.unwrap().len(), 2);

    // Assigned to a group, by its ID: done when answered.
    let target = |kind: &str, id: String| on(json!({ "TargetId": account, "TargetType": "AWS_ACCOUNT", "PrincipalType": kind, "PrincipalId": id }));
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
    assert_eq!(ic::eligible(&client, &account, ada).await.unwrap().iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["Readers"]);
    let listed = sso("ListAccountAssignments", on(json!({ "AccountId": account }))).await.unwrap();
    assert_eq!(listed["AccountAssignments"][0]["PrincipalType"], "GROUP");
    let provisioned = sso("ListPermissionSetsProvisionedToAccount", json!({ "InstanceArn": instance, "AccountId": account })).await.unwrap();
    assert_eq!(provisioned["PermissionSets"], json!([set]));
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
