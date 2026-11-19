//! IAM groups end to end, against a real Postgres: IAM's actions on them, as
//! a signer whose policies allow them (or don't) makes them, and how a
//! member's requests are decided by its groups' policies.

use std::collections::HashMap;
use std::sync::Arc;

use hyper::{HeaderMap, Method};

use super::{Iam, Params};
use crate::{
    App, packer,
    s3::{
        access::{Access, Origin},
        actions::{Check, On},
    },
    users::{self, Principal},
};

/// What a request answered: its result, or its error's code and message.
pub(super) type Answer = Result<String, (String, String)>;

/// `action` with `params`, signed by the user whose key `key` is.
pub(super) async fn call(
    app: &Arc<App>,
    key: &str,
    action: &str,
    params: &[(&str, &str)],
) -> Answer {
    let client = app.pool.get().await.unwrap();
    let principal = Principal::load(&client, key).await.unwrap().unwrap();
    let trusted = Vec::new();
    let origin = Origin {
        peer: Some("127.0.0.1".parse().unwrap()),
        trusted_proxies: &trusted,
        signed: None,
        form: false,
    };
    let mut access = Access::new(
        Some(&principal),
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
        principal: &principal,
        access: &mut access,
    };
    let params = Params(
        params
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<HashMap<_, _>>(),
    );
    let answered = match action {
        "CreateGroup" => iam.create_group(&params).await,
        "GetGroup" => iam.get_group(&params).await,
        "ListGroups" => iam.list_groups(&params).await,
        "UpdateGroup" => iam.update_group(&params).await,
        "DeleteGroup" => iam.delete_group(&params).await,
        "AddUserToGroup" => iam.add_user_to_group(&params, true).await,
        "RemoveUserFromGroup" => iam.add_user_to_group(&params, false).await,
        "ListGroupsForUser" => iam.list_groups_for_user(&params).await,
        "PutGroupPolicy" => iam.put_group_policy(&params).await,
        "GetGroupPolicy" => iam.get_group_policy(&params).await,
        "ListGroupPolicies" => iam.list_group_policies(&params).await,
        "DeleteGroupPolicy" => iam.delete_group_policy(&params).await,
        "AttachGroupPolicy" => iam.attach_group_policy(&params, true).await,
        "DetachGroupPolicy" => iam.attach_group_policy(&params, false).await,
        "ListAttachedGroupPolicies" => iam.list_attached_group_policies(&params).await,
        "DeleteUser" => iam.delete_user(&params).await,
        "GetPolicy" => iam.get_policy(&params).await,
        "ListEntitiesForPolicy" => iam.list_entities_for_policy(&params).await,
        "CreatePolicy" => iam.create_policy(&params).await,
        "AttachUserPolicy" => iam.attach_user_policy(&params, true).await,
        "PutUserPolicy" => iam.put_user_policy(&params).await,
        "DeleteUserPolicy" => iam.delete_user_policy(&params).await,
        "CreateAccessKey" => iam.create_access_key(&params).await,
        "ListAccessKeys" => iam.list_access_keys(&params).await,
        "ListUserPolicies" => iam.list_user_policies(&params).await,
        "ListAttachedUserPolicies" => iam.list_attached_user_policies(&params).await,
        "PutRolePolicy" => iam.put_role_policy(&params).await,
        "AttachRolePolicy" => iam.attach_role_policy(&params, true).await,
        "ListRolePolicies" => iam.list_role_policies(&params).await,
        "ListAttachedRolePolicies" => iam.list_attached_role_policies(&params).await,
        "DeletePolicy" => iam.delete_policy(&params).await,
        other => panic!("no action {other} here"),
    };
    match answered {
        Ok(xml) => Ok(xml.unwrap_or_default()),
        Err(e) => Err((e.code.to_owned(), e.message)),
    }
}

pub(super) fn ok(answer: Answer) -> String {
    answer.unwrap_or_else(|(code, message)| panic!("{code}: {message}"))
}

pub(super) fn refused(answer: Answer, code: &str) -> String {
    match answer {
        Ok(xml) => panic!("not refused: {xml}"),
        Err((c, message)) => {
            assert_eq!(c, code, "{message}");
            message
        }
    }
}

/// Whether the user whose key `key` is may take `action` on object `key` of
/// `bucket`, as its policies (and its groups') decide.
async fn may(app: &Arc<App>, key: &str, action: &'static str, bucket: &str, object: &str) -> bool {
    let client = app.pool.get().await.unwrap();
    let principal = Principal::load(&client, key).await.unwrap().unwrap();
    let origin = Origin {
        peer: None,
        trusted_proxies: &[],
        signed: None,
        form: false,
    };
    let mut access = Access::new(
        Some(&principal),
        &principal.account,
        &Method::GET,
        &HeaderMap::new(),
        "",
        &origin,
    )
    .unwrap();
    let check = Check {
        action,
        on: On::Object(bucket.to_owned(), object.to_owned()),
    };
    access
        .load_all(app, std::slice::from_ref(&check))
        .await
        .unwrap();
    access.allows(&check)
}

async fn node() -> Option<Arc<App>> {
    crate::e2e::node_with(packer::Config::default(), None).await
}

const READ: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::invoices/*"}]}"#;

/// A group's policies, inline and managed, are its members' as if their
/// own, and only theirs; a group with members or policies isn't deleted,
/// nor a user in a group, nor a managed policy attached to one.
#[tokio::test]
async fn groups_policies_are_their_members() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let (admin, _) = users::create_for(&client, &account, "boss", None, true)
        .await
        .unwrap();
    let (ann, _) = users::create_for(&client, &account, "ann", None, false)
        .await
        .unwrap();
    let (bob, _) = users::create_for(&client, &account, "bob", None, false)
        .await
        .unwrap();

    let made = ok(call(
        &app,
        &admin,
        "CreateGroup",
        &[("GroupName", "Readers"), ("Path", "/finance/")],
    )
    .await);
    assert!(
        made.contains(&format!(
            "<Arn>arn:aws:iam::{account}:group/finance/Readers</Arn>"
        )),
        "{made}"
    );
    assert!(made.contains("<GroupId>AGPA"), "{made}");
    // Names are unique regardless of case.
    let message = refused(
        call(&app, &admin, "CreateGroup", &[("GroupName", "readers")]).await,
        "EntityAlreadyExists",
    );
    assert_eq!(message, "Group with name readers already exists.");
    refused(
        call(&app, &admin, "CreateGroup", &[("GroupName", "no/slash")]).await,
        "ValidationError",
    );

    // Nothing yet.
    assert!(!may(&app, &ann, "s3:GetObject", "invoices", "2026/1.pdf").await);
    ok(call(
        &app,
        &admin,
        "AddUserToGroup",
        &[("GroupName", "Readers"), ("UserName", "ann")],
    )
    .await);
    ok(call(
        &app,
        &admin,
        "PutGroupPolicy",
        &[
            ("GroupName", "Readers"),
            ("PolicyName", "read"),
            ("PolicyDocument", READ),
        ],
    )
    .await);
    assert!(may(&app, &ann, "s3:GetObject", "invoices", "2026/1.pdf").await);
    assert!(!may(&app, &ann, "s3:PutObject", "invoices", "2026/1.pdf").await);
    assert!(!may(&app, &bob, "s3:GetObject", "invoices", "2026/1.pdf").await);

    // A managed policy, Cairn's or the account's, likewise.
    let full = "arn:aws:iam::aws:policy/AmazonS3FullAccess";
    ok(call(
        &app,
        &admin,
        "AttachGroupPolicy",
        &[("GroupName", "Readers"), ("PolicyArn", full)],
    )
    .await);
    assert!(may(&app, &ann, "s3:PutObject", "invoices", "2026/1.pdf").await);
    let attached = ok(call(
        &app,
        &admin,
        "ListAttachedGroupPolicies",
        &[("GroupName", "Readers")],
    )
    .await);
    assert!(
        attached.contains("<PolicyName>AmazonS3FullAccess</PolicyName>"),
        "{attached}"
    );
    let entities = ok(call(
        &app,
        &admin,
        "ListEntitiesForPolicy",
        &[("PolicyArn", full)],
    )
    .await);
    assert!(
        entities.contains("<PolicyGroups><member><GroupName>Readers</GroupName><GroupId>AGPA"),
        "{entities}"
    );
    let entities = ok(call(
        &app,
        &admin,
        "ListEntitiesForPolicy",
        &[("PolicyArn", full), ("EntityFilter", "User")],
    )
    .await);
    assert!(
        entities.contains("<PolicyGroups></PolicyGroups>"),
        "{entities}"
    );
    let own = ok(call(
        &app,
        &admin,
        "CreatePolicy",
        &[("PolicyName", "invoices-read"), ("PolicyDocument", READ)],
    )
    .await);
    assert!(
        own.contains("<AttachmentCount>0</AttachmentCount>"),
        "{own}"
    );
    let own_arn = format!("arn:aws:iam::{account}:policy/invoices-read");
    ok(call(
        &app,
        &admin,
        "AttachGroupPolicy",
        &[("GroupName", "readers"), ("PolicyArn", &own_arn)],
    )
    .await);
    let policy = ok(call(&app, &admin, "GetPolicy", &[("PolicyArn", &own_arn)]).await);
    assert!(
        policy.contains("<AttachmentCount>1</AttachmentCount>"),
        "{policy}"
    );
    let message = refused(
        call(&app, &admin, "DeletePolicy", &[("PolicyArn", &own_arn)]).await,
        "DeleteConflict",
    );
    assert_eq!(message, "Cannot delete a policy attached to entities.");

    // A group's Deny is its members' too.
    let deny = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:PutObject","Resource":"*"}]}"#;
    ok(call(&app, &admin, "CreateGroup", &[("GroupName", "Frozen")]).await);
    ok(call(
        &app,
        &admin,
        "PutGroupPolicy",
        &[
            ("GroupName", "Frozen"),
            ("PolicyName", "freeze"),
            ("PolicyDocument", deny),
        ],
    )
    .await);
    ok(call(
        &app,
        &admin,
        "AddUserToGroup",
        &[("GroupName", "Frozen"), ("UserName", "ann")],
    )
    .await);
    assert!(!may(&app, &ann, "s3:PutObject", "invoices", "2026/1.pdf").await);
    assert!(may(&app, &ann, "s3:GetObject", "invoices", "2026/1.pdf").await);

    // Read back.
    let group = ok(call(&app, &admin, "GetGroup", &[("GroupName", "Readers")]).await);
    assert!(
        group.contains("<GroupName>Readers</GroupName>")
            && group.contains("<UserName>ann</UserName>"),
        "{group}"
    );
    let listed = ok(call(&app, &admin, "ListGroups", &[("PathPrefix", "/finance/")]).await);
    assert!(
        listed.contains("Readers") && !listed.contains("Frozen"),
        "{listed}"
    );
    let listed = ok(call(&app, &admin, "ListGroups", &[("MaxItems", "1")]).await);
    assert!(
        listed.contains("<GroupName>Frozen</GroupName>")
            && listed.contains("<Marker>Frozen</Marker>"),
        "{listed}"
    );
    let listed = ok(call(&app, &admin, "ListGroups", &[("Marker", "Frozen")]).await);
    assert!(
        listed.contains("Readers") && !listed.contains("Frozen"),
        "{listed}"
    );
    let mine = ok(call(&app, &admin, "ListGroupsForUser", &[("UserName", "ann")]).await);
    assert!(
        mine.contains("Frozen") && mine.contains("Readers"),
        "{mine}"
    );
    let names = ok(call(
        &app,
        &admin,
        "ListGroupPolicies",
        &[("GroupName", "Readers")],
    )
    .await);
    assert_eq!(
        names,
        "<PolicyNames><member>read</member></PolicyNames><IsTruncated>false</IsTruncated>"
    );
    let document = ok(call(
        &app,
        &admin,
        "GetGroupPolicy",
        &[("GroupName", "Readers"), ("PolicyName", "read")],
    )
    .await);
    assert!(
        document.contains("<PolicyDocument>%7B%22Version"),
        "{document}"
    );
    refused(
        call(
            &app,
            &admin,
            "GetGroupPolicy",
            &[("GroupName", "Readers"), ("PolicyName", "none")],
        )
        .await,
        "NoSuchEntity",
    );

    // Older Cairns, which know no groups, deny its members everything.
    let older = |user: &'static str| {
        let client = &client;
        async move {
            client
                .query_one(
                    "SELECT count(*) FROM user_policies p JOIN users u ON u.id = p.user_id WHERE u.name = $1 AND p.name = 'cairn:groups'",
                    &[&user],
                )
                .await
                .unwrap()
                .get::<_, i64>(0)
        }
    };
    assert_eq!(older("ann").await, 1);
    assert_eq!(older("bob").await, 0);

    // What keeps what.
    let message = refused(
        call(&app, &admin, "DeleteGroup", &[("GroupName", "Readers")]).await,
        "DeleteConflict",
    );
    assert_eq!(
        message,
        "Cannot delete entity, must remove users from group first."
    );
    // (A user without access keys, which would keep it first.)
    users::create_user(&client, &account, "cat", "/", None)
        .await
        .unwrap();
    ok(call(
        &app,
        &admin,
        "AddUserToGroup",
        &[("GroupName", "Frozen"), ("UserName", "cat")],
    )
    .await);
    let message = refused(
        call(&app, &admin, "DeleteUser", &[("UserName", "cat")]).await,
        "DeleteConflict",
    );
    assert_eq!(
        message,
        "Cannot delete entity, must remove user from all groups first."
    );
    ok(call(
        &app,
        &admin,
        "RemoveUserFromGroup",
        &[("GroupName", "Frozen"), ("UserName", "cat")],
    )
    .await);
    ok(call(&app, &admin, "DeleteUser", &[("UserName", "cat")]).await);
    ok(call(
        &app,
        &admin,
        "RemoveUserFromGroup",
        &[("GroupName", "Readers"), ("UserName", "ann")],
    )
    .await);
    assert!(!may(&app, &ann, "s3:GetObject", "invoices", "2026/1.pdf").await);
    assert_eq!(older("ann").await, 1);
    ok(call(
        &app,
        &admin,
        "RemoveUserFromGroup",
        &[("GroupName", "Frozen"), ("UserName", "ann")],
    )
    .await);
    assert_eq!(older("ann").await, 0);
    refused(
        call(
            &app,
            &admin,
            "RemoveUserFromGroup",
            &[("GroupName", "Frozen"), ("UserName", "ann")],
        )
        .await,
        "NoSuchEntity",
    );
    let message = refused(
        call(&app, &admin, "DeleteGroup", &[("GroupName", "Readers")]).await,
        "DeleteConflict",
    );
    assert_eq!(message, "Cannot delete entity, must delete policies first.");
    ok(call(
        &app,
        &admin,
        "DeleteGroupPolicy",
        &[("GroupName", "Readers"), ("PolicyName", "read")],
    )
    .await);
    let message = refused(
        call(&app, &admin, "DeleteGroup", &[("GroupName", "Readers")]).await,
        "DeleteConflict",
    );
    assert_eq!(
        message,
        "Cannot delete entity, must detach all policies first."
    );
    ok(call(
        &app,
        &admin,
        "DetachGroupPolicy",
        &[("GroupName", "Readers"), ("PolicyArn", full)],
    )
    .await);
    ok(call(
        &app,
        &admin,
        "DetachGroupPolicy",
        &[("GroupName", "Readers"), ("PolicyArn", &own_arn)],
    )
    .await);
    refused(
        call(
            &app,
            &admin,
            "DetachGroupPolicy",
            &[("GroupName", "Readers"), ("PolicyArn", full)],
        )
        .await,
        "NoSuchEntity",
    );
    ok(call(&app, &admin, "DeletePolicy", &[("PolicyArn", &own_arn)]).await);
    ok(call(&app, &admin, "DeleteGroup", &[("GroupName", "Readers")]).await);
    let message = refused(
        call(&app, &admin, "GetGroup", &[("GroupName", "Readers")]).await,
        "NoSuchEntity",
    );
    assert_eq!(message, "The group with name Readers cannot be found.");
    // A user deleted otherwise (the command line) leaves its groups.
    ok(call(
        &app,
        &admin,
        "AddUserToGroup",
        &[("GroupName", "Frozen"), ("UserName", "bob")],
    )
    .await);
    users::delete(&client, &account, "bob").await.unwrap();
    let group = ok(call(&app, &admin, "GetGroup", &[("GroupName", "Frozen")]).await);
    assert!(group.contains("<Users></Users>"), "{group}");
}

/// IAM's actions on groups are checked as IAM's own, on the group's ARN;
/// renaming and moving one, on where it goes too.
#[tokio::test]
async fn groups_are_checked_on_their_arns() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let (admin, _) = users::create_for(&client, &account, "boss", None, true)
        .await
        .unwrap();
    let (lead, _) = users::create_for(&client, &account, "lead", None, false)
        .await
        .unwrap();
    users::create_for(&client, &account, "dev", None, false)
        .await
        .unwrap();
    // The lead manages the team's groups' members, and nothing else.
    let manage = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":["iam:AddUserToGroup","iam:RemoveUserFromGroup","iam:GetGroup","iam:UpdateGroup"],"Resource":"arn:aws:iam::{account}:group/team/*"}}]}}"#
    );
    users::put_policy(&client, &account, "lead", "manage", &manage)
        .await
        .unwrap();
    ok(call(
        &app,
        &admin,
        "CreateGroup",
        &[("GroupName", "devs"), ("Path", "/team/")],
    )
    .await);
    ok(call(&app, &admin, "CreateGroup", &[("GroupName", "admins")]).await);

    ok(call(
        &app,
        &lead,
        "AddUserToGroup",
        &[("GroupName", "devs"), ("UserName", "dev")],
    )
    .await);
    let message = refused(
        call(
            &app,
            &lead,
            "AddUserToGroup",
            &[("GroupName", "admins"), ("UserName", "dev")],
        )
        .await,
        "AccessDenied",
    );
    assert!(
        message
            .contains("is not authorized to perform: iam:AddUserToGroup on resource: group admins"),
        "{message}"
    );
    let message = refused(
        call(
            &app,
            &lead,
            "CreateGroup",
            &[("GroupName", "mine"), ("Path", "/team/")],
        )
        .await,
        "AccessDenied",
    );
    assert!(
        message.contains(&format!(
            "iam:CreateGroup on resource: arn:aws:iam::{account}:group/team/mine"
        )),
        "{message}"
    );
    refused(
        call(
            &app,
            &lead,
            "PutGroupPolicy",
            &[
                ("GroupName", "devs"),
                ("PolicyName", "p"),
                ("PolicyDocument", READ),
            ],
        )
        .await,
        "AccessDenied",
    );
    // A user that isn't there, in a group the lead may change.
    let message = refused(
        call(
            &app,
            &lead,
            "AddUserToGroup",
            &[("GroupName", "devs"), ("UserName", "nobody")],
        )
        .await,
        "NoSuchEntity",
    );
    assert_eq!(message, "The user with name nobody cannot be found.");
    // A group that isn't there is checked as it would be, at `/`.
    refused(
        call(&app, &lead, "GetGroup", &[("GroupName", "ghosts")]).await,
        "AccessDenied",
    );
    let message = refused(
        call(&app, &admin, "GetGroup", &[("GroupName", "ghosts")]).await,
        "NoSuchEntity",
    );
    assert_eq!(message, "The group with name ghosts cannot be found.");

    // Renamed within the team's path, but not moved out of it.
    ok(call(
        &app,
        &lead,
        "UpdateGroup",
        &[("GroupName", "devs"), ("NewGroupName", "developers")],
    )
    .await);
    let message = refused(
        call(
            &app,
            &lead,
            "UpdateGroup",
            &[("GroupName", "developers"), ("NewPath", "/")],
        )
        .await,
        "AccessDenied",
    );
    assert!(
        message.contains(&format!(
            "on resource: arn:aws:iam::{account}:group/developers"
        )),
        "{message}"
    );
    let group = ok(call(&app, &lead, "GetGroup", &[("GroupName", "developers")]).await);
    assert!(
        group.contains(&format!(
            "<Arn>arn:aws:iam::{account}:group/team/developers</Arn>"
        )),
        "{group}"
    );
    assert!(group.contains("<UserName>dev</UserName>"), "{group}");
    let message = refused(
        call(
            &app,
            &admin,
            "UpdateGroup",
            &[("GroupName", "developers"), ("NewGroupName", "ADMINS")],
        )
        .await,
        "EntityAlreadyExists",
    );
    assert_eq!(message, "Group with name ADMINS already exists.");
}

/// IAM's quotas: groups per user, policies per group, and the size of a
/// group's inline policies together.
#[tokio::test]
async fn groups_have_iams_quotas() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let (admin, _) = users::create_for(&client, &account, "boss", None, true)
        .await
        .unwrap();
    users::create_for(&client, &account, "joiner", None, false)
        .await
        .unwrap();
    for i in 0..=crate::groups::MAX_GROUPS_PER_USER {
        let name = format!("g{i:02}");
        ok(call(&app, &admin, "CreateGroup", &[("GroupName", &name)]).await);
        let added = call(
            &app,
            &admin,
            "AddUserToGroup",
            &[("GroupName", &name), ("UserName", "joiner")],
        )
        .await;
        if i < crate::groups::MAX_GROUPS_PER_USER {
            ok(added);
        } else {
            assert_eq!(
                refused(added, "LimitExceeded"),
                "Cannot exceed quota for GroupsPerUser: 10"
            );
        }
    }
    // Again, as a member already: no change, no error.
    ok(call(
        &app,
        &admin,
        "AddUserToGroup",
        &[("GroupName", "g00"), ("UserName", "joiner")],
    )
    .await);

    let resources: Vec<String> = (0..60)
        .map(|i| format!("\"arn:aws:s3:::bucket-{i:04}/some/longer/prefix/*\""))
        .collect();
    let big = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"s3:GetObject","Resource":[{}]}}]}}"#,
        resources.join(",")
    );
    assert!(big.len() > crate::groups::MAX_POLICIES / 2 && big.len() < crate::groups::MAX_POLICIES);
    ok(call(
        &app,
        &admin,
        "PutGroupPolicy",
        &[
            ("GroupName", "g00"),
            ("PolicyName", "one"),
            ("PolicyDocument", &big),
        ],
    )
    .await);
    // Replacing one is within it.
    ok(call(
        &app,
        &admin,
        "PutGroupPolicy",
        &[
            ("GroupName", "g00"),
            ("PolicyName", "one"),
            ("PolicyDocument", &big),
        ],
    )
    .await);
    let message = refused(
        call(
            &app,
            &admin,
            "PutGroupPolicy",
            &[
                ("GroupName", "g00"),
                ("PolicyName", "two"),
                ("PolicyDocument", &big),
            ],
        )
        .await,
        "LimitExceeded",
    );
    assert_eq!(
        message,
        "Maximum policy size of 5120 bytes exceeded for group g00"
    );
    refused(
        call(
            &app,
            &admin,
            "PutGroupPolicy",
            &[
                ("GroupName", "g00"),
                ("PolicyName", "bad"),
                ("PolicyDocument", "{"),
            ],
        )
        .await,
        "MalformedPolicyDocument",
    );

    for i in 0..=crate::groups::MAX_ATTACHED {
        let document = format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b{i}/*"}}]}}"#
        );
        ok(call(
            &app,
            &admin,
            "CreatePolicy",
            &[
                ("PolicyName", &format!("p{i}")),
                ("PolicyDocument", &document),
            ],
        )
        .await);
        let arn = format!("arn:aws:iam::{account}:policy/p{i}");
        let attached = call(
            &app,
            &admin,
            "AttachGroupPolicy",
            &[("GroupName", "g01"), ("PolicyArn", &arn)],
        )
        .await;
        if i < crate::groups::MAX_ATTACHED {
            ok(attached);
        } else {
            assert_eq!(
                refused(attached, "LimitExceeded"),
                "Cannot exceed quota for PoliciesPerGroup: 10"
            );
        }
    }
}
