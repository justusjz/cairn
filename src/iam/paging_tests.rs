//! IAM's lists, paged as IAM pages them (`MaxItems`, `Marker`,
//! `IsTruncated`), against a real Postgres.

use super::groups_tests::{call, ok, refused};
use crate::{packer, roles, users};

/// The text of each `<name>` element in `xml`, in order.
fn all(xml: &str, name: &str) -> Vec<String> {
    let (open, close) = (format!("<{name}>"), format!("</{name}>"));
    xml.split(&open)
        .skip(1)
        .map(|rest| rest.split(&close).next().unwrap().to_owned())
        .collect()
}

/// Every page of `action` (`params`, at most `max` an item), as
/// `element`s: each page's, and whether each said it was truncated.
async fn pages(
    app: &std::sync::Arc<crate::App>,
    key: &str,
    action: &str,
    params: &[(&str, &str)],
    max: &str,
    element: &str,
) -> Vec<Vec<String>> {
    let mut pages = Vec::new();
    let mut marker: Option<String> = None;
    loop {
        let mut with: Vec<(&str, &str)> = params.to_vec();
        with.push(("MaxItems", max));
        if let Some(m) = &marker {
            with.push(("Marker", m));
        }
        let xml = ok(call(app, key, action, &with).await);
        pages.push(all(&xml, element));
        let truncated = xml.contains("<IsTruncated>true</IsTruncated>");
        marker = all(&xml, "Marker").pop();
        assert_eq!(truncated, marker.is_some(), "{xml}");
        if !truncated {
            return pages;
        }
    }
}

const DOC: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;

#[tokio::test]
async fn lists_page_as_iams() {
    let Some(app) = crate::e2e::node_with(packer::Config::default(), None).await else {
        return;
    };
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let (admin, _) = users::create_for(&client, &account, "boss", None, true)
        .await
        .unwrap();
    users::create_user(&client, &account, "pat", "/", None)
        .await
        .unwrap();
    let pat = [("UserName", "pat")];

    // Inline policies, by name.
    for name in ["c", "a", "b"] {
        ok(call(
            &app,
            &admin,
            "PutUserPolicy",
            &[
                ("UserName", "pat"),
                ("PolicyName", name),
                ("PolicyDocument", DOC),
            ],
        )
        .await);
    }
    assert_eq!(
        pages(&app, &admin, "ListUserPolicies", &pat, "2", "member").await,
        [vec!["a", "b"], vec!["c"]]
    );
    assert_eq!(
        pages(&app, &admin, "ListUserPolicies", &pat, "3", "member").await,
        [vec!["a", "b", "c"]]
    );
    // A marker still holds once what it names is gone: the next page is
    // what's after it.
    let first = ok(call(
        &app,
        &admin,
        "ListUserPolicies",
        &[("UserName", "pat"), ("MaxItems", "2")],
    )
    .await);
    let marker = all(&first, "Marker").pop().unwrap();
    ok(call(
        &app,
        &admin,
        "DeleteUserPolicy",
        &[("UserName", "pat"), ("PolicyName", "b")],
    )
    .await);
    let next = ok(call(
        &app,
        &admin,
        "ListUserPolicies",
        &[("UserName", "pat"), ("Marker", &marker)],
    )
    .await);
    assert_eq!(all(&next, "member"), ["c"]);
    assert!(
        next.contains("<IsTruncated>false</IsTruncated>") && !next.contains("<Marker>"),
        "{next}"
    );
    let message = refused(
        call(
            &app,
            &admin,
            "ListUserPolicies",
            &[("UserName", "pat"), ("Marker", "!")],
        )
        .await,
        "InvalidInput",
    );
    assert_eq!(message, "Invalid Marker.");
    refused(
        call(
            &app,
            &admin,
            "ListUserPolicies",
            &[("UserName", "pat"), ("MaxItems", "0")],
        )
        .await,
        "ValidationError",
    );

    // Attached policies: Cairn's by name, then the account's by path and name.
    for (name, path) in [("zeta", "/"), ("alpha", "/team/"), ("beta", "/")] {
        ok(call(
            &app,
            &admin,
            "CreatePolicy",
            &[
                ("PolicyName", name),
                ("Path", path),
                ("PolicyDocument", DOC),
            ],
        )
        .await);
    }
    let own = |path: &str, name: &str| format!("arn:aws:iam::{account}:policy{path}{name}");
    let attach = [
        own("/", "zeta"),
        "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess".to_owned(),
        own("/team/", "alpha"),
        "arn:aws:iam::aws:policy/AmazonS3FullAccess".to_owned(),
        own("/", "beta"),
    ];
    for arn in &attach {
        ok(call(
            &app,
            &admin,
            "AttachUserPolicy",
            &[("UserName", "pat"), ("PolicyArn", arn)],
        )
        .await);
    }
    let listed = pages(
        &app,
        &admin,
        "ListAttachedUserPolicies",
        &pat,
        "2",
        "PolicyName",
    )
    .await;
    assert_eq!(
        listed,
        [
            vec!["AmazonS3FullAccess", "AmazonS3ReadOnlyAccess"],
            vec!["beta", "zeta"],
            vec!["alpha"]
        ]
    );

    // Access keys, oldest first.
    for _ in 0..2 {
        ok(call(&app, &admin, "CreateAccessKey", &pat).await);
    }
    let keys = pages(&app, &admin, "ListAccessKeys", &pat, "1", "AccessKeyId").await;
    assert_eq!(keys.len(), 2);
    let ordered: Vec<String> = client
        .query("SELECT access_key_id FROM access_keys a JOIN users u ON u.id = a.user_id WHERE u.name = 'pat' ORDER BY a.created_at, a.access_key_id", &[])
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(keys.concat(), ordered);

    // A role's and a group's, likewise.
    let trust = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{account}:root"}},"Action":"sts:AssumeRole"}}]}}"#
    );
    let trust = roles::check_trust(&client, &account, &trust).await.unwrap();
    let new = roles::New {
        name: "worker",
        path: "/",
        trust: &trust,
        description: "",
        max_session_duration: 3600,
        boundary: None,
        tags: &[],
    };
    roles::create(&client, &account, &new).await.unwrap();
    ok(call(&app, &admin, "CreateGroup", &[("GroupName", "crew")]).await);
    for name in ["one", "two"] {
        ok(call(
            &app,
            &admin,
            "PutRolePolicy",
            &[
                ("RoleName", "worker"),
                ("PolicyName", name),
                ("PolicyDocument", DOC),
            ],
        )
        .await);
        ok(call(
            &app,
            &admin,
            "PutGroupPolicy",
            &[
                ("GroupName", "crew"),
                ("PolicyName", name),
                ("PolicyDocument", DOC),
            ],
        )
        .await);
    }
    for arn in &attach[..2] {
        ok(call(
            &app,
            &admin,
            "AttachRolePolicy",
            &[("RoleName", "worker"), ("PolicyArn", arn)],
        )
        .await);
        ok(call(
            &app,
            &admin,
            "AttachGroupPolicy",
            &[("GroupName", "crew"), ("PolicyArn", arn)],
        )
        .await);
    }
    let role = [("RoleName", "worker")];
    let group = [("GroupName", "crew")];
    assert_eq!(
        pages(&app, &admin, "ListRolePolicies", &role, "1", "member").await,
        [vec!["one"], vec!["two"]]
    );
    assert_eq!(
        pages(&app, &admin, "ListGroupPolicies", &group, "1", "member").await,
        [vec!["one"], vec!["two"]]
    );
    let expected = [vec!["AmazonS3ReadOnlyAccess"], vec!["zeta"]];
    assert_eq!(
        pages(
            &app,
            &admin,
            "ListAttachedRolePolicies",
            &role,
            "1",
            "PolicyName"
        )
        .await,
        expected
    );
    assert_eq!(
        pages(
            &app,
            &admin,
            "ListAttachedGroupPolicies",
            &group,
            "1",
            "PolicyName"
        )
        .await,
        expected
    );

    // A policy's entities: groups, users and roles, paged together.
    users::create_user(&client, &account, "quinn", "/", None)
        .await
        .unwrap();
    ok(call(
        &app,
        &admin,
        "AttachUserPolicy",
        &[("UserName", "quinn"), ("PolicyArn", &attach[0])],
    )
    .await);
    let entities = [("PolicyArn", attach[0].as_str())];
    let mut seen = Vec::new();
    let mut marker: Option<String> = None;
    loop {
        let mut with: Vec<(&str, &str)> = vec![entities[0], ("MaxItems", "2")];
        if let Some(m) = &marker {
            with.push(("Marker", m));
        }
        let xml = ok(call(&app, &admin, "ListEntitiesForPolicy", &with).await);
        let mut page = all(&xml, "GroupName");
        page.extend(all(&xml, "UserName"));
        page.extend(all(&xml, "RoleName"));
        seen.push(page);
        marker = all(&xml, "Marker").pop();
        if marker.is_none() {
            break;
        }
    }
    assert_eq!(seen, [vec!["crew", "pat"], vec!["quinn", "worker"]]);
}
