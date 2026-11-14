//! IAM roles (see `roles`), against a real Postgres: what's kept, and what
//! IAM refuses.

use std::sync::Arc;

use super::node_with;
use crate::{App, managed::Refused, packer, roles, users};

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

fn trusting(account: &str, who: &str) -> String {
    format!(r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{account}:{who}"}},"Action":"sts:AssumeRole"}}]}}"#)
}

async fn make(client: &deadpool_postgres::Object, account: &str, name: &str, trust: &str) -> roles::Role {
    let trust = roles::check_trust(client, account, trust).await.unwrap();
    let new = roles::New { name, path: "/", trust: &trust, description: "", max_session_duration: 3600, boundary: None, tags: &[] };
    let id = roles::create(client, account, &new).await.unwrap();
    roles::Role::load_id(client, id).await.unwrap().unwrap()
}

fn refusal(e: anyhow::Error) -> String {
    match e.downcast::<Refused>() {
        Ok(r) => r.to_string(),
        Err(e) => panic!("not a refusal: {e:#}"),
    }
}

/// A trust policy names the users and roles it named when it was set: one
/// deleted since shows as its unique ID, one renamed by its new ARN, and one
/// made with the name later isn't it (as IAM: probed).
#[tokio::test]
async fn trust_policies_name_principals_as_they_were() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    users::create(&client, "tina", None, false).await.unwrap();
    let tina = users::id_of(&client, &account, "tina").await.unwrap();
    let base = make(&client, &account, "base", &trusting(&account, "root")).await;
    let role = make(&client, &account, "trusting", &trusting(&account, "user/tina")).await;
    assert_eq!(role.trust_principals.get(&format!("arn:aws:iam::{account}:user/tina")), Some(&tina.to_string()));
    let shown = roles::shown_trust(&client, &role).await.unwrap();
    assert!(shown.contains(&format!("arn:aws:iam::{account}:user/tina")), "{shown}");

    // Renamed: by its ARN now.
    users::rename(&client, &account, tina, "tine", "/team/").await.unwrap();
    let shown = roles::shown_trust(&client, &role).await.unwrap();
    assert!(shown.contains(&format!("arn:aws:iam::{account}:user/team/tine")), "{shown}");
    // Deleted: by its unique ID, even once another has the name.
    users::delete(&client, &account, "tine").await.unwrap();
    users::create(&client, "tina", None, false).await.unwrap();
    let shown = roles::shown_trust(&client, &role).await.unwrap();
    assert!(shown.contains(&users::unique_id("AIDA", tina)), "{shown}");

    // A role, likewise.
    let chained = make(&client, &account, "chained", &trusting(&account, "role/base")).await;
    roles::delete(&client, &base).await.unwrap();
    let shown = roles::shown_trust(&client, &chained).await.unwrap();
    assert!(shown.contains(&roles::unique_id(base.id)), "{shown}");

    // Principals that aren't there are refused, as IAM refuses them.
    for who in ["user/nobody", "role/nobody"] {
        let e = roles::check_trust(&client, &account, &trusting(&account, who)).await.unwrap_err();
        assert_eq!(refusal(e), format!("Invalid principal in policy: \"AWS\":\"arn:aws:iam::{account}:{who}\""));
    }
    let e = roles::check_trust(&client, &account, &trusting("999999999999", "root")).await.unwrap_err();
    assert_eq!(refusal(e), "Invalid principal in policy: \"AWS\":\"arn:aws:iam::999999999999:root\"");
    // Past IAM's quota.
    let statements: Vec<String> = (0..40)
        .map(|i| format!(r#"{{"Sid":"S{i}","Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{account}:root"}},"Action":"sts:AssumeRole"}}"#))
        .collect();
    let big = format!(r#"{{"Version":"2012-10-17","Statement":[{}]}}"#, statements.join(","));
    let e = roles::check_trust(&client, &account, &big).await.unwrap_err();
    assert_eq!(refusal(e), "Cannot exceed quota for ACLSizePerRole: 2048");
}

/// A role with policies isn't deleted, as IAM refuses it; its tags and
/// boundary don't keep it. A managed policy attached to a role, or a role's
/// boundary, isn't deleted either.
#[tokio::test]
async fn roles_and_their_policies_keep_each_other() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let role = make(&client, &account, "worker", &trusting(&account, "root")).await;
    let read = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;
    let managed = crate::managed::create(&client, &account, "worker-read", "/", read, "").await.unwrap();
    let arn = managed.arn(&account);

    roles::put_policy(&client, &role, "inline", read).await.unwrap();
    let e = roles::delete(&client, &role).await.unwrap_err();
    assert_eq!(refusal(e), "Cannot delete entity, must delete policies first.");
    assert!(roles::delete_policy(&client, role.id, "inline").await.unwrap());

    roles::attach(&client, &account, &role, &arn, true).await.unwrap();
    roles::attach(&client, &account, &role, "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess", true).await.unwrap();
    assert_eq!(roles::attached(&client, role.id).await.unwrap().len(), 2);
    let e = crate::managed::delete(&client, &account, "worker-read").await.unwrap_err();
    assert_eq!(refusal(e), "Cannot delete a policy attached to entities.");
    let e = roles::delete(&client, &role).await.unwrap_err();
    assert_eq!(refusal(e), "Cannot delete entity, must detach all policies first.");
    roles::attach(&client, &account, &role, &arn, false).await.unwrap();
    roles::attach(&client, &account, &role, "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess", false).await.unwrap();

    // As a boundary.
    roles::set_boundary(&client, role.id, Some(&users::BoundaryRef::Own(managed.id))).await.unwrap();
    let e = crate::managed::delete(&client, &account, "worker-read").await.unwrap_err();
    assert_eq!(refusal(e), "Cannot delete a policy attached to entities.");
    roles::tag(&client, role.id, &[("team".to_owned(), "a".to_owned())]).await.unwrap();
    roles::delete(&client, &role).await.unwrap();
    crate::managed::delete(&client, &account, "worker-read").await.unwrap();

    // Inline policies within IAM's size for a role, together.
    let role = make(&client, &account, "big", &trusting(&account, "root")).await;
    let resources: Vec<String> = (0..120).map(|i| format!("\"arn:aws:s3:::bucket-{i:04}/some/longer/prefix/*\"")).collect();
    let big = format!(r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"s3:GetObject","Resource":[{}]}}]}}"#, resources.join(","));
    assert!(big.len() > roles::MAX_POLICIES / 2 && big.len() < roles::MAX_POLICIES);
    roles::put_policy(&client, &role, "one", &big).await.unwrap();
    let e = roles::put_policy(&client, &role, "two", &big).await.unwrap_err();
    assert_eq!(refusal(e), "Maximum policy size of 10240 bytes exceeded for role big");
}

/// Role names are unique regardless of case, as IAM's (probed).
#[tokio::test]
async fn role_names_are_unique_regardless_of_case() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    make(&client, &account, "Reader", &trusting(&account, "root")).await;
    let trust = roles::check_trust(&client, &account, &trusting(&account, "root")).await.unwrap();
    let new = roles::New { name: "reader", path: "/", trust: &trust, description: "", max_session_duration: 3600, boundary: None, tags: &[] };
    let e = roles::create(&client, &account, &new).await.unwrap_err();
    assert_eq!(refusal(e), "Role with name reader already exists.");
    assert_eq!(roles::Role::load(&client, &account, "READER").await.unwrap().unwrap().name, "Reader");
}
