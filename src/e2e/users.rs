//! Users, their access keys and inline policies (see `roles`), against a
//! real Postgres.

use std::sync::Arc;

use super::node_with;
use crate::{
    App, packer,
    roles::{self, Principal},
};

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

/// The secret older Cairns authenticate `user` with.
async fn legacy_secret(app: &App, user: &str) -> String {
    let client = app.pool.get().await.unwrap();
    client.query_one("SELECT secret FROM roles WHERE name = $1", &[&user]).await.unwrap().get(0)
}

#[tokio::test]
async fn a_user_signs_with_any_of_its_active_keys() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let secret = roles::create(&client, "alice", None, false).await.unwrap();
    let principal = Principal::load(&client, "alice").await.unwrap().unwrap();
    assert_eq!((principal.name.as_str(), principal.secret.as_str()), ("alice", secret.as_str()));
    assert_eq!(principal.account, roles::account(&client).await.unwrap());
    assert_eq!(principal.account.len(), 12);

    let (id, second) = roles::create_key(&client, "alice", None, None).await.unwrap();
    assert_eq!(id.len(), 20);
    assert_eq!(Principal::load(&client, &id).await.unwrap().unwrap().secret, second);
    // At most two, as in IAM.
    let third = roles::create_key(&client, "alice", None, None).await.unwrap_err();
    assert!(third.to_string().contains("2 access keys"), "{third}");
    assert!(roles::create_key(&client, "nobody", None, None).await.unwrap_err().to_string().contains("no user"));

    roles::set_key_active(&client, &id, false).await.unwrap();
    assert!(Principal::load(&client, &id).await.unwrap().is_none());
    roles::set_key_active(&client, &id, true).await.unwrap();
    assert!(Principal::load(&client, &id).await.unwrap().is_some());
    roles::delete_key(&client, &id).await.unwrap();
    assert!(Principal::load(&client, &id).await.unwrap().is_none());
    assert!(roles::delete_key(&client, &id).await.is_err());

    // A key's ID can't be another's, nor a new user's name.
    roles::create_key(&client, "alice", Some("shared".to_owned()), None).await.unwrap();
    let taken = roles::create(&client, "shared", None, false).await.unwrap_err();
    assert!(taken.to_string().contains("access key"), "{taken}");

    let listed = roles::list(&client).await.unwrap();
    let alice = listed.iter().find(|u| u.name == "alice").unwrap();
    assert_eq!(alice.keys.iter().map(|k| k.id.as_str()).collect::<Vec<_>>(), ["alice", "shared"]);

    // Deleting the user deletes its keys.
    roles::delete(&client, "alice").await.unwrap();
    assert!(Principal::load(&client, "shared").await.unwrap().is_none());
}

/// Older Cairns authenticate with `roles.secret`: it's the secret of the key
/// named as the user, while that's active, and none that can be guessed
/// otherwise; and they can't change users.
#[tokio::test]
async fn older_cairns_see_the_first_keys_secret_and_cant_change_users() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let secret = roles::create(&client, "bob", None, false).await.unwrap();
    assert_eq!(legacy_secret(&app, "bob").await, secret);
    let rotated = roles::generate_secret().unwrap();
    roles::update(&client, "bob", None, Some(rotated.clone())).await.unwrap();
    assert_eq!(legacy_secret(&app, "bob").await, rotated);
    assert_eq!(Principal::load(&client, "bob").await.unwrap().unwrap().secret, rotated);
    roles::set_key_active(&client, "bob", false).await.unwrap();
    assert!(legacy_secret(&app, "bob").await.starts_with("unusable:"));
    roles::set_key_active(&client, "bob", true).await.unwrap();
    assert_eq!(legacy_secret(&app, "bob").await, rotated);
    roles::delete_key(&client, "bob").await.unwrap();
    assert!(legacy_secret(&app, "bob").await.starts_with("unusable:"));
    // Without its first key, the user's other keys are rotated as keys.
    let err = roles::update(&client, "bob", None, Some(rotated)).await.unwrap_err();
    assert!(err.to_string().contains("no access key named as the user"), "{err}");

    // A session that doesn't declare `cairn.users` (an older Cairn's).
    let mut client = app.pool.get().await.unwrap();
    for change in [
        "INSERT INTO roles (name, secret) VALUES ('old', 'oldsecret')",
        "UPDATE roles SET secret = 'x' WHERE name = 'bob'",
        "DELETE FROM roles WHERE name = 'bob'",
    ] {
        let tx = client.transaction().await.unwrap();
        tx.batch_execute("SET LOCAL cairn.users = ''").await.unwrap();
        let err = tx.batch_execute(change).await.unwrap_err();
        assert!(format!("{err:?}").contains("too old to change users"), "{change}: {err:?}");
    }
    // What doesn't involve keys, they still may: admin flags, KMS identities.
    let tx = client.transaction().await.unwrap();
    tx.batch_execute("SET LOCAL cairn.users = ''").await.unwrap();
    tx.batch_execute("UPDATE roles SET admin = true, kms_entity_id = 'e' WHERE name = 'bob'").await.unwrap();
}

#[tokio::test]
async fn inline_policies_are_checked_and_kept_as_given() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    roles::create(&client, "carol", None, false).await.unwrap();
    let document = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject",
        "Resource":"arn:aws:s3:::bucket/home/${aws:username}/*"}]}"#;
    roles::put_policy(&client, "carol", "home", document).await.unwrap();
    assert_eq!(roles::get_policy(&client, "carol", "home").await.unwrap(), document);
    assert_eq!(Principal::load(&client, "carol").await.unwrap().unwrap().policies, [document]);
    let listed = roles::list(&client).await.unwrap();
    assert_eq!(listed.iter().find(|u| u.name == "carol").unwrap().policies, ["home"]);

    // Not an identity policy: refused, as IAM refuses it.
    let principal = r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}"#;
    let err = roles::put_policy(&client, "carol", "p", principal).await.unwrap_err();
    assert!(err.to_string().contains("principal"), "{err}");
    assert!(roles::put_policy(&client, "carol", "bad name", document).await.is_err());
    assert!(roles::put_policy(&client, "nobody", "home", document).await.is_err());
    // At most 2048 characters together, whitespace aside.
    let big = format!(
        r#"{{"Statement":[{{"Sid":"{}","Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}]}}"#,
        "x".repeat(1900)
    );
    let err = roles::put_policy(&client, "carol", "big", &big).await.unwrap_err();
    assert!(err.to_string().contains("2048"), "{err}");
    // Replacing a policy counts it once.
    roles::put_policy(&client, "carol", "home", &big).await.unwrap();

    roles::delete_policy(&client, "carol", "home").await.unwrap();
    assert!(roles::get_policy(&client, "carol", "home").await.is_err());
    assert!(roles::delete_policy(&client, "carol", "home").await.is_err());
}
