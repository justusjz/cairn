//! Users, their access keys and inline policies (see `roles`), against a
//! real Postgres.

use std::sync::Arc;

use super::{BUCKET, node_with};
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

    let (id, second) = roles::create_key(&client, &crate::roles::account(&client).await.unwrap(), "alice", None, None).await.unwrap();
    assert_eq!(id.len(), 20);
    assert_eq!(Principal::load(&client, &id).await.unwrap().unwrap().secret, second);
    // At most two, as in IAM.
    let third = roles::create_key(&client, &crate::roles::account(&client).await.unwrap(), "alice", None, None).await.unwrap_err();
    assert!(third.to_string().contains("2 access keys"), "{third}");
    assert!(roles::create_key(&client, &crate::roles::account(&client).await.unwrap(), "nobody", None, None).await.unwrap_err().to_string().contains("no user"));

    roles::set_key_active(&client, None, &id, false).await.unwrap();
    assert!(Principal::load(&client, &id).await.unwrap().is_none());
    roles::set_key_active(&client, None, &id, true).await.unwrap();
    assert!(Principal::load(&client, &id).await.unwrap().is_some());
    // Only the user's own, when the user is named (as the console does).
    roles::create(&client, "mallory", None, false).await.unwrap();
    assert!(roles::set_key_active(&client, Some((&crate::roles::account(&client).await.unwrap(), "mallory")), &id, false).await.is_err());
    assert!(roles::delete_key(&client, Some((&crate::roles::account(&client).await.unwrap(), "mallory")), &id).await.is_err());
    assert!(Principal::load(&client, &id).await.unwrap().is_some());
    roles::delete_key(&client, Some((&crate::roles::account(&client).await.unwrap(), "alice")), &id).await.unwrap();
    assert!(Principal::load(&client, &id).await.unwrap().is_none());
    assert!(roles::delete_key(&client, None, &id).await.is_err());

    // A new user's key is of a random ID, as IAM's, not its name; older
    // Cairns, which know only keys named as users, get no usable secret.
    roles::create_key(&client, &crate::roles::account(&client).await.unwrap(), "alice", Some("shared".to_owned()), None).await.unwrap();
    let account = crate::roles::account(&client).await.unwrap();
    let (key, secret) = roles::create_for(&client, &account, "shared", None, false).await.unwrap();
    assert_ne!(key, "shared");
    assert_eq!(key.len(), 20);
    assert_eq!(Principal::load(&client, &key).await.unwrap().unwrap().secret, secret);
    assert!(legacy_secret(&app, "shared").await.starts_with("unusable:"));
    roles::delete(&client, &account, "shared").await.unwrap();

    let listed = roles::list(&client).await.unwrap();
    let alice = listed.iter().find(|u| u.name == "alice").unwrap();
    assert_eq!(alice.keys.iter().map(|k| k.id.as_str()).collect::<Vec<_>>(), ["alice", "shared"]);

    // Deleting the user deletes its keys.
    roles::delete(&client, &crate::roles::account(&client).await.unwrap(), "alice").await.unwrap();
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
    roles::update(&client, &crate::roles::account(&client).await.unwrap(), "bob", None, Some(rotated.clone())).await.unwrap();
    assert_eq!(legacy_secret(&app, "bob").await, rotated);
    assert_eq!(Principal::load(&client, "bob").await.unwrap().unwrap().secret, rotated);
    roles::set_key_active(&client, None, "bob", false).await.unwrap();
    assert!(legacy_secret(&app, "bob").await.starts_with("unusable:"));
    roles::set_key_active(&client, None, "bob", true).await.unwrap();
    assert_eq!(legacy_secret(&app, "bob").await, rotated);
    roles::delete_key(&client, None, "bob").await.unwrap();
    assert!(legacy_secret(&app, "bob").await.starts_with("unusable:"));
    // Without its first key, the user's other keys are rotated as keys.
    let err = roles::update(&client, &crate::roles::account(&client).await.unwrap(), "bob", None, Some(rotated)).await.unwrap_err();
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
    roles::put_policy(&client, &crate::roles::account(&client).await.unwrap(), "carol", "home", document).await.unwrap();
    assert_eq!(roles::get_policy(&client, &crate::roles::account(&client).await.unwrap(), "carol", "home").await.unwrap(), document);
    assert_eq!(Principal::load(&client, "carol").await.unwrap().unwrap().policies, [document]);
    let listed = roles::list(&client).await.unwrap();
    assert_eq!(listed.iter().find(|u| u.name == "carol").unwrap().policies, ["home"]);

    // Not an identity policy: refused, as IAM refuses it.
    let principal = r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}"#;
    let err = roles::put_policy(&client, &crate::roles::account(&client).await.unwrap(), "carol", "p", principal).await.unwrap_err();
    assert!(err.to_string().contains("principal"), "{err}");
    assert!(roles::put_policy(&client, &crate::roles::account(&client).await.unwrap(), "carol", "bad name", document).await.is_err());
    assert!(roles::put_policy(&client, &crate::roles::account(&client).await.unwrap(), "nobody", "home", document).await.is_err());
    // At most 2048 characters together, whitespace aside.
    let big = format!(
        r#"{{"Statement":[{{"Sid":"{}","Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}]}}"#,
        "x".repeat(1900)
    );
    let err = roles::put_policy(&client, &crate::roles::account(&client).await.unwrap(), "carol", "big", &big).await.unwrap_err();
    assert!(err.to_string().contains("2048"), "{err}");
    // Replacing a policy counts it once.
    roles::put_policy(&client, &crate::roles::account(&client).await.unwrap(), "carol", "home", &big).await.unwrap();

    roles::delete_policy(&client, &crate::roles::account(&client).await.unwrap(), "carol", "home").await.unwrap();
    assert!(roles::get_policy(&client, &crate::roles::account(&client).await.unwrap(), "carol", "home").await.is_err());
    assert!(roles::delete_policy(&client, &crate::roles::account(&client).await.unwrap(), "carol", "home").await.is_err());
}

/// A bucket policy names a user as the one that had the name when it was
/// set, as S3 does: one deleted and made again with the name isn't allowed
/// what the first was, and the policy shows the first by its ID. Older
/// Cairns' policies (written as they write them) are kept so too.
#[tokio::test]
async fn bucket_policies_name_users_as_they_were() {
    use crate::s3::{access, actions, buckets::policy};
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let name = format!("bob-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    roles::create(&client, &name, None, false).await.unwrap();
    let account = roles::account(&client).await.unwrap();
    let arn = format!("arn:aws:iam::{account}:user/{name}");
    let document = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{arn}"}},"Action":"s3:GetObject","Resource":"arn:aws:s3:::{BUCKET}/*"}}]}}"#
    );
    let set = policy::put_bucket_policy(&app, BUCKET, document.clone().into()).await.unwrap();
    assert_eq!(set.status(), hyper::StatusCode::NO_CONTENT);

    let read = actions::Check { action: "s3:GetObject", on: actions::On::Object(BUCKET.to_owned(), "k".to_owned()) };
    let allowed = |principal: Principal| {
        let app = app.clone();
        let read = read.clone();
        let account = account.clone();
        async move {
            let origin = access::Origin { peer: None, trusted_proxies: &[], signed: None, form: false };
            let headers = hyper::HeaderMap::new();
            let mut access =
                access::Access::new(Some(&principal), &account, &hyper::Method::GET, &headers, "", &origin).unwrap();
            access.load(&app, BUCKET).await.unwrap();
            access.allows(&read)
        }
    };
    let first = Principal::load(&client, &name).await.unwrap().unwrap();
    let first_id = first.id.to_string();
    assert!(allowed(first).await);
    let shown = |app: Arc<App>| async move {
        let response = policy::get_bucket_policy(&app, BUCKET).await.unwrap();
        let body = http_body_util::BodyExt::collect(response.into_body()).await.unwrap().to_bytes();
        String::from_utf8(body.to_vec()).unwrap()
    };
    assert!(shown(app.clone()).await.contains(&format!("\"AWS\":\"{arn}\"")));

    roles::delete(&client, &crate::roles::account(&client).await.unwrap(), &name).await.unwrap();
    roles::create(&client, &name, None, false).await.unwrap();
    let second = Principal::load(&client, &name).await.unwrap().unwrap();
    assert!(!allowed(second).await);
    assert!(shown(app.clone()).await.contains(&format!("\"AWS\":\"{first_id}\"")));

    // As an older Cairn writes it: the IDs are kept all the same.
    client.execute("UPDATE buckets SET policy = $2 WHERE name = $1", &[&BUCKET, &document]).await.unwrap();
    let second = Principal::load(&client, &name).await.unwrap().unwrap();
    assert!(allowed(second).await);
    client.execute("UPDATE buckets SET policy = NULL WHERE name = $1", &[&BUCKET]).await.unwrap();
}

/// The names of the managed policies attached to `user` of `account`.
async fn attached(client: &deadpool_postgres::Object, account: &str, user: &str) -> Vec<String> {
    crate::managed::attached(client, account, user).await.unwrap().into_iter().map(|a| a.name).collect()
}

/// Grants from before they were managed policies (rows of `role_grants`,
/// then statements of buckets' policies) move into managed policies, once,
/// and allow what they did; the bucket policy's other statements stay.
#[tokio::test]
async fn old_grants_move_into_managed_policies() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    roles::create(&client, "olga", None, false).await.unwrap();
    let account = roles::account(&client).await.unwrap();
    let mine = format!(
        r#"{{"Statement":[{{"Sid":"Mine","Effect":"Deny","Principal":"*","Action":"s3:DeleteBucket","Resource":"arn:aws:s3:::{BUCKET}"}}]}}"#
    );
    crate::s3::buckets::policy::put_bucket_policy(&app, BUCKET, mine.into()).await.unwrap();
    client
        .execute(
            "INSERT INTO role_grants (role, bucket, permission) VALUES ('olga', $1, 'read'), ('olga', $1, 'write')",
            &[&BUCKET],
        )
        .await
        .unwrap();
    assert_eq!(crate::grants::convert(&client).await.unwrap(), 2);
    assert_eq!(crate::grants::convert(&client).await.unwrap(), 0);
    let left: i64 = client.query_one("SELECT count(*) FROM role_grants", &[]).await.unwrap().get(0);
    assert_eq!(left, 0);
    // In the bucket's policy, as 0.6 kept them; then into managed policies.
    let policy: String =
        client.query_one("SELECT policy FROM buckets WHERE name = $1", &[&BUCKET]).await.unwrap().get(0);
    assert!(policy.contains(&format!("arn:aws:iam::{account}:user/olga")), "{policy}");
    // One the account has already, of another document, keeps its name.
    let other = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}"#;
    crate::managed::create(&client, &account, &format!("{BUCKET}-write"), "/", other, "").await.unwrap();
    assert_eq!(crate::grants::to_managed(&client).await.unwrap(), 2);
    assert_eq!(crate::grants::to_managed(&client).await.unwrap(), 0);
    assert_eq!(attached(&client, &account, "olga").await, [format!("{BUCKET}-read"), format!("{BUCKET}-write-grant")]);
    let policy: String =
        client.query_one("SELECT policy FROM buckets WHERE name = $1", &[&BUCKET]).await.unwrap().get(0);
    assert!(policy.contains(r#""Sid":"Mine""#), "{policy}");
    assert!(!policy.contains("CairnGrant"), "{policy}");
    // What they allow.
    let principal = Principal::load(&client, "olga").await.unwrap().unwrap();
    let origin = crate::s3::access::Origin { peer: None, trusted_proxies: &[], signed: None, form: false };
    let access = crate::s3::access::Access::new(Some(&principal), &account, &hyper::Method::GET, &Default::default(), "", &origin).unwrap();
    let on = || crate::s3::actions::On::Object(BUCKET.to_owned(), "a".to_owned());
    for (action, allowed) in [("s3:GetObject", true), ("s3:PutObject", true), ("s3:DeleteObjectVersion", false)] {
        assert_eq!(access.allows(&crate::s3::actions::Check { action, on: on() }), allowed, "{action}");
    }
    // Listed to the user, as buckets its policies let it list are.
    assert!(crate::s3::access::listable(&principal, &[BUCKET]).unwrap().contains(BUCKET));

    // Revoked (detached), and gone with the user.
    roles::revoke(&client, &account, "olga", BUCKET, &[roles::Permission::Write]).await.unwrap();
    assert_eq!(attached(&client, &account, "olga").await, [format!("{BUCKET}-read")]);
    roles::grant(&client, &account, "olga", BUCKET, &[roles::Permission::Write]).await.unwrap();
    assert_eq!(attached(&client, &account, "olga").await, [format!("{BUCKET}-read"), format!("{BUCKET}-write-grant")]);
    roles::delete(&client, &account, "olga").await.unwrap();
    let left: i64 = client.query_one("SELECT count(*) FROM role_attached_policies", &[]).await.unwrap().get(0);
    assert_eq!(left, 0);
}

/// There's an operator account besides the first tenant account; it owns
/// no buckets, and users and buckets are the tenant's unless said otherwise.
#[tokio::test]
async fn the_operator_account_owns_no_buckets() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let accounts = client.query("SELECT name, operator FROM accounts ORDER BY operator", &[]).await.unwrap();
    let accounts: Vec<(String, bool)> = accounts.iter().map(|r| (r.get(0), r.get(1))).collect();
    assert_eq!(accounts, [("default".to_owned(), false), ("operator".to_owned(), true)]);
    let owner: String =
        client.query_one("SELECT a.name FROM buckets b JOIN accounts a ON a.id = b.account_id WHERE b.name = $1", &[&BUCKET]).await.unwrap().get(0);
    assert_eq!(owner, "default");
    let refused = client
        .execute("UPDATE buckets SET account_id = (SELECT id FROM accounts WHERE operator) WHERE name = $1", &[&BUCKET])
        .await
        .unwrap_err();
    assert!(refused.to_string().contains("owns no buckets") || format!("{refused:?}").contains("owns no buckets"), "{refused:?}");
    // Its users are superadmins by being its users: no access keys, admin
    // flag or policies, and so nothing that signs requests.
    let operator = roles::operator_account(&client).await.unwrap();
    roles::create_without_key(&client, &operator, "superadmin").await.unwrap();
    let refused = |e: anyhow::Error| assert!(e.to_string().contains("superadmins"), "{e}");
    refused(roles::create_key(&client, &operator, "superadmin", Some("superadmin".into()), None).await.unwrap_err());
    refused(roles::create_for(&client, &operator, "another", None, false).await.unwrap_err());
    refused(roles::update(&client, &operator, "superadmin", Some(false), None).await.unwrap_err());
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;
    refused(roles::put_policy(&client, &operator, "superadmin", "all", policy).await.unwrap_err());
    // Nor straight into the database (as an older node would).
    let id = roles::id_of(&client, &operator, "superadmin").await.unwrap();
    let err = client
        .execute("INSERT INTO access_keys (access_key_id, role_id, secret) VALUES ('sneaky', $1, 'secret123')", &[&id])
        .await
        .unwrap_err();
    assert!(format!("{err:?}").contains("superadmins"), "{err:?}");
    // It's marked admin, for older nodes, which decide by that.
    let admin: bool = client.query_one("SELECT admin FROM roles WHERE id = $1", &[&id]).await.unwrap().get(0);
    assert!(admin);
    assert!(Principal::load(&client, "superadmin").await.unwrap().is_none());
}

/// User names are unique in their account, as in IAM: two accounts each
/// have an `ada`, with keys of their own; a grant, a policy and a bucket
/// policy name one of them, never the other.
#[tokio::test]
async fn accounts_have_users_of_the_same_name() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let default = roles::account(&client).await.unwrap();
    let acme = crate::accounts::create(&client, "acme").await.unwrap();
    let (first, _) = roles::create_for(&client, &default, "ada", None, false).await.unwrap();
    let (second, _) = roles::create_for(&client, &acme, "ada", None, false).await.unwrap();
    assert_ne!(first, second);
    assert!(first != "ada" && second != "ada");
    assert_eq!(Principal::load(&client, &first).await.unwrap().unwrap().account, default);
    assert_eq!(Principal::load(&client, &second).await.unwrap().unwrap().account, acme);
    // But not twice in one account.
    assert!(roles::create_for(&client, &acme, "ada", None, false).await.is_err());

    // A grant is the bucket's account's ada's.
    roles::grant(&client, &default, "ada", BUCKET, &[roles::Permission::Read]).await.unwrap();
    assert!(roles::grant(&client, &acme, "ada", BUCKET, &[roles::Permission::Read]).await.is_err());
    assert_eq!(attached(&client, &default, "ada").await, [format!("{BUCKET}-read")]);
    assert!(attached(&client, &acme, "ada").await.is_empty());
    let ours = Principal::load(&client, &first).await.unwrap().unwrap();
    let theirs = Principal::load(&client, &second).await.unwrap().unwrap();
    assert!(crate::s3::access::listable(&ours, &[BUCKET]).unwrap().contains(BUCKET));
    assert!(crate::s3::access::listable(&theirs, &[BUCKET]).unwrap().is_empty());

    // A bucket policy naming acme's ada binds acme's.
    let policy = format!(
        r#"{{"Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{acme}:user/ada"}},"Action":"s3:GetObject","Resource":"arn:aws:s3:::{BUCKET}/*"}}]}}"#
    );
    let set = crate::s3::buckets::policy::put_bucket_policy(&app, BUCKET, policy.into()).await.unwrap();
    assert_eq!(set.status(), hyper::StatusCode::NO_CONTENT);
    let ids: String =
        client.query_one("SELECT policy_principals::text FROM buckets WHERE name = $1", &[&BUCKET]).await.unwrap().get(0);
    assert!(ids.contains(&theirs.id.to_string()) && !ids.contains(&ours.id.to_string()), "{ids}");

    // Deleting one leaves the other.
    roles::delete(&client, &acme, "ada").await.unwrap();
    assert!(Principal::load(&client, &first).await.unwrap().is_some());
    assert!(Principal::load(&client, &second).await.unwrap().is_none());
}

/// A user with a permissions boundary is capped by it here; to older Cairns,
/// which know no boundaries, it has an inline policy that denies it
/// everything (which only they read), and they can't change users, keys or
/// policies at all, so as not to undo that.
#[tokio::test]
async fn older_cairns_deny_bounded_users_everything() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let account = roles::account(&client).await.unwrap();
    roles::create(&client, "bounded", None, false).await.unwrap();
    let all = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;
    roles::put_policy(&client, &account, "bounded", "all", all).await.unwrap();
    let list = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}"#;
    let bound = crate::managed::create(&client, &account, "bound", "/bounds/", list, "").await.unwrap();
    let id = roles::id_of(&client, &account, "bounded").await.unwrap();
    assert!(roles::set_boundary(&client, &account, id, Some(&roles::BoundaryRef::Own(bound.id))).await.unwrap());

    // Here: its policies, and its boundary, by its ARN (path and all).
    let principal = Principal::load(&client, "bounded").await.unwrap().unwrap();
    assert_eq!(principal.policies, [all]);
    let boundary = principal.boundary.as_ref().unwrap();
    assert_eq!(boundary.arn, format!("arn:aws:iam::{account}:policy/bounds/bound"));
    assert_eq!(boundary.document, list);
    let listed = roles::list(&client).await.unwrap();
    let user = listed.iter().find(|u| u.name == "bounded").unwrap();
    assert_eq!(user.policies, ["all"]);
    assert_eq!(user.boundary.as_deref(), Some(boundary.arn.as_str()));
    assert!(roles::get_policy(&client, &account, "bounded", "cairn:boundary").await.is_err());
    assert!(roles::delete_policy(&client, &account, "bounded", "cairn:boundary").await.is_err());

    // What an older Cairn reads: every inline policy, a Deny-all among them.
    let older: Vec<String> = client
        .query_one("SELECT ARRAY(SELECT document FROM role_policies WHERE role_id = $1 ORDER BY name)", &[&id])
        .await
        .unwrap()
        .get(0);
    assert_eq!(older.len(), 2);
    assert!(older.iter().any(|d| d.contains(r#""Effect":"Deny","Action":"*","Resource":"*""#)), "{older:?}");
    // The boundary can't be deleted while it's one.
    let err = crate::managed::delete(&client, &account, "bound").await.unwrap_err();
    assert!(err.to_string().contains("attached to entities"), "{err}");

    // An older Cairn's session changes no user, key or policy.
    let mut session = app.pool.get().await.unwrap();
    for change in [
        "DELETE FROM role_policies WHERE name = 'cairn:boundary'",
        "UPDATE roles SET boundary_policy_id = NULL WHERE name = 'bounded'",
        "INSERT INTO role_tags (role_id, key, value) SELECT id, 'k', 'v' FROM roles WHERE name = 'bounded'",
        "DELETE FROM access_keys",
        "DELETE FROM managed_policies WHERE name = 'nothing'",
    ] {
        let tx = session.transaction().await.unwrap();
        tx.batch_execute("SET LOCAL cairn.users = '2'").await.unwrap();
        let err = tx.batch_execute(change).await.unwrap_err();
        assert!(format!("{err:?}").contains("too old to change users"), "{change}: {err:?}");
    }

    // Without its boundary, the Deny-all goes too.
    assert!(roles::set_boundary(&client, &account, id, None).await.unwrap());
    assert!(Principal::load(&client, "bounded").await.unwrap().unwrap().boundary.is_none());
    let count: i64 = client.query_one("SELECT count(*) FROM role_policies WHERE role_id = $1", &[&id]).await.unwrap().get(0);
    assert_eq!(count, 1);
    crate::managed::delete(&client, &account, "bound").await.unwrap();
}

/// User names are unique in an account regardless of case, as IAM's; a
/// user's tags are at most 50, their keys unique regardless of case.
#[tokio::test]
async fn names_and_tag_keys_are_unique_regardless_of_case() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let account = roles::account(&client).await.unwrap();
    roles::create_user(&client, &account, "Ada", "/team/", None).await.unwrap();
    let err = roles::create_user(&client, &account, "ada", "/", None).await.unwrap_err();
    assert!(err.to_string().contains("already exists"), "{err}");
    roles::create_user(&client, &account, "bob", "/", None).await.unwrap();
    let ada = roles::id_of(&client, &account, "Ada").await.unwrap();
    let err = roles::rename(&client, &account, ada, "BOB", "/").await.unwrap_err();
    assert!(err.to_string().contains("already exists"), "{err}");
    roles::rename(&client, &account, ada, "ADA", "/elsewhere/").await.unwrap();
    let user = roles::Target::load(&client, &account, "ADA").await.unwrap().unwrap();
    assert_eq!(user.arn(), format!("arn:aws:iam::{account}:user/elsewhere/ADA"));

    let tags = |pairs: &[(&str, &str)]| pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<Vec<_>>();
    roles::tag(&client, ada, &tags(&[("team", "a"), ("env", "dev")])).await.unwrap();
    roles::tag(&client, ada, &tags(&[("Team", "b")])).await.unwrap();
    let user = roles::Target::load(&client, &account, "ADA").await.unwrap().unwrap();
    assert_eq!(user.tags, tags(&[("Team", "b"), ("env", "dev")]));
    assert_eq!(user.context("iam:GetUser").get("aws:ResourceTag/team"), Some(&["b".to_owned()][..]));
    let many: Vec<(String, String)> = (0..49).map(|i| (format!("k{i}"), String::new())).collect();
    let err = roles::tag(&client, ada, &many).await.unwrap_err();
    assert!(err.downcast_ref::<roles::TooManyTags>().is_some(), "{err}");
    roles::tag(&client, ada, &many[..48]).await.unwrap();
    roles::untag(&client, ada, &["TEAM".to_owned(), "nope".to_owned()]).await.unwrap();
    let user = roles::Target::load(&client, &account, "ADA").await.unwrap().unwrap();
    assert_eq!(user.tags.len(), 49);
}
