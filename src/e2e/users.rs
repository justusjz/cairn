//! Users, their access keys and inline policies (see `roles`), against a
//! real Postgres.

use std::sync::Arc;

use super::{BUCKET, node_with};
use crate::{
    App, packer,
    users::{self, Principal},
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
    let secret = users::create(&client, "alice", None, false).await.unwrap();
    let principal = Principal::load(&client, "alice").await.unwrap().unwrap();
    assert_eq!((principal.name.as_str(), principal.secret.as_str()), ("alice", secret.as_str()));
    assert_eq!(principal.account, users::account(&client).await.unwrap());
    assert_eq!(principal.account.len(), 12);

    let (id, second) = users::create_key(&client, &crate::users::account(&client).await.unwrap(), "alice", None, None).await.unwrap();
    assert_eq!(id.len(), 20);
    assert_eq!(Principal::load(&client, &id).await.unwrap().unwrap().secret, second);
    // At most two, as in IAM.
    let third = users::create_key(&client, &crate::users::account(&client).await.unwrap(), "alice", None, None).await.unwrap_err();
    assert!(third.to_string().contains("2 access keys"), "{third}");
    assert!(users::create_key(&client, &crate::users::account(&client).await.unwrap(), "nobody", None, None).await.unwrap_err().to_string().contains("no user"));

    users::set_key_active(&client, None, &id, false).await.unwrap();
    assert!(Principal::load(&client, &id).await.unwrap().is_none());
    users::set_key_active(&client, None, &id, true).await.unwrap();
    assert!(Principal::load(&client, &id).await.unwrap().is_some());
    // Only the user's own, when the user is named (as the console does).
    users::create(&client, "mallory", None, false).await.unwrap();
    assert!(users::set_key_active(&client, Some((&crate::users::account(&client).await.unwrap(), "mallory")), &id, false).await.is_err());
    assert!(users::delete_key(&client, Some((&crate::users::account(&client).await.unwrap(), "mallory")), &id).await.is_err());
    assert!(Principal::load(&client, &id).await.unwrap().is_some());
    users::delete_key(&client, Some((&crate::users::account(&client).await.unwrap(), "alice")), &id).await.unwrap();
    assert!(Principal::load(&client, &id).await.unwrap().is_none());
    assert!(users::delete_key(&client, None, &id).await.is_err());

    // A new user's key is of a random ID, as IAM's, not its name; older
    // Cairns, which know only keys named as users, get no usable secret.
    users::create_key(&client, &crate::users::account(&client).await.unwrap(), "alice", Some("shared".to_owned()), None).await.unwrap();
    let account = crate::users::account(&client).await.unwrap();
    let (key, secret) = users::create_for(&client, &account, "shared", None, false).await.unwrap();
    assert_ne!(key, "shared");
    assert_eq!(key.len(), 20);
    assert_eq!(Principal::load(&client, &key).await.unwrap().unwrap().secret, secret);
    assert!(legacy_secret(&app, "shared").await.starts_with("unusable:"));
    users::delete(&client, &account, "shared").await.unwrap();

    let listed = users::list(&client).await.unwrap();
    let alice = listed.iter().find(|u| u.name == "alice").unwrap();
    assert_eq!(alice.keys.iter().map(|k| k.id.as_str()).collect::<Vec<_>>(), ["alice", "shared"]);

    // Deleting the user deletes its keys.
    users::delete(&client, &crate::users::account(&client).await.unwrap(), "alice").await.unwrap();
    assert!(Principal::load(&client, "shared").await.unwrap().is_none());
}

/// Older Cairns authenticate with `roles.secret`: it's the secret of the key
/// named as the user, while that's active, and none that can be guessed
/// otherwise; and they can't change users.
#[tokio::test]
async fn older_cairns_see_the_first_keys_secret_and_cant_change_users() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let secret = users::create(&client, "bob", None, false).await.unwrap();
    assert_eq!(legacy_secret(&app, "bob").await, secret);
    let rotated = users::generate_secret().unwrap();
    users::update(&client, &crate::users::account(&client).await.unwrap(), "bob", None, Some(rotated.clone())).await.unwrap();
    assert_eq!(legacy_secret(&app, "bob").await, rotated);
    assert_eq!(Principal::load(&client, "bob").await.unwrap().unwrap().secret, rotated);
    users::set_key_active(&client, None, "bob", false).await.unwrap();
    assert!(legacy_secret(&app, "bob").await.starts_with("unusable:"));
    users::set_key_active(&client, None, "bob", true).await.unwrap();
    assert_eq!(legacy_secret(&app, "bob").await, rotated);
    users::delete_key(&client, None, "bob").await.unwrap();
    assert!(legacy_secret(&app, "bob").await.starts_with("unusable:"));
    // Without its first key, the user's other keys are rotated as keys.
    let err = users::update(&client, &crate::users::account(&client).await.unwrap(), "bob", None, Some(rotated)).await.unwrap_err();
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

/// Older Cairns read users by the tables' and columns' old names (migration
/// 47), as they loaded a request's user; they may not link logins to users.
#[tokio::test]
async fn older_cairns_read_users_by_their_old_names() {
    let Some(app) = node().await else { return };
    let mut client = app.pool.get().await.unwrap();
    let secret = users::create(&client, "olaf", None, false).await.unwrap();
    let account = crate::users::account(&client).await.unwrap();
    users::put_policy(&client, &account, "olaf", "own", r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#)
        .await
        .unwrap();
    crate::managed::attach(&client, &account, "olaf", "arn:aws:iam::aws:policy/CairnOperatorAccess", true).await.unwrap();
    let id = crate::users::id_of(&client, &account, "olaf").await.unwrap();
    users::tag(&client, id, &[("team".to_owned(), "a".to_owned())]).await.unwrap();
    // Cairn 0.6's query, but for its columns that came later.
    let row = client
        .query_one(
            "SELECT k.secret, r.admin, r.name, r.account_id,
                    ARRAY(SELECT document FROM role_policies WHERE role_id = r.id AND name NOT LIKE 'cairn:%' ORDER BY name),
                    ARRAY(SELECT x.aws_policy FROM role_attached_policies x WHERE x.role_id = r.id AND x.aws_policy IS NOT NULL),
                    ARRAY(SELECT t.key FROM role_tags t WHERE t.role_id = r.id ORDER BY t.seq DESC)
             FROM access_keys k JOIN roles r ON r.id = k.role_id
             JOIN accounts a ON a.id = r.account_id
             WHERE k.access_key_id = $1 AND k.active AND NOT a.operator",
            &[&"olaf"],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), secret);
    assert_eq!(row.get::<_, Vec<String>>(4).len(), 1);
    assert_eq!(row.get::<_, Vec<String>>(5), ["CairnOperatorAccess"]);
    assert_eq!(row.get::<_, Vec<String>>(6), ["team"]);

    let tx = client.transaction().await.unwrap();
    tx.batch_execute("SET LOCAL cairn.users = '5'").await.unwrap();
    let err = tx.batch_execute("DELETE FROM login_identities").await.unwrap_err();
    assert!(format!("{err:?}").contains("too old to change users"), "{err:?}");
}

#[tokio::test]
async fn inline_policies_are_checked_and_kept_as_given() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    users::create(&client, "carol", None, false).await.unwrap();
    let document = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject",
        "Resource":"arn:aws:s3:::bucket/home/${aws:username}/*"}]}"#;
    users::put_policy(&client, &crate::users::account(&client).await.unwrap(), "carol", "home", document).await.unwrap();
    assert_eq!(users::get_policy(&client, &crate::users::account(&client).await.unwrap(), "carol", "home").await.unwrap(), document);
    assert_eq!(Principal::load(&client, "carol").await.unwrap().unwrap().policies, [document]);
    let listed = users::list(&client).await.unwrap();
    assert_eq!(listed.iter().find(|u| u.name == "carol").unwrap().policies, ["home"]);

    // Not an identity policy: refused, as IAM refuses it.
    let principal = r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}"#;
    let err = users::put_policy(&client, &crate::users::account(&client).await.unwrap(), "carol", "p", principal).await.unwrap_err();
    assert!(err.to_string().contains("principal"), "{err}");
    assert!(users::put_policy(&client, &crate::users::account(&client).await.unwrap(), "carol", "bad name", document).await.is_err());
    assert!(users::put_policy(&client, &crate::users::account(&client).await.unwrap(), "nobody", "home", document).await.is_err());
    // At most 2048 characters together, whitespace aside.
    let big = format!(
        r#"{{"Statement":[{{"Sid":"{}","Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}]}}"#,
        "x".repeat(1900)
    );
    let err = users::put_policy(&client, &crate::users::account(&client).await.unwrap(), "carol", "big", &big).await.unwrap_err();
    assert!(err.to_string().contains("2048"), "{err}");
    // Replacing a policy counts it once.
    users::put_policy(&client, &crate::users::account(&client).await.unwrap(), "carol", "home", &big).await.unwrap();

    users::delete_policy(&client, &crate::users::account(&client).await.unwrap(), "carol", "home").await.unwrap();
    assert!(users::get_policy(&client, &crate::users::account(&client).await.unwrap(), "carol", "home").await.is_err());
    assert!(users::delete_policy(&client, &crate::users::account(&client).await.unwrap(), "carol", "home").await.is_err());
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
    users::create(&client, &name, None, false).await.unwrap();
    let account = users::account(&client).await.unwrap();
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

    users::delete(&client, &crate::users::account(&client).await.unwrap(), &name).await.unwrap();
    users::create(&client, &name, None, false).await.unwrap();
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
    users::create(&client, "olga", None, false).await.unwrap();
    let account = users::account(&client).await.unwrap();
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
    users::revoke(&client, &account, "olga", BUCKET, &[users::Permission::Write]).await.unwrap();
    assert_eq!(attached(&client, &account, "olga").await, [format!("{BUCKET}-read")]);
    users::grant(&client, &account, "olga", BUCKET, &[users::Permission::Write]).await.unwrap();
    assert_eq!(attached(&client, &account, "olga").await, [format!("{BUCKET}-read"), format!("{BUCKET}-write-grant")]);
    users::delete(&client, &account, "olga").await.unwrap();
    let left: i64 = client.query_one("SELECT count(*) FROM user_attached_policies", &[]).await.unwrap().get(0);
    assert_eq!(left, 0);
}

/// Cairn has one account (see `plans/single-account.md`): it owns every user
/// and bucket, and no second one can be made, even by an older node. The
/// operator account's row, which older nodes read, is left empty.
#[tokio::test]
async fn there_is_one_account() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let owner: String = client.query_one("SELECT account_id FROM buckets WHERE name = $1", &[&BUCKET]).await.unwrap().get(0);
    assert_eq!(owner, account);
    let err = client.execute("INSERT INTO accounts (id, name) VALUES ('000000000042', 'acme')", &[]).await.unwrap_err();
    assert!(format!("{err:?}").contains("accounts_one"), "{err:?}");
    let mut session = app.pool.get().await.unwrap();
    let tx = session.transaction().await.unwrap();
    tx.batch_execute("SET LOCAL cairn.users = '4'").await.unwrap();
    let err = tx.batch_execute("INSERT INTO accounts (id, name) VALUES ('000000000042', 'acme')").await.unwrap_err();
    assert!(format!("{err:?}").contains("too old to change users"), "{err:?}");
}

/// Operators are users whose policies allow `cairn:` actions: Cairn's
/// `CairnOperatorAccess` allows those and nothing else; `AdministratorAccess`
/// everything.
#[tokio::test]
async fn operators_are_users_with_cairn_actions() {
    use crate::s3::{access::{Access, Origin}, actions::{Check, On}};
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    users::create(&client, "ops", None, false).await.unwrap();
    users::create(&client, "boss", None, true).await.unwrap();
    users::create(&client, "nobody", None, false).await.unwrap();
    crate::managed::attach(&client, &account, "ops", "arn:aws:iam::aws:policy/CairnOperatorAccess", true).await.unwrap();
    let may = async |user: &str, action: &'static str, on: On| {
        let principal = Principal::load(&client, user).await.unwrap().unwrap();
        let origin = Origin { peer: None, trusted_proxies: &[], signed: None, form: false };
        let mut access = Access::new(Some(&principal), &account, &hyper::Method::GET, &hyper::HeaderMap::new(), "", &origin).unwrap();
        let check = Check { action, on };
        access.load_all(&app, std::slice::from_ref(&check)).await.unwrap();
        access.allows(&check)
    };
    let object = || On::Object(BUCKET.to_owned(), "k".to_owned());
    assert!(may("ops", "cairn:GetCluster", On::Cluster).await);
    assert!(may("ops", "cairn:PutSetting", On::Cluster).await);
    assert!(!may("ops", "s3:GetObject", object()).await);
    assert!(!may("ops", "iam:CreateUser", On::user(&account, "/", "x")).await);
    assert!(may("boss", "cairn:PutSetting", On::Cluster).await);
    assert!(may("boss", "s3:GetObject", object()).await);
    assert!(!may("nobody", "cairn:GetCluster", On::Cluster).await);
}

/// Migration 45 makes the operator account's people the account's (see
/// `db::SINGLE_ACCOUNT`): a superadmin with no identity in the account moves
/// into it, as an admin; one whose login is in it already goes, making that
/// user admin; the operator's root becomes the account's, which had none.
/// Empty accounts go. Then migration 46 (`db::NO_ROOT`) makes the root an
/// admin user, `root`.
#[tokio::test]
async fn the_operators_join_the_account() {
    let Some(pool) = super::fresh_database_through(44).await else { return };
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    tx.batch_execute(
        "SET LOCAL cairn.users = '4';
         INSERT INTO accounts (id, name) VALUES ('000000000042', 'spare');
         INSERT INTO roles (name, secret, admin, account_id)
             SELECT 'ada', 'secret123', false, id FROM accounts WHERE name = 'default';
         INSERT INTO roles (name, secret, admin, account_id)
             SELECT n, 'unusable:x', true, id FROM accounts, (VALUES ('sam'), ('ada-ops')) v(n) WHERE operator;
         INSERT INTO logins (id, name) VALUES
             ('00000000-0000-4000-8000-000000000001', 'sam'),
             ('00000000-0000-4000-8000-000000000002', 'ada'),
             ('00000000-0000-4000-8000-000000000003', 'olga');
         INSERT INTO login_identities (login_id, account_id, role_id)
             SELECT '00000000-0000-4000-8000-000000000001', r.account_id, r.id FROM roles r WHERE r.name = 'sam';
         INSERT INTO login_identities (login_id, account_id, role_id)
             SELECT '00000000-0000-4000-8000-000000000002', r.account_id, r.id FROM roles r WHERE r.name IN ('ada', 'ada-ops');
         INSERT INTO login_identities (login_id, account_id, role_id)
             SELECT '00000000-0000-4000-8000-000000000003', id, NULL FROM accounts WHERE operator;",
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    crate::db::init(&pool, usize::MAX).await.unwrap();

    let account = users::account(&client).await.unwrap();
    let names: Vec<String> = client.query("SELECT name FROM accounts WHERE NOT operator", &[]).await.unwrap().iter().map(|r| r.get(0)).collect();
    assert_eq!(names, ["default"]);
    let operators: i64 =
        client.query_one("SELECT count(*) FROM users r JOIN accounts a ON a.id = r.account_id WHERE a.operator", &[]).await.unwrap().get(0);
    assert_eq!(operators, 0);
    let users: Vec<(String, bool, String)> = client
        .query("SELECT name, admin, account_id FROM users ORDER BY name", &[])
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect();
    assert_eq!(
        users,
        [("ada".to_owned(), true, account.clone()), ("root".to_owned(), true, account.clone()), ("sam".to_owned(), true, account.clone())]
    );
    let identities: Vec<(String, String, Option<String>)> = client
        .query(
            "SELECT l.name, i.account_id, r.name FROM login_identities i JOIN logins l ON l.id = i.login_id
             LEFT JOIN users r ON r.id = i.user_id ORDER BY l.name",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect();
    assert_eq!(
        identities,
        [
            ("ada".to_owned(), account.clone(), Some("ada".to_owned())),
            ("olga".to_owned(), account.clone(), Some("root".to_owned())),
            ("sam".to_owned(), account.clone(), Some("sam".to_owned())),
        ]
    );
}

/// Migration 46 makes the root's login an admin user, `root`, or `root-2`
/// if there's a `root` already; the root's enrollment links go, and no
/// identity or link may be a root's any more.
#[tokio::test]
async fn the_roots_login_becomes_an_admin() {
    let Some(pool) = super::fresh_database_through(45).await else { return };
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    tx.batch_execute(
        "SET LOCAL cairn.users = '5';
         INSERT INTO roles (name, secret, admin, account_id)
             SELECT 'Root', 'secret123', false, id FROM accounts WHERE NOT operator;
         INSERT INTO logins (id, name) VALUES ('00000000-0000-4000-8000-000000000001', 'rita');
         INSERT INTO login_identities (login_id, account_id, role_id)
             SELECT '00000000-0000-4000-8000-000000000001', id, NULL FROM accounts WHERE NOT operator;
         INSERT INTO console_enrollments (token_hash, role_id, account_id, expires_at)
             SELECT '\\x00', NULL, id, now() + interval '1 day' FROM accounts WHERE NOT operator;",
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    crate::db::init(&pool, usize::MAX).await.unwrap();
    let row = client
        .query_one(
            "SELECT r.name, r.admin FROM login_identities i JOIN users r ON r.id = i.user_id
             WHERE i.login_id = '00000000-0000-4000-8000-000000000001'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!((row.get::<_, String>(0), row.get::<_, bool>(1)), ("root-2".to_owned(), true));
    let links: i64 = client.query_one("SELECT count(*) FROM console_enrollments", &[]).await.unwrap().get(0);
    assert_eq!(links, 0);
    let err = client
        .execute(
            "INSERT INTO console_enrollments (token_hash, user_id, account_id, expires_at)
             SELECT '\\x01', NULL, id, now() FROM accounts WHERE NOT operator",
            &[],
        )
        .await
        .unwrap_err();
    assert!(format!("{err:?}").contains("not-null") || format!("{err:?}").contains("NotNull"), "{err:?}");
}

/// Migration 45 is refused while two accounts have users or buckets, or
/// a superadmin has a user's name, and changes nothing then.
#[tokio::test]
async fn one_account_is_refused_while_two_are_used() {
    for (setup, refusal) in [
        (
            "INSERT INTO accounts (id, name) VALUES ('000000000042', 'acme');
             INSERT INTO roles (name, secret, admin, account_id) VALUES ('eve', 'secret123', false, '000000000042');
             INSERT INTO roles (name, secret, admin, account_id)
                 SELECT 'ada', 'secret123', false, id FROM accounts WHERE name = 'default';",
            "these have users or buckets: acme, default",
        ),
        (
            "INSERT INTO roles (name, secret, admin, account_id)
                 SELECT 'ada', 'secret123', false, id FROM accounts WHERE name = 'default';
             INSERT INTO roles (name, secret, admin, account_id)
                 SELECT 'Ada', 'unusable:x', true, id FROM accounts WHERE operator;",
            "user Ada has the name of another user",
        ),
    ] {
        let Some(pool) = super::fresh_database_through(44).await else { return };
        let mut client = pool.get().await.unwrap();
        let tx = client.transaction().await.unwrap();
        tx.batch_execute("SET LOCAL cairn.users = '4'").await.unwrap();
        tx.batch_execute(setup).await.unwrap();
        tx.commit().await.unwrap();
        let err = crate::db::init(&pool, usize::MAX).await.unwrap_err();
        assert!(format!("{err:?}").contains(refusal), "{err:?}");
        let version: i32 = client.query_one("SELECT max(version) FROM schema_migrations", &[]).await.unwrap().get(0);
        assert_eq!(version, 44);
    }
}

/// A user with a permissions boundary is capped by it here; to older Cairns,
/// which know no boundaries, it has an inline policy that denies it
/// everything (which only they read), and they can't change users, keys or
/// policies at all, so as not to undo that.
#[tokio::test]
async fn older_cairns_deny_bounded_users_everything() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    users::create(&client, "bounded", None, false).await.unwrap();
    let all = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;
    users::put_policy(&client, &account, "bounded", "all", all).await.unwrap();
    let list = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}"#;
    let bound = crate::managed::create(&client, &account, "bound", "/bounds/", list, "").await.unwrap();
    let id = users::id_of(&client, &account, "bounded").await.unwrap();
    assert!(users::set_boundary(&client, &account, id, Some(&users::BoundaryRef::Own(bound.id))).await.unwrap());

    // Here: its policies, and its boundary, by its ARN (path and all).
    let principal = Principal::load(&client, "bounded").await.unwrap().unwrap();
    assert_eq!(principal.policies, [all]);
    let boundary = principal.boundary.as_ref().unwrap();
    assert_eq!(boundary.arn, format!("arn:aws:iam::{account}:policy/bounds/bound"));
    assert_eq!(boundary.document, list);
    let listed = users::list(&client).await.unwrap();
    let user = listed.iter().find(|u| u.name == "bounded").unwrap();
    assert_eq!(user.policies, ["all"]);
    assert_eq!(user.boundary.as_deref(), Some(boundary.arn.as_str()));
    assert!(users::get_policy(&client, &account, "bounded", "cairn:boundary").await.is_err());
    assert!(users::delete_policy(&client, &account, "bounded", "cairn:boundary").await.is_err());

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
    assert!(users::set_boundary(&client, &account, id, None).await.unwrap());
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
    let account = users::account(&client).await.unwrap();
    users::create_user(&client, &account, "Ada", "/team/", None).await.unwrap();
    let err = users::create_user(&client, &account, "ada", "/", None).await.unwrap_err();
    assert!(err.to_string().contains("already exists"), "{err}");
    users::create_user(&client, &account, "bob", "/", None).await.unwrap();
    let ada = users::id_of(&client, &account, "Ada").await.unwrap();
    let err = users::rename(&client, &account, ada, "BOB", "/").await.unwrap_err();
    assert!(err.to_string().contains("already exists"), "{err}");
    users::rename(&client, &account, ada, "ADA", "/elsewhere/").await.unwrap();
    let user = users::Target::load(&client, &account, "ADA").await.unwrap().unwrap();
    assert_eq!(user.arn(), format!("arn:aws:iam::{account}:user/elsewhere/ADA"));

    let tags = |pairs: &[(&str, &str)]| pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<Vec<_>>();
    users::tag(&client, ada, &tags(&[("team", "a"), ("env", "dev")])).await.unwrap();
    users::tag(&client, ada, &tags(&[("Team", "b")])).await.unwrap();
    let user = users::Target::load(&client, &account, "ADA").await.unwrap().unwrap();
    assert_eq!(user.tags, tags(&[("Team", "b"), ("env", "dev")]));
    assert_eq!(user.context("iam:GetUser").get("aws:ResourceTag/team"), Some(&["b".to_owned()][..]));
    let many: Vec<(String, String)> = (0..49).map(|i| (format!("k{i}"), String::new())).collect();
    let err = users::tag(&client, ada, &many).await.unwrap_err();
    assert!(err.downcast_ref::<users::TooManyTags>().is_some(), "{err}");
    users::tag(&client, ada, &many[..48]).await.unwrap();
    users::untag(&client, ada, &["TEAM".to_owned(), "nope".to_owned()]).await.unwrap();
    let user = users::Target::load(&client, &account, "ADA").await.unwrap().unwrap();
    assert_eq!(user.tags.len(), 49);
}

/// A managed policy's tags, whose keys (unlike users') are case-sensitive,
/// as IAM's (probed).
#[tokio::test]
async fn policies_tag_keys_are_case_sensitive() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let document = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}"#;
    let tags = |pairs: &[(&str, &str)]| pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<Vec<_>>();
    let policy = crate::managed::create_tagged(&client, &account, "p", "/", document, "", &tags(&[("team", "a")])).await.unwrap();
    assert_eq!(policy.tags, tags(&[("team", "a")]));
    crate::managed::tag(&client, policy.id, &tags(&[("Team", "b"), ("team", "c")])).await.unwrap();
    assert_eq!(crate::managed::get(&client, &account, "p").await.unwrap().tags, tags(&[("Team", "b"), ("team", "c")]));
    crate::managed::untag(&client, policy.id, &["TEAM".to_owned(), "team".to_owned()]).await.unwrap();
    assert_eq!(crate::managed::get(&client, &account, "p").await.unwrap().tags, tags(&[("Team", "b")]));
    assert!(crate::managed::check_tags(&tags(&[("k", "1"), ("K", "2")])).is_ok());
    assert!(crate::managed::check_tags(&tags(&[("k", "1"), ("k", "2")])).is_err());
    // Deleted with the policy.
    crate::managed::delete(&client, &account, "p").await.unwrap();
    let left: i64 = client.query_one("SELECT count(*) FROM managed_policy_tags", &[]).await.unwrap().get(0);
    assert_eq!(left, 0);
}

/// A managed policy's versions, as IAM's (probed): up to five, numbered on
/// and never again, the default deciding (a user's policies are its
/// default's document), which can't be deleted, nor can the policy while it
/// has others; the console's edit makes room as Terraform does.
#[tokio::test]
async fn policies_keep_five_versions_and_the_default_decides() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let doc = |action: &str| format!(r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"{action}","Resource":"*"}}]}}"#);
    let policy = crate::managed::create(&client, &account, "p", "/", &doc("s3:ListBucket"), "").await.unwrap();
    let arn = policy.arn(&account);
    users::create(&client, "vera", None, false).await.unwrap();
    crate::managed::attach(&client, &account, "vera", &arn, true).await.unwrap();
    let decides = async || Principal::load(&client, "vera").await.unwrap().unwrap().policies;
    assert_eq!(decides().await, [doc("s3:ListBucket")]);

    let v2 = crate::managed::create_version(&client, policy.id, &arn, &doc("s3:GetObject"), false, false).await.unwrap();
    assert_eq!(v2, 2);
    assert_eq!(decides().await, [doc("s3:ListBucket")], "not the default");
    crate::managed::set_default(&client, policy.id, &arn, 2).await.unwrap();
    assert_eq!(decides().await, [doc("s3:GetObject")]);
    assert_eq!(crate::managed::get(&client, &account, "p").await.unwrap().version, 2);
    let err = crate::managed::delete_version(&client, policy.id, &arn, 2).await.unwrap_err();
    assert!(err.to_string().contains("default version"), "{err}");
    let err = crate::managed::set_default(&client, policy.id, &arn, 9).await.unwrap_err();
    assert!(err.to_string().contains("version v9 does not exist"), "{err}");

    for _ in 0..3 {
        crate::managed::create_version(&client, policy.id, &arn, &doc("s3:PutObject"), false, false).await.unwrap();
    }
    let err = crate::managed::create_version(&client, policy.id, &arn, &doc("s3:PutObject"), true, false).await.unwrap_err();
    assert!(err.to_string().contains("up to 5 versions"), "{err}");
    crate::managed::delete_version(&client, policy.id, &arn, 3).await.unwrap();
    let v6 = crate::managed::create_version(&client, policy.id, &arn, &doc("s3:PutObject"), false, false).await.unwrap();
    assert_eq!(v6, 6, "numbers aren't reused");
    let numbers = |vs: Vec<crate::managed::Version>| vs.iter().map(|v| (v.version, v.default)).collect::<Vec<_>>();
    let versions = crate::managed::versions(&client, policy.id).await.unwrap();
    assert_eq!(numbers(versions), [(6, false), (5, false), (4, false), (2, true), (1, false)]);
    // The console's edit: room made by deleting the oldest but the default.
    assert_eq!(crate::managed::update(&client, &account, "p", &doc("s3:DeleteObject")).await.unwrap(), 7);
    let versions = crate::managed::versions(&client, policy.id).await.unwrap();
    assert_eq!(numbers(versions), [(7, true), (6, false), (5, false), (4, false), (2, false)]);
    assert_eq!(decides().await, [doc("s3:DeleteObject")]);

    crate::managed::attach(&client, &account, "vera", &arn, false).await.unwrap();
    let err = crate::managed::delete(&client, &account, "p").await.unwrap_err();
    assert!(err.to_string().contains("more than one version"), "{err}");
    for v in [2, 4, 5, 6] {
        crate::managed::delete_version(&client, policy.id, &arn, v).await.unwrap();
    }
    crate::managed::delete(&client, &account, "p").await.unwrap();
}
