//! Directory users, as IAM Identity Center has them: people an identity
//! source vouches for when they sign in, rather than IAM users the account
//! keeps. Cairn's identity sources are the console's OpenID Connect
//! providers (see `console::oidc`), which operators configure, each with the
//! claim its ID tokens carry a person's groups in.
//!
//! What a directory user may do is what the **permission sets** assigned to
//! it, or to one of its groups, allow. As in Identity Center, a permission
//! set is provisioned as a role of the account: at
//! `/aws-reserved/sso.amazonaws.com/`, named `AWSReservedSSO_<set>_<suffix>`,
//! trusting `sso.amazonaws.com` only (so that no one assumes it with STS),
//! holding the set's policies. Only the permission set changes it: IAM
//! refuses to (`roles::protected`). A directory user signed in to the
//! console picks one of its permission sets, and acts as a session of its
//! role (`assumed-role/AWSReservedSSO_…/<name>`), which may hand it the
//! session's credentials for the CLI too (see `console::directory`).
//!
//! An **assignment** gives a permission set to a user, by its subject at a
//! source (`sub`), or to a group, by its name in the source's group claim.
//! Cairn learns of users and their groups only when they sign in
//! (`directory_users`): there's no SCIM.

use anyhow::Context as _;
use deadpool_postgres::Object;
use uuid::Uuid;

use crate::{
    db::Cached,
    managed::Refused,
    roles::{self, Role},
};

/// The path of the roles permission sets are provisioned as.
pub const ROLE_PATH: &str = "/aws-reserved/sso.amazonaws.com/";
/// The service those roles trust: Identity Center's, which no request is.
pub const SERVICE: &str = "sso.amazonaws.com";
/// The name of a permission set's role's inline policy, as Identity Center
/// names it.
pub const INLINE_POLICY: &str = "AwsSSOInlinePolicy";
/// A permission set's session: an hour by default, at most 12, as
/// Identity Center's.
pub const SESSION_DURATIONS: std::ops::RangeInclusive<i32> = 3600..=43200;
pub const DEFAULT_SESSION: i32 = 3600;

fn refused<T>(why: Refused) -> anyhow::Result<T> {
    Err(why.into())
}

/// `account`'s Identity Center instance's ARN (made up of the account's
/// ID, as there's one).
pub fn instance_arn(account: &str) -> String {
    format!("arn:aws:sso:::instance/ssoins-{}", short_hash(account.as_bytes()))
}

/// A permission set's ARN.
pub fn permission_set_arn(account: &str, id: Uuid) -> String {
    format!("arn:aws:sso:::permissionSet/ssoins-{}/ps-{}", short_hash(account.as_bytes()), &id.simple().to_string()[..16])
}

/// 16 hex digits of `bytes`'s SHA-256.
fn short_hash(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    digest.as_ref()[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether `name` is a permission set's name, as Identity Center takes one.
pub fn valid_name(name: &str) -> bool {
    (1..=32).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"+=,.@_-".contains(&b))
}

/// A permission set's role's trust policy: Identity Center's only.
fn trust() -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"{SERVICE}"}},"Action":["sts:AssumeRole","sts:TagSession"]}}]}}"#
    )
}

/// A permission set.
#[derive(Clone, Debug)]
pub struct PermissionSet {
    pub id: Uuid,
    pub account: String,
    pub name: String,
    pub description: String,
    /// Its sessions' longest, in seconds.
    pub session_duration: i32,
    /// The role it's provisioned as.
    pub role_id: Uuid,
    pub role_name: String,
    /// When it was made (seconds since the epoch).
    pub created: f64,
}

const COLUMNS: &str = "p.id, p.account_id, p.name, p.description, p.session_duration, p.role_id, r.name,
     extract(epoch FROM p.created_at)::float8";

impl PermissionSet {
    fn of(row: &tokio_postgres::Row) -> PermissionSet {
        PermissionSet {
            id: row.get(0),
            account: row.get(1),
            name: row.get(2),
            description: row.get(3),
            session_duration: row.get(4),
            role_id: row.get(5),
            role_name: row.get(6),
            created: row.get(7),
        }
    }

    pub fn arn(&self) -> String {
        permission_set_arn(&self.account, self.id)
    }

    pub fn role_arn(&self) -> String {
        roles::role_arn(&self.account, ROLE_PATH, &self.role_name)
    }

    /// Its role.
    pub async fn role(&self, client: &Object) -> anyhow::Result<Role> {
        Role::load_id(client, self.role_id).await?.context("a permission set's role is gone")
    }
}

/// `account`'s permission set `name`, if there's one.
pub async fn load(client: &Object, account: &str, name: &str) -> anyhow::Result<Option<PermissionSet>> {
    let row = client
        .query_opt_cached(
            &format!("SELECT {COLUMNS} FROM permission_sets p JOIN iam_roles r ON r.id = p.role_id WHERE p.account_id = $1 AND p.name = $2"),
            &[&account, &name],
        )
        .await?;
    Ok(row.as_ref().map(PermissionSet::of))
}

/// Permission set `id`, if there's one.
pub async fn load_id(client: &Object, id: Uuid) -> anyhow::Result<Option<PermissionSet>> {
    let row = client
        .query_opt_cached(&format!("SELECT {COLUMNS} FROM permission_sets p JOIN iam_roles r ON r.id = p.role_id WHERE p.id = $1"), &[&id])
        .await?;
    Ok(row.as_ref().map(PermissionSet::of))
}

/// `account`'s permission sets, by name.
pub async fn list(client: &Object, account: &str) -> anyhow::Result<Vec<PermissionSet>> {
    let rows = client
        .query_cached(
            &format!("SELECT {COLUMNS} FROM permission_sets p JOIN iam_roles r ON r.id = p.role_id WHERE p.account_id = $1 ORDER BY p.name"),
            &[&account],
        )
        .await?;
    Ok(rows.iter().map(PermissionSet::of).collect())
}

fn check(name: &str, description: &str, session_duration: i32) -> anyhow::Result<()> {
    if !valid_name(name) {
        return refused(Refused::Validation(
            "A permission set's name is 1 to 32 letters, digits and +=,.@_- characters.".into(),
        ));
    }
    if description.chars().count() > 700 {
        return refused(Refused::Validation("A permission set's description is at most 700 characters.".into()));
    }
    if !SESSION_DURATIONS.contains(&session_duration) {
        return refused(Refused::Validation("A permission set's session lasts from 1 to 12 hours (3600 to 43200 seconds).".into()));
    }
    Ok(())
}

/// Makes a permission set of `account`, and its role.
pub async fn create(client: &Object, account: &str, name: &str, description: &str, session_duration: i32) -> anyhow::Result<PermissionSet> {
    check(name, description, session_duration)?;
    if load(client, account, name).await?.is_some() {
        return refused(Refused::Exists(format!("A permission set named {name} already exists.")));
    }
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
    let suffix: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    let role_name = format!("AWSReservedSSO_{name}_{suffix}");
    let trust = roles::check_trust(client, account, &trust()).await?;
    let new = roles::New {
        name: &role_name,
        path: ROLE_PATH,
        trust: &trust,
        description: &format!("Permission set {name} (Identity Center)"),
        max_session_duration: session_duration,
        boundary: None,
        tags: &[],
    };
    let role_id = roles::create(client, account, &new).await?;
    let id = Uuid::new_v4();
    let made = client
        .execute_cached(
            "INSERT INTO permission_sets (id, account_id, name, description, session_duration, role_id)
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
            &[&id, &account, &name, &description, &session_duration, &role_id],
        )
        .await?;
    if made == 0 {
        // Made meanwhile, by another: its role goes again.
        if let Some(role) = Role::load_id(client, role_id).await? {
            roles::delete(client, &role).await?;
        }
        return refused(Refused::Exists(format!("A permission set named {name} already exists.")));
    }
    load_id(client, id).await?.context("a new permission set is gone")
}

/// Changes a permission set's description and session (its role's longest
/// too).
pub async fn update(client: &Object, set: &PermissionSet, description: &str, session_duration: i32) -> anyhow::Result<()> {
    check(&set.name, description, session_duration)?;
    client
        .execute_cached(
            "UPDATE permission_sets SET description = $2, session_duration = $3 WHERE id = $1",
            &[&set.id, &description, &session_duration],
        )
        .await?;
    roles::update(client, set.role_id, None, Some(session_duration)).await
}

/// A permission set's inline policy, if it has one.
pub async fn inline_policy(client: &Object, set: &PermissionSet) -> anyhow::Result<Option<String>> {
    roles::get_policy(client, set.role_id, INLINE_POLICY).await
}

/// Sets (`Some`) or removes a permission set's inline policy.
pub async fn set_inline_policy(client: &Object, set: &PermissionSet, document: Option<&str>) -> anyhow::Result<()> {
    match document {
        Some(document) => roles::put_policy(client, &set.role(client).await?, INLINE_POLICY, document).await,
        None => roles::delete_policy(client, set.role_id, INLINE_POLICY).await.map(|_| ()),
    }
}

/// The managed policies attached to a permission set.
pub async fn managed_policies(client: &Object, set: &PermissionSet) -> anyhow::Result<Vec<crate::managed::Attached>> {
    roles::attached(client, set.role_id).await
}

/// Attaches (`attach`) or detaches a managed policy (by its ARN: AWS's or
/// the account's) to or from a permission set.
pub async fn attach(client: &Object, set: &PermissionSet, arn: &str, attach: bool) -> anyhow::Result<()> {
    roles::attach(client, &set.account, &set.role(client).await?, arn, attach).await
}

/// Deletes a permission set: its assignments, its role, and its role's
/// policies. Its sessions in the console end; credentials handed out from
/// them stop working, as their role is gone.
pub async fn delete(client: &Object, set: &PermissionSet) -> anyhow::Result<()> {
    let role = set.role(client).await?;
    for name in roles::policy_names(client, role.id).await? {
        roles::delete_policy(client, role.id, &name).await?;
    }
    for attached in roles::attached(client, role.id).await? {
        roles::attach(client, &set.account, &role, &attached.arn, false).await?;
    }
    client.execute_cached("DELETE FROM permission_sets WHERE id = $1", &[&set.id]).await?;
    roles::delete(client, &role).await
}

// ─── Assignments ─────────────────────────────────────────────────────────────

/// Whom an assignment is to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrincipalType {
    User,
    Group,
}

impl PrincipalType {
    pub fn parse(text: &str) -> Option<PrincipalType> {
        match text {
            "USER" => Some(PrincipalType::User),
            "GROUP" => Some(PrincipalType::Group),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            PrincipalType::User => "USER",
            PrincipalType::Group => "GROUP",
        }
    }
}

/// A permission set's assignment to a user (by its subject) or group (by
/// its name) of an identity source.
#[derive(Clone, Debug)]
pub struct Assignment {
    pub id: Uuid,
    pub permission_set: String,
    pub principal_type: PrincipalType,
    pub provider: String,
    pub principal_id: String,
    /// The user's name and e-mail, as it last signed in (a user's that has).
    pub user: Option<(String, Option<String>)>,
    pub created: f64,
}

/// `account`'s assignments, by permission set.
pub async fn assignments(client: &Object, account: &str) -> anyhow::Result<Vec<Assignment>> {
    let rows = client
        .query_cached(
            "SELECT a.id, p.name, a.principal_type, a.provider, a.principal_id, u.name, u.email,
                    extract(epoch FROM a.created_at)::float8
             FROM permission_set_assignments a JOIN permission_sets p ON p.id = a.permission_set_id
             LEFT JOIN directory_users u ON a.principal_type = 'USER' AND u.provider = a.provider AND u.subject = a.principal_id
             WHERE p.account_id = $1 ORDER BY p.name, a.principal_type, a.provider, a.principal_id",
            &[&account],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| Assignment {
            id: r.get(0),
            permission_set: r.get(1),
            principal_type: PrincipalType::parse(r.get(2)).expect("the table checks it"),
            provider: r.get(3),
            principal_id: r.get(4),
            user: r.get::<_, Option<String>>(5).map(|name| (name, r.get(6))),
            created: r.get(7),
        })
        .collect())
}

/// Assigns `set` to a user or group of identity source `provider`.
pub async fn assign(client: &Object, set: &PermissionSet, principal_type: PrincipalType, provider: &str, principal_id: &str) -> anyhow::Result<()> {
    if principal_id.is_empty() || principal_id.chars().count() > 256 {
        return refused(Refused::Validation("A user's subject or a group's name is 1 to 256 characters.".into()));
    }
    let known = client.query_opt_cached("SELECT 1 FROM oidc_providers WHERE name = $1", &[&provider]).await?;
    if known.is_none() {
        return refused(Refused::NoSuch(format!("There's no identity source named {provider}.")));
    }
    let made = client
        .execute_cached(
            "INSERT INTO permission_set_assignments (permission_set_id, principal_type, provider, principal_id)
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            &[&set.id, &principal_type.as_str(), &provider, &principal_id],
        )
        .await;
    match made {
        Ok(0) => refused(Refused::Exists("That assignment exists already.".into())),
        Ok(_) => Ok(()),
        // The set or the source went meanwhile.
        Err(e) if e.code() == Some(&tokio_postgres::error::SqlState::FOREIGN_KEY_VIOLATION) => {
            refused(Refused::NoSuch("The permission set or identity source is gone.".into()))
        }
        Err(e) => Err(e.into()),
    }
}

/// Removes one of `account`'s assignments: whether there was one.
pub async fn unassign(client: &Object, account: &str, id: Uuid) -> anyhow::Result<bool> {
    let removed = client
        .execute_cached(
            "DELETE FROM permission_set_assignments a USING permission_sets p
             WHERE a.id = $2 AND p.id = a.permission_set_id AND p.account_id = $1",
            &[&account, &id],
        )
        .await?;
    Ok(removed > 0)
}

/// The permission sets of `account` assigned to the user `subject` of
/// identity source `provider`, or to one of its `groups` there, by name.
pub async fn eligible(client: &Object, account: &str, provider: &str, subject: &str, groups: &[String]) -> anyhow::Result<Vec<PermissionSet>> {
    let rows = client
        .query_cached(
            &format!(
                "SELECT {COLUMNS} FROM permission_sets p JOIN iam_roles r ON r.id = p.role_id
                 WHERE p.account_id = $1 AND EXISTS (
                     SELECT 1 FROM permission_set_assignments a WHERE a.permission_set_id = p.id AND a.provider = $2
                       AND ((a.principal_type = 'USER' AND a.principal_id = $3)
                         OR (a.principal_type = 'GROUP' AND a.principal_id = ANY($4))))
                 ORDER BY p.name"
            ),
            &[&account, &provider, &subject, &groups],
        )
        .await?;
    Ok(rows.iter().map(PermissionSet::of).collect())
}

// ─── Directory users ─────────────────────────────────────────────────────────

/// A directory user, as it last signed in.
#[derive(Clone, Debug)]
pub struct DirectoryUser {
    pub provider: String,
    pub subject: String,
    pub name: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub created: f64,
    pub last_signed_in: f64,
}

/// Notes that the user `subject` of `provider` signed in, as `name`, with
/// `email` and `groups`.
pub async fn signed_in(client: &Object, provider: &str, subject: &str, name: &str, email: Option<&str>, groups: &[String]) -> anyhow::Result<()> {
    client
        .execute_cached(
            "INSERT INTO directory_users (provider, subject, name, email, groups) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (provider, subject) DO UPDATE SET name = $3, email = $4, groups = $5, last_signed_in = now()",
            &[&provider, &subject, &name, &email, &groups],
        )
        .await?;
    Ok(())
}

/// Every directory user that has signed in, most recent first.
pub async fn directory_users(client: &Object) -> anyhow::Result<Vec<DirectoryUser>> {
    let rows = client
        .query_cached(
            "SELECT provider, subject, name, email, groups, extract(epoch FROM created_at)::float8,
                    extract(epoch FROM last_signed_in)::float8
             FROM directory_users ORDER BY last_signed_in DESC, provider, subject",
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| DirectoryUser {
            provider: r.get(0),
            subject: r.get(1),
            name: r.get(2),
            email: r.get(3),
            groups: r.get(4),
            created: r.get(5),
            last_signed_in: r.get(6),
        })
        .collect())
}

/// A role session's name for a directory user, as STS takes one (2 to 64 of
/// `[\w+=,.@-]`): its name, e-mail or subject, the first that has one.
pub fn session_name(candidates: &[Option<&str>]) -> String {
    let clean = |text: &str| -> String {
        text.chars().filter(|c| c.is_ascii_alphanumeric() || "+=,.@_-".contains(*c)).take(64).collect()
    };
    candidates
        .iter()
        .flatten()
        .map(|c| clean(c))
        .find(|c| c.len() >= 2)
        .unwrap_or_else(|| "directory-user".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_its_arns() {
        let id = Uuid::parse_str("0123456789abcdef0123456789abcdef").unwrap();
        let instance = instance_arn("123456789012");
        assert!(instance.starts_with("arn:aws:sso:::instance/ssoins-") && instance.len() == "arn:aws:sso:::instance/ssoins-".len() + 16);
        assert_eq!(permission_set_arn("123456789012", id), format!("arn:aws:sso:::permissionSet/{}/ps-0123456789abcdef", &instance[23..]));
    }

    #[test]
    fn session_names_are_stss() {
        assert_eq!(session_name(&[Some("Ada Lovelace"), Some("ada@example.com")]), "AdaLovelace");
        assert_eq!(session_name(&[Some("Ω"), Some("ada@example.com")]), "ada@example.com");
        assert_eq!(session_name(&[None, None, Some("a")]), "directory-user");
        assert_eq!(session_name(&[Some(&"x".repeat(80))]).len(), 64);
    }

    #[test]
    fn takes_identity_centers_names() {
        assert!(valid_name("DataScience"));
        assert!(valid_name("read-only.v2"));
        assert!(!valid_name(""));
        assert!(!valid_name("has space"));
        assert!(!valid_name(&"x".repeat(33)));
    }
}
