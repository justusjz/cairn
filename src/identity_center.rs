//! Directory users, as IAM Identity Center has them: people an identity
//! source vouches for when they sign in, rather than IAM users the account
//! keeps. Cairn's identity sources are the console's OpenID Connect
//! providers (see `console::oidc`), which operators configure, each with the
//! claim its ID tokens carry a person's groups in.
//!
//! **The identity store** holds the users that have signed in, and the
//! groups their group claims named, each by an ID of its own (Identity
//! Center's principal IDs), and their memberships, as each user's last
//! sign-in said: the identity source decides them, so they're read-only
//! (`identitystore`'s reads; see `sso`). A user's `UserName` is its
//! `preferred_username`, e-mail or subject, the first no other user has; its
//! external ID is its source's issuer and its subject; a group's display
//! name is its name in the claim.
//!
//! What a directory user may do is what the **permission sets** assigned to
//! it, or to one of its groups, allow, in the accounts they're assigned in.
//! As in Identity Center, a permission set is the instance's (its
//! account's), and holds what it allows: an inline policy, AWS managed
//! policies, customer managed policy references (by name and path) and a
//! permissions boundary. An assignment gives it to a user or group in an
//! account (its target). **Provisioning** copies the set into a role in an
//! account (`permission_set_provisions`): the first assignment there does,
//! and sso-admin's `ProvisionPermissionSet` does again once the set has
//! changed, which until then its roles don't (each notes the set's version
//! it holds). The role is at `/aws-reserved/sso.amazonaws.com/`, named
//! `AWSReservedSSO_<set>_<suffix>`, trusting `sso.amazonaws.com` only (so
//! that no one assumes it with STS), holding the set's inline policy
//! (`AwsSSOInlinePolicy`), its AWS managed policies and customer managed
//! policies (the account's own, by name and path, which it must have, or
//! provisioning fails), and its permissions boundary. Only provisioning
//! changes it: IAM refuses to (`roles::protected`). A cluster has one
//! account so far, so that's the only one sets are provisioned to. A
//! directory user signed
//! in to the console picks an account and one of its permission sets there,
//! and acts as a session of the set's role in that account
//! (`assumed-role/AWSReservedSSO_…/<name>`), which may hand it the session's
//! credentials for the CLI too (see `console::directory`).

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
/// How long sso-admin's requests' statuses are kept.
const OPERATIONS_KEPT: std::time::Duration = std::time::Duration::from_secs(90 * 24 * 3600);

fn refused<T>(why: Refused) -> anyhow::Result<T> {
    Err(why.into())
}

/// 16 hex digits of `bytes`'s SHA-256.
fn short_hash(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    digest.as_ref()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `account`'s Identity Center instance's ARN (made up of the account's ID,
/// as it has one).
pub fn instance_arn(account: &str) -> String {
    format!(
        "arn:aws:sso:::instance/ssoins-{}",
        short_hash(account.as_bytes())
    )
}

/// `account`'s identity store's ID (`d-` and ten hex digits), and its ARN.
pub fn identity_store_id(account: &str) -> String {
    format!(
        "d-{}",
        &short_hash(format!("identitystore:{account}").as_bytes())[..10]
    )
}

pub fn identity_store_arn(account: &str) -> String {
    format!(
        "arn:aws:identitystore::{account}:identitystore/{}",
        identity_store_id(account)
    )
}

/// The ARNs of an identity store's user, group and membership.
pub fn user_arn(id: Uuid) -> String {
    format!("arn:aws:identitystore:::user/{id}")
}

pub fn group_arn(id: Uuid) -> String {
    format!("arn:aws:identitystore:::group/{id}")
}

pub fn membership_arn(id: Uuid) -> String {
    format!("arn:aws:identitystore:::membership/{id}")
}

/// A permission set's ARN, of its short ID.
pub fn permission_set_arn(account: &str, short_id: &str) -> String {
    format!(
        "arn:aws:sso:::permissionSet/ssoins-{}/ps-{short_id}",
        short_hash(account.as_bytes())
    )
}

/// The short ID a permission set's ARN of `account`'s names, if it's one.
pub fn short_id_of(account: &str, arn: &str) -> Option<String> {
    let rest = arn.strip_prefix(&format!(
        "arn:aws:sso:::permissionSet/ssoins-{}/ps-",
        short_hash(account.as_bytes())
    ))?;
    (rest.len() == 16 && rest.bytes().all(|b| b.is_ascii_hexdigit())).then(|| rest.to_owned())
}

/// Whether `name` is a permission set's name, as Identity Center takes one.
pub fn valid_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+=,.@_-".contains(&b))
}

/// A permission set's role's trust policy: Identity Center's only.
fn trust() -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"{SERVICE}"}},"Action":["sts:AssumeRole","sts:TagSession"]}}]}}"#
    )
}

/// A permission set: what it is, which provisioning copies into roles.
#[derive(Clone, Debug)]
pub struct PermissionSet {
    pub id: Uuid,
    pub account: String,
    /// The 16 hex digits its ARN ends in (`ps-…`).
    pub short_id: String,
    pub name: String,
    pub description: String,
    /// Its sessions' longest, in seconds.
    pub session_duration: i32,
    pub relay_state: Option<String>,
    /// Its tags, as stored (see `s3::tags`); `None` for none.
    pub tags: Option<String>,
    /// Its version, which every change to what its roles hold raises; a
    /// role holds the latest once it's provisioned with it.
    pub version: i64,
    /// When it was made (seconds since the epoch).
    pub created: f64,
}

const COLUMNS: &str = "p.id, p.account_id, p.short_id, p.name, p.description, p.session_duration, p.relay_state, p.tags,
     p.version, extract(epoch FROM p.created_at)::float8";
const FROM: &str = "FROM permission_sets p";

impl PermissionSet {
    fn of(row: &tokio_postgres::Row) -> PermissionSet {
        PermissionSet {
            id: row.get(0),
            account: row.get(1),
            short_id: row.get(2),
            name: row.get(3),
            description: row.get(4),
            session_duration: row.get(5),
            relay_state: row.get(6),
            tags: row.get(7),
            version: row.get(8),
            created: row.get(9),
        }
    }

    pub fn arn(&self) -> String {
        permission_set_arn(&self.account, &self.short_id)
    }

    /// The name of its role, in every account it's provisioned to.
    pub fn role_name(&self) -> String {
        format!("AWSReservedSSO_{}_{}", self.name, self.short_id)
    }
}

/// A permission set provisioned to an account: its role there.
#[derive(Clone, Debug)]
pub struct Provision {
    pub account: String,
    pub role_id: Uuid,
    pub role_name: String,
    /// Whether the role holds the set's latest version.
    pub latest: bool,
}

impl Provision {
    pub fn role_arn(&self) -> String {
        roles::role_arn(&self.account, ROLE_PATH, &self.role_name)
    }

    async fn role(&self, client: &Object) -> anyhow::Result<Role> {
        Role::load_id(client, self.role_id)
            .await?
            .context("a permission set's role is gone")
    }
}

/// The accounts `set` is provisioned to, by ID.
pub async fn provisions(client: &Object, set: &PermissionSet) -> anyhow::Result<Vec<Provision>> {
    let rows = client
        .query_cached(
            "SELECT v.account_id, v.role_id, r.name, v.version = p.version
             FROM permission_set_provisions v JOIN iam_roles r ON r.id = v.role_id JOIN permission_sets p ON p.id = v.permission_set_id
             WHERE v.permission_set_id = $1 ORDER BY v.account_id",
            &[&set.id],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| Provision {
            account: r.get(0),
            role_id: r.get(1),
            role_name: r.get(2),
            latest: r.get(3),
        })
        .collect())
}

/// `set`'s provisioning to `account`, if it's provisioned there.
pub async fn provisioned(
    client: &Object,
    set: &PermissionSet,
    account: &str,
) -> anyhow::Result<Option<Provision>> {
    Ok(provisions(client, set)
        .await?
        .into_iter()
        .find(|p| p.account == account))
}

/// `instance`'s permission sets provisioned to `account`, with whether
/// their roles there hold their latest versions, by name.
pub async fn provisioned_to(
    client: &Object,
    instance: &str,
    account: &str,
) -> anyhow::Result<Vec<(PermissionSet, bool)>> {
    let rows = client
        .query_cached(
            &format!(
                "SELECT {COLUMNS}, v.version = p.version {FROM}
                 JOIN permission_set_provisions v ON v.permission_set_id = p.id
                 WHERE p.account_id = $1 AND v.account_id = $2 ORDER BY p.name"
            ),
            &[&instance, &account],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| (PermissionSet::of(r), r.get(10)))
        .collect())
}

/// `account`'s permission set `name`, if there's one.
pub async fn load(
    client: &Object,
    account: &str,
    name: &str,
) -> anyhow::Result<Option<PermissionSet>> {
    let row = client
        .query_opt_cached(
            &format!("SELECT {COLUMNS} {FROM} WHERE p.account_id = $1 AND p.name = $2"),
            &[&account, &name],
        )
        .await?;
    Ok(row.as_ref().map(PermissionSet::of))
}

/// `account`'s permission set of ARN `arn`, if there's one.
pub async fn load_arn(
    client: &Object,
    account: &str,
    arn: &str,
) -> anyhow::Result<Option<PermissionSet>> {
    let Some(short) = short_id_of(account, arn) else {
        return Ok(None);
    };
    let row = client
        .query_opt_cached(
            &format!("SELECT {COLUMNS} {FROM} WHERE p.account_id = $1 AND p.short_id = $2"),
            &[&account, &short],
        )
        .await?;
    Ok(row.as_ref().map(PermissionSet::of))
}

/// Permission set `id`, if there's one.
pub async fn load_id(client: &Object, id: Uuid) -> anyhow::Result<Option<PermissionSet>> {
    let row = client
        .query_opt_cached(&format!("SELECT {COLUMNS} {FROM} WHERE p.id = $1"), &[&id])
        .await?;
    Ok(row.as_ref().map(PermissionSet::of))
}

/// `account`'s permission sets, by name.
pub async fn list(client: &Object, account: &str) -> anyhow::Result<Vec<PermissionSet>> {
    let rows = client
        .query_cached(
            &format!("SELECT {COLUMNS} {FROM} WHERE p.account_id = $1 ORDER BY p.name"),
            &[&account],
        )
        .await?;
    Ok(rows.iter().map(PermissionSet::of).collect())
}

fn check_description(description: &str) -> anyhow::Result<()> {
    if description.chars().count() > 700 {
        return refused(Refused::Validation(
            "A permission set's description is at most 700 characters.".into(),
        ));
    }
    Ok(())
}

fn check_duration(seconds: i32) -> anyhow::Result<()> {
    if !SESSION_DURATIONS.contains(&seconds) {
        return refused(Refused::Validation(
            "A permission set's session lasts from 1 to 12 hours (PT1H to PT12H).".into(),
        ));
    }
    Ok(())
}

fn check_relay_state(relay_state: &str) -> anyhow::Result<()> {
    if relay_state.is_empty() || relay_state.chars().count() > 240 {
        return refused(Refused::Validation(
            "A permission set's relay state is 1 to 240 characters.".into(),
        ));
    }
    Ok(())
}

/// What a new permission set is.
pub struct New<'a> {
    pub name: &'a str,
    pub description: &'a str,
    pub session_duration: i32,
    pub relay_state: Option<&'a str>,
    /// Its tags, as stored.
    pub tags: Option<&'a str>,
}

/// Makes a permission set of `account`, provisioned nowhere yet.
pub async fn create(
    client: &Object,
    account: &str,
    new: &New<'_>,
) -> anyhow::Result<PermissionSet> {
    if !valid_name(new.name) {
        return refused(Refused::Validation(
            "A permission set's name is 1 to 32 letters, digits and +=,.@_- characters.".into(),
        ));
    }
    check_description(new.description)?;
    check_duration(new.session_duration)?;
    if let Some(relay_state) = new.relay_state {
        check_relay_state(relay_state)?;
    }
    let id = Uuid::new_v4();
    let short_id = id.simple().to_string()[..16].to_owned();
    let made = client
        .execute_cached(
            "INSERT INTO permission_sets (id, account_id, short_id, name, description, session_duration, relay_state, tags)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING",
            &[&id, &account, &short_id, &new.name, &new.description, &new.session_duration, &new.relay_state, &new.tags],
        )
        .await?;
    if made == 0 {
        return refused(Refused::Exists(format!(
            "A permission set named {} already exists.",
            new.name
        )));
    }
    load_id(client, id)
        .await?
        .context("a new permission set is gone")
}

/// Raises `set`'s version: what its roles hold isn't its latest any more.
async fn changed(client: &Object, set: &PermissionSet) -> anyhow::Result<()> {
    client
        .execute_cached(
            "UPDATE permission_sets SET version = version + 1 WHERE id = $1",
            &[&set.id],
        )
        .await?;
    Ok(())
}

/// What changes of a permission set (`None`: not that).
#[derive(Default)]
pub struct Change<'a> {
    pub description: Option<&'a str>,
    pub session_duration: Option<i32>,
    pub relay_state: Option<&'a str>,
}

/// Changes a permission set (its session duration in its roles once it's
/// provisioned).
pub async fn update(
    client: &Object,
    set: &PermissionSet,
    change: &Change<'_>,
) -> anyhow::Result<()> {
    if let Some(description) = change.description {
        check_description(description)?;
    }
    if let Some(seconds) = change.session_duration {
        check_duration(seconds)?;
    }
    if let Some(relay_state) = change.relay_state {
        check_relay_state(relay_state)?;
    }
    client
        .execute_cached(
            "UPDATE permission_sets SET description = coalesce($2, description), session_duration = coalesce($3, session_duration),
                    relay_state = coalesce($4, relay_state), version = version + CASE WHEN $3::integer IS NULL THEN 0 ELSE 1 END
             WHERE id = $1",
            &[&set.id, &change.description, &change.session_duration, &change.relay_state],
        )
        .await?;
    Ok(())
}

/// Sets a permission set's tags (as stored; `None`: none).
pub async fn set_tags(
    client: &Object,
    set: &PermissionSet,
    tags: Option<&str>,
) -> anyhow::Result<()> {
    client
        .execute_cached(
            "UPDATE permission_sets SET tags = $2 WHERE id = $1",
            &[&set.id, &tags],
        )
        .await?;
    Ok(())
}

/// A permission set's inline policy, if it has one.
pub async fn inline_policy(client: &Object, set: &PermissionSet) -> anyhow::Result<Option<String>> {
    let row = client
        .query_one_cached(
            "SELECT inline_policy FROM permission_sets WHERE id = $1",
            &[&set.id],
        )
        .await?;
    Ok(row.get(0))
}

/// Sets (`Some`: a valid identity policy, which fits in a role) or removes
/// a permission set's inline policy.
pub async fn set_inline_policy(
    client: &Object,
    set: &PermissionSet,
    document: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(document) = document {
        crate::policy::Policy::parse(document, crate::policy::Kind::Identity).map_err(
            |e| match e.code {
                "NotImplemented" => Refused::Unsupported(e.message),
                _ => Refused::Malformed(e.message),
            },
        )?;
        if document.len() > roles::MAX_POLICIES {
            return refused(Refused::Limit(format!(
                "A permission set's inline policy is at most {} bytes.",
                roles::MAX_POLICIES
            )));
        }
    }
    client
        .execute_cached(
            "UPDATE permission_sets SET inline_policy = $2 WHERE id = $1",
            &[&set.id, &document],
        )
        .await?;
    changed(client, set).await
}

/// The managed policies attached to a permission set, by their ARNs: AWS's
/// (Cairn's), then its customer managed policy references, as the
/// instance's account has them.
pub async fn managed_policies(
    client: &Object,
    set: &PermissionSet,
) -> anyhow::Result<Vec<crate::managed::Attached>> {
    let mut attached: Vec<crate::managed::Attached> = aws_policies(client, set)
        .await?
        .into_iter()
        .map(|name| crate::managed::Attached {
            arn: crate::managed::aws_arn(&name),
            name,
        })
        .collect();
    for (name, path) in references(client, set).await? {
        attached.push(crate::managed::Attached {
            arn: customer_policy_arn(&set.account, &name, &path),
            name,
        });
    }
    Ok(attached)
}

/// The names of the AWS managed policies attached to a permission set.
async fn aws_policies(client: &Object, set: &PermissionSet) -> anyhow::Result<Vec<String>> {
    let rows = client
        .query_cached("SELECT name FROM permission_set_managed_policies WHERE permission_set_id = $1 ORDER BY name", &[&set.id])
        .await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}

/// A permission set's customer managed policy references: their names and
/// paths.
pub async fn references(
    client: &Object,
    set: &PermissionSet,
) -> anyhow::Result<Vec<(String, String)>> {
    let rows = client
        .query_cached(
            "SELECT name, path FROM permission_set_customer_policies WHERE permission_set_id = $1 ORDER BY path, name",
            &[&set.id],
        )
        .await?;
    Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
}

/// Whether `arn` is an AWS managed policy's (Cairn's).
pub fn is_aws(arn: &str) -> bool {
    arn.starts_with("arn:aws:iam::aws:policy/")
}

/// The ARN of the account's customer managed policy `name` at `path`.
pub fn customer_policy_arn(account: &str, name: &str, path: &str) -> String {
    format!("arn:aws:iam::{account}:policy{path}{name}")
}

/// The name and path of a customer managed policy's ARN.
pub fn customer_policy_reference(arn: &str) -> Option<(String, String)> {
    let rest = arn.split_once(":policy/")?.1;
    let (path, name) = match rest.rsplit_once('/') {
        Some((path, name)) => (format!("/{path}/"), name),
        None => ("/".to_owned(), rest),
    };
    Some((name.to_owned(), path))
}

/// A managed policy a permission set names: AWS's (by name), or a customer
/// managed policy reference, which each account it's provisioned to must
/// have (by name and path).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyRef {
    Aws(String),
    Customer { name: String, path: String },
}

impl PolicyRef {
    /// The policy `arn` names: AWS's, which must be one of Cairn's, or a
    /// customer managed policy of any account, by its name and path.
    pub fn of_arn(arn: &str) -> anyhow::Result<PolicyRef> {
        if is_aws(arn) {
            return match crate::managed::named(arn, "") {
                Ok(crate::managed::Named::Aws(p)) => Ok(PolicyRef::Aws(p.name.to_owned())),
                _ => refused(Refused::NoSuch(format!(
                    "Policy {arn} does not exist or is not attachable."
                ))),
            };
        }
        match customer_policy_reference(arn) {
            Some((name, path)) if !name.is_empty() && arn.starts_with("arn:aws:iam::") => {
                Ok(PolicyRef::Customer { name, path })
            }
            _ => refused(Refused::Invalid(format!("ARN {arn} is not valid."))),
        }
    }

    /// Its ARN, as `account` has it.
    pub fn arn(&self, account: &str) -> String {
        match self {
            PolicyRef::Aws(name) => crate::managed::aws_arn(name),
            PolicyRef::Customer { name, path } => customer_policy_arn(account, name, path),
        }
    }
}

/// Attaches (`attach`) or detaches a managed policy (by its ARN: AWS's, or
/// a customer managed policy's, by its name and path) to or from a
/// permission set: within as many as a role holds, and refused if it's
/// attached already, or (detaching) isn't.
pub async fn attach(
    client: &Object,
    set: &PermissionSet,
    arn: &str,
    attach: bool,
) -> anyhow::Result<()> {
    let policy = PolicyRef::of_arn(arn)?;
    let attached = managed_policies(client, set).await?;
    let has = attached.iter().any(|a| a.arn == policy.arn(&set.account));
    if attach && has {
        return refused(Refused::Exists(format!(
            "Permission set {} already has the managed policy {arn}.",
            set.name
        )));
    }
    if !attach && !has {
        return refused(Refused::NoSuch(format!("Policy {arn} was not found.")));
    }
    if attach && attached.len() as i64 >= roles::MAX_ATTACHED {
        return refused(Refused::Limit(format!(
            "A permission set has at most {} managed policies.",
            roles::MAX_ATTACHED
        )));
    }
    match (&policy, attach) {
        (PolicyRef::Aws(name), true) => {
            client
                .execute_cached(
                    "INSERT INTO permission_set_managed_policies (permission_set_id, name) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                    &[&set.id, name],
                )
                .await?
        }
        (PolicyRef::Aws(name), false) => {
            client
                .execute_cached("DELETE FROM permission_set_managed_policies WHERE permission_set_id = $1 AND name = $2", &[&set.id, name])
                .await?
        }
        (PolicyRef::Customer { name, path }, true) => {
            client
                .execute_cached(
                    "INSERT INTO permission_set_customer_policies (permission_set_id, name, path) VALUES ($1, $2, $3)
                     ON CONFLICT DO NOTHING",
                    &[&set.id, name, path],
                )
                .await?
        }
        (PolicyRef::Customer { name, path }, false) => {
            client
                .execute_cached(
                    "DELETE FROM permission_set_customer_policies WHERE permission_set_id = $1 AND name = $2 AND path = $3",
                    &[&set.id, name, path],
                )
                .await?
        }
    };
    changed(client, set).await
}

/// A permission set's permissions boundary, if it has one.
pub async fn boundary_ref(
    client: &Object,
    set: &PermissionSet,
) -> anyhow::Result<Option<PolicyRef>> {
    let row = client
        .query_one_cached(
            "SELECT boundary_aws, boundary_name, boundary_path FROM permission_sets WHERE id = $1",
            &[&set.id],
        )
        .await?;
    let (aws, name, path): (Option<String>, Option<String>, Option<String>) =
        (row.get(0), row.get(1), row.get(2));
    Ok(match (aws, name, path) {
        (Some(aws), _, _) => Some(PolicyRef::Aws(aws)),
        (None, Some(name), Some(path)) => Some(PolicyRef::Customer { name, path }),
        _ => None,
    })
}

/// A permission set's permissions boundary's ARN (a customer managed
/// policy's as the instance's account has it), if it has one.
pub async fn boundary(client: &Object, set: &PermissionSet) -> anyhow::Result<Option<String>> {
    Ok(boundary_ref(client, set)
        .await?
        .map(|b| b.arn(&set.account)))
}

/// Sets (`Some`: a managed policy's ARN, AWS's, or a customer managed
/// policy's, by its name and path) or removes a permission set's
/// permissions boundary.
pub async fn set_boundary(
    client: &Object,
    set: &PermissionSet,
    arn: Option<&str>,
) -> anyhow::Result<()> {
    let (aws, name, path) = match arn.map(PolicyRef::of_arn).transpose()? {
        Some(PolicyRef::Aws(name)) => (Some(name), None, None),
        Some(PolicyRef::Customer { name, path }) => (None, Some(name), Some(path)),
        None => (None, None, None),
    };
    client
        .execute_cached(
            "UPDATE permission_sets SET boundary_aws = $2, boundary_name = $3, boundary_path = $4 WHERE id = $1",
            &[&set.id, &aws, &name, &path],
        )
        .await?;
    changed(client, set).await
}

/// Provisions `set` to `account`: makes its role there if it has none, and
/// has the role hold the set as it is now, its customer managed policy
/// references as `account` has them. `Err` (in `Ok`): why it couldn't,
/// a reference `account` doesn't have, say, which leaves the role as it was.
pub async fn provision(
    client: &Object,
    set: &PermissionSet,
    account: &str,
) -> anyhow::Result<Result<(), String>> {
    // Its version first: a change meanwhile leaves it not the latest.
    let Some(set) = load_id(client, set.id).await? else {
        return refused(Refused::NoSuch(format!(
            "Could not find PermissionSet with ARN {}.",
            set.arn()
        )));
    };
    let inline = inline_policy(client, &set).await?;
    let mut wanted: Vec<String> = aws_policies(client, &set)
        .await?
        .iter()
        .map(|n| crate::managed::aws_arn(n))
        .collect();
    let missing = |name: &str, path: &str| {
        format!("The customer managed policy {path}{name} doesn't exist in account {account}.")
    };
    for (name, path) in references(client, &set).await? {
        if crate::managed::own(client, account, &path, &name)
            .await
            .is_err()
        {
            return Ok(Err(missing(&name, &path)));
        }
        wanted.push(customer_policy_arn(account, &name, &path));
    }
    let boundary = match boundary_ref(client, &set).await? {
        Some(policy) => match crate::managed::boundary(client, account, &policy.arn(account)).await
        {
            Ok(boundary) => Some(boundary),
            Err(_) => match &policy {
                PolicyRef::Customer { name, path } => return Ok(Err(missing(name, path))),
                PolicyRef::Aws(name) => {
                    return Ok(Err(format!("The AWS managed policy {name} doesn't exist.")));
                }
            },
        },
        None => None,
    };

    let role = match provisioned(client, &set, account).await? {
        Some(provision) => provision.role(client).await?,
        None => {
            let trust = roles::check_trust(client, account, &trust()).await?;
            let new = roles::New {
                name: &set.role_name(),
                path: ROLE_PATH,
                trust: &trust,
                description: &format!("Permission set {} (Identity Center)", set.name),
                max_session_duration: set.session_duration,
                boundary: None,
                tags: &[],
            };
            let role_id = roles::create(client, account, &new).await?;
            let made = client
                .execute_cached(
                    "INSERT INTO permission_set_provisions (permission_set_id, account_id, role_id, version) VALUES ($1, $2, $3, 0)
                     ON CONFLICT DO NOTHING",
                    &[&set.id, &account, &role_id],
                )
                .await?;
            if made == 0 {
                // Provisioned meanwhile (with a role of another name?).
                if let Some(role) = Role::load_id(client, role_id).await? {
                    roles::delete(client, &role).await?;
                }
                return refused(Refused::Conflict(format!(
                    "Permission set {} is being provisioned to {account} already.",
                    set.name
                )));
            }
            Role::load_id(client, role_id)
                .await?
                .context("a new role is gone")?
        }
    };
    roles::update(client, role.id, None, Some(set.session_duration)).await?;
    match &inline {
        Some(document) => roles::put_policy(client, &role, INLINE_POLICY, document).await?,
        None => {
            roles::delete_policy(client, role.id, INLINE_POLICY).await?;
        }
    }
    let attached = roles::attached(client, role.id).await?;
    for gone in attached.iter().filter(|a| !wanted.contains(&a.arn)) {
        roles::attach(client, account, &role, &gone.arn, false).await?;
    }
    for arn in wanted
        .iter()
        .filter(|arn| !attached.iter().any(|a| a.arn == **arn))
    {
        roles::attach(client, account, &role, arn, true).await?;
    }
    roles::set_boundary(client, role.id, boundary.as_ref()).await?;
    client
        .execute_cached(
            "UPDATE permission_set_provisions SET version = $3 WHERE permission_set_id = $1 AND account_id = $2",
            &[&set.id, &account, &set.version],
        )
        .await?;
    Ok(Ok(()))
}

/// Provisions `set` to every account it's provisioned to: the first reason
/// one failed, if one did (the others are provisioned all the same).
pub async fn provision_all(
    client: &Object,
    set: &PermissionSet,
) -> anyhow::Result<Result<(), String>> {
    let mut failed = Ok(());
    for to in provisions(client, set).await? {
        if let Err(why) = provision(client, set, &to.account).await?
            && failed.is_ok()
        {
            failed = Err(why);
        }
    }
    Ok(failed)
}

/// Deletes a permission set: its assignments, and its roles in every
/// account it's provisioned to, with their policies. Its sessions in the
/// console end; credentials handed out from them stop working, as their
/// roles are gone.
pub async fn delete(client: &Object, set: &PermissionSet) -> anyhow::Result<()> {
    let mut gone = Vec::new();
    for provision in provisions(client, set).await? {
        let role = provision.role(client).await?;
        for name in roles::policy_names(client, role.id).await? {
            roles::delete_policy(client, role.id, &name).await?;
        }
        for attached in roles::attached(client, role.id).await? {
            roles::attach(client, &provision.account, &role, &attached.arn, false).await?;
        }
        if role.boundary.is_some() {
            roles::set_boundary(client, role.id, None).await?;
        }
        gone.push(role);
    }
    client
        .execute_cached("DELETE FROM permission_sets WHERE id = $1", &[&set.id])
        .await?;
    for role in &gone {
        roles::delete(client, role).await?;
    }
    Ok(())
}

// ─── The identity store ──────────────────────────────────────────────────────

/// A directory user: one of an identity source, as it last signed in, or
/// one of Cairn's own directory, as identitystore's writes made it.
#[derive(Clone, Debug)]
pub struct User {
    pub id: Uuid,
    /// Its identity source (by name), and its issuer, and its subject there;
    /// `None` for one of Cairn's own.
    pub provider: Option<String>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub user_name: String,
    pub display_name: String,
    pub email: Option<String>,
    /// One of Cairn's own's attributes, as identitystore has them (`Name`,
    /// `Emails`, `NickName`, …); `{}` for a source's.
    pub profile: serde_json::Value,
    /// Its revision, which every change raises.
    pub revision: i64,
    pub created: f64,
    /// When it last changed (signed in, for a source's).
    pub updated: f64,
}

impl User {
    /// Whether it's one of Cairn's own directory's.
    pub fn own(&self) -> bool {
        self.provider.is_none()
    }
}

const USER_COLUMNS: &str = "u.id, u.provider, p.issuer, u.subject, u.user_name, u.display_name, u.email,
     extract(epoch FROM u.created_at)::float8, extract(epoch FROM u.updated_at)::float8, u.profile::text, u.revision";
const USERS: &str = "FROM identity_users u LEFT JOIN oidc_providers p ON p.name = u.provider";

impl User {
    fn of(row: &tokio_postgres::Row) -> User {
        User {
            id: row.get(0),
            provider: row.get(1),
            issuer: row.get(2),
            subject: row.get(3),
            user_name: row.get(4),
            display_name: row.get(5),
            email: row.get(6),
            created: row.get(7),
            updated: row.get(8),
            profile: serde_json::from_str(row.get(9)).unwrap_or_default(),
            revision: row.get(10),
        }
    }
}

/// A group: one of an identity source, as its users' group claims name it,
/// or one of Cairn's own directory, as identitystore's writes made it.
#[derive(Clone, Debug)]
pub struct Group {
    pub id: Uuid,
    /// Its identity source (by name), and its issuer; `None` for one of
    /// Cairn's own.
    pub provider: Option<String>,
    pub issuer: Option<String>,
    /// Its display name (a source's: its name in the claim).
    pub name: String,
    pub description: Option<String>,
    pub revision: i64,
    pub created: f64,
    pub updated: f64,
}

impl Group {
    /// Whether it's one of Cairn's own directory's.
    pub fn own(&self) -> bool {
        self.provider.is_none()
    }
}

const GROUP_COLUMNS: &str =
    "g.id, g.provider, p.issuer, g.name, extract(epoch FROM g.created_at)::float8,
     extract(epoch FROM g.updated_at)::float8, g.description, g.revision";
const GROUPS: &str = "FROM identity_groups g LEFT JOIN oidc_providers p ON p.name = g.provider";

impl Group {
    fn of(row: &tokio_postgres::Row) -> Group {
        Group {
            id: row.get(0),
            provider: row.get(1),
            issuer: row.get(2),
            name: row.get(3),
            created: row.get(4),
            updated: row.get(5),
            description: row.get(6),
            revision: row.get(7),
        }
    }
}

/// How a user or group is looked up.
pub enum Lookup<'a> {
    Id(Uuid),
    /// By `UserName`, or a group's display name.
    Name(&'a str),
    /// By its external ID: its source's issuer, and its subject (or a
    /// group's name).
    External {
        issuer: &'a str,
        id: &'a str,
    },
}

/// The users `lookup` finds (by name or external ID, at most one).
pub async fn users(client: &Object, lookup: Option<Lookup<'_>>) -> anyhow::Result<Vec<User>> {
    let rows = match lookup {
        None => client.query_cached(&format!("SELECT {USER_COLUMNS} {USERS} ORDER BY u.user_name"), &[]).await?,
        Some(Lookup::Id(id)) => client.query_cached(&format!("SELECT {USER_COLUMNS} {USERS} WHERE u.id = $1"), &[&id]).await?,
        Some(Lookup::Name(name)) => {
            client.query_cached(&format!("SELECT {USER_COLUMNS} {USERS} WHERE u.user_name = $1"), &[&name]).await?
        }
        Some(Lookup::External { issuer, id }) => {
            client
                .query_cached(
                    &format!("SELECT {USER_COLUMNS} {USERS} WHERE rtrim(p.issuer, '/') = rtrim($1, '/') AND u.subject = $2"),
                    &[&issuer, &id],
                )
                .await?
        }
    };
    Ok(rows.iter().map(User::of).collect())
}

/// The groups `lookup` finds (a display name may be several sources').
pub async fn groups(client: &Object, lookup: Option<Lookup<'_>>) -> anyhow::Result<Vec<Group>> {
    let rows = match lookup {
        None => client.query_cached(&format!("SELECT {GROUP_COLUMNS} {GROUPS} ORDER BY g.name, g.provider"), &[]).await?,
        Some(Lookup::Id(id)) => client.query_cached(&format!("SELECT {GROUP_COLUMNS} {GROUPS} WHERE g.id = $1"), &[&id]).await?,
        Some(Lookup::Name(name)) => {
            client.query_cached(&format!("SELECT {GROUP_COLUMNS} {GROUPS} WHERE g.name = $1 ORDER BY g.provider"), &[&name]).await?
        }
        Some(Lookup::External { issuer, id }) => {
            client
                .query_cached(
                    &format!("SELECT {GROUP_COLUMNS} {GROUPS} WHERE rtrim(p.issuer, '/') = rtrim($1, '/') AND g.name = $2"),
                    &[&issuer, &id],
                )
                .await?
        }
    };
    Ok(rows.iter().map(Group::of).collect())
}

/// A user's membership of a group.
#[derive(Clone, Debug)]
pub struct Membership {
    pub id: Uuid,
    pub group_id: Uuid,
    pub user_id: Uuid,
    pub created: f64,
}

/// The memberships of group `group`, or of user `user`, by ID.
pub async fn memberships(
    client: &Object,
    group: Option<Uuid>,
    user: Option<Uuid>,
) -> anyhow::Result<Vec<Membership>> {
    let rows = client
        .query_cached(
            "SELECT id, group_id, user_id, extract(epoch FROM created_at)::float8 FROM identity_group_members
             WHERE ($1::uuid IS NULL OR group_id = $1) AND ($2::uuid IS NULL OR user_id = $2) ORDER BY id",
            &[&group, &user],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| Membership {
            id: r.get(0),
            group_id: r.get(1),
            user_id: r.get(2),
            created: r.get(3),
        })
        .collect())
}

/// Notes that the user `subject` of `provider` signed in, as `name`
/// (`preferred_username`, if it said one: `user_name`), with `email` and
/// in `groups` (their names): its user's ID. Its groups are made as needed,
/// and its memberships become those.
pub async fn signed_in(
    client: &Object,
    provider: &str,
    subject: &str,
    name: &str,
    user_name: Option<&str>,
    email: Option<&str>,
    groups: &[String],
) -> anyhow::Result<Uuid> {
    let known = client
        .query_opt_cached(
            "UPDATE identity_users SET display_name = $3, email = $4, updated_at = now(), revision = revision + 1
             WHERE provider = $1 AND subject = $2 RETURNING id",
            &[&provider, &subject, &name, &email],
        )
        .await?;
    let user = match known {
        Some(row) => row.get(0),
        None => {
            // Its user name: the first of these no one has.
            let id = Uuid::new_v4();
            let candidates = [
                user_name.map(str::to_owned),
                email.map(str::to_owned),
                Some(subject.to_owned()),
                Some(format!("{provider}/{subject}")),
            ];
            let mut made = None;
            for candidate in candidates
                .into_iter()
                .flatten()
                .filter(|c| !c.is_empty() && c.chars().count() <= 128)
            {
                let row = client
                    .query_opt_cached(
                        "INSERT INTO identity_users (id, provider, subject, user_name, display_name, email)
                         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING RETURNING id",
                        &[&id, &provider, &subject, &candidate, &name, &email],
                    )
                    .await?;
                if let Some(row) = row {
                    made = Some(row.get(0));
                    break;
                }
                // Signed in meanwhile, elsewhere.
                if let Some(row) = client
                    .query_opt_cached(
                        "SELECT id FROM identity_users WHERE provider = $1 AND subject = $2",
                        &[&provider, &subject],
                    )
                    .await?
                {
                    made = Some(row.get(0));
                    break;
                }
            }
            made.context("no user name is free for a directory user")?
        }
    };
    let mut group_ids = Vec::new();
    for group in groups {
        let row = client
            .query_one_cached(
                "INSERT INTO identity_groups (id, provider, name) VALUES ($1, $2, $3)
                 ON CONFLICT (provider, name) DO UPDATE SET updated_at = now(), revision = identity_groups.revision + 1 RETURNING id",
                &[&Uuid::new_v4(), &provider, &group],
            )
            .await?;
        group_ids.push(row.get::<_, Uuid>(0));
    }
    client
        .execute_cached(
            // Its source's groups only: one of Cairn's own may have it too.
            "DELETE FROM identity_group_members WHERE user_id = $1 AND NOT group_id = ANY($2)
               AND group_id IN (SELECT id FROM identity_groups WHERE provider = $3)",
            &[&user, &group_ids, &provider],
        )
        .await?;
    for group in &group_ids {
        client
            .execute_cached(
                "INSERT INTO identity_group_members (id, group_id, user_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                &[&Uuid::new_v4(), group, &user],
            )
            .await?;
    }
    Ok(user)
}

// ─── Cairn's own directory ───────────────────────────────────────────────────

/// Whether `name` is reserved, as Identity Center reserves it for users and
/// groups.
fn reserved(name: &str) -> bool {
    name.eq_ignore_ascii_case("Administrator") || name.eq_ignore_ascii_case("AWSAdministrators")
}

/// Checks a text attribute, as identitystore takes one: 1 to 1024
/// characters.
fn check_text(what: &str, text: &str) -> anyhow::Result<()> {
    if text.is_empty() || text.chars().count() > 1024 {
        return refused(Refused::Validation(format!(
            "{what} is 1 to 1024 characters."
        )));
    }
    Ok(())
}

/// Checks a user name, as identitystore takes one: 1 to 128 characters,
/// none of them space, and not a reserved name.
fn check_user_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty()
        || name.chars().count() > 128
        || name.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return refused(Refused::Validation(
            "A UserName is 1 to 128 characters, with no spaces.".into(),
        ));
    }
    if reserved(name) {
        return refused(Refused::Validation(format!("{name} is a reserved name.")));
    }
    Ok(())
}

/// Refused, as one of an identity source's: what it is is what the source
/// says when its users sign in.
fn sources(what: &str) -> anyhow::Error {
    Refused::Validation(format!(
        "That {what} is an identity source's: it's what the source says when its users sign in, and only Cairn's own directory's \
         are changed here."
    ))
    .into()
}

/// A user of Cairn's own directory, as it's made or changed.
pub struct OwnUser<'a> {
    pub user_name: &'a str,
    pub display_name: &'a str,
    /// Its primary e-mail, if it has one.
    pub email: Option<&'a str>,
    /// All its attributes, as identitystore has them.
    pub profile: &'a serde_json::Value,
}

impl OwnUser<'_> {
    fn check(&self) -> anyhow::Result<()> {
        check_user_name(self.user_name)?;
        check_text("A DisplayName", self.display_name)?;
        if let Some(email) = self.email {
            check_text("An e-mail", email)?;
        }
        Ok(())
    }
}

/// What a write refused for a unique name, else its error.
fn unique(e: tokio_postgres::Error, taken: impl FnOnce() -> String) -> anyhow::Error {
    match e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) {
        true => Refused::Exists(taken()).into(),
        false => e.into(),
    }
}

/// What a change of `what` that matched no row means: another changed it
/// meanwhile, or it isn't at `revision`.
fn stale(what: &str) -> anyhow::Error {
    Refused::Conflict(format!(
        "The {what} isn't at that Revision: it was changed meanwhile."
    ))
    .into()
}

/// Makes a user of Cairn's own directory.
pub async fn create_user(client: &Object, new: &OwnUser<'_>) -> anyhow::Result<User> {
    new.check()?;
    let id = Uuid::new_v4();
    client
        .execute_cached(
            "INSERT INTO identity_users (id, provider, subject, user_name, display_name, email, profile)
             VALUES ($1, NULL, NULL, $2, $3, $4, $5::text::jsonb)",
            &[&id, &new.user_name, &new.display_name, &new.email, &new.profile.to_string()],
        )
        .await
        .map_err(|e| unique(e, || format!("A user named {} exists already.", new.user_name)))?;
    users(client, Some(Lookup::Id(id)))
        .await?
        .pop()
        .context("a new user is gone")
}

/// Changes a user of Cairn's own directory to `to`, if it's at `revision`
/// (if given): it as it is now.
pub async fn update_user(
    client: &Object,
    user: &User,
    to: &OwnUser<'_>,
    revision: Option<i64>,
) -> anyhow::Result<User> {
    if !user.own() {
        return Err(sources("user"));
    }
    to.check()?;
    let changed = client
        .execute_cached(
            "UPDATE identity_users SET user_name = $2, display_name = $3, email = $4, profile = $5::text::jsonb, revision = revision + 1,
                    updated_at = now()
             WHERE id = $1 AND provider IS NULL AND ($6::bigint IS NULL OR revision = $6)",
            &[&user.id, &to.user_name, &to.display_name, &to.email, &to.profile.to_string(), &revision],
        )
        .await
        .map_err(|e| unique(e, || format!("A user named {} exists already.", to.user_name)))?;
    if changed == 0 {
        return Err(stale("user"));
    }
    users(client, Some(Lookup::Id(user.id)))
        .await?
        .pop()
        .context("a changed user is gone")
}

/// Deletes a user of Cairn's own directory, if it's at `revision` (if
/// given): its memberships, assignments, passkeys and sessions go too.
pub async fn delete_user(
    client: &Object,
    user: &User,
    revision: Option<i64>,
) -> anyhow::Result<()> {
    if !user.own() {
        return Err(sources("user"));
    }
    let deleted = client
        .execute_cached(
            "DELETE FROM identity_users WHERE id = $1 AND provider IS NULL AND ($2::bigint IS NULL OR revision = $2)",
            &[&user.id, &revision],
        )
        .await?;
    if deleted == 0 {
        return Err(stale("user"));
    }
    Ok(())
}

fn check_group(name: &str, description: Option<&str>) -> anyhow::Result<()> {
    check_text("A DisplayName", name)?;
    if reserved(name) {
        return refused(Refused::Validation(format!("{name} is a reserved name.")));
    }
    if let Some(description) = description {
        check_text("A Description", description)?;
    }
    Ok(())
}

/// Makes a group of Cairn's own directory, named `name` (unique among its
/// own, whatever the case).
pub async fn create_group(
    client: &Object,
    name: &str,
    description: Option<&str>,
) -> anyhow::Result<Group> {
    check_group(name, description)?;
    let id = Uuid::new_v4();
    client
        .execute_cached(
            "INSERT INTO identity_groups (id, provider, name, description) VALUES ($1, NULL, $2, $3)",
            &[&id, &name, &description],
        )
        .await
        .map_err(|e| unique(e, || format!("A group named {name} exists already.")))?;
    groups(client, Some(Lookup::Id(id)))
        .await?
        .pop()
        .context("a new group is gone")
}

/// Changes a group of Cairn's own directory, if it's at `revision` (if
/// given): it as it is now.
pub async fn update_group(
    client: &Object,
    group: &Group,
    name: &str,
    description: Option<&str>,
    revision: Option<i64>,
) -> anyhow::Result<Group> {
    if !group.own() {
        return Err(sources("group"));
    }
    check_group(name, description)?;
    let changed = client
        .execute_cached(
            "UPDATE identity_groups SET name = $2, description = $3, revision = revision + 1, updated_at = now()
             WHERE id = $1 AND provider IS NULL AND ($4::bigint IS NULL OR revision = $4)",
            &[&group.id, &name, &description, &revision],
        )
        .await
        .map_err(|e| unique(e, || format!("A group named {name} exists already.")))?;
    if changed == 0 {
        return Err(stale("group"));
    }
    groups(client, Some(Lookup::Id(group.id)))
        .await?
        .pop()
        .context("a changed group is gone")
}

/// Deletes a group of Cairn's own directory, if it's at `revision` (if
/// given): its memberships and assignments go too.
pub async fn delete_group(
    client: &Object,
    group: &Group,
    revision: Option<i64>,
) -> anyhow::Result<()> {
    if !group.own() {
        return Err(sources("group"));
    }
    let deleted = client
        .execute_cached(
            "DELETE FROM identity_groups WHERE id = $1 AND provider IS NULL AND ($2::bigint IS NULL OR revision = $2)",
            &[&group.id, &revision],
        )
        .await?;
    if deleted == 0 {
        return Err(stale("group"));
    }
    Ok(())
}

/// Puts `user` (any directory user, a source's too) in `group`, one of
/// Cairn's own directory's: the membership.
pub async fn add_member(client: &Object, group: &Group, user: &User) -> anyhow::Result<Membership> {
    if !group.own() {
        return Err(sources("group"));
    }
    let id = Uuid::new_v4();
    let made = client
        .execute_cached(
            "INSERT INTO identity_group_members (id, group_id, user_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            &[&id, &group.id, &user.id],
        )
        .await?;
    if made == 0 {
        return refused(Refused::Exists(format!(
            "{} is in {} already.",
            user.user_name, group.name
        )));
    }
    memberships(client, Some(group.id), Some(user.id))
        .await?
        .pop()
        .context("a new membership is gone")
}

/// Takes a user out of a group of Cairn's own directory, by the
/// membership's ID.
pub async fn remove_membership(client: &Object, id: Uuid) -> anyhow::Result<()> {
    let membership = memberships(client, None, None)
        .await?
        .into_iter()
        .find(|m| m.id == id);
    let Some(membership) = membership else {
        return refused(Refused::NoSuch(format!("There's no membership {id}.")));
    };
    let group = groups(client, Some(Lookup::Id(membership.group_id)))
        .await?
        .pop()
        .context("a membership's group is gone")?;
    if !group.own() {
        return Err(sources("group"));
    }
    client
        .execute_cached("DELETE FROM identity_group_members WHERE id = $1", &[&id])
        .await?;
    Ok(())
}

/// `cairn directory-user …`: what the command line does to Cairn's own
/// directory, on a node (see `admin`). The rest is identitystore's, or the
/// console's.
#[derive(clap::Args, Debug, serde::Serialize, serde::Deserialize)]
pub struct DirectoryUserArgs {
    #[command(flatten)]
    #[serde(skip)]
    pub remote: crate::admin::Remote,
    #[command(subcommand)]
    command: DirectoryUserCommand,
}

#[derive(clap::Subcommand, Debug, serde::Serialize, serde::Deserialize)]
enum DirectoryUserCommand {
    /// Make a user of Cairn's own directory, and print a link (valid 7
    /// days, working once) for it to set up a passkey with: the first
    /// administrator, with `--admin`, who makes everyone else in the
    /// console.
    Create {
        /// Its UserName, which it's known by.
        user_name: String,
        /// Its DisplayName (its UserName, unless given).
        #[arg(long)]
        display_name: Option<String>,
        /// Its e-mail.
        #[arg(long)]
        email: Option<String>,
        /// Assign it the permission set `AdministratorAccess` (everything;
        /// made if there's none) in the management account. A user that
        /// exists already gets it too, and a new link: the way back in for
        /// one locked out.
        #[arg(long)]
        admin: bool,
    },
    /// Print a link (valid 7 days, working once) for a user of Cairn's own
    /// directory to make a passkey with: its first, or another, after
    /// losing one. A new link replaces the last. Made from the node's
    /// console URL.
    Link {
        /// The user's UserName.
        user_name: String,
    },
}

/// `cairn directory-user …`, on a node.
pub async fn run(
    app: &std::sync::Arc<crate::App>,
    args: DirectoryUserArgs,
    out: &mut crate::admin::Output,
) -> anyhow::Result<()> {
    let client = app.pool.get().await?;
    match args.command {
        DirectoryUserCommand::Create {
            user_name,
            display_name,
            email,
            admin,
        } => {
            let existing = users(&client, Some(Lookup::Name(&user_name))).await?.pop();
            let user = match existing {
                Some(user) if admin && user.own() => user,
                Some(_) => {
                    return Err(crate::users::Invalid(format!(
                        "there's a directory user named {user_name:?} already: `cairn directory-user link` makes it a link"
                    ))
                    .into());
                }
                None => {
                    let profile = serde_json::json!({});
                    let own = OwnUser {
                        user_name: &user_name,
                        display_name: display_name.as_deref().unwrap_or(&user_name),
                        email: email.as_deref(),
                        profile: &profile,
                    };
                    create_user(&client, &own).await?
                }
            };
            if admin {
                let account = crate::users::account(&client).await?;
                make_admin(&client, &account, &user).await?;
            }
            let token = crate::console::store::create_setup_link(&client, user.id).await?;
            crate::users::setup_link(app, &token, out);
        }
        DirectoryUserCommand::Link { user_name } => {
            let Some(user) = users(&client, Some(Lookup::Name(&user_name))).await?.pop() else {
                return Err(crate::users::Invalid(format!(
                    "there's no directory user named {user_name:?}"
                ))
                .into());
            };
            let token = crate::console::store::create_setup_link(&client, user.id).await?;
            crate::users::setup_link(app, &token, out);
        }
    }
    Ok(())
}

/// The permission set the command line makes administrators with.
const ADMINISTRATOR_ACCESS: &str = "AdministratorAccess";

/// Assigns `user` the permission set `AdministratorAccess` of `account`
/// (the management account) there, making the set (with AWS's managed
/// policy of the name) if there's none, and giving it that policy if it
/// lacks it. Each step is skipped once done, so that it's done again after
/// a crash midway.
async fn make_admin(client: &Object, account: &str, user: &User) -> anyhow::Result<()> {
    let set = match load(client, account, ADMINISTRATOR_ACCESS).await? {
        Some(set) => set,
        None => {
            let new = New {
                name: ADMINISTRATOR_ACCESS,
                description: "Everything, in the accounts it's assigned in.",
                session_duration: 3600,
                relay_state: None,
                tags: None,
            };
            match create(client, account, &new).await {
                Ok(set) => set,
                // Made meanwhile.
                Err(_) => load(client, account, ADMINISTRATOR_ACCESS)
                    .await?
                    .context("a new permission set is gone")?,
            }
        }
    };
    let policy = crate::managed::aws_arn(ADMINISTRATOR_ACCESS);
    if !managed_policies(client, &set)
        .await?
        .iter()
        .any(|a| a.arn == policy)
    {
        attach(client, &set, &policy, true).await?;
        let set = load_id(client, set.id)
            .await?
            .context("the permission set is gone")?;
        if let Err(why) = provision_all(client, &set).await? {
            anyhow::bail!("provisioning the permission set {}: {why}", set.name);
        }
    }
    let set = load_id(client, set.id)
        .await?
        .context("the permission set is gone")?;
    if assignments(
        client,
        account,
        Some(account),
        Some(set.id),
        Some((PrincipalType::User, user.id)),
    )
    .await?
    .is_empty()
        && let Err(why) = assign(client, &set, account, PrincipalType::User, user.id).await?
    {
        anyhow::bail!("assigning the permission set {}: {why}", set.name);
    }
    Ok(())
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

/// A permission set's assignment to a user or group, in an account.
#[derive(Clone, Debug)]
pub struct Assignment {
    pub id: Uuid,
    /// The account it gives the permission set in (its target), by ID.
    pub account: String,
    pub permission_set: String,
    pub permission_set_short_id: String,
    pub principal_type: PrincipalType,
    pub principal_id: Uuid,
    /// The user's or group's name, its source, and a user's e-mail.
    pub principal_name: String,
    /// The user's or group's identity source; `None` for Cairn's own.
    pub provider: Option<String>,
    pub email: Option<String>,
    pub created: f64,
}

/// The assignments of `account`'s permission sets (in account `target`, of
/// permission set `set`, or to principal `principal`, if given), by
/// permission set and account.
pub async fn assignments(
    client: &Object,
    account: &str,
    target: Option<&str>,
    set: Option<Uuid>,
    principal: Option<(PrincipalType, Uuid)>,
) -> anyhow::Result<Vec<Assignment>> {
    let (kind, id) = match principal {
        Some((kind, id)) => (Some(kind.as_str()), Some(id)),
        None => (None, None),
    };
    let rows = client
        .query_cached(
            "SELECT a.id, p.name, p.short_id, CASE WHEN a.user_id IS NULL THEN 'GROUP' ELSE 'USER' END,
                    coalesce(a.user_id, a.group_id), coalesce(u.user_name, g.name), coalesce(u.provider, g.provider), u.email,
                    extract(epoch FROM a.created_at)::float8, a.account_id
             FROM permission_set_assignments a JOIN permission_sets p ON p.id = a.permission_set_id
             LEFT JOIN identity_users u ON u.id = a.user_id LEFT JOIN identity_groups g ON g.id = a.group_id
             WHERE p.account_id = $1 AND ($2::uuid IS NULL OR p.id = $2)
               AND ($3::text IS NULL OR ($3 = 'USER' AND a.user_id = $4) OR ($3 = 'GROUP' AND a.group_id = $4))
               AND ($5::text IS NULL OR a.account_id = $5)
             ORDER BY p.name, a.account_id, 4, 6",
            &[&account, &set, &kind, &id, &target],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| Assignment {
            id: r.get(0),
            account: r.get(9),
            permission_set: r.get(1),
            permission_set_short_id: r.get(2),
            principal_type: PrincipalType::parse(r.get(3)).expect("one of them"),
            principal_id: r.get(4),
            principal_name: r.get(5),
            provider: r.get(6),
            email: r.get(7),
            created: r.get(8),
        })
        .collect())
}

/// Assigns `set` to the user or group `principal` (by its ID) in
/// `account`, provisioning it there first if it isn't yet (as it is then;
/// once it is, assigning it again doesn't bring its role up to date). `Err`
/// (in `Ok`): why it couldn't be provisioned, which leaves it unassigned.
pub async fn assign(
    client: &Object,
    set: &PermissionSet,
    account: &str,
    kind: PrincipalType,
    principal: Uuid,
) -> anyhow::Result<Result<(), String>> {
    let no_such = || {
        Refused::NoSuch(format!(
            "There's no {} {principal} in the identity store.",
            kind.as_str().to_lowercase()
        ))
    };
    let known = match kind {
        PrincipalType::User => !users(client, Some(Lookup::Id(principal))).await?.is_empty(),
        PrincipalType::Group => !groups(client, Some(Lookup::Id(principal)))
            .await?
            .is_empty(),
    };
    if !known {
        return refused(no_such());
    }
    if !assignments(
        client,
        &set.account,
        Some(account),
        Some(set.id),
        Some((kind, principal)),
    )
    .await?
    .is_empty()
    {
        return refused(Refused::Exists("That assignment exists already.".into()));
    }
    if provisioned(client, set, account).await?.is_none()
        && let Err(why) = provision(client, set, account).await?
    {
        return Ok(Err(why));
    }
    let (user, group) = match kind {
        PrincipalType::User => (Some(principal), None),
        PrincipalType::Group => (None, Some(principal)),
    };
    let made = client
        .execute_cached(
            "INSERT INTO permission_set_assignments (permission_set_id, account_id, user_id, group_id) VALUES ($1, $2, $3, $4)
             ON CONFLICT DO NOTHING",
            &[&set.id, &account, &user, &group],
        )
        .await;
    match made {
        Ok(0) => refused(Refused::Exists("That assignment exists already.".into())),
        Ok(_) => Ok(Ok(())),
        // The set, or the user or group, is gone meanwhile.
        Err(e) if e.code() == Some(&tokio_postgres::error::SqlState::FOREIGN_KEY_VIOLATION) => {
            refused(no_such())
        }
        Err(e) => Err(e.into()),
    }
}

/// Removes `set`'s assignment to a user or group in `account`: whether
/// there was one.
pub async fn unassign(
    client: &Object,
    set: &PermissionSet,
    account: &str,
    kind: PrincipalType,
    principal: Uuid,
) -> anyhow::Result<bool> {
    let column = match kind {
        PrincipalType::User => "user_id",
        PrincipalType::Group => "group_id",
    };
    let removed = client
        .execute(
            &format!("DELETE FROM permission_set_assignments WHERE permission_set_id = $1 AND account_id = $2 AND {column} = $3"),
            &[&set.id, &account, &principal],
        )
        .await?;
    Ok(removed > 0)
}

/// A permission set a directory user may act as in an account: the
/// access portal's choice of an account, and a role there.
#[derive(Clone, Debug)]
pub struct Eligible {
    pub set: PermissionSet,
    /// The account (its ID and name), and the set's role there.
    pub account: String,
    pub account_name: String,
    pub role_id: Uuid,
    pub role_name: String,
}

/// The permission sets of `account`'s instance assigned to directory user
/// `user`, or to one of its groups, with the accounts they're assigned in:
/// by account name, then permission set.
pub async fn eligible(client: &Object, account: &str, user: Uuid) -> anyhow::Result<Vec<Eligible>> {
    let rows = client
        .query_cached(
            &format!(
                "SELECT {COLUMNS}, t.account_id, acc.name, t.role_id, tr.name {FROM}
                 JOIN permission_set_provisions t ON t.permission_set_id = p.id
                 JOIN accounts acc ON acc.id = t.account_id AND acc.closed_at IS NULL
                 JOIN iam_roles tr ON tr.id = t.role_id
                 WHERE p.account_id = $1 AND EXISTS (
                     SELECT 1 FROM permission_set_assignments a WHERE a.permission_set_id = p.id AND a.account_id = t.account_id
                       AND (a.user_id = $2 OR a.group_id IN (SELECT group_id FROM identity_group_members WHERE user_id = $2)))
                 ORDER BY acc.name, t.account_id, p.name"
            ),
            &[&account, &user],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| Eligible {
            set: PermissionSet::of(r),
            account: r.get(10),
            account_name: r.get(11),
            role_id: r.get(12),
            role_name: r.get(13),
        })
        .collect())
}

// ─── sso-admin's requests ────────────────────────────────────────────────────

/// What an asynchronous request of sso-admin's was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationKind {
    /// CreateAccountAssignment.
    Create,
    /// DeleteAccountAssignment.
    Delete,
    /// ProvisionPermissionSet.
    Provision,
}

impl OperationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            OperationKind::Create => "CREATE",
            OperationKind::Delete => "DELETE",
            OperationKind::Provision => "PROVISION",
        }
    }
}

/// An asynchronous request of sso-admin's, done when it was made.
#[derive(Clone, Debug)]
pub struct Operation {
    pub request_id: Uuid,
    pub permission_set_arn: String,
    /// The account it targeted, by ID.
    pub target: Option<String>,
    pub principal: Option<(PrincipalType, Uuid)>,
    /// `SUCCEEDED` or `FAILED` (with why).
    pub status: String,
    pub failure_reason: Option<String>,
    pub created: f64,
}

/// Notes a request of `kind` done, in account `target` (`failure`: why it
/// failed): its ID.
pub async fn record(
    client: &Object,
    account: &str,
    kind: OperationKind,
    permission_set_arn: &str,
    target: Option<&str>,
    principal: Option<(PrincipalType, Uuid)>,
    failure: Option<&str>,
) -> anyhow::Result<Operation> {
    let request_id = Uuid::new_v4();
    let status = if failure.is_some() {
        "FAILED"
    } else {
        "SUCCEEDED"
    };
    let (principal_type, principal_id) = match principal {
        Some((kind, id)) => (Some(kind.as_str()), Some(id)),
        None => (None, None),
    };
    let row = client
        .query_one_cached(
            "INSERT INTO sso_operations (request_id, account_id, kind, permission_set_arn, target_account_id, principal_type, principal_id,
                                         status, failure_reason)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING extract(epoch FROM created_at)::float8",
            &[&request_id, &account, &kind.as_str(), &permission_set_arn, &target, &principal_type, &principal_id, &status, &failure],
        )
        .await?;
    Ok(Operation {
        request_id,
        permission_set_arn: permission_set_arn.to_owned(),
        target: target.map(str::to_owned),
        principal,
        status: status.to_owned(),
        failure_reason: failure.map(str::to_owned),
        created: row.get(0),
    })
}

/// `account`'s requests of `kind` (with status `status`, if given; just
/// `request_id`, if given), newest first.
pub async fn operations(
    client: &Object,
    account: &str,
    kind: OperationKind,
    request_id: Option<Uuid>,
    status: Option<&str>,
) -> anyhow::Result<Vec<Operation>> {
    let rows = client
        .query_cached(
            "SELECT request_id, permission_set_arn, principal_type, principal_id, status, failure_reason,
                    extract(epoch FROM created_at)::float8, target_account_id
             FROM sso_operations WHERE account_id = $1 AND kind = $2 AND ($3::uuid IS NULL OR request_id = $3)
               AND ($4::text IS NULL OR status = $4)
             ORDER BY created_at DESC, request_id",
            &[&account, &kind.as_str(), &request_id, &status],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| Operation {
            request_id: r.get(0),
            permission_set_arn: r.get(1),
            target: r.get(7),
            principal: r
                .get::<_, Option<&str>>(2)
                .and_then(PrincipalType::parse)
                .zip(r.get::<_, Option<Uuid>>(3)),
            status: r.get(4),
            failure_reason: r.get(5),
            created: r.get(6),
        })
        .collect())
}

/// Forgets requests older than `OPERATIONS_KEPT`.
pub async fn reap(client: &Object) -> anyhow::Result<u64> {
    Ok(client
        .execute_cached(
            "DELETE FROM sso_operations WHERE created_at < now() - make_interval(secs => $1)",
            &[&OPERATIONS_KEPT.as_secs_f64()],
        )
        .await?)
}

/// A role session's name for a directory user, as STS takes one (2 to 64 of
/// `[\w+=,.@-]`): its name, e-mail or subject, the first that has one.
pub fn session_name(candidates: &[Option<&str>]) -> String {
    let clean = |text: &str| -> String {
        text.chars()
            .filter(|c| c.is_ascii_alphanumeric() || "+=,.@_-".contains(*c))
            .take(64)
            .collect()
    };
    candidates
        .iter()
        .flatten()
        .map(|c| clean(c))
        .find(|c| c.len() >= 2)
        .unwrap_or_else(|| "directory-user".to_owned())
}

/// An ISO 8601 duration (`PT1H`, `PT90M`, `PT3600S`, `P0DT2H`) in seconds,
/// if it's one of a whole number of seconds.
pub fn parse_duration(text: &str) -> Option<i64> {
    let rest = text.strip_prefix('P')?;
    let (days, time) = match rest.split_once('T') {
        Some((days, time)) => (days, Some(time)),
        None => (rest, None),
    };
    let mut seconds = 0i64;
    let mut parts = |text: &str, units: &[(char, i64)]| -> Option<()> {
        let mut number = String::new();
        let mut last = 0;
        for c in text.chars() {
            if c.is_ascii_digit() {
                number.push(c);
                continue;
            }
            let at = units.iter().position(|(u, _)| *u == c)?;
            if number.is_empty() || at < last {
                return None;
            }
            seconds = seconds.checked_add(number.parse::<i64>().ok()?.checked_mul(units[at].1)?)?;
            number.clear();
            last = at + 1;
        }
        number.is_empty().then_some(())
    };
    parts(days, &[('D', 86400)])?;
    if let Some(time) = time {
        if time.is_empty() {
            return None;
        }
        parts(time, &[('H', 3600), ('M', 60), ('S', 1)])?;
    } else if days.is_empty() {
        return None;
    }
    Some(seconds)
}

/// Seconds as an ISO 8601 duration, as Identity Center writes them
/// (`PT1H`, `PT1H30M`).
pub fn format_duration(seconds: i64) -> String {
    let (h, m, s) = (seconds / 3600, seconds / 60 % 60, seconds % 60);
    let mut out = String::from("PT");
    if h > 0 {
        out.push_str(&format!("{h}H"));
    }
    if m > 0 {
        out.push_str(&format!("{m}M"));
    }
    if s > 0 || out == "PT" {
        out.push_str(&format!("{s}S"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_its_arns() {
        let instance = instance_arn("123456789012");
        assert!(
            instance.starts_with("arn:aws:sso:::instance/ssoins-")
                && instance.len() == "arn:aws:sso:::instance/ssoins-".len() + 16
        );
        let arn = permission_set_arn("123456789012", "0123456789abcdef");
        assert_eq!(
            arn,
            format!(
                "arn:aws:sso:::permissionSet/{}/ps-0123456789abcdef",
                &instance[23..]
            )
        );
        assert_eq!(
            short_id_of("123456789012", &arn).as_deref(),
            Some("0123456789abcdef")
        );
        assert_eq!(short_id_of("999999999999", &arn), None);
        let store = identity_store_id("123456789012");
        assert!(store.starts_with("d-") && store.len() == 12, "{store}");
        assert_eq!(
            customer_policy_reference("arn:aws:iam::1:policy/team/a/read"),
            Some(("read".into(), "/team/a/".into()))
        );
        assert_eq!(
            customer_policy_reference("arn:aws:iam::1:policy/read"),
            Some(("read".into(), "/".into()))
        );
        assert_eq!(
            customer_policy_arn("1", "read", "/team/a/"),
            "arn:aws:iam::1:policy/team/a/read"
        );
    }

    #[test]
    fn reads_and_writes_durations() {
        assert_eq!(parse_duration("PT1H"), Some(3600));
        assert_eq!(parse_duration("PT1H30M"), Some(5400));
        assert_eq!(parse_duration("PT3600S"), Some(3600));
        assert_eq!(parse_duration("P0DT2H"), Some(7200));
        assert_eq!(parse_duration("P1D"), Some(86400));
        for bad in ["", "P", "PT", "1H", "PT1X", "PT30M1H", "PTH", "PT1.5H"] {
            assert_eq!(parse_duration(bad), None, "{bad}");
        }
        assert_eq!(format_duration(3600), "PT1H");
        assert_eq!(format_duration(5400), "PT1H30M");
        assert_eq!(format_duration(43200), "PT12H");
        assert_eq!(format_duration(61), "PT1M1S");
    }

    #[test]
    fn session_names_are_stss() {
        assert_eq!(
            session_name(&[Some("Ada Lovelace"), Some("ada@example.com")]),
            "AdaLovelace"
        );
        assert_eq!(
            session_name(&[Some("Ω"), Some("ada@example.com")]),
            "ada@example.com"
        );
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
