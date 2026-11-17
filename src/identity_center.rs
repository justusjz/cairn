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
//! it, or to one of its groups, allow. As in Identity Center, a permission
//! set is provisioned as a role of the account: at
//! `/aws-reserved/sso.amazonaws.com/`, named `AWSReservedSSO_<set>_<suffix>`,
//! trusting `sso.amazonaws.com` only (so that no one assumes it with STS),
//! holding the set's inline policy (`AwsSSOInlinePolicy`), its AWS managed
//! policies and customer managed policies (the account's, by name and
//! path), and its permissions boundary. Only the permission set changes it:
//! IAM refuses to (`roles::protected`). Changes apply at once, so
//! provisioning (sso-admin's `ProvisionPermissionSet`) has nothing left to
//! do. A directory user signed in to the console picks one of its
//! permission sets, and acts as a session of its role
//! (`assumed-role/AWSReservedSSO_…/<name>`), which may hand it the session's
//! credentials for the CLI too (see `console::directory`).

use anyhow::Context as _;
use deadpool_postgres::Object;
use uuid::Uuid;

use crate::{
    db::Cached,
    managed::Refused,
    roles::{self, Role},
    users::BoundaryRef,
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
    digest.as_ref()[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// `account`'s Identity Center instance's ARN (made up of the account's ID,
/// as it has one).
pub fn instance_arn(account: &str) -> String {
    format!("arn:aws:sso:::instance/ssoins-{}", short_hash(account.as_bytes()))
}

/// `account`'s identity store's ID (`d-` and ten hex digits), and its ARN.
pub fn identity_store_id(account: &str) -> String {
    format!("d-{}", &short_hash(format!("identitystore:{account}").as_bytes())[..10])
}

pub fn identity_store_arn(account: &str) -> String {
    format!("arn:aws:identitystore::{account}:identitystore/{}", identity_store_id(account))
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
    format!("arn:aws:sso:::permissionSet/ssoins-{}/ps-{short_id}", short_hash(account.as_bytes()))
}

/// The short ID a permission set's ARN of `account`'s names, if it's one.
pub fn short_id_of(account: &str, arn: &str) -> Option<String> {
    let rest = arn.strip_prefix(&format!("arn:aws:sso:::permissionSet/ssoins-{}/ps-", short_hash(account.as_bytes())))?;
    (rest.len() == 16 && rest.bytes().all(|b| b.is_ascii_hexdigit())).then(|| rest.to_owned())
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
    /// The 16 hex digits its ARN ends in (`ps-…`).
    pub short_id: String,
    pub name: String,
    pub description: String,
    /// Its sessions' longest, in seconds.
    pub session_duration: i32,
    pub relay_state: Option<String>,
    /// Its tags, as stored (see `s3::tags`); `None` for none.
    pub tags: Option<String>,
    /// The role it's provisioned as.
    pub role_id: Uuid,
    pub role_name: String,
    /// When it was made (seconds since the epoch).
    pub created: f64,
}

const COLUMNS: &str = "p.id, p.account_id, p.short_id, p.name, p.description, p.session_duration, p.relay_state, p.tags,
     p.role_id, r.name, extract(epoch FROM p.created_at)::float8";
const FROM: &str = "FROM permission_sets p JOIN iam_roles r ON r.id = p.role_id";

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
            role_id: row.get(8),
            role_name: row.get(9),
            created: row.get(10),
        }
    }

    pub fn arn(&self) -> String {
        permission_set_arn(&self.account, &self.short_id)
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
        .query_opt_cached(&format!("SELECT {COLUMNS} {FROM} WHERE p.account_id = $1 AND p.name = $2"), &[&account, &name])
        .await?;
    Ok(row.as_ref().map(PermissionSet::of))
}

/// `account`'s permission set of ARN `arn`, if there's one.
pub async fn load_arn(client: &Object, account: &str, arn: &str) -> anyhow::Result<Option<PermissionSet>> {
    let Some(short) = short_id_of(account, arn) else { return Ok(None) };
    let row = client
        .query_opt_cached(&format!("SELECT {COLUMNS} {FROM} WHERE p.account_id = $1 AND p.short_id = $2"), &[&account, &short])
        .await?;
    Ok(row.as_ref().map(PermissionSet::of))
}

/// Permission set `id`, if there's one.
pub async fn load_id(client: &Object, id: Uuid) -> anyhow::Result<Option<PermissionSet>> {
    let row = client.query_opt_cached(&format!("SELECT {COLUMNS} {FROM} WHERE p.id = $1"), &[&id]).await?;
    Ok(row.as_ref().map(PermissionSet::of))
}

/// `account`'s permission sets, by name.
pub async fn list(client: &Object, account: &str) -> anyhow::Result<Vec<PermissionSet>> {
    let rows = client
        .query_cached(&format!("SELECT {COLUMNS} {FROM} WHERE p.account_id = $1 ORDER BY p.name"), &[&account])
        .await?;
    Ok(rows.iter().map(PermissionSet::of).collect())
}

fn check_description(description: &str) -> anyhow::Result<()> {
    if description.chars().count() > 700 {
        return refused(Refused::Validation("A permission set's description is at most 700 characters.".into()));
    }
    Ok(())
}

fn check_duration(seconds: i32) -> anyhow::Result<()> {
    if !SESSION_DURATIONS.contains(&seconds) {
        return refused(Refused::Validation("A permission set's session lasts from 1 to 12 hours (PT1H to PT12H).".into()));
    }
    Ok(())
}

fn check_relay_state(relay_state: &str) -> anyhow::Result<()> {
    if relay_state.is_empty() || relay_state.chars().count() > 240 {
        return refused(Refused::Validation("A permission set's relay state is 1 to 240 characters.".into()));
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

/// Makes a permission set of `account`, and its role.
pub async fn create(client: &Object, account: &str, new: &New<'_>) -> anyhow::Result<PermissionSet> {
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
    if load(client, account, new.name).await?.is_some() {
        return refused(Refused::Exists(format!("A permission set named {} already exists.", new.name)));
    }
    let id = Uuid::new_v4();
    let short_id = id.simple().to_string()[..16].to_owned();
    let role_name = format!("AWSReservedSSO_{}_{short_id}", new.name);
    let trust = roles::check_trust(client, account, &trust()).await?;
    let role = roles::New {
        name: &role_name,
        path: ROLE_PATH,
        trust: &trust,
        description: &format!("Permission set {} (Identity Center)", new.name),
        max_session_duration: new.session_duration,
        boundary: None,
        tags: &[],
    };
    let role_id = roles::create(client, account, &role).await?;
    let made = client
        .execute_cached(
            "INSERT INTO permission_sets (id, account_id, short_id, name, description, session_duration, relay_state, tags, role_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING",
            &[&id, &account, &short_id, &new.name, &new.description, &new.session_duration, &new.relay_state, &new.tags, &role_id],
        )
        .await?;
    if made == 0 {
        // Made meanwhile, by another: its role goes again.
        if let Some(role) = Role::load_id(client, role_id).await? {
            roles::delete(client, &role).await?;
        }
        return refused(Refused::Exists(format!("A permission set named {} already exists.", new.name)));
    }
    load_id(client, id).await?.context("a new permission set is gone")
}

/// What changes of a permission set (`None`: not that).
#[derive(Default)]
pub struct Change<'a> {
    pub description: Option<&'a str>,
    pub session_duration: Option<i32>,
    pub relay_state: Option<&'a str>,
}

/// Changes a permission set (its role's longest session too).
pub async fn update(client: &Object, set: &PermissionSet, change: &Change<'_>) -> anyhow::Result<()> {
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
                    relay_state = coalesce($4, relay_state)
             WHERE id = $1",
            &[&set.id, &change.description, &change.session_duration, &change.relay_state],
        )
        .await?;
    if change.session_duration.is_some() {
        roles::update(client, set.role_id, None, change.session_duration).await?;
    }
    Ok(())
}

/// Sets a permission set's tags (as stored; `None`: none).
pub async fn set_tags(client: &Object, set: &PermissionSet, tags: Option<&str>) -> anyhow::Result<()> {
    client.execute_cached("UPDATE permission_sets SET tags = $2 WHERE id = $1", &[&set.id, &tags]).await?;
    Ok(())
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

/// The managed policies attached to a permission set: AWS's (Cairn's) and
/// the account's (its customer managed policies), by their ARNs.
pub async fn managed_policies(client: &Object, set: &PermissionSet) -> anyhow::Result<Vec<crate::managed::Attached>> {
    roles::attached(client, set.role_id).await
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

/// Attaches (`attach`) or detaches a managed policy (by its ARN: AWS's or
/// the account's) to or from a permission set.
pub async fn attach(client: &Object, set: &PermissionSet, arn: &str, attach: bool) -> anyhow::Result<()> {
    roles::attach(client, &set.account, &set.role(client).await?, arn, attach).await
}

/// A permission set's permissions boundary's ARN, if it has one.
pub async fn boundary(client: &Object, set: &PermissionSet) -> anyhow::Result<Option<String>> {
    Ok(set.role(client).await?.boundary)
}

/// Sets (`Some`: a managed policy's ARN, AWS's or the account's) or removes
/// a permission set's permissions boundary.
pub async fn set_boundary(client: &Object, set: &PermissionSet, arn: Option<&str>) -> anyhow::Result<()> {
    let boundary: Option<BoundaryRef> = match arn {
        Some(arn) => Some(crate::managed::boundary(client, &set.account, arn).await?),
        None => None,
    };
    roles::set_boundary(client, set.role_id, boundary.as_ref()).await
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
    if role.boundary.is_some() {
        roles::set_boundary(client, role.id, None).await?;
    }
    client.execute_cached("DELETE FROM permission_sets WHERE id = $1", &[&set.id]).await?;
    roles::delete(client, &role).await
}

// ─── The identity store ──────────────────────────────────────────────────────

/// A directory user, as it last signed in.
#[derive(Clone, Debug)]
pub struct User {
    pub id: Uuid,
    /// Its identity source (by name), and its issuer, and its subject there.
    pub provider: String,
    pub issuer: String,
    pub subject: String,
    pub user_name: String,
    pub display_name: String,
    pub email: Option<String>,
    pub created: f64,
    /// When it last signed in.
    pub updated: f64,
}

const USER_COLUMNS: &str = "u.id, u.provider, p.issuer, u.subject, u.user_name, u.display_name, u.email,
     extract(epoch FROM u.created_at)::float8, extract(epoch FROM u.updated_at)::float8";
const USERS: &str = "FROM identity_users u JOIN oidc_providers p ON p.name = u.provider";

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
        }
    }
}

/// A group of an identity source, as its users' group claims name it.
#[derive(Clone, Debug)]
pub struct Group {
    pub id: Uuid,
    pub provider: String,
    pub issuer: String,
    /// Its name in the claim (its display name).
    pub name: String,
    pub created: f64,
    pub updated: f64,
}

const GROUP_COLUMNS: &str = "g.id, g.provider, p.issuer, g.name, extract(epoch FROM g.created_at)::float8,
     extract(epoch FROM g.updated_at)::float8";
const GROUPS: &str = "FROM identity_groups g JOIN oidc_providers p ON p.name = g.provider";

impl Group {
    fn of(row: &tokio_postgres::Row) -> Group {
        Group { id: row.get(0), provider: row.get(1), issuer: row.get(2), name: row.get(3), created: row.get(4), updated: row.get(5) }
    }
}

/// How a user or group is looked up.
pub enum Lookup<'a> {
    Id(Uuid),
    /// By `UserName`, or a group's display name.
    Name(&'a str),
    /// By its external ID: its source's issuer, and its subject (or a
    /// group's name).
    External { issuer: &'a str, id: &'a str },
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
pub async fn memberships(client: &Object, group: Option<Uuid>, user: Option<Uuid>) -> anyhow::Result<Vec<Membership>> {
    let rows = client
        .query_cached(
            "SELECT id, group_id, user_id, extract(epoch FROM created_at)::float8 FROM identity_group_members
             WHERE ($1::uuid IS NULL OR group_id = $1) AND ($2::uuid IS NULL OR user_id = $2) ORDER BY id",
            &[&group, &user],
        )
        .await?;
    Ok(rows.iter().map(|r| Membership { id: r.get(0), group_id: r.get(1), user_id: r.get(2), created: r.get(3) }).collect())
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
            "UPDATE identity_users SET display_name = $3, email = $4, updated_at = now()
             WHERE provider = $1 AND subject = $2 RETURNING id",
            &[&provider, &subject, &name, &email],
        )
        .await?;
    let user = match known {
        Some(row) => row.get(0),
        None => {
            // Its user name: the first of these no one has.
            let id = Uuid::new_v4();
            let candidates = [user_name.map(str::to_owned), email.map(str::to_owned), Some(subject.to_owned()), Some(format!("{provider}/{subject}"))];
            let mut made = None;
            for candidate in candidates.into_iter().flatten().filter(|c| !c.is_empty() && c.chars().count() <= 128) {
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
                    .query_opt_cached("SELECT id FROM identity_users WHERE provider = $1 AND subject = $2", &[&provider, &subject])
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
                 ON CONFLICT (provider, name) DO UPDATE SET updated_at = now() RETURNING id",
                &[&Uuid::new_v4(), &provider, &group],
            )
            .await?;
        group_ids.push(row.get::<_, Uuid>(0));
    }
    client
        .execute_cached(
            "DELETE FROM identity_group_members WHERE user_id = $1 AND NOT group_id = ANY($2)",
            &[&user, &group_ids],
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

/// A permission set's assignment to a user or group.
#[derive(Clone, Debug)]
pub struct Assignment {
    pub id: Uuid,
    pub permission_set: String,
    pub permission_set_short_id: String,
    pub principal_type: PrincipalType,
    pub principal_id: Uuid,
    /// The user's or group's name, its source, and a user's e-mail.
    pub principal_name: String,
    pub provider: String,
    pub email: Option<String>,
    pub created: f64,
}

/// `account`'s assignments (of permission set `set`, or to principal
/// `principal`, if given), by permission set.
pub async fn assignments(
    client: &Object,
    account: &str,
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
                    extract(epoch FROM a.created_at)::float8
             FROM permission_set_assignments a JOIN permission_sets p ON p.id = a.permission_set_id
             LEFT JOIN identity_users u ON u.id = a.user_id LEFT JOIN identity_groups g ON g.id = a.group_id
             WHERE p.account_id = $1 AND ($2::uuid IS NULL OR p.id = $2)
               AND ($3::text IS NULL OR ($3 = 'USER' AND a.user_id = $4) OR ($3 = 'GROUP' AND a.group_id = $4))
             ORDER BY p.name, 4, 6",
            &[&account, &set, &kind, &id],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| Assignment {
            id: r.get(0),
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

/// Assigns `set` to the user or group `principal` (by its ID).
pub async fn assign(client: &Object, set: &PermissionSet, kind: PrincipalType, principal: Uuid) -> anyhow::Result<()> {
    let (user, group) = match kind {
        PrincipalType::User => (Some(principal), None),
        PrincipalType::Group => (None, Some(principal)),
    };
    let made = client
        .execute_cached(
            "INSERT INTO permission_set_assignments (permission_set_id, user_id, group_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            &[&set.id, &user, &group],
        )
        .await;
    match made {
        Ok(0) => refused(Refused::Exists("That assignment exists already.".into())),
        Ok(_) => Ok(()),
        // The set, or the user or group, isn't there.
        Err(e) if e.code() == Some(&tokio_postgres::error::SqlState::FOREIGN_KEY_VIOLATION) => refused(Refused::NoSuch(format!(
            "There's no {} {principal} in the identity store.",
            kind.as_str().to_lowercase()
        ))),
        Err(e) => Err(e.into()),
    }
}

/// Removes `set`'s assignment to a user or group: whether there was one.
pub async fn unassign(client: &Object, set: &PermissionSet, kind: PrincipalType, principal: Uuid) -> anyhow::Result<bool> {
    let column = match kind {
        PrincipalType::User => "user_id",
        PrincipalType::Group => "group_id",
    };
    let removed = client
        .execute(&format!("DELETE FROM permission_set_assignments WHERE permission_set_id = $1 AND {column} = $2"), &[&set.id, &principal])
        .await?;
    Ok(removed > 0)
}

/// The permission sets of `account` assigned to directory user `user`, or
/// to one of its groups.
pub async fn eligible(client: &Object, account: &str, user: Uuid) -> anyhow::Result<Vec<PermissionSet>> {
    let rows = client
        .query_cached(
            &format!(
                "SELECT {COLUMNS} {FROM}
                 WHERE p.account_id = $1 AND EXISTS (
                     SELECT 1 FROM permission_set_assignments a WHERE a.permission_set_id = p.id
                       AND (a.user_id = $2 OR a.group_id IN (SELECT group_id FROM identity_group_members WHERE user_id = $2)))
                 ORDER BY p.name"
            ),
            &[&account, &user],
        )
        .await?;
    Ok(rows.iter().map(PermissionSet::of).collect())
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
    pub principal: Option<(PrincipalType, Uuid)>,
    /// `SUCCEEDED` or `FAILED` (with why).
    pub status: String,
    pub failure_reason: Option<String>,
    pub created: f64,
}

/// Notes a request of `kind` done (`failure`: why it failed): its ID.
pub async fn record(
    client: &Object,
    account: &str,
    kind: OperationKind,
    permission_set_arn: &str,
    principal: Option<(PrincipalType, Uuid)>,
    failure: Option<&str>,
) -> anyhow::Result<Operation> {
    let request_id = Uuid::new_v4();
    let status = if failure.is_some() { "FAILED" } else { "SUCCEEDED" };
    let (principal_type, principal_id) = match principal {
        Some((kind, id)) => (Some(kind.as_str()), Some(id)),
        None => (None, None),
    };
    let row = client
        .query_one_cached(
            "INSERT INTO sso_operations (request_id, account_id, kind, permission_set_arn, principal_type, principal_id, status, failure_reason)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING extract(epoch FROM created_at)::float8",
            &[&request_id, &account, &kind.as_str(), &permission_set_arn, &principal_type, &principal_id, &status, &failure],
        )
        .await?;
    Ok(Operation {
        request_id,
        permission_set_arn: permission_set_arn.to_owned(),
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
                    extract(epoch FROM created_at)::float8
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
        text.chars().filter(|c| c.is_ascii_alphanumeric() || "+=,.@_-".contains(*c)).take(64).collect()
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
        assert!(instance.starts_with("arn:aws:sso:::instance/ssoins-") && instance.len() == "arn:aws:sso:::instance/ssoins-".len() + 16);
        let arn = permission_set_arn("123456789012", "0123456789abcdef");
        assert_eq!(arn, format!("arn:aws:sso:::permissionSet/{}/ps-0123456789abcdef", &instance[23..]));
        assert_eq!(short_id_of("123456789012", &arn).as_deref(), Some("0123456789abcdef"));
        assert_eq!(short_id_of("999999999999", &arn), None);
        let store = identity_store_id("123456789012");
        assert!(store.starts_with("d-") && store.len() == 12, "{store}");
        assert_eq!(customer_policy_reference("arn:aws:iam::1:policy/team/a/read"), Some(("read".into(), "/team/a/".into())));
        assert_eq!(customer_policy_reference("arn:aws:iam::1:policy/read"), Some(("read".into(), "/".into())));
        assert_eq!(customer_policy_arn("1", "read", "/team/a/"), "arn:aws:iam::1:policy/team/a/read");
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
