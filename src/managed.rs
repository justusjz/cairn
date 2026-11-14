//! Managed policies, as IAM's: identity policies that are documents of their
//! own, attached to any number of users. There are two kinds:
//!
//! - **Cairn's**, which have AWS's names and ARNs
//!   (`arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess`), and say what AWS's
//!   say, so that policies and tools written for AWS work unchanged. They
//!   can't be changed. AdministratorAccess is kept as a user's admin flag
//!   (which older nodes read); the others as attachments. One is Cairn's
//!   own: `CairnOperatorAccess`, the cluster's `cairn:` actions.
//! - **An account's own** (`arn:aws:iam::<account>:policy/<name>`), which its
//!   admins make, change and delete. IAM keeps up to five versions of one;
//!   Cairn keeps the default, numbered as IAM numbers versions (`v1`, ...).
//!
//! A user's attached policies count as its identity policies, alongside its
//! inline ones (see `users::Principal`, `s3::access`). Limits are IAM's: a
//! document of at most 6,144 characters (but whitespace), and at most 10
//! policies attached to a user.

use std::collections::HashMap;

use deadpool_postgres::Object;
use uuid::Uuid;

use crate::db::Cached;

/// One of Cairn's managed policies, as AWS has it.
pub struct AwsPolicy {
    pub name: &'static str,
    pub description: &'static str,
    pub document: &'static str,
}

/// AdministratorAccess: a user's admin flag.
pub const ADMINISTRATOR_ACCESS: &str = "AdministratorAccess";

/// Cairn's managed policies: AWS's that are about what Cairn does, with
/// AWS's documents.
pub const AWS_POLICIES: &[AwsPolicy] = &[
    AwsPolicy {
        name: ADMINISTRATOR_ACCESS,
        description: "Provides full access to AWS services and resources.",
        document: r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#,
    },
    AwsPolicy {
        name: "AmazonS3FullAccess",
        description: "Provides full access to all buckets via the AWS Management Console.",
        document: r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*","s3-object-lambda:*"],"Resource":"*"}]}"#,
    },
    AwsPolicy {
        name: "AmazonS3ReadOnlyAccess",
        description: "Provides read only access to all buckets via the AWS Management Console.",
        document: r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:Get*","s3:List*","s3:Describe*","s3-object-lambda:Get*","s3-object-lambda:List*"],"Resource":"*"}]}"#,
    },
    // Cairn's own, not AWS's: running the cluster, without the data (see
    // `plans/single-account.md`). AdministratorAccess (`*`) includes it.
    AwsPolicy {
        name: "CairnOperatorAccess",
        description: "Provides full access to the Cairn cluster's settings, nodes and health, but not to buckets or users.",
        document: r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cairn:*","Resource":"*"}]}"#,
    },
];

/// The most a managed policy's document may hold, in characters but
/// whitespace, as in IAM.
pub const MAX_DOCUMENT: usize = 6144;
/// The most managed policies a user may have attached, as IAM's quota.
pub const MAX_ATTACHED: i64 = 10;
/// The most a description may be, as in IAM.
const MAX_DESCRIPTION: usize = 1000;

/// Why a change to managed policies was refused, as IAM's errors say.
#[derive(Debug)]
pub enum Refused {
    /// NoSuchEntity (404).
    NoSuch(String),
    /// EntityAlreadyExists (409).
    Exists(String),
    /// DeleteConflict (409).
    Conflict(String),
    /// LimitExceeded (409).
    Limit(String),
    /// ValidationError (400).
    Validation(String),
    /// MalformedPolicyDocument (400).
    Malformed(String),
    /// InvalidInput (400).
    Invalid(String),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::NoSuch(m) | Refused::Exists(m) | Refused::Conflict(m) | Refused::Limit(m) => f.write_str(m),
            Refused::Malformed(m) | Refused::Invalid(m) | Refused::Validation(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Refused {}

fn refused<T>(r: Refused) -> anyhow::Result<T> {
    Err(r.into())
}

/// An AWS policy's ARN.
pub fn aws_arn(name: &str) -> String {
    format!("arn:aws:iam::aws:policy/{name}")
}

/// An account's policy's ARN, at `path` (`/`, or `/…/`).
pub fn arn(account: &str, path: &str, name: &str) -> String {
    format!("arn:aws:iam::{account}:policy/{}{name}", path.strip_prefix('/').unwrap_or(path))
}

/// Cairn's policy named `name`.
pub fn aws(name: &str) -> Option<&'static AwsPolicy> {
    AWS_POLICIES.iter().find(|p| p.name == name)
}

/// A managed policy, by its ARN.
#[derive(Debug, PartialEq)]
pub enum Named {
    Aws(&'static AwsPolicy),
    /// One of the account's own, by its path (`/`, or `/…/`) and name.
    Own { path: String, name: String },
}

impl std::fmt::Debug for AwsPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name)
    }
}

impl PartialEq for AwsPolicy {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

/// The policy `arn` names, as `account` sees it: one of Cairn's, or one of
/// the account's own (another account's are none it may attach), by its
/// path and name (whether the policy is at that path is the caller's to
/// check: see `own`).
pub fn named(arn: &str, account: &str) -> anyhow::Result<Named> {
    let no_such = || Refused::NoSuch(format!("Policy {arn} does not exist or is not attachable."));
    let Some(rest) = arn.strip_prefix("arn:aws:iam::") else { return refused(Refused::Invalid(format!("ARN {arn} is not valid."))) };
    let Some((owner, rest)) = rest.split_once(":policy/") else { return refused(Refused::Invalid(format!("ARN {arn} is not valid."))) };
    let (path, name) = match rest.rsplit_once('/') {
        Some((path, name)) => (format!("/{path}/"), name),
        None => ("/".to_owned(), rest),
    };
    if name.is_empty() {
        return refused(no_such());
    }
    match owner {
        // Cairn's have no paths.
        "aws" if path == "/" => aws(name).map(Named::Aws).ok_or_else(|| no_such().into()),
        owner if owner == account => Ok(Named::Own { path, name: name.to_owned() }),
        _ => refused(no_such()),
    }
}

/// The account's own policy at `path` named `name` (as `named` gives it).
pub async fn own(client: &Object, account: &str, path: &str, name: &str) -> anyhow::Result<Managed> {
    match get(client, account, name).await {
        Ok(policy) if policy.path == path => Ok(policy),
        Ok(_) | Err(_) => refused(Refused::NoSuch(format!("Policy {} was not found.", arn(account, path, name)))),
    }
}

/// The permissions boundary `arn` names, for a user of `account`, as IAM
/// refuses one (probed): a managed policy, the account's own or Cairn's.
pub async fn boundary(client: &Object, account: &str, arn: &str) -> anyhow::Result<crate::users::BoundaryRef> {
    let scope = || Refused::NoSuch(format!("Scope ARN: {arn} does not exist or is not attachable."));
    let policy = arn.strip_prefix("arn:aws:iam::").and_then(|rest| rest.split_once(":policy/"));
    if policy.is_none_or(|(owner, _)| owner != "aws" && !(owner.len() == 12 && owner.bytes().all(|b| b.is_ascii_digit()))) {
        return refused(Refused::Invalid(format!("ARN {arn} is not valid.")));
    }
    match named(arn, account).map_err(|_| scope())? {
        Named::Aws(p) => Ok(crate::users::BoundaryRef::Aws(p.name)),
        Named::Own { path, name } => match own(client, account, &path, &name).await {
            Ok(policy) => Ok(crate::users::BoundaryRef::Own(policy.id)),
            Err(_) => refused(scope()),
        },
    }
}

/// Checks `document` as a managed policy's.
pub fn check_document(document: &str) -> anyhow::Result<()> {
    crate::policy::Policy::parse(document, crate::policy::Kind::Identity).map_err(|e| Refused::Malformed(e.message))?;
    if document.chars().filter(|c| !c.is_whitespace()).count() > MAX_DOCUMENT {
        return refused(Refused::Limit(format!("Cannot exceed quota for PolicySize: {MAX_DOCUMENT}")));
    }
    Ok(())
}

/// Checks a policy's path (see `users::check_path`).
fn check_path(path: &str) -> anyhow::Result<()> {
    crate::users::check_path(path, "path", false).map_err(|m| Refused::Validation(m).into())
}

fn check_name(name: &str) -> anyhow::Result<()> {
    let valid = (1..=128).contains(&name.len()) && name.chars().all(|c| c.is_ascii_alphanumeric() || "+=,.@_-".contains(c));
    if !valid {
        return refused(Refused::Invalid("a policy's name is 1 to 128 of A-Z, a-z, 0-9 and +=,.@_-".into()));
    }
    Ok(())
}

/// One of an account's managed policies.
#[derive(Clone, Debug)]
pub struct Managed {
    pub id: Uuid,
    pub name: String,
    /// Its path (`/`, or `/…/`), which its ARN has before its name.
    pub path: String,
    pub description: String,
    pub document: String,
    /// Its default version's number (`v1`, ...).
    pub version: i32,
    pub updated_at: f64,
    /// The users it's attached to, by name.
    pub users: Vec<String>,
    /// The users whose permissions boundary it is, by name.
    pub bounds: Vec<String>,
    /// Its tags, oldest first.
    pub tags: Vec<(String, String)>,
}

impl Managed {
    /// Its ARN, as an account's (`account`'s) policy.
    pub fn arn(&self, account: &str) -> String {
        arn(account, &self.path, &self.name)
    }
}

const COLUMNS: &str = "m.id, m.name, m.description, m.document, m.version,
     extract(epoch FROM m.updated_at)::float8,
     ARRAY(SELECT r.name FROM user_attached_policies x JOIN users r ON r.id = x.user_id
           WHERE x.policy_id = m.id ORDER BY r.name),
     m.path,
     ARRAY(SELECT r.name FROM users r WHERE r.boundary_policy_id = m.id ORDER BY r.name),
     ARRAY(SELECT t.key FROM managed_policy_tags t WHERE t.policy_id = m.id ORDER BY t.seq),
     ARRAY(SELECT t.value FROM managed_policy_tags t WHERE t.policy_id = m.id ORDER BY t.seq)";

fn managed_of(row: &tokio_postgres::Row) -> Managed {
    Managed {
        id: row.get(0),
        name: row.get(1),
        description: row.get(2),
        document: row.get(3),
        version: row.get(4),
        updated_at: row.get(5),
        users: row.get(6),
        path: row.get(7),
        bounds: row.get(8),
        tags: crate::users::tags_of(row.get(9), row.get(10)),
    }
}

/// The account's own managed policies, by name.
pub async fn list(client: &Object, account: &str) -> anyhow::Result<Vec<Managed>> {
    let rows = client
        .query_cached(&format!("SELECT {COLUMNS} FROM managed_policies m WHERE m.account_id = $1 ORDER BY m.name"), &[&account])
        .await?;
    Ok(rows.iter().map(managed_of).collect())
}

/// The account's managed policy `name`.
pub async fn get(client: &Object, account: &str, name: &str) -> anyhow::Result<Managed> {
    let row = client
        .query_opt_cached(&format!("SELECT {COLUMNS} FROM managed_policies m WHERE m.account_id = $1 AND m.name = $2"), &[&account, &name])
        .await?;
    match row {
        Some(row) => Ok(managed_of(&row)),
        None => refused(Refused::NoSuch(format!("Policy {} was not found.", arn(account, "/", name)))),
    }
}

/// Makes the account's managed policy `name`, at `path`. Names are unique
/// in an account whatever their paths (probed).
pub async fn create(client: &Object, account: &str, name: &str, path: &str, document: &str, description: &str) -> anyhow::Result<Managed> {
    create_tagged(client, account, name, path, document, description, &[]).await
}

/// As `create`, with `tags` (checked: see `check_tags`).
pub async fn create_tagged(
    client: &Object,
    account: &str,
    name: &str,
    path: &str,
    document: &str,
    description: &str,
    tags: &[(String, String)],
) -> anyhow::Result<Managed> {
    check_name(name)?;
    check_path(path)?;
    check_document(document)?;
    if description.len() > MAX_DESCRIPTION {
        return refused(Refused::Invalid(format!("a policy's description is at most {MAX_DESCRIPTION} characters")));
    }
    let made = client
        .execute_cached(
            "INSERT INTO managed_policies (account_id, name, document, description, path) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT DO NOTHING",
            &[&account, &name, &document, &description, &path],
        )
        .await?;
    if made == 0 {
        return refused(Refused::Exists(format!("A policy called {name} already exists. Duplicate names are not allowed.")));
    }
    let policy = get(client, account, name).await?;
    if !tags.is_empty() {
        tag(client, policy.id, tags).await?;
        return get(client, account, name).await;
    }
    Ok(policy)
}

/// Why `tags` can't be a policy's (the console's; the IAM API says it as
/// IAM does: see `iam`): as a user's (`users::check_tags`), but that keys are
/// case-sensitive (probed).
pub fn check_tags(tags: &[(String, String)]) -> Result<(), String> {
    if tags.len() > crate::users::MAX_TAGS {
        return Err(format!("a policy has at most {} tags", crate::users::MAX_TAGS));
    }
    let mut seen = std::collections::HashSet::new();
    for (key, value) in tags {
        if !(1..=128).contains(&key.chars().count()) || value.chars().count() > 256 {
            return Err("a tag's key is 1 to 128 characters, its value at most 256".to_owned());
        }
        if !key.chars().all(crate::users::tag_char) || !value.chars().all(crate::users::tag_char) {
            return Err("tags hold letters, digits, spaces and _.:/=+-@".to_owned());
        }
        if key.to_ascii_lowercase().starts_with("aws:") {
            return Err("Tag keys beginning with aws: are reserved for system use.".to_owned());
        }
        if !seen.insert(key.as_str()) {
            return Err(format!("the tag key {key:?} is given twice"));
        }
    }
    Ok(())
}

/// Tags policy `id` with `tags`, replacing those it has of the same keys
/// (case-sensitive), unless it would have more than 50 (T43).
pub async fn tag(client: &Object, id: Uuid, tags: &[(String, String)]) -> anyhow::Result<()> {
    let keys: Vec<&str> = tags.iter().map(|(k, _)| k.as_str()).collect();
    let values: Vec<&str> = tags.iter().map(|(_, v)| v.as_str()).collect();
    let max = crate::users::MAX_TAGS as i32;
    let status: String = client
        .query_one_cached("SELECT pg_temp.cairn_tag_policy($1, $2, $3, $4)", &[&id, &keys, &values, &max])
        .await?
        .get(0);
    match status.as_str() {
        "tagged" => Ok(()),
        "too_many" => Err(crate::users::TooManyTags.into()),
        _ => refused(Refused::NoSuch("no such policy".into())),
    }
}

/// Removes policy `id`'s tags of `keys` (case-sensitive), those it has.
pub async fn untag(client: &Object, id: Uuid, keys: &[String]) -> anyhow::Result<()> {
    client
        .execute_cached("DELETE FROM managed_policy_tags WHERE policy_id = $1 AND key = ANY ($2)", &[&id, &keys])
        .await?;
    Ok(())
}

/// A new default version of the account's managed policy `name`, with
/// `document`: if it has five versions already, the oldest that isn't the
/// default goes, as Terraform makes room (the console's edit). Its number.
pub async fn update(client: &Object, account: &str, name: &str, document: &str) -> anyhow::Result<i32> {
    let policy = get(client, account, name).await?;
    create_version(client, policy.id, &policy.arn(account), document, true, true).await
}

/// The most versions a managed policy has, as in IAM.
pub const MAX_VERSIONS: i32 = 5;

/// A new version of policy `id` (whose ARN is `arn`), with `document`, its
/// default if `default`; with five already, the oldest that isn't the
/// default goes first if `prune`, else it's refused, as IAM refuses it
/// (T44). Its number.
pub async fn create_version(client: &Object, id: Uuid, arn: &str, document: &str, default: bool, prune: bool) -> anyhow::Result<i32> {
    check_document(document)?;
    let made: Option<i32> = client
        .query_one_cached(
            "SELECT pg_temp.cairn_create_policy_version($1, $2, $3, $4, $5)",
            &[&id, &document, &default, &prune, &MAX_VERSIONS],
        )
        .await?
        .get(0);
    match made {
        Some(0) => refused(Refused::Limit(
            "A managed policy can have up to 5 versions. Before you create a new version, you must delete an existing version.".into(),
        )),
        Some(version) => Ok(version),
        None => refused(Refused::NoSuch(format!("Policy {arn} was not found."))),
    }
}

/// One of a managed policy's versions.
#[derive(Clone, Debug)]
pub struct Version {
    pub version: i32,
    pub document: String,
    /// When it was made: ISO 8601 (as IAM writes times), and in seconds
    /// since the Unix epoch.
    pub created: String,
    pub created_at: f64,
    /// Whether it's the policy's default, which decides.
    pub default: bool,
}

/// Policy `id`'s versions, newest first (as IAM lists them).
pub async fn versions(client: &Object, id: Uuid) -> anyhow::Result<Vec<Version>> {
    let rows = client
        .query_cached(
            "SELECT v.version, v.document, to_char(v.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
                    extract(epoch FROM v.created_at)::float8, v.version = m.version
             FROM managed_policy_versions v JOIN managed_policies m ON m.id = v.policy_id
             WHERE v.policy_id = $1 ORDER BY v.version DESC",
            &[&id],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| Version { version: r.get(0), document: r.get(1), created: r.get(2), created_at: r.get(3), default: r.get(4) })
        .collect())
}

/// Why changing a policy's version failed, as IAM says it.
fn no_such_version(arn: &str, version: i32) -> Refused {
    Refused::NoSuch(format!("Policy {arn} version v{version} does not exist or is not attachable."))
}

/// Makes version `version` of policy `id` (whose ARN is `arn`) its default
/// (T45).
pub async fn set_default(client: &Object, id: Uuid, arn: &str, version: i32) -> anyhow::Result<()> {
    let status: String = client
        .query_one_cached("SELECT pg_temp.cairn_set_default_policy_version($1, $2)", &[&id, &version])
        .await?
        .get(0);
    match status.as_str() {
        "set" => Ok(()),
        _ => refused(no_such_version(arn, version)),
    }
}

/// Deletes version `version` of policy `id` (whose ARN is `arn`), unless
/// it's the default (T46).
pub async fn delete_version(client: &Object, id: Uuid, arn: &str, version: i32) -> anyhow::Result<()> {
    let status: String = client
        .query_one_cached("SELECT pg_temp.cairn_delete_policy_version($1, $2)", &[&id, &version])
        .await?
        .get(0);
    match status.as_str() {
        "deleted" => Ok(()),
        "default" => refused(Refused::Conflict("Cannot delete the default version of a policy.".into())),
        _ => refused(no_such_version(arn, version)),
    }
}

/// Changes the description of the account's managed policy `name` (which
/// IAM doesn't: the console's).
pub async fn describe(client: &Object, account: &str, name: &str, description: &str) -> anyhow::Result<()> {
    if description.len() > MAX_DESCRIPTION {
        return refused(Refused::Invalid(format!("a policy's description is at most {MAX_DESCRIPTION} characters")));
    }
    let updated = client
        .execute_cached(
            "UPDATE managed_policies SET description = $3 WHERE account_id = $1 AND name = $2",
            &[&account, &name, &description],
        )
        .await?;
    if updated == 0 {
        return refused(Refused::NoSuch(format!("Policy {} was not found.", arn(account, "/", name))));
    }
    Ok(())
}

/// Deletes the account's managed policy `name`, unless it's attached, or
/// a user's permissions boundary (whose foreign key keeps it, too).
pub async fn delete(client: &Object, account: &str, name: &str) -> anyhow::Result<()> {
    let policy = get(client, account, name).await?;
    if !policy.users.is_empty() || !policy.bounds.is_empty() {
        return refused(Refused::Conflict("Cannot delete a policy attached to entities.".into()));
    }
    // Its other versions go first, as in IAM (probed). (One made meanwhile
    // goes with the policy.)
    if versions(client, policy.id).await?.len() > 1 {
        return refused(Refused::Conflict(
            "This policy has more than one version. Before you delete a policy, you must delete the policy's versions. \
             The default version is deleted with the policy."
                .into(),
        ));
    }
    let deleted = client
        .execute_cached(
            "DELETE FROM managed_policies m WHERE m.id = $1
             AND NOT EXISTS (SELECT 1 FROM user_attached_policies x WHERE x.policy_id = m.id)",
            &[&policy.id],
        )
        .await;
    match deleted {
        Ok(1) => Ok(()),
        // Attached meanwhile.
        Ok(_) => refused(Refused::Conflict("Cannot delete a policy attached to entities.".into())),
        Err(e) if e.code() == Some(&tokio_postgres::error::SqlState::FOREIGN_KEY_VIOLATION) => {
            refused(Refused::Conflict("Cannot delete a policy attached to entities.".into()))
        }
        Err(e) => Err(e.into()),
    }
}

/// A policy attached to a user: its name and ARN.
#[derive(Clone, Debug, PartialEq)]
pub struct Attached {
    pub name: String,
    pub arn: String,
}

/// The managed policies attached to each of `account`'s users, by user ID:
/// AdministratorAccess (an admin's), Cairn's others, then the account's.
pub async fn attached_all(client: &Object, account: &str) -> anyhow::Result<HashMap<Uuid, Vec<Attached>>> {
    let rows = client
        .query_cached(
            "SELECT r.id, NULL::text, 'AdministratorAccess' FROM users r WHERE r.account_id = $1 AND r.admin
             UNION ALL
             SELECT r.id, NULL, x.aws_policy FROM user_attached_policies x JOIN users r ON r.id = x.user_id
             WHERE r.account_id = $1 AND x.aws_policy IS NOT NULL
             UNION ALL
             SELECT r.id, m.account_id || ' ' || m.path, m.name FROM user_attached_policies x JOIN users r ON r.id = x.user_id
             JOIN managed_policies m ON m.id = x.policy_id WHERE r.account_id = $1
             ORDER BY 1, 2 NULLS FIRST, 3",
            &[&account],
        )
        .await?;
    let mut all: HashMap<Uuid, Vec<Attached>> = HashMap::new();
    for row in rows {
        let (user, owner, name): (Uuid, Option<String>, String) = (row.get(0), row.get(1), row.get(2));
        let arn = match owner.as_deref().and_then(|o| o.split_once(' ')) {
            Some((owner, path)) => arn(owner, path, &name),
            None => aws_arn(&name),
        };
        all.entry(user).or_default().push(Attached { name, arn });
    }
    Ok(all)
}

/// The managed policies attached to user `user` of `account`.
pub async fn attached(client: &Object, account: &str, user: &str) -> anyhow::Result<Vec<Attached>> {
    let id = crate::users::id_of(client, account, user).await?;
    Ok(attached_all(client, account).await?.remove(&id).unwrap_or_default())
}

/// Attaches (`attach`) or detaches the policy `arn` to user `user` of
/// `account`.
pub async fn attach(client: &Object, account: &str, user: &str, arn: &str, attach: bool) -> anyhow::Result<()> {
    let policy = named(arn, account)?;
    let role = crate::users::id_of(client, account, user)
        .await
        .map_err(|_| Refused::NoSuch(format!("The user with name {user} cannot be found.")))?;
    if attach {
        let count: i64 = client
            .query_one_cached(
                "SELECT (SELECT count(*) FROM user_attached_policies WHERE user_id = $1)
                      + (SELECT count(*) FROM users WHERE id = $1 AND admin)",
                &[&role],
            )
            .await?
            .get(0);
        if count >= MAX_ATTACHED && !attached(client, account, user).await?.iter().any(|a| a.arn == arn) {
            return refused(Refused::Limit(format!("Cannot exceed quota for PoliciesPerUser: {MAX_ATTACHED}")));
        }
    }
    let changed = match &policy {
        Named::Aws(p) if p.name == ADMINISTRATOR_ACCESS => {
            if !attach && !client.query_one_cached("SELECT admin FROM users WHERE id = $1", &[&role]).await?.get::<_, bool>(0) {
                0
            } else {
                client.execute_cached("UPDATE users SET admin = $2 WHERE id = $1", &[&role, &attach]).await?
            }
        }
        Named::Aws(p) if attach => {
            client
                .execute_cached(
                    "INSERT INTO user_attached_policies (user_id, aws_policy) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                    &[&role, &p.name],
                )
                .await?;
            1
        }
        Named::Aws(p) => {
            client
                .execute_cached("DELETE FROM user_attached_policies WHERE user_id = $1 AND aws_policy = $2", &[&role, &p.name])
                .await?
        }
        Named::Own { path, name } => {
            let id = own(client, account, path, name)
                .await
                .map_err(|_| Refused::NoSuch(format!("Policy {arn} does not exist or is not attachable.")))?
                .id;
            if attach {
                client
                    .execute_cached(
                        "INSERT INTO user_attached_policies (user_id, policy_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                        &[&role, &id],
                    )
                    .await?;
                1
            } else {
                client
                    .execute_cached("DELETE FROM user_attached_policies WHERE user_id = $1 AND policy_id = $2", &[&role, &id])
                    .await?
            }
        }
    };
    if changed == 0 {
        return refused(Refused::NoSuch(format!("Policy {arn} was not found.")));
    }
    Ok(())
}

/// A policy ID as IAM shows one (`ANPA`, then 17 characters), from a
/// Cairn ID, or (Cairn's policies) from its name.
pub fn policy_id(id: Option<Uuid>, name: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = match id {
        Some(id) => u128::from_be_bytes(*id.as_bytes()),
        None => {
            let digest = ring::digest::digest(&ring::digest::SHA256, name.as_bytes());
            u128::from_be_bytes(digest.as_ref()[..16].try_into().unwrap())
        }
    };
    let tail: String = (0..17).map(|i| ALPHABET[((bits >> (5 * i)) & 31) as usize] as char).collect();
    format!("ANPA{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cairns_policies_parse() {
        for p in AWS_POLICIES {
            check_document(p.document).unwrap_or_else(|e| panic!("{}: {e}", p.name));
        }
    }

    #[test]
    fn arns_name_policies() {
        assert_eq!(named("arn:aws:iam::aws:policy/AmazonS3FullAccess", "123").unwrap(), Named::Aws(&AWS_POLICIES[1]));
        assert_eq!(named("arn:aws:iam::123:policy/mine", "123").unwrap(), Named::Own { path: "/".into(), name: "mine".into() });
        assert_eq!(
            named("arn:aws:iam::123:policy/a/b/mine", "123").unwrap(),
            Named::Own { path: "/a/b/".into(), name: "mine".into() }
        );
        // Another account's, or one that isn't there.
        assert!(named("arn:aws:iam::456:policy/theirs", "123").is_err());
        assert!(named("arn:aws:iam::aws:policy/AmazonEC2FullAccess", "123").is_err());
        assert!(named("arn:aws:iam::aws:policy/a/AmazonS3FullAccess", "123").is_err());
        assert!(named("nonsense", "123").is_err());
    }

    #[test]
    fn policy_ids_look_like_iams() {
        let id = policy_id(None, "AmazonS3FullAccess");
        assert!(id.starts_with("ANPA") && id.len() == 21);
        assert_eq!(id, policy_id(None, "AmazonS3FullAccess"));
        assert_ne!(id, policy_id(None, "AmazonS3ReadOnlyAccess"));
    }
}
