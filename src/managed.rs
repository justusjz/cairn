//! Managed policies, as IAM's: identity policies that are documents of their
//! own, attached to any number of users. There are two kinds:
//!
//! - **Cairn's**, which have AWS's names and ARNs
//!   (`arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess`), and say what AWS's
//!   say, so that policies and tools written for AWS work unchanged. They
//!   can't be changed. AdministratorAccess is kept as a user's admin flag
//!   (which older nodes read); the others as attachments.
//! - **An account's own** (`arn:aws:iam::<account>:policy/<name>`), which its
//!   admins make, change and delete. IAM keeps up to five versions of one;
//!   Cairn keeps the default, numbered as IAM numbers versions (`v1`, ...).
//!
//! A user's attached policies count as its identity policies, alongside its
//! inline ones (see `roles::Principal`, `s3::access`). Limits are IAM's: a
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
    /// MalformedPolicyDocument (400).
    Malformed(String),
    /// InvalidInput (400).
    Invalid(String),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::NoSuch(m) | Refused::Exists(m) | Refused::Conflict(m) | Refused::Limit(m) => f.write_str(m),
            Refused::Malformed(m) | Refused::Invalid(m) => f.write_str(m),
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

/// An account's policy's ARN.
pub fn arn(account: &str, name: &str) -> String {
    format!("arn:aws:iam::{account}:policy/{name}")
}

/// Cairn's policy named `name`.
pub fn aws(name: &str) -> Option<&'static AwsPolicy> {
    AWS_POLICIES.iter().find(|p| p.name == name)
}

/// A managed policy, by its ARN.
#[derive(Debug, PartialEq)]
pub enum Named {
    Aws(&'static AwsPolicy),
    /// One of the account's own, by name.
    Own(String),
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
/// the account's own (another account's are none it may attach).
pub fn named(arn: &str, account: &str) -> anyhow::Result<Named> {
    let no_such = || Refused::NoSuch(format!("Policy {arn} does not exist or is not attachable."));
    let Some(rest) = arn.strip_prefix("arn:aws:iam::") else { return refused(Refused::Invalid(format!("ARN {arn} is not valid."))) };
    let Some((owner, name)) = rest.split_once(":policy/") else { return refused(Refused::Invalid(format!("ARN {arn} is not valid."))) };
    // No paths: a name has no `/`.
    if name.contains('/') {
        return refused(no_such());
    }
    match owner {
        "aws" => aws(name).map(Named::Aws).ok_or_else(|| no_such().into()),
        owner if owner == account => Ok(Named::Own(name.to_owned())),
        _ => refused(no_such()),
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
    pub description: String,
    pub document: String,
    /// Its default version's number (`v1`, ...).
    pub version: i32,
    pub updated_at: f64,
    /// The users it's attached to, by name.
    pub users: Vec<String>,
}

const COLUMNS: &str = "m.id, m.name, m.description, m.document, m.version,
     extract(epoch FROM m.updated_at)::float8,
     ARRAY(SELECT r.name FROM role_attached_policies x JOIN roles r ON r.id = x.role_id
           WHERE x.policy_id = m.id ORDER BY r.name)";

fn managed_of(row: &tokio_postgres::Row) -> Managed {
    Managed {
        id: row.get(0),
        name: row.get(1),
        description: row.get(2),
        document: row.get(3),
        version: row.get(4),
        updated_at: row.get(5),
        users: row.get(6),
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
        None => refused(Refused::NoSuch(format!("Policy {} was not found.", arn(account, name)))),
    }
}

/// Makes the account's managed policy `name`.
pub async fn create(client: &Object, account: &str, name: &str, document: &str, description: &str) -> anyhow::Result<Managed> {
    check_name(name)?;
    check_document(document)?;
    if description.len() > MAX_DESCRIPTION {
        return refused(Refused::Invalid(format!("a policy's description is at most {MAX_DESCRIPTION} characters")));
    }
    crate::roles::refuse_operator(client, account, "managed policies").await?;
    let made = client
        .execute_cached(
            "INSERT INTO managed_policies (account_id, name, document, description) VALUES ($1, $2, $3, $4)
             ON CONFLICT DO NOTHING",
            &[&account, &name, &document, &description],
        )
        .await?;
    if made == 0 {
        return refused(Refused::Exists(format!("A policy called {name} already exists. Duplicate names are not allowed.")));
    }
    get(client, account, name).await
}

/// Replaces the document of the account's managed policy `name` (its
/// default version): the new version's number.
pub async fn update(client: &Object, account: &str, name: &str, document: &str) -> anyhow::Result<i32> {
    check_document(document)?;
    let row = client
        .query_opt_cached(
            "UPDATE managed_policies SET document = $3, version = version + 1, updated_at = now()
             WHERE account_id = $1 AND name = $2 RETURNING version",
            &[&account, &name, &document],
        )
        .await?;
    match row {
        Some(row) => Ok(row.get(0)),
        None => refused(Refused::NoSuch(format!("Policy {} was not found.", arn(account, name)))),
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
        return refused(Refused::NoSuch(format!("Policy {} was not found.", arn(account, name))));
    }
    Ok(())
}

/// Deletes the account's managed policy `name`, unless it's attached.
pub async fn delete(client: &Object, account: &str, name: &str) -> anyhow::Result<()> {
    let policy = get(client, account, name).await?;
    if !policy.users.is_empty() {
        return refused(Refused::Conflict("Cannot delete a policy attached to entities.".into()));
    }
    let deleted = client
        .execute_cached(
            "DELETE FROM managed_policies m WHERE m.id = $1
             AND NOT EXISTS (SELECT 1 FROM role_attached_policies x WHERE x.policy_id = m.id)",
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
            "SELECT r.id, NULL::text, 'AdministratorAccess' FROM roles r WHERE r.account_id = $1 AND r.admin
             UNION ALL
             SELECT r.id, NULL, x.aws_policy FROM role_attached_policies x JOIN roles r ON r.id = x.role_id
             WHERE r.account_id = $1 AND x.aws_policy IS NOT NULL
             UNION ALL
             SELECT r.id, m.account_id, m.name FROM role_attached_policies x JOIN roles r ON r.id = x.role_id
             JOIN managed_policies m ON m.id = x.policy_id WHERE r.account_id = $1
             ORDER BY 1, 2 NULLS FIRST, 3",
            &[&account],
        )
        .await?;
    let mut all: HashMap<Uuid, Vec<Attached>> = HashMap::new();
    for row in rows {
        let (user, owner, name): (Uuid, Option<String>, String) = (row.get(0), row.get(1), row.get(2));
        let arn = match &owner {
            Some(owner) => arn(owner, &name),
            None => aws_arn(&name),
        };
        all.entry(user).or_default().push(Attached { name, arn });
    }
    Ok(all)
}

/// The managed policies attached to user `user` of `account`.
pub async fn attached(client: &Object, account: &str, user: &str) -> anyhow::Result<Vec<Attached>> {
    let id = crate::roles::id_of(client, account, user).await?;
    Ok(attached_all(client, account).await?.remove(&id).unwrap_or_default())
}

/// Attaches (`attach`) or detaches the policy `arn` to user `user` of
/// `account`.
pub async fn attach(client: &Object, account: &str, user: &str, arn: &str, attach: bool) -> anyhow::Result<()> {
    let policy = named(arn, account)?;
    let role = crate::roles::id_of(client, account, user)
        .await
        .map_err(|_| Refused::NoSuch(format!("The user with name {user} cannot be found.")))?;
    if attach {
        crate::roles::refuse_operator(client, account, "policies").await?;
        let count: i64 = client
            .query_one_cached(
                "SELECT (SELECT count(*) FROM role_attached_policies WHERE role_id = $1)
                      + (SELECT count(*) FROM roles WHERE id = $1 AND admin)",
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
            if !attach && !client.query_one_cached("SELECT admin FROM roles WHERE id = $1", &[&role]).await?.get::<_, bool>(0) {
                0
            } else {
                client.execute_cached("UPDATE roles SET admin = $2 WHERE id = $1", &[&role, &attach]).await?
            }
        }
        Named::Aws(p) if attach => {
            client
                .execute_cached(
                    "INSERT INTO role_attached_policies (role_id, aws_policy) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                    &[&role, &p.name],
                )
                .await?;
            1
        }
        Named::Aws(p) => {
            client
                .execute_cached("DELETE FROM role_attached_policies WHERE role_id = $1 AND aws_policy = $2", &[&role, &p.name])
                .await?
        }
        Named::Own(name) => {
            let id = get(client, account, name).await?.id;
            if attach {
                client
                    .execute_cached(
                        "INSERT INTO role_attached_policies (role_id, policy_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                        &[&role, &id],
                    )
                    .await?;
                1
            } else {
                client
                    .execute_cached("DELETE FROM role_attached_policies WHERE role_id = $1 AND policy_id = $2", &[&role, &id])
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
        assert_eq!(named("arn:aws:iam::123:policy/mine", "123").unwrap(), Named::Own("mine".into()));
        // Another account's, or one that isn't there.
        assert!(named("arn:aws:iam::456:policy/theirs", "123").is_err());
        assert!(named("arn:aws:iam::aws:policy/AmazonEC2FullAccess", "123").is_err());
        assert!(named("arn:aws:iam::123:policy/a/b", "123").is_err());
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
