//! Grants: a user's `read`, `write` or `delete-version` on a bucket, as
//! managed policies (see `managed`) at `GRANTS_PATH`: `<bucket>-read`,
//! `<bucket>-write` and `<bucket>-delete-version` (with a suffix, if the
//! name is taken), each allowing what its permission does on the bucket and
//! its objects, attached to the users granted it. `cairn user grant` and
//! `revoke` (deprecated: the IAM API and the console's policy editor
//! replace them) attach and detach them, making them as needed; they're ordinary
//! policies, which IAM tools see and the console edits as any other.
//!
//! Grants used to be statements of the bucket's policy,
//! `CairnGrant<Permission>`, naming the users granted it, and before that
//! rows of `role_grants`. A Cairn moves any that are left into managed
//! policies as it starts (`convert`, `to_managed`): the same access within
//! the account, kept where IAM keeps it. Two kinds aren't, with a warning
//! each, so that no grant stops a Cairn from starting: an admin's, which is
//! dropped (AdministratorAccess allows everything anyway), and one its user
//! has no room for (IAM's quota of attached policies, `managed::MAX_ATTACHED`),
//! which stays in the bucket's policy, as `CairnKeptGrant<Permission>`: an
//! ordinary statement, which is never moved.

use std::collections::HashSet;

use deadpool_postgres::Object;
use serde_json::{Value, json};

use crate::{
    db::Cached,
    policy::{Kind, Policy},
    users::{Invalid, Permission},
};

/// How often a change is tried again, if the policy changed meanwhile.
const ATTEMPTS: usize = 20;

/// The bucket policy statements grants are: the ones to move (`Grant`), and
/// the ones kept, whose users have no room for their managed policies
/// (`Kept`).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Statement {
    Grant,
    Kept,
}

fn sid(statement: Statement, permission: Permission) -> &'static str {
    match (statement, permission) {
        (Statement::Grant, Permission::Read) => "CairnGrantRead",
        (Statement::Grant, Permission::Write) => "CairnGrantWrite",
        (Statement::Grant, Permission::DeleteVersion) => "CairnGrantDeleteVersion",
        (Statement::Kept, Permission::Read) => "CairnKeptGrantRead",
        (Statement::Kept, Permission::Write) => "CairnKeptGrantWrite",
        (Statement::Kept, Permission::DeleteVersion) => "CairnKeptGrantDeleteVersion",
    }
}

const PERMISSIONS: [Permission; 3] = [
    Permission::Read,
    Permission::Write,
    Permission::DeleteVersion,
];

fn permission_of(sid: &str) -> Option<Permission> {
    PERMISSIONS
        .into_iter()
        .find(|p| self::sid(Statement::Grant, *p) == sid)
}

/// A user's ARN.
pub fn user_arn(account: &str, user: &str) -> String {
    format!("arn:aws:iam::{account}:user/{user}")
}

/// A statement's principals (`AWS`): one, or a list.
fn principals(statement: &Value) -> Vec<String> {
    match &statement["Principal"]["AWS"] {
        Value::String(one) => vec![one.clone()],
        Value::Array(many) => many
            .iter()
            .filter_map(|p| p.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// The statements of a policy's JSON (one, or a list).
fn statements(policy: &Value) -> Vec<Value> {
    match &policy["Statement"] {
        Value::Array(list) => list.clone(),
        Value::Object(_) => vec![policy["Statement"].clone()],
        _ => Vec::new(),
    }
}

/// The grants a bucket's policy holds: whom (by ARN) each permission is
/// granted to.
pub fn in_policy(text: &str) -> Vec<(String, Permission)> {
    let Ok(policy) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    statements(&policy)
        .iter()
        .filter_map(|s| Some((s, permission_of(s["Sid"].as_str()?)?)))
        .flat_map(|(s, permission)| principals(s).into_iter().map(move |arn| (arn, permission)))
        .collect()
}

/// `policy` (a bucket's, or `None`) with each of `changes` made: granting
/// (`true`) or revoking a permission of a user (by ARN). The new policy, as
/// S3 keeps it (normalized), or `None` if nothing is left of it.
#[cfg(test)]
pub fn changed(
    policy: Option<&str>,
    bucket: &str,
    changes: &[(String, Permission, bool)],
) -> anyhow::Result<Option<String>> {
    let changes: Vec<_> = changes
        .iter()
        .map(|(arn, permission, grant)| (Statement::Grant, arn.clone(), *permission, *grant))
        .collect();
    Ok(edited(policy, bucket, &changes)?)
}

/// A change to a bucket policy's grants: to a statement, of a user (by
/// ARN), of a permission, granting (`true`) or revoking it.
type Change = (Statement, String, Permission, bool);

/// A bucket policy that its grants' changes leave unfit to be one (too
/// large, or it didn't parse to begin with).
#[derive(Debug)]
struct Unfit(String);

impl std::fmt::Display for Unfit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Unfit {}

/// `changed`, of any statements.
fn edited(policy: Option<&str>, bucket: &str, changes: &[Change]) -> Result<Option<String>, Unfit> {
    let mut document = match policy {
        Some(text) => serde_json::from_str::<Value>(text)
            .map_err(|e| Unfit(format!("bucket {bucket:?}'s policy doesn't parse: {e}")))?,
        None => json!({ "Version": "2012-10-17", "Statement": [] }),
    };
    let mut list = statements(&document);
    for statement in [Statement::Grant, Statement::Kept] {
        for permission in PERMISSIONS {
            let sid = sid(statement, permission);
            let at = list.iter().position(|s| s["Sid"].as_str() == Some(sid));
            let mut users = at.map(|i| principals(&list[i])).unwrap_or_default();
            let before = users.clone();
            for (_, arn, _, grant) in changes
                .iter()
                .filter(|(s, _, p, _)| *s == statement && *p == permission)
            {
                users.retain(|u| u != arn);
                if *grant {
                    users.push(arn.clone());
                }
            }
            if users == before && at.is_some() {
                continue;
            }
            let statement = json!({
                "Sid": sid,
                "Effect": "Allow",
                "Principal": { "AWS": users },
                "Action": crate::s3::actions::grant_actions(permission),
                "Resource": [format!("arn:aws:s3:::{bucket}"), format!("arn:aws:s3:::{bucket}/*")],
            });
            match (at, users.is_empty()) {
                (Some(i), true) => {
                    list.remove(i);
                }
                (Some(i), false) => list[i] = statement,
                (None, true) => {}
                (None, false) => list.push(statement),
            }
        }
    }
    if list.is_empty() {
        return Ok(None);
    }
    document["Statement"] = Value::Array(list);
    let text = document.to_string();
    let policy = Policy::parse(&text, Kind::Bucket(bucket)).map_err(|e| {
        Unfit(format!(
            "a bucket policy with grants doesn't parse ({}: {})",
            e.code, e.message
        ))
    })?;
    Ok(Some(policy.normalized().to_owned()))
}

/// Applies `changes` to `bucket`'s policy, by compare-and-swap. Whether the
/// bucket exists.
async fn apply(client: &Object, bucket: &str, changes: &[Change]) -> anyhow::Result<bool> {
    for _ in 0..ATTEMPTS {
        let Some(row) = client
            .query_opt_cached("SELECT policy FROM buckets WHERE name = $1", &[&bucket])
            .await?
        else {
            return Ok(false);
        };
        let old: Option<String> = row.get(0);
        let new = edited(old.as_deref(), bucket, changes)?;
        if new == old {
            return Ok(true);
        }
        let swapped = client
            .execute_cached(
                "UPDATE buckets SET policy = $3 WHERE name = $1 AND policy IS NOT DISTINCT FROM $2",
                &[&bucket, &old, &new],
            )
            .await?;
        if swapped == 1 {
            return Ok(true);
        }
    }
    Err(crate::Contended(format!("changing the grants of bucket {bucket:?}")).into())
}

/// The buckets whose policies name user `id`: as ListBuckets lists them to
/// a user not allowed `s3:ListAllMyBuckets` (as MinIO does).
pub async fn visible(client: &Object, id: uuid::Uuid) -> anyhow::Result<HashSet<String>> {
    let rows = client
        .query_cached(
            "SELECT name FROM buckets b
             WHERE EXISTS (SELECT 1 FROM jsonb_each_text(b.policy_principals) p WHERE p.value = $1)",
            &[&id.to_string()],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}

/// Moves the grants left in `role_grants` (from before they were bucket
/// policies) into managed policies (see `move_one`), bucket by bucket, then
/// deletes the bucket's rows (locked in the lock protocol's order, G). Safe
/// to run on several nodes at once, and again. The number of grants moved.
pub async fn convert(client: &Object) -> anyhow::Result<usize> {
    let rows = client
        .query_cached(
            "SELECT g.bucket, g.role, g.permission, r.account_id
             FROM role_grants g JOIN users r ON r.name = g.role
             -- From before accounts: the first tenant account's users.
             WHERE r.account_id = (SELECT id FROM accounts WHERE management)
             ORDER BY g.bucket, g.role, g.permission",
            &[],
        )
        .await?;
    let mut moved = 0;
    let mut at = 0;
    while at < rows.len() {
        let bucket: String = rows[at].get(0);
        let mut kept = Vec::new();
        while at < rows.len() && rows[at].get::<_, String>(0) == bucket {
            let (user, permission, account): (String, String, String) =
                (rows[at].get(1), rows[at].get(2), rows[at].get(3));
            let permission = Permission::from_db(&permission)?;
            match move_one(client, &account, &user, &bucket, permission).await? {
                Some(Moved::Kept) => {
                    kept.push((Statement::Kept, user_arn(&account, &user), permission, true))
                }
                Some(Moved::Attached) => moved += 1,
                Some(Moved::Dropped) | None => {}
            }
            at += 1;
        }
        if !kept.is_empty() {
            keep(client, &bucket, &[], &kept).await?;
            moved += kept.len();
        }
        client
            .execute_cached(
                "WITH l AS (SELECT ctid FROM role_grants WHERE bucket = $1
                            ORDER BY role, bucket, permission FOR UPDATE)
                 DELETE FROM role_grants WHERE ctid IN (SELECT ctid FROM l)",
                &[&bucket],
            )
            .await?;
    }
    Ok(moved)
}

/// What became of a grant `move_one` moved.
#[derive(Debug, PartialEq)]
enum Moved {
    /// Its managed policy is attached to its user.
    Attached,
    /// Its user is an admin: it's gone.
    Dropped,
    /// Its user has no room for its managed policy: it's to stay in the
    /// bucket's policy (`Statement::Kept`).
    Kept,
}

/// Moves user `user`'s grant of `permission` on `bucket` into its managed
/// policy (see `change`), warning if it can't be: an admin's is dropped
/// (AdministratorAccess allows everything already, and the policy would only
/// take one of the user's attached policies), and one its user has no room
/// for is to be kept. `None` if there's no such user.
async fn move_one(
    client: &Object,
    account: &str,
    user: &str,
    bucket: &str,
    permission: Permission,
) -> anyhow::Result<Option<Moved>> {
    use crate::managed::Refused;
    let Some(row) = client
        .query_opt_cached(
            "SELECT admin FROM users WHERE account_id = $1 AND lower(name) = lower($2)",
            &[&account, &user],
        )
        .await?
    else {
        return Ok(None);
    };
    let what = format!(
        "user {user:?}'s grant of {} on bucket {bucket:?}",
        permission.as_str()
    );
    if row.get::<_, bool>(0) {
        eprintln!("warning: dropped {what}: the user is an admin, allowed everything anyway");
        return Ok(Some(Moved::Dropped));
    }
    match change(client, account, user, bucket, &[permission], true).await {
        Ok(()) => Ok(Some(Moved::Attached)),
        Err(e) if matches!(e.downcast_ref::<Refused>(), Some(Refused::Limit(_))) => {
            eprintln!(
                "warning: kept {what} in the bucket's policy, as statement {}: \
                 the user has {} managed policies attached already, IAM's most",
                sid(Statement::Kept, permission),
                crate::managed::MAX_ATTACHED
            );
            Ok(Some(Moved::Kept))
        }
        Err(e) => Err(e),
    }
}

/// Applies `changes` and `kept` (see `Moved::Kept`) to `bucket`'s policy;
/// if the kept grants don't fit in it, `changes` alone, warning that they're
/// dropped.
async fn keep(
    client: &Object,
    bucket: &str,
    changes: &[Change],
    kept: &[Change],
) -> anyhow::Result<()> {
    if kept.is_empty() {
        apply(client, bucket, changes).await?;
        return Ok(());
    }
    let all: Vec<_> = changes.iter().chain(kept).cloned().collect();
    match apply(client, bucket, &all).await {
        Ok(_) => Ok(()),
        Err(e) if e.downcast_ref::<Unfit>().is_some() => {
            for (_, arn, permission, _) in kept {
                eprintln!(
                    "warning: dropped {arn}'s grant of {} on bucket {bucket:?}: \
                     the user has no room for its managed policy, and the bucket's policy can't keep it: {e}",
                    permission.as_str()
                );
            }
            apply(client, bucket, changes).await?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Where grants' managed policies are: a path of Cairn's own. IAM decides
/// who may change a policy by its path, and nothing gives anyone but the
/// account's admins `policy/cairn/*`, so a grant's policy is only the account's admins' to
/// change (who may do anything anyway). A policy elsewhere, of any name, is
/// never taken for a grant's: anyone allowed to make policies under their
/// own path could make one in advance, have it attached by a grant, and
/// change it later.
pub const GRANTS_PATH: &str = "/cairn/grants/";

/// The managed policy a grant of `permission` on `bucket` is: the name it
/// gets (unless the account has a policy of that name already: names are
/// unique in an account, whatever their paths), and its document: what
/// `permission` allows on the bucket and its objects.
pub fn policy_for(bucket: &str, permission: Permission) -> (String, String) {
    let name = format!("{bucket}-{}", permission.as_str());
    let document = json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": crate::s3::actions::grant_actions(permission),
            "Resource": [format!("arn:aws:s3:::{bucket}"), format!("arn:aws:s3:::{bucket}/*")],
        }],
    });
    (name, document.to_string())
}

/// The tags of a grant's policy, by which it's found: the bucket and
/// permission. Its document isn't how: it grows with the bucket
/// configurations Cairn knows (which a grant may read).
fn tags_for(bucket: &str, permission: Permission) -> Vec<(String, String)> {
    vec![
        (BUCKET_TAG.to_owned(), bucket.to_owned()),
        (PERMISSION_TAG.to_owned(), permission.as_str().to_owned()),
    ]
}

/// The tags naming a grant's bucket and permission.
const BUCKET_TAG: &str = "cairn:grant-bucket";
const PERMISSION_TAG: &str = "cairn:grant-permission";

/// The account's policy for a grant of `permission` on `bucket`: one at
/// `GRANTS_PATH` tagged so (the oldest, if there are several), its document
/// brought up to date if it's older; its ARN.
async fn find(
    client: &Object,
    account: &str,
    bucket: &str,
    permission: Permission,
) -> anyhow::Result<Option<String>> {
    let row = client
        .query_opt_cached(
            "SELECT m.name, m.document FROM managed_policies m
             WHERE m.account_id = $1 AND m.path = $2
               AND EXISTS (SELECT 1 FROM managed_policy_tags t WHERE t.policy_id = m.id AND t.key = $3 AND t.value = $4)
               AND EXISTS (SELECT 1 FROM managed_policy_tags t WHERE t.policy_id = m.id AND t.key = $5 AND t.value = $6)
             ORDER BY m.created_at, m.name LIMIT 1",
            &[&account, &GRANTS_PATH, &BUCKET_TAG, &bucket, &PERMISSION_TAG, &permission.as_str()],
        )
        .await?;
    let Some(row) = row else { return Ok(None) };
    let (name, document): (String, String) = (row.get(0), row.get(1));
    let (_, current) = policy_for(bucket, permission);
    if document != current {
        crate::managed::update(client, account, &name, &current).await?;
    }
    Ok(Some(crate::managed::arn(account, GRANTS_PATH, &name)))
}

/// The ARNs of the policies grants of `permission` on `bucket` were before
/// they were at `GRANTS_PATH`: at `/`, named `<bucket>-<permission>` (or,
/// that being taken, `…-grant`), with the description grants had. (Only the
/// account's admins may make policies at `/`.) They stay where they are;
/// granting again doesn't attach another, and revoking detaches them.
async fn earlier(
    client: &Object,
    account: &str,
    bucket: &str,
    permission: Permission,
) -> anyhow::Result<Vec<String>> {
    let (name, _) = policy_for(bucket, permission);
    let rows = client
        .query_cached(
            "SELECT name FROM managed_policies
             WHERE account_id = $1 AND path = '/' AND name = ANY($2) AND description = $3 ORDER BY name",
            &[&account, &vec![name.clone(), format!("{name}-grant")], &description(bucket, permission)],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| crate::managed::arn(account, "/", r.get(0)))
        .collect())
}

fn description(bucket: &str, permission: Permission) -> String {
    format!("{} on bucket {bucket} (a grant)", permission.as_str())
}

/// The ARN of the account's policy for a grant of `permission` on
/// `bucket` (see `find`), made if there's none.
async fn grant_policy(
    client: &Object,
    account: &str,
    bucket: &str,
    permission: Permission,
) -> anyhow::Result<String> {
    use crate::managed::{self, Refused};
    let (name, document) = policy_for(bucket, permission);
    for attempt in 0..ATTEMPTS {
        if let Some(arn) = find(client, account, bucket, permission).await? {
            return Ok(arn);
        }
        // Its name, or, that being taken (by another node's grant meanwhile,
        // or any policy anywhere), the name and a random suffix.
        let name = match attempt {
            0 => name.clone(),
            _ => format!("{name}-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]),
        };
        let tags = tags_for(bucket, permission);
        match managed::create_tagged(
            client,
            account,
            &name,
            GRANTS_PATH,
            &document,
            &description(bucket, permission),
            &tags,
        )
        .await
        {
            Ok(policy) => return Ok(policy.arn(account)),
            Err(e) if matches!(e.downcast_ref::<Refused>(), Some(Refused::Exists(_))) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(crate::Contended(format!("making the policy of a grant on bucket {bucket:?}")).into())
}

/// Grants (`grant`) or revokes `permissions` on `bucket` to user `user` of
/// `account`: attaches or detaches their managed policies (see
/// `grant_policy`, `earlier`). The bucket must be the account's.
pub async fn change(
    client: &Object,
    account: &str,
    user: &str,
    bucket: &str,
    permissions: &[Permission],
    grant: bool,
) -> anyhow::Result<()> {
    use crate::managed::{self, Refused};
    let Some(row) = client
        .query_opt_cached("SELECT account_id FROM buckets WHERE name = $1", &[&bucket])
        .await?
    else {
        return Err(Invalid(format!("no bucket named {bucket:?}; create it first")).into());
    };
    if row.get::<_, String>(0) != account {
        return Err(Invalid(format!("{bucket:?} is another account's bucket")).into());
    }
    let attached: Vec<String> = managed::attached(client, account, user)
        .await?
        .into_iter()
        .map(|a| a.arn)
        .collect();
    for permission in permissions {
        let earlier = earlier(client, account, bucket, *permission).await?;
        if grant {
            // Granted before grants were at `GRANTS_PATH`: it is.
            if earlier.iter().any(|arn| attached.contains(arn)) {
                continue;
            }
            let arn = grant_policy(client, account, bucket, *permission).await?;
            managed::attach(client, account, user, &arn, true).await?;
            continue;
        }
        let current = find(client, account, bucket, *permission).await?;
        for arn in current
            .iter()
            .chain(&earlier)
            .filter(|arn| attached.contains(arn))
        {
            match managed::attach(client, account, user, arn, false).await {
                Ok(()) => {}
                // Detached meanwhile.
                Err(e) if matches!(e.downcast_ref::<Refused>(), Some(Refused::NoSuch(_))) => {}
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}

/// Moves the grants left in buckets' policies (`CairnGrant<Permission>`
/// statements) into managed policies attached to their users (see
/// `move_one`), bucket by bucket: the policies are made and attached, then
/// the statements leave the bucket's policy (a compare-and-swap), but for
/// the grants kept, which move to statements of their own. Safe to run on
/// several nodes at once, and again. Users of other accounts, which no grant
/// could name, are dropped from them. The number of grants moved.
pub async fn to_managed(client: &Object) -> anyhow::Result<usize> {
    let rows = client
        .query_cached(
            "SELECT b.name, b.policy, b.account_id FROM buckets b WHERE b.policy LIKE '%\"CairnGrant%' ORDER BY b.name",
            &[],
        )
        .await?;
    let mut moved = 0;
    for row in rows {
        let (bucket, policy, account): (String, String, String) =
            (row.get(0), row.get(1), row.get(2));
        let prefix = user_arn(&account, "");
        let grants = in_policy(&policy);
        let mut kept = Vec::new();
        for (arn, permission) in &grants {
            let Some(user) = arn.strip_prefix(&prefix) else {
                continue;
            };
            match move_one(client, &account, user, &bucket, *permission).await? {
                Some(Moved::Kept) => kept.push((Statement::Kept, arn.clone(), *permission, true)),
                Some(Moved::Attached) => moved += 1,
                Some(Moved::Dropped) | None => {}
            }
        }
        moved += kept.len();
        let revoked: Vec<_> = grants
            .into_iter()
            .map(|(arn, permission)| (Statement::Grant, arn, permission, false))
            .collect();
        keep(client, &bucket, &revoked, &kept).await?;
    }
    Ok(moved)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "arn:aws:iam::123456789012:user/alice";
    const BOB: &str = "arn:aws:iam::123456789012:user/bob";

    #[test]
    fn grants_are_statements_of_their_own() {
        let p = changed(None, "b", &[(ALICE.into(), Permission::Read, true)])
            .unwrap()
            .unwrap();
        assert_eq!(in_policy(&p), [(ALICE.to_owned(), Permission::Read)]);
        // Kept as S3 keeps policies, and valid as a bucket policy.
        Policy::parse(&p, Kind::Bucket("b")).unwrap();

        // Others' statements stay as they are.
        let mine = r#"{"Version":"2012-10-17","Statement":[{"Sid":"Public","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/pub/*"}]}"#;
        let p = changed(
            Some(mine),
            "b",
            &[
                (ALICE.into(), Permission::Write, true),
                (BOB.into(), Permission::Write, true),
            ],
        )
        .unwrap()
        .unwrap();
        assert!(p.contains(r#""Sid":"Public""#), "{p}");
        let mut grants = in_policy(&p);
        grants.sort_by_key(|(arn, _)| arn.clone());
        assert_eq!(
            grants,
            [
                (ALICE.to_owned(), Permission::Write),
                (BOB.to_owned(), Permission::Write)
            ]
        );

        // Revoking the last of a statement removes it; the rest stays.
        let p = changed(
            Some(&p),
            "b",
            &[
                (ALICE.into(), Permission::Write, false),
                (BOB.into(), Permission::Write, false),
            ],
        )
        .unwrap()
        .unwrap();
        assert!(in_policy(&p).is_empty());
        assert!(p.contains(r#""Sid":"Public""#));
        // And a policy of grants only goes once they're all revoked.
        let p = changed(None, "b", &[(ALICE.into(), Permission::Read, true)]).unwrap();
        assert_eq!(
            changed(
                p.as_deref(),
                "b",
                &[(ALICE.into(), Permission::Read, false)]
            )
            .unwrap(),
            None
        );
        // Granting twice changes nothing.
        let p = changed(None, "b", &[(ALICE.into(), Permission::Read, true)]).unwrap();
        assert_eq!(
            changed(p.as_deref(), "b", &[(ALICE.into(), Permission::Read, true)]).unwrap(),
            p
        );
    }
}

#[cfg(test)]
mod documents {
    use super::*;

    /// A grant's document is still what grants allowed (the actions of
    /// each, in order: a configuration Cairn learns adds its read to all
    /// three).
    #[test]
    fn grants_allow_what_they_did() {
        let reads = "\"s3:GetBucketVersioning\",\"s3:GetEncryptionConfiguration\",\"s3:GetLifecycleConfiguration\",\"s3:GetBucketCORS\",\"s3:GetBucketTagging\",\"s3:GetBucketPublicAccessBlock\",\"s3:GetBucketAcl\",\"s3:GetBucketOwnershipControls\",\"s3:GetBucketLocation\",\"s3:GetBucketObjectLockConfiguration\",\"s3:GetBucketWebsite\",\"s3:GetReplicationConfiguration\",\"s3:GetAccelerateConfiguration\",\"s3:GetBucketRequestPayment\",\"s3:GetBucketLogging\",\"s3:GetBucketNotification\"";
        let document = |actions: &str| {
            format!(
                r#"{{"Statement":[{{"Action":[{actions},{reads}],"Effect":"Allow","Resource":["arn:aws:s3:::b","arn:aws:s3:::b/*"]}}],"Version":"2012-10-17"}}"#
            )
        };
        let read = "\"s3:GetObject\",\"s3:GetObjectVersion\",\"s3:GetObjectAttributes\",\"s3:GetObjectVersionAttributes\",\"s3:GetObjectTagging\",\"s3:GetObjectVersionTagging\",\"s3:GetObjectAcl\",\"s3:GetObjectVersionAcl\",\"s3:GetObjectRetention\",\"s3:GetObjectLegalHold\",\"s3:ListBucket\",\"s3:ListBucketVersions\",\"s3:ListBucketMultipartUploads\",\"s3:ListMultipartUploadParts\"";
        let write = "\"s3:PutObject\",\"s3:PutObjectTagging\",\"s3:PutObjectVersionTagging\",\"s3:DeleteObject\",\"s3:DeleteObjectTagging\",\"s3:DeleteObjectVersionTagging\",\"s3:PutObjectAcl\",\"s3:PutObjectVersionAcl\",\"s3:AbortMultipartUpload\",\"s3:ListBucketMultipartUploads\",\"s3:ListMultipartUploadParts\"";
        assert_eq!(
            policy_for("b", Permission::Read),
            ("b-read".to_owned(), document(read))
        );
        assert_eq!(
            policy_for("b", Permission::Write),
            ("b-write".to_owned(), document(write))
        );
        assert_eq!(
            policy_for("b", Permission::DeleteVersion),
            (
                "b-delete-version".to_owned(),
                document("\"s3:DeleteObjectVersion\"")
            )
        );
    }
}
