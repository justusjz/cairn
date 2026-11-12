//! Grants: a user's `read`, `write` or `delete-version` on a bucket, kept as
//! statements of the bucket's policy, as AWS people share a bucket with a
//! few users (see `plans/policies.md`, "Accounts, root users and logins").
//! So a grant goes with its bucket (a bucket re-created under an old name
//! starts with no access), no user runs into a size limit however many
//! buckets it's granted, and what's in effect is what GetBucketPolicy shows,
//! to any S3 or IAM tool.
//!
//! Each permission is one statement, `CairnGrant<Permission>`, naming the
//! users granted it; the dashboard and console show those as grants, and
//! leave the policy's other statements alone. A change is a compare-and-swap
//! of the bucket's policy (an UPDATE whose condition is on the bucket's row
//! only, re-checked under its lock: F2), retried if another got in first.
//!
//! Grants used to be rows of `role_grants`; a Cairn moves any that are left
//! into their buckets' policies as it starts (`convert`).

use std::collections::HashSet;

use deadpool_postgres::Object;
use serde_json::{Value, json};

use crate::{
    db::Cached,
    policy::{Kind, Policy},
    roles::{Invalid, Permission},
};

/// How often a change is tried again, if the policy changed meanwhile.
const ATTEMPTS: usize = 20;

fn sid(permission: Permission) -> &'static str {
    match permission {
        Permission::Read => "CairnGrantRead",
        Permission::Write => "CairnGrantWrite",
        Permission::DeleteVersion => "CairnGrantDeleteVersion",
    }
}

fn permission_of(sid: &str) -> Option<Permission> {
    [Permission::Read, Permission::Write, Permission::DeleteVersion].into_iter().find(|p| self::sid(*p) == sid)
}

/// A user's ARN.
pub fn user_arn(account: &str, user: &str) -> String {
    format!("arn:aws:iam::{account}:user/{user}")
}

/// A statement's principals (`AWS`): one, or a list.
fn principals(statement: &Value) -> Vec<String> {
    match &statement["Principal"]["AWS"] {
        Value::String(one) => vec![one.clone()],
        Value::Array(many) => many.iter().filter_map(|p| p.as_str().map(str::to_owned)).collect(),
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
    let Ok(policy) = serde_json::from_str::<Value>(text) else { return Vec::new() };
    statements(&policy)
        .iter()
        .filter_map(|s| Some((s, permission_of(s["Sid"].as_str()?)?)))
        .flat_map(|(s, permission)| principals(s).into_iter().map(move |arn| (arn, permission)))
        .collect()
}

/// `policy` (a bucket's, or `None`) with each of `changes` made: granting
/// (`true`) or revoking a permission of a user (by ARN). The new policy, as
/// S3 keeps it (normalized), or `None` if nothing is left of it.
pub fn changed(policy: Option<&str>, bucket: &str, changes: &[(String, Permission, bool)]) -> anyhow::Result<Option<String>> {
    let mut document = match policy {
        Some(text) => serde_json::from_str::<Value>(text)?,
        None => json!({ "Version": "2012-10-17", "Statement": [] }),
    };
    let mut list = statements(&document);
    for permission in [Permission::Read, Permission::Write, Permission::DeleteVersion] {
        let at = list.iter().position(|s| s["Sid"].as_str() == Some(sid(permission)));
        let mut users = at.map(|i| principals(&list[i])).unwrap_or_default();
        let before = users.clone();
        for (arn, _, grant) in changes.iter().filter(|(_, p, _)| *p == permission) {
            users.retain(|u| u != arn);
            if *grant {
                users.push(arn.clone());
            }
        }
        if users == before && at.is_some() {
            continue;
        }
        let statement = json!({
            "Sid": sid(permission),
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
    if list.is_empty() {
        return Ok(None);
    }
    document["Statement"] = Value::Array(list);
    let text = document.to_string();
    let policy = Policy::parse(&text, Kind::Bucket(bucket))
        .map_err(|e| anyhow::anyhow!("a bucket policy with grants doesn't parse ({}: {})", e.code, e.message))?;
    Ok(Some(policy.normalized().to_owned()))
}

/// Makes `changes` to `bucket`'s grants: (user of `account`, permission,
/// grant or revoke). The bucket must be of that account (another account's
/// users are named by its policy itself, for cross-account access).
pub async fn change(client: &Object, account: &str, bucket: &str, changes: &[(&str, Permission, bool)]) -> anyhow::Result<()> {
    let Some(row) = client.query_opt_cached("SELECT account_id FROM buckets WHERE name = $1", &[&bucket]).await? else {
        return Err(Invalid(format!("no bucket named {bucket:?}; create it first")).into());
    };
    let owner: String = row.get(0);
    if owner != account && changes.iter().any(|(_, _, grant)| *grant) {
        return Err(Invalid(format!("{bucket:?} is another account's bucket")).into());
    }
    let mut arns = Vec::new();
    for (user, permission, grant) in changes {
        arns.push((user_arn(account, user), *permission, *grant));
    }
    apply(client, bucket, &arns).await?;
    Ok(())
}

/// Applies `changes` to `bucket`'s policy, by compare-and-swap. Whether the
/// bucket exists.
async fn apply(client: &Object, bucket: &str, changes: &[(String, Permission, bool)]) -> anyhow::Result<bool> {
    for _ in 0..ATTEMPTS {
        let Some(row) = client.query_opt_cached("SELECT policy FROM buckets WHERE name = $1", &[&bucket]).await? else {
            return Ok(false);
        };
        let old: Option<String> = row.get(0);
        let new = changed(old.as_deref(), bucket, changes)?;
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

/// A grant: the bucket, its user (account ID, name), the permission.
pub type Grant = (String, (String, String), Permission);

/// Every grant, of users who exist.
pub async fn list(client: &Object) -> anyhow::Result<Vec<Grant>> {
    let rows = client
        .query_cached(
            "SELECT b.name, b.policy, a.id FROM buckets b JOIN accounts a ON a.id = b.account_id
             WHERE b.policy LIKE '%\"CairnGrant%' ORDER BY b.name",
            &[],
        )
        .await?;
    let users: HashSet<(String, String)> =
        client.query_cached("SELECT account_id, name FROM roles", &[]).await?.iter().map(|r| (r.get(0), r.get(1))).collect();
    let mut grants = Vec::new();
    for row in rows {
        let (bucket, policy, account): (String, String, String) = (row.get(0), row.get(1), row.get(2));
        let prefix = user_arn(&account, "");
        for (arn, permission) in in_policy(&policy) {
            if let Some(user) = arn.strip_prefix(&prefix)
                && users.contains(&(account.clone(), user.to_owned()))
            {
                grants.push((bucket.clone(), (account.clone(), user.to_owned()), permission));
            }
        }
    }
    grants.sort_by(|a, b| (&a.0, &a.1, a.2.as_str()).cmp(&(&b.0, &b.1, b.2.as_str())));
    Ok(grants)
}

/// Revokes everything user `user` of `account` was granted (as it's
/// deleted).
pub async fn forget_user(client: &Object, account: &str, user: &str) -> anyhow::Result<()> {
    let mine: Vec<_> =
        list(client).await?.into_iter().filter(|(_, (a, u), _)| a == account && u == user).collect();
    let mut buckets: Vec<&String> = mine.iter().map(|(b, _, _)| b).collect();
    buckets.dedup();
    for bucket in buckets {
        let changes: Vec<_> =
            mine.iter().filter(|(b, _, _)| b == bucket).map(|(_, (_, u), p)| (u.as_str(), *p, false)).collect();
        change(client, account, bucket, &changes).await?;
    }
    Ok(())
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
/// policies) into their buckets' policies, bucket by bucket, each move one
/// compare-and-swap of the policy, then the rows' deletion (locked in the
/// lock protocol's order, G). Safe to run on several nodes at once: a grant
/// already in its policy isn't added twice.
pub async fn convert(client: &Object) -> anyhow::Result<usize> {
    let rows = client
        .query_cached(
            "SELECT g.bucket, g.role, g.permission, r.account_id
             FROM role_grants g JOIN roles r ON r.name = g.role
             -- From before accounts: the first tenant account's users.
             WHERE r.account_id = (SELECT id FROM accounts WHERE NOT operator ORDER BY created_at, id LIMIT 1)
             ORDER BY g.bucket",
            &[],
        )
        .await?;
    let mut moved = 0;
    let mut at = 0;
    while at < rows.len() {
        let bucket: String = rows[at].get(0);
        let mut changes = Vec::new();
        while at < rows.len() && rows[at].get::<_, String>(0) == bucket {
            let (user, permission, account): (String, String, String) =
                (rows[at].get(1), rows[at].get(2), rows[at].get(3));
            changes.push((user_arn(&account, &user), Permission::from_db(&permission)?, true));
            at += 1;
        }
        apply(client, &bucket, &changes).await?;
        client
            .execute_cached(
                "WITH l AS (SELECT ctid FROM role_grants WHERE bucket = $1
                            ORDER BY role, bucket, permission FOR UPDATE)
                 DELETE FROM role_grants WHERE ctid IN (SELECT ctid FROM l)",
                &[&bucket],
            )
            .await?;
        moved += changes.len();
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
        let p = changed(None, "b", &[(ALICE.into(), Permission::Read, true)]).unwrap().unwrap();
        assert_eq!(in_policy(&p), [(ALICE.to_owned(), Permission::Read)]);
        // Kept as S3 keeps policies, and valid as a bucket policy.
        Policy::parse(&p, Kind::Bucket("b")).unwrap();

        // Others' statements stay as they are.
        let mine = r#"{"Version":"2012-10-17","Statement":[{"Sid":"Public","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/pub/*"}]}"#;
        let p = changed(Some(mine), "b", &[(ALICE.into(), Permission::Write, true), (BOB.into(), Permission::Write, true)])
            .unwrap()
            .unwrap();
        assert!(p.contains(r#""Sid":"Public""#), "{p}");
        let mut grants = in_policy(&p);
        grants.sort_by_key(|(arn, _)| arn.clone());
        assert_eq!(grants, [(ALICE.to_owned(), Permission::Write), (BOB.to_owned(), Permission::Write)]);

        // Revoking the last of a statement removes it; the rest stays.
        let p = changed(Some(&p), "b", &[(ALICE.into(), Permission::Write, false), (BOB.into(), Permission::Write, false)])
            .unwrap()
            .unwrap();
        assert!(in_policy(&p).is_empty());
        assert!(p.contains(r#""Sid":"Public""#));
        // And a policy of grants only goes once they're all revoked.
        let p = changed(None, "b", &[(ALICE.into(), Permission::Read, true)]).unwrap();
        assert_eq!(changed(p.as_deref(), "b", &[(ALICE.into(), Permission::Read, false)]).unwrap(), None);
        // Granting twice changes nothing.
        let p = changed(None, "b", &[(ALICE.into(), Permission::Read, true)]).unwrap();
        assert_eq!(changed(p.as_deref(), "b", &[(ALICE.into(), Permission::Read, true)]).unwrap(), p);
    }
}
