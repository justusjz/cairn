//! Grants: a user's `read`, `write` or `delete-version` on a bucket, as
//! managed policies (see `managed`): `<bucket>-read`, `<bucket>-write` and
//! `<bucket>-delete-version`, of the bucket's account, each allowing what
//! its permission does on the bucket and its objects, attached to the
//! users granted it. `cairn user grant` and `revoke` attach and detach them,
//! making them as needed; they're ordinary policies, which IAM tools see
//! and the console edits as any other.
//!
//! Grants used to be statements of the bucket's policy,
//! `CairnGrant<Permission>`, naming the users granted it, and before that
//! rows of `role_grants`. A Cairn moves any that are left into managed
//! policies as it starts (`convert`, `to_managed`): the same access within
//! the account, kept where IAM keeps it.

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
             FROM role_grants g JOIN users r ON r.name = g.role
             -- From before accounts: the first tenant account's users.
             WHERE r.account_id = (SELECT id FROM accounts WHERE NOT operator)
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

/// The managed policy a grant of `permission` on `bucket` is: the names it
/// may have (the first, unless an account's own policy of another
/// document has it), and its document.
pub fn policy_for(bucket: &str, permission: Permission) -> ([String; 2], String) {
    let name = format!("{bucket}-{}", permission.as_str());
    let document = json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": crate::s3::actions::grant_actions(permission),
            "Resource": [format!("arn:aws:s3:::{bucket}"), format!("arn:aws:s3:::{bucket}/*")],
        }],
    });
    ([name.clone(), format!("{name}-grant")], document.to_string())
}

/// The name of the account's managed policy for a grant of `permission` on
/// `bucket`, made if there's none (`make`); `None` if there's none.
async fn grant_policy(client: &Object, account: &str, bucket: &str, permission: Permission, make: bool) -> anyhow::Result<Option<String>> {
    use crate::managed::{self, Refused};
    let (names, document) = policy_for(bucket, permission);
    for name in names {
        match managed::get(client, account, &name).await {
            Ok(policy) if policy.document == document => return Ok(Some(name)),
            // Another policy of that name: the next one.
            Ok(_) => continue,
            Err(e) if matches!(e.downcast_ref::<Refused>(), Some(Refused::NoSuch(_))) => {
                if !make {
                    continue;
                }
                let description = format!("{} on bucket {bucket} (a grant)", permission.as_str());
                match managed::create(client, account, &name, "/", &document, &description).await {
                    Ok(_) => return Ok(Some(name)),
                    // Made meanwhile (by another node): as it is now.
                    Err(e) if matches!(e.downcast_ref::<Refused>(), Some(Refused::Exists(_))) => {
                        if managed::get(client, account, &name).await?.document == document {
                            return Ok(Some(name));
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
            Err(e) => return Err(e),
        }
    }
    if make {
        return Err(Invalid(format!("the account has policies named {bucket}-{} already, of other documents", permission.as_str())).into());
    }
    Ok(None)
}

/// Grants (`grant`) or revokes `permissions` on `bucket` to user `user` of
/// `account`: attaches or detaches their managed policies. The bucket must
/// be the account's (another account's users are named by its policy
/// itself, for cross-account access).
pub async fn change(client: &Object, account: &str, user: &str, bucket: &str, permissions: &[Permission], grant: bool) -> anyhow::Result<()> {
    let Some(row) = client.query_opt_cached("SELECT account_id FROM buckets WHERE name = $1", &[&bucket]).await? else {
        return Err(Invalid(format!("no bucket named {bucket:?}; create it first")).into());
    };
    if row.get::<_, String>(0) != account {
        return Err(Invalid(format!("{bucket:?} is another account's bucket")).into());
    }
    for permission in permissions {
        let Some(name) = grant_policy(client, account, bucket, *permission, grant).await? else { continue };
        let arn = crate::managed::get(client, account, &name).await?.arn(account);
        match crate::managed::attach(client, account, user, &arn, grant).await {
            Ok(()) => {}
            // Revoking what wasn't granted.
            Err(e) if !grant && matches!(e.downcast_ref::<crate::managed::Refused>(), Some(crate::managed::Refused::NoSuch(_))) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Moves the grants left in buckets' policies (`CairnGrant<Permission>`
/// statements) into managed policies attached to their users, bucket by
/// bucket: the policies are made and attached, then the statements leave
/// the bucket's policy (a compare-and-swap). Safe to run on several nodes
/// at once, and again. Users of other accounts, which no grant could name,
/// are dropped from them. The number of grants moved.
pub async fn to_managed(client: &Object) -> anyhow::Result<usize> {
    let rows = client
        .query_cached(
            "SELECT b.name, b.policy, b.account_id FROM buckets b WHERE b.policy LIKE '%\"CairnGrant%' ORDER BY b.name",
            &[],
        )
        .await?;
    let mut moved = 0;
    for row in rows {
        let (bucket, policy, account): (String, String, String) = (row.get(0), row.get(1), row.get(2));
        let prefix = user_arn(&account, "");
        let grants = in_policy(&policy);
        for (arn, permission) in &grants {
            let Some(user) = arn.strip_prefix(&prefix) else { continue };
            if client.query_opt_cached("SELECT 1 FROM users WHERE account_id = $1 AND lower(name) = lower($2)", &[&account, &user]).await?.is_none() {
                continue;
            }
            change(client, &account, user, &bucket, &[*permission], true).await?;
            moved += 1;
        }
        let revoked: Vec<_> = grants.into_iter().map(|(arn, permission)| (arn, permission, false)).collect();
        apply(client, &bucket, &revoked).await?;
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
