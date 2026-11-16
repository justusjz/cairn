//! IAM groups: collections of an account's users, whose inline and managed
//! policies apply to each of their members as if they were the member's own
//! (see `users::Principal`). So `invoices-read` is attached to a group of
//! the people who read invoices, not to each of them. A group has a path and
//! a name (its ARN is `arn:aws:iam::<account>:group/<path…/name>`), as IAM's;
//! no tags, boundary or trust policy, and it is no principal: policies name
//! it only as a resource (IAM's actions on it).
//!
//! In Postgres: `iam_groups` and `iam_group_…` (`db::IAM_GROUPS`), changed
//! as the lock protocol says (Q(q) in `catalog.sql`).

use deadpool_postgres::Object;
use uuid::Uuid;

use crate::db::Cached;
use crate::managed::{self, Named, Refused, refused};
use crate::policy::{Kind, Policy};

/// The most a group's inline policies may hold together, in characters but
/// whitespace, as in IAM.
pub const MAX_POLICIES: usize = 5120;
/// The most managed policies a group may have attached, as IAM's quota.
pub const MAX_ATTACHED: i64 = managed::MAX_ATTACHED;
/// The most groups a user may be in, as IAM's quota.
pub const MAX_GROUPS_PER_USER: i32 = 10;

/// A group's ARN.
pub fn group_arn(account: &str, path: &str, name: &str) -> String {
    format!("arn:aws:iam::{account}:group/{}{name}", path.strip_prefix('/').unwrap_or(path))
}

/// A group's ID as IAM shows one (`AGPA`, then 17 characters), from its
/// Cairn ID, which never changes or comes back.
pub fn unique_id(id: Uuid) -> String {
    crate::users::unique_id("AGPA", id)
}

/// Whether `name` is a group's name as IAM takes one.
pub fn valid_name(name: &str) -> bool {
    (1..=128).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"+=,.@_-".contains(&b))
}

/// A group, as IAM shows it.
#[derive(Clone, Debug)]
pub struct Group {
    pub id: Uuid,
    pub account: String,
    pub name: String,
    /// Its path (`/`, or `/…/`).
    pub path: String,
    /// When it was made (ISO 8601, as IAM writes times).
    pub created: String,
}

const COLUMNS: &str = "g.id, g.account_id, g.name, g.path, to_char(g.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')";

impl Group {
    fn of(row: &tokio_postgres::Row) -> Group {
        Group { id: row.get(0), account: row.get(1), name: row.get(2), path: row.get(3), created: row.get(4) }
    }

    /// Group `name` of `account` (regardless of case, as IAM finds one), if
    /// there's one.
    pub async fn load(client: &Object, account: &str, name: &str) -> anyhow::Result<Option<Group>> {
        let row = client
            .query_opt_cached(
                &format!("SELECT {COLUMNS} FROM iam_groups g WHERE g.account_id = $1 AND lower(g.name) = lower($2)"),
                &[&account, &name],
            )
            .await?;
        Ok(row.as_ref().map(Group::of))
    }

    /// Group `id`, if there's one.
    pub async fn load_id(client: &Object, id: Uuid) -> anyhow::Result<Option<Group>> {
        let row = client.query_opt_cached(&format!("SELECT {COLUMNS} FROM iam_groups g WHERE g.id = $1"), &[&id]).await?;
        Ok(row.as_ref().map(Group::of))
    }

    /// Its ARN.
    pub fn arn(&self) -> String {
        group_arn(&self.account, &self.path, &self.name)
    }

    /// What IAM's actions on it are checked against.
    pub fn on(&self) -> crate::s3::actions::On {
        crate::s3::actions::On::group(&self.account, &self.path, &self.name)
    }
}

/// IAM's NoSuchEntity for group `name`.
pub fn no_such(name: &str) -> Refused {
    Refused::NoSuch(format!("The group with name {name} cannot be found."))
}

fn exists(name: &str) -> Refused {
    Refused::Exists(format!("Group with name {name} already exists."))
}

/// Makes group `name` of `account`, at `path`: its ID.
pub async fn create(client: &Object, account: &str, name: &str, path: &str) -> anyhow::Result<Uuid> {
    let made = client
        .query_one_cached("INSERT INTO iam_groups (account_id, name, path) VALUES ($1, $2, $3) RETURNING id", &[&account, &name, &path])
        .await;
    match made {
        Ok(row) => Ok(row.get(0)),
        Err(e) if e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) => refused(exists(name)),
        Err(e) => Err(e.into()),
    }
}

/// Renames (`name`) and/or moves (`path`) group `id`: a plain UPDATE of its
/// own row, which no invariant of the lock protocol involves.
pub async fn update(client: &Object, id: Uuid, name: &str, path: &str) -> anyhow::Result<()> {
    let updated = client.execute_cached("UPDATE iam_groups SET name = $2, path = $3 WHERE id = $1", &[&id, &name, &path]).await;
    match updated {
        Ok(_) => Ok(()),
        Err(e) if e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) => refused(exists(name)),
        Err(e) => Err(e.into()),
    }
}

/// Deletes group `group`, unless it has members or policies left (T58).
pub async fn delete(client: &Object, group: &Group) -> anyhow::Result<()> {
    let status: String = client.query_one_cached("SELECT pg_temp.cairn_delete_group($1)", &[&group.id]).await?.get(0);
    match status.as_str() {
        "deleted" => Ok(()),
        "members" => refused(Refused::Conflict("Cannot delete entity, must remove users from group first.".into())),
        "policies" => refused(Refused::Conflict("Cannot delete entity, must delete policies first.".into())),
        "attached" => refused(Refused::Conflict("Cannot delete entity, must detach all policies first.".into())),
        _ => refused(no_such(&group.name)),
    }
}

/// `account`'s groups at paths starting with `prefix`, after `after` (a
/// name), by name: at most `max`.
pub async fn list(client: &Object, account: &str, prefix: &str, after: &str, max: i64) -> anyhow::Result<Vec<Group>> {
    let rows = client
        .query_cached(
            &format!(
                "SELECT {COLUMNS} FROM iam_groups g
                 WHERE g.account_id = $1 AND g.name > $2 AND starts_with(g.path, $3) ORDER BY g.name LIMIT $4"
            ),
            &[&account, &after, &prefix, &max],
        )
        .await?;
    Ok(rows.iter().map(Group::of).collect())
}

/// A group's member: its ID and name.
#[derive(Clone, Debug, PartialEq)]
pub struct Member {
    pub id: Uuid,
    pub name: String,
}

/// Group `id`'s members, by name, after `after` (a name): at most `max`.
pub async fn members(client: &Object, id: Uuid, after: &str, max: i64) -> anyhow::Result<Vec<Member>> {
    let rows = client
        .query_cached(
            "SELECT u.id, u.name FROM iam_group_members x JOIN users u ON u.id = x.user_id
             WHERE x.group_id = $1 AND u.name > $2 ORDER BY u.name LIMIT $3",
            &[&id, &after, &max],
        )
        .await?;
    Ok(rows.iter().map(|r| Member { id: r.get(0), name: r.get(1) }).collect())
}

/// The groups each of `account`'s users is in (their names, by name), by
/// user ID.
pub async fn memberships(client: &Object, account: &str) -> anyhow::Result<std::collections::HashMap<Uuid, Vec<String>>> {
    let rows = client
        .query_cached(
            "SELECT x.user_id, g.name FROM iam_group_members x JOIN iam_groups g ON g.id = x.group_id
             WHERE g.account_id = $1 ORDER BY g.name",
            &[&account],
        )
        .await?;
    let mut all: std::collections::HashMap<Uuid, Vec<String>> = std::collections::HashMap::new();
    for row in rows {
        all.entry(row.get(0)).or_default().push(row.get(1));
    }
    Ok(all)
}

/// The groups user `user` is in, by name.
pub async fn of_user(client: &Object, user: Uuid) -> anyhow::Result<Vec<Group>> {
    let rows = client
        .query_cached(
            &format!(
                "SELECT {COLUMNS} FROM iam_group_members x JOIN iam_groups g ON g.id = x.group_id
                 WHERE x.user_id = $1 ORDER BY g.name"
            ),
            &[&user],
        )
        .await?;
    Ok(rows.iter().map(Group::of).collect())
}

/// Makes user `user` (`name`) a member of `group`, unless it's in as many
/// groups as it may be (T59). One that's a member already stays one.
pub async fn add_member(client: &Object, group: &Group, user: Uuid, name: &str) -> anyhow::Result<()> {
    let status: String = client
        .query_one_cached("SELECT pg_temp.cairn_add_user_to_group($1, $2, $3)", &[&user, &group.id, &MAX_GROUPS_PER_USER])
        .await?
        .get(0);
    match status.as_str() {
        "added" => Ok(()),
        "too_many" => refused(Refused::Limit(format!("Cannot exceed quota for GroupsPerUser: {MAX_GROUPS_PER_USER}"))),
        "no_such_user" => refused(Refused::NoSuch(format!("The user with name {name} cannot be found."))),
        _ => refused(no_such(&group.name)),
    }
}

/// Ends user `user`'s (`name`'s) membership of `group` (T60), as IAM
/// refuses ending one that isn't.
pub async fn remove_member(client: &Object, group: &Group, user: Uuid, name: &str) -> anyhow::Result<()> {
    let status: String = client
        .query_one_cached("SELECT pg_temp.cairn_remove_user_from_group($1, $2)", &[&user, &group.id])
        .await?
        .get(0);
    match status.as_str() {
        "removed" => Ok(()),
        "not_member" => refused(Refused::NoSuch(format!("The user with name {name} cannot be found."))),
        _ => refused(Refused::NoSuch(format!("The user with name {name} cannot be found."))),
    }
}

/// Sets inline policy `name` of group `group` to `document` (a valid
/// identity policy), within `MAX_POLICIES` (T57).
pub async fn put_policy(client: &Object, group: &Group, name: &str, document: &str) -> anyhow::Result<()> {
    crate::users::validate_policy_name(name).map_err(|e| Refused::Validation(e.to_string()))?;
    Policy::parse(document, Kind::Identity).map_err(|e| match e.code {
        "NotImplemented" => Refused::Unsupported(e.message),
        _ => Refused::Malformed(e.message),
    })?;
    let status: String = client
        .query_one_cached(
            "SELECT pg_temp.cairn_put_group_policy($1, $2, $3, $4)",
            &[&group.id, &name, &document, &(MAX_POLICIES as i32)],
        )
        .await?
        .get(0);
    match status.as_str() {
        "set" => Ok(()),
        "too_big" => refused(Refused::Limit(format!(
            "Maximum policy size of {MAX_POLICIES} bytes exceeded for group {}",
            group.name
        ))),
        _ => refused(no_such(&group.name)),
    }
}

/// Group `id`'s inline policy `name`, as it was set.
pub async fn get_policy(client: &Object, id: Uuid, name: &str) -> anyhow::Result<Option<String>> {
    let row = client
        .query_opt_cached("SELECT document FROM iam_group_policies WHERE group_id = $1 AND name = $2", &[&id, &name])
        .await?;
    Ok(row.map(|r| r.get(0)))
}

/// Group `id`'s inline policies' names.
pub async fn policy_names(client: &Object, id: Uuid) -> anyhow::Result<Vec<String>> {
    let rows = client.query_cached("SELECT name FROM iam_group_policies WHERE group_id = $1 ORDER BY name", &[&id]).await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}

/// Deletes group `id`'s inline policy `name`; whether it had one.
pub async fn delete_policy(client: &Object, id: Uuid, name: &str) -> anyhow::Result<bool> {
    let deleted = client
        .execute_cached("DELETE FROM iam_group_policies WHERE group_id = $1 AND name = $2", &[&id, &name])
        .await?;
    Ok(deleted > 0)
}

/// The managed policies attached to group `id`: Cairn's, then the
/// account's.
pub async fn attached(client: &Object, id: Uuid) -> anyhow::Result<Vec<managed::Attached>> {
    let rows = client
        .query_cached(
            "SELECT NULL::text, x.aws_policy FROM iam_group_attached_policies x
             WHERE x.group_id = $1 AND x.aws_policy IS NOT NULL
             UNION ALL
             SELECT m.account_id || ' ' || m.path, m.name FROM iam_group_attached_policies x
             JOIN managed_policies m ON m.id = x.policy_id WHERE x.group_id = $1
             ORDER BY 1 NULLS FIRST, 2",
            &[&id],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| {
            let (owner, name): (Option<String>, String) = (row.get(0), row.get(1));
            let arn = match owner.as_deref().and_then(|o| o.split_once(' ')) {
                Some((owner, path)) => managed::arn(owner, path, &name),
                None => managed::aws_arn(&name),
            };
            managed::Attached { name, arn }
        })
        .collect())
}

/// Attaches (`attach`) or detaches the managed policy `arn` to group
/// `group` of `account`, as IAM refuses it. (An attachment's FK check takes
/// the group's Q(q) shared, so it isn't made to a group being deleted:
/// T58.)
pub async fn attach(client: &Object, account: &str, group: &Group, arn: &str, attach: bool) -> anyhow::Result<()> {
    let policy = managed::named(arn, account)?;
    let attached_now = attached(client, group.id).await?;
    if attach && attached_now.len() as i64 >= MAX_ATTACHED && !attached_now.iter().any(|a| a.arn == arn) {
        return refused(Refused::Limit(format!("Cannot exceed quota for PoliciesPerGroup: {MAX_ATTACHED}")));
    }
    let changed = match &policy {
        Named::Aws(p) if attach => {
            client
                .execute_cached(
                    "INSERT INTO iam_group_attached_policies (group_id, aws_policy) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                    &[&group.id, &p.name],
                )
                .await?;
            1
        }
        Named::Aws(p) => {
            client
                .execute_cached("DELETE FROM iam_group_attached_policies WHERE group_id = $1 AND aws_policy = $2", &[&group.id, &p.name])
                .await?
        }
        Named::Own { path, name } => {
            let id = managed::own(client, account, path, name)
                .await
                .map_err(|_| Refused::NoSuch(format!("Policy {arn} does not exist or is not attachable.")))?
                .id;
            if attach {
                client
                    .execute_cached(
                        "INSERT INTO iam_group_attached_policies (group_id, policy_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                        &[&group.id, &id],
                    )
                    .await?;
                1
            } else {
                client
                    .execute_cached("DELETE FROM iam_group_attached_policies WHERE group_id = $1 AND policy_id = $2", &[&group.id, &id])
                    .await?
            }
        }
    };
    if changed == 0 {
        return refused(Refused::NoSuch(format!("Policy {arn} was not found.")));
    }
    Ok(())
}

/// The groups of `account` that managed policy `arn` is attached to: their
/// IDs and names.
pub async fn of_policy(client: &Object, account: &str, arn: &str) -> anyhow::Result<Vec<(Uuid, String)>> {
    let (own, aws): (Option<Uuid>, Option<&str>) = match managed::named(arn, account) {
        Ok(Named::Aws(p)) => (None, Some(p.name)),
        Ok(Named::Own { path, name }) => match managed::own(client, account, &path, &name).await {
            Ok(policy) => (Some(policy.id), None),
            Err(_) => return Ok(Vec::new()),
        },
        Err(_) => return Ok(Vec::new()),
    };
    let rows = client
        .query_cached(
            "SELECT g.id, g.name FROM iam_group_attached_policies x JOIN iam_groups g ON g.id = x.group_id
             WHERE g.account_id = $1 AND (x.policy_id = $2 OR x.aws_policy = $3) ORDER BY g.name",
            &[&account, &own, &aws],
        )
        .await?;
    Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
}
