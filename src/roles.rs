//! IAM roles: identities that no one signs as with keys of their own, but
//! assumes (STS's AssumeRole), as their trust policies allow, for sessions
//! with temporary credentials. A role has a path and name (its ARN is
//! `arn:aws:iam::<account>:role/<path…/name>`), a trust policy (see
//! `policy::Kind::Trust`), inline and managed policies, tags and a
//! permissions boundary, as a user has; and a longest session it allows
//! (MaxSessionDuration). See `plans/roles.md` (probed).
//!
//! In Postgres: `iam_roles` and `iam_role_…` (`db::IAM_ROLES`), changed as
//! the lock protocol says (O(o) in `catalog.sql`).

use std::collections::HashMap;

use deadpool_postgres::Object;
use uuid::Uuid;

use crate::db::Cached;
use crate::managed::{self, Named, Refused, refused};
use crate::policy::{Kind, Policy};
use crate::users::BoundaryRef;

/// The most a trust policy may hold, in characters but whitespace: IAM's
/// default quota (probed: ACLSizePerRole).
pub const MAX_TRUST: usize = 2048;
/// The most a role's inline policies may hold together, in characters but
/// whitespace, as in IAM.
pub const MAX_POLICIES: usize = 10240;
/// The most managed policies a role may have attached, as IAM's quota.
pub const MAX_ATTACHED: i64 = managed::MAX_ATTACHED;
/// A session's longest a role may allow, and the shortest, in seconds.
pub const SESSION_DURATIONS: std::ops::RangeInclusive<i32> = 3600..=43200;

/// A role's ARN.
pub fn role_arn(account: &str, path: &str, name: &str) -> String {
    format!("arn:aws:iam::{account}:role/{}{name}", path.strip_prefix('/').unwrap_or(path))
}

/// A role's ID as IAM shows one (`AROA`, then 17 characters), from its
/// Cairn ID, which never changes or comes back.
pub fn unique_id(id: Uuid) -> String {
    crate::users::unique_id("AROA", id)
}

/// Whether `name` is a role's name as IAM takes one (probed).
pub fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"+=,.@_-".contains(&b))
}

/// A role, as IAM shows it.
#[derive(Clone, Debug)]
pub struct Role {
    pub id: Uuid,
    pub account: String,
    pub name: String,
    /// Its path (`/`, or `/…/`).
    pub path: String,
    /// Its trust policy, as IAM keeps it (normalized; see
    /// `Policy::normalized`).
    pub trust: String,
    /// The users and roles its trust policy names, by their ARNs: their
    /// IDs, as they were when it was set.
    pub trust_principals: HashMap<String, String>,
    pub description: String,
    pub max_session_duration: i32,
    /// When it was made (ISO 8601, as IAM writes times).
    pub created: String,
    /// Its tags, oldest first.
    pub tags: Vec<(String, String)>,
    /// Its boundary's ARN.
    pub boundary: Option<String>,
}

/// The SQL of a role `r`'s boundary's ARN (NULL if it has none).
const BOUNDARY_ARN: &str = "(SELECT coalesce(
        (SELECT 'arn:aws:iam::' || m.account_id || ':policy/' || substring(m.path FROM 2) || m.name
         FROM managed_policies m WHERE m.id = r.boundary_policy_id),
        'arn:aws:iam::aws:policy/' || r.boundary_aws))";

const COLUMNS: &str = "r.id, r.account_id, r.name, r.path, r.trust_policy, r.trust_principals::text, r.description,
     r.max_session_duration, to_char(r.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
     ARRAY(SELECT t.key FROM iam_role_tags t WHERE t.role_id = r.id ORDER BY t.seq),
     ARRAY(SELECT t.value FROM iam_role_tags t WHERE t.role_id = r.id ORDER BY t.seq)";

impl Role {
    fn of(row: &tokio_postgres::Row) -> anyhow::Result<Role> {
        Ok(Role {
            id: row.get(0),
            account: row.get(1),
            name: row.get(2),
            path: row.get(3),
            trust: row.get(4),
            trust_principals: serde_json::from_str(row.get(5))?,
            description: row.get(6),
            max_session_duration: row.get(7),
            created: row.get(8),
            tags: crate::users::tags_of(row.get(9), row.get(10)),
            boundary: row.get(11),
        })
    }

    /// Role `name` of `account` (regardless of case, as IAM finds one:
    /// probed), if there's one.
    pub async fn load(client: &Object, account: &str, name: &str) -> anyhow::Result<Option<Role>> {
        let row = client
            .query_opt_cached(
                &format!("SELECT {COLUMNS}, {BOUNDARY_ARN} FROM iam_roles r WHERE r.account_id = $1 AND lower(r.name) = lower($2)"),
                &[&account, &name],
            )
            .await?;
        row.as_ref().map(Role::of).transpose()
    }

    /// Role `id`, if there's one.
    pub async fn load_id(client: &Object, id: Uuid) -> anyhow::Result<Option<Role>> {
        let row = client
            .query_opt_cached(&format!("SELECT {COLUMNS}, {BOUNDARY_ARN} FROM iam_roles r WHERE r.id = $1"), &[&id])
            .await?;
        row.as_ref().map(Role::of).transpose()
    }

    /// Its ARN.
    pub fn arn(&self) -> String {
        role_arn(&self.account, &self.path, &self.name)
    }

    /// What IAM's actions on it are checked against.
    pub fn on(&self) -> crate::s3::actions::On {
        crate::s3::actions::On::role(&self.account, &self.path, &self.name)
    }

    /// The condition keys of `action` on it: its tags, as
    /// `aws:ResourceTag/…` and `iam:ResourceTag/…`, and (for the actions
    /// that take it) its boundary, as `iam:PermissionsBoundary`, as for a
    /// user (see `users::Target::context`).
    pub fn context(&self, action: &str) -> crate::policy::Context {
        let mut context = crate::policy::Context::default();
        for (key, value) in &self.tags {
            context.set(&format!("aws:ResourceTag/{key}"), value);
            context.set(&format!("iam:ResourceTag/{key}"), value);
        }
        if CURRENT_BOUNDARY_ACTIONS.iter().any(|a| a.eq_ignore_ascii_case(action))
            && let Some(boundary) = &self.boundary
        {
            context.set("iam:PermissionsBoundary", boundary);
        }
        context
    }
}

/// The actions on a role whose `iam:PermissionsBoundary` is the role's
/// boundary (as it is), from IAM's service reference.
const CURRENT_BOUNDARY_ACTIONS: &[&str] = &[
    "iam:AttachRolePolicy",
    "iam:DetachRolePolicy",
    "iam:PutRolePolicy",
    "iam:DeleteRolePolicy",
    "iam:DeleteRolePermissionsBoundary",
];

/// `text` checked as a trust policy for a role of `account`, as IAM checks
/// one (probed): valid, within `MAX_TRUST`, and naming principals that
/// exist. It as IAM keeps it (normalized).
pub async fn check_trust(client: &Object, account: &str, text: &str) -> anyhow::Result<String> {
    let policy = Policy::parse(text, Kind::Trust).map_err(|e| match e.code {
        "NotImplemented" => Refused::Unsupported(e.message),
        _ => Refused::Malformed(e.message),
    })?;
    if text.chars().filter(|c| !c.is_whitespace()).count() > MAX_TRUST {
        return refused(Refused::Limit(format!("Cannot exceed quota for ACLSizePerRole: {MAX_TRUST}")));
    }
    let invalid = |arn: String| refused(Refused::Malformed(format!("Invalid principal in policy: \"AWS\":\"{arn}\"")));
    for named in policy.accounts() {
        if named != account {
            return invalid(format!("arn:aws:iam::{named}:root"));
        }
    }
    for (named, user) in policy.users() {
        let exists = named == account
            && client
                .query_opt_cached(
                    "SELECT 1 FROM users WHERE substring(path FROM 2) || name = $1 AND account_id = $2",
                    &[&user, &named],
                )
                .await?
                .is_some();
        if !exists {
            return invalid(format!("arn:aws:iam::{named}:user/{user}"));
        }
    }
    for (named, role) in policy.roles() {
        let exists = named == account
            && client
                .query_opt_cached(
                    "SELECT 1 FROM iam_roles WHERE substring(path FROM 2) || name = $1 AND account_id = $2",
                    &[&role, &named],
                )
                .await?
                .is_some();
        if !exists {
            return invalid(format!("arn:aws:iam::{named}:role/{role}"));
        }
    }
    // A session by its role's name (its ARN has no path).
    for (named, role, session) in policy.sessions() {
        let exists = named == account
            && client
                .query_opt_cached("SELECT 1 FROM iam_roles WHERE name = $1 AND account_id = $2", &[&role, &named])
                .await?
                .is_some();
        if !exists {
            return invalid(format!("arn:aws:sts::{named}:assumed-role/{role}/{session}"));
        }
    }
    Ok(policy.normalized().to_owned())
}

/// The role's trust policy as GetRole shows it: as it's kept, but each user
/// or role it names that's gone since named by its unique ID (`AIDA…`,
/// `AROA…`), and each that's been renamed or moved since by its ARN now (as
/// bucket policies' users: probed).
pub async fn shown_trust(client: &Object, role: &Role) -> anyhow::Result<String> {
    let mut gone = HashMap::new();
    for (arn, id) in &role.trust_principals {
        let Ok(id) = id.parse::<Uuid>() else { continue };
        let user = client
            .query_opt_cached(
                "SELECT 'arn:aws:iam::' || account_id || ':user/' || substring(path FROM 2) || name FROM users WHERE id = $1",
                &[&id],
            )
            .await?;
        let now = match user {
            Some(row) => Some(row.get::<_, String>(0)),
            None => client
                .query_opt_cached(
                    "SELECT 'arn:aws:iam::' || account_id || ':role/' || substring(path FROM 2) || name FROM iam_roles WHERE id = $1",
                    &[&id],
                )
                .await?
                .map(|row| row.get(0)),
        };
        match now {
            Some(now) if now == *arn => {}
            Some(now) => {
                gone.insert(arn.clone(), now);
            }
            None if arn.contains(":role/") => {
                gone.insert(arn.clone(), unique_id(id));
            }
            None => {
                gone.insert(arn.clone(), crate::users::unique_id("AIDA", id));
            }
        }
    }
    if gone.is_empty() {
        return Ok(role.trust.clone());
    }
    let policy = Policy::parse(&role.trust, Kind::Trust)
        .map_err(|e| anyhow::anyhow!("role {}'s trust policy doesn't parse: {}", role.name, e.message))?;
    Ok(policy.shown(Kind::Trust, &gone))
}

/// What a new role is made with.
pub struct New<'a> {
    pub name: &'a str,
    pub path: &'a str,
    /// Its trust policy, checked (see `check_trust`).
    pub trust: &'a str,
    pub description: &'a str,
    pub max_session_duration: i32,
    pub boundary: Option<&'a BoundaryRef>,
    pub tags: &'a [(String, String)],
}

/// Makes a role of `account`: its ID.
pub async fn create(client: &Object, account: &str, new: &New<'_>) -> anyhow::Result<Uuid> {
    let (own, aws) = BoundaryRef::columns(new.boundary);
    let made = client
        .query_one_cached(
            "INSERT INTO iam_roles (account_id, name, path, trust_policy, description, max_session_duration,
                                    boundary_policy_id, boundary_aws)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
            &[&account, &new.name, &new.path, &new.trust, &new.description, &new.max_session_duration, &own, &aws],
        )
        .await;
    let id: Uuid = match made {
        Ok(row) => row.get(0),
        Err(e) if e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) => {
            return refused(Refused::Exists(format!("Role with name {} already exists.", new.name)));
        }
        Err(e) => return Err(e.into()),
    };
    if !new.tags.is_empty() {
        tag(client, id, new.tags).await?;
    }
    Ok(id)
}

/// Changes a role's description and/or its longest session.
pub async fn update(client: &Object, id: Uuid, description: Option<&str>, max_session_duration: Option<i32>) -> anyhow::Result<()> {
    client
        .execute_cached(
            "UPDATE iam_roles SET description = coalesce($2, description),
                                  max_session_duration = coalesce($3, max_session_duration)
             WHERE id = $1",
            &[&id, &description, &max_session_duration],
        )
        .await?;
    Ok(())
}

/// Sets a role's trust policy (checked: see `check_trust`).
pub async fn set_trust(client: &Object, id: Uuid, trust: &str) -> anyhow::Result<()> {
    client.execute_cached("UPDATE iam_roles SET trust_policy = $2 WHERE id = $1", &[&id, &trust]).await?;
    Ok(())
}

/// Sets (or, `None`, takes off) a role's permissions boundary.
pub async fn set_boundary(client: &Object, id: Uuid, boundary: Option<&BoundaryRef>) -> anyhow::Result<()> {
    let (own, aws) = BoundaryRef::columns(boundary);
    client
        .execute_cached("UPDATE iam_roles SET boundary_policy_id = $2, boundary_aws = $3 WHERE id = $1", &[&id, &own, &aws])
        .await?;
    Ok(())
}

/// Deletes role `role` (by its name, as IAM refuses it), unless it has
/// policies left (T49).
pub async fn delete(client: &Object, role: &Role) -> anyhow::Result<()> {
    let status: String = client.query_one_cached("SELECT pg_temp.cairn_delete_role($1)", &[&role.id]).await?.get(0);
    match status.as_str() {
        "deleted" => Ok(()),
        "policies" => refused(Refused::Conflict("Cannot delete entity, must delete policies first.".into())),
        "attached" => refused(Refused::Conflict("Cannot delete entity, must detach all policies first.".into())),
        _ => refused(no_such(&role.name)),
    }
}

/// IAM's NoSuchEntity for role `name`.
pub fn no_such(name: &str) -> Refused {
    Refused::NoSuch(format!("The role with name {name} cannot be found."))
}

/// Sets `tags` on role `id` (T48).
pub async fn tag(client: &Object, id: Uuid, tags: &[(String, String)]) -> anyhow::Result<()> {
    let keys: Vec<&str> = tags.iter().map(|(k, _)| k.as_str()).collect();
    let values: Vec<&str> = tags.iter().map(|(_, v)| v.as_str()).collect();
    let status: String = client
        .query_one_cached(
            "SELECT pg_temp.cairn_tag_role($1, $2, $3, $4)",
            &[&id, &keys, &values, &(crate::users::MAX_TAGS as i32)],
        )
        .await?
        .get(0);
    match status.as_str() {
        "tagged" => Ok(()),
        "too_many" => Err(crate::users::TooManyTags.into()),
        _ => refused(Refused::NoSuch("The role cannot be found.".into())),
    }
}

/// Takes the tags `keys` (regardless of case) off role `id`.
pub async fn untag(client: &Object, id: Uuid, keys: &[String]) -> anyhow::Result<()> {
    client
        .execute_cached(
            "DELETE FROM iam_role_tags WHERE role_id = $1 AND lower(key) IN (SELECT lower(k) FROM unnest($2::text[]) k)",
            &[&id, &keys],
        )
        .await?;
    Ok(())
}

/// Sets inline policy `name` of role `role` to `document` (a valid
/// identity policy), within `MAX_POLICIES` (T47).
pub async fn put_policy(client: &Object, role: &Role, name: &str, document: &str) -> anyhow::Result<()> {
    crate::users::validate_policy_name(name).map_err(|e| Refused::Validation(e.to_string()))?;
    Policy::parse(document, Kind::Identity).map_err(|e| match e.code {
        "NotImplemented" => Refused::Unsupported(e.message),
        _ => Refused::Malformed(e.message),
    })?;
    let status: String = client
        .query_one_cached(
            "SELECT pg_temp.cairn_put_role_policy($1, $2, $3, $4)",
            &[&role.id, &name, &document, &(MAX_POLICIES as i32)],
        )
        .await?
        .get(0);
    match status.as_str() {
        "set" => Ok(()),
        "too_big" => refused(Refused::Limit(format!(
            "Maximum policy size of {MAX_POLICIES} bytes exceeded for role {}",
            role.name
        ))),
        _ => refused(no_such(&role.name)),
    }
}

/// Role `id`'s inline policy `name`, as it was set.
pub async fn get_policy(client: &Object, id: Uuid, name: &str) -> anyhow::Result<Option<String>> {
    let row = client
        .query_opt_cached("SELECT document FROM iam_role_policies WHERE role_id = $1 AND name = $2", &[&id, &name])
        .await?;
    Ok(row.map(|r| r.get(0)))
}

/// Role `id`'s inline policies' names.
pub async fn policy_names(client: &Object, id: Uuid) -> anyhow::Result<Vec<String>> {
    let rows = client.query_cached("SELECT name FROM iam_role_policies WHERE role_id = $1 ORDER BY name", &[&id]).await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}

/// Deletes role `id`'s inline policy `name`; whether it had one.
pub async fn delete_policy(client: &Object, id: Uuid, name: &str) -> anyhow::Result<bool> {
    let deleted = client
        .execute_cached("DELETE FROM iam_role_policies WHERE role_id = $1 AND name = $2", &[&id, &name])
        .await?;
    Ok(deleted > 0)
}

/// The managed policies attached to role `id`: Cairn's, then the account's.
pub async fn attached(client: &Object, id: Uuid) -> anyhow::Result<Vec<managed::Attached>> {
    let rows = client
        .query_cached(
            "SELECT NULL::text, x.aws_policy FROM iam_role_attached_policies x
             WHERE x.role_id = $1 AND x.aws_policy IS NOT NULL
             UNION ALL
             SELECT m.account_id || ' ' || m.path, m.name FROM iam_role_attached_policies x
             JOIN managed_policies m ON m.id = x.policy_id WHERE x.role_id = $1
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

/// Attaches (`attach`) or detaches the managed policy `arn` to role `role`
/// of `account`, as IAM refuses it (probed).
pub async fn attach(client: &Object, account: &str, role: &Role, arn: &str, attach: bool) -> anyhow::Result<()> {
    let policy = managed::named(arn, account)?;
    let attached_now = attached(client, role.id).await?;
    if attach && attached_now.len() as i64 >= MAX_ATTACHED && !attached_now.iter().any(|a| a.arn == arn) {
        return refused(Refused::Limit(format!("Cannot exceed quota for PoliciesPerRole: {MAX_ATTACHED}")));
    }
    let changed = match &policy {
        Named::Aws(p) if attach => {
            client
                .execute_cached(
                    "INSERT INTO iam_role_attached_policies (role_id, aws_policy) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                    &[&role.id, &p.name],
                )
                .await?;
            1
        }
        Named::Aws(p) => {
            client
                .execute_cached("DELETE FROM iam_role_attached_policies WHERE role_id = $1 AND aws_policy = $2", &[&role.id, &p.name])
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
                        "INSERT INTO iam_role_attached_policies (role_id, policy_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                        &[&role.id, &id],
                    )
                    .await?;
                1
            } else {
                client
                    .execute_cached("DELETE FROM iam_role_attached_policies WHERE role_id = $1 AND policy_id = $2", &[&role.id, &id])
                    .await?
            }
        }
    };
    if changed == 0 {
        return refused(Refused::NoSuch(format!("Policy {arn} was not found.")));
    }
    Ok(())
}

/// `account`'s roles at paths starting with `prefix`, after `after` (a
/// name), by name: at most `max`.
pub async fn list(client: &Object, account: &str, prefix: &str, after: &str, max: i64) -> anyhow::Result<Vec<Role>> {
    let rows = client
        .query_cached(
            &format!(
                "SELECT {COLUMNS}, {BOUNDARY_ARN} FROM iam_roles r
                 WHERE r.account_id = $1 AND r.name > $2 AND starts_with(r.path, $3) ORDER BY r.name LIMIT $4"
            ),
            &[&account, &after, &prefix, &max],
        )
        .await?;
    rows.iter().map(Role::of).collect()
}

/// The roles of `account` that managed policy `arn` is attached to, and
/// those whose permissions boundary it is: their IDs and names.
pub async fn of_policy(client: &Object, account: &str, arn: &str) -> anyhow::Result<(Vec<(Uuid, String)>, Vec<(Uuid, String)>)> {
    let (own, aws): (Option<Uuid>, Option<&str>) = match managed::named(arn, account) {
        Ok(Named::Aws(p)) => (None, Some(p.name)),
        Ok(Named::Own { path, name }) => match managed::own(client, account, &path, &name).await {
            Ok(policy) => (Some(policy.id), None),
            Err(_) => return Ok((Vec::new(), Vec::new())),
        },
        Err(_) => return Ok((Vec::new(), Vec::new())),
    };
    let pairs = |rows: Vec<tokio_postgres::Row>| rows.iter().map(|r| (r.get(0), r.get(1))).collect::<Vec<_>>();
    let attached = client
        .query_cached(
            "SELECT r.id, r.name FROM iam_role_attached_policies x JOIN iam_roles r ON r.id = x.role_id
             WHERE r.account_id = $1 AND (x.policy_id = $2 OR x.aws_policy = $3) ORDER BY r.name",
            &[&account, &own, &aws],
        )
        .await?;
    let bounded = client
        .query_cached(
            "SELECT r.id, r.name FROM iam_roles r
             WHERE r.account_id = $1 AND (r.boundary_policy_id = $2 OR r.boundary_aws = $3) ORDER BY r.name",
            &[&account, &own, &aws],
        )
        .await?;
    Ok((pairs(attached), pairs(bounded)))
}
