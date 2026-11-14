//! Users (called roles before; still the `roles` table): who may make S3
//! requests, with which access keys, and what each may do.
//!
//! A user has a name (its ARN is `arn:aws:iam::<account>:user/<name>`), up to
//! two access keys (an ID and a secret; IDs are random, as IAM's, except a
//! migrated role's one key, which is named as the user), and permissions: it may be an *admin*, which allows
//! bucket management (create / delete / list every bucket), it holds
//! per-bucket `read` / `write` / `delete-version` grants for object access,
//! and it may have inline identity policies of its own (see `policy`). Admin
//! does not imply object access; that always needs a grant (or a policy).
//!
//! The cluster's operators are users too, whose policies allow them `cairn:`
//! actions (`AdministratorAccess`, `CairnOperatorAccess`; see
//! `plans/single-account.md`).
//!
//! Everything lives in Postgres, so every node sees a change immediately. The
//! `cairn user …` subcommands (`cairn role …`, as before) manage it directly
//! against the database, and the console (see `console::manage`) through the same
//! functions.

#[cfg(test)]
use std::collections::HashSet;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Args, Subcommand, ValueEnum};
use deadpool_postgres::Object;
use serde::{Deserialize, Serialize};

use crate::admin::outln;
use crate::db::Cached;

/// A bucket-level permission a role can be granted.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, ValueEnum, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Permission {
    /// GetObject, HeadObject, ListObjects; the source side of a copy.
    Read,
    /// PutObject, DeleteObject(s), multipart uploads; the destination of a copy.
    /// In a versioned bucket, a delete only adds a delete marker.
    Write,
    /// DeleteObject(s) naming a version ID, which removes that version for good.
    DeleteVersion,
}

impl Permission {
    /// The permission a `role_grants.permission` names.
    pub(crate) fn from_db(s: &str) -> anyhow::Result<Permission> {
        match s {
            "read" => Ok(Permission::Read),
            "write" => Ok(Permission::Write),
            "delete-version" => Ok(Permission::DeleteVersion),
            _ => anyhow::bail!("unknown permission {s:?} in role_grants"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Permission::Read => "read",
            Permission::Write => "write",
            Permission::DeleteVersion => "delete-version",
        }
    }
}

/// An authenticated user's secret (its access key's) and permissions, loaded
/// once per request.
pub struct Principal {
    /// The user's ID, which the KMS knows it by (see `kms`).
    pub id: uuid::Uuid,
    pub name: String,
    /// The account the user is of.
    pub account: String,
    /// The secret of the access key the request is signed with.
    pub secret: String,
    /// Whether it has `AdministratorAccess` (see `s3::actions::admin_policy`).
    pub admin: bool,
    /// The user's inline identity policies, as they were set, and then the
    /// documents of its attached managed policies (but AdministratorAccess,
    /// which is `admin`).
    pub policies: Vec<String>,
    /// Its path (`/`, or `/…/`), which its ARN has before its name.
    pub path: String,
    /// Its tags (`aws:PrincipalTag/…`), as they were set.
    pub tags: Vec<(String, String)>,
    /// Its permissions boundary, which caps what its policies allow.
    pub boundary: Option<Boundary>,
    /// Grants, for tests of what they allowed before they were bucket
    /// policies (`s3::authorize`); grants are statements of buckets'
    /// policies now (see `grants`).
    #[cfg(test)]
    read: HashSet<String>,
    #[cfg(test)]
    write: HashSet<String>,
    #[cfg(test)]
    delete_version: HashSet<String>,
}

/// A user's permissions boundary: a managed policy's ARN and document.
#[derive(Clone, Debug)]
pub struct Boundary {
    pub arn: String,
    pub document: String,
}

/// A user's ARN: its account's, its path's and its name's.
pub fn user_arn(account: &str, path: &str, name: &str) -> String {
    format!("arn:aws:iam::{account}:user/{}{name}", path.strip_prefix('/').unwrap_or(path))
}

/// The SQL of a user `r`'s boundary's ARN (NULL if it has none), as its
/// managed policy's (`managed::arn`) or Cairn's.
pub const BOUNDARY_ARN: &str = "(SELECT coalesce(
        (SELECT 'arn:aws:iam::' || m.account_id || ':policy/' || substring(m.path FROM 2) || m.name
         FROM managed_policies m WHERE m.id = r.boundary_policy_id),
        'arn:aws:iam::aws:policy/' || r.boundary_aws))";

/// The SQL of a user `r`'s tags: keys, then values, newest first.
pub const TAG_KEYS: &str = "ARRAY(SELECT t.key FROM user_tags t WHERE t.user_id = r.id ORDER BY t.seq DESC)";
pub const TAG_VALUES: &str = "ARRAY(SELECT t.value FROM user_tags t WHERE t.user_id = r.id ORDER BY t.seq DESC)";

/// Tags as two lists (keys, values), paired.
pub fn tags_of(keys: Vec<String>, values: Vec<String>) -> Vec<(String, String)> {
    keys.into_iter().zip(values).collect()
}

impl Principal {
    /// Its ARN.
    pub fn arn(&self) -> String {
        user_arn(&self.account, &self.path, &self.name)
    }

    /// Loads the user whose active access key `access_key` is, or `None` if
    /// there's none.
    pub async fn load(client: &Object, access_key: &str) -> anyhow::Result<Option<Self>> {
        Self::load_where(client, "FROM access_keys k JOIN users r ON r.id = k.user_id
             WHERE k.access_key_id = $1 AND k.active", "k.secret", &access_key).await
    }

    /// Loads user `id` itself, as the console acts as it (no secret: it
    /// signs nothing), or `None` if there's none.
    pub async fn load_user(client: &Object, id: uuid::Uuid) -> anyhow::Result<Option<Self>> {
        Self::load_where(client, "FROM users r WHERE r.id = $1", "''::text", &id).await
    }

    async fn load_where(
        client: &Object,
        from: &str,
        secret: &str,
        param: &(dyn tokio_postgres::types::ToSql + Sync),
    ) -> anyhow::Result<Option<Self>> {
        let row = client
            .query_opt_cached(
                &format!("SELECT {secret}, r.admin, r.id, r.name, r.account_id,
                        ARRAY(SELECT document FROM user_policies
                              WHERE user_id = r.id AND name NOT LIKE 'cairn:%' ORDER BY name),
                        ARRAY(SELECT m.document FROM user_attached_policies x
                              JOIN managed_policies m ON m.id = x.policy_id WHERE x.user_id = r.id ORDER BY m.name),
                        ARRAY(SELECT x.aws_policy FROM user_attached_policies x
                              WHERE x.user_id = r.id AND x.aws_policy IS NOT NULL ORDER BY x.aws_policy),
                        r.path, {TAG_KEYS}, {TAG_VALUES}, {BOUNDARY_ARN},
                        (SELECT m.document FROM managed_policies m WHERE m.id = r.boundary_policy_id),
                        r.boundary_aws
                 {from}"),
                &[param],
            )
            .await?;
        Ok(row.map(|r| Principal {
            policies: {
                let mut policies: Vec<String> = r.get(5);
                policies.extend(r.get::<_, Vec<String>>(6));
                // Cairn's, by their names (none that isn't one of them).
                let aws: Vec<String> = r.get(7);
                policies.extend(aws.iter().filter_map(|name| crate::managed::aws(name)).map(|p| p.document.to_owned()));
                policies
            },
            path: r.get(8),
            tags: tags_of(r.get(9), r.get(10)),
            boundary: r.get::<_, Option<String>>(11).and_then(|arn| {
                let document = r
                    .get::<_, Option<String>>(12)
                    .or_else(|| r.get::<_, Option<String>>(13).and_then(|name| crate::managed::aws(&name)).map(|p| p.document.to_owned()))
                    // One of Cairn's that this Cairn doesn't know: it
                    // allows nothing, rather than everything.
                    .unwrap_or_else(|| r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}"#.to_owned());
                Some(Boundary { arn, document })
            }),
            secret: r.get(0),
            admin: r.get(1),
            id: r.get(2),
            name: r.get(3),
            account: r.get(4),
            #[cfg(test)]
            read: HashSet::new(),
            #[cfg(test)]
            write: HashSet::new(),
            #[cfg(test)]
            delete_version: HashSet::new(),
        }))
    }

    /// What a grant allowed before there were policies (see `s3::authorize`).
    #[cfg(test)]
    pub fn can(&self, permission: Permission, bucket: &str) -> bool {
        match permission {
            Permission::Read => self.read.contains(bucket),
            Permission::Write => self.write.contains(bucket),
            Permission::DeleteVersion => self.delete_version.contains(bucket),
        }
    }

    /// Whether a role with these grants could learn that `bucket` exists,
    /// before there were policies (see `s3::authorize`).
    #[cfg(test)]
    pub fn can_see(&self, bucket: &str) -> bool {
        self.admin || self.read.contains(bucket) || self.write.contains(bucket) || self.delete_version.contains(bucket)
    }

    /// A role with these grants, for tests.
    #[cfg(test)]
    pub fn for_test(admin: bool, grants: &[(Permission, &str)]) -> Principal {
        let on = |wanted: Permission| {
            grants.iter().filter(|(p, _)| *p == wanted).map(|(_, b)| b.to_string()).collect()
        };
        Principal {
            id: uuid::Uuid::nil(),
            name: "test".to_owned(),
            account: "123456789012".to_owned(),
            secret: String::new(),
            admin,
            read: on(Permission::Read),
            write: on(Permission::Write),
            delete_version: on(Permission::DeleteVersion),
            policies: Vec::new(),
            path: "/".to_owned(),
            tags: Vec::new(),
            boundary: None,
        }
    }

}

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Args, Debug, Serialize, Deserialize)]
pub struct RoleArgs {
    #[command(flatten)]
    #[serde(skip)]
    pub remote: crate::admin::Remote,
    #[command(subcommand)]
    command: RoleCommand,
}

#[derive(Subcommand, Debug, Serialize, Deserialize)]
enum RoleCommand {
    /// Create a user, with an access key of a random ID. Prints the key's
    /// ID and secret; a random secret is generated unless given.
    Create {
        /// The user's name.
        name: String,
        /// Give the key this ID instead of a random one (for scripted
        /// setups that need a known one).
        #[arg(long)]
        id: Option<String>,
        /// Use this secret instead of generating one (at least 8 characters).
        #[arg(long)]
        secret: Option<String>,
        /// Give the user `AdministratorAccess`: everything in its account.
        #[arg(long)]
        admin: bool,
    },
    /// Change a user's admin flag, and/or the secret of its access key named
    /// as it (a migrated role's; others are rotated with `key create` and
    /// `key delete`).
    Update {
        name: String,
        /// Give (true) or take (false) `AdministratorAccess`.
        #[arg(long)]
        admin: Option<bool>,
        /// Replace the secret with a newly generated one, and print it.
        #[arg(long, conflicts_with = "secret")]
        rotate_secret: bool,
        /// Replace the secret with this one (at least 8 characters).
        #[arg(long)]
        secret: Option<String>,
    },
    /// Delete a user, and all its access keys, grants and policies.
    Delete { name: String },
    /// List users, their admin flag, access keys, grants and policies
    /// (secrets are not shown).
    List,
    /// Print a one-time link (valid 24 hours) for a user to register its
    /// first passkey for the console, and sign in. A new link replaces the
    /// user's last; one for a user with passkeys adds another (when it lost
    /// them, say). Made from the node's console URL; if the node serves no
    /// console, only the link's path is printed.
    Enroll { name: String },
    /// Manage a user's access keys (at most two).
    #[command(subcommand)]
    Key(KeyCommand),
    /// Manage a user's inline identity policies (IAM's policy language).
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Grant permissions on an existing bucket of the account: attaches the
    /// account's managed policy `<bucket>-<permission>`, made if needed.
    Grant {
        name: String,
        bucket: String,
        #[arg(required = true, value_enum)]
        permissions: Vec<Permission>,
    },
    /// Revoke permissions on a bucket (detaches their managed policies);
    /// all of them if none are listed.
    Revoke {
        name: String,
        bucket: String,
        #[arg(value_enum)]
        permissions: Vec<Permission>,
    },
    /// Attach a managed policy to a user, by its ARN: Cairn's
    /// (`arn:aws:iam::aws:policy/CairnOperatorAccess`, say) or the account's.
    Attach { name: String, arn: String },
    /// Detach a managed policy from a user (one that denies it, say).
    Detach { name: String, arn: String },
    /// Take a user's permissions boundary off, whatever its policies say:
    /// the way out of a boundary that locks an admin out.
    Unbound { name: String },
}

#[derive(Subcommand, Debug, Serialize, Deserialize)]
enum KeyCommand {
    /// Make a new access key for a user. Prints its ID and secret.
    Create {
        user: String,
        /// Use this ID (else a random one of 20 characters).
        #[arg(long)]
        id: Option<String>,
        /// Use this secret (else a random one).
        #[arg(long)]
        secret: Option<String>,
    },
    /// Delete an access key.
    Delete { id: String },
    /// Let an access key sign requests again.
    Activate { id: String },
    /// Stop an access key from signing requests, without deleting it.
    Deactivate { id: String },
}

#[derive(Subcommand, Debug, Serialize, Deserialize)]
enum PolicyCommand {
    /// Set a user's inline policy `name` to the JSON in `file` (`-`: stdin).
    Put {
        user: String,
        name: String,
        #[serde(skip)]
        file: String,
        /// The file's contents, as the CLI read them (see `prepare`).
        #[arg(skip)]
        document: String,
    },
    /// Print a user's inline policy.
    Get { user: String, name: String },
    /// Delete a user's inline policy.
    Delete { user: String, name: String },
}

impl RoleArgs {
    /// Reads what the command takes from files, where the CLI runs.
    pub fn prepare(&mut self) -> anyhow::Result<()> {
        if let RoleCommand::Policy(PolicyCommand::Put { file, document, .. }) = &mut self.command {
            *document = crate::admin::read_document(file)?;
        }
        Ok(())
    }
}

/// `cairn user …` (or `cairn role …`): user management, on a node (see
/// `admin`).
pub async fn run(app: &std::sync::Arc<crate::App>, args: RoleArgs, out: &mut crate::admin::Output) -> anyhow::Result<()> {
    let client = app.pool.get().await?;
    let account_id = account(&client).await?;
    let account_id = account_id.as_str();
    match args.command {
        RoleCommand::Create {
            name,
            id,
            secret,
            admin,
        } => {
            let generated = secret.is_none();
            let key = match id {
                Some(id) => {
                    validate_name(&id)?;
                    id
                }
                None => generate_key_id()?,
            };
            let (key, secret) = create_with_key(&client, account_id, &name, key, secret, admin).await?;
            outln!(out, "access key: {key}");
            if generated {
                outln!(out, "secret key: {secret}");
            }
            // Its identity in the KMS, so that key owners can grant it keys
            // now; if the KMS can't be reached, the next maintenance pass
            // makes it.
            let identifying = app.clone();
            tokio::spawn(async move {
                if let Err(e) = identify(&identifying).await {
                    eprintln!("kms: identifying roles: {e:#}");
                }
            });
        }
        RoleCommand::Update {
            name,
            admin,
            rotate_secret,
            secret,
        } => {
            let secret = match (rotate_secret, secret) {
                (true, _) => Some(generate_secret()?),
                (false, s) => s,
            };
            update(&client, account_id, &name, admin, secret.clone()).await?;
            if rotate_secret && let Some(s) = secret {
                outln!(out, "secret key: {s}");
            }
        }
        RoleCommand::Delete { name } => delete(&client, account_id, &name).await?,
        RoleCommand::List => {
            for role in list(&client).await?.into_iter().filter(|r| r.account_id == account_id) {
                let admin = if role.admin { " (admin)" } else { "" };
                outln!(out, "{}{admin}", role.name);
                outln!(out, "  {}", user_arn(account_id, &role.path, &role.name));
                if let Some(boundary) = &role.boundary {
                    outln!(out, "  boundary {boundary}");
                }
                for (key, value) in &role.tags {
                    outln!(out, "  tag {key}={value}");
                }
                outln!(out, "  id {}", role.id);
                if let Some(entity) = role.kms_entity_id {
                    outln!(out, "  KMS entity {entity}");
                }
                for key in role.keys {
                    let state = if key.active { "" } else { " (inactive)" };
                    outln!(out, "  key {}{state}", key.id);
                }
                for policy in crate::managed::attached(&client, account_id, &role.name).await? {
                    outln!(out, "  attached {}", policy.arn);
                }
                for policy in role.policies {
                    outln!(out, "  policy {policy}");
                }
            }
        }
        RoleCommand::Enroll { name } => {
            let token = crate::console::store::create_enrollment(&client, account_id, &name).await?;
            enrollment_link(app, &token, out);
        }
        RoleCommand::Key(command) => match command {
            KeyCommand::Create { user, id, secret } => {
                let (id, secret) = create_key(&client, account_id, &user, id, secret).await?;
                outln!(out, "access key: {id}");
                outln!(out, "secret key: {secret}");
            }
            KeyCommand::Delete { id } => delete_key(&client, None, &id).await?,
            KeyCommand::Activate { id } => set_key_active(&client, None, &id, true).await?,
            KeyCommand::Deactivate { id } => set_key_active(&client, None, &id, false).await?,
        },
        RoleCommand::Policy(command) => match command {
            PolicyCommand::Put { user, name, document, .. } => {
                put_policy(&client, account_id, &user, &name, &document).await?;
            }
            PolicyCommand::Get { user, name } => outln!(out, "{}", get_policy(&client, account_id, &user, &name).await?),
            PolicyCommand::Delete { user, name } => delete_policy(&client, account_id, &user, &name).await?,
        },
        RoleCommand::Grant {
            name,
            bucket,
            permissions,
        } => grant(&client, account_id, &name, &bucket, &permissions).await?,
        RoleCommand::Revoke {
            name,
            bucket,
            permissions,
        } => revoke(&client, account_id, &name, &bucket, &permissions).await?,
        RoleCommand::Attach { name, arn } => crate::managed::attach(&client, account_id, &name, &arn, true).await?,
        RoleCommand::Detach { name, arn } => crate::managed::attach(&client, account_id, &name, &arn, false).await?,
        RoleCommand::Unbound { name } => {
            let id = id_of(&client, account_id, &name).await?;
            set_boundary(&client, account_id, id, None).await?;
        }
    }
    Ok(())
}

/// Prints an enrollment link made of `token`: from the node's console URL,
/// or, if it serves no console, the path to open there.
pub(crate) fn enrollment_link(app: &crate::App, token: &str, out: &mut crate::admin::Output) {
    match app.console.origin() {
        Some(origin) => outln!(out, "{origin}/enroll#{token}"),
        None => {
            out.warn("this node serves no console (--listen-console, --console-url): open this path there");
            outln!(out, "/enroll#{token}");
        }
    }
}

/// A request to change roles that can't be carried out as asked: a bad name, an
/// unknown role, and the like. Its message is meant for whoever asked.
#[derive(Debug)]
pub struct Invalid(pub String);

impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Invalid {}

fn invalid(message: impl Into<String>) -> anyhow::Error {
    Invalid(message.into()).into()
}

/// Role names travel inside the SigV4 `Credential=<name>/<date>/…` field, so they
/// must not contain `/`, `,`, or whitespace. Restrict to a conservative set.
fn validate_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(invalid(
            "role name must be non-empty and use only A-Z, a-z, 0-9, '-', '_', '.'",
        ));
    }
    Ok(())
}

/// minio-go clients (mcli, Mimir) refuse secrets shorter than 8 characters.
fn validate_secret(secret: &str) -> anyhow::Result<()> {
    if secret.len() < 8 {
        return Err(invalid("secret must be at least 8 characters"));
    }
    Ok(())
}

/// A random 40-character secret (240 bits, URL-safe base64), the same length as
/// an AWS secret access key.
pub fn generate_secret() -> anyhow::Result<String> {
    let mut bytes = [0u8; 30];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("generating secret: {e}"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Creates a user of the account, with an access key named as
/// it (as a migrated role's, which tests sign with by the user's name), of
/// `secret` or else a generated one, and returns its secret.
#[cfg(test)]
pub async fn create(
    client: &Object,
    name: &str,
    secret: Option<String>,
    admin: bool,
) -> anyhow::Result<String> {
    let account_id = self::account(client).await?;
    Ok(create_with_key(client, &account_id, name, name.to_owned(), secret, admin).await?.1)
}

/// Creates a user of the account `account_id` without access keys, as
/// IAM's CreateUser does (it gets them with `create_key`; `roles.secret`,
/// which older Cairns read, is none that can be guessed), at `path`
/// (checked: see `check_path`), with the permissions boundary `boundary`.
/// Names are unique in an account regardless of case, as IAM's.
pub async fn create_user(
    client: &Object,
    account_id: &str,
    name: &str,
    path: &str,
    boundary: Option<&BoundaryRef>,
) -> anyhow::Result<()> {
    validate_name(name)?;
    let (own, aws) = BoundaryRef::columns(boundary);
    let inserted = client
        .execute_cached(
            "INSERT INTO users (name, secret, admin, account_id, path, boundary_policy_id, boundary_aws)
             SELECT $1, 'unusable:' || gen_random_uuid() || gen_random_uuid(), false, a.id, $3, $4, $5
             FROM accounts a WHERE a.id = $2
             ON CONFLICT DO NOTHING",
            &[&name, &account_id, &path, &own, &aws],
        )
        .await?;
    if inserted == 0 {
        return Err(invalid(format!("a user named {name:?} already exists")));
    }
    Ok(())
}

/// A permissions boundary, as a user keeps it: one of its account's managed
/// policies (by ID), or one of Cairn's (by name).
#[derive(Clone, Debug, PartialEq)]
pub enum BoundaryRef {
    Own(uuid::Uuid),
    Aws(&'static str),
}

impl BoundaryRef {
    /// `roles.boundary_policy_id` and `roles.boundary_aws` for `boundary`.
    pub fn columns(boundary: Option<&BoundaryRef>) -> (Option<uuid::Uuid>, Option<&'static str>) {
        match boundary {
            Some(BoundaryRef::Own(id)) => (Some(*id), None),
            Some(BoundaryRef::Aws(name)) => (None, Some(*name)),
            None => (None, None),
        }
    }
}

/// Sets (or, `None`, removes) the permissions boundary of user `id`, of
/// account `account_id`. A plain UPDATE of the user's row (see catalog.sql's
/// R(r)), whose trigger keeps the inline policy older Cairns read in its
/// place (`db::BOUNDARIES`). Whether there's such a user.
pub async fn set_boundary(client: &Object, account_id: &str, id: uuid::Uuid, boundary: Option<&BoundaryRef>) -> anyhow::Result<bool> {
    let (own, aws) = BoundaryRef::columns(boundary);
    let updated = client
        .execute_cached(
            "UPDATE users SET boundary_policy_id = $3, boundary_aws = $4 WHERE id = $1 AND account_id = $2",
            &[&id, &account_id, &own, &aws],
        )
        .await?;
    Ok(updated == 1)
}

/// Why a path isn't one, as IAM says (probed), for its parameter `param`
/// (`path`, `newPath`, `pathPrefix`); `prefix`: a path prefix, which
/// needn't end in `/`.
pub fn check_path(path: &str, param: &str, prefix: bool) -> Result<(), String> {
    if path.len() > 512 {
        return Err(format!(
            "1 validation error detected: Value at '{param}' failed to satisfy constraint: Member must have length less than or equal to 512"
        ));
    }
    let shape = match prefix {
        true => path.starts_with('/'),
        false => path == "/" || (path.len() >= 3 && path.starts_with('/') && path.ends_with('/')),
    };
    let printable = path.bytes().all(|b| (0x21..=0x7e).contains(&b));
    if !shape || !printable {
        return Err(match prefix {
            true => format!(
                "The specified value for {param} is invalid. It must begin with the / character and contain only alphanumeric characters and/or / characters."
            ),
            false => format!(
                "The specified value for {param} is invalid. It must begin and end with / and contain only alphanumeric characters and/or / characters."
            ),
        });
    }
    if !path.chars().all(|c| c.is_ascii_alphanumeric() || "+=,.@_-/".contains(c)) {
        return Err(format!(
            "The specified value for {param} is invalid. It must begin and end with / and must be alphanumeric, including the following common characters: equal (=), comma (,), period (.), at (@), and hyphen (-)"
        ));
    }
    Ok(())
}

/// Tags user `id` with `tags` (checked: see `iam`), replacing those it has
/// of the same keys (regardless of case), unless it would have more than
/// 50 (T42).
pub async fn tag(client: &Object, id: uuid::Uuid, tags: &[(String, String)]) -> anyhow::Result<()> {
    let keys: Vec<&str> = tags.iter().map(|(k, _)| k.as_str()).collect();
    let values: Vec<&str> = tags.iter().map(|(_, v)| v.as_str()).collect();
    let status: String = client
        .query_one_cached("SELECT pg_temp.cairn_tag_user($1, $2, $3, $4)", &[&id, &keys, &values, &(MAX_TAGS as i32)])
        .await?
        .get(0);
    match status.as_str() {
        "tagged" => Ok(()),
        "too_many" => Err(TooManyTags.into()),
        _ => Err(invalid("no such user")),
    }
}

/// The most tags a user has, as in IAM.
pub const MAX_TAGS: usize = 50;

/// Whether `c` may be in a tag's key or value, as in IAM: letters, digits,
/// spaces and `_.:/=+-@`.
pub fn tag_char(c: char) -> bool {
    c.is_alphanumeric() || (c.is_whitespace() && !c.is_control()) || "_.:/=+-@".contains(c)
}

/// Why `tags` can't be a user's (the console's; the IAM API says it as IAM
/// does: see `iam`).
pub fn check_tags(tags: &[(String, String)]) -> Result<(), String> {
    if tags.len() > MAX_TAGS {
        return Err(format!("a user has at most {MAX_TAGS} tags"));
    }
    let mut seen = std::collections::HashSet::new();
    for (key, value) in tags {
        if !(1..=128).contains(&key.chars().count()) || value.chars().count() > 256 {
            return Err("a tag's key is 1 to 128 characters, its value at most 256".to_owned());
        }
        if !key.chars().all(tag_char) || !value.chars().all(tag_char) {
            return Err("tags hold letters, digits, spaces and _.:/=+-@".to_owned());
        }
        if key.to_ascii_lowercase().starts_with("aws:") {
            return Err("Tag keys beginning with aws: are reserved for system use.".to_owned());
        }
        if !seen.insert(key.to_lowercase()) {
            return Err("Duplicate tag keys found. Please note that Tag keys are case insensitive.".to_owned());
        }
    }
    Ok(())
}

/// The condition keys of a request that sets `tags`: `aws:RequestTag/…`
/// and `aws:TagKeys`.
pub fn request_tags_context(tags: &[(String, String)]) -> crate::policy::Context {
    let mut context = crate::policy::Context::default();
    for (key, value) in tags {
        context.set(&format!("aws:RequestTag/{key}"), value);
    }
    context.set_all("aws:TagKeys", tags.iter().map(|(k, _)| k.clone()).collect());
    context
}

/// A user would have more than `MAX_TAGS` tags.
#[derive(Debug)]
pub struct TooManyTags;

impl std::fmt::Display for TooManyTags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("The number of tags has reached the maximum limit.")
    }
}

impl std::error::Error for TooManyTags {}

/// Removes user `id`'s tags of `keys` (regardless of case), those it has.
pub async fn untag(client: &Object, id: uuid::Uuid, keys: &[String]) -> anyhow::Result<()> {
    client
        .execute_cached(
            "DELETE FROM user_tags WHERE user_id = $1 AND lower(key) IN (SELECT lower(k) FROM unnest($2::text[]) k)",
            &[&id, &keys],
        )
        .await?;
    Ok(())
}

/// Renames user `id` of `account_id` to `name`, at `path` (IAM's
/// UpdateUser). Its keys, policies and grants are its ID's, and stay; the
/// bucket policies that name it name its ID (see `db::PRINCIPAL_IDS`).
pub async fn rename(client: &Object, account_id: &str, id: uuid::Uuid, name: &str, path: &str) -> anyhow::Result<()> {
    validate_name(name)?;
    let updated = client
        .execute_cached("UPDATE users SET name = $3, path = $4 WHERE id = $1 AND account_id = $2", &[&id, &account_id, &name, &path])
        .await;
    match updated {
        Ok(1) => Ok(()),
        Ok(_) => Err(invalid(format!("no user named {name:?}"))),
        Err(e) if e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) => {
            Err(invalid(format!("a user named {name:?} already exists")))
        }
        Err(e) => Err(e.into()),
    }
}

/// A user as IAM's actions on it are checked (see `iam`): its ARN (its
/// path, and name), its tags (`aws:ResourceTag/…`) and its boundary
/// (`iam:PermissionsBoundary`).
#[derive(Clone, Debug)]
pub struct Target {
    pub id: uuid::Uuid,
    pub account: String,
    pub name: String,
    pub path: String,
    pub admin: bool,
    /// When it was made (ISO 8601, as IAM writes times).
    pub created: String,
    /// Its tags, newest first.
    pub tags: Vec<(String, String)>,
    /// Its boundary's ARN.
    pub boundary: Option<String>,
}

impl Target {
    /// User `name` of `account`, if there's one.
    pub async fn load(client: &Object, account: &str, name: &str) -> anyhow::Result<Option<Target>> {
        let row = client
            .query_opt_cached(
                &format!(
                    "SELECT r.id, r.name, r.path, r.admin,
                            to_char(r.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
                            {TAG_KEYS}, {TAG_VALUES}, {BOUNDARY_ARN}
                     FROM users r WHERE r.account_id = $1 AND lower(r.name) = lower($2)"
                ),
                &[&account, &name],
            )
            .await?;
        Ok(row.map(|r| Target {
            id: r.get(0),
            account: account.to_owned(),
            name: r.get(1),
            path: r.get(2),
            admin: r.get(3),
            created: r.get(4),
            tags: tags_of(r.get(5), r.get(6)),
            boundary: r.get(7),
        }))
    }

    /// Its ARN.
    pub fn arn(&self) -> String {
        user_arn(&self.account, &self.path, &self.name)
    }

    /// What IAM's actions on it are checked against.
    pub fn on(&self) -> crate::s3::actions::On {
        crate::s3::actions::On::user(&self.account, &self.path, &self.name)
    }

    /// The condition keys of `action` on it: its tags, as
    /// `aws:ResourceTag/…` and `iam:ResourceTag/…`, and (for the actions
    /// that take it, but CreateUser and PutUserPermissionsBoundary, which
    /// are about the boundary asked for) its boundary, as
    /// `iam:PermissionsBoundary` (probed).
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

/// The actions on a user whose `iam:PermissionsBoundary` is the user's
/// boundary (as it is), from IAM's service reference (probed).
const CURRENT_BOUNDARY_ACTIONS: &[&str] = &[
    "iam:AttachUserPolicy",
    "iam:DetachUserPolicy",
    "iam:PutUserPolicy",
    "iam:DeleteUserPolicy",
    "iam:DeleteUserPermissionsBoundary",
];

/// Creates a user of the account `account_id`, with an access key of a
/// random ID, as IAM makes them: the key's ID and secret.
#[cfg(test)]
pub async fn create_for(
    client: &Object,
    account_id: &str,
    name: &str,
    secret: Option<String>,
    admin: bool,
) -> anyhow::Result<(String, String)> {
    create_with_key(client, account_id, name, generate_key_id()?, secret, admin).await
}

/// Creates a user of the account `account_id`, with the access key `key`.
async fn create_with_key(
    client: &Object,
    account_id: &str,
    name: &str,
    key: String,
    secret: Option<String>,
    admin: bool,
) -> anyhow::Result<(String, String)> {
    validate_name(name)?;
    let secret = match secret {
        Some(s) => {
            validate_secret(&s)?;
            s
        }
        None => generate_secret()?,
    };
    // One statement: the user and its key, or neither. (`roles.secret` is
    // what older Cairns authenticate with, as the key named as the user:
    // the key's secret if it's that one, else none that can be guessed;
    // the key's trigger keeps it.)
    let inserted = client
        .execute_cached(
            "WITH r AS (
                 INSERT INTO users (name, secret, admin, account_id)
                 VALUES ($1, CASE WHEN $5 = $1 THEN $2
                             ELSE 'unusable:' || gen_random_uuid() || gen_random_uuid() END, $3, $4)
                 ON CONFLICT DO NOTHING RETURNING id
             )
             INSERT INTO access_keys (access_key_id, user_id, secret) SELECT $5, id, $2 FROM r",
            &[&name, &secret, &admin, &account_id, &key],
        )
        .await;
    match inserted {
        Ok(0) => Err(invalid(format!("a user named {name:?} already exists"))),
        Ok(_) => Ok((key, secret)),
        Err(e) if e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) => {
            Err(invalid(format!("an access key named {key:?} already exists")))
        }
        Err(e) => Err(e.into()),
    }
}

/// The account's ID (see `accounts`): Cairn has one, which every user,
/// bucket and policy belongs to. It never changes, so it's read once.
pub async fn account(client: &Object) -> anyhow::Result<String> {
    static ACCOUNT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    if let Some(account) = ACCOUNT.get() {
        return Ok(account.clone());
    }
    // (The operator account's row, which older nodes read, is empty.)
    let account: String = client.query_one_cached("SELECT id FROM accounts WHERE NOT operator", &[]).await?.get(0);
    // Each test's database has an account of its own.
    if !cfg!(test) {
        let _ = ACCOUNT.set(account.clone());
    }
    Ok(account)
}

/// The most access keys a user may have, as in IAM.
const MAX_KEYS: i32 = 2;

/// A random access key ID: 20 characters of base32, as long as AWS's.
fn generate_key_id() -> anyhow::Result<String> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bytes = [0u8; 20];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("generating an access key ID: {e}"))?;
    Ok(bytes.iter().map(|b| ALPHABET[(*b & 31) as usize] as char).collect())
}

/// User `name` of account `account` (its ID): its ID, if there's one.
pub async fn id_of(client: &Object, account: &str, name: &str) -> anyhow::Result<uuid::Uuid> {
    client
        .query_opt_cached("SELECT id FROM users WHERE account_id = $1 AND lower(name) = lower($2)", &[&account, &name])
        .await?
        .map(|row| row.get(0))
        .ok_or_else(|| invalid(format!("no user named {name:?}")))
}

/// Makes a new access key for `user` of `account` (with `id` and `secret`,
/// or random ones), if it has fewer than two. Returns them.
pub async fn create_key(
    client: &Object,
    account: &str,
    user: &str,
    id: Option<String>,
    secret: Option<String>,
) -> anyhow::Result<(String, String)> {
    let id = match id {
        Some(id) => {
            validate_name(&id)?;
            id
        }
        None => generate_key_id()?,
    };
    let secret = match secret {
        Some(s) => {
            validate_secret(&s)?;
            s
        }
        None => generate_secret()?,
    };
    let role = id_of(client, account, user).await?;
    // At most two (I10: `cairn_create_key` counts them under the user's
    // row, held exclusively).
    let status = client
        .query_one_cached("SELECT pg_temp.cairn_create_key($1, $2, $3, $4)", &[&role, &id, &secret, &MAX_KEYS])
        .await?;
    match status.get::<_, &str>(0) {
        "created" => Ok((id, secret)),
        "no_such_user" => Err(invalid(format!("no user named {user:?}"))),
        "too_many" => Err(invalid(format!("{user:?} has {MAX_KEYS} access keys already; delete one first"))),
        "taken" => Err(invalid(format!("an access key named {id:?} already exists"))),
        status => unreachable!("cairn_create_key: unknown status {status}"),
    }
}

/// That there's no access key `id` (of `user`, if given).
fn no_such_key(user: Option<(&str, &str)>, id: &str) -> anyhow::Error {
    match user {
        Some((_, user)) => invalid(format!("{user:?} has no access key {id:?}")),
        None => invalid(format!("no access key {id:?}")),
    }
}

/// Deletes an access key; only `user`'s (account ID, name), if given.
pub async fn delete_key(client: &Object, user: Option<(&str, &str)>, id: &str) -> anyhow::Result<()> {
    let (account, name) = user.unzip();
    let deleted = client
        .execute_cached(
            "DELETE FROM access_keys k USING users r
             WHERE k.access_key_id = $1 AND r.id = k.user_id
               AND ($2::text IS NULL OR (r.account_id = $2 AND lower(r.name) = lower($3)))",
            &[&id, &account, &name],
        )
        .await?;
    if deleted == 0 {
        return Err(no_such_key(user, id));
    }
    Ok(())
}

/// Lets an access key sign requests, or stops it; only `user`'s (account
/// ID, name), if given.
pub async fn set_key_active(client: &Object, user: Option<(&str, &str)>, id: &str, active: bool) -> anyhow::Result<()> {
    let (account, name) = user.unzip();
    let updated = client
        .execute_cached(
            "UPDATE access_keys k SET active = $3 FROM users r
             WHERE k.access_key_id = $1 AND r.id = k.user_id
               AND ($2::text IS NULL OR (r.account_id = $2 AND lower(r.name) = lower($4)))",
            &[&id, &account, &active, &name],
        )
        .await?;
    if updated == 0 {
        return Err(no_such_key(user, id));
    }
    Ok(())
}

/// The most a user's inline policies may hold together, in characters
/// other than whitespace, as in IAM.
const MAX_POLICIES: usize = 2048;

/// Whether `name` may name an inline policy, as in IAM.
fn validate_policy_name(name: &str) -> anyhow::Result<()> {
    let valid = (1..=128).contains(&name.len())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "+=,.@_-".contains(c));
    if !valid {
        return Err(invalid("a policy's name must be 1 to 128 of A-Z, a-z, 0-9 and +=,.@_-"));
    }
    Ok(())
}

/// Sets `user`'s inline policy `name` to `document`, if it's a valid
/// identity policy (see `policy`), and the user's policies stay within
/// IAM's size.
pub async fn put_policy(client: &Object, account: &str, user: &str, name: &str, document: &str) -> anyhow::Result<()> {
    validate_policy_name(name)?;
    crate::policy::Policy::parse(document, crate::policy::Kind::Identity)
        .map_err(|e| invalid(format!("{}: {}", e.code, e.message)))?;
    // Within IAM's size (I10: `cairn_put_policy` sizes them under the
    // user's row, held exclusively).
    let max = MAX_POLICIES as i32;
    let role = id_of(client, account, user).await?;
    let status = client
        .query_one_cached("SELECT pg_temp.cairn_put_policy($1, $2, $3, $4)", &[&role, &name, &document, &max])
        .await?;
    match status.get::<_, &str>(0) {
        "set" => Ok(()),
        "no_such_user" => Err(invalid(format!("no user named {user:?}"))),
        "too_big" => Err(invalid(format!(
            "a user's inline policies may hold {MAX_POLICIES} characters (but whitespace) together"
        ))),
        status => unreachable!("cairn_put_policy: unknown status {status}"),
    }
}

/// `user`'s inline policy `name`, as it was set.
pub async fn get_policy(client: &Object, account: &str, user: &str, name: &str) -> anyhow::Result<String> {
    let row = client
        .query_opt_cached(
            "SELECT p.document FROM user_policies p JOIN users r ON r.id = p.user_id
             WHERE r.account_id = $3 AND lower(r.name) = lower($1) AND p.name = $2 AND p.name NOT LIKE 'cairn:%'",
            &[&user, &name, &account],
        )
        .await?;
    row.map(|r| r.get(0)).ok_or_else(|| invalid(format!("{user:?} has no policy {name:?}")))
}

/// Deletes `user`'s inline policy `name`.
pub async fn delete_policy(client: &Object, account: &str, user: &str, name: &str) -> anyhow::Result<()> {
    let deleted = client
        .execute_cached(
            "DELETE FROM user_policies p USING users r
             WHERE r.id = p.user_id AND r.account_id = $3 AND lower(r.name) = lower($1) AND p.name = $2 AND p.name NOT LIKE 'cairn:%'",
            &[&user, &name, &account],
        )
        .await?;
    if deleted == 0 {
        return Err(invalid(format!("{user:?} has no policy {name:?}")));
    }
    Ok(())
}

/// Changes a role's admin flag and/or secret.
pub async fn update(
    client: &Object,
    account: &str,
    name: &str,
    admin: Option<bool>,
    secret: Option<String>,
) -> anyhow::Result<()> {
    if admin.is_none() && secret.is_none() {
        return Err(invalid(
            "nothing to update; pass --admin, --secret, or --rotate-secret",
        ));
    }
    if let Some(s) = &secret {
        validate_secret(s)?;
    }
    if let Some(admin) = admin {
        let updated = client
            .execute_cached("UPDATE users SET admin = $2 WHERE lower(name) = lower($1) AND account_id = $3", &[&name, &admin, &account])
            .await?;
        if updated == 0 {
            return Err(invalid(format!("no user named {name:?}")));
        }
    }
    if let Some(secret) = secret {
        // The key named as the user (a migrated role's only one).
        let updated = client
            .execute_cached(
                "UPDATE access_keys k SET secret = $2 FROM users r
                 WHERE lower(r.name) = lower($1) AND r.account_id = $3 AND k.user_id = r.id AND k.access_key_id = r.name",
                &[&name, &secret, &account],
            )
            .await?;
        if updated == 0 {
            return Err(invalid(format!(
                "no access key named as the user {name:?}; rotate its keys by making a new one and deleting the old"
            )));
        }
    }
    Ok(())
}

/// Deletes a role and all its grants.
pub async fn delete(client: &Object, account: &str, name: &str) -> anyhow::Result<()> {
    let role = id_of(client, account, name).await?;
    let deleted: bool = client
        .query_one_cached("SELECT pg_temp.cairn_delete_user($1)", &[&role])
        .await?
        .get(0);
    if !deleted {
        return Err(invalid(format!("no user named {name:?}")));
    }
    Ok(())
}

/// Logs in to the KMS once as each role that has no identity (entity) there
/// yet, so that OpenBao makes it, and keeps its ID (see `kms`): then key
/// owners can grant the role keys before it uses any. Likewise as Cairn
/// itself, for SSE-S3, once on each node. A role the KMS can't
/// be asked about now is tried again in the next maintenance pass.
pub async fn identify(app: &crate::App) -> anyhow::Result<()> {
    let Some(kms) = &app.kms else { return Ok(()) };
    // Cairn's own, for SSE-S3, which the KMS's admin grants its key.
    if kms.sse_s3_key().is_some() && kms.cairn_entity().is_none() {
        let entity = kms.identify(crate::kms::Identity::Cairn).await.map_err(|e| anyhow::anyhow!("Cairn itself: {e}"))?;
        eprintln!("kms: Cairn's own identity (for SSE-S3) is the entity {entity}");
    }
    let client = app.pool.get().await?;
    let roles: Vec<uuid::Uuid> = client
        .query_cached("SELECT id FROM users WHERE kms_entity_id IS NULL ORDER BY created_at", &[])
        .await?
        .iter()
        .map(|row| row.get(0))
        .collect();
    drop(client);
    for role in roles {
        let entity = kms.identify(crate::kms::Identity::Role(role)).await.map_err(|e| anyhow::anyhow!("role {role}: {e}"))?;
        // A plain write of one row's own column: no invariant of the lock
        // protocol (see `catalog.sql`) involves it.
        app.pool
            .get()
            .await?
            .execute_cached("UPDATE users SET kms_entity_id = $2 WHERE id = $1", &[&role, &entity])
            .await?;
    }
    Ok(())
}

/// An access key as listed: never with its secret.
pub struct KeyInfo {
    pub id: String,
    pub active: bool,
    /// When it was made, in seconds since the Unix epoch.
    pub created_at: f64,
}

/// A user as listed: never with its secrets.
pub struct RoleInfo {
    pub name: String,
    /// Its account's ID.
    pub account_id: String,
    pub admin: bool,
    /// When it was created, in seconds since the Unix epoch.
    pub created_at: f64,
    /// Its ID, which the KMS knows it by (see `kms`).
    pub id: uuid::Uuid,
    /// Its identity (entity) in the KMS, once Cairn has logged in as it.
    pub kms_entity_id: Option<String>,
    /// Its access keys, oldest first.
    pub keys: Vec<KeyInfo>,
    /// The names of its inline policies, sorted.
    pub policies: Vec<String>,
    /// Its path (`/`, or `/…/`).
    pub path: String,
    /// Its tags, newest first.
    pub tags: Vec<(String, String)>,
    /// Its permissions boundary's ARN.
    pub boundary: Option<String>,
}

/// Every role, by name.
pub async fn list(client: &Object) -> anyhow::Result<Vec<RoleInfo>> {
    let rows = client
        .query_cached(
            &format!("SELECT r.name, r.admin, extract(epoch FROM r.created_at)::float8,
                    NULL, NULL,
                    r.id, r.kms_entity_id,
                    ARRAY(SELECT k.access_key_id FROM access_keys k WHERE k.user_id = r.id
                          ORDER BY k.created_at, k.access_key_id),
                    ARRAY(SELECT k.active FROM access_keys k WHERE k.user_id = r.id
                          ORDER BY k.created_at, k.access_key_id),
                    ARRAY(SELECT extract(epoch FROM k.created_at)::float8 FROM access_keys k
                          WHERE k.user_id = r.id ORDER BY k.created_at, k.access_key_id),
                    ARRAY(SELECT p.name FROM user_policies p WHERE p.user_id = r.id AND p.name NOT LIKE 'cairn:%' ORDER BY p.name),
                    r.account_id, r.path, {TAG_KEYS}, {TAG_VALUES}, {BOUNDARY_ARN}
             FROM users r ORDER BY r.name"),
            &[],
        )
        .await?;
    rows.iter()
        .map(|r| {
            Ok(RoleInfo {
                name: r.get(0),
                admin: r.get(1),
                created_at: r.get(2),
                id: r.get(5),
                kms_entity_id: r.get(6),
                keys: r
                    .get::<_, Vec<String>>(7)
                    .into_iter()
                    .zip(r.get::<_, Vec<bool>>(8))
                    .zip(r.get::<_, Vec<f64>>(9))
                    .map(|((id, active), created_at)| KeyInfo { id, active, created_at })
                    .collect(),
                policies: r.get(10),
                account_id: r.get(11),
                path: r.get(12),
                tags: tags_of(r.get(13), r.get(14)),
                boundary: r.get(15),
            })
        })
        .collect()
}

/// Grants `name` (of `account`) permissions on an existing bucket of its
/// account: as statements of the bucket's policy (see `grants`).
pub async fn grant(
    client: &Object,
    account: &str,
    name: &str,
    bucket: &str,
    permissions: &[Permission],
) -> anyhow::Result<()> {
    id_of(client, account, name).await?;
    crate::grants::change(client, account, name, bucket, permissions, true).await
}

/// Revokes `name`'s (of `account`) permissions on a bucket; all of them if
/// none are given.
pub async fn revoke(
    client: &Object,
    account: &str,
    name: &str,
    bucket: &str,
    permissions: &[Permission],
) -> anyhow::Result<()> {
    id_of(client, account, name).await?;
    let all = [Permission::Read, Permission::Write, Permission::DeleteVersion];
    let permissions = if permissions.is_empty() { &all[..] } else { permissions };
    crate::grants::change(client, account, name, bucket, permissions, false).await
}
