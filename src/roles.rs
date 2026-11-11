//! Users (called roles before; still the `roles` table): who may make S3
//! requests, with which access keys, and what each may do.
//!
//! A user has a name (its ARN is `arn:aws:iam::<account>:user/<name>`), up to
//! two access keys (an ID and a secret; the first is named as the user, as a
//! role's one key was), and permissions: it may be an *admin*, which allows
//! bucket management (create / delete / list every bucket), it holds
//! per-bucket `read` / `write` / `delete-version` grants for object access,
//! and it may have inline identity policies of its own (see `policy`). Admin
//! does not imply object access; that always needs a grant (or a policy).
//!
//! Everything lives in Postgres, so every node sees a change immediately. The
//! `cairn user …` subcommands (`cairn role …`, as before) manage it directly
//! against the database, and the dashboard (see `dashboard`) through the same
//! functions.

use std::collections::HashSet;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Args, Subcommand, ValueEnum};
use deadpool_postgres::Object;
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
    fn from_db(s: &str) -> anyhow::Result<Permission> {
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
    /// The account the user is of (the cluster's).
    pub account: String,
    /// The secret of the access key the request is signed with.
    pub secret: String,
    pub admin: bool,
    read: HashSet<String>,
    write: HashSet<String>,
    delete_version: HashSet<String>,
    /// The user's inline identity policies, as they were set.
    pub policies: Vec<String>,
}

impl Principal {
    /// Loads the user whose active access key `access_key` is, or `None` if
    /// there's none.
    pub async fn load(client: &Object, access_key: &str) -> anyhow::Result<Option<Self>> {
        let row = client
            .query_opt_cached(
                "SELECT k.secret, r.admin, r.id, r.name, (SELECT id FROM accounts),
                        ARRAY(SELECT bucket FROM role_grants
                              WHERE role = r.name AND permission = 'read'),
                        ARRAY(SELECT bucket FROM role_grants
                              WHERE role = r.name AND permission = 'write'),
                        ARRAY(SELECT bucket FROM role_grants
                              WHERE role = r.name AND permission = 'delete-version'),
                        ARRAY(SELECT document FROM role_policies WHERE role_id = r.id ORDER BY name)
                 FROM access_keys k JOIN roles r ON r.id = k.role_id
                 WHERE k.access_key_id = $1 AND k.active",
                &[&access_key],
            )
            .await?;
        Ok(row.map(|r| Principal {
            secret: r.get(0),
            admin: r.get(1),
            id: r.get(2),
            name: r.get(3),
            account: r.get(4),
            read: r.get::<_, Vec<String>>(5).into_iter().collect(),
            write: r.get::<_, Vec<String>>(6).into_iter().collect(),
            delete_version: r.get::<_, Vec<String>>(7).into_iter().collect(),
            policies: r.get(8),
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
        }
    }

    /// The user's grants, as (permission, bucket).
    pub fn grants(&self) -> impl Iterator<Item = (Permission, &str)> {
        let read = self.read.iter().map(|b| (Permission::Read, b.as_str()));
        let write = self.write.iter().map(|b| (Permission::Write, b.as_str()));
        let delete_version = self.delete_version.iter().map(|b| (Permission::DeleteVersion, b.as_str()));
        read.chain(write).chain(delete_version)
    }

    /// Whether the role may learn that `bucket` exists: admins see every bucket,
    /// others only the ones they hold a grant on.
    pub fn can_see(&self, bucket: &str) -> bool {
        self.admin
            || self.read.contains(bucket)
            || self.write.contains(bucket)
            || self.delete_version.contains(bucket)
    }
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct RoleArgs {
    /// PostgreSQL connection string (the same one the nodes use).
    #[arg(long, env = "CAIRN_DATABASE", hide_env_values = true)]
    database: String,
    #[command(subcommand)]
    command: RoleCommand,
}

#[derive(Subcommand, Debug)]
enum RoleCommand {
    /// Create a user, with an access key named as it. Prints the key's
    /// secret; a random one is generated unless given.
    Create {
        /// The user's name, which its first access key's ID is too.
        name: String,
        /// Use this secret instead of generating one (at least 8 characters).
        #[arg(long)]
        secret: Option<String>,
        /// Allow the user to create, delete, and list all buckets.
        #[arg(long)]
        admin: bool,
    },
    /// Change a user's admin flag, and/or the secret of its access key named
    /// as it.
    Update {
        name: String,
        /// Grant (true) or revoke (false) bucket management.
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
    /// Manage a user's access keys (at most two).
    #[command(subcommand)]
    Key(KeyCommand),
    /// Manage a user's inline identity policies (IAM's policy language).
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Grant permissions on an existing bucket. Grants are removed when their
    /// bucket is deleted.
    Grant {
        name: String,
        bucket: String,
        #[arg(required = true, value_enum)]
        permissions: Vec<Permission>,
    },
    /// Revoke permissions on a bucket; all of them if none are listed.
    Revoke {
        name: String,
        bucket: String,
        #[arg(value_enum)]
        permissions: Vec<Permission>,
    },
}

#[derive(Subcommand, Debug)]
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

#[derive(Subcommand, Debug)]
enum PolicyCommand {
    /// Set a user's inline policy `name` to the JSON in `file` (`-`: stdin).
    Put { user: String, name: String, file: String },
    /// Print a user's inline policy.
    Get { user: String, name: String },
    /// Delete a user's inline policy.
    Delete { user: String, name: String },
}

/// `cairn user …` (or `cairn role …`): user management, straight against
/// the database.
pub async fn role_main(args: RoleArgs) -> anyhow::Result<()> {
    let pool = crate::db::connect(&args.database).await?;
    let client = pool.get().await?;
    match args.command {
        RoleCommand::Create {
            name,
            secret,
            admin,
        } => {
            let generated = secret.is_none();
            let secret = create(&client, &name, secret, admin).await?;
            println!("access key: {name}");
            if generated {
                println!("secret key: {secret}");
            }
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
            update(&client, &name, admin, secret.clone()).await?;
            if rotate_secret && let Some(s) = secret {
                println!("secret key: {s}");
            }
        }
        RoleCommand::Delete { name } => delete(&client, &name).await?,
        RoleCommand::List => {
            let account = account(&client).await?;
            for role in list(&client).await? {
                let admin = if role.admin { " (admin)" } else { "" };
                println!("{}{admin}", role.name);
                println!("  arn:aws:iam::{account}:user/{}", role.name);
                println!("  id {}", role.id);
                if let Some(entity) = role.kms_entity_id {
                    println!("  KMS entity {entity}");
                }
                for key in role.keys {
                    let state = if key.active { "" } else { " (inactive)" };
                    println!("  key {}{state}", key.id);
                }
                for (bucket, permission) in role.grants {
                    println!("  {bucket}:{}", permission.as_str());
                }
                for policy in role.policies {
                    println!("  policy {policy}");
                }
            }
        }
        RoleCommand::Key(command) => match command {
            KeyCommand::Create { user, id, secret } => {
                let (id, secret) = create_key(&client, &user, id, secret).await?;
                println!("access key: {id}");
                println!("secret key: {secret}");
            }
            KeyCommand::Delete { id } => delete_key(&client, &id).await?,
            KeyCommand::Activate { id } => set_key_active(&client, &id, true).await?,
            KeyCommand::Deactivate { id } => set_key_active(&client, &id, false).await?,
        },
        RoleCommand::Policy(command) => match command {
            PolicyCommand::Put { user, name, file } => {
                let document = match file.as_str() {
                    "-" => std::io::read_to_string(std::io::stdin())?,
                    path => std::fs::read_to_string(path)?,
                };
                put_policy(&client, &user, &name, &document).await?;
            }
            PolicyCommand::Get { user, name } => println!("{}", get_policy(&client, &user, &name).await?),
            PolicyCommand::Delete { user, name } => delete_policy(&client, &user, &name).await?,
        },
        RoleCommand::Grant {
            name,
            bucket,
            permissions,
        } => grant(&client, &name, &bucket, &permissions).await?,
        RoleCommand::Revoke {
            name,
            bucket,
            permissions,
        } => revoke(&client, &name, &bucket, &permissions).await?,
    }
    Ok(())
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

/// Creates a user, with an access key named as it, of `secret` or else a
/// generated one, and returns its secret.
pub async fn create(
    client: &Object,
    name: &str,
    secret: Option<String>,
    admin: bool,
) -> anyhow::Result<String> {
    validate_name(name)?;
    let secret = match secret {
        Some(s) => {
            validate_secret(&s)?;
            s
        }
        None => generate_secret()?,
    };
    if key_exists(client, name).await? {
        return Err(invalid(format!("an access key named {name:?} already exists")));
    }
    // One statement: the user and its key, or neither. (`roles.secret` is
    // what older Cairns authenticate with; the key's trigger keeps it.)
    let inserted = client
        .execute_cached(
            "WITH r AS (
                 INSERT INTO roles (name, secret, admin) VALUES ($1, $2, $3)
                 ON CONFLICT DO NOTHING RETURNING id
             )
             INSERT INTO access_keys (access_key_id, role_id, secret) SELECT $1, id, $2 FROM r",
            &[&name, &secret, &admin],
        )
        .await;
    match inserted {
        Ok(0) => Err(invalid(format!("a user named {name:?} already exists"))),
        Ok(_) => Ok(secret),
        // Another key took the name meanwhile.
        Err(e) if e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) => {
            Err(invalid(format!("an access key named {name:?} already exists")))
        }
        Err(e) => Err(e.into()),
    }
}

/// The cluster's account ID (see `accounts`), which never changes (until
/// there are tenants), so it's read once.
pub async fn account(client: &Object) -> anyhow::Result<String> {
    static ACCOUNT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    if let Some(account) = ACCOUNT.get() {
        return Ok(account.clone());
    }
    let account: String = client.query_one_cached("SELECT id FROM accounts", &[]).await?.get(0);
    // Each test's database has an account of its own.
    if !cfg!(test) {
        let _ = ACCOUNT.set(account.clone());
    }
    Ok(account)
}

async fn key_exists(client: &Object, id: &str) -> anyhow::Result<bool> {
    Ok(client.query_opt_cached("SELECT 1 FROM access_keys WHERE access_key_id = $1", &[&id]).await?.is_some())
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

/// Makes a new access key for `user` (with `id` and `secret`, or random
/// ones), if it has fewer than two. Returns them.
pub async fn create_key(
    client: &Object,
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
    // At most two (I10: `cairn_create_key` counts them under the user's
    // row, held exclusively).
    let status = client
        .query_one_cached("SELECT pg_temp.cairn_create_key($1, $2, $3, $4)", &[&user, &id, &secret, &MAX_KEYS])
        .await?;
    match status.get::<_, &str>(0) {
        "created" => Ok((id, secret)),
        "no_such_user" => Err(invalid(format!("no user named {user:?}"))),
        "too_many" => Err(invalid(format!("{user:?} has {MAX_KEYS} access keys already; delete one first"))),
        "taken" => Err(invalid(format!("an access key named {id:?} already exists"))),
        status => unreachable!("cairn_create_key: unknown status {status}"),
    }
}

/// Deletes an access key.
pub async fn delete_key(client: &Object, id: &str) -> anyhow::Result<()> {
    let deleted = client.execute_cached("DELETE FROM access_keys WHERE access_key_id = $1", &[&id]).await?;
    if deleted == 0 {
        return Err(invalid(format!("no access key {id:?}")));
    }
    Ok(())
}

/// Lets an access key sign requests, or stops it.
pub async fn set_key_active(client: &Object, id: &str, active: bool) -> anyhow::Result<()> {
    let updated = client
        .execute_cached("UPDATE access_keys SET active = $2 WHERE access_key_id = $1", &[&id, &active])
        .await?;
    if updated == 0 {
        return Err(invalid(format!("no access key {id:?}")));
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
pub async fn put_policy(client: &Object, user: &str, name: &str, document: &str) -> anyhow::Result<()> {
    validate_policy_name(name)?;
    crate::policy::Policy::parse(document, crate::policy::Kind::Identity)
        .map_err(|e| invalid(format!("{}: {}", e.code, e.message)))?;
    // Within IAM's size (I10: `cairn_put_policy` sizes them under the
    // user's row, held exclusively).
    let max = MAX_POLICIES as i32;
    let status = client
        .query_one_cached("SELECT pg_temp.cairn_put_policy($1, $2, $3, $4)", &[&user, &name, &document, &max])
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
pub async fn get_policy(client: &Object, user: &str, name: &str) -> anyhow::Result<String> {
    let row = client
        .query_opt_cached(
            "SELECT p.document FROM role_policies p JOIN roles r ON r.id = p.role_id
             WHERE r.name = $1 AND p.name = $2",
            &[&user, &name],
        )
        .await?;
    row.map(|r| r.get(0)).ok_or_else(|| invalid(format!("{user:?} has no policy {name:?}")))
}

/// Deletes `user`'s inline policy `name`.
pub async fn delete_policy(client: &Object, user: &str, name: &str) -> anyhow::Result<()> {
    let deleted = client
        .execute_cached(
            "DELETE FROM role_policies p USING roles r WHERE r.id = p.role_id AND r.name = $1 AND p.name = $2",
            &[&user, &name],
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
        let updated = client.execute_cached("UPDATE roles SET admin = $2 WHERE name = $1", &[&name, &admin]).await?;
        if updated == 0 {
            return Err(invalid(format!("no user named {name:?}")));
        }
    }
    if let Some(secret) = secret {
        // The key named as the user (its first, a role's only one).
        let updated = client
            .execute_cached(
                "UPDATE access_keys k SET secret = $2 FROM roles r
                 WHERE r.name = $1 AND k.role_id = r.id AND k.access_key_id = r.name",
                &[&name, &secret],
            )
            .await?;
        if updated == 0 {
            return Err(invalid(format!(
                "no access key named as the user {name:?}; make the user a new key instead"
            )));
        }
    }
    Ok(())
}

/// Deletes a role and all its grants.
pub async fn delete(client: &Object, name: &str) -> anyhow::Result<()> {
    // Its grants are locked in the lock protocol's order first (see
    // `cairn_delete_role`).
    let deleted: bool = client
        .query_one_cached("SELECT pg_temp.cairn_delete_role($1)", &[&name])
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
        .query_cached("SELECT id FROM roles WHERE kms_entity_id IS NULL ORDER BY created_at", &[])
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
            .execute_cached("UPDATE roles SET kms_entity_id = $2 WHERE id = $1", &[&role, &entity])
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
    pub admin: bool,
    /// When it was created, in seconds since the Unix epoch.
    pub created_at: f64,
    /// Its ID, which the KMS knows it by (see `kms`).
    pub id: uuid::Uuid,
    /// Its identity (entity) in the KMS, once Cairn has logged in as it.
    pub kms_entity_id: Option<String>,
    /// (bucket, permission), sorted.
    pub grants: Vec<(String, Permission)>,
    /// Its access keys, oldest first.
    pub keys: Vec<KeyInfo>,
    /// The names of its inline policies, sorted.
    pub policies: Vec<String>,
}

/// Every role, by name.
pub async fn list(client: &Object) -> anyhow::Result<Vec<RoleInfo>> {
    let rows = client
        .query_cached(
            "SELECT r.name, r.admin, extract(epoch FROM r.created_at)::float8,
                    ARRAY(SELECT g.bucket FROM role_grants g
                          WHERE g.role = r.name ORDER BY g.bucket, g.permission),
                    ARRAY(SELECT g.permission FROM role_grants g
                          WHERE g.role = r.name ORDER BY g.bucket, g.permission),
                    r.id, r.kms_entity_id,
                    ARRAY(SELECT k.access_key_id FROM access_keys k WHERE k.role_id = r.id
                          ORDER BY k.created_at, k.access_key_id),
                    ARRAY(SELECT k.active FROM access_keys k WHERE k.role_id = r.id
                          ORDER BY k.created_at, k.access_key_id),
                    ARRAY(SELECT extract(epoch FROM k.created_at)::float8 FROM access_keys k
                          WHERE k.role_id = r.id ORDER BY k.created_at, k.access_key_id),
                    ARRAY(SELECT p.name FROM role_policies p WHERE p.role_id = r.id ORDER BY p.name)
             FROM roles r ORDER BY r.name",
            &[],
        )
        .await?;
    rows.iter()
        .map(|r| {
            let buckets = r.get::<_, Vec<String>>(3);
            let permissions = r.get::<_, Vec<String>>(4);
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
                grants: buckets
                    .into_iter()
                    .zip(permissions.iter())
                    .map(|(bucket, p)| Ok((bucket, Permission::from_db(p)?)))
                    .collect::<anyhow::Result<_>>()?,
            })
        })
        .collect()
}

/// Fails with a clear message if `name` isn't a role, so a grant/revoke on a
/// typo'd name doesn't silently do nothing (or trip the FK with a raw error).
async fn require_role(client: &Object, name: &str) -> anyhow::Result<()> {
    if client
        .query_opt_cached("SELECT 1 FROM roles WHERE name = $1", &[&name])
        .await?
        .is_none()
    {
        return Err(invalid(format!("no user named {name:?}")));
    }
    Ok(())
}

/// Grants permissions on an existing bucket (`cairn_grant`, which locks the
/// bucket and the role in the lock protocol's order before inserting).
pub async fn grant(
    client: &Object,
    name: &str,
    bucket: &str,
    permissions: &[Permission],
) -> anyhow::Result<()> {
    let permissions: Vec<&str> = permissions.iter().map(|p| p.as_str()).collect();
    let status = client
        .query_one_cached("SELECT pg_temp.cairn_grant($1, $2, $3)", &[&name, &bucket, &permissions])
        .await?;
    match status.get::<_, &str>(0) {
        "granted" => Ok(()),
        "no_such_role" => Err(invalid(format!("no user named {name:?}"))),
        "no_such_bucket" => Err(invalid(format!("no bucket named {bucket:?}; create it first"))),
        status => unreachable!("cairn_grant: unknown status {status}"),
    }
}

/// Revokes permissions on a bucket; all of them if `permissions` is empty.
pub async fn revoke(
    client: &Object,
    name: &str,
    bucket: &str,
    permissions: &[Permission],
) -> anyhow::Result<()> {
    require_role(client, name).await?;
    let permissions: Vec<&str> = if permissions.is_empty() {
        vec!["read", "write", "delete-version"]
    } else {
        permissions.iter().map(|p| p.as_str()).collect()
    };
    client
        .execute_cached(
            "SELECT pg_temp.cairn_revoke($1, $2, $3)",
            &[&name, &bucket, &permissions],
        )
        .await?;
    Ok(())
}
