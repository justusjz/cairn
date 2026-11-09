//! Roles: the S3 credentials Cairn accepts, and what each may do.
//!
//! A role is an access key ID (its name) plus a secret. It may be an *admin*,
//! which allows bucket management (create / delete / list every bucket), and it
//! holds per-bucket `read` / `write` grants for object access. Admin does not
//! imply object access; that always needs an explicit grant.
//!
//! Everything lives in Postgres, so every node sees a change immediately. The
//! `cairn role …` subcommands manage it directly against the database, and the
//! dashboard (see `dashboard`) through the same functions.

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

/// An authenticated role's secret and permissions, loaded once per request.
pub struct Principal {
    /// The role's ID, which the KMS knows it by (see `kms`).
    pub id: uuid::Uuid,
    pub secret: String,
    pub admin: bool,
    read: HashSet<String>,
    write: HashSet<String>,
    delete_version: HashSet<String>,
}

impl Principal {
    /// Loads the role whose name is `access_key`, or `None` if there is none.
    pub async fn load(client: &Object, access_key: &str) -> anyhow::Result<Option<Self>> {
        let row = client
            .query_opt_cached(
                "SELECT r.secret, r.admin, r.id,
                        ARRAY(SELECT bucket FROM role_grants
                              WHERE role = r.name AND permission = 'read'),
                        ARRAY(SELECT bucket FROM role_grants
                              WHERE role = r.name AND permission = 'write'),
                        ARRAY(SELECT bucket FROM role_grants
                              WHERE role = r.name AND permission = 'delete-version')
                 FROM roles r WHERE r.name = $1",
                &[&access_key],
            )
            .await?;
        Ok(row.map(|r| Principal {
            secret: r.get(0),
            admin: r.get(1),
            id: r.get(2),
            read: r.get::<_, Vec<String>>(3).into_iter().collect(),
            write: r.get::<_, Vec<String>>(4).into_iter().collect(),
            delete_version: r.get::<_, Vec<String>>(5).into_iter().collect(),
        }))
    }

    pub fn can(&self, permission: Permission, bucket: &str) -> bool {
        match permission {
            Permission::Read => self.read.contains(bucket),
            Permission::Write => self.write.contains(bucket),
            Permission::DeleteVersion => self.delete_version.contains(bucket),
        }
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
    /// Create a role. Prints its secret; a random one is generated unless given.
    Create {
        /// Role name, used by clients as the access key ID.
        name: String,
        /// Use this secret instead of generating one (at least 8 characters).
        #[arg(long)]
        secret: Option<String>,
        /// Allow the role to create, delete, and list all buckets.
        #[arg(long)]
        admin: bool,
    },
    /// Change a role's admin flag and/or secret.
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
    /// Delete a role and all its grants.
    Delete { name: String },
    /// List roles, their admin flag, and their grants (secrets are not shown).
    List,
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

/// `cairn role …`: role management, straight against the database.
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
            for role in list(&client).await? {
                let admin = if role.admin { " (admin)" } else { "" };
                println!("{}{admin}", role.name);
                println!("  id {}", role.id);
                if let Some(entity) = role.kms_entity_id {
                    println!("  KMS entity {entity}");
                }
                for (bucket, permission) in role.grants {
                    println!("  {bucket}:{}", permission.as_str());
                }
            }
        }
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

/// Creates a role, with `secret` or else a generated one, and returns its
/// secret.
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
    let inserted = client
        .execute_cached(
            "INSERT INTO roles (name, secret, admin) VALUES ($1, $2, $3)
             ON CONFLICT DO NOTHING",
            &[&name, &secret, &admin],
        )
        .await?;
    if inserted == 0 {
        return Err(invalid(format!("a role named {name:?} already exists")));
    }
    Ok(secret)
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
    let updated = client
        .execute_cached(
            "UPDATE roles SET admin = COALESCE($2, admin), secret = COALESCE($3, secret)
             WHERE name = $1",
            &[&name, &admin, &secret],
        )
        .await?;
    if updated == 0 {
        return Err(invalid(format!("no role named {name:?}")));
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
        return Err(invalid(format!("no role named {name:?}")));
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

/// A role as listed: never with its secret.
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
                    r.id, r.kms_entity_id
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
        return Err(invalid(format!("no role named {name:?}")));
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
        "no_such_role" => Err(invalid(format!("no role named {name:?}"))),
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
