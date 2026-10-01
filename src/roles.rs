//! Roles: the S3 credentials Cairn accepts, and what each may do.
//!
//! A role is an access key ID (its name) plus a secret. It may be an *admin*,
//! which allows bucket management (create / delete / list every bucket), and it
//! holds per-bucket `read` / `write` grants for object access. Admin does not
//! imply object access; that always needs an explicit grant.
//!
//! Everything lives in Postgres, so every node sees a change immediately. The
//! `cairn role …` subcommands manage it directly against the database.

use std::collections::HashSet;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Args, Subcommand, ValueEnum};
use deadpool_postgres::{Object, Pool};
use tokio_postgres::error::SqlState;

/// A bucket-level permission a role can be granted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Permission {
    /// GetObject, HeadObject, ListObjects; the source side of a copy.
    Read,
    /// PutObject, DeleteObject(s), multipart uploads; the destination of a copy.
    Write,
}

impl Permission {
    fn as_str(self) -> &'static str {
        match self {
            Permission::Read => "read",
            Permission::Write => "write",
        }
    }
}

/// An authenticated role's secret and permissions, loaded once per request.
pub struct Principal {
    pub secret: String,
    pub admin: bool,
    read: HashSet<String>,
    write: HashSet<String>,
}

impl Principal {
    /// Loads the role whose name is `access_key`, or `None` if there is none.
    pub async fn load(client: &Object, access_key: &str) -> anyhow::Result<Option<Self>> {
        let row = client
            .query_opt(
                "SELECT r.secret, r.admin,
                        ARRAY(SELECT bucket FROM role_grants
                              WHERE role = r.name AND permission = 'read'),
                        ARRAY(SELECT bucket FROM role_grants
                              WHERE role = r.name AND permission = 'write')
                 FROM roles r WHERE r.name = $1",
                &[&access_key],
            )
            .await?;
        Ok(row.map(|r| Principal {
            secret: r.get(0),
            admin: r.get(1),
            read: r.get::<_, Vec<String>>(2).into_iter().collect(),
            write: r.get::<_, Vec<String>>(3).into_iter().collect(),
        }))
    }

    pub fn can(&self, permission: Permission, bucket: &str) -> bool {
        match permission {
            Permission::Read => self.read.contains(bucket),
            Permission::Write => self.write.contains(bucket),
        }
    }

    /// Whether the role may learn that `bucket` exists: admins see every bucket,
    /// others only the ones they hold a grant on.
    pub fn can_see(&self, bucket: &str) -> bool {
        self.admin || self.read.contains(bucket) || self.write.contains(bucket)
    }
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct RoleArgs {
    /// PostgreSQL connection string (the same one the nodes use).
    #[arg(long)]
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
    match args.command {
        RoleCommand::Create {
            name,
            secret,
            admin,
        } => create(&pool, &name, secret, admin).await,
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
            update(&pool, &name, admin, secret, rotate_secret).await
        }
        RoleCommand::Delete { name } => {
            let client = pool.get().await?;
            if client
                .execute("DELETE FROM roles WHERE name = $1", &[&name])
                .await?
                == 0
            {
                anyhow::bail!("no role named {name:?}");
            }
            Ok(())
        }
        RoleCommand::List => list(&pool).await,
        RoleCommand::Grant {
            name,
            bucket,
            permissions,
        } => grant(&pool, &name, &bucket, &permissions).await,
        RoleCommand::Revoke {
            name,
            bucket,
            permissions,
        } => revoke(&pool, &name, &bucket, &permissions).await,
    }
}

/// Role names travel inside the SigV4 `Credential=<name>/<date>/…` field, so they
/// must not contain `/`, `,`, or whitespace. Restrict to a conservative set.
fn validate_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        anyhow::bail!("role name must be non-empty and use only A-Z, a-z, 0-9, '-', '_', '.'");
    }
    Ok(())
}

/// minio-go clients (mcli, Mimir) refuse secrets shorter than 8 characters.
fn validate_secret(secret: &str) -> anyhow::Result<()> {
    if secret.len() < 8 {
        anyhow::bail!("secret must be at least 8 characters");
    }
    Ok(())
}

/// A random 40-character secret (240 bits, URL-safe base64), the same length as
/// an AWS secret access key.
fn generate_secret() -> anyhow::Result<String> {
    let mut bytes = [0u8; 30];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("generating secret: {e}"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

async fn create(
    pool: &Pool,
    name: &str,
    secret: Option<String>,
    admin: bool,
) -> anyhow::Result<()> {
    validate_name(name)?;
    let (secret, generated) = match secret {
        Some(s) => {
            validate_secret(&s)?;
            (s, false)
        }
        None => (generate_secret()?, true),
    };
    let client = pool.get().await?;
    let inserted = client
        .execute(
            "INSERT INTO roles (name, secret, admin) VALUES ($1, $2, $3)
             ON CONFLICT DO NOTHING",
            &[&name, &secret, &admin],
        )
        .await?;
    if inserted == 0 {
        anyhow::bail!("a role named {name:?} already exists");
    }
    println!("access key: {name}");
    if generated {
        println!("secret key: {secret}");
    }
    Ok(())
}

async fn update(
    pool: &Pool,
    name: &str,
    admin: Option<bool>,
    secret: Option<String>,
    print_secret: bool,
) -> anyhow::Result<()> {
    if admin.is_none() && secret.is_none() {
        anyhow::bail!("nothing to update; pass --admin, --secret, or --rotate-secret");
    }
    if let Some(s) = &secret {
        validate_secret(s)?;
    }
    let client = pool.get().await?;
    let updated = client
        .execute(
            "UPDATE roles SET admin = COALESCE($2, admin), secret = COALESCE($3, secret)
             WHERE name = $1",
            &[&name, &admin, &secret],
        )
        .await?;
    if updated == 0 {
        anyhow::bail!("no role named {name:?}");
    }
    if print_secret && let Some(s) = secret {
        println!("secret key: {s}");
    }
    Ok(())
}

async fn list(pool: &Pool) -> anyhow::Result<()> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT r.name, r.admin,
                    ARRAY(SELECT g.bucket || ':' || g.permission FROM role_grants g
                          WHERE g.role = r.name ORDER BY g.bucket, g.permission)
             FROM roles r ORDER BY r.name",
            &[],
        )
        .await?;
    for r in rows {
        let name: String = r.get(0);
        let admin: bool = r.get(1);
        let grants: Vec<String> = r.get(2);
        let admin = if admin { " (admin)" } else { "" };
        println!("{name}{admin}");
        for g in grants {
            println!("  {g}");
        }
    }
    Ok(())
}

/// Fails with a clear message if `name` isn't a role, so a grant/revoke on a
/// typo'd name doesn't silently do nothing (or trip the FK with a raw error).
async fn require_role(client: &Object, name: &str) -> anyhow::Result<()> {
    if client
        .query_opt("SELECT 1 FROM roles WHERE name = $1", &[&name])
        .await?
        .is_none()
    {
        anyhow::bail!("no role named {name:?}");
    }
    Ok(())
}

async fn grant(
    pool: &Pool,
    name: &str,
    bucket: &str,
    permissions: &[Permission],
) -> anyhow::Result<()> {
    let client = pool.get().await?;
    require_role(&client, name).await?;
    if client
        .query_opt("SELECT 1 FROM buckets WHERE name = $1", &[&bucket])
        .await?
        .is_none()
    {
        anyhow::bail!("no bucket named {bucket:?}; create it first");
    }
    for p in permissions {
        let res = client
            .execute(
                "INSERT INTO role_grants (role, bucket, permission) VALUES ($1, $2, $3)
                 ON CONFLICT DO NOTHING",
                &[&name, &bucket, &p.as_str()],
            )
            .await;
        // The role or bucket was deleted between the checks above and here.
        if let Err(e) = &res
            && e.code() == Some(&SqlState::FOREIGN_KEY_VIOLATION)
        {
            anyhow::bail!("role {name:?} or bucket {bucket:?} was just deleted");
        }
        res?;
    }
    Ok(())
}

async fn revoke(
    pool: &Pool,
    name: &str,
    bucket: &str,
    permissions: &[Permission],
) -> anyhow::Result<()> {
    let client = pool.get().await?;
    require_role(&client, name).await?;
    let permissions: Vec<&str> = if permissions.is_empty() {
        vec!["read", "write"]
    } else {
        permissions.iter().map(|p| p.as_str()).collect()
    };
    client
        .execute(
            "DELETE FROM role_grants WHERE role = $1 AND bucket = $2 AND permission = ANY($3)",
            &[&name, &bucket, &permissions],
        )
        .await?;
    Ok(())
}
