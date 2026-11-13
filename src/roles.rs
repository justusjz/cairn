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
//! The operator account's users are none of that: each is a superadmin by
//! being one, with no access keys, admin flag, grants or policies (see
//! `refuse_operator`), and acts only in the console.
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

impl Principal {
    /// Loads the user whose active access key `access_key` is, or `None` if
    /// there's none.
    pub async fn load(client: &Object, access_key: &str) -> anyhow::Result<Option<Self>> {
        // Never one of the operator account's: it has none (migration 39),
        // and signs nothing.
        Self::load_where(client, "FROM access_keys k JOIN roles r ON r.id = k.role_id
             JOIN accounts a ON a.id = r.account_id
             WHERE k.access_key_id = $1 AND k.active AND NOT a.operator", "k.secret", &access_key).await
    }

    /// Loads user `id` itself, as the console acts as it (no secret: it
    /// signs nothing), or `None` if there's none.
    pub async fn load_user(client: &Object, id: uuid::Uuid) -> anyhow::Result<Option<Self>> {
        Self::load_where(client, "FROM roles r WHERE r.id = $1", "''::text", &id).await
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
                        ARRAY(SELECT document FROM role_policies WHERE role_id = r.id ORDER BY name),
                        ARRAY(SELECT m.document FROM role_attached_policies x
                              JOIN managed_policies m ON m.id = x.policy_id WHERE x.role_id = r.id ORDER BY m.name),
                        ARRAY(SELECT x.aws_policy FROM role_attached_policies x
                              WHERE x.role_id = r.id AND x.aws_policy IS NOT NULL ORDER BY x.aws_policy)
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
        }
    }

}

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Args, Debug, Serialize, Deserialize)]
pub struct RoleArgs {
    #[command(flatten)]
    #[serde(skip)]
    pub remote: crate::admin::Remote,
    /// The account (by name) whose users these are: user names are unique
    /// in an account. The first tenant account (`default`) if not given.
    #[arg(long, global = true)]
    account: Option<String>,
    #[command(subcommand)]
    command: RoleCommand,
}

#[derive(Subcommand, Debug, Serialize, Deserialize)]
enum RoleCommand {
    /// Create a user, with an access key named as it. Prints the key's
    /// secret; a random one is generated unless given. In the operator
    /// account: a superadmin, who gets no key (see `cairn user enroll`).
    Create {
        /// The user's name, which its first access key's ID is too.
        name: String,
        /// Use this secret instead of generating one (at least 8 characters).
        #[arg(long)]
        secret: Option<String>,
        /// Give the user `AdministratorAccess`: everything in its account.
        #[arg(long)]
        admin: bool,
    },
    /// Change a user's admin flag, and/or the secret of its access key named
    /// as it.
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
    // The account's ID.
    let account_id = match &args.account {
        Some(name) => client
            .query_opt_cached("SELECT id FROM accounts WHERE name = $1", &[name])
            .await?
            .map(|row| row.get::<_, String>(0))
            .ok_or_else(|| invalid(format!("no account named {name:?}")))?,
        None => account(&client).await?,
    };
    let account_id = account_id.as_str();
    match args.command {
        RoleCommand::Create {
            name,
            secret,
            admin,
        } => {
            if is_operator(&client, account_id).await? {
                if secret.is_some() || admin {
                    refuse_operator(&client, account_id, "access keys or admin flag").await?;
                }
                create_without_key(&client, account_id, &name).await?;
                let account = args.account.as_deref().unwrap_or("operator");
                outln!(out, "superadmin {name}: make its console link with `cairn user enroll --account {account} {name}`");
                return Ok(());
            }
            let generated = secret.is_none();
            let (key, secret) = create_for(&client, account_id, &name, secret, admin).await?;
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
                outln!(out, "  arn:aws:iam::{account_id}:user/{}", role.name);
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

/// Creates a user of the first tenant account, with an access key named as
/// it, of `secret` or else a generated one, and returns its secret.
#[cfg(test)]
pub async fn create(
    client: &Object,
    name: &str,
    secret: Option<String>,
    admin: bool,
) -> anyhow::Result<String> {
    Ok(create_in(client, None, name, secret, admin).await?.1)
}

#[cfg(test)]
/// Creates a user of the account named `account` (`None`: the first tenant
/// account), as `create`.
pub async fn create_in(
    client: &Object,
    account: Option<&str>,
    name: &str,
    secret: Option<String>,
    admin: bool,
) -> anyhow::Result<(String, String)> {
    let account_id = match account {
        Some(account) => client
            .query_opt_cached("SELECT id FROM accounts WHERE name = $1", &[&account])
            .await?
            .map(|row| row.get::<_, String>(0))
            .ok_or_else(|| invalid(format!("no account named {account:?}")))?,
        None => self::account(client).await?,
    };
    // The operator account's users have no keys: its ID is the name.
    if is_operator(client, &account_id).await? {
        create_without_key(client, &account_id, name).await?;
        return Ok((name.to_owned(), String::new()));
    }
    create_for(client, &account_id, name, secret, admin).await
}

/// Creates a user of the account `account_id` without access keys, as
/// IAM's CreateUser does: it gets them with `create_key`. (`roles.secret`,
/// which older Cairns read, is none that can be guessed.) A user of the
/// operator account is a superadmin, by being one, and never gets keys;
/// it's marked admin for older nodes (see `db`, migration 39).
pub async fn create_without_key(client: &Object, account_id: &str, name: &str) -> anyhow::Result<()> {
    validate_name(name)?;
    let inserted = client
        .execute_cached(
            "INSERT INTO roles (name, secret, admin, account_id)
             SELECT $1, 'unusable:' || gen_random_uuid() || gen_random_uuid(), a.operator, a.id
             FROM accounts a WHERE a.id = $2
             ON CONFLICT DO NOTHING",
            &[&name, &account_id],
        )
        .await?;
    if inserted == 0 {
        return Err(invalid(format!("a user named {name:?} already exists")));
    }
    Ok(())
}

/// Creates a user of the account `account_id`, with an access key named as
/// it (if that's free; else a random one): the key's ID and secret.
pub async fn create_for(
    client: &Object,
    account_id: &str,
    name: &str,
    secret: Option<String>,
    admin: bool,
) -> anyhow::Result<(String, String)> {
    validate_name(name)?;
    refuse_operator(client, account_id, "access keys").await?;
    let secret = match secret {
        Some(s) => {
            validate_secret(&s)?;
            s
        }
        None => generate_secret()?,
    };
    // Its first key is named as it, unless that's taken (by a user of
    // another account, of the same name): then a random one.
    let key = match key_exists(client, name).await? {
        false => name.to_owned(),
        true => generate_key_id()?,
    };
    // One statement: the user and its key, or neither. (`roles.secret` is
    // what older Cairns authenticate with; the key's trigger keeps it.)
    let inserted = client
        .execute_cached(
            "WITH r AS (
                 INSERT INTO roles (name, secret, admin, account_id) VALUES ($1, $2, $3, $4)
                 ON CONFLICT DO NOTHING RETURNING id
             )
             INSERT INTO access_keys (access_key_id, role_id, secret) SELECT $5, id, $2 FROM r",
            &[&name, &secret, &admin, &account_id, &key],
        )
        .await;
    match inserted {
        Ok(0) => Err(invalid(format!("a user named {name:?} already exists"))),
        Ok(_) => Ok((key, secret)),
        // Another key took the name meanwhile.
        Err(e) if e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) => {
            Err(invalid(format!("an access key named {name:?} already exists")))
        }
        Err(e) => Err(e.into()),
    }
}

/// The ID of the first tenant account (`default`; see `accounts`), which
/// users and buckets belong to unless said otherwise, while there are no
/// other tenants; it never changes, so it's read once.
pub async fn account(client: &Object) -> anyhow::Result<String> {
    static ACCOUNT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    if let Some(account) = ACCOUNT.get() {
        return Ok(account.clone());
    }
    let account: String = client
        .query_one_cached("SELECT id FROM accounts WHERE NOT operator ORDER BY created_at, id LIMIT 1", &[])
        .await?
        .get(0);
    // Each test's database has an account of its own.
    if !cfg!(test) {
        let _ = ACCOUNT.set(account.clone());
    }
    Ok(account)
}

/// The operator account's ID (see `accounts`), which never changes, so it's
/// read once.
pub async fn operator_account(client: &Object) -> anyhow::Result<String> {
    static ACCOUNT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    if let Some(account) = ACCOUNT.get() {
        return Ok(account.clone());
    }
    let account: String = client.query_one_cached("SELECT id FROM accounts WHERE operator", &[]).await?.get(0);
    // Each test's database has an account of its own.
    if !cfg!(test) {
        let _ = ACCOUNT.set(account.clone());
    }
    Ok(account)
}

/// Whether `account` (its ID) is the operator account.
pub async fn is_operator(client: &Object, account: &str) -> anyhow::Result<bool> {
    Ok(account == operator_account(client).await?)
}

/// Refuses the operator account's users `what` (access keys, policies, an
/// admin flag): they're superadmins by being its users, and act only in
/// the console, so the IAM that tenants' users have is none of theirs.
pub async fn refuse_operator(client: &Object, account: &str, what: &str) -> anyhow::Result<()> {
    if is_operator(client, account).await? {
        return Err(invalid(format!(
            "the operator account's users are superadmins by being its users, and have no {what}"
        )));
    }
    Ok(())
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

/// User `name` of account `account` (its ID): its ID, if there's one.
pub async fn id_of(client: &Object, account: &str, name: &str) -> anyhow::Result<uuid::Uuid> {
    client
        .query_opt_cached("SELECT id FROM roles WHERE account_id = $1 AND name = $2", &[&account, &name])
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
    refuse_operator(client, account, "access keys").await?;
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
            "DELETE FROM access_keys k USING roles r
             WHERE k.access_key_id = $1 AND r.id = k.role_id
               AND ($2::text IS NULL OR (r.account_id = $2 AND r.name = $3))",
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
            "UPDATE access_keys k SET active = $3 FROM roles r
             WHERE k.access_key_id = $1 AND r.id = k.role_id
               AND ($2::text IS NULL OR (r.account_id = $2 AND r.name = $4))",
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
    refuse_operator(client, account, "policies").await?;
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
            "SELECT p.document FROM role_policies p JOIN roles r ON r.id = p.role_id
             WHERE r.account_id = $3 AND r.name = $1 AND p.name = $2",
            &[&user, &name, &account],
        )
        .await?;
    row.map(|r| r.get(0)).ok_or_else(|| invalid(format!("{user:?} has no policy {name:?}")))
}

/// Deletes `user`'s inline policy `name`.
pub async fn delete_policy(client: &Object, account: &str, user: &str, name: &str) -> anyhow::Result<()> {
    let deleted = client
        .execute_cached(
            "DELETE FROM role_policies p USING roles r
             WHERE r.id = p.role_id AND r.account_id = $3 AND r.name = $1 AND p.name = $2",
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
    refuse_operator(client, account, "admin flag or access keys").await?;
    if let Some(s) = &secret {
        validate_secret(s)?;
    }
    if let Some(admin) = admin {
        let updated = client
            .execute_cached("UPDATE roles SET admin = $2 WHERE name = $1 AND account_id = $3", &[&name, &admin, &account])
            .await?;
        if updated == 0 {
            return Err(invalid(format!("no user named {name:?}")));
        }
    }
    if let Some(secret) = secret {
        // The key named as the user (its first, a role's only one).
        let updated = client
            .execute_cached(
                "UPDATE access_keys k SET secret = $2 FROM roles r
                 WHERE r.name = $1 AND r.account_id = $3 AND k.role_id = r.id AND k.access_key_id = r.name",
                &[&name, &secret, &account],
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
pub async fn delete(client: &Object, account: &str, name: &str) -> anyhow::Result<()> {
    let role = id_of(client, account, name).await?;
    let deleted: bool = client
        .query_one_cached("SELECT pg_temp.cairn_delete_role($1)", &[&role])
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
}

/// Every role, by name.
pub async fn list(client: &Object) -> anyhow::Result<Vec<RoleInfo>> {
    let rows = client
        .query_cached(
            "SELECT r.name, r.admin, extract(epoch FROM r.created_at)::float8,
                    NULL, NULL,
                    r.id, r.kms_entity_id,
                    ARRAY(SELECT k.access_key_id FROM access_keys k WHERE k.role_id = r.id
                          ORDER BY k.created_at, k.access_key_id),
                    ARRAY(SELECT k.active FROM access_keys k WHERE k.role_id = r.id
                          ORDER BY k.created_at, k.access_key_id),
                    ARRAY(SELECT extract(epoch FROM k.created_at)::float8 FROM access_keys k
                          WHERE k.role_id = r.id ORDER BY k.created_at, k.access_key_id),
                    ARRAY(SELECT p.name FROM role_policies p WHERE p.role_id = r.id ORDER BY p.name),
                    a.id
             FROM roles r JOIN accounts a ON a.id = r.account_id ORDER BY a.operator, a.name, r.name",
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
