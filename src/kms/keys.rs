//! KMS keys: symmetric keys of an account, as AWS KMS's
//! (`SYMMETRIC_DEFAULT`, `ENCRYPT_DECRYPT`, of origin `AWS_KMS`), with a
//! policy, tags, aliases, and rotation.
//!
//! A key's material is a 256-bit key per version: the first when it's made,
//! another each rotation. Each is kept in `kms_key_versions` wrapped by the
//! root key (see `kms`), for the key and version, and unwrapped when it's
//! used. What a key encrypts is a ciphertext blob of Cairn's:
//!
//! ```text
//! 0x01 | key ID (16 bytes) | version (4 bytes, big-endian) | nonce (24) | ciphertext | tag (16)
//! ```
//!
//! XChaCha20-Poly1305 under the version's material, with the encryption
//! context (canonical JSON) as associated data, besides the key and
//! version: a blob opens only with the context it was made with, as in
//! KMS. Rotating a key leaves its old blobs as they are: they open with
//! their version, and new ones are made with the latest.
//!
//! Deleting a key is scheduled, 7 to 30 days ahead, as in KMS; then its
//! row and material go, and nothing it encrypted opens again: but a backup
//! of the database (see `backup`) still has its material until the backup
//! is past its retention, wrapped by the root key.

use std::collections::BTreeMap;
use std::sync::Arc;

use deadpool_postgres::GenericClient;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{Kms, RootError};
use crate::db::Cached;
use crate::encryption::{self, Key};
use crate::policy::{Context, Kind, Policy, Verdict};
use crate::s3::access::Access;

/// A key's spec, usage, origin and encryption algorithm: the only ones.
pub const KEY_SPEC: &str = "SYMMETRIC_DEFAULT";
pub const KEY_USAGE: &str = "ENCRYPT_DECRYPT";
pub const ORIGIN: &str = "AWS_KMS";
pub const ALGORITHM: &str = "SYMMETRIC_DEFAULT";

/// How long AWS's managed keys rotate after, in days.
pub const MANAGED_ROTATION_DAYS: i32 = 365;

/// The alias of an account's key for SSE-KMS that names none (S3's).
pub const AWS_S3_ALIAS: &str = "alias/aws/s3";

const BLOB_VERSION: u8 = 1;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 1 + 16 + 4;
/// The most a ciphertext blob holds, as KMS takes them.
pub const MAX_BLOB: usize = 6144;

/// What S3's calls to the KMS say they come through (`kms:ViaService`).
pub fn s3_service() -> String {
    format!("s3.{}.amazonaws.com", crate::s3::buckets::head::REGION)
}

/// A key's ARN.
pub fn key_arn(account: &str, id: Uuid) -> String {
    format!(
        "arn:aws:kms:{}:{account}:key/{id}",
        crate::s3::buckets::head::REGION
    )
}

/// An alias's ARN (its name starts with `alias/`).
pub fn alias_arn(account: &str, name: &str) -> String {
    format!(
        "arn:aws:kms:{}:{account}:{name}",
        crate::s3::buckets::head::REGION
    )
}

/// A key's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Enabled,
    Disabled,
    PendingDeletion,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Enabled => "Enabled",
            State::Disabled => "Disabled",
            State::PendingDeletion => "PendingDeletion",
        }
    }

    fn parse(s: &str) -> State {
        match s {
            "Enabled" => State::Enabled,
            "Disabled" => State::Disabled,
            _ => State::PendingDeletion,
        }
    }
}

/// A KMS key, as the database keeps it.
#[derive(Clone, Debug)]
pub struct KmsKey {
    pub id: Uuid,
    pub account: String,
    pub description: String,
    pub state: State,
    /// Whether it's AWS's (an account's `aws/s3`), which no one manages.
    pub aws_managed: bool,
    pub policy: String,
    pub policy_principals: Option<String>,
    pub tags: Vec<(String, String)>,
    /// Its rotation period, if it rotates on its own.
    pub rotation_days: Option<i32>,
    /// When it next rotates on its own, in seconds since the Unix epoch.
    pub next_rotation: Option<f64>,
    /// When it's deleted, if it's to be (in seconds since the Unix epoch).
    pub deletion_date: Option<f64>,
    pub created_at: f64,
    /// Its aliases' names, in order.
    pub aliases: Vec<String>,
}

impl KmsKey {
    const COLUMNS: &str = "k.id, k.account_id, k.description, k.state, k.manager, k.policy, k.policy_principals::text,
         k.tags::text, k.rotation_days, extract(epoch FROM k.next_rotation)::float8,
         extract(epoch FROM k.deletion_date)::float8, extract(epoch FROM k.created_at)::float8,
         (SELECT coalesce(array_agg(a.name ORDER BY a.name), '{}') FROM kms_aliases a WHERE a.key_id = k.id)";

    fn from_row(row: &tokio_postgres::Row) -> anyhow::Result<KmsKey> {
        Ok(KmsKey {
            id: row.get(0),
            account: row.get(1),
            description: row.get(2),
            state: State::parse(row.get(3)),
            aws_managed: row.get::<_, &str>(4) == "AWS",
            policy: row.get(5),
            policy_principals: row.get(6),
            tags: serde_json::from_str(row.get::<_, &str>(7))?,
            rotation_days: row.get(8),
            next_rotation: row.get(9),
            deletion_date: row.get(10),
            created_at: row.get(11),
            aliases: row.get(12),
        })
    }

    /// The key `id`, if there's one (a closed account's are none).
    pub async fn load(client: &impl GenericClient, id: Uuid) -> anyhow::Result<Option<KmsKey>> {
        let sql = format!(
            "SELECT {} FROM kms_keys k WHERE k.id = $1
               AND NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id = k.account_id AND a.closed_at IS NOT NULL)",
            Self::COLUMNS
        );
        client
            .query_opt_cached(&sql, &[&id])
            .await?
            .map(|r| KmsKey::from_row(&r))
            .transpose()
    }

    /// `account`'s keys, in order of their IDs, after `after`, `limit` of
    /// them at most.
    pub async fn list(
        client: &impl GenericClient,
        account: &str,
        after: Option<Uuid>,
        limit: i64,
    ) -> anyhow::Result<Vec<KmsKey>> {
        let sql = format!(
            "SELECT {} FROM kms_keys k WHERE k.account_id = $1 AND ($2::uuid IS NULL OR k.id > $2)
             ORDER BY k.id LIMIT $3",
            Self::COLUMNS
        );
        client
            .query_cached(&sql, &[&account, &after, &limit])
            .await?
            .iter()
            .map(KmsKey::from_row)
            .collect()
    }

    pub fn arn(&self) -> String {
        key_arn(&self.account, self.id)
    }

    /// Its policy, parsed.
    pub fn parsed_policy(&self) -> anyhow::Result<Arc<Policy>> {
        let arn = self.arn();
        crate::s3::access::parsed(
            &self.policy,
            Kind::Key(&arn),
            Some(self.policy_principals.as_deref().unwrap_or("{}")),
        )
    }

    /// The condition keys a request on it has, of the key itself.
    pub fn context(&self) -> Context {
        let mut context = Context::default();
        context.set("kms:KeyOrigin", ORIGIN);
        context.set("kms:KeySpec", KEY_SPEC);
        context.set("kms:CustomerMasterKeySpec", KEY_SPEC);
        context.set("kms:KeyUsage", KEY_USAGE);
        context.set("kms:CustomerMasterKeyUsage", KEY_USAGE);
        context.set("kms:MultiRegion", "false");
        if !self.aliases.is_empty() {
            context.set_all("kms:ResourceAliases", self.aliases.clone());
        }
        for (key, value) in &self.tags {
            context.set(&format!("aws:ResourceTag/{key}"), value);
        }
        context
    }
}

/// What a request names a key by: its ID or ARN, or an alias (its name, or
/// its ARN). An ID or a name alone is the caller's account's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyRef {
    Id {
        account: Option<String>,
        id: Uuid,
    },
    Alias {
        account: Option<String>,
        name: String,
    },
}

impl KeyRef {
    /// From what a request gives, if it's any of those (in Cairn's region).
    pub fn parse(given: &str) -> Option<KeyRef> {
        let given = given.trim();
        if given.starts_with("alias/") {
            return valid_alias(given).then(|| KeyRef::Alias {
                account: None,
                name: given.to_owned(),
            });
        }
        if let Some(rest) = given.strip_prefix("arn:aws:kms:") {
            let (region, rest) = rest.split_once(':')?;
            let (account, resource) = rest.split_once(':')?;
            if region != crate::s3::buckets::head::REGION
                || account.len() != 12
                || !account.bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }
            if let Some(id) = resource.strip_prefix("key/") {
                return Some(KeyRef::Id {
                    account: Some(account.to_owned()),
                    id: Uuid::parse_str(id).ok()?,
                });
            }
            return (resource.starts_with("alias/") && valid_alias(resource)).then(|| {
                KeyRef::Alias {
                    account: Some(account.to_owned()),
                    name: resource.to_owned(),
                }
            });
        }
        // Only its hyphenated form, as KMS has it.
        (given.len() == 36)
            .then(|| Uuid::parse_str(given).ok())
            .flatten()
            .map(|id| KeyRef::Id { account: None, id })
    }

    /// The alias it names, if it names one.
    pub fn alias(&self) -> Option<&str> {
        match self {
            KeyRef::Alias { name, .. } => Some(name),
            KeyRef::Id { .. } => None,
        }
    }

    /// The account it names, if it names one.
    pub fn account(&self) -> Option<&str> {
        match self {
            KeyRef::Id { account, .. } | KeyRef::Alias { account, .. } => account.as_deref(),
        }
    }
}

/// Whether `name` is an alias's: `alias/`, then 1 to 250 of letters,
/// digits, `/_-`.
pub fn valid_alias(name: &str) -> bool {
    name.strip_prefix("alias/").is_some_and(|rest| {
        !rest.is_empty()
            && name.len() <= 256
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_-".contains(&b))
    })
}

/// The key `given` names, for a caller of `account`: `None` if there's
/// none (an alias another account's key is the target of isn't the
/// caller's: an alias names its own account's keys only).
pub async fn resolve(
    client: &impl GenericClient,
    account: &str,
    given: &KeyRef,
) -> anyhow::Result<Option<KmsKey>> {
    let owner = given.account().unwrap_or(account);
    let id = match given {
        KeyRef::Id { id, .. } => *id,
        KeyRef::Alias { name, .. } => {
            let row = client
                .query_opt_cached(
                    "SELECT key_id FROM kms_aliases WHERE account_id = $1 AND name = $2",
                    &[&owner, &name],
                )
                .await?;
            match row {
                Some(row) => row.get(0),
                None => return Ok(None),
            }
        }
    };
    Ok(KmsKey::load(client, id)
        .await?
        .filter(|key| key.account == owner))
}

/// A new key's policy, if its creator gives none: KMS's default, which
/// lets the account's identity policies decide (and its root user anything).
pub fn default_policy(account: &str) -> String {
    format!(
        "{{\"Version\":\"2012-10-17\",\"Id\":\"key-default-1\",\"Statement\":[{{\"Sid\":\"Enable IAM User Permissions\",\
         \"Effect\":\"Allow\",\"Principal\":{{\"AWS\":\"arn:aws:iam::{account}:root\"}},\"Action\":\"kms:*\",\"Resource\":\"*\"}}]}}"
    )
}

/// The policy of an account's `aws/s3` key, as AWS's: any principal of the
/// account may use it through S3, and the account may read it.
pub fn aws_s3_policy(account: &str) -> String {
    format!(
        "{{\"Version\":\"2012-10-17\",\"Id\":\"auto-s3-2\",\"Statement\":[{{\"Sid\":\"Allow access through S3 for all principals in the account that are authorized to use S3\",\
         \"Effect\":\"Allow\",\"Principal\":{{\"AWS\":\"*\"}},\"Action\":[\"kms:Encrypt\",\"kms:Decrypt\",\"kms:ReEncrypt*\",\"kms:GenerateDataKey*\",\"kms:DescribeKey\"],\
         \"Resource\":\"*\",\"Condition\":{{\"StringEquals\":{{\"kms:CallerAccount\":\"{account}\",\"kms:ViaService\":\"{}\"}}}}}},\
         {{\"Sid\":\"Allow direct access to key metadata to the account\",\"Effect\":\"Allow\",\"Principal\":{{\"AWS\":\"arn:aws:iam::{account}:root\"}},\
         \"Action\":[\"kms:Describe*\",\"kms:Get*\",\"kms:List*\"],\"Resource\":\"*\"}}]}}",
        s3_service()
    )
}

/// A new key's settings.
pub struct NewKey<'a> {
    pub account: &'a str,
    pub description: &'a str,
    /// Its policy, normalized (see `Policy::normalized`).
    pub policy: &'a str,
    pub aws_managed: bool,
    pub tags: &'a [(String, String)],
}

/// The associated data a key version's material is wrapped with.
fn material_ad(id: Uuid, version: i32) -> Vec<u8> {
    [
        b"kms key\0".as_slice(),
        id.as_bytes(),
        &version.to_be_bytes(),
    ]
    .concat()
}

fn new_material() -> Zeroizing<Key> {
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom::fill(key.as_mut_slice()).expect("the OS random number generator failed");
    key
}

/// Makes a key, with its first version.
pub async fn create(
    kms: &Kms,
    client: &impl GenericClient,
    new: &NewKey<'_>,
) -> anyhow::Result<Result<KmsKey, RootError>> {
    let id = Uuid::new_v4();
    let material = new_material();
    let wrapped = match kms.wrap(material.as_slice(), &material_ad(id, 1)).await {
        Ok(wrapped) => wrapped,
        Err(e) => return Ok(Err(e)),
    };
    let tags = serde_json::to_string(new.tags)?;
    let (manager, rotation) = match new.aws_managed {
        true => ("AWS", Some(MANAGED_ROTATION_DAYS)),
        false => ("CUSTOMER", None),
    };
    client
        .execute(
            "INSERT INTO kms_keys (id, account_id, description, state, manager, policy, tags, rotation_days, next_rotation)
             VALUES ($1, $2, $3, 'Enabled', $4, $5, $6::text::jsonb, $7,
                     now() + make_interval(days => $7))",
            &[&id, &new.account, &new.description, &manager, &new.policy, &tags, &rotation],
        )
        .await?;
    client
        .execute(
            "INSERT INTO kms_key_versions (key_id, version, material) VALUES ($1, 1, $2)",
            &[&id, &wrapped],
        )
        .await?;
    let key = KmsKey::load(client, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("a key just made isn't there"))?;
    Ok(Ok(key))
}

/// `account`'s `aws/s3` key, which it's made the first time it's needed.
pub async fn aws_s3_key(
    kms: &Kms,
    client: &impl GenericClient,
    account: &str,
) -> anyhow::Result<Result<KmsKey, RootError>> {
    let alias = KeyRef::Alias {
        account: None,
        name: AWS_S3_ALIAS.to_owned(),
    };
    if let Some(key) = resolve(client, account, &alias).await? {
        return Ok(Ok(key));
    }
    let policy = Policy::parse(&aws_s3_policy(account), Kind::Key("*"))
        .map(|p| p.normalized().to_owned())
        .unwrap_or_else(|_| aws_s3_policy(account));
    let new = NewKey {
        account,
        description: "Default key that protects my S3 objects when no other key is defined",
        policy: &policy,
        aws_managed: true,
        tags: &[],
    };
    let key = match create(kms, client, &new).await? {
        Ok(key) => key,
        Err(e) => return Ok(Err(e)),
    };
    let named = client
        .execute(
            "INSERT INTO kms_aliases (account_id, name, key_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            &[&account, &AWS_S3_ALIAS, &key.id],
        )
        .await?;
    if named == 0 {
        // Another request made one meanwhile: that's the one.
        client
            .execute("DELETE FROM kms_keys WHERE id = $1", &[&key.id])
            .await?;
        return Box::pin(aws_s3_key(kms, client, account)).await;
    }
    KmsKey::load(client, key.id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("a key just made isn't there"))
        .map(Ok)
}

/// Why a key didn't encrypt or decrypt.
#[derive(Debug)]
pub enum KeyError {
    /// The key isn't there (any more).
    NotFound,
    /// The key is disabled.
    Disabled,
    /// The key is to be deleted.
    PendingDeletion,
    /// The blob isn't one of Cairn's, or not the key's, or not with this
    /// encryption context.
    InvalidCiphertext,
    /// The root key couldn't be had.
    Unavailable(anyhow::Error),
    Internal(anyhow::Error),
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::NotFound => write!(f, "the key isn't there"),
            KeyError::Disabled => write!(f, "the key is disabled"),
            KeyError::PendingDeletion => write!(f, "the key is pending deletion"),
            KeyError::InvalidCiphertext => write!(f, "the ciphertext isn't valid"),
            KeyError::Unavailable(e) => write!(f, "the KMS is unavailable: {e:#}"),
            KeyError::Internal(e) => write!(f, "{e:#}"),
        }
    }
}

impl From<anyhow::Error> for KeyError {
    fn from(e: anyhow::Error) -> KeyError {
        KeyError::Internal(e)
    }
}

impl From<tokio_postgres::Error> for KeyError {
    fn from(e: tokio_postgres::Error) -> KeyError {
        KeyError::Internal(e.into())
    }
}

impl From<RootError> for KeyError {
    fn from(e: RootError) -> KeyError {
        match e {
            RootError::Unavailable(e) => KeyError::Unavailable(e),
            RootError::Failed(why) => {
                KeyError::Internal(anyhow::anyhow!("a key's material doesn't unwrap: {why}"))
            }
        }
    }
}

impl KmsKey {
    /// Whether it may encrypt and decrypt: enabled.
    pub fn usable(&self) -> Result<(), KeyError> {
        match self.state {
            State::Enabled => Ok(()),
            State::Disabled => Err(KeyError::Disabled),
            State::PendingDeletion => Err(KeyError::PendingDeletion),
        }
    }
}

/// A key version's material.
async fn material(
    kms: &Kms,
    client: &impl GenericClient,
    id: Uuid,
    version: Option<i32>,
) -> Result<(i32, Zeroizing<Key>), KeyError> {
    let row = client
        .query_opt_cached(
            "SELECT version, material FROM kms_key_versions WHERE key_id = $1
               AND ($2::integer IS NULL OR version = $2) ORDER BY version DESC LIMIT 1",
            &[&id, &version],
        )
        .await?;
    let Some(row) = row else {
        return Err(match version {
            Some(_) => KeyError::InvalidCiphertext,
            None => KeyError::NotFound,
        });
    };
    let version: i32 = row.get(0);
    let wrapped: Vec<u8> = row.get(1);
    let material = kms.unwrap_key(&wrapped, &material_ad(id, version)).await?;
    Ok((version, material))
}

/// An encryption context as canonical JSON.
pub fn canonical(context: &BTreeMap<String, String>) -> String {
    serde_json::to_string(context).expect("strings serialize")
}

fn blob_ad(id: Uuid, version: i32, context: &BTreeMap<String, String>) -> Vec<u8> {
    [
        b"cairn kms ciphertext v1\0".as_slice(),
        id.as_bytes(),
        &version.to_be_bytes(),
        canonical(context).as_bytes(),
    ]
    .concat()
}

/// The key a ciphertext blob is of, and its version, if it's one of
/// Cairn's.
pub fn blob_key(blob: &[u8]) -> Option<(Uuid, i32)> {
    if blob.len() < HEADER_LEN + NONCE_LEN + TAG_LEN || blob[0] != BLOB_VERSION {
        return None;
    }
    let id = Uuid::from_slice(&blob[1..17]).ok()?;
    let version = i32::from_be_bytes(blob[17..21].try_into().ok()?);
    Some((id, version))
}

/// `plaintext` encrypted under `key` (its latest version), with `context`:
/// a ciphertext blob.
pub async fn encrypt(
    kms: &Kms,
    client: &impl GenericClient,
    key: &KmsKey,
    plaintext: &[u8],
    context: &BTreeMap<String, String>,
) -> Result<Vec<u8>, KeyError> {
    key.usable()?;
    let (version, material) = material(kms, client, key.id, None).await?;
    let sealed = encryption::seal_bytes(&material, plaintext, &blob_ad(key.id, version, context));
    Ok([
        &[BLOB_VERSION][..],
        key.id.as_bytes(),
        &version.to_be_bytes(),
        &sealed,
    ]
    .concat())
}

/// What `blob` (of `key`, as `blob_key` tells) holds, if it opens with
/// `context`.
pub async fn decrypt(
    kms: &Kms,
    client: &impl GenericClient,
    key: &KmsKey,
    blob: &[u8],
    context: &BTreeMap<String, String>,
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    let Some((id, version)) = blob_key(blob) else {
        return Err(KeyError::InvalidCiphertext);
    };
    if id != key.id {
        return Err(KeyError::InvalidCiphertext);
    }
    key.usable()?;
    let (_, material) = material(kms, client, key.id, Some(version)).await?;
    encryption::open_bytes(
        &material,
        &blob[HEADER_LEN..],
        &blob_ad(id, version, context),
    )
    .ok_or(KeyError::InvalidCiphertext)
}

/// A new 256-bit data key, and its ciphertext blob under `key`.
pub async fn data_key(
    kms: &Kms,
    client: &impl GenericClient,
    key: &KmsKey,
    context: &BTreeMap<String, String>,
) -> Result<(Zeroizing<Key>, Vec<u8>), KeyError> {
    let plain = new_material();
    let blob = encrypt(kms, client, key, plain.as_slice(), context).await?;
    Ok((plain, blob))
}

/// Rotates `key`: a new version, which encrypts from now on.
/// `automatic` says which kind of rotation it is.
pub async fn rotate(
    kms: &Kms,
    client: &impl GenericClient,
    key: &KmsKey,
    automatic: bool,
) -> Result<(), KeyError> {
    let row = client
        .query_one(
            "SELECT coalesce(max(version), 0) + 1 FROM kms_key_versions WHERE key_id = $1",
            &[&key.id],
        )
        .await?;
    let version: i32 = row.get(0);
    let material = new_material();
    let wrapped = kms
        .wrap(material.as_slice(), &material_ad(key.id, version))
        .await?;
    let kind = if automatic { "AUTOMATIC" } else { "ON_DEMAND" };
    client
        .execute(
            "INSERT INTO kms_key_versions (key_id, version, material, rotation) VALUES ($1, $2, $3, $4)",
            &[&key.id, &version, &wrapped, &kind],
        )
        .await?;
    client
        .execute(
            "UPDATE kms_keys SET next_rotation = now() + make_interval(days => rotation_days)
             WHERE id = $1 AND rotation_days IS NOT NULL AND $2",
            &[&key.id, &automatic],
        )
        .await?;
    Ok(())
}

/// The condition keys of an encryption context, as KMS has them.
pub fn context_keys(context: &BTreeMap<String, String>) -> Context {
    let mut keys = Context::default();
    for (key, value) in context {
        keys.set(&format!("kms:EncryptionContext:{key}"), value);
    }
    if !context.is_empty() {
        keys.set_all(
            "kms:EncryptionContextKeys",
            context.keys().cloned().collect(),
        );
    }
    keys
}

/// Whether `access`'s principal may take `action` (`kms:…`) on `key`, with
/// the condition keys `extra` too; if not, KMS's message for it.
pub fn authorize(
    access: &Access,
    action: &str,
    key: &KmsKey,
    extra: &Context,
) -> anyhow::Result<Result<(), String>> {
    let policy = key.parsed_policy()?;
    let mut context = key.context();
    context.extend(extra);
    let arn = key.arn();
    let verdict = access.key_verdict(action, &arn, &key.account, &policy, &context);
    if verdict == Verdict::Allow {
        return Ok(Ok(()));
    }
    let who = access.principal_arn().unwrap_or("anonymous");
    let why = match verdict {
        Verdict::ExplicitDeny { identity: false } => {
            "with an explicit deny in a resource-based policy".to_owned()
        }
        Verdict::ImplicitDeny => {
            "because no resource-based policy allows the ".to_owned() + action + " action"
        }
        verdict => verdict.why(action, access.boundary()),
    };
    Ok(Err(format!(
        "User: {who} is not authorized to perform: {action} on resource: {arn} {why}"
    )))
}

/// Whether the AWS service `service` (`s3.amazonaws.com`), acting for
/// `account`, may take `action` on `key`, with the condition keys `extra`
/// too: only the key's policy may allow it, by naming the service; if not,
/// KMS's message for it.
pub fn authorize_service(
    service: &str,
    account: &str,
    action: &str,
    key: &KmsKey,
    extra: &Context,
) -> anyhow::Result<Result<(), String>> {
    let policy = key.parsed_policy()?;
    let mut context = key.context();
    context.extend(extra);
    context.set("aws:SourceAccount", account);
    context.set("aws:PrincipalIsAWSService", "true");
    context.set("aws:ResourceAccount", key.account.clone());
    let arn = key.arn();
    let request = crate::policy::Request {
        principal: crate::policy::Principal::Service { name: service },
        action,
        resource: &arn,
        context: &context,
    };
    Ok(match policy.evaluate(&request) {
        crate::policy::Decision::Allow => Ok(()),
        _ => Err(format!(
            "The key policy of {arn} doesn't allow the service {service} to perform: {action}"
        )),
    })
}

/// Upkeep, once a pass: deletes the keys whose deletion is due, and rotates
/// those whose rotation is.
pub async fn maintain(kms: &Kms, pool: &deadpool_postgres::Pool) -> anyhow::Result<()> {
    let client = pool.get().await?;
    let deleted = client
        .execute(
            "DELETE FROM kms_keys WHERE state = 'PendingDeletion' AND deletion_date <= now()",
            &[],
        )
        .await?;
    if deleted > 0 {
        eprintln!("kms: deleted {deleted} keys, as scheduled");
    }
    let due: Vec<Uuid> = client
        .query(
            "SELECT id FROM kms_keys WHERE next_rotation <= now() AND rotation_days IS NOT NULL
               AND state <> 'PendingDeletion' ORDER BY next_rotation LIMIT 100",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    for id in due {
        // One node rotates it: whichever moves its next rotation first.
        let claimed = client
            .execute(
                "UPDATE kms_keys SET next_rotation = now() + make_interval(days => rotation_days)
                 WHERE id = $1 AND next_rotation <= now()",
                &[&id],
            )
            .await?;
        if claimed == 0 {
            continue;
        }
        let Some(key) = KmsKey::load(&client, id).await? else {
            continue;
        };
        if let Err(e) = rotate(kms, &client, &key, true).await {
            eprintln!("kms: rotating key {id}: {e}");
            // Again in the next pass.
            client
                .execute(
                    "UPDATE kms_keys SET next_rotation = now() WHERE id = $1",
                    &[&id],
                )
                .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_named_by_ids_arns_and_aliases() {
        let id = Uuid::new_v4();
        let region = crate::s3::buckets::head::REGION;
        assert_eq!(
            KeyRef::parse(&id.to_string()),
            Some(KeyRef::Id { account: None, id })
        );
        assert_eq!(
            KeyRef::parse(&format!("arn:aws:kms:{region}:111122223333:key/{id}")),
            Some(KeyRef::Id {
                account: Some("111122223333".to_owned()),
                id
            })
        );
        assert_eq!(
            KeyRef::parse("alias/my-key"),
            Some(KeyRef::Alias {
                account: None,
                name: "alias/my-key".to_owned()
            })
        );
        assert_eq!(
            KeyRef::parse(&format!("arn:aws:kms:{region}:111122223333:alias/a/b_c")),
            Some(KeyRef::Alias {
                account: Some("111122223333".to_owned()),
                name: "alias/a/b_c".to_owned()
            })
        );
        for bad in [
            "",
            "alias/",
            "alias/a b",
            "transit/k",
            &id.simple().to_string(),
            &format!("arn:aws:kms:eu-west-9:111122223333:key/{id}"),
            &format!("arn:aws:kms:{region}:1111:key/{id}"),
            &format!("arn:aws:kms:{region}:111122223333:key/nope"),
            &format!("arn:aws:s3:{region}:111122223333:key/{id}"),
        ] {
            assert_eq!(KeyRef::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn blobs_name_their_key_and_version() {
        let id = Uuid::new_v4();
        let blob = [
            &[BLOB_VERSION][..],
            id.as_bytes(),
            &7i32.to_be_bytes(),
            &[0; NONCE_LEN + TAG_LEN],
        ]
        .concat();
        assert_eq!(blob_key(&blob), Some((id, 7)));
        assert_eq!(blob_key(&blob[..30]), None);
        let mut other = blob.clone();
        other[0] = 9;
        assert_eq!(blob_key(&other), None);
    }

    #[test]
    fn the_default_policies_parse() {
        let arn = key_arn("111122223333", Uuid::nil());
        Policy::parse(&default_policy("111122223333"), Kind::Key(&arn)).unwrap();
        Policy::parse(&aws_s3_policy("111122223333"), Kind::Key(&arn)).unwrap();
    }
}
