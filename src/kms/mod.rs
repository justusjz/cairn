//! Cairn's KMS: AWS KMS's API (see `api`), with keys of Cairn's own (see
//! `keys`), which SSE-KMS and SSE-S3 use (see `s3::sse`), and everything
//! else Cairn keeps secret at rest: the backup's key, and the tiers'.
//!
//! Everything secret is wrapped by one **root key**, which is either
//!
//! - a file (`--kms-root-key-file`): 32 random bytes, the same on every
//!   node, best kept on a tmpfs (a Kubernetes secret, a systemd credential),
//!   off the data disks and out of backups; or
//! - a key of OpenBao's (or Vault's) Transit engine (`--kms-address`), which
//!   never leaves it: Cairn asks it to wrap and unwrap (see `transit`).
//!
//! Above the root, both are the same: a KMS key's material (one 256-bit key
//! per rotation) is kept in the database, wrapped by the root, and
//! unwrapped when it's used, then kept in memory for a while (an hour after
//! its last use), so that OpenBao sees a few calls an hour, not one a
//! request. Which KMS key a principal may use, and how, is IAM's to decide:
//! its policies and the key's (see `keys`, `api`).
//!
//! The database also keeps a canary (`kms_root`): a random value wrapped by
//! the root the first node had. Every node checks that it unwraps it, so that
//! a node with another root refuses to start, rather than to wrap secrets
//! nothing else can unwrap.

pub mod api;
pub mod keys;
pub mod transit;

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context as _;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::encryption::{self, Key};

/// How long a node keeps what it unwrapped, after its last use.
const KEEP: Duration = Duration::from_secs(3600);
/// How long a node seals SSE-S3 object keys under one data key.
const SSE_S3_WRITE_KEY: Duration = Duration::from_secs(3600);

/// The associated data the root's wraps start with, before their own.
const ROOT_AD: &[u8] = b"cairn kms root v1\0";
/// The canary's associated data.
const CANARY_AD: &[u8] = b"canary";
/// SSE-S3 data keys': they're shared by many objects, so their names are
/// bound when object keys are sealed instead (see `s3::sse`).
const SSE_S3_AD: &[u8] = b"sse-s3 data key";

/// What a wrap made by the file root starts with.
const FILE_WRAP: u8 = 1;
/// What a wrap made by OpenBao starts with: its ciphertext follows.
const TRANSIT_WRAP: u8 = 2;

/// How the KMS is configured: `cairn serve`'s `--kms-*` flags.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct KmsArgs {
    /// File of the root key: 32 random bytes, raw or base64 (`openssl rand
    /// -base64 32`), the same on every node. Keep it on a tmpfs, off the
    /// data disks and out of backups. Or the root key is OpenBao's
    /// (`--kms-address`); without either, there's no KMS, and SSE-KMS and
    /// SSE-S3 are refused (501).
    #[arg(long, env = "CAIRN_KMS_ROOT_KEY_FILE")]
    pub kms_root_key_file: Option<PathBuf>,
    /// URL of the OpenBao (or Vault) server whose Transit engine holds the
    /// root key, e.g. https://bao.internal:8200.
    #[arg(long, env = "CAIRN_KMS_ADDRESS")]
    pub kms_address: Option<String>,
    /// The root key in OpenBao: `<mount>/<key>` of a Transit engine.
    #[arg(long, env = "CAIRN_KMS_TRANSIT_KEY", default_value = "transit/cairn")]
    pub kms_transit_key: String,
    /// PEM file of the Ed25519 private key Cairn signs its logins to OpenBao
    /// with. The same on every node; OpenBao's JWT auth mount for Cairn
    /// trusts its public key.
    #[arg(long, env = "CAIRN_KMS_JWT_KEY")]
    pub kms_jwt_key: Option<PathBuf>,
    /// Where OpenBao's JWT auth method for Cairn is mounted.
    #[arg(long, env = "CAIRN_KMS_AUTH_MOUNT", default_value = "cairn")]
    pub kms_auth_mount: String,
    /// The role of that auth method that Cairn's logins use.
    #[arg(long, env = "CAIRN_KMS_AUTH_ROLE", default_value = "cairn")]
    pub kms_auth_role: String,
    /// PEM file of the CA certificates to trust for OpenBao's TLS. Without
    /// it, the public web's (Mozilla's) roots.
    #[arg(long, env = "CAIRN_KMS_CA_CERT")]
    pub kms_ca_cert: Option<PathBuf>,
}

/// Why the root didn't wrap or unwrap.
#[derive(Debug)]
pub enum RootError {
    /// OpenBao couldn't be reached, failed, or refused Cairn.
    Unavailable(anyhow::Error),
    /// What was to be unwrapped isn't a wrap of this root's, or not with
    /// this associated data.
    Failed(String),
}

impl std::fmt::Display for RootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RootError::Unavailable(e) => write!(f, "the root key is unavailable: {e:#}"),
            RootError::Failed(why) => write!(f, "the root key can't unwrap it: {why}"),
        }
    }
}

impl std::error::Error for RootError {}

/// The root key.
pub enum Root {
    File(Zeroizing<Key>),
    Transit(Box<transit::Transit>),
}

impl Root {
    /// What kind it is, as the canary's row records it.
    fn kind(&self) -> &'static str {
        match self {
            Root::File(_) => "file",
            Root::Transit(_) => "openbao",
        }
    }

    async fn wrap(&self, plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>, RootError> {
        let ad = [ROOT_AD, ad].concat();
        match self {
            Root::File(key) => Ok([
                &[FILE_WRAP][..],
                &encryption::seal_bytes(key, plaintext, &ad),
            ]
            .concat()),
            Root::Transit(transit) => {
                let ciphertext = transit.encrypt(plaintext, &ad).await?;
                Ok([&[TRANSIT_WRAP][..], ciphertext.as_bytes()].concat())
            }
        }
    }

    async fn unwrap(&self, wrapped: &[u8], ad: &[u8]) -> Result<Zeroizing<Vec<u8>>, RootError> {
        let ad = [ROOT_AD, ad].concat();
        match (self, wrapped.split_first()) {
            (Root::File(key), Some((&FILE_WRAP, sealed))) => {
                encryption::open_bytes(key, sealed, &ad).ok_or_else(|| {
                    RootError::Failed("it doesn't open under the root key".to_owned())
                })
            }
            (Root::Transit(transit), Some((&TRANSIT_WRAP, ciphertext))) => {
                let ciphertext = std::str::from_utf8(ciphertext)
                    .map_err(|_| RootError::Failed("it isn't OpenBao's ciphertext".to_owned()))?;
                transit.decrypt(ciphertext, &ad).await
            }
            (_, Some((&FILE_WRAP, _))) => Err(RootError::Failed(
                "it was wrapped by a root key file, and this node's root key is OpenBao's"
                    .to_owned(),
            )),
            (_, Some((&TRANSIT_WRAP, _))) => Err(RootError::Failed(
                "it was wrapped by OpenBao, and this node's root key is a file".to_owned(),
            )),
            _ => Err(RootError::Failed(
                "it isn't a wrap of a root key's".to_owned(),
            )),
        }
    }
}

/// Reads a root key file: 32 bytes, raw, or base64 (with whitespace around).
pub fn read_root_key_file(path: &std::path::Path) -> anyhow::Result<Zeroizing<Key>> {
    use base64::Engine;
    let bytes = Zeroizing::new(
        std::fs::read(path).with_context(|| format!("reading the root key {}", path.display()))?,
    );
    if let Ok(key) = Key::try_from(bytes.as_slice()) {
        return Ok(Zeroizing::new(key));
    }
    let text = std::str::from_utf8(&bytes).unwrap_or("").trim();
    let decoded = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .unwrap_or_default(),
    );
    Key::try_from(decoded.as_slice())
        .map(Zeroizing::new)
        .map_err(|_| {
            anyhow::anyhow!(
                "the root key {} must be 32 bytes, raw or base64 (openssl rand -base64 32)",
                path.display()
            )
        })
}

/// What a node unwrapped, by a digest of the wrap and its associated data,
/// and when it last used each.
type Unwrapped = HashMap<[u8; 32], (Zeroizing<Vec<u8>>, Instant)>;

pub struct Kms {
    root: Root,
    unwrapped: std::sync::Mutex<Unwrapped>,
    /// The data key new SSE-S3 objects' keys are sealed under, its wrap,
    /// and when it came.
    sse_s3: Mutex<Option<SseS3Key>>,
}

/// A data key for SSE-S3, its wrap, and when it came.
type SseS3Key = (Zeroizing<Key>, Vec<u8>, Instant);

impl Kms {
    /// The KMS `args` configure, or `None` if they configure none. Checks the
    /// configuration only: OpenBao itself isn't asked anything yet.
    pub fn new(args: &KmsArgs) -> anyhow::Result<Option<Arc<Kms>>> {
        let root = match (&args.kms_root_key_file, &args.kms_address) {
            (Some(_), Some(_)) => anyhow::bail!(
                "the root key is either a file (--kms-root-key-file) or OpenBao's (--kms-address), not both"
            ),
            (Some(path), None) => {
                anyhow::ensure!(
                    args.kms_jwt_key.is_none() && args.kms_ca_cert.is_none(),
                    "--kms-jwt-key and --kms-ca-cert are OpenBao's (--kms-address)"
                );
                Root::File(read_root_key_file(path)?)
            }
            (None, Some(address)) => {
                let jwt_key = args
                    .kms_jwt_key
                    .clone()
                    .context("--kms-address needs --kms-jwt-key, to log in to OpenBao")?;
                Root::Transit(Box::new(transit::Transit::new(&transit::TransitArgs {
                    address: address.clone(),
                    jwt_key,
                    auth_mount: args.kms_auth_mount.clone(),
                    auth_role: args.kms_auth_role.clone(),
                    key: args.kms_transit_key.clone(),
                    ca_cert: args.kms_ca_cert.clone(),
                })?))
            }
            (None, None) => {
                anyhow::ensure!(
                    args.kms_jwt_key.is_none() && args.kms_ca_cert.is_none(),
                    "the KMS flags need a root key: --kms-root-key-file or --kms-address"
                );
                return Ok(None);
            }
        };
        Ok(Some(Arc::new(Kms::with_root(root))))
    }

    pub fn with_root(root: Root) -> Kms {
        Kms {
            root,
            unwrapped: std::sync::Mutex::default(),
            sse_s3: Mutex::new(None),
        }
    }

    pub fn root(&self) -> &Root {
        &self.root
    }

    /// `plaintext` wrapped by the root, bound to `ad`.
    pub async fn wrap(&self, plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>, RootError> {
        self.root.wrap(plaintext, ad).await
    }

    /// What `wrapped` (from `wrap` with the same `ad`) holds: as the node
    /// unwrapped it before, or from the root.
    pub async fn unwrap(&self, wrapped: &[u8], ad: &[u8]) -> Result<Zeroizing<Vec<u8>>, RootError> {
        let digest: [u8; 32] = Sha256::new()
            .chain_update((ad.len() as u64).to_be_bytes())
            .chain_update(ad)
            .chain_update(wrapped)
            .finalize()
            .into();
        if let Some((plain, used)) = self.unwrapped.lock().unwrap().get_mut(&digest) {
            *used = Instant::now();
            return Ok(plain.clone());
        }
        let plain = self.root.unwrap(wrapped, ad).await?;
        let mut unwrapped = self.unwrapped.lock().unwrap();
        unwrapped.retain(|_, (_, used)| used.elapsed() < KEEP);
        unwrapped.insert(digest, (plain.clone(), Instant::now()));
        Ok(plain)
    }

    /// A 256-bit key `wrapped` holds (see `unwrap`).
    pub async fn unwrap_key(&self, wrapped: &[u8], ad: &[u8]) -> Result<Zeroizing<Key>, RootError> {
        let plain = self.unwrap(wrapped, ad).await?;
        Key::try_from(plain.as_slice())
            .map(Zeroizing::new)
            .map_err(|_| RootError::Failed("it isn't a 256-bit key".to_owned()))
    }

    /// Forgets everything the node unwrapped (for tests: as if it were a
    /// node that just started).
    #[cfg(test)]
    pub fn forget(&self) {
        self.unwrapped.lock().unwrap().clear();
    }

    /// Checks the root against the cluster's canary, or makes the canary if
    /// there's none: `Err` if the root isn't the cluster's. If OpenBao can't
    /// be reached, it's only said, as the KMS may well be later.
    pub async fn check_root(&self, pool: &deadpool_postgres::Pool) -> anyhow::Result<()> {
        let client = pool.get().await?;
        let row = client
            .query_opt("SELECT kind, canary FROM kms_root", &[])
            .await?;
        match row {
            Some(row) => {
                let kind: String = row.get(0);
                let canary: Vec<u8> = row.get(1);
                match self.root.unwrap(&canary, CANARY_AD).await {
                    Ok(_) => Ok(()),
                    Err(RootError::Unavailable(e)) => {
                        eprintln!("kms: couldn't check the root key against the cluster's: {e:#}");
                        Ok(())
                    }
                    Err(RootError::Failed(why)) => anyhow::bail!(
                        "this node's root key ({}) isn't the cluster's ({kind}): {why}",
                        self.root.kind()
                    ),
                }
            }
            None => {
                let mut value = Zeroizing::new([0u8; 32]);
                getrandom::fill(value.as_mut_slice())
                    .expect("the OS random number generator failed");
                let canary = match self.root.wrap(value.as_slice(), CANARY_AD).await {
                    Ok(canary) => canary,
                    Err(e) => {
                        eprintln!("kms: couldn't make the root key's canary yet: {e}");
                        return Ok(());
                    }
                };
                // Another node may have made one meanwhile: then it's that
                // one this root must unwrap.
                let made = client
                    .execute(
                        "INSERT INTO kms_root (kind, canary) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                        &[&self.root.kind(), &canary],
                    )
                    .await?;
                if made == 0 {
                    drop(client);
                    return Box::pin(self.check_root(pool)).await;
                }
                Ok(())
            }
        }
    }

    /// The data key to seal a new SSE-S3 object's key under, and its wrap:
    /// the node's current one, or a new one once that's an hour old.
    pub async fn sse_s3_data_key(&self) -> Result<(Zeroizing<Key>, Vec<u8>), RootError> {
        let mut current = self.sse_s3.lock().await;
        if let Some((key, wrapped, since)) = current.as_ref()
            && since.elapsed() < SSE_S3_WRITE_KEY
        {
            return Ok((key.clone(), wrapped.clone()));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::fill(key.as_mut_slice()).expect("the OS random number generator failed");
        let wrapped = self.wrap(key.as_slice(), SSE_S3_AD).await?;
        *current = Some((key.clone(), wrapped.clone(), Instant::now()));
        Ok((key, wrapped))
    }

    /// The SSE-S3 data key `wrapped` holds.
    pub async fn sse_s3_open(&self, wrapped: &[u8]) -> Result<Zeroizing<Key>, RootError> {
        self.unwrap_key(wrapped, SSE_S3_AD).await
    }
}

/// Who asks for a KMS key's use through S3 (see `s3::sse`): a principal,
/// with what its request says of it (its address, ...), which the key's
/// policy and its own decide its use by; or S3 itself, as a service (as it
/// writes an inventory report), which the key's policy alone may allow.
#[derive(Clone)]
pub enum Caller {
    Principal(Arc<crate::s3::access::Access>),
    Service {
        /// Its name (`s3.amazonaws.com`).
        name: &'static str,
        /// The account it acts for (`aws:SourceAccount`): a key it names
        /// by an ID or alias is that account's.
        account: String,
        /// The resource it acts for (`aws:SourceArn`), if it says: a
        /// trail's, for CloudTrail.
        source: Option<String>,
    },
}

impl Caller {
    pub fn new(access: crate::s3::access::Access) -> Caller {
        Caller::Principal(Arc::new(access))
    }

    /// `principal`, outside a request of its own (the console's, a batch
    /// job's): its policies, without a request's condition keys.
    pub fn of(principal: &crate::users::Principal) -> anyhow::Result<Caller> {
        let origin = crate::s3::access::Origin {
            peer: None,
            trusted_proxies: &[],
            signed: None,
            form: false,
        };
        crate::s3::access::Access::new(
            Some(principal),
            &principal.account,
            &hyper::Method::GET,
            &hyper::HeaderMap::new(),
            "",
            &origin,
        )
        .map(Caller::new)
    }

    /// S3, as the service, for `account`.
    pub fn s3_service(account: &str) -> Caller {
        Caller::Service {
            name: crate::sns::S3_SERVICE,
            account: account.to_owned(),
            source: None,
        }
    }

    /// The account it acts in.
    pub fn account(&self) -> &str {
        match self {
            Caller::Principal(access) => access.principal_account().unwrap_or_default(),
            Caller::Service { account, .. } => account,
        }
    }
}

/// A 256-bit key Cairn keeps secret at rest (a backup's, a tier's), as the
/// database keeps it: wrapped by the root, or, without a KMS, as it is.
#[derive(Clone)]
pub enum StoredKey {
    Plain(Zeroizing<Key>),
    Wrapped(Vec<u8>),
}

impl std::fmt::Debug for StoredKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoredKey::Plain(_) => f.write_str("StoredKey::Plain(..)"),
            StoredKey::Wrapped(_) => f.write_str("StoredKey::Wrapped(..)"),
        }
    }
}

impl StoredKey {
    /// From a row's key column and whether it's wrapped.
    pub fn from_columns(key: Vec<u8>, wrapped: bool) -> anyhow::Result<StoredKey> {
        if wrapped {
            return Ok(StoredKey::Wrapped(key));
        }
        let key = Zeroizing::new(key);
        Key::try_from(key.as_slice())
            .map(|k| StoredKey::Plain(Zeroizing::new(k)))
            .map_err(|_| anyhow::anyhow!("a stored key isn't 32 bytes"))
    }

    /// `key` as it's to be stored: wrapped by the root for `ad` (what it's
    /// the key of), if there's a KMS.
    pub async fn seal(kms: Option<&Kms>, key: &Key, ad: &[u8]) -> anyhow::Result<StoredKey> {
        Ok(match kms {
            Some(kms) => StoredKey::Wrapped(
                kms.wrap(key, ad)
                    .await
                    .map_err(|e| anyhow::anyhow!("wrapping a key: {e}"))?,
            ),
            None => StoredKey::Plain(Zeroizing::new(*key)),
        })
    }

    /// Its columns: the key (or its wrap), and whether it's wrapped.
    pub fn columns(&self) -> (Vec<u8>, bool) {
        match self {
            StoredKey::Plain(key) => (key.to_vec(), false),
            StoredKey::Wrapped(wrapped) => (wrapped.clone(), true),
        }
    }

    /// The key itself, unwrapped by the root if it's wrapped (`ad` being what
    /// it was wrapped for).
    pub async fn open(&self, kms: Option<&Kms>, ad: &[u8]) -> anyhow::Result<Zeroizing<Key>> {
        match self {
            StoredKey::Plain(key) => Ok(key.clone()),
            StoredKey::Wrapped(wrapped) => {
                let kms = kms.context(
                    "the key is wrapped by the KMS's root key, and this node has no KMS (--kms-root-key-file or --kms-address)",
                )?;
                kms.unwrap_key(wrapped, ad)
                    .await
                    .map_err(|e| anyhow::anyhow!("unwrapping a key: {e}"))
            }
        }
    }
}

/// The associated data a tier's key is wrapped with: its name.
pub fn tier_key_ad(tier: &str) -> Vec<u8> {
    [b"tier key\0".as_slice(), tier.as_bytes()].concat()
}

/// The backup's key's.
pub const BACKUP_KEY_AD: &[u8] = b"backup key";

/// Wraps the keys the database keeps as they are (from before there was a
/// KMS, or from a node without one), now that there's a root.
pub async fn wrap_stored_keys(kms: &Kms, pool: &deadpool_postgres::Pool) -> anyhow::Result<()> {
    let client = pool.get().await?;
    let tiers = client
        .query("SELECT name, key FROM tiers WHERE NOT key_wrapped", &[])
        .await?;
    for row in tiers {
        let name: String = row.get(0);
        let key = Zeroizing::new(row.get::<_, Vec<u8>>(1));
        let key = Key::try_from(key.as_slice()).context("a tier's key isn't 32 bytes")?;
        let wrapped = StoredKey::seal(Some(kms), &key, &tier_key_ad(&name)).await?;
        client
            .execute(
                "UPDATE tiers SET key = $2, key_wrapped = true WHERE name = $1 AND NOT key_wrapped",
                &[&name, &wrapped.columns().0],
            )
            .await?;
        eprintln!("kms: wrapped tier {name}'s key with the root key");
    }
    let backup = client
        .query_opt("SELECT key FROM backup_config WHERE NOT key_wrapped", &[])
        .await?;
    if let Some(row) = backup {
        let key = Zeroizing::new(row.get::<_, Vec<u8>>(0));
        let key = Key::try_from(key.as_slice()).context("the backup's key isn't 32 bytes")?;
        let wrapped = StoredKey::seal(Some(kms), &key, BACKUP_KEY_AD).await?;
        client
            .execute(
                "UPDATE backup_config SET key = $1, key_wrapped = true WHERE NOT key_wrapped",
                &[&wrapped.columns().0],
            )
            .await?;
        eprintln!("kms: wrapped the backup's key with the root key");
    }
    Ok(())
}

/// Refuses a node without a KMS if the database keeps keys it can't
/// unwrap: once there's a root, every node needs it.
pub async fn require_root(pool: &deadpool_postgres::Pool) -> anyhow::Result<()> {
    let client = pool.get().await?;
    let wrapped: bool = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM kms_root)
                 OR EXISTS (SELECT 1 FROM tiers WHERE key_wrapped)
                 OR EXISTS (SELECT 1 FROM backup_config WHERE key_wrapped)",
            &[],
        )
        .await?
        .get(0);
    anyhow::ensure!(
        !wrapped,
        "the cluster has a KMS root key (its keys are wrapped by it), and this node has none: \
         give it the cluster's (--kms-root-key-file, or --kms-address)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_root() -> Kms {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).unwrap();
        Kms::with_root(Root::File(Zeroizing::new(key)))
    }

    #[tokio::test]
    async fn the_file_root_wraps_and_unwraps() {
        let kms = file_root();
        let wrapped = kms.wrap(b"secret", b"ad").await.unwrap();
        assert_eq!(wrapped[0], FILE_WRAP);
        assert_eq!(&*kms.unwrap(&wrapped, b"ad").await.unwrap(), b"secret");
        // Bound to its associated data, and to its root.
        kms.forget();
        assert!(matches!(
            kms.unwrap(&wrapped, b"other").await,
            Err(RootError::Failed(_))
        ));
        assert!(matches!(
            file_root().unwrap(&wrapped, b"ad").await,
            Err(RootError::Failed(_))
        ));
        let mut broken = wrapped.clone();
        *broken.last_mut().unwrap() ^= 1;
        assert!(kms.unwrap(&broken, b"ad").await.is_err());
        assert!(kms.unwrap(&[TRANSIT_WRAP, b'v'], b"ad").await.is_err());
        assert!(kms.unwrap(&[], b"ad").await.is_err());
    }

    #[tokio::test]
    async fn stored_keys_are_wrapped_with_a_kms() {
        let kms = file_root();
        let key = [7u8; 32];
        let stored = StoredKey::seal(Some(&kms), &key, b"tier key\0t")
            .await
            .unwrap();
        assert!(matches!(stored, StoredKey::Wrapped(_)));
        let (column, wrapped) = stored.columns();
        assert!(wrapped);
        let back = StoredKey::from_columns(column, true).unwrap();
        assert_eq!(*back.open(Some(&kms), b"tier key\0t").await.unwrap(), key);
        assert!(back.open(Some(&kms), b"tier key\0u").await.is_err());
        assert!(back.open(None, b"tier key\0t").await.is_err());
        let plain = StoredKey::seal(None, &key, b"x").await.unwrap();
        assert_eq!(*plain.open(None, b"x").await.unwrap(), key);
        assert!(StoredKey::from_columns(vec![1, 2], false).is_err());
    }

    /// The root key in OpenBao (see `db-test.sh`): wraps and unwraps, bound
    /// to its associated data, as Cairn logs in as itself; what a node has
    /// unwrapped, it doesn't ask for again. Skipped without OpenBao.
    #[tokio::test]
    async fn openbao_roots_wrap_and_unwrap() {
        let Ok(address) = std::env::var("CAIRN_TEST_OPENBAO") else {
            return;
        };
        let args = KmsArgs {
            kms_address: Some(address),
            kms_jwt_key: Some(std::env::var("CAIRN_TEST_OPENBAO_JWT_KEY").unwrap().into()),
            kms_transit_key: "transit/cairn".to_owned(),
            kms_auth_mount: "cairn".to_owned(),
            kms_auth_role: "cairn".to_owned(),
            ..KmsArgs::default()
        };
        let kms = Kms::new(&args).unwrap().unwrap();
        let Root::Transit(transit) = kms.root() else {
            panic!("OpenBao's")
        };
        let wrapped = kms.wrap(b"secret", b"ad").await.unwrap();
        assert_eq!(wrapped[0], TRANSIT_WRAP);
        assert!(wrapped[1..].starts_with(b"vault:v1:"));
        let calls = transit.calls();
        assert_eq!(&*kms.unwrap(&wrapped, b"ad").await.unwrap(), b"secret");
        assert_eq!(&*kms.unwrap(&wrapped, b"ad").await.unwrap(), b"secret");
        assert_eq!(transit.calls(), calls + 1, "it has it already");
        assert!(matches!(
            kms.unwrap(&wrapped, b"other").await,
            Err(RootError::Failed(_))
        ));
        assert!(transit.logins().last_success.is_some());
        // A file root can't unwrap it.
        assert!(matches!(
            file_root().unwrap(&wrapped, b"ad").await,
            Err(RootError::Failed(_))
        ));
        // Another key of OpenBao's is no root it may use.
        let other = Kms::new(&KmsArgs {
            kms_transit_key: "transit/other".to_owned(),
            ..args
        })
        .unwrap()
        .unwrap();
        assert!(matches!(
            other.wrap(b"x", b"ad").await,
            Err(RootError::Unavailable(_))
        ));
    }

    #[test]
    fn root_key_files_are_raw_or_base64() {
        let dir = std::env::temp_dir().join(format!("cairn-root-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let raw = dir.join("raw");
        std::fs::write(&raw, [9u8; 32]).unwrap();
        assert_eq!(*read_root_key_file(&raw).unwrap(), [9u8; 32]);
        let b64 = dir.join("b64");
        std::fs::write(&b64, "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=\n").unwrap();
        assert_eq!(*read_root_key_file(&b64).unwrap(), [9u8; 32]);
        let short = dir.join("short");
        std::fs::write(&short, "abc").unwrap();
        assert!(read_root_key_file(&short).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
