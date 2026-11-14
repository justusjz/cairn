//! A client of a KMS: OpenBao's (or Vault's) Transit secrets engine, which
//! SSE-KMS keeps its keys in (see `s3::sse`).
//!
//! Cairn uses two of its calls (`update` on both paths, in OpenBao's terms):
//!
//! - `datakey/plaintext/<key>`: a fresh random data key, both as itself and
//!   encrypted under the named key, which never leaves the KMS;
//! - `decrypt/<key>`: a data key back from its ciphertext.
//!
//! Both take associated data, which the ciphertext is bound to: it decrypts
//! only with the same. Not `encrypt`, which creates a key that doesn't exist
//! yet if the token may, so that a mistyped key name would make a new key.
//!
//! Cairn calls them as the S3 user that made the request, so that the KMS
//! decides which users may use which keys: key owners grant them in OpenBao.
//! Each Cairn user has an OpenBao identity (an entity) of its own, which
//! Cairn logs in as through a JWT auth mount of its own: a JWT that it signs
//! with its private key (Ed25519), naming the user by its ID. OpenBao trusts
//! Cairn to name the right user, as AWS KMS trusts S3; it can't check that
//! itself, since only Cairn can tell who signed an S3 request.
//!
//! That mount must be Cairn's alone, map no claims to groups or metadata
//! (`groups_claim`, `claim_mappings`: Cairn would choose them), and give its
//! tokens no policy but `default`, and Cairn's aliases must never be attached
//! to another entity: then Cairn can use exactly what key owners granted its
//! users, and nothing else in OpenBao.
//!
//! A user's token is kept until two thirds of its TTL have passed. OpenBao
//! applies grants and revocations to tokens already issued, so that doesn't
//! delay them.
//!
//! For SSE-S3, Cairn uses one key (`--kms-sse-s3-key`) as itself: its own
//! identity, with the subject `cairn` (users' are UUIDs), which the KMS's
//! admin grants that key. As S3's bucket keys do, a node reuses a data key
//! from it for an hour of writes, and keeps the data keys it opened for an
//! hour after their last use: so the KMS sees a few calls an hour, not one a
//! request. Which also means that revoking Cairn's access to the key, or
//! deleting it, stops running nodes reading SSE-S3 objects within an hour,
//! not at once.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::Context as _;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode, header};
use hyper_rustls::HttpsConnector;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::encryption::Key;

/// How long a call to the KMS may take, all in all.
const TIMEOUT: Duration = Duration::from_secs(10);

/// How long a node seals SSE-S3 object keys under one data key.
const SSE_S3_WRITE_KEY: Duration = Duration::from_secs(3600);
/// How long a node keeps an SSE-S3 data key it opened, after its last use.
const SSE_S3_KEEP: Duration = Duration::from_secs(3600);
/// The associated data of SSE-S3 data keys at the KMS. They're shared by many
/// objects, so their names are bound when object keys are sealed instead.
const SSE_S3_AD: &[u8] = b"cairn sse-s3 data key v1";

/// The audience of Cairn's JWTs, which its JWT role must be bound to.
pub const AUDIENCE: &str = "cairn";

/// The mount of a key ID that names none.
pub const DEFAULT_MOUNT: &str = "transit";

/// How the KMS is configured: `cairn serve`'s `--kms-*` flags.
#[derive(clap::Args, Debug, Clone)]
pub struct KmsArgs {
    /// URL of the OpenBao (or Vault) server whose Transit engines hold the
    /// keys for SSE-KMS, e.g. https://bao.internal:8200. Without it, requests
    /// for SSE-KMS are refused (501).
    #[arg(long, env = "CAIRN_KMS_ADDRESS")]
    pub kms_address: Option<String>,
    /// PEM file of the Ed25519 private key Cairn signs its users' logins to
    /// the KMS with. The same on every node; the KMS's JWT auth mount for
    /// Cairn trusts its public key.
    #[arg(long, env = "CAIRN_KMS_JWT_KEY")]
    pub kms_jwt_key: Option<PathBuf>,
    /// Where the KMS's JWT auth method for Cairn is mounted.
    #[arg(long, env = "CAIRN_KMS_AUTH_MOUNT", default_value = "cairn")]
    pub kms_auth_mount: String,
    /// The role of that auth method that Cairn's logins use.
    #[arg(long, env = "CAIRN_KMS_AUTH_ROLE", default_value = "s3")]
    pub kms_auth_role: String,
    /// The key for SSE-S3 (`<mount>/<key>`), which Cairn uses as itself (the
    /// subject `cairn` of that auth method). Without it, SSE-S3 is refused.
    #[arg(long, env = "CAIRN_KMS_SSE_S3_KEY")]
    pub kms_sse_s3_key: Option<String>,
    /// PEM file of the CA certificates to trust for the KMS's TLS. Without
    /// it, the public web's (Mozilla's) roots.
    #[arg(long, env = "CAIRN_KMS_CA_CERT")]
    pub kms_ca_cert: Option<PathBuf>,
}

/// A KMS key: a Transit engine's mount path (which may begin with
/// namespaces), and the key's name in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyId {
    mount: String,
    name: String,
}

impl KeyId {
    /// From `<mount>/<key>`, or a key name alone, in the mount `transit`.
    /// `None` unless every segment is a valid name (`valid_segment`): they go
    /// into the KMS's URLs.
    pub fn parse(id: &str) -> Option<KeyId> {
        let (mount, name) = id.rsplit_once('/').unwrap_or((DEFAULT_MOUNT, id));
        (id.len() <= 512 && mount.split('/').all(valid_segment) && valid_segment(name)).then(|| KeyId {
            mount: mount.to_owned(),
            name: name.to_owned(),
        })
    }

    /// `<mount>/<key>`, as it's stored and reported.
    pub fn as_string(&self) -> String {
        format!("{}/{}", self.mount, self.name)
    }

    fn path(&self, operation: &str) -> String {
        format!("{}/{operation}/{}", self.mount, self.name)
    }
}

/// Whether `segment` may be a segment of a key ID: only characters that need
/// no escaping, and no path segments of its own (`.`, `..`).
fn valid_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= 128
        && !segment.starts_with('.')
        && segment.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

/// Who Cairn asks the KMS as: a user, or itself (for SSE-S3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Identity {
    User(Uuid),
    Cairn,
}

impl Identity {
    /// The subject of its JWTs: the user's ID, or `cairn`.
    pub fn subject(self) -> String {
        match self {
            Identity::User(user) => user.to_string(),
            Identity::Cairn => "cairn".to_owned(),
        }
    }
}

/// A token, and when to stop using it (`None`: when it's refused).
struct Token {
    token: Zeroizing<String>,
    renew_at: Option<Instant>,
}

/// Why the KMS didn't do what it was asked.
#[derive(Debug)]
pub enum KmsError {
    /// There's no key of that name.
    NoSuchKey,
    /// The KMS refused the user the key (no policy grants it).
    Denied,
    /// The KMS couldn't be reached, or failed.
    Unavailable(anyhow::Error),
    /// The KMS refused Cairn's login as a user: its setup for Cairn is
    /// wrong. What's likely wrong.
    LoginRefused(String),
    /// The KMS refused the request otherwise: say, a ciphertext that isn't
    /// one, or associated data it wasn't bound to.
    Failed(String),
}

impl std::fmt::Display for KmsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KmsError::NoSuchKey => write!(f, "the KMS has no such key"),
            KmsError::Denied => write!(f, "the KMS refused the user the key"),
            KmsError::Unavailable(e) => write!(f, "the KMS is unavailable: {e:#}"),
            KmsError::LoginRefused(why) => write!(f, "the KMS refused Cairn's login: {why}"),
            KmsError::Failed(message) => write!(f, "the KMS refused the request: {message}"),
        }
    }
}

impl std::error::Error for KmsError {}

/// A fresh data key: itself, and its ciphertext from the KMS.
pub struct DataKey {
    pub plaintext: Zeroizing<Key>,
    pub ciphertext: String,
}

pub struct Kms {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    /// The server's URL, without a trailing slash.
    address: String,
    signer: ring::signature::Ed25519KeyPair,
    auth_mount: String,
    auth_role: String,
    /// Each user's token, by user ID, each behind a lock of its own, so that
    /// one user's login doesn't hold up another's calls.
    tokens: std::sync::Mutex<HashMap<Identity, Arc<Mutex<Option<Token>>>>>,
    /// How this node's logins went, for the console.
    logins: std::sync::Mutex<Logins>,
    /// SSE-S3's key, and its data keys, if it's configured.
    sse_s3: Option<SseS3>,
    /// Calls of the Transit engine, for tests to count.
    #[cfg(test)]
    calls: std::sync::atomic::AtomicU64,
}

/// SSE-S3's key, which Cairn uses as itself, and the node's data keys from it.
struct SseS3 {
    key: KeyId,
    /// The data key new objects' keys are sealed under, and when it came.
    current: Mutex<Option<(DataKey, Instant)>>,
    /// The data keys the node has, by their ciphertext, and when each was last
    /// used.
    opened: std::sync::Mutex<HashMap<String, (Zeroizing<Key>, Instant)>>,
    /// Cairn's own identity (entity) in the KMS, once it logged in as itself.
    entity: std::sync::Mutex<Option<String>>,
}

/// How a node's logins to the KMS went: its last, and its last that worked.
#[derive(Clone, Default)]
pub struct Logins {
    pub last: Option<Login>,
    /// When the last one that worked was, in seconds since the Unix epoch.
    pub last_success: Option<f64>,
}

/// A login to the KMS as a user.
#[derive(Clone)]
pub struct Login {
    /// When, in seconds since the Unix epoch.
    pub at: f64,
    pub who: Identity,
    /// Why it failed, if it did: what's likely wrong.
    pub error: Option<String>,
}

/// How the KMS is, as its health endpoint tells.
pub struct Health {
    pub reachable: bool,
    pub initialized: Option<bool>,
    pub sealed: Option<bool>,
    pub standby: Option<bool>,
    pub version: Option<String>,
    pub error: Option<String>,
}

/// What the KMS answers with: `data` on success, `errors` otherwise.
#[derive(Deserialize)]
struct Answer<T> {
    data: Option<T>,
    auth: Option<LoginAuth>,
    #[serde(default)]
    errors: Vec<String>,
}

#[derive(Deserialize)]
struct LoginAuth {
    client_token: String,
    lease_duration: u64,
    #[serde(default)]
    entity_id: String,
}

#[derive(Deserialize)]
struct DataKeyData {
    plaintext: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct DecryptData {
    plaintext: String,
}

impl Kms {
    /// The KMS `args` configure, or `None` if they configure none. Checks the
    /// configuration only: the KMS itself isn't asked anything yet.
    pub fn new(args: &KmsArgs) -> anyhow::Result<Option<Arc<Kms>>> {
        let Some(address) = &args.kms_address else {
            anyhow::ensure!(
                args.kms_jwt_key.is_none() && args.kms_ca_cert.is_none(),
                "the KMS flags need --kms-address"
            );
            return Ok(None);
        };
        let address = address.trim_end_matches('/').to_owned();
        anyhow::ensure!(
            address.starts_with("https://") || address.starts_with("http://"),
            "--kms-address must be an http(s) URL"
        );
        let jwt_key = args
            .kms_jwt_key
            .as_ref()
            .context("--kms-address needs --kms-jwt-key, to log in to the KMS")?;
        let signer = {
            use rustls::pki_types::{PrivatePkcs8KeyDer, pem::PemObject};
            let der = PrivatePkcs8KeyDer::from_pem_file(jwt_key)
                .with_context(|| format!("reading {} (a PKCS#8 PEM key)", jwt_key.display()))?;
            ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(der.secret_pkcs8_der())
                .map_err(|e| anyhow::anyhow!("{} isn't an Ed25519 key: {e}", jwt_key.display()))?
        };
        for (flag, value) in [("--kms-auth-mount", &args.kms_auth_mount), ("--kms-auth-role", &args.kms_auth_role)] {
            anyhow::ensure!(value.split('/').all(valid_segment), "{flag} isn't a valid path");
        }
        let sse_s3 = match &args.kms_sse_s3_key {
            None => None,
            Some(key) => Some(SseS3 {
                key: KeyId::parse(key).context("--kms-sse-s3-key isn't a valid key ID")?,
                current: Mutex::new(None),
                opened: std::sync::Mutex::default(),
                entity: std::sync::Mutex::default(),
            }),
        };
        let roots = match &args.kms_ca_cert {
            Some(path) => {
                use rustls::pki_types::{CertificateDer, pem::PemObject};
                let mut roots = rustls::RootCertStore::empty();
                for cert in CertificateDer::pem_file_iter(path)
                    .with_context(|| format!("reading {}", path.display()))?
                {
                    roots.add(cert.with_context(|| format!("reading {}", path.display()))?)?;
                }
                anyhow::ensure!(!roots.is_empty(), "{} holds no certificates", path.display());
                roots
            }
            None => rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        };
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .build();
        Ok(Some(Arc::new(Kms {
            client: Client::builder(TokioExecutor::new()).build(connector),
            address,
            signer,
            auth_mount: args.kms_auth_mount.clone(),
            auth_role: args.kms_auth_role.clone(),
            tokens: std::sync::Mutex::default(),
            logins: std::sync::Mutex::default(),
            sse_s3,
            #[cfg(test)]
            calls: std::sync::atomic::AtomicU64::new(0),
        })))
    }

    /// The KMS's URL.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Where Cairn's JWT auth method is mounted, and the role its logins use.
    pub fn auth(&self) -> (&str, &str) {
        (&self.auth_mount, &self.auth_role)
    }

    /// How this node's logins went.
    pub fn logins(&self) -> Logins {
        self.logins.lock().unwrap().clone()
    }

    /// The public key of the key Cairn signs its logins with, as PEM: what
    /// the KMS's JWT auth mount for Cairn is to trust
    /// (`jwt_validation_pubkeys`).
    pub fn public_key_pem(&self) -> String {
        use ring::signature::KeyPair;
        // An Ed25519 SubjectPublicKeyInfo: its fixed DER prefix, and the key.
        const PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
        let der = [&PREFIX[..], self.signer.public_key().as_ref()].concat();
        format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", STANDARD.encode(der))
    }

    /// How the KMS is, from its health endpoint, which needs no token.
    pub async fn health(&self) -> Health {
        #[derive(Deserialize)]
        struct Answer {
            initialized: Option<bool>,
            sealed: Option<bool>,
            standby: Option<bool>,
            version: Option<String>,
        }
        // Each state answers 200, so that only an unreachable KMS fails.
        let url = format!(
            "{}/v1/sys/health?standbyok=true&perfstandbyok=true&sealedcode=200&uninitcode=200",
            self.address
        );
        let exchange = async {
            let request = Request::builder().uri(url).body(Full::new(Bytes::new()))?;
            let response = self.client.request(request).await?;
            let status = response.status();
            let body = response.into_body().collect().await?.to_bytes();
            anyhow::ensure!(status.is_success(), "its health endpoint answered {status}");
            Ok(serde_json::from_slice::<Answer>(&body)?)
        };
        match tokio::time::timeout(Duration::from_secs(3), exchange).await {
            Ok(Ok(answer)) => Health {
                reachable: true,
                initialized: answer.initialized,
                sealed: answer.sealed,
                standby: answer.standby,
                version: answer.version,
                error: None,
            },
            Ok(Err(e)) => Health::unreachable(format!("{e:#}")),
            Err(_) => Health::unreachable("it didn't answer in time".to_owned()),
        }
    }

    /// A fresh 256-bit data key from the KMS key `key`, for `who`, its
    /// ciphertext bound to `associated_data`.
    pub async fn generate(&self, who: Identity, key: &KeyId, associated_data: &[u8]) -> Result<DataKey, KmsError> {
        let body = json!({ "bits": 256, "associated_data": STANDARD.encode(associated_data) });
        let data: DataKeyData = self.call(who, &key.path("datakey/plaintext"), body).await?;
        Ok(DataKey {
            plaintext: decode_key(&data.plaintext)?,
            ciphertext: data.ciphertext,
        })
    }

    /// The data key `ciphertext` (from `generate` with the same key and
    /// associated data) holds, for `who`.
    pub async fn decrypt(
        &self,
        who: Identity,
        key: &KeyId,
        ciphertext: &str,
        associated_data: &[u8],
    ) -> Result<Zeroizing<Key>, KmsError> {
        let body = json!({ "ciphertext": ciphertext, "associated_data": STANDARD.encode(associated_data) });
        let data: DecryptData = self.call(who, &key.path("decrypt"), body).await?;
        decode_key(&data.plaintext)
    }

    /// Logs in as `who`, which makes OpenBao create its entity the first time,
    /// and answers with the entity's ID. Its token is kept.
    pub async fn identify(&self, who: Identity) -> Result<String, KmsError> {
        let slot = self.slot(who);
        let mut token = slot.lock().await;
        let (new, entity_id) = self.log_in(who).await?;
        *token = Some(new);
        if entity_id.is_empty() {
            return Err(KmsError::Unavailable(anyhow::anyhow!("the KMS's login answered without an entity")));
        }
        Ok(entity_id)
    }

    /// Calls `path` with `body` as `who`, with the token Cairn has for it, or
    /// a new one if the KMS refuses that because it's no longer valid (rather
    /// than not allowed this call).
    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        who: Identity,
        path: &str,
        body: serde_json::Value,
    ) -> Result<T, KmsError> {
        #[cfg(test)]
        self.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let url = format!("{}/v1/{path}", self.address);
        let mut fresh = false;
        loop {
            let token = self.token(who, fresh).await?;
            let (status, answer) =
                self.post::<T>(&url, &body, Some(&token)).await.map_err(KmsError::Unavailable)?;
            match (status, answer.data) {
                (StatusCode::OK, Some(data)) => return Ok(data),
                // The token expired, or was revoked: once more with a new one.
                (StatusCode::FORBIDDEN, _) if !fresh && !self.valid(&token).await? => fresh = true,
                (StatusCode::FORBIDDEN, _) => return Err(KmsError::Denied),
                (status, _) if status.is_server_error() => {
                    return Err(KmsError::Unavailable(anyhow::anyhow!(
                        "{status}: {}",
                        answer.errors.join("; ")
                    )));
                }
                // Transit's answer for a key it doesn't have.
                (_, _) if answer.errors.iter().any(|e| e.contains("key not found")) => {
                    return Err(KmsError::NoSuchKey);
                }
                (status, _) => {
                    return Err(KmsError::Failed(format!("{status}: {}", answer.errors.join("; "))));
                }
            }
        }
    }

    /// The lock around `who`'s token.
    fn slot(&self, who: Identity) -> Arc<Mutex<Option<Token>>> {
        self.tokens.lock().unwrap().entry(who).or_default().clone()
    }

    /// A token to call with as `who`: the one Cairn has, unless `fresh` (the
    /// KMS refused it) or it's due for renewal.
    async fn token(&self, who: Identity, fresh: bool) -> Result<Zeroizing<String>, KmsError> {
        let slot = self.slot(who);
        let mut token = slot.lock().await;
        let usable = token
            .as_ref()
            .is_some_and(|t| !fresh && t.renew_at.is_none_or(|at| Instant::now() < at));
        if !usable {
            *token = Some(self.log_in(who).await?.0);
        }
        Ok(token.as_ref().unwrap().token.clone())
    }

    /// SSE-S3's key, if it's configured.
    pub fn sse_s3_key(&self) -> Option<&KeyId> {
        self.sse_s3.as_ref().map(|s| &s.key)
    }

    /// Cairn's own identity in the KMS, for SSE-S3, once it has logged in as
    /// itself.
    pub fn cairn_entity(&self) -> Option<String> {
        self.sse_s3.as_ref()?.entity.lock().unwrap().clone()
    }

    /// The data key to seal a new SSE-S3 object's key under, and its
    /// ciphertext: the node's current one, or a new one once that's an hour
    /// old. Asks the KMS as Cairn.
    pub async fn sse_s3_data_key(&self) -> Result<(Zeroizing<Key>, String), KmsError> {
        let sse_s3 = self.sse_s3.as_ref().expect("SSE-S3 is refused without its key (`requested`)");
        let mut current = sse_s3.current.lock().await;
        if let Some((key, since)) = current.as_ref()
            && since.elapsed() < SSE_S3_WRITE_KEY
        {
            return Ok((key.plaintext.clone(), key.ciphertext.clone()));
        }
        let key = self.generate(Identity::Cairn, &sse_s3.key, SSE_S3_AD).await?;
        let answer = (key.plaintext.clone(), key.ciphertext.clone());
        self.keep(sse_s3, &key.ciphertext, &key.plaintext);
        *current = Some((key, Instant::now()));
        Ok(answer)
    }

    /// The SSE-S3 data key `ciphertext` (from the KMS key `key`) holds: from
    /// the node's, or else from the KMS, as Cairn.
    pub async fn sse_s3_open(&self, key: &KeyId, ciphertext: &str) -> Result<Zeroizing<Key>, KmsError> {
        let Some(sse_s3) = &self.sse_s3 else {
            return Err(KmsError::Failed("SSE-S3 has no key (--kms-sse-s3-key)".to_owned()));
        };
        if let Some((opened, used)) = sse_s3.opened.lock().unwrap().get_mut(ciphertext) {
            *used = Instant::now();
            return Ok(opened.clone());
        }
        let opened = self.decrypt(Identity::Cairn, key, ciphertext, SSE_S3_AD).await?;
        self.keep(sse_s3, ciphertext, &opened);
        Ok(opened)
    }

    /// Keeps an SSE-S3 data key, and forgets those unused for an hour.
    fn keep(&self, sse_s3: &SseS3, ciphertext: &str, key: &Key) {
        let mut opened = sse_s3.opened.lock().unwrap();
        opened.retain(|_, (_, used)| used.elapsed() < SSE_S3_KEEP);
        opened.insert(ciphertext.to_owned(), (Zeroizing::new(*key), Instant::now()));
    }

    /// How many calls of the Transit engine this client made.
    #[cfg(test)]
    pub fn transit_calls(&self) -> u64 {
        self.calls.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether the KMS still takes `token` (every token may look itself up).
    async fn valid(&self, token: &str) -> Result<bool, KmsError> {
        let request = Request::builder()
            .method(Method::GET)
            .uri(format!("{}/v1/auth/token/lookup-self", self.address))
            .header("X-Vault-Token", token)
            .body(Full::new(Bytes::new()))
            .map_err(|e| KmsError::Unavailable(e.into()))?;
        let status = tokio::time::timeout(TIMEOUT, self.client.request(request))
            .await
            .map_err(|_| KmsError::Unavailable(anyhow::anyhow!("the KMS didn't answer in time")))?
            .map_err(|e| KmsError::Unavailable(e.into()))?
            .status();
        if status.is_server_error() {
            return Err(KmsError::Unavailable(anyhow::anyhow!("looking up the token: {status}")));
        }
        Ok(status.is_success())
    }

    /// Logs in as `who`: a new token, and its entity's ID.
    async fn log_in(&self, who: Identity) -> Result<(Token, String), KmsError> {
        let result = self.try_log_in(who).await;
        let at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
        let mut logins = self.logins.lock().unwrap();
        logins.last = Some(Login { at, who, error: result.as_ref().err().map(|e| e.to_string()) });
        if let Ok((_, entity)) = &result {
            logins.last_success = Some(at);
            if who == Identity::Cairn && !entity.is_empty() && let Some(sse_s3) = &self.sse_s3 {
                *sse_s3.entity.lock().unwrap() = Some(entity.clone());
            }
        }
        result
    }

    async fn try_log_in(&self, who: Identity) -> Result<(Token, String), KmsError> {
        // (A missing entity ID is checked by `identify`.)
        let body = json!({ "role": self.auth_role, "jwt": self.jwt(who).as_str() });
        let url = format!("{}/v1/auth/{}/login", self.address, self.auth_mount);
        let (status, answer) = self
            .post::<serde_json::Value>(&url, &body, None)
            .await
            .map_err(KmsError::Unavailable)?;
        let Some(auth) = answer.auth.filter(|_| status == StatusCode::OK) else {
            let why = self.explain_login(status, &answer.errors);
            return Err(if status.is_server_error() {
                KmsError::Unavailable(anyhow::anyhow!("logging in: {why}"))
            } else {
                KmsError::LoginRefused(why)
            });
        };
        // Well before the token runs out; one of no TTL doesn't.
        let renew_at = (auth.lease_duration > 0)
            .then(|| Instant::now() + Duration::from_secs(auth.lease_duration) * 2 / 3);
        Ok((Token { token: Zeroizing::new(auth.client_token), renew_at }, auth.entity_id))
    }

    /// What a failed login's answer says is wrong with the KMS's setup for
    /// Cairn, as far as it can be told: OpenBao's own error otherwise.
    fn explain_login(&self, status: StatusCode, errors: &[String]) -> String {
        let (mount, role) = (&self.auth_mount, &self.auth_role);
        let said = errors.join("; ");
        let has = |s: &str| said.contains(s);
        let why = if status == StatusCode::FORBIDDEN {
            format!("OpenBao has no JWT auth method at auth/{mount} (or it isn't a JWT one)")
        } else if has("could not load configuration") {
            format!("the JWT auth method at auth/{mount} isn't configured: set its jwt_validation_pubkeys to Cairn's public key")
        } else if has("no known key successfully validated") {
            format!("the JWT auth method at auth/{mount} doesn't trust Cairn's key: put Cairn's public key in its jwt_validation_pubkeys")
        } else if has("could not be found") && has("role") {
            format!("the JWT auth method at auth/{mount} has no role {role:?}")
        } else if has("audience") {
            format!("the role {role:?} at auth/{mount} must be bound to the audience {AUDIENCE:?} (bound_audiences)")
        } else if has("claim") && has("not found") {
            format!("the role {role:?} at auth/{mount} must take the user from the claim \"sub\" (user_claim)")
        } else {
            return format!("{status}: {said}");
        };
        format!("{why} (OpenBao said: {said})")
    }

    /// A JWT naming `who`, to log in as it with: valid for two minutes, and
    /// since 30 seconds ago, for clocks that differ a little.
    fn jwt(&self, who: Identity) -> Zeroizing<String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
        let claims = json!({
            "iss": "cairn",
            "sub": who.subject(),
            "aud": AUDIENCE,
            "iat": now,
            "nbf": now - 30,
            "exp": now + 120,
        });
        let claims = URL_SAFE_NO_PAD.encode(claims.to_string());
        let signed = format!("{header}.{claims}");
        let signature = URL_SAFE_NO_PAD.encode(self.signer.sign(signed.as_bytes()));
        Zeroizing::new(format!("{signed}.{signature}"))
    }

    /// POSTs `body` as JSON to `url`, and reads the answer.
    async fn post<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
        token: Option<&str>,
    ) -> anyhow::Result<(StatusCode, Answer<T>)> {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(url)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(token) = token {
            request = request.header("X-Vault-Token", token);
        }
        let request = request.body(Full::new(Bytes::from(body.to_string())))?;
        let exchange = async {
            let response = self.client.request(request).await?;
            let status = response.status();
            let body = response.into_body().collect().await?.to_bytes();
            anyhow::Ok((status, body))
        };
        let (status, body) = tokio::time::timeout(TIMEOUT, exchange)
            .await
            .context("the KMS didn't answer in time")??;
        let answer = serde_json::from_slice(&body).unwrap_or(Answer {
            data: None,
            auth: None,
            errors: vec![String::from_utf8_lossy(&body).chars().take(200).collect()],
        });
        Ok((status, answer))
    }
}

impl Health {
    fn unreachable(error: String) -> Health {
        Health { reachable: false, initialized: None, sealed: None, standby: None, version: None, error: Some(error) }
    }
}

/// A 256-bit key from its base64.
fn decode_key(b64: &str) -> Result<Zeroizing<Key>, KmsError> {
    let bytes = Zeroizing::new(STANDARD.decode(b64).unwrap_or_default());
    let key = Key::try_from(bytes.as_slice())
        .map_err(|_| KmsError::Failed("the KMS's data key isn't 256 bits".to_owned()))?;
    Ok(Zeroizing::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_ids_name_a_mount_and_a_key() {
        let id = |s| KeyId::parse(s).map(|k| k.as_string());
        assert_eq!(id("k").as_deref(), Some("transit/k"));
        assert_eq!(id("team-transit/invoices").as_deref(), Some("team-transit/invoices"));
        assert_eq!(id("finance/transit/a_b.c").as_deref(), Some("finance/transit/a_b.c"));
        for bad in ["", "/k", "k/", "a//k", ".", "..", "../sys/k", "a/../k", "a b", "a%2Fb", "a?b", "ä", &"k".repeat(129)] {
            assert_eq!(id(bad), None, "{bad:?}");
        }
        assert_eq!(KeyId::parse("m/k").unwrap().path("decrypt"), "m/decrypt/k");
    }
}
