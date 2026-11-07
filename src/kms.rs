//! A client of a KMS: OpenBao's (or Vault's) Transit secrets engine, which
//! SSE-KMS keeps its keys in (see `s3::sse`).
//!
//! Cairn uses two of its calls, and needs no other permission (`update` on
//! both paths, in OpenBao's terms):
//!
//! - `datakey/plaintext/<key>`: a fresh random data key, both as itself and
//!   encrypted under the named key, which never leaves the KMS;
//! - `decrypt/<key>`: a data key back from its ciphertext.
//!
//! Both take associated data, which the ciphertext is bound to: it decrypts
//! only with the same. Not `encrypt`, which creates a key that doesn't exist
//! yet if the token may, so that a mistyped key name would make a new key.
//!
//! Cairn authenticates with a token from a file (which an agent may keep
//! fresh), or logs in with AppRole. Either way it gets a token again when the
//! KMS refuses the one it has, and an AppRole token before its lease runs out.

use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context as _;
use base64::{Engine, engine::general_purpose::STANDARD};
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
use zeroize::Zeroizing;

use crate::encryption::Key;

/// How long a call to the KMS may take, all in all.
const TIMEOUT: Duration = Duration::from_secs(10);

/// How the KMS is configured: `cairn serve`'s `--kms-*` flags.
#[derive(clap::Args, Debug, Clone)]
pub struct KmsArgs {
    /// URL of the OpenBao (or Vault) server whose Transit engine holds the
    /// keys for SSE-KMS, e.g. https://bao.internal:8200. Without it, requests
    /// for SSE-KMS are refused (501).
    #[arg(long, env = "CAIRN_KMS_ADDRESS")]
    pub kms_address: Option<String>,
    /// Where the Transit engine is mounted.
    #[arg(long, env = "CAIRN_KMS_MOUNT", default_value = "transit")]
    pub kms_mount: String,
    /// The key for SSE-KMS requests that don't name one.
    #[arg(long, env = "CAIRN_KMS_DEFAULT_KEY")]
    pub kms_default_key: Option<String>,
    /// PEM file of the CA certificates to trust for the KMS's TLS. Without
    /// it, the public web's (Mozilla's) roots.
    #[arg(long, env = "CAIRN_KMS_CA_CERT")]
    pub kms_ca_cert: Option<PathBuf>,
    /// File holding a token for the KMS. Read again whenever the KMS refuses
    /// the token Cairn has, so an agent may renew it in place.
    #[arg(long, env = "CAIRN_KMS_TOKEN_FILE")]
    pub kms_token_file: Option<PathBuf>,
    /// The AppRole role ID to log in to the KMS with, instead of a token file.
    #[arg(long, env = "CAIRN_KMS_APPROLE_ROLE_ID")]
    pub kms_approle_role_id: Option<String>,
    /// File holding the AppRole secret ID.
    #[arg(long, env = "CAIRN_KMS_APPROLE_SECRET_ID_FILE")]
    pub kms_approle_secret_id_file: Option<PathBuf>,
}

/// How Cairn gets a token.
#[derive(Debug)]
enum Auth {
    TokenFile(PathBuf),
    AppRole { role_id: String, secret_id_file: PathBuf },
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
    /// The KMS refused Cairn the key (its policy doesn't allow it).
    Denied,
    /// The KMS couldn't be reached, or failed.
    Unavailable(anyhow::Error),
    /// The KMS refused the request otherwise: say, a ciphertext that isn't
    /// one, or associated data it wasn't bound to.
    Failed(String),
}

impl std::fmt::Display for KmsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KmsError::NoSuchKey => write!(f, "the KMS has no such key"),
            KmsError::Denied => write!(f, "the KMS refused Cairn the key"),
            KmsError::Unavailable(e) => write!(f, "the KMS is unavailable: {e:#}"),
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
    mount: String,
    default_key: String,
    auth: Auth,
    token: Mutex<Option<Token>>,
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
                args.kms_default_key.is_none()
                    && args.kms_token_file.is_none()
                    && args.kms_approle_role_id.is_none()
                    && args.kms_approle_secret_id_file.is_none()
                    && args.kms_ca_cert.is_none(),
                "the KMS flags need --kms-address"
            );
            return Ok(None);
        };
        let address = address.trim_end_matches('/').to_owned();
        anyhow::ensure!(
            address.starts_with("https://") || address.starts_with("http://"),
            "--kms-address must be an http(s) URL"
        );
        let default_key = args
            .kms_default_key
            .clone()
            .context("--kms-address needs --kms-default-key, for requests that name no key")?;
        anyhow::ensure!(valid_key_name(&default_key), "--kms-default-key isn't a valid key name");
        let auth = match (&args.kms_token_file, &args.kms_approle_role_id, &args.kms_approle_secret_id_file) {
            (Some(file), None, None) => Auth::TokenFile(file.clone()),
            (None, Some(role_id), Some(secret_id_file)) => Auth::AppRole {
                role_id: role_id.clone(),
                secret_id_file: secret_id_file.clone(),
            },
            _ => anyhow::bail!(
                "the KMS needs either --kms-token-file, or both --kms-approle-role-id and \
                 --kms-approle-secret-id-file"
            ),
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
            mount: args.kms_mount.trim_matches('/').to_owned(),
            default_key,
            auth,
            token: Mutex::new(None),
        })))
    }

    /// The key for requests that name none.
    pub fn default_key(&self) -> &str {
        &self.default_key
    }

    /// A fresh 256-bit data key from the KMS key `key`, its ciphertext bound
    /// to `associated_data`.
    pub async fn generate(&self, key: &str, associated_data: &[u8]) -> Result<DataKey, KmsError> {
        let body = json!({ "bits": 256, "associated_data": STANDARD.encode(associated_data) });
        let data: DataKeyData = self.call(&format!("datakey/plaintext/{key}"), body).await?;
        Ok(DataKey {
            plaintext: decode_key(&data.plaintext)?,
            ciphertext: data.ciphertext,
        })
    }

    /// The data key `ciphertext` (from `generate` with the same key and
    /// associated data) holds.
    pub async fn decrypt(
        &self,
        key: &str,
        ciphertext: &str,
        associated_data: &[u8],
    ) -> Result<Zeroizing<Key>, KmsError> {
        let body = json!({ "ciphertext": ciphertext, "associated_data": STANDARD.encode(associated_data) });
        let data: DecryptData = self.call(&format!("decrypt/{key}"), body).await?;
        decode_key(&data.plaintext)
    }

    /// Calls the Transit engine's `path` with `body`, with a token, and with
    /// another one if the KMS refuses the one Cairn has because it's no longer
    /// valid (rather than not allowed this call).
    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<T, KmsError> {
        debug_assert!(path.rsplit('/').next().is_some_and(valid_key_name));
        let url = format!("{}/v1/{}/{path}", self.address, self.mount);
        let mut fresh = false;
        loop {
            let token = self.token(fresh).await?;
            let (status, answer) =
                self.post::<T>(&url, &body, Some(&token)).await.map_err(KmsError::Unavailable)?;
            match (status, answer.data) {
                (StatusCode::OK, Some(data)) => return Ok(data),
                // The token expired, or was revoked: once more with a new one.
                // Not merely for a key the policy doesn't allow, or any client
                // could make Cairn log in again and again (using up a secret
                // ID that may be used only so often).
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

    /// A token to call with: the one Cairn has, unless `fresh` (the KMS
    /// refused it) or it's due for renewal.
    async fn token(&self, fresh: bool) -> Result<Zeroizing<String>, KmsError> {
        let mut token = self.token.lock().await;
        let usable = token
            .as_ref()
            .is_some_and(|t| !fresh && t.renew_at.is_none_or(|at| Instant::now() < at));
        if !usable {
            *token = Some(self.log_in().await?);
        }
        Ok(token.as_ref().unwrap().token.clone())
    }

    /// A new token: from its file, or by logging in with AppRole.
    async fn log_in(&self) -> Result<Token, KmsError> {
        let read = |path: &PathBuf| {
            std::fs::read_to_string(path)
                .map(|s| Zeroizing::new(s.trim().to_owned()))
                .with_context(|| format!("reading {}", path.display()))
                .map_err(KmsError::Unavailable)
        };
        match &self.auth {
            Auth::TokenFile(path) => Ok(Token { token: read(path)?, renew_at: None }),
            Auth::AppRole { role_id, secret_id_file } => {
                let secret_id = read(secret_id_file)?;
                let body = json!({ "role_id": role_id, "secret_id": secret_id.as_str() });
                let url = format!("{}/v1/auth/approle/login", self.address);
                let (status, answer) = self
                    .post::<serde_json::Value>(&url, &body, None)
                    .await
                    .map_err(KmsError::Unavailable)?;
                let Some(auth) = answer.auth.filter(|_| status == StatusCode::OK) else {
                    return Err(KmsError::Unavailable(anyhow::anyhow!(
                        "logging in with AppRole: {status}: {}",
                        answer.errors.join("; ")
                    )));
                };
                // Well before the lease runs out; a lease of 0 doesn't.
                let renew_at = (auth.lease_duration > 0)
                    .then(|| Instant::now() + Duration::from_secs(auth.lease_duration) * 2 / 3);
                Ok(Token { token: Zeroizing::new(auth.client_token), renew_at })
            }
        }
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

/// A 256-bit key from its base64.
fn decode_key(b64: &str) -> Result<Zeroizing<Key>, KmsError> {
    let bytes = Zeroizing::new(STANDARD.decode(b64).unwrap_or_default());
    let key = Key::try_from(bytes.as_slice())
        .map_err(|_| KmsError::Failed("the KMS's data key isn't 256 bits".to_owned()))?;
    Ok(Zeroizing::new(key))
}

/// Whether `name` may name a KMS key: it goes into the KMS's URL, so only
/// characters that need no escaping, and no path segments of its own.
pub fn valid_key_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_names_stay_in_their_path_segment() {
        for name in ["k", "cairn-objects", "a_b.c", "K1"] {
            assert!(valid_key_name(name), "{name}");
        }
        for name in ["", ".", "..", "../sys", "a/b", "a b", "a%2Fb", "a?b", "ä", &"k".repeat(129)] {
            assert!(!valid_key_name(name), "{name}");
        }
    }
}
