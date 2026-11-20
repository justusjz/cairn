//! The root key in OpenBao (or Vault): one key of a Transit engine, which
//! never leaves it. Cairn wraps and unwraps with it (`encrypt` and `decrypt`
//! on the key, with associated data), and nothing else: its keys' material,
//! SSE-S3's data keys, the backup's key and the tiers' (see `kms`).
//!
//! Cairn logs in as itself, through a JWT auth mount of its own: a JWT that
//! it signs with its private key (Ed25519), whose subject is `cairn`. Its
//! token is kept until two thirds of its TTL have passed; OpenBao applies a
//! revocation to tokens already issued, so that doesn't delay one.
//!
//! What the KMS's admin grants Cairn is the whole of what it can do in
//! OpenBao: `update` on the key's `encrypt` and `decrypt` paths. Not
//! `create`, so that `encrypt` never makes a key of a mistyped name.

use std::{
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
use zeroize::Zeroizing;

use super::RootError;

/// How long a call to OpenBao may take, all in all.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The audience of Cairn's JWTs, which its JWT role must be bound to.
pub const AUDIENCE: &str = "cairn";
/// The subject of Cairn's JWTs.
pub const SUBJECT: &str = "cairn";

/// How Cairn reaches the root key in OpenBao.
pub struct TransitArgs {
    pub address: String,
    pub jwt_key: PathBuf,
    pub auth_mount: String,
    pub auth_role: String,
    /// `<mount>/<key>`.
    pub key: String,
    pub ca_cert: Option<PathBuf>,
}

/// A token, and when to stop using it (`None`: when it's refused).
struct Token {
    token: Zeroizing<String>,
    renew_at: Option<Instant>,
}

pub struct Transit {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    /// The server's URL, without a trailing slash.
    address: String,
    signer: ring::signature::Ed25519KeyPair,
    auth_mount: String,
    auth_role: String,
    /// The Transit engine's mount, and the key's name in it.
    mount: String,
    name: String,
    token: Mutex<Option<Token>>,
    /// How the node's logins went, for the console.
    logins: std::sync::Mutex<Logins>,
    /// Calls of the Transit engine, for tests to count.
    calls: std::sync::atomic::AtomicU64,
}

/// How a node's logins to OpenBao went: its last, and its last that worked.
#[derive(Clone, Default)]
pub struct Logins {
    /// When the last one was, in seconds since the Unix epoch, and why it
    /// failed, if it did: what's likely wrong.
    pub last: Option<(f64, Option<String>)>,
    /// When the last one that worked was, in seconds since the Unix epoch.
    pub last_success: Option<f64>,
}

/// How OpenBao is, as its health endpoint tells.
pub struct Health {
    pub reachable: bool,
    pub initialized: Option<bool>,
    pub sealed: Option<bool>,
    pub standby: Option<bool>,
    pub version: Option<String>,
    pub error: Option<String>,
}

/// What OpenBao answers with: `data` on success, `errors` otherwise.
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
struct EncryptData {
    ciphertext: String,
}

#[derive(Deserialize)]
struct DecryptData {
    plaintext: String,
}

/// Whether `segment` may be a segment of a path in OpenBao: only characters
/// that need no escaping, and no path segments of its own (`.`, `..`).
fn valid_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= 128
        && !segment.starts_with('.')
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

/// A Transit key's mount and name, from `<mount>/<key>` (the mount may have
/// namespaces in front).
fn parse_key(key: &str) -> Option<(String, String)> {
    let (mount, name) = key.rsplit_once('/')?;
    (mount.split('/').all(valid_segment) && valid_segment(name))
        .then(|| (mount.to_owned(), name.to_owned()))
}

impl Transit {
    /// The client `args` configure. Checks the configuration only: OpenBao
    /// itself isn't asked anything yet.
    pub fn new(args: &TransitArgs) -> anyhow::Result<Transit> {
        let address = args.address.trim_end_matches('/').to_owned();
        anyhow::ensure!(
            address.starts_with("https://") || address.starts_with("http://"),
            "--kms-address must be an http(s) URL"
        );
        let signer = {
            use rustls::pki_types::{PrivatePkcs8KeyDer, pem::PemObject};
            let der = PrivatePkcs8KeyDer::from_pem_file(&args.jwt_key).with_context(|| {
                format!("reading {} (a PKCS#8 PEM key)", args.jwt_key.display())
            })?;
            ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(der.secret_pkcs8_der())
                .map_err(|e| {
                    anyhow::anyhow!("{} isn't an Ed25519 key: {e}", args.jwt_key.display())
                })?
        };
        for (flag, value) in [
            ("--kms-auth-mount", &args.auth_mount),
            ("--kms-auth-role", &args.auth_role),
        ] {
            anyhow::ensure!(
                value.split('/').all(valid_segment),
                "{flag} isn't a valid path"
            );
        }
        let (mount, name) = parse_key(&args.key)
            .context("--kms-transit-key must be <mount>/<key>, of plain names")?;
        let roots = match &args.ca_cert {
            Some(path) => {
                use rustls::pki_types::{CertificateDer, pem::PemObject};
                let mut roots = rustls::RootCertStore::empty();
                for cert in CertificateDer::pem_file_iter(path)
                    .with_context(|| format!("reading {}", path.display()))?
                {
                    roots.add(cert.with_context(|| format!("reading {}", path.display()))?)?;
                }
                anyhow::ensure!(
                    !roots.is_empty(),
                    "{} holds no certificates",
                    path.display()
                );
                roots
            }
            None => {
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
            }
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
        Ok(Transit {
            client: Client::builder(TokioExecutor::new()).build(connector),
            address,
            signer,
            auth_mount: args.auth_mount.clone(),
            auth_role: args.auth_role.clone(),
            mount,
            name,
            token: Mutex::new(None),
            logins: std::sync::Mutex::default(),
            calls: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// OpenBao's URL.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Where Cairn's JWT auth method is mounted, and the role its logins use.
    pub fn auth(&self) -> (&str, &str) {
        (&self.auth_mount, &self.auth_role)
    }

    /// The root key, as `<mount>/<key>`.
    pub fn key(&self) -> String {
        format!("{}/{}", self.mount, self.name)
    }

    /// How this node's logins went.
    pub fn logins(&self) -> Logins {
        self.logins.lock().unwrap().clone()
    }

    /// How many calls of the Transit engine this client made.
    #[cfg(test)]
    pub fn calls(&self) -> u64 {
        self.calls.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The public key of the key Cairn signs its logins with, as PEM: what
    /// the JWT auth mount for Cairn is to trust (`jwt_validation_pubkeys`).
    pub fn public_key_pem(&self) -> String {
        use ring::signature::KeyPair;
        // An Ed25519 SubjectPublicKeyInfo: its fixed DER prefix, and the key.
        const PREFIX: [u8; 12] = [
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        let der = [&PREFIX[..], self.signer.public_key().as_ref()].concat();
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            STANDARD.encode(der)
        )
    }

    /// How OpenBao is, from its health endpoint, which needs no token.
    pub async fn health(&self) -> Health {
        #[derive(Deserialize)]
        struct Answer {
            initialized: Option<bool>,
            sealed: Option<bool>,
            standby: Option<bool>,
            version: Option<String>,
        }
        // Each state answers 200, so that only an unreachable server fails.
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

    /// `plaintext` encrypted under the root key, bound to `associated_data`:
    /// Transit's ciphertext (`vault:v<n>:…`).
    pub async fn encrypt(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<String, RootError> {
        let body = json!({
            "plaintext": STANDARD.encode(plaintext),
            "associated_data": STANDARD.encode(associated_data),
        });
        let data: EncryptData = self.call("encrypt", body).await?;
        Ok(data.ciphertext)
    }

    /// What `ciphertext` (from `encrypt` with the same associated data)
    /// holds.
    pub async fn decrypt(
        &self,
        ciphertext: &str,
        associated_data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, RootError> {
        let body = json!({
            "ciphertext": ciphertext,
            "associated_data": STANDARD.encode(associated_data),
        });
        let data: DecryptData = self.call("decrypt", body).await?;
        let data = Zeroizing::new(data.plaintext);
        STANDARD
            .decode(data.as_bytes())
            .map(Zeroizing::new)
            .map_err(|_| RootError::Failed("OpenBao's plaintext isn't base64".to_owned()))
    }

    /// Calls the key's `operation` with `body`, with the token Cairn has, or
    /// a new one if OpenBao refuses that because it's no longer valid
    /// (rather than not allowed this call).
    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        operation: &str,
        body: serde_json::Value,
    ) -> Result<T, RootError> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let url = format!(
            "{}/v1/{}/{operation}/{}",
            self.address, self.mount, self.name
        );
        let mut fresh = false;
        loop {
            let token = self.token(fresh).await?;
            let (status, answer) = self
                .post::<T>(&url, &body, Some(&token))
                .await
                .map_err(RootError::Unavailable)?;
            match (status, answer.data) {
                (StatusCode::OK, Some(data)) => return Ok(data),
                // The token expired, or was revoked: once more with a new one.
                (StatusCode::FORBIDDEN, _) if !fresh && !self.valid(&token).await? => fresh = true,
                (StatusCode::FORBIDDEN, _) => {
                    return Err(RootError::Unavailable(anyhow::anyhow!(
                        "OpenBao refused Cairn the root key {}: grant its policy update on {}/encrypt/{} and {}/decrypt/{}",
                        self.key(),
                        self.mount,
                        self.name,
                        self.mount,
                        self.name
                    )));
                }
                (status, _) if status.is_server_error() => {
                    return Err(RootError::Unavailable(anyhow::anyhow!(
                        "{status}: {}",
                        answer.errors.join("; ")
                    )));
                }
                // Transit's answer for a key it doesn't have: the root's
                // gone, which nothing but the admin can mend.
                (_, _) if answer.errors.iter().any(|e| e.contains("key not found")) => {
                    return Err(RootError::Unavailable(anyhow::anyhow!(
                        "OpenBao has no root key {}",
                        self.key()
                    )));
                }
                (status, _) => {
                    return Err(RootError::Failed(format!(
                        "{status}: {}",
                        answer.errors.join("; ")
                    )));
                }
            }
        }
    }

    /// A token to call with: the one Cairn has, unless `fresh` (OpenBao
    /// refused it) or it's due for renewal.
    async fn token(&self, fresh: bool) -> Result<Zeroizing<String>, RootError> {
        let mut token = self.token.lock().await;
        let usable = token
            .as_ref()
            .is_some_and(|t| !fresh && t.renew_at.is_none_or(|at| Instant::now() < at));
        if !usable {
            *token = Some(self.log_in().await?);
        }
        Ok(token.as_ref().unwrap().token.clone())
    }

    /// Whether OpenBao still takes `token` (every token may look itself up).
    async fn valid(&self, token: &str) -> Result<bool, RootError> {
        let request = Request::builder()
            .method(Method::GET)
            .uri(format!("{}/v1/auth/token/lookup-self", self.address))
            .header("X-Vault-Token", token)
            .body(Full::new(Bytes::new()))
            .map_err(|e| RootError::Unavailable(e.into()))?;
        let status = tokio::time::timeout(TIMEOUT, self.client.request(request))
            .await
            .map_err(|_| RootError::Unavailable(anyhow::anyhow!("OpenBao didn't answer in time")))?
            .map_err(|e| RootError::Unavailable(e.into()))?
            .status();
        if status.is_server_error() {
            return Err(RootError::Unavailable(anyhow::anyhow!(
                "looking up the token: {status}"
            )));
        }
        Ok(status.is_success())
    }

    /// Logs in: a new token.
    async fn log_in(&self) -> Result<Token, RootError> {
        let result = self.try_log_in().await;
        let at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let mut logins = self.logins.lock().unwrap();
        logins.last = Some((at, result.as_ref().err().map(|e| e.to_string())));
        if result.is_ok() {
            logins.last_success = Some(at);
        }
        result
    }

    async fn try_log_in(&self) -> Result<Token, RootError> {
        let body = json!({ "role": self.auth_role, "jwt": self.jwt().as_str() });
        let url = format!("{}/v1/auth/{}/login", self.address, self.auth_mount);
        let (status, answer) = self
            .post::<serde_json::Value>(&url, &body, None)
            .await
            .map_err(RootError::Unavailable)?;
        let Some(auth) = answer.auth.filter(|_| status == StatusCode::OK) else {
            let why = self.explain_login(status, &answer.errors);
            return Err(RootError::Unavailable(anyhow::anyhow!(
                "OpenBao refused Cairn's login: {why}"
            )));
        };
        // Well before the token runs out; one of no TTL doesn't.
        let renew_at = (auth.lease_duration > 0)
            .then(|| Instant::now() + Duration::from_secs(auth.lease_duration) * 2 / 3);
        Ok(Token {
            token: Zeroizing::new(auth.client_token),
            renew_at,
        })
    }

    /// What a failed login's answer says is wrong with OpenBao's setup for
    /// Cairn, as far as it can be told: OpenBao's own error otherwise.
    fn explain_login(&self, status: StatusCode, errors: &[String]) -> String {
        let (mount, role) = (&self.auth_mount, &self.auth_role);
        let said = errors.join("; ");
        let has = |s: &str| said.contains(s);
        let why = if status == StatusCode::FORBIDDEN {
            format!("OpenBao has no JWT auth method at auth/{mount} (or it isn't a JWT one)")
        } else if has("could not load configuration") {
            format!(
                "the JWT auth method at auth/{mount} isn't configured: set its jwt_validation_pubkeys to Cairn's public key"
            )
        } else if has("no known key successfully validated") {
            format!(
                "the JWT auth method at auth/{mount} doesn't trust Cairn's key: put Cairn's public key in its jwt_validation_pubkeys"
            )
        } else if has("could not be found") && has("role") {
            format!("the JWT auth method at auth/{mount} has no role {role:?}")
        } else if has("audience") {
            format!(
                "the role {role:?} at auth/{mount} must be bound to the audience {AUDIENCE:?} (bound_audiences)"
            )
        } else if has("claim") && has("not found") {
            format!(
                "the role {role:?} at auth/{mount} must take the user from the claim \"sub\" (user_claim)"
            )
        } else if has("sub") && has("bound") {
            format!("the role {role:?} at auth/{mount} must be bound to the subject {SUBJECT:?}")
        } else {
            return format!("{status}: {said}");
        };
        format!("{why} (OpenBao said: {said})")
    }

    /// A JWT naming Cairn, to log in with: valid for two minutes, and since
    /// 30 seconds ago, for clocks that differ a little.
    fn jwt(&self) -> Zeroizing<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
        let claims = json!({
            "iss": "cairn",
            "sub": SUBJECT,
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
            .context("OpenBao didn't answer in time")??;
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
        Health {
            reachable: false,
            initialized: None,
            sealed: None,
            standby: None,
            version: None,
            error: Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_keys_name_a_mount_and_a_key() {
        let key = |s| parse_key(s).map(|(m, n)| format!("{m}|{n}"));
        assert_eq!(key("transit/root").as_deref(), Some("transit|root"));
        assert_eq!(key("ns/transit/a_b.c").as_deref(), Some("ns/transit|a_b.c"));
        for bad in [
            "", "k", "/k", "k/", "a//k", "../sys/k", "a b/k", "t/a%2Fb", "t/ä",
        ] {
            assert_eq!(key(bad), None, "{bad:?}");
        }
    }
}
