//! OpenID Connect sign-in to the console, with any provider that follows
//! the standard (Keycloak, Authentik, Dex, Entra ID, Google, Okta, ...):
//! superadmins configure one by its issuer URL and a client (its ID, and a
//! secret, unless it's a public client), and its discovery document
//! (`/.well-known/openid-configuration`) says the rest.
//!
//! The flow is the authorization code flow with PKCE (S256), a `state` (kept
//! in the database as its hash, used once, for ten minutes) and a `nonce`.
//! The ID token, which comes from the token endpoint over TLS, is checked
//! nevertheless: its signature by the provider's keys (its JWKS: RS256-512,
//! PS256-512, ES256, ES384, EdDSA), its issuer, audience (and `azp`), expiry
//! and nonce.
//!
//! An identity at a provider (its issuer's `sub`) signs in a login it's
//! linked to, and nothing else: it's linked by an enrollment link ("continue
//! with ..."), or from the account page, signed in. No account is ever
//! entered for a matching e-mail address. Providers' URLs must be HTTPS but
//! on loopback (for trying it, and tests).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::Context;
use base64::{Engine, engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}};
use deadpool_postgres::Object;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, body::Bytes, header};
use hyper_rustls::HttpsConnector;
use hyper_util::{client::legacy::{Client, connect::HttpConnector}, rt::TokioExecutor};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use ring::{digest, signature};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use super::store;
use crate::{db::Cached, users::Invalid};

/// How long a sign-in at a provider may take.
pub const FLOW_TTL: Duration = Duration::from_secs(10 * 60);
/// How long a provider's discovery document and keys are kept.
const CACHE_TTL: Duration = Duration::from_secs(3600);
/// How long a provider may take to answer.
const TIMEOUT: Duration = Duration::from_secs(10);
/// How far tokens' times may be off.
const LEEWAY: u64 = 60;
/// The most a provider's answer may hold.
const MAX_ANSWER: usize = 1 << 20;

/// A provider, as superadmins configure it.
#[derive(Clone, Debug)]
pub struct Provider {
    pub name: String,
    pub label: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scopes: String,
}

/// What a provider's discovery document says, of what Cairn uses.
#[derive(Clone, Debug, Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Vec<String>,
}

type Https = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// The HTTP client, and what's cached of providers.
struct Oidc {
    client: Https,
    discovery: Mutex<HashMap<String, (Instant, Discovery)>>,
    keys: Mutex<HashMap<String, (Instant, Vec<Value>)>>,
}

fn oidc() -> &'static Oidc {
    static OIDC: OnceLock<Oidc> = OnceLock::new();
    OIDC.get_or_init(|| {
        let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring has TLS 1.2 and 1.3")
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = hyper_rustls::HttpsConnectorBuilder::new().with_tls_config(tls).https_or_http().enable_http1().build();
        Oidc {
            client: Client::builder(TokioExecutor::new()).build(connector),
            discovery: Mutex::default(),
            keys: Mutex::default(),
        }
    })
}

/// Whether `url` may be a provider's: HTTPS, or HTTP on loopback.
pub fn check_url(url: &str) -> Result<(), Invalid> {
    let uri: hyper::Uri = url.parse().map_err(|_| Invalid(format!("{url:?} isn't a URL")))?;
    let host = uri.host().unwrap_or("");
    let loopback = host == "localhost" || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()) || host == "[::1]";
    match uri.scheme_str() {
        Some("https") => Ok(()),
        Some("http") if loopback => Ok(()),
        _ => Err(Invalid(format!("{url:?} isn't an HTTPS URL"))),
    }
}

/// GETs `url`, as JSON.
async fn get_json<T: serde::de::DeserializeOwned>(url: &str) -> anyhow::Result<T> {
    check_url(url)?;
    let request = Request::builder().method(Method::GET).uri(url).header(header::ACCEPT, "application/json").body(Full::new(Bytes::new()))?;
    let (status, body) = exchange(request).await?;
    anyhow::ensure!(status.is_success(), "{url} answered {status}");
    serde_json::from_slice(&body).with_context(|| format!("{url} didn't answer JSON as expected"))
}

async fn exchange(request: Request<Full<Bytes>>) -> anyhow::Result<(hyper::StatusCode, Bytes)> {
    let call = async {
        let response = oidc().client.request(request).await?;
        let status = response.status();
        let body = http_body_util::Limited::new(response.into_body(), MAX_ANSWER)
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("reading the answer: {e}"))?
            .to_bytes();
        anyhow::Ok((status, body))
    };
    tokio::time::timeout(TIMEOUT, call).await.context("the provider didn't answer in time")?
}

/// The provider's discovery document (cached).
async fn discovery(provider: &Provider) -> anyhow::Result<Discovery> {
    let issuer = provider.issuer.trim_end_matches('/');
    if let Some((at, found)) = oidc().discovery.lock().unwrap().get(issuer)
        && at.elapsed() < CACHE_TTL
    {
        return Ok(found.clone());
    }
    let found: Discovery = get_json(&format!("{issuer}/.well-known/openid-configuration")).await?;
    // OIDC Discovery §4.3: the document is the issuer's own.
    anyhow::ensure!(
        found.issuer.trim_end_matches('/') == issuer,
        "the discovery document is of issuer {:?}, not {issuer:?}",
        found.issuer
    );
    for url in [&found.authorization_endpoint, &found.token_endpoint, &found.jwks_uri] {
        check_url(url)?;
    }
    oidc().discovery.lock().unwrap().insert(issuer.to_owned(), (Instant::now(), found.clone()));
    Ok(found)
}

/// Checks that a provider can be used: its discovery document, and keys.
pub async fn check_provider(provider: &Provider) -> anyhow::Result<()> {
    check_url(&provider.issuer)?;
    let found = discovery(provider).await?;
    keys(&found.jwks_uri, false).await?;
    Ok(())
}

/// The provider's keys (JWKs), cached; `fresh`: fetched again, if they're
/// older than a minute (a key it signs with now that Cairn hasn't seen).
async fn keys(uri: &str, fresh: bool) -> anyhow::Result<Vec<Value>> {
    if let Some((at, keys)) = oidc().keys.lock().unwrap().get(uri)
        && at.elapsed() < CACHE_TTL
        && !(fresh && at.elapsed() > Duration::from_secs(60))
    {
        return Ok(keys.clone());
    }
    #[derive(Deserialize)]
    struct Jwks {
        keys: Vec<Value>,
    }
    let found: Jwks = get_json(uri).await?;
    oidc().keys.lock().unwrap().insert(uri.to_owned(), (Instant::now(), found.keys.clone()));
    Ok(found.keys)
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn random(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    getrandom::fill(&mut bytes).expect("the OS random number generator failed");
    b64(&bytes)
}

/// What RFC 3986 leaves unencoded: letters, digits and `-._~`.
const UNRESERVED: percent_encoding::AsciiSet = NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

fn encode(s: &str) -> String {
    utf8_percent_encode(s, &UNRESERVED).to_string()
}

/// What a sign-in at a provider is for.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Purpose {
    /// Signing in.
    Login,
    /// A new login, for an enrollment link's identity.
    Enroll,
    /// Linking the identity to a signed-in login.
    Link,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::Login => "login",
            Purpose::Enroll => "enroll",
            Purpose::Link => "link",
        }
    }

    fn of(s: &str) -> Option<Purpose> {
        [Purpose::Login, Purpose::Enroll, Purpose::Link].into_iter().find(|p| p.as_str() == s)
    }
}

/// What a sign-in in progress carries to its end.
#[derive(Default)]
pub struct Carried<'a> {
    /// The signed-in login (to link to).
    pub login: Option<Uuid>,
    /// The enrollment link's token.
    pub enrollment: Option<&'a str>,
}

/// The provider named `name`.
pub async fn provider(client: &Object, name: &str) -> anyhow::Result<Option<Provider>> {
    let row = client
        .query_opt_cached(
            "SELECT name, label, issuer, client_id, client_secret, scopes FROM oidc_providers WHERE name = $1",
            &[&name],
        )
        .await?;
    Ok(row.map(|r| Provider {
        name: r.get(0),
        label: r.get(1),
        issuer: r.get(2),
        client_id: r.get(3),
        client_secret: r.get(4),
        scopes: r.get(5),
    }))
}

/// Every provider, by name.
pub async fn providers(client: &Object) -> anyhow::Result<Vec<Provider>> {
    let rows = client
        .query_cached("SELECT name, label, issuer, client_id, client_secret, scopes FROM oidc_providers ORDER BY name", &[])
        .await?;
    Ok(rows
        .iter()
        .map(|r| Provider {
            name: r.get(0),
            label: r.get(1),
            issuer: r.get(2),
            client_id: r.get(3),
            client_secret: r.get(4),
            scopes: r.get(5),
        })
        .collect())
}

/// Starts a sign-in at `provider`, for `purpose`: the URL to send the
/// browser to.
pub async fn start(
    client: &Object,
    provider: &Provider,
    redirect_uri: &str,
    purpose: Purpose,
    carried: Carried<'_>,
) -> anyhow::Result<String> {
    let found = discovery(provider).await?;
    let (state, nonce, verifier) = (random(32), random(32), random(48));
    let challenge = b64(digest::digest(&digest::SHA256, verifier.as_bytes()).as_ref());
    client
        .execute_cached(
            "INSERT INTO oidc_flows (state_hash, provider, nonce, verifier, purpose, login_id, enrollment, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8))",
            &[
                &store::hash(&state),
                &provider.name,
                &nonce,
                &verifier,
                &purpose.as_str(),
                &carried.login,
                &carried.enrollment.map(store::hash),
                &FLOW_TTL.as_secs_f64(),
            ],
        )
        .await?;
    let url = format!(
        "{}{}response_type=code&client_id={}&redirect_uri={}&scope={}&state={state}&nonce={nonce}\
         &code_challenge={challenge}&code_challenge_method=S256",
        found.authorization_endpoint,
        if found.authorization_endpoint.contains('?') { '&' } else { '?' },
        encode(&provider.client_id),
        encode(redirect_uri),
        encode(&provider.scopes),
    );
    Ok(url)
}

/// A finished sign-in at a provider.
pub struct Finished {
    pub provider: Provider,
    pub purpose: Purpose,
    /// The identity at the provider: its subject, and what it says of
    /// itself.
    pub subject: String,
    pub email: Option<String>,
    pub name: Option<String>,
    /// What was carried (the enrollment link's token as its hash).
    pub login: Option<Uuid>,
    pub enrollment: Option<Vec<u8>>,
}

/// Why a sign-in at a provider didn't work, for the person to read.
#[derive(Debug)]
pub struct Failed(pub String);

fn failed<T>(message: impl Into<String>) -> Result<T, Failed> {
    Err(Failed(message.into()))
}

/// Ends a sign-in at a provider, with its answer (`state`, `code`): uses up
/// its state, exchanges the code for tokens, and checks the ID token.
pub async fn finish(client: &Object, redirect_uri: &str, state: &str, code: &str) -> anyhow::Result<Result<Finished, Failed>> {
    let row = client
        .query_opt_cached(
            "DELETE FROM oidc_flows WHERE state_hash = $1 AND expires_at > now()
             RETURNING provider, nonce, verifier, purpose, login_id, enrollment",
            &[&store::hash(state)],
        )
        .await?;
    let Some(row) = row else {
        return Ok(failed("this sign-in took too long, or was done already; try again"));
    };
    let name: String = row.get(0);
    let Some(provider) = self::provider(client, &name).await? else {
        return Ok(failed("that sign-in provider is no longer configured"));
    };
    let (nonce, verifier): (String, String) = (row.get(1), row.get(2));
    // (A sign-in again as the operator account, which there's none of
    // now, started before an upgrade, is none of these.)
    let Some(purpose) = Purpose::of(row.get(3)) else {
        return Ok(failed("this sign-in is of a kind there's no more of; sign in again"));
    };
    let found = discovery(&provider).await?;
    let token = match redeem(&provider, &found, redirect_uri, code, &verifier).await? {
        Ok(token) => token,
        Err(e) => return Ok(Err(e)),
    };
    let claims = match verify(&provider, &found, &token, &nonce).await? {
        Ok(claims) => claims,
        Err(e) => return Ok(Err(e)),
    };
    let text = |key: &str| claims.get(key).and_then(Value::as_str).map(str::to_owned);
    let Some(subject) = text("sub").filter(|s| !s.is_empty()) else {
        return Ok(failed("the provider's ID token names no subject"));
    };
    let email = text("email").filter(|_| claims.get("email_verified").and_then(Value::as_bool) != Some(false));
    let name = text("name").or_else(|| text("preferred_username"));
    Ok(Ok(Finished {
        provider,
        purpose,
        subject,
        email,
        name,
        login: row.get(4),
        enrollment: row.get(5),
    }))
}

/// Exchanges `code` at the token endpoint: the ID token.
async fn redeem(
    provider: &Provider,
    found: &Discovery,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> anyhow::Result<Result<String, Failed>> {
    let mut form = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&code_verifier={}",
        encode(code),
        encode(redirect_uri),
        encode(verifier)
    );
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(&found.token_endpoint)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json");
    // client_secret_basic, the default (OIDC Core §9), unless the provider
    // only takes client_secret_post; a public client sends its ID.
    let methods = &found.token_endpoint_auth_methods_supported;
    match &provider.client_secret {
        Some(secret) if methods.is_empty() || methods.iter().any(|m| m == "client_secret_basic") => {
            let credentials = format!("{}:{}", encode(&provider.client_id), encode(secret));
            request = request.header(header::AUTHORIZATION, format!("Basic {}", STANDARD.encode(credentials)));
        }
        Some(secret) => {
            form.push_str(&format!("&client_id={}&client_secret={}", encode(&provider.client_id), encode(secret)));
        }
        None => form.push_str(&format!("&client_id={}", encode(&provider.client_id))),
    }
    check_url(&found.token_endpoint)?;
    let (status, body) = exchange(request.body(Full::new(Bytes::from(form)))?).await?;
    let answer: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    if !status.is_success() {
        let why = answer["error_description"].as_str().or(answer["error"].as_str()).unwrap_or("no reason given");
        return Ok(failed(format!("{} refused the sign-in: {why}", provider.label)));
    }
    match answer["id_token"].as_str() {
        Some(token) => Ok(Ok(token.to_owned())),
        None => Ok(failed(format!("{} gave no ID token (is `openid` in the scopes?)", provider.label))),
    }
}

/// Checks an ID token (OIDC Core §3.1.3.7): the claims, if it's valid.
async fn verify(provider: &Provider, found: &Discovery, token: &str, nonce: &str) -> anyhow::Result<Result<serde_json::Map<String, Value>, Failed>> {
    let parts: Vec<&str> = token.split('.').collect();
    let [head, body, sig] = parts[..] else { return Ok(failed("the ID token isn't a JWT")) };
    let decode = |part: &str| URL_SAFE_NO_PAD.decode(part.trim_end_matches('='));
    let (Ok(head_bytes), Ok(body_bytes), Ok(sig)) = (decode(head), decode(body), decode(sig)) else {
        return Ok(failed("the ID token isn't a JWT"));
    };
    let Ok(header) = serde_json::from_slice::<Value>(&head_bytes) else { return Ok(failed("the ID token's header isn't JSON")) };
    let Ok(Value::Object(claims)) = serde_json::from_slice::<Value>(&body_bytes) else {
        return Ok(failed("the ID token's claims aren't JSON"));
    };
    let alg = header["alg"].as_str().unwrap_or("");
    let kid = header["kid"].as_str();
    let signed = format!("{head}.{body}");
    let mut verified = false;
    for fresh in [false, true] {
        let keys = keys(&found.jwks_uri, fresh).await?;
        let candidates = keys.iter().filter(|k| kid.is_none_or(|kid| k["kid"].as_str() == Some(kid)));
        if candidates.clone().any(|key| check_signature(alg, key, signed.as_bytes(), &sig)) {
            verified = true;
            break;
        }
        // A key it signs with that Cairn hasn't fetched yet, if any.
        if kid.is_none() || keys.iter().any(|k| k["kid"].as_str() == kid) {
            break;
        }
    }
    if !verified {
        return Ok(failed(format!("the ID token's signature ({alg}) isn't by {}'s keys", provider.label)));
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let number = |key: &str| claims.get(key).and_then(Value::as_u64);
    if claims.get("iss").and_then(Value::as_str).map(|i| i.trim_end_matches('/')) != Some(found.issuer.trim_end_matches('/')) {
        return Ok(failed("the ID token is another issuer's"));
    }
    let audiences: Vec<&str> = match claims.get("aud") {
        Some(Value::String(one)) => vec![one],
        Some(Value::Array(many)) => many.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    if !audiences.contains(&provider.client_id.as_str()) {
        return Ok(failed("the ID token is for another client"));
    }
    if audiences.len() > 1 && claims.get("azp").and_then(Value::as_str) != Some(provider.client_id.as_str()) {
        return Ok(failed("the ID token was issued to another party"));
    }
    if number("exp").is_none_or(|exp| exp + LEEWAY < now) {
        return Ok(failed("the ID token has expired"));
    }
    if number("nbf").is_some_and(|nbf| nbf > now + LEEWAY) || number("iat").is_some_and(|iat| iat > now + LEEWAY) {
        return Ok(failed("the ID token isn't valid yet (is a clock off?)"));
    }
    if claims.get("nonce").and_then(Value::as_str) != Some(nonce) {
        return Ok(failed("the ID token is for another sign-in"));
    }
    Ok(Ok(claims))
}

/// Whether `sig` is `key`'s (a JWK) signature of `message`, by `alg`.
fn check_signature(alg: &str, key: &Value, message: &[u8], sig: &[u8]) -> bool {
    let field = |name: &str| key[name].as_str().and_then(|v| URL_SAFE_NO_PAD.decode(v.trim_end_matches('=')).ok());
    if key["alg"].as_str().is_some_and(|a| a != alg) || key["use"].as_str().is_some_and(|u| u != "sig") {
        return false;
    }
    let rsa = |params: &'static signature::RsaParameters| match (field("n"), field("e")) {
        (Some(n), Some(e)) if key["kty"] == "RSA" => {
            signature::RsaPublicKeyComponents { n: &n, e: &e }.verify(params, message, sig).is_ok()
        }
        _ => false,
    };
    let ec = |crv: &str, alg: &'static signature::EcdsaVerificationAlgorithm| match (field("x"), field("y")) {
        (Some(x), Some(y)) if key["kty"] == "EC" && key["crv"] == crv => {
            let point = [&[4u8][..], &x, &y].concat();
            signature::UnparsedPublicKey::new(alg, point).verify(message, sig).is_ok()
        }
        _ => false,
    };
    match alg {
        "RS256" => rsa(&signature::RSA_PKCS1_2048_8192_SHA256),
        "RS384" => rsa(&signature::RSA_PKCS1_2048_8192_SHA384),
        "RS512" => rsa(&signature::RSA_PKCS1_2048_8192_SHA512),
        "PS256" => rsa(&signature::RSA_PSS_2048_8192_SHA256),
        "PS384" => rsa(&signature::RSA_PSS_2048_8192_SHA384),
        "PS512" => rsa(&signature::RSA_PSS_2048_8192_SHA512),
        "ES256" => ec("P-256", &signature::ECDSA_P256_SHA256_FIXED),
        "ES384" => ec("P-384", &signature::ECDSA_P384_SHA384_FIXED),
        "EdDSA" => match field("x") {
            Some(x) if key["kty"] == "OKP" && key["crv"] == "Ed25519" => {
                signature::UnparsedPublicKey::new(&signature::ED25519, x).verify(message, sig).is_ok()
            }
            _ => false,
        },
        // `none`, HMAC (a shared secret Cairn has no business checking), and
        // anything else.
        _ => false,
    }
}

// ─── Identities at providers ─────────────────────────────────────────────────

/// The login an identity at a provider signs in, if it's linked to one; its
/// use is noted.
pub async fn login_of(client: &Object, provider: &str, subject: &str, email: Option<&str>) -> anyhow::Result<Option<Uuid>> {
    let row = client
        .query_opt_cached(
            "UPDATE login_oidc SET last_used_at = now(), email = coalesce($3, email)
             WHERE provider = $1 AND subject = $2 RETURNING login_id",
            &[&provider, &subject, &email],
        )
        .await?;
    Ok(row.map(|r| r.get(0)))
}

/// Links an identity at a provider to `login` (T35).
pub async fn link(client: &Object, login: Uuid, provider: &str, subject: &str, email: Option<&str>) -> anyhow::Result<()> {
    let status = client
        .query_one_cached("SELECT pg_temp.cairn_link_oidc($1, $2, $3, $4)", &[&login, &provider, &subject, &email])
        .await?;
    match status.get::<_, &str>(0) {
        "linked" => Ok(()),
        "no_such_login" => Err(Invalid("sign in again".into()).into()),
        "taken" => Err(Invalid("that identity signs in another login already".into()).into()),
        status => unreachable!("cairn_link_oidc: unknown status {status}"),
    }
}

/// A new login, named `name`, signing in with an identity at a provider, for
/// enrollment link `enrollment` (its hash) (T36): its ID, and the identity's
/// account.
pub async fn new_login(
    client: &Object,
    name: &str,
    enrollment: &[u8],
    provider: &str,
    subject: &str,
    email: Option<&str>,
) -> anyhow::Result<(Uuid, String)> {
    let login = Uuid::new_v4();
    let row = client
        .query_one_cached(
            "SELECT * FROM pg_temp.cairn_new_oidc_login($1, $2, $3, $4, $5, $6)",
            &[&login, &name, &enrollment, &provider, &subject, &email],
        )
        .await?;
    match row.get::<_, &str>(0) {
        "created" => Ok((login, row.get(1))),
        "no_enrollment" => Err(Invalid("this enrollment link has been used, or has expired".into()).into()),
        "taken" => Err(Invalid(
            "that identity signs in a login already: sign in with it, then open the link again".into(),
        )
        .into()),
        "account_taken" => unreachable!("a new login has no identities"),
        status => unreachable!("cairn_new_oidc_login: unknown status {status}"),
    }
}

/// Unlinks a login's identity at `provider` (T37).
pub async fn unlink(client: &Object, login: Uuid, provider: &str) -> anyhow::Result<()> {
    let status = client.query_one_cached("SELECT pg_temp.cairn_unlink_oidc($1, $2)", &[&login, &provider]).await?;
    match status.get::<_, &str>(0) {
        "unlinked" => Ok(()),
        "none" => Err(Invalid("that provider isn't linked".into()).into()),
        "last" => Err(Invalid("it's your last way to sign in: add a passkey or another provider first".into()).into()),
        status => unreachable!("cairn_unlink_oidc: unknown status {status}"),
    }
}

/// A login's identities at providers: (provider, its label, e-mail).
pub async fn linked(client: &Object, login: Uuid) -> anyhow::Result<Vec<(String, String, Option<String>)>> {
    let rows = client
        .query_cached(
            "SELECT o.provider, p.label, o.email FROM login_oidc o JOIN oidc_providers p ON p.name = o.provider
             WHERE o.login_id = $1 ORDER BY o.provider",
            &[&login],
        )
        .await?;
    Ok(rows.iter().map(|r| (r.get(0), r.get(1), r.get(2))).collect())
}

/// Sets provider `provider`, after checking it can be used (its discovery
/// document and keys).
pub async fn set_provider(client: &Object, provider: &Provider) -> anyhow::Result<()> {
    let valid_name = (1..=32).contains(&provider.name.len())
        && provider.name.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && provider.name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !valid_name {
        return Err(Invalid("a provider's name is 1 to 32 lowercase letters, digits and hyphens".into()).into());
    }
    if provider.label.trim().is_empty() || provider.client_id.is_empty() {
        return Err(Invalid("a provider needs a label and a client ID".into()).into());
    }
    if !provider.scopes.split_whitespace().any(|s| s == "openid") {
        return Err(Invalid("the scopes must include openid".into()).into());
    }
    check_provider(provider)
        .await
        .map_err(|e| Invalid(format!("{} can't be used: {e:#}", provider.issuer)))?;
    client
        .execute_cached(
            "INSERT INTO oidc_providers (name, label, issuer, client_id, client_secret, scopes)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (name) DO UPDATE SET label = $2, issuer = $3, client_id = $4, client_secret = $5, scopes = $6",
            &[
                &provider.name,
                &provider.label.trim(),
                &provider.issuer.trim_end_matches('/'),
                &provider.client_id,
                &provider.client_secret,
                &provider.scopes,
            ],
        )
        .await?;
    oidc().discovery.lock().unwrap().remove(provider.issuer.trim_end_matches('/'));
    Ok(())
}

/// Removes provider `name`, and every login's identity at it.
pub async fn remove_provider(client: &Object, name: &str) -> anyhow::Result<()> {
    let removed = client.execute_cached("DELETE FROM oidc_providers WHERE name = $1", &[&name]).await?;
    if removed == 0 {
        return Err(Invalid(format!("no provider named {name:?}")).into());
    }
    Ok(())
}

/// Removes sign-ins that took too long.
pub async fn reap(client: &Object) -> anyhow::Result<u64> {
    Ok(client.execute_cached("DELETE FROM oidc_flows WHERE expires_at <= now()", &[]).await?)
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(clap::Args, Debug, serde::Serialize, serde::Deserialize)]
pub struct OidcArgs {
    #[command(flatten)]
    #[serde(skip)]
    pub remote: crate::admin::Remote,
    #[command(subcommand)]
    command: OidcCommand,
}

#[derive(clap::Subcommand, Debug, serde::Serialize, serde::Deserialize)]
enum OidcCommand {
    /// List the providers people may sign in to the console at.
    List,
    /// Add or change a provider, after checking its discovery document.
    /// Register `<console URL>/api/oidc/callback` as its redirect URI.
    Set {
        /// Its name: lowercase letters, digits and hyphens.
        name: String,
        /// The issuer URL (its discovery document is under it).
        #[arg(long)]
        issuer: String,
        #[arg(long)]
        client_id: String,
        /// The client's secret (none: a public client); also from
        /// `CAIRN_OIDC_CLIENT_SECRET`.
        #[arg(long, env = "CAIRN_OIDC_CLIENT_SECRET", hide_env_values = true)]
        client_secret: Option<String>,
        /// What the sign-in button says; the name if not given.
        #[arg(long)]
        label: Option<String>,
        #[arg(long, default_value = "openid email profile")]
        scopes: String,
    },
    /// Remove a provider: the identities at it no longer sign anyone in.
    Remove { name: String },
}

/// `cairn oidc …`, on a node (see `admin`).
pub async fn run(app: &std::sync::Arc<crate::App>, args: OidcArgs, out: &mut crate::admin::Output) -> anyhow::Result<()> {
    use crate::admin::outln;
    let client = app.pool.get().await?;
    match args.command {
        OidcCommand::List => {
            for p in providers(&client).await? {
                let kind = if p.client_secret.is_some() { "confidential" } else { "public" };
                outln!(out, "{} ({})\n  issuer {}\n  client {} ({kind}), scopes {}", p.name, p.label, p.issuer, p.client_id, p.scopes);
            }
        }
        OidcCommand::Set { name, issuer, client_id, client_secret, label, scopes } => {
            let label = label.unwrap_or_else(|| name.clone());
            let provider = Provider { name, label, issuer, client_id, client_secret, scopes };
            set_provider(&client, &provider).await?;
        }
        OidcCommand::Remove { name } => remove_provider(&client, &name).await?,
    }
    Ok(())
}

/// A provider for tests: discovery, keys, and a token endpoint that redeems
/// the codes a test issues (checking PKCE and the client's secret), with ID
/// tokens signed by an ES256 key.
#[cfg(test)]
pub mod mock {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use axum::{Json, Router, extract::State, http::HeaderMap, routing::{get, post}};
    use base64::{Engine, engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}};
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
    use serde_json::{Value, json};

    /// What a code redeems to: the claims, and the PKCE challenge it must
    /// come with.
    pub struct Grant {
        pub subject: String,
        pub email: String,
        pub nonce: String,
        pub challenge: String,
    }

    pub struct Mock {
        pub issuer: String,
        key: EcdsaKeyPair,
        grants: Mutex<HashMap<String, Grant>>,
        /// Tamper with what's issued: another audience, or nonce.
        pub audience: Mutex<String>,
    }

    pub const CLIENT_ID: &str = "cairn-console";
    pub const CLIENT_SECRET: &str = "s3cret";

    impl Mock {
        /// Starts one on a loopback port.
        pub async fn start() -> Arc<Mock> {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let issuer = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
            let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
            let mock = Arc::new(Mock {
                issuer,
                key,
                grants: Mutex::default(),
                audience: Mutex::new(CLIENT_ID.to_owned()),
            });
            let app = Router::new()
                .route("/.well-known/openid-configuration", get(discovery))
                .route("/jwks", get(jwks))
                .route("/token", post(token))
                .with_state(mock.clone());
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            mock
        }

        /// A code for the sign-in that `authorize_url` (Cairn's redirect to
        /// the provider) starts, as `subject`.
        pub fn code_for(&self, authorize_url: &str, subject: &str, email: &str) -> (String, String) {
            let query = authorize_url.split_once('?').unwrap().1;
            let param = |name: &str| {
                query.split('&').find_map(|p| p.strip_prefix(&format!("{name}="))).unwrap().to_owned()
            };
            assert_eq!(param("code_challenge_method"), "S256");
            assert_eq!(param("client_id"), CLIENT_ID);
            let code = format!("code-{}", uuid::Uuid::new_v4());
            let grant = Grant {
                subject: subject.to_owned(),
                email: email.to_owned(),
                nonce: param("nonce"),
                challenge: param("code_challenge"),
            };
            self.grants.lock().unwrap().insert(code.clone(), grant);
            (param("state"), code)
        }
    }

    async fn discovery(State(mock): State<Arc<Mock>>) -> Json<Value> {
        let i = &mock.issuer;
        Json(json!({
            "issuer": i,
            "authorization_endpoint": format!("{i}/authorize"),
            "token_endpoint": format!("{i}/token"),
            "jwks_uri": format!("{i}/jwks"),
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        }))
    }

    async fn jwks(State(mock): State<Arc<Mock>>) -> Json<Value> {
        let point = mock.key.public_key().as_ref();
        Json(json!({ "keys": [{
            "kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
            "x": URL_SAFE_NO_PAD.encode(&point[1..33]), "y": URL_SAFE_NO_PAD.encode(&point[33..]),
        }]}))
    }

    async fn token(State(mock): State<Arc<Mock>>, headers: HeaderMap, body: String) -> (axum::http::StatusCode, Json<Value>) {
        let bad = |why: &str| (axum::http::StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_grant", "error_description": why })));
        let basic = format!("Basic {}", STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}")));
        if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(basic.as_str()) {
            return bad("the client didn't authenticate");
        }
        let form: HashMap<String, String> = body
            .split('&')
            .filter_map(|p| p.split_once('='))
            .map(|(k, v)| (k.to_owned(), percent_encoding::percent_decode_str(v).decode_utf8_lossy().into_owned()))
            .collect();
        let Some(grant) = mock.grants.lock().unwrap().remove(&form["code"]) else { return bad("unknown code") };
        let challenge = URL_SAFE_NO_PAD.encode(ring::digest::digest(&ring::digest::SHA256, form["code_verifier"].as_bytes()));
        if challenge != grant.challenge {
            return bad("PKCE failed");
        }
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let header = URL_SAFE_NO_PAD.encode(json!({ "alg": "ES256", "kid": "k1", "typ": "JWT" }).to_string());
        let claims = URL_SAFE_NO_PAD.encode(
            json!({
                "iss": mock.issuer, "sub": grant.subject, "aud": *mock.audience.lock().unwrap(),
                "exp": now + 300, "iat": now, "nonce": grant.nonce,
                "email": grant.email, "email_verified": true, "name": "Test Person",
            })
            .to_string(),
        );
        let signed = format!("{header}.{claims}");
        let sig = mock.key.sign(&SystemRandom::new(), signed.as_bytes()).unwrap();
        let id_token = format!("{signed}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()));
        (axum::http::StatusCode::OK, Json(json!({ "access_token": "at", "token_type": "Bearer", "id_token": id_token })))
    }
}
