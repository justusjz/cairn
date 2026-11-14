//! OpenID Connect, as the console's sign-ins (`console::oidc`) and STS's web
//! identities (`iam_oidc`, AssumeRoleWithWebIdentity) both use it: an
//! issuer's discovery document (`/.well-known/openid-configuration`, the
//! issuer's own) and keys (its JWKS), cached, and ID tokens (JWTs) checked
//! against them: their signature (RS256-512, PS256-512, ES256, ES384,
//! EdDSA; never `none` or HMAC), issuer, audience, times, and (if asked)
//! nonce and authorized party. See `plans/roles.md`, step 5.
//!
//! How an issuer may be reached is the caller's (`Reach`): the console's
//! providers are set by operators, and reached as they say (HTTP on
//! loopback, for trying it); IAM's are any user's with
//! `iam:CreateOpenIDConnectProvider`, so they're reached over HTTPS, at
//! public addresses only (unless the operator lets them reach private ones:
//! `settings::OIDC_PRIVATE_ISSUERS`), so that no one makes Cairn fetch from
//! its own network. Their thumbprints (SHA-1s of certificates) let an issuer
//! whose certificate isn't of a public CA be trusted: a certificate it
//! presents with one of them is the anchor its chain is verified to.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::Context;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, body::Bytes, header};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{Client, connect::{HttpConnector, dns::Name}};
use hyper_util::rt::TokioExecutor;
use ring::{digest, signature};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use serde::Deserialize;
use serde_json::Value;

/// How long a discovery document and keys are kept.
const CACHE_TTL: Duration = Duration::from_secs(3600);
/// How long an issuer may take to answer.
const TIMEOUT: Duration = Duration::from_secs(10);
/// How far tokens' times may be off.
pub const LEEWAY: u64 = 60;
/// The most an issuer's answer may hold.
const MAX_ANSWER: usize = 1 << 20;

/// How an issuer may be reached.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Reach {
    /// Only at public addresses (see `is_public`), over HTTPS. Else any,
    /// and HTTP on loopback too.
    pub public_only: bool,
    /// SHA-1s of certificates to trust as anchors, if the public roots
    /// don't verify the issuer's.
    pub thumbprints: Vec<[u8; 20]>,
}

impl Reach {
    /// The console's providers': as operators set them.
    pub fn operators() -> Reach {
        Reach::default()
    }
}

/// What an issuer's discovery document says, of what Cairn uses.
#[derive(Clone, Debug, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    pub jwks_uri: String,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
}

type Https = Client<HttpsConnector<HttpConnector<Resolver>>, Full<Bytes>>;

/// The HTTP clients (one per `Reach`), and what's cached of issuers, by
/// their `Reach` too (what one way of reaching found isn't another's).
#[derive(Default)]
struct Oidc {
    clients: Mutex<HashMap<Reach, Https>>,
    discovery: Mutex<HashMap<(Reach, String), (Instant, Discovery)>>,
    keys: Mutex<HashMap<(Reach, String), (Instant, Vec<Value>)>>,
}

fn oidc() -> &'static Oidc {
    static OIDC: OnceLock<Oidc> = OnceLock::new();
    OIDC.get_or_init(Oidc::default)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The public roots (webpki-roots).
fn public_roots() -> Arc<RootCertStore> {
    static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    ROOTS
        .get_or_init(|| Arc::new(RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())))
        .clone()
}

/// The client to reach issuers as `reach` says.
fn client(reach: &Reach) -> anyhow::Result<Https> {
    if let Some(client) = oidc().clients.lock().unwrap().get(reach) {
        return Ok(client.clone());
    }
    let verifier = Arc::new(Pinned::new(&reach.thumbprints)?);
    let tls = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("ring has TLS 1.2 and 1.3")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let mut http = HttpConnector::new_with_resolver(Resolver { public_only: reach.public_only });
    http.enforce_http(false);
    let builder = hyper_rustls::HttpsConnectorBuilder::new().with_tls_config(tls);
    let connector = if reach.public_only { builder.https_only() } else { builder.https_or_http() }.enable_http1().wrap_connector(http);
    let client = Client::builder(TokioExecutor::new()).build(connector);
    oidc().clients.lock().unwrap().insert(reach.clone(), client.clone());
    Ok(client)
}

// ─── Where issuers may be ────────────────────────────────────────────────────

/// Whether `ip` is a public address: not loopback, private, link-local
/// (cloud metadata services are), shared (CGNAT), unique local,
/// multicast, unspecified, reserved or for documentation; an IPv4 address
/// mapped (or translated) into IPv6 is its IPv4 address.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
                || a == 0
                || (a == 100 && (64..128).contains(&b)) // shared (RFC 6598)
                || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
                || (a == 198 && (18..20).contains(&b)) // benchmarking
                || a >= 240) // reserved
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let s = v6.segments();
            // NAT64 (64:ff9b::/96) carries an IPv4 address.
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                let [a, b] = s[6].to_be_bytes();
                let [c, d] = s[7].to_be_bytes();
                return is_public(IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d)));
            }
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local
                || (s[0] & 0xffc0) == 0xfe80 // link-local
                || (s[0] & 0xffc0) == 0xfec0 // site-local (deprecated)
                || (s[0] == 0x2001 && s[1] == 0xdb8) // documentation
                || s[..6] == [0, 0, 0, 0, 0, 0]) // IPv4-compatible
        }
    }
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Why a URL can't be an issuer's (or its endpoints').
#[derive(Debug)]
pub struct BadUrl(pub String);

impl std::fmt::Display for BadUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BadUrl {}

/// Whether `url` may be fetched as `reach` says: HTTPS (or, unless only
/// public addresses may be, HTTP on loopback), and, if only public
/// addresses may be, not an IP address that isn't one. (A name is checked
/// as it's resolved: `Resolver`.)
pub fn check_url(url: &str, reach: &Reach) -> Result<(), BadUrl> {
    let uri: hyper::Uri = url.parse().map_err(|_| BadUrl(format!("{url:?} isn't a URL")))?;
    let host = uri.host().unwrap_or("");
    if host.is_empty() {
        return Err(BadUrl(format!("{url:?} has no host")));
    }
    match uri.scheme_str() {
        Some("https") => {}
        Some("http") if !reach.public_only && is_loopback_host(host) => {}
        _ => return Err(BadUrl(format!("{url:?} isn't an HTTPS URL"))),
    }
    if reach.public_only
        && let Ok(ip) = host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>()
        && !is_public(ip)
    {
        return Err(BadUrl(format!("{url:?} isn't at a public address")));
    }
    Ok(())
}

/// Resolves names, as `getaddrinfo` does; if only public addresses may be
/// reached, only to those (and to none if the name has none).
#[derive(Clone, Copy)]
pub struct Resolver {
    public_only: bool,
}

type Resolving = std::pin::Pin<Box<dyn Future<Output = std::io::Result<std::vec::IntoIter<SocketAddr>>> + Send>>;

impl tower::Service<Name> for Resolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = std::io::Error;
    type Future = Resolving;

    fn poll_ready(&mut self, _: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let public_only = self.public_only;
        Box::pin(async move {
            let found: Vec<SocketAddr> = tokio::net::lookup_host((name.as_str(), 0)).await?.collect();
            let kept: Vec<SocketAddr> = found.iter().copied().filter(|a| !public_only || is_public(a.ip())).collect();
            if kept.is_empty() && !found.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("{} isn't at a public address", name.as_str()),
                ));
            }
            Ok(kept.into_iter())
        })
    }
}

// ─── Certificates ────────────────────────────────────────────────────────────

/// Verifies servers' certificates by the public roots, or, failing that, by
/// a certificate the server presents whose SHA-1 is pinned, as an anchor.
#[derive(Debug)]
struct Pinned {
    public: Arc<WebPkiServerVerifier>,
    thumbprints: Vec<[u8; 20]>,
}

impl Pinned {
    fn new(thumbprints: &[[u8; 20]]) -> anyhow::Result<Pinned> {
        let public = WebPkiServerVerifier::builder_with_provider(public_roots(), provider()).build()?;
        Ok(Pinned { public, thumbprints: thumbprints.to_vec() })
    }
}

/// A certificate's SHA-1, as IAM's thumbprints are.
pub fn thumbprint(cert: &[u8]) -> [u8; 20] {
    let sha1 = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, cert);
    sha1.as_ref().try_into().expect("SHA-1 is 20 bytes")
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let by_public = self.public.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now);
        if by_public.is_ok() || self.thumbprints.is_empty() {
            return by_public;
        }
        for cert in std::iter::once(end_entity).chain(intermediates) {
            if !self.thumbprints.contains(&thumbprint(cert)) {
                continue;
            }
            let mut roots = RootCertStore::empty();
            if roots.add(cert.clone().into_owned()).is_err() {
                continue;
            }
            let Ok(pinned) = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider()).build() else { continue };
            if let Ok(verified) = pinned.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now) {
                return Ok(verified);
            }
        }
        by_public
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.public.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.public.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.public.supported_verify_schemes()
    }
}

// ─── Fetching ────────────────────────────────────────────────────────────────

/// Sends `request` (to a URL `check_url` took), as `reach` says: the status
/// and body, within `TIMEOUT` and `MAX_ANSWER`.
pub async fn exchange(request: Request<Full<Bytes>>, reach: &Reach) -> anyhow::Result<(hyper::StatusCode, Bytes)> {
    check_url(&request.uri().to_string(), reach)?;
    let client = client(reach)?;
    let call = async {
        let response = client.request(request).await.context("the issuer couldn't be reached")?;
        let status = response.status();
        let body = http_body_util::Limited::new(response.into_body(), MAX_ANSWER)
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("the issuer's answer broke off, or is too large: {e}"))?
            .to_bytes();
        anyhow::Ok((status, body))
    };
    tokio::time::timeout(TIMEOUT, call).await.context("the issuer didn't answer in time")?
}

/// GETs `url`, as JSON. (Never says what came back, but whether it's JSON:
/// a URL any IAM user chose mustn't read out what it reaches.)
async fn get_json<T: serde::de::DeserializeOwned>(url: &str, reach: &Reach) -> anyhow::Result<T> {
    let request = Request::builder().method(Method::GET).uri(url).header(header::ACCEPT, "application/json").body(Full::new(Bytes::new()))?;
    let (status, body) = exchange(request, reach).await?;
    anyhow::ensure!(status.is_success(), "{url} answered {status}");
    serde_json::from_slice(&body).map_err(|_| anyhow::anyhow!("{url} didn't answer JSON as expected"))
}

/// `issuer`'s discovery document (cached): the issuer's own (OIDC
/// Discovery §4.3), its endpoints URLs `reach` may fetch.
pub async fn discovery(issuer: &str, reach: &Reach) -> anyhow::Result<Discovery> {
    let issuer = issuer.trim_end_matches('/');
    let key = (reach.clone(), issuer.to_owned());
    if let Some((at, found)) = oidc().discovery.lock().unwrap().get(&key)
        && at.elapsed() < CACHE_TTL
    {
        return Ok(found.clone());
    }
    check_url(issuer, reach)?;
    let found: Discovery = get_json(&format!("{issuer}/.well-known/openid-configuration"), reach).await?;
    anyhow::ensure!(
        found.issuer.trim_end_matches('/') == issuer,
        "the discovery document is of issuer {:?}, not {issuer:?}",
        found.issuer
    );
    for url in [found.authorization_endpoint.as_ref(), found.token_endpoint.as_ref(), Some(&found.jwks_uri)].into_iter().flatten() {
        check_url(url, reach)?;
    }
    oidc().discovery.lock().unwrap().insert(key, (Instant::now(), found.clone()));
    Ok(found)
}

/// Forgets what's cached of `issuer`.
pub fn forget(issuer: &str) {
    let issuer = issuer.trim_end_matches('/');
    oidc().discovery.lock().unwrap().retain(|(_, i), _| i != issuer);
}

/// The issuer's keys (JWKs) at `uri`, cached; `fresh`: fetched again, if
/// they're older than a minute (a key it signs with now that Cairn hasn't
/// seen).
pub async fn keys(uri: &str, reach: &Reach, fresh: bool) -> anyhow::Result<Vec<Value>> {
    let key = (reach.clone(), uri.to_owned());
    if let Some((at, keys)) = oidc().keys.lock().unwrap().get(&key)
        && at.elapsed() < CACHE_TTL
        && !(fresh && at.elapsed() > Duration::from_secs(60))
    {
        return Ok(keys.clone());
    }
    #[derive(Deserialize)]
    struct Jwks {
        keys: Vec<Value>,
    }
    let found: Jwks = get_json(uri, reach).await?;
    oidc().keys.lock().unwrap().insert(key, (Instant::now(), found.keys.clone()));
    Ok(found.keys)
}

/// Checks that `issuer` can be used: its discovery document, and keys.
pub async fn check_issuer(issuer: &str, reach: &Reach) -> anyhow::Result<()> {
    let found = discovery(issuer, reach).await?;
    keys(&found.jwks_uri, reach, false).await?;
    Ok(())
}

// ─── Tokens ──────────────────────────────────────────────────────────────────

/// Why a token isn't taken.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rejected {
    /// Not a JWT, or its parts aren't JSON (what's wrong).
    Malformed(&'static str),
    /// Not signed by the issuer's keys (the algorithm it says).
    Signature(String),
    /// Another issuer's.
    Issuer,
    /// For another audience.
    Audience,
    /// Issued to another party (`azp`).
    Party,
    /// Expired at `exp` (Unix seconds), `now` being now.
    Expired { exp: u64, now: u64 },
    /// Not valid yet (`nbf` or `iat` ahead of now).
    NotYet,
    /// Of another sign-in (its `nonce`).
    Nonce,
}

pub type Claims = serde_json::Map<String, Value>;

/// A JWT, parsed (not yet checked).
pub struct Jwt {
    header: Value,
    pub claims: Claims,
    signed: String,
    sig: Vec<u8>,
}

impl Jwt {
    pub fn parse(token: &str) -> Result<Jwt, Rejected> {
        let parts: Vec<&str> = token.split('.').collect();
        let [head, body, sig] = parts[..] else { return Err(Rejected::Malformed("isn't a JWT")) };
        let decode = |part: &str| URL_SAFE_NO_PAD.decode(part.trim_end_matches('='));
        let (Ok(head_bytes), Ok(body_bytes), Ok(sig)) = (decode(head), decode(body), decode(sig)) else {
            return Err(Rejected::Malformed("isn't a JWT"));
        };
        let Ok(header @ Value::Object(_)) = serde_json::from_slice::<Value>(&head_bytes) else {
            return Err(Rejected::Malformed("has a header that isn't JSON"));
        };
        let Ok(Value::Object(claims)) = serde_json::from_slice::<Value>(&body_bytes) else {
            return Err(Rejected::Malformed("has claims that aren't JSON"));
        };
        Ok(Jwt { header, claims, signed: format!("{head}.{body}"), sig })
    }

    /// Claim `key`, if it's a string.
    pub fn text(&self, key: &str) -> Option<&str> {
        self.claims.get(key).and_then(Value::as_str)
    }

    /// Its audiences (`aud`, one or a list).
    pub fn audiences(&self) -> Vec<&str> {
        match self.claims.get("aud") {
            Some(Value::String(one)) => vec![one],
            Some(Value::Array(many)) => many.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        }
    }
}

/// What a token must be.
pub struct Expect<'a> {
    /// Its issuer's discovery document.
    pub found: &'a Discovery,
    /// One of its audiences must be one of these.
    pub audiences: &'a [String],
    /// Its `nonce`, if it must have one.
    pub nonce: Option<&'a str>,
    /// Whether, with more than one audience, its `azp` must be the one
    /// matched (OIDC Core §3.1.3.7, for a client checking its own tokens).
    pub party: bool,
}

/// Checks `token` (OIDC Core §3.1.3.7): the token, and its audience that
/// matched, if it's valid.
pub async fn verify(token: &str, reach: &Reach, expect: &Expect<'_>) -> anyhow::Result<Result<(Jwt, String), Rejected>> {
    let jwt = match Jwt::parse(token) {
        Ok(jwt) => jwt,
        Err(e) => return Ok(Err(e)),
    };
    let alg = jwt.header["alg"].as_str().unwrap_or("").to_owned();
    let kid = jwt.header["kid"].as_str();
    let mut verified = false;
    for fresh in [false, true] {
        let keys = keys(&expect.found.jwks_uri, reach, fresh).await?;
        let candidates = keys.iter().filter(|k| kid.is_none_or(|kid| k["kid"].as_str() == Some(kid)));
        if candidates.clone().any(|key| check_signature(&alg, key, jwt.signed.as_bytes(), &jwt.sig)) {
            verified = true;
            break;
        }
        // A key it signs with that Cairn hasn't fetched yet, if any.
        if kid.is_none() || keys.iter().any(|k| k["kid"].as_str() == kid) {
            break;
        }
    }
    if !verified {
        return Ok(Err(Rejected::Signature(alg)));
    }
    Ok(check_claims(jwt, expect, now()))
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Checks a signed token's claims, at `now`.
fn check_claims(jwt: Jwt, expect: &Expect<'_>, now: u64) -> Result<(Jwt, String), Rejected> {
    let number = |key: &str| jwt.claims.get(key).and_then(Value::as_u64);
    if jwt.text("iss").map(|i| i.trim_end_matches('/')) != Some(expect.found.issuer.trim_end_matches('/')) {
        return Err(Rejected::Issuer);
    }
    let audiences = jwt.audiences();
    let Some(audience) = audiences.iter().find(|a| expect.audiences.iter().any(|e| e == *a)).map(|a| a.to_string()) else {
        return Err(Rejected::Audience);
    };
    if expect.party && audiences.len() > 1 && jwt.text("azp") != Some(audience.as_str()) {
        return Err(Rejected::Party);
    }
    match number("exp") {
        Some(exp) if exp + LEEWAY >= now => {}
        exp => return Err(Rejected::Expired { exp: exp.unwrap_or(0), now }),
    }
    if number("nbf").is_some_and(|nbf| nbf > now + LEEWAY) || number("iat").is_some_and(|iat| iat > now + LEEWAY) {
        return Err(Rejected::NotYet);
    }
    if let Some(nonce) = expect.nonce
        && jwt.text("nonce") != Some(nonce)
    {
        return Err(Rejected::Nonce);
    }
    Ok((jwt, audience))
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
        /// Its port (on 127.0.0.1).
        pub port: u16,
        key: EcdsaKeyPair,
        grants: Mutex<HashMap<String, Grant>>,
        /// Tamper with what's issued: another audience, or nonce.
        pub audience: Mutex<String>,
    }

    pub const CLIENT_ID: &str = "cairn-console";

    /// The test CA's certificate's SHA-1 (as IAM's thumbprints are), and
    /// the CA and the HTTPS mock's certificate (for 127.0.0.1 and
    /// localhost, until 2126) and key: made for these tests only, never
    /// trusted anywhere else.
    pub const CA_THUMBPRINT: &str = "77C128BC67BB94E88F412696D0485F64A6F39912";
    const CA_DER: &str = "MIIBdTCCARygAwIBAgIUMjmcmmgCvnzZuGYrvJxt9qPY+1YwCgYIKoZIzj0EAwIwGDEWMBQGA1UEAwwNQ2Fpcm4gdGVzdCBDQTAgFw0yNjExMTQxNjE2NDRaGA8yMTI2MTAyMTE2MTY0NFowGDEWMBQGA1UEAwwNQ2Fpcm4gdGVzdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPdzEX8tBz/5daj8RWz/6bb15PbjT561fcI8aHN35ra4uDDCoWfGN6UAuhpwf89PtTkrMkzoLiblVRuOiTXU/96jQjBAMB0GA1UdDgQWBBTDnom1RYIt8ZBSG3JxWA3EyCK4UTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAgNHADBEAiBvW9cK6gfwQczlK3DMS+pcEAGdwYUDQ8EhqpompXDfIwIgch/OsRxeGH7yPxR5qiSVLy89/abQsTHrqRgPt76U/5g=";
    const LEAF_DER: &str = "MIIBgTCCASegAwIBAgIUIA2dOsk7wkqWGYujOE1aek3fTiQwCgYIKoZIzj0EAwIwGDEWMBQGA1UEAwwNQ2Fpcm4gdGVzdCBDQTAgFw0yNjExMTQxNjE2NDRaGA8yMTI2MTAyMTE2MTY0NFowFDESMBAGA1UEAwwJMTI3LjAuMC4xMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtb054aTXQq3qM6v81qEa0pIuJXr/DvqjnsQ+kplsedMqIEp71qz//JCUvClqHVHndLdjxOLSevfmO8S4DI0NK6NRME8wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwGgYDVR0RBBMwEYcEfwAAAYIJbG9jYWxob3N0MAoGCCqGSM49BAMCA0gAMEUCIDA5ytCl8VzQWad5MrnrThMq5wMgSQbN7QXFZaaJGSpgAiEAx5IDUcMOQF137zJEmjDOnZJxEKV1wKkQQJeiceztHUc=";
    const LEAF_KEY_DER: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcqg8ejQ8LBXlkMbr6jLncVpZoCoA1wxio2cpMddWPfShRANCAAS1vTnhpNdCreozq/zWoRrSki4lev8O+qOexD6SmWx50yogSnvWrP/8kJS8KWodUed0t2PE4tJ69+Y7xLgMjQ0r";

    /// The HTTPS mock's TLS: its certificate, then the CA's.
    fn tls() -> rustls::ServerConfig {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        let chain = vec![
            CertificateDer::from(STANDARD.decode(LEAF_DER).unwrap()),
            CertificateDer::from(STANDARD.decode(CA_DER).unwrap()),
        ];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(STANDARD.decode(LEAF_KEY_DER).unwrap()));
        rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap()
    }
    pub const CLIENT_SECRET: &str = "s3cret";

    impl Mock {
        /// Starts one on a loopback port, over HTTP.
        pub async fn start() -> Arc<Mock> {
            Mock::start_with(false).await
        }

        /// Starts one on a loopback port, over HTTPS, with a certificate
        /// of the test CA (`CA_THUMBPRINT`), which no public root trusts.
        pub async fn start_https() -> Arc<Mock> {
            Mock::start_with(true).await
        }

        async fn start_with(https: bool) -> Arc<Mock> {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let issuer = format!("{}://127.0.0.1:{port}", if https { "https" } else { "http" });
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
            let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
            let mock = Arc::new(Mock {
                issuer,
                port,
                key,
                grants: Mutex::default(),
                audience: Mutex::new(CLIENT_ID.to_owned()),
            });
            let app = Router::new()
                .route("/.well-known/openid-configuration", get(discovery))
                .route("/jwks", get(jwks))
                .route("/token", post(token))
                .with_state(mock.clone());
            if !https {
                tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
                return mock;
            }
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls()));
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else { continue };
                    let (acceptor, app) = (acceptor.clone(), app.clone());
                    tokio::spawn(async move {
                        let Ok(stream) = acceptor.accept(stream).await else { return };
                        let service = hyper_util::service::TowerToHyperService::new(app);
                        let io = hyper_util::rt::TokioIo::new(stream);
                        let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, service).await;
                    });
                }
            });
            mock
        }

        /// An ID token of its own, with `claims` (its issuer, unless they
        /// say another), signed by its key.
        pub fn id_token(&self, claims: Value) -> String {
            let mut claims = claims;
            if claims.get("iss").is_none() {
                claims["iss"] = Value::String(self.issuer.clone());
            }
            let header = URL_SAFE_NO_PAD.encode(json!({ "alg": "ES256", "kid": "k1", "typ": "JWT" }).to_string());
            let signed = format!("{header}.{}", URL_SAFE_NO_PAD.encode(claims.to_string()));
            let sig = self.key.sign(&SystemRandom::new(), signed.as_bytes()).unwrap();
            format!("{signed}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_addresses() {
        for private in [
            "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1",
            "255.255.255.255", "::1", "::", "fd00::1", "fe80::1", "::ffff:10.0.0.1", "::ffff:127.0.0.1", "64:ff9b::a00:1",
            "2001:db8::1", "::127.0.0.1",
        ] {
            assert!(!is_public(private.parse().unwrap()), "{private}");
        }
        for public in ["1.1.1.1", "140.82.112.3", "2606:4700::1111", "::ffff:1.1.1.1", "64:ff9b::101:101", "100.128.0.1"] {
            assert!(is_public(public.parse().unwrap()), "{public}");
        }
    }

    #[test]
    fn urls() {
        let public = Reach { public_only: true, thumbprints: Vec::new() };
        let operators = Reach::operators();
        assert!(check_url("https://example.com/x", &public).is_ok());
        assert!(check_url("http://example.com", &public).is_err());
        assert!(check_url("http://127.0.0.1:8080", &public).is_err());
        assert!(check_url("https://127.0.0.1:8080", &public).is_err());
        assert!(check_url("https://[::1]/", &public).is_err());
        assert!(check_url("https://169.254.169.254/latest", &public).is_err());
        assert!(check_url("http://127.0.0.1:8080", &operators).is_ok());
        assert!(check_url("http://localhost:8080", &operators).is_ok());
        assert!(check_url("http://example.com", &operators).is_err());
        assert!(check_url("https://10.0.0.1", &operators).is_ok());
    }

    #[tokio::test]
    async fn names_resolve_to_public_addresses_only() {
        let mut resolver = Resolver { public_only: true };
        let refused = tower::Service::call(&mut resolver, "localhost".parse().unwrap()).await;
        assert!(refused.is_err());
        let mut resolver = Resolver { public_only: false };
        let found = tower::Service::call(&mut resolver, "localhost".parse().unwrap()).await.unwrap();
        assert!(found.count() > 0);
    }

    fn discovery_of(issuer: &str) -> Discovery {
        Discovery {
            issuer: issuer.to_owned(),
            authorization_endpoint: None,
            token_endpoint: None,
            jwks_uri: format!("{issuer}/jwks"),
            token_endpoint_auth_methods_supported: Vec::new(),
        }
    }

    fn jwt(claims: Value) -> Jwt {
        let Value::Object(claims) = claims else { panic!() };
        Jwt { header: serde_json::json!({"alg": "ES256"}), claims, signed: String::new(), sig: Vec::new() }
    }

    #[test]
    fn claims() {
        let found = discovery_of("https://issuer.example");
        let audiences = vec!["a".to_owned(), "b".to_owned()];
        let expect = Expect { found: &found, audiences: &audiences, nonce: None, party: false };
        let now = 1_000_000;
        let ok = serde_json::json!({"iss": "https://issuer.example/", "aud": ["x", "b"], "exp": now + 10, "sub": "s"});
        let (_, audience) = check_claims(jwt(ok.clone()), &expect, now).unwrap();
        assert_eq!(audience, "b");
        let with = |key: &str, value: Value| {
            let mut claims = ok.clone();
            claims[key] = value;
            jwt(claims)
        };
        assert_eq!(check_claims(with("iss", "https://other".into()), &expect, now).err(), Some(Rejected::Issuer));
        assert_eq!(check_claims(with("aud", "c".into()), &expect, now).err(), Some(Rejected::Audience));
        assert_eq!(
            check_claims(with("exp", (now - LEEWAY - 1).into()), &expect, now).err(),
            Some(Rejected::Expired { exp: now - LEEWAY - 1, now })
        );
        assert!(check_claims(with("exp", (now - LEEWAY).into()), &expect, now).is_ok());
        assert_eq!(check_claims(with("nbf", (now + LEEWAY + 1).into()), &expect, now).err(), Some(Rejected::NotYet));
        let party = Expect { party: true, ..expect };
        assert_eq!(check_claims(jwt(ok.clone()), &party, now).err(), Some(Rejected::Party));
        assert!(check_claims(with("azp", "b".into()), &party, now).is_ok());
        let nonce = Expect { nonce: Some("n"), party: false, ..party };
        assert_eq!(check_claims(jwt(ok.clone()), &nonce, now).err(), Some(Rejected::Nonce));
        assert!(check_claims(with("nonce", "n".into()), &nonce, now).is_ok());
    }
}
