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

use anyhow::Context;
use base64::{Engine, engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}};
use deadpool_postgres::Object;
use http_body_util::Full;
use hyper::{Method, Request, body::Bytes, header};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use ring::digest;
use serde_json::Value;
use std::time::Duration;
use uuid::Uuid;

use super::store;
use crate::oidc::{Discovery, Expect, Reach, Rejected};
use crate::{db::Cached, users::Invalid};

/// How long a sign-in at a provider may take.
pub const FLOW_TTL: Duration = Duration::from_secs(10 * 60);

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

/// Whether `url` may be a provider's: HTTPS, or HTTP on loopback.
pub fn check_url(url: &str) -> Result<(), Invalid> {
    crate::oidc::check_url(url, &Reach::operators()).map_err(|e| Invalid(e.0))
}

/// The provider's discovery document (cached), with the endpoints the
/// console needs.
async fn discovery(provider: &Provider) -> anyhow::Result<Discovery> {
    let found = crate::oidc::discovery(&provider.issuer, &Reach::operators()).await?;
    anyhow::ensure!(
        found.authorization_endpoint.is_some() && found.token_endpoint.is_some(),
        "{} has no authorization or token endpoint",
        provider.issuer
    );
    Ok(found)
}

/// Checks that a provider can be used: its discovery document, and keys.
pub async fn check_provider(provider: &Provider) -> anyhow::Result<()> {
    check_url(&provider.issuer)?;
    let found = discovery(provider).await?;
    crate::oidc::keys(&found.jwks_uri, &Reach::operators(), false).await?;
    Ok(())
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
    let authorize = found.authorization_endpoint.as_deref().context("no authorization endpoint")?;
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
        authorize,
        if authorize.contains('?') { '&' } else { '?' },
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
    let token_endpoint = found.token_endpoint.as_deref().context("no token endpoint")?;
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(token_endpoint)
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
    let (status, body) = crate::oidc::exchange(request.body(Full::new(Bytes::from(form)))?, &Reach::operators()).await?;
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
    let audiences = [provider.client_id.clone()];
    let expect = Expect { found, audiences: &audiences, nonce: Some(nonce), party: true };
    Ok(match crate::oidc::verify(token, &Reach::operators(), &expect).await? {
        Ok((jwt, _)) => Ok(jwt.claims),
        Err(Rejected::Malformed(why)) => failed(format!("the ID token {why}")),
        Err(Rejected::Signature(alg)) => failed(format!("the ID token's signature ({alg}) isn't by {}'s keys", provider.label)),
        Err(Rejected::Issuer) => failed("the ID token is another issuer's"),
        Err(Rejected::Audience) => failed("the ID token is for another client"),
        Err(Rejected::Party) => failed("the ID token was issued to another party"),
        Err(Rejected::Expired { .. }) => failed("the ID token has expired"),
        Err(Rejected::NotYet) => failed("the ID token isn't valid yet (is a clock off?)"),
        Err(Rejected::Nonce) => failed("the ID token is for another sign-in"),
    })
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
    crate::oidc::forget(&provider.issuer);
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

/// The mock provider tests sign in at (see `oidc::mock`).
#[cfg(test)]
pub use crate::oidc::mock;
