//! Identity Center's access portal for the AWS CLI and SDKs (`aws sso
//! login`, `sso_session` profiles): **sso-oidc** (signing a client in) and
//! **sso** (the portal: accounts, roles and their credentials), on the
//! console's listener, where people sign in. See `plans/sso-login-spike.md`.
//!
//! Clients are pointed here with `AWS_ENDPOINT_URL_SSO` and
//! `AWS_ENDPOINT_URL_SSO_OIDC` (or a `services` section), both the
//! console's URL; `sso_region` is any region, only a label. Both APIs are
//! unsigned REST JSON: sso-oidc's requests carry the client's credentials
//! in their bodies, sso's an access token in `x-amz-sso_bearer_token`.
//!
//! - `GET`/`HEAD /start`, the start URL: the AWS CLI takes only an AWS-owned
//!   one, or one that redirects once to an AWS-owned one, which it doesn't
//!   fetch. So the start URL answers with a redirect to `resolved_start_url`,
//!   at `identitycenter.amazonaws.com` (AWS's own, never a customer's), which
//!   nothing ever contacts. A browser goes on to the console.
//! - `POST /client/register`: a client (an install of the CLI, say) gets an
//!   ID and a secret, for 90 days.
//! - `POST /device_authorization`: a device code, and a user code the person
//!   confirms at `/device` in the console (`--use-device-code`, and profiles
//!   without an `sso_session`).
//! - `GET /authorize`: the authorization code flow with PKCE, which the CLI
//!   opens in a browser, sending back to its loopback address. The person
//!   allows it in the console (`/sso/authorize/<id>`).
//! - `POST /token`: the device code's, the authorization code's, or the
//!   refresh token's grant: an access token (an hour) and the refresh token
//!   (`sso-session-hours`), which a person allowed: a *grant*, of the
//!   directory user who allowed it.
//! - `GET /assignment/accounts`, `GET /assignment/roles`: the accounts the
//!   user has permission sets assigned in, and those (by name, as roles).
//! - `GET /federation/credentials`: temporary credentials of a permission
//!   set's role, as the console's credentials page hands out.
//! - `POST /logout`: ends the grant.
//!
//! Tokens and codes are random, handed out once, and kept as their SHA-256
//! only. A grant goes with its user, and refresh tokens aren't rotated (an
//! SDK keeps the one it has when a refresh answers with the same), so that
//! processes sharing a token cache don't lock each other out.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Json, Router,
    body::Bytes,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use deadpool_postgres::Object;
use ring::digest;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::web::{ApiError, ErrorBody};
use super::{Console, DirectorySigned, store::hash};
use crate::db::Cached;
use crate::identity_center::{self, Eligible};

/// How long a client's registration lasts (as AWS's: 90 days).
const CLIENT_TTL: Duration = Duration::from_secs(90 * 24 * 3600);
/// How long a sign-in may wait for the person to allow it.
const REQUEST_TTL: Duration = Duration::from_secs(10 * 60);
/// How long an authorization code works, once the person allowed it.
const CODE_TTL: Duration = Duration::from_secs(5 * 60);
/// How long an access token works, at most.
const ACCESS_TTL: Duration = Duration::from_secs(3600);
/// How often a client polls for a device code's tokens, in seconds.
const POLL_INTERVAL: u64 = 1;
/// The most a body of either API may be.
pub(super) const MAX_BODY: usize = 64 * 1024;
/// The only scope there is: the portal's accounts and roles.
const SCOPE: &str = "sso:account:access";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const CODE_GRANT: &str = "authorization_code";
const REFRESH_GRANT: &str = "refresh_token";
/// The header the portal's requests carry their access token in.
const BEARER: &str = "x-amz-sso_bearer_token";
/// User codes' letters: consonants only, none that look alike (as RFC
/// 8628's example), so no word comes out.
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

fn secs(d: Duration) -> f64 {
    d.as_secs_f64()
}

/// A random token, URL-safe, and the hash it's kept as.
fn token() -> anyhow::Result<(String, Vec<u8>)> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("generating a token: {e}"))?;
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash(&token);
    Ok((token, hash))
}

/// A user code: 8 letters, as `BCDF-GHJK`.
fn user_code() -> anyhow::Result<String> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("generating a code: {e}"))?;
    // 256 isn't a multiple of 20: the first 16 letters come up a little
    // more often, which costs a fraction of a bit of 34.
    let letters: String = bytes
        .iter()
        .map(|b| USER_CODE_ALPHABET[*b as usize % USER_CODE_ALPHABET.len()] as char)
        .collect();
    Ok(format!("{}-{}", &letters[..4], &letters[4..]))
}

/// A user code as a person typed it: upper case, with its dash, without
/// spaces; `None` if it can't be one.
pub(super) fn normalize_user_code(text: &str) -> Option<String> {
    let letters: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (letters.len() == 8 && letters.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)))
        .then(|| format!("{}-{}", &letters[..4], &letters[4..]))
}

/// The start URL, at the console.
pub(super) fn start_url(console: &Console) -> String {
    format!("{}/start", console.party.origin)
}

/// Where the start URL redirects the AWS CLI to: an AWS-owned URL it takes
/// without fetching, at AWS's own issuer host (which AWS gives no customer),
/// naming this console. Clients send it back as their `startUrl` and
/// `issuerUrl`.
pub(super) fn resolved_start_url(console: &Console) -> String {
    let host = console
        .party
        .origin
        .split_once("://")
        .map_or(console.party.origin.as_str(), |(_, host)| host);
    format!("https://identitycenter.amazonaws.com/cairn/{host}")
}

/// Whether a client's `startUrl` or `issuerUrl` is this portal's: the start
/// URL as configured, or as the CLI resolved it.
fn is_ours(console: &Console, url: &str) -> bool {
    let url = url.trim_end_matches('/');
    url == start_url(console) || url == resolved_start_url(console)
}

// ─── Errors ──────────────────────────────────────────────────────────────────

/// An error of either API, as AWS's REST JSON protocol has them: its type
/// in `x-amzn-errortype`, and sso-oidc's OAuth `error` and
/// `error_description` (or the portal's `message`) in the body.
#[derive(Debug)]
struct AwsError {
    status: StatusCode,
    kind: &'static str,
    /// sso-oidc's OAuth error code, if it's sso-oidc's.
    oauth: Option<&'static str>,
    message: String,
}

impl AwsError {
    fn oidc(
        status: StatusCode,
        kind: &'static str,
        oauth: &'static str,
        message: impl Into<String>,
    ) -> Self {
        AwsError {
            status,
            kind,
            oauth: Some(oauth),
            message: message.into(),
        }
    }

    fn invalid_request(message: impl Into<String>) -> Self {
        Self::oidc(
            StatusCode::BAD_REQUEST,
            "InvalidRequestException",
            "invalid_request",
            message,
        )
    }

    fn invalid_client(message: impl Into<String>) -> Self {
        Self::oidc(
            StatusCode::UNAUTHORIZED,
            "InvalidClientException",
            "invalid_client",
            message,
        )
    }

    fn invalid_grant(message: impl Into<String>) -> Self {
        Self::oidc(
            StatusCode::BAD_REQUEST,
            "InvalidGrantException",
            "invalid_grant",
            message,
        )
    }

    fn invalid_scope(message: impl Into<String>) -> Self {
        Self::oidc(
            StatusCode::BAD_REQUEST,
            "InvalidScopeException",
            "invalid_scope",
            message,
        )
    }

    fn unauthorized_client(message: impl Into<String>) -> Self {
        Self::oidc(
            StatusCode::BAD_REQUEST,
            "UnauthorizedClientException",
            "unauthorized_client",
            message,
        )
    }

    fn slow_down(message: impl Into<String>) -> Self {
        Self::oidc(
            StatusCode::BAD_REQUEST,
            "SlowDownException",
            "slow_down",
            message,
        )
    }

    fn portal(status: StatusCode, kind: &'static str, message: impl Into<String>) -> Self {
        AwsError {
            status,
            kind,
            oauth: None,
            message: message.into(),
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self::portal(StatusCode::UNAUTHORIZED, "UnauthorizedException", message)
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self::portal(StatusCode::NOT_FOUND, "ResourceNotFoundException", message)
    }

    fn bad_portal_request(message: impl Into<String>) -> Self {
        Self::portal(StatusCode::BAD_REQUEST, "InvalidRequestException", message)
    }
}

/// Why a request failed: as the API says, or Cairn's own failure (the
/// database's, say), logged and not explained.
enum Failure {
    Aws(AwsError),
    Internal(anyhow::Error),
}

impl From<AwsError> for Failure {
    fn from(e: AwsError) -> Self {
        Failure::Aws(e)
    }
}

impl From<anyhow::Error> for Failure {
    fn from(e: anyhow::Error) -> Self {
        Failure::Internal(e)
    }
}

impl From<tokio_postgres::Error> for Failure {
    fn from(e: tokio_postgres::Error) -> Self {
        Failure::Internal(e.into())
    }
}

impl From<deadpool_postgres::PoolError> for Failure {
    fn from(e: deadpool_postgres::PoolError) -> Self {
        Failure::Internal(e.into())
    }
}

/// Which API answers, for its internal errors' shape.
#[derive(Clone, Copy)]
enum Api {
    Oidc,
    Portal,
}

fn answer(api: Api, result: Result<Value, Failure>) -> Response {
    let error = match result {
        Ok(body) => return (StatusCode::OK, Json(body)).into_response(),
        Err(Failure::Aws(e)) => e,
        Err(Failure::Internal(e)) => {
            eprintln!("access portal: a request failed: {e:#}");
            let message = "internal error; the node's log has the details";
            match api {
                Api::Oidc => AwsError::oidc(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalServerException",
                    "server_error",
                    message,
                ),
                Api::Portal => AwsError::portal(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalServerException",
                    message,
                ),
            }
        }
    };
    let body = match error.oauth {
        Some(code) => json!({ "error": code, "error_description": error.message }),
        None => json!({ "message": error.message }),
    };
    let mut response = (error.status, Json(body)).into_response();
    response
        .headers_mut()
        .insert("x-amzn-errortype", HeaderValue::from_static(error.kind));
    response
}

// ─── Routes ──────────────────────────────────────────────────────────────────

/// The two APIs and the start URL, at the console's root, where AWS's
/// clients expect them.
pub(super) fn protocol_router() -> Router<Arc<Console>> {
    Router::new()
        .route("/start", get(start))
        .route("/start/", get(start))
        .route("/client/register", post(register_client))
        .route("/device_authorization", post(start_device_authorization))
        .route("/authorize", get(authorize))
        .route("/token", post(create_token))
        .route("/assignment/accounts", get(list_accounts))
        .route("/assignment/roles", get(list_account_roles))
        .route("/federation/credentials", get(get_role_credentials))
        .route("/logout", post(logout))
}

/// The console's own API for the pages where people allow sign-ins (under
/// `/api`, as the page's).
pub(super) fn api_router() -> OpenApiRouter<Arc<Console>> {
    OpenApiRouter::new()
        .routes(routes!(sign_in_request))
        .routes(routes!(device_sign_in_request))
        .routes(routes!(decide))
}

/// The client's address, for the limit on starting sign-ins, if known.
fn client_address(console: &Console, headers: &HeaderMap, peer: Option<IpAddr>) -> Option<IpAddr> {
    crate::s3::access::client_address(headers, peer, &console.app.trusted_proxies)
}

/// Whether the client may start another sign-in (registering, asking for a
/// device code or an authorization), each of which writes a row before
/// anyone is known, under the console's limit on starting sign-ins.
fn allowed(console: &Console, headers: &HeaderMap, peer: Option<IpAddr>) -> bool {
    match client_address(console, headers, peer) {
        Some(address) => console.app.console.sign_ins.allow(address),
        None => true,
    }
}

/// The address a request came from, if the listener says.
struct Peer(Option<IpAddr>);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for Peer {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Peer(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|c| c.0.ip()),
        ))
    }
}

/// A request body of JSON, as AWS's SDKs send.
fn body_of<T: for<'de> Deserialize<'de>>(body: &Bytes) -> Result<T, AwsError> {
    serde_json::from_slice(body)
        .map_err(|e| AwsError::invalid_request(format!("the request isn't valid JSON for it: {e}")))
}

// ─── The start URL ───────────────────────────────────────────────────────────

/// The start URL (`<console>/start`): the AWS CLI's check gets a redirect to
/// an AWS-owned URL (see `resolved_start_url`); a browser goes on to the
/// console.
async fn start(
    State(console): State<Arc<Console>>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let browser = method == Method::GET
        && headers
            .get(header::ACCEPT)
            .and_then(|a| a.to_str().ok())
            .is_some_and(|a| a.contains("text/html"));
    let (status, location) = if browser {
        (StatusCode::SEE_OTHER, "/".to_owned())
    } else {
        (StatusCode::FOUND, resolved_start_url(&console))
    };
    (
        status,
        [
            (header::LOCATION, location),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
    )
        .into_response()
}

// ─── sso-oidc: RegisterClient ────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterClientRequest {
    client_name: Option<String>,
    client_type: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default)]
    grant_types: Vec<String>,
    issuer_url: Option<String>,
}

async fn register_client(
    State(console): State<Arc<Console>>,
    Peer(peer): Peer,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    answer(
        Api::Oidc,
        register_client_with(&console, &headers, peer, &body).await,
    )
}

async fn register_client_with(
    console: &Console,
    headers: &HeaderMap,
    peer: Option<IpAddr>,
    body: &Bytes,
) -> Result<Value, Failure> {
    let request: RegisterClientRequest = body_of(body)?;
    let name = request.client_name.unwrap_or_default();
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 256 || name.chars().any(char::is_control) {
        return Err(AwsError::invalid_request("clientName must be 1 to 256 characters").into());
    }
    if request.client_type.as_deref() != Some("public") {
        return Err(AwsError::invalid_request("clientType must be public").into());
    }
    check_scopes(&request.scopes)?;
    for grant in &request.grant_types {
        if ![CODE_GRANT, REFRESH_GRANT, DEVICE_GRANT].contains(&grant.as_str()) {
            return Err(AwsError::invalid_request(format!(
                "grant type {grant:?} isn't supported: {CODE_GRANT}, {REFRESH_GRANT} and {DEVICE_GRANT} are"
            ))
            .into());
        }
    }
    if request.redirect_uris.len() > 10 {
        return Err(AwsError::invalid_request("at most 10 redirectUris").into());
    }
    for uri in &request.redirect_uris {
        if loopback(uri).is_none() {
            return Err(AwsError::invalid_request(format!(
                "redirect URI {uri:?} isn't one: only a loopback address's (http://127.0.0.1/…) is"
            ))
            .into());
        }
    }
    if request.grant_types.iter().any(|g| g == CODE_GRANT) && request.redirect_uris.is_empty() {
        return Err(
            AwsError::invalid_request("the authorization code grant needs redirectUris").into(),
        );
    }
    if let Some(issuer) = &request.issuer_url
        && !is_ours(console, issuer)
    {
        return Err(not_ours(console, issuer).into());
    }
    if !allowed(console, headers, peer) {
        return Err(AwsError::slow_down("too many sign-ins from here; wait a minute").into());
    }
    let client = console.app.pool.get().await?;
    let (id, _) = token()?;
    let (secret, secret_hash) = token()?;
    let row = client
        .query_one_cached(
            "INSERT INTO sso_clients (id, secret_hash, name, grant_types, redirect_uris, scopes, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7))
             RETURNING extract(epoch FROM created_at)::bigint, extract(epoch FROM expires_at)::bigint",
            &[
                &id,
                &secret_hash,
                &name,
                &request.grant_types,
                &request.redirect_uris,
                &request.scopes,
                &secs(CLIENT_TTL),
            ],
        )
        .await?;
    let origin = &console.party.origin;
    Ok(json!({
        "clientId": id,
        "clientSecret": secret,
        "clientIdIssuedAt": row.get::<_, i64>(0),
        "clientSecretExpiresAt": row.get::<_, i64>(1),
        "authorizationEndpoint": format!("{origin}/authorize"),
        "tokenEndpoint": format!("{origin}/token"),
    }))
}

fn not_ours(console: &Console, url: &str) -> AwsError {
    AwsError::invalid_request(format!(
        "{url} isn't this access portal's start URL: this is {}'s, whose start URL is {}",
        console.party.origin,
        start_url(console)
    ))
}

/// The scopes asked for, if Cairn has them: `sso:account:access` only.
fn check_scopes(scopes: &[String]) -> Result<(), AwsError> {
    match scopes.iter().find(|s| s.as_str() != SCOPE) {
        Some(other) => Err(AwsError::invalid_scope(format!(
            "scope {other:?} isn't one of this portal's: it has {SCOPE} only"
        ))),
        None => Ok(()),
    }
}

/// A loopback redirect URI's host, port (if it has one) and path: `http`,
/// to `127.0.0.1`, `[::1]` or `localhost`, with no query or fragment (RFC
/// 8252); `None` if it isn't one.
fn loopback(text: &str) -> Option<(String, Option<u16>, String)> {
    if text.contains('#') || text.len() > 512 {
        return None;
    }
    let uri: Uri = text.parse().ok()?;
    if uri.scheme_str() != Some("http") || uri.query().is_some() {
        return None;
    }
    let host = uri.host()?.to_ascii_lowercase();
    if !matches!(host.as_str(), "127.0.0.1" | "[::1]" | "localhost") {
        return None;
    }
    let authority = uri.authority()?.as_str();
    if authority.contains('@') {
        return None;
    }
    Some((host, uri.port_u16(), uri.path().to_owned()))
}

/// Whether `asked`, the redirect URI of an authorization, is one of a
/// client's `registered`: the same but for the port, which a registered one
/// without a port leaves to the client (RFC 8252, as the CLI registers
/// `http://127.0.0.1/oauth/callback` and listens on any port).
fn registered_redirect(registered: &[String], asked: &str) -> bool {
    let Some((host, port, path)) = loopback(asked) else {
        return false;
    };
    registered
        .iter()
        .filter_map(|r| loopback(r))
        .any(|(h, p, pa)| h == host && pa == path && (p.is_none() || p == port))
}

// ─── Clients ─────────────────────────────────────────────────────────────────

/// A registered client.
struct Client {
    id: String,
    name: String,
    grant_types: Vec<String>,
    redirect_uris: Vec<String>,
}

/// The client `id`, while its registration lasts.
async fn client_by_id(db: &Object, id: &str) -> anyhow::Result<Option<(Client, Vec<u8>)>> {
    let row = db
        .query_opt_cached(
            "SELECT id, name, grant_types, redirect_uris, secret_hash FROM sso_clients
             WHERE id = $1 AND expires_at > now()",
            &[&id],
        )
        .await?;
    Ok(row.map(|row| {
        (
            Client {
                id: row.get(0),
                name: row.get(1),
                grant_types: row.get(2),
                redirect_uris: row.get(3),
            },
            row.get(4),
        )
    }))
}

/// The client whose ID and secret a request carries, while its registration
/// lasts.
async fn authenticated_client(
    db: &Object,
    id: Option<&str>,
    secret: Option<&str>,
) -> Result<Client, Failure> {
    let (Some(id), Some(secret)) = (id, secret) else {
        return Err(AwsError::invalid_client("clientId and clientSecret are required").into());
    };
    match client_by_id(db, id).await? {
        // Hashes compared: how long that takes says nothing of the secret.
        Some((client, kept)) if kept == hash(secret) => Ok(client),
        _ => Err(AwsError::invalid_client(
            "no such client, or its registration has expired: sign in again (aws sso login)",
        )
        .into()),
    }
}

// ─── sso-oidc: StartDeviceAuthorization ──────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartDeviceAuthorizationRequest {
    client_id: Option<String>,
    client_secret: Option<String>,
    start_url: Option<String>,
}

async fn start_device_authorization(
    State(console): State<Arc<Console>>,
    Peer(peer): Peer,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    answer(
        Api::Oidc,
        start_device_with(&console, &headers, peer, &body).await,
    )
}

async fn start_device_with(
    console: &Console,
    headers: &HeaderMap,
    peer: Option<IpAddr>,
    body: &Bytes,
) -> Result<Value, Failure> {
    let request: StartDeviceAuthorizationRequest = body_of(body)?;
    let db = console.app.pool.get().await?;
    let client = authenticated_client(
        &db,
        request.client_id.as_deref(),
        request.client_secret.as_deref(),
    )
    .await?;
    let Some(start) = &request.start_url else {
        return Err(AwsError::invalid_request("startUrl is required").into());
    };
    if !is_ours(console, start) {
        return Err(not_ours(console, start).into());
    }
    if !client.grant_types.is_empty() && !client.grant_types.iter().any(|g| g == DEVICE_GRANT) {
        return Err(AwsError::unauthorized_client(
            "the client didn't register for the device code grant",
        )
        .into());
    }
    if !allowed(console, headers, peer) {
        return Err(AwsError::slow_down("too many sign-ins from here; wait a minute").into());
    }
    let (device_code, device_hash) = token()?;
    // A user code that's taken (by a sign-in that's pending, or expired and
    // not reaped yet) is drawn again.
    for _ in 0..5 {
        let code = user_code()?;
        let inserted = db
            .execute_cached(
                "INSERT INTO sso_authorizations (id, client_id, kind, scopes, device_code_hash, user_code, status, expires_at)
                 VALUES ($1, $2, 'device', $3, $4, $5, 'pending', now() + make_interval(secs => $6))
                 ON CONFLICT (user_code) DO NOTHING",
                &[&Uuid::new_v4(), &client.id, &vec![SCOPE.to_owned()], &device_hash, &code, &secs(REQUEST_TTL)],
            )
            .await?;
        if inserted == 1 {
            let origin = &console.party.origin;
            return Ok(json!({
                "deviceCode": device_code,
                "userCode": code,
                "verificationUri": format!("{origin}/device"),
                "verificationUriComplete": format!("{origin}/device?user_code={code}"),
                "expiresIn": REQUEST_TTL.as_secs(),
                "interval": POLL_INTERVAL,
            }));
        }
    }
    Err(anyhow::anyhow!("no free user code in 5 draws").into())
}

// ─── sso-oidc: the authorization endpoint ────────────────────────────────────

#[derive(Deserialize)]
struct AuthorizeQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    scopes: Option<String>,
    scope: Option<String>,
}

/// A page of plain text, for what goes wrong before there's anywhere to
/// send the browser back to.
fn text_page(status: StatusCode, text: String) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        text,
    )
        .into_response()
}

/// What a query's value keeps as it is: RFC 3986's unreserved characters.
const QUERY_VALUE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn encode(text: &str) -> String {
    percent_encoding::utf8_percent_encode(text, QUERY_VALUE).to_string()
}

/// `redirect_uri` with `params` added to its query (it has none).
fn with_query(redirect_uri: &str, params: &[(&str, &str)]) -> String {
    let query: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{k}={}", encode(v)))
        .collect();
    format!("{redirect_uri}?{}", query.join("&"))
}

/// The authorization endpoint, which the CLI opens in a browser: checks the
/// client and where to send the browser back to, keeps the request, and has
/// the browser go on to the console's page for it, where the person signs
/// in and allows it (or not).
async fn authorize(
    State(console): State<Arc<Console>>,
    Peer(peer): Peer,
    headers: HeaderMap,
    Query(query): Query<AuthorizeQuery>,
) -> Response {
    match authorize_with(&console, &headers, peer, query).await {
        Ok(response) => response,
        Err(e) => {
            eprintln!("access portal: an authorization failed: {e:#}");
            text_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Signing in failed: an internal error; the node's log has the details.".into(),
            )
        }
    }
}

async fn authorize_with(
    console: &Console,
    headers: &HeaderMap,
    peer: Option<IpAddr>,
    query: AuthorizeQuery,
) -> anyhow::Result<Response> {
    let db = console.app.pool.get().await?;
    // What's wrong before the client and its redirect URI are known is
    // shown here; what's wrong after, sent back to the client (RFC 6749).
    let refuse = |why: &str| {
        text_page(
            StatusCode::BAD_REQUEST,
            format!("This sign-in can't go on: {why}. Start it again (aws sso login)."),
        )
    };
    let Some(client_id) = &query.client_id else {
        return Ok(refuse("it names no client"));
    };
    let Some((client, _)) = client_by_id(&db, client_id).await? else {
        return Ok(refuse(
            "its client isn't registered, or its registration has expired",
        ));
    };
    let Some(redirect_uri) = &query.redirect_uri else {
        return Ok(refuse("it says nowhere to send you back to"));
    };
    if !registered_redirect(&client.redirect_uris, redirect_uri) {
        return Ok(refuse("where it would send you back to isn't the client's"));
    }
    let state = query.state.as_deref().unwrap_or("");
    let back = |error: &str, description: &str| -> Response {
        let mut params = vec![("error", error), ("error_description", description)];
        if !state.is_empty() {
            params.push(("state", state));
        }
        redirect_to(&with_query(redirect_uri, &params))
    };
    if query.response_type.as_deref() != Some("code") {
        return Ok(back(
            "unsupported_response_type",
            "response_type must be code",
        ));
    }
    if !client.grant_types.iter().any(|g| g == CODE_GRANT) {
        return Ok(back(
            "unauthorized_client",
            "the client didn't register for the authorization code grant",
        ));
    }
    let Some(challenge) = query
        .code_challenge
        .as_deref()
        .filter(|c| (43..=128).contains(&c.len()))
    else {
        return Ok(back(
            "invalid_request",
            "a code_challenge (PKCE) is required",
        ));
    };
    if query.code_challenge_method.as_deref() != Some("S256") {
        return Ok(back(
            "invalid_request",
            "code_challenge_method must be S256",
        ));
    }
    if state.len() > 1024 {
        return Ok(back("invalid_request", "state is too long"));
    }
    let scopes: Vec<String> = query
        .scopes
        .as_deref()
        .or(query.scope.as_deref())
        .unwrap_or(SCOPE)
        .split([' ', ','])
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    if let Err(e) = check_scopes(&scopes) {
        return Ok(back("invalid_scope", &e.message));
    }
    if !allowed(console, headers, peer) {
        return Ok(text_page(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many sign-ins from here: wait a minute, and start again (aws sso login).".into(),
        ));
    }
    let id = Uuid::new_v4();
    db.execute_cached(
        "INSERT INTO sso_authorizations (id, client_id, kind, scopes, redirect_uri, state, code_challenge, status, expires_at)
         VALUES ($1, $2, 'code', $3, $4, $5, $6, 'pending', now() + make_interval(secs => $7))",
        &[&id, &client.id, &scopes, redirect_uri, &query.state, &challenge, &secs(REQUEST_TTL)],
    )
    .await?;
    Ok(redirect_to(&format!("/sso/authorize/{id}")))
}

fn redirect_to(location: &str) -> Response {
    (
        StatusCode::FOUND,
        [
            (header::LOCATION, location.to_owned()),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
    )
        .into_response()
}

// ─── sso-oidc: CreateToken ───────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateTokenRequest {
    client_id: Option<String>,
    client_secret: Option<String>,
    grant_type: Option<String>,
    device_code: Option<String>,
    code: Option<String>,
    refresh_token: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    #[serde(default)]
    scope: Vec<String>,
}

async fn create_token(State(console): State<Arc<Console>>, body: Bytes) -> Response {
    answer(Api::Oidc, create_token_with(&console, &body).await)
}

async fn create_token_with(console: &Console, body: &Bytes) -> Result<Value, Failure> {
    let request: CreateTokenRequest = body_of(body)?;
    let db = console.app.pool.get().await?;
    let client = authenticated_client(
        &db,
        request.client_id.as_deref(),
        request.client_secret.as_deref(),
    )
    .await?;
    check_scopes(&request.scope)?;
    match request.grant_type.as_deref() {
        Some(DEVICE_GRANT) => {
            if !client.grant_types.is_empty()
                && !client.grant_types.iter().any(|g| g == DEVICE_GRANT)
            {
                return Err(AwsError::unauthorized_client(
                    "the client didn't register for the device code grant",
                )
                .into());
            }
            let Some(device_code) = &request.device_code else {
                return Err(AwsError::invalid_request("deviceCode is required").into());
            };
            device_grant(&db, &client, device_code).await
        }
        Some(CODE_GRANT) => {
            if !client.grant_types.iter().any(|g| g == CODE_GRANT) {
                return Err(AwsError::unauthorized_client(
                    "the client didn't register for the authorization code grant",
                )
                .into());
            }
            let (Some(code), Some(redirect_uri), Some(verifier)) =
                (&request.code, &request.redirect_uri, &request.code_verifier)
            else {
                return Err(AwsError::invalid_request(
                    "code, redirectUri and codeVerifier are required",
                )
                .into());
            };
            code_grant(&db, &client, code, redirect_uri, verifier).await
        }
        Some(REFRESH_GRANT) => {
            let Some(refresh) = &request.refresh_token else {
                return Err(AwsError::invalid_request("refreshToken is required").into());
            };
            refresh_grant(&db, &client, refresh).await
        }
        Some(other) => Err(AwsError::oidc(
            StatusCode::BAD_REQUEST,
            "UnsupportedGrantTypeException",
            "unsupported_grant_type",
            format!("grant type {other:?} isn't supported"),
        )
        .into()),
        None => Err(AwsError::invalid_request("grantType is required").into()),
    }
}

/// The device code's grant: pending until the person allows it (or not), and
/// then good for one grant.
async fn device_grant(db: &Object, client: &Client, device_code: &str) -> Result<Value, Failure> {
    let row = db
        .query_opt_cached(
            "SELECT status, expires_at <= now() FROM sso_authorizations
             WHERE device_code_hash = $1 AND client_id = $2 AND kind = 'device'",
            &[&hash(device_code), &client.id],
        )
        .await?;
    let Some(row) = row else {
        return Err(AwsError::invalid_grant("no such device code, or it was used").into());
    };
    let (status, expired): (String, bool) = (row.get(0), row.get(1));
    if expired {
        return Err(AwsError::oidc(
            StatusCode::BAD_REQUEST,
            "ExpiredTokenException",
            "expired_token",
            "the device code has expired: sign in again",
        )
        .into());
    }
    match status.as_str() {
        "pending" => Err(AwsError::oidc(
            StatusCode::BAD_REQUEST,
            "AuthorizationPendingException",
            "authorization_pending",
            "waiting for you to allow the sign-in in the console",
        )
        .into()),
        "denied" => {
            db.execute_cached(
                "DELETE FROM sso_authorizations WHERE device_code_hash = $1",
                &[&hash(device_code)],
            )
            .await?;
            Err(AwsError::oidc(
                StatusCode::BAD_REQUEST,
                "AccessDeniedException",
                "access_denied",
                "the sign-in was denied",
            )
            .into())
        }
        _ => {
            // Used once: of polls at the same time, one gets the grant.
            let taken = db
                .query_opt_cached(
                    "DELETE FROM sso_authorizations
                     WHERE device_code_hash = $1 AND client_id = $2 AND status = 'approved' AND expires_at > now()
                     RETURNING account_id, user_id, scopes",
                    &[&hash(device_code), &client.id],
                )
                .await?;
            let Some(taken) = taken else {
                return Err(AwsError::invalid_grant("no such device code, or it was used").into());
            };
            new_grant(db, client, taken.get(0), taken.get(1), taken.get(2)).await
        }
    }
}

/// The authorization code's grant, with its PKCE verifier, once.
async fn code_grant(
    db: &Object,
    client: &Client,
    code: &str,
    redirect_uri: &str,
    verifier: &str,
) -> Result<Value, Failure> {
    let taken = db
        .query_opt_cached(
            "DELETE FROM sso_authorizations
             WHERE code_hash = $1 AND kind = 'code' AND status = 'approved'
             RETURNING client_id, redirect_uri, code_challenge, account_id, user_id, scopes, expires_at > now()",
            &[&hash(code)],
        )
        .await?;
    let invalid =
        || AwsError::invalid_grant("no such authorization code, or it was used or has expired");
    let Some(taken) = taken else {
        return Err(invalid().into());
    };
    if taken.get::<_, String>(0) != client.id || !taken.get::<_, bool>(6) {
        return Err(invalid().into());
    }
    if taken.get::<_, String>(1) != redirect_uri {
        return Err(AwsError::invalid_grant("redirectUri isn't the authorization's").into());
    }
    let challenge: String = taken.get(2);
    let computed = URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, verifier.as_bytes()));
    if !(43..=128).contains(&verifier.len()) || computed != challenge {
        return Err(AwsError::invalid_grant(
            "the code verifier doesn't match the authorization's challenge",
        )
        .into());
    }
    new_grant(db, client, taken.get(3), taken.get(4), taken.get(5)).await
}

/// A grant for directory user `user` of `account`'s instance, which it
/// allowed: its refresh token, for `sso-session-hours`, and a first access
/// token.
async fn new_grant(
    db: &Object,
    client: &Client,
    account: String,
    user: Uuid,
    scopes: Vec<String>,
) -> Result<Value, Failure> {
    let hours = crate::settings::SSO_SESSION_HOURS.get(db).await?;
    let (refresh, refresh_hash) = token()?;
    let id = Uuid::new_v4();
    let row = db
        .query_one_cached(
            "WITH g AS (
                 INSERT INTO sso_grants (id, client_id, account_id, user_id, scopes, refresh_hash, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(hours => $7::int))
                 RETURNING user_id
             )
             SELECT u.user_name FROM g JOIN identity_users u ON u.id = g.user_id",
            &[&id, &client.id, &account, &user, &scopes, &refresh_hash, &(hours as i32)],
        )
        .await?;
    eprintln!(
        "access portal: client {:?} ({}) signed in as directory user {} (grant {id}, {hours} hours)",
        client.name,
        client.id,
        row.get::<_, String>(0)
    );
    access_token(db, id, refresh).await
}

/// The refresh token's grant: a new access token, while the grant lasts and
/// its user exists. The refresh token stays the same.
async fn refresh_grant(db: &Object, client: &Client, refresh: &str) -> Result<Value, Failure> {
    let row = db
        .query_opt_cached(
            "SELECT g.id FROM sso_grants g JOIN identity_users u ON u.id = g.user_id
             WHERE g.refresh_hash = $1 AND g.client_id = $2 AND g.expires_at > now()",
            &[&hash(refresh), &client.id],
        )
        .await?;
    let Some(row) = row else {
        return Err(AwsError::invalid_grant(
            "the refresh token has expired, or was revoked: sign in again (aws sso login)",
        )
        .into());
    };
    access_token(db, row.get(0), refresh.to_owned()).await
}

/// A new access token of grant `id`, for an hour or what's left of the
/// grant, and the grant's refresh token, as CreateToken answers.
async fn access_token(db: &Object, id: Uuid, refresh: String) -> Result<Value, Failure> {
    let (access, access_hash) = token()?;
    let row = db
        .query_one_cached(
            "INSERT INTO sso_access_tokens (token_hash, grant_id, expires_at)
             SELECT $1, id, least(expires_at, now() + make_interval(secs => $3)) FROM sso_grants WHERE id = $2
             RETURNING greatest(1, extract(epoch FROM expires_at - now()))::bigint",
            &[&access_hash, &id, &secs(ACCESS_TTL)],
        )
        .await?;
    Ok(json!({
        "accessToken": access,
        "tokenType": "Bearer",
        "expiresIn": row.get::<_, i64>(0),
        "refreshToken": refresh,
    }))
}

// ─── The portal ──────────────────────────────────────────────────────────────

/// Who an access token is: a grant's directory user.
struct Holder {
    grant: Uuid,
    account: String,
    user: Uuid,
    user_name: String,
    email: Option<String>,
    subject: Option<String>,
    provider: Option<String>,
}

/// Who the access token of a portal request is, while it and its grant
/// last.
async fn holder(db: &Object, headers: &HeaderMap) -> Result<Holder, Failure> {
    let Some(token) = headers.get(BEARER).and_then(|v| v.to_str().ok()) else {
        return Err(
            AwsError::unauthorized(format!("the request has no access token ({BEARER})")).into(),
        );
    };
    let row = db
        .query_opt_cached(
            "SELECT g.id, g.account_id, u.id, u.user_name, u.email, u.subject, u.provider
             FROM sso_access_tokens t JOIN sso_grants g ON g.id = t.grant_id
             JOIN identity_users u ON u.id = g.user_id
             WHERE t.token_hash = $1 AND t.expires_at > now() AND g.expires_at > now()",
            &[&hash(token)],
        )
        .await?;
    let Some(row) = row else {
        return Err(AwsError::unauthorized(
            "the access token has expired, or was revoked: sign in again",
        )
        .into());
    };
    Ok(Holder {
        grant: row.get(0),
        account: row.get(1),
        user: row.get(2),
        user_name: row.get(3),
        email: row.get(4),
        subject: row.get(5),
        provider: row.get(6),
    })
}

#[derive(Deserialize)]
struct Page {
    next_token: Option<String>,
    max_result: Option<String>,
    account_id: Option<String>,
    role_name: Option<String>,
}

/// One page of `items`, from where `next_token` says (an offset), of
/// `max_result` at most (and of 100 at most), and the token of the next.
fn page<T>(items: Vec<T>, query: &Page) -> Result<(Vec<T>, Option<String>), AwsError> {
    let start: usize = match &query.next_token {
        Some(token) => token
            .parse()
            .map_err(|_| AwsError::bad_portal_request("nextToken isn't one of ours"))?,
        None => 0,
    };
    let max: usize = match &query.max_result {
        Some(max) => max
            .parse()
            .ok()
            .filter(|m| (1..=100).contains(m))
            .ok_or_else(|| AwsError::bad_portal_request("maxResult must be from 1 to 100"))?,
        None => 100,
    };
    let total = items.len();
    let items: Vec<T> = items.into_iter().skip(start).take(max).collect();
    let end = start + items.len();
    Ok((items, (end < total).then(|| end.to_string())))
}

/// What the holder may pick: its permission sets, in the accounts they're
/// assigned in.
async fn eligible(db: &Object, holder: &Holder) -> anyhow::Result<Vec<Eligible>> {
    identity_center::eligible(db, &holder.account, holder.user).await
}

async fn list_accounts(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
    Query(query): Query<Page>,
) -> Response {
    answer(
        Api::Portal,
        list_accounts_with(&console, &headers, &query).await,
    )
}

async fn list_accounts_with(
    console: &Console,
    headers: &HeaderMap,
    query: &Page,
) -> Result<Value, Failure> {
    let db = console.app.pool.get().await?;
    let holder = holder(&db, headers).await?;
    let mut accounts: Vec<(String, String)> = Vec::new();
    for e in eligible(&db, &holder).await? {
        if !accounts.iter().any(|(id, _)| *id == e.account) {
            accounts.push((e.account, e.account_name));
        }
    }
    let ids: Vec<String> = accounts.iter().map(|(id, _)| id.clone()).collect();
    let emails = db
        .query_cached("SELECT id, email FROM accounts WHERE id = ANY($1)", &[&ids])
        .await?;
    let email_of = |id: &str| -> Option<String> {
        emails
            .iter()
            .find(|r| r.get::<_, String>(0) == id)
            .and_then(|r| r.get(1))
    };
    let (accounts, next) = page(accounts, query)?;
    let list: Vec<Value> = accounts
        .iter()
        .map(|(id, name)| {
            let mut account = json!({ "accountId": id, "accountName": name });
            if let Some(email) = email_of(id) {
                account["emailAddress"] = json!(email);
            }
            account
        })
        .collect();
    Ok(json!({ "accountList": list, "nextToken": next }))
}

async fn list_account_roles(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
    Query(query): Query<Page>,
) -> Response {
    answer(
        Api::Portal,
        list_account_roles_with(&console, &headers, &query).await,
    )
}

async fn list_account_roles_with(
    console: &Console,
    headers: &HeaderMap,
    query: &Page,
) -> Result<Value, Failure> {
    let db = console.app.pool.get().await?;
    let holder = holder(&db, headers).await?;
    let Some(account) = &query.account_id else {
        return Err(AwsError::bad_portal_request("account_id is required").into());
    };
    let roles: Vec<String> = eligible(&db, &holder)
        .await?
        .into_iter()
        .filter(|e| e.account == *account)
        .map(|e| e.set.name)
        .collect();
    let (roles, next) = page(roles, query)?;
    let list: Vec<Value> = roles
        .iter()
        .map(|name| json!({ "roleName": name, "accountId": account }))
        .collect();
    Ok(json!({ "roleList": list, "nextToken": next }))
}

async fn get_role_credentials(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
    Query(query): Query<Page>,
) -> Response {
    answer(
        Api::Portal,
        get_role_credentials_with(&console, &headers, &query).await,
    )
}

async fn get_role_credentials_with(
    console: &Console,
    headers: &HeaderMap,
    query: &Page,
) -> Result<Value, Failure> {
    let db = console.app.pool.get().await?;
    let holder = holder(&db, headers).await?;
    let (Some(account), Some(role)) = (&query.account_id, &query.role_name) else {
        return Err(AwsError::bad_portal_request("account_id and role_name are required").into());
    };
    let Some(chosen) = eligible(&db, &holder)
        .await?
        .into_iter()
        .find(|e| e.account == *account && e.set.name == *role)
    else {
        return Err(AwsError::not_found(format!(
            "no permission set {role:?} is assigned to you in account {account}"
        ))
        .into());
    };
    let mut session = super::directory::role_session_of(
        &chosen,
        &holder.user_name,
        holder.email.as_deref(),
        holder.subject.as_deref(),
    )?;
    let token = console.app.sessions.seal(&db, &mut session).await?;
    eprintln!(
        "access portal: credentials {} of permission set {} in account {} for directory user {} ({} of {}), grant {}",
        session.key_id,
        chosen.set.name,
        chosen.account,
        holder.user_name,
        holder.subject.as_deref().unwrap_or("-"),
        holder
            .provider
            .as_deref()
            .unwrap_or("Cairn's own directory"),
        holder.grant,
    );
    Ok(json!({
        "roleCredentials": {
            "accessKeyId": session.key_id,
            "secretAccessKey": session.secret,
            "sessionToken": token,
            "expiration": session.expires * 1000,
        }
    }))
}

async fn logout(State(console): State<Arc<Console>>, headers: HeaderMap) -> Response {
    answer(Api::Portal, logout_with(&console, &headers).await)
}

/// Ends the access token's grant: its refresh token, and every access token
/// of it. Credentials handed out last until they expire.
async fn logout_with(console: &Console, headers: &HeaderMap) -> Result<Value, Failure> {
    let db = console.app.pool.get().await?;
    let holder = holder(&db, headers).await?;
    db.execute_cached("DELETE FROM sso_grants WHERE id = $1", &[&holder.grant])
        .await?;
    eprintln!(
        "access portal: directory user {} signed out (grant {})",
        holder.user_name, holder.grant
    );
    Ok(json!({}))
}

// ─── The console's pages ─────────────────────────────────────────────────────

/// A sign-in of the AWS CLI or an SDK, waiting for its person.
#[derive(Serialize, ToSchema)]
struct SignInRequest {
    id: String,
    /// How it signs in: `device` (a code the person confirms) or `code` (a
    /// browser that goes back to the program).
    kind: String,
    /// The name the program gave itself (the CLI's is
    /// `botocore-client-<sso_session>`).
    client_name: String,
    /// The device's code, for the person to check against what the program
    /// shows.
    user_code: Option<String>,
    /// When it can't be allowed anymore (seconds since the epoch).
    expires_at: f64,
    /// How long the program will be signed in for, if allowed, in hours.
    session_hours: i64,
}

const REQUEST_COLUMNS: &str =
    "a.id, a.kind, c.name, a.user_code, extract(epoch FROM a.expires_at)::float8";

async fn request_of(db: &Object, row: tokio_postgres::Row) -> anyhow::Result<SignInRequest> {
    Ok(SignInRequest {
        id: row.get::<_, Uuid>(0).to_string(),
        kind: row.get(1),
        client_name: row.get(2),
        user_code: row.get(3),
        expires_at: row.get(4),
        session_hours: crate::settings::SSO_SESSION_HOURS.get(db).await?,
    })
}

/// The ID of a sign-in, from a page's path.
fn request_id(text: &str) -> Result<Uuid, ApiError> {
    text.parse()
        .map_err(|_| ApiError::NotFound("no such sign-in".into()))
}

/// Only a directory user allows sign-ins, as itself: the root user has no
/// permission sets to hand out.
type Signed = DirectorySigned;

/// A sign-in of the AWS CLI or an SDK (the authorization code's), which the
/// signed-in directory user may allow.
#[utoipa::path(get, path = "/sso/requests/{id}", params(("id" = String, Path)), responses(
    (status = 200, body = SignInRequest),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn sign_in_request(
    State(console): State<Arc<Console>>,
    _signed: Signed,
    Path(id): Path<String>,
) -> Result<Json<SignInRequest>, ApiError> {
    let id = request_id(&id)?;
    let db = console.app.pool.get().await?;
    let row = db
        .query_opt_cached(
            &format!(
                "SELECT {REQUEST_COLUMNS} FROM sso_authorizations a JOIN sso_clients c ON c.id = a.client_id
                 WHERE a.id = $1 AND a.kind = 'code' AND a.status = 'pending' AND a.expires_at > now()"
            ),
            &[&id],
        )
        .await?;
    let Some(row) = row else {
        return Err(ApiError::NotFound(
            "this sign-in was finished, or has expired: start it again (aws sso login)".into(),
        ));
    };
    Ok(Json(request_of(&db, row).await?))
}

#[derive(Deserialize, ToSchema)]
struct UserCode {
    /// The code the program shows, as `BCDF-GHJK`.
    user_code: String,
}

/// The device sign-in of a code the program shows, which the signed-in
/// directory user may allow.
#[utoipa::path(post, path = "/sso/device", request_body = UserCode, responses(
    (status = 200, body = SignInRequest),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn device_sign_in_request(
    State(console): State<Arc<Console>>,
    signed: Signed,
    Json(body): Json<UserCode>,
) -> Result<Json<SignInRequest>, ApiError> {
    // Codes are short: guessing them is limited as signing in is.
    if !console.app.console.sign_ins.allow(user_address(&signed)) {
        return Err(ApiError::TooManyRequests(
            "too many codes tried; wait a minute".into(),
        ));
    }
    let not_found = || {
        ApiError::NotFound("no sign-in is waiting with that code: check it, or start again".into())
    };
    let Some(code) = normalize_user_code(&body.user_code) else {
        return Err(not_found());
    };
    let db = console.app.pool.get().await?;
    let row = db
        .query_opt_cached(
            &format!(
                "SELECT {REQUEST_COLUMNS} FROM sso_authorizations a JOIN sso_clients c ON c.id = a.client_id
                 WHERE a.user_code = $1 AND a.kind = 'device' AND a.status = 'pending' AND a.expires_at > now()"
            ),
            &[&code],
        )
        .await?;
    let Some(row) = row else {
        return Err(not_found());
    };
    Ok(Json(request_of(&db, row).await?))
}

/// What a limit keyed by a signed-in user is keyed by: an address made of
/// its ID, which no client has (the limiter keys by address).
fn user_address(signed: &Signed) -> IpAddr {
    let bytes = signed.session.user_id.as_bytes();
    let mut v6 = [0u8; 16];
    v6[..8].copy_from_slice(&bytes[..8]);
    IpAddr::V6(std::net::Ipv6Addr::from(v6))
}

#[derive(Deserialize, ToSchema)]
struct Decision {
    /// Whether to allow it.
    allow: bool,
}

#[derive(Serialize, ToSchema)]
struct Decided {
    /// Where to send the browser on to, for a sign-in of a browser's (the
    /// program's address on this computer, with the code, or why not).
    redirect: Option<String>,
}

/// Allows a sign-in of the AWS CLI or an SDK, as the signed-in directory
/// user, or denies it.
#[utoipa::path(post, path = "/sso/requests/{id}", params(("id" = String, Path)), request_body = Decision, responses(
    (status = 200, body = Decided),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn decide(
    State(console): State<Arc<Console>>,
    signed: Signed,
    Path(id): Path<String>,
    Json(body): Json<Decision>,
) -> Result<Json<Decided>, ApiError> {
    let id = request_id(&id)?;
    let db = console.app.pool.get().await?;
    let session = &signed.session;
    if body.allow
        && identity_center::eligible(&db, &session.account_id, session.user_id)
            .await?
            .is_empty()
    {
        return Err(ApiError::Forbidden(
            "no permission set is assigned to you: ask an administrator for one".into(),
        ));
    }
    let (code, code_hash) = token()?;
    let row = db
        .query_opt_cached(
            "UPDATE sso_authorizations
             SET status = CASE WHEN $2 THEN 'approved' ELSE 'denied' END,
                 account_id = $3, user_id = $4,
                 code_hash = CASE WHEN kind = 'code' AND $2 THEN $5::bytea END,
                 expires_at = CASE WHEN kind = 'code' THEN least(expires_at, now() + make_interval(secs => $6)) ELSE expires_at END
             WHERE id = $1 AND status = 'pending' AND expires_at > now()
             RETURNING kind, redirect_uri, state",
            &[&id, &body.allow, &session.account_id, &session.user_id, &code_hash, &secs(CODE_TTL)],
        )
        .await?;
    let Some(row) = row else {
        return Err(ApiError::NotFound(
            "this sign-in was finished, or has expired: start it again".into(),
        ));
    };
    eprintln!(
        "access portal: directory user {} {} sign-in {id}",
        session.user_name,
        if body.allow { "allowed" } else { "denied" }
    );
    let kind: String = row.get(0);
    if kind != "code" {
        return Ok(Json(Decided { redirect: None }));
    }
    let redirect_uri: String = row.get(1);
    let state: Option<String> = row.get(2);
    let mut params: Vec<(&str, &str)> = if body.allow {
        vec![("code", code.as_str())]
    } else {
        vec![
            ("error", "access_denied"),
            ("error_description", "you denied the sign-in"),
        ]
    };
    if let Some(state) = state.as_deref().filter(|s| !s.is_empty()) {
        params.push(("state", state));
    }
    Ok(Json(Decided {
        redirect: Some(with_query(&redirect_uri, &params)),
    }))
}

/// Removes what has expired: registrations (and their sign-ins and
/// grants), sign-ins, grants and access tokens.
pub async fn reap(db: &Object) -> anyhow::Result<u64> {
    let mut reaped = 0;
    for table in [
        "sso_access_tokens",
        "sso_authorizations",
        "sso_grants",
        "sso_clients",
    ] {
        reaped += db
            .execute_cached(
                &format!("DELETE FROM {table} WHERE expires_at <= now()"),
                &[],
            )
            .await?;
    }
    Ok(reaped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_codes_are_read_as_typed() {
        let code = user_code().unwrap();
        assert_eq!(code.len(), 9);
        assert_eq!(normalize_user_code(&code), Some(code.clone()));
        assert_eq!(
            normalize_user_code(&code.to_ascii_lowercase().replace('-', " ")),
            Some(code)
        );
        assert_eq!(normalize_user_code("bcdf ghjk"), Some("BCDF-GHJK".into()));
        for bad in ["", "BCDF-GHJ", "BCDF-GHJKL", "ABCD-EFGH", "BCDF-GHJ1"] {
            assert_eq!(normalize_user_code(bad), None, "{bad}");
        }
    }

    #[test]
    fn redirects_go_to_loopback_addresses_only() {
        let registered = vec!["http://127.0.0.1/oauth/callback".to_owned()];
        assert!(registered_redirect(
            &registered,
            "http://127.0.0.1:41709/oauth/callback"
        ));
        assert!(registered_redirect(
            &registered,
            "http://127.0.0.1/oauth/callback"
        ));
        for bad in [
            "http://127.0.0.1:41709/other",
            "http://localhost:41709/oauth/callback",
            "https://127.0.0.1:41709/oauth/callback",
            "http://127.0.0.1:41709/oauth/callback?x=1",
            "http://evil.example.com/oauth/callback",
            "http://127.0.0.1@evil.example.com/oauth/callback",
        ] {
            assert!(!registered_redirect(&registered, bad), "{bad}");
        }
        let fixed = vec!["http://localhost:8080/cb".to_owned()];
        assert!(registered_redirect(&fixed, "http://localhost:8080/cb"));
        assert!(!registered_redirect(&fixed, "http://localhost:8081/cb"));
        for bad in [
            "https://127.0.0.1/cb",
            "http://10.0.0.1/cb",
            "http://127.0.0.1/cb#x",
            "http://user@127.0.0.1/cb",
        ] {
            assert!(loopback(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn pages_go_by_offsets() {
        let query = |next: Option<&str>, max: Option<&str>| Page {
            next_token: next.map(str::to_owned),
            max_result: max.map(str::to_owned),
            account_id: None,
            role_name: None,
        };
        let items: Vec<u32> = (0..5).collect();
        assert_eq!(
            page(items.clone(), &query(None, None)).unwrap(),
            (items.clone(), None)
        );
        assert_eq!(
            page(items.clone(), &query(None, Some("2"))).unwrap(),
            (vec![0, 1], Some("2".into()))
        );
        assert_eq!(
            page(items.clone(), &query(Some("4"), Some("2"))).unwrap(),
            (vec![4], None)
        );
        assert!(page(items.clone(), &query(Some("x"), None)).is_err());
        assert!(page(items, &query(None, Some("0"))).is_err());
    }
}

#[cfg(test)]
mod e2e_tests;
