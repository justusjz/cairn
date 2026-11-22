//! The console: Cairn's web UI, which people sign in to as directory users
//! (Identity Center's: with passkeys, as users of Cairn's own directory, or
//! at an OIDC provider), on its own listener (`--listen-console`) and
//! origin (`--console-url`). They act as the permission set they pick, in
//! one of the organization's accounts, managing its buckets, objects and
//! IAM there, and operators (whose policies allow `cairn:` actions) watch
//! and run the cluster. The root user gets in with a link from a node, to
//! get back in. See `plans/console.md`.
//!
//! Not on the S3 port: objects are served from the S3 origin with whatever
//! `Content-Type` they were given, so an HTML object there could run script
//! in the console's origin and use its sessions. Not on the peer port, which
//! is private and has no sign-in. Cairn doesn't terminate TLS: a proxy in
//! front does; `http://localhost` works too, for trying it.
//!
//! A session is a random token in a `__Host-` cookie (Secure, HttpOnly,
//! SameSite=Strict), kept in the database as its hash (see `store`), so any
//! node behind the load balancer serves it. Every request that changes
//! something must come from the console's own origin (`Origin`), with the
//! `x-cairn-ui` header, which a cross-site form can't send.
//!
//! The UI (`ui/`) is built into `ui/dist`, embedded in the binary, and
//! served from the root here (see `web`). Its API is under `/api`: signing
//! in and the user's own passkeys (`api`), and what the session's identity
//! manages (`manage`), as that identity (`actor`).

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{FromRequestParts, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};

use std::net::SocketAddr;

use axum::extract::ConnectInfo;

use crate::{App, users::Principal};

pub(crate) mod actor;
mod api;
mod batch;
pub mod cbor;
mod cluster;
mod directory;
mod grants;
mod groups;
mod iam;
mod inventory;
mod limit;
mod manage;
pub mod oidc;
mod organizations;
mod policy_catalog;
pub mod portal;
mod replication;
mod settings;
mod sns;
mod sso;
pub mod store;
mod switch;
mod tables;
mod templates;
pub(crate) mod web;
pub mod webauthn;

use actor::Actor;
use web::ApiError;

pub use api::openapi;
use webauthn::Party;

/// The session cookie's name. `__Host-`: browsers only take it from a secure
/// origin, for exactly this host, for every path.
const COOKIE: &str = "__Host-cairn-session";
/// The header every request that changes something must carry.
const CSRF_HEADER: &str = "x-cairn-ui";

/// What the console's API keeps on every node, whether or not it serves the
/// console itself (part of [`App`]).
pub struct Shared {
    /// The last `/storage` report, and when it was made. It takes scans of
    /// whole tables, so every page polling it shares one report a while.
    storage: tokio::sync::Mutex<Option<(std::time::Instant, manage::Storage)>>,
    /// The console's origin, if this node serves it: setup links are made
    /// from it.
    origin: Option<String>,
    /// How often each client may start signing in (see `limit`).
    sign_ins: limit::Limiter,
}

impl Shared {
    pub fn new(origin: Option<String>) -> Shared {
        Shared {
            storage: tokio::sync::Mutex::default(),
            origin,
            sign_ins: limit::Limiter::default(),
        }
    }

    /// The console's origin, if this node serves it.
    pub fn origin(&self) -> Option<&str> {
        self.origin.as_deref()
    }
}

/// What the console's handlers have.
pub struct Console {
    pub app: Arc<App>,
    /// The console's RP ID and origin, from its URL.
    pub party: Party,
}

/// Where the console is, from `--console-url`: its origin (scheme, host and
/// a port that isn't the scheme's), and its host as the RP ID, which
/// WebAuthn requires to be a domain (no IP address). HTTPS, but for
/// `localhost`, which browsers treat as secure.
pub fn parse_url(text: &str) -> Result<Party, String> {
    let uri: Uri = text
        .parse()
        .map_err(|e| format!("{text:?} isn't a URL: {e}"))?;
    let (Some(scheme), Some(host)) = (uri.scheme_str(), uri.host()) else {
        return Err(format!("{text:?} isn't an absolute URL"));
    };
    let host = host.to_ascii_lowercase();
    if !matches!(uri.path(), "" | "/") || uri.query().is_some() {
        return Err(
            "the console's URL must be just an origin, served from its root (no path)".into(),
        );
    }
    if host.starts_with('[') || host.parse::<std::net::IpAddr>().is_ok() {
        return Err("passkeys need the console to have a domain name, not an IP address".into());
    }
    let localhost = host == "localhost" || host.ends_with(".localhost");
    match scheme {
        "https" => {}
        "http" if localhost => {}
        _ => return Err("the console must be served over HTTPS (or be on localhost)".into()),
    }
    let origin = match uri.port_u16() {
        Some(443) if scheme == "https" => format!("https://{host}"),
        Some(80) if scheme == "http" => format!("http://{host}"),
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    };
    Ok(Party { id: host, origin })
}

/// The most of a body the sign-in API (`api`) reads: a passkey's
/// attestation, with its certificates, takes a few KiB.
const MAX_SIGN_IN_BODY: usize = 64 * 1024;

/// The console.
pub fn router(console: Arc<Console>) -> Router {
    // Signing in and enrolling take small JSON documents, before anyone is
    // known: no more is read of them.
    let (api, _) = api::router().split_for_parts();
    let api = api
        .layer(middleware::from_fn_with_state(
            console.clone(),
            limit_sign_ins,
        ))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_SIGN_IN_BODY));
    // What the session's identity manages, as that identity.
    let (managed, _) = manage::router().split_for_parts();
    let managed = managed
        .layer(middleware::from_fn_with_state(console.clone(), as_user))
        .with_state(console.app.clone());
    let api = api
        .merge(managed)
        .fallback(|| async { ApiError::NotFound("no such API route".into()) })
        .layer(middleware::from_fn_with_state(
            console.clone(),
            require_same_origin,
        ))
        .layer(middleware::map_response(|mut resp: Response| async {
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }));
    // Identity Center's access portal for the AWS CLI and SDKs, at the root,
    // as they expect it (see `portal`).
    let portal = portal::protocol_router()
        .layer(axum::extract::DefaultBodyLimit::max(portal::MAX_BODY))
        .layer(middleware::map_response(|mut resp: Response| async {
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }));
    Router::new()
        .nest("/api", api)
        .merge(portal)
        .route("/api/openapi.json", get(|| async { Json(openapi()) }))
        // SNS's unsigned URLs of subscriptions made here (see `sns`).
        .route(sns::UNSIGNED_PREFIX, get(sns_unsigned))
        .route(&format!("{}/", sns::UNSIGNED_PREFIX), get(sns_unsigned))
        .route(
            &format!("{}/{{file}}", sns::UNSIGNED_PREFIX),
            get(sns_unsigned),
        )
        .fallback(static_file)
        .layer(middleware::map_response(web::security_headers))
        .with_state(console)
}

/// SNS's confirmation, unsubscription and certificate URLs, under the
/// console's origin (see `sns::UNSIGNED_PREFIX`), as the S3 endpoint
/// answers them.
async fn sns_unsigned(State(console): State<Arc<Console>>, req: Request) -> Response {
    let (parts, _) = req.into_parts();
    let path = parts
        .uri
        .path()
        .strip_prefix(sns::UNSIGNED_PREFIX)
        .filter(|p| !p.is_empty())
        .unwrap_or("/");
    let path_and_query = match parts.uri.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_owned(),
    };
    let Ok(uri) = path_and_query.parse::<hyper::Uri>() else {
        return ApiError::NotFound("no such SNS URL".into()).into_response();
    };
    let wanted = hyper::Request::get(uri.clone()).body(()).expect("a GET");
    if !crate::sns::wants_unsigned(&wanted) {
        return ApiError::NotFound("no such SNS URL".into()).into_response();
    }
    let response = crate::sns::handle_unsigned(&console.app, &uri, &parts.headers).await;
    response.map(axum::body::Body::new)
}

/// Refuses a start of signing in or enrolling (which writes a row before
/// anyone is known) to a client that started too many lately (see `limit`).
async fn limit_sign_ins(State(console): State<Arc<Console>>, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    let starts = path.ends_with("/login/options")
        || path.ends_with("/enroll/options")
        || path.ends_with("/root/sign-in")
        || (path.contains("/oidc/") && path.ends_with("/start"));
    if req.method() == Method::POST && starts {
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip());
        let client =
            crate::s3::access::client_address(req.headers(), peer, &console.app.trusted_proxies);
        if let Some(client) = client
            && !console.app.console.sign_ins.allow(client)
        {
            return ApiError::TooManyRequests("too many sign-ins from here; wait a minute".into())
                .into_response();
        }
    }
    next.run(req).await
}

/// Refuses requests that change something unless they come from the
/// console's own page: its origin, with the header.
async fn require_same_origin(
    State(console): State<Arc<Console>>,
    req: Request,
    next: Next,
) -> Response {
    if !matches!(*req.method(), Method::GET | Method::HEAD) {
        let origin = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|o| o.to_str().ok());
        if origin != Some(console.party.origin.as_str()) {
            return ApiError::Forbidden(format!(
                "requests must come from {}",
                console.party.origin
            ))
            .into_response();
        }
        if !req.headers().contains_key(CSRF_HEADER) {
            return ApiError::Forbidden("missing x-cairn-ui header".into()).into_response();
        }
    }
    next.run(req).await
}

/// Has the request act as its session's user (see `actor`), or
/// answers 401 without one.
async fn as_user(State(console): State<Arc<Console>>, mut req: Request, next: Next) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    let (method, headers) = (req.method().clone(), req.headers().clone());
    let query = req.uri().query().unwrap_or("").to_owned();
    match user_of(&console, method, headers, query, peer).await {
        Ok(user) => {
            req.extensions_mut().insert(Actor(Arc::new(user)));
            next.run(req).await
        }
        Err(e) => e.into_response(),
    }
}

/// Who a request's session acts as: who it was signed in as, or a session
/// of the role it switched to (see `switch`).
async fn user_of(
    console: &Console,
    method: Method,
    headers: HeaderMap,
    query: String,
    peer: Option<std::net::IpAddr>,
) -> Result<actor::User, ApiError> {
    let token =
        session_token(&headers).ok_or_else(|| ApiError::Unauthorized("sign in first".into()))?;
    let base = signed_in_user_of(console, method, headers, query, peer).await?;
    switch::apply(&console.app.pool.get().await?, &token, base).await
}

/// Who a request's session was signed in as: a directory user's permission
/// set's role's session, or the account's root user.
async fn signed_in_user_of(
    console: &Console,
    method: Method,
    headers: HeaderMap,
    query: String,
    peer: Option<std::net::IpAddr>,
) -> Result<actor::User, ApiError> {
    let unauthorized = || ApiError::Unauthorized("sign in first".into());
    let token = session_token(&headers).ok_or_else(unauthorized)?;
    let client = console.app.pool.get().await?;
    #[cfg(test)]
    if let Some(user) = e2e::test_session(&client, &token, &method, &headers, &query, peer).await {
        return Ok(user);
    }
    if let Some(session) = store::directory_session(&client, &token).await? {
        return directory::user(&client, &session, method, headers, query, peer).await;
    }
    let root = store::root_session(&client, &token)
        .await?
        .ok_or_else(unauthorized)?;
    Ok(root_user(&root, method, headers, query, peer))
}

/// The account's root user, as its session `root` acts, for a request
/// (`method`, `headers`, `query`, from `peer`). It was signed in with a
/// link, no second factor: `aws:MultiFactorAuthPresent` is false.
fn root_user(
    root: &store::RootSession,
    method: Method,
    headers: HeaderMap,
    query: String,
    peer: Option<std::net::IpAddr>,
) -> actor::User {
    let principal = Principal::root(&root.account_id);
    actor::User {
        principal,
        account: root.account_id.clone(),
        method,
        headers,
        query,
        peer,
        mfa_age: None,
    }
}

/// A file of the console's UI, or else its page.
async fn static_file(method: Method, uri: Uri) -> Response {
    if !matches!(method, Method::GET | Method::HEAD) {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    web::serve_asset(uri.path())
}

/// The session token in a request's cookies.
fn session_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| {
            c.trim()
                .strip_prefix(COOKIE)?
                .strip_prefix('=')
                .map(str::to_owned)
        })
}

/// A `Set-Cookie` that starts a directory user's session.
fn session_cookie(token: &str) -> HeaderValue {
    cookie(token, store::SESSION_TTL)
}

/// A `Set-Cookie` that starts a session of the account's root user.
fn root_cookie(token: &str) -> HeaderValue {
    cookie(token, store::ROOT_SESSION_TTL)
}

fn cookie(token: &str, ttl: std::time::Duration) -> HeaderValue {
    let max_age = ttl.as_secs();
    HeaderValue::from_str(&format!(
        "{COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={max_age}"
    ))
    .expect("tokens are URL-safe base64")
}

/// A `Set-Cookie` that ends one.
fn cleared_cookie() -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"
    ))
    .unwrap()
}

/// The session of a user of Cairn's own directory, which manages its
/// passkeys. Handlers that take it answer 401 without a session, and 403 to
/// the root user and to users of identity sources, which have none.
pub(crate) struct PasskeyHolder(pub store::DirectorySession);

impl FromRequestParts<Arc<Console>> for PasskeyHolder {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        console: &Arc<Console>,
    ) -> Result<Self, ApiError> {
        let unauthorized = || ApiError::Unauthorized("sign in first".into());
        let token = session_token(&parts.headers).ok_or_else(unauthorized)?;
        let client = console.app.pool.get().await?;
        match store::directory_session(&client, &token).await? {
            Some(session) if session.provider.is_none() => Ok(PasskeyHolder(session)),
            Some(_) => Err(ApiError::Forbidden(
                "you sign in at your identity source: you have no passkeys here".into(),
            )),
            None if store::root_session(&client, &token).await?.is_some() => {
                Err(ApiError::Forbidden(
                    "the root user has no passkeys: it signs in with a link from a node".into(),
                ))
            }
            None => Err(unauthorized()),
        }
    }
}

/// A directory user's signed-in session: handlers that take it answer 401
/// without a session, and 403 to any other.
pub(crate) struct DirectorySigned {
    pub session: store::DirectorySession,
    pub token: String,
}

impl FromRequestParts<Arc<Console>> for DirectorySigned {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        console: &Arc<Console>,
    ) -> Result<Self, ApiError> {
        let token = session_token(&parts.headers)
            .ok_or_else(|| ApiError::Unauthorized("sign in first".into()))?;
        match store::directory_session(&console.app.pool.get().await?, &token).await? {
            Some(session) => Ok(DirectorySigned { session, token }),
            None => Err(ApiError::Forbidden(
                "only a directory user's session has permission sets".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_https_origins_and_localhost() {
        let party = parse_url("https://Console.Example.com/").unwrap();
        assert_eq!(
            (party.id.as_str(), party.origin.as_str()),
            ("console.example.com", "https://console.example.com")
        );
        let party = parse_url("https://console.example.com:443").unwrap();
        assert_eq!(party.origin, "https://console.example.com");
        let party = parse_url("https://console.example.com:8443").unwrap();
        assert_eq!(party.origin, "https://console.example.com:8443");
        let party = parse_url("http://localhost:9080").unwrap();
        assert_eq!(
            (party.id.as_str(), party.origin.as_str()),
            ("localhost", "http://localhost:9080")
        );
        for bad in [
            "http://console.example.com",
            "https://10.0.0.1",
            "https://[::1]",
            "https://console.example.com/console",
            "console.example.com",
            "ftp://localhost",
        ] {
            assert!(parse_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn finds_the_session_cookie() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("a=b; __Host-cairn-session=tok; c=d"),
        );
        assert_eq!(session_token(&headers).as_deref(), Some("tok"));
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("__Host-cairn-sessionx=tok"),
        );
        assert_eq!(session_token(&headers), None);
    }
}

#[cfg(test)]
mod e2e {
    use axum::http::Request;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::webauthn::tests::{Authenticator, party};
    use super::*;
    use crate::users;

    /// The console's spec, as the UI's types are generated from it.
    /// `CAIRN_UPDATE_OPENAPI=1 cargo test openapi` updates it.
    #[test]
    fn openapi_json_is_up_to_date() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/ui/openapi.json");
        let spec = openapi().to_pretty_json().unwrap() + "\n";
        if std::env::var_os("CAIRN_UPDATE_OPENAPI").is_some() {
            std::fs::write(path, &spec).unwrap();
            return;
        }
        let committed = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            committed == spec,
            "ui/openapi.json is out of date: run `CAIRN_UPDATE_OPENAPI=1 cargo test openapi`, \
             then `npm run gen` in ui/"
        );
    }

    /// Every operation has an ID of its own: the UI's client is generated
    /// by them, and two of a name merge into one's types.
    #[test]
    fn operations_have_ids_of_their_own() {
        let spec = serde_json::to_value(openapi()).unwrap();
        let mut seen = std::collections::HashSet::new();
        for item in spec["paths"].as_object().unwrap().values() {
            for operation in item.as_object().unwrap().values() {
                if let Some(id) = operation.get("operationId").and_then(Value::as_str) {
                    assert!(seen.insert(id.to_owned()), "two operations are named {id}");
                }
            }
        }
    }

    /// The spec is the sign-in API's and `manage`'s, merged: a schema of one
    /// may share a name with one of the other only if it's the same (as
    /// `ErrorBody` is), as it would replace it.
    #[test]
    fn the_apis_schemas_have_names_of_their_own() {
        let schemas =
            |spec: utoipa::openapi::OpenApi| spec.components.map(|c| c.schemas).unwrap_or_default();
        let sign_in = schemas(api::router().split_for_parts().1);
        let managed = schemas(manage::router().split_for_parts().1);
        for (name, schema) in &sign_in {
            if let Some(other) = managed.get(name) {
                let json = |s| serde_json::to_value(s).unwrap();
                assert_eq!(json(schema), json(other), "two schemas named {name}");
            }
        }
    }

    /// A browser on the console's page, signed in once `cookie` is set.
    pub(super) struct Browser {
        console: Arc<Console>,
        cookie: Option<String>,
        origin: String,
    }

    impl Browser {
        /// Sends a request with a JSON body, as the page does: its status,
        /// and its body as JSON (`null` if it isn't).
        pub(super) async fn send(
            &mut self,
            method: &str,
            path: &str,
            body: Option<Value>,
        ) -> (StatusCode, Value) {
            let (status, _, body) = self.request(method, path, body).await;
            (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
        }

        /// Sends a request with a JSON body: its status, headers and body.
        pub(super) async fn request(
            &mut self,
            method: &str,
            path: &str,
            body: Option<Value>,
        ) -> (StatusCode, HeaderMap, Vec<u8>) {
            let mut req = Request::builder()
                .method(method)
                .uri(path)
                .header("origin", &self.origin)
                .header("x-cairn-ui", "1")
                .header("content-type", "application/json");
            if let Some(cookie) = &self.cookie {
                req = req.header("cookie", format!("{COOKIE}={cookie}"));
            }
            let body = body.map(|b| b.to_string()).unwrap_or_default();
            let resp = router(self.console.clone())
                .oneshot(req.body(axum::body::Body::from(body)).unwrap())
                .await
                .unwrap();
            if let Some(set) = resp.headers().get(header::SET_COOKIE) {
                let set = set.to_str().unwrap();
                assert!(set.contains("Secure; HttpOnly; SameSite=Strict"), "{set}");
                let value = set.split(';').next().unwrap().split_once('=').unwrap().1;
                self.cookie = (!value.is_empty()).then(|| value.to_owned());
            }
            let (parts, body) = resp.into_parts();
            let body = body.collect().await.unwrap().to_bytes().to_vec();
            (parts.status, parts.headers, body)
        }
    }

    fn challenge_of(ceremony: &Value) -> Vec<u8> {
        URL_SAFE_NO_PAD
            .decode(ceremony["options"]["challenge"].as_str().unwrap())
            .unwrap()
    }

    fn registration(authenticator: &mut Authenticator, ceremony: &Value, name: &str) -> Value {
        let (client_data, attestation) = authenticator.register(&challenge_of(ceremony));
        json!({
            "challenge_id": ceremony["challenge_id"],
            "name": name,
            "credential": {
                "id": URL_SAFE_NO_PAD.encode(&authenticator.credential_id),
                "client_data_json": URL_SAFE_NO_PAD.encode(client_data),
                "attestation_object": URL_SAFE_NO_PAD.encode(attestation),
            },
        })
    }

    async fn sign_in(
        browser: &mut Browser,
        authenticator: &mut Authenticator,
    ) -> (StatusCode, Value) {
        let (_, ceremony) = browser.send("POST", "/api/login/options", None).await;
        let (client_data, auth_data, sig) = authenticator.assert(&challenge_of(&ceremony));
        let body = json!({
            "challenge_id": ceremony["challenge_id"],
            "credential": {
                "id": URL_SAFE_NO_PAD.encode(&authenticator.credential_id),
                "client_data_json": URL_SAFE_NO_PAD.encode(client_data),
                "authenticator_data": URL_SAFE_NO_PAD.encode(auth_data),
                "signature": URL_SAFE_NO_PAD.encode(sig),
            },
        });
        browser.send("POST", "/api/login", Some(body)).await
    }

    /// The console of node `app`.
    pub(super) fn console_of(app: &Arc<App>) -> Arc<Console> {
        Arc::new(Console {
            app: app.clone(),
            party: party(),
        })
    }

    /// A browser signed in as a new operator `name`: a user with
    /// `CairnOperatorAccess` (the cluster, nothing of the data).
    pub(super) async fn superadmin(console: &Arc<Console>, name: &str) -> Browser {
        let browser = signed_in(console, name, false).await;
        let client = console.app.pool.get().await.unwrap();
        let account = crate::users::account(&client).await.unwrap();
        let arn = crate::managed::aws_arn("CairnOperatorAccess");
        crate::managed::attach(&client, &account, name, &arn, true)
            .await
            .unwrap();
        browser
    }

    /// Sessions that act as IAM users (by token: the user's ID), for tests
    /// of what the console does as a principal, under its policies: no one
    /// signs in as an IAM user (people are directory users), but what a
    /// principal may do is the same, and IAM users' policies are the
    /// quickest to set up. They have MFA, as passkey sessions do.
    static TEST_SESSIONS: std::sync::Mutex<Vec<(String, uuid::Uuid)>> =
        std::sync::Mutex::new(Vec::new());

    /// Who the test session of `token` acts as, while its user exists.
    pub(super) async fn test_session(
        client: &deadpool_postgres::Object,
        token: &str,
        method: &Method,
        headers: &HeaderMap,
        query: &str,
        peer: Option<std::net::IpAddr>,
    ) -> Option<actor::User> {
        let id = TEST_SESSIONS
            .lock()
            .unwrap()
            .iter()
            .find(|(t, _)| t == token)
            .map(|(_, id)| *id)?;
        let principal = Principal::load_user(client, id).await.unwrap()?;
        let account = principal.account.clone();
        let (method, headers, query) = (method.clone(), headers.clone(), query.to_owned());
        Some(actor::User {
            principal,
            account,
            method,
            headers,
            query,
            peer,
            mfa_age: Some(0),
        })
    }

    /// A browser signed in as a new user `name` of the management account
    /// (see `TEST_SESSIONS`).
    pub(super) async fn signed_in(console: &Arc<Console>, name: &str, admin: bool) -> Browser {
        let client = console.app.pool.get().await.unwrap();
        users::create(&client, name, None, admin).await.unwrap();
        let account = crate::users::account(&client).await.unwrap();
        signed_in_as(console, &account, name).await
    }

    /// A browser signed in as user `name` of account `account` (see
    /// `TEST_SESSIONS`).
    pub(super) async fn signed_in_as(console: &Arc<Console>, account: &str, name: &str) -> Browser {
        let client = console.app.pool.get().await.unwrap();
        let id = crate::users::id_of(&client, account, name).await.unwrap();
        let token = uuid::Uuid::new_v4().to_string();
        TEST_SESSIONS.lock().unwrap().push((token.clone(), id));
        Browser {
            console: console.clone(),
            cookie: Some(token),
            origin: party().origin,
        }
    }

    /// An inline policy that allows everything.
    pub(super) const ADMIN: &str =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;

    /// A browser signed in as a new user `name` of Cairn's own directory,
    /// with a passkey (`key`), and permission set `name` assigned to it in
    /// the management account, with `policy` inline: a real session, as
    /// people have them.
    pub(super) async fn directory_user(
        console: &Arc<Console>,
        name: &str,
        policy: &str,
    ) -> (Browser, Authenticator) {
        use crate::identity_center as ic;
        let client = console.app.pool.get().await.unwrap();
        let account = crate::users::account(&client).await.unwrap();
        let profile = json!({});
        let own = ic::OwnUser {
            user_name: name,
            display_name: name,
            email: None,
            profile: &profile,
        };
        let user = ic::create_user(&client, &own).await.unwrap();
        let new = ic::New {
            name,
            description: "",
            session_duration: 3600,
            relay_state: None,
            tags: None,
        };
        let set = ic::create(&client, &account, &new).await.unwrap();
        ic::set_inline_policy(&client, &set, Some(policy))
            .await
            .unwrap();
        ic::assign(&client, &set, &account, ic::PrincipalType::User, user.id)
            .await
            .unwrap()
            .unwrap();
        let token = store::create_setup_link(&client, user.id).await.unwrap();
        let mut browser = Browser {
            console: console.clone(),
            cookie: None,
            origin: party().origin,
        };
        let (_, ceremony) = browser
            .send(
                "POST",
                "/api/enroll/options",
                Some(json!({ "token": token })),
            )
            .await;
        let mut key = Authenticator::ed25519();
        let mut body = registration(&mut key, &ceremony, "Key");
        body["token"] = json!(token);
        let (status, me) = browser.send("POST", "/api/enroll", Some(body)).await;
        assert_eq!(status, StatusCode::OK, "{me}");
        (browser, key)
    }

    impl Browser {
        /// A request with a raw body (an upload).
        async fn upload(&mut self, path: &str, body: &'static [u8]) -> StatusCode {
            let req = Request::builder()
                .method("PUT")
                .uri(path)
                .header("origin", &self.origin)
                .header("x-cairn-ui", "1")
                .header("content-type", "text/plain")
                .header("content-length", body.len())
                .header(
                    "cookie",
                    format!("{COOKIE}={}", self.cookie.as_deref().unwrap_or("")),
                )
                .body(axum::body::Body::from(body))
                .unwrap();
            router(self.console.clone())
                .oneshot(req)
                .await
                .unwrap()
                .status()
        }
    }

    /// The console's buckets and objects are `manage`'s API, as the
    /// signed-in user: what its grants, admin flag and policies allow, and
    /// what a bucket's policy denies it, as over S3.
    #[tokio::test]
    async fn acts_as_the_user_under_its_policies() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = Arc::new(Console {
            app: app.clone(),
            party: party(),
        });
        let client = app.pool.get().await.unwrap();
        let bucket = crate::e2e::BUCKET;

        // Not signed in: nothing.
        let mut nobody = Browser {
            console: console.clone(),
            cookie: None,
            origin: party().origin,
        };
        assert_eq!(
            nobody.send("GET", "/api/buckets", None).await.0,
            StatusCode::UNAUTHORIZED
        );

        // An admin creates buckets, and sees all of its account's.
        let mut admin = signed_in(&console, "boss", true).await;
        assert_eq!(
            admin
                .send("POST", "/api/buckets", Some(json!({ "name": "made-here" })))
                .await
                .0,
            StatusCode::CREATED
        );
        let (status, buckets) = admin.send("GET", "/api/buckets", None).await;
        assert_eq!(status, StatusCode::OK);
        let names: Vec<_> = buckets
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&bucket) && names.contains(&"made-here"),
            "{names:?}"
        );
        // And, with `AdministratorAccess`, reads objects too, as AWS's do.
        assert_eq!(
            admin
                .send("GET", &format!("/api/buckets/{bucket}/objects"), None)
                .await
                .0,
            StatusCode::OK
        );

        // A user without grants or policies may do nothing.
        let mut none = signed_in(&console, "none", false).await;
        let (_, buckets) = none.send("GET", "/api/buckets", None).await;
        assert_eq!(buckets, json!([]));
        let (status, err) = none
            .send("GET", &format!("/api/buckets/{bucket}/objects"), None)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            err["error"].as_str().unwrap(),
            format!(
                "User: arn:aws:iam::{}:user/none is not authorized to perform: s3:ListBucket on resource: \"arn:aws:s3:::{bucket}\" because no identity-based policy allows the s3:ListBucket action",
                users::account(&client).await.unwrap()
            )
        );

        // A reader sees only its bucket, lists and downloads, but can't write.
        let mut reader = signed_in(&console, "reader", false).await;
        users::grant(
            &client,
            &crate::users::account(&client).await.unwrap(),
            "reader",
            bucket,
            &[users::Permission::Read],
        )
        .await
        .unwrap();
        let (_, buckets) = reader.send("GET", "/api/buckets", None).await;
        let names: Vec<_> = buckets
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, [bucket]);
        assert_eq!(
            reader
                .upload(&format!("/api/buckets/{bucket}/object?key=r.txt"), b"no")
                .await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            reader
                .send("POST", "/api/buckets", Some(json!({ "name": "nope-here" })))
                .await
                .0,
            StatusCode::FORBIDDEN
        );

        // A writer uploads; the reader then lists and reads it.
        let mut writer = signed_in(&console, "writer", false).await;
        users::grant(
            &client,
            &crate::users::account(&client).await.unwrap(),
            "writer",
            bucket,
            &[users::Permission::Write],
        )
        .await
        .unwrap();
        let path = format!("/api/buckets/{bucket}/object?key=dir%2Fhello.txt");
        assert_eq!(writer.upload(&path, b"hello").await, StatusCode::NO_CONTENT);
        let (status, listing) = reader
            .send(
                "GET",
                &format!("/api/buckets/{bucket}/objects?prefix=dir%2F"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{listing}");
        assert_eq!(listing["entries"][0]["key"], "dir/hello.txt");
        assert_eq!(listing["entries"][0]["size"], 5);
        let (status, info) = reader
            .send(
                "GET",
                &format!("/api/buckets/{bucket}/object?key=dir%2Fhello.txt"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{info}");
        // Not where it's stored: that's the cluster's (`cairn:`).
        assert_eq!(info["versions"][0]["parts"], Value::Null);
        let req = Request::builder()
            .uri(format!(
                "/api/buckets/{bucket}/download?key=dir%2Fhello.txt"
            ))
            .header(
                "cookie",
                format!("{COOKIE}={}", reader.cookie.as_deref().unwrap()),
            )
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router(console.clone()).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["content-security-policy"], "sandbox");
        assert!(
            resp.headers()["content-disposition"]
                .to_str()
                .unwrap()
                .starts_with("attachment")
        );
        assert_eq!(
            &resp.into_body().collect().await.unwrap().to_bytes()[..],
            b"hello"
        );

        // A bucket policy's Deny wins over the writer's grant.
        let account = users::account(&client).await.unwrap();
        let deny = format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Principal":{{"AWS":"arn:aws:iam::{account}:user/writer"}},"Action":"s3:DeleteObject","Resource":"arn:aws:s3:::{bucket}/*"}}]}}"#
        );
        let (status, err) = admin
            .send(
                "PUT",
                &format!("/api/buckets/{bucket}/policy"),
                Some(json!({ "document": deny })),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
        let delete = format!("/api/buckets/{bucket}/object?key=dir%2Fhello.txt");
        let (status, err) = writer.send("DELETE", &delete, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            err["error"]
                .as_str()
                .unwrap()
                .ends_with("with an explicit deny in a resource-based policy"),
            "{err}"
        );
        assert_eq!(
            admin
                .send("DELETE", &format!("/api/buckets/{bucket}/policy"), None)
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        // The grant is the writer's own (managed) policy: it stays.
        assert_eq!(
            writer.send("DELETE", &delete, None).await.0,
            StatusCode::NO_CONTENT
        );

        // Versioning, as the admin may set it.
        let path = format!("/api/buckets/{bucket}/versioning");
        assert_eq!(
            writer
                .send("PUT", &path, Some(json!({ "status": "Enabled" })))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            admin
                .send("PUT", &path, Some(json!({ "status": "Enabled" })))
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        let (_, buckets) = admin.send("GET", "/api/buckets", None).await;
        let ours = buckets
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["name"] == bucket)
            .unwrap();
        assert_eq!(ours["versioning"], "enabled");

        // The cluster is its operators': `AdministratorAccess` is everything.
        assert_eq!(
            admin.send("GET", "/api/cluster", None).await.0,
            StatusCode::OK
        );
        assert_eq!(
            writer.send("GET", "/api/cluster", None).await.0,
            StatusCode::FORBIDDEN
        );

        // Users, as IAM's actions: the admin (AdministratorAccess) manages
        // its account's; a user without IAM permissions may do none of it.
        let (status, err) = writer.send("GET", "/api/users", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            err["error"].as_str().unwrap().contains("iam:ListUsers"),
            "{err}"
        );
        let new_user = json!({ "name": "made-in-console" });
        assert_eq!(
            writer
                .send("POST", "/api/users", Some(new_user.clone()))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        let (status, made) = admin.send("POST", "/api/users", Some(new_user)).await;
        assert_eq!(status, StatusCode::CREATED, "{made}");
        let (_, users) = admin.send("GET", "/api/users", None).await;
        let names: Vec<_> = users
            .as_array()
            .unwrap()
            .iter()
            .map(|u| u["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"made-in-console") && names.contains(&"writer"),
            "{names:?}"
        );
        // Made with policies and in groups, all or nothing: each checked as
        // IAM's AttachUserPolicy and AddUserToGroup.
        let administrator = crate::managed::aws_arn(crate::managed::ADMINISTRATOR_ACCESS);
        assert_eq!(
            admin
                .send("POST", "/api/groups", Some(json!({ "name": "ops" })))
                .await
                .0,
            StatusCode::CREATED
        );
        let ready = json!({ "name": "made-ready", "policies": [administrator], "groups": ["ops"] });
        assert_eq!(
            writer
                .send("POST", "/api/users", Some(ready.clone()))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        let (status, made) = admin.send("POST", "/api/users", Some(ready)).await;
        assert_eq!(status, StatusCode::CREATED, "{made}");
        let account = crate::users::account(&client).await.unwrap();
        let missing = format!("arn:aws:iam::{account}:policy/missing");
        let half = json!({ "name": "made-half", "policies": [missing], "groups": ["ops"] });
        let (status, err) = admin.send("POST", "/api/users", Some(half)).await;
        assert!(status.is_client_error(), "{status} {err}");
        let (_, users) = admin.send("GET", "/api/users", None).await;
        let users = users.as_array().unwrap();
        let made = users.iter().find(|u| u["name"] == "made-ready").unwrap();
        assert_eq!(made["attached"][0]["name"], "AdministratorAccess", "{made}");
        assert_eq!(made["groups"], json!(["ops"]), "{made}");
        assert!(users.iter().all(|u| u["name"] != "made-half"), "{users:?}");
        let (_, groups) = admin.send("GET", "/api/groups", None).await;
        assert_eq!(groups[0]["members"], json!(["made-ready"]), "{groups}");
        let (status, _) = admin
            .send("POST", "/api/users/made-in-console/keys", None)
            .await;
        assert_eq!(status, StatusCode::CREATED);
        // An inline policy may give a user IAM permissions on itself only,
        // as AWS's self-service policies do.
        let own = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:CreateAccessKey","iam:ListUsers"],"Resource":"arn:aws:iam::*:user/${aws:username}"}]}"#;
        let (status, err) = admin
            .send(
                "PUT",
                "/api/users/writer/policies/self",
                Some(json!({ "document": own })),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
        assert_eq!(
            writer.send("POST", "/api/users/writer/keys", None).await.0,
            StatusCode::CREATED
        );
        assert_eq!(
            writer.send("POST", "/api/users/reader/keys", None).await.0,
            StatusCode::FORBIDDEN
        );
        let (status, err) = admin.send("DELETE", "/api/users/stranger", None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(err["error"], "no user named \"stranger\"");
    }

    /// A delegated admin, as AWS's guide has it: the console makes and
    /// manages users under its path only, with the permissions boundary its
    /// policy names, and can't take the boundary off; what it may list is
    /// those users. The admin sees paths, tags and boundaries, and changes
    /// them.
    #[tokio::test]
    async fn a_delegated_admin_makes_users_only_within_its_boundary() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = Arc::new(Console {
            app: app.clone(),
            party: party(),
        });
        let client = app.pool.get().await.unwrap();
        let account = crate::users::account(&client).await.unwrap();
        let mut admin = signed_in(&console, "root-ish", true).await;
        let mut boss = signed_in(&console, "boss", false).await;

        let bound = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:*","s3:ListAllMyBuckets"],"Resource":"*"}]}"#;
        let (status, err) = admin
            .send(
                "POST",
                "/api/policies",
                Some(json!({ "name": "bound", "path": "/bounds/", "document": bound })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{err}");
        let arn = format!("arn:aws:iam::{account}:policy/bounds/bound");
        let users = format!("arn:aws:iam::{account}:user/team/*");
        let delegated = json!({ "Version": "2012-10-17", "Statement": [
            { "Effect": "Allow", "Action": ["iam:CreateUser", "iam:PutUserPolicy", "iam:TagUser"], "Resource": users,
              "Condition": { "StringEquals": { "iam:PermissionsBoundary": arn } } },
            { "Effect": "Allow", "Action": ["iam:ListUsers", "iam:GetUser", "iam:DeleteUser", "iam:CreateAccessKey"], "Resource": users },
            { "Effect": "Deny", "Action": "iam:DeleteUserPermissionsBoundary", "Resource": "*" },
        ]});
        let (status, err) = admin
            .send(
                "PUT",
                "/api/users/boss/policies/delegated",
                Some(json!({ "document": delegated.to_string() })),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
        let (status, err) = admin
            .send(
                "PATCH",
                "/api/users/boss",
                Some(json!({ "path": "/team/" })),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
        let (status, err) = admin
            .send(
                "PUT",
                "/api/users/boss/boundary",
                Some(json!({ "arn": arn })),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{err}");

        // It lists the users under its path (itself), not the others.
        let (status, listed) = boss.send("GET", "/api/users", None).await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        let names: Vec<_> = listed
            .as_array()
            .unwrap()
            .iter()
            .map(|u| u["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["boss"]);
        assert_eq!(
            listed[0]["arn"],
            format!("arn:aws:iam::{account}:user/team/boss")
        );
        assert_eq!(listed[0]["boundary"], arn);

        // Under its path, with the boundary (and tags), not without.
        let new = |name: &str, path: &str, boundary: Option<&str>| json!({ "name": name, "path": path, "boundary": boundary, "tags": [{ "key": "team", "value": "a" }] });
        let (status, err) = boss
            .send("POST", "/api/users", Some(new("made", "/team/", None)))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{err}");
        assert!(
            err["error"].as_str().unwrap().contains("iam:CreateUser"),
            "{err}"
        );
        let (status, _) = boss
            .send("POST", "/api/users", Some(new("made", "/", Some(&arn))))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, err) = boss
            .send(
                "POST",
                "/api/users",
                Some(new("made", "/team/", Some(&arn))),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{err}");
        let (status, err) = boss.send("DELETE", "/api/users/made/boundary", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{err}");
        assert!(
            err["error"]
                .as_str()
                .unwrap()
                .contains("explicit deny in an identity-based policy"),
            "{err}"
        );
        // Its own s3 permissions are its boundary's at most: none.
        let (status, _) = boss
            .send(
                "POST",
                "/api/buckets",
                Some(json!({ "name": "boss-bucket" })),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // The admin sees it all, and changes tags; the boundary stays until
        // it's taken off, and can't be deleted till then.
        let (status, err) = admin
            .send(
                "PUT",
                "/api/users/made/tags",
                Some(json!({ "tags": [{ "key": "Team", "value": "b" }] })),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
        let (_, listed) = admin.send("GET", "/api/users", None).await;
        let made = listed
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["name"] == "made")
            .unwrap();
        assert_eq!(made["path"], "/team/");
        assert_eq!(made["boundary"], arn);
        assert_eq!(made["tags"], json!([{ "key": "Team", "value": "b" }]));
        let (_, policies) = admin.send("GET", "/api/policies", None).await;
        let p = policies
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["arn"] == arn)
            .unwrap();
        assert_eq!(p["bounds"], json!(["boss", "made"]));
        let (status, _) = admin.send("DELETE", "/api/policies/bound", None).await;
        assert_eq!(status, StatusCode::CONFLICT);
        let (status, _) = admin
            .send("PATCH", "/api/users/made", Some(json!({ "name": "BOSS" })))
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "names are unique regardless of case"
        );
    }

    /// A bucket policy that denies everyone denies its admins too, as in
    /// AWS: the command line on a node takes it off (or the root user: see
    /// `the_root_user_gets_back_in`). Deleting a user ends the sessions
    /// acting as it.
    #[tokio::test]
    async fn a_policy_that_denies_everyone_takes_the_command_line() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = Arc::new(Console {
            app: app.clone(),
            party: party(),
        });
        let client = app.pool.get().await.unwrap();
        let mut admin = signed_in(&console, "boss", true).await;
        assert_eq!(
            admin
                .send(
                    "POST",
                    "/api/buckets",
                    Some(json!({ "name": "locked-data" }))
                )
                .await
                .0,
            StatusCode::CREATED
        );
        let deny = r#"{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::locked-data","arn:aws:s3:::locked-data/*"]}]}"#;
        let (status, err) = admin
            .send(
                "PUT",
                "/api/buckets/locked-data/policy",
                Some(json!({ "document": deny })),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
        assert_eq!(
            admin
                .send("GET", "/api/buckets/locked-data/objects", None)
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            admin
                .send("DELETE", "/api/buckets/locked-data/policy", None)
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        let gone = crate::s3::buckets::policy::set(&client, "locked-data", None).await;
        assert!(gone.is_ok());
        assert_eq!(
            admin
                .send("GET", "/api/buckets/locked-data/objects", None)
                .await
                .0,
            StatusCode::OK
        );
        // An account that doesn't exist is no principal.
        let policy = r#"{"Statement":[{"Effect":"Allow","Principal":{"AWS":"999999999999"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::locked-data/*"}]}"#;
        let (status, err) = admin
            .send(
                "PUT",
                "/api/buckets/locked-data/policy",
                Some(json!({ "document": policy })),
            )
            .await;
        assert_eq!(
            (status, err["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("Invalid principal in policy"))
        );

        let mut dora = signed_in(&console, "dora", false).await;
        assert_eq!(dora.send("GET", "/api/me", None).await.0, StatusCode::OK);
        users::delete(
            &client,
            &crate::users::account(&client).await.unwrap(),
            "dora",
        )
        .await
        .unwrap();
        assert_eq!(
            dora.send("GET", "/api/me", None).await.0,
            StatusCode::UNAUTHORIZED
        );
    }

    /// The account's root user signs in only with a link the command line
    /// makes, once: no identity policy restricts it (a boundary, a group's
    /// deny), a bucket policy that denies everyone denies it too, but never
    /// its own getting, setting or deleting. It has no passkeys to manage,
    /// no MFA, and signs out as anyone does.
    #[tokio::test]
    async fn the_root_user_gets_back_in() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = Arc::new(Console {
            app: app.clone(),
            party: party(),
        });
        let client = app.pool.get().await.unwrap();
        let account = crate::users::account(&client).await.unwrap();
        let mut admin = signed_in(&console, "boss", true).await;
        assert_eq!(
            admin
                .send(
                    "POST",
                    "/api/buckets",
                    Some(json!({ "name": "locked-out" }))
                )
                .await
                .0,
            StatusCode::CREATED
        );
        let deny = r#"{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::locked-out","arn:aws:s3:::locked-out/*"]}]}"#;
        assert_eq!(
            admin
                .send(
                    "PUT",
                    "/api/buckets/locked-out/policy",
                    Some(json!({ "document": deny }))
                )
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            admin
                .send("DELETE", "/api/buckets/locked-out/policy", None)
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        // And the admin loses its admin: a boundary that allows reading S3 only.
        let id = crate::users::id_of(&client, &account, "boss")
            .await
            .unwrap();
        let bound = crate::users::BoundaryRef::Aws("AmazonS3ReadOnlyAccess");
        crate::users::set_boundary(&client, &account, id, Some(&bound))
            .await
            .unwrap();
        assert_eq!(
            admin.send("GET", "/api/users", None).await.0,
            StatusCode::FORBIDDEN
        );

        // A link, used once.
        let token = store::create_root_link(&client, &account).await.unwrap();
        let mut root = Browser {
            console: console.clone(),
            cookie: None,
            origin: party().origin,
        };
        let (status, me) = root
            .send("POST", "/api/root/sign-in", Some(json!({ "token": token })))
            .await;
        assert_eq!(status, StatusCode::OK, "{me}");
        assert_eq!(
            (me["root"].clone(), me["mfa"].clone(), me["cluster"].clone()),
            (json!(true), json!(false), json!(true))
        );
        assert_eq!(
            me["identity"]["arn"],
            format!("arn:aws:iam::{account}:root")
        );
        assert!(me["expires_at"].is_number(), "{me}");
        assert_eq!(root.send("GET", "/api/me", None).await.1["root"], true);
        // Signing in as the root ends the browser's session as a user.
        let (mut was_admin, _) = directory_user(&console, "was-admin", ADMIN).await;
        let session = was_admin.cookie.clone();
        let token = store::create_root_link(&client, &account).await.unwrap();
        assert_eq!(
            was_admin
                .send("POST", "/api/root/sign-in", Some(json!({ "token": token })))
                .await
                .0,
            StatusCode::OK
        );
        was_admin.cookie = session;
        assert_eq!(
            was_admin.send("GET", "/api/me", None).await.0,
            StatusCode::UNAUTHORIZED
        );
        let mut again = Browser {
            console: console.clone(),
            cookie: None,
            origin: party().origin,
        };
        let (status, _) = again
            .send("POST", "/api/root/sign-in", Some(json!({ "token": token })))
            .await;
        assert_eq!(
            (status, again.cookie.is_none()),
            (StatusCode::BAD_REQUEST, true)
        );
        // A new link replaces the last.
        let first = store::create_root_link(&client, &account).await.unwrap();
        let _second = store::create_root_link(&client, &account).await.unwrap();
        assert_eq!(
            again
                .send("POST", "/api/root/sign-in", Some(json!({ "token": first })))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );

        // No identity policy restricts it; the bucket's deny does, but not
        // of the policy itself.
        assert_eq!(root.send("GET", "/api/users", None).await.0, StatusCode::OK);
        assert_eq!(
            root.send("GET", "/api/cluster", None).await.0,
            StatusCode::OK
        );
        let (status, err) = root
            .send("GET", "/api/buckets/locked-out/objects", None)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{err}");
        assert!(
            err["error"]
                .as_str()
                .unwrap()
                .contains(&format!("arn:aws:iam::{account}:root")),
            "{err}"
        );
        let (status, access) = root
            .send("GET", "/api/buckets/locked-out/access", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{access}");
        assert_eq!(
            (
                access["policy"].is_string(),
                access["public_access_block_hidden"].clone()
            ),
            (true, json!(true))
        );
        // What AWS guards against keys alone denies it too: it's no MFA.
        let mfa = r#"{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::locked-out","arn:aws:s3:::locked-out/*"],"Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}]}"#;
        let (status, err) = root
            .send(
                "PUT",
                "/api/buckets/locked-out/policy",
                Some(json!({ "document": mfa })),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
        assert_eq!(
            root.send("GET", "/api/buckets/locked-out/objects", None)
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            root.send("DELETE", "/api/buckets/locked-out/policy", None)
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            root.send("GET", "/api/buckets/locked-out/objects", None)
                .await
                .0,
            StatusCode::OK
        );
        // It puts the admin back.
        assert_eq!(
            root.send("DELETE", "/api/users/boss/boundary", None)
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            admin.send("GET", "/api/users", None).await.0,
            StatusCode::OK
        );

        // It has no passkeys to add.
        assert_eq!(
            root.send("POST", "/api/passkeys/options", None).await.0,
            StatusCode::FORBIDDEN
        );
        // Signing out ends the session, not just the cookie.
        let cookie = root.cookie.clone();
        assert_eq!(
            root.send("POST", "/api/logout", None).await.0,
            StatusCode::NO_CONTENT
        );
        root.cookie = cookie;
        assert_eq!(
            root.send("GET", "/api/me", None).await.0,
            StatusCode::UNAUTHORIZED
        );
    }

    /// The cluster is its operators': users whose policies allow `cairn:`
    /// actions. `CairnOperatorAccess` runs it, and sees none of the data;
    /// `AdministratorAccess` is everything; a user without either sees none
    /// of it. Each is told whether it may (`Me.cluster`).
    #[tokio::test]
    async fn operators_run_the_cluster() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = Arc::new(Console {
            app: app.clone(),
            party: party(),
        });
        let bucket = crate::e2e::BUCKET;
        crate::e2e::put(&app, "secret.txt", b"data".to_vec()).await;
        let mut ops = superadmin(&console, "ops").await;
        let mut admin = signed_in(&console, "admin", true).await;
        let mut user = signed_in(&console, "user", false).await;
        assert_eq!(ops.send("GET", "/api/me", None).await.1["cluster"], true);
        assert_eq!(admin.send("GET", "/api/me", None).await.1["cluster"], true);
        assert_eq!(user.send("GET", "/api/me", None).await.1["cluster"], false);

        for path in [
            "/api/cluster",
            "/api/storage",
            "/api/integrity",
            "/api/lifecycle",
        ] {
            assert_eq!(
                ops.send("GET", path, None).await.0,
                StatusCode::OK,
                "{path}"
            );
            assert_eq!(
                admin.send("GET", path, None).await.0,
                StatusCode::OK,
                "{path}"
            );
            let (status, err) = user.send("GET", path, None).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {err}");
        }
        assert_eq!(
            user.send("PUT", "/api/lifecycle/rate", Some(json!({ "rate": 5 })))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            ops.send("PUT", "/api/lifecycle/rate", Some(json!({ "rate": 5 })))
                .await
                .0,
            StatusCode::NO_CONTENT
        );

        // `CairnOperatorAccess` is none of the data, nor of the users.
        let (_, buckets) = ops.send("GET", "/api/buckets", None).await;
        assert_eq!(buckets, json!([]));
        assert_eq!(
            ops.send("GET", &format!("/api/buckets/{bucket}/objects"), None)
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            ops.send("GET", "/api/users", None).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            admin
                .send("GET", &format!("/api/buckets/{bucket}/objects"), None)
                .await
                .0,
            StatusCode::OK
        );
    }

    /// A console session signed in with a passkey has
    /// `aws:MultiFactorAuthPresent` (and its age): AWS's guard against keys
    /// alone allows it what it denies those.
    #[tokio::test]
    async fn passkey_sessions_have_mfa() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = Arc::new(Console {
            app: app.clone(),
            party: party(),
        });
        let client = app.pool.get().await.unwrap();
        let account = crate::users::account(&client).await.unwrap();
        let guarded = r#"{"Version":"2012-10-17","Statement":[
            {"Effect":"Allow","Action":"cairn:*","Resource":"*"},
            {"Effect":"Deny","Action":"cairn:*","Resource":"*","Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}},
            {"Effect":"Deny","Action":"cairn:PutSetting","Resource":"*","Condition":{"NumericGreaterThan":{"aws:MultiFactorAuthAge":"600"}}}
        ]}"#;
        let (mut ops, _) = directory_user(&console, "guarded", guarded).await;
        let (_, me) = ops.send("GET", "/api/me", None).await;
        assert_eq!((&me["mfa"], &me["cluster"]), (&json!(true), &json!(true)));
        assert_eq!(
            ops.send("GET", "/api/cluster", None).await.0,
            StatusCode::OK
        );
        // Its age is since it signed in.
        client
            .execute(
                "UPDATE console_directory_sessions SET verified_at = now() - interval '1 hour'",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(
            ops.send("GET", "/api/cluster", None).await.0,
            StatusCode::OK
        );
        let rate = Some(json!({ "rate": 5 }));
        assert_eq!(
            ops.send("PUT", "/api/lifecycle/rate", rate).await.0,
            StatusCode::FORBIDDEN
        );
        users::create(&client, "guarded", None, false)
            .await
            .unwrap();
        users::put_policy(&client, &account, "guarded", "guarded", guarded)
            .await
            .unwrap();
        // Its access keys have neither: the guard denies them.
        let user = Principal::load_user(
            &client,
            crate::users::id_of(&client, &account, "guarded")
                .await
                .unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        let origin = crate::s3::access::Origin {
            peer: None,
            trusted_proxies: &[],
            signed: None,
            form: false,
        };
        let mut access = crate::s3::access::Access::new(
            Some(&user),
            &account,
            &Method::GET,
            &HeaderMap::new(),
            "",
            &origin,
        )
        .unwrap();
        access.set_management(&account);
        let check = crate::s3::actions::Check {
            action: "cairn:GetCluster",
            on: crate::s3::actions::On::Cluster,
        };
        assert!(!access.allows(&check));
    }

    impl Browser {
        /// The provider sending the browser back (a cross-site navigation:
        /// no SameSite=Strict cookie goes with it): where it's sent on.
        async fn come_back(&mut self, state: &str, code: &str) -> (StatusCode, String) {
            let req = Request::builder()
                .uri(format!("/api/oidc/callback?state={state}&code={code}"))
                .body(axum::body::Body::empty())
                .unwrap();
            let resp = router(self.console.clone()).oneshot(req).await.unwrap();
            if let Some(set) = resp.headers().get(header::SET_COOKIE) {
                let value = set
                    .to_str()
                    .unwrap()
                    .split(';')
                    .next()
                    .unwrap()
                    .split_once('=')
                    .unwrap()
                    .1;
                self.cookie = (!value.is_empty()).then(|| value.to_owned());
            }
            let location = resp
                .headers()
                .get(header::LOCATION)
                .map(|l| l.to_str().unwrap().to_owned())
                .unwrap_or_default();
            (resp.status(), location)
        }

        /// Starts a sign-in at the mock provider: its authorization URL.
        async fn start_oidc(&mut self) -> String {
            let (status, answer) = self.send("POST", "/api/oidc/mock/start", None).await;
            assert_eq!(status, StatusCode::OK, "{answer}");
            answer["url"].as_str().unwrap().to_owned()
        }
    }

    /// Directory users: an operator configures an identity source; whoever
    /// it vouches for signs in as itself, with the permission sets assigned
    /// to it or its groups (picked for it when there's one), acting as their
    /// roles' sessions, without MFA, and may take their credentials. One
    /// with none doesn't get in; one whose assignment goes loses it at once.
    /// Tokens that aren't right are refused. The permission sets' roles are
    /// Identity Center's: IAM can't change them.
    #[tokio::test]
    async fn directory_users_sign_in_with_permission_sets() {
        use super::oidc::mock::{CLIENT_ID, CLIENT_SECRET, Mock};
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = Arc::new(Console {
            app: app.clone(),
            party: party(),
        });
        let client = app.pool.get().await.unwrap();
        let account = crate::users::account(&client).await.unwrap();
        let mock = Mock::start().await;
        let browser = || Browser {
            console: console.clone(),
            cookie: None,
            origin: party().origin,
        };

        // An operator configures it (checked against its discovery).
        let mut ops = superadmin(&console, "op").await;
        let config = json!({ "label": "Company SSO", "issuer": mock.issuer, "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET });
        let (status, err) = ops
            .send("PUT", "/api/oidc-providers/mock", Some(config))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
        let bad = json!({ "label": "x", "issuer": "https://127.0.0.1:1", "client_id": "c" });
        assert_eq!(
            ops.send("PUT", "/api/oidc-providers/broken", Some(bad))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let mut admin = signed_in(&console, "admin", true).await;
        let config = json!({ "label": "x", "issuer": mock.issuer, "client_id": "c" });
        let mut tenant = signed_in(&console, "tenant", false).await;
        assert_eq!(
            tenant
                .send("PUT", "/api/oidc-providers/sneaky", Some(config))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        let (_, buttons) = browser().send("GET", "/api/oidc/providers", None).await;
        assert_eq!(buttons, json!([{ "name": "mock", "label": "Company SSO" }]));
        let (_, sources) = ops.send("GET", "/api/oidc-providers", None).await;
        assert_eq!(
            sources["providers"][0]["group_claim"], "groups",
            "{sources}"
        );

        // No permission set yet: no way in, but who it was is noted.
        let mut ada = browser();
        let url = ada.start_oidc().await;
        assert!(
            url.starts_with(&format!("{}/authorize?", mock.issuer)),
            "{url}"
        );
        let (state, code) = mock.code_with_groups(&url, "sub-ada", "ada@example.com", &["data"]);
        let (status, location) = ada.come_back(&state, &code).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert!(
            location.starts_with("/login?error=") && location.contains("permission%20set"),
            "{location}"
        );
        assert!(ada.cookie.is_none());
        let (_, seen) = admin.send("GET", "/api/directory-users", None).await;
        assert_eq!(
            (&seen[0]["subject"], &seen[0]["groups"]),
            (&json!("sub-ada"), &json!(["data"]))
        );
        assert_eq!(seen[0]["user_name"], "ada@example.com");
        let ada_id = seen[0]["id"].as_str().unwrap().to_owned();
        let (_, groups) = admin.send("GET", "/api/directory-groups", None).await;
        assert_eq!(
            (&groups[0]["name"], &groups[0]["members"]),
            (&json!("data"), &json!(1))
        );
        let data_id = groups[0]["id"].as_str().unwrap().to_owned();
        assert_eq!(
            tenant.send("GET", "/api/directory-users", None).await.0,
            StatusCode::FORBIDDEN
        );

        // Permission sets, with their policies; the tenant may make none.
        let readers = json!({ "name": "Readers", "description": "Lists buckets" });
        assert_eq!(
            tenant
                .send("POST", "/api/permission-sets", Some(readers.clone()))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            admin
                .send("POST", "/api/permission-sets", Some(readers.clone()))
                .await
                .0,
            StatusCode::CREATED
        );
        assert_eq!(
            admin
                .send("POST", "/api/permission-sets", Some(readers))
                .await
                .0,
            StatusCode::CONFLICT
        );
        let list = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}"#;
        let (status, err) = admin
            .send(
                "PUT",
                "/api/permission-sets/Readers/inline-policy",
                Some(json!({ "document": list })),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
        let admins = json!({ "name": "Admins", "session_duration": 7200 });
        assert_eq!(
            admin
                .send("POST", "/api/permission-sets", Some(admins))
                .await
                .0,
            StatusCode::CREATED
        );
        let full = json!({ "arn": "arn:aws:iam::aws:policy/AdministratorAccess" });
        assert_eq!(
            admin
                .send("POST", "/api/permission-sets/Admins/attached", Some(full))
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        let (_, sets) = admin.send("GET", "/api/permission-sets", None).await;
        assert_eq!(sets.as_array().unwrap().len(), 2);
        let readers_role = sets[1]["role_name"].as_str().unwrap().to_owned();
        assert!(
            readers_role.starts_with("AWSReservedSSO_Readers_"),
            "{sets}"
        );
        // Provisioned nowhere, until they're assigned.
        assert_eq!(sets[1]["provisioned"], json!([]));
        assert!(
            crate::roles::Role::load(&client, &account, &readers_role)
                .await
                .unwrap()
                .is_none()
        );

        // Assigned: Readers to the group, Admins to Ada herself.
        let assign = |set: &str, kind: &str, id: &str| json!({ "permission_set": set, "principal_type": kind, "principal_id": id });
        assert_eq!(
            admin
                .send(
                    "POST",
                    "/api/assignments",
                    Some(assign("Readers", "GROUP", &data_id))
                )
                .await
                .0,
            StatusCode::CREATED
        );
        assert_eq!(
            admin
                .send(
                    "POST",
                    "/api/assignments",
                    Some(assign("Admins", "USER", &ada_id))
                )
                .await
                .0,
            StatusCode::CREATED
        );
        assert_eq!(
            admin
                .send(
                    "POST",
                    "/api/assignments",
                    Some(assign("Admins", "USER", &ada_id))
                )
                .await
                .0,
            StatusCode::CONFLICT
        );
        // Provisioned to the account, as roles there.
        let (_, sets) = admin.send("GET", "/api/permission-sets", None).await;
        let provisioned = &sets[1]["provisioned"];
        assert_eq!(
            provisioned[0]["role_arn"],
            format!("arn:aws:iam::{account}:role/aws-reserved/sso.amazonaws.com/{readers_role}")
        );
        assert_eq!(
            (&provisioned[0]["account_id"], &provisioned[0]["latest"]),
            (&json!(account), &json!(true))
        );
        // Changed in the console, it's provisioned again at once.
        let both = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:ListAllMyBuckets","s3:ListBucket"],"Resource":"*"}]}"#;
        let put = Some(json!({ "document": both }));
        assert_eq!(
            admin
                .send("PUT", "/api/permission-sets/Readers/inline-policy", put)
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        let role = crate::roles::Role::load(&client, &account, &readers_role)
            .await
            .unwrap()
            .unwrap();
        let held =
            crate::roles::get_policy(&client, role.id, crate::identity_center::INLINE_POLICY)
                .await
                .unwrap();
        assert_eq!(held.as_deref(), Some(both));
        let (_, sets) = admin.send("GET", "/api/permission-sets", None).await;
        assert_eq!(sets[1]["provisioned"][0]["latest"], true);

        // IAM can't change their roles, nor make roles where they are.
        let (status, err) = admin
            .send(
                "PATCH",
                &format!("/api/roles/{readers_role}"),
                Some(json!({ "description": "mine" })),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            err["error"].as_str().unwrap().contains("protected role"),
            "{err}"
        );
        assert_eq!(
            admin
                .send("DELETE", &format!("/api/roles/{readers_role}"), None)
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"sso.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
        let fake = json!({ "name": "fake", "path": "/aws-reserved/sso.amazonaws.com/", "trust": trust, "description": "" });
        assert_eq!(
            admin.send("POST", "/api/roles", Some(fake)).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            admin
                .send(
                    "POST",
                    "/api/assignments",
                    Some(assign("Admins", "OTHER", &ada_id))
                )
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        // Only to who's in the identity store (a group as a user, say, isn't).
        assert_eq!(
            admin
                .send(
                    "POST",
                    "/api/assignments",
                    Some(assign("Admins", "USER", &data_id))
                )
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            admin
                .send(
                    "POST",
                    "/api/assignments",
                    Some(assign("Admins", "GROUP", "x"))
                )
                .await
                .0,
            StatusCode::NOT_FOUND
        );

        // Ada has both: she picks one, and acts as its role's session.
        let url = ada.start_oidc().await;
        let (state, code) = mock.code_with_groups(&url, "sub-ada", "ada@example.com", &["data"]);
        assert_eq!(
            ada.come_back(&state, &code).await,
            (StatusCode::SEE_OTHER, "/".to_owned())
        );
        // A state is used once.
        assert!(
            browser()
                .come_back(&state, &code)
                .await
                .1
                .starts_with("/login?error=")
        );
        let (status, me) = ada.send("GET", "/api/me", None).await;
        assert_eq!(status, StatusCode::OK, "{me}");
        assert_eq!(
            (&me["name"], &me["mfa"], &me["directory"]["permission_set"]),
            (&json!("Test Person"), &json!(false), &Value::Null)
        );
        let names: Vec<&str> = me["directory"]["permission_sets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["Admins", "Readers"]);
        // Each in the account it's assigned in: the only one.
        assert!(
            me["directory"]["permission_sets"]
                .as_array()
                .unwrap()
                .iter()
                .all(|s| s["account_id"] == json!(account)),
            "{me}"
        );
        let (status, err) = ada.send("GET", "/api/users", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            err["error"]
                .as_str()
                .unwrap()
                .contains("pick a permission set"),
            "{err}"
        );
        let (status, _) = ada
            .send(
                "POST",
                "/api/directory/permission-set",
                Some(json!({ "name": "Nope" })),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let elsewhere = json!({ "name": "Admins", "account_id": "111111111111" });
        assert_eq!(
            ada.send("POST", "/api/directory/permission-set", Some(elsewhere))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        let (status, me) = ada
            .send(
                "POST",
                "/api/directory/permission-set",
                Some(json!({ "name": "Admins" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{me}");
        assert_eq!(
            (
                &me["directory"]["permission_set_account_id"],
                &me["identity"]["account_id"]
            ),
            (&json!(account), &json!(account))
        );
        assert!(
            me["identity"]["arn"]
                .as_str()
                .unwrap()
                .starts_with(&format!(
                    "arn:aws:sts::{account}:assumed-role/AWSReservedSSO_Admins_"
                ))
        );
        assert!(
            me["identity"]["arn"]
                .as_str()
                .unwrap()
                .ends_with("/ada@example.com"),
            "{me}"
        );
        assert_eq!(ada.send("GET", "/api/users", None).await.0, StatusCode::OK);
        // She signs in at her identity source: no passkeys here.
        assert_eq!(
            ada.send("POST", "/api/passkeys/options", None).await.0,
            StatusCode::FORBIDDEN
        );

        // Her credentials are a session of the role, for its duration.
        let (status, creds) = ada.send("POST", "/api/directory/credentials", None).await;
        assert_eq!(status, StatusCode::OK, "{creds}");
        let expires = creds["expiration"].as_u64().unwrap();
        assert!(
            expires > crate::sessions::now() + 7000 && expires <= crate::sessions::now() + 7200,
            "{creds}"
        );
        let session = Principal::authenticate(
            &client,
            &app.sessions,
            creds["access_key_id"].as_str().unwrap(),
            creds["session_token"].as_str().unwrap().into(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(session.arn().ends_with("/ada@example.com"));
        assert!(
            session
                .principal_arn()
                .contains("/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admins_")
        );
        // A passkey's session has no permission sets.
        assert_eq!(
            tenant
                .send("POST", "/api/directory/credentials", None)
                .await
                .0,
            StatusCode::FORBIDDEN
        );

        // Bob, in the group only: Readers, picked for him.
        let mut bob = browser();
        let url = bob.start_oidc().await;
        let (state, code) =
            mock.code_with_groups(&url, "sub-bob", "bob@example.com", &["data", "other"]);
        assert_eq!(bob.come_back(&state, &code).await.1, "/");
        let (_, me) = bob.send("GET", "/api/me", None).await;
        assert_eq!(me["directory"]["permission_set"], "Readers");
        assert_eq!(me["directory"]["groups"], json!(["data", "other"]));
        assert_eq!(
            bob.send("GET", "/api/buckets", None).await.0,
            StatusCode::OK
        );
        assert_eq!(
            bob.send("GET", "/api/users", None).await.0,
            StatusCode::FORBIDDEN
        );
        // The group's assignment goes: so does his access, at once.
        let (_, assignments) = admin.send("GET", "/api/assignments", None).await;
        let group = assignments
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["principal_type"] == "GROUP")
            .unwrap();
        let path = format!("/api/assignments/{}", group["id"].as_str().unwrap());
        assert_eq!(
            tenant.send("DELETE", &path, None).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            admin.send("DELETE", &path, None).await.0,
            StatusCode::NO_CONTENT
        );
        let (status, err) = bob.send("GET", "/api/buckets", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            err["error"]
                .as_str()
                .unwrap()
                .contains("isn't assigned to you"),
            "{err}"
        );

        // A token for another client is refused.
        *mock.audience.lock().unwrap() = "someone-else".into();
        let mut tricked = browser();
        let url = tricked.start_oidc().await;
        let (state, code) = mock.code_with_groups(&url, "sub-ada", "ada@example.com", &["data"]);
        let (_, location) = tricked.come_back(&state, &code).await;
        assert!(location.contains("another%20client"), "{location}");
        assert!(tricked.cookie.is_none());
        *mock.audience.lock().unwrap() = CLIENT_ID.into();

        // Deleting a permission set: its role, and Ada's use of it, go.
        let admins_role = sets[0]["role_name"].as_str().unwrap().to_owned();
        assert_eq!(
            admin
                .send("DELETE", "/api/permission-sets/Admins", None)
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        assert!(
            crate::roles::Role::load(&client, &account, &admins_role)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            ada.send("GET", "/api/users", None).await.0,
            StatusCode::FORBIDDEN
        );
    }

    /// Users of Cairn's own directory: made in the console, they make a
    /// passkey with a setup link, sign in with it (as multi-factor) and use
    /// the permission sets assigned to them; their passkeys can be taken
    /// away, which signs them out.
    #[tokio::test]
    async fn own_directory_users_sign_in_with_passkeys() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = console_of(&app);
        let client = app.pool.get().await.unwrap();
        let account = crate::users::account(&client).await.unwrap();
        let mut admin = signed_in(&console, "admin", true).await;
        let mut tenant = signed_in(&console, "tenant", false).await;

        let grace = json!({ "user_name": "grace", "display_name": "Grace Hopper", "given_name": "Grace", "email": "grace@example.com" });
        assert_eq!(
            tenant
                .send("POST", "/api/directory-users", Some(grace.clone()))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        let (status, made) = admin
            .send("POST", "/api/directory-users", Some(grace.clone()))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{made}");
        assert_eq!(
            admin
                .send("POST", "/api/directory-users", Some(grace))
                .await
                .0,
            StatusCode::CONFLICT
        );
        let id = made["id"].as_str().unwrap().to_owned();

        // Its setup link: a passkey of its own.
        let link_path = format!("/api/directory-users/{id}/setup-link");
        assert_eq!(
            tenant.send("POST", &link_path, None).await.0,
            StatusCode::FORBIDDEN
        );
        let (status, link) = admin.send("POST", &link_path, None).await;
        assert_eq!(status, StatusCode::CREATED, "{link}");
        let token = link["path"]
            .as_str()
            .unwrap()
            .strip_prefix("/enroll#")
            .unwrap()
            .to_owned();
        let mut browser = Browser {
            console: console.clone(),
            cookie: None,
            origin: party().origin,
        };
        let (status, ceremony) = browser
            .send(
                "POST",
                "/api/enroll/options",
                Some(json!({ "token": token })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{ceremony}");
        assert_eq!(ceremony["identity"], "grace");
        let handle = URL_SAFE_NO_PAD.encode(uuid::Uuid::parse_str(&id).unwrap().as_bytes());
        assert_eq!(ceremony["options"]["user"]["id"], handle);
        let mut key = Authenticator::ed25519();
        let mut body = registration(&mut key, &ceremony, "Laptop");
        body["token"] = json!(token);
        // Set up, but nothing is assigned to her yet: not signed in.
        let (status, err) = browser
            .send("POST", "/api/enroll", Some(body.clone()))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{err}");
        assert!(
            err["error"].as_str().unwrap().contains("no permission set"),
            "{err}"
        );
        assert_eq!(
            browser.send("POST", "/api/enroll", Some(body)).await.0,
            StatusCode::BAD_REQUEST
        );
        let (_, users) = admin.send("GET", "/api/directory-users", None).await;
        let listed = users
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["id"] == json!(id))
            .unwrap()
            .clone();
        assert_eq!(
            (
                &listed["provider"],
                &listed["passkeys"],
                &listed["setup_link_pending"]
            ),
            (&Value::Null, &json!(1), &json!(false))
        );

        // Assigned a permission set, she signs in with her passkey.
        let readers = json!({ "name": "Readers" });
        assert_eq!(
            admin
                .send("POST", "/api/permission-sets", Some(readers))
                .await
                .0,
            StatusCode::CREATED
        );
        let assign =
            json!({ "permission_set": "Readers", "principal_type": "USER", "principal_id": id });
        assert_eq!(
            admin.send("POST", "/api/assignments", Some(assign)).await.0,
            StatusCode::CREATED
        );
        let (status, me) = sign_in(&mut browser, &mut key).await;
        assert_eq!(status, StatusCode::OK, "{me}");
        assert_eq!(
            (&me["name"], &me["mfa"]),
            (&json!("Grace Hopper"), &json!(true))
        );
        assert_eq!(
            (
                &me["directory"]["permission_set"],
                &me["directory"]["provider_label"]
            ),
            (&json!("Readers"), &Value::Null)
        );
        assert!(
            me["identity"]["arn"]
                .as_str()
                .unwrap()
                .starts_with(&format!(
                    "arn:aws:sts::{account}:assumed-role/AWSReservedSSO_Readers_"
                ))
        );
        assert_eq!(browser.send("GET", "/api/me", None).await.0, StatusCode::OK);

        // Her own passkeys: she adds, renames and removes them.
        assert_eq!(
            (
                me["passkeys"][0]["name"].as_str(),
                &me["passkeys"][0]["current"]
            ),
            (Some("Laptop"), &json!(true))
        );
        let (status, ceremony) = browser.send("POST", "/api/passkeys/options", None).await;
        assert_eq!(status, StatusCode::OK, "{ceremony}");
        assert_eq!(ceremony["options"]["user"]["id"], handle);
        assert_eq!(
            ceremony["options"]["excludeCredentials"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let mut phone = Authenticator::p256();
        // Another's challenge isn't hers, nor hers another's.
        let (mut eve, _) = directory_user(&console, "eve", ADMIN).await;
        let (_, theirs) = eve.send("POST", "/api/passkeys/options", None).await;
        let (status, err) = browser
            .send(
                "POST",
                "/api/passkeys",
                Some(registration(&mut phone, &theirs, "Phone")),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            err["error"].as_str().unwrap().contains("isn't yours"),
            "{err}"
        );
        let body = registration(&mut phone, &ceremony, "Phone");
        assert_eq!(
            eve.send("POST", "/api/passkeys", Some(body)).await.0,
            StatusCode::BAD_REQUEST
        );
        let (_, ceremony) = browser.send("POST", "/api/passkeys/options", None).await;
        let body = registration(&mut phone, &ceremony, "Phone");
        assert_eq!(
            browser.send("POST", "/api/passkeys", Some(body)).await.0,
            StatusCode::NO_CONTENT
        );
        let (_, ceremony) = browser.send("POST", "/api/passkeys/options", None).await;
        let (status, err) = browser
            .send(
                "POST",
                "/api/passkeys",
                Some(registration(&mut phone, &ceremony, "Again")),
            )
            .await;
        assert_eq!(
            (status, err["error"].as_str()),
            (
                StatusCode::BAD_REQUEST,
                Some("this passkey is registered already")
            )
        );
        let mut other = Browser {
            console: console.clone(),
            cookie: None,
            origin: party().origin,
        };
        let (status, me) = sign_in(&mut other, &mut phone).await;
        assert_eq!(status, StatusCode::OK, "{me}");
        let current: Vec<_> = me["passkeys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["current"].as_bool().unwrap())
            .collect();
        assert_eq!(current, [false, true]);
        let phone_path = format!(
            "/api/passkeys/{}",
            URL_SAFE_NO_PAD.encode(&phone.credential_id)
        );
        assert_eq!(
            browser
                .send("PUT", &phone_path, Some(json!({ "name": "Old phone" })))
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            browser.send("GET", "/api/me", None).await.1["passkeys"][1]["name"],
            "Old phone"
        );
        // Not someone else's.
        assert_eq!(
            eve.send("DELETE", &phone_path, None).await.0,
            StatusCode::BAD_REQUEST
        );
        // A counter that goes backwards is refused (a cloned authenticator).
        phone.counter = 10;
        assert_eq!(sign_in(&mut other, &mut phone).await.0, StatusCode::OK);
        phone.counter = 3;
        let (status, err) = sign_in(&mut other, &mut phone).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            err["error"].as_str().unwrap().contains("went backwards"),
            "{err}"
        );
        // Removing one ends the sessions signed in with it; never her last.
        assert_eq!(
            browser.send("DELETE", &phone_path, None).await.0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            other.send("GET", "/api/me", None).await.0,
            StatusCode::UNAUTHORIZED
        );
        let laptop_path = format!(
            "/api/passkeys/{}",
            URL_SAFE_NO_PAD.encode(&key.credential_id)
        );
        let (status, err) = browser.send("DELETE", &laptop_path, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(err["error"].as_str().unwrap().contains("last way"), "{err}");

        // The command line makes links too.
        let args: crate::identity_center::DirectoryUserArgs =
            serde_json::from_value(json!({ "command": { "Link": { "user_name": "grace" } } }))
                .unwrap();
        let mut out = crate::admin::Output::default();
        crate::identity_center::run(&app, args, &mut out)
            .await
            .unwrap();
        assert!(out.stdout.contains("/enroll#"), "{}", out.stdout);
        let args: crate::identity_center::DirectoryUserArgs =
            serde_json::from_value(json!({ "command": { "Link": { "user_name": "nobody" } } }))
                .unwrap();
        assert!(
            crate::identity_center::run(&app, args, &mut crate::admin::Output::default())
                .await
                .is_err()
        );

        // Her passkeys taken away: signed out, and they no longer sign in.
        let passkeys = format!("/api/directory-users/{id}/passkeys");
        assert_eq!(
            tenant.send("DELETE", &passkeys, None).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            admin.send("DELETE", &passkeys, None).await.0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            browser.send("GET", "/api/me", None).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            sign_in(&mut browser, &mut key).await.0,
            StatusCode::BAD_REQUEST
        );

        // Deleted, she's gone; a source's users have no setup links.
        assert_eq!(
            admin
                .send("DELETE", &format!("/api/directory-users/{id}"), None)
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        assert!(
            crate::identity_center::users(
                &client,
                Some(crate::identity_center::Lookup::Id(
                    uuid::Uuid::parse_str(&id).unwrap()
                ))
            )
            .await
            .unwrap()
            .is_empty()
        );
    }

    /// The organization's accounts: listed, made and closed in the console,
    /// by the management account's principals whose policies allow it.
    #[tokio::test]
    async fn the_organization_makes_and_closes_accounts() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = console_of(&app);
        let mut admin = signed_in(&console, "admin", true).await;
        let mut tenant = signed_in(&console, "tenant", false).await;
        assert_eq!(
            tenant.send("GET", "/api/accounts", None).await.0,
            StatusCode::FORBIDDEN
        );
        let team = json!({ "name": "Team B", "email": "team-b@example.com" });
        assert_eq!(
            tenant
                .send("POST", "/api/accounts", Some(team.clone()))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        let (status, made) = admin
            .send("POST", "/api/accounts", Some(team.clone()))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{made}");
        let id = made["id"].as_str().unwrap().to_owned();
        assert_eq!(
            made["role_arn"],
            format!("arn:aws:iam::{id}:role/OrganizationAccountAccessRole")
        );
        assert_eq!(
            admin.send("POST", "/api/accounts", Some(team)).await.0,
            StatusCode::CONFLICT
        );
        let (_, accounts) = admin.send("GET", "/api/accounts", None).await;
        let listed: Vec<(&str, bool)> = accounts
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                (
                    a["name"].as_str().unwrap(),
                    a["management"].as_bool().unwrap(),
                )
            })
            .collect();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[1], ("Team B", false));
        assert_eq!(
            admin
                .send("DELETE", &format!("/api/accounts/{id}"), None)
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        let (_, accounts) = admin.send("GET", "/api/accounts", None).await;
        assert_eq!(accounts[1]["status"], "SUSPENDED");
        assert_eq!(
            admin
                .send("DELETE", &format!("/api/accounts/{id}"), None)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }

    /// Switching roles: an administrator of the management account takes a
    /// member account's OrganizationAccountAccessRole, and acts in that
    /// account as its session, until it switches back; who may not assume
    /// a role (by its own policies, or the role's trust) can't switch to
    /// it, whether it's there or not. A directory user switches from its
    /// permission set's role's session, which its assignment still decides.
    #[tokio::test]
    async fn switches_roles_across_accounts() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = console_of(&app);
        let client = app.pool.get().await.unwrap();
        let management = crate::users::account(&client).await.unwrap();
        let mut admin = signed_in(&console, "admin", true).await;
        let mut tenant = signed_in(&console, "tenant", false).await;
        let (status, made) = admin
            .send(
                "POST",
                "/api/accounts",
                Some(json!({ "name": "Team B", "email": "b@example.com" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{made}");
        let member = made["id"].as_str().unwrap().to_owned();
        let access = json!({ "account": member, "role": "OrganizationAccountAccessRole" });

        // The roles to pick: the administrator's, the member's access role;
        // none for the tenant, whose policies allow it none.
        let (status, roles) = admin.send("GET", "/api/switch-role/roles", None).await;
        assert_eq!(status, StatusCode::OK, "{roles}");
        let picked: Vec<_> = roles
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["account_id"].as_str().unwrap(),
                    r["account"].as_str().unwrap(),
                    r["role"].as_str().unwrap(),
                )
            })
            .collect();
        assert!(
            picked.contains(&(&*member, "Team B", "OrganizationAccountAccessRole")),
            "{roles}"
        );
        let (status, roles) = tenant.send("GET", "/api/switch-role/roles", None).await;
        assert_eq!((status, roles), (StatusCode::OK, json!([])));
        // Account names: all the organization's for who may list its accounts.
        let (_, names) = admin.send("GET", "/api/account-names", None).await;
        assert!(
            names
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a["id"] == member.as_str() && a["name"] == "Team B"),
            "{names}"
        );

        // The tenant's policies don't allow it; nor is a role that isn't there.
        let (status, err) = tenant
            .send("POST", "/api/switch-role", Some(access.clone()))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{err}");
        assert!(
            err["error"].as_str().unwrap().contains("sts:AssumeRole"),
            "{err}"
        );
        let missing = json!({ "account": member, "role": "Nobody" });
        assert_eq!(
            admin
                .send("POST", "/api/switch-role", Some(missing))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        let bad = json!({ "account": "12", "role": "OrganizationAccountAccessRole" });
        assert_eq!(
            admin.send("POST", "/api/switch-role", Some(bad)).await.0,
            StatusCode::BAD_REQUEST
        );

        // The administrator switches, and acts in the member account.
        let (status, me) = admin
            .send("POST", "/api/switch-role", Some(access.clone()))
            .await;
        assert_eq!(status, StatusCode::OK, "{me}");
        assert_eq!(
            me["identity"]["arn"],
            format!("arn:aws:sts::{member}:assumed-role/OrganizationAccountAccessRole/admin")
        );
        assert_eq!(
            (&me["identity"]["account"], &me["identity"]["management"]),
            (&json!("Team B"), &json!(false))
        );
        assert_eq!(
            me["switched"]["from"],
            format!("arn:aws:iam::{management}:user/admin")
        );
        let (status, roles) = admin.send("GET", "/api/roles", None).await;
        assert_eq!(status, StatusCode::OK, "{roles}");
        assert!(
            roles.to_string().contains("OrganizationAccountAccessRole"),
            "{roles}"
        );
        let (_, users) = admin.send("GET", "/api/users", None).await;
        assert!(!users.to_string().contains("tenant"), "{users}");
        // Not the management account's anymore: its organization is not the role's to see.
        assert_eq!(
            admin.send("GET", "/api/accounts", None).await.0,
            StatusCode::FORBIDDEN
        );
        // Its own account's name alone.
        let (_, names) = admin.send("GET", "/api/account-names", None).await;
        assert_eq!(names, json!([{ "id": member, "name": "Team B" }]));

        // Back.
        let (status, me) = admin.send("DELETE", "/api/switch-role", None).await;
        assert_eq!(status, StatusCode::OK, "{me}");
        assert_eq!(
            (&me["identity"]["account_id"], &me["switched"]),
            (&json!(management), &Value::Null)
        );
        assert_eq!(
            admin.send("GET", "/api/accounts", None).await.0,
            StatusCode::OK
        );

        // A directory user with an administrator's permission set switches
        // from its role's session; taking the set away ends both.
        let grace =
            json!({ "user_name": "grace", "display_name": "Grace Hopper", "given_name": "Grace" });
        let (_, made) = admin
            .send("POST", "/api/directory-users", Some(grace))
            .await;
        let id = made["id"].as_str().unwrap().to_owned();
        let (_, link) = admin
            .send(
                "POST",
                &format!("/api/directory-users/{id}/setup-link"),
                None,
            )
            .await;
        let token = link["path"]
            .as_str()
            .unwrap()
            .strip_prefix("/enroll#")
            .unwrap()
            .to_owned();
        assert_eq!(
            admin
                .send(
                    "POST",
                    "/api/permission-sets",
                    Some(json!({ "name": "Admins" }))
                )
                .await
                .0,
            StatusCode::CREATED
        );
        let full = json!({ "arn": "arn:aws:iam::aws:policy/AdministratorAccess" });
        assert_eq!(
            admin
                .send("POST", "/api/permission-sets/Admins/attached", Some(full))
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        let assign =
            json!({ "permission_set": "Admins", "principal_type": "USER", "principal_id": id });
        let (status, assigned) = admin.send("POST", "/api/assignments", Some(assign)).await;
        assert_eq!(status, StatusCode::CREATED, "{assigned}");
        let mut browser = Browser {
            console: console.clone(),
            cookie: None,
            origin: party().origin,
        };
        let (_, ceremony) = browser
            .send(
                "POST",
                "/api/enroll/options",
                Some(json!({ "token": token })),
            )
            .await;
        let mut body = registration(&mut Authenticator::ed25519(), &ceremony, "Laptop");
        body["token"] = json!(token);
        let (status, me) = browser.send("POST", "/api/enroll", Some(body)).await;
        assert_eq!(status, StatusCode::OK, "{me}");
        let (status, me) = browser.send("POST", "/api/switch-role", Some(access)).await;
        assert_eq!(status, StatusCode::OK, "{me}");
        assert_eq!(
            me["identity"]["arn"],
            format!("arn:aws:sts::{member}:assumed-role/OrganizationAccountAccessRole/grace")
        );
        assert!(
            me["switched"]["from"]
                .as_str()
                .unwrap()
                .contains(":assumed-role/AWSReservedSSO_Admins_"),
            "{me}"
        );
        assert_eq!(
            browser.send("GET", "/api/roles", None).await.0,
            StatusCode::OK
        );
        let (_, assignments) = admin.send("GET", "/api/assignments", None).await;
        let assignment = assignments
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["principal_id"] == json!(id))
            .unwrap()
            .clone();
        let removed = admin
            .send(
                "DELETE",
                &format!("/api/assignments/{}", assignment["id"].as_str().unwrap()),
                None,
            )
            .await;
        assert_eq!(removed.0, StatusCode::NO_CONTENT, "{}", removed.1);
        assert_eq!(
            browser.send("GET", "/api/roles", None).await.0,
            StatusCode::FORBIDDEN
        );
    }

    /// Identity Center is the management account's: a member account's
    /// principals, whatever their policies allow, see none of its directory
    /// and change none of it (a setup link of theirs would take a
    /// management account's directory user over), as sso-admin and
    /// identitystore refuse them.
    #[tokio::test]
    async fn a_member_account_has_no_identity_center() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = console_of(&app);
        let client = app.pool.get().await.unwrap();
        let mut admin = signed_in(&console, "admin", true).await;
        let (status, made) = admin
            .send(
                "POST",
                "/api/accounts",
                Some(json!({ "name": "Team C", "email": "team-c@example.com" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{made}");
        let member = made["id"].as_str().unwrap().to_owned();
        users::create_for(&client, &member, "intruder", None, true)
            .await
            .unwrap();
        let mut intruder = signed_in_as(&console, &member, "intruder").await;
        let (_, me) = intruder.send("GET", "/api/me", None).await;
        assert_eq!(
            (&me["identity"]["account_id"], &me["identity"]["management"]),
            (&json!(member), &json!(false))
        );
        assert_eq!(
            admin.send("GET", "/api/me", None).await.1["identity"]["management"],
            json!(true)
        );
        // Its own account it administers.
        assert_eq!(
            intruder.send("GET", "/api/users", None).await.0,
            StatusCode::OK
        );

        let grace = json!({ "user_name": "grace", "display_name": "Grace Hopper" });
        let (_, made) = admin
            .send("POST", "/api/directory-users", Some(grace.clone()))
            .await;
        let id = made["id"].as_str().unwrap().to_owned();
        let (_, group) = admin
            .send(
                "POST",
                "/api/directory-groups",
                Some(json!({ "name": "admins" })),
            )
            .await;
        let group = group["id"].as_str().unwrap().to_owned();
        for (method, path, body) in [
            ("GET", "/api/directory-users".to_owned(), None),
            (
                "POST",
                "/api/directory-users".to_owned(),
                Some(json!({ "user_name": "mallory", "display_name": "Mallory" })),
            ),
            ("PUT", format!("/api/directory-users/{id}"), Some(grace)),
            (
                "POST",
                format!("/api/directory-users/{id}/setup-link"),
                None,
            ),
            (
                "DELETE",
                format!("/api/directory-users/{id}/passkeys"),
                None,
            ),
            ("DELETE", format!("/api/directory-users/{id}"), None),
            ("GET", "/api/directory-groups".to_owned(), None),
            (
                "POST",
                "/api/directory-groups".to_owned(),
                Some(json!({ "name": "mallory" })),
            ),
            (
                "POST",
                format!("/api/directory-groups/{group}/members"),
                Some(json!({ "user_id": id })),
            ),
            ("DELETE", format!("/api/directory-groups/{group}"), None),
            ("GET", "/api/permission-sets".to_owned(), None),
            (
                "POST",
                "/api/permission-sets".to_owned(),
                Some(json!({ "name": "Mallory" })),
            ),
            ("GET", "/api/assignments".to_owned(), None),
            ("GET", "/api/organization".to_owned(), None),
        ] {
            let (status, answer) = intruder.send(method, &path, body).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {answer}");
        }
        assert!(
            store::directory_access(&client)
                .await
                .unwrap()
                .get(&uuid::Uuid::parse_str(&id).unwrap())
                .is_none_or(|a| !a.link_pending)
        );
        assert_eq!(
            admin
                .send("GET", "/api/directory-users", None)
                .await
                .1
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    /// Cairn's own directory in the console: users changed, groups made,
    /// changed and deleted, members put in and taken out; and a permission
    /// set whose roles don't hold its latest version provisioned again.
    #[tokio::test]
    async fn manages_the_own_directory_and_provisions() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = console_of(&app);
        let client = app.pool.get().await.unwrap();
        let account = crate::users::account(&client).await.unwrap();
        let mut admin = signed_in(&console, "admin", true).await;
        let mut tenant = signed_in(&console, "tenant", false).await;

        let grace =
            json!({ "user_name": "grace", "display_name": "Grace", "email": "grace@example.com" });
        let (_, made) = admin
            .send("POST", "/api/directory-users", Some(grace))
            .await;
        let id = made["id"].as_str().unwrap().to_owned();
        let change = json!({ "user_name": "ghopper", "display_name": "Grace Hopper", "given_name": "Grace", "family_name": "Hopper" });
        assert_eq!(
            tenant
                .send(
                    "PUT",
                    &format!("/api/directory-users/{id}"),
                    Some(change.clone())
                )
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        let (status, err) = admin
            .send("PUT", &format!("/api/directory-users/{id}"), Some(change))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
        let (_, users) = admin.send("GET", "/api/directory-users", None).await;
        let user = &users[0];
        assert_eq!(
            (
                &user["user_name"],
                &user["display_name"],
                &user["given_name"],
                &user["family_name"],
                &user["email"]
            ),
            (
                &json!("ghopper"),
                &json!("Grace Hopper"),
                &json!("Grace"),
                &json!("Hopper"),
                &Value::Null
            )
        );
        let bad = json!({ "user_name": "has space", "display_name": "x" });
        assert_eq!(
            admin
                .send("PUT", &format!("/api/directory-users/{id}"), Some(bad))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );

        assert_eq!(
            tenant
                .send(
                    "POST",
                    "/api/directory-groups",
                    Some(json!({ "name": "data" }))
                )
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        let (status, made) = admin
            .send(
                "POST",
                "/api/directory-groups",
                Some(json!({ "name": "data", "description": "Analysts" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{made}");
        let group = made["id"].as_str().unwrap().to_owned();
        assert_eq!(
            admin
                .send(
                    "POST",
                    "/api/directory-groups",
                    Some(json!({ "name": "data" }))
                )
                .await
                .0,
            StatusCode::CONFLICT
        );
        let renamed = json!({ "name": "analysts", "description": null });
        assert_eq!(
            admin
                .send(
                    "PUT",
                    &format!("/api/directory-groups/{group}"),
                    Some(renamed)
                )
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        let members = format!("/api/directory-groups/{group}/members");
        assert_eq!(
            admin
                .send("POST", &members, Some(json!({ "user_id": id })))
                .await
                .0,
            StatusCode::CREATED
        );
        assert_eq!(
            admin
                .send("POST", &members, Some(json!({ "user_id": id })))
                .await
                .0,
            StatusCode::CONFLICT
        );
        let (_, groups) = admin.send("GET", "/api/directory-groups", None).await;
        assert_eq!(
            (
                &groups[0]["name"],
                &groups[0]["description"],
                &groups[0]["members"]
            ),
            (&json!("analysts"), &Value::Null, &json!(1))
        );
        assert_eq!(groups[0]["memberships"][0]["user_name"], "ghopper");
        let membership = groups[0]["memberships"][0]["id"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            admin
                .send(
                    "DELETE",
                    &format!("/api/directory-groups/x/members/{membership}"),
                    None
                )
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            admin
                .send("DELETE", &format!("{members}/{membership}"), None)
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            admin.send("GET", "/api/directory-groups", None).await.1[0]["members"],
            json!(0)
        );
        assert_eq!(
            admin
                .send("DELETE", &format!("/api/directory-groups/{group}"), None)
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        assert!(
            admin
                .send("GET", "/api/directory-groups", None)
                .await
                .1
                .as_array()
                .unwrap()
                .is_empty()
        );

        // A set changed without provisioning (as sso-admin's writes leave
        // it) is provisioned again.
        assert_eq!(
            admin
                .send(
                    "POST",
                    "/api/permission-sets",
                    Some(json!({ "name": "Readers" }))
                )
                .await
                .0,
            StatusCode::CREATED
        );
        let assign =
            json!({ "permission_set": "Readers", "principal_type": "USER", "principal_id": id });
        assert_eq!(
            admin.send("POST", "/api/assignments", Some(assign)).await.0,
            StatusCode::CREATED
        );
        let set = crate::identity_center::load(&client, &account, "Readers")
            .await
            .unwrap()
            .unwrap();
        let document = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}"#;
        crate::identity_center::set_inline_policy(&client, &set, Some(document))
            .await
            .unwrap();
        let (_, sets) = admin.send("GET", "/api/permission-sets", None).await;
        assert_eq!(
            (&sets[0]["account_id"], &sets[0]["provisioned"][0]["latest"]),
            (&json!(account), &json!(false))
        );
        assert_eq!(
            tenant
                .send("POST", "/api/permission-sets/Readers/provision", None)
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            admin
                .send("POST", "/api/permission-sets/Readers/provision", None)
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            admin.send("GET", "/api/permission-sets", None).await.1[0]["provisioned"][0]["latest"],
            json!(true)
        );
    }

    /// The organization's structure and SCPs in the console: units made,
    /// renamed and deleted, accounts moved, SCPs enabled, made, attached,
    /// detached and disabled, as Organizations' API does them.
    #[tokio::test]
    async fn the_organization_has_units_and_scps() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = console_of(&app);
        let mut admin = signed_in(&console, "admin", true).await;
        let mut tenant = signed_in(&console, "tenant", false).await;
        assert_eq!(
            tenant.send("GET", "/api/organization", None).await.0,
            StatusCode::FORBIDDEN
        );
        let (status, o) = admin.send("GET", "/api/organization", None).await;
        assert_eq!(status, StatusCode::OK, "{o}");
        let root = o["root_id"].as_str().unwrap().to_owned();
        assert_eq!(
            (&o["scps_enabled"], &o["policies"][0]["name"], &o["units"]),
            (&json!(false), &json!("FullAWSAccess"), &json!([]))
        );

        let (status, made) = admin
            .send(
                "POST",
                "/api/organization/units",
                Some(json!({ "name": "Teams", "parent_id": root })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{made}");
        let unit = made["id"].as_str().unwrap().to_owned();
        assert_eq!(
            admin
                .send(
                    "POST",
                    "/api/organization/units",
                    Some(json!({ "name": "x", "parent_id": "ou-nope" }))
                )
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            admin
                .send(
                    "PUT",
                    &format!("/api/organization/units/{unit}"),
                    Some(json!({ "name": "Squads" }))
                )
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        let (_, made) = admin
            .send(
                "POST",
                "/api/accounts",
                Some(json!({ "name": "Team D", "email": "team-d@example.com" })),
            )
            .await;
        let member = made["id"].as_str().unwrap().to_owned();
        let into = json!({ "parent_id": unit });
        assert_eq!(
            tenant
                .send(
                    "PUT",
                    &format!("/api/accounts/{member}/parent"),
                    Some(into.clone())
                )
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            admin
                .send(
                    "PUT",
                    &format!("/api/accounts/{member}/parent"),
                    Some(into.clone())
                )
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            admin
                .send("PUT", &format!("/api/accounts/{member}/parent"), Some(into))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let (_, accounts) = admin.send("GET", "/api/accounts", None).await;
        assert_eq!(accounts[1]["parent_id"], json!(unit));
        assert_eq!(
            admin
                .send("DELETE", &format!("/api/organization/units/{unit}"), None)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );

        assert_eq!(
            admin.send("PUT", "/api/organization/scps", None).await.0,
            StatusCode::NO_CONTENT
        );
        let (_, o) = admin.send("GET", "/api/organization", None).await;
        assert_eq!(
            (&o["units"][0]["name"], &o["scps_enabled"]),
            (&json!("Squads"), &json!(true))
        );
        let full: Vec<&str> = o["attachments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["target_id"].as_str().unwrap())
            .collect();
        for target in [&root, &unit, &member] {
            assert!(full.contains(&target.as_str()), "{target}: {full:?}");
        }

        let content = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"}]}"#;
        let bad = json!({ "name": "Bad", "content": r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::x"}]}"# });
        assert_eq!(
            admin
                .send("POST", "/api/organization/policies", Some(bad))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let (status, made) = admin
            .send(
                "POST",
                "/api/organization/policies",
                Some(json!({ "name": "NoDelete", "content": content })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{made}");
        let scp = made["id"].as_str().unwrap().to_owned();
        assert_eq!(
            admin
                .send("GET", &format!("/api/organization/policies/{scp}"), None)
                .await
                .1["content"],
            content
        );
        let targets = format!("/api/organization/policies/{scp}/targets");
        assert_eq!(
            admin
                .send("POST", &targets, Some(json!({ "target_id": unit })))
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        let full_access = format!("/api/organization/policies/p-FullAWSAccess/targets/{unit}");
        assert_eq!(
            admin.send("DELETE", &full_access, None).await.0,
            StatusCode::NO_CONTENT
        );
        // Every target keeps one.
        assert_eq!(
            admin
                .send("DELETE", &format!("{targets}/{unit}"), None)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let renamed =
            json!({ "name": "NoDeleting", "description": "Keeps buckets", "content": content });
        assert_eq!(
            admin
                .send(
                    "PUT",
                    &format!("/api/organization/policies/{scp}"),
                    Some(renamed)
                )
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        let (_, o) = admin.send("GET", "/api/organization", None).await;
        assert_eq!(
            (&o["policies"][1]["name"], &o["policies"][1]["description"]),
            (&json!("NoDeleting"), &json!("Keeps buckets"))
        );
        assert_eq!(
            admin
                .send("DELETE", &format!("/api/organization/policies/{scp}"), None)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );

        assert_eq!(
            admin.send("DELETE", "/api/organization/scps", None).await.0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            admin.send("GET", "/api/organization", None).await.1["attachments"],
            json!([])
        );
        assert_eq!(
            admin
                .send("DELETE", &format!("/api/organization/policies/{scp}"), None)
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        let back = json!({ "parent_id": root });
        assert_eq!(
            admin
                .send("PUT", &format!("/api/accounts/{member}/parent"), Some(back))
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            admin
                .send("DELETE", &format!("/api/organization/units/{unit}"), None)
                .await
                .0,
            StatusCode::NO_CONTENT
        );
    }

    /// Bucket and object tags, CORS and websites, set as S3 sets them (and
    /// checked as it checks them), by whom S3's actions allow.
    #[tokio::test]
    async fn edits_tags_cors_and_websites() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = Arc::new(Console {
            app: app.clone(),
            party: party(),
        });
        let client = app.pool.get().await.unwrap();
        let bucket = crate::e2e::BUCKET;
        crate::e2e::put(&app, "t.txt", b"t".to_vec()).await;
        let mut admin = signed_in(&console, "admin", true).await;
        let mut reader = signed_in(&console, "reader", false).await;
        users::grant(
            &client,
            &crate::users::account(&client).await.unwrap(),
            "reader",
            bucket,
            &[users::Permission::Read],
        )
        .await
        .unwrap();

        let tags =
            json!({ "tags": [{ "key": "team", "value": "a" }, { "key": "cost", "value": "1" }] });
        let path = format!("/api/buckets/{bucket}/tags");
        assert_eq!(
            reader.send("PUT", &path, Some(tags.clone())).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            admin.send("PUT", &path, Some(tags)).await.0,
            StatusCode::NO_CONTENT
        );
        let (_, buckets) = admin.send("GET", "/api/buckets", None).await;
        let ours = buckets
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["name"] == bucket)
            .unwrap();
        assert_eq!(
            ours["tags"],
            json!([{ "key": "cost", "value": "1" }, { "key": "team", "value": "a" }])
        );
        // Checked as S3 checks them.
        let bad = json!({ "tags": [{ "key": "aws:reserved", "value": "x" }] });
        let (status, err) = admin.send("PUT", &path, Some(bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
        assert_eq!(
            admin
                .send("PUT", &path, Some(json!({ "tags": [] })))
                .await
                .0,
            StatusCode::NO_CONTENT
        );

        let path = format!("/api/buckets/{bucket}/object/tags?key=t.txt");
        let tags = json!({ "tags": [{ "key": "k", "value": "v" }] });
        assert_eq!(
            reader.send("PUT", &path, Some(tags.clone())).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            admin.send("PUT", &path, Some(tags)).await.0,
            StatusCode::NO_CONTENT
        );
        let (_, info) = admin
            .send(
                "GET",
                &format!("/api/buckets/{bucket}/object?key=t.txt"),
                None,
            )
            .await;
        assert_eq!(
            info["versions"][0]["tags"],
            json!([{ "key": "k", "value": "v" }])
        );

        let path = format!("/api/buckets/{bucket}/cors");
        let (_, cors) = admin.send("GET", &path, None).await;
        assert_eq!(cors["configuration"], Value::Null);
        let rules = json!({ "rules": [{ "origins": ["https://app.example.com"], "methods": ["GET", "PUT"], "headers": ["*"], "max_age": 600 }] });
        assert_eq!(
            admin.send("PUT", &path, Some(rules.clone())).await.0,
            StatusCode::NO_CONTENT
        );
        let (_, cors) = reader.send("GET", &path, None).await;
        assert_eq!(
            cors["configuration"]["rules"][0]["origins"],
            json!(["https://app.example.com"])
        );
        let bad = json!({ "rules": [{ "origins": ["*"], "methods": ["PATCH"] }] });
        let (status, err) = admin.send("PUT", &path, Some(bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
        assert_eq!(
            reader.send("DELETE", &path, None).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            admin.send("DELETE", &path, None).await.0,
            StatusCode::NO_CONTENT
        );

        let path = format!("/api/buckets/{bucket}/website");
        let (_, website) = admin.send("GET", &path, None).await;
        assert_eq!(website["configuration"], Value::Null);
        let site = json!({
            "index_document": "index.html",
            "error_document": "404.html",
            "routing_rules": [{ "condition": { "key_prefix_equals": "docs/" }, "redirect": { "replace_key_prefix_with": "documents/" } }],
        });
        assert_eq!(
            reader.send("PUT", &path, Some(site.clone())).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            admin.send("PUT", &path, Some(site.clone())).await.0,
            StatusCode::NO_CONTENT
        );
        let (_, website) = reader.send("GET", &path, None).await;
        assert_eq!(website["configuration"], site);
        let bad = json!({ "error_document": "404.html" });
        let (status, err) = admin.send("PUT", &path, Some(bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
        assert_eq!(
            reader.send("DELETE", &path, None).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            admin.send("DELETE", &path, None).await.0,
            StatusCode::NO_CONTENT
        );
        let (_, website) = admin.send("GET", &path, None).await;
        assert_eq!(website["configuration"], Value::Null);
    }

    impl Browser {
        /// A part's upload (a raw body): its status and answer.
        async fn put_part(&mut self, path: &str, body: Vec<u8>) -> (StatusCode, Value) {
            let req = Request::builder()
                .method("PUT")
                .uri(path)
                .header("origin", &self.origin)
                .header("x-cairn-ui", "1")
                .header("content-length", body.len())
                .header(
                    "cookie",
                    format!("{COOKIE}={}", self.cookie.as_deref().unwrap_or("")),
                )
                .body(axum::body::Body::from(body))
                .unwrap();
            let resp = router(self.console.clone()).oneshot(req).await.unwrap();
            let status = resp.status();
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
        }
    }

    /// Uploads in parts, as the console's page does for large files: made,
    /// parts put, completed (and the object is the parts'), or aborted;
    /// parts too small are refused at completion, as S3 refuses them.
    #[tokio::test]
    async fn uploads_in_parts() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = Arc::new(Console {
            app: app.clone(),
            party: party(),
        });
        let client = app.pool.get().await.unwrap();
        let bucket = crate::e2e::BUCKET;
        let mut writer = signed_in(&console, "w", false).await;
        let account = crate::users::account(&client).await.unwrap();
        users::grant(
            &client,
            &account,
            "w",
            bucket,
            &[users::Permission::Write, users::Permission::Read],
        )
        .await
        .unwrap();

        let start = |key: &str| json!({ "key": key, "content_type": "application/x-test" });
        let (status, started) = writer
            .send(
                "POST",
                &format!("/api/buckets/{bucket}/uploads"),
                Some(start("big.bin")),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{started}");
        let id = started["upload_id"].as_str().unwrap().to_owned();
        let first = vec![1u8; 5 << 20];
        let (status, one) = writer
            .put_part(
                &format!("/api/buckets/{bucket}/uploads/{id}/parts/1?key=big.bin"),
                first,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{one}");
        let (_, two) = writer
            .put_part(
                &format!("/api/buckets/{bucket}/uploads/{id}/parts/2?key=big.bin"),
                vec![2u8; 10],
            )
            .await;
        let parts = json!({ "parts": [{ "number": 1, "etag": one["etag"] }, { "number": 2, "etag": two["etag"] }] });
        let (status, err) = writer
            .send(
                "POST",
                &format!("/api/buckets/{bucket}/uploads/{id}/complete?key=big.bin"),
                Some(parts),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
        let (_, info) = writer
            .send(
                "GET",
                &format!("/api/buckets/{bucket}/object?key=big.bin"),
                None,
            )
            .await;
        assert_eq!(info["versions"][0]["size"], (5 << 20) + 10);
        assert_eq!(info["versions"][0]["content_type"], "application/x-test");

        // A first part under 5 MiB: refused at completion.
        let (_, started) = writer
            .send(
                "POST",
                &format!("/api/buckets/{bucket}/uploads"),
                Some(start("small.bin")),
            )
            .await;
        let id = started["upload_id"].as_str().unwrap().to_owned();
        let (_, one) = writer
            .put_part(
                &format!("/api/buckets/{bucket}/uploads/{id}/parts/1?key=small.bin"),
                vec![1; 100],
            )
            .await;
        let (_, two) = writer
            .put_part(
                &format!("/api/buckets/{bucket}/uploads/{id}/parts/2?key=small.bin"),
                vec![2; 100],
            )
            .await;
        let parts = json!({ "parts": [{ "number": 1, "etag": one["etag"] }, { "number": 2, "etag": two["etag"] }] });
        let (status, err) = writer
            .send(
                "POST",
                &format!("/api/buckets/{bucket}/uploads/{id}/complete?key=small.bin"),
                Some(parts),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            err["error"]
                .as_str()
                .unwrap()
                .to_lowercase()
                .contains("small"),
            "{err}"
        );
        // Listed, with its parts, and when a lifecycle rule aborts it.
        let list = format!("/api/buckets/{bucket}/uploads");
        let (status, listed) = writer.send("GET", &list, None).await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(
            (listed["count"].as_i64(), listed["bytes"].as_i64()),
            (Some(1), Some(200))
        );
        let upload = &listed["uploads"][0];
        assert_eq!(
            (upload["key"].as_str(), upload["upload_id"].as_str()),
            (Some("small.bin"), Some(id.as_str()))
        );
        assert_eq!(
            (upload["parts"].as_i64(), upload["bytes"].as_i64()),
            (Some(2), Some(200))
        );
        assert!(upload["abort_date"].is_null(), "{upload}");
        client
            .execute(
                r#"UPDATE buckets SET lifecycle = '{"rules":[{"id":"r","enabled":true,"filter":{},"abort_upload_days":1}]}'
                   WHERE name = $1"#,
                &[&bucket],
            )
            .await
            .unwrap();
        let (_, listed) = writer.send("GET", &list, None).await;
        let upload = &listed["uploads"][0];
        assert_eq!(upload["abort_rule"], "r");
        // The midnight (UTC) after it began, and a day.
        let initiated = upload["initiated"].as_f64().unwrap();
        let due = upload["abort_date"].as_f64().unwrap();
        assert_eq!(due % 86400.0, 0.0);
        assert!(
            due > initiated + 86400.0 && due <= initiated + 2.0 * 86400.0,
            "{upload}"
        );
        // Aborted, it's gone.
        let path = format!("/api/buckets/{bucket}/uploads/{id}?key=small.bin");
        assert_eq!(
            writer.send("DELETE", &path, None).await.0,
            StatusCode::NO_CONTENT
        );
        let uploads: i64 = client
            .query_one("SELECT count(*) FROM multipart_uploads", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(uploads, 0);
        let (_, listed) = writer.send("GET", &list, None).await;
        assert_eq!(listed["uploads"], json!([]));
        // Not by someone who may not write there, nor listed by someone
        // who may not list them.
        let mut reader = signed_in(&console, "r", false).await;
        assert_eq!(
            reader.send("GET", &list, None).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            reader
                .send(
                    "POST",
                    &format!("/api/buckets/{bucket}/uploads"),
                    Some(start("x"))
                )
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }

    /// Only the console's own page may sign in: other origins, and requests
    /// without the header, are refused.
    #[tokio::test]
    async fn refuses_requests_from_elsewhere() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = Arc::new(Console {
            app,
            party: party(),
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/login/options")
            .header("origin", party().origin)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router(console.clone()).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // The page itself, at any of its routes.
        let req = Request::builder()
            .uri("/enroll")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router(console).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["content-type"], "text/html; charset=utf-8");
    }

    /// A client may only start signing in so often (each start writes a
    /// challenge), by its address; others aren't held up by it.
    #[tokio::test]
    async fn limits_how_often_a_client_starts_signing_in() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = Arc::new(Console {
            app,
            party: party(),
        });
        let start = |client: &str| {
            let mut req = Request::builder()
                .method("POST")
                .uri("/api/login/options")
                .header("origin", party().origin)
                .header("x-cairn-ui", "1")
                .body(axum::body::Body::empty())
                .unwrap();
            let address: SocketAddr = format!("{client}:50000").parse().unwrap();
            req.extensions_mut().insert(ConnectInfo(address));
            let console = console.clone();
            async move { router(console).oneshot(req).await.unwrap().status() }
        };
        for _ in 0..20 {
            assert_eq!(start("192.0.2.1").await, StatusCode::OK);
        }
        assert_eq!(start("192.0.2.1").await, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(start("192.0.2.2").await, StatusCode::OK);
    }
}
