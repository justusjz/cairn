//! The console: Cairn's web UI, with a sign-in of its own (passkeys, or an
//! OIDC provider), on its own listener (`--listen-console`) and origin
//! (`--console-url`). An account's people manage its buckets, objects and
//! users there; the operator account's (superadmins) watch and run the
//! cluster. See `plans/console.md`.
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
//! in and the login's own passkeys and identities (`api`), and what the
//! session's identity manages (`manage`), as that identity (`actor`).

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

use crate::{App, roles::Principal};

pub(crate) mod actor;
mod api;
pub mod cbor;
mod manage;
pub mod oidc;
pub mod store;
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
    /// The console's origin, if this node serves it: enrollment links are
    /// made from it.
    origin: Option<String>,
}

impl Shared {
    pub fn new(origin: Option<String>) -> Shared {
        Shared { storage: tokio::sync::Mutex::default(), origin }
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
    let uri: Uri = text.parse().map_err(|e| format!("{text:?} isn't a URL: {e}"))?;
    let (Some(scheme), Some(host)) = (uri.scheme_str(), uri.host()) else {
        return Err(format!("{text:?} isn't an absolute URL"));
    };
    let host = host.to_ascii_lowercase();
    if !matches!(uri.path(), "" | "/") || uri.query().is_some() {
        return Err("the console's URL must be just an origin, served from its root (no path)".into());
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
    let api = api.layer(axum::extract::DefaultBodyLimit::max(MAX_SIGN_IN_BODY));
    // What the session's identity manages, as that identity.
    let (managed, _) = manage::router().split_for_parts();
    let managed = managed
        .layer(middleware::from_fn_with_state(console.clone(), as_user))
        .with_state(console.app.clone());
    let api = api
        .merge(managed)
        .fallback(|| async { ApiError::NotFound("no such API route".into()) })
        .layer(middleware::from_fn_with_state(console.clone(), require_same_origin))
        .layer(middleware::map_response(|mut resp: Response| async {
            resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }));
    Router::new()
        .nest("/api", api)
        .route("/api/openapi.json", get(|| async { Json(openapi()) }))
        .fallback(static_file)
        .layer(middleware::map_response(web::security_headers))
        .with_state(console)
}

/// Refuses requests that change something unless they come from the
/// console's own page: its origin, with the header.
async fn require_same_origin(State(console): State<Arc<Console>>, req: Request, next: Next) -> Response {
    if !matches!(*req.method(), Method::GET | Method::HEAD) {
        let origin = req.headers().get(header::ORIGIN).and_then(|o| o.to_str().ok());
        if origin != Some(console.party.origin.as_str()) {
            return ApiError::Forbidden(format!("requests must come from {}", console.party.origin)).into_response();
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
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip());
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

async fn user_of(
    console: &Console,
    method: Method,
    headers: HeaderMap,
    query: String,
    peer: Option<std::net::IpAddr>,
) -> Result<actor::User, ApiError> {
    let unauthorized = || ApiError::Unauthorized("sign in first".into());
    let token = session_token(&headers).ok_or_else(unauthorized)?;
    let client = console.app.pool.get().await?;
    let session = store::session(&client, &token).await?.ok_or_else(unauthorized)?;
    let subject = match &session.identity.user {
        Some(user) => actor::Subject::User(Principal::load_user(&client, user.id).await?.ok_or_else(unauthorized)?),
        None => actor::Subject::Root,
    };
    Ok(actor::User { subject, account: session.identity.account_id, method, headers, query, peer })
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
        .find_map(|c| c.trim().strip_prefix(COOKIE)?.strip_prefix('=').map(str::to_owned))
}

/// A `Set-Cookie` that starts a session.
fn session_cookie(token: &str) -> HeaderValue {
    let max_age = store::SESSION_TTL.as_secs();
    HeaderValue::from_str(&format!("{COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={max_age}"))
        .expect("tokens are URL-safe base64")
}

/// A `Set-Cookie` that ends one.
fn cleared_cookie() -> HeaderValue {
    HeaderValue::from_str(&format!("{COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0")).unwrap()
}

/// The signed-in session of a request: handlers that take it answer 401
/// without one.
pub(crate) struct Signed {
    pub session: store::Session,
    /// The session's token (to switch it).
    pub token: String,
}

impl FromRequestParts<Arc<Console>> for Signed {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, console: &Arc<Console>) -> Result<Self, ApiError> {
        let unauthorized = || ApiError::Unauthorized("sign in first".into());
        let token = session_token(&parts.headers).ok_or_else(unauthorized)?;
        let client = console.app.pool.get().await?;
        let session = store::session(&client, &token).await?.ok_or_else(unauthorized)?;
        Ok(Signed { session, token })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_https_origins_and_localhost() {
        let party = parse_url("https://Console.Example.com/").unwrap();
        assert_eq!((party.id.as_str(), party.origin.as_str()), ("console.example.com", "https://console.example.com"));
        let party = parse_url("https://console.example.com:443").unwrap();
        assert_eq!(party.origin, "https://console.example.com");
        let party = parse_url("https://console.example.com:8443").unwrap();
        assert_eq!(party.origin, "https://console.example.com:8443");
        let party = parse_url("http://localhost:9080").unwrap();
        assert_eq!((party.id.as_str(), party.origin.as_str()), ("localhost", "http://localhost:9080"));
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
        headers.append(header::COOKIE, HeaderValue::from_static("a=b; __Host-cairn-session=tok; c=d"));
        assert_eq!(session_token(&headers).as_deref(), Some("tok"));
        let mut headers = HeaderMap::new();
        headers.append(header::COOKIE, HeaderValue::from_static("__Host-cairn-sessionx=tok"));
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
    use crate::roles;

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

    /// The spec is the sign-in API's and `manage`'s, merged: a schema of one
    /// may share a name with one of the other only if it's the same (as
    /// `ErrorBody` is), as it would replace it.
    #[test]
    fn the_apis_schemas_have_names_of_their_own() {
        let schemas = |spec: utoipa::openapi::OpenApi| spec.components.map(|c| c.schemas).unwrap_or_default();
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
        pub(super) async fn send(&mut self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
            let (status, _, body) = self.request(method, path, body).await;
            (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
        }

        /// Sends a request with a JSON body: its status, headers and body.
        pub(super) async fn request(&mut self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, HeaderMap, Vec<u8>) {
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
            let resp = router(self.console.clone()).oneshot(req.body(axum::body::Body::from(body)).unwrap()).await.unwrap();
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
        URL_SAFE_NO_PAD.decode(ceremony["options"]["challenge"].as_str().unwrap()).unwrap()
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

    async fn sign_in(browser: &mut Browser, authenticator: &mut Authenticator) -> (StatusCode, Value) {
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

    /// A user enrolls its first passkey through a link, signs in with it,
    /// adds a second, can't remove its last, and signs out.
    #[tokio::test]
    async fn enrolls_signs_in_and_manages_passkeys() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else { return };
        let client = app.pool.get().await.unwrap();
        roles::create(&client, "ada", None, true).await.unwrap();
        let console = Arc::new(Console { app: app.clone(), party: party() });
        let mut browser = Browser { console: console.clone(), cookie: None, origin: party().origin };

        // Not signed in.
        assert_eq!(browser.send("GET", "/api/me", None).await.0, StatusCode::UNAUTHORIZED);

        // The link.
        let token = store::create_enrollment(&client, &crate::roles::account(&client).await.unwrap(), "ada").await.unwrap();
        let (status, ceremony) = browser.send("POST", "/api/enroll/options", Some(json!({ "token": token }))).await;
        assert_eq!(status, StatusCode::OK, "{ceremony}");
        assert_eq!(ceremony["identity"], "ada @ default");
        assert_eq!(ceremony["options"]["rp"]["id"], "console.example.com");
        assert_eq!(ceremony["options"]["authenticatorSelection"]["userVerification"], "required");
        let mut laptop = Authenticator::p256();
        let mut body = registration(&mut laptop, &ceremony, "Laptop");
        body["token"] = json!(token);
        let (status, me) = browser.send("POST", "/api/enroll", Some(body.clone())).await;
        assert_eq!(status, StatusCode::OK, "{me}");
        assert_eq!(me["name"], "ada @ default");
        assert_eq!(me["identity"]["user"], "ada");
        assert!(me["identity"]["arn"].as_str().unwrap().ends_with(":user/ada"));
        assert_eq!(me["passkeys"][0]["name"], "Laptop");
        assert_eq!(me["passkeys"][0]["current"], true);
        assert!(browser.cookie.is_some());
        // The link is used up, as is the challenge.
        let (status, err) = browser.send("POST", "/api/enroll", Some(body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(err["error"].as_str().unwrap().contains("try again"), "{err}");
        let (status, _) = browser.send("POST", "/api/enroll/options", Some(json!({ "token": token }))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Signed in, it's the user's.
        let (status, me) = browser.send("GET", "/api/me", None).await;
        assert_eq!((status, me["identity"]["user"].as_str()), (StatusCode::OK, Some("ada")));

        // A second passkey; not the same one twice.
        let (_, ceremony) = browser.send("POST", "/api/passkeys/options", None).await;
        assert_eq!(ceremony["options"]["excludeCredentials"].as_array().unwrap().len(), 1);
        let mut phone = Authenticator::ed25519();
        let body = registration(&mut phone, &ceremony, "Phone");
        assert_eq!(browser.send("POST", "/api/passkeys", Some(body)).await.0, StatusCode::NO_CONTENT);
        let (_, ceremony) = browser.send("POST", "/api/passkeys/options", None).await;
        let body = registration(&mut phone, &ceremony, "Phone again");
        let (status, err) = browser.send("POST", "/api/passkeys", Some(body)).await;
        assert_eq!((status, err["error"].as_str()), (StatusCode::BAD_REQUEST, Some("this passkey is registered already")));

        // Signing in with either, in a browser of its own.
        let mut other = Browser { console: console.clone(), cookie: None, origin: party().origin };
        let (status, me) = sign_in(&mut other, &mut phone).await;
        assert_eq!(status, StatusCode::OK, "{me}");
        let current: Vec<_> = me["passkeys"].as_array().unwrap().iter().map(|p| p["current"].as_bool().unwrap()).collect();
        assert_eq!(current, [false, true]);
        // A counter that goes backwards is refused (a cloned authenticator).
        laptop.counter = 10;
        assert_eq!(sign_in(&mut other, &mut laptop).await.0, StatusCode::OK);
        laptop.counter = 3;
        let (status, err) = sign_in(&mut other, &mut laptop).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(err["error"].as_str().unwrap().contains("went backwards"), "{err}");
        // Nor from another origin.
        let mut evil = Browser { console: console.clone(), cookie: None, origin: "https://evil.example.com".into() };
        let (status, _) = evil.send("POST", "/api/login/options", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Removing the phone's passkey ends the sessions signed in with it.
        let phone_id = URL_SAFE_NO_PAD.encode(&phone.credential_id);
        let path = format!("/api/passkeys/{phone_id}");
        assert_eq!(browser.send("PUT", &path, Some(json!({ "name": "Old phone" }))).await.0, StatusCode::NO_CONTENT);
        assert_eq!(browser.send("DELETE", &path, None).await.0, StatusCode::NO_CONTENT);
        let (status, _) = sign_in(&mut other, &mut phone).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // Not the last one.
        let laptop_id = URL_SAFE_NO_PAD.encode(&laptop.credential_id);
        let (status, err) = browser.send("DELETE", &format!("/api/passkeys/{laptop_id}"), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(err["error"].as_str().unwrap().contains("last way"), "{err}");

        // Signing out ends the session.
        assert_eq!(browser.send("POST", "/api/logout", None).await.0, StatusCode::NO_CONTENT);
        assert!(browser.cookie.is_none());
        assert_eq!(browser.send("GET", "/api/me", None).await.0, StatusCode::UNAUTHORIZED);

        // Deleting the user ends everything.
        laptop.counter = 20;
        let (status, _) = sign_in(&mut browser, &mut laptop).await;
        assert_eq!(status, StatusCode::OK);
        roles::delete(&client, &crate::roles::account(&client).await.unwrap(), "ada").await.unwrap();
        assert_eq!(browser.send("GET", "/api/me", None).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(store::reap(&client).await.unwrap(), 0);
    }

    /// The ID of the account named `name`.
    async fn account_id(client: &deadpool_postgres::Object, name: &str) -> String {
        client.query_one("SELECT id FROM accounts WHERE name = $1", &[&name]).await.unwrap().get(0)
    }

    /// The console of node `app`.
    pub(super) fn console_of(app: &Arc<App>) -> Arc<Console> {
        Arc::new(Console { app: app.clone(), party: party() })
    }

    /// A browser signed in as a new superadmin `name` (a user of the
    /// operator account).
    pub(super) async fn superadmin(console: &Arc<Console>, name: &str) -> Browser {
        signed_in_to(console, Some("operator"), name, true).await
    }

    /// A browser signed in as a new user `name` (with a passkey of its own).
    pub(super) async fn signed_in(console: &Arc<Console>, name: &str, admin: bool) -> Browser {
        signed_in_to(console, None, name, admin).await
    }

    /// A browser signed in as a new user `name` of `account` (by name;
    /// `None`: the first tenant account).
    async fn signed_in_to(console: &Arc<Console>, account: Option<&str>, name: &str, admin: bool) -> Browser {
        let client = console.app.pool.get().await.unwrap();
        roles::create_in(&client, account, name, None, admin).await.unwrap();
        let account = match account {
            Some(account) => account_id(&client, account).await,
            None => crate::roles::account(&client).await.unwrap(),
        };
        let token = store::create_enrollment(&client, &account, name).await.unwrap();
        let mut browser = Browser { console: console.clone(), cookie: None, origin: party().origin };
        let (_, ceremony) = browser.send("POST", "/api/enroll/options", Some(json!({ "token": token }))).await;
        let mut body = registration(&mut Authenticator::ed25519(), &ceremony, "Key");
        body["token"] = json!(token);
        assert_eq!(browser.send("POST", "/api/enroll", Some(body)).await.0, StatusCode::OK);
        browser
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
                .header("cookie", format!("{COOKIE}={}", self.cookie.as_deref().unwrap_or("")))
                .body(axum::body::Body::from(body))
                .unwrap();
            router(self.console.clone()).oneshot(req).await.unwrap().status()
        }
    }

    /// The console's buckets and objects are `manage`'s API, as the
    /// signed-in user: what its grants, admin flag and policies allow, and
    /// what a bucket's policy denies it, as over S3.
    #[tokio::test]
    async fn acts_as_the_user_under_its_policies() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else { return };
        let console = Arc::new(Console { app: app.clone(), party: party() });
        let client = app.pool.get().await.unwrap();
        let bucket = crate::e2e::BUCKET;

        // Not signed in: nothing.
        let mut nobody = Browser { console: console.clone(), cookie: None, origin: party().origin };
        assert_eq!(nobody.send("GET", "/api/buckets", None).await.0, StatusCode::UNAUTHORIZED);

        // An admin creates buckets, and sees all of its account's.
        let mut admin = signed_in(&console, "boss", true).await;
        assert_eq!(admin.send("POST", "/api/buckets", Some(json!({ "name": "made-here" }))).await.0, StatusCode::CREATED);
        let (status, buckets) = admin.send("GET", "/api/buckets", None).await;
        assert_eq!(status, StatusCode::OK);
        let names: Vec<_> = buckets.as_array().unwrap().iter().map(|b| b["name"].as_str().unwrap()).collect();
        assert!(names.contains(&bucket) && names.contains(&"made-here"), "{names:?}");
        // And, with `AdministratorAccess`, reads objects too, as AWS's do.
        assert_eq!(admin.send("GET", &format!("/api/buckets/{bucket}/objects"), None).await.0, StatusCode::OK);

        // A user without grants or policies may do nothing.
        let mut none = signed_in(&console, "none", false).await;
        let (_, buckets) = none.send("GET", "/api/buckets", None).await;
        assert_eq!(buckets, json!([]));
        let (status, err) = none.send("GET", &format!("/api/buckets/{bucket}/objects"), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            err["error"].as_str().unwrap(),
            format!(
                "User: arn:aws:iam::{}:user/none is not authorized to perform: s3:ListBucket on resource: \"arn:aws:s3:::{bucket}\" because no identity-based policy allows the s3:ListBucket action",
                roles::account(&client).await.unwrap()
            )
        );

        // A reader sees only its bucket, lists and downloads, but can't write.
        let mut reader = signed_in(&console, "reader", false).await;
        roles::grant(&client, &crate::roles::account(&client).await.unwrap(), "reader", bucket, &[roles::Permission::Read]).await.unwrap();
        let (_, buckets) = reader.send("GET", "/api/buckets", None).await;
        let names: Vec<_> = buckets.as_array().unwrap().iter().map(|b| b["name"].as_str().unwrap()).collect();
        assert_eq!(names, [bucket]);
        assert_eq!(reader.upload(&format!("/api/buckets/{bucket}/object?key=r.txt"), b"no").await, StatusCode::FORBIDDEN);
        assert_eq!(reader.send("POST", "/api/buckets", Some(json!({ "name": "nope-here" }))).await.0, StatusCode::FORBIDDEN);

        // A writer uploads; the reader then lists and reads it.
        let mut writer = signed_in(&console, "writer", false).await;
        roles::grant(&client, &crate::roles::account(&client).await.unwrap(), "writer", bucket, &[roles::Permission::Write]).await.unwrap();
        let path = format!("/api/buckets/{bucket}/object?key=dir%2Fhello.txt");
        assert_eq!(writer.upload(&path, b"hello").await, StatusCode::NO_CONTENT);
        let (status, listing) = reader.send("GET", &format!("/api/buckets/{bucket}/objects?prefix=dir%2F"), None).await;
        assert_eq!(status, StatusCode::OK, "{listing}");
        assert_eq!(listing["entries"][0]["key"], "dir/hello.txt");
        assert_eq!(listing["entries"][0]["size"], 5);
        let (status, info) = reader.send("GET", &format!("/api/buckets/{bucket}/object?key=dir%2Fhello.txt"), None).await;
        assert_eq!(status, StatusCode::OK, "{info}");
        // Not where it's stored: that's the operator's.
        assert_eq!(info["versions"][0]["parts"], Value::Null);
        let req = Request::builder()
            .uri(format!("/api/buckets/{bucket}/download?key=dir%2Fhello.txt"))
            .header("cookie", format!("{COOKIE}={}", reader.cookie.as_deref().unwrap()))
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router(console.clone()).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["content-security-policy"], "sandbox");
        assert!(resp.headers()["content-disposition"].to_str().unwrap().starts_with("attachment"));
        assert_eq!(&resp.into_body().collect().await.unwrap().to_bytes()[..], b"hello");

        // A bucket policy's Deny wins over the writer's grant.
        let account = roles::account(&client).await.unwrap();
        let deny = format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Principal":{{"AWS":"arn:aws:iam::{account}:user/writer"}},"Action":"s3:DeleteObject","Resource":"arn:aws:s3:::{bucket}/*"}}]}}"#
        );
        let (status, err) = admin.send("PUT", &format!("/api/buckets/{bucket}/policy"), Some(json!({ "document": deny }))).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
        let delete = format!("/api/buckets/{bucket}/object?key=dir%2Fhello.txt");
        let (status, err) = writer.send("DELETE", &delete, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(err["error"].as_str().unwrap().ends_with("with an explicit deny in a resource-based policy"), "{err}");
        assert_eq!(admin.send("DELETE", &format!("/api/buckets/{bucket}/policy"), None).await.0, StatusCode::NO_CONTENT);
        // The grants were statements of that policy: the writer has none now.
        assert_eq!(writer.send("DELETE", &delete, None).await.0, StatusCode::FORBIDDEN);
        roles::grant(&client, &crate::roles::account(&client).await.unwrap(), "writer", bucket, &[roles::Permission::Write]).await.unwrap();
        assert_eq!(writer.send("DELETE", &delete, None).await.0, StatusCode::NO_CONTENT);

        // Versioning, as the admin may set it.
        let path = format!("/api/buckets/{bucket}/versioning");
        assert_eq!(writer.send("PUT", &path, Some(json!({ "status": "Enabled" }))).await.0, StatusCode::FORBIDDEN);
        assert_eq!(admin.send("PUT", &path, Some(json!({ "status": "Enabled" }))).await.0, StatusCode::NO_CONTENT);
        let (_, buckets) = admin.send("GET", "/api/buckets", None).await;
        let ours = buckets.as_array().unwrap().iter().find(|b| b["name"] == bucket).unwrap();
        assert_eq!(ours["versioning"], "enabled");

        // The cluster is the operator account's, not a tenant admin's.
        assert_eq!(admin.send("GET", "/api/cluster", None).await.0, StatusCode::FORBIDDEN);

        // Users, as IAM's actions: the admin (AdministratorAccess) manages
        // its account's; a user without IAM permissions may do none of it.
        let (status, err) = writer.send("GET", "/api/roles", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(err["error"].as_str().unwrap().contains("iam:ListUsers"), "{err}");
        let new_user = json!({ "name": "made-in-console", "admin": false });
        assert_eq!(writer.send("POST", "/api/roles", Some(new_user.clone())).await.0, StatusCode::FORBIDDEN);
        let (status, made) = admin.send("POST", "/api/roles", Some(new_user)).await;
        assert_eq!(status, StatusCode::CREATED, "{made}");
        let (_, users) = admin.send("GET", "/api/roles", None).await;
        let names: Vec<_> = users.as_array().unwrap().iter().map(|u| u["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"made-in-console") && names.contains(&"writer"), "{names:?}");
        let (status, _) = admin.send("POST", "/api/roles/made-in-console/keys", None).await;
        assert_eq!(status, StatusCode::CREATED);
        // An inline policy may give a user IAM permissions on itself only,
        // as AWS's self-service policies do.
        let own = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:CreateAccessKey","iam:ListUsers"],"Resource":"arn:aws:iam::*:user/${aws:username}"}]}"#;
        let (status, err) = admin.send("PUT", "/api/roles/writer/policies/self", Some(json!({ "document": own }))).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
        assert_eq!(writer.send("POST", "/api/roles/writer/keys", None).await.0, StatusCode::CREATED);
        assert_eq!(writer.send("POST", "/api/roles/reader/keys", None).await.0, StatusCode::FORBIDDEN);
        // Another account's users are none of its business.
        let client = app.pool.get().await.unwrap();
        crate::accounts::create(&client, "other").await.unwrap();
        roles::create_in(&client, Some("other"), "stranger", None, false).await.unwrap();
        let (status, err) = admin.send("DELETE", "/api/roles/stranger", None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(err["error"], "no user named \"stranger\"");
        let (_, users) = admin.send("GET", "/api/roles", None).await;
        assert!(!users.as_array().unwrap().iter().any(|u| u["name"] == "stranger"));
    }

    /// One login (one passkey) acts in several accounts: as a user of one,
    /// the root of another, and a superadmin of the operator account, which
    /// takes a fresh passkey to switch into. Each account's buckets are its
    /// own: an admin of one may do nothing in another's; its root may do
    /// anything in its own but what its bucket policies deny, and may always
    /// remove a policy that denies it.
    #[tokio::test]
    async fn one_login_acts_in_several_accounts() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else { return };
        let console = Arc::new(Console { app: app.clone(), party: party() });
        let client = app.pool.get().await.unwrap();
        crate::accounts::create(&client, "acme").await.unwrap();
        roles::create(&client, "dora", None, true).await.unwrap();
        roles::create_in(&client, Some("acme"), "dora-acme", None, false).await.unwrap();
        roles::create_in(&client, Some("operator"), "dora-ops", None, false).await.unwrap();

        // A new login, through the default account's link.
        let mut browser = Browser { console: console.clone(), cookie: None, origin: party().origin };
        let mut key = Authenticator::p256();
        let token = store::create_enrollment(&client, &crate::roles::account(&client).await.unwrap(), "dora").await.unwrap();
        let (_, ceremony) = browser.send("POST", "/api/enroll/options", Some(json!({ "token": token }))).await;
        let mut body = registration(&mut key, &ceremony, "Laptop");
        body["token"] = json!(token);
        let (status, me) = browser.send("POST", "/api/enroll", Some(body)).await;
        assert_eq!(status, StatusCode::OK, "{me}");

        // Acme's root, and acme's user: links added to the same login.
        let root = store::create_root_enrollment(&client, "acme").await.unwrap();
        let (status, me) = browser.send("POST", "/api/enroll/link", Some(json!({ "token": root }))).await;
        assert_eq!(status, StatusCode::OK, "{me}");
        assert_eq!((me["identity"]["account"].as_str(), &me["identity"]["user"]), (Some("acme"), &Value::Null));
        assert!(me["identity"]["arn"].as_str().unwrap().ends_with(":root"));
        // One identity per account: not acme's user as well.
        let user = store::create_enrollment(&client, &account_id(&client, "acme").await, "dora-acme").await.unwrap();
        let (status, err) = browser.send("POST", "/api/enroll/link", Some(json!({ "token": user }))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(err["error"].as_str().unwrap().contains("as someone else"), "{err}");

        // Acme's root makes a bucket, which is acme's.
        assert_eq!(browser.send("POST", "/api/buckets", Some(json!({ "name": "acme-data" }))).await.0, StatusCode::CREATED);
        let path = "/api/buckets/acme-data/object?key=a.txt";
        assert_eq!(browser.upload(path, b"acme").await, StatusCode::NO_CONTENT);
        let (_, buckets) = browser.send("GET", "/api/buckets", None).await;
        let names: Vec<_> = buckets.as_array().unwrap().iter().map(|b| b["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["acme-data"]);

        // As the default account's admin: its buckets, not acme's, whose
        // objects it may not touch either (another account's).
        let default_id: String = me["identities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["account"] == "default")
            .unwrap()["account_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let (status, me) = browser.send("POST", "/api/switch", Some(json!({ "account_id": default_id }))).await;
        assert_eq!(status, StatusCode::OK, "{me}");
        assert_eq!(me["identity"]["user"], "dora");
        let (_, buckets) = browser.send("GET", "/api/buckets", None).await;
        let names: Vec<_> = buckets.as_array().unwrap().iter().map(|b| b["name"].as_str().unwrap()).collect();
        assert!(!names.contains(&"acme-data"), "{names:?}");
        assert_eq!(browser.send("GET", "/api/buckets/acme-data/objects", None).await.0, StatusCode::FORBIDDEN);
        assert_eq!(browser.upload(path, b"intruder").await, StatusCode::FORBIDDEN);
        // Nor take its name.
        assert_eq!(browser.send("POST", "/api/buckets", Some(json!({ "name": "acme-data" }))).await.0, StatusCode::CONFLICT);

        // Back as acme's root: a policy that denies everyone everything.
        let acme_id = me["identities"].as_array().unwrap().iter().find(|i| i["account"] == "acme").unwrap()["account_id"].clone();
        assert_eq!(browser.send("POST", "/api/switch", Some(json!({ "account_id": acme_id }))).await.0, StatusCode::OK);
        let deny = r#"{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::acme-data","arn:aws:s3:::acme-data/*"]}]}"#;
        let (status, err) = browser.send("PUT", "/api/buckets/acme-data/policy", Some(json!({ "document": deny }))).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
        let (status, err) = browser.send("GET", "/api/buckets/acme-data/objects", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(err["error"].as_str().unwrap().contains(":root is not authorized"), "{err}");
        // But it can always remove the policy.
        assert_eq!(browser.send("DELETE", "/api/buckets/acme-data/policy", None).await.0, StatusCode::NO_CONTENT);
        assert_eq!(browser.send("GET", "/api/buckets/acme-data/objects", None).await.0, StatusCode::OK);

        // The operator account: linked, then switched into only with a fresh
        // passkey assertion.
        let ops = store::create_enrollment(&client, &account_id(&client, "operator").await, "dora-ops").await.unwrap();
        let (status, me) = browser.send("POST", "/api/enroll/link", Some(json!({ "token": ops }))).await;
        assert_eq!(status, StatusCode::OK, "{me}");
        let ops_id = me["identities"].as_array().unwrap().iter().find(|i| i["operator"] == true).unwrap()["account_id"].clone();
        assert_eq!(browser.send("POST", "/api/switch", Some(json!({ "account_id": acme_id }))).await.0, StatusCode::OK);
        client.execute("UPDATE console_sessions SET verified_at = now() - interval '1 hour'", &[]).await.unwrap();
        let (status, err) = browser.send("POST", "/api/switch", Some(json!({ "account_id": ops_id }))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{err}");
        let (_, ceremony) = browser.send("POST", "/api/login/options", None).await;
        let (client_data, auth_data, sig) = key.assert(&challenge_of(&ceremony));
        let body = json!({
            "account_id": ops_id,
            "challenge_id": ceremony["challenge_id"],
            "credential": {
                "id": URL_SAFE_NO_PAD.encode(&key.credential_id),
                "client_data_json": URL_SAFE_NO_PAD.encode(client_data),
                "authenticator_data": URL_SAFE_NO_PAD.encode(auth_data),
                "signature": URL_SAFE_NO_PAD.encode(sig),
            },
        });
        let (status, me) = browser.send("POST", "/api/switch", Some(body)).await;
        assert_eq!(status, StatusCode::OK, "{me}");
        assert_eq!(me["identity"]["operator"], true);
        // It owns no buckets, and makes none.
        let (_, buckets) = browser.send("GET", "/api/buckets", None).await;
        assert_eq!(buckets, json!([]));
        assert_eq!(browser.send("POST", "/api/buckets", Some(json!({ "name": "ops-data" }))).await.0, StatusCode::FORBIDDEN);

        // Deleting a user unlinks it, and ends the sessions acting as it.
        roles::delete(&client, &account_id(&client, "operator").await, "dora-ops").await.unwrap();
        assert_eq!(browser.send("GET", "/api/me", None).await.0, StatusCode::UNAUTHORIZED);
        let (status, me) = sign_in(&mut browser, &mut key).await;
        assert_eq!(status, StatusCode::OK, "{me}");
        assert_eq!(me["identities"].as_array().unwrap().len(), 2);
    }

    /// The cluster is the operator account's: its admins (superadmins) see
    /// and run it, make accounts, and manage each other, but see no
    /// tenant's objects; a tenant's admin may do none of it.
    #[tokio::test]
    async fn superadmins_run_the_cluster_and_nothing_else() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else { return };
        let console = Arc::new(Console { app: app.clone(), party: party() });
        let client = app.pool.get().await.unwrap();
        let bucket = crate::e2e::BUCKET;
        crate::e2e::put(&app, "secret.txt", b"tenant data".to_vec()).await;
        let mut tenant = signed_in(&console, "tenant-admin", true).await;
        roles::create_in(&client, Some("operator"), "super", None, true).await.unwrap();
        let token = store::create_enrollment(&client, &account_id(&client, "operator").await, "super").await.unwrap();
        let mut ops = Browser { console: console.clone(), cookie: None, origin: party().origin };
        let (_, ceremony) = ops.send("POST", "/api/enroll/options", Some(json!({ "token": token }))).await;
        let mut body = registration(&mut Authenticator::ed25519(), &ceremony, "Key");
        body["token"] = json!(token);
        let (status, me) = ops.send("POST", "/api/enroll", Some(body)).await;
        assert_eq!(status, StatusCode::OK, "{me}");
        assert_eq!(me["identity"]["operator"], true);

        // The cluster.
        for path in ["/api/cluster", "/api/storage", "/api/integrity", "/api/lifecycle", "/api/accounts"] {
            assert_eq!(ops.send("GET", path, None).await.0, StatusCode::OK, "{path}");
            let (status, err) = tenant.send("GET", path, None).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {err}");
        }
        let (status, err) = tenant.send("PUT", "/api/lifecycle/rate", Some(json!({ "rate": 5 }))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{err}");
        assert_eq!(ops.send("PUT", "/api/lifecycle/rate", Some(json!({ "rate": 5 }))).await.0, StatusCode::NO_CONTENT);

        // Accounts: made, and their roots' links.
        assert_eq!(ops.send("POST", "/api/accounts", Some(json!({ "name": "newco" }))).await.0, StatusCode::CREATED);
        assert_eq!(tenant.send("POST", "/api/accounts", Some(json!({ "name": "evilco" }))).await.0, StatusCode::FORBIDDEN);
        let (status, link) = ops.send("POST", "/api/accounts/newco/enrollment", None).await;
        assert_eq!(status, StatusCode::CREATED, "{link}");
        assert!(link["path"].as_str().unwrap().starts_with("/enroll#"));
        let (_, accounts) = ops.send("GET", "/api/accounts", None).await;
        let names: Vec<_> = accounts.as_array().unwrap().iter().map(|a| a["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["default", "newco", "operator"]);

        // Superadmins manage superadmins, and only them.
        let (_, users) = ops.send("GET", "/api/roles", None).await;
        let names: Vec<_> = users.as_array().unwrap().iter().map(|u| u["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["super"]);
        let new = json!({ "name": "super-2", "admin": true });
        assert_eq!(ops.send("POST", "/api/roles", Some(new)).await.0, StatusCode::CREATED);
        assert_eq!(ops.send("DELETE", "/api/roles/tenant-admin", None).await.0, StatusCode::BAD_REQUEST);

        // No tenant's buckets, nor their objects.
        let (_, buckets) = ops.send("GET", "/api/buckets", None).await;
        assert_eq!(buckets, json!([]));
        let path = format!("/api/buckets/{bucket}/objects");
        assert_eq!(ops.send("GET", &path, None).await.0, StatusCode::FORBIDDEN);
        let path = format!("/api/buckets/{bucket}/object?key=secret.txt");
        assert_eq!(ops.send("GET", &path, None).await.0, StatusCode::FORBIDDEN);
    }

    /// Cross-account access, as in AWS: a bucket's policy may name another
    /// account's users (or the account), who then may do what both that
    /// policy and their own policies allow, and nothing that only one does.
    #[tokio::test]
    async fn another_accounts_users_need_both_sides_to_allow() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else { return };
        let console = Arc::new(Console { app: app.clone(), party: party() });
        let client = app.pool.get().await.unwrap();
        let bucket = crate::e2e::BUCKET;
        crate::e2e::put(&app, "shared.txt", b"shared".to_vec()).await;
        let acme = crate::accounts::create(&client, "acme").await.unwrap();
        let mut eve = signed_in_to(&console, Some("acme"), "eve", false).await;
        let mut owner = signed_in(&console, "owner", true).await;
        let path = format!("/api/buckets/{bucket}/object?key=shared.txt");

        // The bucket's policy names eve; her own policies don't allow it.
        let policy = format!(
            r#"{{"Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{acme}:user/eve"}},"Action":"s3:GetObject","Resource":"arn:aws:s3:::{bucket}/*"}}]}}"#
        );
        let (status, err) = owner.send("PUT", &format!("/api/buckets/{bucket}/policy"), Some(json!({ "document": policy }))).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
        assert_eq!(eve.send("GET", &path, None).await.0, StatusCode::FORBIDDEN);
        // Her own policy allows it, as well: now she may.
        let own = format!(r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::{bucket}/*"}}]}}"#);
        roles::put_policy(&client, &acme, "eve", "read-shared", &own).await.unwrap();
        assert_eq!(eve.send("GET", &path, None).await.0, StatusCode::OK);
        // But only what both allow: not listing it.
        assert_eq!(eve.send("GET", &format!("/api/buckets/{bucket}/objects"), None).await.0, StatusCode::FORBIDDEN);
        // Naming the account leaves it to the account's own policies, too.
        let policy = format!(
            r#"{{"Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{acme}"}},"Action":"s3:GetObject","Resource":"arn:aws:s3:::{bucket}/*"}}]}}"#
        );
        let (status, err) = owner.send("PUT", &format!("/api/buckets/{bucket}/policy"), Some(json!({ "document": policy }))).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
        assert_eq!(eve.send("GET", &path, None).await.0, StatusCode::OK);
        roles::delete_policy(&client, &acme, "eve", "read-shared").await.unwrap();
        assert_eq!(eve.send("GET", &path, None).await.0, StatusCode::FORBIDDEN);
        // An account that doesn't exist is no principal.
        let policy = format!(
            r#"{{"Statement":[{{"Effect":"Allow","Principal":{{"AWS":"999999999999"}},"Action":"s3:GetObject","Resource":"arn:aws:s3:::{bucket}/*"}}]}}"#
        );
        let (status, err) = owner.send("PUT", &format!("/api/buckets/{bucket}/policy"), Some(json!({ "document": policy }))).await;
        assert_eq!((status, err["error"].as_str()), (StatusCode::BAD_REQUEST, Some("Invalid principal in policy")));
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
                let value = set.to_str().unwrap().split(';').next().unwrap().split_once('=').unwrap().1;
                self.cookie = (!value.is_empty()).then(|| value.to_owned());
            }
            let location = resp.headers().get(header::LOCATION).map(|l| l.to_str().unwrap().to_owned()).unwrap_or_default();
            (resp.status(), location)
        }

        /// Starts a sign-in at the mock provider: its authorization URL.
        async fn start_oidc(&mut self, body: Value) -> String {
            let (status, answer) = self.send("POST", "/api/oidc/mock/start", Some(body)).await;
            assert_eq!(status, StatusCode::OK, "{answer}");
            answer["url"].as_str().unwrap().to_owned()
        }
    }

    /// Signing in at an OIDC provider: configured by a superadmin, used to
    /// enroll through a link (a new login), to sign in, linked to a login
    /// that has a passkey, unlinked but not as the last way in, and to sign
    /// in again before acting as the operator. Tokens that aren't right are
    /// refused, and an identity linked to no login signs no one in.
    #[tokio::test]
    async fn signs_in_at_any_oidc_provider() {
        use super::oidc::mock::{CLIENT_ID, CLIENT_SECRET, Mock};
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else { return };
        let console = Arc::new(Console { app: app.clone(), party: party() });
        let client = app.pool.get().await.unwrap();
        let mock = Mock::start().await;

        // A superadmin configures it (checked against its discovery).
        let mut ops = signed_in_to(&console, Some("operator"), "op", true).await;
        let config = json!({ "label": "Company SSO", "issuer": mock.issuer, "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET });
        let (status, err) = ops.send("PUT", "/api/oidc-providers/mock", Some(config)).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
        let bad = json!({ "label": "x", "issuer": "https://127.0.0.1:1", "client_id": "c" });
        assert_eq!(ops.send("PUT", "/api/oidc-providers/broken", Some(bad)).await.0, StatusCode::BAD_REQUEST);
        let mut tenant = signed_in(&console, "tenant", true).await;
        let config = json!({ "label": "x", "issuer": mock.issuer, "client_id": "c" });
        assert_eq!(tenant.send("PUT", "/api/oidc-providers/sneaky", Some(config)).await.0, StatusCode::FORBIDDEN);
        let (_, buttons) = Browser { console: console.clone(), cookie: None, origin: party().origin }
            .send("GET", "/api/oidc/providers", None)
            .await;
        assert_eq!(buttons, json!([{ "name": "mock", "label": "Company SSO" }]));

        // An identity no login has: signs in no one.
        let mut stranger = Browser { console: console.clone(), cookie: None, origin: party().origin };
        let url = stranger.start_oidc(json!({ "purpose": "login" })).await;
        assert!(url.starts_with(&format!("{}/authorize?", mock.issuer)), "{url}");
        let (state, code) = mock.code_for(&url, "sub-unknown", "x@example.com");
        let (status, location) = stranger.come_back(&state, &code).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert!(location.starts_with("/login?error="), "{location}");
        assert!(stranger.cookie.is_none());

        // Enrolling through a link: a new login, signed in at the provider.
        roles::create(&client, "sam", None, false).await.unwrap();
        let token = store::create_enrollment(&client, &crate::roles::account(&client).await.unwrap(), "sam").await.unwrap();
        let mut sam = Browser { console: console.clone(), cookie: None, origin: party().origin };
        let url = sam.start_oidc(json!({ "purpose": "enroll", "token": token })).await;
        let (state, code) = mock.code_for(&url, "sub-sam", "sam@example.com");
        let (status, location) = sam.come_back(&state, &code).await;
        assert_eq!((status, location.as_str()), (StatusCode::SEE_OTHER, "/account"));
        let (status, me) = sam.send("GET", "/api/me", None).await;
        assert_eq!(status, StatusCode::OK, "{me}");
        assert_eq!(me["identity"]["user"], "sam");
        assert_eq!(me["signed_in_at"], "mock");
        assert_eq!(me["oidc"], json!([{ "provider": "mock", "label": "Company SSO", "email": "sam@example.com" }]));
        // A state is used once.
        assert!(sam.come_back(&state, &code).await.1.starts_with("/login?error="));

        // Signing in again, in another browser.
        let mut again = Browser { console: console.clone(), cookie: None, origin: party().origin };
        let url = again.start_oidc(json!({ "purpose": "login" })).await;
        let (state, code) = mock.code_for(&url, "sub-sam", "sam@example.com");
        assert_eq!(again.come_back(&state, &code).await.1, "/");
        assert_eq!(again.send("GET", "/api/me", None).await.1["identity"]["user"], "sam");
        // Its last way in can't be unlinked.
        let (status, err) = again.send("DELETE", "/api/oidc/mock", None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(err["error"].as_str().unwrap().contains("last way"), "{err}");

        // A token for another client is refused.
        *mock.audience.lock().unwrap() = "someone-else".into();
        let mut tricked = Browser { console: console.clone(), cookie: None, origin: party().origin };
        let url = tricked.start_oidc(json!({ "purpose": "login" })).await;
        let (state, code) = mock.code_for(&url, "sub-sam", "sam@example.com");
        let (_, location) = tricked.come_back(&state, &code).await;
        assert!(location.contains("another%20client"), "{location}");
        assert!(tricked.cookie.is_none());
        *mock.audience.lock().unwrap() = CLIENT_ID.into();

        // A login with a passkey links the identity, and may then unlink it.
        let url = tenant.start_oidc(json!({ "purpose": "link" })).await;
        let (state, code) = mock.code_for(&url, "sub-tenant", "t@example.com");
        let saved = tenant.cookie.clone();
        assert_eq!(tenant.come_back(&state, &code).await.1, "/account");
        tenant.cookie = saved;
        let (_, me) = tenant.send("GET", "/api/me", None).await;
        assert_eq!(me["oidc"][0]["provider"], "mock");
        // Not to another login, though.
        let url = tenant.start_oidc(json!({ "purpose": "link" })).await;
        let (state, code) = mock.code_for(&url, "sub-sam", "sam@example.com");
        assert!(tenant.come_back(&state, &code).await.1.starts_with("/account?error="));
        assert_eq!(tenant.send("DELETE", "/api/oidc/mock", None).await.0, StatusCode::NO_CONTENT);

        // Signing in again at the provider, to act as the operator.
        let link = store::create_enrollment(&client, &account_id(&client, "operator").await, "op").await.unwrap();
        roles::create_in(&client, Some("operator"), "sam-ops", None, true).await.unwrap();
        let ops_link = store::create_enrollment(&client, &account_id(&client, "operator").await, "sam-ops").await.unwrap();
        let _ = link;
        assert_eq!(sam.send("POST", "/api/enroll/link", Some(json!({ "token": ops_link }))).await.0, StatusCode::OK);
        let (_, me) = sam.send("GET", "/api/me", None).await;
        let ops_id = me["identities"].as_array().unwrap().iter().find(|i| i["operator"] == true).unwrap()["account_id"].clone();
        let default_id = me["identities"].as_array().unwrap().iter().find(|i| i["operator"] == false).unwrap()["account_id"].clone();
        assert_eq!(sam.send("POST", "/api/switch", Some(json!({ "account_id": default_id }))).await.0, StatusCode::OK);
        client.execute("UPDATE console_sessions SET verified_at = now() - interval '1 hour'", &[]).await.unwrap();
        assert_eq!(sam.send("POST", "/api/switch", Some(json!({ "account_id": ops_id }))).await.0, StatusCode::UNAUTHORIZED);
        let url = sam.start_oidc(json!({ "purpose": "reauth", "account_id": ops_id })).await;
        assert!(url.contains("prompt=login"), "{url}");
        let (state, code) = mock.code_for(&url, "sub-sam", "sam@example.com");
        let saved = sam.cookie.clone();
        assert_eq!(sam.come_back(&state, &code).await.1, "/");
        sam.cookie = saved;
        let (_, me) = sam.send("GET", "/api/me", None).await;
        assert_eq!(me["identity"]["operator"], true, "{me}");
    }

    /// Bucket and object tags and CORS, set as S3 sets them (and checked as
    /// it checks them), by whom S3's actions allow.
    #[tokio::test]
    async fn edits_tags_and_cors() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else { return };
        let console = Arc::new(Console { app: app.clone(), party: party() });
        let client = app.pool.get().await.unwrap();
        let bucket = crate::e2e::BUCKET;
        crate::e2e::put(&app, "t.txt", b"t".to_vec()).await;
        let mut admin = signed_in(&console, "admin", true).await;
        let mut reader = signed_in(&console, "reader", false).await;
        roles::grant(&client, &crate::roles::account(&client).await.unwrap(), "reader", bucket, &[roles::Permission::Read]).await.unwrap();

        let tags = json!({ "tags": [{ "key": "team", "value": "a" }, { "key": "cost", "value": "1" }] });
        let path = format!("/api/buckets/{bucket}/tags");
        assert_eq!(reader.send("PUT", &path, Some(tags.clone())).await.0, StatusCode::FORBIDDEN);
        assert_eq!(admin.send("PUT", &path, Some(tags)).await.0, StatusCode::NO_CONTENT);
        let (_, buckets) = admin.send("GET", "/api/buckets", None).await;
        let ours = buckets.as_array().unwrap().iter().find(|b| b["name"] == bucket).unwrap();
        assert_eq!(ours["tags"], json!([{ "key": "cost", "value": "1" }, { "key": "team", "value": "a" }]));
        // Checked as S3 checks them.
        let bad = json!({ "tags": [{ "key": "aws:reserved", "value": "x" }] });
        let (status, err) = admin.send("PUT", &path, Some(bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
        assert_eq!(admin.send("PUT", &path, Some(json!({ "tags": [] }))).await.0, StatusCode::NO_CONTENT);

        let path = format!("/api/buckets/{bucket}/object/tags?key=t.txt");
        let tags = json!({ "tags": [{ "key": "k", "value": "v" }] });
        assert_eq!(reader.send("PUT", &path, Some(tags.clone())).await.0, StatusCode::FORBIDDEN);
        assert_eq!(admin.send("PUT", &path, Some(tags)).await.0, StatusCode::NO_CONTENT);
        let (_, info) = admin.send("GET", &format!("/api/buckets/{bucket}/object?key=t.txt"), None).await;
        assert_eq!(info["versions"][0]["tags"], json!([{ "key": "k", "value": "v" }]));

        let path = format!("/api/buckets/{bucket}/cors");
        let (_, cors) = admin.send("GET", &path, None).await;
        assert_eq!(cors["configuration"], Value::Null);
        let rules = json!({ "rules": [{ "origins": ["https://app.example.com"], "methods": ["GET", "PUT"], "headers": ["*"], "max_age": 600 }] });
        assert_eq!(admin.send("PUT", &path, Some(rules.clone())).await.0, StatusCode::NO_CONTENT);
        let (_, cors) = reader.send("GET", &path, None).await;
        assert_eq!(cors["configuration"]["rules"][0]["origins"], json!(["https://app.example.com"]));
        let bad = json!({ "rules": [{ "origins": ["*"], "methods": ["PATCH"] }] });
        let (status, err) = admin.send("PUT", &path, Some(bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
        assert_eq!(reader.send("DELETE", &path, None).await.0, StatusCode::FORBIDDEN);
        assert_eq!(admin.send("DELETE", &path, None).await.0, StatusCode::NO_CONTENT);
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
                .header("cookie", format!("{COOKIE}={}", self.cookie.as_deref().unwrap_or("")))
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
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else { return };
        let console = Arc::new(Console { app: app.clone(), party: party() });
        let client = app.pool.get().await.unwrap();
        let bucket = crate::e2e::BUCKET;
        let mut writer = signed_in(&console, "w", false).await;
        let account = crate::roles::account(&client).await.unwrap();
        roles::grant(&client, &account, "w", bucket, &[roles::Permission::Write, roles::Permission::Read]).await.unwrap();

        let start = |key: &str| json!({ "key": key, "content_type": "application/x-test" });
        let (status, started) = writer.send("POST", &format!("/api/buckets/{bucket}/uploads"), Some(start("big.bin"))).await;
        assert_eq!(status, StatusCode::CREATED, "{started}");
        let id = started["upload_id"].as_str().unwrap().to_owned();
        let first = vec![1u8; 5 << 20];
        let (status, one) = writer.put_part(&format!("/api/buckets/{bucket}/uploads/{id}/parts/1?key=big.bin"), first).await;
        assert_eq!(status, StatusCode::OK, "{one}");
        let (_, two) = writer.put_part(&format!("/api/buckets/{bucket}/uploads/{id}/parts/2?key=big.bin"), vec![2u8; 10]).await;
        let parts = json!({ "parts": [{ "number": 1, "etag": one["etag"] }, { "number": 2, "etag": two["etag"] }] });
        let (status, err) = writer.send("POST", &format!("/api/buckets/{bucket}/uploads/{id}/complete?key=big.bin"), Some(parts)).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
        let (_, info) = writer.send("GET", &format!("/api/buckets/{bucket}/object?key=big.bin"), None).await;
        assert_eq!(info["versions"][0]["size"], (5 << 20) + 10);
        assert_eq!(info["versions"][0]["content_type"], "application/x-test");

        // A first part under 5 MiB: refused at completion.
        let (_, started) = writer.send("POST", &format!("/api/buckets/{bucket}/uploads"), Some(start("small.bin"))).await;
        let id = started["upload_id"].as_str().unwrap().to_owned();
        let (_, one) = writer.put_part(&format!("/api/buckets/{bucket}/uploads/{id}/parts/1?key=small.bin"), vec![1; 100]).await;
        let (_, two) = writer.put_part(&format!("/api/buckets/{bucket}/uploads/{id}/parts/2?key=small.bin"), vec![2; 100]).await;
        let parts = json!({ "parts": [{ "number": 1, "etag": one["etag"] }, { "number": 2, "etag": two["etag"] }] });
        let (status, err) = writer.send("POST", &format!("/api/buckets/{bucket}/uploads/{id}/complete?key=small.bin"), Some(parts)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(err["error"].as_str().unwrap().to_lowercase().contains("small"), "{err}");
        // Aborted, it's gone.
        let path = format!("/api/buckets/{bucket}/uploads/{id}?key=small.bin");
        assert_eq!(writer.send("DELETE", &path, None).await.0, StatusCode::NO_CONTENT);
        let uploads: i64 = client.query_one("SELECT count(*) FROM multipart_uploads", &[]).await.unwrap().get(0);
        assert_eq!(uploads, 0);
        // Not by someone who may not write there.
        let mut reader = signed_in(&console, "r", false).await;
        assert_eq!(reader.send("POST", &format!("/api/buckets/{bucket}/uploads"), Some(start("x"))).await.0, StatusCode::FORBIDDEN);
    }

    /// Only the console's own page may sign in: other origins, and requests
    /// without the header, are refused.
    #[tokio::test]
    async fn refuses_requests_from_elsewhere() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else { return };
        let console = Arc::new(Console { app, party: party() });
        let req = Request::builder()
            .method("POST")
            .uri("/api/login/options")
            .header("origin", party().origin)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router(console.clone()).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // The page itself, at any of its routes.
        let req = Request::builder().uri("/enroll").body(axum::body::Body::empty()).unwrap();
        let resp = router(console).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["content-type"], "text/html; charset=utf-8");
    }
}
