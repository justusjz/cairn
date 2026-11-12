//! The console: a web UI for an account's people, with a sign-in of its own
//! (passkeys), on its own listener (`--listen-console`) and origin
//! (`--console-url`). See `plans/console.md`.
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
//! The UI is a page of the same app as the dashboard's (`ui/console.html`),
//! built into `ui/dist/console/`, and served from the root here.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{FromRequestParts, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};

use crate::{App, dashboard::ApiError};

mod api;
pub mod cbor;
pub mod store;
pub mod webauthn;

pub use api::openapi;
use webauthn::Party;

/// The session cookie's name. `__Host-`: browsers only take it from a secure
/// origin, for exactly this host, for every path.
const COOKIE: &str = "__Host-cairn-session";
/// The header every request that changes something must carry.
const CSRF_HEADER: &str = "x-cairn-ui";

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

/// The console.
pub fn router(console: Arc<Console>) -> Router {
    let (api, _) = api::router().split_for_parts();
    let api = api
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
        .layer(middleware::map_response(crate::dashboard::security_headers))
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

/// A file of the console's UI, or else its page.
async fn static_file(method: Method, uri: Uri) -> Response {
    if !matches!(method, Method::GET | Method::HEAD) {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let path = format!("/console{}", uri.path());
    crate::dashboard::serve_asset(&path, "/console/console.html")
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
}

impl FromRequestParts<Arc<Console>> for Signed {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, console: &Arc<Console>) -> Result<Self, ApiError> {
        let unauthorized = || ApiError::Unauthorized("sign in first".into());
        let token = session_token(&parts.headers).ok_or_else(unauthorized)?;
        let client = console.app.pool.get().await?;
        let session = store::session(&client, &token).await?.ok_or_else(unauthorized)?;
        Ok(Signed { session })
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
    #[test]
    fn console_openapi_json_is_up_to_date() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/ui/console-openapi.json");
        let spec = openapi().to_pretty_json().unwrap() + "\n";
        if std::env::var_os("CAIRN_UPDATE_OPENAPI").is_some() {
            std::fs::write(path, &spec).unwrap();
            return;
        }
        let committed = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            committed == spec,
            "ui/console-openapi.json is out of date: run `CAIRN_UPDATE_OPENAPI=1 cargo test openapi`, \
             then `npm run gen` in ui/"
        );
    }

    struct Browser {
        console: Arc<Console>,
        cookie: Option<String>,
        origin: String,
    }

    impl Browser {
        async fn send(&mut self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
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
            let status = resp.status();
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
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
        let token = store::create_enrollment(&client, "ada").await.unwrap();
        let (status, ceremony) = browser.send("POST", "/api/enroll/options", Some(json!({ "token": token }))).await;
        assert_eq!(status, StatusCode::OK, "{ceremony}");
        assert_eq!(ceremony["user"], "ada");
        assert_eq!(ceremony["options"]["rp"]["id"], "console.example.com");
        assert_eq!(ceremony["options"]["authenticatorSelection"]["userVerification"], "required");
        let mut laptop = Authenticator::p256();
        let mut body = registration(&mut laptop, &ceremony, "Laptop");
        body["token"] = json!(token);
        let (status, me) = browser.send("POST", "/api/enroll", Some(body.clone())).await;
        assert_eq!(status, StatusCode::OK, "{me}");
        assert_eq!(me["name"], "ada");
        assert!(me["arn"].as_str().unwrap().ends_with(":user/ada"));
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
        assert_eq!((status, me["name"].as_str()), (StatusCode::OK, Some("ada")));

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
        assert!(err["error"].as_str().unwrap().contains("last passkey"), "{err}");

        // Signing out ends the session.
        assert_eq!(browser.send("POST", "/api/logout", None).await.0, StatusCode::NO_CONTENT);
        assert!(browser.cookie.is_none());
        assert_eq!(browser.send("GET", "/api/me", None).await.0, StatusCode::UNAUTHORIZED);

        // Deleting the user ends everything.
        laptop.counter = 20;
        let (status, _) = sign_in(&mut browser, &mut laptop).await;
        assert_eq!(status, StatusCode::OK);
        roles::delete(&client, "ada").await.unwrap();
        assert_eq!(browser.send("GET", "/api/me", None).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(store::reap(&client).await.unwrap(), 0);
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
