//! The admin UI: a web page for watching and managing the cluster, served on
//! `--listen-admin` (off unless set). The page itself is static and embedded in
//! the binary; it talks to the JSON API under `/api/`, which `api` implements.
//!
//! Logging in takes the name and secret of an admin role. A login is a session
//! of this node, kept in memory, so it ends when the node restarts. Every API
//! request checks again that its role still exists, is still an admin, and has
//! the same secret, so deleting, demoting or rotating a role ends its sessions
//! too.
//!
//! The session cookie is `SameSite=Strict`, and every request that changes
//! something must carry an `x-cairn-ui` header, which a cross-site form can't
//! set, so that another site can't make a logged-in browser do anything here.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    App,
    body::{ResBody, box_response},
    metrics::now_secs,
};

mod api;

/// How long a login lasts.
const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
/// How long a failed login takes, to slow down guessing.
const FAILED_LOGIN_DELAY: Duration = Duration::from_secs(1);
/// The largest request body the API accepts.
const MAX_BODY: usize = 64 * 1024;
/// The header that every request changing something must carry.
const CSRF_HEADER: &str = "x-cairn-ui";

const INDEX_HTML: &str = include_str!("ui/index.html");
const APP_JS: &str = include_str!("ui/app.js");
const APP_CSS: &str = include_str!("ui/app.css");

/// The sessions logged into this node's admin UI, by token.
#[derive(Default)]
pub struct Sessions {
    sessions: Mutex<HashMap<String, Session>>,
}

struct Session {
    role: String,
    /// The SHA-256 of the secret the role logged in with: once the secret
    /// changes, the session ends.
    secret: [u8; 32],
    expires: Instant,
}

impl Sessions {
    fn create(&self, role: &str, secret: &str) -> anyhow::Result<String> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("generating token: {e}"))?;
        let token = URL_SAFE_NO_PAD.encode(bytes);
        let mut sessions = self.sessions.lock().unwrap();
        let now = Instant::now();
        sessions.retain(|_, s| s.expires > now);
        sessions.insert(
            token.clone(),
            Session {
                role: role.to_owned(),
                secret: Sha256::digest(secret).into(),
                expires: now + SESSION_TTL,
            },
        );
        Ok(token)
    }

    /// The role and secret hash of a live session.
    fn get(&self, token: &str) -> Option<(String, [u8; 32])> {
        let sessions = self.sessions.lock().unwrap();
        let s = sessions.get(token)?;
        (s.expires > Instant::now()).then(|| (s.role.clone(), s.secret))
    }

    fn remove(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
    }
}

/// Compares two byte strings in time that only depends on their lengths.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The name of this node's session cookie. Cookies don't tell ports apart, so
/// it names the node: several nodes on one host keep their logins apart.
fn cookie_name(app: &App) -> String {
    let id = app.store.get_node_id().simple().to_string();
    format!("cairn_admin_{}", &id[..8])
}

fn session_token(app: &App, req: &Request<Incoming>) -> Option<String> {
    let name = cookie_name(app);
    req.headers()
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| {
            let (k, v) = c.trim().split_once('=')?;
            (k == name).then(|| v.to_owned())
        })
}

/// The role a request is logged in as, if its session is live and the role is
/// still an admin with the secret it logged in with.
async fn logged_in(app: &App, req: &Request<Incoming>) -> anyhow::Result<Option<String>> {
    let Some(token) = session_token(app, req) else {
        return Ok(None);
    };
    let Some((role, secret)) = app.sessions.get(&token) else {
        return Ok(None);
    };
    let row = app
        .pool
        .get()
        .await?
        .query_opt("SELECT secret, admin FROM roles WHERE name = $1", &[&role])
        .await?;
    let valid = row.is_some_and(|r| {
        let current: [u8; 32] = Sha256::digest(r.get::<_, String>(0)).into();
        r.get::<_, bool>(1) && constant_time_eq(&current, &secret)
    });
    if !valid {
        app.sessions.remove(&token);
        return Ok(None);
    }
    Ok(Some(role))
}

pub async fn handle(req: Request<Incoming>, app: Arc<App>) -> anyhow::Result<Response<ResBody>> {
    let path = req.uri().path().to_owned();
    let Some(route) = path.strip_prefix("/api/") else {
        return Ok(static_file(&path, req.method()));
    };
    // Anything but a read must come from the page itself.
    let reading = matches!(*req.method(), Method::GET | Method::HEAD);
    if !reading && !req.headers().contains_key(CSRF_HEADER) {
        return Ok(error(StatusCode::FORBIDDEN, "missing x-cairn-ui header"));
    }
    match (req.method().clone(), route) {
        (Method::POST, "login") => return login(req, &app).await,
        (Method::POST, "logout") => {
            if let Some(token) = session_token(&app, &req) {
                app.sessions.remove(&token);
            }
            let mut resp = json_response(StatusCode::OK, &json!({}));
            resp.headers_mut().insert(
                header::SET_COOKIE,
                format!(
                    "{}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict",
                    cookie_name(&app)
                )
                .parse()?,
            );
            return Ok(resp);
        }
        _ => {}
    }
    let Some(role) = logged_in(&app, &req).await? else {
        return Ok(error(StatusCode::UNAUTHORIZED, "not logged in"));
    };
    let route = route.to_owned();
    match api::route(req, &app, &role, &route).await {
        Ok(resp) => Ok(resp),
        // A request that can't be carried out as asked isn't a fault.
        Err(e) if e.downcast_ref::<crate::roles::Invalid>().is_some() => {
            Ok(error(StatusCode::BAD_REQUEST, &e.to_string()))
        }
        Err(e) => Err(e),
    }
}

async fn login(req: Request<Incoming>, app: &App) -> anyhow::Result<Response<ResBody>> {
    let Some(body) = read_json(req).await? else {
        return Ok(error(StatusCode::BAD_REQUEST, "expected a JSON body"));
    };
    let name = body["name"].as_str().unwrap_or("");
    let secret = body["secret"].as_str().unwrap_or("");
    let row = app
        .pool
        .get()
        .await?
        .query_opt("SELECT secret, admin FROM roles WHERE name = $1", &[&name])
        .await?;
    let Some(row) =
        row.filter(|r| constant_time_eq(r.get::<_, &str>(0).as_bytes(), secret.as_bytes()))
    else {
        tokio::time::sleep(FAILED_LOGIN_DELAY).await;
        return Ok(error(StatusCode::UNAUTHORIZED, "wrong role name or secret"));
    };
    if !row.get::<_, bool>(1) {
        return Ok(error(
            StatusCode::FORBIDDEN,
            &format!("role {name:?} is not an admin"),
        ));
    }
    let token = app.sessions.create(name, secret)?;
    let mut resp = json_response(StatusCode::OK, &json!({ "role": name }));
    resp.headers_mut().insert(
        header::SET_COOKIE,
        format!(
            "{}={token}; Path=/; Max-Age={}; HttpOnly; SameSite=Strict",
            cookie_name(app),
            SESSION_TTL.as_secs()
        )
        .parse()?,
    );
    Ok(resp)
}

/// The page and its assets. Everything else is the page too, so that the page
/// can be reloaded at any of its own paths.
fn static_file(path: &str, method: &Method) -> Response<ResBody> {
    if !matches!(*method, Method::GET | Method::HEAD) {
        return error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
    }
    let (content_type, body) = match path {
        "/app.js" => ("text/javascript; charset=utf-8", APP_JS),
        "/app.css" => ("text/css; charset=utf-8", APP_CSS),
        _ => ("text/html; charset=utf-8", INDEX_HTML),
    };
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-cache");
    box_response(
        with_security_headers(resp)
            .body(Full::new(Bytes::from(body)))
            .unwrap(),
    )
}

/// Headers that keep the page from being framed, or from running anything but
/// its own script.
fn with_security_headers(resp: hyper::http::response::Builder) -> hyper::http::response::Builder {
    resp.header(
        "content-security-policy",
        "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'",
    )
    .header("x-content-type-options", "nosniff")
    .header("x-frame-options", "DENY")
    .header("referrer-policy", "no-referrer")
}

/// Reads a request's JSON body: `None` if it isn't JSON (or is too large).
async fn read_json(req: Request<Incoming>) -> anyhow::Result<Option<Value>> {
    let Ok(body) = Limited::new(req.into_body(), MAX_BODY).collect().await else {
        return Ok(None);
    };
    Ok(serde_json::from_slice(&body.to_bytes()).ok())
}

fn json_response(status: StatusCode, value: &Value) -> Response<ResBody> {
    let resp = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store");
    box_response(
        with_security_headers(resp)
            .body(Full::new(Bytes::from(value.to_string())))
            .unwrap(),
    )
}

fn error(status: StatusCode, message: &str) -> Response<ResBody> {
    json_response(status, &json!({ "error": message }))
}

/// The response for a failed API request. The details are logged, not sent.
pub fn error_response(e: &anyhow::Error) -> Response<ResBody> {
    if e.downcast_ref::<crate::Unavailable>().is_some() {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "not enough storage nodes are available",
        );
    }
    error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal error; the node's log has the details",
    )
}

/// What this node knows about itself, for the admin UI of any node (see
/// `peer`'s `/stats`).
pub fn node_stats(app: &App) -> Value {
    let mut stats = app.metrics.to_json();
    stats["node"] = app.node.into();
    stats["node_id"] = app.store.get_node_id().to_string().into();
    stats["version"] = env!("CARGO_PKG_VERSION").into();
    stats["replication_factor"] = app.replication_factor.into();
    stats["now"] = now_secs().into();
    stats["disk"] = match app.store.disk_space() {
        Ok((total, available)) => json!({ "total": total, "available": available }),
        Err(e) => json!({ "error": e.to_string() }),
    };
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_in_constant_time() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"secret", b"secrets"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn sessions_end() {
        let sessions = Sessions::default();
        let token = sessions.create("admin", "secret123").unwrap();
        let (role, secret) = sessions.get(&token).unwrap();
        assert_eq!(role, "admin");
        assert_eq!(secret, <[u8; 32]>::from(Sha256::digest("secret123")));
        assert!(sessions.get("other").is_none());
        sessions.remove(&token);
        assert!(sessions.get(&token).is_none());
    }
}
