//! The dashboard: a web UI for watching and managing the cluster, under
//! [`PREFIX`] on the peer endpoint. Like the rest of that endpoint it's
//! unauthenticated, and for the private network only.
//!
//! Everything lives under the prefix, which can't be a bucket's path (bucket
//! names have no `_`), so that the dashboard can later be served on the S3
//! port too, without taking any of S3's paths.
//!
//! The UI is a single-page app (`ui/`, SolidJS), built to `ui/dist` and
//! embedded in the binary by `build.rs`, which requires it. It talks to the
//! JSON API under `api/`, which `api` implements, and whose OpenAPI spec
//! (`ui/openapi.json`) the UI's types are generated from. Paths that aren't
//! an API route or a file of the app serve the app's `index.html`, so it can
//! be reloaded at any of its own routes.
//!
//! There's no login, so there's no cookie a cross-site request could ride on;
//! but a page from anywhere, opened in a browser on the private network, could
//! still send requests here. Every request that changes something must carry
//! an `x-cairn-ui` header, which a cross-site form can't set, and which
//! `fetch` can only set cross-site after a CORS preflight that this endpoint
//! never allows.
//!
//! That leaves DNS rebinding: a page whose domain is made to resolve to a node
//! is the node's origin as far as the browser is concerned, and can do and
//! read anything. So the dashboard only answers requests whose `Host` is one
//! no attacker can point at it: an IP address, `localhost`, or the host of the
//! node's own `--peer-url`.

use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::time::Instant;

use axum::{
    Json, Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{App, metrics::MetricsReport, metrics::now_secs};

mod api;

use api::{Storage, openapi};

/// Where the dashboard lives.
pub const PREFIX: &str = "/_dashboard";
/// The header that every request changing something must carry.
const CSRF_HEADER: &str = "x-cairn-ui";

/// The dashboard's own state, part of [`App`].
pub struct Dashboard {
    /// The host of the node's peer URL: besides IP addresses and `localhost`,
    /// the one host the dashboard answers to.
    peer_host: Option<String>,
    /// The last `/storage` report, and when it was made. It takes scans of
    /// whole tables, so every page polling it shares one report a while.
    storage: tokio::sync::Mutex<Option<(Instant, Storage)>>,
}

impl Dashboard {
    pub fn new(peer_url: &str) -> Dashboard {
        let peer_host = peer_url
            .parse::<Uri>()
            .ok()
            .and_then(|uri| uri.host().map(str::to_ascii_lowercase));
        Dashboard {
            peer_host,
            storage: tokio::sync::Mutex::default(),
        }
    }
}

/// A file of the built UI.
struct Asset {
    path: &'static str,
    content_type: &'static str,
    body: &'static [u8],
}

// `ASSETS`: every file in `ui/dist`.
include!(concat!(env!("OUT_DIR"), "/dashboard_assets.rs"));

/// The dashboard, to nest under [`PREFIX`].
pub fn router(app: Arc<App>) -> Router<Arc<App>> {
    let (api, _) = api::router().split_for_parts();
    let api = api
        .route("/openapi.json", get(|| async { Json(openapi()) }))
        .fallback(|| async { ApiError::NotFound("no such API route".into()) })
        .layer(middleware::from_fn(require_ui_header))
        .layer(middleware::map_response(|mut resp: Response| async {
            set_default(resp.headers_mut(), header::CACHE_CONTROL, "no-store");
            resp
        }));
    Router::new()
        .nest("/api", api)
        .fallback(static_file)
        .layer(middleware::map_response(security_headers))
        .layer(middleware::from_fn_with_state(app, require_known_host))
}

/// Refuses requests for a host that might be a rebound name (see the module's
/// docs).
async fn require_known_host(State(app): State<Arc<App>>, req: Request, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if !known_host(host, app.dashboard.peer_host.as_deref()) {
        return ApiError::Forbidden(
            "the dashboard only answers to an IP address, localhost, or the node's --peer-url"
                .into(),
        )
        .into_response();
    }
    next.run(req).await
}

/// Whether `host` (a `Host` header, maybe with a port) is an IP address,
/// `localhost` (or a name under it, which browsers resolve to loopback
/// themselves), or `peer_host`.
fn known_host(host: &str, peer_host: Option<&str>) -> bool {
    let name = match host.strip_prefix('[') {
        // An IPv6 address, which must be in brackets.
        Some(rest) => {
            return rest.split_once(']').is_some_and(|(ip, port)| {
                (port.is_empty() || port.starts_with(':')) && ip.parse::<Ipv6Addr>().is_ok()
            });
        }
        None => host.split_once(':').map_or(host, |(name, _)| name),
    };
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    let peer_host = peer_host.map(|p| p.strip_suffix('.').unwrap_or(p));
    !name.is_empty()
        && (name.parse::<IpAddr>().is_ok()
            || name == "localhost"
            || name.ends_with(".localhost")
            || peer_host == Some(&name))
}

/// Refuses requests that change something unless they come from the page.
async fn require_ui_header(req: Request, next: Next) -> Response {
    let reading = matches!(*req.method(), Method::GET | Method::HEAD);
    if !reading && !req.headers().contains_key(CSRF_HEADER) {
        return ApiError::Forbidden("missing x-cairn-ui header".into()).into_response();
    }
    next.run(req).await
}

/// Keeps the page from being framed, or from running anything but its own
/// script. A response that sets its own policy (a download) keeps it.
async fn security_headers(mut resp: Response) -> Response {
    let headers = resp.headers_mut();
    set_default(
        headers,
        header::CONTENT_SECURITY_POLICY,
        "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'",
    );
    set_default(headers, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set_default(headers, header::X_FRAME_OPTIONS, "DENY");
    set_default(headers, header::REFERRER_POLICY, "no-referrer");
    resp
}

fn set_default(headers: &mut HeaderMap, name: header::HeaderName, value: &'static str) {
    headers
        .entry(name)
        .or_insert(HeaderValue::from_static(value));
}

/// A file of the UI, or else its `index.html`.
async fn static_file(method: Method, uri: Uri) -> Response {
    if !matches!(method, Method::GET | Method::HEAD) {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let path = uri.path();
    let asset = ASSETS.iter().find(|a| a.path == path);
    // Vite names the files under /assets/ after their content, so they can be
    // cached for good. A missing one is a stale page asking for an old build.
    let cache = match asset {
        Some(_) if path.starts_with("/assets/") => "public, max-age=31536000, immutable",
        None if path.starts_with("/assets/") => return StatusCode::NOT_FOUND.into_response(),
        _ => "no-cache",
    };
    let asset = asset
        .or_else(|| ASSETS.iter().find(|a| a.path == "/index.html"))
        .expect("the UI has an index.html");
    (
        [
            (header::CONTENT_TYPE, asset.content_type),
            (header::CACHE_CONTROL, cache),
        ],
        Body::from(asset.body),
    )
        .into_response()
}

/// A failed API request. Every error has the same body, [`ErrorBody`].
#[derive(Debug)]
pub(crate) enum ApiError {
    /// The request can't be carried out as asked.
    BadRequest(String),
    Forbidden(String),
    NotFound(String),
    /// It conflicts with how things are, e.g. a name that's taken.
    Conflict(String),
    /// A fault, or too few nodes; logged, and not described to the client.
    Failed(anyhow::Error),
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ErrorBody {
    /// What went wrong, for a person to read.
    error: String,
}

impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(e: E) -> Self {
        let e = e.into();
        match e.downcast::<crate::roles::Invalid>() {
            Ok(invalid) => ApiError::BadRequest(invalid.0),
            Err(e) => ApiError::Failed(e),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Forbidden(m) => (StatusCode::FORBIDDEN, m),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, m),
            ApiError::Failed(e) => {
                eprintln!("dashboard request failed: {e:#}");
                if e.downcast_ref::<crate::Unavailable>().is_some() {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "not enough storage nodes are available".to_owned(),
                    )
                } else if e.downcast_ref::<crate::Contended>().is_some() {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "too many concurrent requests on the same data; please retry".to_owned(),
                    )
                } else {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal error; the node's log has the details".to_owned(),
                    )
                }
            }
        };
        (status, Json(ErrorBody { error: message })).into_response()
    }
}

/// What a node reports about itself, for the dashboard of any node (see
/// `peer`'s `/stats`).
#[derive(Serialize, Deserialize, ToSchema)]
pub struct NodeStats {
    pub node: i32,
    pub node_id: String,
    pub version: String,
    pub replication_factor: usize,
    /// The node's clock, in seconds since the Unix epoch.
    pub now: f64,
    /// The filesystem of its data dir, if it could tell.
    pub disk: Option<Disk>,
    pub disk_error: Option<String>,
    #[serde(flatten)]
    pub metrics: MetricsReport,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct Disk {
    /// Bytes in all.
    pub total: u64,
    /// Bytes Cairn may still write.
    pub available: u64,
}

pub fn node_stats(app: &App) -> NodeStats {
    let (disk, disk_error) = match app.store.disk_space() {
        Ok((total, available)) => (Some(Disk { total, available }), None),
        Err(e) => (None, Some(e.to_string())),
    };
    NodeStats {
        node: app.node,
        node_id: app.store.get_node_id().to_string(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        replication_factor: app.replication_factor,
        now: now_secs(),
        disk,
        disk_error,
        metrics: app.metrics.report(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knows_hosts_that_cant_be_rebound() {
        for host in [
            "10.0.0.1",
            "10.0.0.1:9431",
            "[::1]:9431",
            "[fe80::1]",
            "localhost:9431",
            "LocalHost",
            "app.localhost",
            "node-a.internal:9431",
            "node-a.internal.",
        ] {
            assert!(known_host(host, Some("node-a.internal")), "{host}");
        }
        for host in [
            "",
            "evil.example",
            "evil.example:9431",
            "localhost.evil.example",
            "node-a.internal.evil.example",
            "[::1",
            "[evil.example]",
            "[::1]evil",
        ] {
            assert!(!known_host(host, Some("node-a.internal")), "{host}");
        }
        assert!(!known_host("node-a.internal", None));
    }

    #[test]
    fn has_an_index() {
        assert!(ASSETS.iter().any(|a| a.path == "/index.html"));
    }

    /// The UI's types are generated from `ui/openapi.json`, so it must match
    /// the API. `CAIRN_UPDATE_OPENAPI=1 cargo test openapi` updates it.
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
}
