//! The dashboard: a web UI for watching and managing the cluster, served on the
//! peer endpoint, next to the blob routes. Like the rest of that endpoint it's
//! unauthenticated, and for the private network only.
//!
//! The UI is a single-page app (`ui/`, SolidJS), built to `ui/dist` and
//! embedded in the binary by `build.rs`, which requires it. It talks to the JSON API under
//! `/api/`, which `api` implements. Paths that aren't an API route or a file
//! of the app serve the app's `index.html`, so it can be reloaded at any of
//! its own routes.
//!
//! There's no login, so there's no cookie a cross-site request could ride on;
//! but a page from anywhere, opened in a browser on the private network, could
//! still send requests here. Every request that changes something must carry
//! an `x-cairn-ui` header, which a cross-site form can't set, and which
//! `fetch` can only set cross-site after a CORS preflight that this endpoint
//! never allows.

use std::sync::Arc;

use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header,
};
use serde_json::{Value, json};

use crate::{
    App,
    body::{ResBody, box_response},
    metrics::now_secs,
};

mod api;

/// The largest request body the API accepts.
const MAX_BODY: usize = 64 * 1024;
/// The header that every request changing something must carry.
const CSRF_HEADER: &str = "x-cairn-ui";

/// A file of the built UI.
struct Asset {
    path: &'static str,
    content_type: &'static str,
    body: &'static [u8],
}

// `ASSETS`: every file in `ui/dist`.
include!(concat!(env!("OUT_DIR"), "/dashboard_assets.rs"));

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
    let what = format!("{} {path}", req.method());
    let route = route.to_owned();
    match api::route(req, &app, &route).await {
        Ok(resp) => Ok(resp),
        // A request that can't be carried out as asked isn't a fault.
        Err(e) if e.downcast_ref::<crate::roles::Invalid>().is_some() => {
            Ok(error(StatusCode::BAD_REQUEST, &e.to_string()))
        }
        // Answered here, rather than by the peer endpoint's bare 500, so that
        // the UI can say what happened.
        Err(e) => {
            eprintln!("{what} failed: {e:#}");
            Ok(error_response(&e))
        }
    }
}

/// A file of the UI, or else its `index.html`.
fn static_file(path: &str, method: &Method) -> Response<ResBody> {
    if !matches!(*method, Method::GET | Method::HEAD) {
        return error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
    }
    let asset = ASSETS.iter().find(|a| a.path == path);
    // Vite names the files under /assets/ after their content, so they can be
    // cached for good. A missing one is a stale page asking for an old build.
    let cache = match asset {
        Some(_) if path.starts_with("/assets/") => "public, max-age=31536000, immutable",
        None if path.starts_with("/assets/") => {
            return error(StatusCode::NOT_FOUND, "no such file");
        }
        _ => "no-cache",
    };
    let asset = asset
        .or_else(|| ASSETS.iter().find(|a| a.path == "/index.html"))
        .expect("the UI has an index.html");
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, asset.content_type)
        .header(header::CACHE_CONTROL, cache);
    box_response(
        with_security_headers(resp)
            .body(Full::new(Bytes::from_static(asset.body)))
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
fn error_response(e: &anyhow::Error) -> Response<ResBody> {
    if e.downcast_ref::<crate::Unavailable>().is_some() {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "not enough storage nodes are available",
        );
    }
    if e.downcast_ref::<crate::Contended>().is_some() {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "too many concurrent requests on the same data; please retry",
        );
    }
    error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal error; the node's log has the details",
    )
}

/// What this node knows about itself, for the dashboard of any node (see
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
    fn has_an_index() {
        assert!(ASSETS.iter().any(|a| a.path == "/index.html"));
    }
}
