//! What the console's handlers share: their errors, the built UI's files,
//! and the headers every response gets.
//!
//! The UI is a single-page app (`ui/`, SolidJS), built to `ui/dist` and
//! embedded in the binary by `build.rs`, which requires it. Paths that aren't
//! an API route or a file of the app serve its `index.html`, so it can be
//! reloaded at any of its own routes.

use axum::{
    Json,
    body::Body,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use utoipa::ToSchema;

/// A file of the built UI.
struct Asset {
    path: &'static str,
    content_type: &'static str,
    body: &'static [u8],
}

// `ASSETS`: every file in `ui/dist`.
include!(concat!(env!("OUT_DIR"), "/ui_assets.rs"));

/// Keeps the page from being framed, or from running anything but its own
/// script. A response that sets its own policy (a download) keeps it.
pub(crate) async fn security_headers(mut resp: Response) -> Response {
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

/// The built UI's file at `path`, or else its page (for the app's own
/// routes).
pub(crate) fn serve_asset(path: &str) -> Response {
    let asset = ASSETS.iter().find(|a| a.path == path);
    // Vite names the files under assets/ after their content, so they can be
    // cached for good. A missing one is a stale page asking for an old build.
    let is_asset = path.starts_with("/assets/");
    let cache = match asset {
        Some(_) if is_asset => "public, max-age=31536000, immutable",
        None if is_asset => return StatusCode::NOT_FOUND.into_response(),
        _ => "no-cache",
    };
    let asset = asset
        .or_else(|| ASSETS.iter().find(|a| a.path == "/index.html"))
        .expect("the UI has its pages");
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
    /// Not signed in (the console).
    Unauthorized(String),
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
            ApiError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m),
            ApiError::Forbidden(m) => (StatusCode::FORBIDDEN, m),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, m),
            ApiError::Failed(e) => {
                eprintln!("console request failed: {e:#}");
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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_an_index() {
        assert!(ASSETS.iter().any(|a| a.path == "/index.html"));
    }
}
