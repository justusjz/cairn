use std::sync::Arc;

use http_body_util::Full;
use hyper::{Request, Response, StatusCode, body::Bytes};
use uuid::Uuid;

use crate::{
    App,
    body::{ResBody, box_response, channel_body, send_file},
    prune,
};

/// The response for a failed peer request: a bare 500 (peers only check the
/// status; the error itself is logged by the caller).
pub fn error_response(_e: &anyhow::Error) -> Response<ResBody> {
    box_response(empty(StatusCode::INTERNAL_SERVER_ERROR))
}

pub async fn handle(
    req: Request<hyper::body::Incoming>,
    app: Arc<App>,
) -> anyhow::Result<Response<ResBody>> {
    let path = req.uri().path();
    if path == "/prune" {
        // Admin/repair: scan this node and stream a line-per-action report. The
        // timers are node policy (hardcoded); the caller only chooses dry-run vs
        // apply.
        let apply = param(req.uri().query().unwrap_or(""), "apply").as_deref() == Some("true");
        let (tx, body) = channel_body();
        tokio::spawn(prune::run(app.clone(), apply, tx));
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(body)
            .unwrap());
    }
    if let Some(part_id) = path.strip_prefix("/parts/") {
        // Parse the id up front: `part_id` borrows `req` (via `path`), and
        // collecting the body below consumes `req`, so the borrow must end here.
        let part_id = match Uuid::parse_str(part_id) {
            Ok(id) => id,
            Err(_) => return Ok(box_response(empty(StatusCode::BAD_REQUEST))),
        };
        // Clone the method so the PUT arm can still consume `req`'s body.
        return match req.method().clone() {
            hyper::Method::GET => {
                // Dumb data plane: stream whatever bytes we hold from disk — the
                // whole part, or just `?offset=&length=` of it — or 404 so the
                // reader can fall through to another replica.
                let range = parse_range(req.uri().query().unwrap_or(""));
                match app.store.open_part(part_id).await? {
                    Some(file) => {
                        let (tx, body) = channel_body();
                        tokio::spawn(async move {
                            if let Err(e) = send_file(file, range, &tx).await {
                                let _ = tx.send(Err(e)).await;
                            }
                        });
                        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .body(body)
                            .unwrap())
                    }
                    None => Ok(box_response(empty(StatusCode::NOT_FOUND))),
                }
            }
            hyper::Method::PUT => {
                // Stream the body straight to disk (and announce the location),
                // without buffering the whole part in memory.
                crate::write_part_streaming(&app, part_id, req.into_body()).await?;
                Ok(box_response(empty(StatusCode::OK)))
            }
            hyper::Method::DELETE => {
                // Best-effort happy-path reap: the coordinator dropped this part's
                // catalog rows and is asking us to delete the file now (idempotent;
                // a missing file is fine). The GC is the backstop if this is missed.
                app.store.remove_part(part_id).await?;
                Ok(box_response(empty(StatusCode::OK)))
            }
            _ => Ok(box_response(empty(StatusCode::METHOD_NOT_ALLOWED))),
        };
    }
    Ok(box_response(empty(StatusCode::NOT_FOUND)))
}

fn empty(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// Reads a raw (undecoded) query parameter — peer params are simple
/// flags/integers, so no percent-decoding is needed.
fn param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|p| {
        let (k, v) = p.split_once('=')?;
        (k == name).then(|| v.to_owned())
    })
}

/// Parses an `?offset=&length=` part range; both must be present, else the whole
/// part is served.
fn parse_range(query: &str) -> Option<(u64, u64)> {
    let offset = param(query, "offset")?.parse().ok()?;
    let length = param(query, "length")?.parse().ok()?;
    Some((offset, length))
}
