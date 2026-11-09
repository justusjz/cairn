//! The peer endpoint: blob traffic between nodes, each node's metrics, and
//! the dashboard. Unauthenticated, for the private network only.

use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    extract::{Path, RawQuery, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{any, get},
};
use http_body_util::{BodyExt, Empty};
use hyper::{
    Request,
    body::{Bytes, Frame},
};
use hyper_util::{
    client::legacy::{Client, ResponseFuture, connect::HttpConnector},
    rt::{TokioExecutor, TokioTimer},
};
use uuid::Uuid;

use crate::{
    App, blob_file,
    body::{ResBody, channel_body, send_file},
    checksum::BlockLayout,
    gc, packer,
};

/// Response header of a blob PUT: the hex CRC64/NVME of the file the replica
/// stored (the data plus its checksum table and blob ID).
pub const CRC64_HEADER: &str = "x-cairn-crc64nvme";

/// How long a connection to a peer may sit idle in the pool before it's
/// closed. A peer's server never closes one itself (`axum::serve` sets no
/// timer, so hyper's header read timeout doesn't apply), so this is what keeps
/// connections to nodes that are rarely talked to from staying open for good.
const IDLE_TIMEOUT: Duration = Duration::from_secs(20);

/// The HTTP client that every request to another node goes through: one per
/// process, so that connections to a peer are kept open and reused, rather
/// than opened anew for every blob that's read, written or reaped. Cheap to
/// clone; the clones share the pool. HTTP/1.1, so that every transfer has a
/// connection (and TCP flow) of its own.
#[derive(Clone)]
pub struct PeerClient(Client<HttpConnector, ResBody>);

impl PeerClient {
    pub fn new() -> PeerClient {
        // Without TCP_NODELAY, a request's small writes on a reused connection
        // wait for the ACK of the response before (Nagle's algorithm), which
        // the peer delays: tens of milliseconds per request.
        let mut connector = HttpConnector::new();
        connector.set_nodelay(true);
        PeerClient(
            Client::builder(TokioExecutor::new())
                .pool_idle_timeout(IDLE_TIMEOUT)
                .pool_timer(TokioTimer::new())
                .build(connector),
        )
    }

    pub fn request(&self, req: Request<ResBody>) -> ResponseFuture {
        self.0.request(req)
    }

    /// The body of a request that has none.
    pub fn empty() -> ResBody {
        Empty::new().map_err(|never| match never {}).boxed_unsync()
    }
}

/// A failed peer request: a bare 500, since peers only check the status. The
/// error itself is logged.
struct Failed(anyhow::Error);

impl IntoResponse for Failed {
    fn into_response(self) -> Response {
        eprintln!("peer request failed: {:#}", self.0);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for Failed {
    fn from(e: E) -> Self {
        Failed(e.into())
    }
}

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/maintain", any(maintain))
        .route("/stats", get(stats))
        .route(
            "/blobs/{blob_id}",
            get(get_blob).put(put_blob).delete(delete_blob),
        )
        .nest(
            crate::dashboard::PREFIX,
            crate::dashboard::router(app.clone()),
        )
        // `nest` doesn't match the prefix with a trailing slash.
        .route("/", get(to_dashboard))
        .route(&format!("{}/", crate::dashboard::PREFIX), get(to_dashboard))
        .with_state(app)
}

async fn to_dashboard() -> Redirect {
    Redirect::to(crate::dashboard::PREFIX)
}

/// For tests: runs a maintenance pass now (as the background one would, but
/// sweeping everything), and reports what it did once it's done (a failed
/// packing job is only logged).
async fn maintain(State(app): State<Arc<App>>) -> Result<Response, Failed> {
    let mut report = format!("gc: {}\n", gc::pass(&app, gc::Scope::everything()).await);
    for job in packer::pass(&app).await? {
        report.push_str(&format!("packer: {job}\n"));
    }
    Ok((
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        report,
    )
        .into_response())
}

/// This node's own metrics, for the dashboard of whichever node it's open on.
async fn stats(State(app): State<Arc<App>>) -> axum::Json<crate::dashboard::NodeStats> {
    axum::Json(crate::dashboard::node_stats(&app).await)
}

/// Dumb data plane: streams whatever bytes we hold from disk — the whole blob,
/// or just `?offset=&length=` of it — or 404 so the reader can fall through to
/// another replica. For a block-aligned range of a checksummed blob, the reader
/// sends the blob's size and block size from the catalog
/// (`?blob_size=&block_size=`); we check our file against them and send the
/// range's block checksums from the file first. The reader verifies the bytes
/// against them, so we don't have to.
async fn get_blob(
    State(app): State<Arc<App>>,
    Path(blob_id): Path<String>,
    RawQuery(query): RawQuery,
) -> Result<Response, Failed> {
    let Ok(blob_id) = Uuid::parse_str(&blob_id) else {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    };
    let query = query.unwrap_or_default();
    let range = parse_range(&query);
    let layout = parse_layout(&query);
    let Some(mut file) = app.store.open_blob(blob_id).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let crcs = match (layout, range) {
        (Some(layout), Some((offset, length))) => {
            match blob_file::open_range(&mut file, blob_id, layout, offset, length).await {
                Ok(crcs) => Some(crcs),
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::InvalidData {
                        eprintln!("CORRUPTION: blob {blob_id}: {e}");
                    }
                    return Err(e.into());
                }
            }
        }
        (Some(_), None) => return Ok(StatusCode::BAD_REQUEST.into_response()),
        (None, _) => None,
    };
    let (tx, body) = channel_body();
    tokio::spawn(async move {
        if let Some(crcs) = crcs
            && tx.send(Ok(Frame::data(Bytes::from(crcs)))).await.is_err()
        {
            return;
        }
        if let Err(e) = send_file(file, range, &tx).await {
            let _ = tx.send(Err(e)).await;
        }
    });
    Ok(Body::new(body).into_response())
}

/// Streams the body straight to disk (and announces the location), without
/// buffering the whole blob in memory. Answers with the CRC of the file we
/// stored, so the writer can check that we got exactly the bytes it sent.
async fn put_blob(
    State(app): State<Arc<App>>,
    Path(blob_id): Path<String>,
    body: Body,
) -> Result<Response, Failed> {
    let Ok(blob_id) = Uuid::parse_str(&blob_id) else {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    };
    let crc = crate::write_blob_streaming(&app, blob_id, body).await?;
    let crc = HeaderValue::from_str(&format!("{crc:016x}"))?;
    Ok(([(CRC64_HEADER, crc)], ()).into_response())
}

/// Best-effort happy-path reap: the coordinator dropped this blob's catalog
/// rows and is asking us to delete the file now (idempotent; a missing file is
/// fine). The GC is the backstop if this is missed.
async fn delete_blob(
    State(app): State<Arc<App>>,
    Path(blob_id): Path<String>,
) -> Result<Response, Failed> {
    let Ok(blob_id) = Uuid::parse_str(&blob_id) else {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    };
    app.store.remove_blob(blob_id).await?;
    Ok(StatusCode::OK.into_response())
}

/// Reads a raw (undecoded) query parameter — peer params are simple
/// flags/integers, so no percent-decoding is needed.
fn param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|p| {
        let (k, v) = p.split_once('=')?;
        (k == name).then(|| v.to_owned())
    })
}

/// Parses a checksummed blob's `?blob_size=&block_size=`; both must be present,
/// else the blob is read without checksums.
fn parse_layout(query: &str) -> Option<BlockLayout> {
    let blob_size = param(query, "blob_size")?.parse().ok()?;
    let block_size = param(query, "block_size")?.parse().ok()?;
    Some(BlockLayout {
        block_size,
        blob_size,
    })
}

/// Parses an `?offset=&length=` blob range; both must be present, else the whole
/// blob is served.
fn parse_range(query: &str) -> Option<(u64, u64)> {
    let offset = param(query, "offset")?.parse().ok()?;
    let length = param(query, "length")?.parse().ok()?;
    Some((offset, length))
}
