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
    App,
    blob_file::{self, ShardFile},
    body::{ResBody, channel_body, send_file},
    gc, packer,
    shards::{Layout, STRIPE_UNIT},
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
        .route("/scrub", any(scrub))
        .route("/stats", get(stats))
        .route(
            "/blobs/{blob_id}",
            get(get_blob).put(put_blob).delete(delete_blob),
        )
        .route("/blobs/{blob_id}/table", get(get_table))
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

/// Scrubs this node's copies now, unpaced: those due (as the background
/// scrubber would), or with `?all`, every one. For tests, and for an operator
/// who wants to know now. Reports what it found once it's done.
async fn scrub(
    State(app): State<Arc<App>>,
    RawQuery(query): RawQuery,
) -> Result<Response, Failed> {
    let all = query.unwrap_or_default().split('&').any(|p| p == "all" || p.starts_with("all="));
    let scope = if all { crate::scrub::Scope::Everything } else { crate::scrub::Scope::Due };
    let report = crate::scrub::pass(&app, scope, &crate::scrub::Pacer::new(None)).await?;
    Ok((
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("scrub: {report}\n"),
    )
        .into_response())
}

/// This node's own metrics, for the dashboard of whichever node it's open on.
async fn stats(State(app): State<Arc<App>>) -> axum::Json<crate::dashboard::NodeStats> {
    axum::Json(crate::dashboard::node_stats(&app).await)
}

/// Dumb data plane: streams whatever bytes we hold of a blob from disk (our
/// shard of it) — the whole file, or just `?offset=&length=` of its data —
/// or 404 so the reader can fall through to another shard. For a
/// block-aligned range of a checksummed blob, the reader sends the blob's
/// layout from the catalog and which shard it expects us to hold (see
/// `layout_query`); we check our file against them and send the range's
/// block checksums from the file first. The reader verifies the bytes
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
    let expected = parse_layout(&query, blob_id);
    let Some(mut file) = app.store.open_blob(blob_id).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let crcs = match (expected, range) {
        (Some(expected), Some((offset, length))) => {
            match blob_file::open_range(&mut file, &expected, offset, length).await {
                Ok(crcs) => Some(crcs),
                Err(e) => return Err(damaged(&app, blob_id, e)),
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

/// The checksums of shard `?of=`'s blocks over its block-aligned range
/// `?offset=&length=`, from the table our shard's file keeps of it (every
/// coded shard's file has every shard's table): for a reader that decoded
/// that shard, to verify what it decoded. Checks our file as `get_blob` does.
async fn get_table(
    State(app): State<Arc<App>>,
    Path(blob_id): Path<String>,
    RawQuery(query): RawQuery,
) -> Result<Response, Failed> {
    let Ok(blob_id) = Uuid::parse_str(&blob_id) else {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    };
    let query = query.unwrap_or_default();
    let (Some(expected), Some((offset, length)), Some(of)) = (
        parse_layout(&query, blob_id),
        parse_range(&query),
        param(&query, "of").and_then(|v| v.parse().ok()),
    ) else {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    };
    let Some(mut file) = app.store.open_blob(blob_id).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    match blob_file::read_table(&mut file, &expected, of, offset, length).await {
        Ok(crcs) => Ok(Body::from(crcs).into_response()),
        Err(e) => Err(damaged(&app, blob_id, e)),
    }
}

/// A failed read of our file: if it's damaged, it's logged, and flagged for
/// our scrubber, since the reader can't tell this from any other failure.
fn damaged(app: &App, blob_id: Uuid, e: std::io::Error) -> Failed {
    if e.kind() == std::io::ErrorKind::InvalidData {
        eprintln!("CORRUPTION: blob {blob_id}: {e}");
        crate::scrub::suspect(app, blob_id, app.node);
    }
    e.into()
}

/// Streams the body straight to disk (and announces the location), without
/// buffering the whole blob in memory: our shard of the blob, `?shard=`,
/// moved here from node `?replaces=` if given (see `write_blob_streaming`). Answers with the CRC of the file we
/// stored, so the writer can check that we got exactly the bytes it sent.
async fn put_blob(
    State(app): State<Arc<App>>,
    Path(blob_id): Path<String>,
    RawQuery(query): RawQuery,
    body: Body,
) -> Result<Response, Failed> {
    let Ok(blob_id) = Uuid::parse_str(&blob_id) else {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    };
    let query = query.unwrap_or_default();
    let Some(shard) = parse_shard(&query, blob_id) else {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    };
    let replaces = match param(&query, "replaces").map(|v| v.parse::<i32>()) {
        None => None,
        Some(Ok(node)) => Some(node),
        Some(Err(_)) => return Ok(StatusCode::BAD_REQUEST.into_response()),
    };
    let crc = crate::write_blob_streaming(&app, &shard, replaces, body).await?;
    let crc = HeaderValue::from_str(&format!("{crc:016x}"))?;
    Ok(([(CRC64_HEADER, crc)], ()).into_response())
}

/// Best-effort happy-path reap: the coordinator dropped this blob's catalog
/// rows (or moved our shard of it elsewhere) and is asking us to delete the
/// file now (idempotent; a missing file is fine), unless a shard of the blob
/// has moved here since. The GC is the backstop if this is missed.
async fn delete_blob(
    State(app): State<Arc<App>>,
    Path(blob_id): Path<String>,
) -> Result<Response, Failed> {
    let Ok(blob_id) = Uuid::parse_str(&blob_id) else {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    };
    crate::blobs::remove_unplaced(&app, blob_id).await?;
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

/// The query parameters that tell a node which shard file of a blob to
/// expect (see `parse_layout`). A replicated blob's are the same for every
/// shard, as they were before blobs had shards, so that nodes of either
/// version understand each other's reads of them.
pub fn layout_query(file: &ShardFile) -> String {
    let l = file.layout;
    let mut query = format!("&blob_size={}&block_size={}", l.size, l.block_size);
    if !l.replicated() {
        query.push_str(&format!(
            "&data_shards={}&parity_shards={}&stripe_unit={}&shard={}",
            l.data_shards, l.parity_shards, l.stripe_unit, file.shard
        ));
    }
    query
}

/// Parses the shard file that `layout_query` describes. Without
/// `?blob_size=&block_size=`, the blob is from before checksums (or the
/// request is malformed), and is read without them; without the rest, it's
/// replicated.
fn parse_layout(query: &str, blob_id: Uuid) -> Option<ShardFile> {
    let number = |name: &str| param(query, name)?.parse::<u64>().ok();
    let layout = Layout {
        size: number("blob_size")?,
        block_size: number("block_size")?,
        data_shards: number("data_shards").unwrap_or(1) as u32,
        parity_shards: number("parity_shards").unwrap_or(0) as u32,
        stripe_unit: number("stripe_unit").unwrap_or(STRIPE_UNIT as u64),
    };
    if layout.block_size == 0 || layout.data_shards == 0 || layout.stripe_unit == 0 {
        return None;
    }
    let shard = number("shard").unwrap_or(0) as u32;
    (shard < layout.shards().max(1)).then_some(ShardFile { blob_id, layout, shard })
}

/// What a writer asks a node to store (see `write_blob_streaming`):
/// `?shard=`, and for a coded blob its layout too (`layout_query`), whose
/// size is known up front. A replicated blob's shard is streamed, its size
/// unknown until it ends.
fn parse_shard(query: &str, blob_id: Uuid) -> Option<crate::ShardWrite> {
    let shard: u32 = param(query, "shard")?.parse().ok()?;
    match parse_layout(query, blob_id) {
        Some(file) if !file.layout.replicated() && file.shard == shard => Some(crate::ShardWrite::Coded(file)),
        Some(_) => None,
        None => Some(crate::ShardWrite::Replica { blob_id, shard }),
    }
}

/// Parses an `?offset=&length=` blob range; both must be present, else the whole
/// blob is served.
fn parse_range(query: &str) -> Option<(u64, u64)> {
    let offset = param(query, "offset")?.parse().ok()?;
    let length = param(query, "length")?.parse().ok()?;
    Some((offset, length))
}
