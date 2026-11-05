use std::{net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use clap::{Args, Parser, Subcommand};
use deadpool_postgres::{Object, Pool};
use http_body_util::BodyExt;
use hyper::{
    Method, Request, StatusCode, body::Body, body::Bytes, body::Frame,
    server::conn::http1, service::service_fn,
};
use hyper_util::{rt::TokioIo, server::graceful::GracefulShutdown};
use md5::{Digest, Md5};
use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinSet};
use uuid::Uuid;

use crate::db::Cached;
use crate::auth::Rejection;
use crate::blobs::{Location, ReapTarget, reap_blobs};
use crate::body::{FrameSender, channel_body};
use crate::checksum::BlobSummer;
use crate::payload::Payload;
use crate::s3::conditional::Preconditions;
use crate::store::Store;
use crate::writing::WritingSet;

mod peer;

mod auth;
mod aws_chunked;
mod blob_file;
mod blobs;
mod body;
mod checksum;
mod dashboard;
mod db;
#[cfg(test)]
mod e2e;
mod gc;
mod metrics;
mod packer;
mod payload;
mod roles;
mod s3;
mod store;
mod writing;

pub struct App {
    pool: Pool,
    store: Store,
    /// This node's number (`nodes.id`), which locations refer to it by.
    node: i32,
    replication_factor: usize,
    writing: WritingSet,
    pack: packer::Config,
    metrics: Arc<metrics::Metrics>,
    dashboard: dashboard::Dashboard,
    /// Every request to another node goes through this.
    peers: peer::PeerClient,
    /// Lets a test step in at set points of a packing job.
    #[cfg(test)]
    pack_hook: Option<packer::Hook>,
}

#[derive(Parser, Debug)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run a storage node.
    Serve(ServeArgs),
    /// Manage roles: S3 credentials and their bucket permissions.
    Role(roles::RoleArgs),
}

// Every flag can also be set through the environment variable named in its
// help, e.g. `CAIRN_DATA_DIR` for `--data-dir`; a flag given on the command line
// wins.
#[derive(Args, Debug)]
struct ServeArgs {
    /// PostgreSQL connection string, shared by all nodes.
    #[arg(long, env = "CAIRN_DATABASE", hide_env_values = true)]
    database: String,
    /// Bind address for the S3 API.
    #[arg(long, env = "CAIRN_LISTEN_CLIENT")]
    listen_client: String,
    /// Bind address for the peer endpoint (replica traffic between nodes).
    /// It always runs; defaults to a loopback port. Override to bind externally,
    /// or to run several nodes on one host.
    #[arg(long, env = "CAIRN_LISTEN_PEER", default_value = "127.0.0.1:9431")]
    listen_peer: String,
    /// URL other nodes use to reach this node's peer endpoint, e.g.
    /// http://10.0.0.1:9431. Defaults to http://<listen-peer>; set it explicitly
    /// only if the bind address isn't routable (e.g. 0.0.0.0).
    #[arg(long, env = "CAIRN_PEER_URL")]
    peer_url: Option<String>,
    /// How many replicas every blob is stored on.
    #[arg(long, env = "CAIRN_REPLICATION_FACTOR", default_value_t = 1)]
    replication_factor: usize,
    /// Local directory for blobs.
    #[arg(long, env = "CAIRN_DATA_DIR")]
    data_dir: String,
}

/// How often a node refreshes its `nodes` row (last_seen / free_space).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
/// How often a node runs its maintenance pass.
pub(crate) const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Serve(args) => serve_main(args).await,
        Command::Role(args) => roles::role_main(args).await,
    }
}

async fn serve_main(args: ServeArgs) -> anyhow::Result<()> {
    let pool = db::connect(&args.database).await?;
    let store = Store::new(args.data_dir)?;
    // The URL peers use to reach us: explicit if given, otherwise derived from
    // the (always-set) peer bind address.
    let peer_url = args
        .peer_url
        .clone()
        .unwrap_or_else(|| format!("http://{}", args.listen_peer));
    // Register this node before serving traffic, then keep its heartbeat fresh in
    // the background.
    let node = register_node(&pool, &store, &peer_url).await?;
    let app = Arc::new(App {
        pool,
        store,
        node,
        replication_factor: args.replication_factor,
        writing: WritingSet::default(),
        pack: packer::Config::default(),
        metrics: Arc::default(),
        dashboard: dashboard::Dashboard::new(&peer_url),
        peers: peer::PeerClient::new(),
        #[cfg(test)]
        pack_hook: None,
    });
    tokio::spawn(heartbeat(app.clone(), peer_url));
    tokio::spawn(maintain(app.clone()));

    let listen_client_addr = SocketAddr::from_str(&args.listen_client).unwrap();
    let listen_peer_addr = SocketAddr::from_str(&args.listen_peer).unwrap();
    // Both servers run until SIGTERM or Ctrl-C (or until one errors out). Then
    // the S3 API stops accepting connections and finishes the requests in
    // flight, and only after that does the peer endpoint, since those requests
    // may still be reading and writing replicas through it, ours included.
    // Whatever is cut off anyway is left for GC, as after a crash.
    let (stop_peer, peer_stopped) = tokio::sync::oneshot::channel::<()>();
    let client = async {
        let result = serve_client(listen_client_addr, app.clone(), shutdown_signal()).await;
        let _ = stop_peer.send(());
        result
    };
    let peer = serve_peer(listen_peer_addr, app.clone(), async {
        let _ = peer_stopped.await;
    });
    tokio::try_join!(client, peer)?;
    eprintln!("shut down");
    Ok(())
}

/// Resolves on the first SIGTERM (what `docker stop`, Kubernetes and systemd
/// send) or SIGINT (Ctrl-C). A second one exits right away, without waiting
/// for the requests in flight.
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("failed to listen for SIGTERM");
    let mut int = signal(SignalKind::interrupt()).expect("failed to listen for SIGINT");
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
    eprintln!("shutting down: finishing the requests in flight (signal again to exit now)");
    tokio::spawn(async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
        eprintln!("exiting without waiting for the requests in flight");
        std::process::exit(1);
    });
}

/// Background upkeep, on every node, once a minute: garbage collection, then
/// packing. Both work in small steps, so that every pass is cheap.
async fn maintain(app: Arc<App>) {
    let mut sweep = gc::Sweep::new();
    loop {
        tokio::time::sleep(MAINTENANCE_INTERVAL).await;
        app.metrics.pass_started(sweep.position());
        let (task_app, scope) = (app.clone(), sweep.next_scope());
        // A task of its own, so that a panic (a bug) fails this pass, rather
        // than ending maintenance on this node.
        let pass = tokio::spawn(async move {
            let app = task_app;
            let report = gc::pass(&app, scope).await;
            if !report.is_empty() {
                eprintln!("gc: {report}");
            }
            app.metrics.gc_done(&report);
            match packer::pass(&app).await {
                Ok(jobs) => {
                    for job in jobs {
                        eprintln!("packer: {job}");
                        app.metrics.pack_done(&job);
                    }
                }
                Err(e) => {
                    eprintln!("packer: pass failed: {e:#}");
                    app.metrics.pack_failed(format!("pass failed: {e:#}"));
                }
            }
        });
        if let Err(e) = pass.await {
            eprintln!("maintenance pass failed: {e}");
            app.metrics.maintenance_failed(format!("pass failed: {e}"));
        }
        app.metrics.pass_finished();
    }
}

/// Upserts this node's row in `nodes`, returning its number. Used both for the
/// initial registration and for each heartbeat, since both are the same "I'm
/// alive, here's my state" statement.
async fn register_node(pool: &Pool, store: &Store, peer_url: &str) -> anyhow::Result<i32> {
    let client = pool.get().await?;
    let node_id = store.get_node_id().to_string();
    let free_space = store.available_space()? as i64;
    let row = client
        .query_one_cached(
            "INSERT INTO nodes (node_id, peer_url, last_seen, free_space)
             VALUES ($1, $2, NOW(), $3)
             ON CONFLICT (node_id)
             DO UPDATE SET peer_url = $2, last_seen = NOW(), free_space = $3
             RETURNING id",
            &[&node_id, &peer_url, &free_space],
        )
        .await?;
    Ok(row.get(0))
}

async fn heartbeat(app: Arc<App>, peer_url: String) {
    let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
    loop {
        interval.tick().await;
        if let Err(e) = register_node(&app.pool, &app.store, &peer_url).await {
            eprintln!("heartbeat failed: {e}");
        }
    }
}

/// An error caused by storage nodes being down or unreachable (too few live
/// nodes, or a replica failing mid-upload), as opposed to a bug or a database
/// fault. Answered with 503, since retrying once the cluster recovers can succeed.
#[derive(Debug)]
pub struct Unavailable(pub String);

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Unavailable {}

/// A transaction that kept failing with conflicts against concurrent ones
/// (deadlocks, say), and gave up. Answered with 503 SlowDown, so the client
/// backs off and retries.
#[derive(Debug)]
pub struct Contended(pub String);

impl std::fmt::Display for Contended {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Contended {}

/// Serves the S3 API, counting every request in the node's metrics, until
/// `shutdown` resolves; then waits for the requests in flight to finish.
async fn serve_client(
    addr: SocketAddr,
    app: Arc<App>,
    shutdown: impl Future<Output = ()>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let graceful = GracefulShutdown::new();
    tokio::pin!(shutdown);
    loop {
        let (stream, _peer_addr) = tokio::select! {
            accepted = listener.accept() => accepted?,
            () = &mut shutdown => break,
        };
        let io = TokioIo::new(stream);
        let app = app.clone();
        let watcher = graceful.watcher();
        tokio::task::spawn(async move {
            let service = service_fn(move |req| {
                let app = app.clone();
                async move {
                    let what = format!("{} {}", req.method(), req.uri().path());
                    let started = std::time::Instant::now();
                    let in_flight = app.metrics.begin();
                    let op = metrics::Op::classify(
                        req.method(),
                        req.uri().path(),
                        req.uri().query().unwrap_or(""),
                        req.headers(),
                    );
                    let bytes_in = metrics::bytes_in(req.headers());
                    // A handler error must still produce a response: returning
                    // it to hyper would drop the connection without one, which
                    // clients take as a network fault and retry with backoff.
                    let res = s3::handle(req, app.clone()).await.unwrap_or_else(|e| {
                        eprintln!("{what} failed: {e:#}");
                        s3::error_response(&e)
                    });
                    let (parts, body) = res.into_parts();
                    let body =
                        app.metrics
                            .record(op, parts.status, bytes_in, started.elapsed(), body, in_flight);
                    Ok::<_, std::convert::Infallible>(hyper::Response::from_parts(parts, body))
                }
            });
            let conn = http1::Builder::new().serve_connection(io, service);
            if let Err(err) = watcher.watch(conn).await {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
    drop(listener);
    graceful.shutdown().await;
    Ok(())
}

/// Serves the peer endpoint (see `peer`) until `shutdown` resolves; then waits
/// for the requests in flight to finish.
async fn serve_peer(
    addr: SocketAddr,
    app: Arc<App>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, peer::router(app)).with_graceful_shutdown(shutdown).await?;
    Ok(())
}

async fn choose_replicas(client: &Object, count: usize) -> anyhow::Result<Vec<Location>> {
    let nodes = client
        .query_cached(
            "SELECT id, peer_url FROM nodes WHERE last_seen > NOW() - INTERVAL '10 seconds' ORDER BY free_space DESC",
            &[],
        )
        .await?;
    if nodes.len() < count {
        return Err(Unavailable(format!(
            "need {count} replicas but only {} node(s) are live",
            nodes.len()
        ))
        .into());
    }
    Ok(nodes[0..count]
        .iter()
        .map(|n| (n.get("id"), n.get("peer_url")))
        .collect())
}

/// Streams a blob body (one side of the writer's fan-out) to a single
/// replica's peer endpoint, returning the CRC64/NVME the replica reports for
/// the file it stored.
async fn upload_to_replica(
    peers: &peer::PeerClient,
    peer_url: &str,
    blob_id: Uuid,
    body: body::ResBody,
) -> anyhow::Result<u64> {
    let req = Request::builder()
        .method(Method::PUT)
        .uri(format!("{peer_url}/blobs/{blob_id}"))
        .body(body)?;
    let res = peers.request(req).await?;
    if res.status() != StatusCode::OK {
        anyhow::bail!("replica {peer_url} returned status {}", res.status());
    }
    let crc = res
        .headers()
        .get(peer::CRC64_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| u64::from_str_radix(v, 16).ok());
    crc.ok_or_else(|| anyhow::anyhow!("replica {peer_url} didn't report a checksum"))
}

/// Streams a body to this node's local disk followed by its checksum table (see
/// `blob_file`), fsyncs it, and records this node as a location for the blob.
/// Returns the CRC64/NVME of the whole file written. Shared by
/// the peer PUT endpoint (an `Incoming`) and the local-replica sink in
/// `upload_part` (a channel-backed body) — hence the generic body.
async fn write_blob_streaming<B>(app: &App, blob_id: Uuid, body: B) -> anyhow::Result<u64>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    // Mark the blob as being written for the whole write→announce window, so the
    // GC's file sweep won't treat this in-flight file (no location yet) as an
    // orphan. The guard drops after the location insert below.
    let _writing = app.writing.begin(blob_id);
    match write_and_announce(app, blob_id, body).await {
        Ok(crc) => Ok(crc),
        Err(failure) => {
            // Delete the file right away, unless its location may have been
            // recorded after all: then a commit may count on it, and it's left
            // to the GC to judge. That's only after a lost connection: an
            // error Postgres reports means the insert was rolled back.
            if !failure.maybe_announced {
                let _ = app.store.remove_blob(blob_id).await;
            }
            Err(failure.error)
        }
    }
}

/// Why a replica failed to store a blob, and whether its location might have
/// been recorded nonetheless.
struct WriteFailure {
    error: anyhow::Error,
    maybe_announced: bool,
}

impl<E: Into<anyhow::Error>> From<E> for WriteFailure {
    fn from(e: E) -> Self {
        WriteFailure {
            error: e.into(),
            maybe_announced: false,
        }
    }
}

/// The body of `write_blob_streaming`.
async fn write_and_announce<B>(app: &App, blob_id: Uuid, mut body: B) -> Result<u64, WriteFailure>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let mut file = app.store.create_blob(blob_id).await?;
    // The checksums are computed from the bytes as received, before they hit
    // the disk, so the table catches anything that goes wrong on the way down.
    let mut summer = BlobSummer::new(checksum::BLOCK_SIZE);
    let mut file_crc = crc64fast_nvme::Digest::new();
    while let Some(frame) = body.frame().await {
        if let Ok(chunk) = frame?.into_data() {
            summer.update(&chunk);
            file_crc.write(&chunk);
            file.write_all(&chunk).await?;
        }
    }
    let trailer = blob_file::trailer(blob_id, &summer.finish());
    file_crc.write(&trailer);
    file.write_all(&trailer).await?;
    // fsync before announcing the location, so the bytes survive a crash by the
    // time the leader's commit can count this replica.
    file.sync_all().await?;
    let client = app.pool.get().await?;
    // The blob may be gone (its upload given up): then this fails its FK check.
    if let Err(e) = client
        .execute_cached(
            "INSERT INTO blob_locations (blob_id, node) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            &[&blob_id, &app.node],
        )
        .await
    {
        let maybe_announced = e.code().is_none();
        return Err(WriteFailure {
            error: e.into(),
            maybe_announced,
        });
    }
    Ok(file_crc.sum64())
}

/// A new blob being written to its replicas: a pending blob row, and a sink per
/// replica (local or remote) fed through a bounded channel, so the slowest one
/// applies backpressure. Computes the blob's checksums as the data passes.
/// Shared by uploads and the packer.
pub(crate) struct BlobWriter {
    app: Arc<App>,
    pub blob_id: Uuid,
    pub replicas: Vec<Location>,
    senders: Vec<FrameSender>,
    sinks: JoinSet<anyhow::Result<u64>>,
    summer: BlobSummer,
    crc: crc64fast_nvme::Digest,
    size: u64,
}

impl BlobWriter {
    /// Creates the pending blob and starts a sink on each of its replicas.
    pub(crate) async fn begin(app: &Arc<App>) -> anyhow::Result<BlobWriter> {
        let writer = Self::start(app, None).await?;
        Ok(writer.expect("only a bucket can be missing"))
    }

    /// Like `begin`, for an upload into `bucket`: `None` if there's no such
    /// bucket, and then there's no pending blob either. Saves the upload a
    /// round trip to Postgres for checking the bucket first. (The commit checks
    /// again, since the bucket may be deleted while the body streams.)
    pub(crate) async fn begin_in_bucket(
        app: &Arc<App>,
        bucket: &str,
    ) -> anyhow::Result<Option<BlobWriter>> {
        Self::start(app, Some(bucket)).await
    }

    async fn start(app: &Arc<App>, bucket: Option<&str>) -> anyhow::Result<Option<BlobWriter>> {
        let client = app.pool.get().await?;
        // Time-ordered, so new blobs land at the end of the indexes on blob_id.
        let blob_id = Uuid::now_v7();
        // Its size isn't known until all the data has passed, so it starts at 0
        // and is set at commit. Created only if the bucket exists, when there's
        // one to check.
        let insert = async {
            client
                .execute_cached(
                    "INSERT INTO blobs (blob_id, size, state, created_at)
                     SELECT $1, 0, 'pending', NOW()
                     WHERE $2::text IS NULL OR EXISTS (SELECT 1 FROM buckets WHERE name = $2)",
                    &[&blob_id, &bucket],
                )
                .await
        };
        // Independent of each other, so they're sent together, and take one
        // round trip between them.
        let (inserted, replicas) = tokio::join!(insert, choose_replicas(&client, app.replication_factor));
        if inserted? == 0 {
            return Ok(None);
        }
        drop(client);
        let replicas = match replicas {
            Ok(replicas) => replicas,
            Err(e) => {
                // No sink has started, so there are only the row's to delete.
                blobs::discard(app, blob_id).await;
                return Err(e);
            }
        };
        // The pooled connection was dropped above, before the (potentially long)
        // write: the local sink needs one to record its location, and concurrent
        // writes could otherwise exhaust the pool and deadlock.
        let mut senders = Vec::new();
        let mut sinks = JoinSet::new();
        for (node, peer_url) in replicas.clone() {
            let (tx, body) = channel_body();
            senders.push(tx);
            // A replica that is ourselves writes straight to local disk (no HTTP
            // hop, and on a single host there's no peer server).
            if node == app.node {
                let app = app.clone();
                sinks.spawn(async move { write_blob_streaming(&app, blob_id, body).await });
            } else {
                let peers = app.peers.clone();
                sinks.spawn(async move {
                    upload_to_replica(&peers, &peer_url, blob_id, body)
                        .await
                        .map_err(|e| Unavailable(format!("replica {peer_url}: {e:#}")).into())
                });
            }
        }
        Ok(Some(BlobWriter {
            app: app.clone(),
            blob_id,
            replicas,
            senders,
            sinks,
            summer: BlobSummer::new(checksum::BLOCK_SIZE),
            crc: crc64fast_nvme::Digest::new(),
            size: 0,
        }))
    }

    /// Appends `chunk` to the blob on every replica.
    pub(crate) async fn write(&mut self, chunk: Bytes) {
        self.summer.update(&chunk);
        self.crc.write(&chunk);
        self.size += chunk.len() as u64;
        for tx in &self.senders {
            // A dropped receiver means that sink's task failed; its real error
            // surfaces in `finish`.
            let _ = tx.send(Ok(Frame::data(chunk.clone()))).await;
        }
    }

    /// Gives up on the blob: faults the sinks, so no replica durably stores the
    /// truncated data, waits for them, and deletes the pending blob and
    /// whatever its replicas stored.
    pub(crate) async fn abort(mut self, reason: &str) {
        for tx in &self.senders {
            let _ = tx.send(Err(std::io::Error::other(reason.to_owned()))).await;
        }
        self.senders.clear();
        // Their resulting errors are expected.
        while self.sinks.join_next().await.is_some() {}
        blobs::discard(&self.app, self.blob_id).await;
    }

    /// Ends the blob and waits for every replica to store it. Fails if one
    /// couldn't, or if one stored different bytes than were sent, and then
    /// deletes the pending blob and whatever its replicas stored.
    pub(crate) async fn finish(mut self) -> anyhow::Result<Written> {
        self.senders.clear();
        // Every sink is waited for, also after one failed, so that none is still
        // writing when the blob is deleted.
        let mut replica_crcs = Vec::new();
        let mut failure = None;
        while let Some(res) = self.sinks.join_next().await {
            match res.map_err(anyhow::Error::from).and_then(|r| r) {
                Ok(crc) => replica_crcs.push(crc),
                Err(e) => failure = failure.or(Some(e)),
            }
        }
        if let Some(e) = failure {
            blobs::discard(&self.app, self.blob_id).await;
            return Err(e);
        }
        // Every replica must have stored exactly the file we expect: the bytes we
        // sent, followed by the checksum table and blob ID they determine. A
        // mismatch means a copy was damaged in transit or on its way to disk; the
        // write can be retried.
        // The data's CRC covers just the data; the file's carries on over the
        // trailer.
        let blob_id = self.blob_id;
        let data_crc = self.crc.sum64();
        self.crc.write(&blob_file::trailer(blob_id, &self.summer.finish()));
        let file_crc = self.crc.sum64();
        if replica_crcs.iter().any(|&replica_crc| replica_crc != file_crc) {
            blobs::discard(&self.app, blob_id).await;
            return Err(Unavailable(format!(
                "blob {blob_id}: a replica stored different bytes than were sent"
            ))
            .into());
        }
        Ok(Written {
            blob_id,
            nodes: self.replicas.iter().map(|(node, _)| *node).collect(),
            replicas: self.replicas,
            size: self.size,
            data_crc,
            file_crc,
        })
    }
}

/// A blob fully written to its replicas, but still pending.
pub(crate) struct Written {
    pub blob_id: Uuid,
    pub nodes: Vec<i32>,
    pub replicas: Vec<Location>,
    pub size: u64,
    /// CRC64/NVME of the data, and of the whole file as stored.
    pub data_crc: u64,
    pub file_crc: u64,
}

/// Where a freshly-uploaded part should be attached. The part row is inserted
/// in the same transaction that flips its blob to 'committed', so
/// the invariant "a committed blob is referenced" holds with no orphan window.
/// The size, ETag and CRC aren't carried here: they're computed by
/// `upload_part` as the body streams, and passed to `try_commit_part` alongside
/// the target.
enum AttachTarget {
    /// A single-PUT object: point (bucket, key) at exactly this one part,
    /// replacing whatever it referenced before. `conditions` carries any
    /// conditional-write guard (If-Match / If-None-Match), evaluated against the
    /// current object inside the commit transaction; it's empty for a copy
    /// destination (whose conditions apply to the source instead).
    Object {
        bucket: String,
        key: String,
        content_type: String,
        conditions: Preconditions,
    },
    /// A part staged under an in-progress multipart upload.
    MultipartPart { upload_id: Uuid, part_number: i32 },
}

/// The outcome of an upload: the committed part's ETag, or why it wasn't
/// committed.
enum UploadResult {
    /// Committed, with the new part's ETag and, for an object write, the
    /// `x-amz-version-id` to report for the version it created.
    Committed {
        etag: String,
        version_id: Option<String>,
    },
    /// The body wasn't what the request claimed it to be (see `Payload`).
    Rejected(Rejection),
    /// A conditional-write guard (If-Match / If-None-Match) didn't hold against
    /// the object currently at the target key.
    PreconditionFailed,
    /// The target bucket doesn't exist, or was deleted while the body streamed.
    NoSuchBucket,
    /// The target multipart upload was completed or aborted while the body
    /// streamed.
    NoSuchUpload,
}

/// Uploads `body`, checked against what its request claims about it
/// (`payload`), as a new blob, and attaches it to `attach`. Nothing is
/// committed unless the body is everything it claimed to be.
async fn upload_part<B>(
    app: &Arc<App>,
    mut body: B,
    attach: &AttachTarget,
    mut payload: Payload,
) -> anyhow::Result<UploadResult>
where
    B: Body<Data = Bytes> + Unpin + Send,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    // 1-2. create the pending blob and start writing it to its replicas. An
    // object's bucket is checked on the way.
    let mut writer = match attach {
        AttachTarget::Object { bucket, .. } => match BlobWriter::begin_in_bucket(app, bucket).await? {
            Some(writer) => writer,
            None => return Ok(UploadResult::NoSuchBucket),
        },
        AttachTarget::MultipartPart { .. } => BlobWriter::begin(app).await?,
    };
    let blob_id = writer.blob_id;
    // 3. tee: read the client body once, decoding it (an `aws-chunked` body's
    // framing isn't the object) and checking it as it goes, hashing the data
    // for the ETag, and fanning each chunk out to every replica.
    let mut hasher = Md5::new();
    let failure = loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                let Ok(chunk) = frame.into_data() else { continue };
                match payload.decode(chunk) {
                    Ok(data) => {
                        for piece in data {
                            hasher.update(&piece);
                            writer.write(piece).await;
                        }
                    }
                    Err(rejection) => break Some(Ok(rejection)),
                }
            }
            Some(Err(e)) => break Some(Err(anyhow::Error::from(e))),
            None => break payload.finish().err().map(Ok),
        }
    };
    // 4. wait for every replica to finish. If the body failed to read, or
    // wasn't what it claimed to be, fault the sinks instead, so they don't
    // durably store it.
    match failure {
        None => {}
        Some(Ok(rejection)) => {
            writer.abort(rejection.code).await;
            return Ok(UploadResult::Rejected(rejection));
        }
        Some(Err(e)) => {
            writer.abort(&e.to_string()).await;
            return Err(e);
        }
    }
    // On failure, `finish` deletes what the replicas stored itself.
    let written = writer.finish().await?;
    // Whatever keeps the upload from committing from here on, the blob is
    // deleted with its files right away; only a crash leaves it to the GC.
    let result = async {
        let etag: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
        // 5. commit + attach with the now-known size and ETag, in one transaction;
        // retry on a conflict.
        let mut client = app.pool.get().await?;
        for attempt in 0..db::MAX_TX_ATTEMPTS {
            db::backoff(attempt).await;
            match try_commit_part(&mut client, &written, attach, &etag).await {
                Ok(CommitResult::Committed { reap, version_id }) => {
                    // Reap the blobs this overwrite displaced; their rows are gone.
                    reap_blobs(app, reap);
                    return Ok(UploadResult::Committed { etag, version_id });
                }
                Ok(CommitResult::PreconditionFailed) => return Ok(UploadResult::PreconditionFailed),
                Ok(CommitResult::NoSuchBucket) => return Ok(UploadResult::NoSuchBucket),
                Ok(CommitResult::NoSuchUpload) => return Ok(UploadResult::NoSuchUpload),
                Ok(CommitResult::MissingLocations { present, required }) => {
                    return Err(Unavailable(format!(
                        "blob {blob_id} not durable: only {present}/{required} replicas reported a location"
                    ))
                    .into());
                }
                Err(e) if db::is_conflict(&e) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(Contended(format!("blob {blob_id}: commit kept conflicting with concurrent ones")).into())
    }
    .await;
    if !matches!(result, Ok(UploadResult::Committed { .. })) {
        // Safe even if a commit attempt's outcome is unknown: a committed blob
        // isn't touched.
        blobs::discard(app, written.blob_id).await;
    }
    result
}

enum CommitResult {
    /// Committed; carries the replica locations of any blobs this displaced
    /// (an overwrite or part re-upload), for the caller to reap, and the
    /// version ID to report for an object write.
    Committed {
        reap: Vec<ReapTarget>,
        version_id: Option<String>,
    },
    MissingLocations { present: i64, required: usize },
    /// A conditional-write guard didn't hold; nothing was written.
    PreconditionFailed,
    NoSuchBucket,
    NoSuchUpload,
}

/// Runs the commit transaction once (`cairn_commit_object` or
/// `cairn_commit_upload_part`): confirms that all of the blob's replicas
/// recorded their locations, and if so marks the blob committed (recording its
/// size and the CRC64/NVME of its file) and attaches a part spanning it to
/// `attach` (with the CRC64/NVME of its data), all in one statement, and so
/// one transaction. The raw postgres error is returned unwrapped so the caller can distinguish a
/// conflict (retry) from a real error (give up).
async fn try_commit_part(
    client: &mut Object,
    written: &Written,
    attach: &AttachTarget,
    etag: &str,
) -> Result<CommitResult, tokio_postgres::Error> {
    // CRCs are stored as their 64 bits, read as a signed BIGINT. The part's
    // covers just its data, and stays valid wherever it's moved later; the
    // blob's covers its whole file, for a scrub to check against.
    let size = written.size as i64;
    let file_crc = written.file_crc as i64;
    let block_size = checksum::BLOCK_SIZE as i32;
    let data_crc = written.data_crc as i64;
    let (row, version_column, reap_column) = match attach {
        AttachTarget::Object {
            bucket,
            key,
            content_type,
            conditions,
        } => {
            let (if_match, if_none_match) = conditions.write_conditions();
            let row = client
                .query_one_cached(
                    "SELECT status, present, version_id, reap_blob, reap_node, reap_peer
                     FROM pg_temp.cairn_commit_object($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                                                      $11, $12, $13)",
                    &[
                        &written.blob_id,
                        &written.nodes,
                        &size,
                        &file_crc,
                        &block_size,
                        &data_crc,
                        &etag,
                        bucket,
                        key,
                        content_type,
                        &if_match,
                        &if_none_match,
                        &s3::versions::new_version_id(),
                    ],
                )
                .await?;
            (row, Some(2), 3)
        }
        AttachTarget::MultipartPart {
            upload_id,
            part_number,
        } => {
            let row = client
                .query_one_cached(
                    "SELECT status, present, reap_blob, reap_node, reap_peer
                     FROM pg_temp.cairn_commit_upload_part($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                    &[
                        &written.blob_id,
                        &written.nodes,
                        &size,
                        &file_crc,
                        &block_size,
                        &data_crc,
                        &etag,
                        upload_id,
                        part_number,
                    ],
                )
                .await?;
            (row, None, 2)
        }
    };
    // On anything but a commit, the function changed nothing.
    match row.get::<_, &str>(0) {
        "committed" => {}
        "missing_locations" => {
            return Ok(CommitResult::MissingLocations {
                present: row.get(1),
                required: written.nodes.len(),
            });
        }
        "precondition_failed" => return Ok(CommitResult::PreconditionFailed),
        "no_such_bucket" => return Ok(CommitResult::NoSuchBucket),
        "no_such_upload" => return Ok(CommitResult::NoSuchUpload),
        status => unreachable!("cairn_commit_*: unknown status {status}"),
    }
    let version_id = version_column.and_then(|c| row.get(c));
    let reap = blobs::reap_columns(&row, reap_column);
    Ok(CommitResult::Committed { reap, version_id })
}
