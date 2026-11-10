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
mod encryption;
mod gc;
mod kms;
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
    /// Whether SSE-C keys are accepted over plain HTTP (see `s3::sse_c`).
    allow_sse_c_over_http: bool,
    /// The KMS SSE-KMS keeps its keys in, if there's one (see `s3::sse`).
    kms: Option<Arc<kms::Kms>>,
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
    /// Accept SSE-C keys in requests that didn't come over HTTPS (that no
    /// proxy marked `X-Forwarded-Proto: https`). Only for a network that's
    /// encrypted itself: the key travels in a header.
    #[arg(long, env = "CAIRN_ALLOW_SSE_C_OVER_HTTP")]
    allow_sse_c_over_http: bool,
    #[command(flatten)]
    kms: kms::KmsArgs,
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
    // A node holds keys in memory: its clients' (SSE-C), and data keys from
    // the KMS (SSE-KMS). No core dump of it may hold them, nor may another
    // process of the same user read its memory (ptrace, /proc/<pid>/mem).
    // Swap is the operator's to rule out (see README.md).
    // SAFETY: prctl with PR_SET_DUMPABLE takes no pointers.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
        anyhow::bail!("couldn't make the process non-dumpable: {}", std::io::Error::last_os_error());
    }
    let kms = kms::Kms::new(&args.kms)?;
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
        allow_sse_c_over_http: args.allow_sse_c_over_http,
        kms,
        #[cfg(test)]
        pack_hook: None,
    });
    tokio::spawn(heartbeat(app.clone(), peer_url));
    tokio::spawn(maintain(app.clone()));
    // The roles' identities in the KMS, now rather than in a minute.
    let identifying = app.clone();
    tokio::spawn(async move {
        if let Err(e) = roles::identify(&identifying).await {
            eprintln!("kms: identifying roles: {e:#}");
        }
    });

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
            if let Err(e) = roles::identify(&app).await {
                eprintln!("kms: identifying roles: {e:#}");
            }
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
                    // A handler error must still produce a response (`handle`
                    // makes one): returning it to hyper would drop the
                    // connection without one, which clients take as a network
                    // fault and retry with backoff.
                    let res = s3::handle(req, app.clone(), &what).await;
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
    /// Whether the blob has been handed on (`finish`) or deleted (`abort`).
    /// Until then, dropping the writer deletes it (see `Drop`).
    settled: bool,
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
        // If this future is dropped before the writer exists (whose `Drop`
        // takes over), the pending blob is deleted in the background. Armed
        // before the insert, since that may have happened by then; if the
        // insert is still underway when the discard runs, the GC has the row.
        let mut pending = blobs::DiscardOnDrop::new(app, blob_id);
        // Independent of each other, so they're sent together, and take one
        // round trip between them.
        let (inserted, replicas) = tokio::join!(insert, choose_replicas(&client, app.replication_factor));
        if inserted? == 0 {
            pending.disarm();
            return Ok(None);
        }
        drop(client);
        let replicas = match replicas {
            Ok(replicas) => replicas,
            Err(e) => {
                // No sink has started, so there are only the row's to delete.
                blobs::discard(app, blob_id).await;
                pending.disarm();
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
        pending.disarm();
        Ok(Some(BlobWriter {
            app: app.clone(),
            blob_id,
            replicas,
            senders,
            sinks,
            summer: BlobSummer::new(checksum::BLOCK_SIZE),
            crc: crc64fast_nvme::Digest::new(),
            size: 0,
            settled: false,
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
        let (senders, sinks) = (std::mem::take(&mut self.senders), std::mem::take(&mut self.sinks));
        give_up(&self.app, self.blob_id, senders, sinks, reason).await;
        self.settled = true;
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
            self.settled = true;
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
        let summer = std::mem::replace(&mut self.summer, BlobSummer::new(checksum::BLOCK_SIZE));
        self.crc.write(&blob_file::trailer(blob_id, &summer.finish()));
        let file_crc = self.crc.sum64();
        if replica_crcs.iter().any(|&replica_crc| replica_crc != file_crc) {
            blobs::discard(&self.app, blob_id).await;
            self.settled = true;
            return Err(Unavailable(format!(
                "blob {blob_id}: a replica stored different bytes than were sent"
            ))
            .into());
        }
        // From here on, the caller sees to the blob.
        self.settled = true;
        Ok(Written {
            blob_id,
            nodes: self.replicas.iter().map(|(node, _)| *node).collect(),
            replicas: std::mem::take(&mut self.replicas),
            size: self.size,
            data_crc,
            file_crc,
        })
    }
}

/// A writer dropped before `finish` or `abort` settled its blob (the future
/// of its request was dropped, as hyper does when the client hangs up) gives
/// the blob up all the same, in the background, as `abort` would. A writer
/// dropped within `finish` has no senders left, so its sinks complete the
/// blob, which is then deleted.
impl Drop for BlobWriter {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        let (app, blob_id) = (self.app.clone(), self.blob_id);
        let (senders, sinks) = (std::mem::take(&mut self.senders), std::mem::take(&mut self.sinks));
        tokio::spawn(async move {
            give_up(&app, blob_id, senders, sinks, "the upload was given up").await;
        });
    }
}

/// Gives up on a blob being written: faults the sinks still being fed, so no
/// replica durably stores the truncated data, waits for every sink (so that
/// none is still writing when the blob is deleted), and deletes the pending
/// blob and whatever its replicas stored.
async fn give_up(
    app: &Arc<App>,
    blob_id: Uuid,
    senders: Vec<FrameSender>,
    mut sinks: JoinSet<anyhow::Result<u64>>,
    reason: &str,
) {
    for tx in &senders {
        let _ = tx.send(Err(std::io::Error::other(reason.to_owned()))).await;
    }
    drop(senders);
    // Their resulting errors are expected.
    while sinks.join_next().await.is_some() {}
    blobs::discard(app, blob_id).await;
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
        /// What `s3::metadata` stores with it.
        metadata: String,
        conditions: Preconditions,
        /// If it's encrypted: what with, and how that's stored.
        sealing: Option<Sealing>,
        /// The checksum it's stored with (see `s3::checksums`).
        checksum: s3::checksums::Wanted,
    },
    /// A part staged under an in-progress multipart upload, encrypted with
    /// `key` if the upload is encrypted (SSE-C, SSE-KMS or SSE-S3), whose
    /// ETag is then an MD5, sealed, if it's SSE-S3 (see `s3::sse`).
    MultipartPart {
        upload_id: Uuid,
        part_number: i32,
        key: Option<zeroize::Zeroizing<encryption::Key>>,
        sse_s3: bool,
        /// The checksum it's stored with: its upload's algorithm's.
        checksum: s3::checksums::Wanted,
    },
}

impl AttachTarget {
    fn checksum(&self) -> s3::checksums::Wanted {
        match self {
            AttachTarget::Object { checksum, .. } | AttachTarget::MultipartPart { checksum, .. } => *checksum,
        }
    }

    /// The key it's encrypted with, if it is.
    fn key(&self) -> Option<&encryption::Key> {
        match self {
            AttachTarget::Object { sealing, .. } => sealing.as_ref().map(|sealing| &*sealing.key),
            AttachTarget::MultipartPart { key, .. } => key.as_deref(),
        }
    }
}

pub(crate) use s3::sse::Sealing;

/// The outcome of an upload: the committed part's ETag, or why it wasn't
/// committed.
enum UploadResult {
    /// Committed, with the new part's ETag and checksum (if it's stored with
    /// one) and, for an object write, the `x-amz-version-id` to report for
    /// the version it created, and its last-modified time (ISO 8601).
    Committed {
        etag: String,
        checksum: Option<s3::checksums::Checksum>,
        /// The checksum the client sent with it, checked.
        sent: Option<s3::checksums::Checksum>,
        version_id: Option<String>,
        last_modified: Option<String>,
    },
    /// The body wasn't what the request claimed it to be (see `Payload`).
    Rejected(Rejection),
    /// A conditional-write guard (If-Match / If-None-Match) didn't hold against
    /// the object currently at the target key.
    PreconditionFailed,
    /// An If-Match found no object at the target key.
    NoSuchKey,
    /// The target bucket doesn't exist, or was deleted while the body streamed.
    NoSuchBucket,
    /// The target multipart upload was completed or aborted while the body
    /// streamed.
    NoSuchUpload,
    /// A conditional write couldn't be decided: the current object's ETag
    /// couldn't be had (its key from the KMS, say). The response.
    Refused(hyper::Response<http_body_util::Full<Bytes>>),
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
    // An encrypted part is stored as its ciphertext; its ETag is its salt.
    let mut sealer = match attach {
        AttachTarget::Object { sealing: Some(sealing), .. } => {
            Some(encryption::Sealer::new(&sealing.key, encryption::new_salt()))
        }
        AttachTarget::MultipartPart { key: Some(key), .. } => {
            Some(encryption::Sealer::new(key, encryption::new_salt()))
        }
        _ => None,
    };
    // A plain part's ETag is its MD5, and so is an SSE-S3 part's, as in S3
    // (sealed, to store: see `s3::sse`); other encrypted parts' is their salt.
    // If the client declared the MD5 (Content-MD5), the body is checked against
    // it as it's read, so it's that one. Otherwise a task of its own works it
    // out beside the writing (MD5 is slow, and can't be split up), from the same
    // plaintext chunks, through a short queue.
    let sse_s3 = match attach {
        AttachTarget::Object { sealing, .. } => {
            sealing.as_ref().is_some_and(|sealing| matches!(sealing.stored, s3::sse::Stored::S3(_)))
        }
        AttachTarget::MultipartPart { sse_s3, .. } => *sse_s3,
    };
    let md5_etag = sealer.is_none() || sse_s3;
    let claimed_md5 = payload.claimed_md5();
    let (md5_tx, md5_task) = match (md5_etag, claimed_md5) {
        (true, None) => {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(4);
            let task = tokio::spawn(async move {
                let mut hasher = Md5::new();
                while let Some(piece) = rx.recv().await {
                    hasher.update(&piece);
                }
                hasher.finalize()
            });
            (Some(tx), Some(task))
        }
        _ => (None, None),
    };
    // The checksum it's stored with: the one the client sent, checked as
    // it's read (see `Payload`), or one worked out here. A plain part's
    // CRC64NVME is the writer's own of its data.
    let sent = payload.declared_algorithm();
    let checksum_algorithm = attach.checksum().algorithm(sent);
    let mut checksum_hasher = match checksum_algorithm {
        Some(algorithm) if Some(algorithm) != sent => match (algorithm, &sealer) {
            (s3::checksums::Algorithm::Crc64Nvme, None) => None,
            _ => Some(s3::checksums::Hasher::new(algorithm)),
        },
        _ => None,
    };
    // 3. tee: read the client body once, decoding it (an `aws-chunked` body's
    // framing isn't the object) and checking it as it goes, hashing the data
    // for the ETag (or encrypting it), and fanning each chunk out to every
    // replica.
    let mut client_checksum = None;
    let failure = loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                let Ok(chunk) = frame.into_data() else { continue };
                match payload.decode(chunk) {
                    Ok(data) => {
                        for piece in data {
                            if let Some(hasher) = &mut checksum_hasher {
                                hasher.update(&piece);
                            }
                            if let Some(md5_tx) = &md5_tx {
                                // Only fails if the task panicked; awaited below.
                                let _ = md5_tx.send(piece.clone()).await;
                            }
                            match &mut sealer {
                                Some(sealer) => {
                                    for sealed in sealer.update(&piece) {
                                        writer.write(sealed).await;
                                    }
                                }
                                None => writer.write(piece).await,
                            }
                        }
                    }
                    Err(rejection) => break Some(Ok(rejection)),
                }
            }
            Some(Err(e)) => break Some(Err(anyhow::Error::from(e))),
            None => match payload.finish() {
                Ok(checked) => {
                    client_checksum = checked;
                    break None;
                }
                Err(rejection) => break Some(Ok(rejection)),
            },
        }
    };
    // The MD5 task has all there is.
    drop(md5_tx);
    // The last segment, once the whole body is in and what it claimed to be.
    let encrypted = match sealer {
        Some(sealer) if failure.is_none() => {
            let salt = sealer.salt();
            let (sealed, plain) = sealer.finish();
            writer.write(sealed).await;
            Some(Encrypted { plain_size: plain, salt })
        }
        _ => None,
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
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    // The ETag clients are told, and the one stored (the same, but SSE-S3's).
    let etag = match (&encrypted, md5_etag, claimed_md5, md5_task) {
        (Some(encrypted), false, _, _) => hex(&encrypted.salt),
        (_, true, Some(claimed), _) => hex(&claimed),
        (_, true, None, Some(task)) => match task.await {
            Ok(md5) => hex(&md5),
            Err(e) => {
                writer.abort("the MD5 task failed").await;
                return Err(e.into());
            }
        },
        _ => unreachable!("a part's ETag is its salt, or its MD5 claimed or worked out"),
    };
    let stored_etag = if sse_s3 {
        let key = match attach {
            AttachTarget::Object { sealing: Some(sealing), .. } => &sealing.key,
            AttachTarget::MultipartPart { key: Some(key), .. } => key,
            _ => unreachable!("an SSE-S3 part has its key"),
        };
        s3::sse::seal_etag(key, &etag)
    } else {
        etag.clone()
    };
    // On failure, `finish` deletes what the replicas stored itself.
    let written = writer.finish().await?;
    // The checksum, as clients are told it, and as it's stored (sealed, if
    // the part's encrypted: see `s3::checksums`).
    let sent = client_checksum.as_ref().map(|(algorithm, raw)| s3::checksums::Checksum::full(*algorithm, raw));
    let checksum = checksum_algorithm.map(|algorithm| {
        let raw = match (client_checksum.take(), checksum_hasher.take()) {
            (Some((sent, raw)), _) if sent == algorithm => raw,
            (_, Some(hasher)) => hasher.finish(),
            _ => written.data_crc.to_be_bytes().to_vec(),
        };
        s3::checksums::Checksum::full(algorithm, &raw)
    });
    let stored_checksum = checksum.as_ref().map(|checksum| match attach.key() {
        Some(key) => s3::checksums::ChecksumKey::new(key).seal(&checksum.value),
        None => checksum.value.clone(),
    });
    // If this future is dropped before the blob is committed or discarded, the
    // blob is deleted in the background.
    let mut pending = blobs::DiscardOnDrop::new(app, written.blob_id);
    // Whatever keeps the upload from committing from here on, the blob is
    // deleted with its files right away; only a crash leaves it to the GC.
    let result = async {
        // 5. commit + attach with the now-known size and ETag, in one transaction;
        // retry on a conflict.
        let mut client = app.pool.get().await?;
        for attempt in 0..db::MAX_TX_ATTEMPTS {
            db::backoff(attempt).await;
            // A conditional write is decided here, against the current
            // object, whose ETag only Cairn can read (it may be SSE-S3's);
            // the commit checks that it's still the current one.
            let expected = match attach {
                AttachTarget::Object { bucket, key, conditions, .. } if conditions.has_write_conditions() => {
                    let current = match s3::versions::current_object(app, bucket, key).await? {
                        Ok(current) => current,
                        Err(refused) => return Ok(UploadResult::Refused(refused)),
                    };
                    if !conditions.allows_write(current.as_ref().map(|c| c.etag.as_str())) {
                        // If-Match for a key without an object is S3's 404, not a 412.
                        if conditions.has_if_match() && current.is_none() {
                            return Ok(UploadResult::NoSuchKey);
                        }
                        return Ok(UploadResult::PreconditionFailed);
                    }
                    Some(current.map(|c| c.id))
                }
                _ => None,
            };
            let stored = Stored { etag: &stored_etag, checksum: checksum.as_ref().zip(stored_checksum.as_deref()) };
            match try_commit_part(&mut client, &written, attach, &stored, encrypted.as_ref(), expected).await {
                Ok(CommitResult::Committed { reap, version_id, last_modified }) => {
                    // Reap the blobs this overwrite displaced; their rows are gone.
                    reap_blobs(app, reap);
                    return Ok(UploadResult::Committed { etag, checksum, sent, version_id, last_modified });
                }
                // Another write landed since it was decided: decide again.
                Ok(CommitResult::Stale) => continue,
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
    pending.disarm();
    result
}

enum CommitResult {
    /// Committed; carries the replica locations of any blobs this displaced
    /// (an overwrite or part re-upload), for the caller to reap, and the
    /// version ID to report for an object write.
    Committed {
        reap: Vec<ReapTarget>,
        version_id: Option<String>,
        last_modified: Option<String>,
    },
    MissingLocations { present: i64, required: usize },
    /// The object a conditional write was decided against isn't the current
    /// one anymore; nothing was written.
    Stale,
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
/// An encrypted part's plaintext size and salt.
struct Encrypted {
    plain_size: u64,
    salt: encryption::Salt,
}

/// What's stored of a part's ETag and checksum: as they are, or sealed (an
/// SSE-S3 one's ETag, an encrypted one's checksum).
struct Stored<'a> {
    etag: &'a str,
    /// The checksum, and its value as it's stored.
    checksum: Option<(&'a s3::checksums::Checksum, &'a str)>,
}

async fn try_commit_part(
    client: &mut Object,
    written: &Written,
    attach: &AttachTarget,
    stored: &Stored<'_>,
    encrypted: Option<&Encrypted>,
    expected: Option<Option<i64>>,
) -> Result<CommitResult, tokio_postgres::Error> {
    let etag = stored.etag;
    let checksum_algorithm = stored.checksum.map(|(c, _)| c.algorithm.name());
    let checksum_type = stored.checksum.map(|(c, _)| c.kind.name());
    let checksum = stored.checksum.map(|(_, value)| value);
    // CRCs are stored as their 64 bits, read as a signed BIGINT. The part's
    // covers just its data, and stays valid wherever it's moved later; the
    // blob's covers its whole file, for a scrub to check against.
    let size = written.size as i64;
    let file_crc = written.file_crc as i64;
    let block_size = checksum::BLOCK_SIZE as i32;
    let data_crc = written.data_crc as i64;
    let plain_size = encrypted.map(|e| e.plain_size as i64);
    let enc_salt = encrypted.map(|e| e.salt.to_vec());
    let (row, version_column, reap_column, last_modified_column) = match attach {
        AttachTarget::Object {
            bucket,
            key,
            content_type,
            metadata,
            sealing,
            ..
        } => {
            let plain = s3::sse::Stored::Plain;
            let sse = sealing.as_ref().map_or(&plain, |sealing| &sealing.stored).columns();
            let row = client
                .query_one_cached(
                    "SELECT status, present, version_id, reap_blob, reap_node, reap_peer, last_modified
                     FROM pg_temp.cairn_commit_object($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                                                      $11, $12, $13, $14, $15, $16, $17, $18,
                                                      $19, $20, $21, $22, $23, $24, $25)",
                    &[
                        &written.blob_id,
                        &written.nodes,
                        &size,
                        &file_crc,
                        &block_size,
                        &data_crc,
                        &etag,
                        &plain_size,
                        &enc_salt,
                        bucket,
                        key,
                        content_type,
                        metadata,
                        &sse.sse_c_key,
                        &sse.kms_key_id,
                        &sse.kms_data_key,
                        &sse.kms_sealed,
                        &sse.kms_context,
                        &sse.sse_s3,
                        &checksum_algorithm,
                        &checksum_type,
                        &checksum,
                        &expected.is_some(),
                        &expected.flatten(),
                        &s3::versions::new_version_id(),
                    ],
                )
                .await?;
            (row, Some(2), 3, Some(6))
        }
        AttachTarget::MultipartPart {
            upload_id,
            part_number,
            ..
        } => {
            let row = client
                .query_one_cached(
                    "SELECT status, present, reap_blob, reap_node, reap_peer
                     FROM pg_temp.cairn_commit_upload_part($1, $2, $3, $4, $5, $6, $7, $8, $9,
                                                           $10, $11, $12)",
                    &[
                        &written.blob_id,
                        &written.nodes,
                        &size,
                        &file_crc,
                        &block_size,
                        &data_crc,
                        &etag,
                        &plain_size,
                        &enc_salt,
                        upload_id,
                        part_number,
                        &checksum,
                    ],
                )
                .await?;
            (row, None, 2, None)
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
        "stale" => return Ok(CommitResult::Stale),
        "no_such_bucket" => return Ok(CommitResult::NoSuchBucket),
        "no_such_upload" => return Ok(CommitResult::NoSuchUpload),
        status => unreachable!("cairn_commit_*: unknown status {status}"),
    }
    let version_id = version_column.and_then(|c| row.get(c));
    let last_modified = last_modified_column.map(|c| row.get(c));
    let reap = blobs::reap_columns(&row, reap_column);
    Ok(CommitResult::Committed { reap, version_id, last_modified })
}
