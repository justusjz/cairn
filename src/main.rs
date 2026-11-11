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
use crate::blob_file::ShardFile;
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
mod lifecycle;
mod metrics;
mod mover;
mod nodes;
mod packer;
mod payload;
mod roles;
mod s3;
mod scrub;
mod settings;
mod shards;
mod store;
mod writing;

pub struct App {
    pool: Pool,
    store: Store,
    /// This node's number (`nodes.id`), which locations refer to it by.
    node: i32,
    replication_factor: usize,
    /// How many bytes per second the scrubber reads; 0 if it's off.
    scrub_rate: u64,
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

impl App {
    /// How many parity shards a new blob gets: as many as there are replicas
    /// besides the blob's one data shard, so that coded blobs survive losing
    /// as many nodes as replicated ones (see `shards`).
    pub(crate) fn parity_shards(&self) -> u32 {
        self.replication_factor.saturating_sub(1) as u32
    }
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
    /// Show or change the cluster's settings.
    Config(settings::ConfigArgs),
    /// List the cluster's nodes, or remove one.
    Node(nodes::NodeArgs),
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
    /// How many bytes per second the scrubber reads, checking this node's
    /// data against its checksums: e.g. 25MiB (the default), 100MB. 0 turns
    /// it off.
    #[arg(long, env = "CAIRN_SCRUB_RATE", default_value = "25MiB", value_parser = scrub::parse_rate)]
    scrub_rate: u64,
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
        Command::Config(args) => settings::config_main(args).await,
        Command::Node(args) => nodes::node_main(args).await,
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
        scrub_rate: args.scrub_rate,
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
    tokio::spawn(apply_lifecycles(app.clone()));
    tokio::spawn(scrub::run(app.clone()));
    tokio::spawn(mover::run(app.clone()));
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

/// Lifecycle rules, on every node: once a minute, the steps of buckets'
/// sweeps that are due (see `lifecycle`). Apart from `maintain`, so that
/// neither holds up the other.
async fn apply_lifecycles(app: Arc<App>) {
    loop {
        tokio::time::sleep(MAINTENANCE_INTERVAL).await;
        let task_app = app.clone();
        // A task of its own, so that a panic (a bug) fails this pass, rather
        // than ending lifecycle sweeps on this node.
        let pass = tokio::spawn(async move {
            // The database's clock, which every node shares, rather than this
            // node's, which may be off: it decides what's due.
            let now = match lifecycle::database_time(&task_app).await {
                Ok(now) => now,
                Err(e) => {
                    eprintln!("lifecycle: pass failed: {e:#}");
                    task_app.metrics.lifecycle_failed(format!("pass failed: {e:#}"));
                    return;
                }
            };
            for result in lifecycle::pass(&task_app, now).await {
                match result {
                    Ok(report) => {
                        if !report.is_empty() {
                            eprintln!("lifecycle: {report}");
                        }
                        task_app.metrics.lifecycle_done(&report);
                    }
                    Err((bucket, e)) => {
                        eprintln!("lifecycle: bucket {bucket}: sweep failed: {e:#}");
                        task_app.metrics.lifecycle_failed(format!("bucket {bucket}: sweep failed: {e:#}"));
                    }
                }
            }
        });
        if let Err(e) = pass.await {
            eprintln!("lifecycle pass failed: {e}");
            app.metrics.lifecycle_failed(format!("pass failed: {e}"));
        }
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

/// Chooses `count` live nodes for the shards of a new blob, those with the
/// most free space first: the node for shard i is the i-th. Nodes being
/// removed get none (see `mover`).
async fn choose_nodes(client: &Object, count: usize) -> anyhow::Result<Vec<Location>> {
    let nodes = client
        .query_cached(
            "SELECT id, peer_url FROM nodes
             WHERE state = 'active' AND last_seen > NOW() - INTERVAL '10 seconds'
             ORDER BY free_space DESC",
            &[],
        )
        .await?;
    if nodes.len() < count {
        return Err(Unavailable(format!(
            "need {count} nodes for a blob's shards but only {} are live",
            nodes.len()
        ))
        .into());
    }
    Ok(nodes[0..count]
        .iter()
        .zip(0..)
        .map(|(n, shard)| Location {
            node: n.get("id"),
            peer_url: n.get("peer_url"),
            shard,
        })
        .collect())
}

/// What a node is asked to store of a blob being written.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ShardWrite {
    /// A shard of a replicated blob: the blob's bytes, streamed, its size
    /// unknown until they end. The node writes the table after them.
    Replica { blob_id: Uuid, shard: u32 },
    /// A shard of a coded blob, whose layout is known up front: the shard's
    /// bytes, followed by the tables of all of the blob's shards, as the
    /// writer computed them. The node checks its own against them.
    Coded(ShardFile),
}

impl ShardWrite {
    fn blob_id(&self) -> Uuid {
        match self {
            ShardWrite::Replica { blob_id, .. } => *blob_id,
            ShardWrite::Coded(file) => file.blob_id,
        }
    }

    fn shard(&self) -> u32 {
        match self {
            ShardWrite::Replica { shard, .. } => *shard,
            ShardWrite::Coded(file) => file.shard,
        }
    }

    /// The query of the PUT that asks a peer for it, moving it from node
    /// `replaces` if given (see `peer::parse_shard`).
    fn query(&self, replaces: Option<i32>) -> String {
        let mut query = match self {
            ShardWrite::Replica { shard, .. } => format!("?shard={shard}"),
            // A coded shard's layout names the shard too.
            ShardWrite::Coded(file) => format!("?{}", &peer::layout_query(file)[1..]),
        };
        if let Some(node) = replaces {
            query.push_str(&format!("&replaces={node}"));
        }
        query
    }
}

/// Streams a shard (one side of the writer's fan-out, or a move from node
/// `replaces`) to the node at `peer_url`, returning the CRC64/NVME it
/// reports for the file it stored.
pub(crate) async fn upload_to_peer(
    peers: &peer::PeerClient,
    peer_url: &str,
    write: &ShardWrite,
    replaces: Option<i32>,
    body: body::ResBody,
) -> anyhow::Result<u64> {
    let req = Request::builder()
        .method(Method::PUT)
        .uri(format!("{peer_url}/blobs/{}{}", write.blob_id(), write.query(replaces)))
        .body(body)?;
    let res = peers.request(req).await?;
    if res.status() != StatusCode::OK {
        anyhow::bail!("node {peer_url} returned status {}", res.status());
    }
    let crc = res
        .headers()
        .get(peer::CRC64_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| u64::from_str_radix(v, 16).ok());
    crc.ok_or_else(|| anyhow::anyhow!("node {peer_url} didn't report a checksum"))
}

/// Streams a shard of a blob to this node's local disk, followed by its
/// trailer (see `blob_file`), fsyncs it, and records this node as holding
/// the shard. Returns the CRC64/NVME of the whole file written. Shared by
/// the peer PUT endpoint (an `Incoming`) and the local sink of `BlobWriter`
/// (a channel-backed body) — hence the generic body.
///
/// With `replaces`, the shard of a committed blob moves here from that node
/// (see `mover`): the location moves, if the file is the one the catalog
/// describes, and the shard is still there.
async fn write_blob_streaming<B>(
    app: &App,
    write: &ShardWrite,
    replaces: Option<i32>,
    body: B,
) -> anyhow::Result<u64>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let blob_id = write.blob_id();
    // Mark the blob as being written for the whole write→announce window, so the
    // GC's file sweep won't treat this in-flight file (no location yet) as an
    // orphan. The guard drops after the location insert below.
    let _writing = app.writing.begin(blob_id);
    // A shard moving here is written to a file of its own, and only becomes
    // the blob's file once its location has moved: the node may hold another
    // shard of the blob already, whose file mustn't be touched.
    let staged = replaces.map(|_| app.store.move_path(blob_id));
    match write_and_announce(app, write, replaces, staged.as_deref(), body).await {
        Ok(crc) => Ok(crc),
        Err(failure) => {
            // Delete the file right away, unless its location may have been
            // recorded after all: then a commit may count on it, and it's left
            // to the GC to judge. That's only after a lost connection: an
            // error Postgres reports means the insert was rolled back.
            match &staged {
                None if !failure.maybe_announced => {
                    let _ = app.store.remove_blob(blob_id).await;
                }
                None => {}
                Some(path) => settle_move(app, write, path, failure.maybe_announced).await,
            }
            Err(failure.error)
        }
    }
}

/// Settles a shard that failed to move here, staged at `path`: it's deleted,
/// unless the move may have committed after all (a lost connection). Then
/// the catalog is asked: if the shard's location is here, the file becomes
/// the blob's; if the catalog can't be asked, it's left to the GC, and a
/// location without its file is the scrubber's to repair.
async fn settle_move(app: &App, write: &ShardWrite, path: &std::path::Path, maybe_moved: bool) {
    let blob_id = write.blob_id();
    let _file = app.writing.lock_file(blob_id).await;
    let moved = if maybe_moved {
        let shard = write.shard() as i16;
        let query = async {
            let client = app.pool.get().await?;
            let row = client
                .query_opt_cached(
                    "SELECT 1 FROM blob_locations WHERE blob_id = $1 AND node = $2 AND shard = $3",
                    &[&blob_id, &app.node, &shard],
                )
                .await?;
            anyhow::Ok(row.is_some())
        };
        match query.await {
            Ok(moved) => moved,
            Err(e) => {
                eprintln!("blob {blob_id}: can't tell whether a shard moved here, leaving it to the GC: {e:#}");
                return;
            }
        }
    } else {
        false
    };
    let settled = if moved {
        app.store.install_move(path, blob_id).await
    } else {
        app.store.remove_at(path).await
    };
    if let Err(e) = settled {
        eprintln!("blob {blob_id}: settling a shard that moved here failed: {e:#}");
    }
}

/// Why a node failed to store a shard, and whether its location might have
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
async fn write_and_announce<B>(
    app: &App,
    write: &ShardWrite,
    replaces: Option<i32>,
    staged: Option<&std::path::Path>,
    mut body: B,
) -> Result<u64, WriteFailure>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let blob_id = write.blob_id();
    let mut file = match staged {
        Some(path) => app.store.create_at(path).await?,
        None => app.store.create_blob(blob_id).await?,
    };
    // The checksums are computed from the bytes as received, before they hit
    // the disk, so the table catches anything that goes wrong on the way down.
    let mut summer = BlobSummer::new(checksum::BLOCK_SIZE);
    let mut file_crc = crc64fast_nvme::Digest::new();
    // A coded shard's bytes end where its layout says, and the tables follow.
    let data_len = match write {
        ShardWrite::Replica { .. } => u64::MAX,
        ShardWrite::Coded(shard) => shard.data_len(),
    };
    let mut size = 0;
    let mut tables = Vec::new();
    while let Some(frame) = body.frame().await {
        if let Ok(mut chunk) = frame?.into_data() {
            let data = chunk.split_to(chunk.len().min((data_len - size) as usize));
            size += data.len() as u64;
            summer.update(&data);
            file_crc.write(&data);
            file.write_all(&data).await?;
            tables.extend_from_slice(&chunk);
        }
    }
    let trailer = match write {
        ShardWrite::Replica { .. } => {
            let shard = ShardFile {
                blob_id,
                layout: shards::Layout::new(size, 1, 0),
                shard: 0,
            };
            blob_file::trailer(&shard, &[summer.finish()])
        }
        ShardWrite::Coded(shard) => {
            if size != data_len {
                return Err(anyhow::anyhow!("blob {blob_id}: got {size} bytes of shard {}, not {data_len}", shard.shard).into());
            }
            tables.extend_from_slice(&blob_file::tail(shard));
            let ours = summer.finish();
            match blob_file::split_trailer(shard, &tables) {
                Some((sent, _)) if sent[shard.shard as usize] == ours.0.as_slice() => {}
                Some(_) => {
                    return Err(anyhow::anyhow!("blob {blob_id}: shard {} isn't what its table says", shard.shard).into());
                }
                None => {
                    return Err(anyhow::anyhow!("blob {blob_id}: shard {} came with tables of the wrong size", shard.shard).into());
                }
            }
            tables
        }
    };
    file_crc.write(&trailer);
    file.write_all(&trailer).await?;
    // fsync before announcing the location, so the bytes survive a crash by the
    // time the leader's commit can count this shard.
    file.sync_all().await?;
    let client = app.pool.get().await?;
    let shard = write.shard() as i16;
    let crc = file_crc.sum64();
    let mut file_lock = None;
    let announced = match replaces {
        // The blob may be gone (its upload given up): then this fails its FK
        // check.
        None => client
            .execute_cached(
                // The bytes were checksummed on their way to the disk, and the
                // writer compares the CRC: the copy is known intact as of now.
                // A repeated insert is fine; another node's location for the
                // same shard isn't (`blob_locations_shard`), and fails the
                // write.
                "INSERT INTO blob_locations (blob_id, node, shard, checked_at) VALUES ($1, $2, $3, NOW())
                 ON CONFLICT (blob_id, node) DO NOTHING",
                &[&blob_id, &app.node, &shard],
            )
            .await
            .map(|_| None),
        Some(from) => {
            // Held until the file has the blob's name (see `remove_unplaced`).
            file_lock = Some(app.writing.lock_file(blob_id).await);
            client
                .query_one_cached(
                    "SELECT status FROM pg_temp.cairn_move_shard($1, $2, $3, $4, $5)",
                    &[&blob_id, &shard, &from, &app.node, &(crc as i64)],
                )
                .await
                .map(|row| Some(row.get::<_, String>(0)))
        }
    };
    match announced {
        Ok(None) => {}
        Ok(Some(status)) if status == "moved" => {
            // Its location is here now: it's the blob's file. Failing that,
            // the location has no file, which reads fail over from, and the
            // scrubber repairs.
            if let Some(path) = staged
                && let Err(e) = app.store.install_move(path, blob_id).await
            {
                eprintln!("CORRUPTION: blob {blob_id}: shard {shard} moved here, but its file couldn't be installed: {e:#}");
                let _ = app.store.remove_at(path).await;
                crate::scrub::suspect(app, blob_id, app.node);
                return Err(e.into());
            }
            drop(file_lock);
        }
        // Nothing changed: the file is of no use.
        Ok(Some(status)) => {
            return Err(anyhow::anyhow!("blob {blob_id}: shard {shard} wasn't moved here: {status}").into());
        }
        Err(e) => {
            let maybe_announced = e.code().is_none();
            return Err(WriteFailure {
                error: e.into(),
                maybe_announced,
            });
        }
    }
    Ok(crc)
}

/// How a `BlobWriter` turns the blob's bytes into its shards.
enum Coding {
    /// Every shard is the blob, sent on as it comes.
    Replicated { summer: BlobSummer },
    /// The blob's rows are encoded as they fill (see `shards`).
    Coded {
        layout: shards::Layout,
        /// The row being filled.
        row: Vec<u8>,
        /// Each shard's table, and the CRC of its file, so far.
        summers: Vec<BlobSummer>,
        digests: Vec<crc64fast_nvme::Digest>,
    },
}

/// A new blob being written to its shards: a pending blob row, and a sink per
/// shard (local or remote) fed through a bounded channel, so the slowest one
/// applies backpressure. Computes the blob's checksums as the data passes.
/// Shared by uploads and the packer.
pub(crate) struct BlobWriter {
    app: Arc<App>,
    pub blob_id: Uuid,
    /// Where each shard goes, in shard order.
    pub locations: Vec<Location>,
    senders: Vec<FrameSender>,
    /// Each sink's shard, and the CRC of the file it stored.
    sinks: JoinSet<anyhow::Result<(u32, u64)>>,
    coding: Coding,
    /// The CRC of the blob's bytes.
    crc: crc64fast_nvme::Digest,
    size: u64,
    /// Whether the blob has been handed on (`finish`) or deleted (`abort`).
    /// Until then, dropping the writer deletes it (see `Drop`).
    settled: bool,
}

impl BlobWriter {
    /// Creates a pending replicated blob, and starts a sink for each shard.
    pub(crate) async fn begin(app: &Arc<App>) -> anyhow::Result<BlobWriter> {
        let writer = Self::start(app, None, 1, None).await?;
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
        Self::start(app, Some(bucket), 1, None).await
    }

    /// Creates a pending blob of `size` bytes in `data_shards` data shards
    /// (and the cluster's parity shards), and starts a sink for each shard.
    /// With one data shard, it's replicated.
    pub(crate) async fn begin_coded(app: &Arc<App>, data_shards: u32, size: u64) -> anyhow::Result<BlobWriter> {
        let writer = Self::start(app, None, data_shards, Some(size)).await?;
        Ok(writer.expect("only a bucket can be missing"))
    }

    async fn start(
        app: &Arc<App>,
        bucket: Option<&str>,
        data_shards: u32,
        size: Option<u64>,
    ) -> anyhow::Result<Option<BlobWriter>> {
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
        let shard_count = (data_shards + app.parity_shards()) as usize;
        // Independent of each other, so they're sent together, and take one
        // round trip between them.
        let (inserted, locations) = tokio::join!(insert, choose_nodes(&client, shard_count));
        if inserted? == 0 {
            pending.disarm();
            return Ok(None);
        }
        drop(client);
        let locations = match locations {
            Ok(locations) => locations,
            Err(e) => {
                // No sink has started, so there are only the row's to delete.
                blobs::discard(app, blob_id).await;
                pending.disarm();
                return Err(e);
            }
        };
        let coding = match size {
            Some(size) if data_shards > 1 => {
                let layout = shards::Layout::new(size, data_shards, app.parity_shards());
                Coding::Coded {
                    layout,
                    row: Vec::new(),
                    summers: (0..layout.shards()).map(|_| BlobSummer::new(checksum::BLOCK_SIZE)).collect(),
                    digests: (0..layout.shards()).map(|_| crc64fast_nvme::Digest::new()).collect(),
                }
            }
            _ => Coding::Replicated {
                summer: BlobSummer::new(checksum::BLOCK_SIZE),
            },
        };
        // The pooled connection was dropped above, before the (potentially long)
        // write: the local sink needs one to record its location, and concurrent
        // writes could otherwise exhaust the pool and deadlock.
        let mut senders = Vec::new();
        let mut sinks = JoinSet::new();
        for location in locations.clone() {
            let write = match &coding {
                Coding::Replicated { .. } => ShardWrite::Replica {
                    blob_id,
                    shard: location.shard,
                },
                Coding::Coded { layout, .. } => ShardWrite::Coded(ShardFile {
                    blob_id,
                    layout: *layout,
                    shard: location.shard,
                }),
            };
            let (tx, body) = channel_body();
            senders.push(tx);
            // A shard for ourselves goes straight to local disk (no HTTP hop,
            // and on a single host there's no peer server).
            let shard = location.shard;
            if location.node == app.node {
                let app = app.clone();
                sinks.spawn(async move { Ok((shard, write_blob_streaming(&app, &write, None, body).await?)) });
            } else {
                let peers = app.peers.clone();
                sinks.spawn(async move {
                    let peer_url = location.peer_url;
                    match upload_to_peer(&peers, &peer_url, &write, None, body).await {
                        Ok(crc) => Ok((shard, crc)),
                        Err(e) => Err(Unavailable(format!("node {peer_url}: {e:#}")).into()),
                    }
                });
            }
        }
        pending.disarm();
        Ok(Some(BlobWriter {
            app: app.clone(),
            blob_id,
            locations,
            senders,
            sinks,
            coding,
            crc: crc64fast_nvme::Digest::new(),
            size: 0,
            settled: false,
        }))
    }

    /// Appends `chunk` to the blob.
    pub(crate) async fn write(&mut self, chunk: Bytes) {
        self.crc.write(&chunk);
        self.size += chunk.len() as u64;
        match &mut self.coding {
            Coding::Replicated { summer } => {
                summer.update(&chunk);
                for tx in &self.senders {
                    // A dropped receiver means that sink's task failed; its real
                    // error surfaces in `finish`.
                    let _ = tx.send(Ok(Frame::data(chunk.clone()))).await;
                }
            }
            Coding::Coded { .. } => {
                let mut chunk = &chunk[..];
                while !chunk.is_empty() {
                    let Coding::Coded { layout, row, .. } = &mut self.coding else { unreachable!() };
                    let row_len = (layout.data_shards as u64 * layout.stripe_unit) as usize;
                    let take = chunk.len().min(row_len - row.len());
                    row.extend_from_slice(&chunk[..take]);
                    chunk = &chunk[take..];
                    if row.len() == row_len {
                        self.send_row().await;
                    }
                }
            }
        }
    }

    /// Encodes the row being filled (the last one may be short), and sends
    /// each of its cells to its shard.
    async fn send_row(&mut self) {
        let Coding::Coded { layout, row, summers, digests } = &mut self.coding else {
            unreachable!("only a coded blob has rows");
        };
        let row = Bytes::from(std::mem::take(row));
        let su = layout.stripe_unit as usize;
        let (k, m) = (layout.data_shards as usize, layout.parity_shards);
        let cells: Vec<Bytes> = (0..k).map(|j| row.slice((j * su).min(row.len())..((j + 1) * su).min(row.len()))).collect();
        let to_encode = cells.clone();
        let parity = tokio::task::spawn_blocking(move || {
            let cells: Vec<&[u8]> = to_encode.iter().map(|c| &c[..]).collect();
            shards::encode(&cells, m, su)
        })
        .await
        .expect("encoding doesn't panic");
        let all = cells.into_iter().chain(parity.into_iter().map(Bytes::from));
        for (shard, cell) in all.enumerate() {
            if cell.is_empty() {
                continue;
            }
            summers[shard].update(&cell);
            digests[shard].write(&cell);
            let _ = self.senders[shard].send(Ok(Frame::data(cell))).await;
        }
    }

    /// Gives up on the blob: faults the sinks, so no node durably stores the
    /// truncated data, waits for them, and deletes the pending blob and
    /// whatever its nodes stored.
    pub(crate) async fn abort(mut self, reason: &str) {
        let (senders, sinks) = (std::mem::take(&mut self.senders), std::mem::take(&mut self.sinks));
        give_up(&self.app, self.blob_id, senders, sinks, reason).await;
        self.settled = true;
    }

    /// Ends the blob and waits for every node to store its shard. Fails if one
    /// couldn't, or if one stored different bytes than were sent, and then
    /// deletes the pending blob and whatever its nodes stored.
    pub(crate) async fn finish(mut self) -> anyhow::Result<Written> {
        let blob_id = self.blob_id;
        // Every shard's file as it must be: the bytes sent, followed by the
        // trailer they determine. The data's CRC covers just the data; each
        // file's carries on over its trailer.
        let expected: Result<(shards::Layout, Vec<u64>), String> = match &mut self.coding {
            Coding::Replicated { summer } => {
                let summer = std::mem::replace(summer, BlobSummer::new(checksum::BLOCK_SIZE));
                let layout = shards::Layout::new(self.size, 1, self.app.parity_shards());
                let file = ShardFile { blob_id, layout, shard: 0 };
                let mut crc = self.crc.clone();
                crc.write(&blob_file::trailer(&file, &[summer.finish()]));
                Ok((layout, vec![crc.sum64(); layout.shards() as usize]))
            }
            Coding::Coded { layout, row, .. } => {
                let layout = *layout;
                if !row.is_empty() {
                    self.send_row().await;
                }
                let Coding::Coded { summers, digests, .. } = &mut self.coding else { unreachable!() };
                if self.size != layout.size {
                    Err(format!("got {} bytes of a blob of {}", self.size, layout.size))
                } else {
                    let tables: Vec<_> = std::mem::take(summers).into_iter().map(BlobSummer::finish).collect();
                    let sent: Vec<u8> = tables.iter().flat_map(|t| t.0.iter().copied()).collect();
                    let mut crcs = Vec::new();
                    for (shard, mut digest) in std::mem::take(digests).into_iter().enumerate() {
                        let file = ShardFile { blob_id, layout, shard: shard as u32 };
                        digest.write(&blob_file::trailer(&file, &tables));
                        crcs.push(digest.sum64());
                        let _ = self.senders[shard].send(Ok(Frame::data(Bytes::from(sent.clone())))).await;
                    }
                    Ok((layout, crcs))
                }
            }
        };
        let (layout, shard_crcs) = match expected {
            Ok(expected) => expected,
            Err(e) => {
                let (senders, sinks) = (std::mem::take(&mut self.senders), std::mem::take(&mut self.sinks));
                give_up(&self.app, blob_id, senders, sinks, &e).await;
                self.settled = true;
                anyhow::bail!("blob {blob_id}: {e}");
            }
        };
        self.senders.clear();
        // Every sink is waited for, also after one failed, so that none is still
        // writing when the blob is deleted.
        let mut stored = Vec::new();
        let mut failure = None;
        while let Some(res) = self.sinks.join_next().await {
            match res.map_err(anyhow::Error::from).and_then(|r| r) {
                Ok(crc) => stored.push(crc),
                Err(e) => failure = failure.or(Some(e)),
            }
        }
        if let Some(e) = failure {
            blobs::discard(&self.app, blob_id).await;
            self.settled = true;
            return Err(e);
        }
        // Every node must have stored exactly the file we expect. A mismatch
        // means a shard was damaged in transit or on its way to disk; the
        // write can be retried.
        if stored.iter().any(|&(shard, crc)| shard_crcs[shard as usize] != crc) {
            blobs::discard(&self.app, blob_id).await;
            self.settled = true;
            return Err(Unavailable(format!(
                "blob {blob_id}: a node stored different bytes than were sent"
            ))
            .into());
        }
        // From here on, the caller sees to the blob.
        self.settled = true;
        Ok(Written {
            blob_id,
            layout,
            locations: std::mem::take(&mut self.locations),
            data_crc: self.crc.sum64(),
            shard_crcs,
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
/// node durably stores the truncated data, waits for every sink (so that
/// none is still writing when the blob is deleted), and deletes the pending
/// blob and whatever its nodes stored.
async fn give_up(
    app: &Arc<App>,
    blob_id: Uuid,
    senders: Vec<FrameSender>,
    mut sinks: JoinSet<anyhow::Result<(u32, u64)>>,
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

/// A blob fully written to its shards, but still pending.
pub(crate) struct Written {
    pub blob_id: Uuid,
    pub layout: shards::Layout,
    /// Where its shards are, in shard order.
    pub locations: Vec<Location>,
    /// CRC64/NVME of its bytes, and of each shard's file as stored.
    pub data_crc: u64,
    pub shard_crcs: Vec<u64>,
}

impl Written {
    pub fn size(&self) -> u64 {
        self.layout.size
    }

    /// Its locations as the catalog's commits take them: nodes, and shards.
    pub fn location_columns(&self) -> (Vec<i32>, Vec<i16>) {
        self.locations.iter().map(|l| (l.node, l.shard as i16)).unzip()
    }

    /// Its shards' file CRCs as stored: their 64 bits, read as signed.
    pub fn crc_column(&self) -> Vec<i64> {
        self.shard_crcs.iter().map(|&crc| crc as i64).collect()
    }
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
/// `cairn_commit_upload_part`): confirms that all of the blob's shards
/// recorded their locations, and if so marks the blob committed (recording its
/// layout and the CRC64/NVME of each shard's file) and attaches a part spanning it to
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
    // shards' cover their whole files, for a scrub to check against.
    let size = written.size() as i64;
    let (nodes, shards) = written.location_columns();
    let shard_crcs = written.crc_column();
    let layout = written.layout;
    let block_size = layout.block_size as i32;
    let (data_shards, parity_shards) = (layout.data_shards as i16, layout.parity_shards as i16);
    let stripe_unit = layout.stripe_unit as i32;
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
                                                      $19, $20, $21, $22, $23, $24, $25, $26,
                                                      $27, $28, $29)",
                    &[
                        &written.blob_id,
                        &nodes,
                        &shards,
                        &size,
                        &block_size,
                        &data_shards,
                        &parity_shards,
                        &stripe_unit,
                        &shard_crcs,
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
                                                           $10, $11, $12, $13, $14, $15, $16)",
                    &[
                        &written.blob_id,
                        &nodes,
                        &shards,
                        &size,
                        &block_size,
                        &data_shards,
                        &parity_shards,
                        &stripe_unit,
                        &shard_crcs,
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
                required: written.locations.len(),
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
