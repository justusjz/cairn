use std::{net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use clap::{Args, Parser, Subcommand};
use deadpool_postgres::{Object, Pool};
use http_body_util::BodyExt;
use hyper::{
    Method, Request, StatusCode, body::Body, body::Bytes, body::Frame,
    server::conn::http1, service::service_fn,
};
use hyper_util::{client::legacy::Client, rt::TokioExecutor, rt::TokioIo};
use md5::{Digest, Md5};
use sha2::Sha256;
use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinSet};
use tokio_postgres::IsolationLevel;
use uuid::Uuid;

use crate::auth::{ContentSha256, StreamingChunkVerifier, TrailerChecksum};
use crate::aws_chunked::AwsChunkedDecoder;
use crate::blobs::{Location, ReapTarget, deleted_parts, drop_blobs_of_deleted_parts, reap_blobs};
use crate::body::{FrameSender, channel_body};
use crate::checksum::BlobSummer;
use crate::s3::{conditional::Preconditions, versions::Versioning};
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

#[derive(Args, Debug)]
struct ServeArgs {
    #[arg(long)]
    database: String,
    #[arg(long)]
    listen_client: String,
    /// Bind address for the peer endpoint (replica traffic between nodes).
    /// It always runs; defaults to a loopback port. Override to bind externally,
    /// or to run several nodes on one host.
    #[arg(long, default_value = "127.0.0.1:9431")]
    listen_peer: String,
    /// URL other nodes use to reach this node's peer endpoint, e.g.
    /// http://10.0.0.1:9431. Defaults to http://<listen-peer>; set it explicitly
    /// only if the bind address isn't routable (e.g. 0.0.0.0).
    #[arg(long)]
    peer_url: Option<String>,
    /// How many replicas every blob is stored on.
    #[arg(long, default_value_t = 1)]
    replication_factor: usize,
    #[arg(long)]
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
        #[cfg(test)]
        pack_hook: None,
    });
    tokio::spawn(heartbeat(app.clone(), peer_url));
    tokio::spawn(maintain(app.clone()));

    let listen_client_addr = SocketAddr::from_str(&args.listen_client).unwrap();
    let listen_peer_addr = SocketAddr::from_str(&args.listen_peer).unwrap();
    // Both servers run and loop forever, so awaiting them keeps the process alive
    // until one errors out.
    tokio::try_join!(
        serve_client(listen_client_addr, app.clone()),
        serve_peer(listen_peer_addr, app.clone()),
    )?;
    Ok(())
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
        .query_one(
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

/// A transaction that kept failing with serialization conflicts against
/// concurrent ones, and gave up. Answered with 503 SlowDown, so the client
/// backs off and retries.
#[derive(Debug)]
pub struct Contended(pub String);

impl std::fmt::Display for Contended {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Contended {}

/// Serves the S3 API, counting every request in the node's metrics.
async fn serve_client(addr: SocketAddr, app: Arc<App>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (stream, _peer_addr) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let app = app.clone();
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
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}

/// Serves the peer endpoint (see `peer`).
async fn serve_peer(addr: SocketAddr, app: Arc<App>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, peer::router(app)).await?;
    Ok(())
}

async fn choose_replicas(client: &Object, count: usize) -> anyhow::Result<Vec<Location>> {
    let nodes = client
        .query(
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

/// Streams a blob body to a single replica's peer endpoint, returning the
/// CRC64/NVME the replica reports for the file it stored. Generic over the body so the
/// caller can hand us any stream (e.g. one side of a fan-out tee), not just the
/// original client `Incoming`.
async fn upload_to_replica<B>(peer_url: &str, blob_id: Uuid, body: B) -> anyhow::Result<u64>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let client = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method(Method::PUT)
        .uri(format!("{peer_url}/blobs/{blob_id}"))
        .body(body)?;
    let res = client.request(req).await?;
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
async fn write_blob_streaming<B>(app: &App, blob_id: Uuid, mut body: B) -> anyhow::Result<u64>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    // Mark the blob as being written for the whole write→announce window, so the
    // GC's file sweep won't treat this in-flight file (no location yet) as an
    // orphan. The guard drops after the location insert below.
    let _writing = app.writing.begin(blob_id);
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
    client
        .execute(
            "INSERT INTO blob_locations (blob_id, node) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            &[&blob_id, &app.node],
        )
        .await?;
    Ok(file_crc.sum64())
}

/// A new blob being written to its replicas: a pending blob row, and a sink per
/// replica (local or remote) fed through a bounded channel, so the slowest one
/// applies backpressure. Computes the blob's checksums as the data passes.
/// Shared by uploads and the packer.
pub(crate) struct BlobWriter {
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
        let client = app.pool.get().await?;
        // Time-ordered, so new blobs land at the end of the indexes on blob_id.
        let blob_id = Uuid::now_v7();
        // Its size isn't known until all the data has passed, so it starts at 0
        // and is set at commit.
        client
            .execute(
                "INSERT INTO blobs (blob_id, size, state, created_at) VALUES ($1, 0, 'pending', NOW())",
                &[&blob_id],
            )
            .await?;
        let replicas = choose_replicas(&client, app.replication_factor).await?;
        // Don't hold a pooled connection across the (potentially long) write: the
        // local sink needs one to record its location, and concurrent writes could
        // otherwise exhaust the pool and deadlock.
        drop(client);
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
                sinks.spawn(async move {
                    upload_to_replica(&peer_url, blob_id, body)
                        .await
                        .map_err(|e| Unavailable(format!("replica {peer_url}: {e:#}")).into())
                });
            }
        }
        Ok(BlobWriter {
            blob_id,
            replicas,
            senders,
            sinks,
            summer: BlobSummer::new(checksum::BLOCK_SIZE),
            crc: crc64fast_nvme::Digest::new(),
            size: 0,
        })
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
    /// truncated data, and waits for them. The pending blob is left for the GC.
    pub(crate) async fn abort(mut self, reason: &str) {
        for tx in &self.senders {
            let _ = tx.send(Err(std::io::Error::other(reason.to_owned()))).await;
        }
        self.senders.clear();
        // Their resulting errors are expected.
        while self.sinks.join_next().await.is_some() {}
    }

    /// Ends the blob and waits for every replica to store it. Fails if one
    /// couldn't, or if one stored different bytes than were sent.
    pub(crate) async fn finish(mut self) -> anyhow::Result<Written> {
        self.senders.clear();
        let mut replica_crcs = Vec::new();
        while let Some(res) = self.sinks.join_next().await {
            replica_crcs.push(res??);
        }
        // Every replica must have stored exactly the file we expect: the bytes we
        // sent, followed by the checksum table and blob ID they determine. A
        // mismatch means a copy was damaged in transit or on its way to disk; the
        // pending blob is left for the GC, and the write can be retried.
        // The data's CRC covers just the data; the file's carries on over the
        // trailer.
        let blob_id = self.blob_id;
        let data_crc = self.crc.sum64();
        self.crc.write(&blob_file::trailer(blob_id, &self.summer.finish()));
        let file_crc = self.crc.sum64();
        if replica_crcs.iter().any(|&replica_crc| replica_crc != file_crc) {
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

impl Written {
    /// Commits the blob, as part of the caller's (serializable) transaction,
    /// which must also attach a part to it. Confirms first that every replica
    /// recorded its location; if not, returns how many did, and changes nothing.
    pub(crate) async fn commit(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
    ) -> Result<Result<(), i64>, tokio_postgres::Error> {
        let present: i64 = tx
            .query_one(
                "SELECT count(*) FROM blob_locations WHERE blob_id = $1 AND node = ANY($2)",
                &[&self.blob_id, &self.nodes],
            )
            .await?
            .get(0);
        if present as usize != self.nodes.len() {
            return Ok(Err(present));
        }
        // The CRC covers the blob's whole file, for a scrub to check against.
        // Stored as its 64 bits, read as a signed BIGINT.
        let file_crc = self.file_crc as i64;
        let block_size = checksum::BLOCK_SIZE as i32;
        tx.execute(
            "UPDATE blobs SET state = 'committed', size = $2, crc64nvme = $3, block_size = $4
             WHERE blob_id = $1",
            &[&self.blob_id, &(self.size as i64), &file_crc, &block_size],
        )
        .await?;
        Ok(Ok(()))
    }
}

/// Where a freshly-uploaded part should be attached. The part row is inserted
/// in the same serializable transaction that flips its blob to 'committed', so
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

/// The outcome of an upload: the committed part's ETag, or a rejection because
/// the streamed body didn't match the client's `x-amz-content-sha256`.
enum UploadResult {
    /// Committed, with the new part's ETag and, for an object write, the
    /// `x-amz-version-id` to report for the version it created.
    Committed {
        etag: String,
        version_id: Option<String>,
    },
    ContentSha256Mismatch,
    /// A mode-4 chunk signature didn't verify against the secret.
    ChunkSignatureMismatch,
    /// A conditional-write guard (If-Match / If-None-Match) didn't hold against
    /// the object currently at the target key.
    PreconditionFailed,
}

async fn upload_part<B>(
    app: &Arc<App>,
    mut body: B,
    attach: &AttachTarget,
    aws_chunked: bool,
    content_sha256: ContentSha256,
    chunk_verifier: Option<StreamingChunkVerifier>,
) -> anyhow::Result<UploadResult>
where
    B: Body<Data = Bytes> + Unpin + Send,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    // 1-2. create the pending blob and start writing it to its replicas.
    let mut writer = BlobWriter::begin(app).await?;
    let blob_id = writer.blob_id;
    // 3. tee: read the client body once, hashing it and fanning each chunk out
    // to every replica.
    let mut hasher = Md5::new();
    let mut read_err: Option<anyhow::Error> = None;
    // A streaming-signature upload arrives `aws-chunked` framed; decode it back to
    // the raw object bytes before hashing/sizing/teeing, so the ETag and size
    // describe the object — not the framing. A verifier (mode 4) checks each
    // chunk's signature as it's decoded; a bad chunk faults the stream.
    let verifying = chunk_verifier.is_some();
    let mut chunk_failed = false;
    let mut decoder = aws_chunked.then(move || AwsChunkedDecoder::new(chunk_verifier));
    // Verify body integrity for a whole-body hash claim. The chunked modes carry
    // their integrity differently (trailer checksum or per-chunk signatures), so
    // they're handled elsewhere — only a non-chunked Single() hash is checked here.
    // `Md5` and `Sha256` share one `Digest` trait (same `digest` version), so both
    // hashers coexist here without trait ambiguity.
    let mut content_hasher: Option<Sha256> =
        matches!((&content_sha256, aws_chunked), (ContentSha256::Single(_), false))
            .then(Sha256::new);
    // For an `aws-chunked` trailer body, compute the declared checksum over the
    // decoded payload; it's compared to the body's trailer value at the end. An
    // algorithm we don't support is skipped (logged) rather than rejected.
    let mut trailer_checksum = match (&content_sha256, aws_chunked) {
        (ContentSha256::StreamingTrailer { trailer }, true) => {
            let checksum = TrailerChecksum::for_trailer(trailer);
            if checksum.is_none() && !trailer.is_empty() {
                eprintln!("unsupported aws-chunked trailer '{trailer}', skipping integrity check");
            }
            checksum
        }
        _ => None,
    };
    loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                let Ok(chunk) = frame.into_data() else { continue };
                let segments = match &mut decoder {
                    Some(dec) => match dec.decode(chunk) {
                        Ok(segments) => segments,
                        Err(e) => {
                            // A decode error while verifying is a bad chunk
                            // signature (or malformed signed framing) — a client
                            // error, surfaced as 403 rather than a 500.
                            chunk_failed = verifying;
                            read_err = Some(e.into());
                            break;
                        }
                    },
                    None => vec![chunk],
                };
                for chunk in segments {
                    hasher.update(&chunk);
                    if let Some(h) = &mut content_hasher {
                        h.update(&chunk);
                    }
                    if let Some(c) = &mut trailer_checksum {
                        c.update(&chunk);
                    }
                    writer.write(chunk).await;
                }
            }
            Some(Err(e)) => {
                read_err = Some(e.into());
                break;
            }
            None => {
                // A chunked body must end with its terminating zero-size chunk;
                // stopping short means truncation, so fault the sinks rather than
                // durably store a short object.
                if let Some(dec) = &decoder
                    && !dec.is_complete()
                {
                    read_err = Some(std::io::Error::other("aws-chunked: truncated body").into());
                }
                break;
            }
        }
    }
    // 4. wait for every replica to finish. On a client read error, fault the
    // sinks instead, so they don't durably store a truncated part.
    if let Some(e) = read_err {
        writer.abort(&e.to_string()).await;
        // A bad chunk signature (mode 4) is a client error, not a server fault.
        if chunk_failed {
            return Ok(UploadResult::ChunkSignatureMismatch);
        }
        return Err(e);
    }
    let written = writer.finish().await?;
    // The body is fully read and replicated (but not yet committed). If the client
    // claimed a whole-body hash, check it now and refuse to commit on a mismatch —
    // the pending blob is left for the GC to reclaim.
    if let (Some(h), ContentSha256::Single(expected)) = (content_hasher, &content_sha256) {
        let actual: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        if actual != *expected {
            return Ok(UploadResult::ContentSha256Mismatch);
        }
    }
    // For a trailer body, compare our checksum to the value the body carried in
    // its trailer (captured by the decoder). A missing/garbled trailer fails too.
    if let (Some(c), ContentSha256::StreamingTrailer { trailer }) =
        (trailer_checksum, &content_sha256)
    {
        let claimed = decoder.as_ref().and_then(|d| d.trailer(trailer));
        if claimed.as_deref() != Some(c.finish_base64().as_str()) {
            return Ok(UploadResult::ContentSha256Mismatch);
        }
    }
    let etag: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
    // 5. commit + attach with the now-known size and ETag, under a serializable
    // transaction; retry on a serialization conflict (e.g. a concurrent upload
    // to a neighbouring key).
    let mut client = app.pool.get().await?;
    let mut committed = None;
    let mut precondition_failed = false;
    for attempt in 0..db::MAX_TX_ATTEMPTS {
        db::backoff(attempt).await;
        match try_commit_part(&mut client, &written, attach, &etag).await {
            Ok(CommitResult::Committed { reap, version_id }) => {
                // Reap the blobs this overwrite displaced; their rows are gone.
                reap_blobs(app, reap);
                committed = Some(version_id);
                break;
            }
            Ok(CommitResult::PreconditionFailed) => {
                precondition_failed = true;
                break;
            }
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
    // The pending blob left behind by a failed conditional write is reclaimed by
    // the GC, exactly like the content-sha256 mismatch path above.
    if precondition_failed {
        return Ok(UploadResult::PreconditionFailed);
    }
    let Some(version_id) = committed else {
        return Err(Contended(format!(
            "blob {blob_id}: commit kept conflicting with concurrent ones"
        ))
        .into());
    };
    Ok(UploadResult::Committed { etag, version_id })
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
}

/// Runs the commit transaction once under SERIALIZABLE isolation: confirms that
/// all `nodes` hold a location for `blob_id`, and if so marks the blob committed
/// (recording its size and the CRC64/NVME of its file) and attaches a part
/// spanning it to `attach` (with the CRC64/NVME of its data), in the same
/// transaction. The raw postgres error is returned unwrapped so the
/// caller can distinguish a serialization failure (retry) from a real error
/// (give up).
async fn try_commit_part(
    client: &mut Object,
    written: &Written,
    attach: &AttachTarget,
    etag: &str,
) -> Result<CommitResult, tokio_postgres::Error> {
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()
        .await?;
    if let Err(present) = written.commit(&tx).await? {
        // A location is missing; dropping `tx` here rolls the transaction back.
        return Ok(CommitResult::MissingLocations {
            present,
            required: written.nodes.len(),
        });
    }
    let blob_id = written.blob_id;
    let size = written.size as i64;
    // The part's CRC covers just its data, and stays valid wherever it's moved
    // later. Stored as its 64 bits, read as a signed BIGINT.
    let crc = written.data_crc as i64;
    const INSERT_PART: &str = "INSERT INTO parts
             (blob_id, blob_offset, size, etag, crc64nvme, object_id, upload_id, part_number,
              created_at)
         VALUES ($1, 0, $2, $3, $4, $5, $6, $7, NOW())";
    // Parts this transaction deletes; their blobs are dropped at its end.
    let mut freed = Vec::new();
    let mut version_id = None;
    match attach {
        AttachTarget::Object {
            bucket,
            key,
            content_type,
            conditions,
        } => {
            // Conditional write: evaluate If-Match / If-None-Match against the
            // object currently at the key, inside this serializable transaction so
            // the guard is atomic with the overwrite below (a pre-check would race
            // a concurrent writer). Skipped when no write conditions are set.
            if conditions.has_write_conditions() {
                let current = s3::versions::current_etag(&tx, bucket, key).await?;
                if !conditions.allows_write(current.as_deref()) {
                    // Dropping `tx` here rolls the transaction back.
                    return Ok(CommitResult::PreconditionFailed);
                }
            }
            // Insert the new version first, so the part's owner FK target exists.
            // Reading the bucket's versioning state in this transaction orders the
            // write against a concurrent PutBucketVersioning. A bucket deleted
            // meanwhile reads as unversioned; the objects -> buckets FK then
            // rejects the insert.
            let versioning = s3::versions::bucket_versioning(&tx, bucket)
                .await?
                .unwrap_or(Versioning::Unversioned);
            let version = s3::versions::put_version(
                &tx, bucket, key, versioning, size, etag, content_type, &mut freed,
            )
            .await?;
            version_id = version.version_id;
            tx.execute(
                INSERT_PART,
                &[&blob_id, &size, &etag, &crc, &Some(version.id), &None::<Uuid>, &1i32],
            )
            .await?;
        }
        AttachTarget::MultipartPart {
            upload_id,
            part_number,
        } => {
            // Displace any part previously uploaded at this number (S3 allows
            // re-uploading a part number), freeing the (upload_id, part_number)
            // slot.
            let displaced = tx
                .query(
                    "DELETE FROM parts WHERE upload_id = $1 AND part_number = $2
                     RETURNING blob_id, size",
                    &[upload_id, part_number],
                )
                .await?;
            freed.extend(deleted_parts(&displaced));
            tx.execute(
                INSERT_PART,
                &[&blob_id, &size, &etag, &crc, &None::<i64>, &Some(*upload_id), part_number],
            )
            .await?;
        }
    }
    let reap = drop_blobs_of_deleted_parts(&tx, &freed).await?;
    tx.commit().await?;
    Ok(CommitResult::Committed { reap, version_id })
}
