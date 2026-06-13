use std::{net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use clap::{Args, Parser, Subcommand};
use deadpool_postgres::{Object, Pool};
use http_body_util::{BodyExt, Empty};
use hyper::{
    Method, Request, StatusCode, body::Body, body::Bytes, body::Frame, body::Incoming,
    server::conn::http1, service::service_fn,
};
use hyper_util::{client::legacy::Client, rt::TokioExecutor, rt::TokioIo};
use md5::{Digest, Md5};
use sha2::Sha256;
use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinSet};
use tokio_postgres::{IsolationLevel, error::SqlState};
use uuid::Uuid;

use crate::auth::ContentSha256;
use crate::aws_chunked::AwsChunkedDecoder;
use crate::body::{FrameSender, channel_body};
use crate::store::Store;
use crate::writing::WritingSet;

mod peer;

mod auth;
mod aws_chunked;
mod body;
mod db;
mod prune;
mod s3;
mod store;
mod writing;

pub struct App {
    pool: Pool,
    store: Store,
    replication_factor: usize,
    writing: WritingSet,
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
    /// Reclaim orphaned and failed-upload parts on a node (manual repair).
    Prune(PruneArgs),
}

#[derive(Args, Debug)]
struct ServeArgs {
    #[arg(long)]
    database: String,
    #[arg(long)]
    listen_client: String,
    /// Bind address for the peer endpoint (replica traffic + the prune endpoint).
    /// It always runs; defaults to a loopback port. Override to bind externally,
    /// or to run several nodes on one host.
    #[arg(long, default_value = "127.0.0.1:9431")]
    listen_peer: String,
    /// URL other nodes use to reach this node's peer endpoint, e.g.
    /// http://10.0.0.1:9431. Defaults to http://<listen-peer>; set it explicitly
    /// only if the bind address isn't routable (e.g. 0.0.0.0).
    #[arg(long)]
    peer_url: Option<String>,
    /// How many replicas every part is stored on.
    #[arg(long, default_value_t = 1)]
    replication_factor: usize,
    #[arg(long)]
    data_dir: String,
}

#[derive(Args, Debug)]
struct PruneArgs {
    /// Peer URL of the node to prune.
    #[arg(long, default_value = "http://127.0.0.1:9431")]
    peer: String,
    /// Actually delete; without this it's a dry run that only reports.
    #[arg(long)]
    apply: bool,
}

/// How often a node refreshes its `nodes` row (last_seen / free_space).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Serve(args) => serve_main(args).await,
        Command::Prune(args) => prune_main(args).await,
    }
}

async fn serve_main(args: ServeArgs) -> anyhow::Result<()> {
    let pool = db::connect(&args.database).await?;
    let app = Arc::new(App {
        pool,
        store: Store::new(args.data_dir)?,
        replication_factor: args.replication_factor,
        writing: WritingSet::default(),
    });
    // The URL peers use to reach us: explicit if given, otherwise derived from
    // the (always-set) peer bind address.
    let peer_url = args
        .peer_url
        .clone()
        .unwrap_or_else(|| format!("http://{}", args.listen_peer));
    // Register this node before serving traffic, then keep its heartbeat fresh in
    // the background.
    register_node(&app, &peer_url).await?;
    tokio::spawn(heartbeat(app.clone(), peer_url));

    let listen_client_addr = SocketAddr::from_str(&args.listen_client).unwrap();
    let listen_peer_addr = SocketAddr::from_str(&args.listen_peer).unwrap();
    // Both servers run and loop forever, so awaiting them keeps the process alive
    // until one errors out.
    tokio::try_join!(
        serve(listen_client_addr, app.clone(), ServeKind::Client),
        serve(listen_peer_addr, app.clone(), ServeKind::Peer),
    )?;
    Ok(())
}

/// `cairn prune`: triggers a prune on a node's peer endpoint and streams its
/// report to stdout.
async fn prune_main(args: PruneArgs) -> anyhow::Result<()> {
    let http = Client::builder(TokioExecutor::new()).build_http();
    let url = format!(
        "{}/prune?apply={}",
        args.peer.trim_end_matches('/'),
        args.apply,
    );
    let req = Request::builder()
        .method(Method::POST)
        .uri(url)
        .body(Empty::<Bytes>::new())?;
    let res = http.request(req).await?;
    if res.status() != StatusCode::OK {
        anyhow::bail!("prune request to {} failed: {}", args.peer, res.status());
    }
    // Stream the report straight to stdout as the node produces it.
    let mut body = res.into_body();
    let mut stdout = tokio::io::stdout();
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame?.into_data() {
            stdout.write_all(&data).await?;
        }
    }
    stdout.flush().await?;
    Ok(())
}

/// Upserts this node's row in `nodes`. Used both for the initial registration
/// and for each heartbeat, since both are the same "I'm alive, here's my state"
/// statement.
async fn register_node(app: &App, peer_url: &str) -> anyhow::Result<()> {
    let client = app.pool.get().await?;
    let node_id = app.store.get_node_id().to_string();
    let free_space = app.store.available_space()? as i64;
    client
        .execute(
            "INSERT INTO nodes (node_id, peer_url, last_seen, free_space)
             VALUES ($1, $2, NOW(), $3)
             ON CONFLICT (node_id)
             DO UPDATE SET peer_url = $2, last_seen = NOW(), free_space = $3",
            &[&node_id, &peer_url, &free_space],
        )
        .await?;
    Ok(())
}

async fn heartbeat(app: Arc<App>, peer_url: String) {
    let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
    loop {
        interval.tick().await;
        if let Err(e) = register_node(&app, &peer_url).await {
            eprintln!("heartbeat failed: {e}");
        }
    }
}

#[derive(Clone, Copy)]
enum ServeKind {
    Client,
    Peer,
}

async fn serve(addr: SocketAddr, app: Arc<App>, kind: ServeKind) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (stream, _peer_addr) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let app = app.clone();
        tokio::task::spawn(async move {
            let service = service_fn(move |req| {
                let app = app.clone();
                async move {
                    match kind {
                        ServeKind::Client => s3::handle(req, app).await,
                        ServeKind::Peer => peer::handle(req, app).await,
                    }
                }
            });
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}

async fn choose_replicas(client: &Object, count: usize) -> anyhow::Result<Vec<(String, String)>> {
    let nodes = client
        .query(
            "SELECT node_id, peer_url FROM nodes WHERE last_seen > NOW() - INTERVAL '10 seconds' ORDER BY free_space DESC",
            &[],
        )
        .await?;
    if nodes.len() < count {
        anyhow::bail!(
            "need {count} replicas but only {} node(s) are registered",
            nodes.len()
        );
    }
    Ok(nodes[0..count]
        .iter()
        .map(|n| (n.get("node_id"), n.get("peer_url")))
        .collect())
}

/// Streams a part body to a single replica's peer endpoint. Generic over the
/// body so the caller can hand us any stream (e.g. one side of a fan-out tee),
/// not just the original client `Incoming`.
async fn upload_to_replica<B>(peer_url: &str, part_id: Uuid, body: B) -> anyhow::Result<()>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let client = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method(Method::PUT)
        .uri(format!("{peer_url}/parts/{part_id}"))
        .body(body)?;
    let res = client.request(req).await?;
    if res.status() != StatusCode::OK {
        anyhow::bail!("replica {peer_url} returned status {}", res.status());
    }
    Ok(())
}

/// Streams a body to this node's local disk, fsyncs it, and records this node as
/// a location for the part. Shared by the peer PUT endpoint (an `Incoming`) and
/// the local-replica sink in `upload_part` (a channel-backed body) — hence the
/// generic body.
async fn write_part_streaming<B>(app: &App, part_id: Uuid, mut body: B) -> anyhow::Result<()>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    // Mark the part as being written for the whole write→announce window, so the
    // GC's file sweep won't treat this in-flight file (no location yet) as an
    // orphan. The guard drops after the location insert below.
    let _writing = app.writing.begin(part_id);
    let mut file = app.store.create_part(part_id).await?;
    while let Some(frame) = body.frame().await {
        if let Ok(chunk) = frame?.into_data() {
            file.write_all(&chunk).await?;
        }
    }
    // fsync before announcing the location, so the bytes survive a crash by the
    // time the leader's commit can count this replica.
    file.sync_all().await?;
    let node_id = app.store.get_node_id().to_string();
    let client = app.pool.get().await?;
    client
        .execute(
            "INSERT INTO part_locations (part_id, node_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            &[&part_id, &node_id],
        )
        .await?;
    Ok(())
}

/// Where a freshly-committed part should be attached. The attach happens inside
/// the same serializable transaction that flips the part to 'committed', so the
/// invariant "committed implies referenced" holds with no orphan window.
/// The size and ETag aren't carried here: they're computed by `upload_part` as
/// the body streams, and passed to `try_commit_part` alongside the target.
enum AttachTarget {
    /// A single-PUT object: point (bucket, key) at exactly this one part,
    /// replacing whatever it referenced before.
    Object {
        bucket: String,
        key: String,
        content_type: String,
    },
    /// A part staged under an in-progress multipart upload.
    MultipartPart { upload_id: Uuid, part_number: i32 },
}

/// Streams `body` into a fresh part replicated across the cluster — hashing it
/// as it flows — then commits and attaches it to `attach`. Returns the ETag.
/// The outcome of an upload: the committed part's ETag, or a rejection because
/// the streamed body didn't match the client's `x-amz-content-sha256`.
enum UploadResult {
    Committed(String),
    ContentSha256Mismatch,
}

async fn upload_part(
    app: &Arc<App>,
    mut body: Incoming,
    attach: &AttachTarget,
    aws_chunked: bool,
    content_sha256: ContentSha256,
) -> anyhow::Result<UploadResult> {
    let client = app.pool.get().await?;
    let part_id = Uuid::new_v4();
    // 1. create the pending part. Its size isn't known until the body is fully
    // streamed, so it starts at 0 and is set at commit.
    client
        .execute(
            "INSERT INTO parts (part_id, size, state, created_at) VALUES ($1, 0, 'pending', NOW())",
            &[&part_id],
        )
        .await?;
    // 2. choose replicas; give each (local or remote) a channel-backed body that
    // the tee loop below feeds. A replica that is ourselves writes straight to
    // local disk (no HTTP hop — and on a single host there's no peer server).
    let replicas = choose_replicas(&client, app.replication_factor).await?;
    let node_ids: Vec<String> = replicas.iter().map(|(id, _)| id.clone()).collect();
    // Don't hold a pooled connection across the (potentially long) stream — the
    // local sink needs one to record its location, and concurrent uploads could
    // otherwise exhaust the pool and deadlock. Re-acquire one for the commit.
    drop(client);
    let self_id = app.store.get_node_id().to_string();
    let mut senders: Vec<FrameSender> = Vec::new();
    let mut sinks = JoinSet::new();
    for (node_id, peer_url) in replicas {
        let (tx, part_body) = channel_body();
        senders.push(tx);
        if node_id == self_id {
            let app = app.clone();
            sinks.spawn(async move { write_part_streaming(&app, part_id, part_body).await });
        } else {
            sinks.spawn(async move { upload_to_replica(&peer_url, part_id, part_body).await });
        }
    }
    // 3. tee: read the client body once, hashing and fanning each chunk out to
    // every replica. The bounded channels apply backpressure at the slowest sink.
    let mut hasher = Md5::new();
    let mut size: i64 = 0;
    let mut read_err: Option<anyhow::Error> = None;
    // A streaming-signature upload arrives `aws-chunked` framed; decode it back to
    // the raw object bytes before hashing/sizing/teeing, so the ETag and size
    // describe the object — not the framing.
    let mut decoder = aws_chunked.then(AwsChunkedDecoder::new);
    // Verify body integrity for a whole-body hash claim. The chunked modes carry
    // their integrity differently (trailer checksum or per-chunk signatures), so
    // they're handled elsewhere — only a non-chunked Single() hash is checked here.
    // `Md5` and `Sha256` share one `Digest` trait (same `digest` version), so both
    // hashers coexist here without trait ambiguity.
    let mut content_hasher: Option<Sha256> =
        matches!((&content_sha256, aws_chunked), (ContentSha256::Single(_), false))
            .then(Sha256::new);
    loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                let Ok(chunk) = frame.into_data() else { continue };
                let segments = match &mut decoder {
                    Some(dec) => match dec.decode(chunk) {
                        Ok(segments) => segments,
                        Err(e) => {
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
                    size += chunk.len() as i64;
                    for tx in &senders {
                        // A dropped receiver means that sink's task failed; we'll
                        // surface its real error when we drain the JoinSet.
                        let _ = tx.send(Ok(Frame::data(chunk.clone()))).await;
                    }
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
    // On a client read error, fault the sinks so they don't durably store a
    // truncated part; then close the channels so the bodies finish.
    if let Some(e) = &read_err {
        for tx in &senders {
            let _ = tx.send(Err(std::io::Error::other(e.to_string()))).await;
        }
    }
    drop(senders);
    // 4. wait for every replica to finish (or fail).
    while let Some(res) = sinks.join_next().await {
        res??;
    }
    if let Some(e) = read_err {
        return Err(e);
    }
    // The body is fully read and replicated (but not yet committed). If the client
    // claimed a whole-body hash, check it now and refuse to commit on a mismatch —
    // the pending part is left for the GC to reclaim.
    if let (Some(h), ContentSha256::Single(expected)) = (content_hasher, &content_sha256) {
        let actual: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        if actual != *expected {
            return Ok(UploadResult::ContentSha256Mismatch);
        }
    }
    let etag: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
    // 5. commit + attach with the now-known size and ETag, under a serializable
    // transaction; retry on a serialization conflict (e.g. a concurrent GC).
    let mut client = app.pool.get().await?;
    let mut committed = false;
    for _ in 0..MAX_COMMIT_ATTEMPTS {
        match try_commit_part(&mut client, part_id, &node_ids, attach, size, &etag).await {
            Ok(CommitResult::Committed) => {
                committed = true;
                break;
            }
            Ok(CommitResult::MissingLocations { present, required }) => anyhow::bail!(
                "part {part_id} not durable: only {present}/{required} replicas reported a location"
            ),
            Err(e) if e.code() == Some(&SqlState::T_R_SERIALIZATION_FAILURE) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    if !committed {
        anyhow::bail!(
            "part {part_id}: commit aborted after {MAX_COMMIT_ATTEMPTS} serialization retries"
        );
    }
    Ok(UploadResult::Committed(etag))
}

const MAX_COMMIT_ATTEMPTS: usize = 10;

enum CommitResult {
    Committed,
    MissingLocations { present: i64, required: usize },
}

/// Runs the commit transaction once under SERIALIZABLE isolation: confirms that
/// all `node_ids` hold a location for `part_id`, and if so marks the part
/// committed and attaches it to `attach` in the same transaction. The raw
/// postgres error is returned unwrapped so the caller can distinguish a
/// serialization failure (retry) from a real error (give up).
async fn try_commit_part(
    client: &mut Object,
    part_id: Uuid,
    node_ids: &[String],
    attach: &AttachTarget,
    size: i64,
    etag: &str,
) -> Result<CommitResult, tokio_postgres::Error> {
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()
        .await?;
    let present: i64 = tx
        .query_one(
            "SELECT count(*) FROM part_locations WHERE part_id = $1 AND node_id = ANY($2)",
            &[&part_id, &node_ids],
        )
        .await?
        .get(0);
    if present as usize != node_ids.len() {
        // A location is missing; dropping `tx` here rolls the transaction back.
        return Ok(CommitResult::MissingLocations {
            present,
            required: node_ids.len(),
        });
    }
    match attach {
        AttachTarget::Object {
            bucket,
            key,
            content_type,
        } => {
            // Upsert the object's metadata first, so the part's owner FK target
            // exists.
            tx.execute(
                "INSERT INTO objects (bucket, key, size, etag, content_type, last_modified)
                 VALUES ($1, $2, $3, $4, $5, NOW())
                 ON CONFLICT (bucket, key)
                 DO UPDATE SET size = $3, etag = $4, content_type = $5, last_modified = NOW()",
                &[bucket, key, &size, &etag, content_type],
            )
            .await?;
            // Drop whatever parts the key referenced before: their rows (and, via
            // cascade, their part_locations) go now, their on-disk bytes are
            // reclaimed later by GC. This also frees the (bucket, key, part_number)
            // slot for the new part.
            tx.execute(
                "DELETE FROM parts WHERE object_bucket = $1 AND object_key = $2",
                &[bucket, key],
            )
            .await?;
            // Commit this part and point it at the object in one step.
            tx.execute(
                "UPDATE parts
                 SET state = 'committed', size = $1, etag = $2,
                     object_bucket = $3, object_key = $4, part_number = 1
                 WHERE part_id = $5",
                &[&size, &etag, bucket, key, &part_id],
            )
            .await?;
        }
        AttachTarget::MultipartPart {
            upload_id,
            part_number,
        } => {
            // Displace any part previously uploaded at this number (S3 allows
            // re-uploading a part number); its row + locations go now, its file
            // is reclaimed later by GC. Frees the (upload_id, part_number) slot.
            tx.execute(
                "DELETE FROM parts WHERE upload_id = $1 AND part_number = $2",
                &[upload_id, part_number],
            )
            .await?;
            // Commit this part and stage it under the upload in one step.
            tx.execute(
                "UPDATE parts
                 SET state = 'committed', size = $1, etag = $2, upload_id = $3, part_number = $4
                 WHERE part_id = $5",
                &[&size, &etag, upload_id, part_number, &part_id],
            )
            .await?;
        }
    }
    tx.commit().await?;
    Ok(CommitResult::Committed)
}
