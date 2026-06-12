use std::{net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use clap::Parser;
use deadpool_postgres::{Object, Pool};
use http_body_util::{BodyExt, Empty, Full};
use hyper::{
    Method, Request, StatusCode, body::Body, body::Bytes, server::conn::http1, service::service_fn,
};
use hyper_util::{client::legacy::Client, rt::TokioExecutor, rt::TokioIo};
use tokio::{net::TcpListener, task::JoinSet};
use tokio_postgres::{IsolationLevel, error::SqlState};
use uuid::Uuid;

use crate::store::Store;

mod peer;

mod db;
mod s3;
mod store;

pub struct App {
    pool: Pool,
    store: Store,
    replication_factor: usize,
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    database: String,
    #[arg(long)]
    listen_client: String,
    /// Bind address for the peer endpoint. Omit on a single-host deployment:
    /// with no peers to talk to, a node serves its own replicas locally.
    #[arg(long)]
    listen_peer: Option<String>,
    /// URL other nodes use to reach this node's peer endpoint, e.g.
    /// http://10.0.0.1:9001. Defaults to http://<listen-peer> when omitted; set
    /// it explicitly only if the bind address isn't routable (e.g. 0.0.0.0).
    #[arg(long)]
    peer_url: Option<String>,
    /// How many replicas every part is stored on.
    #[arg(long, default_value_t = 1)]
    replication_factor: usize,
    #[arg(long)]
    data_dir: String,
}

/// How often a node refreshes its `nodes` row (last_seen / free_space).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

// TODO: report real available disk space for the data dir (needs a statvfs-style
// call or a small crate). Placeholder for now so replica selection has a value.
const FREE_SPACE_PLACEHOLDER: i64 = 1 << 40; // 1 TiB

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let pool = db::connect(&args.database).await?;
    let app = Arc::new(App {
        pool,
        store: Store::new(args.data_dir)?,
        replication_factor: args.replication_factor,
    });
    // Resolve the URL peers use to reach us: explicit if given, otherwise derived
    // from the peer bind address, otherwise empty (single host — we never get
    // contacted, and our own replicas are served locally).
    let peer_url = match (&args.peer_url, &args.listen_peer) {
        (Some(url), _) => url.clone(),
        (None, Some(listen_peer)) => format!("http://{listen_peer}"),
        (None, None) => String::new(),
    };
    // Register this node before serving traffic, then keep its heartbeat fresh in
    // the background.
    register_node(&app, &peer_url).await?;
    tokio::spawn(heartbeat(app.clone(), peer_url));

    let listen_client_addr = SocketAddr::from_str(&args.listen_client).unwrap();
    let client = serve(listen_client_addr, app.clone(), ServeKind::Client);
    // The peer server only runs when there are peers to serve. Both servers loop
    // forever, so awaiting them keeps the process alive until one errors out.
    match &args.listen_peer {
        Some(listen_peer) => {
            let listen_peer_addr = SocketAddr::from_str(listen_peer).unwrap();
            let peer = serve(listen_peer_addr, app.clone(), ServeKind::Peer);
            tokio::try_join!(client, peer)?;
        }
        None => client.await?,
    }
    Ok(())
}

/// Upserts this node's row in `nodes`. Used both for the initial registration
/// and for each heartbeat, since both are the same "I'm alive, here's my state"
/// statement.
async fn register_node(app: &App, peer_url: &str) -> anyhow::Result<()> {
    let client = app.pool.get().await?;
    let node_id = app.store.get_node_id().to_string();
    client
        .execute(
            "INSERT INTO nodes (node_id, peer_url, last_seen, free_space)
             VALUES ($1, $2, NOW(), $3)
             ON CONFLICT (node_id)
             DO UPDATE SET peer_url = $2, last_seen = NOW(), free_space = $3",
            &[&node_id, &peer_url, &FREE_SPACE_PLACEHOLDER],
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

/// Fetches a part from a single replica's peer endpoint. `Ok(Some)` is the
/// bytes, `Ok(None)` means the replica answered 404 (it doesn't hold the part),
/// and `Err` is a transport-level failure. The caller can advance to the next
/// replica on either of the latter two while still telling them apart.
async fn fetch_from_replica(peer_url: &str, part_id: Uuid) -> anyhow::Result<Option<Bytes>> {
    let client = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("{peer_url}/parts/{part_id}"))
        .body(Empty::<Bytes>::new())?;
    let res = client.request(req).await?;
    match res.status() {
        StatusCode::OK => Ok(Some(res.into_body().collect().await?.to_bytes())),
        StatusCode::NOT_FOUND => Ok(None),
        status => anyhow::bail!("replica {peer_url} returned status {status}"),
    }
}

/// Durably writes a part's bytes to this node's local disk and records this node
/// as one of its locations. Shared by the peer PUT endpoint and the local-replica
/// fast path in `upload_part` (no HTTP hop when a chosen replica is ourselves).
async fn store_part_locally(app: &App, part_id: Uuid, data: Bytes) -> anyhow::Result<()> {
    app.store.write_part(part_id, data).await?;
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
enum AttachTarget {
    /// A single-PUT object: point (bucket, key) at exactly this one part,
    /// replacing whatever it referenced before.
    Object {
        bucket: String,
        key: String,
        size: i64,
        etag: String,
        content_type: String,
    },
}

/// Stores `data` as a new part replicated across the cluster, then commits and
/// attaches it to `attach` atomically. Returns the new part's id.
async fn upload_part(app: &Arc<App>, data: Bytes, attach: &AttachTarget) -> anyhow::Result<Uuid> {
    let mut client = app.pool.get().await?;
    let part_id = Uuid::new_v4();
    // 1. create the (pending) part entry in the database
    client
        .execute(
            "INSERT INTO parts (part_id, size, state, created_at) VALUES ($1, $2, 'pending', NOW())",
            &[&part_id, &(data.len() as i64)],
        )
        .await?;
    // 2. choose replicas
    let replicas = choose_replicas(&client, app.replication_factor).await?;
    let node_ids: Vec<String> = replicas.iter().map(|(id, _)| id.clone()).collect();
    // 3. send a copy of the part to each replica, concurrently. A replica that is
    // ourselves writes locally (no HTTP hop — and on a single host there's no peer
    // server to hop to); we spawn it alongside the remote uploads and join them
    // all uniformly, so local disk I/O overlaps the network round-trips.
    let self_id = app.store.get_node_id().to_string();
    let mut uploads = JoinSet::new();
    for (node_id, peer_url) in replicas {
        let data = data.clone();
        if node_id == self_id {
            let app = app.clone();
            uploads.spawn(async move { store_part_locally(&app, part_id, data).await });
        } else {
            uploads
                .spawn(async move { upload_to_replica(&peer_url, part_id, Full::new(data)).await });
        }
    }
    while let Some(res) = uploads.join_next().await {
        // res: Result<anyhow::Result<()>, JoinError> — the task itself panicking,
        // then the upload's own error. Either one fails the whole part.
        res??;
    }
    // 4. commit + attach: flip the part to 'committed' and link it to `attach`,
    // but only after re-confirming in a serializable transaction that every
    // replica still holds a location row. A concurrent GC dropping one of those
    // locations conflicts with our read, so SSI aborts one side with a
    // serialization failure, which we retry afresh.
    let mut committed = false;
    for _ in 0..MAX_COMMIT_ATTEMPTS {
        match try_commit_part(&mut client, part_id, &node_ids, attach).await {
            Ok(CommitResult::Committed) => {
                committed = true;
                break;
            }
            Ok(CommitResult::MissingLocations { present, required }) => anyhow::bail!(
                "part {part_id} not durable: only {present}/{required} replicas reported a location"
            ),
            // Serialization conflict (e.g. a concurrent GC delete) — retry.
            Err(e) if e.code() == Some(&SqlState::T_R_SERIALIZATION_FAILURE) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    if !committed {
        anyhow::bail!(
            "part {part_id}: commit aborted after {MAX_COMMIT_ATTEMPTS} serialization retries"
        );
    }
    Ok(part_id)
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
    tx.execute(
        "UPDATE parts SET state = 'committed' WHERE part_id = $1",
        &[&part_id],
    )
    .await?;
    match attach {
        AttachTarget::Object {
            bucket,
            key,
            size,
            etag,
            content_type,
        } => {
            // Upsert the object's metadata, then point it at this single part,
            // replacing any parts the key referenced before (which then become
            // unreferenced and GC-eligible).
            tx.execute(
                "INSERT INTO objects (bucket, key, size, etag, content_type, last_modified)
                 VALUES ($1, $2, $3, $4, $5, NOW())
                 ON CONFLICT (bucket, key)
                 DO UPDATE SET size = $3, etag = $4, content_type = $5, last_modified = NOW()",
                &[bucket, key, size, etag, content_type],
            )
            .await?;
            tx.execute(
                "DELETE FROM object_parts WHERE bucket = $1 AND key = $2",
                &[bucket, key],
            )
            .await?;
            tx.execute(
                "INSERT INTO object_parts (bucket, key, part_number, part_id) VALUES ($1, $2, 1, $3)",
                &[bucket, key, &part_id],
            )
            .await?;
        }
    }
    tx.commit().await?;
    Ok(CommitResult::Committed)
}
