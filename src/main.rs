use std::{net::SocketAddr, str::FromStr, sync::Arc};

use clap::Parser;
use deadpool_postgres::{Object, Pool};
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, StatusCode, body::Body, body::Incoming, server::conn::http1,
    service::service_fn,
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
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    database: String,
    #[arg(long)]
    listen_client: String,
    #[arg(long)]
    listen_peer: String,
    #[arg(long)]
    data_dir: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let pool = db::connect(&args.database).await?;
    let app = Arc::new(App {
        pool,
        store: Store::new(args.data_dir),
    });
    let listen_client_addr = SocketAddr::from_str(&args.listen_client).unwrap();
    let listen_peer_addr = SocketAddr::from_str(&args.listen_peer).unwrap();
    tokio::spawn(serve(listen_client_addr, app.clone(), ServeKind::Client));
    tokio::spawn(serve(listen_peer_addr, app.clone(), ServeKind::Peer));
    Ok(())
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
            "SELECT node_id, peer_url FROM nodes ORDER BY free_space DESC",
            &[],
        )
        .await?;
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

async fn upload_part(app: &App, body: Incoming) -> anyhow::Result<()> {
    let mut client = app.pool.get().await?;
    let part_id = Uuid::new_v4();
    // Buffer the whole upload once on the leader; we fan the same bytes out to
    // each replica below (streaming dropped for now).
    let data = body.collect().await?.to_bytes();
    // 1. create file entry in the database
    client
        .execute(
            "INSERT INTO parts (part_id, size, state, created_at) VALUES ($1, $2, 'pending', NOW())",
            &[&part_id, &(data.len() as i64)],
        )
        .await?;
    // 2. choose replicas (TODO: dynamic RF?)
    let replicas = choose_replicas(&client, 2).await?;
    let node_ids: Vec<String> = replicas.iter().map(|(id, _)| id.clone()).collect();
    // 3. send a copy of the part to each replica, concurrently
    let mut uploads = JoinSet::new();
    for (_node_id, peer_url) in replicas {
        let data = data.clone();
        uploads.spawn(async move { upload_to_replica(&peer_url, part_id, Full::new(data)).await });
    }
    while let Some(res) = uploads.join_next().await {
        // res: Result<anyhow::Result<()>, JoinError> — the task itself panicking,
        // then the upload's own error. Either one fails the whole part.
        res??;
    }
    // 4. commit: flip the part to 'committed', but only after re-confirming in a
    // serializable transaction that every replica still holds a location row. A
    // concurrent GC dropping one of those locations conflicts with our read, so
    // SSI aborts one side with a serialization failure, which we retry afresh.
    let mut committed = false;
    for _ in 0..MAX_COMMIT_ATTEMPTS {
        match try_commit_part(&mut client, part_id, &node_ids).await {
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
    // Open question, still unsolved: the GC/upload race. If a replica writes the
    // file to disk, the GC sees no committed location and deletes the bytes, and
    // only *then* does the replica insert its location row — we'd commit a part
    // whose bytes are already gone.
    Ok(())
}

const MAX_COMMIT_ATTEMPTS: usize = 10;

enum CommitResult {
    Committed,
    MissingLocations { present: i64, required: usize },
}

/// Runs the commit transaction once under SERIALIZABLE isolation: confirms that
/// all `node_ids` hold a location for `part_id`, and if so marks the part
/// committed. The raw postgres error is returned unwrapped so the caller can
/// distinguish a serialization failure (retry) from a real error (give up).
async fn try_commit_part(
    client: &mut Object,
    part_id: Uuid,
    node_ids: &[String],
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
    tx.commit().await?;
    Ok(CommitResult::Committed)
}
