use std::{net::SocketAddr, str::FromStr, sync::Arc};

use clap::Parser;
use deadpool_postgres::Pool;
use hyper::{server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::s3::handle;

mod db;
mod s3;

pub struct App {
    pool: Pool,
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    database: String,
    #[arg(short, long)]
    listen_client: String,
    /*#[arg(short, long)]
    listen_peer: String,*/
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let pool = db::connect(&args.database).await?;
    let app = Arc::new(App { pool });
    let listen_client_addr = SocketAddr::from_str(&args.listen_client).unwrap();
    // let listen_peer_addr = SocketAddr::from_str(&args.listen_peer).unwrap();
    let listener = TcpListener::bind(listen_client_addr).await?;
    println!("Listening on 127.0.0.1:19000...");
    loop {
        let (stream, _peer_addr) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let app = app.clone();
        tokio::task::spawn(async move {
            let service = service_fn(move |req| {
                let app = app.clone();
                handle(req, app)
            });
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}
