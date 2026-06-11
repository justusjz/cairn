use std::{net::SocketAddr, sync::Arc};

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let pool = db::connect("postgres://postgres:password@127.0.0.1:5432/cairn").await?;
    let app = Arc::new(App { pool });
    let addr = SocketAddr::from(([127, 0, 0, 1], 19000));
    let listener = TcpListener::bind(addr).await?;
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
