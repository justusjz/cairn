use std::net::SocketAddr;

use http_body_util::Full;
use hyper::{Request, Response, body::Bytes, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

async fn handle(_req: Request<hyper::body::Incoming>) -> anyhow::Result<Response<Full<Bytes>>> {
    Ok(Response::new(Full::new(Bytes::from("Hello, world!"))))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 19000));
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on 127.0.0.1:19000...");
    loop {
        let (stream, _peer_addr) = listener.accept().await?;
        let io = TokioIo::new(stream);
        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(handle))
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}
