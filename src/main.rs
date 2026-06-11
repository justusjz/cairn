use std::net::SocketAddr;

use http_body_util::Full;
use hyper::{Request, Response, StatusCode, body::Bytes, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use percent_encoding::percent_decode_str;
use tokio::net::TcpListener;

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn format_s3_error(status: StatusCode, code: &str, message: &str) -> Response<Full<Bytes>> {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <Error><Code>{}</Code><Message>{}</Message></Error>",
        xml_escape(code),
        xml_escape(message)
    );
    Response::builder()
        .status(status)
        .header("content-type", "application/xml")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn decode_path_param(param: &str) -> String {
    percent_decode_str(param).decode_utf8_lossy().into_owned()
}

async fn handle(req: Request<hyper::body::Incoming>) -> anyhow::Result<Response<Full<Bytes>>> {
    let path = req.uri().path().trim_start_matches('/');
    if path.is_empty() {
        return match req.method() {
            &hyper::Method::GET => list_buckets().await,
            _ => Ok(format_s3_error(
                StatusCode::METHOD_NOT_ALLOWED,
                "MethodNotAllowed",
                "",
            )),
        };
    }
    let (bucket, key) = match path.split_once('/') {
        Some((bucket, key)) => (decode_path_param(bucket), decode_path_param(key)),
        None => (decode_path_param(path), "".to_owned()),
    };
    if key.is_empty() {
        // bucket operations
        match req.method() {
            &hyper::Method::PUT => create_bucket().await,
            _ => Ok(format_s3_error(
                StatusCode::METHOD_NOT_ALLOWED,
                "MethodNotAllowed",
                "",
            )),
        }
    } else {
        // object operations
        Ok(Response::new(Full::new(Bytes::from("Object operations"))))
    }
}

async fn list_buckets() -> anyhow::Result<Response<Full<Bytes>>> {
    Ok(Response::new(Full::new(Bytes::from("listing buckets"))))
}

async fn create_bucket() -> anyhow::Result<Response<Full<Bytes>>> {
    Ok(Response::new(Full::new(Bytes::from("creating bucket"))))
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
