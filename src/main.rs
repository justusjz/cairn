use std::{net::SocketAddr, sync::Arc};

use deadpool_postgres::Pool;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode, body::Bytes, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use percent_encoding::percent_decode_str;
use tokio::net::TcpListener;

mod db;

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

async fn handle(
    req: Request<hyper::body::Incoming>,
    app: Arc<App>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let path = req.uri().path().trim_start_matches('/');
    if path.is_empty() {
        return match req.method() {
            &hyper::Method::GET => list_buckets(&app).await,
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
            &hyper::Method::PUT => create_bucket(&app, &bucket).await,
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

fn xml_ok(body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

async fn list_buckets(app: &App) -> anyhow::Result<Response<Full<Bytes>>> {
    let client = app.pool.get().await?;
    let rows = client
        .query(
            "SELECT name, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')
             FROM buckets ORDER BY name",
            &[],
        )
        .await?;
    let mut body = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <ListAllMyBucketsResult><Owner><ID>cairn</ID>\
             <DisplayName>cairn</DisplayName></Owner><Buckets>",
    );
    for r in &rows {
        let name: String = r.get(0);
        let created: String = r.get(1);
        body.push_str(&format!(
            "<Bucket><Name>{}</Name><CreationDate>{}</CreationDate></Bucket>",
            xml_escape(&name),
            created
        ));
    }
    body.push_str("</Buckets></ListAllMyBucketsResult>");
    Ok(xml_ok(body))
}

async fn create_bucket(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let client = app.pool.get().await?;
    client
        .execute(
            "INSERT INTO buckets (name) VALUES ($1) ON CONFLICT DO NOTHING",
            &[&bucket],
        )
        .await?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("location", format!("/{bucket}"))
        .body(Full::new(Bytes::new()))
        .unwrap())
}

struct App {
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
