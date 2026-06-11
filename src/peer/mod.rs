use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, body::Bytes};
use uuid::Uuid;

use crate::App;

pub async fn handle(
    req: Request<hyper::body::Incoming>,
    app: Arc<App>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let path = req.uri().path();
    if let Some(part_id) = path.strip_prefix("/parts/") {
        // Parse the id up front: `part_id` borrows `req` (via `path`), and
        // collecting the body below consumes `req`, so the borrow must end here.
        let part_id = match Uuid::parse_str(part_id) {
            Ok(id) => id,
            Err(_) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::new()))
                    .unwrap());
            }
        };
        // Clone the method so the PUT arm can still consume `req`'s body.
        return match req.method().clone() {
            hyper::Method::GET => {
                // Dumb data plane: hand back whatever bytes we hold, or 404 so the
                // reader can fall through to another replica.
                match app.store.read_part(part_id).await {
                    Ok(data) => Ok(Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from(data)))
                        .unwrap()),
                    Err(e) => match e.downcast_ref::<std::io::Error>() {
                        Some(io) if io.kind() == std::io::ErrorKind::NotFound => Ok(
                            Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        ),
                        _ => Err(e),
                    },
                }
            }
            hyper::Method::PUT => {
                // Buffer the whole body into memory, then write it durably.
                let data = req.into_body().collect().await?.to_bytes();
                app.store.write_part(part_id, data).await?;
                // Only now that the bytes are fsync'd do we announce this node as a
                // location for the part. The leader's serializable commit counts
                // exactly these rows, so this insert is what makes our copy "count"
                // towards durability. ON CONFLICT keeps a retried upload idempotent.
                let node_id = app.store.get_node_id().to_string();
                let client = app.pool.get().await?;
                client
                    .execute(
                        "INSERT INTO part_locations (part_id, node_id) VALUES ($1, $2) \
                         ON CONFLICT DO NOTHING",
                        &[&part_id, &node_id],
                    )
                    .await?;
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(Full::new(Bytes::new()))
                    .unwrap())
            }
            _ => Ok(Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Full::new(Bytes::new()))
                .unwrap()),
        };
    }
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::new()))
        .unwrap())
}
