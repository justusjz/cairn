use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, body::Bytes};
use uuid::Uuid;

use crate::{
    App,
    body::{ResBody, box_response, channel_body, send_file},
};

pub async fn handle(
    req: Request<hyper::body::Incoming>,
    app: Arc<App>,
) -> anyhow::Result<Response<ResBody>> {
    let path = req.uri().path();
    if let Some(part_id) = path.strip_prefix("/parts/") {
        // Parse the id up front: `part_id` borrows `req` (via `path`), and
        // collecting the body below consumes `req`, so the borrow must end here.
        let part_id = match Uuid::parse_str(part_id) {
            Ok(id) => id,
            Err(_) => return Ok(box_response(empty(StatusCode::BAD_REQUEST))),
        };
        // Clone the method so the PUT arm can still consume `req`'s body.
        return match req.method().clone() {
            hyper::Method::GET => {
                // Dumb data plane: stream whatever bytes we hold from disk, or 404
                // so the reader can fall through to another replica.
                match app.store.open_part(part_id).await? {
                    Some(file) => {
                        let (tx, body) = channel_body();
                        tokio::spawn(async move {
                            if let Err(e) = send_file(file, &tx).await {
                                let _ = tx.send(Err(e)).await;
                            }
                        });
                        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .body(body)
                            .unwrap())
                    }
                    None => Ok(box_response(empty(StatusCode::NOT_FOUND))),
                }
            }
            hyper::Method::PUT => {
                // Buffer the whole body into memory, then write it durably and
                // announce this node as a location for the part.
                let data = req.into_body().collect().await?.to_bytes();
                crate::store_part_locally(&app, part_id, data).await?;
                Ok(box_response(empty(StatusCode::OK)))
            }
            _ => Ok(box_response(empty(StatusCode::METHOD_NOT_ALLOWED))),
        };
    }
    Ok(box_response(empty(StatusCode::NOT_FOUND)))
}

fn empty(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .unwrap()
}
