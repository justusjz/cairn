use std::sync::Arc;

use http_body_util::Full;
use hyper::{Request, Response, StatusCode, body::Bytes, body::Frame};
use uuid::Uuid;

use crate::{
    App, blob_file,
    checksum::BlockLayout,
    body::{ResBody, box_response, channel_body, send_file},
    gc, packer,
};

/// The response for a failed peer request: a bare 500 (peers only check the
/// status; the error itself is logged by the caller).
/// Response header of a blob PUT: the hex CRC64/NVME of the file the replica
/// stored (the data plus its checksum table and blob ID).
pub const CRC64_HEADER: &str = "x-cairn-crc64nvme";

pub fn error_response(_e: &anyhow::Error) -> Response<ResBody> {
    box_response(empty(StatusCode::INTERNAL_SERVER_ERROR))
}

pub async fn handle(
    req: Request<hyper::body::Incoming>,
    app: Arc<App>,
) -> anyhow::Result<Response<ResBody>> {
    let path = req.uri().path();
    if path == "/maintain" {
        // For tests: run a maintenance pass now (as the background one would,
        // but sweeping everything), and report what it did once it's done (a
        // failed packing job is only logged).
        let mut report = format!("gc: {}\n", gc::pass(&app, gc::Scope::everything()).await);
        for job in packer::pass(&app).await? {
            report.push_str(&format!("packer: {job}\n"));
        }
        return Ok(box_response(
            Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Full::new(Bytes::from(report)))
                .unwrap(),
        ));
    }
    if path == "/stats" {
        // This node's own metrics, for the admin UI of whichever node it's
        // open on.
        let body = crate::admin::node_stats(&app).to_string();
        return Ok(box_response(
            Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(body)))
                .unwrap(),
        ));
    }
    if let Some(blob_id) = path.strip_prefix("/blobs/") {
        // Parse the id up front: `blob_id` borrows `req` (via `path`), and
        // collecting the body below consumes `req`, so the borrow must end here.
        let blob_id = match Uuid::parse_str(blob_id) {
            Ok(id) => id,
            Err(_) => return Ok(box_response(empty(StatusCode::BAD_REQUEST))),
        };
        // Clone the method so the PUT arm can still consume `req`'s body.
        return match req.method().clone() {
            hyper::Method::GET => {
                // Dumb data plane: stream whatever bytes we hold from disk — the
                // whole blob, or just `?offset=&length=` of it — or 404 so the
                // reader can fall through to another replica. For a block-aligned
                // range of a checksummed blob, the reader sends the blob's size and
                // block size from the catalog (`?blob_size=&block_size=`); we check
                // our file against them and send the range's block checksums from
                // the file first. The reader verifies the bytes against them, so we
                // don't have to.
                let query = req.uri().query().unwrap_or("");
                let range = parse_range(query);
                let layout = parse_layout(query);
                match app.store.open_blob(blob_id).await? {
                    Some(mut file) => {
                        let crcs = match (layout, range) {
                            (Some(layout), Some((offset, length))) => {
                                match blob_file::open_range(
                                    &mut file, blob_id, layout, offset, length,
                                )
                                .await
                                {
                                    Ok(crcs) => Some(crcs),
                                    Err(e) => {
                                        if e.kind() == std::io::ErrorKind::InvalidData {
                                            eprintln!("CORRUPTION: blob {blob_id}: {e}");
                                        }
                                        return Err(e.into());
                                    }
                                }
                            }
                            (Some(_), None) => {
                                return Ok(box_response(empty(StatusCode::BAD_REQUEST)));
                            }
                            (None, _) => None,
                        };
                        let (tx, body) = channel_body();
                        tokio::spawn(async move {
                            if let Some(crcs) = crcs
                                && tx.send(Ok(Frame::data(Bytes::from(crcs)))).await.is_err()
                            {
                                return;
                            }
                            if let Err(e) = send_file(file, range, &tx).await {
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
                // Stream the body straight to disk (and announce the location),
                // without buffering the whole blob in memory. Answer with the
                // CRC of the file we stored, so the writer can check that we got
                // exactly the bytes it sent.
                let crc = crate::write_blob_streaming(&app, blob_id, req.into_body()).await?;
                Ok(box_response(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(CRC64_HEADER, format!("{crc:016x}"))
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                ))
            }
            hyper::Method::DELETE => {
                // Best-effort happy-path reap: the coordinator dropped this blob's
                // catalog rows and is asking us to delete the file now (idempotent;
                // a missing file is fine). The GC is the backstop if this is missed.
                app.store.remove_blob(blob_id).await?;
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

/// Reads a raw (undecoded) query parameter — peer params are simple
/// flags/integers, so no percent-decoding is needed.
fn param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|p| {
        let (k, v) = p.split_once('=')?;
        (k == name).then(|| v.to_owned())
    })
}

/// Parses a checksummed blob's `?blob_size=&block_size=`; both must be present,
/// else the blob is read without checksums.
fn parse_layout(query: &str) -> Option<BlockLayout> {
    let blob_size = param(query, "blob_size")?.parse().ok()?;
    let block_size = param(query, "block_size")?.parse().ok()?;
    Some(BlockLayout {
        block_size,
        blob_size,
    })
}

/// Parses an `?offset=&length=` blob range; both must be present, else the whole
/// blob is served.
fn parse_range(query: &str) -> Option<(u64, u64)> {
    let offset = param(query, "offset")?.parse().ok()?;
    let length = param(query, "length")?.parse().ok()?;
    Some((offset, length))
}
