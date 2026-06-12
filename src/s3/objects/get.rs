use std::io;
use std::sync::Arc;

use http_body_util::Empty;
use hyper::{Method, Request, Response, StatusCode, body::Bytes, header};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use uuid::Uuid;

use crate::{
    App,
    body::{FrameSender, ResBody, box_response, channel_body, send_file, send_incoming},
    s3::util::format_s3_error,
};

pub async fn get_object(
    app: &Arc<App>,
    bucket: &str,
    key: &str,
) -> anyhow::Result<Response<ResBody>> {
    let mut client = app.pool.get().await?;
    // Read the metadata, the ordered parts, and each part's locations in one
    // RepeatableRead snapshot, so a concurrent overwrite can't tear the view.
    let tx = client
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
        .start()
        .await?;
    let row = tx
        .query_opt(
            "SELECT etag, content_type, size,
                    to_char(last_modified AT TIME ZONE 'UTC', 'Dy, DD Mon YYYY HH24:MI:SS \"GMT\"')
             FROM objects WHERE bucket = $1 AND key = $2",
            &[&bucket, &key],
        )
        .await?;
    let (etag, content_type, size, last_modified): (String, String, i64, String) = match row {
        Some(row) => (row.get(0), row.get(1), row.get(2), row.get(3)),
        None => return Ok(box_response(format_s3_error(StatusCode::NOT_FOUND, "NoSuchKey", ""))),
    };
    // Freshest location first per part, so we try the most-likely-live node first.
    let rows = tx
        .query(
            "SELECT p.part_number, p.part_id, pl.node_id, n.peer_url
             FROM parts p
             JOIN part_locations pl ON pl.part_id = p.part_id
             JOIN nodes n ON n.node_id = pl.node_id
             WHERE p.object_bucket = $1 AND p.object_key = $2
             ORDER BY p.part_number, n.last_seen DESC",
            &[&bucket, &key],
        )
        .await?;
    tx.commit().await?;

    // Group the flat rows into ordered parts, each with its candidate locations.
    let mut parts: Vec<(Uuid, Vec<(String, String)>)> = Vec::new();
    let mut current: Option<i32> = None;
    for row in &rows {
        let part_number: i32 = row.get(0);
        let part_id: Uuid = row.get(1);
        let node_id: String = row.get(2);
        let peer_url: String = row.get(3);
        if current != Some(part_number) {
            parts.push((part_id, Vec::new()));
            current = Some(part_number);
        }
        parts.last_mut().unwrap().1.push((node_id, peer_url));
    }

    // Stream the parts in order through a channel-backed body: a background task
    // pulls each from a replica (locally if that's us) and forwards its chunks.
    // We set Content-Length, so a truncated stream (a part we can't serve) is
    // detected by the client rather than read as a short-but-complete object.
    let (sender, body) = channel_body();
    let app = app.clone();
    let self_id = app.store.get_node_id().to_string();
    tokio::spawn(async move {
        for (part_id, locations) in parts {
            if let Err(e) = stream_part(&app, part_id, None, &locations, &self_id, &sender).await {
                let _ = sender.send(Err(e)).await;
                return;
            }
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::ETAG, format!("\"{etag}\""))
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, size)
        .header(header::LAST_MODIFIED, last_modified)
        .body(body)
        .unwrap())
}

/// Streams one part to `tx` — the whole part, or just `range` (offset, length) of
/// it — trying its locations in order (freshest first). Failover only happens
/// before a source produces its first byte; once we start forwarding, a mid-stream
/// failure faults the whole response (we can't unsend).
async fn stream_part(
    app: &App,
    part_id: Uuid,
    range: Option<(u64, u64)>,
    locations: &[(String, String)],
    self_id: &str,
    tx: &FrameSender,
) -> io::Result<()> {
    for (node_id, peer_url) in locations {
        if node_id == self_id {
            // We hold it: stream from local disk (no peer server needed).
            match app.store.open_part(part_id).await {
                Ok(Some(file)) => return send_file(file, range, tx).await,
                Ok(None) => continue,
                Err(e) => {
                    eprintln!("local open of part {part_id} failed: {e}");
                    continue;
                }
            }
        } else {
            // `client` stays in scope across send_incoming, keeping the connection
            // alive while we stream the response body.
            let client = Client::builder(TokioExecutor::new()).build_http();
            let uri = match range {
                Some((offset, length)) => {
                    format!("{peer_url}/parts/{part_id}?offset={offset}&length={length}")
                }
                None => format!("{peer_url}/parts/{part_id}"),
            };
            let req = match Request::builder()
                .method(Method::GET)
                .uri(uri)
                .body(Empty::<Bytes>::new())
            {
                Ok(req) => req,
                Err(_) => continue,
            };
            match client.request(req).await {
                Ok(res) if res.status() == StatusCode::OK => {
                    return send_incoming(res.into_body(), tx).await;
                }
                Ok(res) if res.status() == StatusCode::NOT_FOUND => continue,
                Ok(res) => {
                    eprintln!("replica {peer_url} returned {} for part {part_id}", res.status());
                    continue;
                }
                Err(e) => {
                    eprintln!("fetch of part {part_id} from {peer_url} failed: {e}");
                    continue;
                }
            }
        }
    }
    Err(io::Error::other(format!(
        "no replica could serve part {part_id}"
    )))
}

/// Metadata-only response for the key: answered straight from `objects`, never
/// touching a replica. s3cmd issues this before a download.
pub async fn head_object(
    app: &App,
    bucket: &str,
    key: &str,
) -> anyhow::Result<Response<http_body_util::Full<Bytes>>> {
    let client = app.pool.get().await?;
    let row = client
        .query_opt(
            "SELECT size, etag, content_type,
                    to_char(last_modified AT TIME ZONE 'UTC', 'Dy, DD Mon YYYY HH24:MI:SS \"GMT\"')
             FROM objects WHERE bucket = $1 AND key = $2",
            &[&bucket, &key],
        )
        .await?;
    match row {
        Some(row) => {
            let size: i64 = row.get(0);
            let etag: String = row.get(1);
            let content_type: String = row.get(2);
            let last_modified: String = row.get(3);
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_LENGTH, size)
                .header(header::ETAG, format!("\"{etag}\""))
                .header(header::CONTENT_TYPE, content_type)
                .header(header::LAST_MODIFIED, last_modified)
                .body(http_body_util::Full::new(Bytes::new()))
                .unwrap())
        }
        None => Ok(format_s3_error(StatusCode::NOT_FOUND, "NoSuchKey", "")),
    }
}
