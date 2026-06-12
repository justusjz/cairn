use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes, header};
use uuid::Uuid;

use crate::{App, s3::util::format_s3_error};

pub async fn get_object(
    app: &App,
    bucket: &str,
    key: &str,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let mut client = app.pool.get().await?;
    // Resolve the part this key points at, plus the metadata we echo back.
    // last_modified is formatted as an RFC 1123 HTTP-date (what S3 clients expect).
    let tx = client
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
        .start()
        .await?;
    let row = tx
        .query_opt(
            "SELECT etag, content_type,
                    to_char(last_modified AT TIME ZONE 'UTC', 'Dy, DD Mon YYYY HH24:MI:SS \"GMT\"')
             FROM objects WHERE bucket = $1 AND key = $2",
            &[&bucket, &key],
        )
        .await?;
    let (etag, content_type, last_modified): (String, String, String) = match row {
        Some(row) => (row.get(0), row.get(1), row.get(2)),
        None => return Ok(format_s3_error(StatusCode::NOT_FOUND, "NoSuchKey", "")),
    };
    let parts = tx
        .query(
            "SELECT part_number, part_id FROM object_parts WHERE bucket = $1 AND key = $2",
            &[&bucket, &key],
        )
        .await?;
    if parts.len() != 1 {
        panic!("object does not have exactly 1 part");
    }
    let part_id: Uuid = parts[0].get(1);
    // Every replica that holds the part, with its peer URL — freshest heartbeat
    // first, so we try the node most likely to be alive before the others.
    let locations = tx
        .query(
            "SELECT part_locations.node_id, nodes.peer_url
            FROM part_locations
            JOIN nodes
            ON part_locations.node_id = nodes.node_id
            WHERE part_locations.part_id = $1
            ORDER BY nodes.last_seen DESC",
            &[&part_id],
        )
        .await?;
    tx.commit().await?;
    drop(client);
    // Try each replica in turn, returning the first that has the bytes. This is
    // simple but serial: a slow or dead replica costs us its full latency before
    // we move on. Future improvement: hedged requests — fire a backup to the next
    // replica after a short delay and take whichever responds first — to bound
    // tail latency without always doubling read load.
    let self_id = app.store.get_node_id().to_string();
    for row in &locations {
        let node_id: &str = row.get(0);
        let peer_url: &str = row.get(1);
        // If we hold it ourselves, read from local disk instead of an HTTP hop —
        // and on a single host there's no peer server to hop to anyway.
        let fetched = if node_id == self_id {
            app.store
                .read_part_opt(part_id)
                .await
                .map(|opt| opt.map(Bytes::from))
        } else {
            crate::fetch_from_replica(peer_url, part_id).await
        };
        match fetched {
            Ok(Some(data)) => {
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(header::ETAG, format!("\"{etag}\""))
                    .header(header::CONTENT_TYPE, content_type.as_str())
                    .header(header::LAST_MODIFIED, last_modified.as_str())
                    .body(Full::new(data))
                    .unwrap());
            }
            // 404 means the DB lists this replica but it doesn't actually hold the
            // bytes (GC / inconsistency) — just try the next one.
            Ok(None) => continue,
            // Couldn't reach this replica; log and fall through to the next.
            Err(e) => {
                eprintln!("fetch of part {part_id} from {peer_url} failed: {e}");
                continue;
            }
        }
    }
    // The object points at a part, but no replica could serve it right now.
    Ok(format_s3_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "ServiceUnavailable",
        "no replica could serve the requested object",
    ))
}

/// Metadata-only response for the key: answered straight from `objects`, never
/// touching a replica. s3cmd issues this before a download.
pub async fn head_object(
    app: &App,
    bucket: &str,
    key: &str,
) -> anyhow::Result<Response<Full<Bytes>>> {
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
                .body(Full::new(Bytes::new()))
                .unwrap())
        }
        None => Ok(format_s3_error(StatusCode::NOT_FOUND, "NoSuchKey", "")),
    }
}
