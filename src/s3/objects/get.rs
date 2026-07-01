use std::io;
use std::sync::Arc;

use http_body_util::Empty;
use hyper::{Method, Request, Response, StatusCode, body::Bytes, header};
use deadpool_postgres::GenericClient;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use uuid::Uuid;

use crate::{
    App,
    body::{FrameSender, ResBody, box_response, channel_body, send_file, send_incoming},
    s3::conditional::{Precondition, Preconditions, not_modified},
    s3::util::format_s3_error,
};

pub async fn get_object(
    app: &Arc<App>,
    bucket: &str,
    key: &str,
    range_header: Option<&str>,
    preconditions: &Preconditions,
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
                    to_char(last_modified AT TIME ZONE 'UTC', 'Dy, DD Mon YYYY HH24:MI:SS \"GMT\"'),
                    floor(extract(epoch FROM last_modified))::bigint
             FROM objects WHERE bucket = $1 AND key = $2",
            &[&bucket, &key],
        )
        .await?;
    let (etag, content_type, size, last_modified, lm_epoch): (String, String, i64, String, i64) =
        match row {
            Some(row) => (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4)),
            None => {
                return Ok(box_response(format_s3_error(StatusCode::NOT_FOUND, "NoSuchKey", "")));
            }
        };
    // Honour conditional-request headers before doing any streaming work.
    match preconditions.evaluate(&etag, lm_epoch, true) {
        Precondition::Proceed => {}
        Precondition::NotModified => return Ok(box_response(not_modified(&etag, &last_modified))),
        Precondition::Failed => {
            return Ok(box_response(format_s3_error(
                StatusCode::PRECONDITION_FAILED,
                "PreconditionFailed",
                "at least one of the preconditions you specified did not hold",
            )));
        }
    }
    let size = size as u64;
    // Resolve the requested object range as a half-open [range_start, range_end).
    // No/unsupported Range → the whole object (200); a satisfiable range → 206; a
    // syntactically valid but unsatisfiable one → 416.
    let (range_start, range_end, partial) = match parse_range(range_header, size) {
        Ok(Some((start, end))) => (start, end, true),
        Ok(None) => (0, size, false),
        Err(()) => {
            return Ok(box_response(format_s3_error(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "InvalidRange",
                "the requested range is not satisfiable",
            )));
        }
    };
    // Resolve the ordered parts and each part's candidate locations (freshest
    // first) from this same snapshot.
    let parts = resolve_object_parts(&tx, bucket, key).await?;
    tx.commit().await?;

    // Select the parts overlapping the requested range and stream them (each over
    // its computed sub-range) through a channel-backed body: a background task
    // pulls each from a replica (locally if that's us) and forwards its chunks. We
    // set Content-Length, so a truncated stream (a part we can't serve) is detected
    // by the client rather than read as a short-but-complete object.
    let slices = select_parts_in_range(parts, range_start, range_end);
    let (sender, body) = channel_body();
    spawn_range_stream(app.clone(), slices, sender);

    let builder = Response::builder()
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::ETAG, format!("\"{etag}\""))
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, range_end - range_start)
        .header(header::LAST_MODIFIED, last_modified);
    let builder = if partial {
        builder.status(StatusCode::PARTIAL_CONTENT).header(
            header::CONTENT_RANGE,
            format!("bytes {range_start}-{}/{size}", range_end - 1),
        )
    } else {
        builder.status(StatusCode::OK)
    };
    Ok(builder.body(body).unwrap())
}

/// One committed part of an object for streaming: its id, its size in bytes, and
/// its candidate replica locations as (node_id, peer_url), freshest node first.
pub(crate) type PartLocation = (Uuid, u64, Vec<(String, String)>);

/// Resolves an object's committed parts in order, each with its size and its
/// candidate replica locations (freshest node first). Runs within the caller's
/// transaction, so the parts and their locations come from one consistent
/// snapshot. Shared by GetObject (range streaming) and CopyObject (whole-object
/// copy).
pub(crate) async fn resolve_object_parts<C: GenericClient>(
    client: &C,
    bucket: &str,
    key: &str,
) -> Result<Vec<PartLocation>, tokio_postgres::Error> {
    let rows = client
        .query(
            "SELECT p.part_number, p.part_id, p.size, pl.node_id, n.peer_url
             FROM parts p
             JOIN part_locations pl ON pl.part_id = p.part_id
             JOIN nodes n ON n.node_id = pl.node_id
             WHERE p.object_bucket = $1 AND p.object_key = $2
             ORDER BY p.part_number, n.last_seen DESC",
            &[&bucket, &key],
        )
        .await?;
    // Fold the flat join rows into one entry per part (rows are ordered by
    // part_number, then location), collecting each part's candidate locations.
    let mut parts: Vec<PartLocation> = Vec::new();
    let mut current: Option<i32> = None;
    for row in &rows {
        let part_number: i32 = row.get(0);
        let part_id: Uuid = row.get(1);
        let part_size: i64 = row.get(2);
        let node_id: String = row.get(3);
        let peer_url: String = row.get(4);
        if current != Some(part_number) {
            parts.push((part_id, part_size as u64, Vec::new()));
            current = Some(part_number);
        }
        parts.last_mut().unwrap().2.push((node_id, peer_url));
    }
    Ok(parts)
}

/// A slice of one part selected for streaming: its id, its candidate replica
/// locations, and the (offset, length) to read from *within* the part.
pub(crate) type PartSlice = (Uuid, Vec<(String, String)>, u64, u64);

/// Selects the parts overlapping the half-open byte range [range_start, range_end)
/// of the assembled object, each with the (offset, length) to read from within it.
/// Parts entirely outside the range are dropped; `parts` must be in object order.
/// Shared by GetObject (ranged reads) and the copy paths.
pub(crate) fn select_parts_in_range(
    parts: Vec<PartLocation>,
    range_start: u64,
    range_end: u64,
) -> Vec<PartSlice> {
    // Track the object offset where each part begins, and intersect its span with
    // the requested range.
    let mut slices: Vec<PartSlice> = Vec::new();
    let mut cursor: u64 = 0;
    for (part_id, part_size, locations) in parts {
        let part_start = cursor;
        let part_end = cursor + part_size;
        cursor = part_end;
        let overlap_start = range_start.max(part_start);
        let overlap_end = range_end.min(part_end);
        if overlap_start >= overlap_end {
            continue; // part lies entirely outside the requested range
        }
        slices.push((
            part_id,
            locations,
            overlap_start - part_start,  // offset within the part
            overlap_end - overlap_start, // bytes to read from it
        ));
    }
    slices
}

/// Spawns a background task that streams each selected part-slice to `sender`,
/// pulling each from a replica (locally if that's us) via [`stream_part`]. If any
/// slice can't be served the stream is faulted. Shared by GetObject and the copy
/// paths.
pub(crate) fn spawn_range_stream(app: Arc<App>, slices: Vec<PartSlice>, sender: FrameSender) {
    let self_id = app.store.get_node_id().to_string();
    tokio::spawn(async move {
        for (part_id, locations, offset, length) in slices {
            let range = Some((offset, length));
            if let Err(e) = stream_part(&app, part_id, range, &locations, &self_id, &sender).await {
                let _ = sender.send(Err(e)).await;
                return;
            }
        }
    });
}

/// Parses a single-range `Range: bytes=…` header against the object `size` into a
/// half-open [start, end). `Ok(None)` = no usable range (serve the whole object,
/// 200); `Err(())` = a syntactically valid but unsatisfiable range (416).
/// Malformed and multi-range headers are ignored (treated as `None`).
pub(crate) fn parse_range(header: Option<&str>, size: u64) -> Result<Option<(u64, u64)>, ()> {
    let Some(spec) = header.and_then(|h| h.strip_prefix("bytes=")) else {
        return Ok(None);
    };
    let spec = spec.trim();
    if spec.contains(',') {
        return Ok(None); // multi-range unsupported — serve the whole object
    }
    let Some((start_s, end_s)) = spec.split_once('-') else {
        return Ok(None); // malformed
    };
    let (start, end) = if start_s.trim().is_empty() {
        // bytes=-N: the last N bytes.
        let Ok(suffix) = end_s.trim().parse::<u64>() else {
            return Ok(None);
        };
        if suffix == 0 {
            return Err(());
        }
        (size.saturating_sub(suffix), size)
    } else {
        let Ok(start) = start_s.trim().parse::<u64>() else {
            return Ok(None);
        };
        let end = if end_s.trim().is_empty() {
            size // bytes=start-
        } else {
            let Ok(last) = end_s.trim().parse::<u64>() else {
                return Ok(None);
            };
            if last < start {
                return Err(());
            }
            last.saturating_add(1) // inclusive end → half-open
        };
        (start, end)
    };
    let end = end.min(size);
    if start >= end {
        return Err(()); // start at/after the object end, or an empty range
    }
    Ok(Some((start, end)))
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
    range_header: Option<&str>,
    preconditions: &Preconditions,
) -> anyhow::Result<Response<http_body_util::Full<Bytes>>> {
    let client = app.pool.get().await?;
    let row = client
        .query_opt(
            "SELECT size, etag, content_type,
                    to_char(last_modified AT TIME ZONE 'UTC', 'Dy, DD Mon YYYY HH24:MI:SS \"GMT\"'),
                    floor(extract(epoch FROM last_modified))::bigint
             FROM objects WHERE bucket = $1 AND key = $2",
            &[&bucket, &key],
        )
        .await?;
    let (size, etag, content_type, last_modified, lm_epoch): (i64, String, String, String, i64) =
        match row {
            Some(row) => (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4)),
            None => return Ok(format_s3_error(StatusCode::NOT_FOUND, "NoSuchKey", "")),
        };
    // Honour conditional-request headers, exactly as GET does.
    match preconditions.evaluate(&etag, lm_epoch, true) {
        Precondition::Proceed => {}
        Precondition::NotModified => return Ok(not_modified(&etag, &last_modified)),
        Precondition::Failed => {
            return Ok(format_s3_error(
                StatusCode::PRECONDITION_FAILED,
                "PreconditionFailed",
                "at least one of the preconditions you specified did not hold",
            ));
        }
    }
    // HEAD returns exactly the headers a GET would, with no body — so mirror the
    // GET range handling (206 + Content-Range for a range, 416 if unsatisfiable).
    let size = size as u64;
    let (range_start, range_end, partial) = match parse_range(range_header, size) {
        Ok(Some((start, end))) => (start, end, true),
        Ok(None) => (0, size, false),
        Err(()) => {
            return Ok(format_s3_error(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "InvalidRange",
                "the requested range is not satisfiable",
            ));
        }
    };
    let builder = Response::builder()
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::ETAG, format!("\"{etag}\""))
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, range_end - range_start)
        .header(header::LAST_MODIFIED, last_modified);
    let builder = if partial {
        builder.status(StatusCode::PARTIAL_CONTENT).header(
            header::CONTENT_RANGE,
            format!("bytes {range_start}-{}/{size}", range_end - 1),
        )
    } else {
        builder.status(StatusCode::OK)
    };
    Ok(builder.body(http_body_util::Full::new(Bytes::new())).unwrap())
}
