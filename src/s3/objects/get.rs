use std::sync::Arc;

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes, header};
use deadpool_postgres::GenericClient;
use uuid::Uuid;

use crate::{
    App,
    blobs::{BlobSlice, Location, stream_blob_range},
    checksum::BlockLayout,
    body::{FrameSender, ResBody, box_response, channel_body},
    s3::conditional::{Precondition, Preconditions, not_modified},
    s3::util::{format_s3_error, with_delete_marker, with_version_id},
    s3::versions::Versioning,
};

/// The object version a read addresses, as far as its response needs it.
pub(crate) struct ObjectVersion {
    /// Row id, to resolve its parts by.
    pub id: i64,
    pub etag: String,
    pub content_type: String,
    pub size: i64,
    /// Last-Modified as an HTTP date (for headers) and in ISO 8601 (for XML
    /// bodies), and as a Unix timestamp for conditionals.
    pub last_modified: String,
    pub last_modified_iso: String,
    pub lm_epoch: i64,
    /// The `x-amz-version-id` to report.
    pub version_id: Option<String>,
}

/// Why a read found nothing to read. Each read reports it differently.
pub(crate) enum Missing {
    /// No such key (or the bucket is gone).
    NoSuchKey,
    /// The named version doesn't exist.
    NoSuchVersion,
    /// The version read is a delete marker: the current one when no version was
    /// named (`named` false), else the named one. Carries the marker's
    /// `x-amz-version-id` and HTTP Last-Modified.
    DeleteMarker {
        named: bool,
        version_id: Option<String>,
        last_modified: String,
    },
}

impl Missing {
    /// The S3 error a GET or HEAD answers with:
    /// - no such key: 404 NoSuchKey;
    /// - no such version: 404 NoSuchVersion;
    /// - the current version is a delete marker: 404 NoSuchKey, flagged with
    ///   `x-amz-delete-marker` and the marker's version ID;
    /// - the named version is a delete marker: 405 MethodNotAllowed, flagged the
    ///   same way (a marker has no data to read).
    pub fn read_response(self) -> Response<Full<Bytes>> {
        match self {
            Missing::NoSuchKey => no_such_key(),
            Missing::NoSuchVersion => no_such_version(),
            Missing::DeleteMarker {
                named,
                version_id,
                last_modified,
            } => {
                let resp = if named {
                    let mut resp = format_s3_error(
                        StatusCode::METHOD_NOT_ALLOWED,
                        "MethodNotAllowed",
                        "the specified method is not allowed against this resource",
                    );
                    resp.headers_mut()
                        .insert(header::LAST_MODIFIED, last_modified.parse().unwrap());
                    resp
                } else {
                    no_such_key()
                };
                with_delete_marker(with_version_id(resp, version_id.as_deref()))
            }
        }
    }
}

/// Looks up the version a read addresses: the one named by `version_id`, or
/// else the key's current version — or why there's nothing to read.
pub(crate) async fn lookup_version<C: GenericClient>(
    client: &C,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
) -> Result<Result<ObjectVersion, Missing>, tokio_postgres::Error> {
    let row = client
        .query_opt(
            "SELECT o.id, o.etag, o.content_type, o.size,
                    to_char(o.last_modified AT TIME ZONE 'UTC', 'Dy, DD Mon YYYY HH24:MI:SS \"GMT\"'),
                    to_char(o.last_modified AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'),
                    floor(extract(epoch FROM o.last_modified))::bigint,
                    o.version_id, o.is_delete_marker, b.versioning
             FROM objects o JOIN buckets b ON b.name = o.bucket
             WHERE o.bucket = $1 AND o.key = $2
               AND CASE WHEN $3::text IS NULL THEN o.is_latest ELSE o.version_id = $3 END",
            &[&bucket, &key, &version_id],
        )
        .await?;
    let Some(row) = row else {
        return Ok(Err(match version_id {
            Some(_) => Missing::NoSuchVersion,
            None => Missing::NoSuchKey,
        }));
    };
    let versioning = Versioning::from_db(row.get(9));
    let reported = versioning.reported(row.get(7));
    if row.get::<_, bool>(8) {
        return Ok(Err(Missing::DeleteMarker {
            named: version_id.is_some(),
            version_id: reported,
            last_modified: row.get(4),
        }));
    }
    Ok(Ok(ObjectVersion {
        id: row.get(0),
        etag: row.get(1),
        content_type: row.get(2),
        size: row.get(3),
        last_modified: row.get(4),
        last_modified_iso: row.get(5),
        lm_epoch: row.get(6),
        version_id: reported,
    }))
}

/// S3's 404 for a key with nothing to read. The message must not be empty:
/// aws-cli's error-message hook crashes on an empty `<Message>`.
fn no_such_key() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::NOT_FOUND,
        "NoSuchKey",
        "the specified key does not exist",
    )
}

pub(crate) fn no_such_version() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::NOT_FOUND,
        "NoSuchVersion",
        "the specified version does not exist",
    )
}

pub async fn get_object(
    app: &Arc<App>,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
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
    let version = match lookup_version(&tx, bucket, key, version_id).await? {
        Ok(version) => version,
        Err(missing) => return Ok(box_response(missing.read_response())),
    };
    let ObjectVersion {
        id: object_id,
        etag,
        content_type,
        size,
        last_modified,
        lm_epoch,
        version_id,
        ..
    } = version;
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
    let parts = resolve_object_parts(&tx, object_id).await?;
    tx.commit().await?;

    // Select the parts overlapping the requested range and stream them (each over
    // its computed sub-range) through a channel-backed body: a background task
    // pulls each from a replica (locally if that's us), verifies it, and forwards
    // it. We set Content-Length, so a truncated stream (a part we can't serve) is
    // detected by the client rather than read as a short-but-complete object.
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
    Ok(with_version_id(builder.body(body).unwrap(), version_id.as_deref()))
}

/// One part of an object for streaming: where its bytes live (a blob, the
/// blob's block layout, and the offset in it), its size, and the blob's
/// candidate replica locations, freshest node first.
pub(crate) struct PartLocation {
    pub blob_id: Uuid,
    pub layout: Option<BlockLayout>,
    pub blob_offset: u64,
    pub size: u64,
    pub locations: Vec<Location>,
}

/// Resolves an object version's parts in order, each with its blob and the
/// blob's candidate replica locations (freshest node first). Runs within the
/// caller's transaction, so the parts and their locations come from one
/// consistent snapshot. Shared by GetObject (range streaming) and CopyObject
/// (whole-object copy).
pub(crate) async fn resolve_object_parts<C: GenericClient>(
    client: &C,
    object_id: i64,
) -> Result<Vec<PartLocation>, tokio_postgres::Error> {
    let rows = client
        .query(
            "SELECT p.part_number, p.blob_id, p.blob_offset, p.size, b.size, b.block_size,
                    bl.node, n.peer_url
             FROM parts p
             JOIN blobs b ON b.blob_id = p.blob_id
             JOIN blob_locations bl ON bl.blob_id = p.blob_id
             JOIN nodes n ON n.id = bl.node
             WHERE p.object_id = $1
             ORDER BY p.part_number, n.last_seen DESC",
            &[&object_id],
        )
        .await?;
    // Fold the flat join rows into one entry per part (rows are ordered by
    // part_number, then location), collecting each part's candidate locations.
    let mut parts: Vec<PartLocation> = Vec::new();
    let mut current: Option<i32> = None;
    for row in &rows {
        let part_number: i32 = row.get(0);
        if current != Some(part_number) {
            // A blob without a block size predates checksums.
            let layout = row.get::<_, Option<i32>>(5).map(|block_size| BlockLayout {
                block_size: block_size as u64,
                blob_size: row.get::<_, i64>(4) as u64,
            });
            parts.push(PartLocation {
                blob_id: row.get(1),
                layout,
                blob_offset: row.get::<_, i64>(2) as u64,
                size: row.get::<_, i64>(3) as u64,
                locations: Vec::new(),
            });
            current = Some(part_number);
        }
        parts.last_mut().unwrap().locations.push((row.get(6), row.get(7)));
    }
    Ok(parts)
}

/// Selects the parts overlapping the half-open byte range [range_start, range_end)
/// of the assembled object, each as the slice of its blob to read. Parts entirely
/// outside the range are dropped; `parts` must be in object order. Shared by
/// GetObject (ranged reads) and the copy paths.
pub(crate) fn select_parts_in_range(
    parts: Vec<PartLocation>,
    range_start: u64,
    range_end: u64,
) -> Vec<BlobSlice> {
    // Track the object offset where each part begins, and intersect its span with
    // the requested range.
    let mut slices: Vec<BlobSlice> = Vec::new();
    let mut cursor: u64 = 0;
    for part in parts {
        let part_start = cursor;
        let part_end = cursor + part.size;
        cursor = part_end;
        let overlap_start = range_start.max(part_start);
        let overlap_end = range_end.min(part_end);
        if overlap_start >= overlap_end {
            continue; // part lies entirely outside the requested range
        }
        slices.push(BlobSlice {
            blob_id: part.blob_id,
            layout: part.layout,
            locations: part.locations,
            offset: part.blob_offset + (overlap_start - part_start),
            length: overlap_end - overlap_start,
        });
    }
    slices
}

/// Spawns a background task that streams each selected blob slice to `sender`,
/// verified and pulled from a replica (locally if that's us) by
/// [`stream_blob_range`]. If any slice can't be served the stream is faulted.
/// Shared by GetObject and the copy paths.
pub(crate) fn spawn_range_stream(app: Arc<App>, slices: Vec<BlobSlice>, sender: FrameSender) {
    tokio::spawn(async move {
        for slice in slices {
            if let Err(e) = stream_blob_range(&app, &slice, &sender).await {
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

/// Metadata-only response for the key: answered straight from `objects`, never
/// touching a replica. s3cmd issues this before a download.
pub async fn head_object(
    app: &App,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    range_header: Option<&str>,
    preconditions: &Preconditions,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let client = app.pool.get().await?;
    let ObjectVersion {
        etag,
        content_type,
        size,
        last_modified,
        lm_epoch,
        version_id,
        ..
    } = match lookup_version(&client, bucket, key, version_id).await? {
        Ok(version) => version,
        Err(missing) => return Ok(missing.read_response()),
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
    Ok(with_version_id(builder.body(Full::new(Bytes::new())).unwrap(), version_id.as_deref()))
}
