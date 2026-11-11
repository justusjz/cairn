use std::{io, sync::Arc};

use http_body_util::Full;
use hyper::{
    Response, StatusCode,
    body::{Bytes, Frame},
    header,
};
use deadpool_postgres::GenericClient;
use uuid::Uuid;

use crate::db::Cached;
use crate::{
    App,
    blobs::{BlobSlice, Location, stream_blob_range},
    checksum::BlockLayout,
    body::{FrameSender, ResBody, box_response, channel_body},
    encryption::{Key, Opener, Salt, segment_range},
    s3::conditional::{Precondition, Preconditions, not_modified},
    s3::checksums::{ChecksumKey, Storing, StoredChecksum},
    s3::metadata,
    s3::sse::{self, Stored},
    s3::sse_c::CustomerKey,
    s3::util::{format_s3_error, with_delete_marker, with_version_id},
    s3::versions::Versioning,
};

/// The object version a read addresses, as far as its response needs it.
pub(crate) struct ObjectVersion {
    /// Row id, to resolve its parts by.
    pub id: i64,
    pub etag: String,
    pub content_type: String,
    /// The headers stored with it (see `s3::metadata`).
    pub metadata: String,
    /// How it's encrypted (see `s3::sse`).
    pub encryption: Stored,
    pub size: i64,
    /// Last-Modified as an HTTP date (for headers) and in ISO 8601 (for XML
    /// bodies), and as a Unix timestamp for conditionals.
    pub last_modified: String,
    pub last_modified_iso: String,
    pub lm_epoch: i64,
    /// The `x-amz-version-id` to report.
    pub version_id: Option<String>,
    /// Its checksum, as it's stored (see `s3::checksums`), if it has one.
    pub checksum: Option<StoredChecksum>,
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
        .query_opt_cached(
            "SELECT o.id, o.etag, o.content_type, o.size,
                    to_char(o.last_modified AT TIME ZONE 'UTC', 'Dy, DD Mon YYYY HH24:MI:SS \"GMT\"'),
                    to_char(o.last_modified AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'),
                    floor(extract(epoch FROM o.last_modified))::bigint,
                    o.version_id, o.is_delete_marker, b.versioning, o.metadata, o.sse_c_key,
                    o.sse_kms_key_id, o.sse_kms_data_key, o.sse_kms_sealed, o.sse_kms_context,
                    o.sse_s3, o.checksum_algorithm, o.checksum_type, o.checksum
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
        metadata: row.get(10),
        encryption: Stored::from_row(&row, 11),
        size: row.get(3),
        last_modified: row.get(4),
        last_modified_iso: row.get(5),
        lm_epoch: row.get(6),
        version_id: reported,
        checksum: StoredChecksum::from_row(&row, 17),
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
    customer_key: Option<&CustomerKey>,
    role: Option<uuid::Uuid>,
    checksum_mode: bool,
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
        metadata,
        encryption,
        size,
        last_modified,
        lm_epoch,
        version_id,
        checksum,
        ..
    } = version;
    // An SSE-C object only with its key; before the conditions, which would
    // tell about it otherwise.
    if let Err(refused) = sse::check(&encryption, customer_key) {
        return Ok(box_response(refused));
    }
    // Its ETag, as clients know it (an SSE-S3 one's is stored sealed).
    let etag = match sse::plain_etag(app, &encryption, &etag, bucket, key).await? {
        Ok(etag) => etag,
        Err(refused) => return Ok(box_response(refused)),
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
    let parts = resolve_object_parts(&tx, object_id).await?;
    tx.commit().await?;
    // Bytes that no replica holds intact fail the read before it starts,
    // rather than cutting it off there.
    if reads_lost(&client, &parts, range_start, range_end).await? {
        eprintln!("refusing to read {bucket}/{key}: some of the range {range_start}-{range_end} is lost");
        return Ok(box_response(lost_data()));
    }
    // The key it's encrypted with, from the KMS for an SSE-KMS object: only
    // once it's certain to be read.
    let object_key = match sse::open(app, &encryption, customer_key, role, bucket, key).await? {
        Ok(object_key) => object_key,
        Err(refused) => return Ok(box_response(refused)),
    };

    // Select the parts overlapping the requested range and stream them (each over
    // its computed sub-range) through a channel-backed body: a background task
    // pulls each from a replica (locally if that's us), verifies it, and forwards
    // it. We set Content-Length, so a truncated stream (a part we can't serve) is
    // detected by the client rather than read as a short-but-complete object.
    let slices = select_parts_in_range(parts, range_start, range_end, object_key.as_deref());
    let (sender, body) = channel_body();
    spawn_range_stream(app.clone(), slices, sender);

    let builder = Response::builder()
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::ETAG, format!("\"{etag}\""))
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, range_end - range_start)
        .header(header::LAST_MODIFIED, last_modified);
    let builder = metadata::apply(builder, &metadata);
    let builder = sse::echo(builder, &encryption, customer_key);
    let builder = match checksum.filter(|_| checksum_mode && !partial) {
        Some(checksum) => checksum_headers(builder, &checksum, object_key.as_deref())?,
        None => builder,
    };
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
#[derive(Clone)]
pub(crate) struct PartLocation {
    pub id: i64,
    pub blob_id: Uuid,
    pub layout: Option<BlockLayout>,
    pub blob_offset: u64,
    /// What it takes in its blob.
    pub size: u64,
    /// If it's encrypted: its plaintext's size, and its salt.
    pub plain_size: Option<u64>,
    pub salt: Option<Salt>,
    pub locations: Vec<Location>,
}

impl PartLocation {
    /// What it contributes to its object.
    pub fn object_size(&self) -> u64 {
        self.plain_size.unwrap_or(self.size)
    }
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
        .query_cached(
            "SELECT p.part_number, p.blob_id, p.blob_offset, p.size, b.size, b.block_size,
                    bl.node, n.peer_url, p.id, p.plain_size, p.enc_salt
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
                id: row.get(8),
                blob_id: row.get(1),
                layout,
                blob_offset: row.get::<_, i64>(2) as u64,
                size: row.get::<_, i64>(3) as u64,
                plain_size: row.get::<_, Option<i64>>(9).map(|size| size as u64),
                salt: row
                    .get::<_, Option<Vec<u8>>>(10)
                    .map(|salt| salt.try_into().expect("a salt is 16 bytes (parts_encrypted)")),
                locations: Vec::new(),
            });
            current = Some(part_number);
        }
        parts.last_mut().unwrap().locations.push((row.get(6), row.get(7)));
    }
    Ok(parts)
}

/// A slice of a blob to read for an object's range, and, if its part is
/// encrypted, how to decrypt it.
pub(crate) struct ReadSlice {
    pub blob: BlobSlice,
    pub decrypt: Option<Decrypt>,
}

/// How to decrypt a slice of an encrypted part: whole segments of it, from
/// `first` on, of which the range is `len` bytes from `skip` on.
pub(crate) struct Decrypt {
    /// `None` if the read has no key; then it fails.
    key: Option<zeroize::Zeroizing<Key>>,
    salt: Salt,
    plain: u64,
    first: u64,
    skip: u64,
    len: u64,
}

/// Selects the parts overlapping the half-open byte range [range_start, range_end)
/// of the assembled object, each as the slice of its blob to read. Parts entirely
/// outside the range are dropped; `parts` must be in object order. An encrypted
/// part's slice is its whole segments that the range overlaps, decrypted with
/// `key`. Shared by GetObject (ranged reads) and the copy paths.
pub(crate) fn select_parts_in_range(
    parts: Vec<PartLocation>,
    range_start: u64,
    range_end: u64,
    key: Option<&Key>,
) -> Vec<ReadSlice> {
    // Track the object offset where each part begins, and intersect its span with
    // the requested range.
    let mut slices = Vec::new();
    let mut cursor: u64 = 0;
    for part in parts {
        let part_start = cursor;
        let part_end = cursor + part.object_size();
        cursor = part_end;
        let overlap_start = range_start.max(part_start);
        let overlap_end = range_end.min(part_end);
        if overlap_start >= overlap_end {
            continue; // part lies entirely outside the requested range
        }
        let (within, length, decrypt) = match (part.salt, part.plain_size) {
            (Some(salt), Some(plain)) => {
                let range = segment_range(plain, overlap_start - part_start, overlap_end - part_start);
                let decrypt = Decrypt {
                    key: key.map(|key| zeroize::Zeroizing::new(*key)),
                    salt,
                    plain,
                    first: range.first,
                    skip: range.skip,
                    len: range.len,
                };
                (range.stored_start, range.stored_end - range.stored_start, Some(decrypt))
            }
            _ => (overlap_start - part_start, overlap_end - overlap_start, None),
        };
        slices.push(ReadSlice {
            blob: BlobSlice {
                blob_id: part.blob_id,
                layout: part.layout,
                locations: part.locations,
                offset: part.blob_offset + within,
                length,
                part: Some((part.id, part.blob_offset)),
            },
            decrypt,
        });
    }
    slices
}

/// Whether any of the bytes [`start`, `end`) of an object, which is made of
/// `parts`, are lost: intact on no replica, as the scrubber found (see
/// `scrub`). The bytes of its blobs that a read would fetch, that is: whole
/// segments, if it's encrypted.
pub(crate) async fn reads_lost<C: GenericClient>(
    client: &C,
    parts: &[PartLocation],
    start: u64,
    end: u64,
) -> Result<bool, tokio_postgres::Error> {
    let slices = select_parts_in_range(parts.to_vec(), start, end, None);
    if slices.is_empty() {
        return Ok(false);
    }
    let (mut blobs, mut starts, mut stops) = (Vec::new(), Vec::new(), Vec::new());
    for ReadSlice { blob, .. } in &slices {
        blobs.push(blob.blob_id);
        starts.push(blob.offset as i64);
        stops.push((blob.offset + blob.length) as i64);
    }
    // Almost always, nothing is lost: a lookup per blob in an empty table.
    let row = client
        .query_one_cached(
            "SELECT EXISTS (
                 SELECT 1 FROM unnest($1::uuid[], $2::bigint[], $3::bigint[]) AS s(blob_id, start, stop)
                 JOIN lost_ranges l ON l.blob_id = s.blob_id
                 WHERE l.start < s.stop AND l.stop > s.start
             )",
            &[&blobs, &starts, &stops],
        )
        .await?;
    Ok(row.get(0))
}

/// The answer to a read or copy of lost bytes.
pub(crate) fn lost_data() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "InternalError",
        "some of the requested data is damaged on every replica, and can't be read",
    )
}

/// Spawns a background task that streams each selected blob slice to `sender`,
/// verified and pulled from a replica (locally if that's us) by
/// [`stream_blob_range`]. If any slice can't be served the stream is faulted.
/// Shared by GetObject and the copy paths.
///
/// The packer may move a part to another blob after it was resolved, and reap
/// the old one mid-read. So when a slice can't be served, its part is looked up
/// again, and the rest is read from wherever it lives now.
pub(crate) fn spawn_range_stream(app: Arc<App>, slices: Vec<ReadSlice>, sender: FrameSender) {
    tokio::spawn(async move {
        for slice in slices {
            let read = match slice.decrypt {
                None => read_slice(&app, slice.blob, &sender).await,
                Some(decrypt) => read_decrypted(&app, slice.blob, decrypt, &sender).await,
            };
            if let Err(e) = read {
                let _ = sender.send(Err(e)).await;
                return;
            }
        }
    });
}

/// Streams `slice` to `tx`, following its part if the packer moves it.
async fn read_slice(app: &App, mut slice: BlobSlice, tx: &FrameSender) -> io::Result<()> {
    let mut moves = 0;
    while let Err(e) = stream_blob_range(app, &mut slice, tx).await {
        match relocate(app, &slice).await {
            Ok(Some(moved)) if moves < MAX_RELOCATIONS => {
                slice = moved;
                moves += 1;
            }
            Ok(_) => return Err(e),
            Err(lookup) => {
                eprintln!("looking up part of blob {} failed: {lookup:#}", slice.blob_id);
                return Err(e);
            }
        }
    }
    Ok(())
}

/// Streams the plaintext of an encrypted part's `slice` to `tx`. The slice is
/// read as any other, and decrypted after: its bytes come verified and in
/// order, whichever replica or blob they're read from (`read_slice` resumes
/// where a failed read stopped, maybe mid-segment), so the decryption only
/// ever sees one stream. The reading runs as a task of its own, so that it
/// and the decryption proceed side by side; a bounded channel between them
/// keeps what's in flight small.
async fn read_decrypted(
    app: &Arc<App>,
    slice: BlobSlice,
    decrypt: Decrypt,
    tx: &FrameSender,
) -> io::Result<()> {
    let Some(key) = &decrypt.key else {
        return Err(io::Error::other("an encrypted part, and no key to read it with"));
    };
    let (stored_tx, mut stored) = tokio::sync::mpsc::channel(4);
    let reading = {
        let app = app.clone();
        tokio::spawn(async move { read_slice(&app, slice, &stored_tx).await })
    };
    let open = async {
        let mut opener = Opener::new(key, decrypt.salt, decrypt.plain, decrypt.first);
        let (mut skip, mut left) = (decrypt.skip as usize, decrypt.len as usize);
        while let Some(frame) = stored.recv().await {
            let Ok(data) = frame?.into_data() else { continue };
            let opened = opener.update(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            for mut plain in opened {
                let skipped = skip.min(plain.len());
                plain = plain.slice(skipped..);
                skip -= skipped;
                let take = left.min(plain.len());
                if take > 0 {
                    left -= take;
                    tx.send(Ok(Frame::data(plain.slice(..take))))
                        .await
                        .map_err(|_| io::Error::other("the reader went away"))?;
                }
            }
        }
        opener.finish().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok::<_, io::Error>(left)
    };
    let opened = open.await;
    // Stops the reading, if the decryption gave up first (its sends fail).
    drop(stored);
    let read = reading.await.map_err(io::Error::other)?;
    read?;
    if opened? > 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "an encrypted part ended early"));
    }
    Ok(())
}

/// How often a single read follows its part to a new blob before giving up.
const MAX_RELOCATIONS: usize = 3;

/// The rest of `slice` in the blob its part lives in now, or `None` if the part
/// hasn't moved (so there's nowhere else to read it from) or is gone.
async fn relocate(app: &App, slice: &BlobSlice) -> anyhow::Result<Option<BlobSlice>> {
    let Some((part_id, old_offset)) = slice.part else {
        return Ok(None);
    };
    let client = app.pool.get().await?;
    let rows = client
        .query_cached(
            "SELECT p.blob_id, p.blob_offset, b.size, b.block_size, bl.node, n.peer_url
             FROM parts p
             JOIN blobs b ON b.blob_id = p.blob_id
             JOIN blob_locations bl ON bl.blob_id = p.blob_id
             JOIN nodes n ON n.id = bl.node
             WHERE p.id = $1
             ORDER BY n.last_seen DESC",
            &[&part_id],
        )
        .await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let blob_id: Uuid = row.get(0);
    if blob_id == slice.blob_id {
        return Ok(None);
    }
    let blob_offset = row.get::<_, i64>(1) as u64;
    Ok(Some(BlobSlice {
        blob_id,
        layout: row.get::<_, Option<i32>>(3).map(|block_size| BlockLayout {
            block_size: block_size as u64,
            blob_size: row.get::<_, i64>(2) as u64,
        }),
        locations: rows.iter().map(|r| (r.get(4), r.get(5))).collect(),
        // The slice keeps its offset within the part.
        offset: blob_offset + (slice.offset - old_offset),
        length: slice.length,
        part: Some((part_id, blob_offset)),
    }))
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
    customer_key: Option<&CustomerKey>,
    role: Option<uuid::Uuid>,
    checksum_mode: bool,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let client = app.pool.get().await?;
    let ObjectVersion {
        etag,
        content_type,
        metadata,
        encryption,
        size,
        last_modified,
        lm_epoch,
        version_id,
        checksum,
        ..
    } = match lookup_version(&client, bucket, key, version_id).await? {
        Ok(version) => version,
        Err(missing) => return Ok(missing.read_response()),
    };
    // Like GET's, but an SSE-KMS object's key isn't needed (an SSE-S3 one's
    // is, for its ETag).
    if let Err(refused) = sse::check(&encryption, customer_key) {
        return Ok(refused);
    }
    let etag = match sse::plain_etag(app, &encryption, &etag, bucket, key).await? {
        Ok(etag) => etag,
        Err(refused) => return Ok(refused),
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
    let builder = metadata::apply(builder, &metadata);
    let builder = sse::echo(builder, &encryption, customer_key);
    // Its checksum, if asked for: an encrypted one's sealed under its key,
    // which, for an SSE-KMS one, is only asked of the KMS then.
    let builder = match checksum.filter(|_| checksum_mode && !partial) {
        Some(checksum) => {
            let object_key = match encryption {
                Stored::Plain => None,
                _ => match sse::open(app, &encryption, customer_key, role, bucket, key).await? {
                    Ok(object_key) => object_key,
                    Err(refused) => return Ok(refused),
                },
            };
            checksum_headers(builder, &checksum, object_key.as_deref())?
        }
        None => builder,
    };
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

/// An object's checksum, as a read with `x-amz-checksum-mode: ENABLED` tells
/// it (S3 tells none for a range): opened with its object key, if it's
/// encrypted.
fn checksum_headers(
    builder: hyper::http::response::Builder,
    checksum: &StoredChecksum,
    object_key: Option<&Key>,
) -> anyhow::Result<hyper::http::response::Builder> {
    let checksum_key = object_key.map(ChecksumKey::new);
    let storing = match &checksum_key {
        Some(checksum_key) => Storing::Sealed(checksum_key),
        None => Storing::Plain,
    };
    Ok(checksum.read(&storing)?.headers(builder))
}
