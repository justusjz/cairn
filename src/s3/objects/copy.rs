use std::sync::Arc;

use deadpool_postgres::GenericClient;
use http_body_util::{BodyExt, Full};
use hyper::{Response, StatusCode, body::Bytes, header::HeaderValue};
use md5::{Digest, Md5};
use tokio_postgres::IsolationLevel;
use uuid::Uuid;

use crate::{
    App, AttachTarget, Contended, UploadResult,
    auth::ContentSha256,
    blobs::{deleted_parts, drop_blobs_of_deleted_parts, reap_blobs},
    body::channel_body,
    db,
    s3::{
        conditional::{Precondition, Preconditions},
        objects::get::{
            Missing, ObjectVersion, PartLocation, lookup_version, no_such_version, parse_range,
            resolve_object_parts, select_parts_in_range, spawn_range_stream,
        },
        util::{decode_path_param, format_s3_error, query_param, with_version_id, xml_ok},
        versions::{Versioning, bucket_versioning, put_version},
    },
};

/// The 412 response returned when a copy-source precondition isn't met.
fn copy_precondition_failed() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::PRECONDITION_FAILED,
        "PreconditionFailed",
        "the source object did not satisfy the copy conditions",
    )
}

/// How often a copy starts over because its source changed while it ran.
const MAX_SOURCE_ATTEMPTS: usize = 5;

/// A part of a copy's source, as the catalog has it.
struct SourcePart {
    id: i64,
    blob_id: Uuid,
    offset: i64,
    size: i64,
    etag: String,
    crc64nvme: Option<i64>,
}

/// The version a copy reads: its metadata, its parts, and where to read them
/// from, should the copy have to hash some of the data.
struct Source {
    version: ObjectVersion,
    parts: Vec<SourcePart>,
    locations: Vec<PartLocation>,
}

/// CopyObject: `PUT /{dest_bucket}/{dest_key}` with an `x-amz-copy-source`
/// header. Copies only metadata: the new version gets parts of its own on the
/// source's bytes, which the two then share. Deleting either leaves the other
/// intact; the bytes go once neither references them.
///
/// The copy's ETag is the MD5 of its data, as S3's is. For a source of one
/// part, that's the part's ETag. A multipart source has no such ETag, so its
/// data is read once to work it out (but not written).
///
/// `metadata_directive` is `x-amz-metadata-directive` (COPY, the default, or
/// REPLACE). Under COPY the destination inherits the source's content-type; under
/// REPLACE it takes `request_content_type` (the request's own Content-Type).
pub async fn copy_object(
    app: &Arc<App>,
    dest_bucket: &str,
    dest_key: &str,
    copy_source: &str,
    metadata_directive: Option<&str>,
    request_content_type: &str,
    preconditions: &Preconditions,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let (src_bucket, src_key, src_version) = match parse_copy_source(copy_source) {
        Some(source) => source,
        None => {
            return Ok(format_s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "the x-amz-copy-source header is malformed",
            ));
        }
    };

    // COPY (the default) keeps the source metadata; only REPLACE substitutes new.
    let replace = metadata_directive
        .map(|d| d.eq_ignore_ascii_case("REPLACE"))
        .unwrap_or(false);
    // S3 rejects a copy of an object onto itself that changes nothing, guarding
    // against a client accidentally issuing a destructive no-op. Copying a named
    // version onto its own key is allowed: that's how an old version is restored.
    if src_bucket == dest_bucket && src_key == dest_key && !replace && src_version.is_none() {
        return Ok(format_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "this copy request is illegal because it is trying to copy an object to \
             itself without changing the object's metadata",
        ));
    }
    let client = app.pool.get().await?;
    if client
        .query_opt("SELECT 1 FROM buckets WHERE name = $1", &[&dest_bucket])
        .await?
        .is_none()
    {
        return Ok(format_s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "the specified bucket does not exist",
        ));
    }
    drop(client);

    for _ in 0..MAX_SOURCE_ATTEMPTS {
        let source = match read_source(app, &src_bucket, &src_key, src_version.as_deref()).await? {
            Ok(source) => source,
            Err(missing) => return Ok(missing),
        };
        // Honour x-amz-copy-source-if-* conditions on the source; any failure (a
        // 304 for a read maps to 412 here) aborts the copy.
        let version = &source.version;
        if preconditions.evaluate(&version.etag, version.lm_epoch, true) != Precondition::Proceed {
            return Ok(copy_precondition_failed());
        }
        let etag = match source.parts.as_slice() {
            [part] => part.etag.clone(),
            _ => {
                let size = version.size as u64;
                hash_range(app, source.locations.clone(), 0, size).await?.0
            }
        };
        let content_type = if replace {
            request_content_type
        } else {
            &version.content_type
        };
        let Some(version_id) =
            commit_object_copy(app, &source, dest_bucket, dest_key, &etag, content_type).await?
        else {
            continue; // the source changed meanwhile: copy what it is now
        };

        // CopyObject reports the result in the body (not just the ETag header):
        // read back the new version's freshly-stamped last-modified in ISO 8601.
        // An unversioned bucket's only version is `null`.
        let client = app.pool.get().await?;
        let last_modified: String = client
            .query_one(
                "SELECT to_char(last_modified AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\".000Z\"')
                 FROM objects WHERE bucket = $1 AND key = $2 AND version_id = $3",
                &[&dest_bucket, &dest_key, &version_id.as_deref().unwrap_or("null")],
            )
            .await?
            .get(0);
        let resp = with_version_id(
            xml_ok(format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                 <CopyObjectResult>\
                 <LastModified>{last_modified}</LastModified>\
                 <ETag>\"{etag}\"</ETag>\
                 </CopyObjectResult>"
            )),
            version_id.as_deref(),
        );
        return Ok(with_copy_source_version_id(resp, source.version.version_id.as_deref()));
    }
    Err(Contended("the copy source kept changing".to_owned()).into())
}

/// The transaction that makes a copy of `source` at `bucket`/`key`: a new
/// version with parts on the source's bytes. Returns its version ID to report,
/// or `None` if the source changed since it was read.
async fn commit_object_copy(
    app: &Arc<App>,
    source: &Source,
    bucket: &str,
    key: &str,
    etag: &str,
    content_type: &str,
) -> anyhow::Result<Option<Option<String>>> {
    let mut client = app.pool.get().await?;
    for attempt in 0..db::MAX_TX_ATTEMPTS {
        db::backoff(attempt).await;
        let result: Result<_, tokio_postgres::Error> = async {
            let tx = client
                .build_transaction()
                .isolation_level(IsolationLevel::Serializable)
                .start()
                .await?;
            let Some(parts) = current_parts(&tx, source).await? else {
                return Ok(None);
            };
            // Reading the bucket's versioning state in this transaction orders
            // the write against a concurrent PutBucketVersioning. A bucket deleted
            // meanwhile reads as unversioned; the objects -> buckets FK then
            // rejects the insert.
            let versioning = bucket_versioning(&tx, bucket)
                .await?
                .unwrap_or(Versioning::Unversioned);
            let mut freed = Vec::new();
            let size = source.version.size;
            let version =
                put_version(&tx, bucket, key, versioning, size, etag, content_type, &mut freed)
                    .await?;
            for (number, part) in (1..).zip(&parts) {
                let (etag, crc) = (&part.etag, part.crc64nvme);
                insert_part(&tx, part, 0, part.size, etag, crc, Some(version.id), None, number)
                    .await?;
            }
            // After inserting the new parts: a copy onto its own source replaces
            // the version whose bytes it shares.
            let reap = drop_blobs_of_deleted_parts(&tx, &freed).await?;
            tx.commit().await?;
            Ok(Some((version.version_id, reap)))
        }
        .await;
        match result {
            Ok(Some((version_id, reap))) => {
                reap_blobs(app, reap);
                return Ok(Some(version_id));
            }
            Ok(None) => return Ok(None),
            Err(e) if db::is_conflict(&e) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(Contended("the copy kept conflicting with concurrent requests".to_owned()).into())
}

/// UploadPartCopy: `PUT /{bucket}/{key}?partNumber=N&uploadId=U` with an
/// `x-amz-copy-source` header (and optional `x-amz-copy-source-range`). Copies a
/// byte range of the source object into a part staged under the upload — the
/// large-object counterpart to CopyObject, letting a client assemble a copy out of
/// parts bigger than a single CopyObject would allow. Returns the new part's ETag.
///
/// A range within one part of the source only takes metadata: the new part is
/// on the source's bytes. Its ETag is their MD5, which, unless the range is a
/// whole part, takes reading them (but not writing them). A part can't span
/// blobs, so a range over several parts of the source is copied as data.
pub async fn copy_part(
    app: &Arc<App>,
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: &str,
    copy_source: &str,
    copy_source_range: Option<&str>,
    preconditions: &Preconditions,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let upload_id = match Uuid::parse_str(upload_id) {
        Ok(id) => id,
        Err(_) => return Ok(no_such_upload()),
    };
    let part_number: i32 = match part_number.parse() {
        Ok(n) if (1..=10_000).contains(&n) => n,
        _ => {
            return Ok(format_s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "partNumber must be an integer in 1..=10000",
            ));
        }
    };
    let (src_bucket, src_key, src_version) = match parse_copy_source(copy_source) {
        Some(source) => source,
        None => {
            return Ok(format_s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "the x-amz-copy-source header is malformed",
            ));
        }
    };

    // Reject up front if the upload is gone, and require it to belong to the
    // request's bucket/key — as put_part does.
    let client = app.pool.get().await?;
    if client
        .query_opt(
            "SELECT 1 FROM multipart_uploads WHERE upload_id = $1 AND bucket = $2 AND key = $3",
            &[&upload_id, &bucket, &key],
        )
        .await?
        .is_none()
    {
        return Ok(no_such_upload());
    }
    drop(client);

    for _ in 0..MAX_SOURCE_ATTEMPTS {
        let source = match read_source(app, &src_bucket, &src_key, src_version.as_deref()).await? {
            Ok(source) => source,
            Err(missing) => return Ok(missing),
        };
        let version = &source.version;
        // Honour x-amz-copy-source-if-* conditions on the source before copying.
        if preconditions.evaluate(&version.etag, version.lm_epoch, true) != Precondition::Proceed {
            return Ok(copy_precondition_failed());
        }
        // Resolve the copy range against the source size (absent header → whole
        // object). Reuses GET's range parser; an unsatisfiable range is a 400.
        let size = version.size as u64;
        let (start, end) = match parse_range(copy_source_range, size) {
            Ok(Some((start, end))) => (start, end),
            Ok(None) => (0, size),
            Err(()) => {
                return Ok(format_s3_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidArgument",
                    "the x-amz-copy-source-range is not satisfiable",
                ));
            }
        };
        let respond = |etag: &str| {
            let resp = xml_ok(format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                 <CopyPartResult>\
                 <LastModified>{}</LastModified>\
                 <ETag>\"{etag}\"</ETag>\
                 </CopyPartResult>",
                version.last_modified_iso
            ));
            with_copy_source_version_id(resp, version.version_id.as_deref())
        };
        let Some((index, within)) = part_holding(&source.parts, start, end) else {
            let etag = stream_part_copy(app, &source, start, end, upload_id, part_number).await?;
            return Ok(respond(&etag));
        };
        let part = &source.parts[index];
        let length = (end - start) as i64;
        let (etag, crc) = if within == 0 && length == part.size {
            (part.etag.clone(), part.crc64nvme)
        } else {
            let (md5, crc) = hash_range(app, source.locations.clone(), start, end).await?;
            (md5, Some(crc as i64))
        };
        let new_part = NewPart {
            index,
            within: within as i64,
            length,
            etag: &etag,
            crc,
        };
        match commit_part_copy(app, &source, &new_part, upload_id, part_number).await? {
            PartCopy::Committed => return Ok(respond(&etag)),
            PartCopy::NoSuchUpload => return Ok(no_such_upload()),
            PartCopy::SourceChanged => continue,
        }
    }
    Err(Contended("the copy source kept changing".to_owned()).into())
}

/// The part an UploadPartCopy stages: a range of one part of the source.
struct NewPart<'a> {
    /// Which part of the source, and where in it.
    index: usize,
    within: i64,
    length: i64,
    etag: &'a str,
    crc: Option<i64>,
}

enum PartCopy {
    Committed,
    NoSuchUpload,
    SourceChanged,
}

/// The transaction that stages `new_part` as part `part_number` of the upload,
/// on the bytes of the source part it copies, displacing any part uploaded at
/// that number before.
async fn commit_part_copy(
    app: &Arc<App>,
    source: &Source,
    new_part: &NewPart<'_>,
    upload_id: Uuid,
    part_number: i32,
) -> anyhow::Result<PartCopy> {
    let mut client = app.pool.get().await?;
    for attempt in 0..db::MAX_TX_ATTEMPTS {
        db::backoff(attempt).await;
        let result: Result<_, tokio_postgres::Error> = async {
            let tx = client
                .build_transaction()
                .isolation_level(IsolationLevel::Serializable)
                .start()
                .await?;
            let Some(parts) = current_parts(&tx, source).await? else {
                return Ok((PartCopy::SourceChanged, Vec::new()));
            };
            let upload = tx
                .query_opt("SELECT 1 FROM multipart_uploads WHERE upload_id = $1", &[&upload_id])
                .await?;
            if upload.is_none() {
                return Ok((PartCopy::NoSuchUpload, Vec::new()));
            }
            let displaced = tx
                .query(
                    "DELETE FROM parts WHERE upload_id = $1 AND part_number = $2
                     RETURNING blob_id, size",
                    &[&upload_id, &part_number],
                )
                .await?;
            let part = &parts[new_part.index];
            insert_part(
                &tx,
                part,
                new_part.within,
                new_part.length,
                new_part.etag,
                new_part.crc,
                None,
                Some(upload_id),
                part_number,
            )
            .await?;
            let reap = drop_blobs_of_deleted_parts(&tx, &deleted_parts(&displaced)).await?;
            tx.commit().await?;
            Ok((PartCopy::Committed, reap))
        }
        .await;
        match result {
            Ok((outcome, reap)) => {
                reap_blobs(app, reap);
                return Ok(outcome);
            }
            Err(e) if db::is_conflict(&e) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(Contended("the copy kept conflicting with concurrent requests".to_owned()).into())
}

/// Copies bytes [start, end) of `source` as data into a new part staged
/// under the upload, through the normal upload path (which works out the
/// part's ETag as it streams). For a range over several parts of the source.
async fn stream_part_copy(
    app: &Arc<App>,
    source: &Source,
    start: u64,
    end: u64,
    upload_id: Uuid,
    part_number: i32,
) -> anyhow::Result<String> {
    let (sender, source_body) = channel_body();
    let slices = select_parts_in_range(source.locations.clone(), start, end);
    spawn_range_stream(app.clone(), slices, sender);
    let attach = AttachTarget::MultipartPart {
        upload_id,
        part_number,
    };
    // The source stream is trusted internal data, so it carries no
    // content-sha256 claim and no aws-chunked framing: only Committed is
    // reachable.
    match crate::upload_part(app, source_body, &attach, false, ContentSha256::Unsigned, None).await? {
        UploadResult::Committed { etag, .. } => Ok(etag),
        UploadResult::ContentSha256Mismatch
        | UploadResult::ChunkSignatureMismatch
        | UploadResult::PreconditionFailed => {
            anyhow::bail!("the copy of a source range failed an integrity check")
        }
    }
}

/// Reads the version a copy addresses (the one named, else the key's current
/// one), with its parts, from one snapshot. `Err` holds the response for a
/// source with nothing to copy.
async fn read_source(
    app: &App,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
) -> anyhow::Result<Result<Source, Response<Full<Bytes>>>> {
    let mut client = app.pool.get().await?;
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .start()
        .await?;
    let version = match lookup_version(&tx, bucket, key, version_id).await? {
        Ok(version) => version,
        Err(missing) => return Ok(Err(source_missing(missing))),
    };
    let parts = source_parts(&tx, version.id).await?;
    let locations = resolve_object_parts(&tx, version.id).await?;
    tx.commit().await?;
    Ok(Ok(Source {
        version,
        parts,
        locations,
    }))
}

/// The parts of the object version with row id `object_id`, in order.
async fn source_parts<C: GenericClient>(
    client: &C,
    object_id: i64,
) -> Result<Vec<SourcePart>, tokio_postgres::Error> {
    let rows = client
        .query(
            "SELECT id, blob_id, blob_offset, size, etag, crc64nvme FROM parts
             WHERE object_id = $1 ORDER BY part_number",
            &[&object_id],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| SourcePart {
            id: r.get(0),
            blob_id: r.get(1),
            offset: r.get(2),
            size: r.get(3),
            etag: r.get(4),
            crc64nvme: r.get(5),
        })
        .collect())
}

/// The source's parts as they are now, in the copy's transaction, or `None` if
/// the source isn't what the copy read anymore. A part's bytes never change, so
/// the same parts mean the same data, though the packer may have moved them to
/// another blob since. A deleted version takes its parts with it, and every
/// object has at least one, so a deleted source shows here too.
async fn current_parts<C: GenericClient>(
    client: &C,
    source: &Source,
) -> Result<Option<Vec<SourcePart>>, tokio_postgres::Error> {
    let parts = source_parts(client, source.version.id).await?;
    let same = parts.len() == source.parts.len()
        && parts
            .iter()
            .zip(&source.parts)
            .all(|(now, then)| now.id == then.id && now.size == then.size);
    Ok(same.then_some(parts))
}

/// Inserts a part on `length` bytes of the source part `on`, from `within` it.
#[allow(clippy::too_many_arguments)]
async fn insert_part<C: GenericClient>(
    client: &C,
    on: &SourcePart,
    within: i64,
    length: i64,
    etag: &str,
    crc64nvme: Option<i64>,
    object_id: Option<i64>,
    upload_id: Option<Uuid>,
    part_number: i32,
) -> Result<(), tokio_postgres::Error> {
    client
        .execute(
            "INSERT INTO parts
                 (blob_id, blob_offset, size, etag, crc64nvme, object_id, upload_id, part_number,
                  created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())",
            &[
                &on.blob_id,
                &(on.offset + within),
                &length,
                &etag,
                &crc64nvme,
                &object_id,
                &upload_id,
                &part_number,
            ],
        )
        .await?;
    Ok(())
}

/// The part of `parts` (in object order) that holds all of [start, end), and
/// where the range starts in it; `None` if the range spans several parts.
fn part_holding(parts: &[SourcePart], start: u64, end: u64) -> Option<(usize, u64)> {
    let mut part_start = 0;
    for (i, part) in parts.iter().enumerate() {
        let part_end = part_start + part.size as u64;
        if start >= part_start && end <= part_end && (start < part_end || part.size == 0) {
            return Some((i, start - part_start));
        }
        part_start = part_end;
    }
    None
}

/// Reads bytes [start, end) of an object (its `parts`), verified like a GET,
/// and returns their MD5 (hex) and CRC64/NVME: what a copy of them needs, and
/// the catalog doesn't have.
async fn hash_range(
    app: &Arc<App>,
    parts: Vec<PartLocation>,
    start: u64,
    end: u64,
) -> anyhow::Result<(String, u64)> {
    let (sender, mut body) = channel_body();
    spawn_range_stream(app.clone(), select_parts_in_range(parts, start, end), sender);
    let mut md5 = Md5::new();
    let mut crc = crc64fast_nvme::Digest::new();
    let mut read = 0;
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame?.into_data() {
            md5.update(&data);
            crc.write(&data);
            read += data.len() as u64;
        }
    }
    anyhow::ensure!(read == end - start, "the copy source was cut short");
    let md5: String = md5.finalize().iter().map(|b| format!("{b:02x}")).collect();
    Ok((md5, crc.sum64()))
}

fn no_such_upload() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::NOT_FOUND,
        "NoSuchUpload",
        "the specified multipart upload does not exist",
    )
}

/// The S3 error for a copy source with nothing to copy. Unlike a GET, naming a
/// delete marker by version ID is a 400: a copy source may not refer to one.
fn source_missing(missing: Missing) -> Response<Full<Bytes>> {
    match missing {
        Missing::NoSuchKey | Missing::DeleteMarker { named: false, .. } => format_s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchKey",
            "the specified source key does not exist",
        ),
        Missing::NoSuchVersion => no_such_version(),
        Missing::DeleteMarker { named: true, .. } => format_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "the source of a copy request may not specifically refer to a delete marker by \
             version id",
        ),
    }
}

/// Sets `x-amz-copy-source-version-id`, the version a copy read, if there's one
/// to report.
fn with_copy_source_version_id(
    mut resp: Response<Full<Bytes>>,
    version_id: Option<&str>,
) -> Response<Full<Bytes>> {
    if let Some(v) = version_id {
        resp.headers_mut().insert(
            "x-amz-copy-source-version-id",
            HeaderValue::from_str(v).unwrap(),
        );
    }
    resp
}

/// Parses an `x-amz-copy-source` value ("/bucket/key" or "bucket/key", optionally
/// with a "?versionId=…" suffix, percent-encoded) into (bucket, key, version ID).
/// Strips a leading slash and splits off the query, then splits bucket/key at the
/// first slash and decodes each half — mirroring how the request path is parsed.
/// Returns None if malformed (no key separator, or an empty component).
pub(crate) fn parse_copy_source(copy_source: &str) -> Option<(String, String, Option<String>)> {
    let raw = copy_source.trim_start_matches('/');
    let (raw, query) = raw.split_once('?').unwrap_or((raw, ""));
    let version_id = query_param(query, "versionId");
    let (bucket, key) = raw.split_once('/')?;
    let (bucket, key) = (decode_path_param(bucket), decode_path_param(key));
    if bucket.is_empty() || key.is_empty() {
        return None;
    }
    Some((bucket, key, version_id))
}
