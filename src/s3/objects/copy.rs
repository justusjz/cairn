use std::sync::Arc;

use deadpool_postgres::GenericClient;
use http_body_util::{BodyExt, Full};
use hyper::{Response, StatusCode, body::Bytes, header::HeaderValue};
use md5::{Digest, Md5};
use tokio_postgres::IsolationLevel;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::db::Cached;
use crate::{
    App, AttachTarget, Contended, Sealing, UploadResult,
    blobs::{reap_blobs, reap_columns},
    body::channel_body,
    db,
    encryption::Key,
    payload::Payload,
    s3::{
        conditional::{Precondition, Preconditions},
        checksums::{self, Algorithm, Checksum, ChecksumKey, Storing, Type},
        multipart::upload,
        sse::{self, Stored, Wanted},
        sse_c::CustomerKey,
        objects::get::{
            Missing, ObjectVersion, PartLocation, lookup_version, no_such_version,
            resolve_object_parts, select_parts_in_range, spawn_range_stream,
        },
        util::{
            MAX_UPLOAD, decode_path_param, format_s3_error, is_well_formed, query_param,
            with_version_id, xml_ok,
        },
        versions::{invalid_version_id, is_version_id, new_version_id},
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
    size: i64,
    etag: String,
    crc64nvme: Option<i64>,
    /// Its plaintext's size, if it's encrypted.
    plain_size: Option<i64>,
    /// Its checksum, as it's stored (in its object's algorithm).
    checksum: Option<String>,
}

impl SourcePart {
    /// What it contributes to its object.
    fn object_size(&self) -> u64 {
        self.plain_size.unwrap_or(self.size) as u64
    }
}

/// The version a copy reads: its metadata, its parts, and where to read them
/// from, should the copy have to hash some of the data.
struct Source {
    version: ObjectVersion,
    parts: Vec<SourcePart>,
    locations: Vec<PartLocation>,
}

/// The keys of a CopyObject: its source's SSE-C key (from the
/// `x-amz-copy-source-server-side-encryption-customer-*` headers), if it's
/// SSE-C, and how its destination is to be encrypted.
#[derive(Clone, Copy, Default)]
pub struct CopyKeys<'a> {
    pub source: Option<&'a CustomerKey>,
    pub dest: Wanted<'a>,
    /// Who the KMS is asked as, for SSE-KMS (see `kms`).
    pub role: Option<Uuid>,
    /// The algorithm of the checksum it asks for (`x-amz-checksum-algorithm`).
    pub checksum: Option<Algorithm>,
}

impl CopyKeys<'_> {
    /// Whether the destination can share the bytes of a source encrypted as
    /// `source` is: both are plain, or SSE-C with the same key, or both SSE-KMS
    /// (under any key: the copy seals the same object key under a data key of
    /// its own), or both SSE-S3. Otherwise the data is decrypted and encrypted
    /// again: so is a copy between SSE-KMS and SSE-S3, whose ETags differ (an
    /// SSE-S3 object's is its content's MD5, which this works out).
    fn shares(&self, source: &Stored) -> bool {
        match (source, self.dest) {
            (Stored::Plain, Wanted::Plain) | (Stored::Kms(_), Wanted::Kms(_)) | (Stored::S3(_), Wanted::S3) => true,
            (Stored::Customer { .. }, Wanted::Customer(dest)) => {
                self.source.is_some_and(|source| source.key() == dest.key())
            }
            _ => false,
        }
    }

    /// Whether a copy of a source encrypted as `source` onto itself leaves its
    /// encryption as it is: plain, or SSE-C with the same key. An SSE-KMS
    /// destination never does: it's a new object with keys of its own, as in
    /// MinIO.
    fn keeps(&self, source: &Stored) -> bool {
        match (source, self.dest) {
            (Stored::Plain, Wanted::Plain) => true,
            (Stored::Customer { .. }, Wanted::Customer(_)) => self.shares(source),
            _ => false,
        }
    }
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
/// An SSE-C source needs its key (`keys.source`). The copy shares its bytes
/// if it's encrypted with the same key, or both are plain, or both SSE-KMS
/// (see `CopyKeys::shares`); then an encrypted copy's ETag is the source's (an
/// MD5 of the data would give it away). Otherwise the data is read, decrypted,
/// and written again, encrypted as `keys.dest` asks.
///
/// `metadata_directive` is `x-amz-metadata-directive` (COPY, the default, or
/// REPLACE). Under COPY the destination inherits the source's content-type and
/// metadata; under REPLACE it takes `request_content_type` and
/// `request_metadata` (the request's own Content-Type and metadata).
#[allow(clippy::too_many_arguments)]
pub async fn copy_object(
    app: &Arc<App>,
    dest_bucket: &str,
    dest_key: &str,
    copy_source: &str,
    metadata_directive: Option<&str>,
    request_content_type: &str,
    request_metadata: &str,
    preconditions: &Preconditions,
    keys: CopyKeys<'_>,
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
    if let Some(v) = src_version.as_deref().filter(|v| !is_version_id(v)) {
        return Ok(invalid_version_id("versionId", v));
    }

    let replace = replaces_metadata(metadata_directive);
    // S3 rejects a copy of an object onto itself that changes nothing, guarding
    // against a client accidentally issuing a destructive no-op. Copying a named
    // version onto its own key is allowed: that's how an old version is restored.
    // So is changing its encryption (another key, or none), which is only
    // known once the source is read: a request without encryption headers
    // decrypts an SSE-KMS source.
    let same_object = src_bucket == dest_bucket && src_key == dest_key && src_version.is_none();
    let client = app.pool.get().await?;
    if client
        .query_opt_cached("SELECT 1 FROM buckets WHERE name = $1", &[&dest_bucket])
        .await?
        .is_none()
    {
        return Ok(no_such_bucket());
    }
    drop(client);

    for _ in 0..MAX_SOURCE_ATTEMPTS {
        let source = match read_source(app, &src_bucket, &src_key, src_version.as_deref()).await? {
            Ok(source) => source,
            Err(missing) => return Ok(missing),
        };
        // An SSE-C source only with its key; before the conditions, which would
        // tell about it otherwise.
        let encryption = &source.version.encryption;
        if let Err(refused) = sse::check(encryption, keys.source) {
            return Ok(refused);
        }
        if same_object && !replace && keys.keeps(encryption) {
            return Ok(format_s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "this copy request is illegal because it is trying to copy an object to \
                 itself without changing the object's metadata",
            ));
        }
        // Honour x-amz-copy-source-if-* conditions on the source; any failure (a
        // 304 for a read maps to 412 here) aborts the copy. Against its ETag as
        // clients know it (an SSE-S3 one's is stored sealed).
        let version = &source.version;
        let source_etag = match sse::plain_etag(app, encryption, &version.etag, &src_bucket, &src_key).await? {
            Ok(etag) => etag,
            Err(refused) => return Ok(refused),
        };
        if preconditions.evaluate(&source_etag, version.lm_epoch, true) != Precondition::Proceed {
            return Ok(copy_precondition_failed());
        }
        // As in S3: a larger object is copied part by part (UploadPartCopy).
        if version.size as u64 > MAX_UPLOAD {
            return Ok(format_s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                &format!(
                    "The specified copy source is larger than the maximum allowable size for a \
                     copy source: {MAX_UPLOAD}"
                ),
            ));
        }
        let (content_type, metadata) = if replace {
            (request_content_type, request_metadata)
        } else {
            (version.content_type.as_str(), version.metadata.as_str())
        };
        let respond = |etag: &str, checksum: Option<&Checksum>, version_id: Option<&str>, last_modified: &str, stored: &Stored| {
            let checksum = checksum.map_or(String::new(), Checksum::xml);
            let resp = with_version_id(
                xml_ok(format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <CopyObjectResult>\
                     <LastModified>{last_modified}</LastModified>\
                     <ETag>\"{etag}\"</ETag>{checksum}\
                     </CopyObjectResult>"
                )),
                version_id,
            );
            let resp = with_copy_source_version_id(resp, source.version.version_id.as_deref());
            sse::echo_onto(resp, stored, keys.dest.customer())
        };
        // The key the source is encrypted with, if it is.
        let source_key = match sse::open(app, encryption, keys.source, keys.role, &src_bucket, &src_key).await? {
            Ok(key) => key,
            Err(refused) => return Ok(refused),
        };
        // The copy's checksum: of the algorithm it asks for, else its
        // source's, else S3's default; always FULL_OBJECT, as the copy isn't
        // multipart (a COMPOSITE source's is worked out again, as MinIO does).
        let checksum_algorithm = keys
            .checksum
            .or(version.checksum.as_ref().map(|checksum| checksum.algorithm))
            .unwrap_or(Algorithm::Crc64Nvme);
        if !keys.shares(encryption) {
            let dest = Dest { bucket: dest_bucket, key: dest_key, content_type, metadata, checksum: checksum_algorithm };
            let sealing = match sse::seal(app, keys.dest, keys.role, dest_bucket, dest_key).await? {
                Ok(sealing) => sealing,
                Err(refused) => return Ok(refused),
            };
            let stored = sealing.as_ref().map_or(Stored::Plain, |sealing| sealing.stored.clone());
            match stream_object_copy(app, &source, &dest, source_key, sealing).await {
                Ok(Some((etag, checksum, version_id, last_modified))) => {
                    return Ok(respond(&etag, checksum.as_ref(), version_id.as_deref(), &last_modified, &stored));
                }
                Ok(None) => return Ok(no_such_bucket()),
                // Its data went with it: copy what it is now.
                Err(_) if source.changed(app).await? => continue,
                Err(e) => return Err(e),
            }
        }
        // The copy's ETag, as clients know it, and as it's stored (an SSE-S3
        // one's sealed, under the object key the copy shares).
        let (etag, stored_etag) = match source.parts.as_slice() {
            _ if !encryption.is_plain() => (source_etag.clone(), version.etag.clone()),
            [part] => (part.etag.clone(), part.etag.clone()),
            _ => {
                let size = version.size as u64;
                match hash_range(app, source.locations.clone(), 0, size, Hashing::default()).await {
                    Ok(hashes) => {
                        let md5 = hashes.md5.expect("asked for");
                        (md5.clone(), md5)
                    }
                    // Its data went with it: copy what it is now.
                    Err(_) if source.changed(app).await? => continue,
                    Err(e) => return Err(e),
                }
            }
        };
        // The copy's own record of the same key: a check of the client's, or
        // the object key sealed under a data key for the copy.
        let stored = match (keys.dest, &source_key) {
            (Wanted::Plain, _) => Stored::Plain,
            (Wanted::Customer(dest), _) => Stored::Customer { check: dest.new_check() },
            (Wanted::Kms(request), Some(object_key)) => {
                match sse::reseal(app, object_key, request, keys.role, dest_bucket, dest_key).await? {
                    Ok(envelope) => Stored::Kms(envelope),
                    Err(refused) => return Ok(refused),
                }
            }
            (Wanted::S3, Some(object_key)) => {
                match sse::reseal_s3(app, object_key, dest_bucket, dest_key).await? {
                    Ok(envelope) => Stored::S3(envelope),
                    Err(refused) => return Ok(refused),
                }
            }
            (Wanted::Kms(_) | Wanted::S3, None) => {
                unreachable!("an SSE-KMS or SSE-S3 copy shares only an encrypted source's parts")
            }
        };
        // Its checksum, under the key it shares with its source, if it's
        // encrypted.
        let copied = match copy_checksum(app, &source, checksum_algorithm, source_key.as_deref()).await {
            Ok(copied) => copied,
            // Its data went with it: copy what it is now.
            Err(_) if source.changed(app).await? => continue,
            Err(e) => return Err(e),
        };
        // CopyObject reports the new version's last-modified time in the body
        // (not just the ETag header). It comes from the commit itself: read
        // afterwards, a concurrent write to the key could have replaced the
        // version already.
        let dest = Dest { bucket: dest_bucket, key: dest_key, content_type, metadata, checksum: checksum_algorithm };
        let (version_id, last_modified) =
            match commit_object_copy(app, &source, &dest, &stored_etag, &stored, &copied).await? {
                ObjectCopy::Committed { version_id, last_modified } => (version_id, last_modified),
                ObjectCopy::SourceChanged => continue, // copy what it is now
                ObjectCopy::NoSuchBucket => return Ok(no_such_bucket()),
            };
        return Ok(respond(&etag, Some(&copied.checksum), version_id.as_deref(), &last_modified, &stored));
    }
    Err(Contended("the copy source kept changing".to_owned()).into())
}

/// Whether a copy's `x-amz-metadata-directive` has it take the request's
/// metadata (REPLACE), rather than keep the source's (COPY, the default).
pub fn replaces_metadata(metadata_directive: Option<&str>) -> bool {
    metadata_directive.is_some_and(|d| d.eq_ignore_ascii_case("REPLACE"))
}

/// Where a CopyObject writes, and what its new version is to have.
struct Dest<'a> {
    bucket: &'a str,
    key: &'a str,
    content_type: &'a str,
    metadata: &'a str,
    /// The algorithm of its checksum (FULL_OBJECT).
    checksum: Algorithm,
}

/// The checksum of a copy that shares its source's parts, as it's stored, and
/// whether its parts keep theirs (they're of its algorithm).
struct Copied {
    checksum: Checksum,
    stored: String,
    part_checksums: bool,
}

/// Works out the checksum of a copy of `source` that shares its parts (and
/// its key, `object_key`, if it's encrypted), of `algorithm`: the source's,
/// if it's a FULL_OBJECT one of it; combined from its parts', if they have
/// CRCs of it (a COMPOSITE one's, or a plain one's own CRC64NVME); else from
/// its data, read.
async fn copy_checksum(
    app: &Arc<App>,
    source: &Source,
    algorithm: Algorithm,
    object_key: Option<&Key>,
) -> anyhow::Result<Copied> {
    let checksum_key = object_key.map(ChecksumKey::new);
    let storing = match &checksum_key {
        Some(checksum_key) => Storing::Sealed(checksum_key),
        None => Storing::Plain,
    };
    let same = source.version.checksum.as_ref().filter(|checksum| checksum.algorithm == algorithm);
    if let Some(checksum) = same.filter(|checksum| checksum.kind == Type::FullObject) {
        return Ok(Copied { checksum: checksum.read(&storing)?, stored: checksum.stored.clone(), part_checksums: true });
    }
    let combined = |raws: Vec<Vec<u8>>| {
        let pieces = raws.iter().zip(&source.parts).map(|(raw, part)| (raw.as_slice(), part.object_size()));
        Checksum::full(algorithm, &checksums::combine_all(algorithm, pieces))
    };
    let checksum = if same.is_some() && algorithm.combines() && source.parts.iter().all(|p| p.checksum.is_some()) {
        let mut raws = Vec::with_capacity(source.parts.len());
        for part in &source.parts {
            let value = storing.read(part.checksum.as_deref().expect("checked"))?;
            raws.push(algorithm.decode(&value).ok_or_else(|| anyhow::anyhow!("a stored checksum isn't one"))?);
        }
        combined(raws)
    } else if algorithm == Algorithm::Crc64Nvme
        && object_key.is_none()
        && source.parts.iter().all(|p| p.crc64nvme.is_some())
    {
        combined(source.parts.iter().map(|p| (p.crc64nvme.expect("checked") as u64).to_be_bytes().to_vec()).collect())
    } else {
        let size = source.version.size as u64;
        let hashing = Hashing { md5: false, checksum: Some(algorithm), key: object_key };
        let hashes = hash_range(app, source.locations.clone(), 0, size, hashing).await?;
        Checksum::full(algorithm, &hashes.checksum.expect("asked for"))
    };
    let stored = storing.store(&checksum.value);
    Ok(Copied { checksum, stored, part_checksums: same.is_some() })
}

/// Copies `source` to `dest` as data, through the normal upload path: read
/// (and decrypted with `source_key`) like a GET, and written (encrypted as
/// `sealing` says) like a PUT, which works out the ETag as it streams. For a
/// copy that can't share the source's bytes. The new version's ETag, version
/// ID to report and last-modified time, or `None` if the bucket is gone.
async fn stream_object_copy(
    app: &Arc<App>,
    source: &Source,
    dest: &Dest<'_>,
    source_key: Option<Zeroizing<Key>>,
    sealing: Option<Sealing>,
) -> anyhow::Result<Option<(String, Option<Checksum>, Option<String>, String)>> {
    let (sender, body) = channel_body();
    let size = source.version.size as u64;
    let slices = select_parts_in_range(source.locations.clone(), 0, size, source_key.as_deref());
    spawn_range_stream(app.clone(), slices, sender);
    let attach = AttachTarget::Object {
        bucket: dest.bucket.to_owned(),
        key: dest.key.to_owned(),
        content_type: dest.content_type.to_owned(),
        metadata: dest.metadata.to_owned(),
        conditions: Preconditions::default(),
        sealing,
        checksum: checksums::Wanted::Exactly(dest.checksum),
    };
    // The source stream is data from within Cairn (verified as it's read), so
    // there's nothing to check it against.
    match crate::upload_part(app, body, &attach, Payload::unchecked()).await? {
        UploadResult::Committed { etag, checksum, version_id, last_modified, .. } => Ok(Some((
            etag,
            checksum,
            version_id,
            last_modified.expect("an object write reports its last-modified time"),
        ))),
        UploadResult::NoSuchBucket => Ok(None),
        // Nothing is checked, there are no conditions, and an object has no upload.
        UploadResult::Rejected(_)
        | UploadResult::Refused(_)
        | UploadResult::PreconditionFailed
        | UploadResult::NoSuchKey
        | UploadResult::NoSuchUpload => {
            unreachable!(
                "an unchecked, unconditional object write only commits, or finds no bucket"
            )
        }
    }
}

enum ObjectCopy {
    /// Committed, with the version ID to report, and the new version's
    /// last-modified time in ISO 8601.
    Committed {
        version_id: Option<String>,
        last_modified: String,
    },
    /// The source changed since it was read.
    SourceChanged,
    /// The destination bucket was deleted meanwhile.
    NoSuchBucket,
}

/// The transaction that makes a copy of `source` at `bucket`/`key`: a new
/// version with parts on the source's bytes.
async fn commit_object_copy(
    app: &Arc<App>,
    source: &Source,
    dest: &Dest<'_>,
    etag: &str,
    stored: &Stored,
    copied: &Copied,
) -> anyhow::Result<ObjectCopy> {
    let (part_ids, part_sizes) = source.part_keys();
    let sse = stored.columns();
    let client = app.pool.get().await?;
    for attempt in 0..db::MAX_TX_ATTEMPTS {
        db::backoff(attempt).await;
        let result: Result<_, tokio_postgres::Error> = async {
            let row = client
                .query_one_cached(
                    "SELECT status, version_id, last_modified, reap_blob, reap_node, reap_peer
                     FROM pg_temp.cairn_copy_object($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                                                    $12, $13, $14, $15, $16, $17, $18, $19, $20)",
                    &[
                        &source.version.id,
                        &part_ids,
                        &part_sizes,
                        &dest.bucket,
                        &dest.key,
                        &source.version.size,
                        &etag,
                        &dest.content_type,
                        &dest.metadata,
                        &sse.sse_c_key,
                        &sse.kms_key_id,
                        &sse.kms_data_key,
                        &sse.kms_sealed,
                        &sse.kms_context,
                        &sse.sse_s3,
                        &copied.checksum.algorithm.name(),
                        &copied.checksum.kind.name(),
                        &copied.stored,
                        &copied.part_checksums,
                        &new_version_id(),
                    ],
                )
                .await?;
            // On anything but a commit, the function changed nothing.
            match row.get::<_, &str>(0) {
                "committed" => {}
                "source_changed" => return Ok((ObjectCopy::SourceChanged, Vec::new())),
                "no_such_bucket" => return Ok((ObjectCopy::NoSuchBucket, Vec::new())),
                status => unreachable!("cairn_copy_object: unknown status {status}"),
            }
            let reap = reap_columns(&row, 3);
            let committed = ObjectCopy::Committed {
                version_id: row.get(1),
                last_modified: row.get(2),
            };
            Ok((committed, reap))
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
///
/// So is any range of an encrypted source (an SSE-C one needs its key,
/// `source_key`), or into an encrypted upload (an SSE-C one needs its key,
/// `dest_key`, as an UploadPart does): a range of ciphertext isn't a part of
/// its own.
#[allow(clippy::too_many_arguments)]
pub async fn copy_part(
    app: &Arc<App>,
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: &str,
    copy_source: &str,
    copy_source_range: Option<&str>,
    preconditions: &Preconditions,
    source_key: Option<&CustomerKey>,
    dest_key: Option<&CustomerKey>,
    role: Option<Uuid>,
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
    if let Some(v) = src_version.as_deref().filter(|v| !is_version_id(v)) {
        return Ok(invalid_version_id("versionId", v));
    }

    // Reject up front if the upload is gone, and require it to belong to the
    // request's bucket/key, and its key if it's SSE-C — as put_part does.
    let Some(upload) = upload(app, &upload_id, bucket, key).await? else {
        return Ok(no_such_upload());
    };
    let upload_encryption = upload.encryption.clone();
    // The new part's checksum is of its upload's algorithm (see `Upload`).
    let part_checksum = match upload.part_checksum() {
        checksums::Wanted::Exactly(algorithm) => Some(algorithm),
        _ => None,
    };
    if let Err(refused) = sse::check(&upload_encryption, dest_key) {
        return Ok(refused);
    }

    for _ in 0..MAX_SOURCE_ATTEMPTS {
        let source = match read_source(app, &src_bucket, &src_key, src_version.as_deref()).await? {
            Ok(source) => source,
            Err(missing) => return Ok(missing),
        };
        if let Err(refused) = sse::check(&source.version.encryption, source_key) {
            return Ok(refused);
        }
        let version = &source.version;
        // Honour x-amz-copy-source-if-* conditions on the source before copying,
        // against its ETag as clients know it.
        let source_etag =
            match sse::plain_etag(app, &version.encryption, &version.etag, &src_bucket, &src_key).await? {
                Ok(etag) => etag,
                Err(refused) => return Ok(refused),
            };
        if preconditions.evaluate(&source_etag, version.lm_epoch, true) != Precondition::Proceed {
            return Ok(copy_precondition_failed());
        }
        // Resolve the copy range against the source size (absent header → whole
        // object).
        let size = version.size as u64;
        let (start, end) = match copy_source_range.map(|range| parse_copy_range(range, size)) {
            None => (0, size),
            Some(Ok(range)) => range,
            Some(Err(refused)) => return Ok(refused),
        };
        if end - start > MAX_UPLOAD {
            return Ok(format_s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                &format!("The specified copy range is larger than the maximum part size: {MAX_UPLOAD}"),
            ));
        }
        // The part's checksum is told for an upload of an algorithm (S3: "if
        // the multipart upload request was created with" it).
        let respond = |etag: &str, checksum: Option<&Checksum>| {
            let checksum = match (checksum, upload.checksum) {
                (Some(checksum), Some(_)) => {
                    let element = checksum.algorithm.element();
                    format!("<{element}>{}</{element}>", checksum.value)
                }
                _ => String::new(),
            };
            let resp = xml_ok(format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                 <CopyPartResult>\
                 <LastModified>{}</LastModified>\
                 <ETag>\"{etag}\"</ETag>{checksum}\
                 </CopyPartResult>",
                version.last_modified_iso
            ));
            let resp = with_copy_source_version_id(resp, version.version_id.as_deref());
            sse::echo_onto(resp, &upload_encryption, dest_key)
        };
        let encrypted = !version.encryption.is_plain() || !upload_encryption.is_plain();
        let holding = part_holding(&source.parts, start, end).filter(|_| !encrypted);
        let Some((index, within)) = holding else {
            let keys = match stream_keys(app, &source, source_key, &src_bucket, &src_key, &upload_encryption, dest_key, role, bucket, key).await? {
                Ok(keys) => keys,
                Err(refused) => return Ok(refused),
            };
            return Ok(
                match stream_part_copy(app, &source, start, end, upload_id, part_number, keys, upload.part_checksum()).await {
                    Ok(Some((etag, checksum))) => respond(&etag, checksum.as_ref()),
                    Ok(None) => no_such_upload(),
                    // Its data went with it: copy what it is now.
                    Err(_) if source.changed(app).await? => continue,
                    Err(e) => return Err(e),
                },
            );
        };
        let part = &source.parts[index];
        let length = (end - start) as i64;
        let whole = within == 0 && length == part.size;
        // A whole part's checksum may be had without reading it: its own
        // (of its object's algorithm; a single PUT's is its object's), or its
        // CRC64NVME. Both plain: the source is.
        let known = part_checksum.filter(|_| whole).and_then(|algorithm| {
            let object = version.checksum.as_ref().filter(|c| c.algorithm == algorithm);
            let value = match object {
                Some(_) if part.checksum.is_some() => part.checksum.clone(),
                Some(c) if source.parts.len() == 1 && c.kind == Type::FullObject => Some(c.stored.clone()),
                _ if algorithm == Algorithm::Crc64Nvme => {
                    part.crc64nvme.map(|crc| checksums::encode(&(crc as u64).to_be_bytes()))
                }
                _ => None,
            };
            value.map(|value| Checksum { algorithm, kind: Type::FullObject, value })
        });
        let (etag, crc, checksum) = if whole && (part_checksum.is_none() || known.is_some()) {
            (part.etag.clone(), part.crc64nvme, known)
        } else {
            let hashing = Hashing { md5: !whole, checksum: part_checksum, key: None };
            let hashes = match hash_range(app, source.locations.clone(), start, end, hashing).await {
                Ok(hashes) => hashes,
                // Its data went with it: copy what it is now.
                Err(_) if source.changed(app).await? => continue,
                Err(e) => return Err(e),
            };
            let etag = hashes.md5.unwrap_or_else(|| part.etag.clone());
            let checksum = part_checksum.zip(hashes.checksum).map(|(a, raw)| Checksum::full(a, &raw));
            (etag, Some(hashes.crc64nvme as i64), checksum)
        };
        let new_part = NewPart {
            index,
            within: within as i64,
            length,
            etag: &etag,
            crc,
            checksum: checksum.as_ref().map(|checksum| checksum.value.as_str()),
        };
        match commit_part_copy(app, &source, &new_part, upload_id, part_number).await? {
            PartCopy::Committed => return Ok(respond(&etag, checksum.as_ref())),
            PartCopy::NoSuchUpload => return Ok(no_such_upload()),
            PartCopy::SourceChanged => continue,
        }
    }
    Err(Contended("the copy source kept changing".to_owned()).into())
}

/// An UploadPartCopy's `x-amz-copy-source-range` of a source of `size` bytes,
/// as a half-open range. Stricter than a GET's Range, as in S3: exactly
/// `bytes=first-last` (400 InvalidArgument otherwise), within the source (416
/// InvalidRange otherwise).
fn parse_copy_range(range: &str, size: u64) -> Result<(u64, u64), Response<Full<Bytes>>> {
    let malformed = || {
        format_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "The x-amz-copy-source-range value must be of the form bytes=first-last where \
             first and last are the zero-based offsets of the first and last bytes to copy",
        )
    };
    let number = |s: &str| {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse::<u64>().ok())
            .flatten()
    };
    let (first, last) = range
        .trim()
        .strip_prefix("bytes=")
        .and_then(|r| r.split_once('-'))
        .and_then(|(first, last)| Some((number(first)?, number(last)?)))
        .filter(|(first, last)| first <= last)
        .ok_or_else(malformed)?;
    if last >= size {
        return Err(format_s3_error(
            StatusCode::RANGE_NOT_SATISFIABLE,
            "InvalidRange",
            "The requested range is not satisfiable",
        ));
    }
    Ok((first, last + 1))
}

/// The part an UploadPartCopy stages: a range of one part of the source.
struct NewPart<'a> {
    /// Which part of the source, and where in it.
    index: usize,
    within: i64,
    length: i64,
    etag: &'a str,
    crc: Option<i64>,
    /// Its checksum (plain: so is the upload).
    checksum: Option<&'a str>,
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
    let (part_ids, part_sizes) = source.part_keys();
    // The function's part index counts from 1.
    let index = new_part.index as i32 + 1;
    let client = app.pool.get().await?;
    for attempt in 0..db::MAX_TX_ATTEMPTS {
        db::backoff(attempt).await;
        let result: Result<_, tokio_postgres::Error> = async {
            let row = client
                .query_one_cached(
                    "SELECT status, reap_blob, reap_node, reap_peer
                     FROM pg_temp.cairn_copy_part($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
                    &[
                        &source.version.id,
                        &part_ids,
                        &part_sizes,
                        &index,
                        &new_part.within,
                        &new_part.length,
                        &new_part.etag,
                        &new_part.crc,
                        &upload_id,
                        &part_number,
                        &new_part.checksum,
                    ],
                )
                .await?;
            // On anything but a commit, the function changed nothing.
            let outcome = match row.get::<_, &str>(0) {
                "committed" => PartCopy::Committed,
                "source_changed" => return Ok((PartCopy::SourceChanged, Vec::new())),
                "no_such_upload" => return Ok((PartCopy::NoSuchUpload, Vec::new())),
                status => unreachable!("cairn_copy_part: unknown status {status}"),
            };
            let reap = reap_columns(&row, 1);
            Ok((outcome, reap))
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
/// part's ETag as it streams): decrypted with the source's key and encrypted
/// with the upload's (`keys`), if they're encrypted. For a range over several
/// parts of the source, or of or into an encrypted one. `None` if the upload
/// was completed or aborted meanwhile.
#[allow(clippy::too_many_arguments)]
async fn stream_part_copy(
    app: &Arc<App>,
    source: &Source,
    start: u64,
    end: u64,
    upload_id: Uuid,
    part_number: i32,
    keys: StreamKeys,
    checksum: checksums::Wanted,
) -> anyhow::Result<Option<(String, Option<Checksum>)>> {
    let (sender, source_body) = channel_body();
    let slices = select_parts_in_range(source.locations.clone(), start, end, keys.source.as_deref());
    spawn_range_stream(app.clone(), slices, sender);
    let attach = AttachTarget::MultipartPart {
        upload_id,
        part_number,
        key: keys.dest,
        sse_s3: keys.dest_s3,
        checksum,
    };
    // The source stream is data from within Cairn (verified against its block
    // checksums as it's read), so there's nothing to check it against.
    match crate::upload_part(app, source_body, &attach, Payload::unchecked()).await? {
        UploadResult::Committed { etag, checksum, .. } => Ok(Some((etag, checksum))),
        UploadResult::NoSuchUpload => Ok(None),
        // Nothing is checked, there are no conditions, and a part has no bucket
        // to check.
        UploadResult::Rejected(_)
        | UploadResult::Refused(_)
        | UploadResult::PreconditionFailed
        | UploadResult::NoSuchKey
        | UploadResult::NoSuchBucket => {
            unreachable!("an unchecked part upload only commits, or finds its upload gone")
        }
    }
}

/// The keys an UploadPartCopy streams with: its source's, and its upload's.
struct StreamKeys {
    source: Option<Zeroizing<Key>>,
    dest: Option<Zeroizing<Key>>,
    /// Whether the upload is SSE-S3 (whose parts' ETags are sealed MD5s).
    dest_s3: bool,
}

/// The keys of an UploadPartCopy's source (`source_key` being the SSE-C key
/// the request gave for it) and of its upload (`dest_key` likewise), both
/// `check`ed already. Asks the KMS for SSE-KMS ones.
#[allow(clippy::too_many_arguments)]
async fn stream_keys(
    app: &App,
    source: &Source,
    source_key: Option<&CustomerKey>,
    src_bucket: &str,
    src_key: &str,
    upload: &Stored,
    dest_key: Option<&CustomerKey>,
    role: Option<Uuid>,
    bucket: &str,
    key: &str,
) -> anyhow::Result<Result<StreamKeys, Response<Full<Bytes>>>> {
    let source = match sse::open(app, &source.version.encryption, source_key, role, src_bucket, src_key).await? {
        Ok(key) => key,
        Err(refused) => return Ok(Err(refused)),
    };
    let dest = match sse::open(app, upload, dest_key, role, bucket, key).await? {
        Ok(key) => key,
        Err(refused) => return Ok(Err(refused)),
    };
    Ok(Ok(StreamKeys { source, dest, dest_s3: matches!(upload, Stored::S3(_)) }))
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

impl Source {
    /// The ids and sizes of the source's parts, in order, by which a copy's
    /// commit tells whether they're still the same (see `cairn_source_parts`).
    fn part_keys(&self) -> (Vec<i64>, Vec<i64>) {
        self.parts.iter().map(|p| (p.id, p.size)).unzip()
    }

    /// Whether the source version has been replaced or deleted since it was
    /// read (its parts aren't the same anymore). Its bytes may be gone then,
    /// so a failure to read them is a reason to start over, not an error.
    async fn changed(&self, app: &App) -> anyhow::Result<bool> {
        let client = app.pool.get().await?;
        let now = source_parts(&client, self.version.id).await?;
        let same = now.len() == self.parts.len()
            && now.iter().zip(&self.parts).all(|(a, b)| a.id == b.id && a.size == b.size);
        Ok(!same)
    }
}

/// The parts of the object version with row id `object_id`, in order.
async fn source_parts<C: GenericClient>(
    client: &C,
    object_id: i64,
) -> Result<Vec<SourcePart>, tokio_postgres::Error> {
    let rows = client
        .query_cached(
            "SELECT id, size, etag, crc64nvme, plain_size, checksum FROM parts
             WHERE object_id = $1 ORDER BY part_number",
            &[&object_id],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| SourcePart {
            id: r.get(0),
            size: r.get(1),
            etag: r.get(2),
            crc64nvme: r.get(3),
            plain_size: r.get(4),
            checksum: r.get(5),
        })
        .collect())
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

/// What `hash_range` works out: the MD5 (for an ETag), and a checksum of an
/// algorithm, of data decrypted with `key`, if it's encrypted. CRC64/NVME
/// always (a part's own).
struct Hashing<'a> {
    md5: bool,
    checksum: Option<Algorithm>,
    key: Option<&'a Key>,
}

impl Default for Hashing<'_> {
    fn default() -> Self {
        Hashing { md5: true, checksum: None, key: None }
    }
}

/// What `hash_range` worked out: the MD5 in hex, the CRC64/NVME, and the
/// checksum (raw).
struct Hashes {
    md5: Option<String>,
    crc64nvme: u64,
    checksum: Option<Vec<u8>>,
}

/// Reads bytes [start, end) of an object (its `parts`), verified (and
/// decrypted) like a GET, and works out what a copy of them needs, and the
/// catalog doesn't have.
async fn hash_range(
    app: &Arc<App>,
    parts: Vec<PartLocation>,
    start: u64,
    end: u64,
    hashing: Hashing<'_>,
) -> anyhow::Result<Hashes> {
    let (sender, mut body) = channel_body();
    spawn_range_stream(app.clone(), select_parts_in_range(parts, start, end, hashing.key), sender);
    let mut md5 = hashing.md5.then(Md5::new);
    let mut crc = crc64fast_nvme::Digest::new();
    let mut checksum = hashing.checksum.map(checksums::Hasher::new);
    let mut read = 0;
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame?.into_data() {
            if let Some(md5) = &mut md5 {
                md5.update(&data);
            }
            if let Some(checksum) = &mut checksum {
                checksum.update(&data);
            }
            crc.write(&data);
            read += data.len() as u64;
        }
    }
    anyhow::ensure!(read == end - start, "the copy source was cut short");
    Ok(Hashes {
        md5: md5.map(|md5| md5.finalize().iter().map(|b| format!("{b:02x}")).collect()),
        crc64nvme: crc.sum64(),
        checksum: checksum.map(checksums::Hasher::finish),
    })
}

fn no_such_bucket() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::NOT_FOUND,
        "NoSuchBucket",
        "the specified bucket does not exist",
    )
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
    if let Some(v) = version_id.and_then(|v| HeaderValue::from_str(v).ok()) {
        resp.headers_mut().insert("x-amz-copy-source-version-id", v);
    }
    resp
}

/// Parses an `x-amz-copy-source` value ("/bucket/key" or "bucket/key", optionally
/// with a "?versionId=…" suffix, percent-encoded) into (bucket, key, version ID).
/// Strips a leading slash and splits off the query, then splits bucket/key at the
/// first slash and decodes each half — mirroring how the request path is parsed.
/// Returns None if malformed (no key separator, an empty component, or one that
/// isn't well-formed, see `is_well_formed`).
pub(crate) fn parse_copy_source(copy_source: &str) -> Option<(String, String, Option<String>)> {
    let raw = copy_source.trim_start_matches('/');
    let (raw, query) = raw.split_once('?').unwrap_or((raw, ""));
    let version_id = query_param(query, "versionId");
    let (bucket, key) = raw.split_once('/')?;
    if !is_well_formed(bucket) || !is_well_formed(key) || !is_well_formed(query) {
        return None;
    }
    let (bucket, key) = (decode_path_param(bucket), decode_path_param(key));
    if bucket.is_empty() || key.is_empty() {
        return None;
    }
    Some((bucket, key, version_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_ranges_are_strict() {
        assert_eq!(parse_copy_range("bytes=0-4", 5).unwrap(), (0, 5));
        assert_eq!(parse_copy_range("bytes=2-2", 5).unwrap(), (2, 3));
        for malformed in [
            "0-2",
            "bytes=0",
            "bytes=hello-world",
            "bytes=0-bar",
            "bytes=hello-",
            "bytes=0-2,3-5",
            "bytes=3-1",
            "bytes=-2",
        ] {
            let refused = parse_copy_range(malformed, 5).unwrap_err();
            assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "{malformed}");
        }
        assert_eq!(
            parse_copy_range("bytes=0-21", 5).unwrap_err().status(),
            StatusCode::RANGE_NOT_SATISFIABLE
        );
    }
}
