use std::sync::Arc;

use deadpool_postgres::Object;
use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use uuid::Uuid;
use zeroize::Zeroizing;

use std::collections::HashMap;

use md5::{Digest, Md5};

use crate::db::Cached;
use crate::{
    App,
    blobs::{ReapTarget, reap_blobs, reap_columns},
    db,
    s3::conditional::Preconditions,
    encryption::{Field, Key, Owner, Salt, Storing},
    s3::checksums::{self, Algorithm, Checksum, Type},
    s3::multipart::{Upload, checksum_columns, upload},
    s3::sse::{self, Stored},
    s3::sse_c::CustomerKey,
    s3::util::{format_s3_error, slow_down, with_version_id, xml_escape, xml_ok},
    s3::versions::{current_object, new_version_id},
};

enum CompleteOutcome {
    Done {
        bucket: String,
        key: String,
        etag: String,
        /// The object's checksum, if it has one.
        checksum: Option<Checksum>,
        /// Locations of the blobs freed by replacing the old version and by
        /// dropping the staged parts the client left out, to reap after commit.
        reap: Vec<ReapTarget>,
        /// The `x-amz-version-id` to report for the new version.
        version_id: Option<String>,
    },
    NoSuchUpload,
    InvalidPart,
    /// A part of a COMPOSITE upload is listed without its checksum: its
    /// number, as listed.
    MissingChecksum(Algorithm, i32),
    /// Its parts make an object larger than S3 stores.
    TooLarge,
    /// A part, not the last, is smaller than S3 takes.
    TooSmall,
    /// A conditional-completion guard (If-Match / If-None-Match) didn't hold.
    PreconditionFailed,
    /// An If-Match found no object to match.
    NoSuchKey,
    /// What it was decided on changed (a part, or the current object): to
    /// decide again.
    Stale,
    /// An ETag couldn't be had (its key from the KMS, say): the response.
    Refused(Response<Full<Bytes>>),
    /// The checksum it claims for the object isn't the object's.
    BadDigest(Algorithm),
}

/// The keys a completion may need: the client's, for an SSE-C upload's
/// checksums, and the role the KMS is asked as, for an SSE-KMS one's.
#[derive(Clone, Copy)]
struct Keys<'a> {
    customer: Option<&'a CustomerKey>,
    role: Option<Uuid>,
}

/// What a CompleteMultipartUpload asks for.
struct Request<'a> {
    listed: &'a Listed,
    claimed: &'a Claimed,
    preconditions: &'a Preconditions,
    /// The object's size, as `x-amz-mp-object-size` claims it.
    expected_size: Option<u64>,
}

/// The object size `x-amz-mp-object-size` claims, if it's there, or S3's
/// 400 for one that isn't a size (probed).
pub fn expected_size(headers: &hyper::HeaderMap) -> Result<Option<u64>, Response<Full<Bytes>>> {
    let Some(value) = headers.get("x-amz-mp-object-size") else { return Ok(None) };
    let text = String::from_utf8_lossy(value.as_bytes());
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let message = match text.strip_prefix('-') {
        _ if digits(&text) => match text.parse::<u64>() {
            Ok(size) => return Ok(Some(size)),
            Err(_) => format!("Value for x-amz-mp-object-size header is invalid: '{text}'"),
        },
        Some(rest) if digits(rest) => format!("Value for x-amz-mp-object-size header is less than zero: '{text}'"),
        _ => format!("Value for x-amz-mp-object-size header is invalid: '{text}'"),
    };
    Err(format_s3_error(StatusCode::BAD_REQUEST, "InvalidRequest", &message))
}

/// The parts a CompleteMultipartUpload lists: each one's number, ETag, and
/// the checksums listed with it.
struct Listed {
    numbers_and_etags: Vec<(i32, String)>,
    checksums: Vec<Vec<(Algorithm, String)>>,
}

/// What a CompleteMultipartUpload claims about its object's checksum (see
/// `checksums::claimed`).
pub type Claimed = Option<checksums::Claim>;

/// Parses a CompleteMultipartUpload body into its parts, namespace-
/// agnostically. Returns None on malformed XML.
fn parse_complete_request(body: &str) -> Option<Listed> {
    let doc = roxmltree::Document::parse(body).ok()?;
    let mut parts = Vec::new();
    let mut checksums = Vec::new();
    for part in doc.descendants().filter(|n| n.tag_name().name() == "Part") {
        let part_number: i32 = part
            .children()
            .find(|n| n.tag_name().name() == "PartNumber")
            .and_then(|n| n.text())?
            .trim()
            .parse()
            .ok()?;
        let etag = part
            .children()
            .find(|n| n.tag_name().name() == "ETag")
            .and_then(|n| n.text())?
            .trim()
            .trim_matches('"')
            .to_owned();
        parts.push((part_number, etag));
        checksums.push(
            Algorithm::ALL
                .into_iter()
                .filter_map(|algorithm| {
                    let element = algorithm.element();
                    let value = part.children().find(|n| n.tag_name().name() == element)?.text()?;
                    Some((algorithm, value.trim().to_owned()))
                })
                .collect(),
        );
    }
    Some(Listed { numbers_and_etags: parts, checksums })
}

/// CompleteMultipartUpload: `POST /{bucket}/{key}?uploadId=U` with a part-list
/// body. Assembles the listed parts into the object atomically. A retry of a
/// completion that went through (its response lost, say) is answered as it
/// was, as long as the version it made is still there.
#[allow(clippy::too_many_arguments)]
pub async fn complete_multipart_upload(
    app: &Arc<App>,
    bucket: &str,
    key: &str,
    upload_id: &str,
    body: Bytes,
    preconditions: &Preconditions,
    customer_key: Option<&CustomerKey>,
    role: Option<Uuid>,
    expected_size: Option<u64>,
    claimed: Claimed,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let upload_id = match Uuid::parse_str(upload_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(format_s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchUpload",
                "the specified multipart upload does not exist",
            ));
        }
    };
    let Ok(body_str) = std::str::from_utf8(&body) else {
        return Ok(format_s3_error(
            StatusCode::BAD_REQUEST,
            "MalformedXML",
            "request body is not valid UTF-8",
        ));
    };
    let listed = match parse_complete_request(body_str) {
        Some(listed) if !listed.numbers_and_etags.is_empty() => listed,
        _ => {
            return Ok(format_s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "could not parse the part list",
            ));
        }
    };
    let requested = &listed.numbers_and_etags;
    // S3 requires the parts in ascending (and thus distinct) part-number order.
    if !requested.windows(2).all(|w| w[0].0 < w[1].0) {
        return Ok(format_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidPartOrder",
            "parts must be listed in ascending part-number order",
        ));
    }

    // The object gets its upload's encryption; an SSE-C key isn't needed,
    // unless the upload has an algorithm, whose checksums are sealed under
    // it (S3 needs it then; MinIO's 400). One given must be the upload's (a
    // retry, whose upload is gone, isn't checked).
    let upload = upload(app, &upload_id, bucket, key).await?;
    if let Some(upload) = &upload {
        if matches!(upload.encryption, Stored::Customer { .. }) && upload.checksum.is_some() && customer_key.is_none() {
            return Ok(format_s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "Requests specifying Server Side Encryption with Customer provided keys must provide an \
                 appropriate secret key.",
            ));
        }
        if customer_key.is_some()
            && let Err(refused) = sse::check(&upload.encryption, customer_key, bucket, key)
        {
            return Ok(refused);
        }
    }
    let encryption = upload.as_ref().map(|upload| upload.encryption.clone());
    let keys = Keys { customer: customer_key, role };
    let mut client = app.pool.get().await?;
    for attempt in 0..db::MAX_TX_ATTEMPTS {
        db::backoff(attempt).await;
        let request = Request { listed: &listed, claimed: &claimed, preconditions, expected_size };
        let attempt = try_complete(app, &mut client, bucket, key, &upload_id, &request, upload.as_ref(), keys);
        match attempt.await {
            Ok(CompleteOutcome::Done {
                bucket,
                key,
                etag,
                checksum,
                reap,
                version_id,
            }) => {
                reap_blobs(app, reap);
                let body = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                     <Bucket>{}</Bucket><Key>{}</Key><ETag>\"{}\"</ETag>{}\
                     </CompleteMultipartUploadResult>",
                    xml_escape(&bucket),
                    xml_escape(&key),
                    xml_escape(&etag),
                    checksum.as_ref().map_or(String::new(), Checksum::xml),
                );
                let response = with_version_id(xml_ok(body), version_id.as_deref());
                // A retry's upload is gone, but its version tells.
                let encryption = match &encryption {
                    Some(encryption) => encryption.clone(),
                    None => completed_encryption(&client, &bucket, &key, &upload_id).await?,
                };
                return Ok(sse::echo_onto(response, &encryption, customer_key));
            }
            Ok(CompleteOutcome::NoSuchUpload) => {
                return Ok(format_s3_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchUpload",
                    "the specified multipart upload does not exist",
                ));
            }
            Ok(CompleteOutcome::InvalidPart) => {
                return Ok(format_s3_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidPart",
                    "One or more of the specified parts could not be found.  The part may not have been uploaded, or the specified entity tag may not match the part's entity tag.",
                ));
            }
            Ok(CompleteOutcome::MissingChecksum(algorithm, number)) => {
                return Ok(format_s3_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    &format!(
                        "The upload was created using a {} checksum. The complete request must include the \
                         checksum for each part. It was missing for part {number} in the request.",
                        algorithm.name().to_lowercase()
                    ),
                ));
            }
            Ok(CompleteOutcome::TooLarge) => {
                return Ok(format_s3_error(
                    StatusCode::BAD_REQUEST,
                    "EntityTooLarge",
                    &format!(
                        "Your proposed upload exceeds the maximum allowed object size ({} bytes).",
                        crate::s3::util::MAX_OBJECT
                    ),
                ));
            }
            Ok(CompleteOutcome::TooSmall) => {
                return Ok(format_s3_error(
                    StatusCode::BAD_REQUEST,
                    "EntityTooSmall",
                    &format!(
                        "Your proposed upload is smaller than the minimum allowed size: every part \
                         but the last must be at least {} bytes.",
                        crate::s3::util::MIN_PART
                    ),
                ));
            }
            Ok(CompleteOutcome::NoSuchKey) => {
                return Ok(format_s3_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchKey",
                    "the specified key does not exist",
                ));
            }
            Ok(CompleteOutcome::PreconditionFailed) => {
                return Ok(format_s3_error(
                    StatusCode::PRECONDITION_FAILED,
                    "PreconditionFailed",
                    "at least one of the preconditions you specified did not hold",
                ));
            }
            Ok(CompleteOutcome::BadDigest(algorithm)) => return Ok(checksums::bad_digest(algorithm)),
            Ok(CompleteOutcome::Stale) => continue,
            Ok(CompleteOutcome::Refused(refused)) => return Ok(refused),
            Err(e) if e.downcast_ref::<tokio_postgres::Error>().is_some_and(db::is_conflict) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(slow_down())
}

/// The ETag S3 gives a multipart object of the `listed` parts: the MD5 of
/// their ETags' bytes (each an MD5, or another 16 bytes in hex), then the part
/// count. `None` if one isn't 32 hex digits, so names no part.
fn combined_etag(listed: &[(i32, String)]) -> Option<String> {
    let mut md5 = Md5::new();
    for (_, etag) in listed {
        if etag.len() != 32 || !etag.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return None;
        }
        for i in (0..32).step_by(2) {
            md5.update([u8::from_str_radix(&etag[i..i + 2], 16).ok()?]);
        }
    }
    let hex: String = md5.finalize().iter().map(|b| format!("{b:02x}")).collect();
    Some(format!("{hex}-{}", listed.len()))
}

/// Whether the checksum a completion claims (if any) is `checksum`: of its
/// algorithm and type, and its value. S3's BadDigest otherwise.
fn check_claim(claimed: &Claimed, checksum: Option<&Checksum>) -> Option<CompleteOutcome> {
    let (algorithm, value, kind) = claimed.as_ref()?;
    let matches = checksum.is_some_and(|checksum| {
        checksum.algorithm == *algorithm
            && kind.is_none_or(|kind| kind == checksum.kind)
            && checksums::matches(checksum, value)
    });
    (!matches).then_some(CompleteOutcome::BadDigest(*algorithm))
}

/// The key the checksums of an object (or upload) encrypted as `stored` are
/// sealed under, its object key, if it's encrypted, or why it can't be had.
/// `None` too for an SSE-C one without its key given (whose checksums can't
/// be read).
async fn checksum_key(
    app: &App,
    stored: &Stored,
    keys: Keys<'_>,
    bucket: &str,
    key: &str,
) -> anyhow::Result<Result<Option<Zeroizing<Key>>, Response<Full<Bytes>>>> {
    if matches!(stored, Stored::Customer { .. }) && keys.customer.is_none() {
        return Ok(Ok(None));
    }
    sse::open(app, stored, keys.customer, keys.role, bucket, key).await
}

/// The completion a retry repeats, whose upload is gone: the version it made,
/// if that's still there and has the ETag the `combined` listed parts give,
/// answered as it was; or else, there's no such upload.
#[allow(clippy::too_many_arguments)]
async fn completed(
    app: &App,
    client: &Object,
    bucket: &str,
    key: &str,
    upload_id: &Uuid,
    combined: Option<&str>,
    claimed: &Claimed,
    keys: Keys<'_>,
) -> anyhow::Result<CompleteOutcome> {
    let Some(combined) = combined else { return Ok(CompleteOutcome::NoSuchUpload) };
    let row = client
        .query_opt_cached(
            "SELECT o.etag, o.version_id, b.versioning, o.sse_c_key, o.sse_kms_key_id,
                    o.sse_kms_data_key, o.sse_kms_sealed, o.sse_kms_context, o.sse_s3,
                    o.checksum_algorithm, o.checksum_type, o.checksum
             FROM objects o JOIN buckets b ON b.name = o.bucket
             WHERE o.bucket = $1 AND o.key = $2 AND o.upload_id = $3 LIMIT 1",
            &[&bucket, &key, upload_id],
        )
        .await?;
    let Some(row) = row else { return Ok(CompleteOutcome::NoSuchUpload) };
    let stored = Stored::from_row(&row, 3);
    let etag = match sse::plain_etag(app, &stored, row.get(0), bucket, key).await? {
        Ok(etag) => etag,
        Err(refused) => return Ok(CompleteOutcome::Refused(refused)),
    };
    if etag != combined {
        return Ok(CompleteOutcome::NoSuchUpload);
    }
    // Its checksum, as it was answered with (an SSE-C one's only with its
    // key, which the retry needn't give).
    let checksum = match (checksum_columns(&row, 9), row.get::<_, Option<&str>>(11)) {
        (Some((algorithm, kind)), Some(value)) => {
            let value = match &stored {
                Stored::Plain => Some(value.to_owned()),
                _ => match checksum_key(app, &stored, keys, bucket, key).await? {
                    Ok(Some(checksum_key)) => {
                        let owner = Owner::Object { bucket, key };
                        Some(Storing::Sealed(&checksum_key).read(Field::Checksum, owner, value)?)
                    }
                    Ok(None) => None,
                    Err(refused) => return Ok(CompleteOutcome::Refused(refused)),
                },
            };
            value.map(|value| Checksum { algorithm, kind, value })
        }
        _ => None,
    };
    if let Some(bad) = check_claim(claimed, checksum.as_ref()) {
        return Ok(bad);
    }
    let versioning: &str = row.get(2);
    Ok(CompleteOutcome::Done {
        bucket: bucket.to_owned(),
        key: key.to_owned(),
        etag,
        checksum,
        reap: Vec::new(),
        version_id: if versioning == "enabled" { row.get(1) } else { None },
    })
}

/// How the version that completed `upload_id` is encrypted (plain if it's
/// gone).
async fn completed_encryption(
    client: &Object,
    bucket: &str,
    key: &str,
    upload_id: &Uuid,
) -> Result<Stored, tokio_postgres::Error> {
    let row = client
        .query_opt_cached(
            "SELECT sse_c_key, sse_kms_key_id, sse_kms_data_key, sse_kms_sealed, sse_kms_context, sse_s3
             FROM objects WHERE bucket = $1 AND key = $2 AND upload_id = $3",
            &[&bucket, &key, upload_id],
        )
        .await?;
    Ok(row.map_or(Stored::Plain, |row| Stored::from_row(&row, 0)))
}

/// A part staged under the upload, as the completion needs it.
struct Staged {
    id: i64,
    /// Its ETag and checksum as clients know them (opened, if they're
    /// sealed).
    etag: String,
    checksum: Option<String>,
    /// Its plaintext's size.
    size: u64,
}

/// The object's checksum, from its `parts`' (in order), if it gets one
/// (`upload.object_checksum`) and they all have theirs: COMPOSITE, or
/// FULL_OBJECT, combined (see `s3::checksums`).
fn object_checksum(upload: &Upload, parts: &[&Staged]) -> anyhow::Result<Option<Checksum>> {
    let Some((algorithm, kind)) = upload.object_checksum() else { return Ok(None) };
    let mut raws = Vec::with_capacity(parts.len());
    for part in parts {
        let Some(value) = &part.checksum else { return Ok(None) };
        let raw = algorithm
            .decode(value)
            .ok_or_else(|| anyhow::anyhow!("a stored {} checksum isn't one", algorithm.name()))?;
        raws.push(raw);
    }
    let value = match kind {
        Type::Composite => checksums::composite(algorithm, &raws),
        Type::FullObject => checksums::encode(&checksums::combine_all(
            algorithm,
            raws.iter().zip(parts).map(|(raw, part)| (raw.as_slice(), part.size)),
        )),
    };
    Ok(Some(Checksum { algorithm, kind, value }))
}

/// One attempt at the completion (`cairn_complete_upload`): matches the
/// listed parts against the upload's (`None` if it's gone) by their ETags and
/// checksums, which only Cairn can read (an SSE-S3 upload's ETags are sealed,
/// an encrypted one's checksums), works out the object's ETag and checksum,
/// and decides a conditional completion; the transaction checks that what
/// this decided on is still so.
#[allow(clippy::too_many_arguments)]
async fn try_complete(
    app: &App,
    client: &mut Object,
    bucket: &str,
    key: &str,
    upload_id: &Uuid,
    request: &Request<'_>,
    upload: Option<&Upload>,
    keys: Keys<'_>,
) -> anyhow::Result<CompleteOutcome> {
    let requested = &request.listed.numbers_and_etags;
    let combined = combined_etag(requested);
    let Some(upload) = upload else {
        return completed(app, client, bucket, key, upload_id, combined.as_deref(), request.claimed, keys).await;
    };
    let encryption = &upload.encryption;
    let etag_key = match sse::etag_key(app, encryption, bucket, key).await? {
        Ok(etag_key) => etag_key,
        Err(refused) => return Ok(CompleteOutcome::Refused(refused)),
    };
    // The key its checksums are sealed under, if they are, and there are
    // any (`complete_multipart_upload` checked that an SSE-C one's is given).
    let checksum_key = match (encryption, upload.object_checksum()) {
        (Stored::Plain, _) | (_, None) => None,
        _ => match checksum_key(app, encryption, keys, bucket, key).await? {
            Ok(checksum_key) => checksum_key,
            Err(refused) => return Ok(CompleteOutcome::Refused(refused)),
        },
    };
    // How its checksums are stored: an encrypted one's only ever sealed. One
    // whose key isn't had can't have checksums read or stored (it gets none:
    // `complete_multipart_upload` sees that an SSE-C one of an algorithm
    // comes with its key).
    let storing = match (&checksum_key, encryption) {
        (Some(checksum_key), _) => Some(Storing::Sealed(checksum_key)),
        (None, Stored::Plain) => Some(Storing::Plain),
        (None, _) => None,
    };
    anyhow::ensure!(
        storing.is_some() || upload.object_checksum().is_none(),
        "an encrypted upload's checksums can't be had without its key"
    );
    // The upload's staged parts, by number, with their ETags and checksums
    // as clients know them.
    let mut staged = HashMap::new();
    for row in client
        .query_cached(
            "SELECT part_number, id, etag, checksum, coalesce(plain_size, size), enc_salt
             FROM parts WHERE upload_id = $1",
            &[upload_id],
        )
        .await?
    {
        // Its values, sealed as its own, if the upload is encrypted (see
        // `encryption`), by its salt.
        let salt: Option<Salt> = row
            .get::<_, Option<&[u8]>>(5)
            .map(|salt| salt.try_into().expect("a salt is 16 bytes (parts_encrypted)"));
        let owner = || match &salt {
            Some(salt) => Ok(Owner::Part(salt)),
            None => Err(anyhow::anyhow!("a part of an encrypted upload has no salt")),
        };
        let etag: String = row.get(2);
        let etag = match &etag_key {
            Some(etag_key) => etag_key.open(owner()?, &etag)?,
            None => etag,
        };
        // A part's checksum is only had where the object gets one.
        let checksum = match (row.get::<_, Option<&str>>(3), &storing) {
            (Some(stored), Some(Storing::Plain)) if upload.object_checksum().is_some() => Some(stored.to_owned()),
            (Some(stored), Some(storing)) if upload.object_checksum().is_some() => {
                Some(storing.read(Field::Checksum, owner()?, stored)?)
            }
            _ => None,
        };
        let size = row.get::<_, i64>(4) as u64;
        staged.insert(row.get::<_, i32>(0), Staged { id: row.get(1), etag, checksum, size });
    }
    // Each listed part must be staged, with its ETag; and with its checksum
    // if the upload is COMPOSITE, which S3 requires to be listed. A FULL_OBJECT
    // upload's needn't be (probed), but one listed is checked, as one of the
    // default, CRC64NVME, is.
    let algorithm = upload.object_checksum().map(|(algorithm, _)| algorithm);
    let mut parts = Vec::with_capacity(requested.len());
    for ((number, etag), listed) in requested.iter().zip(&request.listed.checksums) {
        let Some(part) = staged.get(number).filter(|part| part.etag == *etag) else {
            return Ok(CompleteOutcome::InvalidPart);
        };
        let listed = listed.iter().find(|(a, _)| Some(*a) == algorithm).map(|(_, value)| value);
        match (listed, &part.checksum) {
            (Some(listed), Some(checksum)) if listed == checksum => {}
            (Some(_), _) => return Ok(CompleteOutcome::InvalidPart),
            (None, _) => match upload.checksum {
                Some((algorithm, Type::Composite)) => return Ok(CompleteOutcome::MissingChecksum(algorithm, *number)),
                _ => {}
            },
        }
        parts.push(part);
    }
    let Some(combined) = combined else { return Ok(CompleteOutcome::InvalidPart) };
    // The size the client expects, if it says (S3's 400, probed).
    let size: u64 = parts.iter().map(|part| part.size).sum();
    if let Some(expected) = request.expected_size.filter(|expected| *expected != size) {
        return Ok(CompleteOutcome::Refused(format_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            &format!("The provided 'x-amz-mp-object-size' header value {expected} does not match what was computed: {size}"),
        )));
    }
    let checksum = object_checksum(upload, &parts)?;
    if let Some(bad) = check_claim(request.claimed, checksum.as_ref()) {
        return Ok(bad);
    }
    let stored_etag = match &etag_key {
        Some(etag_key) => etag_key.seal(Owner::Object { bucket, key }, &combined),
        None => combined.clone(),
    };
    let stored_checksum = match (&checksum, &storing) {
        (Some(checksum), Some(storing)) => Some(storing.store(Field::Checksum, Owner::Object { bucket, key }, &checksum.value)),
        (Some(_), None) => unreachable!("an object gets a checksum only where its parts' can be read"),
        (None, _) => None,
    };
    let preconditions = request.preconditions;
    let expected = if preconditions.has_write_conditions() {
        let current = match current_object(app, bucket, key).await? {
            Ok(current) => current,
            Err(refused) => return Ok(CompleteOutcome::Refused(refused)),
        };
        if !preconditions.allows_write(current.as_ref().map(|c| c.etag.as_str())) {
            // If-Match for a key without an object is S3's 404, not a 412.
            if preconditions.has_if_match() && current.is_none() {
                return Ok(CompleteOutcome::NoSuchKey);
            }
            return Ok(CompleteOutcome::PreconditionFailed);
        }
        Some(current.map(|c| c.id))
    } else {
        None
    };
    let part_ids: Vec<i64> = parts.iter().map(|part| part.id).collect();
    let part_numbers: Vec<i32> = requested.iter().map(|(n, _)| *n).collect();
    let row = client
        .query_one_cached(
            "SELECT status, version_id, reap_blob, reap_node, reap_peer
             FROM pg_temp.cairn_complete_upload($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            &[
                upload_id,
                &bucket,
                &key,
                &part_ids,
                &part_numbers,
                &stored_etag,
                &checksum.as_ref().map(|c| c.algorithm.name()),
                &checksum.as_ref().map(|c| c.kind.name()),
                &stored_checksum,
                &expected.is_some(),
                &expected.flatten(),
                &new_version_id(),
            ],
        )
        .await?;
    // On anything but completion, the function changed nothing, leaving the
    // upload intact for the client to retry or abort.
    match row.get::<_, &str>(0) {
        "done" => {}
        // Completed meanwhile, by a request like this one, say.
        "no_such_upload" => {
            return completed(app, client, bucket, key, upload_id, Some(&combined), request.claimed, keys).await;
        }
        "stale" => return Ok(CompleteOutcome::Stale),
        "too_large" => return Ok(CompleteOutcome::TooLarge),
        "too_small" => return Ok(CompleteOutcome::TooSmall),
        status => unreachable!("cairn_complete_upload: unknown status {status}"),
    }
    Ok(CompleteOutcome::Done {
        bucket: bucket.to_owned(),
        key: key.to_owned(),
        etag: combined,
        checksum,
        version_id: row.get(1),
        reap: reap_columns(&row, 2),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `x-amz-mp-object-size`, as S3 reads it (probed).
    #[test]
    fn reads_the_expected_size() {
        let read = |value: &str| {
            let mut headers = hyper::HeaderMap::new();
            headers.insert("x-amz-mp-object-size", value.parse().unwrap());
            expected_size(&headers).map_err(|refused| {
                let body = refused.into_body();
                let body = read_body(body);
                body[body.find("<Message>").unwrap() + 9..body.find("</Message>").unwrap()].to_owned()
            })
        };
        assert!(matches!(expected_size(&hyper::HeaderMap::new()), Ok(None)));
        assert_eq!(read("5242885"), Ok(Some(5242885)));
        assert_eq!(read("05242885"), Ok(Some(5242885)));
        assert_eq!(read("-1"), Err("Value for x-amz-mp-object-size header is less than zero: '-1'".to_owned()));
        for bad in ["abc", "", "1e7", "+5", "99999999999999999999"] {
            assert_eq!(read(bad), Err(format!("Value for x-amz-mp-object-size header is invalid: '{bad}'")));
        }
    }

    fn read_body(body: Full<Bytes>) -> String {
        use http_body_util::BodyExt;
        let bytes = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(body.collect())
            .unwrap()
            .to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }
}
