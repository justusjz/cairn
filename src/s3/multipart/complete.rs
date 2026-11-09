use std::sync::Arc;

use deadpool_postgres::Object;
use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use uuid::Uuid;

use std::collections::HashMap;

use md5::{Digest, Md5};

use crate::db::Cached;
use crate::{
    App,
    blobs::{ReapTarget, reap_blobs, reap_columns},
    db,
    s3::conditional::Preconditions,
    s3::multipart::upload_encryption,
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
        /// Locations of the blobs freed by replacing the old version and by
        /// dropping the staged parts the client left out, to reap after commit.
        reap: Vec<ReapTarget>,
        /// The `x-amz-version-id` to report for the new version.
        version_id: Option<String>,
    },
    NoSuchUpload,
    InvalidPart,
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
}

/// Parses a CompleteMultipartUpload body into (part_number, unquoted-etag) pairs,
/// namespace-agnostically. Returns None on malformed XML.
fn parse_complete_request(body: &str) -> Option<Vec<(i32, String)>> {
    let doc = roxmltree::Document::parse(body).ok()?;
    let mut parts = Vec::new();
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
    }
    Some(parts)
}

/// CompleteMultipartUpload: `POST /{bucket}/{key}?uploadId=U` with a part-list
/// body. Assembles the listed parts into the object atomically. A retry of a
/// completion that went through (its response lost, say) is answered as it
/// was, as long as the version it made is still there.
pub async fn complete_multipart_upload(
    app: &Arc<App>,
    bucket: &str,
    key: &str,
    upload_id: &str,
    body: Bytes,
    preconditions: &Preconditions,
    customer_key: Option<&CustomerKey>,
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
    let requested = match parse_complete_request(body_str) {
        Some(parts) if !parts.is_empty() => parts,
        _ => {
            return Ok(format_s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "could not parse the part list",
            ));
        }
    };
    // S3 requires the parts in ascending (and thus distinct) part-number order.
    if !requested.windows(2).all(|w| w[0].0 < w[1].0) {
        return Ok(format_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidPartOrder",
            "parts must be listed in ascending part-number order",
        ));
    }

    // The object gets its upload's encryption; an SSE-C key isn't needed. One
    // given must be the upload's (a retry, whose upload is gone, isn't checked).
    let encryption = upload_encryption(app, &upload_id, bucket, key).await?;
    if let (Some(encryption), Some(_)) = (&encryption, customer_key)
        && let Err(refused) = sse::check(encryption, customer_key)
    {
        return Ok(refused);
    }
    let mut client = app.pool.get().await?;
    for attempt in 0..db::MAX_TX_ATTEMPTS {
        db::backoff(attempt).await;
        let attempt = try_complete(app, &mut client, bucket, key, &upload_id, &requested, preconditions, encryption.as_ref());
        match attempt.await {
            Ok(CompleteOutcome::Done {
                bucket,
                key,
                etag,
                reap,
                version_id,
            }) => {
                reap_blobs(app, reap);
                let body = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                     <Bucket>{}</Bucket><Key>{}</Key><ETag>\"{}\"</ETag>\
                     </CompleteMultipartUploadResult>",
                    xml_escape(&bucket),
                    xml_escape(&key),
                    xml_escape(&etag),
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
                    "one or more listed parts could not be found or its ETag did not match",
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

/// The completion a retry repeats, whose upload is gone: the version it made,
/// if that's still there and has the ETag the `combined` listed parts give,
/// answered as it was; or else, there's no such upload.
async fn completed(
    app: &App,
    client: &Object,
    bucket: &str,
    key: &str,
    upload_id: &Uuid,
    combined: Option<&str>,
) -> anyhow::Result<CompleteOutcome> {
    let Some(combined) = combined else { return Ok(CompleteOutcome::NoSuchUpload) };
    let row = client
        .query_opt_cached(
            "SELECT o.etag, o.version_id, b.versioning, o.sse_c_key, o.sse_kms_key_id,
                    o.sse_kms_data_key, o.sse_kms_sealed, o.sse_kms_context, o.sse_s3
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
    let versioning: &str = row.get(2);
    Ok(CompleteOutcome::Done {
        bucket: bucket.to_owned(),
        key: key.to_owned(),
        etag,
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

/// One attempt at the completion (`cairn_complete_upload`): matches the
/// listed parts against the upload's (`encryption`, `None` if it's gone) by
/// their ETags, which only Cairn can read (an SSE-S3 upload's are sealed),
/// works out the object's ETag, and decides a conditional completion; the
/// transaction checks that what this decided on is still so.
#[allow(clippy::too_many_arguments)]
async fn try_complete(
    app: &App,
    client: &mut Object,
    bucket: &str,
    key: &str,
    upload_id: &Uuid,
    requested: &[(i32, String)],
    preconditions: &Preconditions,
    encryption: Option<&Stored>,
) -> anyhow::Result<CompleteOutcome> {
    let combined = combined_etag(requested);
    let Some(encryption) = encryption else {
        return completed(app, client, bucket, key, upload_id, combined.as_deref()).await;
    };
    let etag_key = match sse::etag_key(app, encryption, bucket, key).await? {
        Ok(etag_key) => etag_key,
        Err(refused) => return Ok(CompleteOutcome::Refused(refused)),
    };
    // The upload's staged parts, by number, with their ETags as clients know
    // them.
    let mut staged = HashMap::new();
    for row in client
        .query_cached("SELECT part_number, id, etag FROM parts WHERE upload_id = $1", &[upload_id])
        .await?
    {
        let etag: String = row.get(2);
        let etag = match &etag_key {
            Some(etag_key) => etag_key.open(&etag)?,
            None => etag,
        };
        staged.insert(row.get::<_, i32>(0), (row.get::<_, i64>(1), etag));
    }
    let mut part_ids = Vec::with_capacity(requested.len());
    for (number, etag) in requested {
        match staged.get(number) {
            Some((id, staged)) if staged == etag => part_ids.push(*id),
            _ => return Ok(CompleteOutcome::InvalidPart),
        }
    }
    let Some(combined) = combined else { return Ok(CompleteOutcome::InvalidPart) };
    let stored_etag = match &etag_key {
        Some(etag_key) => etag_key.seal(&combined),
        None => combined.clone(),
    };
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
    let part_numbers: Vec<i32> = requested.iter().map(|(n, _)| *n).collect();
    let row = client
        .query_one_cached(
            "SELECT status, version_id, reap_blob, reap_node, reap_peer
             FROM pg_temp.cairn_complete_upload($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            &[
                upload_id,
                &bucket,
                &key,
                &part_ids,
                &part_numbers,
                &stored_etag,
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
        "no_such_upload" => return completed(app, client, bucket, key, upload_id, Some(&combined)).await,
        "stale" => return Ok(CompleteOutcome::Stale),
        "too_large" => return Ok(CompleteOutcome::TooLarge),
        "too_small" => return Ok(CompleteOutcome::TooSmall),
        status => unreachable!("cairn_complete_upload: unknown status {status}"),
    }
    Ok(CompleteOutcome::Done {
        bucket: bucket.to_owned(),
        key: key.to_owned(),
        etag: combined,
        version_id: row.get(1),
        reap: reap_columns(&row, 2),
    })
}
