use std::sync::Arc;

use deadpool_postgres::Object;
use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use uuid::Uuid;

use crate::db::Cached;
use crate::{
    App,
    blobs::{ReapTarget, reap_blobs, reap_columns},
    db,
    s3::conditional::Preconditions,
    s3::sse_c::{self, CustomerKey},
    s3::util::{format_s3_error, slow_down, with_version_id, xml_escape, xml_ok},
    s3::versions::new_version_id,
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

    let mut client = app.pool.get().await?;
    // The object gets its upload's key check; a key isn't needed. One given
    // must be the upload's (a retry, whose upload is gone, isn't checked).
    if let Some(customer) = customer_key {
        let upload = client
            .query_opt_cached(
                "SELECT sse_c_key FROM multipart_uploads WHERE upload_id = $1 AND bucket = $2 AND key = $3",
                &[&upload_id, &bucket, &key],
            )
            .await?;
        if let Some(upload) = upload {
            let check: Option<Vec<u8>> = upload.get(0);
            if let Err(refused) = sse_c::check_read(check.as_deref(), Some(customer)) {
                return Ok(refused);
            }
        }
    }
    for attempt in 0..db::MAX_TX_ATTEMPTS {
        db::backoff(attempt).await;
        match try_complete(&mut client, bucket, key, &upload_id, &requested, preconditions).await {
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
                return Ok(match customer_key {
                    Some(customer) => customer.echo_onto(response),
                    None => response,
                });
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
            Ok(CompleteOutcome::PreconditionFailed) => {
                return Ok(format_s3_error(
                    StatusCode::PRECONDITION_FAILED,
                    "PreconditionFailed",
                    "at least one of the preconditions you specified did not hold",
                ));
            }
            Err(e) if db::is_conflict(&e) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(slow_down())
}

/// One attempt at the completion transaction (`cairn_complete_upload`). The
/// raw postgres error is returned so the caller can retry on a conflict.
async fn try_complete(
    client: &mut Object,
    bucket: &str,
    key: &str,
    upload_id: &Uuid,
    requested: &[(i32, String)],
    preconditions: &Preconditions,
) -> Result<CompleteOutcome, tokio_postgres::Error> {
    let (part_numbers, etags): (Vec<i32>, Vec<&str>) =
        requested.iter().map(|(n, etag)| (*n, etag.as_str())).unzip();
    let (if_match, if_none_match) = preconditions.write_conditions();
    let row = client
        .query_one_cached(
            "SELECT status, etag, version_id, reap_blob, reap_node, reap_peer
             FROM pg_temp.cairn_complete_upload($1, $2, $3, $4, $5, $6, $7, $8)",
            &[
                upload_id,
                &bucket,
                &key,
                &part_numbers,
                &etags,
                &if_match,
                &if_none_match,
                &new_version_id(),
            ],
        )
        .await?;
    // On anything but completion, the function changed nothing, leaving the
    // upload intact for the client to retry or abort.
    match row.get::<_, &str>(0) {
        "done" => {}
        "no_such_upload" => return Ok(CompleteOutcome::NoSuchUpload),
        "invalid_part" => return Ok(CompleteOutcome::InvalidPart),
        "too_large" => return Ok(CompleteOutcome::TooLarge),
        "too_small" => return Ok(CompleteOutcome::TooSmall),
        "precondition_failed" => return Ok(CompleteOutcome::PreconditionFailed),
        status => unreachable!("cairn_complete_upload: unknown status {status}"),
    }
    let outcome = CompleteOutcome::Done {
        bucket: bucket.to_owned(),
        key: key.to_owned(),
        etag: row.get(1),
        version_id: row.get(2),
        reap: reap_columns(&row, 3),
    };
    Ok(outcome)
}
