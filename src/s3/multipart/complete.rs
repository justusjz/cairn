use std::{collections::HashMap, sync::Arc};

use deadpool_postgres::Object;
use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use md5::{Digest, Md5};
use tokio_postgres::{IsolationLevel, error::SqlState};
use uuid::Uuid;

use crate::{
    App, ReapTarget, reap_parts, reap_targets,
    s3::conditional::Preconditions,
    s3::util::{format_s3_error, with_version_id, xml_escape, xml_ok},
    s3::versions::{Versioning, bucket_versioning, current_etag, put_version},
};

const MAX_COMPLETE_ATTEMPTS: usize = 10;

enum CompleteOutcome {
    Done {
        bucket: String,
        key: String,
        etag: String,
        /// Locations of the replaced version's parts and of the staged parts the
        /// client left out, to reap after commit.
        reap: Vec<ReapTarget>,
        /// The `x-amz-version-id` to report for the new version.
        version_id: Option<String>,
    },
    NoSuchUpload,
    InvalidPart,
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

/// Decodes a hex string into bytes (our part ETags are 32-char hex MD5s).
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .filter_map(|i| u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok())
        .collect()
}

/// CompleteMultipartUpload: `POST /{bucket}/{key}?uploadId=U` with a part-list
/// body. Assembles the listed parts into the object atomically.
pub async fn complete_multipart_upload(
    app: &Arc<App>,
    bucket: &str,
    key: &str,
    upload_id: &str,
    body: Bytes,
    preconditions: &Preconditions,
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
    for _ in 0..MAX_COMPLETE_ATTEMPTS {
        match try_complete(&mut client, bucket, key, &upload_id, &requested, preconditions).await {
            Ok(CompleteOutcome::Done {
                bucket,
                key,
                etag,
                reap,
                version_id,
            }) => {
                reap_parts(app, reap);
                let body = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                     <Bucket>{}</Bucket><Key>{}</Key><ETag>\"{}\"</ETag>\
                     </CompleteMultipartUploadResult>",
                    xml_escape(&bucket),
                    xml_escape(&key),
                    xml_escape(&etag),
                );
                return Ok(with_version_id(xml_ok(body), version_id.as_deref()));
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
            Ok(CompleteOutcome::PreconditionFailed) => {
                return Ok(format_s3_error(
                    StatusCode::PRECONDITION_FAILED,
                    "PreconditionFailed",
                    "at least one of the preconditions you specified did not hold",
                ));
            }
            Err(e) if e.code() == Some(&SqlState::T_R_SERIALIZATION_FAILURE) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(format_s3_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "ServiceUnavailable",
        "completion aborted after serialization retries",
    ))
}

/// One attempt at the completion transaction, serializable like the part commit
/// (it writes objects + parts and races overwrites/GC). The raw postgres error
/// is returned so the caller can retry on a serialization failure.
async fn try_complete(
    client: &mut Object,
    bucket: &str,
    key: &str,
    upload_id: &Uuid,
    requested: &[(i32, String)],
    preconditions: &Preconditions,
) -> Result<CompleteOutcome, tokio_postgres::Error> {
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()
        .await?;
    // The upload defines the target object's content type. It must belong to
    // the request's bucket/key: authorization only checked that bucket.
    let upload = tx
        .query_opt(
            "SELECT content_type FROM multipart_uploads
             WHERE upload_id = $1 AND bucket = $2 AND key = $3",
            &[upload_id, &bucket, &key],
        )
        .await?;
    let content_type: String = match upload {
        Some(row) => row.get(0),
        None => return Ok(CompleteOutcome::NoSuchUpload),
    };
    let (bucket, key) = (bucket.to_owned(), key.to_owned());
    // Index the staged parts by number, then validate each requested part while
    // summing the total size and folding the binary MD5s for the combined ETag.
    let staged = tx
        .query(
            "SELECT part_number, etag, size FROM parts WHERE upload_id = $1",
            &[upload_id],
        )
        .await?;
    let mut by_number: HashMap<i32, (String, i64)> = HashMap::new();
    for row in &staged {
        by_number.insert(row.get(0), (row.get(1), row.get(2)));
    }
    let mut hasher = Md5::new();
    let mut total_size: i64 = 0;
    for (part_number, req_etag) in requested {
        match by_number.get(part_number) {
            Some((etag, size)) if etag == req_etag => {
                total_size += size;
                hasher.update(hex_to_bytes(etag));
            }
            _ => return Ok(CompleteOutcome::InvalidPart),
        }
    }
    let combined: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let final_etag = format!("{combined}-{}", requested.len());

    // Conditional completion: honour If-Match / If-None-Match against the object
    // currently at the key, inside this serializable transaction so the guard is
    // atomic with the swap below (matching conditional PutObject).
    if preconditions.has_write_conditions() {
        let current = current_etag(&tx, &bucket, &key).await?;
        if !preconditions.allows_write(current.as_deref()) {
            // Dropping `tx` here rolls the transaction back, leaving the upload
            // intact for the client to retry or abort.
            return Ok(CompleteOutcome::PreconditionFailed);
        }
    }

    // Publish atomically: the new version (replacing the old one and its parts),
    // re-point the chosen staged parts to it, then delete the upload (cascading
    // away the staged parts the client didn't include).
    // The upload's FK guarantees the bucket exists.
    let versioning = bucket_versioning(&tx, &bucket)
        .await?
        .unwrap_or(Versioning::Unversioned);
    let mut reap = Vec::new();
    let version = put_version(
        &tx,
        &bucket,
        &key,
        versioning,
        total_size,
        &final_etag,
        &content_type,
        &mut reap,
    )
    .await?;
    let part_numbers: Vec<i32> = requested.iter().map(|(pn, _)| *pn).collect();
    tx.execute(
        "UPDATE parts SET upload_id = NULL, object_id = $1
         WHERE upload_id = $2 AND part_number = ANY($3)",
        &[&version.id, upload_id, &part_numbers],
    )
    .await?;
    // Delete the upload, which cascades away any staged parts not included in the
    // completed object. Those are the only parts still staged under it now, so
    // capture their locations first to reap them along with the replaced ones.
    let unused = tx
        .query(
            "SELECT pl.part_id, pl.node_id, n.peer_url
             FROM parts p
             JOIN part_locations pl ON pl.part_id = p.part_id
             JOIN nodes n ON n.node_id = pl.node_id
             WHERE p.upload_id = $1",
            &[upload_id],
        )
        .await?;
    reap.extend(reap_targets(&unused));
    tx.execute(
        "DELETE FROM multipart_uploads WHERE upload_id = $1",
        &[upload_id],
    )
    .await?;
    tx.commit().await?;
    Ok(CompleteOutcome::Done {
        bucket,
        key,
        etag: final_etag,
        reap,
        version_id: version.version_id,
    })
}
