use std::collections::HashMap;
use std::sync::Arc;

use deadpool_postgres::Object;
use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes, header};
use md5::{Digest, Md5};
use tokio_postgres::{IsolationLevel, error::SqlState};
use uuid::Uuid;

use crate::{
    App, AttachTarget,
    s3::util::{format_s3_error, xml_escape, xml_ok},
};

/// CreateMultipartUpload: `POST /{bucket}/{key}?uploads`. Stages an upload and
/// hands back its UploadId. Nothing about the live object changes until
/// CompleteMultipartUpload.
pub async fn create_multipart_upload(
    app: &App,
    bucket: &str,
    key: &str,
    content_type: &str,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let client = app.pool.get().await?;
    if client
        .query_opt("SELECT 1 FROM buckets WHERE name = $1", &[&bucket])
        .await?
        .is_none()
    {
        return Ok(format_s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "the specified bucket does not exist",
        ));
    }
    // The content type is captured now and applied to the object at completion.
    let upload_id = Uuid::new_v4();
    client
        .execute(
            "INSERT INTO multipart_uploads (upload_id, bucket, key, content_type, initiated_at)
             VALUES ($1, $2, $3, $4, NOW())",
            &[&upload_id, &bucket, &key, &content_type],
        )
        .await?;
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId>\
         </InitiateMultipartUploadResult>",
        xml_escape(bucket),
        xml_escape(key),
        upload_id
    );
    Ok(xml_ok(body))
}

/// UploadPart: `PUT /{bucket}/{key}?partNumber=N&uploadId=U`. Stores the part and
/// stages it under the upload (the live object is untouched); returns its ETag.
pub async fn put_part(
    app: &Arc<App>,
    upload_id: &str,
    part_number: &str,
    data: Bytes,
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
    // Reject up front if the upload is gone, so we don't replicate a part we'd
    // only fail to stage at commit (the FK would reject it anyway).
    let client = app.pool.get().await?;
    if client
        .query_opt(
            "SELECT 1 FROM multipart_uploads WHERE upload_id = $1",
            &[&upload_id],
        )
        .await?
        .is_none()
    {
        return Ok(format_s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "the specified multipart upload does not exist",
        ));
    }
    drop(client);

    let etag: String = Md5::digest(&data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    crate::upload_part(
        app,
        data,
        &AttachTarget::MultipartPart {
            upload_id,
            part_number,
            etag: etag.clone(),
        },
    )
    .await?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::ETAG, format!("\"{etag}\""))
        .body(Full::new(Bytes::new()))
        .unwrap())
}

const MAX_COMPLETE_ATTEMPTS: usize = 10;

enum CompleteOutcome {
    Done {
        bucket: String,
        key: String,
        etag: String,
    },
    NoSuchUpload,
    InvalidPart,
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
    app: &App,
    upload_id: &str,
    body: Bytes,
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
        match try_complete(&mut client, &upload_id, &requested).await {
            Ok(CompleteOutcome::Done { bucket, key, etag }) => {
                let body = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                     <Bucket>{}</Bucket><Key>{}</Key><ETag>\"{}\"</ETag>\
                     </CompleteMultipartUploadResult>",
                    xml_escape(&bucket),
                    xml_escape(&key),
                    xml_escape(&etag),
                );
                return Ok(xml_ok(body));
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
    upload_id: &Uuid,
    requested: &[(i32, String)],
) -> Result<CompleteOutcome, tokio_postgres::Error> {
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()
        .await?;
    // The upload defines the target object and its content type.
    let upload = tx
        .query_opt(
            "SELECT bucket, key, content_type FROM multipart_uploads WHERE upload_id = $1",
            &[upload_id],
        )
        .await?;
    let (bucket, key, content_type): (String, String, String) = match upload {
        Some(row) => (row.get(0), row.get(1), row.get(2)),
        None => return Ok(CompleteOutcome::NoSuchUpload),
    };
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

    // Publish atomically: object metadata, drop the old object's parts, re-point
    // the chosen staged parts to the object, then delete the upload (cascading
    // away the staged parts the client didn't include).
    tx.execute(
        "INSERT INTO objects (bucket, key, size, etag, content_type, last_modified)
         VALUES ($1, $2, $3, $4, $5, NOW())
         ON CONFLICT (bucket, key)
         DO UPDATE SET size = $3, etag = $4, content_type = $5, last_modified = NOW()",
        &[&bucket, &key, &total_size, &final_etag, &content_type],
    )
    .await?;
    tx.execute(
        "DELETE FROM parts WHERE object_bucket = $1 AND object_key = $2",
        &[&bucket, &key],
    )
    .await?;
    let part_numbers: Vec<i32> = requested.iter().map(|(pn, _)| *pn).collect();
    tx.execute(
        "UPDATE parts SET upload_id = NULL, object_bucket = $1, object_key = $2
         WHERE upload_id = $3 AND part_number = ANY($4)",
        &[&bucket, &key, upload_id, &part_numbers],
    )
    .await?;
    // delete the multipart upload, which also drops any staged
    // parts that were not included in the completed object
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
    })
}
