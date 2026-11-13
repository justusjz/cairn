use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use uuid::Uuid;

use crate::db::Cached;
use crate::{
    App,
    encryption::{Field, Owner, Salt, Storing},
    s3::multipart::{Upload, checksum_columns},
    s3::sse::{self, Stored},
    s3::sse_c::CustomerKey,
    s3::util::{format_s3_error, xml_escape, xml_ok},
};

/// The most parts a page lists, as in S3.
pub const MAX_PARTS: i64 = 1000;

/// ListParts: `GET /{bucket}/{key}?uploadId=U`. Lists the parts uploaded to an
/// incomplete upload so far, by part number, after `part_number_marker`: what
/// a client resuming an upload needs (CompleteMultipartUpload takes each
/// part's ETag). Sizes are of the parts' data, encrypted or not.
#[allow(clippy::too_many_arguments)]
pub async fn list_parts(
    app: &App,
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number_marker: i32,
    max_parts: i64,
    customer_key: Option<&CustomerKey>,
    role: Option<Uuid>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let Ok(upload) = Uuid::parse_str(upload_id) else {
        return Ok(no_such_upload());
    };
    let mut client = app.pool.get().await?;
    // The upload and its parts as of one moment.
    let tx = client
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
        .start()
        .await?;
    // It must belong to the request's bucket and key: authorization only
    // checked the bucket.
    let Some((encryption, checksum)) = tx
        .query_opt_cached(
            "SELECT sse_c_key, sse_kms_key_id, sse_kms_data_key, sse_kms_sealed, sse_kms_context, sse_s3,
                    checksum_algorithm, checksum_type
             FROM multipart_uploads WHERE upload_id = $1 AND bucket = $2 AND key = $3",
            &[&upload, &bucket, &key],
        )
        .await?
        .map(|row| (Stored::from_row(&row, 0), checksum_columns(&row, 6)))
    else {
        return Ok(no_such_upload());
    };
    let upload_info = Upload { encryption, checksum };
    // One more than a page, to tell whether there's more.
    let limit = max_parts + 1;
    let rows = tx
        .query_cached(
            "SELECT part_number, etag, coalesce(plain_size, size),
                    to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'),
                    checksum, enc_salt
             FROM parts WHERE upload_id = $1 AND part_number > $2
             ORDER BY part_number LIMIT $3",
            &[&upload, &part_number_marker, &limit],
        )
        .await?;
    tx.commit().await?;
    drop(client);
    let encryption = &upload_info.encryption;
    // An SSE-C upload's key, if given, must be its own. Its parts' checksums
    // are told only with it (S3 needs it for an upload of an algorithm).
    if customer_key.is_some()
        && let Err(refused) = sse::check(encryption, customer_key, bucket, key)
    {
        return Ok(refused);
    }
    // An SSE-S3 upload's part ETags are stored sealed, under its key.
    let etag_key = match sse::etag_key(app, encryption, bucket, key).await? {
        Ok(etag_key) => etag_key,
        Err(refused) => return Ok(refused),
    };
    // Its parts' checksums: of its algorithm, sealed if it's encrypted.
    let algorithm = upload_info.object_checksum().map(|(algorithm, _)| algorithm);
    let has_checksums = algorithm.is_some() && kept_rows(&rows, max_parts).iter().any(|row| row.get::<_, Option<&str>>(4).is_some());
    let checksum_key = match encryption {
        Stored::Plain => None,
        Stored::Customer { .. } if customer_key.is_none() => None,
        _ if !has_checksums => None,
        _ => match sse::open(app, encryption, customer_key, role, bucket, key).await? {
            Ok(object_key) => object_key,
            Err(refused) => return Ok(refused),
        },
    };
    let storing = match (&checksum_key, encryption) {
        (Some(checksum_key), _) => Some(Storing::Sealed(checksum_key)),
        (None, Stored::Plain) => Some(Storing::Plain),
        // An SSE-C one's without its key: not told.
        (None, _) => None,
    };

    let truncated = rows.len() as i64 > max_parts;
    let kept = kept_rows(&rows, max_parts);
    let owner = "<ID>cairn</ID><DisplayName>cairn</DisplayName>";
    let mut body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <ListPartsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Bucket>{}</Bucket><Key>{}</Key><UploadId>{upload}</UploadId>\
         <Initiator>{owner}</Initiator><Owner>{owner}</Owner>\
         <StorageClass>STANDARD</StorageClass>{}\
         <PartNumberMarker>{part_number_marker}</PartNumberMarker>",
        xml_escape(bucket),
        xml_escape(key),
        upload_info.object_checksum().map_or(String::new(), |(algorithm, kind)| format!(
            "<ChecksumAlgorithm>{}</ChecksumAlgorithm><ChecksumType>{}</ChecksumType>",
            algorithm.name(),
            kind.name()
        )),
    );
    // The next page starts after this one's last part; an empty page (max-parts
    // 0) hands back the incoming marker.
    let next = kept.last().map_or(part_number_marker, |row| row.get(0));
    body.push_str(&format!(
        "<NextPartNumberMarker>{next}</NextPartNumberMarker>\
         <MaxParts>{max_parts}</MaxParts><IsTruncated>{truncated}</IsTruncated>"
    ));
    for row in kept {
        let (number, etag, size, modified): (i32, &str, i64, &str) =
            (row.get(0), row.get(1), row.get(2), row.get(3));
        // Its values, sealed as its own, if the upload is encrypted (see
        // `encryption`), by its salt.
        let salt: Option<Salt> = row
            .get::<_, Option<&[u8]>>(5)
            .map(|salt| salt.try_into().expect("a salt is 16 bytes (parts_encrypted)"));
        let owner = || match &salt {
            Some(salt) => Ok(Owner::Part(salt)),
            None => Err(anyhow::anyhow!("a part of an encrypted upload has no salt")),
        };
        let etag = match &etag_key {
            Some(etag_key) => etag_key.open(owner()?, etag)?,
            None => etag.to_owned(),
        };
        let checksum = match (algorithm, &storing, row.get::<_, Option<&str>>(4)) {
            (Some(algorithm), Some(storing), Some(stored)) => {
                let value = match storing {
                    Storing::Plain => stored.to_owned(),
                    Storing::Sealed(_) => storing.read(Field::Checksum, owner()?, stored)?,
                };
                let element = algorithm.element();
                format!("<{element}>{}</{element}>", value)
            }
            _ => String::new(),
        };
        body.push_str(&format!(
            "<Part><PartNumber>{number}</PartNumber><LastModified>{modified}</LastModified>\
             <ETag>\"{}\"</ETag><Size>{size}</Size>{checksum}</Part>",
            xml_escape(&etag),
        ));
    }
    body.push_str("</ListPartsResult>");
    Ok(xml_ok(body))
}

/// The rows of a page of `max_parts`, of the one more that were read.
fn kept_rows(rows: &[tokio_postgres::Row], max_parts: i64) -> &[tokio_postgres::Row] {
    &rows[..(max_parts as usize).min(rows.len())]
}

fn no_such_upload() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::NOT_FOUND,
        "NoSuchUpload",
        "the specified multipart upload does not exist",
    )
}
