use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use uuid::Uuid;

use crate::db::Cached;
use crate::{
    App,
    s3::util::{format_s3_error, xml_escape, xml_ok},
};

/// The most parts a page lists, as in S3.
pub const MAX_PARTS: i64 = 1000;

/// ListParts: `GET /{bucket}/{key}?uploadId=U`. Lists the parts uploaded to an
/// incomplete upload so far, by part number, after `part_number_marker`: what
/// a client resuming an upload needs (CompleteMultipartUpload takes each
/// part's ETag). Sizes are of the parts' data, encrypted or not.
pub async fn list_parts(
    app: &App,
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number_marker: i32,
    max_parts: i64,
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
    if tx
        .query_opt_cached(
            "SELECT 1 FROM multipart_uploads WHERE upload_id = $1 AND bucket = $2 AND key = $3",
            &[&upload, &bucket, &key],
        )
        .await?
        .is_none()
    {
        return Ok(no_such_upload());
    }
    // One more than a page, to tell whether there's more.
    let limit = max_parts + 1;
    let rows = tx
        .query_cached(
            "SELECT part_number, etag, coalesce(plain_size, size),
                    to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')
             FROM parts WHERE upload_id = $1 AND part_number > $2
             ORDER BY part_number LIMIT $3",
            &[&upload, &part_number_marker, &limit],
        )
        .await?;
    tx.commit().await?;
    drop(client);

    let truncated = rows.len() as i64 > max_parts;
    let kept = &rows[..(max_parts as usize).min(rows.len())];
    let owner = "<ID>cairn</ID><DisplayName>cairn</DisplayName>";
    let mut body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <ListPartsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Bucket>{}</Bucket><Key>{}</Key><UploadId>{upload}</UploadId>\
         <Initiator>{owner}</Initiator><Owner>{owner}</Owner>\
         <StorageClass>STANDARD</StorageClass>\
         <PartNumberMarker>{part_number_marker}</PartNumberMarker>",
        xml_escape(bucket),
        xml_escape(key),
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
        body.push_str(&format!(
            "<Part><PartNumber>{number}</PartNumber><LastModified>{modified}</LastModified>\
             <ETag>\"{}\"</ETag><Size>{size}</Size></Part>",
            xml_escape(etag),
        ));
    }
    body.push_str("</ListPartsResult>");
    Ok(xml_ok(body))
}

fn no_such_upload() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::NOT_FOUND,
        "NoSuchUpload",
        "the specified multipart upload does not exist",
    )
}
