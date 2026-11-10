use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use uuid::Uuid;

use crate::db::Cached;
use crate::{
    App,
    s3::util::{Encoding, format_s3_error, xml_escape, xml_ok},
    s3::versions::bucket_versioning,
};

/// ListMultipartUploads: `GET /{bucket}?uploads`. Lists the bucket's incomplete
/// uploads under `prefix`, keys in ascending order and each key's uploads in
/// the order they were created, rolling keys up into common prefixes at
/// `delimiter` like ListObjects.
///
/// Pagination follows S3: the page starts after `key_marker`, or, with an
/// `upload_id_marker` too, after that upload of `key_marker` (so the key's
/// later uploads come first). Without a key marker, the upload marker is
/// ignored, as S3 ignores it. Uploads and common prefixes each count toward
/// `max_uploads`.
#[allow(clippy::too_many_arguments)]
pub async fn list_multipart_uploads(
    app: &App,
    bucket: &str,
    prefix: &str,
    delimiter: Option<&str>,
    key_marker: &str,
    upload_id_marker: Option<&str>,
    max_uploads: i64,
    encoding: Encoding,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let upload_id_marker = upload_id_marker.filter(|_| !key_marker.is_empty());
    // Upload IDs are UUIDv7s, which order an upload among its key's whether or
    // not it still exists; anything else names no upload.
    let marker_id = match upload_id_marker.map(Uuid::parse_str) {
        None => None,
        Some(Ok(id)) => Some(id),
        Some(Err(_)) => {
            return Ok(format_s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "invalid upload id marker specified",
            ));
        }
    };
    let mut client = app.pool.get().await?;
    let tx = client.transaction().await?;
    if bucket_versioning(&tx, bucket).await?.is_none() {
        return Ok(format_s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "the specified bucket does not exist",
        ));
    }
    // One page, plus one entry to tell whether there's more.
    let limit = (max_uploads + 1) as i32;
    let delim = delimiter.unwrap_or("");
    let rows = tx
        .query_cached(
            "SELECT name AS key, is_prefix, upload_id,
                    to_char(initiated_at AT TIME ZONE 'UTC',
                            'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS initiated,
                    checksum_algorithm, checksum_type
             FROM pg_temp.cairn_list_uploads($1, $2, $3, $4, $5, $6)",
            &[&bucket, &prefix, &delim, &key_marker, &marker_id, &limit],
        )
        .await?;
    tx.commit().await?;
    drop(client);

    // A page of none tells nothing about what's left (as in S3).
    let truncated = rows.len() as i64 > max_uploads && max_uploads > 0;
    let kept = &rows[..(max_uploads as usize).min(rows.len())];

    let mut uploads = String::new();
    let mut prefixes = String::new();
    for row in kept {
        if row.get::<_, bool>("is_prefix") {
            prefixes.push_str(&format!(
                "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
                encoding.xml(row.get("key"))
            ));
            continue;
        }
        let upload_id: Uuid = row.get("upload_id");
        let initiated: &str = row.get("initiated");
        let checksum = crate::s3::checksums::listed(row, 4);
        uploads.push_str(&format!(
            "<Upload><Key>{}</Key><UploadId>{upload_id}</UploadId>{INITIATOR}{OWNER}\
             <StorageClass>STANDARD</StorageClass><Initiated>{initiated}</Initiated>{checksum}</Upload>",
            encoding.xml(row.get("key")),
        ));
    }

    let mut body = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <ListMultipartUploadsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    body.push_str(&format!("<Bucket>{}</Bucket>", xml_escape(bucket)));
    body.push_str(&format!(
        "<KeyMarker>{}</KeyMarker>",
        encoding.xml(key_marker)
    ));
    body.push_str(&format!(
        "<UploadIdMarker>{}</UploadIdMarker>",
        xml_escape(upload_id_marker.unwrap_or(""))
    ));
    body.push_str(&format!("<Prefix>{}</Prefix>", encoding.xml(prefix)));
    if let Some(d) = delimiter {
        body.push_str(&format!("<Delimiter>{}</Delimiter>", encoding.xml(d)));
    }
    body.push_str(&format!("<MaxUploads>{max_uploads}</MaxUploads>"));
    body.push_str(encoding.element());
    body.push_str(&format!("<IsTruncated>{truncated}</IsTruncated>"));
    // The next page resumes after the last entry kept: after that upload of its
    // key, or past a whole common prefix, which is then the key marker. An empty
    // page (max_uploads == 0) can't advance on its own, so it hands back the
    // incoming markers.
    if truncated {
        let (next_key, next_upload) = match kept.last() {
            Some(row) if row.get::<_, bool>("is_prefix") => (row.get::<_, String>("key"), None),
            Some(row) => (
                row.get::<_, String>("key"),
                Some(row.get::<_, Uuid>("upload_id").to_string()),
            ),
            None => (key_marker.to_owned(), upload_id_marker.map(str::to_owned)),
        };
        body.push_str(&format!(
            "<NextKeyMarker>{}</NextKeyMarker>",
            encoding.xml(&next_key)
        ));
        if let Some(u) = next_upload {
            body.push_str(&format!("<NextUploadIdMarker>{}</NextUploadIdMarker>", xml_escape(&u)));
        }
    }
    body.push_str(&uploads);
    body.push_str(&prefixes);
    body.push_str("</ListMultipartUploadsResult>");
    Ok(xml_ok(body))
}

/// The fixed initiator and owner Cairn reports, matching the ACL stub.
const INITIATOR: &str = "<Initiator><ID>cairn</ID><DisplayName>cairn</DisplayName></Initiator>";
const OWNER: &str = "<Owner><ID>cairn</ID><DisplayName>cairn</DisplayName></Owner>";
