use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::{
    App,
    s3::util::{format_s3_error, xml_escape, xml_ok},
    s3::versions::bucket_versioning,
};

/// ListObjectVersions: `GET /{bucket}?versions`. Lists every version and delete
/// marker under `prefix`, keys in ascending order and each key's versions newest
/// first, rolling keys up into common prefixes at `delimiter` like ListObjects.
///
/// Pagination follows S3: the page starts after `key_marker`, or, with a
/// `version_id_marker` too, after that version of `key_marker` (so the rest of
/// that key's older versions come first). Versions, delete markers and common
/// prefixes each count toward `max_keys`.
pub async fn list_object_versions(
    app: &App,
    bucket: &str,
    prefix: &str,
    delimiter: Option<&str>,
    key_marker: &str,
    version_id_marker: Option<&str>,
    max_keys: i64,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let mut client = app.pool.get().await?;
    let tx = client.transaction().await?;
    if bucket_versioning(&tx, bucket).await?.is_none() {
        return Ok(format_s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "the specified bucket does not exist",
        ));
    }
    // A version-id-marker only means something within a key-marker; resolve it
    // to the version's row id, which orders a key's versions (higher is newer).
    let marker_id: Option<i64> = match version_id_marker {
        None => None,
        Some(_) if key_marker.is_empty() => {
            return Ok(invalid_argument(
                "a version-id marker cannot be specified without a key marker",
            ));
        }
        Some(v) => match tx
            .query_opt(
                "SELECT id FROM objects WHERE bucket = $1 AND key = $2 AND version_id = $3",
                &[&bucket, &key_marker, &v],
            )
            .await?
        {
            Some(row) => Some(row.get(0)),
            None => return Ok(invalid_argument("invalid version id specified")),
        },
    };

    // One sorted, paginated stream of entries: each version or delete marker of
    // a leaf key is an entry of its own, while all versions under a common prefix
    // collapse into a single entry (so a folder counts once toward max-keys and
    // is never split across pages). Tokens are computed as in ListObjects; see
    // there for the delimiter handling. A folder's `key` is its greatest key, the
    // cursor that skips the whole folder when handed back as the key-marker.
    //
    // The cursor is (key > marker) or, within the marker's own key, (id below the
    // version marker's): versions of a key are ordered newest (highest id) first.
    // We fetch one extra row (LIMIT max_keys + 1) purely to detect truncation.
    let limit = max_keys + 1;
    let delim = delimiter.unwrap_or("");
    let rows = tx
        .query(
            "WITH t AS (
                 SELECT id, key, version_id, is_latest, is_delete_marker, size, etag,
                        to_char(last_modified AT TIME ZONE 'UTC',
                                'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS last_modified,
                        CASE WHEN $3 <> '' AND position($3 IN substr(key, length($2) + 1)) > 0
                             THEN $2 || substr(substr(key, length($2) + 1), 1,
                                               position($3 IN substr(key, length($2) + 1)) + length($3) - 1)
                             ELSE key
                        END AS token,
                        ($3 <> '' AND position($3 IN substr(key, length($2) + 1)) > 0) AS is_prefix
                 FROM objects
                 WHERE bucket = $1 AND starts_with(key, $2)
                   AND (key > $4 OR (key = $4 AND id < $5))
             )
             SELECT token, true AS is_prefix, max(key) AS key, NULL::bigint AS id,
                    NULL::text AS version_id, NULL::bool AS is_latest,
                    NULL::bool AS is_delete_marker, NULL::bigint AS size,
                    NULL::text AS etag, NULL::text AS last_modified
             FROM t WHERE is_prefix GROUP BY token
             UNION ALL
             SELECT token, false, key, id, version_id, is_latest, is_delete_marker, size,
                    etag, last_modified
             FROM t WHERE NOT is_prefix
             ORDER BY token, id DESC NULLS FIRST
             LIMIT $6",
            &[&bucket, &prefix, &delim, &key_marker, &marker_id, &limit],
        )
        .await?;
    tx.commit().await?;
    drop(client);

    // The extra row (if present) means there's more; keep only max_keys of them.
    let truncated = rows.len() as i64 > max_keys;
    let kept = &rows[..(max_keys as usize).min(rows.len())];

    let mut entries = String::new();
    let mut prefixes = String::new();
    for row in kept {
        if row.get::<_, bool>("is_prefix") {
            prefixes.push_str(&format!(
                "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
                xml_escape(row.get("token"))
            ));
            continue;
        }
        let key: &str = row.get("key");
        let version_id: &str = row.get("version_id");
        let is_latest: bool = row.get("is_latest");
        let last_modified: &str = row.get("last_modified");
        let common = format!(
            "<Key>{}</Key><VersionId>{}</VersionId><IsLatest>{is_latest}</IsLatest>\
             <LastModified>{last_modified}</LastModified>",
            xml_escape(key),
            xml_escape(version_id),
        );
        if row.get::<_, bool>("is_delete_marker") {
            entries.push_str(&format!("<DeleteMarker>{common}{OWNER}</DeleteMarker>"));
        } else {
            let etag: &str = row.get("etag");
            let size: i64 = row.get("size");
            entries.push_str(&format!(
                "<Version>{common}<ETag>\"{}\"</ETag><Size>{size}</Size>\
                 <StorageClass>STANDARD</StorageClass>{OWNER}</Version>",
                xml_escape(etag),
            ));
        }
    }

    let mut body = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <ListVersionsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    body.push_str(&format!("<Name>{}</Name>", xml_escape(bucket)));
    body.push_str(&format!("<Prefix>{}</Prefix>", xml_escape(prefix)));
    body.push_str(&format!("<KeyMarker>{}</KeyMarker>", xml_escape(key_marker)));
    body.push_str(&format!(
        "<VersionIdMarker>{}</VersionIdMarker>",
        xml_escape(version_id_marker.unwrap_or(""))
    ));
    if let Some(d) = delimiter {
        body.push_str(&format!("<Delimiter>{}</Delimiter>", xml_escape(d)));
    }
    body.push_str(&format!("<MaxKeys>{max_keys}</MaxKeys>"));
    body.push_str(&format!("<IsTruncated>{truncated}</IsTruncated>"));
    // The next page resumes after the last entry kept: after that version of its
    // key, or past a whole folder. An empty page (max_keys == 0) can't advance on
    // its own, so it hands back the incoming markers.
    if truncated {
        let (next_key, next_version) = match kept.last() {
            Some(row) if row.get::<_, bool>("is_prefix") => (row.get("key"), None),
            Some(row) => (row.get("key"), Some(row.get("version_id"))),
            None => (key_marker, version_id_marker),
        };
        body.push_str(&format!(
            "<NextKeyMarker>{}</NextKeyMarker>",
            xml_escape(next_key)
        ));
        if let Some(v) = next_version {
            body.push_str(&format!(
                "<NextVersionIdMarker>{}</NextVersionIdMarker>",
                xml_escape(v)
            ));
        }
    }
    body.push_str(&entries);
    body.push_str(&prefixes);
    body.push_str("</ListVersionsResult>");
    Ok(xml_ok(body))
}

/// The fixed owner Cairn reports, matching the ACL stub.
const OWNER: &str = "<Owner><ID>cairn</ID><DisplayName>cairn</DisplayName></Owner>";

fn invalid_argument(message: &str) -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::BAD_REQUEST, "InvalidArgument", message)
}
