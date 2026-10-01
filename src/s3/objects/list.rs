use anyhow::Ok;
use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::{
    App,
    s3::util::{encode_continuation_token, format_s3_error, xml_escape, xml_ok},
};

/// S3's cap on keys returned per listing, and the default when `max-keys` is
/// unspecified — both are 1000.
pub const MAX_KEYS_LIMIT: i64 = 1000;

/// Which listing dialect the client used — selects the response envelope. The
/// underlying query is identical; only the echoed/cursor elements differ.
pub enum ListVersion {
    /// ListObjects (v1): echoes `<Marker>`, emits `<NextMarker>` when truncated.
    V1,
    /// ListObjectsV2: emits `<KeyCount>`, echoes `<ContinuationToken>` /
    /// `<StartAfter>`, and emits `<NextContinuationToken>` when truncated.
    V2 {
        continuation_token: Option<String>,
        start_after: Option<String>,
    },
}

pub async fn list_objects(
    app: &App,
    bucket: &str,
    prefix: &str,
    delimiter: Option<&str>,
    marker: &str,
    max_keys: i64,
    version: ListVersion,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let mut client = app.pool.get().await?;
    let tx = client.transaction().await?;

    let exists = tx
        .query_opt("SELECT 1 FROM buckets WHERE name = $1", &[&bucket])
        .await?;
    if exists.is_none() {
        return Ok(format_s3_error(StatusCode::NOT_FOUND, "NoSuchBucket", ""));
    }

    // Build the listing as one sorted, deduped, paginated stream of "tokens". A
    // token is the key itself (a leaf) or, when a delimiter is set and the key's
    // post-prefix remainder contains it, the rolled-up folder `prefix + (remainder
    // through the first delimiter)` (a common prefix). GROUP BY collapses each
    // folder's keys into a single row, so a folder counts as exactly one item
    // toward max-keys and is never split across a page boundary.
    //
    // `resume_key = max(key)` is the cursor we hand back: for a leaf it's the key;
    // for a folder it's that folder's greatest key. Feeding it back as `key >
    // marker` skips the whole exhausted folder (no duplicate) yet lets a mid-group
    // `start-after` re-show the folder — see the cursor handling in the router.
    //
    // `key > $4` resumes after the cursor; the empty delimiter ($3) disables
    // rollup (note: `position('' IN …)` is 1 in Postgres, so the `$3 <> ''` guard
    // is load-bearing). We fetch one extra row (LIMIT max_keys + 1) purely to
    // detect truncation.
    let limit = max_keys + 1;
    let delim = delimiter.unwrap_or("");
    let rows = tx
        .query(
            "SELECT token,
                    bool_or(is_prefix) AS is_prefix,
                    max(key) AS resume_key,
                    max(size) AS size,
                    max(etag) AS etag,
                    max(last_modified) AS last_modified
             FROM (
                 SELECT key, size, etag,
                        to_char(last_modified AT TIME ZONE 'UTC',
                                'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS last_modified,
                        CASE WHEN $3 <> '' AND position($3 IN substr(key, length($2) + 1)) > 0
                             THEN $2 || substr(substr(key, length($2) + 1), 1,
                                               position($3 IN substr(key, length($2) + 1)) + length($3) - 1)
                             ELSE key
                        END AS token,
                        ($3 <> '' AND position($3 IN substr(key, length($2) + 1)) > 0) AS is_prefix
                 FROM objects
                 WHERE bucket = $1 AND is_latest AND NOT is_delete_marker
                   AND starts_with(key, $2) AND key > $4
             ) t
             GROUP BY token
             ORDER BY token
             LIMIT $5",
            &[&bucket, &prefix, &delim, &marker, &limit],
        )
        .await?;
    tx.commit().await?;
    drop(client);

    // The extra row (if present) means there's more; keep only max_keys of them.
    let truncated = rows.len() as i64 > max_keys;
    let kept = &rows[..(max_keys as usize).min(rows.len())];
    let key_count = kept.len();

    // The next cursor is the last kept item's resume_key. An empty page
    // (max_keys == 0) can't advance on its own, so reuse the incoming marker.
    let next_marker: Option<String> = truncated.then(|| {
        kept.last()
            .map(|r| r.get::<_, String>("resume_key"))
            .unwrap_or_else(|| marker.to_string())
    });

    // Split the sorted stream into the two output lists (each stays sorted).
    let mut contents = String::new();
    let mut prefixes = String::new();
    for row in kept {
        let token: String = row.get("token");
        if row.get::<_, bool>("is_prefix") {
            prefixes.push_str(&format!(
                "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
                xml_escape(&token)
            ));
        } else {
            let size: i64 = row.get("size");
            let etag: String = row.get("etag");
            let last_modified: String = row.get("last_modified");
            contents.push_str(&format!(
                "<Contents><Key>{}</Key><LastModified>{}</LastModified>\
                 <ETag>\"{}\"</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>",
                xml_escape(&token),
                last_modified,
                xml_escape(&etag),
                size,
            ));
        }
    }

    let mut body = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    body.push_str(&format!("<Name>{}</Name>", xml_escape(bucket)));
    body.push_str(&format!("<Prefix>{}</Prefix>", xml_escape(prefix)));
    if let Some(d) = delimiter {
        body.push_str(&format!("<Delimiter>{}</Delimiter>", xml_escape(d)));
    }
    body.push_str(&format!("<MaxKeys>{max_keys}</MaxKeys>"));
    // Version-specific cursor elements. v1 speaks markers; v2 speaks opaque
    // continuation tokens and reports KeyCount.
    match &version {
        ListVersion::V1 => {
            body.push_str(&format!("<Marker>{}</Marker>", xml_escape(marker)));
            if let Some(nm) = &next_marker {
                body.push_str(&format!("<NextMarker>{}</NextMarker>", xml_escape(nm)));
            }
        }
        ListVersion::V2 {
            continuation_token,
            start_after,
        } => {
            body.push_str(&format!("<KeyCount>{key_count}</KeyCount>"));
            if let Some(token) = continuation_token {
                body.push_str(&format!(
                    "<ContinuationToken>{}</ContinuationToken>",
                    xml_escape(token)
                ));
            }
            if let Some(sa) = start_after {
                body.push_str(&format!("<StartAfter>{}</StartAfter>", xml_escape(sa)));
            }
            if let Some(nm) = &next_marker {
                body.push_str(&format!(
                    "<NextContinuationToken>{}</NextContinuationToken>",
                    encode_continuation_token(nm)
                ));
            }
        }
    }
    body.push_str(&format!("<IsTruncated>{truncated}</IsTruncated>"));
    body.push_str(&contents);
    body.push_str(&prefixes);
    body.push_str("</ListBucketResult>");
    Ok(xml_ok(body))
}
