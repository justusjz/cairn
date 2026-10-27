use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::{
    App,
    s3::util::{Timestamp, encode_continuation_token, format_s3_error, xml_escape, xml_ok},
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

/// One page of a listing: the keys, and the common prefixes their names roll
/// up into, in order.
pub struct Listing {
    pub entries: Vec<ListEntry>,
    /// Whether there's more after this page.
    pub truncated: bool,
    /// What to resume after for the next page, if there is one.
    pub next_marker: Option<String>,
}

pub enum ListEntry {
    /// A key's current version.
    Object {
        key: String,
        size: i64,
        /// None for a delete marker.
        etag: Option<String>,
        last_modified: Timestamp,
        delete_marker: bool,
    },
    /// The keys whose names continue past `prefix` with the delimiter, rolled
    /// up: how many there are, their total size, and when the last changed.
    Prefix {
        prefix: String,
        objects: i64,
        bytes: i64,
        last_modified: Timestamp,
    },
}

/// What to list.
pub struct ListQuery<'a> {
    pub prefix: &'a str,
    /// Roll keys up at the first occurrence of this after the prefix.
    pub delimiter: Option<&'a str>,
    /// Resume after this key.
    pub marker: &'a str,
    pub max_keys: i64,
    /// Also list the keys whose current version is a delete marker (which S3
    /// leaves out).
    pub delete_markers: bool,
}

/// A page of the current versions in `bucket`, or `None` if there's no such
/// bucket. Shared by ListObjects(V2) and the dashboard.
pub async fn list(app: &App, bucket: &str, q: &ListQuery<'_>) -> anyhow::Result<Option<Listing>> {
    let mut client = app.pool.get().await?;
    let tx = client.transaction().await?;

    let exists = tx
        .query_opt("SELECT 1 FROM buckets WHERE name = $1", &[&bucket])
        .await?;
    if exists.is_none() {
        return Ok(None);
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
    // detect truncation. For a leaf, the aggregates are just its own values.
    let limit = q.max_keys + 1;
    let delim = q.delimiter.unwrap_or("");
    let rows = tx
        .query(
            "SELECT token,
                    bool_or(is_prefix),
                    max(key),
                    count(*),
                    sum(size)::bigint,
                    max(etag),
                    to_char(max(last_modified) AT TIME ZONE 'UTC',
                            'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'),
                    extract(epoch FROM max(last_modified))::float8,
                    bool_or(is_delete_marker)
             FROM (
                 SELECT key, size, etag, last_modified, is_delete_marker,
                        CASE WHEN $3 <> '' AND position($3 IN substr(key, length($2) + 1)) > 0
                             THEN $2 || substr(substr(key, length($2) + 1), 1,
                                               position($3 IN substr(key, length($2) + 1)) + length($3) - 1)
                             ELSE key
                        END AS token,
                        ($3 <> '' AND position($3 IN substr(key, length($2) + 1)) > 0) AS is_prefix
                 FROM objects
                 WHERE bucket = $1 AND is_latest AND (NOT is_delete_marker OR $6)
                   AND starts_with(key, $2) AND key > $4
             ) t
             GROUP BY token
             ORDER BY token
             LIMIT $5",
            &[&bucket, &q.prefix, &delim, &q.marker, &limit, &q.delete_markers],
        )
        .await?;
    tx.commit().await?;
    drop(client);

    // The extra row (if present) means there's more; keep only max_keys of them.
    let truncated = rows.len() as i64 > q.max_keys;
    let kept = &rows[..(q.max_keys as usize).min(rows.len())];

    // The next cursor is the last kept item's resume_key. An empty page
    // (max_keys == 0) can't advance on its own, so reuse the incoming marker.
    let next_marker = truncated.then(|| {
        kept.last()
            .map(|r| r.get::<_, String>(2))
            .unwrap_or_else(|| q.marker.to_string())
    });
    let entries = kept
        .iter()
        .map(|r| {
            let last_modified = Timestamp {
                iso: r.get(6),
                epoch: r.get(7),
            };
            if r.get::<_, bool>(1) {
                ListEntry::Prefix {
                    prefix: r.get(0),
                    objects: r.get(3),
                    bytes: r.get(4),
                    last_modified,
                }
            } else {
                ListEntry::Object {
                    key: r.get(0),
                    size: r.get(4),
                    etag: r.get(5),
                    last_modified,
                    delete_marker: r.get(8),
                }
            }
        })
        .collect();
    Ok(Some(Listing {
        entries,
        truncated,
        next_marker,
    }))
}

/// ListObjects and ListObjectsV2: a page of `list`, as S3's XML.
pub async fn list_objects(
    app: &App,
    bucket: &str,
    prefix: &str,
    delimiter: Option<&str>,
    marker: &str,
    max_keys: i64,
    version: ListVersion,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let query = ListQuery {
        prefix,
        delimiter,
        marker,
        max_keys,
        delete_markers: false,
    };
    let Some(listing) = list(app, bucket, &query).await? else {
        return Ok(format_s3_error(StatusCode::NOT_FOUND, "NoSuchBucket", ""));
    };
    let key_count = listing.entries.len();
    let next_marker = listing.next_marker;
    let truncated = listing.truncated;

    // Split the sorted stream into the two output lists (each stays sorted).
    let mut contents = String::new();
    let mut prefixes = String::new();
    for entry in &listing.entries {
        match entry {
            ListEntry::Prefix { prefix, .. } => prefixes.push_str(&format!(
                "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
                xml_escape(prefix)
            )),
            ListEntry::Object {
                key,
                size,
                etag,
                last_modified,
                ..
            } => contents.push_str(&format!(
                "<Contents><Key>{}</Key><LastModified>{}</LastModified>\
                 <ETag>\"{}\"</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>",
                xml_escape(key),
                last_modified.iso,
                xml_escape(etag.as_deref().unwrap_or("")),
                size,
            )),
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
