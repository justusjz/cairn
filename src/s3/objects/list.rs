use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::db::Cached;
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
    /// up, and their totals, if the query asked for them.
    Prefix {
        prefix: String,
        totals: Option<PrefixTotals>,
    },
}

/// What a common prefix holds: how many keys, their total size, and when the
/// last of them changed.
pub struct PrefixTotals {
    pub objects: i64,
    pub bytes: i64,
    pub last_modified: Timestamp,
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
    /// Work out each common prefix's totals, which costs reading all of its
    /// keys (the dashboard shows them; S3 doesn't).
    pub totals: bool,
}

/// A page of the current versions in `bucket`, or `None` if there's no such
/// bucket. Shared by ListObjects(V2) and the dashboard.
pub async fn list(app: &App, bucket: &str, q: &ListQuery<'_>) -> anyhow::Result<Option<Listing>> {
    let mut client = app.pool.get().await?;
    let tx = client.transaction().await?;

    let exists = tx
        .query_opt_cached("SELECT 1 FROM buckets WHERE name = $1", &[&bucket])
        .await?;
    if exists.is_none() {
        return Ok(None);
    }

    // One page, as `cairn_list_current` walks it, plus one entry to tell
    // whether there's more. Markers work as in MinIO: the next page resumes
    // after this one's last entry, a key or a common prefix.
    let limit = (q.max_keys + 1) as i32;
    let delim = q.delimiter.unwrap_or("");
    let rows = tx
        .query_cached(
            "SELECT name, is_prefix, objects, size, etag,
                    to_char(last_modified AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'),
                    extract(epoch FROM last_modified)::float8, is_delete_marker
             FROM pg_temp.cairn_list_current($1, $2, $3, $4, $5, $6, $7)",
            &[&bucket, &q.prefix, &delim, &q.marker, &limit, &q.delete_markers, &q.totals],
        )
        .await?;
    tx.commit().await?;
    drop(client);

    // The extra row (if present) means there's more; keep only max_keys of them.
    let truncated = rows.len() as i64 > q.max_keys;
    let kept = &rows[..(q.max_keys as usize).min(rows.len())];

    // The next marker is the last kept entry. An empty page (max_keys == 0)
    // can't advance on its own, so it reuses the incoming marker.
    let next_marker = truncated.then(|| {
        kept.last()
            .map(|r| r.get::<_, String>(0))
            .unwrap_or_else(|| q.marker.to_string())
    });
    let timestamp = |r: &tokio_postgres::Row| {
        Some(Timestamp {
            iso: r.get::<_, Option<String>>(5)?,
            epoch: r.get::<_, Option<f64>>(6)?,
        })
    };
    let entries = kept
        .iter()
        .map(|r| {
            if r.get::<_, bool>(1) {
                let totals = timestamp(r).map(|last_modified| PrefixTotals {
                    objects: r.get(2),
                    bytes: r.get(3),
                    last_modified,
                });
                ListEntry::Prefix {
                    prefix: r.get(0),
                    totals,
                }
            } else {
                ListEntry::Object {
                    key: r.get(0),
                    size: r.get(3),
                    etag: r.get(4),
                    last_modified: timestamp(r).expect("a key has a last-modified time"),
                    delete_marker: r.get(7),
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
        totals: false,
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
