use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::db::Cached;
use crate::{
    App,
    s3::util::{
        Encoding, Timestamp, encode_continuation_token, format_s3_error, xml_escape, xml_ok,
    },
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
        /// Whether each key's owner is listed (`fetch-owner`), as v1 always does.
        fetch_owner: bool,
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
                    extract(epoch FROM last_modified)::float8, is_delete_marker,
                    sse_s3, sse_kms_key_id, sse_kms_data_key, sse_kms_sealed
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
    let mut entries = Vec::with_capacity(kept.len());
    for r in kept {
        entries.push(
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
                let key: String = r.get(0);
                ListEntry::Object {
                    etag: listed_etag(app, bucket, &key, r, 4, 8).await?,
                    key,
                    size: r.get(3),
                    last_modified: timestamp(r).expect("a key has a last-modified time"),
                    delete_marker: r.get(7),
                }
            },
        );
    }
    Ok(Some(Listing {
        entries,
        truncated,
        next_marker,
    }))
}

/// The ETag of a listed object at `bucket`/`key`, as clients know it: the one
/// in `row`'s column `etag`, decrypted if the row's SSE-S3 columns (`sse_s3,
/// sse_kms_key_id, sse_kms_data_key, sse_kms_sealed`, from `sse` on) say it's
/// sealed. A listing fails if the KMS can't open an object's key (which a node
/// usually has already: see `kms`).
pub(crate) async fn listed_etag(
    app: &App,
    bucket: &str,
    key: &str,
    row: &tokio_postgres::Row,
    etag: usize,
    sse: usize,
) -> anyhow::Result<Option<String>> {
    let stored: Option<String> = row.get(etag);
    let (Some(stored), Some(true)) = (stored, row.get::<_, Option<bool>>(sse)) else {
        return Ok(row.get(etag));
    };
    let encryption = crate::s3::sse::Stored::S3(crate::s3::sse::Envelope {
        key_id: row.get(sse + 1),
        data_key: row.get(sse + 2),
        sealed: row.get(sse + 3),
        context: None,
    });
    match crate::s3::sse::plain_etag(app, &encryption, &stored, bucket, key).await? {
        Ok(etag) => Ok(Some(etag)),
        Err(_) => anyhow::bail!("the KMS couldn't open the key of {bucket}/{key}, to list its ETag"),
    }
}

/// ListObjects and ListObjectsV2: a page of `list`, as S3's XML, with keys and
/// the like written as `encoding` says.
#[allow(clippy::too_many_arguments)]
pub async fn list_objects(
    app: &App,
    bucket: &str,
    prefix: &str,
    delimiter: Option<&str>,
    marker: &str,
    max_keys: i64,
    version: ListVersion,
    encoding: Encoding,
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
    // A page of none tells nothing about what's left, so S3 says there's
    // nothing (`max-keys=0`).
    let truncated = listing.truncated && max_keys > 0;
    let next_marker = listing.next_marker.filter(|_| truncated);
    let owner = match &version {
        ListVersion::V1
        | ListVersion::V2 {
            fetch_owner: true, ..
        } => "<Owner><ID>cairn</ID><DisplayName>cairn</DisplayName></Owner>",
        ListVersion::V2 { .. } => "",
    };

    // Split the sorted stream into the two output lists (each stays sorted).
    let mut contents = String::new();
    let mut prefixes = String::new();
    for entry in &listing.entries {
        match entry {
            ListEntry::Prefix { prefix, .. } => prefixes.push_str(&format!(
                "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
                encoding.xml(prefix)
            )),
            ListEntry::Object {
                key,
                size,
                etag,
                last_modified,
                ..
            } => contents.push_str(&format!(
                "<Contents><Key>{}</Key><LastModified>{}</LastModified>\
                 <ETag>\"{}\"</ETag><Size>{}</Size>{owner}<StorageClass>STANDARD</StorageClass></Contents>",
                encoding.xml(key),
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
    // ListObjects (v1) doesn't encode the prefix it echoes, as S3 doesn't (nor
    // do SDKs decode it); v2 does.
    let echoed_prefix = match &version {
        ListVersion::V1 => xml_escape(prefix),
        ListVersion::V2 { .. } => encoding.xml(prefix),
    };
    body.push_str(&format!("<Prefix>{echoed_prefix}</Prefix>"));
    if let Some(d) = delimiter {
        body.push_str(&format!("<Delimiter>{}</Delimiter>", encoding.xml(d)));
    }
    body.push_str(&format!("<MaxKeys>{max_keys}</MaxKeys>"));
    body.push_str(encoding.element());
    // Version-specific cursor elements. v1 speaks markers; v2 speaks opaque
    // continuation tokens and reports KeyCount.
    match &version {
        ListVersion::V1 => {
            body.push_str(&format!("<Marker>{}</Marker>", encoding.xml(marker)));
            if let Some(nm) = &next_marker {
                body.push_str(&format!("<NextMarker>{}</NextMarker>", encoding.xml(nm)));
            }
        }
        ListVersion::V2 {
            continuation_token,
            start_after,
            ..
        } => {
            body.push_str(&format!("<KeyCount>{key_count}</KeyCount>"));
            if let Some(token) = continuation_token {
                body.push_str(&format!(
                    "<ContinuationToken>{}</ContinuationToken>",
                    xml_escape(token)
                ));
            }
            if let Some(sa) = start_after {
                body.push_str(&format!("<StartAfter>{}</StartAfter>", encoding.xml(sa)));
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
