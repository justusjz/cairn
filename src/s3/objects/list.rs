use anyhow::Ok;
use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::{
    App,
    s3::util::{format_s3_error, xml_escape, xml_ok},
};

pub async fn list_objects(
    app: &App,
    bucket: &str,
    prefix: &str,
    delimiter: Option<&str>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let mut client = app.pool.get().await?;
    let tx = client.transaction().await?;

    let exists = tx
        .query_opt("SELECT 1 FROM buckets WHERE name = $1", &[&bucket])
        .await?;
    if exists.is_none() {
        return Ok(format_s3_error(StatusCode::NOT_FOUND, "NoSuchBucket", ""));
    }

    // Leaf objects: keys under the prefix whose remainder (the part after the
    // prefix) contains no delimiter. With no delimiter, every matching key is a
    // leaf. LastModified is the ISO-8601 listing format here, distinct from the
    // RFC-1123 `Last-Modified` *header* used by GET/HEAD.
    let contents = match delimiter {
        Some(d) if !d.is_empty() => {
            tx
                .query(
                    "SELECT key, size, etag,
                            to_char(last_modified AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')
                     FROM objects
                     WHERE bucket = $1
                       AND starts_with(key, $2)
                       AND position($3 IN substr(key, length($2) + 1)) = 0
                     ORDER BY key",
                    &[&bucket, &prefix, &d],
                )
                .await?
        }
        _ => {
            tx
                .query(
                    "SELECT key, size, etag,
                            to_char(last_modified AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')
                     FROM objects
                     WHERE bucket = $1 AND starts_with(key, $2)
                     ORDER BY key",
                    &[&bucket, &prefix],
                )
                .await?
        }
    };

    // Common prefixes ("folders"): for keys whose post-prefix remainder contains
    // the delimiter, roll them up to prefix + (remainder up to and including the
    // first delimiter). Done in Postgres — the DISTINCT happens server-side, so
    // we only ship the handful of distinct prefixes, never the rolled-up keys.
    let common_prefixes = match delimiter {
        Some(d) if !d.is_empty() => {
            tx.query(
                "SELECT DISTINCT
                            $2 || substr(rest, 1, position($3 IN rest) + length($3) - 1) AS cp
                     FROM (
                         SELECT substr(key, length($2) + 1) AS rest
                         FROM objects
                         WHERE bucket = $1 AND starts_with(key, $2)
                     ) s
                     WHERE position($3 IN rest) > 0
                     ORDER BY cp",
                &[&bucket, &prefix, &d],
            )
            .await?
        }
        _ => Vec::new(),
    };
    tx.commit().await?;
    drop(client);

    let key_count = contents.len() + common_prefixes.len();

    let mut body = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    body.push_str(&format!("<Name>{}</Name>", xml_escape(bucket)));
    body.push_str(&format!("<Prefix>{}</Prefix>", xml_escape(prefix)));
    if let Some(d) = delimiter {
        body.push_str(&format!("<Delimiter>{}</Delimiter>", xml_escape(d)));
    }
    body.push_str("<MaxKeys>1000</MaxKeys>");
    body.push_str(&format!("<KeyCount>{key_count}</KeyCount>"));
    // TODO: pagination is unbounded — we always return everything and never emit
    // a continuation token / marker (which differ between list v1 and v2). Fine
    // until buckets get large.
    body.push_str("<IsTruncated>false</IsTruncated>");
    for row in &contents {
        let key: String = row.get(0);
        let size: i64 = row.get(1);
        let etag: String = row.get(2);
        let last_modified: String = row.get(3);
        body.push_str(&format!(
            "<Contents><Key>{}</Key><LastModified>{}</LastModified>\
             <ETag>\"{}\"</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>",
            xml_escape(&key),
            last_modified,
            xml_escape(&etag),
            size,
        ));
    }
    for row in &common_prefixes {
        let cp: String = row.get(0);
        body.push_str(&format!(
            "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
            xml_escape(&cp)
        ));
    }
    body.push_str("</ListBucketResult>");
    Ok(xml_ok(body))
}
