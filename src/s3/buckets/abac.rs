//! A bucket's ABAC (attribute-based access control): GetBucketAbac and
//! PutBucketAbac (`?abac`). Enabled, the bucket's tags are its and its
//! objects' `aws:ResourceTag`s and `s3:BucketTag`s (see `s3::access`), and
//! only S3 Control's TagResource and UntagResource change them (see
//! `tagging`, `resource_tags`). Disabled by default. As S3 answers (probed,
//! see `plans/abac.md`):
//!
//! - `<AbacStatus><Status>Enabled|Disabled</Status></AbacStatus>`, the
//!   status case-sensitive; any other, or none, is MalformedXML, as is a
//!   document that isn't XML. The root element's name and namespace aren't
//!   checked.
//! - An empty body is MissingRequestBodyError. No checksum is required.
//! - PutBucketAbac answers 200, empty.

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::db::Cached;
use crate::{
    App,
    s3::buckets::tagging::no_such_bucket,
    s3::util::{format_s3_error, xml_ok},
};

/// GetBucketAbac.
pub async fn get_bucket_abac(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached("SELECT abac FROM buckets WHERE name = $1", &[&bucket])
        .await?;
    Ok(match row {
        None => no_such_bucket(),
        Some(row) => xml_ok(document(row.get(0))),
    })
}

/// PutBucketAbac: `PUT /{bucket}?abac` with an `<AbacStatus>` body.
pub async fn put_bucket_abac(
    app: &App,
    bucket: &str,
    body: Bytes,
) -> anyhow::Result<Response<Full<Bytes>>> {
    if body.is_empty() {
        return Ok(format_s3_error(
            StatusCode::BAD_REQUEST,
            "MissingRequestBodyError",
            "Request Body is empty",
        ));
    }
    let Some(enabled) = parse(&body) else {
        return Ok(format_s3_error(
            StatusCode::BAD_REQUEST,
            "MalformedXML",
            "The XML you provided was not well-formed or did not validate against our published schema",
        ));
    };
    let exists: bool = app
        .pool
        .get()
        .await?
        .query_one_cached(
            "SELECT pg_temp.cairn_set_bucket_abac($1, $2)",
            &[&bucket, &enabled],
        )
        .await?
        .get(0);
    Ok(match exists {
        true => Response::new(Full::new(Bytes::new())),
        false => no_such_bucket(),
    })
}

/// Whether an `<AbacStatus>` document enables ABAC, or `None` if it isn't
/// one S3 takes.
fn parse(body: &[u8]) -> Option<bool> {
    let text = std::str::from_utf8(body).ok()?;
    let doc = roxmltree::Document::parse(text).ok()?;
    let mut statuses = doc
        .root_element()
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "Status");
    let status = statuses.next()?;
    if statuses.next().is_some() {
        return None;
    }
    match status.text().unwrap_or_default() {
        "Enabled" => Some(true),
        "Disabled" => Some(false),
        _ => None,
    }
}

/// The `<AbacStatus>` document GetBucketAbac answers with.
fn document(enabled: bool) -> String {
    let status = if enabled { "Enabled" } else { "Disabled" };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <AbacStatus xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>{status}</Status></AbacStatus>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_as_s3_does() {
        let ns = |status: &str| {
            format!(
                r#"<AbacStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>{status}</Status></AbacStatus>"#
            )
        };
        assert_eq!(parse(ns("Enabled").as_bytes()), Some(true));
        assert_eq!(parse(ns("Disabled").as_bytes()), Some(false));
        for status in ["enabled", "ENABLED", "", "On", "Suspended"] {
            assert_eq!(parse(ns(status).as_bytes()), None, "{status}");
        }
        assert_eq!(
            parse(b"<AbacStatus><Status>Disabled</Status></AbacStatus>"),
            Some(false)
        );
        assert_eq!(parse(b"<Foo><Status>Enabled</Status></Foo>"), Some(true));
        assert_eq!(parse(b"<AbacStatus></AbacStatus>"), None);
        assert_eq!(parse(b"<AbacStatus><Status>"), None);
        assert!(document(false).contains("<Status>Disabled</Status>"));
    }
}
