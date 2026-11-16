//! A bucket's server access logging configuration: PutBucketLogging and
//! GetBucketLogging (`?logging`). A `<BucketLoggingStatus>` with a
//! `<LoggingEnabled>` names the bucket the logs go to (the target), the
//! prefix of their keys, and how the rest of their keys is made; one without
//! turns logging off.
//!
//! The target must exist and be of the bucket's account, as in S3. Whether
//! its policy lets the logs be written (by the `logging.s3.amazonaws.com`
//! service, see `s3::service`) isn't checked here: as in S3, logs it doesn't
//! allow are just not delivered. `TargetGrants` are refused, as S3 refuses
//! them for a target whose ACLs are disabled, as every Cairn bucket's are.
//!
//! Kept as JSON in the bucket's row, set by a plain UPDATE of it (T64), as
//! its website configuration is.

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use serde::{Deserialize, Serialize};

use crate::{
    App,
    db::Cached,
    s3::util::{error_document, format_s3_error, xml_escape, xml_ok},
};

/// The largest configuration document taken.
const MAX_DOCUMENT: usize = 64 << 10;

/// Where a bucket's access logs go (`<LoggingEnabled>`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Logging {
    /// The bucket they're written to.
    pub target_bucket: String,
    /// What their keys begin with (may be empty).
    pub target_prefix: String,
    /// How the rest of their keys is made, if it was given
    /// (`TargetObjectKeyFormat`): if not, as `SimplePrefix`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_format: Option<KeyFormat>,
}

/// How a log's key is made, after the target prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyFormat {
    /// `YYYY-mm-DD-HH-MM-SS-UniqueString`.
    Simple,
    /// `SourceAccountId/SourceRegion/SourceBucket/YYYY/MM/DD/` and then the
    /// simple key, dated by the given time, if it was given (else S3's
    /// default, the time of the events).
    Partitioned(Option<DateSource>),
}

/// Which time a partitioned key's date is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DateSource {
    /// That of the events it logs.
    EventTime,
    /// That of the log's delivery.
    DeliveryTime,
}

impl DateSource {
    fn name(self) -> &'static str {
        match self {
            DateSource::EventTime => "EventTime",
            DateSource::DeliveryTime => "DeliveryTime",
        }
    }
}

/// Why a configuration is refused.
#[derive(Debug, PartialEq)]
pub enum Invalid {
    /// 400 MalformedXML: not the document S3's schema has.
    Malformed(String),
    /// 400 AccessControlListNotSupported: it has `TargetGrants`.
    Grants,
}

impl Invalid {
    fn response(&self) -> Response<Full<Bytes>> {
        match self {
            Invalid::Malformed(_) => format_s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "The XML you provided was not well-formed or did not validate against our published schema",
            ),
            Invalid::Grants => format_s3_error(
                StatusCode::BAD_REQUEST,
                "AccessControlListNotSupported",
                "The target bucket does not allow ACLs",
            ),
        }
    }
}

type Node<'a, 'i> = roxmltree::Node<'a, 'i>;

/// `node`'s only child `name`, if it has one; refused if it has several.
fn child<'a, 'i>(node: Node<'a, 'i>, name: &str) -> Result<Option<Node<'a, 'i>>, Invalid> {
    let mut found = node.children().filter(|n| n.is_element() && n.tag_name().name() == name);
    match (found.next(), found.next()) {
        (None, _) => Ok(None),
        (Some(child), None) => Ok(Some(child)),
        _ => Err(Invalid::Malformed(format!("more than one {name}"))),
    }
}

fn required_text(node: Node, name: &str) -> Result<String, Invalid> {
    let child = child(node, name)?.ok_or_else(|| Invalid::Malformed(format!("{} needs a {name}", node.tag_name().name())))?;
    Ok(child.text().unwrap_or("").to_owned())
}

/// Refuses the children of `node` that aren't among `known`.
fn only(node: Node, known: &[&str]) -> Result<(), Invalid> {
    match node.children().filter(|n| n.is_element()).find(|n| !known.contains(&n.tag_name().name())) {
        Some(n) => Err(Invalid::Malformed(format!("unknown element {}", n.tag_name().name()))),
        None => Ok(()),
    }
}

impl Logging {
    /// Parses a `<BucketLoggingStatus>`, as PutBucketLogging takes it:
    /// `None` if it turns logging off.
    pub fn parse(body: &str) -> Result<Option<Logging>, Invalid> {
        let doc = roxmltree::Document::parse(body).map_err(|_| Invalid::Malformed("not XML".to_owned()))?;
        let root = doc.root_element();
        if root.tag_name().name() != "BucketLoggingStatus" {
            return Err(Invalid::Malformed("not a BucketLoggingStatus".to_owned()));
        }
        only(root, &["LoggingEnabled"])?;
        let Some(enabled) = child(root, "LoggingEnabled")? else { return Ok(None) };
        only(enabled, &["TargetBucket", "TargetPrefix", "TargetGrants", "TargetObjectKeyFormat"])?;
        let target_bucket = required_text(enabled, "TargetBucket")?;
        let target_prefix = required_text(enabled, "TargetPrefix")?;
        if let Some(grants) = child(enabled, "TargetGrants")? {
            only(grants, &["Grant"])?;
            if grants.children().any(|n| n.is_element()) {
                return Err(Invalid::Grants);
            }
        }
        let key_format = match child(enabled, "TargetObjectKeyFormat")? {
            None => None,
            Some(format) => {
                only(format, &["SimplePrefix", "PartitionedPrefix"])?;
                match (child(format, "SimplePrefix")?, child(format, "PartitionedPrefix")?) {
                    (Some(simple), None) => {
                        only(simple, &[])?;
                        Some(KeyFormat::Simple)
                    }
                    (None, Some(partitioned)) => {
                        only(partitioned, &["PartitionDateSource"])?;
                        let source = match child(partitioned, "PartitionDateSource")? {
                            None => None,
                            Some(source) => match source.text().unwrap_or("") {
                                "EventTime" => Some(DateSource::EventTime),
                                "DeliveryTime" => Some(DateSource::DeliveryTime),
                                _ => return Err(Invalid::Malformed("PartitionDateSource is EventTime or DeliveryTime".to_owned())),
                            },
                        };
                        Some(KeyFormat::Partitioned(source))
                    }
                    _ => {
                        return Err(Invalid::Malformed(
                            "TargetObjectKeyFormat is either SimplePrefix or PartitionedPrefix".to_owned(),
                        ));
                    }
                }
            }
        };
        Ok(Some(Logging { target_bucket, target_prefix, key_format }))
    }

    /// The `<BucketLoggingStatus>` GetBucketLogging answers for `logging`.
    pub fn xml(logging: Option<&Logging>) -> String {
        let mut xml = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <BucketLoggingStatus xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
        );
        if let Some(logging) = logging {
            xml.push_str(&format!(
                "<LoggingEnabled><TargetBucket>{}</TargetBucket><TargetPrefix>{}</TargetPrefix>",
                xml_escape(&logging.target_bucket),
                xml_escape(&logging.target_prefix),
            ));
            match logging.key_format {
                None => {}
                Some(KeyFormat::Simple) => xml.push_str("<TargetObjectKeyFormat><SimplePrefix/></TargetObjectKeyFormat>"),
                Some(KeyFormat::Partitioned(None)) => {
                    xml.push_str("<TargetObjectKeyFormat><PartitionedPrefix/></TargetObjectKeyFormat>")
                }
                Some(KeyFormat::Partitioned(Some(source))) => xml.push_str(&format!(
                    "<TargetObjectKeyFormat><PartitionedPrefix><PartitionDateSource>{}</PartitionDateSource>\
                     </PartitionedPrefix></TargetObjectKeyFormat>",
                    source.name()
                )),
            }
            xml.push_str("</LoggingEnabled>");
        }
        xml.push_str("</BucketLoggingStatus>");
        xml
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a logging configuration serializes")
    }

    pub fn from_json(json: &str) -> serde_json::Result<Logging> {
        serde_json::from_str(json)
    }
}

/// The bucket's logging configuration: `None` if there's no such bucket,
/// `Some(None)` if it logs nothing.
pub async fn load(app: &App, bucket: &str) -> anyhow::Result<Option<Option<Logging>>> {
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached("SELECT logging FROM buckets WHERE name = $1", &[&bucket])
        .await?;
    let Some(row) = row else { return Ok(None) };
    let Some(json) = row.get::<_, Option<String>>(0) else { return Ok(Some(None)) };
    let logging = Logging::from_json(&json).map_err(|e| {
        anyhow::anyhow!("bucket {bucket}'s logging configuration doesn't parse (written by a newer Cairn?): {e}")
    })?;
    Ok(Some(Some(logging)))
}

/// GetBucketLogging: `GET /{bucket}?logging`. An empty
/// `<BucketLoggingStatus>` for a bucket that logs nothing, as in S3.
pub async fn get_bucket_logging(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    Ok(match load(app, bucket).await? {
        None => no_such_bucket(),
        Some(logging) => xml_ok(Logging::xml(logging.as_ref())),
    })
}

/// PutBucketLogging: `PUT /{bucket}?logging` with a `<BucketLoggingStatus>`
/// body, checked against its integrity headers (see `Payload`), of which S3
/// requires one. Replaces the bucket's configuration.
pub async fn put_bucket_logging(app: &App, bucket: &str, body: Bytes) -> anyhow::Result<Response<Full<Bytes>>> {
    if body.len() > MAX_DOCUMENT {
        return Ok(format_s3_error(StatusCode::BAD_REQUEST, "MaxMessageLengthExceeded", "Your request was too big."));
    }
    let parsed = std::str::from_utf8(&body).map_err(|_| Invalid::Malformed("not UTF-8".to_owned())).and_then(Logging::parse);
    let logging = match parsed {
        Ok(logging) => logging,
        Err(invalid) => return Ok(invalid.response()),
    };
    if let Some(logging) = &logging {
        let client = app.pool.get().await?;
        let names = [bucket, logging.target_bucket.as_str()];
        let rows = client
            .query_cached("SELECT name, account_id FROM buckets WHERE name = ANY($1)", &[&&names[..]])
            .await?;
        let owner = |name: &str| rows.iter().find(|r| r.get::<_, &str>(0) == name).map(|r| r.get::<_, String>(1));
        let Some(source_owner) = owner(bucket) else { return Ok(no_such_bucket()) };
        match owner(&logging.target_bucket) {
            None => return Ok(invalid_target(&logging.target_bucket, "The target bucket for logging does not exist")),
            Some(target_owner) if target_owner != source_owner => {
                return Ok(invalid_target(
                    &logging.target_bucket,
                    "The owner for the bucket to be logged and the target bucket must be the same.",
                ));
            }
            Some(_) => {}
        }
    }
    let config = logging.as_ref().map(Logging::to_json);
    let set: bool = app
        .pool
        .get()
        .await?
        .query_one_cached("SELECT pg_temp.cairn_set_logging($1, $2)", &[&bucket, &config])
        .await?
        .get(0);
    Ok(match set {
        true => Response::builder().status(StatusCode::OK).body(Full::new(Bytes::new())).unwrap(),
        false => no_such_bucket(),
    })
}

/// S3's 400 for a target bucket it won't log to.
fn invalid_target(target: &str, message: &str) -> Response<Full<Bytes>> {
    error_document(StatusCode::BAD_REQUEST, "InvalidTargetBucketForLogging", message, &[("TargetBucket", target.to_owned())])
}

fn no_such_bucket() -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::NOT_FOUND, "NoSuchBucket", "The specified bucket does not exist")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(inner: &str) -> Result<Option<Logging>, Invalid> {
        Logging::parse(&format!("<BucketLoggingStatus xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{inner}</BucketLoggingStatus>"))
    }

    fn enabled(inner: &str) -> Result<Option<Logging>, Invalid> {
        status(&format!("<LoggingEnabled>{inner}</LoggingEnabled>"))
    }

    const TARGET: &str = "<TargetBucket>logs</TargetBucket><TargetPrefix>src/</TargetPrefix>";

    #[test]
    fn without_logging_enabled_it_logs_nothing() {
        assert_eq!(status(""), Ok(None));
        assert_eq!(Logging::xml(None), "<?xml version=\"1.0\" encoding=\"UTF-8\"?><BucketLoggingStatus xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></BucketLoggingStatus>");
    }

    #[test]
    fn a_target_and_its_prefix() {
        let logging = enabled(TARGET).unwrap().unwrap();
        assert_eq!(logging, Logging { target_bucket: "logs".to_owned(), target_prefix: "src/".to_owned(), key_format: None });
        assert!(Logging::xml(Some(&logging)).contains(
            "<LoggingEnabled><TargetBucket>logs</TargetBucket><TargetPrefix>src/</TargetPrefix></LoggingEnabled>"
        ));
        // An empty prefix is one.
        let logging = enabled("<TargetBucket>logs</TargetBucket><TargetPrefix/>").unwrap().unwrap();
        assert_eq!(logging.target_prefix, "");
    }

    #[test]
    fn both_target_bucket_and_prefix_are_required() {
        assert!(matches!(enabled("<TargetBucket>logs</TargetBucket>"), Err(Invalid::Malformed(_))));
        assert!(matches!(enabled("<TargetPrefix>p</TargetPrefix>"), Err(Invalid::Malformed(_))));
    }

    #[test]
    fn key_formats() {
        let format = |inner: &str| enabled(&format!("{TARGET}<TargetObjectKeyFormat>{inner}</TargetObjectKeyFormat>"));
        assert_eq!(format("<SimplePrefix/>").unwrap().unwrap().key_format, Some(KeyFormat::Simple));
        assert_eq!(format("<PartitionedPrefix/>").unwrap().unwrap().key_format, Some(KeyFormat::Partitioned(None)));
        let delivery = format("<PartitionedPrefix><PartitionDateSource>DeliveryTime</PartitionDateSource></PartitionedPrefix>");
        let delivery = delivery.unwrap().unwrap();
        assert_eq!(delivery.key_format, Some(KeyFormat::Partitioned(Some(DateSource::DeliveryTime))));
        // As it's answered, it's parsed back.
        let xml = Logging::xml(Some(&delivery));
        assert_eq!(Logging::parse(&xml).unwrap().unwrap(), delivery);
        assert_eq!(Logging::from_json(&delivery.to_json()).unwrap(), delivery);
        // One or the other, and only S3's date sources.
        assert!(matches!(format(""), Err(Invalid::Malformed(_))));
        assert!(matches!(format("<SimplePrefix/><PartitionedPrefix/>"), Err(Invalid::Malformed(_))));
        let other = format("<PartitionedPrefix><PartitionDateSource>Now</PartitionDateSource></PartitionedPrefix>");
        assert!(matches!(other, Err(Invalid::Malformed(_))));
    }

    #[test]
    fn grants_are_refused() {
        let grant = "<TargetGrants><Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" \
                     xsi:type=\"Group\"><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee>\
                     <Permission>READ</Permission></Grant></TargetGrants>";
        assert_eq!(enabled(&format!("{TARGET}{grant}")), Err(Invalid::Grants));
        // None at all is no grant.
        assert!(enabled(&format!("{TARGET}<TargetGrants/>")).unwrap().is_some());
    }

    #[test]
    fn what_isnt_s3s_schema_is_malformed() {
        assert!(matches!(Logging::parse("<LoggingEnabled/>"), Err(Invalid::Malformed(_))));
        assert!(matches!(Logging::parse("not xml"), Err(Invalid::Malformed(_))));
        assert!(matches!(enabled(&format!("{TARGET}<Other/>")), Err(Invalid::Malformed(_))));
        assert!(matches!(status(&format!("<LoggingEnabled>{TARGET}</LoggingEnabled><LoggingEnabled>{TARGET}</LoggingEnabled>")), Err(Invalid::Malformed(_))));
    }

    #[test]
    fn values_are_escaped() {
        let logging = Logging { target_bucket: "logs".to_owned(), target_prefix: "a&b<".to_owned(), key_format: None };
        let xml = Logging::xml(Some(&logging));
        assert!(xml.contains("<TargetPrefix>a&amp;b&lt;</TargetPrefix>"));
        assert_eq!(Logging::parse(&xml).unwrap().unwrap(), logging);
    }
}
