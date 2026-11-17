//! A server access log record: one line per request, of space-separated
//! fields, as S3 writes them (see S3's user guide, "Amazon S3 server access
//! log format"). A field without a value is `-`; those that may have spaces
//! (the request line, the referrer and the user agent) are quoted.

use std::time::SystemTime;

use hyper::{HeaderMap, Method};

use crate::lifecycle::rules::Day;

/// A record's fields, in their order.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Record {
    /// The canonical ID of the bucket's owner.
    pub owner: String,
    pub bucket: String,
    /// When the request was received.
    pub time: Option<SystemTime>,
    pub remote_ip: Option<String>,
    /// The ARN of who made it; none for an anonymous (or unauthenticated)
    /// request.
    pub requester: Option<String>,
    pub request_id: String,
    /// `REST.GET.OBJECT`, say (see `operation`).
    pub operation: String,
    /// The key, URL-encoded (as the request had it).
    pub key: Option<String>,
    /// The request line: method, path and query, and HTTP version.
    pub request_uri: String,
    pub status: u16,
    pub error_code: Option<String>,
    pub bytes_sent: u64,
    pub object_size: Option<u64>,
    /// Milliseconds from receiving the request to sending the response's
    /// last byte.
    pub total_time: u64,
    /// Milliseconds from receiving the request to its response being ready.
    pub turn_around_time: u64,
    pub referer: Option<String>,
    pub user_agent: Option<String>,
    pub version_id: Option<String>,
    /// `SigV4` or `SigV2`, if signed.
    pub signature_version: Option<&'static str>,
    /// `AuthHeader` or `QueryString`, if signed.
    pub authentication_type: Option<&'static str>,
    pub host: Option<String>,
}

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// A time as S3's records have it: `[06/Feb/2019:00:00:38 +0000]`.
pub fn time(time: SystemTime) -> String {
    let day = Day::of(time);
    let (year, month, date) = day.civil();
    let secs = time.duration_since(day.midnight()).map_or(0, |d| d.as_secs());
    format!(
        "[{date:02}/{}/{year:04}:{:02}:{:02}:{:02} +0000]",
        MONTHS[month as usize - 1],
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// A value of a field: `-` if there's none (or it's empty), and without
/// what would end the field or the line.
fn plain(value: Option<&str>) -> String {
    match value.filter(|v| !v.is_empty()) {
        None => "-".to_owned(),
        Some(v) => escape(v, b' '),
    }
}

/// A quoted field's value: always quoted, `"-"` if there's none.
fn quoted(value: Option<&str>) -> String {
    match value.filter(|v| !v.is_empty()) {
        None => "\"-\"".to_owned(),
        Some(v) => format!("\"{}\"", escape(v, b'"')),
    }
}

/// `value`, with `end` (what ends its field) and control characters
/// percent-encoded, so that it can't end its field or line.
fn escape(value: &str, end: u8) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if c.is_ascii_control() || c == end as char || (end == b'"' && c == '\\') {
            out.push_str(&format!("%{:02X}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

fn number(n: u64) -> String {
    match n {
        0 => "-".to_owned(),
        n => n.to_string(),
    }
}

impl Record {
    /// The record's line, without its line break.
    pub fn line(&self) -> String {
        [
            plain(Some(&self.owner)),
            plain(Some(&self.bucket)),
            self.time.map_or_else(|| "-".to_owned(), time),
            plain(self.remote_ip.as_deref()),
            plain(self.requester.as_deref()),
            plain(Some(&self.request_id)),
            plain(Some(&self.operation)),
            plain(self.key.as_deref()),
            quoted(Some(&self.request_uri)),
            self.status.to_string(),
            plain(self.error_code.as_deref()),
            number(self.bytes_sent),
            self.object_size.map_or_else(|| "-".to_owned(), |s| s.to_string()),
            self.total_time.to_string(),
            self.turn_around_time.to_string(),
            quoted(self.referer.as_deref()),
            quoted(self.user_agent.as_deref()),
            plain(self.version_id.as_deref()),
            // Host ID (`x-amz-id-2`), which Cairn doesn't have.
            "-".to_owned(),
            plain(self.signature_version),
            // Cipher suite: TLS ends at the proxy in front of Cairn.
            "-".to_owned(),
            plain(self.authentication_type),
            plain(self.host.as_deref()),
            // TLS version, likewise.
            "-".to_owned(),
            // Access point ARN: there are none.
            "-".to_owned(),
            // Whether an ACL was required: there are none.
            "-".to_owned(),
        ]
        .join(" ")
    }
}

/// How a request was signed: its signature version and authentication
/// type, as a record has them. None for an unsigned one.
pub fn signing(headers: &HeaderMap, query: &str) -> (Option<&'static str>, Option<&'static str>) {
    let header = headers.get(hyper::header::AUTHORIZATION).and_then(|v| v.to_str().ok());
    if header.is_some_and(|h| h.starts_with("AWS4-")) {
        return (Some("SigV4"), Some("AuthHeader"));
    }
    if crate::s3::util::query_param(query, "X-Amz-Algorithm").is_some() {
        return (Some("SigV4"), Some("QueryString"));
    }
    if header.is_some_and(|h| h.starts_with("AWS ")) {
        return (Some("SigV2"), Some("AuthHeader"));
    }
    if header.is_none() && crate::s3::util::query_param(query, "AWSAccessKeyId").is_some() {
        return (Some("SigV2"), Some("QueryString"));
    }
    (None, None)
}

/// What S3's records call a request (`REST.GET.OBJECT`): by its method,
/// whether it's on an object (`key`), and its subresource. A request to a
/// bucket's website endpoint is `WEBSITE.GET.OBJECT`.
pub fn operation(method: &Method, key: bool, query: &str, headers: &HeaderMap, website: bool) -> String {
    let m = method.as_str();
    if website {
        return format!("WEBSITE.{m}.OBJECT");
    }
    if *method == Method::OPTIONS {
        return "REST.OPTIONS.PREFLIGHT".to_owned();
    }
    let has = |name| crate::s3::util::query_param(query, name).is_some();
    let copy = headers.contains_key("x-amz-copy-source");
    let resource = if key {
        if has("uploads") {
            "UPLOADS".to_owned()
        } else if has("uploadId") {
            match *method {
                Method::PUT if copy => return "REST.COPY.PART".to_owned(),
                Method::PUT => "PART".to_owned(),
                _ => "UPLOAD".to_owned(),
            }
        } else if has("tagging") {
            "OBJECT_TAGGING".to_owned()
        } else if let Some(sub) = subresource(query, OBJECT_SUBRESOURCES) {
            sub
        } else if *method == Method::PUT && copy {
            return "REST.COPY.OBJECT".to_owned();
        } else {
            "OBJECT".to_owned()
        }
    } else if *method == Method::POST && has("delete") {
        "MULTI_OBJECT_DELETE".to_owned()
    } else if *method == Method::POST && crate::s3::objects::post::is_form(headers) {
        "OBJECT".to_owned()
    } else if has("versions") {
        "BUCKETVERSIONS".to_owned()
    } else if has("policy") {
        "BUCKETPOLICY".to_owned()
    } else if has("logging") {
        "LOGGING_STATUS".to_owned()
    } else if has("object-lock") {
        "OBJECT_LOCK_CONFIGURATION".to_owned()
    } else if has("inventory") {
        "INVENTORY_CONFIGURATION".to_owned()
    } else if let Some(sub) = subresource(query, BUCKET_SUBRESOURCES) {
        sub
    } else {
        "BUCKET".to_owned()
    };
    format!("REST.{m}.{resource}")
}

/// An object's subresources, besides those `operation` names itself.
const OBJECT_SUBRESOURCES: &[&str] = &["acl", "attributes", "legal-hold", "restore", "retention", "torrent", "select"];

/// A bucket's.
const BUCKET_SUBRESOURCES: &[&str] = &[
    "abac",
    "accelerate",
    "acl",
    "analytics",
    "cors",
    "encryption",
    "intelligent-tiering",
    "lifecycle",
    "location",
    "metrics",
    "notification",
    "ownershipControls",
    "policyStatus",
    "publicAccessBlock",
    "replication",
    "requestPayment",
    "tagging",
    "uploads",
    "versioning",
    "website",
];

/// The first of `known` that `query` has, as S3's operations name it:
/// `publicAccessBlock` is `PUBLIC_ACCESS_BLOCK`, `legal-hold` `LEGAL_HOLD`.
fn subresource(query: &str, known: &[&str]) -> Option<String> {
    let name = known.iter().find(|name| crate::s3::util::query_param(query, name).is_some())?;
    let mut out = String::new();
    for c in name.chars() {
        if c.is_ascii_uppercase() {
            out.push('_');
        }
        out.push(if c == '-' { '_' } else { c.to_ascii_uppercase() });
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn op(method: Method, key: bool, query: &str) -> String {
        operation(&method, key, query, &HeaderMap::new(), false)
    }

    #[test]
    fn operations_are_named_as_s3_names_them() {
        assert_eq!(op(Method::GET, true, ""), "REST.GET.OBJECT");
        assert_eq!(op(Method::HEAD, true, "versionId=x"), "REST.HEAD.OBJECT");
        assert_eq!(op(Method::PUT, true, ""), "REST.PUT.OBJECT");
        assert_eq!(op(Method::DELETE, true, ""), "REST.DELETE.OBJECT");
        assert_eq!(op(Method::GET, false, "list-type=2&prefix=a"), "REST.GET.BUCKET");
        assert_eq!(op(Method::HEAD, false, ""), "REST.HEAD.BUCKET");
        assert_eq!(op(Method::GET, false, "versions"), "REST.GET.BUCKETVERSIONS");
        assert_eq!(op(Method::GET, false, "uploads"), "REST.GET.UPLOADS");
        assert_eq!(op(Method::POST, false, "delete"), "REST.POST.MULTI_OBJECT_DELETE");
        assert_eq!(op(Method::POST, true, "uploads"), "REST.POST.UPLOADS");
        assert_eq!(op(Method::PUT, true, "partNumber=1&uploadId=u"), "REST.PUT.PART");
        assert_eq!(op(Method::POST, true, "uploadId=u"), "REST.POST.UPLOAD");
        assert_eq!(op(Method::GET, true, "uploadId=u"), "REST.GET.UPLOAD");
        assert_eq!(op(Method::DELETE, true, "uploadId=u"), "REST.DELETE.UPLOAD");
        assert_eq!(op(Method::GET, true, "tagging"), "REST.GET.OBJECT_TAGGING");
        assert_eq!(op(Method::GET, false, "tagging"), "REST.GET.TAGGING");
        assert_eq!(op(Method::PUT, false, "logging"), "REST.PUT.LOGGING_STATUS");
        assert_eq!(op(Method::GET, false, "policy"), "REST.GET.BUCKETPOLICY");
        assert_eq!(op(Method::GET, false, "versioning"), "REST.GET.VERSIONING");
        assert_eq!(op(Method::GET, false, "publicAccessBlock"), "REST.GET.PUBLIC_ACCESS_BLOCK");
        assert_eq!(op(Method::PUT, true, "legal-hold"), "REST.PUT.LEGAL_HOLD");
        assert_eq!(op(Method::OPTIONS, true, ""), "REST.OPTIONS.PREFLIGHT");
        let mut copy = HeaderMap::new();
        copy.insert("x-amz-copy-source", "/b/k".parse().unwrap());
        assert_eq!(operation(&Method::PUT, true, "", &copy, false), "REST.COPY.OBJECT");
        assert_eq!(operation(&Method::PUT, true, "partNumber=1&uploadId=u", &copy, false), "REST.COPY.PART");
        assert_eq!(operation(&Method::GET, true, "", &HeaderMap::new(), true), "WEBSITE.GET.OBJECT");
    }

    #[test]
    fn times_are_s3s() {
        // 2019-02-06T00:00:38Z.
        let t = UNIX_EPOCH + Duration::from_secs(1_549_411_238);
        assert_eq!(time(t), "[06/Feb/2019:00:00:38 +0000]");
    }

    #[test]
    fn a_line_has_every_field() {
        let record = Record {
            owner: "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be".to_owned(),
            bucket: "amzn-s3-demo-bucket1".to_owned(),
            time: Some(UNIX_EPOCH + Duration::from_secs(1_549_411_238)),
            remote_ip: Some("192.0.2.3".to_owned()),
            requester: None,
            request_id: "3E57427F3EXAMPLE".to_owned(),
            operation: "REST.GET.VERSIONING".to_owned(),
            key: None,
            request_uri: "GET /amzn-s3-demo-bucket1?versioning HTTP/1.1".to_owned(),
            status: 200,
            error_code: None,
            bytes_sent: 113,
            object_size: None,
            total_time: 7,
            turn_around_time: 0,
            referer: None,
            user_agent: Some("S3Console/0.4".to_owned()),
            version_id: None,
            signature_version: Some("SigV4"),
            authentication_type: Some("AuthHeader"),
            host: Some("amzn-s3-demo-bucket1.s3.us-west-1.amazonaws.com".to_owned()),
        };
        assert_eq!(
            record.line(),
            "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be amzn-s3-demo-bucket1 \
             [06/Feb/2019:00:00:38 +0000] 192.0.2.3 - 3E57427F3EXAMPLE REST.GET.VERSIONING - \
             \"GET /amzn-s3-demo-bucket1?versioning HTTP/1.1\" 200 - 113 - 7 0 \"-\" \"S3Console/0.4\" - - \
             SigV4 - AuthHeader amzn-s3-demo-bucket1.s3.us-west-1.amazonaws.com - - -"
        );
    }

    #[test]
    fn values_cant_end_their_field_or_line() {
        assert_eq!(quoted(Some("a \"b\"\nc")), "\"a %22b%22%0Ac\"");
        assert_eq!(plain(Some("a b")), "a%20b");
        assert_eq!(plain(Some("")), "-");
    }
}
