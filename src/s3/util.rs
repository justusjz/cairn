use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::Full;
use hyper::{Method, Response, StatusCode, body::Bytes, header::HeaderValue};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};

use crate::auth::Rejection;

/// A time, as S3 writes it in XML and as seconds since the Unix epoch.
pub struct Timestamp {
    pub iso: String,
    pub epoch: f64,
}

/// SQL for a `TIMESTAMPTZ` column's [`Timestamp`]: its ISO text, then its epoch.
pub fn timestamp_sql(column: &str) -> String {
    format!(
        "to_char({column} AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), \
         extract(epoch FROM {column})::float8"
    )
}

pub fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn xml_ok(body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// A fixed AccessControlPolicy. Cairn doesn't model ACLs, so every bucket and
/// object reports owner "cairn" with FULL_CONTROL. This lets clients that probe
/// ACLs (e.g. `s3cmd info`, which issues a `?acl` GET) parse a valid response
/// instead of choking on object bytes.
pub fn stub_acl() -> Response<Full<Bytes>> {
    xml_ok(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Owner><ID>cairn</ID><DisplayName>cairn</DisplayName></Owner>\
         <AccessControlList><Grant>\
         <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">\
         <ID>cairn</ID><DisplayName>cairn</DisplayName></Grantee>\
         <Permission>FULL_CONTROL</Permission>\
         </Grant></AccessControlList>\
         </AccessControlPolicy>"
            .to_string(),
    )
}

const XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
const S3_XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// Read-only stubs for the bucket sub-resource GETs S3 clients probe (s3cmd
/// `info`, minio-go's `cp` preflight, Terraform's refresh of a bucket). Cairn
/// implements none of these features, so we answer exactly as S3 does for an
/// unconfigured bucket (and as MinIO's stubs do): `location`, `versioning`,
/// `accelerate`, `requestPayment`, `logging` and `notification` return a 200
/// empty (or default) config; the rest return their "not configured" 404.
/// Returns `None` for a normal listing GET (no recognised sub-resource).
///
/// Existence-agnostic, like [`stub_acl`] — clients probe these on buckets they're
/// already using.
pub fn bucket_subresource_stub(query: &str) -> Option<Response<Full<Bytes>>> {
    let present = |name| query_param(query, name).is_some();
    if present("acl") {
        Some(stub_acl())
    } else if present("location") {
        Some(xml_ok(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></LocationConstraint>"
                .to_string(),
        ))
    } else if present("versioning") {
        Some(xml_ok(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></VersioningConfiguration>"
                .to_string(),
        ))
    } else if present("object-lock") {
        Some(format_s3_error(
            StatusCode::NOT_FOUND,
            "ObjectLockConfigurationNotFoundError",
            "object lock configuration does not exist for this bucket",
        ))
    } else if present("website") {
        Some(format_s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchWebsiteConfiguration",
            "The specified bucket does not have a website configuration",
        ))
    } else if present("replication") {
        Some(format_s3_error(
            StatusCode::NOT_FOUND,
            "ReplicationConfigurationNotFoundError",
            "The replication configuration was not found",
        ))
    } else if present("accelerate") {
        Some(xml_ok(format!("{XML}<AccelerateConfiguration xmlns=\"{S3_XMLNS}\"/>")))
    } else if present("requestPayment") {
        Some(xml_ok(format!(
            "{XML}<RequestPaymentConfiguration xmlns=\"{S3_XMLNS}\"><Payer>BucketOwner</Payer>\
             </RequestPaymentConfiguration>"
        )))
    } else if present("logging") {
        Some(xml_ok(format!("{XML}<BucketLoggingStatus xmlns=\"{S3_XMLNS}\"/>")))
    } else if present("notification") {
        Some(xml_ok(format!("{XML}<NotificationConfiguration xmlns=\"{S3_XMLNS}\"/>")))
    } else {
        None
    }
}

/// A part number as a read names one (`?partNumber=N`): 1 to 10,000.
pub fn part_number(text: &str) -> Option<u32> {
    let number = text.bytes().all(|b| b.is_ascii_digit()).then(|| text.parse::<u32>().ok()).flatten()?;
    (1..=10_000).contains(&number).then_some(number)
}

/// S3's 400 for a part number that isn't one (probed).
pub fn invalid_part_number(text: &str) -> Response<Full<Bytes>> {
    let mut rejection = Rejection::new(
        StatusCode::BAD_REQUEST,
        "InvalidArgument",
        "Part number must be an integer between 1 and 10000, inclusive",
    );
    rejection.details.push(("ArgumentName", "partNumber".to_owned()));
    rejection.details.push(("ArgumentValue", text.to_owned()));
    rejection_response(&rejection)
}

/// Sets `x-amz-version-id` on a response, if there's a version ID to report.
/// Version IDs are checked as they come in (`is_version_id`), so every one
/// makes a valid header; one that wouldn't is left out rather than panicking.
pub fn with_version_id<B>(mut resp: Response<B>, version_id: Option<&str>) -> Response<B> {
    if let Some(v) = version_id.and_then(|v| HeaderValue::from_str(v).ok()) {
        resp.headers_mut().insert("x-amz-version-id", v);
    }
    resp
}

/// Marks a response as concerning a delete marker (`x-amz-delete-marker: true`).
pub fn with_delete_marker<B>(mut resp: Response<B>) -> Response<B> {
    resp.headers_mut()
        .insert("x-amz-delete-marker", HeaderValue::from_static("true"));
    resp
}

pub fn format_s3_error(status: StatusCode, code: &str, message: &str) -> Response<Full<Bytes>> {
    error_document(status, code, message, &[])
}

/// The S3 error for a request refused for what it claims about itself.
pub fn rejection_response(rejection: &Rejection) -> Response<Full<Bytes>> {
    error_document(rejection.status, rejection.code, &rejection.message, &rejection.details)
}

/// An S3 error document: its code and message, and any further elements.
fn error_document(
    status: StatusCode,
    code: &str,
    message: &str,
    details: &[(&str, String)],
) -> Response<Full<Bytes>> {
    let mut body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <Error><Code>{}</Code><Message>{}</Message>",
        xml_escape(code),
        xml_escape(message)
    );
    for (name, value) in details {
        body.push_str(&format!("<{name}>{}</{name}>", xml_escape(value)));
    }
    // The request's ID, as its x-amz-request-id header has it too.
    if let Some(id) = crate::s3::request_id() {
        body.push_str(&format!("<RequestId>{id}</RequestId>"));
    }
    body.push_str("</Error>");
    Response::builder()
        .status(status)
        .header("content-type", "application/xml")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// S3's 503 for a request that kept conflicting with concurrent ones and gave
/// up. S3 clients back off and retry it.
pub fn slow_down() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "SlowDown",
        "too many concurrent requests on the same data; please retry",
    )
}

pub fn decode_path_param(param: &str) -> String {
    percent_decode_str(param).decode_utf8_lossy().into_owned()
}

/// Whether a percent-encoded path segment or query value names something S3
/// keys can be: valid UTF-8 without NUL characters. S3 keys are UTF-8 strings;
/// one that isn't valid UTF-8 would be mangled by `decode_path_param` (two
/// such keys could become the same one), and a NUL can't be stored. MinIO
/// refuses both too.
pub fn is_well_formed(param: &str) -> bool {
    percent_decode_str(param)
        .decode_utf8()
        .is_ok_and(|decoded| !decoded.contains('\0'))
}

/// The longest key S3 allows, in bytes of its UTF-8.
pub const MAX_KEY_LENGTH: usize = 1024;

/// The error for a request whose path or query isn't well-formed (see
/// `is_well_formed`). S3 has no error for it, since it takes NUL (and can't be
/// sent invalid UTF-8 in XML); this is MinIO's message.
pub fn unsupported_characters() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::BAD_REQUEST,
        "InvalidArgument",
        "Object name contains unsupported characters.",
    )
}

/// The most data S3 takes in one request: a PutObject's, an UploadPart's, an
/// UploadPartCopy's range, and a CopyObject's source (5 GiB). Larger objects
/// are multipart uploads, and are copied part by part.
pub const MAX_UPLOAD: u64 = 5 << 30;

/// The smallest part S3 takes in a multipart upload, but for the last (5 MiB).
/// Mirrored in `cairn_complete_upload`.
pub const MIN_PART: u64 = 5 << 20;

/// The largest object S3 stores (5 TiB). Mirrored in `cairn_complete_upload`.
pub const MAX_OBJECT: u64 = 5 << 40;

/// S3's subresources: query parameters that pick the operation, rather than
/// parameterize it. `PUT /bucket/key?tagging` is PutObjectTagging, not a
/// PutObject, so one Cairn doesn't handle must be refused, never served as the
/// plain operation: that would overwrite the object with the request's XML, or
/// delete it, or a bucket. Other parameters are ignored, as S3 ignores them
/// (SDKs add some, like `x-id`).
const SUBRESOURCES: &[&str] = &[
    "accelerate",
    "acl",
    "analytics",
    "attributes",
    "cors",
    "delete",
    "encryption",
    "intelligent-tiering",
    "inventory",
    "legal-hold",
    "lifecycle",
    "location",
    "logging",
    "metadataConfiguration",
    "metadataTable",
    "metrics",
    "notification",
    "object-lock",
    "ownershipControls",
    "partNumber",
    "policy",
    "policyStatus",
    "publicAccessBlock",
    "renameObject",
    "replication",
    "requestPayment",
    "restore",
    "retention",
    "select",
    "session",
    "tagging",
    "torrent",
    "uploadId",
    "uploads",
    "versioning",
    "versions",
    "website",
];

/// The subresources Cairn handles, by method, for a bucket-level request or an
/// object-level one. Must match the routing in `s3::handle`.
fn handled_subresources(method: &Method, bucket_level: bool) -> &'static [&'static str] {
    match (bucket_level, method) {
        // ListObjectVersions, ListMultipartUploads, versioning, encryption,
        // lifecycle, ownership controls (`acl`), and the stubs
        // (`bucket_subresource_stub`).
        (true, &Method::GET) => &[
            "versioning",
            "encryption",
            "versions",
            "uploads",
            "ownershipControls",
            "acl",
            "location",
            "object-lock",
            "policy",
            "policyStatus",
            "cors",
            "tagging",
            "lifecycle",
            "website",
            "replication",
            "accelerate",
            "requestPayment",
            "logging",
            "notification",
            // Ignored, as S3 ignores it on a bucket (probed): a listing.
            "attributes",
        ],
        // PutBucketVersioning, PutBucketEncryption,
        // PutBucketLifecycleConfiguration, PutBucketCors, PutBucketTagging,
        // PutBucketPolicy, PutBucketAcl (`acl`).
        (true, &Method::PUT) => &["versioning", "encryption", "lifecycle", "cors", "tagging", "policy", "acl"],
        (true, &Method::POST) => &["delete"],
        // DeleteBucketEncryption, DeleteBucketLifecycle, DeleteBucketCors,
        // DeleteBucketTagging, DeleteBucketPolicy.
        (true, &Method::DELETE) => &["encryption", "lifecycle", "cors", "tagging", "policy"],
        // GetObjectAcl (stubbed), ListParts, GetObjectTagging, a part of
        // the object, GetObjectAttributes.
        (false, &Method::GET) => &["acl", "uploadId", "tagging", "partNumber", "attributes"],
        // A part of the object.
        (false, &Method::HEAD) => &["partNumber"],
        // UploadPart / UploadPartCopy, PutObjectAcl (`acl`), PutObjectTagging.
        (false, &Method::PUT) => &["uploadId", "partNumber", "acl", "tagging"],
        // CreateMultipartUpload / CompleteMultipartUpload.
        (false, &Method::POST) => &["uploads", "uploadId"],
        // AbortMultipartUpload, DeleteObjectTagging.
        (false, &Method::DELETE) => &["uploadId", "tagging"],
        _ => &[],
    }
}

/// A 501 for a request naming a subresource Cairn doesn't handle for its method
/// (see [`SUBRESOURCES`]), or `None` if it names none.
pub fn unsupported_subresource(
    method: &Method,
    bucket_level: bool,
    query: &str,
) -> Option<Response<Full<Bytes>>> {
    let handled = handled_subresources(method, bucket_level);
    let name = query
        .split('&')
        .map(|pair| decode_path_param(pair.split_once('=').map_or(pair, |(k, _)| k)))
        .find(|name| SUBRESOURCES.contains(&name.as_str()) && !handled.contains(&name.as_str()))?;
    Some(format_s3_error(
        StatusCode::NOT_IMPLEMENTED,
        "NotImplemented",
        &format!("the {name} subresource is not implemented for {method} requests"),
    ))
}

/// Mints a ListObjectsV2 `continuation-token` carrying `marker` (the key to
/// resume after). URL-safe base64 has no `+`/`/`/`=`, so the token survives
/// `query_param` untouched on the way back. Inverse of
/// [`decode_continuation_token`].
pub fn encode_continuation_token(marker: &str) -> String {
    URL_SAFE_NO_PAD.encode(marker)
}

/// Decodes a ListObjectsV2 `continuation-token` back to the marker it carries
/// (the key to resume after). A token that doesn't decode is a malformed client
/// request.
pub fn decode_continuation_token(token: &str) -> Option<String> {
    let bytes = URL_SAFE_NO_PAD.decode(token).ok()?;
    String::from_utf8(bytes).ok()
}

/// How a listing writes keys, prefixes, delimiters and markers: as they are,
/// or, asked for with `encoding-type=url`, percent-encoded (so that keys XML
/// can't hold, control characters say, come through).
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub enum Encoding {
    #[default]
    Plain,
    Url,
}

/// What `encoding-type=url` leaves as it is, as S3 does: unreserved characters
/// and `/`.
const URL_KEEPS: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~')
    .remove(b'/');

impl Encoding {
    /// `encoding-type`, or the error to refuse a listing with.
    pub fn from_query(query: &str) -> Result<Encoding, Response<Full<Bytes>>> {
        match query_param(query, "encoding-type").as_deref() {
            None => Ok(Encoding::Plain),
            Some(e) if e.eq_ignore_ascii_case("url") => Ok(Encoding::Url),
            Some(_) => Err(format_s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "Invalid Encoding Method specified in Request",
            )),
        }
    }

    /// `s`, encoded, escaped for XML.
    pub fn xml(self, s: &str) -> String {
        match self {
            Encoding::Plain => xml_escape(s),
            Encoding::Url => utf8_percent_encode(s, URL_KEEPS).to_string(),
        }
    }

    /// The `<EncodingType>` a listing reports, if it was asked for one.
    pub fn element(self) -> &'static str {
        match self {
            Encoding::Plain => "",
            Encoding::Url => "<EncodingType>url</EncodingType>",
        }
    }
}

/// A listing's page size (`max-keys`, `max-uploads`, `max-parts`,
/// `max-buckets`): `default` if absent, at most `max`, or the error for one
/// that isn't a whole number, not negative, as S3 refuses it.
pub fn page_size(
    query: &str,
    name: &str,
    default: i64,
    max: i64,
) -> Result<i64, Response<Full<Bytes>>> {
    match query_param(query, name) {
        None => Ok(default),
        Some(v) => match v.trim().parse::<i64>() {
            Ok(n) if n >= 0 => Ok(n.min(max)),
            _ => Err(format_s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                &format!("Provided {name} not an integer or within integer range"),
            )),
        },
    }
}

/// A listing's delimiter: none if absent or empty, as S3 takes an empty one.
pub fn delimiter(query: &str) -> Option<String> {
    query_param(query, "delimiter").filter(|d| !d.is_empty())
}

/// Extracts and percent-decodes a single parameter from a raw query string
/// (e.g. "prefix=dir%2F&delimiter=%2F").
pub fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (k == name).then(|| decode_path_param(&v.replace('+', " ")))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_utf8_without_nul_is_well_formed() {
        for good in ["", "a/b", "caf%C3%A9", "%01", "a%20b", "%E2%82%AC"] {
            assert!(is_well_formed(good), "{good}");
        }
        for bad in ["%FF", "caf%C3", "a%00b", "%C0%80"] {
            assert!(!is_well_formed(bad), "{bad}");
        }
    }

    #[tokio::test]
    async fn an_error_names_its_request() {
        use http_body_util::BodyExt;
        let body = |response: Response<Full<Bytes>>| async move {
            String::from_utf8(
                response
                    .into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes()
                    .to_vec(),
            )
            .unwrap()
        };
        let named = crate::s3::REQUEST_ID
            .scope("0123456789ABCDEF".to_owned(), async {
                format_s3_error(StatusCode::NOT_FOUND, "NoSuchKey", "no")
            })
            .await;
        assert!(
            body(named)
                .await
                .ends_with("<RequestId>0123456789ABCDEF</RequestId></Error>")
        );
        // Outside of a request (the dashboard's, say), none.
        let unnamed = format_s3_error(StatusCode::NOT_FOUND, "NoSuchKey", "no");
        assert!(!body(unnamed).await.contains("RequestId"));
    }

    #[test]
    fn listings_encode_and_page_as_s3_does() {
        assert_eq!(
            Encoding::Url.xml("foo+1/quux ab/a&b~-_."),
            "foo%2B1/quux%20ab/a%26b~-_."
        );
        assert_eq!(Encoding::Plain.xml("a&b"), "a&amp;b");
        assert_eq!(
            Encoding::from_query("encoding-type=url").unwrap(),
            Encoding::Url
        );
        assert!(Encoding::from_query("encoding-type=base64").is_err());
        assert_eq!(page_size("", "max-keys", 1000, 1000).unwrap(), 1000);
        assert_eq!(page_size("max-keys=0", "max-keys", 1000, 1000).unwrap(), 0);
        assert_eq!(
            page_size("max-keys=5000", "max-keys", 1000, 1000).unwrap(),
            1000
        );
        for bad in ["max-keys=blah", "max-keys=-1", "max-keys="] {
            assert!(page_size(bad, "max-keys", 1000, 1000).is_err(), "{bad}");
        }
        assert_eq!(delimiter("delimiter="), None);
        assert_eq!(delimiter("delimiter=%2F").as_deref(), Some("/"));
    }

    #[test]
    fn only_unhandled_subresources_are_refused() {
        let refused = |method, bucket_level, query| {
            unsupported_subresource(&method, bucket_level, query).map(|resp| resp.status())
        };
        // What Cairn routes, and parameters that aren't subresources at all.
        for (method, bucket_level, query) in [
            (Method::GET, true, ""),
            (Method::GET, true, "list-type=2&prefix=a&x-id=ListObjectsV2"),
            (Method::GET, true, "versions&key-marker=a"),
            (Method::GET, true, "uploads&prefix=a"),
            (Method::GET, true, "policy"),
            (Method::GET, true, "policyStatus"),
            (Method::PUT, true, "policy"),
            (Method::DELETE, true, "policy"),
            (Method::PUT, true, "versioning"),
            (Method::PUT, true, "lifecycle"),
            (Method::DELETE, true, "lifecycle"),
            (Method::PUT, true, ""),
            (Method::POST, true, "delete"),
            (Method::DELETE, true, ""),
            (Method::GET, false, "versionId=null"),
            (Method::GET, false, "acl"),
            (Method::GET, false, "response-content-type=a%2Fb"),
            (Method::HEAD, false, "versionId=null"),
            (Method::PUT, false, "x-id=PutObject"),
            (Method::PUT, false, "partNumber=1&uploadId=u"),
            (Method::POST, false, "uploads"),
            (Method::POST, false, "uploadId=u"),
            (Method::PUT, false, "acl"),
            (Method::PUT, true, "acl"),
            (Method::GET, true, "ownershipControls"),
            (Method::GET, true, "website"),
            (Method::PUT, true, "cors"),
            (Method::DELETE, true, "cors"),
            (Method::PUT, false, "tagging"),
            (Method::DELETE, false, "tagging&versionId=null"),
            (Method::GET, false, "tagging"),
            (Method::PUT, true, "tagging"),
            (Method::DELETE, true, "tagging"),
            (Method::GET, false, "uploadId=u&max-parts=2"),
            (Method::DELETE, false, "versionId=null"),
            (Method::DELETE, false, "uploadId=u"),
            (Method::GET, false, "attributes"),
            (Method::GET, false, "partNumber=1"),
            (Method::HEAD, false, "partNumber=1"),
            (Method::GET, true, "attributes"),
        ] {
            assert_eq!(refused(method.clone(), bucket_level, query), None, "{method} {query}");
        }
        // Each of these used to run as the plain operation: overwriting the
        // object, deleting it or the bucket, or serving the wrong bytes.
        for (method, bucket_level, query) in [
            (Method::PUT, false, "retention&versionId=null"),
            (Method::POST, false, "restore"),
            (Method::DELETE, true, "website"),
            (Method::GET, true, "inventory"),
            (Method::GET, true, "prefix=a&%69nventory"),
        ] {
            assert_eq!(
                refused(method.clone(), bucket_level, query),
                Some(StatusCode::NOT_IMPLEMENTED),
                "{method} {query}"
            );
        }
    }
}
