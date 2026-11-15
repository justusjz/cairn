//! An object's metadata: the headers S3 stores with it, other than its
//! Content-Type (a column of its own), and returns on every GET and HEAD.
//!
//! It's stored as one text, a header block: a `name: value` line for each, in
//! order of their names. HTTP doesn't allow a CR or LF in a header value, nor
//! a `:` in a name, so that needs no escaping. Names are lowercase, as hyper
//! hands them over.

use http_body_util::Full;
use hyper::{HeaderMap, Response, StatusCode, body::Bytes, http::response::Builder};

use crate::s3::util::format_s3_error;

/// The headers S3 stores with an object, besides `x-amz-meta-*`.
const STORED: &[&str] = &[
    "cache-control",
    "content-disposition",
    "content-encoding",
    "content-language",
    "expires",
    REDIRECT,
];

/// Where the bucket's website redirects a request for the object to (see
/// `s3::website`). Stored and returned like the others, as S3 does (probed).
const REDIRECT: &str = "x-amz-website-redirect-location";

const USER_PREFIX: &str = "x-amz-meta-";

/// The Content-Type of an object whose write gives none (probed: S3's, not
/// `application/octet-stream`).
pub const DEFAULT_CONTENT_TYPE: &str = "binary/octet-stream";

/// The most user-defined metadata S3 stores with an object: its names (after
/// the prefix) and values, in bytes.
const MAX_USER_METADATA: usize = 2048;

/// The metadata a write's request headers give its object, or the error to
/// refuse the request with.
pub fn from_request(headers: &HeaderMap) -> Result<String, Response<Full<Bytes>>> {
    let mut stored: Vec<(&str, String)> = Vec::new();
    let mut user_size = 0;
    for name in headers.keys() {
        let name = name.as_str();
        let user = name.strip_prefix(USER_PREFIX);
        if user.is_none() && !STORED.contains(&name) {
            continue;
        }
        // Repeated headers are one, their values joined (RFC 9110, 5.3). A
        // user-defined one's bytes are Latin-1, as S3 reads them (probed).
        let mut values = Vec::new();
        for value in headers.get_all(name) {
            let value = match (value.to_str(), user) {
                (Ok(value), _) => value.to_owned(),
                (Err(_), Some(_)) => value.as_bytes().iter().map(|&b| char::from(b)).collect(),
                (Err(_), None) => {
                    return Err(format_s3_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidArgument",
                        &format!("the {name} header must be printable US-ASCII"),
                    ));
                }
            };
            values.push(value.trim().to_owned());
        }
        let mut value = values.join(", ");
        // `aws-chunked` describes the request's body, not the object's.
        if name == "content-encoding" {
            value = value
                .split(',')
                .map(str::trim)
                .filter(|coding| !coding.is_empty() && !coding.eq_ignore_ascii_case("aws-chunked"))
                .collect::<Vec<_>>()
                .join(", ");
            if value.is_empty() {
                continue;
            }
        }
        // Counted as sent (in UTF-8), then any RFC 2047 encoded words in it
        // decoded, as S3 does (probed).
        if let Some(user) = user {
            user_size += user.len() + value.len();
            value = decode_words(&value).unwrap_or(value);
        }
        if name == REDIRECT && !["/", "http://", "https://"].iter().any(|prefix| value.starts_with(prefix)) {
            return Err(format_s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidRedirectLocation",
                "The website redirect location must have a prefix of 'http://' or 'https://' or '/'.",
            ));
        }
        stored.push((name, value));
    }
    if user_size > MAX_USER_METADATA {
        return Err(format_s3_error(
            StatusCode::BAD_REQUEST,
            "MetadataTooLarge",
            "your metadata headers exceed the maximum allowed metadata size",
        ));
    }
    stored.sort();
    Ok(stored.iter().map(|(name, value)| format!("{name}: {value}\n")).collect())
}

/// GetObject's and HeadObject's `response-*` query parameters, and the
/// headers whose values they replace in that response (only), as in S3: so a
/// presigned URL can have a browser save the object under a name of its own.
const OVERRIDES: [(&str, &str); 6] = [
    ("response-content-type", "content-type"),
    ("response-content-language", "content-language"),
    ("response-expires", "expires"),
    ("response-cache-control", "cache-control"),
    ("response-content-disposition", "content-disposition"),
    ("response-content-encoding", "content-encoding"),
];

/// The headers a read's `response-*` parameters replace.
#[derive(Default)]
pub struct Overrides(Vec<(&'static str, hyper::header::HeaderValue)>);

impl Overrides {
    /// The overrides `query` asks for, or the error to refuse it with.
    pub fn from_query(query: &str) -> Result<Overrides, Response<Full<Bytes>>> {
        let mut overrides = Vec::new();
        for (parameter, header) in OVERRIDES {
            let Some(value) = crate::s3::util::query_param(query, parameter) else {
                continue;
            };
            let Ok(value) = value.parse() else {
                return Err(format_s3_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidArgument",
                    &format!("{parameter} isn't a valid header value"),
                ));
            };
            overrides.push((header, value));
        }
        Ok(Overrides(overrides))
    }

    /// Whether the read asks for any.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// S3's refusal of overrides in an anonymous read (probed; a HEAD's
    /// has no body).
    pub fn refused_anonymously() -> Response<Full<Bytes>> {
        format_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "Request specific response headers cannot be used for anonymous GET requests.",
        )
    }

    /// Replaces the headers of a successful read's `response`.
    pub fn apply<B>(&self, mut response: Response<B>) -> Response<B> {
        if response.status().is_success() {
            for (header, value) in &self.0 {
                response.headers_mut().insert(*header, value.clone());
            }
        }
        response
    }
}

/// The website redirect location the stored `metadata` has, if any.
pub fn redirect_location(metadata: &str) -> Option<&str> {
    metadata.lines().find_map(|line| line.strip_prefix(REDIRECT)?.strip_prefix(": "))
}

/// The stored `metadata`, with `location` its website redirect location.
pub fn with_redirect(metadata: &str, location: &str) -> String {
    let mut stored: String =
        metadata.lines().filter(|line| !line.starts_with(REDIRECT)).map(|line| format!("{line}\n")).collect();
    stored.push_str(&format!("{REDIRECT}: {location}\n"));
    stored
}

/// Adds the stored `metadata`'s headers to a response: one that isn't ASCII
/// as an RFC 2047 encoded word, as S3 sends it (probed).
pub fn apply(mut builder: Builder, metadata: &str) -> Builder {
    for line in metadata.lines() {
        if let Some((name, value)) = line.split_once(": ") {
            builder = match value.is_ascii() {
                true => builder.header(name, value),
                false => builder.header(name, encode_word(value)),
            };
        }
    }
    builder
}

/// `value` as one RFC 2047 encoded word, Q-encoded UTF-8, as S3 writes it:
/// `=?UTF-8?Q?x_caf=C3=A9_y?=`.
fn encode_word(value: &str) -> String {
    let mut word = String::from("=?UTF-8?Q?");
    for byte in value.bytes() {
        match byte {
            b' ' => word.push('_'),
            b if b.is_ascii_alphanumeric() => word.push(char::from(b)),
            b => word.push_str(&format!("={b:02X}")),
        }
    }
    word.push_str("?=");
    word
}

/// `value` with its RFC 2047 encoded words (`=?charset?B|Q?text?=`) decoded,
/// and the white space between two of them dropped; `None` if it has none,
/// or one can't be decoded (S3 fails on one with a 500), or what they decode
/// to has control characters, which a header can't carry.
fn decode_words(value: &str) -> Option<String> {
    use base64::Engine;
    let mut out = String::new();
    let mut rest = value;
    let mut decoded_any = false;
    // White space after an encoded word, held until it's known whether
    // another follows.
    let mut pending = String::new();
    let mut after_word = false;
    while !rest.is_empty() {
        let Some(start) = rest.find("=?") else {
            out.push_str(&pending);
            out.push_str(rest);
            break;
        };
        let (before, word) = rest.split_at(start);
        // `=?charset?encoding?text?=`.
        let mut fields = word[2..].splitn(3, '?');
        let (Some(charset), Some(encoding), Some(text_end)) = (fields.next(), fields.next(), fields.next()) else {
            out.push_str(&pending);
            out.push_str(rest);
            break;
        };
        let Some(end) = text_end.find("?=") else {
            out.push_str(&pending);
            out.push_str(rest);
            break;
        };
        let text = &text_end[..end];
        let bytes = match encoding {
            "B" | "b" => base64::engine::general_purpose::STANDARD.decode(text).ok()?,
            "Q" | "q" => {
                let mut bytes = Vec::new();
                let mut chars = text.bytes();
                while let Some(b) = chars.next() {
                    match b {
                        b'_' => bytes.push(b' '),
                        b'=' => {
                            let hex = [chars.next()?, chars.next()?];
                            bytes.push(u8::from_str_radix(std::str::from_utf8(&hex).ok()?, 16).ok()?);
                        }
                        b => bytes.push(b),
                    }
                }
                bytes
            }
            _ => return None,
        };
        let decoded = match charset.to_ascii_lowercase().as_str() {
            "utf-8" | "utf8" | "us-ascii" => String::from_utf8(bytes).ok()?,
            "iso-8859-1" | "latin1" => bytes.iter().map(|&b| char::from(b)).collect(),
            _ => return None,
        };
        if !(after_word && before.chars().all(char::is_whitespace)) {
            out.push_str(before);
        }
        pending.clear();
        out.push_str(&decoded);
        decoded_any = true;
        after_word = true;
        rest = &text_end[end + 2..];
        // White space up to a next word is dropped then; else it's kept.
        let spaces = rest.len() - rest.trim_start().len();
        pending.push_str(&rest[..spaces]);
        rest = &rest[spaces..];
        if !rest.starts_with("=?") {
            out.push_str(&pending);
            pending.clear();
            after_word = false;
        }
    }
    let clean = out.chars().all(|c| c == '\t' || !c.is_control());
    (decoded_any && clean).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_and_encodes_words_as_s3_does() {
        assert_eq!(decode_words("=?UTF-8?B?YWJj?=").as_deref(), Some("abc"));
        assert_eq!(decode_words("=?UTF-8?Q?caf=C3=A9?=").as_deref(), Some("caf\u{e9}"));
        assert_eq!(decode_words("x =?UTF-8?Q?caf=C3=A9?= y").as_deref(), Some("x caf\u{e9} y"));
        assert_eq!(decode_words("=?ISO-8859-1?Q?caf=E9?=").as_deref(), Some("caf\u{e9}"));
        assert_eq!(decode_words("=?utf-8?b?Y2Fmw6k=?=").as_deref(), Some("caf\u{e9}"));
        assert_eq!(decode_words("=?UTF-8?Q?a?= =?UTF-8?Q?b?=").as_deref(), Some("ab"));
        assert_eq!(decode_words("a?=b"), None);
        assert_eq!(decode_words("plain"), None);
        assert_eq!(decode_words("=?UTF-8?B?!!!?="), None);
        assert_eq!(decode_words("=?UTF-8?Q?a=0Ab?="), None);
        assert_eq!(encode_word("x caf\u{e9} y"), "=?UTF-8?Q?x_caf=C3=A9_y?=");
        assert_eq!(encode_word("caf\u{c3}\u{a9}"), "=?UTF-8?Q?caf=C3=83=C2=A9?=");
    }

    #[test]
    fn takes_user_metadata_as_latin_1() {
        let mut map = HeaderMap::new();
        map.insert("x-amz-meta-m", hyper::header::HeaderValue::from_bytes(b"caf\xe9").unwrap());
        assert_eq!(from_request(&map).unwrap(), "x-amz-meta-m: caf\u{e9}\n");
        let mut map = HeaderMap::new();
        map.insert("cache-control", hyper::header::HeaderValue::from_bytes(b"caf\xe9").unwrap());
        assert!(from_request(&map).is_err());
        // Counted as sent: two bytes of UTF-8 are four once read as Latin-1.
        let mut map = HeaderMap::new();
        let mut value = vec![b'v'; 2045];
        value.extend_from_slice("\u{e9}".as_bytes());
        map.insert("x-amz-meta-m", hyper::header::HeaderValue::from_bytes(&value).unwrap());
        assert!(from_request(&map).is_err());
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        map
    }

    #[test]
    fn keeps_what_s3_stores_and_strips_aws_chunked() {
        let got = from_request(&headers(&[
            ("X-Amz-Meta-B", "two"),
            ("x-amz-meta-a", " one "),
            ("x-amz-meta-a", "again"),
            ("x-amz-meta-empty", ""),
            ("cache-control", "no-cache"),
            ("content-encoding", "aws-chunked,gzip"),
            ("content-type", "text/plain"),
            ("x-amz-date", "20261106T000000Z"),
        ]))
        .unwrap();
        assert_eq!(
            got,
            "cache-control: no-cache\ncontent-encoding: gzip\nx-amz-meta-a: one, again\n\
             x-amz-meta-b: two\nx-amz-meta-empty: \n"
        );
        // Only aws-chunked: no Content-Encoding to store.
        assert_eq!(from_request(&headers(&[("content-encoding", "aws-chunked")])).unwrap(), "");
    }

    #[test]
    fn round_trips_onto_a_response() {
        let stored = from_request(&headers(&[("x-amz-meta-k", "v: w"), ("x-amz-meta-e", "")])).unwrap();
        let response = apply(Response::builder(), &stored).body(()).unwrap();
        assert_eq!(response.headers()["x-amz-meta-k"], "v: w");
        assert_eq!(response.headers()["x-amz-meta-e"], "");
    }

    #[test]
    fn response_parameters_replace_a_reads_headers() {
        let query = "response-content-type=text%2Fcsv&response-content-disposition=attachment%3B%20filename%3D%22r.csv%22&x-id=GetObject";
        let overrides = Overrides::from_query(query).unwrap();
        let read = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/octet-stream");
        let response = overrides.apply(read.body(()).unwrap());
        assert_eq!(response.headers()["content-type"], "text/csv");
        assert_eq!(
            response.headers()["content-disposition"],
            "attachment; filename=\"r.csv\""
        );
        assert_eq!(response.headers().get_all("content-type").iter().count(), 1);
        // Not an error's.
        let missing = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(())
            .unwrap();
        assert!(
            !overrides
                .apply(missing)
                .headers()
                .contains_key("content-disposition")
        );
        // A value that can't be a header's is refused.
        assert!(Overrides::from_query("response-content-type=a%0Ab").is_err());
    }

    #[test]
    fn refuses_too_much_user_metadata() {
        let at_limit = "x".repeat(MAX_USER_METADATA - 1);
        assert!(from_request(&headers(&[("x-amz-meta-k", &at_limit)])).is_ok());
        let over = "x".repeat(MAX_USER_METADATA);
        let refused = from_request(&headers(&[("x-amz-meta-k", &over)])).unwrap_err();
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn keeps_a_website_redirect_location_that_is_one() {
        let stored = from_request(&headers(&[("x-amz-meta-a", "b"), (REDIRECT, "/elsewhere")])).unwrap();
        assert_eq!(redirect_location(&stored), Some("/elsewhere"));
        assert_eq!(redirect_location("x-amz-meta-a: b\n"), None);
        for location in ["/other", "http://example.com/x", "https://example.com/"] {
            let got = from_request(&headers(&[("x-amz-website-redirect-location", location)])).unwrap();
            assert_eq!(got, format!("x-amz-website-redirect-location: {location}\n"));
        }
        for location in ["nope", "ftp://example.com/", ""] {
            assert!(from_request(&headers(&[("x-amz-website-redirect-location", location)])).is_err(), "{location}");
        }
    }
}
