//! Tags: the key-value pairs a client keeps with an object version (up to 10)
//! or a bucket (up to 50), as S3 does. An object's come with its write
//! (`x-amz-tagging`, or a POST form's `tagging` field), or are set later by
//! PutObjectTagging, which changes them in place: they aren't part of the
//! version's data, so it's not a new version, and its ETag and Last-Modified
//! stay. Lifecycle rules can pick objects by them (see `lifecycle::rules`).
//!
//! They're stored in plaintext whatever an object's encryption, as its
//! metadata is, and as S3 keeps them: an SSE-C object's are read and changed
//! without its key, and lifecycle sweeps, which have no keys, read them.
//!
//! Stored as text in `x-amz-tagging`'s form, `k=v&k=v`, each key and value
//! percent-encoded but for unreserved characters, sorted by key: S3 hands
//! them back in that order. Empty for none.
//!
//! What S3 takes, and its errors, were observed on S3 itself (see
//! `plans/tagging.md`), where its documentation says otherwise.

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};

use crate::s3::util::{format_s3_error, xml_escape};

/// The most tags an object may have, as in S3.
pub const MAX_OBJECT_TAGS: usize = 10;
/// The most tags a bucket may have, as in S3.
pub const MAX_BUCKET_TAGS: usize = 50;
/// The longest key and value, in UTF-16 code units, as S3 counts them.
pub const MAX_KEY: usize = 128;
pub const MAX_VALUE: usize = 256;

/// The header a write's tags come in, and CopyObject's directive for them.
pub const HEADER: &str = "x-amz-tagging";
pub const DIRECTIVE: &str = "x-amz-tagging-directive";
/// The header GET and HEAD tell an object's number of tags in.
pub const COUNT: &str = "x-amz-tagging-count";

/// What's escaped in the stored form: all but unreserved characters.
const ESCAPED: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');

/// What tags are on: the limits and messages differ.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum On {
    Object,
    Bucket,
}

/// A tag set: unique keys, sorted.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Tags(Vec<(String, String)>);

impl Tags {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// The value of the tag `key`, if there's one.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.binary_search_by(|(k, _)| k.as_str().cmp(key)).ok().map(|i| self.0[i].1.as_str())
    }

    /// Checked tags, sorted: S3's error for the first that isn't one, or for
    /// a key twice (`duplicate`, which differs by where they came from), or
    /// for too many.
    fn checked(
        pairs: Vec<(String, String)>,
        on: On,
        duplicate: impl Fn() -> Response<Full<Bytes>>,
    ) -> Result<Tags, Response<Full<Bytes>>> {
        for (key, value) in &pairs {
            check(key, value, on)?;
        }
        let mut pairs = pairs;
        pairs.sort_by(|(a, _), (b, _)| a.cmp(b));
        if pairs.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(duplicate());
        }
        let (max, message) = match on {
            On::Object => (MAX_OBJECT_TAGS, "Object tags cannot be greater than 10"),
            On::Bucket => (MAX_BUCKET_TAGS, "Bucket tag count cannot be greater than 50"),
        };
        if pairs.len() > max {
            return Err(format_s3_error(StatusCode::BAD_REQUEST, "BadRequest", message));
        }
        Ok(Tags(pairs))
    }

    /// An object's tags from an `x-amz-tagging` header: URL query parameters
    /// (`k=v&k=v`, `+` for a space), as S3 takes them: empty pairs are
    /// skipped, a key without `=` has an empty value, and an empty header is
    /// no tags.
    pub fn from_header(value: &[u8]) -> Result<Tags, Response<Full<Bytes>>> {
        let malformed = || {
            format_s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "The header 'x-amz-tagging' shall be encoded as UTF-8 then URLEncoded URL query parameters \
                 without tag name duplicates.",
            )
        };
        let value = std::str::from_utf8(value).map_err(|_| malformed())?;
        let mut pairs = Vec::new();
        for pair in value.split('&').filter(|pair| !pair.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            if key.is_empty() || value.contains('=') {
                return Err(malformed());
            }
            pairs.push((decode(key).ok_or_else(malformed)?, decode(value).ok_or_else(malformed)?));
        }
        Tags::checked(pairs, On::Object, malformed)
    }

    /// Tags from a `<Tagging>` document (PutObjectTagging's and
    /// PutBucketTagging's body, a POST form's `tagging` field). Every `<Tag>`
    /// has a `<Key>` and a `<Value>`; no `<TagSet>` is no tags.
    pub fn from_xml(body: &[u8], on: On) -> Result<Tags, Response<Full<Bytes>>> {
        let pairs = parse_xml(body).map_err(|why| {
            format_s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                &format!(
                    "The XML you provided was not well-formed or did not validate against our published schema \
                     ({why})"
                ),
            )
        })?;
        Tags::checked(pairs, on, || {
            format_s3_error(StatusCode::BAD_REQUEST, "InvalidTag", "Cannot provide multiple Tags with the same key")
        })
    }

    /// Tags as they're stored (see the module's documentation). Stored tags
    /// were checked when they were written, so this doesn't check them again.
    pub fn from_stored(stored: &str) -> Tags {
        let decode = |s: &str| percent_decode_str(s).decode_utf8_lossy().into_owned();
        Tags(
            stored
                .split('&')
                .filter(|pair| !pair.is_empty())
                .map(|pair| {
                    let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                    (decode(key), decode(value))
                })
                .collect(),
        )
    }

    /// How they're stored.
    pub fn stored(&self) -> String {
        self.0
            .iter()
            .map(|(k, v)| format!("{}={}", utf8_percent_encode(k, ESCAPED), utf8_percent_encode(v, ESCAPED)))
            .collect::<Vec<_>>()
            .join("&")
    }

    /// The `<Tagging>` document GetObjectTagging and GetBucketTagging answer
    /// with (`<TagSet/>` for none, as S3 writes it).
    pub fn xml(&self) -> String {
        let mut out = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <Tagging xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
        );
        if self.0.is_empty() {
            out.push_str("<TagSet/>");
        } else {
            out.push_str("<TagSet>");
            for (key, value) in &self.0 {
                out.push_str(&format!("<Tag><Key>{}</Key><Value>{}</Value></Tag>", xml_escape(key), xml_escape(value)));
            }
            out.push_str("</TagSet>");
        }
        out.push_str("</Tagging>");
        out
    }
}

/// The number of tags in their stored form, for `x-amz-tagging-count`.
pub fn count(stored: &str) -> usize {
    stored.split('&').filter(|pair| !pair.is_empty()).count()
}

/// A key or value of `x-amz-tagging`, URL-decoded strictly: every `%` starts
/// an escape, and the result is UTF-8.
fn decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    for (i, _) in s.match_indices('%') {
        if !bytes.get(i + 1..i + 3).is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit)) {
            return None;
        }
    }
    percent_decode_str(&s.replace('+', " ")).decode_utf8().ok().map(|s| s.into_owned())
}

/// Whether `c` may be in a key or value, as S3 takes them: what AWS
/// documents as `[\p{L}\p{Z}\p{N}_.:/=+\-@]`. S3 refuses the other
/// punctuation, controls (tabs) and symbols (emoji).
fn allowed(c: char) -> bool {
    c.is_alphabetic() || c.is_numeric() || is_separator(c) || "_.:/=+-@".contains(c)
}

/// Unicode's separators (`\p{Z}`): spaces, and the line and paragraph
/// separators. Unlike `char::is_whitespace`, not tabs or newlines.
fn is_separator(c: char) -> bool {
    matches!(
        c,
        ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}'
            | '\u{3000}'
    )
}

/// S3's error for a tag it doesn't take, if it doesn't.
fn check(key: &str, value: &str, on: On) -> Result<(), Response<Full<Bytes>>> {
    let invalid = |message: &str| format_s3_error(StatusCode::BAD_REQUEST, "InvalidTag", message);
    let length = key.encode_utf16().count();
    if length == 0 || length > MAX_KEY || !key.chars().all(allowed) {
        return Err(invalid("The TagKey you have provided is invalid"));
    }
    if value.encode_utf16().count() > MAX_VALUE || !value.chars().all(allowed) {
        return Err(invalid("The TagValue you have provided is invalid"));
    }
    if key.starts_with("aws:") {
        return Err(invalid(match on {
            On::Object => "Your TagKey cannot be prefixed with aws:",
            On::Bucket => "System tags cannot be added/updated by requester",
        }));
    }
    Ok(())
}

/// The child elements of `node`.
fn elements<'a, 'input>(node: roxmltree::Node<'a, 'input>) -> Vec<roxmltree::Node<'a, 'input>> {
    node.children().filter(|n| n.is_element()).collect()
}

/// The pairs of a `<Tagging>` document, unchecked, or why it isn't one.
fn parse_xml(body: &[u8]) -> Result<Vec<(String, String)>, String> {
    let text = std::str::from_utf8(body).map_err(|_| "not UTF-8".to_owned())?;
    let doc = roxmltree::Document::parse(text).map_err(|e| e.to_string())?;
    let root = doc.root_element();
    if root.tag_name().name() != "Tagging" {
        return Err("the root element isn't Tagging".to_owned());
    }
    let mut pairs = Vec::new();
    for set in elements(root) {
        if set.tag_name().name() != "TagSet" {
            return Err(format!("unknown element {}", set.tag_name().name()));
        }
        for tag in elements(set) {
            if tag.tag_name().name() != "Tag" {
                return Err(format!("unknown element {}", tag.tag_name().name()));
            }
            let (mut key, mut value) = (None, None);
            for field in elements(tag) {
                let slot = match field.tag_name().name() {
                    "Key" => &mut key,
                    "Value" => &mut value,
                    other => return Err(format!("unknown element {other}")),
                };
                if slot.is_some() {
                    return Err(format!("a Tag has one {}", field.tag_name().name()));
                }
                *slot = Some(field.text().unwrap_or_default().to_owned());
            }
            match (key, value) {
                (Some(key), Some(value)) => pairs.push((key, value)),
                _ => return Err("a Tag has a Key and a Value".to_owned()),
            }
        }
    }
    Ok(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(response: Response<Full<Bytes>>) -> (u16, String) {
        use http_body_util::BodyExt;
        let status = response.status().as_u16();
        let body = block_on(response.into_body().collect());
        let body = String::from_utf8(body.unwrap().to_bytes().to_vec()).unwrap();
        let code = body.split("<Code>").nth(1).and_then(|s| s.split("</Code>").next()).unwrap().to_owned();
        let message = body.split("<Message>").nth(1).and_then(|s| s.split("</Message>").next()).unwrap();
        (status, format!("{code}: {message}"))
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(future)
    }

    fn tagging(pairs: &[(&str, &str)]) -> Vec<u8> {
        let tags: String = pairs
            .iter()
            .map(|(k, v)| format!("<Tag><Key>{}</Key><Value>{}</Value></Tag>", xml_escape(k), xml_escape(v)))
            .collect();
        format!("<Tagging xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><TagSet>{tags}</TagSet></Tagging>")
            .into_bytes()
    }

    fn pairs(tags: &Tags) -> Vec<(&str, &str)> {
        tags.iter().collect()
    }

    #[test]
    fn headers_parse_as_s3_takes_them() {
        let tags = |header: &str| Tags::from_header(header.as_bytes()).map(|tags| tags.stored());
        assert_eq!(tags("z=1&a=2").unwrap(), "a=2&z=1");
        assert_eq!(pairs(&Tags::from_header(b"a+b=c+d").unwrap()), [("a b", "c d")]);
        assert_eq!(pairs(&Tags::from_header(b"a=%C3%A4").unwrap()), [("a", "ä")]);
        assert_eq!(pairs(&Tags::from_header(b"a").unwrap()), [("a", "")]);
        assert_eq!(pairs(&Tags::from_header(b"a=1&&b=2&").unwrap()), [("a", "1"), ("b", "2")]);
        assert!(Tags::from_header(b"").unwrap().is_empty());
        let malformed = (
            400,
            "InvalidArgument: The header 'x-amz-tagging' shall be encoded as UTF-8 then URLEncoded URL query \
             parameters without tag name duplicates."
                .to_owned(),
        );
        for bad in ["=v", "a=%zz", "a=%zz&b=2", "a=1&a=2", "a=b=c", "a=%", "a=%C3"] {
            assert_eq!(code(Tags::from_header(bad.as_bytes()).unwrap_err()), malformed, "{bad}");
        }
        let eleven: Vec<String> = (0..11).map(|i| format!("k{i}=v")).collect();
        assert_eq!(
            code(Tags::from_header(eleven.join("&").as_bytes()).unwrap_err()),
            (400, "BadRequest: Object tags cannot be greater than 10".to_owned())
        );
        assert_eq!(
            code(Tags::from_header(format!("{}=v", "a".repeat(129)).as_bytes()).unwrap_err()),
            (400, "InvalidTag: The TagKey you have provided is invalid".to_owned())
        );
        assert_eq!(
            code(Tags::from_header(b"aws%3Afoo=v").unwrap_err()),
            (400, "InvalidTag: Your TagKey cannot be prefixed with aws:".to_owned())
        );
        assert_eq!(
            code(Tags::from_header(b"a%21=v").unwrap_err()),
            (400, "InvalidTag: The TagKey you have provided is invalid".to_owned())
        );
    }

    #[test]
    fn documents_parse_as_s3_takes_them() {
        let ten: Vec<(String, String)> = (0..10).map(|i| (format!("k{i}"), "v".to_owned())).collect();
        let ten: Vec<(&str, &str)> = ten.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        assert_eq!(Tags::from_xml(&tagging(&ten), On::Object).unwrap().len(), 10);
        let mut eleven = ten.clone();
        eleven.push(("k10", "v"));
        assert_eq!(
            code(Tags::from_xml(&tagging(&eleven), On::Object).unwrap_err()),
            (400, "BadRequest: Object tags cannot be greater than 10".to_owned())
        );
        assert_eq!(Tags::from_xml(&tagging(&eleven), On::Bucket).unwrap().len(), 11);
        assert_eq!(
            code(Tags::from_xml(&tagging(&[("a", "1"), ("a", "1")]), On::Object).unwrap_err()),
            (400, "InvalidTag: Cannot provide multiple Tags with the same key".to_owned())
        );
        let key = |k: &str| Tags::from_xml(&tagging(&[(k, "v")]), On::Object).map(|_| ()).map_err(code);
        let value = |v: &str| Tags::from_xml(&tagging(&[("k", v)]), On::Object).map(|_| ()).map_err(code);
        let bad_key = Err((400, "InvalidTag: The TagKey you have provided is invalid".to_owned()));
        let bad_value = Err((400, "InvalidTag: The TagValue you have provided is invalid".to_owned()));
        assert_eq!(key(&"a".repeat(128)), Ok(()));
        assert_eq!(key(&"ä".repeat(128)), Ok(()));
        assert_eq!(key(&"a".repeat(129)), bad_key);
        assert_eq!(key(""), bad_key);
        assert_eq!(value(&"v".repeat(256)), Ok(()));
        assert_eq!(value(&"v".repeat(257)), bad_value);
        assert_eq!(value(""), Ok(()));
        for good in ["k+-=._:/@", "k ", "kä", "k日本", "k\u{a0}", "k\u{2003}", "k١", " a ", "AWS:foo"] {
            assert_eq!(key(good), Ok(()), "{good:?}");
        }
        for bad in ["!", "#", "$", "%", "&", "*", "?", ",", ";", "<", "'", "\"", "\t", "~", "😀"] {
            assert_eq!(key(&format!("k{bad}")), bad_key, "{bad:?}");
        }
        for bad in ["!", "#", "*", "😀", "\t"] {
            assert_eq!(value(&format!("v{bad}")), bad_value, "{bad:?}");
        }
        assert_eq!(value("aws:foo"), Ok(()));
        assert_eq!(key("aws:foo"), Err((400, "InvalidTag: Your TagKey cannot be prefixed with aws:".to_owned())));
        assert_eq!(
            code(Tags::from_xml(&tagging(&[("aws:x", "1")]), On::Bucket).unwrap_err()),
            (400, "InvalidTag: System tags cannot be added/updated by requester".to_owned())
        );
        let fifty_one: Vec<(String, String)> = (0..51).map(|i| (format!("k{i}"), "v".to_owned())).collect();
        let fifty_one: Vec<(&str, &str)> = fifty_one.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        assert_eq!(
            code(Tags::from_xml(&tagging(&fifty_one), On::Bucket).unwrap_err()),
            (400, "BadRequest: Bucket tag count cannot be greater than 50".to_owned())
        );
    }

    #[test]
    fn documents_must_be_well_formed() {
        assert!(Tags::from_xml(b"<Tagging/>", On::Object).unwrap().is_empty());
        assert!(Tags::from_xml(b"<Tagging><TagSet/></Tagging>", On::Object).unwrap().is_empty());
        for bad in [
            "<Tagging><TagSet><Tag>",
            "<Tags><TagSet/></Tags>",
            "<Tagging><TagSet><Tag><Key>a</Key></Tag></TagSet></Tagging>",
            "<Tagging><TagSet><Tag><Value>a</Value></Tag></TagSet></Tagging>",
            "<Tagging><TagSet><Tag><Key>a</Key><Value>1</Value><Value>2</Value></Tag></TagSet></Tagging>",
            "<Tagging><TagSet><Tag><Key>a</Key><Value>1</Value><Other/></Tag></TagSet></Tagging>",
            "<Tagging><Other/></Tagging>",
        ] {
            let (status, message) = code(Tags::from_xml(bad.as_bytes(), On::Object).unwrap_err());
            assert_eq!(status, 400, "{bad}");
            assert!(message.starts_with("MalformedXML: "), "{bad}: {message}");
        }
    }

    #[test]
    fn the_stored_form_round_trips() {
        let tags = Tags::from_xml(&tagging(&[("z", "1"), ("a b", "c=d&e"), ("ä/@", ""), ("+", "%")]), On::Bucket);
        // `%` isn't a value S3 takes, but the stored form doesn't care.
        assert!(tags.is_err());
        let tags = Tags::from_xml(&tagging(&[("z", "1"), ("a b", "c=d+e"), ("ä/@", "")]), On::Object).unwrap();
        let stored = tags.stored();
        // Sorted by key, bytewise.
        assert_eq!(stored, "a%20b=c%3Dd%2Be&z=1&%C3%A4%2F%40=");
        assert_eq!(Tags::from_stored(&stored), tags);
        assert_eq!(count(&stored), 3);
        assert_eq!(count(""), 0);
        assert_eq!(Tags::from_stored(""), Tags::default());
        assert!(Tags::default().xml().ends_with("<Tagging xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><TagSet/></Tagging>"));
        assert_eq!(tags.get("a b"), Some("c=d+e"));
        assert_eq!(tags.get("b"), None);
        assert_eq!(
            tags.xml(),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Tagging xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <TagSet><Tag><Key>a b</Key><Value>c=d+e</Value></Tag><Tag><Key>z</Key><Value>1</Value></Tag>\
             <Tag><Key>ä/@</Key><Value></Value></Tag></TagSet></Tagging>"
        );
    }
}
