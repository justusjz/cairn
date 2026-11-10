//! The policy of a POST Object upload (see `objects::post`): a JSON document,
//! signed with the form, that says until when the form may be used, and what
//! its fields may hold. As S3 checks it:
//!
//! - `expiration`: an ISO 8601 time, in UTC; the form is refused from then on.
//! - `conditions`: each `{"name": "value"}` (any number of pairs) or
//!   `["eq", "$name", "value"]` is an exact match, `["starts-with", "$name",
//!   "prefix"]` a prefix (`""` matching anything), and `["content-length-range",
//!   min, max]` the file's size, inclusive. Names are case-insensitive, values
//!   not. A field the form doesn't have is `""`; `$bucket` is the bucket the
//!   form is posted to.
//! - starts-with only for the fields S3 allows it for (`STARTS_WITH`).
//! - A Content-Type is a comma-separated list for starts-with: every item
//!   must match.
//! - Every field of the form must be named by a condition, but those S3
//!   exempts (`EXEMPT`) and, as MinIO does, SSE-C's: a policy that names its
//!   key would have to hold it, and whoever signs it to know it.

use hyper::StatusCode;
use serde_json::Value;

use crate::auth::Rejection;

/// A form's fields but its file: lowercase names, each once, in the order sent.
pub type Fields = Vec<(String, String)>;

/// The value of the field `name` (lowercase) of `fields`, if it's there.
pub fn field<'a>(fields: &'a Fields, name: &str) -> Option<&'a str> {
    fields.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
}

/// The fields that need no condition, as in S3.
const EXEMPT: [&str; 3] = ["x-amz-signature", "file", "policy"];
/// Nor do fields with this prefix.
const IGNORED_PREFIX: &str = "x-ignore-";
/// Nor, as in MinIO, do SSE-C's (see the module's documentation).
const SSE_C: [&str; 3] = [
    "x-amz-server-side-encryption-customer-algorithm",
    "x-amz-server-side-encryption-customer-key",
    "x-amz-server-side-encryption-customer-key-md5",
];

/// The fields a starts-with condition may name, besides `x-amz-meta-*`.
const STARTS_WITH: [&str; 10] = [
    "key",
    "acl",
    "cache-control",
    "content-type",
    "content-disposition",
    "content-encoding",
    "content-language",
    "expires",
    "success_action_redirect",
    "redirect",
];

#[derive(Debug, PartialEq, Eq)]
enum Condition {
    /// The field `.0` (lowercase, without its `$`) is exactly `.1`.
    Eq(String, String),
    /// The field `.0` starts with `.1`.
    StartsWith(String, String),
    /// The file is at least `.0` and at most `.1` bytes.
    Length(u64, u64),
}

#[derive(Debug)]
pub struct Policy {
    /// Unix seconds.
    expiration: i64,
    conditions: Vec<Condition>,
}

/// S3's 400 for a policy that isn't one.
fn invalid(message: impl std::fmt::Display) -> Rejection {
    Rejection::new(StatusCode::BAD_REQUEST, "InvalidPolicyDocument", format!("Invalid Policy: {message}"))
}

/// S3's 403 for a form its policy doesn't allow.
fn refused(message: impl std::fmt::Display) -> Rejection {
    Rejection::new(StatusCode::FORBIDDEN, "AccessDenied", format!("Invalid according to Policy: {message}"))
}

impl Policy {
    /// Parses a policy document (the `policy` field, base64-decoded).
    pub fn parse(document: &[u8]) -> Result<Policy, Rejection> {
        let document: Value =
            serde_json::from_slice(document).map_err(|_| invalid("Invalid JSON."))?;
        let Value::Object(document) = document else { return Err(invalid("Invalid JSON.")) };
        if let Some(other) = document.keys().find(|k| *k != "expiration" && *k != "conditions") {
            return Err(invalid(format_args!("Unexpected field: {other}.")));
        }
        let expiration = match document.get("expiration") {
            Some(Value::String(s)) => parse_time(s).ok_or_else(|| invalid("Invalid 'expiration' value."))?,
            Some(_) => return Err(invalid("Invalid 'expiration' value.")),
            None => return Err(invalid("Policy missing expiration.")),
        };
        let Some(Value::Array(list)) = document.get("conditions") else {
            return Err(invalid("Policy missing conditions."));
        };
        let mut conditions = Vec::new();
        for condition in list {
            match condition {
                Value::Object(pairs) => {
                    for (name, value) in pairs {
                        let Value::String(value) = value else {
                            return Err(invalid(format_args!("Invalid condition for {name}.")));
                        };
                        conditions.push(Condition::Eq(name.to_ascii_lowercase(), value.clone()));
                    }
                }
                Value::Array(items) => conditions.push(parse_condition(items)?),
                _ => return Err(invalid("Invalid condition.")),
            }
        }
        Ok(Policy { expiration, conditions })
    }

    /// The least and most bytes the file may have, if the policy says.
    pub fn length_range(&self) -> Option<(u64, u64)> {
        self.conditions.iter().fold(None, |range, condition| match (condition, range) {
            (Condition::Length(min, max), None) => Some((*min, *max)),
            (Condition::Length(min, max), Some((lo, hi))) => Some((lo.max(*min), hi.min(*max))),
            _ => range,
        })
    }

    /// Whether a form of `fields`, posted to `bucket` at `now` (Unix
    /// seconds), is one the policy allows. The file's size is checked as it
    /// arrives (`length_range`).
    pub fn check(&self, fields: &Fields, bucket: &str, now: i64) -> Result<(), Rejection> {
        if now >= self.expiration {
            return Err(refused("Policy expired."));
        }
        let value = |name: &str| match name {
            "bucket" => bucket,
            _ => field(fields, name).unwrap_or(""),
        };
        for condition in &self.conditions {
            let holds = match condition {
                Condition::Eq(name, expected) => value(name) == expected,
                Condition::StartsWith(name, prefix) if name == "content-type" => {
                    value(name).split(',').all(|item| item.trim().starts_with(prefix.as_str()))
                }
                Condition::StartsWith(name, prefix) => value(name).starts_with(prefix.as_str()),
                Condition::Length(..) => true,
            };
            if !holds {
                let (op, name, v) = match condition {
                    Condition::Eq(name, v) => ("eq", name, v),
                    Condition::StartsWith(name, v) => ("starts-with", name, v),
                    Condition::Length(..) => unreachable!("always holds here"),
                };
                let shown = serde_json::json!([op, format!("${name}"), v]);
                return Err(refused(format_args!("Policy Condition failed: {shown}")));
            }
        }
        let extra: Vec<&str> = fields
            .iter()
            .map(|(name, _)| name.as_str())
            .filter(|name| !EXEMPT.contains(name) && !SSE_C.contains(name) && !name.starts_with(IGNORED_PREFIX))
            .filter(|name| {
                !self.conditions.iter().any(|c| matches!(c, Condition::Eq(n, _) | Condition::StartsWith(n, _) if n == name))
            })
            .collect();
        if !extra.is_empty() {
            return Err(refused(format_args!("Extra input fields: {}", extra.join(", "))));
        }
        Ok(())
    }
}

/// A condition written as an array.
fn parse_condition(items: &[Value]) -> Result<Condition, Rejection> {
    let op = match items.first() {
        Some(Value::String(op)) => op.to_ascii_lowercase(),
        _ => return Err(invalid("Invalid condition.")),
    };
    if items.len() != 3 {
        return Err(invalid(format_args!("wrong number of arguments for condition '{op}'.")));
    }
    if op == "content-length-range" {
        // Numbers, or (as MinIO takes them) numbers in strings.
        let bound = |v: &Value| match v {
            Value::Number(n) => n.as_u64(),
            Value::String(s) => s.trim().parse().ok(),
            _ => None,
        };
        return match (bound(&items[1]), bound(&items[2])) {
            (Some(min), Some(max)) if min <= max => Ok(Condition::Length(min, max)),
            _ => Err(invalid("Invalid content-length-range.")),
        };
    }
    let (Value::String(name), Value::String(value)) = (&items[1], &items[2]) else {
        return Err(invalid(format_args!("Invalid condition '{op}'.")));
    };
    let Some(name) = name.strip_prefix('$') else {
        return Err(invalid(format_args!("Invalid field name '{name}' in condition '{op}'.")));
    };
    let name = name.to_ascii_lowercase();
    match op.as_str() {
        "eq" => Ok(Condition::Eq(name, value.clone())),
        "starts-with" if STARTS_WITH.contains(&name.as_str()) || name.starts_with("x-amz-meta-") => {
            Ok(Condition::StartsWith(name, value.clone()))
        }
        "starts-with" => Err(invalid(format_args!("Invalid 'starts-with' condition for {name}: only exact matches are allowed."))),
        _ => Err(invalid(format_args!("Invalid condition '{op}'."))),
    }
}

/// An ISO 8601 time in UTC (`2015-12-30T12:00:00.000Z`, the fraction
/// optional, or with a `+00:00` offset), in Unix seconds.
fn parse_time(s: &str) -> Option<i64> {
    let (date, time) = s.split_once('T')?;
    let (time, offset) = match time.strip_suffix('Z') {
        Some(time) => (time, 0),
        None => {
            let at = time.rfind(['+', '-'])?;
            let (time, offset) = time.split_at(at);
            let (hours, minutes) = offset[1..].split_once(':')?;
            let minutes: i64 = hours.parse::<i64>().ok()? * 60 + minutes.parse::<i64>().ok()?;
            (time, if offset.starts_with('-') { -minutes } else { minutes } * 60)
        }
    };
    let time = match time.split_once('.') {
        Some((time, fraction)) if !fraction.is_empty() && fraction.bytes().all(|b| b.is_ascii_digit()) => time,
        Some(_) => return None,
        None => time,
    };
    let (d, t) = (date.as_bytes(), time.as_bytes());
    if d.len() != 10 || d[4] != b'-' || d[7] != b'-' || t.len() != 8 || t[2] != b':' || t[5] != b':' {
        return None;
    }
    let date: String = date.split('-').collect();
    let time: String = time.split(':').collect();
    crate::auth::parse_amz_date(&format!("{date}T{time}Z")).map(|t| t - offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(conditions: &str) -> Policy {
        Policy::parse(format!(r#"{{"expiration": "2026-11-10T12:00:00.000Z", "conditions": [{conditions}]}}"#).as_bytes())
            .unwrap()
    }

    fn fields(pairs: &[(&str, &str)]) -> Fields {
        pairs.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect()
    }

    /// Before the policy's expiration.
    const NOW: i64 = 1_794_312_000 - 1;

    fn code(result: Result<(), Rejection>) -> Option<String> {
        result.err().map(|r| format!("{} {}", r.code, r.message))
    }

    #[test]
    fn parses_times() {
        assert_eq!(parse_time("2026-11-10T12:00:00.000Z"), Some(NOW + 1));
        assert_eq!(parse_time("2026-11-10T12:00:00Z"), Some(NOW + 1));
        assert_eq!(parse_time("2026-11-10T13:00:00+01:00"), Some(NOW + 1));
        assert_eq!(parse_time("2026-11-10T11:30:00-00:30"), Some(NOW + 1));
        for bad in ["2026-11-10", "2026-11-10T12:00:00", "2026-11-10T12:00:00.Z", "20261110T120000Z", "2026-13-10T12:00:00Z"] {
            assert_eq!(parse_time(bad), None, "{bad}");
        }
    }

    #[test]
    fn refuses_what_isnt_a_policy() {
        for document in [
            "",
            "[]",
            r#"{"conditions": []}"#,
            r#"{"expiration": "tomorrow", "conditions": []}"#,
            r#"{"expiration": "2026-11-10T12:00:00Z"}"#,
            r#"{"expiration": "2026-11-10T12:00:00Z", "conditions": [], "other": 1}"#,
            r#"{"expiration": "2026-11-10T12:00:00Z", "conditions": [{"key": 1}]}"#,
            r#"{"expiration": "2026-11-10T12:00:00Z", "conditions": [["eq", "key", "a"]]}"#,
            r#"{"expiration": "2026-11-10T12:00:00Z", "conditions": [["eq", "$key"]]}"#,
            r#"{"expiration": "2026-11-10T12:00:00Z", "conditions": [["matches", "$key", "a"]]}"#,
            r#"{"expiration": "2026-11-10T12:00:00Z", "conditions": [["content-length-range", 10, 1]]}"#,
            r#"{"expiration": "2026-11-10T12:00:00Z", "conditions": [["content-length-range", -1, 1]]}"#,
            r#"{"expiration": "2026-11-10T12:00:00Z", "conditions": [["starts-with", "$bucket", ""]]}"#,
            r#"{"expiration": "2026-11-10T12:00:00Z", "conditions": [["starts-with", "$x-amz-date", ""]]}"#,
            r#"{"expiration": "2026-11-10T12:00:00Z", "conditions": [["starts-with", "$success_action_status", ""]]}"#,
        ] {
            let refused = Policy::parse(document.as_bytes()).unwrap_err();
            assert_eq!((refused.status, refused.code), (StatusCode::BAD_REQUEST, "InvalidPolicyDocument"), "{document}");
        }
    }

    #[test]
    fn expires() {
        let p = policy("");
        assert_eq!(code(p.check(&vec![], "b", NOW)), None);
        assert_eq!(code(p.check(&vec![], "b", NOW + 1)).unwrap(), "AccessDenied Invalid according to Policy: Policy expired.");
    }

    #[test]
    fn checks_conditions() {
        let p = policy(r#"{"bucket": "b", "Key": "a/b"}, ["EQ", "$X-Amz-Meta-Tag", "v"], ["starts-with", "$acl", ""]"#);
        let good = fields(&[("key", "a/b"), ("x-amz-meta-tag", "v"), ("acl", "private")]);
        assert_eq!(code(p.check(&good, "b", NOW)), None);
        assert_eq!(
            code(p.check(&good, "c", NOW)).unwrap(),
            r#"AccessDenied Invalid according to Policy: Policy Condition failed: ["eq","$bucket","b"]"#
        );
        // Values are case-sensitive; a missing field is "".
        let upper = fields(&[("key", "A/b"), ("x-amz-meta-tag", "v"), ("acl", "private")]);
        assert!(code(p.check(&upper, "b", NOW)).unwrap().contains(r#"["eq","$key","a/b"]"#));
        let missing = fields(&[("key", "a/b"), ("acl", "private")]);
        assert!(code(p.check(&missing, "b", NOW)).unwrap().contains("$x-amz-meta-tag"));
        // starts-with "" holds for a missing field too.
        let no_acl = fields(&[("key", "a/b"), ("x-amz-meta-tag", "v")]);
        assert_eq!(code(p.check(&no_acl, "b", NOW)), None);
    }

    #[test]
    fn starts_with() {
        let p = policy(r#"["starts-with", "$key", "user/"], ["starts-with", "$Content-Type", "image/"]"#);
        let check = |key: &str, ct: &str| code(p.check(&fields(&[("key", key), ("content-type", ct)]), "b", NOW));
        assert_eq!(check("user/x", "image/png"), None);
        assert!(check("users/x", "image/png").is_some());
        assert!(check("user/x", "text/plain").is_some());
        // A Content-Type is a list.
        assert_eq!(check("user/x", "image/jpg, image/png"), None);
        assert!(check("user/x", "image/jpg,text/plain").is_some());
        // Any other field is a plain value.
        let p = policy(r#"["starts-with", "$key", "a"]"#);
        assert_eq!(code(p.check(&fields(&[("key", "ab,c")]), "b", NOW)), None);
    }

    #[test]
    fn every_field_needs_a_condition() {
        let p = policy(r#"{"key": "k"}"#);
        let mut form = fields(&[
            ("key", "k"),
            ("policy", "..."),
            ("x-amz-signature", "..."),
            ("x-ignore-me", "x"),
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            ("x-amz-server-side-encryption-customer-key", "..."),
            ("x-amz-server-side-encryption-customer-key-md5", "..."),
        ]);
        assert_eq!(code(p.check(&form, "b", NOW)), None);
        form.push(("x-amz-date".into(), "d".into()));
        form.push(("x-amz-server-side-encryption-aws-kms-key-id".into(), "k".into()));
        assert_eq!(
            code(p.check(&form, "b", NOW)).unwrap(),
            "AccessDenied Invalid according to Policy: Extra input fields: x-amz-date, \
             x-amz-server-side-encryption-aws-kms-key-id"
        );
        // A condition on an exempt field is checked all the same.
        let p = policy(r#"{"key": "k"}, {"x-amz-server-side-encryption-customer-key-md5": "m"}"#);
        assert!(code(p.check(&fields(&[("key", "k")]), "b", NOW)).is_some());
    }

    #[test]
    fn length_ranges() {
        assert_eq!(policy("").length_range(), None);
        assert_eq!(policy(r#"["content-length-range", 1, 10]"#).length_range(), Some((1, 10)));
        assert_eq!(policy(r#"["content-length-range", "0", "0"]"#).length_range(), Some((0, 0)));
        let both = policy(r#"["content-length-range", 1, 10], ["content-length-range", 5, 20]"#);
        assert_eq!(both.length_range(), Some((5, 10)));
    }

    /// AWS's example policy (sigv4-post-example), CRLF and all.
    #[test]
    fn parses_aws_example() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let p = Policy::parse(&STANDARD.decode(crate::auth::tests::AWS_POST_POLICY).unwrap()).unwrap();
        let form = fields(&[
            ("key", "user/user1/photo.jpg"),
            ("acl", "public-read"),
            ("success_action_redirect", "http://sigv4examplebucket.s3.amazonaws.com/successful_upload.html"),
            ("content-type", "image/jpeg"),
            ("x-amz-meta-uuid", "14365123651274"),
            ("x-amz-server-side-encryption", "AES256"),
            ("x-amz-credential", "AKIAIOSFODNN7EXAMPLE/20151229/us-east-1/s3/aws4_request"),
            ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
            ("x-amz-date", "20151229T000000Z"),
            ("x-amz-meta-tag", ""),
            ("policy", crate::auth::tests::AWS_POST_POLICY),
            ("x-amz-signature", "8afdbf4008c03f22c2cd3cdb72e4afbb1f6a588f3255ac628749a66d7f09699e"),
        ]);
        let at = parse_time("2015-12-29T00:00:00Z").unwrap();
        assert_eq!(code(p.check(&form, "sigv4examplebucket", at)), None);
        assert!(code(p.check(&form, "sigv4examplebucket", parse_time("2015-12-30T12:00:00Z").unwrap())).is_some());
    }
}
