//! Request body integrity and SigV4 streaming-signature verification.
//!
//! A client declares its body's hash in `x-amz-content-sha256`. We verify the
//! body matches that claim — by hashing (modes 2/3) or, for a signed streaming
//! body (mode 4), by verifying the per-chunk HMAC signature chain.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit, Mac};
use hyper::{HeaderMap, StatusCode};
use md5::Md5;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Hex SHA-256 of the empty string — a fixed line in the chunk string-to-sign,
/// and the data hash of the terminating zero-size chunk.
pub const EMPTY_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// A request refused for what it claims about itself (its signature, or its
/// body's integrity): the S3 error to answer it with.
#[derive(Debug, PartialEq, Eq)]
pub struct Rejection {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    /// Further elements of the error document, as S3 adds them (such as
    /// `HeadersNotSigned`).
    pub details: Vec<(&'static str, String)>,
}

impl Rejection {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Rejection {
            status,
            code,
            message: message.into(),
            details: Vec::new(),
        }
    }
}

/// What a client's `x-amz-content-sha256` header claims about the body.
#[derive(Debug)]
pub enum ContentSha256 {
    /// `UNSIGNED-PAYLOAD`: the client makes no claim, so there's nothing to
    /// verify. (`verify_sigv4` refuses a request without the header.)
    Unsigned,
    /// Hex SHA-256 of the entire body; checked once the body has been read.
    Single(String),
    /// `aws-chunked` body whose integrity rides on per-chunk HMAC signatures —
    /// verifiable only with the signing key (the auth layer), not by hashing here.
    Streaming,
    /// `aws-chunked` body with a trailing checksum (verifiable without a key).
    /// `trailer` is the declared trailer header name, e.g. `x-amz-checksum-crc32`.
    StreamingTrailer { trailer: String },
}

impl ContentSha256 {
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let header = |name| headers.get(name).and_then(|v| v.to_str().ok());
        match header("x-amz-content-sha256") {
            None | Some("UNSIGNED-PAYLOAD") => ContentSha256::Unsigned,
            Some("STREAMING-UNSIGNED-PAYLOAD-TRAILER") => ContentSha256::StreamingTrailer {
                trailer: header("x-amz-trailer").unwrap_or("").to_ascii_lowercase(),
            },
            // Other STREAMING-* variants are HMAC-signed; verifying their chunks
            // needs the signing key, so they're the auth layer's job.
            Some(v) if v.starts_with("STREAMING-") => ContentSha256::Streaming,
            Some(hex) => ContentSha256::Single(hex.to_ascii_lowercase()),
        }
    }
}

/// A streaming checksum over the decoded body, used to verify an `aws-chunked`
/// trailer.
pub enum TrailerChecksum {
    Crc32(crc32fast::Hasher),
    Sha256(Sha256),
}

impl TrailerChecksum {
    /// Builds the checksum matching a trailer name (`x-amz-checksum-crc32` /
    /// `…-sha256`); `None` for an algorithm we don't compute, so the caller can
    /// skip verification rather than reject a body it can't check.
    pub fn for_trailer(name: &str) -> Option<Self> {
        match name {
            "x-amz-checksum-crc32" => Some(Self::Crc32(crc32fast::Hasher::new())),
            "x-amz-checksum-sha256" => Some(Self::Sha256(Sha256::new())),
            _ => None,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::Crc32(h) => h.update(data),
            Self::Sha256(h) => h.update(data),
        }
    }

    /// The base64 checksum, in the same form S3 puts in the trailer value.
    pub fn finish_base64(self) -> String {
        match self {
            Self::Crc32(h) => STANDARD.encode(h.finalize().to_be_bytes()),
            Self::Sha256(h) => STANDARD.encode(h.finalize()),
        }
    }
}

/// The body-integrity headers a client may attach to a DeleteObjects request:
/// `Content-MD5` (minio-go) or an `x-amz-checksum-{crc32,sha256}` (aws-cli). At
/// least one must be present and correct — that's the destructive op's guard.
pub struct BodyChecksum {
    content_md5: Option<String>,
    crc32: Option<String>,
    sha256: Option<String>,
}

impl BodyChecksum {
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let h = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned);
        Self {
            content_md5: h("content-md5"),
            crc32: h("x-amz-checksum-crc32"),
            sha256: h("x-amz-checksum-sha256"),
        }
    }

    /// Whether the client supplied any supported integrity header.
    pub fn is_present(&self) -> bool {
        self.content_md5.is_some() || self.crc32.is_some() || self.sha256.is_some()
    }

    /// Checks every supplied checksum against `body` (base64-encoded, as on the
    /// wire); `false` if any present one mismatches.
    pub fn matches(&self, body: &[u8]) -> bool {
        if let Some(md5) = &self.content_md5
            && STANDARD.encode(Md5::digest(body)) != md5.trim()
        {
            return false;
        }
        if let Some(crc) = &self.crc32 {
            let mut hasher = crc32fast::Hasher::new();
            hasher.update(body);
            if STANDARD.encode(hasher.finalize().to_be_bytes()) != crc.trim() {
                return false;
            }
        }
        if let Some(sha) = &self.sha256
            && STANDARD.encode(Sha256::digest(body)) != sha.trim()
        {
            return false;
        }
        true
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Derives a SigV4 signing key: the HMAC chain over date, region, and service.
fn derive_signing_key(secret: &str, date: &str, region: &str, service: &str) -> [u8; 32] {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// Verifies the per-chunk signature chain of a `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`
/// body. Built from the request's `Authorization`/`x-amz-date` plus the server
/// secret, then fed each chunk's data hash and claimed signature in order. This
/// proves both body integrity and that the client holds the secret; it does *not*
/// verify the seed against the canonical request (the metadata-binding step is a
/// later slice), so the seed is taken as the chain's anchor.
pub struct StreamingChunkVerifier {
    signing_key: [u8; 32],
    datetime: String, // x-amz-date, the full timestamp
    scope: String,    // "<date>/<region>/<service>/aws4_request"
    prev_signature: String, // seed signature first, then each verified chunk
}

impl StreamingChunkVerifier {
    /// Builds the verifier from a signed streaming request, or `None` if it lacks
    /// the `Authorization` / `x-amz-date` we need (e.g. an unsigned request).
    pub fn from_headers(headers: &HeaderMap, secret: &str) -> Option<Self> {
        let auth = Authorization::from_headers(headers)?;
        let datetime = headers.get("x-amz-date").and_then(|v| v.to_str().ok())?;
        Some(Self {
            signing_key: derive_signing_key(secret, &auth.date, &auth.region, &auth.service),
            datetime: datetime.to_owned(),
            scope: auth.scope,
            prev_signature: auth.signature,
        })
    }

    /// Verifies one chunk given its data's hex SHA-256 and the claimed signature
    /// (hex), advancing the chain on success. Constant-time via `verify_slice`.
    pub fn verify_chunk(&mut self, data_hash: &str, chunk_signature: &str) -> bool {
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{}\n{EMPTY_SHA256}\n{}",
            self.datetime, self.scope, self.prev_signature, data_hash,
        );
        let Some(sig) = hex_decode(chunk_signature) else {
            return false;
        };
        let mut mac = HmacSha256::new_from_slice(&self.signing_key).expect("any key length");
        mac.update(string_to_sign.as_bytes());
        if mac.verify_slice(&sig).is_ok() {
            self.prev_signature = chunk_signature.to_owned();
            true
        } else {
            false
        }
    }
}

/// The SigV4 `Authorization` header fields, parsed once and shared by request
/// verification and the streaming chunk verifier.
///
/// `AWS4-HMAC-SHA256 Credential=<akid>/<date>/<region>/<service>/aws4_request,
///  SignedHeaders=h1;h2;…, Signature=<hex>`
struct Authorization {
    access_key: String,
    date: String,
    region: String,
    service: String,
    scope: String,
    signed_headers: Vec<String>,
    signature: String,
}

impl Authorization {
    fn from_headers(headers: &HeaderMap) -> Option<Self> {
        let value = headers.get("authorization").and_then(|v| v.to_str().ok())?;
        let rest = value.strip_prefix("AWS4-HMAC-SHA256 ")?;
        let (mut credential, mut signed, mut signature) = (None, None, None);
        for part in rest.split(',') {
            let part = part.trim();
            if let Some(c) = part.strip_prefix("Credential=") {
                credential = Some(c);
            } else if let Some(s) = part.strip_prefix("SignedHeaders=") {
                signed = Some(s);
            } else if let Some(s) = part.strip_prefix("Signature=") {
                signature = Some(s);
            }
        }
        let mut cred = credential?.split('/');
        let access_key = cred.next()?.to_owned();
        let date = cred.next()?.to_owned();
        let region = cred.next()?.to_owned();
        let service = cred.next()?.to_owned();
        let terminator = cred.next()?; // aws4_request
        Some(Authorization {
            access_key,
            scope: format!("{date}/{region}/{service}/{terminator}"),
            date,
            region,
            service,
            signed_headers: signed?.split(';').map(str::to_owned).collect(),
            signature: signature?.to_owned(),
        })
    }
}

/// The access key ID a SigV4-signed request claims (from its `Authorization`
/// credential), used to look up the secret to verify it with. `None` for an
/// unsigned or malformed request.
pub fn access_key(headers: &HeaderMap) -> Option<String> {
    Authorization::from_headers(headers).map(|a| a.access_key)
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// The AWS canonical query string: `key=value` pairs sorted by key (values are
/// already percent-encoded on the wire by AWS clients), joined with `&`. A param
/// with no `=` becomes `key=`.
fn canonical_query(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(&str, &str)> = query
        .split('&')
        .map(|p| p.split_once('=').unwrap_or((p, "")))
        .collect();
    pairs.sort_unstable();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Rebuilds the SigV4 canonical request from the wire. The canonical URI is the
/// request path as received (S3 signs it un-normalized, single-encoded); the
/// payload hash is the `x-amz-content-sha256` value verbatim.
fn canonical_request(
    method: &str,
    path: &str,
    query: &str,
    headers: &HeaderMap,
    auth: &Authorization,
    payload_hash: &str,
) -> String {
    let uri = if path.is_empty() { "/" } else { path };
    let mut canonical_headers = String::new();
    for name in &auth.signed_headers {
        let value = headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("");
        // Trim and collapse internal whitespace runs, per the SigV4 spec.
        let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(&value);
        canonical_headers.push('\n');
    }
    let signed_headers = auth.signed_headers.join(";");
    format!(
        "{method}\n{uri}\n{}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
        canonical_query(query),
    )
}

/// How far a request's `x-amz-date` may be from the server clock, either way.
/// Matches S3's 15 minutes. `x-amz-date` is part of the string-to-sign, so this
/// bounds how long a captured request can be replayed.
const MAX_CLOCK_SKEW_SECS: i64 = 15 * 60;

/// Parses an `x-amz-date` (`YYYYMMDDTHHMMSSZ`, UTC) into Unix seconds; `None` if
/// it isn't in exactly that form or names an impossible date/time.
fn parse_amz_date(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let num = |range: std::ops::Range<usize>| -> Option<i64> {
        let digits = &s[range];
        digits.bytes().all(|c| c.is_ascii_digit()).then(|| digits.parse().ok())?
    };
    let (year, month, day) = (num(0..4)?, num(4..6)?, num(6..8)?);
    let (hour, min, sec) = (num(9..11)?, num(11..13)?, num(13..15)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60
    {
        return None;
    }
    // Days since the epoch for a proleptic Gregorian date (Howard Hinnant's
    // days_from_civil).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12; // March = 0
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hour * 3_600 + min * 60 + sec)
}

/// Checks a request's `x-amz-date` against the server clock (`now`, Unix
/// seconds) and its credential scope date, as S3 does: a malformed timestamp or a
/// scope dated another day is `AccessDenied`, and one outside the allowed skew is
/// `RequestTimeTooSkewed`.
fn check_request_time(datetime: &str, scope_date: &str, now: i64) -> Result<(), &'static str> {
    let t = parse_amz_date(datetime).ok_or("AccessDenied")?;
    if datetime[..8] != *scope_date {
        return Err("AccessDenied");
    }
    if (now - t).abs() > MAX_CLOCK_SKEW_SECS {
        return Err("RequestTimeTooSkewed");
    }
    Ok(())
}

/// The values `x-amz-content-sha256` may take besides a hex SHA-256, as S3
/// accepts them.
const PAYLOAD_HASH_KEYWORDS: [&str; 4] = [
    "UNSIGNED-PAYLOAD",
    "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
    "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
    "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
];

/// Whether `value` is something S3 accepts as `x-amz-content-sha256`.
fn valid_payload_hash(value: &str) -> bool {
    PAYLOAD_HASH_KEYWORDS.contains(&value)
        || (value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The headers that the request's signature has to cover, but doesn't:
/// `host`, and every `x-amz-*` header. S3 refuses a request with any of them
/// unsigned, since whoever relays it could otherwise add or change them.
fn unsigned_headers(headers: &HeaderMap, auth: &Authorization) -> Vec<String> {
    let signed = |name: &str| auth.signed_headers.iter().any(|s| s == name);
    let mut names: Vec<String> = headers
        .keys()
        .map(|name| name.as_str())
        .filter(|name| name.starts_with("x-amz-") && !signed(name))
        .map(str::to_owned)
        .collect();
    if !signed("host") {
        names.push("host".to_owned());
    }
    names.sort();
    names
}

/// Verifies a request's SigV4 header signature against `secret`, as S3 does:
///
/// - a missing or malformed `Authorization` or `x-amz-date`: 403 AccessDenied;
/// - no `x-amz-content-sha256` (400 InvalidRequest), or one that's neither a
///   SHA-256 nor one of S3's keywords (400 InvalidArgument). Its value is what
///   the signature covers the body with, so it can't be left out;
/// - `host` or an `x-amz-*` header that the signature doesn't cover: 403
///   AccessDenied, naming them in `HeadersNotSigned`;
/// - a timestamp too far from the server clock: 403 RequestTimeTooSkewed;
/// - a wrong signature: 403 SignatureDoesNotMatch.
pub fn verify_sigv4(
    method: &str,
    path: &str,
    query: &str,
    headers: &HeaderMap,
    secret: &str,
) -> Result<(), Rejection> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs() as i64;
    verify_sigv4_at(method, path, query, headers, secret, now)
}

/// `verify_sigv4`, with the server clock at `now` (Unix seconds).
fn verify_sigv4_at(
    method: &str,
    path: &str,
    query: &str,
    headers: &HeaderMap,
    secret: &str,
    now: i64,
) -> Result<(), Rejection> {
    let access_denied = |message: &str| Rejection::new(StatusCode::FORBIDDEN, "AccessDenied", message);
    let auth = Authorization::from_headers(headers)
        .ok_or_else(|| access_denied("the Authorization header is malformed"))?;
    let datetime = headers
        .get("x-amz-date")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| access_denied("the request has no valid x-amz-date header"))?;
    let payload_hash = match headers.get("x-amz-content-sha256").map(|v| v.to_str()) {
        None => {
            return Err(Rejection::new(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "Missing required header for this request: x-amz-content-sha256",
            ));
        }
        Some(Ok(value)) if valid_payload_hash(value) => value,
        Some(_) => {
            return Err(Rejection::new(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "x-amz-content-sha256 must be UNSIGNED-PAYLOAD, \
                 STREAMING-UNSIGNED-PAYLOAD-TRAILER, STREAMING-AWS4-HMAC-SHA256-PAYLOAD, \
                 STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER or a valid SHA-256 value",
            ));
        }
    };
    let unsigned = unsigned_headers(headers, &auth);
    if !unsigned.is_empty() {
        let mut rejection =
            access_denied("There were headers present in the request which were not signed");
        rejection.details.push(("HeadersNotSigned", unsigned.join(", ")));
        return Err(rejection);
    }
    check_request_time(datetime, &auth.date, now).map_err(|code| {
        let message = match code {
            "RequestTimeTooSkewed" => {
                "The difference between the request time and the server's time is too large."
            }
            _ => "the request's x-amz-date is malformed or doesn't match its credential scope",
        };
        Rejection::new(StatusCode::FORBIDDEN, code, message)
    })?;
    let canonical = canonical_request(method, path, query, headers, &auth, payload_hash);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{datetime}\n{}\n{}",
        auth.scope,
        sha256_hex(canonical.as_bytes()),
    );
    let key = derive_signing_key(secret, &auth.date, &auth.region, &auth.service);
    let mismatch = || {
        Rejection::new(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "The request signature we calculated does not match the signature you provided.",
        )
    };
    let sig = hex_decode(&auth.signature).ok_or_else(mismatch)?;
    let mut mac = HmacSha256::new_from_slice(&key).expect("any key length");
    mac.update(string_to_sign.as_bytes());
    mac.verify_slice(&sig).map_err(|_| mismatch())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::HeaderMap;

    fn test_verifier() -> StreamingChunkVerifier {
        let mut h = HeaderMap::new();
        h.insert("x-amz-date", "20260613T000000Z".parse().unwrap());
        h.insert(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=akid/20260613/us-east-1/s3/aws4_request, \
             SignedHeaders=host, Signature=53ed0a"
                .parse()
                .unwrap(),
        );
        StreamingChunkVerifier::from_headers(&h, "cairnsecret").unwrap()
    }

    const DATE: &str = "20260613T120000Z";
    const SECRET: &str = "cairnsecret";

    /// The headers of a PUT of `/b/k`, signed at `DATE` with `SECRET`, which
    /// covers `headers` (lowercase names), but not `unsigned`, which are added
    /// afterwards.
    fn signed(headers: &[(&str, &str)], unsigned: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (name, value) in headers {
            h.insert(hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(), value.parse().unwrap());
        }
        let mut names: Vec<&str> = headers.iter().map(|(name, _)| *name).collect();
        names.sort();
        let scope = format!("{}/us-east-1/s3/aws4_request", &DATE[..8]);
        let auth = Authorization {
            access_key: "akid".into(),
            date: DATE[..8].into(),
            region: "us-east-1".into(),
            service: "s3".into(),
            scope: scope.clone(),
            signed_headers: names.iter().map(|n| n.to_string()).collect(),
            signature: String::new(),
        };
        let payload_hash = h
            .get("x-amz-content-sha256")
            .map_or("UNSIGNED-PAYLOAD", |v| v.to_str().unwrap())
            .to_owned();
        let canonical = canonical_request("PUT", "/b/k", "", &h, &auth, &payload_hash);
        let sts = format!("AWS4-HMAC-SHA256\n{DATE}\n{scope}\n{}", sha256_hex(canonical.as_bytes()));
        let key = derive_signing_key(SECRET, &auth.date, &auth.region, &auth.service);
        let signature: String =
            hmac_sha256(&key, sts.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential=akid/{scope}, SignedHeaders={}, Signature={signature}",
            names.join(";")
        );
        h.insert("authorization", authorization.parse().unwrap());
        for (name, value) in unsigned {
            h.insert(*name, value.parse().unwrap());
        }
        h
    }

    fn verify(headers: &HeaderMap) -> Result<(), Rejection> {
        verify_sigv4_at("PUT", "/b/k", "", headers, SECRET, parse_amz_date(DATE).unwrap())
    }

    const BASE: [(&str, &str); 3] = [
        ("host", "localhost:8333"),
        ("x-amz-content-sha256", EMPTY_SHA256),
        ("x-amz-date", DATE),
    ];

    #[test]
    fn accepts_a_signed_request() {
        assert_eq!(verify(&signed(&BASE, &[])), Ok(()));
        // Headers other than the host and x-amz-* may go unsigned, as in S3.
        let h = signed(&BASE, &[("content-type", "text/plain"), ("content-encoding", "gzip")]);
        assert_eq!(verify(&h), Ok(()));
        for keyword in PAYLOAD_HASH_KEYWORDS {
            let h = signed(&[BASE[0], ("x-amz-content-sha256", keyword), BASE[2]], &[]);
            assert_eq!(verify(&h), Ok(()), "{keyword}");
        }
    }

    #[test]
    fn rejects_unsigned_amz_headers() {
        let h = signed(&BASE, &[("x-amz-copy-source", "/other/key"), ("x-amz-meta-a", "1")]);
        let rejection = verify(&h).unwrap_err();
        assert_eq!((rejection.status, rejection.code), (StatusCode::FORBIDDEN, "AccessDenied"));
        let unsigned = "x-amz-copy-source, x-amz-meta-a".to_owned();
        assert_eq!(rejection.details, [("HeadersNotSigned", unsigned)]);
        // The host must be signed too.
        let h = signed(&BASE[1..], &[("host", "localhost:8333")]);
        assert_eq!(verify(&h).unwrap_err().details, [("HeadersNotSigned", "host".to_owned())]);
    }

    #[test]
    fn requires_a_valid_payload_hash() {
        let rejection = verify(&signed(&[BASE[0], BASE[2]], &[])).unwrap_err();
        assert_eq!((rejection.status, rejection.code), (StatusCode::BAD_REQUEST, "InvalidRequest"));
        let not_hex = "g".repeat(64);
        for bad in ["STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD", "abc", &not_hex] {
            let h = signed(&[BASE[0], ("x-amz-content-sha256", bad), BASE[2]], &[]);
            let rejection = verify(&h).unwrap_err();
            let expected = (StatusCode::BAD_REQUEST, "InvalidArgument");
            assert_eq!((rejection.status, rejection.code), expected, "{bad}");
        }
    }

    #[test]
    fn rejects_a_changed_payload_hash() {
        let mut h = signed(&BASE, &[]);
        h.insert("x-amz-content-sha256", "UNSIGNED-PAYLOAD".parse().unwrap());
        assert_eq!(verify(&h).unwrap_err().code, "SignatureDoesNotMatch");
    }

    #[test]
    fn chunk_chain_accepts_correct_signature() {
        // Compute the chunk signature the way a client would, then verify it.
        let key = derive_signing_key("cairnsecret", "20260613", "us-east-1", "s3");
        let sts = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n20260613T000000Z\n\
             20260613/us-east-1/s3/aws4_request\n53ed0a\n{EMPTY_SHA256}\n{EMPTY_SHA256}",
        );
        let good: String = hmac_sha256(&key, sts.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(test_verifier().verify_chunk(EMPTY_SHA256, &good));
    }

    #[test]
    fn parses_amz_date() {
        assert_eq!(parse_amz_date("19700101T000000Z"), Some(0));
        assert_eq!(parse_amz_date("20000229T123456Z"), Some(951_827_696));
        assert_eq!(parse_amz_date("20260613T000000Z"), Some(1_781_308_800));
        for bad in [
            "",
            "20260613T000000",
            "20260613 000000Z",
            "2026-6-13T00000Z",
            "20261301T000000Z",
            "20260613T240000Z",
            "+0260613T000000Z",
        ] {
            assert_eq!(parse_amz_date(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn request_time_skew() {
        let t = parse_amz_date("20260613T120000Z").unwrap();
        let check = |now| check_request_time("20260613T120000Z", "20260613", now);
        assert_eq!(check(t), Ok(()));
        assert_eq!(check(t + MAX_CLOCK_SKEW_SECS), Ok(()));
        assert_eq!(check(t - MAX_CLOCK_SKEW_SECS), Ok(()));
        assert_eq!(check(t + MAX_CLOCK_SKEW_SECS + 1), Err("RequestTimeTooSkewed"));
        assert_eq!(check(t - MAX_CLOCK_SKEW_SECS - 1), Err("RequestTimeTooSkewed"));
        // the credential scope must be dated the same day as x-amz-date
        assert_eq!(
            check_request_time("20260613T120000Z", "20260612", t),
            Err("AccessDenied"),
        );
        assert_eq!(check_request_time("garbage", "20260613", t), Err("AccessDenied"));
    }

    #[test]
    fn chunk_chain_rejects_tampered_signature() {
        assert!(!test_verifier().verify_chunk(EMPTY_SHA256, &"0".repeat(64)));
        // a non-hex / wrong-length signature is rejected too
        assert!(!test_verifier().verify_chunk(EMPTY_SHA256, "nothex"));
    }
}
