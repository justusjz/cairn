//! SigV4: verifying a request's signature, and the signatures of the chunks of
//! a signed streaming body. What a body claims about itself otherwise is
//! checked in `payload`.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use hyper::{HeaderMap, StatusCode};
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
/// body (and its trailer's signature, with `…-PAYLOAD-TRAILER`). Built from the
/// request's `Authorization`/`x-amz-date` plus the server secret, then fed each
/// chunk's data hash and claimed signature in order. The chain starts at the
/// seed signature, the request's own, which `verify_sigv4` has checked against
/// the request's headers. So each chunk is bound to the request, and to the
/// chunks before it.
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
        let string_to_sign = self.chunk_string_to_sign(data_hash);
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

    /// Verifies the trailer's signature, given the hex SHA-256 of its
    /// canonical headers, chained from the terminating chunk's signature.
    pub fn verify_trailer(&self, trailer_hash: &str, signature: &str) -> bool {
        let Some(sig) = hex_decode(signature) else {
            return false;
        };
        let mut mac = HmacSha256::new_from_slice(&self.signing_key).expect("any key length");
        mac.update(self.trailer_string_to_sign(trailer_hash).as_bytes());
        mac.verify_slice(&sig).is_ok()
    }

    fn chunk_string_to_sign(&self, data_hash: &str) -> String {
        format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{}\n{EMPTY_SHA256}\n{}",
            self.datetime, self.scope, self.prev_signature, data_hash,
        )
    }

    fn trailer_string_to_sign(&self, trailer_hash: &str) -> String {
        format!(
            "AWS4-HMAC-SHA256-TRAILER\n{}\n{}\n{}\n{}",
            self.datetime, self.scope, self.prev_signature, trailer_hash,
        )
    }

    /// The signature the next chunk needs, for tests that build a signed body.
    #[cfg(test)]
    pub fn sign_chunk(&mut self, data: &[u8]) -> String {
        let signature = hex(&hmac_sha256(
            &self.signing_key,
            self.chunk_string_to_sign(&sha256_hex(data)).as_bytes(),
        ));
        self.prev_signature = signature.clone();
        signature
    }

    /// The signature a trailer with `canonical` headers needs, for tests.
    #[cfg(test)]
    pub fn sign_trailer(&self, canonical: &str) -> String {
        hex(&hmac_sha256(
            &self.signing_key,
            self.trailer_string_to_sign(&sha256_hex(canonical.as_bytes())).as_bytes(),
        ))
    }
}

#[cfg(test)]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The SigV4 `Authorization` header fields, parsed once and shared by request
/// verification and the streaming chunk verifier. Or the same, from a
/// presigned URL's query (`from_query`).
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

    /// The same fields from a presigned URL's query (`X-Amz-Credential`,
    /// `X-Amz-SignedHeaders`, `X-Amz-Signature`), or `None` if it isn't one.
    fn from_query(query: &str) -> Option<Self> {
        let get = |name| query_value(query, name);
        if get("X-Amz-Algorithm")? != "AWS4-HMAC-SHA256" {
            return None;
        }
        let credential = get("X-Amz-Credential")?;
        let mut cred = credential.split('/');
        let (access_key, date, region, service) = (
            cred.next()?.to_owned(),
            cred.next()?.to_owned(),
            cred.next()?.to_owned(),
            cred.next()?.to_owned(),
        );
        let terminator = cred.next()?;
        Some(Authorization {
            access_key,
            scope: format!("{date}/{region}/{service}/{terminator}"),
            date,
            region,
            service,
            signed_headers: get("X-Amz-SignedHeaders")?
                .split(';')
                .map(str::to_owned)
                .collect(),
            signature: get("X-Amz-Signature")?,
        })
    }
}

/// A query parameter's value, percent-decoded; `None` if it's absent.
fn query_value(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (k == name).then(|| {
            percent_encoding::percent_decode_str(v)
                .decode_utf8_lossy()
                .into_owned()
        })
    })
}

/// Whether the request is signed in its query: a presigned URL.
fn presigned(query: &str) -> bool {
    query_value(query, "X-Amz-Algorithm").is_some()
}

/// What a signed request says about its signature, as policies' condition
/// keys see it (see `s3::access`).
#[derive(Clone, Debug)]
pub struct Signed {
    pub access_key: String,
    /// The service it's signed for (`s3`; `iam`, `sts`).
    pub service: String,
    /// The credential's region.
    pub region: String,
    /// Signed in its query (a presigned URL), rather than its headers.
    pub presigned: bool,
    /// When it was signed (`X-Amz-Date`), as SigV4 writes it.
    pub date: Option<String>,
}

/// The signature a request claims to have (not checked), or `None` for an
/// unsigned or malformed one.
pub fn signed(headers: &HeaderMap, query: &str) -> Option<Signed> {
    let presigned = !headers.contains_key("authorization");
    let authorization = match presigned {
        false => Authorization::from_headers(headers)?,
        true => Authorization::from_query(query)?,
    };
    let date = match presigned {
        false => headers.get("x-amz-date").and_then(|v| v.to_str().ok()).map(str::to_owned),
        true => query_value(query, "X-Amz-Date"),
    };
    Some(Signed {
        access_key: authorization.access_key,
        service: authorization.service,
        region: authorization.region,
        presigned,
        date,
    })
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
    // A presigned URL's signature isn't part of what it signs.
    let mut pairs: Vec<(&str, &str)> = query
        .split('&')
        .map(|p| p.split_once('=').unwrap_or((p, "")))
        .filter(|(k, _)| *k != "X-Amz-Signature")
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
        // Trim and collapse internal whitespace runs, per the SigV4 spec; a
        // header sent more than once is its values, joined by commas.
        let value = headers
            .get_all(name)
            .iter()
            .map(|v| v.to_str().unwrap_or("").split_whitespace().collect::<Vec<_>>().join(" "))
            .collect::<Vec<_>>()
            .join(",");
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
pub(crate) fn parse_amz_date(s: &str) -> Option<i64> {
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
    verify_sigv4_at(method, path, query, headers, secret, now, None)
}

/// As `verify_sigv4`, for a request of another service than S3 (IAM, STS),
/// whose signature covers its `body` by its SHA-256, which the client needn't
/// send in `x-amz-content-sha256` (if it does, it must be the body's).
pub fn verify_sigv4_with_body(
    method: &str,
    path: &str,
    query: &str,
    headers: &HeaderMap,
    secret: &str,
    body: &[u8],
) -> Result<(), Rejection> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock after 1970").as_secs() as i64;
    let hash = sha256_hex(body);
    verify_sigv4_at(method, path, query, headers, secret, now, Some(&hash))
}

/// The longest a presigned URL may be valid: a week, as in S3.
pub const MAX_PRESIGNED_SECS: i64 = 7 * 24 * 60 * 60;

/// `verify_sigv4`, with the server clock at `now` (Unix seconds).
fn verify_sigv4_at(
    method: &str,
    path: &str,
    query: &str,
    headers: &HeaderMap,
    secret: &str,
    now: i64,
    body_hash: Option<&str>,
) -> Result<(), Rejection> {
    if !headers.contains_key("authorization") {
        return verify_presigned_at(method, path, query, headers, secret, now, body_hash);
    }
    if presigned(query) {
        return Err(Rejection::new(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "Only one auth mechanism allowed; only the X-Amz-Algorithm query parameter or the \
             Authorization header should be specified",
        ));
    }
    let access_denied = |message: &str| Rejection::new(StatusCode::FORBIDDEN, "AccessDenied", message);
    let auth = Authorization::from_headers(headers)
        .ok_or_else(|| access_denied("the Authorization header is malformed"))?;
    let datetime = headers
        .get("x-amz-date")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| access_denied("the request has no valid x-amz-date header"))?;
    let payload_hash = match headers.get("x-amz-content-sha256").map(|v| v.to_str()) {
        // The body's, as the service signs it.
        Some(Ok(value)) if body_hash.is_some_and(|hash| hash == value) => value,
        Some(_) if body_hash.is_some() => {
            return Err(Rejection::new(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "x-amz-content-sha256 isn't the body's SHA-256",
            ));
        }
        None if body_hash.is_some() => body_hash.unwrap(),
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
    check_signature(
        method,
        path,
        query,
        headers,
        &auth,
        payload_hash,
        datetime,
        secret,
    )
}

/// Verifies a presigned URL: a SigV4 signature in the query (`X-Amz-*`), as S3
/// does. It's valid from its `X-Amz-Date` (give or take the clock skew S3
/// allows) for `X-Amz-Expires` seconds, at most a week. For S3 its body is
/// unsigned, unless it comes with a (signed) `x-amz-content-sha256`; for
/// another service (`body_hash`), its signature covers its body, as with a
/// signed header, so a body can't be added to a leaked URL. `host` and every
/// `x-amz-*` header must be signed, as with a signed header.
fn verify_presigned_at(
    method: &str,
    path: &str,
    query: &str,
    headers: &HeaderMap,
    secret: &str,
    now: i64,
    body_hash: Option<&str>,
) -> Result<(), Rejection> {
    let parameters_error = |message: &str| {
        Rejection::new(
            StatusCode::BAD_REQUEST,
            "AuthorizationQueryParametersError",
            message,
        )
    };
    let access_denied =
        |message: &str| Rejection::new(StatusCode::FORBIDDEN, "AccessDenied", message);
    let auth = Authorization::from_query(query).ok_or_else(|| {
        parameters_error(
            "Query-string authentication version 4 requires the X-Amz-Algorithm, \
             X-Amz-Credential, X-Amz-Signature, X-Amz-Date, X-Amz-SignedHeaders, and \
             X-Amz-Expires parameters.",
        )
    })?;
    let datetime = query_value(query, "X-Amz-Date")
        .ok_or_else(|| parameters_error("X-Amz-Date is missing"))?;
    let expires: i64 = query_value(query, "X-Amz-Expires")
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| parameters_error("X-Amz-Expires should be a number"))?;
    // Out of range is a 403, as S3 answers it; not a number, a 400.
    if expires <= 0 {
        return Err(access_denied("X-Amz-Expires must be non-negative"));
    }
    if expires > MAX_PRESIGNED_SECS {
        return Err(access_denied(
            "X-Amz-Expires must be less than a week (in seconds) that is 604800",
        ));
    }
    let signed_at = parse_amz_date(&datetime)
        .filter(|_| datetime[..8] == *auth.date)
        .ok_or_else(|| {
            access_denied(
                "the presigned URL's X-Amz-Date is malformed or doesn't match its credential scope",
            )
        })?;
    if now < signed_at - MAX_CLOCK_SKEW_SECS {
        return Err(access_denied("Request is not valid yet"));
    }
    if now > signed_at + expires {
        return Err(access_denied("Request has expired"));
    }
    let payload_hash = match headers.get("x-amz-content-sha256").map(|v| v.to_str()) {
        Some(Ok(value)) if body_hash.is_some_and(|hash| hash == value) => value,
        Some(_) if body_hash.is_some() => {
            return Err(Rejection::new(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "x-amz-content-sha256 isn't the body's SHA-256",
            ));
        }
        None if body_hash.is_some() => body_hash.unwrap(),
        None => "UNSIGNED-PAYLOAD",
        Some(Ok(value)) if valid_payload_hash(value) => value,
        Some(_) => {
            return Err(Rejection::new(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "x-amz-content-sha256 must be UNSIGNED-PAYLOAD or a valid SHA-256 value",
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
    check_signature(
        method,
        path,
        query,
        headers,
        &auth,
        payload_hash,
        &datetime,
        secret,
    )
}

/// The signature of a POST Object form (see `s3::objects::post`): its policy
/// signed with SigV4, in the fields `x-amz-algorithm`, `x-amz-credential`,
/// `x-amz-date` and `x-amz-signature`.
#[derive(Debug)]
pub struct PostSignature {
    pub access_key: String,
    date: String,
    region: String,
    service: String,
    /// The `policy` field, base64, as sent: what's signed.
    policy: String,
    signature: String,
}

impl PostSignature {
    /// How the form is signed, as a request's signature is: for its
    /// condition keys (`s3:authType` `POST`, `s3:signatureversion`,
    /// `aws:RequestedRegion`), which a policy may deny forms by.
    pub fn signed(&self) -> Signed {
        Signed {
            access_key: self.access_key.clone(),
            service: "s3".to_owned(),
            region: self.region.clone(),
            presigned: false,
            date: None,
        }
    }

    /// The signature a form's fields (`field` by lowercase name) carry, or
    /// why they don't carry one. Its time has to be its credential's day; the
    /// policy's expiration bounds how long it's valid, not the clock skew.
    pub fn from_fields<'a>(field: impl Fn(&str) -> Option<&'a str>) -> Result<PostSignature, Rejection> {
        let parameters_error = |message: &str| {
            Rejection::new(StatusCode::BAD_REQUEST, "AuthorizationQueryParametersError", message)
        };
        let (Some(policy), Some(signature)) = (field("policy"), field("x-amz-signature")) else {
            return Err(Rejection::new(StatusCode::FORBIDDEN, "AccessDenied", "the form is not signed"));
        };
        if field("x-amz-algorithm") != Some("AWS4-HMAC-SHA256") {
            return Err(parameters_error("X-Amz-Algorithm only supports \"AWS4-HMAC-SHA256\""));
        }
        let credential = field("x-amz-credential").unwrap_or("");
        let mut parts = credential.split('/');
        let (Some(access_key), Some(date), Some(region), Some(service), Some("aws4_request"), None) =
            (parts.next(), parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(parameters_error(
                "Error parsing the X-Amz-Credential parameter; the Credential is mal-formed; \
                 expecting \"<YOUR-AKID>/YYYYMMDD/REGION/SERVICE/aws4_request\".",
            ));
        };
        let datetime = field("x-amz-date").unwrap_or("");
        if parse_amz_date(datetime).is_none() || datetime[..8] != *date {
            return Err(Rejection::new(
                StatusCode::FORBIDDEN,
                "AccessDenied",
                "the form's x-amz-date is malformed or doesn't match its credential scope",
            ));
        }
        Ok(PostSignature {
            access_key: access_key.to_owned(),
            date: date.to_owned(),
            region: region.to_owned(),
            service: service.to_owned(),
            policy: policy.to_owned(),
            signature: signature.to_owned(),
        })
    }

    /// Checks the signature of the policy under the key `secret` derives for
    /// the credential's scope.
    pub fn verify(&self, secret: &str) -> Result<(), Rejection> {
        let key = derive_signing_key(secret, &self.date, &self.region, &self.service);
        let mismatch = || {
            Rejection::new(
                StatusCode::FORBIDDEN,
                "SignatureDoesNotMatch",
                "The request signature we calculated does not match the signature you provided.",
            )
        };
        let sig = hex_decode(&self.signature).ok_or_else(mismatch)?;
        let mut mac = HmacSha256::new_from_slice(&key).expect("any key length");
        mac.update(self.policy.as_bytes());
        mac.verify_slice(&sig).map_err(|_| mismatch())
    }
}

/// Checks the signature of the canonical request the parts make, under the
/// key `secret` derives for the credential's scope.
#[allow(clippy::too_many_arguments)]
fn check_signature(
    method: &str,
    path: &str,
    query: &str,
    headers: &HeaderMap,
    auth: &Authorization,
    payload_hash: &str,
    datetime: &str,
    secret: &str,
) -> Result<(), Rejection> {
    let canonical = canonical_request(method, path, query, headers, auth, payload_hash);
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
pub(crate) mod tests {
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
        verify_sigv4_at("PUT", "/b/k", "", headers, SECRET, parse_amz_date(DATE).unwrap(), None)
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

    /// A header sent more than once is signed as its values, joined by
    /// commas (as the SigV4 spec says, and botocore signs it).
    #[test]
    fn signs_a_repeated_headers_values_together() {
        let mut headers = HeaderMap::new();
        headers.append("x-amz-object-attributes", "ETag".parse().unwrap());
        headers.append("x-amz-object-attributes", " Object  Size ".parse().unwrap());
        let auth = Authorization {
            access_key: String::new(),
            date: String::new(),
            region: String::new(),
            service: String::new(),
            scope: String::new(),
            signed_headers: vec!["x-amz-object-attributes".to_owned()],
            signature: String::new(),
        };
        let canonical = canonical_request("GET", "/b/k", "attributes", &headers, &auth, EMPTY_SHA256);
        assert!(canonical.contains("\nx-amz-object-attributes:ETag,Object Size\n"), "{canonical}");
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

    /// AWS's example of a presigned URL (a GET of examplebucket's test.txt,
    /// signed on 24 May 2013 for a day), from its SigV4 documentation.
    const AWS_PRESIGNED: &str = "X-Amz-Algorithm=AWS4-HMAC-SHA256\
        &X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request\
        &X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host\
        &X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404";
    const AWS_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    fn verify_aws_presigned(query: &str, headers: &HeaderMap, now: i64) -> Result<(), Rejection> {
        verify_sigv4_at("GET", "/test.txt", query, headers, AWS_SECRET, now, None)
    }

    /// A presigned IAM request (another service than S3) signs its body:
    /// one presigned with none can't be sent with one, to run another action.
    #[test]
    fn a_presigned_iam_request_signs_its_body() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "localhost:8333".parse().unwrap());
        let query = format!(
            "Action=ListAccessKeys&Version=2010-05-08&X-Amz-Algorithm=AWS4-HMAC-SHA256\
             &X-Amz-Credential=akid%2F{}%2Fus-east-1%2Fiam%2Faws4_request\
             &X-Amz-Date={DATE}&X-Amz-Expires=3600&X-Amz-SignedHeaders=host",
            &DATE[..8]
        );
        let auth = Authorization::from_query(&format!("{query}&X-Amz-Signature=x")).unwrap();
        let canonical = canonical_request("POST", "/", &query, &headers, &auth, EMPTY_SHA256);
        let sts = format!("AWS4-HMAC-SHA256\n{DATE}\n{}\n{}", auth.scope, sha256_hex(canonical.as_bytes()));
        let key = derive_signing_key(SECRET, &auth.date, &auth.region, &auth.service);
        let signature: String = hmac_sha256(&key, sts.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
        let query = format!("{query}&X-Amz-Signature={signature}");
        let now = parse_amz_date(DATE).unwrap();
        let verify = |body: &[u8]| {
            verify_sigv4_at("POST", "/", &query, &headers, SECRET, now, Some(&sha256_hex(body)))
        };
        assert_eq!(verify(b""), Ok(()));
        let rejection = verify(b"Action=CreateAccessKey&UserName=root").unwrap_err();
        assert_eq!(rejection.code, "SignatureDoesNotMatch");
    }

    fn aws_host() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("host", "examplebucket.s3.amazonaws.com".parse().unwrap());
        h
    }

    #[test]
    fn verifies_a_presigned_url() {
        let signed_at = parse_amz_date("20130524T000000Z").unwrap();
        let claimed = super::signed(&aws_host(), AWS_PRESIGNED).unwrap();
        assert_eq!(claimed.access_key, "AKIAIOSFODNN7EXAMPLE");
        assert!(claimed.presigned);
        assert_eq!(claimed.region, "us-east-1");
        assert_eq!(claimed.date.as_deref(), Some("20130524T000000Z"));
        // Valid for its day, and from a little before it, as the clock may be off.
        for now in [signed_at - 60, signed_at, signed_at + 86_400] {
            assert_eq!(
                verify_aws_presigned(AWS_PRESIGNED, &aws_host(), now),
                Ok(()),
                "{now}"
            );
        }
        let code = |query: &str, headers: &HeaderMap, now: i64| {
            verify_aws_presigned(query, headers, now).unwrap_err()
        };
        assert_eq!(
            code(AWS_PRESIGNED, &aws_host(), signed_at + 86_401).message,
            "Request has expired"
        );
        assert_eq!(
            code(AWS_PRESIGNED, &aws_host(), signed_at - 3600).message,
            "Request is not valid yet"
        );
        // Anything it covers changed: the expiry, the host, the path.
        let longer = AWS_PRESIGNED.replace("X-Amz-Expires=86400", "X-Amz-Expires=86500");
        assert_eq!(
            code(&longer, &aws_host(), signed_at).code,
            "SignatureDoesNotMatch"
        );
        let mut other_host = HeaderMap::new();
        other_host.insert("host", "otherbucket.s3.amazonaws.com".parse().unwrap());
        assert_eq!(
            code(AWS_PRESIGNED, &other_host, signed_at).code,
            "SignatureDoesNotMatch"
        );
        let other_path = verify_sigv4_at(
            "GET",
            "/other.txt",
            AWS_PRESIGNED,
            &aws_host(),
            AWS_SECRET,
            signed_at,
            None,
        );
        assert_eq!(other_path.unwrap_err().code, "SignatureDoesNotMatch");
        // An x-amz-* header it doesn't cover.
        let mut extra = aws_host();
        extra.insert("x-amz-meta-a", "1".parse().unwrap());
        assert_eq!(code(AWS_PRESIGNED, &extra, signed_at).code, "AccessDenied");
        // At most a week, and positive (403, as S3 answers); a number (400).
        for (expires, expected) in [
            ("604801", (StatusCode::FORBIDDEN, "AccessDenied")),
            ("0", (StatusCode::FORBIDDEN, "AccessDenied")),
            ("-5", (StatusCode::FORBIDDEN, "AccessDenied")),
            (
                "soon",
                (StatusCode::BAD_REQUEST, "AuthorizationQueryParametersError"),
            ),
        ] {
            let query =
                AWS_PRESIGNED.replace("X-Amz-Expires=86400", &format!("X-Amz-Expires={expires}"));
            let rejection = code(&query, &aws_host(), signed_at);
            assert_eq!((rejection.status, rejection.code), expected, "{expires}");
        }
        // Not both kinds of signature at once.
        let both = signed(&BASE, &[]);
        let rejection = verify_sigv4_at(
            "PUT",
            "/b/k",
            AWS_PRESIGNED,
            &both,
            SECRET,
            parse_amz_date(DATE).unwrap(),
            None,
        )
        .unwrap_err();
        assert_eq!(
            (rejection.status, rejection.code),
            (StatusCode::BAD_REQUEST, "InvalidArgument")
        );
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

    /// AWS's example POST policy (sigv4-post-example), base64, as signed.
    pub(crate) const AWS_POST_POLICY: &str = "eyAiZXhwaXJhdGlvbiI6ICIyMDE1LTEyLTMwVDEyOjAwOjAwLjAwMFoiLA0KICAiY29uZGl0aW9ucyI6IFsNCiAgICB7ImJ1Y2tldCI6ICJzaWd2NGV4YW1wbGVidWNrZXQifSwNCiAgICBbInN0YXJ0cy13aXRoIiwgIiRrZXkiLCAidXNlci91c2VyMS8iXSwNCiAgICB7ImFjbCI6ICJwdWJsaWMtcmVhZCJ9LA0KICAgIHsic3VjY2Vzc19hY3Rpb25fcmVkaXJlY3QiOiAiaHR0cDovL3NpZ3Y0ZXhhbXBsZWJ1Y2tldC5zMy5hbWF6b25hd3MuY29tL3N1Y2Nlc3NmdWxfdXBsb2FkLmh0bWwifSwNCiAgICBbInN0YXJ0cy13aXRoIiwgIiRDb250ZW50LVR5cGUiLCAiaW1hZ2UvIl0sDQogICAgeyJ4LWFtei1tZXRhLXV1aWQiOiAiMTQzNjUxMjM2NTEyNzQifSwNCiAgICB7IngtYW16LXNlcnZlci1zaWRlLWVuY3J5cHRpb24iOiAiQUVTMjU2In0sDQogICAgWyJzdGFydHMtd2l0aCIsICIkeC1hbXotbWV0YS10YWciLCAiIl0sDQoNCiAgICB7IngtYW16LWNyZWRlbnRpYWwiOiAiQUtJQUlPU0ZPRE5ON0VYQU1QTEUvMjAxNTEyMjkvdXMtZWFzdC0xL3MzL2F3czRfcmVxdWVzdCJ9LA0KICAgIHsieC1hbXotYWxnb3JpdGhtIjogIkFXUzQtSE1BQy1TSEEyNTYifSwNCiAgICB7IngtYW16LWRhdGUiOiAiMjAxNTEyMjlUMDAwMDAwWiIgfQ0KICBdDQp9";

    /// The fields of AWS's example form, with `changed` replacing some.
    fn aws_post_form(changed: &[(&'static str, &'static str)]) -> Vec<(&'static str, &'static str)> {
        let mut fields = vec![
            ("policy", AWS_POST_POLICY),
            ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
            ("x-amz-credential", "AKIAIOSFODNN7EXAMPLE/20151229/us-east-1/s3/aws4_request"),
            ("x-amz-date", "20151229T000000Z"),
            ("x-amz-signature", "8afdbf4008c03f22c2cd3cdb72e4afbb1f6a588f3255ac628749a66d7f09699e"),
        ];
        for (name, value) in changed {
            fields.retain(|(n, _)| n != name);
            if !value.is_empty() {
                fields.push((name, value));
            }
        }
        fields
    }

    fn post_signature(fields: &[(&'static str, &'static str)]) -> Result<PostSignature, Rejection> {
        PostSignature::from_fields(|name| fields.iter().find(|(n, _)| *n == name).map(|(_, v)| *v))
    }

    #[test]
    fn verifies_aws_post_example() {
        let signature = post_signature(&aws_post_form(&[])).unwrap();
        assert_eq!(signature.access_key, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(signature.verify(AWS_SECRET), Ok(()));
        let code = |r: Result<(), Rejection>| r.unwrap_err().code;
        assert_eq!(code(signature.verify("other")), "SignatureDoesNotMatch");
        // Another policy, or another day's key.
        let other = post_signature(&aws_post_form(&[("policy", "e30=")])).unwrap();
        assert_eq!(code(other.verify(AWS_SECRET)), "SignatureDoesNotMatch");
        let other = post_signature(&aws_post_form(&[
            ("x-amz-credential", "AKIAIOSFODNN7EXAMPLE/20151230/us-east-1/s3/aws4_request"),
            ("x-amz-date", "20151230T000000Z"),
        ]))
        .unwrap();
        assert_eq!(code(other.verify(AWS_SECRET)), "SignatureDoesNotMatch");
        let bad = post_signature(&aws_post_form(&[("x-amz-signature", "nothex")])).unwrap();
        assert_eq!(code(bad.verify(AWS_SECRET)), "SignatureDoesNotMatch");
    }

    #[test]
    fn refuses_malformed_post_signatures() {
        let code = |changed: &[(&'static str, &'static str)]| post_signature(&aws_post_form(changed)).unwrap_err().code;
        assert_eq!(code(&[("policy", "")]), "AccessDenied");
        assert_eq!(code(&[("x-amz-signature", "")]), "AccessDenied");
        assert_eq!(code(&[("x-amz-algorithm", "")]), "AuthorizationQueryParametersError");
        assert_eq!(code(&[("x-amz-algorithm", "AWS4-HMAC-SHA1")]), "AuthorizationQueryParametersError");
        assert_eq!(code(&[("x-amz-credential", "")]), "AuthorizationQueryParametersError");
        assert_eq!(code(&[("x-amz-credential", "AKID/20151229/us-east-1/s3")]), "AuthorizationQueryParametersError");
        assert_eq!(code(&[("x-amz-credential", "AKID/20151229/us-east-1/s3/aws4_request/x")]), "AuthorizationQueryParametersError");
        assert_eq!(code(&[("x-amz-date", "")]), "AccessDenied");
        assert_eq!(code(&[("x-amz-date", "20151229")]), "AccessDenied");
        assert_eq!(code(&[("x-amz-date", "20151230T000000Z")]), "AccessDenied");
    }
}
