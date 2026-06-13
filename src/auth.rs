//! Request body integrity and SigV4 streaming-signature verification.
//!
//! A client declares its body's hash in `x-amz-content-sha256`. We verify the
//! body matches that claim — by hashing (modes 2/3) or, for a signed streaming
//! body (mode 4), by verifying the per-chunk HMAC signature chain.

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit, Mac};
use hyper::HeaderMap;
use md5::Md5;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Hex SHA-256 of the empty string — a fixed line in the chunk string-to-sign,
/// and the data hash of the terminating zero-size chunk.
pub const EMPTY_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// The shared secret S3 clients sign streaming uploads with. Fixed for now (not
/// yet configurable). minio-go clients (mcli, Mimir) require a secret of at least
/// 8 characters, so it can't be shortened to just "cairn".
pub const SECRET_KEY: &str = "cairnsecret";

/// What a client's `x-amz-content-sha256` header claims about the body.
#[derive(Debug)]
pub enum ContentSha256 {
    /// `UNSIGNED-PAYLOAD`, or no header: the client makes no claim, so there's
    /// nothing to verify.
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
        let _access_key = cred.next()?;
        let date = cred.next()?.to_owned();
        let region = cred.next()?.to_owned();
        let service = cred.next()?.to_owned();
        let terminator = cred.next()?; // aws4_request
        Some(Authorization {
            scope: format!("{date}/{region}/{service}/{terminator}"),
            date,
            region,
            service,
            signed_headers: signed?.split(';').map(str::to_owned).collect(),
            signature: signature?.to_owned(),
        })
    }
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
    let payload_hash = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("UNSIGNED-PAYLOAD");
    format!(
        "{method}\n{uri}\n{}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
        canonical_query(query),
    )
}

/// Verifies a request's SigV4 header signature against `secret`. `Ok(())` on a
/// match; `Err(code)` with the S3 error code otherwise — missing `Authorization`
/// / `x-amz-date` → `AccessDenied`, wrong signature → `SignatureDoesNotMatch`.
pub fn verify_sigv4(
    method: &str,
    path: &str,
    query: &str,
    headers: &HeaderMap,
    secret: &str,
) -> Result<(), &'static str> {
    let auth = Authorization::from_headers(headers).ok_or("AccessDenied")?;
    let datetime = headers
        .get("x-amz-date")
        .and_then(|v| v.to_str().ok())
        .ok_or("AccessDenied")?;
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{datetime}\n{}\n{}",
        auth.scope,
        sha256_hex(canonical_request(method, path, query, headers, &auth).as_bytes()),
    );
    let key = derive_signing_key(secret, &auth.date, &auth.region, &auth.service);
    let sig = hex_decode(&auth.signature).ok_or("SignatureDoesNotMatch")?;
    let mut mac = HmacSha256::new_from_slice(&key).expect("any key length");
    mac.update(string_to_sign.as_bytes());
    mac.verify_slice(&sig).map_err(|_| "SignatureDoesNotMatch")
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
    fn chunk_chain_rejects_tampered_signature() {
        assert!(!test_verifier().verify_chunk(EMPTY_SHA256, &"0".repeat(64)));
        // a non-hex / wrong-length signature is rejected too
        assert!(!test_verifier().verify_chunk(EMPTY_SHA256, "nothex"));
    }
}
