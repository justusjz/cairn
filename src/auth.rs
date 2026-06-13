//! Request body integrity and SigV4 streaming-signature verification.
//!
//! A client declares its body's hash in `x-amz-content-sha256`. We verify the
//! body matches that claim — by hashing (modes 2/3) or, for a signed streaming
//! body (mode 4), by verifying the per-chunk HMAC signature chain.

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit, Mac};
use hyper::HeaderMap;
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
        let header = |name| headers.get(name).and_then(|v| v.to_str().ok());
        // Authorization: AWS4-HMAC-SHA256 Credential=<akid>/<date>/<region>/<service>/aws4_request,
        //                SignedHeaders=…, Signature=<hex>
        let auth = header("authorization")?.strip_prefix("AWS4-HMAC-SHA256 ")?;
        let mut credential = None;
        let mut signature = None;
        for part in auth.split(',') {
            let part = part.trim();
            if let Some(c) = part.strip_prefix("Credential=") {
                credential = Some(c);
            } else if let Some(s) = part.strip_prefix("Signature=") {
                signature = Some(s);
            }
        }
        let mut cred = credential?.split('/');
        let _access_key = cred.next()?;
        let date = cred.next()?;
        let region = cred.next()?;
        let service = cred.next()?;
        let terminator = cred.next()?; // aws4_request
        Some(Self {
            signing_key: derive_signing_key(secret, date, region, service),
            datetime: header("x-amz-date")?.to_owned(),
            scope: format!("{date}/{region}/{service}/{terminator}"),
            prev_signature: signature?.to_owned(),
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
