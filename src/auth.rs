//! Request body integrity (and, later, SigV4 authentication).
//!
//! A client declares its body's hash in `x-amz-content-sha256`. We verify the
//! body matches that claim; the signature layer (which proves the *claim itself*
//! is authentic) is layered on top later.

use base64::{Engine, engine::general_purpose::STANDARD};
use hyper::HeaderMap;
use sha2::{Digest, Sha256};

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
