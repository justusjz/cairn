//! Request body integrity (and, later, SigV4 authentication).
//!
//! A client declares its body's hash in `x-amz-content-sha256`. We verify the
//! body matches that claim; the signature layer (which proves the *claim itself*
//! is authentic) is layered on top later.

use hyper::HeaderMap;

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
    StreamingTrailer,
}

impl ContentSha256 {
    pub fn from_headers(headers: &HeaderMap) -> Self {
        match headers
            .get("x-amz-content-sha256")
            .and_then(|v| v.to_str().ok())
        {
            None | Some("UNSIGNED-PAYLOAD") => ContentSha256::Unsigned,
            Some("STREAMING-AWS4-HMAC-SHA256-PAYLOAD") => ContentSha256::Streaming,
            Some(v) if v.starts_with("STREAMING-") => ContentSha256::StreamingTrailer,
            Some(hex) => ContentSha256::Single(hex.to_ascii_lowercase()),
        }
    }
}
