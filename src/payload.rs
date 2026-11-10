//! A request body, checked against everything the request claims about it, as
//! S3 checks it:
//!
//! - `x-amz-content-sha256`: the SHA-256 of the body as sent, or a keyword.
//!   `STREAMING-…` means the body is `aws-chunked` framed, and is decoded; its
//!   chunks are signed (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD…`) or not
//!   (`STREAMING-UNSIGNED-PAYLOAD-TRAILER`). Only this header decides the
//!   framing: `Content-Encoding` isn't signed, so it can't.
//! - `x-amz-decoded-content-length`: the length of a streaming body's data.
//! - `Content-MD5`, and an `x-amz-checksum-*` header: checksums of the data.
//! - `x-amz-trailer`: a checksum of the data, which a streaming body carries
//!   in a trailer after its last chunk.
//!
//! `verify_sigv4` has checked the signature over these headers, and that
//! `x-amz-content-sha256` is valid. A body is fed through [`Payload::decode`]
//! as it arrives, which yields its data, and [`Payload::finish`] then says
//! whether it was all it claimed to be. Nothing of it should be kept before
//! that.

use base64::{Engine, engine::general_purpose::STANDARD};
use hyper::{HeaderMap, StatusCode, body::Bytes};
use md5::Md5;
use sha2::{Digest, Sha256};

use crate::{
    auth::{Rejection, StreamingChunkVerifier},
    aws_chunked::{AwsChunkedDecoder, ChunkError},
    s3::checksums::{Algorithm, Hasher as Checksum, SDK_ALGORITHM},
};

/// A request body as it arrives, and what it's checked against.
pub struct Payload {
    /// The `aws-chunked` framing of a streaming body.
    decoder: Option<AwsChunkedDecoder>,
    /// Whether a streaming body's chunks (and trailer) are signed.
    signed: bool,
    /// `x-amz-decoded-content-length`, for a streaming body.
    decoded_length: Option<u64>,
    /// `Content-Length`, which, unless the body is streaming, is the data's.
    content_length: Option<u64>,
    /// The most data the body may hold (see `at_most`).
    max: Option<u64>,
    /// The least data it may hold (see `at_least`).
    min: Option<u64>,
    /// How many bytes of data have been decoded.
    decoded: u64,
    /// The SHA-256 of the body as sent, and the hex one it claims.
    sha256: Option<(Sha256, String)>,
    /// The MD5 of the data, and the one `Content-MD5` claims.
    md5: Option<(Md5, Vec<u8>)>,
    /// The checksum of the data that an `x-amz-checksum-*` header claims.
    checksum: Option<(Algorithm, Checksum, Vec<u8>)>,
    /// The checksum of the data that the trailer is to claim.
    trailer: Option<(Algorithm, Checksum)>,
}

/// Whether the request has a header that declares a checksum of its body:
/// `Content-MD5` or an `x-amz-checksum-*` one. DeleteObjects requires one.
pub fn has_body_checksum(headers: &HeaderMap) -> bool {
    headers.contains_key("content-md5")
        || Algorithm::ALL.iter().any(|a| headers.contains_key(a.header()))
}

fn bad_request(code: &'static str, message: impl Into<String>) -> Rejection {
    Rejection::new(StatusCode::BAD_REQUEST, code, message)
}

/// S3's 400 for an upload over its size limit.
pub fn too_large() -> Rejection {
    bad_request("EntityTooLarge", "Your proposed upload exceeds the maximum allowed size.")
}

/// S3's 400 for an upload under the size a POST policy requires.
pub fn too_small() -> Rejection {
    bad_request("EntityTooSmall", "Your proposed upload is smaller than the minimum allowed object size.")
}

fn bad_digest(algorithm: Algorithm) -> Rejection {
    bad_request(
        "BadDigest",
        format!("The {} you specified did not match the calculated checksum.", algorithm.name()),
    )
}

impl Payload {
    /// What the request's headers claim about its body, or why they're
    /// refused before any of it is read. `secret` is the role's, to verify a
    /// signed streaming body with. `checksum_headers` says whether an
    /// `x-amz-checksum-*` header is one of the body: for most requests, but
    /// not CompleteMultipartUpload, where it's the object's.
    pub fn new(
        headers: &HeaderMap,
        secret: &str,
        checksum_headers: bool,
    ) -> Result<Payload, Rejection> {
        let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
        let mut payload = Payload::unchecked();
        payload.content_length = header("content-length").and_then(|v| v.trim().parse().ok());
        // `verify_sigv4` has checked that it's there, and valid.
        // Only a presigned URL comes without one (`verify_sigv4` checked a
        // signed header's): its body is unsigned.
        let (streaming, trailer) = match header("x-amz-content-sha256").unwrap_or("UNSIGNED-PAYLOAD") {
            "UNSIGNED-PAYLOAD" => (false, false),
            "STREAMING-UNSIGNED-PAYLOAD-TRAILER" => (true, true),
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" => {
                payload.signed = true;
                (true, false)
            }
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER" => {
                payload.signed = true;
                (true, true)
            }
            hex => {
                payload.sha256 = Some((Sha256::new(), hex.to_ascii_lowercase()));
                (false, false)
            }
        };
        if streaming {
            let verifier = match payload.signed {
                true => Some(StreamingChunkVerifier::from_headers(headers, secret).ok_or_else(
                    || Rejection::new(StatusCode::FORBIDDEN, "AccessDenied", "the request isn't signed"),
                )?),
                false => None,
            };
            payload.decoder = Some(AwsChunkedDecoder::new(verifier));
            let length = header("x-amz-decoded-content-length").ok_or_else(|| {
                Rejection::new(
                    StatusCode::LENGTH_REQUIRED,
                    "MissingContentLength",
                    "You must provide the x-amz-decoded-content-length HTTP header.",
                )
            })?;
            let length = length.trim().parse().map_err(|_| {
                bad_request("InvalidArgument", "x-amz-decoded-content-length is not a number")
            })?;
            payload.decoded_length = Some(length);
        }
        if trailer {
            let algorithm = header("x-amz-trailer").and_then(Algorithm::from_header).ok_or_else(|| {
                bad_request(
                    "InvalidRequest",
                    "The value specified in the x-amz-trailer header is not supported",
                )
            })?;
            payload.trailer = Some((algorithm, Checksum::new(algorithm)));
        }
        if let Some(value) = headers.get("content-md5") {
            let md5 = value.to_str().ok().and_then(|v| STANDARD.decode(v.trim()).ok());
            let md5 = md5.filter(|md5| md5.len() == 16).ok_or_else(|| {
                bad_request("InvalidDigest", "The Content-MD5 you specified was not valid.")
            })?;
            payload.md5 = Some((Md5::new(), md5));
        }
        if checksum_headers {
            let mut declared = Algorithm::ALL.into_iter().filter(|a| headers.contains_key(a.header()));
            if let Some(algorithm) = declared.next() {
                if declared.next().is_some() {
                    return Err(bad_request(
                        "InvalidRequest",
                        "Expecting a single x-amz-checksum- header. Multiple checksum Types are \
                         not allowed.",
                    ));
                }
                let claimed = header(algorithm.header()).and_then(|v| algorithm.decode(v));
                let claimed = claimed.ok_or_else(|| {
                    bad_request(
                        "InvalidRequest",
                        format!("Value for {} header is invalid.", algorithm.header()),
                    )
                })?;
                payload.checksum = Some((algorithm, Checksum::new(algorithm), claimed));
            }
            // An SDK names the algorithm of the checksum it sends, which S3
            // requires to be sent, and to be of that algorithm.
            if let Some(named) = header(SDK_ALGORITHM) {
                match (Algorithm::from_name(named), payload.declared_algorithm()) {
                    (Some(named), Some(sent)) if named != sent => return Err(bad_digest(named)),
                    (Some(_), Some(_)) => {}
                    (Some(named), None) => {
                        return Err(bad_request(
                            "InvalidRequest",
                            format!(
                                "x-amz-sdk-checksum-algorithm specified, but no corresponding \
                                 {} header or trailer was sent.",
                                named.header()
                            ),
                        ));
                    }
                    (None, _) => {
                        return Err(bad_request(
                            "InvalidRequest",
                            "Value for x-amz-sdk-checksum-algorithm header is invalid.",
                        ));
                    }
                }
            }
        }
        Ok(payload)
    }

    /// The algorithm of the checksum the body declares it comes with (in an
    /// `x-amz-checksum-*` header, or the trailer), if any.
    pub fn declared_algorithm(&self) -> Option<Algorithm> {
        self.checksum.as_ref().map(|(a, ..)| *a).or(self.trailer.as_ref().map(|(a, _)| *a))
    }

    /// The MD5 `Content-MD5` declares. Once `finish` succeeds, it's the data's.
    pub fn claimed_md5(&self) -> Option<[u8; 16]> {
        self.md5.as_ref().and_then(|(_, claimed)| claimed.as_slice().try_into().ok())
    }

    /// A body that claims nothing, and isn't framed: data from within Cairn.
    pub fn unchecked() -> Payload {
        Payload {
            decoder: None,
            signed: false,
            decoded_length: None,
            content_length: None,
            max: None,
            min: None,
            decoded: 0,
            sha256: None,
            md5: None,
            checksum: None,
            trailer: None,
        }
    }

    /// Limits an upload's data to `max` bytes, as S3 does: refused now if it
    /// declares more (in `Content-Length`, or, streaming, in
    /// `x-amz-decoded-content-length`), and as soon as more of it arrives (a
    /// body in chunked transfer encoding, which S3 takes too, declares none).
    pub fn at_most(mut self, max: u64) -> Result<Payload, Rejection> {
        let declared = match self.decoder {
            Some(_) => self.decoded_length,
            None => self.content_length,
        };
        if declared.is_some_and(|length| length > max) {
            return Err(too_large());
        }
        self.max = Some(max);
        Ok(self)
    }

    /// Requires an upload's data to be at least `min` bytes, as a POST
    /// policy can (see `s3::post_policy`): refused once it's all in.
    pub fn at_least(mut self, min: u64) -> Payload {
        self.min = Some(min);
        self
    }

    /// Takes the next `chunk` of the body as sent, and returns the data in it.
    pub fn decode(&mut self, chunk: Bytes) -> Result<Vec<Bytes>, Rejection> {
        if let Some((hasher, _)) = &mut self.sha256 {
            hasher.update(&chunk);
        }
        let data = match &mut self.decoder {
            Some(decoder) => decoder.decode(chunk).map_err(chunk_rejection)?,
            None => vec![chunk],
        };
        for piece in &data {
            self.decoded += piece.len() as u64;
            if self.max.is_some_and(|max| self.decoded > max) {
                return Err(too_large());
            }
            if let Some((hasher, _)) = &mut self.md5 {
                hasher.update(piece);
            }
            if let Some((_, checksum, _)) = &mut self.checksum {
                checksum.update(piece);
            }
            if let Some((_, checksum)) = &mut self.trailer {
                checksum.update(piece);
            }
        }
        Ok(data)
    }

    /// Checks, once the whole body has been read, that it was everything it
    /// claimed to be, and returns the checksum it came with (in an
    /// `x-amz-checksum-*` header, or the trailer), checked: its algorithm, and
    /// its raw bytes.
    pub fn finish(self) -> Result<Option<(Algorithm, Vec<u8>)>, Rejection> {
        let mut checked = None;
        if self.min.is_some_and(|min| self.decoded < min) {
            return Err(too_small());
        }
        if let Some(decoder) = &self.decoder {
            if !decoder.is_complete() || self.decoded_length != Some(self.decoded) {
                return Err(bad_request(
                    "IncompleteBody",
                    "You did not provide the number of bytes specified by the \
                     x-amz-decoded-content-length HTTP header",
                ));
            }
            if let Some((algorithm, checksum)) = self.trailer {
                let claimed = decoder.trailer(algorithm.header()).ok_or_else(|| {
                    bad_request(
                        "MalformedTrailerError",
                        "The request contained trailing data that was not well-formed or did \
                         not conform to our published schema.",
                    )
                })?;
                if self.signed {
                    decoder.verify_trailer_signature().map_err(chunk_rejection)?;
                }
                let computed = checksum.finish();
                if algorithm.decode(&claimed).as_ref() != Some(&computed) {
                    return Err(bad_digest(algorithm));
                }
                checked = Some((algorithm, computed));
            }
        }
        if let Some((hasher, claimed)) = self.sha256 {
            let computed: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
            if computed != claimed {
                let mut rejection = bad_request(
                    "XAmzContentSHA256Mismatch",
                    "The provided 'x-amz-content-sha256' header does not match what was computed.",
                );
                rejection.details.push(("ClientComputedContentSHA256", claimed));
                rejection.details.push(("S3ComputedContentSHA256", computed));
                return Err(rejection);
            }
        }
        if let Some((hasher, claimed)) = self.md5
            && hasher.finalize().as_slice() != claimed
        {
            return Err(bad_request(
                "BadDigest",
                "The Content-MD5 you specified did not match what we received.",
            ));
        }
        if let Some((algorithm, checksum, claimed)) = self.checksum {
            if checksum.finish() != claimed {
                return Err(bad_digest(algorithm));
            }
            checked = Some((algorithm, claimed));
        }
        Ok(checked)
    }
}

/// The S3 error for an `aws-chunked` body that failed to decode.
fn chunk_rejection(error: ChunkError) -> Rejection {
    match error {
        ChunkError::Signature => Rejection::new(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "The request signature we calculated does not match the signature you provided.",
        ),
        ChunkError::TooSmall => bad_request(
            "InvalidChunkSizeError",
            "Only the last chunk is allowed to have a size less than 8192 bytes",
        ),
        ChunkError::Malformed(what) => {
            bad_request("IncompleteBody", format!("The aws-chunked body is malformed: {what}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::EMPTY_SHA256;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (name, value) in pairs {
            h.append(*name, value.parse().unwrap());
        }
        h
    }

    /// Feeds `body` to the payload `pairs` describe, one byte at a time, and
    /// returns the data, or the rejection.
    fn read(pairs: &[(&'static str, &str)], body: &[u8]) -> Result<Vec<u8>, Rejection> {
        let mut payload = Payload::new(&headers(pairs), "secret", true)?;
        let mut data = Vec::new();
        for byte in body {
            for piece in payload.decode(Bytes::copy_from_slice(&[*byte]))? {
                data.extend_from_slice(&piece);
            }
        }
        payload.finish()?;
        Ok(data)
    }

    fn code(result: Result<Vec<u8>, Rejection>) -> &'static str {
        result.unwrap_err().code
    }

    fn sha256_hex(data: &[u8]) -> String {
        Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn checks_the_sha256_of_the_body_as_sent() {
        let hash = sha256_hex(b"data");
        assert_eq!(read(&[("x-amz-content-sha256", &hash)], b"data").unwrap(), b"data");
        let rejection = read(&[("x-amz-content-sha256", &hash)], b"date").unwrap_err();
        assert_eq!(rejection.code, "XAmzContentSHA256Mismatch");
        assert_eq!(rejection.details[0], ("ClientComputedContentSHA256", hash));
        // Content-Encoding doesn't make a body aws-chunked: only a STREAMING-…
        // x-amz-content-sha256 does, which the signature covers.
        let framed = b"4\r\nevil\r\n0\r\n\r\n";
        let pairs = [("x-amz-content-sha256", EMPTY_SHA256), ("content-encoding", "aws-chunked")];
        assert_eq!(code(read(&pairs, framed)), "XAmzContentSHA256Mismatch");
        let pairs = [("x-amz-content-sha256", "UNSIGNED-PAYLOAD"), ("content-encoding", "aws-chunked")];
        assert_eq!(read(&pairs, framed).unwrap(), framed);
    }

    /// Feeds `body`, limited to `max` bytes, a byte at a time.
    fn read_at_most(pairs: &[(&'static str, &str)], body: &[u8], max: u64) -> Result<Vec<u8>, Rejection> {
        let mut payload = Payload::new(&headers(pairs), "secret", true)?.at_most(max)?;
        let mut data = Vec::new();
        for byte in body {
            for piece in payload.decode(Bytes::copy_from_slice(&[*byte]))? {
                data.extend_from_slice(&piece);
            }
        }
        payload.finish()?;
        Ok(data)
    }

    #[test]
    fn requires_enough_data() {
        let unsigned = ("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        let read = |body: &[u8]| {
            let mut payload = Payload::new(&headers(&[unsigned]), "secret", true).unwrap().at_least(4);
            payload.decode(Bytes::copy_from_slice(body)).unwrap();
            payload.finish()
        };
        assert!(read(b"data").is_ok());
        assert_eq!(read(b"dat").unwrap_err().code, "EntityTooSmall");
    }

    #[test]
    fn limits_the_data() {
        let unsigned = ("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        assert_eq!(read_at_most(&[unsigned, ("content-length", "4")], b"data", 4).unwrap(), b"data");
        // Declared too large: refused before any of it is read.
        let refused = Payload::new(&headers(&[unsigned, ("content-length", "5")]), "secret", true)
            .unwrap()
            .at_most(4);
        assert_eq!(refused.err().unwrap().code, "EntityTooLarge");
        // Not declared (chunked transfer encoding, which S3 takes too): taken,
        // and refused once there's more.
        assert_eq!(read_at_most(&[unsigned], b"data", 4).unwrap(), b"data");
        assert_eq!(
            code(read_at_most(&[unsigned], b"datas", 4)),
            "EntityTooLarge"
        );
        // Streaming: by its declared data length, not its framed one.
        let pairs = [
            ("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER"),
            ("x-amz-trailer", "x-amz-checksum-crc32c"),
            ("x-amz-decoded-content-length", "9"),
            ("content-length", "1000"),
        ];
        let crc = checksum(Algorithm::Crc32c, b"some data");
        let body = unsigned_body(b"some data", 4, &format!("x-amz-checksum-crc32c:{crc}\r\n"));
        assert_eq!(read_at_most(&pairs, &body, 9).unwrap(), b"some data");
        assert_eq!(code(read_at_most(&pairs, &body, 8)), "EntityTooLarge");
    }

    #[test]
    fn checks_content_md5() {
        let md5 = STANDARD.encode(Md5::digest(b"data"));
        let pairs = [("x-amz-content-sha256", "UNSIGNED-PAYLOAD"), ("content-md5", md5.as_str())];
        assert_eq!(read(&pairs, b"data").unwrap(), b"data");
        assert_eq!(code(read(&pairs, b"date")), "BadDigest");
        let pairs = [("x-amz-content-sha256", "UNSIGNED-PAYLOAD"), ("content-md5", "nope")];
        assert_eq!(code(read(&pairs, b"data")), "InvalidDigest");
    }

    /// The base64 `algorithm` checksum of `data`.
    fn checksum(algorithm: Algorithm, data: &[u8]) -> String {
        let mut checksum = Checksum::new(algorithm);
        checksum.update(data);
        STANDARD.encode(checksum.finish())
    }

    #[test]
    fn checks_a_checksum_header() {
        // The algorithms' check values, over "123456789".
        assert_eq!(checksum(Algorithm::Crc32, b"123456789"), STANDARD.encode(0xcbf43926u32.to_be_bytes()));
        assert_eq!(checksum(Algorithm::Crc32c, b"123456789"), STANDARD.encode(0xe3069283u32.to_be_bytes()));
        assert_eq!(
            checksum(Algorithm::Crc64Nvme, b"123456789"),
            STANDARD.encode(0xae8b14860a799888u64.to_be_bytes())
        );
        for algorithm in Algorithm::ALL {
            let value = checksum(algorithm, b"data");
            let pairs = [("x-amz-content-sha256", "UNSIGNED-PAYLOAD"), (algorithm.header(), value.as_str())];
            assert_eq!(read(&pairs, b"data").unwrap(), b"data", "{algorithm:?}");
            let rejection = read(&pairs, b"date").unwrap_err();
            assert_eq!(rejection.code, "BadDigest", "{algorithm:?}");
            assert!(rejection.message.contains(algorithm.name()));
        }
        let crc = checksum(Algorithm::Crc32, b"data");
        let two = [
            ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
            ("x-amz-checksum-crc32", crc.as_str()),
            ("x-amz-checksum-crc32c", crc.as_str()),
        ];
        assert_eq!(code(read(&two, b"data")), "InvalidRequest");
        let bad = [("x-amz-content-sha256", "UNSIGNED-PAYLOAD"), ("x-amz-checksum-sha256", crc.as_str())];
        assert_eq!(code(read(&bad, b"data")), "InvalidRequest");
    }

    #[test]
    fn returns_the_checksum_it_checked() {
        let crc = checksum(Algorithm::Crc32, b"data");
        let pairs = [("x-amz-content-sha256", "UNSIGNED-PAYLOAD"), ("x-amz-checksum-crc32", crc.as_str())];
        let mut payload = Payload::new(&headers(&pairs), "secret", true).unwrap();
        payload.decode(Bytes::from_static(b"data")).unwrap();
        let (algorithm, raw) = payload.finish().unwrap().unwrap();
        assert_eq!((algorithm, STANDARD.encode(raw)), (Algorithm::Crc32, crc));
    }

    #[test]
    fn checks_the_sdks_algorithm() {
        let crc = checksum(Algorithm::Crc32, b"data");
        let sent = [("x-amz-content-sha256", "UNSIGNED-PAYLOAD"), ("x-amz-checksum-crc32", crc.as_str())];
        let with = |named: &'static str| [&sent[..], &[("x-amz-sdk-checksum-algorithm", named)]].concat();
        assert_eq!(read(&with("CRC32"), b"data").unwrap(), b"data");
        assert_eq!(read(&with("crc32"), b"data").unwrap(), b"data");
        assert_eq!(code(read(&with("CRC32C"), b"data")), "BadDigest");
        assert_eq!(code(read(&with("MD4"), b"data")), "InvalidRequest");
        // Named, but not sent.
        let unsent = [("x-amz-content-sha256", "UNSIGNED-PAYLOAD"), ("x-amz-sdk-checksum-algorithm", "CRC32")];
        assert_eq!(code(read(&unsent, b"data")), "InvalidRequest");
    }

    #[test]
    fn ignores_checksum_headers_that_arent_the_bodys() {
        let pairs = [("x-amz-content-sha256", "UNSIGNED-PAYLOAD"), ("x-amz-checksum-crc32", "AAAAAA==")];
        let mut payload = Payload::new(&headers(&pairs), "secret", false).unwrap();
        payload.decode(Bytes::from_static(b"data")).unwrap();
        assert_eq!(payload.finish(), Ok(None));
    }

    /// An unsigned streaming body of `data`, in chunks of `chunk` bytes, with
    /// `trailer` lines after its last.
    fn unsigned_body(data: &[u8], chunk: usize, trailer: &str) -> Vec<u8> {
        let mut body = Vec::new();
        for piece in data.chunks(chunk) {
            body.extend(format!("{:x}\r\n", piece.len()).bytes());
            body.extend_from_slice(piece);
            body.extend(b"\r\n");
        }
        body.extend(format!("0\r\n{trailer}\r\n").bytes());
        body
    }

    #[test]
    fn checks_an_unsigned_streaming_body() {
        let crc = checksum(Algorithm::Crc32c, b"some data");
        let pairs = [
            ("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER"),
            ("x-amz-trailer", "x-amz-checksum-crc32c"),
            ("x-amz-decoded-content-length", "9"),
        ];
        let good = unsigned_body(b"some data", 4, &format!("x-amz-checksum-crc32c:{crc}\r\n"));
        assert_eq!(read(&pairs, &good).unwrap(), b"some data");
        let wrong = unsigned_body(b"some data", 4, "x-amz-checksum-crc32c:AAAAAA==\r\n");
        assert_eq!(code(read(&pairs, &wrong)), "BadDigest");
        let missing = unsigned_body(b"some data", 4, "");
        assert_eq!(code(read(&pairs, &missing)), "MalformedTrailerError");
        // Cut short, in the data or in the trailer, or longer than declared.
        assert_eq!(code(read(&pairs, &good[..10])), "IncompleteBody");
        assert_eq!(code(read(&pairs, &good[..good.len() - 8])), "IncompleteBody");
        let longer = unsigned_body(b"some data!", 4, &format!("x-amz-checksum-crc32c:{crc}\r\n"));
        assert_eq!(code(read(&pairs, &longer)), "IncompleteBody");
        // The length must be declared, and the trailer's algorithm known.
        assert_eq!(code(read(&pairs[..2], &good)), "MissingContentLength");
        let unknown = [pairs[0], ("x-amz-trailer", "x-amz-checksum-md4"), pairs[2]];
        assert_eq!(code(read(&unknown, &good)), "InvalidRequest");
    }

    /// The headers of a signed streaming request, as far as decoding its body
    /// needs them (the chunk chain starts at the request's signature).
    fn signed_headers(content_sha256: &'static str, length: usize) -> Vec<(&'static str, String)> {
        vec![
            ("x-amz-content-sha256", content_sha256.to_owned()),
            ("x-amz-decoded-content-length", length.to_string()),
            ("x-amz-date", "20260613T120000Z".to_owned()),
            ("x-amz-trailer", "x-amz-checksum-crc32".to_owned()),
            (
                "authorization",
                "AWS4-HMAC-SHA256 Credential=akid/20260613/us-east-1/s3/aws4_request, \
                 SignedHeaders=host, Signature=5eed"
                    .to_owned(),
            ),
        ]
    }

    /// A signed streaming body of `data` in chunks of `sizes`, signed with the
    /// key of `h`'s request, ending with a signed CRC32 trailer if `trailer`.
    fn signed_body(h: &HeaderMap, data: &[u8], sizes: &[usize], trailer: bool) -> Vec<u8> {
        let mut signer = StreamingChunkVerifier::from_headers(h, "secret").unwrap();
        let mut body = Vec::new();
        let mut rest = data;
        for &size in sizes.iter().chain([&0]) {
            let (piece, tail) = rest.split_at(size);
            rest = tail;
            let signature = signer.sign_chunk(piece);
            body.extend(format!("{size:x};chunk-signature={signature}\r\n").bytes());
            body.extend_from_slice(piece);
            if size > 0 {
                body.extend(b"\r\n");
            }
        }
        if trailer {
            let canonical = format!("x-amz-checksum-crc32:{}\n", checksum(Algorithm::Crc32, data));
            let signature = signer.sign_trailer(&canonical);
            body.extend(canonical.replace('\n', "\r\n").bytes());
            body.extend(format!("x-amz-trailer-signature:{signature}\r\n").bytes());
        }
        body.extend(b"\r\n");
        body
    }

    fn read_signed(pairs: &[(&'static str, String)], body: &[u8]) -> Result<Vec<u8>, Rejection> {
        let pairs: Vec<(&'static str, &str)> = pairs.iter().map(|(n, v)| (*n, v.as_str())).collect();
        read(&pairs, body)
    }

    #[test]
    fn checks_a_signed_streaming_body() {
        let data = vec![7u8; 20_000];
        let pairs = signed_headers("STREAMING-AWS4-HMAC-SHA256-PAYLOAD", data.len());
        let h = headers(&pairs.iter().map(|(n, v)| (*n, v.as_str())).collect::<Vec<_>>());
        let body = signed_body(&h, &data, &[8192, 8192, 3616], false);
        assert_eq!(read_signed(&pairs, &body).unwrap(), data);
        // A changed byte breaks its chunk's signature.
        let mut tampered = body.clone();
        let at = tampered.len() - 100;
        tampered[at] ^= 1;
        assert_eq!(code(read_signed(&pairs, &tampered)), "SignatureDoesNotMatch");
        // Only the last chunk with data may be smaller than 8 KiB.
        let small = signed_body(&h, &data, &[100, 16384, 3516], false);
        assert_eq!(code(read_signed(&pairs, &small)), "InvalidChunkSizeError");
    }

    #[test]
    fn checks_a_signed_trailer() {
        let data = vec![9u8; 10_000];
        let pairs = signed_headers("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER", data.len());
        let h = headers(&pairs.iter().map(|(n, v)| (*n, v.as_str())).collect::<Vec<_>>());
        let body = signed_body(&h, &data, &[8192, 1808], true);
        assert_eq!(read_signed(&pairs, &body).unwrap(), data);
        // The trailer's value is covered by its signature.
        let crc = checksum(Algorithm::Crc32, &data);
        let at = body.windows(crc.len()).position(|w| w == crc.as_bytes()).unwrap();
        let mut forged = body.clone();
        forged[at] = if forged[at] == b'A' { b'B' } else { b'A' };
        assert_eq!(code(read_signed(&pairs, &forged)), "SignatureDoesNotMatch");
    }
}
