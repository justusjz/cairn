//! Decoder for AWS SigV4 *streaming* uploads (`Content-Encoding: aws-chunked`).
//!
//! When an S3 client uploads with a streaming signature, the request body isn't
//! the raw object — it's framed into chunks:
//!
//! ```text
//! <hex-size>;chunk-signature=<sig>\r\n
//! <chunk-data>\r\n
//! ...
//! 0;chunk-signature=<sig>\r\n
//! \r\n
//! ```
//!
//! (The `;chunk-signature=…` is absent for `STREAMING-UNSIGNED-PAYLOAD-TRAILER`,
//! and a trailer may follow the terminating zero-size chunk.) We don't verify
//! signatures, so decoding just means stripping the framing and concatenating
//! the chunk payloads. Size and ETag are then computed over the decoded bytes,
//! which is what the object actually is.

use std::io;

use hyper::{HeaderMap, body::Bytes, header};

/// True if the request body is `aws-chunked` framed and must be decoded before
/// storage. Signalled by a streaming `x-amz-content-sha256`
/// (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`, `…-TRAILER`, or the unsigned variant),
/// or by an explicit `Content-Encoding: aws-chunked`.
pub fn is_aws_chunked(headers: &HeaderMap) -> bool {
    let streaming_sha = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("STREAMING-"));
    let chunked_encoding = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|e| e.trim() == "aws-chunked"));
    streaming_sha || chunked_encoding
}

/// Cap on a single chunk-size line, so a malformed stream can't make us buffer
/// without bound. Real headers are well under 100 bytes (hex size + signature).
const MAX_HEADER_LINE: usize = 8192;
/// Cap on the captured trailer, same reasoning as the chunk-header cap.
const MAX_TRAILER: usize = 8192;

enum State {
    /// Accumulating the `<hex-size>[;…]\r\n` line into `header`.
    Header,
    /// Inside a chunk's payload; `n` data bytes remain before its trailing CRLF.
    Data(u64),
    /// Consuming the `\r\n` that follows a chunk's payload; `rem` bytes left.
    DataCrlf(u8),
    /// Saw the terminating zero-size chunk; everything after is the trailer
    /// section (`name:value\r\n` lines), accumulated into `trailer`.
    Trailer,
}

/// Incremental decoder: fed body chunks as they arrive (split at arbitrary byte
/// boundaries), it emits the decoded payload bytes and captures any trailer.
pub struct AwsChunkedDecoder {
    state: State,
    header: Vec<u8>,
    trailer: Vec<u8>,
}

impl AwsChunkedDecoder {
    pub fn new() -> Self {
        Self {
            state: State::Header,
            header: Vec::new(),
            trailer: Vec::new(),
        }
    }

    /// Feeds one body chunk through the decoder, returning the decoded payload
    /// segments it produced. Segments are zero-copy slices of `input`, so no
    /// payload bytes are duplicated. Errors on a malformed frame.
    pub fn decode(&mut self, input: Bytes) -> io::Result<Vec<Bytes>> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < input.len() {
            match self.state {
                State::Header => {
                    self.header.push(input[i]);
                    i += 1;
                    if self.header.ends_with(b"\r\n") {
                        let size = parse_chunk_size(&self.header)?;
                        self.header.clear();
                        self.state = if size == 0 {
                            State::Trailer
                        } else {
                            State::Data(size)
                        };
                    } else if self.header.len() > MAX_HEADER_LINE {
                        return Err(io::Error::other("aws-chunked: chunk header too long"));
                    }
                }
                State::Data(ref mut n) => {
                    let avail = (input.len() - i) as u64;
                    let take = (*n).min(avail) as usize;
                    if take > 0 {
                        out.push(input.slice(i..i + take));
                    }
                    i += take;
                    *n -= take as u64;
                    if *n == 0 {
                        self.state = State::DataCrlf(2);
                    }
                }
                State::DataCrlf(ref mut rem) => {
                    while *rem > 0 && i < input.len() {
                        // The two bytes after a chunk's payload must be exactly
                        // CRLF; anything else means the announced chunk size was
                        // wrong and the framing is misaligned, so fail rather than
                        // silently swallow payload bytes.
                        let expected = if *rem == 2 { b'\r' } else { b'\n' };
                        if input[i] != expected {
                            return Err(io::Error::other(
                                "aws-chunked: missing CRLF after chunk data",
                            ));
                        }
                        i += 1;
                        *rem -= 1;
                    }
                    if *rem == 0 {
                        self.state = State::Header;
                    }
                }
                State::Trailer => {
                    let rest = &input[i..];
                    if self.trailer.len() + rest.len() > MAX_TRAILER {
                        return Err(io::Error::other("aws-chunked: trailer too long"));
                    }
                    self.trailer.extend_from_slice(rest);
                    i = input.len();
                }
            }
        }
        Ok(out)
    }

    /// The value of trailer header `name` (case-insensitive), if the body carried
    /// one — e.g. `x-amz-checksum-crc32`. Only meaningful once the body is fully
    /// read (`is_complete`).
    pub fn trailer(&self, name: &str) -> Option<String> {
        let text = std::str::from_utf8(&self.trailer).ok()?;
        text.lines().find_map(|line| {
            let (k, v) = line.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case(name)
                .then(|| v.trim().to_owned())
        })
    }

    /// Whether the terminating zero-size chunk has been seen. A stream that ends
    /// without it is truncated, and storing it would silently corrupt the object.
    pub fn is_complete(&self) -> bool {
        matches!(self.state, State::Trailer)
    }
}

impl Default for AwsChunkedDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Parses the hex size from a `<hex>[;chunk-signature=…]\r\n` line.
fn parse_chunk_size(line: &[u8]) -> io::Result<u64> {
    let line = &line[..line.len() - 2]; // strip the trailing \r\n
    let hex = line.split(|&b| b == b';').next().unwrap_or(line);
    let hex = std::str::from_utf8(hex)
        .map_err(|_| io::Error::other("aws-chunked: non-utf8 chunk size"))?
        .trim();
    u64::from_str_radix(hex, 16).map_err(|_| io::Error::other("aws-chunked: invalid chunk size"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A signed data chunk: `<hex-size>;chunk-signature=…\r\n<data>\r\n`.
    fn signed_chunk(data: &[u8]) -> Vec<u8> {
        let mut v = format!("{:x};chunk-signature=0bad51g\r\n", data.len()).into_bytes();
        v.extend_from_slice(data);
        v.extend_from_slice(b"\r\n");
        v
    }

    /// The terminating zero-size chunk.
    fn terminator() -> Vec<u8> {
        b"0;chunk-signature=0bad51g\r\n\r\n".to_vec()
    }

    /// Feeds `input` to a fresh decoder in `step`-sized slices, returning the
    /// decoded payload and whether the stream completed.
    fn decode_in_steps(input: &[u8], step: usize) -> (Vec<u8>, bool) {
        let mut dec = AwsChunkedDecoder::new();
        let mut out = Vec::new();
        let mut i = 0;
        while i < input.len() {
            let end = (i + step).min(input.len());
            let segs = dec.decode(Bytes::copy_from_slice(&input[i..end])).unwrap();
            for s in segs {
                out.extend_from_slice(&s);
            }
            i = end;
        }
        (out, dec.is_complete())
    }

    #[test]
    fn single_chunk() {
        let mut body = signed_chunk(b"hello, world");
        body.extend(terminator());
        let (out, complete) = decode_in_steps(&body, body.len());
        assert_eq!(out, b"hello, world");
        assert!(complete);
    }

    #[test]
    fn multiple_chunks_concatenate() {
        let mut body = signed_chunk(b"abc");
        body.extend(signed_chunk(b"defgh"));
        body.extend(terminator());
        let (out, complete) = decode_in_steps(&body, body.len());
        assert_eq!(out, b"abcdefgh");
        assert!(complete);
    }

    #[test]
    fn survives_arbitrary_splits() {
        // The framing can be split at any byte boundary across HTTP frames;
        // feeding one byte at a time is the worst case and must still decode.
        let mut body = signed_chunk(b"the quick brown fox");
        body.extend(signed_chunk(&[0u8; 600])); // crosses many 1-byte feeds
        body.extend(terminator());
        let mut expected = b"the quick brown fox".to_vec();
        expected.extend_from_slice(&[0u8; 600]);
        for step in [1, 2, 3, 7, 64] {
            let (out, complete) = decode_in_steps(&body, step);
            assert_eq!(out, expected, "wrong output at step {step}");
            assert!(complete, "not complete at step {step}");
        }
    }

    #[test]
    fn unsigned_chunks_without_signature() {
        // STREAMING-UNSIGNED-PAYLOAD-TRAILER omits `;chunk-signature=…`.
        let body = b"5\r\nhello\r\n0\r\n\r\n";
        let (out, complete) = decode_in_steps(body, 1);
        assert_eq!(out, b"hello");
        assert!(complete);
    }

    #[test]
    fn trailer_after_terminator_is_ignored() {
        let mut body = signed_chunk(b"data");
        body.extend_from_slice(b"0\r\nx-amz-checksum-crc32:abcd1234\r\n\r\n");
        let (out, complete) = decode_in_steps(&body, 1);
        assert_eq!(out, b"data");
        assert!(complete);
    }

    #[test]
    fn captures_trailer() {
        let mut dec = AwsChunkedDecoder::new();
        let body = b"5\r\nhello\r\n0\r\nx-amz-checksum-crc32:abc123==\r\n\r\n";
        let out: Vec<u8> = dec
            .decode(Bytes::copy_from_slice(body))
            .unwrap()
            .iter()
            .flat_map(|b| b.to_vec())
            .collect();
        assert_eq!(out, b"hello");
        assert!(dec.is_complete());
        // case-insensitive name lookup; absent trailer is None
        assert_eq!(dec.trailer("X-Amz-Checksum-Crc32").as_deref(), Some("abc123=="));
        assert_eq!(dec.trailer("x-amz-checksum-sha256"), None);
    }

    #[test]
    fn truncated_body_is_not_complete() {
        // A chunk announced but cut off before its terminator: the caller must
        // see is_complete() == false and reject the upload.
        let body = signed_chunk(b"partial"); // no terminator
        let (out, complete) = decode_in_steps(&body, body.len());
        assert_eq!(out, b"partial");
        assert!(!complete);
    }

    #[test]
    fn invalid_chunk_size_errors() {
        let mut dec = AwsChunkedDecoder::new();
        assert!(dec.decode(Bytes::from_static(b"zz\r\n")).is_err());
    }

    #[test]
    fn missing_crlf_after_data_errors() {
        // The chunk claims 3 bytes ("abc") but follows them with "XY" instead of
        // CRLF — a misaligned frame that must be rejected, not silently skipped.
        let mut dec = AwsChunkedDecoder::new();
        assert!(dec.decode(Bytes::from_static(b"3\r\nabcXY")).is_err());
    }
}
