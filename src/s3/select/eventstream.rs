//! The response's framing: AWS's event stream
//! (`application/vnd.amazon.eventstream`), as SelectObjectContent's
//! documentation describes its messages.
//!
//! A message is its total length and its headers' (4 bytes each, big
//! endian), the CRC32 of those 8 bytes, its headers, its payload, and the
//! CRC32 of all that. A header is its name's length (1 byte), its name, its
//! value's type (7: a string), its value's length (2 bytes), and its value.

use hyper::body::Bytes;

/// A message with `headers` (all strings) and `payload`.
pub fn message(headers: &[(&str, &str)], payload: &[u8]) -> Bytes {
    let mut encoded = Vec::new();
    for (name, value) in headers {
        encoded.push(name.len() as u8);
        encoded.extend_from_slice(name.as_bytes());
        encoded.push(7);
        encoded.extend_from_slice(&(value.len() as u16).to_be_bytes());
        encoded.extend_from_slice(value.as_bytes());
    }
    let total = 12 + encoded.len() + payload.len() + 4;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(total as u32).to_be_bytes());
    out.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    let prelude = crc32fast::hash(&out);
    out.extend_from_slice(&prelude.to_be_bytes());
    out.extend_from_slice(&encoded);
    out.extend_from_slice(payload);
    let crc = crc32fast::hash(&out);
    out.extend_from_slice(&crc.to_be_bytes());
    out.into()
}

fn event(kind: &str, content_type: Option<&str>, payload: &[u8]) -> Bytes {
    let mut headers = vec![(":event-type", kind)];
    if let Some(content_type) = content_type {
        headers.push((":content-type", content_type));
    }
    headers.push((":message-type", "event"));
    message(&headers, payload)
}

/// Some of the selected records.
pub fn records(payload: &[u8]) -> Bytes {
    event("Records", Some("application/octet-stream"), payload)
}

/// How much was scanned, processed and returned.
#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    /// The object's bytes read (compressed, if it is).
    pub scanned: u64,
    /// Their bytes decompressed.
    pub processed: u64,
    /// The records' bytes returned.
    pub returned: u64,
}

impl Stats {
    fn xml(&self, element: &str) -> Vec<u8> {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><{element} xmlns=\"\">\
             <BytesScanned>{}</BytesScanned><BytesProcessed>{}</BytesProcessed>\
             <BytesReturned>{}</BytesReturned></{element}>",
            self.scanned, self.processed, self.returned
        )
        .into_bytes()
    }

    /// The Stats event, which ends a query that succeeded (before End).
    pub fn stats(&self) -> Bytes {
        event("Stats", Some("text/xml"), &self.xml("Stats"))
    }

    /// A Progress event, sent along the way if the request asks for them.
    pub fn progress(&self) -> Bytes {
        event("Progress", Some("text/xml"), &self.xml("Progress"))
    }
}

/// A Cont event: nothing, to keep the connection alive.
pub fn cont() -> Bytes {
    event("Cont", None, &[])
}

/// The End event.
pub fn end() -> Bytes {
    event("End", None, &[])
}

/// An error, which ends a query that failed after it started answering.
pub fn error(code: &str, message: &str) -> Bytes {
    self::message(
        &[
            (":error-code", code),
            (":error-message", message),
            (":message-type", "error"),
        ],
        &[],
    )
}

/// The headers and payload of the first message in `stream`, checking its
/// framing, and the rest of `stream`.
#[cfg(test)]
pub fn decode(stream: &[u8]) -> (Vec<(String, String)>, Vec<u8>, &[u8]) {
    let total = u32::from_be_bytes(stream[0..4].try_into().unwrap()) as usize;
    let (message, rest) = stream.split_at(total);
    let headers_len = u32::from_be_bytes(message[4..8].try_into().unwrap()) as usize;
    let prelude = u32::from_be_bytes(message[8..12].try_into().unwrap());
    assert_eq!(prelude, crc32fast::hash(&message[..8]));
    let crc = u32::from_be_bytes(message[total - 4..].try_into().unwrap());
    assert_eq!(crc, crc32fast::hash(&message[..total - 4]));
    let mut headers = Vec::new();
    let mut i = 12;
    while i < 12 + headers_len {
        let n = message[i] as usize;
        let name = String::from_utf8(message[i + 1..i + 1 + n].to_vec()).unwrap();
        i += 1 + n;
        assert_eq!(message[i], 7);
        let len = u16::from_be_bytes(message[i + 1..i + 3].try_into().unwrap()) as usize;
        let value = String::from_utf8(message[i + 3..i + 3 + len].to_vec()).unwrap();
        i += 3 + len;
        headers.push((name, value));
    }
    (headers, message[12 + headers_len..total - 4].to_vec(), rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_messages() {
        let (headers, payload, _) = decode(&records(b"a,b\n"));
        assert_eq!(payload, b"a,b\n");
        assert!(headers.contains(&(":event-type".into(), "Records".into())));
        assert!(headers.contains(&(":message-type".into(), "event".into())));
        let (headers, payload, _) = decode(&end());
        assert!(payload.is_empty());
        assert_eq!(headers.len(), 2);
        let (headers, _, _) = decode(&error("CastFailed", "no"));
        assert!(headers.contains(&(":error-code".into(), "CastFailed".into())));
    }

    /// A message AWS's documentation gives: an empty one, with no headers
    /// (its CRCs are well known).
    #[test]
    fn matches_the_reference_framing() {
        let empty = message(&[], &[]);
        assert_eq!(
            &empty[..],
            &[
                0, 0, 0, 0x10, 0, 0, 0, 0, 0x05, 0xc2, 0x48, 0xeb, 0x7d, 0x98, 0xc8, 0xff
            ]
        );
    }
}
