//! SSE-C: objects encrypted with a key their client supplies with every
//! request that writes or reads them, in three headers: the algorithm (S3's
//! label `AES256`, whatever the server uses; Cairn's format is in
//! `encryption`), the key (base64 of 256 bits), and its MD5 (base64).
//!
//! The key is never stored or logged. It doesn't encrypt the data itself: an
//! object (and an upload) has a random object key, as an SSE-KMS one has (see
//! `sse`), which it keeps sealed under the client's key, bound to its name. A
//! wrong key fails to open it, so it's told from the right one before
//! anything is read; and two objects under one key don't show that they are.
//! A copy shares its source's parts by sealing the same object key under its
//! own key, which may be another: so changing an object's key (a copy onto
//! itself) is a matter of its catalog row, as in MinIO.
//!
//! The key travels in a header, so S3 only accepts it over TLS. Cairn sits
//! behind a TLS-terminating proxy, so it goes by `X-Forwarded-Proto` (or
//! `Forwarded`): a request that doesn't say it came over HTTPS is refused,
//! which catches a client that talks to Cairn over plain HTTP by mistake.
//! Behind an encrypted network instead (Nebula, say), `--allow-sse-c-over-http`
//! lets it through.

use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::Full;
use hyper::{
    HeaderMap, Response, StatusCode,
    body::Bytes,
    header::{FORWARDED, HeaderName},
    http::response::Builder,
};
use md5::{Digest, Md5};
use zeroize::Zeroizing;

use crate::{encryption::Key, s3::util::format_s3_error};

/// The algorithm a request must name: S3's only one.
pub const ALGORITHM: &str = "AES256";

/// The headers naming the key of the object a request is about.
pub const HEADERS: Names = Names {
    algorithm: "x-amz-server-side-encryption-customer-algorithm",
    key: "x-amz-server-side-encryption-customer-key",
    md5: "x-amz-server-side-encryption-customer-key-md5",
};

/// The headers naming the key of a copy's source.
pub const COPY_SOURCE_HEADERS: Names = Names {
    algorithm: "x-amz-copy-source-server-side-encryption-customer-algorithm",
    key: "x-amz-copy-source-server-side-encryption-customer-key",
    md5: "x-amz-copy-source-server-side-encryption-customer-key-md5",
};

pub struct Names {
    algorithm: &'static str,
    key: &'static str,
    md5: &'static str,
}

/// A client's key, as a request supplied it.
pub struct CustomerKey {
    key: Zeroizing<Key>,
    /// Its MD5, base64, as the request gave it (and responses echo it).
    md5: String,
}

impl CustomerKey {
    pub fn key(&self) -> &Key {
        &self.key
    }

    /// Adds the headers S3 answers an SSE-C request with: the algorithm, and
    /// the key's MD5.
    pub fn echo(&self, builder: Builder) -> Builder {
        builder
            .header(HEADERS.algorithm, ALGORITHM)
            .header(HEADERS.md5, self.md5.as_str())
    }
}

fn invalid(code: &str, message: &str) -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::BAD_REQUEST, code, message)
}

/// The key the request names in the headers `names`, if it names one, or why
/// it's refused. `secure` is whether it came over a secure connection.
pub fn requested(
    headers: &HeaderMap,
    names: &Names,
    secure: bool,
) -> Result<Option<CustomerKey>, Response<Full<Bytes>>> {
    let get = |name| headers.get(name).map(|v| v.to_str().unwrap_or("").trim());
    let (algorithm, key, md5) = (get(names.algorithm), get(names.key), get(names.md5));
    if algorithm.is_none() && key.is_none() && md5.is_none() {
        return Ok(None);
    }
    let Some(algorithm) = algorithm else {
        return Err(invalid(
            "InvalidArgument",
            "Requests specifying Server Side Encryption with Customer provided keys must provide a valid encryption algorithm.",
        ));
    };
    if algorithm != ALGORITHM {
        return Err(invalid(
            "InvalidEncryptionAlgorithmError",
            "The encryption request you specified is not valid. The valid value is AES256.",
        ));
    }
    let Some(key) = key else {
        return Err(invalid(
            "InvalidArgument",
            "Requests specifying Server Side Encryption with Customer provided keys must provide an appropriate secret key.",
        ));
    };
    let Some(md5) = md5 else {
        return Err(invalid(
            "InvalidArgument",
            "Requests specifying Server Side Encryption with Customer provided keys must provide the client calculated MD5 of the secret key.",
        ));
    };
    let decoded = Zeroizing::new(STANDARD.decode(key).unwrap_or_default());
    let Ok(key) = <Key>::try_from(decoded.as_slice()) else {
        return Err(invalid(
            "InvalidArgument",
            "The secret key was invalid for the specified algorithm.",
        ));
    };
    let key = Zeroizing::new(key);
    if STANDARD.decode(md5).ok().as_deref() != Some(Md5::digest(key.as_slice()).as_slice()) {
        return Err(invalid(
            "InvalidArgument",
            "The calculated MD5 hash of the key did not match the hash that was provided.",
        ));
    }
    if !secure {
        return Err(invalid(
            "InvalidRequest",
            "Requests specifying Server Side Encryption with Customer provided keys must be made over a secure connection.",
        ));
    }
    Ok(Some(CustomerKey {
        key,
        md5: md5.to_owned(),
    }))
}

/// Whether the request came over HTTPS, as the proxy in front of Cairn tells
/// (its first hop's, if there were several), or `allow_http` lets any through.
pub fn secure(headers: &HeaderMap, allow_http: bool) -> bool {
    if allow_http {
        return true;
    }
    let first = |name| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(str::trim)
    };
    if let Some(proto) = first(HeaderName::from_static("x-forwarded-proto")) {
        return proto.eq_ignore_ascii_case("https");
    }
    first(FORWARDED).is_some_and(|hop| {
        hop.split(';').any(|pair| {
            pair.trim().split_once('=').is_some_and(|(k, v)| {
                k.trim().eq_ignore_ascii_case("proto")
                    && v.trim().trim_matches('"').eq_ignore_ascii_case("https")
            })
        })
    })
}

/// Whether a stored object (SSE-C or not: `customer`) may be read with the
/// key a request gave, if it gave one (`opens`: whether the object's key
/// opens under it), or the error to refuse the request with.
pub fn check_read(customer: bool, opens: Option<bool>) -> Result<(), Response<Full<Bytes>>> {
    match (customer, opens) {
        (false, None) => Ok(()),
        (true, None) => Err(invalid(
            "InvalidRequest",
            "The object was stored using a form of Server Side Encryption. The correct parameters must be provided to retrieve the object.",
        )),
        (false, Some(_)) => Err(invalid(
            "InvalidRequest",
            "The encryption parameters are not applicable to this object.",
        )),
        (true, Some(true)) => Ok(()),
        // S3 answers a wrong key with 400 too.
        (true, Some(false)) => Err(invalid(
            "InvalidRequest",
            "The provided encryption key doesn't match the one the object was stored with.",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_B64: &str = "pO3upElrwuEXSoFwCfnZPdSsmt/xWeFa0N9KgDijwVs=";
    const MD5_B64: &str = "DWygnHRtgiJ77HCm+1rvHw==";

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        map
    }

    fn full(algorithm: &str, key: &str, md5: &str) -> HeaderMap {
        headers(&[
            (HEADERS.algorithm, algorithm),
            (HEADERS.key, key),
            (HEADERS.md5, md5),
        ])
    }

    fn refused(map: &HeaderMap, secure: bool) -> Option<String> {
        requested(map, &HEADERS, secure)
            .err()
            .map(|r| format!("{}", r.status().as_u16()))
    }

    #[test]
    fn parses_a_key_and_checks_it() {
        let key = requested(&full("AES256", KEY_B64, MD5_B64), &HEADERS, true)
            .unwrap()
            .unwrap();
        assert_eq!(STANDARD.encode(key.key()), KEY_B64);
        assert!(check_read(true, Some(true)).is_ok());
        assert!(check_read(true, Some(false)).is_err());
        assert!(check_read(true, None).is_err());
        assert!(check_read(false, Some(true)).is_err());
        assert!(check_read(false, None).is_ok());
    }

    #[test]
    fn refuses_incomplete_or_wrong_headers() {
        assert!(
            requested(&HeaderMap::new(), &HEADERS, false)
                .unwrap()
                .is_none()
        );
        let short = STANDARD.encode([1u8; 16]);
        let short_md5 = STANDARD.encode(Md5::digest([1u8; 16]));
        for map in [
            headers(&[(HEADERS.key, KEY_B64), (HEADERS.md5, MD5_B64)]),
            headers(&[(HEADERS.algorithm, "AES256"), (HEADERS.key, KEY_B64)]),
            headers(&[(HEADERS.algorithm, "AES256")]),
            full("aws:kms", KEY_B64, MD5_B64),
            full("AES256", KEY_B64, "AAAAAAAAAAAAAAAAAAAAAA=="),
            full("AES256", &short, &short_md5),
            full("AES256", "not base64!", MD5_B64),
        ] {
            assert_eq!(refused(&map, true).as_deref(), Some("400"), "{map:?}");
        }
        // Over plain HTTP, a right key is refused too.
        assert_eq!(
            refused(&full("AES256", KEY_B64, MD5_B64), false).as_deref(),
            Some("400")
        );
    }

    #[test]
    fn knows_a_secure_request() {
        assert!(!secure(&HeaderMap::new(), false));
        assert!(secure(&HeaderMap::new(), true));
        assert!(secure(&headers(&[("x-forwarded-proto", "https")]), false));
        assert!(secure(
            &headers(&[("x-forwarded-proto", "HTTPS, http")]),
            false
        ));
        assert!(!secure(&headers(&[("x-forwarded-proto", "http")]), false));
        assert!(secure(
            &headers(&[("forwarded", "for=1.2.3.4;proto=https;host=x")]),
            false
        ));
        assert!(!secure(
            &headers(&[("forwarded", "proto=http, proto=https")]),
            false
        ));
    }
}
