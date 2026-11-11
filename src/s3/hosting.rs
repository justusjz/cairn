//! Virtual-hosted-style requests: `bucket.<domain>/key` rather than
//! path-style `/bucket/key`. With `--domain` set, a request whose `Host` is a
//! subdomain of it names its bucket there; any other (to the domain itself,
//! or an IP address) is path-style, as without it. As in S3, the bucket is all
//! of the host before `.<domain>`, dots included (`my.bucket.<domain>`), not
//! just its first label.
//!
//! Both are routed alike: a virtual-hosted request is turned into the path a
//! path-style one would have (see `Route`). Only its signature is checked
//! against the path it came with, which is the one its client signed.

use hyper::{HeaderMap, header};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

/// Characters of a host's bucket escaped in its path: all but those a bucket
/// name may have. A `Host` can't hold the others, but a `/` or `%` there must
/// not change how the path splits or decodes.
const BUCKET_ESCAPES: &AsciiSet = &NON_ALPHANUMERIC.remove(b'.').remove(b'-');

/// Where a request goes: its bucket and key, as a path-style request's path
/// names them.
#[derive(Debug, PartialEq)]
pub struct Route {
    /// `/bucket/key`, percent-encoded as a request's path is.
    pub path: String,
    /// Whether the bucket was in the request's host, not its path.
    pub virtual_host: bool,
}

impl Route {
    /// The route of a request to `path` with `headers`, under `domain` (see
    /// `parse_domain`), if there's one.
    pub fn of(domain: Option<&str>, headers: &HeaderMap, path: &str) -> Route {
        let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
        match domain.zip(host).and_then(|(domain, host)| bucket_of(domain, host)) {
            Some(bucket) => Route {
                path: format!(
                    "/{}/{}",
                    utf8_percent_encode(&bucket, BUCKET_ESCAPES),
                    path.strip_prefix('/').unwrap_or(path)
                ),
                virtual_host: true,
            },
            None => Route { path: path.to_owned(), virtual_host: false },
        }
    }
}

/// The bucket `host` (a `Host` header, maybe with a port) names, if it's a
/// subdomain of `domain`. Host names are case-insensitive, and may end with
/// the root's `.`.
fn bucket_of(domain: &str, host: &str) -> Option<String> {
    // An IPv6 address is never a subdomain.
    if host.starts_with('[') {
        return None;
    }
    let name = host.rsplit_once(':').map_or(host, |(name, _)| name);
    let name = name.to_ascii_lowercase();
    let bucket = name.trim_end_matches('.').strip_suffix(domain)?.strip_suffix('.')?;
    (!bucket.is_empty()).then(|| bucket.to_owned())
}

/// Parses `--domain`: a host name, compared without regard to case or a
/// trailing `.`.
pub fn parse_domain(domain: &str) -> Result<String, String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let label = |l: &str| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    match domain.split('.').all(label) {
        true => Ok(domain),
        false => Err(format!("{domain:?} isn't a domain name (e.g. s3.example.com)")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(domain: Option<&str>, host: &str, path: &str) -> (String, bool) {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, host.parse().unwrap());
        let route = Route::of(domain, &headers, path);
        (route.path, route.virtual_host)
    }

    #[test]
    fn virtual_hosted() {
        let d = Some("s3.example.com");
        let vhost = |path: &str| (path.to_owned(), true);
        assert_eq!(route(d, "b.s3.example.com", "/k"), vhost("/b/k"));
        assert_eq!(route(d, "b.s3.example.com:9000", "/a/k%20x"), vhost("/b/a/k%20x"));
        assert_eq!(route(d, "B.S3.Example.COM.", "/k"), vhost("/b/k"));
        // The bucket itself, and keys starting with a `/`.
        assert_eq!(route(d, "b.s3.example.com", "/"), vhost("/b/"));
        assert_eq!(route(d, "b.s3.example.com", "//k"), vhost("/b//k"));
        // Dots in a bucket's name.
        assert_eq!(route(d, "my.bucket.s3.example.com", "/k"), vhost("/my.bucket/k"));
        // Nothing a host holds changes where the bucket ends.
        assert_eq!(route(d, "a%2Fb.s3.example.com", "/k"), vhost("/a%252fb/k"));
    }

    #[test]
    fn path_style() {
        let d = Some("s3.example.com");
        let path = |path: &str| (path.to_owned(), false);
        for host in [
            "s3.example.com",
            "s3.example.com:9000",
            ".s3.example.com",
            "bs3.example.com",
            "b.s3.example.org",
            "127.0.0.1:9000",
            "[::1]:9000",
            "localhost",
        ] {
            assert_eq!(route(d, host, "/b/k"), path("/b/k"), "{host}");
        }
        // Without a domain, every request is.
        assert_eq!(route(None, "b.s3.example.com", "/b/k"), path("/b/k"));
        // So is one without a host.
        assert_eq!(Route::of(d, &HeaderMap::new(), "/b/k"), Route { path: "/b/k".to_owned(), virtual_host: false });
    }

    #[test]
    fn domains() {
        assert_eq!(parse_domain("S3.Example.com.").unwrap(), "s3.example.com");
        assert_eq!(parse_domain("localhost").unwrap(), "localhost");
        for bad in ["", ".", "s3..example.com", ".s3.example.com", "s3.example.com:9000", "http://s3.example.com", "*.example.com"] {
            assert!(parse_domain(bad).is_err(), "{bad}");
        }
    }
}
