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
//!
//! A bucket's website (see `s3::website`) is reached at hosts of its own, as
//! S3's website endpoints are: with `--website-domain` set, a request to a
//! subdomain of it is one to its bucket's website. And with `--domain` set,
//! so that Cairn knows the S3 API's own hosts, a request to any other host
//! name (not the domain, a subdomain of it, an IP address or `localhost`)
//! is one to the website of the bucket named all of the host, as S3's
//! website endpoints take a host that isn't theirs: a custom domain, whose
//! bucket has its name (`www.example.com`), and whose DNS points at Cairn.

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
    /// Whether it's a request to the bucket's website (see `s3::website`).
    pub website: bool,
}

impl Route {
    /// The route of a request to `path` with `headers`, under `domain` and
    /// `website_domain` (see `parse_domain`), if there are any.
    pub fn of(domain: Option<&str>, website_domain: Option<&str>, headers: &HeaderMap, path: &str) -> Route {
        let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
        // The websites' first: their domain may be a subdomain of the API's.
        if let Some(bucket) = website_domain.zip(host).and_then(|(domain, host)| bucket_of(domain, host)) {
            return Route { path: in_bucket(&bucket, path), virtual_host: true, website: true };
        }
        let Some((domain, host)) = domain.zip(host) else {
            return Route { path: path.to_owned(), virtual_host: false, website: false };
        };
        if let Some(bucket) = bucket_of(domain, host) {
            return Route { path: in_bucket(&bucket, path), virtual_host: true, website: false };
        }
        match custom_domain(domain, host) {
            Some(bucket) => Route { path: in_bucket(&bucket, path), virtual_host: true, website: true },
            None => Route { path: path.to_owned(), virtual_host: false, website: false },
        }
    }
}

/// The bucket whose website `host` names as a custom domain, if it's not
/// one of the S3 API's under `domain`: the domain itself, an IP address
/// (which no bucket's name may look like, as in S3) or `localhost`.
fn custom_domain(domain: &str, host: &str) -> Option<String> {
    if host.starts_with('[') {
        return None;
    }
    let name = host.rsplit_once(':').map_or(host, |(name, _)| name);
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let api = name.is_empty() || name == domain || name == "localhost" || name.parse::<std::net::IpAddr>().is_ok();
    (!api).then_some(name)
}

/// The path-style path of `path` (a request's) in `bucket`.
fn in_bucket(bucket: &str, path: &str) -> String {
    format!("/{}/{}", utf8_percent_encode(bucket, BUCKET_ESCAPES), path.strip_prefix('/').unwrap_or(path))
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
        let route = Route::of(domain, None, &headers, path);
        assert!(!route.website, "{host}");
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
        // The domain itself, IP addresses and localhost are the API's.
        for host in ["s3.example.com", "s3.example.com:9000", "S3.Example.com.", "127.0.0.1:9000", "[::1]:9000", "localhost"] {
            assert_eq!(route(d, host, "/b/k"), path("/b/k"), "{host}");
        }
        // Without a domain, every request is.
        for host in ["b.s3.example.com", "www.example.com", "cairn.internal:9000"] {
            assert_eq!(route(None, host, "/b/k"), path("/b/k"), "{host}");
        }
        // So is one without a host.
        let none = Route { path: "/b/k".to_owned(), virtual_host: false, website: false };
        assert_eq!(Route::of(d, Some("s3-website.example.com"), &HeaderMap::new(), "/b/k"), none);
    }

    fn headers(host: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, host.parse().unwrap());
        headers
    }

    #[test]
    fn websites() {
        let (d, w) = (Some("s3.example.com"), Some("s3-website.example.com"));
        let website = |path: &str| Route { path: path.to_owned(), virtual_host: true, website: true };
        assert_eq!(Route::of(d, w, &headers("b.s3-website.example.com"), "/a/k"), website("/b/a/k"));
        assert_eq!(Route::of(d, w, &headers("My.Site.S3-Website.Example.com:80"), "/"), website("/my.site/"));
        // Without the API's domain too.
        assert_eq!(Route::of(None, w, &headers("b.s3-website.example.com"), "/k"), website("/b/k"));
        // A website domain under the API's is the websites'.
        let under = Some("web.s3.example.com");
        assert_eq!(Route::of(d, under, &headers("b.web.s3.example.com"), "/k"), website("/b/k"));
        assert!(!Route::of(d, under, &headers("b.s3.example.com"), "/k").website);
        assert!(!Route::of(d, under, &headers("web.s3.example.com"), "/b/k").website);

        // Any other host, once Cairn knows the API's: a custom domain, all
        // of which is its bucket's name.
        assert_eq!(Route::of(d, w, &headers("WWW.Example.com.:8080"), "/a"), website("/www.example.com/a"));
        assert_eq!(Route::of(d, None, &headers("example.org"), "/"), website("/example.org/"));
        assert_eq!(Route::of(d, w, &headers("cairn.internal:9000"), "/b/k"), website("/cairn.internal/b/k"));
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
