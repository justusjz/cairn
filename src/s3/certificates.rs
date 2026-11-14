//! Which hosts a TLS-terminating proxy in front of Cairn may get certificates
//! for, as they're asked for: Caddy's on-demand TLS asks before it gets one
//! for a host it hasn't a certificate for (`GET <ask URL>?domain=<host>`,
//! allowed by a 200), which the peer endpoint answers (`/tls/ask`).
//!
//! Exactly the hosts Cairn serves something at (see `hosting`): the S3
//! API's domain, a bucket's (virtual-hosted) if the bucket exists, and a
//! website's (at the website domain, or a custom domain) if its bucket has
//! a website configuration. Nothing else, so that no one can have the proxy
//! ask for certificates by pointing names of their own at it (or just by
//! naming them in TLS handshakes), which would use up the CA's rate limits
//! (and the CA might take it for abuse).

use crate::{App, db::Cached, s3::hosting::Host};

/// Whether the proxy may get a certificate for `host` (a host name, without
/// a port).
pub async fn allowed(app: &App, host: &str) -> anyhow::Result<bool> {
    let name = host.trim_end_matches('.').to_ascii_lowercase();
    // A host name: no port, no IP address (which CAs don't certify by ACME's
    // HTTP and TLS challenges, and Cairn takes as path-style).
    let label = |l: &str| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !name.split('.').all(label) || name.parse::<std::net::IpAddr>().is_ok() {
        return Ok(false);
    }
    let (domain, website_domain) = (app.domain.as_deref(), app.website_domain.as_deref());
    let (bucket, website) = match Host::of(domain, website_domain, &name) {
        Host::PathStyle => return Ok(domain == Some(name.as_str())),
        Host::Bucket(bucket) => (bucket, false),
        Host::Website(bucket) => (bucket, true),
    };
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached("SELECT website IS NOT NULL FROM buckets WHERE name = $1", &[&bucket])
        .await?;
    Ok(row.is_some_and(|row| !website || row.get::<_, bool>(0)))
}
