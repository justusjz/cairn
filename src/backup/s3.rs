//! A small S3 client: the calls a backup makes of its target, signed with
//! SigV4. Objects are named relative to the target's prefix.
//!
//! Every call is retried a few times, with backoff, on what may pass (the
//! network, 5xx, 429, `SlowDown`); a 4xx is final.

use std::time::Duration;

use base64::Engine;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, StatusCode};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use md5::{Digest, Md5};

use crate::auth::{day_of, derive_signing_key, hmac_sha256, sha256_hex};

type Https = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

/// How often a call is attempted, at most.
const ATTEMPTS: u32 = 5;
/// How long a call may take before it's given up (and retried).
const TIMEOUT: Duration = Duration::from_secs(300);

/// Where a backup is kept: a bucket of an S3 service, and a prefix in it.
#[derive(Clone, PartialEq, Eq)]
pub struct Location {
    /// The service's URL: `https://host[:port]` (or `http://`).
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    /// Empty, or ending in `/`.
    pub prefix: String,
    /// Whether the bucket is named in the path (`host/bucket/key`), rather
    /// than the host (`bucket.host/key`).
    pub path_style: bool,
    pub access_key_id: String,
    pub secret_access_key: String,
}

impl std::fmt::Debug for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Location")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("access_key_id", &self.access_key_id)
            .finish_non_exhaustive()
    }
}

impl Location {
    /// Checks the location, and puts its prefix into its form: empty, or
    /// ending in a single `/`.
    pub fn normalized(mut self) -> anyhow::Result<Location> {
        let (scheme, rest) = self
            .endpoint
            .split_once("://")
            .ok_or_else(|| anyhow::anyhow!("the endpoint {:?} isn't a URL (https://host[:port])", self.endpoint))?;
        anyhow::ensure!(
            scheme == "https" || scheme == "http",
            "the endpoint {:?} must be https:// (or http://)",
            self.endpoint
        );
        let host = rest.trim_end_matches('/');
        anyhow::ensure!(
            !host.is_empty() && !host.contains(['/', '?', '#', '@']),
            "the endpoint {:?} must be just a scheme and a host (and port)",
            self.endpoint
        );
        self.endpoint = format!("{scheme}://{host}");
        anyhow::ensure!(!self.bucket.is_empty() && !self.bucket.contains('/'), "a bucket name is needed");
        anyhow::ensure!(!self.region.is_empty(), "a region is needed");
        let prefix = self.prefix.trim_matches('/');
        self.prefix = if prefix.is_empty() { String::new() } else { format!("{prefix}/") };
        Ok(self)
    }

    /// Where it is, for people: `bucket/prefix at endpoint`.
    pub fn describe(&self) -> String {
        format!("s3://{}/{} at {}", self.bucket, self.prefix, self.endpoint)
    }
}

/// An S3 error answer, or another status the call didn't expect.
#[derive(Debug)]
pub struct Failed {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the target answered {}", self.status)?;
        if !self.code.is_empty() {
            write!(f, " {}", self.code)?;
        }
        if !self.message.is_empty() {
            write!(f, ": {}", self.message)?;
        }
        Ok(())
    }
}

impl std::error::Error for Failed {}

/// A client of a backup's location.
#[derive(Clone)]
pub struct Target {
    pub location: Location,
    client: Https,
}

/// An answer: its status, headers and body.
struct Answer {
    status: StatusCode,
    headers: hyper::HeaderMap,
    body: Bytes,
}

impl Target {
    pub fn new(location: Location) -> anyhow::Result<Target> {
        let location = location.normalized()?;
        let tls = rustls::ClientConfig::builder_with_provider(crate::oidc::provider())
            .with_safe_default_protocol_versions()
            .expect("ring has TLS 1.2 and 1.3")
            .with_root_certificates(crate::oidc::public_roots())
            .with_no_client_auth();
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .build();
        Ok(Target {
            location,
            client: Client::builder(TokioExecutor::new()).build(connector),
        })
    }

    /// Stores `body` as `name`.
    pub async fn put(&self, name: &str, body: Bytes) -> anyhow::Result<()> {
        self.call(Method::PUT, Some(name), &[], &[], body).await?;
        Ok(())
    }

    /// Starts a multipart upload of `name`; its upload ID.
    pub async fn create_upload(&self, name: &str) -> anyhow::Result<String> {
        let answer = self.call(Method::POST, Some(name), &[("uploads", "")], &[], Bytes::new()).await?;
        let doc = String::from_utf8_lossy(&answer.body).into_owned();
        xml_text(&doc, "UploadId").ok_or_else(|| anyhow::anyhow!("the target started an upload without an UploadId"))
    }

    /// Uploads part `number` (from 1) of an upload; its ETag.
    pub async fn upload_part(&self, name: &str, upload_id: &str, number: u32, body: Bytes) -> anyhow::Result<String> {
        let number = number.to_string();
        let answer = self
            .call(Method::PUT, Some(name), &[("partNumber", &number), ("uploadId", upload_id)], &[], body)
            .await?;
        answer
            .headers
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("the target took a part without an ETag"))
    }

    /// Completes an upload of the parts with `etags`, in order.
    pub async fn complete_upload(&self, name: &str, upload_id: &str, etags: &[String]) -> anyhow::Result<()> {
        let mut doc = String::from("<CompleteMultipartUpload>");
        for (i, etag) in etags.iter().enumerate() {
            doc.push_str(&format!("<Part><PartNumber>{}</PartNumber><ETag>{}</ETag></Part>", i + 1, xml_escape(etag)));
        }
        doc.push_str("</CompleteMultipartUpload>");
        let answer = self
            .call(Method::POST, Some(name), &[("uploadId", upload_id)], &[], Bytes::from(doc))
            .await?;
        // S3 may answer 200 with an error document, after it started.
        let body = String::from_utf8_lossy(&answer.body);
        if let Some(code) = xml_text(&body, "Code") {
            anyhow::bail!(Failed {
                status: answer.status,
                code,
                message: xml_text(&body, "Message").unwrap_or_default(),
            });
        }
        Ok(())
    }

    /// Gives an upload up (best effort).
    pub async fn abort_upload(&self, name: &str, upload_id: &str) {
        if let Err(e) = self.call(Method::DELETE, Some(name), &[("uploadId", upload_id)], &[], Bytes::new()).await {
            eprintln!("backup: aborting the upload of {name} failed: {e:#}");
        }
    }

    /// Bytes [`start`, `end`) of `name`.
    pub async fn get_range(&self, name: &str, start: u64, end: u64) -> anyhow::Result<Bytes> {
        anyhow::ensure!(start < end, "an empty range of {name}");
        let range = format!("bytes={start}-{}", end - 1);
        let answer = self.call(Method::GET, Some(name), &[], &[("range", &range)], Bytes::new()).await?;
        let want = (end - start) as usize;
        match answer.status {
            StatusCode::PARTIAL_CONTENT if answer.body.len() == want => Ok(answer.body),
            // A whole object, for a range that covers it.
            StatusCode::OK if start == 0 && answer.body.len() == want => Ok(answer.body),
            status => anyhow::bail!(
                "reading bytes {start}-{end} of {name}: the target answered {status} with {} bytes",
                answer.body.len()
            ),
        }
    }

    /// The names and sizes of the objects whose names start with `prefix`
    /// (relative to the location's), in order.
    pub async fn list(&self, prefix: &str) -> anyhow::Result<Vec<(String, u64)>> {
        let full = format!("{}{prefix}", self.location.prefix);
        let mut found = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut query = vec![("list-type", "2"), ("prefix", full.as_str())];
            if let Some(token) = &token {
                query.push(("continuation-token", token));
            }
            let answer = self.call(Method::GET, None, &query, &[], Bytes::new()).await?;
            let body = String::from_utf8_lossy(&answer.body).into_owned();
            let doc = roxmltree::Document::parse(&body)?;
            for contents in doc.descendants().filter(|n| n.has_tag_name("Contents")) {
                let child = |tag: &str| {
                    contents
                        .children()
                        .find(|n| n.has_tag_name(tag))
                        .and_then(|n| n.text())
                        .map(str::to_owned)
                };
                let (Some(key), Some(size)) = (child("Key"), child("Size")) else { continue };
                if let Some(name) = key.strip_prefix(&self.location.prefix) {
                    found.push((name.to_owned(), size.parse()?));
                }
            }
            let truncated = xml_text(&body, "IsTruncated").is_some_and(|t| t == "true");
            token = xml_text(&body, "NextContinuationToken");
            if !truncated || token.is_none() {
                break;
            }
        }
        found.sort();
        Ok(found)
    }

    /// Deletes the objects `names` (missing ones are no error), up to a
    /// thousand a call.
    pub async fn delete(&self, names: &[String]) -> anyhow::Result<()> {
        for chunk in names.chunks(1000) {
            let mut doc = String::from("<Delete><Quiet>true</Quiet>");
            for name in chunk {
                doc.push_str(&format!("<Object><Key>{}</Key></Object>", xml_escape(&format!("{}{name}", self.location.prefix))));
            }
            doc.push_str("</Delete>");
            let md5 = base64::engine::general_purpose::STANDARD.encode(Md5::digest(doc.as_bytes()));
            let answer = self
                .call(Method::POST, None, &[("delete", "")], &[("content-md5", &md5)], Bytes::from(doc))
                .await?;
            let body = String::from_utf8_lossy(&answer.body);
            let doc = roxmltree::Document::parse(&body)?;
            if let Some(error) = doc.descendants().find(|n| n.has_tag_name("Error")) {
                let child = |tag: &str| {
                    error.children().find(|n| n.has_tag_name(tag)).and_then(|n| n.text()).unwrap_or_default().to_owned()
                };
                anyhow::bail!("deleting {} failed: {} {}", child("Key"), child("Code"), child("Message"));
            }
        }
        Ok(())
    }

    /// Checks that the location can be listed (its bucket exists, the
    /// credentials work).
    pub async fn check(&self) -> anyhow::Result<()> {
        let full = self.location.prefix.clone();
        self.call(Method::GET, None, &[("list-type", "2"), ("prefix", &full), ("max-keys", "1")], &[], Bytes::new())
            .await?;
        Ok(())
    }

    /// Sends a call, retrying what may pass; fails on an answer other than
    /// 2xx.
    async fn call(
        &self,
        method: Method,
        name: Option<&str>,
        query: &[(&str, &str)],
        headers: &[(&str, &str)],
        body: Bytes,
    ) -> anyhow::Result<Answer> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let result = tokio::time::timeout(TIMEOUT, self.send(&method, name, query, headers, body.clone())).await;
            let error = match result {
                Ok(Ok(answer)) if answer.status.is_success() => return Ok(answer),
                Ok(Ok(answer)) => {
                    let text = String::from_utf8_lossy(&answer.body);
                    let failed = Failed {
                        status: answer.status,
                        code: xml_text(&text, "Code").unwrap_or_default(),
                        message: xml_text(&text, "Message").unwrap_or_default(),
                    };
                    let passing = answer.status.is_server_error()
                        || answer.status == StatusCode::TOO_MANY_REQUESTS
                        || failed.code == "SlowDown"
                        || failed.code == "RequestTimeout";
                    if !passing {
                        return Err(failed.into());
                    }
                    anyhow::Error::from(failed)
                }
                Ok(Err(e)) => e,
                Err(_) => anyhow::anyhow!("no answer in {TIMEOUT:?}"),
            };
            if attempt >= ATTEMPTS {
                let what = name.unwrap_or("the bucket");
                return Err(error.context(format!("{method} {what} on {}", self.location.endpoint)));
            }
            tokio::time::sleep(Duration::from_millis(200 << attempt)).await;
        }
    }

    async fn send(
        &self,
        method: &Method,
        name: Option<&str>,
        query: &[(&str, &str)],
        headers: &[(&str, &str)],
        body: Bytes,
    ) -> anyhow::Result<Answer> {
        let location = &self.location;
        let (scheme, authority) = location.endpoint.split_once("://").expect("a normalized endpoint");
        let key = name.map(|name| format!("{}{name}", location.prefix));
        let (host, path) = match (location.path_style, &key) {
            (true, Some(key)) => (authority.to_owned(), format!("/{}/{}", location.bucket, key)),
            (true, None) => (authority.to_owned(), format!("/{}", location.bucket)),
            (false, Some(key)) => (format!("{}.{authority}", location.bucket), format!("/{key}")),
            (false, None) => (format!("{}.{authority}", location.bucket), "/".to_owned()),
        };
        let path = uri_encode(&path, false);
        let mut pairs: Vec<(String, String)> =
            query.iter().map(|(k, v)| (uri_encode(k, true), uri_encode(v, true))).collect();
        pairs.sort();
        let query = pairs.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&");
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64;
        let date = day_of(now);
        let secs = now.rem_euclid(86_400);
        let amz_date = format!("{date}T{:02}{:02}{:02}Z", secs / 3600, secs / 60 % 60, secs % 60);
        let payload = sha256_hex(&body);
        // Signed: these, and the call's own headers.
        let mut signed: Vec<(String, String)> = vec![
            ("host".to_owned(), host.clone()),
            ("x-amz-content-sha256".to_owned(), payload.clone()),
            ("x-amz-date".to_owned(), amz_date.clone()),
        ];
        for (name, value) in headers {
            signed.push((name.to_ascii_lowercase(), value.trim().to_owned()));
        }
        signed.sort();
        let names = signed.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(";");
        let mut canonical = format!("{method}\n{path}\n{query}\n");
        for (name, value) in &signed {
            canonical.push_str(&format!("{name}:{value}\n"));
        }
        canonical.push_str(&format!("\n{names}\n{payload}"));
        let scope = format!("{date}/{}/s3/aws4_request", location.region);
        let to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", sha256_hex(canonical.as_bytes()));
        let key = derive_signing_key(&location.secret_access_key, &date, &location.region, "s3");
        let signature: String = hmac_sha256(&key, to_sign.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={names}, Signature={signature}",
            location.access_key_id
        );
        let uri = if query.is_empty() {
            format!("{scheme}://{host}{path}")
        } else {
            format!("{scheme}://{host}{path}?{query}")
        };
        let mut request = Request::builder().method(method.clone()).uri(uri);
        for (name, value) in &signed {
            request = request.header(name.as_str(), value.as_str());
        }
        let request = request
            .header("authorization", authorization)
            .header("content-length", body.len())
            .body(Full::new(body))?;
        let response = self.client.request(request).await?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await?.to_bytes();
        Ok(Answer { status, headers, body })
    }
}

/// `s`, URI-encoded as SigV4 has it: every byte but the unreserved ones, and
/// `/` too where `slash` says so.
fn uri_encode(s: &str, slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b'/' if !slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// The text of the first element `tag` of the document `doc`.
fn xml_text(doc: &str, tag: &str) -> Option<String> {
    let doc = roxmltree::Document::parse(doc).ok()?;
    doc.descendants()
        .find(|n| n.has_tag_name(tag))
        .map(|n| n.text().unwrap_or_default().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_as_sigv4_does() {
        assert_eq!(uri_encode("/b/a key+é", false), "/b/a%20key%2B%C3%A9");
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
    }

    #[test]
    fn normalizes_locations() {
        let location = Location {
            endpoint: "https://s3.example.com/".into(),
            region: "us-east-1".into(),
            bucket: "b".into(),
            prefix: "/cairn/backup/".into(),
            path_style: true,
            access_key_id: "k".into(),
            secret_access_key: "s".into(),
        };
        let normal = location.clone().normalized().unwrap();
        assert_eq!(normal.endpoint, "https://s3.example.com");
        assert_eq!(normal.prefix, "cairn/backup/");
        let root = Location { prefix: "/".into(), ..location.clone() }.normalized().unwrap();
        assert_eq!(root.prefix, "");
        assert!(Location { endpoint: "s3.example.com".into(), ..location.clone() }.normalized().is_err());
        assert!(Location { endpoint: "https://h/path".into(), ..location }.normalized().is_err());
    }
}
