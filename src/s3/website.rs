//! A bucket's website, as S3's website endpoints serve it: what's in the
//! bucket, to anyone, as web pages, by its website configuration (see
//! `buckets::website`). Requests come to hosts of the websites' own (see
//! `hosting`).
//!
//! As in S3:
//!
//! - Only GET and HEAD (and CORS preflights). Requests aren't signed: each
//!   is anonymous, so only what the bucket's policy makes public is served
//!   (`s3:GetObject`), and a public access block applies as to any request.
//! - A configuration that redirects every request (`RedirectAllRequestsTo`)
//!   answers each with a 301 to the same path there.
//! - Otherwise, the first routing rule whose condition is only on the key
//!   (or that has none) redirects a request for a key it matches.
//! - The root, and a key ending in `/`, is served its index document: the
//!   key with the configuration's suffix appended. A key that isn't there,
//!   but whose index document (`key/` and the suffix) is, is redirected
//!   there with a 302.
//! - An object with a website redirect location
//!   (`x-amz-website-redirect-location`) is a 301 there.
//! - A request that fails is redirected by the first routing rule whose
//!   condition is on its error's status (and its key's prefix, if the
//!   condition names one). Else a 4XX is answered with the error document,
//!   if there is one, with the error's status; anything else with an HTML
//!   page that says what went wrong (and why the error document couldn't be
//!   served, if it couldn't be).
//! - A key that isn't there is a 403, not a 404, unless the bucket's policy
//!   makes listing it public (`s3:ListBucket`), so that keys can't be found
//!   by guessing.
//!
//! Redirects to the request's own host and protocol name what its `Host`
//! and `X-Forwarded-Proto` say.

use std::{net::IpAddr, sync::Arc};

use http_body_util::{BodyExt, Full};
use hyper::{
    HeaderMap, Method, Response, StatusCode,
    body::Bytes,
    header::{self, HeaderName, HeaderValue},
};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

use crate::{
    App,
    body::{ResBody, box_response},
    s3::{
        access,
        actions::{Check, On},
        buckets::{
            cors,
            website::{self, RoutingRule},
        },
        conditional::Preconditions,
        metadata,
        objects::get::{get_object, head_object, lookup_version},
        util::decode_path_param,
    },
};

/// The characters escaped in a key in a redirect's `Location`: all but
/// those a path keeps as they are.
const KEY_ESCAPES: &AsciiSet = &NON_ALPHANUMERIC.remove(b'/').remove(b'-').remove(b'.').remove(b'_').remove(b'~');

/// An error a website request ends with, as S3's HTML page has it.
#[derive(Clone, Debug, PartialEq)]
struct Failure {
    status: StatusCode,
    code: String,
    message: String,
    /// The page's further items (`Key`, `BucketName`).
    details: Vec<(&'static str, String)>,
}

impl Failure {
    fn new(status: StatusCode, code: &str, message: &str) -> Failure {
        Failure { status, code: code.to_owned(), message: message.to_owned(), details: Vec::new() }
    }

    fn with(mut self, name: &'static str, value: &str) -> Failure {
        self.details.push((name, value.to_owned()));
        self
    }

    fn no_such_key(key: &str) -> Failure {
        Failure::new(StatusCode::NOT_FOUND, "NoSuchKey", "The specified key does not exist.").with("Key", key)
    }

    fn access_denied() -> Failure {
        Failure::new(StatusCode::FORBIDDEN, "AccessDenied", "Access Denied")
    }
}

/// What reading an object for a website request came to.
enum Fetched {
    /// It, as a GET (or HEAD) of it answers.
    Object(Response<ResBody>),
    /// Its website redirect location.
    Redirect(String),
    Failed(Failure),
}

/// A website request, once its bucket has a website configuration.
struct Site<'a> {
    app: &'a Arc<App>,
    method: &'a Method,
    headers: &'a HeaderMap,
    bucket: &'a str,
    access: access::Access,
}

/// Answers a request for the website of the bucket `path` (a route's: see
/// `hosting`) names, from `peer`.
pub async fn serve(
    app: &Arc<App>,
    method: &Method,
    headers: &HeaderMap,
    path: &str,
    peer: IpAddr,
) -> anyhow::Result<Response<ResBody>> {
    let path = path.strip_prefix('/').unwrap_or(path);
    let (bucket, rest) = path.split_once('/').unwrap_or((path, ""));
    let bucket = decode_path_param(bucket);
    let key = decode_path_param(rest);
    let head = *method == Method::HEAD;
    if bucket.is_empty() {
        let failure = Failure::new(StatusCode::NOT_FOUND, "NoSuchBucket", "The specified bucket does not exist");
        return Ok(page(&failure.with("BucketName", ""), None, head));
    }
    // A browser's CORS preflight, answered by the bucket's CORS rules.
    if *method == Method::OPTIONS {
        return Ok(box_response(cors::preflight(app, headers, &bucket, true).await?));
    }
    if !matches!(*method, Method::GET | Method::HEAD) {
        let failure = Failure::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "The specified method is not allowed against this resource.",
        )
        .with("Method", method.as_str())
        .with("ResourceType", "OBJECT");
        let mut response = page(&failure, None, false);
        response.headers_mut().insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        return Ok(response);
    }
    let config = match website::load(app, &bucket).await? {
        None => {
            let failure = Failure::new(StatusCode::NOT_FOUND, "NoSuchBucket", "The specified bucket does not exist");
            return Ok(page(&failure.with("BucketName", &bucket), None, head));
        }
        Some(None) => {
            let failure = Failure::new(
                StatusCode::NOT_FOUND,
                "NoSuchWebsiteConfiguration",
                "The specified bucket does not have a website configuration",
            );
            return Ok(page(&failure.with("BucketName", &bucket), None, head));
        }
        Some(Some(config)) => config,
    };
    let own = Own::of(headers, &bucket);
    // Every request, to the same path elsewhere.
    if let Some(all) = &config.redirect_all_requests_to {
        let protocol = all.protocol.as_deref().unwrap_or(own.protocol);
        return Ok(redirect(StatusCode::MOVED_PERMANENTLY, &format!("{protocol}://{}/{rest}", all.host_name)));
    }
    if let Some(rule) = config.routing_rules.iter().find(|rule| matches(rule, &key, None)) {
        return Ok(redirect_by(rule, &key, &own));
    }
    let account = crate::users::account(&app.pool.get().await?).await?;
    let origin = access::Origin { peer: Some(peer), trusted_proxies: &app.trusted_proxies, signed: None, form: false };
    let mut access = access::Access::new(None, &account, method, headers, "", &origin)?;
    access.load(app, &bucket).await?;
    let site = Site { app, method, headers, bucket: &bucket, access };
    let suffix = config.index_document.as_deref().unwrap_or_default();
    let target = match key.is_empty() || key.ends_with('/') {
        true => format!("{key}{suffix}"),
        false => key.clone(),
    };
    let failure = match site.fetch(&target, true).await? {
        Fetched::Object(response) => return Ok(response),
        Fetched::Redirect(location) => return Ok(redirect(StatusCode::MOVED_PERMANENTLY, &location)),
        Fetched::Failed(failure) => failure,
    };
    // A "directory" without its `/`, if it has an index document.
    if failure.code == "NoSuchKey" && target == key && !key.is_empty() {
        let index = format!("{key}/{suffix}");
        if site.readable(&index) && site.exists(&index).await? {
            return Ok(redirect(StatusCode::FOUND, &format!("/{}/", utf8_percent_encode(&key, KEY_ESCAPES))));
        }
    }
    let failure = site.hide_missing(failure);
    if let Some(rule) = config.routing_rules.iter().find(|rule| matches(rule, &key, Some(failure.status))) {
        return Ok(redirect_by(rule, &key, &own));
    }
    let Some(document) = config.error_document.as_deref().filter(|_| failure.status.is_client_error()) else {
        return Ok(page(&failure, None, head));
    };
    Ok(match site.fetch(document, false).await? {
        Fetched::Object(mut response) => {
            *response.status_mut() = failure.status;
            response
        }
        Fetched::Redirect(location) => redirect(StatusCode::MOVED_PERMANENTLY, &location),
        Fetched::Failed(error_document) => page(&failure, Some(&site.hide_missing(error_document)), head),
    })
}

impl Site<'_> {
    /// Whether the object `key` may be read anonymously.
    fn readable(&self, key: &str) -> bool {
        self.access.allows(&Check { action: "s3:GetObject", on: On::Object(self.bucket.to_owned(), key.to_owned()) })
    }

    /// Whether `key` has a current version that isn't a delete marker.
    async fn exists(&self, key: &str) -> anyhow::Result<bool> {
        let client = self.app.pool.get().await?;
        Ok(lookup_version(&client, self.bucket, key, None).await?.is_ok())
    }

    /// A key that isn't there, as told to whom may not list the bucket.
    fn hide_missing(&self, failure: Failure) -> Failure {
        let list = Check { action: "s3:ListBucket", on: On::Bucket(self.bucket.to_owned()) };
        match failure.code == "NoSuchKey" && !self.access.allows(&list) {
            true => Failure::access_denied(),
            false => failure,
        }
    }

    /// Reads the object `key`, as the request asks (its range and
    /// conditions, if it's the one `requested`, not the error document).
    async fn fetch(&self, key: &str, requested: bool) -> anyhow::Result<Fetched> {
        if !self.readable(key) {
            return Ok(Fetched::Failed(Failure::access_denied()));
        }
        {
            let client = self.app.pool.get().await?;
            match lookup_version(&client, self.bucket, key, None).await? {
                Err(_) => return Ok(Fetched::Failed(Failure::no_such_key(key))),
                Ok(version) => {
                    if let Some(location) = metadata::redirect_location(&version.metadata) {
                        return Ok(Fetched::Redirect(location.to_owned()));
                    }
                }
            }
        }
        let range = match requested {
            true => self.headers.get(header::RANGE).and_then(|v| v.to_str().ok()),
            false => None,
        };
        let preconditions = match requested {
            true => Preconditions::from_headers(self.headers),
            false => Preconditions::from_headers(&HeaderMap::new()),
        };
        let response = match *self.method {
            Method::HEAD => {
                let response =
                    head_object(self.app, self.bucket, key, None, range, None, &preconditions, None, None, false).await?;
                box_response(response)
            }
            _ => get_object(self.app, self.bucket, key, None, range, None, &preconditions, None, None, false).await?,
        };
        let status = response.status();
        if status.is_success() || status == StatusCode::NOT_MODIFIED {
            return Ok(Fetched::Object(without_api_headers(response)));
        }
        // An error from the API's handlers, whose document says which.
        let (parts, body) = response.into_parts();
        let body = body.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
        let failure = match error_of(&body) {
            Some((code, message)) => {
                let failure = Failure { status: parts.status, code, message, details: Vec::new() };
                match failure.code.as_str() {
                    "NoSuchKey" => failure.with("Key", key),
                    _ => failure,
                }
            }
            None => Failure::new(parts.status, "InternalError", "We encountered an internal error. Please try again."),
        };
        Ok(Fetched::Failed(failure))
    }
}

/// What a GET of an object answers with that's the API's, not the page's:
/// its version and how it's stored. S3's website endpoints keep the rest
/// (its metadata, `x-amz-meta-*` too).
fn without_api_headers(mut response: Response<ResBody>) -> Response<ResBody> {
    let headers = response.headers_mut();
    let api: Vec<HeaderName> = headers
        .keys()
        .filter(|name| {
            let name = name.as_str();
            name.starts_with("x-amz-") && !name.starts_with("x-amz-meta-") && name != "x-amz-request-id"
        })
        .cloned()
        .collect();
    for name in api {
        headers.remove(name);
    }
    response
}

/// The code and message of an S3 error document.
fn error_of(body: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(body).ok()?;
    let doc = roxmltree::Document::parse(text).ok()?;
    let field = |name| {
        doc.root_element().children().find(|n| n.tag_name().name() == name).and_then(|n| n.text()).map(str::to_owned)
    };
    Some((field("Code")?, field("Message").unwrap_or_default()))
}

/// The request's own host and protocol, for redirects that keep them.
struct Own<'a> {
    host: &'a str,
    protocol: &'a str,
}

impl<'a> Own<'a> {
    fn of(headers: &'a HeaderMap, bucket: &'a str) -> Own<'a> {
        Own {
            host: headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or(bucket),
            protocol: match crate::s3::sse_c::secure(headers, false) {
                true => "https",
                false => "http",
            },
        }
    }
}

/// Whether `rule` redirects a request for `key`: before it's served
/// (`error` `None`), if its condition is only on the key; else once it has
/// failed with `error`, if its condition is on that error.
fn matches(rule: &RoutingRule, key: &str, error: Option<StatusCode>) -> bool {
    let Some(condition) = &rule.condition else { return error.is_none() };
    let prefix = condition.key_prefix_equals.as_deref().is_none_or(|prefix| key.starts_with(prefix));
    match (condition.http_error_code_returned_equals, error) {
        (None, None) => prefix,
        (Some(code), Some(error)) => prefix && code == error.as_u16(),
        _ => false,
    }
}

/// The redirect `rule` makes of a request for `key`.
fn redirect_by(rule: &RoutingRule, key: &str, own: &Own) -> Response<ResBody> {
    let to = &rule.redirect;
    let prefix = rule.condition.as_ref().and_then(|c| c.key_prefix_equals.as_deref()).unwrap_or("");
    let key = match (&to.replace_key_with, &to.replace_key_prefix_with) {
        (Some(replacement), _) => replacement.clone(),
        (None, Some(replacement)) => format!("{replacement}{}", key.strip_prefix(prefix).unwrap_or(key)),
        (None, None) => key.to_owned(),
    };
    let location = format!(
        "{}://{}/{}",
        to.protocol.as_deref().unwrap_or(own.protocol),
        to.host_name.as_deref().unwrap_or(own.host),
        utf8_percent_encode(&key, KEY_ESCAPES)
    );
    let status = to.http_redirect_code.and_then(|code| StatusCode::from_u16(code).ok());
    redirect(status.unwrap_or(StatusCode::MOVED_PERMANENTLY), &location)
}

/// A redirect to `location`, with no body.
fn redirect(status: StatusCode, location: &str) -> Response<ResBody> {
    let mut response = Response::builder().status(status).body(Full::new(Bytes::new())).unwrap();
    if let Ok(location) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    box_response(response)
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// S3's HTML page for a website request's `failure`, and for the error
/// document's, if it couldn't be served. A HEAD's has no body. Either way,
/// its headers say what went wrong, as S3's do.
fn page(failure: &Failure, error_document: Option<&Failure>, head: bool) -> Response<ResBody> {
    let items = |failure: &Failure, request_id: bool| {
        let mut items = vec![("Code", failure.code.clone()), ("Message", failure.message.clone())];
        items.extend(failure.details.iter().cloned());
        if request_id && let Some(id) = crate::s3::request_id() {
            items.push(("RequestId", id));
        }
        let lines: String =
            items.iter().map(|(name, value)| format!("<li>{name}: {}</li>\n", html_escape(value))).collect();
        format!("<ul>\n{lines}</ul>\n")
    };
    let status = failure.status;
    let title = format!("{} {}", status.as_u16(), status.canonical_reason().unwrap_or(""));
    let mut html = format!("<html>\n<head><title>{title}</title></head>\n<body>\n<h1>{title}</h1>\n");
    html.push_str(&items(failure, true));
    if let Some(error_document) = error_document {
        html.push_str("<h3>An Error Occurred While Attempting to Retrieve a Custom Error Document</h3>\n");
        html.push_str(&items(error_document, false));
    }
    html.push_str("<hr/>\n</body>\n</html>\n");
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CONTENT_LENGTH, html.len());
    let error_headers = [("x-amz-error-code", &failure.code), ("x-amz-error-message", &failure.message)];
    for (name, value) in error_headers {
        if let Ok(value) = HeaderValue::from_str(value) {
            builder = builder.header(name, value);
        }
    }
    for (name, value) in &failure.details {
        if let Ok(value) = HeaderValue::from_str(value) {
            builder = builder.header(format!("x-amz-error-detail-{name}"), value);
        }
    }
    let body = match head {
        true => Bytes::new(),
        false => Bytes::from(html),
    };
    box_response(builder.body(Full::new(body)).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3::buckets::website::{Condition, Redirect};

    fn rule(prefix: Option<&str>, error: Option<u16>, redirect: Redirect) -> RoutingRule {
        let condition = match (prefix, error) {
            (None, None) => None,
            _ => Some(Condition {
                key_prefix_equals: prefix.map(str::to_owned),
                http_error_code_returned_equals: error,
            }),
        };
        RoutingRule { condition, redirect }
    }

    fn location(rule: &RoutingRule, key: &str) -> (StatusCode, String) {
        let own = Own { host: "site.example:8080", protocol: "http" };
        let response = redirect_by(rule, key, &own);
        (response.status(), response.headers()[header::LOCATION].to_str().unwrap().to_owned())
    }

    #[test]
    fn rules_match_keys_or_errors() {
        let any = Redirect { protocol: Some("https".to_owned()), ..Default::default() };
        let all = rule(None, None, any.clone());
        assert!(matches(&all, "a", None));
        assert!(!matches(&all, "a", Some(StatusCode::NOT_FOUND)));
        let docs = rule(Some("docs/"), None, any.clone());
        assert!(matches(&docs, "docs/a.html", None));
        assert!(!matches(&docs, "doc", None));
        assert!(!matches(&docs, "docs/a.html", Some(StatusCode::NOT_FOUND)));
        let missing = rule(None, Some(404), any.clone());
        assert!(!matches(&missing, "a", None));
        assert!(matches(&missing, "a", Some(StatusCode::NOT_FOUND)));
        assert!(!matches(&missing, "a", Some(StatusCode::FORBIDDEN)));
        let missing_docs = rule(Some("docs/"), Some(404), any);
        assert!(matches(&missing_docs, "docs/a", Some(StatusCode::NOT_FOUND)));
        assert!(!matches(&missing_docs, "a", Some(StatusCode::NOT_FOUND)));
    }

    #[test]
    fn redirects_where_rules_say() {
        let prefix = Redirect { replace_key_prefix_with: Some("documents/".to_owned()), ..Default::default() };
        assert_eq!(
            location(&rule(Some("docs/"), None, prefix.clone()), "docs/a b.html"),
            (StatusCode::MOVED_PERMANENTLY, "http://site.example:8080/documents/a%20b.html".to_owned())
        );
        // Without a prefix in the condition, it's prepended.
        assert_eq!(location(&rule(None, Some(404), prefix), "a").1, "http://site.example:8080/documents/a");
        let elsewhere = Redirect {
            host_name: Some("example.com".to_owned()),
            protocol: Some("https".to_owned()),
            replace_key_with: Some("error.html".to_owned()),
            http_redirect_code: Some(307),
            ..Default::default()
        };
        assert_eq!(
            location(&rule(None, Some(404), elsewhere), "x"),
            (StatusCode::TEMPORARY_REDIRECT, "https://example.com/error.html".to_owned())
        );
        let host = Redirect { host_name: Some("example.com".to_owned()), ..Default::default() };
        assert_eq!(location(&rule(None, None, host), "a/b").1, "http://example.com/a/b");
    }

    #[tokio::test]
    async fn pages_say_what_went_wrong() {
        let failure = Failure::no_such_key("a<b");
        let response = page(&failure, Some(&Failure::access_denied()), false);
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers()["x-amz-error-code"], "NoSuchKey");
        assert_eq!(response.headers()["x-amz-error-detail-Key"], "a<b");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = std::str::from_utf8(&body).unwrap();
        assert!(body.contains("<h1>404 Not Found</h1>"), "{body}");
        assert!(body.contains("<li>Key: a&lt;b</li>"), "{body}");
        assert!(body.contains("Custom Error Document</h3>\n<ul>\n<li>Code: AccessDenied</li>"), "{body}");

        let response = page(&failure, None, true);
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(response.into_body().collect().await.unwrap().to_bytes().is_empty());
    }

    #[test]
    fn reads_errors_of_the_api() {
        let body = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>InvalidRange</Code>\
                     <Message>the requested range is not satisfiable</Message><RequestId>1</RequestId></Error>";
        assert_eq!(
            error_of(body),
            Some(("InvalidRange".to_owned(), "the requested range is not satisfiable".to_owned()))
        );
        assert_eq!(error_of(b"nope"), None);
    }
}
