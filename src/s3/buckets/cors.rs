//! A bucket's CORS configuration: PutBucketCors, GetBucketCors and
//! DeleteBucketCors (`?cors`), and what it does: it answers browsers'
//! preflight requests (`OPTIONS`, unsigned), and adds CORS headers to the
//! responses to requests from an origin it allows (errors too, so that a page
//! can read them).
//!
//! A request is allowed by the first rule that allows its origin, its method
//! (for a preflight, the one it asks for in `Access-Control-Request-Method`)
//! and, for a preflight, every header it asks for in
//! `Access-Control-Request-Headers`, as in S3. Origins and headers may have
//! one `*` in them, which stands for anything (or nothing); headers are
//! matched without regard to case, origins and methods exactly.
//!
//! Only per bucket, as in S3: there's no setting for the whole cluster.

use http_body_util::Full;
use hyper::{
    HeaderMap, Method, Response, StatusCode,
    body::Bytes,
    header::{self, HeaderName, HeaderValue},
};
use serde::{Deserialize, Serialize};

use crate::db::Cached;
use crate::{
    App,
    auth::Rejection,
    s3::util::{format_s3_error, rejection_response, xml_escape, xml_ok},
};

/// The most rules a configuration may have, as in S3.
const MAX_RULES: usize = 100;
/// The largest configuration document S3 takes, in bytes.
pub const MAX_DOCUMENT: usize = 64 << 10;
/// The longest rule ID, as in S3.
const MAX_ID_LENGTH: usize = 255;
/// The methods a rule may allow, as in S3.
const METHODS: &[&str] = &["GET", "PUT", "HEAD", "POST", "DELETE"];

/// A bucket's CORS configuration.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub rules: Vec<Rule>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// `AllowedOrigin`s.
    pub origins: Vec<String>,
    /// `AllowedMethod`s.
    pub methods: Vec<String>,
    /// `AllowedHeader`s: what a preflight may ask to send.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<String>,
    /// `ExposeHeader`s: the response headers a page may read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expose: Vec<String>,
    /// `MaxAgeSeconds`: how long a browser may keep a preflight's answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age: Option<i32>,
}

/// Why a configuration was refused, as S3 refuses it.
#[derive(Debug, PartialEq)]
pub enum Invalid {
    /// 400 MalformedXML: not the document S3 expects.
    Malformed(String),
    /// 400 InvalidRequest: the document, with a value S3 doesn't allow.
    Request(String),
}

type Node<'a, 'i> = roxmltree::Node<'a, 'i>;

/// The element children of `node` named `name`.
fn children<'a, 'i>(node: Node<'a, 'i>, name: &str) -> Vec<Node<'a, 'i>> {
    node.children().filter(|n| n.tag_name().name() == name).collect()
}

/// The texts of `node`'s children named `name`, trimmed.
fn texts(node: Node, name: &str) -> Vec<String> {
    children(node, name).iter().map(|n| n.text().unwrap_or("").trim().to_owned()).collect()
}

/// The text of `node`'s only child `name`, if it has one; `Err` if it has
/// several.
fn text(node: Node, name: &str) -> Result<Option<String>, Invalid> {
    match &texts(node, name)[..] {
        [] => Ok(None),
        [text] => Ok(Some(text.clone())),
        _ => Err(Invalid::Malformed(format!("more than one {name}"))),
    }
}

/// Refuses the children of `node` that aren't among `known`: S3's schema has
/// no others.
fn only(node: Node, known: &[&str]) -> Result<(), Invalid> {
    match node.children().filter(|n| n.is_element()).find(|n| !known.contains(&n.tag_name().name())) {
        Some(n) => Err(Invalid::Malformed(format!("unknown element {}", n.tag_name().name()))),
        None => Ok(()),
    }
}

impl Configuration {
    /// Parses a `<CORSConfiguration>`, as PutBucketCors takes it.
    pub fn parse(body: &str) -> Result<Configuration, Invalid> {
        let doc = roxmltree::Document::parse(body).map_err(|_| Invalid::Malformed("not XML".to_owned()))?;
        let root = doc.root_element();
        if root.tag_name().name() != "CORSConfiguration" {
            return Err(Invalid::Malformed("not a CORSConfiguration".to_owned()));
        }
        only(root, &["CORSRule"])?;
        let rules = children(root, "CORSRule");
        if rules.is_empty() {
            return Err(Invalid::Malformed("a CORS configuration needs at least one rule".to_owned()));
        }
        let rules = rules.into_iter().map(Rule::parse).collect::<Result<Vec<_>, _>>()?;
        Configuration { rules }.check().map_err(Invalid::Request)
    }

    /// Checks a configuration for what S3 doesn't allow in one that's
    /// well-formed. What's wrong, if anything.
    pub fn check(self) -> Result<Configuration, String> {
        if self.rules.len() > MAX_RULES {
            return Err(format!("A CORS configuration may have at most {MAX_RULES} rules"));
        }
        for rule in &self.rules {
            rule.check()?;
        }
        Ok(self)
    }

    /// As GetBucketCors answers.
    pub fn to_xml(&self) -> String {
        let mut out = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <CORSConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
        );
        for rule in &self.rules {
            rule.write_xml(&mut out);
        }
        out.push_str("</CORSConfiguration>");
        out
    }

    /// As it's stored.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a configuration serializes")
    }

    pub fn from_json(json: &str) -> serde_json::Result<Configuration> {
        serde_json::from_str(json)
    }

    /// The first rule that allows a request from `origin` with `method`,
    /// which (for a preflight) asks to send `headers`.
    pub fn find(&self, origin: &str, method: &str, headers: &[&str]) -> Option<&Rule> {
        self.rules.iter().find(|rule| {
            rule.origins.iter().any(|o| matches(o, origin, false))
                && rule.methods.iter().any(|m| m == method)
                && headers.iter().all(|h| rule.headers.iter().any(|a| matches(a, h, true)))
        })
    }
}

/// Whether `value` matches `pattern`, which may have one `*` standing for
/// any run of characters, `*` alone for any value.
fn matches(pattern: &str, value: &str, ignore_case: bool) -> bool {
    let (pattern, value) = match ignore_case {
        true => (pattern.to_ascii_lowercase(), value.to_ascii_lowercase()),
        false => (pattern.to_owned(), value.to_owned()),
    };
    match pattern.split_once('*') {
        None => pattern == value,
        Some((prefix, suffix)) => {
            value.len() >= prefix.len() + suffix.len() && value.starts_with(prefix) && value.ends_with(suffix)
        }
    }
}

impl Rule {
    fn parse(node: Node) -> Result<Rule, Invalid> {
        only(node, &["ID", "AllowedOrigin", "AllowedMethod", "AllowedHeader", "ExposeHeader", "MaxAgeSeconds"])?;
        let max_age = match text(node, "MaxAgeSeconds")? {
            None => None,
            Some(text) => {
                Some(text.parse().map_err(|_| Invalid::Malformed("MaxAgeSeconds must be a number".to_owned()))?)
            }
        };
        let rule = Rule {
            id: text(node, "ID")?,
            origins: texts(node, "AllowedOrigin"),
            methods: texts(node, "AllowedMethod"),
            headers: texts(node, "AllowedHeader"),
            expose: texts(node, "ExposeHeader"),
            max_age,
        };
        if rule.origins.is_empty() || rule.methods.is_empty() {
            return Err(Invalid::Malformed("a CORS rule needs an AllowedOrigin and an AllowedMethod".to_owned()));
        }
        Ok(rule)
    }

    fn check(&self) -> Result<(), String> {
        if self.origins.is_empty() || self.methods.is_empty() {
            return Err("a CORS rule needs an AllowedOrigin and an AllowedMethod".to_owned());
        }
        if self.id.as_ref().is_some_and(|id| id.len() > MAX_ID_LENGTH) {
            return Err(format!("The ID of a CORS rule can't be longer than {MAX_ID_LENGTH} characters"));
        }
        if let Some(method) = self.methods.iter().find(|m| !METHODS.contains(&m.as_str())) {
            return Err(format!("Found unsupported HTTP method in CORS config. Unsupported method is {method}"));
        }
        if let Some(origin) = self.origins.iter().find(|o| o.matches('*').count() > 1) {
            return Err(format!("AllowedOrigin \"{origin}\" can not have more than one wildcard."));
        }
        if let Some(header) = self.headers.iter().find(|h| h.matches('*').count() > 1) {
            return Err(format!("AllowedHeader \"{header}\" can not have more than one wildcard."));
        }
        if let Some(header) = self.expose.iter().find(|h| h.contains('*')) {
            return Err(format!(
                "ExposeHeader \"{header}\" contains wildcard. We currently do not support wildcard for ExposeHeader."
            ));
        }
        // Each is sent back in a header: a value that can't be one would
        // make every matching response fail.
        let mut values = self.origins.iter().chain(&self.headers).chain(&self.expose);
        if let Some(value) = values.find(|v| HeaderValue::from_str(v).is_err()) {
            return Err(format!("\"{value}\" isn't a valid HTTP header value"));
        }
        if let Some(header) = self.headers.iter().chain(&self.expose).find(|h| !is_token(&h.replace('*', "a"))) {
            return Err(format!("\"{header}\" isn't a valid HTTP header name"));
        }
        Ok(())
    }

    fn write_xml(&self, out: &mut String) {
        out.push_str("<CORSRule>");
        if let Some(id) = &self.id {
            out.push_str(&format!("<ID>{}</ID>", xml_escape(id)));
        }
        let lists = [
            ("AllowedHeader", &self.headers),
            ("AllowedMethod", &self.methods),
            ("AllowedOrigin", &self.origins),
            ("ExposeHeader", &self.expose),
        ];
        for (name, values) in lists {
            for value in values {
                out.push_str(&format!("<{name}>{}</{name}>", xml_escape(value)));
            }
        }
        if let Some(max_age) = self.max_age {
            out.push_str(&format!("<MaxAgeSeconds>{max_age}</MaxAgeSeconds>"));
        }
        out.push_str("</CORSRule>");
    }

    /// Sets the headers that allow a request from `origin` (a preflight
    /// asking to send `requested` headers, or `None` for any other).
    fn allow(&self, origin: &str, requested: Option<&[&str]>, headers: &mut HeaderMap) {
        // A rule for any origin allows any, credentials or not; a rule
        // for some allows this one, with credentials, as S3 answers.
        let any = self.origins.iter().any(|o| o == "*") && !self.origins.iter().any(|o| matches_exactly(o, origin));
        let mut set = |name: HeaderName, value: &str| {
            if let Ok(value) = HeaderValue::from_str(value) {
                headers.insert(name, value);
            }
        };
        set(header::ACCESS_CONTROL_ALLOW_ORIGIN, if any { "*" } else { origin });
        if !any {
            set(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
        }
        set(header::ACCESS_CONTROL_ALLOW_METHODS, &self.methods.join(", "));
        if let Some(requested) = requested.filter(|r| !r.is_empty()) {
            set(header::ACCESS_CONTROL_ALLOW_HEADERS, &requested.join(", "));
        }
        if !self.expose.is_empty() {
            set(header::ACCESS_CONTROL_EXPOSE_HEADERS, &self.expose.join(", "));
        }
        if let Some(max_age) = self.max_age {
            set(header::ACCESS_CONTROL_MAX_AGE, &max_age.to_string());
        }
    }
}

/// Whether `pattern` names `origin` itself, other than by the wildcard alone.
fn matches_exactly(pattern: &str, origin: &str) -> bool {
    pattern != "*" && matches(pattern, origin, false)
}

/// Whether `name` is an HTTP token (RFC 9110, 5.6.2), as header names are.
fn is_token(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// What CORS responses vary by, as S3 says they do.
const VARY: &str = "Origin, Access-Control-Request-Headers, Access-Control-Request-Method";

/// The bucket's CORS configuration: `None` if there's no such bucket,
/// `Some(None)` if it has none.
async fn load(app: &App, bucket: &str) -> anyhow::Result<Option<Option<Configuration>>> {
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached("SELECT cors FROM buckets WHERE name = $1", &[&bucket])
        .await?;
    let Some(row) = row else { return Ok(None) };
    let Some(json) = row.get::<_, Option<String>>(0) else { return Ok(Some(None)) };
    let config = Configuration::from_json(&json)
        .map_err(|e| anyhow::anyhow!("bucket {bucket}'s CORS configuration doesn't parse: {e}"))?;
    Ok(Some(Some(config)))
}

/// The header `name`'s value, if it has one that's text.
fn header<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// The headers a preflight asks to send: `Access-Control-Request-Headers`, a
/// comma-separated list (perhaps in several headers).
fn requested_headers(headers: &HeaderMap) -> Vec<&str> {
    headers
        .get_all(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .collect()
}

/// A preflight's 403: what it asked for isn't allowed.
fn forbidden(message: &str, method: &str, object: bool) -> Response<Full<Bytes>> {
    let mut rejection = Rejection::new(StatusCode::FORBIDDEN, "AccessForbidden", message);
    rejection.details = vec![
        ("Method", method.to_owned()),
        ("ResourceType", if object { "OBJECT" } else { "BUCKET" }.to_owned()),
    ];
    rejection_response(&rejection)
}

/// A browser's preflight request: `OPTIONS /{bucket}[/{key}]`, unsigned,
/// which asks whether a request from its `Origin` with the method in its
/// `Access-Control-Request-Method` (and the headers in its
/// `Access-Control-Request-Headers`) is allowed. It is, with a 200 and the
/// headers that say so, if a rule of the bucket's configuration allows it;
/// else it's a 403.
pub async fn preflight(
    app: &App,
    headers: &HeaderMap,
    bucket: &str,
    object: bool,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let bad_request = |message: &str| format_s3_error(StatusCode::BAD_REQUEST, "BadRequest", message);
    let Some(origin) = header(headers, &header::ORIGIN) else {
        return Ok(bad_request("Insufficient information. Origin request header needed."));
    };
    let method = match header(headers, &header::ACCESS_CONTROL_REQUEST_METHOD) {
        Some(method) if METHODS.contains(&method) => method,
        method => {
            return Ok(bad_request(&format!("Invalid Access-Control-Request-Method: {}", method.unwrap_or("null"))));
        }
    };
    let config = match load(app, bucket).await? {
        None => {
            return Ok(format_s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchBucket",
                "the specified bucket does not exist",
            ));
        }
        Some(None) => return Ok(forbidden("CORSResponse: CORS is not enabled for this bucket.", method, object)),
        Some(Some(config)) => config,
    };
    let requested = requested_headers(headers);
    let Some(rule) = config.find(origin, method, &requested) else {
        return Ok(forbidden(
            "CORSResponse: This CORS request is not allowed. This is usually because the evalution of \
             Origin, request method / Access-Control-Request-Method or Access-Control-Request-Headers \
             are not whitelisted by the resource's CORS spec.",
            method,
            object,
        ));
    };
    let mut response = Response::builder().status(StatusCode::OK).body(Full::new(Bytes::new())).unwrap();
    rule.allow(origin, Some(&requested), response.headers_mut());
    response.headers_mut().insert(header::VARY, HeaderValue::from_static(VARY));
    Ok(response)
}

/// What a request that isn't a preflight needs to know to have its response
/// get CORS headers: where it's from, and what it does to which bucket.
pub struct Cross {
    origin: String,
    method: Method,
    bucket: String,
}

impl Cross {
    /// The request's, if it's from another origin (it has an `Origin`) and
    /// concerns a bucket.
    pub fn of(method: &Method, headers: &HeaderMap, bucket: &str) -> Option<Cross> {
        let origin = header(headers, &header::ORIGIN)?;
        (!bucket.is_empty() && *method != Method::OPTIONS).then(|| Cross {
            origin: origin.to_owned(),
            method: method.clone(),
            bucket: bucket.to_owned(),
        })
    }

    /// Adds the CORS headers its bucket's configuration gives the response,
    /// if any: the response's status doesn't matter.
    pub async fn apply<B>(&self, app: &App, response: &mut Response<B>) -> anyhow::Result<()> {
        let Some(Some(config)) = load(app, &self.bucket).await? else { return Ok(()) };
        let headers = response.headers_mut();
        headers.insert(header::VARY, HeaderValue::from_static(VARY));
        if let Some(rule) = config.find(&self.origin, self.method.as_str(), &[]) {
            rule.allow(&self.origin, None, headers);
        }
        Ok(())
    }
}

/// GetBucketCors: `GET /{bucket}?cors`. A bucket without a configuration
/// answers 404 NoSuchCORSConfiguration, as in S3.
pub async fn get_bucket_cors(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    Ok(match load(app, bucket).await? {
        None => no_such_bucket(),
        Some(None) => {
            format_s3_error(StatusCode::NOT_FOUND, "NoSuchCORSConfiguration", "The CORS configuration does not exist")
        }
        Some(Some(config)) => xml_ok(config.to_xml()),
    })
}

/// PutBucketCors: `PUT /{bucket}?cors` with a `<CORSConfiguration>` body,
/// checked against its integrity headers (see `Payload`), of which S3
/// requires one. Replaces the bucket's configuration.
pub async fn put_bucket_cors(app: &App, bucket: &str, body: Bytes) -> anyhow::Result<Response<Full<Bytes>>> {
    if body.len() > MAX_DOCUMENT {
        return Ok(format_s3_error(
            StatusCode::BAD_REQUEST,
            "MaxMessageLengthExceeded",
            "Your request was too big.",
        ));
    }
    let parsed = std::str::from_utf8(&body)
        .map_err(|_| Invalid::Malformed("not UTF-8".to_owned()))
        .and_then(Configuration::parse);
    let config = match parsed {
        Ok(config) => config,
        Err(Invalid::Malformed(why)) => {
            return Ok(format_s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                &format!(
                    "The XML you provided was not well-formed or did not validate against our \
                     published schema ({why})"
                ),
            ));
        }
        Err(Invalid::Request(why)) => {
            return Ok(format_s3_error(StatusCode::BAD_REQUEST, "InvalidRequest", &why));
        }
    };
    Ok(match set(app, bucket, Some(&config.to_json())).await? {
        true => Response::builder().status(StatusCode::OK).body(Full::new(Bytes::new())).unwrap(),
        false => no_such_bucket(),
    })
}

/// DeleteBucketCors: `DELETE /{bucket}?cors`. Cross-origin requests to the
/// bucket aren't allowed from then on.
pub async fn delete_bucket_cors(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    Ok(match set(app, bucket, None).await? {
        true => Response::builder().status(StatusCode::NO_CONTENT).body(Full::new(Bytes::new())).unwrap(),
        false => no_such_bucket(),
    })
}

/// Sets the bucket's configuration (`cairn_set_cors`). Whether it exists.
async fn set(app: &App, bucket: &str, config: Option<&str>) -> anyhow::Result<bool> {
    Ok(app
        .pool
        .get()
        .await?
        .query_one_cached("SELECT pg_temp.cairn_set_cors($1, $2)", &[&bucket, &config])
        .await?
        .get(0))
}

fn no_such_bucket() -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::NOT_FOUND, "NoSuchBucket", "the specified bucket does not exist")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(rules: &str) -> Result<Configuration, Invalid> {
        Configuration::parse(&format!(
            "<CORSConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{rules}</CORSConfiguration>"
        ))
    }

    fn rule(origins: &[&str], methods: &[&str]) -> String {
        let origins: String = origins.iter().map(|o| format!("<AllowedOrigin>{o}</AllowedOrigin>")).collect();
        let methods: String = methods.iter().map(|m| format!("<AllowedMethod>{m}</AllowedMethod>")).collect();
        format!("<CORSRule>{origins}{methods}</CORSRule>")
    }

    /// The origin a request from `origin` with `method` is allowed for, as
    /// its response's `Access-Control-Allow-Origin` says, and the methods
    /// its `Access-Control-Allow-Methods` names.
    fn allowed(config: &Configuration, origin: &str, method: &str) -> Option<(String, String)> {
        let rule = config.find(origin, method, &[])?;
        let mut headers = HeaderMap::new();
        rule.allow(origin, None, &mut headers);
        let get = |name| headers.get(name).unwrap().to_str().unwrap().to_owned();
        Some((get(header::ACCESS_CONTROL_ALLOW_ORIGIN), get(header::ACCESS_CONTROL_ALLOW_METHODS)))
    }

    /// s3-tests' test_cors_origin_response, which S3 passes.
    #[test]
    fn matches_origins_with_a_wildcard() {
        let config = config(
            &[
                rule(&["*suffix"], &["GET"]),
                rule(&["start*end"], &["GET"]),
                rule(&["prefix*"], &["GET"]),
                rule(&["*.put"], &["PUT"]),
            ]
            .concat(),
        )
        .unwrap();
        let get = |origin| allowed(&config, origin, "GET").map(|(origin, _)| origin);
        for origin in ["foo.suffix", "startend", "start1end", "start12end", "prefix", "prefix.suffix"] {
            assert_eq!(get(origin).as_deref(), Some(origin), "{origin}");
        }
        for origin in ["foo.bar", "foo.suffix.get", "0start12end", "bla.prefix", "foo.put", "Foo.Suffix"] {
            assert_eq!(get(origin), None, "{origin}");
        }
        assert_eq!(allowed(&config, "foo.put", "PUT"), Some(("foo.put".to_owned(), "PUT".to_owned())));
        assert_eq!(allowed(&config, "foo.suffix", "PUT"), None);
        // `start*end` doesn't match `startend` twice over (`*` overlapping).
        assert_eq!(get("starend"), None);
    }

    #[test]
    fn a_wildcard_rule_allows_any_origin_without_credentials() {
        let any = config(&rule(&["*"], &["GET", "HEAD"])).unwrap();
        assert_eq!(allowed(&any, "https://a.example", "GET"), Some(("*".to_owned(), "GET, HEAD".to_owned())));
        let mut headers = HeaderMap::new();
        any.rules[0].allow("https://a.example", None, &mut headers);
        assert!(!headers.contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS));

        let one = config(&rule(&["https://a.example"], &["GET"])).unwrap();
        let mut headers = HeaderMap::new();
        one.rules[0].allow("https://a.example", None, &mut headers);
        assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], "https://a.example");
        assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_CREDENTIALS], "true");
    }

    /// The first rule that allows a request is the one that answers it.
    #[test]
    fn the_first_matching_rule_answers() {
        let rules = "<CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod>\
                     <MaxAgeSeconds>10</MaxAgeSeconds></CORSRule>\
                     <CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod>\
                     <AllowedMethod>PUT</AllowedMethod><MaxAgeSeconds>20</MaxAgeSeconds></CORSRule>";
        let config = config(rules).unwrap();
        assert_eq!(config.find("o", "GET", &[]).unwrap().max_age, Some(10));
        assert_eq!(config.find("o", "PUT", &[]).unwrap().max_age, Some(20));
    }

    /// A preflight's headers must all be allowed, regardless of case.
    #[test]
    fn matches_requested_headers() {
        let rules = "<CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>PUT</AllowedMethod>\
                     <AllowedHeader>Content-Type</AllowedHeader><AllowedHeader>x-amz-meta-*</AllowedHeader>\
                     <ExposeHeader>ETag</ExposeHeader><ExposeHeader>x-amz-version-id</ExposeHeader>\
                     </CORSRule>";
        let config = config(rules).unwrap();
        assert!(config.find("o", "PUT", &["content-type", "X-Amz-Meta-Name"]).is_some());
        assert!(config.find("o", "PUT", &["content-type", "x-amz-date"]).is_none());
        // s3-tests' test_cors_header_option: no allowed headers allow none.
        let none = super::tests::config(&rule(&["*"], &["GET"])).unwrap();
        assert!(none.find("o", "GET", &["x-amz-meta-header2"]).is_none());

        let mut headers = HeaderMap::new();
        config.rules[0].allow("o", Some(&["content-type", "x-amz-meta-a"]), &mut headers);
        assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_HEADERS], "content-type, x-amz-meta-a");
        assert_eq!(headers[header::ACCESS_CONTROL_EXPOSE_HEADERS], "ETag, x-amz-version-id");
        assert!(!headers.contains_key(header::ACCESS_CONTROL_MAX_AGE));
    }

    #[test]
    fn reads_back_as_it_was_set() {
        let rules = "<CORSRule><ID>uploads</ID><AllowedHeader>*</AllowedHeader><AllowedMethod>PUT</AllowedMethod>\
                     <AllowedMethod>POST</AllowedMethod><AllowedOrigin>https://*.example.com</AllowedOrigin>\
                     <ExposeHeader>ETag</ExposeHeader><MaxAgeSeconds>3000</MaxAgeSeconds></CORSRule>\
                     <CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin></CORSRule>";
        let parsed = config(rules).unwrap();
        assert_eq!(
            parsed.to_xml(),
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                 <CORSConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{rules}</CORSConfiguration>"
            )
        );
        assert_eq!(Configuration::from_json(&parsed.to_json()).unwrap(), parsed);
    }

    #[test]
    fn refuses_what_s3_refuses() {
        let malformed = |rules: &str| matches!(config(rules), Err(Invalid::Malformed(_)));
        let refused = |rules: &str| match config(rules) {
            Err(Invalid::Request(why)) => why,
            other => panic!("{rules}: {other:?}"),
        };
        assert!(malformed(""));
        assert!(malformed(&rule(&[], &["GET"])));
        assert!(malformed(&rule(&["*"], &[])));
        assert!(malformed("<CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod>\
                           <Unknown/></CORSRule>"));
        assert!(malformed("<CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod>\
                           <MaxAgeSeconds>soon</MaxAgeSeconds></CORSRule>"));
        assert!(matches!(Configuration::parse("<Other/>"), Err(Invalid::Malformed(_))));
        assert_eq!(
            refused(&rule(&["*"], &["PATCH"])),
            "Found unsupported HTTP method in CORS config. Unsupported method is PATCH"
        );
        // Methods are as HTTP has them: case matters.
        assert!(refused(&rule(&["*"], &["get"])).contains("get"));
        assert!(refused(&rule(&["http://*.*"], &["GET"])).contains("more than one wildcard"));
        assert!(refused("<CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod>\
                         <AllowedHeader>x-*-*</AllowedHeader></CORSRule>")
            .contains("more than one wildcard"));
        assert!(refused("<CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod>\
                         <ExposeHeader>*</ExposeHeader></CORSRule>")
            .contains("wildcard"));
        assert!(refused("<CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod>\
                         <AllowedHeader>a b</AllowedHeader></CORSRule>")
            .contains("header name"));
        let id = |n| format!("<CORSRule><ID>{}</ID><AllowedOrigin>*</AllowedOrigin>\
                              <AllowedMethod>GET</AllowedMethod></CORSRule>", "i".repeat(n));
        assert!(config(&id(MAX_ID_LENGTH)).is_ok());
        assert!(refused(&id(MAX_ID_LENGTH + 1)).contains("ID"));
        assert!(config(&rule(&["*"], &["GET"]).repeat(MAX_RULES)).is_ok());
        assert!(refused(&rule(&["*"], &["GET"]).repeat(MAX_RULES + 1)).contains("at most"));
    }
}
