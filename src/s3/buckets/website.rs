//! A bucket's website configuration: PutBucketWebsite, GetBucketWebsite and
//! DeleteBucketWebsite (`?website`), as in S3. What it does, the bucket's
//! website as its website endpoint serves it, is `s3::website`.
//!
//! A configuration either redirects every request to another host
//! (`RedirectAllRequestsTo`), or has an index document (`IndexDocument`),
//! and maybe an error document (`ErrorDocument`) and up to 50 routing rules
//! (`RoutingRules`), each of which redirects the requests it matches: by
//! the prefix of their keys, the error they'd get, or both.

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use serde::{Deserialize, Serialize};

use crate::db::Cached;
use crate::{
    App,
    auth::Rejection,
    s3::util::{format_s3_error, rejection_response, xml_escape, xml_ok},
};

/// The most routing rules a configuration may have, as in S3.
pub const MAX_RULES: usize = 50;
/// The largest configuration document taken, in bytes (as CORS's).
pub const MAX_DOCUMENT: usize = 64 << 10;

/// A bucket's website configuration.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Website {
    /// `RedirectAllRequestsTo`: every request is redirected there; nothing
    /// else may be set then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_all_requests_to: Option<RedirectAll>,
    /// `IndexDocument`'s `Suffix`: what a request for a "directory" (the
    /// root, or a key ending in `/`) is served, appended to its key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index_document: Option<String>,
    /// `ErrorDocument`'s `Key`: the object served (with the error's status)
    /// for a 4XX error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_document: Option<String>,
    /// `RoutingRules`: the first one whose condition a request meets
    /// redirects it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routing_rules: Vec<RoutingRule>,
}

/// Where every request is redirected to.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RedirectAll {
    pub host_name: String,
    /// `http` or `https`; the request's own, if none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RoutingRule {
    /// What requests the rule redirects; all, if none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<Condition>,
    pub redirect: Redirect,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    /// `KeyPrefixEquals`: the requests for keys starting with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_prefix_equals: Option<String>,
    /// `HttpErrorCodeReturnedEquals`: the requests that would get this
    /// error (a 4XX or 5XX), only once they have.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_error_code_returned_equals: Option<u16>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Redirect {
    /// The host redirected to; the request's own, if none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_name: Option<String>,
    /// The redirect's status, a 3XX but 300; 301, if none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_redirect_code: Option<u16>,
    /// `http` or `https`; the request's own, if none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// What replaces the prefix the condition names (all of a key, if it
    /// names none).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replace_key_prefix_with: Option<String>,
    /// What replaces the key. Not with `replace_key_prefix_with`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replace_key_with: Option<String>,
}

/// Why a configuration was refused, as S3 refuses it.
#[derive(Debug, PartialEq)]
pub enum Invalid {
    /// 400 MalformedXML: not the document S3's schema has.
    Malformed(String),
    /// 400 InvalidArgument: a value S3 doesn't take; the message, and the
    /// argument's name and value, as S3's error names them.
    Argument(String, &'static str, String),
    /// 400 InvalidRequest: a configuration S3 doesn't take.
    Request(String),
}

impl Invalid {
    /// The response S3 refuses a PutBucketWebsite with.
    pub fn response(&self) -> Response<Full<Bytes>> {
        match self {
            Invalid::Malformed(why) => format_s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                &format!(
                    "The XML you provided was not well-formed or did not validate against our published schema ({why})"
                ),
            ),
            Invalid::Argument(message, name, value) => {
                let mut rejection = Rejection::new(StatusCode::BAD_REQUEST, "InvalidArgument", message.clone());
                rejection.details = vec![("ArgumentName", (*name).to_owned()), ("ArgumentValue", value.clone())];
                rejection_response(&rejection)
            }
            Invalid::Request(message) => format_s3_error(StatusCode::BAD_REQUEST, "InvalidRequest", message),
        }
    }
}

type Node<'a, 'i> = roxmltree::Node<'a, 'i>;

/// The element children of `node` named `name`.
fn children<'a, 'i>(node: Node<'a, 'i>, name: &str) -> Vec<Node<'a, 'i>> {
    node.children().filter(|n| n.tag_name().name() == name).collect()
}

/// `node`'s only child `name`, if it has one; `Err` if it has several.
fn child<'a, 'i>(node: Node<'a, 'i>, name: &str) -> Result<Option<Node<'a, 'i>>, Invalid> {
    match &children(node, name)[..] {
        [] => Ok(None),
        [child] => Ok(Some(*child)),
        _ => Err(Invalid::Malformed(format!("more than one {name}"))),
    }
}

/// The text of `node`'s only child `name`, if it has one (untrimmed: a key
/// may start or end with spaces).
fn text(node: Node, name: &str) -> Result<Option<String>, Invalid> {
    Ok(child(node, name)?.map(|n| n.text().unwrap_or("").to_owned()))
}

/// The text of `node`'s child `name`, which S3's schema requires.
fn required(node: Node, name: &str) -> Result<String, Invalid> {
    text(node, name)?.ok_or_else(|| Invalid::Malformed(format!("{} needs a {name}", node.tag_name().name())))
}

/// Refuses the children of `node` that aren't among `known`: S3's schema has
/// no others.
fn only(node: Node, known: &[&str]) -> Result<(), Invalid> {
    match node.children().filter(|n| n.is_element()).find(|n| !known.contains(&n.tag_name().name())) {
        Some(n) => Err(Invalid::Malformed(format!("unknown element {}", n.tag_name().name()))),
        None => Ok(()),
    }
}

/// A status code's text as a number, if it's one.
fn code(text: Option<String>, name: &'static str) -> Result<Option<u16>, Invalid> {
    match text {
        None => Ok(None),
        Some(text) => match text.trim().parse() {
            Ok(code) => Ok(Some(code)),
            Err(_) => Err(Invalid::Argument(format!("The provided {name} ({text}) is not valid."), name, text)),
        },
    }
}

/// S3's refusal of a protocol other than `http` or `https`.
fn check_protocol(protocol: &Option<String>) -> Result<(), Invalid> {
    match protocol.as_deref() {
        None | Some("http" | "https") => Ok(()),
        Some(other) => Err(Invalid::Argument(
            "Invalid protocol, protocol can be http or https. If not defined the protocol will be selected \
             automatically."
                .to_owned(),
            "Protocol",
            other.to_owned(),
        )),
    }
}

impl Website {
    /// Parses a `<WebsiteConfiguration>`, as PutBucketWebsite takes it.
    pub fn parse(body: &str) -> Result<Website, Invalid> {
        let doc = roxmltree::Document::parse(body).map_err(|_| Invalid::Malformed("not XML".to_owned()))?;
        let root = doc.root_element();
        if root.tag_name().name() != "WebsiteConfiguration" {
            return Err(Invalid::Malformed("not a WebsiteConfiguration".to_owned()));
        }
        only(root, &["RedirectAllRequestsTo", "IndexDocument", "ErrorDocument", "RoutingRules"])?;
        let redirect_all_requests_to = match child(root, "RedirectAllRequestsTo")? {
            None => None,
            Some(node) => {
                only(node, &["HostName", "Protocol"])?;
                Some(RedirectAll { host_name: required(node, "HostName")?, protocol: text(node, "Protocol")? })
            }
        };
        let index_document = match child(root, "IndexDocument")? {
            None => None,
            Some(node) => {
                only(node, &["Suffix"])?;
                Some(required(node, "Suffix")?)
            }
        };
        let error_document = match child(root, "ErrorDocument")? {
            None => None,
            Some(node) => {
                only(node, &["Key"])?;
                Some(required(node, "Key")?)
            }
        };
        let routing_rules = match child(root, "RoutingRules")? {
            None => Vec::new(),
            Some(node) => {
                only(node, &["RoutingRule"])?;
                children(node, "RoutingRule").into_iter().map(RoutingRule::parse).collect::<Result<_, _>>()?
            }
        };
        Website { redirect_all_requests_to, index_document, error_document, routing_rules }.check()
    }

    /// Checks a configuration for what S3 doesn't allow in one that's
    /// well-formed.
    pub fn check(self) -> Result<Website, Invalid> {
        if let Some(all) = &self.redirect_all_requests_to {
            if self.index_document.is_some() || self.error_document.is_some() || !self.routing_rules.is_empty() {
                return Err(Invalid::Request(
                    "RedirectAllRequestsTo cannot be provided in conjunction with other Routing Rules.".to_owned(),
                ));
            }
            if all.host_name.trim().is_empty() {
                return Err(Invalid::Argument(
                    "The HostName of RedirectAllRequestsTo can't be empty.".to_owned(),
                    "HostName",
                    all.host_name.clone(),
                ));
            }
            check_host(&all.host_name)?;
            check_protocol(&all.protocol)?;
            return Ok(self);
        }
        let Some(suffix) = &self.index_document else {
            return Err(Invalid::Argument(
                "A value for IndexDocument Suffix must be provided if RedirectAllRequestsTo is empty".to_owned(),
                "IndexDocument",
                String::new(),
            ));
        };
        if suffix.is_empty() || suffix.contains('/') {
            return Err(Invalid::Argument(
                "The IndexDocument Suffix is not well formed".to_owned(),
                "IndexDocument",
                suffix.clone(),
            ));
        }
        if let Some(key) = self.error_document.as_ref().filter(|key| key.is_empty()) {
            return Err(Invalid::Argument(
                "The ErrorDocument Key is not well formed".to_owned(),
                "ErrorDocument",
                key.clone(),
            ));
        }
        if self.routing_rules.len() > MAX_RULES {
            return Err(Invalid::Argument(
                format!("The number of routing rules must not exceed allowed limit of {MAX_RULES} rules."),
                "RoutingRules",
                self.routing_rules.len().to_string(),
            ));
        }
        for rule in &self.routing_rules {
            rule.check()?;
        }
        Ok(self)
    }

    /// As GetBucketWebsite answers.
    pub fn to_xml(&self) -> String {
        let mut out = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <WebsiteConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
        );
        if let Some(all) = &self.redirect_all_requests_to {
            out.push_str("<RedirectAllRequestsTo>");
            element(&mut out, "HostName", Some(&all.host_name));
            element(&mut out, "Protocol", all.protocol.as_ref());
            out.push_str("</RedirectAllRequestsTo>");
        }
        if let Some(suffix) = &self.index_document {
            out.push_str(&format!("<IndexDocument><Suffix>{}</Suffix></IndexDocument>", xml_escape(suffix)));
        }
        if let Some(key) = &self.error_document {
            out.push_str(&format!("<ErrorDocument><Key>{}</Key></ErrorDocument>", xml_escape(key)));
        }
        if !self.routing_rules.is_empty() {
            out.push_str("<RoutingRules>");
            for rule in &self.routing_rules {
                rule.write_xml(&mut out);
            }
            out.push_str("</RoutingRules>");
        }
        out.push_str("</WebsiteConfiguration>");
        out
    }

    /// As it's stored.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a configuration serializes")
    }

    pub fn from_json(json: &str) -> serde_json::Result<Website> {
        serde_json::from_str(json)
    }
}

/// `<name>value</name>`, if there's a value.
fn element(out: &mut String, name: &str, value: Option<&impl std::fmt::Display>) {
    if let Some(value) = value {
        out.push_str(&format!("<{name}>{}</{name}>", xml_escape(&value.to_string())));
    }
}

/// A host redirected to must be one a `Location` can name: no scheme,
/// path, or anything a URL's authority can't hold.
fn check_host(host: &str) -> Result<(), Invalid> {
    let fine = |b: u8| b.is_ascii_alphanumeric() || b".-_:[]".contains(&b);
    match host.bytes().all(fine) {
        true => Ok(()),
        false => Err(Invalid::Argument("The HostName is not well formed".to_owned(), "HostName", host.to_owned())),
    }
}

impl RoutingRule {
    fn parse(node: Node) -> Result<RoutingRule, Invalid> {
        only(node, &["Condition", "Redirect"])?;
        let condition = match child(node, "Condition")? {
            None => None,
            Some(node) => {
                only(node, &["KeyPrefixEquals", "HttpErrorCodeReturnedEquals"])?;
                Some(Condition {
                    key_prefix_equals: text(node, "KeyPrefixEquals")?,
                    http_error_code_returned_equals: code(
                        text(node, "HttpErrorCodeReturnedEquals")?,
                        "HttpErrorCodeReturnedEquals",
                    )?,
                })
            }
        };
        let Some(redirect) = child(node, "Redirect")? else {
            return Err(Invalid::Malformed("a RoutingRule needs a Redirect".to_owned()));
        };
        only(
            redirect,
            &["HostName", "HttpRedirectCode", "Protocol", "ReplaceKeyPrefixWith", "ReplaceKeyWith"],
        )?;
        let redirect = Redirect {
            host_name: text(redirect, "HostName")?,
            http_redirect_code: code(text(redirect, "HttpRedirectCode")?, "HttpRedirectCode")?,
            protocol: text(redirect, "Protocol")?,
            replace_key_prefix_with: text(redirect, "ReplaceKeyPrefixWith")?,
            replace_key_with: text(redirect, "ReplaceKeyWith")?,
        };
        Ok(RoutingRule { condition, redirect })
    }

    fn check(&self) -> Result<(), Invalid> {
        if let Some(condition) = &self.condition {
            if condition.key_prefix_equals.is_none() && condition.http_error_code_returned_equals.is_none() {
                return Err(Invalid::Argument(
                    "Condition cannot be empty. To redirect all requests without a condition, the condition \
                     element shouldn't be present."
                        .to_owned(),
                    "Condition",
                    String::new(),
                ));
            }
            if let Some(code) = condition.http_error_code_returned_equals.filter(|c| !(400..600).contains(c)) {
                return Err(Invalid::Argument(
                    format!("The provided HTTP error code ({code}) is not valid. Valid codes are 4XX or 5XX."),
                    "HttpErrorCodeReturnedEquals",
                    code.to_string(),
                ));
            }
        }
        let redirect = &self.redirect;
        if redirect == &Redirect::default() {
            return Err(Invalid::Argument(
                "Redirect must contain at least one of HostName, HttpRedirectCode, Protocol, ReplaceKeyPrefixWith \
                 or ReplaceKeyWith."
                    .to_owned(),
                "Redirect",
                String::new(),
            ));
        }
        if redirect.replace_key_prefix_with.is_some() && redirect.replace_key_with.is_some() {
            return Err(Invalid::Argument(
                "You can only define ReplaceKeyPrefix or ReplaceKey but not both.".to_owned(),
                "ReplaceKeyPrefixWith",
                redirect.replace_key_prefix_with.clone().unwrap_or_default(),
            ));
        }
        if let Some(code) = redirect.http_redirect_code.filter(|c| !(301..400).contains(c)) {
            return Err(Invalid::Argument(
                format!("The provided HTTP redirect code ({code}) is not valid. Valid codes are 3XX except 300."),
                "HttpRedirectCode",
                code.to_string(),
            ));
        }
        if let Some(host) = &redirect.host_name {
            check_host(host)?;
        }
        check_protocol(&redirect.protocol)
    }

    fn write_xml(&self, out: &mut String) {
        out.push_str("<RoutingRule>");
        if let Some(condition) = &self.condition {
            out.push_str("<Condition>");
            element(out, "HttpErrorCodeReturnedEquals", condition.http_error_code_returned_equals.as_ref());
            element(out, "KeyPrefixEquals", condition.key_prefix_equals.as_ref());
            out.push_str("</Condition>");
        }
        let redirect = &self.redirect;
        out.push_str("<Redirect>");
        element(out, "HostName", redirect.host_name.as_ref());
        element(out, "HttpRedirectCode", redirect.http_redirect_code.as_ref());
        element(out, "Protocol", redirect.protocol.as_ref());
        element(out, "ReplaceKeyPrefixWith", redirect.replace_key_prefix_with.as_ref());
        element(out, "ReplaceKeyWith", redirect.replace_key_with.as_ref());
        out.push_str("</Redirect></RoutingRule>");
    }
}

/// The bucket's website configuration: `None` if there's no such bucket,
/// `Some(None)` if it has none.
pub async fn load(app: &App, bucket: &str) -> anyhow::Result<Option<Option<Website>>> {
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached("SELECT website FROM buckets WHERE name = $1", &[&bucket])
        .await?;
    let Some(row) = row else { return Ok(None) };
    let Some(json) = row.get::<_, Option<String>>(0) else { return Ok(Some(None)) };
    let config = Website::from_json(&json)
        .map_err(|e| anyhow::anyhow!("bucket {bucket}'s website configuration doesn't parse: {e}"))?;
    Ok(Some(Some(config)))
}

/// S3's 404 for a bucket without a website configuration.
pub fn no_such_website_configuration() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::NOT_FOUND,
        "NoSuchWebsiteConfiguration",
        "The specified bucket does not have a website configuration",
    )
}

/// GetBucketWebsite: `GET /{bucket}?website`. A bucket without a
/// configuration answers 404 NoSuchWebsiteConfiguration, as in S3.
pub async fn get_bucket_website(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    Ok(match load(app, bucket).await? {
        None => no_such_bucket(),
        Some(None) => no_such_website_configuration(),
        Some(Some(config)) => xml_ok(config.to_xml()),
    })
}

/// PutBucketWebsite: `PUT /{bucket}?website` with a `<WebsiteConfiguration>`
/// body, checked against its integrity headers (see `Payload`), of which S3
/// requires one. Replaces the bucket's configuration.
pub async fn put_bucket_website(app: &App, bucket: &str, body: Bytes) -> anyhow::Result<Response<Full<Bytes>>> {
    if body.len() > MAX_DOCUMENT {
        return Ok(format_s3_error(
            StatusCode::BAD_REQUEST,
            "MaxMessageLengthExceeded",
            "Your request was too big.",
        ));
    }
    let parsed = std::str::from_utf8(&body).map_err(|_| Invalid::Malformed("not UTF-8".to_owned())).and_then(Website::parse);
    let config = match parsed {
        Ok(config) => config,
        Err(invalid) => return Ok(invalid.response()),
    };
    Ok(match set(app, bucket, Some(&config.to_json())).await? {
        true => Response::builder().status(StatusCode::OK).body(Full::new(Bytes::new())).unwrap(),
        false => no_such_bucket(),
    })
}

/// DeleteBucketWebsite: `DELETE /{bucket}?website`. The bucket's website
/// endpoint serves nothing from then on. A 204 whether it had one or not,
/// as in S3.
pub async fn delete_bucket_website(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    Ok(match set(app, bucket, None).await? {
        true => Response::builder().status(StatusCode::NO_CONTENT).body(Full::new(Bytes::new())).unwrap(),
        false => no_such_bucket(),
    })
}

/// Sets the bucket's configuration (`cairn_set_website`). Whether it exists.
async fn set(app: &App, bucket: &str, config: Option<&str>) -> anyhow::Result<bool> {
    Ok(app
        .pool
        .get()
        .await?
        .query_one_cached("SELECT pg_temp.cairn_set_website($1, $2)", &[&bucket, &config])
        .await?
        .get(0))
}

fn no_such_bucket() -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::NOT_FOUND, "NoSuchBucket", "the specified bucket does not exist")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(inner: &str) -> Result<Website, Invalid> {
        Website::parse(&format!(
            "<WebsiteConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{inner}</WebsiteConfiguration>"
        ))
    }

    const INDEX: &str = "<IndexDocument><Suffix>index.html</Suffix></IndexDocument>";

    fn rule(condition: &str, redirect: &str) -> String {
        let condition = match condition {
            "" => String::new(),
            condition => format!("<Condition>{condition}</Condition>"),
        };
        format!("{INDEX}<RoutingRules><RoutingRule>{condition}<Redirect>{redirect}</Redirect></RoutingRule></RoutingRules>")
    }

    /// The InvalidArgument `inner` is refused with: its argument's name.
    fn argument(inner: &str) -> &'static str {
        match config(inner) {
            Err(Invalid::Argument(_, name, _)) => name,
            other => panic!("{inner}: {other:?}"),
        }
    }

    #[test]
    fn reads_back_as_it_was_set() {
        let inner = "<IndexDocument><Suffix>index.html</Suffix></IndexDocument>\
                     <ErrorDocument><Key>errors/404.html</Key></ErrorDocument>\
                     <RoutingRules><RoutingRule><Condition><KeyPrefixEquals>docs/</KeyPrefixEquals></Condition>\
                     <Redirect><ReplaceKeyPrefixWith>documents/</ReplaceKeyPrefixWith></Redirect></RoutingRule>\
                     <RoutingRule><Condition><HttpErrorCodeReturnedEquals>404</HttpErrorCodeReturnedEquals>\
                     <KeyPrefixEquals>a &amp; b</KeyPrefixEquals></Condition>\
                     <Redirect><HostName>example.com</HostName><HttpRedirectCode>302</HttpRedirectCode>\
                     <Protocol>https</Protocol><ReplaceKeyWith>missing.html</ReplaceKeyWith></Redirect></RoutingRule>\
                     </RoutingRules>";
        let parsed = config(inner).unwrap();
        assert_eq!(parsed.routing_rules[1].condition.as_ref().unwrap().key_prefix_equals.as_deref(), Some("a & b"));
        assert_eq!(
            parsed.to_xml(),
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                 <WebsiteConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{inner}</WebsiteConfiguration>"
            )
        );
        assert_eq!(Website::from_json(&parsed.to_json()).unwrap(), parsed);

        let all = "<RedirectAllRequestsTo><HostName>www.example.com</HostName><Protocol>https</Protocol>\
                   </RedirectAllRequestsTo>";
        let parsed = config(all).unwrap();
        assert!(parsed.to_xml().contains(all));
        assert_eq!(Website::from_json(&parsed.to_json()).unwrap(), parsed);
    }

    #[test]
    fn refuses_what_s3_refuses() {
        let malformed = |inner: &str| matches!(config(inner), Err(Invalid::Malformed(_)));
        assert!(matches!(Website::parse("<Other/>"), Err(Invalid::Malformed(_))));
        assert!(malformed("<IndexDocument/>"));
        assert!(malformed(&format!("{INDEX}<Unknown/>")));
        assert!(malformed(&format!("{INDEX}{INDEX}")));
        assert!(malformed("<RedirectAllRequestsTo><Protocol>http</Protocol></RedirectAllRequestsTo>"));
        assert!(malformed(&format!("{INDEX}<RoutingRules><RoutingRule/></RoutingRules>")));
        assert!(malformed(&format!("{INDEX}<ErrorDocument/>")));

        // An index document, unless every request is redirected.
        assert_eq!(argument(""), "IndexDocument");
        assert_eq!(argument("<ErrorDocument><Key>e.html</Key></ErrorDocument>"), "IndexDocument");
        assert_eq!(argument("<IndexDocument><Suffix></Suffix></IndexDocument>"), "IndexDocument");
        assert_eq!(argument("<IndexDocument><Suffix>a/index.html</Suffix></IndexDocument>"), "IndexDocument");
        assert!(matches!(
            config(&format!("{INDEX}<RedirectAllRequestsTo><HostName>h</HostName></RedirectAllRequestsTo>")),
            Err(Invalid::Request(_))
        ));
        assert_eq!(
            argument("<RedirectAllRequestsTo><HostName>h</HostName><Protocol>ftp</Protocol></RedirectAllRequestsTo>"),
            "Protocol"
        );
        assert_eq!(argument("<RedirectAllRequestsTo><HostName>a/b</HostName></RedirectAllRequestsTo>"), "HostName");

        assert_eq!(argument(&rule("", "")), "Redirect");
        assert_eq!(argument(&rule("", "<HttpRedirectCode>300</HttpRedirectCode>")), "HttpRedirectCode");
        assert_eq!(argument(&rule("", "<HttpRedirectCode>200</HttpRedirectCode>")), "HttpRedirectCode");
        assert_eq!(argument(&rule("", "<HttpRedirectCode>soon</HttpRedirectCode>")), "HttpRedirectCode");
        assert_eq!(argument(&rule("", "<Protocol>gopher</Protocol>")), "Protocol");
        assert_eq!(
            argument(&rule("", "<ReplaceKeyPrefixWith>a</ReplaceKeyPrefixWith><ReplaceKeyWith>b</ReplaceKeyWith>")),
            "ReplaceKeyPrefixWith"
        );
        assert_eq!(argument(&rule("<KeyPrefixEquals>a</KeyPrefixEquals>", "")), "Redirect");
        assert_eq!(
            argument(&rule("<HttpErrorCodeReturnedEquals>302</HttpErrorCodeReturnedEquals>", "<Protocol>https</Protocol>")),
            "HttpErrorCodeReturnedEquals"
        );
        // An empty condition: leave it out instead.
        assert_eq!(argument(&rule("<KeyPrefixEquals>a</KeyPrefixEquals>", "")), "Redirect");
        assert!(config(&format!(
            "{INDEX}<RoutingRules><RoutingRule><Condition/><Redirect><Protocol>https</Protocol></Redirect>\
             </RoutingRule></RoutingRules>"
        ))
        .is_err_and(|e| matches!(e, Invalid::Argument(_, "Condition", _))));
        // An empty prefix to replace with is one: it strips the condition's.
        assert!(config(&rule("<KeyPrefixEquals>old/</KeyPrefixEquals>", "<ReplaceKeyPrefixWith></ReplaceKeyPrefixWith>")).is_ok());

        let rules = |n| {
            let one = "<RoutingRule><Redirect><Protocol>https</Protocol></Redirect></RoutingRule>";
            format!("{INDEX}<RoutingRules>{}</RoutingRules>", one.repeat(n))
        };
        assert!(config(&rules(MAX_RULES)).is_ok());
        assert_eq!(argument(&rules(MAX_RULES + 1)), "RoutingRules");
    }
}
