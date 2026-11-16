//! SNS, on the S3 port, for S3's event notifications (see `notifications`,
//! and `plans/notifications.md`): requests signed for the `sns` service are
//! these, whatever their path, as IAM's are (see `iam`). Topics, with
//! policies, delivery policies and tags; subscriptions over HTTP(S) only,
//! confirmed as SNS confirms them (a token sent to the endpoint, which a
//! GET of its `SubscribeURL`, or ConfirmSubscription, gives back); Publish.
//! As SNS answers (probed): its query protocol, its errors.
//!
//! A request acts as its signer: each action is checked as SNS's own
//! (`sns:CreateTopic` on the topic's ARN, ...), by the signer's policies and
//! the topic's (its resource policy, as a bucket's is). A topic's default
//! policy is SNS's, whose condition (`AWS:SourceOwner`) no request to Cairn
//! carries: so it allows nothing, and what a user may do with topics is up
//! to its own policies, and what a topic's policy says beyond the default.
//!
//! Unsigned: a confirmation's `SubscribeURL`, an `UnsubscribeURL`, and the
//! signing certificates (see `notifications::signing`).

mod subscriptions;
mod topics;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode, body::Bytes};
use uuid::Uuid;

use crate::{
    App,
    auth::Signed,
    notifications::delivery_policy::TopicPolicy,
    policy::{Context, Kind, Policy, Verdict},
    s3::{
        access::{Access, Origin},
        actions::{Check, On},
        util::{decode_path_param, xml_escape},
    },
    users::{self, Principal},
};

/// SNS's XML namespace.
pub const XMLNS: &str = "http://sns.amazonaws.com/doc/2010-03-31/";

/// The most a request's body may hold: a message (at most 256 KiB), encoded.
const MAX_BODY: usize = 1 << 20;

/// A topic's ARN, in Cairn's region.
pub fn topic_arn(account: &str, name: &str) -> String {
    format!("arn:aws:sns:{}:{account}:{name}", crate::s3::buckets::head::REGION)
}

/// A subscription's ARN: its topic's, and its ID.
pub fn subscription_arn(topic_arn: &str, id: Uuid) -> String {
    format!("{topic_arn}:{id}")
}

/// A topic's account and name, from its ARN, if it's one of Cairn's region.
pub fn parse_topic_arn(arn: &str) -> Option<(String, String)> {
    let (region, account, name) = crate::notifications::config::parse_topic_arn(arn)?;
    (region == crate::s3::buckets::head::REGION && !name.contains(':')).then(|| (account.to_owned(), name.to_owned()))
}

/// A topic.
#[derive(Clone, Debug)]
pub struct Topic {
    pub id: Uuid,
    pub account: String,
    pub name: String,
    pub display_name: String,
    /// Its policy, normalized.
    pub policy: String,
    /// The users and roles its policy names, by their ARNs (as bucket
    /// policies keep them).
    pub policy_principals: Option<String>,
    pub delivery_policy: Option<String>,
    pub signature_version: i16,
    pub tags: Vec<(String, String)>,
}

impl Topic {
    pub fn arn(&self) -> String {
        topic_arn(&self.account, &self.name)
    }

    pub fn delivery_policy(&self) -> Option<TopicPolicy> {
        self.delivery_policy.as_deref().and_then(|p| TopicPolicy::parse(p).ok().flatten())
    }

    /// Its policy, parsed.
    pub fn parsed_policy(&self) -> anyhow::Result<Arc<Policy>> {
        let arn = self.arn();
        crate::s3::access::parsed(&self.policy, Kind::Topic(&arn), Some(self.policy_principals.as_deref().unwrap_or("{}")))
    }

    const COLUMNS: &str =
        "id, account_id, name, display_name, policy, policy_principals::text, delivery_policy, signature_version, tags::text";

    fn from_row(row: &tokio_postgres::Row) -> anyhow::Result<Topic> {
        Ok(Topic {
            id: row.get(0),
            account: row.get(1),
            name: row.get(2),
            display_name: row.get(3),
            policy: row.get(4),
            policy_principals: row.get(5),
            delivery_policy: row.get(6),
            signature_version: row.get(7),
            tags: serde_json::from_str(row.get::<_, &str>(8))?,
        })
    }

    /// `account`'s topic `name`, if there's one.
    pub async fn load(client: &impl deadpool_postgres::GenericClient, account: &str, name: &str) -> anyhow::Result<Option<Topic>> {
        let sql = format!("SELECT {} FROM sns_topics WHERE account_id = $1 AND name = $2", Self::COLUMNS);
        client.query_opt(&sql, &[&account, &name]).await?.map(|r| Topic::from_row(&r)).transpose()
    }

    /// The topic with ID `id`, if it's there.
    pub async fn by_id(client: &impl deadpool_postgres::GenericClient, id: Uuid) -> anyhow::Result<Option<Topic>> {
        let sql = format!("SELECT {} FROM sns_topics WHERE id = $1", Self::COLUMNS);
        client.query_opt(&sql, &[&id]).await?.map(|r| Topic::from_row(&r)).transpose()
    }
}

/// The service S3 publishes as.
pub const S3_SERVICE: &str = "s3.amazonaws.com";

/// Whether `topic`'s policy lets S3 publish bucket `bucket`'s events (of
/// `owner`'s), as S3 checks before it takes a configuration, and Cairn
/// before each event: as the service, with the bucket as its source.
pub fn s3_may_publish(topic: &Topic, bucket: &str, owner: &str) -> anyhow::Result<bool> {
    let policy = topic.parsed_policy()?;
    let mut context = Context::default();
    context.set("aws:SourceArn", format!("arn:aws:s3:::{bucket}"));
    context.set("aws:SourceAccount", owner);
    context.set("aws:PrincipalIsAWSService", "true");
    context.set("aws:SecureTransport", "true");
    context.set("aws:ResourceAccount", topic.account.clone());
    let arn = topic.arn();
    let request = crate::policy::Request {
        principal: crate::policy::Principal::Service { name: S3_SERVICE },
        action: "sns:Publish",
        resource: &arn,
        context: &context,
    };
    Ok(policy.evaluate(&request) == crate::policy::Decision::Allow)
}

/// SNS's default policy for a new topic (probed).
pub fn default_policy(account: &str, arn: &str) -> String {
    format!(
        "{{\"Version\":\"2008-10-17\",\"Id\":\"__default_policy_ID\",\"Statement\":[{{\"Sid\":\"__default_statement_ID\",\
         \"Effect\":\"Allow\",\"Principal\":{{\"AWS\":\"*\"}},\"Action\":[\"SNS:GetTopicAttributes\",\"SNS:SetTopicAttributes\",\
         \"SNS:AddPermission\",\"SNS:RemovePermission\",\"SNS:DeleteTopic\",\"SNS:Subscribe\",\"SNS:ListSubscriptionsByTopic\",\
         \"SNS:Publish\"],\"Resource\":\"{arn}\",\"Condition\":{{\"StringEquals\":{{\"AWS:SourceOwner\":\"{account}\"}}}}}}]}}"
    )
}

/// Whether a request signed so is SNS's.
pub fn wants(signed: &Signed) -> bool {
    signed.service == "sns"
}

/// A failed request: its status, code and message.
pub struct Error {
    pub(crate) status: StatusCode,
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

fn error(status: StatusCode, code: &'static str, message: impl Into<String>) -> Error {
    Error { status, code, message: message.into() }
}

/// SNS's 400 for what a request gives: "Invalid parameter: …".
fn invalid(message: impl AsRef<str>) -> Error {
    error(StatusCode::BAD_REQUEST, "InvalidParameter", format!("Invalid parameter: {}", message.as_ref()))
}

fn not_found(message: &str) -> Error {
    error(StatusCode::NOT_FOUND, "NotFound", message)
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Error {
        eprintln!("sns: request failed: {e:#}");
        error(StatusCode::INTERNAL_SERVER_ERROR, "InternalError", "internal error; the node's log has the details")
    }
}

impl From<tokio_postgres::Error> for Error {
    fn from(e: tokio_postgres::Error) -> Error {
        anyhow::Error::from(e).into()
    }
}

impl From<deadpool_postgres::PoolError> for Error {
    fn from(e: deadpool_postgres::PoolError) -> Error {
        anyhow::Error::from(e).into()
    }
}

type Result<T> = std::result::Result<T, Error>;

/// A request's parameters, form-decoded.
pub(crate) struct Params(pub(crate) HashMap<String, String>);

impl Params {
    fn parse(text: &str, into: &mut HashMap<String, String>) -> Result<()> {
        for pair in text.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let decode = |s: &str| decode_path_param(&s.replace('+', " "));
            let name = decode(k);
            if into.contains_key(&name) {
                return Err(error(StatusCode::BAD_REQUEST, "MalformedQueryString", format!("the parameter {name} is given more than once")));
            }
            into.insert(name, decode(v));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn of(pairs: &[(&str, &str)]) -> Params {
        Params(pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect())
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    /// A parameter SNS requires: missing, it's SNS's 400.
    fn required(&self, name: &str) -> Result<&str> {
        self.get(name).ok_or_else(|| invalid(format!("{name} Reason: No value was provided for {name}")))
    }

    /// A map's entries (`<name>.entry.N.key` and `.value`), in order.
    fn entries(&self, name: &str) -> Vec<(String, String)> {
        (1..)
            .map_while(|n| {
                let key = self.get(&format!("{name}.entry.{n}.key"))?;
                Some((key.to_owned(), self.get(&format!("{name}.entry.{n}.value")).unwrap_or("").to_owned()))
            })
            .collect()
    }

    /// A list's members (`<name>.member.N`).
    fn members(&self, name: &str) -> Vec<String> {
        (1..).map_while(|n| self.get(&format!("{name}.member.{n}")).map(str::to_owned)).collect()
    }

    /// Tags (`Tags.member.N.Key` and `.Value`).
    fn tags(&self) -> Vec<(String, String)> {
        (1..)
            .map_while(|n| {
                let key = self.get(&format!("Tags.member.{n}.Key"))?;
                Some((key.to_owned(), self.get(&format!("Tags.member.{n}.Value")).unwrap_or("").to_owned()))
            })
            .collect()
    }
}

/// A request's answer, as SNS writes it: its action's name, and its
/// result's elements (none for an action that has no result).
type Answer = (String, Option<String>);

/// SNS's answer.
fn answer(request_id: &str, result: Result<Answer>) -> Response<Full<Bytes>> {
    let (status, body) = match result {
        Ok((action, inner)) => {
            let result = inner.map(|inner| format!("<{action}Result>{inner}</{action}Result>")).unwrap_or_default();
            (
                StatusCode::OK,
                format!(
                    "<{action}Response xmlns=\"{XMLNS}\">{result}<ResponseMetadata><RequestId>{request_id}</RequestId>\
                     </ResponseMetadata></{action}Response>"
                ),
            )
        }
        Err(e) => {
            let kind = if e.status.is_server_error() { "Receiver" } else { "Sender" };
            (
                e.status,
                format!(
                    "<ErrorResponse xmlns=\"{XMLNS}\"><Error><Type>{kind}</Type><Code>{}</Code><Message>{}</Message>\
                     </Error><RequestId>{request_id}</RequestId></ErrorResponse>",
                    e.code,
                    xml_escape(&e.message)
                ),
            )
        }
    };
    Response::builder()
        .status(status)
        .header("content-type", "text/xml")
        .header("x-amzn-requestid", request_id)
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// An SNS request, on the S3 port.
pub async fn handle(app: &Arc<App>, req: Request<crate::listen::ClientBody>, signed: Signed, peer: IpAddr) -> Response<Full<Bytes>> {
    let request_id = Uuid::new_v4().to_string();
    let result = respond(app, req, &signed, peer).await;
    answer(&request_id, result)
}

/// The URL clients reach this endpoint at, as a request to it says: its
/// scheme and `Host` (see `objects::post::object_location`).
fn base_url(headers: &hyper::HeaderMap) -> String {
    let host = headers.get(hyper::header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("localhost");
    let scheme = if crate::s3::sse_c::secure(headers, false) { "https" } else { "http" };
    format!("{scheme}://{host}")
}

async fn respond(app: &Arc<App>, req: Request<crate::listen::ClientBody>, signed: &Signed, peer: IpAddr) -> Result<Answer> {
    let (parts, body) = req.into_parts();
    let body = Limited::new(body, MAX_BODY)
        .collect()
        .await
        .map_err(|_| error(StatusCode::BAD_REQUEST, "MalformedQueryString", "the request's body is too large, or broken"))?
        .to_bytes();
    let query = parts.uri.query().unwrap_or("");
    let mut params = HashMap::new();
    Params::parse(query, &mut params)?;
    if !body.is_empty() {
        let text = std::str::from_utf8(&body).map_err(|_| error(StatusCode::BAD_REQUEST, "MalformedQueryString", "the request's body isn't UTF-8"))?;
        Params::parse(text, &mut params)?;
    }
    let params = Params(params);
    let action = params
        .get("Action")
        .ok_or_else(|| error(StatusCode::BAD_REQUEST, "MissingAction", "Missing Action"))?
        .to_owned();
    let client = app.pool.get().await?;
    let principal = match Principal::authenticate(&client, &app.sessions, &signed.access_key, signed.token.as_deref()).await? {
        Ok(principal) => principal,
        Err(users::Unknown::Expired) => {
            return Err(error(StatusCode::FORBIDDEN, "ExpiredToken", "The security token included in the request is expired"));
        }
        Err(_) => {
            return Err(error(StatusCode::FORBIDDEN, "InvalidClientTokenId", "The security token included in the request is invalid."));
        }
    };
    crate::auth::verify_sigv4_with_body(parts.method.as_str(), parts.uri.path(), query, &parts.headers, &principal.secret, &body)
        .map_err(|r| error(r.status, if r.code == "SignatureDoesNotMatch" { "SignatureDoesNotMatch" } else { "AuthorizationError" }, r.message))?;
    let origin = Origin { peer: Some(peer), trusted_proxies: &app.trusted_proxies, signed: Some(signed), form: false };
    let mut access = Access::new(Some(&principal), &principal.account, &parts.method, &parts.headers, "", &origin)?;
    let base = base_url(&parts.headers);
    let mut sns = Sns { app, client: &client, principal: &principal, access: &mut access, base_url: base };
    let inner = sns.dispatch(&action, &params).await?;
    Ok((action, inner))
}

/// A request's actions, as its signer.
pub(crate) struct Sns<'a> {
    pub(crate) app: &'a Arc<App>,
    pub(crate) client: &'a deadpool_postgres::Object,
    pub(crate) principal: &'a Principal,
    pub(crate) access: &'a mut Access,
    /// Where clients reach this endpoint (see `base_url`).
    pub(crate) base_url: String,
}

/// SNS's actions Cairn doesn't have (botocore's model, 2010-03-31).
const OTHER_ACTIONS: &[&str] = &[
    "CheckIfPhoneNumberIsOptedOut",
    "CreatePlatformApplication",
    "CreatePlatformEndpoint",
    "CreateSMSSandboxPhoneNumber",
    "DeleteEndpoint",
    "DeletePlatformApplication",
    "DeleteSMSSandboxPhoneNumber",
    "GetDataProtectionPolicy",
    "GetEndpointAttributes",
    "GetPlatformApplicationAttributes",
    "GetSMSAttributes",
    "GetSMSSandboxAccountStatus",
    "ListEndpointsByPlatformApplication",
    "ListOriginationNumbers",
    "ListPhoneNumbersOptedOut",
    "ListPlatformApplications",
    "ListSMSSandboxPhoneNumbers",
    "OptInPhoneNumber",
    "PublishBatch",
    "PutDataProtectionPolicy",
    "SetEndpointAttributes",
    "SetPlatformApplicationAttributes",
    "SetSMSAttributes",
    "VerifySMSSandboxPhoneNumber",
];

impl Sns<'_> {
    pub(crate) async fn dispatch(&mut self, action: &str, params: &Params) -> Result<Option<String>> {
        match action {
            "CreateTopic" => self.create_topic(params).await,
            "DeleteTopic" => self.delete_topic(params).await,
            "ListTopics" => self.list_topics(params).await,
            "GetTopicAttributes" => self.get_topic_attributes(params).await,
            "SetTopicAttributes" => self.set_topic_attributes(params).await,
            "AddPermission" => self.add_permission(params).await,
            "RemovePermission" => self.remove_permission(params).await,
            "TagResource" => self.tag_resource(params).await,
            "UntagResource" => self.untag_resource(params).await,
            "ListTagsForResource" => self.list_tags_for_resource(params).await,
            "Subscribe" => self.subscribe(params).await,
            "ConfirmSubscription" => self.confirm_subscription(params).await,
            "Unsubscribe" => self.unsubscribe(params).await,
            "ListSubscriptions" => self.list_subscriptions(params, None).await,
            "ListSubscriptionsByTopic" => {
                let topic = self.topic(params.required("TopicArn")?).await?;
                self.list_subscriptions(params, Some(topic)).await
            }
            "GetSubscriptionAttributes" => self.get_subscription_attributes(params).await,
            "SetSubscriptionAttributes" => self.set_subscription_attributes(params).await,
            "Publish" => self.publish(params).await,
            other if OTHER_ACTIONS.contains(&other) => Err(error(
                StatusCode::BAD_REQUEST,
                "InvalidAction",
                format!("Cairn's SNS has topics, HTTP(S) subscriptions and Publish; not {other}"),
            )),
            other => Err(error(StatusCode::BAD_REQUEST, "InvalidAction", format!("Could not find operation {other} for version 2010-03-31"))),
        }
    }

    fn account(&self) -> &str {
        &self.principal.account
    }

    /// Refuses the request unless `action` (`sns:…`) on `on` is allowed, by
    /// the signer's policies and (for a topic) the topic's, with the
    /// condition keys `extra` too, as SNS refuses it (probed).
    async fn check(&mut self, action: &'static str, on: On, topic: Option<&Topic>, extra: &Context) -> Result<()> {
        if let Some(topic) = topic {
            self.access.set_topic_policy(&topic.arn(), topic.parsed_policy()?);
        }
        let check = Check { action, on };
        let verdict = self.access.verdict_with(&check, extra);
        if verdict == Verdict::Allow {
            return Ok(());
        }
        // SNS names its actions `SNS:…` in its messages (probed).
        let shown = format!("SNS:{}", &action[4..]);
        Err(error(
            StatusCode::FORBIDDEN,
            "AuthorizationError",
            format!(
                "User: {} is not authorized to perform: {shown} on resource: {} {}",
                self.principal.arn(),
                check.on.arn(),
                verdict.why(&shown, self.access.boundary())
            ),
        ))
    }

    /// The topic `arn` names: SNS's 400 for an ARN that isn't one, its 404
    /// for a topic that isn't there.
    async fn topic(&mut self, arn: &str) -> Result<Topic> {
        let (account, name) = parse_arn(arn, "TopicArn")?;
        if account != self.account() {
            return Err(error(StatusCode::FORBIDDEN, "InvalidClientTokenId", "No account found for the given parameters"));
        }
        Topic::load(self.client, &account, &name).await?.ok_or_else(|| not_found("Topic does not exist"))
    }
}

/// An ARN's account and last part (a topic's name), as SNS checks one a
/// request gives as `param` (probed).
fn parse_arn(arn: &str, param: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = arn.split(':').collect();
    if parts.len() < 6 {
        return Err(invalid(format!("{param} Reason: An ARN must have at least 6 elements, not {}", parts.len())));
    }
    if parts[0] != "arn" || parts[2] != "sns" || parts[4].is_empty() || parts[5].is_empty() {
        return Err(invalid(format!("{param} Reason: {arn} does not start with arn:aws:sns")));
    }
    if parts[3] != crate::s3::buckets::head::REGION {
        return Err(not_found("Topic does not exist"));
    }
    Ok((parts[4].to_owned(), parts[5].to_owned()))
}

/// Attributes as SNS writes them.
fn attributes_xml(attributes: &[(&str, String)]) -> String {
    let entries: String = attributes
        .iter()
        .map(|(k, v)| format!("<entry><key>{}</key><value>{}</value></entry>", xml_escape(k), xml_escape(v)))
        .collect();
    format!("<Attributes>{entries}</Attributes>")
}

/// Whether an unsigned request is SNS's: a GET of `/` confirming or ending
/// a subscription (a message's `SubscribeURL`, `UnsubscribeURL`), or of a
/// signing certificate.
pub fn wants_unsigned<B>(req: &Request<B>) -> bool {
    if *req.method() != hyper::Method::GET {
        return false;
    }
    let path = req.uri().path();
    if crate::notifications::signing::certificate_id(path).is_some() {
        return true;
    }
    let query = req.uri().query().unwrap_or("");
    path == "/" && query.split('&').any(|p| p == "Action=ConfirmSubscription" || p == "Action=Unsubscribe")
}

/// An unsigned SNS request (see `wants_unsigned`).
pub async fn handle_unsigned(app: &Arc<App>, uri: &hyper::Uri, headers: &hyper::HeaderMap) -> Response<Full<Bytes>> {
    let request_id = Uuid::new_v4().to_string();
    if let Some(id) = crate::notifications::signing::certificate_id(uri.path()) {
        let found = async { crate::notifications::signing::certificate(&app.pool.get().await?, id).await }.await;
        return match found {
            Ok(Some(pem)) => Response::builder()
                .header("content-type", "application/x-x509-ca-cert")
                .body(Full::new(Bytes::from(pem)))
                .unwrap(),
            Ok(None) => Response::builder().status(StatusCode::NOT_FOUND).body(Full::new(Bytes::new())).unwrap(),
            Err(e) => {
                eprintln!("sns: reading a certificate failed: {e:#}");
                Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Full::new(Bytes::new())).unwrap()
            }
        };
    }
    let mut params = HashMap::new();
    let result = match Params::parse(uri.query().unwrap_or(""), &mut params) {
        Ok(()) => {
            let params = Params(params);
            let base = base_url(headers);
            match params.get("Action") {
                Some("ConfirmSubscription") => subscriptions::confirm_unsigned(app, &params).await.map(|r| ("ConfirmSubscription".to_owned(), r)),
                _ => subscriptions::unsubscribe_unsigned(app, &params, &base).await.map(|r| ("Unsubscribe".to_owned(), r)),
            }
        }
        Err(e) => Err(e),
    };
    answer(&request_id, result)
}

#[cfg(test)]
mod tests;
