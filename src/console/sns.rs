//! The console's API for SNS's topics, their subscriptions, and buckets'
//! notification configurations (see `sns`, `notifications`). Each call is
//! SNS's own action, run as the session's identity (`Sns::dispatch`), so
//! it's checked and validated exactly as SNS's API checks it; reads take
//! what that answers apart.
//!
//! A subscription made here is confirmed (and ended) through the console's
//! own origin: its messages' `SubscribeURL`s, `UnsubscribeURL`s and
//! certificates are under `/sns/` there (see `unsigned`), as the console
//! doesn't know where clients reach the S3 endpoint.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, Path, Query},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::actor::Actor;
use super::manage::{AppState, Result, Tag, s3_error};
use super::web::{ApiError, ErrorBody};
use crate::{App, s3::actions::On, sns};

pub(super) fn router() -> OpenApiRouter<Arc<App>> {
    OpenApiRouter::new()
        .routes(routes!(list_topics, create_topic))
        .routes(routes!(get_topic, delete_topic))
        .routes(routes!(set_topic_settings))
        .routes(routes!(set_topic_policy))
        .routes(routes!(set_topic_delivery_policy))
        .routes(routes!(set_topic_tags))
        .routes(routes!(subscribe, unsubscribe))
        .routes(routes!(publish))
        .routes(routes!(get_bucket_notifications, put_bucket_notifications))
}

/// Where the console's own SNS URLs are, under its origin.
pub(super) const UNSIGNED_PREFIX: &str = "/sns";

/// Runs SNS's `action`, as `actor`, with `params`: its answer's result (XML).
async fn call(app: &Arc<App>, actor: &Actor, action: &str, params: &[(&str, &str)]) -> Result<String> {
    let client = app.pool.get().await?;
    let mut access = actor.access_for(app).await?;
    let origin = app.console.origin().unwrap_or_default();
    let mut sns = sns::Sns {
        app,
        client: &client,
        principal: actor.principal(),
        access: &mut access,
        base_url: format!("{origin}{UNSIGNED_PREFIX}"),
    };
    let params = sns::Params(params.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<HashMap<_, _>>());
    match sns.dispatch(action, &params).await {
        Ok(xml) => Ok(xml.unwrap_or_default()),
        Err(e) => Err(match e.status {
            StatusCode::NOT_FOUND => ApiError::NotFound(e.message),
            StatusCode::FORBIDDEN => ApiError::Forbidden(e.message),
            s if s.is_client_error() => ApiError::BadRequest(e.message),
            _ => ApiError::Failed(anyhow::anyhow!("SNS's {action} failed: {}", e.message)),
        }),
    }
}

/// The elements named `name` in `xml` (a result's), as their texts.
fn texts(xml: &str, name: &str) -> Vec<String> {
    // A whole document's declaration can't be inside another element.
    let xml = match xml.trim_start().strip_prefix("<?xml") {
        Some(rest) => rest.split_once("?>").map_or("", |(_, body)| body),
        None => xml,
    };
    let doc = format!("<r>{xml}</r>");
    let Ok(doc) = roxmltree::Document::parse(&doc) else { return Vec::new() };
    doc.descendants().filter(|n| n.has_tag_name(name)).map(|n| n.text().unwrap_or("").to_owned()).collect()
}

/// A Get…Attributes answer's attributes.
fn attributes(xml: &str) -> HashMap<String, String> {
    let doc = format!("<r>{xml}</r>");
    let Ok(doc) = roxmltree::Document::parse(&doc) else { return HashMap::new() };
    doc.descendants()
        .filter(|n| n.has_tag_name("entry"))
        .filter_map(|e| {
            let get = |name: &str| e.children().find(|c| c.has_tag_name(name)).map(|c| c.text().unwrap_or("").to_owned());
            Some((get("key")?, get("value").unwrap_or_default()))
        })
        .collect()
}

fn arn(actor: &Actor, name: &str) -> String {
    sns::topic_arn(actor.account(), name)
}

// ─── Topics ──────────────────────────────────────────────────────────────────

/// A topic, as lists show it.
#[derive(Serialize, ToSchema)]
struct TopicSummary {
    name: String,
    arn: String,
    display_name: String,
    subscriptions_confirmed: u32,
    subscriptions_pending: u32,
}

/// The account's topics the session may see (`sns:ListTopics`), with what
/// `sns:GetTopicAttributes` shows of each (nothing, if it may not).
#[utoipa::path(get, path = "/topics", responses(
    (status = 200, body = Vec<TopicSummary>),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn list_topics(State(app): AppState, Extension(actor): Extension<Actor>) -> Result<Json<Vec<TopicSummary>>> {
    let mut arns = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let params: Vec<(&str, &str)> = token.as_deref().map(|t| vec![("NextToken", t)]).unwrap_or_default();
        let xml = call(&app, &actor, "ListTopics", &params).await?;
        arns.extend(texts(&xml, "TopicArn"));
        token = texts(&xml, "NextToken").into_iter().next();
        if token.is_none() {
            break;
        }
    }
    let mut topics = Vec::new();
    for arn in arns {
        let name = arn.rsplit(':').next().unwrap_or("").to_owned();
        let attributes = match call(&app, &actor, "GetTopicAttributes", &[("TopicArn", &arn)]).await {
            Ok(xml) => attributes(&xml),
            Err(ApiError::Forbidden(_)) => HashMap::new(),
            Err(e) => return Err(e),
        };
        let count = |k: &str| attributes.get(k).and_then(|v| v.parse().ok()).unwrap_or(0);
        topics.push(TopicSummary {
            display_name: attributes.get("DisplayName").cloned().unwrap_or_default(),
            subscriptions_confirmed: count("SubscriptionsConfirmed"),
            subscriptions_pending: count("SubscriptionsPending"),
            name,
            arn,
        });
    }
    Ok(Json(topics))
}

#[derive(Deserialize, ToSchema)]
struct NewTopic {
    name: String,
    #[serde(default)]
    display_name: String,
}

/// Makes a topic, as SNS's CreateTopic does.
#[utoipa::path(post, path = "/topics", request_body = NewTopic, responses(
    (status = 201, description = "Made"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_topic(State(app): AppState, Extension(actor): Extension<Actor>, Json(body): Json<NewTopic>) -> Result<StatusCode> {
    let mut params = vec![("Name", body.name.as_str())];
    if !body.display_name.is_empty() {
        params.extend([("Attributes.entry.1.key", "DisplayName"), ("Attributes.entry.1.value", body.display_name.as_str())]);
    }
    call(&app, &actor, "CreateTopic", &params).await?;
    Ok(StatusCode::CREATED)
}

/// A topic's subscription.
#[derive(Serialize, ToSchema)]
struct SubscriptionSummary {
    /// Its ARN, once it's confirmed; else `PendingConfirmation`, or
    /// `Deleted` (which an old token can still restore).
    arn: String,
    protocol: String,
    endpoint: String,
}

/// A topic, and its subscriptions.
#[derive(Serialize, ToSchema)]
struct TopicDetail {
    name: String,
    arn: String,
    display_name: String,
    /// Its policy (JSON).
    policy: String,
    /// Its delivery policy, if it has one of its own (JSON).
    delivery_policy: Option<String>,
    /// What applies: its own, or SNS's defaults (JSON).
    effective_delivery_policy: String,
    /// 1 (SHA1) or 2 (SHA256).
    signature_version: u8,
    tags: Vec<Tag>,
    subscriptions: Vec<SubscriptionSummary>,
}

#[utoipa::path(get, path = "/topics/{name}", params(("name" = String, Path)), responses(
    (status = 200, body = TopicDetail),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn get_topic(State(app): AppState, Extension(actor): Extension<Actor>, Path(name): Path<String>) -> Result<Json<TopicDetail>> {
    let arn = arn(&actor, &name);
    let a = attributes(&call(&app, &actor, "GetTopicAttributes", &[("TopicArn", &arn)]).await?);
    let tags = match call(&app, &actor, "ListTagsForResource", &[("ResourceArn", &arn)]).await {
        Ok(xml) => texts(&xml, "Key").into_iter().zip(texts(&xml, "Value")).map(|(key, value)| Tag { key, value }).collect(),
        Err(ApiError::Forbidden(_)) => Vec::new(),
        Err(e) => return Err(e),
    };
    let mut subscriptions = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let mut params = vec![("TopicArn", arn.as_str())];
        if let Some(t) = &token {
            params.push(("NextToken", t));
        }
        let xml = match call(&app, &actor, "ListSubscriptionsByTopic", &params).await {
            Ok(xml) => xml,
            Err(ApiError::Forbidden(_)) => break,
            Err(e) => return Err(e),
        };
        let (arns, protocols, endpoints) = (texts(&xml, "SubscriptionArn"), texts(&xml, "Protocol"), texts(&xml, "Endpoint"));
        for ((arn, protocol), endpoint) in arns.into_iter().zip(protocols).zip(endpoints) {
            subscriptions.push(SubscriptionSummary { arn, protocol, endpoint });
        }
        token = texts(&xml, "NextToken").into_iter().next();
        if token.is_none() {
            break;
        }
    }
    Ok(Json(TopicDetail {
        display_name: a.get("DisplayName").cloned().unwrap_or_default(),
        policy: a.get("Policy").cloned().unwrap_or_default(),
        delivery_policy: a.get("DeliveryPolicy").cloned(),
        effective_delivery_policy: a.get("EffectiveDeliveryPolicy").cloned().unwrap_or_default(),
        signature_version: a.get("SignatureVersion").and_then(|v| v.parse().ok()).unwrap_or(1),
        name,
        arn,
        tags,
        subscriptions,
    }))
}

/// Deletes a topic, and its subscriptions, as SNS's DeleteTopic does.
/// Buckets' configurations naming it stay, and their events are dropped.
#[utoipa::path(delete, path = "/topics/{name}", params(("name" = String, Path)), responses(
    (status = 204, description = "Deleted"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_topic(State(app): AppState, Extension(actor): Extension<Actor>, Path(name): Path<String>) -> Result<StatusCode> {
    call(&app, &actor, "DeleteTopic", &[("TopicArn", &arn(&actor, &name))]).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct TopicSettings {
    display_name: String,
    /// 1 (SHA1, SNS's default) or 2 (SHA256).
    signature_version: u8,
}

/// Sets a topic's display name and signature version.
#[utoipa::path(put, path = "/topics/{name}/settings", params(("name" = String, Path)), request_body = TopicSettings, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn set_topic_settings(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<TopicSettings>,
) -> Result<StatusCode> {
    let arn = arn(&actor, &name);
    let version = body.signature_version.to_string();
    for (attribute, value) in [("DisplayName", body.display_name.as_str()), ("SignatureVersion", version.as_str())] {
        call(&app, &actor, "SetTopicAttributes", &[("TopicArn", &arn), ("AttributeName", attribute), ("AttributeValue", value)]).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct Document {
    /// JSON; for a delivery policy, empty to remove it.
    document: String,
}

/// Sets a topic's policy, as SetTopicAttributes does.
#[utoipa::path(put, path = "/topics/{name}/policy", params(("name" = String, Path)), request_body = Document, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn set_topic_policy(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<Document>,
) -> Result<StatusCode> {
    let arn = arn(&actor, &name);
    call(&app, &actor, "SetTopicAttributes", &[("TopicArn", &arn), ("AttributeName", "Policy"), ("AttributeValue", &body.document)]).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Sets (or, empty, removes) a topic's delivery policy.
#[utoipa::path(put, path = "/topics/{name}/delivery-policy", params(("name" = String, Path)), request_body = Document, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn set_topic_delivery_policy(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<Document>,
) -> Result<StatusCode> {
    let arn = arn(&actor, &name);
    let params = [("TopicArn", arn.as_str()), ("AttributeName", "DeliveryPolicy"), ("AttributeValue", body.document.as_str())];
    call(&app, &actor, "SetTopicAttributes", &params).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Sets a topic's tags to these: those it has that aren't are removed.
#[utoipa::path(put, path = "/topics/{name}/tags", params(("name" = String, Path)), request_body = Vec<Tag>, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn set_topic_tags(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(tags): Json<Vec<Tag>>,
) -> Result<StatusCode> {
    let arn = arn(&actor, &name);
    let had = texts(&call(&app, &actor, "ListTagsForResource", &[("ResourceArn", &arn)]).await?, "Key");
    let gone: Vec<&String> = had.iter().filter(|k| !tags.iter().any(|t| &t.key == *k)).collect();
    if !gone.is_empty() {
        let names: Vec<String> = (1..=gone.len()).map(|n| format!("TagKeys.member.{n}")).collect();
        let mut params = vec![("ResourceArn", arn.as_str())];
        params.extend(names.iter().map(String::as_str).zip(gone.iter().map(|k| k.as_str())));
        call(&app, &actor, "UntagResource", &params).await?;
    }
    if !tags.is_empty() {
        let names: Vec<(String, String)> =
            (1..=tags.len()).map(|n| (format!("Tags.member.{n}.Key"), format!("Tags.member.{n}.Value"))).collect();
        let mut params = vec![("ResourceArn", arn.as_str())];
        for ((key_name, value_name), tag) in names.iter().zip(&tags) {
            params.push((key_name, &tag.key));
            params.push((value_name, &tag.value));
        }
        call(&app, &actor, "TagResource", &params).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct NewSubscription {
    /// `http` or `https`.
    protocol: String,
    endpoint: String,
}

/// Subscribes an endpoint to a topic: it's sent a confirmation, whose
/// `SubscribeURL` (under the console's origin) confirms it.
#[utoipa::path(post, path = "/topics/{name}/subscriptions", params(("name" = String, Path)), request_body = NewSubscription, responses(
    (status = 201, description = "Pending its confirmation"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn subscribe(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<NewSubscription>,
) -> Result<StatusCode> {
    let arn = arn(&actor, &name);
    let params = [("TopicArn", arn.as_str()), ("Protocol", body.protocol.as_str()), ("Endpoint", body.endpoint.as_str())];
    call(&app, &actor, "Subscribe", &params).await?;
    Ok(StatusCode::CREATED)
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct SubscriptionParams {
    /// The subscription's ARN.
    arn: String,
}

/// Unsubscribes a confirmed subscription, as SNS's Unsubscribe does.
#[utoipa::path(delete, path = "/topics/{name}/subscriptions", params(("name" = String, Path), SubscriptionParams), responses(
    (status = 204, description = "Unsubscribed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn unsubscribe(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(_name): Path<String>,
    Query(params): Query<SubscriptionParams>,
) -> Result<StatusCode> {
    call(&app, &actor, "Unsubscribe", &[("SubscriptionArn", &params.arn)]).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct NewMessage {
    #[serde(default)]
    subject: String,
    message: String,
}

#[derive(Serialize, ToSchema)]
struct Published {
    message_id: String,
}

/// Publishes a message to a topic's subscriptions (to try them).
#[utoipa::path(post, path = "/topics/{name}/publish", params(("name" = String, Path)), request_body = NewMessage, responses(
    (status = 200, body = Published),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn publish(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<NewMessage>,
) -> Result<Json<Published>> {
    let arn = arn(&actor, &name);
    let mut params = vec![("TopicArn", arn.as_str()), ("Message", body.message.as_str())];
    if !body.subject.is_empty() {
        params.push(("Subject", body.subject.as_str()));
    }
    let xml = call(&app, &actor, "Publish", &params).await?;
    Ok(Json(Published { message_id: texts(&xml, "MessageId").into_iter().next().unwrap_or_default() }))
}

// ─── Buckets' notification configurations ────────────────────────────────────

/// One of a bucket's notification configurations: events (S3's names,
/// `s3:ObjectCreated:*`, ...) of keys with a prefix and suffix, to a topic.
#[derive(Serialize, Deserialize, ToSchema)]
struct NotificationRule {
    /// Empty, for one to be made.
    #[serde(default)]
    id: String,
    topic_arn: String,
    events: Vec<String>,
    #[serde(default)]
    prefix: String,
    #[serde(default)]
    suffix: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
struct BucketNotifications {
    rules: Vec<NotificationRule>,
    /// The events a rule may name, in S3's order (in a response).
    #[serde(default)]
    events: Vec<String>,
}

#[utoipa::path(get, path = "/buckets/{bucket}/notifications", params(("bucket" = String, Path)), responses(
    (status = 200, body = BucketNotifications),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn get_bucket_notifications(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
) -> Result<Json<BucketNotifications>> {
    actor.check(&app, "s3:GetBucketNotification", On::Bucket(bucket.clone())).await?;
    let client = app.pool.get().await?;
    if crate::db::Cached::query_opt_cached(&client, "SELECT 1 FROM buckets WHERE name = $1", &[&bucket]).await?.is_none() {
        return Err(ApiError::NotFound(format!("no bucket named {bucket:?}")));
    }
    let rules = crate::s3::buckets::notification::configured(&client, &bucket)
        .await?
        .into_iter()
        .map(|t| NotificationRule { id: t.id, topic_arn: t.topic_arn, events: t.events, prefix: t.prefix, suffix: t.suffix })
        .collect();
    let events = crate::notifications::config::EVENTS.iter().map(|e| e.to_string()).collect();
    Ok(Json(BucketNotifications { rules, events }))
}

/// Replaces a bucket's notification configurations, as S3's
/// PutBucketNotificationConfiguration does: each topic must let S3 publish
/// the bucket's events; each is sent S3's test event.
#[utoipa::path(put, path = "/buckets/{bucket}/notifications", params(("bucket" = String, Path)), request_body = BucketNotifications, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn put_bucket_notifications(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Json(body): Json<BucketNotifications>,
) -> Result<StatusCode> {
    use crate::s3::util::xml_escape;
    actor.check(&app, "s3:PutBucketNotification", On::Bucket(bucket.clone())).await?;
    let mut xml = String::from("<NotificationConfiguration>");
    for rule in &body.rules {
        xml.push_str("<TopicConfiguration>");
        if !rule.id.is_empty() {
            xml.push_str(&format!("<Id>{}</Id>", xml_escape(&rule.id)));
        }
        xml.push_str(&format!("<Topic>{}</Topic>", xml_escape(&rule.topic_arn)));
        for event in &rule.events {
            xml.push_str(&format!("<Event>{}</Event>", xml_escape(event)));
        }
        if !rule.prefix.is_empty() || !rule.suffix.is_empty() {
            xml.push_str("<Filter><S3Key>");
            for (name, value) in [("prefix", &rule.prefix), ("suffix", &rule.suffix)] {
                if !value.is_empty() {
                    xml.push_str(&format!("<FilterRule><Name>{name}</Name><Value>{}</Value></FilterRule>", xml_escape(value)));
                }
            }
            xml.push_str("</S3Key></Filter>");
        }
        xml.push_str("</TopicConfiguration>");
    }
    xml.push_str("</NotificationConfiguration>");
    let response = crate::s3::buckets::notification::put(&app, &bucket, xml.into()).await?;
    if !response.status().is_success() {
        return Err(notification_error(response).await);
    }
    Ok(StatusCode::NO_CONTENT)
}

/// S3's refusal of a configuration, with what it names (the topics it
/// couldn't validate, and why).
async fn notification_error(response: hyper::Response<http_body_util::Full<hyper::body::Bytes>>) -> ApiError {
    use http_body_util::BodyExt;
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
    let text = String::from_utf8_lossy(&bytes).to_string();
    let details: Vec<String> = (1..=8)
        .filter_map(|n| {
            let name = texts(&text, &format!("ArgumentName{n}")).into_iter().next()?;
            let value = texts(&text, &format!("ArgumentValue{n}")).into_iter().next().unwrap_or_default();
            Some(format!("{name}: {value}"))
        })
        .chain(texts(&text, "ArgumentValue").into_iter().map(|v| format!("({v})")))
        .collect();
    match s3_error(hyper::Response::from_parts(parts, http_body_util::Full::new(bytes))).await {
        ApiError::BadRequest(message) if !details.is_empty() => ApiError::BadRequest(format!("{message}: {}", details.join("; "))),
        e => e,
    }
}

use axum::extract::State;

#[cfg(test)]
mod e2e {
    use serde_json::json;

    use super::super::e2e::{console_of, signed_in};
    use crate::e2e::BUCKET;
    use axum::http::StatusCode;

    /// Topics, a bucket's notification rules and its inventory, as an admin
    /// edits them on the console, checked as SNS and S3 check them; a
    /// subscription made there confirmed at the console's own SNS URL.
    #[tokio::test]
    async fn manages_topics_notifications_and_inventory() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else { return };
        let console = console_of(&app);
        let mut admin = signed_in(&console, "admin", true).await;
        let mut user = signed_in(&console, "nobody", false).await;
        let client = app.pool.get().await.unwrap();
        let account = crate::users::account(&client).await.unwrap();
        let arn = crate::sns::topic_arn(&account, "events");

        assert_eq!(admin.send("POST", "/api/topics", Some(json!({"name": "events"}))).await.0, StatusCode::CREATED);
        assert_eq!(admin.send("POST", "/api/topics", Some(json!({"name": "bad name"}))).await.0, StatusCode::BAD_REQUEST);
        let (_, topics) = admin.send("GET", "/api/topics", None).await;
        assert_eq!(topics[0]["arn"], arn);
        assert_eq!(user.send("GET", "/api/topics", None).await.0, StatusCode::FORBIDDEN);

        // A rule for a topic S3 may not publish to is refused, saying which.
        let rules = json!({"rules": [{"topic_arn": arn, "events": ["s3:ObjectCreated:*"], "prefix": "in/"}]});
        let path = format!("/api/buckets/{BUCKET}/notifications");
        let (status, body) = admin.send("PUT", &path, Some(rules.clone())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let message = body["error"].as_str().unwrap();
        assert!(message.contains("Unable to validate") && message.contains(&arn), "{message}");
        let policy = json!({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"},
            "Action": "SNS:Publish", "Resource": arn, "Condition": {"ArnLike": {"aws:SourceArn": format!("arn:aws:s3:::{BUCKET}")}}}]});
        let policy = json!({"document": policy.to_string()});
        assert_eq!(admin.send("PUT", "/api/topics/events/policy", Some(policy)).await.0, StatusCode::NO_CONTENT);
        assert_eq!(admin.send("PUT", &path, Some(rules)).await.0, StatusCode::NO_CONTENT);
        let (_, stored) = admin.send("GET", &path, None).await;
        assert_eq!(stored["rules"][0]["prefix"], "in/");
        assert_eq!(stored["rules"][0]["id"].as_str().unwrap().len(), 48);
        let bad = json!({"rules": [{"topic_arn": arn, "events": ["s3:Bogus"]}]});
        let (status, body) = admin.send("PUT", &path, Some(bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("not supported"), "{body}");

        // A subscription, confirmed at the console's SubscribeURL.
        let sub = json!({"protocol": "https", "endpoint": "https://example.com/hook"});
        assert_eq!(admin.send("POST", "/api/topics/events/subscriptions", Some(sub)).await.0, StatusCode::CREATED);
        let body: String = client
            .query_one("SELECT body FROM sns_deliveries WHERE message_type = 'SubscriptionConfirmation'", &[])
            .await
            .unwrap()
            .get(0);
        let confirmation: serde_json::Value = serde_json::from_str(&body).unwrap();
        let url = confirmation["SubscribeURL"].as_str().unwrap();
        let at = url.find("/sns/").expect("under the console's /sns");
        let (status, _, answer) = admin.request("GET", &url[at..], None).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&answer));
        let cert = confirmation["SigningCertURL"].as_str().unwrap();
        let (status, _, pem) = admin.request("GET", &cert[cert.find("/sns/").unwrap()..], None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(String::from_utf8_lossy(&pem).starts_with("-----BEGIN CERTIFICATE-----"));
        let (_, topic) = admin.send("GET", "/api/topics/events", None).await;
        assert!(topic["subscriptions"][0]["arn"].as_str().unwrap().starts_with(&arn), "{topic}");
        let (status, published) = admin.send("POST", "/api/topics/events/publish", Some(json!({"message": "hi"}))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(published["message_id"].as_str().unwrap().len(), 36);

        // Inventory.
        let form = json!({"id": "daily", "enabled": true, "destination_bucket": BUCKET, "destination_prefix": "reports",
            "format": "Parquet", "all_versions": false, "frequency": "Daily", "fields": ["Size", "ETag"]});
        let inventory = format!("/api/buckets/{BUCKET}/inventory");
        assert_eq!(admin.send("PUT", &format!("{inventory}/daily"), Some(form)).await.0, StatusCode::NO_CONTENT);
        let (_, listed) = admin.send("GET", &inventory, None).await;
        let c = &listed["inventories"][0]["configuration"];
        assert_eq!((c["id"].as_str(), c["format"].as_str(), c["destination_prefix"].as_str()), (Some("daily"), Some("Parquet"), Some("reports")));
        assert_eq!(c["fields"], json!(["Size", "ETag"]));
        let bad = json!({"id": "x", "enabled": true, "destination_bucket": BUCKET, "format": "TSV", "all_versions": false, "frequency": "Daily"});
        assert!(admin.send("PUT", &format!("{inventory}/x"), Some(bad)).await.0.is_client_error());
        assert_eq!(user.send("GET", &inventory, None).await.0, StatusCode::FORBIDDEN);
        assert_eq!(admin.send("DELETE", &format!("{inventory}/daily"), None).await.0, StatusCode::NO_CONTENT);
        assert_eq!(admin.send("DELETE", "/api/topics/events", None).await.0, StatusCode::NO_CONTENT);
    }
}
