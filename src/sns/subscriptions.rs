//! SNS's subscriptions, over HTTP(S) only, and Publish, as SNS answers them
//! (probed, see `plans/notifications.md`): Subscribe sends a confirmation,
//! with a token, to the endpoint, which confirms the subscription given
//! back (ConfirmSubscription, or a GET of its `SubscribeURL`). Every
//! Subscribe of the endpoint sends a new one, and every token confirms the
//! subscription, even after it's been unsubscribed, which it restores, as
//! long as the token lasts (`TOKEN_LIFE`). A GET of a message's
//! `UnsubscribeURL` unsubscribes it, unless it was confirmed asking for
//! that to be authenticated, and sends an `UnsubscribeConfirmation`, whose
//! `SubscribeURL` restores it; Unsubscribe does neither.

use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hyper::StatusCode;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{Params, Result, Sns, Topic, attributes_xml, error, invalid, not_found, parse_arn, subscription_arn};
use crate::{
    App,
    db::Cached,
    notifications::{
        delivery::{self, Confirmation, Message},
        delivery_policy::{Effective, SubscriptionPolicy},
        signing,
    },
    policy::Context,
    s3::{actions::On, util::xml_escape},
};

/// How long a confirmation's token lasts: SNS's three days.
const TOKEN_LIFE: &str = "3 days";
/// A page of ListSubscriptions.
const PAGE: i64 = 100;
/// The most a message may be, in bytes.
const MAX_MESSAGE: usize = 256 << 10;

/// A subscription's attributes Cairn has nothing of: refused.
const UNSUPPORTED: &[&str] = &["FilterPolicy", "FilterPolicyScope", "RedrivePolicy", "SubscriptionRoleArn", "ReplayPolicy"];

/// A new token, and its hash, as it's kept.
fn token() -> (String, Vec<u8>) {
    let mut bytes = [0u8; 128];
    getrandom::fill(&mut bytes).expect("the OS random number generator failed");
    let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let hash = hash(&token);
    (token, hash)
}

fn hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// A subscription.
struct Subscription {
    id: Uuid,
    topic: Topic,
    protocol: String,
    endpoint: String,
    base_url: String,
    state: String,
    raw: bool,
    delivery_policy: Option<String>,
    principal: String,
    authenticated: bool,
}

impl Subscription {
    fn arn(&self) -> String {
        subscription_arn(&self.topic.arn(), self.id)
    }

    /// As lists show its ARN: `PendingConfirmation` or `Deleted` unless
    /// it's confirmed (probed).
    fn shown_arn(&self) -> String {
        match self.state.as_str() {
            "pending" => "PendingConfirmation".to_owned(),
            "deleted" => "Deleted".to_owned(),
            _ => self.arn(),
        }
    }

    async fn load(client: &impl deadpool_postgres::GenericClient, id: Uuid) -> anyhow::Result<Option<Subscription>> {
        let Some(row) = client
            .query_opt(
                "SELECT id, topic_id, protocol, endpoint, base_url, state, raw, delivery_policy, principal, authenticated
                 FROM sns_subscriptions WHERE id = $1",
                &[&id],
            )
            .await?
        else {
            return Ok(None);
        };
        let Some(topic) = Topic::by_id(client, row.get(1)).await? else { return Ok(None) };
        Ok(Some(Subscription {
            id: row.get(0),
            topic,
            protocol: row.get(2),
            endpoint: row.get(3),
            base_url: row.get(4),
            state: row.get(5),
            raw: row.get(6),
            delivery_policy: row.get(7),
            principal: row.get(8),
            authenticated: row.get(9),
        }))
    }
}

/// The subscription a `SubscriptionArn` names, if it's there: SNS's 400 for
/// one that isn't an ARN.
async fn named(client: &impl deadpool_postgres::GenericClient, arn: &str) -> Result<Option<Subscription>> {
    parse_arn(arn, "SubscriptionArn")?;
    let id = arn.rsplit(':').next().and_then(|id| Uuid::parse_str(id).ok());
    let Some(id) = id else { return Ok(None) };
    let found = Subscription::load(client, id).await?;
    Ok(found.filter(|s| s.arn() == arn))
}

/// The subscription a token confirms (or restores), if it does: confirmed
/// now, authenticated to unsubscribe if `authenticate`. SNS's 400 for a
/// token that isn't one.
async fn confirm(client: &impl deadpool_postgres::GenericClient, token: &str, authenticate: bool) -> Result<Subscription> {
    let row = client
        .query_opt("SELECT subscription_id FROM sns_tokens WHERE hash = $1 AND expires > now()", &[&hash(token)])
        .await?;
    let Some(row) = row else { return Err(invalid("Token")) };
    let id: Uuid = row.get(0);
    client
        .execute(
            "UPDATE sns_subscriptions SET state = 'confirmed', changed_at = now(), authenticated = authenticated OR $2
             WHERE id = $1",
            &[&id, &authenticate],
        )
        .await?;
    Subscription::load(client, id).await?.ok_or_else(|| invalid("Token"))
}

/// A ConfirmSubscription, unsigned: a GET of a confirmation's
/// `SubscribeURL`, whose token is all it needs.
pub(super) async fn confirm_unsigned(app: &Arc<App>, params: &Params) -> Result<Option<String>> {
    let client = app.pool.get().await?;
    let token = params.required("Token")?;
    params.get("TopicArn").map(|arn| parse_arn(arn, "TopicArn")).transpose()?;
    let authenticate = params.get("AuthenticateOnUnsubscribe").is_some_and(|v| v.eq_ignore_ascii_case("true"));
    let subscription = confirm(&client, token, authenticate).await?;
    Ok(Some(format!("<SubscriptionArn>{}</SubscriptionArn>", xml_escape(&subscription.arn()))))
}

/// An Unsubscribe, unsigned: a GET of a message's `UnsubscribeURL`. It
/// sends an `UnsubscribeConfirmation`, whose token restores the
/// subscription.
pub(super) async fn unsubscribe_unsigned(app: &Arc<App>, params: &Params, _base: &str) -> Result<Option<String>> {
    let client = app.pool.get().await?;
    let arn = params.required("SubscriptionArn")?;
    let Some(subscription) = named(&client, arn).await? else { return Err(not_found("Subscription does not exist")) };
    if subscription.authenticated {
        return Err(error(StatusCode::FORBIDDEN, "AuthorizationError", "This subscription may only be deleted by an authorized user."));
    }
    if subscription.state == "confirmed" {
        client
            .execute_cached(
                "UPDATE sns_subscriptions SET state = 'deleted', changed_at = now() WHERE id = $1",
                &[&subscription.id],
            )
            .await?;
        let key = signing::current(&client, false).await?;
        let (token, hash) = token();
        client
            .execute_cached(
                &format!("INSERT INTO sns_tokens (hash, subscription_id, expires) VALUES ($1, $2, now() + interval '{TOKEN_LIFE}')"),
                &[&hash, &subscription.id],
            )
            .await?;
        delivery::confirm(&client, &key, &subscription.topic, subscription.id, &subscription.base_url, &token, Confirmation::Unsubscribe)
            .await?;
    }
    Ok(None)
}

impl Sns<'_> {
    pub(super) async fn subscribe(&mut self, params: &Params) -> Result<Option<String>> {
        let topic = self.topic(params.required("TopicArn")?).await?;
        let protocol = params.required("Protocol")?.to_owned();
        let endpoint = params.get("Endpoint").unwrap_or("").to_owned();
        let mut context = Context::default();
        context.set("sns:Protocol", protocol.clone());
        context.set("sns:Endpoint", endpoint.clone());
        self.check("sns:Subscribe", On::Topic(topic.account.clone(), topic.name.clone()), Some(&topic), &context).await?;
        if protocol != "http" && protocol != "https" {
            return Err(invalid(format!("Amazon SNS does not support this protocol string: {protocol}")));
        }
        let uri: Option<hyper::Uri> = endpoint.parse().ok();
        let fits = uri.as_ref().is_some_and(|u| u.scheme_str() == Some(protocol.as_str()) && u.host().is_some_and(|h| !h.is_empty()));
        if !fits {
            return Err(invalid("Endpoint must match the specified protocol"));
        }
        let mut raw = false;
        let mut delivery_policy = None;
        for (name, value) in params.entries("Attributes") {
            match name.as_str() {
                "RawMessageDelivery" => raw = raw_value(&value)?,
                "DeliveryPolicy" => delivery_policy = subscription_policy(&value)?,
                other if UNSUPPORTED.contains(&other) => {
                    return Err(invalid(format!("Attributes Reason: Cairn's SNS doesn't support the attribute {other}")));
                }
                other => return Err(invalid(format!("Attributes Reason: Unknown attribute {other}"))),
            }
        }
        // The endpoint's subscription, if it has one: pending again, if it
        // was deleted. Either way, it's sent a new confirmation (probed).
        let principal = self.principal.arn();
        let id: Uuid = self
            .client
            .query_one_cached(
                "INSERT INTO sns_subscriptions (topic_id, protocol, endpoint, base_url, state, raw, delivery_policy, principal)
                 VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7)
                 ON CONFLICT (topic_id, protocol, endpoint) DO UPDATE
                     SET state = CASE WHEN sns_subscriptions.state = 'deleted' THEN 'pending' ELSE sns_subscriptions.state END,
                         base_url = EXCLUDED.base_url, changed_at = now()
                 RETURNING id",
                &[&topic.id, &protocol, &endpoint, &self.base_url, &raw, &delivery_policy, &principal],
            )
            .await?
            .get(0);
        let key = signing::current(self.client, false).await?;
        let (token, hash) = token();
        self.client
            .execute_cached(
                &format!("INSERT INTO sns_tokens (hash, subscription_id, expires) VALUES ($1, $2, now() + interval '{TOKEN_LIFE}')"),
                &[&hash, &id],
            )
            .await?;
        delivery::confirm(self.client, &key, &topic, id, &self.base_url, &token, Confirmation::Subscribe).await?;
        let shown = match params.get("ReturnSubscriptionArn").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
            true => subscription_arn(&topic.arn(), id),
            false => "pending confirmation".to_owned(),
        };
        Ok(Some(format!("<SubscriptionArn>{}</SubscriptionArn>", xml_escape(&shown))))
    }

    pub(super) async fn confirm_subscription(&mut self, params: &Params) -> Result<Option<String>> {
        let arn = params.required("TopicArn")?;
        parse_arn(arn, "TopicArn")?;
        let token = params.required("Token")?;
        let authenticate = params.get("AuthenticateOnUnsubscribe").is_some_and(|v| v.eq_ignore_ascii_case("true"));
        // The token decides the subscription, whatever topic is named
        // (probed); allowed on the subscription's topic.
        let row = self
            .client
            .query_opt_cached(
                "SELECT s.topic_id FROM sns_tokens k JOIN sns_subscriptions s ON s.id = k.subscription_id
                 WHERE k.hash = $1 AND k.expires > now()",
                &[&hash(token)],
            )
            .await?;
        let Some(row) = row else { return Err(invalid("Token")) };
        let topic = Topic::by_id(self.client, row.get(0)).await?.ok_or_else(|| invalid("Token"))?;
        self.check("sns:ConfirmSubscription", On::Topic(topic.account.clone(), topic.name.clone()), Some(&topic), &Context::default())
            .await?;
        let subscription = confirm(self.client, token, authenticate).await?;
        Ok(Some(format!("<SubscriptionArn>{}</SubscriptionArn>", xml_escape(&subscription.arn()))))
    }

    pub(super) async fn unsubscribe(&mut self, params: &Params) -> Result<Option<String>> {
        let arn = params.required("SubscriptionArn")?;
        // One that isn't there is no error (probed).
        let Some(subscription) = named(self.client, arn).await? else { return Ok(None) };
        let topic = subscription.topic.clone();
        self.check("sns:Unsubscribe", On::Topic(topic.account.clone(), topic.name.clone()), Some(&topic), &Context::default()).await?;
        if subscription.state == "pending" {
            return Err(invalid("SubscriptionArn Reason: Cannot unsubscribe a subscription that is pending confirmation"));
        }
        self.client
            .execute_cached(
                "UPDATE sns_subscriptions SET state = 'deleted', changed_at = now() WHERE id = $1",
                &[&subscription.id],
            )
            .await?;
        Ok(None)
    }

    /// ListSubscriptions, or (`topic`) ListSubscriptionsByTopic.
    pub(super) async fn list_subscriptions(&mut self, params: &Params, topic: Option<Topic>) -> Result<Option<String>> {
        let account = self.account().to_owned();
        match &topic {
            Some(t) => {
                self.check("sns:ListSubscriptionsByTopic", On::Topic(t.account.clone(), t.name.clone()), Some(t), &Context::default())
                    .await?
            }
            None => self.check("sns:ListSubscriptions", On::Arn(super::topic_arn(&account, "*")), None, &Context::default()).await?,
        }
        let after = match params.get("NextToken") {
            Some(token) => Some(
                URL_SAFE_NO_PAD
                    .decode(token)
                    .ok()
                    .and_then(|b| Uuid::from_slice(&b).ok())
                    .ok_or_else(|| invalid("NextToken"))?,
            ),
            None => None,
        };
        let topic_id = topic.as_ref().map(|t| t.id);
        let rows = self
            .client
            .query_cached(
                "SELECT s.id FROM sns_subscriptions s JOIN sns_topics t ON t.id = s.topic_id
                 WHERE t.account_id = $1 AND ($2::uuid IS NULL OR s.topic_id = $2) AND ($3::uuid IS NULL OR s.id > $3)
                 ORDER BY s.id LIMIT $4",
                &[&account, &topic_id, &after, &(PAGE + 1)],
            )
            .await?;
        let ids: Vec<Uuid> = rows.iter().map(|r| r.get(0)).collect();
        let more = ids.len() as i64 > PAGE;
        let mut members = String::new();
        for id in ids.iter().take(PAGE as usize) {
            let Some(s) = Subscription::load(self.client, *id).await? else { continue };
            members.push_str(&format!(
                "<member><SubscriptionArn>{}</SubscriptionArn><Owner>{}</Owner><Protocol>{}</Protocol>\
                 <Endpoint>{}</Endpoint><TopicArn>{}</TopicArn></member>",
                xml_escape(&s.shown_arn()),
                xml_escape(&s.topic.account),
                xml_escape(&s.protocol),
                xml_escape(&s.endpoint),
                xml_escape(&s.topic.arn())
            ));
        }
        let next = match (more, ids.get(PAGE as usize - 1)) {
            (true, Some(last)) => format!("<NextToken>{}</NextToken>", URL_SAFE_NO_PAD.encode(last.as_bytes())),
            _ => String::new(),
        };
        Ok(Some(format!("<Subscriptions>{members}</Subscriptions>{next}")))
    }

    /// The subscription a request's `SubscriptionArn` names: SNS's 404 if
    /// it isn't there.
    async fn subscription(&mut self, params: &Params) -> Result<Subscription> {
        named(self.client, params.required("SubscriptionArn")?).await?.ok_or_else(|| not_found("Subscription does not exist"))
    }

    pub(super) async fn get_subscription_attributes(&mut self, params: &Params) -> Result<Option<String>> {
        let s = self.subscription(params).await?;
        let topic = s.topic.clone();
        self.check("sns:GetSubscriptionAttributes", On::Topic(topic.account.clone(), topic.name.clone()), Some(&topic), &Context::default())
            .await?;
        let policy = s.delivery_policy.as_deref().and_then(|p| SubscriptionPolicy::parse(p).ok().flatten());
        let effective = Effective::of(topic.delivery_policy().as_ref(), policy.as_ref());
        let mut attributes = vec![
            ("SubscriptionPrincipal", s.principal.clone()),
            ("Owner", topic.account.clone()),
            ("RawMessageDelivery", s.raw.to_string()),
            ("TopicArn", topic.arn()),
            ("Endpoint", s.endpoint.clone()),
            ("EffectiveDeliveryPolicy", effective.json()),
            ("Protocol", s.protocol.clone()),
            ("PendingConfirmation", (s.state == "pending").to_string()),
            ("ConfirmationWasAuthenticated", s.authenticated.to_string()),
            ("SubscriptionArn", s.arn()),
        ];
        if let Some(policy) = &policy {
            attributes.push(("DeliveryPolicy", policy.json()));
        }
        Ok(Some(attributes_xml(&attributes)))
    }

    pub(super) async fn set_subscription_attributes(&mut self, params: &Params) -> Result<Option<String>> {
        let s = self.subscription(params).await?;
        let name = params.required("AttributeName")?.to_owned();
        let value = params.get("AttributeValue").unwrap_or("").to_owned();
        let topic = s.topic.clone();
        self.check("sns:SetSubscriptionAttributes", On::Topic(topic.account.clone(), topic.name.clone()), Some(&topic), &Context::default())
            .await?;
        match name.as_str() {
            "RawMessageDelivery" => {
                let raw = raw_value(&value)?;
                self.client.execute_cached("UPDATE sns_subscriptions SET raw = $2 WHERE id = $1", &[&s.id, &raw]).await?;
            }
            "DeliveryPolicy" => {
                let policy = subscription_policy(&value)?;
                self.client.execute_cached("UPDATE sns_subscriptions SET delivery_policy = $2 WHERE id = $1", &[&s.id, &policy]).await?;
            }
            other if UNSUPPORTED.contains(&other) => {
                return Err(invalid(format!("AttributeName Reason: Cairn's SNS doesn't support the attribute {other}")));
            }
            _ => return Err(invalid("AttributeName")),
        }
        Ok(None)
    }

    pub(super) async fn publish(&mut self, params: &Params) -> Result<Option<String>> {
        let Some(arn) = params.get("TopicArn") else {
            if params.get("TargetArn").is_some() || params.get("PhoneNumber").is_some() {
                return Err(invalid("Cairn's SNS publishes to topics only"));
            }
            return Err(invalid("TopicArn or TargetArn Reason: no value for required parameter"));
        };
        let topic = self.topic(arn).await?;
        self.check("sns:Publish", On::Topic(topic.account.clone(), topic.name.clone()), Some(&topic), &Context::default()).await?;
        let message = params.get("Message").unwrap_or("");
        if message.is_empty() {
            return Err(invalid("Empty message"));
        }
        if message.len() > MAX_MESSAGE {
            return Err(invalid("Message too long"));
        }
        if params.get("MessageStructure").is_some() {
            return Err(invalid("MessageStructure Reason: Cairn's SNS delivers one message to every protocol"));
        }
        let subject = params.get("Subject");
        if let Some(subject) = subject
            && (subject.is_empty() || subject.chars().count() > 100 || !subject.chars().all(|c| c.is_ascii() && !c.is_ascii_control()))
        {
            return Err(invalid("Subject"));
        }
        let attributes = message_attributes(params)?;
        let key = signing::current(self.client, false).await?;
        let message = Message { subject, message, attributes };
        let id = delivery::publish(self.client, &key, &topic, &message).await?;
        Ok(Some(format!("<MessageId>{id}</MessageId>")))
    }
}

/// `RawMessageDelivery`'s value (probed: `true` or `false` only).
fn raw_value(value: &str) -> Result<bool> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(invalid(format!("RawMessageDelivery: Invalid value [{other}]. Must be true or false."))),
    }
}

/// A subscription's `DeliveryPolicy`, as it's kept; `None` for none.
fn subscription_policy(value: &str) -> Result<Option<String>> {
    match SubscriptionPolicy::parse(value) {
        Ok(policy) => Ok(policy.map(|p| p.json())),
        Err(why) => Err(invalid(format!("DeliveryPolicy: {why}"))),
    }
}

/// A Publish's `MessageAttributes`, as notifications carry them (JSON).
fn message_attributes(params: &Params) -> Result<Option<String>> {
    let mut out = Vec::new();
    for n in 1.. {
        let Some(name) = params.get(&format!("MessageAttributes.entry.{n}.Name")) else { break };
        let kind = params.get(&format!("MessageAttributes.entry.{n}.Value.DataType")).unwrap_or("");
        let value = match kind.split('.').next().unwrap_or("") {
            "String" | "Number" => params.get(&format!("MessageAttributes.entry.{n}.Value.StringValue")),
            "Binary" => params.get(&format!("MessageAttributes.entry.{n}.Value.BinaryValue")),
            _ => return Err(invalid(format!("The message attribute '{name}' has an invalid message attribute type, the set of supported type prefixes is Binary, Number, and String."))),
        };
        let Some(value) = value else {
            return Err(invalid(format!("The message attribute '{name}' must contain non-empty message attribute value for message attribute type '{kind}'.")));
        };
        let shown_kind = if kind.starts_with("Binary") { "Binary" } else { kind };
        out.push(format!(
            "{}:{{\"Type\":{},\"Value\":{}}}",
            serde_json::to_string(name).unwrap(),
            serde_json::to_string(shown_kind).unwrap(),
            serde_json::to_string(value).unwrap()
        ));
    }
    Ok((!out.is_empty()).then(|| format!("{{{}}}", out.join(","))))
}
