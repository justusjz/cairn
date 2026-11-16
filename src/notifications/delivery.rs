//! Delivering SNS's messages, on every node: S3's events, from the outbox
//! (`fan_out`), and what's published (`publish`), become a delivery per
//! confirmed subscription of their topic (`sns_deliveries`), each with its
//! body built and signed once; `send` POSTs them, and retries them as the
//! subscription's delivery policy says (see `delivery_policy`), until it's
//! answered, or its retries (or its deadline) run out.
//!
//! As SNS, a 2xx answer delivers a message, and so does a 4xx but 429: that
//! is final, not retried (probed). Anything else (a 429, a 5xx, no answer, a
//! redirect, which isn't followed) is retried. A delivery being sent is
//! leased for `LEASE`, so a node that dies sending it leaves it to be sent
//! again: at least once, never lost to a crash.
//!
//! Endpoints are reached at public addresses only, checked at every
//! connection (see `oidc::Resolver`), unless the cluster's
//! `notification-private-endpoints` setting lets them be private.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::{Request, body::Bytes};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use uuid::Uuid;

use super::{
    Event,
    delivery_policy::{Effective, SubscriptionPolicy, TopicPolicy},
    signing::{self, CONFIRMATION_FIELDS, Key, NOTIFICATION_FIELDS},
};
use crate::{App, db::Cached, sns};

/// How long a delivery is leased while it's sent.
const LEASE: &str = "2 minutes";
/// How long an endpoint may take to answer.
const TIMEOUT: Duration = Duration::from_secs(15);
/// The most deliveries a node sends at once, and events it fans out at once.
const BATCH: i64 = 64;
/// How long a delivery may be held back by throttling, beyond its retries.
const SLACK: u64 = 300;
/// How often the worker looks for work when it found none.
const IDLE: Duration = Duration::from_secs(1);

/// The user agent SNS sends with.
pub const USER_AGENT: &str = "Amazon Simple Notification Service Agent";

/// The worker: fans out events, and sends what's due, until the process
/// ends.
pub async fn run(app: Arc<App>) {
    loop {
        let task_app = app.clone();
        // A task of its own, so that a panic (a bug) fails this round, not
        // the worker.
        let round = tokio::spawn(async move {
            let mut busy = false;
            match fan_out(&task_app).await {
                Ok(n) => busy |= n > 0,
                Err(e) => eprintln!("notifications: fanning out events failed: {e:#}"),
            }
            match send(&task_app).await {
                Ok(n) => busy |= n > 0,
                Err(e) => eprintln!("notifications: sending failed: {e:#}"),
            }
            busy
        });
        match round.await {
            Ok(true) => continue,
            Ok(false) => {}
            Err(e) => eprintln!("notifications: round failed: {e}"),
        }
        tokio::time::sleep(IDLE).await;
    }
}

/// Now, as SNS writes times (`2026-11-16T09:50:47.302Z`).
pub fn now() -> String {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    iso(since.as_secs(), since.subsec_millis())
}

/// `seconds` (and `millis`) since the epoch, as ISO 8601 in UTC.
fn iso(seconds: u64, millis: u32) -> String {
    let days = (seconds / 86400) as i64;
    let rest = seconds % 86400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z", rest / 3600, rest / 60 % 60, rest % 60)
}

/// A string as JSON.
fn s(text: &str) -> String {
    serde_json::to_string(text).expect("a string serializes")
}

/// A message to a topic, before it's a subscription's.
pub struct Message<'a> {
    pub subject: Option<&'a str>,
    pub message: &'a str,
    /// Its `MessageAttributes`, as SNS writes them (JSON), if any.
    pub attributes: Option<String>,
}

/// A subscription, as deliveries to it need it.
struct Subscriber {
    id: Uuid,
    base_url: String,
    raw: bool,
    delivery_policy: Option<String>,
}

/// The deadline of a delivery under `effective`: its retries' time, and a
/// while for throttling.
fn deadline(effective: &Effective) -> String {
    format!("{} seconds", effective.retry.total() + SLACK)
}

/// `message` published to `topic`: a delivery to each of its confirmed
/// subscriptions, its body signed with `key`. Returns its ID.
pub async fn publish(client: &impl deadpool_postgres::GenericClient, key: &Key, topic: &sns::Topic, message: &Message<'_>) -> anyhow::Result<Uuid> {
    let id = Uuid::new_v4();
    let timestamp = now();
    let arn = topic.arn();
    let fields = |name: &str| -> Option<String> {
        match name {
            "Message" => Some(message.message.to_owned()),
            "MessageId" => Some(id.to_string()),
            "Subject" => message.subject.map(str::to_owned),
            "Timestamp" => Some(timestamp.clone()),
            "TopicArn" => Some(arn.clone()),
            "Type" => Some("Notification".to_owned()),
            _ => None,
        }
    };
    let signature = key.sign(topic.signature_version, &signing::string_to_sign(NOTIFICATION_FIELDS, fields));
    let rows = client
        .query(
            "SELECT id, base_url, raw, delivery_policy FROM sns_subscriptions WHERE topic_id = $1 AND state = 'confirmed'",
            &[&topic.id],
        )
        .await?;
    let topic_policy = topic.delivery_policy();
    for row in rows {
        let sub = Subscriber { id: row.get(0), base_url: row.get(1), raw: row.get(2), delivery_policy: row.get(3) };
        let body = match sub.raw {
            true => message.message.to_owned(),
            false => {
                let subject = message.subject.map(|t| format!("\"Subject\":{},", s(t))).unwrap_or_default();
                let attributes = message.attributes.as_ref().map(|a| format!(",\"MessageAttributes\":{a}")).unwrap_or_default();
                format!(
                    "{{\"Type\":\"Notification\",\"MessageId\":\"{id}\",\"TopicArn\":{arn},{subject}\"Message\":{message},\
                     \"Timestamp\":\"{timestamp}\",\"SignatureVersion\":\"{version}\",\"Signature\":\"{signature}\",\
                     \"SigningCertURL\":{cert},\"UnsubscribeURL\":{unsubscribe}{attributes}}}",
                    arn = s(&arn),
                    message = s(message.message),
                    version = topic.signature_version,
                    cert = s(&format!("{}/{}", sub.base_url, signing::certificate_name(key.id))),
                    unsubscribe = s(&format!(
                        "{}/?Action=Unsubscribe&SubscriptionArn={}",
                        sub.base_url,
                        sns::subscription_arn(&arn, sub.id)
                    )),
                )
            }
        };
        let sub_policy = sub.delivery_policy.as_deref().and_then(|p| SubscriptionPolicy::parse(p).ok().flatten());
        let effective = Effective::of(topic_policy.as_ref(), sub_policy.as_ref());
        client
            .execute(
                "INSERT INTO sns_deliveries (subscription_id, message_type, message_id, topic_arn, body, raw, deadline)
                 VALUES ($1, 'Notification', $2, $3, $4, $5, now() + $6::text::interval)",
                &[&sub.id, &id, &arn, &body, &sub.raw, &deadline(&effective)],
            )
            .await?;
    }
    Ok(id)
}

/// What a (un)subscription's confirmation is.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Confirmation {
    Subscribe,
    Unsubscribe,
}

/// Queues a confirmation to subscription `subscription` (at `base_url`) of
/// `topic`, with `token`, signed with `key`.
pub async fn confirm(
    client: &impl deadpool_postgres::GenericClient,
    key: &Key,
    topic: &sns::Topic,
    subscription: Uuid,
    base_url: &str,
    token: &str,
    kind: Confirmation,
) -> anyhow::Result<()> {
    let id = Uuid::new_v4();
    let timestamp = now();
    let arn = topic.arn();
    let (message_type, text) = match kind {
        Confirmation::Subscribe => (
            "SubscriptionConfirmation",
            format!(
                "You have chosen to subscribe to the topic {arn}.\nTo confirm the subscription, visit the SubscribeURL included in this message."
            ),
        ),
        Confirmation::Unsubscribe => (
            "UnsubscribeConfirmation",
            format!(
                "You have chosen to deactivate subscription {}.\nTo cancel this operation and restore the subscription, visit the SubscribeURL included in this message.",
                sns::subscription_arn(&arn, subscription)
            ),
        ),
    };
    let subscribe_url = format!("{base_url}/?Action=ConfirmSubscription&TopicArn={arn}&Token={token}");
    let fields = |name: &str| -> Option<String> {
        match name {
            "Message" => Some(text.clone()),
            "MessageId" => Some(id.to_string()),
            "SubscribeURL" => Some(subscribe_url.clone()),
            "Timestamp" => Some(timestamp.clone()),
            "Token" => Some(token.to_owned()),
            "TopicArn" => Some(arn.clone()),
            "Type" => Some(message_type.to_owned()),
            _ => None,
        }
    };
    let signature = key.sign(topic.signature_version, &signing::string_to_sign(CONFIRMATION_FIELDS, fields));
    let body = format!(
        "{{\"Type\":\"{message_type}\",\"MessageId\":\"{id}\",\"Token\":\"{token}\",\"TopicArn\":{arn},\"Message\":{text},\
         \"SubscribeURL\":{subscribe_url},\"Timestamp\":\"{timestamp}\",\"SignatureVersion\":\"{version}\",\
         \"Signature\":\"{signature}\",\"SigningCertURL\":{cert}}}",
        arn = s(&arn),
        text = s(&text),
        subscribe_url = s(&subscribe_url),
        version = topic.signature_version,
        cert = s(&format!("{base_url}/{}", signing::certificate_name(key.id))),
    );
    let effective = Effective::of(topic.delivery_policy().as_ref(), None);
    client
        .execute(
            "INSERT INTO sns_deliveries (subscription_id, message_type, message_id, topic_arn, body, raw, deadline)
             VALUES ($1, $2, $3, $4, $5, false, now() + $6::text::interval)",
            &[&subscription, &message_type, &id, &arn, &body, &deadline(&effective)],
        )
        .await?;
    Ok(())
}

/// Turns a batch of the outbox's events into deliveries; how many there
/// were. One transaction: a node that dies fanning them out leaves them be.
pub async fn fan_out(app: &App) -> anyhow::Result<usize> {
    let mut client = app.pool.get().await?;
    // Most of the time there's nothing; then, no key needed.
    if client.query_opt_cached("SELECT 1 FROM notification_events LIMIT 1", &[]).await?.is_none() {
        return Ok(0);
    }
    let key = signing::current(&client, false).await?;
    let tx = client.transaction().await?;
    let rows = tx
        .query(
            "SELECT seq, bucket, key, event, size, etag, version_id, sequencer, context::text, config_id, topic_arn,
                    to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')
             FROM notification_events ORDER BY seq LIMIT $1 FOR UPDATE SKIP LOCKED",
            &[&BATCH],
        )
        .await?;
    let mut done = Vec::with_capacity(rows.len());
    let mut topics: HashMap<String, Option<sns::Topic>> = HashMap::new();
    let mut owners: HashMap<String, String> = HashMap::new();
    for row in &rows {
        let event = Event {
            seq: row.get(0),
            bucket: row.get(1),
            key: row.get(2),
            name: row.get(3),
            size: row.get(4),
            etag: row.get(5),
            version_id: row.get(6),
            sequencer: row.get(7),
            context: serde_json::from_str(row.get::<_, &str>(8))?,
            config_id: row.get(9),
            topic_arn: row.get(10),
            time: row.get(11),
        };
        done.push(event.seq);
        if !topics.contains_key(&event.topic_arn) {
            let topic = match sns::parse_topic_arn(&event.topic_arn) {
                Some((account, name)) => sns::Topic::load(&tx, &account, &name).await?,
                None => None,
            };
            topics.insert(event.topic_arn.clone(), topic);
        }
        let Some(topic) = topics.get(&event.topic_arn).and_then(Option::as_ref) else {
            // Gone since: as S3, the event is dropped.
            eprintln!("notifications: dropped an event of bucket {}: topic {} doesn't exist", event.bucket, event.topic_arn);
            continue;
        };
        let owner = match owners.get(&event.bucket) {
            Some(owner) => owner.clone(),
            None => {
                let owner = tx
                    .query_opt("SELECT account_id FROM buckets WHERE name = $1", &[&event.bucket])
                    .await?
                    .map_or_else(|| topic.account.clone(), |r| r.get(0));
                owners.insert(event.bucket.clone(), owner.clone());
                owner
            }
        };
        if !sns::s3_may_publish(topic, &event.bucket, &owner)? {
            eprintln!(
                "notifications: dropped an event of bucket {}: topic {}'s policy doesn't let S3 publish it",
                event.bucket, event.topic_arn
            );
            continue;
        }
        let mut event = event;
        if event.name.starts_with("ObjectTagging:") {
            event.etag = open_etag(app, &event).await?;
        }
        let message = event.message(&owner);
        let message = Message { subject: Some("Amazon S3 Notification"), message: &message, attributes: None };
        publish(&tx, &key, topic, &message).await?;
    }
    tx.execute("DELETE FROM notification_events WHERE seq = ANY($1)", &[&done]).await?;
    tx.commit().await?;
    Ok(done.len())
}

/// A tagging event's ETag, as clients know it: an SSE-S3 version's is
/// stored sealed, which the catalog's function can't open. `None` if the
/// version's gone since.
async fn open_etag(app: &App, event: &Event) -> anyhow::Result<Option<String>> {
    let Some(etag) = &event.etag else { return Ok(None) };
    let client = app.pool.get().await?;
    let version = event.version_id.as_deref().unwrap_or("null");
    let Some(row) = client
        .query_opt_cached(
            "SELECT sse_c_key, sse_kms_key_id, sse_kms_data_key, sse_kms_sealed, sse_kms_context, sse_s3
             FROM objects WHERE bucket = $1 AND key = $2 AND version_id = $3",
            &[&event.bucket, &event.key, &version],
        )
        .await?
    else {
        return Ok(None);
    };
    let stored = crate::s3::sse::Stored::from_row(&row, 0);
    match crate::s3::sse::etag_key(app, &stored, &event.bucket, &event.key).await? {
        Ok(Some(key)) => {
            let owner = crate::encryption::Owner::Object { bucket: &event.bucket, key: &event.key };
            Ok(Some(key.open(owner, etag)?))
        }
        Ok(None) => Ok(Some(etag.clone())),
        // Its key can't be had now: no ETag, rather than a sealed one.
        Err(_) => Ok(None),
    }
}

type Https = Client<HttpsConnector<HttpConnector<crate::oidc::Resolver>>, Full<Bytes>>;

/// The client deliveries go through: `public_only` or not.
fn client(public_only: bool) -> Https {
    static CLIENTS: OnceLock<[Https; 2]> = OnceLock::new();
    let clients = CLIENTS.get_or_init(|| {
        let make = |public_only: bool| {
            let tls = rustls::ClientConfig::builder_with_provider(crate::oidc::provider())
                .with_safe_default_protocol_versions()
                .expect("ring has TLS 1.2 and 1.3")
                .with_root_certificates(crate::oidc::public_roots())
                .with_no_client_auth();
            let mut http = HttpConnector::new_with_resolver(crate::oidc::Resolver::new(public_only));
            http.enforce_http(false);
            let connector =
                hyper_rustls::HttpsConnectorBuilder::new().with_tls_config(tls).https_or_http().enable_http1().wrap_connector(http);
            Client::builder(TokioExecutor::new()).build(connector)
        };
        [make(true), make(false)]
    });
    clients[if public_only { 0 } else { 1 }].clone()
}

/// What an attempt at a delivery came to.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Answered 2xx.
    Delivered,
    /// Answered with a 4xx but 429: final.
    Refused(u16),
    /// To be tried again.
    Failed(String),
}

/// One delivery claimed to send.
struct Claimed {
    id: i64,
    message_type: String,
    message_id: Uuid,
    topic_arn: String,
    body: String,
    raw: bool,
    attempt: i32,
    expired: bool,
    subscription: Uuid,
    endpoint: String,
    state: String,
    effective: Effective,
}

/// POSTs `body` to `endpoint`, as SNS does.
pub async fn post(public_only: bool, endpoint: &str, headers: &[(&str, String)], body: String) -> Outcome {
    let mut request = Request::post(endpoint);
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    let request = match request.body(Full::new(Bytes::from(body))) {
        Ok(request) => request,
        Err(e) => return Outcome::Failed(format!("not a request: {e}")),
    };
    let call = async {
        let response = client(public_only).request(request).await.map_err(|e| format!("couldn't be reached: {e}"))?;
        let status = response.status();
        // What it says doesn't matter; it's read (to a limit) so the
        // connection can be reused.
        let _ = http_body_util::Limited::new(response.into_body(), 64 << 10).collect().await;
        Ok::<_, String>(status)
    };
    match tokio::time::timeout(TIMEOUT, call).await {
        Err(_) => Outcome::Failed("didn't answer in time".to_owned()),
        Ok(Err(e)) => Outcome::Failed(e),
        Ok(Ok(status)) if status.is_success() => Outcome::Delivered,
        Ok(Ok(status)) if status.is_client_error() && status.as_u16() != 429 => Outcome::Refused(status.as_u16()),
        Ok(Ok(status)) => Outcome::Failed(format!("answered {status}")),
    }
}

/// Sends a batch of the deliveries that are due; how many.
pub async fn send(app: &App) -> anyhow::Result<usize> {
    let client = app.pool.get().await?;
    let rows = client
        .query_cached(
            &format!(
                "UPDATE sns_deliveries d SET next_at = now() + interval '{LEASE}'
                 FROM (SELECT id FROM sns_deliveries WHERE next_at <= now() ORDER BY next_at LIMIT $1 FOR UPDATE SKIP LOCKED) c
                 WHERE d.id = c.id
                 RETURNING d.id, d.message_type, d.message_id, d.topic_arn, d.body, d.raw, d.attempt, d.deadline < now(),
                           d.subscription_id"
            ),
            &[&BATCH],
        )
        .await?;
    if rows.is_empty() {
        return Ok(0);
    }
    let ids: Vec<Uuid> = rows.iter().map(|r| r.get(8)).collect();
    let subs = client
        .query_cached(
            "SELECT s.id, s.endpoint, s.state, s.delivery_policy, t.delivery_policy
             FROM sns_subscriptions s JOIN sns_topics t ON t.id = s.topic_id WHERE s.id = ANY($1)",
            &[&ids],
        )
        .await?;
    let subs: HashMap<Uuid, (String, String, Effective)> = subs
        .iter()
        .map(|r| {
            let sub = r.get::<_, Option<&str>>(3).and_then(|p| SubscriptionPolicy::parse(p).ok().flatten());
            let topic = r.get::<_, Option<&str>>(4).and_then(|p| TopicPolicy::parse(p).ok().flatten());
            (r.get(0), (r.get(1), r.get(2), Effective::of(topic.as_ref(), sub.as_ref())))
        })
        .collect();
    let public_only = crate::settings::NOTIFICATION_PRIVATE_ENDPOINTS.get(&client).await? == 0;
    let mut claimed = Vec::new();
    let mut gone = Vec::new();
    for row in &rows {
        let subscription: Uuid = row.get(8);
        let Some((endpoint, state, effective)) = subs.get(&subscription) else {
            gone.push(row.get::<_, i64>(0));
            continue;
        };
        claimed.push(Claimed {
            id: row.get(0),
            message_type: row.get(1),
            message_id: row.get(2),
            topic_arn: row.get(3),
            body: row.get(4),
            raw: row.get(5),
            attempt: row.get(6),
            expired: row.get(7),
            subscription,
            endpoint: endpoint.clone(),
            state: state.clone(),
            effective: effective.clone(),
        });
    }
    // Throttled subscriptions get so many a second; the rest wait a second.
    let mut sent_to: HashMap<Uuid, u32> = HashMap::new();
    let mut later = Vec::new();
    let mut sending = Vec::new();
    for c in claimed {
        // A notification only to a subscription still confirmed; a
        // confirmation to one still pending (or, an unsubscription's, gone).
        let wanted = match c.message_type.as_str() {
            "Notification" => c.state == "confirmed",
            "SubscriptionConfirmation" => c.state == "pending",
            _ => true,
        };
        if !wanted || c.expired {
            gone.push(c.id);
            continue;
        }
        let count = sent_to.entry(c.subscription).or_default();
        if c.effective.throttle.is_some_and(|max| *count >= max) {
            later.push(c.id);
            continue;
        }
        *count += 1;
        sending.push(c);
    }
    if !later.is_empty() {
        client.execute_cached("UPDATE sns_deliveries SET next_at = now() + interval '1 second' WHERE id = ANY($1)", &[&later]).await?;
    }
    if !gone.is_empty() {
        client.execute_cached("DELETE FROM sns_deliveries WHERE id = ANY($1)", &[&gone]).await?;
    }
    let mut attempts = tokio::task::JoinSet::new();
    for c in sending {
        attempts.spawn(async move {
        let mut headers = vec![
            ("content-type", c.effective.content_type.clone()),
            ("user-agent", USER_AGENT.to_owned()),
            ("x-amz-sns-message-type", c.message_type.clone()),
            ("x-amz-sns-message-id", c.message_id.to_string()),
            ("x-amz-sns-topic-arn", c.topic_arn.clone()),
        ];
        if c.message_type != "SubscriptionConfirmation" {
            headers.push(("x-amz-sns-subscription-arn", sns::subscription_arn(&c.topic_arn, c.subscription)));
        }
        if c.raw {
            headers.push(("x-amz-sns-rawdelivery", "true".to_owned()));
        }
        let outcome = post(public_only, &c.endpoint, &headers, c.body.clone()).await;
        (c, outcome)
        });
    }
    let results = attempts.join_all().await;
    let n = results.len();
    for (c, outcome) in results {
        match outcome {
            Outcome::Delivered => {
                client.execute_cached("DELETE FROM sns_deliveries WHERE id = $1", &[&c.id]).await?;
            }
            Outcome::Refused(status) => {
                eprintln!("notifications: {} answered {status} to message {}: not retried", c.endpoint, c.message_id);
                client.execute_cached("DELETE FROM sns_deliveries WHERE id = $1", &[&c.id]).await?;
            }
            Outcome::Failed(why) => match c.effective.retry.delay(c.attempt as u32 + 1) {
                Some(delay) => {
                    client
                        .execute_cached(
                            "UPDATE sns_deliveries SET attempt = attempt + 1, next_at = now() + make_interval(secs => $2)
                             WHERE id = $1",
                            &[&c.id, &(delay as f64)],
                        )
                        .await?;
                }
                None => {
                    eprintln!(
                        "notifications: gave up on message {} to {} after {} attempts: {why}",
                        c.message_id,
                        c.endpoint,
                        c.attempt + 1
                    );
                    client.execute_cached("DELETE FROM sns_deliveries WHERE id = $1", &[&c.id]).await?;
                }
            },
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_times_as_sns_does() {
        assert_eq!(iso(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso(1_794_822_384, 913), "2026-11-16T09:46:24.913Z");
    }
}
