//! S3's event notifications, through SNS (see `sns`, and
//! `plans/notifications.md`): a bucket's notification configurations (see
//! `config`) name topics, and each change to an object that one matches is
//! an event, written to the outbox (`notification_events`) by the change's
//! own transaction (`cairn_notify` in `catalog.sql`). The delivery worker
//! (see `delivery`) turns events into SNS messages, signed (see `signing`),
//! and sends them to each confirmed subscription of their topics, retried as
//! the subscriptions' delivery policies say (see `delivery_policy`).
//!
//! What a change is, for its events, the catalog function is told by its
//! caller (`context`): who made it (`userIdentity`), from where, in which
//! request, and how (`Put` or `Post`, ...). A request's task carries who
//! made it (`Requester`), set once it's authenticated (see `s3`).

pub mod config;
pub mod delivery;
pub mod delivery_policy;
pub mod signing;

use std::sync::Mutex;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Value, json};

/// Who makes the request a task handles, as its events say.
#[derive(Clone, Debug, Default)]
pub struct Requester {
    /// `userIdentity.principalId`: `AWS:` and the principal's unique ID.
    pub principal: Option<String>,
    /// `requestParameters.sourceIPAddress`.
    pub ip: Option<String>,
    /// What a write makes, if not a `Put`: POST Object's `Post`.
    pub created: Option<&'static str>,
    /// What the task's writes are replicas of, if they are (see
    /// `replication`): `cairn_replica` reads it from the context.
    pub replica: Option<Value>,
}

tokio::task_local! {
    static REQUESTER: Mutex<Requester>;
}

/// Runs `f` as a request's task, whose requester `set_requester` sets.
pub async fn scope<F: Future>(f: F) -> F::Output {
    REQUESTER.scope(Mutex::new(Requester::default()), f).await
}

/// Sets who makes the task's request: a principal's unique ID (`None`:
/// anonymous), and the client's address.
pub fn set_requester(principal: Option<String>, ip: Option<std::net::IpAddr>) {
    let _ = REQUESTER.try_with(|r| {
        let mut r = r.lock().unwrap();
        r.principal = Some(principal.map_or_else(|| "Anonymous".to_owned(), |id| format!("AWS:{id}")));
        r.ip = ip.map(|ip| ip.to_string());
    });
}

/// Sets what the task's write makes (POST Object's: `Post`).
pub fn set_created(created: &'static str) {
    let _ = REQUESTER.try_with(|r| r.lock().unwrap().created = Some(created));
}

/// Makes the task's writes replicas (see `replication`): of the version
/// `version_id`, last modified at `last_modified` (ISO 8601, as Postgres
/// reads it), whose stored ETag `etag` the replica keeps, if it's given.
pub fn set_replica(version_id: &str, last_modified: &str, etag: Option<&str>) {
    let mut replica = json!({ "version_id": version_id, "last_modified": last_modified });
    if let Some(etag) = etag {
        replica["etag"] = json!(etag);
    }
    let _ = REQUESTER.try_with(|r| r.lock().unwrap().replica = Some(replica));
}

fn requester() -> Requester {
    REQUESTER.try_with(|r| r.lock().unwrap().clone()).unwrap_or_default()
}

/// What a write is, for its events (`cairn_notify`'s `cairn.notify`): the
/// task's requester and request, and how the write makes an object
/// (`created`: `Put`, unless the task says otherwise, or `Copy`, ...), with
/// the ETag clients know it by (an SSE-S3 one's is stored sealed).
pub fn context(created: Option<&str>, etag: Option<&str>) -> String {
    let r = requester();
    let created = created.or(r.created).unwrap_or("Put");
    let mut context = base(&r);
    context["created"] = json!(created);
    if let Some(etag) = etag {
        context["etag"] = json!(etag);
    }
    context.to_string()
}

/// A tagging's context (`Put` or `Delete`).
pub fn tagging_context(tagging: &str) -> String {
    let mut context = base(&requester());
    context["tagging"] = json!(tagging);
    context.to_string()
}

/// A deletion's context.
pub fn delete_context() -> String {
    base(&requester()).to_string()
}

/// A lifecycle sweep's: S3's own.
pub fn lifecycle_context() -> String {
    json!({ "source": "lifecycle", "principal": LIFECYCLE_PRINCIPAL }).to_string()
}

/// Who a lifecycle sweep's events say made them. (Unprobed: see
/// `plans/notifications.md`.)
const LIFECYCLE_PRINCIPAL: &str = "s3.amazonaws.com";

fn base(r: &Requester) -> Value {
    let mut context = json!({});
    if let Some(principal) = &r.principal {
        context["principal"] = json!(principal);
    }
    if let Some(ip) = &r.ip {
        context["ip"] = json!(ip);
    }
    if let Some(id) = crate::s3::request_id() {
        context["request_id"] = json!(id);
    }
    if let Some(replica) = &r.replica {
        context["replica"] = replica.clone();
    }
    context
}

/// The maintenance pass's upkeep: tokens past their life go, and with
/// them the subscriptions they could still confirm (or restore), pending or
/// deleted, as SNS forgets an unconfirmed one after three days; and the
/// signing key is renewed when it's due (only once there are topics).
pub async fn maintain(client: &deadpool_postgres::Object) -> anyhow::Result<()> {
    use crate::db::Cached;
    client.execute_cached("DELETE FROM sns_tokens WHERE expires < now()", &[]).await?;
    client
        .execute_cached(
            "DELETE FROM sns_subscriptions s WHERE s.state <> 'confirmed' AND s.changed_at < now() - interval '1 hour'
             AND NOT EXISTS (SELECT 1 FROM sns_tokens k WHERE k.subscription_id = s.id)",
            &[],
        )
        .await?;
    if client.query_opt_cached("SELECT 1 FROM sns_topics LIMIT 1", &[]).await?.is_some() {
        signing::current(client, true).await?;
    }
    Ok(())
}

/// One event of the outbox.
#[derive(Clone, Debug)]
pub struct Event {
    pub seq: i64,
    pub bucket: String,
    pub key: String,
    /// `ObjectCreated:Put`, ...
    pub name: String,
    pub size: Option<i64>,
    pub etag: Option<String>,
    pub version_id: Option<String>,
    pub sequencer: Option<i64>,
    pub context: Value,
    pub config_id: String,
    pub topic_arn: String,
    /// When it happened, as S3 writes it (`2026-11-16T09:50:46.600Z`).
    pub time: String,
}

/// The characters an event's key keeps as they are; the rest are
/// percent-encoded, and a space is `+` (probed: `n/ü a+b=c` is
/// `n/%C3%BC+a%2Bb%3Dc`).
const KEY_ESCAPES: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'/').remove(b'*').remove(b'~');

/// A key as an event writes it: form-encoded, but its `/`s.
pub fn event_key(key: &str) -> String {
    key.split(' ').map(|part| utf8_percent_encode(part, KEY_ESCAPES).to_string()).collect::<Vec<_>>().join("+")
}

/// A string as JSON.
fn s(text: &str) -> String {
    serde_json::to_string(text).expect("a string serializes")
}

impl Event {
    /// The event as S3 writes it, in an SNS message's `Message`: a record of
    /// its own, its fields in S3's order (probed), in `account`'s bucket.
    pub fn message(&self, account: &str) -> String {
        let ctx = |name: &str| self.context.get(name).and_then(Value::as_str);
        let principal = ctx("principal").unwrap_or("Anonymous");
        let ip = ctx("ip").unwrap_or("");
        let request_id = ctx("request_id").unwrap_or("");
        // A created object's ETag as clients know it; else as stored, which
        // only an SSE-S3 object's isn't (see `delivery`, which opens those).
        let etag = match self.name.starts_with("ObjectCreated:") {
            true => ctx("etag").map(str::to_owned).or(self.etag.clone()),
            false => self.etag.clone(),
        };
        let etag = etag.map(|e| e.trim_matches('"').to_owned());
        let mut object = vec![format!("\"key\":{}", s(&event_key(&self.key)))];
        let removed = self.name.starts_with("ObjectRemoved:") || self.name.starts_with("LifecycleExpiration:");
        let marker = self.name.ends_with(":DeleteMarkerCreated");
        let tagging = self.name.starts_with("ObjectTagging:");
        if let Some(size) = self.size.filter(|_| !removed && !tagging) {
            object.push(format!("\"size\":{size}"));
        }
        if let Some(etag) = etag.filter(|_| !removed || marker) {
            object.push(format!("\"eTag\":{}", s(&etag)));
        }
        if let Some(version) = &self.version_id {
            object.push(format!("\"versionId\":{}", s(version)));
        }
        if let Some(sequencer) = self.sequencer.filter(|_| !tagging) {
            object.push(format!("\"sequencer\":\"{sequencer:018X}\""));
        }
        if self.name == "ObjectCreated:Copy" {
            object.push("\"hasObjectAnnotation\":false".to_owned());
        }
        format!(
            "{{\"Records\":[{{\"eventVersion\":\"2.6\",\"eventSource\":\"aws:s3\",\"awsRegion\":{region},\
             \"eventTime\":{time},\"eventName\":{name},\"userIdentity\":{{\"principalId\":{principal}}},\
             \"requestParameters\":{{\"sourceIPAddress\":{ip}}},\
             \"responseElements\":{{\"x-amz-request-id\":{request_id},\"x-amz-id-2\":{host_id}}},\
             \"s3\":{{\"s3SchemaVersion\":\"1.0\",\"configurationId\":{config},\
             \"bucket\":{{\"name\":{bucket},\"ownerIdentity\":{{\"principalId\":{owner}}},\"arn\":{arn}}},\
             \"object\":{{{object}}}}}}}]}}",
            region = s(crate::s3::buckets::head::REGION),
            time = s(&self.time),
            name = s(&self.name),
            principal = s(principal),
            ip = s(ip),
            request_id = s(request_id),
            host_id = s(&host_id(request_id)),
            config = s(&self.config_id),
            bucket = s(&self.bucket),
            owner = s(account),
            arn = s(&format!("arn:aws:s3:::{}", self.bucket)),
            object = object.join(","),
        )
    }
}

/// A request's `x-amz-id-2`, which Cairn doesn't send: its ID, as the host
/// ID S3's events have beside it.
fn host_id(request_id: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(request_id.as_bytes())
}

/// The message S3 sends a topic to test a configuration (`s3:TestEvent`),
/// for bucket `bucket`, at `time`.
pub fn test_message(bucket: &str, time: &str, request_id: &str) -> String {
    format!(
        "{{\"Service\":\"Amazon S3\",\"Event\":\"s3:TestEvent\",\"Time\":{},\"Bucket\":{},\"RequestId\":{},\"HostId\":{}}}",
        s(time),
        s(bucket),
        s(request_id),
        s(&host_id(request_id))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_form_encoded_but_slashes() {
        assert_eq!(event_key("n/ü a+b=c"), "n/%C3%BC+a%2Bb%3Dc");
        assert_eq!(event_key("plain/key.txt"), "plain/key.txt");
    }

    fn event(name: &str) -> Event {
        Event {
            seq: 1,
            bucket: "b".into(),
            key: "n/a".into(),
            name: name.into(),
            size: Some(5),
            etag: Some("\"5d41402abc4b2a76b9719d911017c592\"".into()),
            version_id: Some("v1".into()),
            sequencer: Some(0x6AFAD1F68B4842A3),
            context: json!({"principal": "AWS:AIDAX", "ip": "1.2.3.4", "request_id": "R1"}),
            config_id: "c".into(),
            topic_arn: "arn:aws:sns:us-east-1:123456789012:t".into(),
            time: "2026-11-16T09:50:46.600Z".into(),
        }
    }

    #[test]
    fn records_are_as_s3_writes_them() {
        let message = event("ObjectCreated:Put").message("123456789012");
        assert!(message.starts_with(
            "{\"Records\":[{\"eventVersion\":\"2.6\",\"eventSource\":\"aws:s3\",\"awsRegion\":\"us-east-1\",\
             \"eventTime\":\"2026-11-16T09:50:46.600Z\",\"eventName\":\"ObjectCreated:Put\""
        ));
        assert!(message.contains(
            "\"object\":{\"key\":\"n/a\",\"size\":5,\"eTag\":\"5d41402abc4b2a76b9719d911017c592\",\
             \"versionId\":\"v1\",\"sequencer\":\"006AFAD1F68B4842A3\"}"
        ));
        let parsed: Value = serde_json::from_str(&message).unwrap();
        assert_eq!(parsed["Records"][0]["userIdentity"]["principalId"], "AWS:AIDAX");
        // A deletion has neither size nor ETag; a marker an ETag.
        let deleted = event("ObjectRemoved:Delete").message("1");
        assert!(deleted.contains("\"object\":{\"key\":\"n/a\",\"versionId\":\"v1\",\"sequencer\":"));
        let marker = event("ObjectRemoved:DeleteMarkerCreated").message("1");
        assert!(marker.contains("\"object\":{\"key\":\"n/a\",\"eTag\":"));
        // Tagging has no sequencer; a copy says it has no annotation.
        let tagged = event("ObjectTagging:Put").message("1");
        assert!(tagged.contains("\"object\":{\"key\":\"n/a\",\"eTag\":\"5d41402abc4b2a76b9719d911017c592\",\"versionId\":\"v1\"}"));
        assert!(event("ObjectCreated:Copy").message("1").contains("\"hasObjectAnnotation\":false}"));
    }
}
