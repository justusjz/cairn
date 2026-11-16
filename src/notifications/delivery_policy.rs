//! SNS's delivery policies, for HTTP(S) (probed, see
//! `plans/notifications.md`): how often, and how far apart, a delivery is
//! retried, and how fast a subscription is sent to. A topic's
//! (`DeliveryPolicy`, `{"http": {...}}`) sets its subscriptions' defaults; a
//! subscription's (`{"healthyRetryPolicy": ..., ...}`) overrides them, unless
//! the topic's disables that. What applies is the effective policy, which
//! both attributes show (`EffectiveDeliveryPolicy`), as SNS writes them.

use serde_json::{Map, Value};

/// A retry policy: the retries after a first attempt, in four phases (none
/// waiting, then waiting the least, then backing off from the least to the
/// most, then waiting the most), their delays in seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retry {
    pub min_delay: u32,
    pub max_delay: u32,
    pub retries: u32,
    pub no_delay: u32,
    pub min_delays: u32,
    pub max_delays: u32,
    pub backoff: Backoff,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backoff {
    Linear,
    Arithmetic,
    Geometric,
    Exponential,
}

impl Backoff {
    fn name(self) -> &'static str {
        match self {
            Backoff::Linear => "linear",
            Backoff::Arithmetic => "arithmetic",
            Backoff::Geometric => "geometric",
            Backoff::Exponential => "exponential",
        }
    }
}

/// SNS's default for HTTP(S): three retries, twenty seconds apart (probed).
pub const DEFAULT_RETRY: Retry =
    Retry { min_delay: 20, max_delay: 20, retries: 3, no_delay: 0, min_delays: 0, max_delays: 0, backoff: Backoff::Linear };

/// The most a policy may retry for, in seconds, and how many times.
const MAX_TOTAL: u64 = 3600;
const MAX_RETRIES: u32 = 100;

/// The content type messages are sent with, by default.
pub const DEFAULT_CONTENT_TYPE: &str = "text/plain; charset=UTF-8";

impl Retry {
    /// How long to wait before retry `n` (1-based); `None` once there are
    /// no retries left.
    pub fn delay(&self, n: u32) -> Option<u32> {
        if n == 0 || n > self.retries {
            return None;
        }
        let backoffs = self.retries - self.no_delay - self.min_delays - self.max_delays;
        if n <= self.no_delay {
            return Some(0);
        }
        let n = n - self.no_delay;
        if n <= self.min_delays {
            return Some(self.min_delay);
        }
        let n = n - self.min_delays;
        if n <= backoffs {
            // From the least towards the most, the last backoff the most.
            let t = n as f64 / backoffs as f64;
            let f = match self.backoff {
                Backoff::Linear | Backoff::Arithmetic => t,
                Backoff::Geometric => t * t,
                Backoff::Exponential => (2f64.powf(4.0 * t) - 1.0) / 15.0,
            };
            let span = (self.max_delay - self.min_delay) as f64;
            return Some(self.min_delay + (span * f).round() as u32);
        }
        Some(self.max_delay)
    }

    /// How long all its retries wait, together.
    pub fn total(&self) -> u64 {
        (1..=self.retries).map(|n| self.delay(n).unwrap_or(0) as u64).sum()
    }

    fn json(&self) -> String {
        format!(
            "{{\"minDelayTarget\":{},\"maxDelayTarget\":{},\"numRetries\":{},\"numMaxDelayRetries\":{},\
             \"numNoDelayRetries\":{},\"numMinDelayRetries\":{},\"backoffFunction\":\"{}\"}}",
            self.min_delay,
            self.max_delay,
            self.retries,
            self.max_delays,
            self.no_delay,
            self.min_delays,
            self.backoff.name()
        )
    }
}

/// A topic's delivery policy, as set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TopicPolicy {
    pub retry: Option<Retry>,
    pub throttle: Option<u32>,
    pub content_type: Option<String>,
    pub disable_overrides: bool,
}

/// A subscription's delivery policy, as set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionPolicy {
    pub retry: Option<Retry>,
    pub throttle: Option<u32>,
    pub content_type: Option<String>,
}

/// What applies to a subscription's deliveries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Effective {
    pub retry: Retry,
    /// At most so many messages a second, if limited.
    pub throttle: Option<u32>,
    pub content_type: String,
}

/// Why a policy was refused, as SNS says after "Invalid parameter:
/// DeliveryPolicy: ".
pub type Refused = String;

fn object<'a>(value: &'a Value, path: &str) -> Result<&'a Map<String, Value>, Refused> {
    value.as_object().ok_or_else(|| format!("Invalid JSON: {path} must be an object"))
}

fn only(map: &Map<String, Value>, path: &str, known: &[&str]) -> Result<(), Refused> {
    match map.keys().find(|k| !known.contains(&k.as_str())) {
        Some(key) => Err(format!("Unexpected JSON member: {}{key}", if path.is_empty() { String::new() } else { format!("{path}.") })),
        None => Ok(()),
    }
}

fn number(map: &Map<String, Value>, path: &str, name: &str) -> Result<Option<u32>, Refused> {
    match map.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .filter(|n| *n <= u32::MAX as u64)
            .map(|n| Some(n as u32))
            .ok_or_else(|| format!("Invalid JSON: {path}.{name} must be a whole number")),
    }
}

fn retry(value: &Value, path: &str) -> Result<Option<Retry>, Refused> {
    if value.is_null() {
        return Ok(None);
    }
    let map = object(value, path)?;
    only(map, path, &[
        "minDelayTarget",
        "maxDelayTarget",
        "numRetries",
        "numNoDelayRetries",
        "numMinDelayRetries",
        "numMaxDelayRetries",
        "backoffFunction",
    ])?;
    let required = |name: &str| -> Result<u32, Refused> {
        number(map, path, name)?.ok_or_else(|| format!("{path}.{name} must be specified"))
    };
    let min_delay = required("minDelayTarget")?;
    let max_delay = required("maxDelayTarget")?;
    let retries = required("numRetries")?;
    let no_delay = number(map, path, "numNoDelayRetries")?.unwrap_or(0);
    let min_delays = number(map, path, "numMinDelayRetries")?.unwrap_or(0);
    let max_delays = number(map, path, "numMaxDelayRetries")?.unwrap_or(0);
    let backoff = match map.get("backoffFunction") {
        None | Some(Value::Null) => Backoff::Linear,
        Some(Value::String(f)) => match f.as_str() {
            "linear" => Backoff::Linear,
            "arithmetic" => Backoff::Arithmetic,
            "geometric" => Backoff::Geometric,
            "exponential" => Backoff::Exponential,
            other => return Err(format!("Invalid JSON: the value [{other}] is not a valid backoff function")),
        },
        Some(other) => return Err(format!("Invalid JSON: the value [{other}] is not a valid backoff function")),
    };
    if min_delay < 1 {
        return Err(format!("{path}.minDelayTarget must be greater than or equal to 1"));
    }
    if max_delay < min_delay {
        return Err(format!("{path}.maxDelayTarget must be greater than or equal to minDelayTarget"));
    }
    if max_delay > MAX_TOTAL as u32 {
        return Err(format!("{path}.maxDelayTarget must be less than or equal to {MAX_TOTAL}"));
    }
    if retries > MAX_RETRIES {
        return Err(format!("{path}.numRetries must be less than or equal to {MAX_RETRIES}"));
    }
    if (no_delay as u64 + min_delays as u64 + max_delays as u64) > retries as u64 {
        return Err(format!(
            "{path}.numRetries must be greater than or equal to total of numMinDelayRetries, numNoDelayRetries and numMaxDelayRetries"
        ));
    }
    let retry = Retry { min_delay, max_delay, retries, no_delay, min_delays, max_delays, backoff };
    if retry.total() > MAX_TOTAL {
        return Err(format!("{path}: Total policy retry time cannot be greater than {MAX_TOTAL} seconds"));
    }
    Ok(Some(retry))
}

fn throttle(value: &Value, path: &str) -> Result<Option<u32>, Refused> {
    if value.is_null() {
        return Ok(None);
    }
    let map = object(value, path)?;
    only(map, path, &["maxReceivesPerSecond"])?;
    match number(map, path, "maxReceivesPerSecond")? {
        Some(n) if n >= 1 => Ok(Some(n)),
        Some(_) => Err(format!("{path}.maxReceivesPerSecond must be >= 1")),
        None => Ok(None),
    }
}

fn content_type(value: &Value, path: &str, topic: bool) -> Result<Option<String>, Refused> {
    if value.is_null() {
        return Ok(None);
    }
    let map = object(value, path)?;
    only(map, path, &["headerContentType"])?;
    let Some(kind) = map.get("headerContentType").and_then(Value::as_str) else { return Ok(None) };
    let allowed = ["application/json", "text/plain"];
    let base = kind.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    if topic && !allowed.contains(&base.as_str()) {
        return Err(format!("{path}: Content-Type set at the Topic DeliveryPolicy level can only be application/json or text/plain."));
    }
    Ok(Some(kind.to_owned()))
}

fn parse_json(text: &str) -> Result<Value, Refused> {
    serde_json::from_str(text).map_err(|e| format!("Invalid JSON: {e}"))
}

impl TopicPolicy {
    /// A topic's `DeliveryPolicy` attribute; `None` for none (empty, or `{}`).
    pub fn parse(text: &str) -> Result<Option<TopicPolicy>, Refused> {
        if text.trim().is_empty() {
            return Ok(None);
        }
        let value = parse_json(text)?;
        let top = object(&value, "")?;
        let mut policy = TopicPolicy::default();
        for (protocol, inner) in top {
            if protocol != "http" {
                // SNS names the first member it doesn't know, all the way down.
                let mut path = protocol.clone();
                let mut at = inner;
                while let Some((key, next)) = at.as_object().and_then(|m| m.iter().next()) {
                    path = format!("{path}.{key}");
                    at = next;
                }
                return Err(format!("Unexpected JSON member: {path}"));
            }
            let map = object(inner, "http")?;
            only(map, "http", &[
                "defaultHealthyRetryPolicy",
                "defaultSicklyRetryPolicy",
                "defaultThrottlePolicy",
                "defaultRequestPolicy",
                "disableSubscriptionOverrides",
            ])?;
            if let Some(v) = map.get("defaultHealthyRetryPolicy") {
                policy.retry = retry(v, "http.defaultHealthyRetryPolicy")?;
            }
            if let Some(v) = map.get("defaultSicklyRetryPolicy") {
                // Taken, and dropped, as SNS drops it (probed).
                retry(v, "http.defaultSicklyRetryPolicy")?;
            }
            if let Some(v) = map.get("defaultThrottlePolicy") {
                policy.throttle = throttle(v, "http.defaultThrottlePolicy")?;
            }
            if let Some(v) = map.get("defaultRequestPolicy") {
                policy.content_type = content_type(v, "http.defaultRequestPolicy", true)?;
            }
            policy.disable_overrides = map.get("disableSubscriptionOverrides").and_then(Value::as_bool).unwrap_or(false);
        }
        Ok((!top.is_empty()).then_some(policy))
    }

    /// As SNS keeps it, and shows it (`DeliveryPolicy`).
    pub fn json(&self) -> String {
        let mut http = Vec::new();
        if let Some(retry) = &self.retry {
            http.push(format!("\"defaultHealthyRetryPolicy\":{}", retry.json()));
        }
        http.push(format!("\"disableSubscriptionOverrides\":{}", self.disable_overrides));
        if let Some(n) = self.throttle {
            http.push(format!("\"defaultThrottlePolicy\":{{\"maxReceivesPerSecond\":{n}}}"));
        }
        if let Some(kind) = &self.content_type {
            http.push(format!("\"defaultRequestPolicy\":{{\"headerContentType\":{}}}", serde_json::to_string(kind).unwrap()));
        }
        format!("{{\"http\":{{{}}}}}", http.join(","))
    }

    /// A topic's `EffectiveDeliveryPolicy`: its own, or SNS's defaults.
    pub fn effective_json(policy: Option<&TopicPolicy>) -> String {
        let default = TopicPolicy::default();
        let p = policy.unwrap_or(&default);
        let retry = p.retry.unwrap_or(DEFAULT_RETRY);
        let mut http = vec![
            format!("\"defaultHealthyRetryPolicy\":{}", retry.json()),
            format!("\"disableSubscriptionOverrides\":{}", p.disable_overrides),
        ];
        if let Some(n) = p.throttle {
            http.push(format!("\"defaultThrottlePolicy\":{{\"maxReceivesPerSecond\":{n}}}"));
        }
        let kind = p.content_type.as_deref().unwrap_or(DEFAULT_CONTENT_TYPE);
        http.push(format!("\"defaultRequestPolicy\":{{\"headerContentType\":{}}}", serde_json::to_string(kind).unwrap()));
        format!("{{\"http\":{{{}}}}}", http.join(","))
    }
}

impl SubscriptionPolicy {
    /// A subscription's `DeliveryPolicy` attribute; `None` for none.
    pub fn parse(text: &str) -> Result<Option<SubscriptionPolicy>, Refused> {
        if text.trim().is_empty() {
            return Ok(None);
        }
        let value = parse_json(text)?;
        let map = object(&value, "")?;
        if let Some(key) = map.keys().find(|k| {
            !["healthyRetryPolicy", "sicklyRetryPolicy", "throttlePolicy", "requestPolicy", "guaranteed", "healthPolicy"].contains(&k.as_str())
        }) {
            return Err(format!(
                "Invalid JSON: Unrecognized field \"{key}\", not marked as ignorable (6 known properties: \"requestPolicy\", \
                 \"throttlePolicy\", \"healthyRetryPolicy\", \"healthPolicy\", \"sicklyRetryPolicy\", \"guaranteed\")"
            ));
        }
        let mut policy = SubscriptionPolicy::default();
        if let Some(v) = map.get("healthyRetryPolicy") {
            policy.retry = retry(v, "healthyRetryPolicy")?;
        }
        if let Some(v) = map.get("sicklyRetryPolicy") {
            retry(v, "sicklyRetryPolicy")?;
        }
        if let Some(v) = map.get("throttlePolicy") {
            policy.throttle = throttle(v, "throttlePolicy")?;
        }
        if let Some(v) = map.get("requestPolicy") {
            policy.content_type = content_type(v, "requestPolicy", false)?;
        }
        Ok(Some(policy))
    }

    /// As SNS shows it (`DeliveryPolicy`): every member, unset ones null
    /// (probed).
    pub fn json(&self) -> String {
        let retry = self.retry.map_or_else(
            || "null".to_owned(),
            |r| {
                // Phases not set show as null; they're kept as 0.
                r.json()
            },
        );
        let throttle = self.throttle.map_or_else(|| "null".to_owned(), |n| format!("{{\"maxReceivesPerSecond\":{n}}}"));
        let request = self.content_type.as_ref().map_or_else(
            || "null".to_owned(),
            |k| format!("{{\"headerContentType\":{}}}", serde_json::to_string(k).unwrap()),
        );
        format!(
            "{{\"healthyRetryPolicy\":{retry},\"sicklyRetryPolicy\":null,\"throttlePolicy\":{throttle},\"requestPolicy\":{request},\"guaranteed\":false}}"
        )
    }
}

impl Effective {
    /// What applies to a subscription: its own policy's parts, else its
    /// topic's, else SNS's defaults; only its topic's, if that disables
    /// overrides.
    pub fn of(topic: Option<&TopicPolicy>, subscription: Option<&SubscriptionPolicy>) -> Effective {
        let subscription = subscription.filter(|_| !topic.is_some_and(|t| t.disable_overrides));
        Effective {
            retry: subscription.and_then(|s| s.retry).or(topic.and_then(|t| t.retry)).unwrap_or(DEFAULT_RETRY),
            throttle: subscription.and_then(|s| s.throttle).or(topic.and_then(|t| t.throttle)),
            content_type: subscription
                .and_then(|s| s.content_type.clone())
                .or(topic.and_then(|t| t.content_type.clone()))
                .unwrap_or_else(|| DEFAULT_CONTENT_TYPE.to_owned()),
        }
    }

    /// A subscription's `EffectiveDeliveryPolicy` (probed).
    pub fn json(&self) -> String {
        let throttle = self.throttle.map_or_else(|| "null".to_owned(), |n| format!("{{\"maxReceivesPerSecond\":{n}}}"));
        format!(
            "{{\"healthyRetryPolicy\":{},\"sicklyRetryPolicy\":null,\"throttlePolicy\":{throttle},\
             \"requestPolicy\":{{\"headerContentType\":{}}},\"guaranteed\":false}}",
            self.retry.json(),
            serde_json::to_string(&self.content_type).unwrap()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(text: &str) -> String {
        TopicPolicy::parse(text).expect_err("refused")
    }

    #[test]
    fn checks_topic_policies_as_sns_does() {
        let p = |r: &str| format!("{{\"http\":{{\"defaultHealthyRetryPolicy\":{r}}}}}");
        assert_eq!(
            refused(&p(r#"{"minDelayTarget":1,"maxDelayTarget":1,"numRetries":101}"#)),
            "http.defaultHealthyRetryPolicy.numRetries must be less than or equal to 100"
        );
        assert_eq!(
            refused(&p(r#"{"minDelayTarget":30,"maxDelayTarget":20,"numRetries":3}"#)),
            "http.defaultHealthyRetryPolicy.maxDelayTarget must be greater than or equal to minDelayTarget"
        );
        assert_eq!(
            refused(&p(r#"{"minDelayTarget":1,"maxDelayTarget":3601,"numRetries":3}"#)),
            "http.defaultHealthyRetryPolicy.maxDelayTarget must be less than or equal to 3600"
        );
        assert_eq!(
            refused(&p(r#"{"minDelayTarget":3600,"maxDelayTarget":3600,"numRetries":2}"#)),
            "http.defaultHealthyRetryPolicy: Total policy retry time cannot be greater than 3600 seconds"
        );
        assert_eq!(
            refused(&p(r#"{"minDelayTarget":0,"maxDelayTarget":1,"numRetries":1}"#)),
            "http.defaultHealthyRetryPolicy.minDelayTarget must be greater than or equal to 1"
        );
        assert_eq!(refused(&p(r#"{"numRetries":5}"#)), "http.defaultHealthyRetryPolicy.minDelayTarget must be specified");
        assert_eq!(
            refused(&p(r#"{"minDelayTarget":1,"maxDelayTarget":2,"numRetries":1,"bogus":1}"#)),
            "Unexpected JSON member: http.defaultHealthyRetryPolicy.bogus"
        );
        assert_eq!(
            refused(r#"{"sqs":{"defaultHealthyRetryPolicy":{"numRetries":1}}}"#),
            "Unexpected JSON member: sqs.defaultHealthyRetryPolicy.numRetries"
        );
        assert_eq!(
            refused(r#"{"http":{"defaultThrottlePolicy":{"maxReceivesPerSecond":0}}}"#),
            "http.defaultThrottlePolicy.maxReceivesPerSecond must be >= 1"
        );
        assert!(refused("{").starts_with("Invalid JSON:"));
        assert_eq!(TopicPolicy::parse("{}").unwrap(), None);
        assert_eq!(TopicPolicy::parse("").unwrap(), None);
    }

    #[test]
    fn shows_policies_as_sns_does() {
        let text = r#"{"http":{"defaultHealthyRetryPolicy":{"minDelayTarget":5,"maxDelayTarget":20,"numRetries":6,"numNoDelayRetries":1,"numMinDelayRetries":1,"numMaxDelayRetries":1,"backoffFunction":"exponential"}}}"#;
        let policy = TopicPolicy::parse(text).unwrap().unwrap();
        assert_eq!(
            policy.json(),
            r#"{"http":{"defaultHealthyRetryPolicy":{"minDelayTarget":5,"maxDelayTarget":20,"numRetries":6,"numMaxDelayRetries":1,"numNoDelayRetries":1,"numMinDelayRetries":1,"backoffFunction":"exponential"},"disableSubscriptionOverrides":false}}"#
        );
        assert_eq!(
            TopicPolicy::effective_json(None),
            r#"{"http":{"defaultHealthyRetryPolicy":{"minDelayTarget":20,"maxDelayTarget":20,"numRetries":3,"numMaxDelayRetries":0,"numNoDelayRetries":0,"numMinDelayRetries":0,"backoffFunction":"linear"},"disableSubscriptionOverrides":false,"defaultRequestPolicy":{"headerContentType":"text/plain; charset=UTF-8"}}}"#
        );
        // A subscription without a policy of its own takes its topic's.
        let effective = Effective::of(Some(&policy), None);
        assert_eq!(effective.retry, policy.retry.unwrap());
        assert!(effective.json().starts_with(r#"{"healthyRetryPolicy":{"minDelayTarget":5,"#));
        // The phases: one at once, one after the least, three backing off,
        // one after the most.
        let r = policy.retry.unwrap();
        let delays: Vec<u32> = (1..=6).map(|n| r.delay(n).unwrap()).collect();
        assert_eq!(delays[0], 0);
        assert_eq!(delays[1], 5);
        assert!(delays[2] > 5 && delays[2] < delays[3] && delays[4] == 20);
        assert_eq!(delays[5], 20);
        assert_eq!(r.delay(7), None);
        // SNS's default.
        assert_eq!((1..=4).map(|n| DEFAULT_RETRY.delay(n)).collect::<Vec<_>>(), [Some(20), Some(20), Some(20), None]);
    }

    #[test]
    fn checks_subscription_policies() {
        assert!(SubscriptionPolicy::parse(r#"{"http":{}}"#).unwrap_err().starts_with("Invalid JSON: Unrecognized field \"http\""));
        assert_eq!(
            SubscriptionPolicy::parse(r#"{"healthyRetryPolicy":{"minDelayTarget":1,"maxDelayTarget":1,"numRetries":101}}"#).unwrap_err(),
            "healthyRetryPolicy.numRetries must be less than or equal to 100"
        );
        let p = SubscriptionPolicy::parse(r#"{"throttlePolicy":{"maxReceivesPerSecond":2}}"#).unwrap().unwrap();
        assert_eq!(
            p.json(),
            r#"{"healthyRetryPolicy":null,"sicklyRetryPolicy":null,"throttlePolicy":{"maxReceivesPerSecond":2},"requestPolicy":null,"guaranteed":false}"#
        );
    }
}
