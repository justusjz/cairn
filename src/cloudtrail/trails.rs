//! Trails: an account's, each delivering its events (those its selectors
//! select, see `selectors`) to a bucket, as CloudTrail's log files (see
//! `delivery`), while it's logging. A trail is its account's, by its name,
//! in Cairn's one region: so every trail is "multi-region" in effect, and
//! has every event; `IsMultiRegionTrail` is kept, and given back, as it's
//! set.

use deadpool_postgres::GenericClient;
use serde_json::{Value, json};

use super::selectors::Selectors;
use crate::db::Cached;

/// The most trails an account may have (CloudTrail's, per region).
pub const MAX_TRAILS: i64 = 5;
/// The most tags a trail may have.
pub const MAX_TAGS: usize = 50;
/// The longest key prefix a trail's log files may have.
pub const MAX_PREFIX: usize = 200;

/// The services whose events are global (IAM's, ...): a trail that doesn't
/// include global service events doesn't deliver theirs.
const GLOBAL: &[&str] = &[
    "iam.amazonaws.com",
    "organizations.amazonaws.com",
    "signin.amazonaws.com",
];

/// A trail.
#[derive(Clone, Debug)]
pub struct Trail {
    pub account: String,
    pub name: String,
    pub bucket: String,
    pub prefix: Option<String>,
    pub include_global: bool,
    pub multi_region: bool,
    /// The KMS key its log files are encrypted with (SSE-KMS), as it was
    /// given (an ARN, an alias's ARN).
    pub kms_key_id: Option<String>,
    /// Its selectors, if they were set (else every management event).
    pub selectors: Option<Selectors>,
    pub tags: Vec<(String, String)>,
    pub logging: bool,
    /// When it last started and stopped logging, in seconds.
    pub started: Option<f64>,
    pub stopped: Option<f64>,
    /// When it last delivered a file, last tried to, whether that
    /// succeeded, and the last error, if the last attempt failed.
    pub delivered: Option<f64>,
    pub attempted: Option<f64>,
    pub attempt_ok: Option<bool>,
    pub error: Option<String>,
}

/// The columns a trail is loaded from (see `Trail::from_row`).
pub const COLUMNS: &str = "account_id, name, bucket, prefix, include_global, multi_region,
    kms_key_id, selectors::text, tags::text, logging,
    extract(epoch FROM started_at)::float8, extract(epoch FROM stopped_at)::float8,
    extract(epoch FROM delivered_at)::float8, extract(epoch FROM attempted_at)::float8,
    attempt_ok, delivery_error";

/// A trail's ARN.
pub fn arn(account: &str, name: &str) -> String {
    format!(
        "arn:aws:cloudtrail:{}:{account}:trail/{name}",
        crate::s3::buckets::head::REGION
    )
}

/// Whether `name` may be a trail's: 3 to 128 letters, digits, `.`, `_` and
/// `-`, starting and ending with a letter or digit, without two of `._-`
/// together, and not like an IP address.
pub fn valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    let punctuation = |b: &u8| b"._-".contains(b);
    (3..=128).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || punctuation(b))
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && !bytes
            .windows(2)
            .any(|w| punctuation(&w[0]) && punctuation(&w[1]))
        && name.parse::<std::net::Ipv4Addr>().is_err()
}

/// What a request names a trail by.
#[derive(Debug, PartialEq)]
pub enum Named {
    /// One of `account`'s, by this name.
    Trail(String),
    /// An ARN that isn't of `account`'s trails (another account's or
    /// region's): there's no such trail for it.
    Elsewhere,
}

/// Why a trail's name or ARN isn't one.
#[derive(Debug, PartialEq)]
pub enum BadName {
    /// Not a name a trail may have.
    Name,
    /// Not a trail's ARN.
    Arn,
}

/// The trail `given` names, a name or an ARN, for a request of `account`.
pub fn named(given: &str, account: &str) -> Result<Named, BadName> {
    let Some(rest) = given.strip_prefix("arn:") else {
        return match valid_name(given) {
            true => Ok(Named::Trail(given.to_owned())),
            false => Err(BadName::Name),
        };
    };
    let parts: Vec<&str> = rest.splitn(5, ':').collect();
    let [partition, "cloudtrail", region, owner, resource] = parts[..] else {
        return Err(BadName::Arn);
    };
    let Some(name) = resource.strip_prefix("trail/") else {
        return Err(BadName::Arn);
    };
    if partition != "aws" || owner.len() != 12 || !owner.bytes().all(|b| b.is_ascii_digit()) {
        return Err(BadName::Arn);
    }
    if !valid_name(name) {
        return Err(BadName::Arn);
    }
    match region == crate::s3::buckets::head::REGION && owner == account {
        true => Ok(Named::Trail(name.to_owned())),
        false => Ok(Named::Elsewhere),
    }
}

impl Trail {
    pub fn from_row(row: &tokio_postgres::Row) -> anyhow::Result<Trail> {
        let selectors = match row.get::<_, Option<String>>(7) {
            None => None,
            Some(text) => {
                let Value::Object(members) = serde_json::from_str(&text)? else {
                    anyhow::bail!("a trail's stored selectors aren't an object");
                };
                Some(
                    Selectors::parse(&members)
                        .map_err(|e| anyhow::anyhow!("a trail's stored selectors: {}", e.0))?,
                )
            }
        };
        let tags: Vec<Value> = serde_json::from_str(row.get(8))?;
        let tags = tags
            .iter()
            .map(|t| {
                (
                    t["Key"].as_str().unwrap_or_default().to_owned(),
                    t["Value"].as_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        Ok(Trail {
            account: row.get(0),
            name: row.get(1),
            bucket: row.get(2),
            prefix: row.get(3),
            include_global: row.get(4),
            multi_region: row.get(5),
            kms_key_id: row.get(6),
            selectors,
            tags,
            logging: row.get(9),
            started: row.get(10),
            stopped: row.get(11),
            delivered: row.get(12),
            attempted: row.get(13),
            attempt_ok: row.get(14),
            error: row.get(15),
        })
    }

    /// `account`'s trail `name`, if there's one.
    pub async fn load(
        client: &impl GenericClient,
        account: &str,
        name: &str,
    ) -> anyhow::Result<Option<Trail>> {
        let sql =
            format!("SELECT {COLUMNS} FROM cloudtrail_trails WHERE account_id = $1 AND name = $2");
        client
            .query_opt_cached(&sql, &[&account, &name])
            .await?
            .map(|row| Trail::from_row(&row))
            .transpose()
    }

    /// `account`'s trails, by their names.
    pub async fn list(client: &impl GenericClient, account: &str) -> anyhow::Result<Vec<Trail>> {
        let sql =
            format!("SELECT {COLUMNS} FROM cloudtrail_trails WHERE account_id = $1 ORDER BY name");
        client
            .query_cached(&sql, &[&account])
            .await?
            .iter()
            .map(Trail::from_row)
            .collect()
    }

    pub fn arn(&self) -> String {
        arn(&self.account, &self.name)
    }

    /// What its log files' keys start with: its prefix (and `/`), then
    /// `AWSLogs/<account>/CloudTrail/<region>/`.
    pub fn key_prefix(&self) -> String {
        key_prefix(self.prefix.as_deref(), &self.account)
    }

    /// Whether it delivers `record`: one of its account's events, while it
    /// was logging, that its selectors select.
    pub fn delivers(&self, record: &Value) -> bool {
        if record["recipientAccountId"].as_str() != Some(&self.account) {
            return false;
        }
        let Some(started) = self.started else {
            return false;
        };
        let Some(time) = record["eventTime"].as_str().and_then(event_time) else {
            return false;
        };
        // Events are timed to the second: those of the second it started
        // in are its.
        if time < started.floor() as i64 {
            return false;
        }
        if !self.logging && self.stopped.is_some_and(|stopped| time > stopped as i64) {
            return false;
        }
        let source = record["eventSource"].as_str().unwrap_or("");
        if !self.include_global && GLOBAL.contains(&source) {
            return false;
        }
        match &self.selectors {
            Some(selectors) => selectors.select(record),
            None => Selectors::default().select(record),
        }
    }

    /// As `DescribeTrails` and `GetTrail` answer.
    pub fn to_json(&self) -> Value {
        let mut trail = self.settings();
        trail["HomeRegion"] = json!(crate::s3::buckets::head::REGION);
        trail["HasCustomEventSelectors"] = json!(self.selectors.is_some());
        trail["HasInsightSelectors"] = json!(false);
        trail
    }

    /// As `CreateTrail` and `UpdateTrail` answer.
    pub fn settings(&self) -> Value {
        let mut trail = json!({
            "Name": self.name,
            "S3BucketName": self.bucket,
            "IncludeGlobalServiceEvents": self.include_global,
            "IsMultiRegionTrail": self.multi_region,
            "TrailARN": self.arn(),
            "LogFileValidationEnabled": false,
            "IsOrganizationTrail": false,
        });
        if let Some(prefix) = &self.prefix {
            trail["S3KeyPrefix"] = json!(prefix);
        }
        if let Some(key) = &self.kms_key_id {
            trail["KmsKeyId"] = json!(key);
        }
        trail
    }

    /// Its tags, as the API has them.
    pub fn tags_json(&self) -> Value {
        tags_json(&self.tags)
    }
}

/// `tags`, as the API (and the database) has them.
pub fn tags_json(tags: &[(String, String)]) -> Value {
    Value::Array(
        tags.iter()
            .map(|(k, v)| json!({ "Key": k, "Value": v }))
            .collect(),
    )
}

/// What the log files of `account`'s trail with `prefix` start with.
pub fn key_prefix(prefix: Option<&str>, account: &str) -> String {
    let region = crate::s3::buckets::head::REGION;
    let logs = format!("AWSLogs/{account}/CloudTrail/{region}/");
    match prefix {
        Some(prefix) if !prefix.is_empty() => format!("{prefix}/{logs}"),
        _ => logs,
    }
}

/// An event's time (`eventTime`, `2026-11-16T05:06:07Z`), in seconds.
pub fn event_time(text: &str) -> Option<i64> {
    crate::backup::restore::parse_time(text)
        .ok()
        .map(|millis| millis.div_euclid(1000))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_checked() {
        for name in ["abc", "my-trail", "Trail_1.x", "a1b"] {
            assert!(valid_name(name), "{name}");
        }
        for name in [
            "ab",
            "-abc",
            "abc-",
            "my--trail",
            "my-_trail",
            "has space",
            "192.168.5.4",
            &"a".repeat(129),
        ] {
            assert!(!valid_name(name), "{name}");
        }
    }

    #[test]
    fn trails_are_named_by_names_or_arns() {
        let account = "111122223333";
        let region = crate::s3::buckets::head::REGION;
        assert_eq!(named("t1x", account), Ok(Named::Trail("t1x".to_owned())));
        assert_eq!(
            named(&arn(account, "t1x"), account),
            Ok(Named::Trail("t1x".to_owned()))
        );
        assert_eq!(
            named(&arn("444455556666", "t1x"), account),
            Ok(Named::Elsewhere)
        );
        assert_eq!(
            named(
                &format!("arn:aws:cloudtrail:elsewhere-1:{account}:trail/t1x"),
                account
            ),
            Ok(Named::Elsewhere)
        );
        assert_eq!(named("a b", account), Err(BadName::Name));
        assert_eq!(
            named(&format!("arn:aws:s3:{region}:{account}:trail/t1x"), account),
            Err(BadName::Arn)
        );
        assert_eq!(
            named(
                &format!("arn:aws:cloudtrail:{region}:{account}:t1x"),
                account
            ),
            Err(BadName::Arn)
        );
    }

    #[test]
    fn keys_are_cloudtrails() {
        let region = crate::s3::buckets::head::REGION;
        assert_eq!(
            key_prefix(None, "111122223333"),
            format!("AWSLogs/111122223333/CloudTrail/{region}/")
        );
        assert_eq!(
            key_prefix(Some("p/q"), "111122223333"),
            format!("p/q/AWSLogs/111122223333/CloudTrail/{region}/")
        );
    }

    #[test]
    fn trails_deliver_their_events_while_logging() {
        let mut trail = Trail {
            account: "111122223333".to_owned(),
            name: "t1x".to_owned(),
            bucket: "b".to_owned(),
            prefix: None,
            include_global: false,
            multi_region: false,
            kms_key_id: None,
            selectors: None,
            tags: Vec::new(),
            logging: true,
            // 2026-11-16T05:06:07.5Z.
            started: Some(1_794_805_567.5),
            stopped: None,
            delivered: None,
            attempted: None,
            attempt_ok: None,
            error: None,
        };
        let record = |account: &str, time: &str, source: &str| {
            json!({
                "recipientAccountId": account,
                "eventTime": time,
                "eventSource": source,
                "readOnly": true,
                "managementEvent": true,
            })
        };
        let kms = "kms.amazonaws.com";
        assert!(trail.delivers(&record("111122223333", "2026-11-16T05:06:07Z", kms)));
        assert!(!trail.delivers(&record("111122223333", "2026-11-16T05:06:06Z", kms)));
        assert!(!trail.delivers(&record("444455556666", "2026-11-16T05:06:08Z", kms)));
        assert!(!trail.delivers(&record(
            "111122223333",
            "2026-11-16T05:06:08Z",
            "iam.amazonaws.com"
        )));
        trail.logging = false;
        trail.stopped = Some(1_794_805_600.0);
        assert!(trail.delivers(&record("111122223333", "2026-11-16T05:06:40Z", kms)));
        assert!(!trail.delivers(&record("111122223333", "2026-11-16T05:06:41Z", kms)));
    }
}
