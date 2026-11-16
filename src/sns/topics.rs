//! SNS's topics: CreateTopic, DeleteTopic, ListTopics, Get- and
//! SetTopicAttributes, Add- and RemovePermission, and tags, as SNS answers
//! them (probed, see `plans/notifications.md`).

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hyper::StatusCode;
use serde_json::{Value, json};

use super::{Params, Result, Sns, Topic, attributes_xml, default_policy, error, invalid, parse_arn, topic_arn};
use crate::{
    db::Cached,
    notifications::delivery_policy::TopicPolicy,
    policy::{Context, Kind},
    s3::{actions::On, util::xml_escape},
};

/// The attributes a topic takes, which Cairn keeps.
const SETTABLE: &[&str] = &["DisplayName", "Policy", "DeliveryPolicy", "SignatureVersion"];

/// SNS's other attributes, which Cairn has nothing of: refused, rather than
/// taken and ignored.
const UNSUPPORTED: &[&str] = &[
    "KmsMasterKeyId",
    "FifoTopic",
    "ContentBasedDeduplication",
    "FifoThroughputScope",
    "TracingConfig",
    "ArchivePolicy",
    "DataProtectionPolicy",
    "HTTPSuccessFeedbackRoleArn",
    "HTTPSuccessFeedbackSampleRate",
    "HTTPFailureFeedbackRoleArn",
    "ApplicationSuccessFeedbackRoleArn",
    "ApplicationSuccessFeedbackSampleRate",
    "ApplicationFailureFeedbackRoleArn",
    "FirehoseSuccessFeedbackRoleArn",
    "FirehoseSuccessFeedbackSampleRate",
    "FirehoseFailureFeedbackRoleArn",
    "LambdaSuccessFeedbackRoleArn",
    "LambdaSuccessFeedbackSampleRate",
    "LambdaFailureFeedbackRoleArn",
    "SQSSuccessFeedbackRoleArn",
    "SQSSuccessFeedbackSampleRate",
    "SQSFailureFeedbackRoleArn",
];

/// The most tags a topic has, and a page of ListTopics.
const MAX_TAGS: usize = 50;
const PAGE: i64 = 100;

/// Whether `name` is a topic's: letters, digits, `-` and `_`, 1 to 256 of
/// them (probed; no FIFO topics, so no `.fifo`).
fn valid_name(name: &str) -> bool {
    (1..=256).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A topic's attribute, as it's to be kept.
enum Value_ {
    DisplayName(String),
    /// Its normalized text.
    Policy(String),
    /// Its normalized text; `None` to clear it.
    DeliveryPolicy(Option<String>),
    SignatureVersion(i16),
}

impl Sns<'_> {
    /// Checks attribute `name` set to `value` for topic `arn`, as SNS does
    /// (`what` says how its errors name it: `Attributes`, or the name).
    async fn attribute(&self, arn: &str, name: &str, value: &str, create: bool) -> Result<Value_> {
        match name {
            "DisplayName" => {
                if value.chars().count() > 100 {
                    return Err(invalid("DisplayName Reason: must be at most 100 characters"));
                }
                Ok(Value_::DisplayName(value.to_owned()))
            }
            "Policy" => match crate::s3::buckets::policy::check_as(self.client, Kind::Topic(arn), value).await? {
                Ok(checked) => Ok(Value_::Policy(checked.normalized)),
                // SNS says nothing more (probed).
                Err(_) => Err(invalid("Policy Error: null")),
            },
            "DeliveryPolicy" => match TopicPolicy::parse(value) {
                Ok(policy) => Ok(Value_::DeliveryPolicy(policy.map(|p| p.json()))),
                Err(why) => Err(invalid(format!("DeliveryPolicy: {why}"))),
            },
            "SignatureVersion" => match value {
                "1" => Ok(Value_::SignatureVersion(1)),
                "2" => Ok(Value_::SignatureVersion(2)),
                other => Err(invalid(format!("SignatureVersion: Invalid value '[{other}]'. Must be 1 or 2."))),
            },
            other if UNSUPPORTED.contains(&other) => Err(invalid(match create {
                true => format!("Attributes Reason: Cairn's SNS doesn't support the attribute {other}"),
                false => format!("AttributeName Reason: Cairn's SNS doesn't support the attribute {other}"),
            })),
            other => Err(invalid(match create {
                true => format!("Attributes Reason: Unknown attribute {other}"),
                false => "AttributeName".to_owned(),
            })),
        }
    }

    pub(super) async fn create_topic(&mut self, params: &Params) -> Result<Option<String>> {
        let name = params.required("Name")?.to_owned();
        if !valid_name(&name) {
            return Err(invalid("Topic Name"));
        }
        let account = self.account().to_owned();
        let arn = topic_arn(&account, &name);
        let tags = params.tags();
        check_tags(&tags)?;
        let mut context = Context::default();
        for (key, value) in &tags {
            context.set(&format!("aws:RequestTag/{key}"), value.clone());
        }
        if !tags.is_empty() {
            context.set_all("aws:TagKeys", tags.iter().map(|(k, _)| k.clone()).collect());
        }
        self.check("sns:CreateTopic", On::Topic(account.clone(), name.clone()), None, &context).await?;
        let mut values = Vec::new();
        for (key, value) in params.entries("Attributes") {
            values.push((key.clone(), self.attribute(&arn, &key, &value, true).await?));
        }
        if let Some(existing) = Topic::load(self.client, &account, &name).await? {
            // The same topic again: only if it's asked for as it is.
            let same = values.iter().all(|(_, v)| match v {
                Value_::DisplayName(d) => *d == existing.display_name,
                Value_::Policy(p) => *p == existing.policy,
                Value_::DeliveryPolicy(p) => *p == existing.delivery_policy,
                Value_::SignatureVersion(n) => *n == existing.signature_version,
            });
            if !same {
                return Err(invalid("Attributes Reason: Topic already exists with different attributes"));
            }
            let mut asked = tags.clone();
            let mut has = existing.tags.clone();
            asked.sort();
            has.sort();
            if !tags.is_empty() && asked != has {
                return Err(invalid("Tags Reason: Topic already exists with different tags"));
            }
            return Ok(Some(format!("<TopicArn>{}</TopicArn>", xml_escape(&arn))));
        }
        let mut display_name = String::new();
        let mut policy = default_policy(&account, &arn);
        let mut delivery_policy = None;
        let mut signature_version = 1i16;
        for (_, value) in values {
            match value {
                Value_::DisplayName(d) => display_name = d,
                Value_::Policy(p) => policy = p,
                Value_::DeliveryPolicy(p) => delivery_policy = p,
                Value_::SignatureVersion(n) => signature_version = n,
            }
        }
        let tags_json = serde_json::to_string(&tags).expect("tags serialize");
        self.client
            .execute_cached(
                "INSERT INTO sns_topics (account_id, name, display_name, policy, delivery_policy, signature_version, tags)
                 VALUES ($1, $2, $3, $4, $5, $6, $7::text::jsonb) ON CONFLICT (account_id, name) DO NOTHING",
                &[&account, &name, &display_name, &policy, &delivery_policy, &signature_version, &tags_json],
            )
            .await?;
        Ok(Some(format!("<TopicArn>{}</TopicArn>", xml_escape(&arn))))
    }

    pub(super) async fn delete_topic(&mut self, params: &Params) -> Result<Option<String>> {
        let (account, name) = parse_arn(params.required("TopicArn")?, "TopicArn")?;
        let topic = Topic::load(self.client, &account, &name).await?;
        self.check("sns:DeleteTopic", On::Topic(account.clone(), name.clone()), topic.as_ref(), &Context::default()).await?;
        // Deleting one that isn't there is no error (probed); its
        // subscriptions and their deliveries go with it.
        self.client
            .execute_cached("DELETE FROM sns_topics WHERE account_id = $1 AND name = $2", &[&account, &name])
            .await?;
        Ok(None)
    }

    pub(super) async fn list_topics(&mut self, params: &Params) -> Result<Option<String>> {
        let account = self.account().to_owned();
        let on = On::Arn(topic_arn(&account, "*"));
        self.check("sns:ListTopics", on, None, &Context::default()).await?;
        let after = match params.get("NextToken") {
            Some(token) => Some(
                URL_SAFE_NO_PAD
                    .decode(token)
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .ok_or_else(|| invalid("NextToken"))?,
            ),
            None => None,
        };
        let rows = self
            .client
            .query_cached(
                "SELECT name FROM sns_topics WHERE account_id = $1 AND ($2::text IS NULL OR name > $2) ORDER BY name LIMIT $3",
                &[&account, &after, &(PAGE + 1)],
            )
            .await?;
        let names: Vec<String> = rows.iter().map(|r| r.get(0)).collect();
        let more = names.len() as i64 > PAGE;
        let names = &names[..names.len().min(PAGE as usize)];
        let members: String = names
            .iter()
            .map(|n| format!("<member><TopicArn>{}</TopicArn></member>", xml_escape(&topic_arn(&account, n))))
            .collect();
        let next = match (more, names.last()) {
            (true, Some(last)) => format!("<NextToken>{}</NextToken>", URL_SAFE_NO_PAD.encode(last)),
            _ => String::new(),
        };
        Ok(Some(format!("<Topics>{members}</Topics>{next}")))
    }

    pub(super) async fn get_topic_attributes(&mut self, params: &Params) -> Result<Option<String>> {
        let topic = self.topic(params.required("TopicArn")?).await?;
        self.check("sns:GetTopicAttributes", On::Topic(topic.account.clone(), topic.name.clone()), Some(&topic), &Context::default())
            .await?;
        let counts = self
            .client
            .query_one_cached(
                "SELECT count(*) FILTER (WHERE state = 'pending'), count(*) FILTER (WHERE state = 'confirmed'),
                        count(*) FILTER (WHERE state = 'deleted')
                 FROM sns_subscriptions WHERE topic_id = $1",
                &[&topic.id],
            )
            .await?;
        let count = |i: usize| counts.get::<_, i64>(i).to_string();
        let policy = topic.delivery_policy();
        let mut attributes = vec![
            ("Policy", topic.policy.clone()),
            ("Owner", topic.account.clone()),
            ("SubscriptionsPending", count(0)),
            ("TopicArn", topic.arn()),
            ("EffectiveDeliveryPolicy", TopicPolicy::effective_json(policy.as_ref())),
            ("SubscriptionsConfirmed", count(1)),
            ("DisplayName", topic.display_name.clone()),
            ("SubscriptionsDeleted", count(2)),
        ];
        if let Some(policy) = &policy {
            attributes.push(("DeliveryPolicy", policy.json()));
        }
        if topic.signature_version != 1 {
            attributes.push(("SignatureVersion", topic.signature_version.to_string()));
        }
        Ok(Some(attributes_xml(&attributes)))
    }

    pub(super) async fn set_topic_attributes(&mut self, params: &Params) -> Result<Option<String>> {
        let topic = self.topic(params.required("TopicArn")?).await?;
        let name = params.required("AttributeName")?.to_owned();
        let value = params.get("AttributeValue").unwrap_or("").to_owned();
        self.check("sns:SetTopicAttributes", On::Topic(topic.account.clone(), topic.name.clone()), Some(&topic), &Context::default())
            .await?;
        if !SETTABLE.contains(&name.as_str()) && !UNSUPPORTED.contains(&name.as_str()) {
            return Err(invalid("AttributeName"));
        }
        let (column, text, number) = match self.attribute(&topic.arn(), &name, &value, false).await? {
            Value_::DisplayName(d) => ("display_name", Some(d), None),
            Value_::Policy(p) => ("policy", Some(p), None),
            Value_::DeliveryPolicy(p) => ("delivery_policy", p, None),
            Value_::SignatureVersion(n) => ("signature_version", None, Some(n)),
        };
        match number {
            Some(n) => {
                self.client.execute_cached("UPDATE sns_topics SET signature_version = $2 WHERE id = $1", &[&topic.id, &n]).await?;
            }
            None => {
                let sql = format!("UPDATE sns_topics SET {column} = $2 WHERE id = $1");
                self.client.execute_cached(&sql, &[&topic.id, &text]).await?;
            }
        }
        Ok(None)
    }

    /// AddPermission: a statement allowing accounts actions on the topic,
    /// by its label, added to the topic's policy.
    pub(super) async fn add_permission(&mut self, params: &Params) -> Result<Option<String>> {
        let topic = self.topic(params.required("TopicArn")?).await?;
        let label = params.required("Label")?.to_owned();
        let accounts = params.members("AWSAccountId");
        let actions = params.members("ActionName");
        self.check("sns:AddPermission", On::Topic(topic.account.clone(), topic.name.clone()), Some(&topic), &Context::default()).await?;
        if label.is_empty() || label.len() > 80 || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return Err(invalid("Label"));
        }
        if accounts.is_empty() || actions.is_empty() {
            return Err(invalid(if accounts.is_empty() { "AWSAccountId" } else { "ActionName" }));
        }
        let mut policy: Value = serde_json::from_str(&topic.policy).map_err(anyhow::Error::from)?;
        let statements = policy["Statement"].as_array_mut().ok_or_else(|| anyhow::anyhow!("a topic's policy without statements"))?;
        if statements.iter().any(|s| s["Sid"] == label.as_str()) {
            return Err(invalid("Statement already exists"));
        }
        let principals: Vec<String> = accounts.iter().map(|a| format!("arn:aws:iam::{a}:root")).collect();
        let actions: Vec<String> = actions.iter().map(|a| format!("SNS:{a}")).collect();
        statements.push(json!({
            "Sid": label,
            "Effect": "Allow",
            "Principal": {"AWS": principals},
            "Action": actions,
            "Resource": topic.arn(),
        }));
        self.store_policy(&topic, &policy.to_string()).await
    }

    pub(super) async fn remove_permission(&mut self, params: &Params) -> Result<Option<String>> {
        let topic = self.topic(params.required("TopicArn")?).await?;
        let label = params.required("Label")?.to_owned();
        self.check("sns:RemovePermission", On::Topic(topic.account.clone(), topic.name.clone()), Some(&topic), &Context::default())
            .await?;
        let mut policy: Value = serde_json::from_str(&topic.policy).map_err(anyhow::Error::from)?;
        let statements = policy["Statement"].as_array_mut().ok_or_else(|| anyhow::anyhow!("a topic's policy without statements"))?;
        let before = statements.len();
        statements.retain(|s| s["Sid"] != label.as_str());
        if statements.len() == before {
            return Err(invalid("Statement does not exist"));
        }
        // A policy without statements isn't one: the topic's is the default.
        let text = match statements.is_empty() {
            true => default_policy(&topic.account, &topic.arn()),
            false => policy.to_string(),
        };
        self.store_policy(&topic, &text).await
    }

    async fn store_policy(&mut self, topic: &Topic, text: &str) -> Result<Option<String>> {
        let normalized = match self.attribute(&topic.arn(), "Policy", text, false).await? {
            Value_::Policy(p) => p,
            _ => unreachable!("a policy is a policy"),
        };
        self.client.execute_cached("UPDATE sns_topics SET policy = $2 WHERE id = $1", &[&topic.id, &normalized]).await?;
        Ok(None)
    }

    /// The topic a tagging request's `ResourceArn` names.
    async fn tagged(&mut self, params: &Params) -> Result<Topic> {
        let arn = params.required("ResourceArn")?.to_owned();
        match parse_arn(&arn, "ResourceArn") {
            Ok(_) => self.topic(&arn).await.map_err(|e| match e.status {
                StatusCode::NOT_FOUND => error(StatusCode::NOT_FOUND, "ResourceNotFound", "Resource does not exist"),
                _ => e,
            }),
            Err(e) => Err(e),
        }
    }

    pub(super) async fn tag_resource(&mut self, params: &Params) -> Result<Option<String>> {
        let topic = self.tagged(params).await?;
        let tags = params.tags();
        if tags.is_empty() {
            return Err(invalid("Tags Reason: No value was provided for Tags"));
        }
        check_tags(&tags)?;
        let mut context = Context::default();
        for (key, value) in &tags {
            context.set(&format!("aws:RequestTag/{key}"), value.clone());
        }
        context.set_all("aws:TagKeys", tags.iter().map(|(k, _)| k.clone()).collect());
        self.check("sns:TagResource", On::Topic(topic.account.clone(), topic.name.clone()), Some(&topic), &context).await?;
        self.retag(&topic, |current| {
            for (key, value) in &tags {
                match current.iter_mut().find(|(k, _)| k == key) {
                    Some(slot) => slot.1 = value.clone(),
                    None => current.push((key.clone(), value.clone())),
                }
            }
        })
        .await
    }

    pub(super) async fn untag_resource(&mut self, params: &Params) -> Result<Option<String>> {
        let topic = self.tagged(params).await?;
        let keys = params.members("TagKeys");
        if keys.is_empty() {
            return Err(invalid("TagKeys Reason: No value was provided for TagKeys"));
        }
        let mut context = Context::default();
        context.set_all("aws:TagKeys", keys.clone());
        self.check("sns:UntagResource", On::Topic(topic.account.clone(), topic.name.clone()), Some(&topic), &context).await?;
        self.retag(&topic, |current| current.retain(|(k, _)| !keys.contains(k))).await
    }

    /// Changes the topic's tags as `change` does, under its row's lock, so
    /// that two changes don't lose one, nor exceed the limit together.
    async fn retag(&mut self, topic: &Topic, change: impl Fn(&mut Vec<(String, String)>)) -> Result<Option<String>> {
        let mut client = self.app.pool.get().await?;
        let tx = client.transaction().await?;
        let Some(row) = tx.query_opt("SELECT tags::text FROM sns_topics WHERE id = $1 FOR UPDATE", &[&topic.id]).await? else {
            return Err(error(StatusCode::NOT_FOUND, "ResourceNotFound", "Resource does not exist"));
        };
        let mut tags: Vec<(String, String)> = serde_json::from_str(row.get::<_, &str>(0)).map_err(anyhow::Error::from)?;
        change(&mut tags);
        if tags.len() > MAX_TAGS {
            return Err(error(StatusCode::BAD_REQUEST, "TagLimitExceeded", "Could not complete request: tag quota of per resource exceeded"));
        }
        let text = serde_json::to_string(&tags).expect("tags serialize");
        tx.execute("UPDATE sns_topics SET tags = $2::text::jsonb WHERE id = $1", &[&topic.id, &text]).await?;
        tx.commit().await?;
        Ok(None)
    }

    pub(super) async fn list_tags_for_resource(&mut self, params: &Params) -> Result<Option<String>> {
        let topic = self.tagged(params).await?;
        self.check("sns:ListTagsForResource", On::Topic(topic.account.clone(), topic.name.clone()), Some(&topic), &Context::default())
            .await?;
        let members: String = topic
            .tags
            .iter()
            .map(|(k, v)| format!("<member><Key>{}</Key><Value>{}</Value></member>", xml_escape(k), xml_escape(v)))
            .collect();
        Ok(Some(format!("<Tags>{members}</Tags>")))
    }
}

/// Tags, checked as SNS checks them: at most 50, keys of 1 to 128
/// characters, values of at most 256, no key twice, no `aws:` keys.
fn check_tags(tags: &[(String, String)]) -> Result<()> {
    if tags.len() > MAX_TAGS {
        return Err(error(StatusCode::BAD_REQUEST, "TagLimitExceeded", "Could not complete request: tag quota of per resource exceeded"));
    }
    for (i, (key, value)) in tags.iter().enumerate() {
        let fine = |t: &str| t.chars().all(crate::users::tag_char);
        if key.is_empty() || key.chars().count() > 128 || !fine(key) {
            return Err(invalid("Tags Reason: invalid tag key"));
        }
        if value.chars().count() > 256 || !fine(value) {
            return Err(invalid("Tags Reason: invalid tag value"));
        }
        if key.to_ascii_lowercase().starts_with("aws:") {
            return Err(error(StatusCode::BAD_REQUEST, "InvalidParameter", "Invalid parameter: Tags Reason: aws: is a reserved prefix"));
        }
        if tags[..i].iter().any(|(k, _)| k == key) {
            return Err(invalid("Tags Reason: Duplicate tag keys"));
        }
    }
    Ok(())
}

