//! A bucket's notification configuration: PutBucketNotificationConfiguration
//! and GetBucketNotificationConfiguration (`?notification`), as S3 answers
//! them (probed, see `plans/notifications.md`). The configuration itself is
//! `notifications::config`'s; what it does, `cairn_notify`'s (in
//! `catalog.sql`) and `notifications::delivery`'s.
//!
//! A configuration's destinations are checked last, as S3 checks them: each
//! topic must exist, and its policy let S3 publish the bucket's events, or
//! S3's "Unable to validate the following destination configurations" names
//! each that doesn't. Queues and functions fail it too: Cairn delivers to
//! SNS topics only. Once it's set, each configuration's topic is sent S3's
//! test event (probed: one per configuration).
//!
//! Setting one takes the bucket's row FOR NO KEY UPDATE, so two don't
//! interleave their rows; writes, which take it FOR KEY SHARE, don't wait.

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::{
    App,
    db::Cached,
    notifications::{
        self,
        config::{self, Refused, Topic},
        delivery::{self, Message},
        signing,
    },
    s3::util::{error_document, format_s3_error, xml_ok},
    sns,
};

fn no_such_bucket() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::NOT_FOUND,
        "NoSuchBucket",
        "The specified bucket does not exist",
    )
}

fn refused(refused: Refused) -> Response<Full<Bytes>> {
    error_document(
        StatusCode::BAD_REQUEST,
        refused.code,
        &refused.message,
        &refused.details,
    )
}

/// The bucket's configuration, as it's kept.
pub async fn configured(
    client: &impl deadpool_postgres::GenericClient,
    bucket: &str,
) -> anyhow::Result<Vec<Topic>> {
    let rows = client
        .query(
            "SELECT id, topic_arn, events, prefix, suffix FROM bucket_notifications WHERE bucket = $1 ORDER BY position",
            &[&bucket],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| {
            let (prefix, suffix): (String, String) = (r.get(3), r.get(4));
            Topic {
                id: r.get(0),
                topic_arn: r.get(1),
                events: r.get(2),
                filtered: !prefix.is_empty() || !suffix.is_empty(),
                prefix,
                suffix,
            }
        })
        .collect())
}

pub async fn get(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let client = app.pool.get().await?;
    if client
        .query_opt_cached("SELECT 1 FROM buckets WHERE name = $1", &[&bucket])
        .await?
        .is_none()
    {
        return Ok(no_such_bucket());
    }
    Ok(xml_ok(config::xml(&configured(&client, bucket).await?)))
}

pub async fn put(app: &App, bucket: &str, body: Bytes) -> anyhow::Result<Response<Full<Bytes>>> {
    let requested = match config::parse(&body) {
        Ok(requested) => requested,
        Err(r) => return Ok(refused(r)),
    };
    if requested.event_bridge {
        return Ok(format_s3_error(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "Cairn doesn't send events to EventBridge",
        ));
    }
    let mut client = app.pool.get().await?;
    let Some(owner) = client
        .query_opt_cached("SELECT account_id FROM buckets WHERE name = $1", &[&bucket])
        .await?
    else {
        return Ok(no_such_bucket());
    };
    let owner: String = owner.get(0);
    // The destinations: first that each is an ARN, then that each can be
    // published to (probed).
    for topic in &requested.topics {
        if config::parse_topic_arn(&topic.topic_arn).is_none() {
            return Ok(refused(Refused {
                code: "InvalidArgument",
                message: "The ARN could not be parsed".to_owned(),
                details: vec![
                    ("ArgumentName", "Topic".to_owned()),
                    ("ArgumentValue", topic.topic_arn.clone()),
                ],
            }));
        }
    }
    let mut failed: Vec<(String, String)> = Vec::new();
    let mut topics = std::collections::HashMap::new();
    for topic in &requested.topics {
        if topics.contains_key(&topic.topic_arn)
            || failed.iter().any(|(arn, _)| *arn == topic.topic_arn)
        {
            continue;
        }
        let found = match sns::parse_topic_arn(&topic.topic_arn) {
            Some((account, name)) => sns::Topic::load(&client, &account, &name).await?,
            None => None,
        };
        match found {
            Some(t) if sns::s3_may_publish(&t, bucket, &owner)? => {
                topics.insert(topic.topic_arn.clone(), t);
            }
            // A missing topic is the same failure (probed).
            _ => failed.push((
                topic.topic_arn.clone(),
                "Permissions on the destination topic do not allow S3 to publish notifications from this bucket".to_owned(),
            )),
        }
    }
    for arn in &requested.elsewhere {
        failed.push((
            arn.clone(),
            "Cairn delivers notifications to SNS topics only".to_owned(),
        ));
    }
    if !failed.is_empty() {
        let mut details = Vec::new();
        for (i, (arn, why)) in failed.into_iter().enumerate() {
            details.push((argument("Name", i + 1), arn));
            details.push((argument("Value", i + 1), why));
        }
        return Ok(refused(Refused {
            code: "InvalidArgument",
            message: "Unable to validate the following destination configurations".to_owned(),
            details,
        }));
    }
    let tx = client.transaction().await?;
    if tx
        .query_opt(
            "SELECT 1 FROM buckets WHERE name = $1 FOR NO KEY UPDATE",
            &[&bucket],
        )
        .await?
        .is_none()
    {
        return Ok(no_such_bucket());
    }
    tx.execute(
        "DELETE FROM bucket_notifications WHERE bucket = $1",
        &[&bucket],
    )
    .await?;
    for (position, t) in requested.topics.iter().enumerate() {
        tx.execute(
            "INSERT INTO bucket_notifications (bucket, position, id, topic_arn, events, prefix, suffix)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[&bucket, &(position as i32), &t.id, &t.topic_arn, &t.events, &t.prefix, &t.suffix],
        )
        .await?;
    }
    tx.commit().await?;
    // S3's test event, one per configuration.
    if !requested.topics.is_empty() {
        let key = signing::current(&client, false).await?;
        let request_id = crate::s3::request_id().unwrap_or_default();
        for t in &requested.topics {
            let Some(topic) = topics.get(&t.topic_arn) else {
                continue;
            };
            let text = notifications::test_message(bucket, &delivery::now(), &request_id);
            let message = Message {
                subject: Some("Amazon S3 Notification"),
                message: &text,
                attributes: None,
            };
            delivery::publish(&client, &key, topic, &message).await?;
        }
    }
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::new()))
        .unwrap())
}

/// `ArgumentName1`, `ArgumentValue2`, ...: static, as error details' names
/// are.
fn argument(what: &str, n: usize) -> &'static str {
    const NAMES: [&str; 8] = [
        "ArgumentName1",
        "ArgumentName2",
        "ArgumentName3",
        "ArgumentName4",
        "ArgumentName5",
        "ArgumentName6",
        "ArgumentName7",
        "ArgumentName8",
    ];
    const VALUES: [&str; 8] = [
        "ArgumentValue1",
        "ArgumentValue2",
        "ArgumentValue3",
        "ArgumentValue4",
        "ArgumentValue5",
        "ArgumentValue6",
        "ArgumentValue7",
        "ArgumentValue8",
    ];
    let names = if what == "Name" { &NAMES } else { &VALUES };
    names[(n - 1).min(7)]
}
