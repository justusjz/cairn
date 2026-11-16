//! A bucket's server access logging configuration (see
//! `s3::buckets::logging`): set, read back and turned off, against a real
//! Postgres; and whether a target's policy lets the logging service write
//! to it (see `s3::service`).

use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::{StatusCode, body::Bytes};

use super::{BUCKET, node_with};
use crate::{
    App, packer,
    policy::Context,
    s3::{
        buckets::{
            logging::{get_bucket_logging, put_bucket_logging},
            policy::put_bucket_policy,
        },
        service::Destination,
    },
};

/// The bucket the logs go to.
const LOGS: &str = "logs";
const SERVICE: &str = "logging.s3.amazonaws.com";

async fn node() -> Option<Arc<App>> {
    let app = node_with(packer::Config::default(), None).await?;
    app.pool.get().await.unwrap().execute("INSERT INTO buckets (name) VALUES ($1)", &[&LOGS]).await.unwrap();
    Some(app)
}

fn status(inner: &str) -> Bytes {
    Bytes::from(format!(
        "<BucketLoggingStatus xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{inner}</BucketLoggingStatus>"
    ))
}

async fn body(response: hyper::Response<http_body_util::Full<Bytes>>) -> String {
    String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
}

#[tokio::test]
async fn logging_is_set_read_back_and_turned_off() {
    let Some(app) = node().await else { return };
    // None, at first.
    let got = body(get_bucket_logging(&app, BUCKET).await.unwrap()).await;
    assert!(got.ends_with("<BucketLoggingStatus xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></BucketLoggingStatus>"));

    let enabled = format!(
        "<LoggingEnabled><TargetBucket>{LOGS}</TargetBucket><TargetPrefix>{BUCKET}/</TargetPrefix>\
         <TargetObjectKeyFormat><PartitionedPrefix><PartitionDateSource>EventTime</PartitionDateSource>\
         </PartitionedPrefix></TargetObjectKeyFormat></LoggingEnabled>"
    );
    let response = put_bucket_logging(&app, BUCKET, status(&enabled)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let got = body(get_bucket_logging(&app, BUCKET).await.unwrap()).await;
    assert!(got.contains(&enabled), "{got}");

    // A bucket may log to itself.
    let itself = format!("<LoggingEnabled><TargetBucket>{BUCKET}</TargetBucket><TargetPrefix/></LoggingEnabled>");
    assert_eq!(put_bucket_logging(&app, BUCKET, status(&itself)).await.unwrap().status(), StatusCode::OK);

    // Turned off.
    assert_eq!(put_bucket_logging(&app, BUCKET, status("")).await.unwrap().status(), StatusCode::OK);
    let got = body(get_bucket_logging(&app, BUCKET).await.unwrap()).await;
    assert!(!got.contains("LoggingEnabled"), "{got}");
}

#[tokio::test]
async fn the_target_must_exist() {
    let Some(app) = node().await else { return };
    let enabled = "<LoggingEnabled><TargetBucket>nowhere</TargetBucket><TargetPrefix>p</TargetPrefix></LoggingEnabled>";
    let response = put_bucket_logging(&app, BUCKET, status(enabled)).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let got = body(response).await;
    assert!(got.contains("<Code>InvalidTargetBucketForLogging</Code>"), "{got}");
    assert!(got.contains("<TargetBucket>nowhere</TargetBucket>"), "{got}");
    // And nothing was set.
    assert!(!body(get_bucket_logging(&app, BUCKET).await.unwrap()).await.contains("LoggingEnabled"));
}

#[tokio::test]
async fn a_missing_bucket_has_no_configuration() {
    let Some(app) = node().await else { return };
    assert_eq!(get_bucket_logging(&app, "nope").await.unwrap().status(), StatusCode::NOT_FOUND);
    let enabled = format!("<LoggingEnabled><TargetBucket>{LOGS}</TargetBucket><TargetPrefix/></LoggingEnabled>");
    assert_eq!(put_bucket_logging(&app, "nope", status(&enabled)).await.unwrap().status(), StatusCode::NOT_FOUND);
    assert_eq!(put_bucket_logging(&app, "nope", status("")).await.unwrap().status(), StatusCode::NOT_FOUND);
}

/// The target's policy S3's user guide gives for server access logs of
/// `BUCKET`.
#[tokio::test]
async fn the_targets_policy_decides_whether_the_service_may_write() {
    let Some(app) = node().await else { return };
    let account = crate::users::account(&app.pool.get().await.unwrap()).await.unwrap();
    let may = |destination: &Destination, source: &str, key: &str| {
        destination.allows_put(SERVICE, source, &account, key, Context::default())
    };
    // No policy: no.
    let destination = Destination::load(&app, LOGS).await.unwrap().unwrap();
    assert_eq!(destination.owner, account);
    assert!(!may(&destination, BUCKET, "bucket/2026-11-16-00-00-00-0123456789ABCDEF"));

    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Sid":"S3ServerAccessLogsPolicy","Effect":"Allow",
            "Principal":{{"Service":"{SERVICE}"}},"Action":"s3:PutObject",
            "Resource":"arn:aws:s3:::{LOGS}/bucket/*",
            "Condition":{{"ArnLike":{{"aws:SourceArn":"arn:aws:s3:::{BUCKET}"}},
                "StringEquals":{{"aws:SourceAccount":"{account}"}}}}}}]}}"#
    );
    let response = put_bucket_policy(&app, LOGS, Bytes::from(policy)).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let destination = Destination::load(&app, LOGS).await.unwrap().unwrap();
    assert!(may(&destination, BUCKET, "bucket/2026-11-16-00-00-00-0123456789ABCDEF"));
    // Not under another prefix, nor for another bucket, nor as another
    // service, nor for another account.
    assert!(!may(&destination, BUCKET, "other/2026-11-16-00-00-00-0123456789ABCDEF"));
    assert!(!may(&destination, "other", "bucket/2026-11-16-00-00-00-0123456789ABCDEF"));
    let key = "bucket/2026-11-16-00-00-00-0123456789ABCDEF";
    assert!(!destination.allows_put("s3.amazonaws.com", BUCKET, &account, key, Context::default()));
    assert!(!destination.allows_put(SERVICE, BUCKET, "111122223333", key, Context::default()));

    assert!(Destination::load(&app, "nope").await.unwrap().is_none());
}
