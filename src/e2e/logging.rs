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

/// Requests to a bucket that logs, sent to a node's client listener, are
/// recorded, spooled and delivered to its target, as S3 writes them; those
/// to a bucket that doesn't, aren't.
#[tokio::test]
async fn requests_are_logged_to_the_target() {
    use crate::access_log::{Logs, delivery, spool::Rotation};
    use http_body_util::Full;
    use hyper_util::{client::legacy::Client, rt::TokioExecutor};

    let Some(app) = node().await else { return };
    let mut app = Arc::into_inner(app).expect("a new node isn't shared");
    let spool = app.store.data_dir().join("access-logs");
    let rotation = Rotation { age: std::time::Duration::from_millis(1), bytes: u64::MAX };
    app.access_logs = Logs::start(spool.clone(), rotation).unwrap();
    let app = Arc::new(app);
    let account = crate::users::account(&app.pool.get().await.unwrap()).await.unwrap();

    // The bucket's objects are public, and the target's logs too, so that
    // anonymous requests read them; the logging service may write to it.
    use crate::s3::buckets::public_access;
    assert!(public_access::set_account(&app, &account, None).await.unwrap());
    assert!(public_access::set(&app, BUCKET, None).await.unwrap());
    assert!(public_access::set(&app, LOGS, None).await.unwrap());
    let public = |bucket: &str| {
        format!(r#"{{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::{bucket}/*"}}"#)
    };
    let policy = format!(r#"{{"Statement":[{}]}}"#, public(BUCKET));
    assert_eq!(put_bucket_policy(&app, BUCKET, Bytes::from(policy)).await.unwrap().status(), StatusCode::NO_CONTENT);
    let policy = format!(
        r#"{{"Statement":[{},{{"Effect":"Allow","Principal":{{"Service":"{SERVICE}"}},"Action":"s3:PutObject",
            "Resource":"arn:aws:s3:::{LOGS}/access/*",
            "Condition":{{"ArnLike":{{"aws:SourceArn":"arn:aws:s3:::{BUCKET}"}},"StringEquals":{{"aws:SourceAccount":"{account}"}}}}}}]}}"#,
        public(LOGS)
    );
    assert_eq!(put_bucket_policy(&app, LOGS, Bytes::from(policy)).await.unwrap().status(), StatusCode::NO_CONTENT);
    let enabled = format!("<LoggingEnabled><TargetBucket>{LOGS}</TargetBucket><TargetPrefix>access/</TargetPrefix></LoggingEnabled>");
    assert_eq!(put_bucket_logging(&app, BUCKET, status(&enabled)).await.unwrap().status(), StatusCode::OK);
    app.access_logs.refresh(&app).await.unwrap();

    let attach = crate::AttachTarget::Object { storage_class: crate::classes::STANDARD.to_owned(),
        bucket: BUCKET.to_owned(),
        key: "hello.txt".to_owned(),
        content_type: "text/plain".to_owned(),
        metadata: String::new(),
        conditions: crate::s3::conditional::Preconditions::default(),
        sealing: None,
        checksum: crate::e2e::OBJECT_CHECKSUM,
        tags: String::new(),
        lock: Default::default(),
    };
    let body = Full::new(Bytes::from_static(b"hello"));
    let written = crate::upload_part(&app, body, &attach, crate::payload::Payload::unchecked()).await.unwrap();
    assert!(matches!(written, crate::UploadResult::Committed { .. }));

    // The node's client listener.
    let address = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    // On a runtime of its own, whose thread has the stack a debug build's
    // request needs (more than a test thread's).
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let serving = {
        let app = app.clone();
        std::thread::Builder::new()
            .stack_size(64 << 20)
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .thread_stack_size(64 << 20)
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(crate::serve_client(address, 16, app, async {
                    let _ = stopped.await;
                }))
            })
            .unwrap()
    };
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let get = |path: String| {
        let client = client.clone();
        async move {
            let request = hyper::Request::get(format!("http://{address}{path}"))
                .header("user-agent", "logging test/1.0")
                .header("referer", "https://example.com/a page")
                .body(Full::new(Bytes::new()))
                .unwrap();
            // The listener may not be up yet.
            let mut tries = 0;
            let response = loop {
                match client.request(request.clone()).await {
                    Ok(response) => break response,
                    Err(_) if tries < 50 => {
                        tries += 1;
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            let status = response.status();
            (status, response.into_body().collect().await.unwrap().to_bytes())
        }
    };
    assert_eq!(get(format!("/{BUCKET}/hello.txt")).await, (StatusCode::OK, Bytes::from_static(b"hello")));
    assert_eq!(get(format!("/{BUCKET}/missing")).await.0, StatusCode::FORBIDDEN);
    assert_eq!(get(format!("/{BUCKET}?versioning")).await.0, StatusCode::FORBIDDEN);
    // Not to a bucket that doesn't log.
    assert_eq!(get(format!("/{LOGS}/nothing")).await.0, StatusCode::FORBIDDEN);

    // The spool's files close within a second or so; then they're
    // delivered.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let open = || {
        std::fs::read_dir(&spool).unwrap().any(|e| e.unwrap().path().extension().is_some_and(|e| e == "open"))
    };
    while open() {
        assert!(std::time::Instant::now() < deadline, "the spool's files weren't closed");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    delivery::deliver_all(&app, &spool).await.unwrap();
    assert!(crate::access_log::spool::Spool::closed(&spool).unwrap().is_empty(), "delivered files are removed");
    let keys: Vec<String> = app
        .pool
        .get()
        .await
        .unwrap()
        .query("SELECT key FROM objects WHERE bucket = $1", &[&LOGS])
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    // One per spool file (the test's requests may span two).
    assert!(!keys.is_empty() && keys.len() <= 2, "{keys:?}");
    let mut log = String::new();
    for key in &keys {
        assert!(key.starts_with("access/") && key.len() == "access/YYYY-mm-DD-HH-MM-SS-".len() + 16, "{keys:?}");
        let (status, object) = get(format!("/{LOGS}/{key}")).await;
        assert_eq!(status, StatusCode::OK);
        log.push_str(&String::from_utf8(object.to_vec()).unwrap());
    }
    assert_eq!(log.lines().count(), 3, "{log}");
    let line = |request: &str| log.lines().find(|l| l.contains(request)).unwrap_or_else(|| panic!("{request}: {log}"));
    let owner = crate::s3::util::canonical_id(&account);
    let fields = |line: &str| -> Vec<String> {
        // Split on spaces outside brackets and quotes.
        let (mut fields, mut field, mut within) = (Vec::new(), String::new(), None);
        for c in line.chars() {
            match (within, c) {
                (None, ' ') => fields.push(std::mem::take(&mut field)),
                (None, '[') => (within, field) = (Some(']'), field + "["),
                (None, '"') => (within, field) = (Some('"'), field + "\""),
                (Some(end), c) if c == end => (within, field) = (None, field + &c.to_string()),
                (_, c) => field.push(c),
            }
        }
        fields.push(field);
        fields
    };
    let read = fields(line("/hello.txt "));
    assert_eq!(read.len(), 26, "{read:?}");
    assert_eq!(read[0], owner);
    assert_eq!(read[1], BUCKET);
    assert!(read[2].starts_with('[') && read[2].ends_with(" +0000]"), "{read:?}");
    assert_eq!(read[3], "127.0.0.1");
    assert_eq!(read[4], "-");
    assert_eq!(read[5].len(), 16);
    assert_eq!(read[6], "REST.GET.OBJECT");
    assert_eq!(read[7], "hello.txt");
    assert_eq!(read[8], format!("\"GET /{BUCKET}/hello.txt HTTP/1.1\""));
    assert_eq!((read[9].as_str(), read[10].as_str(), read[11].as_str(), read[12].as_str()), ("200", "-", "5", "5"));
    assert_eq!(read[15], "\"https://example.com/a page\"");
    assert_eq!(read[16], "\"logging test/1.0\"");
    assert_eq!(read[22], address.to_string());
    let missing = fields(line("/missing "));
    assert_eq!((missing[6].as_str(), missing[9].as_str(), missing[10].as_str()), ("REST.GET.OBJECT", "403", "AccessDenied"));
    let versioning = fields(line("?versioning "));
    assert_eq!((versioning[6].as_str(), versioning[7].as_str()), ("REST.GET.VERSIONING", "-"));
    let _ = stop.send(());
    serving.join().unwrap().unwrap();
}

/// Records a target doesn't take (its policy doesn't let the service write
/// them) are dropped, as S3 drops them: not kept to be tried again.
#[tokio::test]
async fn records_the_target_refuses_are_dropped() {
    use crate::access_log::{delivery, spool::Line};
    let Some(app) = node().await else { return };
    let enabled = format!("<LoggingEnabled><TargetBucket>{LOGS}</TargetBucket><TargetPrefix/></LoggingEnabled>");
    assert_eq!(put_bucket_logging(&app, BUCKET, status(&enabled)).await.unwrap().status(), StatusCode::OK);
    let spool = app.store.data_dir().join("access-logs-dropped");
    std::fs::create_dir_all(&spool).unwrap();
    let file = spool.join("0000000000001-1.closed");
    let mut data = Line::encode(BUCKET, std::time::SystemTime::now(), "a record");
    // And one of a bucket that doesn't log (any more).
    data.extend(Line::encode("other", std::time::SystemTime::now(), "another"));
    std::fs::write(&file, data).unwrap();
    delivery::deliver_all(&app, &spool).await.unwrap();
    assert!(!file.exists());
    let written: i64 = app
        .pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT count(*) FROM objects WHERE bucket = $1", &[&LOGS])
        .await
        .unwrap()
        .get(0);
    assert_eq!(written, 0);
}
