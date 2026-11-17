//! Batch Operations' jobs against a real Postgres (see `e2e`): created
//! through S3 Control's requests, and run by lifecycle steps, with the
//! clock moved ahead instead of waiting.

use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use http_body_util::{BodyExt, Full};
use hyper::{HeaderMap, Method, StatusCode, body::Bytes};

use super::control;
use crate::{
    App,
    e2e::{BUCKET, node_with, put},
    lifecycle::pass,
    packer, roles,
    s3::access::{Access, Origin},
    users::{self, Principal},
};

const MINUTE: Duration = Duration::from_secs(60);
const ROLE: &str = "batch";

async fn node() -> Option<Arc<App>> {
    let app = node_with(packer::Config::default(), None).await?;
    crate::settings::LIFECYCLE_RATE.set(&app.pool.get().await.unwrap(), 1_000_000).await.unwrap();
    Some(app)
}

async fn account(app: &App) -> String {
    users::account(&app.pool.get().await.unwrap()).await.unwrap()
}

/// A user named `name`: an admin, or with the identity policy `statements`.
async fn user(app: &App, name: &str, statements: Option<&str>) -> Principal {
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let (key, _) = users::create_for(&client, &account, name, None, statements.is_none()).await.unwrap();
    if let Some(statements) = statements {
        let policy = format!(r#"{{"Version":"2012-10-17","Statement":[{statements}]}}"#);
        users::put_policy(&client, &account, name, "p", &policy).await.unwrap();
    }
    Principal::load(&client, &key).await.unwrap().unwrap()
}

fn access(principal: &Principal) -> Access {
    let origin = Origin { peer: Some("127.0.0.1".parse().unwrap()), trusted_proxies: &[], signed: None, form: false };
    Access::new(Some(principal), &principal.account, &Method::POST, &HeaderMap::new(), "", &origin).unwrap()
}

/// The role jobs act as: trusting `service` to assume it, and allowed
/// `actions` on the test bucket and its objects.
async fn role(app: &App, service: &str, actions: &str) {
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let trust = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"{service}"}},"Action":"sts:AssumeRole"}}]}}"#
    );
    let trust = roles::check_trust(&client, &account, &trust).await.unwrap();
    let new = roles::New { name: ROLE, path: "/", trust: &trust, description: "", max_session_duration: 3600, boundary: None, tags: &[] };
    let id = roles::create(&client, &account, &new).await.unwrap();
    let role = roles::Role::load_id(&client, id).await.unwrap().unwrap();
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":{actions},"Resource":["arn:aws:s3:::{BUCKET}","arn:aws:s3:::{BUCKET}/*"]}}]}}"#
    );
    roles::put_policy(&client, &role, "p", &policy).await.unwrap();
}

/// The usual role: it may read manifests and tag objects.
async fn tagging_role(app: &App) {
    role(app, super::SERVICE, r#"["s3:GetObject","s3:PutObjectTagging","s3:PutObjectVersionTagging","s3:DeleteObjectTagging"]"#)
        .await;
}

/// Puts a manifest of `lines` at `key`; its ETag.
async fn manifest(app: &Arc<App>, key: &str, lines: &str) -> String {
    put(app, key, lines.as_bytes().to_vec()).await;
    use md5::Digest;
    md5::Md5::digest(lines.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

fn create_request(token: &str, operation: &str, key: &str, etag: &str, confirmation: bool, account: &str) -> String {
    format!(
        "<CreateJobRequest xmlns=\"http://awss3control.amazonaws.com/doc/2018-08-20/\">\
         <ConfirmationRequired>{confirmation}</ConfirmationRequired>\
         <Operation>{operation}</Operation><Report><Enabled>false</Enabled></Report>\
         <ClientRequestToken>{token}</ClientRequestToken>\
         <Manifest><Spec><Format>S3BatchOperations_CSV_20180820</Format>\
         <Fields><member>Bucket</member><member>Key</member></Fields></Spec>\
         <Location><ObjectArn>arn:aws:s3:::{BUCKET}/{key}</ObjectArn><ETag>{etag}</ETag></Location></Manifest>\
         <Priority>10</Priority><RoleArn>arn:aws:iam::{account}:role/{ROLE}</RoleArn></CreateJobRequest>"
    )
}

const PUT_TAGS: &str =
    "<S3PutObjectTagging><TagSet><member><Key>team</Key><Value>red</Value></member></TagSet></S3PutObjectTagging>";

async fn body_of(response: hyper::Response<Full<Bytes>>) -> (StatusCode, String) {
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

fn element<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    xml.split(&format!("<{name}>")).nth(1)?.split(&format!("</{name}>")).next()
}

/// Creates a job as `principal`: its ID.
async fn create(app: &Arc<App>, principal: &Principal, body: &str) -> String {
    let (status, body) = body_of(control::create(app, &access(principal), &principal.account, body.as_bytes()).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    element(&body, "JobId").unwrap().to_owned()
}

/// The job's `<Job>`.
async fn describe(app: &Arc<App>, principal: &Principal, id: &str) -> String {
    let (status, body) = body_of(control::describe(app, &access(principal), &principal.account, id).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

async fn status_of(app: &Arc<App>, principal: &Principal, id: &str) -> String {
    element(&describe(app, principal, id).await, "Status").unwrap().to_owned()
}

/// Takes the step `minutes` from now.
async fn step(app: &Arc<App>, minutes: u32) {
    for result in pass(app, SystemTime::now() + MINUTE * minutes).await {
        result.map_err(|(_, e)| e).unwrap();
    }
}

async fn tags_of(app: &App, key: &str) -> String {
    let client = app.pool.get().await.unwrap();
    let row = client
        .query_one("SELECT tags FROM objects WHERE bucket = $1 AND key = $2 AND is_latest", &[&BUCKET, &key])
        .await
        .unwrap();
    row.get(0)
}

/// A job is prepared (its manifest counted), then runs its tasks as its
/// role, as far as they go: those on objects that aren't there fail.
#[tokio::test]
async fn a_job_tags_the_objects_of_its_manifest() {
    let Some(app) = node().await else { return };
    let account = account(&app).await;
    let admin = user(&app, "admin", None).await;
    tagging_role(&app).await;
    put(&app, "a", b"a".to_vec()).await;
    put(&app, "my photo+1.jpg", b"b".to_vec()).await;
    let etag = manifest(&app, "manifest.csv", &format!("{BUCKET},a\n\"{BUCKET}\",my+photo%2B1.jpg\r\n{BUCKET},missing")).await;
    let id = create(&app, &admin, &create_request("t1", PUT_TAGS, "manifest.csv", &etag, false, &account)).await;
    assert_eq!(status_of(&app, &admin, &id).await, "New");

    step(&app, 1).await;
    let job = describe(&app, &admin, &id).await;
    assert_eq!(element(&job, "Status"), Some("Ready"), "{job}");
    assert_eq!(element(&job, "TotalNumberOfTasks"), Some("3"));

    step(&app, 2).await;
    let job = describe(&app, &admin, &id).await;
    assert_eq!(element(&job, "Status"), Some("Complete"), "{job}");
    assert_eq!(element(&job, "NumberOfTasksSucceeded"), Some("2"));
    assert_eq!(element(&job, "NumberOfTasksFailed"), Some("1"));
    assert!(element(&job, "TerminationDate").is_some());
    assert_eq!(element(&job, "JobArn"), Some(format!("arn:aws:s3:us-east-1:{account}:job/{id}").as_str()));
    assert_eq!(tags_of(&app, "a").await, "team=red");
    assert_eq!(tags_of(&app, "my photo+1.jpg").await, "team=red");

    // And a job that deletes them, of one of the two.
    let etag = manifest(&app, "delete.csv", &format!("{BUCKET},a\n")).await;
    let id = create(&app, &admin, &create_request("t2", "<S3DeleteObjectTagging/>", "delete.csv", &etag, false, &account)).await;
    step(&app, 3).await;
    step(&app, 4).await;
    assert_eq!(status_of(&app, &admin, &id).await, "Complete");
    assert_eq!(tags_of(&app, "a").await, "");
    assert_eq!(tags_of(&app, "my photo+1.jpg").await, "team=red");
}

/// A job that asks to be confirmed waits for UpdateJobStatus; one
/// cancelled before it runs never does.
#[tokio::test]
async fn jobs_are_confirmed_or_cancelled() {
    let Some(app) = node().await else { return };
    let account = account(&app).await;
    let admin = user(&app, "admin", None).await;
    tagging_role(&app).await;
    put(&app, "a", b"a".to_vec()).await;
    let etag = manifest(&app, "manifest.csv", &format!("{BUCKET},a\n")).await;
    let confirmed = create(&app, &admin, &create_request("t1", PUT_TAGS, "manifest.csv", &etag, true, &account)).await;
    let cancelled = create(&app, &admin, &create_request("t2", PUT_TAGS, "manifest.csv", &etag, true, &account)).await;
    step(&app, 1).await;
    for id in [&confirmed, &cancelled] {
        let job = describe(&app, &admin, id).await;
        assert_eq!(element(&job, "Status"), Some("Suspended"), "{job}");
        assert_eq!(element(&job, "SuspendedCause"), Some("AWAITING_CONFIRMATION"));
    }
    step(&app, 2).await;
    assert_eq!(tags_of(&app, "a").await, "");

    let update = |id: String, query: &'static str| {
        let app = app.clone();
        let access = access(&admin);
        let account = account.clone();
        async move { body_of(control::update_status(&app, &access, &account, &id, query).await.unwrap()).await }
    };
    let (status, body) = update(confirmed.clone(), "requestedJobStatus=Ready").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(element(&body, "Status"), Some("Ready"));
    let (status, body) = update(cancelled.clone(), "requestedJobStatus=Cancelled&statusUpdateReason=nope").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(element(&body, "Status"), Some("Cancelled"));
    assert_eq!(element(&body, "StatusUpdateReason"), Some("nope"));
    // A cancelled job stays so.
    let (status, body) = update(cancelled.clone(), "requestedJobStatus=Ready").await;
    assert_eq!((status, element(&body, "Code")), (StatusCode::BAD_REQUEST, Some("JobStatusException")));
    let (status, body) = update(cancelled.clone(), "requestedJobStatus=Active").await;
    assert_eq!((status, element(&body, "Code")), (StatusCode::BAD_REQUEST, Some("BadRequestException")));

    step(&app, 3).await;
    assert_eq!(status_of(&app, &admin, &confirmed).await, "Complete");
    assert_eq!(status_of(&app, &admin, &cancelled).await, "Cancelled");
    assert_eq!(tags_of(&app, "a").await, "team=red");
}

/// A job fails, saying why, if its role doesn't trust the service, if its
/// manifest changed since it was created, if a line of it isn't a task, or
/// if most of its tasks fail.
#[tokio::test]
async fn jobs_fail_saying_why() {
    let Some(app) = node().await else { return };
    let account = account(&app).await;
    let admin = user(&app, "admin", None).await;
    role(&app, "s3.amazonaws.com", r#"["s3:GetObject"]"#).await;
    let etag = manifest(&app, "manifest.csv", &format!("{BUCKET},a\n")).await;
    let untrusted = create(&app, &admin, &create_request("t1", PUT_TAGS, "manifest.csv", &etag, false, &account)).await;
    step(&app, 1).await;
    let job = describe(&app, &admin, &untrusted).await;
    assert_eq!(element(&job, "Status"), Some("Failed"), "{job}");
    assert_eq!(element(&job, "FailureCode"), Some("RoleUnusable"));

    // The role, trusting the service now.
    let client = app.pool.get().await.unwrap();
    let role = roles::Role::load(&client, &account, ROLE).await.unwrap().unwrap();
    let trust = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"{}"}},"Action":"sts:AssumeRole"}}]}}"#,
        super::SERVICE
    );
    roles::set_trust(&client, role.id, &roles::check_trust(&client, &account, &trust).await.unwrap()).await.unwrap();

    let changed = create(&app, &admin, &create_request("t2", PUT_TAGS, "manifest.csv", "0123", false, &account)).await;
    let bad = manifest(&app, "bad.csv", &format!("{BUCKET},a\n{BUCKET}\n")).await;
    let invalid = create(&app, &admin, &create_request("t3", PUT_TAGS, "bad.csv", &bad, false, &account)).await;
    let lines: String = (0..1100).map(|i| format!("{BUCKET},missing{i}\n")).collect();
    let failing = manifest(&app, "failing.csv", &lines).await;
    let failing = create(&app, &admin, &create_request("t4", PUT_TAGS, "failing.csv", &failing, false, &account)).await;
    step(&app, 2).await;
    let job = describe(&app, &admin, &changed).await;
    assert_eq!(element(&job, "FailureCode"), Some("ManifestETagMismatch"), "{job}");
    let job = describe(&app, &admin, &invalid).await;
    assert_eq!(element(&job, "FailureCode"), Some("ManifestInvalid"), "{job}");
    assert!(element(&job, "FailureReason").unwrap().contains("Line 2"), "{job}");
    // Its tasks are denied (the role may only read): a thousand fail, and
    // the job with them.
    step(&app, 3).await;
    step(&app, 4).await;
    let job = describe(&app, &admin, &failing).await;
    assert_eq!(element(&job, "Status"), Some("Failed"), "{job}");
    assert_eq!(element(&job, "FailureCode"), Some("TaskFailureThresholdExceeded"));
    assert_eq!(element(&job, "NumberOfTasksFailed"), Some("1000"));
}

/// Each task is authorized as its role's session's request: one on an
/// object the role may not tag fails.
#[tokio::test]
async fn tasks_are_authorized_as_the_role() {
    let Some(app) = node().await else { return };
    let account = account(&app).await;
    let admin = user(&app, "admin", None).await;
    role(&app, super::SERVICE, r#"["s3:GetObject","s3:PutObjectTagging"]"#).await;
    // Not on `private/`.
    let client = app.pool.get().await.unwrap();
    let role = roles::Role::load(&client, &account, ROLE).await.unwrap().unwrap();
    let deny = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Action":"s3:PutObjectTagging","Resource":"arn:aws:s3:::{BUCKET}/private/*"}}]}}"#
    );
    roles::put_policy(&client, &role, "deny", &deny).await.unwrap();
    put(&app, "public/a", b"a".to_vec()).await;
    put(&app, "private/a", b"a".to_vec()).await;
    let etag = manifest(&app, "manifest.csv", &format!("{BUCKET},public/a\n{BUCKET},private/a\n")).await;
    let id = create(&app, &admin, &create_request("t1", PUT_TAGS, "manifest.csv", &etag, false, &account)).await;
    step(&app, 1).await;
    step(&app, 2).await;
    let job = describe(&app, &admin, &id).await;
    assert_eq!(element(&job, "Status"), Some("Complete"), "{job}");
    assert_eq!(element(&job, "NumberOfTasksFailed"), Some("1"));
    assert_eq!(tags_of(&app, "public/a").await, "team=red");
    assert_eq!(tags_of(&app, "private/a").await, "");
}

/// CreateJob needs `s3:CreateJob` and `iam:PassRole`; a client's retry of
/// it (the same token, the same request) is the same job, and another
/// request with the token is refused.
#[tokio::test]
async fn creating_jobs() {
    let Some(app) = node().await else { return };
    let account = account(&app).await;
    let admin = user(&app, "admin", None).await;
    let request = create_request("t1", PUT_TAGS, "manifest.csv", "abc", false, &account);
    let first = create(&app, &admin, &request).await;
    assert_eq!(create(&app, &admin, &request).await, first);
    let other = create_request("t1", "<S3DeleteObjectTagging/>", "manifest.csv", "abc", false, &account);
    let (status, body) = body_of(control::create(&app, &access(&admin), &account, other.as_bytes()).await.unwrap()).await;
    assert_eq!((status, element(&body, "Code")), (StatusCode::BAD_REQUEST, Some("IdempotencyException")));

    let creator = user(&app, "creator", Some(r#"{"Effect":"Allow","Action":"s3:CreateJob","Resource":"*"}"#)).await;
    let request = create_request("t2", PUT_TAGS, "manifest.csv", "abc", false, &account);
    let (status, body) = body_of(control::create(&app, &access(&creator), &account, request.as_bytes()).await.unwrap()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("iam:PassRole"), "{body}");
    // A condition on the operation.
    let tagger = user(
        &app,
        "tagger",
        Some(
            r#"{"Effect":"Allow","Action":"s3:CreateJob","Resource":"*","Condition":{"StringEquals":{"s3:RequestJobOperation":"S3DeleteObjectTagging"}}},
               {"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}"#,
        ),
    )
    .await;
    let (status, body) = body_of(control::create(&app, &access(&tagger), &account, request.as_bytes()).await.unwrap()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let deleting = create_request("t3", "<S3DeleteObjectTagging/>", "manifest.csv", "abc", false, &account);
    create(&app, &tagger, &deleting).await;
    // Another's job is no one's to describe without `s3:DescribeJob`.
    let (status, _) = body_of(control::describe(&app, &access(&tagger), &account, &first).await.unwrap()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = body_of(control::describe(&app, &access(&admin), &account, &uuid::Uuid::new_v4().to_string()).await.unwrap()).await;
    assert_eq!((status, element(&body, "Code")), (StatusCode::NOT_FOUND, Some("NotFoundException")));
}

/// ListJobs lists the newest first, a page at a time, of the statuses
/// asked for.
#[tokio::test]
async fn jobs_are_listed() {
    let Some(app) = node().await else { return };
    let account = account(&app).await;
    let admin = user(&app, "admin", None).await;
    let mut ids = Vec::new();
    for i in 0..3 {
        ids.push(create(&app, &admin, &create_request(&format!("t{i}"), PUT_TAGS, "m.csv", "abc", false, &account)).await);
    }
    let list = |query: String| {
        let app = app.clone();
        let access = access(&admin);
        let account = account.clone();
        async move { body_of(control::list(&app, &access, &account, &query).await.unwrap()).await }
    };
    let (status, page) = list("maxResults=2".to_owned()).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let listed = |page: &str| page.split("<JobId>").skip(1).map(|s| s.split("</JobId>").next().unwrap().to_owned()).collect::<Vec<_>>();
    assert_eq!(listed(&page), [ids[2].clone(), ids[1].clone()]);
    assert!(page.contains("<Operation>S3PutObjectTagging</Operation>"), "{page}");
    let token = element(&page, "NextToken").unwrap().to_owned();
    let (_, page) = list(format!("maxResults=2&nextToken={token}")).await;
    assert_eq!(listed(&page), [ids[0].clone()]);
    assert!(element(&page, "NextToken").is_none());
    let (_, page) = list("jobStatuses=Complete&jobStatuses=Failed".to_owned()).await;
    assert!(listed(&page).is_empty(), "{page}");
    let (_, page) = list("jobStatuses=New".to_owned()).await;
    assert_eq!(listed(&page).len(), 3);
    let (status, page) = list("jobStatuses=Nope".to_owned()).await;
    assert_eq!((status, element(&page, "Code")), (StatusCode::BAD_REQUEST, Some("InvalidRequestException")));

    // Priorities and tags.
    let (status, body) =
        body_of(control::update_priority(&app, &access(&admin), &account, &ids[0], "priority=99").await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(element(&describe(&app, &admin, &ids[0]).await, "Priority"), Some("99"));
    let tags = "<PutJobTaggingRequest><Tags><member><Key>k</Key><Value>v</Value></member></Tags></PutJobTaggingRequest>";
    let (status, _) = body_of(control::put_tagging(&app, &access(&admin), &account, &ids[0], tags.as_bytes()).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = body_of(control::get_tagging(&app, &access(&admin), &account, &ids[0]).await.unwrap()).await;
    assert!(body.contains("<Tags><member><Key>k</Key><Value>v</Value></member></Tags>"), "{body}");
}
