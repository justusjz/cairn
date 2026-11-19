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

/// `request` with the report `report` (a `<Report>` element) instead of
/// none.
fn with_report(request: &str, report: &str) -> String {
    request.replace("<Report><Enabled>false</Enabled></Report>", report)
}

fn report(scope: &str) -> String {
    format!(
        "<Report><Bucket>arn:aws:s3:::{BUCKET}</Bucket><Format>Report_CSV_20180820</Format>\
         <Enabled>true</Enabled><Prefix>reports</Prefix><ReportScope>{scope}</ReportScope></Report>"
    )
}

/// The report's manifest of job `id`, and its result files' contents, by
/// their statuses, checked against the manifest's MD5s.
async fn report_of(app: &Arc<App>, id: &str) -> (serde_json::Value, Vec<(String, String)>) {
    let manifest = crate::e2e::get(app, &format!("reports/job-{id}/manifest.json")).await.expect("a manifest");
    let manifest: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
    assert_eq!(manifest["Format"], "Report_CSV_20180820");
    assert_eq!(manifest["ReportSchema"], "Bucket, Key, VersionId, TaskStatus, ErrorCode, HTTPStatusCode, ResultMessage");
    let mut files = Vec::new();
    for result in manifest["Results"].as_array().unwrap() {
        assert_eq!(result["Bucket"], BUCKET);
        let key = result["Key"].as_str().unwrap();
        assert!(key.starts_with(&format!("reports/job-{id}/results/")), "{key}");
        let data = crate::e2e::get(app, key).await.expect("a result file");
        use md5::Digest;
        let md5: String = md5::Md5::digest(&data).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(result["MD5Checksum"], md5.as_str());
        files.push((result["TaskExecutionStatus"].as_str().unwrap().to_owned(), String::from_utf8(data).unwrap()));
    }
    (manifest, files)
}

/// A job's report lists every task, those that succeeded and those that
/// failed in files of their own; or only those that failed.
#[tokio::test]
async fn reports_list_the_tasks() {
    let Some(app) = node().await else { return };
    let account = account(&app).await;
    let admin = user(&app, "admin", None).await;
    role(&app, super::SERVICE, r#"["s3:GetObject","s3:PutObject","s3:PutObjectTagging"]"#).await;
    put(&app, "a b", b"a".to_vec()).await;
    let etag = manifest(&app, "manifest.csv", &format!("{BUCKET},a+b\n{BUCKET},missing\n")).await;
    let all = with_report(&create_request("t1", PUT_TAGS, "manifest.csv", &etag, false, &account), &report("AllTasks"));
    let all = create(&app, &admin, &all).await;
    let failed = with_report(&create_request("t2", PUT_TAGS, "manifest.csv", &etag, false, &account), &report("FailedTasksOnly"));
    let failed = create(&app, &admin, &failed).await;
    step(&app, 1).await;
    step(&app, 2).await;
    assert_eq!(status_of(&app, &admin, &all).await, "Complete");
    assert_eq!(status_of(&app, &admin, &failed).await, "Complete");

    let (manifest, files) = report_of(&app, &all).await;
    assert!(manifest["ReportCreationDate"].as_str().unwrap().ends_with('Z'));
    assert_eq!(
        files,
        [
            ("succeeded".to_owned(), format!("{BUCKET},a+b,,succeeded,200,,Successful\n")),
            ("failed".to_owned(), format!("{BUCKET},missing,,failed,404,NoSuchKey,The specified key does not exist.\n")),
        ]
    );
    let (_, files) = report_of(&app, &failed).await;
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].0, "failed");
}

/// A job whose report can't be written fails before it does anything.
#[tokio::test]
async fn a_report_that_cant_be_written_fails_the_job() {
    let Some(app) = node().await else { return };
    let account = account(&app).await;
    let admin = user(&app, "admin", None).await;
    tagging_role(&app).await;
    put(&app, "a", b"a".to_vec()).await;
    let etag = manifest(&app, "manifest.csv", &format!("{BUCKET},a\n")).await;
    let id = with_report(&create_request("t1", PUT_TAGS, "manifest.csv", &etag, false, &account), &report("AllTasks"));
    let id = create(&app, &admin, &id).await;
    step(&app, 1).await;
    let job = describe(&app, &admin, &id).await;
    assert_eq!(element(&job, "Status"), Some("Failed"), "{job}");
    assert_eq!(element(&job, "FailureCode"), Some("ReportUnwritable"));
    assert!(element(&job, "FailureReason").unwrap().contains("s3:PutObject"), "{job}");
    step(&app, 2).await;
    assert_eq!(tags_of(&app, "a").await, "");
}

/// A job cancelled while it runs reports the tasks it did.
#[tokio::test]
async fn a_cancelled_job_reports_what_it_did() {
    let Some(app) = node().await else { return };
    // Ten tasks a minute.
    crate::settings::LIFECYCLE_RATE.set(&app.pool.get().await.unwrap(), 600).await.unwrap();
    let account = account(&app).await;
    let admin = user(&app, "admin", None).await;
    role(&app, super::SERVICE, r#"["s3:GetObject","s3:PutObject","s3:PutObjectTagging"]"#).await;
    let lines: String = (0..30).map(|i| format!("{BUCKET},missing{i}\n")).collect();
    let etag = manifest(&app, "manifest.csv", &lines).await;
    let id = with_report(&create_request("t1", PUT_TAGS, "manifest.csv", &etag, false, &account), &report("AllTasks"));
    let id = create(&app, &admin, &id).await;
    step(&app, 1).await;
    step(&app, 2).await;
    let job = describe(&app, &admin, &id).await;
    assert_eq!(element(&job, "Status"), Some("Active"), "{job}");
    assert_eq!(element(&job, "NumberOfTasksFailed"), Some("10"));
    let (status, body) =
        body_of(control::update_status(&app, &access(&admin), &account, &id, "requestedJobStatus=Cancelled").await.unwrap()).await;
    assert_eq!((status, element(&body, "Status")), (StatusCode::OK, Some("Cancelling")), "{body}");
    step(&app, 3).await;
    assert_eq!(status_of(&app, &admin, &id).await, "Cancelled");
    let (_, files) = report_of(&app, &id).await;
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].1.lines().count(), 10);
}

/// Enables Object Lock on the test bucket (and versioning, which it needs).
async fn lock_bucket(app: &App) {
    use crate::s3::{buckets::versioning::put_bucket_versioning, object_lock::put_object_lock_configuration};
    let versioning = "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";
    let response =
        put_bucket_versioning(app, BUCKET, Bytes::from(versioning), crate::mfa::Presented::Absent).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let lock = "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>";
    assert_eq!(put_object_lock_configuration(app, BUCKET, Bytes::from(lock)).await.unwrap().status(), StatusCode::OK);
}

/// The current version of `key`'s lock: its mode, retain-until date (to the
/// second) and legal hold.
async fn lock_of(app: &App, key: &str) -> (Option<String>, Option<i64>, Option<bool>) {
    let client = app.pool.get().await.unwrap();
    let row = client
        .query_one(
            "SELECT retain_mode, extract(epoch FROM retain_until)::bigint, legal_hold FROM objects
             WHERE bucket = $1 AND key = $2 AND is_latest",
            &[&BUCKET, &key],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1), row.get(2))
}

/// S3PutObjectRetention's operation, retaining until `days` from now.
fn retention(mode: &str, days: u64, bypass: bool) -> (String, i64) {
    let until = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() + days * 86_400;
    let bypass = if bypass { "<BypassGovernanceRetention>true</BypassGovernanceRetention>" } else { "" };
    let operation = format!(
        "<S3PutObjectRetention>{bypass}<Retention><RetainUntilDate>{}</RetainUntilDate><Mode>{mode}</Mode></Retention>\
         </S3PutObjectRetention>",
        crate::sessions::iso(until)
    );
    (operation, until as i64)
}

/// Jobs set versions' retention and legal holds, as PutObjectRetention and
/// PutObjectLegalHold would: a job done again does no harm, and shortening
/// a GOVERNANCE retention needs the role to bypass it.
#[tokio::test]
async fn jobs_set_retention_and_legal_holds() {
    let Some(app) = node().await else { return };
    let account = account(&app).await;
    let admin = user(&app, "admin", None).await;
    role(
        &app,
        super::SERVICE,
        r#"["s3:GetObject","s3:PutObject","s3:PutObjectRetention","s3:PutObjectLegalHold"]"#,
    )
    .await;
    put(&app, "a", b"a".to_vec()).await;
    let etag = manifest(&app, "manifest.csv", &format!("{BUCKET},a\n")).await;
    // Each job two steps, later than the last's.
    let run = |token: &'static str, operation: String, report: bool| {
        let minute = 2 * token[1..].parse::<u32>().unwrap() + 1;
        let app = app.clone();
        let admin = &admin;
        let etag = etag.clone();
        let account = account.clone();
        async move {
            let mut request = create_request(token, &operation, "manifest.csv", &etag, false, &account);
            if report {
                request = with_report(&request, &self::report("FailedTasksOnly"));
            }
            let id = create(&app, admin, &request).await;
            step(&app, minute).await;
            step(&app, minute + 1).await;
            let job = describe(&app, admin, &id).await;
            assert_eq!(element(&job, "Status"), Some("Complete"), "{job}");
            (id, element(&job, "NumberOfTasksFailed").unwrap().to_owned())
        }
    };

    // Without Object Lock on the bucket, as PutObjectRetention fails.
    let (id, failed) = run("t0", retention("GOVERNANCE", 2, false).0, true).await;
    assert_eq!(failed, "1");
    let (_, files) = report_of(&app, &id).await;
    assert!(files[0].1.contains(",failed,400,InvalidRequest,Bucket is missing Object Lock Configuration"), "{files:?}");

    lock_bucket(&app).await;
    let (operation, until) = retention("GOVERNANCE", 2, false);
    assert_eq!(run("t1", operation.clone(), false).await.1, "0");
    assert_eq!(lock_of(&app, "a").await, (Some("GOVERNANCE".to_owned()), Some(until), None));
    // Again, as a page done again after its node died would be.
    assert_eq!(run("t2", operation, false).await.1, "0");

    // Shortening it: refused, unless the job asks to bypass GOVERNANCE mode
    // and the role may.
    let (shorter, _) = retention("GOVERNANCE", 1, true);
    let (id, failed) = run("t3", shorter.clone(), true).await;
    assert_eq!(failed, "1");
    let (_, files) = report_of(&app, &id).await;
    assert!(files[0].1.contains(",failed,403,AccessDenied,"), "{files:?}");
    assert_eq!(lock_of(&app, "a").await.1, Some(until));
    let client = app.pool.get().await.unwrap();
    let role = roles::Role::load(&client, &account, ROLE).await.unwrap().unwrap();
    let bypass = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"s3:BypassGovernanceRetention","Resource":"arn:aws:s3:::{BUCKET}/*"}}]}}"#
    );
    roles::put_policy(&client, &role, "bypass", &bypass).await.unwrap();
    let (shorter, until) = retention("GOVERNANCE", 1, true);
    assert_eq!(run("t4", shorter, false).await.1, "0");
    assert_eq!(lock_of(&app, "a").await.1, Some(until));

    // Legal holds.
    let hold = |status: &str| {
        format!("<S3PutObjectLegalHold><LegalHold><Status>{status}</Status></LegalHold></S3PutObjectLegalHold>")
    };
    assert_eq!(run("t5", hold("ON"), false).await.1, "0");
    assert_eq!(lock_of(&app, "a").await.2, Some(true));
    assert_eq!(run("t6", hold("OFF"), false).await.1, "0");
    assert_eq!(lock_of(&app, "a").await.2, Some(false));
}

/// `request`, its manifest an inventory report's (`manifest.json`).
fn of_inventory(request: &str) -> String {
    request
        .replace("S3BatchOperations_CSV_20180820", "S3InventoryReport_CSV_20161130")
        .replace("<Fields><member>Bucket</member><member>Key</member></Fields>", "")
}

fn gzip(text: &str) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(text.as_bytes()).unwrap();
    encoder.finish().unwrap()
}

fn md5_hex(data: &[u8]) -> String {
    use md5::Digest;
    md5::Md5::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// Puts an inventory report of data files `files` (their keys and lines),
/// in `format`, its manifest at `inv/<name>/manifest.json`, listing
/// `md5s` for its files (theirs, if `None`): the manifest's ETag.
async fn put_inventory(app: &Arc<App>, name: &str, files: &[(&str, String)], format: &str, md5s: Option<&[&str]>) -> String {
    let mut listed = Vec::new();
    for (i, (key, lines)) in files.iter().enumerate() {
        let data = gzip(lines);
        let md5 = md5s.map_or_else(|| md5_hex(&data), |md5s| md5s[i].to_owned());
        listed.push(serde_json::json!({ "key": key, "size": data.len(), "MD5checksum": md5 }));
        put(app, key, data).await;
    }
    let manifest = serde_json::json!({
        "sourceBucket": BUCKET,
        "destinationBucket": format!("arn:aws:s3:::{BUCKET}"),
        "version": "2016-11-30",
        "creationTimestamp": "1700000000000",
        "fileFormat": format,
        "fileSchema": "Bucket, Key, VersionId, IsLatest",
        "files": listed,
    });
    let manifest = serde_json::to_vec(&manifest).unwrap();
    let etag = md5_hex(&manifest);
    put(app, &format!("inv/{name}/manifest.json"), manifest).await;
    etag
}

/// A data file's lines, as an inventory report writes them (quoted,
/// with versions' columns), of `keys`.
fn inventory_lines(keys: impl Iterator<Item = String>) -> String {
    keys.map(|key| format!("\"{BUCKET}\",\"{key}\",\"\",\"true\"\n")).collect()
}

/// A job whose manifest is an inventory report Cairn wrote (see
/// `inventory`) does its tasks to the objects the report lists.
#[tokio::test]
async fn a_job_runs_over_an_inventory_report() {
    let Some(app) = node().await else { return };
    let account = account(&app).await;
    let admin = user(&app, "admin", None).await;
    tagging_role(&app).await;
    // Reports of the bucket's `photos/`, into the bucket itself.
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"s3.amazonaws.com"}},
            "Action":"s3:PutObject","Resource":"arn:aws:s3:::{BUCKET}/inv/*"}}]}}"#
    );
    let response = crate::s3::buckets::policy::put_bucket_policy(&app, BUCKET, Bytes::from(policy)).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    put(&app, "photos/a b.jpg", b"a".to_vec()).await;
    put(&app, "photos/c.jpg", b"c".to_vec()).await;
    let configuration = format!(
        "<InventoryConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Destination><S3BucketDestination><Bucket>arn:aws:s3:::{BUCKET}</Bucket><Format>CSV</Format>\
         <Prefix>inv</Prefix></S3BucketDestination></Destination><IsEnabled>true</IsEnabled><Id>daily</Id>\
         <Filter><Prefix>photos/</Prefix></Filter><IncludedObjectVersions>Current</IncludedObjectVersions>\
         <Schedule><Frequency>Daily</Frequency></Schedule></InventoryConfiguration>"
    );
    let response =
        crate::s3::buckets::inventory::put(&app, BUCKET, "inventory&id=daily", Bytes::from(configuration), None).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    step(&app, 1).await;
    let client = app.pool.get().await.unwrap();
    let key: String = client
        .query_one("SELECT key FROM objects WHERE bucket = $1 AND key LIKE 'inv/%/manifest.json' AND is_latest", &[&BUCKET])
        .await
        .unwrap()
        .get(0);
    let etag = md5_hex(&crate::e2e::get(&app, &key).await.unwrap());

    let id = create(&app, &admin, &of_inventory(&create_request("t1", PUT_TAGS, &key, &etag, false, &account))).await;
    step(&app, 2).await;
    let job = describe(&app, &admin, &id).await;
    assert_eq!(element(&job, "Status"), Some("Ready"), "{job}");
    assert_eq!(element(&job, "TotalNumberOfTasks"), Some("2"));
    step(&app, 3).await;
    let job = describe(&app, &admin, &id).await;
    assert_eq!(element(&job, "Status"), Some("Complete"), "{job}");
    assert_eq!(element(&job, "NumberOfTasksSucceeded"), Some("2"));
    assert_eq!(tags_of(&app, "photos/a b.jpg").await, "team=red");
    assert_eq!(tags_of(&app, "photos/c.jpg").await, "team=red");
}

/// An inventory report's data files are read a page at a time, across
/// turns: a turn that starts in the middle of one goes on from there, and
/// each task is done once.
#[tokio::test]
async fn inventory_reports_are_read_a_page_at_a_time() {
    let Some(app) = node().await else { return };
    // Ten tasks a minute.
    crate::settings::LIFECYCLE_RATE.set(&app.pool.get().await.unwrap(), 600).await.unwrap();
    let account = account(&app).await;
    let admin = user(&app, "admin", None).await;
    role(&app, super::SERVICE, r#"["s3:GetObject","s3:PutObject","s3:PutObjectTagging"]"#).await;
    for i in 0..28 {
        put(&app, &format!("k{i:02}"), b"x".to_vec()).await;
    }
    let files = [
        ("inv/r/data/1.csv.gz", inventory_lines((0..25).map(|i| format!("k{i:02}")))),
        ("inv/r/data/2.csv.gz", inventory_lines((25..28).map(|i| format!("k{i:02}")))),
    ];
    let etag = put_inventory(&app, "r", &files, "CSV", None).await;
    let request = of_inventory(&create_request("t1", PUT_TAGS, "inv/r/manifest.json", &etag, false, &account));
    let id = create(&app, &admin, &with_report(&request, &report("AllTasks"))).await;
    step(&app, 1).await;
    assert_eq!(element(&describe(&app, &admin, &id).await, "TotalNumberOfTasks"), Some("28"));
    // Ten tasks a step: the second starts in the middle of the first file.
    step(&app, 2).await;
    step(&app, 3).await;
    let job = describe(&app, &admin, &id).await;
    assert_eq!(element(&job, "Status"), Some("Active"), "{job}");
    assert_eq!(element(&job, "NumberOfTasksSucceeded"), Some("20"), "{job}");
    // The rest of the first file, and the second.
    step(&app, 4).await;
    let job = describe(&app, &admin, &id).await;
    assert_eq!(element(&job, "Status"), Some("Complete"), "{job}");
    assert_eq!(element(&job, "NumberOfTasksSucceeded"), Some("28"));
    assert_eq!(element(&job, "NumberOfTasksFailed"), Some("0"));
    for i in 0..28 {
        assert_eq!(tags_of(&app, &format!("k{i:02}")).await, "team=red", "k{i:02}");
    }
    // The report lists each task once, in order.
    let (_, files) = report_of(&app, &id).await;
    let keys: Vec<String> = files.iter().flat_map(|(_, lines)| lines.lines().map(|l| l.split(',').nth(1).unwrap().to_owned())).collect();
    assert_eq!(keys, (0..28).map(|i| format!("k{i:02}")).collect::<Vec<_>>());
}

/// A job fails, saying why, if its inventory report isn't CSV, if a data
/// file isn't the one its manifest lists, or if one changes after the job
/// was prepared.
#[tokio::test]
async fn inventory_reports_that_cant_be_read_fail_jobs() {
    let Some(app) = node().await else { return };
    let account = account(&app).await;
    let admin = user(&app, "admin", None).await;
    tagging_role(&app).await;
    let lines = inventory_lines(["a".to_owned()].into_iter());
    let job = |token: &'static str, name: &'static str, etag: String, confirmation: bool| {
        let app = app.clone();
        let admin = &admin;
        let account = account.clone();
        async move {
            let key = format!("inv/{name}/manifest.json");
            create(&app, admin, &of_inventory(&create_request(token, PUT_TAGS, &key, &etag, confirmation, &account))).await
        }
    };
    let etag = put_inventory(&app, "parquet", &[("inv/parquet/data/1.parquet", lines.clone())], "Parquet", None).await;
    let parquet = job("t1", "parquet", etag, false).await;
    let etag = put_inventory(&app, "md5", &[("inv/md5/data/1.csv.gz", lines.clone())], "CSV", Some(&["00"])).await;
    let md5 = job("t2", "md5", etag, false).await;
    let etag = put_inventory(&app, "changed", &[("inv/changed/data/1.csv.gz", lines.clone())], "CSV", None).await;
    let changed = job("t3", "changed", etag, true).await;
    step(&app, 1).await;

    let job = describe(&app, &admin, &parquet).await;
    assert_eq!(element(&job, "FailureCode"), Some("ManifestInvalid"), "{job}");
    assert!(element(&job, "FailureReason").unwrap().contains("not CSV"), "{job}");
    let job = describe(&app, &admin, &md5).await;
    assert_eq!(element(&job, "FailureCode"), Some("ManifestInvalid"), "{job}");
    assert!(element(&job, "FailureReason").unwrap().contains("MD5"), "{job}");
    // Prepared, then its data file changes before it's confirmed.
    assert_eq!(status_of(&app, &admin, &changed).await, "Suspended");
    put(&app, "inv/changed/data/1.csv.gz", gzip(&inventory_lines(["b".to_owned()].into_iter()))).await;
    let (status, _) =
        body_of(control::update_status(&app, &access(&admin), &account, &changed, "requestedJobStatus=Ready").await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    step(&app, 2).await;
    let job = describe(&app, &admin, &changed).await;
    assert_eq!(element(&job, "FailureCode"), Some("ManifestETagMismatch"), "{job}");
}

/// The bucket Batch Replication's tests replicate to.
const BACKUP: &str = "backup";

/// Sets up replication of the test bucket's `data/` to `BACKUP`, both
/// versioned, as a role of its own (trusting S3, as replication's must).
async fn replicating(app: &Arc<App>, admin: &Principal) {
    use crate::s3::buckets::{replication, versioning::put_bucket_versioning};
    let client = app.pool.get().await.unwrap();
    client.execute("INSERT INTO buckets (name) VALUES ($1)", &[&BACKUP]).await.unwrap();
    for bucket in [BUCKET, BACKUP] {
        let body = "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";
        let response = put_bucket_versioning(app, bucket, Bytes::from(body), crate::mfa::Presented::Absent).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let account = users::account(&client).await.unwrap();
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"s3.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    let trust = roles::check_trust(&client, &account, trust).await.unwrap();
    let new = roles::New { name: "replication", path: "/", trust: &trust, description: "", max_session_duration: 3600, boundary: None, tags: &[] };
    let id = roles::create(&client, &account, &new).await.unwrap();
    let role = roles::Role::load_id(&client, id).await.unwrap().unwrap();
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":["s3:GetObjectVersionForReplication","s3:ReplicateObject","s3:ReplicateDelete","s3:ReplicateTags"],"Resource":["arn:aws:s3:::{BUCKET}/*","arn:aws:s3:::{BACKUP}/*"]}}]}}"#
    );
    roles::put_policy(&client, &role, "p", &policy).await.unwrap();
    let response = replication::put(app, BUCKET, Bytes::from(replication_config(&account)), &access(admin)).await.unwrap();
    assert_eq!(body_of(response).await.0, StatusCode::OK);
}

/// The version IDs of `bucket`'s `key`, newest first, with their
/// replication statuses.
async fn versions_of(app: &App, bucket: &str, key: &str) -> Vec<(String, Option<String>)> {
    let client = app.pool.get().await.unwrap();
    let rows = client
        .query(
            "SELECT version_id, replication_status FROM objects WHERE bucket = $1 AND key = $2
             ORDER BY last_modified DESC, id DESC",
            &[&bucket, &key],
        )
        .await
        .unwrap();
    rows.iter().map(|r| (r.get(0), r.get(1))).collect()
}

/// A Batch Replication job's request, of a manifest of versions.
fn replication_request(token: &str, key: &str, etag: &str, account: &str) -> String {
    create_request(token, "<S3ReplicateObject/>", key, etag, false, account)
        .replace("<member>Key</member></Fields>", "<member>Key</member><member>VersionId</member></Fields>")
}

/// Batch Replication replicates versions that were there before their
/// rule, as their rule says, in whatever order the manifest lists them:
/// each lands among its key's versions by its time, so the destination's
/// are the source's, in order. What no rule replicates fails as S3 says,
/// and so does a version that isn't there.
#[tokio::test]
async fn batch_replication_replicates_existing_versions() {
    let Some(app) = node().await else { return };
    let account = account(&app).await;
    let admin = user(&app, "admin", None).await;
    role(&app, super::SERVICE, r#"["s3:GetObject","s3:PutObject","s3:InitiateReplication"]"#).await;
    // Written before there's a configuration: not replicated.
    let client = app.pool.get().await.unwrap();
    replicating(&app, &admin).await;
    client.execute("UPDATE buckets SET replication = NULL WHERE name = $1", &[&BUCKET]).await.unwrap();
    for data in [&b"one"[..], b"two", b"three"] {
        put(&app, "data/a", data.to_vec()).await;
    }
    put(&app, "data/b", b"b".to_vec()).await;
    let deleted = crate::s3::objects::delete::delete_object(&app, BUCKET, "data/b", None, false, None, crate::mfa::Presented::Absent)
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    put(&app, "other", b"o".to_vec()).await;
    let response = crate::s3::buckets::replication::put(
        &app,
        BUCKET,
        Bytes::from(replication_config(&account)),
        &access(&admin),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let a = versions_of(&app, BUCKET, "data/a").await;
    let b = versions_of(&app, BUCKET, "data/b").await;
    assert!(a.iter().all(|(_, status)| status.is_none()), "{a:?}");
    assert_eq!(client.query_one("SELECT count(*) FROM replication_queue", &[]).await.unwrap().get::<_, i64>(0), 0);

    // Newest first, as an inventory report lists them; the marker, the
    // object under it, a key no rule picks, a version that isn't there, and
    // a key's current version (by none).
    let other = &versions_of(&app, BUCKET, "other").await[0].0;
    let mut lines: Vec<String> = a.iter().map(|(v, _)| format!("{BUCKET},data/a,{v}")).collect();
    lines.extend(b.iter().map(|(v, _)| format!("{BUCKET},data/b,{v}")));
    lines.push(format!("{BUCKET},other,{other}"));
    lines.push(format!("{BUCKET},data/a,{other}"));
    lines.push(format!("{BUCKET},data/a,"));
    let etag = manifest(&app, "manifest.csv", &lines.join("\n")).await;
    let id = with_report(&replication_request("t1", "manifest.csv", &etag, &account), &report("FailedTasksOnly"));
    let id = create(&app, &admin, &id).await;
    step(&app, 1).await;
    step(&app, 2).await;
    let job = describe(&app, &admin, &id).await;
    assert_eq!(element(&job, "Status"), Some("Complete"), "{job}");
    assert!(job.contains("<S3ReplicateObject/>"), "{job}");
    assert_eq!(element(&job, "NumberOfTasksSucceeded"), Some("6"), "{job}");
    assert_eq!(element(&job, "NumberOfTasksFailed"), Some("2"), "{job}");
    let (_, files) = report_of(&app, &id).await;
    let failed: Vec<(&str, &str)> =
        files[0].1.lines().map(|l| l.split(',').collect::<Vec<_>>()).map(|c| (c[1], c[5])).collect();
    assert_eq!(failed, [("other", "SrcObjectNotEligible"), ("data/a", "NoSuchVersion")]);
    // Queued once each (the current version twice in the manifest), and
    // PENDING until they're replicated.
    assert_eq!(client.query_one("SELECT count(*) FROM replication_queue", &[]).await.unwrap().get::<_, i64>(0), 5);
    assert!(versions_of(&app, BUCKET, "data/a").await.iter().all(|(_, s)| s.as_deref() == Some("PENDING")));

    while crate::replication::round(&app).await.unwrap() > 0 {}
    let ids = |versions: &[(String, Option<String>)]| versions.iter().map(|(v, _)| v.clone()).collect::<Vec<_>>();
    assert_eq!(ids(&versions_of(&app, BACKUP, "data/a").await), ids(&a));
    assert_eq!(ids(&versions_of(&app, BACKUP, "data/b").await), ids(&b));
    assert!(versions_of(&app, BUCKET, "data/a").await.iter().all(|(_, s)| s.as_deref() == Some("COMPLETED")));
    let current = crate::s3::objects::get::get_object(
        &app,
        BACKUP,
        "data/a",
        None,
        None,
        None,
        &crate::s3::conditional::Preconditions::default(),
        None,
        None,
        false,
    )
    .await
    .unwrap();
    assert_eq!(current.into_body().collect().await.unwrap().to_bytes(), &b"three"[..]);
    let head = crate::s3::objects::get::head_object(
        &app,
        BACKUP,
        "data/b",
        None,
        None,
        None,
        &crate::s3::conditional::Preconditions::default(),
        None,
        None,
        false,
    )
    .await
    .unwrap();
    assert_eq!(head.status(), StatusCode::NOT_FOUND, "the marker is current");

    // Again: replicated already, so nothing changes, but they're done.
    let id = create(&app, &admin, &replication_request("t2", "manifest.csv", &etag, &account)).await;
    step(&app, 3).await;
    step(&app, 4).await;
    assert_eq!(element(&describe(&app, &admin, &id).await, "NumberOfTasksSucceeded"), Some("6"));
    while crate::replication::round(&app).await.unwrap() > 0 {}
    assert_eq!(versions_of(&app, BACKUP, "data/a").await.len(), 3);
    assert!(versions_of(&app, BUCKET, "data/a").await.iter().all(|(_, s)| s.as_deref() == Some("COMPLETED")));
}

/// The replication configuration `replicating` sets.
fn replication_config(account: &str) -> String {
    format!(
        "<ReplicationConfiguration><Role>arn:aws:iam::{account}:role/replication</Role>\
         <Rule><ID>data</ID><Priority>1</Priority><Filter><Prefix>data/</Prefix></Filter><Status>Enabled</Status>\
         <Destination><Bucket>arn:aws:s3:::{BACKUP}</Bucket></Destination>\
         <DeleteMarkerReplication><Status>Enabled</Status></DeleteMarkerReplication></Rule></ReplicationConfiguration>"
    )
}

/// A job's role must be allowed `s3:InitiateReplication` on each object,
/// and its bucket must have a replication configuration.
#[tokio::test]
async fn batch_replication_needs_its_permission_and_a_configuration() {
    let Some(app) = node().await else { return };
    let account = account(&app).await;
    let admin = user(&app, "admin", None).await;
    role(&app, super::SERVICE, r#"["s3:GetObject","s3:PutObject"]"#).await;
    put(&app, "data/a", b"a".to_vec()).await;
    let etag = manifest(&app, "manifest.csv", &format!("{BUCKET},data/a,")).await;
    // No configuration (nor versioning) yet.
    let id = with_report(&replication_request("t1", "manifest.csv", &etag, &account), &report("FailedTasksOnly"));
    let id = create(&app, &admin, &id).await;
    step(&app, 1).await;
    step(&app, 2).await;
    let (_, files) = report_of(&app, &id).await;
    assert!(files[0].1.contains(",AccessDenied,"), "{files:?}");
    assert!(files[0].1.contains("s3:InitiateReplication"), "{files:?}");

    let client = app.pool.get().await.unwrap();
    let role = roles::Role::load(&client, &account, ROLE).await.unwrap().unwrap();
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:InitiateReplication"],"Resource":["arn:aws:s3:::{BUCKET}/*"]}}]}}"#
    );
    roles::put_policy(&client, &role, "p", &policy).await.unwrap();
    let id = with_report(&replication_request("t2", "manifest.csv", &etag, &account), &report("FailedTasksOnly"));
    let id = create(&app, &admin, &id).await;
    step(&app, 3).await;
    step(&app, 4).await;
    let (_, files) = report_of(&app, &id).await;
    assert!(files[0].1.contains(",400,SrcBucketReplicationConfigMissing,"), "{files:?}");
}
