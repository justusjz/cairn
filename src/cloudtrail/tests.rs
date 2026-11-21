//! CloudTrail's API end to end, against a real Postgres: LookupEvents over
//! what the nodes shipped, newest first, a page at a time, by an attribute
//! and times; who may look events up; and its refusals.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hyper::{HeaderMap, Method};
use serde_json::{Value, json};

use super::Api;
use crate::{
    App,
    audit::{self, lookup, ship},
    e2e::kms_node,
    s3::access::{Access, Origin},
    users::Principal,
};

/// What a request answered: its result, or its error's type and message.
type Answer = Result<Value, (String, String)>;

async fn call(app: &Arc<App>, principal: &Principal, operation: &str, params: Value) -> Answer {
    let origin = Origin {
        peer: Some("127.0.0.1".parse().unwrap()),
        trusted_proxies: &[],
        signed: None,
        form: false,
    };
    let access = Access::new(
        Some(principal),
        &principal.account,
        &Method::POST,
        &HeaderMap::new(),
        "",
        &origin,
    )
    .unwrap();
    let Value::Object(params) = params else {
        panic!("params are an object")
    };
    let api = Api {
        app,
        principal,
        access: &access,
        params: &params,
        touched: Default::default(),
    };
    api.dispatch(operation)
        .await
        .map_err(|e| (e.kind.to_owned(), e.message))
}

fn ok(answer: Answer) -> Value {
    answer.unwrap_or_else(|(kind, message)| panic!("{kind}: {message}"))
}

fn refused(answer: Answer, kind: &str) {
    match answer {
        Ok(value) => panic!("not refused: {value}"),
        Err((k, message)) => assert_eq!(k, kind, "{message}"),
    }
}

/// A new user `name`, with the identity policy `statements` (none if
/// empty).
async fn user(app: &Arc<App>, name: &str, statements: &str) -> Principal {
    let client = app.pool.get().await.unwrap();
    let account = crate::users::account(&client).await.unwrap();
    let (key, _) = crate::users::create_for(&client, &account, name, None, false)
        .await
        .unwrap();
    if !statements.is_empty() {
        let policy = format!(r#"{{"Version":"2012-10-17","Statement":[{statements}]}}"#);
        crate::users::put_policy(&client, &account, name, "p", &policy)
            .await
            .unwrap();
    }
    Principal::load(&client, &key).await.unwrap().unwrap()
}

/// A record of `account`'s, as `audit::Event` writes them.
fn record(account: &str, id: &str, time: u64, name: &str, user: &str) -> String {
    let mut event = audit::Event::new(
        "kms.amazonaws.com",
        name,
        json!({ "type": "IAMUser", "userName": user, "accessKeyId": format!("AKIA{user}") }),
        account,
        name != "CreateKey",
    );
    event.time = UNIX_EPOCH + Duration::from_secs(time);
    let mut record = event.to_json();
    record["eventID"] = json!(id);
    record.to_string()
}

/// Writes a closed file of the log, opened at `opened` (seconds), into
/// `dir`, with `records`.
fn file(dir: &std::path::Path, opened: u64, seq: u32, records: &[String]) {
    let data: String = records.iter().map(|r| format!("{r}\n")).collect();
    let name = format!("{}-{seq}-0000000{seq}.closed", opened * 1000 + 1);
    std::fs::write(dir.join(name), data).unwrap();
}

/// The IDs of the events of a LookupEvents' answer.
fn ids(answer: &Value) -> Vec<&str> {
    answer["Events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["EventId"].as_str().unwrap())
        .collect()
}

/// Every page of a lookup, `max` events a page.
async fn pages(app: &Arc<App>, who: &Principal, mut params: Value, max: u64) -> Vec<Vec<String>> {
    params["MaxResults"] = json!(max);
    let mut pages = Vec::new();
    loop {
        let answer = ok(call(app, who, "LookupEvents", params.clone()).await);
        pages.push(ids(&answer).iter().map(|s| s.to_string()).collect());
        match answer.get("NextToken") {
            Some(token) => params["NextToken"] = token.clone(),
            None => return pages,
        }
        assert!(pages.len() < 20, "pages without end");
    }
}

/// An account's events are looked up newest first, every node's of a time
/// together, a page at a time; by an attribute, and between times; and no
/// other account's.
#[tokio::test]
async fn events_are_looked_up() {
    let Some(app) = kms_node().await else { return };
    let reader = user(
        &app,
        "reader",
        r#"{"Effect":"Allow","Action":"cloudtrail:LookupEvents","Resource":"*"}"#,
    )
    .await;
    let account = reader.account.clone();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // A five-minute mark an hour ago.
    let base = (now - 3600) / 300 * 300;
    let dir = std::env::temp_dir().join(format!("cairn-lookup-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    // Two nodes' files of a window, and one's of a window ten minutes on.
    file(
        &dir,
        base,
        1,
        &[
            record(&account, "e1", base + 10, "Decrypt", "alice"),
            record(&account, "e2", base + 20, "Encrypt", "bob"),
        ],
    );
    file(
        &dir,
        base + 1,
        2,
        &[
            record(&account, "e3", base + 15, "Decrypt", "alice"),
            record("999999999999", "x1", base + 16, "Decrypt", "eve"),
        ],
    );
    file(
        &dir,
        base + 600,
        3,
        &[
            record(&account, "e4", base + 610, "CreateKey", "alice"),
            // In the same second: after it, as it was logged after it.
            record(&account, "e5", base + 610, "Encrypt", "alice"),
        ],
    );
    // Long ago, past the default 90 days.
    file(
        &dir,
        base - 100 * 86400,
        4,
        &[record(
            &account,
            "old",
            base - 100 * 86400,
            "Decrypt",
            "alice",
        )],
    );
    assert_eq!(ship::ship_all(&app, &dir).await.unwrap(), 4);

    // Each object's index says whose events it has, and which.
    let metadata: Vec<String> = app
        .pool
        .get()
        .await
        .unwrap()
        .query(
            "SELECT metadata FROM objects WHERE bucket = $1 AND key LIKE 'audit/%' ORDER BY key",
            &[&crate::internal::BUCKET],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    let mut accounts = ["999999999999", account.as_str()];
    accounts.sort();
    assert_eq!(
        metadata[2],
        format!(
            "x-amz-meta-accounts: ,{},{},\nx-amz-meta-events: ,Decrypt,\n",
            accounts[0], accounts[1]
        )
    );

    let all = ok(call(&app, &reader, "LookupEvents", json!({})).await);
    assert_eq!(ids(&all), ["e5", "e4", "e2", "e3", "e1"]);
    assert!(all.get("NextToken").is_none());
    let e2 = &all["Events"][2];
    assert_eq!(e2["EventName"], "Encrypt");
    assert_eq!(e2["Username"], "bob");
    assert_eq!(e2["AccessKeyId"], "AKIAbob");
    assert_eq!(e2["ReadOnly"], "true");
    assert_eq!(e2["EventTime"], base + 20);
    assert_eq!(e2["EventSource"], "kms.amazonaws.com");
    let record: Value = serde_json::from_str(e2["CloudTrailEvent"].as_str().unwrap()).unwrap();
    assert_eq!(record["eventID"], "e2");
    assert_eq!(record["recipientAccountId"], account.as_str());

    // A page at a time, the same.
    assert_eq!(
        pages(&app, &reader, json!({}), 1).await,
        [vec!["e5"], vec!["e4"], vec!["e2"], vec!["e3"], vec!["e1"]]
    );
    assert_eq!(
        pages(&app, &reader, json!({}), 2).await,
        [vec!["e5", "e4"], vec!["e2", "e3"], vec!["e1"]]
    );
    assert_eq!(
        pages(&app, &reader, json!({}), 3).await,
        [vec!["e5", "e4", "e2"], vec!["e3", "e1"]]
    );

    // By an attribute.
    let by = |key: &str, value: &str| json!({ "LookupAttributes": [{ "AttributeKey": key, "AttributeValue": value }] });
    let found = |answer: Answer| {
        ids(&ok(answer))
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        found(call(&app, &reader, "LookupEvents", by("EventName", "Decrypt")).await),
        ["e3", "e1"]
    );
    assert_eq!(
        pages(&app, &reader, by("EventName", "Decrypt"), 1).await,
        [vec!["e3"], vec!["e1"]]
    );
    assert_eq!(
        found(call(&app, &reader, "LookupEvents", by("Username", "bob")).await),
        ["e2"]
    );
    assert_eq!(
        found(call(&app, &reader, "LookupEvents", by("ReadOnly", "false")).await),
        ["e4"]
    );
    assert_eq!(
        found(call(&app, &reader, "LookupEvents", by("EventId", "x1")).await),
        Vec::<String>::new()
    );

    // Between times (inclusive), as numbers or as text.
    let between = json!({ "StartTime": base + 12, "EndTime": base + 20 });
    assert_eq!(
        found(call(&app, &reader, "LookupEvents", between).await),
        ["e2", "e3"]
    );
    let iso = |t: u64| crate::sessions::iso(t);
    let between = json!({ "StartTime": iso(base + 600), "EndTime": iso(base + 700) });
    assert_eq!(
        found(call(&app, &reader, "LookupEvents", between).await),
        ["e5", "e4"]
    );
    let long_ago = json!({ "StartTime": base - 101 * 86400, "EndTime": base - 99 * 86400 });
    assert_eq!(
        found(call(&app, &reader, "LookupEvents", long_ago).await),
        ["old"]
    );

    // Another account's are its own.
    let other = lookup::Query {
        account: "999999999999".to_owned(),
        attribute: None,
        start: 0,
        end: now as i64,
        given: (true, true),
        max: 50,
    };
    let page = lookup::lookup(&app, &other, None).await.unwrap();
    let other_ids: Vec<&str> = page
        .events
        .iter()
        .map(|e| e["eventID"].as_str().unwrap())
        .collect();
    assert_eq!(other_ids, ["x1"]);

    // No Insights.
    let insights = json!({ "EventCategory": "insight" });
    assert_eq!(
        found(call(&app, &reader, "LookupEvents", insights).await),
        Vec::<String>::new()
    );

    // A token is its lookup's alone.
    let first = ok(call(&app, &reader, "LookupEvents", json!({ "MaxResults": 1 })).await);
    let token = first["NextToken"].clone();
    let mut elsewhere = by("EventName", "Decrypt");
    elsewhere["NextToken"] = token;
    refused(
        call(&app, &reader, "LookupEvents", elsewhere).await,
        "InvalidNextTokenException",
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Who may look events up, as their identity policies say; and the
/// lookups CloudTrail refuses.
#[tokio::test]
async fn lookups_are_checked() {
    let Some(app) = kms_node().await else { return };
    let nobody = user(&app, "nobody", "").await;
    refused(
        call(&app, &nobody, "LookupEvents", json!({})).await,
        "AccessDeniedException",
    );
    let reader = user(
        &app,
        "reader",
        r#"{"Effect":"Allow","Action":"cloudtrail:Lookup*","Resource":"*"}"#,
    )
    .await;
    assert_eq!(
        ok(call(&app, &reader, "LookupEvents", json!({})).await),
        json!({ "Events": [] })
    );
    let attribute =
        |key: &str, value: &str| json!({ "AttributeKey": key, "AttributeValue": value });
    for (params, kind) in [
        (
            json!({ "LookupAttributes": [attribute("EventName", "a"), attribute("Username", "b")] }),
            "InvalidLookupAttributesException",
        ),
        (
            json!({ "LookupAttributes": [attribute("Color", "red")] }),
            "InvalidLookupAttributesException",
        ),
        (
            json!({ "LookupAttributes": [attribute("EventName", "")] }),
            "InvalidLookupAttributesException",
        ),
        (json!({ "MaxResults": 0 }), "InvalidMaxResultsException"),
        (json!({ "MaxResults": 51 }), "InvalidMaxResultsException"),
        (
            json!({ "StartTime": 1_800_000_000, "EndTime": 1_700_000_000 }),
            "InvalidTimeRangeException",
        ),
        (
            json!({ "NextToken": "garbage" }),
            "InvalidNextTokenException",
        ),
        (
            json!({ "EventCategory": "data" }),
            "InvalidEventCategoryException",
        ),
        (
            json!({ "StartTime": "yesterday" }),
            "SerializationException",
        ),
    ] {
        refused(
            call(&app, &reader, "LookupEvents", params.clone()).await,
            kind,
        );
    }
    refused(
        call(&app, &reader, "CreateTrail", json!({})).await,
        "InvalidTrailNameException",
    );
    assert_eq!(super::read_only("LookupEvents"), Some(true));
    assert_eq!(super::read_only("CreateTrail"), Some(false));
    assert_eq!(super::read_only("Frobnicate"), None);
}

/// What's logged is found once it's shipped: a node's records, from its
/// log to LookupEvents.
#[tokio::test]
async fn logged_events_are_found() {
    use crate::audit::log::Rotation;

    let Some(app) = kms_node().await else { return };
    let mut app = Arc::into_inner(app).expect("a new node isn't shared");
    let dir = std::env::temp_dir().join(format!("cairn-audit-{}", uuid::Uuid::new_v4()));
    let rotation = Rotation {
        period: Duration::from_millis(1),
        bytes: u64::MAX,
    };
    app.audit = audit::Audit::start_with(dir.clone(), rotation).unwrap();
    let app = Arc::new(app);
    let reader = user(
        &app,
        "reader",
        r#"{"Effect":"Allow","Action":"cloudtrail:LookupEvents","Resource":"*"}"#,
    )
    .await;
    let mut event = audit::Event::new(
        "kms.amazonaws.com",
        "GenerateRandom",
        audit::identity(&reader, "AKIAREADER"),
        &reader.account,
        true,
    );
    event.request_id = "r-1".to_owned();
    app.audit.record(&event).await.unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut found = Vec::new();
    while found.is_empty() {
        assert!(std::time::Instant::now() < deadline, "never found");
        tokio::time::sleep(Duration::from_millis(50)).await;
        ship::ship_all(&app, &dir).await.unwrap();
        let answer = ok(call(&app, &reader, "LookupEvents", json!({})).await);
        found = answer["Events"].as_array().unwrap().clone();
    }
    assert_eq!(found.len(), 1);
    assert_eq!(found[0]["EventId"], event.id.to_string());
    assert_eq!(found[0]["Username"], "reader");
    assert_eq!(found[0]["AccessKeyId"], "AKIAREADER");
    let record: Value =
        serde_json::from_str(found[0]["CloudTrailEvent"].as_str().unwrap()).unwrap();
    assert_eq!(record, event.to_json());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The bucket trails deliver to, in the tests.
const LOGS: &str = "trail-logs";

/// A user who may do anything with CloudTrail.
async fn admin(app: &Arc<App>) -> Principal {
    user(
        app,
        "admin",
        r#"{"Effect":"Allow","Action":"cloudtrail:*","Resource":"*"}"#,
    )
    .await
}

/// Creates the bucket `LOGS`, with a policy that lets CloudTrail write the
/// log files of `account`'s trails to it with `prefix` (CloudTrail's own
/// example, but for any trail of the account's).
async fn logs_bucket(app: &Arc<App>, account: &str, prefix: &str) {
    let client = app.pool.get().await.unwrap();
    client
        .execute(
            "INSERT INTO buckets (name) VALUES ($1) ON CONFLICT DO NOTHING",
            &[&LOGS],
        )
        .await
        .unwrap();
    logs_policy(app, account, prefix).await;
}

/// Sets the policy of `LOGS` (see `logs_bucket`).
async fn logs_policy(app: &Arc<App>, account: &str, prefix: &str) {
    let region = crate::s3::buckets::head::REGION;
    let policy = json!({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": { "Service": "cloudtrail.amazonaws.com" },
                "Action": "s3:GetBucketAcl",
                "Resource": format!("arn:aws:s3:::{LOGS}"),
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": { "Service": "cloudtrail.amazonaws.com" },
                "Action": "s3:PutObject",
                "Resource": format!("arn:aws:s3:::{LOGS}/{prefix}AWSLogs/{account}/*"),
                "Condition": {
                    "StringEquals": { "s3:x-amz-acl": "bucket-owner-full-control" },
                    "StringLike": {
                        "aws:SourceArn": format!("arn:aws:cloudtrail:{region}:{account}:trail/*"),
                    },
                },
            },
        ],
    });
    let response = crate::s3::buckets::policy::put_bucket_policy(
        app,
        LOGS,
        hyper::body::Bytes::from(policy.to_string()),
    )
    .await
    .unwrap();
    assert!(response.status().is_success(), "{:?}", response.status());
}

/// Removes the policy of `LOGS`.
async fn no_logs_policy(app: &Arc<App>) {
    app.pool
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE buckets SET policy = NULL, policy_principals = NULL WHERE name = $1",
            &[&LOGS],
        )
        .await
        .unwrap();
}

/// A trail is created, read back, changed, tagged, and deleted; and the
/// trails CloudTrail refuses are.
#[tokio::test]
async fn trails_are_managed() {
    let Some(app) = kms_node().await else { return };
    let admin = admin(&app).await;
    let account = admin.account.clone();
    let region = crate::s3::buckets::head::REGION;
    let arn = format!("arn:aws:cloudtrail:{region}:{account}:trail/main");

    // A bucket that isn't there, or doesn't let CloudTrail write.
    let main = json!({ "Name": "main", "S3BucketName": LOGS });
    refused(
        call(&app, &admin, "CreateTrail", main.clone()).await,
        "S3BucketDoesNotExistException",
    );
    logs_bucket(&app, &account, "").await;
    no_logs_policy(&app).await;
    refused(
        call(&app, &admin, "CreateTrail", main.clone()).await,
        "InsufficientS3BucketPolicyException",
    );
    logs_policy(&app, &account, "").await;

    // Created: not logging yet.
    let mut tagged = main.clone();
    tagged["TagsList"] = json!([{ "Key": "team", "Value": "storage" }]);
    let created = ok(call(&app, &admin, "CreateTrail", tagged).await);
    assert_eq!(
        created,
        json!({
            "Name": "main",
            "S3BucketName": LOGS,
            "IncludeGlobalServiceEvents": true,
            "IsMultiRegionTrail": false,
            "TrailARN": arn,
            "LogFileValidationEnabled": false,
            "IsOrganizationTrail": false,
        })
    );
    refused(
        call(&app, &admin, "CreateTrail", main.clone()).await,
        "TrailAlreadyExistsException",
    );
    let status = ok(call(&app, &admin, "GetTrailStatus", json!({ "Name": "main" })).await);
    assert_eq!(status["IsLogging"], false);
    assert!(status.get("LatestDeliveryTime").is_none());

    // Read back, by its name or ARN.
    let got = ok(call(&app, &admin, "GetTrail", json!({ "Name": arn })).await);
    assert_eq!(got["Trail"]["Name"], "main");
    assert_eq!(got["Trail"]["HomeRegion"], region);
    assert_eq!(got["Trail"]["HasCustomEventSelectors"], false);
    let described = ok(call(&app, &admin, "DescribeTrails", json!({})).await);
    assert_eq!(described["trailList"].as_array().unwrap().len(), 1);
    let described = ok(call(
        &app,
        &admin,
        "DescribeTrails",
        json!({ "trailNameList": ["other", arn] }),
    )
    .await);
    assert_eq!(described["trailList"][0]["TrailARN"], arn);
    assert_eq!(described["trailList"].as_array().unwrap().len(), 1);
    let listed = ok(call(&app, &admin, "ListTrails", json!({})).await);
    assert_eq!(
        listed,
        json!({ "Trails": [{ "TrailARN": arn, "Name": "main", "HomeRegion": region }] })
    );

    // Its selectors: every management event, until they're set.
    let selectors = ok(call(
        &app,
        &admin,
        "GetEventSelectors",
        json!({ "TrailName": "main" }),
    )
    .await);
    assert_eq!(
        selectors,
        json!({
            "TrailARN": arn,
            "EventSelectors": [{
                "ReadWriteType": "All",
                "IncludeManagementEvents": true,
                "DataResources": [],
                "ExcludeManagementEventSources": [],
            }],
        })
    );
    let advanced = json!([{
        "Name": "writes",
        "FieldSelectors": [
            { "Field": "eventCategory", "Equals": ["Management"] },
            { "Field": "readOnly", "Equals": ["false"] },
        ],
    }]);
    let put = ok(call(
        &app,
        &admin,
        "PutEventSelectors",
        json!({ "TrailName": arn, "AdvancedEventSelectors": advanced }),
    )
    .await);
    assert_eq!(put["AdvancedEventSelectors"], advanced);
    let selectors = ok(call(
        &app,
        &admin,
        "GetEventSelectors",
        json!({ "TrailName": "main" }),
    )
    .await);
    assert_eq!(selectors["AdvancedEventSelectors"], advanced);
    assert!(selectors.get("EventSelectors").is_none());
    let got = ok(call(&app, &admin, "GetTrail", json!({ "Name": "main" })).await);
    assert_eq!(got["Trail"]["HasCustomEventSelectors"], true);
    refused(
        call(
            &app,
            &admin,
            "PutEventSelectors",
            json!({ "TrailName": "main", "EventSelectors": [{ "ReadWriteType": "Never" }] }),
        )
        .await,
        "InvalidEventSelectorsException",
    );
    // No Insights.
    refused(
        call(
            &app,
            &admin,
            "GetInsightSelectors",
            json!({ "TrailName": "main" }),
        )
        .await,
        "InsightNotEnabledException",
    );

    // Tags.
    ok(call(
        &app,
        &admin,
        "AddTags",
        json!({ "ResourceId": arn, "TagsList": [
            { "Key": "team", "Value": "kms" },
            { "Key": "cost", "Value": "1" },
        ] }),
    )
    .await);
    ok(call(
        &app,
        &admin,
        "RemoveTags",
        json!({ "ResourceId": arn, "TagsList": [{ "Key": "cost" }] }),
    )
    .await);
    let tags = ok(call(&app, &admin, "ListTags", json!({ "ResourceIdList": [arn] })).await);
    assert_eq!(
        tags,
        json!({ "ResourceTagList": [{
            "ResourceId": arn,
            "TagsList": [{ "Key": "team", "Value": "kms" }],
        }] })
    );
    refused(
        call(
            &app,
            &admin,
            "ListTags",
            json!({ "ResourceIdList": ["main"] }),
        )
        .await,
        "CloudTrailARNInvalidException",
    );
    let elsewhere = format!("arn:aws:cloudtrail:{region}:{account}:trail/nope");
    refused(
        call(
            &app,
            &admin,
            "ListTags",
            json!({ "ResourceIdList": [elsewhere] }),
        )
        .await,
        "ResourceNotFoundException",
    );
    let many: Vec<Value> = (0..51)
        .map(|n| json!({ "Key": format!("k{n}"), "Value": "v" }))
        .collect();
    refused(
        call(
            &app,
            &admin,
            "AddTags",
            json!({ "ResourceId": arn, "TagsList": many }),
        )
        .await,
        "TagsLimitExceededException",
    );

    // Changed: a prefix the bucket's policy doesn't allow, then one it does.
    refused(
        call(
            &app,
            &admin,
            "UpdateTrail",
            json!({ "Name": "main", "S3KeyPrefix": "cairn" }),
        )
        .await,
        "InsufficientS3BucketPolicyException",
    );
    logs_policy(&app, &account, "cairn/").await;
    let updated = ok(call(
        &app,
        &admin,
        "UpdateTrail",
        json!({ "Name": "main", "S3KeyPrefix": "cairn", "IsMultiRegionTrail": true }),
    )
    .await);
    assert_eq!(updated["S3KeyPrefix"], "cairn");
    assert_eq!(updated["IsMultiRegionTrail"], true);
    refused(
        call(
            &app,
            &admin,
            "UpdateTrail",
            json!({ "Name": "main", "IncludeGlobalServiceEvents": false }),
        )
        .await,
        "InvalidParameterCombinationException",
    );

    // What CloudTrail (or Cairn) refuses.
    for (params, kind) in [
        (
            json!({ "Name": "a b", "S3BucketName": LOGS }),
            "InvalidTrailNameException",
        ),
        (
            json!({ "Name": "x--y", "S3BucketName": LOGS }),
            "InvalidTrailNameException",
        ),
        (
            json!({ "Name": "nobucket" }),
            "InvalidS3BucketNameException",
        ),
        (
            json!({ "Name": "global", "S3BucketName": LOGS, "IsMultiRegionTrail": true,
                    "IncludeGlobalServiceEvents": false }),
            "InvalidParameterCombinationException",
        ),
        (
            json!({ "Name": "sns", "S3BucketName": LOGS, "SnsTopicName": "t" }),
            "UnsupportedOperationException",
        ),
        (
            json!({ "Name": "digests", "S3BucketName": LOGS, "EnableLogFileValidation": true }),
            "UnsupportedOperationException",
        ),
        (
            json!({ "Name": "long", "S3BucketName": LOGS, "S3KeyPrefix": "p".repeat(201) }),
            "InvalidS3PrefixException",
        ),
        (
            json!({ "Name": "keyless", "S3BucketName": LOGS,
                    "KmsKeyId": "00000000-0000-0000-0000-000000000000" }),
            "KmsKeyNotFoundException",
        ),
        (
            json!({ "Name": "tags", "S3BucketName": LOGS,
                    "TagsList": [{ "Key": "aws:x", "Value": "y" }] }),
            "InvalidTagParameterException",
        ),
    ] {
        refused(
            call(&app, &admin, "CreateTrail", params.clone()).await,
            kind,
        );
    }
    for (operation, params, kind) in [
        (
            "GetTrail",
            json!({ "Name": "nope" }),
            "TrailNotFoundException",
        ),
        (
            "StartLogging",
            json!({ "Name": "nope" }),
            "TrailNotFoundException",
        ),
        (
            "GetTrail",
            json!({ "Name": format!("arn:aws:cloudtrail:{region}:444455556666:trail/main") }),
            "TrailNotFoundException",
        ),
        (
            "GetTrail",
            json!({ "Name": format!("arn:aws:cloudtrail:{region}:{account}:main") }),
            "CloudTrailARNInvalidException",
        ),
        (
            "DeleteTrail",
            json!({ "Name": "nope" }),
            "TrailNotFoundException",
        ),
    ] {
        refused(call(&app, &admin, operation, params).await, kind);
    }

    // At most five trails.
    for n in 2..=5 {
        ok(call(
            &app,
            &admin,
            "CreateTrail",
            json!({ "Name": format!("trail{n}"), "S3BucketName": LOGS, "S3KeyPrefix": "cairn" }),
        )
        .await);
    }
    refused(
        call(
            &app,
            &admin,
            "CreateTrail",
            json!({ "Name": "trail6", "S3BucketName": LOGS, "S3KeyPrefix": "cairn" }),
        )
        .await,
        "MaximumNumberOfTrailsExceededException",
    );

    // Deleted.
    ok(call(&app, &admin, "DeleteTrail", json!({ "Name": arn })).await);
    refused(
        call(&app, &admin, "GetTrail", json!({ "Name": "main" })).await,
        "TrailNotFoundException",
    );
    let listed = ok(call(&app, &admin, "ListTrails", json!({})).await);
    assert_eq!(listed["Trails"].as_array().unwrap().len(), 4);
}

/// Who may do what with trails, as their identity policies say: on a
/// trail's ARN.
#[tokio::test]
async fn trails_are_checked() {
    let Some(app) = kms_node().await else { return };
    let admin = admin(&app).await;
    let account = admin.account.clone();
    logs_bucket(&app, &account, "").await;
    ok(call(
        &app,
        &admin,
        "CreateTrail",
        json!({ "Name": "mine", "S3BucketName": LOGS }),
    )
    .await);
    ok(call(
        &app,
        &admin,
        "CreateTrail",
        json!({ "Name": "theirs", "S3BucketName": LOGS }),
    )
    .await);
    let region = crate::s3::buckets::head::REGION;
    let statement = format!(
        r#"{{"Effect":"Allow","Action":["cloudtrail:GetTrail","cloudtrail:StartLogging"],
            "Resource":"arn:aws:cloudtrail:{region}:{account}:trail/mine"}}"#
    );
    let operator = user(&app, "operator", &statement).await;
    ok(call(&app, &operator, "GetTrail", json!({ "Name": "mine" })).await);
    ok(call(&app, &operator, "StartLogging", json!({ "Name": "mine" })).await);
    for (operation, params) in [
        ("GetTrail", json!({ "Name": "theirs" })),
        ("StopLogging", json!({ "Name": "mine" })),
        ("DeleteTrail", json!({ "Name": "mine" })),
        ("DescribeTrails", json!({})),
        (
            "CreateTrail",
            json!({ "Name": "new", "S3BucketName": LOGS }),
        ),
    ] {
        refused(
            call(&app, &operator, operation, params).await,
            "AccessDeniedException",
        );
    }
    for operation in ["CreateTrail", "ListTrails", "ListPublicKeys", "GetTrail"] {
        let expected = super::read_only(operation);
        assert!(expected.is_some(), "{operation}");
    }
    assert_eq!(super::read_only("CreateTrail"), Some(false));
    assert_eq!(super::read_only("DescribeTrails"), Some(true));
    refused(
        call(&app, &admin, "ListPublicKeys", json!({})).await,
        "UnsupportedOperationException",
    );
}

/// The log files delivered to `LOGS`: their keys, and their records' IDs.
async fn delivered(app: &Arc<App>) -> Vec<(String, Vec<String>)> {
    let keys: Vec<String> = app
        .pool
        .get()
        .await
        .unwrap()
        .query(
            "SELECT key FROM objects WHERE bucket = $1 AND is_latest ORDER BY key",
            &[&LOGS],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    let mut files = Vec::new();
    for key in keys {
        use http_body_util::BodyExt;
        let response = crate::s3::objects::get::get_object(
            app,
            LOGS,
            &key,
            None,
            None,
            None,
            &Default::default(),
            None,
            None,
            false,
        )
        .await
        .unwrap();
        assert!(
            response.status().is_success(),
            "{key}: {}",
            response.status()
        );
        let gz = response.into_body().collect().await.unwrap().to_bytes();
        let mut data = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&gz[..]), &mut data).unwrap();
        let file: Value = serde_json::from_slice(&data).unwrap();
        let ids = file["Records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["eventID"].as_str().unwrap().to_owned())
            .collect();
        files.push((key, ids));
    }
    files
}

/// Every record ID of what's been delivered to `LOGS`, in order.
async fn delivered_ids(app: &Arc<App>) -> Vec<String> {
    let mut ids: Vec<String> = delivered(app)
        .await
        .into_iter()
        .flat_map(|(_, ids)| ids)
        .collect();
    ids.sort();
    ids
}

/// How many objects are queued for delivery.
async fn queued(app: &Arc<App>) -> i64 {
    app.pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT count(*) FROM cloudtrail_pending", &[])
        .await
        .unwrap()
        .get(0)
}

/// A trail delivers its account's events, those its selectors select,
/// while it's logging, as CloudTrail's log files; those that fail are
/// tried again; and one node at a time delivers.
#[tokio::test]
async fn trails_deliver_their_events() {
    use super::delivery;

    let Some(app) = kms_node().await else { return };
    let admin = admin(&app).await;
    let account = admin.account.clone();
    logs_bucket(&app, &account, "").await;
    ok(call(
        &app,
        &admin,
        "CreateTrail",
        json!({ "Name": "main", "S3BucketName": LOGS }),
    )
    .await);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let dir = std::env::temp_dir().join(format!("cairn-trail-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();

    // Shipped before it logs: not queued.
    file(
        &dir,
        now,
        1,
        &[record(&account, "early", now - 600, "Decrypt", "alice")],
    );
    ship::ship_all(&app, &dir).await.unwrap();
    assert_eq!(queued(&app).await, 0);
    // Once it starts, what was shipped of the five minutes it started in
    // is (its events of since it started are its).
    ok(call(&app, &admin, "StartLogging", json!({ "Name": "main" })).await);
    assert_eq!(queued(&app).await, 1);
    // As if it had started an hour ago, so that the events of the test's
    // files are of since then (they're logged after their times).
    let set = async |sql: &str| {
        app.pool
            .get()
            .await
            .unwrap()
            .execute(sql, &[])
            .await
            .unwrap();
    };
    set("UPDATE cloudtrail_trails SET started_at = now() - interval '1 hour'").await;
    assert!(
        ok(call(&app, &admin, "GetTrailStatus", json!({ "Name": "main" })).await)["IsLogging"]
            == true
    );

    // Two nodes' files: the account's events, and another account's.
    file(
        &dir,
        now + 1,
        2,
        &[
            record(&account, "e1", now - 500, "Decrypt", "alice"),
            record("999999999999", "x1", now - 500, "Decrypt", "eve"),
        ],
    );
    file(
        &dir,
        now + 2,
        3,
        &[record(&account, "e2", now - 500, "CreateKey", "bob")],
    );
    ship::ship_all(&app, &dir).await.unwrap();
    assert_eq!(queued(&app).await, 3);

    let report = delivery::deliver(&app).await.unwrap();
    assert!(report.failed.is_empty(), "{report:?}");
    assert_eq!(queued(&app).await, 0);
    assert_eq!(delivered_ids(&app).await, ["e1", "e2", "early"]);
    let files = delivered(&app).await;
    assert_eq!(files.len(), 1);
    let region = crate::s3::buckets::head::REGION;
    let prefix = format!("AWSLogs/{account}/CloudTrail/{region}/");
    let key = &files[0].0;
    assert!(key.starts_with(&prefix), "{key}");
    let name = key.rsplit('/').next().unwrap();
    assert!(
        name.starts_with(&format!("{account}_CloudTrail_{region}_")) && name.ends_with(".json.gz"),
        "{name}"
    );
    let status = ok(call(&app, &admin, "GetTrailStatus", json!({ "Name": "main" })).await);
    assert!(status["LatestDeliveryTime"].is_number(), "{status}");
    assert!(status.get("LatestDeliveryError").is_none(), "{status}");
    assert_ne!(status["LatestDeliveryAttemptSucceeded"], "");

    // Only writes, now; and a bucket whose policy no longer lets
    // CloudTrail write: tried again, until it does.
    ok(call(
        &app,
        &admin,
        "PutEventSelectors",
        json!({ "TrailName": "main", "EventSelectors": [{ "ReadWriteType": "WriteOnly" }] }),
    )
    .await);
    no_logs_policy(&app).await;
    file(
        &dir,
        now + 3,
        4,
        &[
            record(&account, "e3", now - 400, "Decrypt", "alice"),
            record(&account, "e4", now - 400, "CreateKey", "alice"),
        ],
    );
    ship::ship_all(&app, &dir).await.unwrap();
    let report = delivery::deliver(&app).await.unwrap();
    assert_eq!(report.failed.len(), 1, "{report:?}");
    assert_eq!(queued(&app).await, 1);
    let status = ok(call(&app, &admin, "GetTrailStatus", json!({ "Name": "main" })).await);
    let error = status["LatestDeliveryError"].as_str().unwrap();
    assert!(error.starts_with("AccessDenied"), "{error}");
    assert_eq!(status["LatestDeliveryAttemptSucceeded"], "");
    logs_policy(&app, &account, "").await;
    let report = delivery::deliver(&app).await.unwrap();
    assert!(report.failed.is_empty(), "{report:?}");
    assert_eq!(queued(&app).await, 0);
    assert_eq!(delivered_ids(&app).await, ["e1", "e2", "e4", "early"]);
    let status = ok(call(&app, &admin, "GetTrailStatus", json!({ "Name": "main" })).await);
    assert!(status.get("LatestDeliveryError").is_none(), "{status}");

    // Stopped: its events of before it stopped are delivered, not after.
    ok(call(&app, &admin, "StopLogging", json!({ "Name": "main" })).await);
    set("UPDATE cloudtrail_trails SET stopped_at = now() - interval '300 seconds'").await;
    let stopped =
        ok(call(&app, &admin, "GetTrailStatus", json!({ "Name": "main" })).await)["StopLoggingTime"]
            .as_f64()
            .unwrap() as u64;
    file(
        &dir,
        now + 4,
        5,
        &[
            record(&account, "e5", stopped, "CreateKey", "alice"),
            record(&account, "late", stopped + 100, "CreateKey", "alice"),
        ],
    );
    ship::ship_all(&app, &dir).await.unwrap();
    delivery::deliver(&app).await.unwrap();
    assert_eq!(delivered_ids(&app).await, ["e1", "e2", "e4", "e5", "early"]);

    // One node at a time: not while another holds the lease.
    ok(call(&app, &admin, "StartLogging", json!({ "Name": "main" })).await);
    let started = ok(call(&app, &admin, "GetTrailStatus", json!({ "Name": "main" })).await)
        ["StartLoggingTime"]
        .as_f64()
        .unwrap() as u64;
    file(
        &dir,
        now + 5,
        6,
        &[record(&account, "e6", started + 1, "CreateKey", "alice")],
    );
    ship::ship_all(&app, &dir).await.unwrap();
    let other = uuid::Uuid::new_v4();
    app.pool
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE cloudtrail_delivery SET holder = $1, lease_until = now() + interval '1 minute'",
            &[&other],
        )
        .await
        .unwrap();
    let mine = uuid::Uuid::new_v4();
    assert_eq!(delivery::deliver_leased(&app, mine).await.unwrap(), None);
    // (Started again, it has the objects of the five minutes it started
    // in queued again too, whose events of before then aren't its.)
    assert!(queued(&app).await >= 1);
    app.pool
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE cloudtrail_delivery SET lease_until = now() - interval '1 second'",
            &[],
        )
        .await
        .unwrap();
    let report = delivery::deliver_leased(&app, mine).await.unwrap().unwrap();
    assert_eq!(report.files.len(), 1);
    assert_eq!(queued(&app).await, 0);
    assert_eq!(
        delivered_ids(&app).await,
        ["e1", "e2", "e4", "e5", "e6", "early"]
    );

    // Deleted: what's queued for it goes with it.
    file(
        &dir,
        now + 6,
        7,
        &[record(&account, "e7", started + 2, "CreateKey", "alice")],
    );
    ship::ship_all(&app, &dir).await.unwrap();
    assert_eq!(queued(&app).await, 1);
    ok(call(&app, &admin, "DeleteTrail", json!({ "Name": "main" })).await);
    assert_eq!(queued(&app).await, 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A trail with a KMS key has its log files encrypted with it (SSE-KMS),
/// if the key's policy lets CloudTrail use it.
#[tokio::test]
async fn trails_encrypt_with_their_keys() {
    use super::delivery;
    use crate::kms::keys;

    let Some(app) = kms_node().await else { return };
    let admin = admin(&app).await;
    let account = admin.account.clone();
    logs_bucket(&app, &account, "").await;
    let new_key = async |policy: &Value| {
        let client = app.pool.get().await.unwrap();
        let new = keys::NewKey {
            account: &account,
            description: "",
            policy: &policy.to_string(),
            aws_managed: false,
            tags: &[],
        };
        keys::create(app.kms.as_ref().unwrap(), &client, &new)
            .await
            .unwrap()
            .unwrap()
            .arn()
    };
    let owner = json!({
        "Sid": "Owner",
        "Effect": "Allow",
        "Principal": { "AWS": format!("arn:aws:iam::{account}:root") },
        "Action": "kms:*",
        "Resource": "*",
    });
    let unusable = new_key(&json!({ "Version": "2012-10-17", "Statement": [owner] })).await;
    refused(
        call(
            &app,
            &admin,
            "CreateTrail",
            json!({ "Name": "main", "S3BucketName": LOGS, "KmsKeyId": unusable }),
        )
        .await,
        "InsufficientEncryptionPolicyException",
    );
    // CloudTrail's own example's statement.
    let region = crate::s3::buckets::head::REGION;
    let usable = new_key(&json!({ "Version": "2012-10-17", "Statement": [owner, {
        "Sid": "Allow CloudTrail to encrypt logs",
        "Effect": "Allow",
        "Principal": { "Service": "cloudtrail.amazonaws.com" },
        "Action": "kms:GenerateDataKey*",
        "Resource": "*",
        "Condition": {
            "StringEquals": {
                "aws:SourceArn": format!("arn:aws:cloudtrail:{region}:{account}:trail/main"),
            },
            "StringLike": {
                "kms:EncryptionContext:aws:cloudtrail:arn":
                    format!("arn:aws:cloudtrail:*:{account}:trail/*"),
            },
        },
    }] }))
    .await;
    let created = ok(call(
        &app,
        &admin,
        "CreateTrail",
        json!({ "Name": "main", "S3BucketName": LOGS, "KmsKeyId": usable }),
    )
    .await);
    assert_eq!(created["KmsKeyId"], usable);
    ok(call(&app, &admin, "StartLogging", json!({ "Name": "main" })).await);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let dir = std::env::temp_dir().join(format!("cairn-trail-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    file(
        &dir,
        now,
        1,
        &[record(&account, "e1", now + 10, "CreateKey", "alice")],
    );
    ship::ship_all(&app, &dir).await.unwrap();
    let report = delivery::deliver(&app).await.unwrap();
    assert!(report.failed.is_empty(), "{report:?}");
    assert_eq!(report.files.len(), 1);
    let encrypted: Option<String> = app
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT sse_kms_key_id FROM objects WHERE bucket = $1 AND is_latest",
            &[&LOGS],
        )
        .await
        .unwrap()
        .get(0);
    assert!(encrypted.is_some_and(|k| usable.ends_with(&k) || k == usable));
    std::fs::remove_dir_all(&dir).unwrap();
}
