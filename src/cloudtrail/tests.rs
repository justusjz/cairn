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
        "UnsupportedOperationException",
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
