//! The console's API for CloudTrail: the account's event history
//! (`LookupEvents`) and its trails, with their status, event selectors and
//! tags (see `cloudtrail`). Each call is CloudTrail's own operation, run as
//! the session's identity (`cloudtrail::console_call`), so it's checked and
//! validated exactly as CloudTrail's API checks it, and recorded, as
//! CloudTrail records the console's calls (`sessionCredentialFromConsole`):
//! the console is no way around the log. Reads take what that answers
//! apart.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::actor::Actor;
use super::manage::{AppState, Result, Tag};
use super::web::{ApiError, ErrorBody};
use crate::App;

pub(super) fn router() -> OpenApiRouter<Arc<App>> {
    OpenApiRouter::new()
        .routes(routes!(lookup_events))
        .routes(routes!(list_trails, create_trail))
        .routes(routes!(get_trail, update_trail, delete_trail))
        .routes(routes!(set_trail_logging))
        .routes(routes!(set_trail_selectors))
        .routes(routes!(set_trail_tags))
}

/// Runs CloudTrail's `operation`, as `actor`, with `params` (an object):
/// its answer.
async fn call(app: &Arc<App>, actor: &Actor, operation: &str, params: Value) -> Result<Value> {
    let access = actor.access_for(app).await?;
    let Value::Object(params) = params else {
        return Err(ApiError::Failed(anyhow::anyhow!(
            "CloudTrail's {operation}: its parameters aren't an object"
        )));
    };
    let user = &actor.0;
    crate::cloudtrail::console_call(
        app,
        &user.principal,
        &access,
        &user.headers,
        user.peer,
        user.mfa_age.is_some(),
        operation,
        params,
    )
    .await
    .map_err(|e| match e.kind {
        "AccessDeniedException" => ApiError::Forbidden(e.message),
        "TrailNotFoundException" | "ResourceNotFoundException" => ApiError::NotFound(e.message),
        "TrailAlreadyExistsException" | "MaximumNumberOfTrailsExceededException" => {
            ApiError::Conflict(e.message)
        }
        _ if e.status.is_client_error() => ApiError::BadRequest(e.message),
        _ => ApiError::Failed(anyhow::anyhow!(
            "CloudTrail's {operation} failed: {}",
            e.message
        )),
    })
}

/// `value`, as a string, if it's one.
fn text(value: &Value) -> Option<String> {
    value.as_str().map(str::to_owned)
}

/// A time CloudTrail answers as text (`2026-11-16T05:06:07Z`), in seconds;
/// `None` if it's "" or isn't one.
fn iso_time(value: &Value) -> Option<f64> {
    let text = value.as_str().filter(|s| !s.is_empty())?;
    crate::backup::restore::parse_time(text)
        .ok()
        .map(|millis| millis as f64 / 1000.0)
}

// ─── Event history ───────────────────────────────────────────────────────────

/// Which events to look up: at most one attribute, and a time range.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct EventQuery {
    /// The attribute to look up by: `EventName`, `Username`,
    /// `ResourceName`, `ResourceType`, `EventSource`, `EventId`,
    /// `ReadOnly` or `AccessKeyId`.
    attribute: Option<String>,
    /// The value it must have, exactly.
    value: Option<String>,
    /// From when (seconds since the epoch); 90 days ago if not given.
    start: Option<i64>,
    /// Until when (seconds); now if not given.
    end: Option<i64>,
    /// The page to go on with: a `next_token` the last page answered.
    next_token: Option<String>,
    /// The most events a page has: 1 to 50 (50 if not given).
    max: Option<u32>,
}

/// A resource an event is about.
#[derive(Serialize, ToSchema)]
struct EventResource {
    /// Its type (`AWS::KMS::Key`).
    kind: Option<String>,
    /// Its ARN.
    name: Option<String>,
}

/// An event of the account's history.
#[derive(Serialize, ToSchema)]
struct EventSummary {
    id: String,
    /// When it happened, in seconds since the epoch.
    time: Option<f64>,
    /// Its operation (`Decrypt`).
    name: String,
    /// The service it's of (`kms.amazonaws.com`).
    source: String,
    /// Who made it: a user's name, a role session's, or `root`.
    username: Option<String>,
    access_key_id: Option<String>,
    read_only: bool,
    source_ip: Option<String>,
    /// Why it failed, if it did: the error's code.
    error_code: Option<String>,
    error_message: Option<String>,
    /// Whether it was made through the console.
    console: bool,
    resources: Vec<EventResource>,
    /// The whole record, as CloudTrail's (JSON).
    record: String,
}

/// A page of the account's events, newest first.
#[derive(Serialize, ToSchema)]
struct EventPage {
    events: Vec<EventSummary>,
    /// Where the next page starts, if there may be more. A page may have
    /// fewer events than asked for (none, even) and still have one: a
    /// lookup reads only so much at a time.
    next_token: Option<String>,
}

/// The account's events, as CloudTrail's LookupEvents answers them: newest
/// first, a page at a time, by at most one attribute.
#[utoipa::path(get, path = "/cloudtrail/events", params(EventQuery), responses(
    (status = 200, body = EventPage),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn lookup_events(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Query(query): Query<EventQuery>,
) -> Result<Json<EventPage>> {
    let mut params = Map::new();
    let value = query.value.as_deref().map(str::trim).unwrap_or("");
    if let Some(attribute) = query.attribute.as_deref().filter(|a| !a.is_empty())
        && !value.is_empty()
    {
        params.insert(
            "LookupAttributes".to_owned(),
            json!([{ "AttributeKey": attribute, "AttributeValue": value }]),
        );
    }
    if let Some(start) = query.start {
        params.insert("StartTime".to_owned(), json!(start));
    }
    if let Some(end) = query.end {
        params.insert("EndTime".to_owned(), json!(end));
    }
    if let Some(token) = query.next_token.filter(|t| !t.is_empty()) {
        params.insert("NextToken".to_owned(), json!(token));
    }
    if let Some(max) = query.max {
        params.insert("MaxResults".to_owned(), json!(max));
    }
    let answer = call(&app, &actor, "LookupEvents", Value::Object(params)).await?;
    let events = answer["Events"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|e| {
            let record_text = e["CloudTrailEvent"].as_str().unwrap_or("{}");
            let record: Value = serde_json::from_str(record_text).unwrap_or(Value::Null);
            EventSummary {
                id: text(&e["EventId"]).unwrap_or_default(),
                time: e["EventTime"].as_f64(),
                name: text(&e["EventName"]).unwrap_or_default(),
                source: text(&e["EventSource"]).unwrap_or_default(),
                username: text(&e["Username"]),
                access_key_id: text(&e["AccessKeyId"]),
                read_only: e["ReadOnly"].as_str() == Some("true"),
                source_ip: text(&record["sourceIPAddress"]),
                error_code: text(&record["errorCode"]),
                error_message: text(&record["errorMessage"]),
                console: record["sessionCredentialFromConsole"].as_str() == Some("true"),
                resources: e["Resources"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|r| EventResource {
                        kind: text(&r["ResourceType"]),
                        name: text(&r["ResourceName"]),
                    })
                    .collect(),
                record: record_text.to_owned(),
            }
        })
        .collect();
    Ok(Json(EventPage {
        events,
        next_token: text(&answer["NextToken"]),
    }))
}

// ─── Trails ──────────────────────────────────────────────────────────────────

/// How a trail is doing, as GetTrailStatus answers.
#[derive(Serialize, ToSchema)]
struct TrailStatus {
    logging: bool,
    /// When it last started and stopped logging (seconds).
    started: Option<f64>,
    stopped: Option<f64>,
    /// When it last delivered a log file.
    delivered: Option<f64>,
    /// When it last tried to, and whether that succeeded.
    attempted: Option<f64>,
    attempt_succeeded: bool,
    /// Why its last delivery failed, if it did.
    error: Option<String>,
}

/// A trail's settings, as DescribeTrails answers them.
#[derive(Serialize, ToSchema)]
struct TrailSettings {
    name: String,
    arn: String,
    /// The bucket its log files are delivered to.
    bucket: String,
    /// The key prefix they have there, if any.
    prefix: Option<String>,
    /// The KMS key they're encrypted with (SSE-KMS), if any.
    kms_key_id: Option<String>,
    include_global: bool,
    multi_region: bool,
    /// Whether its event selectors were set (else it delivers every
    /// management event).
    custom_selectors: bool,
}

impl TrailSettings {
    fn from_json(trail: &Value) -> TrailSettings {
        TrailSettings {
            name: text(&trail["Name"]).unwrap_or_default(),
            arn: text(&trail["TrailARN"]).unwrap_or_default(),
            bucket: text(&trail["S3BucketName"]).unwrap_or_default(),
            prefix: text(&trail["S3KeyPrefix"]),
            kms_key_id: text(&trail["KmsKeyId"]),
            include_global: trail["IncludeGlobalServiceEvents"]
                .as_bool()
                .unwrap_or(true),
            multi_region: trail["IsMultiRegionTrail"].as_bool().unwrap_or(false),
            custom_selectors: trail["HasCustomEventSelectors"].as_bool().unwrap_or(false),
        }
    }
}

/// A trail, as lists show it.
#[derive(Serialize, ToSchema)]
struct TrailSummary {
    #[serde(flatten)]
    settings: TrailSettings,
    /// How it's doing; `None` if the session may not see it
    /// (`cloudtrail:GetTrailStatus`).
    status: Option<TrailStatus>,
}

/// A trail's status, unless the session may not see it.
async fn status(app: &Arc<App>, actor: &Actor, name: &str) -> Result<Option<TrailStatus>> {
    let s = match call(app, actor, "GetTrailStatus", json!({ "Name": name })).await {
        Ok(s) => s,
        Err(ApiError::Forbidden(_)) => return Ok(None),
        Err(e) => return Err(e),
    };
    Ok(Some(TrailStatus {
        logging: s["IsLogging"].as_bool().unwrap_or(false),
        started: s["StartLoggingTime"].as_f64(),
        stopped: s["StopLoggingTime"].as_f64(),
        delivered: s["LatestDeliveryTime"].as_f64(),
        attempted: iso_time(&s["LatestDeliveryAttemptTime"]),
        attempt_succeeded: iso_time(&s["LatestDeliveryAttemptSucceeded"]).is_some(),
        error: text(&s["LatestDeliveryError"]),
    }))
}

/// The account's trails (`cloudtrail:DescribeTrails`), with how each is
/// doing (if the session may see it).
#[utoipa::path(get, path = "/trails", responses(
    (status = 200, body = Vec<TrailSummary>),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn list_trails(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
) -> Result<Json<Vec<TrailSummary>>> {
    let answer = call(&app, &actor, "DescribeTrails", json!({})).await?;
    let mut trails = Vec::new();
    for trail in answer["trailList"].as_array().into_iter().flatten() {
        let settings = TrailSettings::from_json(trail);
        let status = status(&app, &actor, &settings.name).await?;
        trails.push(TrailSummary { settings, status });
    }
    Ok(Json(trails))
}

/// What a trail is to be, made or changed.
#[derive(Deserialize, ToSchema)]
struct TrailForm {
    bucket: String,
    /// The key prefix of its files in the bucket; none if empty.
    #[serde(default)]
    prefix: String,
    /// The KMS key to encrypt its files with (an ID, ARN or alias); none
    /// if empty: the bucket's default encryption.
    #[serde(default)]
    kms_key_id: String,
    #[serde(default = "yes")]
    include_global: bool,
    #[serde(default = "yes")]
    multi_region: bool,
}

fn yes() -> bool {
    true
}

impl TrailForm {
    /// As CreateTrail's and UpdateTrail's parameters, with `name`.
    fn params(&self, name: &str) -> Value {
        json!({
            "Name": name,
            "S3BucketName": self.bucket.trim(),
            "S3KeyPrefix": self.prefix.trim(),
            "KmsKeyId": self.kms_key_id.trim(),
            "IncludeGlobalServiceEvents": self.include_global,
            "IsMultiRegionTrail": self.multi_region,
        })
    }
}

/// A new trail.
#[derive(Deserialize, ToSchema)]
struct NewTrail {
    name: String,
    #[serde(flatten)]
    form: TrailForm,
    /// Whether it starts logging once it's made (as the AWS console's do).
    #[serde(default = "yes")]
    start_logging: bool,
    #[serde(default)]
    tags: Vec<Tag>,
}

/// Makes a trail, as CloudTrail's CreateTrail does, and starts it logging
/// if asked to (StartLogging).
#[utoipa::path(post, path = "/trails", request_body = NewTrail, responses(
    (status = 201, description = "Made"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_trail(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Json(body): Json<NewTrail>,
) -> Result<StatusCode> {
    let name = body.name.trim();
    let mut params = body.form.params(name);
    if body.form.prefix.trim().is_empty() {
        params.as_object_mut().unwrap().remove("S3KeyPrefix");
    }
    if body.form.kms_key_id.trim().is_empty() {
        params.as_object_mut().unwrap().remove("KmsKeyId");
    }
    if !body.tags.is_empty() {
        params["TagsList"] = tags_list(&body.tags);
    }
    call(&app, &actor, "CreateTrail", params).await?;
    if body.start_logging {
        call(&app, &actor, "StartLogging", json!({ "Name": name })).await?;
    }
    Ok(StatusCode::CREATED)
}

/// A trail: its settings, status, event selectors and tags.
#[derive(Serialize, ToSchema)]
struct TrailDetail {
    #[serde(flatten)]
    settings: TrailSettings,
    status: Option<TrailStatus>,
    /// Its event selectors, as GetEventSelectors answers them
    /// (`EventSelectors` or `AdvancedEventSelectors`; JSON); `None` if the
    /// session may not see them.
    selectors: Option<String>,
    /// Its tags; `None` if the session may not see them.
    tags: Option<Vec<Tag>>,
}

#[utoipa::path(get, path = "/trails/{name}", params(("name" = String, Path)), responses(
    (status = 200, body = TrailDetail),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn get_trail(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
) -> Result<Json<TrailDetail>> {
    let trail = call(&app, &actor, "GetTrail", json!({ "Name": name })).await?;
    let settings = TrailSettings::from_json(&trail["Trail"]);
    let status = status(&app, &actor, &name).await?;
    let selectors = match call(
        &app,
        &actor,
        "GetEventSelectors",
        json!({ "TrailName": name }),
    )
    .await
    {
        Ok(Value::Object(mut answer)) => {
            answer.remove("TrailARN");
            Some(serde_json::to_string_pretty(&answer).unwrap_or_default())
        }
        Ok(_) | Err(ApiError::Forbidden(_)) => None,
        Err(e) => return Err(e),
    };
    let tags = match call(
        &app,
        &actor,
        "ListTags",
        json!({ "ResourceIdList": [settings.arn] }),
    )
    .await
    {
        Ok(answer) => Some(
            answer["ResourceTagList"][0]["TagsList"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|t| Tag {
                    key: text(&t["Key"]).unwrap_or_default(),
                    value: text(&t["Value"]).unwrap_or_default(),
                })
                .collect(),
        ),
        Err(ApiError::Forbidden(_)) => None,
        Err(e) => return Err(e),
    };
    Ok(Json(TrailDetail {
        settings,
        status,
        selectors,
        tags,
    }))
}

/// Changes a trail's settings, as UpdateTrail does: an empty prefix or key
/// removes it.
#[utoipa::path(put, path = "/trails/{name}", params(("name" = String, Path)), request_body = TrailForm, responses(
    (status = 204, description = "Changed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn update_trail(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<TrailForm>,
) -> Result<StatusCode> {
    call(&app, &actor, "UpdateTrail", body.params(&name)).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes a trail, as DeleteTrail does: the files it delivered stay.
#[utoipa::path(delete, path = "/trails/{name}", params(("name" = String, Path)), responses(
    (status = 204, description = "Deleted"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_trail(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
) -> Result<StatusCode> {
    call(&app, &actor, "DeleteTrail", json!({ "Name": name })).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct Logging {
    logging: bool,
}

/// Starts or stops a trail's logging (StartLogging, StopLogging).
#[utoipa::path(put, path = "/trails/{name}/logging", params(("name" = String, Path)), request_body = Logging, responses(
    (status = 204, description = "Started or stopped"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn set_trail_logging(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<Logging>,
) -> Result<StatusCode> {
    let operation = match body.logging {
        true => "StartLogging",
        false => "StopLogging",
    };
    call(&app, &actor, operation, json!({ "Name": name })).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct Selectors {
    /// `{"EventSelectors": [...]}` or `{"AdvancedEventSelectors": [...]}`,
    /// as PutEventSelectors takes them (JSON).
    document: String,
}

/// Sets a trail's event selectors, as PutEventSelectors does.
#[utoipa::path(put, path = "/trails/{name}/selectors", params(("name" = String, Path)), request_body = Selectors, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn set_trail_selectors(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<Selectors>,
) -> Result<StatusCode> {
    let Ok(Value::Object(mut params)) = serde_json::from_str::<Value>(&body.document) else {
        return Err(ApiError::BadRequest(
            "the event selectors aren't a JSON object".to_owned(),
        ));
    };
    params.retain(|k, _| k == "EventSelectors" || k == "AdvancedEventSelectors");
    params.insert("TrailName".to_owned(), json!(name));
    call(&app, &actor, "PutEventSelectors", Value::Object(params)).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `tags`, as CloudTrail's `TagsList`.
fn tags_list(tags: &[Tag]) -> Value {
    tags.iter()
        .map(|t| json!({ "Key": t.key, "Value": t.value }))
        .collect()
}

/// Sets a trail's tags to these: those it has that aren't are removed
/// (AddTags, RemoveTags).
#[utoipa::path(put, path = "/trails/{name}/tags", params(("name" = String, Path)), request_body = Vec<Tag>, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn set_trail_tags(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(tags): Json<Vec<Tag>>,
) -> Result<StatusCode> {
    let arn = crate::cloudtrail::trails::arn(actor.account(), &name);
    let had = call(&app, &actor, "ListTags", json!({ "ResourceIdList": [arn] })).await?;
    let gone: Vec<Value> = had["ResourceTagList"][0]["TagsList"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|t| !tags.iter().any(|n| t["Key"].as_str() == Some(&n.key)))
        .map(|t| json!({ "Key": t["Key"] }))
        .collect();
    if !gone.is_empty() {
        call(
            &app,
            &actor,
            "RemoveTags",
            json!({ "ResourceId": arn, "TagsList": gone }),
        )
        .await?;
    }
    if !tags.is_empty() {
        call(
            &app,
            &actor,
            "AddTags",
            json!({ "ResourceId": arn, "TagsList": tags_list(&tags) }),
        )
        .await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod e2e {
    use std::sync::Arc;
    use std::time::Duration;

    use axum::http::StatusCode;
    use serde_json::{Value, json};

    use super::super::e2e::{console_of, signed_in};
    use crate::audit::{self, log::Rotation, ship};

    /// A trail made, changed, stopped and deleted on the console, as
    /// CloudTrail checks it; and the console's calls in the event history,
    /// as the user's, made through the console.
    #[tokio::test]
    async fn manages_trails_and_shows_events() {
        let Some(app) = crate::e2e::kms_node().await else {
            return;
        };
        let mut app = Arc::into_inner(app).expect("a new node isn't shared");
        let dir = std::env::temp_dir().join(format!("cairn-audit-{}", uuid::Uuid::new_v4()));
        let rotation = Rotation {
            period: Duration::from_millis(1),
            bytes: u64::MAX,
        };
        app.audit = audit::Audit::start_with(dir.clone(), rotation).unwrap();
        let app = Arc::new(app);
        let console = console_of(&app);
        let mut admin = signed_in(&console, "admin", true).await;
        let mut nobody = signed_in(&console, "nobody", false).await;
        let client = app.pool.get().await.unwrap();
        let account = crate::users::account(&client).await.unwrap();
        let region = crate::s3::buckets::head::REGION;

        let logs = "console-trail-logs";
        assert_eq!(
            admin
                .send("POST", "/api/buckets", Some(json!({"name": logs})))
                .await
                .0,
            StatusCode::CREATED
        );
        let trail = json!({"name": "main", "bucket": logs, "prefix": "ct"});
        // The bucket's policy doesn't let CloudTrail write to it yet.
        let (status, body) = admin.send("POST", "/api/trails", Some(trail.clone())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body["error"].as_str().unwrap().contains("bucket policy"),
            "{body}"
        );
        let policy = json!({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
             "Action": "s3:GetBucketAcl", "Resource": format!("arn:aws:s3:::{logs}")},
            {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
             "Action": "s3:PutObject", "Resource": format!("arn:aws:s3:::{logs}/ct/AWSLogs/{account}/*"),
             "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}},
        ]});
        assert_eq!(
            admin
                .send(
                    "PUT",
                    &format!("/api/buckets/{logs}/policy"),
                    Some(json!({"document": policy.to_string()}))
                )
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        let (status, body) = admin.send("POST", "/api/trails", Some(trail.clone())).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(
            admin.send("POST", "/api/trails", Some(trail)).await.0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            admin
                .send(
                    "POST",
                    "/api/trails",
                    Some(json!({"name": "-bad", "bucket": logs}))
                )
                .await
                .0,
            StatusCode::BAD_REQUEST
        );

        // Listed, logging (it was started), with its settings.
        let (status, listed) = admin.send("GET", "/api/trails", None).await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(listed.as_array().unwrap().len(), 1);
        assert_eq!(listed[0]["name"], "main");
        assert_eq!(
            listed[0]["arn"],
            format!("arn:aws:cloudtrail:{region}:{account}:trail/main")
        );
        assert_eq!(listed[0]["prefix"], "ct");
        assert_eq!(listed[0]["status"]["logging"], true);
        assert_eq!(
            nobody.send("GET", "/api/trails", None).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            nobody.send("DELETE", "/api/trails/main", None).await.0,
            StatusCode::FORBIDDEN
        );

        // Its selectors, tags, settings and logging.
        let selectors = json!({"EventSelectors": [{"ReadWriteType": "WriteOnly",
            "IncludeManagementEvents": true, "ExcludeManagementEventSources": ["kms.amazonaws.com"]}]});
        let path = "/api/trails/main/selectors";
        assert_eq!(
            admin
                .send(
                    "PUT",
                    path,
                    Some(json!({"document": selectors.to_string()}))
                )
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        let (status, body) = admin
            .send(
                "PUT",
                path,
                Some(json!({"document": r#"{"EventSelectors": "x"}"#})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let tags = json!([{"key": "team", "value": "sec"}, {"key": "env", "value": "prod"}]);
        assert_eq!(
            admin
                .send("PUT", "/api/trails/main/tags", Some(tags))
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        let tags = json!([{"key": "team", "value": "audit"}]);
        assert_eq!(
            admin
                .send("PUT", "/api/trails/main/tags", Some(tags))
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        let form =
            json!({"bucket": logs, "prefix": "ct", "include_global": true, "multi_region": false});
        assert_eq!(
            admin.send("PUT", "/api/trails/main", Some(form)).await.0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            admin
                .send(
                    "PUT",
                    "/api/trails/main/logging",
                    Some(json!({"logging": false}))
                )
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        let (status, detail) = admin.send("GET", "/api/trails/main", None).await;
        assert_eq!(status, StatusCode::OK, "{detail}");
        assert_eq!(detail["multi_region"], false);
        assert_eq!(detail["custom_selectors"], true);
        assert_eq!(detail["status"]["logging"], false);
        assert!(detail["status"]["stopped"].as_f64().is_some(), "{detail}");
        assert_eq!(detail["tags"], json!([{"key": "team", "value": "audit"}]));
        let stored: Value = serde_json::from_str(detail["selectors"].as_str().unwrap()).unwrap();
        assert_eq!(
            stored["EventSelectors"][0]["ExcludeManagementEventSources"],
            json!(["kms.amazonaws.com"])
        );
        assert_eq!(
            admin.send("GET", "/api/trails/none", None).await.0,
            StatusCode::NOT_FOUND
        );

        // The console's calls are in the event history, as the admin's,
        // through the console, once they're shipped.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let created = loop {
            assert!(std::time::Instant::now() < deadline, "never found");
            tokio::time::sleep(Duration::from_millis(50)).await;
            ship::ship_all(&app, &dir).await.unwrap();
            let (status, page) = admin
                .send(
                    "GET",
                    "/api/cloudtrail/events?attribute=EventName&value=CreateTrail",
                    None,
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{page}");
            let events = page["events"].as_array().unwrap().clone();
            if events.len() == 4 {
                break events;
            }
        };
        // Refused ones too: for the bucket's policy, a name that was taken,
        // and one that isn't a name.
        let mut failed: Vec<_> = created
            .iter()
            .filter_map(|e| e["error_code"].as_str())
            .collect();
        failed.sort();
        assert_eq!(
            failed,
            [
                "InsufficientS3BucketPolicyException",
                "InvalidTrailNameException",
                "TrailAlreadyExistsException"
            ],
            "{created:?}"
        );
        let made = created.iter().find(|e| e["error_code"].is_null()).unwrap();
        assert_eq!(made["username"], "admin");
        assert_eq!(made["source"], "cloudtrail.amazonaws.com");
        assert_eq!(made["console"], true);
        assert_eq!(made["read_only"], false);
        assert_eq!(made["access_key_id"], Value::Null);
        let record: Value = serde_json::from_str(made["record"].as_str().unwrap()).unwrap();
        assert_eq!(record["sessionCredentialFromConsole"], "true");
        assert_eq!(record["requestParameters"]["name"], "main");
        assert_eq!(
            made["resources"][0]["name"],
            format!("arn:aws:cloudtrail:{region}:{account}:trail/main")
        );
        // A page at a time.
        let (_, page) = admin
            .send(
                "GET",
                "/api/cloudtrail/events?attribute=EventName&value=CreateTrail&max=1",
                None,
            )
            .await;
        assert_eq!(page["events"].as_array().unwrap().len(), 1);
        let token = page["next_token"].as_str().expect("more").to_owned();
        let (status, next) = admin
            .send(
                "GET",
                &format!(
                    "/api/cloudtrail/events?attribute=EventName&value=CreateTrail&max=1&next_token={token}"
                ),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{next}");
        assert_ne!(next["events"][0]["id"], page["events"][0]["id"]);
        assert_eq!(
            admin
                .send(
                    "GET",
                    "/api/cloudtrail/events?attribute=Bogus&value=x",
                    None
                )
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            nobody.send("GET", "/api/cloudtrail/events", None).await.0,
            StatusCode::FORBIDDEN
        );

        assert_eq!(
            admin.send("DELETE", "/api/trails/main", None).await.0,
            StatusCode::NO_CONTENT
        );
        let (_, listed) = admin.send("GET", "/api/trails", None).await;
        assert_eq!(listed, json!([]));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
