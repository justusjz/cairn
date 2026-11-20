//! The console's API for S3 Tables (see `tables`): the account's table
//! buckets, their namespaces and tables, and their policies. Each call is
//! S3 Tables' own operation, run as the session's identity
//! (`tables::Ctx::dispatch`), so it's checked and validated exactly as the
//! `s3tables` API checks it; reads take what that answers apart.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use hyper::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::actor::Actor;
use super::manage::{AppState, Result};
use super::web::{ApiError, ErrorBody};
use crate::{App, tables};

pub(super) fn router() -> OpenApiRouter<Arc<App>> {
    OpenApiRouter::new()
        .routes(routes!(list_table_buckets, create_table_bucket))
        .routes(routes!(get_table_bucket, delete_table_bucket))
        .routes(routes!(set_table_bucket_policy))
        .routes(routes!(create_table_namespace))
        .routes(routes!(delete_table_namespace))
        .routes(routes!(create_iceberg_table))
        .routes(routes!(delete_iceberg_table))
        .routes(routes!(set_table_bucket_encryption))
        .routes(routes!(set_table_bucket_storage_class))
        .routes(routes!(set_table_bucket_maintenance))
        .routes(routes!(get_table_maintenance))
        .routes(routes!(set_table_snapshot_management))
        .routes(routes!(set_table_compaction))
}

/// Runs S3 Tables' operation `method` `path` (its ARNs as they are: each
/// is encoded here), as `actor`, with `query` and `body`: its output
/// (`null` for none).
async fn call(
    app: &Arc<App>,
    actor: &Actor,
    method: Method,
    segments: &[&str],
    query: &str,
    body: Value,
) -> Result<Value> {
    let mut access = actor.access_for(app).await?;
    let mut ctx = tables::Ctx {
        app,
        client: app.pool.get().await?,
        principal: actor.principal(),
        access: &mut access,
        endpoint: None,
    };
    let path: String = segments.iter().map(|s| format!("/{}", encode(s))).collect();
    let body = match body {
        Value::Null => Vec::new(),
        body => body.to_string().into_bytes(),
    };
    match ctx.dispatch(&method, &path, query, &body).await {
        Ok(tables::Answer::Json(value)) => Ok(value),
        Ok(tables::Answer::NoContent) => Ok(Value::Null),
        Ok(tables::Answer::Raw(_, body)) => Ok(body.unwrap_or(Value::Null)),
        Err(e) => Err(match e.status {
            StatusCode::NOT_FOUND => ApiError::NotFound(e.message),
            StatusCode::FORBIDDEN => ApiError::Forbidden(e.message),
            StatusCode::CONFLICT => ApiError::Conflict(e.message),
            s if s.is_client_error() => ApiError::BadRequest(e.message),
            StatusCode::NOT_IMPLEMENTED => ApiError::BadRequest(e.message),
            _ => ApiError::Failed(anyhow::anyhow!(
                "S3 Tables' {method} {path} failed: {}",
                e.message
            )),
        }),
    }
}

fn encode(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

fn arn(actor: &Actor, name: &str) -> String {
    tables::names::bucket_arn(actor.account(), name)
}

fn text(value: &Value, name: &str) -> String {
    value[name].as_str().unwrap_or("").to_owned()
}

/// What may be read, or nothing if it may not be (`Forbidden`).
fn allowed(result: Result<Value>) -> Result<Option<Value>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(ApiError::Forbidden(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// A table bucket, as lists show it.
#[derive(Serialize, ToSchema)]
struct TableBucketSummary {
    name: String,
    arn: String,
    created_at: String,
}

/// The account's table buckets (`s3tables:ListTableBuckets`).
#[utoipa::path(get, path = "/table-buckets", responses(
    (status = 200, body = Vec<TableBucketSummary>),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn list_table_buckets(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
) -> Result<Json<Vec<TableBucketSummary>>> {
    let mut buckets = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let query = token
            .as_deref()
            .map(|t| format!("continuationToken={}", encode(t)))
            .unwrap_or_default();
        let page = call(&app, &actor, Method::GET, &["buckets"], &query, Value::Null).await?;
        for b in page["tableBuckets"].as_array().into_iter().flatten() {
            buckets.push(TableBucketSummary {
                name: text(b, "name"),
                arn: text(b, "arn"),
                created_at: text(b, "createdAt"),
            });
        }
        token = page["continuationToken"].as_str().map(str::to_owned);
        if token.is_none() {
            break;
        }
    }
    Ok(Json(buckets))
}

#[derive(Deserialize, ToSchema)]
struct NewTableBucket {
    name: String,
}

/// Makes a table bucket, as CreateTableBucket does.
#[utoipa::path(post, path = "/table-buckets", request_body = NewTableBucket, responses(
    (status = 201, description = "Made"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_table_bucket(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Json(body): Json<NewTableBucket>,
) -> Result<StatusCode> {
    call(
        &app,
        &actor,
        Method::PUT,
        &["buckets"],
        "",
        json!({ "name": body.name }),
    )
    .await?;
    Ok(StatusCode::CREATED)
}

/// A namespace of a table bucket.
#[derive(Serialize, ToSchema)]
struct NamespaceSummary {
    name: String,
    created_at: String,
}

/// A table of a table bucket.
#[derive(Serialize, ToSchema)]
struct TableSummary {
    namespace: String,
    name: String,
    arn: String,
    created_at: String,
    modified_at: String,
    /// Its current metadata file, if it has one (and it may be seen).
    metadata_location: Option<String>,
    /// Where its files are (and it may be seen).
    warehouse_location: Option<String>,
}

/// A table bucket, its configuration, and what's in it.
#[derive(Serialize, ToSchema)]
struct TableBucketDetail {
    name: String,
    arn: String,
    created_at: String,
    /// `AES256` or `aws:kms`, and its key, if it may be seen.
    encryption: Option<String>,
    storage_class: Option<String>,
    /// Its policy (JSON), if it has one (and it may be seen).
    policy: Option<String>,
    /// Its tables' unreferenced file removal, if it may be seen.
    unreferenced_file_removal: Option<UnreferencedFileRemoval>,
    namespaces: Vec<NamespaceSummary>,
    tables: Vec<TableSummary>,
}

#[utoipa::path(get, path = "/table-buckets/{name}", params(("name" = String, Path)), responses(
    (status = 200, body = TableBucketDetail),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn get_table_bucket(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
) -> Result<Json<TableBucketDetail>> {
    let arn = arn(&actor, &name);
    let bucket = call(
        &app,
        &actor,
        Method::GET,
        &["buckets", &arn],
        "",
        Value::Null,
    )
    .await?;
    let get = |what: &'static str| {
        let (app, actor, arn) = (&app, &actor, arn.clone());
        async move {
            allowed(
                call(
                    app,
                    actor,
                    Method::GET,
                    &["buckets", &arn, what],
                    "",
                    Value::Null,
                )
                .await,
            )
        }
    };
    let encryption = get("encryption").await?.map(|e| {
        let config = &e["encryptionConfiguration"];
        match config["kmsKeyArn"].as_str() {
            Some(key) => format!("{} ({key})", text(config, "sseAlgorithm")),
            None => text(config, "sseAlgorithm"),
        }
    });
    let storage_class = get("storage-class")
        .await?
        .map(|c| text(&c["storageClassConfiguration"], "storageClass"));
    let unreferenced_file_removal = get("maintenance").await?.map(|m| {
        let value = &m["configuration"][UNREFERENCED];
        let settings = &value["settings"][UNREFERENCED];
        UnreferencedFileRemoval {
            enabled: value["status"] != "disabled",
            unreferenced_days: settings["unreferencedDays"].as_i64().unwrap_or(0),
            non_current_days: settings["nonCurrentDays"].as_i64().unwrap_or(0),
        }
    });
    let policy = match call(
        &app,
        &actor,
        Method::GET,
        &["buckets", &arn, "policy"],
        "",
        Value::Null,
    )
    .await
    {
        Ok(p) => Some(text(&p, "resourcePolicy")),
        Err(ApiError::Forbidden(_) | ApiError::NotFound(_)) => None,
        Err(e) => return Err(e),
    };
    let mut namespaces = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let query = token
            .as_deref()
            .map(|t| format!("continuationToken={}", encode(t)))
            .unwrap_or_default();
        let Some(page) = allowed(
            call(
                &app,
                &actor,
                Method::GET,
                &["namespaces", &arn],
                &query,
                Value::Null,
            )
            .await,
        )?
        else {
            break;
        };
        for n in page["namespaces"].as_array().into_iter().flatten() {
            namespaces.push(NamespaceSummary {
                name: n["namespace"][0].as_str().unwrap_or("").to_owned(),
                created_at: text(n, "createdAt"),
            });
        }
        token = page["continuationToken"].as_str().map(str::to_owned);
        if token.is_none() {
            break;
        }
    }
    let mut tables = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let query = token
            .as_deref()
            .map(|t| format!("continuationToken={}", encode(t)))
            .unwrap_or_default();
        let Some(page) = allowed(
            call(
                &app,
                &actor,
                Method::GET,
                &["tables", &arn],
                &query,
                Value::Null,
            )
            .await,
        )?
        else {
            break;
        };
        for t in page["tables"].as_array().into_iter().flatten() {
            let namespace = t["namespace"][0].as_str().unwrap_or("").to_owned();
            let table = text(t, "name");
            let location = allowed(
                call(
                    &app,
                    &actor,
                    Method::GET,
                    &["tables", &arn, &namespace, &table, "metadata-location"],
                    "",
                    Value::Null,
                )
                .await,
            )?;
            tables.push(TableSummary {
                arn: text(t, "tableARN"),
                created_at: text(t, "createdAt"),
                modified_at: text(t, "modifiedAt"),
                metadata_location: location
                    .as_ref()
                    .and_then(|l| l["metadataLocation"].as_str().map(str::to_owned)),
                warehouse_location: location.as_ref().map(|l| text(l, "warehouseLocation")),
                namespace,
                name: table,
            });
        }
        token = page["continuationToken"].as_str().map(str::to_owned);
        if token.is_none() {
            break;
        }
    }
    Ok(Json(TableBucketDetail {
        name: text(&bucket, "name"),
        arn,
        created_at: text(&bucket, "createdAt"),
        encryption,
        storage_class,
        policy,
        unreferenced_file_removal,
        namespaces,
        tables,
    }))
}

/// Deletes a table bucket, as DeleteTableBucket does: an empty one only.
#[utoipa::path(delete, path = "/table-buckets/{name}", params(("name" = String, Path)), responses(
    (status = 204, description = "Deleted"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_table_bucket(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
) -> Result<StatusCode> {
    let arn = arn(&actor, &name);
    call(
        &app,
        &actor,
        Method::DELETE,
        &["buckets", &arn],
        "",
        Value::Null,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct PolicyDocument {
    /// The policy (JSON); empty to delete it.
    document: String,
}

/// Sets a table bucket's policy (PutTableBucketPolicy), or deletes it
/// (DeleteTableBucketPolicy), if it's empty.
#[utoipa::path(put, path = "/table-buckets/{name}/policy", params(("name" = String, Path)),
    request_body = PolicyDocument, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn set_table_bucket_policy(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<PolicyDocument>,
) -> Result<StatusCode> {
    let arn = arn(&actor, &name);
    let document = body.document.trim();
    match document.is_empty() {
        true => {
            call(
                &app,
                &actor,
                Method::DELETE,
                &["buckets", &arn, "policy"],
                "",
                Value::Null,
            )
            .await?
        }
        false => {
            call(
                &app,
                &actor,
                Method::PUT,
                &["buckets", &arn, "policy"],
                "",
                json!({ "resourcePolicy": document }),
            )
            .await?
        }
    };
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct NewNamespace {
    name: String,
}

/// Makes a namespace in a table bucket, as CreateNamespace does.
#[utoipa::path(post, path = "/table-buckets/{name}/namespaces", params(("name" = String, Path)),
    request_body = NewNamespace, responses(
    (status = 201, description = "Made"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_table_namespace(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<NewNamespace>,
) -> Result<StatusCode> {
    let arn = arn(&actor, &name);
    call(
        &app,
        &actor,
        Method::PUT,
        &["namespaces", &arn],
        "",
        json!({ "namespace": [body.name] }),
    )
    .await?;
    Ok(StatusCode::CREATED)
}

/// Deletes an empty namespace, as DeleteNamespace does.
#[utoipa::path(delete, path = "/table-buckets/{name}/namespaces/{namespace}",
    params(("name" = String, Path), ("namespace" = String, Path)), responses(
    (status = 204, description = "Deleted"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_table_namespace(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((name, namespace)): Path<(String, String)>,
) -> Result<StatusCode> {
    let arn = arn(&actor, &name);
    call(
        &app,
        &actor,
        Method::DELETE,
        &["namespaces", &arn, &namespace],
        "",
        Value::Null,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct NewTable {
    namespace: String,
    name: String,
}

/// Makes an (empty) Iceberg table, as CreateTable does: without metadata,
/// which its first writer makes.
#[utoipa::path(post, path = "/table-buckets/{name}/tables", params(("name" = String, Path)),
    request_body = NewTable, responses(
    (status = 201, description = "Made"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_iceberg_table(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<NewTable>,
) -> Result<StatusCode> {
    let arn = arn(&actor, &name);
    call(
        &app,
        &actor,
        Method::PUT,
        &["tables", &arn, &body.namespace],
        "",
        json!({ "name": body.name, "format": "ICEBERG" }),
    )
    .await?;
    Ok(StatusCode::CREATED)
}

/// Deletes a table, and its files, as DeleteTable does.
#[utoipa::path(delete, path = "/table-buckets/{name}/tables/{namespace}/{table}",
    params(("name" = String, Path), ("namespace" = String, Path), ("table" = String, Path)), responses(
    (status = 204, description = "Deleted"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_iceberg_table(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((name, namespace, table)): Path<(String, String, String)>,
) -> Result<StatusCode> {
    let arn = arn(&actor, &name);
    call(
        &app,
        &actor,
        Method::DELETE,
        &["tables", &arn, &namespace, &table],
        "",
        Value::Null,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Maintenance and settings ────────────────────────────────────────────────

const UNREFERENCED: &str = tables::maintenance::UNREFERENCED;
const SNAPSHOTS: &str = tables::maintenance::SNAPSHOTS;
const COMPACTION: &str = tables::compaction::COMPACTION;

fn status(enabled: bool) -> &'static str {
    match enabled {
        true => "enabled",
        false => "disabled",
    }
}

#[derive(Deserialize, ToSchema)]
struct TableBucketEncryption {
    /// `AES256` (SSE-S3) or `aws:kms` (SSE-KMS).
    algorithm: String,
    /// The key, for `aws:kms`.
    #[serde(default)]
    kms_key_arn: String,
}

/// Sets what a table bucket's new tables are encrypted with, as
/// PutTableBucketEncryption does.
#[utoipa::path(put, path = "/table-buckets/{name}/encryption", params(("name" = String, Path)),
    request_body = TableBucketEncryption, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn set_table_bucket_encryption(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<TableBucketEncryption>,
) -> Result<StatusCode> {
    let arn = arn(&actor, &name);
    let mut configuration = json!({ "sseAlgorithm": body.algorithm });
    if !body.kms_key_arn.is_empty() {
        configuration["kmsKeyArn"] = json!(body.kms_key_arn);
    }
    call(
        &app,
        &actor,
        Method::PUT,
        &["buckets", &arn, "encryption"],
        "",
        json!({ "encryptionConfiguration": configuration }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct TableBucketStorageClass {
    /// `STANDARD` or `INTELLIGENT_TIERING`.
    storage_class: String,
}

/// Sets a table bucket's new tables' storage class, as
/// PutTableBucketStorageClass does.
#[utoipa::path(put, path = "/table-buckets/{name}/storage-class", params(("name" = String, Path)),
    request_body = TableBucketStorageClass, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn set_table_bucket_storage_class(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<TableBucketStorageClass>,
) -> Result<StatusCode> {
    let arn = arn(&actor, &name);
    call(
        &app,
        &actor,
        Method::PUT,
        &["buckets", &arn, "storage-class"],
        "",
        json!({ "storageClassConfiguration": { "storageClass": body.storage_class } }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// A table bucket's unreferenced file removal: its tables' files that
/// nothing references are noncurrent after `unreferenced_days`, and
/// deleted `non_current_days` after that.
#[derive(Serialize, Deserialize, ToSchema)]
struct UnreferencedFileRemoval {
    enabled: bool,
    unreferenced_days: i64,
    non_current_days: i64,
}

/// Sets a table bucket's unreferenced file removal, as
/// PutTableBucketMaintenanceConfiguration does.
#[utoipa::path(put, path = "/table-buckets/{name}/maintenance", params(("name" = String, Path)),
    request_body = UnreferencedFileRemoval, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn set_table_bucket_maintenance(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<UnreferencedFileRemoval>,
) -> Result<StatusCode> {
    let arn = arn(&actor, &name);
    call(
        &app,
        &actor,
        Method::PUT,
        &["buckets", &arn, "maintenance", UNREFERENCED],
        "",
        json!({ "value": {
            "status": status(body.enabled),
            "settings": { UNREFERENCED: {
                "unreferencedDays": body.unreferenced_days,
                "nonCurrentDays": body.non_current_days,
            } },
        } }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// A table's snapshot management: its snapshots beyond the newest
/// `min_snapshots_to_keep`, and older than `max_snapshot_age_hours`, expire.
#[derive(Serialize, Deserialize, ToSchema)]
struct TableSnapshotManagement {
    enabled: bool,
    min_snapshots_to_keep: i64,
    max_snapshot_age_hours: i64,
}

/// A table's compaction: its small files rewritten into files of the
/// target size, their rows ordered as the strategy says.
#[derive(Serialize, Deserialize, ToSchema)]
struct TableCompaction {
    enabled: bool,
    /// 64 to 512.
    target_file_size_mb: i64,
    /// `auto`, `binpack`, `sort` or `z-order`.
    strategy: String,
}

/// How a maintenance job last went.
#[derive(Serialize, ToSchema)]
struct TableMaintenanceJob {
    /// `icebergCompaction`, `icebergSnapshotManagement` or
    /// `icebergUnreferencedFileRemoval`.
    kind: String,
    /// `Successful`, `Failed`, `Not_Yet_Run` or `Disabled`.
    status: String,
    /// ISO 8601.
    last_run: Option<String>,
    failure: Option<String>,
}

/// A table's maintenance, and how its jobs last went (each if it may be
/// seen).
#[derive(Serialize, ToSchema)]
struct TableMaintenance {
    snapshot_management: Option<TableSnapshotManagement>,
    compaction: Option<TableCompaction>,
    jobs: Option<Vec<TableMaintenanceJob>>,
}

/// A table's maintenance configuration (GetTableMaintenanceConfiguration),
/// and its jobs' status (GetTableMaintenanceJobStatus).
#[utoipa::path(get, path = "/table-buckets/{name}/tables/{namespace}/{table}/maintenance",
    params(("name" = String, Path), ("namespace" = String, Path), ("table" = String, Path)), responses(
    (status = 200, body = TableMaintenance),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn get_table_maintenance(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((name, namespace, table)): Path<(String, String, String)>,
) -> Result<Json<TableMaintenance>> {
    let arn = arn(&actor, &name);
    let configuration = allowed(
        call(
            &app,
            &actor,
            Method::GET,
            &["tables", &arn, &namespace, &table, "maintenance"],
            "",
            Value::Null,
        )
        .await,
    )?;
    let of = |kind: &str| {
        configuration.as_ref().map(|c| {
            let value = &c["configuration"][kind];
            (
                value["status"] != "disabled",
                value["settings"][kind].clone(),
            )
        })
    };
    let snapshot_management = of(SNAPSHOTS).map(|(enabled, s)| TableSnapshotManagement {
        enabled,
        min_snapshots_to_keep: s["minSnapshotsToKeep"].as_i64().unwrap_or(0),
        max_snapshot_age_hours: s["maxSnapshotAgeHours"].as_i64().unwrap_or(0),
    });
    let compaction = of(COMPACTION).map(|(enabled, s)| TableCompaction {
        enabled,
        target_file_size_mb: s["targetFileSizeMB"].as_i64().unwrap_or(0),
        strategy: text(&s, "strategy"),
    });
    let jobs = allowed(
        call(
            &app,
            &actor,
            Method::GET,
            &["tables", &arn, &namespace, &table, "maintenance-job-status"],
            "",
            Value::Null,
        )
        .await,
    )?
    .map(|s| {
        let mut jobs: Vec<TableMaintenanceJob> = s["status"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(kind, job)| TableMaintenanceJob {
                kind: kind.clone(),
                status: text(job, "status"),
                last_run: job["lastRunTimestamp"].as_str().map(str::to_owned),
                failure: job["failureMessage"].as_str().map(str::to_owned),
            })
            .collect();
        jobs.sort_by(|a, b| a.kind.cmp(&b.kind));
        jobs
    });
    Ok(Json(TableMaintenance {
        snapshot_management,
        compaction,
        jobs,
    }))
}

/// Sets a table's snapshot management, as PutTableMaintenanceConfiguration
/// does.
#[utoipa::path(put, path = "/table-buckets/{name}/tables/{namespace}/{table}/maintenance/snapshots",
    params(("name" = String, Path), ("namespace" = String, Path), ("table" = String, Path)),
    request_body = TableSnapshotManagement, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn set_table_snapshot_management(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((name, namespace, table)): Path<(String, String, String)>,
    Json(body): Json<TableSnapshotManagement>,
) -> Result<StatusCode> {
    let arn = arn(&actor, &name);
    call(
        &app,
        &actor,
        Method::PUT,
        &["tables", &arn, &namespace, &table, "maintenance", SNAPSHOTS],
        "",
        json!({ "value": {
            "status": status(body.enabled),
            "settings": { SNAPSHOTS: {
                "minSnapshotsToKeep": body.min_snapshots_to_keep,
                "maxSnapshotAgeHours": body.max_snapshot_age_hours,
            } },
        } }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Sets a table's compaction, as PutTableMaintenanceConfiguration does.
#[utoipa::path(put, path = "/table-buckets/{name}/tables/{namespace}/{table}/maintenance/compaction",
    params(("name" = String, Path), ("namespace" = String, Path), ("table" = String, Path)),
    request_body = TableCompaction, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn set_table_compaction(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((name, namespace, table)): Path<(String, String, String)>,
    Json(body): Json<TableCompaction>,
) -> Result<StatusCode> {
    let arn = arn(&actor, &name);
    call(
        &app,
        &actor,
        Method::PUT,
        &[
            "tables",
            &arn,
            &namespace,
            &table,
            "maintenance",
            COMPACTION,
        ],
        "",
        json!({ "value": {
            "status": status(body.enabled),
            "settings": { COMPACTION: {
                "targetFileSizeMB": body.target_file_size_mb,
                "strategy": body.strategy,
            } },
        } }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod e2e {
    use axum::http::StatusCode;
    use serde_json::json;

    use super::super::e2e::{console_of, signed_in};

    /// A table bucket's encryption, storage class and unreferenced file
    /// removal, and a table's snapshot management and compaction, as the
    /// console sets them: S3 Tables' own operations, checked as it checks
    /// them.
    #[tokio::test]
    async fn sets_table_maintenance() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = console_of(&app);
        let mut admin = signed_in(&console, "admin", true).await;
        let mut user = signed_in(&console, "nobody", false).await;
        for (path, body) in [
            ("/api/table-buckets", json!({ "name": "lake" })),
            (
                "/api/table-buckets/lake/namespaces",
                json!({ "name": "sales" }),
            ),
            (
                "/api/table-buckets/lake/tables",
                json!({ "namespace": "sales", "name": "orders" }),
            ),
        ] {
            let (status, body) = admin.send("POST", path, Some(body)).await;
            assert_eq!(status, StatusCode::CREATED, "{path}: {body}");
        }

        let (_, detail) = admin.send("GET", "/api/table-buckets/lake", None).await;
        assert_eq!(
            detail["unreferenced_file_removal"],
            json!({ "enabled": true, "unreferenced_days": 3, "non_current_days": 10 })
        );
        let removal = |enabled: bool, days: i64| {
            Some(json!({ "enabled": enabled, "unreferenced_days": days, "non_current_days": 20 }))
        };
        let path = "/api/table-buckets/lake/maintenance";
        assert_eq!(
            admin.send("PUT", path, removal(false, 0)).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            user.send("PUT", path, removal(false, 5)).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            admin.send("PUT", path, removal(false, 5)).await.0,
            StatusCode::NO_CONTENT
        );

        let class = |c: &str| Some(json!({ "storage_class": c }));
        let path = "/api/table-buckets/lake/storage-class";
        assert_eq!(
            admin.send("PUT", path, class("GLACIER")).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            admin
                .send("PUT", path, class("INTELLIGENT_TIERING"))
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        let encryption = |a: &str, key: &str| Some(json!({ "algorithm": a, "kms_key_arn": key }));
        let path = "/api/table-buckets/lake/encryption";
        assert_eq!(
            admin.send("PUT", path, encryption("aws:kms", "")).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            admin.send("PUT", path, encryption("AES256", "")).await.0,
            StatusCode::NO_CONTENT
        );
        let (_, detail) = admin.send("GET", "/api/table-buckets/lake", None).await;
        assert_eq!(
            detail["unreferenced_file_removal"],
            json!({ "enabled": false, "unreferenced_days": 5, "non_current_days": 20 })
        );
        // A class the operator hasn't defined is STANDARD, as an object's.
        assert_eq!(detail["storage_class"], "STANDARD");
        assert_eq!(detail["encryption"], "AES256");

        let table = "/api/table-buckets/lake/tables/sales/orders/maintenance";
        let (status, m) = admin.send("GET", table, None).await;
        assert_eq!(status, StatusCode::OK, "{m}");
        assert_eq!(
            m["snapshot_management"],
            json!({ "enabled": true, "min_snapshots_to_keep": 1, "max_snapshot_age_hours": 120 })
        );
        assert_eq!(
            m["compaction"],
            json!({ "enabled": true, "target_file_size_mb": 512, "strategy": "auto" })
        );
        // The table has no metadata yet: none has run; the bucket's removal
        // is off.
        let jobs = m["jobs"].as_array().unwrap();
        assert_eq!(jobs.len(), 3, "{m}");
        let status_of = |kind: &str| {
            jobs.iter().find(|j| j["kind"] == kind).unwrap()["status"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        assert_eq!(status_of("icebergCompaction"), "Not_Yet_Run");
        assert_eq!(status_of("icebergUnreferencedFileRemoval"), "Disabled");

        let compaction = |size: i64, strategy: &str| {
            Some(json!({ "enabled": true, "target_file_size_mb": size, "strategy": strategy }))
        };
        let path = format!("{table}/compaction");
        assert_eq!(
            admin.send("PUT", &path, compaction(1000, "auto")).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            admin.send("PUT", &path, compaction(256, "spiral")).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            admin.send("PUT", &path, compaction(256, "z-order")).await.0,
            StatusCode::NO_CONTENT
        );
        let snapshots =
            json!({ "enabled": false, "min_snapshots_to_keep": 3, "max_snapshot_age_hours": 48 });
        let path = format!("{table}/snapshots");
        assert_eq!(
            user.send("PUT", &path, Some(snapshots.clone())).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            admin.send("PUT", &path, Some(snapshots.clone())).await.0,
            StatusCode::NO_CONTENT
        );
        let (_, m) = admin.send("GET", table, None).await;
        assert_eq!(m["snapshot_management"], snapshots);
        assert_eq!(m["compaction"]["strategy"], "z-order");
        assert_eq!(m["compaction"]["target_file_size_mb"], 256);
        // What may not be seen isn't shown.
        let (status, m) = user.send("GET", table, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(m["compaction"], serde_json::Value::Null);
        assert_eq!(m["jobs"], serde_json::Value::Null);
    }
}
