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
