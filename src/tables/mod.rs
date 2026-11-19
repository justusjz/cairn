//! S3 Tables, on the S3 port: requests signed for the `s3tables` service
//! are these, whatever their path, as IAM's and SNS's are (see `s3`). Table
//! buckets of an account's, their namespaces (one level), and their Apache
//! Iceberg tables, through the `s3tables` API (restJson1: botocore's
//! `s3tables/2018-05-10`).
//!
//! A table is a pointer to its current Iceberg metadata file
//! (`metadataLocation`), which UpdateTableMetadataLocation swaps against
//! the table's version token, a new one on each change: Iceberg's atomic
//! commit, for clients that write their metadata files themselves. Its
//! files are in its storage (`warehouseLocation`), a bucket of its own
//! (see `storage`), which clients read and write through the S3 API.
//!
//! A request acts as its signer: each operation is checked as its
//! `s3tables:` action, on the table bucket's ARN or the table's, by the
//! signer's policies and the table bucket's resource policy, and the
//! table's (both, for a table: as a bucket's policy is, across accounts
//! too), with S3 Tables' condition keys (`s3tables:namespace`,
//! `s3tables:tableName`, `s3tables:TableBucketTag/…`, …). Another account's
//! table bucket may be used where its policies allow it, as in AWS.
//!
//! Iceberg's REST catalog is here too, under `/iceberg` (see
//! `iceberg::rest`), and CreateTable with `metadata` writes the table's
//! first metadata file as it does.
//!
//! Not here: maintenance that runs, replication,
//! server access logging, record expiration (AWS's own tables only), and
//! migrations from Glue (see `plans/s3-tables.md`). Where AWS's answers
//! weren't known (and couldn't be probed), they follow its API model and
//! documentation, or the nearest case.

mod buckets;
#[cfg(test)]
mod e2e;
pub mod iceberg;
pub mod names;
mod namespaces;
pub mod storage;
mod table;

use std::net::IpAddr;
use std::sync::Arc;

use http_body_util::{BodyExt, Full, Limited};
use hyper::{Method, Request, Response, StatusCode, body::Bytes};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{
    App,
    auth::Signed,
    db::Cached,
    policy::{Context, Kind, Policy, Verdict},
    s3::{
        access::{Access, Origin},
        actions::{Check, On},
        util::{decode_continuation_token, decode_path_param, encode_continuation_token},
    },
    users::{self, Principal},
};

pub use names::is_storage;

/// S3 Tables' actions (AWS's service authorization reference), which table
/// buckets' and tables' policies name, and identity policies may.
pub const ACTIONS: &[&str] = &[
    "CompleteTableMigration",
    "CreateNamespace",
    "CreateTable",
    "CreateTableBucket",
    "DeleteNamespace",
    "DeleteTable",
    "DeleteTableBucket",
    "DeleteTableBucketEncryption",
    "DeleteTableBucketMetricsConfiguration",
    "DeleteTableBucketPolicy",
    "DeleteTableBucketReplication",
    "DeleteTablePolicy",
    "DeleteTableReplication",
    "GetNamespace",
    "GetTable",
    "GetTableBucket",
    "GetTableBucketEncryption",
    "GetTableBucketLogging",
    "GetTableBucketMaintenanceConfiguration",
    "GetTableBucketMetricsConfiguration",
    "GetTableBucketPolicy",
    "GetTableBucketReplication",
    "GetTableBucketStorageClass",
    "GetTableData",
    "GetTableEncryption",
    "GetTableMaintenanceConfiguration",
    "GetTableMaintenanceJobStatus",
    "GetTableMetadataLocation",
    "GetTableMigration",
    "GetTablePolicy",
    "GetTableRecordExpirationConfiguration",
    "GetTableRecordExpirationJobStatus",
    "GetTableReplication",
    "GetTableReplicationStatus",
    "GetTableStorageClass",
    "ListNamespaces",
    "ListTableBuckets",
    "ListTableMigrations",
    "ListTables",
    "ListTagsForResource",
    "PutTableBucketEncryption",
    "PutTableBucketLogging",
    "PutTableBucketMaintenanceConfiguration",
    "PutTableBucketMetricsConfiguration",
    "PutTableBucketPolicy",
    "PutTableBucketReplication",
    "PutTableBucketStorageClass",
    "PutTableData",
    "PutTableEncryption",
    "PutTableMaintenanceConfiguration",
    "PutTablePolicy",
    "PutTableRecordExpirationConfiguration",
    "PutTableReplication",
    "PutTableStorageClass",
    "RenameTable",
    "StartTableMigration",
    "SyncTableMigration",
    "TagResource",
    "UntagResource",
    "UpdateTableMetadataLocation",
    "UpdateTableMigration",
];

/// Whether `key` (lowercase) is one of S3 Tables' condition keys, which
/// Cairn's requests carry where AWS's do.
pub fn evaluated_key(key: &str) -> bool {
    matches!(
        key,
        "s3tables:namespace"
            | "s3tables:tablename"
            | "s3tables:ssealgorithm"
            | "s3tables:kmskeyarn"
            | "s3tables:storageclass"
    ) || key
        .strip_prefix("s3tables:tablebuckettag/")
        .is_some_and(|tag| !tag.is_empty())
}

/// Whether a request signed so is S3 Tables'.
pub fn wants(signed: &Signed) -> bool {
    signed.service == "s3tables"
}

/// The most a request's body may hold: an Iceberg commit's too.
const MAX_BODY: usize = 8 << 20;

/// The most table buckets an account may have, and namespaces and tables
/// a table bucket may (AWS's default quotas).
const MAX_BUCKETS: i64 = 100;
const MAX_NAMESPACES: i64 = 10_000;
const MAX_TABLES: i64 = 10_000;

/// The most a resource policy may be.
const MAX_POLICY: usize = 20_480;

/// A failed request: its status, its exception's name, and its message.
#[derive(Debug)]
pub struct Error {
    pub(crate) status: StatusCode,
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

fn error(status: StatusCode, code: &'static str, message: impl Into<String>) -> Error {
    Error {
        status,
        code,
        message: message.into(),
    }
}

fn bad_request(message: impl Into<String>) -> Error {
    error(StatusCode::BAD_REQUEST, "BadRequestException", message)
}

fn not_found(message: impl Into<String>) -> Error {
    error(StatusCode::NOT_FOUND, "NotFoundException", message)
}

fn conflict(message: impl Into<String>) -> Error {
    error(StatusCode::CONFLICT, "ConflictException", message)
}

fn not_implemented(what: &str) -> Error {
    error(
        StatusCode::NOT_IMPLEMENTED,
        "NotImplemented",
        format!("Cairn's S3 Tables don't have {what}."),
    )
}

const NO_BUCKET: &str = "The specified bucket does not exist.";
const NO_NAMESPACE: &str = "The specified namespace does not exist.";
const NO_TABLE: &str = "The specified table does not exist.";

fn no_bucket() -> Error {
    not_found(NO_BUCKET)
}

fn no_namespace() -> Error {
    not_found(NO_NAMESPACE)
}

fn no_table() -> Error {
    not_found(NO_TABLE)
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Error {
        eprintln!("s3tables: a request failed: {e:#}");
        error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerErrorException",
            "We encountered an internal error. Please try again.",
        )
    }
}

impl From<tokio_postgres::Error> for Error {
    fn from(e: tokio_postgres::Error) -> Error {
        anyhow::Error::from(e).into()
    }
}

impl From<deadpool_postgres::PoolError> for Error {
    fn from(e: deadpool_postgres::PoolError) -> Error {
        anyhow::Error::from(e).into()
    }
}

/// What an operation answers.
#[derive(Debug)]
pub(crate) enum Answer {
    /// 200, with its output.
    Json(Value),
    /// 204, without a body.
    NoContent,
    /// Any status, with a body (JSON) or none: Iceberg's REST catalog's
    /// answers, its errors too (see `iceberg::rest`).
    Raw(StatusCode, Option<Value>),
}

/// An S3 Tables request, on the S3 port.
pub async fn handle(
    app: &Arc<App>,
    req: Request<crate::listen::ClientBody>,
    signed: Signed,
    peer: IpAddr,
) -> Response<Full<Bytes>> {
    let request_id = Uuid::new_v4().to_string();
    let response = Response::builder()
        .header("x-amzn-requestid", &request_id)
        .header("content-type", "application/json");
    match respond(app, req, &signed, peer).await {
        Ok(Answer::Json(value)) => response
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from(value.to_string()))),
        Ok(Answer::NoContent) => response
            .status(StatusCode::NO_CONTENT)
            .body(Full::new(Bytes::new())),
        Ok(Answer::Raw(status, body)) => response.status(status).body(Full::new(
            body.map_or_else(Bytes::new, |b| Bytes::from(b.to_string())),
        )),
        Err(e) => response
            .status(e.status)
            .header("x-amzn-errortype", e.code)
            .body(Full::new(Bytes::from(
                json!({ "message": e.message }).to_string(),
            ))),
    }
    .unwrap()
}

/// `path` as services other than S3 sign it: each of its (encoded)
/// segments encoded again (`%3A` is `%253A`), as the SDKs do.
fn double_encoded(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for b in path.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

async fn respond(
    app: &Arc<App>,
    req: Request<crate::listen::ClientBody>,
    signed: &Signed,
    peer: IpAddr,
) -> Result<Answer> {
    let (parts, body) = req.into_parts();
    let body = Limited::new(body, MAX_BODY)
        .collect()
        .await
        .map_err(|_| bad_request("The request's body is too large, or broken."))?
        .to_bytes();
    let client = app.pool.get().await?;
    let principal = match Principal::authenticate(
        &client,
        &app.sessions,
        &signed.access_key,
        signed.token.as_deref(),
    )
    .await?
    {
        Ok(principal) => principal,
        Err(users::Unknown::Expired) => {
            return Err(error(
                StatusCode::FORBIDDEN,
                "ExpiredTokenException",
                "The security token included in the request is expired",
            ));
        }
        Err(_) => {
            return Err(error(
                StatusCode::FORBIDDEN,
                "UnrecognizedClientException",
                "The security token included in the request is invalid.",
            ));
        }
    };
    let query = parts.uri.query().unwrap_or("");
    crate::auth::verify_sigv4_with_body(
        parts.method.as_str(),
        &double_encoded(parts.uri.path()),
        query,
        &parts.headers,
        &principal.secret,
        &body,
    )
    .map_err(|r| {
        error(
            StatusCode::FORBIDDEN,
            if r.code == "SignatureDoesNotMatch" {
                "InvalidSignatureException"
            } else {
                "IncompleteSignatureException"
            },
            r.message,
        )
    })?;
    let origin = Origin {
        peer: Some(peer),
        trusted_proxies: &app.trusted_proxies,
        signed: Some(signed),
        form: false,
    };
    let mut access = Access::new(
        Some(&principal),
        &principal.account,
        &parts.method,
        &parts.headers,
        "",
        &origin,
    )?;
    let mut ctx = Ctx {
        app,
        client,
        principal: &principal,
        access: &mut access,
        endpoint: Some(endpoint(&parts.headers)),
    };
    ctx.dispatch(&parts.method, parts.uri.path(), query, &body)
        .await
}

/// A request's operations, as its signer.
pub(crate) struct Ctx<'a> {
    pub(crate) app: &'a Arc<App>,
    pub(crate) client: deadpool_postgres::Object,
    pub(crate) principal: &'a Principal,
    pub(crate) access: &'a mut Access,
    /// Where the client reached this endpoint, as its request says (see
    /// `endpoint`), if it's a client's request.
    pub(crate) endpoint: Option<String>,
}

/// The URL clients reach this endpoint at, as a request to it says: its
/// scheme (HTTPS, if a trusted proxy says so) and `Host`.
fn endpoint(headers: &hyper::HeaderMap) -> String {
    let host = headers
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let scheme = match crate::s3::sse_c::secure(headers, false) {
        true => "https",
        false => "http",
    };
    format!("{scheme}://{host}")
}

/// A request's JSON body.
pub(crate) struct Input(Map<String, Value>);

impl Input {
    fn parse(body: &[u8]) -> Result<Input> {
        if body.is_empty() {
            return Ok(Input(Map::new()));
        }
        match serde_json::from_slice(body) {
            Ok(Value::Object(map)) => Ok(Input(map)),
            _ => Err(bad_request("The request's body isn't a JSON object.")),
        }
    }

    fn get(&self, name: &str) -> Option<&Value> {
        self.0.get(name).filter(|v| !v.is_null())
    }

    /// A string member, if it's there.
    fn str(&self, name: &str) -> Result<Option<&str>> {
        match self.get(name) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s)),
            Some(_) => Err(bad_request(format!("{name} must be a string."))),
        }
    }

    /// A string member the operation requires.
    fn required(&self, name: &str) -> Result<&str> {
        self.str(name)?
            .ok_or_else(|| bad_request(format!("{name} is required.")))
    }

    /// An object member, if it's there.
    fn object(&self, name: &str) -> Result<Option<Input>> {
        match self.get(name) {
            None => Ok(None),
            Some(Value::Object(map)) => Ok(Some(Input(map.clone()))),
            Some(_) => Err(bad_request(format!("{name} must be an object."))),
        }
    }

    /// An integer member, if it's there.
    fn int(&self, name: &str) -> Result<Option<i64>> {
        match self.get(name) {
            None => Ok(None),
            Some(v) => v
                .as_i64()
                .map(Some)
                .ok_or_else(|| bad_request(format!("{name} must be an integer."))),
        }
    }
}

/// A page of a listing: how many (`max`, 1 to 1000; 1000 if not given) to
/// list after the continuation token's position, if there's one.
struct Page {
    max: i64,
    after: Option<String>,
}

impl Page {
    fn of(query: &str, max_name: &str) -> Result<Page> {
        let max = match crate::s3::util::query_param(query, max_name) {
            None => 1000,
            Some(text) => match text.parse::<i64>() {
                Ok(n) if (1..=1000).contains(&n) => n,
                _ => {
                    return Err(bad_request(format!(
                        "{max_name} must be between 1 and 1000."
                    )));
                }
            },
        };
        let after = match crate::s3::util::query_param(query, "continuationToken") {
            None => None,
            Some(token) => Some(
                decode_continuation_token(&token)
                    .ok_or_else(|| bad_request("The continuation token is not valid."))?,
            ),
        };
        Ok(Page { max, after })
    }

    /// The token that continues after `last`, if the page was full.
    fn next(&self, count: usize, last: Option<String>) -> Option<String> {
        (count as i64 == self.max)
            .then_some(last)
            .flatten()
            .map(|last| encode_continuation_token(&last))
    }
}

/// SQL for a timestamp column's ISO 8601 text, as S3 Tables writes them.
fn iso(column: &str) -> String {
    format!("to_char({column} AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')")
}

/// Tags, as S3 Tables takes them: a map of up to 50, keys of 1 to 128
/// characters, values of up to 256, none starting with `aws:`.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Tags(pub(crate) Vec<(String, String)>);

impl Tags {
    fn from_stored(stored: Option<&str>) -> Tags {
        let map: Map<String, Value> = stored
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();
        Tags(
            map.into_iter()
                .map(|(k, v)| (k, v.as_str().unwrap_or("").to_owned()))
                .collect(),
        )
    }

    /// Their stored form (none, if there are none).
    fn stored(&self) -> Option<String> {
        (!self.0.is_empty()).then(|| self.json().to_string())
    }

    fn json(&self) -> Value {
        Value::Object(
            self.0
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect(),
        )
    }

    /// The tags a request's member `tags` gives (none, if it's not there).
    fn from_input(input: &Input) -> Result<Tags> {
        let Some(value) = input.get("tags") else {
            return Ok(Tags::default());
        };
        let Value::Object(map) = value else {
            return Err(bad_request("tags must be a map."));
        };
        let mut tags = Vec::new();
        for (key, value) in map {
            let Value::String(value) = value else {
                return Err(bad_request("A tag's value must be a string."));
            };
            if !(1..=128).contains(&key.chars().count()) || value.chars().count() > 256 {
                return Err(bad_request(
                    "A tag's key must be 1 to 128 characters, and its value at most 256.",
                ));
            }
            if key.to_ascii_lowercase().starts_with("aws:") {
                return Err(bad_request("Tag keys may not start with aws:."));
            }
            tags.push((key.clone(), value.clone()));
        }
        let tags = Tags(tags);
        tags.limit()?;
        Ok(tags)
    }

    fn limit(&self) -> Result<()> {
        match self.0.len() > 50 {
            true => Err(bad_request("A resource may have at most 50 tags.")),
            false => Ok(()),
        }
    }

    /// `other`'s tags too, replacing ours of their keys.
    fn merged(&self, other: &Tags) -> Tags {
        let mut tags = self.0.clone();
        for (key, value) in &other.0 {
            match tags.iter_mut().find(|(k, _)| k == key) {
                Some(tag) => tag.1 = value.clone(),
                None => tags.push((key.clone(), value.clone())),
            }
        }
        Tags(tags)
    }

    /// The request's: `aws:RequestTag/…` and `aws:TagKeys`.
    fn set_request_context(&self, context: &mut Context) {
        for (key, value) in &self.0 {
            context.set(&format!("aws:RequestTag/{key}"), value);
        }
        context.set_all(
            "aws:TagKeys",
            self.0.iter().map(|(k, _)| k.clone()).collect(),
        );
    }
}

/// A table bucket.
#[derive(Clone, Debug)]
pub(crate) struct TableBucket {
    pub(crate) id: Uuid,
    pub(crate) account: String,
    pub(crate) name: String,
    pub(crate) created: String,
    pub(crate) policy: Option<String>,
    pub(crate) sse_algorithm: String,
    pub(crate) kms_key: Option<String>,
    pub(crate) storage_class: String,
    pub(crate) maintenance: Map<String, Value>,
    pub(crate) metrics: bool,
    pub(crate) tags: Tags,
    /// The users and roles its policy names, by their ARNs (as bucket
    /// policies keep them).
    pub(crate) policy_principals: Option<String>,
}

impl TableBucket {
    fn columns() -> String {
        format!(
            "b.id, b.account_id, b.name, {}, b.policy, b.sse_algorithm, b.kms_key, b.storage_class, \
             b.maintenance::text, b.metrics, b.tags, b.policy_principals::text",
            iso("b.created_at")
        )
    }

    fn from_row(row: &tokio_postgres::Row) -> TableBucket {
        TableBucket {
            id: row.get(0),
            account: row.get(1),
            name: row.get(2),
            created: row.get(3),
            policy: row.get(4),
            sse_algorithm: row.get(5),
            kms_key: row.get(6),
            storage_class: row.get(7),
            maintenance: serde_json::from_str(row.get::<_, &str>(8)).unwrap_or_default(),
            metrics: row.get(9),
            tags: Tags::from_stored(row.get(10)),
            policy_principals: row.get(11),
        }
    }

    /// `account`'s table bucket `name`, if there's one (a closed account's
    /// are none: see `organizations`).
    pub(crate) async fn load(
        client: &impl deadpool_postgres::GenericClient,
        account: &str,
        name: &str,
    ) -> anyhow::Result<Option<TableBucket>> {
        let sql = format!(
            "SELECT {} FROM table_buckets b JOIN accounts a ON a.id = b.account_id
             WHERE b.account_id = $1 AND b.name = $2 AND a.closed_at IS NULL",
            Self::columns()
        );
        Ok(client
            .query_opt(&sql, &[&account, &name])
            .await?
            .map(|r| TableBucket::from_row(&r)))
    }

    pub(crate) fn arn(&self) -> String {
        names::bucket_arn(&self.account, &self.name)
    }

    /// Its policy, parsed.
    fn parsed_policy(&self) -> anyhow::Result<Option<Arc<Policy>>> {
        let arn = self.arn();
        self.policy
            .as_deref()
            .map(|text| {
                let ids = self.policy_principals.as_deref().unwrap_or("{}");
                crate::s3::access::parsed(text, Kind::Tables(&arn), Some(ids))
            })
            .transpose()
    }

    fn summary(&self) -> Value {
        json!({
            "arn": self.arn(),
            "name": self.name,
            "ownerAccountId": self.account,
            "createdAt": self.created,
            "tableBucketId": self.id.to_string(),
            "type": "customer",
        })
    }
}

/// A table, and its namespace.
#[derive(Clone, Debug)]
pub(crate) struct Table {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) namespace_id: Uuid,
    pub(crate) namespace: String,
    /// Its storage bucket's name.
    pub(crate) storage: String,
    pub(crate) metadata_location: Option<String>,
    pub(crate) version_token: String,
    pub(crate) created: String,
    pub(crate) created_by: String,
    pub(crate) modified: String,
    pub(crate) modified_by: String,
    pub(crate) policy: Option<String>,
    pub(crate) sse_algorithm: String,
    pub(crate) kms_key: Option<String>,
    pub(crate) storage_class: String,
    pub(crate) maintenance: Map<String, Value>,
    pub(crate) tags: Tags,
    /// The users and roles its policy names, by their ARNs.
    pub(crate) policy_principals: Option<String>,
}

impl Table {
    fn columns() -> String {
        format!(
            "t.id, t.name, n.id, n.name, t.storage, t.metadata_location, t.version_token, {}, \
             t.created_by, {}, t.modified_by, t.policy, t.sse_algorithm, t.kms_key, t.storage_class, \
             t.maintenance::text, t.tags, t.policy_principals::text",
            iso("t.created_at"),
            iso("t.modified_at")
        )
    }

    fn from_row(row: &tokio_postgres::Row) -> Table {
        Table {
            id: row.get(0),
            name: row.get(1),
            namespace_id: row.get(2),
            namespace: row.get(3),
            storage: row.get(4),
            metadata_location: row.get(5),
            version_token: row.get(6),
            created: row.get(7),
            created_by: row.get(8),
            modified: row.get(9),
            modified_by: row.get(10),
            policy: row.get(11),
            sse_algorithm: row.get(12),
            kms_key: row.get(13),
            storage_class: row.get(14),
            maintenance: serde_json::from_str(row.get::<_, &str>(15)).unwrap_or_default(),
            tags: Tags::from_stored(row.get(16)),
            policy_principals: row.get(17),
        }
    }

    /// Table `name` in namespace `namespace` of table bucket `bucket`, if
    /// it's there; locked (`FOR UPDATE`), with `lock`.
    pub(crate) async fn load(
        client: &impl deadpool_postgres::GenericClient,
        bucket: Uuid,
        namespace: &str,
        name: &str,
        lock: bool,
    ) -> anyhow::Result<Option<Table>> {
        let sql = format!(
            "SELECT {} FROM tables t JOIN table_namespaces n ON n.id = t.namespace_id
             WHERE t.table_bucket_id = $1 AND n.name = $2 AND t.name = $3{}",
            Self::columns(),
            if lock { " FOR UPDATE OF t" } else { "" }
        );
        Ok(client
            .query_opt(&sql, &[&bucket, &namespace, &name])
            .await?
            .map(|r| Table::from_row(&r)))
    }

    /// Table `id` of table bucket `bucket`, if it's there.
    pub(crate) async fn by_id(
        client: &impl deadpool_postgres::GenericClient,
        bucket: Uuid,
        id: Uuid,
    ) -> anyhow::Result<Option<Table>> {
        let sql = format!(
            "SELECT {} FROM tables t JOIN table_namespaces n ON n.id = t.namespace_id
             WHERE t.table_bucket_id = $1 AND t.id = $2",
            Self::columns()
        );
        Ok(client
            .query_opt(&sql, &[&bucket, &id])
            .await?
            .map(|r| Table::from_row(&r)))
    }

    /// The table whose storage `bucket` is, and its table bucket's
    /// account and name, if there's one (see `storage`).
    pub(crate) async fn by_storage(
        client: &impl deadpool_postgres::GenericClient,
        bucket: &str,
    ) -> anyhow::Result<Option<(TableBucket, Table)>> {
        let sql = format!(
            "SELECT {}, {} FROM tables t JOIN table_namespaces n ON n.id = t.namespace_id
             JOIN table_buckets b ON b.id = t.table_bucket_id JOIN accounts a ON a.id = b.account_id
             WHERE t.storage = $1 AND a.closed_at IS NULL",
            Self::columns(),
            TableBucket::columns()
        );
        let Some(row) = client.query_opt(&sql, &[&bucket]).await? else {
            return Ok(None);
        };
        let table = Table::from_row(&row);
        // The bucket's columns follow the table's 18.
        let bucket = TableBucket {
            id: row.get(18),
            account: row.get(19),
            name: row.get(20),
            created: row.get(21),
            policy: row.get(22),
            sse_algorithm: row.get(23),
            kms_key: row.get(24),
            storage_class: row.get(25),
            maintenance: serde_json::from_str(row.get::<_, &str>(26)).unwrap_or_default(),
            metrics: row.get(27),
            tags: Tags::from_stored(row.get(28)),
            policy_principals: row.get(29),
        };
        Ok(Some((bucket, table)))
    }

    pub(crate) fn arn(&self, bucket: &TableBucket) -> String {
        names::table_arn(&bucket.arn(), &self.id.to_string())
    }

    pub(crate) fn warehouse_location(&self) -> String {
        format!("s3://{}", self.storage)
    }

    /// Its policy, parsed.
    fn parsed_policy(&self, bucket: &TableBucket) -> anyhow::Result<Option<Arc<Policy>>> {
        let arn = self.arn(bucket);
        self.policy
            .as_deref()
            .map(|text| {
                let ids = self.policy_principals.as_deref().unwrap_or("{}");
                crate::s3::access::parsed(text, Kind::Tables(&arn), Some(ids))
            })
            .transpose()
    }
}

/// A new version token.
fn version_token() -> String {
    Uuid::new_v4().simple().to_string()
}

/// A resource's policy, as `Access::set_resource` takes it: its table
/// bucket's ARN, its account, and its (and its table's) resource policy.
pub(crate) type Resource = (String, String, Option<Arc<Policy>>);

/// What a check is on.
pub(crate) enum Target<'b> {
    /// No resource (`*`): ListTableBuckets.
    Account,
    /// A table bucket (that may not be there: then by its ARN's account
    /// and name), and perhaps a namespace in it.
    Bucket {
        account: &'b str,
        name: &'b str,
        bucket: Option<&'b TableBucket>,
        namespace: Option<&'b str>,
    },
    /// A table of a bucket.
    Table {
        bucket: &'b TableBucket,
        table: &'b Table,
    },
    /// A table that isn't there (or not yet): by its namespace and name,
    /// on the ARN of every table of the bucket's.
    NoTable {
        bucket: &'b TableBucket,
        namespace: &'b str,
        name: &'b str,
    },
}

/// The resource policies `target` is decided by, and the condition keys of
/// its resource, and its ARN; with its table bucket's ARN and account.
pub(crate) fn resource_of(target: &Target) -> anyhow::Result<(On, Context, Option<Resource>)> {
    let mut context = Context::default();
    let set_bucket_tags = |context: &mut Context, bucket: &TableBucket, resource: bool| {
        for (key, value) in &bucket.tags.0 {
            context.set(&format!("s3tables:TableBucketTag/{key}"), value);
            if resource {
                context.set(&format!("aws:ResourceTag/{key}"), value);
            }
        }
    };
    Ok(match target {
        Target::Account => (On::Account, context, None),
        Target::Bucket {
            account,
            name,
            bucket,
            namespace,
        } => {
            let arn = names::bucket_arn(account, name);
            if let Some(namespace) = namespace {
                context.set("s3tables:namespace", *namespace);
            }
            let policy = match bucket {
                Some(bucket) => {
                    set_bucket_tags(&mut context, bucket, true);
                    bucket.parsed_policy()?
                }
                None => None,
            };
            (
                On::Arn(arn.clone()),
                context,
                Some((arn, account.to_string(), policy)),
            )
        }
        Target::Table { bucket, table } => {
            set_bucket_tags(&mut context, bucket, false);
            for (key, value) in &table.tags.0 {
                context.set(&format!("aws:ResourceTag/{key}"), value);
            }
            context.set("s3tables:namespace", &table.namespace);
            context.set("s3tables:tableName", &table.name);
            let policy = match (bucket.parsed_policy()?, table.parsed_policy(bucket)?) {
                (Some(b), Some(t)) => Some(Arc::new(b.merged(&t))),
                (b, t) => b.or(t),
            };
            (
                On::Arn(table.arn(bucket)),
                context,
                Some((bucket.arn(), bucket.account.clone(), policy)),
            )
        }
        Target::NoTable {
            bucket,
            namespace,
            name,
        } => {
            set_bucket_tags(&mut context, bucket, false);
            context.set("s3tables:namespace", *namespace);
            context.set("s3tables:tableName", *name);
            (
                On::Arn(names::table_arn(&bucket.arn(), "*")),
                context,
                Some((
                    bucket.arn(),
                    bucket.account.clone(),
                    bucket.parsed_policy()?,
                )),
            )
        }
    })
}

impl Ctx<'_> {
    pub(crate) fn account(&self) -> &str {
        &self.principal.account
    }

    /// Refuses the request unless `action` (`s3tables:…`) on `target` is
    /// allowed, by the signer's policies and the resource's, with the
    /// condition keys `extra` too.
    pub(crate) fn check(
        &mut self,
        action: &'static str,
        target: &Target,
        extra: &Context,
    ) -> Result<()> {
        let (on, mut context, resource) = resource_of(target)?;
        if let Some((arn, account, policy)) = resource {
            self.access.set_resource(&arn, &account, policy);
        }
        context.extend(extra);
        let check = Check { action, on };
        let verdict = self.access.verdict_with(&check, &context);
        if verdict == Verdict::Allow {
            return Ok(());
        }
        let on = match &check.on {
            On::Account => String::new(),
            on => format!(" on resource: {}", on.arn()),
        };
        Err(error(
            StatusCode::FORBIDDEN,
            "AccessDeniedException",
            format!(
                "User: {} is not authorized to perform: {action}{on} {}",
                self.principal.arn(),
                verdict.why(action, self.access.boundary())
            ),
        ))
    }

    /// The table bucket an ARN names: its account and name, and the bucket
    /// if it's there.
    async fn bucket_of(&self, arn: &str) -> Result<(String, String, Option<TableBucket>)> {
        match names::parse_arn(arn).map_err(bad_request)? {
            Some(names::Arn::Bucket { account, name }) => {
                let bucket = TableBucket::load(&self.client, &account, &name).await?;
                Ok((account, name, bucket))
            }
            Some(names::Arn::Table { .. }) => Err(bad_request(format!(
                "The specified ARN is not a table bucket's: {arn}"
            ))),
            None => Err(no_bucket()),
        }
    }

    /// The table bucket `arn` names, if `action` on it is allowed; S3
    /// Tables' 404 if it's not there.
    async fn checked_bucket(
        &mut self,
        arn: &str,
        action: &'static str,
        extra: &Context,
    ) -> Result<TableBucket> {
        let (account, name, bucket) = self.bucket_of(arn).await?;
        self.check(
            action,
            &Target::Bucket {
                account: &account,
                name: &name,
                bucket: bucket.as_ref(),
                namespace: None,
            },
            extra,
        )?;
        bucket.ok_or_else(no_bucket)
    }

    /// The table bucket `arn` names, and its table `name` in `namespace`,
    /// if `action` on it is allowed; 404 if either isn't there.
    async fn checked_table(
        &mut self,
        arn: &str,
        namespace: &str,
        name: &str,
        action: &'static str,
        extra: &Context,
    ) -> Result<(TableBucket, Table)> {
        let (account, bucket_name, bucket) = self.bucket_of(arn).await?;
        let Some(bucket) = bucket else {
            self.check(
                action,
                &Target::Bucket {
                    account: &account,
                    name: &bucket_name,
                    bucket: None,
                    namespace: Some(namespace),
                },
                extra,
            )?;
            return Err(no_bucket());
        };
        let table = Table::load(&self.client, bucket.id, namespace, name, false).await?;
        match table {
            Some(table) => {
                self.check(
                    action,
                    &Target::Table {
                        bucket: &bucket,
                        table: &table,
                    },
                    extra,
                )?;
                Ok((bucket, table))
            }
            None => {
                self.check(
                    action,
                    &Target::NoTable {
                        bucket: &bucket,
                        namespace,
                        name,
                    },
                    extra,
                )?;
                Err(no_table())
            }
        }
    }

    /// Routes a request to its operation.
    pub(crate) async fn dispatch(
        &mut self,
        method: &Method,
        path: &str,
        query: &str,
        body: &[u8],
    ) -> Result<Answer> {
        let segments: Vec<String> = path
            .trim_start_matches('/')
            .split('/')
            .map(decode_path_param)
            .collect();
        let segments: Vec<&str> = segments.iter().map(String::as_str).collect();
        // Iceberg's REST catalog (see `iceberg::rest`).
        if segments.first() == Some(&"iceberg") {
            return Ok(self.iceberg(method, &segments[1..], query, body).await);
        }
        let input = Input::parse(body)?;
        let q = |name: &str| crate::s3::util::query_param(query, name);
        use Method as M;
        match (method, &segments[..]) {
            (&M::PUT, ["buckets"]) => self.create_bucket(&input).await,
            (&M::GET, ["buckets"]) => self.list_buckets(query).await,
            (&M::GET, ["buckets", arn]) => self.get_bucket(arn).await,
            (&M::DELETE, ["buckets", arn]) => self.delete_bucket(arn).await,
            (&M::PUT, ["buckets", arn, "policy"]) => self.put_bucket_policy(arn, &input).await,
            (&M::GET, ["buckets", arn, "policy"]) => self.get_bucket_policy(arn).await,
            (&M::DELETE, ["buckets", arn, "policy"]) => self.delete_bucket_policy(arn).await,
            (&M::PUT, ["buckets", arn, "encryption"]) => {
                self.put_bucket_encryption(arn, &input).await
            }
            (&M::GET, ["buckets", arn, "encryption"]) => self.get_bucket_encryption(arn).await,
            (&M::DELETE, ["buckets", arn, "encryption"]) => {
                self.delete_bucket_encryption(arn).await
            }
            (&M::PUT, ["buckets", arn, "storage-class"]) => {
                self.put_bucket_storage_class(arn, &input).await
            }
            (&M::GET, ["buckets", arn, "storage-class"]) => {
                self.get_bucket_storage_class(arn).await
            }
            (&M::GET, ["buckets", arn, "maintenance"]) => self.get_bucket_maintenance(arn).await,
            (&M::PUT, ["buckets", arn, "maintenance", kind]) => {
                self.put_bucket_maintenance(arn, kind, &input).await
            }
            (&M::PUT, ["buckets", arn, "metrics"]) => self.put_bucket_metrics(arn, true).await,
            (&M::GET, ["buckets", arn, "metrics"]) => self.get_bucket_metrics(arn).await,
            (&M::DELETE, ["buckets", arn, "metrics"]) => self.put_bucket_metrics(arn, false).await,
            (&M::PUT | &M::GET, ["buckets", _, "logging"]) => {
                Err(not_implemented("server access logging"))
            }
            (&M::PUT, ["namespaces", arn]) => self.create_namespace(arn, &input).await,
            (&M::GET, ["namespaces", arn]) => self.list_namespaces(arn, query).await,
            (&M::GET, ["namespaces", arn, namespace]) => self.get_namespace(arn, namespace).await,
            (&M::DELETE, ["namespaces", arn, namespace]) => {
                self.delete_namespace(arn, namespace).await
            }
            (&M::PUT, ["tables", arn, namespace]) => {
                self.create_table(arn, namespace, &input).await
            }
            (&M::GET, ["tables", arn]) => self.list_tables(arn, query).await,
            (&M::DELETE, ["tables", arn, namespace, name]) => {
                self.delete_table(arn, namespace, name, q("versionToken"))
                    .await
            }
            (&M::PUT, ["tables", arn, namespace, name, "rename"]) => {
                self.rename_table(arn, namespace, name, &input).await
            }
            (&M::GET, ["tables", arn, namespace, name, "metadata-location"]) => {
                self.get_metadata_location(arn, namespace, name).await
            }
            (&M::PUT, ["tables", arn, namespace, name, "metadata-location"]) => {
                self.update_metadata_location(arn, namespace, name, &input)
                    .await
            }
            (&M::PUT, ["tables", arn, namespace, name, "policy"]) => {
                self.put_table_policy(arn, namespace, name, &input).await
            }
            (&M::GET, ["tables", arn, namespace, name, "policy"]) => {
                self.get_table_policy(arn, namespace, name).await
            }
            (&M::DELETE, ["tables", arn, namespace, name, "policy"]) => {
                self.delete_table_policy(arn, namespace, name).await
            }
            (&M::GET, ["tables", arn, namespace, name, "encryption"]) => {
                self.get_table_encryption(arn, namespace, name).await
            }
            (&M::GET, ["tables", arn, namespace, name, "storage-class"]) => {
                self.get_table_storage_class(arn, namespace, name).await
            }
            (&M::GET, ["tables", arn, namespace, name, "maintenance"]) => {
                self.get_table_maintenance(arn, namespace, name).await
            }
            (&M::PUT, ["tables", arn, namespace, name, "maintenance", kind]) => {
                self.put_table_maintenance(arn, namespace, name, kind, &input)
                    .await
            }
            (&M::GET, ["tables", arn, namespace, name, "maintenance-job-status"]) => {
                self.get_table_maintenance_status(arn, namespace, name)
                    .await
            }
            (&M::GET, ["get-table"]) => self.get_table(query).await,
            (&M::POST, ["tag", arn]) => self.tag_resource(arn, &input).await,
            (&M::DELETE, ["tag", arn]) => self.untag_resource(arn, query).await,
            (&M::GET, ["tag", arn]) => self.list_tags(arn).await,
            (
                &M::PUT | &M::GET | &M::DELETE,
                ["table-bucket-replication" | "table-replication" | "replication-status"],
            ) => Err(not_implemented("replication")),
            (
                &M::PUT | &M::GET,
                ["table-record-expiration" | "table-record-expiration-job-status"],
            ) => Err(error(
                StatusCode::METHOD_NOT_ALLOWED,
                "MethodNotAllowedException",
                "Record expiration is only supported for AWS managed tables.",
            )),
            (
                _,
                [
                    "start-table-migration"
                    | "sync-table-migration"
                    | "get-table-migration"
                    | "list-table-migrations"
                    | "update-table-migration"
                    | "complete-table-migration",
                ],
            ) => Err(not_implemented("table migrations")),
            _ => Err(error(
                StatusCode::NOT_FOUND,
                "UnknownOperationException",
                format!("No S3 Tables operation is {method} {path}."),
            )),
        }
    }

    /// ListTagsForResource, TagResource, UntagResource: the resource an
    /// ARN names, and whether it's a table.
    async fn tagged(
        &mut self,
        arn: &str,
        action: &'static str,
        extra: &Context,
    ) -> Result<(TableBucket, Option<Table>)> {
        match names::parse_arn(arn).map_err(bad_request)? {
            Some(names::Arn::Bucket { .. }) => {
                let bucket = self.checked_bucket(arn, action, extra).await?;
                Ok((bucket, None))
            }
            Some(names::Arn::Table {
                account,
                bucket: name,
                id,
            }) => {
                let bucket = TableBucket::load(&self.client, &account, &name).await?;
                let table = match (&bucket, Uuid::parse_str(&id)) {
                    (Some(bucket), Ok(id)) => Table::by_id(&self.client, bucket.id, id).await?,
                    _ => None,
                };
                match (bucket, table) {
                    (Some(bucket), Some(table)) => {
                        self.check(
                            action,
                            &Target::Table {
                                bucket: &bucket,
                                table: &table,
                            },
                            extra,
                        )?;
                        Ok((bucket, Some(table)))
                    }
                    (bucket, _) => {
                        self.check(
                            action,
                            &Target::Bucket {
                                account: &account,
                                name: &name,
                                bucket: bucket.as_ref(),
                                namespace: None,
                            },
                            extra,
                        )?;
                        Err(not_found("The specified resource does not exist."))
                    }
                }
            }
            None => Err(not_found("The specified resource does not exist.")),
        }
    }

    async fn list_tags(&mut self, arn: &str) -> Result<Answer> {
        let (bucket, table) = self
            .tagged(arn, "s3tables:ListTagsForResource", &Context::default())
            .await?;
        let tags = match &table {
            Some(table) => &table.tags,
            None => &bucket.tags,
        };
        Ok(Answer::Json(json!({ "tags": tags.json() })))
    }

    async fn tag_resource(&mut self, arn: &str, input: &Input) -> Result<Answer> {
        if input.get("tags").is_none() {
            return Err(bad_request("tags is required."));
        }
        let tags = Tags::from_input(input)?;
        let mut extra = Context::default();
        tags.set_request_context(&mut extra);
        let (bucket, table) = self.tagged(arn, "s3tables:TagResource", &extra).await?;
        let merged = match &table {
            Some(table) => table.tags.merged(&tags),
            None => bucket.tags.merged(&tags),
        };
        merged.limit()?;
        self.store_tags(&bucket, table.as_ref(), &merged).await?;
        Ok(Answer::Json(json!({})))
    }

    async fn untag_resource(&mut self, arn: &str, query: &str) -> Result<Answer> {
        let keys: Vec<String> = query
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .filter(|(k, _)| *k == "tagKeys")
            .map(|(_, v)| decode_path_param(&v.replace('+', " ")))
            .collect();
        if keys.is_empty() {
            return Err(bad_request("tagKeys is required."));
        }
        let mut extra = Context::default();
        extra.set_all("aws:TagKeys", keys.clone());
        let (bucket, table) = self.tagged(arn, "s3tables:UntagResource", &extra).await?;
        let tags = match &table {
            Some(table) => &table.tags,
            None => &bucket.tags,
        };
        let left = Tags(
            tags.0
                .iter()
                .filter(|(k, _)| !keys.contains(k))
                .cloned()
                .collect(),
        );
        self.store_tags(&bucket, table.as_ref(), &left).await?;
        Ok(Answer::NoContent)
    }

    async fn store_tags(
        &self,
        bucket: &TableBucket,
        table: Option<&Table>,
        tags: &Tags,
    ) -> Result<()> {
        let stored = tags.stored();
        match table {
            Some(table) => {
                self.client
                    .execute_cached(
                        "UPDATE tables SET tags = $2 WHERE id = $1",
                        &[&table.id, &stored],
                    )
                    .await?
            }
            None => {
                self.client
                    .execute_cached(
                        "UPDATE table_buckets SET tags = $2 WHERE id = $1",
                        &[&bucket.id, &stored],
                    )
                    .await?
            }
        };
        Ok(())
    }
}

/// A resource policy a request gives (`resourcePolicy`), checked as one of
/// `arn`'s (a table bucket's or a table's): S3 Tables' 400 if it isn't
/// one, and its 403 if it would make the resource public, which S3 Tables
/// blocks.
fn checked_policy(input: &Input, arn: &str) -> Result<String> {
    let text = input.required("resourcePolicy")?;
    if text.is_empty() || text.len() > MAX_POLICY {
        return Err(bad_request(format!(
            "The resource policy must be 1 to {MAX_POLICY} characters."
        )));
    }
    let policy = Policy::parse(text, Kind::Tables(arn)).map_err(|e| bad_request(e.message))?;
    if policy.is_public() {
        return Err(error(
            StatusCode::FORBIDDEN,
            "AccessDeniedException",
            "Access denied: the policy would make the resource public, which S3 Tables blocks.",
        ));
    }
    Ok(text.to_owned())
}

/// An encryption configuration a request gives (`encryptionConfiguration`,
/// if it does): its algorithm and KMS key ARN.
fn encryption_of(input: &Input) -> Result<Option<(String, Option<String>)>> {
    let Some(config) = input.object("encryptionConfiguration")? else {
        return Ok(None);
    };
    let algorithm = config.required("sseAlgorithm")?;
    let key = config.str("kmsKeyArn")?;
    match (algorithm, key) {
        ("AES256", None) => Ok(Some(("AES256".into(), None))),
        ("AES256", Some(_)) => Err(bad_request(
            "A KMS key ARN may only be given with the aws:kms algorithm.",
        )),
        ("aws:kms", Some(key)) => {
            let valid = key
                .split(':')
                .collect::<Vec<_>>()
                .get(..6)
                .is_some_and(|p| {
                    p[0] == "arn"
                        && p[1].starts_with("aws")
                        && p[2] == "kms"
                        && p[5].starts_with("key/")
                        && p[5].len() > 4
                });
            if !valid {
                return Err(bad_request(format!("The KMS key ARN is not valid: {key}")));
            }
            Ok(Some(("aws:kms".into(), Some(key.to_owned()))))
        }
        ("aws:kms", None) => Err(bad_request(
            "A KMS key ARN is required with the aws:kms algorithm.",
        )),
        (other, _) => Err(bad_request(format!(
            "The encryption algorithm is not valid: {other}"
        ))),
    }
}

fn encryption_json(algorithm: &str, key: Option<&str>) -> Value {
    let mut config = json!({ "sseAlgorithm": algorithm });
    if let Some(key) = key {
        config["kmsKeyArn"] = json!(key);
    }
    json!({ "encryptionConfiguration": config })
}

/// A storage class a request gives (`storageClassConfiguration`, if it
/// does).
fn storage_class_of(input: &Input) -> Result<Option<String>> {
    let Some(config) = input.object("storageClassConfiguration")? else {
        return Ok(None);
    };
    match config.required("storageClass")? {
        class @ ("STANDARD" | "INTELLIGENT_TIERING") => Ok(Some(class.to_owned())),
        other => Err(bad_request(format!(
            "The storage class is not valid: {other}"
        ))),
    }
}

/// The condition keys of an encryption configuration and a storage class
/// a request asks for.
fn configuration_context(
    encryption: Option<&(String, Option<String>)>,
    class: Option<&str>,
) -> Context {
    let mut context = Context::default();
    if let Some((algorithm, key)) = encryption {
        context.set("s3tables:SSEAlgorithm", algorithm);
        if let Some(key) = key {
            context.set("s3tables:KMSKeyArn", key);
        }
    }
    if let Some(class) = class {
        context.set("s3tables:StorageClass", class);
    }
    context
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_signed_encoded_again() {
        assert_eq!(
            double_encoded(
                "/buckets/arn%3Aaws%3As3tables%3Aus-east-1%3A111122223333%3Abucket%2Fdata"
            ),
            "/buckets/arn%253Aaws%253As3tables%253Aus-east-1%253A111122223333%253Abucket%252Fdata"
        );
        assert_eq!(double_encoded("/get-table"), "/get-table");
    }

    #[test]
    fn keys() {
        assert!(evaluated_key("s3tables:namespace"));
        assert!(evaluated_key("s3tables:tablebuckettag/team"));
        assert!(!evaluated_key("s3tables:tablebuckettag/"));
        assert!(!evaluated_key("s3tables:other"));
    }

    #[test]
    fn tags() {
        let input = Input::parse(br#"{"tags":{"team":"data","env":"prod"}}"#).unwrap();
        let tags = Tags::from_input(&input).unwrap();
        assert_eq!(tags.0.len(), 2);
        let merged = tags.merged(&Tags(vec![("team".into(), "ml".into())]));
        let mut stored = Tags::from_stored(merged.stored().as_deref()).0;
        let mut expected = merged.0.clone();
        stored.sort();
        expected.sort();
        assert_eq!(stored, expected);
        assert!(merged.0.contains(&("team".to_owned(), "ml".to_owned())));
        let input = Input::parse(br#"{"tags":{"aws:x":"y"}}"#).unwrap();
        assert!(Tags::from_input(&input).is_err());
    }
}
