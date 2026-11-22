//! Kinesis Data Streams' API, on the S3 port: requests signed for the
//! `kinesis` service are these, whatever their path, as KMS's are (see
//! `kms::api`). Its JSON protocol (`X-Amz-Target: Kinesis_20131202.<Operation>`,
//! JSON 1.1; not CBOR, which the AWS SDK for Java uses by default:
//! `AWS_CBOR_DISABLE=true` turns it off), its errors.
//!
//! Streams in provisioned mode (on-demand ones are made with 4 shards, and
//! described as provisioned), their records (see `streams`), and their
//! retention. Not (yet): resharding (`UpdateShardCount`, `SplitShard`,
//! `MergeShards`), enhanced fan-out (`RegisterStreamConsumer`,
//! `SubscribeToShard`), tags, server-side encryption with a stream's own
//! KMS key, resource policies.
//!
//! A request acts as its signer, as Kinesis's own actions
//! (`kinesis:PutRecord`, on the stream's ARN; `kinesis:ListStreams` on
//! `*`), by its identity policies, on its own account's streams only.
//! Calls that only manage streams are recorded in the audit log, as
//! CloudTrail records Kinesis's management events; those of records
//! (`PutRecord(s)`, `GetShardIterator`, `GetRecords`) aren't: they're
//! CloudTrail's data events, which Cairn doesn't record (yet).

use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode, body::Bytes};
use md5::Digest;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::{Failed, MAX_DATA, MAX_KEY, Record};
use crate::{
    App, audit,
    auth::Signed,
    db::Cached,
    policy::Verdict,
    s3::{
        access::{Access, Origin},
        actions::{Check, On},
    },
    users::{self, Principal},
};

/// The most a request's body may hold: PutRecords' 5 MiB of records, in
/// base64, with room for their keys.
const MAX_BODY: usize = 8 * 1024 * 1024;
/// What every operation's target starts with.
const TARGET: &str = "Kinesis_20131202.";
/// The service Kinesis's events are of.
const SOURCE: &str = "kinesis.amazonaws.com";
/// The type of the resource a stream is, in events.
const STREAM_TYPE: &str = "AWS::Kinesis::Stream";
/// The most shards a stream may have.
const MAX_SHARDS: i32 = 1000;
/// The shards an on-demand stream is made with.
const ON_DEMAND_SHARDS: i32 = 4;
/// The most records PutRecords takes.
const MAX_PUT_RECORDS: usize = 500;
/// The most bytes (data and keys) PutRecords takes.
const MAX_PUT_BYTES: usize = 5 * 1024 * 1024;
/// The most records GetRecords returns.
const MAX_GET_RECORDS: usize = 10_000;
/// The most bytes of data GetRecords returns.
const MAX_GET_BYTES: usize = 10 * 1024 * 1024;
/// How long a shard iterator is good for.
const ITERATOR_MILLIS: i64 = 5 * 60 * 1000;
/// The shortest and longest retention, in hours.
const RETENTION: std::ops::RangeInclusive<i64> = 24..=8760;

/// Whether a request signed so is Kinesis's.
pub fn wants(signed: &Signed) -> bool {
    signed.service == "kinesis"
}

/// A failed request: its status, Kinesis's type for it, and a message.
#[derive(Debug)]
pub struct Error {
    status: StatusCode,
    kind: &'static str,
    message: String,
}

fn bad(kind: &'static str, message: impl Into<String>) -> Error {
    Error {
        status: StatusCode::BAD_REQUEST,
        kind,
        message: message.into(),
    }
}

fn invalid(message: impl Into<String>) -> Error {
    bad("InvalidArgumentException", message)
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Error {
        eprintln!("kinesis: request failed: {e:#}");
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            kind: "InternalFailure",
            message: "internal error; the node's log has the details".to_owned(),
        }
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

type Result<T> = std::result::Result<T, Error>;

/// The operations Cairn has, and whether each only reads; `None`: a data
/// event, which isn't recorded.
const OPERATIONS: &[(&str, Option<bool>)] = &[
    ("CreateStream", Some(false)),
    ("DeleteStream", Some(false)),
    ("ListStreams", Some(true)),
    ("DescribeStream", Some(true)),
    ("DescribeStreamSummary", Some(true)),
    ("ListShards", Some(true)),
    ("IncreaseStreamRetentionPeriod", Some(false)),
    ("DecreaseStreamRetentionPeriod", Some(false)),
    ("PutRecord", None),
    ("PutRecords", None),
    ("GetShardIterator", None),
    ("GetRecords", None),
];

/// A Kinesis request, on the S3 port.
pub async fn handle(
    app: &Arc<App>,
    req: Request<crate::listen::ClientBody>,
    signed: Signed,
    peer: IpAddr,
) -> Response<Full<Bytes>> {
    let request_id = Uuid::new_v4().to_string();
    let (status, body) = match respond(app, req, &signed, peer, &request_id).await {
        Ok(answer) => (StatusCode::OK, answer.to_string()),
        Err(e) => (
            e.status,
            json!({ "__type": e.kind, "message": e.message }).to_string(),
        ),
    };
    Response::builder()
        .status(status)
        .header("content-type", "application/x-amz-json-1.1")
        .header("x-amzn-requestid", request_id)
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

async fn respond(
    app: &Arc<App>,
    req: Request<crate::listen::ClientBody>,
    signed: &Signed,
    peer: IpAddr,
    request_id: &str,
) -> Result<Value> {
    let (parts, body) = req.into_parts();
    if parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|t| t.contains("cbor"))
    {
        return Err(bad(
            "SerializationException",
            "Cairn's Kinesis speaks JSON only; set AWS_CBOR_DISABLE=true",
        ));
    }
    let body = Limited::new(body, MAX_BODY)
        .collect()
        .await
        .map_err(|_| {
            bad(
                "SerializationException",
                "the request's body is too large, or broken",
            )
        })?
        .to_bytes();
    let target = parts
        .headers
        .get("x-amz-target")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let operation = target
        .strip_prefix(TARGET)
        .ok_or_else(|| {
            bad(
                "UnknownOperationException",
                format!("No such operation: {target}"),
            )
        })?
        .to_owned();
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
            return Err(bad(
                "ExpiredTokenException",
                "The security token included in the request is expired",
            ));
        }
        Err(_) => {
            return Err(bad(
                "UnrecognizedClientException",
                "The security token included in the request is invalid.",
            ));
        }
    };
    drop(client);
    crate::auth::verify_sigv4_with_body(
        parts.method.as_str(),
        parts.uri.path(),
        parts.uri.query().unwrap_or(""),
        &parts.headers,
        &principal.secret,
        &body,
    )
    .map_err(|r| {
        bad(
            if r.code == "SignatureDoesNotMatch" {
                "InvalidSignatureException"
            } else {
                "IncompleteSignature"
            },
            r.message,
        )
    })?;
    let Some(&(_, recorded)) = OPERATIONS.iter().find(|(name, _)| *name == operation) else {
        return Err(bad(
            "UnknownOperationException",
            format!("Cairn doesn't have Kinesis's {operation} yet"),
        ));
    };
    let params: Value = match body.is_empty() {
        true => Value::Object(Map::new()),
        false => serde_json::from_slice(&body)
            .map_err(|_| bad("SerializationException", "the request's body isn't JSON"))?,
    };
    let Value::Object(params) = params else {
        return Err(bad(
            "SerializationException",
            "the request's body isn't a JSON object",
        ));
    };
    let origin = Origin {
        peer: Some(peer),
        trusted_proxies: &app.trusted_proxies,
        signed: Some(signed),
        form: false,
    };
    let access = Access::new(
        Some(&principal),
        &principal.account,
        &parts.method,
        &parts.headers,
        "",
        &origin,
    )?;
    let api = Api {
        app,
        principal: &principal,
        access: &access,
        params: &params,
        touched: Mutex::default(),
    };
    let result = api.dispatch(&operation).await;
    let Some(read_only) = recorded else {
        return result;
    };
    let mut event = audit::Event::of_request(
        SOURCE,
        &operation,
        &principal,
        &signed.access_key,
        &parts.headers,
        peer,
        &app.trusted_proxies,
        request_id,
        read_only,
    );
    event.parameters = audit::parameters(&params, &[], &[]);
    for resource in api.touched.into_inner().unwrap_or_else(|e| e.into_inner()) {
        event.touch(resource);
    }
    if let Err(e) = &result {
        event.error = Some((e.kind.to_owned(), e.message.clone()));
    }
    // A request whose record can't be logged fails.
    app.audit
        .record(&event)
        .await
        .map_err(|e| Error::from(anyhow::Error::new(e)))?;
    result
}

/// A stream, as the database has it.
struct Stream {
    id: Uuid,
    name: String,
    shards: i32,
    retention_hours: i32,
    created: SystemTime,
}

impl Stream {
    fn from_row(row: &tokio_postgres::Row) -> Stream {
        Stream {
            id: row.get("id"),
            name: row.get("name"),
            shards: row.get("shard_count"),
            retention_hours: row.get("retention_hours"),
            created: row.get("created_at"),
        }
    }
}

/// A stream's ARN.
pub fn arn(account: &str, name: &str) -> String {
    format!(
        "arn:aws:kinesis:{}:{account}:stream/{name}",
        crate::s3::buckets::head::REGION
    )
}

/// Whether `name` can be a stream's: 1 to 128 letters, digits, `_`, `-`
/// and `.`.
fn valid_name(name: &str) -> bool {
    (1..=128).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// The shard IDs' form.
fn shard_id(shard: i32) -> String {
    format!("shardId-{shard:012}")
}

/// The shard a shard ID names, if it's one of `count`.
fn parse_shard_id(id: &str, count: i32) -> Option<i32> {
    let n: i32 = id.strip_prefix("shardId-")?.parse().ok()?;
    (0..count).contains(&n).then_some(n)
}

/// The hash keys of `count` shards: each an even part of the 128-bit
/// space, the last up to its end.
fn hash_range(shard: i32, count: i32) -> (u128, u128) {
    let size = u128::MAX / count as u128;
    let start = shard as u128 * size;
    let end = match shard == count - 1 {
        true => u128::MAX,
        false => start + size - 1,
    };
    (start, end)
}

/// The shard of `count` that a hash key falls in.
fn shard_of(hash: u128, count: i32) -> i32 {
    ((hash / (u128::MAX / count as u128)) as i32).min(count - 1)
}

/// A partition key's hash key: its MD5, as Kinesis hashes it.
fn hash_key(key: &str) -> u128 {
    u128::from_be_bytes(md5::Md5::digest(key.as_bytes()).into())
}

/// Seconds since the epoch, as Kinesis's timestamps are.
fn seconds(time: SystemTime) -> f64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as f64 / 1000.0)
        .unwrap_or(0.0)
}

/// A position in a shard, as GetShardIterator hands it out.
#[derive(Debug, PartialEq, Eq)]
struct Position {
    stream: Uuid,
    shard: i32,
    sequence: i64,
    /// When it was handed out, in milliseconds since the epoch.
    issued: i64,
}

impl Position {
    fn encode(&self) -> String {
        STANDARD.encode(format!(
            "1:{}:{}:{}:{}",
            self.stream, self.shard, self.sequence, self.issued
        ))
    }

    fn decode(token: &str) -> Option<Position> {
        let text = String::from_utf8(STANDARD.decode(token).ok()?).ok()?;
        let mut parts = text.split(':');
        if parts.next()? != "1" {
            return None;
        }
        let iterator = Position {
            stream: parts.next()?.parse().ok()?,
            shard: parts.next()?.parse().ok()?,
            sequence: parts.next()?.parse().ok()?,
            issued: parts.next()?.parse().ok()?,
        };
        parts.next().is_none().then_some(iterator)
    }
}

/// A request, as its signer makes it.
struct Api<'a> {
    app: &'a Arc<App>,
    principal: &'a Principal,
    access: &'a Access,
    params: &'a Map<String, Value>,
    /// The resources (streams) it's about, for its event.
    touched: Mutex<Vec<audit::Resource>>,
}

impl Api<'_> {
    async fn dispatch(&self, operation: &str) -> Result<Value> {
        match operation {
            "CreateStream" => self.create_stream().await,
            "DeleteStream" => self.delete_stream().await,
            "ListStreams" => self.list_streams().await,
            "DescribeStream" => self.describe_stream().await,
            "DescribeStreamSummary" => self.describe_stream_summary().await,
            "ListShards" => self.list_shards().await,
            "IncreaseStreamRetentionPeriod" => self.set_retention(true).await,
            "DecreaseStreamRetentionPeriod" => self.set_retention(false).await,
            "PutRecord" => self.put_record().await,
            "PutRecords" => self.put_records().await,
            "GetShardIterator" => self.get_shard_iterator().await,
            "GetRecords" => self.get_records().await,
            other => Err(bad(
                "UnknownOperationException",
                format!("Cairn doesn't have Kinesis's {other} yet"),
            )),
        }
    }

    /// Refuses the request unless the identity policies allow `action` on
    /// `on`.
    fn check_on(&self, action: &'static str, on: On) -> Result<()> {
        let resource = on.arn();
        let check = Check { action, on };
        let verdict = self.access.verdict(&check);
        if verdict == Verdict::Allow {
            return Ok(());
        }
        Err(bad(
            "AccessDeniedException",
            format!(
                "User: {} is not authorized to perform: {action} on resource: {resource} {}",
                self.principal.arn(),
                verdict.why(action, self.access.boundary())
            ),
        ))
    }

    fn string(&self, name: &str) -> Result<Option<&str>> {
        match self.params.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s)),
            Some(_) => Err(bad(
                "SerializationException",
                format!("{name} must be a string"),
            )),
        }
    }

    fn integer(&self, name: &str) -> Result<Option<i64>> {
        match self.params.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Number(n)) => n.as_i64().map(Some).ok_or_else(|| {
                bad(
                    "SerializationException",
                    format!("{name} must be an integer"),
                )
            }),
            Some(_) => Err(bad(
                "SerializationException",
                format!("{name} must be an integer"),
            )),
        }
    }

    /// The name of the caller's stream that `StreamName` or `StreamARN`
    /// names, checked against `action` on it.
    fn stream_name(&self, action: &'static str) -> Result<String> {
        let name = match (self.string("StreamName")?, self.string("StreamARN")?) {
            (Some(name), None) => name.to_owned(),
            (None, Some(given)) => {
                let prefix = format!(
                    "arn:aws:kinesis:{}:{}:stream/",
                    crate::s3::buckets::head::REGION,
                    self.principal.account
                );
                match given.strip_prefix(&prefix) {
                    Some(name) => name.to_owned(),
                    None => {
                        return Err(invalid(format!(
                            "{given} isn't the ARN of a stream of account {} in {}",
                            self.principal.account,
                            crate::s3::buckets::head::REGION
                        )));
                    }
                }
            }
            (Some(_), Some(_)) => {
                return Err(invalid("give StreamName or StreamARN, not both"));
            }
            (None, None) => return Err(invalid("StreamName or StreamARN is required")),
        };
        if !valid_name(&name) {
            return Err(bad(
                "ValidationException",
                format!(
                    "{name:?} isn't a stream's name: 1 to 128 letters, digits, '_', '-' and '.'"
                ),
            ));
        }
        let arn = arn(&self.principal.account, &name);
        self.touched
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(audit::Resource {
                arn: arn.clone(),
                account: self.principal.account.clone(),
                kind: STREAM_TYPE,
            });
        self.check_on(action, On::Arn(arn))?;
        Ok(name)
    }

    /// The caller's stream named so.
    async fn stream(&self, name: &str) -> Result<Stream> {
        let row = self
            .app
            .pool
            .get()
            .await?
            .query_opt_cached(
                "SELECT id, name, shard_count, retention_hours, created_at FROM streams
                 WHERE account_id = $1 AND name = $2",
                &[&self.principal.account, &name],
            )
            .await?;
        match row {
            Some(row) => Ok(Stream::from_row(&row)),
            None => Err(not_found(&self.principal.account, name)),
        }
    }

    async fn create_stream(&self) -> Result<Value> {
        let name = self.stream_name("kinesis:CreateStream")?;
        let mode = self
            .params
            .get("StreamModeDetails")
            .and_then(|m| m.get("StreamMode"))
            .and_then(Value::as_str)
            .unwrap_or("PROVISIONED");
        let shards = match (mode, self.integer("ShardCount")?) {
            ("ON_DEMAND", None) => ON_DEMAND_SHARDS as i64,
            ("ON_DEMAND", Some(_)) => {
                return Err(invalid("ShardCount isn't given for an on-demand stream"));
            }
            ("PROVISIONED", Some(n)) => n,
            ("PROVISIONED", None) => {
                return Err(invalid("ShardCount is required for a provisioned stream"));
            }
            (other, _) => return Err(invalid(format!("{other} isn't a stream mode"))),
        };
        if !(1..=MAX_SHARDS as i64).contains(&shards) {
            return Err(invalid(format!(
                "ShardCount must be from 1 to {MAX_SHARDS}"
            )));
        }
        let mut client = self.app.pool.get().await?;
        let tx = client.transaction().await?;
        let id = Uuid::now_v7();
        let inserted = tx
            .execute_cached(
                "INSERT INTO streams (id, account_id, name, shard_count) VALUES ($1, $2, $3, $4)
                 ON CONFLICT (account_id, name) DO NOTHING",
                &[&id, &self.principal.account, &name, &(shards as i32)],
            )
            .await?;
        if inserted == 0 {
            return Err(bad(
                "ResourceInUseException",
                format!(
                    "Stream {name} under account {} already exists.",
                    self.principal.account
                ),
            ));
        }
        tx.execute_cached(
            "INSERT INTO stream_shards (stream_id, shard) SELECT $1, generate_series(0, $2 - 1)",
            &[&id, &(shards as i32)],
        )
        .await?;
        tx.commit().await?;
        Ok(json!({}))
    }

    async fn delete_stream(&self) -> Result<Value> {
        let name = self.stream_name("kinesis:DeleteStream")?;
        let deleted: bool = self
            .app
            .pool
            .get()
            .await?
            .query_one_cached(
                "SELECT pg_temp.cairn_stream_delete($1, $2)",
                &[&self.principal.account, &name],
            )
            .await?
            .get(0);
        match deleted {
            true => Ok(json!({})),
            false => Err(not_found(&self.principal.account, &name)),
        }
    }

    async fn list_streams(&self) -> Result<Value> {
        self.check_on("kinesis:ListStreams", On::Account)?;
        let limit = self.integer("Limit")?.unwrap_or(100).clamp(1, 10_000);
        let after = match self.string("NextToken")? {
            Some(token) => Some(
                String::from_utf8(
                    STANDARD
                        .decode(token)
                        .map_err(|_| invalid("bad NextToken"))?,
                )
                .map_err(|_| invalid("bad NextToken"))?,
            ),
            None => self.string("ExclusiveStartStreamName")?.map(str::to_owned),
        };
        let rows = self
            .app
            .pool
            .get()
            .await?
            .query_cached(
                "SELECT id, name, shard_count, retention_hours, created_at FROM streams
                 WHERE account_id = $1 AND ($2::text IS NULL OR name > $2)
                 ORDER BY name LIMIT $3",
                &[&self.principal.account, &after, &(limit + 1)],
            )
            .await?;
        let more = rows.len() as i64 > limit;
        let streams: Vec<Stream> = rows
            .iter()
            .take(limit as usize)
            .map(Stream::from_row)
            .collect();
        let mut answer = json!({
            "StreamNames": streams.iter().map(|s| s.name.clone()).collect::<Vec<_>>(),
            "HasMoreStreams": more,
            "StreamSummaries": streams.iter().map(|s| json!({
                "StreamName": s.name,
                "StreamARN": arn(&self.principal.account, &s.name),
                "StreamStatus": "ACTIVE",
                "StreamModeDetails": { "StreamMode": "PROVISIONED" },
                "StreamCreationTimestamp": seconds(s.created),
            })).collect::<Vec<_>>(),
        });
        if more && let Some(last) = streams.last() {
            answer["NextToken"] = json!(STANDARD.encode(&last.name));
        }
        Ok(answer)
    }

    fn shards_of(&self, stream: &Stream, from: i32) -> Vec<Value> {
        (from..stream.shards)
            .map(|shard| {
                let (start, end) = hash_range(shard, stream.shards);
                json!({
                    "ShardId": shard_id(shard),
                    "HashKeyRange": {
                        "StartingHashKey": start.to_string(),
                        "EndingHashKey": end.to_string(),
                    },
                    "SequenceNumberRange": { "StartingSequenceNumber": "0" },
                })
            })
            .collect()
    }

    async fn describe_stream(&self) -> Result<Value> {
        let name = self.stream_name("kinesis:DescribeStream")?;
        let stream = self.stream(&name).await?;
        let from = match self.string("ExclusiveStartShardId")? {
            Some(id) => parse_shard_id(id, stream.shards).map_or(stream.shards, |n| n + 1),
            None => 0,
        };
        let limit = self.integer("Limit")?.unwrap_or(100).clamp(1, 10_000) as usize;
        let shards = self.shards_of(&stream, from);
        let more = shards.len() > limit;
        Ok(json!({
            "StreamDescription": {
                "StreamName": stream.name,
                "StreamARN": arn(&self.principal.account, &stream.name),
                "StreamStatus": "ACTIVE",
                "StreamModeDetails": { "StreamMode": "PROVISIONED" },
                "Shards": shards.into_iter().take(limit).collect::<Vec<_>>(),
                "HasMoreShards": more,
                "RetentionPeriodHours": stream.retention_hours,
                "StreamCreationTimestamp": seconds(stream.created),
                "EnhancedMonitoring": [{ "ShardLevelMetrics": [] }],
                "EncryptionType": "NONE",
            }
        }))
    }

    async fn describe_stream_summary(&self) -> Result<Value> {
        let name = self.stream_name("kinesis:DescribeStreamSummary")?;
        let stream = self.stream(&name).await?;
        Ok(json!({
            "StreamDescriptionSummary": {
                "StreamName": stream.name,
                "StreamARN": arn(&self.principal.account, &stream.name),
                "StreamStatus": "ACTIVE",
                "StreamModeDetails": { "StreamMode": "PROVISIONED" },
                "RetentionPeriodHours": stream.retention_hours,
                "StreamCreationTimestamp": seconds(stream.created),
                "EnhancedMonitoring": [{ "ShardLevelMetrics": [] }],
                "EncryptionType": "NONE",
                "OpenShardCount": stream.shards,
                "ConsumerCount": 0,
            }
        }))
    }

    async fn list_shards(&self) -> Result<Value> {
        // A NextToken carries its stream: it's given alone.
        let (name, from) = match self.string("NextToken")? {
            Some(token) => {
                let text = STANDARD
                    .decode(token)
                    .ok()
                    .and_then(|t| String::from_utf8(t).ok())
                    .ok_or_else(|| invalid("bad NextToken"))?;
                let (name, from) = text
                    .rsplit_once(':')
                    .ok_or_else(|| invalid("bad NextToken"))?;
                let from: i32 = from.parse().map_err(|_| invalid("bad NextToken"))?;
                if !valid_name(name) {
                    return Err(invalid("bad NextToken"));
                }
                let arn = arn(&self.principal.account, name);
                self.check_on("kinesis:ListShards", On::Arn(arn))?;
                (name.to_owned(), from)
            }
            None => {
                let name = self.stream_name("kinesis:ListShards")?;
                let from = match self.string("ExclusiveStartShardId")? {
                    Some(id) => id
                        .strip_prefix("shardId-")
                        .and_then(|n| n.parse::<i32>().ok())
                        .map_or(0, |n| n + 1),
                    None => 0,
                };
                (name, from)
            }
        };
        let stream = self.stream(&name).await?;
        let limit = self.integer("MaxResults")?.unwrap_or(1000).clamp(1, 10_000) as usize;
        let shards = self.shards_of(&stream, from.max(0));
        let more = shards.len() > limit;
        let mut answer = json!({
            "Shards": shards.into_iter().take(limit).collect::<Vec<_>>(),
        });
        if more {
            answer["NextToken"] =
                json!(STANDARD.encode(format!("{}:{}", stream.name, from.max(0) + limit as i32)));
        }
        Ok(answer)
    }

    async fn set_retention(&self, increase: bool) -> Result<Value> {
        let action = match increase {
            true => "kinesis:IncreaseStreamRetentionPeriod",
            false => "kinesis:DecreaseStreamRetentionPeriod",
        };
        let name = self.stream_name(action)?;
        let hours = self
            .integer("RetentionPeriodHours")?
            .ok_or_else(|| invalid("RetentionPeriodHours is required"))?;
        if !RETENTION.contains(&hours) {
            return Err(invalid(format!(
                "RetentionPeriodHours must be from {} to {}",
                RETENTION.start(),
                RETENTION.end()
            )));
        }
        let hours = hours as i32;
        let stream = self.stream(&name).await?;
        if increase && hours < stream.retention_hours {
            return Err(invalid(format!(
                "Requested retention period ({hours} hours) for stream {name} can not be shorter \
                 than existing retention period ({} hours). Use DecreaseRetentionPeriod API.",
                stream.retention_hours
            )));
        }
        if !increase && hours > stream.retention_hours {
            return Err(invalid(format!(
                "Requested retention period ({hours} hours) for stream {name} can not be longer \
                 than existing retention period ({} hours). Use IncreaseRetentionPeriod API.",
                stream.retention_hours
            )));
        }
        self.app
            .pool
            .get()
            .await?
            .execute_cached(
                "UPDATE streams SET retention_hours = $2 WHERE id = $1",
                &[&stream.id, &hours],
            )
            .await?;
        Ok(json!({}))
    }

    /// A record as PutRecord or PutRecords' entries give it, and the shard
    /// it goes to.
    fn record_of(entry: &Map<String, Value>, shards: i32) -> Result<(i32, Record)> {
        let key = match entry.get("PartitionKey") {
            Some(Value::String(k)) if !k.is_empty() && k.chars().count() <= MAX_KEY => k.clone(),
            _ => {
                return Err(invalid(format!(
                    "PartitionKey is required: 1 to {MAX_KEY} characters"
                )));
            }
        };
        let data = match entry.get("Data") {
            Some(Value::String(d)) => STANDARD
                .decode(d)
                .map_err(|_| bad("SerializationException", "Data isn't base64"))?,
            _ => return Err(invalid("Data is required")),
        };
        if data.len() > MAX_DATA {
            return Err(invalid(format!(
                "a record's Data must be at most {MAX_DATA} bytes"
            )));
        }
        let hash = match entry.get("ExplicitHashKey") {
            None | Some(Value::Null) => hash_key(&key),
            Some(Value::String(h)) => h
                .parse::<u128>()
                .map_err(|_| invalid(format!("ExplicitHashKey {h} isn't from 0 to 2^128 - 1")))?,
            Some(_) => return Err(invalid("ExplicitHashKey must be a string")),
        };
        Ok((shard_of(hash, shards), Record::new(key, data)))
    }

    async fn put_record(&self) -> Result<Value> {
        let name = self.stream_name("kinesis:PutRecord")?;
        let stream = self.stream(&name).await?;
        let (shard, record) = Self::record_of(self.params, stream.shards)?;
        let sequence = self
            .app
            .streams
            .append(self.app, stream.id, shard, vec![record])
            .await
            .map_err(|e| failed(e, &self.principal.account, &name))?;
        Ok(json!({
            "ShardId": shard_id(shard),
            "SequenceNumber": sequence.to_string(),
            "EncryptionType": "NONE",
        }))
    }

    async fn put_records(&self) -> Result<Value> {
        let name = self.stream_name("kinesis:PutRecords")?;
        let entries = match self.params.get("Records") {
            Some(Value::Array(entries)) if !entries.is_empty() => entries,
            _ => return Err(invalid("Records is required: 1 to 500 records")),
        };
        if entries.len() > MAX_PUT_RECORDS {
            return Err(invalid(format!(
                "Records must have at most {MAX_PUT_RECORDS} records"
            )));
        }
        let stream = self.stream(&name).await?;
        // Each shard's records, in their order, with their places in the
        // request.
        let mut shards: BTreeMap<i32, (Vec<usize>, Vec<Record>)> = BTreeMap::new();
        let mut total = 0;
        for (i, entry) in entries.iter().enumerate() {
            let Value::Object(entry) = entry else {
                return Err(bad("SerializationException", "a record must be an object"));
            };
            let (shard, record) = Self::record_of(entry, stream.shards)?;
            total += record.data.len() + record.key.len();
            let (places, records) = shards.entry(shard).or_default();
            places.push(i);
            records.push(record);
        }
        if total > MAX_PUT_BYTES {
            return Err(invalid(format!(
                "the records must add up to at most {MAX_PUT_BYTES} bytes"
            )));
        }
        let mut appends = tokio::task::JoinSet::new();
        for (shard, (places, records)) in shards {
            let app = self.app.clone();
            let id = stream.id;
            appends.spawn(async move {
                let outcome = app.streams.append(&app, id, shard, records).await;
                (shard, places, outcome)
            });
        }
        let mut results = vec![Value::Null; entries.len()];
        let mut failures = 0;
        let mut gone = false;
        for (shard, places, outcome) in appends.join_all().await {
            for (n, &i) in places.iter().enumerate() {
                results[i] = match outcome {
                    Ok(first) => json!({
                        "ShardId": shard_id(shard),
                        "SequenceNumber": (first + n as i64).to_string(),
                    }),
                    Err(e) => {
                        failures += 1;
                        gone |= e == Failed::Gone;
                        json!({
                            "ErrorCode": "InternalFailure",
                            "ErrorMessage": "Internal service failure.",
                        })
                    }
                };
            }
        }
        if gone {
            return Err(not_found(&self.principal.account, &name));
        }
        Ok(json!({
            "FailedRecordCount": failures,
            "Records": results,
            "EncryptionType": "NONE",
        }))
    }

    async fn get_shard_iterator(&self) -> Result<Value> {
        let name = self.stream_name("kinesis:GetShardIterator")?;
        let stream = self.stream(&name).await?;
        let given = self
            .string("ShardId")?
            .ok_or_else(|| invalid("ShardId is required"))?;
        let shard = parse_shard_id(given, stream.shards).ok_or_else(|| {
            bad(
                "ResourceNotFoundException",
                format!(
                    "Shard {given} in stream {name} under account {} does not exist",
                    self.principal.account
                ),
            )
        })?;
        let kind = self
            .string("ShardIteratorType")?
            .ok_or_else(|| invalid("ShardIteratorType is required"))?;
        let given_sequence = || -> Result<i64> {
            let s = self
                .string("StartingSequenceNumber")?
                .ok_or_else(|| invalid(format!("StartingSequenceNumber is required for {kind}")))?;
            s.parse::<i64>()
                .ok()
                .filter(|n| *n >= 0)
                .ok_or_else(|| invalid(format!("StartingSequenceNumber {s} isn't one")))
        };
        let sequence = match kind {
            "TRIM_HORIZON" => 0,
            "LATEST" => super::next_sequence(self.app, stream.id, shard).await?,
            "AT_SEQUENCE_NUMBER" | "AFTER_SEQUENCE_NUMBER" => {
                let n = given_sequence()?;
                let end = super::next_sequence(self.app, stream.id, shard).await?;
                if n >= end {
                    return Err(invalid(format!(
                        "StartingSequenceNumber {n} used in GetShardIterator on shard {given} \
                         in stream {name} under account {} is invalid because it did not come \
                         from this stream.",
                        self.principal.account
                    )));
                }
                n + (kind == "AFTER_SEQUENCE_NUMBER") as i64
            }
            "AT_TIMESTAMP" => {
                let at = match self.params.get("Timestamp") {
                    Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
                    _ => return Err(invalid("Timestamp is required for AT_TIMESTAMP")),
                };
                super::sequence_at(self.app, stream.id, shard, (at * 1000.0) as i64).await?
            }
            other => return Err(invalid(format!("{other} isn't a ShardIteratorType"))),
        };
        let iterator = Position {
            stream: stream.id,
            shard,
            sequence,
            issued: super::now_millis(),
        };
        Ok(json!({ "ShardIterator": iterator.encode() }))
    }

    async fn get_records(&self) -> Result<Value> {
        let token = self
            .string("ShardIterator")?
            .ok_or_else(|| invalid("ShardIterator is required"))?;
        let iterator = Position::decode(token).ok_or_else(|| invalid("ShardIterator isn't one"))?;
        let row = self
            .app
            .pool
            .get()
            .await?
            .query_opt_cached(
                "SELECT account_id, name FROM streams WHERE id = $1",
                &[&iterator.stream],
            )
            .await?;
        let Some(row) = row else {
            return Err(bad(
                "ResourceNotFoundException",
                "the shard iterator's stream doesn't exist any more",
            ));
        };
        let account: String = row.get(0);
        let name: String = row.get(1);
        if account != self.principal.account {
            return Err(bad(
                "AccessDeniedException",
                "the shard iterator is another account's",
            ));
        }
        self.check_on("kinesis:GetRecords", On::Arn(arn(&account, &name)))?;
        if super::now_millis() - iterator.issued > ITERATOR_MILLIS {
            return Err(bad(
                "ExpiredIteratorException",
                format!(
                    "Iterator expired. The iterator was created at time {}",
                    iterator.issued
                ),
            ));
        }
        let limit = self.integer("Limit")?.unwrap_or(MAX_GET_RECORDS as i64);
        if !(1..=MAX_GET_RECORDS as i64).contains(&limit) {
            return Err(invalid(format!(
                "Limit must be from 1 to {MAX_GET_RECORDS}"
            )));
        }
        let read = super::read(
            self.app,
            iterator.stream,
            iterator.shard,
            iterator.sequence,
            limit as usize,
            MAX_GET_BYTES,
        )
        .await?;
        let behind = match read.next >= read.end {
            true => 0,
            false => read
                .records
                .last()
                .map_or(0, |(_, r)| (super::now_millis() - r.arrived).max(0)),
        };
        let next = Position {
            sequence: read.next,
            issued: super::now_millis(),
            ..iterator
        };
        Ok(json!({
            "Records": read.records.iter().map(|(sequence, r)| json!({
                "SequenceNumber": sequence.to_string(),
                "ApproximateArrivalTimestamp": r.arrived as f64 / 1000.0,
                "Data": STANDARD.encode(&r.data),
                "PartitionKey": r.key,
            })).collect::<Vec<_>>(),
            "NextShardIterator": next.encode(),
            "MillisBehindLatest": behind,
        }))
    }
}

fn not_found(account: &str, name: &str) -> Error {
    bad(
        "ResourceNotFoundException",
        format!("Stream {name} under account {account} not found."),
    )
}

/// The error of records that weren't appended.
fn failed(e: Failed, account: &str, name: &str) -> Error {
    match e {
        Failed::Gone => not_found(account, name),
        Failed::Internal => Error {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            kind: "InternalFailure",
            message: "internal error; the node's log has the details".to_owned(),
        },
    }
}

/// Calls `operation` as the user of access key `key`, as a signed request
/// would, for the tests: its answer, or its error's type and message.
#[cfg(test)]
pub(super) async fn call(
    app: &Arc<App>,
    key: &str,
    operation: &str,
    params: Value,
) -> std::result::Result<Value, (String, String)> {
    let client = app.pool.get().await.unwrap();
    let principal = Principal::load(&client, key).await.unwrap().unwrap();
    drop(client);
    let origin = Origin {
        peer: Some("127.0.0.1".parse().unwrap()),
        trusted_proxies: &[],
        signed: None,
        form: false,
    };
    let access = Access::new(
        Some(&principal),
        &principal.account,
        &hyper::Method::POST,
        &hyper::HeaderMap::new(),
        "",
        &origin,
    )
    .unwrap();
    let Value::Object(params) = params else {
        panic!("params must be an object");
    };
    let api = Api {
        app,
        principal: &principal,
        access: &access,
        params: &params,
        touched: Mutex::default(),
    };
    api.dispatch(operation)
        .await
        .map_err(|e| (e.kind.to_owned(), e.message))
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn shards_split_the_hash_keys() {
        for count in [1, 2, 3, 7, 1000] {
            let mut next = 0u128;
            for shard in 0..count {
                let (start, end) = hash_range(shard, count);
                assert_eq!(start, next);
                assert_eq!(shard_of(start, count), shard);
                assert_eq!(shard_of(end, count), shard);
                next = end.wrapping_add(1);
            }
            assert_eq!(next, 0, "the last shard ends at 2^128 - 1");
        }
    }

    #[test]
    fn keys_hash_as_kinesis_hashes_them() {
        // MD5("a") = 0cc175b9c0f1b6a831c399e269772661.
        assert_eq!(hash_key("a"), 0x0cc175b9c0f1b6a831c399e269772661);
    }

    #[test]
    fn iterators_round_trip() {
        let iterator = Position {
            stream: Uuid::now_v7(),
            shard: 3,
            sequence: 42,
            issued: 1_700_000_000_000,
        };
        assert_eq!(Position::decode(&iterator.encode()), Some(iterator));
        assert_eq!(Position::decode("bm9wZQ=="), None);
        assert_eq!(Position::decode("!"), None);
    }

    #[test]
    fn names_and_shard_ids() {
        assert!(valid_name("my-stream_1.x"));
        assert!(!valid_name(""));
        assert!(!valid_name("a/b"));
        assert!(!valid_name(&"a".repeat(129)));
        assert_eq!(shard_id(7), "shardId-000000000007");
        assert_eq!(parse_shard_id("shardId-000000000007", 8), Some(7));
        assert_eq!(parse_shard_id("shardId-000000000008", 8), None);
        assert_eq!(parse_shard_id("7", 8), None);
    }
}
