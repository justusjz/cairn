//! AWS CloudTrail's API, on the S3 port: requests signed for the
//! `cloudtrail` service are these, whatever their path, as KMS's are (see
//! `kms::api`). Its JSON protocol (`X-Amz-Target:
//! com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.<Operation>`,
//! JSON 1.1), its errors. So far, `LookupEvents`: the event history of the
//! caller's account, from the audit log (see `audit::lookup`). Trails come
//! next (see `plans/cloudtrail.md`).
//!
//! A request acts as its signer, as CloudTrail's own actions
//! (`cloudtrail:LookupEvents`, on `*`), by its identity policies. Each
//! authenticated request to one of CloudTrail's operations is itself
//! recorded, as CloudTrail records its own, before it's answered.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode, body::Bytes};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{
    App,
    audit::{
        self,
        lookup::{self, Attribute, Cursor, Query},
    },
    auth::Signed,
    policy::Verdict,
    s3::{
        access::{Access, Origin},
        actions::{Check, On},
    },
    users::{self, Principal},
};

/// The most a request's body may hold.
const MAX_BODY: usize = 64 * 1024;
/// What every operation's target starts with.
const TARGET: &str = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.";
/// The service CloudTrail's own events are of.
const SOURCE: &str = "cloudtrail.amazonaws.com";
/// How long events are kept, and looked up by default: 90 days.
const HISTORY: i64 = audit::ship::RETENTION_DAYS as i64 * 86400;

/// Whether a request signed so is CloudTrail's.
pub fn wants(signed: &Signed) -> bool {
    signed.service == "cloudtrail"
}

/// A failed request: its status, CloudTrail's type for it, and a message.
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

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Error {
        eprintln!("cloudtrail: request failed: {e:#}");
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

/// The operations Cairn has, and whether each only reads (as CloudTrail's
/// `readOnly` has it).
const OPERATIONS: &[(&str, bool)] = &[("LookupEvents", true)];

/// CloudTrail's other operations: refused, as Cairn doesn't have them yet,
/// and recorded as calls that may change something.
const OTHER_OPERATIONS: &[&str] = &[
    "AddTags",
    "CreateTrail",
    "DeleteTrail",
    "DescribeTrails",
    "GetEventSelectors",
    "GetInsightSelectors",
    "GetTrail",
    "GetTrailStatus",
    "ListPublicKeys",
    "ListTags",
    "ListTrails",
    "PutEventSelectors",
    "PutInsightSelectors",
    "RemoveTags",
    "StartLogging",
    "StopLogging",
    "UpdateTrail",
];

/// Whether `operation` only reads: `None` if it isn't CloudTrail's (or is
/// CloudTrail Lake's, which Cairn won't have).
fn read_only(operation: &str) -> Option<bool> {
    match OPERATIONS.iter().find(|(name, _)| *name == operation) {
        Some((_, read_only)) => Some(*read_only),
        None => OTHER_OPERATIONS.contains(&operation).then_some(false),
    }
}

/// A CloudTrail request, on the S3 port.
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
            json!({ "__type": e.kind, "Message": e.message, "message": e.message }).to_string(),
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
    let Some(read_only) = read_only(&operation) else {
        return Err(bad(
            "UnknownOperationException",
            format!("No such operation: {operation}"),
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
    let api = Api {
        app,
        principal: &principal,
        access: &access,
        params: &params,
    };
    let result = api.dispatch(&operation).await;
    match &result {
        Ok(Value::Object(members)) if !read_only => {
            event.response = audit::parameters(members, &[], &[]);
        }
        Ok(_) => {}
        Err(e) => event.error = Some((e.kind.to_owned(), e.message.clone())),
    }
    // A request whose record can't be logged fails.
    app.audit
        .record(&event)
        .await
        .map_err(|e| Error::from(anyhow::Error::new(e)))?;
    result
}

/// A request, as its signer makes it.
pub(crate) struct Api<'a> {
    pub app: &'a Arc<App>,
    pub principal: &'a Principal,
    pub access: &'a Access,
    pub params: &'a Map<String, Value>,
}

impl Api<'_> {
    pub async fn dispatch(&self, operation: &str) -> Result<Value> {
        match operation {
            "LookupEvents" => self.lookup_events().await,
            other => Err(bad(
                "UnsupportedOperationException",
                format!("Cairn doesn't have CloudTrail's {other} yet"),
            )),
        }
    }

    /// Refuses the request unless the identity policies allow `action`.
    fn check(&self, action: &'static str) -> Result<()> {
        let check = Check {
            action,
            on: On::Account,
        };
        let verdict = self.access.verdict(&check);
        if verdict == Verdict::Allow {
            return Ok(());
        }
        Err(bad(
            "AccessDeniedException",
            format!(
                "User: {} is not authorized to perform: {action} on resource: * {}",
                self.principal.arn(),
                verdict.why(action, self.access.boundary())
            ),
        ))
    }

    /// A time (`StartTime`, `EndTime`), in seconds: a number, as the JSON
    /// protocol sends timestamps, or ISO 8601's text.
    fn time(&self, name: &str) -> Result<Option<i64>> {
        match self.params.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Number(n)) => n
                .as_f64()
                .filter(|t| t.is_finite())
                .map(|t| Some(t.floor() as i64))
                .ok_or_else(|| bad("SerializationException", format!("{name} isn't a time"))),
            Some(Value::String(s)) => crate::backup::restore::parse_time(s)
                .map(|millis| Some(millis.div_euclid(1000)))
                .map_err(|e| bad("SerializationException", e)),
            Some(_) => Err(bad(
                "SerializationException",
                format!("{name} isn't a time"),
            )),
        }
    }

    async fn lookup_events(&self) -> Result<Value> {
        self.check("cloudtrail:LookupEvents")?;
        let attribute = match self.params.get("LookupAttributes") {
            None | Some(Value::Null) => None,
            Some(Value::Array(items)) if items.is_empty() => None,
            Some(Value::Array(items)) if items.len() == 1 => {
                let invalid = || {
                    bad(
                        "InvalidLookupAttributesException",
                        format!(
                            "A lookup attribute's AttributeKey must be one of {}, and its AttributeValue 1 to 2000 characters",
                            Attribute::ALL.map(|(n, _)| n).join(", ")
                        ),
                    )
                };
                let key = items[0]["AttributeKey"].as_str().ok_or_else(invalid)?;
                let value = items[0]["AttributeValue"].as_str().ok_or_else(invalid)?;
                let attribute = Attribute::parse(key).ok_or_else(invalid)?;
                if value.is_empty() || value.chars().count() > 2000 {
                    return Err(invalid());
                }
                Some((attribute, value.to_owned()))
            }
            Some(Value::Array(_)) => {
                return Err(bad(
                    "InvalidLookupAttributesException",
                    "You can only specify one lookup attribute",
                ));
            }
            Some(_) => {
                return Err(bad(
                    "SerializationException",
                    "LookupAttributes must be a list",
                ));
            }
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        let (start, end) = (self.time("StartTime")?, self.time("EndTime")?);
        let given = (start.is_some(), end.is_some());
        let end = end.unwrap_or(now);
        let start = start.unwrap_or(end.min(now) - HISTORY);
        if start > end {
            return Err(bad(
                "InvalidTimeRangeException",
                "The StartTime must be before the EndTime",
            ));
        }
        let max = match self.params.get("MaxResults") {
            None | Some(Value::Null) => 50,
            Some(n) => match n.as_u64() {
                Some(n @ 1..=50) => n as usize,
                _ => {
                    return Err(bad(
                        "InvalidMaxResultsException",
                        "MaxResults must be from 1 to 50",
                    ));
                }
            },
        };
        let query = Query {
            account: self.principal.account.clone(),
            attribute,
            start,
            end,
            given,
            max,
        };
        let cursor = match self.params.get("NextToken") {
            None | Some(Value::Null) => None,
            Some(token) => Some(
                token
                    .as_str()
                    .and_then(|t| Cursor::parse(t, &query))
                    .ok_or_else(|| {
                        bad(
                            "InvalidNextTokenException",
                            "The NextToken isn't one of this lookup's",
                        )
                    })?,
            ),
        };
        let events = match self.params.get("EventCategory").and_then(Value::as_str) {
            // Cairn has no Insights: no Insights events.
            Some("insight") => lookup::Page {
                events: Vec::new(),
                next: None,
            },
            Some(other) => {
                return Err(bad(
                    "InvalidEventCategoryException",
                    format!("{other} isn't an event category: only insight is"),
                ));
            }
            None => lookup::lookup(self.app, &query, cursor).await?,
        };
        let mut answer = json!({
            "Events": events.events.iter().map(lookup::summary).collect::<Vec<_>>(),
        });
        if let Some(next) = events.next {
            answer["NextToken"] = json!(next.token(&query));
        }
        Ok(answer)
    }
}

#[cfg(test)]
mod tests;
