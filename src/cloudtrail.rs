//! AWS CloudTrail's API, on the S3 port: requests signed for the
//! `cloudtrail` service are these, whatever their path, as KMS's are (see
//! `kms::api`). Its JSON protocol (`X-Amz-Target:
//! com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.<Operation>`,
//! JSON 1.1), its errors. `LookupEvents`: the event history of the caller's
//! account, from the audit log (see `audit::lookup`); and trails (see
//! `trails`), which deliver an account's events to a bucket (see
//! `delivery`), with their event selectors (see `selectors`) and tags.
//! Not (yet): log file validation's digests, SNS notifications, CloudWatch
//! Logs, organization trails, Insights (see `plans/cloudtrail.md`).
//!
//! A request acts as its signer, as CloudTrail's own actions
//! (`cloudtrail:CreateTrail`, on the trail's ARN; `cloudtrail:LookupEvents`,
//! `DescribeTrails` and `ListTrails`, on `*`), by its identity policies.
//! Each authenticated request to one of CloudTrail's operations is itself
//! recorded, as CloudTrail records its own, before it's answered.

pub mod delivery;
pub mod selectors;
pub mod trails;

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
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
    db::Cached,
    policy::Verdict,
    s3::{
        access::{Access, Origin},
        actions::{Check, On},
    },
    users::{self, Principal},
};
use selectors::Selectors;
use trails::{BadName, Named, Trail};

/// The most a request's body may hold.
const MAX_BODY: usize = 64 * 1024;
/// What every operation's target starts with.
const TARGET: &str = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.";
/// The service CloudTrail's own events are of.
const SOURCE: &str = delivery::SERVICE;
/// The type of the resource a trail is, in events.
const TRAIL_TYPE: &str = "AWS::CloudTrail::Trail";
/// How long events are kept, and looked up by default: 90 days.
const HISTORY: i64 = audit::ship::RETENTION_DAYS as i64 * 86400;

/// Whether a request signed so is CloudTrail's.
pub fn wants(signed: &Signed) -> bool {
    signed.service == "cloudtrail"
}

/// A failed request: its status, CloudTrail's type for it, and a message.
#[derive(Debug)]
pub struct Error {
    pub(crate) status: StatusCode,
    pub(crate) kind: &'static str,
    pub(crate) message: String,
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
const OPERATIONS: &[(&str, bool)] = &[
    ("LookupEvents", true),
    ("CreateTrail", false),
    ("UpdateTrail", false),
    ("DeleteTrail", false),
    ("GetTrail", true),
    ("DescribeTrails", true),
    ("ListTrails", true),
    ("GetTrailStatus", true),
    ("StartLogging", false),
    ("StopLogging", false),
    ("PutEventSelectors", false),
    ("GetEventSelectors", true),
    ("PutInsightSelectors", false),
    ("GetInsightSelectors", true),
    ("AddTags", false),
    ("RemoveTags", false),
    ("ListTags", true),
];

/// CloudTrail's other operations: refused, as Cairn doesn't have them yet,
/// and recorded as calls that may change something.
const OTHER_OPERATIONS: &[&str] = &["ListPublicKeys"];

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
    let event = audit::Event::of_request(
        SOURCE,
        &operation,
        &principal,
        &signed.access_key,
        &parts.headers,
        Some(peer),
        &app.trusted_proxies,
        request_id,
        read_only,
    );
    run(app, &principal, &access, &params, event).await
}

/// Runs a request to `event`'s operation, with `params`, as `principal`
/// (with `access`), and records it as `event`, with its outcome, before
/// it's answered: a request whose record can't be logged fails.
async fn run(
    app: &Arc<App>,
    principal: &Principal,
    access: &Access,
    params: &Map<String, Value>,
    mut event: audit::Event,
) -> Result<Value> {
    event.parameters = audit::parameters(params, &[], &[]);
    let api = Api {
        app,
        principal,
        access,
        params,
        touched: Mutex::default(),
    };
    let result = api.dispatch(&event.name).await;
    for resource in api.touched.into_inner().unwrap_or_else(|e| e.into_inner()) {
        event.touch(resource);
    }
    match &result {
        Ok(Value::Object(members)) if !event.read_only => {
            event.response = audit::parameters(members, &[], &[]);
        }
        Ok(_) => {}
        Err(e) => event.error = Some((e.kind.to_owned(), e.message.clone())),
    }
    app.audit
        .record(&event)
        .await
        .map_err(|e| Error::from(anyhow::Error::new(e)))?;
    result
}

/// A console session's request to `operation`, with `params`: run as its
/// `principal` (with `access`), and recorded as CloudTrail records the
/// console's, made with the session's credentials
/// (`sessionCredentialFromConsole`), so that the console is no way around
/// the log. `headers` and `peer` are the console's request's; `mfa`, whether
/// the session was signed in with a second factor.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn console_call(
    app: &Arc<App>,
    principal: &Principal,
    access: &Access,
    headers: &hyper::HeaderMap,
    peer: Option<IpAddr>,
    mfa: bool,
    operation: &str,
    params: Map<String, Value>,
) -> Result<Value> {
    let Some(read_only) = read_only(operation) else {
        return Err(bad(
            "UnknownOperationException",
            format!("No such operation: {operation}"),
        ));
    };
    let request_id = Uuid::new_v4().to_string();
    let mut event = audit::Event::of_request(
        SOURCE,
        operation,
        principal,
        "",
        headers,
        peer,
        &app.trusted_proxies,
        &request_id,
        read_only,
    );
    event.console = true;
    if mfa && let Some(attributes) = event.identity.pointer_mut("/sessionContext/attributes") {
        attributes["mfaAuthenticated"] = json!("true");
    }
    run(app, principal, access, &params, event).await
}

/// A request, as its signer makes it.
pub(crate) struct Api<'a> {
    pub app: &'a Arc<App>,
    pub principal: &'a Principal,
    pub access: &'a Access,
    pub params: &'a Map<String, Value>,
    /// The resources (trails) it's about, for its event.
    pub touched: Mutex<Vec<audit::Resource>>,
}

impl Api<'_> {
    pub async fn dispatch(&self, operation: &str) -> Result<Value> {
        match operation {
            "LookupEvents" => self.lookup_events().await,
            "CreateTrail" => self.create_trail().await,
            "UpdateTrail" => self.update_trail().await,
            "DeleteTrail" => self.delete_trail().await,
            "GetTrail" => self.get_trail().await,
            "DescribeTrails" => self.describe_trails().await,
            "ListTrails" => self.list_trails().await,
            "GetTrailStatus" => self.get_trail_status().await,
            "StartLogging" => self.start_logging().await,
            "StopLogging" => self.stop_logging().await,
            "PutEventSelectors" => self.put_event_selectors().await,
            "GetEventSelectors" => self.get_event_selectors().await,
            "PutInsightSelectors" => self.put_insight_selectors().await,
            "GetInsightSelectors" => self.get_insight_selectors().await,
            "AddTags" => self.add_tags().await,
            "RemoveTags" => self.remove_tags().await,
            "ListTags" => self.list_tags().await,
            other => Err(bad(
                "UnsupportedOperationException",
                format!("Cairn doesn't have CloudTrail's {other} yet"),
            )),
        }
    }

    /// Refuses the request unless the identity policies allow `action`.
    fn check(&self, action: &'static str) -> Result<()> {
        self.check_on(action, On::Account)
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

    /// The account's trail named so: its ARN's resource, which `check_on`
    /// takes, and its event's.
    fn touch(&self, name: &str) -> On {
        let arn = trails::arn(&self.principal.account, name);
        self.touched
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(audit::Resource {
                arn: arn.clone(),
                account: self.principal.account.clone(),
                kind: TRAIL_TYPE,
            });
        On::Arn(arn)
    }

    /// The string member `name`, if it's given.
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

    /// The boolean member `name`, if it's given.
    fn boolean(&self, name: &str) -> Result<Option<bool>> {
        match self.params.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Bool(b)) => Ok(Some(*b)),
            Some(_) => Err(bad(
                "SerializationException",
                format!("{name} must be true or false"),
            )),
        }
    }

    /// The name of the account's trail the member `member` names (by its
    /// name or ARN).
    fn trail_name(&self, member: &str) -> Result<String> {
        let given = self.string(member)?.unwrap_or("");
        match trails::named(given, &self.principal.account) {
            Ok(Named::Trail(name)) => Ok(name),
            Ok(Named::Elsewhere) => Err(not_found(given, &self.principal.account)),
            Err(BadName::Name) => Err(bad(
                "InvalidTrailNameException",
                format!(
                    "{given:?} isn't a trail's name: 3 to 128 letters, digits, periods, underscores \
                     and dashes, starting and ending with a letter or digit"
                ),
            )),
            Err(BadName::Arn) => Err(bad(
                "CloudTrailARNInvalidException",
                format!("{given} isn't a trail's ARN"),
            )),
        }
    }

    /// The account's trail `name`.
    async fn trail(&self, client: &impl Cached, name: &str) -> Result<Trail> {
        Trail::load(client, &self.principal.account, name)
            .await?
            .ok_or_else(|| not_found(name, &self.principal.account))
    }

    /// The trail the member `member` names, as `action` may have it.
    async fn named_trail(&self, member: &str, action: &'static str) -> Result<Trail> {
        let name = self.trail_name(member)?;
        let on = self.touch(&name);
        self.check_on(action, on)?;
        let client = self.app.pool.get().await?;
        self.trail(&client, &name).await
    }

    /// `S3KeyPrefix`, if one's given: none if it's empty.
    fn prefix(&self) -> Result<Option<Option<String>>> {
        Ok(match self.string("S3KeyPrefix")? {
            None => None,
            Some("") => Some(None),
            Some(prefix) if prefix.chars().count() > trails::MAX_PREFIX => {
                return Err(bad(
                    "InvalidS3PrefixException",
                    format!(
                        "An S3 key prefix is at most {} characters",
                        trails::MAX_PREFIX
                    ),
                ));
            }
            Some(prefix) => Some(Some(prefix.to_owned())),
        })
    }

    /// Refuses what Cairn's trails don't have (yet).
    fn refuse_unsupported(&self) -> Result<()> {
        let unsupported = |what: &str| {
            Err(bad(
                "UnsupportedOperationException",
                format!("Cairn's trails don't have {what} yet"),
            ))
        };
        if self.string("SnsTopicName")?.is_some_and(|s| !s.is_empty()) {
            return unsupported("SNS notifications");
        }
        if self
            .string("CloudWatchLogsLogGroupArn")?
            .is_some_and(|s| !s.is_empty())
            || self
                .string("CloudWatchLogsRoleArn")?
                .is_some_and(|s| !s.is_empty())
        {
            return unsupported("CloudWatch Logs");
        }
        if self.boolean("IsOrganizationTrail")? == Some(true) {
            return unsupported("organization trails");
        }
        if self.boolean("EnableLogFileValidation")? == Some(true) {
            return unsupported("log file validation");
        }
        Ok(())
    }

    /// Refuses a multi-region trail without global services' events, as
    /// CloudTrail does.
    fn check_combination(include_global: bool, multi_region: bool) -> Result<()> {
        if multi_region && !include_global {
            return Err(bad(
                "InvalidParameterCombinationException",
                "A multi-region trail must include global service events",
            ));
        }
        Ok(())
    }

    /// Refuses `bucket` (with `prefix`) for the trail `name` unless its
    /// policy lets CloudTrail write the trail's log files, as CloudTrail
    /// does.
    async fn check_bucket(&self, bucket: &str, prefix: Option<&str>, name: &str) -> Result<()> {
        let Some(destination) = crate::s3::service::Destination::load(self.app, bucket).await?
        else {
            return Err(bad(
                "S3BucketDoesNotExistException",
                format!("S3 bucket {bucket} does not exist."),
            ));
        };
        let account = &self.principal.account;
        let key = trails::key_prefix(prefix, account);
        if let Err(why) =
            delivery::allowed(&destination, &trails::arn(account, name), account, &key)
        {
            return Err(bad(
                "InsufficientS3BucketPolicyException",
                format!("Incorrect S3 bucket policy is detected for bucket: {bucket}: {why}"),
            ));
        }
        Ok(())
    }

    /// The ARN of the KMS key `given` names, for the trail `name`'s files,
    /// if its policy lets CloudTrail encrypt them with it, as CloudTrail
    /// checks.
    async fn check_key(&self, given: &str, name: &str) -> Result<String> {
        use crate::kms::keys;
        if self.app.kms.is_none() {
            return Err(bad("KmsException", "Cairn has no KMS"));
        }
        let Some(key_ref) = keys::KeyRef::parse(given) else {
            return Err(bad(
                "InvalidKmsKeyIdException",
                format!("{given} isn't a KMS key's ID, ARN or alias"),
            ));
        };
        let client = self.app.pool.get().await?;
        let Some(key) = keys::resolve(&client, &self.principal.account, &key_ref).await? else {
            return Err(bad(
                "KmsKeyNotFoundException",
                format!("KMS key {given} doesn't exist"),
            ));
        };
        if let Err(e) = key.usable() {
            return Err(bad("KmsException", format!("KMS key {given}: {e}")));
        }
        let trail = trails::arn(&self.principal.account, name);
        let context =
            std::collections::BTreeMap::from([(delivery::CONTEXT_KEY.to_owned(), trail.clone())]);
        let mut extra = keys::context_keys(&context);
        extra.set("aws:SourceArn", trail);
        let allowed = keys::authorize_service(
            SOURCE,
            &self.principal.account,
            "kms:GenerateDataKey",
            &key,
            &extra,
        )?;
        if let Err(why) = allowed {
            return Err(bad(
                "InsufficientEncryptionPolicyException",
                format!("Insufficient permissions to access KMS key {given}: {why}"),
            ));
        }
        Ok(key.arn())
    }

    async fn create_trail(&self) -> Result<Value> {
        let name = self.string("Name")?.unwrap_or("");
        if !trails::valid_name(name) {
            return Err(bad(
                "InvalidTrailNameException",
                format!(
                    "{name:?} isn't a trail's name: 3 to 128 letters, digits, periods, \
                     underscores and dashes, starting and ending with a letter or digit"
                ),
            ));
        }
        let on = self.touch(name);
        self.check_on("cloudtrail:CreateTrail", on.clone())?;
        let tags = parse_tags(self.params.get("TagsList"))?;
        if !tags.is_empty() {
            self.check_on("cloudtrail:AddTags", on)?;
        }
        self.refuse_unsupported()?;
        let bucket = self.string("S3BucketName")?.unwrap_or("");
        if bucket.is_empty() {
            return Err(bad(
                "InvalidS3BucketNameException",
                "A trail needs an S3BucketName",
            ));
        }
        let prefix = self.prefix()?.flatten();
        let include_global = self.boolean("IncludeGlobalServiceEvents")?.unwrap_or(true);
        let multi_region = self.boolean("IsMultiRegionTrail")?.unwrap_or(false);
        Self::check_combination(include_global, multi_region)?;
        let kms_key_id = match self.string("KmsKeyId")? {
            None | Some("") => None,
            Some(given) => Some(self.check_key(given, name).await?),
        };
        self.check_bucket(bucket, prefix.as_deref(), name).await?;
        let account = &self.principal.account;
        let client = self.app.pool.get().await?;
        let count: i64 = client
            .query_one_cached(
                "SELECT count(*) FROM cloudtrail_trails WHERE account_id = $1",
                &[account],
            )
            .await?
            .get(0);
        if count >= trails::MAX_TRAILS {
            return Err(bad(
                "MaximumNumberOfTrailsExceededException",
                format!("An account may have at most {} trails", trails::MAX_TRAILS),
            ));
        }
        let inserted = client
            .execute_cached(
                "INSERT INTO cloudtrail_trails
                     (account_id, name, bucket, prefix, include_global, multi_region,
                      kms_key_id, tags)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::text::jsonb)
                 ON CONFLICT DO NOTHING",
                &[
                    account,
                    &name,
                    &bucket,
                    &prefix,
                    &include_global,
                    &multi_region,
                    &kms_key_id,
                    &trails::tags_json(&tags).to_string(),
                ],
            )
            .await?;
        if inserted == 0 {
            return Err(bad(
                "TrailAlreadyExistsException",
                format!("Trail {name} already exists for customer: {account}"),
            ));
        }
        Ok(self.trail(&client, name).await?.settings())
    }

    async fn update_trail(&self) -> Result<Value> {
        let mut trail = self.named_trail("Name", "cloudtrail:UpdateTrail").await?;
        self.refuse_unsupported()?;
        let mut recheck = false;
        if let Some(bucket) = self.string("S3BucketName")? {
            if bucket.is_empty() {
                return Err(bad(
                    "InvalidS3BucketNameException",
                    "A trail needs an S3BucketName",
                ));
            }
            recheck |= bucket != trail.bucket;
            trail.bucket = bucket.to_owned();
        }
        if let Some(prefix) = self.prefix()? {
            recheck |= prefix != trail.prefix;
            trail.prefix = prefix;
        }
        if let Some(include) = self.boolean("IncludeGlobalServiceEvents")? {
            trail.include_global = include;
        }
        if let Some(multi) = self.boolean("IsMultiRegionTrail")? {
            trail.multi_region = multi;
        }
        Self::check_combination(trail.include_global, trail.multi_region)?;
        match self.string("KmsKeyId")? {
            None => {}
            Some("") => trail.kms_key_id = None,
            Some(given) => trail.kms_key_id = Some(self.check_key(given, &trail.name).await?),
        }
        if recheck {
            self.check_bucket(&trail.bucket, trail.prefix.as_deref(), &trail.name)
                .await?;
        }
        let client = self.app.pool.get().await?;
        let updated = client
            .execute_cached(
                "UPDATE cloudtrail_trails
                 SET bucket = $3, prefix = $4, include_global = $5, multi_region = $6,
                     kms_key_id = $7
                 WHERE account_id = $1 AND name = $2",
                &[
                    &trail.account,
                    &trail.name,
                    &trail.bucket,
                    &trail.prefix,
                    &trail.include_global,
                    &trail.multi_region,
                    &trail.kms_key_id,
                ],
            )
            .await?;
        if updated == 0 {
            return Err(not_found(&trail.name, &trail.account));
        }
        Ok(trail.settings())
    }

    async fn delete_trail(&self) -> Result<Value> {
        let name = self.trail_name("Name")?;
        let on = self.touch(&name);
        self.check_on("cloudtrail:DeleteTrail", on)?;
        let deleted = self
            .app
            .pool
            .get()
            .await?
            .execute_cached(
                "DELETE FROM cloudtrail_trails WHERE account_id = $1 AND name = $2",
                &[&self.principal.account, &name],
            )
            .await?;
        if deleted == 0 {
            return Err(not_found(&name, &self.principal.account));
        }
        Ok(json!({}))
    }

    async fn get_trail(&self) -> Result<Value> {
        let trail = self.named_trail("Name", "cloudtrail:GetTrail").await?;
        Ok(json!({ "Trail": trail.to_json() }))
    }

    async fn describe_trails(&self) -> Result<Value> {
        self.check("cloudtrail:DescribeTrails")?;
        let client = self.app.pool.get().await?;
        let all = Trail::list(&client, &self.principal.account).await?;
        let wanted = match self.params.get("trailNameList") {
            None | Some(Value::Null) => None,
            Some(Value::Array(items)) if items.is_empty() => None,
            Some(Value::Array(items)) => {
                let mut names = Vec::new();
                for item in items {
                    let Some(given) = item.as_str() else {
                        return Err(bad(
                            "SerializationException",
                            "trailNameList must be a list of strings",
                        ));
                    };
                    match trails::named(given, &self.principal.account) {
                        Ok(Named::Trail(name)) => names.push(name),
                        // Not the account's: not there.
                        Ok(Named::Elsewhere) => {}
                        Err(_) => {
                            return Err(bad(
                                "InvalidTrailNameException",
                                format!("{given:?} isn't a trail's name or ARN"),
                            ));
                        }
                    }
                }
                Some(names)
            }
            Some(_) => {
                return Err(bad(
                    "SerializationException",
                    "trailNameList must be a list of strings",
                ));
            }
        };
        let list: Vec<Value> = all
            .iter()
            .filter(|t| wanted.as_ref().is_none_or(|w| w.contains(&t.name)))
            .map(Trail::to_json)
            .collect();
        Ok(json!({ "trailList": list }))
    }

    async fn list_trails(&self) -> Result<Value> {
        self.check("cloudtrail:ListTrails")?;
        let client = self.app.pool.get().await?;
        let list: Vec<Value> = Trail::list(&client, &self.principal.account)
            .await?
            .iter()
            .map(|t| {
                json!({
                    "TrailARN": t.arn(),
                    "Name": t.name,
                    "HomeRegion": crate::s3::buckets::head::REGION,
                })
            })
            .collect();
        Ok(json!({ "Trails": list }))
    }

    async fn get_trail_status(&self) -> Result<Value> {
        let trail = self
            .named_trail("Name", "cloudtrail:GetTrailStatus")
            .await?;
        // The JSON protocol's timestamps (seconds), and the strings some
        // of the times are as well (`2026-11-16T05:06:07Z`), or "".
        let iso = |t: Option<f64>| t.map_or(String::new(), |t| crate::sessions::iso(t as u64));
        let mut status = json!({
            "IsLogging": trail.logging,
            "LatestDeliveryAttemptTime": iso(trail.attempted),
            "LatestDeliveryAttemptSucceeded": match trail.attempt_ok {
                Some(true) => iso(trail.attempted),
                _ => String::new(),
            },
            "LatestNotificationAttemptTime": "",
            "LatestNotificationAttemptSucceeded": "",
            "TimeLoggingStarted": iso(trail.started),
            "TimeLoggingStopped": iso(trail.stopped),
        });
        for (member, time) in [
            ("LatestDeliveryTime", trail.delivered),
            ("StartLoggingTime", trail.started),
            ("StopLoggingTime", trail.stopped),
        ] {
            if let Some(time) = time {
                status[member] = json!(time);
            }
        }
        if let Some(error) = &trail.error {
            status["LatestDeliveryError"] = json!(error);
        }
        Ok(status)
    }

    async fn start_logging(&self) -> Result<Value> {
        let trail = self.named_trail("Name", "cloudtrail:StartLogging").await?;
        let client = self.app.pool.get().await?;
        let started = client
            .query_opt_cached(
                "UPDATE cloudtrail_trails SET logging = true, started_at = now()
                 WHERE account_id = $1 AND name = $2 AND NOT logging
                 RETURNING extract(epoch FROM started_at)::float8",
                &[&trail.account, &trail.name],
            )
            .await?;
        if let Some(row) = started {
            delivery::backfill(&client, &trail.account, &trail.name, row.get(0)).await?;
        }
        Ok(json!({}))
    }

    async fn stop_logging(&self) -> Result<Value> {
        let trail = self.named_trail("Name", "cloudtrail:StopLogging").await?;
        self.app
            .pool
            .get()
            .await?
            .execute_cached(
                "UPDATE cloudtrail_trails SET logging = false, stopped_at = now()
                 WHERE account_id = $1 AND name = $2 AND logging",
                &[&trail.account, &trail.name],
            )
            .await?;
        Ok(json!({}))
    }

    async fn put_event_selectors(&self) -> Result<Value> {
        let trail = self
            .named_trail("TrailName", "cloudtrail:PutEventSelectors")
            .await?;
        let selectors = Selectors::parse(self.params)
            .map_err(|e| bad("InvalidEventSelectorsException", e.0))?;
        let stored = Value::Object(selectors.to_json());
        self.app
            .pool
            .get()
            .await?
            .execute_cached(
                "UPDATE cloudtrail_trails SET selectors = $3::text::jsonb
                 WHERE account_id = $1 AND name = $2",
                &[&trail.account, &trail.name, &stored.to_string()],
            )
            .await?;
        let mut answer = selectors.to_json();
        answer.insert("TrailARN".to_owned(), json!(trail.arn()));
        Ok(Value::Object(answer))
    }

    async fn get_event_selectors(&self) -> Result<Value> {
        let trail = self
            .named_trail("TrailName", "cloudtrail:GetEventSelectors")
            .await?;
        let mut answer = trail.selectors.clone().unwrap_or_default().to_json();
        answer.insert("TrailARN".to_owned(), json!(trail.arn()));
        Ok(Value::Object(answer))
    }

    async fn put_insight_selectors(&self) -> Result<Value> {
        let trail = self
            .named_trail("TrailName", "cloudtrail:PutInsightSelectors")
            .await?;
        match self.params.get("InsightSelectors") {
            Some(Value::Array(items)) if items.is_empty() => {
                Ok(json!({ "TrailARN": trail.arn(), "InsightSelectors": [] }))
            }
            _ => Err(bad(
                "UnsupportedOperationException",
                "Cairn has no Insights: a trail's InsightSelectors may only be empty",
            )),
        }
    }

    async fn get_insight_selectors(&self) -> Result<Value> {
        let trail = self
            .named_trail("TrailName", "cloudtrail:GetInsightSelectors")
            .await?;
        Err(bad(
            "InsightNotEnabledException",
            format!(
                "Trail {} does not have Insights enabled. Edit the trail settings to enable \
                 Insights, and then try the operation again.",
                trail.arn()
            ),
        ))
    }

    /// The trail a tagging request's resource ID (its ARN) names.
    async fn tagged(&self, given: &str, action: &'static str) -> Result<Trail> {
        let missing = || {
            bad(
                "ResourceNotFoundException",
                format!("Resource {given} not found"),
            )
        };
        let name = match trails::named(given, &self.principal.account) {
            Ok(Named::Trail(name)) if given.starts_with("arn:") => name,
            Ok(Named::Elsewhere) => return Err(missing()),
            _ => {
                return Err(bad(
                    "CloudTrailARNInvalidException",
                    format!("{given} isn't a trail's ARN"),
                ));
            }
        };
        let on = self.touch(&name);
        self.check_on(action, on)?;
        let client = self.app.pool.get().await?;
        Trail::load(&client, &self.principal.account, &name)
            .await?
            .ok_or_else(missing)
    }

    /// Stores `trail`'s tags.
    async fn store_tags(&self, trail: &Trail, tags: &[(String, String)]) -> Result<()> {
        if tags.len() > trails::MAX_TAGS {
            return Err(bad(
                "TagsLimitExceededException",
                format!("A trail may have at most {} tags", trails::MAX_TAGS),
            ));
        }
        self.app
            .pool
            .get()
            .await?
            .execute_cached(
                "UPDATE cloudtrail_trails SET tags = $3::text::jsonb
                 WHERE account_id = $1 AND name = $2",
                &[
                    &trail.account,
                    &trail.name,
                    &trails::tags_json(tags).to_string(),
                ],
            )
            .await?;
        Ok(())
    }

    async fn add_tags(&self) -> Result<Value> {
        let given = self.string("ResourceId")?.unwrap_or("");
        let trail = self.tagged(given, "cloudtrail:AddTags").await?;
        let mut tags = trail.tags.clone();
        for (key, value) in parse_tags(self.params.get("TagsList"))? {
            match tags.iter_mut().find(|(k, _)| *k == key) {
                Some(tag) => tag.1 = value,
                None => tags.push((key, value)),
            }
        }
        self.store_tags(&trail, &tags).await?;
        Ok(json!({}))
    }

    async fn remove_tags(&self) -> Result<Value> {
        let given = self.string("ResourceId")?.unwrap_or("");
        let trail = self.tagged(given, "cloudtrail:RemoveTags").await?;
        let removed = parse_tags(self.params.get("TagsList"))?;
        let tags: Vec<(String, String)> = trail
            .tags
            .iter()
            .filter(|(k, _)| !removed.iter().any(|(r, _)| r == k))
            .cloned()
            .collect();
        self.store_tags(&trail, &tags).await?;
        Ok(json!({}))
    }

    async fn list_tags(&self) -> Result<Value> {
        let Some(Value::Array(ids)) = self.params.get("ResourceIdList") else {
            return Err(bad(
                "InvalidParameterException",
                "ResourceIdList must be a list of trails' ARNs",
            ));
        };
        if ids.len() > 20 {
            return Err(bad(
                "InvalidParameterException",
                "ResourceIdList may have at most 20 ARNs",
            ));
        }
        let mut list = Vec::new();
        for id in ids {
            let Some(given) = id.as_str() else {
                return Err(bad(
                    "SerializationException",
                    "ResourceIdList must be a list of strings",
                ));
            };
            let trail = self.tagged(given, "cloudtrail:ListTags").await?;
            list.push(json!({ "ResourceId": trail.arn(), "TagsList": trail.tags_json() }));
        }
        Ok(json!({ "ResourceTagList": list }))
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

/// CloudTrail's error for a trail `name` (or ARN) of `account`'s that
/// isn't there.
fn not_found(name: &str, account: &str) -> Error {
    let arn = match name.starts_with("arn:") {
        true => name.to_owned(),
        false => trails::arn(account, name),
    };
    bad(
        "TrailNotFoundException",
        format!("Unknown trail: {arn} for the user: {account}"),
    )
}

/// A `TagsList`: its tags, by their keys, each key once.
fn parse_tags(value: Option<&Value>) -> Result<Vec<(String, String)>> {
    let invalid = |message: String| bad("InvalidTagParameterException", message);
    let items = match value {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(items)) => items,
        Some(_) => return Err(invalid("TagsList must be a list".to_owned())),
    };
    let mut tags: Vec<(String, String)> = Vec::new();
    for item in items {
        let key = item["Key"].as_str().unwrap_or("");
        let value = match &item["Value"] {
            Value::Null => "",
            Value::String(v) => v,
            _ => return Err(invalid(format!("The value of tag {key} must be a string"))),
        };
        if key.is_empty() || key.chars().count() > 128 {
            return Err(invalid("A tag's key is 1 to 128 characters".to_owned()));
        }
        if key.starts_with("aws:") {
            return Err(invalid(format!(
                "Tag keys starting with aws: are AWS's: {key}"
            )));
        }
        if value.chars().count() > 256 {
            return Err(invalid(format!(
                "The value of tag {key} is over 256 characters"
            )));
        }
        if tags.iter().any(|(k, _)| k == key) {
            return Err(invalid(format!("Tag {key} is given twice")));
        }
        tags.push((key.to_owned(), value.to_owned()));
    }
    Ok(tags)
}

#[cfg(test)]
mod tests;
