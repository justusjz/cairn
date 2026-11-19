//! S3 Control's requests on Batch Operations jobs (`/v20180820/jobs…`,
//! naming the account in `x-amz-account-id`): CreateJob, DescribeJob,
//! ListJobs, UpdateJobPriority, UpdateJobStatus, and GetJobTagging,
//! PutJobTagging and DeleteJobTagging. The signer's own account's only, as
//! S3 Control's other requests here (see `s3::buckets::public_access`).
//!
//! Their shapes are S3 Control's API model's (botocore's
//! `s3control/2018-08-20`): lists' items are `<member>`s, and errors are
//! named as its exceptions are (`BadRequestException`, `NotFoundException`,
//! …). Which status each is answered with, and their messages, are
//! Cairn's guesses, yet to be probed against S3.
//!
//! Each is authorized as S3's actions for it say (`s3:CreateJob`, …), with
//! their condition keys: `s3:RequestJobPriority`,
//! `s3:RequestJobOperation`, `s3:ExistingJobPriority`,
//! `s3:ExistingJobOperation` and `s3:JobSuspendedCause`. CreateJob also
//! needs `iam:PassRole` on its role (with `iam:PassedToService` the
//! service it's passed to, `batchoperations.s3.amazonaws.com`).

use std::time::SystemTime;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::Full;
use hyper::{Method, Request, Response, StatusCode, body::Bytes};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{AWAITING_CONFIRMATION, Failure, Manifest, Operation, Report, manifest};
use crate::db::Cached;
use crate::{
    App,
    policy::{Context, Verdict},
    s3::{
        access::Access,
        actions::{Check, On},
        tags::{self, Tags},
        util::{format_s3_error, query_param, rejection_response, xml_escape, xml_ok},
    },
    users::Principal,
};

/// S3 Control's path for jobs.
const JOBS: &str = "/v20180820/jobs";
const CONTROL_XMLNS: &str = "http://awss3control.amazonaws.com/doc/2018-08-20/";

/// The most tags a job may have.
const MAX_JOB_TAGS: usize = 50;
/// The most jobs a page of ListJobs lists.
const MAX_RESULTS: i64 = 1000;
/// The longest description, client request token and status update
/// reason.
const MAX_DESCRIPTION: usize = 256;
const MAX_TOKEN: usize = 64;
const MAX_REASON: usize = 256;

/// Every status a job may have, as ListJobs takes them (`jobStatuses`).
const STATUSES: &[&str] = &[
    "Active",
    "Cancelled",
    "Cancelling",
    "Complete",
    "Completing",
    "Failed",
    "Failing",
    "New",
    "Paused",
    "Pausing",
    "Preparing",
    "Ready",
    "Suspended",
];

/// S3's operations Cairn doesn't do yet.
const UNIMPLEMENTED: &[&str] = &[
    "LambdaInvoke",
    "S3PutObjectAcl",
    "S3InitiateRestoreObject",
    "S3ComputeObjectChecksum",
    "S3UpdateObjectEncryption",
];

/// Whether a request to `path` (as sent) with `headers` is S3 Control's, on
/// Batch Operations' jobs.
pub fn is_control(path: &str, headers: &hyper::HeaderMap) -> bool {
    (path == JOBS || path.starts_with("/v20180820/jobs/"))
        && headers.contains_key("x-amz-account-id")
}

fn error(status: StatusCode, code: &str, message: &str) -> Response<Full<Bytes>> {
    format_s3_error(status, code, message)
}

pub(super) fn bad_request(message: &str) -> Response<Full<Bytes>> {
    error(StatusCode::BAD_REQUEST, "BadRequestException", message)
}

fn not_found() -> Response<Full<Bytes>> {
    error(StatusCode::NOT_FOUND, "NotFoundException", "Job not found")
}

pub(super) fn not_implemented(what: &str) -> Response<Full<Bytes>> {
    error(
        StatusCode::NOT_IMPLEMENTED,
        "NotImplemented",
        &format!("{what} isn't implemented."),
    )
}

/// What a request on jobs is.
enum Op {
    Create,
    List,
    Describe(String),
    Priority(String),
    Status(String),
    GetTagging(String),
    PutTagging(String),
    DeleteTagging(String),
}

fn op(method: &Method, path: &str) -> Option<Op> {
    let rest = path
        .strip_prefix(JOBS)
        .filter(|rest| rest.is_empty() || rest.starts_with('/'))?;
    let segments: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    let id = |i: usize| crate::s3::util::decode_path_param(segments[i]);
    Some(match (method, segments.as_slice()) {
        (&Method::POST, []) => Op::Create,
        (&Method::GET, []) => Op::List,
        (&Method::GET, [_]) => Op::Describe(id(0)),
        (&Method::POST, [_, "priority"]) => Op::Priority(id(0)),
        (&Method::POST, [_, "status"]) => Op::Status(id(0)),
        (&Method::GET, [_, "tagging"]) => Op::GetTagging(id(0)),
        (&Method::PUT, [_, "tagging"]) => Op::PutTagging(id(0)),
        (&Method::DELETE, [_, "tagging"]) => Op::DeleteTagging(id(0)),
        _ => return None,
    })
}

/// Handles a request `is_control` says is one, by `principal`, as `access`
/// decides it; `secret` is what its body is signed with.
pub async fn handle(
    app: &App,
    req: Request<crate::listen::ClientBody>,
    principal: Option<&Principal>,
    access: &mut Access,
    secret: &str,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let named = req
        .headers()
        .get("x-amz-account-id")
        .and_then(|v| v.to_str().ok());
    let Some(principal) = principal.filter(|p| named == Some(p.account.as_str())) else {
        return Ok(error(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "Access Denied",
        ));
    };
    let Some(op) = op(req.method(), req.uri().path()) else {
        return Ok(error(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "The specified method is not allowed against this resource.",
        ));
    };
    let query = req.uri().query().unwrap_or("").to_owned();
    let account = principal.account.clone();
    let body = match op {
        Op::Create | Op::PutTagging(_) => match crate::s3::read_body(req, secret, false).await? {
            Ok(body) => body,
            Err(rejection) => return Ok(rejection_response(&rejection)),
        },
        _ => Bytes::new(),
    };
    match op {
        Op::Create => create(app, access, &account, &body).await,
        Op::List => list(app, access, &account, &query).await,
        Op::Describe(id) => describe(app, access, &account, &id).await,
        Op::Priority(id) => update_priority(app, access, &account, &id, &query).await,
        Op::Status(id) => update_status(app, access, &account, &id, &query).await,
        Op::GetTagging(id) => get_tagging(app, access, &account, &id).await,
        Op::PutTagging(id) => put_tagging(app, access, &account, &id, &body).await,
        Op::DeleteTagging(id) => delete_tagging(app, access, &account, &id).await,
    }
}

/// `access`'s refusal of `action` on `on`, with the condition keys
/// `extra`, if it refuses it.
fn refused(
    access: &Access,
    action: &'static str,
    on: On,
    extra: &Context,
) -> Option<Response<Full<Bytes>>> {
    let check = Check { action, on };
    match access.verdict_with(&check, extra) {
        Verdict::Allow => None,
        verdict => Some(access.denied(&check, verdict)),
    }
}

/// A job, as it's described.
struct Described {
    id: Uuid,
    status: String,
    description: Option<String>,
    priority: i32,
    confirmation: bool,
    operation: Operation,
    manifest: Manifest,
    generator: Option<super::generate::Generator>,
    report: Report,
    role_arn: String,
    tags: Vec<(String, String)>,
    created: SystemTime,
    terminated: Option<SystemTime>,
    suspended: Option<SystemTime>,
    suspended_cause: Option<String>,
    status_reason: Option<String>,
    failures: Vec<Failure>,
    total: i64,
    succeeded: i64,
    failed: i64,
    active_seconds: f64,
}

const COLUMNS: &str = "id, status, description, priority, confirmation, operation, manifest, report, role_arn, tags,
     created_at, terminated_at, suspended_at, suspended_cause, status_reason, failures, total, succeeded, failed,
     active_seconds, generator";

impl Described {
    fn of(row: &tokio_postgres::Row) -> anyhow::Result<Described> {
        let json = |i: usize| -> String { row.get(i) };
        Ok(Described {
            id: row.get(0),
            status: row.get(1),
            description: row.get(2),
            priority: row.get(3),
            confirmation: row.get(4),
            operation: serde_json::from_str(&json(5))?,
            manifest: serde_json::from_str(&json(6))?,
            report: serde_json::from_str(&json(7))?,
            role_arn: row.get(8),
            tags: serde_json::from_str(&json(9))?,
            created: row.get(10),
            terminated: row.get(11),
            suspended: row.get(12),
            suspended_cause: row.get(13),
            status_reason: row.get(14),
            failures: serde_json::from_str(&json(15))?,
            total: row.get(16),
            succeeded: row.get(17),
            failed: row.get(18),
            active_seconds: row.get(19),
            generator: row
                .get::<_, Option<String>>(20)
                .as_deref()
                .map(serde_json::from_str)
                .transpose()?,
        })
    }

    /// The condition keys of checks on it.
    fn context(&self) -> Context {
        let mut context = Context::default();
        context.set("s3:ExistingJobPriority", self.priority.to_string());
        context.set("s3:ExistingJobOperation", self.operation.name());
        if let Some(cause) = &self.suspended_cause {
            context.set("s3:JobSuspendedCause", cause);
        }
        context
    }

    fn progress(&self) -> String {
        format!(
            "<ProgressSummary><TotalNumberOfTasks>{}</TotalNumberOfTasks>\
             <NumberOfTasksSucceeded>{}</NumberOfTasksSucceeded><NumberOfTasksFailed>{}</NumberOfTasksFailed>\
             <Timers><ElapsedTimeInActiveSeconds>{}</ElapsedTimeInActiveSeconds></Timers></ProgressSummary>",
            self.total, self.succeeded, self.failed, self.active_seconds as i64
        )
    }

    /// Its `<Job>` (DescribeJob's).
    fn xml(&self, account: &str) -> String {
        let mut out = format!(
            "<Job><JobId>{}</JobId><ConfirmationRequired>{}</ConfirmationRequired>",
            self.id, self.confirmation
        );
        if let Some(description) = &self.description {
            out.push_str(&element("Description", description));
        }
        out.push_str(&element("JobArn", &super::arn(account, self.id)));
        out.push_str(&element("Status", &self.status));
        // A generated manifest is its generator's to tell.
        match &self.generator {
            Some(_) => {}
            None => out.push_str(&manifest_xml(&self.manifest)),
        }
        out.push_str(&operation_xml(&self.operation));
        out.push_str(&format!("<Priority>{}</Priority>", self.priority));
        out.push_str(&self.progress());
        if let Some(reason) = &self.status_reason {
            out.push_str(&element("StatusUpdateReason", reason));
        }
        if !self.failures.is_empty() {
            out.push_str("<FailureReasons>");
            for failure in &self.failures {
                out.push_str(&format!(
                    "<member>{}{}</member>",
                    element("FailureCode", &failure.code),
                    element("FailureReason", &failure.reason)
                ));
            }
            out.push_str("</FailureReasons>");
        }
        out.push_str(&report_xml(&self.report));
        out.push_str(&element("CreationTime", &time(self.created)));
        if let Some(terminated) = self.terminated {
            out.push_str(&element("TerminationDate", &time(terminated)));
        }
        out.push_str(&element("RoleArn", &self.role_arn));
        if let Some(suspended) = self.suspended {
            out.push_str(&element("SuspendedDate", &time(suspended)));
        }
        if let Some(cause) = &self.suspended_cause {
            out.push_str(&element("SuspendedCause", cause));
        }
        if let Some(generator) = &self.generator {
            out.push_str(&generator.xml());
            out.push_str(&super::generate::descriptor_xml(generator, &self.manifest));
        }
        out.push_str("</Job>");
        out
    }

    /// Its `<member>` of ListJobs's `<Jobs>`.
    fn listed(&self) -> String {
        let mut out = format!("<member><JobId>{}</JobId>", self.id);
        if let Some(description) = &self.description {
            out.push_str(&element("Description", description));
        }
        out.push_str(&element("Operation", self.operation.name()));
        out.push_str(&format!("<Priority>{}</Priority>", self.priority));
        out.push_str(&element("Status", &self.status));
        out.push_str(&element("CreationTime", &time(self.created)));
        if let Some(terminated) = self.terminated {
            out.push_str(&element("TerminationDate", &time(terminated)));
        }
        out.push_str(&self.progress());
        out.push_str("</member>");
        out
    }
}

pub(super) fn element(name: &str, text: &str) -> String {
    format!("<{name}>{}</{name}>", xml_escape(text))
}

/// A time as S3 Control writes it (ISO 8601, to the second).
fn time(t: SystemTime) -> String {
    crate::sessions::iso(
        t.duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
}

pub(super) fn tags_xml(name: &str, tags: &[(String, String)]) -> String {
    let mut out = format!("<{name}>");
    for (key, value) in tags {
        out.push_str(&format!(
            "<member>{}{}</member>",
            element("Key", key),
            element("Value", value)
        ));
    }
    out.push_str(&format!("</{name}>"));
    out
}

fn operation_xml(operation: &Operation) -> String {
    match operation {
        Operation::PutTagging { tags } => {
            format!(
                "<Operation><S3PutObjectTagging>{}</S3PutObjectTagging></Operation>",
                tags_xml("TagSet", tags)
            )
        }
        Operation::DeleteTagging => "<Operation><S3DeleteObjectTagging/></Operation>".to_owned(),
        Operation::PutRetention {
            mode,
            until,
            bypass,
        } => {
            let mut out = String::from("<Operation><S3PutObjectRetention>");
            if *bypass {
                out.push_str("<BypassGovernanceRetention>true</BypassGovernanceRetention>");
            }
            out.push_str("<Retention>");
            if let Some(until) = until {
                out.push_str(&element("RetainUntilDate", until));
            }
            if let Some(mode) = mode {
                out.push_str(&element("Mode", mode));
            }
            out.push_str("</Retention></S3PutObjectRetention></Operation>");
            out
        }
        Operation::PutLegalHold { on } => format!(
            "<Operation><S3PutObjectLegalHold><LegalHold><Status>{}</Status></LegalHold></S3PutObjectLegalHold></Operation>",
            if *on { "ON" } else { "OFF" }
        ),
        Operation::Replicate => "<Operation><S3ReplicateObject/></Operation>".to_owned(),
        Operation::Copy(copy) => format!("<Operation>{}</Operation>", copy.xml()),
    }
}

fn manifest_xml(manifest: &Manifest) -> String {
    let fields: String = manifest
        .fields
        .iter()
        .map(|f| element("member", f))
        .collect();
    let fields = match fields.is_empty() {
        true => fields,
        false => format!("<Fields>{fields}</Fields>"),
    };
    let mut out = format!(
        "<Manifest><Spec>{}{fields}</Spec><Location>",
        element("Format", &manifest.format)
    );
    out.push_str(&element("ObjectArn", &manifest.arn));
    if let Some(version_id) = &manifest.version_id {
        out.push_str(&element("ObjectVersionId", version_id));
    }
    out.push_str(&element("ETag", &manifest.etag));
    out.push_str("</Location></Manifest>");
    out
}

fn report_xml(report: &Report) -> String {
    let mut out = String::from("<Report>");
    if let Some(bucket) = &report.bucket {
        out.push_str(&element("Bucket", bucket));
    }
    if let Some(format) = &report.format {
        out.push_str(&element("Format", format));
    }
    out.push_str(&format!("<Enabled>{}</Enabled>", report.enabled));
    if let Some(prefix) = &report.prefix {
        out.push_str(&element("Prefix", prefix));
    }
    if let Some(scope) = &report.scope {
        out.push_str(&element("ReportScope", scope));
    }
    if let Some(owner) = &report.expected_owner {
        out.push_str(&element("ExpectedBucketOwner", owner));
    }
    out.push_str("</Report>");
    out
}

/// The job `id` of `account`, if there's one.
async fn load(app: &App, account: &str, id: &str) -> anyhow::Result<Option<Described>> {
    let Ok(id) = Uuid::parse_str(id) else {
        return Ok(None);
    };
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached(
            &format!("SELECT {COLUMNS} FROM batch_jobs WHERE id = $1 AND account_id = $2"),
            &[&id, &account],
        )
        .await?;
    row.as_ref().map(Described::of).transpose()
}

/// The job `id`, and the check of `action` on it: its refusal, or 404 if
/// there's no such job (once the check, without its keys, allows it).
async fn authorized(
    app: &App,
    access: &Access,
    account: &str,
    id: &str,
    action: &'static str,
    extra: &Context,
) -> anyhow::Result<Result<Described, Response<Full<Bytes>>>> {
    let on = || On::Arn(format!("arn:aws:s3:{}:{account}:job/{id}", super::REGION));
    let Some(job) = load(app, account, id).await? else {
        return Ok(Err(
            refused(access, action, on(), extra).unwrap_or_else(not_found)
        ));
    };
    let mut context = job.context();
    context.extend(extra);
    match refused(access, action, on(), &context) {
        Some(refusal) => Ok(Err(refusal)),
        None => Ok(Ok(job)),
    }
}

/// CreateJob's request, parsed.
#[derive(Debug, PartialEq)]
pub(crate) struct NewJob {
    pub confirmation: bool,
    pub operation: Operation,
    pub report: Report,
    pub token: String,
    pub manifest: Manifest,
    /// Its manifest generator, if it has one instead of a manifest (whose
    /// manifest is then `Generator::placeholder`'s).
    pub generator: Option<super::generate::Generator>,
    pub description: Option<String>,
    pub priority: i32,
    pub role_arn: String,
    pub tags: Vec<(String, String)>,
}

/// The child elements of `node`.
pub(super) fn children<'a, 'input>(
    node: roxmltree::Node<'a, 'input>,
) -> impl Iterator<Item = roxmltree::Node<'a, 'input>> {
    node.children().filter(|n| n.is_element())
}

pub(super) fn child<'a, 'input>(
    node: roxmltree::Node<'a, 'input>,
    name: &str,
) -> Option<roxmltree::Node<'a, 'input>> {
    children(node).find(|n| n.tag_name().name() == name)
}

pub(super) fn text<'a>(node: roxmltree::Node<'a, '_>, name: &str) -> Option<&'a str> {
    child(node, name).map(|n| n.text().unwrap_or(""))
}

pub(super) fn boolean(
    node: roxmltree::Node,
    name: &str,
) -> Result<Option<bool>, Response<Full<Bytes>>> {
    match text(node, name) {
        None => Ok(None),
        Some("true") => Ok(Some(true)),
        Some("false") => Ok(Some(false)),
        Some(_) => Err(bad_request(&format!("{name} must be true or false."))),
    }
}

/// A `<member>` list of tags (`S3TagSet`), unchecked.
pub(super) fn tag_members(
    node: roxmltree::Node,
) -> Result<Vec<(String, String)>, Response<Full<Bytes>>> {
    let mut pairs = Vec::new();
    for member in children(node) {
        let (Some(key), Some(value)) = (text(member, "Key"), text(member, "Value")) else {
            return Err(bad_request("A tag must have a Key and a Value."));
        };
        pairs.push((key.to_owned(), value.to_owned()));
    }
    Ok(pairs)
}

/// A job's tags, checked: at most 50.
fn job_tags(pairs: Vec<(String, String)>) -> Result<Vec<(String, String)>, Response<Full<Bytes>>> {
    let tags = Tags::from_pairs(pairs, tags::On::Resource)?;
    let pairs: Vec<(String, String)> = tags
        .iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    if pairs.len() > MAX_JOB_TAGS {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "TooManyTagsException",
            "The number of tags exceeds the limit of 50 tags.",
        ));
    }
    Ok(pairs)
}

/// The bucket and key of an object's ARN (`arn:aws:s3:::bucket/key`).
fn object_of_arn(arn: &str) -> Option<(String, String)> {
    let path = arn.strip_prefix("arn:aws:s3:::")?;
    let (bucket, key) = path.split_once('/')?;
    (!bucket.is_empty() && !key.is_empty()).then(|| (bucket.to_owned(), key.to_owned()))
}

/// CreateJob's `<CreateJobRequest>`, or why it isn't one Cairn takes.
pub(crate) fn parse_create(body: &[u8]) -> Result<NewJob, Response<Full<Bytes>>> {
    let malformed = || tags::malformed("");
    let text_body = std::str::from_utf8(body).map_err(|_| malformed())?;
    let doc = roxmltree::Document::parse(text_body).map_err(|_| malformed())?;
    let root = doc.root_element();
    if root.tag_name().name() != "CreateJobRequest" {
        return Err(malformed());
    }
    let confirmation = boolean(root, "ConfirmationRequired")?.unwrap_or(false);

    let Some(operation) = child(root, "Operation") else {
        return Err(bad_request("An operation is required."));
    };
    let mut operations = children(operation);
    let (Some(operation), None) = (operations.next(), operations.next()) else {
        return Err(bad_request("A job must have exactly one operation."));
    };
    let operation = match operation.tag_name().name() {
        "S3PutObjectTagging" => {
            let pairs = match child(operation, "TagSet") {
                Some(set) => tag_members(set)?,
                None => Vec::new(),
            };
            let tags = Tags::from_pairs(pairs, tags::On::Object)?;
            Operation::PutTagging {
                tags: tags
                    .iter()
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect(),
            }
        }
        "S3DeleteObjectTagging" => Operation::DeleteTagging,
        "S3PutObjectRetention" => parse_retention(operation)?,
        "S3PutObjectLegalHold" => {
            let status = child(operation, "LegalHold").and_then(|hold| text(hold, "Status"));
            match status {
                Some("ON") => Operation::PutLegalHold { on: true },
                Some("OFF") => Operation::PutLegalHold { on: false },
                _ => {
                    return Err(bad_request(
                        "A legal hold's Status, ON or OFF, is required.",
                    ));
                }
            }
        }
        "S3ReplicateObject" => Operation::Replicate,
        "S3PutObjectCopy" => Operation::Copy(Box::new(super::copy::parse(operation)?)),
        name if UNIMPLEMENTED.contains(&name) => {
            return Err(not_implemented(&format!("The {name} operation")));
        }
        name => return Err(bad_request(&format!("{name} isn't an operation."))),
    };

    let Some(report) = child(root, "Report") else {
        return Err(bad_request("A report is required."));
    };
    let Some(enabled) = boolean(report, "Enabled")? else {
        return Err(bad_request("A report's Enabled is required."));
    };
    let owned = |name| text(report, name).map(str::to_owned);
    let report = Report {
        enabled,
        bucket: owned("Bucket"),
        format: owned("Format"),
        prefix: owned("Prefix"),
        scope: owned("ReportScope"),
        expected_owner: owned("ExpectedBucketOwner"),
    };
    if enabled {
        check_report(&report)?;
    }

    let token = text(root, "ClientRequestToken").unwrap_or("");
    if token.is_empty() || token.chars().count() > MAX_TOKEN {
        return Err(bad_request(
            "A ClientRequestToken of 1 to 64 characters is required.",
        ));
    }

    let (manifest, generator) = match (child(root, "Manifest"), child(root, "ManifestGenerator")) {
        (Some(_), Some(_)) => {
            return Err(bad_request(
                "A job has a manifest or a manifest generator, not both.",
            ));
        }
        (None, None) => {
            return Err(bad_request(
                "A manifest or a manifest generator is required.",
            ));
        }
        (Some(manifest), None) => (parse_manifest(manifest)?, None),
        (None, Some(generator)) => {
            let generator = super::generate::parse(generator)?;
            (generator.placeholder(), Some(generator))
        }
    };

    let description = text(root, "Description").map(str::to_owned);
    if description
        .as_ref()
        .is_some_and(|d| d.is_empty() || d.chars().count() > MAX_DESCRIPTION)
    {
        return Err(bad_request("A description is 1 to 256 characters."));
    }
    let priority = match text(root, "Priority").map(|p| p.parse::<i32>()) {
        Some(Ok(priority)) if priority >= 0 => priority,
        Some(_) => return Err(bad_request("A priority is a number from 0 to 2147483647.")),
        None => return Err(bad_request("A priority is required.")),
    };
    let role_arn = text(root, "RoleArn").unwrap_or("").to_owned();
    if !is_role_arn(&role_arn) {
        return Err(bad_request(&format!("{role_arn} isn't a role's ARN.")));
    }
    let tags = match child(root, "Tags") {
        Some(tags) => job_tags(tag_members(tags)?)?,
        None => Vec::new(),
    };
    Ok(NewJob {
        confirmation,
        operation,
        report,
        token: token.to_owned(),
        manifest,
        generator,
        description,
        priority,
        role_arn,
        tags,
    })
}

/// CreateJob's `<Manifest>`, or why it isn't one Cairn takes.
fn parse_manifest(manifest: roxmltree::Node) -> Result<Manifest, Response<Full<Bytes>>> {
    let (Some(spec), Some(location)) = (child(manifest, "Spec"), child(manifest, "Location"))
    else {
        return Err(bad_request("A manifest's Spec and Location are required."));
    };
    let format = text(spec, "Format").unwrap_or("");
    if format != manifest::CSV && !manifest::is_inventory(format) {
        return Err(bad_request(&format!("{format} isn't a manifest format.")));
    }
    // A CSV manifest's columns, as its Fields name them; an inventory
    // report's are its schema's.
    let mut names = Vec::new();
    if format == manifest::CSV {
        let Some(fields) = child(spec, "Fields") else {
            return Err(bad_request("A CSV manifest's Fields are required."));
        };
        let mut parsed = Vec::new();
        for field in children(fields) {
            let name = field.text().unwrap_or("");
            let Some(f) = manifest::Field::parse(name) else {
                return Err(bad_request(&format!("{name} isn't a manifest field.")));
            };
            parsed.push(f);
            names.push(f.name().to_owned());
        }
        manifest::check_fields(&parsed).map_err(|why| bad_request(&why))?;
    }
    let arn = text(location, "ObjectArn").unwrap_or("").to_owned();
    let Some((bucket, key)) =
        object_of_arn(&arn).filter(|(bucket, _)| !crate::internal::is_internal(bucket))
    else {
        return Err(bad_request(&format!("{arn} isn't an object's ARN.")));
    };
    let etag = text(location, "ETag").unwrap_or("").to_owned();
    if etag.trim_matches('"').is_empty() {
        return Err(bad_request("A manifest's ETag is required."));
    }
    let version_id = text(location, "ObjectVersionId").map(str::to_owned);
    Ok(Manifest {
        format: format.to_owned(),
        fields: names,
        arn,
        bucket,
        key,
        version_id,
        etag,
        generated: false,
    })
}

/// S3PutObjectRetention's operation: its `Retention` (a mode and a
/// retain-until date in the future, or neither, to remove one), and
/// whether it may bypass GOVERNANCE mode.
fn parse_retention(operation: roxmltree::Node) -> Result<Operation, Response<Full<Bytes>>> {
    use crate::s3::object_lock::{Mode, parse_date};
    let bypass = boolean(operation, "BypassGovernanceRetention")?.unwrap_or(false);
    let Some(retention) = child(operation, "Retention") else {
        return Err(bad_request("A retention is required."));
    };
    if child(retention, "EventHold").is_some() || child(retention, "EventHoldDuration").is_some() {
        return Err(not_implemented("An event hold"));
    }
    let (mode, until) = match (text(retention, "Mode"), text(retention, "RetainUntilDate")) {
        (None, None) => (None, None),
        (Some(mode), Some(until)) => {
            if Mode::parse(mode).is_none() {
                return Err(bad_request(
                    "A retention's Mode is GOVERNANCE or COMPLIANCE.",
                ));
            }
            let Some(date) = parse_date(until) else {
                return Err(bad_request("A retention's RetainUntilDate isn't a date."));
            };
            if date <= SystemTime::now() {
                return Err(bad_request(crate::s3::object_lock::IN_THE_PAST));
            }
            (Some(mode.to_owned()), Some(until.to_owned()))
        }
        _ => {
            return Err(bad_request(
                "A retention has both a Mode and a RetainUntilDate, or neither.",
            ));
        }
    };
    Ok(Operation::PutRetention {
        mode,
        until,
        bypass,
    })
}

/// Why an enabled report isn't one Cairn writes: it needs a bucket (by its
/// ARN) and the format, and may have a scope, a prefix of up to 512
/// characters and an expected owner.
fn check_report(report: &Report) -> Result<(), Response<Full<Bytes>>> {
    let bucket = report.bucket.as_deref().unwrap_or("");
    if super::report::bucket_of_arn(bucket).is_none() {
        return Err(bad_request("A report's Bucket must be a bucket's ARN."));
    }
    if report.format.as_deref() != Some(super::report::FORMAT) {
        return Err(bad_request(
            "A report's Format must be Report_CSV_20180820.",
        ));
    }
    if report
        .scope
        .as_deref()
        .is_some_and(|s| s != super::report::ALL_TASKS && s != super::report::FAILED_TASKS_ONLY)
    {
        return Err(bad_request(
            "A report's ReportScope must be AllTasks or FailedTasksOnly.",
        ));
    }
    if report
        .prefix
        .as_deref()
        .is_some_and(|p| p.is_empty() || p.chars().count() > 512)
    {
        return Err(bad_request("A report's Prefix is 1 to 512 characters."));
    }
    if report
        .expected_owner
        .as_deref()
        .is_some_and(|o| o.len() != 12 || !o.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(bad_request(
            "A report's ExpectedBucketOwner must be an account ID.",
        ));
    }
    Ok(())
}

/// Whether `arn` is a role's (`arn:aws:iam::<account>:role/…`).
fn is_role_arn(arn: &str) -> bool {
    let Some(rest) = arn.strip_prefix("arn:aws:iam::") else {
        return false;
    };
    let Some((account, path)) = rest.split_once(':') else {
        return false;
    };
    account.len() == 12
        && account.bytes().all(|b| b.is_ascii_digit())
        && path.len() > 5
        && path.starts_with("role/")
}

/// CreateJob.
pub(crate) async fn create(
    app: &App,
    access: &Access,
    account: &str,
    body: &[u8],
) -> anyhow::Result<Response<Full<Bytes>>> {
    let job = match parse_create(body) {
        Ok(job) => job,
        Err(refused) => return Ok(refused),
    };
    if let Operation::Copy(copy) = &job.operation
        && let Err(refused) = super::copy::check(app, copy).await?
    {
        return Ok(refused);
    }
    let mut context = Context::default();
    context.set("s3:RequestJobPriority", job.priority.to_string());
    context.set("s3:RequestJobOperation", job.operation.name());
    if let Some(refusal) = refused(access, "s3:CreateJob", On::Account, &context) {
        return Ok(refusal);
    }
    let mut context = Context::default();
    context.set("iam:PassedToService", super::SERVICE);
    if let Some(refusal) = refused(
        access,
        "iam:PassRole",
        On::Arn(job.role_arn.clone()),
        &context,
    ) {
        return Ok(refusal);
    }
    let id = match insert(app, account, &job, &hex(&Sha256::digest(body))).await? {
        Ok(id) => id,
        Err(refusal) => return Ok(refusal),
    };
    Ok(xml_ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CreateJobResult xmlns=\"{CONTROL_XMLNS}\"><JobId>{id}</JobId></CreateJobResult>"
    )))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Makes the job `job` of `account`, whose request's digest is `digest`;
/// or, if its token made one already, that one, if it was made by the same
/// request (a client's retry), else IdempotencyException.
pub(crate) async fn insert(
    app: &App,
    account: &str,
    job: &NewJob,
    digest: &str,
) -> anyhow::Result<Result<Uuid, Response<Full<Bytes>>>> {
    let client = app.pool.get().await?;
    let id = Uuid::new_v4();
    let row = client
        .query_opt_cached(
            "INSERT INTO batch_jobs (id, account_id, token, digest, status, description, priority, confirmation,
                 operation, manifest, report, role_arn, tags, generator)
             VALUES ($1, $2, $3, $4, 'New', $5, $6, $7, $8, $9, $10, $11, $12, $13)
             ON CONFLICT (account_id, token) DO NOTHING
             RETURNING id",
            &[
                &id,
                &account,
                &job.token,
                &digest,
                &job.description,
                &job.priority,
                &job.confirmation,
                &serde_json::to_string(&job.operation)?,
                &serde_json::to_string(&job.manifest)?,
                &serde_json::to_string(&job.report)?,
                &job.role_arn,
                &serde_json::to_string(&job.tags)?,
                &job.generator.as_ref().map(serde_json::to_string).transpose()?,
            ],
        )
        .await?;
    if let Some(row) = row {
        return Ok(Ok(row.get(0)));
    }
    let row = client
        .query_one_cached(
            "SELECT id, digest FROM batch_jobs WHERE account_id = $1 AND token = $2",
            &[&account, &job.token],
        )
        .await?;
    if row.get::<_, &str>(1) == digest {
        return Ok(Ok(row.get(0)));
    }
    Ok(Err(error(
        StatusCode::BAD_REQUEST,
        "IdempotencyException",
        "Another job was created with this ClientRequestToken, from a different request.",
    )))
}

/// DescribeJob.
pub(crate) async fn describe(
    app: &App,
    access: &Access,
    account: &str,
    id: &str,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let job = match authorized(
        app,
        access,
        account,
        id,
        "s3:DescribeJob",
        &Context::default(),
    )
    .await?
    {
        Ok(job) => job,
        Err(refusal) => return Ok(refusal),
    };
    Ok(xml_ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><DescribeJobResult xmlns=\"{CONTROL_XMLNS}\">{}</DescribeJobResult>",
        job.xml(account)
    )))
}

/// ListJobs: the account's jobs, newest first, a page of `maxResults` (at
/// most 1000) at a time, of the statuses `jobStatuses` names, if it names
/// any.
pub(crate) async fn list(
    app: &App,
    access: &Access,
    account: &str,
    query: &str,
) -> anyhow::Result<Response<Full<Bytes>>> {
    if let Some(refusal) = refused(access, "s3:ListJobs", On::Account, &Context::default()) {
        return Ok(refusal);
    }
    let invalid =
        |message: &str| error(StatusCode::BAD_REQUEST, "InvalidRequestException", message);
    let statuses: Vec<String> = query
        .split('&')
        .filter_map(|pair| {
            pair.split_once('=')
                .filter(|(name, _)| *name == "jobStatuses")
        })
        .map(|(_, value)| crate::s3::util::decode_path_param(value))
        .collect();
    if let Some(status) = statuses.iter().find(|s| !STATUSES.contains(&s.as_str())) {
        return Ok(invalid(&format!("{status} isn't a job status.")));
    }
    let max = match query_param(query, "maxResults").map(|m| m.parse::<i64>()) {
        None => MAX_RESULTS,
        Some(Ok(max)) if (0..=MAX_RESULTS).contains(&max) => max,
        Some(_) => return Ok(invalid("maxResults is a number from 0 to 1000.")),
    };
    let after = match query_param(query, "nextToken") {
        None => None,
        Some(token) => match decode_token(&token) {
            Some(after) => Some(after),
            None => {
                return Ok(error(
                    StatusCode::BAD_REQUEST,
                    "InvalidNextTokenException",
                    "The next token isn't valid.",
                ));
            }
        },
    };
    let (after_time, after_id) = after.unwrap_or((i64::MAX, Uuid::max()));
    let rows = app
        .pool
        .get()
        .await?
        .query_cached(
            &format!(
                "SELECT {COLUMNS}, (extract(epoch FROM created_at) * 1000000)::bigint FROM batch_jobs
                 WHERE account_id = $1 AND (cardinality($2::text[]) = 0 OR status = ANY($2))
                   AND ((extract(epoch FROM created_at) * 1000000)::bigint, id) < ($3, $4)
                 ORDER BY created_at DESC, id DESC LIMIT $5"
            ),
            &[&account, &statuses, &after_time, &after_id, &(max + 1)],
        )
        .await?;
    let more = rows.len() as i64 > max;
    let mut out = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListJobsResult xmlns=\"{CONTROL_XMLNS}\">"
    );
    let shown = &rows[..rows.len().min(max as usize)];
    if more && let Some(last) = shown.last() {
        out.push_str(&element(
            "NextToken",
            &encode_token(last.get(21), last.get(0)),
        ));
    }
    out.push_str("<Jobs>");
    for row in shown {
        out.push_str(&Described::of(row)?.listed());
    }
    out.push_str("</Jobs></ListJobsResult>");
    Ok(xml_ok(out))
}

/// ListJobs's `nextToken`: where the page ended (the last job's creation
/// time, in microseconds, and ID).
fn encode_token(micros: i64, id: Uuid) -> String {
    URL_SAFE_NO_PAD.encode(format!("{micros}:{id}"))
}

fn decode_token(token: &str) -> Option<(i64, Uuid)> {
    let text = String::from_utf8(URL_SAFE_NO_PAD.decode(token).ok()?).ok()?;
    let (micros, id) = text.split_once(':')?;
    Some((micros.parse().ok()?, Uuid::parse_str(id).ok()?))
}

/// UpdateJobPriority.
pub(crate) async fn update_priority(
    app: &App,
    access: &Access,
    account: &str,
    id: &str,
    query: &str,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let priority = match query_param(query, "priority").map(|p| p.parse::<i32>()) {
        Some(Ok(priority)) if priority >= 0 => priority,
        _ => return Ok(bad_request("A priority is a number from 0 to 2147483647.")),
    };
    let mut context = Context::default();
    context.set("s3:RequestJobPriority", priority.to_string());
    let job = match authorized(app, access, account, id, "s3:UpdateJobPriority", &context).await? {
        Ok(job) => job,
        Err(refusal) => return Ok(refusal),
    };
    app.pool
        .get()
        .await?
        .execute_cached(
            "UPDATE batch_jobs SET priority = $2 WHERE id = $1",
            &[&job.id, &priority],
        )
        .await?;
    Ok(xml_ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><UpdateJobPriorityResult xmlns=\"{CONTROL_XMLNS}\">\
         <JobId>{}</JobId><Priority>{priority}</Priority></UpdateJobPriorityResult>",
        job.id
    )))
}

/// UpdateJobStatus: confirms a job awaiting it (`Ready`), or cancels one
/// that hasn't ended (`Cancelled`; an active one is `Cancelling` until its
/// next turn).
pub(crate) async fn update_status(
    app: &App,
    access: &Access,
    account: &str,
    id: &str,
    query: &str,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let requested = query_param(query, "requestedJobStatus").unwrap_or_default();
    if !matches!(requested.as_str(), "Ready" | "Cancelled") {
        return Ok(bad_request(
            "The requested job status must be Ready or Cancelled.",
        ));
    }
    let reason = query_param(query, "statusUpdateReason");
    if reason
        .as_ref()
        .is_some_and(|r| r.is_empty() || r.chars().count() > MAX_REASON)
    {
        return Ok(bad_request(
            "A status update reason is 1 to 256 characters.",
        ));
    }
    let job = match authorized(
        app,
        access,
        account,
        id,
        "s3:UpdateJobStatus",
        &Context::default(),
    )
    .await?
    {
        Ok(job) => job,
        Err(refusal) => return Ok(refusal),
    };
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached(
            "UPDATE batch_jobs SET
                 status = CASE WHEN $2 = 'Ready' THEN 'Ready'
                               WHEN status = 'Active' OR status = 'Cancelling' THEN 'Cancelling'
                               ELSE 'Cancelled' END,
                 terminated_at = CASE WHEN $2 = 'Cancelled' AND status NOT IN ('Active', 'Cancelling') THEN now()
                                      ELSE terminated_at END,
                 suspended_cause = CASE WHEN $2 = 'Ready' THEN NULL ELSE suspended_cause END,
                 status_reason = coalesce($3, status_reason)
             WHERE id = $1 AND CASE WHEN $2 = 'Ready' THEN status = 'Suspended' AND suspended_cause = $4
                                    ELSE status IN ('New', 'Preparing', 'Suspended', 'Ready', 'Active', 'Cancelling') END
             RETURNING status, status_reason",
            &[&job.id, &requested, &reason, &AWAITING_CONFIRMATION],
        )
        .await?;
    let Some(row) = row else {
        let message = match requested.as_str() {
            "Ready" => format!("The job is {}, not awaiting confirmation.", job.status),
            _ => format!("The job is {} already.", job.status),
        };
        return Ok(error(
            StatusCode::BAD_REQUEST,
            "JobStatusException",
            &message,
        ));
    };
    let mut out = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><UpdateJobStatusResult xmlns=\"{CONTROL_XMLNS}\"><JobId>{}</JobId>{}",
        job.id,
        element("Status", row.get(0))
    );
    if let Some(reason) = row.get::<_, Option<&str>>(1) {
        out.push_str(&element("StatusUpdateReason", reason));
    }
    out.push_str("</UpdateJobStatusResult>");
    Ok(xml_ok(out))
}

/// GetJobTagging.
pub(crate) async fn get_tagging(
    app: &App,
    access: &Access,
    account: &str,
    id: &str,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let job = match authorized(
        app,
        access,
        account,
        id,
        "s3:GetJobTagging",
        &Context::default(),
    )
    .await?
    {
        Ok(job) => job,
        Err(refusal) => return Ok(refusal),
    };
    Ok(xml_ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><GetJobTaggingResult xmlns=\"{CONTROL_XMLNS}\">{}</GetJobTaggingResult>",
        tags_xml("Tags", &job.tags)
    )))
}

/// PutJobTagging: replaces the job's tags.
pub(crate) async fn put_tagging(
    app: &App,
    access: &Access,
    account: &str,
    id: &str,
    body: &[u8],
) -> anyhow::Result<Response<Full<Bytes>>> {
    let text_body = std::str::from_utf8(body).map_err(|_| ()).ok();
    let doc = text_body.and_then(|t| roxmltree::Document::parse(t).ok());
    let Some(doc) = doc.filter(|d| d.root_element().tag_name().name() == "PutJobTaggingRequest")
    else {
        return Ok(tags::malformed(""));
    };
    let pairs = match child(doc.root_element(), "Tags") {
        Some(tags) => match tag_members(tags) {
            Ok(pairs) => pairs,
            Err(refused) => return Ok(refused),
        },
        None => return Ok(bad_request("Tags are required.")),
    };
    let tags = match job_tags(pairs) {
        Ok(tags) => tags,
        Err(refused) => return Ok(refused),
    };
    set_tags(app, access, account, id, "s3:PutJobTagging", &tags).await
}

/// DeleteJobTagging: removes the job's tags.
async fn delete_tagging(
    app: &App,
    access: &Access,
    account: &str,
    id: &str,
) -> anyhow::Result<Response<Full<Bytes>>> {
    set_tags(app, access, account, id, "s3:DeleteJobTagging", &[]).await
}

async fn set_tags(
    app: &App,
    access: &Access,
    account: &str,
    id: &str,
    action: &'static str,
    tags: &[(String, String)],
) -> anyhow::Result<Response<Full<Bytes>>> {
    let job = match authorized(app, access, account, id, action, &Context::default()).await? {
        Ok(job) => job,
        Err(refusal) => return Ok(refusal),
    };
    app.pool
        .get()
        .await?
        .execute_cached(
            "UPDATE batch_jobs SET tags = $2 WHERE id = $1",
            &[&job.id, &serde_json::to_string(tags)?],
        )
        .await?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::new()))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(operation: &str, extra: &str) -> String {
        format!(
            "<CreateJobRequest xmlns=\"{CONTROL_XMLNS}\"><ConfirmationRequired>true</ConfirmationRequired>\
             <Operation>{operation}</Operation><Report><Enabled>false</Enabled></Report>\
             <ClientRequestToken>t1</ClientRequestToken>\
             <Manifest><Spec><Format>S3BatchOperations_CSV_20180820</Format>\
             <Fields><member>Bucket</member><member>Key</member></Fields></Spec>\
             <Location><ObjectArn>arn:aws:s3:::m/dir/manifest.csv</ObjectArn><ETag>\"abc\"</ETag></Location></Manifest>\
             <Priority>10</Priority><RoleArn>arn:aws:iam::123456789012:role/batch</RoleArn>{extra}</CreateJobRequest>"
        )
    }

    const PUT: &str = "<S3PutObjectTagging><TagSet><member><Key>b</Key><Value>2</Value></member>\
                       <member><Key>a</Key><Value>1</Value></member></TagSet></S3PutObjectTagging>";

    fn refusal(body: &str) -> (u16, String) {
        let response = parse_create(body.as_bytes()).unwrap_err();
        let status = response.status().as_u16();
        let body = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                use http_body_util::BodyExt;
                response.into_body().collect().await.unwrap().to_bytes()
            });
        let body = String::from_utf8(body.to_vec()).unwrap();
        (
            status,
            body.split("<Code>")
                .nth(1)
                .unwrap()
                .split("</Code>")
                .next()
                .unwrap()
                .to_owned(),
        )
    }

    #[test]
    fn create_requests_are_parsed() {
        let job =
            parse_create(request(PUT, "<Description>tag them</Description>").as_bytes()).unwrap();
        assert!(job.confirmation);
        assert_eq!(
            job.operation,
            Operation::PutTagging {
                tags: vec![("a".into(), "1".into()), ("b".into(), "2".into())]
            }
        );
        assert_eq!(job.token, "t1");
        assert_eq!(job.manifest.bucket, "m");
        assert_eq!(job.manifest.key, "dir/manifest.csv");
        assert_eq!(job.manifest.fields, ["Bucket", "Key"]);
        assert_eq!(job.manifest.etag.trim_matches('"'), "abc");
        assert_eq!(job.priority, 10);
        assert_eq!(job.description.as_deref(), Some("tag them"));
        let job = parse_create(request("<S3DeleteObjectTagging/>", "").as_bytes()).unwrap();
        assert_eq!(job.operation, Operation::DeleteTagging);
        let job = parse_create(request("<S3ReplicateObject/>", "").as_bytes()).unwrap();
        assert_eq!(job.operation, Operation::Replicate);
        assert_eq!(
            super::operation_xml(&job.operation),
            "<Operation><S3ReplicateObject/></Operation>"
        );
    }

    #[test]
    fn what_cairn_doesnt_do_is_not_implemented() {
        let acl = "<S3PutObjectAcl><AccessControlPolicy><CannedAccessControlList>private</CannedAccessControlList>\
                   </AccessControlPolicy></S3PutObjectAcl>";
        assert_eq!(
            refusal(&request(acl, "")),
            (501, "NotImplemented".to_owned())
        );
        let copy = "<S3PutObjectCopy><TargetResource>arn:aws:s3:::b</TargetResource>\
                    <RequesterPays>true</RequesterPays></S3PutObjectCopy>";
        assert_eq!(
            refusal(&request(copy, "")),
            (501, "NotImplemented".to_owned())
        );
    }

    #[test]
    fn copies_are_parsed_and_described() {
        let copy = "<S3PutObjectCopy><TargetResource>arn:aws:s3:::b</TargetResource>\
                    <TargetKeyPrefix>copies/</TargetKeyPrefix></S3PutObjectCopy>";
        let job = parse_create(request(copy, "").as_bytes()).unwrap();
        let Operation::Copy(parsed) = &job.operation else {
            panic!("{:?}", job.operation)
        };
        assert_eq!(parsed.bucket(), "b");
        assert_eq!(job.operation.name(), "S3PutObjectCopy");
        assert_eq!(
            operation_xml(&job.operation),
            format!("<Operation>{copy}</Operation>")
        );
    }

    #[test]
    fn object_lock_operations_are_parsed() {
        let retention =
            |inner: &str| format!("<S3PutObjectRetention>{inner}</S3PutObjectRetention>");
        let job = parse_create(
            request(
                &retention(
                    "<BypassGovernanceRetention>true</BypassGovernanceRetention>\
                     <Retention><RetainUntilDate>2100-01-01T00:00:00Z</RetainUntilDate><Mode>COMPLIANCE</Mode></Retention>",
                ),
                "",
            )
            .as_bytes(),
        )
        .unwrap();
        let until = Some("2100-01-01T00:00:00Z".to_owned());
        assert_eq!(
            job.operation,
            Operation::PutRetention {
                mode: Some("COMPLIANCE".to_owned()),
                until,
                bypass: true
            }
        );
        assert!(operation_xml(&job.operation).contains("<Mode>COMPLIANCE</Mode>"));
        // Neither removes a retention.
        let job = parse_create(request(&retention("<Retention/>"), "").as_bytes()).unwrap();
        assert_eq!(
            job.operation,
            Operation::PutRetention {
                mode: None,
                until: None,
                bypass: false
            }
        );
        let bad = (400, "BadRequestException".to_owned());
        assert_eq!(refusal(&request(&retention(""), "")), bad);
        assert_eq!(
            refusal(&request(
                &retention("<Retention><Mode>COMPLIANCE</Mode></Retention>"),
                ""
            )),
            bad
        );
        let past = "<Retention><RetainUntilDate>2000-01-01T00:00:00Z</RetainUntilDate><Mode>GOVERNANCE</Mode></Retention>";
        assert_eq!(refusal(&request(&retention(past), "")), bad);
        let lower = "<Retention><RetainUntilDate>2100-01-01T00:00:00Z</RetainUntilDate><Mode>governance</Mode></Retention>";
        assert_eq!(refusal(&request(&retention(lower), "")), bad);
        let event = "<Retention><EventHold>ON</EventHold></Retention>";
        assert_eq!(
            refusal(&request(&retention(event), "")),
            (501, "NotImplemented".to_owned())
        );

        let hold = |status: &str| {
            format!(
                "<S3PutObjectLegalHold><LegalHold><Status>{status}</Status></LegalHold></S3PutObjectLegalHold>"
            )
        };
        let job = parse_create(request(&hold("ON"), "").as_bytes()).unwrap();
        assert_eq!(job.operation, Operation::PutLegalHold { on: true });
        assert_eq!(refusal(&request(&hold("on"), "")), bad);
    }

    #[test]
    fn inventory_reports_are_manifests() {
        let inventory = request(PUT, "")
            .replace(
                "S3BatchOperations_CSV_20180820",
                "S3InventoryReport_CSV_20161130",
            )
            .replace(
                "<Fields><member>Bucket</member><member>Key</member></Fields>",
                "",
            );
        let job = parse_create(inventory.as_bytes()).unwrap();
        assert_eq!(job.manifest.format, "S3InventoryReport_CSV_20161130");
        assert!(job.manifest.fields.is_empty());
        let csv = request(PUT, "").replace(
            "<Fields><member>Bucket</member><member>Key</member></Fields>",
            "",
        );
        assert_eq!(refusal(&csv), (400, "BadRequestException".to_owned()));
    }

    #[test]
    fn reports_are_checked() {
        let with = |report: &str| {
            request(PUT, "").replace("<Report><Enabled>false</Enabled></Report>", report)
        };
        let job = parse_create(
            with("<Report><Bucket>arn:aws:s3:::reports</Bucket><Format>Report_CSV_20180820</Format>\
                  <Enabled>true</Enabled><Prefix>batch</Prefix><ReportScope>FailedTasksOnly</ReportScope></Report>")
                .as_bytes(),
        )
        .unwrap();
        assert!(job.report.enabled);
        assert_eq!(job.report.scope.as_deref(), Some("FailedTasksOnly"));
        let bad = (400, "BadRequestException".to_owned());
        assert_eq!(
            refusal(&with("<Report><Enabled>true</Enabled></Report>")),
            bad
        );
        assert_eq!(
            refusal(&with(
                "<Report><Bucket>arn:aws:s3:::reports</Bucket><Enabled>true</Enabled></Report>"
            )),
            bad
        );
        assert_eq!(
            refusal(&with(
                "<Report><Bucket>reports</Bucket><Format>Report_CSV_20180820</Format><Enabled>true</Enabled></Report>"
            )),
            bad
        );
        assert_eq!(
            refusal(&with(
                "<Report><Bucket>arn:aws:s3:::reports</Bucket><Format>Report_CSV_20180820</Format>\
                 <Enabled>true</Enabled><ReportScope>Some</ReportScope></Report>"
            )),
            bad
        );
    }

    #[test]
    fn bad_requests_are_refused() {
        let bad = (400, "BadRequestException".to_owned());
        assert_eq!(
            refusal(&request(&(PUT.to_owned() + "<S3DeleteObjectTagging/>"), "")),
            bad
        );
        assert_eq!(refusal(&request("<S3Nothing/>", "")), bad);
        assert_eq!(
            refusal(
                &request(PUT, "").replace("<Priority>10</Priority>", "<Priority>-1</Priority>")
            ),
            bad
        );
        assert_eq!(
            refusal(&request(PUT, "").replace("role/batch", "user/batch")),
            bad
        );
        assert_eq!(
            refusal(&request(PUT, "").replace("<member>Key</member>", "")),
            bad
        );
        assert_eq!(
            refusal(&request(PUT, "").replace("<ETag>\"abc\"</ETag>", "<ETag></ETag>")),
            bad
        );
        assert_eq!(
            refusal(&request(PUT, "").replace("m/dir/manifest.csv", "m")),
            bad
        );
        assert_eq!(refusal(&request(PUT, "").replace("t1", "")), bad);
        let tags: String = (0..11)
            .map(|i| format!("<member><Key>k{i}</Key><Value>v</Value></member>"))
            .collect();
        let many = format!("<S3PutObjectTagging><TagSet>{tags}</TagSet></S3PutObjectTagging>");
        assert_eq!(refusal(&request(&many, "")).0, 400);
        assert_eq!(refusal("<CreateJobRequest>").1, "MalformedXML");
    }

    #[test]
    fn requests_are_routed() {
        assert!(matches!(
            op(&Method::POST, "/v20180820/jobs"),
            Some(Op::Create)
        ));
        assert!(matches!(
            op(&Method::GET, "/v20180820/jobs"),
            Some(Op::List)
        ));
        assert!(
            matches!(op(&Method::GET, "/v20180820/jobs/abc"), Some(Op::Describe(id)) if id == "abc")
        );
        assert!(matches!(
            op(&Method::POST, "/v20180820/jobs/abc/status"),
            Some(Op::Status(_))
        ));
        assert!(matches!(
            op(&Method::POST, "/v20180820/jobs/abc/priority"),
            Some(Op::Priority(_))
        ));
        assert!(matches!(
            op(&Method::DELETE, "/v20180820/jobs/abc/tagging"),
            Some(Op::DeleteTagging(_))
        ));
        assert!(op(&Method::DELETE, "/v20180820/jobs/abc").is_none());
        assert!(op(&Method::GET, "/v20180820/jobsx").is_none());
    }

    #[test]
    fn next_tokens_round_trip() {
        let id = Uuid::new_v4();
        assert_eq!(
            decode_token(&encode_token(1_700_000_000_123_456, id)),
            Some((1_700_000_000_123_456, id))
        );
        assert_eq!(decode_token("nope"), None);
    }
}
