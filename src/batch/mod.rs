//! S3 Batch Operations: jobs that do one operation to each object of a
//! manifest, as S3 Control's CreateJob asks (see `control`, and `manifest`
//! for the manifest's format), acting as the role it names.
//!
//! Only some of S3's operations, and not all of how they're asked for:
//!
//! - Operations: `S3PutObjectTagging` (replacing each version's tags) and
//!   `S3DeleteObjectTagging`. Doing either twice does no harm, which a job
//!   relies on (below). Others are refused with 501 NotImplemented.
//! - Manifests: CSV objects (`S3BatchOperations_CSV_20180820`) only; not
//!   inventory reports' `manifest.json`, nor manifests S3 generates.
//! - Completion reports: none (`Report` must have `Enabled` false); a job's
//!   counts of tasks that succeeded and failed are all it tells.
//!
//! A job goes through S3's statuses: `New` when it's created, `Preparing`
//! while its manifest is read through (each line checked, and counted:
//! its `TotalNumberOfTasks`), then `Suspended` until UpdateJobStatus
//! confirms it if CreateJob asked for that (`ConfirmationRequired`), else
//! (and then) `Ready`, `Active` once its tasks start, and `Complete` when
//! the last is done. A job whose manifest or role can't be used, or whose
//! tasks fail too often (more than half of them, once a thousand have
//! been done, as S3 counts it), is `Failed`, and says why in its
//! `FailureReasons`. UpdateJobStatus cancels it (`Cancelled`; an `Active`
//! one is `Cancelling` until its next turn).
//!
//! Jobs take turns in the steps the cluster takes lifecycle sweeps and
//! inventory reports in (see `lifecycle`), sharing their rate: each task is
//! one of the versions read an hour the rate allows (preparing reads the
//! manifest only, and takes none of it, but at most `PREPARE_BYTES` of it a
//! turn). Among jobs, the highest priority goes first, then the one that
//! has waited longest. A turn reads its manifest a page of lines at a time,
//! by byte ranges, pinned to its ETag (If-Match), so that a manifest
//! changed under a job fails it rather than changing what it does; and
//! saves where it has got to after each page (`batch_jobs.cursor`), with
//! the counts of what succeeded and failed. A node that dies mid-page
//! leaves its page to be done again by another: its tasks were done, but
//! not counted, and are done and counted again, which is why only
//! operations that can be repeated are run.
//!
//! A job acts as its role, as S3 assumes it: as the
//! `batchoperations.s3.amazonaws.com` service, which the role's trust
//! policy must allow (with `aws:SourceAccount` and `aws:SourceArn` the
//! job's account and ARN, for its conditions). Each task is authorized as
//! a request of that role's session would be, by its policies and the
//! bucket's, and so is reading the manifest (`s3:GetObject`). Its writes'
//! events (see `notifications`) name the session.
//!
//! A job is kept for 90 days after it ends, as S3 keeps them.

pub mod control;
pub mod manifest;

use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use deadpool_postgres::Object;
use http_body_util::BodyExt;
use hyper::{HeaderMap, Method, StatusCode, body::Bytes, header};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::Cached;
use crate::{
    App,
    policy::{Context, Decision, Kind, Policy, Principal as Who, Request},
    s3::{
        access::{Access, Origin},
        actions, conditional::Preconditions,
        objects::{get::get_object, tagging::{self, Outcome, Tagging}},
        tags::Tags,
    },
    users::Principal,
};

use manifest::{Field, Task};

/// The service a job's role is assumed as.
pub const SERVICE: &str = "batchoperations.s3.amazonaws.com";
/// The name of the role sessions jobs act as.
const SESSION_NAME: &str = "s3-batch-operations";
/// The region of jobs' ARNs: as every bucket's (see `S3-COMPATIBILITY.md`).
const REGION: &str = "us-east-1";

/// The most tasks done at a time: a page of the manifest.
const PAGE: usize = 1000;
/// How much of the manifest is read at a time: a page's lines, or as
/// many as are in it. A line longer than it fails the job (keys are at
/// most 1 KiB, 3 URL-encoded).
const CHUNK: u64 = 1 << 20;
/// The most of a manifest a turn of preparing reads.
const PREPARE_BYTES: u64 = 64 << 20;
/// After how many tasks a job fails if more than half have.
const FAILURE_THRESHOLD_AFTER: i64 = 1000;
/// How long a job is kept after it ends.
const KEPT: Duration = Duration::from_secs(90 * 24 * 3600);
/// How long a job's role session is good for (it's never handed out: the
/// job's own turns use it).
const SESSION: u64 = 3600;
/// The longest failure reason, as S3's are (`JobFailureReason`).
const MAX_REASON: usize = 256;

/// Statuses a job ends in.
pub const TERMINAL: &[&str] = &["Complete", "Cancelled", "Failed"];
/// What `SuspendedCause` says of a job waiting for UpdateJobStatus to
/// confirm it.
pub const AWAITING_CONFIRMATION: &str = "AWAITING_CONFIRMATION";

/// A job's ARN.
pub fn arn(account: &str, id: Uuid) -> String {
    format!("arn:aws:s3:{REGION}:{account}:job/{id}")
}

/// What a job does to each object, as it's kept (JSON).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum Operation {
    /// Replaces each version's tags with these.
    #[serde(rename = "put_tagging")]
    PutTagging { tags: Vec<(String, String)> },
    /// Removes each version's tags.
    #[serde(rename = "delete_tagging")]
    DeleteTagging,
}

impl Operation {
    /// Its name, as S3 Control has it (`OperationName`).
    pub fn name(&self) -> &'static str {
        match self {
            Operation::PutTagging { .. } => "S3PutObjectTagging",
            Operation::DeleteTagging => "S3DeleteObjectTagging",
        }
    }
}

/// A job's manifest, as CreateJob gave it (JSON).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: String,
    pub fields: Vec<String>,
    /// Its object, by its ARN as given, and as a bucket and key.
    pub arn: String,
    pub bucket: String,
    pub key: String,
    pub version_id: Option<String>,
    /// Its ETag, as given (quoted or not).
    pub etag: String,
}

impl Manifest {
    fn fields(&self) -> Vec<Field> {
        self.fields.iter().filter_map(|f| Field::parse(f)).collect()
    }

    /// Its ETag, quoted, as If-Match has it.
    fn if_match(&self) -> String {
        format!("\"{}\"", self.etag.trim_matches('"'))
    }
}

/// A job's completion report, as CreateJob gave it (JSON): only told back.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub enabled: bool,
    pub bucket: Option<String>,
    pub format: Option<String>,
    pub prefix: Option<String>,
    pub scope: Option<String>,
    pub expected_owner: Option<String>,
}

/// Why a job failed, as its `FailureReasons` say it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    pub code: String,
    pub reason: String,
}

impl Failure {
    fn new(code: &str, reason: impl Into<String>) -> Failure {
        let mut reason: String = reason.into();
        if reason.len() > MAX_REASON {
            let mut end = MAX_REASON;
            while !reason.is_char_boundary(end) {
                end -= 1;
            }
            reason.truncate(end);
        }
        Failure { code: code.to_owned(), reason }
    }
}

/// A job, as a turn takes it.
pub(crate) struct Job {
    pub id: Uuid,
    pub account: String,
    pub status: String,
    operation: Operation,
    manifest: Manifest,
    role_arn: String,
    prepared: i64,
    total: i64,
    cursor: i64,
    succeeded: i64,
    failed: i64,
}

/// What a turn of a job did.
#[derive(Debug, Default, PartialEq)]
pub struct Turn {
    pub id: Uuid,
    /// Tasks done, and of them, how many succeeded.
    pub tasks: i64,
    pub succeeded: i64,
    /// Manifest lines read through while preparing.
    pub prepared: i64,
    /// Its status after the turn.
    pub status: String,
    /// Why the job failed, if it did.
    pub failure: Option<Failure>,
    /// The first task that failed, and why.
    pub failed_task: Option<String>,
}

impl std::fmt::Display for Turn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "job {}: ", self.id)?;
        if self.prepared > 0 {
            write!(f, "{} tasks found, ", self.prepared)?;
        }
        if self.tasks > 0 {
            write!(f, "{} tasks done ({} failed), ", self.tasks, self.tasks - self.succeeded)?;
        }
        write!(f, "{}", self.status)?;
        if let Some(failure) = &self.failure {
            write!(f, ": {}: {}", failure.code, failure.reason)?;
        }
        if let Some(task) = &self.failed_task {
            write!(f, " (first failed task: {task})")?;
        }
        Ok(())
    }
}

/// Forgets the jobs that ended more than 90 days before `now`, a few at a
/// time.
pub(crate) async fn forget_old(client: &Object, now: SystemTime) -> anyhow::Result<()> {
    client
        .execute_cached(
            "DELETE FROM batch_jobs WHERE id IN (
                 SELECT id FROM batch_jobs WHERE terminated_at < $1 ORDER BY terminated_at LIMIT 100)",
            &[&(now - KEPT)],
        )
        .await?;
    Ok(())
}

/// The job whose turn is next, but for those `visited` this step already,
/// and since when it has waited.
pub(crate) async fn next(client: &Object, visited: &[Uuid]) -> anyhow::Result<Option<(SystemTime, Job)>> {
    let row = client
        .query_opt_cached(
            "SELECT id, account_id, status, operation, manifest, role_arn, prepared, total, cursor,
                    succeeded, failed, waiting_since
             FROM batch_jobs
             WHERE status IN ('New', 'Preparing', 'Ready', 'Active', 'Cancelling') AND NOT (id = ANY($1))
             ORDER BY priority DESC, waiting_since LIMIT 1",
            &[&visited],
        )
        .await?;
    let Some(row) = row else { return Ok(None) };
    let operation: String = row.get(3);
    let manifest: String = row.get(4);
    let job = Job {
        id: row.get(0),
        account: row.get(1),
        status: row.get(2),
        operation: serde_json::from_str(&operation)?,
        manifest: serde_json::from_str(&manifest)?,
        role_arn: row.get(5),
        prepared: row.get(6),
        total: row.get(7),
        cursor: row.get(8),
        succeeded: row.get(9),
        failed: row.get(10),
    };
    Ok(Some((row.get(11), job)))
}

/// Takes a turn of `job`: prepares it, or does its tasks as far as
/// `budget` (versions to read) allows, taking off what it does.
pub(crate) async fn turn(
    app: &Arc<App>,
    client: &Object,
    job: Job,
    now: SystemTime,
    budget: &mut i64,
) -> anyhow::Result<Turn> {
    let mut turn = Turn { id: job.id, status: job.status.clone(), ..Turn::default() };
    match job.status.as_str() {
        "Cancelling" => {
            end(client, &job, "Cancelled", None, now).await?;
            turn.status = "Cancelled".to_owned();
        }
        "New" | "Preparing" => prepare(app, client, &job, now, &mut turn).await?,
        _ => run(app, client, &job, now, budget, &mut turn).await?,
    }
    Ok(turn)
}

/// Ends the job as `status` (`Complete`, `Cancelled`, or `Failed` with
/// `failure`), unless it ended meanwhile.
async fn end(client: &Object, job: &Job, status: &str, failure: Option<&Failure>, now: SystemTime) -> anyhow::Result<()> {
    let failures = serde_json::to_string(&failure.into_iter().collect::<Vec<_>>())?;
    client
        .execute_cached(
            "UPDATE batch_jobs SET status = $2, terminated_at = $3, waiting_since = $3, failures = (failures::jsonb || $4::text::jsonb)::text
             WHERE id = $1 AND status IN ('New', 'Preparing', 'Ready', 'Active', 'Cancelling')",
            &[&job.id, &status, &now, &failures],
        )
        .await?;
    Ok(())
}

/// Fails the job, as `turn` tells.
async fn fail(client: &Object, job: &Job, failure: Failure, now: SystemTime, turn: &mut Turn) -> anyhow::Result<()> {
    end(client, job, "Failed", Some(&failure), now).await?;
    turn.status = "Failed".to_owned();
    turn.failure = Some(failure);
    Ok(())
}

/// Reads the job's manifest through from where preparing it got to, as
/// far as `PREPARE_BYTES` goes, checking and counting its lines; once
/// it's at the end, the job is ready (or suspended, to be confirmed).
async fn prepare(app: &Arc<App>, client: &Object, job: &Job, now: SystemTime, turn: &mut Turn) -> anyhow::Result<()> {
    let principal = match session(client, job).await? {
        Ok(principal) => principal,
        Err(failure) => return fail(client, job, failure, now, turn).await,
    };
    if let Err(failure) = may_read_manifest(app, &principal, &job.manifest).await? {
        return fail(client, job, failure, now, turn).await;
    }
    let fields = job.manifest.fields();
    let mut prepared = job.prepared as u64;
    let mut total = job.total;
    let mut done = false;
    let start = prepared;
    while prepared - start < PREPARE_BYTES {
        let chunk = match read(app, &job.manifest, principal.id, prepared).await? {
            Ok(chunk) => chunk,
            Err(failure) => return fail(client, job, failure, now, turn).await,
        };
        let (lines, consumed) = manifest::lines(&chunk.data, chunk.last, usize::MAX);
        for line in lines {
            let parsed = std::str::from_utf8(line)
                .map_err(|_| "it isn't UTF-8".to_owned())
                .and_then(|line| manifest::parse_line(line, &fields));
            if let Err(why) = parsed {
                let failure = Failure::new("ManifestInvalid", format!("Line {} of the manifest isn't a task: {why}.", total + 1));
                return fail(client, job, failure, now, turn).await;
            }
            total += 1;
            turn.prepared += 1;
        }
        prepared += consumed as u64;
        if chunk.last && consumed == chunk.data.len() {
            done = true;
            break;
        }
        if consumed == 0 {
            let failure = Failure::new("ManifestInvalid", format!("Line {} of the manifest is too long.", total + 1));
            return fail(client, job, failure, now, turn).await;
        }
    }
    let row = client
        .query_opt_cached(
            "UPDATE batch_jobs SET prepared = $2, total = $3::bigint, waiting_since = $4,
                 status = CASE WHEN NOT $5::boolean THEN 'Preparing'
                               WHEN $3::bigint = 0 THEN 'Complete'
                               WHEN confirmation THEN 'Suspended'
                               ELSE 'Ready' END,
                 suspended_at = CASE WHEN $5::boolean AND $3::bigint > 0 AND confirmation THEN $4::timestamptz END,
                 suspended_cause = CASE WHEN $5::boolean AND $3::bigint > 0 AND confirmation THEN $6::text END,
                 terminated_at = CASE WHEN $5::boolean AND $3::bigint = 0 THEN $4::timestamptz END
             WHERE id = $1 AND status IN ('New', 'Preparing')
             RETURNING status",
            &[&job.id, &(prepared as i64), &total, &now, &done, &AWAITING_CONFIRMATION],
        )
        .await?;
    turn.status = row.map_or_else(|| "Cancelled".to_owned(), |row| row.get(0));
    Ok(())
}

/// Does the job's tasks, a page at a time, as far as `budget` allows.
async fn run(
    app: &Arc<App>,
    client: &Object,
    job: &Job,
    now: SystemTime,
    budget: &mut i64,
    turn: &mut Turn,
) -> anyhow::Result<()> {
    let principal = match session(client, job).await? {
        Ok(principal) => principal,
        Err(failure) => return fail(client, job, failure, now, turn).await,
    };
    if let Err(failure) = may_read_manifest(app, &principal, &job.manifest).await? {
        return fail(client, job, failure, now, turn).await;
    }
    client
        .execute_cached("UPDATE batch_jobs SET status = 'Active' WHERE id = $1 AND status = 'Ready'", &[&job.id])
        .await?;
    turn.status = "Active".to_owned();
    let account = crate::users::account(client).await?;
    let origin = Origin { peer: None, trusted_proxies: &[], signed: None, form: false };
    let mut access = Access::new(Some(&principal), &account, &Method::PUT, &HeaderMap::new(), "", &origin)?;
    let tags = match &job.operation {
        Operation::PutTagging { tags } => match Tags::from_pairs(tags.clone(), crate::s3::tags::On::Object) {
            Ok(tags) => tags,
            Err(_) => anyhow::bail!("job {}: its stored tags aren't an object's", job.id),
        },
        Operation::DeleteTagging => Tags::default(),
    };
    if matches!(job.operation, Operation::PutTagging { .. }) {
        crate::s3::abac::request_tags(&mut access, &tags);
    }
    let fields = job.manifest.fields();
    let (mut cursor, mut succeeded, mut failed) = (job.cursor as u64, job.succeeded, job.failed);
    // Its tasks' writes are its role session's, as their events say.
    crate::notifications::scope(async {
        crate::notifications::set_requester(Some(principal.unique_id()), None);
        while *budget > 0 {
            let began = std::time::Instant::now();
            let chunk = match read(app, &job.manifest, principal.id, cursor).await? {
                Ok(chunk) => chunk,
                Err(failure) => return fail(client, job, failure, now, turn).await,
            };
            let limit = (*budget).clamp(1, PAGE as i64) as usize;
            let (lines, consumed) = manifest::lines(&chunk.data, chunk.last, limit);
            let finished = chunk.last && consumed == chunk.data.len();
            if lines.is_empty() && !finished {
                let failure = Failure::new("ManifestInvalid", "A line of the manifest is too long.");
                return fail(client, job, failure, now, turn).await;
            }
            for line in &lines {
                let task = std::str::from_utf8(line)
                    .map_err(|_| "it isn't UTF-8".to_owned())
                    .and_then(|line| manifest::parse_line(line, &fields));
                let result = match &task {
                    Ok(task) => run_task(app, &mut access, &job.operation, &tags, task).await?,
                    Err(why) => Err(format!("400 InvalidManifestLine ({why})")),
                };
                match result {
                    Ok(()) => {
                        succeeded += 1;
                        turn.succeeded += 1;
                    }
                    Err(why) => {
                        failed += 1;
                        if turn.failed_task.is_none() {
                            let on = task.map_or_else(|_| "a line".to_owned(), |t| format!("{}/{}", t.bucket, t.key));
                            turn.failed_task = Some(format!("{on}: {why}"));
                        }
                    }
                }
                turn.tasks += 1;
            }
            *budget -= lines.len().max(1) as i64;
            cursor += consumed as u64;
            let row = client
                .query_opt_cached(
                    "UPDATE batch_jobs SET cursor = $2, succeeded = $3, failed = $4,
                         active_seconds = active_seconds + $5, waiting_since = $6
                     WHERE id = $1 AND status IN ('Active', 'Cancelling')
                     RETURNING status",
                    &[&job.id, &(cursor as i64), &succeeded, &failed, &began.elapsed().as_secs_f64(), &now],
                )
                .await?;
            let Some(row) = row else {
                // Ended meanwhile.
                turn.status = "Cancelled".to_owned();
                return Ok(());
            };
            crate::lifecycle::extend(client, now).await?;
            let done = succeeded + failed;
            if done >= FAILURE_THRESHOLD_AFTER && failed * 2 > done {
                let failure = Failure::new(
                    "TaskFailureThresholdExceeded",
                    format!("{failed} of the job's {done} tasks so far failed, more than half of them."),
                );
                return fail(client, job, failure, now, turn).await;
            }
            if finished {
                end(client, job, "Complete", None, now).await?;
                turn.status = "Complete".to_owned();
                return Ok(());
            }
            if row.get::<_, &str>(0) == "Cancelling" {
                end(client, job, "Cancelled", None, now).await?;
                turn.status = "Cancelled".to_owned();
                return Ok(());
            }
        }
        Ok(())
    })
    .await
}

/// Does `operation` to the object of `task`, as `access` (its role's
/// session's) allows it; why not, if it didn't (S3's status and code).
async fn run_task(
    app: &Arc<App>,
    access: &mut Access,
    operation: &Operation,
    tags: &Tags,
    task: &Task,
) -> anyhow::Result<Result<(), String>> {
    let Task { bucket, key, version_id } = task;
    if let Some(v) = version_id.as_deref().filter(|v| !crate::s3::versions::is_version_id(v)) {
        return Ok(Err(format!("400 InvalidArgument (invalid version ID {v})")));
    }
    if crate::s3::directory::is_directory(bucket) {
        return Ok(Err("501 NotImplemented (a directory bucket's objects have no tags)".to_owned()));
    }
    let (method, tagging) = match operation {
        Operation::PutTagging { .. } => (Method::PUT, Tagging::Put),
        Operation::DeleteTagging => (Method::DELETE, Tagging::Delete),
    };
    let mut query = "tagging".to_owned();
    if let Some(v) = version_id {
        query.push_str(&format!("&versionId={}", percent_encoding::utf8_percent_encode(v, percent_encoding::NON_ALPHANUMERIC)));
    }
    if let Err(why) = authorize(app, access, &method, bucket, key, &query).await? {
        return Ok(Err(why));
    }
    Ok(match tagging::set_tags(app, bucket, key, version_id.as_deref(), tags, tagging).await? {
        Outcome::Tagged(_) => Ok(()),
        Outcome::DeleteMarker(_) => Err("405 MethodNotAllowed (a delete marker has no tags)".to_owned()),
        Outcome::NoSuchVersion => Err("404 NoSuchVersion".to_owned()),
        Outcome::NoSuchKey => Err("404 NoSuchKey".to_owned()),
        Outcome::NoSuchBucket => Err("404 NoSuchBucket".to_owned()),
        Outcome::Contended => Err("503 SlowDown".to_owned()),
    })
}

/// Whether `access` allows the request (`method` on `bucket`'s `key`, with
/// `query`), as `s3::handle_request` authorizes it; why not (S3's status
/// and code), if it doesn't.
async fn authorize(
    app: &App,
    access: &mut Access,
    method: &Method,
    bucket: &str,
    key: &str,
    query: &str,
) -> anyhow::Result<Result<(), String>> {
    let headers = HeaderMap::new();
    let Some(operation) = actions::operation(method, bucket, key, query, &headers) else {
        anyhow::bail!("{method} {bucket}/{key}?{query} is no operation");
    };
    access.forget_object_tags();
    let exists = access.load(app, bucket).await?;
    access.load_all(app, &operation.checks).await?;
    crate::s3::abac::prepare(app, access, &operation, bucket, key, query, &headers).await?;
    Ok(match access.first_denied(&operation.checks) {
        None => Ok(()),
        Some(_) if !exists => Err("404 NoSuchBucket".to_owned()),
        Some((check, _)) => Err(format!("403 AccessDenied (the role may not {} on it)", check.action)),
    })
}

/// Whether the job's role session (`principal`) may read its manifest.
async fn may_read_manifest(app: &App, principal: &Principal, manifest: &Manifest) -> anyhow::Result<Result<(), Failure>> {
    let account = crate::users::account(&app.pool.get().await?).await?;
    let origin = Origin { peer: None, trusted_proxies: &[], signed: None, form: false };
    let mut access = Access::new(Some(principal), &account, &Method::GET, &HeaderMap::new(), "", &origin)?;
    let query = match &manifest.version_id {
        Some(v) => format!("versionId={}", percent_encoding::utf8_percent_encode(v, percent_encoding::NON_ALPHANUMERIC)),
        None => String::new(),
    };
    Ok(authorize(app, &mut access, &Method::GET, &manifest.bucket, &manifest.key, &query)
        .await?
        .map_err(|why| Failure::new("ManifestUnreadable", format!("Reading the manifest {} failed: {why}.", manifest.arn))))
}

/// The session of the job's role, assumed as `SERVICE`; why not, if it
/// can't be (no such role, or it doesn't trust the service).
async fn session(client: &Object, job: &Job) -> anyhow::Result<Result<Principal, Failure>> {
    let unusable = |why: &str| Failure::new("RoleUnusable", format!("The role {} {why}.", job.role_arn));
    let Some((path, name)) = role_of_arn(&job.role_arn, &job.account) else {
        return Ok(Err(unusable("isn't one of the account's")));
    };
    let Some(role) = crate::roles::Role::load(client, &job.account, name).await?.filter(|r| r.path == path && r.name == name)
    else {
        return Ok(Err(unusable("doesn't exist")));
    };
    let trust = Policy::parse(&role.trust, Kind::Trust)
        .map_err(|e| anyhow::anyhow!("role {}'s trust policy doesn't parse: {}", role.name, e.message))?
        .with_ids(role.trust_principals.clone());
    let mut context = Context::default();
    context.set("aws:SourceAccount", &job.account);
    context.set("aws:SourceArn", arn(&job.account, job.id));
    let role_arn = role.arn();
    let request = Request { principal: Who::Service { name: SERVICE }, action: "sts:AssumeRole", resource: &role_arn, context: &context };
    if trust.evaluate_trust(&request).0 != Decision::Allow {
        return Ok(Err(unusable(&format!("doesn't trust {SERVICE} to assume it"))));
    }
    let now = crate::sessions::now();
    let session = crate::sessions::Session {
        key_id: String::new(),
        secret: String::new(),
        issued: now,
        expires: now + SESSION,
        who: crate::sessions::Who::Role { id: role.id, session: SESSION_NAME.to_owned() },
        policy: None,
        policy_arns: Vec::new(),
        tags: Vec::new(),
        transitive: Vec::new(),
        source_identity: None,
        chained: false,
        provider: None,
        directory: None,
        access_grants: None,
    };
    Ok(match Principal::of_session(client, session).await? {
        Ok(principal) => Ok(principal),
        Err(_) => Err(unusable("doesn't exist")),
    })
}

/// A role's path and name, from its ARN, if it's `account`'s.
pub(crate) fn role_of_arn<'a>(arn: &'a str, account: &str) -> Option<(String, &'a str)> {
    let rest = arn.strip_prefix("arn:aws:iam::")?.strip_prefix(account)?.strip_prefix(":role/")?;
    let (path, name) = match rest.rsplit_once('/') {
        Some((path, name)) => (format!("/{path}/"), name),
        None => ("/".to_owned(), rest),
    };
    (!name.is_empty()).then_some((path, name))
}

/// Some of a manifest, read from `from`.
struct Chunk {
    data: Bytes,
    /// Whether it's the rest of the manifest.
    last: bool,
}

/// Reads up to `CHUNK` bytes of the manifest from `from`, as long as it's
/// still the one of its ETag (as the role `role` asks the KMS for its key,
/// if it's SSE-KMS); why it can't be, if it can't.
async fn read(app: &Arc<App>, manifest: &Manifest, role: Uuid, from: u64) -> anyhow::Result<Result<Chunk, Failure>> {
    let mut headers = HeaderMap::new();
    headers.insert(header::IF_MATCH, manifest.if_match().parse()?);
    let preconditions = Preconditions::from_headers(&headers);
    let range = format!("bytes={from}-{}", from + CHUNK - 1);
    let response = get_object(
        app,
        &manifest.bucket,
        &manifest.key,
        manifest.version_id.as_deref(),
        Some(&range),
        None,
        &preconditions,
        None,
        Some(role),
        false,
    )
    .await?;
    let status = response.status();
    let unreadable = |why: String| Ok(Err(Failure::new("ManifestUnreadable", format!("Reading the manifest {} failed: {why}.", manifest.arn))));
    match status {
        StatusCode::OK | StatusCode::PARTIAL_CONTENT => {}
        // Past its end: there's no more.
        StatusCode::RANGE_NOT_SATISFIABLE => return Ok(Ok(Chunk { data: Bytes::new(), last: true })),
        StatusCode::PRECONDITION_FAILED => {
            return Ok(Err(Failure::new(
                "ManifestETagMismatch",
                format!("The manifest {} isn't the one of ETag {} any more.", manifest.arn, manifest.etag),
            )));
        }
        _ => {
            let body = response.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
            let body = String::from_utf8_lossy(&body);
            let code = body.split("<Code>").nth(1).and_then(|s| s.split("</Code>").next()).unwrap_or("");
            return unreadable(format!("{} {code}", status.as_u16()));
        }
    }
    // Its size, from `Content-Range` (`bytes a-b/size`).
    let size = response
        .headers()
        .get(header::CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit_once('/'))
        .and_then(|(_, size)| size.parse::<u64>().ok());
    let data = response.into_body().collect().await.map_err(|e| anyhow::anyhow!("reading the manifest: {e}"))?.to_bytes();
    let last = match size {
        Some(size) => from + data.len() as u64 >= size,
        // The whole of it.
        None => status == StatusCode::OK,
    };
    Ok(Ok(Chunk { data, last }))
}

#[cfg(test)]
mod e2e;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_are_named_by_their_arns() {
        let account = "123456789012";
        assert_eq!(role_of_arn("arn:aws:iam::123456789012:role/batch", account), Some(("/".to_owned(), "batch")));
        assert_eq!(role_of_arn("arn:aws:iam::123456789012:role/ops/batch", account), Some(("/ops/".to_owned(), "batch")));
        assert_eq!(role_of_arn("arn:aws:iam::999999999999:role/batch", account), None);
        assert_eq!(role_of_arn("arn:aws:iam::123456789012:user/batch", account), None);
        assert_eq!(role_of_arn("arn:aws:iam::123456789012:role/", account), None);
    }

    #[test]
    fn failure_reasons_are_short() {
        let failure = Failure::new("X", "é".repeat(200));
        assert!(failure.reason.len() <= MAX_REASON);
        assert!(failure.reason.chars().all(|c| c == 'é'));
    }

    #[test]
    fn operations_are_kept_as_json() {
        let put = Operation::PutTagging { tags: vec![("a".to_owned(), "1".to_owned())] };
        let json = serde_json::to_string(&put).unwrap();
        assert_eq!(json, r#"{"t":"put_tagging","tags":[["a","1"]]}"#);
        assert_eq!(serde_json::from_str::<Operation>(&json).unwrap(), put);
        assert_eq!(serde_json::from_str::<Operation>(r#"{"t":"delete_tagging"}"#).unwrap(), Operation::DeleteTagging);
    }
}
