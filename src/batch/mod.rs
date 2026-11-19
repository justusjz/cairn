//! S3 Batch Operations: jobs that do one operation to each object of a
//! manifest, as S3 Control's CreateJob asks (see `control`, and `manifest`
//! for the manifest's format), acting as the role it names.
//!
//! Only some of S3's operations, and not all of how they're asked for:
//!
//! - Operations: `S3PutObjectTagging` (replacing each version's tags),
//!   `S3DeleteObjectTagging`, `S3PutObjectRetention` and
//!   `S3PutObjectLegalHold` (see `s3::object_lock`), `S3ReplicateObject`
//!   (Batch Replication: each version is queued to be replicated by its
//!   bucket's replication configuration, as a new version is; see
//!   `replicate`), and `S3PutObjectCopy` (see `copy`). Doing any but a copy
//!   twice does no harm, which a job relies on (below): a retention set
//!   again is set to the same date, which isn't shortening it, and a
//!   version is queued once; a copy is recorded with the version it
//!   writes, so that it's done once (see `copy`). Others are refused with
//!   501 NotImplemented.
//! - Manifests: CSV objects (`S3BatchOperations_CSV_20180820`), and
//!   inventory reports (`S3InventoryReport_CSV_20161130`, `…_20211130`) of
//!   CSV or Parquet (see `source`); or, with a manifest generator, one the
//!   job generates from a bucket's objects, while it's prepared, before it
//!   prepares that (see `generate`).
//! - Completion reports: as S3 writes them, of all tasks or only those that
//!   failed (see `report`).
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
//! has waited longest. A turn reads its manifest a page of lines at a time
//! (see `source`), pinned to its ETag (If-Match), so that a manifest
//! changed under a job fails it rather than changing what it does; and
//! saves where it has got to after each page (`batch_jobs.cursor`), with
//! the counts of what succeeded and failed, and the page's result files,
//! if it has a report. A node that dies mid-page
//! leaves its page to be done again by another: its tasks were done, but
//! not counted, and are done and counted again, which is why only
//! operations that can be repeated are run, or, a copy, that are recorded
//! as they're done.
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
pub mod copy;
pub mod generate;
pub mod manifest;
mod parquet;
pub mod report;
pub mod source;

use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use deadpool_postgres::Object;
use hyper::{HeaderMap, Method};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::Cached;
use crate::{
    App,
    policy::{Context, Decision, Kind, Policy, Principal as Who, Request},
    s3::{
        access::{Access, Origin},
        actions,
        object_lock::{Change, Mode, Outcome as LockOutcome, parse_date},
        objects::tagging::{self, Outcome, Tagging},
        tags::Tags,
    },
    users::Principal,
};

use manifest::{Field, Task};
use report::{Line, TaskFailure, Writer};
use source::{DataRows, Inventory, Position, Source};

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
    /// Sets each version's retention: a mode (`GOVERNANCE`, `COMPLIANCE`)
    /// and the time it lasts until, as given (ISO 8601); neither removes it.
    /// With `bypass`, it may shorten or remove a GOVERNANCE one, if the
    /// role is allowed `s3:BypassGovernanceRetention`.
    #[serde(rename = "put_retention")]
    PutRetention { mode: Option<String>, until: Option<String>, bypass: bool },
    /// Puts each version's legal hold on, or lifts it.
    #[serde(rename = "put_legal_hold")]
    PutLegalHold { on: bool },
    /// Replicates each version by its bucket's replication configuration
    /// (Batch Replication; see `replicate`).
    #[serde(rename = "replicate")]
    Replicate,
    /// Copies each version (see `copy`).
    #[serde(rename = "copy")]
    Copy(Box<copy::Copy>),
}

impl Operation {
    /// Its name, as S3 Control has it (`OperationName`).
    pub fn name(&self) -> &'static str {
        match self {
            Operation::PutTagging { .. } => "S3PutObjectTagging",
            Operation::DeleteTagging => "S3DeleteObjectTagging",
            Operation::PutRetention { .. } => "S3PutObjectRetention",
            Operation::PutLegalHold { .. } => "S3PutObjectLegalHold",
            Operation::Replicate => "S3ReplicateObject",
            Operation::Copy(_) => "S3PutObjectCopy",
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
    /// Whether the job generated it (see `generate`): Cairn wrote it and
    /// its data files, which the role need not be allowed to read.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub generated: bool,
}

impl Manifest {
    fn fields(&self) -> Vec<Field> {
        self.fields.iter().filter_map(|f| Field::parse(f)).collect()
    }
}

/// A job's completion report, as CreateJob gave it (JSON); see `report`.
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
    report: Report,
    role_arn: String,
    /// Its manifest generator, if it has one, and where generating its
    /// manifest has got to (see `generate`).
    generator: Option<generate::Generator>,
    generation: Option<generate::Generation>,
    /// Its inventory report's data files, once preparing has read its
    /// manifest (if its manifest is one).
    inventory: Option<Inventory>,
    prepared: Position,
    total: i64,
    cursor: Position,
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
                    succeeded, failed, waiting_since, report, prepared_file, cursor_file, inventory,
                    generator, generation
             FROM batch_jobs
             WHERE status IN ('New', 'Preparing', 'Ready', 'Active', 'Cancelling') AND NOT (id = ANY($1))
             ORDER BY priority DESC, waiting_since LIMIT 1",
            &[&visited],
        )
        .await?;
    let Some(row) = row else { return Ok(None) };
    let operation: String = row.get(3);
    let manifest: String = row.get(4);
    let report: String = row.get(12);
    let inventory: Option<String> = row.get(15);
    let generator: Option<String> = row.get(16);
    let generation: Option<String> = row.get(17);
    let job = Job {
        id: row.get(0),
        account: row.get(1),
        status: row.get(2),
        operation: serde_json::from_str(&operation)?,
        manifest: serde_json::from_str(&manifest)?,
        report: serde_json::from_str(&report)?,
        role_arn: row.get(5),
        generator: generator.as_deref().map(serde_json::from_str).transpose()?,
        generation: generation.as_deref().map(serde_json::from_str).transpose()?,
        inventory: inventory.as_deref().map(serde_json::from_str).transpose()?,
        prepared: Position { file: row.get(13), offset: row.get::<_, i64>(6) as u64 },
        total: row.get(7),
        cursor: Position { file: row.get(14), offset: row.get::<_, i64>(8) as u64 },
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
            let principal = session(client, &job).await?.ok();
            conclude(app, client, &job, principal.as_ref(), "Cancelled", None, now, &mut turn).await?;
        }
        "New" | "Preparing" => prepare(app, client, &job, now, budget, &mut turn).await?,
        _ => run(app, client, &job, now, budget, &mut turn).await?,
    }
    Ok(turn)
}

/// Ends the job as `status` (`Complete`, `Cancelled`, or `Failed` with
/// `failures`), unless it ended meanwhile.
async fn end(client: &Object, job: &Job, status: &str, failures: &[&Failure], now: SystemTime) -> anyhow::Result<()> {
    let failures = serde_json::to_string(failures)?;
    client
        .execute_cached(
            "UPDATE batch_jobs SET status = $2, terminated_at = $3, waiting_since = $3, failures = (failures::jsonb || $4::text::jsonb)::text
             WHERE id = $1 AND status IN ('New', 'Preparing', 'Ready', 'Active', 'Cancelling')",
            &[&job.id, &status, &now, &failures],
        )
        .await?;
    // Its copies' records (see `copy`): no turn of it is taken again.
    client.execute_cached("DELETE FROM batch_job_copies WHERE job_id = $1", &[&job.id]).await?;
    Ok(())
}

/// Fails the job, as `turn` tells.
async fn fail(client: &Object, job: &Job, failure: Failure, now: SystemTime, turn: &mut Turn) -> anyhow::Result<()> {
    end(client, job, "Failed", &[&failure], now).await?;
    turn.status = "Failed".to_owned();
    turn.failure = Some(failure);
    Ok(())
}

/// Ends a job that has run as `status` (`Complete`, `Cancelled`, or
/// `Failed` with `failure`): writes its report's manifest first, if it has
/// a report, as its role session `principal`; if that can't be written (or
/// the role can't be assumed any more), the job fails, saying so.
#[allow(clippy::too_many_arguments)]
async fn conclude(
    app: &Arc<App>,
    client: &Object,
    job: &Job,
    principal: Option<&Principal>,
    status: &str,
    failure: Option<Failure>,
    now: SystemTime,
    turn: &mut Turn,
) -> anyhow::Result<()> {
    if let Some(writer) = Writer::of(&job.report, job.id) {
        let written = match principal {
            Some(principal) => writer.manifest(app, client, principal, job.id, now).await?,
            None => Err(Failure::new("ReportUnwritable", format!("The role {} can't be assumed to write the completion report.", job.role_arn))),
        };
        if let Err(unwritable) = written {
            let failures: Vec<&Failure> = failure.iter().chain([&unwritable]).collect();
            end(client, job, "Failed", &failures, now).await?;
            turn.status = "Failed".to_owned();
            turn.failure = Some(unwritable);
            return Ok(());
        }
    }
    match failure {
        Some(failure) => fail(client, job, failure, now, turn).await,
        None => {
            end(client, job, status, &[], now).await?;
            turn.status = status.to_owned();
            Ok(())
        }
    }
}

/// Reads the job's manifest through from where preparing it got to, as
/// far as `PREPARE_BYTES` goes, checking and counting its lines; once
/// it's at the end, the job is ready (or suspended, to be confirmed).
async fn prepare(app: &Arc<App>, client: &Object, job: &Job, now: SystemTime, budget: &mut i64, turn: &mut Turn) -> anyhow::Result<()> {
    let principal = match session(client, job).await? {
        Ok(principal) => principal,
        Err(failure) => return fail(client, job, failure, now, turn).await,
    };
    if let Some(writer) = Writer::of(&job.report, job.id)
        && let Err(failure) = writer.check(app, &principal).await?
    {
        return fail(client, job, failure, now, turn).await;
    }
    // Its manifest, to be generated first.
    if job.manifest.format == manifest::TO_BE_GENERATED {
        let Some(generator) = &job.generator else {
            anyhow::bail!("job {} has neither a manifest nor a generator", job.id);
        };
        return match generate::step(app, client, job, generator, &principal, now, budget).await? {
            Ok(found) => {
                turn.prepared += found.tasks;
                turn.status = found.status;
                Ok(())
            }
            Err(failure) => fail(client, job, failure, now, turn).await,
        };
    }
    if let Err(failure) = may_read_manifest(app, &principal, &job.manifest).await? {
        return fail(client, job, failure, now, turn).await;
    }
    let mut total = job.total;
    let (prepared, inventory, done) = match job.manifest.format.as_str() {
        format if manifest::is_inventory(format) => {
            let mut inventory = match &job.inventory {
                Some(inventory) => inventory.clone(),
                None => match source::read_inventory(app, &job.manifest, principal.id).await? {
                    Ok(inventory) => inventory,
                    Err(failure) => return fail(client, job, failure, now, turn).await,
                },
            };
            // Whole data files, as far as `PREPARE_BYTES` goes.
            let mut file = job.prepared.file as usize;
            let mut read = 0;
            while file < inventory.files.len() && read < PREPARE_BYTES {
                let key = inventory.files[file].key.clone();
                let mut rows = match DataRows::open(app, &inventory, file, &principal).await? {
                    Ok(rows) => rows,
                    Err(failure) => return fail(client, job, failure, now, turn).await,
                };
                loop {
                    let entries = match rows.entries(PAGE).await? {
                        Ok(entries) if entries.is_empty() => break,
                        Ok(entries) => entries,
                        Err(failure) => return fail(client, job, failure, now, turn).await,
                    };
                    for entry in entries {
                        if let Err(bad) = entry {
                            let why = format!("{} {} of the data file {key} isn't a task: {}.", rows.entry_name(), total + 1, bad.why);
                            return fail(client, job, Failure::new("ManifestInvalid", why), now, turn).await;
                        }
                        total += 1;
                        turn.prepared += 1;
                    }
                }
                let (md5, size, etag) = rows.digest();
                if md5 != inventory.files[file].md5 {
                    let why = format!("The data file {key} isn't the one the inventory report lists (its MD5 differs).");
                    return fail(client, job, Failure::new("ManifestInvalid", why), now, turn).await;
                }
                read += size;
                inventory.files[file].etag = Some(etag);
                file += 1;
            }
            let done = file == inventory.files.len();
            (Position { file: file as i32, offset: 0 }, Some(serde_json::to_string(&inventory)?), done)
        }
        _ => {
            let fields = job.manifest.fields();
            let mut prepared = job.prepared.offset;
            let mut done = false;
            let start = prepared;
            while prepared - start < PREPARE_BYTES {
                let chunk = match source::read(app, &job.manifest, principal.id, prepared).await? {
                    Ok(chunk) => chunk,
                    Err(failure) => return fail(client, job, failure, now, turn).await,
                };
                let (lines, consumed) = manifest::lines(&chunk.data, chunk.last, usize::MAX);
                for line in lines {
                    if let Err(why) = check_line(line, &fields) {
                        let why = format!("Line {} of the manifest isn't a task: {why}.", total + 1);
                        return fail(client, job, Failure::new("ManifestInvalid", why), now, turn).await;
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
            (Position { file: 0, offset: prepared }, None, done)
        }
    };
    let row = client
        .query_opt_cached(
            "UPDATE batch_jobs SET prepared = $2, total = $3::bigint, waiting_since = $4,
                 status = CASE WHEN NOT $5::boolean THEN 'Preparing'
                               WHEN $3::bigint = 0 THEN 'Complete'
                               WHEN confirmation THEN 'Suspended'
                               ELSE 'Ready' END,
                 suspended_at = CASE WHEN $5::boolean AND $3::bigint > 0 AND confirmation THEN $4::timestamptz END,
                 suspended_cause = CASE WHEN $5::boolean AND $3::bigint > 0 AND confirmation THEN $6::text END,
                 terminated_at = CASE WHEN $5::boolean AND $3::bigint = 0 THEN $4::timestamptz END,
                 prepared_file = $7, inventory = $8
             WHERE id = $1 AND status IN ('New', 'Preparing')
             RETURNING status",
            &[&job.id, &(prepared.offset as i64), &total, &now, &done, &AWAITING_CONFIRMATION, &prepared.file, &inventory],
        )
        .await?;
    turn.status = row.map_or_else(|| "Cancelled".to_owned(), |row| row.get(0));
    Ok(())
}

/// Why a manifest's line isn't a task, if it isn't.
fn check_line(line: &[u8], fields: &[Field]) -> Result<(), String> {
    let line = std::str::from_utf8(line).map_err(|_| "it isn't UTF-8".to_owned())?;
    manifest::parse_line(line, fields).map(|_| ())
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
    let origin = Origin { peer: None, trusted_proxies: &[], signed: None, form: false };
    // A copy's requests have headers, as policies see them.
    let headers = match &job.operation {
        Operation::Copy(copy) => match copy.headers() {
            Ok(headers) => headers,
            Err(why) => anyhow::bail!("job {}: its copy's {why}", job.id),
        },
        _ => HeaderMap::new(),
    };
    let mut access = Access::new(Some(&principal), &principal.account, &Method::PUT, &headers, "", &origin)?;
    let tags = match &job.operation {
        Operation::PutTagging { tags } => match Tags::from_pairs(tags.clone(), crate::s3::tags::On::Object) {
            Ok(tags) => tags,
            Err(_) => anyhow::bail!("job {}: its stored tags aren't an object's", job.id),
        },
        _ => Tags::default(),
    };
    // What the tasks ask for, which policies may test.
    match &job.operation {
        Operation::PutTagging { .. } => crate::s3::abac::request_tags(&mut access, &tags),
        Operation::PutRetention { mode, until, .. } => {
            crate::s3::object_lock::set_context(&mut access.context, mode.as_deref(), until.as_deref(), None)
        }
        Operation::PutLegalHold { on } => {
            crate::s3::object_lock::set_context(&mut access.context, None, None, Some(if *on { "ON" } else { "OFF" }))
        }
        Operation::DeleteTagging | Operation::Replicate | Operation::Copy(_) => {}
    }
    let copier = match &job.operation {
        Operation::Copy(copy) => Some(copy::Copier::new(job.id, copy, headers, &mut access)?),
        _ => None,
    };
    let mut source = match (&job.inventory, job.manifest.format.as_str()) {
        (Some(inventory), _) => Source::Inventory(inventory, None),
        (None, format) if manifest::is_inventory(format) => anyhow::bail!("job {} was prepared without its inventory report's files", job.id),
        (None, _) => Source::Csv(&job.manifest),
    };
    let writer = Writer::of(&job.report, job.id);
    let who = principal.arn();
    let (mut cursor, mut succeeded, mut failed) = (job.cursor, job.succeeded, job.failed);
    // Its tasks' writes are its role session's, as their events say.
    crate::notifications::scope(async {
        crate::notifications::set_requester(Some(principal.unique_id()), None);
        while *budget > 0 {
            let began = std::time::Instant::now();
            let limit = (*budget).clamp(1, PAGE as i64) as usize;
            let page = match source.page(app, &principal, cursor, limit).await? {
                Ok(page) => page,
                Err(failure) => return fail(client, job, failure, now, turn).await,
            };
            let (entries, finished) = (page.entries, page.finished);
            let count = entries.len();
            let mut done_lines = Vec::with_capacity(count);
            for entry in entries {
                // Preparing checked every entry, and the manifest is pinned
                // to its ETag: one that isn't a task fails all the same.
                // Its ordinal: the tasks before it, as the job's counts
                // (saved with its cursor) and the page's tell.
                let ordinal = succeeded + failed;
                let (task, result) = match entry {
                    Ok(task) => {
                        let result = match &copier {
                            Some(copier) => match unfit(&task, &job.operation) {
                                Some(failure) => Err(failure),
                                None => copier.run(app, &mut access, &principal, &who, ordinal, &task).await?,
                            },
                            None => run_task(app, &mut access, &who, &job.operation, &tags, &task).await?,
                        };
                        (task, result)
                    }
                    Err(bad) => {
                        let task = Task { bucket: bad.bucket, key: bad.key, version_id: None };
                        (task, Err(TaskFailure::new(400, "InvalidManifestLine", bad.why)))
                    }
                };
                match &result {
                    Ok(()) => {
                        succeeded += 1;
                        turn.succeeded += 1;
                    }
                    Err(why) => {
                        failed += 1;
                        if turn.failed_task.is_none() {
                            turn.failed_task = Some(format!("{}/{}: {why}", task.bucket, task.key));
                        }
                    }
                }
                turn.tasks += 1;
                done_lines.push(Line { task, result });
            }
            *budget -= count.max(1) as i64;
            let start = cursor;
            cursor = page.end;
            let files = match &writer {
                Some(writer) => match writer.page(app, &principal, job.id, start, &done_lines).await? {
                    Ok(files) => files,
                    Err(failure) => return fail(client, job, failure, now, turn).await,
                },
                None => Vec::new(),
            };
            let keys: Vec<&str> = files.iter().map(|f| f.key.as_str()).collect();
            let statuses: Vec<&str> = files.iter().map(|f| f.status).collect();
            let md5s: Vec<&str> = files.iter().map(|f| f.md5.as_str()).collect();
            // Where it got to, its counts and the page's result files, at
            // once.
            let row = client
                .query_opt_cached(
                    "WITH job AS (
                         UPDATE batch_jobs SET cursor = $2, succeeded = $3, failed = $4,
                             active_seconds = active_seconds + $5, waiting_since = $6, cursor_file = $11
                         WHERE id = $1 AND status IN ('Active', 'Cancelling')
                         RETURNING status),
                     files AS (
                         INSERT INTO batch_job_results (job_id, file, start_at, status, key, md5)
                         SELECT $1, $12, $7, f.status, f.key, f.md5
                         FROM unnest($8::text[], $9::text[], $10::text[]) AS f(status, key, md5)
                         WHERE EXISTS (SELECT 1 FROM job)
                         ON CONFLICT DO NOTHING)
                     SELECT status FROM job",
                    &[
                        &job.id,
                        &(cursor.offset as i64),
                        &succeeded,
                        &failed,
                        &began.elapsed().as_secs_f64(),
                        &now,
                        &(start.offset as i64),
                        &statuses,
                        &keys,
                        &md5s,
                        &cursor.file,
                        &start.file,
                    ],
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
                return conclude(app, client, job, Some(&principal), "Failed", Some(failure), now, turn).await;
            }
            if finished {
                return conclude(app, client, job, Some(&principal), "Complete", None, now, turn).await;
            }
            if row.get::<_, &str>(0) == "Cancelling" {
                return conclude(app, client, job, Some(&principal), "Cancelled", None, now, turn).await;
            }
        }
        Ok(())
    })
    .await
}

/// Does `operation` to the object of `task`, as `access` (its role's
/// session's, `who`) allows it; why not, if it didn't.
async fn run_task(
    app: &Arc<App>,
    access: &mut Access,
    who: &str,
    operation: &Operation,
    tags: &Tags,
    task: &Task,
) -> anyhow::Result<Result<(), TaskFailure>> {
    let Task { bucket, key, version_id } = task;
    if let Some(failure) = unfit(task, operation) {
        return Ok(Err(failure));
    }
    // The request the task is, as policies see it.
    let query = |subresource: &str| match version_id {
        Some(v) => format!("{subresource}&versionId={}", percent_encoding::utf8_percent_encode(v, percent_encoding::NON_ALPHANUMERIC)),
        None => subresource.to_owned(),
    };
    let version_id = version_id.as_deref();
    let change = match operation {
        Operation::PutTagging { .. } | Operation::DeleteTagging => {
            let (method, tagging) = match operation {
                Operation::PutTagging { .. } => (Method::PUT, Tagging::Put),
                _ => (Method::DELETE, Tagging::Delete),
            };
            if let Err(failure) = authorize(app, access, who, &method, bucket, key, &query("tagging"), &HeaderMap::new()).await? {
                return Ok(Err(failure));
            }
            return Ok(match tagging::set_tags(app, bucket, key, version_id, tags, tagging).await? {
                Outcome::Tagged(_) => Ok(()),
                Outcome::DeleteMarker(_) => Err(delete_marker()),
                Outcome::NoSuchVersion => Err(no_such_version()),
                Outcome::NoSuchKey => Err(no_such_key()),
                Outcome::NoSuchBucket => Err(no_such_bucket()),
                Outcome::Contended => Err(slow_down()),
            });
        }
        Operation::PutRetention { mode, until, bypass } => {
            if let Err(failure) = authorize(app, access, who, &Method::PUT, bucket, key, &query("retention"), &HeaderMap::new()).await? {
                return Ok(Err(failure));
            }
            let retention = match (mode.as_deref().and_then(Mode::parse), until.as_deref().and_then(parse_date)) {
                (Some(mode), Some(until)) => Some((mode, until)),
                _ => None,
            };
            if retention.is_some_and(|(_, until)| until <= SystemTime::now()) {
                return Ok(Err(TaskFailure::new(400, "InvalidArgument", crate::s3::object_lock::IN_THE_PAST)));
            }
            // As a request asking to bypass GOVERNANCE mode: only if the
            // role may.
            let check = actions::Check {
                action: "s3:BypassGovernanceRetention",
                on: actions::On::Object(bucket.clone(), key.clone()),
            };
            Change::Retention { retention, bypass: *bypass && access.allows(&check) }
        }
        Operation::PutLegalHold { on } => {
            if let Err(failure) = authorize(app, access, who, &Method::PUT, bucket, key, &query("legal-hold"), &HeaderMap::new()).await? {
                return Ok(Err(failure));
            }
            Change::LegalHold(*on)
        }
        Operation::Copy(_) => anyhow::bail!("a copy's task is its copier's"),
        Operation::Replicate => {
            // No request of S3's API is this: it's allowed as its action is.
            let checks = [actions::Check { action: "s3:InitiateReplication", on: actions::On::Object(bucket.clone(), key.clone()) }];
            access.forget_object_tags();
            let exists = access.load(app, bucket).await?;
            access.load_all(app, &checks).await?;
            return Ok(match access.first_denied(&checks) {
                None => replicate(app, bucket, key, version_id).await?,
                Some(_) if !exists => Err(no_such_bucket()),
                Some((check, _)) => Err(TaskFailure::new(
                    403,
                    "AccessDenied",
                    format!("User: {who} is not authorized to perform: {} on resource: \"{}\"", check.action, check.on.arn()),
                )),
            });
        }
    };
    Ok(match crate::s3::object_lock::change_lock(app, bucket, key, version_id, change).await? {
        LockOutcome::Set => Ok(()),
        LockOutcome::Locked => Err(TaskFailure::new(403, "AccessDenied", crate::s3::object_lock::LOCKED_MESSAGE)),
        LockOutcome::DeleteMarker(_) => Err(delete_marker()),
        LockOutcome::NoSuchVersion => Err(no_such_version()),
        LockOutcome::NoSuchKey => Err(no_such_key()),
        LockOutcome::NoObjectLock => {
            Err(TaskFailure::new(400, "InvalidRequest", "Bucket is missing Object Lock Configuration"))
        }
        LockOutcome::NoSuchBucket => Err(no_such_bucket()),
        LockOutcome::Contended => Err(slow_down()),
    })
}

/// Why `operation` can't be done to `task`'s object, if it can't: its
/// version ID isn't one, or its bucket is a directory bucket.
fn unfit(task: &Task, operation: &Operation) -> Option<TaskFailure> {
    if task.version_id.as_deref().is_some_and(|v| !crate::s3::versions::is_version_id(v)) {
        return Some(TaskFailure::new(400, "InvalidArgument", "Invalid version id specified"));
    }
    if crate::s3::directory::is_directory(&task.bucket) {
        let what = format!("{} isn't done to a directory bucket's objects.", operation.name());
        return Some(TaskFailure::new(501, "NotImplemented", what));
    }
    None
}

/// Batch Replication's task: queues the version (the key's current one if
/// it names none) for each destination its bucket's replication
/// configuration sends it to, to be replicated by the configuration's
/// role, as a version is when it's written (see `replication`), however
/// it was replicated before (T69). So the task is done once it's queued:
/// whether its replication fails is its status's to tell
/// (`x-amz-replication-status`), as S3's Batch Replication reports its
/// tasks done when it starts them.
async fn replicate(app: &App, bucket: &str, key: &str, version_id: Option<&str>) -> anyhow::Result<Result<(), TaskFailure>> {
    let client = app.pool.get().await?;
    for attempt in 0..crate::db::MAX_TX_ATTEMPTS {
        crate::db::backoff(attempt).await;
        let status = match client
            .query_one_cached("SELECT pg_temp.cairn_replicate_existing($1, $2, $3)", &[&bucket, &key, &version_id])
            .await
        {
            Ok(row) => row.get::<_, String>(0),
            Err(e) if crate::db::is_conflict(&e) => continue,
            Err(e) => return Err(e.into()),
        };
        let not_eligible = |why: &str| Err(TaskFailure::new(400, "SrcObjectNotEligible", why));
        return Ok(match status.as_str() {
            "queued" => Ok(()),
            "no_such_bucket" => Err(no_such_bucket()),
            "no_such_key" => Err(no_such_key()),
            "no_such_version" => Err(no_such_version()),
            "no_configuration" => Err(TaskFailure::new(
                400,
                "SrcBucketReplicationConfigMissing",
                "The source bucket has no replication configuration.",
            )),
            "null_version" => not_eligible("The null version isn't replicated: it has no version ID for its replica to keep."),
            "not_eligible" => not_eligible("No rule of the bucket's replication configuration replicates the object."),
            status => anyhow::bail!("cairn_replicate_existing answered {status}"),
        });
    }
    Ok(Err(slow_down()))
}

fn delete_marker() -> TaskFailure {
    TaskFailure::new(405, "MethodNotAllowed", "The specified method is not allowed against this resource.")
}

fn no_such_version() -> TaskFailure {
    TaskFailure::new(404, "NoSuchVersion", "The specified version does not exist.")
}

fn no_such_key() -> TaskFailure {
    TaskFailure::new(404, "NoSuchKey", "The specified key does not exist.")
}

fn no_such_bucket() -> TaskFailure {
    TaskFailure::new(404, "NoSuchBucket", "The specified bucket does not exist")
}

fn slow_down() -> TaskFailure {
    TaskFailure::new(503, "SlowDown", "Please reduce your request rate.")
}

/// Whether `access` (of `who`, by its ARN) allows the request (`method` on
/// `bucket`'s `key`, with `query` and `headers`), as `s3::handle_request`
/// authorizes it; why not, as S3 would answer, if it doesn't.
#[allow(clippy::too_many_arguments)]
async fn authorize(
    app: &App,
    access: &mut Access,
    who: &str,
    method: &Method,
    bucket: &str,
    key: &str,
    query: &str,
    headers: &HeaderMap,
) -> anyhow::Result<Result<(), TaskFailure>> {
    let Some(operation) = actions::operation(method, bucket, key, query, headers) else {
        anyhow::bail!("{method} {bucket}/{key}?{query} is no operation");
    };
    access.forget_object_tags();
    let exists = access.load(app, bucket).await?;
    access.load_all(app, &operation.checks).await?;
    crate::s3::abac::prepare(app, access, &operation, bucket, key, query, headers).await?;
    crate::s3::acl::prepare(app, access, &operation, bucket, key, query, headers).await?;
    Ok(match access.first_denied(&operation.checks) {
        None => Ok(()),
        Some(_) if !exists => Err(no_such_bucket()),
        Some((check, _)) => Err(TaskFailure::new(
            403,
            "AccessDenied",
            format!("User: {who} is not authorized to perform: {} on resource: \"{}\"", check.action, check.on.arn()),
        )),
    })
}

/// Whether the job's role session (`principal`) may read its manifest.
async fn may_read_manifest(app: &App, principal: &Principal, manifest: &Manifest) -> anyhow::Result<Result<(), Failure>> {
    if manifest.generated {
        return Ok(Ok(()));
    }
    may_read(app, principal, &manifest.bucket, &manifest.key, manifest.version_id.as_deref(), &manifest.arn).await
}

/// Whether the role session `principal` may read the object (`bucket`'s
/// `key`, of `version_id`; `arn`, as failures name it).
async fn may_read(
    app: &App,
    principal: &Principal,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    arn: &str,
) -> anyhow::Result<Result<(), Failure>> {
    let origin = Origin { peer: None, trusted_proxies: &[], signed: None, form: false };
    let mut access = Access::new(Some(principal), &principal.account, &Method::GET, &HeaderMap::new(), "", &origin)?;
    let query = match version_id {
        Some(v) => format!("versionId={}", percent_encoding::utf8_percent_encode(v, percent_encoding::NON_ALPHANUMERIC)),
        None => String::new(),
    };
    Ok(authorize(app, &mut access, &principal.arn(), &Method::GET, bucket, key, &query, &HeaderMap::new())
        .await?
        .map_err(|why| Failure::new("ManifestUnreadable", format!("Reading {arn} failed: {why}."))))
}

/// The session of the job's role, assumed as `SERVICE`; why not, if it
/// can't be (no such role, or it doesn't trust the service).
async fn session(client: &Object, job: &Job) -> anyhow::Result<Result<Principal, Failure>> {
    let assumed = assume(client, &job.account, &job.role_arn, SERVICE, &arn(&job.account, job.id), SESSION_NAME).await?;
    Ok(assumed.map_err(|why| Failure::new("RoleUnusable", format!("The role {} {why}.", job.role_arn))))
}

/// The session `session_name` of the role `role_arn` of `account`, as
/// `service` assumes it for what `source_arn` names (the trust policy's
/// `aws:SourceArn`, with `aws:SourceAccount` the account); why not, if it
/// can't be (no such role, or it doesn't trust the service), as the end of
/// a sentence about the role.
pub(crate) async fn assume(
    client: &Object,
    account: &str,
    role_arn: &str,
    service: &str,
    source_arn: &str,
    session_name: &str,
) -> anyhow::Result<Result<Principal, String>> {
    let Some((path, name)) = role_of_arn(role_arn, account) else {
        return Ok(Err("isn't one of the account's".to_owned()));
    };
    let Some(role) = crate::roles::Role::load(client, account, name).await?.filter(|r| r.path == path && r.name == name)
    else {
        return Ok(Err("doesn't exist".to_owned()));
    };
    let trust = Policy::parse(&role.trust, Kind::Trust)
        .map_err(|e| anyhow::anyhow!("role {}'s trust policy doesn't parse: {}", role.name, e.message))?
        .with_ids(role.trust_principals.clone());
    let mut context = Context::default();
    context.set("aws:SourceAccount", account);
    context.set("aws:SourceArn", source_arn);
    let role_arn = role.arn();
    let request = Request { principal: Who::Service { name: service }, action: "sts:AssumeRole", resource: &role_arn, context: &context };
    if trust.evaluate_trust(&request).0 != Decision::Allow {
        return Ok(Err(format!("doesn't trust {service} to assume it")));
    }
    let now = crate::sessions::now();
    let session = crate::sessions::Session {
        key_id: String::new(),
        secret: String::new(),
        issued: now,
        expires: now + SESSION,
        who: crate::sessions::Who::Role { id: role.id, session: session_name.to_owned() },
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
        Err(_) => Err("doesn't exist".to_owned()),
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
        assert_eq!(serde_json::to_string(&Operation::Replicate).unwrap(), r#"{"t":"replicate"}"#);
        let copy = Operation::Copy(Box::new(copy::Copy {
            target: "arn:aws:s3:::dest".to_owned(),
            prefix: Some("p/".to_owned()),
            ..copy::Copy::default()
        }));
        let json = serde_json::to_string(&copy).unwrap();
        assert_eq!(json, r#"{"t":"copy","target":"arn:aws:s3:::dest","prefix":"p/"}"#);
        assert_eq!(serde_json::from_str::<Operation>(&json).unwrap(), copy);
    }
}
