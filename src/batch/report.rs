//! A job's completion report (`Report_CSV_20180820`), as S3 writes it, to
//! the bucket and prefix CreateJob's `Report` names, as the job's role
//! (which must be allowed `s3:PutObject` there):
//!
//! - `<prefix>/job-<id>/results/<name>.csv`: the results of a page of the
//!   job's tasks, one line each (bucket, key URL-encoded as the manifest has
//!   it, version ID, `succeeded` or `failed`, the HTTP status, the error
//!   code, and a message), those that succeeded in one file and those that
//!   failed in another (only the latter with `FailedTasksOnly`). A file is
//!   written once its page's tasks are done, before where the job has got
//!   to is saved, and recorded with it (`batch_job_results`); its name is
//!   derived from the job and where its page starts, so a page done again,
//!   after its node died, writes the same file again rather than another.
//! - `<prefix>/job-<id>/manifest.json`: the result files, written when the
//!   job ends, once it has run (`Complete`, `Failed` after its tasks failed
//!   too often, or `Cancelled` while active).

use std::{borrow::Cow, sync::Arc, time::SystemTime};

use deadpool_postgres::Object;
use http_body_util::{BodyExt, Full};
use hyper::{HeaderMap, Method, StatusCode, body::Bytes};
use md5::{Digest, Md5};
use sha2::Sha256;
use uuid::Uuid;

use super::{Failure, Report, authorize, manifest::Task, source::Position};
use crate::db::Cached;
use crate::{
    App,
    payload::Payload,
    s3::{
        access::{Access, Origin},
        conditional::Preconditions,
        object_lock::Lock,
        sse::Wanted,
        util::{Encoding, MAX_UPLOAD},
    },
    users::Principal,
};

/// The report's format, and its lines' columns, as its manifest says them.
pub const FORMAT: &str = "Report_CSV_20180820";
const SCHEMA: &str = "Bucket, Key, VersionId, TaskStatus, ErrorCode, HTTPStatusCode, ResultMessage";
/// Which tasks a report has.
pub const ALL_TASKS: &str = "AllTasks";
pub const FAILED_TASKS_ONLY: &str = "FailedTasksOnly";

/// Why a task failed, as its report line says it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskFailure {
    pub status: u16,
    pub code: Cow<'static, str>,
    pub message: String,
}

impl TaskFailure {
    pub fn new(status: u16, code: impl Into<Cow<'static, str>>, message: impl Into<String>) -> TaskFailure {
        TaskFailure { status, code: code.into(), message: message.into() }
    }
}

impl std::fmt::Display for TaskFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}: {}", self.status, self.code, self.message)
    }
}

/// A task done, as its line of the report has it.
pub struct Line {
    pub task: Task,
    pub result: Result<(), TaskFailure>,
}

/// A result file written: its key, and whether its tasks succeeded or
/// failed (`succeeded`, `failed`), and its MD5 (hex).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResultFile {
    pub key: String,
    pub status: &'static str,
    pub md5: String,
}

/// Where a job's report goes, if it has one.
pub struct Writer {
    bucket: String,
    /// What its keys start with: `<prefix>/job-<id>/`.
    root: String,
    failed_only: bool,
    expected_owner: Option<String>,
}

impl Writer {
    /// The writer of job `id`'s report, if `report` asks for one.
    pub fn of(report: &Report, id: Uuid) -> Option<Writer> {
        if !report.enabled {
            return None;
        }
        let bucket = report.bucket.as_deref().and_then(bucket_of_arn)?.to_owned();
        let prefix = report.prefix.as_deref().map(|p| p.trim_end_matches('/')).filter(|p| !p.is_empty());
        let root = match prefix {
            Some(prefix) => format!("{prefix}/job-{id}/"),
            None => format!("job-{id}/"),
        };
        let failed_only = report.scope.as_deref() == Some(FAILED_TASKS_ONLY);
        Some(Writer { bucket, root, failed_only, expected_owner: report.expected_owner.clone() })
    }

    fn manifest_key(&self) -> String {
        format!("{}manifest.json", self.root)
    }

    /// Whether the role session `principal` may write the report: the
    /// bucket is there (and its owner's the one expected), and it may put
    /// its manifest.
    pub async fn check(&self, app: &App, principal: &Principal) -> anyhow::Result<Result<(), Failure>> {
        let unwritable = |why: String| Failure::new("ReportUnwritable", format!("The completion report can't be written: {why}."));
        let owner: Option<String> = app
            .pool
            .get()
            .await?
            .query_opt_cached("SELECT account_id FROM buckets WHERE name = $1", &[&self.bucket])
            .await?
            .map(|row| row.get(0));
        let Some(owner) = owner else {
            return Ok(Err(unwritable(format!("its bucket {} doesn't exist", self.bucket))));
        };
        if self.expected_owner.as_ref().is_some_and(|expected| *expected != owner) {
            return Ok(Err(unwritable(format!("its bucket {} isn't the expected owner's", self.bucket))));
        }
        Ok(may_put(app, principal, &self.bucket, &self.manifest_key()).await?.map_err(|f| unwritable(f.to_string())))
    }

    /// Writes the result files of the page of `lines` starting at `start`
    /// in the manifest, as `principal`.
    pub async fn page(
        &self,
        app: &Arc<App>,
        principal: &Principal,
        id: Uuid,
        start: Position,
        lines: &[Line],
    ) -> anyhow::Result<Result<Vec<ResultFile>, Failure>> {
        let mut files = Vec::new();
        for (status, succeeded) in [("succeeded", true), ("failed", false)] {
            if succeeded && self.failed_only {
                continue;
            }
            let body: String = lines.iter().filter(|l| l.result.is_ok() == succeeded).map(csv_line).collect();
            if body.is_empty() {
                continue;
            }
            let key = format!("{}results/{}.csv", self.root, file_name(id, start, status));
            match self.put(app, principal, &key, "text/csv", body.into_bytes()).await? {
                Ok(md5) => files.push(ResultFile { key, status, md5 }),
                Err(failure) => return Ok(Err(failure)),
            }
        }
        Ok(Ok(files))
    }

    /// Writes the report's manifest, of the result files recorded for job
    /// `id`, as `principal`.
    pub async fn manifest(
        &self,
        app: &Arc<App>,
        client: &Object,
        principal: &Principal,
        id: Uuid,
        now: SystemTime,
    ) -> anyhow::Result<Result<(), Failure>> {
        let rows = client
            .query_cached(
                "SELECT key, status, md5 FROM batch_job_results WHERE job_id = $1 ORDER BY file, start_at, status DESC",
                &[&id],
            )
            .await?;
        let results: Vec<serde_json::Value> = rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "TaskExecutionStatus": row.get::<_, &str>(1),
                    "Bucket": self.bucket,
                    "MD5Checksum": row.get::<_, &str>(2),
                    "Key": row.get::<_, &str>(0),
                })
            })
            .collect();
        let manifest = serde_json::json!({
            "Format": FORMAT,
            "ReportCreationDate": iso_millis(now),
            "Results": results,
            "ReportSchema": SCHEMA,
        });
        let body = serde_json::to_vec_pretty(&manifest)?;
        Ok(self.put(app, principal, &self.manifest_key(), "application/json", body).await?.map(|_| ()))
    }

    /// Writes `body` to `key`, as `principal`, encrypted as the bucket's
    /// default encryption says: its MD5 (hex).
    async fn put(
        &self,
        app: &Arc<App>,
        principal: &Principal,
        key: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> anyhow::Result<Result<String, Failure>> {
        let unwritable = |why: String| Failure::new("ReportUnwritable", format!("Writing the completion report's {key} failed: {why}."));
        if let Err(why) = may_put(app, principal, &self.bucket, key).await? {
            return Ok(Err(unwritable(why.to_string())));
        }
        let server = match crate::s3::buckets::encryption::default_request(app, &self.bucket).await? {
            Ok(server) => server,
            Err(refused) => return Ok(Err(unwritable(refusal(refused).await))),
        };
        let md5: String = Md5::digest(&body).iter().map(|b| format!("{b:02x}")).collect();
        let payload = Payload::unchecked().at_most(MAX_UPLOAD).map_err(|_| anyhow::anyhow!("an unchecked payload has no length"))?;
        let response = crate::s3::objects::put::put_object(
            app,
            &self.bucket,
            key,
            content_type,
            "",
            "",
            Full::new(Bytes::from(body)),
            payload,
            &Preconditions::default(),
            Wanted::new(None, server.as_ref()),
            Some(principal.id),
            Lock::default(),
            crate::classes::STANDARD,
        )
        .await?;
        if response.status() == StatusCode::OK {
            return Ok(Ok(md5));
        }
        if response.status().is_server_error() {
            anyhow::bail!("writing {key} to bucket {}: {}", self.bucket, refusal(response).await);
        }
        Ok(Err(unwritable(refusal(response).await)))
    }
}

/// Whether `principal` may put `key` in `bucket`.
async fn may_put(app: &App, principal: &Principal, bucket: &str, key: &str) -> anyhow::Result<Result<(), TaskFailure>> {
    let origin = Origin { peer: None, trusted_proxies: &[], signed: None, form: false };
    let mut access = Access::new(Some(principal), &principal.account, &Method::PUT, &HeaderMap::new(), "", &origin)?;
    authorize(app, &mut access, &principal.arn(), &Method::PUT, bucket, key, "", &HeaderMap::new()).await
}

/// What an S3 error response says: its code and message.
async fn refusal(response: hyper::Response<Full<Bytes>>) -> String {
    let status = response.status();
    let body = response.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
    let body = String::from_utf8_lossy(&body);
    let element = |name: &str| body.split(&format!("<{name}>")).nth(1)?.split(&format!("</{name}>")).next().map(str::to_owned);
    match (element("Code"), element("Message")) {
        (Some(code), Some(message)) => format!("{code}: {message}"),
        (Some(code), None) => code,
        _ => status.to_string(),
    }
}

/// The bucket of a bucket's ARN (`arn:aws:s3:::bucket`).
pub fn bucket_of_arn(arn: &str) -> Option<&str> {
    arn.strip_prefix("arn:aws:s3:::").filter(|b| !b.is_empty() && !b.contains('/'))
}

/// The name of the result file of job `id`'s page at `start` of tasks that
/// `status`: always the same, 40 hex digits, as S3's are.
fn file_name(id: Uuid, start: Position, status: &str) -> String {
    let Position { file, offset } = start;
    let digest = match file {
        0 => Sha256::digest(format!("{id}/{offset}/{status}")),
        _ => Sha256::digest(format!("{id}/{file}/{offset}/{status}")),
    };
    digest.iter().take(20).map(|b| format!("{b:02x}")).collect()
}

/// A task's line of a result file.
fn csv_line(line: &Line) -> String {
    let Task { bucket, key, version_id } = &line.task;
    let (status, http, code, message) = match &line.result {
        Ok(()) => ("succeeded", 200, "", "Successful"),
        Err(failure) => ("failed", failure.status, failure.code.as_ref(), failure.message.as_str()),
    };
    let columns = [
        bucket.as_str(),
        &Encoding::Url.xml(key),
        version_id.as_deref().unwrap_or(""),
        status,
        &http.to_string(),
        code,
        message,
    ];
    let mut out = columns.iter().map(|c| quoted(c)).collect::<Vec<_>>().join(",");
    out.push('\n');
    out
}

/// A CSV column: quoted if it has a comma, a quote or a line break.
fn quoted(column: &str) -> String {
    match column.contains([',', '"', '\n', '\r']) {
        true => format!("\"{}\"", column.replace('"', "\"\"")),
        false => column.to_owned(),
    }
}

/// A time as `2026-11-16T05:00:00.000Z`.
fn iso_millis(t: SystemTime) -> String {
    let since = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    let seconds = crate::sessions::iso(since.as_secs());
    format!("{}.{:03}Z", seconds.trim_end_matches('Z'), since.subsec_millis())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(key: &str, version_id: Option<&str>) -> Task {
        Task { bucket: "b".to_owned(), key: key.to_owned(), version_id: version_id.map(str::to_owned) }
    }

    #[test]
    fn lines_are_s3s() {
        let ok = Line { task: task("photos/a b.jpg", None), result: Ok(()) };
        assert_eq!(csv_line(&ok), "b,photos/a+b.jpg,,succeeded,200,,Successful\n");
        let failed = Line {
            task: task("k", Some("v1")),
            result: Err(TaskFailure::new(403, "AccessDenied", "User: x is not authorized, \"really\"")),
        };
        assert_eq!(csv_line(&failed), "b,k,v1,failed,403,AccessDenied,\"User: x is not authorized, \"\"really\"\"\"\n");
    }

    #[test]
    fn reports_go_under_their_prefix() {
        let id = Uuid::nil();
        let report = |prefix: Option<&str>, scope: Option<&str>| Report {
            enabled: true,
            bucket: Some("arn:aws:s3:::reports".to_owned()),
            format: Some(FORMAT.to_owned()),
            prefix: prefix.map(str::to_owned),
            scope: scope.map(str::to_owned),
            expected_owner: None,
        };
        let writer = Writer::of(&report(Some("batch/"), None), id).unwrap();
        assert_eq!(writer.bucket, "reports");
        assert_eq!(writer.manifest_key(), format!("batch/job-{id}/manifest.json"));
        assert!(!writer.failed_only);
        let writer = Writer::of(&report(None, Some(FAILED_TASKS_ONLY)), id).unwrap();
        assert_eq!(writer.manifest_key(), format!("job-{id}/manifest.json"));
        assert!(writer.failed_only);
        assert!(Writer::of(&Report::default(), id).is_none());
    }

    #[test]
    fn result_files_are_named_by_their_page() {
        let id = Uuid::nil();
        let at = |file, offset| Position { file, offset };
        assert_eq!(file_name(id, at(0, 0), "failed"), file_name(id, at(0, 0), "failed"));
        assert_ne!(file_name(id, at(0, 0), "failed"), file_name(id, at(0, 0), "succeeded"));
        assert_ne!(file_name(id, at(0, 0), "failed"), file_name(id, at(0, 1), "failed"));
        assert_ne!(file_name(id, at(1, 0), "failed"), file_name(id, at(0, 0), "failed"));
        assert_eq!(file_name(id, at(0, 0), "failed").len(), 40);
    }

    #[test]
    fn times_have_milliseconds() {
        let t = SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(1_763_269_323_045);
        assert_eq!(iso_millis(t), "2025-11-16T05:02:03.045Z");
    }
}
