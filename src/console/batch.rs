//! The console's API for Batch Operations' jobs (see `batch`): listed,
//! described, made, confirmed, cancelled and reprioritized. Each call is S3
//! Control's own request (`batch::control`), run as the session's identity,
//! so it's checked and validated exactly as S3 Control checks it (its
//! actions, condition keys, and `iam:PassRole` on a new job's role); reads
//! take what that answers apart.
//!
//! A new job is asked for as a form (`NewBatchJob`), which is written as
//! CreateJob's `<CreateJobRequest>`: nothing of it is checked here.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use http_body_util::{BodyExt, Full};
use hyper::{Response, body::Bytes};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::actor::Actor;
use super::manage::{AppState, Result, Tag, s3_error};
use super::web::{ApiError, ErrorBody};
use crate::{App, batch::control, s3::util::xml_escape};

pub(super) fn router() -> OpenApiRouter<Arc<App>> {
    OpenApiRouter::new()
        .routes(routes!(list_batch_jobs, create_batch_job))
        .routes(routes!(get_batch_job))
        .routes(routes!(set_batch_job_priority))
        .routes(routes!(set_batch_job_status))
}

/// What S3 Control answered: its body (XML), or its error.
async fn answered(resp: anyhow::Result<Response<Full<Bytes>>>) -> Result<String> {
    let resp = resp?;
    if !resp.status().is_success() {
        return Err(s3_error(resp).await);
    }
    let body = resp
        .into_body()
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    Ok(String::from_utf8_lossy(&body).into_owned())
}

fn encode(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

fn element(name: &str, text: &str) -> String {
    format!("<{name}>{}</{name}>", xml_escape(text))
}

/// The child element `name` of `node`.
fn child<'a, 'i>(node: roxmltree::Node<'a, 'i>, name: &str) -> Option<roxmltree::Node<'a, 'i>> {
    node.children()
        .find(|n| n.is_element() && n.tag_name().name() == name)
}

fn text(node: roxmltree::Node, name: &str) -> Option<String> {
    child(node, name).map(|n| n.text().unwrap_or("").to_owned())
}

fn number(node: roxmltree::Node, name: &str) -> i64 {
    text(node, name).and_then(|t| t.parse().ok()).unwrap_or(0)
}

fn members(node: Option<roxmltree::Node>) -> Vec<String> {
    node.into_iter()
        .flat_map(|n| n.children().filter(|c| c.is_element()))
        .map(|m| m.text().unwrap_or("").to_owned())
        .collect()
}

/// A setting of a job's operation or manifest generator, as the detail
/// shows it.
#[derive(Serialize, ToSchema)]
struct JobSetting {
    /// Where it is (`Retention.Mode`, say), lists' members unnamed.
    name: String,
    value: String,
}

/// The settings under `node`: each element without elements of its own,
/// by its path; a tag (a `Key` and a `Value`) as `key=value`.
fn settings(node: roxmltree::Node) -> Vec<JobSetting> {
    fn walk(node: roxmltree::Node, path: &str, out: &mut Vec<JobSetting>) {
        for c in node.children().filter(|c| c.is_element()) {
            let name = c.tag_name().name();
            let path = match (name, path) {
                ("member" | "entry", _) => path.to_owned(),
                (_, "") => name.to_owned(),
                _ => format!("{path}.{name}"),
            };
            if let (Some(key), Some(value)) = (text(c, "Key"), text(c, "Value")) {
                out.push(JobSetting {
                    name: path,
                    value: format!("{key}={value}"),
                });
            } else if c.children().any(|g| g.is_element()) {
                walk(c, &path, out);
            } else {
                out.push(JobSetting {
                    name: path,
                    value: c.text().unwrap_or("").to_owned(),
                });
            }
        }
    }
    let mut out = Vec::new();
    walk(node, "", &mut out);
    out
}

/// A job, as lists show it.
#[derive(Serialize, ToSchema)]
struct BatchJobSummary {
    id: String,
    description: Option<String>,
    /// Its operation, as S3 Control names it (`S3PutObjectTagging`, …).
    operation: String,
    priority: i64,
    status: String,
    /// ISO 8601.
    created_at: String,
    terminated_at: Option<String>,
    total: i64,
    succeeded: i64,
    failed: i64,
}

/// The account's jobs, newest first (`s3:ListJobs`).
#[utoipa::path(get, path = "/batch-jobs", responses(
    (status = 200, body = Vec<BatchJobSummary>),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn list_batch_jobs(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
) -> Result<Json<Vec<BatchJobSummary>>> {
    let access = actor.access_for(&app).await?;
    let mut jobs = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let query = token
            .as_deref()
            .map(|t| format!("nextToken={}", encode(t)))
            .unwrap_or_default();
        let xml = answered(control::list(&app, &access, actor.account(), &query).await).await?;
        let doc = roxmltree::Document::parse(&xml).map_err(anyhow::Error::from)?;
        let root = doc.root_element();
        for job in child(root, "Jobs")
            .into_iter()
            .flat_map(|j| j.children().filter(|c| c.is_element()))
        {
            let progress = child(job, "ProgressSummary");
            let count = |name| progress.map_or(0, |p| number(p, name));
            jobs.push(BatchJobSummary {
                id: text(job, "JobId").unwrap_or_default(),
                description: text(job, "Description"),
                operation: text(job, "Operation").unwrap_or_default(),
                priority: number(job, "Priority"),
                status: text(job, "Status").unwrap_or_default(),
                created_at: text(job, "CreationTime").unwrap_or_default(),
                terminated_at: text(job, "TerminationDate"),
                total: count("TotalNumberOfTasks"),
                succeeded: count("NumberOfTasksSucceeded"),
                failed: count("NumberOfTasksFailed"),
            });
        }
        token = text(root, "NextToken");
        if token.is_none() {
            break;
        }
    }
    Ok(Json(jobs))
}

/// A manifest object: a CSV one, or an inventory report's `manifest.json`.
#[derive(Serialize, ToSchema)]
struct BatchManifestObject {
    format: String,
    object_arn: String,
    version_id: Option<String>,
    etag: String,
    /// A CSV manifest's columns.
    fields: Vec<String>,
}

fn manifest_object(node: roxmltree::Node) -> BatchManifestObject {
    let spec = child(node, "Spec");
    let location = child(node, "Location");
    let at = |name| location.and_then(|l| text(l, name));
    BatchManifestObject {
        format: spec
            .and_then(|s| text(s, "Format"))
            .or_else(|| text(node, "Format"))
            .unwrap_or_default(),
        object_arn: at("ObjectArn").unwrap_or_default(),
        version_id: at("ObjectVersionId"),
        etag: at("ETag").unwrap_or_default(),
        fields: members(spec.and_then(|s| child(s, "Fields"))),
    }
}

/// Where a job's completion report goes, if it writes one.
#[derive(Serialize, ToSchema)]
struct JobReport {
    enabled: bool,
    /// The bucket's ARN.
    bucket: Option<String>,
    prefix: Option<String>,
    format: Option<String>,
    /// `AllTasks` or `FailedTasksOnly`.
    scope: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct BatchJobFailure {
    code: String,
    reason: String,
}

/// A job, as DescribeJob tells it.
#[derive(Serialize, ToSchema)]
struct BatchJobDetail {
    id: String,
    arn: String,
    description: Option<String>,
    status: String,
    priority: i64,
    confirmation_required: bool,
    operation: String,
    /// What the operation does (its tags, retention, target, …).
    operation_settings: Vec<JobSetting>,
    /// Its manifest, if it was given one.
    manifest: Option<BatchManifestObject>,
    /// Its manifest generator's settings, if it generates its manifest.
    generator: Option<Vec<JobSetting>>,
    /// The manifest it generated, once it has (if it's written out).
    generated_manifest: Option<BatchManifestObject>,
    report: JobReport,
    role_arn: String,
    /// ISO 8601.
    created_at: String,
    terminated_at: Option<String>,
    suspended_at: Option<String>,
    /// `AWAITING_CONFIRMATION`, while it waits to be confirmed.
    suspended_cause: Option<String>,
    status_reason: Option<String>,
    failures: Vec<BatchJobFailure>,
    total: i64,
    succeeded: i64,
    failed: i64,
    active_seconds: i64,
}

#[utoipa::path(get, path = "/batch-jobs/{id}", params(("id" = String, Path)), responses(
    (status = 200, body = BatchJobDetail),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn get_batch_job(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
) -> Result<Json<BatchJobDetail>> {
    let access = actor.access_for(&app).await?;
    let xml = answered(control::describe(&app, &access, actor.account(), &id).await).await?;
    let doc = roxmltree::Document::parse(&xml).map_err(anyhow::Error::from)?;
    let Some(job) = child(doc.root_element(), "Job") else {
        return Err(ApiError::Failed(anyhow::anyhow!(
            "DescribeJob answered no job"
        )));
    };
    let operation = child(job, "Operation").and_then(|o| o.children().find(|c| c.is_element()));
    let report = child(job, "Report");
    let progress = child(job, "ProgressSummary");
    let count = |name| progress.map_or(0, |p| number(p, name));
    Ok(Json(BatchJobDetail {
        id: text(job, "JobId").unwrap_or_default(),
        arn: text(job, "JobArn").unwrap_or_default(),
        description: text(job, "Description"),
        status: text(job, "Status").unwrap_or_default(),
        priority: number(job, "Priority"),
        confirmation_required: text(job, "ConfirmationRequired").as_deref() == Some("true"),
        operation: operation
            .map(|o| o.tag_name().name().to_owned())
            .unwrap_or_default(),
        operation_settings: operation.map(settings).unwrap_or_default(),
        manifest: child(job, "Manifest").map(manifest_object),
        generator: child(job, "ManifestGenerator")
            .and_then(|g| child(g, "S3JobManifestGenerator"))
            .map(settings),
        generated_manifest: child(job, "GeneratedManifestDescriptor").map(manifest_object),
        report: JobReport {
            enabled: report.and_then(|r| text(r, "Enabled")).as_deref() == Some("true"),
            bucket: report.and_then(|r| text(r, "Bucket")),
            prefix: report.and_then(|r| text(r, "Prefix")),
            format: report.and_then(|r| text(r, "Format")),
            scope: report.and_then(|r| text(r, "ReportScope")),
        },
        role_arn: text(job, "RoleArn").unwrap_or_default(),
        created_at: text(job, "CreationTime").unwrap_or_default(),
        terminated_at: text(job, "TerminationDate"),
        suspended_at: text(job, "SuspendedDate"),
        suspended_cause: text(job, "SuspendedCause"),
        status_reason: text(job, "StatusUpdateReason"),
        failures: child(job, "FailureReasons")
            .into_iter()
            .flat_map(|f| f.children().filter(|c| c.is_element()))
            .map(|f| BatchJobFailure {
                code: text(f, "FailureCode").unwrap_or_default(),
                reason: text(f, "FailureReason").unwrap_or_default(),
            })
            .collect(),
        total: count("TotalNumberOfTasks"),
        succeeded: count("NumberOfTasksSucceeded"),
        failed: count("NumberOfTasksFailed"),
        active_seconds: progress
            .and_then(|p| child(p, "Timers"))
            .map_or(0, |t| number(t, "ElapsedTimeInActiveSeconds")),
    }))
}

/// What a new job does to each object.
#[derive(Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
enum BatchOperation {
    /// Replaces each version's tags (`S3PutObjectTagging`).
    PutTagging { tags: Vec<Tag> },
    /// `S3DeleteObjectTagging`.
    DeleteTagging,
    /// `S3PutObjectRetention`: a mode and a date, or neither to remove it.
    PutRetention {
        #[serde(default)]
        mode: String,
        /// ISO 8601.
        #[serde(default)]
        retain_until: String,
        #[serde(default)]
        bypass_governance: bool,
    },
    /// `S3PutObjectLegalHold`.
    PutLegalHold { on: bool },
    /// Batch Replication (`S3ReplicateObject`).
    Replicate,
    /// `S3PutObjectCopy`, into a bucket, under a prefix.
    Copy {
        target_bucket: String,
        #[serde(default)]
        target_prefix: String,
        #[serde(default)]
        storage_class: String,
        #[serde(default)]
        canned_acl: String,
    },
    /// `S3PutObjectAcl`, a canned ACL.
    PutAcl { canned_acl: String },
    /// `S3ComputeObjectChecksum`.
    ComputeChecksum {
        algorithm: String,
        /// `FULL_OBJECT` or `COMPOSITE`.
        #[serde(default)]
        checksum_type: String,
    },
    /// `S3UpdateObjectEncryption`, to SSE-KMS under a key.
    UpdateEncryption {
        kms_key_arn: String,
        #[serde(default)]
        bucket_key_enabled: bool,
    },
}

/// Which objects a new job is on.
#[derive(Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
enum BatchManifest {
    /// A CSV object of `bucket,key` lines (`bucket,key,versionId` with
    /// version IDs).
    Csv {
        bucket: String,
        key: String,
        #[serde(default)]
        version_ids: bool,
        /// The object's ETag (what the job is pinned to).
        etag: String,
        #[serde(default)]
        version_id: String,
    },
    /// An inventory report's `manifest.json`.
    Inventory {
        bucket: String,
        key: String,
        etag: String,
        #[serde(default)]
        version_id: String,
    },
    /// Generated from a bucket's objects, those its filters pass.
    Generate {
        source_bucket: String,
        #[serde(default)]
        prefixes: Vec<String>,
        #[serde(default)]
        suffixes: Vec<String>,
        /// ISO 8601.
        #[serde(default)]
        created_after: String,
        #[serde(default)]
        created_before: String,
        min_size: Option<i64>,
        max_size: Option<i64>,
        #[serde(default)]
        storage_classes: Vec<String>,
        /// Only what its bucket's replication configuration replicates.
        #[serde(default)]
        eligible_for_replication: bool,
        /// `COMPLETED`, `FAILED`, `REPLICA`, `NONE`.
        #[serde(default)]
        replication_statuses: Vec<String>,
        /// Where to write the manifest out (empty: it isn't).
        #[serde(default)]
        output_bucket: String,
        #[serde(default)]
        output_prefix: String,
    },
}

/// A new job's completion report.
#[derive(Deserialize, ToSchema)]
struct BatchReport {
    enabled: bool,
    #[serde(default)]
    bucket: String,
    #[serde(default)]
    prefix: String,
    /// Only the tasks that failed.
    #[serde(default)]
    failed_only: bool,
}

/// A new job, as the console asks for it.
#[derive(Deserialize, ToSchema)]
struct NewBatchJob {
    #[serde(default)]
    description: String,
    priority: i32,
    /// Whether it waits to be confirmed before it runs.
    #[serde(default)]
    confirmation_required: bool,
    /// The role it acts as.
    role_arn: String,
    operation: BatchOperation,
    manifest: BatchManifest,
    report: BatchReport,
}

/// `element`, unless `text` is empty.
fn optional(name: &str, text: &str) -> String {
    match text.is_empty() {
        true => String::new(),
        false => element(name, text),
    }
}

fn list_xml(name: &str, items: &[String]) -> String {
    match items.is_empty() {
        true => String::new(),
        false => format!(
            "<{name}>{}</{name}>",
            items
                .iter()
                .map(|i| element("member", i))
                .collect::<String>()
        ),
    }
}

fn bucket_arn(bucket: &str) -> String {
    match bucket.is_empty() || bucket.starts_with("arn:") {
        true => bucket.to_owned(),
        false => format!("arn:aws:s3:::{bucket}"),
    }
}

impl BatchOperation {
    fn xml(&self) -> String {
        let inner = match self {
            BatchOperation::PutTagging { tags } => {
                let tags: String = tags
                    .iter()
                    .map(|t| {
                        format!(
                            "<member>{}{}</member>",
                            element("Key", &t.key),
                            element("Value", &t.value)
                        )
                    })
                    .collect();
                format!("<S3PutObjectTagging><TagSet>{tags}</TagSet></S3PutObjectTagging>")
            }
            BatchOperation::DeleteTagging => "<S3DeleteObjectTagging/>".to_owned(),
            BatchOperation::PutRetention {
                mode,
                retain_until,
                bypass_governance,
            } => format!(
                "<S3PutObjectRetention>{}<Retention>{}{}</Retention></S3PutObjectRetention>",
                element("BypassGovernanceRetention", &bypass_governance.to_string()),
                optional("Mode", mode),
                optional("RetainUntilDate", retain_until)
            ),
            BatchOperation::PutLegalHold { on } => format!(
                "<S3PutObjectLegalHold><LegalHold>{}</LegalHold></S3PutObjectLegalHold>",
                element("Status", if *on { "ON" } else { "OFF" })
            ),
            BatchOperation::Replicate => "<S3ReplicateObject/>".to_owned(),
            BatchOperation::Copy {
                target_bucket,
                target_prefix,
                storage_class,
                canned_acl,
            } => format!(
                "<S3PutObjectCopy>{}{}{}{}</S3PutObjectCopy>",
                optional("TargetResource", &bucket_arn(target_bucket)),
                optional("TargetKeyPrefix", target_prefix),
                optional("StorageClass", storage_class),
                optional("CannedAccessControlList", canned_acl)
            ),
            BatchOperation::PutAcl { canned_acl } => format!(
                "<S3PutObjectAcl><AccessControlPolicy>{}</AccessControlPolicy></S3PutObjectAcl>",
                optional("CannedAccessControlList", canned_acl)
            ),
            BatchOperation::ComputeChecksum {
                algorithm,
                checksum_type,
            } => format!(
                "<S3ComputeObjectChecksum>{}{}</S3ComputeObjectChecksum>",
                optional("ChecksumAlgorithm", algorithm),
                optional("ChecksumType", checksum_type)
            ),
            BatchOperation::UpdateEncryption {
                kms_key_arn,
                bucket_key_enabled,
            } => format!(
                "<S3UpdateObjectEncryption><ObjectEncryption><SSE-KMS>{}{}</SSE-KMS></ObjectEncryption>\
                 </S3UpdateObjectEncryption>",
                optional("KMSKeyArn", kms_key_arn),
                element("BucketKeyEnabled", &bucket_key_enabled.to_string())
            ),
        };
        format!("<Operation>{inner}</Operation>")
    }
}

impl BatchManifest {
    fn xml(&self) -> String {
        let location = |bucket: &str, key: &str, etag: &str, version_id: &str| {
            format!(
                "<Location>{}{}{}</Location>",
                element("ObjectArn", &format!("arn:aws:s3:::{bucket}/{key}")),
                optional("ObjectVersionId", version_id),
                optional("ETag", etag)
            )
        };
        match self {
            BatchManifest::Csv {
                bucket,
                key,
                version_ids,
                etag,
                version_id,
            } => {
                let fields = match version_ids {
                    true => "<member>Bucket</member><member>Key</member><member>VersionId</member>",
                    false => "<member>Bucket</member><member>Key</member>",
                };
                format!(
                    "<Manifest><Spec>{}<Fields>{fields}</Fields></Spec>{}</Manifest>",
                    element("Format", crate::batch::manifest::CSV),
                    location(bucket, key, etag, version_id)
                )
            }
            BatchManifest::Inventory {
                bucket,
                key,
                etag,
                version_id,
            } => format!(
                "<Manifest><Spec>{}</Spec>{}</Manifest>",
                element("Format", crate::batch::manifest::INVENTORY),
                location(bucket, key, etag, version_id)
            ),
            BatchManifest::Generate {
                source_bucket,
                prefixes,
                suffixes,
                created_after,
                created_before,
                min_size,
                max_size,
                storage_classes,
                eligible_for_replication,
                replication_statuses,
                output_bucket,
                output_prefix,
            } => {
                let mut filter = String::new();
                if *eligible_for_replication {
                    filter.push_str("<EligibleForReplication>true</EligibleForReplication>");
                }
                filter.push_str(&optional("CreatedAfter", created_after));
                filter.push_str(&optional("CreatedBefore", created_before));
                filter.push_str(&list_xml("ObjectReplicationStatuses", replication_statuses));
                if !prefixes.is_empty() || !suffixes.is_empty() {
                    filter.push_str(&format!(
                        "<KeyNameConstraint>{}{}</KeyNameConstraint>",
                        list_xml("MatchAnyPrefix", prefixes),
                        list_xml("MatchAnySuffix", suffixes)
                    ));
                }
                if let Some(size) = min_size {
                    filter.push_str(&element("ObjectSizeGreaterThanBytes", &size.to_string()));
                }
                if let Some(size) = max_size {
                    filter.push_str(&element("ObjectSizeLessThanBytes", &size.to_string()));
                }
                filter.push_str(&list_xml("MatchAnyStorageClass", storage_classes));
                let output = match output_bucket.is_empty() {
                    true => String::new(),
                    false => format!(
                        "<ManifestOutputLocation>{}{}{}</ManifestOutputLocation>",
                        element("Bucket", &bucket_arn(output_bucket)),
                        optional("ManifestPrefix", output_prefix),
                        element(
                            "ManifestFormat",
                            crate::batch::manifest::GENERATED_INVENTORY
                        )
                    ),
                };
                let filter = match filter.is_empty() {
                    true => String::new(),
                    false => format!("<Filter>{filter}</Filter>"),
                };
                format!(
                    "<ManifestGenerator><S3JobManifestGenerator>{}{output}{filter}{}\
                     </S3JobManifestGenerator></ManifestGenerator>",
                    element("SourceBucket", &bucket_arn(source_bucket)),
                    element(
                        "EnableManifestOutput",
                        &(!output_bucket.is_empty()).to_string()
                    )
                )
            }
        }
    }
}

impl BatchReport {
    fn xml(&self) -> String {
        match self.enabled {
            false => "<Report><Enabled>false</Enabled></Report>".to_owned(),
            true => format!(
                "<Report>{}{}<Enabled>true</Enabled>{}{}</Report>",
                optional("Bucket", &bucket_arn(&self.bucket)),
                element("Format", crate::batch::report::FORMAT),
                optional("Prefix", &self.prefix),
                element(
                    "ReportScope",
                    match self.failed_only {
                        true => crate::batch::report::FAILED_TASKS_ONLY,
                        false => crate::batch::report::ALL_TASKS,
                    }
                )
            ),
        }
    }
}

impl NewBatchJob {
    /// It as CreateJob's request, with a token of its own (each job the
    /// console makes is a new one).
    fn xml(&self) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CreateJobRequest>{}{}{}{}{}{}{}{}</CreateJobRequest>",
            element(
                "ConfirmationRequired",
                &self.confirmation_required.to_string()
            ),
            self.operation.xml(),
            self.report.xml(),
            element("ClientRequestToken", &uuid::Uuid::new_v4().to_string()),
            self.manifest.xml(),
            optional("Description", &self.description),
            element("Priority", &self.priority.to_string()),
            optional("RoleArn", &self.role_arn),
        )
    }
}

/// The made job.
#[derive(Serialize, ToSchema)]
struct MadeBatchJob {
    id: String,
}

/// Makes a job, as CreateJob does (`s3:CreateJob`, and `iam:PassRole` on
/// its role).
#[utoipa::path(post, path = "/batch-jobs", request_body = NewBatchJob, responses(
    (status = 201, body = MadeBatchJob),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_batch_job(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Json(body): Json<NewBatchJob>,
) -> Result<(StatusCode, Json<MadeBatchJob>)> {
    let access = actor.access_for(&app).await?;
    let request = body.xml();
    let xml =
        answered(control::create(&app, &access, actor.account(), request.as_bytes()).await).await?;
    let doc = roxmltree::Document::parse(&xml).map_err(anyhow::Error::from)?;
    let id = text(doc.root_element(), "JobId").unwrap_or_default();
    Ok((StatusCode::CREATED, Json(MadeBatchJob { id })))
}

#[derive(Deserialize, ToSchema)]
struct BatchJobPriority {
    priority: i32,
}

/// Sets a job's priority, as UpdateJobPriority does.
#[utoipa::path(put, path = "/batch-jobs/{id}/priority", params(("id" = String, Path)),
    request_body = BatchJobPriority, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn set_batch_job_priority(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
    Json(body): Json<BatchJobPriority>,
) -> Result<StatusCode> {
    let access = actor.access_for(&app).await?;
    let query = format!("priority={}", body.priority);
    answered(control::update_priority(&app, &access, actor.account(), &id, &query).await).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct BatchJobStatus {
    /// `Ready` (confirms a job awaiting it) or `Cancelled`.
    status: String,
    /// Why (kept with the job).
    #[serde(default)]
    reason: String,
}

/// Confirms or cancels a job, as UpdateJobStatus does.
#[utoipa::path(put, path = "/batch-jobs/{id}/status", params(("id" = String, Path)),
    request_body = BatchJobStatus, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn set_batch_job_status(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
    Json(body): Json<BatchJobStatus>,
) -> Result<StatusCode> {
    let access = actor.access_for(&app).await?;
    let mut query = format!("requestedJobStatus={}", encode(&body.status));
    if !body.reason.is_empty() {
        query.push_str(&format!("&statusUpdateReason={}", encode(&body.reason)));
    }
    answered(control::update_status(&app, &access, actor.account(), &id, &query).await).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod e2e {
    use axum::http::StatusCode;
    use serde_json::{Value, json};

    use super::super::e2e::{console_of, signed_in};
    use crate::e2e::BUCKET;

    /// A job generating its manifest from `BUCKET`, tagging what it lists,
    /// as `role`.
    fn new_job(role: &str) -> Value {
        json!({
            "description": "tag the reports",
            "priority": 10,
            "confirmation_required": true,
            "role_arn": role,
            "operation": { "type": "put_tagging", "tags": [{ "key": "a", "value": "1" }] },
            "manifest": { "type": "generate", "source_bucket": BUCKET, "prefixes": ["reports/"] },
            "report": { "enabled": false },
        })
    }

    /// Jobs as the console makes, lists, describes, confirms, reprioritizes
    /// and cancels them: S3 Control's requests, checked as S3 Control checks
    /// them (`iam:PassRole` on the role too).
    #[tokio::test]
    async fn manages_batch_jobs() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = console_of(&app);
        let mut admin = signed_in(&console, "admin", true).await;
        let mut creator = signed_in(&console, "creator", false).await;
        let client = app.pool.get().await.unwrap();
        let account = crate::users::account(&client).await.unwrap();
        let role = format!("arn:aws:iam::{account}:role/batch");

        // S3 Control's validation: a role's ARN, an operation as it takes it.
        let mut bad = new_job("not-a-role");
        let (status, body) = admin
            .send("POST", "/api/batch-jobs", Some(bad.clone()))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("isn't a role's ARN")
        );
        bad["role_arn"] = json!(role);
        bad["operation"] = json!({ "type": "put_retention", "mode": "SOMETIMES", "retain_until": "2099-01-01T00:00:00Z" });
        let (status, _) = admin.send("POST", "/api/batch-jobs", Some(bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, made) = admin
            .send("POST", "/api/batch-jobs", Some(new_job(&role)))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{made}");
        let id = made["id"].as_str().unwrap().to_owned();
        let path = format!("/api/batch-jobs/{id}");

        let (status, list) = admin.send("GET", "/api/batch-jobs", None).await;
        assert_eq!(status, StatusCode::OK, "{list}");
        assert_eq!(list[0]["id"], id);
        assert_eq!(list[0]["operation"], "S3PutObjectTagging");
        assert_eq!(list[0]["priority"], 10);

        let (status, job) = admin.send("GET", &path, None).await;
        assert_eq!(status, StatusCode::OK, "{job}");
        assert_eq!(job["operation"], "S3PutObjectTagging");
        assert_eq!(job["operation_settings"][0]["name"], "TagSet");
        assert_eq!(job["operation_settings"][0]["value"], "a=1");
        assert_eq!(job["confirmation_required"], true);
        assert_eq!(job["role_arn"], role);
        assert_eq!(job["manifest"], Value::Null);
        let generator = job["generator"].as_array().unwrap();
        let has = |name: &str, value: &str| {
            generator
                .iter()
                .any(|s| s["name"] == name && s["value"] == value)
        };
        assert!(has("SourceBucket", &format!("arn:aws:s3:::{BUCKET}")));
        assert!(has("Filter.KeyNameConstraint.MatchAnyPrefix", "reports/"));
        assert_eq!(job["report"]["enabled"], false);

        // Not awaiting confirmation yet; then, once prepared, it is.
        let ready = json!({ "status": "Ready" });
        let (status, _) = admin
            .send("PUT", &format!("{path}/status"), Some(ready.clone()))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        client
            .execute(
                "UPDATE batch_jobs SET status = 'Suspended', suspended_cause = $2 WHERE id = $1",
                &[
                    &uuid::Uuid::parse_str(&id).unwrap(),
                    &crate::batch::AWAITING_CONFIRMATION,
                ],
            )
            .await
            .unwrap();
        let (_, job) = admin.send("GET", &path, None).await;
        assert_eq!(job["suspended_cause"], "AWAITING_CONFIRMATION");
        let (status, body) = admin
            .send("PUT", &format!("{path}/status"), Some(ready))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        let (_, job) = admin.send("GET", &path, None).await;
        assert_eq!(job["status"], "Ready");

        let priority = |p: i32| Some(json!({ "priority": p }));
        let (status, _) = admin
            .send("PUT", &format!("{path}/priority"), priority(42))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = admin
            .send("PUT", &format!("{path}/priority"), priority(-1))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let cancel = json!({ "status": "Cancelled", "reason": "not needed" });
        let (status, _) = admin
            .send("PUT", &format!("{path}/status"), Some(cancel.clone()))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, job) = admin.send("GET", &path, None).await;
        assert_eq!(job["status"], "Cancelled");
        assert_eq!(job["priority"], 42);
        assert_eq!(job["status_reason"], "not needed");
        let (status, _) = admin
            .send("PUT", &format!("{path}/status"), Some(cancel))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            admin
                .send(
                    "GET",
                    "/api/batch-jobs/00000000-0000-0000-0000-000000000000",
                    None
                )
                .await
                .0,
            StatusCode::NOT_FOUND
        );

        // The user's policies decide: listing, describing, and making a
        // job, which needs iam:PassRole on its role too.
        assert_eq!(
            creator.send("GET", "/api/batch-jobs", None).await.0,
            StatusCode::FORBIDDEN
        );
        let allowed =
            r#"{"Effect":"Allow","Action":["s3:CreateJob","s3:ListJobs"],"Resource":"*"}"#;
        let policy = format!(r#"{{"Version":"2012-10-17","Statement":[{allowed}]}}"#);
        crate::users::put_policy(&client, &account, "creator", "p", &policy)
            .await
            .unwrap();
        let (status, list) = creator.send("GET", "/api/batch-jobs", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(list.as_array().unwrap().len(), 1);
        assert_eq!(
            creator.send("GET", &path, None).await.0,
            StatusCode::FORBIDDEN
        );
        let (status, body) = creator
            .send("POST", "/api/batch-jobs", Some(new_job(&role)))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            body["error"].as_str().unwrap().contains("iam:PassRole"),
            "{body}"
        );
        let policy = format!(
            r#"{{"Version":"2012-10-17","Statement":[{allowed},{{"Effect":"Allow","Action":"iam:PassRole","Resource":"{role}"}}]}}"#
        );
        crate::users::put_policy(&client, &account, "creator", "p", &policy)
            .await
            .unwrap();
        let (status, body) = creator
            .send("POST", "/api/batch-jobs", Some(new_job(&role)))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
}
