//! Replication to other clusters: Cairn's, MinIO's or RustFS's (see
//! `inbound` for the other way).
//!
//! A **remote** is another cluster's S3 endpoint, with credentials and a
//! kind (`cairn remote add`): a replication rule names a bucket there by an
//! ARN of its own, `arn:cairn:replication::<remote>:<bucket>` (or MinIO's
//! form, `arn:minio:replication:<region>:<remote>:<bucket>`, which a
//! configuration written for MinIO has, once its remote is registered by
//! that ID). Versions are queued for it as for a bucket of the cluster
//! (`<remote>:<bucket>`, see `config::Destination::target`), and replicated
//! by the same worker, by MinIO's requests (see `inbound`, which takes
//! them): S3's own, marked as replication's, with what the replica keeps of
//! its source in headers, both MinIO's and RustFS's.
//!
//! - An object's version is read (as the configuration's role, which must
//!   be allowed `s3:GetObjectVersionForReplication`, as within the
//!   cluster; and which opens SSE-KMS versions), and written there with
//!   its version ID, last-modified time, ETag, content headers, metadata,
//!   tags and Object Lock: in one PutObject up to `SINGLE` bytes, else as
//!   a multipart upload, whose ETag the destination keeps the source's of
//!   too. SSE-S3 versions ask for SSE-S3 there, and SSE-KMS ones for the
//!   rule's KMS key (`ReplicaKmsKeyID`, as the remote names it). An SSE-C
//!   version can't be read without its client's key, and fails.
//! - A delete marker, as a DeleteObject of its version ID, marked as one.
//! - A deletion of a version (a rule with `DeleteReplication`), as a
//!   DeleteObject of its version ID.
//!
//! A version that's there already (a HeadObject of its ID finds it) isn't
//! written again. The remote's answers decide: a 4xx fails the version
//! (the credentials may not, the bucket isn't there or isn't versioned),
//! and anything else (the network, 5xx) is tried again later, as within
//! the cluster.
//!
//! MinIO and RustFS take only UUIDs for version IDs: to them, a version of
//! Cairn's is known by its UUID form (see `s3::versions::uuid_form`), and
//! `inbound` finds it by that again. A Cairn remote is sent the ID as it is.
//!
//! The remote's credentials are what may write there: its users' policies
//! decide, as `s3:ReplicateObject`, `s3:ReplicateTags` and
//! `s3:ReplicateDelete` (Cairn's, see `inbound`; MinIO also wants
//! `s3:PutObject` and `s3:DeleteObject`).

use std::sync::Arc;

use clap::{Args, Subcommand, ValueEnum};
use deadpool_postgres::GenericClient;
use http_body_util::BodyExt;
use hyper::{Method, StatusCode, body::Bytes};
use serde::{Deserialize, Serialize};

use super::{Outcome, Queued, Version, config::Rule};
use crate::{
    App,
    admin::{Output, outln},
    backup::s3::{Failed, Location, Target},
    db::Cached,
    s3::{conditional::Preconditions, versions::uuid_form},
    users::Principal,
};

/// The largest version written in one PutObject; larger ones are
/// multipart uploads.
const SINGLE: u64 = 16 << 20;
/// The most parts an upload may have, as in S3.
const MAX_PARTS: u64 = 10_000;
/// How many versions a node writes to remotes at once (each holds a part
/// in memory).
static TRANSFERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8);

/// What a remote is: how it takes version IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
pub enum Kind {
    Cairn,
    Minio,
    Rustfs,
}

impl Kind {
    /// Its name: `cairn`, `minio` or `rustfs`.
    pub fn name(self) -> &'static str {
        match self {
            Kind::Cairn => "cairn",
            Kind::Minio => "minio",
            Kind::Rustfs => "rustfs",
        }
    }

    /// The kind named `name` (see [`Kind::name`]).
    pub fn parse(name: &str) -> Option<Kind> {
        [Kind::Cairn, Kind::Minio, Kind::Rustfs]
            .into_iter()
            .find(|k| k.name() == name)
    }

    /// Version `id`, as the remote knows it.
    fn version_id(self, id: &str) -> String {
        match self {
            Kind::Cairn => id.to_owned(),
            Kind::Minio | Kind::Rustfs => uuid_form(id),
        }
    }
}

/// A registered remote.
pub struct Remote {
    pub name: String,
    pub kind: Kind,
    endpoint: String,
    region: String,
    path_style: bool,
    access_key_id: String,
    secret_access_key: String,
}

impl Remote {
    /// The remote `name`, if there's one.
    pub async fn load(app: &App, name: &str) -> anyhow::Result<Option<Remote>> {
        let row = app
            .pool
            .get()
            .await?
            .query_opt_cached(
                "SELECT endpoint, region, path_style, access_key_id, secret_access_key, kind
                 FROM replication_remotes WHERE name = $1",
                &[&name],
            )
            .await?;
        let Some(row) = row else { return Ok(None) };
        let kind: &str = row.get(5);
        Ok(Some(Remote {
            name: name.to_owned(),
            kind: Kind::parse(kind)
                .ok_or_else(|| anyhow::anyhow!("remote {name}'s kind {kind} is unknown"))?,
            endpoint: row.get(0),
            region: row.get(1),
            path_style: row.get(2),
            access_key_id: row.get(3),
            secret_access_key: row.get(4),
        }))
    }

    /// A client of its bucket `bucket`.
    pub fn bucket(&self, bucket: &str) -> anyhow::Result<Target> {
        Target::new(Location {
            endpoint: self.endpoint.clone(),
            region: self.region.clone(),
            bucket: bucket.to_owned(),
            prefix: String::new(),
            path_style: self.path_style,
            access_key_id: self.access_key_id.clone(),
            secret_access_key: self.secret_access_key.clone(),
        })
    }

    /// Why its bucket `bucket` can't take replicas, if it can't: it isn't
    /// there, or reachable with the remote's credentials, or versioned, or
    /// (if `locked`) has no Object Lock.
    pub async fn refuse(&self, bucket: &str, locked: bool) -> anyhow::Result<Option<String>> {
        let target = self.bucket(bucket)?;
        let empty = Bytes::new();
        let versioning = match target
            .call(Method::GET, None, &[("versioning", "")], &[], empty.clone())
            .await
        {
            Ok(answer) => answer,
            Err(e) => {
                return Ok(Some(format!(
                    "Destination bucket {bucket} at remote {} can't be reached: {e:#}",
                    self.name
                )));
            }
        };
        if xml_text(&versioning.body, "Status").as_deref() != Some("Enabled") {
            return Ok(Some(format!(
                "Destination bucket {bucket} at remote {} must have versioning enabled.",
                self.name
            )));
        }
        if locked {
            let lock = target
                .call(Method::GET, None, &[("object-lock", "")], &[], empty)
                .await;
            let enabled = lock.is_ok_and(|answer| {
                xml_text(&answer.body, "ObjectLockEnabled").as_deref() == Some("Enabled")
            });
            if !enabled {
                return Ok(Some(format!(
                    "Object Lock is enabled on the source bucket, so it must be on destination bucket {bucket} at \
                     remote {} too.",
                    self.name
                )));
            }
        }
        Ok(None)
    }
}

/// The text of the first element `tag` of XML document `body`.
fn xml_text(body: &[u8], tag: &str) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let doc = roxmltree::Document::parse(text).ok()?;
    doc.descendants()
        .find(|n| n.has_tag_name(tag))
        .map(|n| n.text().unwrap_or_default().to_owned())
}

/// The headers that mark a request as replication's, both MinIO's and
/// RustFS's, with `suffix`'s value `value` (see `inbound`).
fn marked(headers: &mut Vec<(String, String)>, suffix: &str, value: &str) {
    for name in super::inbound::header_names(suffix) {
        headers.push((name, value.to_owned()));
    }
}

/// What a remote's refusal (or failure to answer) comes to.
fn outcome_of_error(remote: &str, e: anyhow::Error) -> Outcome {
    let why = format!("remote {remote}: {e:#}");
    match e.downcast_ref::<Failed>() {
        Some(failed)
            if failed.status.is_client_error()
                && failed.status != StatusCode::TOO_MANY_REQUESTS
                && failed.status != StatusCode::REQUEST_TIMEOUT =>
        {
            Outcome::Failed(why)
        }
        _ => Outcome::Retry(why),
    }
}

/// The headers of a read of a version that its replica keeps: its content
/// headers, metadata and Object Lock.
fn kept_headers(read: &hyper::HeaderMap) -> Vec<(String, String)> {
    const KEPT: [&str; 10] = [
        "content-type",
        "content-encoding",
        "content-disposition",
        "content-language",
        "cache-control",
        "expires",
        "x-amz-website-redirect-location",
        "x-amz-object-lock-mode",
        "x-amz-object-lock-retain-until-date",
        "x-amz-object-lock-legal-hold",
    ];
    read.iter()
        .filter(|(name, _)| {
            KEPT.contains(&name.as_str()) || name.as_str().starts_with("x-amz-meta-")
        })
        .filter_map(|(name, value)| {
            Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
        })
        .collect()
}

/// Replicates the queued version `q`, an object's or a delete marker's
/// (`version`), to its rule's remote bucket.
pub(super) async fn replicate(
    app: &Arc<App>,
    principal: &Principal,
    rule: &Rule,
    q: &Queued,
    version: &Version,
) -> anyhow::Result<Outcome> {
    let destination = &rule.destination;
    let name = destination.remote.as_deref().expect("a remote destination");
    let Some(remote) = Remote::load(app, name).await? else {
        return Ok(Outcome::Failed(format!("there's no remote {name}")));
    };
    let target = remote.bucket(&destination.bucket)?;
    let version_id = remote.kind.version_id(&q.version_id);
    let mut headers: Vec<(String, String)> =
        vec![("x-amz-replication-status".to_owned(), "REPLICA".to_owned())];
    marked(&mut headers, "source-replication-request", "true");
    marked(&mut headers, "source-version-id", &version_id);
    marked(&mut headers, "source-mtime", &version.last_modified);
    if version.marker {
        marked(&mut headers, "source-deletemarker", "true");
        let headers: Vec<(&str, &str)> = headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        return Ok(
            match target
                .call(
                    Method::DELETE,
                    Some(&q.key),
                    &[("versionId", &version_id)],
                    &headers,
                    Bytes::new(),
                )
                .await
            {
                Ok(_) => Outcome::Done,
                Err(e) => outcome_of_error(name, e),
            },
        );
    }
    if version.customer.is_some() {
        return Ok(Outcome::Failed(
            "an SSE-C version can't be replicated to another cluster: its data can't be read without its client's key"
                .to_owned(),
        ));
    }
    if version.kms {
        let Some(key) = &destination.kms_key else {
            return Ok(Outcome::Failed(
                "its rule names no KMS key for SSE-KMS replicas".to_owned(),
            ));
        };
        headers.push((
            "x-amz-server-side-encryption".to_owned(),
            "aws:kms".to_owned(),
        ));
        headers.push((
            "x-amz-server-side-encryption-aws-kms-key-id".to_owned(),
            key.clone(),
        ));
    } else if version.s3 {
        headers.push((
            "x-amz-server-side-encryption".to_owned(),
            "AES256".to_owned(),
        ));
    }
    // There already: an earlier attempt's, which didn't get to say so.
    match target
        .call(
            Method::HEAD,
            Some(&q.key),
            &[("versionId", &version_id)],
            &[],
            Bytes::new(),
        )
        .await
    {
        Ok(_) => return Ok(Outcome::Done),
        Err(e) if e.downcast_ref::<Failed>().is_some() => {}
        Err(e) => return Ok(outcome_of_error(name, e)),
    }
    let _permit = TRANSFERS.acquire().await?;
    let role = Some(principal.kms_caller()?);
    let head = crate::s3::objects::get::head_object(
        app,
        &q.bucket,
        &q.key,
        Some(&q.version_id),
        None,
        None,
        &Preconditions::default(),
        None,
        role.clone(),
        false,
    )
    .await?;
    match head.status() {
        StatusCode::OK => {}
        // Deleted since: there's nothing to replicate.
        StatusCode::NOT_FOUND => return Ok(Outcome::Done),
        status => {
            let retry = status.is_server_error();
            let why = crate::inventory::refusal(head).await;
            return Ok(if retry {
                Outcome::Retry(why)
            } else {
                Outcome::Failed(why)
            });
        }
    }
    let size: u64 = head
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("a version's HEAD without a length"))?;
    let etag = head
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim_matches('"').to_owned())
        .ok_or_else(|| anyhow::anyhow!("a version's HEAD without an ETag"))?;
    marked(&mut headers, "source-etag", &etag);
    headers.extend(kept_headers(head.headers()));
    if !version.tags.is_empty() {
        headers.push(("x-amz-tagging".to_owned(), version.tags.clone()));
    }
    if let Some(class) = &destination.storage_class {
        headers.push(("x-amz-storage-class".to_owned(), class.clone()));
    }
    // Bytes [`start`, `end`) of the version.
    let read = |start: u64, end: u64| {
        let app = app.clone();
        let role = role.clone();
        let (bucket, key, id) = (q.bucket.clone(), q.key.clone(), q.version_id.clone());
        async move {
            let range = (end > start).then(|| format!("bytes={start}-{}", end - 1));
            let response = crate::s3::objects::get::get_object(
                &app,
                &bucket,
                &key,
                Some(&id),
                range.as_deref(),
                None,
                &Preconditions::default(),
                None,
                role,
                false,
            )
            .await?;
            anyhow::ensure!(
                response.status().is_success(),
                "reading bytes {start}-{end} of the version: {}",
                response.status()
            );
            let body = response.into_body().collect().await?.to_bytes();
            anyhow::ensure!(
                end == start || body.len() as u64 == end - start,
                "reading bytes {start}-{end} of the version: {} bytes",
                body.len()
            );
            Ok::<Bytes, anyhow::Error>(if end == start { Bytes::new() } else { body })
        }
    };
    let sent = if size <= SINGLE {
        let body = read(0, size).await?;
        let headers: Vec<(&str, &str)> = headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        target
            .call(
                Method::PUT,
                Some(&q.key),
                &[("versionId", &version_id)],
                &headers,
                body,
            )
            .await
            .map(|_| ())
    } else {
        upload(&target, &q.key, &version_id, &headers, size, read).await
    };
    Ok(match sent {
        Ok(()) => Outcome::Done,
        Err(e) => outcome_of_error(name, e),
    })
}

/// Writes a version of `size` bytes, which `read` reads ranges of, as a
/// multipart upload of `key` with `headers` (its version ID and ETag with
/// the upload's start, as MinIO sends them; the time and ETag with its
/// completion).
async fn upload<F, R>(
    target: &Target,
    key: &str,
    version_id: &str,
    headers: &[(String, String)],
    size: u64,
    read: F,
) -> anyhow::Result<()>
where
    F: Fn(u64, u64) -> R,
    R: std::future::Future<Output = anyhow::Result<Bytes>>,
{
    let part_size = SINGLE.max(size.div_ceil(MAX_PARTS).next_multiple_of(1 << 20));
    // The time is the completion's, as MinIO sends it; the ETag both's, as
    // MinIO keeps the start's and Cairn the completion's.
    let completing = |name: &str| name.ends_with("source-mtime");
    let start: Vec<(&str, &str)> = headers
        .iter()
        .filter(|(n, _)| !completing(n))
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    let marks: Vec<(&str, &str)> = headers
        .iter()
        .filter(|(n, _)| {
            n.contains("source-replication-request") || n == "x-amz-replication-status"
        })
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    let complete: Vec<(&str, &str)> = headers
        .iter()
        .filter(|(n, _)| {
            completing(n)
                || n.ends_with("source-etag")
                || n.contains("source-replication-request")
                || n == "x-amz-replication-status"
        })
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    let answer = target
        .call(
            Method::POST,
            Some(key),
            &[("uploads", ""), ("versionId", version_id)],
            &start,
            Bytes::new(),
        )
        .await?;
    let upload_id = xml_text(&answer.body, "UploadId")
        .ok_or_else(|| anyhow::anyhow!("the remote started an upload without an UploadId"))?;
    let result: anyhow::Result<()> = async {
        let mut etags = Vec::new();
        let mut offset = 0;
        let mut number = 0u64;
        while offset < size {
            number += 1;
            let end = (offset + part_size).min(size);
            let body = read(offset, end).await?;
            let number_text = number.to_string();
            let answer = target
                .call(
                    Method::PUT,
                    Some(key),
                    &[("partNumber", &number_text), ("uploadId", &upload_id)],
                    &marks,
                    body,
                )
                .await?;
            let etag = answer
                .headers
                .get("etag")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
                .ok_or_else(|| anyhow::anyhow!("the remote took a part without an ETag"))?;
            etags.push(etag);
            offset = end;
        }
        let mut doc = String::from("<CompleteMultipartUpload>");
        for (i, etag) in etags.iter().enumerate() {
            doc.push_str(&format!(
                "<Part><PartNumber>{}</PartNumber><ETag>{}</ETag></Part>",
                i + 1,
                crate::s3::util::xml_escape(etag)
            ));
        }
        doc.push_str("</CompleteMultipartUpload>");
        let answer = target
            .call(
                Method::POST,
                Some(key),
                &[("uploadId", &upload_id)],
                &complete,
                Bytes::from(doc),
            )
            .await?;
        // S3 may answer 200 with an error document, after it started.
        if let Some(code) = xml_text(&answer.body, "Code") {
            anyhow::bail!(Failed {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code,
                message: xml_text(&answer.body, "Message").unwrap_or_default(),
            });
        }
        Ok(())
    }
    .await;
    if result.is_err() {
        // Best effort: what's left is the remote's lifecycle's to abort.
        let _ = target
            .call(
                Method::DELETE,
                Some(key),
                &[("uploadId", &upload_id)],
                &marks,
                Bytes::new(),
            )
            .await;
    }
    result
}

/// Replicates the deletion of the queued version `q` (`marker` if it was a
/// delete marker) to its rule's remote bucket: the version there is
/// deleted, if it's there.
pub(super) async fn purge(app: &App, rule: &Rule, q: &Queued) -> anyhow::Result<Outcome> {
    let destination = &rule.destination;
    let name = destination.remote.as_deref().expect("a remote destination");
    let Some(remote) = Remote::load(app, name).await? else {
        return Ok(Outcome::Failed(format!("there's no remote {name}")));
    };
    let target = remote.bucket(&destination.bucket)?;
    let version_id = remote.kind.version_id(&q.version_id);
    let mut headers: Vec<(String, String)> =
        vec![("x-amz-replication-status".to_owned(), "REPLICA".to_owned())];
    marked(&mut headers, "source-replication-request", "true");
    marked(&mut headers, "source-version-id", &version_id);
    let headers: Vec<(&str, &str)> = headers
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    Ok(
        match target
            .call(
                Method::DELETE,
                Some(&q.key),
                &[("versionId", &version_id)],
                &headers,
                Bytes::new(),
            )
            .await
        {
            Ok(_) => Outcome::Done,
            // Not there: nothing's left to delete.
            Err(e)
                if e.downcast_ref::<Failed>().is_some_and(|f| {
                    f.status == StatusCode::NOT_FOUND && f.code != "NoSuchBucket"
                }) =>
            {
                Outcome::Done
            }
            Err(e) => outcome_of_error(name, e),
        },
    )
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Args, Debug, Serialize, Deserialize)]
pub struct RemoteArgs {
    #[command(flatten)]
    #[serde(skip)]
    pub remote: crate::admin::Remote,
    #[command(subcommand)]
    command: RemoteCommand,
}

#[derive(Subcommand, Debug, Serialize, Deserialize)]
enum RemoteCommand {
    /// List the remotes, and the buckets whose rules replicate to them.
    List,
    /// Add a remote: another cluster's S3 endpoint, which buckets'
    /// replication rules can name buckets of
    /// (`arn:cairn:replication::<name>:<bucket>`).
    Add {
        /// Its name: lowercase letters, digits, - and _. To take a
        /// configuration written for MinIO as it is, the ID its ARNs have.
        name: String,
        /// Its S3 endpoint's URL, e.g. https://s3.dc2.example.com.
        #[arg(long)]
        endpoint: String,
        /// The region requests are signed for.
        #[arg(long, default_value = "us-east-1")]
        region: String,
        /// Name buckets in the path (host/bucket/key) rather than the host
        /// (bucket.host/key), as MinIO and RustFS are usually set up.
        #[arg(long)]
        path_style: bool,
        /// What it is: Cairn takes version IDs as they are; MinIO and
        /// RustFS take UUIDs, which Cairn's IDs are sent as.
        #[arg(long, value_enum)]
        kind: Kind,
        #[arg(long, env = "CAIRN_REMOTE_ACCESS_KEY_ID")]
        access_key_id: String,
        #[arg(long, env = "CAIRN_REMOTE_SECRET_ACCESS_KEY", hide_env_values = true)]
        secret_access_key: String,
    },
    /// Change a remote's credentials, endpoint, region, or addressing.
    Set {
        name: String,
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        region: Option<String>,
        /// Whether buckets are named in the path (host/bucket/key) rather
        /// than the host (bucket.host/key).
        #[arg(long)]
        path_style: Option<bool>,
        #[arg(long, requires = "secret_access_key")]
        access_key_id: Option<String>,
        #[arg(long, requires = "access_key_id", hide_env_values = true)]
        secret_access_key: Option<String>,
    },
    /// Delete a remote that no bucket's rules name.
    Delete { name: String },
}

/// An endpoint, as `Location` takes it: `https://host[:port]`.
fn endpoint_arg(endpoint: &str) -> anyhow::Result<String> {
    let location = Location {
        endpoint: endpoint.to_owned(),
        region: "us-east-1".to_owned(),
        bucket: "b".to_owned(),
        prefix: String::new(),
        path_style: true,
        access_key_id: String::new(),
        secret_access_key: String::new(),
    }
    .normalized()
    .map_err(|e| crate::classes::bad_input(format!("{e:#}")))?;
    Ok(location.endpoint)
}

/// The buckets whose rules name remote `name`.
async fn naming<C: GenericClient>(client: &C, name: &str) -> anyhow::Result<Vec<String>> {
    let rows = client
        .query_cached(
            "SELECT b.name FROM buckets b
             WHERE b.replication IS NOT NULL
               AND EXISTS (SELECT 1 FROM jsonb_array_elements(b.replication::jsonb -> 'rules') r
                           WHERE r -> 'destination' ->> 'remote' = $1)
             ORDER BY b.name",
            &[&name],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}

/// A remote, as `cairn remote list` and the console show it. Its secret
/// access key isn't shown.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RemoteSummary {
    pub name: String,
    pub endpoint: String,
    pub region: String,
    pub path_style: bool,
    /// `cairn`, `minio` or `rustfs`.
    pub kind: String,
    pub access_key_id: String,
    /// The buckets whose replication rules name it.
    pub buckets: Vec<String>,
}

/// Every remote, by name.
pub async fn list<C: GenericClient>(client: &C) -> anyhow::Result<Vec<RemoteSummary>> {
    let rows = client
        .query_cached(
            "SELECT name, endpoint, region, path_style, kind, access_key_id
             FROM replication_remotes ORDER BY name",
            &[],
        )
        .await?;
    let mut remotes = Vec::new();
    for r in rows {
        let name: String = r.get(0);
        remotes.push(RemoteSummary {
            buckets: naming(client, &name).await?,
            name,
            endpoint: r.get(1),
            region: r.get(2),
            path_style: r.get(3),
            kind: r.get(4),
            access_key_id: r.get(5),
        });
    }
    Ok(remotes)
}

/// A remote to add, as `cairn remote add` takes it.
#[derive(Debug)]
pub struct NewRemote {
    pub name: String,
    pub endpoint: String,
    pub region: String,
    pub path_style: bool,
    pub kind: Kind,
    pub access_key_id: String,
    pub secret_access_key: String,
}

/// Adds a remote. Returns its endpoint, as it's kept.
pub async fn add<C: GenericClient>(client: &C, new: NewRemote) -> anyhow::Result<String> {
    use crate::classes::bad_input;
    let name = &new.name;
    if !crate::tiers::valid_name(name) {
        return Err(bad_input(
            "a remote's name is up to 32 lowercase letters, digits, - and _, starting with a letter or digit",
        ));
    }
    if new.region.is_empty() {
        return Err(bad_input("a region is needed"));
    }
    let endpoint = endpoint_arg(&new.endpoint)?;
    let inserted = client
        .execute_cached(
            "INSERT INTO replication_remotes (name, endpoint, region, path_style, access_key_id,
                                              secret_access_key, kind)
             VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
            &[
                name,
                &endpoint,
                &new.region,
                &new.path_style,
                &new.access_key_id,
                &new.secret_access_key,
                &new.kind.name(),
            ],
        )
        .await?;
    if inserted != 1 {
        return Err(
            crate::managed::Refused::Exists(format!("there's a remote {name} already")).into(),
        );
    }
    Ok(endpoint)
}

/// A change to a remote, as `cairn remote set` takes it: what's `None`
/// stays as it is. Its kind can't change: the version IDs it was sent are
/// its kind's.
#[derive(Debug, Default)]
pub struct RemoteChange {
    pub endpoint: Option<String>,
    pub region: Option<String>,
    pub path_style: Option<bool>,
    /// New credentials: an access key ID and its secret.
    pub credentials: Option<(String, String)>,
}

/// Changes remote `name` as `change` says.
pub async fn set<C: GenericClient>(
    client: &C,
    name: &str,
    change: RemoteChange,
) -> anyhow::Result<()> {
    let endpoint = change.endpoint.as_deref().map(endpoint_arg).transpose()?;
    if change.region.as_deref() == Some("") {
        return Err(crate::classes::bad_input("a region is needed"));
    }
    let (access_key_id, secret_access_key) = change.credentials.unzip();
    let updated = client
        .execute_cached(
            "UPDATE replication_remotes SET endpoint = coalesce($2, endpoint),
                    access_key_id = coalesce($3, access_key_id),
                    secret_access_key = coalesce($4, secret_access_key),
                    region = coalesce($5, region),
                    path_style = coalesce($6, path_style)
             WHERE name = $1",
            &[
                &name,
                &endpoint,
                &access_key_id,
                &secret_access_key,
                &change.region,
                &change.path_style,
            ],
        )
        .await?;
    if updated != 1 {
        return Err(crate::managed::Refused::NoSuch(format!("there's no remote {name}")).into());
    }
    Ok(())
}

/// Deletes remote `name`, which no bucket's rules may name.
pub async fn delete<C: GenericClient>(client: &C, name: &str) -> anyhow::Result<()> {
    use crate::managed::Refused;
    let buckets = naming(client, name).await?;
    if !buckets.is_empty() {
        return Err(Refused::Conflict(format!(
            "buckets replicate to remote {name}: {} (change their replication configurations first)",
            buckets.join(", ")
        ))
        .into());
    }
    let deleted = client
        .execute_cached("DELETE FROM replication_remotes WHERE name = $1", &[&name])
        .await?;
    if deleted != 1 {
        return Err(Refused::NoSuch(format!("there's no remote {name}")).into());
    }
    Ok(())
}

/// `cairn remote …`, on a node (see `admin`).
pub async fn run(app: &Arc<App>, args: RemoteArgs, out: &mut Output) -> anyhow::Result<()> {
    let client = app.pool.get().await?;
    match args.command {
        RemoteCommand::List => {
            let remotes = list(&client).await?;
            if remotes.is_empty() {
                outln!(out, "no remotes (cairn remote add)");
            }
            for r in remotes {
                outln!(
                    out,
                    "{}: {} at {}{}, as {}",
                    r.name,
                    r.kind,
                    r.endpoint,
                    if r.path_style { " (path-style)" } else { "" },
                    r.access_key_id
                );
                outln!(
                    out,
                    "  replicated to by: {}",
                    if r.buckets.is_empty() {
                        "no bucket".to_owned()
                    } else {
                        r.buckets.join(", ")
                    }
                );
            }
        }
        RemoteCommand::Add {
            name,
            endpoint,
            region,
            path_style,
            kind,
            access_key_id,
            secret_access_key,
        } => {
            let new = NewRemote {
                name: name.clone(),
                endpoint,
                region,
                path_style,
                kind,
                access_key_id,
                secret_access_key,
            };
            let endpoint = add(&client, new).await?;
            outln!(out, "remote {name}: {} at {endpoint}", kind.name());
            outln!(
                out,
                "name its buckets in replication rules as arn:cairn:replication::{name}:<bucket>"
            );
        }
        RemoteCommand::Set {
            name,
            endpoint,
            region,
            path_style,
            access_key_id,
            secret_access_key,
        } => {
            let change = RemoteChange {
                endpoint,
                region,
                path_style,
                credentials: access_key_id.zip(secret_access_key),
            };
            set(&client, &name, change).await?;
            outln!(out, "remote {name} changed");
        }
        RemoteCommand::Delete { name } => {
            delete(&client, &name).await?;
            outln!(out, "remote {name} deleted");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minio_and_rustfs_are_sent_uuids() {
        let id = crate::s3::versions::new_version_id();
        assert_eq!(Kind::Cairn.version_id(&id), id);
        assert_eq!(Kind::Minio.version_id(&id), uuid_form(&id));
        assert_eq!(Kind::Rustfs.version_id(&id), uuid_form(&id));
        assert_eq!(Kind::Minio.version_id("null"), "null");
    }

    #[test]
    fn replicas_keep_their_sources_headers() {
        let mut read = hyper::HeaderMap::new();
        for (name, value) in [
            ("content-type", "text/plain"),
            ("x-amz-meta-colour", "blue"),
            ("x-amz-object-lock-mode", "GOVERNANCE"),
            ("content-length", "5"),
            ("x-amz-version-id", "x"),
            ("etag", "\"abc\""),
        ] {
            read.insert(name, value.parse().unwrap());
        }
        let mut kept = kept_headers(&read);
        kept.sort();
        let names: Vec<&str> = kept.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "content-type",
                "x-amz-meta-colour",
                "x-amz-object-lock-mode"
            ]
        );
    }
}
