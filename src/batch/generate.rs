//! Manifests that jobs generate (CreateJob's `ManifestGenerator`, its
//! `S3JobManifestGenerator`): a job without a manifest names a source
//! bucket, and the filters its objects must pass, and preparing it first
//! walks the bucket and writes what passes as a manifest, which the job
//! then runs from as from any inventory report's (see `source`).
//!
//! The manifest is a snapshot: the walk writes it as it goes, and the job
//! runs from what it wrote, not from the bucket as it is by then. So a
//! job's count of tasks is what it does, and a copy into the bucket it
//! walks (see `copy`) never copies its own copies; and its tasks' ordinals,
//! which a copy's record is by, stay the tasks they were.
//!
//! It's written as an inventory report is (`S3InventoryReport_CSV_20211130`,
//! as S3's are): gzipped CSV data files, of each version's bucket, key and
//! version ID, and a `manifest.json` that lists them. Where to:
//!
//! - With `EnableManifestOutput`, to the bucket and prefix its
//!   `ManifestOutputLocation` says, as the job's role (which must be
//!   allowed `s3:PutObject` there), encrypted as it says (or as the
//!   bucket's default encryption does): `<prefix>/job-<id>/manifest.json`,
//!   and its data files under `<prefix>/job-<id>/data/`. They stay when
//!   the job ends, for other jobs to use.
//! - Otherwise, to Cairn's internal bucket (see `internal`), under
//!   `jobs/<id>/`, which no one else can reach. They go once the job ends
//!   (see `forget_generated`).
//!
//! Either way, the role reads none of them itself: Cairn wrote them, and
//! reads them pinned to what it wrote (their ETags and MD5s).
//!
//! What it walks: in a bucket that's versioned (or was), each version
//! that isn't a delete marker, with its version ID; in one that never was,
//! each current object, without one (so that its task is on whatever
//! version is current when it's done, as S3's are without a version ID).
//! In key order, each key's versions newest first.
//!
//! The filters (`JobManifestGeneratorFilter`): when it was made
//! (`CreatedAfter`, `CreatedBefore`: its last-modified time, exclusive),
//! its size (`ObjectSizeGreaterThanBytes`, `ObjectSizeLessThanBytes`), its
//! storage class (`MatchAnyStorageClass`), its replication status
//! (`ObjectReplicationStatuses`: `NONE` if it has none), whether its
//! bucket's replication configuration replicates it
//! (`EligibleForReplication`, as `cairn_replicate_existing` decides it,
//! but for its null version, which isn't), and its key
//! (`KeyNameConstraint`: one of the prefixes, one of the suffixes and one
//! of the substrings it names, of those lists it gives). Not yet
//! `MatchAnyObjectEncryption` (501).
//!
//! The walk takes turns as preparing does (see `mod.rs`), but reads versions,
//! and so takes them off the step's budget as tasks do: each turn reads at
//! least `MIN_READ` versions (so that its data file isn't tiny), at most
//! `MAX_READ`, and writes what passed as a data file of its own, named by
//! its place in the manifest; then saves where it got to
//! (`batch_jobs.generation`). A node that dies before that leaves the
//! turn to be taken again, which writes the same file again. Its last turn
//! writes `manifest.json`, which becomes the job's manifest.
//!
//! Before each turn, the role must still be allowed
//! `s3:PutInventoryConfiguration` on the source bucket (as S3 asks, since
//! its manifests are inventory reports), and the bucket be the expected
//! owner's (`ExpectedBucketOwner`), as the output's must
//! (`ExpectedManifestBucketOwner`).

use std::{io::Write as _, sync::Arc, time::SystemTime};

use deadpool_postgres::Object;
use flate2::{Compression, write::GzEncoder};
use http_body_util::Full;
use hyper::{HeaderMap, Method, Response, StatusCode, body::Bytes, header};
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    Failure, Job, Manifest, authorize,
    control::{bad_request, boolean, child, children, element, not_implemented, text},
    manifest,
    report::{bucket_of_arn, may_put, quoted, refusal},
};
use crate::db::Cached;
use crate::{
    App,
    payload::Payload,
    s3::{
        access::{Access, Origin},
        conditional::Preconditions,
        object_lock::Lock,
        sse::{KmsRequest, ServerSide, Wanted},
        util::{Encoding, MAX_UPLOAD},
    },
    users::Principal,
};

/// The fewest and most versions a turn reads (but its last); in tests, few,
/// so that a walk takes turns, and a key's versions split between them.
#[cfg(not(test))]
const MIN_READ: i64 = 10_000;
#[cfg(not(test))]
const MAX_READ: i64 = 100_000;
#[cfg(test)]
const MIN_READ: i64 = 1;
#[cfg(test)]
const MAX_READ: i64 = 2;
/// The most versions read at a time.
const PAGE: i64 = 1000;
/// The data files' columns, as `manifest.json` names them.
const SCHEMA: &str = "Bucket, Key, VersionId";
/// The replication statuses `ObjectReplicationStatuses` may name.
const STATUSES: &[&str] = &["COMPLETED", "FAILED", "REPLICA", "NONE"];
/// The longest prefix of an output location, as S3 takes them.
const MAX_PREFIX: usize = 512;

/// A job's manifest generator, as CreateJob gave it (JSON).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Generator {
    /// The source bucket, by its ARN as given, and its name.
    pub source_arn: String,
    pub source: String,
    /// The account expected to own it (`ExpectedBucketOwner`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_owner: Option<String>,
    /// `EnableManifestOutput`: whether the manifest is written to `output`.
    pub enable_output: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<Output>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<Filter>,
}

/// Where a generated manifest is written (`S3ManifestOutputLocation`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Output {
    /// The bucket, by its ARN as given, and its name.
    pub bucket_arn: String,
    pub bucket: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<Encryption>,
    pub format: String,
}

/// How a generated manifest's objects are encrypted
/// (`GeneratedManifestEncryption`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Encryption {
    S3,
    /// Under this KMS key: its ID, as `kms::KeyId` has it, and as given.
    Kms {
        key_id: String,
        given: String,
    },
}

/// Which objects of the source bucket a generated manifest has
/// (`JobManifestGeneratorFilter`). Times as given (ISO 8601).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Filter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eligible_for_replication: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_before: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replication_statuses: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_name: Option<KeyName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_greater_than: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_less_than: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub storage_classes: Vec<String>,
}

/// `KeyNameConstraint`: a key must match one of each list it gives.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct KeyName {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suffixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub substrings: Vec<String>,
}

impl KeyName {
    /// Whether `key` matches it.
    pub fn matches(&self, key: &str) -> bool {
        let any = |list: &[String], test: &dyn Fn(&str) -> bool| {
            list.is_empty() || list.iter().any(|s| test(s))
        };
        any(&self.prefixes, &|p| key.starts_with(p))
            && any(&self.suffixes, &|s| key.ends_with(s))
            && any(&self.substrings, &|s| key.contains(s))
    }
}

/// Where generating a job's manifest has got to (JSON).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Generation {
    /// The last version read: its key, and its place among the key's
    /// versions (its last-modified time, as microseconds since the epoch,
    /// and its row ID), which they're read in (newest first).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<(String, i64, i64)>,
    /// The data files written so far.
    #[serde(default)]
    pub files: Vec<File>,
    /// Versions read, and of them, tasks: those that passed the filters.
    #[serde(default)]
    pub read: i64,
    #[serde(default)]
    pub tasks: i64,
}

/// A data file of a generated manifest.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct File {
    pub key: String,
    pub size: u64,
    /// Its MD5 (hex).
    pub md5: String,
}

/// The `<ManifestGenerator>` of CreateJob, or why it isn't one Cairn takes.
pub(super) fn parse(node: roxmltree::Node) -> Result<Generator, Response<Full<Bytes>>> {
    let Some(node) = child(node, "S3JobManifestGenerator") else {
        return Err(bad_request(
            "A manifest generator's S3JobManifestGenerator is required.",
        ));
    };
    let source_arn = text(node, "SourceBucket").unwrap_or("").to_owned();
    let Some(source) = bucket_of_arn(&source_arn).filter(|b| !crate::internal::is_internal(b))
    else {
        return Err(bad_request(&format!("{source_arn} isn't a bucket's ARN.")));
    };
    if crate::tables::is_storage(source) {
        return Err(bad_request(
            "A table's storage can't be a manifest generator's source.",
        ));
    }
    if crate::s3::directory::is_directory(source) {
        return Err(bad_request(
            "A directory bucket can't be a manifest generator's source.",
        ));
    }
    let source = source.to_owned();
    let expected_owner = account(node, "ExpectedBucketOwner")?;
    let Some(enable_output) = boolean(node, "EnableManifestOutput")? else {
        return Err(bad_request(
            "A manifest generator's EnableManifestOutput is required.",
        ));
    };
    let output = match child(node, "ManifestOutputLocation") {
        Some(location) => Some(parse_output(location)?),
        None => None,
    };
    if enable_output && output.is_none() {
        return Err(bad_request(
            "A manifest generator with EnableManifestOutput needs a ManifestOutputLocation.",
        ));
    }
    let filter = match child(node, "Filter") {
        Some(filter) => Some(parse_filter(filter)?),
        None => None,
    };
    Ok(Generator {
        source_arn,
        source,
        expected_owner,
        enable_output,
        output,
        filter,
    })
}

/// An account ID (12 digits), if `node` has `name`.
fn account(node: roxmltree::Node, name: &str) -> Result<Option<String>, Response<Full<Bytes>>> {
    match text(node, name) {
        None => Ok(None),
        Some(id) if id.len() == 12 && id.bytes().all(|b| b.is_ascii_digit()) => {
            Ok(Some(id.to_owned()))
        }
        Some(_) => Err(bad_request(&format!("{name} must be an account ID."))),
    }
}

fn parse_output(node: roxmltree::Node) -> Result<Output, Response<Full<Bytes>>> {
    let bucket_arn = text(node, "Bucket").unwrap_or("").to_owned();
    let Some(bucket) = bucket_of_arn(&bucket_arn).filter(|b| !crate::internal::is_internal(b))
    else {
        return Err(bad_request(&format!("{bucket_arn} isn't a bucket's ARN.")));
    };
    if crate::tables::is_storage(bucket) {
        return Err(bad_request(
            "A generated manifest can't be written to a table's storage.",
        ));
    }
    if crate::s3::directory::is_directory(bucket) {
        return Err(bad_request(
            "A generated manifest can't be written to a directory bucket.",
        ));
    }
    let bucket = bucket.to_owned();
    let format = text(node, "ManifestFormat").unwrap_or("").to_owned();
    if format != manifest::GENERATED_INVENTORY {
        return Err(bad_request(&format!(
            "A generated manifest's ManifestFormat must be {}.",
            manifest::GENERATED_INVENTORY
        )));
    }
    let prefix = text(node, "ManifestPrefix").map(str::to_owned);
    if prefix
        .as_ref()
        .is_some_and(|p| p.is_empty() || p.chars().count() > MAX_PREFIX)
    {
        return Err(bad_request("A ManifestPrefix is 1 to 512 characters."));
    }
    let encryption = match child(node, "ManifestEncryption") {
        None => None,
        Some(encryption) => match (child(encryption, "SSE-S3"), child(encryption, "SSE-KMS")) {
            (Some(_), None) => Some(Encryption::S3),
            (None, Some(kms)) => {
                let given = text(kms, "KeyId").unwrap_or("").to_owned();
                let id = given.strip_prefix("arn:aws:kms:").unwrap_or(&given);
                let Some(key_id) = crate::kms::KeyId::parse(id) else {
                    return Err(bad_request(&format!("The KMS key ID {given} isn't valid.")));
                };
                Some(Encryption::Kms {
                    key_id: key_id.as_string(),
                    given,
                })
            }
            _ => {
                return Err(bad_request(
                    "A ManifestEncryption is either SSE-S3 or SSE-KMS.",
                ));
            }
        },
    };
    let expected_owner = account(node, "ExpectedManifestBucketOwner")?;
    Ok(Output {
        bucket_arn,
        bucket,
        expected_owner,
        prefix,
        encryption,
        format,
    })
}

/// The text of each element of the list `name` of `node`, if it has it.
fn list(node: roxmltree::Node, name: &str) -> Vec<String> {
    child(node, name).map_or_else(Vec::new, |list| {
        children(list)
            .map(|m| m.text().unwrap_or("").to_owned())
            .collect()
    })
}

/// A size in bytes, if `node` has `name`.
fn size(node: roxmltree::Node, name: &str) -> Result<Option<i64>, Response<Full<Bytes>>> {
    match text(node, name).map(|t| t.parse::<i64>()) {
        None => Ok(None),
        Some(Ok(size)) if size >= 0 => Ok(Some(size)),
        Some(_) => Err(bad_request(&format!("{name} must be a number of bytes."))),
    }
}

/// A time (ISO 8601), as given, if `node` has `name`.
fn time(node: roxmltree::Node, name: &str) -> Result<Option<String>, Response<Full<Bytes>>> {
    match text(node, name) {
        None => Ok(None),
        Some(t) if crate::s3::object_lock::parse_date(t).is_some() => Ok(Some(t.to_owned())),
        Some(_) => Err(bad_request(&format!("{name} isn't a time."))),
    }
}

fn parse_filter(node: roxmltree::Node) -> Result<Filter, Response<Full<Bytes>>> {
    if child(node, "MatchAnyObjectEncryption").is_some() {
        return Err(not_implemented(
            "A manifest generator's MatchAnyObjectEncryption",
        ));
    }
    let replication_statuses = list(node, "ObjectReplicationStatuses");
    if let Some(status) = replication_statuses
        .iter()
        .find(|s| !STATUSES.contains(&s.as_str()))
    {
        return Err(bad_request(&format!(
            "{status} isn't a replication status (COMPLETED, FAILED, REPLICA or NONE)."
        )));
    }
    let storage_classes = list(node, "MatchAnyStorageClass");
    if storage_classes.iter().any(String::is_empty) {
        return Err(bad_request("A storage class can't be empty."));
    }
    let key_name = child(node, "KeyNameConstraint").map(|constraint| KeyName {
        prefixes: list(constraint, "MatchAnyPrefix"),
        suffixes: list(constraint, "MatchAnySuffix"),
        substrings: list(constraint, "MatchAnySubstring"),
    });
    Ok(Filter {
        eligible_for_replication: boolean(node, "EligibleForReplication")?,
        created_after: time(node, "CreatedAfter")?,
        created_before: time(node, "CreatedBefore")?,
        replication_statuses,
        key_name,
        size_greater_than: size(node, "ObjectSizeGreaterThanBytes")?,
        size_less_than: size(node, "ObjectSizeLessThanBytes")?,
        storage_classes,
    })
}

/// A list of `<member>`s, as `name`.
fn members_xml(name: &str, items: &[String]) -> String {
    if items.is_empty() {
        return String::new();
    }
    let members: String = items.iter().map(|i| element("member", i)).collect();
    format!("<{name}>{members}</{name}>")
}

impl Generator {
    /// Its `<ManifestGenerator>`, as DescribeJob answers it.
    pub(super) fn xml(&self) -> String {
        let mut out = String::from("<ManifestGenerator><S3JobManifestGenerator>");
        if let Some(owner) = &self.expected_owner {
            out.push_str(&element("ExpectedBucketOwner", owner));
        }
        out.push_str(&element("SourceBucket", &self.source_arn));
        if let Some(output) = &self.output {
            out.push_str("<ManifestOutputLocation>");
            if let Some(owner) = &output.expected_owner {
                out.push_str(&element("ExpectedManifestBucketOwner", owner));
            }
            out.push_str(&element("Bucket", &output.bucket_arn));
            if let Some(prefix) = &output.prefix {
                out.push_str(&element("ManifestPrefix", prefix));
            }
            match &output.encryption {
                Some(Encryption::S3) => {
                    out.push_str("<ManifestEncryption><SSE-S3/></ManifestEncryption>")
                }
                Some(Encryption::Kms { given, .. }) => out.push_str(&format!(
                    "<ManifestEncryption><SSE-KMS>{}</SSE-KMS></ManifestEncryption>",
                    element("KeyId", given)
                )),
                None => {}
            }
            out.push_str(&element("ManifestFormat", &output.format));
            out.push_str("</ManifestOutputLocation>");
        }
        if let Some(filter) = &self.filter {
            out.push_str("<Filter>");
            if let Some(eligible) = filter.eligible_for_replication {
                out.push_str(&format!(
                    "<EligibleForReplication>{eligible}</EligibleForReplication>"
                ));
            }
            if let Some(after) = &filter.created_after {
                out.push_str(&element("CreatedAfter", after));
            }
            if let Some(before) = &filter.created_before {
                out.push_str(&element("CreatedBefore", before));
            }
            out.push_str(&members_xml(
                "ObjectReplicationStatuses",
                &filter.replication_statuses,
            ));
            if let Some(key_name) = &filter.key_name {
                out.push_str("<KeyNameConstraint>");
                out.push_str(&members_xml("MatchAnyPrefix", &key_name.prefixes));
                out.push_str(&members_xml("MatchAnySuffix", &key_name.suffixes));
                out.push_str(&members_xml("MatchAnySubstring", &key_name.substrings));
                out.push_str("</KeyNameConstraint>");
            }
            if let Some(size) = filter.size_greater_than {
                out.push_str(&format!(
                    "<ObjectSizeGreaterThanBytes>{size}</ObjectSizeGreaterThanBytes>"
                ));
            }
            if let Some(size) = filter.size_less_than {
                out.push_str(&format!(
                    "<ObjectSizeLessThanBytes>{size}</ObjectSizeLessThanBytes>"
                ));
            }
            out.push_str(&members_xml(
                "MatchAnyStorageClass",
                &filter.storage_classes,
            ));
            out.push_str("</Filter>");
        }
        out.push_str(&format!(
            "<EnableManifestOutput>{}</EnableManifestOutput>",
            self.enable_output
        ));
        out.push_str("</S3JobManifestGenerator></ManifestGenerator>");
        out
    }

    /// What a job generating its manifest has as its manifest until it's
    /// generated: none (see `manifest::TO_BE_GENERATED`).
    pub(super) fn placeholder(&self) -> Manifest {
        Manifest {
            format: manifest::TO_BE_GENERATED.to_owned(),
            fields: Vec::new(),
            arn: String::new(),
            bucket: self.source.clone(),
            key: String::new(),
            version_id: None,
            etag: String::new(),
            generated: false,
        }
    }

    /// Where its manifest is written, if it's written out.
    fn written_out(&self) -> Option<&Output> {
        self.output.as_ref().filter(|_| self.enable_output)
    }
}

/// A job's `<GeneratedManifestDescriptor>`, once its manifest is written
/// out (one in the internal bucket is no one's to see).
pub(super) fn descriptor_xml(generator: &Generator, manifest: &Manifest) -> String {
    if !manifest.generated || generator.written_out().is_none() {
        return String::new();
    }
    let mut out = String::from("<GeneratedManifestDescriptor>");
    out.push_str(&element("Format", &manifest.format));
    out.push_str("<Location>");
    out.push_str(&element("ObjectArn", &manifest.arn));
    if let Some(version_id) = &manifest.version_id {
        out.push_str(&element("ObjectVersionId", version_id));
    }
    out.push_str(&element("ETag", &manifest.etag));
    out.push_str("</Location></GeneratedManifestDescriptor>");
    out
}

/// Where a job's generated manifest goes.
struct Destination<'a> {
    bucket: &'a str,
    /// What its keys start with: `jobs/<id>/`, or `<prefix>/job-<id>/`.
    root: String,
    /// Its output location, if it's written out (as the role); else it's
    /// the internal bucket.
    output: Option<&'a Output>,
}

impl<'a> Destination<'a> {
    fn of(generator: &'a Generator, id: Uuid) -> Destination<'a> {
        match generator.written_out() {
            Some(output) => {
                let prefix = output
                    .prefix
                    .as_deref()
                    .map(|p| p.trim_end_matches('/'))
                    .filter(|p| !p.is_empty());
                let root = match prefix {
                    Some(prefix) => format!("{prefix}/job-{id}/"),
                    None => format!("job-{id}/"),
                };
                Destination {
                    bucket: &output.bucket,
                    root,
                    output: Some(output),
                }
            }
            None => Destination {
                bucket: crate::internal::BUCKET,
                root: internal_root(id),
                output: None,
            },
        }
    }

    fn manifest_key(&self) -> String {
        format!("{}manifest.json", self.root)
    }

    /// Whether the job's role session may write it there (its bucket the
    /// expected owner's), if it's written out.
    async fn check(
        &self,
        app: &App,
        client: &Object,
        principal: &Principal,
    ) -> anyhow::Result<Result<(), Failure>> {
        let Some(output) = self.output else {
            return Ok(Ok(()));
        };
        let unwritable = |why: String| {
            Failure::new(
                "ManifestUnwritable",
                format!("The generated manifest can't be written: {why}."),
            )
        };
        let owner: Option<String> = client
            .query_opt_cached(
                "SELECT account_id FROM buckets WHERE name = $1",
                &[&self.bucket],
            )
            .await?
            .map(|row| row.get(0));
        let Some(owner) = owner else {
            return Ok(Err(unwritable(format!(
                "its bucket {} doesn't exist",
                self.bucket
            ))));
        };
        if output
            .expected_owner
            .as_ref()
            .is_some_and(|expected| *expected != owner)
        {
            return Ok(Err(unwritable(format!(
                "its bucket {} isn't the expected owner's",
                self.bucket
            ))));
        }
        Ok(may_put(app, principal, self.bucket, &self.manifest_key())
            .await?
            .map_err(|why| unwritable(why.to_string())))
    }

    /// Writes `body` to `key` (as the role session `principal`, if it's
    /// written out): its version ID and ETag.
    async fn put(
        &self,
        app: &Arc<App>,
        principal: &Principal,
        key: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> anyhow::Result<Result<(Option<String>, String), Failure>> {
        let unwritable = |why: String| {
            Failure::new(
                "ManifestUnwritable",
                format!("Writing the generated manifest's {key} failed: {why}."),
            )
        };
        let (server, role) = match self.output {
            None => (None, None),
            Some(output) => {
                if let Err(why) = may_put(app, principal, self.bucket, key).await? {
                    return Ok(Err(unwritable(why.to_string())));
                }
                let server = match &output.encryption {
                    Some(Encryption::S3) => Some(ServerSide::S3),
                    Some(Encryption::Kms { key_id, .. }) => {
                        let key_id = crate::kms::KeyId::parse(key_id).ok_or_else(|| {
                            anyhow::anyhow!("the stored KMS key ID {key_id:?} isn't one")
                        })?;
                        Some(ServerSide::Kms(KmsRequest {
                            key_id,
                            context: None,
                        }))
                    }
                    None => match crate::s3::buckets::encryption::default_request(app, self.bucket)
                        .await?
                    {
                        Ok(server) => server,
                        Err(refused) => return Ok(Err(unwritable(refusal(refused).await))),
                    },
                };
                (server, Some(principal.id))
            }
        };
        let payload = Payload::unchecked()
            .at_most(MAX_UPLOAD)
            .map_err(|_| anyhow::anyhow!("an unchecked payload has no length"))?;
        let response = crate::s3::objects::put::put_object(
            app,
            self.bucket,
            key,
            content_type,
            "",
            "",
            Full::new(Bytes::from(body)),
            payload,
            &Preconditions::default(),
            Wanted::new(None, server.as_ref()),
            role,
            Lock::default(),
            crate::classes::STANDARD,
        )
        .await?;
        if response.status() == StatusCode::OK {
            let header = |name: &str| {
                response
                    .headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned)
            };
            let etag = header(header::ETAG.as_str())
                .unwrap_or_default()
                .trim_matches('"')
                .to_owned();
            return Ok(Ok((header("x-amz-version-id"), etag)));
        }
        if response.status().is_server_error() || self.output.is_none() {
            anyhow::bail!(
                "writing {key} to bucket {}: {}",
                self.bucket,
                refusal(response).await
            );
        }
        Ok(Err(unwritable(refusal(response).await)))
    }
}

/// What the keys of job `id`'s manifest in the internal bucket start with.
fn internal_root(id: Uuid) -> String {
    format!("jobs/{id}/")
}

/// What a step of generating a manifest did.
pub(super) struct Stepped {
    /// Tasks found (versions that passed the filters).
    pub tasks: i64,
    /// The job's status after it.
    pub status: String,
}

/// What a version of the source bucket is to the walk.
struct Version {
    key: String,
    version_id: String,
    modified: i64,
    id: i64,
    size: i64,
    storage_class: String,
    replication_status: Option<String>,
    eligible: bool,
}

/// Whether the source bucket is versioned (or was), as the walk takes it.
async fn versioned(
    client: &Object,
    bucket: &str,
) -> anyhow::Result<Option<(bool, String, Option<String>)>> {
    let row = client
        .query_opt_cached("SELECT versioning <> 'unversioned', account_id, replication FROM buckets WHERE name = $1", &[&bucket])
        .await?;
    Ok(row.map(|row| (row.get(0), row.get(1), row.get(2))))
}

/// The columns a page of versions has (see `Version`), with whether
/// eligibility is wanted, and the replication configuration it's by, the
/// parameters `$<wanted>` and `$<config>`.
fn columns(wanted: usize, config: usize) -> String {
    format!(
        "key, version_id, (extract(epoch FROM last_modified) * 1000000)::bigint, id, size, storage_class,
         replication_status,
         ${wanted}::boolean AND version_id <> 'null' AND EXISTS (
             SELECT 1 FROM pg_temp.cairn_replication_targets(${config}::text::jsonb, key, is_delete_marker, tags,
                 CASE WHEN sse_c_key IS NOT NULL THEN 'customer'
                      WHEN sse_kms_key_id IS NOT NULL AND NOT coalesce(sse_s3, false) THEN 'kms'
                      ELSE 'plain' END))"
    )
}

/// The next page of up to `limit` of the bucket's versions (`all`; else
/// its current objects), but delete markers, after `after` (its key, and
/// the place of its last version read among the key's), with whether
/// they're eligible for replication by the configuration `eligibility`,
/// if that's wanted.
async fn page(
    client: &Object,
    bucket: &str,
    all: bool,
    after: &Option<(String, i64, i64)>,
    limit: i64,
    eligibility: Option<&str>,
) -> anyhow::Result<Vec<Version>> {
    let wanted = eligibility.is_some();
    let config = eligibility.unwrap_or("{}");
    let mut rows = Vec::new();
    // The rest of the key whose versions the last page ended within.
    if let (true, Some((key, modified, id))) = (all, after) {
        rows = client
            .query_cached(
                &format!(
                    "SELECT {} FROM objects
                     WHERE bucket = $1 AND key = $2
                       AND (last_modified, id) < ('epoch'::timestamptz + $3::bigint * interval '1 microsecond', $4)
                       AND NOT is_delete_marker
                     ORDER BY last_modified DESC, id DESC LIMIT $7",
                    columns(5, 6)
                ),
                &[&bucket, key, modified, id, &wanted, &config, &limit],
            )
            .await?;
    }
    let limit = limit - rows.len() as i64;
    if limit > 0 {
        let after_key = after.as_ref().map_or("", |(key, _, _)| key.as_str());
        let current = if all { "" } else { "AND is_latest" };
        let order = if all {
            "key, last_modified DESC, id DESC"
        } else {
            "key"
        };
        rows.extend(
            client
                .query_cached(
                    &format!(
                        "SELECT {} FROM objects
                         WHERE bucket = $1 AND key > $2 AND NOT is_delete_marker {current}
                         ORDER BY {order} LIMIT $5",
                        columns(3, 4)
                    ),
                    &[&bucket, &after_key, &wanted, &config, &limit],
                )
                .await?,
        );
    }
    Ok(rows
        .iter()
        .map(|row| Version {
            key: row.get(0),
            version_id: row.get(1),
            modified: row.get(2),
            id: row.get(3),
            size: row.get(4),
            storage_class: row.get(5),
            replication_status: row.get(6),
            eligible: row.get(7),
        })
        .collect())
}

/// Whether `version` passes `filter` (`after`, `before`: its times, parsed,
/// as microseconds since the epoch).
fn passes(filter: &Filter, after: Option<i64>, before: Option<i64>, version: &Version) -> bool {
    after.is_none_or(|after| version.modified > after)
        && before.is_none_or(|before| version.modified < before)
        && filter
            .size_greater_than
            .is_none_or(|size| version.size > size)
        && filter.size_less_than.is_none_or(|size| version.size < size)
        && (filter.storage_classes.is_empty()
            || filter.storage_classes.contains(&version.storage_class))
        && (filter.replication_statuses.is_empty()
            || filter
                .replication_statuses
                .iter()
                .any(|s| s == version.replication_status.as_deref().unwrap_or("NONE")))
        && filter
            .eligible_for_replication
            .is_none_or(|eligible| version.eligible == eligible)
        && filter
            .key_name
            .as_ref()
            .is_none_or(|key_name| key_name.matches(&version.key))
}

/// A time (ISO 8601) as microseconds since the epoch.
fn micros(text: &Option<String>) -> Option<i64> {
    let time = crate::s3::object_lock::parse_date(text.as_deref()?)?;
    Some(
        time.duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_micros() as i64),
    )
}

/// A task's line of a data file: its bucket, its key (URL-encoded, as the
/// manifest reader decodes them), and its version ID (if it's of one).
fn csv_line(bucket: &str, key: &str, version_id: Option<&str>) -> String {
    let key = Encoding::Url.xml(key);
    format!(
        "{},{},{}\n",
        quoted(bucket),
        quoted(&key),
        quoted(version_id.unwrap_or(""))
    )
}

/// Takes generating `job`'s manifest a turn further: walks on through its
/// source bucket, reading as many versions as `budget` allows (at least
/// `MIN_READ`, at most `MAX_READ`, and takes them off it), writes the ones
/// that pass as a data file, and saves where it got to; at the end of the
/// bucket, writes its `manifest.json`, which becomes the job's manifest,
/// to be prepared. As the job's role session `principal`. Why the job
/// fails, if it does.
pub(super) async fn step(
    app: &Arc<App>,
    client: &Object,
    job: &Job,
    generator: &Generator,
    principal: &Principal,
    now: SystemTime,
    budget: &mut i64,
) -> anyhow::Result<Result<Stepped, Failure>> {
    let source = &generator.source;
    let Some((all, owner, replication)) = versioned(client, source).await? else {
        return Ok(Err(Failure::new(
            "SourceBucketUnreadable",
            format!("The source bucket {source} doesn't exist."),
        )));
    };
    if generator
        .expected_owner
        .as_ref()
        .is_some_and(|expected| *expected != owner)
    {
        return Ok(Err(Failure::new(
            "SourceBucketUnreadable",
            format!("The source bucket {source} isn't the expected owner's."),
        )));
    }
    // As S3 asks of the role, whose manifests are inventory reports.
    let origin = Origin {
        peer: None,
        trusted_proxies: &[],
        signed: None,
        form: false,
    };
    let mut access = Access::new(
        Some(principal),
        &principal.account,
        &Method::PUT,
        &HeaderMap::new(),
        "",
        &origin,
    )?;
    let query = "inventory&id=batch-operations";
    if let Err(why) = authorize(
        app,
        &mut access,
        &principal.arn(),
        &Method::PUT,
        source,
        "",
        query,
        &HeaderMap::new(),
    )
    .await?
    {
        return Ok(Err(Failure::new(
            "SourceBucketUnreadable",
            format!("The source bucket {source} can't be listed: {why}."),
        )));
    }
    let destination = Destination::of(generator, job.id);
    if let Err(failure) = destination.check(app, client, principal).await? {
        return Ok(Err(failure));
    }
    let filter = generator.filter.clone().unwrap_or_default();
    let (after_time, before_time) = (
        micros(&filter.created_after),
        micros(&filter.created_before),
    );
    // Its replication configuration, if eligibility's asked: none, and
    // nothing is eligible.
    let eligibility = match filter.eligible_for_replication {
        Some(_) => Some(replication.as_deref().unwrap_or("{\"rules\":[]}")),
        None => None,
    };

    let mut generation = job.generation.clone().unwrap_or_default();
    let limit = (*budget).clamp(MIN_READ, MAX_READ);
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    let (mut read, mut tasks, mut end) = (0, 0, false);
    while read < limit {
        let versions = page(
            client,
            source,
            all,
            &generation.after,
            PAGE.min(limit - read),
            eligibility,
        )
        .await?;
        if versions.is_empty() {
            end = true;
            break;
        }
        read += versions.len() as i64;
        for version in &versions {
            if passes(&filter, after_time, before_time, version) {
                let version_id = all.then_some(version.version_id.as_str());
                encoder.write_all(csv_line(source, &version.key, version_id).as_bytes())?;
                tasks += 1;
            }
        }
        let last = versions.last().expect("not empty");
        generation.after = Some((last.key.clone(), last.modified, last.id));
    }
    *budget -= read;
    generation.read += read;
    if tasks > 0 {
        let body = encoder.finish()?;
        let md5: String = Md5::digest(&body)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let key = format!("{}data/{}.csv.gz", destination.root, generation.files.len());
        let size = body.len() as u64;
        if let Err(failure) = destination
            .put(app, principal, &key, "application/x-gzip", body)
            .await?
        {
            return Ok(Err(failure));
        }
        generation.files.push(File { key, size, md5 });
        generation.tasks += tasks;
    }
    if !end {
        let row = client
            .query_opt_cached(
                "UPDATE batch_jobs SET status = 'Preparing', generation = $2, waiting_since = $3
                 WHERE id = $1 AND status IN ('New', 'Preparing') RETURNING status",
                &[&job.id, &serde_json::to_string(&generation)?, &now],
            )
            .await?;
        let status = row.map_or_else(|| "Cancelled".to_owned(), |row| row.get(0));
        return Ok(Ok(Stepped { tasks, status }));
    }
    // Its manifest, of its data files.
    let manifest_key = destination.manifest_key();
    let files: Vec<serde_json::Value> = generation
        .files
        .iter()
        .map(|f| serde_json::json!({ "key": f.key, "size": f.size, "MD5checksum": f.md5 }))
        .collect();
    let created = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let body = serde_json::json!({
        "sourceBucket": source,
        "destinationBucket": format!("arn:aws:s3:::{}", destination.bucket),
        "version": "2021-11-30",
        "creationTimestamp": created.to_string(),
        "fileFormat": "CSV",
        "fileSchema": SCHEMA,
        "files": files,
    });
    let (version_id, etag) = match destination
        .put(
            app,
            principal,
            &manifest_key,
            "application/json",
            serde_json::to_vec_pretty(&body)?,
        )
        .await?
    {
        Ok(written) => written,
        Err(failure) => return Ok(Err(failure)),
    };
    let manifest = Manifest {
        format: manifest::GENERATED_INVENTORY.to_owned(),
        fields: Vec::new(),
        arn: format!("arn:aws:s3:::{}/{manifest_key}", destination.bucket),
        bucket: destination.bucket.to_owned(),
        key: manifest_key,
        version_id,
        etag,
        generated: true,
    };
    let row = client
        .query_opt_cached(
            "UPDATE batch_jobs SET status = 'Preparing', manifest = $2, generation = $3, waiting_since = $4,
                 prepared = 0, prepared_file = 0
             WHERE id = $1 AND status IN ('New', 'Preparing') RETURNING status",
            &[&job.id, &serde_json::to_string(&manifest)?, &serde_json::to_string(&generation)?, &now],
        )
        .await?;
    let status = row.map_or_else(|| "Cancelled".to_owned(), |row| row.get(0));
    Ok(Ok(Stepped { tasks, status }))
}

/// Deletes the manifests jobs generated into the internal bucket once
/// they're no use: their jobs have ended (or are gone). A few jobs' at a
/// time.
pub(crate) async fn forget_generated(app: &Arc<App>, client: &Object) -> anyhow::Result<()> {
    let rows = client
        .query_cached(
            "SELECT key FROM objects o
             WHERE bucket = $1 AND key LIKE 'jobs/%' AND is_latest
               AND NOT EXISTS (
                   SELECT 1 FROM batch_jobs j
                   WHERE j.id::text = split_part(o.key, '/', 2)
                     AND j.status IN ('New', 'Preparing', 'Suspended', 'Ready', 'Active', 'Cancelling'))
             ORDER BY key LIMIT 1000",
            &[&crate::internal::BUCKET],
        )
        .await?;
    for row in rows {
        let key: &str = row.get(0);
        let response = crate::s3::objects::delete::delete_object(
            app,
            crate::internal::BUCKET,
            key,
            None,
            false,
            None,
            crate::mfa::Presented::Absent,
        )
        .await?;
        if !response.status().is_success() {
            anyhow::bail!(
                "deleting {key} from the internal bucket: {}",
                refusal(response).await
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(xml: &str) -> Result<Generator, u16> {
        let doc = roxmltree::Document::parse(xml).unwrap();
        parse(doc.root_element()).map_err(|r| r.status().as_u16())
    }

    const FULL: &str = "<ManifestGenerator><S3JobManifestGenerator>\
        <ExpectedBucketOwner>123456789012</ExpectedBucketOwner>\
        <SourceBucket>arn:aws:s3:::source</SourceBucket>\
        <ManifestOutputLocation><ExpectedManifestBucketOwner>123456789012</ExpectedManifestBucketOwner>\
        <Bucket>arn:aws:s3:::manifests</Bucket><ManifestPrefix>generated</ManifestPrefix>\
        <ManifestEncryption><SSE-S3/></ManifestEncryption>\
        <ManifestFormat>S3InventoryReport_CSV_20211130</ManifestFormat></ManifestOutputLocation>\
        <Filter><EligibleForReplication>true</EligibleForReplication>\
        <CreatedAfter>2026-01-01T00:00:00Z</CreatedAfter><CreatedBefore>2026-12-01T00:00:00Z</CreatedBefore>\
        <ObjectReplicationStatuses><member>NONE</member><member>FAILED</member></ObjectReplicationStatuses>\
        <KeyNameConstraint><MatchAnyPrefix><member>logs/</member></MatchAnyPrefix>\
        <MatchAnySuffix><member>.gz</member></MatchAnySuffix><MatchAnySubstring><member>2026</member></MatchAnySubstring>\
        </KeyNameConstraint><ObjectSizeGreaterThanBytes>100</ObjectSizeGreaterThanBytes>\
        <ObjectSizeLessThanBytes>200</ObjectSizeLessThanBytes>\
        <MatchAnyStorageClass><member>STANDARD</member></MatchAnyStorageClass></Filter>\
        <EnableManifestOutput>true</EnableManifestOutput></S3JobManifestGenerator></ManifestGenerator>";

    #[test]
    fn generators_are_parsed_and_answered_back() {
        let generator = parsed(FULL).unwrap();
        assert_eq!(generator.source, "source");
        assert_eq!(generator.expected_owner.as_deref(), Some("123456789012"));
        let output = generator.output.as_ref().unwrap();
        assert_eq!(
            (output.bucket.as_str(), output.prefix.as_deref()),
            ("manifests", Some("generated"))
        );
        assert_eq!(output.encryption, Some(Encryption::S3));
        let filter = generator.filter.as_ref().unwrap();
        assert_eq!(filter.replication_statuses, ["NONE", "FAILED"]);
        assert_eq!(filter.key_name.as_ref().unwrap().suffixes, [".gz"]);
        assert_eq!(
            (filter.size_greater_than, filter.size_less_than),
            (Some(100), Some(200))
        );
        // DescribeJob answers what was given, which parses to the same.
        assert_eq!(generator.xml(), FULL);
        let json = serde_json::to_string(&generator).unwrap();
        assert_eq!(serde_json::from_str::<Generator>(&json).unwrap(), generator);
    }

    #[test]
    fn what_isnt_taken_is_refused() {
        let minimal = |inner: &str| {
            format!(
                "<ManifestGenerator><S3JobManifestGenerator><SourceBucket>arn:aws:s3:::source</SourceBucket>\
                 {inner}</S3JobManifestGenerator></ManifestGenerator>"
            )
        };
        assert!(
            parsed(&minimal(
                "<EnableManifestOutput>false</EnableManifestOutput>"
            ))
            .is_ok()
        );
        assert_eq!(
            parsed(&minimal("")),
            Err(400),
            "EnableManifestOutput is required"
        );
        assert_eq!(
            parsed(&minimal(
                "<EnableManifestOutput>true</EnableManifestOutput>"
            )),
            Err(400),
            "output needs a location"
        );
        let internal = "<ManifestGenerator><S3JobManifestGenerator><SourceBucket>arn:aws:s3:::cairn_internal</SourceBucket>\
             <EnableManifestOutput>false</EnableManifestOutput></S3JobManifestGenerator></ManifestGenerator>";
        assert_eq!(
            parsed(internal),
            Err(400),
            "the internal bucket is no source"
        );
        let directory = internal.replace("cairn_internal", "d--use1-az1--x-s3");
        assert_eq!(parsed(&directory), Err(400), "nor is a directory bucket");
        let filter = |inner: &str| {
            minimal(&format!(
                "<EnableManifestOutput>false</EnableManifestOutput><Filter>{inner}</Filter>"
            ))
        };
        assert_eq!(
            parsed(&filter(
                "<ObjectReplicationStatuses><member>PENDING</member></ObjectReplicationStatuses>"
            )),
            Err(400)
        );
        assert_eq!(
            parsed(&filter("<CreatedAfter>yesterday</CreatedAfter>")),
            Err(400)
        );
        assert_eq!(
            parsed(&filter(
                "<ObjectSizeLessThanBytes>-1</ObjectSizeLessThanBytes>"
            )),
            Err(400)
        );
        assert_eq!(
            parsed(&filter(
                "<MatchAnyObjectEncryption><member><SSE-S3/></member></MatchAnyObjectEncryption>"
            )),
            Err(501)
        );
        let output = |format: &str| {
            minimal(&format!(
                "<EnableManifestOutput>true</EnableManifestOutput><ManifestOutputLocation>\
                 <Bucket>arn:aws:s3:::m</Bucket><ManifestFormat>{format}</ManifestFormat></ManifestOutputLocation>"
            ))
        };
        assert!(parsed(&output("S3InventoryReport_CSV_20211130")).is_ok());
        assert_eq!(parsed(&output("S3BatchOperations_CSV_20180820")), Err(400));
    }

    #[test]
    fn key_names_match_one_of_each_list() {
        let key_name = KeyName {
            prefixes: vec!["a/".into(), "b/".into()],
            suffixes: vec![".gz".into()],
            substrings: vec![],
        };
        assert!(key_name.matches("a/x.gz"));
        assert!(key_name.matches("b/y.gz"));
        assert!(!key_name.matches("c/x.gz"));
        assert!(!key_name.matches("a/x.txt"));
        assert!(KeyName::default().matches("anything"));
    }

    #[test]
    fn filters_pass_what_they_name() {
        let version = |size, class: &str, status: Option<&str>| Version {
            key: "k".into(),
            version_id: "v".into(),
            modified: 1_000_000,
            id: 1,
            size,
            storage_class: class.into(),
            replication_status: status.map(str::to_owned),
            eligible: false,
        };
        let filter = Filter {
            size_greater_than: Some(10),
            storage_classes: vec!["STANDARD".into()],
            replication_statuses: vec!["NONE".into()],
            ..Filter::default()
        };
        assert!(passes(&filter, None, None, &version(11, "STANDARD", None)));
        assert!(
            !passes(&filter, None, None, &version(10, "STANDARD", None)),
            "greater than, not equal"
        );
        assert!(!passes(&filter, None, None, &version(11, "COLD", None)));
        assert!(!passes(
            &filter,
            None,
            None,
            &version(11, "STANDARD", Some("COMPLETED"))
        ));
        assert!(
            !passes(
                &filter,
                Some(1_000_000),
                None,
                &version(11, "STANDARD", None)
            ),
            "after, not at"
        );
        assert!(passes(
            &filter,
            Some(999_999),
            Some(1_000_001),
            &version(11, "STANDARD", None)
        ));
        let eligible = Filter {
            eligible_for_replication: Some(true),
            ..Filter::default()
        };
        assert!(!passes(
            &eligible,
            None,
            None,
            &version(0, "STANDARD", None)
        ));
    }

    #[test]
    fn lines_are_url_encoded_and_quoted() {
        assert_eq!(csv_line("b", "a b/c,d", Some("v1")), "b,a+b/c%2Cd,v1\n");
        assert_eq!(csv_line("b", "k", None), "b,k,\n");
    }
}
