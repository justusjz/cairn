//! Batch Operations' `S3PutObjectCopy`: each task's object copied to the
//! job's bucket (its `TargetResource`), at its key after the job's
//! `TargetKeyPrefix`, as a CopyObject would copy it, with what the job asks
//! of the copy: its metadata (`MetadataDirective`, `NewObjectMetadata`),
//! tags (`NewObjectTagging`), ACL, storage class, encryption, Object Lock,
//! checksum, and conditions on its source (`ModifiedSinceConstraint`,
//! `UnModifiedSinceConstraint`).
//!
//! A task is the CopyObject request the job's operation and the task's
//! object make (`Copy::headers`, and the task's `x-amz-copy-source`):
//! authorized as the role session's would be, by the same actions and
//! condition keys (`s3:x-amz-copy-source`, `s3:x-amz-metadata-directive`,
//! …), and done by CopyObject itself, as the role's. Its failure is what
//! CopyObject answers.
//!
//! Unlike the job's other operations, a copy done twice isn't the same as
//! a copy done once: it makes another version. So each copy is recorded,
//! by the job and the task's ordinal (how many tasks come before it in
//! the manifest, which the job's counts, saved with its cursor, tell), in
//! the transaction that writes it (`cairn_batch_task` in `catalog.sql`). A
//! page done again, after a node died mid-page, finds the tasks it did
//! done, and does the rest; a write of a task recorded meanwhile is rolled
//! back.
//!
//! Not as in S3: no requester pays, event holds or annotations
//! (`AnnotationDirective` `EXCLUDE`). `NewObjectMetadata`'s `ContentLength`
//! and `ContentMD5` are ignored, as they don't apply to a copy.

use std::{
    borrow::Cow,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use http_body_util::{BodyExt, Full};
use hyper::{
    HeaderMap, Method, Response,
    body::Bytes,
    header::{HeaderName, HeaderValue},
};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    control::{
        bad_request, boolean, child, children, element, not_implemented, tag_members, tags_xml,
        text,
    },
    manifest::Task,
    report::TaskFailure,
};
use crate::db::Cached;
use crate::{
    App, Contended,
    policy::Context,
    s3::{
        access::Access,
        acl,
        checksums::Algorithm,
        conditional::Preconditions,
        metadata,
        object_lock::{self, Lock, Mode},
        objects::copy::{CopyKeys, copy_object, replaces_metadata},
        sse,
        tags::{self, Tags},
    },
    users::Principal,
};

/// The longest key, in bytes, as S3's.
const MAX_KEY: usize = 1024;

/// The canned ACLs S3 Control takes for a copy (`S3CannedAccessControlList`).
const CANNED: &[&str] = &[
    "private",
    "public-read",
    "public-read-write",
    "aws-exec-read",
    "authenticated-read",
    "bucket-owner-read",
    "bucket-owner-full-control",
];

/// What's escaped in a copy source's bucket and key: all but what S3's
/// SDKs leave as it is, and `/`.
const COPY_SOURCE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~')
    .remove(b'/');

/// A grant of the copy's ACL (`S3Grant`): its grantee, by its kind
/// (`id`, `emailAddress` or `uri`) and identifier, and its permission.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Grant {
    pub kind: String,
    pub identifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub permission: String,
}

/// The metadata a copy asks for (`NewObjectMetadata`), its user-defined
/// metadata by its names without `x-amz-meta-`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct NewMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_disposition: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// `HttpExpiresDate`, as given (ISO 8601).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub user: Vec<(String, String)>,
    /// `SSEAlgorithm`: `AES256` (SSE-S3) or `KMS` (SSE-KMS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sse: Option<String>,
}

/// What S3PutObjectCopy asks for, as it's kept (JSON). Dates are as they
/// were given (ISO 8601).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Copy {
    /// The bucket copies go to, by its ARN (`TargetResource`).
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canned_acl: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<Grant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_directive: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_since: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unmodified_since: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<NewMetadata>,
    /// The copies' tags (`NewObjectTagging`), replacing their sources';
    /// `None`, the sources' are kept.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<(String, String)>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kms_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket_key: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_until: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legal_hold: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
}

/// The bucket of a bucket's ARN (`arn:aws:s3:::bucket`).
fn bucket_of_arn(arn: &str) -> Option<&str> {
    arn.strip_prefix("arn:aws:s3:::")
        .filter(|b| !b.is_empty() && !b.contains('/'))
}

/// An ISO 8601 time (S3 Control's `TimeStamp`).
fn date(text: &str) -> Option<SystemTime> {
    object_lock::parse_date(text)
}

/// A time as HTTP writes it (`Sun, 06 Nov 1994 08:49:37 GMT`), to the
/// second.
fn http_date(time: SystemTime) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let seconds = time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()) as i64;
    let (days, rest) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    // 1970-01-01 was a Thursday.
    let weekday = DAYS[(days + 4).rem_euclid(7) as usize];
    let (hour, minute, second) = (rest / 3600, rest % 3600 / 60, rest % 60);
    format!(
        "{weekday}, {day:02} {} {year} {hour:02}:{minute:02}:{second:02} GMT",
        MONTHS[month as usize - 1]
    )
}

impl Copy {
    /// The bucket copies go to.
    pub fn bucket(&self) -> &str {
        bucket_of_arn(&self.target).unwrap_or("")
    }

    /// The key the copy of `key` goes to.
    fn key(&self, key: &str) -> String {
        format!("{}{key}", self.prefix.as_deref().unwrap_or(""))
    }

    /// The tags it gives its copies, stored form (see `s3::tags`), if it
    /// replaces their sources'.
    fn stored_tags(&self) -> anyhow::Result<Option<String>> {
        let Some(pairs) = &self.tags else {
            return Ok(None);
        };
        match Tags::from_pairs(pairs.clone(), tags::On::Object) {
            Ok(tags) => Ok(Some(tags.stored())),
            Err(_) => anyhow::bail!("a copy job's stored tags aren't an object's"),
        }
    }

    /// The headers of the CopyObject requests it makes, but for their
    /// `x-amz-copy-source`; or why there are none, which CreateJob refuses.
    pub fn headers(&self) -> Result<HeaderMap, String> {
        let mut headers = HeaderMap::new();
        let mut insert = |name: &str, value: &str| -> Result<(), String> {
            let name = HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes())
                .map_err(|_| format!("{name} isn't a header's name"))?;
            // Printable US-ASCII, as S3 stores metadata.
            if !value.bytes().all(|b| (b' '..=b'~').contains(&b)) {
                return Err(format!("{name}'s value must be printable US-ASCII"));
            }
            let value = HeaderValue::from_str(value)
                .map_err(|_| format!("{name}'s value isn't a header's"))?;
            headers.append(name, value);
            Ok(())
        };
        if let Some(directive) = &self.metadata_directive {
            insert("x-amz-metadata-directive", directive)?;
        }
        if let Some(m) = &self.metadata {
            let named = [
                ("cache-control", &m.cache_control),
                ("content-disposition", &m.content_disposition),
                ("content-encoding", &m.content_encoding),
                ("content-language", &m.content_language),
                ("content-type", &m.content_type),
            ];
            for (name, value) in named {
                if let Some(value) = value {
                    insert(name, value)?;
                }
            }
            if let Some(expires) = &m.expires {
                let at = date(expires).ok_or_else(|| "HttpExpiresDate isn't a date".to_owned())?;
                insert("expires", &http_date(at))?;
            }
            for (name, value) in &m.user {
                insert(&format!("x-amz-meta-{name}"), value)?;
            }
        }
        // SSE-S3 or SSE-KMS; a KMS key alone asks for SSE-KMS.
        let algorithm = self.metadata.as_ref().and_then(|m| m.sse.as_deref());
        match (algorithm, &self.kms_key_id) {
            (Some("AES256"), None) => insert(sse::ENCRYPTION, sse::AES256)?,
            (Some("AES256"), Some(_)) => {
                return Err("SSEAwsKmsKeyId is for SSEAlgorithm KMS".to_owned());
            }
            (Some("KMS") | None, Some(key_id)) => {
                insert(sse::ENCRYPTION, sse::AWS_KMS)?;
                insert(sse::KMS_KEY_ID, key_id)?;
            }
            (Some("KMS"), None) => insert(sse::ENCRYPTION, sse::AWS_KMS)?,
            (Some(other), _) => return Err(format!("{other} isn't an SSEAlgorithm")),
            (None, None) => {}
        }
        if let Some(enabled) = self.bucket_key {
            insert(
                sse::BUCKET_KEY_ENABLED,
                if enabled { "true" } else { "false" },
            )?;
        }
        if let Some(pairs) = &self.tags {
            insert(tags::DIRECTIVE, "REPLACE")?;
            let tags = Tags::from_pairs(pairs.clone(), tags::On::Object)
                .map_err(|_| "the tags aren't an object's".to_owned())?;
            let encode = |s: &str| utf8_percent_encode(s, NON_ALPHANUMERIC).to_string();
            let query: Vec<String> = tags
                .iter()
                .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
                .collect();
            insert(tags::HEADER, &query.join("&"))?;
        }
        if let Some(location) = &self.redirect {
            insert("x-amz-website-redirect-location", location)?;
        }
        if let Some(class) = &self.storage_class {
            insert("x-amz-storage-class", class)?;
        }
        if let Some(mode) = &self.lock_mode {
            insert(object_lock::MODE, mode)?;
        }
        if let Some(until) = &self.lock_until {
            insert(object_lock::RETAIN_UNTIL, until)?;
        }
        if let Some(hold) = &self.legal_hold {
            insert(object_lock::LEGAL_HOLD, hold)?;
        }
        if let Some(algorithm) = &self.checksum {
            insert(crate::s3::checksums::ALGORITHM, algorithm)?;
        }
        if let Some(canned) = &self.canned_acl {
            insert("x-amz-acl", canned)?;
        }
        for permission in ["FULL_CONTROL", "READ", "WRITE", "READ_ACP", "WRITE_ACP"] {
            let grantees: Vec<String> = self
                .grants
                .iter()
                .filter(|g| g.permission == permission)
                .map(|g| format!("{}=\"{}\"", g.kind, g.identifier))
                .collect();
            if !grantees.is_empty() {
                let name = format!(
                    "x-amz-grant-{}",
                    permission.to_ascii_lowercase().replace('_', "-")
                );
                insert(&name, &grantees.join(", "))?;
            }
        }
        let constraints = [
            ("x-amz-copy-source-if-modified-since", &self.modified_since),
            (
                "x-amz-copy-source-if-unmodified-since",
                &self.unmodified_since,
            ),
        ];
        for (name, since) in constraints {
            if let Some(since) = since {
                let at = date(since).ok_or_else(|| format!("{since} isn't a date"))?;
                insert(name, &http_date(at))?;
            }
        }
        Ok(headers)
    }

    /// Its `<S3PutObjectCopy>`, as DescribeJob answers it.
    pub fn xml(&self) -> String {
        let mut out = String::from("<S3PutObjectCopy>");
        out.push_str(&element("TargetResource", &self.target));
        let optional = |out: &mut String, name: &str, value: &Option<String>| {
            if let Some(value) = value {
                out.push_str(&element(name, value));
            }
        };
        optional(&mut out, "CannedAccessControlList", &self.canned_acl);
        if !self.grants.is_empty() {
            out.push_str("<AccessControlGrants>");
            for grant in &self.grants {
                out.push_str("<member><Grantee>");
                out.push_str(&element("TypeIdentifier", &grant.kind));
                out.push_str(&element("Identifier", &grant.identifier));
                if let Some(name) = &grant.display_name {
                    out.push_str(&element("DisplayName", name));
                }
                out.push_str("</Grantee>");
                out.push_str(&element("Permission", &grant.permission));
                out.push_str("</member>");
            }
            out.push_str("</AccessControlGrants>");
        }
        optional(&mut out, "MetadataDirective", &self.metadata_directive);
        optional(&mut out, "ModifiedSinceConstraint", &self.modified_since);
        if let Some(m) = &self.metadata {
            out.push_str("<NewObjectMetadata>");
            optional(&mut out, "CacheControl", &m.cache_control);
            optional(&mut out, "ContentDisposition", &m.content_disposition);
            optional(&mut out, "ContentEncoding", &m.content_encoding);
            optional(&mut out, "ContentLanguage", &m.content_language);
            if !m.user.is_empty() {
                out.push_str("<UserMetadata>");
                for (key, value) in &m.user {
                    out.push_str(&format!(
                        "<entry>{}{}</entry>",
                        element("key", key),
                        element("value", value)
                    ));
                }
                out.push_str("</UserMetadata>");
            }
            optional(&mut out, "ContentType", &m.content_type);
            optional(&mut out, "HttpExpiresDate", &m.expires);
            optional(&mut out, "SSEAlgorithm", &m.sse);
            out.push_str("</NewObjectMetadata>");
        }
        if let Some(tags) = &self.tags {
            out.push_str(&tags_xml("NewObjectTagging", tags));
        }
        optional(&mut out, "RedirectLocation", &self.redirect);
        optional(&mut out, "StorageClass", &self.storage_class);
        optional(
            &mut out,
            "UnModifiedSinceConstraint",
            &self.unmodified_since,
        );
        optional(&mut out, "SSEAwsKmsKeyId", &self.kms_key_id);
        optional(&mut out, "TargetKeyPrefix", &self.prefix);
        optional(&mut out, "ObjectLockLegalHoldStatus", &self.legal_hold);
        optional(&mut out, "ObjectLockMode", &self.lock_mode);
        optional(&mut out, "ObjectLockRetainUntilDate", &self.lock_until);
        if let Some(enabled) = self.bucket_key {
            out.push_str(&element(
                "BucketKeyEnabled",
                if enabled { "true" } else { "false" },
            ));
        }
        optional(&mut out, "ChecksumAlgorithm", &self.checksum);
        out.push_str("</S3PutObjectCopy>");
        out
    }

    /// The condition keys of what its copies ask for that aren't headers'
    /// (see `s3::access`): their Object Lock, and the tags they're given.
    pub fn set_context(&self, access: &mut Access) {
        object_lock::set_context(
            &mut access.context,
            self.lock_mode.as_deref(),
            self.lock_until.as_deref(),
            self.legal_hold.as_deref(),
        );
        if let Some(pairs) = &self.tags
            && let Ok(tags) = Tags::from_pairs(pairs.clone(), tags::On::Object)
        {
            crate::s3::abac::request_tags(access, &tags);
        }
    }
}

/// S3PutObjectCopy's operation, as CreateJob gives it, or why it isn't one
/// Cairn takes. What depends on the cluster (that its storage class is
/// one of the cluster's) is CreateJob's to check (`check`).
pub(super) fn parse(operation: roxmltree::Node) -> Result<Copy, Response<Full<Bytes>>> {
    let owned = |node: roxmltree::Node, name: &str| text(node, name).map(str::to_owned);
    for unsupported in ["ObjectLockEventHold", "ObjectLockEventHoldDuration"] {
        if child(operation, unsupported).is_some() {
            return Err(not_implemented("An event hold"));
        }
    }
    if boolean(operation, "RequesterPays")? == Some(true) {
        return Err(not_implemented("Requester pays"));
    }
    match text(operation, "AnnotationDirective") {
        None | Some("COPY") => {}
        Some("EXCLUDE") => return Err(not_implemented("AnnotationDirective EXCLUDE")),
        Some(other) => {
            return Err(bad_request(&format!(
                "{other} isn't an AnnotationDirective."
            )));
        }
    }
    let target = owned(operation, "TargetResource").unwrap_or_default();
    if target.starts_with("arn:aws:s3express:") {
        return Err(not_implemented("Copying into a directory bucket"));
    }
    let Some(bucket) = bucket_of_arn(&target) else {
        return Err(bad_request(
            "A TargetResource, a bucket's ARN, is required.",
        ));
    };
    if crate::s3::directory::is_directory(bucket) {
        return Err(not_implemented("Copying into a directory bucket"));
    }
    if crate::tables::is_storage(bucket) {
        return Err(bad_request("A table's storage can't be a copy's target."));
    }
    let prefix = owned(operation, "TargetKeyPrefix");
    if prefix
        .as_ref()
        .is_some_and(|p| p.is_empty() || p.len() > MAX_KEY)
    {
        return Err(bad_request("A TargetKeyPrefix is 1 to 1024 bytes."));
    }
    let canned_acl = owned(operation, "CannedAccessControlList");
    if let Some(canned) = canned_acl.as_deref().filter(|c| !CANNED.contains(c)) {
        return Err(bad_request(&format!(
            "{canned} isn't a CannedAccessControlList."
        )));
    }
    let mut grants = Vec::new();
    if let Some(list) = child(operation, "AccessControlGrants") {
        for member in children(list) {
            let grantee = child(member, "Grantee");
            let field = |name| {
                grantee
                    .and_then(|g| text(g, name))
                    .filter(|t| !t.is_empty())
                    .map(str::to_owned)
            };
            let (Some(kind), Some(identifier), Some(permission)) = (
                field("TypeIdentifier"),
                field("Identifier"),
                owned(member, "Permission"),
            ) else {
                return Err(bad_request(
                    "A grant has a Grantee (its TypeIdentifier and Identifier) and a Permission.",
                ));
            };
            if !matches!(kind.as_str(), "id" | "emailAddress" | "uri") {
                return Err(bad_request(&format!(
                    "{kind} isn't a grantee's TypeIdentifier."
                )));
            }
            if !matches!(
                permission.as_str(),
                "FULL_CONTROL" | "READ" | "WRITE" | "READ_ACP" | "WRITE_ACP"
            ) {
                return Err(bad_request(&format!("{permission} isn't a Permission.")));
            }
            grants.push(Grant {
                kind,
                identifier,
                display_name: field("DisplayName"),
                permission,
            });
        }
    }
    let metadata_directive = owned(operation, "MetadataDirective");
    if metadata_directive
        .as_deref()
        .is_some_and(|d| d != "COPY" && d != "REPLACE")
    {
        return Err(bad_request("A MetadataDirective is COPY or REPLACE."));
    }
    let dated = |name: &str| -> Result<Option<String>, Response<Full<Bytes>>> {
        match owned(operation, name) {
            Some(value) if date(&value).is_none() => {
                Err(bad_request(&format!("{name} isn't a date.")))
            }
            value => Ok(value),
        }
    };
    let modified_since = dated("ModifiedSinceConstraint")?;
    let unmodified_since = dated("UnModifiedSinceConstraint")?;
    let metadata = match child(operation, "NewObjectMetadata") {
        None => None,
        Some(m) => {
            if boolean(m, "RequesterCharged")? == Some(true) {
                return Err(not_implemented("Requester pays"));
            }
            let mut user = Vec::new();
            if let Some(map) = child(m, "UserMetadata") {
                for entry in children(map) {
                    let Some(key) = text(entry, "key").filter(|k| !k.is_empty()) else {
                        return Err(bad_request("A UserMetadata entry has a key."));
                    };
                    user.push((
                        key.to_ascii_lowercase(),
                        text(entry, "value").unwrap_or("").to_owned(),
                    ));
                }
            }
            let expires = match owned(m, "HttpExpiresDate") {
                Some(value) if date(&value).is_none() => {
                    return Err(bad_request("HttpExpiresDate isn't a date."));
                }
                value => value,
            };
            let sse = owned(m, "SSEAlgorithm");
            if sse.as_deref().is_some_and(|a| a != "AES256" && a != "KMS") {
                return Err(bad_request("An SSEAlgorithm is AES256 or KMS."));
            }
            Some(NewMetadata {
                cache_control: owned(m, "CacheControl"),
                content_disposition: owned(m, "ContentDisposition"),
                content_encoding: owned(m, "ContentEncoding"),
                content_language: owned(m, "ContentLanguage"),
                content_type: owned(m, "ContentType"),
                expires,
                user,
                sse,
            })
        }
    };
    let tags = match child(operation, "NewObjectTagging") {
        None => None,
        Some(set) => {
            let tags = Tags::from_pairs(tag_members(set)?, tags::On::Object)?;
            Some(
                tags.iter()
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect(),
            )
        }
    };
    let (lock_mode, lock_until) = (
        owned(operation, "ObjectLockMode"),
        owned(operation, "ObjectLockRetainUntilDate"),
    );
    match (lock_mode.as_deref(), lock_until.as_deref()) {
        (None, None) => {}
        (Some(mode), Some(until)) => {
            if Mode::parse(mode).is_none() {
                return Err(bad_request(
                    "An ObjectLockMode is GOVERNANCE or COMPLIANCE.",
                ));
            }
            match date(until) {
                None => return Err(bad_request("ObjectLockRetainUntilDate isn't a date.")),
                Some(until) if until <= SystemTime::now() => {
                    return Err(bad_request(object_lock::IN_THE_PAST));
                }
                Some(_) => {}
            }
        }
        _ => {
            return Err(bad_request(
                "An ObjectLockMode needs an ObjectLockRetainUntilDate, and the other way around.",
            ));
        }
    }
    let legal_hold = owned(operation, "ObjectLockLegalHoldStatus");
    if legal_hold
        .as_deref()
        .is_some_and(|h| h != "ON" && h != "OFF")
    {
        return Err(bad_request("An ObjectLockLegalHoldStatus is ON or OFF."));
    }
    let checksum = owned(operation, "ChecksumAlgorithm");
    // S3 Control's names (`S3ChecksumAlgorithm`) are S3's, exactly.
    if let Some(name) = checksum.as_deref()
        && Algorithm::from_name(name).is_none_or(|a| a.name() != name)
    {
        return Err(bad_request(&format!("{name} isn't a ChecksumAlgorithm.")));
    }
    let storage_class = owned(operation, "StorageClass");
    if storage_class.as_deref() == Some("") {
        return Err(bad_request("A StorageClass can't be empty."));
    }
    let copy = Copy {
        target,
        prefix,
        canned_acl,
        grants,
        metadata_directive,
        modified_since,
        unmodified_since,
        metadata,
        tags,
        redirect: owned(operation, "RedirectLocation"),
        storage_class,
        kms_key_id: owned(operation, "SSEAwsKmsKeyId"),
        bucket_key: boolean(operation, "BucketKeyEnabled")?,
        lock_mode,
        lock_until,
        legal_hold,
        checksum,
    };
    // What its copies' requests would ask for, as CopyObject checks it.
    let headers = copy
        .headers()
        .map_err(|why| bad_request(&format!("The copy's {why}.")))?;
    if replaces_metadata(copy.metadata_directive.as_deref())
        && metadata::from_request(&headers).is_err()
    {
        return Err(bad_request("The copy's new metadata is larger than 2 KB."));
    }
    Ok(copy)
}

/// Why CreateJob refuses the copy, as the cluster is: a storage class it
/// hasn't.
pub(super) async fn check(
    app: &App,
    copy: &Copy,
) -> anyhow::Result<Result<(), Response<Full<Bytes>>>> {
    if let Some(class) = &copy.storage_class
        && crate::classes::resolve(app, Some(class)).await?.is_err()
    {
        return Ok(Err(bad_request(&format!(
            "There's no storage class {class}."
        ))));
    }
    Ok(Ok(()))
}

/// What a job's copy tasks share: its operation, and the requests it
/// makes (their headers, but for their sources, and their condition keys).
pub(super) struct Copier<'a> {
    pub job: Uuid,
    pub copy: &'a Copy,
    pub headers: HeaderMap,
    /// The condition keys of its requests, but for their sources'.
    pub context: Context,
    /// The tags it gives its copies, stored form, if it replaces theirs.
    pub tags: Option<String>,
}

impl<'a> Copier<'a> {
    /// The copier of job `job`'s `copy`, as `access` (its role session's,
    /// made of `Copy::headers`) has its condition keys.
    pub fn new(
        job: Uuid,
        copy: &'a Copy,
        headers: HeaderMap,
        access: &mut Access,
    ) -> anyhow::Result<Copier<'a>> {
        copy.set_context(access);
        Ok(Copier {
            job,
            copy,
            headers,
            context: access.context.clone(),
            tags: copy.stored_tags()?,
        })
    }

    /// Copies `task`'s object, as its task of ordinal `ordinal`, as
    /// `access` (the role session `principal`'s, `who`) allows it; why not,
    /// if it didn't. Done already if it's recorded (see the module's doc).
    pub async fn run(
        &self,
        app: &Arc<App>,
        access: &mut Access,
        principal: &Principal,
        who: &str,
        ordinal: i64,
        task: &Task,
    ) -> anyhow::Result<Result<(), TaskFailure>> {
        if done(app, self.job, ordinal).await? {
            return Ok(Ok(()));
        }
        let bucket = self.copy.bucket();
        let key = self.copy.key(&task.key);
        if key.len() > MAX_KEY {
            return Ok(Err(TaskFailure::new(
                400,
                "KeyTooLongError",
                "Your key is too long",
            )));
        }
        // The CopyObject request the task is.
        let mut copy_source = format!(
            "/{}/{}",
            utf8_percent_encode(&task.bucket, COPY_SOURCE),
            utf8_percent_encode(&task.key, COPY_SOURCE)
        );
        if let Some(version_id) = &task.version_id {
            copy_source.push_str(&format!(
                "?versionId={}",
                utf8_percent_encode(version_id, NON_ALPHANUMERIC)
            ));
        }
        let mut headers = self.headers.clone();
        headers.insert("x-amz-copy-source", HeaderValue::from_str(&copy_source)?);
        access.context = self.context.clone();
        access.context.set("s3:x-amz-copy-source", &copy_source);
        if let Some(version_id) = &task.version_id {
            access.context.set("s3:versionid", version_id);
        }
        if let Err(failure) =
            super::authorize(app, access, who, &Method::PUT, bucket, &key, "", &headers).await?
        {
            return Ok(Err(failure));
        }
        // What CopyObject's handler makes of its headers (see `s3`).
        let header = |name| headers.get(name).and_then(|v| v.to_str().ok());
        let lock = match Lock::from_headers(&headers) {
            Ok(lock) => lock,
            Err(refused) => return Ok(Err(failure_of(refused).await)),
        };
        let storage_class =
            match crate::classes::resolve(app, header("x-amz-storage-class")).await? {
                Ok(class) => class,
                Err(name) => return Ok(Err(failure_of(crate::classes::invalid(&name)).await)),
            };
        let sse_s3 = app
            .kms
            .as_ref()
            .is_some_and(|kms| kms.sse_s3_key().is_some());
        let server = match sse::requested(&headers, false, app.kms.is_some(), sse_s3)
            .and_then(|request| sse::for_object(request, bucket, &key))
        {
            Ok(request) => request,
            Err(refused) => return Ok(Err(failure_of(refused).await)),
        };
        let server = match server {
            None => match crate::s3::buckets::encryption::default_request(app, bucket).await? {
                Ok(request) => request,
                Err(refused) => return Ok(Err(failure_of(refused).await)),
            },
            request => request,
        };
        let acl = match access.acls_enabled(bucket) {
            false => acl::check_write(&headers, acl::On::Object).map(|()| None),
            true => acl::for_write(app, bucket, Some(&principal.account), &headers).await?,
        };
        let acl = match acl {
            Ok(acl) => acl,
            Err(refused) => return Ok(Err(failure_of(refused).await)),
        };
        let directive = self.copy.metadata_directive.as_deref();
        let metadata = match metadata::from_request(&headers) {
            Ok(metadata) => metadata,
            Err(refused) if replaces_metadata(directive) => {
                return Ok(Err(failure_of(refused).await));
            }
            Err(_) => String::new(),
        };
        let content_type = header("content-type").unwrap_or(metadata::DEFAULT_CONTENT_TYPE);
        let keys = CopyKeys {
            source: None,
            dest: sse::Wanted::new(None, server.as_ref()),
            role: principal.kms_role(),
            checksum: self.copy.checksum.as_deref().and_then(Algorithm::from_name),
            lock,
            conditions: None,
            restates: self.copy.storage_class.is_some() || self.copy.redirect.is_some(),
            storage_class: Some(&storage_class),
            replica: false,
        };
        let preconditions = Preconditions::from_copy_source_headers(&headers);
        crate::notifications::set_acl(acl);
        crate::notifications::set_batch_task(Some((self.job, ordinal)));
        let copied = copy_object(
            app,
            bucket,
            &key,
            &copy_source,
            directive,
            content_type,
            &metadata,
            self.tags.as_deref(),
            &preconditions,
            keys,
        )
        .await;
        crate::notifications::set_batch_task(None);
        crate::notifications::set_acl(None);
        match copied {
            Ok(response) if response.status().is_success() => Ok(Ok(())),
            Ok(response) => Ok(Err(failure_of(response).await)),
            // Its write was refused, as another did the task meanwhile.
            Err(_) if done(app, self.job, ordinal).await? => Ok(Ok(())),
            Err(e) if e.is::<Contended>() => Ok(Err(super::slow_down())),
            Err(e) => Err(e),
        }
    }
}

/// Whether job `job`'s task of ordinal `ordinal` made its copy.
async fn done(app: &App, job: Uuid, ordinal: i64) -> anyhow::Result<bool> {
    let client = app.pool.get().await?;
    let row = client
        .query_opt_cached(
            "SELECT 1 FROM batch_job_copies WHERE job_id = $1 AND task = $2",
            &[&job, &ordinal],
        )
        .await?;
    Ok(row.is_some())
}

/// The task's failure that a refusal (an S3 error's response) is.
async fn failure_of(response: Response<Full<Bytes>>) -> TaskFailure {
    let status = response.status().as_u16();
    let body = response
        .into_body()
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let body = String::from_utf8_lossy(&body);
    let doc = roxmltree::Document::parse(&body).ok();
    let element = |name: &str| {
        doc.as_ref()
            .and_then(|doc| text(doc.root_element(), name))
            .map(str::to_owned)
    };
    let code = element("Code").unwrap_or_else(|| "InternalError".to_owned());
    let message = element("Message").unwrap_or_default();
    TaskFailure::new(status, Cow::Owned(code), message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(operation: &str) -> Result<Copy, u16> {
        let xml = format!("<Operation>{operation}</Operation>");
        let doc = roxmltree::Document::parse(&xml).unwrap();
        let node = doc.root_element().first_element_child().unwrap();
        parse(node).map_err(|refused| refused.status().as_u16())
    }

    #[test]
    fn http_dates_are_as_http_writes_them() {
        assert_eq!(
            http_date(UNIX_EPOCH + std::time::Duration::from_secs(784_111_777)),
            "Sun, 06 Nov 1994 08:49:37 GMT"
        );
        assert_eq!(http_date(UNIX_EPOCH), "Thu, 01 Jan 1970 00:00:00 GMT");
        for seconds in [951_782_400, 1_709_208_000, 4_102_444_799] {
            let at = UNIX_EPOCH + std::time::Duration::from_secs(seconds);
            assert_eq!(
                crate::s3::conditional::parse_http_date(&http_date(at)),
                Some(seconds as i64)
            );
        }
    }

    #[test]
    fn copies_are_parsed() {
        let copy = parsed(
            "<S3PutObjectCopy><TargetResource>arn:aws:s3:::dest</TargetResource>\
             <TargetKeyPrefix>copies/</TargetKeyPrefix><MetadataDirective>REPLACE</MetadataDirective>\
             <NewObjectMetadata><ContentType>text/plain</ContentType>\
             <UserMetadata><entry><key>Colour</key><value>blue</value></entry></UserMetadata></NewObjectMetadata>\
             <NewObjectTagging><member><Key>a</Key><Value>1</Value></member></NewObjectTagging>\
             <AccessControlGrants><member><Grantee><TypeIdentifier>id</TypeIdentifier><Identifier>abc</Identifier>\
             </Grantee><Permission>READ</Permission></member></AccessControlGrants>\
             <ModifiedSinceConstraint>2026-01-01T00:00:00Z</ModifiedSinceConstraint>\
             <StorageClass>STANDARD</StorageClass><ChecksumAlgorithm>SHA256</ChecksumAlgorithm>\
             </S3PutObjectCopy>",
        )
        .unwrap();
        assert_eq!(copy.bucket(), "dest");
        assert_eq!(copy.key("a/b"), "copies/a/b");
        assert_eq!(copy.tags, Some(vec![("a".to_owned(), "1".to_owned())]));
        let headers = copy.headers().unwrap();
        assert_eq!(headers["x-amz-metadata-directive"], "REPLACE");
        assert_eq!(headers["content-type"], "text/plain");
        assert_eq!(headers["x-amz-meta-colour"], "blue");
        assert_eq!(headers["x-amz-tagging-directive"], "REPLACE");
        assert_eq!(headers["x-amz-tagging"], "a=1");
        assert_eq!(headers["x-amz-grant-read"], "id=\"abc\"");
        assert_eq!(
            headers["x-amz-copy-source-if-modified-since"],
            "Thu, 01 Jan 2026 00:00:00 GMT"
        );
        assert_eq!(headers["x-amz-storage-class"], "STANDARD");
        assert_eq!(headers["x-amz-checksum-algorithm"], "SHA256");
        // What DescribeJob answers is what it was given.
        let xml = format!("<Operation>{}</Operation>", copy.xml());
        let doc = roxmltree::Document::parse(&xml).unwrap();
        assert_eq!(
            parse(doc.root_element().first_element_child().unwrap()).unwrap(),
            copy
        );
        let json = serde_json::to_string(&copy).unwrap();
        assert_eq!(serde_json::from_str::<Copy>(&json).unwrap(), copy);
    }

    #[test]
    fn copies_cairn_cant_make_are_refused() {
        let target = "<TargetResource>arn:aws:s3:::dest</TargetResource>";
        assert_eq!(parsed("<S3PutObjectCopy/>"), Err(400));
        assert_eq!(
            parsed("<S3PutObjectCopy><TargetResource>dest</TargetResource></S3PutObjectCopy>"),
            Err(400)
        );
        let refused = [
            ("<RequesterPays>true</RequesterPays>", 501),
            ("<ObjectLockEventHold>ON</ObjectLockEventHold>", 501),
            ("<AnnotationDirective>EXCLUDE</AnnotationDirective>", 501),
            ("<ChecksumAlgorithm>xxhash3</ChecksumAlgorithm>", 400),
            ("<ChecksumAlgorithm>ROT13</ChecksumAlgorithm>", 400),
            ("<MetadataDirective>KEEP</MetadataDirective>", 400),
            (
                "<CannedAccessControlList>everyone</CannedAccessControlList>",
                400,
            ),
            ("<ObjectLockMode>GOVERNANCE</ObjectLockMode>", 400),
            (
                "<ObjectLockMode>GOVERNANCE</ObjectLockMode><ObjectLockRetainUntilDate>2020-01-01T00:00:00Z</ObjectLockRetainUntilDate>",
                400,
            ),
            (
                "<ModifiedSinceConstraint>yesterday</ModifiedSinceConstraint>",
                400,
            ),
            (
                "<NewObjectMetadata><SSEAlgorithm>AES256</SSEAlgorithm></NewObjectMetadata><SSEAwsKmsKeyId>k</SSEAwsKmsKeyId>",
                400,
            ),
            (
                "<NewObjectMetadata><UserMetadata><entry><key>a</key><value>ü</value></entry></UserMetadata></NewObjectMetadata>",
                400,
            ),
        ];
        for (rest, status) in refused {
            assert_eq!(
                parsed(&format!(
                    "<S3PutObjectCopy>{target}{rest}</S3PutObjectCopy>"
                )),
                Err(status),
                "{rest}"
            );
        }
        let directory = "<S3PutObjectCopy><TargetResource>arn:aws:s3express:us-east-1:123456789012:bucket/b--use1-az4--x-s3</TargetResource></S3PutObjectCopy>";
        assert_eq!(parsed(directory), Err(501));
    }

    #[test]
    fn a_kms_key_asks_for_sse_kms() {
        let copy = Copy {
            target: "arn:aws:s3:::dest".to_owned(),
            kms_key_id: Some("key".to_owned()),
            ..Copy::default()
        };
        let headers = copy.headers().unwrap();
        assert_eq!(headers[sse::ENCRYPTION], sse::AWS_KMS);
        assert_eq!(headers[sse::KMS_KEY_ID], "key");
    }
}
