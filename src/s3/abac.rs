//! The object tag keys of a request's checks (see `plans/abac.md`; what
//! carries which was probed on S3):
//!
//! - `s3:RequestObjectTag/…` and `s3:RequestObjectTagKeys`, the tags a
//!   write gives its object: PutObject's, CreateMultipartUpload's and (only
//!   replacing its source's) CopyObject's `x-amz-tagging`, and
//!   PutObjectTagging's body (see `s3::handle_request`). UploadPart,
//!   UploadPartCopy and CompleteMultipartUpload carry their upload's tags.
//!   None (or an empty set) is no keys.
//! - `s3:ExistingObjectTag/…`, the tags of the version a request reads or
//!   annotates (the one named by `versionId`, else the latest; none for a
//!   delete marker or no version), and those of a copy's source. Not a
//!   write's, which is about a new version; S3 has none on its PutObject.
//!
//! The bucket's tags (`aws:ResourceTag`, `s3:BucketTag`) are `access`'s.
//! What takes another lookup (the upload's or the version's tags) is only
//! looked up if a policy that could decide the request tests its keys:
//! otherwise every read would pay for it.

use hyper::HeaderMap;

use crate::db::Cached;
use crate::{
    App,
    s3::{
        access::Access,
        actions::Operation,
        objects::copy::parse_copy_source,
        tags::{self, Tags},
        util::query_param,
    },
};

/// The operations on an existing version, whose checks carry its tags.
const ON_EXISTING: &[&str] = &[
    "GetObject",
    "HeadObject",
    "GetObjectAttributes",
    "GetObjectAcl",
    "PutObjectAcl",
    "GetObjectTagging",
    "PutObjectTagging",
    "DeleteObjectTagging",
];

/// Sets the condition keys of `operation`'s object tags in `access`, whose
/// checks' buckets are loaded.
pub async fn prepare(
    app: &App,
    access: &mut Access,
    operation: &Operation,
    bucket: &str,
    key: &str,
    query: &str,
    headers: &HeaderMap,
) -> anyhow::Result<()> {
    let replaces = headers
        .get(tags::DIRECTIVE)
        .is_some_and(|d| d.as_bytes() == b"REPLACE");
    let given = match operation.name {
        "PutObject" | "CreateMultipartUpload" => true,
        "CopyObject" => replaces,
        _ => false,
    };
    if given
        && let Some(Ok(tags)) = headers
            .get(tags::HEADER)
            .map(|v| Tags::from_header(v.as_bytes()))
    {
        request_tags(access, &tags);
    }
    if matches!(
        operation.name,
        "UploadPart" | "UploadPartCopy" | "CompleteMultipartUpload"
    ) && access.tests(Some(bucket), "s3:requestobjecttag")
        && let Some(upload_id) =
            query_param(query, "uploadId").and_then(|id| uuid::Uuid::parse_str(&id).ok())
    {
        let row = app
            .pool
            .get()
            .await?
            .query_opt_cached(
                "SELECT tags FROM multipart_uploads WHERE upload_id = $1 AND bucket = $2 AND key = $3",
                &[&upload_id, &bucket, &key],
            )
            .await?;
        if let Some(row) = row {
            request_tags(access, &Tags::from_stored(row.get(0)));
        }
    }
    let mut existing = Vec::new();
    if ON_EXISTING.contains(&operation.name) {
        existing.push((
            bucket.to_owned(),
            key.to_owned(),
            query_param(query, "versionId"),
        ));
    }
    if matches!(operation.name, "CopyObject" | "UploadPartCopy")
        && let Some(source) = headers
            .get("x-amz-copy-source")
            .and_then(|v| v.to_str().ok())
        && let Some(source) = parse_copy_source(source)
    {
        existing.push(source);
    }
    for (bucket, key, version_id) in existing {
        if !access.tests(Some(&bucket), "s3:existingobjecttag/") {
            continue;
        }
        if let Some(tags) = version_tags(app, &bucket, &key, version_id.as_deref()).await? {
            access.set_object_tags(&bucket, &key, tags);
        }
    }
    Ok(())
}

/// Sets the tags a request gives its object as its `s3:RequestObjectTag`s
/// (none if there are none).
pub fn request_tags(access: &mut Access, tags: &Tags) {
    if !tags.is_empty() {
        tags.set_context(
            &mut access.context,
            "s3:RequestObjectTag",
            Some("s3:RequestObjectTagKeys"),
        );
    }
}

/// The tags of the version of `key` in `bucket` named `version_id` (else
/// its latest), if it's there and has any, and isn't a delete marker.
async fn version_tags(
    app: &App,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
) -> anyhow::Result<Option<Tags>> {
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached(
            "SELECT tags FROM objects
             WHERE bucket = $1 AND key = $2 AND NOT is_delete_marker
               AND CASE WHEN $3::text IS NULL THEN is_latest ELSE version_id = $3 END",
            &[&bucket, &key, &version_id],
        )
        .await?;
    Ok(row
        .map(|row| Tags::from_stored(row.get(0)))
        .filter(|tags| !tags.is_empty()))
}
