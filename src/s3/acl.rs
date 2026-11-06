//! ACLs, as modern S3 takes them: disabled. New S3 buckets default to Object
//! Ownership "bucket owner enforced" (since April 2023), under which the bucket
//! owner owns everything in it, and access is a matter of policies (here, of
//! roles' grants), never ACLs. Cairn answers as such a bucket does:
//!
//! - A write may ask for no ACL, or for one that grants only the bucket owner
//!   full control: `bucket-owner-full-control` for an object, `private` for a
//!   bucket. Anything else, a canned ACL or `x-amz-grant-*` grants, is refused,
//!   rather than ignored.
//! - Setting an ACL (`PUT ?acl`) is the same: a no-op if it's the owner's
//!   only, refused otherwise.
//! - Reading one shows the owner with full control (`util::stub_acl`).

use http_body_util::Full;
use hyper::{HeaderMap, Response, StatusCode, body::Bytes};

use crate::s3::util::{format_s3_error, xml_ok};

/// What an ACL would be set on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum On {
    Object,
    Bucket,
}

impl On {
    /// The canned ACL that grants only the bucket owner full control.
    fn owner_only(self) -> &'static str {
        match self {
            On::Object => "bucket-owner-full-control",
            On::Bucket => "private",
        }
    }
}

/// Whether the request asks for an ACL other than the owner's only, which
/// a bucket without ACLs refuses.
fn asks_for_other_acl(headers: &HeaderMap, on: On) -> bool {
    let grants = headers
        .keys()
        .any(|name| name.as_str().starts_with("x-amz-grant-"));
    let canned = headers
        .get("x-amz-acl")
        .map(|v| v.to_str().unwrap_or("").trim());
    grants || canned.is_some_and(|acl| acl != on.owner_only())
}

/// Refuses a write (PutObject, CreateMultipartUpload, CopyObject, or, `On::Bucket`,
/// CreateBucket) that asks for an ACL other than the owner's only.
pub fn check_write(headers: &HeaderMap, on: On) -> Result<(), Response<Full<Bytes>>> {
    if !asks_for_other_acl(headers, on) {
        return Ok(());
    }
    Err(match on {
        On::Object => not_supported(),
        On::Bucket => format_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidBucketAclWithObjectOwnership",
            "Bucket cannot have ACLs set with ObjectOwnership's BucketOwnerEnforced setting",
        ),
    })
}

/// PutObjectAcl / PutBucketAcl: a no-op for the owner's only ACL (in
/// `x-amz-acl`, and nothing else), refused for anything else, which includes
/// an ACL in the body.
pub fn put(headers: &HeaderMap, on: On) -> Response<Full<Bytes>> {
    let has_body = headers
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim() != "0");
    let canned = headers
        .get("x-amz-acl")
        .map(|v| v.to_str().unwrap_or("").trim());
    if canned == Some(on.owner_only()) && !asks_for_other_acl(headers, on) && !has_body {
        return Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .unwrap();
    }
    not_supported()
}

/// PutObjectAcl: as `put`, for an object version that exists (404 otherwise).
pub async fn put_object_acl(
    app: &crate::App,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    headers: &HeaderMap,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let client = app.pool.get().await?;
    Ok(
        match crate::s3::objects::get::lookup_version(&client, bucket, key, version_id).await? {
            Ok(_) => put(headers, On::Object),
            Err(missing) => missing.read_response(),
        },
    )
}

/// PutBucketAcl: as `put`, for a bucket that exists (404 otherwise).
pub async fn put_bucket_acl(
    app: &crate::App,
    bucket: &str,
    headers: &HeaderMap,
) -> anyhow::Result<Response<Full<Bytes>>> {
    use crate::db::Cached;
    let client = app.pool.get().await?;
    let exists = client
        .query_opt_cached("SELECT 1 FROM buckets WHERE name = $1", &[&bucket])
        .await?
        .is_some();
    Ok(match exists {
        true => put(headers, On::Bucket),
        false => format_s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "the specified bucket does not exist",
        ),
    })
}

fn not_supported() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::BAD_REQUEST,
        "AccessControlListNotSupported",
        "The bucket does not allow ACLs",
    )
}

/// GetBucketOwnershipControls: every bucket is "bucket owner enforced".
pub fn ownership_controls() -> Response<Full<Bytes>> {
    xml_ok(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <OwnershipControls xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Rule><ObjectOwnership>BucketOwnerEnforced</ObjectOwnership></Rule>\
         </OwnershipControls>"
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, value.parse().unwrap());
        }
        map
    }

    #[test]
    fn takes_no_acl_or_the_owners_only() {
        for on in [On::Object, On::Bucket] {
            assert!(check_write(&HeaderMap::new(), on).is_ok());
            assert!(check_write(&headers(&[("x-amz-acl", on.owner_only())]), on).is_ok());
            for other in [
                headers(&[("x-amz-acl", "public-read")]),
                headers(&[(
                    "x-amz-grant-read",
                    "uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"",
                )]),
                headers(&[
                    ("x-amz-acl", on.owner_only()),
                    ("x-amz-grant-full-control", "id=other"),
                ]),
            ] {
                assert_eq!(
                    check_write(&other, on).unwrap_err().status(),
                    StatusCode::BAD_REQUEST,
                    "{on:?} {other:?}"
                );
            }
        }
        // `private` is a bucket's owner-only ACL, not an object's.
        assert!(check_write(&headers(&[("x-amz-acl", "private")]), On::Object).is_err());
        assert!(
            check_write(
                &headers(&[("x-amz-acl", "bucket-owner-full-control")]),
                On::Bucket
            )
            .is_err()
        );
    }

    #[test]
    fn setting_the_owners_only_acl_is_a_no_op() {
        let owner = headers(&[("x-amz-acl", "bucket-owner-full-control")]);
        assert_eq!(put(&owner, On::Object).status(), StatusCode::OK);
        assert_eq!(
            put(&headers(&[("x-amz-acl", "public-read")]), On::Object).status(),
            StatusCode::BAD_REQUEST
        );
        // An ACL in the body (an AccessControlPolicy) isn't looked into.
        let body = headers(&[("content-length", "300")]);
        assert_eq!(put(&body, On::Object).status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            put(&headers(&[("x-amz-acl", "private")]), On::Bucket).status(),
            StatusCode::OK
        );
    }
}
