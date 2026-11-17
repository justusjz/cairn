//! ACLs, as modern S3 takes them: disabled. New S3 buckets default to Object
//! Ownership "bucket owner enforced" (since April 2023), under which the bucket
//! owner owns everything in it, and access is a matter of policies, never
//! ACLs. Cairn answers as such a bucket does (probed):
//!
//! - An object write may ask for no ACL, or a canned one that gives no one
//!   but the bucket owner anything: `private`, `bucket-owner-read`,
//!   `bucket-owner-full-control`. Another canned ACL, or `x-amz-grant-*`
//!   grants, is refused, rather than ignored; a canned ACL S3 doesn't have is
//!   an `InvalidArgument`. CreateBucket takes `private` only.
//! - Setting an ACL (`PUT ?acl`) is always refused.
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

/// S3's canned ACLs.
const CANNED: &[&str] = &[
    "private",
    "public-read",
    "public-read-write",
    "authenticated-read",
    "aws-exec-read",
    "bucket-owner-read",
    "bucket-owner-full-control",
    "log-delivery-write",
];

impl On {
    /// The canned ACLs that give no one but the bucket owner anything.
    fn owner_only(self) -> &'static [&'static str] {
        match self {
            On::Object => &["private", "bucket-owner-read", "bucket-owner-full-control"],
            On::Bucket => &["private"],
        }
    }
}

/// Refuses a write (PutObject, CreateMultipartUpload, CopyObject, or, `On::Bucket`,
/// CreateBucket) that asks for an ACL other than the owner's only.
pub fn check_write(headers: &HeaderMap, on: On) -> Result<(), Response<Full<Bytes>>> {
    let grants = headers.keys().any(|name| name.as_str().starts_with("x-amz-grant-"));
    let canned = headers.get("x-amz-acl").map(|v| String::from_utf8_lossy(v.as_bytes()).trim().to_owned());
    if on == On::Object
        && let Some(acl) = canned.as_deref().filter(|acl| !CANNED.contains(acl))
    {
        let mut rejection = crate::auth::Rejection::new(StatusCode::BAD_REQUEST, "InvalidArgument", "");
        rejection.details.push(("ArgumentName", "x-amz-acl".to_owned()));
        rejection.details.push(("ArgumentValue", acl.to_owned()));
        return Err(crate::s3::util::rejection_response(&rejection));
    }
    if !grants && canned.as_deref().is_none_or(|acl| on.owner_only().contains(&acl)) {
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

/// PutObjectAcl / PutBucketAcl: refused, whatever ACL they ask for, as S3
/// refuses them with ACLs disabled (probed: the owner's only ones too).
pub fn put(_headers: &HeaderMap, _on: On) -> Response<Full<Bytes>> {
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

/// GetObjectAcl: the owner's full control (see `util::stub_acl`), of an object
/// version that exists; a missing one's 404, or a delete marker's, as S3's
/// (probed).
pub async fn get_object_acl(
    app: &crate::App,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let client = app.pool.get().await?;
    let owner_id = crate::s3::util::canonical_id(&crate::s3::util::bucket_owner(&client, bucket).await?);
    Ok(
        match crate::s3::objects::get::lookup_version(&client, bucket, key, version_id).await? {
            Ok(_) => crate::s3::util::stub_acl(&owner_id),
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
            "The specified bucket does not exist",
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

/// PutBucketOwnershipControls: a no-op for BucketOwnerEnforced, which every
/// bucket is; the others, which have ACLs, aren't implemented; anything
/// else is S3's MalformedXML (probed).
pub fn put_ownership_controls(body: &[u8]) -> Response<Full<Bytes>> {
    let ownership = std::str::from_utf8(body).ok().and_then(|text| {
        let doc = roxmltree::Document::parse(text).ok()?;
        let root = doc.root_element();
        if root.tag_name().name() != "OwnershipControls" {
            return None;
        }
        let rules: Vec<_> = root.children().filter(|n| n.is_element()).collect();
        let [rule] = rules[..] else { return None };
        let values: Vec<_> = rule.children().filter(|n| n.is_element()).collect();
        match (rule.tag_name().name(), &values[..]) {
            ("Rule", [value]) if value.tag_name().name() == "ObjectOwnership" => value.text().map(str::to_owned),
            _ => None,
        }
    });
    match ownership.as_deref() {
        Some("BucketOwnerEnforced") => Response::builder().status(StatusCode::OK).body(Full::new(Bytes::new())).unwrap(),
        Some("ObjectWriter" | "BucketOwnerPreferred") => format_s3_error(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "Cairn has no ACLs: every bucket's object ownership is BucketOwnerEnforced",
        ),
        _ => format_s3_error(
            StatusCode::BAD_REQUEST,
            "MalformedXML",
            "The XML you provided was not well-formed or did not validate against our published schema",
        ),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn takes_bucket_owner_enforced_only() {
        let put = |rule: &str| {
            let body = format!("<OwnershipControls xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Rule>{rule}</Rule></OwnershipControls>");
            super::put_ownership_controls(body.as_bytes()).status().as_u16()
        };
        assert_eq!(put("<ObjectOwnership>BucketOwnerEnforced</ObjectOwnership>"), 200);
        assert_eq!(put("<ObjectOwnership>ObjectWriter</ObjectOwnership>"), 501);
        assert_eq!(put("<ObjectOwnership>Nope</ObjectOwnership>"), 400);
        assert_eq!(put(""), 400);
    }

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
            assert!(check_write(&headers(&[("x-amz-acl", "private")]), on).is_ok());
            for other in [
                headers(&[("x-amz-acl", "public-read")]),
                headers(&[(
                    "x-amz-grant-read",
                    "uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"",
                )]),
                headers(&[("x-amz-acl", "private"), ("x-amz-grant-full-control", "id=other")]),
            ] {
                assert_eq!(
                    check_write(&other, on).unwrap_err().status(),
                    StatusCode::BAD_REQUEST,
                    "{on:?} {other:?}"
                );
            }
        }
        for owners in ["bucket-owner-read", "bucket-owner-full-control"] {
            assert!(check_write(&headers(&[("x-amz-acl", owners)]), On::Object).is_ok());
            assert!(check_write(&headers(&[("x-amz-acl", owners)]), On::Bucket).is_err());
        }
        // One S3 doesn't have (case-sensitive) isn't refused as an ACL.
        for unknown in ["PRIVATE", "nonsense"] {
            let refused = check_write(&headers(&[("x-amz-acl", unknown)]), On::Object).unwrap_err();
            assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn setting_an_acl_is_refused() {
        for (acl, on) in [("bucket-owner-full-control", On::Object), ("private", On::Bucket), ("public-read", On::Object)] {
            assert_eq!(put(&headers(&[("x-amz-acl", acl)]), on).status(), StatusCode::BAD_REQUEST);
        }
    }
}
