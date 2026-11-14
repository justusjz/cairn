//! What each S3 request is, as policies see it: the actions it needs, on
//! which resources (see `policy`, and `plans/policies.md`). From AWS's
//! service authorization reference for S3 (its operations' authorized
//! actions), which is what the IAM and S3 guides say too:
//!
//! - GetObjectAttributes is `s3:GetObjectAttributes` and `s3:GetObject`;
//! - a read of one version is `s3:GetObjectVersion` (and of its tags,
//!   `s3:GetObjectVersionTagging`), a delete of one `s3:DeleteObjectVersion`;
//! - a write that sets tags (`x-amz-tagging`) needs `s3:PutObjectTagging`
//!   too, and one that sets an ACL `s3:PutObjectAcl` (`s3:PutBucketAcl`, for
//!   a bucket), and one that sets a retention or a legal hold
//!   `s3:PutObjectRetention` or `s3:PutObjectLegalHold` (a bucket created
//!   with Object Lock, `s3:PutBucketObjectLockConfiguration` and
//!   `s3:PutBucketVersioning`);
//! - bypassing a GOVERNANCE retention needs `s3:BypassGovernanceRetention`,
//!   checked where it's asked for (see `s3::object_lock`);
//! - a copy needs the source's read, on the source;
//! - HeadBucket is `s3:ListBucket`;
//! - deleting a bucket's configuration is its `Put` action.
//!
//! Not checked here: DeleteObjects checks each key on its own (`delete`),
//! and POST Object its form's key (`objects::post`).

use hyper::{HeaderMap, Method};

use crate::s3::{object_lock, objects::copy::parse_copy_source, util::query_param};

/// What an action is checked against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum On {
    /// No resource (`*`): ListAllMyBuckets.
    Account,
    Bucket(String),
    Object(String, String),
    /// A user of an account (by its ID), by its path (without its leading
    /// `/`) and name, for IAM's actions on it (see `On::user`).
    User(String, String),
    /// An account's users (by its ID) whose paths start with a prefix
    /// (without its leading `/`), for `iam:ListUsers` (`user/`, then the
    /// prefix: probed).
    Users(String, String),
    /// A managed policy of an account (by its ID; `aws`: Cairn's), by its
    /// path (without its leading `/`) and name, for IAM's actions on it.
    Policy(String, String),
    /// The cluster, for Cairn's actions (`cairn:`), which operators'
    /// policies allow: the account's.
    Cluster,
}

impl On {
    /// Its ARN.
    pub fn arn(&self) -> String {
        match self {
            On::Account => "*".to_owned(),
            On::Bucket(bucket) => format!("arn:aws:s3:::{bucket}"),
            On::Object(bucket, key) => format!("arn:aws:s3:::{bucket}/{key}"),
            On::User(account, name) => format!("arn:aws:iam::{account}:user/{name}"),
            On::Users(account, prefix) => format!("arn:aws:iam::{account}:user/{prefix}"),
            On::Policy(account, name) => format!("arn:aws:iam::{account}:policy/{name}"),
            On::Cluster => "arn:cairn:::cluster".to_owned(),
        }
    }

    /// User `name` of `account`, at `path`.
    pub fn user(account: &str, path: &str, name: &str) -> On {
        On::User(account.to_owned(), format!("{}{name}", path.strip_prefix('/').unwrap_or(path)))
    }

    /// `account`'s users at paths starting with `prefix` (`/…`).
    pub fn users(account: &str, prefix: &str) -> On {
        On::Users(account.to_owned(), prefix.strip_prefix('/').unwrap_or(prefix).to_owned())
    }

    /// Managed policy `name` of `account` (`aws`: Cairn's), at `path`.
    pub fn policy(account: &str, path: &str, name: &str) -> On {
        On::Policy(account.to_owned(), format!("{}{name}", path.strip_prefix('/').unwrap_or(path)))
    }

    /// The bucket whose policy applies, if any.
    pub fn bucket(&self) -> Option<&str> {
        match self {
            On::Bucket(bucket) | On::Object(bucket, _) => Some(bucket),
            _ => None,
        }
    }
}

/// One action a request needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    pub action: &'static str,
    pub on: On,
}

/// A request, as routing sees it.
pub struct Operation {
    /// S3's name for it (`GetObject`, ...).
    pub name: &'static str,
    pub checks: Vec<Check>,
}

/// Reading a bucket's configuration: the operation's name, and its action.
type Read = (&'static str, &'static str);
/// Writing it: the operation that sets it and its action, and the one that
/// deletes it (none, if it can't be) and its action.
type Write = (&'static str, &'static str, &'static str, &'static str);

/// A bucket configuration's subresource, and its reads and writes.
const CONFIGURATION: &[(&str, Read, Option<Write>)] = &[
    (
        "versioning",
        ("GetBucketVersioning", "s3:GetBucketVersioning"),
        Some(("PutBucketVersioning", "s3:PutBucketVersioning", "", "")),
    ),
    (
        "encryption",
        ("GetBucketEncryption", "s3:GetEncryptionConfiguration"),
        Some(("PutBucketEncryption", "s3:PutEncryptionConfiguration", "DeleteBucketEncryption", "s3:PutEncryptionConfiguration")),
    ),
    (
        "lifecycle",
        ("GetBucketLifecycleConfiguration", "s3:GetLifecycleConfiguration"),
        Some(("PutBucketLifecycleConfiguration", "s3:PutLifecycleConfiguration", "DeleteBucketLifecycle", "s3:PutLifecycleConfiguration")),
    ),
    (
        "cors",
        ("GetBucketCors", "s3:GetBucketCORS"),
        Some(("PutBucketCors", "s3:PutBucketCORS", "DeleteBucketCors", "s3:PutBucketCORS")),
    ),
    (
        "tagging",
        ("GetBucketTagging", "s3:GetBucketTagging"),
        Some(("PutBucketTagging", "s3:PutBucketTagging", "DeleteBucketTagging", "s3:PutBucketTagging")),
    ),
    (
        "policy",
        ("GetBucketPolicy", "s3:GetBucketPolicy"),
        Some(("PutBucketPolicy", "s3:PutBucketPolicy", "DeleteBucketPolicy", "s3:DeleteBucketPolicy")),
    ),
    ("policyStatus", ("GetBucketPolicyStatus", "s3:GetBucketPolicyStatus"), None),
    (
        "publicAccessBlock",
        ("GetPublicAccessBlock", "s3:GetBucketPublicAccessBlock"),
        Some(("PutPublicAccessBlock", "s3:PutBucketPublicAccessBlock", "DeletePublicAccessBlock", "s3:PutBucketPublicAccessBlock")),
    ),
    ("acl", ("GetBucketAcl", "s3:GetBucketAcl"), Some(("PutBucketAcl", "s3:PutBucketAcl", "", ""))),
    ("ownershipControls", ("GetBucketOwnershipControls", "s3:GetBucketOwnershipControls"), None),
    ("location", ("GetBucketLocation", "s3:GetBucketLocation"), None),
    (
        "object-lock",
        ("GetObjectLockConfiguration", "s3:GetBucketObjectLockConfiguration"),
        Some(("PutObjectLockConfiguration", "s3:PutBucketObjectLockConfiguration", "", "")),
    ),
    ("website", ("GetBucketWebsite", "s3:GetBucketWebsite"), None),
    ("replication", ("GetBucketReplication", "s3:GetReplicationConfiguration"), None),
    ("accelerate", ("GetBucketAccelerateConfiguration", "s3:GetAccelerateConfiguration"), None),
    ("requestPayment", ("GetBucketRequestPayment", "s3:GetBucketRequestPayment"), None),
    ("logging", ("GetBucketLogging", "s3:GetBucketLogging"), None),
    ("notification", ("GetBucketNotificationConfiguration", "s3:GetBucketNotification"), None),
];

/// The actions that read a bucket's configuration, which anyone the bucket
/// is visible to may (see the built-in policies). Not its policy, which
/// names who may do what, nor whether that makes it public.
fn configuration_reads() -> impl Iterator<Item = &'static str> {
    CONFIGURATION
        .iter()
        .map(|(_, (_, action), _)| *action)
        .filter(|a| !matches!(*a, "s3:GetBucketPolicy" | "s3:GetBucketPolicyStatus"))
}

/// Whether a request's headers set an ACL.
fn sets_acl(headers: &HeaderMap) -> bool {
    headers.contains_key("x-amz-acl") || headers.keys().any(|name| name.as_str().starts_with("x-amz-grant-"))
}

/// What a request is, and the actions it needs. `None` for what isn't
/// routed to an operation (a method a resource has none for).
pub fn operation(method: &Method, bucket: &str, key: &str, query: &str, headers: &HeaderMap) -> Option<Operation> {
    let has = |name| query_param(query, name).is_some();
    let check = |action, on: On| Check { action, on };
    let one = |name, action, on| Some(Operation { name, checks: vec![check(action, on)] });
    if bucket.is_empty() {
        return match *method {
            Method::GET => one("ListBuckets", "s3:ListAllMyBuckets", On::Account),
            _ => None,
        };
    }
    let on_bucket = || On::Bucket(bucket.to_owned());
    if key.is_empty() {
        let configuration = CONFIGURATION.iter().find(|(name, _, _)| has(name));
        return match (method.clone(), configuration) {
            (Method::GET, Some((_, (name, action), _))) => one(name, action, on_bucket()),
            (Method::GET, None) if has("versions") => one("ListObjectVersions", "s3:ListBucketVersions", on_bucket()),
            (Method::GET, None) if has("uploads") => {
                one("ListMultipartUploads", "s3:ListBucketMultipartUploads", on_bucket())
            }
            (Method::GET, None) => {
                let name = if query_param(query, "list-type").as_deref() == Some("2") { "ListObjectsV2" } else { "ListObjects" };
                one(name, "s3:ListBucket", on_bucket())
            }
            (Method::HEAD, _) => one("HeadBucket", "s3:ListBucket", on_bucket()),
            (Method::PUT, Some((_, _, Some((name, action, _, _))))) => one(name, action, on_bucket()),
            (Method::PUT, Some(_)) => None,
            (Method::PUT, None) => {
                let mut checks = vec![check("s3:CreateBucket", on_bucket())];
                if sets_acl(headers) {
                    checks.push(check("s3:PutBucketAcl", on_bucket()));
                }
                // Object Lock, which a bucket is created with by both.
                if crate::s3::object_lock::asks_for_bucket(headers) {
                    checks.push(check("s3:PutBucketObjectLockConfiguration", on_bucket()));
                    checks.push(check("s3:PutBucketVersioning", on_bucket()));
                }
                Some(Operation { name: "CreateBucket", checks })
            }
            (Method::DELETE, Some((_, _, Some((_, _, name, action))))) if !name.is_empty() => {
                one(name, action, on_bucket())
            }
            (Method::DELETE, Some(_)) => None,
            (Method::DELETE, None) => one("DeleteBucket", "s3:DeleteBucket", on_bucket()),
            // Each key is checked on its own.
            (Method::POST, None) if has("delete") => Some(Operation { name: "DeleteObjects", checks: Vec::new() }),
            _ => None,
        };
    }
    let on_object = || On::Object(bucket.to_owned(), key.to_owned());
    let version = has("versionId");
    let versioned = |plain, of_version| if version { of_version } else { plain };
    let tags = headers.contains_key("x-amz-tagging");
    // A write that makes an object: its tags, ACL and Object Lock are
    // actions of their own.
    let writes = |name| {
        let mut checks = vec![check("s3:PutObject", on_object())];
        if tags {
            checks.push(check("s3:PutObjectTagging", on_object()));
        }
        if headers.contains_key(object_lock::MODE) || headers.contains_key(object_lock::RETAIN_UNTIL) {
            checks.push(check("s3:PutObjectRetention", on_object()));
        }
        if headers.contains_key(object_lock::LEGAL_HOLD) {
            checks.push(check("s3:PutObjectLegalHold", on_object()));
        }
        if sets_acl(headers) {
            checks.push(check("s3:PutObjectAcl", on_object()));
        }
        Operation { name, checks }
    };
    // A copy's source, read as a version if it names one.
    let source = || {
        let copy_source = headers.get("x-amz-copy-source").and_then(|v| v.to_str().ok())?;
        let (bucket, key, version) = parse_copy_source(copy_source)?;
        let action = if version.is_some() { "s3:GetObjectVersion" } else { "s3:GetObject" };
        Some(check(action, On::Object(bucket, key)))
    };
    let copies = headers.contains_key("x-amz-copy-source");
    match method.clone() {
        Method::GET if has("acl") => one("GetObjectAcl", versioned("s3:GetObjectAcl", "s3:GetObjectVersionAcl"), on_object()),
        Method::GET if has("uploadId") => one("ListParts", "s3:ListMultipartUploadParts", on_object()),
        Method::GET if has("retention") => one("GetObjectRetention", "s3:GetObjectRetention", on_object()),
        Method::GET if has("legal-hold") => one("GetObjectLegalHold", "s3:GetObjectLegalHold", on_object()),
        Method::PUT if has("retention") => one("PutObjectRetention", "s3:PutObjectRetention", on_object()),
        Method::PUT if has("legal-hold") => one("PutObjectLegalHold", "s3:PutObjectLegalHold", on_object()),
        Method::GET if has("tagging") => {
            one("GetObjectTagging", versioned("s3:GetObjectTagging", "s3:GetObjectVersionTagging"), on_object())
        }
        // Both, as S3 asks for both (its user guide's GetObjectAttributes).
        Method::GET if has("attributes") => Some(Operation {
            name: "GetObjectAttributes",
            checks: vec![
                check(versioned("s3:GetObjectAttributes", "s3:GetObjectVersionAttributes"), on_object()),
                check(versioned("s3:GetObject", "s3:GetObjectVersion"), on_object()),
            ],
        }),
        Method::GET => one("GetObject", versioned("s3:GetObject", "s3:GetObjectVersion"), on_object()),
        Method::HEAD => one("HeadObject", versioned("s3:GetObject", "s3:GetObjectVersion"), on_object()),
        Method::PUT if has("acl") => one("PutObjectAcl", versioned("s3:PutObjectAcl", "s3:PutObjectVersionAcl"), on_object()),
        Method::PUT if has("tagging") => {
            one("PutObjectTagging", versioned("s3:PutObjectTagging", "s3:PutObjectVersionTagging"), on_object())
        }
        Method::PUT if has("uploadId") && copies => {
            let mut checks = vec![check("s3:PutObject", on_object())];
            checks.extend(source());
            Some(Operation { name: "UploadPartCopy", checks })
        }
        Method::PUT if has("uploadId") => one("UploadPart", "s3:PutObject", on_object()),
        Method::PUT if copies => {
            let mut operation = writes("CopyObject");
            // Only tags the copy is given (not the source's) are set.
            let replaces = headers.get("x-amz-tagging-directive").is_some_and(|d| d.as_bytes() == b"REPLACE");
            if !replaces {
                operation.checks.retain(|c| c.action != "s3:PutObjectTagging");
            }
            operation.checks.extend(source());
            Some(operation)
        }
        Method::PUT => Some(writes("PutObject")),
        Method::POST if has("uploads") => Some(writes("CreateMultipartUpload")),
        Method::POST if has("uploadId") => one("CompleteMultipartUpload", "s3:PutObject", on_object()),
        Method::DELETE if has("uploadId") => one("AbortMultipartUpload", "s3:AbortMultipartUpload", on_object()),
        Method::DELETE if has("tagging") => {
            one("DeleteObjectTagging", versioned("s3:DeleteObjectTagging", "s3:DeleteObjectVersionTagging"), on_object())
        }
        Method::DELETE => one("DeleteObject", versioned("s3:DeleteObject", "s3:DeleteObjectVersion"), on_object()),
        _ => None,
    }
}

/// The action deleting one key of a DeleteObjects takes.
pub fn delete(version: bool) -> &'static str {
    if version { "s3:DeleteObjectVersion" } else { "s3:DeleteObject" }
}

/// What a grant of `permission` allows on its bucket and the bucket's
/// objects: exactly what the grant allowed before there were policies (see
/// `roles`), but HeadBucket (`s3:ListBucket`), which only `read` allows now,
/// as in S3; and reading the bucket's configuration (but its policy), with
/// any of them. A `read` grant may read versions' Object Lock, but no grant
/// may set one (only the bucket's default retention applies to a writer's
/// writes), nor bypass one.
pub fn grant_actions(permission: crate::roles::Permission) -> Vec<&'static str> {
    use crate::roles::Permission;
    let mut actions: Vec<&str> = match permission {
        Permission::Read => vec![
            "s3:GetObject",
            "s3:GetObjectVersion",
            "s3:GetObjectAttributes",
            "s3:GetObjectVersionAttributes",
            "s3:GetObjectTagging",
            "s3:GetObjectVersionTagging",
            "s3:GetObjectAcl",
            "s3:GetObjectVersionAcl",
            "s3:GetObjectRetention",
            "s3:GetObjectLegalHold",
            "s3:ListBucket",
            "s3:ListBucketVersions",
            "s3:ListBucketMultipartUploads",
            "s3:ListMultipartUploadParts",
        ],
        Permission::Write => vec![
            "s3:PutObject",
            "s3:PutObjectTagging",
            "s3:PutObjectVersionTagging",
            "s3:DeleteObject",
            "s3:DeleteObjectTagging",
            "s3:DeleteObjectVersionTagging",
            "s3:PutObjectAcl",
            "s3:PutObjectVersionAcl",
            "s3:AbortMultipartUpload",
            "s3:ListBucketMultipartUploads",
            "s3:ListMultipartUploadParts",
        ],
        Permission::DeleteVersion => vec!["s3:DeleteObjectVersion"],
    };
    actions.extend(configuration_reads());
    actions
}

/// A grant of `permission` on `bucket`, as an identity policy (for tests:
/// grants are statements of their buckets' policies, see `grants`).
#[cfg(test)]
pub fn grant_policy(permission: crate::roles::Permission, bucket: &str) -> String {
    let actions = grant_actions(permission).iter().map(|a| format!("\"{a}\"")).collect::<Vec<_>>().join(",");
    format!(
        "{{\"Version\":\"2012-10-17\",\"Statement\":[\
         {{\"Effect\":\"Allow\",\"Action\":[{actions}],\"Resource\":[\"arn:aws:s3:::{bucket}\",\"arn:aws:s3:::{bucket}/*\"]}}]}}"
    )
}

/// The built-in managed policy `AdministratorAccess`, which an admin has
/// attached: everything, as AWS's. Bounded to the admin's own account, as
/// in AWS, by whose resources are whose (see `plans/policies.md`).
pub fn admin_policy() -> String {
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{
        Context, Kind, Policy, Principal, Request, Verdict, verdict,
        s3_actions::{ACTIONS, Applies},
    };
    use crate::roles::Permission;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(), value.parse().unwrap());
        }
        headers
    }

    /// Every request Cairn routes, as (method, bucket, key, query, headers).
    fn requests() -> Vec<(Method, &'static str, &'static str, &'static str, HeaderMap)> {
        let none = HeaderMap::new;
        let mut requests = vec![(Method::GET, "", "", "", none())];
        for (name, _, write) in CONFIGURATION {
            requests.push((Method::GET, "b", "", name, none()));
            if let Some((_, _, delete, _)) = write {
                requests.push((Method::PUT, "b", "", name, none()));
                if !delete.is_empty() {
                    requests.push((Method::DELETE, "b", "", name, none()));
                }
            }
        }
        requests.extend([
            (Method::GET, "b", "", "", none()),
            (Method::GET, "b", "", "list-type=2&prefix=a", none()),
            (Method::GET, "b", "", "versions", none()),
            (Method::GET, "b", "", "uploads", none()),
            (Method::HEAD, "b", "", "", none()),
            (Method::PUT, "b", "", "", none()),
            (Method::DELETE, "b", "", "", none()),
            (Method::GET, "b", "k", "", none()),
            (Method::GET, "b", "k", "versionId=v", none()),
            (Method::HEAD, "b", "k", "", none()),
            (Method::HEAD, "b", "k", "versionId=v", none()),
            (Method::GET, "b", "k", "acl", none()),
            (Method::GET, "b", "k", "tagging", none()),
            (Method::GET, "b", "k", "tagging&versionId=v", none()),
            (Method::GET, "b", "k", "uploadId=u", none()),
            (Method::GET, "b", "k", "attributes", none()),
            (Method::GET, "b", "k", "attributes&versionId=v", none()),
            (Method::GET, "b", "k", "partNumber=2", none()),
            (Method::HEAD, "b", "k", "partNumber=2", none()),
            (Method::PUT, "b", "k", "", none()),
            (Method::PUT, "b", "k", "", headers(&[("x-amz-tagging", "a=b")])),
            (Method::PUT, "b", "k", "acl", none()),
            (Method::PUT, "b", "k", "tagging", none()),
            (Method::PUT, "b", "k", "tagging&versionId=v", none()),
            (Method::PUT, "b", "k", "uploadId=u&partNumber=1", none()),
            (Method::PUT, "b", "k", "uploadId=u&partNumber=1", headers(&[("x-amz-copy-source", "src/s")])),
            (Method::PUT, "b", "k", "", headers(&[("x-amz-copy-source", "src/s")])),
            (Method::PUT, "b", "k", "", headers(&[("x-amz-copy-source", "src/s?versionId=v")])),
            (Method::PUT, "b", "k", "", headers(&[("x-amz-copy-source", "b/s"), ("x-amz-tagging-directive", "REPLACE"), ("x-amz-tagging", "a=b")])),
            (Method::POST, "b", "k", "uploads", none()),
            (Method::POST, "b", "k", "uploads", headers(&[("x-amz-tagging", "a=b")])),
            (Method::POST, "b", "k", "uploadId=u", none()),
            (Method::DELETE, "b", "k", "", none()),
            (Method::DELETE, "b", "k", "versionId=v", none()),
            (Method::DELETE, "b", "k", "uploadId=u", none()),
            (Method::DELETE, "b", "k", "tagging", none()),
            (Method::DELETE, "b", "k", "tagging&versionId=v", none()),
            (Method::GET, "b", "k", "retention", none()),
            (Method::GET, "b", "k", "legal-hold&versionId=v", none()),
            (Method::PUT, "b", "k", "retention", none()),
            (Method::PUT, "b", "k", "legal-hold", none()),
            (Method::PUT, "b", "k", "", headers(&[("x-amz-object-lock-legal-hold", "ON")])),
            (Method::PUT, "b", "", "", headers(&[("x-amz-bucket-object-lock-enabled", "true")])),
        ]);
        requests
    }

    /// Every action is one of S3's, and on the kind of resource it applies to.
    #[test]
    fn actions_are_s3s() {
        for (method, bucket, key, query, headers) in requests() {
            let operation = operation(&method, bucket, key, query, &headers).unwrap();
            assert!(!operation.checks.is_empty(), "{}", operation.name);
            for Check { action, on } in operation.checks {
                let name = action.strip_prefix("s3:").unwrap();
                let (_, applies, _) = ACTIONS.iter().find(|(n, _, _)| *n == name).unwrap_or_else(|| panic!("{action}"));
                let wanted = match on {
                    On::Account => Applies::Account,
                    On::Bucket(_) => Applies::Bucket,
                    On::Object(..) => Applies::Object,
                    on => panic!("S3's operations are on S3's resources, not {on:?}"),
                };
                assert_eq!(*applies, wanted, "{action}");
            }
        }
        for permission in [Permission::Read, Permission::Write, Permission::DeleteVersion] {
            Policy::parse(&grant_policy(permission, "b"), Kind::Identity).unwrap();
        }
        Policy::parse(&admin_policy(), Kind::Identity).unwrap();
    }

    #[test]
    fn versions_tags_and_copies_need_their_own_actions() {
        let actions = |method: Method, key, query, pairs: &[(&str, &str)]| {
            let operation = operation(&method, "b", key, query, &headers(pairs)).unwrap();
            operation.checks.into_iter().map(|c| (c.action, c.on.arn())).collect::<Vec<_>>()
        };
        assert_eq!(actions(Method::GET, "k", "versionId=v", &[]), [("s3:GetObjectVersion", "arn:aws:s3:::b/k".to_owned())]);
        assert_eq!(
            actions(Method::PUT, "k", "", &[("x-amz-tagging", "a=b"), ("x-amz-acl", "private")]),
            [
                ("s3:PutObject", "arn:aws:s3:::b/k".to_owned()),
                ("s3:PutObjectTagging", "arn:aws:s3:::b/k".to_owned()),
                ("s3:PutObjectAcl", "arn:aws:s3:::b/k".to_owned()),
            ]
        );
        assert_eq!(
            actions(Method::PUT, "k", "", &[("x-amz-copy-source", "/src/a%20b?versionId=v"), ("x-amz-tagging", "a=b")]),
            [("s3:PutObject", "arn:aws:s3:::b/k".to_owned()), ("s3:GetObjectVersion", "arn:aws:s3:::src/a b".to_owned())]
        );
        assert_eq!(actions(Method::HEAD, "", "", &[]), [("s3:ListBucket", "arn:aws:s3:::b".to_owned())]);
        assert_eq!(actions(Method::DELETE, "", "cors", &[]), [("s3:PutBucketCORS", "arn:aws:s3:::b".to_owned())]);
        assert!(operation(&Method::DELETE, "b", "", "versioning", &HeaderMap::new()).is_none());
        assert!(operation(&Method::PATCH, "b", "k", "", &HeaderMap::new()).is_none());
    }

    /// The policies a role's grants (statements of the buckets' policies,
    /// see `grants`) and admin flag become: its identity policies, and the
    /// buckets'.
    fn policies(grants: &[(Permission, &str)], admin: bool) -> (Vec<Policy>, Vec<(&'static str, Policy)>) {
        let mut identity = Vec::new();
        if admin {
            identity.push(Policy::parse(&admin_policy(), Kind::Identity).unwrap());
        }
        let buckets = ["b", "src"]
            .into_iter()
            .filter_map(|bucket| {
                let changes: Vec<_> = grants
                    .iter()
                    .filter(|(_, b)| *b == bucket)
                    .map(|(p, _)| ("arn:aws:iam::123456789012:user/r".to_owned(), *p, true))
                    .collect();
                let text = crate::grants::changed(None, bucket, &changes).unwrap()?;
                // Its users bound to their IDs, as stored policies' are.
                let ids = [("arn:aws:iam::123456789012:user/r".to_owned(), "r".to_owned())].into();
                Some((bucket, Policy::parse(&text, Kind::Bucket(bucket)).unwrap().with_ids(ids)))
            })
            .collect();
        (identity, buckets)
    }

    /// Whether these policies allow every check of `operation`.
    fn allowed((identity, buckets): &(Vec<Policy>, Vec<(&str, Policy)>), operation: &Operation) -> bool {
        let context = Context::default();
        operation.checks.iter().all(|check| {
            let resource = check.on.arn();
            let request = Request {
                principal: Principal::User { account: "123456789012", name: "r", id: "r" },
                action: check.action,
                resource: &resource,
                context: &context,
            };
            let bucket = buckets.iter().find(|(b, _)| Some(*b) == check.on.bucket()).map(|(_, p)| p);
            verdict(identity, bucket, &request) == Verdict::Allow
        })
    }

    /// Every combination of grants on the bucket and a copy's source allows
    /// exactly what `authorize` allowed it, but where S3 says otherwise; and
    /// an admin (`AdministratorAccess`) is allowed everything.
    #[test]
    fn grants_allow_what_they_did() {
        let permissions = [Permission::Read, Permission::Write, Permission::DeleteVersion];
        let mut differences = Vec::new();
        for mask in 0..(1 << 7) {
            let mut grants = Vec::new();
            for (i, permission) in permissions.iter().enumerate() {
                if mask & (1 << i) != 0 {
                    grants.push((*permission, "b"));
                }
                if mask & (1 << (i + 3)) != 0 {
                    grants.push((*permission, "src"));
                }
            }
            let admin = mask & (1 << 6) != 0;
            let principal = crate::roles::Principal::for_test(admin, &grants);
            let policies = policies(&grants, admin);
            for (method, bucket, key, query, headers) in requests() {
                // ListBuckets and DeleteObjects decide per bucket and key.
                if bucket.is_empty() {
                    continue;
                }
                let operation = operation(&method, bucket, key, query, &headers).unwrap();
                let copy_source = headers.get("x-amz-copy-source").and_then(|v| v.to_str().ok());
                let before = crate::s3::authorize(&principal, &method, bucket, key, query, copy_source);
                let after = allowed(&policies, &operation);
                if admin {
                    assert!(after, "{}", operation.name);
                    continue;
                }
                if before != after {
                    differences.push((operation.name, before, after));
                }
            }
        }
        differences.sort();
        differences.dedup();
        // HeadBucket is `s3:ListBucket`: only `read` (and not a writer, who
        // could HEAD any bucket they could see) may; the bucket policy is
        // for admins only, not everyone who sees the bucket; and setting
        // a version's Object Lock is no writer's.
        assert_eq!(
            differences,
            [
                ("GetBucketPolicy", true, false),
                ("GetBucketPolicyStatus", true, false),
                ("HeadBucket", true, false),
                ("PutObject", true, false),
                ("PutObjectLegalHold", true, false),
                ("PutObjectRetention", true, false),
            ],
            "{differences:?}"
        );
    }
}
