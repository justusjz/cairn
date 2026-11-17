//! What S3 Access Grants' scopes cover, and the session policy a vended
//! session gets (see `access_grants`).
//!
//! A scope is an `s3://` URI. Below `s3://`, it's a path (`bucket/key`)
//! that covers the paths it's a prefix of, but for an object's (S3PrefixType
//! `Object`): that covers its own path only. A trailing `*` says the same
//! as none; elsewhere, a `*` is refused, as nothing would match it as
//! written.
//!
//! - A location's scope (`s3://`, `s3://bucket`, `s3://bucket/prefix/`)
//!   names no `*`. Without a trailing `/`, it's a whole bucket, or a whole
//!   "directory": `s3://bucket/dir` covers `bucket/dir/…`, not `bucket/dirt`.
//! - A grant's is its location's joined with its sub-prefix (with a `/` if
//!   the location's scope doesn't end in one), or, with no sub-prefix,
//!   everything in the location (`s3://bucket/*`).
//! - GetDataAccess's target is a prefix (`s3://bucket/prefix/*`), or an
//!   object's key with `targetType=Object`.

use serde_json::{Value, json};

/// The scheme every scope starts with.
pub const SCHEME: &str = "s3://";

/// What a grant allows: reading, writing (and deleting), or both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission {
    Read,
    Write,
    ReadWrite,
}

impl Permission {
    pub fn parse(text: &str) -> Option<Permission> {
        match text {
            "READ" => Some(Permission::Read),
            "WRITE" => Some(Permission::Write),
            "READWRITE" => Some(Permission::ReadWrite),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Permission::Read => "READ",
            Permission::Write => "WRITE",
            Permission::ReadWrite => "READWRITE",
        }
    }

    /// Whether a grant of this permission covers a request for `asked`.
    pub fn covers(self, asked: Permission) -> bool {
        self == Permission::ReadWrite || self == asked
    }

    fn reads(self) -> bool {
        self != Permission::Write
    }

    fn writes(self) -> bool {
        self != Permission::Read
    }
}

/// What a scope covers: the paths starting with `path`, or (`object`) that
/// path only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Covered {
    pub path: String,
    pub object: bool,
}

impl Covered {
    /// Whether it covers all of `other`.
    pub fn covers(&self, other: &Covered) -> bool {
        match self.object {
            true => other.object && other.path == self.path,
            false => other.path.starts_with(&self.path),
        }
    }

    /// Whether it and `other` cover any path in common.
    pub fn overlaps(&self, other: &Covered) -> bool {
        self.covers(other) || other.covers(self)
    }
}

/// Why a scope isn't one.
pub type Invalid = String;

/// The path below `s3://` of `scope`.
fn path_of(scope: &str) -> Result<&str, Invalid> {
    scope.strip_prefix(SCHEME).ok_or_else(|| format!("The S3 path {scope} must start with {SCHEME}."))
}

/// A wildcard anywhere but at the end.
fn check_wildcards(scope: &str, path: &str) -> Result<(), Invalid> {
    match path.trim_end_matches('*').contains('*') || path.ends_with("**") {
        true => Err(format!("The S3 path {scope} may have a wildcard (*) only at its end.")),
        false => Ok(()),
    }
}

/// Checks a location's scope: `s3://`, then a bucket and maybe a prefix,
/// without wildcards.
pub fn check_location(scope: &str) -> Result<(), Invalid> {
    let path = path_of(scope)?;
    if path.contains('*') {
        return Err(format!("The location scope {scope} may not have a wildcard (*)."));
    }
    if path.starts_with('/') {
        return Err(format!("The location scope {scope} doesn't name a bucket."));
    }
    Ok(())
}

/// What a location's scope covers (see the module's documentation).
pub fn location_covers(scope: &str) -> Covered {
    let path = scope.strip_prefix(SCHEME).unwrap_or(scope);
    let path = match path.is_empty() || path.ends_with('/') {
        true => path.to_owned(),
        false => format!("{path}/"),
    };
    Covered { path, object: false }
}

/// A grant's scope, from its location's and its sub-prefix (checked: a
/// wildcard only at the end; none in an object's).
pub fn grant_scope(location: &str, sub_prefix: Option<&str>, object: bool) -> Result<String, Invalid> {
    let join = |rest: &str| match location.ends_with('/') || location == SCHEME {
        true => format!("{location}{rest}"),
        false => format!("{location}/{rest}"),
    };
    let scope = match sub_prefix {
        None if object => return Err("A grant on an object (S3PrefixType Object) needs its key as its S3SubPrefix.".to_owned()),
        None => join("*"),
        Some(sub) if sub.starts_with('/') => return Err(format!("The S3SubPrefix {sub} may not start with /.")),
        Some(sub) => join(sub),
    };
    check_wildcards(&scope, &scope[SCHEME.len()..])?;
    if object && scope.contains('*') {
        return Err(format!("A grant on an object (S3PrefixType Object) can't have a wildcard (*): {scope}."));
    }
    Ok(scope)
}

/// What a grant's scope (as `grant_scope` made it) covers.
pub fn grant_covers(scope: &str, object: bool) -> Covered {
    let path = scope.strip_prefix(SCHEME).unwrap_or(scope);
    Covered { path: path.strip_suffix('*').unwrap_or(path).to_owned(), object }
}

/// What a request's scope covers: GetDataAccess's target, ListCallerAccessGrants'
/// grant scope. Without a wildcard, a bucket alone (`s3://bucket`) is the
/// whole bucket.
pub fn target_covers(target: &str, object: bool) -> Result<Covered, Invalid> {
    let path = path_of(target)?;
    check_wildcards(target, path)?;
    if object {
        if path.contains('*') || !path.trim_end_matches('/').contains('/') {
            return Err(format!("The target {target} isn't an object's (targetType Object)."));
        }
        return Ok(Covered { path: path.to_owned(), object: true });
    }
    let path = match path.strip_suffix('*') {
        Some(prefix) => prefix.to_owned(),
        None if !path.is_empty() && !path.contains('/') => format!("{path}/"),
        None => path.to_owned(),
    };
    Ok(Covered { path, object: false })
}

/// The S3 actions a vended session may take: on objects, and on buckets
/// (listing). The actions S3's authorization reference gives
/// `s3:AccessGrantsInstanceArn`, split by what they do.
const READ_OBJECT: &[&str] = &["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectAcl", "s3:GetObjectVersionAcl", "s3:ListMultipartUploadParts"];
const READ_BUCKET: &[&str] = &["s3:ListBucket", "s3:ListBucketVersions"];
const WRITE_OBJECT: &[&str] = &[
    "s3:PutObject",
    "s3:PutObjectAcl",
    "s3:PutObjectVersionAcl",
    "s3:DeleteObject",
    "s3:DeleteObjectVersion",
    "s3:AbortMultipartUpload",
    "s3:ListMultipartUploadParts",
];
const WRITE_BUCKET: &[&str] = &["s3:ListBucketMultipartUploads"];

/// `text` as a policy's ARN or condition value matches it literally:
/// `$`, `*` and `?` escaped as policy variables.
fn literal(text: &str) -> String {
    text.replace('$', "${$}").replace('*', "${*}").replace('?', "${?}")
}

/// The session policy of a session vended for `permission` on `covered`:
/// its object actions on the objects it covers, and its listings of what it
/// covers (of nothing, for an object's).
pub fn session_policy(covered: &Covered, permission: Permission) -> String {
    let mut object_actions: Vec<&str> = Vec::new();
    let mut bucket_actions: Vec<&str> = Vec::new();
    if permission.reads() {
        object_actions.extend(READ_OBJECT);
        bucket_actions.extend(READ_BUCKET);
    }
    if permission.writes() {
        object_actions.extend(WRITE_OBJECT.iter().filter(|a| !object_actions.contains(a)).collect::<Vec<_>>());
        bucket_actions.extend(WRITE_BUCKET);
    }
    let objects = match covered.object {
        true => format!("arn:aws:s3:::{}", literal(&covered.path)),
        false => format!("arn:aws:s3:::{}*", literal(&covered.path)),
    };
    let mut statements = vec![json!({"Effect": "Allow", "Action": object_actions, "Resource": objects})];
    if !covered.object {
        let statement: Value = match covered.path.split_once('/') {
            // A prefix of a bucket's keys: its listings of them.
            Some((bucket, prefix)) if !prefix.is_empty() => json!({
                "Effect": "Allow",
                "Action": bucket_actions,
                "Resource": format!("arn:aws:s3:::{}", literal(bucket)),
                "Condition": {"StringLike": {"s3:prefix": format!("{}*", literal(prefix))}},
            }),
            Some((bucket, _)) => json!({"Effect": "Allow", "Action": bucket_actions, "Resource": format!("arn:aws:s3:::{}", literal(bucket))}),
            // Buckets by a prefix of their names (or every bucket).
            None => json!({"Effect": "Allow", "Action": bucket_actions, "Resource": format!("arn:aws:s3:::{}*", literal(&covered.path))}),
        };
        statements.push(statement);
    }
    json!({"Version": "2012-10-17", "Statement": statements}).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Context, Decision, Kind, Policy, Principal, Request};

    fn covered(path: &str, object: bool) -> Covered {
        Covered { path: path.to_owned(), object }
    }

    #[test]
    fn grant_scopes_join_their_locations() {
        assert_eq!(grant_scope("s3://", Some("bucket/logs/*"), false).unwrap(), "s3://bucket/logs/*");
        assert_eq!(grant_scope("s3://", None, false).unwrap(), "s3://*");
        assert_eq!(grant_scope("s3://bucket", None, false).unwrap(), "s3://bucket/*");
        assert_eq!(grant_scope("s3://bucket", Some("a/b*"), false).unwrap(), "s3://bucket/a/b*");
        assert_eq!(grant_scope("s3://bucket/a/", Some("b.txt"), true).unwrap(), "s3://bucket/a/b.txt");
        assert!(grant_scope("s3://bucket", Some("a*/b"), false).is_err());
        assert!(grant_scope("s3://bucket", Some("a**"), false).is_err());
        assert!(grant_scope("s3://bucket", Some("a*"), true).is_err());
        assert!(grant_scope("s3://bucket", None, true).is_err());
        assert!(grant_scope("s3://bucket", Some("/a"), false).is_err());
    }

    #[test]
    fn locations_cover_whole_buckets_and_directories() {
        let bucket = location_covers("s3://bucket");
        assert!(bucket.covers(&covered("bucket/k", false)));
        assert!(!bucket.covers(&covered("bucket2/k", false)));
        assert!(location_covers("s3://").covers(&covered("any/k", true)));
        assert!(!location_covers("s3://b/dir").covers(&covered("b/dirt", false)));
        assert!(check_location("s3://b/*").is_err());
        assert!(check_location("b/x").is_err());
        assert!(check_location("s3://").is_ok());
    }

    #[test]
    fn targets_are_prefixes_or_objects() {
        assert_eq!(target_covers("s3://b/logs/*", false).unwrap(), covered("b/logs/", false));
        assert_eq!(target_covers("s3://b", false).unwrap(), covered("b/", false));
        assert_eq!(target_covers("s3://b/k.txt", true).unwrap(), covered("b/k.txt", true));
        assert!(target_covers("s3://b", true).is_err());
        assert!(target_covers("s3://b/*/x", false).is_err());

        // A grant on a prefix covers what's below it; an object's, itself.
        let logs = grant_covers("s3://b/logs/*", false);
        assert!(logs.covers(&target_covers("s3://b/logs/2026/*", false).unwrap()));
        assert!(logs.covers(&target_covers("s3://b/logs/x", true).unwrap()));
        assert!(!logs.covers(&target_covers("s3://b/*", false).unwrap()));
        let one = grant_covers("s3://b/k.txt", true);
        assert!(one.covers(&target_covers("s3://b/k.txt", true).unwrap()));
        assert!(!one.covers(&target_covers("s3://b/k.txt*", false).unwrap()));
    }

    #[test]
    fn permissions_cover_their_own() {
        assert!(Permission::ReadWrite.covers(Permission::Read));
        assert!(Permission::Read.covers(Permission::Read));
        assert!(!Permission::Read.covers(Permission::Write));
        assert!(!Permission::Write.covers(Permission::ReadWrite));
    }

    fn allows(policy: &Policy, action: &str, resource: &str, prefix: Option<&str>) -> bool {
        let mut context = Context::default();
        if let Some(prefix) = prefix {
            context.set("s3:prefix", prefix);
        }
        let principal = Principal::Session { account: "123456789012", role: "r", id: "x", session: "s" };
        policy.evaluate(&Request { principal, action, resource, context: &context }) == Decision::Allow
    }

    #[test]
    fn session_policies_allow_the_scope_only() {
        let text = session_policy(&covered("b/logs/", false), Permission::Read);
        let policy = Policy::parse(&text, Kind::Identity).unwrap();
        assert!(allows(&policy, "s3:GetObject", "arn:aws:s3:::b/logs/a", None));
        assert!(!allows(&policy, "s3:GetObject", "arn:aws:s3:::b/other", None));
        assert!(!allows(&policy, "s3:PutObject", "arn:aws:s3:::b/logs/a", None));
        assert!(allows(&policy, "s3:ListBucket", "arn:aws:s3:::b", Some("logs/2026")));
        assert!(!allows(&policy, "s3:ListBucket", "arn:aws:s3:::b", Some("other")));
        assert!(!allows(&policy, "s3:ListBucket", "arn:aws:s3:::b", None));

        let text = session_policy(&covered("b/", false), Permission::ReadWrite);
        let policy = Policy::parse(&text, Kind::Identity).unwrap();
        assert!(allows(&policy, "s3:PutObject", "arn:aws:s3:::b/x", None));
        assert!(allows(&policy, "s3:DeleteObject", "arn:aws:s3:::b/x", None));
        assert!(allows(&policy, "s3:ListBucket", "arn:aws:s3:::b", None));
        assert!(!allows(&policy, "s3:ListBucket", "arn:aws:s3:::b2", None));

        // Wildcards in keys are literal.
        let text = session_policy(&covered("b/a*?$c", true), Permission::Write);
        let policy = Policy::parse(&text, Kind::Identity).unwrap();
        assert!(allows(&policy, "s3:PutObject", "arn:aws:s3:::b/a*?$c", None));
        assert!(!allows(&policy, "s3:PutObject", "arn:aws:s3:::b/aXYc", None));
        assert!(!allows(&policy, "s3:GetObject", "arn:aws:s3:::b/a*?$c", None));
        assert!(!allows(&policy, "s3:ListBucketMultipartUploads", "arn:aws:s3:::b", None));

        // Every bucket.
        let text = session_policy(&covered("", false), Permission::Read);
        let policy = Policy::parse(&text, Kind::Identity).unwrap();
        assert!(allows(&policy, "s3:GetObject", "arn:aws:s3:::any/k", None));
        assert!(allows(&policy, "s3:ListBucket", "arn:aws:s3:::any", None));
    }
}
