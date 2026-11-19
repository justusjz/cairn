//! ACLs (see `README.md`, "ACLs"), as S3 has them: a bucket's Object
//! Ownership decides whether they're enabled.
//!
//! - `BucketOwnerEnforced` (new buckets', and every bucket's made before
//!   Cairn had ACLs): disabled. The bucket owner owns everything in it, and
//!   access is a matter of policies alone. A write may ask for no ACL, or a
//!   canned one that gives no one but the bucket owner anything (`private`,
//!   `bucket-owner-read`, `bucket-owner-full-control`; CreateBucket
//!   `private` only); another, or `x-amz-grant-*` grants, is refused, as is
//!   setting one. Reading one shows the owner's full control (probed).
//! - `BucketOwnerPreferred`: enabled; a write that gives the bucket owner
//!   full control (`bucket-owner-full-control`) makes the bucket owner its
//!   object's owner; any other, the writer's account.
//! - `ObjectWriter`, or no ownership controls (deleted): enabled; the
//!   writer's account owns what it writes.
//!
//! An ACL is a list of grants: of a permission (`FULL_CONTROL`, `READ`,
//! `WRITE`, `READ_ACP`, `WRITE_ACP`) to an account (by its canonical ID,
//! `util::canonical_id`) or a group (everyone, any signed request's
//! principal, S3's log delivery). What a grant allows is decided as a
//! bucket policy's statement allowing its actions to its grantee is (see
//! `policy`, and `Acl::policy`), with the bucket's own policy: an account's
//! root by itself, its users if their own policies allow it too.
//!
//! What an object's ACL grants is about its owner's object: when that's
//! another account than the bucket's, the bucket's policy can't allow
//! reading it (only deny), and its owner's ACL is what can (`OWNED`). Its
//! deletion, and writes, are the bucket owner's to allow, as in S3.
//!
//! A version's owner and ACL are stored with it (`objects.owner_id`,
//! `objects.acl`; NULL: the bucket owner, and its full control alone), as
//! the write asks for them (`for_write`, which the catalog reads from the
//! write's context: `cairn_write_acl`); a bucket's are its account and
//! `buckets.acl`. They're kept when ACLs are disabled, which then ignores
//! them, as S3 does: enabling them again brings them back.

use std::collections::HashMap;

use http_body_util::Full;
use hyper::{HeaderMap, Response, StatusCode, body::Bytes};
use serde::{Deserialize, Serialize};

use crate::{
    App,
    db::Cached,
    s3::util::{canonical_id, format_s3_error, xml_escape, xml_ok},
};

/// What an ACL would be set on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum On {
    Object,
    Bucket,
}

/// A bucket's Object Ownership.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ownership {
    /// ACLs disabled.
    Enforced,
    Preferred,
    /// Also a bucket without ownership controls.
    Writer,
}

impl Ownership {
    /// As `buckets.object_ownership` stores it (NULL: none, `ObjectWriter`).
    pub fn from_stored(stored: Option<&str>) -> Ownership {
        match stored {
            Some("BucketOwnerEnforced") => Ownership::Enforced,
            Some("BucketOwnerPreferred") => Ownership::Preferred,
            _ => Ownership::Writer,
        }
    }

    /// Its name, as S3's documents and `buckets.object_ownership` have it.
    pub fn name(self) -> &'static str {
        match self {
            Ownership::Enforced => "BucketOwnerEnforced",
            Ownership::Preferred => "BucketOwnerPreferred",
            Ownership::Writer => "ObjectWriter",
        }
    }

    fn parse(name: &str) -> Option<Ownership> {
        [Ownership::Enforced, Ownership::Preferred, Ownership::Writer].into_iter().find(|o| o.name() == name)
    }

    /// Whether ACLs are enabled.
    pub fn enabled(self) -> bool {
        self != Ownership::Enforced
    }
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

/// The headers that grant a permission, and the permission.
const GRANT_HEADERS: &[(&str, Permission)] = &[
    ("x-amz-grant-full-control", Permission::FullControl),
    ("x-amz-grant-read", Permission::Read),
    ("x-amz-grant-write", Permission::Write),
    ("x-amz-grant-read-acp", Permission::ReadAcp),
    ("x-amz-grant-write-acp", Permission::WriteAcp),
];

/// The most grants an ACL has, as in S3.
const MAX_GRANTS: usize = 100;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Permission {
    #[serde(rename = "FULL_CONTROL")]
    FullControl,
    #[serde(rename = "READ")]
    Read,
    #[serde(rename = "WRITE")]
    Write,
    #[serde(rename = "READ_ACP")]
    ReadAcp,
    #[serde(rename = "WRITE_ACP")]
    WriteAcp,
}

impl Permission {
    fn name(self) -> &'static str {
        match self {
            Permission::FullControl => "FULL_CONTROL",
            Permission::Read => "READ",
            Permission::Write => "WRITE",
            Permission::ReadAcp => "READ_ACP",
            Permission::WriteAcp => "WRITE_ACP",
        }
    }

    fn parse(name: &str) -> Option<Permission> {
        GRANT_HEADERS.iter().map(|(_, p)| *p).find(|p| p.name() == name)
    }

    /// The actions it allows on a bucket (`bucket`'s, and those on its
    /// objects: `objects`), or on an object, as S3's user guide maps them.
    fn actions(self, on: On) -> (&'static [&'static str], &'static [&'static str]) {
        match (on, self) {
            (On::Bucket, Permission::Read) => {
                (&["s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads"], &[])
            }
            // Writing objects, and deleting them: the bucket's, whoever owns
            // them.
            (On::Bucket, Permission::Write) => (&[], &["s3:PutObject", "s3:DeleteObject"]),
            (On::Bucket, Permission::ReadAcp) => (&["s3:GetBucketAcl"], &[]),
            (On::Bucket, Permission::WriteAcp) => (&["s3:PutBucketAcl"], &[]),
            (On::Bucket, Permission::FullControl) => (
                &["s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads", "s3:GetBucketAcl", "s3:PutBucketAcl"],
                &["s3:PutObject", "s3:DeleteObject"],
            ),
            (On::Object, Permission::Read) => (&[], &["s3:GetObject", "s3:GetObjectVersion"]),
            (On::Object, Permission::Write) => (&[], &[]),
            (On::Object, Permission::ReadAcp) => (&[], &["s3:GetObjectAcl", "s3:GetObjectVersionAcl"]),
            (On::Object, Permission::WriteAcp) => (&[], &["s3:PutObjectAcl", "s3:PutObjectVersionAcl"]),
            (On::Object, Permission::FullControl) => (
                &[],
                &[
                    "s3:GetObject",
                    "s3:GetObjectVersion",
                    "s3:GetObjectAcl",
                    "s3:GetObjectVersionAcl",
                    "s3:PutObjectAcl",
                    "s3:PutObjectVersionAcl",
                ],
            ),
        }
    }
}

/// The actions on an object that are about its owner's object, which the
/// owner's ACL (and policies) decide, not the bucket's, when the two owners
/// differ (see the module's doc).
pub const OWNED: &[&str] = &[
    "s3:GetObject",
    "s3:GetObjectVersion",
    "s3:GetObjectAcl",
    "s3:GetObjectVersionAcl",
    "s3:PutObjectAcl",
    "s3:PutObjectVersionAcl",
    "s3:GetObjectTagging",
    "s3:GetObjectVersionTagging",
    "s3:GetObjectAttributes",
    "s3:GetObjectVersionAttributes",
];

/// S3's predefined groups.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Group {
    /// Everyone, anonymous requests too.
    AllUsers,
    /// Any signed request's principal, of any account.
    AuthenticatedUsers,
    /// S3's server access log delivery (`logging.s3.amazonaws.com`).
    LogDelivery,
}

impl Group {
    const ALL: [Group; 3] = [Group::AllUsers, Group::AuthenticatedUsers, Group::LogDelivery];

    pub fn uri(self) -> &'static str {
        match self {
            Group::AllUsers => "http://acs.amazonaws.com/groups/global/AllUsers",
            Group::AuthenticatedUsers => "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
            Group::LogDelivery => "http://acs.amazonaws.com/groups/s3/LogDelivery",
        }
    }

    fn from_uri(uri: &str) -> Option<Group> {
        Group::ALL.into_iter().find(|g| g.uri() == uri)
    }

    /// Whether a grant to it makes what it's on public.
    fn public(self) -> bool {
        matches!(self, Group::AllUsers | Group::AuthenticatedUsers)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Grantee {
    /// An account, by its ID.
    Account(String),
    Group(Group),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Grant {
    pub grantee: Grantee,
    pub permission: Permission,
}

/// An ACL's grants.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Acl {
    pub grants: Vec<Grant>,
}

/// A refused request's response.
type Refused = Response<Full<Bytes>>;

impl Acl {
    /// `owner`'s full control alone: what a bucket or object has unless it's
    /// given another.
    pub fn private(owner: &str) -> Acl {
        Acl { grants: vec![Grant { grantee: Grantee::Account(owner.to_owned()), permission: Permission::FullControl }] }
    }

    /// As stored (`buckets.acl`, `objects.acl`): NULL is `owner`'s full
    /// control alone. One that doesn't read (a newer Cairn's) is none, which
    /// grants no one but the owner anything.
    pub fn from_stored(stored: Option<&str>, owner: &str) -> Acl {
        match stored {
            None => Acl::private(owner),
            Some(text) => Acl { grants: serde_json::from_str(text).unwrap_or_default() },
        }
    }

    /// As it's stored: `None` if it's `owner`'s full control alone.
    pub fn stored(&self, owner: &str) -> Option<String> {
        (*self != Acl::private(owner)).then(|| serde_json::to_string(&self.grants).expect("grants serialize"))
    }

    /// The canned ACL `name` (a known one: see `CANNED`), on a bucket or an
    /// object owned by `owner`, in a bucket owned by `bucket_owner`.
    fn canned(name: &str, on: On, owner: &str, bucket_owner: &str) -> Acl {
        let mut acl = Acl::private(owner);
        let mut grant = |grantee, permission| acl.grants.push(Grant { grantee, permission });
        let all = Grantee::Group(Group::AllUsers);
        match name {
            "public-read" => grant(all, Permission::Read),
            "public-read-write" => {
                grant(all.clone(), Permission::Read);
                grant(all, Permission::Write);
            }
            "authenticated-read" => grant(Grantee::Group(Group::AuthenticatedUsers), Permission::Read),
            "log-delivery-write" => {
                grant(Grantee::Group(Group::LogDelivery), Permission::Write);
                grant(Grantee::Group(Group::LogDelivery), Permission::ReadAcp);
            }
            // The bucket owner's, on an object (a bucket's ignores them, as
            // S3's does), if it isn't the object's owner already.
            "bucket-owner-read" if on == On::Object && owner != bucket_owner => {
                grant(Grantee::Account(bucket_owner.to_owned()), Permission::Read)
            }
            "bucket-owner-full-control" if on == On::Object && owner != bucket_owner => {
                grant(Grantee::Account(bucket_owner.to_owned()), Permission::FullControl)
            }
            // `aws-exec-read` gives EC2 its AMIs' bundles; Cairn has no EC2.
            _ => {}
        }
        acl
    }

    /// Whether it grants anything to everyone, or to any signed request.
    pub fn is_public(&self) -> bool {
        self.grants.iter().any(|g| matches!(g.grantee, Grantee::Group(group) if group.public()))
    }

    /// Whether it grants anyone but `owner` anything.
    pub fn grants_others(&self, owner: &str) -> bool {
        self.grants.iter().any(|g| g.grantee != Grantee::Account(owner.to_owned()))
    }

    /// What it allows, as a bucket policy of `bucket` (its text): on the
    /// bucket and its objects (`On::Bucket`), or on an object of its
    /// (`On::Object`), owned by `owner`, whose grants to itself go without
    /// saying. Without its public grants, if `ignore_public`
    /// (IgnorePublicAcls). `None` if it allows no one else anything.
    pub fn policy(&self, on: On, bucket: &str, owner: &str, ignore_public: bool) -> Option<String> {
        use serde_json::json;
        let mut statements = Vec::new();
        for grant in &self.grants {
            let mut condition = None;
            let principal = match &grant.grantee {
                Grantee::Account(account) if account == owner => continue,
                Grantee::Account(account) => json!({ "AWS": format!("arn:aws:iam::{account}:root") }),
                Grantee::Group(group) if ignore_public && group.public() => continue,
                Grantee::Group(Group::AllUsers) => json!("*"),
                Grantee::Group(Group::AuthenticatedUsers) => {
                    condition = Some(json!({ "StringNotEquals": { "aws:PrincipalType": "Anonymous" } }));
                    json!("*")
                }
                Grantee::Group(Group::LogDelivery) => json!({ "Service": crate::access_log::SERVICE }),
            };
            let (on_bucket, on_objects) = grant.permission.actions(on);
            for (actions, resource) in [(on_bucket, format!("arn:aws:s3:::{bucket}")), (on_objects, format!("arn:aws:s3:::{bucket}/*"))] {
                if actions.is_empty() {
                    continue;
                }
                let mut statement = json!({ "Effect": "Allow", "Principal": principal, "Action": actions, "Resource": resource });
                if let Some(condition) = &condition {
                    statement["Condition"] = condition.clone();
                }
                statements.push(statement);
            }
        }
        (!statements.is_empty()).then(|| json!({ "Version": "2012-10-17", "Statement": statements }).to_string())
    }

    /// It as S3's `<AccessControlPolicy>`, of what `owner` owns.
    pub fn xml(&self, owner: &str) -> String {
        let mut grants = String::new();
        for grant in &self.grants {
            let grantee = match &grant.grantee {
                Grantee::Account(account) => format!("xsi:type=\"CanonicalUser\"><ID>{}</ID>", canonical_id(account)),
                Grantee::Group(group) => format!("xsi:type=\"Group\"><URI>{}</URI>", group.uri()),
            };
            grants.push_str(&format!(
                "<Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" {grantee}</Grantee>\
                 <Permission>{}</Permission></Grant>",
                grant.permission.name()
            ));
        }
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Owner><ID>{}</ID></Owner><AccessControlList>{grants}</AccessControlList>\
             </AccessControlPolicy>",
            canonical_id(owner)
        )
    }
}

/// The accounts grants may name, by their canonical IDs (and their own).
pub struct Accounts(HashMap<String, String>);

impl Accounts {
    pub async fn load(client: &deadpool_postgres::Object) -> anyhow::Result<Accounts> {
        let rows = client.query_cached("SELECT id FROM accounts WHERE NOT internal", &[]).await?;
        let mut by_id = HashMap::new();
        for row in rows {
            let id: String = row.get(0);
            by_id.insert(canonical_id(&id), id.clone());
            by_id.insert(id.clone(), id);
        }
        Ok(Accounts(by_id))
    }

    #[cfg(test)]
    pub fn of(ids: &[&str]) -> Accounts {
        Accounts(ids.iter().flat_map(|id| [(canonical_id(id), id.to_string()), (id.to_string(), id.to_string())]).collect())
    }

    /// The account a grant names by `id`: its canonical ID, or (Cairn's
    /// own leniency) its account ID.
    fn resolve(&self, id: &str) -> Result<String, Refused> {
        self.0.get(id).cloned().ok_or_else(|| invalid_argument("Invalid id", "CanonicalUser/ID", id))
    }
}

fn invalid_argument(message: &str, name: &str, value: &str) -> Refused {
    let mut rejection = crate::auth::Rejection::new(StatusCode::BAD_REQUEST, "InvalidArgument", message);
    rejection.details.push(("ArgumentName", name.to_owned()));
    rejection.details.push(("ArgumentValue", value.to_owned()));
    crate::s3::util::rejection_response(&rejection)
}

fn malformed() -> Refused {
    format_s3_error(
        StatusCode::BAD_REQUEST,
        "MalformedACLError",
        "The XML you provided was not well-formed or did not validate against our published schema",
    )
}

fn no_such_email() -> Refused {
    format_s3_error(
        StatusCode::BAD_REQUEST,
        "UnresolvableGrantByEmailAddress",
        "The e-mail address you provided does not match any account on record.",
    )
}

fn grantee(kind: &str, value: &str, accounts: &Accounts) -> Result<Grantee, Refused> {
    match kind {
        "id" | "CanonicalUser" => Ok(Grantee::Account(accounts.resolve(value)?)),
        "uri" | "Group" => Group::from_uri(value).map(Grantee::Group).ok_or_else(|| invalid_argument("Invalid group uri", "uri", value)),
        // Cairn's accounts have no e-mail addresses.
        "emailAddress" | "AmazonCustomerByEmail" => Err(no_such_email()),
        _ => Err(invalid_argument("Argument format not recognized", kind, value)),
    }
}

/// The grantees of an `x-amz-grant-*` header: `id="…"`, `uri="…"` or
/// `emailAddress="…"`, separated by commas.
fn header_grantees(name: &str, value: &str, accounts: &Accounts) -> Result<Vec<Grantee>, Refused> {
    let mut grantees = Vec::new();
    let mut rest = value.trim();
    while !rest.is_empty() {
        let Some((kind, after)) = rest.split_once('=') else {
            return Err(invalid_argument("Argument format not recognized", name, value));
        };
        let after = after.trim_start();
        let (item, next) = match after.strip_prefix('"') {
            Some(quoted) => {
                let Some((item, next)) = quoted.split_once('"') else {
                    return Err(invalid_argument("Argument format not recognized", name, value));
                };
                (item, next)
            }
            None => after.split_once(',').map_or((after, ""), |(item, next)| (item, next)),
        };
        grantees.push(grantee(kind.trim(), item.trim(), accounts)?);
        rest = next.trim_start();
        rest = rest.strip_prefix(',').unwrap_or(rest).trim_start();
    }
    Ok(grantees)
}

/// What a request's headers ask for: a canned ACL, or grants; `None` if
/// they ask for neither. Grants name accounts `accounts` has.
enum Asked {
    Canned(String),
    Grants(Vec<Grant>),
}

fn asked(headers: &HeaderMap, accounts: Option<&Accounts>) -> Result<Option<Asked>, Refused> {
    let canned = headers.get("x-amz-acl").map(|v| String::from_utf8_lossy(v.as_bytes()).trim().to_owned());
    let granting: Vec<_> = GRANT_HEADERS.iter().filter(|(name, _)| headers.contains_key(*name)).collect();
    match (canned, granting.is_empty()) {
        (Some(_), false) => Err(format_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "Specifying both Canned ACLs and Header Grants is not allowed",
        )),
        (Some(canned), true) if !CANNED.contains(&canned.as_str()) => Err(invalid_argument("", "x-amz-acl", &canned)),
        (Some(canned), true) => Ok(Some(Asked::Canned(canned))),
        (None, true) => Ok(None),
        (None, false) => {
            let accounts = accounts.expect("grants are read with the accounts");
            let mut grants = Vec::new();
            for (name, permission) in granting {
                for value in headers.get_all(*name) {
                    let value = String::from_utf8_lossy(value.as_bytes());
                    for grantee in header_grantees(name, &value, accounts)? {
                        grants.push(Grant { grantee, permission: *permission });
                    }
                }
            }
            if grants.len() > MAX_GRANTS {
                return Err(malformed());
            }
            Ok(Some(Asked::Grants(grants)))
        }
    }
}

/// Whether headers grant anything (`x-amz-grant-*`), which takes the
/// accounts to read.
fn has_grants(headers: &HeaderMap) -> bool {
    GRANT_HEADERS.iter().any(|(name, _)| headers.contains_key(*name))
}

/// The accounts, if `headers` grant anything.
async fn accounts_for(app: &App, headers: &HeaderMap) -> anyhow::Result<Option<Accounts>> {
    Ok(match has_grants(headers) {
        true => Some(Accounts::load(&app.pool.get().await?).await?),
        false => None,
    })
}

fn elements<'a, 'i>(node: roxmltree::Node<'a, 'i>) -> Vec<roxmltree::Node<'a, 'i>> {
    node.children().filter(|n| n.is_element()).collect()
}

/// The text of `node`'s child `name`, if it has one.
fn text_of(node: roxmltree::Node<'_, '_>, name: &str) -> Option<String> {
    node.children().find(|n| n.is_element() && n.tag_name().name() == name).map(|n| n.text().unwrap_or("").trim().to_owned())
}

/// An `<AccessControlPolicy>` document's owner (its canonical ID, if it
/// names one) and ACL.
fn from_xml(body: &[u8], accounts: &Accounts) -> Result<(Option<String>, Acl), Refused> {
    const XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";
    let text = std::str::from_utf8(body).map_err(|_| malformed())?;
    let doc = roxmltree::Document::parse(text).map_err(|_| malformed())?;
    let root = doc.root_element();
    if root.tag_name().name() != "AccessControlPolicy" {
        return Err(malformed());
    }
    let mut owner = None;
    let mut acl = Acl::default();
    for child in elements(root) {
        match child.tag_name().name() {
            "Owner" => owner = text_of(child, "ID"),
            "AccessControlList" => {
                for grant in elements(child) {
                    if grant.tag_name().name() != "Grant" {
                        return Err(malformed());
                    }
                    let Some(node) = grant.children().find(|n| n.is_element() && n.tag_name().name() == "Grantee") else {
                        return Err(malformed());
                    };
                    let permission = text_of(grant, "Permission").and_then(|p| Permission::parse(&p)).ok_or_else(malformed)?;
                    // By its type; else by what it has.
                    let kind = node.attribute((XSI, "type")).map(str::to_owned).or_else(|| {
                        ["ID", "URI", "EmailAddress"].into_iter().find(|n| text_of(node, n).is_some()).map(|n| {
                            match n {
                                "ID" => "CanonicalUser",
                                "URI" => "Group",
                                _ => "AmazonCustomerByEmail",
                            }
                            .to_owned()
                        })
                    });
                    let value = match kind.as_deref() {
                        Some("CanonicalUser") => text_of(node, "ID"),
                        Some("Group") => text_of(node, "URI"),
                        Some("AmazonCustomerByEmail") => text_of(node, "EmailAddress"),
                        _ => None,
                    };
                    let (Some(kind), Some(value)) = (kind, value) else { return Err(malformed()) };
                    acl.grants.push(Grant { grantee: grantee(&kind, &value, accounts)?, permission });
                }
            }
            _ => return Err(malformed()),
        }
    }
    if acl.grants.len() > MAX_GRANTS {
        return Err(malformed());
    }
    Ok((owner, acl))
}

/// A bucket, as its ACLs see it.
pub struct Bucket {
    /// The account that owns it.
    pub owner: String,
    pub ownership: Ownership,
    /// Whether it has ownership controls (not deleted).
    pub controlled: bool,
    pub stored: Option<String>,
    /// BlockPublicAcls, its own or its account's.
    pub block_public: bool,
}

impl Bucket {
    pub async fn load(client: &deadpool_postgres::Object, bucket: &str) -> anyhow::Result<Option<Bucket>> {
        let row = client
            .query_opt_cached(
                "SELECT b.account_id, b.object_ownership, b.acl,
                        (coalesce(b.public_access_block, 0) | coalesce(a.public_access_block, 0))::smallint
                 FROM buckets b JOIN accounts a ON a.id = b.account_id WHERE b.name = $1",
                &[&bucket],
            )
            .await?;
        Ok(row.map(|row| {
            let ownership: Option<String> = row.get(1);
            let bits: i16 = row.get(3);
            Bucket {
                owner: row.get(0),
                ownership: Ownership::from_stored(ownership.as_deref()),
                controlled: ownership.is_some(),
                stored: row.get(2),
                block_public: bits & 1 != 0,
            }
        }))
    }

    pub fn acl(&self) -> Acl {
        Acl::from_stored(self.stored.as_deref(), &self.owner)
    }
}

fn no_such_bucket() -> Refused {
    format_s3_error(StatusCode::NOT_FOUND, "NoSuchBucket", "The specified bucket does not exist")
}

fn not_supported() -> Refused {
    format_s3_error(StatusCode::BAD_REQUEST, "AccessControlListNotSupported", "The bucket does not allow ACLs")
}

fn with_enforced() -> Refused {
    format_s3_error(
        StatusCode::BAD_REQUEST,
        "InvalidBucketAclWithObjectOwnership",
        "Bucket cannot have ACLs set with ObjectOwnership's BucketOwnerEnforced setting",
    )
}

/// What BlockPublicAcls answers a public ACL, as S3 does.
fn blocked() -> Refused {
    format_s3_error(StatusCode::FORBIDDEN, "AccessDenied", "Access Denied")
}

/// Refuses a write (PutObject, CreateMultipartUpload, CopyObject, or, `On::Bucket`,
/// CreateBucket) to a bucket with ACLs disabled that asks for an ACL other
/// than the owner's only.
pub fn check_write(headers: &HeaderMap, on: On) -> Result<(), Refused> {
    let grants = has_grants(headers);
    let canned = headers.get("x-amz-acl").map(|v| String::from_utf8_lossy(v.as_bytes()).trim().to_owned());
    if on == On::Object
        && let Some(acl) = canned.as_deref().filter(|acl| !CANNED.contains(acl))
    {
        return Err(invalid_argument("", "x-amz-acl", acl));
    }
    let owner_only: &[&str] = match on {
        On::Object => &["private", "bucket-owner-read", "bucket-owner-full-control"],
        On::Bucket => &["private"],
    };
    if !grants && canned.as_deref().is_none_or(|acl| owner_only.contains(&acl)) {
        return Ok(());
    }
    Err(match on {
        On::Object => not_supported(),
        On::Bucket => with_enforced(),
    })
}

/// The owner and ACL an object write (PutObject, POST Object, CopyObject,
/// CreateMultipartUpload) of `writer`'s (an account; `None`: anonymous) to
/// `bucket` gives its object, as its headers ask for them, for
/// `notifications::set_acl`: `None` if it's the bucket owner's, with its
/// full control alone (as every write to a bucket with ACLs disabled is).
/// Refused if the bucket has them disabled and it asks for another, or it
/// asks for a public one that BlockPublicAcls blocks.
pub async fn for_write(
    app: &App,
    bucket: &str,
    writer: Option<&str>,
    headers: &HeaderMap,
) -> anyhow::Result<Result<Option<(String, Option<String>)>, Refused>> {
    let client = app.pool.get().await?;
    let loaded = match Bucket::load(&client, bucket).await? {
        // A missing bucket is refused where it's written.
        Some(loaded) if loaded.ownership.enabled() => loaded,
        _ => return Ok(check_write(headers, On::Object).map(|()| None)),
    };
    drop(client);
    let accounts = accounts_for(app, headers).await?;
    let asked = match asked(headers, accounts.as_ref()) {
        Ok(asked) => asked,
        Err(refused) => return Ok(Err(refused)),
    };
    // An anonymous write's object is the bucket owner's (S3's would be its
    // anonymous user's).
    let writer = writer.unwrap_or(&loaded.owner);
    let owner = match (&loaded.ownership, &asked) {
        (Ownership::Preferred, Some(Asked::Canned(canned))) if canned == "bucket-owner-full-control" => &loaded.owner,
        _ => writer,
    };
    let acl = match asked {
        Some(Asked::Canned(canned)) => Acl::canned(&canned, On::Object, owner, &loaded.owner),
        Some(Asked::Grants(grants)) => Acl { grants },
        None => Acl::private(owner),
    };
    if loaded.block_public && acl.is_public() {
        return Ok(Err(blocked()));
    }
    let stored = acl.stored(owner);
    Ok(Ok((owner != loaded.owner || stored.is_some()).then(|| (owner.to_owned(), stored))))
}

/// A new bucket's Object Ownership (`x-amz-object-ownership`; else
/// `BucketOwnerEnforced`) and ACL (as stored), as CreateBucket's headers
/// ask for them, of `owner`'s. New buckets block public access, so a
/// public ACL is refused, as S3 refuses it.
pub async fn for_bucket(app: &App, owner: &str, headers: &HeaderMap) -> anyhow::Result<Result<(Ownership, Option<String>), Refused>> {
    let ownership = match headers.get("x-amz-object-ownership").map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned()) {
        None => Ownership::Enforced,
        Some(name) => match Ownership::parse(&name) {
            Some(ownership) => ownership,
            None => {
                return Ok(Err(invalid_argument(
                    &format!("Invalid x-amz-object-ownership header: {name}"),
                    "x-amz-object-ownership",
                    &name,
                )));
            }
        },
    };
    if !ownership.enabled() {
        return Ok(check_write(headers, On::Bucket).map(|()| (ownership, None)));
    }
    let accounts = accounts_for(app, headers).await?;
    let acl = match asked(headers, accounts.as_ref()) {
        Err(refused) => return Ok(Err(refused)),
        Ok(Some(Asked::Canned(canned))) => Acl::canned(&canned, On::Bucket, owner, owner),
        Ok(Some(Asked::Grants(grants))) => Acl { grants },
        Ok(None) => Acl::private(owner),
    };
    if acl.is_public() {
        return Ok(Err(format_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidBucketAclWithBlockPublicAccessError",
            "Bucket cannot have public ACLs set with BlockPublicAccess enabled",
        )));
    }
    Ok(Ok((ownership, acl.stored(owner))))
}

/// The ACL a PutBucketAcl or PutObjectAcl sets, on what `owner` owns in a
/// bucket `bucket_owner` owns: its headers' or its body's, not both.
fn to_set(headers: &HeaderMap, body: &[u8], on: On, owner: &str, bucket_owner: &str, accounts: &Accounts) -> Result<Acl, Refused> {
    let from_headers = asked(headers, Some(accounts))?;
    let has_body = !body.iter().all(u8::is_ascii_whitespace);
    match (from_headers, has_body) {
        (Some(_), true) => Err(format_s3_error(StatusCode::BAD_REQUEST, "UnexpectedContent", "This request does not support content")),
        (Some(Asked::Canned(canned)), false) => Ok(Acl::canned(&canned, on, owner, bucket_owner)),
        (Some(Asked::Grants(grants)), false) => Ok(Acl { grants }),
        (None, false) => Err(format_s3_error(
            StatusCode::BAD_REQUEST,
            "MissingSecurityHeader",
            "Your request was missing a required header",
        )),
        (None, true) => {
            let (named, acl) = from_xml(body, accounts)?;
            // The owner it names must be the owner.
            if named.is_some_and(|named| named != canonical_id(owner) && named != owner) {
                return Err(format_s3_error(StatusCode::FORBIDDEN, "AccessDenied", "Access Denied"));
            }
            Ok(acl)
        }
    }
}

/// GetBucketAcl: its ACL, or, with ACLs disabled, its owner's full
/// control.
pub async fn get_bucket_acl(app: &App, bucket: &str) -> anyhow::Result<Refused> {
    let client = app.pool.get().await?;
    Ok(match Bucket::load(&client, bucket).await? {
        None => no_such_bucket(),
        Some(loaded) if !loaded.ownership.enabled() => xml_ok(Acl::private(&loaded.owner).xml(&loaded.owner)),
        Some(loaded) => xml_ok(loaded.acl().xml(&loaded.owner)),
    })
}

/// PutBucketAcl: sets its ACL, from the headers or the body; refused with
/// ACLs disabled, whatever it asks for (probed: the owner's only too).
pub async fn put_bucket_acl(app: &App, bucket: &str, headers: &HeaderMap, body: &[u8]) -> anyhow::Result<Refused> {
    let client = app.pool.get().await?;
    let loaded = match Bucket::load(&client, bucket).await? {
        None => return Ok(no_such_bucket()),
        Some(loaded) if !loaded.ownership.enabled() => return Ok(not_supported()),
        Some(loaded) => loaded,
    };
    let accounts = Accounts::load(&client).await?;
    let acl = match to_set(headers, body, On::Bucket, &loaded.owner, &loaded.owner, &accounts) {
        Ok(acl) => acl,
        Err(refused) => return Ok(refused),
    };
    if loaded.block_public && acl.is_public() {
        return Ok(blocked());
    }
    // As T21's: a plain UPDATE of the bucket's row.
    client
        .execute_cached("UPDATE buckets SET acl = $2 WHERE name = $1", &[&bucket, &acl.stored(&loaded.owner)])
        .await?;
    Ok(Response::builder().status(StatusCode::OK).body(Full::new(Bytes::new())).unwrap())
}

/// A version's owner and stored ACL, if it's there: `Err` with the
/// response its absence gets (404, a delete marker's 405, ...).
async fn version(
    client: &deadpool_postgres::Object,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
) -> anyhow::Result<Result<(Option<String>, Option<String>, Option<String>), Refused>> {
    let found = match crate::s3::objects::get::lookup_version(client, bucket, key, version_id).await? {
        Ok(found) => found,
        Err(missing) => return Ok(Err(missing.read_response())),
    };
    let row = client.query_one_cached("SELECT owner_id, acl, version_id FROM objects WHERE id = $1", &[&found.id]).await?;
    Ok(Ok((row.get(0), row.get(1), row.get(2))))
}

/// The owner and ACL of the version of `key` named `version_id` (else its
/// latest), for its checks (see `access`), if `bucket` has ACLs enabled,
/// and it's there and not a delete marker.
pub async fn version_acl(app: &App, bucket: &str, key: &str, version_id: Option<&str>) -> anyhow::Result<Option<(String, Acl)>> {
    let client = app.pool.get().await?;
    let Some(loaded) = Bucket::load(&client, bucket).await?.filter(|b| b.ownership.enabled()) else {
        return Ok(None);
    };
    let row = client
        .query_opt_cached(
            "SELECT owner_id, acl FROM objects
             WHERE bucket = $1 AND key = $2 AND NOT is_delete_marker
               AND CASE WHEN $3::text IS NULL THEN is_latest ELSE version_id = $3 END",
            &[&bucket, &key, &version_id],
        )
        .await?;
    Ok(row.map(|row| {
        let owner = row.get::<_, Option<String>>(0).unwrap_or_else(|| loaded.owner.clone());
        let acl = Acl::from_stored(row.get(1), &owner);
        (owner, acl)
    }))
}

/// The operations on an existing version, whose checks its owner and ACL
/// decide (see `OWNED`).
const ON_EXISTING: &[&str] = &["GetObject", "HeadObject", "GetObjectAttributes", "GetObjectAcl", "PutObjectAcl", "GetObjectTagging"];

/// Sets the owners and ACLs of the versions `operation` is on in `access`
/// (whose checks' buckets are loaded): the one it reads or annotates, and a
/// copy's source, if their buckets have ACLs enabled.
pub async fn prepare(
    app: &App,
    access: &mut crate::s3::access::Access,
    operation: &crate::s3::actions::Operation,
    bucket: &str,
    key: &str,
    query: &str,
    headers: &HeaderMap,
) -> anyhow::Result<()> {
    let mut existing = Vec::new();
    if ON_EXISTING.contains(&operation.name) {
        existing.push((bucket.to_owned(), key.to_owned(), crate::s3::util::query_param(query, "versionId")));
    }
    if matches!(operation.name, "CopyObject" | "UploadPartCopy")
        && let Some(source) = headers.get("x-amz-copy-source").and_then(|v| v.to_str().ok())
        && let Some(source) = crate::s3::objects::copy::parse_copy_source(source)
    {
        existing.push(source);
    }
    for (bucket, key, version_id) in existing {
        if !access.acls_enabled(&bucket) {
            continue;
        }
        if let Some((owner, acl)) = version_acl(app, &bucket, &key, version_id.as_deref()).await? {
            access.set_object_acl(&bucket, &key, &owner, &acl)?;
        }
    }
    Ok(())
}

/// The version ID header of an object ACL's response.
fn with_version(response: Refused, version_id: Option<&str>) -> Refused {
    crate::s3::util::with_version_id(response, version_id.filter(|v| *v != "null"))
}

/// GetObjectAcl: the version's ACL, or, with ACLs disabled, its bucket
/// owner's full control; a missing one's 404, or a delete marker's, as S3's
/// (probed).
pub async fn get_object_acl(app: &App, bucket: &str, key: &str, version_id: Option<&str>) -> anyhow::Result<Refused> {
    let client = app.pool.get().await?;
    let Some(loaded) = Bucket::load(&client, bucket).await? else { return Ok(no_such_bucket()) };
    let (owner, stored, version) = match version(&client, bucket, key, version_id).await? {
        Ok(found) => found,
        Err(missing) => return Ok(missing),
    };
    if !loaded.ownership.enabled() {
        return Ok(xml_ok(Acl::private(&loaded.owner).xml(&loaded.owner)));
    }
    let owner = owner.unwrap_or(loaded.owner);
    let acl = Acl::from_stored(stored.as_deref(), &owner);
    Ok(with_version(xml_ok(acl.xml(&owner)), version.as_deref()))
}

/// PutObjectAcl: sets the version's ACL, from the headers or the body;
/// refused with ACLs disabled, whatever it asks for (probed: the owner's
/// only too), once the version's found (404 otherwise).
pub async fn put_object_acl(
    app: &App,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    headers: &HeaderMap,
    body: &[u8],
) -> anyhow::Result<Refused> {
    let client = app.pool.get().await?;
    let Some(loaded) = Bucket::load(&client, bucket).await? else { return Ok(no_such_bucket()) };
    let owner = match version(&client, bucket, key, version_id).await? {
        Ok((owner, _, _)) => owner.unwrap_or_else(|| loaded.owner.clone()),
        Err(missing) => return Ok(missing),
    };
    if !loaded.ownership.enabled() {
        return Ok(not_supported());
    }
    let accounts = Accounts::load(&client).await?;
    let acl = match to_set(headers, body, On::Object, &owner, &loaded.owner, &accounts) {
        Ok(acl) => acl,
        Err(refused) => return Ok(refused),
    };
    if loaded.block_public && acl.is_public() {
        return Ok(blocked());
    }
    let notify = crate::notifications::delete_context();
    let row = client
        .query_one_cached(
            "SELECT status, version_id FROM pg_temp.cairn_set_acl($1, $2, $3, $4, $5)",
            &[&bucket, &key, &version_id, &acl.stored(&owner), &notify],
        )
        .await?;
    let status: String = row.get(0);
    let version: Option<String> = row.get(1);
    Ok(match status.as_str() {
        "set" => with_version(Response::builder().status(StatusCode::OK).body(Full::new(Bytes::new())).unwrap(), version.as_deref()),
        // Gone meanwhile: as if it had been before.
        _ => match self::version(&client, bucket, key, version_id).await? {
            Err(missing) => missing,
            Ok(_) => anyhow::bail!("cairn_set_acl answered {status}"),
        },
    })
}

/// GetBucketOwnershipControls: its Object Ownership; 404 if it has no
/// controls.
pub async fn get_ownership_controls(app: &App, bucket: &str) -> anyhow::Result<Refused> {
    let client = app.pool.get().await?;
    Ok(match Bucket::load(&client, bucket).await? {
        None => no_such_bucket(),
        Some(loaded) if !loaded.controlled => format_s3_error(
            StatusCode::NOT_FOUND,
            "OwnershipControlsNotFoundError",
            "The bucket ownership controls were not found",
        ),
        Some(loaded) => xml_ok(format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <OwnershipControls xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Rule><ObjectOwnership>{}</ObjectOwnership></Rule>\
             </OwnershipControls>",
            loaded.ownership.name()
        )),
    })
}

/// A `<OwnershipControls>` document's Object Ownership; `None` if it isn't
/// one (S3's MalformedXML, probed).
fn parse_ownership(body: &[u8]) -> Option<Ownership> {
    let text = std::str::from_utf8(body).ok()?;
    let doc = roxmltree::Document::parse(text).ok()?;
    let root = doc.root_element();
    if root.tag_name().name() != "OwnershipControls" {
        return None;
    }
    let rules: Vec<_> = root.children().filter(|n| n.is_element()).collect();
    let [rule] = rules[..] else { return None };
    let values: Vec<_> = rule.children().filter(|n| n.is_element()).collect();
    match (rule.tag_name().name(), &values[..]) {
        ("Rule", [value]) if value.tag_name().name() == "ObjectOwnership" => Ownership::parse(value.text()?.trim()),
        _ => None,
    }
}

/// PutBucketOwnershipControls (`Some`, its body) and
/// DeleteBucketOwnershipControls (`None`). Disabling ACLs is refused while
/// the bucket's ACL grants anyone but its owner anything, as in S3; its
/// objects' are ignored from then on.
pub async fn set_ownership_controls(app: &App, bucket: &str, body: Option<&[u8]>) -> anyhow::Result<Refused> {
    let ownership = match body.map(parse_ownership) {
        Some(None) => {
            return Ok(format_s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "The XML you provided was not well-formed or did not validate against our published schema",
            ));
        }
        Some(Some(ownership)) => Some(ownership),
        None => None,
    };
    let client = app.pool.get().await?;
    let Some(loaded) = Bucket::load(&client, bucket).await? else { return Ok(no_such_bucket()) };
    if ownership == Some(Ownership::Enforced) && loaded.acl().grants_others(&loaded.owner) {
        return Ok(with_enforced());
    }
    // As T21's: a plain UPDATE of the bucket's row; the ACL's check is
    // racy against a PutBucketAcl, as the policy's against its block is.
    client
        .execute_cached(
            "UPDATE buckets SET object_ownership = $2 WHERE name = $1",
            &[&bucket, &ownership.map(Ownership::name)],
        )
        .await?;
    let status = if body.is_some() { StatusCode::OK } else { StatusCode::NO_CONTENT };
    Ok(Response::builder().status(status).body(Full::new(Bytes::new())).unwrap())
}

/// An object's owner, as listings show it (`<Owner>`): its canonical ID.
pub fn owner_xml(owner: &str) -> String {
    format!("<Owner><ID>{}</ID></Owner>", xml_escape(&canonical_id(owner)))
}

/// Who owns what a listing of `bucket` lists: its owner, unless it has
/// ACLs enabled and a version of one of `keys` is another account's (by
/// key and version ID: `owner`).
pub struct Owners {
    pub bucket_owner: String,
    others: HashMap<(String, String), String>,
}

impl Owners {
    pub async fn load(app: &App, bucket: &str, keys: &[&str]) -> anyhow::Result<Owners> {
        let client = app.pool.get().await?;
        let Some(loaded) = Bucket::load(&client, bucket).await? else {
            let bucket_owner = crate::s3::util::bucket_owner(&client, bucket).await?;
            return Ok(Owners { bucket_owner, others: HashMap::new() });
        };
        let mut others = HashMap::new();
        if loaded.ownership.enabled() && !keys.is_empty() {
            let rows = client
                .query_cached(
                    "SELECT key, version_id, owner_id, is_latest FROM objects
                     WHERE bucket = $1 AND key = ANY($2) AND owner_id IS NOT NULL AND owner_id <> $3",
                    &[&bucket, &keys, &loaded.owner],
                )
                .await?;
            for row in rows {
                let (key, version_id, owner): (String, String, String) = (row.get(0), row.get(1), row.get(2));
                if row.get::<_, bool>(3) {
                    others.insert((key.clone(), String::new()), owner.clone());
                }
                others.insert((key, version_id), owner);
            }
        }
        Ok(Owners { bucket_owner: loaded.owner, others })
    }

    /// The owner of `key`'s version `version_id` (`None`: its latest).
    pub fn of(&self, key: &str, version_id: Option<&str>) -> &str {
        self.others.get(&(key.to_owned(), version_id.unwrap_or("").to_owned())).unwrap_or(&self.bucket_owner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: &str = "111111111111";
    const OTHER: &str = "222222222222";

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, value.parse().unwrap());
        }
        map
    }

    #[test]
    fn parses_ownership_controls() {
        let put = |rule: &str| {
            let body = format!("<OwnershipControls xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Rule>{rule}</Rule></OwnershipControls>");
            parse_ownership(body.as_bytes())
        };
        assert_eq!(put("<ObjectOwnership>BucketOwnerEnforced</ObjectOwnership>"), Some(Ownership::Enforced));
        assert_eq!(put("<ObjectOwnership>ObjectWriter</ObjectOwnership>"), Some(Ownership::Writer));
        assert_eq!(put("<ObjectOwnership>BucketOwnerPreferred</ObjectOwnership>"), Some(Ownership::Preferred));
        assert_eq!(put("<ObjectOwnership>Nope</ObjectOwnership>"), None);
        assert_eq!(put(""), None);
    }

    #[test]
    fn takes_no_acl_or_the_owners_only_with_acls_disabled() {
        for on in [On::Object, On::Bucket] {
            assert!(check_write(&HeaderMap::new(), on).is_ok());
            assert!(check_write(&headers(&[("x-amz-acl", "private")]), on).is_ok());
            for other in [
                headers(&[("x-amz-acl", "public-read")]),
                headers(&[("x-amz-grant-read", "uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"")]),
                headers(&[("x-amz-acl", "private"), ("x-amz-grant-full-control", "id=other")]),
            ] {
                assert_eq!(check_write(&other, on).unwrap_err().status(), StatusCode::BAD_REQUEST, "{on:?} {other:?}");
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
    fn expands_canned_acls() {
        let read = |grantee| Grant { grantee, permission: Permission::Read };
        let all = Grantee::Group(Group::AllUsers);
        assert_eq!(Acl::canned("private", On::Object, OTHER, OWNER), Acl::private(OTHER));
        assert_eq!(Acl::canned("public-read", On::Object, OWNER, OWNER).grants[1], read(all.clone()));
        assert_eq!(Acl::canned("public-read-write", On::Bucket, OWNER, OWNER).grants.len(), 3);
        // The bucket owner's, on another's object.
        let full = Acl::canned("bucket-owner-full-control", On::Object, OTHER, OWNER);
        assert_eq!(full.grants[1], Grant { grantee: Grantee::Account(OWNER.into()), permission: Permission::FullControl });
        assert_eq!(Acl::canned("bucket-owner-full-control", On::Object, OWNER, OWNER), Acl::private(OWNER));
        assert_eq!(Acl::canned("bucket-owner-read", On::Bucket, OWNER, OWNER), Acl::private(OWNER));
        assert!(Acl::canned("authenticated-read", On::Object, OWNER, OWNER).is_public());
        assert!(!Acl::canned("log-delivery-write", On::Bucket, OWNER, OWNER).is_public());
    }

    #[test]
    fn stores_only_what_isnt_the_default() {
        assert_eq!(Acl::private(OWNER).stored(OWNER), None);
        let public = Acl::canned("public-read", On::Object, OWNER, OWNER);
        let stored = public.stored(OWNER).unwrap();
        assert_eq!(Acl::from_stored(Some(&stored), OWNER), public);
        assert_eq!(Acl::from_stored(None, OWNER), Acl::private(OWNER));
    }

    #[test]
    fn reads_header_grants() {
        let accounts = Accounts::of(&[OWNER, OTHER]);
        let id = canonical_id(OTHER);
        let both = headers(&[
            ("x-amz-grant-read", &format!("id=\"{id}\", uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"")),
            ("x-amz-grant-write-acp", &format!("id={OTHER}")),
        ]);
        let Ok(Some(Asked::Grants(grants))) = asked(&both, Some(&accounts)) else { panic!() };
        assert_eq!(
            grants,
            vec![
                Grant { grantee: Grantee::Account(OTHER.into()), permission: Permission::Read },
                Grant { grantee: Grantee::Group(Group::AllUsers), permission: Permission::Read },
                Grant { grantee: Grantee::Account(OTHER.into()), permission: Permission::WriteAcp },
            ]
        );
        let code = |h: HeaderMap| asked(&h, Some(&accounts)).err().map(|r| r.status().as_u16());
        assert_eq!(code(headers(&[("x-amz-grant-read", "id=\"nobody\"")])), Some(400));
        assert_eq!(code(headers(&[("x-amz-grant-read", "emailAddress=\"a@example.com\"")])), Some(400));
        assert_eq!(code(headers(&[("x-amz-grant-read", "uri=\"http://example.com/x\"")])), Some(400));
        assert_eq!(code(headers(&[("x-amz-grant-read", "nonsense")])), Some(400));
        assert_eq!(code(headers(&[("x-amz-acl", "private"), ("x-amz-grant-read", &format!("id={OTHER}"))])), Some(400));
        assert_eq!(code(headers(&[("x-amz-acl", "public")])), Some(400));
    }

    #[test]
    fn reads_what_it_writes_as_xml() {
        let accounts = Accounts::of(&[OWNER, OTHER]);
        let mut acl = Acl::canned("public-read", On::Bucket, OWNER, OWNER);
        acl.grants.push(Grant { grantee: Grantee::Account(OTHER.into()), permission: Permission::WriteAcp });
        acl.grants.push(Grant { grantee: Grantee::Group(Group::LogDelivery), permission: Permission::Write });
        let xml = acl.xml(OWNER);
        let (owner, read) = from_xml(xml.as_bytes(), &accounts).unwrap();
        assert_eq!(owner, Some(canonical_id(OWNER)));
        assert_eq!(read, acl);
        // Without types, by what they have.
        let untyped = format!(
            "<AccessControlPolicy><AccessControlList><Grant><Grantee><ID>{}</ID></Grantee>\
             <Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>",
            canonical_id(OTHER)
        );
        assert_eq!(from_xml(untyped.as_bytes(), &accounts).unwrap().1.grants[0].grantee, Grantee::Account(OTHER.into()));
        for bad in ["<Nope/>", "<AccessControlPolicy><AccessControlList><Grant><Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>", "not xml"] {
            assert_eq!(from_xml(bad.as_bytes(), &accounts).unwrap_err().status(), StatusCode::BAD_REQUEST, "{bad}");
        }
    }

    #[test]
    fn allows_as_a_bucket_policy_does() {
        use crate::policy::{Context, Decision, Kind, Policy, Principal, Request};
        let mut acl = Acl::canned("public-read", On::Bucket, OWNER, OWNER);
        acl.grants.push(Grant { grantee: Grantee::Account(OTHER.into()), permission: Permission::Write });
        acl.grants.push(Grant { grantee: Grantee::Group(Group::AuthenticatedUsers), permission: Permission::ReadAcp });
        let text = acl.policy(On::Bucket, "b", OWNER, false).unwrap();
        let policy = Policy::parse(&text, Kind::Bucket("b")).unwrap();
        let mut anonymous = Context::default();
        anonymous.set("aws:PrincipalType", "Anonymous");
        let mut signed = Context::default();
        signed.set("aws:PrincipalType", "User");
        let decide = |principal, action, resource, context: &Context| {
            policy.evaluate_across(&Request { principal, action, resource, context }, true)
        };
        let user = Principal::User { account: OTHER, name: "u", id: "AIDA" };
        let root = Principal::Root { account: OTHER };
        assert_eq!(decide(Principal::Anonymous, "s3:ListBucket", "arn:aws:s3:::b", &anonymous), Decision::Allow);
        assert_eq!(decide(Principal::Anonymous, "s3:PutObject", "arn:aws:s3:::b/k", &anonymous), Decision::NotApplicable);
        assert_eq!(decide(root, "s3:PutObject", "arn:aws:s3:::b/k", &signed), Decision::Allow);
        assert_eq!(decide(user, "s3:PutObject", "arn:aws:s3:::b/k", &signed), Decision::Allow);
        assert_eq!(decide(Principal::Anonymous, "s3:GetBucketAcl", "arn:aws:s3:::b", &anonymous), Decision::NotApplicable);
        assert_eq!(decide(user, "s3:GetBucketAcl", "arn:aws:s3:::b", &signed), Decision::Allow);
        // IgnorePublicAcls: only the account's grant.
        let ignored = acl.policy(On::Bucket, "b", OWNER, true).unwrap();
        assert!(!ignored.contains("\"*\""));
        // The owner's alone allow no one else anything.
        assert_eq!(Acl::private(OWNER).policy(On::Object, "b", OWNER, false), None);
        let object = Acl::canned("public-read", On::Object, OWNER, OWNER).policy(On::Object, "b", OWNER, false).unwrap();
        let policy = Policy::parse(&object, Kind::Bucket("b")).unwrap();
        let read = Request { principal: Principal::Anonymous, action: "s3:GetObject", resource: "arn:aws:s3:::b/k", context: &anonymous };
        assert_eq!(policy.evaluate(&read), Decision::Allow);
    }
}
