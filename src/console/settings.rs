//! The console's API for a bucket's settings that S3 keeps as documents of
//! their own (default encryption, Object Lock, Object Ownership and ACLs,
//! server access logging, versioning's MFA delete), and for what an object
//! version has besides its data (its storage class, checksum, retention,
//! legal hold and ACL).
//!
//! Each handler checks its S3 operation's actions, with the condition keys
//! S3 gives them (an Object Lock change's mode and date, say), and changes
//! things through S3's own handlers, with the documents S3 takes, so what's
//! refused is refused as S3 refuses it, and says why in S3's words.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::actor::Actor;
use super::manage::{AppState, Result, s3_error};
use super::web::{ApiError, ErrorBody};
use crate::{
    App,
    db::Cached,
    policy::Context,
    s3::{
        acl::{self, Grant, Grantee, Group, Permission},
        actions::{Check, On},
        buckets::{encryption, logging},
        checksums::StoredChecksum,
        object_lock,
        sse::{self, Stored},
        util::xml_escape,
        versions::Versioning,
    },
};

/// How many versions of a key are shown, as `manage::object` shows them.
const MAX_VERSIONS: i64 = 200;

pub(super) fn router() -> OpenApiRouter<Arc<App>> {
    OpenApiRouter::new()
        .routes(routes!(list_storage_classes))
        .routes(routes!(
            get_bucket_encryption,
            put_bucket_encryption,
            delete_bucket_encryption
        ))
        .routes(routes!(get_object_lock, put_object_lock))
        .routes(routes!(get_ownership, put_ownership, delete_ownership))
        .routes(routes!(get_bucket_acl, put_bucket_acl))
        .routes(routes!(
            get_bucket_logging,
            put_bucket_logging,
            delete_bucket_logging
        ))
        .routes(routes!(get_versioning))
        .routes(routes!(get_object_details))
        .routes(routes!(put_retention))
        .routes(routes!(put_legal_hold))
        .routes(routes!(put_object_acl))
        .routes(routes!(change_storage_class))
}

/// What an S3 handler answered: success, or its error as the API's. A 501
/// (what needs a KMS, without one) is the request's to fix, and says so.
async fn answered(
    mut resp: hyper::Response<http_body_util::Full<hyper::body::Bytes>>,
) -> Result<StatusCode> {
    match resp.status() {
        s if s.is_success() => Ok(StatusCode::NO_CONTENT),
        StatusCode::NOT_IMPLEMENTED => {
            *resp.status_mut() = StatusCode::BAD_REQUEST;
            Err(s3_error(resp).await)
        }
        _ => Err(s3_error(resp).await),
    }
}

fn no_such_bucket(bucket: &str) -> ApiError {
    ApiError::NotFound(format!("no bucket named {bucket:?}"))
}

// ─── Storage classes ─────────────────────────────────────────────────────────

/// A storage class, as a write may name it.
#[derive(Serialize, ToSchema)]
struct StorageClassName {
    name: String,
    /// Its place in the classes' order, the warmest highest (STANDARD is 0);
    /// none if it has none.
    rank: Option<i32>,
}

/// The storage classes a write may name, the warmest first: their names
/// and ranks only (`/storage` has their pools and layouts, for operators).
/// Any identity may read them: they're what every S3 client may name in
/// `x-amz-storage-class`, and listings and HEAD tell them of every object.
#[utoipa::path(get, path = "/storage-classes", responses(
    (status = 200, body = Vec<StorageClassName>),
    (status = "5XX", body = ErrorBody),
))]
async fn list_storage_classes(State(app): AppState) -> Result<Json<Vec<StorageClassName>>> {
    let classes = crate::classes::load(&app.pool.get().await?).await?;
    let mut names: Vec<StorageClassName> = classes
        .into_values()
        .map(|c| StorageClassName {
            name: c.name,
            rank: c.rank,
        })
        .collect();
    if !names.iter().any(|c| c.name == crate::classes::STANDARD) {
        names.push(StorageClassName {
            name: crate::classes::STANDARD.to_owned(),
            rank: Some(0),
        });
    }
    // Ranked ones by rank, then the others, by name.
    names.sort_by(|a, b| {
        b.rank
            .is_some()
            .cmp(&a.rank.is_some())
            .then(b.rank.cmp(&a.rank))
            .then(a.name.cmp(&b.name))
    });
    Ok(Json(names))
}

/// The class a console upload named (none: STANDARD), as
/// `x-amz-storage-class` names it: refused if there's no such class.
pub(super) async fn storage_class(app: &App, name: Option<&str>) -> Result<String> {
    match crate::classes::resolve(app, name).await? {
        Ok(class) => Ok(class),
        Err(name) => Err(ApiError::BadRequest(format!(
            "there's no storage class {name}"
        ))),
    }
}

// ─── Default encryption ──────────────────────────────────────────────────────

/// A bucket's default encryption, as PutBucketEncryption sets it.
#[derive(Serialize, Deserialize, ToSchema)]
struct DefaultEncryption {
    /// `AES256` (SSE-S3, under Cairn's own key) or `aws:kms` (SSE-KMS).
    algorithm: String,
    /// SSE-KMS: the key (`mount/name`, or a name in the mount `transit`).
    #[serde(default)]
    kms_key_id: Option<String>,
    /// Whether it asks for a bucket key: told back, but every object has
    /// keys of its own.
    #[serde(default)]
    bucket_key: bool,
}

#[derive(Serialize, ToSchema)]
struct BucketEncryption {
    /// `null` if it has none: writes that ask for no encryption aren't
    /// encrypted.
    configuration: Option<DefaultEncryption>,
    /// Whether the cluster has a KMS, which either needs.
    kms: bool,
    /// Whether it has a key of its own for SSE-S3.
    sse_s3: bool,
}

#[utoipa::path(get, path = "/buckets/{bucket}/encryption", params(("bucket" = String, Path)), responses(
    (status = 200, body = BucketEncryption),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn get_bucket_encryption(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
) -> Result<Json<BucketEncryption>> {
    actor
        .check(
            &app,
            "s3:GetEncryptionConfiguration",
            On::Bucket(bucket.clone()),
        )
        .await?;
    let default = encryption::bucket_default(&app, &bucket)
        .await?
        .map_err(|()| no_such_bucket(&bucket))?;
    let configuration = default.map(|d| DefaultEncryption {
        algorithm: if d.key_id.is_some() {
            "aws:kms"
        } else {
            "AES256"
        }
        .to_owned(),
        kms_key_id: d.key_id.map(|k| k.as_string()),
        bucket_key: d.bucket_key,
    });
    Ok(Json(BucketEncryption {
        configuration,
        kms: app.kms.is_some(),
        sse_s3: app
            .kms
            .as_ref()
            .is_some_and(|kms| kms.sse_s3_key().is_some()),
    }))
}

/// Sets a bucket's default encryption, checked as PutBucketEncryption
/// checks it: an SSE-KMS key must be one the KMS has.
#[utoipa::path(put, path = "/buckets/{bucket}/encryption", params(("bucket" = String, Path)),
    request_body = DefaultEncryption, responses(
        (status = 204, description = "Set"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn put_bucket_encryption(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Json(body): Json<DefaultEncryption>,
) -> Result<StatusCode> {
    actor
        .check(
            &app,
            "s3:PutEncryptionConfiguration",
            On::Bucket(bucket.clone()),
        )
        .await?;
    let key = match body.kms_key_id.as_deref().filter(|k| !k.is_empty()) {
        Some(key) => format!("<KMSMasterKeyID>{}</KMSMasterKeyID>", xml_escape(key)),
        None => String::new(),
    };
    let xml = format!(
        "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault>\
         <SSEAlgorithm>{}</SSEAlgorithm>{key}</ApplyServerSideEncryptionByDefault>\
         <BucketKeyEnabled>{}</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>",
        xml_escape(&body.algorithm),
        body.bucket_key
    );
    // As the user, as S3 tries the key (a root has no identity in the KMS).
    let role = actor.kms_role().unwrap_or(uuid::Uuid::nil());
    answered(encryption::put_bucket_encryption(&app, &bucket, xml.into(), role).await?).await
}

/// Removes a bucket's default encryption: new writes are encrypted only if
/// they ask; what's written stays as it is.
#[utoipa::path(delete, path = "/buckets/{bucket}/encryption", params(("bucket" = String, Path)), responses(
    (status = 204, description = "Removed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_bucket_encryption(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
) -> Result<StatusCode> {
    // DeleteBucketEncryption is authorized as its put, in S3.
    actor
        .check(
            &app,
            "s3:PutEncryptionConfiguration",
            On::Bucket(bucket.clone()),
        )
        .await?;
    answered(encryption::delete_bucket_encryption(&app, &bucket).await?).await
}

// ─── Object Lock ─────────────────────────────────────────────────────────────

/// A default retention: its mode, for so many days or years.
#[derive(Serialize, Deserialize, ToSchema)]
struct DefaultRetention {
    /// `GOVERNANCE` or `COMPLIANCE`.
    mode: String,
    /// Either days or years.
    #[serde(default)]
    days: Option<i32>,
    #[serde(default)]
    years: Option<i32>,
}

#[derive(Serialize, ToSchema)]
struct BucketObjectLock {
    /// Whether the bucket has Object Lock (it can't be disabled again).
    enabled: bool,
    /// What every new version that asks for no retention gets.
    default_retention: Option<DefaultRetention>,
}

#[derive(Deserialize, ToSchema)]
struct NewObjectLock {
    /// None: no default retention.
    #[serde(default)]
    default_retention: Option<DefaultRetention>,
}

#[utoipa::path(get, path = "/buckets/{bucket}/object-lock", params(("bucket" = String, Path)), responses(
    (status = 200, body = BucketObjectLock),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn get_object_lock(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
) -> Result<Json<BucketObjectLock>> {
    actor
        .check(
            &app,
            "s3:GetBucketObjectLockConfiguration",
            On::Bucket(bucket.clone()),
        )
        .await?;
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached(
            "SELECT object_lock, lock_mode, lock_days, lock_years FROM buckets WHERE name = $1",
            &[&bucket],
        )
        .await?
        .ok_or_else(|| no_such_bucket(&bucket))?;
    let default_retention = row
        .get::<_, Option<String>>(1)
        .map(|mode| DefaultRetention {
            mode,
            days: row.get(2),
            years: row.get(3),
        });
    Ok(Json(BucketObjectLock {
        enabled: row.get(0),
        default_retention,
    }))
}

/// Sets a bucket's Object Lock configuration, as PutObjectLockConfiguration
/// does: enables Object Lock (on a versioned bucket only, for good), and
/// sets or removes its default retention.
#[utoipa::path(put, path = "/buckets/{bucket}/object-lock", params(("bucket" = String, Path)),
    request_body = NewObjectLock, responses(
        (status = 204, description = "Set"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn put_object_lock(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Json(body): Json<NewObjectLock>,
) -> Result<StatusCode> {
    actor
        .check(
            &app,
            "s3:PutBucketObjectLockConfiguration",
            On::Bucket(bucket.clone()),
        )
        .await?;
    let rule = match &body.default_retention {
        None => String::new(),
        Some(r) => {
            let period = match (r.days, r.years) {
                (Some(days), None) => format!("<Days>{days}</Days>"),
                (None, Some(years)) => format!("<Years>{years}</Years>"),
                _ => {
                    return Err(ApiError::BadRequest(
                        "a default retention is either days or years".into(),
                    ));
                }
            };
            format!(
                "<Rule><DefaultRetention><Mode>{}</Mode>{period}</DefaultRetention></Rule>",
                xml_escape(&r.mode)
            )
        }
    };
    let xml = format!(
        "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled>{rule}</ObjectLockConfiguration>"
    );
    answered(object_lock::put_object_lock_configuration(&app, &bucket, xml.into()).await?).await
}

// ─── Object Ownership and ACLs ───────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
struct BucketOwnership {
    /// `BucketOwnerEnforced` (ACLs disabled), `BucketOwnerPreferred` or
    /// `ObjectWriter`; `null` if it has no ownership controls, which is as
    /// `ObjectWriter`.
    ownership: Option<String>,
}

#[derive(Deserialize, ToSchema)]
struct NewOwnership {
    ownership: String,
}

#[utoipa::path(get, path = "/buckets/{bucket}/ownership", params(("bucket" = String, Path)), responses(
    (status = 200, body = BucketOwnership),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn get_ownership(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
) -> Result<Json<BucketOwnership>> {
    actor
        .check(
            &app,
            "s3:GetBucketOwnershipControls",
            On::Bucket(bucket.clone()),
        )
        .await?;
    let loaded = acl::Bucket::load(&app.pool.get().await?, &bucket)
        .await?
        .ok_or_else(|| no_such_bucket(&bucket))?;
    Ok(Json(BucketOwnership {
        ownership: loaded
            .controlled
            .then(|| loaded.ownership.name().to_owned()),
    }))
}

/// Sets a bucket's Object Ownership, as PutBucketOwnershipControls does:
/// disabling ACLs is refused while the bucket's ACL grants anyone but its
/// owner anything.
#[utoipa::path(put, path = "/buckets/{bucket}/ownership", params(("bucket" = String, Path)),
    request_body = NewOwnership, responses(
        (status = 204, description = "Set"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn put_ownership(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Json(body): Json<NewOwnership>,
) -> Result<StatusCode> {
    actor
        .check(
            &app,
            "s3:PutBucketOwnershipControls",
            On::Bucket(bucket.clone()),
        )
        .await?;
    let xml = format!(
        "<OwnershipControls><Rule><ObjectOwnership>{}</ObjectOwnership></Rule></OwnershipControls>",
        xml_escape(&body.ownership)
    );
    answered(acl::set_ownership_controls(&app, &bucket, Some(xml.as_bytes())).await?).await
}

/// Removes a bucket's ownership controls, as DeleteBucketOwnershipControls
/// does: ACLs are enabled, and writers own what they write.
#[utoipa::path(delete, path = "/buckets/{bucket}/ownership", params(("bucket" = String, Path)), responses(
    (status = 204, description = "Removed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_ownership(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
) -> Result<StatusCode> {
    // DeleteBucketOwnershipControls is authorized as its put, in S3.
    actor
        .check(
            &app,
            "s3:PutBucketOwnershipControls",
            On::Bucket(bucket.clone()),
        )
        .await?;
    answered(acl::set_ownership_controls(&app, &bucket, None).await?).await
}

/// A grant of an ACL.
#[derive(Serialize, Deserialize, ToSchema)]
struct AclGrant {
    /// `account` or `group`.
    grantee_type: String,
    /// An account's ID (or canonical ID), or a group: `AllUsers` (everyone,
    /// unsigned requests too), `AuthenticatedUsers` (any signed request) or
    /// `LogDelivery` (server access logs).
    grantee: String,
    /// `FULL_CONTROL`, `READ`, `WRITE`, `READ_ACP` or `WRITE_ACP`.
    permission: String,
}

/// An ACL, of a bucket or an object version.
#[derive(Serialize, ToSchema)]
struct AclInfo {
    /// The account that owns what it's on.
    owner: String,
    grants: Vec<AclGrant>,
}

#[derive(Serialize, ToSchema)]
struct BucketAcl {
    /// Whether the bucket has ACLs enabled (its Object Ownership isn't
    /// `BucketOwnerEnforced`); if not, its ACL is its owner's full control.
    enabled: bool,
    acl: AclInfo,
}

#[derive(Deserialize, ToSchema)]
struct NewAcl {
    /// The whole ACL: what it doesn't grant isn't granted.
    grants: Vec<AclGrant>,
}

const GROUPS: [(Group, &str); 3] = [
    (Group::AllUsers, "AllUsers"),
    (Group::AuthenticatedUsers, "AuthenticatedUsers"),
    (Group::LogDelivery, "LogDelivery"),
];

fn permission_name(permission: Permission) -> String {
    match serde_json::to_value(permission) {
        Ok(serde_json::Value::String(name)) => name,
        _ => unreachable!("a permission serializes as its name"),
    }
}

/// An ACL as the console shows it.
fn acl_info(owner: &str, acl: &acl::Acl) -> AclInfo {
    let grants = acl
        .grants
        .iter()
        .map(
            |Grant {
                 grantee,
                 permission,
             }| {
                let (grantee_type, grantee) = match grantee {
                    Grantee::Account(account) => ("account", account.clone()),
                    Grantee::Group(group) => (
                        "group",
                        GROUPS
                            .iter()
                            .find(|(g, _)| g == group)
                            .map_or("", |(_, name)| name)
                            .to_owned(),
                    ),
                };
                AclGrant {
                    grantee_type: grantee_type.to_owned(),
                    grantee,
                    permission: permission_name(*permission),
                }
            },
        )
        .collect();
    AclInfo {
        owner: owner.to_owned(),
        grants,
    }
}

/// Grants as PutBucketAcl's and PutObjectAcl's `<AccessControlPolicy>`,
/// which checks them (their accounts, groups and permissions).
fn acl_xml(grants: &[AclGrant]) -> Result<String> {
    let mut xml = String::new();
    for grant in grants {
        let grantee = match grant.grantee_type.as_str() {
            "account" => format!(
                "xsi:type=\"CanonicalUser\"><ID>{}</ID>",
                xml_escape(grant.grantee.trim())
            ),
            "group" => {
                let Some((group, _)) = GROUPS.iter().find(|(_, n)| *n == grant.grantee) else {
                    return Err(ApiError::BadRequest(format!(
                        "there's no group {:?}: it's AllUsers, AuthenticatedUsers or LogDelivery",
                        grant.grantee
                    )));
                };
                format!("xsi:type=\"Group\"><URI>{}</URI>", group.uri())
            }
            other => {
                return Err(ApiError::BadRequest(format!(
                    "a grantee is an account or a group, not {other:?}"
                )));
            }
        };
        xml.push_str(&format!(
            "<Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" {grantee}</Grantee>\
             <Permission>{}</Permission></Grant>",
            xml_escape(&grant.permission)
        ));
    }
    Ok(format!(
        "<AccessControlPolicy><AccessControlList>{xml}</AccessControlList></AccessControlPolicy>"
    ))
}

#[utoipa::path(get, path = "/buckets/{bucket}/acl", params(("bucket" = String, Path)), responses(
    (status = 200, body = BucketAcl),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn get_bucket_acl(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
) -> Result<Json<BucketAcl>> {
    actor
        .check(&app, "s3:GetBucketAcl", On::Bucket(bucket.clone()))
        .await?;
    let loaded = acl::Bucket::load(&app.pool.get().await?, &bucket)
        .await?
        .ok_or_else(|| no_such_bucket(&bucket))?;
    // As GetBucketAcl tells it: with ACLs disabled, the owner's full control.
    let enabled = loaded.ownership.enabled();
    let acl = match enabled {
        true => loaded.acl(),
        false => acl::Acl::private(&loaded.owner),
    };
    Ok(Json(BucketAcl {
        enabled,
        acl: acl_info(&loaded.owner, &acl),
    }))
}

/// Replaces a bucket's ACL, as PutBucketAcl does: refused with ACLs
/// disabled, and a public one with BlockPublicAcls.
#[utoipa::path(put, path = "/buckets/{bucket}/acl", params(("bucket" = String, Path)),
    request_body = NewAcl, responses(
        (status = 204, description = "Set"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn put_bucket_acl(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Json(body): Json<NewAcl>,
) -> Result<StatusCode> {
    actor
        .check(&app, "s3:PutBucketAcl", On::Bucket(bucket.clone()))
        .await?;
    let xml = acl_xml(&body.grants)?;
    answered(acl::put_bucket_acl(&app, &bucket, &HeaderMap::new(), xml.as_bytes()).await?).await
}

// ─── Server access logging ───────────────────────────────────────────────────

/// Where a bucket's server access logs go.
#[derive(Serialize, Deserialize, ToSchema)]
struct BucketLoggingForm {
    /// The bucket they're written to: one of the same account's.
    target_bucket: String,
    /// What their keys begin with (may be empty).
    #[serde(default)]
    target_prefix: String,
    /// How the rest of their keys is made: `SimplePrefix`
    /// (`YYYY-mm-DD-HH-MM-SS-UniqueString`), `PartitionedPrefix` (by
    /// account, region, bucket and date first), or `null` (as `SimplePrefix`).
    #[serde(default)]
    key_format: Option<String>,
    /// `PartitionedPrefix`: whose date the partitions are, `EventTime` or
    /// `DeliveryTime` (`null`: the events').
    #[serde(default)]
    date_source: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct BucketLogging {
    /// `null` if it logs nothing.
    configuration: Option<BucketLoggingForm>,
}

#[utoipa::path(get, path = "/buckets/{bucket}/logging", params(("bucket" = String, Path)), responses(
    (status = 200, body = BucketLogging),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn get_bucket_logging(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
) -> Result<Json<BucketLogging>> {
    actor
        .check(&app, "s3:GetBucketLogging", On::Bucket(bucket.clone()))
        .await?;
    let configuration = logging::load(&app, &bucket)
        .await?
        .ok_or_else(|| no_such_bucket(&bucket))?
        .map(|l| {
            use logging::{DateSource, KeyFormat};
            let (key_format, date_source) = match l.key_format {
                None => (None, None),
                Some(KeyFormat::Simple) => (Some("SimplePrefix"), None),
                Some(KeyFormat::Partitioned(source)) => (
                    Some("PartitionedPrefix"),
                    source.map(|s| match s {
                        DateSource::EventTime => "EventTime",
                        DateSource::DeliveryTime => "DeliveryTime",
                    }),
                ),
            };
            BucketLoggingForm {
                target_bucket: l.target_bucket,
                target_prefix: l.target_prefix,
                key_format: key_format.map(str::to_owned),
                date_source: date_source.map(str::to_owned),
            }
        });
    Ok(Json(BucketLogging { configuration }))
}

/// Logs a bucket's requests into another, as PutBucketLogging does: the
/// target must be the same account's. Its policy must let
/// `logging.s3.amazonaws.com` write them, or they aren't delivered, as in S3.
#[utoipa::path(put, path = "/buckets/{bucket}/logging", params(("bucket" = String, Path)),
    request_body = BucketLoggingForm, responses(
        (status = 204, description = "Set"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn put_bucket_logging(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Json(body): Json<BucketLoggingForm>,
) -> Result<StatusCode> {
    actor
        .check(&app, "s3:PutBucketLogging", On::Bucket(bucket.clone()))
        .await?;
    let format = match (body.key_format.as_deref(), body.date_source.as_deref()) {
        (None | Some(""), _) => String::new(),
        (Some("SimplePrefix"), _) => {
            "<TargetObjectKeyFormat><SimplePrefix/></TargetObjectKeyFormat>".to_owned()
        }
        (Some("PartitionedPrefix"), None | Some("")) => {
            "<TargetObjectKeyFormat><PartitionedPrefix/></TargetObjectKeyFormat>".to_owned()
        }
        (Some("PartitionedPrefix"), Some(source)) => format!(
            "<TargetObjectKeyFormat><PartitionedPrefix><PartitionDateSource>{}</PartitionDateSource>\
             </PartitionedPrefix></TargetObjectKeyFormat>",
            xml_escape(source)
        ),
        (Some(other), _) => {
            return Err(ApiError::BadRequest(format!(
                "a key format is SimplePrefix or PartitionedPrefix, not {other:?}"
            )));
        }
    };
    let xml = format!(
        "<BucketLoggingStatus><LoggingEnabled><TargetBucket>{}</TargetBucket>\
         <TargetPrefix>{}</TargetPrefix>{format}</LoggingEnabled></BucketLoggingStatus>",
        xml_escape(&body.target_bucket),
        xml_escape(&body.target_prefix)
    );
    answered(logging::put_bucket_logging(&app, &bucket, xml.into()).await?).await
}

/// Turns a bucket's server access logging off, as PutBucketLogging does
/// with an empty `<BucketLoggingStatus>`.
#[utoipa::path(delete, path = "/buckets/{bucket}/logging", params(("bucket" = String, Path)), responses(
    (status = 204, description = "Turned off"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_bucket_logging(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
) -> Result<StatusCode> {
    actor
        .check(&app, "s3:PutBucketLogging", On::Bucket(bucket.clone()))
        .await?;
    let xml = "<BucketLoggingStatus></BucketLoggingStatus>";
    answered(logging::put_bucket_logging(&app, &bucket, xml.into()).await?).await
}

// ─── Versioning ──────────────────────────────────────────────────────────────

/// A bucket's versioning, as GetBucketVersioning tells it.
#[derive(Serialize, ToSchema)]
struct BucketVersioning {
    status: Versioning,
    /// Whether deleting a version, or changing versioning, needs an MFA
    /// code (`x-amz-mfa`); `null` if it was never set. Only the S3 API
    /// changes it, with one.
    mfa_delete: Option<bool>,
}

#[utoipa::path(get, path = "/buckets/{bucket}/versioning", params(("bucket" = String, Path)), responses(
    (status = 200, body = BucketVersioning),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn get_versioning(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
) -> Result<Json<BucketVersioning>> {
    actor
        .check(&app, "s3:GetBucketVersioning", On::Bucket(bucket.clone()))
        .await?;
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached(
            "SELECT versioning, mfa_delete FROM buckets WHERE name = $1",
            &[&bucket],
        )
        .await?
        .ok_or_else(|| no_such_bucket(&bucket))?;
    Ok(Json(BucketVersioning {
        status: Versioning::from_db(row.get(0)),
        mfa_delete: row.get(1),
    }))
}

// ─── Object versions ─────────────────────────────────────────────────────────

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct KeyParams {
    key: String,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct VersionParams {
    key: String,
    /// The version; the current one if not given.
    version: Option<String>,
}

/// What a key's versions have besides their data, as far as the actor may
/// read it: what it may not read is `null`.
#[derive(Serialize, ToSchema)]
struct ObjectDetails {
    /// Whether the bucket has ACLs enabled.
    acls_enabled: bool,
    /// Whether the bucket has Object Lock.
    object_lock: bool,
    /// Whether the actor may read versions' retentions
    /// (`s3:GetObjectRetention`) and legal holds (`s3:GetObjectLegalHold`).
    reads_retention: bool,
    reads_legal_hold: bool,
    /// Whether it may bypass GOVERNANCE mode
    /// (`s3:BypassGovernanceRetention`).
    may_bypass_governance: bool,
    /// Newest first, as `/buckets/{bucket}/object` lists them.
    versions: Vec<VersionDetails>,
}

#[derive(Serialize, ToSchema)]
struct VersionDetails {
    version_id: String,
    /// None for a delete marker.
    storage_class: Option<String>,
    checksum: Option<ChecksumInfo>,
    retention: Option<Retention>,
    /// Whether it has a legal hold; `null` if it never had one, or it may
    /// not be read.
    legal_hold: Option<bool>,
    /// Its ACL, if the bucket has ACLs enabled and the actor may read it
    /// (`s3:GetObjectAcl`, an older version's `s3:GetObjectVersionAcl`).
    acl: Option<AclInfo>,
}

/// A version's checksum (see `s3::checksums`).
#[derive(Serialize, ToSchema)]
struct ChecksumInfo {
    /// `CRC32`, `CRC32C`, `CRC64NVME`, `SHA1`, `SHA256`, ...
    algorithm: String,
    /// `FULL_OBJECT` or `COMPOSITE` (of its parts' checksums).
    kind: String,
    /// Base64; `null` if it's sealed under a key Cairn doesn't open for
    /// this (SSE-C's, the client's; SSE-KMS's, which takes the KMS).
    value: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
struct Retention {
    /// `GOVERNANCE` or `COMPLIANCE`.
    mode: String,
    /// ISO 8601.
    retain_until: String,
}

/// What each version of a key has besides its data: its storage class,
/// checksum, retention, legal hold and ACL.
#[utoipa::path(get, path = "/buckets/{bucket}/object/details", params(("bucket" = String, Path), KeyParams),
    responses(
        (status = 200, body = ObjectDetails),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn get_object_details(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Query(params): Query<KeyParams>,
) -> Result<Json<ObjectDetails>> {
    // As HeadObject (which tells the class, the checksum, the retention and
    // the legal hold), and its older versions as ListObjectVersions.
    let on = || On::Object(bucket.clone(), params.key.clone());
    actor.check(&app, "s3:GetObject", on()).await?;
    let check = |action| (Check { action, on: on() }, Context::default());
    let [
        lists_versions,
        reads_retention,
        reads_legal_hold,
        bypass,
        reads_acl,
        reads_version_acl,
    ] = actor
        .allows_each(
            &app,
            &[
                (
                    Check {
                        action: "s3:ListBucketVersions",
                        on: On::Bucket(bucket.clone()),
                    },
                    Context::default(),
                ),
                check("s3:GetObjectRetention"),
                check("s3:GetObjectLegalHold"),
                check("s3:BypassGovernanceRetention"),
                check("s3:GetObjectAcl"),
                check("s3:GetObjectVersionAcl"),
            ],
        )
        .await?[..]
    else {
        unreachable!("a verdict for each check")
    };
    let client = app.pool.get().await?;
    let loaded = acl::Bucket::load(&client, &bucket)
        .await?
        .ok_or_else(|| no_such_bucket(&bucket))?;
    let object_lock: bool = client
        .query_one_cached(
            "SELECT object_lock FROM buckets WHERE name = $1",
            &[&bucket],
        )
        .await?
        .get(0);
    let limit = if lists_versions { MAX_VERSIONS } else { 1 };
    let sql = format!(
        "SELECT o.version_id, o.is_latest, o.is_delete_marker, o.storage_class,
                o.checksum_algorithm, o.checksum_type, o.checksum,
                o.sse_c_key, o.sse_kms_key_id, o.sse_kms_data_key, o.sse_kms_sealed,
                o.sse_kms_context, o.sse_s3, o.owner_id, o.acl, {}
         FROM objects o WHERE o.bucket = $1 AND o.key = $2
         ORDER BY o.last_modified DESC, o.id DESC LIMIT $3",
        object_lock::COLUMNS
    );
    let rows = client
        .query_cached(&sql, &[&bucket, &params.key, &limit])
        .await?;
    drop(client);
    let acls_enabled = loaded.ownership.enabled();
    let mut details = Vec::with_capacity(rows.len());
    for row in &rows {
        let latest: bool = row.get(1);
        if row.get::<_, bool>(2) {
            details.push(VersionDetails {
                version_id: row.get(0),
                storage_class: None,
                checksum: None,
                retention: None,
                legal_hold: None,
                acl: None,
            });
            continue;
        }
        let stored = Stored::from_row(row, 7);
        let checksum = match StoredChecksum::from_row(row, 4) {
            None => None,
            Some(checksum) => {
                // Plain, or sealed under its object key: SSE-S3's Cairn
                // opens itself, as it does its ETag (see `manage::object`).
                let value = match &stored {
                    Stored::Plain => Some(checksum.stored.clone()),
                    Stored::S3(_) => {
                        match sse::open(&app, &stored, None, None, &bucket, &params.key).await? {
                            Ok(Some(object_key)) => Some(
                                checksum
                                    .read(
                                        crate::encryption::Storing::Sealed(&object_key),
                                        &bucket,
                                        &params.key,
                                    )?
                                    .value,
                            ),
                            _ => None,
                        }
                    }
                    Stored::Kms(_) | Stored::Customer { .. } => None,
                };
                Some(ChecksumInfo {
                    algorithm: checksum.algorithm.name().to_owned(),
                    kind: checksum.kind.name().to_owned(),
                    value,
                })
            }
        };
        let lock = object_lock::Stored::from_row(row, 15);
        let retention = match (lock.mode, lock.until) {
            (Some(mode), Some(retain_until)) if reads_retention => {
                Some(Retention { mode, retain_until })
            }
            _ => None,
        };
        let shows_acl = if latest { reads_acl } else { reads_version_acl };
        let acl = (acls_enabled && shows_acl).then(|| {
            let owner = row
                .get::<_, Option<String>>(13)
                .unwrap_or_else(|| loaded.owner.clone());
            let acl = acl::Acl::from_stored(row.get(14), &owner);
            acl_info(&owner, &acl)
        });
        details.push(VersionDetails {
            version_id: row.get(0),
            storage_class: Some(row.get(3)),
            checksum,
            retention,
            legal_hold: lock.legal_hold.filter(|_| reads_legal_hold),
            acl,
        });
    }
    Ok(Json(ObjectDetails {
        acls_enabled,
        object_lock,
        reads_retention,
        reads_legal_hold,
        may_bypass_governance: bypass,
        versions: details,
    }))
}

#[derive(Deserialize, ToSchema)]
struct NewRetention {
    /// `GOVERNANCE` or `COMPLIANCE`; none, with no date, removes it.
    #[serde(default)]
    mode: Option<String>,
    /// ISO 8601, in the future.
    #[serde(default)]
    retain_until: Option<String>,
    /// Whether to bypass GOVERNANCE mode (to shorten or remove such a
    /// retention), which `s3:BypassGovernanceRetention` must allow.
    #[serde(default)]
    bypass_governance: bool,
}

/// Sets a version's retention, as PutObjectRetention does: it may only be
/// lengthened, but for one in GOVERNANCE mode, with the bypass.
#[utoipa::path(put, path = "/buckets/{bucket}/object/retention", params(("bucket" = String, Path), VersionParams),
    request_body = NewRetention, responses(
        (status = 204, description = "Set"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn put_retention(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Query(params): Query<VersionParams>,
    Json(body): Json<NewRetention>,
) -> Result<StatusCode> {
    let on = || On::Object(bucket.clone(), params.key.clone());
    let mut context = Context::default();
    object_lock::set_context(
        &mut context,
        body.mode.as_deref(),
        body.retain_until.as_deref(),
        None,
    );
    actor
        .check_with(&app, "s3:PutObjectRetention", on(), &context)
        .await?;
    // Asked for, and allowed, as S3 has it: else the change is as one
    // without it.
    let bypass = body.bypass_governance
        && actor
            .allows(&app, "s3:BypassGovernanceRetention", on())
            .await?;
    let element = |name, value: &Option<String>| {
        value.as_deref().map_or(String::new(), |v| {
            format!("<{name}>{}</{name}>", xml_escape(v))
        })
    };
    let xml = format!(
        "<Retention>{}{}</Retention>",
        element("Mode", &body.mode),
        element("RetainUntilDate", &body.retain_until)
    );
    let resp = object_lock::put_object_retention(
        &app,
        &bucket,
        &params.key,
        params.version.as_deref(),
        xml.as_bytes(),
        bypass,
    )
    .await?;
    answered(resp).await
}

#[derive(Deserialize, ToSchema)]
struct NewLegalHold {
    /// Whether the version is to have a legal hold.
    on: bool,
}

/// Places or lifts a version's legal hold, as PutObjectLegalHold does.
#[utoipa::path(put, path = "/buckets/{bucket}/object/legal-hold", params(("bucket" = String, Path), VersionParams),
    request_body = NewLegalHold, responses(
        (status = 204, description = "Set"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn put_legal_hold(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Query(params): Query<VersionParams>,
    Json(body): Json<NewLegalHold>,
) -> Result<StatusCode> {
    let status = if body.on { "ON" } else { "OFF" };
    let mut context = Context::default();
    object_lock::set_context(&mut context, None, None, Some(status));
    actor
        .check_with(
            &app,
            "s3:PutObjectLegalHold",
            On::Object(bucket.clone(), params.key.clone()),
            &context,
        )
        .await?;
    let xml = format!("<LegalHold><Status>{status}</Status></LegalHold>");
    let resp = object_lock::put_object_legal_hold(
        &app,
        &bucket,
        &params.key,
        params.version.as_deref(),
        xml.as_bytes(),
    )
    .await?;
    answered(resp).await
}

/// Replaces a version's ACL, as PutObjectAcl does: refused with ACLs
/// disabled, and a public one with BlockPublicAcls.
#[utoipa::path(put, path = "/buckets/{bucket}/object/acl", params(("bucket" = String, Path), VersionParams),
    request_body = NewAcl, responses(
        (status = 204, description = "Set"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn put_object_acl(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Query(params): Query<VersionParams>,
    Json(body): Json<NewAcl>,
) -> Result<StatusCode> {
    let action = match params.version {
        Some(_) => "s3:PutObjectVersionAcl",
        None => "s3:PutObjectAcl",
    };
    actor
        .check(&app, action, On::Object(bucket.clone(), params.key.clone()))
        .await?;
    let xml = acl_xml(&body.grants)?;
    let resp = acl::put_object_acl(
        &app,
        &bucket,
        &params.key,
        params.version.as_deref(),
        &HeaderMap::new(),
        xml.as_bytes(),
    )
    .await?;
    answered(resp).await
}

#[derive(Deserialize, ToSchema)]
struct NewStorageClass {
    storage_class: String,
}

/// Moves a key's current version into another storage class, as S3 does
/// it: a CopyObject onto itself that names the class, which makes a new
/// version (in a versioned bucket; else it replaces it), with the same
/// data, metadata, tags and encryption. Into a lower class, it shares the
/// version's bytes; into another, they're written again (see `classes`).
/// As CopyObject, at most 5 GiB, and not of an SSE-C version, whose key
/// Cairn doesn't have.
#[utoipa::path(post, path = "/buckets/{bucket}/object/storage-class", params(("bucket" = String, Path), KeyParams),
    request_body = NewStorageClass, responses(
        (status = 204, description = "Copied"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn change_storage_class(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Query(params): Query<KeyParams>,
    Json(body): Json<NewStorageClass>,
) -> Result<StatusCode> {
    let on = || On::Object(bucket.clone(), params.key.clone());
    // As CopyObject's: the write, and the read of its source.
    actor
        .check_all(
            &app,
            &[
                Check {
                    action: "s3:PutObject",
                    on: on(),
                },
                Check {
                    action: "s3:GetObject",
                    on: on(),
                },
            ],
        )
        .await?;
    let class = storage_class(&app, Some(&body.storage_class)).await?;
    // The version as it is: its encryption, which the copy keeps, and its
    // ETag, which the copy's source must still have.
    let client = app.pool.get().await?;
    let version =
        match crate::s3::objects::get::lookup_version(&client, &bucket, &params.key, None).await? {
            Ok(version) => version,
            Err(missing) => return Err(s3_error(missing.read_response()).await),
        };
    drop(client);
    let kms;
    let dest = match &version.encryption {
        Stored::Plain => sse::Wanted::Plain,
        Stored::S3(_) => sse::Wanted::S3,
        Stored::Kms(envelope) => {
            let key_id = crate::kms::KeyId::parse(&envelope.key_id).ok_or_else(|| {
                anyhow::anyhow!("the stored KMS key ID {:?} isn't one", envelope.key_id)
            })?;
            let context = envelope
                .context
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(anyhow::Error::from)?;
            kms = sse::KmsRequest { key_id, context };
            sse::Wanted::Kms(&kms)
        }
        Stored::Customer { .. } => {
            return Err(ApiError::BadRequest(
                "an SSE-C version's class can only be changed with its key, through the S3 API"
                    .into(),
            ));
        }
    };
    let etag = match sse::plain_etag(
        &app,
        &version.encryption,
        &version.etag,
        &bucket,
        &params.key,
    )
    .await?
    {
        Ok(etag) => etag,
        Err(refused) => return Err(s3_error(refused).await),
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-amz-copy-source-if-match",
        HeaderValue::from_str(&format!("\"{etag}\"")).map_err(anyhow::Error::from)?,
    );
    let source_conditions =
        crate::s3::conditional::Preconditions::from_copy_source_headers(&headers);
    let source = format!(
        "{}/{}",
        percent_encoding::utf8_percent_encode(&bucket, percent_encoding::NON_ALPHANUMERIC),
        percent_encoding::utf8_percent_encode(&params.key, percent_encoding::NON_ALPHANUMERIC)
    );
    let resp = crate::s3::objects::copy::copy_object(
        &app,
        &bucket,
        &params.key,
        &source,
        None,
        "",
        "",
        None,
        &source_conditions,
        crate::s3::objects::copy::CopyKeys {
            source: None,
            dest,
            role: actor.kms_role(),
            checksum: None,
            lock: Default::default(),
            conditions: None,
            restates: true,
            storage_class: Some(&class),
            replica: false,
        },
    )
    .await?;
    let status = resp.status();
    if !status.is_success() {
        return Err(s3_error(resp).await);
    }
    // An error may come with a 200, once the answer has started (as S3's).
    let answer = resp.into_body().collect().await.map(|b| b.to_bytes())?;
    if String::from_utf8_lossy(&answer).contains("<Error>") {
        let mut resp = hyper::Response::new(http_body_util::Full::new(answer));
        *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        return Err(s3_error(resp).await);
    }
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod e2e {
    use serde_json::{Value, json};

    use super::super::e2e::{Browser, console_of, signed_in};
    use super::*;
    use crate::e2e::{BUCKET, kms_node, node_with};

    async fn node() -> Option<Arc<App>> {
        node_with(crate::packer::Config::default(), None).await
    }

    /// Sends `body` to `path` with `method`: the status.
    async fn status(browser: &mut Browser, method: &str, path: &str, body: Value) -> StatusCode {
        browser.send(method, path, Some(body)).await.0
    }

    /// Object Lock, Object Ownership and ACLs, logging and versioning,
    /// through S3's handlers, and as S3 refuses them.
    #[tokio::test]
    async fn edits_bucket_settings() {
        let Some(app) = node().await else { return };
        let console = console_of(&app);
        let mut admin = signed_in(&console, "admin", true).await;
        let path = |what: &str| format!("/api/buckets/{BUCKET}/{what}");

        // Default encryption needs a KMS, which this node hasn't.
        let (status_, body) = admin.send("GET", &path("encryption"), None).await;
        assert_eq!(status_, StatusCode::OK);
        assert_eq!(
            body,
            json!({ "configuration": null, "kms": false, "sse_s3": false })
        );
        let sse_s3 = json!({ "algorithm": "AES256" });
        let (status_, body) = admin.send("PUT", &path("encryption"), Some(sse_s3)).await;
        assert_eq!(status_, StatusCode::BAD_REQUEST, "{body}");

        // Object Lock only on a versioned bucket.
        let (_, lock) = admin.send("GET", &path("object-lock"), None).await;
        assert_eq!(lock, json!({ "enabled": false, "default_retention": null }));
        let retention = json!({ "default_retention": { "mode": "GOVERNANCE", "days": 2 } });
        assert_eq!(
            status(&mut admin, "PUT", &path("object-lock"), retention.clone()).await,
            StatusCode::CONFLICT
        );
        let enabled = json!({ "status": "Enabled" });
        assert_eq!(
            status(&mut admin, "PUT", &path("versioning"), enabled).await,
            StatusCode::NO_CONTENT
        );
        let (_, versioning) = admin.send("GET", &path("versioning"), None).await;
        assert_eq!(
            versioning,
            json!({ "status": "enabled", "mfa_delete": null })
        );
        assert_eq!(
            status(&mut admin, "PUT", &path("object-lock"), retention).await,
            StatusCode::NO_CONTENT
        );
        let (_, lock) = admin.send("GET", &path("object-lock"), None).await;
        assert_eq!(
            lock,
            json!({ "enabled": true, "default_retention": { "mode": "GOVERNANCE", "days": 2, "years": null } })
        );
        for bad in [
            json!({ "default_retention": { "mode": "GOVERNANCE", "days": 2, "years": 1 } }),
            json!({ "default_retention": { "mode": "FOREVER", "days": 2 } }),
            json!({ "default_retention": { "mode": "COMPLIANCE", "years": 101 } }),
        ] {
            let (status_, body) = admin.send("PUT", &path("object-lock"), Some(bad)).await;
            assert_eq!(status_, StatusCode::BAD_REQUEST, "{body}");
        }
        assert_eq!(
            status(&mut admin, "PUT", &path("object-lock"), json!({})).await,
            StatusCode::NO_CONTENT
        );
        let (_, lock) = admin.send("GET", &path("object-lock"), None).await;
        assert_eq!(lock, json!({ "enabled": true, "default_retention": null }));

        // ACLs, once Object Ownership enables them.
        let (_, acl) = admin.send("GET", &path("acl"), None).await;
        let owner = acl["acl"]["owner"].as_str().unwrap().to_owned();
        let private =
            json!([{ "grantee_type": "account", "grantee": owner, "permission": "FULL_CONTROL" }]);
        assert_eq!(acl["acl"]["grants"], private);
        let logs_may_write = json!({ "grants": [
            { "grantee_type": "account", "grantee": owner, "permission": "FULL_CONTROL" },
            { "grantee_type": "group", "grantee": "LogDelivery", "permission": "WRITE" },
        ] });
        let enforced = json!({ "ownership": "BucketOwnerEnforced" });
        assert_eq!(
            status(&mut admin, "PUT", &path("ownership"), enforced.clone()).await,
            StatusCode::NO_CONTENT
        );
        let (status_, body) = admin
            .send("PUT", &path("acl"), Some(logs_may_write.clone()))
            .await;
        assert_eq!(status_, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("ACLs"), "{body}");
        let writer = json!({ "ownership": "ObjectWriter" });
        assert_eq!(
            status(&mut admin, "PUT", &path("ownership"), writer).await,
            StatusCode::NO_CONTENT
        );
        let (_, ownership) = admin.send("GET", &path("ownership"), None).await;
        assert_eq!(ownership, json!({ "ownership": "ObjectWriter" }));
        assert_eq!(
            status(&mut admin, "PUT", &path("acl"), logs_may_write).await,
            StatusCode::NO_CONTENT
        );
        let (_, acl) = admin.send("GET", &path("acl"), None).await;
        assert_eq!(acl["enabled"], true);
        assert_eq!(acl["acl"]["grants"][1]["grantee"], "LogDelivery");
        for bad in [
            json!({ "grantee_type": "group", "grantee": "Everyone", "permission": "READ" }),
            json!({ "grantee_type": "account", "grantee": "999999999999", "permission": "READ" }),
            json!({ "grantee_type": "account", "grantee": owner, "permission": "EVERYTHING" }),
        ] {
            let (status_, body) = admin
                .send("PUT", &path("acl"), Some(json!({ "grants": [bad] })))
                .await;
            assert_eq!(status_, StatusCode::BAD_REQUEST, "{body}");
        }
        // ACLs can't be disabled while the bucket's grants others anything.
        assert_eq!(
            status(&mut admin, "PUT", &path("ownership"), enforced.clone()).await,
            StatusCode::BAD_REQUEST
        );
        let only_owner = json!({ "grants": private });
        assert_eq!(
            status(&mut admin, "PUT", &path("acl"), only_owner).await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            status(&mut admin, "PUT", &path("ownership"), enforced).await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            admin.send("DELETE", &path("ownership"), None).await.0,
            StatusCode::NO_CONTENT
        );
        let (_, ownership) = admin.send("GET", &path("ownership"), None).await;
        assert_eq!(ownership, json!({ "ownership": null }));

        // Server access logging, into a bucket of the same account.
        let (_, logging) = admin.send("GET", &path("logging"), None).await;
        assert_eq!(logging, json!({ "configuration": null }));
        assert_eq!(
            status(
                &mut admin,
                "POST",
                "/api/buckets",
                json!({ "name": "logs" })
            )
            .await,
            StatusCode::CREATED
        );
        let config = json!({
            "target_bucket": "logs", "target_prefix": "access/",
            "key_format": "PartitionedPrefix", "date_source": "DeliveryTime",
        });
        assert_eq!(
            status(&mut admin, "PUT", &path("logging"), config.clone()).await,
            StatusCode::NO_CONTENT
        );
        let (_, logging) = admin.send("GET", &path("logging"), None).await;
        assert_eq!(logging, json!({ "configuration": config }));
        let nowhere = json!({ "target_bucket": "nope", "target_prefix": "" });
        let (status_, body) = admin.send("PUT", &path("logging"), Some(nowhere)).await;
        assert_eq!(status_, StatusCode::BAD_REQUEST);
        assert!(
            body["error"].as_str().unwrap().contains("does not exist"),
            "{body}"
        );
        let bad = json!({ "target_bucket": "logs", "key_format": "Shuffled" });
        assert_eq!(
            status(&mut admin, "PUT", &path("logging"), bad).await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            admin.send("DELETE", &path("logging"), None).await.0,
            StatusCode::NO_CONTENT
        );
        let (_, logging) = admin.send("GET", &path("logging"), None).await;
        assert_eq!(logging, json!({ "configuration": null }));

        // Each is its operation's action.
        let mut nobody = signed_in(&console, "nobody", false).await;
        for (what, action) in [
            ("encryption", "s3:GetEncryptionConfiguration"),
            ("object-lock", "s3:GetBucketObjectLockConfiguration"),
            ("ownership", "s3:GetBucketOwnershipControls"),
            ("acl", "s3:GetBucketAcl"),
            ("logging", "s3:GetBucketLogging"),
            ("versioning", "s3:GetBucketVersioning"),
        ] {
            let (status_, body) = nobody.send("GET", &path(what), None).await;
            assert_eq!(status_, StatusCode::FORBIDDEN, "{what}");
            assert!(body["error"].as_str().unwrap().contains(action), "{body}");
        }
        for (method, what, body, action) in [
            (
                "PUT",
                "encryption",
                json!({ "algorithm": "AES256" }),
                "s3:PutEncryptionConfiguration",
            ),
            (
                "DELETE",
                "encryption",
                Value::Null,
                "s3:PutEncryptionConfiguration",
            ),
            (
                "PUT",
                "object-lock",
                json!({}),
                "s3:PutBucketObjectLockConfiguration",
            ),
            (
                "PUT",
                "ownership",
                json!({ "ownership": "ObjectWriter" }),
                "s3:PutBucketOwnershipControls",
            ),
            ("PUT", "acl", json!({ "grants": [] }), "s3:PutBucketAcl"),
            (
                "PUT",
                "logging",
                json!({ "target_bucket": "logs" }),
                "s3:PutBucketLogging",
            ),
        ] {
            let (status_, answer) = nobody.send(method, &path(what), Some(body)).await;
            assert_eq!(status_, StatusCode::FORBIDDEN, "{method} {what}");
            assert!(
                answer["error"].as_str().unwrap().contains(action),
                "{answer}"
            );
        }
        // Any identity may read the classes' names.
        let (status_, classes) = nobody.send("GET", "/api/storage-classes", None).await;
        assert_eq!(status_, StatusCode::OK);
        assert_eq!(classes, json!([{ "name": "STANDARD", "rank": 0 }]));
    }

    /// Default encryption, with a KMS: SSE-S3, SSE-KMS under a key it has,
    /// and the bucket list tells which.
    #[tokio::test]
    async fn edits_default_encryption() {
        let Some(app) = kms_node().await else { return };
        let mut admin = signed_in(&console_of(&app), "admin", true).await;
        let path = format!("/api/buckets/{BUCKET}/encryption");
        let listed = |buckets: Value| {
            let bucket = buckets
                .as_array()
                .unwrap()
                .iter()
                .find(|b| b["name"] == BUCKET)
                .unwrap()
                .clone();
            (
                bucket["default_encryption"].clone(),
                bucket["default_kms_key"].clone(),
            )
        };
        let sse_s3 = json!({ "algorithm": "AES256", "kms_key_id": null, "bucket_key": false });
        assert_eq!(
            status(&mut admin, "PUT", &path, sse_s3.clone()).await,
            StatusCode::NO_CONTENT
        );
        let (_, got) = admin.send("GET", &path, None).await;
        assert_eq!(
            got,
            json!({ "configuration": sse_s3, "kms": true, "sse_s3": true })
        );
        let (_, buckets) = admin.send("GET", "/api/buckets", None).await;
        assert_eq!(listed(buckets), (json!("SSE-S3"), Value::Null));

        let kms = json!({ "algorithm": "aws:kms", "kms_key_id": "cairn-test", "bucket_key": true });
        assert_eq!(
            status(&mut admin, "PUT", &path, kms).await,
            StatusCode::NO_CONTENT
        );
        let (_, got) = admin.send("GET", &path, None).await;
        assert_eq!(
            got["configuration"],
            json!({ "algorithm": "aws:kms", "kms_key_id": "transit/cairn-test", "bucket_key": true })
        );
        let (_, buckets) = admin.send("GET", "/api/buckets", None).await;
        assert_eq!(
            listed(buckets),
            (json!("SSE-KMS"), json!("transit/cairn-test"))
        );

        for bad in [
            json!({ "algorithm": "aws:kms" }),
            json!({ "algorithm": "AES256", "kms_key_id": "cairn-test" }),
            json!({ "algorithm": "aws:kms", "kms_key_id": "../key" }),
            json!({ "algorithm": "DES" }),
        ] {
            let (status_, body) = admin.send("PUT", &path, Some(bad)).await;
            assert_eq!(status_, StatusCode::BAD_REQUEST, "{body}");
        }
        assert_eq!(
            admin.send("DELETE", &path, None).await.0,
            StatusCode::NO_CONTENT
        );
        let (_, got) = admin.send("GET", &path, None).await;
        assert_eq!(got["configuration"], Value::Null);
    }

    /// A version's class, checksum, retention, legal hold and ACL; and
    /// uploads and copies in a class.
    #[tokio::test]
    async fn edits_object_settings() {
        let Some(app) = node().await else { return };
        // A colder class, in the same pool.
        app.pool
            .get()
            .await
            .unwrap()
            .execute(
                "INSERT INTO storage_classes (name, pool, rank) VALUES ('COLD', 'default', -10)",
                &[],
            )
            .await
            .unwrap();
        crate::refresh_settings(&app).await.unwrap();
        let console = console_of(&app);
        let mut admin = signed_in(&console, "admin", true).await;
        let (_, classes) = admin.send("GET", "/api/storage-classes", None).await;
        assert_eq!(
            classes,
            json!([{ "name": "STANDARD", "rank": 0 }, { "name": "COLD", "rank": -10 }])
        );

        let bucket = "locked";
        let create = json!({ "name": bucket, "object_lock": true });
        assert_eq!(
            status(&mut admin, "POST", "/api/buckets", create).await,
            StatusCode::CREATED
        );
        let object =
            |what: &str, query: &str| format!("/api/buckets/{bucket}/object{what}?key=k{query}");
        // Uploaded in a class; one there's none of is refused, as is a
        // multipart upload in one.
        let nope = object("", "&storage_class=NOPE");
        assert_eq!(
            status(&mut admin, "PUT", &nope, json!("data")).await,
            StatusCode::BAD_REQUEST
        );
        let started = json!({ "key": "k", "storage_class": "NOPE" });
        let uploads = format!("/api/buckets/{bucket}/uploads");
        assert_eq!(
            status(&mut admin, "POST", &uploads, started).await,
            StatusCode::BAD_REQUEST
        );
        let cold = object("", "&storage_class=COLD");
        assert_eq!(
            status(&mut admin, "PUT", &cold, json!("data")).await,
            StatusCode::NO_CONTENT
        );

        let (status_, details) = admin.send("GET", &object("/details", ""), None).await;
        assert_eq!(status_, StatusCode::OK);
        assert_eq!(
            (
                &details["object_lock"],
                &details["acls_enabled"],
                &details["may_bypass_governance"]
            ),
            (&json!(true), &json!(false), &json!(true))
        );
        let first = &details["versions"][0];
        let version = first["version_id"].as_str().unwrap().to_owned();
        assert_eq!(first["storage_class"], "COLD");
        assert_eq!(first["checksum"]["kind"], "FULL_OBJECT");
        assert!(first["checksum"]["value"].is_string(), "{first}");
        assert_eq!(
            (&first["retention"], &first["legal_hold"]),
            (&Value::Null, &Value::Null)
        );
        let on_version = |what: &str| object(what, &format!("&version={version}"));

        // Into another class: a new version, of the same data.
        let class = |name: &str| json!({ "storage_class": name });
        let change = object("/storage-class", "");
        assert_eq!(
            status(&mut admin, "POST", &change, class("STANDARD")).await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            status(&mut admin, "POST", &change, class("NOPE")).await,
            StatusCode::BAD_REQUEST
        );
        let (_, details) = admin.send("GET", &object("/details", ""), None).await;
        let classes: Vec<&Value> = details["versions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| &v["storage_class"])
            .collect();
        assert_eq!(classes, [&json!("STANDARD"), &json!("COLD")]);
        assert_eq!(
            details["versions"][0]["checksum"],
            details["versions"][1]["checksum"]
        );
        let uri = format!("/api/buckets/{bucket}/download?key=k");
        assert_eq!(admin.request("GET", &uri, None).await.2, b"\"data\"");

        // A legal hold keeps the version.
        let hold = |on: bool| json!({ "on": on });
        assert_eq!(
            status(&mut admin, "PUT", &on_version("/legal-hold"), hold(true)).await,
            StatusCode::NO_CONTENT
        );
        let (_, details) = admin.send("GET", &object("/details", ""), None).await;
        assert_eq!(details["versions"][1]["legal_hold"], true);
        let (status_, _) = admin.send("DELETE", &on_version(""), None).await;
        assert!(status_.is_client_error(), "{status_}");
        assert_eq!(
            status(&mut admin, "PUT", &on_version("/legal-hold"), hold(false)).await,
            StatusCode::NO_CONTENT
        );

        // A retention may only be lengthened, but GOVERNANCE's with the
        // bypass, which the admin is allowed.
        let until = |days: u64| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            crate::sessions::iso(now + days * 86_400)
        };
        let ten = until(10);
        let retain = |until: &str, bypass: bool| json!({ "mode": "GOVERNANCE", "retain_until": until, "bypass_governance": bypass });
        let retention = on_version("/retention");
        assert_eq!(
            status(&mut admin, "PUT", &retention, retain(&ten, false)).await,
            StatusCode::NO_CONTENT
        );
        let (_, details) = admin.send("GET", &object("/details", ""), None).await;
        assert_eq!(
            details["versions"][1]["retention"],
            json!({ "mode": "GOVERNANCE", "retain_until": ten.replace('Z', ".000Z") })
        );
        let five = until(5);
        assert_eq!(
            status(&mut admin, "PUT", &retention, retain(&five, false)).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(&mut admin, "PUT", &retention, retain(&five, true)).await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            status(
                &mut admin,
                "PUT",
                &retention,
                retain("2001-01-01T00:00:00Z", false)
            )
            .await,
            StatusCode::BAD_REQUEST
        );
        let none = json!({ "mode": null, "retain_until": null, "bypass_governance": true });
        assert_eq!(
            status(&mut admin, "PUT", &retention, none).await,
            StatusCode::NO_CONTENT
        );
        let (_, details) = admin.send("GET", &object("/details", ""), None).await;
        assert_eq!(details["versions"][1]["retention"], Value::Null);

        // An object's ACL, once the bucket has ACLs enabled.
        let grants = json!({ "grants": [
            { "grantee_type": "group", "grantee": "LogDelivery", "permission": "READ" },
        ] });
        assert_eq!(
            status(&mut admin, "PUT", &on_version("/acl"), grants.clone()).await,
            StatusCode::BAD_REQUEST
        );
        let writer = json!({ "ownership": "ObjectWriter" });
        let ownership = format!("/api/buckets/{bucket}/ownership");
        assert_eq!(
            status(&mut admin, "PUT", &ownership, writer).await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            status(&mut admin, "PUT", &on_version("/acl"), grants).await,
            StatusCode::NO_CONTENT
        );
        let (_, details) = admin.send("GET", &object("/details", ""), None).await;
        assert_eq!(details["acls_enabled"], true);
        assert_eq!(
            details["versions"][1]["acl"]["grants"],
            json!([{ "grantee_type": "group", "grantee": "LogDelivery", "permission": "READ" }])
        );
        assert_eq!(
            details["versions"][0]["acl"]["grants"][0]["permission"],
            "FULL_CONTROL"
        );

        // Each is its operation's action.
        let mut nobody = signed_in(&console, "nobody", false).await;
        let (status_, body) = nobody.send("GET", &object("/details", ""), None).await;
        assert_eq!(status_, StatusCode::FORBIDDEN);
        assert!(
            body["error"].as_str().unwrap().contains("s3:GetObject"),
            "{body}"
        );
        for (what, body, action) in [
            ("/legal-hold", hold(true), "s3:PutObjectLegalHold"),
            ("/retention", retain(&ten, false), "s3:PutObjectRetention"),
            ("/acl", json!({ "grants": [] }), "s3:PutObjectVersionAcl"),
        ] {
            let (status_, answer) = nobody.send("PUT", &on_version(what), Some(body)).await;
            assert_eq!(status_, StatusCode::FORBIDDEN, "{what}");
            assert!(
                answer["error"].as_str().unwrap().contains(action),
                "{answer}"
            );
        }
        let (status_, answer) = nobody.send("POST", &change, Some(class("COLD"))).await;
        assert_eq!(status_, StatusCode::FORBIDDEN);
        assert!(
            answer["error"].as_str().unwrap().contains("s3:PutObject"),
            "{answer}"
        );
    }
}
