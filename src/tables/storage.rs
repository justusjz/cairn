//! Tables' storage: a bucket of each table's (`names::storage_name`, which
//! no S3 bucket's name can be), whose objects are the table's files, kept
//! as any bucket's are (blobs, erasure coding, the packer, storage classes,
//! backups). Clients read and write them through the S3 API, as the
//! table's (its `warehouseLocation`); what's different is in front of it
//! (`gate`):
//!
//! - **Operations.** Only those AWS has for table storage: GetObject,
//!   HeadObject, PutObject, the multipart ones and ListParts. Not listings,
//!   deletes or copies: only maintenance deletes a table's files. Not
//!   presigned, nor anonymous, nor signed with SigV2 (as directory buckets
//!   aren't: see `s3`). The bucket is in no listing of buckets.
//! - **Authorization.** As the table's, not a bucket's: a read is
//!   `s3tables:GetTableData`, a write `s3tables:PutTableData`, on the
//!   table's ARN, by the principal's policies and the table bucket's and
//!   table's (see `tables`). No S3 policy decides anything about it.
//! - **Headers.** Objects are stored in the table's storage class and
//!   encrypted as its encryption configuration says (with a KMS: without
//!   one, Cairn has no SSE-S3, and they're stored as they come). What a
//!   write may ask for is what AWS fixes: no ACL but
//!   `bucket-owner-full-control`, no storage class but `STANDARD`, no
//!   encryption but the table's, and no tags, Object Lock, SSE-C or
//!   website redirects.
//!
//! A deleted table's storage stays behind, refused to every request (its
//! table is none), until `purge` has deleted its objects and it.

use std::sync::Arc;
use std::time::Duration;

use deadpool_postgres::GenericClient;
use http_body_util::Full;
use hyper::{HeaderMap, Response, StatusCode, body::Bytes, header::HeaderValue};

use super::{Table, Target, resource_of};
use crate::{
    App,
    policy::Verdict,
    s3::{
        access::Access,
        actions::{Check, Operation},
        util::{format_s3_error, query_param, xml_escape},
    },
    users::Principal,
};

/// Makes table storage bucket `name`, of `account`, in a table's creation
/// (`tx`).
pub(super) async fn create(
    tx: &impl GenericClient,
    name: &str,
    account: &str,
) -> anyhow::Result<()> {
    tx.execute(
        "INSERT INTO buckets (name, account_id) VALUES ($1, $2)",
        &[&name, &account],
    )
    .await?;
    Ok(())
}

/// The S3 operations table storage takes, and whether each writes.
const OPERATIONS: &[(&str, bool)] = &[
    ("GetObject", false),
    ("HeadObject", false),
    ("ListParts", false),
    ("PutObject", true),
    ("CreateMultipartUpload", true),
    ("UploadPart", true),
    ("CompleteMultipartUpload", true),
    ("AbortMultipartUpload", true),
];

/// Headers a request to table storage may not have (by prefix), as they
/// ask for what it hasn't.
const REFUSED_HEADERS: &[&str] = &[
    "x-amz-tagging",
    "x-amz-object-lock-",
    "x-amz-server-side-encryption-customer-",
    "x-amz-copy-source-server-side-encryption-customer-",
    "x-amz-website-redirect-location",
    "x-amz-grant-",
];

fn refused(status: StatusCode, code: &str, message: &str) -> Response<Full<Bytes>> {
    format_s3_error(status, code, message)
}

/// Decides an S3 request on table storage `bucket`: refused (its answer),
/// or allowed, and then `access` allows its checks, and `headers` ask for
/// the table's storage class and encryption.
pub async fn gate(
    app: &Arc<App>,
    access: &mut Access,
    principal: Option<&Principal>,
    operation: &Operation,
    bucket: &str,
    query: &str,
    headers: &mut HeaderMap,
) -> anyhow::Result<Result<(), Response<Full<Bytes>>>> {
    let Some(principal) = principal else {
        return Ok(Err(refused(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "Access Denied",
        )));
    };
    if query_param(query, "X-Amz-Signature").is_some() || query_param(query, "Signature").is_some()
    {
        return Ok(Err(refused(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "Presigned URLs aren't supported for table storage.",
        )));
    }
    let Some(&(_, writes)) = OPERATIONS.iter().find(|(name, _)| *name == operation.name) else {
        return Ok(Err(refused(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "The specified method is not allowed against this resource.",
        )));
    };
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    for (name, _) in headers.iter() {
        if REFUSED_HEADERS.iter().any(|p| name.as_str().starts_with(p)) {
            return Ok(Err(refused(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                &format!("Table storage doesn't take the {name} header."),
            )));
        }
    }
    if header("x-amz-acl").is_some_and(|acl| acl != "bucket-owner-full-control") {
        return Ok(Err(refused(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "Table storage's objects' ACL is bucket-owner-full-control.",
        )));
    }
    if header("x-amz-storage-class").is_some_and(|class| class != "STANDARD") {
        return Ok(Err(refused(
            StatusCode::BAD_REQUEST,
            "InvalidStorageClass",
            "Table storage's objects are stored in the table's storage class: ask for STANDARD, or none.",
        )));
    }
    let Some((table_bucket, table)) = Table::by_storage(&app.pool.get().await?, bucket).await?
    else {
        return Ok(Err(refused(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
        )));
    };
    if let Some(algorithm) = header("x-amz-server-side-encryption")
        && algorithm != table.sse_algorithm
    {
        return Ok(Err(refused(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "Table storage's objects are encrypted as the table's encryption configuration says.",
        )));
    }
    let action = match writes {
        true => "s3tables:PutTableData",
        false => "s3tables:GetTableData",
    };
    let target = Target::Table {
        bucket: &table_bucket,
        table: &table,
    };
    let (on, context, resource) = resource_of(&target)?;
    if let Some((arn, account, policy)) = resource {
        access.set_resource(&arn, &account, policy);
    }
    let check = Check { action, on };
    match access.verdict_with(&check, &context) {
        Verdict::Allow => {}
        verdict => return Ok(Err(access.denied(&check, verdict))),
    }
    let _ = principal;
    // Allowed: the S3 checks are the table's.
    access.grant(bucket);
    if matches!(operation.name, "PutObject" | "CreateMultipartUpload") {
        set_storage(app, &table, headers);
    }
    Ok(Ok(()))
}

/// Makes a write ask for `table`'s storage class and encryption.
fn set_storage(app: &App, table: &Table, headers: &mut HeaderMap) {
    headers.remove("x-amz-storage-class");
    if table.storage_class != crate::classes::STANDARD
        && let Ok(class) = HeaderValue::from_str(&table.storage_class)
    {
        headers.insert("x-amz-storage-class", class);
    }
    headers.remove("x-amz-server-side-encryption");
    headers.remove("x-amz-server-side-encryption-aws-kms-key-id");
    let Some(kms) = &app.kms else {
        return;
    };
    match (table.sse_algorithm.as_str(), &table.kms_key) {
        ("aws:kms", Some(key)) => {
            if let Ok(id) = HeaderValue::from_str(&kms_key_id(key)) {
                headers.insert(
                    "x-amz-server-side-encryption",
                    HeaderValue::from_static("aws:kms"),
                );
                headers.insert("x-amz-server-side-encryption-aws-kms-key-id", id);
            }
        }
        _ if kms.sse_s3_key().is_some() => {
            headers.insert(
                "x-amz-server-side-encryption",
                HeaderValue::from_static("AES256"),
            );
        }
        _ => {}
    }
}

/// Cairn's key ID (`<mount>/<key>`) of a KMS key ARN as S3 Tables takes
/// them (`arn:aws:kms:<region>:<account>:key/<mount>/<key>`).
pub fn kms_key_id(arn: &str) -> String {
    arn.split_once(":key/").map_or(arn, |(_, id)| id).to_owned()
}

/// Whether a request's `checks` touch table storage other than `bucket`
/// (a copy's source, say), which only its own operations may.
pub fn reaches_storage(operation: &Operation, bucket: &str) -> bool {
    operation
        .checks
        .iter()
        .filter_map(|c| c.on.bucket())
        .any(|b| b != bucket && super::is_storage(b))
}

/// How often `run` looks for deleted tables' storage.
const PURGE_INTERVAL: Duration = Duration::from_secs(60);

/// Purges deleted tables' storage, forever.
pub async fn run(app: Arc<App>) {
    loop {
        tokio::time::sleep(PURGE_INTERVAL).await;
        let task_app = app.clone();
        let pass = tokio::spawn(async move { purge(&task_app).await });
        match pass.await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => eprintln!("tables: purged the storage of {n} deleted table(s)"),
            Ok(Err(e)) => eprintln!("tables: purging deleted tables' storage failed: {e:#}"),
            Err(e) => eprintln!("tables: purging deleted tables' storage panicked: {e}"),
        }
    }
}

/// Deletes the objects of deleted tables' storage, and then it; how many
/// it deleted. Storage some write still slips into stays for the next.
pub async fn purge(app: &Arc<App>) -> anyhow::Result<usize> {
    let orphans: Vec<String> = app
        .pool
        .get()
        .await?
        .query(
            "SELECT name FROM buckets b WHERE name LIKE '%--table-s3'
               AND NOT EXISTS (SELECT 1 FROM tables t WHERE t.storage = b.name)
             ORDER BY name LIMIT 100",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let mut purged = 0;
    for bucket in orphans {
        loop {
            let keys: Vec<String> = app
                .pool
                .get()
                .await?
                .query(
                    "SELECT DISTINCT key FROM objects WHERE bucket = $1 ORDER BY key LIMIT 1000",
                    &[&bucket],
                )
                .await?
                .iter()
                .map(|r| r.get(0))
                .collect();
            if keys.is_empty() {
                break;
            }
            let body: String = keys
                .iter()
                .map(|k| format!("<Object><Key>{}</Key></Object>", xml_escape(k)))
                .collect();
            let body = format!("<Delete><Quiet>true</Quiet>{body}</Delete>");
            let response = crate::s3::objects::delete::delete_objects(
                app,
                &bucket,
                Bytes::from(body),
                &|_, _| true,
                &|_| false,
                crate::mfa::Presented::Absent,
            )
            .await?;
            if !response.status().is_success() {
                anyhow::bail!("deleting {bucket}'s objects: {}", response.status());
            }
        }
        let response = crate::s3::buckets::delete::delete_bucket(app, &bucket).await?;
        if response.status().is_success() {
            purged += 1;
        }
    }
    Ok(purged)
}
