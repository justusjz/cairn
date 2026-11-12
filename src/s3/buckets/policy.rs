//! A bucket's policy: PutBucketPolicy, GetBucketPolicy, DeleteBucketPolicy
//! and GetBucketPolicyStatus (`?policy`, `?policyStatus`), as S3 answers them
//! (probed; see `plans/policies.md`). What the policy decides is `access`'s.
//! The superadmin can always read and delete one (`cairn bucket-policy`), as
//! an AWS account's root user can, so that one that denies everyone can't
//! lock its bucket for good.

use std::collections::HashMap;

use clap::{Args, Subcommand};
use deadpool_postgres::Object;
use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::{
    App,
    db::Cached,
    policy::{Kind, Policy},
    s3::util::{format_s3_error, xml_ok},
};

/// Why a policy can't be the bucket's: S3's code and message.
pub struct Refused {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

/// A policy as it's to be kept: normalized, and whether it's public (which
/// a public access block may refuse: see `public_access`).
pub struct Checked {
    pub normalized: String,
    pub public: bool,
}

/// `text` as `bucket`'s policy would be kept, if S3 would take it: a valid
/// bucket policy, whose users and accounts exist.
pub async fn check(client: &Object, bucket: &str, text: &str) -> anyhow::Result<Result<Checked, Refused>> {
    let policy = match Policy::parse(text, Kind::Bucket(bucket)) {
        Ok(policy) => policy,
        Err(invalid) => {
            let status = match invalid.code {
                "NotImplemented" => StatusCode::NOT_IMPLEMENTED,
                _ => StatusCode::BAD_REQUEST,
            };
            return Ok(Err(Refused { status, code: invalid.code, message: invalid.message }));
        }
    };
    let account = crate::roles::account(client).await?;
    let invalid_principal = || {
        Ok(Err(Refused {
            status: StatusCode::BAD_REQUEST,
            code: "MalformedPolicy",
            message: "Invalid principal in policy".to_owned(),
        }))
    };
    // There's one account (until tenants), and its users.
    if policy.accounts().any(|a| a != account) {
        return invalid_principal();
    }
    for (user_account, user) in policy.users() {
        let exists = client.query_opt_cached("SELECT 1 FROM roles WHERE name = $1", &[&user]).await?.is_some();
        if user_account != account || !exists {
            return invalid_principal();
        }
    }
    Ok(Ok(Checked { normalized: policy.normalized().to_owned(), public: policy.is_public() }))
}

/// The bucket's policy, normalized: `None` if there's no such bucket,
/// `Some(None)` if it has none.
async fn stored(client: &Object, bucket: &str) -> anyhow::Result<Option<Option<String>>> {
    let row = client.query_opt_cached("SELECT policy FROM buckets WHERE name = $1", &[&bucket]).await?;
    Ok(row.map(|row| row.get(0)))
}

/// The bucket's policy as GetBucketPolicy shows it: as it's kept, but each
/// user it names that's gone since it was set named by its ID, as S3 shows
/// one (a user made with the name since isn't the one it names: see
/// `db::PRINCIPAL_IDS`). `None` if there's no such bucket, `Some(None)` if
/// it has none.
pub async fn shown(client: &Object, bucket: &str) -> anyhow::Result<Option<Option<String>>> {
    let row = client
        .query_opt_cached(
            "SELECT b.policy,
                    (SELECT coalesce(jsonb_object_agg(p.key, p.value), '{}'::jsonb)
                     FROM jsonb_each_text(b.policy_principals) p
                     WHERE NOT EXISTS (SELECT 1 FROM roles r WHERE r.id::text = p.value))::text
             FROM buckets b WHERE b.name = $1",
            &[&bucket],
        )
        .await?;
    let Some(row) = row else { return Ok(None) };
    let Some(text) = row.get::<_, Option<String>>(0) else { return Ok(Some(None)) };
    let gone: HashMap<String, String> = serde_json::from_str(row.get(1))?;
    if gone.is_empty() {
        return Ok(Some(Some(text)));
    }
    let kind = Kind::Bucket(bucket);
    let policy = Policy::parse(&text, kind)
        .map_err(|e| anyhow::anyhow!("bucket {bucket}'s policy doesn't parse: {}", e.message))?;
    Ok(Some(Some(policy.shown(kind, &gone))))
}

/// What setting a bucket's policy did.
#[derive(Debug, PartialEq, Eq)]
pub enum Set {
    Set,
    /// It's public, and public policies are blocked (see `public_access`).
    Blocked,
    NoSuchBucket,
}

/// Sets (`None`: deletes) the bucket's policy (`cairn_set_policy`), unless
/// it's public and that's blocked.
pub async fn set(client: &Object, bucket: &str, policy: Option<&Checked>) -> anyhow::Result<Set> {
    let (text, public) = policy.map_or((None, false), |p| (Some(p.normalized.as_str()), p.public));
    let status: String = client
        .query_one_cached("SELECT pg_temp.cairn_set_policy($1, $2, $3)", &[&bucket, &text, &public])
        .await?
        .get(0);
    Ok(match status.as_str() {
        "set" => Set::Set,
        "blocked" => Set::Blocked,
        "no_such_bucket" => Set::NoSuchBucket,
        other => anyhow::bail!("cairn_set_policy: unexpected status {other}"),
    })
}

/// Why a public policy was refused.
pub const BLOCKED: &str = "public policies are blocked by the BlockPublicPolicy block public access setting \
                           (the bucket's, or the cluster's block-public-policy)";

fn no_such_bucket() -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::NOT_FOUND, "NoSuchBucket", "the specified bucket does not exist")
}

fn no_such_policy() -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::NOT_FOUND, "NoSuchBucketPolicy", "The bucket policy does not exist")
}

fn empty(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder().status(status).body(Full::new(Bytes::new())).unwrap()
}

/// GetBucketPolicy: `GET /{bucket}?policy`: the policy, as S3 keeps it.
pub async fn get_bucket_policy(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    Ok(match shown(&app.pool.get().await?, bucket).await? {
        None => no_such_bucket(),
        Some(None) => no_such_policy(),
        Some(Some(policy)) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(policy)))
            .unwrap(),
    })
}

/// PutBucketPolicy: `PUT /{bucket}?policy` with the policy (JSON), which S3
/// takes without an integrity header (probed). 204, as in S3.
pub async fn put_bucket_policy(app: &App, bucket: &str, body: Bytes) -> anyhow::Result<Response<Full<Bytes>>> {
    let client = app.pool.get().await?;
    let Ok(text) = std::str::from_utf8(&body) else {
        return Ok(format_s3_error(
            StatusCode::BAD_REQUEST,
            "MalformedPolicy",
            "Policies must be valid JSON and the first byte must be '{'",
        ));
    };
    let policy = match check(&client, bucket, text).await? {
        Ok(policy) => policy,
        Err(refused) => return Ok(format_s3_error(refused.status, refused.code, &refused.message)),
    };
    Ok(match set(&client, bucket, Some(&policy)).await? {
        Set::Set => empty(StatusCode::NO_CONTENT),
        Set::Blocked => format_s3_error(StatusCode::FORBIDDEN, "AccessDenied", BLOCKED),
        Set::NoSuchBucket => no_such_bucket(),
    })
}

/// DeleteBucketPolicy: `DELETE /{bucket}?policy`. 204, with a policy or
/// without (probed).
pub async fn delete_bucket_policy(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    Ok(match set(&app.pool.get().await?, bucket, None).await? {
        Set::NoSuchBucket => no_such_bucket(),
        _ => empty(StatusCode::NO_CONTENT),
    })
}

/// GetBucketPolicyStatus: `GET /{bucket}?policyStatus`: whether the policy
/// makes the bucket public (see `Policy::is_public`).
pub async fn get_bucket_policy_status(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    Ok(match stored(&app.pool.get().await?, bucket).await? {
        None => no_such_bucket(),
        Some(None) => no_such_policy(),
        Some(Some(text)) => {
            let public = Policy::parse(&text, Kind::Bucket(bucket))
                .map_err(|e| anyhow::anyhow!("bucket {bucket}'s policy doesn't parse: {}", e.message))?
                .is_public();
            xml_ok(format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                 <PolicyStatus xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><IsPublic>{public}</IsPublic></PolicyStatus>"
            ))
        }
    })
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct BucketPolicyArgs {
    /// PostgreSQL connection string (the same one the nodes use).
    #[arg(long, env = "CAIRN_DATABASE", hide_env_values = true)]
    database: String,
    #[command(subcommand)]
    command: BucketPolicyCommand,
}

#[derive(Subcommand, Debug)]
enum BucketPolicyCommand {
    /// Print a bucket's policy.
    Get { bucket: String },
    /// Set a bucket's policy to the JSON in `file` (`-`: stdin).
    Put { bucket: String, file: String },
    /// Delete a bucket's policy, whatever it says.
    Delete { bucket: String },
}

/// `cairn bucket-policy …`: a bucket's policy, straight against the
/// database, whatever the policy says about who may change it.
pub async fn bucket_policy_main(args: BucketPolicyArgs) -> anyhow::Result<()> {
    let pool = crate::db::connect(&args.database).await?;
    let client = pool.get().await?;
    match args.command {
        BucketPolicyCommand::Get { bucket } => match shown(&client, &bucket).await? {
            None => anyhow::bail!("no bucket named {bucket:?}"),
            Some(None) => anyhow::bail!("{bucket:?} has no policy"),
            Some(Some(policy)) => println!("{policy}"),
        },
        BucketPolicyCommand::Put { bucket, file } => {
            let text = match file.as_str() {
                "-" => std::io::read_to_string(std::io::stdin())?,
                path => std::fs::read_to_string(path)?,
            };
            let policy = match check(&client, &bucket, &text).await? {
                Ok(policy) => policy,
                Err(refused) => anyhow::bail!("{}: {}", refused.code, refused.message),
            };
            match set(&client, &bucket, Some(&policy)).await? {
                Set::Set => {}
                Set::Blocked => anyhow::bail!(
                    "{BLOCKED}: turn the bucket's off first (DeletePublicAccessBlock, or on the dashboard), \
                     or the cluster's (cairn config set block-public-policy 0)"
                ),
                Set::NoSuchBucket => anyhow::bail!("no bucket named {bucket:?}"),
            }
        }
        BucketPolicyCommand::Delete { bucket } => {
            if set(&client, &bucket, None).await? == Set::NoSuchBucket {
                anyhow::bail!("no bucket named {bucket:?}");
            }
        }
    }
    Ok(())
}
