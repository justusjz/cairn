//! A bucket's policy: PutBucketPolicy, GetBucketPolicy, DeleteBucketPolicy
//! and GetBucketPolicyStatus (`?policy`, `?policyStatus`), as S3 answers them
//! (probed; see `plans/policies.md`). What the policy decides is `access`'s.
//! The superadmin can always read and delete one (`cairn bucket-policy`), as
//! an AWS account's root user can, so that one that denies everyone can't
//! lock its bucket for good.

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

/// `text` as `bucket`'s policy would be kept (normalized), if S3 would take
/// it: a valid bucket policy, whose users and accounts exist.
pub async fn check(client: &Object, bucket: &str, text: &str) -> anyhow::Result<Result<String, Refused>> {
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
    Ok(Ok(policy.normalized().to_owned()))
}

/// The bucket's policy, normalized: `None` if there's no such bucket,
/// `Some(None)` if it has none.
async fn stored(client: &Object, bucket: &str) -> anyhow::Result<Option<Option<String>>> {
    let row = client.query_opt_cached("SELECT policy FROM buckets WHERE name = $1", &[&bucket]).await?;
    Ok(row.map(|row| row.get(0)))
}

/// Sets (`None`: deletes) the bucket's policy (`cairn_set_policy`). Whether
/// the bucket exists.
async fn set(client: &Object, bucket: &str, policy: Option<&str>) -> anyhow::Result<bool> {
    Ok(client.query_one_cached("SELECT pg_temp.cairn_set_policy($1, $2)", &[&bucket, &policy]).await?.get(0))
}

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
    Ok(match stored(&app.pool.get().await?, bucket).await? {
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
        true => empty(StatusCode::NO_CONTENT),
        false => no_such_bucket(),
    })
}

/// DeleteBucketPolicy: `DELETE /{bucket}?policy`. 204, with a policy or
/// without (probed).
pub async fn delete_bucket_policy(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    Ok(match set(&app.pool.get().await?, bucket, None).await? {
        true => empty(StatusCode::NO_CONTENT),
        false => no_such_bucket(),
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
        BucketPolicyCommand::Get { bucket } => match stored(&client, &bucket).await? {
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
            if !set(&client, &bucket, Some(&policy)).await? {
                anyhow::bail!("no bucket named {bucket:?}");
            }
        }
        BucketPolicyCommand::Delete { bucket } => {
            if !set(&client, &bucket, None).await? {
                anyhow::bail!("no bucket named {bucket:?}");
            }
        }
    }
    Ok(())
}
