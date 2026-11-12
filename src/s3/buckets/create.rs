use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::db::Cached;
use crate::{App, s3::util::format_s3_error};

pub enum Creation {
    Created,
    /// There already is a bucket of that name, the account's own.
    Exists,
    /// There is one of another account (names are global, as in S3).
    OwnedByOther,
    /// The account is the operator's, which owns no buckets.
    Operator,
    /// The name isn't a valid bucket name.
    InvalidName,
}

/// Prefixes and suffixes S3 reserves, which no bucket name may have.
const RESERVED_PREFIXES: [&str; 3] = ["xn--", "sthree-", "amzn-s3-demo-"];
const RESERVED_SUFFIXES: [&str; 5] = ["-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"];

/// Whether `name` is a valid S3 bucket name: 3 to 63 lowercase letters, digits,
/// dots and hyphens, starting and ending with a letter or digit, not formatted
/// like an IP address, and without a prefix or suffix S3 reserves. No bucket
/// name has a `_`, so paths starting with one never name a bucket.
pub fn valid_bucket_name(name: &str) -> bool {
    let edge = |c: Option<char>| c.is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let ip_address = name.split('.').count() == 4
        && name
            .split('.')
            .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    (3..=63).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
        && edge(name.chars().next())
        && edge(name.chars().last())
        && !name.contains("..")
        && !ip_address
        && !RESERVED_PREFIXES.iter().any(|p| name.starts_with(p))
        && !RESERVED_SUFFIXES.iter().any(|s| name.ends_with(s))
}

/// Creates a bucket of account `account` (its ID; `None`: the first tenant
/// account). Shared by CreateBucket and the dashboard.
pub async fn create(app: &App, name: &str, account: Option<&str>) -> anyhow::Result<Creation> {
    if !valid_bucket_name(name) {
        return Ok(Creation::InvalidName);
    }
    let client = app.pool.get().await?;
    let account = match account {
        Some(account) => account.to_owned(),
        None => crate::roles::account(&client).await?,
    };
    let operator: bool = client
        .query_opt_cached("SELECT operator FROM accounts WHERE id = $1", &[&account])
        .await?
        .is_some_and(|row| row.get(0));
    if operator {
        return Ok(Creation::Operator);
    }
    let inserted = client
        .execute_cached(
            "INSERT INTO buckets (name, account_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            &[&name, &account],
        )
        .await?;
    if inserted == 1 {
        return Ok(Creation::Created);
    }
    let owner: Option<String> = client
        .query_opt_cached("SELECT account_id FROM buckets WHERE name = $1", &[&name])
        .await?
        .map(|row| row.get(0));
    Ok(match owner {
        Some(owner) if owner != account => Creation::OwnedByOther,
        _ => Creation::Exists,
    })
}

/// CreateBucket: `PUT /{bucket}`, by a user of `account`. Creating a bucket
/// that exists succeeds, as it does for its owner in S3's us-east-1; another
/// account's is BucketAlreadyExists, as in S3.
pub async fn create_bucket(app: &App, bucket: &str, account: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    match create(app, bucket, Some(account)).await? {
        Creation::InvalidName => {
            return Ok(format_s3_error(StatusCode::BAD_REQUEST, "InvalidBucketName", "the specified bucket is not valid"));
        }
        Creation::OwnedByOther => {
            return Ok(format_s3_error(
                StatusCode::CONFLICT,
                "BucketAlreadyExists",
                "The requested bucket name is not available. The bucket namespace is shared by all users of the system. \
                 Please select a different name and try again.",
            ));
        }
        Creation::Operator => {
            return Ok(format_s3_error(StatusCode::FORBIDDEN, "AccessDenied", "the operator account owns no buckets"));
        }
        Creation::Created | Creation::Exists => {}
    }
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("location", format!("/{bucket}"))
        .body(Full::new(Bytes::new()))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_bucket_names() {
        for name in [
            "abc",
            "my-bucket",
            "my.bucket.2",
            &"a".repeat(63),
            "1.2.3",
            "1.2.3.4.5",
            "v1.2.3.x",
        ] {
            assert!(valid_bucket_name(name), "{name}");
        }
        for name in [
            "ab",
            "My-Bucket",
            "-abc",
            "abc-",
            "a..b",
            "a_b",
            "a/b",
            "_dashboard",
            &"a".repeat(64),
            "192.168.5.123",
            "xn--bucket",
            "sthree-x",
            "data-s3alias",
            "data--x-s3",
        ] {
            assert!(!valid_bucket_name(name), "{name}");
        }
    }
}
