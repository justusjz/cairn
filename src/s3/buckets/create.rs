use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::db::Cached;
use crate::{App, s3::util::format_s3_error};

pub enum Creation {
    Created,
    /// There already is a bucket of that name.
    Exists,
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

/// Creates a bucket. Shared by CreateBucket and the dashboard.
pub async fn create(app: &App, name: &str) -> anyhow::Result<Creation> {
    if !valid_bucket_name(name) {
        return Ok(Creation::InvalidName);
    }
    let inserted = app
        .pool
        .get()
        .await?
        .execute_cached(
            "INSERT INTO buckets (name) VALUES ($1) ON CONFLICT DO NOTHING",
            &[&name],
        )
        .await?;
    Ok(if inserted == 0 {
        Creation::Exists
    } else {
        Creation::Created
    })
}

/// CreateBucket: `PUT /{bucket}`. Creating a bucket that exists succeeds, as
/// it does for its owner in S3's us-east-1.
pub async fn create_bucket(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    if let Creation::InvalidName = create(app, bucket).await? {
        return Ok(format_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidBucketName",
            "the specified bucket is not valid",
        ));
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
