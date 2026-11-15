use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::db::Cached;
use crate::{
    App,
    s3::tags::{self, Tags},
    s3::util::format_s3_error,
};

pub enum Creation {
    Created,
    /// There already is a bucket of that name, the account's own.
    Exists,
    /// There is one of another account (names are global, as in S3).
    OwnedByOther,
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

/// Creates a bucket of account `account` (its ID). Shared by CreateBucket
/// and the console. With `object_lock`, it has Object Lock enabled (see
/// `s3::object_lock`), and so is versioned, from the start.
pub async fn create(app: &App, name: &str, account: &str, object_lock: bool) -> anyhow::Result<Creation> {
    create_tagged(app, name, account, object_lock, None).await
}

/// As `create`, with `tags` (CreateBucket's): only if it makes the bucket.
pub async fn create_tagged(
    app: &App,
    name: &str,
    account: &str,
    object_lock: bool,
    tags: Option<&Tags>,
) -> anyhow::Result<Creation> {
    if !valid_bucket_name(name) {
        return Ok(Creation::InvalidName);
    }
    let stored = tags.filter(|tags| !tags.is_empty()).map(Tags::stored);
    let client = app.pool.get().await?;
    let inserted = client
        .execute_cached(
            "INSERT INTO buckets (name, account_id, object_lock, versioning, tags)
             VALUES ($1, $2, $3, CASE WHEN $3 THEN 'enabled' ELSE 'unversioned' END, $4)
             ON CONFLICT DO NOTHING",
            &[&name, &account, &object_lock, &stored],
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

/// CreateBucket: `PUT /{bucket}`, by a user of `account`, with Object Lock
/// if `object_lock` (`x-amz-bucket-object-lock-enabled: true`), and `tags`
/// (see `tags`). Creating a bucket that exists succeeds, as it does for its
/// owner in S3's us-east-1 (and changes nothing, its tags neither, probed);
/// another account's is BucketAlreadyExists, as in S3.
pub async fn create_bucket(
    app: &App,
    bucket: &str,
    account: &str,
    object_lock: bool,
    tags: Option<&Tags>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    match create_tagged(app, bucket, account, object_lock, tags).await? {
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
        Creation::Created | Creation::Exists => {}
    }
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("location", format!("/{bucket}"))
        .body(Full::new(Bytes::new()))
        .unwrap())
}

/// The tags a CreateBucket's `<CreateBucketConfiguration>` gives its bucket
/// (`<Tags><Tag><Key/><Value/></Tag>…</Tags>`), if any: none for an empty
/// body, or an empty `<Tags>`. Checked as S3 checks them (probed, see
/// `tags::On::NewBucket`); a body that isn't XML is MalformedXML.
pub fn tags(body: &[u8]) -> Result<Option<Tags>, Response<Full<Bytes>>> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    let text = std::str::from_utf8(body).map_err(|_| tags::malformed("not UTF-8"))?;
    let doc = roxmltree::Document::parse(text).map_err(|e| tags::malformed(&e.to_string()))?;
    let Some(list) = doc.root_element().children().find(|n| n.is_element() && n.tag_name().name() == "Tags") else {
        return Ok(None);
    };
    let tags = Tags::from_elements(list, tags::On::NewBucket)?;
    Ok(Some(tags).filter(|tags| !tags.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_tags() {
        let configuration = |tags: &str| {
            format!(
                r#"<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                   <LocationConstraint>eu-north-1</LocationConstraint>{tags}</CreateBucketConfiguration>"#
            )
        };
        let tag = |k: &str, v: &str| format!("<Tag><Key>{k}</Key><Value>{v}</Value></Tag>");
        assert_eq!(tags(b"").unwrap(), None);
        assert_eq!(tags(configuration("").as_bytes()).unwrap(), None);
        assert_eq!(tags(configuration("<Tags/>").as_bytes()).unwrap(), None);
        let some = tags(configuration(&format!("<Tags>{}{}</Tags>", tag("team", "red"), tag("a", ""))).as_bytes());
        assert_eq!(some.unwrap().unwrap().iter().collect::<Vec<_>>(), [("a", ""), ("team", "red")]);
        let status = |body: String| tags(body.as_bytes()).unwrap_err().status();
        assert_eq!(status(configuration(&format!("<Tags>{}</Tags>", tag("aws:x", "1")))), StatusCode::BAD_REQUEST);
        let many: String = (0..51).map(|i| tag(&format!("k{i}"), "v")).collect();
        assert_eq!(status(configuration(&format!("<Tags>{many}</Tags>"))), StatusCode::BAD_REQUEST);
        let fifty: String = (0..50).map(|i| tag(&format!("k{i}"), "v")).collect();
        assert!(tags(configuration(&format!("<Tags>{fifty}</Tags>")).as_bytes()).is_ok());
        assert_eq!(status(configuration("<Tags><Tag><Key>a</Key></Tag></Tags>")), StatusCode::BAD_REQUEST);
        assert_eq!(status("<CreateBucketConfiguration>".to_owned()), StatusCode::BAD_REQUEST);
    }

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
            "_console",
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
