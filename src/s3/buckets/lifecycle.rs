//! A bucket's lifecycle configuration: PutBucketLifecycleConfiguration,
//! GetBucketLifecycleConfiguration and DeleteBucketLifecycle (`?lifecycle`).
//! What the rules do, and when, is `lifecycle`'s.

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::db::Cached;
use crate::{
    App,
    lifecycle::rules::{Configuration, Invalid},
    s3::util::{format_s3_error, xml_ok},
};

/// GetBucketLifecycleConfiguration: `GET /{bucket}?lifecycle`. A bucket
/// without one answers 404 NoSuchLifecycleConfiguration, as in S3.
pub async fn get_bucket_lifecycle(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached("SELECT lifecycle FROM buckets WHERE name = $1", &[&bucket])
        .await?;
    let Some(row) = row else { return Ok(no_such_bucket()) };
    let Some(json) = row.get::<_, Option<String>>(0) else {
        return Ok(format_s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchLifecycleConfiguration",
            "The lifecycle configuration does not exist",
        ));
    };
    let config = Configuration::from_json(&json)
        .map_err(|e| anyhow::anyhow!("bucket {bucket}'s lifecycle configuration doesn't parse: {e}"))?;
    Ok(xml_ok(config.to_xml()))
}

/// PutBucketLifecycleConfiguration: `PUT /{bucket}?lifecycle` with a
/// `<LifecycleConfiguration>` body, checked against its integrity headers
/// (see `Payload`), of which S3 requires one. Replaces the bucket's
/// configuration, and makes a run of it due now.
pub async fn put_bucket_lifecycle(app: &App, bucket: &str, body: Bytes) -> anyhow::Result<Response<Full<Bytes>>> {
    let parsed = std::str::from_utf8(&body)
        .map_err(|_| Invalid::Malformed("not UTF-8".to_owned()))
        .and_then(Configuration::parse);
    let config = match parsed {
        Ok(config) => config,
        Err(Invalid::Malformed(_)) => {
            return Ok(format_s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "The XML you provided was not well-formed or did not validate against our published schema",
            ));
        }
        Err(Invalid::Argument(why)) => {
            return Ok(format_s3_error(StatusCode::BAD_REQUEST, "InvalidArgument", &why));
        }
        Err(Invalid::Request(why)) => {
            return Ok(format_s3_error(StatusCode::BAD_REQUEST, "InvalidRequest", &why));
        }
        Err(Invalid::Unsupported(why)) => {
            return Ok(format_s3_error(StatusCode::NOT_IMPLEMENTED, "NotImplemented", &why));
        }
    };
    Ok(match set(app, bucket, Some(&config.to_json())).await? {
        Set::Done => Response::builder().status(StatusCode::OK).body(Full::new(Bytes::new())).unwrap(),
        Set::NoSuchBucket => no_such_bucket(),
        Set::MfaDelete => mfa_delete(),
    })
}

/// DeleteBucketLifecycle: `DELETE /{bucket}?lifecycle`. Nothing expires from
/// then on; a run in progress stops before its next expiration.
pub async fn delete_bucket_lifecycle(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    Ok(match set(app, bucket, None).await? {
        Set::Done => Response::builder().status(StatusCode::NO_CONTENT).body(Full::new(Bytes::new())).unwrap(),
        Set::NoSuchBucket => no_such_bucket(),
        Set::MfaDelete => unreachable!("removing a configuration is never refused"),
    })
}

/// What setting a bucket's configuration came to.
pub(crate) enum Set {
    Done,
    NoSuchBucket,
    /// The bucket has MFA delete, which S3 supports no lifecycle
    /// configuration on (see `mfa`; migration 60's check).
    MfaDelete,
}

/// The constraint that keeps a bucket with MFA delete without a lifecycle
/// configuration (migration 60).
const MFA_DELETE_CHECK: &str = "buckets_mfa_delete_lifecycle";

/// Sets the bucket's configuration (`cairn_set_lifecycle`), or removes it.
pub(crate) async fn set(app: &App, bucket: &str, config: Option<&str>) -> anyhow::Result<Set> {
    let set = app
        .pool
        .get()
        .await?
        .query_one_cached("SELECT pg_temp.cairn_set_lifecycle($1, $2)", &[&bucket, &config])
        .await;
    match set {
        Ok(row) => Ok(if row.get(0) { Set::Done } else { Set::NoSuchBucket }),
        Err(e) if e.as_db_error().and_then(|e| e.constraint()) == Some(MFA_DELETE_CHECK) => Ok(Set::MfaDelete),
        Err(e) => Err(e.into()),
    }
}

/// S3 supports no lifecycle configuration on a bucket with MFA delete (as
/// its docs say; how it refuses one is unprobed).
pub(crate) fn mfa_delete() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::CONFLICT,
        "InvalidBucketState",
        "Lifecycle configuration is not supported on a bucket with MFA delete enabled.",
    )
}

fn no_such_bucket() -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::NOT_FOUND, "NoSuchBucket", "The specified bucket does not exist")
}
