//! A bucket's lifecycle configuration: PutBucketLifecycleConfiguration,
//! GetBucketLifecycleConfiguration and DeleteBucketLifecycle (`?lifecycle`).
//! What the rules do, and when, is `lifecycle`'s.

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::db::Cached;
use crate::{
    App,
    lifecycle::rules::{Configuration, Invalid, TransitionMinimum},
    s3::util::{format_s3_error, xml_ok},
};

/// The header that says which objects are too small to transition (see
/// `TransitionMinimum`), on a PUT and in the answers to PUT and GET.
pub const MINIMUM_HEADER: &str = "x-amz-transition-default-minimum-object-size";

/// `response`, with `config`'s minimum in its header.
fn with_minimum(mut response: Response<Full<Bytes>>, config: &Configuration) -> Response<Full<Bytes>> {
    let minimum = config.transition_minimum.unwrap_or(TransitionMinimum::AllStorageClasses128K);
    response.headers_mut().insert(MINIMUM_HEADER, hyper::header::HeaderValue::from_static(minimum.as_str()));
    response
}

/// What's wrong with the storage classes `config` transitions objects into,
/// if anything: each must be defined, and ranked (see `classes`). As this
/// node knows them, or the database, if it doesn't know one.
pub(crate) async fn check_classes(app: &App, config: &Configuration) -> anyhow::Result<Result<(), String>> {
    let check = |classes: &std::collections::BTreeMap<String, crate::classes::Class>| {
        let ranks = classes.values().filter_map(|c| Some((c.name.clone(), c.rank?))).collect();
        config.check_classes(&ranks, |name| classes.contains_key(name))
    };
    if check(&app.classes.all()).is_ok() {
        return Ok(Ok(()));
    }
    // Perhaps defined or ranked since this node last read them.
    let classes = crate::classes::load(&app.pool.get().await?).await?;
    let checked = check(&classes);
    app.classes.set(classes);
    Ok(checked)
}

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
    Ok(with_minimum(xml_ok(config.to_xml()), &config))
}

/// PutBucketLifecycleConfiguration: `PUT /{bucket}?lifecycle` with a
/// `<LifecycleConfiguration>` body, checked against its integrity headers
/// (see `Payload`), of which S3 requires one, and the minimum size of the
/// objects its rules transition, if the request says (`minimum`, its
/// `x-amz-transition-default-minimum-object-size`). Replaces the bucket's
/// configuration, and makes a run of it due now.
pub async fn put_bucket_lifecycle(
    app: &App,
    bucket: &str,
    body: Bytes,
    minimum: Option<&str>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let minimum = match minimum.map(|value| (value, TransitionMinimum::parse(value))) {
        None => None,
        Some((_, Some(minimum))) => Some(minimum),
        Some((value, None)) => {
            return Ok(format_s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                &format!("{MINIMUM_HEADER} must be all_storage_classes_128K or varies_by_storage_class, not {value}"),
            ));
        }
    };
    let parsed = std::str::from_utf8(&body)
        .map_err(|_| Invalid::Malformed("not UTF-8".to_owned()))
        .and_then(Configuration::parse);
    let mut config = match parsed {
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
    };
    // As S3 stores it: its default isn't.
    config.transition_minimum = minimum.filter(|m| *m != TransitionMinimum::AllStorageClasses128K);
    if let Err(why) = check_classes(app, &config).await? {
        return Ok(format_s3_error(StatusCode::BAD_REQUEST, "InvalidStorageClass", &why));
    }
    Ok(match set(app, bucket, Some(&config.to_json())).await? {
        Set::Done => with_minimum(
            Response::builder().status(StatusCode::OK).body(Full::new(Bytes::new())).unwrap(),
            &config,
        ),
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
