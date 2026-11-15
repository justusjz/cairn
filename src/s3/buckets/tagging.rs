//! A bucket's tags (see `s3::tags`): GetBucketTagging, PutBucketTagging and
//! DeleteBucketTagging (`?tagging`). As S3 answers them (observed): an empty
//! tag set is no tag set, which GetBucketTagging answers with 404
//! NoSuchTagSet; PutBucketTagging and DeleteBucketTagging answer 204. With
//! the bucket's ABAC enabled, only S3 Control's TagResource and
//! UntagResource change its tags (see `resource_tags`): these two are 400s
//! (probed).

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::db::Cached;
use crate::{
    App,
    s3::tags::{On, Tags},
    s3::util::{format_s3_error, xml_ok},
};

/// GetBucketTagging.
pub async fn get_bucket_tagging(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached("SELECT tags FROM buckets WHERE name = $1", &[&bucket])
        .await?;
    Ok(match row {
        None => no_such_bucket(),
        Some(row) => match row.get::<_, Option<&str>>(0) {
            None => format_s3_error(StatusCode::NOT_FOUND, "NoSuchTagSet", "The TagSet does not exist"),
            Some(stored) => xml_ok(Tags::from_stored(stored).xml()),
        },
    })
}

/// PutBucketTagging: `PUT /{bucket}?tagging` with a `<Tagging>` body,
/// checked against its integrity headers (see `Payload`), of which S3
/// requires one. Replaces the bucket's tags.
pub async fn put_bucket_tagging(app: &App, bucket: &str, body: Bytes) -> anyhow::Result<Response<Full<Bytes>>> {
    let tags = match Tags::from_xml(&body, On::Bucket) {
        Ok(tags) => tags,
        Err(refused) => return Ok(refused),
    };
    set(app, bucket, Some(tags).filter(|tags| !tags.is_empty()), ABAC_PUT).await
}

/// S3's refusals of PutBucketTagging and DeleteBucketTagging on a bucket
/// with ABAC enabled (probed).
const ABAC_PUT: &str = "This S3 general purpose bucket has attribute-based access control (ABAC) enabled. \
                        To add tags to this bucket, initiate a TagResource request. To delete tags from this \
                        bucket, initiate an UntagResource request.";
const ABAC_DELETE: &str = "This S3 general purpose bucket has attribute-based access control (ABAC) enabled. \
                           To delete tags from this bucket, initiate an UntagResource request.";

/// DeleteBucketTagging: 204, whether it had tags or not.
pub async fn delete_bucket_tagging(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    set(app, bucket, None, ABAC_DELETE).await
}

/// Sets the bucket's tags (`cairn_set_bucket_tags`), none if `None`; refused
/// with `abac` if the bucket's ABAC is enabled.
async fn set(app: &App, bucket: &str, tags: Option<Tags>, abac: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let stored = tags.map(|tags| tags.stored());
    let status: String = app
        .pool
        .get()
        .await?
        .query_one_cached("SELECT pg_temp.cairn_set_bucket_tags($1, $2)", &[&bucket, &stored])
        .await?
        .get(0);
    Ok(match status.as_str() {
        "ok" => Response::builder().status(StatusCode::NO_CONTENT).body(Full::new(Bytes::new())).unwrap(),
        "abac" => format_s3_error(StatusCode::BAD_REQUEST, "BadRequest", abac),
        _ => no_such_bucket(),
    })
}

pub(crate) fn no_such_bucket() -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::NOT_FOUND, "NoSuchBucket", "The specified bucket does not exist")
}
