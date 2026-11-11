//! A bucket's tags (see `s3::tags`): GetBucketTagging, PutBucketTagging and
//! DeleteBucketTagging (`?tagging`). As S3 answers them (observed): an empty
//! tag set is no tag set, which GetBucketTagging answers with 404
//! NoSuchTagSet; PutBucketTagging and DeleteBucketTagging answer 204.

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
    set(app, bucket, Some(tags).filter(|tags| !tags.is_empty())).await
}

/// DeleteBucketTagging: 204, whether it had tags or not.
pub async fn delete_bucket_tagging(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    set(app, bucket, None).await
}

/// Sets the bucket's tags (`cairn_set_bucket_tags`), none if `None`.
async fn set(app: &App, bucket: &str, tags: Option<Tags>) -> anyhow::Result<Response<Full<Bytes>>> {
    let stored = tags.map(|tags| tags.stored());
    let exists: bool = app
        .pool
        .get()
        .await?
        .query_one_cached("SELECT pg_temp.cairn_set_bucket_tags($1, $2)", &[&bucket, &stored])
        .await?
        .get(0);
    Ok(match exists {
        true => Response::builder().status(StatusCode::NO_CONTENT).body(Full::new(Bytes::new())).unwrap(),
        false => no_such_bucket(),
    })
}

fn no_such_bucket() -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::NOT_FOUND, "NoSuchBucket", "the specified bucket does not exist")
}
