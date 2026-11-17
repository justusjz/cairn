//! An object version's tags (see `s3::tags`): GetObjectTagging,
//! PutObjectTagging and DeleteObjectTagging (`?tagging`, optionally with a
//! `versionId`; without one, the current version's).
//!
//! As S3 answers them (observed): an SSE-C object's need no key; a delete
//! marker has none, which all three answer with 405 MethodNotAllowed
//! (`Allow: DELETE`), whether it was named or is the current version; and
//! each reports the version's ID as GetObject would.

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes, header};

use crate::db::{self, Cached};
use crate::{
    App,
    s3::objects::get::{Missing, lookup_version, no_such_version},
    s3::tags::{On, Tags},
    s3::util::{format_s3_error, slow_down, with_delete_marker, with_version_id, xml_ok},
    s3::versions::Versioning,
};

/// GetObjectTagging.
pub async fn get_object_tagging(
    app: &App,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let client = app.pool.get().await?;
    Ok(match lookup_version(&client, bucket, key, version_id).await? {
        Ok(version) => {
            with_version_id(xml_ok(Tags::from_stored(&version.tags).xml()), version.version_id.as_deref())
        }
        Err(Missing::NoSuchKey) => no_such_key(),
        Err(Missing::NoSuchVersion) => no_such_version(),
        Err(Missing::DeleteMarker { version_id, .. }) => delete_marker(version_id.as_deref()),
    })
}

/// PutObjectTagging: replaces the version's tags with the `<Tagging>`
/// document's (none, if it has none). Unlike PutBucketTagging, S3 doesn't
/// require a checksum of the body.
pub async fn put_object_tagging(
    app: &App,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    body: Bytes,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let tags = match Tags::from_xml(&body, On::Object) {
        Ok(tags) => tags,
        Err(refused) => return Ok(refused),
    };
    set(app, bucket, key, version_id, &tags, StatusCode::OK).await
}

/// DeleteObjectTagging: 204, whether the version had tags or not.
pub async fn delete_object_tagging(
    app: &App,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    set(app, bucket, key, version_id, &Tags::default(), StatusCode::NO_CONTENT).await
}

/// Sets the version's tags (`cairn_set_tags`), retrying on a conflict, and
/// answers with `status` if it did.
async fn set(
    app: &App,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    tags: &Tags,
    status: StatusCode,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let tagging = if status == StatusCode::NO_CONTENT { Tagging::Delete } else { Tagging::Put };
    Ok(match set_tags(app, bucket, key, version_id, tags, tagging).await? {
        Outcome::Tagged(reported) => {
            let response = Response::builder().status(status).body(Full::new(Bytes::new())).unwrap();
            with_version_id(response, reported.as_deref())
        }
        Outcome::DeleteMarker(reported) => delete_marker(reported.as_deref()),
        Outcome::NoSuchVersion => no_such_version(),
        Outcome::NoSuchKey => no_such_key(),
        Outcome::NoSuchBucket => {
            format_s3_error(StatusCode::NOT_FOUND, "NoSuchBucket", "The specified bucket does not exist")
        }
        Outcome::Contended => slow_down(),
    })
}

/// Which tagging a change of a version's tags is, as its event says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tagging {
    Put,
    Delete,
}

/// What setting a version's tags came to.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Set; the version's ID, as a response reports it.
    Tagged(Option<String>),
    /// The version is a delete marker, which has no tags; its ID, likewise.
    DeleteMarker(Option<String>),
    NoSuchVersion,
    NoSuchKey,
    NoSuchBucket,
    /// Other writes to the key kept getting in its way.
    Contended,
}

/// Sets the tags of the version `version_id` of `key` (the current one if
/// `None`) to `tags` (`cairn_set_tags`), retrying on a conflict: what
/// PutObjectTagging and DeleteObjectTagging do (`tagging` says which), and
/// batch jobs' tasks (see `batch`).
pub async fn set_tags(
    app: &App,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    tags: &Tags,
    tagging: Tagging,
) -> anyhow::Result<Outcome> {
    let stored = tags.stored();
    // A deletion of its tags is one event, a setting another.
    let notify = crate::notifications::tagging_context(match tagging {
        Tagging::Delete => "Delete",
        Tagging::Put => "Put",
    });
    let client = app.pool.get().await?;
    for attempt in 0..db::MAX_TX_ATTEMPTS {
        db::backoff(attempt).await;
        let row = match client
            .query_one_cached(
                "SELECT status, versioning, version_id FROM pg_temp.cairn_set_tags($1, $2, $3, $4, $5)",
                &[&bucket, &key, &version_id, &stored, &notify],
            )
            .await
        {
            Ok(row) => row,
            Err(e) if db::is_conflict(&e) => continue,
            Err(e) => return Err(e.into()),
        };
        let reported = row
            .get::<_, Option<&str>>(1)
            .zip(row.get::<_, Option<&str>>(2))
            .and_then(|(versioning, id)| Versioning::from_db(versioning).reported(id));
        return Ok(match row.get::<_, &str>(0) {
            "tagged" => Outcome::Tagged(reported),
            "delete_marker" => Outcome::DeleteMarker(reported),
            "no_such_version" => Outcome::NoSuchVersion,
            "no_such_key" => Outcome::NoSuchKey,
            "no_such_bucket" => Outcome::NoSuchBucket,
            other => anyhow::bail!("cairn_set_tags: unexpected status {other}"),
        });
    }
    Ok(Outcome::Contended)
}

/// S3's answer for a delete marker's tags: 405, as for any method but
/// DELETE on a marker.
fn delete_marker(version_id: Option<&str>) -> Response<Full<Bytes>> {
    let mut response = format_s3_error(
        StatusCode::METHOD_NOT_ALLOWED,
        "MethodNotAllowed",
        "The specified method is not allowed against this resource.",
    );
    response.headers_mut().insert(header::ALLOW, header::HeaderValue::from_static("DELETE"));
    with_delete_marker(with_version_id(response, version_id))
}

fn no_such_key() -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::NOT_FOUND, "NoSuchKey", "The specified key does not exist.")
}
