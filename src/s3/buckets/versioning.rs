use deadpool_postgres::Object;
use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::db::Cached;
use crate::{
    App,
    db,
    s3::util::{format_s3_error, slow_down, xml_ok},
    s3::versions::{Versioning, bucket_versioning},
};

/// GetBucketVersioning: `GET /{bucket}?versioning`. A bucket that has never been
/// versioned reports an empty configuration, as in S3; otherwise its status.
pub async fn get_bucket_versioning(
    app: &App,
    bucket: &str,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let client = app.pool.get().await?;
    let status = match bucket_versioning(&client, bucket).await? {
        None => return Ok(no_such_bucket()),
        Some(Versioning::Unversioned) => "",
        Some(Versioning::Enabled) => "<Status>Enabled</Status>",
        Some(Versioning::Suspended) => "<Status>Suspended</Status>",
    };
    Ok(xml_ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         {status}</VersioningConfiguration>"
    )))
}

/// What a PutBucketVersioning body asks for.
enum Requested {
    /// Set this state.
    Set(Versioning),
    /// Nothing to change (only `<MfaDelete>Disabled</MfaDelete>`, our only mode).
    Unchanged,
    /// MFA delete, which Cairn doesn't support.
    MfaDelete,
}

/// Parses a `<VersioningConfiguration>` body. `Status` is `Enabled` or
/// `Suspended` (case-sensitive, as in S3); a bucket can't be returned to
/// unversioned. Namespace-agnostic like the other parsers; None if malformed.
fn parse_versioning(body: &str) -> Option<Requested> {
    let doc = roxmltree::Document::parse(body).ok()?;
    let root = doc.root_element();
    if root.tag_name().name() != "VersioningConfiguration" {
        return None;
    }
    let child = |name| {
        root.children()
            .find(|n| n.tag_name().name() == name)
            .map(|n| n.text().unwrap_or("").trim())
    };
    match child("MfaDelete") {
        None | Some("Disabled") => {}
        Some("Enabled") => return Some(Requested::MfaDelete),
        Some(_) => return None,
    }
    match child("Status") {
        Some("Enabled") => Some(Requested::Set(Versioning::Enabled)),
        Some("Suspended") => Some(Requested::Set(Versioning::Suspended)),
        Some(_) => None,
        None => Some(Requested::Unchanged),
    }
}

/// One attempt at the update (`cairn_set_versioning`). It locks the bucket
/// row, which every write and delete in the bucket holds while it reads the
/// state and lands, so each lands entirely before or entirely after the change
/// (I2 in `catalog.sql`). Returns its status: 'set', 'no_such_bucket', or
/// 'locked' (a bucket with Object Lock stays versioned).
async fn try_update(
    client: &mut Object,
    bucket: &str,
    versioning: Versioning,
) -> Result<String, tokio_postgres::Error> {
    let status: String = client
        .query_one_cached(
            "SELECT pg_temp.cairn_set_versioning($1, $2)",
            &[&bucket, &versioning.as_db()],
        )
        .await?
        .get(0);
    Ok(status)
}

/// PutBucketVersioning: `PUT /{bucket}?versioning` with a
/// `<VersioningConfiguration>` body. Enables or suspends versioning. Suspending
/// keeps every existing version; it only changes how new writes and deletes land.
/// A bucket with Object Lock can't be suspended, as in S3.
/// The body has been checked against its integrity headers (see `Payload`).
pub async fn put_bucket_versioning(
    app: &App,
    bucket: &str,
    body: Bytes,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let requested = std::str::from_utf8(&body).ok().and_then(parse_versioning);
    let versioning = match requested {
        Some(Requested::Set(versioning)) => Some(versioning),
        Some(Requested::Unchanged) => None,
        Some(Requested::MfaDelete) => {
            return Ok(format_s3_error(
                StatusCode::NOT_IMPLEMENTED,
                "NotImplemented",
                "MFA delete is not supported",
            ));
        }
        None => {
            return Ok(format_s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "could not parse the versioning configuration",
            ));
        }
    };
    let mut client = app.pool.get().await?;
    let Some(versioning) = versioning else {
        // Nothing to change, but the bucket must still exist.
        return Ok(match bucket_versioning(&client, bucket).await? {
            Some(_) => ok(),
            None => no_such_bucket(),
        });
    };
    for attempt in 0..db::MAX_TX_ATTEMPTS {
        db::backoff(attempt).await;
        let status = try_update(&mut client, bucket, versioning).await;
        match status.as_deref() {
            Ok("set") => return Ok(ok()),
            Ok("locked") => {
                return Ok(format_s3_error(
                    StatusCode::CONFLICT,
                    "InvalidBucketState",
                    "An Object Lock configuration is present on this bucket, so the versioning state cannot be changed.",
                ));
            }
            Ok(_) => return Ok(no_such_bucket()),
            Err(e) if db::is_conflict(e) => continue,
            Err(_) => return Err(status.unwrap_err().into()),
        }
    }
    Ok(slow_down())
}

fn ok() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

fn no_such_bucket() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::NOT_FOUND,
        "NoSuchBucket",
        "the specified bucket does not exist",
    )
}
