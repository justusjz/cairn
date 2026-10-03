use deadpool_postgres::Object;
use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use tokio_postgres::{IsolationLevel, error::SqlState};

use crate::{
    App,
    auth::BodyChecksum,
    s3::util::{format_s3_error, xml_ok},
    s3::versions::{Versioning, bucket_versioning},
};

/// Bounded retry for the serializable update, mirroring the other write paths.
const MAX_UPDATE_ATTEMPTS: usize = 10;

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

/// One serializable attempt at the update. Serializable, so it's ordered against
/// the writes and deletes that read the bucket's state in their own transactions:
/// each lands entirely before or entirely after the change. Returns whether the
/// bucket exists.
async fn try_update(
    client: &mut Object,
    bucket: &str,
    versioning: Versioning,
) -> Result<bool, tokio_postgres::Error> {
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()
        .await?;
    let updated = tx
        .execute(
            "UPDATE buckets SET versioning = $2 WHERE name = $1",
            &[&bucket, &versioning.as_db()],
        )
        .await?;
    tx.commit().await?;
    Ok(updated == 1)
}

/// PutBucketVersioning: `PUT /{bucket}?versioning` with a
/// `<VersioningConfiguration>` body. Enables or suspends versioning. Suspending
/// keeps every existing version; it only changes how new writes and deletes land.
/// An integrity header (Content-MD5 / x-amz-checksum-*) is verified if present.
pub async fn put_bucket_versioning(
    app: &App,
    bucket: &str,
    body: Bytes,
    checksum: BodyChecksum,
) -> anyhow::Result<Response<Full<Bytes>>> {
    if checksum.is_present() && !checksum.matches(&body) {
        return Ok(format_s3_error(
            StatusCode::BAD_REQUEST,
            "BadDigest",
            "the integrity checksum you specified did not match what we received",
        ));
    }
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
    for _ in 0..MAX_UPDATE_ATTEMPTS {
        match try_update(&mut client, bucket, versioning).await {
            Ok(true) => return Ok(ok()),
            Ok(false) => return Ok(no_such_bucket()),
            Err(e) if e.code() == Some(&SqlState::T_R_SERIALIZATION_FAILURE) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(format_s3_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "ServiceUnavailable",
        "update aborted after serialization retries",
    ))
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
