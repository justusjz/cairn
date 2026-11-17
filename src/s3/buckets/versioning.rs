use deadpool_postgres::Object;
use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::db::Cached;
use crate::{
    App,
    db,
    mfa::Presented,
    s3::util::{format_s3_error, slow_down, xml_ok},
    s3::versions::{Versioning, bucket_versioning},
};

/// GetBucketVersioning: `GET /{bucket}?versioning`. A bucket that has never been
/// versioned reports an empty configuration, as in S3; otherwise its status.
/// MFA delete is reported once it's been configured, either way, as in S3.
pub async fn get_bucket_versioning(
    app: &App,
    bucket: &str,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let client = app.pool.get().await?;
    let Some(row) = client
        .query_opt_cached("SELECT versioning, mfa_delete FROM buckets WHERE name = $1", &[&bucket])
        .await?
    else {
        return Ok(no_such_bucket());
    };
    let status = match Versioning::from_db(row.get(0)) {
        Versioning::Unversioned => "",
        Versioning::Enabled => "<Status>Enabled</Status>",
        Versioning::Suspended => "<Status>Suspended</Status>",
    };
    let mfa_delete = match row.get::<_, Option<bool>>(1) {
        None => "",
        Some(true) => "<MfaDelete>Enabled</MfaDelete>",
        Some(false) => "<MfaDelete>Disabled</MfaDelete>",
    };
    Ok(xml_ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         {status}{mfa_delete}</VersioningConfiguration>"
    )))
}

/// What a PutBucketVersioning body asks for: a versioning state, and MFA
/// delete on or off (see `mfa`); None for either to keep it.
#[derive(Debug, PartialEq)]
struct Requested {
    versioning: Option<Versioning>,
    mfa_delete: Option<bool>,
}

/// Parses a `<VersioningConfiguration>` body. `Status` is `Enabled` or
/// `Suspended` (case-sensitive, as in S3); a bucket can't be returned to
/// unversioned. Enabling MFA delete takes a `Status` too, as S3's docs say
/// ("you must include Status whenever you use MfaDelete"; only for
/// `Enabled` here, as Cairn always took `Disabled` alone). Namespace-agnostic
/// like the other parsers; None if malformed.
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
    let mfa_delete = match child("MfaDelete") {
        None => None,
        Some("Enabled") => Some(true),
        Some("Disabled") => Some(false),
        Some(_) => return None,
    };
    let versioning = match child("Status") {
        Some("Enabled") => Some(Versioning::Enabled),
        Some("Suspended") => Some(Versioning::Suspended),
        Some(_) => return None,
        None if mfa_delete == Some(true) => return None,
        None => None,
    };
    Some(Requested { versioning, mfa_delete })
}

/// One attempt at the update (`cairn_set_versioning`). It locks the bucket
/// row, which every write and delete in the bucket holds while it reads the
/// state and lands, so each lands entirely before or entirely after the change
/// (I2 in `catalog.sql`). Returns its status: 'set', 'no_such_bucket',
/// 'mfa' (MFA delete wants the root's code), 'lifecycle' (MFA delete on a
/// bucket with a lifecycle configuration) or 'locked' (a bucket with Object
/// Lock stays versioned).
async fn try_update(
    client: &mut Object,
    bucket: &str,
    requested: &Requested,
    mfa: Presented,
) -> Result<String, tokio_postgres::Error> {
    let status: String = client
        .query_one_cached(
            "SELECT pg_temp.cairn_set_versioning($1, $2, $3, $4)",
            &[&bucket, &requested.versioning.map(Versioning::as_db), &requested.mfa_delete, &mfa.as_db()],
        )
        .await?
        .get(0);
    Ok(status)
}

/// PutBucketVersioning: `PUT /{bucket}?versioning` with a
/// `<VersioningConfiguration>` body. Enables or suspends versioning. Suspending
/// keeps every existing version; it only changes how new writes and deletes land.
/// A bucket with Object Lock can't be suspended, as in S3.
/// Enabling MFA delete, and any change to a bucket that has it, takes the
/// root's code (`mfa`, from `x-amz-mfa`; see `mfa`).
/// The body has been checked against its integrity headers (see `Payload`).
pub async fn put_bucket_versioning(
    app: &App,
    bucket: &str,
    body: Bytes,
    mfa: Presented,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let Some(requested) = std::str::from_utf8(&body).ok().and_then(parse_versioning) else {
        return Ok(format_s3_error(
            StatusCode::BAD_REQUEST,
            "MalformedXML",
            "could not parse the versioning configuration",
        ));
    };
    let mut client = app.pool.get().await?;
    if requested == (Requested { versioning: None, mfa_delete: None }) {
        // Nothing to change, but the bucket must still exist.
        return Ok(match bucket_versioning(&client, bucket).await? {
            Some(_) => ok(),
            None => no_such_bucket(),
        });
    }
    for attempt in 0..db::MAX_TX_ATTEMPTS {
        db::backoff(attempt).await;
        let status = try_update(&mut client, bucket, &requested, mfa).await;
        match status.as_deref() {
            Ok("set") => return Ok(ok()),
            Ok("mfa") => return Ok(crate::mfa::required()),
            Ok("lifecycle") => {
                return Ok(format_s3_error(
                    StatusCode::CONFLICT,
                    "InvalidBucketState",
                    "MFA delete can't be enabled on a bucket with a lifecycle configuration.",
                ));
            }
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
        "The specified bucket does not exist",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mfa_delete_is_asked_for_with_a_status() {
        let parse = |inner: &str| parse_versioning(&format!("<VersioningConfiguration>{inner}</VersioningConfiguration>"));
        let requested = |versioning, mfa_delete| Some(Requested { versioning, mfa_delete });
        assert_eq!(parse(""), requested(None, None));
        assert_eq!(parse("<Status>Enabled</Status>"), requested(Some(Versioning::Enabled), None));
        assert_eq!(
            parse("<Status>Enabled</Status><MfaDelete>Enabled</MfaDelete>"),
            requested(Some(Versioning::Enabled), Some(true))
        );
        assert_eq!(
            parse("<MfaDelete>Disabled</MfaDelete><Status>Suspended</Status>"),
            requested(Some(Versioning::Suspended), Some(false))
        );
        assert_eq!(parse("<MfaDelete>Disabled</MfaDelete>"), requested(None, Some(false)));
        assert_eq!(parse("<MfaDelete>Enabled</MfaDelete>"), None);
        assert_eq!(parse("<Status>Enabled</Status><MfaDelete>enabled</MfaDelete>"), None);
    }
}
