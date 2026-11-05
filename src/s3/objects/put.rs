use std::sync::Arc;

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes, body::Incoming, header};

use crate::db::Cached;
use crate::{
    App, AttachTarget, UploadResult,
    payload::Payload,
    s3::conditional::Preconditions,
    s3::util::{format_s3_error, rejection_response, with_version_id},
    s3::versions::current_etag,
};

pub async fn put_object(
    app: &Arc<App>,
    bucket: &str,
    key: &str,
    content_type: &str,
    body: Incoming,
    payload: Payload,
    conditions: &Preconditions,
) -> anyhow::Result<Response<Full<Bytes>>> {
    // Fast-fail a conditional write (If-Match / If-None-Match) before streaming the
    // body, so a client "create if absent" against an existing key doesn't upload
    // the whole object just to be rejected. This is only an optimization — the
    // authoritative, race-free check runs inside the commit transaction. A
    // missing bucket takes precedence. (Without conditions, `upload_part`
    // checks the bucket as it starts, before it replicates anything.)
    if conditions.has_write_conditions() {
        let client = app.pool.get().await?;
        // Independent, so they're sent together: one round trip.
        let (exists, current) = tokio::join!(
            async { client.query_opt_cached("SELECT 1 FROM buckets WHERE name = $1", &[&bucket]).await },
            current_etag(&client, bucket, key),
        );
        if exists?.is_none() {
            return Ok(no_such_bucket());
        }
        if !conditions.allows_write(current?.as_deref()) {
            return Ok(precondition_failed());
        }
    }

    // Stream the body into one replicated, committed part and atomically point
    // (bucket, key) at it. `upload_part` computes the ETag (hex MD5) as it streams.
    let attach = AttachTarget::Object {
        bucket: bucket.to_owned(),
        key: key.to_owned(),
        content_type: content_type.to_owned(),
        conditions: conditions.clone(),
    };
    match crate::upload_part(app, body, &attach, payload).await? {
        UploadResult::Committed { etag, version_id } => Ok(with_version_id(
            Response::builder()
                .status(StatusCode::OK)
                .header(header::ETAG, format!("\"{etag}\""))
                .body(Full::new(Bytes::new()))
                .unwrap(),
            version_id.as_deref(),
        )),
        UploadResult::Rejected(rejection) => Ok(rejection_response(&rejection)),
        // A concurrent writer won the race between the fast-fail check and commit.
        UploadResult::PreconditionFailed => Ok(precondition_failed()),
        // There's no such bucket, or it was deleted while the body streamed.
        UploadResult::NoSuchBucket => Ok(no_such_bucket()),
        UploadResult::NoSuchUpload => unreachable!("an object write has no upload"),
    }
}

fn no_such_bucket() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::NOT_FOUND,
        "NoSuchBucket",
        "the specified bucket does not exist",
    )
}

/// The 412 returned when a conditional-write guard (If-Match / If-None-Match)
/// doesn't hold.
fn precondition_failed() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::PRECONDITION_FAILED,
        "PreconditionFailed",
        "at least one of the preconditions you specified did not hold",
    )
}
