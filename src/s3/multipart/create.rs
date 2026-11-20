use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use uuid::Uuid;

use crate::db::Cached;
use crate::{
    App,
    s3::checksums::{self, Algorithm, Type},
    s3::object_lock::{self, Lock},
    s3::sse::{self, Wanted},
    s3::util::{format_s3_error, xml_escape, xml_ok},
};

/// CreateMultipartUpload: `POST /{bucket}/{key}?uploads`. Stages an upload and
/// hands back its UploadId. Nothing about the live object changes until
/// CompleteMultipartUpload. `tags` are the object's, stored form (see
/// `s3::tags`): an upload's tags are fixed now, as in S3, as is the Object
/// Lock it asks for (`lock`, see `s3::object_lock`). `initiator` is the ARN
/// of the principal that begins it (`None`: anonymous), as `Initiator`
/// tells it. Its parts, and so the object, are of storage class
/// `storage_class`, which exists (see `classes`).
#[allow(clippy::too_many_arguments)]
pub async fn create_multipart_upload(
    app: &App,
    bucket: &str,
    key: &str,
    content_type: &str,
    metadata: &str,
    tags: &str,
    wanted: Wanted<'_>,
    role: Option<Uuid>,
    checksum: Option<(Algorithm, Type)>,
    lock: Lock,
    initiator: Option<&str>,
    storage_class: &str,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let client = app.pool.get().await?;
    let Some(bucket_row) = client
        .query_opt_cached("SELECT lifecycle FROM buckets WHERE name = $1", &[&bucket])
        .await?
    else {
        return Ok(format_s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified bucket does not exist",
        ));
    };
    drop(client);
    // A lock only where there's Object Lock.
    if let Some(refused) = object_lock::check_write(app, bucket, &lock).await? {
        return Ok(refused);
    }
    let (lock_mode, lock_until, legal_hold) = lock.columns();
    // The content type, metadata and tags are captured now and applied to the object
    // at completion; so is its encryption, which its parts need: its object
    // key, sealed under the client's key or a data key (see `sse`).
    let upload_id = Uuid::now_v7();
    let stored = match sse::seal(app, wanted, role, bucket, key).await? {
        Ok(sealing) => sealing.map_or(sse::Stored::Plain, |sealing| sealing.stored),
        Err(refused) => return Ok(refused),
    };
    let sse = stored.columns();
    // Its object's owner and ACL, to be (see `s3::acl`).
    let (owner_id, acl) =
        crate::notifications::write_acl().map_or((None, None), |(owner, acl)| (Some(owner), acl));
    let initiated = app
        .pool
        .get()
        .await?
        .query_one_cached(
            "INSERT INTO multipart_uploads (upload_id, bucket, key, content_type, metadata,
                                            sse_c_key, sse_kms_key_id, sse_kms_data_key,
                                            sse_kms_sealed, sse_kms_context, sse_s3,
                                            checksum_algorithm, checksum_type, tags, initiated_at,
                                            retain_mode, retain_until, legal_hold, initiator, storage_class,
                                            owner_id, acl, replica_version_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW(), $15, $16, $17, $18, $19,
                     $20, $21, $22)
             RETURNING extract(epoch FROM initiated_at)::float8",
            &[
                &upload_id,
                &bucket,
                &key,
                &content_type,
                &metadata,
                &sse.sse_c_key,
                &sse.kms_key_id,
                &sse.kms_data_key,
                &sse.kms_sealed,
                &sse.kms_context,
                &sse.sse_s3,
                &checksum.map(|(algorithm, _)| algorithm.name()),
                &checksum.map(|(_, kind)| kind.name()),
                &tags,
                &lock_mode,
                &lock_until,
                &legal_hold,
                &initiator,
                &storage_class,
                &owner_id,
                &acl,
                // The version ID a replica's upload keeps (see
                // `replication::inbound`).
                &crate::notifications::replica_version_id(),
            ],
        )
        .await?;
    let initiated = crate::s3::expiration::from_epoch(initiated.get(0));
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId>\
         </InitiateMultipartUploadResult>",
        xml_escape(bucket),
        xml_escape(key),
        upload_id
    );
    let customer_key = wanted.customer();
    let mut response = sse::echo_onto(xml_ok(body), &stored, customer_key);
    // The checksum it asked for, as S3 tells it.
    if let Some((algorithm, kind)) = checksum {
        response
            .headers_mut()
            .insert(checksums::ALGORITHM, algorithm.name().parse().unwrap());
        response
            .headers_mut()
            .insert(checksums::TYPE, kind.name().parse().unwrap());
    }
    // When a lifecycle rule aborts it, as S3 tells it.
    let lifecycle: Option<&str> = bucket_row.get(0);
    Ok(crate::s3::expiration::abort_onto(
        response, lifecycle, key, initiated,
    ))
}
