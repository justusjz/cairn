//! A bucket's default encryption: PutBucketEncryption, GetBucketEncryption
//! and DeleteBucketEncryption (`?encryption`). A write that asks for no
//! encryption of its own (no SSE-C or SSE-KMS headers at all) is encrypted as
//! its bucket's default says: PutObject, CopyObject's destination,
//! CreateMultipartUpload. One that asks for one gets what it asks for, as in
//! S3 and MinIO.
//!
//! The default is SSE-KMS under a key (Cairn has no SSE-S3 yet), which the
//! writing role must be allowed to use, as when it names the key itself (see
//! `kms`).

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use uuid::Uuid;

use crate::db::Cached;
use crate::{
    App,
    kms::{KeyId, KmsError},
    s3::sse::KmsRequest,
    s3::util::{format_s3_error, xml_escape, xml_ok},
};

/// What a bucket's default encryption is.
#[derive(Clone, Debug, PartialEq)]
pub struct Default {
    /// SSE-KMS under this key.
    pub key_id: KeyId,
    /// Whether the configuration asked for a bucket key (S3's way of making
    /// fewer KMS calls). Told back, but every object has keys of its own.
    pub bucket_key: bool,
}

/// The bucket's default encryption, if it has one; `Err(())` if there's no
/// such bucket.
pub async fn bucket_default(app: &App, bucket: &str) -> anyhow::Result<Result<Option<Default>, ()>> {
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached(
            "SELECT sse_kms_key_id, sse_bucket_key FROM buckets WHERE name = $1",
            &[&bucket],
        )
        .await?;
    let Some(row) = row else { return Ok(Err(())) };
    let key_id: Option<String> = row.get(0);
    Ok(Ok(match key_id {
        Some(id) => Some(Default {
            key_id: KeyId::parse(&id).ok_or_else(|| anyhow::anyhow!("the stored KMS key ID {id:?} isn't one"))?,
            bucket_key: row.get(1),
        }),
        None => None,
    }))
}

/// The SSE-KMS a write to `bucket` that asks for no encryption of its own
/// (no SSE-C or SSE-KMS headers at all) is to have: its bucket's default, if
/// any. Refused if that needs a KMS, and there's none. A missing bucket is
/// the write's to report.
pub async fn default_request(
    app: &App,
    bucket: &str,
) -> anyhow::Result<Result<Option<KmsRequest>, Response<Full<Bytes>>>> {
    Ok(match bucket_default(app, bucket).await? {
        Ok(None) | Err(()) => Ok(None),
        Ok(Some(_)) if app.kms.is_none() => Err(format_s3_error(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "the bucket's default encryption is SSE-KMS, but no KMS is configured",
        )),
        Ok(Some(default)) => Ok(Some(KmsRequest { key_id: default.key_id, context: None })),
    })
}

/// GetBucketEncryption: `GET /{bucket}?encryption`. A bucket without a default
/// answers 404 ServerSideEncryptionConfigurationNotFoundError, as in S3 (before
/// SSE-S3 became every bucket's default) and MinIO.
pub async fn get_bucket_encryption(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let default = match bucket_default(app, bucket).await? {
        Ok(Some(default)) => default,
        Ok(None) => return Ok(not_found()),
        Err(()) => return Ok(no_such_bucket()),
    };
    Ok(xml_ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <ServerSideEncryptionConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Rule><ApplyServerSideEncryptionByDefault>\
         <SSEAlgorithm>aws:kms</SSEAlgorithm>\
         <KMSMasterKeyID>arn:aws:kms:{}</KMSMasterKeyID>\
         </ApplyServerSideEncryptionByDefault>\
         <BucketKeyEnabled>{}</BucketKeyEnabled></Rule>\
         </ServerSideEncryptionConfiguration>",
        xml_escape(&default.key_id.as_string()),
        default.bucket_key,
    )))
}

/// What a PutBucketEncryption body asks for.
#[derive(Debug, PartialEq)]
enum Requested {
    Kms(Default),
    /// SSE-S3 (`AES256`), which Cairn doesn't have yet.
    SseS3,
}

/// Parses a `<ServerSideEncryptionConfiguration>`: exactly one `Rule`, whose
/// `ApplyServerSideEncryptionByDefault` has an `SSEAlgorithm` (`aws:kms` with
/// a `KMSMasterKeyID`, or `AES256` without), as MinIO checks it. Why not, if
/// it isn't one.
fn parse(body: &str) -> Result<Requested, &'static str> {
    let doc = roxmltree::Document::parse(body).map_err(|_| "not XML")?;
    let root = doc.root_element();
    if root.tag_name().name() != "ServerSideEncryptionConfiguration" {
        return Err("not a ServerSideEncryptionConfiguration");
    }
    fn child<'a, 'i>(node: roxmltree::Node<'a, 'i>, name: &str) -> Vec<roxmltree::Node<'a, 'i>> {
        node.children().filter(|n| n.tag_name().name() == name).collect()
    }
    let [rule] = child(root, "Rule")[..] else {
        return Err("only one server-side encryption rule is allowed at a time");
    };
    let [action] = child(rule, "ApplyServerSideEncryptionByDefault")[..] else {
        return Err("a rule needs one ApplyServerSideEncryptionByDefault");
    };
    let text = |node, name| child(node, name).first().map(|n| n.text().unwrap_or("").trim().to_owned());
    let bucket_key = match text(rule, "BucketKeyEnabled").as_deref() {
        None | Some("false") => false,
        Some("true") => true,
        Some(_) => return Err("BucketKeyEnabled must be true or false"),
    };
    // Not trimmed: MinIO refuses a key ID with spaces around it.
    let key_id = child(action, "KMSMasterKeyID")
        .first()
        .map(|n| n.text().unwrap_or("").to_owned())
        .filter(|id| !id.is_empty());
    match (text(action, "SSEAlgorithm").as_deref(), key_id) {
        (Some("AES256"), None) => Ok(Requested::SseS3),
        (Some("AES256"), Some(_)) => Err("MasterKeyID is allowed with aws:kms only"),
        (Some("aws:kms"), None) => Err("MasterKeyID is missing with aws:kms"),
        (Some("aws:kms"), Some(id)) => {
            let id = id.strip_prefix("arn:aws:kms:").unwrap_or(&id);
            let key_id = KeyId::parse(id).ok_or("MasterKeyID contains unsupported characters")?;
            Ok(Requested::Kms(Default { key_id, bucket_key }))
        }
        _ => Err("Unknown SSE algorithm"),
    }
}

/// PutBucketEncryption: `PUT /{bucket}?encryption` with a
/// `<ServerSideEncryptionConfiguration>` body, checked against its integrity
/// headers (see `Payload`). The key must be one the KMS has: it's tried as
/// the role `role`, which needn't be one that may use it (a key the KMS
/// refuses it is taken as it is).
pub async fn put_bucket_encryption(
    app: &App,
    bucket: &str,
    body: Bytes,
    role: Uuid,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let requested = match std::str::from_utf8(&body).map_err(|_| "not UTF-8").and_then(parse) {
        Ok(requested) => requested,
        Err(why) => {
            return Ok(format_s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                &format!(
                    "The XML you provided was not well-formed or did not validate against our \
                     published schema ({why})"
                ),
            ));
        }
    };
    let Requested::Kms(default) = requested else {
        return Ok(format_s3_error(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "Cairn has no SSE-S3; a bucket's default encryption can be SSE-KMS (aws:kms)",
        ));
    };
    let Some(kms) = &app.kms else {
        return Ok(format_s3_error(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "Server side encryption specified but KMS is not configured",
        ));
    };
    if !matches!(bucket_default(app, bucket).await?, Ok(_)) {
        return Ok(no_such_bucket());
    }
    match kms.generate(role, &default.key_id, b"cairn: a bucket's default key").await {
        Ok(_) | Err(KmsError::Denied) => {}
        Err(KmsError::NoSuchKey) => {
            return Ok(format_s3_error(StatusCode::BAD_REQUEST, "KMS.NotFoundException", "Invalid keyId"));
        }
        Err(e @ (KmsError::Unavailable(_) | KmsError::LoginRefused(_))) => {
            eprintln!("kms: checking a bucket's default key: {e}");
            return Ok(format_s3_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                "the KMS is unavailable; please try again later",
            ));
        }
        Err(e @ KmsError::Failed(_)) => return Err(anyhow::Error::new(e)),
    }
    let key_id = default.key_id.as_string();
    let set = set(app, bucket, Some("aws:kms"), Some(&key_id), default.bucket_key).await?;
    Ok(if set { ok() } else { no_such_bucket() })
}

/// DeleteBucketEncryption: `DELETE /{bucket}?encryption`. New writes are no
/// longer encrypted unless they ask; what's written stays as it is.
pub async fn delete_bucket_encryption(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    if !set(app, bucket, None, None, false).await? {
        return Ok(no_such_bucket());
    }
    Ok(Response::builder().status(StatusCode::NO_CONTENT).body(Full::new(Bytes::new())).unwrap())
}

/// Sets the bucket's default (`cairn_set_encryption`). Whether it exists.
async fn set(
    app: &App,
    bucket: &str,
    algorithm: Option<&str>,
    key_id: Option<&str>,
    bucket_key: bool,
) -> anyhow::Result<bool> {
    Ok(app
        .pool
        .get()
        .await?
        .query_one_cached(
            "SELECT pg_temp.cairn_set_encryption($1, $2, $3, $4)",
            &[&bucket, &algorithm, &key_id, &bucket_key],
        )
        .await?
        .get(0))
}

fn ok() -> Response<Full<Bytes>> {
    Response::builder().status(StatusCode::OK).body(Full::new(Bytes::new())).unwrap()
}

fn not_found() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::NOT_FOUND,
        "ServerSideEncryptionConfigurationNotFoundError",
        "The server side encryption configuration was not found",
    )
}

fn no_such_bucket() -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::NOT_FOUND, "NoSuchBucket", "the specified bucket does not exist")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(rules: &str) -> String {
        format!(
            "<ServerSideEncryptionConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{rules}\
             </ServerSideEncryptionConfiguration>"
        )
    }

    fn kms(key: &str, bucket_key: &str) -> String {
        format!(
            "<Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm>\
             <KMSMasterKeyID>{key}</KMSMasterKeyID></ApplyServerSideEncryptionByDefault>{bucket_key}</Rule>"
        )
    }

    #[test]
    fn parses_configurations() {
        let default = |id: &str, bucket_key| Requested::Kms(Default { key_id: KeyId::parse(id).unwrap(), bucket_key });
        assert_eq!(parse(&config(&kms("k", ""))), Ok(default("transit/k", false)));
        assert_eq!(
            parse(&config(&kms("arn:aws:kms:team/k", "<BucketKeyEnabled>true</BucketKeyEnabled>"))),
            Ok(default("team/k", true))
        );
        let aes = "<Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm>\
                   </ApplyServerSideEncryptionByDefault></Rule>";
        assert_eq!(parse(&config(aes)), Ok(Requested::SseS3));
    }

    #[test]
    fn refuses_bad_configurations() {
        for bad in [
            "not xml".to_owned(),
            "<Other/>".to_owned(),
            config(""),
            config(&format!("{}{}", kms("a", ""), kms("b", ""))),
            config("<Rule></Rule>"),
            config(&kms("", "")),
            config(&kms(" k", "")),
            config(&kms("../k", "")),
            config(&kms("k", "<BucketKeyEnabled>yes</BucketKeyEnabled>")),
            config(
                "<Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm>\
                 <KMSMasterKeyID>k</KMSMasterKeyID></ApplyServerSideEncryptionByDefault></Rule>",
            ),
            config(
                "<Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms:dsse</SSEAlgorithm>\
                 <KMSMasterKeyID>k</KMSMasterKeyID></ApplyServerSideEncryptionByDefault></Rule>",
            ),
        ] {
            assert!(parse(&bad).is_err(), "{bad}");
        }
    }
}
