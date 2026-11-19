//! Batch Operations' `S3UpdateObjectEncryption`: changes each version's
//! server-side encryption to SSE-KMS, under the KMS key the job names, in
//! place, without its data being read or written again (see
//! `s3::sse::update_encryption`): from SSE-S3, or from SSE-KMS under
//! another key (or the same one: a new data key). A plain or SSE-C
//! version's task fails, as do those of versions that are retained or under
//! a legal hold, as S3's do. Doing it twice does no harm: the second time
//! seals the same object key under yet another data key.
//!
//! The job's role must be allowed `s3:UpdateObjectEncryption` on each
//! version (with the condition keys `s3:x-amz-server-side-encryption`,
//! `aws:kms`, and `s3:x-amz-server-side-encryption-aws-kms-key-id`, the
//! key's ARN), and the KMS must allow it the use of the key, and of the old
//! one for an SSE-KMS version (see `kms`). `BucketKeyEnabled` is accepted
//! and ignored, as it is on writes: every object has keys of its own.

use std::sync::Arc;

use http_body_util::Full;
use hyper::{Response, body::Bytes};
use serde::{Deserialize, Serialize};

use super::{
    control::{bad_request, boolean, child, element, text},
    copy::failure_of,
    manifest::Task,
    report::TaskFailure,
};
use crate::{
    App,
    kms::KeyId,
    s3::{access::Access, actions, sse::KmsRequest},
    users::Principal,
};

/// What a key ARN starts with.
const ARN_PREFIX: &str = "arn:aws:kms:";

/// The SSE-KMS encryption a job gives each version.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpdateEncryption {
    /// The KMS key's ARN, as given.
    pub key_arn: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub bucket_key: bool,
}

/// The key a KMS key ARN names: `arn:aws:kms:<region>:<account>:key/<id>`,
/// as S3 Tables has them, or `arn:aws:kms:<id>`, as S3's responses report
/// Cairn's (see `S3-COMPATIBILITY.md`), where `<id>` is `<mount>/<key>`.
fn key_id(arn: &str) -> Option<KeyId> {
    let id = arn.strip_prefix(ARN_PREFIX)?;
    let id = id.split_once(":key/").map_or(id, |(_, id)| id);
    KeyId::parse(id)
}

/// CreateJob's `<S3UpdateObjectEncryption>`: its `ObjectEncryption`'s
/// `SSE-KMS` (as S3's documents spell it; or `SSEKMS`), of a `KMSKeyArn`,
/// a key's full ARN, and `BucketKeyEnabled`.
pub(super) fn parse(operation: roxmltree::Node) -> Result<UpdateEncryption, Response<Full<Bytes>>> {
    let kms = child(operation, "ObjectEncryption")
        .and_then(|e| child(e, "SSE-KMS").or_else(|| child(e, "SSEKMS")));
    let Some(kms) = kms else {
        return Err(bad_request(
            "An ObjectEncryption of SSE-KMS is required: it's the only encryption objects can be updated to.",
        ));
    };
    let Some(key_arn) = text(kms, "KMSKeyArn") else {
        return Err(bad_request("A KMSKeyArn is required."));
    };
    if key_id(key_arn).is_none() {
        return Err(bad_request(&format!(
            "{key_arn} isn't a KMS key's ARN: arn:aws:kms:<region>:<account>:key/<mount>/<key>."
        )));
    }
    Ok(UpdateEncryption {
        key_arn: key_arn.to_owned(),
        bucket_key: boolean(kms, "BucketKeyEnabled")?.unwrap_or(false),
    })
}

impl UpdateEncryption {
    /// It as CreateJob's `<S3UpdateObjectEncryption>`, as DescribeJob tells
    /// it.
    pub fn xml(&self) -> String {
        format!(
            "<S3UpdateObjectEncryption><ObjectEncryption><SSE-KMS>{}{}</SSE-KMS></ObjectEncryption>\
             </S3UpdateObjectEncryption>",
            element("KMSKeyArn", &self.key_arn),
            element("BucketKeyEnabled", &self.bucket_key.to_string())
        )
    }

    /// The condition keys of its tasks' requests.
    pub fn set_context(&self, access: &mut Access) {
        access
            .context
            .set("s3:x-amz-server-side-encryption", crate::s3::sse::AWS_KMS);
        access.context.set(
            "s3:x-amz-server-side-encryption-aws-kms-key-id",
            &self.key_arn,
        );
    }
}

/// Updates the encryption of `task`'s version, as `access` (of the job's
/// role session `principal`, `who`) allows it; why not, if it didn't.
pub(super) async fn run(
    app: &Arc<App>,
    access: &mut Access,
    principal: &Principal,
    who: &str,
    update: &UpdateEncryption,
    task: &Task,
) -> anyhow::Result<Result<(), TaskFailure>> {
    let Task {
        bucket,
        key,
        version_id,
    } = task;
    // No request of Cairn's S3 API is this: it's allowed as its action is.
    let checks = [actions::Check {
        action: "s3:UpdateObjectEncryption",
        on: actions::On::Object(bucket.clone(), key.clone()),
    }];
    access.forget_object_tags();
    let exists = access.load(app, bucket).await?;
    access.load_all(app, &checks).await?;
    if let Some((check, _)) = access.first_denied(&checks) {
        return Ok(Err(match exists {
            false => super::no_such_bucket(),
            true => TaskFailure::new(
                403,
                "AccessDenied",
                format!(
                    "User: {who} is not authorized to perform: {} on resource: \"{}\"",
                    check.action,
                    check.on.arn()
                ),
            ),
        }));
    }
    if app.kms.is_none() {
        return Ok(Err(TaskFailure::new(
            501,
            "NotImplemented",
            "Server side encryption specified but KMS is not configured",
        )));
    }
    let Some(key_id) = key_id(&update.key_arn) else {
        anyhow::bail!("{} is no KMS key's ARN", update.key_arn);
    };
    let request = KmsRequest {
        key_id,
        context: None,
    };
    let updated = crate::s3::sse::update_encryption(
        app,
        bucket,
        key,
        version_id.as_deref(),
        &request,
        principal.kms_role(),
    )
    .await?;
    Ok(match updated {
        Ok(()) => Ok(()),
        Err(refused) => Err(failure_of(refused).await),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(operation: &str) -> Result<UpdateEncryption, u16> {
        let xml = format!("<Operation>{operation}</Operation>");
        let doc = roxmltree::Document::parse(&xml).unwrap();
        let node = doc.root_element().first_element_child().unwrap();
        parse(node).map_err(|r| r.status().as_u16())
    }

    #[test]
    fn key_arns_name_keys() {
        assert_eq!(
            key_id("arn:aws:kms:us-east-1:123456789012:key/transit/k").map(|k| k.as_string()),
            Some("transit/k".to_owned())
        );
        assert_eq!(
            key_id("arn:aws:kms:ns/transit/k").map(|k| k.as_string()),
            Some("ns/transit/k".to_owned())
        );
        assert_eq!(key_id("transit/k"), None);
        assert_eq!(key_id("arn:aws:kms:us-east-1:123456789012:alias/a"), None);
    }

    #[test]
    fn updates_are_parsed() {
        let update = parsed(
            "<S3UpdateObjectEncryption><ObjectEncryption><SSE-KMS>\
             <KMSKeyArn>arn:aws:kms:us-east-1:123456789012:key/transit/k</KMSKeyArn>\
             <BucketKeyEnabled>true</BucketKeyEnabled></SSE-KMS></ObjectEncryption></S3UpdateObjectEncryption>",
        )
        .unwrap();
        assert!(update.bucket_key);
        assert_eq!(parsed(&update.xml()).unwrap(), update);
        let update = parsed(
            "<S3UpdateObjectEncryption><ObjectEncryption><SSEKMS>\
             <KMSKeyArn>arn:aws:kms:transit/k</KMSKeyArn></SSEKMS></ObjectEncryption></S3UpdateObjectEncryption>",
        )
        .unwrap();
        assert!(!update.bucket_key);
        for bad in [
            "<S3UpdateObjectEncryption/>",
            "<S3UpdateObjectEncryption><ObjectEncryption><SSE-KMS/></ObjectEncryption></S3UpdateObjectEncryption>",
            "<S3UpdateObjectEncryption><ObjectEncryption><SSE-KMS><KMSKeyArn>k</KMSKeyArn></SSE-KMS>\
             </ObjectEncryption></S3UpdateObjectEncryption>",
            "<S3UpdateObjectEncryption><ObjectEncryption><SSE-KMS><KMSKeyArn>arn:aws:kms:transit/k</KMSKeyArn>\
             <BucketKeyEnabled>yes</BucketKeyEnabled></SSE-KMS></ObjectEncryption></S3UpdateObjectEncryption>",
        ] {
            assert_eq!(parsed(bad), Err(400), "{bad}");
        }
    }
}
