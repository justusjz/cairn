pub mod abort;
pub mod complete;
pub mod create;
pub mod list;
pub mod list_parts;
pub mod upload_part;

use uuid::Uuid;

use crate::{
    App,
    db::Cached,
    s3::checksums::{Algorithm, Type, Wanted},
    s3::sse::Stored,
};

/// An upload's `<Initiator>`, as S3 tells it (probed): the ARN of the
/// principal that began it, and its name: a user's name, or a role
/// session's `<role>/<session>`. An upload of an anonymous request's, or one
/// from before Cairn kept who began it, names the account (`owner_id`, its
/// canonical ID), as its `<Owner>` does.
pub(crate) fn initiator_xml(initiator: Option<&str>, owner_id: &str) -> String {
    use crate::s3::util::xml_escape;
    let Some(arn) = initiator else {
        return format!("<Initiator><ID>{owner_id}</ID></Initiator>");
    };
    // `arn:aws:<service>::<account>:<resource>`
    let resource = arn.splitn(6, ':').nth(5).unwrap_or("");
    let name = match resource.split_once('/') {
        // A user's path isn't part of its name.
        Some(("user", rest)) => rest.rsplit('/').next().unwrap_or(rest),
        // `assumed-role/<role>/<session>`, `federated-user/<name>`.
        Some((_, rest)) => rest,
        None => resource,
    };
    format!(
        "<Initiator><ID>{}</ID><DisplayName>{}</DisplayName></Initiator>",
        xml_escape(arn),
        xml_escape(name)
    )
}

/// An upload in progress, as its parts and its completion need it.
pub(crate) struct Upload {
    /// How it's encrypted (see `s3::sse`).
    pub encryption: Stored,
    /// The checksum its client asked for, if it did (see `s3::checksums`).
    pub checksum: Option<(Algorithm, Type)>,
    /// Its storage class (see `classes`), its parts'.
    pub storage_class: String,
}

impl Upload {
    /// The checksum its parts are stored with: of the algorithm its client
    /// asked for, or else CRC64NVME, the default S3 gives an object (as a
    /// FULL_OBJECT checksum). But an SSE-C upload's without an algorithm get
    /// none: S3 needs the key on CompleteMultipartUpload and ListParts only
    /// for an upload with one, so it can't have checksums sealed under it.
    pub fn part_checksum(&self) -> Wanted {
        match (self.checksum, &self.encryption) {
            (Some((algorithm, _)), _) => Wanted::Exactly(algorithm),
            (None, Stored::Customer { .. }) => Wanted::Nothing,
            (None, _) => Wanted::Exactly(Algorithm::Crc64Nvme),
        }
    }

    /// Why a part declaring a checksum of `declared` (if any) can't be one
    /// of this upload, if it can't: an upload of an algorithm takes parts
    /// with checksums of it only, but a FULL_OBJECT one's parts may come
    /// without, their checksums worked out here, as S3 does (probed).
    pub fn mismatch(&self, declared: Option<Algorithm>) -> Option<String> {
        let (algorithm, kind) = self.checksum?;
        if declared == Some(algorithm) || (declared.is_none() && kind == Type::FullObject) {
            return None;
        }
        Some(format!(
            "Checksum Type mismatch occurred, expected checksum Type: {}, actual checksum Type: {}",
            algorithm.name().to_lowercase(),
            declared.map_or("null".to_owned(), |a| a.name().to_lowercase())
        ))
    }

    /// The algorithm and type of the object's checksum, if it gets one.
    pub fn object_checksum(&self) -> Option<(Algorithm, Type)> {
        match self.part_checksum() {
            Wanted::Exactly(algorithm) => Some((
                algorithm,
                self.checksum.map_or(Type::FullObject, |(_, kind)| kind),
            )),
            _ => None,
        }
    }
}

/// S3's 404 for an upload that isn't there (probed), naming it.
pub(crate) fn no_such_upload(
    upload_id: &str,
) -> hyper::Response<http_body_util::Full<hyper::body::Bytes>> {
    let mut rejection = crate::auth::Rejection::new(
        hyper::StatusCode::NOT_FOUND,
        "NoSuchUpload",
        "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.",
    );
    rejection.details.push(("UploadId", upload_id.to_owned()));
    crate::s3::util::rejection_response(&rejection)
}

/// The upload `upload_id`, or `None` if there's no such upload of
/// `bucket`/`key` (authorization only checked the bucket).
pub(crate) async fn upload(
    app: &App,
    upload_id: &Uuid,
    bucket: &str,
    key: &str,
) -> anyhow::Result<Option<Upload>> {
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached(
            "SELECT sse_c_key, sse_kms_key_id, sse_kms_data_key, sse_kms_sealed, sse_kms_context, sse_s3,
                    checksum_algorithm, checksum_type, storage_class
             FROM multipart_uploads WHERE upload_id = $1 AND bucket = $2 AND key = $3",
            &[upload_id, &bucket, &key],
        )
        .await?;
    Ok(row.map(|row| Upload {
        encryption: Stored::from_row(&row, 0),
        checksum: checksum_columns(&row, 6),
        storage_class: row.get(8),
    }))
}

/// An algorithm and type from a row's two columns, from `first` on.
pub(crate) fn checksum_columns(
    row: &tokio_postgres::Row,
    first: usize,
) -> Option<(Algorithm, Type)> {
    let algorithm: Option<&str> = row.get(first);
    let kind: Option<&str> = row.get(first + 1);
    Some((Algorithm::from_name(algorithm?)?, Type::from_name(kind?)?))
}

/// How an upload is encrypted (see `s3::sse`), or `None` if there's no such
/// upload of `bucket`/`key`.
#[cfg(test)]
pub(crate) async fn upload_encryption(
    app: &App,
    upload_id: &Uuid,
    bucket: &str,
    key: &str,
) -> anyhow::Result<Option<Stored>> {
    Ok(upload(app, upload_id, bucket, key)
        .await?
        .map(|upload| upload.encryption))
}

#[cfg(test)]
mod initiator_tests {
    use super::initiator_xml;

    /// As S3 names them (probed, `plans/probes/expiration_probe.py`).
    #[test]
    fn initiators_are_named_as_in_s3() {
        assert_eq!(
            initiator_xml(Some("arn:aws:iam::258167966071:user/demo"), "c"),
            "<Initiator><ID>arn:aws:iam::258167966071:user/demo</ID><DisplayName>demo</DisplayName></Initiator>"
        );
        assert_eq!(
            initiator_xml(
                Some("arn:aws:sts::258167966071:assumed-role/probe/sess-1"),
                "c"
            ),
            "<Initiator><ID>arn:aws:sts::258167966071:assumed-role/probe/sess-1</ID>\
             <DisplayName>probe/sess-1</DisplayName></Initiator>"
        );
        assert!(
            initiator_xml(Some("arn:aws:iam::1:user/team/alice"), "c")
                .contains("<DisplayName>alice</DisplayName>")
        );
        assert_eq!(
            initiator_xml(None, "c"),
            "<Initiator><ID>c</ID></Initiator>"
        );
    }
}
