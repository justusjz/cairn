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

/// An upload in progress, as its parts and its completion need it.
pub(crate) struct Upload {
    /// How it's encrypted (see `s3::sse`).
    pub encryption: Stored,
    /// The checksum its client asked for, if it did (see `s3::checksums`).
    pub checksum: Option<(Algorithm, Type)>,
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
            Wanted::Exactly(algorithm) => {
                Some((algorithm, self.checksum.map_or(Type::FullObject, |(_, kind)| kind)))
            }
            _ => None,
        }
    }
}

/// The upload `upload_id`, or `None` if there's no such upload of
/// `bucket`/`key` (authorization only checked the bucket).
pub(crate) async fn upload(app: &App, upload_id: &Uuid, bucket: &str, key: &str) -> anyhow::Result<Option<Upload>> {
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached(
            "SELECT sse_c_key, sse_kms_key_id, sse_kms_data_key, sse_kms_sealed, sse_kms_context, sse_s3,
                    checksum_algorithm, checksum_type
             FROM multipart_uploads WHERE upload_id = $1 AND bucket = $2 AND key = $3",
            &[upload_id, &bucket, &key],
        )
        .await?;
    Ok(row.map(|row| Upload {
        encryption: Stored::from_row(&row, 0),
        checksum: checksum_columns(&row, 6),
    }))
}

/// An algorithm and type from a row's two columns, from `first` on.
pub(crate) fn checksum_columns(row: &tokio_postgres::Row, first: usize) -> Option<(Algorithm, Type)> {
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
    Ok(upload(app, upload_id, bucket, key).await?.map(|upload| upload.encryption))
}
