//! Object versions in the catalog: how writes and deletes land in a bucket
//! depending on its versioning state, mirroring S3.
//!
//! Every row of `objects` is one version of a key. A write to an *enabled* bucket
//! adds a version with a fresh random ID; a write to an *unversioned* or
//! *suspended* bucket replaces the key's `null` version instead. A delete without
//! a version ID removes the `null` version in an unversioned bucket, but adds a
//! delete marker once the bucket is (or was) versioned, since older versions
//! beneath it must stay hidden. A delete naming a version ID removes exactly that
//! version, for good.
//!
//! The writes and deletes themselves are catalog functions (`cairn_put_version`
//! and `cairn_delete_key` in `catalog.sql`), which run inside the caller's
//! transaction. They hand the parts of removed versions back as freed parts,
//! for the transaction to drop their blobs with at its end: only then, after it
//! has attached any parts of its own, does it know which blobs nothing
//! references anymore. (A copy of an object onto itself replaces the version it
//! references the data of.)

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use deadpool_postgres::GenericClient;
use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

use crate::db::Cached;
use crate::{auth::Rejection, s3::util::rejection_response};

/// A bucket's versioning state. A bucket starts out unversioned; once enabled,
/// it only moves between enabled and suspended. Serialized as it's stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Versioning {
    Unversioned,
    Enabled,
    Suspended,
}

impl Versioning {
    pub fn from_db(s: &str) -> Self {
        match s {
            "enabled" => Versioning::Enabled,
            "suspended" => Versioning::Suspended,
            _ => Versioning::Unversioned,
        }
    }

    pub fn as_db(self) -> &'static str {
        match self {
            Versioning::Unversioned => "unversioned",
            Versioning::Enabled => "enabled",
            Versioning::Suspended => "suspended",
        }
    }

    /// The `x-amz-version-id` to report for `version_id`. S3 only reports
    /// version IDs once a bucket has been versioned; until then there's none.
    pub fn reported(self, version_id: &str) -> Option<String> {
        (self != Versioning::Unversioned).then(|| version_id.to_owned())
    }
}

/// The versioning state of `bucket`, or `None` if there is no such bucket.
pub async fn bucket_versioning<C: GenericClient>(
    client: &C,
    bucket: &str,
) -> Result<Option<Versioning>, tokio_postgres::Error> {
    Ok(client
        .query_opt_cached("SELECT versioning FROM buckets WHERE name = $1", &[&bucket])
        .await?
        .map(|row| Versioning::from_db(row.get(0))))
}

/// A fresh, opaque version ID, which callers hand to the catalog functions
/// that may need one: 192 random bits as 32 characters of letters,
/// digits, `.` and `_` (URL-safe base64 with `-` swapped for `.`, which keeps it
/// one-to-one). None of these need escaping in a query string, and unlike a
/// leading `-`, none can make an ID look like a command-line option to a CLI.
/// It can never be `null`.
pub(crate) fn new_version_id() -> String {
    let mut bytes = [0u8; 24];
    getrandom::fill(&mut bytes).expect("the OS random number generator failed");
    URL_SAFE_NO_PAD.encode(bytes).replace('-', ".")
}

/// Whether `id` can be a version ID: `null`, or one `new_version_id` makes, 32
/// characters of URL-safe base64 (with `.` for `-`, which IDs from before that
/// swap still have). Anything else names no version, and is refused before it
/// gets anywhere, as S3 refuses a malformed one.
pub(crate) fn is_version_id(id: &str) -> bool {
    id == "null"
        || (id.len() == 32
            && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')))
}

/// S3's 400 for a version ID that can't be one, given as `argument`.
pub(crate) fn invalid_version_id(argument: &str, id: &str) -> Response<Full<Bytes>> {
    let mut rejection =
        Rejection::new(StatusCode::BAD_REQUEST, "InvalidArgument", "Invalid version id specified");
    rejection.details.push(("ArgumentName", argument.to_owned()));
    rejection.details.push(("ArgumentValue", id.to_owned()));
    rejection_response(&rejection)
}

/// The object a plain GET of the key would return, as a conditional write
/// (If-Match / If-None-Match) is decided against: its row id, and its ETag as
/// clients see it (decrypted, for SSE-S3).
pub struct Current {
    pub id: i64,
    pub etag: String,
}

/// The key's current object (see `Current`): its current version, unless
/// that's a delete marker (then the key reads as absent). `Err` holds why its
/// ETag can't be had (the KMS can't open an SSE-S3 one, say). The write
/// lands only if this is still the current one when it does (see
/// `cairn_current_version`).
pub async fn current_object(
    app: &crate::App,
    bucket: &str,
    key: &str,
) -> anyhow::Result<Result<Option<Current>, Response<Full<Bytes>>>> {
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached(
            "SELECT id, etag, sse_c_key, sse_kms_key_id, sse_kms_data_key, sse_kms_sealed,
                    sse_kms_context, sse_s3
             FROM objects
             WHERE bucket = $1 AND key = $2 AND is_latest AND NOT is_delete_marker",
            &[&bucket, &key],
        )
        .await?;
    let Some(row) = row else { return Ok(Ok(None)) };
    let stored = crate::s3::sse::Stored::from_row(&row, 2);
    let etag: String = row.get(1);
    Ok(crate::s3::sse::plain_etag(app, &stored, &etag, bucket, key)
        .await?
        .map(|etag| Some(Current { id: row.get(0), etag })))
}

/// The outcome of a delete: the `x-amz-version-id` to report, and whether the
/// version it concerns is a delete marker (one just created, or the one removed).
pub struct Deleted {
    pub version_id: Option<String>,
    pub delete_marker: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_ids_use_a_safe_alphabet() {
        for _ in 0..1000 {
            let id = new_version_id();
            assert_eq!(id.len(), 32);
            assert!(
                id.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_'),
                "{id}"
            );
            assert!(is_version_id(&id), "{id}");
        }
    }

    #[test]
    fn only_version_ids_are_version_ids() {
        assert!(is_version_id("null"));
        // From before `-` was swapped for `.`.
        assert!(is_version_id("Ab-_0123456789abcdefghijklmnopqr"));
        let long = "a".repeat(33);
        for bad in [
            "",
            "NULL",
            "abc",
            "Ab-_0123456789abcdefghijklmnopq\n",
            "Ab-_0123456789abcdefghijklmnop/r",
            &long,
        ] {
            assert!(!is_version_id(bad), "{bad:?}");
        }
    }
}
