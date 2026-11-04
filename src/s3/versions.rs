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
        .query_opt("SELECT versioning FROM buckets WHERE name = $1", &[&bucket])
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

/// The ETag of the object a plain GET of the key would return: the current
/// version, unless that's a delete marker (then the key reads as absent). This is
/// what conditional writes (If-Match / If-None-Match) are evaluated against.
pub async fn current_etag<C: GenericClient>(
    client: &C,
    bucket: &str,
    key: &str,
) -> Result<Option<String>, tokio_postgres::Error> {
    Ok(client
        .query_opt(
            "SELECT etag FROM objects
             WHERE bucket = $1 AND key = $2 AND is_latest AND NOT is_delete_marker",
            &[&bucket, &key],
        )
        .await?
        .map(|row| row.get(0)))
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
        }
    }
}
