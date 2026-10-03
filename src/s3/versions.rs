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
//! All of this runs inside the caller's serializable transaction. Removed
//! versions' part locations are pushed onto a reap list for the caller to delete
//! after commit; if it never gets to, `cairn prune` reclaims the files.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use deadpool_postgres::GenericClient;

use crate::{ReapTarget, reap_targets};

/// A bucket's versioning state. A bucket starts out unversioned; once enabled,
/// it only moves between enabled and suspended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

/// A fresh, opaque version ID: 192 random bits as 32 URL-safe base64 characters,
/// so it needs no escaping in a query string and can never be `null`.
fn new_version_id() -> String {
    let mut bytes = [0u8; 24];
    getrandom::fill(&mut bytes).expect("the OS random number generator failed");
    URL_SAFE_NO_PAD.encode(bytes)
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

/// A version just written: its row id (to attach parts to) and the
/// `x-amz-version-id` to report for it.
pub struct NewVersion {
    pub id: i64,
    pub version_id: Option<String>,
}

/// Writes a new object version as the key's current version, the way S3 lands a
/// write in a bucket with the given versioning state. Locations of any parts it
/// replaces are pushed onto `reap`.
pub async fn put_version<C: GenericClient>(
    client: &C,
    bucket: &str,
    key: &str,
    versioning: Versioning,
    size: i64,
    etag: &str,
    content_type: &str,
    reap: &mut Vec<ReapTarget>,
) -> Result<NewVersion, tokio_postgres::Error> {
    let version_id = match versioning {
        Versioning::Enabled => new_version_id(),
        // The null version is replaced wherever it sits among the key's versions.
        Versioning::Unversioned | Versioning::Suspended => {
            remove_null_version(client, bucket, key, reap).await?;
            "null".to_owned()
        }
    };
    demote_current(client, bucket, key).await?;
    let id: i64 = client
        .query_one(
            "INSERT INTO objects (bucket, key, version_id, is_latest, is_delete_marker,
                                  size, etag, content_type, last_modified)
             VALUES ($1, $2, $3, true, false, $4, $5, $6, NOW())
             RETURNING id",
            &[&bucket, &key, &version_id, &size, &etag, &content_type],
        )
        .await?
        .get(0);
    Ok(NewVersion {
        id,
        version_id: versioning.reported(&version_id),
    })
}

/// The outcome of a delete: the `x-amz-version-id` to report, and whether the
/// version it concerns is a delete marker (one just created, or the one removed).
pub struct Deleted {
    pub version_id: Option<String>,
    pub delete_marker: bool,
}

/// Deletes `key` the way S3 does in a bucket with the given versioning state.
/// With a `version_id`, that version is removed for good (a no-op if there's no
/// such version); if it was current, the next-newest version takes its place.
/// Without one, an unversioned bucket drops the `null` version, while a versioned
/// one stacks a delete marker on top (a suspended bucket's marker replaces the
/// `null` version). Locations of removed parts are pushed onto `reap`.
pub async fn delete_key<C: GenericClient>(
    client: &C,
    bucket: &str,
    key: &str,
    versioning: Versioning,
    version_id: Option<&str>,
    reap: &mut Vec<ReapTarget>,
) -> Result<Deleted, tokio_postgres::Error> {
    if let Some(version_id) = version_id {
        let row = client
            .query_opt(
                "SELECT id, is_latest, is_delete_marker FROM objects
                 WHERE bucket = $1 AND key = $2 AND version_id = $3",
                &[&bucket, &key, &version_id],
            )
            .await?;
        let mut delete_marker = false;
        if let Some(row) = row {
            delete_marker = row.get(2);
            remove_version(client, row.get(0), reap).await?;
            if row.get::<_, bool>(1) {
                promote_newest(client, bucket, key).await?;
            }
        }
        return Ok(Deleted {
            version_id: Some(version_id.to_owned()),
            delete_marker,
        });
    }
    let marker_id = match versioning {
        Versioning::Unversioned => {
            remove_null_version(client, bucket, key, reap).await?;
            return Ok(Deleted {
                version_id: None,
                delete_marker: false,
            });
        }
        Versioning::Enabled => new_version_id(),
        Versioning::Suspended => {
            remove_null_version(client, bucket, key, reap).await?;
            "null".to_owned()
        }
    };
    demote_current(client, bucket, key).await?;
    client
        .execute(
            "INSERT INTO objects (bucket, key, version_id, is_latest, is_delete_marker,
                                  size, etag, content_type, last_modified)
             VALUES ($1, $2, $3, true, true, 0, NULL, NULL, NOW())",
            &[&bucket, &key, &marker_id],
        )
        .await?;
    Ok(Deleted {
        version_id: Some(marker_id),
        delete_marker: true,
    })
}

/// Removes the key's `null` version, if it has one.
async fn remove_null_version<C: GenericClient>(
    client: &C,
    bucket: &str,
    key: &str,
    reap: &mut Vec<ReapTarget>,
) -> Result<(), tokio_postgres::Error> {
    let row = client
        .query_opt(
            "SELECT id FROM objects WHERE bucket = $1 AND key = $2 AND version_id = 'null'",
            &[&bucket, &key],
        )
        .await?;
    if let Some(row) = row {
        remove_version(client, row.get(0), reap).await?;
    }
    Ok(())
}

/// Removes the version with row id `id`, cascading its parts and part_locations
/// away. Their locations are captured first, so the caller can reap the files.
async fn remove_version<C: GenericClient>(
    client: &C,
    id: i64,
    reap: &mut Vec<ReapTarget>,
) -> Result<(), tokio_postgres::Error> {
    let located = client
        .query(
            "SELECT pl.part_id, pl.node_id, n.peer_url
             FROM parts p
             JOIN part_locations pl ON pl.part_id = p.part_id
             JOIN nodes n ON n.node_id = pl.node_id
             WHERE p.object_id = $1",
            &[&id],
        )
        .await?;
    reap.extend(reap_targets(&located));
    client
        .execute("DELETE FROM objects WHERE id = $1", &[&id])
        .await?;
    Ok(())
}

/// Clears the current-version flag of the key, ahead of inserting a new current
/// version.
async fn demote_current<C: GenericClient>(
    client: &C,
    bucket: &str,
    key: &str,
) -> Result<(), tokio_postgres::Error> {
    client
        .execute(
            "UPDATE objects SET is_latest = false WHERE bucket = $1 AND key = $2 AND is_latest",
            &[&bucket, &key],
        )
        .await?;
    Ok(())
}

/// Makes the key's newest remaining version current, after the current one was
/// removed. A key with no versions left simply ceases to exist.
async fn promote_newest<C: GenericClient>(
    client: &C,
    bucket: &str,
    key: &str,
) -> Result<(), tokio_postgres::Error> {
    client
        .execute(
            "UPDATE objects SET is_latest = true
             WHERE id = (SELECT max(id) FROM objects WHERE bucket = $1 AND key = $2)",
            &[&bucket, &key],
        )
        .await?;
    Ok(())
}
