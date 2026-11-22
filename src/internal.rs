//! What Cairn keeps for itself, out of everyone's reach: an internal
//! account (`accounts.internal`), closed from the start, so that it has no
//! principals, and in no listing of accounts; and its one bucket, named
//! `BUCKET`, which no S3 bucket can be (it has a `_`), and so no request
//! names (`s3` refuses it as a bucket that doesn't exist), in no listing of
//! buckets. Cairn writes and reads its objects itself, as it does any
//! bucket's, without asking anyone's permission (see `db::BATCH_MANIFEST_GENERATORS`).
//!
//! What's kept there: the manifests Batch Operations' jobs generate, while
//! the jobs last (see `batch::generate`), under `jobs/`; and the audit
//! log's records, for 90 days (see `audit::ship`), under `audit/`; and
//! streams' records (see `streams`), for their streams' retention, under
//! `streams/`.

/// The internal bucket's name.
pub const BUCKET: &str = "cairn_internal";

/// Whether `bucket` is the internal bucket.
pub fn is_internal(bucket: &str) -> bool {
    bucket == BUCKET
}
