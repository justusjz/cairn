use std::str::FromStr;
use std::time::Duration;

use deadpool_postgres::{Manager, ManagerConfig, Pool};
use tokio_postgres::NoTls;

const RETRY_INTERVAL: Duration = Duration::from_secs(1);
const MAX_ATTEMPTS: u32 = 60;

pub async fn connect(url: &str) -> anyhow::Result<Pool> {
    let conf = tokio_postgres::Config::from_str(url)?;
    let mgr = Manager::from_config(
        conf,
        NoTls,
        ManagerConfig {
            recycling_method: deadpool_postgres::RecyclingMethod::Fast,
        },
    );
    let pool = Pool::builder(mgr).max_size(16).build()?;
    // Postgres may not be up yet (e.g. started alongside us), so retry the initial
    // connect + schema for a while before giving up rather than crashing on boot.
    let mut attempt = 0;
    loop {
        attempt += 1;
        match init(&pool).await {
            Ok(()) => return Ok(pool),
            Err(e) if attempt >= MAX_ATTEMPTS => return Err(e),
            Err(e) => {
                eprintln!("waiting for postgres (attempt {attempt}/{MAX_ATTEMPTS}): {e}");
                tokio::time::sleep(RETRY_INTERVAL).await;
            }
        }
    }
}

/// How often a serializable transaction is attempted while it keeps failing
/// with serialization conflicts. With the pauses of [`backoff`], that's up to
/// about a second and a half of retrying.
pub const MAX_TX_ATTEMPTS: usize = 20;

/// Whether `e` is a conflict with a concurrent transaction, which the
/// transaction may not hit again if it's retried. That's a serialization
/// failure, or a unique violation: two writes that both find a key free (say,
/// the first two uploads to it) both insert it, and Postgres may report the
/// second one's failure as either. The transactions that retry on conflicts
/// only insert unique keys after checking that they're free, so a unique
/// violation can only come from such a race.
pub fn is_conflict(e: &tokio_postgres::Error) -> bool {
    use tokio_postgres::error::SqlState;
    matches!(
        e.code(),
        Some(&SqlState::T_R_SERIALIZATION_FAILURE | &SqlState::UNIQUE_VIOLATION)
    )
}

/// Waits before attempt `attempt` (counting from 0) of a transaction that hit
/// a serialization conflict. The first attempt goes ahead right away. After
/// that, the pause grows exponentially, from up to 1 ms to up to 100 ms, and is
/// random within that, so that transactions that collided don't retry in step
/// and collide again.
pub async fn backoff(attempt: usize) {
    if attempt == 0 {
        return;
    }
    let max = Duration::from_millis(1 << (attempt - 1).min(7)).min(Duration::from_millis(100));
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).expect("the OS random number generator failed");
    let fraction = u64::from_le_bytes(random) as f64 / u64::MAX as f64;
    tokio::time::sleep(max.mul_f64(fraction)).await;
}

/// Arbitrary key for the advisory lock that serializes migrations, so nodes
/// starting at the same time don't race to apply the same step.
const MIGRATION_LOCK: i64 = 0x6361_6972_6e00; // "cairn\0"

/// The schema, as an ordered list of steps. Migration `n` (1-based) is
/// `MIGRATIONS[n - 1]`; `schema_migrations` records which have been applied.
/// Only ever append: an applied step must never change.
const MIGRATIONS: &[&str] = &[
    INITIAL_SCHEMA,
    VERSIONING,
    DELETE_VERSION_GRANT,
    BLOBS,
    PACKING,
    GC,
];

/// Applies every pending migration in a single transaction, so a failure leaves
/// the schema untouched. Refuses to run against a database migrated by a newer
/// Cairn, whose schema this binary doesn't understand.
async fn init(pool: &Pool) -> anyhow::Result<()> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK])
        .await?;
    tx.batch_execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
             version     INT PRIMARY KEY,
             applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
         )",
    )
    .await?;
    let current: i32 = tx
        .query_one("SELECT coalesce(max(version), 0) FROM schema_migrations", &[])
        .await?
        .get(0);
    let known = MIGRATIONS.len() as i32;
    if current > known {
        anyhow::bail!(
            "database schema is at version {current}, but this Cairn only knows up to {known}; \
             upgrade Cairn"
        );
    }
    for (version, sql) in (1..).zip(MIGRATIONS).skip(current as usize) {
        tx.batch_execute(sql).await?;
        tx.execute(
            "INSERT INTO schema_migrations (version) VALUES ($1)",
            &[&version],
        )
        .await?;
        eprintln!("applied schema migration {version}");
    }
    tx.commit().await?;
    Ok(())
}

/// Migration 1: the schema as it stood before migrations were tracked. Written
/// with `IF NOT EXISTS`, so a database created by an earlier Cairn (which ran
/// this on every boot) passes through it unchanged.
const INITIAL_SCHEMA: &str = r#"
-- Cluster membership: each node self-registers and heartbeats `last_seen`.
-- node_id is a UUID bound to the node's data dir (never operator-supplied).
CREATE TABLE IF NOT EXISTS nodes (
    node_id     TEXT PRIMARY KEY,
    peer_url    TEXT NOT NULL,
    last_seen   TIMESTAMPTZ NOT NULL,
    free_space  BIGINT NOT NULL            -- Free space available in bytes
);

CREATE TABLE IF NOT EXISTS buckets (
    name        TEXT PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS objects (
    bucket        TEXT NOT NULL REFERENCES buckets(name) ON DELETE CASCADE,
    key           TEXT NOT NULL,
    size          BIGINT NOT NULL,          -- total object size in bytes
    etag          TEXT NOT NULL,            -- S3 ETag
    content_type  TEXT NOT NULL,
    last_modified TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (bucket, key)
);

-- In-progress multipart uploads. Keyed by upload_id and kept entirely separate
-- from the live (bucket, key) object mapping: the object stays readable with its
-- old data until CompleteMultipartUpload performs the atomic swap. `key` is plain
-- text (the target object need not exist yet), only `bucket` must.
CREATE TABLE IF NOT EXISTS multipart_uploads (
    upload_id     UUID PRIMARY KEY,
    bucket        TEXT NOT NULL REFERENCES buckets(name) ON DELETE CASCADE,
    key           TEXT NOT NULL,
    content_type  TEXT NOT NULL,
    initiated_at  TIMESTAMPTZ NOT NULL
);

-- A stored blob, plus its ownership. A committed part belongs to exactly one of
-- an object or an in-progress upload; a pending (in-flight) part may have neither
-- yet, since a single-PUT object row doesn't exist until commit. The owner FKs
-- are ON DELETE CASCADE: dropping an object or upload reclaims its part rows,
-- which in turn cascades part_locations -- so the GC only ever has to reconcile
-- dangling files against this table, never trace references.
CREATE TABLE IF NOT EXISTS parts (
    part_id        UUID PRIMARY KEY,
    size           BIGINT NOT NULL,
    state          TEXT NOT NULL,            -- 'pending' | 'committed'
    created_at     TIMESTAMPTZ NOT NULL,
    etag           TEXT,                     -- per-part MD5 hex, set at commit
    object_bucket  TEXT,
    object_key     TEXT,
    upload_id      UUID,
    part_number    INT,                      -- ordering within the owner
    FOREIGN KEY (object_bucket, object_key) REFERENCES objects(bucket, key) ON DELETE CASCADE,
    FOREIGN KEY (upload_id) REFERENCES multipart_uploads(upload_id) ON DELETE CASCADE,
    -- object_bucket / object_key are set together or not at all (composite FKs
    -- use MATCH SIMPLE, so a half-set owner would silently skip the FK check).
    CHECK ((object_bucket IS NULL) = (object_key IS NULL)),
    -- At most one owner. (Not exactly one: a pending single-PUT part has neither
    -- until commit; "committed implies an owner" is an application invariant.)
    CHECK (num_nonnulls(object_key, upload_id) <= 1)
);

-- One part per (owner, part_number); partial so pending/unowned parts (all NULL)
-- don't collide.
CREATE UNIQUE INDEX IF NOT EXISTS parts_object_part_number
    ON parts (object_bucket, object_key, part_number)
    WHERE object_key IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS parts_upload_part_number
    ON parts (upload_id, part_number)
    WHERE upload_id IS NOT NULL;

-- S3 credentials. The role name is the access key ID. The secret is stored in
-- plaintext because SigV4 is an HMAC scheme: verifying a signature needs the
-- secret itself, not a hash of it. `admin` grants bucket management (create,
-- delete, list all) but no object access.
CREATE TABLE IF NOT EXISTS roles (
    name        TEXT PRIMARY KEY,
    secret      TEXT NOT NULL,
    admin       BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-bucket object permissions. A grant needs its bucket to exist, and goes
-- away with it: a bucket re-created under the same name starts with no grants,
-- so a stale grant can't silently hand an old role access to a new bucket.
CREATE TABLE IF NOT EXISTS role_grants (
    role        TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
    bucket      TEXT NOT NULL REFERENCES buckets(name) ON DELETE CASCADE,
    permission  TEXT NOT NULL CHECK (permission IN ('read', 'write')),
    PRIMARY KEY (role, bucket, permission)
);

CREATE TABLE IF NOT EXISTS part_locations (
    part_id     UUID NOT NULL REFERENCES parts(part_id) ON DELETE CASCADE,
    node_id     TEXT NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE,
    PRIMARY KEY (part_id, node_id)
);
"#;

/// Migration 2: object versioning. `objects` goes from one row per key to one
/// row per *version* of a key, identified by a surrogate `id` that parts now
/// reference. Existing objects become the `null` version (what S3 calls the
/// version of an object written while the bucket was unversioned), and every
/// bucket starts out unversioned.
const VERSIONING: &str = r#"
-- 'unversioned' until versioning is first enabled; after that it only moves
-- between 'enabled' and 'suspended', never back (as in S3).
ALTER TABLE buckets ADD COLUMN versioning TEXT NOT NULL DEFAULT 'unversioned'
    CHECK (versioning IN ('unversioned', 'enabled', 'suspended'));

-- `id` is internal: it is the row's identity and orders a key's versions
-- (higher is newer). Replacing the null version deletes its row and inserts a
-- fresh one, so the replacement also sorts newest. `version_id` is the opaque
-- S3 version ID, or the literal 'null'. A delete marker carries no data, so it
-- has no ETag or content type.
ALTER TABLE objects
    ADD COLUMN id BIGINT GENERATED ALWAYS AS IDENTITY,
    ADD COLUMN version_id TEXT NOT NULL DEFAULT 'null',
    ADD COLUMN is_latest BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN is_delete_marker BOOLEAN NOT NULL DEFAULT false,
    ALTER COLUMN etag DROP NOT NULL,
    ALTER COLUMN content_type DROP NOT NULL;
-- The defaults only exist to backfill existing rows; new rows must be explicit.
ALTER TABLE objects
    ALTER COLUMN version_id DROP DEFAULT,
    ALTER COLUMN is_latest DROP DEFAULT,
    ALTER COLUMN is_delete_marker DROP DEFAULT,
    ADD CHECK (is_delete_marker = (etag IS NULL)),
    ADD CHECK (is_delete_marker = (content_type IS NULL)),
    ADD CHECK (NOT is_delete_marker OR size = 0);

-- Re-point parts from (object_bucket, object_key) to the version's id. Dropping
-- the old columns also drops the composite FK, the unique part-number index and
-- both CHECKs that mention them; they're recreated against object_id below,
-- once `id` is the primary key.
ALTER TABLE parts ADD COLUMN object_id BIGINT;
UPDATE parts p SET object_id = o.id
    FROM objects o
    WHERE o.bucket = p.object_bucket AND o.key = p.object_key;
ALTER TABLE parts DROP COLUMN object_bucket, DROP COLUMN object_key;

-- (bucket, key) is no longer unique, only (bucket, key, version_id) is.
ALTER TABLE objects DROP CONSTRAINT objects_pkey;
ALTER TABLE objects ADD PRIMARY KEY (id);
ALTER TABLE objects ADD UNIQUE (bucket, key, version_id);

ALTER TABLE parts
    ADD FOREIGN KEY (object_id) REFERENCES objects(id) ON DELETE CASCADE,
    -- At most one owner, as before.
    ADD CHECK (num_nonnulls(object_id, upload_id) <= 1);
CREATE UNIQUE INDEX parts_object_part_number
    ON parts (object_id, part_number)
    WHERE object_id IS NOT NULL;
-- At most one current version per key; the current version is what a plain
-- GET/HEAD sees (unless it's a delete marker, in which case the key reads as
-- absent).
CREATE UNIQUE INDEX objects_latest ON objects (bucket, key) WHERE is_latest;
-- ListObjects(V2) scans only live objects: current, and not a delete marker.
CREATE INDEX objects_live ON objects (bucket, key)
    WHERE is_latest AND NOT is_delete_marker;
-- ListObjectVersions walks each key's versions newest first.
CREATE INDEX objects_versions ON objects (bucket, key, id DESC);
"#;

/// Migration 3: the `delete-version` grant, which permanently deletes specific
/// object versions. Kept apart from `write` so that a role able to write (e.g. a
/// backup client) can't destroy the history versioning preserves.
const DELETE_VERSION_GRANT: &str = r#"
ALTER TABLE role_grants
    DROP CONSTRAINT role_grants_permission_check,
    ADD CONSTRAINT role_grants_permission_check
        CHECK (permission IN ('read', 'write', 'delete-version'));
"#;

/// Migration 4: blobs. What's stored on disk is now a *blob*, and a part is a
/// byte range of one: parts link objects to blobs, and blobs carry the replica
/// locations and the pending/committed state that parts used to. Several parts
/// may share a blob (packing small parts together, metadata-only copies), so a
/// blob lives exactly as long as some part references it.
///
/// Each existing part becomes a blob with the same ID, so the files on disk keep
/// their names. Those files have no checksum table (see `blob_file`); new blobs
/// always do.
const BLOBS: &str = r#"
-- A compact number for each node, for blob_locations (which has a row per
-- replica of every blob) to refer to it by. node_id stays its identity.
ALTER TABLE nodes ADD COLUMN id INT GENERATED ALWAYS AS IDENTITY UNIQUE;

-- A file stored on one or more nodes. `pending` while its replicas are being
-- written; it's committed together with the first part that references it, so
-- a committed blob that no part references is garbage.
--
-- The block checksums (CRC32C) live in a table inside the blob file, not here.
-- The catalog records the block size (the file doesn't describe itself, so
-- this is how readers know its layout) and the CRC64/NVME of the whole file
-- as stored (data, checksum table and blob ID, identical on every replica),
-- which a scrub checks the file against. A different algorithm than the blocks'
-- on purpose, so it's an independent second check. Both are set at commit, and
-- are NULL for a pending blob and for one written before checksums, whose file
-- is bare data. CRCs are stored as their 64 bits, read as a signed BIGINT.
CREATE TABLE blobs (
    blob_id     UUID PRIMARY KEY,
    size        BIGINT NOT NULL CHECK (size >= 0),
    state       TEXT NOT NULL CHECK (state IN ('pending', 'committed')),
    created_at  TIMESTAMPTZ NOT NULL,
    block_size  INT CHECK (block_size > 0),
    crc64nvme   BIGINT,
    CHECK ((block_size IS NULL) = (crc64nvme IS NULL))
);
INSERT INTO blobs (blob_id, size, state, created_at)
    SELECT part_id, size, state, created_at FROM parts;

CREATE TABLE blob_locations (
    blob_id     UUID NOT NULL REFERENCES blobs(blob_id) ON DELETE CASCADE,
    node        INT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    PRIMARY KEY (blob_id, node)
);
-- What a node holds, for prune (and later scrub and repair).
CREATE INDEX blob_locations_node ON blob_locations (node);
INSERT INTO blob_locations (blob_id, node)
    SELECT pl.part_id, n.id FROM part_locations pl JOIN nodes n ON n.node_id = pl.node_id;
DROP TABLE part_locations;

-- A part now only exists once its data is committed, so it always has exactly
-- one owner. Pending parts live on as pending blobs (reaped by `cairn prune`),
-- as do committed parts that somehow lost their owner (unreferenced blobs, also
-- reaped by prune).
DELETE FROM parts WHERE state = 'pending' OR num_nonnulls(object_id, upload_id) = 0;

-- The part's bytes are [blob_offset, blob_offset + size) of its blob. The FK
-- has no cascade: a blob can't be deleted while a part still references it.
-- `crc64nvme` is the CRC64/NVME of the part's own bytes, which stays valid
-- wherever the part is moved; NULL for parts written before checksums. It's
-- also the checksum S3 computes for objects by default. Nothing refers
-- to a part by its ID, so the UUID gives way to a plain sequence.
ALTER TABLE parts
    ADD COLUMN blob_id UUID,
    ADD COLUMN blob_offset BIGINT NOT NULL DEFAULT 0 CHECK (blob_offset >= 0),
    ADD COLUMN crc64nvme BIGINT;
UPDATE parts SET blob_id = part_id;
ALTER TABLE parts
    DROP COLUMN part_id,
    ADD COLUMN id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ALTER COLUMN blob_id SET NOT NULL,
    ALTER COLUMN blob_offset DROP DEFAULT,
    ALTER COLUMN etag SET NOT NULL,
    ADD FOREIGN KEY (blob_id) REFERENCES blobs(blob_id),
    ADD CHECK (size >= 0),
    -- Replaces migration 2's "at most one owner" check.
    DROP CONSTRAINT IF EXISTS parts_check,
    ADD CONSTRAINT parts_one_owner CHECK (num_nonnulls(object_id, upload_id) = 1),
    DROP COLUMN state,
    DROP COLUMN created_at;
-- Finding a blob's parts: is it still referenced, and (later) which parts to
-- re-point when it's repacked.
CREATE INDEX parts_blob ON parts (blob_id);
"#;

/// Migration 5: packing (see `packer`). Parts get their age, which the packer
/// groups them by, and blobs get what the packer needs to pick and claim them:
/// how many of their bytes are garbage, and a lease.
pub(crate) const PACKING: &str = r#"
-- When the part was created. It stays the same when the packer moves the part
-- to another blob, so it's the age of the data, not of the blob holding it.
-- Existing parts get their blob's creation time: until now, every blob was
-- written for exactly one part.
ALTER TABLE parts ADD COLUMN created_at TIMESTAMPTZ;
UPDATE parts p SET created_at = b.created_at FROM blobs b WHERE b.blob_id = p.blob_id;
ALTER TABLE parts ALTER COLUMN created_at SET NOT NULL;

-- `dead_size`: bytes of the blob that no part references anymore, as of the
-- packer's last fold of `blob_garbage`. Only packed blobs ever have any: a blob
-- written for one part is dropped together with it.
-- `pack_lease_until`: set while a packer is moving the blob's parts elsewhere,
-- so other packers leave it alone. Expires on its own if that packer dies.
ALTER TABLE blobs
    ADD COLUMN dead_size BIGINT NOT NULL DEFAULT 0 CHECK (dead_size >= 0),
    ADD COLUMN pack_lease_until TIMESTAMPTZ;

-- Candidates for consolidation (up to `packer::SMALL_SIZE`, which must match),
-- oldest first, and for compaction.
CREATE INDEX blobs_small ON blobs (created_at)
    WHERE state = 'committed' AND size <= 67108864;
CREATE INDEX blobs_sparse ON blobs (blob_id) WHERE dead_size > 0;

-- A log of bytes that became garbage: the sizes of deleted parts, per blob.
-- The packer folds it into `blobs.dead_size`. Deleting parts only appends here,
-- instead of updating the blob row directly, so that concurrent deletes of
-- parts in the same packed blob don't conflict with each other. A trigger,
-- since parts are also deleted by cascades (an object or upload going away).
CREATE TABLE blob_garbage (
    blob_id     UUID NOT NULL,
    size        BIGINT NOT NULL
);
CREATE FUNCTION log_blob_garbage() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO blob_garbage (blob_id, size)
        SELECT blob_id, sum(size) FROM gone GROUP BY blob_id HAVING sum(size) > 0;
    RETURN NULL;
END
$$;
CREATE TRIGGER parts_garbage AFTER DELETE ON parts
    REFERENCING OLD TABLE AS gone
    FOR EACH STATEMENT EXECUTE FUNCTION log_blob_garbage();
"#;

/// Migration 6: automatic garbage collection (see `gc`).
const GC: &str = r#"
-- Finding the pending blobs that have been pending too long, every minute.
CREATE INDEX blobs_pending ON blobs (created_at) WHERE state = 'pending';

-- When some node last checked the whole catalog for unreferenced blobs. A node
-- claims the next check by moving this forward, so it runs once a day, on one
-- node. A single row.
CREATE TABLE gc_runs (
    id                  BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
    unreferenced_check  TIMESTAMPTZ NOT NULL DEFAULT '-infinity'
);
INSERT INTO gc_runs DEFAULT VALUES;
"#;
