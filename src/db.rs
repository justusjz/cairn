use std::str::FromStr;
use std::time::Duration;

use deadpool_postgres::{GenericClient, Hook, HookError, Manager, ManagerConfig, Pool};
use tokio_postgres::{Error, NoTls, Row, types::ToSql};

const RETRY_INTERVAL: Duration = Duration::from_secs(1);
const MAX_ATTEMPTS: u32 = 60;

pub async fn connect(url: &str) -> anyhow::Result<Pool> {
    let conf = tokio_postgres::Config::from_str(url)?;
    let mgr = Manager::from_config(
        conf,
        NoTls,
        ManagerConfig {
            // Not `Clean`: its DISCARD ALL would drop the session's functions.
            recycling_method: deadpool_postgres::RecyclingMethod::Fast,
        },
    );
    let pool = Pool::builder(mgr)
        .max_size(16)
        .post_create(Hook::async_fn(|client, _| {
            Box::pin(async move {
                install_functions(client).await.map_err(HookError::Backend)
            })
        }))
        .build()?;
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

/// The version of the lock protocol (see `catalog.sql`) that this Cairn's
/// sessions follow, which `PROTOCOL_GATE` requires of every session that
/// writes to the catalog. Changing the protocol in a way that's unsafe to run
/// alongside the old one means bumping this, in a new migration that requires
/// the new version.
pub(crate) const PROTOCOL: &str = "4";

/// The catalog's transactions, as functions (see `catalog.sql`).
const CATALOG_FUNCTIONS: &str = include_str!("catalog.sql");

/// Creates the catalog's functions in the connection's own `pg_temp` schema.
/// Every connection does this once, when it's opened, so the functions are
/// always this binary's version of them, whatever other nodes run. They live
/// as long as the session, which is why the pool must never reset sessions.
///
/// It also pins the session's default isolation level to READ COMMITTED,
/// which the functions' lock protocol is built on (see `catalog.sql`), so that
/// a server configured otherwise can't change it for the statements that run
/// on their own, outside an explicit transaction. And it declares the lock
/// protocol the session follows, without which the catalog refuses its writes
/// (see `PROTOCOL_GATE`).
async fn install_functions(client: &tokio_postgres::Client) -> Result<(), tokio_postgres::Error> {
    client
        .batch_execute(&format!(
            "SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL READ COMMITTED;
             SET cairn.protocol = '{PROTOCOL}';
             SET cairn.users = '1'"
        ))
        .await?;
    client.batch_execute(CATALOG_FUNCTIONS).await
}

/// Running statements as prepared statements, prepared once per connection and
/// cached by their text. A statement run as plain text is prepared anew every
/// time, which costs a round trip to Postgres of its own; a cached one runs in
/// one. Every statement Cairn runs repeatedly goes through these.
pub(crate) trait Cached: GenericClient {
    async fn query_cached(&self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Vec<Row>, Error> {
        let statement = self.prepare_cached(sql).await?;
        self.query(&statement, params).await
    }

    async fn query_one_cached(&self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Row, Error> {
        let statement = self.prepare_cached(sql).await?;
        self.query_one(&statement, params).await
    }

    async fn query_opt_cached(
        &self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<Row>, Error> {
        let statement = self.prepare_cached(sql).await?;
        self.query_opt(&statement, params).await
    }

    async fn execute_cached(&self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<u64, Error> {
        let statement = self.prepare_cached(sql).await?;
        self.execute(&statement, params).await
    }
}

impl<C: GenericClient> Cached for C {}

/// How often a transaction is attempted while it keeps failing with conflicts.
/// With the pauses of [`backoff`], that's up to about a second and a half of
/// retrying.
pub const MAX_TX_ATTEMPTS: usize = 20;

/// How many deadlocks `is_conflict` has seen. There should be none.
pub static DEADLOCKS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Whether `e` is a conflict with a concurrent transaction, which the
/// transaction may not hit again if it's retried:
///
/// - A deadlock, which Postgres resolves by aborting one of the transactions.
///   The lock protocol (see `catalog.sql`) rules them out, except against a
///   migration's DDL, so one is logged as a bug (and counted, in
///   `DEADLOCKS`), but still retried.
/// - A serialization failure: a transaction found a part moved by the packer
///   between reading it and locking its blob (rule C in `catalog.sql`).
/// - A unique violation, which the lock protocol rules out too, since every
///   insert of a unique key happens under the lock that guards it. It's
///   retried all the same, as a backstop.
pub fn is_conflict(e: &tokio_postgres::Error) -> bool {
    use tokio_postgres::error::SqlState;
    if e.code() == Some(&SqlState::T_R_DEADLOCK_DETECTED) {
        DEADLOCKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        eprintln!("BUG: deadlock, which the lock protocol should rule out (unless a migration ran): {e}");
    }
    matches!(
        e.code(),
        Some(
            &SqlState::T_R_DEADLOCK_DETECTED
                | &SqlState::T_R_SERIALIZATION_FAILURE
                | &SqlState::UNIQUE_VIOLATION
        )
    )
}

/// Waits before attempt `attempt` (counting from 0) of a transaction that hit
/// a conflict. The first attempt goes ahead right away. After
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

/// The advisory lock that keeps garbage folds from running concurrently (see
/// `cairn_fold_garbage`, which repeats it as a literal).
#[cfg(test)]
const FOLD_LOCK: i64 = MIGRATION_LOCK + 1; // "cairn\1"

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
    UNREFERENCED_BY_LOG,
    PROTOCOL_GATE,
    BYTEWISE_KEYS,
    COMPACTABLE,
    UPLOADS_BY_KEY,
    COMPLETED_FROM,
    METADATA,
    ENCRYPTED_PARTS,
    SSE_KMS,
    ROLE_IDS,
    BUCKET_ENCRYPTION,
    SSE_S3,
    CHECKSUMS,
    LIFECYCLE,
    SCRUBBING,
    LOST_RANGES,
    LEGACY_BLOBS,
    SHARDS,
    NODE_STATES,
    BUCKET_CORS,
    TAGGING,
    LAYOUTS,
    USERS,
    CONSOLE,
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

/// Migration 7: unreferenced blobs are found through the garbage log alone. The
/// packer drops the blobs it logs once no part references them (see
/// `packer::fold_garbage`), so the daily check for them, and its table, go.
const UNREFERENCED_BY_LOG: &str = r#"
DROP TABLE gc_runs;

-- Log every blob a part is deleted from, an empty part's too: its blob may be
-- left unreferenced just the same.
CREATE OR REPLACE FUNCTION log_blob_garbage() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO blob_garbage (blob_id, size)
        SELECT blob_id, sum(size) FROM gone GROUP BY blob_id;
    RETURN NULL;
END
$$;

-- Blobs that became unreferenced before the garbage log existed (migration 5)
-- were never logged. Logging them now hands them to the packer too.
INSERT INTO blob_garbage (blob_id, size)
    SELECT b.blob_id, b.size FROM blobs b
    WHERE b.state = 'committed'
      AND NOT EXISTS (SELECT 1 FROM parts p WHERE p.blob_id = b.blob_id);
"#;

/// Migration 8: only sessions that follow lock protocol 2 (see `catalog.sql`)
/// may write to the catalog. Cairn 0.4.0 ran every catalog transaction at
/// SERIALIZABLE, and takes none of the protocol's locks; SSI doesn't see the
/// protocol's READ COMMITTED transactions, so the two must never write side
/// by side: a 0.4.0 node enabling versioning, say, could make a new node's
/// PUT delete a null version for good. 0.4.0 refuses a schema newer than it
/// knows, but only when it starts, so nodes already running would carry on.
///
/// Instead, every statement that writes to a catalog table now checks that
/// its session declared the protocol (`install_functions` does), and fails
/// otherwise. Creating the triggers waits for the transactions that have
/// written to the tables to finish, so from the moment this commits, no old
/// session writes anything: each old transaction either ended before, or
/// fails. Their reads keep working.
const PROTOCOL_GATE: &str = r#"
CREATE FUNCTION cairn_require_protocol() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('cairn.protocol', true) IS DISTINCT FROM '2' THEN
        RAISE EXCEPTION 'this Cairn is too old for its database, which another node upgraded; upgrade it too'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    RETURN NULL;
END
$$;
CREATE TRIGGER nodes_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON nodes
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
CREATE TRIGGER buckets_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON buckets
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
CREATE TRIGGER objects_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON objects
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
CREATE TRIGGER multipart_uploads_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON multipart_uploads
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
CREATE TRIGGER parts_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON parts
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
CREATE TRIGGER blobs_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON blobs
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
CREATE TRIGGER blob_locations_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON blob_locations
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
CREATE TRIGGER blob_garbage_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON blob_garbage
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
CREATE TRIGGER roles_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON roles
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
CREATE TRIGGER role_grants_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON role_grants
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
"#;

/// Migration 9: keys compare byte by byte, as S3 orders them. They used the
/// database's default collation, which sorts by locale rules (`en_US.utf8`
/// puts `a` before `B`, and ignores punctuation at first), so listings came
/// out in a different order than S3's, and a listing's markers compared that
/// way too. In a UTF-8 database, the `C` collation's byte order is S3's
/// order (UTF-8 bytes sort as their code points do), so the migration
/// refuses any other encoding.
///
/// Only the collation changes, so the table isn't rewritten, but the indexes
/// on `key` are rebuilt, under a lock that holds up every request on objects
/// while they are. Equality is the same under both collations (Postgres's are
/// deterministic), so no unique index can find duplicates.
const BYTEWISE_KEYS: &str = r#"
DO $$
BEGIN
    IF (SELECT pg_encoding_to_char(encoding) FROM pg_database
        WHERE datname = current_database()) <> 'UTF8' THEN
        RAISE EXCEPTION 'Cairn needs a database with UTF8 encoding, to order keys as S3 does';
    END IF;
END
$$;
ALTER TABLE objects ALTER COLUMN key TYPE text COLLATE "C";
ALTER TABLE multipart_uploads ALTER COLUMN key TYPE text COLLATE "C";
"#;

/// Migration 10: the packer's compaction candidates, least live data first,
/// so that each node's claim (once a minute) reads the few it takes off an
/// index, rather than sorting every blob with any garbage. The threshold
/// (`packer::COMPACT_THRESHOLD`, which must match) is part of the index, so
/// that blobs with a little garbage aren't in it. `blobs_sparse` served only
/// the claim's old query.
pub(crate) const COMPACTABLE: &str = r#"
CREATE INDEX blobs_compactable ON blobs ((size - dead_size))
    WHERE state = 'committed' AND dead_size > 0 AND dead_size >= size * 0.25;
DROP INDEX blobs_sparse;
"#;

/// Migration 11: the uploads of a bucket in the order ListMultipartUploads
/// walks them, by key, and each key's by ID (UUIDv7s, so in the order they
/// were created), and DeleteBucket finds them by.
const UPLOADS_BY_KEY: &str = r#"
CREATE INDEX multipart_uploads_by_key ON multipart_uploads (bucket, key, upload_id);
"#;

/// Migration 12: the upload a version was completed from, so that a retried
/// CompleteMultipartUpload, whose upload is gone, can tell that it succeeded.
/// Nullable without a default, so the table isn't rewritten.
const COMPLETED_FROM: &str = r#"
ALTER TABLE objects ADD COLUMN upload_id uuid;
"#;

/// Migration 13: the headers S3 stores with an object besides its Content-Type
/// (see `s3::metadata`), and those an upload is to give its object. A
/// constant default, so neither table is rewritten.
const METADATA: &str = r#"
ALTER TABLE objects ADD COLUMN metadata text NOT NULL DEFAULT '';
ALTER TABLE multipart_uploads ADD COLUMN metadata text NOT NULL DEFAULT '';
"#;

/// Migration 14: encrypted parts (see `encryption`). An encrypted part's
/// `size` stays what it takes in its blob, which everything below the S3 layer
/// works with; `plain_size` is its plaintext's, which objects are made of, and
/// `enc_salt` its salt. A plain part has neither. An SSE-C object, and an
/// upload that's to make one, keep a check of the client's key: a random salt
/// and the HMAC-SHA256 of the key under it, never the key.
///
/// The checks are NOT VALID, so adding them doesn't scan the tables: they hold
/// for every row written from now on, and every row before has NULLs.
const ENCRYPTED_PARTS: &str = r#"
ALTER TABLE parts ADD COLUMN plain_size bigint;
ALTER TABLE parts ADD COLUMN enc_salt bytea;
ALTER TABLE parts ADD CONSTRAINT parts_encrypted CHECK (
    (plain_size IS NULL) = (enc_salt IS NULL)
    AND (enc_salt IS NULL OR (octet_length(enc_salt) = 16 AND plain_size >= 0))
) NOT VALID;
ALTER TABLE objects ADD COLUMN sse_c_key bytea;
ALTER TABLE objects ADD CONSTRAINT objects_sse_c_key
    CHECK (octet_length(sse_c_key) = 48) NOT VALID;
ALTER TABLE multipart_uploads ADD COLUMN sse_c_key bytea;
ALTER TABLE multipart_uploads ADD CONSTRAINT multipart_uploads_sse_c_key
    CHECK (octet_length(sse_c_key) = 48) NOT VALID;
"#;

/// Migration 15: SSE-KMS (see `s3::sse`). An SSE-KMS object, and an upload
/// that's to make one, keep the name of their KMS key, the data key the KMS
/// gave for them (as its ciphertext, which only the KMS can open), the
/// object's own key sealed under that data key (nonce, ciphertext and tag),
/// and the encryption context their client gave, if any (as canonical JSON).
/// The checks are NOT VALID, as migration 14's: every row before has NULLs.
///
/// It also moves the catalog to lock protocol 3. The locks are the same, but
/// a Cairn from before encryption doesn't know an object's key records: a
/// copy it made of an encrypted object would share the object's encrypted
/// parts, but not what opens them, and be unreadable. So such a Cairn may no
/// longer write (see migration 8). Its reads keep working; it can't decrypt
/// an encrypted object, and serves its ciphertext.
const SSE_KMS: &str = r#"
ALTER TABLE objects ADD COLUMN sse_kms_key_id text;
ALTER TABLE objects ADD COLUMN sse_kms_data_key text;
ALTER TABLE objects ADD COLUMN sse_kms_sealed bytea;
ALTER TABLE objects ADD COLUMN sse_kms_context text;
ALTER TABLE objects ADD CONSTRAINT objects_sse_kms CHECK (
    (sse_kms_key_id IS NULL) = (sse_kms_data_key IS NULL)
    AND (sse_kms_key_id IS NULL) = (sse_kms_sealed IS NULL)
    AND (sse_kms_context IS NULL OR sse_kms_key_id IS NOT NULL)
    AND (sse_kms_sealed IS NULL OR octet_length(sse_kms_sealed) = 72)
    AND (sse_kms_key_id IS NULL OR sse_c_key IS NULL)
) NOT VALID;
ALTER TABLE multipart_uploads ADD COLUMN sse_kms_key_id text;
ALTER TABLE multipart_uploads ADD COLUMN sse_kms_data_key text;
ALTER TABLE multipart_uploads ADD COLUMN sse_kms_sealed bytea;
ALTER TABLE multipart_uploads ADD COLUMN sse_kms_context text;
ALTER TABLE multipart_uploads ADD CONSTRAINT multipart_uploads_sse_kms CHECK (
    (sse_kms_key_id IS NULL) = (sse_kms_data_key IS NULL)
    AND (sse_kms_key_id IS NULL) = (sse_kms_sealed IS NULL)
    AND (sse_kms_context IS NULL OR sse_kms_key_id IS NOT NULL)
    AND (sse_kms_sealed IS NULL OR octet_length(sse_kms_sealed) = 72)
    AND (sse_kms_key_id IS NULL OR sse_c_key IS NULL)
) NOT VALID;
CREATE OR REPLACE FUNCTION cairn_require_protocol() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('cairn.protocol', true) IS DISTINCT FROM '3' THEN
        RAISE EXCEPTION 'this Cairn is too old for its database, which another node upgraded; upgrade it too'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    RETURN NULL;
END
$$;
"#;

/// Migration 16: every role gets an ID that's never reused, which the KMS
/// knows it by (see `kms`): a role deleted and made again under its name
/// mustn't inherit what the KMS allowed the old one. And the ID of its
/// identity (entity) in the KMS, once Cairn has logged in as it.
///
/// The IDs are random, so the table (small) is rewritten. No new lock
/// protocol: the one before (3) was never released, and nothing here changes
/// what a write must do.
const ROLE_IDS: &str = r#"
ALTER TABLE roles ADD COLUMN id uuid NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE roles ADD CONSTRAINT roles_id UNIQUE (id);
ALTER TABLE roles ADD COLUMN kms_entity_id text;
"#;

/// Migration 17: a bucket's default encryption (see
/// `s3::buckets::encryption`), as PutBucketEncryption sets it: SSE-KMS under
/// a key (its algorithm, the only one, and the key ID), and whether its
/// configuration asked for a bucket key (told back, but nothing changes). A
/// constant default, so the table isn't rewritten, and the checks are NOT
/// VALID, as migration 14's: every row before has NULLs.
const BUCKET_ENCRYPTION: &str = r#"
ALTER TABLE buckets ADD COLUMN sse_algorithm text;
ALTER TABLE buckets ADD COLUMN sse_kms_key_id text;
ALTER TABLE buckets ADD COLUMN sse_bucket_key boolean NOT NULL DEFAULT false;
ALTER TABLE buckets ADD CONSTRAINT buckets_sse CHECK (
    (sse_algorithm IS NULL OR sse_algorithm = 'aws:kms')
    AND (sse_algorithm IS NULL) = (sse_kms_key_id IS NULL)
) NOT VALID;
"#;

/// Migration 18: SSE-S3 (see `s3::sse`). An SSE-S3 object (or upload) keeps
/// its keys as an SSE-KMS one does, under Cairn's own key, and is marked so.
/// And a bucket's default may be SSE-S3 (`AES256`, without a key).
const SSE_S3: &str = r#"
ALTER TABLE objects ADD COLUMN sse_s3 boolean NOT NULL DEFAULT false;
ALTER TABLE objects ADD CONSTRAINT objects_sse_s3
    CHECK (NOT sse_s3 OR (sse_kms_key_id IS NOT NULL AND sse_kms_context IS NULL)) NOT VALID;
ALTER TABLE multipart_uploads ADD COLUMN sse_s3 boolean NOT NULL DEFAULT false;
ALTER TABLE multipart_uploads ADD CONSTRAINT multipart_uploads_sse_s3
    CHECK (NOT sse_s3 OR (sse_kms_key_id IS NOT NULL AND sse_kms_context IS NULL)) NOT VALID;
ALTER TABLE buckets DROP CONSTRAINT buckets_sse;
ALTER TABLE buckets ADD CONSTRAINT buckets_sse CHECK (
    (sse_algorithm IS NULL AND sse_kms_key_id IS NULL)
    OR (sse_algorithm = 'aws:kms' AND sse_kms_key_id IS NOT NULL)
    OR (sse_algorithm = 'AES256' AND sse_kms_key_id IS NULL)
) NOT VALID;
"#;

/// Migration 19: S3's checksums of objects and parts (see `s3::checksums`).
/// An object's: its algorithm, type and value; an upload's: the algorithm
/// and type its client asked for; a part's: its value, in its upload's
/// algorithm. Values are as reported (base64), or sealed (hex) if encrypted.
/// NULL for those from before. The checks are NOT VALID, as migration 14's.
const CHECKSUMS: &str = r#"
ALTER TABLE objects ADD COLUMN checksum_algorithm text;
ALTER TABLE objects ADD COLUMN checksum_type text;
ALTER TABLE objects ADD COLUMN checksum text;
ALTER TABLE objects ADD CONSTRAINT objects_checksum CHECK (
    (checksum_algorithm IS NULL) = (checksum IS NULL)
    AND (checksum_algorithm IS NULL) = (checksum_type IS NULL)
    AND (checksum_algorithm IS NULL
         OR checksum_algorithm IN ('CRC32', 'CRC32C', 'CRC64NVME', 'SHA1', 'SHA256'))
    AND (checksum_type IS NULL OR checksum_type IN ('FULL_OBJECT', 'COMPOSITE'))
) NOT VALID;
ALTER TABLE multipart_uploads ADD COLUMN checksum_algorithm text;
ALTER TABLE multipart_uploads ADD COLUMN checksum_type text;
ALTER TABLE multipart_uploads ADD CONSTRAINT multipart_uploads_checksum CHECK (
    (checksum_algorithm IS NULL) = (checksum_type IS NULL)
    AND (checksum_algorithm IS NULL
         OR checksum_algorithm IN ('CRC32', 'CRC32C', 'CRC64NVME', 'SHA1', 'SHA256'))
    AND (checksum_type IS NULL OR checksum_type IN ('FULL_OBJECT', 'COMPOSITE'))
) NOT VALID;
ALTER TABLE parts ADD COLUMN checksum text;
"#;

/// Migration 20: lifecycle rules (see `lifecycle`), and the cluster's
/// settings (see `settings`), of which the rate lifecycle sweeps go at is the
/// first.
///
/// A bucket's rules stay with it, as JSON (NULL for none), with a number
/// that every change of them increases, which sweeps check theirs against.
/// Its sweep of them has a row of its own in `lifecycle_sweeps`, so that a
/// sweep's progress doesn't update the row of the bucket, which every write
/// in it locks: when it gets its next turn (when its next sweep starts, or,
/// during one, when it last had a turn), when the sweep started (NULL between
/// sweeps), the key it has got to, how many versions it has read, and what it
/// has done; and the last whole sweep, as JSON.
///
/// `lifecycle_runs` is the single row that sweeps take turns through: one
/// step at a time in the whole cluster, under its lease, when the last one
/// began (which the next one's share of the rate is counted from), and the
/// rate steps have actually reached, when they had more to do than their
/// share (an average, over about an hour).
const LIFECYCLE: &str = r#"
CREATE TABLE settings (
    name   text PRIMARY KEY,
    value  text NOT NULL
);
CREATE TRIGGER settings_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON settings
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();

CREATE TABLE lifecycle_runs (
    id            boolean PRIMARY KEY DEFAULT true CHECK (id),
    lease_until   timestamptz,
    last_step     timestamptz,
    reached_rate  double precision,
    reached_at    timestamptz
);
INSERT INTO lifecycle_runs DEFAULT VALUES;
CREATE TRIGGER lifecycle_runs_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON lifecycle_runs
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();

ALTER TABLE buckets
    ADD COLUMN lifecycle text,
    ADD COLUMN lifecycle_generation bigint NOT NULL DEFAULT 0;

CREATE TABLE lifecycle_sweeps (
    bucket      text PRIMARY KEY REFERENCES buckets(name) ON DELETE CASCADE,
    generation  bigint NOT NULL,
    due         timestamptz NOT NULL,
    started     timestamptz,
    cursor      text,
    seen        bigint NOT NULL DEFAULT 0,
    expired     bigint NOT NULL DEFAULT 0,
    removed     bigint NOT NULL DEFAULT 0,
    aborted     bigint NOT NULL DEFAULT 0,
    last        text
);
CREATE INDEX lifecycle_sweeps_due ON lifecycle_sweeps (due);
CREATE TRIGGER lifecycle_sweeps_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON lifecycle_sweeps
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
"#;

/// Migration 21: scrubbing (see `scrub`). Each copy of a blob records when it
/// was last known intact: when its replica wrote it, then when the scrubber
/// last checked it. NULL for copies from before, which come first;
/// `-infinity` for one a read found damaged or missing, which comes next. The
/// index is the order the scrubber takes a node's copies in.
///
/// `scrub_findings` records the damaged and missing copies the scrubber
/// found: at most one open finding per copy, resolved when the copy is found
/// intact again (`repaired`), or its blob or node is gone (`gone`). A copy
/// whose bytes are intact nowhere (`lost`) stays open. No FK to
/// the blob, since a finding outlives it. `bad_blocks` lists the blocks that
/// failed, NULL if the whole file is at fault (missing, the wrong length or
/// blob ID).
const SCRUBBING: &str = r#"
ALTER TABLE blob_locations ADD COLUMN checked_at timestamptz;
CREATE INDEX blob_locations_scrub ON blob_locations (node, checked_at NULLS FIRST);

CREATE TABLE scrub_findings (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    blob_id     uuid NOT NULL,
    node        int NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    found_at    timestamptz NOT NULL,
    problem     text NOT NULL CHECK (problem IN ('missing', 'damaged', 'catalog')),
    bad_blocks  bigint[],
    detail      text NOT NULL,
    outcome     text CHECK (outcome IN ('repaired', 'lost', 'gone')),
    resolved_at timestamptz
);
CREATE UNIQUE INDEX scrub_findings_open ON scrub_findings (blob_id, node)
    WHERE resolved_at IS NULL;
CREATE INDEX scrub_findings_resolved ON scrub_findings (resolved_at)
    WHERE resolved_at IS NOT NULL;
CREATE TRIGGER scrub_findings_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON scrub_findings
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
"#;

/// Migration 22: lost data (see `scrub`). The byte ranges [start, stop) of a
/// blob that no copy of it holds intact, as far as the scrubber could find
/// out. They go once some copy turns out to hold them after all, and with
/// their blob.
const LOST_RANGES: &str = r#"
CREATE TABLE lost_ranges (
    blob_id  uuid NOT NULL REFERENCES blobs(blob_id) ON DELETE CASCADE,
    start    bigint NOT NULL CHECK (start >= 0),
    stop     bigint NOT NULL CHECK (stop > start),
    found_at timestamptz NOT NULL,
    PRIMARY KEY (blob_id, start)
);
CREATE TRIGGER lost_ranges_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON lost_ranges
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
"#;

/// Migration 23: the blobs from before checksums, which the packer upgrades to
/// checksummed ones, oldest first (see `packer`). Every node looks for one in
/// every pass, so it's read off an index, which empties as they're upgraded.
const LEGACY_BLOBS: &str = r#"
CREATE INDEX blobs_legacy ON blobs (created_at)
    WHERE state = 'committed' AND block_size IS NULL;
"#;

/// Migration 24: shards (see `shards`). Every blob is k data shards and m
/// parity shards, each on a node of its own; replication is k = 1. A
/// location records which shard its node holds, and the catalog keeps the
/// CRC64/NVME of each shard's file (they differ only once k > 1) instead of
/// one per blob. Existing blobs are replicated: 1 + (copies - 1), their
/// copies numbered by node, their file CRC repeated.
///
/// Lock protocol 4: the protocol itself doesn't change, but a node of
/// protocol 3 would read a coded blob's shards as replicas. The gate goes
/// first, since this session already follows protocol 4.
pub(crate) const SHARDS: &str = r#"
CREATE OR REPLACE FUNCTION cairn_require_protocol() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('cairn.protocol', true) IS DISTINCT FROM '4' THEN
        RAISE EXCEPTION 'this Cairn is too old for its database, which another node upgraded; upgrade it too'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    RETURN NULL;
END
$$;

ALTER TABLE blobs
    ADD COLUMN data_shards smallint NOT NULL DEFAULT 1 CHECK (data_shards >= 1),
    ADD COLUMN parity_shards smallint NOT NULL DEFAULT 0 CHECK (parity_shards >= 0),
    ADD COLUMN stripe_unit int NOT NULL DEFAULT 1048576 CHECK (stripe_unit > 0),
    ADD COLUMN shard_crcs bigint[];

ALTER TABLE blob_locations ADD COLUMN shard smallint;
UPDATE blob_locations bl SET shard = n.shard
FROM (SELECT blob_id, node, row_number() OVER (PARTITION BY blob_id ORDER BY node) - 1 AS shard
      FROM blob_locations) AS n
WHERE n.blob_id = bl.blob_id AND n.node = bl.node;
ALTER TABLE blob_locations
    ALTER COLUMN shard SET NOT NULL,
    ADD CHECK (shard >= 0);
-- At most one location per shard: a commit counts the shards the writer sent
-- out, and this makes sure no shard is counted for two nodes. (A node holds
-- at most one shard of a blob: the primary key.)
CREATE UNIQUE INDEX blob_locations_shard ON blob_locations (blob_id, shard);

UPDATE blobs b SET parity_shards = c.copies - 1
FROM (SELECT blob_id, count(*)::smallint AS copies FROM blob_locations GROUP BY blob_id) AS c
WHERE c.blob_id = b.blob_id AND b.state = 'committed';
UPDATE blobs SET shard_crcs = array_fill(crc64nvme, ARRAY[data_shards + parity_shards])
WHERE crc64nvme IS NOT NULL;
ALTER TABLE blobs DROP COLUMN crc64nvme;
ALTER TABLE blobs
    ADD CONSTRAINT blobs_checksummed CHECK ((block_size IS NULL) = (shard_crcs IS NULL)),
    ADD CONSTRAINT blobs_shard_crcs
        CHECK (cardinality(shard_crcs) = data_shards + parity_shards);

-- Replicated blobs large enough to be coded, which the packer converts once
-- they're old enough (see `packer`), oldest first. Every node looks for one in
-- every pass while coding is on. The size bound is `packer::SMALL_SIZE`.
CREATE INDEX blobs_replicated ON blobs (created_at)
    WHERE state = 'committed' AND data_shards = 1 AND block_size IS NOT NULL
      AND size > 67108864;
"#;

/// Migration 25: nodes can be removed (see `mover`). A node being removed
/// gets no new shards, and its shards move to other nodes; once it holds none,
/// it's removed. No new lock protocol: 4, which migration 24 introduced, is
/// released together with this.
const NODE_STATES: &str = r#"
ALTER TABLE nodes ADD COLUMN state text NOT NULL DEFAULT 'active'
    CHECK (state IN ('active', 'removing', 'removed'));
-- When the state last changed: a removal only finishes once no upload that
-- may have chosen the node before is still pending.
ALTER TABLE nodes ADD COLUMN state_since timestamptz NOT NULL DEFAULT NOW();
"#;

/// Migration 26: a bucket's CORS configuration (see `s3::buckets::cors`), as
/// PutBucketCors sets it, as JSON; NULL if it has none. No new lock protocol:
/// it's set by a plain UPDATE of the bucket's row (T21), and a Cairn that
/// doesn't know it merely answers without CORS headers.
const BUCKET_CORS: &str = r#"
ALTER TABLE buckets ADD COLUMN cors text;
"#;

/// Tags (see `s3::tags`): an object version's and an upload's, in their
/// stored form, empty for none; a bucket's, NULL for none.
const TAGGING: &str = r#"
ALTER TABLE objects ADD COLUMN tags text NOT NULL DEFAULT '';
ALTER TABLE multipart_uploads ADD COLUMN tags text NOT NULL DEFAULT '';
ALTER TABLE buckets ADD COLUMN tags text;
"#;

/// Migration 28: blobs are brought to the cluster's layout whatever their
/// age (see `packer::Layouts`): the packer converts large blobs in any other
/// layout, off `blobs_large`, rather than replicated ones a week old, and the
/// mover adds or drops copies of replicated blobs, off `blobs_copies` (see
/// `mover`). Both claims read their index in order, from the layout on, so
/// that they read only as far as they take. The size bound is
/// `packer::SMALL_SIZE`. No new lock protocol: copies are added and dropped
/// under X(x) exclusive, as shards are moved, and a Cairn that doesn't know
/// them reads a blob's locations as they are.
pub(crate) const LAYOUTS: &str = r#"
DROP INDEX blobs_replicated;
CREATE INDEX blobs_large ON blobs (data_shards, parity_shards)
    WHERE state = 'committed' AND block_size IS NOT NULL AND size > 67108864;
CREATE INDEX blobs_copies ON blobs (parity_shards)
    WHERE state = 'committed' AND data_shards = 1 AND block_size IS NOT NULL;
"#;

/// Migration 29: users (still the `roles` table, which Cairns before this
/// one read) get access keys of their own, several, and inline identity
/// policies; buckets get bucket policies; and the cluster is an account, by
/// a 12-digit ID, as IAM's principals name them (see `policy`, and
/// `plans/policies.md`). Each role's key becomes its first access key, by
/// the role's name. No new lock protocol: keys and policies are plain rows of
/// their user, and a bucket's policy a plain UPDATE of its row, as its
/// encryption is (T16); no invariant of the catalog involves them.
///
/// Older Cairns keep reading `roles.secret`, so that's kept as the secret of
/// the key named as the user (an unusable one, if that key is inactive or
/// gone), and they can't change users anymore: only sessions that declare
/// `cairn.users` (`install_functions`) may write `roles`, as a Cairn that
/// knows no access keys would make users without any, or change a secret
/// that no longer counts.
const USERS: &str = r#"
CREATE TABLE accounts (
    id         text PRIMARY KEY CHECK (id ~ '^[0-9]{12}$'),
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO accounts (id) VALUES (lpad(floor(random() * 1e12)::bigint::text, 12, '0'));

CREATE TABLE access_keys (
    access_key_id text PRIMARY KEY,
    role_id       uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    secret        text NOT NULL,
    active        boolean NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX access_keys_role ON access_keys (role_id);
INSERT INTO access_keys (access_key_id, role_id, secret, created_at)
    SELECT name, id, secret, created_at FROM roles;

CREATE TABLE role_policies (
    role_id  uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    name     text NOT NULL,
    document text NOT NULL,
    PRIMARY KEY (role_id, name)
);

ALTER TABLE buckets ADD COLUMN policy text;

CREATE TRIGGER accounts_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON accounts
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
CREATE TRIGGER access_keys_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON access_keys
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
CREATE TRIGGER role_policies_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON role_policies
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();

CREATE FUNCTION cairn_require_users() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('cairn.users', true) IS DISTINCT FROM '1' THEN
        RAISE EXCEPTION 'this Cairn is too old to change users, which have access keys now; upgrade it'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    RETURN NULL;
END
$$;
CREATE TRIGGER roles_users BEFORE INSERT OR DELETE OR TRUNCATE OR UPDATE OF name, secret ON roles
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_users();

-- What older Cairns authenticate with: the secret of the key named as the
-- user, while it's active.
CREATE FUNCTION cairn_legacy_secret() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    v_key access_keys;
BEGIN
    v_key := CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
    UPDATE roles r SET secret = coalesce(
        (SELECT k.secret FROM access_keys k WHERE k.access_key_id = r.name AND k.role_id = r.id AND k.active),
        'unusable:' || gen_random_uuid() || gen_random_uuid())
    WHERE r.id = v_key.role_id AND r.name = v_key.access_key_id;
    RETURN NULL;
END
$$;
CREATE TRIGGER access_keys_legacy AFTER INSERT OR UPDATE OR DELETE ON access_keys
    FOR EACH ROW EXECUTE FUNCTION cairn_legacy_secret();
"#;

/// Migration 30: the console's sign-ins (see `console`): users' passkeys,
/// the one-time links that enroll their first, the challenges of ceremonies
/// in progress, and sessions. All of them rows of their user (R(r)); tokens
/// are kept as their SHA-256 only.
const CONSOLE: &str = r#"
CREATE TABLE passkeys (
    credential_id   bytea PRIMARY KEY,
    role_id         uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    public_key      bytea NOT NULL,
    sign_count      bigint NOT NULL,
    name            text NOT NULL,
    backup_eligible boolean NOT NULL,
    backed_up       boolean NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_used_at    timestamptz
);
CREATE INDEX passkeys_role ON passkeys (role_id);

CREATE TABLE console_enrollments (
    token_hash bytea PRIMARY KEY,
    role_id    uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);
CREATE INDEX console_enrollments_role ON console_enrollments (role_id);

-- `purpose`: 'enroll', 'add' (a passkey, signed in) or 'login'; `role_id`
-- is whose, but for a login, which finds out.
CREATE TABLE console_challenges (
    id         uuid PRIMARY KEY,
    challenge  bytea NOT NULL,
    purpose    text NOT NULL CHECK (purpose IN ('enroll', 'add', 'login')),
    role_id    uuid REFERENCES roles (id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL
);
CREATE INDEX console_challenges_role ON console_challenges (role_id);

CREATE TABLE console_sessions (
    token_hash    bytea PRIMARY KEY,
    role_id       uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    credential_id bytea NOT NULL REFERENCES passkeys (credential_id) ON DELETE CASCADE,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL
);
CREATE INDEX console_sessions_role ON console_sessions (role_id);
CREATE INDEX console_sessions_credential ON console_sessions (credential_id);

CREATE TRIGGER passkeys_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON passkeys
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
CREATE TRIGGER console_enrollments_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON console_enrollments
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
CREATE TRIGGER console_challenges_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON console_challenges
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
CREATE TRIGGER console_sessions_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON console_sessions
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
"#;

#[cfg(test)]
mod tests {
    #[test]
    fn the_gate_requires_this_protocol() {
        // The last migration to define the gate's function sets the protocol.
        let gate = super::MIGRATIONS
            .iter()
            .rev()
            .find(|sql| sql.contains("FUNCTION cairn_require_protocol() RETURNS"))
            .unwrap();
        let check = format!("IS DISTINCT FROM '{}'", super::PROTOCOL);
        assert!(gate.contains(&check));
    }

    /// Every table in the schema is gated, or listed here as not needing it.
    #[test]
    fn every_table_is_gated() {
        let schema = super::MIGRATIONS.concat();
        let dropped = ["part_locations", "gc_runs"];
        // Written only under the migrations' own lock, by Cairns that check
        // the schema's version first.
        let ungated = ["schema_migrations"];
        for line in schema.lines() {
            let Some(rest) = line.strip_prefix("CREATE TABLE ") else { continue };
            let table = rest.trim_start_matches("IF NOT EXISTS ").split([' ', '(']).next().unwrap();
            if dropped.contains(&table) || ungated.contains(&table) {
                continue;
            }
            // Tables from after the gate get theirs in their own migration.
            let trigger = format!("CREATE TRIGGER {table}_protocol ");
            assert!(schema.contains(&trigger), "{table} isn't gated");
        }
    }

    #[test]
    fn the_size_limits_match_the_catalog() {
        let limit = crate::s3::util::MAX_OBJECT.to_string();
        assert!(super::CATALOG_FUNCTIONS.contains(&format!("v_total > {limit}")));
        let limit = crate::s3::util::MIN_PART.to_string();
        assert!(super::CATALOG_FUNCTIONS.contains(&format!("p.size) < {limit}")));
    }

    #[test]
    fn the_fold_lock_matches_the_catalog() {
        let call = format!("pg_try_advisory_xact_lock({})", super::FOLD_LOCK);
        assert!(super::CATALOG_FUNCTIONS.contains(&call));
    }
}
