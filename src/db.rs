use std::str::FromStr;
use std::time::Duration;

use deadpool_postgres::{GenericClient, Hook, HookError, Manager, ManagerConfig, Pool};
use tokio_postgres::{Error, NoTls, Row, types::ToSql};

const RETRY_INTERVAL: Duration = Duration::from_secs(1);
const MAX_ATTEMPTS: u32 = 60;

pub async fn connect(url: &str) -> anyhow::Result<Pool> {
    connect_through(url, MIGRATIONS.len()).await
}

/// As `connect`, with the schema migrated up to step `last` only (for tests
/// of a migration, which set up what it migrates first).
pub(crate) async fn connect_through(url: &str, last: usize) -> anyhow::Result<Pool> {
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
        match init(&pool, last).await {
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
pub(crate) const PROTOCOL: &str = "6";

/// What this Cairn's sessions declare as `cairn.users`, which the users'
/// gate (`cairn_require_users`, last raised by `USERS_RENAMED`) requires of
/// every session that changes users, their keys or policies.
pub(crate) const USERS_GATE: &str = "6";

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
             SET cairn.users = '{USERS_GATE}'"
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
    PRINCIPAL_IDS,
    PUBLIC_ACCESS_BLOCK,
    ACCOUNTS,
    LOGINS,
    OIDC,
    USER_NAMES,
    OBJECT_LOCK,
    SSE_C_SEALED,
    OPERATOR_MEMBERS,
    MANAGED_POLICIES,
    ACCOUNT_PUBLIC_ACCESS_BLOCK,
    BOUNDARIES,
    POLICY_TAGS,
    POLICY_VERSIONS,
    SINGLE_ACCOUNT,
    NO_ROOT,
    USERS_RENAMED,
    IAM_ROLES,
];

/// Applies every pending migration in a single transaction, so a failure leaves
/// the schema untouched. Refuses to run against a database migrated by a newer
/// Cairn, whose schema this binary doesn't understand.
pub(crate) async fn init(pool: &Pool, last: usize) -> anyhow::Result<()> {
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
    for (version, sql) in (1..).zip(MIGRATIONS).take(last).skip(current as usize) {
        // Each step runs as the lock protocol of its own time, which the
        // gate (`PROTOCOL_GATE`) requires: on a fresh database, a step that
        // writes a gated table runs before the gate is raised to this
        // Cairn's protocol. That's the protocol the step raises the gate to,
        // if it does (it does so first), else the gate's as the steps before
        // left it. For this transaction only.
        // Likewise the users' gate (`cairn.users`; see `USERS`).
        for (setting, function, ours) in
            [("cairn.protocol", "cairn_require_protocol", PROTOCOL), ("cairn.users", "cairn_require_users", USERS_GATE)]
        {
            match gate_of(sql, function) {
                Some(value) => {
                    tx.execute("SELECT set_config($1, $2, true)", &[&setting, &value]).await?;
                }
                None => {
                    tx.execute(
                        "SELECT set_config($1, coalesce(
                             (SELECT substring(p.prosrc FROM 'IS DISTINCT FROM ''([0-9]+)''')
                              FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                              WHERE p.proname = $2 AND n.nspname = 'public'),
                             $3), true)",
                        &[&setting, &function, &ours],
                    )
                    .await?;
                }
            }
        }
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

/// The value a migration step raises a gate to, if it defines the gate's
/// function (`cairn_require_protocol`, `cairn_require_users`).
fn gate_of(sql: &str, function: &str) -> Option<String> {
    let (_, rest) = sql.split_once(&format!("FUNCTION {function}() RETURNS"))?;
    let (_, rest) = rest.split_once("IS DISTINCT FROM '")?;
    Some(rest.split('\'').next()?.to_owned())
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

/// Migration 31: the users a bucket's policy names, by the IDs they had when
/// it was set (`buckets.policy_principals`: ARN → ID), as S3 keeps a user's
/// unique ID: a user deleted and made again with its name is another user,
/// which the policy doesn't name (see `policy::Policy::with_ids`). A trigger
/// keeps them with every policy written, an older Cairn's too, from the
/// users there are as it's written; the policies there are get theirs now.
/// A user that's gone is no one's: a user deleted before this migration is
/// named by no one's ID.
const PRINCIPAL_IDS: &str = r#"
ALTER TABLE buckets ADD COLUMN policy_principals jsonb;

CREATE FUNCTION cairn_policy_principals() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.policy_principals := CASE WHEN NEW.policy IS NOT NULL THEN (
        SELECT coalesce(jsonb_object_agg(p.arn, r.id::text), '{}'::jsonb)
        FROM (
            SELECT DISTINCT a #>> '{}' AS arn
            FROM jsonb_path_query(NEW.policy::jsonb, 'lax $.Statement[*].Principal.AWS[*]') a
            UNION
            SELECT a #>> '{}'
            FROM jsonb_path_query(NEW.policy::jsonb, 'lax $.Statement[*].NotPrincipal.AWS[*]') a
        ) p
        JOIN roles r ON r.name = substring(p.arn FROM '^arn:aws:iam::[0-9]{12}:user/(.+)$')
    ) END;
    RETURN NEW;
END
$$;
CREATE TRIGGER buckets_policy_principals BEFORE INSERT OR UPDATE OF policy ON buckets
    FOR EACH ROW EXECUTE FUNCTION cairn_policy_principals();

UPDATE buckets SET policy = policy WHERE policy IS NOT NULL;
"#;

/// Migration 32: a bucket's public access block (see
/// `s3::buckets::public_access`), its four flags as bits: 1
/// BlockPublicAcls, 2 IgnorePublicAcls, 4 BlockPublicPolicy, 8
/// RestrictPublicBuckets. NULL: it has none. The buckets there are have none;
/// new ones get all four, as S3's do, older Cairns' too (the column's
/// default).
const PUBLIC_ACCESS_BLOCK: &str = r#"
ALTER TABLE buckets ADD COLUMN public_access_block smallint
    CHECK (public_access_block BETWEEN 0 AND 15);
ALTER TABLE buckets ALTER COLUMN public_access_block SET DEFAULT 15;
"#;

/// Migration 33: accounts as AWS's (see `plans/policies.md`, "Accounts,
/// root users and logins"). Each has a name; the one there is becomes the
/// first tenant account, `default`, and an operator account is added, whose
/// users are the superadmins, and which owns no buckets. Every user and
/// every bucket belongs to an account: the ones there are to `default`, as
/// are buckets that older Cairns create (the column's default).
///
/// Grants move into buckets' policies (see `grants`), which a Cairn moves at
/// its start: older Cairns may no longer write `role_grants`, nor change
/// users, unless their sessions declare `cairn.users = '2'`. (Those of 0.5.1
/// read bucket policies, so they see the grants there.)
const ACCOUNTS: &str = r#"
ALTER TABLE accounts ADD COLUMN name text;
ALTER TABLE accounts ADD COLUMN operator boolean NOT NULL DEFAULT false;
UPDATE accounts SET name = 'default';
ALTER TABLE accounts ALTER COLUMN name SET NOT NULL;
ALTER TABLE accounts ADD CONSTRAINT accounts_name UNIQUE (name);
ALTER TABLE accounts ADD CONSTRAINT accounts_name_check CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$');
CREATE UNIQUE INDEX accounts_one_operator ON accounts (operator) WHERE operator;
INSERT INTO accounts (id, name, operator)
SELECT id, 'operator', true FROM (
    SELECT lpad(floor(random() * 1e12)::bigint::text, 12, '0') AS id FROM generate_series(1, 10)
) c WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id = c.id) LIMIT 1;

ALTER TABLE roles ADD COLUMN account_id text REFERENCES accounts (id);
UPDATE roles SET account_id = (SELECT id FROM accounts WHERE name = 'default');
ALTER TABLE roles ALTER COLUMN account_id SET NOT NULL;
CREATE INDEX roles_account ON roles (account_id);

ALTER TABLE buckets ADD COLUMN account_id text REFERENCES accounts (id);
UPDATE buckets SET account_id = (SELECT id FROM accounts WHERE name = 'default');
DO $$ BEGIN
    EXECUTE format('ALTER TABLE buckets ALTER COLUMN account_id SET DEFAULT %L',
                   (SELECT id FROM accounts WHERE name = 'default'));
END $$;
ALTER TABLE buckets ALTER COLUMN account_id SET NOT NULL;
CREATE INDEX buckets_account ON buckets (account_id);

-- The operator account owns no buckets.
CREATE FUNCTION cairn_tenant_buckets() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (SELECT operator FROM accounts WHERE id = NEW.account_id) THEN
        RAISE EXCEPTION 'the operator account owns no buckets' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER buckets_tenant BEFORE INSERT OR UPDATE OF account_id ON buckets
    FOR EACH ROW EXECUTE FUNCTION cairn_tenant_buckets();

CREATE OR REPLACE FUNCTION cairn_require_users() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('cairn.users', true) IS DISTINCT FROM '2' THEN
        RAISE EXCEPTION 'this Cairn is too old to change users or grants, which are bucket policies now; upgrade it'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    RETURN NULL;
END
$$;
CREATE TRIGGER role_grants_users BEFORE INSERT OR UPDATE ON role_grants
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_users();
"#;

/// Migration 34: the console's logins (see `console`): a person, with
/// passkeys, linked to at most one identity per account, an identity being a
/// user, or (no user) the account's root; an identity belongs to at most one
/// login. Passkeys move from users to logins (each user that had some gets
/// a login of its own, with the user's ID); enrollment links are for an
/// identity; sessions act as one of their login's identities, and end
/// with its link. Sessions and challenges in progress are dropped.
const LOGINS: &str = r#"
CREATE TABLE logins (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE login_identities (
    login_id   uuid NOT NULL REFERENCES logins (id) ON DELETE CASCADE,
    account_id text NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    role_id    uuid REFERENCES roles (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (login_id, account_id)
);
CREATE UNIQUE INDEX login_identities_user ON login_identities (role_id) WHERE role_id IS NOT NULL;
CREATE UNIQUE INDEX login_identities_root ON login_identities (account_id) WHERE role_id IS NULL;

INSERT INTO logins (id, name)
SELECT r.id, r.name FROM roles r WHERE EXISTS (SELECT 1 FROM passkeys p WHERE p.role_id = r.id);
INSERT INTO login_identities (login_id, account_id, role_id)
SELECT r.id, r.account_id, r.id FROM roles r WHERE EXISTS (SELECT 1 FROM logins l WHERE l.id = r.id);

DELETE FROM console_sessions;
DELETE FROM console_challenges;

ALTER TABLE passkeys ADD COLUMN login_id uuid REFERENCES logins (id) ON DELETE CASCADE;
UPDATE passkeys SET login_id = role_id;
ALTER TABLE passkeys ALTER COLUMN login_id SET NOT NULL;
DROP INDEX passkeys_role;
ALTER TABLE passkeys DROP COLUMN role_id;
CREATE INDEX passkeys_login ON passkeys (login_id);

ALTER TABLE console_enrollments ADD COLUMN account_id text REFERENCES accounts (id) ON DELETE CASCADE;
UPDATE console_enrollments e SET account_id = r.account_id FROM roles r WHERE r.id = e.role_id;
ALTER TABLE console_enrollments ALTER COLUMN account_id SET NOT NULL;
ALTER TABLE console_enrollments ALTER COLUMN role_id DROP NOT NULL;
CREATE INDEX console_enrollments_account ON console_enrollments (account_id);

ALTER TABLE console_challenges DROP COLUMN role_id;
ALTER TABLE console_challenges ADD COLUMN login_id uuid REFERENCES logins (id) ON DELETE CASCADE;
CREATE INDEX console_challenges_login ON console_challenges (login_id);

DROP INDEX console_sessions_role;
ALTER TABLE console_sessions DROP COLUMN role_id;
ALTER TABLE console_sessions ADD COLUMN login_id uuid NOT NULL REFERENCES logins (id) ON DELETE CASCADE;
ALTER TABLE console_sessions ADD COLUMN account_id text NOT NULL;
ALTER TABLE console_sessions ADD FOREIGN KEY (login_id, account_id)
    REFERENCES login_identities (login_id, account_id) ON DELETE CASCADE;
ALTER TABLE console_sessions ADD COLUMN verified_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX console_sessions_identity ON console_sessions (login_id, account_id);

CREATE TRIGGER logins_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON logins
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
CREATE TRIGGER login_identities_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON login_identities
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
"#;

/// Migration 35: OpenID Connect sign-in to the console (see
/// `console::oidc`): the providers superadmins configure (by their issuer,
/// whose discovery document says the rest), the identities at them (issuer
/// and subject) that sign in a login, and sign-ins in progress (their
/// state, used once). A session signed in that way has no passkey.
const OIDC: &str = r#"
CREATE TABLE oidc_providers (
    name          text PRIMARY KEY CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,31}$'),
    label         text NOT NULL,
    issuer        text NOT NULL,
    client_id     text NOT NULL,
    client_secret text,
    scopes        text NOT NULL DEFAULT 'openid email profile',
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE login_oidc (
    provider     text NOT NULL REFERENCES oidc_providers (name) ON DELETE CASCADE,
    subject      text NOT NULL,
    login_id     uuid NOT NULL REFERENCES logins (id) ON DELETE CASCADE,
    email        text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    PRIMARY KEY (provider, subject)
);
CREATE INDEX login_oidc_login ON login_oidc (login_id);

CREATE TABLE oidc_flows (
    state_hash bytea PRIMARY KEY,
    provider   text NOT NULL REFERENCES oidc_providers (name) ON DELETE CASCADE,
    nonce      text NOT NULL,
    verifier   text NOT NULL,
    purpose    text NOT NULL CHECK (purpose IN ('login', 'enroll', 'link', 'reauth')),
    login_id   uuid REFERENCES logins (id) ON DELETE CASCADE,
    enrollment bytea,
    account_id text,
    session    bytea,
    expires_at timestamptz NOT NULL
);

ALTER TABLE console_sessions ALTER COLUMN credential_id DROP NOT NULL;
ALTER TABLE console_sessions ADD COLUMN oidc_provider text;

CREATE TRIGGER oidc_providers_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON oidc_providers
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
CREATE TRIGGER login_oidc_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON login_oidc
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
CREATE TRIGGER oidc_flows_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON oidc_flows
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
"#;

/// Migration 36: user names are unique per account, as in IAM, not across
/// the cluster. `role_grants`, which referenced users by name, is only read
/// now (by older Cairns: grants are bucket policies), so it loses its
/// reference. A bucket policy's users are bound to the IDs of the users of
/// the accounts its ARNs name.
const USER_NAMES: &str = r#"
ALTER TABLE role_grants DROP CONSTRAINT role_grants_role_fkey;
-- The ID (unique, `roles_id`) identifies a user now; its name, in its account.
ALTER TABLE roles DROP CONSTRAINT roles_pkey;
ALTER TABLE roles ADD CONSTRAINT roles_account_name UNIQUE (account_id, name);
DROP INDEX roles_account;

CREATE OR REPLACE FUNCTION cairn_policy_principals() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.policy_principals := CASE WHEN NEW.policy IS NOT NULL THEN (
        SELECT coalesce(jsonb_object_agg(p.arn, r.id::text), '{}'::jsonb)
        FROM (
            SELECT DISTINCT a #>> '{}' AS arn
            FROM jsonb_path_query(NEW.policy::jsonb, 'lax $.Statement[*].Principal.AWS[*]') a
            UNION
            SELECT a #>> '{}'
            FROM jsonb_path_query(NEW.policy::jsonb, 'lax $.Statement[*].NotPrincipal.AWS[*]') a
        ) p
        JOIN roles r ON r.account_id = substring(p.arn FROM '^arn:aws:iam::([0-9]{12}):user/')
                    AND r.name = substring(p.arn FROM '^arn:aws:iam::[0-9]{12}:user/(.+)$')
    ) END;
    RETURN NEW;
END
$$;
"#;

/// Migration 37: Object Lock, as in S3 (see `s3::object_lock`). A bucket
/// may have it enabled (for good: then it stays versioned), with a default
/// retention for new versions; a version may have a retention (a mode and
/// the time it lasts until) and a legal hold, as may an upload, for the
/// version it completes. Locked versions are kept from being deleted by
/// the catalog's functions, and, for a legal hold and compliance mode, by
/// triggers too, which no request can get around.
///
/// Lock protocol 5: the protocol itself doesn't change, but a node of
/// protocol 4 knows no locks, and would delete locked versions.
const OBJECT_LOCK: &str = r#"
CREATE OR REPLACE FUNCTION cairn_require_protocol() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('cairn.protocol', true) IS DISTINCT FROM '5' THEN
        RAISE EXCEPTION 'this Cairn is too old for its database, which another node upgraded; upgrade it too'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    RETURN NULL;
END
$$;

ALTER TABLE buckets
    ADD COLUMN object_lock boolean NOT NULL DEFAULT false,
    ADD COLUMN lock_mode text CHECK (lock_mode IN ('GOVERNANCE', 'COMPLIANCE')),
    ADD COLUMN lock_days int CHECK (lock_days > 0),
    ADD COLUMN lock_years int CHECK (lock_years > 0),
    ADD CONSTRAINT buckets_lock_default CHECK (
        (lock_mode IS NULL AND lock_days IS NULL AND lock_years IS NULL)
        OR (object_lock AND lock_mode IS NOT NULL AND (lock_days IS NULL) <> (lock_years IS NULL))
    ),
    ADD CONSTRAINT buckets_lock_versioned CHECK (NOT object_lock OR versioning = 'enabled');

ALTER TABLE objects
    ADD COLUMN retain_mode text CHECK (retain_mode IN ('GOVERNANCE', 'COMPLIANCE')),
    ADD COLUMN retain_until timestamptz,
    ADD COLUMN legal_hold boolean,
    ADD CONSTRAINT objects_retention CHECK ((retain_mode IS NULL) = (retain_until IS NULL));
ALTER TABLE multipart_uploads
    ADD COLUMN retain_mode text CHECK (retain_mode IN ('GOVERNANCE', 'COMPLIANCE')),
    ADD COLUMN retain_until timestamptz,
    ADD COLUMN legal_hold boolean,
    ADD CONSTRAINT multipart_uploads_retention CHECK ((retain_mode IS NULL) = (retain_until IS NULL));

-- Object Lock stays enabled once it is.
CREATE FUNCTION cairn_keep_object_lock() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Object Lock can''t be disabled on bucket %', OLD.name
        USING ERRCODE = 'insufficient_privilege';
END
$$;
CREATE TRIGGER buckets_object_lock BEFORE UPDATE OF object_lock ON buckets
    FOR EACH ROW WHEN (OLD.object_lock AND NOT NEW.object_lock)
    EXECUTE FUNCTION cairn_keep_object_lock();

-- A version under a legal hold, or retained in compliance mode, is never
-- deleted, and its compliance retention only ever lengthens while it lasts.
CREATE FUNCTION cairn_protect_locked() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.legal_hold OR (OLD.retain_mode = 'COMPLIANCE' AND OLD.retain_until > now()) THEN
            RAISE EXCEPTION 'version % of %/% is protected by Object Lock', OLD.version_id, OLD.bucket, OLD.key
                USING ERRCODE = 'insufficient_privilege';
        END IF;
        RETURN OLD;
    END IF;
    IF OLD.retain_mode = 'COMPLIANCE' AND OLD.retain_until > now()
       AND (NEW.retain_mode IS DISTINCT FROM 'COMPLIANCE' OR NEW.retain_until IS NULL
            OR NEW.retain_until < OLD.retain_until
            OR NEW.bucket <> OLD.bucket OR NEW.key <> OLD.key OR NEW.version_id <> OLD.version_id) THEN
        RAISE EXCEPTION 'the compliance retention of version % of %/% can''t be shortened', OLD.version_id, OLD.bucket, OLD.key
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF OLD.legal_hold AND NEW.legal_hold
       AND (NEW.bucket <> OLD.bucket OR NEW.key <> OLD.key OR NEW.version_id <> OLD.version_id) THEN
        RAISE EXCEPTION 'version % of %/% is under a legal hold', OLD.version_id, OLD.bucket, OLD.key
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER objects_locked BEFORE DELETE OR UPDATE ON objects
    FOR EACH ROW WHEN (OLD.legal_hold OR OLD.retain_mode = 'COMPLIANCE')
    EXECUTE FUNCTION cairn_protect_locked();
"#;

/// Migration 38: SSE-C's `sse_c_key` holds the object key sealed under the
/// client's key (72 bytes: nonce, key, tag; see `s3::sse`), no longer a
/// check of the client's key (48), as SSE-C objects now have keys of their
/// own, as SSE-KMS ones do. The protocol goes to 6, so that an older node
/// writes no checks into it. SSE-C objects from before can't be read any
/// more (no deployment had any).
const SSE_C_SEALED: &str = r#"
CREATE OR REPLACE FUNCTION cairn_require_protocol() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('cairn.protocol', true) IS DISTINCT FROM '6' THEN
        RAISE EXCEPTION 'this Cairn is too old for its database, which another node upgraded; upgrade it too'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    RETURN NULL;
END
$$;

ALTER TABLE objects DROP CONSTRAINT objects_sse_c_key;
ALTER TABLE objects ADD CONSTRAINT objects_sse_c_key
    CHECK (octet_length(sse_c_key) = 72) NOT VALID;
ALTER TABLE multipart_uploads DROP CONSTRAINT multipart_uploads_sse_c_key;
ALTER TABLE multipart_uploads ADD CONSTRAINT multipart_uploads_sse_c_key
    CHECK (octet_length(sse_c_key) = 72) NOT VALID;
"#;

/// Migration 39: the operator account's users are members, not IAM users:
/// each is a superadmin, by being one, with no access keys, inline
/// policies or grants (see `users::refuse_operator`). Their keys and
/// policies go, and triggers keep new ones out. They're all marked admin,
/// so that an older node, which decides `cairn:` actions by
/// `AdministratorAccess`, lets each of them do what this one does.
const OPERATOR_MEMBERS: &str = r#"
DELETE FROM access_keys k USING roles r, accounts a
    WHERE r.id = k.role_id AND a.id = r.account_id AND a.operator;
DELETE FROM role_policies p USING roles r, accounts a
    WHERE r.id = p.role_id AND a.id = r.account_id AND a.operator;
UPDATE roles r SET admin = true, secret = 'unusable:' || gen_random_uuid() || gen_random_uuid()
    FROM accounts a WHERE a.id = r.account_id AND a.operator;

CREATE FUNCTION cairn_operator_members() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (SELECT a.operator FROM roles r JOIN accounts a ON a.id = r.account_id WHERE r.id = NEW.role_id) THEN
        RAISE EXCEPTION 'the operator account''s users are superadmins, with no access keys or policies'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER access_keys_operator BEFORE INSERT OR UPDATE OF role_id ON access_keys
    FOR EACH ROW EXECUTE FUNCTION cairn_operator_members();
CREATE TRIGGER role_policies_operator BEFORE INSERT OR UPDATE OF role_id ON role_policies
    FOR EACH ROW EXECUTE FUNCTION cairn_operator_members();
"#;

/// Migration 40: managed policies, as IAM's (see `managed`): an account's
/// own, by name, and their attachments to its users, which are of the
/// account's own policies (`policy_id`) or of Cairn's, which have AWS's
/// names (`aws_policy`: `AmazonS3ReadOnlyAccess`, say). AdministratorAccess
/// stays the users' admin flag, which older nodes read. A policy that's
/// attached can't be deleted (IAM's DeleteConflict). The operator account's
/// users get none (see migration 39).
const MANAGED_POLICIES: &str = r#"
CREATE TABLE managed_policies (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id  text NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    name        text NOT NULL CHECK (name ~ '^[A-Za-z0-9+=,.@_-]{1,128}$'),
    description text NOT NULL DEFAULT '',
    document    text NOT NULL,
    version     integer NOT NULL DEFAULT 1,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, name)
);

CREATE TABLE role_attached_policies (
    role_id    uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    policy_id  uuid REFERENCES managed_policies (id),
    aws_policy text,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((policy_id IS NULL) <> (aws_policy IS NULL))
);
CREATE UNIQUE INDEX role_attached_policies_own ON role_attached_policies (role_id, policy_id)
    WHERE policy_id IS NOT NULL;
CREATE UNIQUE INDEX role_attached_policies_aws ON role_attached_policies (role_id, aws_policy)
    WHERE aws_policy IS NOT NULL;
CREATE INDEX role_attached_policies_policy ON role_attached_policies (policy_id);

-- A user's attached policies are its own account's.
CREATE FUNCTION cairn_attached_policy_account() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.policy_id IS NOT NULL AND (SELECT account_id FROM managed_policies WHERE id = NEW.policy_id)
        IS DISTINCT FROM (SELECT account_id FROM roles WHERE id = NEW.role_id) THEN
        RAISE EXCEPTION 'a user''s managed policies are its own account''s' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER role_attached_policies_account BEFORE INSERT OR UPDATE ON role_attached_policies
    FOR EACH ROW EXECUTE FUNCTION cairn_attached_policy_account();
CREATE TRIGGER role_attached_policies_operator BEFORE INSERT OR UPDATE OF role_id ON role_attached_policies
    FOR EACH ROW EXECUTE FUNCTION cairn_operator_members();

CREATE TRIGGER managed_policies_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON managed_policies
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
CREATE TRIGGER role_attached_policies_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON role_attached_policies
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
"#;

/// Migration 41: an account's public access block (see
/// `s3::buckets::public_access`), as S3's account-level one (S3 Control's
/// PutPublicAccessBlock), its flags as the buckets' bits (migration 32).
/// NULL: it has none, as a new account doesn't. It replaces the settings
/// `block-public-policy` and `restrict-public-buckets`, which applied to
/// every account: those that were on carry over into every tenant account's
/// block, so that no bucket opens up, and go.
const ACCOUNT_PUBLIC_ACCESS_BLOCK: &str = r#"
ALTER TABLE accounts ADD COLUMN public_access_block smallint
    CHECK (public_access_block BETWEEN 0 AND 15);
UPDATE accounts SET public_access_block =
    CASE WHEN EXISTS (SELECT 1 FROM settings WHERE name = 'block-public-policy' AND value <> '0') THEN 4 ELSE 0 END
    | CASE WHEN EXISTS (SELECT 1 FROM settings WHERE name = 'restrict-public-buckets' AND value <> '0') THEN 8 ELSE 0 END
WHERE NOT operator
  AND EXISTS (SELECT 1 FROM settings WHERE name IN ('block-public-policy', 'restrict-public-buckets') AND value <> '0');
DELETE FROM settings WHERE name IN ('block-public-policy', 'restrict-public-buckets');
"#;

/// Migration 42: IAM's permissions boundaries, user paths and tags, and
/// managed policies' paths (see `iam`, `plans/boundaries.md`), and user
/// names unique regardless of case, as IAM's are.
///
/// A user's boundary is a managed policy (the account's own, which can't be
/// deleted while it's one, or Cairn's), which caps what its identity
/// policies allow. An older Cairn knows no boundaries, and would allow a
/// bounded user what the boundary doesn't: so a bounded user also has an
/// inline policy that denies everything, `cairn:boundary` (kept by a
/// trigger), which only older Cairns read (this one leaves out the inline
/// policies named `cairn:…`, which IAM's names can't be). And older Cairns
/// may no longer change users, policies or keys at all (`cairn.users` 3),
/// which could undo that.
const BOUNDARIES: &str = r#"
DO $$
DECLARE
    v_clashes text;
BEGIN
    SELECT string_agg(format('%s in account %s', names, account_id), '; ') INTO v_clashes
    FROM (SELECT account_id, string_agg(name, ', ' ORDER BY name) AS names
          FROM roles GROUP BY account_id, lower(name) HAVING count(*) > 1) c;
    IF v_clashes IS NOT NULL THEN
        RAISE EXCEPTION 'user names must differ in more than case now, as IAM''s do: delete one of each of %, with the Cairn you have, before upgrading', v_clashes
            USING ERRCODE = 'unique_violation';
    END IF;
END $$;
CREATE UNIQUE INDEX roles_account_lower_name ON roles (account_id, lower(name));

ALTER TABLE roles ADD COLUMN path text NOT NULL DEFAULT '/'
    CHECK (length(path) <= 512 AND path ~ '^/([A-Za-z0-9+=,.@_/-]*/)?$' AND path <> '//');
ALTER TABLE roles ADD COLUMN boundary_policy_id uuid REFERENCES managed_policies (id);
ALTER TABLE roles ADD COLUMN boundary_aws text;
ALTER TABLE roles ADD CONSTRAINT roles_one_boundary CHECK (boundary_policy_id IS NULL OR boundary_aws IS NULL);
CREATE INDEX roles_boundary ON roles (boundary_policy_id) WHERE boundary_policy_id IS NOT NULL;

ALTER TABLE managed_policies ADD COLUMN path text NOT NULL DEFAULT '/'
    CHECK (length(path) <= 512 AND path ~ '^/([A-Za-z0-9+=,.@_/-]*/)?$' AND path <> '//');

-- A user's tags: at most 50 (see catalog.sql's I10), keys unique regardless
-- of case. `seq` orders them as IAM lists them: newest first.
CREATE TABLE role_tags (
    role_id uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    key     text NOT NULL CHECK (length(key) BETWEEN 1 AND 128),
    value   text NOT NULL CHECK (length(value) <= 256),
    seq     bigint GENERATED ALWAYS AS IDENTITY
);
CREATE UNIQUE INDEX role_tags_key ON role_tags (role_id, lower(key));

-- A user's boundary is its own account's.
CREATE FUNCTION cairn_boundary_account() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.boundary_policy_id IS NOT NULL AND (SELECT account_id FROM managed_policies WHERE id = NEW.boundary_policy_id)
        IS DISTINCT FROM NEW.account_id THEN
        RAISE EXCEPTION 'a user''s permissions boundary is its own account''s' USING ERRCODE = 'check_violation';
    END IF;
    IF (NEW.boundary_policy_id IS NOT NULL OR NEW.boundary_aws IS NOT NULL)
        AND (SELECT operator FROM accounts WHERE id = NEW.account_id) THEN
        RAISE EXCEPTION 'the operator account''s users are superadmins, with no permissions boundaries'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER roles_boundary_account BEFORE INSERT OR UPDATE OF boundary_policy_id, account_id ON roles
    FOR EACH ROW EXECUTE FUNCTION cairn_boundary_account();

-- What older Cairns read in place of a boundary: deny all.
CREATE FUNCTION cairn_boundary_for_older() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.boundary_policy_id IS NOT NULL OR NEW.boundary_aws IS NOT NULL THEN
        INSERT INTO role_policies (role_id, name, document)
        VALUES (NEW.id, 'cairn:boundary', '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}')
        ON CONFLICT DO NOTHING;
    ELSE
        DELETE FROM role_policies WHERE role_id = NEW.id AND name = 'cairn:boundary';
    END IF;
    RETURN NULL;
END
$$;
CREATE TRIGGER roles_boundary_for_older AFTER INSERT OR UPDATE OF boundary_policy_id, boundary_aws ON roles
    FOR EACH ROW EXECUTE FUNCTION cairn_boundary_for_older();

-- Bucket policies name users by their ARNs, paths and all.
CREATE OR REPLACE FUNCTION cairn_policy_principals() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.policy_principals := CASE WHEN NEW.policy IS NOT NULL THEN (
        SELECT coalesce(jsonb_object_agg(p.arn, r.id::text), '{}'::jsonb)
        FROM (
            SELECT DISTINCT a #>> '{}' AS arn
            FROM jsonb_path_query(NEW.policy::jsonb, 'lax $.Statement[*].Principal.AWS[*]') a
            UNION
            SELECT a #>> '{}'
            FROM jsonb_path_query(NEW.policy::jsonb, 'lax $.Statement[*].NotPrincipal.AWS[*]') a
        ) p
        JOIN roles r ON r.account_id = substring(p.arn FROM '^arn:aws:iam::([0-9]{12}):user/')
                    AND substring(r.path FROM 2) || r.name = substring(p.arn FROM '^arn:aws:iam::[0-9]{12}:user/(.+)$')
    ) END;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION cairn_require_users() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('cairn.users', true) IS DISTINCT FROM '3' THEN
        RAISE EXCEPTION 'this Cairn is too old to change users, which have permissions boundaries now; upgrade it'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    RETURN NULL;
END
$$;
DROP TRIGGER roles_users ON roles;
CREATE TRIGGER roles_users BEFORE INSERT OR DELETE OR TRUNCATE
    OR UPDATE OF name, secret, account_id, path, boundary_policy_id, boundary_aws ON roles
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_users();
CREATE TRIGGER role_policies_users BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON role_policies
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_users();
CREATE TRIGGER role_attached_policies_users BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON role_attached_policies
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_users();
CREATE TRIGGER managed_policies_users BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON managed_policies
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_users();
CREATE TRIGGER access_keys_users BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON access_keys
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_users();
CREATE TRIGGER role_tags_users BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON role_tags
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_users();
CREATE TRIGGER role_tags_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON role_tags
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
CREATE TRIGGER role_tags_operator BEFORE INSERT OR UPDATE OF role_id ON role_tags
    FOR EACH ROW EXECUTE FUNCTION cairn_operator_members();
"#;


/// Migration 43: managed policies' tags, as IAM's (see `iam`,
/// `plans/policy-tags-versions.md`): at most 50 (see catalog.sql's I10),
/// whose keys, unlike users', are case-sensitive (probed). Older Cairns know
/// none, and may change no policies (the users' gate, `BOUNDARIES`).
const POLICY_TAGS: &str = r#"
CREATE TABLE managed_policy_tags (
    policy_id uuid NOT NULL REFERENCES managed_policies (id) ON DELETE CASCADE,
    key       text NOT NULL CHECK (length(key) BETWEEN 1 AND 128),
    value     text NOT NULL CHECK (length(value) <= 256),
    seq       bigint GENERATED ALWAYS AS IDENTITY,
    UNIQUE (policy_id, key)
);
CREATE TRIGGER managed_policy_tags_users BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON managed_policy_tags
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_users();
CREATE TRIGGER managed_policy_tags_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON managed_policy_tags
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
"#;

/// Migration 44: managed policies' versions, as IAM's (see `iam`,
/// `plans/policy-tags-versions.md`): up to five of a policy, numbered on
/// (never reused), one of them the default, which decides. A policy's own
/// `version` and `document` stay its default's (catalog.sql's I13), which
/// older Cairns read, and evaluation still does. A new policy's first
/// version is made by a trigger. Older Cairns would replace the default
/// version in place, so they may change no policies any more (`cairn.users`
/// 4).
const POLICY_VERSIONS: &str = r#"
-- The gate is raised first (see `init`).
CREATE OR REPLACE FUNCTION cairn_require_users() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('cairn.users', true) IS DISTINCT FROM '4' THEN
        RAISE EXCEPTION 'this Cairn is too old to change users or policies, which have versions now; upgrade it'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    RETURN NULL;
END
$$;

CREATE TABLE managed_policy_versions (
    policy_id  uuid NOT NULL REFERENCES managed_policies (id) ON DELETE CASCADE,
    version    integer NOT NULL CHECK (version >= 1),
    document   text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (policy_id, version)
);
INSERT INTO managed_policy_versions (policy_id, version, document, created_at)
    SELECT id, version, document, updated_at FROM managed_policies;
ALTER TABLE managed_policies ADD COLUMN next_version integer;
UPDATE managed_policies SET next_version = version + 1;
ALTER TABLE managed_policies ALTER COLUMN next_version SET DEFAULT 2;
ALTER TABLE managed_policies ALTER COLUMN next_version SET NOT NULL;

CREATE FUNCTION cairn_policy_first_version() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO managed_policy_versions (policy_id, version, document, created_at)
    VALUES (NEW.id, NEW.version, NEW.document, NEW.created_at);
    RETURN NULL;
END
$$;
CREATE TRIGGER managed_policies_first_version AFTER INSERT ON managed_policies
    FOR EACH ROW EXECUTE FUNCTION cairn_policy_first_version();

CREATE TRIGGER managed_policy_versions_users BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON managed_policy_versions
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_users();
CREATE TRIGGER managed_policy_versions_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON managed_policy_versions
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
"#;
/// Migration 45: one account (see `plans/single-account.md`). Refused while
/// more than one account but the operator's has users or buckets. The
/// others go; the operator account's users move into the one, as admins
/// (they could manage everything before), but those whose logins are in it
/// already, which go, making the user they're in it as admin. The
/// operator account's root becomes the account's (if it has none), else a
/// user `operator` (`-2`, ...). The operator account's row stays, empty:
/// older nodes read its ID once, to decide `cairn:` by (to no one now), and
/// so keep serving S3 until they're upgraded; they may change no users
/// (`cairn.users` 5), and a second account can't be made.
const SINGLE_ACCOUNT: &str = r#"
-- The gate is raised first (see `init`).
CREATE OR REPLACE FUNCTION cairn_require_users() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('cairn.users', true) IS DISTINCT FROM '5' THEN
        RAISE EXCEPTION 'this Cairn is too old to change users or accounts: Cairn has one account now; upgrade it'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    RETURN NULL;
END
$$;
CREATE TRIGGER accounts_users BEFORE INSERT OR DELETE OR TRUNCATE ON accounts
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_users();

DO $$
DECLARE
    v_used text;
    v_account text;
    v_ops text;
    v_member record;
    v_held boolean;
    v_held_role uuid;
    v_root uuid;
    v_name text;
    v_n integer := 1;
    v_role uuid;
BEGIN
    SELECT string_agg(name, ', ' ORDER BY name) INTO v_used FROM accounts a
    WHERE NOT operator AND (EXISTS (SELECT 1 FROM roles r WHERE r.account_id = a.id)
                            OR EXISTS (SELECT 1 FROM buckets b WHERE b.account_id = a.id));
    IF v_used LIKE '%,%' THEN
        RAISE EXCEPTION 'Cairn has one account now, but these have users or buckets: %. Delete the users and buckets of all but one, with the Cairn you have, before upgrading', v_used
            USING ERRCODE = 'check_violation';
    END IF;
    SELECT id INTO v_account FROM accounts a WHERE NOT operator
    ORDER BY EXISTS (SELECT 1 FROM roles r WHERE r.account_id = a.id)
             OR EXISTS (SELECT 1 FROM buckets b WHERE b.account_id = a.id) DESC, created_at, id
    LIMIT 1;
    SELECT id INTO v_ops FROM accounts WHERE operator;
    DELETE FROM oidc_flows WHERE account_id IS NOT NULL AND account_id <> v_account;
    DELETE FROM accounts WHERE NOT operator AND id <> v_account;

    -- Sign-ins as the operator account.
    DELETE FROM console_sessions WHERE account_id = v_ops;
    DELETE FROM console_enrollments WHERE account_id = v_ops;

    -- Its users: superadmins, admins now.
    FOR v_member IN
        SELECT r.id, r.name, i.login_id FROM roles r LEFT JOIN login_identities i ON i.role_id = r.id
        WHERE r.account_id = v_ops ORDER BY r.name
    LOOP
        v_held := false;
        SELECT true, role_id INTO v_held, v_held_role FROM login_identities
        WHERE login_id = v_member.login_id AND account_id = v_account;
        IF coalesce(v_held, false) THEN
            UPDATE roles SET admin = true WHERE id = v_held_role;
            DELETE FROM roles WHERE id = v_member.id;
        ELSIF EXISTS (SELECT 1 FROM roles WHERE account_id = v_account AND lower(name) = lower(v_member.name)) THEN
            RAISE EXCEPTION 'the operator account''s user % has the name of another user: Cairn has one account now; delete or rename one of them, with the Cairn you have, before upgrading', v_member.name
                USING ERRCODE = 'unique_violation';
        ELSE
            UPDATE login_identities SET account_id = v_account WHERE role_id = v_member.id;
            UPDATE roles SET account_id = v_account, admin = true WHERE id = v_member.id;
        END IF;
    END LOOP;

    -- Its root.
    SELECT login_id INTO v_root FROM login_identities WHERE account_id = v_ops AND role_id IS NULL;
    IF v_root IS NOT NULL THEN
        v_held := false;
        SELECT true, role_id INTO v_held, v_held_role FROM login_identities
        WHERE login_id = v_root AND account_id = v_account;
        IF coalesce(v_held, false) THEN
            UPDATE roles SET admin = true WHERE id = v_held_role;
            DELETE FROM login_identities WHERE login_id = v_root AND account_id = v_ops;
        ELSIF NOT EXISTS (SELECT 1 FROM login_identities WHERE account_id = v_account AND role_id IS NULL) THEN
            UPDATE login_identities SET account_id = v_account WHERE login_id = v_root AND account_id = v_ops;
        ELSE
            v_name := 'operator';
            WHILE EXISTS (SELECT 1 FROM roles WHERE account_id = v_account AND lower(name) = v_name) LOOP
                v_n := v_n + 1;
                v_name := 'operator-' || v_n;
            END LOOP;
            INSERT INTO roles (name, secret, admin, account_id)
            VALUES (v_name, 'unusable:' || gen_random_uuid() || gen_random_uuid(), true, v_account)
            RETURNING id INTO v_role;
            UPDATE login_identities SET account_id = v_account, role_id = v_role
            WHERE login_id = v_root AND account_id = v_ops;
        END IF;
    END IF;
END $$;

-- One account (and the operator's, empty, for older nodes).
CREATE UNIQUE INDEX accounts_one ON accounts (operator) WHERE NOT operator;
"#;
/// Migration 46: no root (see `plans/single-account.md`): the account's
/// root, which identity policies didn't restrict, goes; the command line on
/// a node is the way out of what policies lock. A login that was the root
/// becomes an admin user, `root` (`root-2`, ...), so it keeps its way in.
/// Roots' enrollment links go, and no identity or link is a root's again.
const NO_ROOT: &str = r#"
DO $$
DECLARE
    v_root record;
    v_name text;
    v_n integer;
    v_role uuid;
BEGIN
    FOR v_root IN SELECT login_id, account_id FROM login_identities WHERE role_id IS NULL LOOP
        v_name := 'root';
        v_n := 1;
        WHILE EXISTS (SELECT 1 FROM roles WHERE account_id = v_root.account_id AND lower(name) = v_name) LOOP
            v_n := v_n + 1;
            v_name := 'root-' || v_n;
        END LOOP;
        INSERT INTO roles (name, secret, admin, account_id)
        VALUES (v_name, 'unusable:' || gen_random_uuid() || gen_random_uuid(), true, v_root.account_id)
        RETURNING id INTO v_role;
        UPDATE login_identities SET role_id = v_role
        WHERE login_id = v_root.login_id AND account_id = v_root.account_id;
    END LOOP;
END $$;
DELETE FROM console_enrollments WHERE role_id IS NULL;
DROP INDEX login_identities_root;
ALTER TABLE login_identities ALTER COLUMN role_id SET NOT NULL;
ALTER TABLE console_enrollments ALTER COLUMN role_id SET NOT NULL;
"#;
/// Migration 47: users' tables are named as users (`roles` was their name
/// from before they were IAM users; IAM roles are another thing, see
/// `plans/roles.md`): `roles` → `users`, `role_policies`,
/// `role_attached_policies`, `role_tags` → `user_…`, and every `role_id` →
/// `user_id`. `role_grants` stays (only read, to move what's left of it).
/// Older nodes read the old names until they're upgraded: each renamed table
/// keeps a view by its old name, with its old columns, and the tables whose
/// names stay keep a `role_id` (generated, the same as `user_id`). They may
/// change no users (`cairn.users` 6), nor logins' identities or enrollment
/// links (whose `role_id` they could no longer write).
const USERS_RENAMED: &str = r#"
-- The gate is raised first (see `init`).
CREATE OR REPLACE FUNCTION cairn_require_users() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('cairn.users', true) IS DISTINCT FROM '6' THEN
        RAISE EXCEPTION 'this Cairn is too old to change users: their tables were renamed; upgrade it'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    RETURN NULL;
END
$$;

ALTER TABLE roles RENAME TO users;
ALTER TABLE role_policies RENAME TO user_policies;
ALTER TABLE role_attached_policies RENAME TO user_attached_policies;
ALTER TABLE role_tags RENAME TO user_tags;
ALTER SEQUENCE role_tags_seq_seq RENAME TO user_tags_seq_seq;
ALTER TABLE user_policies RENAME COLUMN role_id TO user_id;
ALTER TABLE user_attached_policies RENAME COLUMN role_id TO user_id;
ALTER TABLE user_tags RENAME COLUMN role_id TO user_id;
ALTER TABLE access_keys RENAME COLUMN role_id TO user_id;
ALTER TABLE login_identities RENAME COLUMN role_id TO user_id;
ALTER TABLE console_enrollments RENAME COLUMN role_id TO user_id;

ALTER TABLE users RENAME CONSTRAINT roles_account_name TO users_account_name;
ALTER TABLE users RENAME CONSTRAINT roles_id TO users_id;
ALTER TABLE users RENAME CONSTRAINT roles_one_boundary TO users_one_boundary;
ALTER TABLE users RENAME CONSTRAINT roles_path_check TO users_path_check;
ALTER TABLE users RENAME CONSTRAINT roles_account_id_fkey TO users_account_id_fkey;
ALTER TABLE users RENAME CONSTRAINT roles_boundary_policy_id_fkey TO users_boundary_policy_id_fkey;
ALTER INDEX roles_account_lower_name RENAME TO users_account_lower_name;
ALTER INDEX roles_boundary RENAME TO users_boundary;
ALTER TRIGGER roles_boundary_account ON users RENAME TO users_boundary_account;
ALTER TRIGGER roles_boundary_for_older ON users RENAME TO users_boundary_for_older;
ALTER TRIGGER roles_protocol ON users RENAME TO users_protocol;
ALTER TRIGGER roles_users ON users RENAME TO users_users;

ALTER TABLE user_policies RENAME CONSTRAINT role_policies_pkey TO user_policies_pkey;
ALTER TABLE user_policies RENAME CONSTRAINT role_policies_role_id_fkey TO user_policies_user_id_fkey;
ALTER TRIGGER role_policies_operator ON user_policies RENAME TO user_policies_operator;
ALTER TRIGGER role_policies_protocol ON user_policies RENAME TO user_policies_protocol;
ALTER TRIGGER role_policies_users ON user_policies RENAME TO user_policies_users;

ALTER TABLE user_attached_policies RENAME CONSTRAINT role_attached_policies_check TO user_attached_policies_check;
ALTER TABLE user_attached_policies RENAME CONSTRAINT role_attached_policies_policy_id_fkey TO user_attached_policies_policy_id_fkey;
ALTER TABLE user_attached_policies RENAME CONSTRAINT role_attached_policies_role_id_fkey TO user_attached_policies_user_id_fkey;
ALTER INDEX role_attached_policies_aws RENAME TO user_attached_policies_aws;
ALTER INDEX role_attached_policies_own RENAME TO user_attached_policies_own;
ALTER INDEX role_attached_policies_policy RENAME TO user_attached_policies_policy;
ALTER TRIGGER role_attached_policies_account ON user_attached_policies RENAME TO user_attached_policies_account;
ALTER TRIGGER role_attached_policies_operator ON user_attached_policies RENAME TO user_attached_policies_operator;
ALTER TRIGGER role_attached_policies_protocol ON user_attached_policies RENAME TO user_attached_policies_protocol;
ALTER TRIGGER role_attached_policies_users ON user_attached_policies RENAME TO user_attached_policies_users;

ALTER TABLE user_tags RENAME CONSTRAINT role_tags_key_check TO user_tags_key_check;
ALTER TABLE user_tags RENAME CONSTRAINT role_tags_value_check TO user_tags_value_check;
ALTER TABLE user_tags RENAME CONSTRAINT role_tags_role_id_fkey TO user_tags_user_id_fkey;
ALTER INDEX role_tags_key RENAME TO user_tags_key;
ALTER TRIGGER role_tags_operator ON user_tags RENAME TO user_tags_operator;
ALTER TRIGGER role_tags_protocol ON user_tags RENAME TO user_tags_protocol;
ALTER TRIGGER role_tags_users ON user_tags RENAME TO user_tags_users;

ALTER TABLE access_keys RENAME CONSTRAINT access_keys_role_id_fkey TO access_keys_user_id_fkey;
ALTER INDEX access_keys_role RENAME TO access_keys_user;
ALTER TABLE login_identities RENAME CONSTRAINT login_identities_role_id_fkey TO login_identities_user_id_fkey;
ALTER TABLE console_enrollments RENAME CONSTRAINT console_enrollments_role_id_fkey TO console_enrollments_user_id_fkey;
ALTER INDEX console_enrollments_role RENAME TO console_enrollments_user;

-- The functions the triggers run, by the new names.
CREATE OR REPLACE FUNCTION cairn_attached_policy_account() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.policy_id IS NOT NULL AND (SELECT account_id FROM managed_policies WHERE id = NEW.policy_id)
        IS DISTINCT FROM (SELECT account_id FROM users WHERE id = NEW.user_id) THEN
        RAISE EXCEPTION 'a user''s managed policies are its own account''s' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
CREATE OR REPLACE FUNCTION cairn_boundary_for_older() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.boundary_policy_id IS NOT NULL OR NEW.boundary_aws IS NOT NULL THEN
        INSERT INTO user_policies (user_id, name, document)
        VALUES (NEW.id, 'cairn:boundary', '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}')
        ON CONFLICT DO NOTHING;
    ELSE
        DELETE FROM user_policies WHERE user_id = NEW.id AND name = 'cairn:boundary';
    END IF;
    RETURN NULL;
END
$$;
CREATE OR REPLACE FUNCTION cairn_legacy_secret() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    v_key access_keys;
BEGIN
    v_key := CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
    UPDATE users u SET secret = coalesce(
        (SELECT k.secret FROM access_keys k WHERE k.access_key_id = u.name AND k.user_id = u.id AND k.active),
        'unusable:' || gen_random_uuid() || gen_random_uuid())
    WHERE u.id = v_key.user_id AND u.name = v_key.access_key_id;
    RETURN NULL;
END
$$;
CREATE OR REPLACE FUNCTION cairn_operator_members() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (SELECT a.operator FROM users u JOIN accounts a ON a.id = u.account_id WHERE u.id = NEW.user_id) THEN
        RAISE EXCEPTION 'the operator account''s users are superadmins, with no access keys or policies'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
CREATE OR REPLACE FUNCTION cairn_policy_principals() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.policy_principals := CASE WHEN NEW.policy IS NOT NULL THEN (
        SELECT coalesce(jsonb_object_agg(p.arn, u.id::text), '{}'::jsonb)
        FROM (
            SELECT DISTINCT a #>> '{}' AS arn
            FROM jsonb_path_query(NEW.policy::jsonb, 'lax $.Statement[*].Principal.AWS[*]') a
            UNION
            SELECT a #>> '{}'
            FROM jsonb_path_query(NEW.policy::jsonb, 'lax $.Statement[*].NotPrincipal.AWS[*]') a
        ) p
        JOIN users u ON u.account_id = substring(p.arn FROM '^arn:aws:iam::([0-9]{12}):user/')
                    AND substring(u.path FROM 2) || u.name = substring(p.arn FROM '^arn:aws:iam::[0-9]{12}:user/(.+)$')
    ) END;
    RETURN NEW;
END
$$;

-- For older nodes, until they're upgraded: the old names, to read.
CREATE VIEW roles AS SELECT * FROM users;
CREATE VIEW role_policies AS SELECT user_id AS role_id, name, document FROM user_policies;
CREATE VIEW role_attached_policies AS SELECT user_id AS role_id, policy_id, aws_policy, created_at FROM user_attached_policies;
CREATE VIEW role_tags AS SELECT user_id AS role_id, key, value, seq FROM user_tags;
ALTER TABLE access_keys ADD COLUMN role_id uuid GENERATED ALWAYS AS (user_id) STORED;
ALTER TABLE login_identities ADD COLUMN role_id uuid GENERATED ALWAYS AS (user_id) STORED;
ALTER TABLE console_enrollments ADD COLUMN role_id uuid GENERATED ALWAYS AS (user_id) STORED;
CREATE TRIGGER login_identities_users BEFORE INSERT OR DELETE OR UPDATE OR TRUNCATE ON login_identities
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_users();
CREATE TRIGGER console_enrollments_users BEFORE INSERT OR DELETE OR UPDATE OR TRUNCATE ON console_enrollments
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_users();
"#;
/// Migration 48: IAM roles (see `roles`, `plans/roles.md`): assumable
/// identities with a trust policy, inline and managed policies, tags and a
/// permissions boundary, as users have. Named `iam_role…`, as `role…` are
/// older nodes' views of users' tables (`USERS_RENAMED`). A trust policy's
/// users and roles are kept by their IDs, as a bucket policy's users are
/// (`PRINCIPAL_IDS`), so it names those it named when it was set.
const IAM_ROLES: &str = r#"
CREATE TABLE iam_roles (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id           text NOT NULL REFERENCES accounts (id),
    name                 text NOT NULL CHECK (name ~ '^[A-Za-z0-9+=,.@_-]{1,64}$'),
    path                 text NOT NULL DEFAULT '/'
                         CHECK (length(path) <= 512 AND path ~ '^/([A-Za-z0-9+=,.@_/-]*/)?$' AND path <> '//'),
    trust_policy         text NOT NULL,
    trust_principals     jsonb NOT NULL DEFAULT '{}',
    description          text NOT NULL DEFAULT '' CHECK (length(description) <= 1000),
    max_session_duration integer NOT NULL DEFAULT 3600 CHECK (max_session_duration BETWEEN 3600 AND 43200),
    boundary_policy_id   uuid REFERENCES managed_policies (id),
    boundary_aws         text,
    kms_entity_id        text,
    created_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iam_roles_one_boundary CHECK (boundary_policy_id IS NULL OR boundary_aws IS NULL)
);
CREATE UNIQUE INDEX iam_roles_account_lower_name ON iam_roles (account_id, lower(name));
CREATE INDEX iam_roles_boundary ON iam_roles (boundary_policy_id) WHERE boundary_policy_id IS NOT NULL;

CREATE TABLE iam_role_policies (
    role_id  uuid NOT NULL REFERENCES iam_roles (id) ON DELETE CASCADE,
    name     text NOT NULL,
    document text NOT NULL,
    PRIMARY KEY (role_id, name)
);

CREATE TABLE iam_role_attached_policies (
    role_id    uuid NOT NULL REFERENCES iam_roles (id) ON DELETE CASCADE,
    policy_id  uuid REFERENCES managed_policies (id),
    aws_policy text,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((policy_id IS NULL) <> (aws_policy IS NULL))
);
CREATE UNIQUE INDEX iam_role_attached_policies_own ON iam_role_attached_policies (role_id, policy_id)
    WHERE policy_id IS NOT NULL;
CREATE UNIQUE INDEX iam_role_attached_policies_aws ON iam_role_attached_policies (role_id, aws_policy)
    WHERE aws_policy IS NOT NULL;
CREATE INDEX iam_role_attached_policies_policy ON iam_role_attached_policies (policy_id);

CREATE TABLE iam_role_tags (
    role_id uuid NOT NULL REFERENCES iam_roles (id) ON DELETE CASCADE,
    key     text NOT NULL CHECK (length(key) BETWEEN 1 AND 128),
    value   text NOT NULL CHECK (length(value) <= 256),
    seq     bigint GENERATED ALWAYS AS IDENTITY
);
CREATE UNIQUE INDEX iam_role_tags_key ON iam_role_tags (role_id, lower(key));

-- A role's boundary and managed policies are its own account's.
CREATE TRIGGER iam_roles_boundary_account BEFORE INSERT OR UPDATE OF boundary_policy_id, account_id ON iam_roles
    FOR EACH ROW EXECUTE FUNCTION cairn_boundary_account();
CREATE FUNCTION cairn_role_attached_policy_account() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.policy_id IS NOT NULL AND (SELECT account_id FROM managed_policies WHERE id = NEW.policy_id)
        IS DISTINCT FROM (SELECT account_id FROM iam_roles WHERE id = NEW.role_id) THEN
        RAISE EXCEPTION 'a role''s managed policies are its own account''s' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER iam_role_attached_policies_account BEFORE INSERT OR UPDATE ON iam_role_attached_policies
    FOR EACH ROW EXECUTE FUNCTION cairn_role_attached_policy_account();

-- The users and roles a trust policy names, by ARN: their IDs.
CREATE FUNCTION cairn_trust_principals() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.trust_principals := (
        SELECT coalesce(jsonb_object_agg(p.arn, coalesce(u.id, r.id)::text), '{}'::jsonb)
        FROM (
            SELECT DISTINCT a #>> '{}' AS arn
            FROM jsonb_path_query(NEW.trust_policy::jsonb, 'lax $.Statement[*].Principal.AWS[*]') a
        ) p
        LEFT JOIN users u ON u.account_id = substring(p.arn FROM '^arn:aws:iam::([0-9]{12}):user/')
                         AND substring(u.path FROM 2) || u.name = substring(p.arn FROM '^arn:aws:iam::[0-9]{12}:user/(.+)$')
        LEFT JOIN iam_roles r ON r.account_id = substring(p.arn FROM '^arn:aws:iam::([0-9]{12}):role/')
                             AND substring(r.path FROM 2) || r.name = substring(p.arn FROM '^arn:aws:iam::[0-9]{12}:role/(.+)$')
        WHERE u.id IS NOT NULL OR r.id IS NOT NULL
    );
    RETURN NEW;
END
$$;
CREATE TRIGGER iam_roles_trust_principals BEFORE INSERT OR UPDATE OF trust_policy ON iam_roles
    FOR EACH ROW EXECUTE FUNCTION cairn_trust_principals();

CREATE TRIGGER iam_roles_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON iam_roles
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
CREATE TRIGGER iam_roles_users BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON iam_roles
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_users();
CREATE TRIGGER iam_role_policies_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON iam_role_policies
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
CREATE TRIGGER iam_role_policies_users BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON iam_role_policies
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_users();
CREATE TRIGGER iam_role_attached_policies_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON iam_role_attached_policies
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
CREATE TRIGGER iam_role_attached_policies_users BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON iam_role_attached_policies
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_users();
CREATE TRIGGER iam_role_tags_protocol BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON iam_role_tags
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_protocol();
CREATE TRIGGER iam_role_tags_users BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON iam_role_tags
    FOR EACH STATEMENT EXECUTE FUNCTION cairn_require_users();
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
