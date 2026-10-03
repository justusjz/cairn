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

/// Arbitrary key for the advisory lock that serializes migrations, so nodes
/// starting at the same time don't race to apply the same step.
const MIGRATION_LOCK: i64 = 0x6361_6972_6e00; // "cairn\0"

/// The schema, as an ordered list of steps. Migration `n` (1-based) is
/// `MIGRATIONS[n - 1]`; `schema_migrations` records which have been applied.
/// Only ever append: an applied step must never change.
const MIGRATIONS: &[&str] = &[INITIAL_SCHEMA, VERSIONING, DELETE_VERSION_GRANT];

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
