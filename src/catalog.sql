-- The catalog's multi-statement transactions, one function each, so that a
-- transaction is a single round trip to Postgres. See `db::install_functions`:
-- each connection creates these in its own session's `pg_temp` schema, so
-- they're always the version of the binary that calls them, and they're
-- called (and call each other) as `pg_temp.cairn_…`.
--
-- Callers run each function as a statement of its own, which is then its own
-- transaction: one round trip. So every function either succeeds, or reports
-- why it didn't (a `status`) without having changed anything; it checks all
-- it needs to before its first write. The locations of the blobs to reap
-- after commit come back as three parallel arrays (blob, node, peer URL).
--
-- PL/pgSQL throughout: unlike SQL functions, their bodies aren't checked
-- against the schema when they're created, which happens before migrations
-- run on a fresh database. All of them are VOLATILE (the default), which
-- matters for F1 below.
--
--
-- THE LOCK PROTOCOL
--
-- Every writing transaction runs at READ COMMITTED. (SERIALIZABLE tracks
-- reads by index page, so concurrent uploads of unrelated keys kept failing
-- each other.) Correctness rests on this protocol instead: each invariant
-- below has one guard, and every transaction that could break the invariant
-- holds that guard, and checks the invariant after acquiring it, in a later
-- statement. That relies on two documented facts about READ COMMITTED:
--
-- F1. Every statement, including each statement of a VOLATILE function, sees
--     everything committed before it started. So a check in a statement after
--     a lock was acquired sees all that the lock's previous holders committed.
-- F2. When an UPDATE, DELETE or SELECT ... FOR ... finds its target row
--     changed by a transaction that committed after the statement's snapshot
--     was taken, it waits for that transaction, and then re-evaluates its
--     WHERE clause on the row's newest version (and skips the row if it was
--     deleted). But only the target row is re-read: everything else the
--     clause looks at (other tables' rows, joined or in subqueries such as
--     NOT EXISTS (SELECT ... FROM parts ...)) still comes from the snapshot
--     taken before the wait. So only conditions on the target row's own
--     columns are re-checked reliably, and a condition on other rows is
--     always checked in a later statement than the one that takes the lock.
--
-- The locks. The shared mode is always FOR KEY SHARE, the mode the FK checks
-- take anyway. It conflicts with FOR UPDATE and DELETE, but not with plain
-- UPDATEs (FOR NO KEY UPDATE), so the exclusive mode is always an explicit
-- SELECT ... FOR UPDATE. In the order they're taken (see "Deadlocks"):
--
--   B(b)    The bucket's row. Shared: writing objects or uploads in it,
--           reading its versioning state. Exclusive: changing the versioning
--           state, deleting the bucket.
--   U(u)    The upload's row. Shared: attaching a part to it. Exclusive:
--           completing or aborting it.
--   P(u,n)  An advisory lock per part number of an upload
--           (`cairn_lock_part_number`), in the two-key space. Taken by every
--           attach to that part number.
--   S(b,s)  An advisory lock per stripe of a bucket's keys: each key falls in
--           one of 16 stripes, by its hash. Shared: changing the versions of a
--           few keys (which then also take their K). Exclusive: changing the
--           versions of many keys at once (a large DeleteObjects), instead of
--           taking their K. See `cairn_lock_keys`.
--   K(b,k)  An advisory lock per key, in the one-key space. Taken by every
--           change to the versions of key k that doesn't hold its stripe
--           exclusively. Bucket names can't contain '/', so 'b/k' identifies
--           the key. Together, S and K make every two writers of a key
--           conflict: both take K, or one holds S exclusively, which conflicts
--           with the other's S in either mode.
--   G(g)    The role_grants rows. Locked (exclusively, in primary-key order)
--           before they're deleted.
--   R(r)    The role's row. Shared: granting it a permission. Exclusive (by
--           deleting it): deleting the role.
--   X(x)    The blob's row. Shared: referencing it, changing or deleting
--           a part on it, or changing its `lost_ranges` (the scrubber,
--           which locks the row with nothing else). Exclusive: committing it, deleting it, removing a
--           location, moving parts off or onto it (the packer). All of a
--           transaction's blobs are locked by one call of `cairn_lock_blobs`.
--
-- Advisory locks whose ids collide (two keys hashing alike) merely share a
-- lock, which is still taken in the same place in the order.
--
-- Advisory locks live in Postgres's shared lock table, which holds about
-- `max_locks_per_transaction` (64 by default) per connection, and every
-- transaction needs some of that for its table and index locks too. So no
-- transaction takes more than 16 advisory locks (stripes and keys), and
-- however many run at once, they can't fill it.
--
-- The invariants, and how each is kept:
--
-- I1. A key's versions: at most one current version, which is the newest (by
--     id); at most one null version; a conditional write is evaluated against
--     the current version as of the write (Cairn decides it against a version
--     it read, and the write lands only if that's still the current one). Guard: K(b,k) (or its stripe's
--     S(b,s) exclusively, see above), taken by every
--     writer of a key's versions (`cairn_put_version` and `cairn_delete_key`
--     callers) before reading them. So writes to a key are serialized, and a
--     new version's id (drawn after the lock) grows with commit order. The
--     unique indexes on objects are a backstop.
-- I2. A write or delete lands entirely before or after a change of the
--     bucket's versioning state. Guard: B(b): writers read the state with it
--     shared, PutBucketVersioning holds it exclusively.
-- I3. A bucket is only deleted when it has no objects and no uploads, since
--     its cascades must never delete data. (DeleteBucket aborts the uploads
--     itself first.) Guard: B(b): DeleteBucket holds it
--     exclusively and checks afterwards; every inserter of objects holds it
--     shared (and CreateMultipartUpload's insert, through its FK check). An
--     inserter that finds the row gone reports NoSuchBucket
--     (CompleteMultipartUpload reports NoSuchUpload: an upload's bucket
--     outlives it).
-- I4. CompleteMultipartUpload publishes exactly the parts it computed the
--     ETag and size from, and no part is attached to an upload being or
--     already completed or aborted. Guard: U(u): exclusive for complete and
--     abort, before they read the staged parts; shared for attaching, before
--     checking the upload exists. Attaches to the same part number are
--     serialized by P(u,n), so the part an attach displaces stays put.
-- I5. A part only references an existing, committed blob; a blob is only
--     deleted when no part references it; a blob is only committed with all
--     of its shards' locations present. Guard: X(x).
--     - Referencing (copies): lock the source parts' blobs shared, then
--       re-read the source parts, and check they're still the same parts, on
--       those blobs (`cairn_source_parts`).
--     - Deleting: lock the candidates exclusively, then delete those without
--       parts in a later statement (`cairn_drop_unreferenced_blobs`).
--     - Committing: lock exclusively, then check it's pending and count its
--       locations. Locations are only removed together with their blob, or
--       (in the future) under X(x) exclusive.
--     - Deleting a pending blob (GC, and `blobs::abandon` for failed uploads
--       and packing jobs): the GC locks the stale ones with SKIP LOCKED,
--       re-checking that they're pending (F2), and so never touches one being
--       committed; the abandon is a single DELETE whose condition is on the
--       blob row only, re-checked (F2).
--     The parts FKs remain as a backstop; with this protocol, they can't fail.
-- I6. Every unreferenced committed blob is dropped eventually. A blob becomes
--     unreferenced only by its parts being deleted, which the parts_garbage
--     trigger logs in the same transaction, or moved by the packer, which
--     checks its sources itself. Folds run one at a time (an advisory lock),
--     so each log row is taken exactly once.
-- I7. The packer moves a part only if it's still where the job read it from:
--     a compare-and-swap on the part row. Its sources and new blobs are
--     locked exclusively up front, so no one else changes those part rows
--     while it does.
-- I8. `dead_size` and the packer's leases are heuristics: nothing depends on
--     them for correctness.
--
-- DEADLOCKS
--
-- There are none, by three rules, which every transaction follows:
--
-- A. All of a transaction's locks are taken up front, in one global order:
--    B, U, P, S (by stripe), K (by lock id), G (by primary key), R, X (by
--    blob id), each stripe in one mode, each blob
--    in its final mode (exclusive wins over shared). A transaction that waits
--    for a lock therefore only ever waits for one that comes later in the
--    order than all it holds, so no cycle of waits can form.
-- B. No statement waits for anything else. Every row a transaction changes,
--    deletes or locks implicitly (through an FK check, a unique index, a
--    cascade) is covered by a lock it already holds, and so is every
--    conflicting holder of that row: object rows are only changed under
--    their key's K, part rows under their blob's X (and their key's K or
--    their upload's U), blob rows under their X, grant rows under G, bucket
--    and upload rows under B and U. The rows that new objects, parts and
--    locations reference (their bucket, upload, blob) are locked first.
-- C. Read, lock, verify. Which blobs to lock is only known from reading
--    parts, so a transaction reads them first. What it read is stable under
--    its earlier locks (the key's versions under K, an upload's parts under U
--    or P), except for the blob a part is on: the packer may move the part
--    in between. So after locking, `cairn_check_on` checks the parts are
--    still on locked blobs, and if not, raises a serialization failure, which
--    rolls the transaction back for the caller to retry (`db::is_conflict`).
--    A copy's source parts may also be replaced or deleted (no lock of ours
--    covers the source key): then the copy starts over ('source_changed').
--
-- Statements that run on their own (the pending blob and location inserts,
-- CreateMultipartUpload, role creation and updates, the heartbeat, the
-- scrubber's and reads' updates of a location's `checked_at`, and the
-- scrubber's changes to `scrub_findings`) hold nothing that anyone waits for
-- while they wait, so they can't be part of a cycle either. (A location insert's FK checks lock its node's row shared,
-- but nothing ever locks a node's row exclusively.) An insert whose FK checks
-- would lock rows out of order (a grant's: the role, then the bucket) is a
-- function that locks them in order first (`cairn_grant`). The GC
-- and the packer's claim use SKIP LOCKED, so they never wait at all. What
-- remains is DDL (migrations), whose table locks a running cluster can
-- deadlock with; the retry covers that.

-- B(b), shared: returns the bucket's versioning state, or NULL if there's no
-- such bucket (I2, I3).
CREATE OR REPLACE FUNCTION pg_temp.cairn_lock_bucket(p_bucket text)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    result text;
BEGIN
    SELECT versioning INTO result FROM buckets WHERE name = p_bucket FOR KEY SHARE;
    RETURN result;
END
$$;

-- U(u), shared: whether the upload exists (I4).
CREATE OR REPLACE FUNCTION pg_temp.cairn_lock_upload(p_upload uuid)
RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM multipart_uploads WHERE upload_id = p_upload FOR KEY SHARE;
    RETURN FOUND;
END
$$;

-- P(u,n) (I4).
CREATE OR REPLACE FUNCTION pg_temp.cairn_lock_part_number(p_upload uuid, p_part_number int)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext(p_upload::text), p_part_number);
END
$$;

-- How many distinct keys a transaction locks one by one (S shared, K for
-- each); with more, it locks their stripes exclusively instead. Either way, a
-- transaction takes at most 16 advisory locks. Mirrored by
-- `e2e::locking::MAX_KEY_LOCKS`.
--
-- K(b,k), under S(b,s), for each of the keys (I1): the stripes in order of
-- their numbers, then the keys in order of their lock ids. A stripe's lock id
-- is the hash of 'b/' seeded with the stripe's number plus one, and a key's
-- the hash of 'b/k' seeded with 0; keys are never empty, so the two never
-- name the same text.
CREATE OR REPLACE FUNCTION pg_temp.cairn_lock_keys(p_bucket text, p_keys text[])
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_few boolean;
    v_stripe int;
    v_id bigint;
BEGIN
    v_few := (SELECT count(DISTINCT k) FROM unnest(p_keys) AS k) <= 8;
    FOR v_stripe IN
        SELECT DISTINCT hashtext(k) & 15 AS stripe FROM unnest(p_keys) AS k ORDER BY stripe
    LOOP
        v_id := hashtextextended(p_bucket || '/', v_stripe + 1);
        IF v_few THEN
            PERFORM pg_advisory_xact_lock_shared(v_id);
        ELSE
            PERFORM pg_advisory_xact_lock(v_id);
        END IF;
    END LOOP;
    IF NOT v_few THEN
        RETURN;
    END IF;
    FOR v_id IN
        SELECT DISTINCT hashtextextended(p_bucket || '/' || k, 0) AS id
        FROM unnest(p_keys) AS k ORDER BY id
    LOOP
        PERFORM pg_advisory_xact_lock(v_id);
    END LOOP;
END
$$;

-- X(x) for each of the blobs that exist, in order of their ids, exclusively
-- where `p_exclusive` says so for any of its entries, else shared (I5, rule
-- A). Returns the blobs it locked; one deleted meanwhile isn't among them.
CREATE OR REPLACE FUNCTION pg_temp.cairn_lock_blobs(p_blobs uuid[], p_exclusive boolean[])
RETURNS uuid[] LANGUAGE plpgsql AS $$
DECLARE
    v_locked uuid[] := '{}';
    r record;
BEGIN
    IF NOT false = ANY(p_exclusive) THEN
        -- All exclusive: one statement, which locks the rows as they come out
        -- of the sort.
        SELECT coalesce(array_agg(s.blob_id), '{}') INTO v_locked FROM (
            SELECT blob_id FROM blobs WHERE blob_id = ANY(p_blobs) ORDER BY blob_id FOR UPDATE
        ) AS s;
        RETURN v_locked;
    END IF;
    FOR r IN
        SELECT t.blob_id, bool_or(t.exclusive) AS exclusive
        FROM unnest(p_blobs, p_exclusive) AS t(blob_id, exclusive)
        GROUP BY t.blob_id ORDER BY t.blob_id
    LOOP
        IF r.exclusive THEN
            PERFORM 1 FROM blobs WHERE blob_id = r.blob_id FOR UPDATE;
        ELSE
            PERFORM 1 FROM blobs WHERE blob_id = r.blob_id FOR KEY SHARE;
        END IF;
        IF FOUND THEN
            v_locked := v_locked || r.blob_id;
        END IF;
    END LOOP;
    RETURN v_locked;
END
$$;

-- What deleting these parts needs locked: each one's blob, exclusively if
-- the part may be all it holds (it's the blob's size), since the blob may
-- then have to be dropped; else shared. A packed blob whose last part is
-- deleted is dropped by the packer instead (see `cairn_fold_garbage`), so
-- deletes of different parts in a packed blob don't wait for each other.
-- A blob's size doesn't change once it's committed, and parts only reference
-- committed blobs.
CREATE OR REPLACE FUNCTION pg_temp.cairn_freeable(
    p_parts bigint[], OUT blobs uuid[], OUT exclusive boolean[]
) LANGUAGE plpgsql AS $$
BEGIN
    SELECT coalesce(array_agg(p.blob_id), '{}'), coalesce(array_agg(b.size = p.size), '{}')
    INTO blobs, exclusive
    FROM parts p JOIN blobs b ON b.blob_id = p.blob_id
    WHERE p.id = ANY(p_parts);
END
$$;

-- The blobs of `p_blobs` that `p_exclusive` marks: the ones to try dropping.
CREATE OR REPLACE FUNCTION pg_temp.cairn_exclusive(p_blobs uuid[], p_exclusive boolean[])
RETURNS uuid[] LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
    RETURN ARRAY(SELECT t.blob_id FROM unnest(p_blobs, p_exclusive) AS t(blob_id, exclusive)
                 WHERE t.exclusive);
END
$$;

-- Rule C: raises a serialization failure, for the caller to retry, unless
-- all of the parts are on blobs in `p_locked` (the packer may have moved one
-- between reading it and locking its blob).
CREATE OR REPLACE FUNCTION pg_temp.cairn_check_on(p_parts bigint[], p_locked uuid[])
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM parts WHERE id = ANY(p_parts) AND NOT blob_id = ANY(p_locked)) THEN
        RAISE EXCEPTION 'cairn: a part moved to another blob while its blob was being locked'
            USING ERRCODE = 'serialization_failure';
    END IF;
END
$$;

-- The row id of the object a plain GET of the key would return (NULL if
-- there's none), which a conditional write was decided against (by Cairn:
-- see `s3::versions::current_object`). Under K(b,k).
CREATE OR REPLACE FUNCTION pg_temp.cairn_current_version(p_bucket text, p_key text)
RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE
    result bigint;
BEGIN
    SELECT id INTO result FROM objects
    WHERE bucket = p_bucket AND key = p_key AND is_latest AND NOT is_delete_marker;
    RETURN result;
END
$$;

-- How many of the shards that the writer sent to `p_nodes` (shard
-- `p_shards[i]` to node `p_nodes[i]`) have their location recorded, if the
-- blob is still pending; 0 if it isn't (it's gone: deleted by the GC as
-- stale, say). Under X(x) exclusive.
CREATE OR REPLACE FUNCTION pg_temp.cairn_locations_present(p_blob uuid, p_nodes int[], p_shards smallint[])
RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE
    result bigint;
BEGIN
    PERFORM 1 FROM blobs WHERE blob_id = p_blob AND state = 'pending';
    IF NOT FOUND THEN
        RETURN 0;
    END IF;
    SELECT count(*) INTO result
    FROM blob_locations bl JOIN unnest(p_nodes, p_shards) AS w(node, shard)
        ON w.node = bl.node AND w.shard = bl.shard
    WHERE bl.blob_id = p_blob;
    RETURN result;
END
$$;

-- Marks a blob committed, recording its layout and the CRC64/NVME of each
-- shard's file (see `Written`). The caller holds X(x) exclusive and has
-- checked its locations.
CREATE OR REPLACE FUNCTION pg_temp.cairn_mark_committed(
    p_blob uuid, p_size bigint, p_block_size int, p_data_shards smallint,
    p_parity_shards smallint, p_stripe_unit int, p_shard_crcs bigint[]
) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    UPDATE blobs SET state = 'committed', size = p_size, block_size = p_block_size,
                     data_shards = p_data_shards, parity_shards = p_parity_shards,
                     stripe_unit = p_stripe_unit, shard_crcs = p_shard_crcs
    WHERE blob_id = p_blob;
END
$$;

-- Deletes those of the blobs that no part references anymore (typically the
-- blobs of parts just deleted or moved in the same transaction), cascading
-- their locations away; returns those locations. The caller holds X(x)
-- exclusive on all of them (I5), so this sees every part that a holder of a
-- shared lock attached (F1), and no one can attach one now.
CREATE OR REPLACE FUNCTION pg_temp.cairn_drop_unreferenced_blobs(
    p_blobs uuid[],
    OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
BEGIN
    -- All parts of a statement see the same snapshot, so the outer SELECT
    -- still sees the locations that the DELETE cascades away.
    WITH gone AS (
        DELETE FROM blobs b
        WHERE b.blob_id = ANY(p_blobs)
          AND NOT EXISTS (SELECT 1 FROM parts p WHERE p.blob_id = b.blob_id)
        RETURNING b.blob_id
    )
    SELECT coalesce(array_agg(bl.blob_id), '{}'), coalesce(array_agg(bl.node), '{}'),
           coalesce(array_agg(n.peer_url), '{}')
    INTO reap_blob, reap_node, reap_peer
    FROM gone
    JOIN blob_locations bl ON bl.blob_id = gone.blob_id
    JOIN nodes n ON n.id = bl.node;
END
$$;

-- Sets the blobs' `dead_size` to exactly the bytes that no part references:
-- the size, less the union of the parts' byte ranges (parts can share bytes,
-- through copies). Under X(x) exclusive.
CREATE OR REPLACE FUNCTION pg_temp.cairn_refresh_dead_size(p_blobs uuid[])
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    UPDATE blobs b SET dead_size = b.size - coalesce(live.bytes, 0)
    FROM (SELECT DISTINCT unnest(p_blobs) AS blob_id) AS t
    LEFT JOIN (
        SELECT blob_id, sum(upper(r) - lower(r))::bigint AS bytes
        FROM (
            SELECT blob_id, unnest(range_agg(int8range(blob_offset, blob_offset + size))) AS r
            FROM parts WHERE blob_id = ANY(p_blobs)
            GROUP BY blob_id
        ) AS ranges
        GROUP BY blob_id
    ) AS live ON live.blob_id = t.blob_id
    WHERE b.blob_id = t.blob_id;
END
$$;

-- The parts of the object version with row id `p_id`.
CREATE OR REPLACE FUNCTION pg_temp.cairn_version_parts(p_id bigint)
RETURNS bigint[] LANGUAGE plpgsql AS $$
BEGIN
    RETURN ARRAY(SELECT id FROM parts WHERE object_id = p_id);
END
$$;

-- The parts that writing a new version of the key would remove: those of its
-- null version, unless the bucket is versioned (see `cairn_put_version`).
-- Under K(b,k), so they stay the key's.
CREATE OR REPLACE FUNCTION pg_temp.cairn_freed_by_put(p_bucket text, p_key text, p_versioning text)
RETURNS bigint[] LANGUAGE plpgsql AS $$
BEGIN
    IF p_versioning = 'enabled' THEN
        RETURN '{}';
    END IF;
    RETURN ARRAY(
        SELECT p.id FROM objects o JOIN parts p ON p.object_id = o.id
        WHERE o.bucket = p_bucket AND o.key = p_key AND o.version_id = 'null'
    );
END
$$;

-- The parts that deleting the key (or the named version of it) may remove
-- (see `cairn_delete_key`). Under K(b,k).
CREATE OR REPLACE FUNCTION pg_temp.cairn_freed_by_delete(
    p_bucket text, p_key text, p_versioning text, p_version_id text
) RETURNS bigint[] LANGUAGE plpgsql AS $$
BEGIN
    IF p_version_id IS NOT NULL THEN
        RETURN ARRAY(
            SELECT p.id FROM objects o JOIN parts p ON p.object_id = o.id
            WHERE o.bucket = p_bucket AND o.key = p_key AND o.version_id = p_version_id
        );
    END IF;
    RETURN pg_temp.cairn_freed_by_put(p_bucket, p_key, p_versioning);
END
$$;

-- Removes the version with row id `p_id` and its parts. Under K(b,k), and
-- X(x) on the parts' blobs.
CREATE OR REPLACE FUNCTION pg_temp.cairn_remove_version(p_id bigint)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM parts WHERE object_id = p_id;
    DELETE FROM objects WHERE id = p_id;
END
$$;

-- Removes the key's `null` version, if it has one. Under K(b,k), and X(x) on
-- its parts' blobs.
CREATE OR REPLACE FUNCTION pg_temp.cairn_remove_null_version(p_bucket text, p_key text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_id bigint;
BEGIN
    SELECT id INTO v_id FROM objects
    WHERE bucket = p_bucket AND key = p_key AND version_id = 'null';
    IF FOUND THEN
        PERFORM pg_temp.cairn_remove_version(v_id);
    END IF;
END
$$;

-- Clears the key's current-version flag, ahead of inserting a new current
-- version. Under K(b,k).
CREATE OR REPLACE FUNCTION pg_temp.cairn_demote_current(p_bucket text, p_key text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    UPDATE objects SET is_latest = false WHERE bucket = p_bucket AND key = p_key AND is_latest;
END
$$;

-- Makes the key's newest remaining version current, after the current one was
-- removed. Under K(b,k).
CREATE OR REPLACE FUNCTION pg_temp.cairn_promote_newest(p_bucket text, p_key text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    UPDATE objects SET is_latest = true
    WHERE id = (SELECT max(id) FROM objects WHERE bucket = p_bucket AND key = p_key);
END
$$;

-- Writes a new object version as the key's current version, the way S3 lands
-- a write in a bucket with the given versioning state, with its content type,
-- metadata (see `s3::metadata`) and encryption (see `s3::sse`): its SSE-C key
-- check, or its SSE-KMS (or SSE-S3, if `p_sse_s3`) key, data key, sealed
-- object key and context (NULLs for what it isn't), and its checksum (see
-- `s3::checksums`; NULLs for none). `p_size` is its plaintext's. `p_new_version_id` is
-- the fresh version ID to use if the bucket is versioned. Returns the new
-- row's id, and the version ID to report (NULL unless versioning is enabled).
-- The caller holds B(b) shared (which gave it the versioning state), K(b,k), and
-- X(x) on the blobs of the parts `cairn_freed_by_put` names.
CREATE OR REPLACE FUNCTION pg_temp.cairn_put_version(
    p_bucket text, p_key text, p_versioning text, p_size bigint, p_etag text,
    p_content_type text, p_metadata text, p_sse_c_key bytea, p_kms_key_id text,
    p_kms_data_key text, p_kms_sealed bytea, p_kms_context text, p_sse_s3 boolean,
    p_checksum_algorithm text, p_checksum_type text, p_checksum text, p_new_version_id text,
    OUT id bigint, OUT version_id text
) LANGUAGE plpgsql AS $$
DECLARE
    v_version_id text;
BEGIN
    IF p_versioning = 'enabled' THEN
        v_version_id := p_new_version_id;
    ELSE
        -- The null version is replaced wherever it sits among the key's versions.
        PERFORM pg_temp.cairn_remove_null_version(p_bucket, p_key);
        v_version_id := 'null';
    END IF;
    PERFORM pg_temp.cairn_demote_current(p_bucket, p_key);
    INSERT INTO objects (bucket, key, version_id, is_latest, is_delete_marker,
                         size, etag, content_type, metadata, sse_c_key, sse_kms_key_id,
                         sse_kms_data_key, sse_kms_sealed, sse_kms_context, sse_s3,
                         checksum_algorithm, checksum_type, checksum, last_modified)
    VALUES (p_bucket, p_key, v_version_id, true, false, p_size, p_etag, p_content_type,
            p_metadata, p_sse_c_key, p_kms_key_id, p_kms_data_key, p_kms_sealed,
            p_kms_context, p_sse_s3, p_checksum_algorithm, p_checksum_type, p_checksum, NOW())
    RETURNING objects.id INTO id;
    -- A write's version ID is reported only where it's a new one: S3 reports
    -- none for the null version (unversioned or suspended).
    version_id := CASE WHEN p_versioning = 'enabled' THEN v_version_id END;
END
$$;

-- Deletes the key the way S3 does in a bucket with the given versioning state:
-- a named version for good, else the null version (unversioned) or by
-- stacking a delete marker (versioned; it replaces the null version in a
-- suspended bucket). `p_marker_id` is the fresh version ID of a marker in an
-- enabled bucket. Returns the version ID to report, and whether it concerns a
-- delete marker. The caller holds B(b) shared, K(b,k), and X(x) on the blobs
-- of the parts `cairn_freed_by_delete` names.
CREATE OR REPLACE FUNCTION pg_temp.cairn_delete_key(
    p_bucket text, p_key text, p_versioning text, p_version_id text, p_marker_id text,
    OUT version_id text, OUT delete_marker boolean
) LANGUAGE plpgsql AS $$
DECLARE
    v_row record;
    v_marker text;
BEGIN
    delete_marker := false;
    IF p_version_id IS NOT NULL THEN
        SELECT o.id, o.is_latest, o.is_delete_marker INTO v_row FROM objects o
        WHERE o.bucket = p_bucket AND o.key = p_key AND o.version_id = p_version_id;
        IF FOUND THEN
            delete_marker := v_row.is_delete_marker;
            PERFORM pg_temp.cairn_remove_version(v_row.id);
            IF v_row.is_latest THEN
                PERFORM pg_temp.cairn_promote_newest(p_bucket, p_key);
            END IF;
        END IF;
        version_id := p_version_id;
        RETURN;
    END IF;
    IF p_versioning = 'unversioned' THEN
        PERFORM pg_temp.cairn_remove_null_version(p_bucket, p_key);
        version_id := NULL;
        RETURN;
    ELSIF p_versioning = 'enabled' THEN
        v_marker := p_marker_id;
    ELSE
        PERFORM pg_temp.cairn_remove_null_version(p_bucket, p_key);
        v_marker := 'null';
    END IF;
    PERFORM pg_temp.cairn_demote_current(p_bucket, p_key);
    INSERT INTO objects (bucket, key, version_id, is_latest, is_delete_marker,
                         size, etag, content_type, last_modified)
    VALUES (p_bucket, p_key, v_marker, true, true, 0, NULL, NULL, NOW());
    version_id := v_marker;
    delete_marker := true;
END
$$;

-- T1: commits an uploaded blob as a single-part object at (bucket, key).
-- Takes B(b) shared, K(b,k), then X: the blob exclusively, and the blobs of
-- the version it replaces. Checks that the bucket exists ('no_such_bucket'),
-- that a conditional write was decided against the version that's current
-- (`p_expected`, NULL for none; 'stale' otherwise, for the caller to decide
-- again) and that every shard's node
-- recorded its location ('missing_locations', with how many did), then
-- commits the blob, writes the version and attaches the part ('committed',
-- with the version's last-modified time in ISO 8601, as CopyObject reports
-- it).
-- The blob's shards went to `p_nodes` (shard `p_shards[i]` to node
-- `p_nodes[i]`), and its layout and shards' file CRCs are as
-- `cairn_mark_committed` takes them.
-- `p_size` is the blob's (and the part's); an encrypted part also has its
-- plaintext's size and its salt (NULL for a plain one), and an encrypted
-- object its encryption, as `cairn_put_version` takes it, as it does the
-- object's checksum.
CREATE OR REPLACE FUNCTION pg_temp.cairn_commit_object(
    p_blob uuid, p_nodes int[], p_shards smallint[], p_size bigint, p_block_size int,
    p_data_shards smallint, p_parity_shards smallint, p_stripe_unit int, p_shard_crcs bigint[],
    p_data_crc bigint, p_etag text, p_plain_size bigint, p_enc_salt bytea,
    p_bucket text, p_key text, p_content_type text, p_metadata text, p_sse_c_key bytea,
    p_kms_key_id text, p_kms_data_key text, p_kms_sealed bytea, p_kms_context text,
    p_sse_s3 boolean, p_checksum_algorithm text, p_checksum_type text, p_checksum text,
    p_conditional boolean, p_expected bigint, p_new_version_id text,
    OUT status text, OUT present bigint, OUT version_id text, OUT last_modified text,
    OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_versioning text;
    v_freed bigint[];
    f record;
    v_locked uuid[];
    v record;
BEGIN
    reap_blob := '{}';
    reap_node := '{}';
    reap_peer := '{}';
    v_versioning := pg_temp.cairn_lock_bucket(p_bucket);
    IF v_versioning IS NULL THEN
        status := 'no_such_bucket';
        RETURN;
    END IF;
    PERFORM pg_temp.cairn_lock_keys(p_bucket, ARRAY[p_key]);
    IF p_conditional
       AND pg_temp.cairn_current_version(p_bucket, p_key) IS DISTINCT FROM p_expected THEN
        status := 'stale';
        RETURN;
    END IF;
    v_freed := pg_temp.cairn_freed_by_put(p_bucket, p_key, v_versioning);
    SELECT * INTO f FROM pg_temp.cairn_freeable(v_freed);
    v_locked := pg_temp.cairn_lock_blobs(p_blob || f.blobs, true || f.exclusive);
    PERFORM pg_temp.cairn_check_on(v_freed, v_locked);
    present := pg_temp.cairn_locations_present(p_blob, p_nodes, p_shards);
    IF present <> cardinality(p_nodes) THEN
        status := 'missing_locations';
        RETURN;
    END IF;
    PERFORM pg_temp.cairn_mark_committed(p_blob, p_size, p_block_size, p_data_shards,
                                         p_parity_shards, p_stripe_unit, p_shard_crcs);
    SELECT * INTO v FROM pg_temp.cairn_put_version(
        p_bucket, p_key, v_versioning, coalesce(p_plain_size, p_size), p_etag, p_content_type,
        p_metadata, p_sse_c_key, p_kms_key_id, p_kms_data_key, p_kms_sealed, p_kms_context,
        p_sse_s3, p_checksum_algorithm, p_checksum_type, p_checksum, p_new_version_id);
    version_id := v.version_id;
    SELECT to_char(o.last_modified AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS".000Z"')
    INTO last_modified FROM objects o WHERE o.id = v.id;
    INSERT INTO parts (blob_id, blob_offset, size, etag, crc64nvme, object_id, upload_id,
                       part_number, plain_size, enc_salt, created_at)
    VALUES (p_blob, 0, p_size, p_etag, p_data_crc, v.id, NULL, 1, p_plain_size, p_enc_salt,
            NOW());
    SELECT * INTO reap_blob, reap_node, reap_peer
    FROM pg_temp.cairn_drop_unreferenced_blobs(pg_temp.cairn_exclusive(f.blobs, f.exclusive));
    status := 'committed';
END
$$;

-- T2: commits an uploaded blob as part `p_part_number` of a multipart upload,
-- displacing any part uploaded at that number before. Takes U(u) shared,
-- P(u,n), then X: the blob exclusively, and the displaced part's blob. Or
-- 'no_such_upload', or 'missing_locations'. Shards, layout, sizes and salt as for
-- `cairn_commit_object`; `p_checksum` is the part's (see `s3::checksums`).
CREATE OR REPLACE FUNCTION pg_temp.cairn_commit_upload_part(
    p_blob uuid, p_nodes int[], p_shards smallint[], p_size bigint, p_block_size int,
    p_data_shards smallint, p_parity_shards smallint, p_stripe_unit int, p_shard_crcs bigint[],
    p_data_crc bigint, p_etag text, p_plain_size bigint, p_enc_salt bytea,
    p_upload uuid, p_part_number int, p_checksum text,
    OUT status text, OUT present bigint,
    OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_displaced bigint[];
    f record;
    v_locked uuid[];
BEGIN
    reap_blob := '{}';
    reap_node := '{}';
    reap_peer := '{}';
    IF NOT pg_temp.cairn_lock_upload(p_upload) THEN
        status := 'no_such_upload';
        RETURN;
    END IF;
    PERFORM pg_temp.cairn_lock_part_number(p_upload, p_part_number);
    v_displaced := ARRAY(SELECT id FROM parts
                         WHERE upload_id = p_upload AND part_number = p_part_number);
    SELECT * INTO f FROM pg_temp.cairn_freeable(v_displaced);
    v_locked := pg_temp.cairn_lock_blobs(p_blob || f.blobs, true || f.exclusive);
    PERFORM pg_temp.cairn_check_on(v_displaced, v_locked);
    present := pg_temp.cairn_locations_present(p_blob, p_nodes, p_shards);
    IF present <> cardinality(p_nodes) THEN
        status := 'missing_locations';
        RETURN;
    END IF;
    PERFORM pg_temp.cairn_mark_committed(p_blob, p_size, p_block_size, p_data_shards,
                                         p_parity_shards, p_stripe_unit, p_shard_crcs);
    DELETE FROM parts WHERE id = ANY(v_displaced);
    INSERT INTO parts (blob_id, blob_offset, size, etag, crc64nvme, object_id, upload_id,
                       part_number, plain_size, enc_salt, checksum, created_at)
    VALUES (p_blob, 0, p_size, p_etag, p_data_crc, NULL, p_upload, p_part_number,
            p_plain_size, p_enc_salt, p_checksum, NOW());
    SELECT * INTO reap_blob, reap_node, reap_peer
    FROM pg_temp.cairn_drop_unreferenced_blobs(pg_temp.cairn_exclusive(f.blobs, f.exclusive));
    status := 'committed';
END
$$;

-- The blobs of the parts of a copy's source version, as read now: the ones
-- the copy is to lock (shared). Not locked themselves; `cairn_source_parts`
-- checks after locking.
CREATE OR REPLACE FUNCTION pg_temp.cairn_source_blobs(p_object bigint)
RETURNS uuid[] LANGUAGE plpgsql AS $$
BEGIN
    RETURN ARRAY(SELECT blob_id FROM parts WHERE object_id = p_object);
END
$$;

-- The current parts of a copy's source version, in order, if they're still
-- the ones (by id and size) the copy read; NULL arrays if not. A part's bytes
-- never change, so the same parts mean the same data. A deleted version
-- takes its parts with it, and every object has at least one, so a deleted
-- source shows here too. If they're the same parts, but one has moved off the
-- blobs in `p_locked` (the packer), this raises a serialization failure
-- (rule C).
CREATE OR REPLACE FUNCTION pg_temp.cairn_source_parts(
    p_object bigint, p_part_ids bigint[], p_part_sizes bigint[], p_locked uuid[],
    OUT blob_ids uuid[], OUT offsets bigint[], OUT sizes bigint[],
    OUT etags text[], OUT crcs bigint[], OUT plain_sizes bigint[], OUT salts bytea[],
    OUT checksums text[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_ids bigint[];
BEGIN
    SELECT coalesce(array_agg(p.id ORDER BY p.part_number), '{}'),
           coalesce(array_agg(p.blob_id ORDER BY p.part_number), '{}'),
           coalesce(array_agg(p.blob_offset ORDER BY p.part_number), '{}'),
           coalesce(array_agg(p.size ORDER BY p.part_number), '{}'),
           coalesce(array_agg(p.etag ORDER BY p.part_number), '{}'),
           coalesce(array_agg(p.crc64nvme ORDER BY p.part_number), '{}'),
           coalesce(array_agg(p.plain_size ORDER BY p.part_number), '{}'),
           coalesce(array_agg(p.enc_salt ORDER BY p.part_number), '{}'),
           coalesce(array_agg(p.checksum ORDER BY p.part_number), '{}')
    INTO v_ids, blob_ids, offsets, sizes, etags, crcs, plain_sizes, salts, checksums
    FROM parts p WHERE p.object_id = p_object;
    IF v_ids <> p_part_ids OR sizes <> p_part_sizes THEN
        blob_ids := NULL;
        offsets := NULL;
        sizes := NULL;
        etags := NULL;
        crcs := NULL;
        plain_sizes := NULL;
        salts := NULL;
        checksums := NULL;
        RETURN;
    END IF;
    PERFORM pg_temp.cairn_check_on(v_ids, p_locked);
END
$$;

-- T3: CopyObject's commit: a new version at (bucket, key) with parts on the
-- source version's bytes ('committed', with the new version's last-modified
-- time in ISO 8601, as CopyObject reports it), unless the source changed since the
-- copy read it ('source_changed') or the bucket is gone ('no_such_bucket').
-- Takes B(b) shared, K(b,k), then X: the source's blobs shared, and those of
-- the version it replaces. The copy's checksum is Cairn's to work out; its
-- parts keep the source's parts' checksums if `p_part_checksums` (they're in
-- the copy's algorithm, and open under its key).
CREATE OR REPLACE FUNCTION pg_temp.cairn_copy_object(
    p_source bigint, p_part_ids bigint[], p_part_sizes bigint[],
    p_bucket text, p_key text, p_size bigint, p_etag text, p_content_type text,
    p_metadata text, p_sse_c_key bytea, p_kms_key_id text, p_kms_data_key text,
    p_kms_sealed bytea, p_kms_context text, p_sse_s3 boolean, p_checksum_algorithm text,
    p_checksum_type text, p_checksum text, p_part_checksums boolean, p_new_version_id text,
    OUT status text, OUT version_id text, OUT last_modified text,
    OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_versioning text;
    v_sources uuid[];
    v_freed bigint[];
    f record;
    v_locked uuid[];
    s record;
    v record;
BEGIN
    reap_blob := '{}';
    reap_node := '{}';
    reap_peer := '{}';
    v_versioning := pg_temp.cairn_lock_bucket(p_bucket);
    IF v_versioning IS NULL THEN
        status := 'no_such_bucket';
        RETURN;
    END IF;
    PERFORM pg_temp.cairn_lock_keys(p_bucket, ARRAY[p_key]);
    v_sources := pg_temp.cairn_source_blobs(p_source);
    v_freed := pg_temp.cairn_freed_by_put(p_bucket, p_key, v_versioning);
    SELECT * INTO f FROM pg_temp.cairn_freeable(v_freed);
    v_locked := pg_temp.cairn_lock_blobs(
        v_sources || f.blobs, array_fill(false, ARRAY[cardinality(v_sources)]) || f.exclusive);
    PERFORM pg_temp.cairn_check_on(v_freed, v_locked);
    -- Read after the locks (F1), and before the new version is written: a
    -- copy onto its own source replaces the version whose bytes it shares.
    SELECT * INTO s FROM pg_temp.cairn_source_parts(p_source, p_part_ids, p_part_sizes, v_locked);
    IF s.blob_ids IS NULL THEN
        status := 'source_changed';
        RETURN;
    END IF;
    SELECT * INTO v FROM pg_temp.cairn_put_version(
        p_bucket, p_key, v_versioning, p_size, p_etag, p_content_type, p_metadata,
        p_sse_c_key, p_kms_key_id, p_kms_data_key, p_kms_sealed, p_kms_context,
        p_sse_s3, p_checksum_algorithm, p_checksum_type, p_checksum, p_new_version_id);
    version_id := v.version_id;
    SELECT to_char(o.last_modified AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS".000Z"')
    INTO last_modified FROM objects o WHERE o.id = v.id;
    INSERT INTO parts (blob_id, blob_offset, size, etag, crc64nvme, object_id, upload_id,
                       part_number, plain_size, enc_salt, checksum, created_at)
    SELECT t.blob_id, t.blob_offset, t.size, t.etag, t.crc, v.id, NULL, t.n, t.plain_size,
           t.salt, CASE WHEN p_part_checksums THEN t.checksum END, NOW()
    FROM unnest(s.blob_ids, s.offsets, s.sizes, s.etags, s.crcs, s.plain_sizes, s.salts,
                s.checksums)
        WITH ORDINALITY AS t(blob_id, blob_offset, size, etag, crc, plain_size, salt, checksum, n);
    -- After inserting the new parts, so that a self-copy keeps its bytes.
    SELECT * INTO reap_blob, reap_node, reap_peer
    FROM pg_temp.cairn_drop_unreferenced_blobs(pg_temp.cairn_exclusive(f.blobs, f.exclusive));
    status := 'committed';
END
$$;

-- T4: UploadPartCopy's commit: stages `p_length` bytes of source part
-- `p_index` (1-based), from `p_within` in it, as part `p_part_number` of the
-- upload, displacing any part uploaded at that number before ('committed').
-- Or 'no_such_upload', or 'source_changed'. Takes U(u) shared, P(u,n), then
-- X: the source's blobs shared, and the displaced part's blob. `p_checksum`
-- is the new part's (see `s3::checksums`).
CREATE OR REPLACE FUNCTION pg_temp.cairn_copy_part(
    p_source bigint, p_part_ids bigint[], p_part_sizes bigint[],
    p_index int, p_within bigint, p_length bigint, p_etag text, p_crc bigint,
    p_upload uuid, p_part_number int, p_checksum text,
    OUT status text,
    OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_sources uuid[];
    v_displaced bigint[];
    f record;
    v_locked uuid[];
    s record;
BEGIN
    reap_blob := '{}';
    reap_node := '{}';
    reap_peer := '{}';
    IF NOT pg_temp.cairn_lock_upload(p_upload) THEN
        status := 'no_such_upload';
        RETURN;
    END IF;
    PERFORM pg_temp.cairn_lock_part_number(p_upload, p_part_number);
    v_sources := pg_temp.cairn_source_blobs(p_source);
    v_displaced := ARRAY(SELECT id FROM parts
                         WHERE upload_id = p_upload AND part_number = p_part_number);
    SELECT * INTO f FROM pg_temp.cairn_freeable(v_displaced);
    v_locked := pg_temp.cairn_lock_blobs(
        v_sources || f.blobs, array_fill(false, ARRAY[cardinality(v_sources)]) || f.exclusive);
    PERFORM pg_temp.cairn_check_on(v_displaced, v_locked);
    -- Read after the locks (F1).
    SELECT * INTO s FROM pg_temp.cairn_source_parts(p_source, p_part_ids, p_part_sizes, v_locked);
    IF s.blob_ids IS NULL THEN
        status := 'source_changed';
        RETURN;
    END IF;
    -- A range of an encrypted part isn't a part (its bytes are ciphertext);
    -- such a copy streams instead.
    IF s.salts[p_index] IS NOT NULL THEN
        RAISE EXCEPTION 'cairn: a range of an encrypted part can''t be staged in place';
    END IF;
    DELETE FROM parts WHERE id = ANY(v_displaced);
    INSERT INTO parts (blob_id, blob_offset, size, etag, crc64nvme, object_id, upload_id,
                       part_number, checksum, created_at)
    VALUES (s.blob_ids[p_index], s.offsets[p_index] + p_within, p_length, p_etag, p_crc,
            NULL, p_upload, p_part_number, p_checksum, NOW());
    SELECT * INTO reap_blob, reap_node, reap_peer
    FROM pg_temp.cairn_drop_unreferenced_blobs(pg_temp.cairn_exclusive(f.blobs, f.exclusive));
    status := 'committed';
END
$$;

-- T5: CompleteMultipartUpload. Takes B(b) shared, U(u) exclusive, K(b,k),
-- then X: the blobs of the listed parts (shared), the left-out staged parts
-- and the replaced version's parts. Cairn has matched the listed parts
-- against the upload's (by their ETags, which only it can read: see
-- `s3::sse`), worked out the object's ETag (`p_etag`, as it's stored), and
-- decided a conditional completion against the version `p_expected`. This
-- checks that the upload exists and belongs to (bucket, key)
-- ('no_such_upload': Cairn tells a retry, whose upload this already
-- completed, from there), that the listed parts are still those staged at
-- their numbers, and the conditional's version still the current one
-- ('stale', for Cairn to decide again), that every part but the last is
-- large enough ('too_small') and they make an object S3 would store
-- ('too_large'). Then publishes the listed parts as the key's new version,
-- deletes the staged parts left out, and the upload ('done'). The object's
-- checksum, like its ETag, Cairn works out from the listed parts' (a part's
-- never changes: a part uploaded again is a new row).
CREATE OR REPLACE FUNCTION pg_temp.cairn_complete_upload(
    p_upload uuid, p_bucket text, p_key text, p_part_ids bigint[], p_part_numbers int[],
    p_etag text, p_checksum_algorithm text, p_checksum_type text, p_checksum text,
    p_conditional boolean, p_expected bigint, p_new_version_id text,
    OUT status text, OUT version_id text,
    OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_versioning text;
    u record;
    v_listed bigint[];
    v_listed_blobs uuid[];
    v_total bigint;
    v_unused bigint[];
    v_freed bigint[];
    f record;
    v_locked uuid[];
    v record;
BEGIN
    reap_blob := '{}';
    reap_node := '{}';
    reap_peer := '{}';
    -- An upload's bucket exists as long as the upload does.
    v_versioning := pg_temp.cairn_lock_bucket(p_bucket);
    -- The upload defines the object's content type, metadata and encryption.
    -- It must belong to the request's bucket and key: authorization only
    -- checked the bucket.
    SELECT * INTO u
    FROM multipart_uploads
    WHERE upload_id = p_upload AND bucket = p_bucket AND key = p_key
    FOR UPDATE;
    IF v_versioning IS NULL OR NOT FOUND THEN
        status := 'no_such_upload';
        RETURN;
    END IF;
    PERFORM pg_temp.cairn_lock_keys(p_bucket, ARRAY[p_key]);
    -- The listed parts, if they're still staged at their numbers (U(u) holds
    -- them there from now on).
    SELECT coalesce(array_agg(p.id ORDER BY r.n), '{}'),
           coalesce(array_agg(p.blob_id ORDER BY r.n), '{}'),
           sum(coalesce(p.plain_size, p.size))
    INTO v_listed, v_listed_blobs, v_total
    FROM unnest(p_part_ids, p_part_numbers) WITH ORDINALITY AS r(id, part_number, n)
    JOIN parts p ON p.id = r.id AND p.upload_id = p_upload AND p.part_number = r.part_number;
    IF cardinality(v_listed) <> cardinality(p_part_ids) THEN
        status := 'stale';
        RETURN;
    END IF;
    IF p_conditional
       AND pg_temp.cairn_current_version(p_bucket, p_key) IS DISTINCT FROM p_expected THEN
        status := 'stale';
        RETURN;
    END IF;
    -- S3's smallest part, 5 MiB, but for the last (`s3::util::MIN_PART`).
    IF EXISTS (SELECT 1 FROM unnest(p_part_ids) WITH ORDINALITY AS r(id, n)
               JOIN parts p ON p.id = r.id
               WHERE r.n < cardinality(p_part_ids)
                 AND coalesce(p.plain_size, p.size) < 5242880) THEN
        status := 'too_small';
        RETURN;
    END IF;
    -- S3's largest object, 5 TiB (`s3::util::MAX_OBJECT`).
    IF v_total > 5497558138880 THEN
        status := 'too_large';
        RETURN;
    END IF;
    v_unused := ARRAY(SELECT id FROM parts WHERE upload_id = p_upload AND NOT id = ANY(v_listed));
    v_freed := pg_temp.cairn_freed_by_put(p_bucket, p_key, v_versioning);
    SELECT * INTO f FROM pg_temp.cairn_freeable(v_unused || v_freed);
    v_locked := pg_temp.cairn_lock_blobs(
        v_listed_blobs || f.blobs,
        array_fill(false, ARRAY[cardinality(v_listed_blobs)]) || f.exclusive);
    PERFORM pg_temp.cairn_check_on(v_listed || v_unused || v_freed, v_locked);
    SELECT * INTO v FROM pg_temp.cairn_put_version(
        p_bucket, p_key, v_versioning, v_total, p_etag, u.content_type, u.metadata,
        u.sse_c_key, u.sse_kms_key_id, u.sse_kms_data_key, u.sse_kms_sealed, u.sse_kms_context,
        u.sse_s3, p_checksum_algorithm, p_checksum_type, p_checksum, p_new_version_id);
    version_id := v.version_id;
    UPDATE objects SET upload_id = p_upload WHERE id = v.id;
    UPDATE parts SET upload_id = NULL, object_id = v.id WHERE id = ANY(v_listed);
    DELETE FROM parts WHERE id = ANY(v_unused);
    SELECT * INTO reap_blob, reap_node, reap_peer
    FROM pg_temp.cairn_drop_unreferenced_blobs(pg_temp.cairn_exclusive(f.blobs, f.exclusive));
    DELETE FROM multipart_uploads WHERE upload_id = p_upload;
    status := 'done';
END
$$;

-- T6: AbortMultipartUpload. Takes U(u) exclusive, then X on the staged parts'
-- blobs. Deletes the upload (if it belongs to bucket and key), its staged
-- parts, and their blobs. `existed` is whether there was one.
CREATE OR REPLACE FUNCTION pg_temp.cairn_abort_upload(
    p_upload uuid, p_bucket text, p_key text,
    OUT existed boolean,
    OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_staged bigint[];
    f record;
    v_locked uuid[];
BEGIN
    reap_blob := '{}';
    reap_node := '{}';
    reap_peer := '{}';
    PERFORM 1 FROM multipart_uploads
    WHERE upload_id = p_upload AND bucket = p_bucket AND key = p_key
    FOR UPDATE;
    existed := FOUND;
    IF NOT existed THEN
        RETURN;
    END IF;
    v_staged := ARRAY(SELECT id FROM parts WHERE upload_id = p_upload);
    SELECT * INTO f FROM pg_temp.cairn_freeable(v_staged);
    v_locked := pg_temp.cairn_lock_blobs(f.blobs, f.exclusive);
    PERFORM pg_temp.cairn_check_on(v_staged, v_locked);
    DELETE FROM parts WHERE id = ANY(v_staged);
    DELETE FROM multipart_uploads WHERE upload_id = p_upload;
    SELECT * INTO reap_blob, reap_node, reap_peer
    FROM pg_temp.cairn_drop_unreferenced_blobs(pg_temp.cairn_exclusive(f.blobs, f.exclusive));
END
$$;

-- T8: DeleteObject(s). Takes B(b) shared and K(b,k) for every key, then X on
-- the blobs of every part the deletes may remove. Deletes each target (a key,
-- and a version ID or NULL) the way the bucket's versioning state dictates
-- ('deleted', with each one's version ID to report and whether it concerns a
-- delete marker), or reports 'no_such_bucket'. `p_marker_ids` holds a fresh
-- version ID per target, for a delete marker in an enabled bucket.
CREATE OR REPLACE FUNCTION pg_temp.cairn_delete_objects(
    p_bucket text, p_keys text[], p_version_ids text[], p_marker_ids text[],
    OUT status text, OUT version_ids text[], OUT delete_markers boolean[],
    OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_versioning text;
    v_freed bigint[] := '{}';
    f record;
    v_locked uuid[];
    d record;
BEGIN
    reap_blob := '{}';
    reap_node := '{}';
    reap_peer := '{}';
    version_ids := '{}';
    delete_markers := '{}';
    v_versioning := pg_temp.cairn_lock_bucket(p_bucket);
    IF v_versioning IS NULL THEN
        status := 'no_such_bucket';
        RETURN;
    END IF;
    PERFORM pg_temp.cairn_lock_keys(p_bucket, p_keys);
    -- Every version the targets name or may remove exists now, under the
    -- keys' locks; the deletes only add delete markers, which have no parts.
    FOR i IN 1 .. coalesce(cardinality(p_keys), 0) LOOP
        v_freed := v_freed || pg_temp.cairn_freed_by_delete(
            p_bucket, p_keys[i], v_versioning, p_version_ids[i]);
    END LOOP;
    SELECT * INTO f FROM pg_temp.cairn_freeable(v_freed);
    v_locked := pg_temp.cairn_lock_blobs(f.blobs, f.exclusive);
    PERFORM pg_temp.cairn_check_on(v_freed, v_locked);
    FOR i IN 1 .. coalesce(cardinality(p_keys), 0) LOOP
        SELECT * INTO d FROM pg_temp.cairn_delete_key(
            p_bucket, p_keys[i], v_versioning, p_version_ids[i], p_marker_ids[i]);
        version_ids := version_ids || d.version_id;
        delete_markers := delete_markers || d.delete_marker;
    END LOOP;
    SELECT * INTO reap_blob, reap_node, reap_peer
    FROM pg_temp.cairn_drop_unreferenced_blobs(pg_temp.cairn_exclusive(f.blobs, f.exclusive));
    status := 'deleted';
END
$$;

-- T9: DeleteBucket. Takes B(b) exclusive, then U(u) exclusive on each of the
-- bucket's uploads (in order of their ids), G on its grants, and X on the
-- uploads' staged parts' blobs. Only a bucket without objects is deleted, as
-- S3 deletes one; its incomplete uploads are aborted with it, as S3 aborts
-- them, and their parts and blobs deleted here, not by the cascades, which
-- must never delete data (I3). Returns 'deleted', 'no_such_bucket' or
-- 'not_empty'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_delete_bucket(
    p_bucket text,
    OUT status text,
    OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_uploads uuid[];
    v_staged bigint[];
    f record;
    v_locked uuid[];
BEGIN
    reap_blob := '{}';
    reap_node := '{}';
    reap_peer := '{}';
    PERFORM 1 FROM buckets WHERE name = p_bucket FOR UPDATE;
    IF NOT FOUND THEN
        status := 'no_such_bucket';
        RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM objects WHERE bucket = p_bucket) THEN
        status := 'not_empty';
        RETURN;
    END IF;
    -- No upload can be created in the bucket now (its insert's FK check
    -- conflicts with B), and none attaches a part once its U is held.
    v_uploads := ARRAY(SELECT s.upload_id FROM (
        SELECT upload_id FROM multipart_uploads WHERE bucket = p_bucket
        ORDER BY upload_id FOR UPDATE
    ) AS s);
    -- The grants go with the bucket (a cascade); locked first, in order.
    PERFORM 1 FROM role_grants WHERE bucket = p_bucket
    ORDER BY role, bucket, permission FOR UPDATE;
    v_staged := ARRAY(SELECT id FROM parts WHERE upload_id = ANY(v_uploads));
    SELECT * INTO f FROM pg_temp.cairn_freeable(v_staged);
    v_locked := pg_temp.cairn_lock_blobs(f.blobs, f.exclusive);
    PERFORM pg_temp.cairn_check_on(v_staged, v_locked);
    DELETE FROM parts WHERE id = ANY(v_staged);
    DELETE FROM multipart_uploads WHERE upload_id = ANY(v_uploads);
    DELETE FROM buckets WHERE name = p_bucket;
    SELECT * INTO reap_blob, reap_node, reap_peer
    FROM pg_temp.cairn_drop_unreferenced_blobs(pg_temp.cairn_exclusive(f.blobs, f.exclusive));
    status := 'deleted';
END
$$;

-- T10: PutBucketVersioning. Takes B(b) exclusive, so that the change is
-- ordered against every write and delete in the bucket (I2). Returns whether
-- the bucket exists.
CREATE OR REPLACE FUNCTION pg_temp.cairn_set_versioning(p_bucket text, p_versioning text)
RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM buckets WHERE name = p_bucket FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    UPDATE buckets SET versioning = p_versioning WHERE name = p_bucket;
    RETURN true;
END
$$;

-- T16: PutBucketEncryption and DeleteBucketEncryption: sets (or, with NULLs,
-- removes) the bucket's default encryption. A plain UPDATE of the bucket's
-- row, which conflicts with B(b) exclusive (waiting for a change of
-- versioning, or a deletion), but not shared: no invariant involves the
-- default, which a write reads as it begins, not under B, and keeps for
-- good. Returns whether the bucket exists.
CREATE OR REPLACE FUNCTION pg_temp.cairn_set_encryption(
    p_bucket text, p_algorithm text, p_kms_key_id text, p_bucket_key boolean
) RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
    UPDATE buckets SET sse_algorithm = p_algorithm, sse_kms_key_id = p_kms_key_id,
                       sse_bucket_key = p_bucket_key
    WHERE name = p_bucket;
    RETURN FOUND;
END
$$;

-- T17: a lifecycle sweep's expirations (see `lifecycle`). Takes B(b) shared
-- and K(b,k) for every key, then X on the blobs of every part they may
-- remove, as DeleteObjects does (T8). Each target is a version the sweep found
-- due, by its row id, with what made it due, which is checked again under the
-- locks, before anything changes, so that a version written or deleted since
-- isn't mistaken for it:
--
--   'current'     still the key's current version, and not a delete marker;
--                 deleted as a DeleteObject without a version ID would (a
--                 delete marker in a versioned bucket). `p_marker_ids` holds
--                 a fresh version ID for that marker.
--   'marker'      still the key's current version, a delete marker, and its
--                 only one; removed for good.
--   'noncurrent'  not the current version, the version after it still
--                 `p_successors` (which made it noncurrent when it did), and
--                 at least `p_newer` versions newer than it; removed for good.
--
-- `p_generation` is the generation of the configuration the sweep follows:
-- if the bucket's is another (it was changed or deleted since), nothing is
-- done
-- ('changed'). Returns 'expired', with which targets were, or
-- 'no_such_bucket'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_lifecycle_expire(
    p_bucket text, p_generation bigint, p_keys text[], p_ids bigint[], p_version_ids text[],
    p_kinds text[], p_successors bigint[], p_newer int[], p_marker_ids text[],
    OUT status text, OUT applied boolean[],
    OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_versioning text;
    v_ok boolean;
    v_freed bigint[] := '{}';
    f record;
    v_locked uuid[];
BEGIN
    reap_blob := '{}';
    reap_node := '{}';
    reap_peer := '{}';
    applied := '{}';
    v_versioning := pg_temp.cairn_lock_bucket(p_bucket);
    IF v_versioning IS NULL THEN
        status := 'no_such_bucket';
        RETURN;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM buckets
        WHERE name = p_bucket AND lifecycle IS NOT NULL AND lifecycle_generation = p_generation
    ) THEN
        status := 'changed';
        RETURN;
    END IF;
    PERFORM pg_temp.cairn_lock_keys(p_bucket, p_keys);
    -- Every check before any change, so that one target's expiration can't
    -- make another's look undue (removing the version after it, say).
    FOR i IN 1 .. coalesce(cardinality(p_keys), 0) LOOP
        IF p_kinds[i] = 'current' THEN
            v_ok := pg_temp.cairn_current_version(p_bucket, p_keys[i]) IS NOT DISTINCT FROM p_ids[i];
        ELSIF p_kinds[i] = 'marker' THEN
            v_ok := EXISTS (
                SELECT 1 FROM objects
                WHERE id = p_ids[i] AND bucket = p_bucket AND key = p_keys[i]
                  AND is_latest AND is_delete_marker
            ) AND NOT EXISTS (
                SELECT 1 FROM objects
                WHERE bucket = p_bucket AND key = p_keys[i] AND id <> p_ids[i]
            );
        ELSIF p_kinds[i] = 'noncurrent' THEN
            v_ok := EXISTS (
                SELECT 1 FROM objects
                WHERE id = p_ids[i] AND bucket = p_bucket AND key = p_keys[i] AND NOT is_latest
            ) AND (
                SELECT min(id) FROM objects
                WHERE bucket = p_bucket AND key = p_keys[i] AND id > p_ids[i]
            ) IS NOT DISTINCT FROM p_successors[i] AND (
                SELECT count(*) FROM objects
                WHERE bucket = p_bucket AND key = p_keys[i] AND id > p_ids[i]
            ) >= p_newer[i];
        ELSE
            RAISE EXCEPTION 'cairn_lifecycle_expire: unknown kind %', p_kinds[i];
        END IF;
        applied := applied || v_ok;
    END LOOP;
    FOR i IN 1 .. coalesce(cardinality(p_keys), 0) LOOP
        CONTINUE WHEN NOT applied[i];
        v_freed := v_freed || pg_temp.cairn_freed_by_delete(
            p_bucket, p_keys[i], v_versioning,
            CASE WHEN p_kinds[i] = 'current' THEN NULL ELSE p_version_ids[i] END);
    END LOOP;
    SELECT * INTO f FROM pg_temp.cairn_freeable(v_freed);
    v_locked := pg_temp.cairn_lock_blobs(f.blobs, f.exclusive);
    PERFORM pg_temp.cairn_check_on(v_freed, v_locked);
    FOR i IN 1 .. coalesce(cardinality(p_keys), 0) LOOP
        CONTINUE WHEN NOT applied[i];
        IF p_kinds[i] = 'current' THEN
            PERFORM pg_temp.cairn_delete_key(p_bucket, p_keys[i], v_versioning, NULL, p_marker_ids[i]);
        ELSE
            PERFORM pg_temp.cairn_delete_key(p_bucket, p_keys[i], v_versioning, p_version_ids[i], NULL);
        END IF;
    END LOOP;
    SELECT * INTO reap_blob, reap_node, reap_peer
    FROM pg_temp.cairn_drop_unreferenced_blobs(pg_temp.cairn_exclusive(f.blobs, f.exclusive));
    status := 'expired';
END
$$;

-- Claims the cluster's next lifecycle step (see `lifecycle`), if no node
-- holds it (its lease has run out, if one did), and the last one began at
-- least `p_gap` seconds before `p_now`: then takes a lease of `p_lease`
-- seconds, and records the step as beginning at `p_now`. Returns whether it
-- claimed it, and when the last step began. The single row, locked with SKIP
-- LOCKED, so that it never waits: another node claiming it at the same time
-- gets nothing.
CREATE OR REPLACE FUNCTION pg_temp.cairn_lifecycle_claim(
    p_now timestamptz, p_lease double precision, p_gap double precision,
    OUT claimed boolean, OUT previous timestamptz
) LANGUAGE plpgsql AS $$
BEGIN
    SELECT last_step INTO previous FROM lifecycle_runs
    WHERE id AND (lease_until IS NULL OR lease_until <= p_now)
      AND (last_step IS NULL OR last_step <= p_now - make_interval(secs => p_gap))
    FOR UPDATE SKIP LOCKED;
    claimed := FOUND;
    IF claimed THEN
        UPDATE lifecycle_runs SET lease_until = p_now + make_interval(secs => p_lease), last_step = p_now
        WHERE id;
    END IF;
END
$$;

-- T18: PutBucketLifecycleConfiguration and DeleteBucketLifecycle: sets (or,
-- with NULL, removes) the bucket's lifecycle configuration, with a new
-- generation, and starts a new sweep of it, due now (the last whole sweep
-- stays, for the dashboard), or drops its sweep. Plain UPDATEs of the
-- bucket's row, as T16's: no invariant involves the configuration, which a
-- sweep checks itself (T17). The sweep's row's FK check locks the bucket's
-- row shared, which it updated already. Returns whether the bucket exists.
CREATE OR REPLACE FUNCTION pg_temp.cairn_set_lifecycle(p_bucket text, p_config text)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    v_generation bigint;
BEGIN
    UPDATE buckets SET lifecycle = p_config, lifecycle_generation = lifecycle_generation + 1
    WHERE name = p_bucket
    RETURNING lifecycle_generation INTO v_generation;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    IF p_config IS NULL THEN
        DELETE FROM lifecycle_sweeps WHERE bucket = p_bucket;
    ELSE
        INSERT INTO lifecycle_sweeps (bucket, generation, due) VALUES (p_bucket, v_generation, now())
        ON CONFLICT (bucket) DO UPDATE SET generation = v_generation, due = now(), started = NULL,
            cursor = NULL, seen = 0, expired = 0, removed = 0, aborted = 0;
    END IF;
    RETURN true;
END
$$;

-- Deletes a role. Takes G on the role's grants (in order), which go with it
-- (a cascade), then R (by deleting the row). Returns whether there was one.
CREATE OR REPLACE FUNCTION pg_temp.cairn_delete_role(p_role text)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    v_deleted bigint;
BEGIN
    PERFORM 1 FROM role_grants WHERE role = p_role
    ORDER BY role, bucket, permission FOR UPDATE;
    DELETE FROM roles WHERE name = p_role;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted > 0;
END
$$;

-- Revokes a role's permissions on a bucket. Takes G on those grants (in
-- order).
CREATE OR REPLACE FUNCTION pg_temp.cairn_revoke(p_role text, p_bucket text, p_permissions text[])
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM role_grants
    WHERE role = p_role AND bucket = p_bucket AND permission = ANY(p_permissions)
    ORDER BY role, bucket, permission FOR UPDATE;
    DELETE FROM role_grants
    WHERE role = p_role AND bucket = p_bucket AND permission = ANY(p_permissions);
END
$$;

-- Grants a role permissions on a bucket. Takes B(b) shared, then R(r) shared,
-- which the inserts' FK checks would otherwise take the other way round.
-- Returns 'granted', 'no_such_role' or 'no_such_bucket'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_grant(p_role text, p_bucket text, p_permissions text[])
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    v_bucket boolean;
BEGIN
    PERFORM 1 FROM buckets WHERE name = p_bucket FOR KEY SHARE;
    v_bucket := FOUND;
    PERFORM 1 FROM roles WHERE name = p_role FOR KEY SHARE;
    -- A missing role is reported first.
    IF NOT FOUND THEN
        RETURN 'no_such_role';
    ELSIF NOT v_bucket THEN
        RETURN 'no_such_bucket';
    END IF;
    INSERT INTO role_grants (role, bucket, permission)
    SELECT p_role, p_bucket, p FROM unnest(p_permissions) AS p
    ON CONFLICT DO NOTHING;
    RETURN 'granted';
END
$$;

-- T13: takes up to `p_limit` rows of the garbage log: drops the logged blobs
-- that no part references anymore, and refreshes the `dead_size` of the rest
-- (see `packer::fold_garbage`). Takes X exclusive on the logged blobs. `more`
-- is whether there may be more rows to take. In batches, so that a large log
-- (after deleting many objects) doesn't make for one huge transaction that
-- holds the locks of all its blobs; a blob logged in several batches is just
-- looked at several times. Folds run one at a time (I6): if another one is
-- running, this returns right away, leaving the log to it.
CREATE OR REPLACE FUNCTION pg_temp.cairn_fold_garbage(
    p_limit int,
    OUT more boolean, OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_logged uuid[];
    v_taken bigint;
BEGIN
    more := false;
    reap_blob := '{}';
    reap_node := '{}';
    reap_peer := '{}';
    -- `db::FOLD_LOCK`, which a test checks against this.
    IF NOT pg_try_advisory_xact_lock(109270032084481) THEN
        RETURN;
    END IF;
    -- Only folds delete log rows, and they run one at a time, so the rows
    -- picked stay where they are until they're deleted.
    WITH taken AS (
        DELETE FROM blob_garbage
        WHERE ctid IN (SELECT ctid FROM blob_garbage LIMIT p_limit)
        RETURNING blob_id
    )
    SELECT coalesce(array_agg(DISTINCT blob_id), '{}'), count(*) INTO v_logged, v_taken FROM taken;
    more := v_taken >= p_limit;
    PERFORM pg_temp.cairn_lock_blobs(v_logged, array_fill(true, ARRAY[cardinality(v_logged)]));
    SELECT * INTO reap_blob, reap_node, reap_peer
    FROM pg_temp.cairn_drop_unreferenced_blobs(v_logged);
    -- The log's sizes would count bytes that another part still shares as
    -- garbage, so the blobs' garbage is worked out afresh.
    PERFORM pg_temp.cairn_refresh_dead_size(v_logged);
END
$$;

-- T14: claims the source blobs for a packing job, if there's one worth
-- running (see `packer::claim`): `p_kind` is 'compact', 'consolidate',
-- 'upgrade' (a blob from before checksums, one at a time) or 'convert'
-- (replicated blobs of more than `p_small_size` live bytes, older than
-- `p_cold_secs`, to be coded).
-- Takes candidates, skipping those another transaction has locked (it never
-- waits), until their live bytes would exceed `p_budget`, and leases them.
-- Returns them, or an empty array if the job isn't worth it. The lease is a
-- heuristic (I8).
--
-- Every node claims every minute, so a claim must be cheap when there's
-- nothing to do. Compaction reads its candidates off the `blobs_compactable`
-- index, least live data first, and stops once it has enough; consolidation
-- first adds its candidates up without locking them, and only locks them once
-- they're worth a job, since a row lock is a write.
--
-- Blobs with parts on lost data (`lost_ranges`, see `scrub`) aren't
-- candidates: those parts would fail the job's verification, again after every
-- lease. Lost data that no part uses anymore doesn't keep a blob from being
-- compacted, which then drops it, and its lost ranges with it. Which blobs
-- have lost data is a heuristic too: one that loses data after it's claimed
-- just fails its job.
CREATE OR REPLACE FUNCTION pg_temp.cairn_claim(
    p_kind text, p_compact_threshold float8, p_max_sources bigint, p_small_size bigint,
    p_target_size bigint, p_budget bigint, p_lease_secs float8, p_cold_secs float8
) RETURNS uuid[] LANGUAGE plpgsql AS $$
DECLARE
    v_sources uuid[] := '{}';
    v_total bigint := 0;
    v_count bigint;
    r record;
BEGIN
    IF p_kind = 'compact' AND p_compact_threshold >= 0.25 THEN
        -- Least live data first: that's the cheapest space to free. The
        -- threshold of `blobs_compactable` (`packer::COMPACT_THRESHOLD`, which
        -- a test checks against this) is repeated as a literal, so that the
        -- planner can use the partial index.
        FOR r IN
            SELECT blob_id, size - dead_size AS live FROM blobs
            WHERE state = 'committed' AND dead_size > 0 AND dead_size >= size * 0.25
              AND dead_size >= size * p_compact_threshold
              AND (pack_lease_until IS NULL OR pack_lease_until < NOW())
              AND NOT EXISTS (SELECT 1 FROM lost_ranges l JOIN parts p ON p.blob_id = l.blob_id
                              WHERE l.blob_id = blobs.blob_id
                                AND p.blob_offset < l.stop AND p.blob_offset + p.size > l.start)
            ORDER BY size - dead_size
            LIMIT p_max_sources FOR UPDATE SKIP LOCKED
        LOOP
            EXIT WHEN v_total + r.live > p_budget AND cardinality(v_sources) > 0;
            v_total := v_total + r.live;
            v_sources := v_sources || r.blob_id;
        END LOOP;
        IF cardinality(v_sources) = 0 THEN
            RETURN '{}';
        END IF;
    ELSIF p_kind = 'compact' THEN
        -- A lower threshold than the index's (tests): the same, without it.
        FOR r IN
            SELECT blob_id, size - dead_size AS live FROM blobs
            WHERE state = 'committed' AND dead_size > 0 AND dead_size >= size * p_compact_threshold
              AND (pack_lease_until IS NULL OR pack_lease_until < NOW())
              AND NOT EXISTS (SELECT 1 FROM lost_ranges l JOIN parts p ON p.blob_id = l.blob_id
                              WHERE l.blob_id = blobs.blob_id
                                AND p.blob_offset < l.stop AND p.blob_offset + p.size > l.start)
            ORDER BY size - dead_size
            LIMIT p_max_sources FOR UPDATE SKIP LOCKED
        LOOP
            EXIT WHEN v_total + r.live > p_budget AND cardinality(v_sources) > 0;
            v_total := v_total + r.live;
            v_sources := v_sources || r.blob_id;
        END LOOP;
        IF cardinality(v_sources) = 0 THEN
            RETURN '{}';
        END IF;
    ELSIF p_kind = 'convert' AND p_small_size >= 67108864 THEN
        -- The oldest first, off `blobs_replicated`, whose size bound
        -- (`packer::SMALL_SIZE`, which a test checks against this) is repeated
        -- as a literal, so that the planner can use the partial index. Those
        -- mostly garbage are compaction's: it codes what it keeps.
        FOR r IN
            SELECT blob_id, size - dead_size AS live FROM blobs
            WHERE state = 'committed' AND data_shards = 1 AND block_size IS NOT NULL
              AND size > 67108864
              AND size - dead_size > p_small_size AND dead_size < size * p_compact_threshold
              AND created_at < NOW() - make_interval(secs => p_cold_secs)
              AND (pack_lease_until IS NULL OR pack_lease_until < NOW())
              AND NOT EXISTS (SELECT 1 FROM lost_ranges l JOIN parts p ON p.blob_id = l.blob_id
                              WHERE l.blob_id = blobs.blob_id
                                AND p.blob_offset < l.stop AND p.blob_offset + p.size > l.start)
            ORDER BY created_at
            LIMIT p_max_sources FOR UPDATE SKIP LOCKED
        LOOP
            EXIT WHEN v_total + r.live > p_budget AND cardinality(v_sources) > 0;
            v_total := v_total + r.live;
            v_sources := v_sources || r.blob_id;
        END LOOP;
        IF cardinality(v_sources) = 0 THEN
            RETURN '{}';
        END IF;
    ELSIF p_kind = 'convert' THEN
        -- A smaller `p_small_size` than the index's (tests): the same,
        -- without it.
        FOR r IN
            SELECT blob_id, size - dead_size AS live FROM blobs
            WHERE state = 'committed' AND data_shards = 1 AND block_size IS NOT NULL
              AND size - dead_size > p_small_size AND dead_size < size * p_compact_threshold
              AND created_at < NOW() - make_interval(secs => p_cold_secs)
              AND (pack_lease_until IS NULL OR pack_lease_until < NOW())
              AND NOT EXISTS (SELECT 1 FROM lost_ranges l JOIN parts p ON p.blob_id = l.blob_id
                              WHERE l.blob_id = blobs.blob_id
                                AND p.blob_offset < l.stop AND p.blob_offset + p.size > l.start)
            ORDER BY created_at
            LIMIT p_max_sources FOR UPDATE SKIP LOCKED
        LOOP
            EXIT WHEN v_total + r.live > p_budget AND cardinality(v_sources) > 0;
            v_total := v_total + r.live;
            v_sources := v_sources || r.blob_id;
        END LOOP;
        IF cardinality(v_sources) = 0 THEN
            RETURN '{}';
        END IF;
    ELSIF p_kind = 'upgrade' THEN
        -- One blob from before checksums, the oldest, off `blobs_legacy`.
        FOR r IN
            SELECT blob_id FROM blobs
            WHERE state = 'committed' AND block_size IS NULL
              AND (pack_lease_until IS NULL OR pack_lease_until < NOW())
              AND NOT EXISTS (SELECT 1 FROM lost_ranges l JOIN parts p ON p.blob_id = l.blob_id
                              WHERE l.blob_id = blobs.blob_id
                                AND p.blob_offset < l.stop AND p.blob_offset + p.size > l.start)
            ORDER BY created_at
            LIMIT 1 FOR UPDATE SKIP LOCKED
        LOOP
            v_sources := v_sources || r.blob_id;
        END LOOP;
        IF cardinality(v_sources) = 0 THEN
            RETURN '{}';
        END IF;
    ELSE
        -- Whether the candidates are worth a job at all, without locking them.
        -- Blobs that others have locked count too, so this can only be too
        -- hopeful, which the locked count below then corrects.
        SELECT coalesce(sum(c.size), 0), count(*) INTO v_total, v_count FROM (
            SELECT size FROM blobs
            WHERE state = 'committed' AND size <= 67108864 AND size <= p_small_size
              AND (pack_lease_until IS NULL OR pack_lease_until < NOW())
              AND NOT EXISTS (SELECT 1 FROM lost_ranges l JOIN parts p ON p.blob_id = l.blob_id
                              WHERE l.blob_id = blobs.blob_id
                                AND p.blob_offset < l.stop AND p.blob_offset + p.size > l.start)
            ORDER BY created_at
            LIMIT p_max_sources
        ) AS c;
        IF v_total < p_target_size AND v_count < p_max_sources THEN
            RETURN '{}';
        END IF;
        v_total := 0;
        -- Oldest first. The `blobs_small` index's size bound
        -- (`packer::SMALL_SIZE`, which a test checks against this) is repeated
        -- as a literal, so that the planner can use the partial index.
        FOR r IN
            SELECT blob_id, size AS live FROM blobs
            WHERE state = 'committed' AND size <= 67108864 AND size <= p_small_size
              AND (pack_lease_until IS NULL OR pack_lease_until < NOW())
              AND NOT EXISTS (SELECT 1 FROM lost_ranges l JOIN parts p ON p.blob_id = l.blob_id
                              WHERE l.blob_id = blobs.blob_id
                                AND p.blob_offset < l.stop AND p.blob_offset + p.size > l.start)
            ORDER BY created_at
            LIMIT p_max_sources FOR UPDATE SKIP LOCKED
        LOOP
            EXIT WHEN v_total + r.live > p_budget AND cardinality(v_sources) > 0;
            v_total := v_total + r.live;
            v_sources := v_sources || r.blob_id;
        END LOOP;
        IF v_total < p_target_size AND cardinality(v_sources) < p_max_sources THEN
            RETURN '{}';
        END IF;
    END IF;
    UPDATE blobs SET pack_lease_until = NOW() + make_interval(secs => p_lease_secs)
    WHERE blob_id = ANY(v_sources);
    RETURN v_sources;
END
$$;

-- T15: the commit that ends a packing job (see `packer::commit`). Takes X
-- exclusive on its sources and new blobs. Checks that the new blobs are still
-- pending and every shard of each recorded its location
-- ('missing_locations', with how many of one blob's did). Then commits the new
-- blobs, moves each part that's still where the job found it into its new
-- blob (I7), drops the sources and new blobs that nothing references anymore,
-- and releases the leases on the sources that remain ('committed').
--
-- The new blobs come as parallel arrays (`p_out_*`), and their shards as
-- (blob, node, shard, CRC64/NVME of the shard's file) tuples (`p_loc_*`);
-- the parts as (id, old blob, old offset, new blob, new offset).
CREATE OR REPLACE FUNCTION pg_temp.cairn_pack_commit(
    p_sources uuid[],
    p_out_blobs uuid[], p_out_sizes bigint[], p_block_size int, p_out_data_shards smallint[],
    p_out_parity_shards smallint[], p_stripe_unit int,
    p_loc_blobs uuid[], p_loc_nodes int[], p_loc_shards smallint[], p_loc_crcs bigint[],
    p_part_ids bigint[], p_old_blobs uuid[], p_old_offsets bigint[],
    p_new_blobs uuid[], p_new_offsets bigint[],
    OUT status text, OUT present bigint,
    OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_nodes int[];
    v_shards smallint[];
    v_crcs bigint[];
    v_touched uuid[];
BEGIN
    reap_blob := '{}';
    reap_node := '{}';
    reap_peer := '{}';
    v_touched := p_sources || p_out_blobs;
    PERFORM pg_temp.cairn_lock_blobs(v_touched, array_fill(true, ARRAY[cardinality(v_touched)]));
    FOR i IN 1 .. coalesce(cardinality(p_out_blobs), 0) LOOP
        SELECT coalesce(array_agg(l.node), '{}'), coalesce(array_agg(l.shard), '{}')
        INTO v_nodes, v_shards
        FROM unnest(p_loc_blobs, p_loc_nodes, p_loc_shards) AS l(blob_id, node, shard)
        WHERE l.blob_id = p_out_blobs[i];
        present := pg_temp.cairn_locations_present(p_out_blobs[i], v_nodes, v_shards);
        IF present <> cardinality(v_nodes) THEN
            status := 'missing_locations';
            RETURN;
        END IF;
    END LOOP;
    FOR i IN 1 .. coalesce(cardinality(p_out_blobs), 0) LOOP
        SELECT array_agg(l.crc ORDER BY l.shard) INTO v_crcs
        FROM unnest(p_loc_blobs, p_loc_shards, p_loc_crcs) AS l(blob_id, shard, crc)
        WHERE l.blob_id = p_out_blobs[i];
        PERFORM pg_temp.cairn_mark_committed(p_out_blobs[i], p_out_sizes[i], p_block_size,
                                             p_out_data_shards[i], p_out_parity_shards[i],
                                             p_stripe_unit, v_crcs);
    END LOOP;
    -- Only parts on the sources match, and their rows are covered by the
    -- sources' locks (rule B).
    UPDATE parts p SET blob_id = m.new_blob, blob_offset = m.new_offset
    FROM unnest(p_part_ids, p_old_blobs, p_old_offsets, p_new_blobs, p_new_offsets)
        AS m(id, old_blob, old_offset, new_blob, new_offset)
    WHERE p.id = m.id AND p.blob_id = m.old_blob AND p.blob_offset = m.old_offset;
    -- Whatever didn't move into a new blob (its part was deleted meanwhile) is
    -- garbage there, and so is whatever moved out of a source that remains.
    PERFORM pg_temp.cairn_refresh_dead_size(v_touched);
    SELECT * INTO reap_blob, reap_node, reap_peer
    FROM pg_temp.cairn_drop_unreferenced_blobs(v_touched);
    UPDATE blobs SET pack_lease_until = NULL WHERE blob_id = ANY(p_sources);
    status := 'committed';
END
$$;

-- LISTINGS
--
-- ListObjects(V2) and ListObjectVersions walk the keys in order, instead of
-- reading every key under the prefix: they read a range of the index until a
-- key rolls up into a common prefix, and then jump past all of that prefix's
-- keys at once (see `cairn_prefix_end`), to read on from there. So a page
-- costs a range as long as the page, and a lookup for each common prefix on
-- it, whatever the delimiter, and however many keys there are. They read, so
-- they take no locks; each runs as one statement, and so sees one snapshot.
--
-- Keys compare as bytes (their C collation, migration 9), which is S3's order.
-- Everything compared with them is given the same collation, explicitly. A
-- function called with C-collated arguments sees all of its text parameters
-- as C, the bucket's too, so the bucket is compared in its own collation
-- explicitly: else no index on (bucket, key) can serve the lookups.
--
-- Markers work as in MinIO: an entry, a key or a common prefix, is listed only
-- if it sorts after the marker, and a page's next marker is its last entry.
-- So a marker that names a common prefix resumes past all of its keys.

-- The least text that sorts after every text starting with `p`, or NULL if
-- there's none: `p` with its last character incremented, after dropping
-- trailing characters that can't be (U+10FFFF). The surrogates, which text
-- can't hold, are skipped. Byte order is code point order in UTF-8, so this
-- is right for the C collation.
CREATE OR REPLACE FUNCTION pg_temp.cairn_prefix_end(p text)
RETURNS text LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    v text COLLATE "C" := p;
    c int;
BEGIN
    WHILE v <> '' LOOP
        c := ascii(right(v, 1));
        IF c < 1114111 THEN
            IF c + 1 BETWEEN 55296 AND 57343 THEN
                RETURN left(v, -1) || chr(57344);
            END IF;
            RETURN left(v, -1) || chr(c + 1);
        END IF;
        v := left(v, -1);
    END LOOP;
    RETURN NULL;
END
$$;

-- Where a walk starts: at the prefix, or just after the marker, whichever is
-- later. The least text after `m` is `m` with U+0001 appended, since text
-- can't hold U+0000.
CREATE OR REPLACE FUNCTION pg_temp.cairn_walk_start(p_prefix text, p_marker text)
RETURNS text LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
    IF p_marker = '' THEN
        RETURN p_prefix;
    END IF;
    RETURN greatest(p_prefix COLLATE "C", (p_marker || chr(1)) COLLATE "C");
END
$$;

-- The common prefix that `p_key` rolls up into under `p_prefix` and
-- `p_delimiter`, or NULL if it's listed as a key.
CREATE OR REPLACE FUNCTION pg_temp.cairn_common_prefix(p_key text, p_prefix text, p_delimiter text)
RETURNS text LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    v_rest text := substr(p_key, length(p_prefix) + 1);
    v_pos int;
BEGIN
    IF p_delimiter = '' THEN
        RETURN NULL;
    END IF;
    v_pos := strpos(v_rest, p_delimiter);
    IF v_pos = 0 THEN
        RETURN NULL;
    END IF;
    RETURN p_prefix || substr(v_rest, 1, v_pos + length(p_delimiter) - 1);
END
$$;

-- A page of up to `p_limit` entries of ListObjects(V2): the current versions
-- of the keys under `p_prefix` (and the delete markers too, if
-- `p_delete_markers`), rolled up at `p_delimiter` ('' for none), after
-- `p_marker`. A common prefix comes with how many keys it holds, their total
-- size and when the last changed, if `p_totals` (which costs reading them all).
CREATE OR REPLACE FUNCTION pg_temp.cairn_list_current(
    p_bucket text, p_prefix text, p_delimiter text, p_marker text, p_limit int,
    p_delete_markers boolean, p_totals boolean,
    OUT name text, OUT is_prefix boolean, OUT objects bigint, OUT size bigint, OUT etag text,
    OUT last_modified timestamptz, OUT is_delete_marker boolean,
    OUT sse_s3 boolean, OUT sse_kms_key_id text, OUT sse_kms_data_key text, OUT sse_kms_sealed bytea,
    OUT checksum_algorithm text, OUT checksum_type text
) RETURNS SETOF record LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_pfx text COLLATE "C" := p_prefix;
    v_marker text COLLATE "C" := p_marker;
    v_delim text COLLATE "C" := p_delimiter;
    v_from text COLLATE "C" := pg_temp.cairn_walk_start(p_prefix, p_marker);
    v_end text COLLATE "C" := pg_temp.cairn_prefix_end(p_prefix);
    v_count int := 0;
    v_cp text COLLATE "C";
    v_past text COLLATE "C";
    c refcursor;
    r record;
BEGIN
    LOOP
        -- The keys from v_from on, in order: a range of `objects_latest`, read
        -- until it reaches a key that rolls up into a common prefix. (Every key
        -- in [v_from, v_end) starts with the prefix.)
        IF v_end IS NULL THEN
            OPEN c FOR
                SELECT o.key, o.size, o.etag, o.last_modified, o.is_delete_marker, o.sse_s3,
                       o.sse_kms_key_id, o.sse_kms_data_key, o.sse_kms_sealed,
                       o.checksum_algorithm, o.checksum_type FROM objects o
                WHERE o.bucket = p_bucket COLLATE "default" AND o.is_latest AND o.key >= v_from
                  AND (p_delete_markers OR NOT o.is_delete_marker)
                ORDER BY o.key LIMIT p_limit - v_count;
        ELSE
            OPEN c FOR
                SELECT o.key, o.size, o.etag, o.last_modified, o.is_delete_marker, o.sse_s3,
                       o.sse_kms_key_id, o.sse_kms_data_key, o.sse_kms_sealed,
                       o.checksum_algorithm, o.checksum_type FROM objects o
                WHERE o.bucket = p_bucket COLLATE "default" AND o.is_latest AND o.key >= v_from
                  AND o.key < v_end AND (p_delete_markers OR NOT o.is_delete_marker)
                ORDER BY o.key LIMIT p_limit - v_count;
        END IF;
        v_cp := NULL;
        LOOP
            FETCH c INTO r;
            EXIT WHEN NOT FOUND;
            v_cp := pg_temp.cairn_common_prefix(r.key, v_pfx, v_delim);
            EXIT WHEN v_cp IS NOT NULL;
            name := r.key;
            is_prefix := false;
            objects := 1;
            size := r.size;
            etag := r.etag;
            last_modified := r.last_modified;
            is_delete_marker := r.is_delete_marker;
            sse_s3 := r.sse_s3;
            sse_kms_key_id := r.sse_kms_key_id;
            sse_kms_data_key := r.sse_kms_data_key;
            sse_kms_sealed := r.sse_kms_sealed;
            checksum_algorithm := r.checksum_algorithm;
            checksum_type := r.checksum_type;
            RETURN NEXT;
            v_count := v_count + 1;
        END LOOP;
        CLOSE c;
        -- The keys ran out, or the page is full.
        EXIT WHEN v_cp IS NULL;
        -- Past every key the common prefix holds.
        v_past := pg_temp.cairn_prefix_end(v_cp);
        IF v_cp > v_marker THEN
            name := v_cp;
            is_prefix := true;
            objects := NULL;
            size := NULL;
            etag := NULL;
            last_modified := NULL;
            is_delete_marker := false;
            sse_s3 := NULL;
            sse_kms_key_id := NULL;
            sse_kms_data_key := NULL;
            sse_kms_sealed := NULL;
            checksum_algorithm := NULL;
            checksum_type := NULL;
            IF p_totals AND v_past IS NULL THEN
                SELECT count(*), coalesce(sum(o.size), 0), max(o.last_modified)
                INTO objects, size, last_modified
                FROM objects o
                WHERE o.bucket = p_bucket COLLATE "default" AND o.is_latest AND o.key >= v_cp
                  AND (p_delete_markers OR NOT o.is_delete_marker);
            ELSIF p_totals THEN
                SELECT count(*), coalesce(sum(o.size), 0), max(o.last_modified)
                INTO objects, size, last_modified
                FROM objects o
                WHERE o.bucket = p_bucket COLLATE "default" AND o.is_latest AND o.key >= v_cp
                  AND o.key < v_past AND (p_delete_markers OR NOT o.is_delete_marker);
            END IF;
            RETURN NEXT;
            v_count := v_count + 1;
        END IF;
        EXIT WHEN v_past IS NULL OR v_count >= p_limit;
        v_from := v_past;
    END LOOP;
END
$$;

-- A page of up to `p_limit` entries of ListObjectVersions: every version of
-- the keys under `p_prefix`, newest first, rolled up at `p_delimiter` ('' for
-- none), after the version with row id `p_id_marker` of `p_key_marker` (or,
-- if that's NULL, after all versions of `p_key_marker`).
CREATE OR REPLACE FUNCTION pg_temp.cairn_list_versions(
    p_bucket text, p_prefix text, p_delimiter text, p_key_marker text, p_id_marker bigint,
    p_limit int,
    OUT name text, OUT is_prefix boolean, OUT version_id text, OUT is_latest boolean,
    OUT is_delete_marker boolean, OUT size bigint, OUT etag text, OUT last_modified timestamptz,
    OUT sse_s3 boolean, OUT sse_kms_key_id text, OUT sse_kms_data_key text, OUT sse_kms_sealed bytea,
    OUT checksum_algorithm text, OUT checksum_type text
) RETURNS SETOF record LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_pfx text COLLATE "C" := p_prefix;
    v_marker text COLLATE "C" := p_key_marker;
    v_delim text COLLATE "C" := p_delimiter;
    v_from text COLLATE "C" := pg_temp.cairn_walk_start(p_prefix, p_key_marker);
    v_end text COLLATE "C" := pg_temp.cairn_prefix_end(p_prefix);
    v_count int := 0;
    v_cp text COLLATE "C";
    c refcursor;
    r record;
BEGIN
    -- The versions of the marker's own key older than the version marker come
    -- first, if that key is listed as a key.
    IF p_id_marker IS NOT NULL AND starts_with(v_marker, v_pfx)
       AND pg_temp.cairn_common_prefix(v_marker, v_pfx, v_delim) IS NULL THEN
        RETURN QUERY
            SELECT o.key::text, false, o.version_id, o.is_latest, o.is_delete_marker, o.size,
                   o.etag, o.last_modified, o.sse_s3, o.sse_kms_key_id, o.sse_kms_data_key,
                   o.sse_kms_sealed, o.checksum_algorithm, o.checksum_type
            FROM objects o
            WHERE o.bucket = p_bucket COLLATE "default" AND o.key = v_marker
              AND o.id < p_id_marker
            ORDER BY o.id DESC LIMIT p_limit;
        GET DIAGNOSTICS v_count = ROW_COUNT;
    END IF;
    WHILE v_count < p_limit LOOP
        -- The versions from v_from on, in order: a range of `objects_versions`,
        -- read until it reaches a key that rolls up into a common prefix.
        IF v_end IS NULL THEN
            OPEN c FOR
                SELECT o.key, o.version_id, o.is_latest, o.is_delete_marker, o.size, o.etag,
                       o.last_modified, o.sse_s3, o.sse_kms_key_id, o.sse_kms_data_key,
                       o.sse_kms_sealed, o.checksum_algorithm, o.checksum_type
                FROM objects o
                WHERE o.bucket = p_bucket COLLATE "default" AND o.key >= v_from
                ORDER BY o.key, o.id DESC LIMIT p_limit - v_count;
        ELSE
            OPEN c FOR
                SELECT o.key, o.version_id, o.is_latest, o.is_delete_marker, o.size, o.etag,
                       o.last_modified, o.sse_s3, o.sse_kms_key_id, o.sse_kms_data_key,
                       o.sse_kms_sealed, o.checksum_algorithm, o.checksum_type
                FROM objects o
                WHERE o.bucket = p_bucket COLLATE "default" AND o.key >= v_from AND o.key < v_end
                ORDER BY o.key, o.id DESC LIMIT p_limit - v_count;
        END IF;
        v_cp := NULL;
        LOOP
            FETCH c INTO r;
            EXIT WHEN NOT FOUND;
            v_cp := pg_temp.cairn_common_prefix(r.key, v_pfx, v_delim);
            EXIT WHEN v_cp IS NOT NULL;
            name := r.key;
            is_prefix := false;
            version_id := r.version_id;
            is_latest := r.is_latest;
            is_delete_marker := r.is_delete_marker;
            size := r.size;
            etag := r.etag;
            last_modified := r.last_modified;
            sse_s3 := r.sse_s3;
            sse_kms_key_id := r.sse_kms_key_id;
            sse_kms_data_key := r.sse_kms_data_key;
            sse_kms_sealed := r.sse_kms_sealed;
            checksum_algorithm := r.checksum_algorithm;
            checksum_type := r.checksum_type;
            RETURN NEXT;
            v_count := v_count + 1;
        END LOOP;
        CLOSE c;
        -- The versions ran out, or the page is full.
        EXIT WHEN v_cp IS NULL;
        IF v_cp > v_marker THEN
            name := v_cp;
            is_prefix := true;
            version_id := NULL;
            is_latest := NULL;
            is_delete_marker := NULL;
            size := NULL;
            etag := NULL;
            last_modified := NULL;
            sse_s3 := NULL;
            sse_kms_key_id := NULL;
            sse_kms_data_key := NULL;
            sse_kms_sealed := NULL;
            checksum_algorithm := NULL;
            checksum_type := NULL;
            RETURN NEXT;
            v_count := v_count + 1;
        END IF;
        -- Past every key the common prefix holds.
        v_from := pg_temp.cairn_prefix_end(v_cp);
        EXIT WHEN v_from IS NULL;
    END LOOP;
END
$$;

-- ListMultipartUploads: the walk of `cairn_list_versions`, over the bucket's
-- incomplete uploads, ordered by key and then by upload ID (UUIDv7s, so each
-- key's in the order they were created). With an upload marker, the marker
-- key's uploads after it come first, if that key is listed as a key; the
-- marker needn't exist, the IDs order themselves. At most `p_limit` entries.
CREATE OR REPLACE FUNCTION pg_temp.cairn_list_uploads(
    p_bucket text, p_prefix text, p_delimiter text, p_key_marker text, p_upload_marker uuid,
    p_limit int,
    OUT name text, OUT is_prefix boolean, OUT upload_id uuid, OUT initiated_at timestamptz,
    OUT checksum_algorithm text, OUT checksum_type text
) RETURNS SETOF record LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_pfx text COLLATE "C" := p_prefix;
    v_marker text COLLATE "C" := p_key_marker;
    v_delim text COLLATE "C" := p_delimiter;
    v_from text COLLATE "C" := pg_temp.cairn_walk_start(p_prefix, p_key_marker);
    v_end text COLLATE "C" := pg_temp.cairn_prefix_end(p_prefix);
    v_count int := 0;
    v_cp text COLLATE "C";
    c refcursor;
    r record;
BEGIN
    IF p_upload_marker IS NOT NULL AND starts_with(v_marker, v_pfx)
       AND pg_temp.cairn_common_prefix(v_marker, v_pfx, v_delim) IS NULL THEN
        RETURN QUERY
            SELECT u.key::text, false, u.upload_id, u.initiated_at, u.checksum_algorithm,
                   u.checksum_type
            FROM multipart_uploads u
            WHERE u.bucket = p_bucket COLLATE "default" AND u.key = v_marker
              AND u.upload_id > p_upload_marker
            ORDER BY u.upload_id LIMIT p_limit;
        GET DIAGNOSTICS v_count = ROW_COUNT;
    END IF;
    WHILE v_count < p_limit LOOP
        IF v_end IS NULL THEN
            OPEN c FOR
                SELECT u.key, u.upload_id, u.initiated_at, u.checksum_algorithm, u.checksum_type
                FROM multipart_uploads u
                WHERE u.bucket = p_bucket COLLATE "default" AND u.key >= v_from
                ORDER BY u.key, u.upload_id LIMIT p_limit - v_count;
        ELSE
            OPEN c FOR
                SELECT u.key, u.upload_id, u.initiated_at, u.checksum_algorithm, u.checksum_type
                FROM multipart_uploads u
                WHERE u.bucket = p_bucket COLLATE "default" AND u.key >= v_from AND u.key < v_end
                ORDER BY u.key, u.upload_id LIMIT p_limit - v_count;
        END IF;
        v_cp := NULL;
        LOOP
            FETCH c INTO r;
            EXIT WHEN NOT FOUND;
            v_cp := pg_temp.cairn_common_prefix(r.key, v_pfx, v_delim);
            EXIT WHEN v_cp IS NOT NULL;
            name := r.key;
            is_prefix := false;
            upload_id := r.upload_id;
            initiated_at := r.initiated_at;
            checksum_algorithm := r.checksum_algorithm;
            checksum_type := r.checksum_type;
            RETURN NEXT;
            v_count := v_count + 1;
        END LOOP;
        CLOSE c;
        EXIT WHEN v_cp IS NULL;
        IF v_cp > v_marker THEN
            name := v_cp;
            is_prefix := true;
            upload_id := NULL;
            initiated_at := NULL;
            checksum_algorithm := NULL;
            checksum_type := NULL;
            RETURN NEXT;
            v_count := v_count + 1;
        END IF;
        v_from := pg_temp.cairn_prefix_end(v_cp);
        EXIT WHEN v_from IS NULL;
    END LOOP;
END
$$;
