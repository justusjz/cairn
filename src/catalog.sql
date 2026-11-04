-- The catalog's multi-statement transactions, one function each, so that a
-- transaction is a single round trip to Postgres. See `db::install_functions`:
-- each connection creates these in its own session's `pg_temp` schema, so
-- they're always the version of the binary that calls them, and they're
-- called (and call each other) as `pg_temp.cairn_…`.
--
-- Callers run each function as a statement of its own, which is then its own
-- transaction: one round trip. So every function either succeeds, or reports
-- why it didn't (a `status`) without having changed anything; it checks all
-- it needs to before its first write. Freed parts are passed around as two parallel arrays (their
-- blobs and sizes), and the locations of the blobs to reap after commit as
-- three (blob, node, peer URL).
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
-- F2. An UPDATE, DELETE or SELECT ... FOR ... that waits for a row lock
--     re-evaluates its WHERE clause on the row's newest version once it gets
--     the lock, but only conditions on that row (and rows joined to it in the
--     same statement), not subqueries such as NOT EXISTS (SELECT ... FROM
--     parts ...). So a condition on other rows is always checked in a later
--     statement than the one that takes the lock.
--
-- Postgres detects deadlocks and aborts one of the transactions, which the
-- callers retry (`db::is_conflict`), so the lock order (bucket, upload, keys
-- by lock id, blobs by id) only matters for speed, never for correctness.
--
-- The locks. The shared mode is always FOR KEY SHARE, the mode the FK checks
-- take anyway. It conflicts with FOR UPDATE and DELETE, but not with plain
-- UPDATEs (FOR NO KEY UPDATE), so the exclusive mode is always an explicit
-- SELECT ... FOR UPDATE.
--
--   B(b)    The bucket's row. Shared: writing objects or uploads in it,
--           reading its versioning state. Exclusive: changing the versioning
--           state, deleting the bucket.
--   K(b,k)  The advisory lock `cairn_lock_key`. Taken (exclusive) by every
--           change to the versions of key k. Bucket names can't contain '/',
--           so 'b/k' identifies the key; keys whose hashes collide merely
--           share a lock.
--   U(u)    The upload's row. Shared: attaching a part to it. Exclusive:
--           completing or aborting it.
--   X(x)    The blob's row. Shared: creating a reference to it (a part on
--           it). Exclusive: committing it, deleting it, removing a location.
--
-- The invariants, and how each is kept:
--
-- I1. A key's versions: at most one current version, which is the newest (by
--     id); at most one null version; a conditional write is evaluated against
--     the current version as of the write. Guard: K(b,k), taken by every
--     writer of a key's versions (`cairn_put_version` and `cairn_delete_key`
--     callers) before reading them. So writes to a key are serialized, and a
--     new version's id (drawn after the lock) grows with commit order. The
--     unique indexes on objects are a backstop.
-- I2. A write or delete lands entirely before or after a change of the
--     bucket's versioning state. Guard: B(b): writers read the state with it
--     shared, PutBucketVersioning holds it exclusively.
-- I3. A bucket is only deleted when it has no objects and no uploads, since
--     its cascades must never delete data. Guard: B(b): DeleteBucket holds it
--     exclusively and checks afterwards; every inserter of objects holds it
--     shared (and CreateMultipartUpload's insert, through its FK check). An
--     inserter that finds the row gone reports NoSuchBucket.
-- I4. CompleteMultipartUpload publishes exactly the parts it computed the
--     ETag and size from, and no part is attached to an upload being or
--     already completed or aborted. Guard: U(u): exclusive for complete and
--     abort, before they read the staged parts; shared for attaching, before
--     checking the upload exists. Two attaches to the same part number are
--     ordered by the unique index: the second fails, and its retry displaces
--     the first.
-- I5. A part only references an existing, committed blob; a blob is only
--     deleted when no part references it; a blob is only committed with all
--     of its replicas' locations present. Guard: X(x).
--     - Referencing (copies): lock the source parts' blobs shared, then
--       re-read the source parts, and check they're still the same parts, on
--       those blobs (`cairn_lock_source`, `cairn_source_parts`).
--     - Deleting: lock the candidates exclusively, then delete those without
--       parts in a later statement (`cairn_lock_blobs`, `cairn_drop_*`).
--     - Committing: lock exclusively, then check it's pending and count its
--       locations (`cairn_lock_pending`). Locations are only removed together
--       with their blob, or (in the future) under X(x) exclusive.
--     - Deleting a pending blob (GC, the packer's abandon): one DELETE whose
--       condition is on the blob row only, so F2 re-checks it after waiting
--       for a committer.
--     The parts FKs remain as a backstop; with this protocol, they can't fail.
-- I6. Every unreferenced committed blob is dropped eventually. A blob becomes
--     unreferenced only by its parts being deleted, which the parts_garbage
--     trigger logs in the same transaction, or moved by the packer, which
--     checks its sources itself. `cairn_fold_garbage` takes each log row
--     exactly once (concurrent folds wait for each other's rows, then skip
--     them, F2).
-- I7. The packer moves a part only if it's still where the job read it from:
--     a compare-and-swap on the part row, re-checked after waiting (F2). Its
--     sources and new blobs are locked exclusively up front.
-- I8. `dead_size` and the packer's leases are heuristics: nothing depends on
--     them for correctness.

-- Whether an If-Match / If-None-Match value matches `etag`. A value is NULL
-- when the header is absent, empty for `*`, and else its entity-tags (see
-- `Preconditions::write_conditions`).
CREATE OR REPLACE FUNCTION pg_temp.cairn_etag_matches(tags text[], etag text)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
    RETURN cardinality(tags) = 0 OR etag = ANY(tags);
END
$$;

-- Whether a conditional write may proceed against the key's current ETag
-- (NULL if there's no current object), as `Preconditions::allows_write`.
CREATE OR REPLACE FUNCTION pg_temp.cairn_allows_write(
    if_match text[], if_none_match text[], current_etag text
) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
    IF if_none_match IS NOT NULL AND current_etag IS NOT NULL
       AND pg_temp.cairn_etag_matches(if_none_match, current_etag) THEN
        RETURN false;
    END IF;
    IF if_match IS NOT NULL
       AND (current_etag IS NULL OR NOT pg_temp.cairn_etag_matches(if_match, current_etag)) THEN
        RETURN false;
    END IF;
    RETURN true;
END
$$;

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

-- K(b,k) for each of the keys, in the order of their lock ids, so that
-- transactions taking several don't deadlock (I1).
CREATE OR REPLACE FUNCTION pg_temp.cairn_lock_keys(p_bucket text, p_keys text[])
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_id bigint;
BEGIN
    FOR v_id IN
        SELECT DISTINCT hashtextextended(p_bucket || '/' || k, 0) AS id
        FROM unnest(p_keys) AS k ORDER BY id
    LOOP
        PERFORM pg_advisory_xact_lock(v_id);
    END LOOP;
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

-- X(x), exclusive, for each of the blobs that exist, in order of their ids
-- (I5).
CREATE OR REPLACE FUNCTION pg_temp.cairn_lock_blobs(p_blobs uuid[])
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    -- The rows are locked as they come out of the sort.
    PERFORM 1 FROM blobs WHERE blob_id = ANY(p_blobs) ORDER BY blob_id FOR UPDATE;
END
$$;

-- X(x), exclusive, for a blob about to be committed: whether it's still
-- pending (else it's gone: deleted by the GC as stale, say) (I5).
CREATE OR REPLACE FUNCTION pg_temp.cairn_lock_pending(p_blob uuid)
RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM blobs WHERE blob_id = p_blob AND state = 'pending' FOR UPDATE;
    RETURN FOUND;
END
$$;

-- X(x), shared, for the blobs of the parts of a copy's source version, which
-- the copy is about to reference (I5). Returns the blobs it locked; a blob
-- deleted meanwhile isn't among them.
CREATE OR REPLACE FUNCTION pg_temp.cairn_lock_source(p_object bigint)
RETURNS uuid[] LANGUAGE plpgsql AS $$
DECLARE
    result uuid[];
BEGIN
    SELECT coalesce(array_agg(s.blob_id), '{}') INTO result
    FROM (
        SELECT b.blob_id FROM blobs b
        WHERE b.blob_id IN (SELECT p.blob_id FROM parts p WHERE p.object_id = p_object)
        ORDER BY b.blob_id
        FOR KEY SHARE
    ) AS s;
    RETURN result;
END
$$;

-- The ETag of the object a plain GET of the key would return. Under K(b,k).
CREATE OR REPLACE FUNCTION pg_temp.cairn_current_etag(p_bucket text, p_key text)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    result text;
BEGIN
    SELECT etag INTO result FROM objects
    WHERE bucket = p_bucket AND key = p_key AND is_latest AND NOT is_delete_marker;
    RETURN result;
END
$$;

-- How many of `nodes` hold a location for the blob. Under X(x) exclusive.
CREATE OR REPLACE FUNCTION pg_temp.cairn_locations_present(p_blob uuid, p_nodes int[])
RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE
    result bigint;
BEGIN
    SELECT count(*) INTO result FROM blob_locations WHERE blob_id = p_blob AND node = ANY(p_nodes);
    RETURN result;
END
$$;

-- Marks a blob committed, recording its size and the CRC64/NVME of its file
-- (see `Written`). The caller holds X(x) exclusive and has checked its
-- locations.
CREATE OR REPLACE FUNCTION pg_temp.cairn_mark_committed(
    p_blob uuid, p_size bigint, p_file_crc bigint, p_block_size int
) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    UPDATE blobs SET state = 'committed', size = p_size, crc64nvme = p_file_crc,
                     block_size = p_block_size
    WHERE blob_id = p_blob;
END
$$;

-- Deletes the blobs that deleted parts (of these blobs and sizes, deleted in
-- the same transaction) held on their own, unless something else still
-- references them (another object's copy, say), cascading their locations
-- away; returns those locations.
--
-- Only a blob the size of the deleted part can have held nothing else, so
-- that's the only kind this locks and checks for other parts. That keeps
-- concurrent deletes of different parts in a packed blob from waiting for
-- each other. A packed blob whose last part is deleted is dropped by the
-- packer instead (see `cairn_fold_garbage`).
CREATE OR REPLACE FUNCTION pg_temp.cairn_drop_blobs_of_deleted_parts(
    p_blobs uuid[], p_sizes bigint[],
    OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_whole uuid[];
BEGIN
    -- A blob's size doesn't change once it's committed, and a part only
    -- references committed blobs.
    SELECT coalesce(array_agg(DISTINCT b.blob_id), '{}') INTO v_whole
    FROM blobs b
    JOIN unnest(p_blobs, p_sizes) AS d(blob_id, size)
        ON d.blob_id = b.blob_id AND d.size = b.size;
    SELECT * INTO reap_blob, reap_node, reap_peer
    FROM pg_temp.cairn_drop_unreferenced_blobs(v_whole);
END
$$;

-- Deletes those of the blobs that no part references anymore (typically the
-- blobs of parts just deleted or moved in the same transaction), cascading
-- their locations away; returns those locations. I5: the blobs are locked
-- first, and checked for parts in a later statement, which therefore sees
-- every part that a transaction holding a blob's shared lock attached.
CREATE OR REPLACE FUNCTION pg_temp.cairn_drop_unreferenced_blobs(
    p_blobs uuid[],
    OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_temp.cairn_lock_blobs(p_blobs);
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
-- through copies).
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

-- Removes the version with row id `p_id` and its parts, returning those.
-- Under K(b,k).
CREATE OR REPLACE FUNCTION pg_temp.cairn_remove_version(
    p_id bigint, OUT freed_blobs uuid[], OUT freed_sizes bigint[]
) LANGUAGE plpgsql AS $$
BEGIN
    WITH gone AS (DELETE FROM parts WHERE object_id = p_id RETURNING blob_id, size)
    SELECT coalesce(array_agg(blob_id), '{}'), coalesce(array_agg(size), '{}')
    INTO freed_blobs, freed_sizes
    FROM gone;
    DELETE FROM objects WHERE id = p_id;
END
$$;

-- Removes the key's `null` version, if it has one, returning its parts.
-- Under K(b,k).
CREATE OR REPLACE FUNCTION pg_temp.cairn_remove_null_version(
    p_bucket text, p_key text, OUT freed_blobs uuid[], OUT freed_sizes bigint[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_id bigint;
BEGIN
    freed_blobs := '{}';
    freed_sizes := '{}';
    SELECT id INTO v_id FROM objects
    WHERE bucket = p_bucket AND key = p_key AND version_id = 'null';
    IF FOUND THEN
        SELECT * INTO freed_blobs, freed_sizes FROM pg_temp.cairn_remove_version(v_id);
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
-- a write in a bucket with the given versioning state. `p_new_version_id` is
-- the fresh version ID to use if the bucket is versioned. Returns the new
-- row's id, the version ID to report (NULL in an unversioned bucket), and the
-- parts of the version it removed. The caller holds B(b) shared (which gave it
-- the versioning state) and K(b,k).
CREATE OR REPLACE FUNCTION pg_temp.cairn_put_version(
    p_bucket text, p_key text, p_versioning text, p_size bigint, p_etag text,
    p_content_type text, p_new_version_id text,
    OUT id bigint, OUT version_id text, OUT freed_blobs uuid[], OUT freed_sizes bigint[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_version_id text;
BEGIN
    freed_blobs := '{}';
    freed_sizes := '{}';
    IF p_versioning = 'enabled' THEN
        v_version_id := p_new_version_id;
    ELSE
        -- The null version is replaced wherever it sits among the key's versions.
        SELECT * INTO freed_blobs, freed_sizes FROM pg_temp.cairn_remove_null_version(p_bucket, p_key);
        v_version_id := 'null';
    END IF;
    PERFORM pg_temp.cairn_demote_current(p_bucket, p_key);
    INSERT INTO objects (bucket, key, version_id, is_latest, is_delete_marker,
                         size, etag, content_type, last_modified)
    VALUES (p_bucket, p_key, v_version_id, true, false, p_size, p_etag, p_content_type, NOW())
    RETURNING objects.id INTO id;
    version_id := CASE WHEN p_versioning = 'unversioned' THEN NULL ELSE v_version_id END;
END
$$;

-- Deletes the key the way S3 does in a bucket with the given versioning state:
-- a named version for good, else the null version (unversioned) or by
-- stacking a delete marker (versioned; it replaces the null version in a
-- suspended bucket). `p_marker_id` is the fresh version ID of a marker in an
-- enabled bucket. Returns the version ID to report, whether it concerns a
-- delete marker, and the parts it removed. The caller holds B(b) shared and
-- K(b,k).
CREATE OR REPLACE FUNCTION pg_temp.cairn_delete_key(
    p_bucket text, p_key text, p_versioning text, p_version_id text, p_marker_id text,
    OUT version_id text, OUT delete_marker boolean,
    OUT freed_blobs uuid[], OUT freed_sizes bigint[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_row record;
    v_marker text;
BEGIN
    freed_blobs := '{}';
    freed_sizes := '{}';
    delete_marker := false;
    IF p_version_id IS NOT NULL THEN
        SELECT o.id, o.is_latest, o.is_delete_marker INTO v_row FROM objects o
        WHERE o.bucket = p_bucket AND o.key = p_key AND o.version_id = p_version_id;
        IF FOUND THEN
            delete_marker := v_row.is_delete_marker;
            SELECT * INTO freed_blobs, freed_sizes FROM pg_temp.cairn_remove_version(v_row.id);
            IF v_row.is_latest THEN
                PERFORM pg_temp.cairn_promote_newest(p_bucket, p_key);
            END IF;
        END IF;
        version_id := p_version_id;
        RETURN;
    END IF;
    IF p_versioning = 'unversioned' THEN
        SELECT * INTO freed_blobs, freed_sizes FROM pg_temp.cairn_remove_null_version(p_bucket, p_key);
        version_id := NULL;
        RETURN;
    ELSIF p_versioning = 'enabled' THEN
        v_marker := p_marker_id;
    ELSE
        SELECT * INTO freed_blobs, freed_sizes FROM pg_temp.cairn_remove_null_version(p_bucket, p_key);
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
-- Takes B(b) shared, K(b,k), X(blob) exclusive. Checks that the bucket exists
-- ('no_such_bucket'), the conditional-write guard ('precondition_failed') and
-- that every replica recorded its location ('missing_locations', with how
-- many did), then commits the blob, writes the version and attaches the part
-- ('committed').
CREATE OR REPLACE FUNCTION pg_temp.cairn_commit_object(
    p_blob uuid, p_nodes int[], p_size bigint, p_file_crc bigint, p_block_size int,
    p_data_crc bigint, p_etag text,
    p_bucket text, p_key text, p_content_type text,
    p_if_match text[], p_if_none_match text[], p_new_version_id text,
    OUT status text, OUT present bigint, OUT version_id text,
    OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_versioning text;
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
    IF (p_if_match IS NOT NULL OR p_if_none_match IS NOT NULL)
       AND NOT pg_temp.cairn_allows_write(p_if_match, p_if_none_match,
                                          pg_temp.cairn_current_etag(p_bucket, p_key)) THEN
        status := 'precondition_failed';
        RETURN;
    END IF;
    IF pg_temp.cairn_lock_pending(p_blob) THEN
        present := pg_temp.cairn_locations_present(p_blob, p_nodes);
    ELSE
        present := 0;
    END IF;
    IF present <> cardinality(p_nodes) THEN
        status := 'missing_locations';
        RETURN;
    END IF;
    PERFORM pg_temp.cairn_mark_committed(p_blob, p_size, p_file_crc, p_block_size);
    SELECT * INTO v FROM pg_temp.cairn_put_version(
        p_bucket, p_key, v_versioning, p_size, p_etag, p_content_type, p_new_version_id);
    version_id := v.version_id;
    INSERT INTO parts (blob_id, blob_offset, size, etag, crc64nvme, object_id, upload_id,
                       part_number, created_at)
    VALUES (p_blob, 0, p_size, p_etag, p_data_crc, v.id, NULL, 1, NOW());
    SELECT * INTO reap_blob, reap_node, reap_peer
    FROM pg_temp.cairn_drop_blobs_of_deleted_parts(v.freed_blobs, v.freed_sizes);
    status := 'committed';
END
$$;

-- T2: commits an uploaded blob as part `p_part_number` of a multipart upload,
-- displacing any part uploaded at that number before. Takes U(u) shared,
-- X(blob) exclusive. Or 'no_such_upload', or 'missing_locations'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_commit_upload_part(
    p_blob uuid, p_nodes int[], p_size bigint, p_file_crc bigint, p_block_size int,
    p_data_crc bigint, p_etag text,
    p_upload uuid, p_part_number int,
    OUT status text, OUT present bigint,
    OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_blobs uuid[];
    v_sizes bigint[];
BEGIN
    reap_blob := '{}';
    reap_node := '{}';
    reap_peer := '{}';
    IF NOT pg_temp.cairn_lock_upload(p_upload) THEN
        status := 'no_such_upload';
        RETURN;
    END IF;
    IF pg_temp.cairn_lock_pending(p_blob) THEN
        present := pg_temp.cairn_locations_present(p_blob, p_nodes);
    ELSE
        present := 0;
    END IF;
    IF present <> cardinality(p_nodes) THEN
        status := 'missing_locations';
        RETURN;
    END IF;
    PERFORM pg_temp.cairn_mark_committed(p_blob, p_size, p_file_crc, p_block_size);
    -- A concurrent upload of the same part number that commits first makes the
    -- INSERT below fail with a unique violation; the retry displaces it.
    WITH displaced AS (
        DELETE FROM parts WHERE upload_id = p_upload AND part_number = p_part_number
        RETURNING blob_id, size
    )
    SELECT coalesce(array_agg(blob_id), '{}'), coalesce(array_agg(size), '{}')
    INTO v_blobs, v_sizes FROM displaced;
    INSERT INTO parts (blob_id, blob_offset, size, etag, crc64nvme, object_id, upload_id,
                       part_number, created_at)
    VALUES (p_blob, 0, p_size, p_etag, p_data_crc, NULL, p_upload, p_part_number, NOW());
    SELECT * INTO reap_blob, reap_node, reap_peer
    FROM pg_temp.cairn_drop_blobs_of_deleted_parts(v_blobs, v_sizes);
    status := 'committed';
END
$$;

-- The current parts of a copy's source version, in order, if they're still
-- the ones (by id and size) the copy read, and all on blobs in `p_locked`
-- (which the caller holds X(x) shared on); NULL arrays if not. A part's bytes
-- never change, so the same parts mean the same data, though the packer may
-- have moved them to another blob since (and then they aren't on the locked
-- ones). A deleted version takes its parts with it, and every object has at
-- least one, so a deleted source shows here too.
CREATE OR REPLACE FUNCTION pg_temp.cairn_source_parts(
    p_object bigint, p_part_ids bigint[], p_part_sizes bigint[], p_locked uuid[],
    OUT blob_ids uuid[], OUT offsets bigint[], OUT sizes bigint[],
    OUT etags text[], OUT crcs bigint[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_ids bigint[];
BEGIN
    SELECT coalesce(array_agg(p.id ORDER BY p.part_number), '{}'),
           coalesce(array_agg(p.blob_id ORDER BY p.part_number), '{}'),
           coalesce(array_agg(p.blob_offset ORDER BY p.part_number), '{}'),
           coalesce(array_agg(p.size ORDER BY p.part_number), '{}'),
           coalesce(array_agg(p.etag ORDER BY p.part_number), '{}'),
           coalesce(array_agg(p.crc64nvme ORDER BY p.part_number), '{}')
    INTO v_ids, blob_ids, offsets, sizes, etags, crcs
    FROM parts p WHERE p.object_id = p_object;
    IF v_ids <> p_part_ids OR sizes <> p_part_sizes OR NOT blob_ids <@ p_locked THEN
        blob_ids := NULL;
        offsets := NULL;
        sizes := NULL;
        etags := NULL;
        crcs := NULL;
    END IF;
END
$$;

-- T3: CopyObject's commit: a new version at (bucket, key) with parts on the
-- source version's bytes ('committed'), unless the source changed since the
-- copy read it ('source_changed') or the bucket is gone ('no_such_bucket').
-- Takes B(b) shared, K(b,k), X(x) shared on the source's blobs.
CREATE OR REPLACE FUNCTION pg_temp.cairn_copy_object(
    p_source bigint, p_part_ids bigint[], p_part_sizes bigint[],
    p_bucket text, p_key text, p_size bigint, p_etag text, p_content_type text,
    p_new_version_id text,
    OUT status text, OUT version_id text,
    OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_versioning text;
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
    v_locked := pg_temp.cairn_lock_source(p_source);
    -- Read after the locks (F1), and before the new version is written: a
    -- copy onto its own source replaces the version whose bytes it shares.
    SELECT * INTO s FROM pg_temp.cairn_source_parts(p_source, p_part_ids, p_part_sizes, v_locked);
    IF s.blob_ids IS NULL THEN
        status := 'source_changed';
        RETURN;
    END IF;
    SELECT * INTO v FROM pg_temp.cairn_put_version(
        p_bucket, p_key, v_versioning, p_size, p_etag, p_content_type, p_new_version_id);
    version_id := v.version_id;
    INSERT INTO parts (blob_id, blob_offset, size, etag, crc64nvme, object_id, upload_id,
                       part_number, created_at)
    SELECT t.blob_id, t.blob_offset, t.size, t.etag, t.crc, v.id, NULL, t.n, NOW()
    FROM unnest(s.blob_ids, s.offsets, s.sizes, s.etags, s.crcs)
        WITH ORDINALITY AS t(blob_id, blob_offset, size, etag, crc, n);
    -- After inserting the new parts, so that a self-copy keeps its bytes.
    SELECT * INTO reap_blob, reap_node, reap_peer
    FROM pg_temp.cairn_drop_blobs_of_deleted_parts(v.freed_blobs, v.freed_sizes);
    status := 'committed';
END
$$;

-- T4: UploadPartCopy's commit: stages `p_length` bytes of source part
-- `p_index` (1-based), from `p_within` in it, as part `p_part_number` of the
-- upload, displacing any part uploaded at that number before ('committed').
-- Or 'no_such_upload', or 'source_changed'. Takes U(u) shared, X(x) shared on
-- the source's blobs.
CREATE OR REPLACE FUNCTION pg_temp.cairn_copy_part(
    p_source bigint, p_part_ids bigint[], p_part_sizes bigint[],
    p_index int, p_within bigint, p_length bigint, p_etag text, p_crc bigint,
    p_upload uuid, p_part_number int,
    OUT status text,
    OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_locked uuid[];
    s record;
    v_blobs uuid[];
    v_sizes bigint[];
BEGIN
    reap_blob := '{}';
    reap_node := '{}';
    reap_peer := '{}';
    IF NOT pg_temp.cairn_lock_upload(p_upload) THEN
        status := 'no_such_upload';
        RETURN;
    END IF;
    v_locked := pg_temp.cairn_lock_source(p_source);
    -- Read after the locks (F1).
    SELECT * INTO s FROM pg_temp.cairn_source_parts(p_source, p_part_ids, p_part_sizes, v_locked);
    IF s.blob_ids IS NULL THEN
        status := 'source_changed';
        RETURN;
    END IF;
    WITH displaced AS (
        DELETE FROM parts WHERE upload_id = p_upload AND part_number = p_part_number
        RETURNING blob_id, size
    )
    SELECT coalesce(array_agg(blob_id), '{}'), coalesce(array_agg(size), '{}')
    INTO v_blobs, v_sizes FROM displaced;
    INSERT INTO parts (blob_id, blob_offset, size, etag, crc64nvme, object_id, upload_id,
                       part_number, created_at)
    VALUES (s.blob_ids[p_index], s.offsets[p_index] + p_within, p_length, p_etag, p_crc,
            NULL, p_upload, p_part_number, NOW());
    SELECT * INTO reap_blob, reap_node, reap_peer
    FROM pg_temp.cairn_drop_blobs_of_deleted_parts(v_blobs, v_sizes);
    status := 'committed';
END
$$;

-- T5: CompleteMultipartUpload. Takes B(b) shared, U(u) exclusive, K(b,k).
-- Checks that the upload exists and belongs to (bucket, key)
-- ('no_such_upload'), that every listed part is staged with the listed ETag
-- ('invalid_part'), and the conditional-write guard ('precondition_failed').
-- Then publishes the listed parts as the key's new version, deletes the staged
-- parts left out, and the upload ('done', with the object's ETag).
CREATE OR REPLACE FUNCTION pg_temp.cairn_complete_upload(
    p_upload uuid, p_bucket text, p_key text, p_part_numbers int[], p_etags text[],
    p_if_match text[], p_if_none_match text[], p_new_version_id text,
    OUT status text, OUT etag text, OUT version_id text,
    OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_versioning text;
    v_content_type text;
    v_matched bigint;
    v_total bigint;
    v_combined text;
    v record;
    v_blobs uuid[];
    v_sizes bigint[];
BEGIN
    reap_blob := '{}';
    reap_node := '{}';
    reap_peer := '{}';
    -- An upload's bucket exists as long as the upload does.
    v_versioning := pg_temp.cairn_lock_bucket(p_bucket);
    -- The upload defines the object's content type. It must belong to the
    -- request's bucket and key: authorization only checked the bucket.
    SELECT content_type INTO v_content_type FROM multipart_uploads
    WHERE upload_id = p_upload AND bucket = p_bucket AND key = p_key
    FOR UPDATE;
    IF v_versioning IS NULL OR NOT FOUND THEN
        status := 'no_such_upload';
        RETURN;
    END IF;
    PERFORM pg_temp.cairn_lock_keys(p_bucket, ARRAY[p_key]);
    -- The object's ETag is the MD5 of the listed parts' binary MD5s, then the
    -- part count. The part numbers are distinct (the caller checked their order).
    SELECT count(*), sum(p.size), md5(string_agg(decode(p.etag, 'hex'), ''::bytea ORDER BY r.n))
    INTO v_matched, v_total, v_combined
    FROM unnest(p_part_numbers, p_etags) WITH ORDINALITY AS r(part_number, etag, n)
    JOIN parts p ON p.upload_id = p_upload AND p.part_number = r.part_number
                AND p.etag = r.etag;
    IF v_matched <> cardinality(p_part_numbers) THEN
        status := 'invalid_part';
        RETURN;
    END IF;
    IF (p_if_match IS NOT NULL OR p_if_none_match IS NOT NULL)
       AND NOT pg_temp.cairn_allows_write(p_if_match, p_if_none_match,
                                          pg_temp.cairn_current_etag(p_bucket, p_key)) THEN
        status := 'precondition_failed';
        RETURN;
    END IF;
    etag := v_combined || '-' || cardinality(p_part_numbers);
    SELECT * INTO v FROM pg_temp.cairn_put_version(
        p_bucket, p_key, v_versioning, v_total, etag, v_content_type, p_new_version_id);
    version_id := v.version_id;
    UPDATE parts SET upload_id = NULL, object_id = v.id
    WHERE upload_id = p_upload AND part_number = ANY(p_part_numbers);
    -- The staged parts left out of the object are the only ones still staged.
    WITH unused AS (DELETE FROM parts WHERE upload_id = p_upload RETURNING blob_id, size)
    SELECT coalesce(array_agg(blob_id), '{}'), coalesce(array_agg(size), '{}')
    INTO v_blobs, v_sizes FROM unused;
    SELECT * INTO reap_blob, reap_node, reap_peer
    FROM pg_temp.cairn_drop_blobs_of_deleted_parts(v.freed_blobs || v_blobs,
                                                   v.freed_sizes || v_sizes);
    DELETE FROM multipart_uploads WHERE upload_id = p_upload;
    status := 'done';
END
$$;

-- T6: AbortMultipartUpload. Takes U(u) exclusive. Deletes the upload (if it
-- belongs to bucket and key), its staged parts, and their blobs. `existed` is
-- whether there was one.
CREATE OR REPLACE FUNCTION pg_temp.cairn_abort_upload(
    p_upload uuid, p_bucket text, p_key text,
    OUT existed boolean,
    OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_blobs uuid[];
    v_sizes bigint[];
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
    WITH staged AS (DELETE FROM parts WHERE upload_id = p_upload RETURNING blob_id, size)
    SELECT coalesce(array_agg(blob_id), '{}'), coalesce(array_agg(size), '{}')
    INTO v_blobs, v_sizes FROM staged;
    DELETE FROM multipart_uploads WHERE upload_id = p_upload;
    SELECT * INTO reap_blob, reap_node, reap_peer
    FROM pg_temp.cairn_drop_blobs_of_deleted_parts(v_blobs, v_sizes);
END
$$;

-- T8: DeleteObject(s). Takes B(b) shared and K(b,k) for every key. Deletes
-- each target (a key, and a version ID or NULL) the way the bucket's
-- versioning state dictates ('deleted', with each one's version ID to report
-- and whether it concerns a delete marker), or reports 'no_such_bucket'.
-- `p_marker_ids` holds a fresh version ID per target, for a delete marker in
-- an enabled bucket.
CREATE OR REPLACE FUNCTION pg_temp.cairn_delete_objects(
    p_bucket text, p_keys text[], p_version_ids text[], p_marker_ids text[],
    OUT status text, OUT version_ids text[], OUT delete_markers boolean[],
    OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_versioning text;
    v_blobs uuid[] := '{}';
    v_sizes bigint[] := '{}';
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
    FOR i IN 1 .. coalesce(cardinality(p_keys), 0) LOOP
        SELECT * INTO d FROM pg_temp.cairn_delete_key(
            p_bucket, p_keys[i], v_versioning, p_version_ids[i], p_marker_ids[i]);
        version_ids := version_ids || d.version_id;
        delete_markers := delete_markers || d.delete_marker;
        v_blobs := v_blobs || d.freed_blobs;
        v_sizes := v_sizes || d.freed_sizes;
    END LOOP;
    SELECT * INTO reap_blob, reap_node, reap_peer
    FROM pg_temp.cairn_drop_blobs_of_deleted_parts(v_blobs, v_sizes);
    status := 'deleted';
END
$$;

-- T9: DeleteBucket. Takes B(b) exclusive. Only an empty bucket (no objects,
-- no uploads) is deleted: the cascades from it must never delete data.
-- Returns 'deleted', 'no_such_bucket' or 'not_empty'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_delete_bucket(p_bucket text)
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM buckets WHERE name = p_bucket FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'no_such_bucket';
    END IF;
    IF EXISTS (SELECT 1 FROM objects WHERE bucket = p_bucket)
       OR EXISTS (SELECT 1 FROM multipart_uploads WHERE bucket = p_bucket) THEN
        RETURN 'not_empty';
    END IF;
    DELETE FROM buckets WHERE name = p_bucket;
    RETURN 'deleted';
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

-- T13: takes the garbage log: drops the logged blobs that no part references
-- anymore, and refreshes the `dead_size` of the rest (see
-- `packer::fold_garbage`). Takes X(x) exclusive on the logged blobs.
CREATE OR REPLACE FUNCTION pg_temp.cairn_fold_garbage(
    OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_logged uuid[];
BEGIN
    WITH taken AS (DELETE FROM blob_garbage RETURNING blob_id)
    SELECT coalesce(array_agg(DISTINCT blob_id), '{}') INTO v_logged FROM taken;
    SELECT * INTO reap_blob, reap_node, reap_peer
    FROM pg_temp.cairn_drop_unreferenced_blobs(v_logged);
    -- The log's sizes would count bytes that another part still shares as
    -- garbage, so the blobs' garbage is worked out afresh.
    PERFORM pg_temp.cairn_refresh_dead_size(v_logged);
END
$$;

-- T14: claims the source blobs for a packing job, if there's one worth
-- running (see `packer::claim`): `p_kind` is 'compact' or 'consolidate'.
-- Takes candidates, skipping those a concurrent claim has locked, until their
-- live bytes would exceed `p_budget`, and leases them. Returns them, or an
-- empty array if the job isn't worth it. The lease is a heuristic (I8).
CREATE OR REPLACE FUNCTION pg_temp.cairn_claim(
    p_kind text, p_compact_threshold float8, p_max_sources bigint, p_small_size bigint,
    p_target_size bigint, p_budget bigint, p_lease_secs float8
) RETURNS uuid[] LANGUAGE plpgsql AS $$
DECLARE
    v_sources uuid[] := '{}';
    v_total bigint := 0;
    r record;
BEGIN
    IF p_kind = 'compact' THEN
        -- Least live data first: that's the cheapest space to free.
        FOR r IN
            SELECT blob_id, size - dead_size AS live FROM blobs
            WHERE dead_size > 0 AND state = 'committed' AND dead_size >= size * p_compact_threshold
              AND (pack_lease_until IS NULL OR pack_lease_until < NOW())
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
    ELSE
        -- Oldest first. The `blobs_small` index's size bound
        -- (`packer::SMALL_SIZE`, which a test checks against this) is repeated
        -- as a literal, so that the planner can use the partial index.
        FOR r IN
            SELECT blob_id, size AS live FROM blobs
            WHERE state = 'committed' AND size <= 67108864 AND size <= p_small_size
              AND (pack_lease_until IS NULL OR pack_lease_until < NOW())
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

-- T15: the commit that ends a packing job (see `packer::commit`). Takes X(x)
-- exclusive on its sources and new blobs. Checks that the new blobs are still
-- pending and every replica of each recorded its location
-- ('missing_locations', with how many of one blob's did). Then commits the new
-- blobs, moves each part that's still where the job found it into its new
-- blob (I7), drops the sources and new blobs that nothing references anymore,
-- and releases the leases on the sources that remain ('committed').
--
-- The new blobs come as parallel arrays (`p_out_*`), and their replicas as
-- (blob, node) pairs (`p_loc_*`); the parts as (id, old blob, old offset, new
-- blob, new offset).
CREATE OR REPLACE FUNCTION pg_temp.cairn_pack_commit(
    p_sources uuid[],
    p_out_blobs uuid[], p_out_sizes bigint[], p_out_crcs bigint[], p_block_size int,
    p_loc_blobs uuid[], p_loc_nodes int[],
    p_part_ids bigint[], p_old_blobs uuid[], p_old_offsets bigint[],
    p_new_blobs uuid[], p_new_offsets bigint[],
    OUT status text, OUT present bigint,
    OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_nodes int[];
    v_touched uuid[];
BEGIN
    reap_blob := '{}';
    reap_node := '{}';
    reap_peer := '{}';
    v_touched := p_sources || p_out_blobs;
    PERFORM pg_temp.cairn_lock_blobs(v_touched);
    FOR i IN 1 .. coalesce(cardinality(p_out_blobs), 0) LOOP
        SELECT coalesce(array_agg(l.node), '{}') INTO v_nodes
        FROM unnest(p_loc_blobs, p_loc_nodes) AS l(blob_id, node)
        WHERE l.blob_id = p_out_blobs[i];
        PERFORM 1 FROM blobs WHERE blob_id = p_out_blobs[i] AND state = 'pending';
        IF FOUND THEN
            present := pg_temp.cairn_locations_present(p_out_blobs[i], v_nodes);
        ELSE
            present := 0;
        END IF;
        IF present <> cardinality(v_nodes) THEN
            status := 'missing_locations';
            RETURN;
        END IF;
    END LOOP;
    FOR i IN 1 .. coalesce(cardinality(p_out_blobs), 0) LOOP
        PERFORM pg_temp.cairn_mark_committed(p_out_blobs[i], p_out_sizes[i], p_out_crcs[i],
                                             p_block_size);
    END LOOP;
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
