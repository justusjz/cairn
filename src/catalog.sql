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
--   A(a)    The account's row. Shared, as FOR SHARE (not KEY SHARE: what it
--           guards is changed by a plain UPDATE): setting a bucket's policy,
--           which reads the account's public access block (I12). Exclusive,
--           as that plain UPDATE: setting the block (T41). The FK checks of
--           what references the account take FOR KEY SHARE, which conflicts
--           with neither.
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
--   G(g)    The role_grants rows, from before grants were bucket policies
--           (see `grants`; only deleted now). Locked (exclusively, in
--           primary-key order) before they're deleted.
--   R(r)    A user's row (`users`; `roles` before migration 47).
--           Exclusive: giving it an access key, setting an inline
--           policy, or tagging it (I10); deleting the user (by deleting
--           the row); setting its permissions boundary (a plain UPDATE,
--           whose trigger keeps the inline policy `cairn:boundary`).
--   O(o)    An IAM role's row (`iam_roles`; see `roles`). Exclusive:
--           setting an inline policy or tagging it (I10); deleting it
--           (T49), which checks it has no policies left.
--   Q(q)    An IAM group's row (`iam_groups`; see `groups`). Shared:
--           adding a member to it (T59), under the member's R(r), which
--           every change of a user's memberships holds (T59, T60, deleting
--           the user). Exclusive: setting an inline policy (I10); deleting
--           it (T58), which checks it has no members or policies left.
--   D(d)    An IAM OIDC provider's row (`iam_oidc_providers`; see
--           `iam_oidc`). Exclusive: adding a client ID, tagging it,
--           setting its thumbprints (I10).
--   M(m)    A managed policy's row. Exclusive: tagging it (I10); making,
--           deleting a version, or setting its default (I13).
--   Y(y)    A user of Cairn's own directory's row (`identity_users`; see
--           `identity_center`). Exclusive: giving it a passkey (signed in,
--           or with a setup link), removing one (I10).
--   X(x)    The blob's row. Shared: referencing it, changing or deleting
--           a part on it, or changing its `lost_ranges` (the scrubber,
--           which locks the row with nothing else). Exclusive: committing it, deleting it, removing a
--           location, moving parts off or onto it (the packer). All of a
--           transaction's blobs are locked by one call of `cairn_lock_blobs`.
--           A remote blob's `tier_blobs` row (see `tiers`) goes with it:
--           inserted with the blob while it's pending, deleted by the
--           cascade when the blob is, under X(x) exclusive; the trigger
--           that queues its object in `tier_garbage` inserts a row that
--           nothing else locks.
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
-- I5. A part only references an existing, committed (or remote, or
--     restoring) blob; a blob is only deleted when no part references it; a
--     blob is only committed with all of its shards' locations present, and
--     made remote only with its tier's object written (T70). Guard: X(x).
--     - Referencing (copies): lock the source parts' blobs shared, then
--       re-read the source parts, and check they're still the same parts, on
--       those blobs (`cairn_source_parts`).
--     - Deleting: lock the candidates exclusively, then delete those without
--       parts in a later statement (`cairn_drop_unreferenced_blobs`).
--     - Committing: lock exclusively, then check it's pending and count its
--       locations. Locations are only removed together with their blob, or
--       by a move (`cairn_move_shard`) or a dropped copy
--       (`cairn_drop_copy`), which hold X(x) exclusive, and check the blob
--       is committed after taking it.
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
-- I8. `dead_size` and the packer's leases (which the mover takes too) are
--     heuristics: nothing depends on them for correctness.
-- I9. A blob has at most one location per shard, and a node at most one
--     shard of a blob: the unique indexes on blob_locations. A move, and an
--     added or dropped copy, check both under X(x) exclusive, before they
--     change the locations; the only other inserts are a pending blob's
--     sinks, each with a shard of its own. A committed blob has a location
--     for each of its shards: they change together, under X(x) exclusive.
-- I10. A user has at most two access keys, its inline policies hold at
--     most 2048 characters (but whitespace) together (but `cairn:boundary`,
--     which isn't one of its own: see `db::BOUNDARIES`), and it has at most
--     50 tags, as in IAM: making a key, setting a policy, or tagging it
--     holds R(r) exclusively, and counts what the user has in a later
--     statement (T28, T29, T42). A managed policy has at most 50 tags too:
--     tagging it holds M(m) exclusively, and counts in a later statement
--     (T43). A role's inline policies hold at most 10240 characters
--     together, and it has at most 50 tags: under O(o), counted in a later
--     statement (T47, T48). A group's inline policies hold at most 5120
--     characters together: under Q(q), counted in a later statement (T57);
--     and a user is in at most 10 groups: adding it to one holds R(r)
--     exclusively (then the group's Q(q) shared), and counts in a later
--     statement (T59). An IAM OIDC provider has at most 100 client
--     IDs and 50 tags: under D(d), counted in a later statement (T50,
--     T51); its thumbprints (at most five, checked before) are replaced
--     under D(d) too (T52). Likewise a user of Cairn's own directory has
--     at most 8 passkeys, as IAM's MFA devices, under Y(y) (T65), and
--     doesn't remove its own last one (T66): it has none until it uses a
--     setup link, or after an administrator removed them all. Deleting a
--     key or a policy only takes from them. The console's setup links, challenges and
--     sessions are each used up or ended by a single DELETE, whose condition
--     is on its own row (F2), so each is used once.
-- I11. A version that Object Lock keeps (a legal hold, or a retention that
--     lasts: see `cairn_locked`) is never removed, and its retention only
--     changes as S3 lets it (T39). Guard: K(b,k): every remover of a named
--     version (T8, T17) checks the lock after taking K, and every change of
--     a version's lock (T39, T40) takes K. Writes never remove versions of
--     a bucket with Object Lock, which stays versioned (T10, and the
--     `buckets_lock_versioned` constraint). The `objects_locked` trigger is
--     the backstop for legal holds and compliance mode.
-- I12. A public bucket policy is only set while neither the bucket's public
--     access block nor its account's has BlockPublicPolicy. (A block set
--     later leaves a policy that's there, as in S3.) Guards: B(b) for the
--     bucket's block, A(a) for the account's: T27 holds both while it checks
--     them, T32 changes the bucket's under B, T41 the account's under A.
-- I13. A managed policy has at most five versions, one of them its default,
--     whose number and document its own row's `version` and `document` are
--     (which evaluation reads); version numbers are never reused (its
--     `next_version`). Every change of its versions (T44, T45, T46) holds
--     M(m) exclusively, and reads them in a later statement. Its first
--     version is made with its row, by a trigger (`db::POLICY_VERSIONS`).
-- I14. A change to a key's versions or tags that commits has its events, in
--     the outbox (`notification_events`), and one that doesn't has none; a
--     key's events' sequencers grow with its changes' commit order. No guard
--     of its own: each event is inserted by `cairn_notify`, in the change's
--     own transaction, which holds the key's K (or its stripe's S) when it
--     draws the sequencer. The bucket's notification configurations are read
--     unlocked: a change racing a new configuration follows the old one or
--     the new, whichever its statement sees, which S3 doesn't promise either.
--     Neither table has foreign keys a change could wait on (rule B), and
--     only the delivery worker locks the outbox's rows (`notifications`).
-- I15. A bucket with a replication configuration is versioned, and stays
--     so (see `replication`). Guard: the bucket's row: setting the
--     configuration (T67) takes it as a plain UPDATE does, and checks the
--     versioning state in a later statement; changing the state (T10)
--     takes it exclusively. A version a write makes is queued for each of
--     the destinations it goes to in the write's own transaction, under
--     its K(b,k), as its events are (I14); the queue is read and leased by
--     the replication worker only (SKIP LOCKED), and a version leaves it
--     under its key's K (T68), which is what changes its status. A Batch
--     Replication job's task queues a version that's there already (T69),
--     under its key's K too.
--
-- DEADLOCKS
--
-- There are none, by three rules, which every transaction follows:
--
-- A. All of a transaction's locks are taken up front, in one global order:
--    B, A, U, P, S (by stripe), K (by lock id), G (by primary key), R, O, Q, D, M, Y, X (by
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
-- CreateMultipartUpload, user creation and updates, the heartbeat, the
-- scrubber's and reads' updates of a location's `checked_at`, and the
-- scrubber's changes to `scrub_findings`) hold nothing that anyone waits for
-- while they wait, so they can't be part of a cycle either. (A location insert's FK checks lock its node's row shared,
-- but nothing ever locks a node's row exclusively.) Grants are statements of
-- buckets' policies (see `grants`), changed by plain UPDATEs of the bucket's
-- row. The GC
-- and the packer's and the mover's claims use SKIP LOCKED, so they never wait at all. What
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
-- through copies). And their `misplaced_size` (see `classes`): the bytes of
-- the extents (runs of referenced bytes, back to back or overlapping) that
-- no part of a version or upload of the blob's own class references, but
-- only those of other, ranked classes, while the blob's class is ranked too.
-- The packer moves exactly those (see `packer::relocate`), each extent into
-- the highest of its versions' classes, so that a blob it rewrites isn't a
-- candidate again for the same bytes. A part of a class without a rank, or
-- of no version or upload, keeps its extent where it is. Under X(x)
-- exclusive.
CREATE OR REPLACE FUNCTION pg_temp.cairn_refresh_dead_size(p_blobs uuid[])
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    UPDATE blobs b SET dead_size = b.size - coalesce(live.bytes, 0),
                       misplaced_size = coalesce(misplaced.bytes, 0)
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
    LEFT JOIN (
        SELECT e.blob_id, sum(upper(e.r) - lower(e.r))::bigint AS bytes
        FROM (
            SELECT blob_id, unnest(range_agg(int8range(blob_offset, blob_offset + size))) AS r
            FROM parts WHERE blob_id = ANY(p_blobs)
            GROUP BY blob_id
        ) AS e
        JOIN blobs eb ON eb.blob_id = e.blob_id
        JOIN storage_classes ec ON ec.name = eb.storage_class
        WHERE ec.rank IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM parts p
            LEFT JOIN objects o ON o.id = p.object_id
            LEFT JOIN multipart_uploads u ON u.upload_id = p.upload_id
            LEFT JOIN storage_classes pc ON pc.name = coalesce(o.storage_class, u.storage_class)
            WHERE p.blob_id = e.blob_id AND int8range(p.blob_offset, p.blob_offset + p.size) && e.r
              AND (pc.rank IS NULL OR pc.name = eb.storage_class)
        )
        GROUP BY e.blob_id
    ) AS misplaced ON misplaced.blob_id = t.blob_id
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

-- Whether Object Lock keeps the version with row id `p_id` from being
-- deleted (see `s3::object_lock`): a legal hold, or a retention that lasts,
-- unless it's in governance mode and the deleter may bypass it
-- (`p_bypass`). Under K(b,k).
CREATE OR REPLACE FUNCTION pg_temp.cairn_locked(p_id bigint, p_bypass boolean)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    result boolean;
BEGIN
    SELECT coalesce(legal_hold, false)
           OR coalesce(retain_until > NOW() AND (retain_mode = 'COMPLIANCE' OR NOT p_bypass), false)
    INTO result FROM objects WHERE id = p_id;
    RETURN coalesce(result, false);
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

-- The last-modified time of a new version of the key, and whether it's
-- the key's current version. A key's versions are ordered by their
-- last-modified times, then their row IDs (which grow), as S3 orders them
-- by time: see `objects_versions`. A write's version is the newest: its
-- time is now, or (if its transaction began before the key's newest
-- version was written: it waited for K(b,k)) just after that version's
-- time, so that no two of a key's versions written to it have the same
-- time (and so none of their replicas, which are ordered by it too). A
-- replica (`p_replica`: see `cairn_replica`) keeps its source's time, and
-- lands where that puts it, which is below the key's versions that are
-- newer: it's current only if none is. Under K(b,k).
CREATE OR REPLACE FUNCTION pg_temp.cairn_version_time(p_bucket text, p_key text, p_replica jsonb,
    OUT modified timestamptz, OUT latest boolean)
LANGUAGE plpgsql AS $$
BEGIN
    IF p_replica IS NULL OR p_replica ->> 'last_modified' IS NULL THEN
        modified := greatest(NOW(),
            (SELECT max(o.last_modified) FROM objects o WHERE o.bucket = p_bucket AND o.key = p_key)
                + interval '1 microsecond');
        latest := true;
    ELSE
        modified := (p_replica ->> 'last_modified')::timestamptz;
        latest := NOT EXISTS (
            SELECT 1 FROM objects o WHERE o.bucket = p_bucket AND o.key = p_key AND o.last_modified > modified
        );
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
    WHERE id = (SELECT id FROM objects WHERE bucket = p_bucket AND key = p_key
                ORDER BY last_modified DESC, id DESC LIMIT 1);
END
$$;

-- Writes a new object version as the key's current version, the way S3 lands
-- a write in a bucket with the given versioning state, with its content type,
-- metadata (see `s3::metadata`) and encryption (see `s3::sse`): its SSE-C key
-- check, or its SSE-KMS (or SSE-S3, if `p_sse_s3`) key, data key, sealed
-- object key and context (NULLs for what it isn't), and its checksum (see
-- `s3::checksums`; NULLs for none), its tags (see `s3::tags`), and its
-- Object Lock (see `s3::object_lock`): a retention (`p_lock_mode` and
-- `p_lock_until`; NULLs for the bucket's default retention, if it has one)
-- and a legal hold (NULL for none set). `p_size`
-- is its plaintext's. `p_new_version_id` is
-- the fresh version ID to use if the bucket is versioned. Returns the new
-- row's id, and the version ID to report (NULL unless versioning is enabled).
-- The caller holds B(b) shared (which gave it the versioning state), K(b,k), and
-- X(x) on the blobs of the parts `cairn_freed_by_put` names.
-- Records the event a change to key `p_key` makes, for each of the
-- bucket's notification configurations it matches (see `notifications`), in
-- the change's own transaction: so a change that commits has its events, and
-- one that doesn't has none. What the change is comes from the caller, as
-- `cairn.notify` (a JSON object, transaction-local, see `cairn_notify_start`):
-- who made it and how, or nothing, for a change that makes no events.
-- `p_event` is the event: `ObjectCreated` (made what `created` says: Put,
-- Post, Copy or CompleteMultipartUpload), `ObjectRemoved:…`, or
-- `ObjectTagging` (`tagging` says Put or Delete); a lifecycle's
-- (`"source": "lifecycle"`) removals are `LifecycleExpiration:…`.
--
-- The configurations are read without a lock: a change racing a new
-- configuration follows either the old one or the new, as its statement
-- sees them, which is all S3 promises too. The sequencer is drawn under the
-- key's K, so a key's events' sequencers grow with its changes' commit
-- order. The outbox has no foreign keys (rule B).
CREATE OR REPLACE FUNCTION pg_temp.cairn_notify(
    p_bucket text, p_key text, p_event text, p_size bigint, p_etag text, p_version_id text
) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_context jsonb;
    v_event text := p_event;
    v_sequencer bigint;
BEGIN
    IF coalesce(current_setting('cairn.notify', true), '') = '' THEN
        RETURN;
    END IF;
    PERFORM 1 FROM bucket_notifications n WHERE n.bucket = p_bucket LIMIT 1;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    -- Not the write's ACL, which its events don't tell.
    v_context := current_setting('cairn.notify', true)::jsonb - 'acl';
    IF v_event = 'ObjectCreated' THEN
        v_event := 'ObjectCreated:' || coalesce(v_context ->> 'created', 'Put');
    ELSIF v_event = 'ObjectTagging' THEN
        v_event := 'ObjectTagging:' || coalesce(v_context ->> 'tagging', 'Put');
    ELSIF v_context ->> 'source' = 'lifecycle' AND v_event LIKE 'ObjectRemoved:%' THEN
        v_event := 'LifecycleExpiration:' || substring(v_event FROM 15);
    END IF;
    v_sequencer := nextval('notification_sequencers');
    INSERT INTO notification_events (bucket, key, event, size, etag, version_id, sequencer, context,
                                     config_id, topic_arn)
    SELECT p_bucket, p_key, v_event, p_size, p_etag, nullif(p_version_id, 'null'), v_sequencer,
           v_context, n.id, n.topic_arn
    FROM bucket_notifications n
    WHERE n.bucket = p_bucket
      AND ('s3:' || v_event = ANY (n.events) OR 's3:' || split_part(v_event, ':', 1) || ':*' = ANY (n.events))
      AND starts_with(p_key, n.prefix)
      AND (n.suffix = '' OR right(p_key, length(n.suffix)) = n.suffix)
    ORDER BY n.position;
END
$$;

-- Sets what the transaction's changes are, for their events (`cairn_notify`):
-- `p_notify` (NULL or empty: they make none).
CREATE OR REPLACE FUNCTION pg_temp.cairn_notify_start(p_notify text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM set_config('cairn.notify', coalesce(p_notify, ''), true);
END
$$;

-- What the transaction's write is a replica of, if it's one (see
-- `replication`): its `cairn.notify` says so (`replica`), with the
-- source's version ID, last-modified time, and (for a plain source) ETag,
-- which the replica keeps, and, for an SSE-C source, the bucket its sealed
-- key is sealed for (`sse_c_bucket`). NULL for any other write.
CREATE OR REPLACE FUNCTION pg_temp.cairn_replica() RETURNS jsonb LANGUAGE plpgsql AS $$
BEGIN
    IF coalesce(current_setting('cairn.notify', true), '') = '' THEN
        RETURN NULL;
    END IF;
    RETURN current_setting('cairn.notify', true)::jsonb -> 'replica';
END
$$;

-- The destinations a version of key `p_key` goes to by the replication
-- configuration `p_config` (see `replication`), and the rule that sends it
-- to each: of the enabled rules whose filter it matches (a prefix of the
-- key, tags it has, `p_tags`, in their stored form: see `s3::tags`), the one
-- of highest priority (then the first) for each destination. A delete
-- marker (`p_marker`) goes only where that rule replicates delete markers,
-- and an SSE-KMS object (`p_encryption` 'kms') only where it replicates
-- those.
CREATE OR REPLACE FUNCTION pg_temp.cairn_replication_targets(
    p_config jsonb, p_key text, p_marker boolean, p_tags text, p_encryption text
) RETURNS TABLE (destination text, rule_id text) LANGUAGE sql STABLE AS $$
    WITH matching AS (
        SELECT r ->> 'id' AS id, coalesce((r ->> 'priority')::int, 0) AS priority,
               coalesce(r -> 'destination' ->> 'target', r -> 'destination' ->> 'bucket') AS destination,
               coalesce((r ->> 'delete_markers')::boolean, false) AS markers,
               coalesce((r ->> 'kms_objects')::boolean, false) AS kms, t.n
        FROM jsonb_array_elements(p_config -> 'rules') WITH ORDINALITY AS t(r, n)
        WHERE coalesce((r ->> 'enabled')::boolean, false)
          AND starts_with(p_key, coalesce(r ->> 'prefix', ''))
          AND ARRAY(SELECT jsonb_array_elements_text(coalesce(r -> 'stored_tags', '[]'::jsonb)))
              <@ CASE WHEN coalesce(p_tags, '') = '' THEN '{}'::text[] ELSE string_to_array(p_tags, '&') END
    ), chosen AS (
        SELECT DISTINCT ON (destination) * FROM matching ORDER BY destination, priority DESC, n
    )
    SELECT c.destination, c.id FROM chosen c
    WHERE CASE WHEN p_marker THEN c.markers
               WHEN p_encryption = 'kms' THEN c.kms
               ELSE true END
$$;

-- Queues the new version `p_version_id` of key `p_key` (row `p_object_id`;
-- `p_marker` if it's a delete marker) for each destination of the bucket's
-- replication configuration that a rule sends it to (see
-- `cairn_replication_targets`). A queued object is PENDING. Replicas
-- aren't replicated again, nor are a lifecycle's
-- delete markers (as in S3), nor a null version, which only a bucket that
-- isn't versioned has (I15).
--
-- In the write's own transaction, under its K(b,k), so that a version
-- that commits is queued, and a key's versions are queued in the order
-- they're written. The configuration is read unlocked, as the
-- notification configurations are (I14). The queue has no foreign keys
-- (rule B).
CREATE OR REPLACE FUNCTION pg_temp.cairn_replicate(
    p_bucket text, p_key text, p_object_id bigint, p_version_id text, p_marker boolean,
    p_tags text, p_encryption text
) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_config jsonb;
    v_queued bigint;
BEGIN
    IF p_version_id IS NULL OR p_version_id = 'null' OR pg_temp.cairn_replica() IS NOT NULL THEN
        RETURN;
    END IF;
    -- Nor are a lifecycle's delete markers, as in S3.
    IF p_marker AND coalesce(current_setting('cairn.notify', true), '') <> ''
       AND current_setting('cairn.notify', true)::jsonb ->> 'source' = 'lifecycle' THEN
        RETURN;
    END IF;
    SELECT replication::jsonb INTO v_config FROM buckets WHERE name = p_bucket AND replication IS NOT NULL;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    INSERT INTO replication_queue (bucket, key, version_id, marker, destination, rule_id)
    SELECT p_bucket, p_key, p_version_id, p_marker, t.destination, t.rule_id
    FROM pg_temp.cairn_replication_targets(v_config, p_key, p_marker, p_tags, p_encryption) t;
    GET DIAGNOSTICS v_queued = ROW_COUNT;
    IF v_queued > 0 AND NOT p_marker THEN
        UPDATE objects SET replication_status = 'PENDING' WHERE id = p_object_id;
    END IF;
END
$$;

-- Queues the deletion of version `p_version_id` of key `p_key` (`p_marker`
-- if it was a delete marker; its tags `p_tags`) for each destination of the
-- bucket's replication configuration whose rule replicates deletions of
-- versions (MinIO's `DeleteReplication`, see `replication::config`) and
-- would send it there: of the enabled rules whose filter it matches, the one
-- of highest priority for each destination, as `cairn_replication_targets`
-- picks them. Not a deletion that's replication's itself (see
-- `replication::inbound`), nor a lifecycle's, which each cluster does by
-- its own rules. In the deletion's own transaction, under its K(b,k), as
-- `cairn_replicate` queues writes (I15).
CREATE OR REPLACE FUNCTION pg_temp.cairn_replicate_purge(
    p_bucket text, p_key text, p_version_id text, p_marker boolean, p_tags text
) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_config jsonb;
BEGIN
    IF p_version_id IS NULL OR p_version_id = 'null' OR pg_temp.cairn_replica() IS NOT NULL THEN
        RETURN;
    END IF;
    IF coalesce(current_setting('cairn.notify', true), '') <> ''
       AND current_setting('cairn.notify', true)::jsonb ->> 'source' = 'lifecycle' THEN
        RETURN;
    END IF;
    SELECT replication::jsonb INTO v_config FROM buckets WHERE name = p_bucket AND replication IS NOT NULL;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    INSERT INTO replication_queue (bucket, key, version_id, marker, destination, rule_id, purge)
    SELECT p_bucket, p_key, p_version_id, p_marker, c.destination, c.id, true
    FROM (
        SELECT DISTINCT ON (destination) * FROM (
            SELECT r ->> 'id' AS id, coalesce((r ->> 'priority')::int, 0) AS priority,
                   coalesce(r -> 'destination' ->> 'target', r -> 'destination' ->> 'bucket') AS destination,
                   coalesce((r ->> 'delete_versions')::boolean, false) AS deletes, t.n
            FROM jsonb_array_elements(v_config -> 'rules') WITH ORDINALITY AS t(r, n)
            WHERE coalesce((r ->> 'enabled')::boolean, false)
              AND starts_with(p_key, coalesce(r ->> 'prefix', ''))
              AND ARRAY(SELECT jsonb_array_elements_text(coalesce(r -> 'stored_tags', '[]'::jsonb)))
                  <@ CASE WHEN coalesce(p_tags, '') = '' THEN '{}'::text[] ELSE string_to_array(p_tags, '&') END
        ) matching
        ORDER BY destination, priority DESC, n
    ) c
    WHERE c.deletes;
END
$$;

-- The owner and ACL the transaction's write gives its version (see
-- `s3::acl`): its `cairn.notify` says so (`acl`: `owner`, the account's ID,
-- and `grants`, as `objects.acl` has them), unless they're its bucket
-- owner's full control alone, the default (NULL).
CREATE OR REPLACE FUNCTION pg_temp.cairn_write_acl() RETURNS jsonb LANGUAGE plpgsql AS $$
BEGIN
    IF coalesce(current_setting('cairn.notify', true), '') = '' THEN
        RETURN NULL;
    END IF;
    RETURN current_setting('cairn.notify', true)::jsonb -> 'acl';
END
$$;

-- Records that the transaction's write is a Batch Operations job's task's
-- (see `batch::copy`), if its `cairn.notify` says it is (`batch_task`: the
-- job's ID, and the task's ordinal), in the transaction that writes its
-- version: so a task done again, after a node died between the write and
-- saving where its job had got to, is found done, and never makes a second
-- version. A task that's recorded already (by a write that committed
-- meanwhile) is refused, which rolls the write back. Under the job's row's
-- KEY SHARE lock (its foreign key), which only deleting the job, once
-- it's ended, conflicts with.
CREATE OR REPLACE FUNCTION pg_temp.cairn_batch_task() RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_task jsonb;
BEGIN
    IF coalesce(current_setting('cairn.notify', true), '') = '' THEN
        RETURN;
    END IF;
    v_task := current_setting('cairn.notify', true)::jsonb -> 'batch_task';
    IF v_task IS NULL THEN
        RETURN;
    END IF;
    INSERT INTO batch_job_copies (job_id, task)
    VALUES ((v_task ->> 'job')::uuid, (v_task ->> 'task')::bigint)
    ON CONFLICT DO NOTHING;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'cairn: task % of batch job % is done already', v_task ->> 'task', v_task ->> 'job';
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION pg_temp.cairn_put_version(
    p_bucket text, p_key text, p_versioning text, p_size bigint, p_etag text,
    p_content_type text, p_metadata text, p_sse_c_key bytea, p_kms_key_id text,
    p_kms_data_key text, p_kms_sealed bytea, p_kms_context text, p_sse_s3 boolean,
    p_checksum_algorithm text, p_checksum_type text, p_checksum text, p_tags text,
    p_new_version_id text, p_lock_mode text, p_lock_until timestamptz, p_legal_hold boolean,
    p_storage_class text,
    OUT id bigint, OUT version_id text
) LANGUAGE plpgsql AS $$
DECLARE
    v_version_id text;
    v_mode text := p_lock_mode;
    v_until timestamptz := p_lock_until;
    v_replica jsonb := pg_temp.cairn_replica();
    v_modified timestamptz;
    v_latest boolean;
    v_acl jsonb := pg_temp.cairn_write_acl();
BEGIN
    -- The bucket's default retention, as of the write, if it asks for none.
    IF v_mode IS NULL THEN
        SELECT b.lock_mode,
               NOW() + make_interval(years => coalesce(b.lock_years, 0), days => coalesce(b.lock_days, 0))
        INTO v_mode, v_until
        FROM buckets b WHERE b.name = p_bucket AND b.object_lock AND b.lock_mode IS NOT NULL;
    END IF;
    -- A replica keeps its source's version ID, which only a versioned
    -- bucket has, and lands once (the worker checks first; this is the
    -- backstop, under K(b,k)).
    IF v_replica IS NOT NULL AND p_versioning <> 'enabled' THEN
        RAISE EXCEPTION 'cairn: a replica''s destination % isn''t versioned', p_bucket;
    END IF;
    IF p_versioning = 'enabled' THEN
        v_version_id := coalesce(v_replica ->> 'version_id', p_new_version_id);
        IF v_replica IS NOT NULL AND EXISTS (
            SELECT 1 FROM objects o WHERE o.bucket = p_bucket AND o.key = p_key AND o.version_id = v_version_id
        ) THEN
            RAISE EXCEPTION 'cairn: version % of %/% is replicated already', v_version_id, p_bucket, p_key;
        END IF;
    ELSE
        -- The null version is replaced wherever it sits among the key's versions.
        PERFORM pg_temp.cairn_remove_null_version(p_bucket, p_key);
        v_version_id := 'null';
    END IF;
    PERFORM pg_temp.cairn_batch_task();
    SELECT * INTO v_modified, v_latest FROM pg_temp.cairn_version_time(p_bucket, p_key, v_replica);
    IF v_latest THEN
        PERFORM pg_temp.cairn_demote_current(p_bucket, p_key);
    END IF;
    INSERT INTO objects (bucket, key, version_id, is_latest, is_delete_marker,
                         size, etag, content_type, metadata, sse_c_key, sse_kms_key_id,
                         sse_kms_data_key, sse_kms_sealed, sse_kms_context, sse_s3,
                         checksum_algorithm, checksum_type, checksum, tags, last_modified,
                         retain_mode, retain_until, legal_hold, storage_class, replication_status,
                         sse_c_bucket, owner_id, acl)
    VALUES (p_bucket, p_key, v_version_id, v_latest, false, p_size,
            -- An encrypted version's ETag is stored as it's written (sealed,
            -- for SSE-S3): a replica's source's is kept only for a plain one.
            CASE WHEN p_sse_c_key IS NULL AND p_kms_key_id IS NULL AND NOT coalesce(p_sse_s3, false)
                 THEN coalesce(v_replica ->> 'etag', p_etag) ELSE p_etag END, p_content_type,
            p_metadata, p_sse_c_key, p_kms_key_id, p_kms_data_key, p_kms_sealed,
            p_kms_context, p_sse_s3, p_checksum_algorithm, p_checksum_type, p_checksum, p_tags,
            v_modified, v_mode, v_until,
            p_legal_hold, p_storage_class, CASE WHEN v_replica IS NOT NULL THEN 'REPLICA' END,
            CASE WHEN p_sse_c_key IS NOT NULL THEN v_replica ->> 'sse_c_bucket' END,
            v_acl ->> 'owner', v_acl ->> 'grants')
    RETURNING objects.id INTO id;
    -- A write's version ID is reported only where it's a new one: S3 reports
    -- none for the null version (unversioned or suspended).
    version_id := CASE WHEN p_versioning = 'enabled' THEN v_version_id END;
    PERFORM pg_temp.cairn_notify(p_bucket, p_key, 'ObjectCreated', p_size, p_etag, version_id);
    PERFORM pg_temp.cairn_replicate(p_bucket, p_key, id, version_id, false, p_tags,
        CASE WHEN p_sse_c_key IS NOT NULL THEN 'customer'
             WHEN p_kms_key_id IS NOT NULL AND NOT coalesce(p_sse_s3, false) THEN 'kms'
             ELSE 'plain' END);
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
    v_replica jsonb := pg_temp.cairn_replica();
    v_modified timestamptz;
    v_latest boolean;
BEGIN
    delete_marker := false;
    IF p_version_id IS NOT NULL THEN
        SELECT o.id, o.is_latest, o.is_delete_marker, o.tags INTO v_row FROM objects o
        WHERE o.bucket = p_bucket AND o.key = p_key AND o.version_id = p_version_id;
        IF FOUND THEN
            delete_marker := v_row.is_delete_marker;
            PERFORM pg_temp.cairn_remove_version(v_row.id);
            IF v_row.is_latest THEN
                PERFORM pg_temp.cairn_promote_newest(p_bucket, p_key);
            END IF;
            PERFORM pg_temp.cairn_replicate_purge(p_bucket, p_key, p_version_id, v_row.is_delete_marker, v_row.tags);
        END IF;
        version_id := p_version_id;
        PERFORM pg_temp.cairn_notify(p_bucket, p_key,
            CASE WHEN delete_marker THEN 'ObjectRemoved:DeleteMarkerCreated' ELSE 'ObjectRemoved:Delete' END,
            NULL, NULL, p_version_id);
        RETURN;
    END IF;
    IF p_versioning = 'unversioned' THEN
        PERFORM pg_temp.cairn_remove_null_version(p_bucket, p_key);
        version_id := NULL;
        PERFORM pg_temp.cairn_notify(p_bucket, p_key, 'ObjectRemoved:Delete', NULL, NULL, NULL);
        RETURN;
    ELSIF p_versioning = 'enabled' THEN
        v_marker := p_marker_id;
    ELSE
        PERFORM pg_temp.cairn_remove_null_version(p_bucket, p_key);
        v_marker := 'null';
    END IF;
    -- A replica of a delete marker as a replica of an object is (see
    -- `cairn_put_version`).
    IF v_replica IS NOT NULL AND (p_versioning <> 'enabled' OR EXISTS (
        SELECT 1 FROM objects o WHERE o.bucket = p_bucket AND o.key = p_key AND o.version_id = v_marker
    )) THEN
        RAISE EXCEPTION 'cairn: delete marker % of %/% can''t be replicated, or is already', v_marker, p_bucket, p_key;
    END IF;
    SELECT * INTO v_modified, v_latest FROM pg_temp.cairn_version_time(p_bucket, p_key, v_replica);
    IF v_latest THEN
        PERFORM pg_temp.cairn_demote_current(p_bucket, p_key);
    END IF;
    INSERT INTO objects (bucket, key, version_id, is_latest, is_delete_marker,
                         size, etag, content_type, last_modified, replication_status)
    VALUES (p_bucket, p_key, v_marker, v_latest, true, 0, NULL, NULL, v_modified,
            CASE WHEN v_replica IS NOT NULL THEN 'REPLICA' END);
    version_id := v_marker;
    delete_marker := true;
    PERFORM pg_temp.cairn_notify(p_bucket, p_key, 'ObjectRemoved:DeleteMarkerCreated', NULL,
                                 '"d41d8cd98f00b204e9800998ecf8427e"', v_marker);
    PERFORM pg_temp.cairn_replicate(p_bucket, p_key, NULL, v_marker, true, NULL, NULL);
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
-- object's checksum, tags and Object Lock.
CREATE OR REPLACE FUNCTION pg_temp.cairn_commit_object(
    p_blob uuid, p_nodes int[], p_shards smallint[], p_size bigint, p_block_size int,
    p_data_shards smallint, p_parity_shards smallint, p_stripe_unit int, p_shard_crcs bigint[],
    p_data_crc bigint, p_etag text, p_part_etag text, p_plain_size bigint, p_enc_salt bytea,
    p_bucket text, p_key text, p_content_type text, p_metadata text, p_sse_c_key bytea,
    p_kms_key_id text, p_kms_data_key text, p_kms_sealed bytea, p_kms_context text,
    p_sse_s3 boolean, p_checksum_algorithm text, p_checksum_type text, p_checksum text,
    p_tags text, p_conditional boolean, p_expected bigint, p_new_version_id text,
    p_lock_mode text, p_lock_until timestamptz, p_legal_hold boolean, p_notify text DEFAULT NULL,
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
    PERFORM pg_temp.cairn_notify_start(p_notify);
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
        p_sse_s3, p_checksum_algorithm, p_checksum_type, p_checksum, p_tags, p_new_version_id,
        p_lock_mode, p_lock_until, p_legal_hold,
        (SELECT b.storage_class FROM blobs b WHERE b.blob_id = p_blob));
    version_id := v.version_id;
    SELECT to_char(o.last_modified AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS".000Z"')
    INTO last_modified FROM objects o WHERE o.id = v.id;
    INSERT INTO parts (blob_id, blob_offset, size, etag, crc64nvme, object_id, upload_id,
                       part_number, plain_size, enc_salt, created_at)
    VALUES (p_blob, 0, p_size, p_part_etag, p_data_crc, v.id, NULL, 1, p_plain_size, p_enc_salt,
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
-- copy read it ('source_changed') or the bucket is gone ('no_such_bucket'),
-- or a conditional copy (If-Match, If-None-Match) was decided against
-- another version than the current one (`p_expected`, NULL for none;
-- 'stale', for the caller to decide again).
-- Takes B(b) shared, K(b,k), then X: the source's blobs shared, and those of
-- the version it replaces. The copy's checksum is Cairn's to work out; its
-- parts keep the source's parts' checksums if `p_part_checksums` (they're in
-- the copy's algorithm, and open under its key). Its storage class is
-- `p_storage_class`, which must be its source's or one ranked below it (see
-- `classes`), or NULL for its source's.
CREATE OR REPLACE FUNCTION pg_temp.cairn_copy_object(
    p_source bigint, p_part_ids bigint[], p_part_sizes bigint[],
    p_bucket text, p_key text, p_size bigint, p_etag text, p_content_type text,
    p_metadata text, p_sse_c_key bytea, p_kms_key_id text, p_kms_data_key text,
    p_kms_sealed bytea, p_kms_context text, p_sse_s3 boolean, p_checksum_algorithm text,
    p_checksum_type text, p_checksum text, p_tags text, p_part_checksums boolean,
    p_new_version_id text, p_lock_mode text, p_lock_until timestamptz, p_legal_hold boolean,
    p_conditional boolean, p_expected bigint, p_notify text DEFAULT NULL,
    p_storage_class text DEFAULT NULL,
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
    PERFORM pg_temp.cairn_notify_start(p_notify);
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
        p_sse_s3, p_checksum_algorithm, p_checksum_type, p_checksum, p_tags, p_new_version_id,
        p_lock_mode, p_lock_until, p_legal_hold,
        -- The class it asks for, which its source's blobs stand in for (it's
        -- its source's, or below it: see `classes`), else its source's.
        coalesce(p_storage_class, (SELECT o.storage_class FROM objects o WHERE o.id = p_source), 'STANDARD'));
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
    p_conditional boolean, p_expected bigint, p_new_version_id text, p_notify text DEFAULT NULL,
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
    PERFORM pg_temp.cairn_notify_start(p_notify);
    reap_blob := '{}';
    reap_node := '{}';
    reap_peer := '{}';
    -- An upload's bucket exists as long as the upload does.
    v_versioning := pg_temp.cairn_lock_bucket(p_bucket);
    -- The upload defines the object's content type, metadata, encryption,
    -- tags and Object Lock (but the bucket's default retention, as of now).
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
        u.sse_s3, p_checksum_algorithm, p_checksum_type, p_checksum, u.tags, p_new_version_id,
        u.retain_mode, u.retain_until, u.legal_hold, u.storage_class);
    version_id := v.version_id;
    -- The upload's owner and ACL, as it was created with.
    UPDATE objects SET upload_id = p_upload, owner_id = u.owner_id, acl = u.acl WHERE id = v.id;
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
-- version ID per target, for a delete marker in an enabled bucket. A named
-- version that Object Lock keeps (`cairn_locked`, bypassing governance mode
-- where `p_bypass` says so) isn't deleted, and is `locked` instead (with no
-- version ID or delete marker to report). A conditional delete (If-Match,
-- checked by the caller against the version it read) names that version's
-- row in `p_expected`: unless it's still its key's current version, under
-- K(b,k), nothing is deleted and the status is 'stale', for the caller to
-- check again. In a bucket with MFA delete, which B(b) keeps as it is,
-- nothing is deleted and the status is 'mfa' unless the request gave the
-- root's code (`p_mfa`, as `mfa::Presented::as_db`) if any target names a
-- version, and gave no code that isn't valid at all (as S3's DeleteObjects
-- fails whole).
CREATE OR REPLACE FUNCTION pg_temp.cairn_delete_objects(
    p_bucket text, p_keys text[], p_version_ids text[], p_marker_ids text[], p_bypass boolean[],
    p_expected bigint[] DEFAULT '{}', p_notify text DEFAULT NULL, p_mfa boolean DEFAULT NULL,
    OUT status text, OUT version_ids text[], OUT delete_markers boolean[], OUT locked boolean[],
    OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_versioning text;
    v_freed bigint[] := '{}';
    f record;
    v_locked uuid[];
    d record;
    v_kept boolean;
BEGIN
    PERFORM pg_temp.cairn_notify_start(p_notify);
    reap_blob := '{}';
    reap_node := '{}';
    reap_peer := '{}';
    version_ids := '{}';
    delete_markers := '{}';
    locked := '{}';
    v_versioning := pg_temp.cairn_lock_bucket(p_bucket);
    IF v_versioning IS NULL THEN
        status := 'no_such_bucket';
        RETURN;
    END IF;
    IF (SELECT mfa_delete FROM buckets WHERE name = p_bucket) AND p_mfa IS NOT TRUE
       AND (p_mfa IS NOT NULL OR EXISTS (SELECT 1 FROM unnest(p_version_ids) v WHERE v IS NOT NULL)) THEN
        status := 'mfa';
        RETURN;
    END IF;
    PERFORM pg_temp.cairn_lock_keys(p_bucket, p_keys);
    FOR i IN 1 .. coalesce(cardinality(p_expected), 0) LOOP
        CONTINUE WHEN p_expected[i] IS NULL;
        PERFORM 1 FROM objects o
        WHERE o.id = p_expected[i] AND o.bucket = p_bucket AND o.key = p_keys[i]
          AND o.is_latest AND NOT o.is_delete_marker;
        IF NOT FOUND THEN
            status := 'stale';
            RETURN;
        END IF;
    END LOOP;
    -- Every version the targets name or may remove exists now, under the
    -- keys' locks; the deletes only add delete markers, which have no parts.
    FOR i IN 1 .. coalesce(cardinality(p_keys), 0) LOOP
        v_kept := p_version_ids[i] IS NOT NULL AND pg_temp.cairn_locked(
            (SELECT o.id FROM objects o
             WHERE o.bucket = p_bucket AND o.key = p_keys[i] AND o.version_id = p_version_ids[i]),
            coalesce(p_bypass[i], false));
        locked := locked || v_kept;
        CONTINUE WHEN v_kept;
        v_freed := v_freed || pg_temp.cairn_freed_by_delete(
            p_bucket, p_keys[i], v_versioning, p_version_ids[i]);
    END LOOP;
    SELECT * INTO f FROM pg_temp.cairn_freeable(v_freed);
    v_locked := pg_temp.cairn_lock_blobs(f.blobs, f.exclusive);
    PERFORM pg_temp.cairn_check_on(v_freed, v_locked);
    FOR i IN 1 .. coalesce(cardinality(p_keys), 0) LOOP
        IF locked[i] THEN
            version_ids := version_ids || NULL::text;
            delete_markers := delete_markers || false;
            CONTINUE;
        END IF;
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
-- ordered against every write and delete in the bucket (I2), and against
-- enabling Object Lock (T38). Sets the versioning state (`p_versioning`,
-- NULL to keep it) and MFA delete (`p_mfa_delete`, NULL to keep it). With
-- MFA delete enabled, or to enable it, the request must have given the
-- root's code (`p_mfa`, as `mfa::Presented::as_db`), else 'mfa'. Returns
-- 'set', 'no_such_bucket', 'mfa', 'lifecycle' to enable MFA delete on a
-- bucket with a lifecycle configuration (which it can't have), 'locked'
-- for a bucket with Object Lock, which stays versioned, or 'replicated'
-- for a bucket with a replication configuration, which does too (I15).
CREATE OR REPLACE FUNCTION pg_temp.cairn_set_versioning(
    p_bucket text, p_versioning text, p_mfa_delete boolean DEFAULT NULL, p_mfa boolean DEFAULT NULL
) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    b record;
BEGIN
    SELECT object_lock, lifecycle IS NOT NULL AS lifecycle, coalesce(mfa_delete, false) AS mfa_delete,
           replication IS NOT NULL AS replicated
    INTO b FROM buckets WHERE name = p_bucket FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'no_such_bucket';
    END IF;
    IF (b.mfa_delete OR p_mfa_delete) AND p_mfa IS NOT TRUE THEN
        RETURN 'mfa';
    END IF;
    IF p_mfa_delete AND b.lifecycle THEN
        RETURN 'lifecycle';
    END IF;
    IF p_versioning <> 'enabled' AND b.object_lock THEN
        RETURN 'locked';
    END IF;
    IF p_versioning <> 'enabled' AND b.replicated THEN
        RETURN 'replicated';
    END IF;
    UPDATE buckets SET versioning = coalesce(p_versioning, versioning), mfa_delete = coalesce(p_mfa_delete, mfa_delete)
    WHERE name = p_bucket;
    RETURN 'set';
END
$$;

-- T38: PutObjectLockConfiguration: enables Object Lock on the bucket, which
-- must be versioned ('not_versioned'), and sets its default retention (a
-- mode, and days or years; NULLs for none). Takes the bucket's row as a
-- plain UPDATE does, which orders it against a change of versioning (T10),
-- and checks the versioning state under it. Writes read the default as they
-- land (`cairn_put_version`); enabling Object Lock only lets them take
-- locks, which they may as soon as it's committed. 'set', 'not_versioned'
-- or 'no_such_bucket'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_set_object_lock(
    p_bucket text, p_mode text, p_days int, p_years int
) RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM buckets WHERE name = p_bucket FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RETURN 'no_such_bucket';
    END IF;
    IF (SELECT versioning FROM buckets WHERE name = p_bucket) <> 'enabled' THEN
        RETURN 'not_versioned';
    END IF;
    UPDATE buckets SET object_lock = true, lock_mode = p_mode, lock_days = p_days, lock_years = p_years
    WHERE name = p_bucket;
    RETURN 'set';
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
--                 at least `p_newer` versions newer than it, and not kept by
--                 Object Lock (as in S3, lifecycle rules never bypass it);
--                 removed for good.
--
-- A 'current' or 'noncurrent' target must also still have the tags the sweep
-- read, `p_tags` (stored form): a version re-tagged since may no longer match
-- the rule's filter. A tag change doesn't make a new version, but it takes
-- K(b,k) (T22), so it can't happen while this holds the key.
--
-- `p_generation` is the generation of the configuration the sweep follows:
-- if the bucket's is another (it was changed or deleted since), nothing is
-- done
-- ('changed'). Returns 'expired', with which targets were, or
-- 'no_such_bucket'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_lifecycle_expire(
    p_bucket text, p_generation bigint, p_keys text[], p_ids bigint[], p_version_ids text[],
    p_kinds text[], p_successors bigint[], p_newer int[], p_marker_ids text[], p_tags text[],
    p_notify text DEFAULT NULL,
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
    PERFORM pg_temp.cairn_notify_start(p_notify);
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
            v_ok := pg_temp.cairn_current_version(p_bucket, p_keys[i]) IS NOT DISTINCT FROM p_ids[i]
                AND EXISTS (SELECT 1 FROM objects WHERE id = p_ids[i] AND tags = p_tags[i]);
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
                  AND tags = p_tags[i]
            ) AND NOT pg_temp.cairn_locked(p_ids[i], false) AND (
                SELECT n.id FROM objects n, objects v
                WHERE v.id = p_ids[i] AND n.bucket = p_bucket AND n.key = p_keys[i]
                  AND (n.last_modified, n.id) > (v.last_modified, v.id)
                ORDER BY n.last_modified, n.id LIMIT 1
            ) IS NOT DISTINCT FROM p_successors[i] AND (
                SELECT count(*) FROM objects n, objects v
                WHERE v.id = p_ids[i] AND n.bucket = p_bucket AND n.key = p_keys[i]
                  AND (n.last_modified, n.id) > (v.last_modified, v.id)
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

-- T72: a lifecycle sweep's transitions (see `lifecycle`). Takes B(b)
-- shared and K(b,k) for every key, as T17 does, and nothing else: it
-- changes only versions' storage classes, which their blobs stand in for
-- already (see `classes`), and moves no bytes. Each target is a version the
-- sweep found due, by its row id, and the class it's due to go to,
-- checked again under the locks: it's still there, not a delete marker,
-- current if `p_current` (and noncurrent if not), with the tags the sweep
-- read (`p_tags`, as T17 checks them), and of a class ranked above
-- `p_classes`. Object Lock doesn't keep a version from it, as in S3.
--
-- The blobs the transitioned versions' parts are on go into the garbage
-- log, which nothing but folds reads: the next fold works out the bytes on
-- them that are now misplaced (`cairn_refresh_dead_size`), which the
-- packer then moves.
--
-- 'changed' if the bucket's configuration isn't of `p_generation` anymore,
-- 'no_such_bucket', or 'transitioned', with which targets were.
CREATE OR REPLACE FUNCTION pg_temp.cairn_lifecycle_transition(
    p_bucket text, p_generation bigint, p_keys text[], p_ids bigint[], p_classes text[],
    p_current boolean[], p_tags text[], p_notify text DEFAULT NULL,
    OUT status text, OUT applied boolean[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_ok boolean;
    v_ids bigint[] := '{}';
    r record;
BEGIN
    PERFORM pg_temp.cairn_notify_start(p_notify);
    applied := '{}';
    IF pg_temp.cairn_lock_bucket(p_bucket) IS NULL THEN
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
    FOR i IN 1 .. coalesce(cardinality(p_keys), 0) LOOP
        v_ok := EXISTS (
            SELECT 1 FROM objects o
            JOIN storage_classes oc ON oc.name = o.storage_class
            JOIN storage_classes tc ON tc.name = p_classes[i]
            WHERE o.id = p_ids[i] AND o.bucket = p_bucket AND o.key = p_keys[i]
              AND NOT o.is_delete_marker AND o.is_latest = p_current[i] AND o.tags = p_tags[i]
              AND tc.rank < oc.rank
        );
        applied := applied || v_ok;
        IF v_ok THEN
            v_ids := v_ids || p_ids[i];
        END IF;
    END LOOP;
    UPDATE objects o SET storage_class = t.class
    FROM unnest(p_ids, p_classes, applied) AS t(id, class, ok)
    WHERE o.id = t.id AND t.ok;
    INSERT INTO blob_garbage (blob_id, size)
    SELECT DISTINCT p.blob_id, 0 FROM parts p WHERE p.object_id = ANY(v_ids);
    FOR r IN SELECT o.key, o.size, o.etag, o.version_id FROM objects o WHERE o.id = ANY(v_ids) LOOP
        PERFORM pg_temp.cairn_notify(p_bucket, r.key, 'LifecycleTransition', r.size, r.etag, r.version_id);
    END LOOP;
    status := 'transitioned';
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

-- T22: PutObjectTagging and DeleteObjectTagging: sets the tags (stored form,
-- see `s3::tags`; empty for none) of the version `p_version_id` of the key,
-- or of its current version if NULL, in place: it's no new version, and its
-- ETag and last-modified time stay. Takes B(b) shared and K(b,k): object rows
-- only change under K (I1), and a lifecycle sweep re-checks a version's tags
-- under it (T17). Returns 'tagged', or 'no_such_bucket', 'no_such_key',
-- 'no_such_version', or 'delete_marker' (which has no tags); and the
-- bucket's versioning state and the version's ID (for the last two, and
-- 'tagged'), which the response reports.
CREATE OR REPLACE FUNCTION pg_temp.cairn_set_tags(
    p_bucket text, p_key text, p_version_id text, p_tags text, p_notify text DEFAULT NULL,
    OUT status text, OUT versioning text, OUT version_id text
) LANGUAGE plpgsql AS $$
DECLARE
    o record;
BEGIN
    PERFORM pg_temp.cairn_notify_start(p_notify);
    versioning := pg_temp.cairn_lock_bucket(p_bucket);
    IF versioning IS NULL THEN
        status := 'no_such_bucket';
        RETURN;
    END IF;
    PERFORM pg_temp.cairn_lock_keys(p_bucket, ARRAY[p_key]);
    SELECT ob.id, ob.version_id, ob.is_delete_marker INTO o
    FROM objects ob
    WHERE ob.bucket = p_bucket AND ob.key = p_key
      AND CASE WHEN p_version_id IS NULL THEN ob.is_latest ELSE ob.version_id = p_version_id END;
    IF NOT FOUND THEN
        status := CASE WHEN p_version_id IS NULL THEN 'no_such_key' ELSE 'no_such_version' END;
        RETURN;
    END IF;
    version_id := o.version_id;
    IF o.is_delete_marker THEN
        status := 'delete_marker';
        RETURN;
    END IF;
    UPDATE objects SET tags = p_tags WHERE id = o.id;
    PERFORM pg_temp.cairn_notify(p_bucket, p_key, 'ObjectTagging', NULL,
                                 (SELECT ob.etag FROM objects ob WHERE ob.id = o.id), o.version_id);
    status := 'tagged';
END
$$;

-- T71: PutObjectAcl: sets the ACL (`p_acl`, stored as `s3::acl` has it;
-- NULL for its owner's full control alone) of the version `p_version_id` of
-- the key, or of its current version if NULL, in place, as T22 sets tags:
-- under B(b) shared and K(b,k). Its owner stays. Returns 'set', or
-- 'no_such_bucket', 'no_such_key', 'no_such_version' or 'delete_marker';
-- and the version's ID, which the response reports.
CREATE OR REPLACE FUNCTION pg_temp.cairn_set_acl(
    p_bucket text, p_key text, p_version_id text, p_acl text, p_notify text DEFAULT NULL,
    OUT status text, OUT versioning text, OUT version_id text
) LANGUAGE plpgsql AS $$
DECLARE
    o record;
BEGIN
    PERFORM pg_temp.cairn_notify_start(p_notify);
    versioning := pg_temp.cairn_lock_bucket(p_bucket);
    IF versioning IS NULL THEN
        status := 'no_such_bucket';
        RETURN;
    END IF;
    PERFORM pg_temp.cairn_lock_keys(p_bucket, ARRAY[p_key]);
    SELECT ob.id, ob.version_id, ob.is_delete_marker, ob.etag INTO o
    FROM objects ob
    WHERE ob.bucket = p_bucket AND ob.key = p_key
      AND CASE WHEN p_version_id IS NULL THEN ob.is_latest ELSE ob.version_id = p_version_id END;
    IF NOT FOUND THEN
        status := CASE WHEN p_version_id IS NULL THEN 'no_such_key' ELSE 'no_such_version' END;
        RETURN;
    END IF;
    version_id := o.version_id;
    IF o.is_delete_marker THEN
        status := 'delete_marker';
        RETURN;
    END IF;
    UPDATE objects SET acl = p_acl WHERE id = o.id;
    PERFORM pg_temp.cairn_notify(p_bucket, p_key, 'ObjectAcl:Put', NULL, o.etag, o.version_id);
    status := 'set';
END
$$;

-- T73: UpdateObjectEncryption (Batch Operations' S3UpdateObjectEncryption;
-- see `s3::sse::update_encryption`): stores the version's object key, which
-- its data stays encrypted under, sealed under another SSE-KMS data key, in
-- place, as the caller sealed it (`p_kms_*`); and, for a version that was
-- SSE-S3, its ETag and its parts' as SSE-KMS keeps them, in the clear
-- (`p_etag`, and `p_part_ids` with `p_part_etags`; NULLs: as they are).
-- Takes B(b) shared, K(b,k), and X(x) shared for its parts' blobs, whose
-- rows it changes. The version, by its row id `p_id`, must still be the one
-- the caller read: its sealed key still `p_sealed`, and its parts still
-- `p_part_ids`, if given. A version that's retained or under a legal hold
-- isn't changed, as S3 has it. Returns 'updated', 'no_such_bucket',
-- 'changed' (it isn't the one read anymore, or is gone), or 'locked'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_update_encryption(
    p_bucket text, p_key text, p_id bigint, p_sealed bytea, p_kms_key_id text,
    p_kms_data_key text, p_kms_sealed bytea, p_kms_context text, p_etag text,
    p_part_ids bigint[], p_part_etags text[],
    OUT status text
) LANGUAGE plpgsql AS $$
DECLARE
    o record;
    v_blobs uuid[];
BEGIN
    IF pg_temp.cairn_lock_bucket(p_bucket) IS NULL THEN
        status := 'no_such_bucket';
        RETURN;
    END IF;
    PERFORM pg_temp.cairn_lock_keys(p_bucket, ARRAY[p_key]);
    SELECT ob.id, ob.sse_kms_sealed, ob.retain_until, ob.legal_hold INTO o
    FROM objects ob
    WHERE ob.id = p_id AND ob.bucket = p_bucket AND ob.key = p_key AND NOT ob.is_delete_marker;
    IF NOT FOUND OR o.sse_kms_sealed IS DISTINCT FROM p_sealed THEN
        status := 'changed';
        RETURN;
    END IF;
    IF o.retain_until > NOW() OR coalesce(o.legal_hold, false) THEN
        status := 'locked';
        RETURN;
    END IF;
    IF p_part_ids IS NOT NULL THEN
        SELECT coalesce(array_agg(p.blob_id), '{}') INTO v_blobs FROM parts p WHERE p.object_id = o.id;
        PERFORM pg_temp.cairn_lock_blobs(v_blobs, array_fill(false, ARRAY[cardinality(v_blobs)]));
        IF (SELECT coalesce(array_agg(p.id ORDER BY p.id), '{}') FROM parts p WHERE p.object_id = o.id)
           IS DISTINCT FROM (SELECT coalesce(array_agg(i ORDER BY i), '{}') FROM unnest(p_part_ids) AS i) THEN
            status := 'changed';
            RETURN;
        END IF;
        UPDATE parts p SET etag = t.etag
        FROM unnest(p_part_ids, p_part_etags) AS t(id, etag)
        WHERE p.id = t.id AND p.object_id = o.id;
    END IF;
    UPDATE objects SET sse_kms_key_id = p_kms_key_id, sse_kms_data_key = p_kms_data_key,
                       sse_kms_sealed = p_kms_sealed, sse_kms_context = p_kms_context,
                       sse_s3 = false, etag = coalesce(p_etag, etag)
    WHERE id = o.id;
    status := 'updated';
END
$$;

-- T39: PutObjectRetention: sets the retention (`p_mode` and `p_until`;
-- NULLs to remove it) of the version `p_version_id` of the key, or of its
-- current version if NULL, in place, as S3 lets it be changed: a retention
-- that still lasts only lengthens, and stays in compliance mode; one in
-- governance mode may also become compliance mode, and may be shortened or
-- removed only by whom may bypass it (`p_bypass`). Takes B(b) shared and
-- K(b,k), as T22 does: deletes and lifecycle sweeps check a version's
-- retention under K. Returns 'set', or 'no_such_bucket', 'no_object_lock'
-- (the bucket hasn't Object Lock enabled), 'no_such_key',
-- 'no_such_version', 'delete_marker', or 'locked' (the change isn't
-- allowed); and the bucket's versioning state and the version's ID, as
-- T22 does.
CREATE OR REPLACE FUNCTION pg_temp.cairn_set_retention(
    p_bucket text, p_key text, p_version_id text, p_mode text, p_until timestamptz, p_bypass boolean,
    OUT status text, OUT versioning text, OUT version_id text
) LANGUAGE plpgsql AS $$
DECLARE
    o record;
BEGIN
    versioning := pg_temp.cairn_lock_bucket(p_bucket);
    IF versioning IS NULL THEN
        status := 'no_such_bucket';
        RETURN;
    END IF;
    IF NOT (SELECT object_lock FROM buckets WHERE name = p_bucket) THEN
        status := 'no_object_lock';
        RETURN;
    END IF;
    PERFORM pg_temp.cairn_lock_keys(p_bucket, ARRAY[p_key]);
    SELECT ob.id, ob.version_id, ob.is_delete_marker, ob.retain_mode, ob.retain_until INTO o
    FROM objects ob
    WHERE ob.bucket = p_bucket AND ob.key = p_key
      AND CASE WHEN p_version_id IS NULL THEN ob.is_latest ELSE ob.version_id = p_version_id END;
    IF NOT FOUND THEN
        status := CASE WHEN p_version_id IS NULL THEN 'no_such_key' ELSE 'no_such_version' END;
        RETURN;
    END IF;
    version_id := o.version_id;
    IF o.is_delete_marker THEN
        status := 'delete_marker';
        RETURN;
    END IF;
    IF o.retain_until > NOW() THEN
        IF o.retain_mode = 'COMPLIANCE' THEN
            IF p_mode IS DISTINCT FROM 'COMPLIANCE' OR p_until < o.retain_until THEN
                status := 'locked';
                RETURN;
            END IF;
        ELSIF NOT p_bypass AND (p_mode IS NULL OR p_until < o.retain_until) THEN
            status := 'locked';
            RETURN;
        END IF;
    END IF;
    UPDATE objects SET retain_mode = p_mode, retain_until = p_until WHERE id = o.id;
    status := 'set';
END
$$;

-- T40: PutObjectLegalHold: sets the legal hold of the version, as T39 sets
-- its retention, under the same locks, with the same statuses but
-- 'locked': anyone allowed to may set or lift it.
CREATE OR REPLACE FUNCTION pg_temp.cairn_set_legal_hold(
    p_bucket text, p_key text, p_version_id text, p_hold boolean,
    OUT status text, OUT versioning text, OUT version_id text
) LANGUAGE plpgsql AS $$
DECLARE
    o record;
BEGIN
    versioning := pg_temp.cairn_lock_bucket(p_bucket);
    IF versioning IS NULL THEN
        status := 'no_such_bucket';
        RETURN;
    END IF;
    IF NOT (SELECT object_lock FROM buckets WHERE name = p_bucket) THEN
        status := 'no_object_lock';
        RETURN;
    END IF;
    PERFORM pg_temp.cairn_lock_keys(p_bucket, ARRAY[p_key]);
    SELECT ob.id, ob.version_id, ob.is_delete_marker INTO o
    FROM objects ob
    WHERE ob.bucket = p_bucket AND ob.key = p_key
      AND CASE WHEN p_version_id IS NULL THEN ob.is_latest ELSE ob.version_id = p_version_id END;
    IF NOT FOUND THEN
        status := CASE WHEN p_version_id IS NULL THEN 'no_such_key' ELSE 'no_such_version' END;
        RETURN;
    END IF;
    version_id := o.version_id;
    IF o.is_delete_marker THEN
        status := 'delete_marker';
        RETURN;
    END IF;
    UPDATE objects SET legal_hold = p_hold WHERE id = o.id;
    status := 'set';
END
$$;

-- T23: PutBucketTagging and DeleteBucketTagging: sets (or, with NULL,
-- removes) the bucket's tags, unless its ABAC is enabled (then only T56
-- changes them, as in S3). A plain UPDATE of the bucket's row, as T21's;
-- ABAC is a column of the same row, which the UPDATE re-checks after any
-- wait (F2), so a concurrent T55 is never missed. Returns 'ok', 'abac' (not
-- set), or 'missing' (no such bucket).
CREATE OR REPLACE FUNCTION pg_temp.cairn_set_bucket_tags(p_bucket text, p_tags text)
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    UPDATE buckets SET tags = p_tags WHERE name = p_bucket AND NOT abac;
    IF FOUND THEN
        RETURN 'ok';
    END IF;
    PERFORM 1 FROM buckets WHERE name = p_bucket;
    RETURN CASE WHEN FOUND THEN 'abac' ELSE 'missing' END;
END
$$;

-- T55: PutBucketAbac: enables or disables the bucket's ABAC (whether its tags
-- are its `aws:ResourceTag`s, see `s3::access`). A plain UPDATE of the
-- bucket's row, as T21's. Returns whether the bucket exists.
CREATE OR REPLACE FUNCTION pg_temp.cairn_set_bucket_abac(p_bucket text, p_abac boolean)
RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
    UPDATE buckets SET abac = p_abac WHERE name = p_bucket;
    RETURN FOUND;
END
$$;

-- T56: S3 Control's TagResource and UntagResource on a bucket: replaces its
-- tags `p_old` (as the caller read them, NULL for none) with `p_new`, which
-- the caller computed from them, whatever its ABAC. A compare-and-swap: a
-- plain UPDATE of the bucket's row whose WHERE re-checks the row's own
-- `tags` after any wait (F2), so of two concurrent changes the second finds
-- the tags moved, and the caller reads them again. Returns 'ok', 'moved' or
-- 'missing' (no such bucket).
CREATE OR REPLACE FUNCTION pg_temp.cairn_swap_bucket_tags(p_bucket text, p_old text, p_new text)
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    UPDATE buckets SET tags = p_new WHERE name = p_bucket AND tags IS NOT DISTINCT FROM p_old;
    IF FOUND THEN
        RETURN 'ok';
    END IF;
    PERFORM 1 FROM buckets WHERE name = p_bucket;
    RETURN CASE WHEN FOUND THEN 'moved' ELSE 'missing' END;
END
$$;

-- T21: PutBucketCors and DeleteBucketCors: sets (or, with NULL, removes) the
-- bucket's CORS configuration. A plain UPDATE of the bucket's row, as T16's:
-- no invariant involves the configuration, which requests read as they're
-- answered, not under B. Returns whether the bucket exists.
CREATE OR REPLACE FUNCTION pg_temp.cairn_set_cors(p_bucket text, p_config text)
RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
    UPDATE buckets SET cors = p_config WHERE name = p_bucket;
    RETURN FOUND;
END
$$;

-- T54: PutBucketWebsite and DeleteBucketWebsite: sets (or, with NULL,
-- removes) the bucket's website configuration. A plain UPDATE of the
-- bucket's row, as T21's. Returns whether the bucket exists.
CREATE OR REPLACE FUNCTION pg_temp.cairn_set_website(p_bucket text, p_config text)
RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
    UPDATE buckets SET website = p_config WHERE name = p_bucket;
    RETURN FOUND;
END
$$;

-- T64: PutBucketLogging: sets (or, with NULL, removes) the bucket's server
-- access logging configuration. A plain UPDATE of the bucket's row, as T54's.
-- Returns whether the bucket exists.
CREATE OR REPLACE FUNCTION pg_temp.cairn_set_logging(p_bucket text, p_config text)
RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
    UPDATE buckets SET logging = p_config WHERE name = p_bucket;
    RETURN FOUND;
END
$$;

-- T67: PutBucketReplication and DeleteBucketReplication: sets (or, with
-- NULL, removes) the bucket's replication configuration (see
-- `replication`), which only a versioned bucket may have (I15): takes the
-- bucket's row as a plain UPDATE does, which orders it against a change of
-- versioning (T10), and checks the state under it, as T38 does. 'set',
-- 'not_versioned' or 'no_such_bucket'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_set_replication(p_bucket text, p_config text)
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM buckets WHERE name = p_bucket FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RETURN 'no_such_bucket';
    END IF;
    IF p_config IS NOT NULL AND (SELECT versioning FROM buckets WHERE name = p_bucket) <> 'enabled' THEN
        RETURN 'not_versioned';
    END IF;
    UPDATE buckets SET replication = p_config WHERE name = p_bucket;
    RETURN 'set';
END
$$;

-- T68: a queued version, replicated or given up on (see `replication`):
-- takes K(b,k) of its source key, drops it from the queue, and sets the
-- source version's status: FAILED if `p_failed` (whatever its other
-- destinations do), else COMPLETED once no destination is left to
-- replicate it to, unless one failed. Returns whether it was still queued.
CREATE OR REPLACE FUNCTION pg_temp.cairn_replication_done(p_seq bigint, p_failed boolean)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    q record;
BEGIN
    SELECT bucket, key, version_id, marker, purge INTO q FROM replication_queue WHERE seq = p_seq;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    PERFORM pg_temp.cairn_lock_keys(q.bucket, ARRAY[q.key]);
    DELETE FROM replication_queue WHERE seq = p_seq;
    -- A delete marker has no status, nor has a deleted version.
    IF NOT FOUND OR q.marker OR q.purge THEN
        RETURN FOUND;
    END IF;
    IF p_failed THEN
        UPDATE objects SET replication_status = 'FAILED'
        WHERE bucket = q.bucket AND key = q.key AND version_id = q.version_id
          AND replication_status IN ('PENDING', 'COMPLETED');
    ELSE
        UPDATE objects SET replication_status = 'COMPLETED'
        WHERE bucket = q.bucket AND key = q.key AND version_id = q.version_id
          AND replication_status = 'PENDING'
          AND NOT EXISTS (SELECT 1 FROM replication_queue r
                          WHERE r.bucket = q.bucket AND r.key = q.key AND r.version_id = q.version_id);
    END IF;
    RETURN true;
END
$$;

-- T69: a Batch Replication job's task (see `batch`): queues version
-- `p_version_id` of key `p_key` for each destination the bucket's
-- replication configuration sends it to now (`cairn_replication_targets`),
-- as a write queues its version (`cairn_replicate`), but whenever it was
-- written, and whatever its status: a version that was replicated, or
-- failed to be, or is a replica itself, is replicated (again), as S3's
-- Batch Replication does. Where it's queued already, it isn't again. Takes
-- K(b,k), as a write does, and a queued object (but a replica) is PENDING
-- (I15). Returns 'queued'; 'no_such_version' (or 'no_such_key', named
-- by none); 'no_configuration' if the bucket has none (or is gone:
-- 'no_such_bucket'); 'null_version' for the null version, which has no ID
-- for its replica to keep; or 'not_eligible' if no rule sends it anywhere.
CREATE OR REPLACE FUNCTION pg_temp.cairn_replicate_existing(p_bucket text, p_key text, p_version_id text)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    v_config text;
    o record;
    v_queued bigint;
BEGIN
    SELECT replication INTO v_config FROM buckets WHERE name = p_bucket;
    IF NOT FOUND THEN
        RETURN 'no_such_bucket';
    END IF;
    PERFORM pg_temp.cairn_lock_keys(p_bucket, ARRAY[p_key]);
    SELECT id, version_id, is_delete_marker, tags,
           CASE WHEN sse_c_key IS NOT NULL THEN 'customer'
                WHEN sse_kms_key_id IS NOT NULL AND NOT coalesce(sse_s3, false) THEN 'kms'
                ELSE 'plain' END AS encryption
    INTO o FROM objects
    WHERE bucket = p_bucket AND key = p_key
      AND CASE WHEN p_version_id IS NULL THEN is_latest ELSE version_id = p_version_id END;
    IF NOT FOUND THEN
        RETURN CASE WHEN p_version_id IS NULL THEN 'no_such_key' ELSE 'no_such_version' END;
    END IF;
    IF v_config IS NULL THEN
        RETURN 'no_configuration';
    END IF;
    IF o.version_id = 'null' THEN
        RETURN 'null_version';
    END IF;
    INSERT INTO replication_queue (bucket, key, version_id, marker, destination, rule_id)
    SELECT p_bucket, p_key, o.version_id, o.is_delete_marker, t.destination, t.rule_id
    FROM pg_temp.cairn_replication_targets(v_config::jsonb, p_key, o.is_delete_marker, o.tags, o.encryption) t
    WHERE NOT EXISTS (SELECT 1 FROM replication_queue r
                      WHERE r.bucket = p_bucket AND r.key = p_key AND r.version_id = o.version_id
                        AND r.destination = t.destination);
    GET DIAGNOSTICS v_queued = ROW_COUNT;
    IF v_queued = 0 AND NOT EXISTS (
        SELECT 1 FROM pg_temp.cairn_replication_targets(v_config::jsonb, p_key, o.is_delete_marker, o.tags, o.encryption)
    ) THEN
        RETURN 'not_eligible';
    END IF;
    IF v_queued > 0 AND NOT o.is_delete_marker THEN
        UPDATE objects SET replication_status = 'PENDING'
        WHERE id = o.id AND replication_status IS DISTINCT FROM 'REPLICA';
    END IF;
    RETURN 'queued';
END
$$;

-- T27: PutBucketPolicy and DeleteBucketPolicy: sets (or, with NULL, removes)
-- the bucket's policy, unless it's public (`p_public`) and the bucket's
-- public access block, or its account's, blocks public policies ('blocked')
-- (I12). Takes B(b) as a plain UPDATE does (no key update), then A(a) shared,
-- and checks both blocks in a later statement, so that a PutPublicAccessBlock
-- of either (T32, T41) lands entirely before or after. Requests read the
-- policy as they begin, not under B. 'set', 'blocked' or 'no_such_bucket'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_set_policy(p_bucket text, p_policy text, p_public boolean)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    v_account text;
BEGIN
    SELECT account_id INTO v_account FROM buckets WHERE name = p_bucket FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RETURN 'no_such_bucket';
    END IF;
    PERFORM 1 FROM accounts WHERE id = v_account FOR SHARE;
    IF p_public AND (coalesce((SELECT public_access_block FROM buckets WHERE name = p_bucket), 0) & 4 <> 0
                     OR coalesce((SELECT public_access_block FROM accounts WHERE id = v_account), 0) & 4 <> 0) THEN
        RETURN 'blocked';
    END IF;
    UPDATE buckets SET policy = p_policy WHERE name = p_bucket;
    RETURN 'set';
END
$$;

-- T32: PutPublicAccessBlock and DeletePublicAccessBlock: sets (or, with
-- NULL, removes) the bucket's public access block. A plain UPDATE of the
-- bucket's row, as T16's. Returns whether the bucket exists.
CREATE OR REPLACE FUNCTION pg_temp.cairn_set_public_access_block(p_bucket text, p_block smallint)
RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
    UPDATE buckets SET public_access_block = p_block WHERE name = p_bucket;
    RETURN FOUND;
END
$$;

-- T41: S3 Control's PutPublicAccessBlock and DeletePublicAccessBlock: sets
-- (or, with NULL, removes) the account's public access block. A plain UPDATE
-- of the account's row, which is A(a) exclusive (I12), and holds nothing
-- else. Returns whether the account exists.
CREATE OR REPLACE FUNCTION pg_temp.cairn_set_account_public_access_block(p_account text, p_block smallint)
RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
    UPDATE accounts SET public_access_block = p_block WHERE id = p_account;
    RETURN FOUND;
END
$$;

-- T28: gives a user an access key, unless it has `p_max` already (I10).
-- Takes R(r) exclusively, then counts its keys. The key's FK check locks the
-- row shared, which it holds already; its trigger keeps `users.secret` (see
-- migration 29), on the same row. Returns 'created', 'no_such_user',
-- 'too_many' or 'taken' (another key has the ID).
CREATE OR REPLACE FUNCTION pg_temp.cairn_create_key(p_user uuid, p_id text, p_secret text, p_max integer)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    v_user uuid;
BEGIN
    SELECT id INTO v_user FROM users WHERE id = p_user FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'no_such_user';
    END IF;
    IF (SELECT count(*) FROM access_keys WHERE user_id = v_user) >= p_max THEN
        RETURN 'too_many';
    END IF;
    INSERT INTO access_keys (access_key_id, user_id, secret) VALUES (p_id, v_user, p_secret)
    ON CONFLICT DO NOTHING;
    IF NOT FOUND THEN
        RETURN 'taken';
    END IF;
    RETURN 'created';
END
$$;

-- T29: sets a user's inline policy `p_name`, unless its policies would hold
-- more than `p_max` characters (but whitespace) together (I10). Takes R(r)
-- exclusively, then sizes the others. Returns 'set', 'no_such_user' or
-- 'too_big'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_put_policy(p_user uuid, p_name text, p_document text, p_max integer)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    v_user uuid;
BEGIN
    SELECT id INTO v_user FROM users WHERE id = p_user FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'no_such_user';
    END IF;
    IF (SELECT coalesce(sum(length(regexp_replace(document, '\s', '', 'g'))), 0)
        FROM user_policies WHERE user_id = v_user AND name <> p_name AND name NOT LIKE 'cairn:%')
       + length(regexp_replace(p_document, '\s', '', 'g')) > p_max THEN
        RETURN 'too_big';
    END IF;
    INSERT INTO user_policies (user_id, name, document) VALUES (v_user, p_name, p_document)
    ON CONFLICT (user_id, name) DO UPDATE SET document = EXCLUDED.document;
    RETURN 'set';
END
$$;

-- T42: TagUser: sets the user's tags `p_keys` to `p_values` (a key that
-- differs from one it has only in case replaces it, key and all), unless it
-- would have more than `p_max` (I10). Takes R(r) exclusively, then counts
-- in a later statement. Returns 'tagged', 'no_such_user' or 'too_many'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_tag_user(p_user uuid, p_keys text[], p_values text[], p_max integer)
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM users WHERE id = p_user FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'no_such_user';
    END IF;
    IF (SELECT count(*) FROM user_tags WHERE user_id = p_user AND lower(key) <> ALL (SELECT lower(k) FROM unnest(p_keys) k))
       + cardinality(p_keys) > p_max THEN
        RETURN 'too_many';
    END IF;
    DELETE FROM user_tags WHERE user_id = p_user AND lower(key) IN (SELECT lower(k) FROM unnest(p_keys) k);
    INSERT INTO user_tags (user_id, key, value) SELECT p_user, k, v FROM unnest(p_keys, p_values) AS t(k, v);
    RETURN 'tagged';
END
$$;

-- T43: TagPolicy: sets the managed policy's tags `p_keys` to `p_values`
-- (keys are case-sensitive, as IAM's are on policies), unless it would have
-- more than `p_max` (I10). Takes M(m) exclusively, then counts in a later
-- statement. Returns 'tagged', 'no_such_policy' or 'too_many'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_tag_policy(p_policy uuid, p_keys text[], p_values text[], p_max integer)
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM managed_policies WHERE id = p_policy FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'no_such_policy';
    END IF;
    IF (SELECT count(*) FROM managed_policy_tags WHERE policy_id = p_policy AND key <> ALL (p_keys))
       + cardinality(p_keys) > p_max THEN
        RETURN 'too_many';
    END IF;
    DELETE FROM managed_policy_tags WHERE policy_id = p_policy AND key = ANY (p_keys);
    INSERT INTO managed_policy_tags (policy_id, key, value) SELECT p_policy, k, v FROM unnest(p_keys, p_values) AS t(k, v);
    RETURN 'tagged';
END
$$;

-- T44: CreatePolicyVersion: a new version of the managed policy, numbered
-- next, its default if `p_default`; if it has `p_max` already, the oldest
-- that isn't the default goes first when `p_prune` (as Terraform does it,
-- and the console), else it's refused (I13). Takes M(m) exclusively, then
-- counts in a later statement. Returns the new version's number, 0 if it
-- has too many, NULL if there's no such policy.
CREATE OR REPLACE FUNCTION pg_temp.cairn_create_policy_version(
    p_policy uuid, p_document text, p_default boolean, p_prune boolean, p_max integer)
RETURNS integer LANGUAGE plpgsql AS $$
DECLARE
    v_version integer;
BEGIN
    PERFORM 1 FROM managed_policies WHERE id = p_policy FOR UPDATE;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    IF p_prune AND (SELECT count(*) FROM managed_policy_versions WHERE policy_id = p_policy) >= p_max THEN
        DELETE FROM managed_policy_versions
        WHERE policy_id = p_policy AND version = (
            SELECT min(v.version) FROM managed_policy_versions v
            WHERE v.policy_id = p_policy AND v.version <> (SELECT version FROM managed_policies WHERE id = p_policy));
    END IF;
    IF (SELECT count(*) FROM managed_policy_versions WHERE policy_id = p_policy) >= p_max THEN
        RETURN 0;
    END IF;
    UPDATE managed_policies SET next_version = next_version + 1, updated_at = now()
    WHERE id = p_policy RETURNING next_version - 1 INTO v_version;
    INSERT INTO managed_policy_versions (policy_id, version, document) VALUES (p_policy, v_version, p_document);
    IF p_default THEN
        UPDATE managed_policies SET version = v_version, document = p_document WHERE id = p_policy;
    END IF;
    RETURN v_version;
END
$$;

-- T45: SetDefaultPolicyVersion: makes version `p_version` of the managed
-- policy its default (I13). Takes M(m) exclusively, then reads the version.
-- Returns 'set', 'no_such_policy' or 'no_such_version'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_set_default_policy_version(p_policy uuid, p_version integer)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    v_document text;
BEGIN
    PERFORM 1 FROM managed_policies WHERE id = p_policy FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'no_such_policy';
    END IF;
    SELECT document INTO v_document FROM managed_policy_versions WHERE policy_id = p_policy AND version = p_version;
    IF NOT FOUND THEN
        RETURN 'no_such_version';
    END IF;
    UPDATE managed_policies SET version = p_version, document = v_document, updated_at = now() WHERE id = p_policy;
    RETURN 'set';
END
$$;

-- T46: DeletePolicyVersion: deletes version `p_version` of the managed
-- policy, unless it's its default (I13). Takes M(m) exclusively, then reads
-- which is. Returns 'deleted', 'default', 'no_such_policy' or
-- 'no_such_version'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_delete_policy_version(p_policy uuid, p_version integer)
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM managed_policies WHERE id = p_policy FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'no_such_policy';
    END IF;
    IF (SELECT version FROM managed_policies WHERE id = p_policy) = p_version THEN
        RETURN 'default';
    END IF;
    DELETE FROM managed_policy_versions WHERE policy_id = p_policy AND version = p_version;
    IF NOT FOUND THEN
        RETURN 'no_such_version';
    END IF;
    RETURN 'deleted';
END
$$;

-- T65: gives a user of Cairn's own directory a passkey, unless it has
-- `p_max` already (I10): signed in (`p_link` NULL), or with its setup link
-- `p_link` (by its hash), which it uses up. Takes Y(y) exclusively, then
-- counts, then uses the link up by a DELETE whose condition is on its own
-- row (F2), so that it's used once. A credential registered meanwhile fails
-- the insert's unique index, and so the whole statement. Returns 'added',
-- 'no_such_user', 'no_link' (used, or expired), 'too_many' or 'taken', and
-- the user's ID.
CREATE OR REPLACE FUNCTION pg_temp.cairn_add_directory_passkey(
    p_user uuid, p_link bytea, p_credential bytea, p_public_key bytea, p_sign_count bigint,
    p_name text, p_backup_eligible boolean, p_backed_up boolean, p_max integer,
    OUT status text, OUT o_user uuid)
LANGUAGE plpgsql AS $$
BEGIN
    o_user := p_user;
    IF p_link IS NOT NULL THEN
        SELECT l.user_id INTO o_user FROM directory_setup_links l WHERE l.token_hash = p_link AND l.expires_at > now();
        IF NOT FOUND THEN
            status := 'no_link';
            RETURN;
        END IF;
    END IF;
    PERFORM 1 FROM identity_users u WHERE u.id = o_user AND u.provider IS NULL FOR UPDATE;
    IF NOT FOUND THEN
        status := CASE WHEN p_link IS NULL THEN 'no_such_user' ELSE 'no_link' END;
        RETURN;
    END IF;
    IF (SELECT count(*) FROM directory_passkeys d WHERE d.user_id = o_user) >= p_max THEN
        status := 'too_many';
        RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM directory_passkeys WHERE credential_id = p_credential) THEN
        status := 'taken';
        RETURN;
    END IF;
    IF p_link IS NOT NULL THEN
        DELETE FROM directory_setup_links l
        WHERE l.token_hash = p_link AND l.user_id = o_user AND l.expires_at > now();
        IF NOT FOUND THEN
            status := 'no_link';
            RETURN;
        END IF;
    END IF;
    INSERT INTO directory_passkeys (credential_id, user_id, public_key, sign_count, name, backup_eligible, backed_up)
    VALUES (p_credential, o_user, p_public_key, p_sign_count, p_name, p_backup_eligible, p_backed_up);
    status := 'added';
END
$$;

-- T66: removes one of a directory user's passkeys (and so the sessions
-- signed in with it), unless it's the user's last, so that no one locks
-- themselves out (an administrator still may: `delete_directory_passkeys`).
-- Takes Y(y) exclusively, then counts. Returns 'deleted', 'no_such_passkey'
-- or 'last'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_delete_directory_passkey(p_user uuid, p_credential bytea)
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM identity_users WHERE id = p_user FOR UPDATE;
    IF NOT EXISTS (SELECT 1 FROM directory_passkeys WHERE user_id = p_user AND credential_id = p_credential) THEN
        RETURN 'no_such_passkey';
    END IF;
    IF (SELECT count(*) FROM directory_passkeys WHERE user_id = p_user) <= 1 THEN
        RETURN 'last';
    END IF;
    DELETE FROM directory_passkeys WHERE user_id = p_user AND credential_id = p_credential;
    RETURN 'deleted';
END
$$;

-- T18: PutBucketLifecycleConfiguration and DeleteBucketLifecycle: sets (or,
-- with NULL, removes) the bucket's lifecycle configuration, with a new
-- generation, and starts a new sweep of it, due now (the last whole sweep
-- stays, for the console), or drops its sweep. Plain UPDATEs of the
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

-- T61: PutBucketInventoryConfiguration: sets the bucket's inventory
-- configuration `p_id`, with a new generation, and starts a new report of
-- it, due now (the last whole report stays), unless the bucket has
-- `p_max` others already. Takes the bucket's row as a plain UPDATE does
-- (FOR NO KEY UPDATE, as T18's UPDATE does), which serializes the
-- bucket's configuration changes, so that two can't both find room for
-- one more; it doesn't conflict with B(b) shared. No invariant involves
-- the configuration, which a report checks itself (T62, T63). Returns
-- 'set', 'too_many' or 'no_such_bucket'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_put_inventory(
    p_bucket text, p_id text, p_config text, p_enabled boolean, p_setter uuid, p_max int)
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM buckets WHERE name = p_bucket FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RETURN 'no_such_bucket';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM inventories WHERE bucket = p_bucket AND id = p_id)
       AND (SELECT count(*) FROM inventories WHERE bucket = p_bucket) >= p_max THEN
        RETURN 'too_many';
    END IF;
    INSERT INTO inventories (bucket, id, config, enabled, setter, due)
    VALUES (p_bucket, p_id, p_config, p_enabled, p_setter, now())
    ON CONFLICT (bucket, id) DO UPDATE SET config = p_config, enabled = p_enabled, setter = p_setter,
        generation = nextval('inventory_generations'), due = now(), started = NULL,
        cursor_key = NULL, cursor_id = NULL, cursor_modified = NULL, seen = 0, files = 0, failure = NULL, failed_at = NULL;
    DELETE FROM inventory_files WHERE bucket = p_bucket AND id = p_id;
    RETURN 'set';
END
$$;

-- T62: a report's data file, written: records it, and where the report has
-- got to (the last version in it), and how many versions it has read, as
-- long as the configuration is still of `p_generation`. Plain writes,
-- keyed by the configuration (see T61). Returns whether it was.
CREATE OR REPLACE FUNCTION pg_temp.cairn_inventory_file(
    p_bucket text, p_id text, p_generation bigint, p_started timestamptz, p_key text,
    p_size bigint, p_md5 text, p_cursor_key text, p_cursor_id bigint, p_seen bigint,
    p_cursor_modified timestamptz)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    v_seq int;
BEGIN
    UPDATE inventories SET started = p_started, cursor_key = p_cursor_key, cursor_id = p_cursor_id,
        cursor_modified = p_cursor_modified,
        seen = seen + p_seen, files = files + 1, failure = NULL, failed_at = NULL
    WHERE bucket = p_bucket AND id = p_id AND generation = p_generation
    RETURNING files INTO v_seq;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    INSERT INTO inventory_files (bucket, id, generation, seq, key, size, md5)
    VALUES (p_bucket, p_id, p_generation, v_seq, p_key, p_size, p_md5);
    RETURN true;
END
$$;

-- T63: a report, done (its manifest written): records it as the last whole
-- one, makes the next one due at `p_due`, and drops its data files, as
-- long as the configuration is still of `p_generation`. Plain writes, as
-- T62's. Returns whether it was.
CREATE OR REPLACE FUNCTION pg_temp.cairn_inventory_done(
    p_bucket text, p_id text, p_generation bigint, p_last text, p_due timestamptz)
RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
    UPDATE inventories SET started = NULL, cursor_key = NULL, cursor_id = NULL, cursor_modified = NULL, seen = 0, files = 0,
        failure = NULL, failed_at = NULL, last = p_last, due = p_due
    WHERE bucket = p_bucket AND id = p_id AND generation = p_generation;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    DELETE FROM inventory_files WHERE bucket = p_bucket AND id = p_id AND generation = p_generation;
    RETURN true;
END
$$;

-- Deletes a user (by its ID): takes R (by deleting the row), and its keys,
-- policies and console identities go with it (cascades). (Its grants are
-- statements of buckets' policies, which `grants` removes first.) Returns
-- whether there was one.
CREATE OR REPLACE FUNCTION pg_temp.cairn_delete_user(p_user uuid)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    v_deleted bigint;
BEGIN
    DELETE FROM users WHERE id = p_user;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted > 0;
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

-- Adds to `sources` (and their live bytes to `total`) the committed blobs
-- of class `p_class` that are worth compacting for their misplaced bytes
-- (see `cairn_refresh_dead_size`) together with their garbage: the least
-- live data that stays first, until their live bytes would exceed
-- `p_budget`, as T14's compaction does, but for those it took already.
CREATE OR REPLACE FUNCTION pg_temp.cairn_claim_misplaced(
    p_class text, p_compact_threshold float8, p_max_sources bigint, p_budget bigint,
    INOUT sources uuid[], INOUT total bigint
) LANGUAGE plpgsql AS $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT blob_id, size - dead_size AS live FROM blobs
        WHERE storage_class = p_class AND misplaced_size > 0 AND state = 'committed'
          AND dead_size + misplaced_size >= size * p_compact_threshold
          AND NOT (blob_id = ANY(sources))
          AND (pack_lease_until IS NULL OR pack_lease_until < NOW())
          AND NOT EXISTS (SELECT 1 FROM lost_ranges l JOIN parts p ON p.blob_id = l.blob_id
                          WHERE l.blob_id = blobs.blob_id
                            AND p.blob_offset < l.stop AND p.blob_offset + p.size > l.start)
        ORDER BY size - dead_size - misplaced_size
        LIMIT p_max_sources FOR UPDATE SKIP LOCKED
    LOOP
        EXIT WHEN cardinality(sources) >= p_max_sources
            OR (total + r.live > p_budget AND cardinality(sources) > 0);
        total := total + r.live;
        sources := sources || r.blob_id;
    END LOOP;
END
$$;

-- T14: claims the source blobs for a packing job, if there's one worth
-- running (see `packer::claim`), all of storage class `p_class`: `p_kind` is
-- 'compact' (blobs mostly garbage, or garbage and misplaced bytes, see
-- `classes`), 'consolidate', 'upgrade' (a blob from before checksums, one at
-- a time) or 'convert' (blobs of more than `p_small_size` live bytes not in
-- `p_data_shards` data shards and, if it isn't NULL, `p_parity_shards`
-- parity shards, unless `p_data_shards` is NULL; then blobs of any size not
-- in the pool `p_pool`, the class's, see `classes`).
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
    p_target_size bigint, p_budget bigint, p_lease_secs float8, p_data_shards smallint,
    p_parity_shards smallint, p_class text, p_pool text
) RETURNS uuid[] LANGUAGE plpgsql AS $$
DECLARE
    v_sources uuid[] := '{}';
    v_total bigint := 0;
    v_count bigint;
    v_dir int;
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
              AND dead_size >= size * p_compact_threshold AND storage_class = p_class
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
        SELECT * INTO v_sources, v_total FROM pg_temp.cairn_claim_misplaced(
            p_class, p_compact_threshold, p_max_sources, p_budget, v_sources, v_total);
        IF cardinality(v_sources) = 0 THEN
            RETURN '{}';
        END IF;
    ELSIF p_kind = 'compact' THEN
        -- A lower threshold than the index's (tests): the same, without it.
        FOR r IN
            SELECT blob_id, size - dead_size AS live FROM blobs
            WHERE state = 'committed' AND dead_size > 0 AND dead_size >= size * p_compact_threshold
              AND storage_class = p_class
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
        SELECT * INTO v_sources, v_total FROM pg_temp.cairn_claim_misplaced(
            p_class, p_compact_threshold, p_max_sources, p_budget, v_sources, v_total);
        IF cardinality(v_sources) = 0 THEN
            RETURN '{}';
        END IF;
    ELSIF p_kind = 'convert' AND p_data_shards IS NULL THEN
        -- Blobs of the class outside its pool, of any size: those in pools
        -- that sort before it, then after it, two ranges of `blobs_pool`.
        FOR v_dir IN 1..2 LOOP
            FOR r IN EXECUTE format(
                'SELECT blob_id, size - dead_size AS live FROM blobs
                 WHERE state = ''committed'' AND block_size IS NOT NULL
                   AND storage_class = $1 AND pool %s $2
                   AND (pack_lease_until IS NULL OR pack_lease_until < NOW())
                   AND NOT EXISTS (SELECT 1 FROM lost_ranges l JOIN parts p ON p.blob_id = l.blob_id
                                   WHERE l.blob_id = blobs.blob_id
                                     AND p.blob_offset < l.stop AND p.blob_offset + p.size > l.start)
                 LIMIT $3 FOR UPDATE SKIP LOCKED',
                CASE v_dir WHEN 1 THEN '<' ELSE '>' END)
            USING p_class, p_pool, p_max_sources
            LOOP
                EXIT WHEN v_total + r.live > p_budget AND cardinality(v_sources) > 0;
                v_total := v_total + r.live;
                v_sources := v_sources || r.blob_id;
            END LOOP;
        END LOOP;
        IF cardinality(v_sources) = 0 THEN
            RETURN '{}';
        END IF;
    ELSIF p_kind = 'convert' THEN
        -- Blobs whose (data shards, parity shards) is below the layout, then
        -- those above it, each a range of `blobs_large` (`blobs_layout` in
        -- `db.rs`), read in its order, so that a claim reads only as far as
        -- it takes, however many blobs there are to convert. Without parity
        -- shards to go by, or with one data shard (whose blobs' copies are
        -- the mover's, see `cairn_claim_copies`), only the data shards
        -- count: the bounds are past any parity shards. Its size bound
        -- (`packer::SMALL_SIZE`, which a test checks against this) is in the
        -- query as a literal, so that the planner can use the partial index,
        -- unless `p_small_size` is a smaller one (tests): then it goes
        -- without. Those mostly garbage are compaction's: it converts what it
        -- keeps.
        FOR v_dir IN 1..2 LOOP
            FOR r IN EXECUTE format(
                'SELECT blob_id, size - dead_size AS live FROM blobs
                 WHERE state = ''committed'' AND block_size IS NOT NULL %s
                   AND storage_class = $6
                   AND (data_shards, parity_shards) %s ($1, $2)
                   AND size - dead_size > $3 AND dead_size < size * $4
                   AND (pack_lease_until IS NULL OR pack_lease_until < NOW())
                   AND NOT EXISTS (SELECT 1 FROM lost_ranges l JOIN parts p ON p.blob_id = l.blob_id
                                   WHERE l.blob_id = blobs.blob_id
                                     AND p.blob_offset < l.stop AND p.blob_offset + p.size > l.start)
                 ORDER BY data_shards %s, parity_shards %s
                 LIMIT $5 FOR UPDATE SKIP LOCKED',
                CASE WHEN p_small_size >= 67108864 THEN 'AND size > 67108864' ELSE '' END,
                CASE v_dir WHEN 1 THEN '<' ELSE '>' END,
                CASE v_dir WHEN 1 THEN 'DESC' ELSE 'ASC' END,
                CASE v_dir WHEN 1 THEN 'DESC' ELSE 'ASC' END)
            USING p_data_shards,
                  CASE WHEN p_parity_shards IS NULL OR p_data_shards = 1 THEN
                      CASE v_dir WHEN 1 THEN 0 ELSE 32767 END
                  ELSE p_parity_shards END,
                  p_small_size, p_compact_threshold, p_max_sources, p_class
            LOOP
                EXIT WHEN v_total + r.live > p_budget AND cardinality(v_sources) > 0;
                v_total := v_total + r.live;
                v_sources := v_sources || r.blob_id;
            END LOOP;
        END LOOP;
        IF cardinality(v_sources) = 0 THEN
            RETURN '{}';
        END IF;
    ELSIF p_kind = 'upgrade' THEN
        -- One blob from before checksums, the oldest, off `blobs_legacy`.
        FOR r IN
            SELECT blob_id FROM blobs
            WHERE state = 'committed' AND block_size IS NULL AND storage_class = p_class
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
              AND storage_class = p_class
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
              AND storage_class = p_class
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
-- and releases the leases on the sources that remain ('committed'), unless
-- `p_release` is false: the job goes on with them (see `packer::relocate`).
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
    p_new_blobs uuid[], p_new_offsets bigint[], p_release boolean DEFAULT true,
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
    WITH moved AS (
        UPDATE parts p SET blob_id = m.new_blob, blob_offset = m.new_offset
        FROM unnest(p_part_ids, p_old_blobs, p_old_offsets, p_new_blobs, p_new_offsets)
            AS m(id, old_blob, old_offset, new_blob, new_offset)
        WHERE p.id = m.id AND p.blob_id = m.old_blob AND p.blob_offset = m.old_offset
        RETURNING p.id, m.old_blob
    )
    -- Parts that came out of a tier (see `tiers`): the backup points at
    -- the tier's object, which is going, so it backs them up anew.
    INSERT INTO backup_tier_moves (part_id)
    SELECT moved.id FROM moved JOIN blobs b ON b.blob_id = moved.old_blob
    WHERE b.state = 'remote' AND EXISTS (SELECT 1 FROM backup_config);
    -- Whatever didn't move into a new blob (its part was deleted meanwhile) is
    -- garbage there, and so is whatever moved out of a source that remains.
    PERFORM pg_temp.cairn_refresh_dead_size(v_touched);
    SELECT * INTO reap_blob, reap_node, reap_peer
    FROM pg_temp.cairn_drop_unreferenced_blobs(v_touched);
    IF p_release THEN
        UPDATE blobs SET pack_lease_until = NULL WHERE blob_id = ANY(p_sources);
    END IF;
    status := 'committed';
END
$$;

-- T69: claims the source blobs for a job that moves blobs of storage class
-- `p_class` into its tier `p_tier` (see `tiers`), as `cairn_claim` does for
-- the packer's jobs. `p_kind` is:
--
-- - 'stage': the class's blobs in the cluster (committed), oldest first,
--   once they're worth a job: their live bytes fill a blob
--   (`p_target_size`), the oldest has waited `p_wait_secs`, or
--   `p_max_sources` of them wait;
-- - 'compact': its remote blobs in `p_tier` with at least
--   `p_compact_threshold` of them garbage or misplaced (see `classes`),
--   least live data that stays first;
-- - 'move': its remote blobs in another tier than `p_tier` (any, if it's
--   NULL: the class is no longer a tier's), oldest first.
--
-- Takes candidates, skipping those another transaction has locked, until
-- their live bytes would exceed `p_budget`, and leases them; returns them,
-- or an empty array. Blobs with parts on lost data aren't candidates, as
-- in `cairn_claim`.
CREATE OR REPLACE FUNCTION pg_temp.cairn_claim_tier(
    p_kind text, p_class text, p_tier text, p_compact_threshold float8, p_max_sources bigint,
    p_target_size bigint, p_budget bigint, p_wait_secs float8, p_lease_secs float8
) RETURNS uuid[] LANGUAGE plpgsql AS $$
DECLARE
    v_sources uuid[] := '{}';
    v_total bigint := 0;
    v_count bigint;
    v_waited boolean;
    r record;
BEGIN
    IF p_kind = 'stage' THEN
        -- Whether they're worth a job, without locking them.
        SELECT coalesce(sum(c.live), 0), count(*), coalesce(bool_or(c.created_at < NOW() - make_interval(secs => p_wait_secs)), false)
        INTO v_total, v_count, v_waited FROM (
            SELECT size - dead_size AS live, created_at FROM blobs
            WHERE state = 'committed' AND storage_class = p_class
              AND (pack_lease_until IS NULL OR pack_lease_until < NOW())
            ORDER BY created_at
            LIMIT p_max_sources
        ) AS c;
        IF v_total < p_target_size AND v_count < p_max_sources AND NOT v_waited THEN
            RETURN '{}';
        END IF;
        v_total := 0;
        FOR r IN
            SELECT blob_id, size - dead_size AS live FROM blobs
            WHERE state = 'committed' AND storage_class = p_class
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
    ELSIF p_kind = 'compact' THEN
        FOR r IN
            SELECT b.blob_id, b.size - b.dead_size AS live FROM blobs b
            JOIN tier_blobs t ON t.blob_id = b.blob_id
            WHERE b.state = 'remote' AND b.storage_class = p_class AND t.tier = p_tier
              AND (b.dead_size > 0 OR b.misplaced_size > 0)
              AND b.dead_size + b.misplaced_size >= b.size * p_compact_threshold
              AND (b.pack_lease_until IS NULL OR b.pack_lease_until < NOW())
            ORDER BY b.size - b.dead_size - b.misplaced_size
            LIMIT p_max_sources FOR UPDATE OF b SKIP LOCKED
        LOOP
            EXIT WHEN v_total + r.live > p_budget AND cardinality(v_sources) > 0;
            v_total := v_total + r.live;
            v_sources := v_sources || r.blob_id;
        END LOOP;
    ELSE
        FOR r IN
            SELECT b.blob_id, b.size - b.dead_size AS live FROM blobs b
            JOIN tier_blobs t ON t.blob_id = b.blob_id
            WHERE b.state = 'remote' AND b.storage_class = p_class AND t.tier IS DISTINCT FROM p_tier
              AND (b.pack_lease_until IS NULL OR b.pack_lease_until < NOW())
            ORDER BY b.created_at
            LIMIT p_max_sources FOR UPDATE OF b SKIP LOCKED
        LOOP
            EXIT WHEN v_total + r.live > p_budget AND cardinality(v_sources) > 0;
            v_total := v_total + r.live;
            v_sources := v_sources || r.blob_id;
        END LOOP;
    END IF;
    IF cardinality(v_sources) = 0 THEN
        RETURN '{}';
    END IF;
    UPDATE blobs SET pack_lease_until = NOW() + make_interval(secs => p_lease_secs)
    WHERE blob_id = ANY(v_sources);
    RETURN v_sources;
END
$$;

-- T70: the commit that ends a job moving blobs into a tier (see
-- `tiers::offload`), as T15 ends a packing job. Takes X exclusive on its
-- sources and new blobs. Checks that the new blobs are still pending, with
-- their tier's objects recorded ('gone' otherwise: the GC took one as
-- stale, and its object with it). Then makes them remote, moves each part
-- that's still where the job found it into its new blob (I7), queues the
-- parts that moved for the backup, if there is one (it points them at the
-- tier's objects, see `backup::cycle`), drops the sources and new blobs
-- that nothing references anymore, and releases the leases on the sources
-- that remain ('committed').
CREATE OR REPLACE FUNCTION pg_temp.cairn_tier_commit(
    p_sources uuid[], p_out_blobs uuid[], p_out_sizes bigint[],
    p_part_ids bigint[], p_old_blobs uuid[], p_old_offsets bigint[],
    p_new_blobs uuid[], p_new_offsets bigint[],
    OUT status text, OUT reap_blob uuid[], OUT reap_node int[], OUT reap_peer text[]
) LANGUAGE plpgsql AS $$
DECLARE
    v_touched uuid[];
BEGIN
    reap_blob := '{}';
    reap_node := '{}';
    reap_peer := '{}';
    v_touched := p_sources || p_out_blobs;
    PERFORM pg_temp.cairn_lock_blobs(v_touched, array_fill(true, ARRAY[cardinality(v_touched)]));
    IF (SELECT count(*) FROM blobs b JOIN tier_blobs t ON t.blob_id = b.blob_id
        WHERE b.blob_id = ANY(p_out_blobs) AND b.state = 'pending') <> cardinality(p_out_blobs) THEN
        status := 'gone';
        RETURN;
    END IF;
    UPDATE blobs b SET state = 'remote', size = o.size
    FROM unnest(p_out_blobs, p_out_sizes) AS o(blob_id, size)
    WHERE b.blob_id = o.blob_id;
    WITH moved AS (
        UPDATE parts p SET blob_id = m.new_blob, blob_offset = m.new_offset
        FROM unnest(p_part_ids, p_old_blobs, p_old_offsets, p_new_blobs, p_new_offsets)
            AS m(id, old_blob, old_offset, new_blob, new_offset)
        WHERE p.id = m.id AND p.blob_id = m.old_blob AND p.blob_offset = m.old_offset
        RETURNING p.id
    )
    INSERT INTO backup_tier_moves (part_id)
    SELECT id FROM moved WHERE EXISTS (SELECT 1 FROM backup_config);
    PERFORM pg_temp.cairn_refresh_dead_size(v_touched);
    SELECT * INTO reap_blob, reap_node, reap_peer
    FROM pg_temp.cairn_drop_unreferenced_blobs(v_touched);
    UPDATE blobs SET pack_lease_until = NULL WHERE blob_id = ANY(p_sources);
    status := 'committed';
END
$$;

-- T19: moves shard `p_shard` of a blob from node `p_from` to node `p_to`,
-- which has stored it (see `mover`). Takes X(x) exclusive, then checks that
-- the blob is committed ('gone' otherwise: deleted, say), that the file
-- `p_to` stored is the shard the catalog describes (its CRC64/NVME is the
-- shard's, 'mismatch' otherwise), that the shard is still on `p_from`
-- ('gone' otherwise: another move took it), and that `p_to` holds no shard
-- of the blob ('occupied'), and stored it in the blob's pool ('mismatch'
-- otherwise, see `classes`). Then swaps the location, resolves the old copy's
-- open scrub findings ('moved'), and returns the old node's peer URL, to
-- reap its file. Locations are only removed together with their blob, or
-- here (I5).
CREATE OR REPLACE FUNCTION pg_temp.cairn_move_shard(
    p_blob uuid, p_shard smallint, p_from int, p_to int, p_crc bigint, p_pool text,
    OUT status text, OUT reap_peer text
) LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_temp.cairn_lock_blobs(ARRAY[p_blob], ARRAY[true]);
    PERFORM 1 FROM blobs WHERE blob_id = p_blob AND state = 'committed';
    IF NOT FOUND THEN
        status := 'gone';
        RETURN;
    END IF;
    PERFORM 1 FROM blobs WHERE blob_id = p_blob AND shard_crcs[p_shard + 1] = p_crc AND pool = p_pool;
    IF NOT FOUND THEN
        status := 'mismatch';
        RETURN;
    END IF;
    PERFORM 1 FROM blob_locations WHERE blob_id = p_blob AND node = p_from AND shard = p_shard;
    IF NOT FOUND THEN
        status := 'gone';
        RETURN;
    END IF;
    PERFORM 1 FROM blob_locations WHERE blob_id = p_blob AND node = p_to;
    IF FOUND THEN
        status := 'occupied';
        RETURN;
    END IF;
    SELECT peer_url INTO reap_peer FROM nodes WHERE id = p_from;
    DELETE FROM blob_locations WHERE blob_id = p_blob AND node = p_from AND shard = p_shard;
    -- Checksummed on its way to the disk, and checked against the catalog:
    -- the copy is known intact as of now.
    INSERT INTO blob_locations (blob_id, node, shard, checked_at)
    VALUES (p_blob, p_to, p_shard, NOW());
    UPDATE scrub_findings SET outcome = 'gone', resolved_at = NOW()
    WHERE blob_id = p_blob AND node = p_from AND resolved_at IS NULL;
    status := 'moved';
END
$$;

-- T20: claims up to `p_limit` blobs with shards to move (see `mover`): on
-- nodes that aren't active (being removed), or on active nodes that have
-- been down for more than `p_after_secs` (NULL: never), skipping those
-- another transaction has locked (it never waits) or a job has leased; the
-- blobs with the fewest live shards beyond their data shards first. Leases
-- them, as the packer's claim does (I8).
CREATE OR REPLACE FUNCTION pg_temp.cairn_claim_moves(
    p_after_secs float8, p_limit int, p_lease_secs float8
) RETURNS uuid[] LANGUAGE plpgsql AS $$
DECLARE
    v_claimed uuid[] := '{}';
    r record;
BEGIN
    FOR r IN
        SELECT b.blob_id FROM blobs b
        JOIN (
            SELECT bl.blob_id,
                   count(*) FILTER (WHERE n.last_seen > NOW() - INTERVAL '10 seconds') AS live
            FROM blob_locations bl JOIN nodes n ON n.id = bl.node
            WHERE bl.blob_id IN (
                SELECT m.blob_id FROM blob_locations m JOIN nodes mn ON mn.id = m.node
                WHERE mn.state <> 'active'
                   OR mn.last_seen < NOW() - make_interval(secs => p_after_secs)
            )
            GROUP BY bl.blob_id
        ) AS s ON s.blob_id = b.blob_id
        WHERE b.state = 'committed'
          AND (b.pack_lease_until IS NULL OR b.pack_lease_until < NOW())
        ORDER BY s.live - b.data_shards, b.blob_id
        LIMIT p_limit
        FOR UPDATE OF b SKIP LOCKED
    LOOP
        v_claimed := v_claimed || r.blob_id;
    END LOOP;
    UPDATE blobs SET pack_lease_until = NOW() + make_interval(secs => p_lease_secs)
    WHERE blob_id = ANY(v_claimed);
    RETURN v_claimed;
END
$$;

-- T24: claims up to `p_limit` replicated blobs of storage class `p_class`
-- whose copies don't number `p_parity_shards` + 1 (see `mover`), skipping those another transaction
-- has locked (it never waits) or a job has leased, and those larger than
-- `p_coded_above`, if it isn't NULL, which the packer converts (see
-- `cairn_claim`). Those with too few copies first, the fewest first, off
-- `blobs_copies`, read in its order, so that a claim reads only as far as it
-- takes. Leases them, as the packer's claim does (I8).
CREATE OR REPLACE FUNCTION pg_temp.cairn_claim_copies(
    p_class text, p_parity_shards smallint, p_coded_above bigint, p_limit int, p_lease_secs float8
) RETURNS uuid[] LANGUAGE plpgsql AS $$
DECLARE
    v_claimed uuid[] := '{}';
    r record;
BEGIN
    FOR r IN
        SELECT blob_id FROM blobs
        WHERE state = 'committed' AND data_shards = 1 AND block_size IS NOT NULL
          AND storage_class = p_class AND parity_shards < p_parity_shards
          AND (p_coded_above IS NULL OR size <= p_coded_above)
          AND (pack_lease_until IS NULL OR pack_lease_until < NOW())
        ORDER BY parity_shards
        LIMIT p_limit
        FOR UPDATE SKIP LOCKED
    LOOP
        v_claimed := v_claimed || r.blob_id;
    END LOOP;
    FOR r IN
        SELECT blob_id FROM blobs
        WHERE state = 'committed' AND data_shards = 1 AND block_size IS NOT NULL
          AND storage_class = p_class AND parity_shards > p_parity_shards
          AND (p_coded_above IS NULL OR size <= p_coded_above)
          AND (pack_lease_until IS NULL OR pack_lease_until < NOW())
        ORDER BY parity_shards DESC
        LIMIT p_limit - cardinality(v_claimed)
        FOR UPDATE SKIP LOCKED
    LOOP
        v_claimed := v_claimed || r.blob_id;
    END LOOP;
    UPDATE blobs SET pack_lease_until = NOW() + make_interval(secs => p_lease_secs)
    WHERE blob_id = ANY(v_claimed);
    RETURN v_claimed;
END
$$;

-- T25: adds node `p_node`'s copy of a replicated blob, as shard `p_shard`,
-- which it has stored (see `mover`). Takes X(x) exclusive, then checks that
-- the blob is committed, replicated, and still has `p_parity_shards` parity
-- shards, of which the new copy is the next ('changed' otherwise: deleted,
-- or another job got there first), that the file is the blob's (its
-- CRC64/NVME is every copy's, and it's in the blob's pool: 'mismatch'
-- otherwise), and that `p_node` holds
-- no copy yet ('occupied'). Then adds the location and the parity shard
-- ('added'). Every location is added under X(x) exclusive, or by a pending
-- blob's sinks (I9).
CREATE OR REPLACE FUNCTION pg_temp.cairn_add_copy(
    p_blob uuid, p_shard smallint, p_node int, p_crc bigint, p_parity_shards smallint, p_pool text
) RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_temp.cairn_lock_blobs(ARRAY[p_blob], ARRAY[true]);
    PERFORM 1 FROM blobs
    WHERE blob_id = p_blob AND state = 'committed' AND data_shards = 1
      AND parity_shards = p_parity_shards AND p_shard = 1 + p_parity_shards;
    IF NOT FOUND THEN
        RETURN 'changed';
    END IF;
    PERFORM 1 FROM blobs WHERE blob_id = p_blob AND shard_crcs[1] = p_crc AND pool = p_pool;
    IF NOT FOUND THEN
        RETURN 'mismatch';
    END IF;
    PERFORM 1 FROM blob_locations WHERE blob_id = p_blob AND node = p_node;
    IF FOUND THEN
        RETURN 'occupied';
    END IF;
    -- Checksummed on its way to the disk, and checked against the catalog:
    -- the copy is known intact as of now.
    INSERT INTO blob_locations (blob_id, node, shard, checked_at)
    VALUES (p_blob, p_node, p_shard, NOW());
    UPDATE blobs SET parity_shards = parity_shards + 1, shard_crcs = shard_crcs || p_crc
    WHERE blob_id = p_blob;
    RETURN 'added';
END
$$;

-- T26: drops node `p_node`'s copy of a replicated blob (see `mover`). Takes
-- X(x) exclusive, then checks that the blob is committed, replicated, and
-- still has `p_parity_shards` parity shards, at least one ('changed'
-- otherwise), and that `p_node` holds a copy ('gone' otherwise). Then
-- removes its location and a parity shard: the last copy takes the dropped
-- one's shard number, which it may, since copies are alike (their files
-- hold no shard index, see `blob_file`). Resolves the copy's open scrub
-- findings, and returns the node's peer URL, to reap its file ('dropped').
CREATE OR REPLACE FUNCTION pg_temp.cairn_drop_copy(
    p_blob uuid, p_node int, p_parity_shards smallint,
    OUT status text, OUT reap_peer text
) LANGUAGE plpgsql AS $$
DECLARE
    v_shard smallint;
BEGIN
    PERFORM pg_temp.cairn_lock_blobs(ARRAY[p_blob], ARRAY[true]);
    PERFORM 1 FROM blobs
    WHERE blob_id = p_blob AND state = 'committed' AND data_shards = 1
      AND parity_shards = p_parity_shards AND p_parity_shards > 0;
    IF NOT FOUND THEN
        status := 'changed';
        RETURN;
    END IF;
    SELECT shard INTO v_shard FROM blob_locations WHERE blob_id = p_blob AND node = p_node;
    IF NOT FOUND THEN
        status := 'gone';
        RETURN;
    END IF;
    SELECT peer_url INTO reap_peer FROM nodes WHERE id = p_node;
    DELETE FROM blob_locations WHERE blob_id = p_blob AND node = p_node;
    UPDATE blob_locations SET shard = v_shard WHERE blob_id = p_blob AND shard = p_parity_shards;
    UPDATE blobs SET parity_shards = parity_shards - 1, shard_crcs = shard_crcs[1:p_parity_shards]
    WHERE blob_id = p_blob;
    UPDATE scrub_findings SET outcome = 'gone', resolved_at = NOW()
    WHERE blob_id = p_blob AND node = p_node AND resolved_at IS NULL;
    status := 'dropped';
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
    OUT checksum_algorithm text, OUT checksum_type text, OUT storage_class text
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
                       o.checksum_algorithm, o.checksum_type, o.storage_class FROM objects o
                WHERE o.bucket = p_bucket COLLATE "default" AND o.is_latest AND o.key >= v_from
                  AND (p_delete_markers OR NOT o.is_delete_marker)
                ORDER BY o.key LIMIT p_limit - v_count;
        ELSE
            OPEN c FOR
                SELECT o.key, o.size, o.etag, o.last_modified, o.is_delete_marker, o.sse_s3,
                       o.sse_kms_key_id, o.sse_kms_data_key, o.sse_kms_sealed,
                       o.checksum_algorithm, o.checksum_type, o.storage_class FROM objects o
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
            storage_class := r.storage_class;
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
            storage_class := NULL;
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
-- the keys under `p_prefix`, newest first (see `cairn_version_time`), rolled
-- up at `p_delimiter` ('' for none), after the version with row id
-- `p_id_marker` of `p_key_marker` (or, if that's NULL, after all versions of
-- `p_key_marker`; if there's no such version any more, from the key's
-- newest).
CREATE OR REPLACE FUNCTION pg_temp.cairn_list_versions(
    p_bucket text, p_prefix text, p_delimiter text, p_key_marker text, p_id_marker bigint,
    p_limit int,
    OUT name text, OUT is_prefix boolean, OUT version_id text, OUT is_latest boolean,
    OUT is_delete_marker boolean, OUT size bigint, OUT etag text, OUT last_modified timestamptz,
    OUT sse_s3 boolean, OUT sse_kms_key_id text, OUT sse_kms_data_key text, OUT sse_kms_sealed bytea,
    OUT checksum_algorithm text, OUT checksum_type text, OUT storage_class text
) RETURNS SETOF record LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_pfx text COLLATE "C" := p_prefix;
    v_marker text COLLATE "C" := p_key_marker;
    v_delim text COLLATE "C" := p_delimiter;
    v_from text COLLATE "C" := pg_temp.cairn_walk_start(p_prefix, p_key_marker);
    v_end text COLLATE "C" := pg_temp.cairn_prefix_end(p_prefix);
    v_count int := 0;
    v_cp text COLLATE "C";
    v_marker_modified timestamptz;
    c refcursor;
    r record;
BEGIN
    SELECT o.last_modified INTO v_marker_modified FROM objects o WHERE o.id = p_id_marker;
    -- The versions of the marker's own key older than the version marker come
    -- first, if that key is listed as a key.
    IF p_id_marker IS NOT NULL AND starts_with(v_marker, v_pfx)
       AND pg_temp.cairn_common_prefix(v_marker, v_pfx, v_delim) IS NULL THEN
        RETURN QUERY
            SELECT o.key::text, false, o.version_id, o.is_latest, o.is_delete_marker, o.size,
                   o.etag, o.last_modified, o.sse_s3, o.sse_kms_key_id, o.sse_kms_data_key,
                   o.sse_kms_sealed, o.checksum_algorithm, o.checksum_type, o.storage_class
            FROM objects o
            WHERE o.bucket = p_bucket COLLATE "default" AND o.key = v_marker
              AND (v_marker_modified IS NULL OR (o.last_modified, o.id) < (v_marker_modified, p_id_marker))
            ORDER BY o.last_modified DESC, o.id DESC LIMIT p_limit;
        GET DIAGNOSTICS v_count = ROW_COUNT;
    END IF;
    WHILE v_count < p_limit LOOP
        -- The versions from v_from on, in order: a range of `objects_versions`,
        -- read until it reaches a key that rolls up into a common prefix.
        IF v_end IS NULL THEN
            OPEN c FOR
                SELECT o.key, o.version_id, o.is_latest, o.is_delete_marker, o.size, o.etag,
                       o.last_modified, o.sse_s3, o.sse_kms_key_id, o.sse_kms_data_key,
                       o.sse_kms_sealed, o.checksum_algorithm, o.checksum_type, o.storage_class
                FROM objects o
                WHERE o.bucket = p_bucket COLLATE "default" AND o.key >= v_from
                ORDER BY o.key, o.last_modified DESC, o.id DESC LIMIT p_limit - v_count;
        ELSE
            OPEN c FOR
                SELECT o.key, o.version_id, o.is_latest, o.is_delete_marker, o.size, o.etag,
                       o.last_modified, o.sse_s3, o.sse_kms_key_id, o.sse_kms_data_key,
                       o.sse_kms_sealed, o.checksum_algorithm, o.checksum_type, o.storage_class
                FROM objects o
                WHERE o.bucket = p_bucket COLLATE "default" AND o.key >= v_from AND o.key < v_end
                ORDER BY o.key, o.last_modified DESC, o.id DESC LIMIT p_limit - v_count;
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
            storage_class := r.storage_class;
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
            storage_class := NULL;
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
    OUT checksum_algorithm text, OUT checksum_type text, OUT initiator text, OUT storage_class text
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
                   u.checksum_type, u.initiator, u.storage_class
            FROM multipart_uploads u
            WHERE u.bucket = p_bucket COLLATE "default" AND u.key = v_marker
              AND u.upload_id > p_upload_marker
            ORDER BY u.upload_id LIMIT p_limit;
        GET DIAGNOSTICS v_count = ROW_COUNT;
    END IF;
    WHILE v_count < p_limit LOOP
        IF v_end IS NULL THEN
            OPEN c FOR
                SELECT u.key, u.upload_id, u.initiated_at, u.checksum_algorithm, u.checksum_type,
                       u.initiator, u.storage_class
                FROM multipart_uploads u
                WHERE u.bucket = p_bucket COLLATE "default" AND u.key >= v_from
                ORDER BY u.key, u.upload_id LIMIT p_limit - v_count;
        ELSE
            OPEN c FOR
                SELECT u.key, u.upload_id, u.initiated_at, u.checksum_algorithm, u.checksum_type,
                       u.initiator, u.storage_class
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
            initiator := r.initiator;
            storage_class := r.storage_class;
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
            initiator := NULL;
            storage_class := NULL;
            RETURN NEXT;
            v_count := v_count + 1;
        END IF;
        v_from := pg_temp.cairn_prefix_end(v_cp);
        EXIT WHEN v_from IS NULL;
    END LOOP;
END
$$;

-- T47: PutRolePolicy: sets the role's inline policy `p_name`, unless its
-- inline policies would hold more than `p_max` characters (but whitespace)
-- together (I10). Takes O(o) exclusively, then sizes them in a later
-- statement. Returns 'set', 'no_such_role' or 'too_big'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_put_role_policy(p_role uuid, p_name text, p_document text, p_max integer)
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM iam_roles WHERE id = p_role FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'no_such_role';
    END IF;
    IF (SELECT coalesce(sum(length(regexp_replace(document, '\s', '', 'g'))), 0)
        FROM iam_role_policies WHERE role_id = p_role AND name <> p_name)
       + length(regexp_replace(p_document, '\s', '', 'g')) > p_max THEN
        RETURN 'too_big';
    END IF;
    INSERT INTO iam_role_policies (role_id, name, document) VALUES (p_role, p_name, p_document)
    ON CONFLICT (role_id, name) DO UPDATE SET document = EXCLUDED.document;
    RETURN 'set';
END
$$;

-- T48: TagRole: as T42, for a role, under O(o). Returns 'tagged',
-- 'no_such_role' or 'too_many'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_tag_role(p_role uuid, p_keys text[], p_values text[], p_max integer)
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM iam_roles WHERE id = p_role FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'no_such_role';
    END IF;
    IF (SELECT count(*) FROM iam_role_tags WHERE role_id = p_role AND lower(key) <> ALL (SELECT lower(k) FROM unnest(p_keys) k))
       + cardinality(p_keys) > p_max THEN
        RETURN 'too_many';
    END IF;
    DELETE FROM iam_role_tags WHERE role_id = p_role AND lower(key) IN (SELECT lower(k) FROM unnest(p_keys) k);
    INSERT INTO iam_role_tags (role_id, key, value) SELECT p_role, k, v FROM unnest(p_keys, p_values) AS t(k, v);
    RETURN 'tagged';
END
$$;

-- T49: DeleteRole: deletes the role, unless it has inline or attached
-- policies left, as IAM refuses it (its tags and boundary don't keep it).
-- Takes O(o) exclusively, then checks in a later statement, so that no
-- policy set meanwhile goes with it unseen. Returns 'deleted',
-- 'no_such_role', 'policies' or 'attached'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_delete_role(p_role uuid)
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM iam_roles WHERE id = p_role FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'no_such_role';
    END IF;
    IF EXISTS (SELECT 1 FROM iam_role_policies WHERE role_id = p_role) THEN
        RETURN 'policies';
    END IF;
    IF EXISTS (SELECT 1 FROM iam_role_attached_policies WHERE role_id = p_role) THEN
        RETURN 'attached';
    END IF;
    DELETE FROM iam_roles WHERE id = p_role;
    RETURN 'deleted';
END
$$;

-- T57: PutGroupPolicy: sets the group's inline policy `p_name`, unless its
-- inline policies would hold more than `p_max` characters (but whitespace)
-- together (I10). Takes Q(q) exclusively, then sizes them in a later
-- statement. Returns 'set', 'no_such_group' or 'too_big'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_put_group_policy(p_group uuid, p_name text, p_document text, p_max integer)
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM iam_groups WHERE id = p_group FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'no_such_group';
    END IF;
    IF (SELECT coalesce(sum(length(regexp_replace(document, '\s', '', 'g'))), 0)
        FROM iam_group_policies WHERE group_id = p_group AND name <> p_name)
       + length(regexp_replace(p_document, '\s', '', 'g')) > p_max THEN
        RETURN 'too_big';
    END IF;
    INSERT INTO iam_group_policies (group_id, name, document) VALUES (p_group, p_name, p_document)
    ON CONFLICT (group_id, name) DO UPDATE SET document = EXCLUDED.document;
    RETURN 'set';
END
$$;

-- T58: DeleteGroup: deletes the group, unless it has members, or inline or
-- attached policies left, as IAM refuses it. Takes Q(q) exclusively, then
-- checks in a later statement, so that no member added or policy set
-- meanwhile goes with it unseen (an attachment's or a member's FK check
-- takes Q(q) shared). Returns 'deleted', 'no_such_group', 'members',
-- 'policies' or 'attached'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_delete_group(p_group uuid)
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM iam_groups WHERE id = p_group FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'no_such_group';
    END IF;
    IF EXISTS (SELECT 1 FROM iam_group_members WHERE group_id = p_group) THEN
        RETURN 'members';
    END IF;
    IF EXISTS (SELECT 1 FROM iam_group_policies WHERE group_id = p_group) THEN
        RETURN 'policies';
    END IF;
    IF EXISTS (SELECT 1 FROM iam_group_attached_policies WHERE group_id = p_group) THEN
        RETURN 'attached';
    END IF;
    DELETE FROM iam_groups WHERE id = p_group;
    RETURN 'deleted';
END
$$;

-- T59: AddUserToGroup: makes the user a member of the group, unless it's in
-- `p_max` groups already (I10). Takes R(r) exclusively, then Q(q) shared (so
-- the group isn't deleted meanwhile: T58), then counts in a later
-- statement. Returns 'added' (or already a member), 'no_such_user',
-- 'no_such_group' or 'too_many'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_add_user_to_group(p_user uuid, p_group uuid, p_max integer)
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM users WHERE id = p_user FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'no_such_user';
    END IF;
    PERFORM 1 FROM iam_groups WHERE id = p_group FOR KEY SHARE;
    IF NOT FOUND THEN
        RETURN 'no_such_group';
    END IF;
    IF EXISTS (SELECT 1 FROM iam_group_members WHERE user_id = p_user AND group_id = p_group) THEN
        RETURN 'added';
    END IF;
    IF (SELECT count(*) FROM iam_group_members WHERE user_id = p_user) >= p_max THEN
        RETURN 'too_many';
    END IF;
    INSERT INTO iam_group_members (group_id, user_id) VALUES (p_group, p_user);
    RETURN 'added';
END
$$;

-- T60: RemoveUserFromGroup: ends the user's membership of the group. Takes
-- R(r) exclusively, as every change of a user's memberships does (T59, and
-- deleting the user), so that the trigger that keeps its `cairn:groups`
-- policy (see `db::IAM_GROUPS`) sees all of them. Returns 'removed',
-- 'no_such_user' or 'not_member'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_remove_user_from_group(p_user uuid, p_group uuid)
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM users WHERE id = p_user FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'no_such_user';
    END IF;
    DELETE FROM iam_group_members WHERE user_id = p_user AND group_id = p_group;
    IF NOT FOUND THEN
        RETURN 'not_member';
    END IF;
    RETURN 'removed';
END
$$;

-- T50: AddClientIDToOpenIDConnectProvider: adds `p_client` to the
-- provider's client IDs, unless it would have more than `p_max` (I10).
-- Takes D(d) exclusively, then counts in a later statement. Returns 'added'
-- (also if it was there), 'no_such_provider' or 'too_many'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_add_oidc_client_id(p_provider uuid, p_client text, p_max integer)
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM iam_oidc_providers WHERE id = p_provider FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'no_such_provider';
    END IF;
    IF EXISTS (SELECT 1 FROM iam_oidc_provider_client_ids WHERE provider_id = p_provider AND client_id = p_client) THEN
        RETURN 'added';
    END IF;
    IF (SELECT count(*) FROM iam_oidc_provider_client_ids WHERE provider_id = p_provider) >= p_max THEN
        RETURN 'too_many';
    END IF;
    INSERT INTO iam_oidc_provider_client_ids (provider_id, client_id) VALUES (p_provider, p_client);
    RETURN 'added';
END
$$;

-- T51: TagOpenIDConnectProvider: as T42, for an OIDC provider, under D(d).
-- Returns 'tagged', 'no_such_provider' or 'too_many'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_tag_oidc_provider(p_provider uuid, p_keys text[], p_values text[], p_max integer)
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM iam_oidc_providers WHERE id = p_provider FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'no_such_provider';
    END IF;
    IF (SELECT count(*) FROM iam_oidc_provider_tags
        WHERE provider_id = p_provider AND lower(key) <> ALL (SELECT lower(k) FROM unnest(p_keys) k))
       + cardinality(p_keys) > p_max THEN
        RETURN 'too_many';
    END IF;
    DELETE FROM iam_oidc_provider_tags WHERE provider_id = p_provider AND lower(key) IN (SELECT lower(k) FROM unnest(p_keys) k);
    INSERT INTO iam_oidc_provider_tags (provider_id, key, value) SELECT p_provider, k, v FROM unnest(p_keys, p_values) AS t(k, v);
    RETURN 'tagged';
END
$$;

-- T52: UpdateOpenIDConnectProviderThumbprint: replaces the provider's
-- thumbprints (at most five, none twice: checked by the caller) with `p_thumbprints`,
-- under D(d), so that two replacements don't mix. Returns 'set' or
-- 'no_such_provider'.
CREATE OR REPLACE FUNCTION pg_temp.cairn_set_oidc_thumbprints(p_provider uuid, p_thumbprints text[])
RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM iam_oidc_providers WHERE id = p_provider FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'no_such_provider';
    END IF;
    DELETE FROM iam_oidc_provider_thumbprints WHERE provider_id = p_provider;
    INSERT INTO iam_oidc_provider_thumbprints (provider_id, thumbprint)
    SELECT p_provider, t FROM unnest(p_thumbprints) WITH ORDINALITY AS u(t, n) ORDER BY n;
    RETURN 'set';
END
$$;

-- T53: CreateOpenIDConnectProvider: makes the provider, with its client
-- IDs, thumbprints and tags (each checked by the caller), all at once. A
-- provider of the URL already there is the unique index's violation.
-- Returns the new provider's ID.
CREATE OR REPLACE FUNCTION pg_temp.cairn_create_oidc_provider(
    p_account text, p_url text, p_clients text[], p_thumbprints text[], p_keys text[], p_values text[])
RETURNS uuid LANGUAGE plpgsql AS $$
DECLARE
    v_id uuid;
BEGIN
    INSERT INTO iam_oidc_providers (account_id, url) VALUES (p_account, p_url) RETURNING id INTO v_id;
    INSERT INTO iam_oidc_provider_client_ids (provider_id, client_id)
    SELECT v_id, c FROM unnest(p_clients) WITH ORDINALITY AS u(c, n) ORDER BY n;
    INSERT INTO iam_oidc_provider_thumbprints (provider_id, thumbprint)
    SELECT v_id, t FROM unnest(p_thumbprints) WITH ORDINALITY AS u(t, n) ORDER BY n;
    INSERT INTO iam_oidc_provider_tags (provider_id, key, value)
    SELECT v_id, k, v FROM unnest(p_keys, p_values) WITH ORDINALITY AS u(k, v, n) ORDER BY n;
    RETURN v_id;
END
$$;

-- T74: claims up to `p_limit` uneven blobs of pool `p_pool` (see
-- `placement`, `mover`), to spread them, skipping those another transaction
-- has locked (it never waits) or a job has leased. Leases them, as the
-- packer's claim does (I8).
CREATE OR REPLACE FUNCTION pg_temp.cairn_claim_spread(
    p_pool text, p_limit int, p_lease_secs float8
) RETURNS uuid[] LANGUAGE plpgsql AS $$
DECLARE
    v_claimed uuid[] := '{}';
    r record;
BEGIN
    FOR r IN
        SELECT blob_id FROM blobs
        WHERE uneven AND pool = p_pool AND state = 'committed'
          AND (pack_lease_until IS NULL OR pack_lease_until < NOW())
        ORDER BY blob_id
        LIMIT p_limit
        FOR UPDATE SKIP LOCKED
    LOOP
        v_claimed := v_claimed || r.blob_id;
    END LOOP;
    UPDATE blobs SET pack_lease_until = NOW() + make_interval(secs => p_lease_secs)
    WHERE blob_id = ANY(v_claimed);
    RETURN v_claimed;
END
$$;
