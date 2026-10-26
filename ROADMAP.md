# Roadmap

Where Cairn is headed, roughly in order. Items without a settled design say
so; this file records what's planned, not how it will be built.

## Next release

Object versioning, and storage reorganized around blobs, which several
objects can share, so that clusters with many small objects stay cheap to run.

Done:

- **Object versioning.** Buckets can keep every version of an object, as in
  S3.
- **Blobs with checksums.** Objects are stored as byte ranges of blobs. Every
  blob is checksummed in 64 KiB blocks, and every read is verified, falling
  back to another replica on damage.
- **Packing.** Small objects are packed together into 256 MiB blobs, and
  packed blobs are compacted once a quarter of them is garbage.
- **Automatic garbage collection.** Leftovers of crashes and failed uploads
  are cleaned up in the background; `cairn prune` is gone.
- **Concurrent writes.** Conflicting requests are retried with backoff, and
  answered with 503 SlowDown if they still can't complete, instead of 500.
- **Admin UI.** A web UI (`--listen-admin`) showing nodes, disks, request
  rates, replica health and background jobs, with a bucket explorer and role
  management.
- **Metadata-only copies.** CopyObject and UploadPartCopy point the new object
  at the existing data instead of copying it. (A part copied from a range that
  spans several parts of its source is still copied as data.)

## Next

- **Replication factor in the database.** One setting for the whole cluster,
  instead of a `serve` flag that every node must agree on. Open: how existing
  clusters move over.
- **Cluster status.** A `cairn status` command that shows which nodes are
  down, and how much data is below the replication factor. (The admin UI's
  Storage page shows this already.)
- **Replica repair.** Restoring copies lost with a node. Open: when it runs
  on its own (if ever), and when it waits for the operator to add a node, so
  that data doesn't move twice.
- **Removing a node.** Moving a node's data off before it's taken away, so
  that redundancy never drops.
- **Scrubbing.** Checking stored data against its checksums in the
  background, and repairing damaged copies.
- **CI.** Running the test suites (`db-test.sh`, `test.sh`, `ha-test.sh`) on
  every change.

## Later

- **Erasure coding.** Converting data to an erasure-coded layout in the
  background, to store it with less overhead than full replicas.

## Ideas

Smaller improvements, done when they're needed:

- Compacting more eagerly as disks fill up.
- Preferring locally held data when packing.
- Per-key locking for writes, if very busy buckets still see SlowDown.
