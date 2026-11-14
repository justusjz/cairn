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
- **Dashboard.** A web UI on the peer endpoint showing nodes, disks, request
  rates, replica health and background jobs, with a bucket explorer and role
  management. Since replaced by the console.
- **Metadata-only copies.** CopyObject and UploadPartCopy point the new object
  at the existing data instead of copying it. (A part copied from a range that
  spans several parts of its source is still copied as data.)
- **Scrubbing.** Every node checks its data against its checksums in the
  background, at a set rate, and repairs damaged copies from the intact
  blocks of others; data intact on no replica is reported, and reads of it
  fail up front. Data from before checksums is rewritten with them.

## Next

- **Erasure coding.** Every blob is k data and m parity shards, and
  replication is k = 1; blobs over 64 MiB are coded with k > 1, which takes
  less space for the same tolerance of lost nodes, as they're written if
  their size is known, else by the packer. Existing blobs follow changes of
  the settings. Implemented.
- **Replica repair and removing nodes.** `cairn node remove` moves a node's
  shards to the others, copied from it while it's up, else rebuilt from the
  other shards; the `repair-after` setting rebuilds a node's shards once it
  has been down that long. Implemented.
- **Replication factor in the database.** The `parity-shards` setting, next
  to `data-shards`: unset, every node goes by its `--replication-factor` as
  before; once set, it overrides the flags. Implemented; the flag can go in
  a later release.
- **Cluster status.** A `cairn status` command that shows which nodes are
  down, and how much data is below the replication factor. (The console's
  Storage page shows this already.)
- **CI.** Running the test suites (`db-test.sh`, `test.sh`, `ha-test.sh`) on
  every change.

- **Console and IAM.** Implemented: a web UI with passkey and OIDC sign-in
  on a listener of its own, which replaced the dashboard; one account,
  whose operators are users with `cairn:` policies; IAM policies, inline
  and managed (Cairn's with AWS's names, and the account's own), bucket
  policies, permissions boundaries, paths and tags, and the IAM API. Open:
  policy templates (a team, a service user, the MFA guard), groups, tag
  conditions, and STS with roles (`AssumeRoleWithWebIdentity`).

- **Object Lock.** Retention periods and legal holds, which keep versions
  from being deleted, by anyone or by lifecycle rules, as in S3: what makes
  history safe from admin credentials too. Implemented, with governance
  and compliance modes.
- **Lifecycle transitions.** Moving objects between storage classes by
  lifecycle rules, once Cairn has more than one (erasure-coded storage, say).
  Expiration rules are done.

## Ideas

Smaller improvements, done when they're needed:

- **A queue of due lifecycle actions**, so that lifecycle sweeps read only
  what's due, instead of every version under the rules' prefixes each day.
  Writes would add the actions their versions become due for (expire this
  version on day D; remove that one, now noncurrent, on day E; …) to a table
  indexed by due time, from the two catalog functions every write and delete
  goes through (`cairn_put_version`, `cairn_delete_key`), and sweeps would
  take what's due from it. Its entries would only be hints, checked again
  when they're executed as expirations are now, so writes only ever add to
  it. Changing a bucket's rules would hold up its writes while the change
  commits (as changing versioning does), and rebuild its queue by one sweep
  of today's kind, which would also stay as an occasional backstop. Worth it
  once buckets with rules hold hundreds of millions of versions.
- Compacting more eagerly as disks fill up.
- Preferring locally held data when packing.
