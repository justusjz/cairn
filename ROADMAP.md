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
  on a listener of its own, which replaced the dashboard; accounts in an
  organization, whose management account's operators are users with
  `cairn:` policies; IAM policies, inline
  and managed (Cairn's with AWS's names, and the account's own), bucket
  policies, permissions boundaries, paths and tags, groups, and the IAM
  API. Open: policy templates (a team, a service user, the MFA guard), tag
  conditions, and STS with roles (`AssumeRoleWithWebIdentity`).
  S3 Access Grants (IAM grantees): implemented. Directory users, as
  Identity Center's (OIDC identity sources, permission sets as reserved
  roles, assignments to users and groups, sso-admin's API and
  identitystore's reads): implemented. Permission sets provisioned per
  account (as roles made at their first assignment there, updated by
  provisioning), and assignments and directory users' sessions in an
  account. Cairn's own directory (users and groups made with
  identitystore's writes, or the console; passkeys set up with links):
  implemented. Member accounts, as AWS Organizations has them (the
  existing account as the management account, CreateAccount with
  `OrganizationAccountAccessRole`, cross-account AssumeRole, CloseAccount):
  implemented. Cross-account access to SNS topics (their policies) and
  Access Grants (instances' resource policies): implemented (KMS keys are
  OpenBao's, whose policies decide their use). Organizational units and
  service control policies: implemented. Next: organization condition
  keys (`aws:PrincipalOrgID`, `aws:PrincipalOrgPaths`). The console's
  OUs and SCPs: implemented. Also: directory users and groups as Access Grants
  grantees, switching roles in the console, and the access portal's APIs
  for `aws sso login`.

- **Object Lock.** Retention periods and legal holds, which keep versions
  from being deleted, by anyone or by lifecycle rules, as in S3: what makes
  history safe from admin credentials too. Implemented, with governance
  and compliance modes.
- **Inventory and Batch Operations.** S3 Inventory: daily or weekly reports
  of a bucket's objects, as S3 writes them (CSV or Parquet; not ORC),
  paced by the rate lifecycle sweeps go at, which they share. Implemented. Batch
  Operations: jobs that tag objects (or remove their tags) and set their
  Object Lock retention and legal holds, from CSV manifests or inventory
  reports (CSV or Parquet), or from manifests they generate from a bucket's
  objects and S3's filters (snapshots, kept internally or written out), as a
  role, at that rate too, with completion reports, and copy objects, each copy
  recorded with the version it writes, so that one done again when a node dies
  mid-page makes no second version; set their ACLs, work out their checksums
  at rest (in the completion report), and change their encryption to SSE-KMS
  in place. Implemented.
- **Storage classes.** Classes of the operator's, each in a pool of the
  nodes' disks (`--data-dir <pool>=<path>`, several per node) with a layout
  of its own; objects ask for one with `x-amz-storage-class`, and change
  class by being copied, or by lifecycle transitions; the packer rewrites a
  class's data after a change of its pool or layout. Implemented.
- **Backups.** The whole cluster, continuously, to a bucket of another S3
  service: its database's changes in journals every few minutes (the RPO),
  with the parts' bytes, in few, large, encrypted objects, and base
  snapshots; restored into a new database from that bucket alone, with
  the data readable at once and copied into the new cluster in the
  background. Implemented, with restores to a point in time within the
  retention.
- **Bucket replication.** S3's replication configurations
  (`PutBucketReplication`), as a role, with S3's statuses. Within the
  cluster: replicas share their sources' bytes, so they cost only metadata,
  except in another storage class. Implemented. Next: replicating to
  another Cairn cluster, keeping version IDs, with deletes, tags and
  retention kept in sync, both ways (a remote target registered with its
  endpoint and credentials). Then replicating to other S3 providers, one
  way only, without their version IDs (the provider makes its own). Also:
  later changes to tags and Object Lock. Batch Replication (existing
  objects, as a Batch Operations job) is done, of CSV manifests, inventory
  reports and generated manifests, with their filters
  (`EligibleForReplication`, `ObjectReplicationStatuses`, …).
- **Remote tiers.** Storage classes that keep their data in a bucket of
  another S3 service (`cairn tier`): written into the cluster first, then
  moved there by the packer, packed and encrypted, and read from there.
  Backups point at the tiers' objects rather than copying them, and a
  restored cluster reads them, read-only until it's given the tier.
  Implemented, for tiers whose objects can be read at once. Next: cold
  tiers (Glacier Flexible Retrieval, Deep Archive), whose objects need a
  restore first: `RestoreObject` and its status (`x-amz-restore`,
  `RestoreStatus`, the `s3:ObjectRestore:*` events), as a request that
  restores the tier's objects holding a version's parts, and copies those
  parts into the cluster for the days asked, once the tier has; reads of
  an object that isn't restored fail with `InvalidObjectState`, as in S3.
- **Lifecycle transitions.** Moving objects between storage classes by
  lifecycle rules (`Transition`, `NoncurrentVersionTransition`), into
  lower classes in the order the operator ranks them (`cairn class set
  --rank`). A transition only relabels the version, which the blob's
  higher class stands in for; the packer moves the bytes into their class
  when it rewrites the blob, once its garbage and misplaced bytes together
  make it worth it. Implemented. Next: compacting more eagerly as pools
  fill up (see below), which moves misplaced bytes sooner too.

- **S3 Tables.** Table buckets of Iceberg tables, as AWS has them: the
  `s3tables` API, each table's storage as a bucket of the cluster's, table
  bucket and table policies, and Iceberg's REST catalog (signed for
  `s3tables`) for PyIceberg, Spark, Trino and DuckDB, and the
  maintenance S3 does itself: compaction (`binpack`, `sort`, `z-order`),
  snapshot expiry and removing unreferenced files. Implemented. Next:
  maintaining SSE-KMS tables, replication of tables, and table buckets'
  access logs. See `plans/s3-tables.md`.

- **S3 Select.** SelectObjectContent over CSV and JSON, uncompressed or
  gzipped, with `ScanRange`s (which AWS SDK for pandas splits objects
  into) and timestamps with the date and time functions, for applications
  that still use it: AWS closed it to new customers in 2024, and MinIO had
  it. Implemented. Next: Parquet input, paths into JSON documents in
  `FROM`, and BZIP2.

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
