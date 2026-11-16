# S3 Inventory, then Batch Operations

Inventory is implemented as described below; Batch Operations are not
yet (see **Later**).

S3 Inventory first, as S3 has it: a scheduled report of a bucket's
objects, written as files to a bucket. Batch Operations come after, on
what inventory builds; they're sketched under **Later** and not built yet.

## Why

Batch Operations (one action over millions of objects: tagging, Object
Lock retention, copies in place to re-encrypt) are worth having in a
system with versioning, Object Lock and SSE. Their manifests are most
often inventory reports, and inventory is useful by itself: audits
("is everything encrypted?", "what's under retention?"), and tools that
read inventories (Athena, Spark, `s3 inventory`-aware scripts) work
unchanged.

Inventory also builds most of what Batch Operations need: a background
job over a whole bucket that goes at a set pace and survives restarts,
Cairn writing objects into a bucket on its own behalf, destination bucket
policies naming `s3.amazonaws.com`, and CSV with manifests.

A bucket can hold billions of versions, so three things matter more than
anything else here: a report is **resumable** (a node dying loses at most
one data file's work), it's **paced** (it never takes more of the
database than the operator allows), and it's **streamed** (no part of a
report is ever held in memory whole: not its rows, not its files, not
its manifest).

## What

### The API

`PutBucketInventoryConfiguration`, `GetBucketInventoryConfiguration`,
`DeleteBucketInventoryConfiguration` and `ListBucketInventoryConfigurations`
(`?inventory`, `?inventory&id=`), checked as `s3:PutInventoryConfiguration`
and `s3:GetInventoryConfiguration` (the actions and
`s3:InventoryAccessibleOptionalFields` are known to the policy engine
already), validated as S3 validates them, up to 1,000 per bucket.

Only `CSV` is produced. A configuration asking for `ORC` or `Parquet` is
refused, `501 NotImplemented`, a difference in `S3-COMPATIBILITY.md`,
rather than accepted and never delivered. The other formats can come
later; nothing below depends on the format but the encoder.

A configuration is kept per bucket and ID (`inventories`, one row each),
as JSON, with a generation that every change of it increases, and the
user that set it, as whom an SSE-KMS report asks the KMS for its data
keys (as a bucket's default encryption does).

### Reports

A report is a run over the bucket's versions (`IncludedObjectVersions`
`All`) or its current objects (`Current`: no noncurrent versions, no
delete markers), under the configuration's prefix, in key order (and
each key's versions newest first). Its output, in AWS's layout under the
destination's prefix:

- data files, `<prefix>/<bucket>/<id>/data/<uuid>.csv.gz`: gzipped CSV,
  every value quoted, no header, keys URL-encoded;
- `<prefix>/<bucket>/<id>/<YYYY-MM-DDTHH-MMZ>/manifest.json`, listing the
  data files with their sizes and MD5s, and `manifest.checksum`, the
  manifest's MD5;
- `<prefix>/<bucket>/<id>/hive/dt=<YYYY-MM-DD-HH-MM>/symlink.txt`, the data
  files' `s3://` URLs, for Athena and Hive.

The fields come from the catalog: size, last-modified, ETag (opened, for
SSE-S3), multipart (the version was completed from an upload), encryption
status, Object Lock mode, retain-until and legal hold, checksum
algorithm, owner (the account's canonical ID), the ACL (the owner's full
control: ACLs are always disabled) and the lifecycle expiration date
(from the bucket's rules). Storage class is always `STANDARD`;
replication status, Intelligent-Tiering tier and bucket key status are
empty, as S3 leaves them for objects they don't apply to.

A report is as of no single moment, as S3's aren't: what's written or
deleted while it runs may or may not be in it.

### Delivery

Cairn writes a report's files as the `s3.amazonaws.com` service, as S3
does, so the destination bucket's policy has to allow it, as on AWS:
`s3:PutObject` on the destination's objects, to the `Service` principal
`s3.amazonaws.com`, with `aws:SourceAccount` (the account) and
`aws:SourceArn` (the source bucket's ARN) in the request's context, and
`s3:x-amz-acl` as `bucket-owner-full-control`. That's the one place a
`Service` principal ever matches; it never matches anything a client
sends. Only a statement naming the service allows it (`*` doesn't).

The files are ordinary writes otherwise: the destination's versioning,
Object Lock defaults and default encryption apply, and the configuration's
`SSE-S3` or `SSE-KMS` encrypts them.

A delivery that fails (no destination, a policy that doesn't allow it, a
KMS that refuses) is retried an hour later, from where the report had
got to; the failure is logged, shown among the events on the console's
Jobs page, and kept with the configuration.

### Pacing: one budget with lifecycle sweeps

Inventory reports and lifecycle sweeps both read versions from the
catalog in the background, so they share one budget: the
`lifecycle-rate` setting, versions read per hour across the cluster,
which now covers both (its name stays, so existing settings keep
working). They share its steps too: one step at a time in the whole
cluster, about once a minute, under the lease lifecycle sweeps take
already. A step serves whichever lifecycle sweep or inventory report has
waited longest, gives it its turn, and sends it to the back of the line,
until the step's share of the rate is used up. So when only one of them
has work, it gets the whole rate; when both do, they take turns.

A lifecycle turn reads as much as is left of the step's share, as now.
An inventory turn writes one data file, which has to be written whole
(see below), and so may read more than is left; what it reads over is a
debt, which the next steps pay off before they read anything. The rate
holds on average, and a data file is at most about ten minutes of the
rate (`rate / 6` versions, between 10,000 and 1,000,000), so no turn
runs far ahead of it.

### Resuming

A data file is one object, written in one turn, streamed (see below).
After it's written, the report's cursor (the last key, and version, it
holds) and the file (its key, size and MD5) are saved together. A node
that dies mid-file leaves an upload that never committed, which the
garbage collector cleans up; the next turn, on any node, starts that file
over from the saved cursor. A report's files are rows of their own
(`inventory_files`), so a report of any size keeps only its cursor in
the configuration's row.

Once the last data file is written, the manifest, its checksum and the
symlink file are written from those rows, the rows are dropped, and the
next report is due a day (`Daily`) or a week (`Weekly`) after this one
started. A changed configuration (a new generation) starts its report
over; a deleted one drops it.

### Streaming

Rows are read a page (1,000) at a time, written as CSV into a gzip
encoder, and its output goes out as the body of the data file's write
(the same streaming write PutObject uses), through a bounded channel. So
a turn holds one page of rows, the encoder's window and a few chunks in
flight, whatever the bucket's size. The MD5 for the manifest is computed
over the compressed bytes as they go out. The manifest and symlink files
are streamed the same way, from the file rows, a page at a time.

## Later

- **ORC and Parquet**, when someone needs them.
- **The console** showing a bucket's inventory configurations and their
  last reports (and failures), and setting them.
- **Batch Operations**, under S3 Control (`/v20180820/jobs`): `CreateJob`,
  `DescribeJob`, `ListJobs`, `UpdateJobStatus`, `UpdateJobPriority`, job
  tags. Manifests as CSV or inventory reports (`manifest.json`), later
  S3's manifest generator. Operations first: object tags, Object Lock
  retention and legal holds, and copies (in place, to re-encrypt). Jobs
  run as a role (`iam:PassRole`), at the same shared pace, resumable as
  reports are, and write completion reports. Not Lambda invocations,
  restores or replication.

## How it went in

- `src/inventory/`: configurations (`config.rs`), reports (`mod.rs`),
  their tests (`e2e.rs`).
- `src/s3/buckets/inventory.rs`: the API.
- `src/lifecycle/mod.rs`: steps serve inventory reports too, and carry
  the debt.
- `src/policy/`: the `Service` principal, for deliveries only.
- Migration 54: `inventories`, `inventory_files`, `lifecycle_runs.debt`.
