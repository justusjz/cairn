# S3 Tables

Amazon S3 Tables, as AWS has them: table buckets of Apache Iceberg tables,
managed through the `s3tables` API and Iceberg's REST catalog protocol,
with their data in storage that S3's object API reads and writes. MinIO
has the same in AIStor Tables (an Iceberg REST catalog in the object store,
signed for `s3tables`, though without AWS's `s3tables` API itself).

The point: Spark, Trino, PyIceberg and DuckDB can use a Cairn cluster as
their lakehouse with nothing else to run, configured as for AWS (SigV4,
signing name `s3tables`), and AWS's tools (`aws s3tables`, the SDKs,
Terraform) work against it.

AWS's reference, as of November 2026: the API reference's S3 Tables
operations, botocore's `s3tables/2018-05-10` model (58 operations), the
service authorization reference for `s3tables`, and the user guide's
`s3-tables-*` pages. What those don't say is marked *unverified* below,
and has to be probed or decided.

## What S3 Tables is

- **Table buckets**, an account's, unique by name in the account (not
  globally), `arn:aws:s3tables:<region>:<account>:bucket/<name>`. Names:
  3 to 63 of `[a-z0-9-]`, a letter or digit at both ends, not starting with
  `xn--`, `sthree-`, `amzn-s3-demo-` or `aws`, not ending in a reserved
  suffix. At most 100 per account.
- **Namespaces** in a table bucket, one level only. Names: 1 to 255 of
  `[a-z0-9_]`, starting with a letter or digit, not with `aws`. At most
  10,000 per bucket.
- **Tables** in a namespace, format `ICEBERG` only,
  `…:bucket/<name>/table/<table-id>`: by ID, so a rename keeps the ARN. At
  most 10,000 per bucket. A table is a pointer to its current
  `metadata.json` (`metadataLocation`), swapped by
  UpdateTableMetadataLocation against a `versionToken` (409 `Conflict` if
  it's stale): Iceberg's atomic commit. And a **warehouse location** of its
  own, `s3://<random>--table-s3`, where its files are.
- **Table storage.** The warehouse location is a bucket for S3's object
  API, with a handful of its operations: GetObject, HeadObject, PutObject,
  the multipart ones and ListParts. No listings, no deletes, no copies,
  tags, ACLs or presigned URLs. Reads need `s3tables:GetTableData` on the
  table's ARN, writes `s3tables:PutTableData`. Only maintenance deletes
  files.
- **Policies.** A table bucket's resource policy, and a table's, besides
  identity policies: IAM's evaluation, with `s3tables:` actions (one per
  operation, plus GetTableData, PutTableData, PutTableEncryption,
  PutTableStorageClass), and condition keys `s3tables:namespace`,
  `s3tables:tableName`, `s3tables:SSEAlgorithm`, `s3tables:KMSKeyArn`,
  `s3tables:StorageClass`, `s3tables:TableBucketTag/<key>`, and the
  `aws:ResourceTag`, `aws:RequestTag` and `aws:TagKeys` keys. Policies that
  would make a bucket or table public are refused.
- **Configuration.** Encryption (SSE-S3 or SSE-KMS) and storage class
  (`STANDARD`, `INTELLIGENT_TIERING`) of a bucket, the default for its new
  tables, and of a table, fixed when it's created. Tags. Request metrics
  (a CloudWatch switch). Server access logging.
- **Maintenance**, which S3 runs itself:
  - *Compaction* of a table (on by default): small files into ones of a
    target size (64 to 512 MB), by `binpack`, `sort` or `z-order`,
    applying row-level deletes, as a new snapshot.
  - *Snapshot management* of a table: expires snapshots older than
    `maxSnapshotAgeHours` (default 120) beyond the newest
    `minSnapshotsToKeep` (default 1). Fails for tables with tags or
    branches, or `history.expire.*` properties.
  - *Unreferenced file removal* of a bucket's tables: files no snapshot
    has referenced for `unreferencedDays` (default 3) become noncurrent,
    and are deleted after `nonCurrentDays` (default 10).
  - Job status per table and kind: `Not_Yet_Run`, `Successful`, `Failed`
    (with a message), `Disabled`.
- **The Iceberg REST endpoint**, `https://s3tables.<region>.amazonaws.com/iceberg`,
  whose warehouse (and URL prefix) is the table bucket's ARN: config,
  namespaces (create, load, exists, list, drop; the `owner` property
  only), tables (create, load, exists, list, commit, drop with purge,
  rename). Not views, register-table, staged creates (400), multi-table
  transactions, credential vending, scan planning, or metadata files over
  50 MB. Each operation is authorized as its `s3tables:` actions (a commit,
  as UpdateTableMetadataLocation, PutTableData and GetTableData).
- **Newer, and AWS's own:** replication of tables to other buckets (a
  role, up to 5 destinations), record expiration (AWS-managed tables only:
  `MethodNotAllowed` otherwise), the AWS-managed `aws-s3` bucket of S3
  Metadata's tables, and migrating tables from Glue.

## How it fits Cairn

Requests signed for `s3tables` are S3 Tables', whatever their path, as
IAM's, SNS's and Organizations' are routed by their signature's service
(`s3::handle_request`): paths under `/iceberg/` are the REST catalog's,
the rest the `s3tables` API's (restJson1). So the S3 endpoint is the
`s3tables` endpoint too, as with the other services: `aws s3tables
--endpoint-url https://s3.example.com`, and the catalog's `uri` is
`https://s3.example.com/iceberg`.

**A table's storage is a bucket** of Cairn's, named as AWS's warehouse
locations are (`<36 characters>--table-s3`, which no S3 bucket can be:
`--table-s3` is reserved already in `buckets::create`). So its files get
everything a bucket's objects have: blobs, packing, erasure coding,
scrubbing, storage classes and tiers, backups, SSE. What's different is
in front of it, as with directory buckets (`s3::directory`):

- not in ListBuckets, and no bucket-level operation on it (HeadBucket
  *unverified*);
- object operations other than AWS's list refused (`MethodNotAllowed`,
  *unverified*: probe), and so are headers asking for anything but its
  ACL, storage class and encryption;
- authorized as the table's: `s3:GetObject` and the like become
  `s3tables:GetTableData`/`PutTableData` on the table's ARN, under the
  identity's policies, the table bucket's and the table's, with
  `s3tables:namespace` and `s3tables:tableName` set (`s3::actions`);
- unversioned; its objects' storage class and encryption are the table's.

Its files are written by clients through the S3 API (signed for `s3`, the
bucket in the path or host; *unverified* for AWS, which documents only
the host), and by Cairn itself, as it does the internal bucket's
(`internal`): the metadata files of the REST catalog's commits, and
maintenance's.

**The catalog is in Postgres.** A commit is one transaction that locks
the table's row, checks its version token or the commit's requirements,
and swaps its metadata location. Nothing else needs to be consistent.

## Schema (migration 84)

- `table_buckets`: ID, account, name (unique per account), created at,
  policy (and its principals' IDs, as a bucket policy's), encryption,
  storage class, maintenance configuration (JSON), metrics, tags.
- `table_namespaces`: ID, table bucket, name, created at and by.
- `tables`: ID, table bucket, namespace, name (unique per namespace), its
  storage bucket, metadata location, version token, created and modified
  at and by, policy, encryption, storage class, maintenance
  configuration, tags. A deleted table's row goes at once; its storage
  bucket, which no table names any more, is purged in the background.
- Lock protocol 17, so that no older node writes to table storage.

Phase 3 adds `table_maintenance_runs` (per table and kind: status, last
run, failure message, cursor) and `table_noncurrent_files`.

Backups capture every table but those listed in `backup::capture::EXCLUDED`,
which its test checks, so these come along.

## Phase 1: table buckets, namespaces, tables, and their storage

Done, as below, with these choices made on the way:

- A table's storage gets its encryption and storage class from the
  table on each write (the gate sets the headers), not as the bucket's
  default: so they follow the table's configuration. Without a KMS,
  SSE-S3 (the default) stores files unencrypted.
- Compaction is `disabled` in a table's configuration by default (AWS's is
  enabled), as nothing runs it. Snapshot management and unreferenced file
  removal are enabled by default, as AWS's, and report `Not_Yet_Run`.
- Table storage refuses SigV2 (and so SigV2-presigned URLs, botocore's
  default for S3), as directory buckets do.
- A denied `s3tables` request is `403 AccessDeniedException`.
- Batch Operations, replication, generated manifests and copies can't
  reach table storage either.

The `s3tables` API, without Iceberg's metadata: everything a client that
writes its own `metadata.json` needs (the AWS SDKs, AWS's own
`s3-tables-catalog-for-iceberg` for Java, Terraform).

1. **Routing and the wire format** (`tables::mod`): `s3tables` in the
   dispatch, restJson1 bodies and errors (`{"message": …}` with
   `x-amzn-errortype`; BadRequest 400, Forbidden and AccessDenied 403,
   NotFound 404, Conflict 409, TooManyRequests 429), ARNs in paths
   URL-encoded, pages with continuation tokens. `auth::wrong_service`
   no longer refuses `s3tables`.
2. **Table buckets**: Create, Get, List (prefix, `maxBuckets`, `type`),
   Delete (empty only). Names as above.
3. **Namespaces**: Create, Get, List, Delete (empty only).
4. **Tables**: Create (format `ICEBERG`; `metadata` refused with 501
   until Phase 2), Get (by bucket, namespace and name, or by ARN), List,
   Rename (within the bucket, across namespaces too), Delete (optional
   version token), Get and UpdateTableMetadataLocation. A new location
   must start with the warehouse location and end in `.metadata.json` or
   `.metadata.json.gz`. A version token is random per write.
5. **Storage buckets**: made with their table, in the same transaction;
   gated as above. A deleted table's bucket is emptied in the background
   (its versions deleted as lifecycle expirations delete them), then
   dropped: DeleteTable doesn't wait for it. Storage buckets count toward
   no bucket limit.
6. **Authorization** (`policy`, `s3::actions`):
   - `On::TableBucket` and `On::Table`, and their ARNs.
   - `Kind::TableBucket` and `Kind::Table` resource policies: their
     principals, `s3tables:` actions only, on the bucket and its tables
     (or the table) only. Refused if public.
   - The condition keys above.
   - CreateTable's dependent actions (`PutTableEncryption`,
     `PutTableStorageClass`, `TagResource`, and `PutTableData` once it
     takes metadata).
   - AWS's managed policies `AmazonS3TablesFullAccess` and
     `AmazonS3TablesReadOnlyAccess` (`managed`).
   - Cross-account: other accounts of the organization, by the
     resource policies, as for SNS topics.
7. **Policies, encryption, storage class, tags**: their operations.
   - Encryption `aws:kms` takes Cairn's key IDs, as SSE-KMS does
     (`<mount>/<key>`, an `arn:aws:kms:` prefix stripped). Without a KMS,
     `AES256` is refused as a bucket's default encryption is.
   - Storage classes are the operator's, by S3's names: an undefined
     `INTELLIGENT_TIERING` is `STANDARD`, as for objects.
8. **Accepted, without effect**: the metrics configuration (Put, Get,
   Delete; Cairn has its own metrics).
9. **Refused**:
   - With 501: replication, logging (until Phase 5), Glue migrations.
   - With `MethodNotAllowed`, as AWS answers for customer tables: record
     expiration.
   - Maintenance configurations: stored and returned with AWS's defaults
     (Phase 3 makes them do something). Enabling compaction is refused
     until Phase 4.
10. **Console**: a Table buckets page (buckets, namespaces, tables, their
    policies and configuration; a table's metadata location and
    snapshots once Phase 2 reads them).
11. **Docs**: S3-COMPATIBILITY.md's S3 Tables section, the README's,
    ROADMAP.md.

Tests: e2e tests in Rust as the other features have (`tables::e2e`, run
by `db-test.sh`): names, pages, conflicts, every action's authorization
and the resource policies, storage's gate. And `aws s3tables` in
`test.sh`, with a table written by hand (a `metadata.json` PUT into
storage, then UpdateTableMetadataLocation).

## Phase 2: Iceberg's REST catalog

Done, as below, with these choices made on the way:

- New tables' IDs are fresh, as Java's `newTableMetadata` assigns them
  (a struct's fields first, then what's in each; partition fields from
  1000), so a table's metadata doesn't depend on its client's numbering.
- Format versions 2 and 3; 1 is refused.
- A table made through the `s3tables` API without metadata has none until
  a commit gives it (as a staged creation's updates would: `assert-create`
  holds); loading it is a 404 until then.
- A commit with no changes writes no file.
- The config's S3 settings are defaults, not overrides, so that an
  engine's own (another endpoint, say) win.
- Metrics reports are taken and dropped (`204`), as Java's engines send
  them unless told not to; PyIceberg's commit retries work as they do with
  AWS.
- Making a table writes its first metadata file after the table's row is
  committed; if that fails, the row goes again.

What makes it useful to Spark, Trino, PyIceberg and DuckDB, which don't
write `metadata.json` themselves with a REST catalog: the server applies
a commit's changes and writes the new metadata file.

1. **Iceberg's table metadata** (`tables::iceberg::metadata`): format
   versions 1 to 3, read and written as JSON (gzipped too), and built as
   Iceberg's `TableMetadataBuilder` builds it:
   - Updates: assign-uuid, upgrade-format-version, add-schema,
     set-current-schema, add-spec, set-default-spec, add-sort-order,
     set-default-sort-order, add-snapshot, set-snapshot-ref,
     remove-snapshots, remove-snapshot-ref, set-properties,
     remove-properties, set-statistics, remove-statistics, the partition
     statistics' pair, remove-partition-specs, remove-schemas, and
     encryption keys (v3).
   - set-location: refused; a table's location is its warehouse
     location.
   - Requirements: assert-create, assert-table-uuid,
     assert-ref-snapshot-id, assert-last-assigned-field-id,
     assert-current-schema-id, assert-last-assigned-partition-id,
     assert-default-spec-id, assert-default-sort-order-id.
   - Snapshot log, metadata log (`write.metadata.previous-versions-max`),
     sequence numbers, last-updated-ms.

   Kept as serde_json values with typed views of what's checked, so that
   fields Cairn doesn't know survive a commit. Not the `iceberg` crate:
   it brings Arrow, OpenDAL and an async runtime of its own into a static
   binary for what is a few hundred lines of JSON rules. Iceberg's Java
   and Rust builders are the reference, and their tests' cases are ours.
2. **The endpoint** (`tables::iceberg::rest`):
   - Under `/iceberg/v1/`: config, namespaces, tables, rename, as AWS
     lists them.
   - Errors as Iceberg's (`{"error": {"message", "type", "code"}}`), and
     AWS's 400s for what it refuses.
   - The prefix is the table bucket's ARN, URL-encoded.
   - config's `overrides` give the S3 endpoint (`--domain`'s) and
     path-style access where there's no domain, so that clients' FileIO
     reaches table storage without settings of their own (AWS's exact
     answer *unverified*: probe).
3. **Commits**: load the current metadata, check the requirements, apply
   the updates, write `metadata/<n+1>-<uuid>.metadata.json` into storage,
   then swap the location in a transaction that checks it's still the one
   loaded. A conflict is Iceberg's 409 `CommitFailedException`, which
   clients retry. A file of a commit that lost is left to Phase 3.
4. **Creates**: from the REST create request, and CreateTable's
   `metadata` (`schema`, `schemaV2`, `partitionSpec`, `writeOrder`,
   `properties`), which needs `s3tables:PutTableData`.
5. **Loads**: the metadata file read back, at most 50 MB, as AWS caps it.

Tests: e2e tests of the builder (Iceberg's own cases), and PyIceberg in
`test.sh`: create a namespace and a table, append, read back, evolve the
schema, two writers racing. Spark and Trino by hand before the release,
with the configuration that goes in the README.

## Phase 3: snapshot management and unreferenced file removal

The maintenance that keeps a table's storage from growing forever. A
background loop (`tables::maintenance`, spawned in `main` as lifecycle
sweeps are): its runs are rows that any node takes, paced by the rate
lifecycle sweeps go at.

1. **Snapshot management**: as Iceberg's `ExpireSnapshots` (`retainLast`
   with `expireOlderThan`), the table's settings, or its
   `history.expire.*` properties. Failed, as AWS's, for tables with tags
   or branches. It's a commit of `remove-snapshots`, so it only needs the
   metadata JSON. It conflicts with clients' commits as theirs do, and is
   retried.
2. **Unreferenced file removal**: what's referenced is every file of
   every snapshot (manifest lists, manifests, data and delete files,
   statistics) and every metadata file the metadata log keeps. Every other
   file in storage that's older than the day is unreferenced:
   - recorded in `table_noncurrent_files` once it's been unreferenced for
     `unreferencedDays`;
   - deleted `nonCurrentDays` after that;
   - forgotten if a commit references it again meanwhile.

   Reading manifests means Avro: the `apache-avro` crate (pure Rust;
   deflate and snappy, as Iceberg writes them). A table's files are
   listed by Cairn itself, which clients can't do. Skipped for tables with
   `gc.enabled=false`, with AWS's failure message.
3. **Job status**, and the configurations' operations take effect.

Tests: e2e tests that expire snapshots and remove files of a table
PyIceberg wrote, with the days made seconds.

## Phase 4: compaction

Rewriting a table's small data files into large ones, as a commit of
`replace` snapshots. This is a query engine's work, and the most of this
plan by far:

- reading and writing Parquet with Iceberg's types, field IDs and
  partitioning, beyond what `inventory` and `batch` do with the `parquet`
  crate's low-level API: Arrow, or its record reader;
- applying positional and equality deletes, and v3's deletion vectors
  (Puffin);
- metrics for the new files' manifests;
- sort and z-order.

Binpack first, without deletes, once Phases 1 to 3 are in use and someone
needs it. Until then, compaction stays refused (501 to enabling it, and
`Disabled` in its status), as S3-COMPATIBILITY.md will say.

## Phase 5: the rest, as needed

- Server access logging of table storage's requests (`access_log`),
  to the configured bucket.
- Replication of tables to other table buckets in the cluster, as
  bucket replication does it.
- Intelligent-Tiering as a real class, if Cairn ever has one.
- Not planned: the AWS-managed `aws-s3` bucket (S3 Metadata isn't in
  Cairn), record expiration, Glue migrations.

## To decide

- **Probing AWS.** Most of Cairn's behavior was checked against real
  requests. Without an account to probe with, S3 Tables goes into "Not
  checked against AWS", and the *unverified* points above follow the
  docs and the model, or the nearest case.
- **MinIO's path.** AIStor serves its catalog at `/_iceberg/v1`. An alias
  for it is cheap, if clients configured for MinIO matter.
- **Phase 4's scope**, once Phase 3 is in use.
