# S3 compatibility

Cairn implements the Amazon S3 API, along with the parts of IAM, STS, SNS,
Organizations, Identity Center and KMS that S3 clients and tools use, and
the basics of Kinesis Data Streams. Where Cairn
implements a feature, it aims to behave exactly as AWS does: the same
requests, responses, errors and edge cases. Its behavior was checked against
real S3 requests, except where [noted](#not-checked-against-aws).

This document lists what Cairn doesn't implement, and where a client can
tell it apart from AWS. It doesn't list how Cairn works inside (its cipher,
how it stores data), or where it's only faster than AWS (lifecycle, logs and
inventory reports, policy changes). It compares AWS with a complete Cairn
deployment: behind a TLS proxy, with a KMS for SSE-KMS and SSE-S3, and with a
website domain (see the [README](README.md)). Any other difference is a bug;
please report it.

✅ supported, as in AWS · 🟡 supported, with the differences noted ·
❌ not supported (`501 NotImplemented`, or reported as unconfigured)

---

## Requests and authentication

| Feature | | Notes |
| --- | --- | --- |
| Path-style and virtual-hosted-style requests | ✅ | |
| SigV4 and SigV2 (headers, presigned URLs, browser POST forms) | ✅ | |
| Streaming uploads (aws-chunked, signed and unsigned, trailing checksums) | ✅ | |
| Anonymous requests | ✅ | |
| IAM, STS, SNS and the other services' APIs | ✅ | On the S3 endpoint, by the service in the credential scope. |
| SigV4A | ❌ | |
| Regions | ❌ | Every bucket is in `us-east-1`, and behaves as S3's there do. `LocationConstraint` is ignored, and ListBuckets has no `BucketRegion`. |
| Dual-stack, FIPS, Transfer Acceleration and access-point endpoints | ❌ | |
| A CNAME pointing at a bucket's S3 API | ❌ | Any host name but the API's is a bucket's [website](#buckets-and-objects). |

## Buckets and objects

| Feature | | Notes |
| --- | --- | --- |
| Buckets: create, delete, head, list | ✅ | |
| Objects: put, get, head, copy, delete, batch delete, attributes | ✅ | Keys are UTF-8 without NUL. |
| Conditional requests (reads, writes, deletes) | ✅ | Racing writes are decided one after the other, never `409 ConditionalRequestConflict`. |
| Byte-range and part-number reads | ✅ | |
| Multipart uploads, UploadPartCopy | ✅ | |
| ListObjects (v1, v2), ListObjectVersions, ListMultipartUploads, ListParts | ✅ | A marker naming a common prefix continues after all of its keys. |
| User-defined metadata, object and bucket tags | ✅ | |
| Checksums: CRC32, CRC32C, CRC64NVME, SHA-1, SHA-256, SHA-512, MD5, XXHash64, XXHash3, XXHash128, full-object and composite | ✅ | CopyObject's checksum, and a CRC64NVME upload's, is always `FULL_OBJECT`. |
| Browser uploads (POST Object) | 🟡 | The `x-amz-acl` and `x-amz-website-redirect-location` fields are ignored. |
| Versioning, MFA delete | ✅ | The root's MFA device is made on a node (`cairn account root-mfa`). |
| Object Lock: retention, legal holds, default retention | ✅ | |
| Object Lock event-based holds | ❌ | |
| Lifecycle: expiration, noncurrent versions, delete markers, incomplete uploads | ✅ | |
| Lifecycle transitions (`Transition`, `NoncurrentVersionTransition`) | 🟡 | Into the operator's ranked classes, lower than the version's own only. S3's minimum days between transitions into its classes don't apply. An object's data moves into its new class's storage later, when the packer rewrites it; the class it reports changes at once. |
| Restore (`RestoreObject`) | ❌ | |
| Storage classes | 🟡 | The operator's, by S3's names or others. One of S3's the operator hasn't defined is stored as `STANDARD`. None needs a restore. |
| CORS | ✅ | |
| Static website hosting | ✅ | Also on custom domains: a host name is the website of the bucket of that name. |
| Inventory: CSV, Parquet | ✅ | Configuration IDs are 1 to 64 of `[A-Za-z0-9._-]`. |
| Inventory: ORC | ❌ | |
| Server access logging | 🟡 | Not logged yet: lifecycle actions (`S3.EXPIRE.OBJECT`, …), DeleteObjects' keys (`BATCH.DELETE.OBJECT`), POST Object's requester. Host ID and TLS fields are `-`. |
| [Event notifications](#event-notifications), to SNS topics | 🟡 | |
| Event notifications to SQS, Lambda, EventBridge | ❌ | |
| [Batch Operations](#batch-operations): tagging, Object Lock, replication, copies, ACLs, checksums, encryption updates | 🟡 | |
| Batch Operations: `LambdaInvoke`, `S3InitiateRestoreObject` | ❌ | |
| [Replication](#replication) to buckets in the cluster, and to and from other Cairn, MinIO and RustFS clusters | 🟡 | |
| Replication to other S3 providers, RTC | ❌ | |
| [Directory buckets](#directory-buckets) (S3 Express One Zone), CreateSession | 🟡 | |
| Directory buckets: RenameObject, appends, bucket tags, Local Zones | ❌ | |
| [S3 Tables](#s3-tables): table buckets, namespaces, tables, their storage, policies, Iceberg REST endpoint, compaction, snapshot management, unreferenced file removal | 🟡 | |
| S3 Tables: replication, logging | ❌ | |
| Analytics, metrics, Intelligent-Tiering, Storage Lens | ❌ | |
| [S3 Select](#s3-select): CSV and JSON, uncompressed or GZIP, Parquet, `ScanRange`, timestamps and their functions | 🟡 | |
| S3 Select: BZIP2 | ❌ | `501 NotImplemented`. |
| Requester pays | ❌ | |
| Access points, Object Lambda, Multi-Region Access Points | ❌ | |

## Encryption

| Feature | | Notes |
| --- | --- | --- |
| SSE-C | ✅ | |
| SSE-S3 | ✅ | |
| SSE-KMS | ✅ | Keys are [Cairn's KMS](#kms)'s. |
| Bucket default encryption | ✅ | |
| Encrypting every object by default | ❌ | New buckets have no default encryption, as in S3 before 2023: set it. |
| DSSE-KMS | ❌ | |

## KMS

| Feature | | Notes |
| --- | --- | --- |
| Symmetric keys (`SYMMETRIC_DEFAULT`): create, describe, list, enable, disable, policies, tags | ✅ | |
| Aliases, `aws/s3` | ✅ | `aws/s3` is made the first time SSE-KMS needs it. |
| Encrypt, Decrypt, ReEncrypt, GenerateDataKey(WithoutPlaintext), GenerateRandom | 🟡 | Ciphertexts are Cairn's own format: AWS's don't decrypt in Cairn, nor Cairn's in AWS. |
| Key policies with IAM policies (`kms:` actions and condition keys) | ✅ | |
| Automatic and on-demand rotation | ✅ | |
| Scheduled deletion | 🟡 | The key's material stays in database backups, wrapped by the root key, until they're past their retention. |
| Grants | ❌ | |
| Asymmetric, HMAC, imported and multi-Region keys, custom key stores | ❌ | |
| CloudTrail | 🟡 | Every call is recorded as CloudTrail's event, durably, and kept in the cluster for 90 days. `LookupEvents` reads them (the event history, with its attributes, times and paging; no rate limit). Trails deliver them to a bucket as CloudTrail's log files, with basic and advanced event selectors, SSE-KMS and tags, within about 5.5 minutes, at least once. Not yet: log file validation (digests), SNS notifications, organization trails; not planned: CloudWatch Logs, Insights. |

## Kinesis Data Streams

| Feature | | Notes |
| --- | --- | --- |
| CreateStream, DeleteStream, ListStreams, DescribeStream(Summary), ListShards | 🟡 | Streams are `ACTIVE` as soon as they're made, and gone as soon as they're deleted. On-demand streams are made with 4 shards, and described as provisioned. Up to 1,000 shards a stream. |
| Retention: IncreaseStreamRetentionPeriod, DecreaseStreamRetentionPeriod | ✅ | 24 hours to 365 days. |
| PutRecord, PutRecords | 🟡 | Sequence numbers are each shard's own count from 0, not AWS's 56-digit numbers; they grow with every record, as AWS's do. No throughput limits per shard (`ProvisionedThroughputExceededException`). `SequenceNumberForOrdering` is ignored: a shard's records are in the order they're written anyway. |
| GetShardIterator, GetRecords | 🟡 | All iterator types. `AT_TIMESTAMP` goes by when each batch of records was written, not each record. No limit of 5 calls a second per shard. |
| JSON protocol | 🟡 | Not CBOR, which the AWS SDK for Java uses by default: set `AWS_CBOR_DISABLE=true`. |
| IAM policies (`kinesis:` actions, on streams' ARNs) | ✅ | A stream is only its own account's: no resource policies, no cross-account access. |
| CloudTrail | 🟡 | Management events (creating, describing, deleting streams, retention) are recorded; data events (records) aren't. |
| Resharding (UpdateShardCount, SplitShard, MergeShards) | ❌ | |
| Enhanced fan-out (RegisterStreamConsumer, SubscribeToShard) | ❌ | |
| Tags, server-side encryption with a KMS key (StartStreamEncryption), resource policies, enhanced monitoring | ❌ | With a KMS, records are stored encrypted with SSE-S3, as the audit log is. |
| The Kinesis Client Library (KCL) | ❌ | It keeps its leases in DynamoDB, which Cairn doesn't have. |

## Access control

| Feature | | Notes |
| --- | --- | --- |
| Bucket policies, identity policies, permissions boundaries, session policies | ✅ | |
| Bucket ABAC (bucket tags in policies) | ✅ | |
| Condition keys | ✅ | |
| Condition keys `s3:TlsVersion`, `s3:locationconstraint`, `s3:ObjectCreationOperation`, `s3:x-amz-object-ownership`, `s3:x-amz-object-if-match`, `s3:x-amz-bucket-namespace`, `s3:resourceArnBeingAuthorized`, event-hold keys | ❌ | Refused. |
| VPC, organization, access point and batch job condition keys | ❌ | Never present. |
| `Service` principals | 🟡 | Match only what Cairn does as a service: `s3.amazonaws.com` (inventory, replication), `access-grants.s3.amazonaws.com`. |
| `CanonicalUser` principals | ❌ | |
| Block Public Access, for buckets and the account | ✅ | |
| ACLs disabled, Object Ownership `BucketOwnerEnforced` | ✅ | New buckets' default, as on S3. |
| [ACLs](#acls) enabled (`ObjectWriter`, `BucketOwnerPreferred`, no ownership controls) | 🟡 | |
| [Access Grants](#access-grants), with IAM grantees | ✅ | |
| Access Grants: directory grantees, applications, sharing through RAM | ❌ | |

## IAM

| Feature | | Notes |
| --- | --- | --- |
| Users, groups, roles: create, get, list, update, delete; tags; boundaries | 🟡 | User names are `[A-Za-z0-9._-]`. `RoleLastUsed` and `PasswordLastUsed` aren't reported. |
| Access keys | 🟡 | IDs have no `AKIA` prefix. GetAccessKeyLastUsed isn't supported. |
| Inline and managed policies, versions, attachments, ListEntitiesForPolicy | 🟡 | `PathPrefix` on the attachment lists and `PolicyUsageFilter` are ignored. |
| AWS managed policies `AdministratorAccess`, `AmazonS3FullAccess`, `AmazonS3ReadOnlyAccess` | ✅ | |
| Other AWS managed policies | ❌ | |
| OpenID Connect providers | 🟡 | The issuer must be reachable when one is created. Thumbprints pin the issuer's certificate, so private CAs work. |
| Root user | 🟡 | No password or long-term access keys: `cairn account root-link` and `cairn account root-key` sign it in from a node. Its requests are never multi-factor. |
| Login profiles, MFA devices, SAML providers, instance profiles, service-linked roles | ❌ | |
| Account settings, GetAccountAuthorizationDetails, policy simulation, credential and last-accessed reports, certificates, SSH keys, service-specific credentials | ❌ | |

## STS

| Action | | Notes |
| --- | --- | --- |
| GetCallerIdentity, AssumeRole, GetSessionToken, GetAccessKeyInfo | ✅ | `SerialNumber`/`TokenCode` always fail: there are no MFA devices. |
| AssumeRoleWithWebIdentity | 🟡 | Unsigned requests only. Only the `sub`, `aud` and `amr` claims are condition keys. No OAuth 2.0 access tokens (`ProviderId`). |
| GetFederationToken | 🟡 | Session tags don't need `sts:TagSession`; no `TransitiveTagKeys`. |
| AssumeRoleWithSAML, AssumeRoot, DecodeAuthorizationMessage, GetDelegatedAccessToken, GetWebIdentityToken | ❌ | |

## Organizations

| Feature | | Notes |
| --- | --- | --- |
| DescribeOrganization, ListAccounts, DescribeAccount | ✅ | The management account has no e-mail address. |
| CreateAccount, its statuses | 🟡 | Done at once: `SUCCEEDED` or `FAILED` when answered. No e-mail is sent. |
| CloseAccount | 🟡 | Only an account without buckets, at once: it's not kept for 90 days. |
| Organizational units, the root | 🟡 | Their operations are authorized on the organization's ARN. |
| Service control policies | ✅ | |
| Cross-account access by resource policies | ✅ | Only to the organization's accounts. |
| RCPs, tag, backup and declarative policies, `Tags` on creation | ❌ | |
| Invitations, delegated administrators, trusted services | ❌ | |
| Member accounts' root users | ❌ | As with AWS's centralized root access. |
| Organization condition keys (`aws:PrincipalOrgID`, …) | ❌ | |

## Identity Center

| Feature | | Notes |
| --- | --- | --- |
| sso-admin: permission sets, their policies, assignments, provisioning | 🟡 | The management account's instance only. Requests are done at once: never `IN_PROGRESS`. |
| sso-admin: CreateInstance, DeleteInstance, UpdateInstance, the instance's tags | ❌ | |
| identitystore: reads | ✅ | |
| identitystore: writes | 🟡 | Cairn's own directory's users and groups only; user names and group names are unique. |
| Identity sources | 🟡 | Cairn's own directory and any number of OpenID Connect providers, at once. A provider's users and groups appear when they first sign in. |
| SAML identity sources, SCIM sync | ❌ | |
| Access portal (`sso`, `sso-oidc`, `aws sso login`) | 🟡 | At the console's URL, which clients are pointed at (`AWS_ENDPOINT_URL_SSO`, `AWS_ENDPOINT_URL_SSO_OIDC`). Its start URL redirects to an AWS-owned one, as the AWS CLI requires. The `sso:account:access` scope only; refresh tokens aren't rotated. |
| sso-oidc: `CreateTokenWithIAM`, trusted token issuers, applications' scopes | ❌ | |
| Applications, trusted token issuers, attributes for access control | ❌ | |

Directory users of Cairn's own directory sign in with passkeys, set up
through a link instead of an invitation e-mail; their sessions are
multi-factor. MFA at an OpenID Connect provider isn't trusted.

---

## Differences in detail

### Access Grants

| Feature | | Notes |
| --- | --- | --- |
| Instances, locations, grants, and their tags | ✅ | Tags aren't `aws:ResourceTag/…` to policies. |
| GetDataAccess, ListCallerAccessGrants, GetAccessGrantsInstanceForPrefix | ✅ | `auditContext` is ignored; `instanceScope=ALL` is `SELF`. |
| Grantees: IAM users and roles, of any of the organization's accounts | ✅ | |
| Grantees: directory users and groups, applications | ❌ | |
| Trusted identity propagation (`sts:SetContext`) | ❌ | |
| Instances shared through AWS RAM | ❌ | |
| CloudTrail records of data access | ❌ | S3 Control's requests aren't in server access logs either. |

### ACLs

| Feature | | Notes |
| --- | --- | --- |
| Bucket and object ACLs: canned, `x-amz-grant-*` headers, `AccessControlPolicy` documents | ✅ | |
| Grantees: accounts, `AllUsers`, `AuthenticatedUsers`, `LogDelivery` | ✅ | Accounts also by their 12-digit IDs, and by their e-mail addresses (only some S3 regions take them). |
| Objects owned by their writers' accounts | 🟡 | An anonymous write's object is the bucket owner's, not S3's anonymous user's. |
| `BlockPublicAcls`, `IgnorePublicAcls` | ✅ | |
| `aws-exec-read` | 🟡 | `private`: there's no EC2 to grant. |
| Logging `TargetGrants` | ❌ | Refused, as S3 refuses them for a target with ACLs disabled. |
| Access logs' `aclRequired` | ❌ | `-`. |
| ListMultipartUploads' `Owner` | 🟡 | Always the bucket owner. |

### Event notifications

Through SNS topics, on the S3 endpoint for requests signed for `sns`.

| SNS feature | | Notes |
| --- | --- | --- |
| Topics, their attributes, permissions and tags | ✅ | Topic encryption (`KmsMasterKeyId`) and delivery status logging are refused. |
| Subscriptions, HTTP(S) | 🟡 | To public addresses, unless `notification-private-endpoints` allows private ones. |
| Subscriptions, other protocols (`sqs`, `lambda`, `email`, …) | ❌ | |
| Subscription filter and redrive policies | ❌ | |
| Publish | 🟡 | No `MessageStructure`. |
| Message signatures | 🟡 | `SigningCertURL` is on Cairn's endpoint, which AWS SDKs' validators refuse: use one whose certificate host is configurable. |
| PublishBatch, FIFO topics, platform applications, SMS, data protection | ❌ | |

### Batch Operations

| Feature | | Notes |
| --- | --- | --- |
| `S3PutObjectTagging`, `S3DeleteObjectTagging`, `S3PutObjectRetention`, `S3PutObjectLegalHold` | ✅ | |
| `S3ReplicateObject` (Batch Replication) | 🟡 | A task succeeds once its version is queued. A task without a version ID replicates the current version. |
| `S3PutObjectCopy` | 🟡 | Not into directory buckets. `NewObjectMetadata`'s `ContentLength` and `ContentMD5` are ignored. |
| `S3PutObjectCopy`: requester pays, event holds, `AnnotationDirective` `EXCLUDE` | ❌ | |
| `S3PutObjectAcl` | ✅ | Each task is the PutObjectAcl request it would be, and fails as that would: with the bucket's ACLs disabled, say. |
| `S3ComputeObjectChecksum` | 🟡 | `COMPOSITE` of an object that isn't multipart is its `FULL_OBJECT` one, as reported. A `COMPOSITE` result's `checksum_base64` has no `-N`. |
| `S3UpdateObjectEncryption` | 🟡 | `BucketKeyEnabled` is ignored. An SSE-S3 object's ETag, its MD5, is kept, as on S3: so it's then stored in the clear, as SSE-KMS objects' ETags are. Replicas aren't updated, as on S3. |
| `LambdaInvoke`, `S3InitiateRestoreObject` | ❌ | |
| CSV manifests, CSV and Parquet inventory reports | ✅ | A Parquet report's row group may hold at most 64 MiB of buckets, keys and version IDs. |
| Manifest generators (`S3JobManifestGenerator`) | 🟡 | A versioned bucket's manifest has every version but delete markers. A manifest that isn't written out is kept in Cairn's internal bucket until the job ends. Output files are named by Cairn (`<prefix>/job-<id>/…`). Failure codes are Cairn's. |
| Manifest generators: `MatchAnyObjectEncryption` | ❌ | |
| ORC inventory reports | ❌ | |
| Completion reports | 🟡 | One result file per thousand tasks; messages are Cairn's. |
| Job statuses | 🟡 | Never `Completing`, `Failing`, `Pausing` or `Paused`. |
| Errors | 🟡 | Codes are S3 Control's; HTTP statuses, messages and failure codes are Cairn's. |

### Replication

| Feature | | Notes |
| --- | --- | --- |
| Replication to buckets in the cluster, of any account | ✅ | |
| SSE-C objects into another storage class | ❌ | They fail. |
| Replica modification sync (`ReplicaModifications`) | ❌ | Accepted, no effect: later changes to tags, Object Lock or ACLs aren't replicated. |
| Replicas' owners and ACLs | ✅ | Their sources', unless `AccessControlTranslation` or the destination's ACLs are disabled. |
| `ExistingObjectReplication`, `ReplicationTime`, `Metrics` | ❌ | Batch Replication replicates existing objects. |
| Replication to other clusters (Cairn, MinIO, RustFS) | 🟡 | A Cairn extension, by MinIO's protocol: destinations `arn:cairn:replication::<remote>:<bucket>` (or MinIO's `arn:minio:replication:…`), of remotes registered with `cairn remote`. SSE-C versions fail. Versions over 16 MiB are sent as multipart uploads, so a replica's composite checksum may differ from its source's (its ETag doesn't). |
| Deletions of versions (MinIO's `DeleteReplication`) | ✅ | Not S3's: replicated where a rule has it. |
| Replication into the cluster, from MinIO, RustFS or Cairn | ✅ | MinIO's replication requests (`x-minio-source-*`, or RustFS's `x-rustfs-source-*`), authorized as `s3:ReplicateObject`, `s3:ReplicateTags` and `s3:ReplicateDelete`; their version IDs (UUIDs) are kept. Null versions can't be replicated in. `/minio/health/live` and `/minio/health/ready` answer 200, unsigned. |

### Directory buckets

| | S3 | Cairn |
| --- | --- | --- |
| Zone | The bucket's Availability Zone | Whatever the name says; data is spread as any bucket's. |
| Endpoints | Regional and zonal | The S3 endpoint, for both. |
| CreateSession of a bucket that doesn't exist | `404` | Succeeds, as SDKs make one before CreateBucket. |
| Default encryption | SSE-S3 | None ([Encryption](#encryption)); a session's encryption headers are ignored. |
| Condition keys | `s3express:` | Only `s3express:SessionMode` and `s3express:ResourceAccount`. |

### S3 Tables

| | S3 | Cairn |
| --- | --- | --- |
| Endpoint | `s3tables.<region>.amazonaws.com` | The S3 endpoint, for requests signed for `s3tables`. |
| Table storage | Its own endpoint | The S3 endpoint, path-style or virtual-hosted, signed for `s3`. |
| Table storage's encryption, by default | SSE-S3 | SSE-S3 with a KMS; without one, none (as for [buckets](#encryption)). |
| Storage classes | `STANDARD`, `INTELLIGENT_TIERING` | The operator's, by those names; one it hasn't defined is `STANDARD`. |
| Compaction | On by default; `auto`, `binpack`, `sort`, `z-order` | The same, as Iceberg's Java rewrites choose files (75% and 180% of the target size, 5 files, deletes). Z-order flips floats' bits exactly (Iceberg's shifts them by 31). Parquet only, and not for tables encrypted with SSE-KMS. When AWS's runs isn't documented: Cairn's hourly. |
| Snapshot management, unreferenced file removal | As their configurations say | As theirs say, hourly and daily; not for tables encrypted with SSE-KMS (their jobs fail, saying so). Unreferenced files are noted, not made noncurrent S3 versions: they stay readable until they're deleted. |
| Iceberg REST endpoint | `s3tables.<region>.amazonaws.com/iceberg` | The S3 endpoint's `/iceberg`. |
| The REST catalog's config | Not checked | The warehouse's `prefix`, and as defaults, `s3.endpoint` (the endpoint the request reached), `s3.path-style-access`, `client.region` and `rest-metrics-reporting-enabled=false`. |
| The REST catalog's metrics reports | Not checked | Taken, and dropped. |
| Format versions of tables the REST catalog commits to | 1 to 3 | 2 and 3. |
| Replication, server access logging, Glue migrations | ✅ | `501`. |
| Request metrics configuration | CloudWatch metrics | Kept, without effect. |
| Table storage signed with SigV2 | Not checked | Refused, as for directory buckets. |
| A policy that would make a table bucket or table public | Refused | Refused with `403 AccessDeniedException` (S3's code not checked). |

### S3 Select

SelectObjectContent runs AWS's SQL over CSV, JSON and Parquet objects: `SELECT`
lists (or `*`), `FROM S3Object` with an alias, `WHERE` and `LIMIT`; paths
(`s.name`, `s."Name"`, `_1`, `s.a.b[0]`); operators, `LIKE`, `BETWEEN`,
`IN`, `IS [NOT] NULL|MISSING`, `CASE`, `CAST`; the string, conditional,
date and time functions, with timestamps (`` `2007-02-23T12:14Z` ``,
`TO_TIMESTAMP`, `CAST(... AS TIMESTAMP)`); and `COUNT`, `SUM`, `AVG`, `MIN`
and `MAX`. The object is read as
it streams, and a `LIMIT` stops reading it.

A Parquet object is read by its footer, and then only the chunks of the
columns a query reads, of the row groups its condition doesn't rule out by
their statistics (a comparison of a column with a literal, `BETWEEN`, `IN`,
`IS NULL`, and `AND`s and `OR`s of them). Each chunk streams as it's
decoded, so a query holds about a page of each column it reads, however
large the row group (a 386 MB one, read 4 columns of 8, took 24 MiB). A
row group may be at most 512 MB uncompressed, as in S3. Its types are S3 Select's: integers,
`DECIMAL` (as a float, as elsewhere), strings and `ENUM`, `DATE` and
`TIMESTAMP` (`MILLIS`, `MICROS`, `NANOS`) as timestamps, and `LIST`s; and
also booleans, floats, doubles, groups and `MAP`s (as structs), and
`BINARY` that's UTF-8 (as a string). `INT96` timestamps and `TIME`s are
`400 UnsupportedParquetType`, if a query reads them; columns compressed
with anything but Snappy or GZIP, `400 ParquetUnsupportedCompressionCodec`.
A `ScanRange` of a Parquet object reads the row groups that start in it.

A `ScanRange` reads the records whose first byte is in it, each to its end
(as AWS's API reference has it), of uncompressed CSV and JSON `LINES`; a
CSV object's header is read from its start, whatever the range. Ranges
that split an object into consecutive pieces (`0-99`, `100-199`, ...) read
each record once. AWS SDK for pandas' `select_query` sends ranges that
share their last byte with the next one's first (`0-1048576`,
`1048576-2097152`, ...): a record whose first byte is that shared one is
in both, and returned twice, as AWS's rule has it.

| | S3 | Cairn |
| --- | --- | --- |
| Availability | Only to accounts that used it before July 2024 | To everyone. |
| A string compared with a number (CSV's fields are strings) | Not checked | Compared as a number, if it reads as one (`s.age > 40`); arithmetic takes such strings too. `NULL` if it doesn't. |
| `AllowQuotedRecordDelimiter` false | A quoted record delimiter splits the record | Ignored: a quoted field may always hold one. |
| `\r\n` line ends, with the default `RecordDelimiter` | Not checked | Read as `\n`. |
| JSON `DOCUMENT` | One document, or several, with paths into it in `FROM` | Values one after another, each a record of at most 1 MB; paths in `FROM` (but `S3Object[*]`) are `400 UnsupportedSyntax`. |
| Wildcards in paths (`s.a[*]`) | Supported | `400 UnsupportedSyntax`. |
| `DECIMAL` | A decimal | A float. |
| A string where a timestamp is expected (CSV and JSON have their timestamps as strings) | Not checked | Taken as the timestamp it reads as, by functions (`EXTRACT(YEAR FROM s.date)`) and comparisons (`` s.date > `2024T` ``). A comparison with one that doesn't read as one is `NULL`. |
| A timestamp with a time and no offset (`2010-01-01T23:00`, as in AWS's `DATE_DIFF` example) | Not checked | Its offset is unknown, as `-00:00`, and counts as UTC. |
| `TO_TIMESTAMP` with a format pattern | Not documented, but mentioned in `TO_STRING`'s table | `400 IncorrectSqlFunctionArgumentType`: only Ion's text. |
| `TO_STRING`'s patterns | As its table has them | As Java's `DateTimeFormatter` has them, which the table is of. Where its examples look garbled, Java's: `x` is `+07` (not `7`), `SS` of 0.06 seconds is `06` (not `6`). |
| `` DATE_DIFF(year, `2010T`, `2010-05T`) `` | `4`, by AWS's documentation, which must mean `month` | `0`: whole years. |
| `ScanRange` that starts within a multi-character `RecordDelimiter` that repeats itself (`||` in `||||`) | Not checked (AWS takes single characters) | The first record found after the range's start may be cut differently than reading from the object's start cuts it. |
| Keywords (`FileHeaderInfo`, `Type`, `CompressionType`, `QuoteFields`, `ExpressionType`) | Any case (`Use`, `Lines`) | Any case. |
| Error codes and messages | AWS's | AWS's documented codes, and `EvaluatorInvalidArguments` for division by zero, which they don't cover; the messages are Cairn's. |
| Parquet error codes | `UnsupportedParquetType`, `ParquetUnsupportedCompressionCodec`, `OverMaxParquetBlockSize`; AWS's list of them didn't load to check | Those, and `ParquetParsingError` for an object that isn't Parquet. |
| `DECIMAL`, and `INT(64)` | Decimals | A float, and an integer. |
| Nested data (lists, groups) in CSV output | Only JSON output has it; a `LIST` in CSV only if the query reads only simple values | Written as its JSON. |
| A `TIMESTAMP(NANOS)` within a list or group | A timestamp | An integer (the nanoseconds); top-level columns' are timestamps. |
| Progress events | Every so often | Every second, if asked for; Cont events after 5 seconds without one. |

### Edge cases

| | S3 | Cairn |
| --- | --- | --- |
| Copying an unencrypted object onto itself, unchanged | Works (every object is encrypted) | Refused unless the bucket has default encryption, as in S3 before 2023. |
| `x-amz-*` query parameters (`x-amz-meta-*`, `x-amz-tagging`, …) | Applied as headers | Ignored. To be fixed. |
| PUT without `Content-Length` or body framing | `411 MissingContentLength` | Stores an empty object. To be fixed. |
| Signature and clock-skew errors | Detail elements (`StringToSign`, `ServerTime`, …) | None. To be fixed. |
| POST Object | Clock-skew check; SSE-C fields need policy conditions | Neither. |

### Not checked against AWS

These follow AWS's documentation and API models, not real requests:

- Organizations, Identity Center and Access Grants.
- KMS, which follows AWS's API reference and its key policy documentation:
  in particular its errors' messages, and which state errors a key's
  management operations get (KMSInvalidStateException, DisabledException).
- MFA delete's errors (a missing or invalid code, `x-amz-mfa` over HTTP,
  MFA delete with a lifecycle configuration), and whether deleting a
  suspended bucket's `null` version needs a code (Cairn: no).
- Server access logs' operation names for the rarer subresources.
- S3 Tables, which follow AWS's API model and documentation: in particular
  the messages of their errors, which errors a refused operation on table
  storage gets (Cairn: S3's `405 MethodNotAllowed`), and the order of
  ListTables' pages (Cairn: by namespace, then name). The REST catalog
  follows Iceberg's REST spec and the `iceberg` crate's port of Java's
  `TableMetadata.Builder`, and the
  operations AWS lists for its endpoint; its errors' messages, and the
  metadata it writes, may differ from AWS's in detail.
- Directory buckets' errors for unsupported operations, delimiters,
  prefixes, `start-after` and gaps in part numbers.
- `411 MissingContentLength` above.
- S3 Select, which follows AWS's user guide and API reference: in
  particular how strictly it types values, its output of numbers (floats
  always have a fraction: `54.0`), and its errors' codes.

---

## Cairn's own additions

- **The console:** a web UI that people sign in to as directory users
  (Identity Center's), with passkeys or at an OpenID Connect provider; IAM
  users have access keys only. It acts as the signed-in permission set's
  role session: every operation is authorized as its `s3:`, `iam:` or
  `cairn:` action. It switches roles as AWS's console does.
- **Operators:** the cluster's settings and nodes are managed through `cairn:`
  actions on `arn:aws:cairn:::cluster` (`CairnOperatorAccess` allows them
  all).
- **Policy templates:** ready-made managed policies for teams sharing the
  account, access to buckets, and requiring MFA.
- **The `cairn` CLI:** on a node, sets up the cluster and is the break-glass
  for access, outside of policies.
- **Trusted proxies:** the TLS proxy's forwarded headers set `aws:SourceIp`
  and `aws:SecureTransport`.
- **Session revocation:** `cairn sessions revoke-all` ends every session in
  the cluster.
