# S3 compatibility

Cairn implements the Amazon S3 API, along with the parts of IAM, STS, SNS,
Organizations and Identity Center that S3 clients and tools use. Where Cairn
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
| [Batch Operations](#batch-operations): tagging, Object Lock, replication, copies | 🟡 | |
| Batch Operations: other operations | ❌ | |
| [Replication](#replication) to buckets in the cluster | 🟡 | |
| Replication to other clusters or providers, RTC | ❌ | |
| [Directory buckets](#directory-buckets) (S3 Express One Zone), CreateSession | 🟡 | |
| Directory buckets: RenameObject, appends, bucket tags, Local Zones | ❌ | |
| [S3 Tables](#s3-tables): table buckets, namespaces, tables, their storage, policies, Iceberg REST endpoint, snapshot management, unreferenced file removal | 🟡 | |
| S3 Tables: compaction, replication, logging | ❌ | |
| Analytics, metrics, Intelligent-Tiering, Storage Lens | ❌ | |
| [S3 Select](#s3-select): CSV and JSON, uncompressed or GZIP | 🟡 | |
| S3 Select: Parquet, BZIP2, `ScanRange`, date and time functions | ❌ | `501 NotImplemented` (the functions: `400 UnsupportedFunction`). |
| Torrents, requester pays | ❌ | |
| Access points, Object Lambda, Multi-Region Access Points | ❌ | |

## Encryption

| Feature | | Notes |
| --- | --- | --- |
| SSE-C | ✅ | |
| SSE-S3 | ✅ | |
| SSE-KMS | 🟡 | Keys are [OpenBao or Vault Transit](#kms-keys)'s. |
| Bucket default encryption | ✅ | |
| Encrypting every object by default | ❌ | New buckets have no default encryption, as in S3 before 2023: set it. |
| DSSE-KMS | ❌ | |

### KMS keys

- Key IDs are `<transit-mount>/<key>`; an `arn:aws:kms:` prefix is
  stripped. There are no aliases, and no default `aws/s3` key, so `aws:kms`
  needs a key ID.
- Who may use a key is decided by OpenBao's or Vault's policies for the
  requesting role, not by `kms:` actions in IAM policies.

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
| Access portal (`sso`, `sso-oidc`, `aws sso login`) | ❌ | A directory user's console page hands out credentials instead. |
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
| Batch Operations' `S3PutObjectAcl`, access logs' `aclRequired` | ❌ | `aclRequired` is `-`. |
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
| Other operations | ❌ | |
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
| SSE-KMS keys | AWS KMS keys | [OpenBao or Vault Transit](#kms-keys)'s, as `arn:aws:kms:<region>:<account>:key/<mount>/<key>`. |
| Storage classes | `STANDARD`, `INTELLIGENT_TIERING` | The operator's, by those names; one it hasn't defined is `STANDARD`. |
| Compaction | On by default | Off, and can't be enabled (`501`). |
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

SelectObjectContent runs AWS's SQL over CSV and JSON objects: `SELECT`
lists (or `*`), `FROM S3Object` with an alias, `WHERE` and `LIMIT`; paths
(`s.name`, `s."Name"`, `_1`, `s.a.b[0]`); operators, `LIKE`, `BETWEEN`,
`IN`, `IS [NOT] NULL|MISSING`, `CASE`, `CAST`; the string and conditional
functions; and `COUNT`, `SUM`, `AVG`, `MIN` and `MAX`. The object is read as
it streams, and a `LIMIT` stops reading it.

| | S3 | Cairn |
| --- | --- | --- |
| Availability | Only to accounts that used it before July 2024 | To everyone. |
| A string compared with a number (CSV's fields are strings) | Not checked | Compared as a number, if it reads as one (`s.age > 40`); arithmetic takes such strings too. `NULL` if it doesn't. |
| `AllowQuotedRecordDelimiter` false | A quoted record delimiter splits the record | Ignored: a quoted field may always hold one. |
| `\r\n` line ends, with the default `RecordDelimiter` | Not checked | Read as `\n`. |
| JSON `DOCUMENT` | One document, or several, with paths into it in `FROM` | Values one after another, each a record of at most 1 MB; paths in `FROM` (but `S3Object[*]`) are `400 UnsupportedSyntax`. |
| Wildcards in paths (`s.a[*]`) | Supported | `400 UnsupportedSyntax`. |
| `DECIMAL` | A decimal | A float. |
| Error codes and messages | AWS's | AWS's documented codes, and `EvaluatorInvalidArguments` for division by zero, which they don't cover; the messages are Cairn's. |
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
- MFA delete's errors (a missing or invalid code, `x-amz-mfa` over HTTP,
  MFA delete with a lifecycle configuration), and whether deleting a
  suspended bucket's `null` version needs a code (Cairn: no).
- Server access logs' operation names for the rarer subresources.
- S3 Tables, which follow AWS's API model and documentation: in particular
  the messages of their errors, which errors a refused operation on table
  storage gets (Cairn: S3's `405 MethodNotAllowed`), and the order of
  ListTables' pages (Cairn: by namespace, then name). The REST catalog
  follows Iceberg's REST spec and Java's `TableMetadata.Builder`, and the
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
