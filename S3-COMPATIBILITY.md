# S3 compatibility

Cairn implements the Amazon S3 API, along with the parts of IAM and STS that
S3 clients and tools use. Where Cairn implements a feature, it aims to behave
exactly as S3 does: the same requests, responses, errors and edge cases.
Cairn's behavior was checked against real S3 requests, not only against AWS's
documentation.

This document lists what Cairn doesn't implement, and the few places where it
deliberately differs from AWS. It compares AWS with a complete Cairn
deployment: behind a TLS proxy, with a KMS for SSE-KMS and SSE-S3, and with a
website domain configured (see the [README](README.md)). Any other
difference from S3 is a bug; please report it.

Legend: ✅ supported, 🟡 supported with differences (listed below), ❌ not
supported.

---

## Features

### Requests and authentication

| Feature | | Notes |
| --- | --- | --- |
| Path-style and virtual-hosted-style requests | ✅ | |
| SigV4 (header, presigned URLs, browser POST forms) | ✅ | |
| Streaming uploads (aws-chunked, signed and unsigned, with trailing checksums) | ✅ | |
| Anonymous requests | ✅ | Allowed by bucket policies. |
| Temporary credentials (STS) | ✅ | [STS](#sts) |
| SigV2 (header, presigned URLs, browser POST forms) | ✅ | |
| SigV4A | ❌ | |
| Dual-stack, FIPS, Transfer Acceleration and access-point endpoints | ❌ | |

### Buckets and objects

| Feature | | Notes |
| --- | --- | --- |
| Buckets: create, delete, head, list | 🟡 | [Regions](#regions-and-accounts) |
| Objects: put, get, head, copy, delete, batch delete, attributes | ✅ | |
| Conditional requests (reads, writes, deletes) | ✅ | |
| Byte-range and part-number reads | ✅ | |
| Browser uploads (POST Object) | 🟡 | [POST Object](#post-object) |
| Multipart uploads, including UploadPartCopy | ✅ | |
| ListObjects (v1, v2), ListObjectVersions, ListMultipartUploads, ListParts | ✅ | |
| User-defined metadata | ✅ | |
| Object and bucket tags | ✅ | Bucket tags through S3 Control's TagResource too. |
| Checksums: CRC32, CRC32C, CRC64NVME, SHA-1, SHA-256, full-object and composite | ✅ | |
| Checksums: MD5, SHA-512, XXHash | ❌ | |
| Versioning | ✅ | |
| Object Lock: retention, legal holds, default retention | ✅ | No event-based holds. |
| Lifecycle: expiration, noncurrent expiration, delete markers, incomplete uploads | 🟡 | [Lifecycle](#lifecycle) |
| Storage classes | 🟡 | The operator's, by any name: [Storage classes](#storage-classes) |
| Lifecycle transitions, restore | ❌ | [Storage classes](#storage-classes) |
| CORS | ✅ | |
| Static website hosting | ✅ | [Endpoints](#endpoints-and-domains) |
| Directory buckets (S3 Express One Zone), `CreateSession` | 🟡 | [Directory buckets](#directory-buckets) |
| RenameObject, appends (S3 Express) | ❌ | |
| Inventory | 🟡 | CSV and Parquet, not ORC: [Inventory](#inventory) |
| Event notifications, to SNS topics | 🟡 | Over HTTP(S) subscriptions: [Event notifications](#event-notifications) |
| Event notifications to SQS, Lambda, EventBridge | ❌ | |
| Server access logging | 🟡 | [Server access logging](#server-access-logging) |
| Batch Operations | 🟡 | Tagging, Object Lock and replication: [Batch Operations](#batch-operations) |
| Replication, to buckets in the cluster | 🟡 | [Replication](#replication) |
| Replication to other clusters or providers, RTC | ❌ | |

### Security

| Feature | | Notes |
| --- | --- | --- |
| SSE-C | ✅ | |
| SSE-S3 | 🟡 | [Encryption](#encryption) |
| SSE-KMS | 🟡 | On OpenBao or Vault Transit: [Encryption](#encryption) |
| DSSE-KMS | ❌ | |
| Bucket default encryption | 🟡 | [Encryption](#encryption) |
| Bucket policies | ✅ | |
| Block Public Access, for buckets and the account | ✅ | |
| ACLs | 🟡 | Disabled, as on new S3 buckets: [ACLs](#acls) |
| Object Ownership | 🟡 | Always `BucketOwnerEnforced`: [ACLs](#acls) |
| Bucket ABAC (bucket tags in policies) | ✅ | |
| S3 Access Grants | 🟡 | IAM grantees (any account's) only: [Access Grants](#access-grants) |
| MFA delete | 🟡 | [MFA delete](#mfa-delete) |
| IAM Identity Center (directory users, permission sets, sso-admin, identitystore) | 🟡 | Own directory and OIDC sources: [Identity Center](#identity-center) |
| AWS Organizations (member accounts, OUs, SCPs) | 🟡 | [Organizations](#organizations) |
| Access points, Object Lambda, Multi-Region Access Points | ❌ | |

### Not implemented

These answer `501 NotImplemented`, or report the feature as unconfigured, as
S3 reports a bucket that doesn't use it:

- Analytics, metrics, Intelligent-Tiering, Storage Lens.
- S3 Select, torrents.
- S3 Express's metadata tables, access points for directory buckets.
- Requester pays, Transfer Acceleration.
- Directory users and groups as S3 Access Grants grantees ([Access
  Grants](#access-grants)).
- Identity Center's access portal APIs (`sso`, `sso-oidc`, so `aws sso
  login`) and applications ([Identity Center](#identity-center)).

---

## Differences from AWS

### Regions and accounts

- **No regions.** A credential scope may name any region. Every bucket is in
  `us-east-1`, and behaves as S3's buckets there do: GetBucketLocation
  answers an empty `LocationConstraint`, and `x-amz-bucket-region` is
  `us-east-1`. (So creating a bucket you already own answers `200`, as in
  `us-east-1`, not `409 BucketAlreadyOwnedByYou`, as in other regions.)
  CreateBucket ignores its `LocationConstraint`. ListBuckets has no
  `BucketRegion`.
- **Accounts.** A cluster has an organization: its management account,
  and member accounts made from it ([Organizations](#organizations)). An
  account's canonical user ID is derived from its ID. SCPs cap member
  accounts' principals; there are no RCPs or organization condition keys
  (`aws:PrincipalOrgID`, …) yet.
- **The root user is made on a node, for a while.** It has no password or
  long-term access keys, and no MFA device but MFA delete's ([MFA
  delete](#mfa-delete)): `cairn account root-link` prints a
  one-time link to the console, and `cairn account root-key` temporary
  credentials (15 minutes, as `AssumeRoot`'s at most, but not scoped to a
  task policy). As in AWS, identity policies don't restrict it; resource
  policies' denies do, but for its own buckets' policy actions. It's never
  multi-factor, has no user of its own to IAM (actions on the signer's own
  user must name one), and STS makes no sessions of it. Admins have
  `AdministratorAccess`.

### Endpoints and domains

- **One API domain** for virtual-hosted-style requests.
- **Custom domains:** any other host name is the website of the bucket of
  that name, with certificates issued on demand by the TLS proxy. A host name
  can't point at a bucket's S3 API, as an S3 CNAME can.
- **No separate ports:** websites, IAM and STS are served on the S3 endpoint.
  Requests reach IAM and STS by the service in their credential scope (`iam`,
  `sts`), so point IAM and STS clients at the S3 endpoint URL.

### Encryption

- **Objects aren't encrypted by default.** S3 encrypts every object with
  SSE-S3. In Cairn, an object is encrypted only if its write asks for it, or
  its bucket has default encryption. Buckets have none until one is set.
- **The cipher is XChaCha20-Poly1305**, for SSE-C and SSE-S3 too, which the
  API still calls `AES256`.
- **SSE-KMS uses OpenBao or HashiCorp Vault Transit**, not AWS KMS:
  - Key IDs are `<transit-mount>/<key>` (an `arn:aws:kms:` prefix is
    stripped). There are no aliases, and no default `aws/s3` key, so
    `aws:kms` needs a key ID.
  - Access to keys is decided by OpenBao's policies for the requesting role,
    not by `kms:` actions in IAM policies.
  - Bucket keys (`BucketKeyEnabled`) are accepted and ignored.

### Storage classes

The classes are the operator's (`cairn class`, see the README): each keeps
its data in a pool of the nodes' disks, with redundancy of its own. They may
have S3's names or others.

- An object is of the class its write's `x-amz-storage-class` names
  (PutObject, POST Object, CreateMultipartUpload, CopyObject), else STANDARD.
  One of S3's classes that isn't defined is taken as STANDARD, as before
  Cairn had classes; any other undefined class is refused with
  `InvalidStorageClass`, as in S3.
- An object reports its class as in S3: `x-amz-storage-class` on GET and
  HEAD for any class but STANDARD, `StorageClass` in listings,
  GetObjectAttributes, ListParts, ListMultipartUploads and inventory reports.
- Every class is read as STANDARD is: none needs a restore, and none has a
  minimum duration or size. That holds for classes kept in a remote tier
  too (another S3 service, see the README), whose data is read from there;
  tiers whose objects would need a restore (`GLACIER`, `DEEP_ARCHIVE` on
  AWS) aren't supported yet, so `RestoreObject` isn't either.
- A copy into another class writes the data again; a copy without
  `x-amz-storage-class` is STANDARD, as in S3.
- Lifecycle transitions aren't supported (`501`).

### ACLs

Cairn has no ACLs. Every bucket behaves as an S3 bucket with Object Ownership
`BucketOwnerEnforced`, the default for new S3 buckets since 2023, under which
S3 disables ACLs. What S3 accepts and refuses for such a bucket, Cairn accepts
and refuses too. The difference is that ACLs can't be enabled:

- PutBucketOwnershipControls accepts only `BucketOwnerEnforced`; the other
  settings are `501`.
- DeleteBucketOwnershipControls is `501`. On S3 it enables ACLs.

### Lifecycle

- Rules are applied by a daily background sweep of each bucket, so an expired
  object can stay readable for up to a day after it expires.

### MFA delete

As in S3, a bucket with MFA delete takes no request that deletes a version
(DeleteObject with `versionId`, DeleteObjects naming one) or changes its
versioning without `x-amz-mfa`, and only the root user's own request, with a
code of its MFA device, over HTTPS, gives a valid one. Only the root enables
it. DeleteObjects fails whole without a code if it names a version, and with
an invalid one whatever it names. GetBucketVersioning reports `MfaDelete`
once it's been configured.

- **The device** is a virtual one (TOTP, as authenticator apps make codes),
  the account's only: `cairn account root-mfa` makes it on a node, and
  prints its secret. Its serial number is
  `arn:aws:iam::<account>:mfa/root-account-mfa-device`. There are no IAM MFA
  device APIs, and the console can't use it, as AWS's can't.
- **Codes** are taken from the 30-second step before now to the one after,
  and may be used more than once while they last.
- **Not checked against S3**, only against AWS's documentation: the error
  for a missing or invalid code (`403 AccessDenied`, "Mfa Authentication
  must be used for this request"), for `x-amz-mfa` over plain HTTP (`400
  InvalidRequest`), and for a lifecycle configuration on a bucket with MFA
  delete, or MFA delete on a bucket with one (`409 InvalidBucketState`: S3
  supports no lifecycle configuration with MFA delete). Nor whether S3 wants
  the code for a delete without `versionId` that removes a suspended
  bucket's `null` version for good: Cairn doesn't.

### Inventory

- **CSV and Parquet only.** A configuration asking for ORC is refused with
  `501 NotImplemented`.
- **Parquet files** have one row group per about 16 MiB of rows,
  Snappy-compressed (as S3's are) and PLAIN-encoded; fields Cairn has no value for are null.
- **Configuration IDs** are 1 to 64 letters, digits, `.`, `-` and `_`.
- **Data files** list keys in order, each key's versions newest first. S3
  promises no order.
- **Event holds, Intelligent-Tiering and bucket keys** don't exist, so
  their fields are always empty. `ReplicationStatus` is a version's
  ([Replication](#replication)).
- **Timing.** A configuration's first report starts within minutes, not
  within 48 hours, and reports go at the cluster's `lifecycle-rate`, which
  they share with lifecycle sweeps (see the [README](README.md#inventory)).
- **Failed deliveries** are tried again hourly. S3 skips that day's report.

### Batch Operations

- **Operations.** `S3PutObjectTagging`, `S3DeleteObjectTagging`,
  `S3PutObjectRetention`, `S3PutObjectLegalHold` and `S3ReplicateObject`
  only; a job of another operation is refused with `501 NotImplemented`, as
  is a retention with an event hold (Cairn has none). A retention's date
  must be in the future when the job is created, and is checked again by
  each task.
- **Batch Replication** (`S3ReplicateObject`) replicates the versions its
  manifest lists, whatever their replication status, by their bucket's
  configuration as it is when the task runs. A task succeeds once its
  version is queued (or is queued already); whether it's then replicated,
  its status tells (`x-amz-replication-status`), not the completion
  report. Its failures are `SrcObjectNotEligible` (no rule picks the
  version, or it's the null version, which has no version ID for a
  replica to keep) and `SrcBucketReplicationConfigMissing`; the role
  needs `s3:InitiateReplication` on the object. A task without a version
  ID replicates the key's current version (S3 requires version IDs).
  There's no manifest generator, so no `ObjectReplicationStatuses` or
  other filters: list what's to be replicated in the manifest, or an
  inventory report.
- **Manifests.** CSV manifests (`S3BatchOperations_CSV_20180820`) and CSV
  inventory reports (`S3InventoryReport_CSV_20161130`); manifest generators
  are refused with `501 NotImplemented`. A CSV manifest's lines must have
  exactly the columns its `Fields` name. An inventory report in Parquet or
  ORC fails the job while it's prepared, as does a data file whose MD5
  isn't the one its manifest lists; preparing records each data file's
  ETag, and a data file changed after that fails the job too.
- **Completion reports** have a result file per page of up to a thousand
  tasks (one for those that succeeded, one for those that failed), named
  by a hash of the job and the page; their lines' messages are Cairn's.
  The report bucket is checked (it exists, the role may put the manifest)
  while the job is prepared: a job whose report can't be written fails
  then, with `ReportUnwritable`. A job that fails or is cancelled before it
  runs has no report.
- **Statuses.** A job is never `Completing`, `Failing`, `Pausing` or
  `Paused`: it goes straight to `Complete`, `Failed` or `Cancelled`.
- **Errors.** CreateJob checks the request, and then `s3:CreateJob` and
  `iam:PassRole`; its role and manifest are first used while the job is
  prepared, which fails it (with `FailureReasons`) if they can't be. The
  errors' codes are those of S3 Control's API model (`BadRequestException`,
  `NotFoundException`, `JobStatusException`, `IdempotencyException`, …);
  their statuses and messages, and the failure codes, are Cairn's own.
- **Timing.** A job is prepared and run in the steps lifecycle sweeps and
  inventory reports take turns in, at the cluster's `lifecycle-rate` (each
  task counts as a version read; see the [README](README.md#batch-operations)).

### Server access logging

- **Timing.** Logs arrive within about six minutes, not hours (see the
  [README](README.md#server-access-logs)).
- **What's logged.** Every S3 request to the bucket, and to its website
  endpoint (`WEBSITE.GET.OBJECT`). Not yet: lifecycle's expirations
  (`S3.EXPIRE.OBJECT`, …) and DeleteObjects' keys (`BATCH.DELETE.OBJECT`),
  only the request itself (`REST.POST.MULTI_OBJECT_DELETE`). The requester
  of a POST Object (a browser upload) is left out.
- **Fields.** Host ID, cipher suite and TLS version are always `-` (TLS ends
  at the proxy in front of Cairn), as are the access point ARN and
  `aclRequired`. The turn-around time includes reading the request's body.
  The operations of the commoner requests are named as S3 names them; those
  of the rarer subresources follow its pattern (`REST.GET.OWNERSHIP_CONTROLS`),
  unchecked against S3.
- **Targets** must exist and belong to the bucket's account, as in S3.
  `TargetGrants` are refused with `AccessControlListNotSupported`, as S3
  refuses them for a target bucket whose ACLs are disabled ([ACLs](#acls)).
  Grant the `logging.s3.amazonaws.com` service `s3:PutObject` in the target's
  bucket policy instead, as S3's user guide does.

### POST Object

- There's no clock-skew check; only the policy's `expiration` limits a form.
- The fields `x-amz-website-redirect-location` and `x-amz-acl` are ignored.
- The SSE-C fields need no policy condition, and `content-length-range` takes
  its bounds as strings too (as MinIO does).

### Objects

- **Keys** must be valid UTF-8 without NUL characters. S3 takes NUL.
- **Conditional writes** that race are decided one after the other. Cairn
  never answers `409 ConditionalRequestConflict`.
- **Copying an object onto itself unchanged** is refused for an unencrypted
  object in a bucket without default encryption, as S3 refused it before it
  encrypted every bucket. Elsewhere it works.
- **CopyObject's checksum** is always FULL_OBJECT. A CRC64NVME multipart
  upload is always FULL_OBJECT, even if COMPOSITE is asked for (as in MinIO).
- **Metadata:** an RFC 2047 encoded word that doesn't decode is stored as
  sent. S3 fails such a request with a `500`.
- **CreateBucket's tags:** a key given twice is `400 InvalidTag`, as in
  PutBucketTagging. S3 fails such a request with a `500`.
- **ListObjectsV2 continuation tokens** aren't opaque: they encode the key to
  continue after. A marker that names a common prefix continues after all of
  its keys (as in MinIO).

### Directory buckets

Directory buckets (`<base>--<zone>--x-s3`) work as in S3 Express One Zone:
sessions (`CreateSession`, `x-amz-s3session-token`), `s3express:` actions on
`arn:aws:s3express:us-east-1:<account>:bucket/<name>` (only
`s3express:CreateSession` from a bucket policy; regional operations from
identity policies only), ListDirectoryBuckets apart from ListBuckets, and
S3's limits: no versioning, Object Lock, tags, ACLs, SSE-C, CORS or websites;
ListObjectsV2 only, with `/` the only delimiter and only prefixes ending in
it; part numbers 1, 2, 3, … without gaps; storage class `EXPRESS_ONEZONE`.
Requests under a session are authorized by the session alone, without
looking up policies.

- **No zones.** Cairn has no Availability Zones: the zone is whatever the
  name and the `CreateBucketConfiguration` say (they must agree). Local Zones
  are refused. Data is stored as any bucket's, with the cluster's redundancy,
  not in one zone.
- **One endpoint.** Regional and zonal operations are both served on the S3
  endpoint, virtual-hosted or path-style, as SDKs address directory buckets
  at a custom endpoint, and may be signed for `s3express` or `s3`.
- **Sessions of buckets not created yet.** SDKs at a custom endpoint make a
  session before CreateBucket, so CreateSession of a bucket that doesn't exist
  succeeds (S3 answers `404`); that session's requests are authorized by its
  principal's policies, as if it were none. Requests signed without a session
  are authorized as a session's creation would be (`s3express:CreateSession`,
  in `ReadWrite` mode to write).
- **Not yet:** RenameObject, appends (`x-amz-write-offset-bytes`), bucket tags
  and S3 Express's condition keys other than `s3express:SessionMode` and
  `s3express:ResourceAccount`. Objects aren't encrypted by default, as in
  other buckets ([Encryption](#encryption)), and a session's encryption
  headers are ignored (its response tells the bucket's default).
- **ETags** are MD5 digests, as in general purpose buckets; S3's aren't, and
  clients don't rely on either.
- **Refusals.** What a directory bucket doesn't have (an operation, a
  feature's header, `Content-MD5` on zonal operations) is
  `501 NotImplemented`, "This bucket does not support …", as S3 refuses
  `Content-MD5`; whether S3 answers its other unsupported operations the
  same wasn't probed. Neither were its errors for a listing's delimiter or
  prefix, `start-after`, or a gap in part numbers (Cairn: `400`).
- **The console** doesn't manage directory buckets; use the S3 API.

### Policies

The policy language and its evaluation are IAM's: identity policies (inline
and managed), permissions boundaries, session policies, bucket policies and
trust policies.

- **ABAC takes effect at once.** A bucket's tags and its ABAC setting
  decide the next request. S3 takes a minute or more to apply them.
- **Other unsupported S3 keys,** refused with `501`: `s3:TlsVersion`,
  `s3:locationconstraint`, the event-hold keys, `s3:ObjectCreationOperation`,
  `s3:x-amz-object-ownership`, `s3:x-amz-object-if-match`,
  `s3:x-amz-bucket-namespace` and `s3:resourceArnBeingAuthorized`.
- **Keys that are never present,** because what they describe doesn't exist:
  VPC, organization, service, access point and batch job keys. `aws:SourceAccount` and `aws:SourceArn` are present only in what
  Cairn does as `s3.amazonaws.com`, and in Access Grants' assuming a
  location's role.
- **Principals:** `Service` principals match only what Cairn does as that
  service: `s3.amazonaws.com` delivering inventory reports and assuming a
  replication configuration's role, and
  `access-grants.s3.amazonaws.com` assuming a location's role. As in AWS,
  `"*"` covers it too. `CanonicalUser` principals are refused.
- **Managed policies:** of AWS's, only `AdministratorAccess`,
  `AmazonS3FullAccess` and `AmazonS3ReadOnlyAccess` exist, plus Cairn's
  `CairnOperatorAccess`.

### IAM

IAM's Query API (`aws iam`, Terraform, SDKs), for:

| Area | Actions |
| --- | --- |
| Users | Create, get, list, update, delete; tags; permissions boundaries |
| Access keys | Create, list, update, delete |
| Policies | Inline user and role policies; managed policies with versions, tags and attachments; ListEntitiesForPolicy |
| Roles | Create, get, list, update, delete; trust policies; tags; permissions boundaries |
| Groups | Create, get, list, update, delete; members; inline and managed policies |
| OpenID Connect providers | All actions |

Not implemented (`501`): login profiles and passwords, MFA devices,
SAML providers, instance profiles and service-linked roles, account settings
(aliases, password policy, summary), GetAccountAuthorizationDetails, policy
simulation, certificates, SSH keys, service-specific credentials, credential
reports, last-accessed details, GetAccessKeyLastUsed.

Differences:

- User names may only use `[A-Za-z0-9._-]`, and paths only `[\w+=,.@/-]`.
- Access key IDs have no `AKIA` prefix.
- ListAttachedUserPolicies, ListAttachedRolePolicies,
  ListAttachedGroupPolicies and ListEntitiesForPolicy ignore `PathPrefix`,
  and ListPolicies ignores `PolicyUsageFilter`. (Every list pages, with
  `MaxItems` and `Marker`, as IAM's do.)
- `iam:PassRole` is checked only where a role is passed to a service:
  an Access Grants location's role ([Access Grants](#access-grants)).
- Roles under `/aws-reserved/` are permission sets' ([Identity
  Center](#identity-center)): IAM won't make them, and refuses to change
  them with `UnmodifiableEntity`.
- `RoleLastUsed` and `PasswordLastUsed` are never reported.
- **OpenID Connect providers:** Cairn fetches the issuer's discovery document
  when a provider is created, and refuses one it can't reach. Thumbprints are
  enforced as certificate pins, which lets issuers on private CAs work.

### Organizations

Accounts as AWS Organizations has them: the account a cluster starts with
is the organization's management account, which makes member accounts
(see the README's *Accounts*). Organizations' API covers
DescribeOrganization (any account's principals), and, the management
account's only, ListAccounts, DescribeAccount, CreateAccount (with
DescribeCreateAccountStatus and ListCreateAccountStatus), CloseAccount,
the root (ListRoots, Enable/DisablePolicyType), organizational units
(Create/Describe/Update/DeleteOrganizationalUnit,
ListOrganizationalUnitsForParent, ListAccountsForParent, ListChildren,
ListParents, MoveAccount) and service control policies
(Create/Describe/Update/DeletePolicy, ListPolicies, Attach/DetachPolicy,
ListPoliciesForTarget, ListTargetsForPolicy). This wasn't checked against
AWS. It differs in that:

- **SCPs only:** other policy types (RCPs, tag, backup and declarative
  policies, …), invitations, delegated administrators and trusted services
  answer `501`, and so do `Tags` on CreateAccount, CreateOrganizationalUnit
  and CreatePolicy.
- **SCPs** are evaluated as AWS's: every level from the root to the
  account must allow a member account principal's request, a Deny in any
  denies it, a bucket's policy doesn't get past them, and the management
  account is under none. `FullAWSAccess` is attached to every root, unit and
  account while they're enabled, and each keeps one at least
  (`MIN_POLICY_TYPE_ATTACHMENT_LIMIT_EXCEEDED`); disabling them detaches
  all. Changes apply to requests at once, sessions' already made too.
- **The structure's operations are decided on the organization's ARN,**
  not on the root's, a unit's or a policy's.
- **Done at once.** CreateAccount's status is `SUCCEEDED` (or `FAILED`, with
  `EMAIL_ALREADY_EXISTS`) when it's answered, and kept for 90 days.
- **No member root users,** as AWS's centralized root access has it: a
  member account's way in is `OrganizationAccountAccessRole` (or the role
  named in `RoleName`) and Identity Center's permission sets.
- **Closing is at once,** and only of an account without buckets: its
  status is `SUSPENDED` from then on, and its users, roles and sessions are
  no one. AWS keeps a closed account for 90 days, and its data with it.
- **No e-mail is sent,** and the management account has none (so
  DescribeOrganization has no `MasterAccountEmail`).
- **Cross-account access** works as AWS's, by resource policies: buckets'
  policies, roles' trust policies, SNS topics' policies (AddPermission) and
  Access Grants instances' resource policies. Across accounts, both the
  resource's policy and the caller's own policies must allow a request.
  Other accounts are the organization's (open) only: a policy naming one
  that isn't is refused. KMS keys are OpenBao's or Vault's, not accounts'
  ([Encryption](#encryption)): their own policies decide who uses them,
  whatever account a role is in.

### Identity Center

Directory users, as IAM Identity Center has them: people who sign in to the
console at an identity source, and act as a session of the role of a
permission set assigned to them or a group of theirs (see the README's
*Directory users*). As in Identity Center, a permission set is provisioned
to an account (when it's first assigned there, and again by
ProvisionPermissionSet once it has changed) as a role at
`/aws-reserved/sso.amazonaws.com/` named `AWSReservedSSO_<set>_<suffix>`,
which IAM refuses to change (`UnmodifiableEntity`), with an inline policy
named `AwsSSOInlinePolicy`. sso-admin's API covers the instance,
permission sets (their inline, AWS managed and customer managed policies,
boundaries, relay states and tags), assignments, and provisioning;
identitystore's, its reads (users, groups, memberships, by IDs, user
names, display names and external IDs) and writes (of Cairn's own
directory). This, too, wasn't checked against
AWS. It differs in that:

- **Cairn's own directory and identity sources, side by side.** Identity
  Center has one identity source at a time; Cairn has its own directory
  (Identity Center's built-in one) and any number of OpenID Connect
  providers (not SAML) at once.
  - identitystore's writes make and change the own directory's users,
    groups and memberships, and refuse a source's (`ValidationException`).
    A group of its own may have any directory user as a member.
  - A source's user, and its groups (from a claim of its ID token), are in
    the identity store once it has signed in, and its memberships of its
    source's groups are what its last sign-in said: there's no directory
    sync (SCIM). A user's external ID is its source's issuer and its
    subject; a group's, its source's issuer and its name (its display
    name, which several sources' groups may share: GetGroupId then wants
    the external ID).
- **Users of the own directory sign in with passkeys,** not a password
  and MFA, and get their first through a setup link (valid 7 days) that
  the console or the command line makes, in place of Identity Center's
  invitation e-mail or one-time password; there's no e-mail. A passkey
  sign-in is multi-factor (`aws:MultiFactorAuthPresent`). CreateUser
  requires `UserName`, `DisplayName` and `Name`, as Identity Center does;
  `UserName` and groups' `DisplayName` are unique (a group's whatever its
  case), and `Administrator` and `AWSAdministrators` are reserved. Each
  attribute is kept as given, checked for its type and length only.
  UpdateUser and UpdateGroup take attribute paths (`name.familyName`,
  `aws:identitystore:enterprise.department`); one without a value removes
  its attribute.
- **The organization's instance, done at once.** The management account's
  instance is the only one (CreateInstance, DeleteInstance and
  UpdateInstance answer `501`; a member account's principals may not call
  sso-admin or identitystore), and the organization's open accounts the
  targets of assignments and provisioning. Their requests are done when
  they're answered: their statuses are
  `SUCCEEDED` or `FAILED` (never `IN_PROGRESS`), and creating an
  assignment there is, or deleting one there isn't, succeeds. Their
  statuses are kept for 90 days.
- **A provisioned set's role stays** when its last assignment in the
  account goes, until the set is deleted.
- **The console provisions a set again when it's saved there**, if the
  session may (`sso:ProvisionPermissionSet`), so that edits there take
  effect at once; sso-admin's changes wait for ProvisionPermissionSet, as
  AWS's do.
- **No access portal API** (`sso`, `sso-oidc`): `aws sso login` and SSO
  profiles don't work. A directory user's page hands out its session's
  credentials instead, as the access portal's "access keys" do.
- **Not supported:** applications, trusted token issuers, regions, and
  attributes for access control (claims as session tags), which answer
  `501`; the instance's tags; and MFA at the identity source, which Cairn
  doesn't trust: the sessions of a source's users never have
  `aws:MultiFactorAuthPresent`.
- **Console sessions** last 12 hours at most (1 hour unused); taking an
  assignment away ends a session's use of it at once.

### Access Grants

S3 Control's Access Grants API: instances, locations, grants,
GetDataAccess, ListCallerAccessGrants, GetAccessGrantsInstanceForPrefix,
and tags on all three (TagResource, at creation too). Its responses parse
in AWS's SDKs and CLI. Unlike the rest of this document, its behavior was
**not checked against S3**, only against AWS's documentation and API model,
so the points below are Cairn's reading of them:

- **IAM grantees only.** Cairn's [directory users](#identity-center) aren't
  grantees yet: `DIRECTORY_USER` and `DIRECTORY_GROUP` grantees,
  applications and Identity Center instances are refused with `501`.
- **Other accounts.** A grant may name another account's user or role,
  which calls GetDataAccess with the instance's account
  (`x-amz-account-id`), if the instance's resource policy allows it and its
  own policies do too, as in AWS. `instanceScope=ALL` is taken as `SELF`:
  there's no sharing through AWS RAM. GetAccessGrantsInstanceResourcePolicy
  answers an empty result when there's none, and the policy's
  `Organization` is kept, but decides nothing.
- **Scopes.** A grant's scope is its location's joined with its
  sub-prefix; without one, `<location>/*`. A trailing `*` is optional; one
  elsewhere is refused. A grantee's narrowest matching grant is the one
  GetDataAccess uses.
- **Vended sessions** are sessions of the location's role, whose trust
  policy must let `access-grants.s3.amazonaws.com` take `sts:AssumeRole`
  (with `aws:SourceAccount` and `aws:SourceArn` to condition on). Their
  session policy allows: `READ`, GetObject(Version)(Acl),
  ListMultipartUploadParts, ListBucket and ListBucketVersions; `WRITE`,
  PutObject(Version)Acl, PutObject, DeleteObject(Version),
  AbortMultipartUpload, ListMultipartUploadParts and
  ListBucketMultipartUploads (the actions that take
  `s3:AccessGrantsInstanceArn`). Listing is allowed under the scope's
  prefix (`s3:prefix`) only. The session's name is the grantee's unique ID.
- **Authorization.** Each operation needs its `s3:` action on the
  instance's ARN, but those on one location or grant, which need it on
  theirs; CreateAccessGrant needs it on both the instance and the
  location. Creating or updating a location needs `iam:PassRole` on its
  role (with `iam:PassedToService`). The root user may do everything, but
  is no grantee, nor is a federated user.
- **Grantees** must be existing IAM users or roles of the account when the
  grant is made. They're kept by ARN, as in S3: a user deleted and made
  again with its name has its grants again.
- **Errors** for missing, duplicate and non-empty resources use the codes
  AWS documents, with `404` and `409`; their messages are Cairn's.
- `s3:AccessGrantScope`, `s3:AccessGrantsLocationScope` and
  `s3:AccessGrantsInstanceArn` are evaluated. The resources' tags are kept
  and listed, but aren't `aws:ResourceTag/…` to policies.
- GetDataAccess's `auditContext` and `instanceScope` are taken and
  ignored. Vended sessions have no source identity.

Not implemented:

- **Identity Center** in Access Grants: directory users and groups as
  grantees (a group of an IdP, rather than an IAM
  principal, granted a prefix), applications (`ApplicationArn`,
  `allowedByApplication`), and sessions carrying a person's identity
  (`sts:SetContext`, trusted identity propagation).
- **Auditing:** there's no CloudTrail, and S3 Control's requests aren't in
  [server access logs](#server-access-logging), so who got data access
  when isn't recorded (the session's name, the grantee's unique ID, is in
  its requests' access log records).
- **Access points,** which grants can't name either.

### Event notifications

A bucket's notification configuration (`?notification`) names SNS topics,
which Cairn has: the SNS API is served on the S3 endpoint, for requests
signed for the `sns` service (`aws sns --endpoint-url …`, Terraform's
`aws_sns_topic`, `aws_sns_topic_policy` and `aws_sns_topic_subscription`).
Validation, records, test events, subscriptions and their confirmation,
message signatures and retries are as AWS's.

| SNS action | |
| --- | --- |
| CreateTopic, DeleteTopic, ListTopics, Get/SetTopicAttributes, Add/RemovePermission | ✅ |
| TagResource, UntagResource, ListTagsForResource | ✅ |
| Subscribe, ConfirmSubscription, Unsubscribe, ListSubscriptions(ByTopic), Get/SetSubscriptionAttributes | 🟡 |
| Publish | 🟡 |
| PublishBatch, FIFO topics, platform applications, SMS, data protection | ❌ |

- **HTTP(S) subscriptions only.** Other protocols (`sqs`, `lambda`,
  `email`, …) are refused as AWS refuses an unknown one. A configuration's
  queues and functions fail its destination validation, and EventBridge
  is `501 NotImplemented`.
- **Signatures:** messages are signed as SNS signs them (versions 1 and 2),
  with Cairn's own keys. `SigningCertURL` is on Cairn's endpoint, so AWS's
  SDK message validators, which only take certificates from
  `sns.<region>.amazonaws.com`, refuse them: check signatures with a
  validator whose certificate host is configurable, or yourself.
- **Delivery** is never lost to a crash: events are written in their
  object's own transaction, and deliveries are retried as their delivery
  policies say (AWS's by default), then dropped. Writes never wait for
  delivery.
- **Private endpoints:** subscriptions deliver to public addresses only,
  unless the `notification-private-endpoints` setting allows private ones.
- **Not supported:** subscription filter policies, redrive policies (DLQs),
  `MessageStructure`, topic encryption (`KmsMasterKeyId`) and delivery
  status logging. They're refused, not ignored.
- **Default topic policy:** AWS's, whose condition (`AWS:SourceOwner`) no
  request to Cairn carries, so a topic's users need identity policies
  allowing `sns:` actions, and S3 needs a statement allowing it to publish,
  as on AWS.

### Replication

A bucket's replication configuration (`?replication`, both of S3's
schemas) replicates to other buckets of the cluster, of any account, as
S3's same-region replication does. The role is assumed as
`s3.amazonaws.com`, and must be allowed `s3:GetObjectVersionForReplication`,
`s3:ReplicateObject`, `s3:ReplicateDelete` and `s3:ReplicateTags`, by its
policies and the buckets' policies. The caller of PutBucketReplication must
be allowed `iam:PassRole` on it. Both buckets must be versioned, and the
source can't be suspended while it has a configuration. A replica keeps
its source's version ID, last-modified time, ETag, metadata, tags and
Object Lock. `x-amz-replication-status` is `PENDING`, `COMPLETED` or
`FAILED` on the source, and `REPLICA` on the replica.

- **Within the cluster only.** A destination is a bucket of the cluster,
  named by its ARN. There's no replication to other Cairn clusters or
  other S3 providers yet.
- **Replicas share their source's bytes.** A replica is a new version
  that points at the source's data, so it takes no space and no data is
  copied. It's written again only into another storage class
  (`StorageClass`). So a replica protects against deletes, overwrites
  and, with Object Lock, tampering, but not against losing the data:
  erasure coding and the replication factor guard that.
- **Asynchronous,** usually within a second: versions are queued in their
  write's own transaction, so none is lost to a crash. A key's versions
  are replicated in the order they were written. A replica lands among
  the destination key's versions by its last-modified time (its
  source's), as S3 orders versions by time: below a version written to
  the destination since, which stays current.
- **Failures** are final, as in S3: a version the role may not replicate,
  or whose destination is gone or no longer versioned, is `FAILED`.
  Transient errors are retried with backoff, for about 40 minutes.
- **Not replicated, as in S3:** versions written before their rule
  (unless a [Batch Replication](#batch-operations) job replicates them),
  replicas (likewise), delete markers made by lifecycle rules, deletes of a version
  by ID, and SSE-KMS objects unless their rule replicates them
  (`SseKmsEncryptedObjects`, under its `ReplicaKmsKeyID`).
- **SSE-C objects** are replicated as they're stored, since Cairn
  doesn't have the client's key, and open with the same key. For that
  reason they can't be written into another storage class: an SSE-C
  version whose rule names a different `StorageClass` fails.
- **Not replicated, unlike S3:** later changes to a version's tags,
  retention or legal hold. `ReplicaModifications` is kept and returned,
  but has no effect.
- **Refused:** `ExistingObjectReplication`, `ReplicationTime` and
  `Metrics` (`501 NotImplemented`). Existing objects are replicated by
  Batch Replication instead (see [Batch Operations](#batch-operations)).
- **Ownership:** replicas are always owned by the destination bucket's
  account, since ACLs are disabled. `AccessControlTranslation` is taken,
  but it needs `s3:ObjectOwnerOverrideToBucketOwner`, as in S3.

### STS

| Action | |
| --- | --- |
| GetCallerIdentity, AssumeRole, GetSessionToken, GetAccessKeyInfo | ✅ |
| AssumeRoleWithWebIdentity | 🟡 |
| GetFederationToken | 🟡 |
| AssumeRoleWithSAML, DecodeAuthorizationMessage, AssumeRoot, GetDelegatedAccessToken, GetWebIdentityToken | ❌ |

- **AssumeRoleWithWebIdentity** is taken unsigned only. Of the token's
  claims, only `sub`, `aud` and `amr` become condition keys; conditions on
  other claims (`email`, GitHub's `job_workflow_ref`, …) never match.
  OAuth 2.0 access tokens (`ProviderId`) aren't supported.
- **GetFederationToken:** session tags don't need `sts:TagSession`, and
  `TransitiveTagKeys` isn't taken.
- **MFA:** there are no MFA devices, so `SerialNumber`/`TokenCode` always fail.
- **Revocation:** besides AWS's `aws:TokenIssueTime` deny, `cairn sessions
  revoke-all` ends every session in the cluster.

---

## Known gaps

Differences that are open, and should be fixed:

- S3 applies some `x-amz-*` query parameters as headers (`x-amz-meta-*`,
  `x-amz-tagging`, `x-amz-acl`, `x-amz-storage-class`,
  `x-amz-server-side-encryption`); Cairn ignores them.
- A PUT with neither `Content-Length` nor a body framing stores an empty
  object; S3 is believed to answer `411 MissingContentLength` (not yet
  checked against S3).
- Signature and clock-skew errors have no detail elements (`StringToSign`,
  `CanonicalRequest`, `RequestTime`, `ServerTime`).

---

## Cairn's own additions

- **The console:** a web UI with passkey or OpenID Connect sign-in. It acts
  as the signed-in user: every operation is authorized as its `s3:`, `iam:`
  or `cairn:` action. It switches roles as AWS's console does: a role the
  signed-in user may assume with STS, for an hour at most.
- **Operators:** the cluster's settings and nodes are managed through `cairn:`
  actions on `arn:aws:cairn:::cluster`, granted like any other permission
  (`CairnOperatorAccess` allows them all).
- **Policy templates:** ready-made managed policies for teams sharing the
  account, access to buckets, and requiring MFA.
- **The `cairn` CLI:** on a node, sets up the cluster and is the break-glass
  for access, outside of policies.
- **Trusted proxies:** the TLS proxy's forwarded headers set `aws:SourceIp`
  and `aws:SecureTransport`.
