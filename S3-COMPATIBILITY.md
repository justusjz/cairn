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
| SigV2, SigV4A | ❌ | |
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
| Versioning | ✅ | Without MFA delete. |
| Object Lock: retention, legal holds, default retention | ✅ | No event-based holds. |
| Lifecycle: expiration, noncurrent expiration, delete markers, incomplete uploads | 🟡 | [Lifecycle](#lifecycle) |
| Lifecycle transitions | ❌ | There are no other storage classes. |
| Storage classes other than STANDARD, restore | ❌ | [Storage classes](#storage-classes) |
| CORS | ✅ | |
| Static website hosting | ✅ | [Endpoints](#endpoints-and-domains) |
| RenameObject, appends (S3 Express) | ❌ | |
| Inventory | 🟡 | CSV only: [Inventory](#inventory) |

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
| MFA delete | ❌ | |
| Access points, Object Lambda, Multi-Region Access Points | ❌ | |

### Not implemented

These answer `501 NotImplemented`, or report the feature as unconfigured, as
S3 reports a bucket that doesn't use it:

- Replication, server access logging, event notifications.
- Analytics, metrics, Intelligent-Tiering, Storage Lens.
- S3 Select, torrents, S3 Batch Operations.
- S3 Express (directory buckets, `CreateSession`), metadata tables.
- Requester pays, Transfer Acceleration.

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
- **One account.** A cluster has one account, which owns every bucket, user,
  role and policy. Its canonical user ID is derived from the account ID.
  There are no Organizations, so no SCPs, RCPs or organization condition keys.
- **No root user.** Every principal, admins included, is subject to policies.
  Admins have `AdministratorAccess`.

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

Every object is STANDARD. `x-amz-storage-class` is accepted and ignored,
whatever its value; S3 refuses one it doesn't know.

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

### Inventory

- **CSV only.** A configuration asking for ORC or Parquet is refused with
  `501 NotImplemented`.
- **Configuration IDs** are 1 to 64 letters, digits, `.`, `-` and `_`.
- **Data files** list keys in order, each key's versions newest first. S3
  promises no order.
- **Event holds, replication, Intelligent-Tiering and bucket keys** don't
  exist, so their fields are always empty.
- **Timing.** A configuration's first report starts within minutes, not
  within 48 hours, and reports go at the cluster's `lifecycle-rate`, which
  they share with lifecycle sweeps (see the [README](README.md#inventory)).
- **Failed deliveries** are tried again hourly. S3 skips that day's report.

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
  VPC, organization, service, access point, access grant, replication and
  batch job keys. `aws:SourceAccount` and `aws:SourceArn` are present only
  in what Cairn does as `s3.amazonaws.com`.
- **Principals:** `Service` principals match only what Cairn does as that
  service: `s3.amazonaws.com` delivering inventory reports. As in AWS, `"*"`
  covers it too. `CanonicalUser` principals are refused.
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
| OpenID Connect providers | All actions |

Not implemented (`501`): groups, login profiles and passwords, MFA devices,
SAML providers, instance profiles and service-linked roles, account settings
(aliases, password policy, summary), GetAccountAuthorizationDetails, policy
simulation, certificates, SSH keys, service-specific credentials, credential
reports, last-accessed details, GetAccessKeyLastUsed.

Differences:

- User names may only use `[A-Za-z0-9._-]`, and paths only `[\w+=,.@/-]`.
- Access key IDs have no `AKIA` prefix.
- These list actions return everything at once and ignore paging:
  ListAccessKeys, ListUserPolicies, ListAttachedUserPolicies,
  ListRolePolicies, ListAttachedRolePolicies, ListEntitiesForPolicy.
  ListPolicies ignores `PolicyUsageFilter`.
- `iam:PassRole` is never checked, since there are no services to pass roles to.
- `RoleLastUsed` and `PasswordLastUsed` are never reported.
- **OpenID Connect providers:** Cairn fetches the issuer's discovery document
  when a provider is created, and refuses one it can't reach. Thumbprints are
  enforced as certificate pins, which lets issuers on private CAs work.

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

- Unknown storage classes are accepted ([Storage classes](#storage-classes)).
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
  or `cairn:` action.
- **Operators:** the cluster's settings and nodes are managed through `cairn:`
  actions on `arn:aws:cairn:::cluster`, granted like any other permission
  (`CairnOperatorAccess` allows them all).
- **Policy templates:** ready-made managed policies for teams sharing the
  account, access to buckets, and requiring MFA.
- **The `cairn` CLI:** on a node, sets up the cluster and is the break-glass
  for access, outside of policies.
- **Trusted proxies:** the TLS proxy's forwarded headers set `aws:SourceIp`
  and `aws:SecureTransport`.
