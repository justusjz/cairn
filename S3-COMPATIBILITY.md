# S3 compatibility

This document describes, as exactly as possible, which parts of the Amazon S3
API (and of the IAM and STS APIs that S3 clients and tools rely on) Cairn
implements, and how its behavior differs from AWS's. It is a reference for
client authors, operators evaluating Cairn, and anyone debugging an
incompatibility. For how to run and configure Cairn, see the
[README](README.md).

Many behaviors below are marked **(probed)**: Cairn's code was written
against what real S3 (or IAM/STS) answered to the same request, not only
against AWS's documentation. Where Cairn follows MinIO instead (usually
where AWS documents nothing), that is said too.

Legend used throughout:

| Mark | Meaning |
| --- | --- |
| ✅ | Implemented and honored, as in S3. |
| 🟡 | Implemented with differences (described next to it). |
| 🔹 | Accepted and validated or stored, but has no effect, or a fixed answer (a stub). |
| ⚪ | Ignored: Cairn never reads it. |
| ❌ | Refused (the error is given), or not implemented (`501 NotImplemented` unless said otherwise). |

---

## Contents

1. [At a glance](#1-at-a-glance)
2. [Endpoint, transport and addressing](#2-endpoint-transport-and-addressing)
3. [Authentication](#3-authentication)
4. [Common request handling](#4-common-request-handling)
5. [Operation support matrix](#5-operation-support-matrix)
6. [Buckets](#6-buckets)
7. [Listings](#7-listings)
8. [Objects](#8-objects)
9. [Multipart uploads](#9-multipart-uploads)
10. [Checksums and payload integrity](#10-checksums-and-payload-integrity)
11. [Tags](#11-tags)
12. [Versioning](#12-versioning)
13. [Object Lock](#13-object-lock)
14. [Lifecycle](#14-lifecycle)
15. [CORS](#15-cors)
16. [Static website hosting](#16-static-website-hosting)
17. [Server-side encryption](#17-server-side-encryption)
18. [ACLs and Object Ownership](#18-acls-and-object-ownership)
19. [Bucket policies and Block Public Access](#19-bucket-policies-and-block-public-access)
20. [Authorization and the policy language](#20-authorization-and-the-policy-language)
21. [IAM API](#21-iam-api)
22. [STS API](#22-sts-api)
23. [OpenID Connect providers and web identity](#23-openid-connect-providers-and-web-identity)
24. [Cairn-specific concepts](#24-cairn-specific-concepts)
25. [Request header reference](#25-request-header-reference)
26. [Response header reference](#26-response-header-reference)
27. [Limits](#27-limits)
28. [Summary of deviations from AWS](#28-summary-of-deviations-from-aws)

---

## 1. At a glance

**Implemented:**
- Path-style and virtual-hosted-style addressing.
- SigV4 header authentication, presigned URLs, and aws-chunked streaming uploads (signed, unsigned and with trailers).
- Buckets and the full object lifecycle: put, get, head, copy, delete, batch delete, GetObjectAttributes, browser POST uploads.
- Multipart uploads, including UploadPartCopy.
- ListObjects v1 and v2, ListObjectVersions, ListMultipartUploads and ListParts.
- Conditional reads, and conditional writes (`If-Match`, `If-None-Match: *`).
- Every S3 checksum algorithm except the newest (CRC32, CRC32C, CRC64NVME, SHA-1, SHA-256), full-object and composite.
- Object and bucket tags.
- Versioning; Object Lock (governance, compliance, legal holds); lifecycle expiration.
- CORS and static website hosting.
- SSE-C, SSE-KMS (on OpenBao/Vault Transit), SSE-S3, and bucket default encryption.
- Bucket policies and Block Public Access, at bucket and account level.
- An IAM-compatible policy engine, with permissions boundaries and session policies.
- An IAM API: users, access keys, inline and managed policies, roles, OIDC providers and tags.
- An STS API: AssumeRole, AssumeRoleWithWebIdentity, GetSessionToken, GetFederationToken, GetCallerIdentity, GetAccessKeyInfo.

**Not implemented:**
- ACLs other than owner-only. Buckets are always `BucketOwnerEnforced`.
- Storage classes other than STANDARD, transitions, restore and Glacier.
- Replication, logging, event notifications, inventory, analytics, metrics, Intelligent-Tiering, S3 Select, torrents.
- Access points, Object Lambda, Multi-Region Access Points.
- S3 Express (directory buckets, `CreateSession`, appends, rename).
- Metadata tables.
- Requester pays.
- MFA delete.
- SigV2 and SigV4A.
- IAM groups, instance profiles, login profiles, MFA devices, SAML.

Cairn has a single account (see [§24](#24-cairn-specific-concepts)): all buckets, users and roles belong to it.

---

## 2. Endpoint, transport and addressing

### Transport

- **Protocol:** the S3 API listener (`--listen-client`) speaks **HTTP/1.1 only**. There is no TLS and no HTTP/2 (neither h2 nor h2c). Run a TLS-terminating proxy in front of it; `deploy/compose` uses Caddy.
- **Timeouts:**
  - A connection that sits idle, or takes more than **30 s** to send a request head, is closed.
  - A request body that sends nothing for **30 s** fails with `400 RequestTimeout`.
  - A response the client reads none of for **60 s** is cut off.
- **Connections:** at most `--max-connections` (default 4096) are served at once. Further connections wait to be accepted; they are not refused.
- **`Expect: 100-continue`:** the HTTP server answers it the first time the handler reads the body. A request refused before its body is read (bad signature, bad headers, too large) gets its final answer without a `100`.
- **One port for everything:** IAM and STS are served on the same port as S3 ([§21](#21-iam-api)). So are buckets' websites ([§16](#16-static-website-hosting)).

### Addressing

| Style | Support |
| --- | --- |
| Path-style (`host/bucket/key`) | ✅ Always. |
| Virtual-hosted-style (`bucket.domain/key`) | ✅ With `--domain <name>`. Only **one** domain can be configured. The bucket is everything in the host before `.<domain>`, dots included (`my.bucket.s3.example.com` is bucket `my.bucket`). Matching ignores case, a port and a trailing dot. IPv6 literal hosts are always path-style. |
| Website endpoints | ✅ With `--website-domain <name>`: `bucket.<website-domain>`. |
| Custom domains | ✅ With `--domain` set, any host that is not the domain, a subdomain of it, an IP literal or `localhost` is the website of the bucket named by the whole host, served over HTTPS when the proxy gets certificates on demand ([§16](#16-static-website-hosting)). So clients must reach the S3 API by the domain, an IP address or `localhost`, not by another name. (S3 only serves custom domains over HTTP, or over HTTPS through CloudFront.) |
| Dual-stack, FIPS, accelerate, access-point and region-specific endpoints | ❌ No special handling. |

The signature is always checked against the path the client sent, so virtual-hosted requests verify correctly even though they are routed as `/bucket/key`. The proxy must pass `Host` through unchanged.

### Regions

- Cairn has no regions. **Any region in a SigV4 credential scope is accepted.** The signing key is derived from whatever region the client used, and that region becomes `aws:RequestedRegion`.
- `GetBucketLocation` always answers an empty `LocationConstraint`, which means `us-east-1`.
- A `CreateBucketConfiguration` body is never read.
- No response carries `x-amz-bucket-region` or `BucketRegion`.

### Trusted proxies

`--trusted-proxy <CIDR>` (repeatable) names proxies whose forwarding headers Cairn believes:

- **Client address:** `X-Forwarded-For` (every instance, comma-split). Cairn takes the right-most hop that isn't a trusted proxy. This feeds `aws:SourceIp`. `Forwarded: for=` is not used.
- **HTTPS:** the first `X-Forwarded-Proto`, else `Forwarded: proto=`. This feeds `aws:SecureTransport` and the SSE-C HTTPS requirement.

From an untrusted peer the TCP address is used, and the connection counts as HTTP.

---

## 3. Authentication

### Signature versions

| Mechanism | Support |
| --- | --- |
| SigV4 `Authorization: AWS4-HMAC-SHA256 …` | ✅ |
| SigV4 presigned URL (`X-Amz-Algorithm=AWS4-HMAC-SHA256&…`) | ✅ `X-Amz-Expires` 1–604800 s. |
| SigV4 POST policy (browser form) | ✅ See [POST Object](#post-object-browser-uploads). |
| Anonymous (no signature) | ✅ Only bucket policies can allow it. |
| SigV2 header (`Authorization: AWS key:sig`) | ❌ `403 AccessDenied` "request is not signed". |
| SigV2 presigned URL (`AWSAccessKeyId`/`Signature`/`Expires`) | ❌ Not recognized: the request is treated as **anonymous**, and the parameters are ignored. |
| SigV2 POST form | ❌ `403 AccessDenied` "the form is not signed". |
| SigV4A (`AWS4-ECDSA-P256-SHA256`) | ❌ `403 AccessDenied` "request is not signed". |

### SigV4 header requests

Checks run in this order:

1. **Unknown or invalid credentials**, checked before the signature (probed):
   - unknown or inactive access key, or a temporary key without a token: `403 InvalidAccessKeyId`;
   - malformed token, or a token sent with a long-term key: `400 InvalidToken`;
   - expired session: `400 ExpiredToken`.
2. **Two auth mechanisms:** both an `Authorization` header and `X-Amz-Algorithm` in the query is `400 InvalidArgument` "Only one auth mechanism allowed".
3. **Request time:** `x-amz-date` is **required**. The `Date` header is never accepted in its place. If it is missing, malformed, or on a different day than the credential scope: `403 AccessDenied`.
4. **Payload hash:** `x-amz-content-sha256` is **required**. If missing: `400 InvalidRequest`. Accepted values are in [§10](#10-checksums-and-payload-integrity). Any other value: `400 InvalidArgument`.
5. **Signed headers:** `host` and every `x-amz-*` header must be signed. Otherwise `403 AccessDenied` "There were headers present in the request which were not signed", with a `<HeadersNotSigned>` element. Other headers (`Content-Type`, `Content-MD5`, …) may stay unsigned.
6. **Clock skew:** more than ±15 minutes from the server's clock is `403 RequestTimeTooSkewed`. There are no `RequestTime`/`ServerTime` detail elements.
7. **Signature:** a wrong one is `403 SignatureDoesNotMatch`, with no `StringToSign`/`CanonicalRequest` detail elements.

Canonicalization details:

- **Path:** the canonical URI is the path exactly as received, not normalized or re-encoded (S3's rule).
- **Query:** the canonical query string uses the parameters **as encoded on the wire**, sorted, without re-encoding them. A client whose wire encoding differs from SigV4's canonical encoding fails to verify.
- **Service:** the credential scope's service is not validated for S3. `iam` and `sts` route to IAM/STS; anything else is treated as S3.
- **Errors never returned:** `AuthorizationHeaderMalformed`, `MissingSecurityHeader` and `SignatureVersionNotSupported`.

### Presigned URLs

- **Required parameters:** `X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-SignedHeaders`, `X-Amz-Signature`, `X-Amz-Date` and `X-Amz-Expires`.
  - A missing `X-Amz-Date`, or a non-numeric `X-Amz-Expires`: `400 AuthorizationQueryParametersError`.
  - `X-Amz-Expires` ≤ 0 or over 604800: `403 AccessDenied` (probed).
- **Validity window:** from 15 minutes before `X-Amz-Date` (earlier: "Request is not valid yet") until `X-Amz-Date + X-Amz-Expires` ("Request has expired").
- **Session token:** `X-Amz-Security-Token` carries it.
- **Payload:** without an `x-amz-content-sha256` header, the payload is `UNSIGNED-PAYLOAD`.
- **Missing signature:** a query with SigV4 parameters but no `X-Amz-Signature` is treated as anonymous.
- **SSE-C:** presigned SSE-C requests must sign the key headers, and the client must send them.

### Temporary credentials

- **Recognition:** access key IDs beginning with `ASIA` are temporary ([§22](#22-sts-api)). They need `X-Amz-Security-Token`, as a header or in the query.
- **Re-validation:** the session's user or role is re-read on every request. A deleted user or role ends its sessions at once.

---

## 4. Common request handling

### Errors and request IDs

- **Error body:** every error is S3's XML document: `<Error><Code/><Message/>[details]<RequestId/></Error>`, with `Content-Type: application/xml`.
- **Request IDs:** every response carries `x-amz-request-id` (16 hex characters). There is no `x-amz-id-2`.
- **Server failures:**
  - Contended writes that keep conflicting after retries: `503 SlowDown`.
  - Too few storage nodes reachable: `503 ServiceUnavailable`.
  - Anything else: `500 InternalError`. The details are only in the node's log.

### Subresources

S3 picks an operation by a query parameter (a *subresource*: `?tagging`, `?acl`, …).

- Cairn knows 37 of them: `accelerate`, `acl`, `analytics`, `attributes`, `cors`, `delete`, `encryption`, `intelligent-tiering`, `inventory`, `legal-hold`, `lifecycle`, `location`, `logging`, `metadataConfiguration`, `metadataTable`, `metrics`, `notification`, `object-lock`, `ownershipControls`, `partNumber`, `policy`, `policyStatus`, `publicAccessBlock`, `renameObject`, `replication`, `requestPayment`, `restore`, `retention`, `select`, `session`, `tagging`, `torrent`, `uploadId`, `uploads`, `versioning`, `versions`, `website`.
- A request naming one that isn't implemented **for its method** gets `501 NotImplemented` "the X subresource is not implemented for M requests". It is never served as the plain operation, which could overwrite or delete data.
- This check runs after authentication and before authorization, so anonymous requests get the 501 too. Names are percent-decoded first.
- Other query parameters (such as the SDKs' `x-id`) are ignored.
- `?attributes` on an object with a method other than GET is `405 MethodNotAllowed` with `Allow: GET` (probed). On a bucket, `?attributes` is ignored, which makes the request a listing (probed).

### Names and keys

- **Well-formedness:** the path and every query value must percent-decode to valid UTF-8 without NUL. Otherwise `400 InvalidArgument` "Object name contains unsupported characters." (MinIO's message; S3 has none).
- **Key length:** over 1024 bytes is `400 KeyTooLongError`, on every object operation, reads included.
- **Ordering:** keys sort by UTF-8 bytes, as in S3. Cairn requires a UTF-8 PostgreSQL database for this.

### Missing buckets and keys (403 vs 404)

- **Missing bucket:** if the caller is denied and the bucket doesn't exist, the answer is `404 NoSuchBucket`; bucket names aren't secret. The exception is CreateBucket.
- **Missing key or version on GetObject, HeadObject or GetObjectAttributes:** `403 AccessDenied` to a caller not allowed `s3:ListBucket` on the bucket, so keys can't be discovered by guessing (probed). Callers allowed `s3:ListBucket` get `404`. Tagging, ACL and DeleteObject do not hide missing keys.
- **Cross-account:** a request from another account that the bucket policy allows on an operation reserved to the bucket's own account (its policy) is `405 MethodNotAllowed`, as in S3.

### Request bodies handled whole

XML and JSON bodies (configurations, DeleteObjects, CompleteMultipartUpload, …) may be at most **8 MiB**. Larger is `400 MaxMessageLengthExceeded`. CORS and website configurations are capped at 64 KiB. These bodies are verified against any `Content-MD5`, `x-amz-checksum-*` or `x-amz-content-sha256` they declare.

---

## 5. Operation support matrix

### Service

| Operation | Status | Notes |
| --- | --- | --- |
| ListBuckets | 🟡 | [§6](#listbuckets) |

### Buckets

| Operation | Status | Notes |
| --- | --- | --- |
| CreateBucket | 🟡 | [§6](#createbucket) |
| DeleteBucket | ✅ | [§6](#deletebucket) |
| HeadBucket | 🟡 | No `x-amz-bucket-region`. |
| GetBucketLocation | 🔹 | Always empty, which means `us-east-1`. |
| Get/PutBucketVersioning | 🟡 | No MFA delete. [§12](#12-versioning) |
| Get/Put/DeleteBucketEncryption | 🟡 | [§17](#bucket-default-encryption) |
| Get/Put/DeleteBucketLifecycle(Configuration) | 🟡 | Expiration only; transitions are 501. [§14](#14-lifecycle) |
| Get/Put/DeleteBucketCors | ✅ | [§15](#15-cors) |
| Get/Put/DeleteBucketWebsite | ✅ | [§16](#16-static-website-hosting) |
| Get/Put/DeleteBucketTagging | ✅ | [§11](#11-tags) |
| Get/Put/DeleteBucketPolicy | ✅ | [§19](#19-bucket-policies-and-block-public-access) |
| GetBucketPolicyStatus | ✅ | |
| Get/Put/DeletePublicAccessBlock (bucket) | ✅ | |
| Get/Put/DeletePublicAccessBlock (account, S3 Control) | ✅ | |
| Get/PutObjectLockConfiguration | ✅ | [§13](#13-object-lock) |
| GetBucketAcl | 🔹 | Fixed answer. |
| PutBucketAcl | 🔹 | Only `private`. |
| GetBucketOwnershipControls | 🔹 | Always `BucketOwnerEnforced`. |
| Put/DeleteBucketOwnershipControls | ❌ | 501 |
| GetBucketAccelerateConfiguration | 🔹 | Empty. PUT is 501. |
| GetBucketRequestPayment | 🔹 | `BucketOwner`. PUT is 501. |
| GetBucketLogging | 🔹 | Empty. PUT is 501. |
| GetBucketNotificationConfiguration | 🔹 | Empty. PUT is 501. |
| GetBucketReplication | 🔹 | Always `404 ReplicationConfigurationNotFoundError`. PUT and DELETE are 501. |
| Analytics, inventory, metrics, Intelligent-Tiering configurations | ❌ | 501 for every method. |
| Metadata table and metadata configurations | ❌ | 501 |
| CreateSession (S3 Express) | ❌ | 501 |
| ABAC (Get/PutBucketAbac) | ❌ | `?abac` isn't a recognized subresource, so it is handled as the plain request: GET lists the bucket, PUT is CreateBucket. |

### Listings

| Operation | Status | Notes |
| --- | --- | --- |
| ListObjects (v1) | 🟡 | [§7](#7-listings) |
| ListObjectsV2 | 🟡 | |
| ListObjectVersions | ✅ | |
| ListMultipartUploads | ✅ | |
| ListParts | 🟡 | |

### Objects

| Operation | Status | Notes |
| --- | --- | --- |
| PutObject | 🟡 | [§8](#putobject) |
| GetObject | 🟡 | [§8](#getobject-and-headobject) |
| HeadObject | 🟡 | |
| DeleteObject | 🟡 | No conditional deletes. |
| DeleteObjects | ✅ | |
| CopyObject | 🟡 | |
| GetObjectAttributes | 🟡 | Ignores conditional headers. |
| POST Object (browser form) | 🟡 | |
| Get/Put/DeleteObjectTagging | ✅ | |
| GetObjectAcl | 🔹 | Fixed answer. |
| PutObjectAcl | 🔹 | Only `bucket-owner-full-control`. |
| Get/PutObjectRetention | ✅ | |
| Get/PutObjectLegalHold | ✅ | |
| RestoreObject | ❌ | 501 |
| SelectObjectContent | ❌ | 501 |
| GetObjectTorrent | ❌ | 501 |
| RenameObject | ❌ | 501 |
| Append (`x-amz-write-offset-bytes`) | ⚪ | Ignored: the PUT overwrites the object. |

### Multipart

| Operation | Status | Notes |
| --- | --- | --- |
| CreateMultipartUpload | 🟡 | [§9](#9-multipart-uploads) |
| UploadPart | ✅ | |
| UploadPartCopy | ✅ | |
| CompleteMultipartUpload | 🟡 | |
| AbortMultipartUpload | ✅ | |

### Other S3 APIs

| API | Status |
| --- | --- |
| S3 Control (other than the account public access block): access points, jobs, Storage Lens, Multi-Region Access Points | ❌ |
| IAM | 🟡 [§21](#21-iam-api) |
| STS | 🟡 [§22](#22-sts-api) |

---

## 6. Buckets

### ListBuckets

`GET /`

- **Who sees what:**
  - Anonymous: `403 AccessDenied`.
  - With `s3:ListAllMyBuckets`: every bucket of the caller's account.
  - Without it: the buckets the caller's grants or policies make visible (as MinIO does).
- **Parameters:**
  - `max-buckets`: 1–10000, default 10000. `0` or a non-integer is `400 InvalidArgument`.
  - `continuation-token`: base64url of the last bucket name. An invalid token is `400 InvalidArgument`.
  - `prefix`.
  - `bucket-region` and `encoding-type` are ignored.
- **Response:**
  - `<ListAllMyBucketsResult>`, **without an XML namespace**, unlike every other listing.
  - `Owner` (the fixed `cairn`), then `Buckets/Bucket/{Name, CreationDate}` sorted by name.
  - `ContinuationToken` when more buckets remain, and `Prefix` when one was given.
  - No `BucketRegion`.
- Methods other than GET on `/` are `405`.

### CreateBucket

`PUT /bucket`

- **Names:**
  - 3–63 characters of `[a-z0-9.-]`, starting and ending with a letter or digit.
  - No `..`, and not shaped like an IPv4 address.
  - Not starting `xn--`, `sthree-` or `amzn-s3-demo-`, and not ending `-s3alias`, `--ol-s3`, `.mrap`, `--x-s3` or `--table-s3`.
  - Otherwise `400 InvalidBucketName`.
- **Name already taken:**
  - By the caller's own account: **`200 OK`, and nothing changes**, as us-east-1 answers. `BucketAlreadyOwnedByYou` is never returned.
  - By another account: `409 BucketAlreadyExists`.
- **Body:** never read. `CreateBucketConfiguration`, `LocationConstraint`, `Location` and `Bucket` (directory buckets) are all ignored. No `InvalidLocationConstraint` error is ever returned.
- **Headers:**

  | Header | Status |
  | --- | --- |
  | `x-amz-acl` | 🔹 Only `private`. Anything else: `400 InvalidBucketAclWithObjectOwnership`. Setting it also needs `s3:PutBucketAcl`. |
  | `x-amz-grant-*` | ❌ `400 InvalidBucketAclWithObjectOwnership`. |
  | `x-amz-bucket-object-lock-enabled` | ✅ `true` (case-insensitive) creates the bucket with Object Lock **and versioning enabled**. Also needs `s3:PutBucketObjectLockConfiguration` and `s3:PutBucketVersioning`. |
  | `x-amz-object-ownership` | ⚪ Every bucket is `BucketOwnerEnforced`. |
  | `x-amz-expected-bucket-owner` | ⚪ |

- **Anonymous:** always `403`, even if a policy allowed it.
- **Response:** `200` with `Location: /bucket`.
- **Defaults of a new bucket:**
  - All four Block Public Access flags on, as S3 does since 2023.
  - Unversioned.
  - No default encryption (S3 applies SSE-S3 to every bucket; see [§17](#17-server-side-encryption)).

### DeleteBucket

`DELETE /bucket`

- `204` on success. A missing bucket is `404 NoSuchBucket`.
- `409 BucketNotEmpty` if any version or delete marker remains.
- Incomplete multipart uploads do not block deletion: they are aborted, as in S3.

### HeadBucket

`HEAD /bucket`

- `200` or `404`. It needs `s3:ListBucket`.
- It sends no `x-amz-bucket-region` and no `x-amz-access-point-alias`.

---

## 7. Listings

### Common behavior

- **`max-keys`, `max-uploads`, `max-parts`:**
  - Default 1000. Larger values are capped at 1000 silently, and the response echoes the capped value.
  - A negative, empty or non-integer value is `400 InvalidArgument`.
  - `0` gives an empty page with `IsTruncated=false`, except in ListParts.
- **`delimiter`:** any string, **multi-character delimiters included**. An empty delimiter means none.
- **`encoding-type`:**
  - Only `url` (case-insensitive). Anything else is `400 InvalidArgument`.
  - It encodes keys, prefixes, delimiters and markers, leaving unreserved characters and `/`.
  - ListParts and ListBuckets don't take it.
- **Markers follow MinIO's rule:** an entry is listed only if it sorts after the marker. A marker that names a common prefix therefore resumes **after all of that prefix's keys**.
- **Fixed fields:**
  - `Owner` and `Initiator` are always `<ID>cairn</ID><DisplayName>cairn</DisplayName>`.
  - `StorageClass` is always `STANDARD`.
  - `RestoreStatus` is never returned; `x-amz-optional-object-attributes` is ignored.

### ListObjects (v1) and ListObjectsV2

- **Dialect:** a request is v2 only when `list-type=2`. **Any other `list-type` value gives a v1 listing.**
- **v1:**
  - `marker`.
  - `NextMarker` is returned **whenever the listing is truncated**, with or without a delimiter. S3 returns it only with one.
  - The echoed `Prefix` is not URL-encoded, even with `encoding-type=url`.
- **v2:**
  - `continuation-token` takes precedence over `start-after`. `start-after` is still echoed.
  - The token is base64url of the last returned key or prefix. It is **not opaque**, and an invalid one is `400 InvalidArgument`.
  - `fetch-owner` adds `Owner` only for the exact value `true`.
  - `KeyCount` counts keys plus common prefixes.
- **Contents:**
  - Only current versions; delete markers are excluded.
  - Each entry has `Key`, `LastModified` (with milliseconds) and `ETag`. Multipart objects' ETags look like `"…-N"`.
  - `ChecksumAlgorithm` and `ChecksumType` whenever the object has a checksum. By default every object has one, a CRC64NVME FULL_OBJECT ([§10](#10-checksums-and-payload-integrity)).
  - Then `Size`, `Owner` (v1, or v2 with `fetch-owner`) and `StorageClass`.
- **Missing bucket:** `404 NoSuchBucket`, with an empty `Message`.

### ListObjectVersions

`GET /bucket?versions`

- **Parameters:** `prefix`, `delimiter`, `key-marker`, `version-id-marker`, `max-keys`, `encoding-type`.
- **`version-id-marker`:**
  - It must be a valid version ID (`null`, or 32 characters of `[A-Za-z0-9._-]`); otherwise `400 InvalidArgument`.
  - It is refused without `key-marker`.
  - A marker that no longer exists resumes at the key's newest remaining version.
- **Response:**
  - `Version` and `DeleteMarker` entries interleaved, keys ascending and versions newest first.
  - Each `Version` has `Key`, `VersionId`, `IsLatest`, `LastModified`, `ETag`, checksum fields, `Size`, `StorageClass` and `Owner`.
  - `NextKeyMarker` and `NextVersionIdMarker` only when truncated.

### ListMultipartUploads

`GET /bucket?uploads`

- **Parameters:** `prefix`, `delimiter`, `key-marker`, `upload-id-marker`, `max-uploads`, `encoding-type`.
- **`upload-id-marker`:** ignored without `key-marker`. Otherwise it must be an upload ID (a UUID); if not, `400 InvalidArgument`.
- **Order:** by key, then by upload creation time.
- **Upload entries:** `Key`, `UploadId`, `Initiator`, `Owner`, `StorageClass` and `Initiated`. `ChecksumAlgorithm`/`ChecksumType` appear only if the upload was created with an explicit algorithm.

### ListParts

`GET /bucket/key?uploadId=…`

- **`max-parts`:** 1–1000.
- **`part-number-marker`:** a non-integer value is **silently read as 0**.
- **No `encoding-type`.**
- **Response:**
  - `ChecksumAlgorithm`/`ChecksumType` whenever the upload has an object checksum, **including the default CRC64NVME FULL_OBJECT**. ListMultipartUploads omits these for the same upload.
  - `NextPartNumberMarker` is always present.
  - Each part has `PartNumber`, `LastModified`, `ETag`, `Size` and, if available, `Checksum<ALG>`.
- **Deviation:** with `max-parts=0`, a non-empty upload answers `IsTruncated=true` with the same marker, so a client paging that way would loop.
- **SSE-C uploads:** the key is optional. Without it, part checksums are left out.
- **Errors:** a missing or foreign upload is `404 NoSuchUpload`.

---

## 8. Objects

### Stored metadata

These request headers are stored with the object and returned verbatim on GET/HEAD:

- `Content-Type`: default **`binary/octet-stream`** (probed); not validated.
- `Cache-Control`, `Content-Disposition`, `Content-Language`, `Expires`: stored as given. `Expires` is never parsed as a date.
- `Content-Encoding`: `aws-chunked` is removed from it; nothing is stored if nothing remains.
- `x-amz-meta-*`: the name is lowercased, values are trimmed, and repeated headers are joined with `, `.
- `x-amz-website-redirect-location`: must begin with `/`, `http://` or `https://`, else `400 InvalidRedirectLocation`. It is returned on GET/HEAD (probed), and websites follow it.

Validation:

- **ASCII only:** values must be printable US-ASCII. **Non-ASCII values are refused** with `400 InvalidArgument`. S3 accepts some and sets `x-amz-missing-meta`.
- **Size limit:** user metadata may total **2048 bytes**, else `400 MetadataTooLarge`. This counts each name *after* `x-amz-meta-` plus its value. The standard headers above don't count.

### PutObject

`PUT /bucket/key`

| Request header | Status |
| --- | --- |
| `Content-Length` | ✅ At most 5 GiB, else `400 EntityTooLarge` before the body is read. 🟡 A body without one (chunked transfer encoding) is accepted, and refused as soon as it passes 5 GiB. S3 answers `411`. |
| `Content-Type`, `Cache-Control`, `Content-Disposition`, `Content-Encoding`, `Content-Language`, `Expires`, `x-amz-meta-*`, `x-amz-website-redirect-location` | ✅ Stored (see above). |
| `Content-MD5` | ✅ Verified. Malformed: `400 InvalidDigest`. Mismatch: `400 BadDigest`. Becomes the ETag. |
| `x-amz-content-sha256`, `x-amz-decoded-content-length`, `x-amz-trailer` | ✅ [§10](#10-checksums-and-payload-integrity) |
| `x-amz-checksum-{crc32,crc32c,crc64nvme,sha1,sha256}` | ✅ Verified and stored as the object's full-object checksum. |
| `x-amz-sdk-checksum-algorithm` | ✅ Must match the checksum header or trailer sent. |
| `x-amz-checksum-type` | 🟡 `FULL_OBJECT` only with no checksum or a CRC checksum. `COMPOSITE` is accepted and ignored. Anything else: `400 InvalidArgument` (MinIO's rule; S3 documents none). |
| `x-amz-checksum-algorithm` | ⚪ Not read on PutObject. |
| `x-amz-tagging` | ✅ [§11](#11-tags). Also needs `s3:PutObjectTagging`. |
| `If-None-Match` | ✅ Only `*` (create only if absent). An existing object: `412 PreconditionFailed`. Any other value: `501 NotImplemented` (probed). |
| `If-Match` | ✅ Compare-and-swap against the current ETag. Lists, `W/` and `*` are accepted. No current object: `404 NoSuchKey`. Mismatch: `412`. |
| `If-Modified-Since`, `If-Unmodified-Since` | ⚪ Ignored on writes. |
| `x-amz-acl` | 🔹 Only `bucket-owner-full-control`. **`private` is refused.** Others: `400 AccessControlListNotSupported`. |
| `x-amz-grant-*` | ❌ `400 AccessControlListNotSupported`. |
| `x-amz-storage-class` | ⚪ **Any value is accepted and ignored**. Every object is STANDARD. Policies can test it (`s3:x-amz-storage-class`). |
| `x-amz-server-side-encryption*`, `x-amz-server-side-encryption-customer-*` | ✅ [§17](#17-server-side-encryption) |
| `x-amz-object-lock-mode`, `-retain-until-date`, `-legal-hold` | ✅ [§13](#13-object-lock) |
| `x-amz-write-offset-bytes` | ⚪ Ignored: the object is overwritten whole. |
| `x-amz-expected-bucket-owner`, `x-amz-request-payer` | ⚪ |

Conditional writes are checked before the body streams, and again atomically when the write commits. A write that lands in between makes Cairn re-decide, answering 412 or succeeding. **S3's `409 ConditionalRequestConflict` is never returned.**

Response:

- `200`, with an empty body.
- `ETag`:
  - A plain or SSE-S3 object: the MD5 of the content, or the verified `Content-MD5`.
  - An **SSE-C or SSE-KMS object: random**, not an MD5. S3's ETags for these aren't MD5s either.
- **Always** `x-amz-checksum-<alg>` plus `x-amz-checksum-type: FULL_OBJECT`: the client's algorithm, or CRC64NVME computed by Cairn when the client sent none.
- `x-amz-version-id` in a versioning-enabled bucket.
- The encryption headers ([§17](#17-server-side-encryption)).
- Never sent: `x-amz-expiration`, `x-amz-object-size`, `x-amz-server-side-encryption-bucket-key-enabled`, `x-amz-request-charged`.

### GetObject and HeadObject

`GET` / `HEAD /bucket/key`

| Parameter / header | Status |
| --- | --- |
| `versionId` | ✅ `null` or a 32-character ID, else `400 InvalidArgument`. Unknown: `404 NoSuchVersion`. |
| `partNumber` | ✅ 1–10000, else `400 InvalidArgument` (probed format). With `Range`: `400 InvalidRequest`. See below. |
| `response-content-type`, `-content-language`, `-expires`, `-cache-control`, `-content-disposition`, `-content-encoding` | ✅ Replace those headers on 2xx answers (GET and HEAD). Anonymous requests with any of them: `400 InvalidRequest` (probed). |
| `Range` | 🟡 One range: `bytes=a-b`, `bytes=a-` or `bytes=-n`. **Multiple ranges, or a malformed header, are ignored: the whole object, 200.** `bytes=b-a` with b < a is `416` (RFC 9110 says ignore). A start beyond the end, or any range of an empty object: `416 InvalidRange`, without `Content-Range: bytes */size`. An end past the object is clamped. |
| `If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since` | ✅ RFC 9110 precedence, as S3 documents: a true `If-Match` overrides a false `If-Unmodified-Since`, and `If-None-Match` overrides `If-Modified-Since`. Failures are `412` or `304`. Dates must be RFC 1123, others are ignored, and comparison is to the second. ETag lists, `W/` and `*` are accepted. |
| `x-amz-checksum-mode` | ✅ Exactly `ENABLED` returns the checksum headers. |
| `x-amz-server-side-encryption-customer-*` | ✅ Required for SSE-C objects. |
| `x-amz-server-side-encryption`, `-aws-kms-key-id`, `-context` | ❌ `400 BadRequest` (MinIO's answer). |
| `x-amz-expected-bucket-owner`, `x-amz-request-payer` | ⚪ |

Part reads (`?partNumber=N`), as probed:

- On a multipart object, part N is the Nth part listed at completion, counted from 1.
- Any other object is a single part, so only `partNumber=1` is valid.
- A missing part is `416 InvalidPartNumber`, with `PartNumberRequested` and `ActualPartCount`.
- A part read answers `206` with `Content-Range`, even `partNumber=1` of a non-multipart object.
- Multipart objects also get `x-amz-mp-parts-count`.

Response headers:

- `Accept-Ranges: bytes`, `ETag`, `Content-Type`, `Content-Length` and `Last-Modified`.
- The stored metadata.
- `x-amz-tagging-count` (when > 0).
- `x-amz-version-id` (once the bucket has been versioned).
- Encryption headers.
- The Object Lock headers, only to callers allowed `s3:GetObjectRetention` / `s3:GetObjectLegalHold`.
- Checksum headers, with `x-amz-checksum-mode: ENABLED`:
  - only for a whole-object read or a part read, never for a `Range`;
  - a part of a FULL_OBJECT multipart object has none;
  - a part of a COMPOSITE one has its own.
- **`x-amz-storage-class` is never sent** (S3 omits it for STANDARD too).
- Never sent: `x-amz-expiration`, `x-amz-restore`, `x-amz-replication-status`, `x-amz-missing-meta`, `x-amz-object-lock-*` to callers without permission.

Delete markers:

- When the current version is a delete marker: `404 NoSuchKey`, with `x-amz-delete-marker: true` and `x-amz-version-id`.
- When a named version is a delete marker: `405 MethodNotAllowed`, with `Last-Modified` and the same headers.

Status codes:

- A `304` carries `ETag`, `Last-Modified`, `x-amz-version-id` and (for part reads) `x-amz-mp-parts-count`.
- Data damaged on every replica is refused up front with `500 InternalError`, before any byte is sent.
- A replica failing mid-stream with no other able to continue cuts the stream off.

HeadObject differences:

- It is answered from the catalog, without reading data.
- An SSE-KMS object needs the KMS only for `x-amz-checksum-mode: ENABLED`.

### DeleteObject

`DELETE /bucket/key[?versionId=]`

- **Without `versionId`:**
  - unversioned bucket: removes the object;
  - versioning enabled: adds a delete marker;
  - versioning suspended: replaces the `null` version with a `null` delete marker.
- **With `versionId`:** removes that version for good. It needs `s3:DeleteObjectVersion`.
- **Idempotent:** a missing key or version is still `204`. A missing bucket is `404`.
- **Object Lock:** a locked version is `403 AccessDenied` "Access Denied because object protected by object lock.". [Governance bypass](#13-object-lock) applies.
- **Response:** `204`, with `x-amz-version-id` (once the bucket has been versioned) and `x-amz-delete-marker: true` when a marker was made or removed.
- **Ignored ⚪:**
  - `If-Match`, `x-amz-if-match-last-modified-time` and `x-amz-if-match-size` (S3's conditional deletes);
  - `x-amz-mfa`, `x-amz-expected-bucket-owner`, `x-amz-request-payer`;
  - SSE headers.

### DeleteObjects

`POST /bucket?delete`

- **Checksum:** `Content-MD5` or an `x-amz-checksum-*` header is **required**. Otherwise `400 InvalidRequest` "Missing required header for this request: Content-MD5 OR x-amz-checksum-*". A checksum sent only as a trailer doesn't count.
- **Body:**
  - Up to **1000** `<Object>` entries, else `400 MalformedXML`. Each needs a `<Key>` and may have a `<VersionId>`.
  - `<Quiet>true</Quiet>` is supported.
  - The per-object `<ETag>`, `<LastModifiedTime>` and `<Size>` (conditional deletes) are **ignored**.
  - Invalid XML, no objects, or an empty key: `400 MalformedXML`.
- **Per-key authorization** (`s3:DeleteObject` or `s3:DeleteObjectVersion`):
  - A denied key is reported as `<Error><Code>AccessDenied</Code>`, and the rest proceed.
  - A malformed version ID is reported as `NoSuchVersion`.
  - A locked version is reported as `AccessDenied`. The bypass header is checked per key.
- **Response:** `<DeleteResult>`, with `Deleted` entries (`Key`, `VersionId`, `DeleteMarker`, `DeleteMarkerVersionId`) and `Error` entries. Errors are listed even in quiet mode. Missing keys count as deleted.
- **Ignored:** `x-amz-mfa`, `x-amz-expected-bucket-owner`, `x-amz-request-payer`.

### CopyObject

`PUT /bucket/key` with `x-amz-copy-source`

| Header | Status |
| --- | --- |
| `x-amz-copy-source` | ✅ `[/]bucket/key[?versionId=V]`, percent-encoded. Malformed: `400 InvalidArgument`. A missing source (or its current version a delete marker): `404 NoSuchKey`. A missing version: `404 NoSuchVersion`. A version that is a delete marker: `400 InvalidRequest`. Needs `s3:GetObject` (or `s3:GetObjectVersion`) on the source. |
| `x-amz-metadata-directive` | ✅ `COPY` (default) or `REPLACE`, case-sensitive (probed). Else `400 InvalidArgument`. Under `COPY`, the request's metadata headers are ignored, not even validated. |
| `x-amz-tagging-directive` | ✅ `COPY` (default) or `REPLACE`, case-sensitive. `s3:PutObjectTagging` is needed only for `REPLACE`. |
| `x-amz-copy-source-if-match`, `-if-none-match`, `-if-modified-since`, `-if-unmodified-since` | ✅ Checked against the source. Any failure (including a would-be 304) is `412 PreconditionFailed`. |
| `If-Match`, `If-None-Match` (destination) | ✅ As on PutObject (`If-None-Match` only `*`, else 501). |
| `If-Modified-Since`, `If-Unmodified-Since` (destination) | ⚪ |
| `x-amz-checksum-algorithm` | ✅ The copy's checksum algorithm. Unknown: `400 InvalidArgument`. |
| `x-amz-checksum-*` values, `Content-MD5`, the body | ⚪ |
| `x-amz-copy-source-range` | ⚪ Only UploadPartCopy uses it. |
| `x-amz-storage-class` | ⚪ |
| `x-amz-website-redirect-location` | ✅ Only with `REPLACE` (it is metadata). |
| `x-amz-acl` / `x-amz-grant-*` | 🔹 As on PutObject. |
| `x-amz-object-lock-*` | ✅ The copy's own lock. A copy never inherits the source's. |
| SSE headers, `x-amz-copy-source-server-side-encryption-customer-*` | ✅ [§17](#17-server-side-encryption) |
| `x-amz-source-expected-bucket-owner`, `x-amz-expected-bucket-owner`, `x-amz-request-payer` | ⚪ |

Behavior:

- **Source size:** a source over 5 GiB is `400 InvalidRequest`. Larger objects must be copied with UploadPartCopy.
- **Copying an object onto itself** (no source version) is `400 InvalidRequest` unless the metadata directive is `REPLACE`, the tagging directive is `REPLACE`, or the encryption changes. **A change of storage class or redirect location alone does not count** (S3 accepts those). Copying a named version onto its own key works; that is how a version is restored.
- **Shared data:** where encryption allows, the copy shares the source's data instead of copying it.
- **ETag:**
  - Copies of plain and SSE-S3 objects get the MD5 of the content. A multipart source becomes a single-part copy.
  - Copies between SSE-C and SSE-KMS keep the source's ETag.
- **Checksum:** the copy's checksum is always FULL_OBJECT (as MinIO), in the requested algorithm, else the source's, else CRC64NVME.

Response:

- `<CopyObjectResult>`, **without an XML namespace**, with `LastModified`, `ETag` and the checksum elements.
- `x-amz-version-id`, `x-amz-copy-source-version-id` (when the source bucket is versioned) and the destination's encryption headers.
- No `x-amz-checksum-*` headers.

### GetObjectAttributes

`GET /bucket/key?attributes` (probed)

- **`x-amz-object-attributes`:** required. Several headers or a comma list of `ETag`, `Checksum`, `ObjectParts`, `StorageClass`, `ObjectSize`, case-sensitive.
  - Missing or empty: `400 InvalidRequest`.
  - An unknown name: `400 InvalidArgument`.
- **`x-amz-max-parts`** (default 1000) **and `x-amz-part-number-marker`:** integers.
- **`?partNumber`** as well: `400 InvalidArgument` "Conflicting query string parameters".
- **Permissions:** `s3:GetObjectAttributes` *and* `s3:GetObject`; with `versionId`, their Version variants.
- **Conditional headers are ignored** ⚪. S3 documents them for this operation.
- **Response:**
  - `ETag`, unquoted.
  - `Checksum`, with the type. A composite value loses its `-N`.
  - `ObjectParts`, for multipart objects. Parts and paging are listed only when the checksum is COMPOSITE (probed).
  - `StorageClass`, always `STANDARD`.
  - `ObjectSize`.
  - Headers: `Last-Modified` and `x-amz-version-id`.

### POST Object (browser uploads)

`POST /bucket` with `Content-Type: multipart/form-data`

Any `multipart/form-data` POST is treated as a form upload before anything else is routed. That includes `POST /bucket?delete` with such a body.

Framing:

- **Path:** it must name only the bucket. With a key: `405`.
- **Auth:** an `Authorization` header or `X-Amz-Algorithm` as well: `400 InvalidArgument`.
- **Size:** fields before the file may total **20 KiB**, else `400 MaxPostPreDataLengthExceededError`.
- **Fields:** names are case-insensitive. A duplicate field is `400 MalformedPOSTRequest`. Fields after the file are never read.
- **Filename:** `${filename}` in any field becomes the file's base name.
- **Content type:** the file part's own `Content-Type` is ignored. The object's comes from the `Content-Type` field.

Signature:

- SigV4 only: `policy`, `x-amz-algorithm`, `x-amz-credential`, `x-amz-date`, `x-amz-signature`, and optionally `x-amz-security-token`.
- A form with none of the signing fields is anonymous; only a bucket policy can allow it, and no POST policy is checked.
- There is **no clock-skew check**: only the policy's `expiration` limits a form's life.

Policy document:

- **Fields:** `expiration` and `conditions` only, else `400 InvalidPolicyDocument`. A reached expiration: `403 AccessDenied` "Policy expired.".
- **Conditions:**
  - `{"field":"value"}` and `["eq","$field","value"]`.
  - `["starts-with","$field","prefix"]`, only on `key`, `acl`, `cache-control`, `content-type`, `content-disposition`, `content-encoding`, `content-language`, `expires`, `success_action_redirect`, `redirect` and `x-amz-meta-*`. On `Content-Type`, every comma-separated item must match.
  - `["content-length-range", min, max]`. Numeric strings are accepted too (as MinIO). It is enforced while streaming: `400 EntityTooLarge` or `EntityTooSmall`.
- **Every field needs a condition**, except `x-amz-signature`, `file`, `policy` and `x-ignore-*`. The three SSE-C fields are also exempt (as MinIO). Uncovered fields: `403 AccessDenied` "Extra input fields".

Recognized fields:

- `key` (required), `content-type`, `cache-control`, `content-disposition`, `content-encoding`, `content-language`, `expires`, `x-amz-meta-*`.
- `content-md5` and `x-amz-checksum-*`. `x-amz-checksum-algorithm` maps to `x-amz-sdk-checksum-algorithm`. `x-amz-checksum-type`.
- The SSE and SSE-C fields, and the Object Lock fields.
- `acl` (only `bucket-owner-full-control`).
- `tagging`: an XML `<Tagging>` document.
- `x-amz-storage-class` (ignored).
- `success_action_redirect` / `redirect` and `success_action_status`.

Ignored fields:

- `x-amz-website-redirect-location` (S3 accepts it).
- A field literally named `x-amz-acl`.
- `x-amz-grant-*`, `x-amz-expected-bucket-owner`, and anything else unknown.
- The Object Lock checksum requirement of PutObject is not applied to forms.

Response:

- `success_action_redirect` (an absolute http(s) URL): `303` to `url?bucket=…&key=…&etag=…`.
- Else `success_action_status`:
  - `200`: empty;
  - `201`: `<PostResponse>` with `Location`, `Bucket`, `Key` and `ETag`, without a namespace;
  - **anything else, or none: `204`**.
- A `Location` header with the object's URL, plus PutObject's headers.

---

## 9. Multipart uploads

### Identifiers and limits

| Limit | Value |
| --- | --- |
| Upload IDs | Lowercase UUIDv7 (time-ordered). A non-UUID ID, or one belonging to another bucket or key: `404 NoSuchUpload`. |
| Part numbers | 1–10000, else `400 InvalidArgument` "partNumber must be an integer in 1..=10000". Unlike GET `?partNumber`, this error has no `ArgumentName`/`ArgumentValue`. |
| Part size | At most 5 GiB (`400 EntityTooLarge`). At least 5 MiB, except the last (`400 EntityTooSmall`, checked at completion). Sizes are of the plaintext. |
| Object size | At most 5 TiB (`400 EntityTooLarge`). |
| Re-uploading a part number | Replaces the earlier part atomically; the last write wins. |

### CreateMultipartUpload

`POST /bucket/key?uploads`

- **Headers captured for the object:** `Content-Type`, the stored metadata, `x-amz-tagging`, encryption (or the bucket's default), Object Lock headers and ACL headers. These are validated as on PutObject.
- **Checksums:**
  - `x-amz-checksum-algorithm` takes CRC32, CRC32C, CRC64NVME, SHA1 or SHA256, case-insensitive.
  - `x-amz-checksum-type` defaults to COMPOSITE. **CRC64NVME is always made FULL_OBJECT**, even if COMPOSITE is asked for (as MinIO).
  - SHA1/SHA256 with FULL_OBJECT, a type without an algorithm (FULL_OBJECT), or an unknown value: `400 InvalidArgument`.
- **Default checksum:** an upload created without an algorithm still gets a **CRC64NVME FULL_OBJECT** object checksum. SSE-C uploads are the exception.
- **Response:** `<InitiateMultipartUploadResult>` with `Bucket`, `Key` and `UploadId`, the encryption headers, and the checksum headers when an algorithm was requested.
- **Never sent:** `x-amz-abort-date` and `x-amz-abort-rule-id`, even when a lifecycle abort rule applies.

### UploadPart

`PUT /bucket/key?partNumber=N&uploadId=U`

- **Body integrity:** `Content-MD5`, `x-amz-content-sha256`, aws-chunked (all variants), `x-amz-checksum-*` and `x-amz-sdk-checksum-algorithm` are verified as on PutObject.
- **Checksums against the upload's algorithm:**
  - If the upload has an algorithm, each part must declare it, as a header or trailer. Otherwise `400 InvalidRequest` "Checksum Type mismatch…".
  - In a FULL_OBJECT upload, parts may omit it, and Cairn computes it (probed).
  - An upload without an algorithm accepts, verifies and echoes any part checksum.
- **Refused headers:**
  - `x-amz-tagging`: `400 InvalidArgument` "The specified header is not valid in this context".
  - `x-amz-server-side-encryption*`: `501 NotImplemented` (as MinIO). SSE-C uploads need the key on every part.
- **Response:**
  - `ETag`: the part's MD5 (or the verified `Content-MD5`); for SSE-C and SSE-KMS parts, a random value.
  - The part's checksum header (probed).
  - The encryption headers.

### UploadPartCopy

`PUT …?partNumber&uploadId` with `x-amz-copy-source`

- **`x-amz-copy-source`:** as for CopyObject.
- **`x-amz-copy-source-range`:**
  - Strictly `bytes=first-last` with first ≤ last, else `400 InvalidArgument`.
  - Past the end: `416 InvalidRange`.
  - Without a range, the whole source is copied.
  - A range (or source) over 5 GiB: `400 InvalidArgument`.
- **Source conditions:** `x-amz-copy-source-if-*` are checked against the source (`412`).
- **Encryption:** SSE-C on either side is supported, with the source's key in the `x-amz-copy-source-…` headers.
- **Checksum:** the upload's algorithm is used, and the request's `x-amz-checksum-algorithm` is ignored. The result shows it only if the upload was created with an explicit algorithm.
- **Response:**
  - `<CopyPartResult>`, **without an XML namespace**, with `LastModified` (the source version's), `ETag` and an optional checksum.
  - `x-amz-copy-source-version-id`.

### CompleteMultipartUpload

`POST /bucket/key?uploadId=U`

- **Body:**
  - Any root element is accepted.
  - Every `Part` needs `PartNumber` and `ETag`; quotes are trimmed.
  - Per-part `Checksum<ALG>` elements are read.
  - Unparsable or empty: `400 MalformedXML`.
- **Order:** parts must be in strictly ascending order, so duplicates are refused too: `400 InvalidPartOrder`. 🟡 This is checked before the upload is looked up, so a missing upload with misordered parts gets InvalidPartOrder, not NoSuchUpload.
- **Part matching:** each listed part must exist with exactly that ETag, else `400 InvalidPart`. Parts staged but not listed are discarded.
- **Part checksums:**
  - A COMPOSITE upload needs every part's checksum, else `400 InvalidRequest`.
  - A FULL_OBJECT upload may omit them (probed).
  - A listed checksum in the upload's algorithm must match (`InvalidPart`).
- **Object checksum:**
  - The request's `x-amz-checksum-<alg>` header, if present, is the **whole object's** checksum. With the optional `x-amz-checksum-type`, it must match the computed one (`400 BadDigest`). A COMPOSITE claim may leave off `-N`.
  - FULL_OBJECT checksums are combined from the part CRCs without re-reading data. COMPOSITE is `base64(H(part checksums))-N`.
- **`x-amz-mp-object-size`:** validated, and must equal the actual size, else `400 InvalidRequest` (probed messages).
- **Size limits:** a non-last part under 5 MiB is `EntityTooSmall`. A total over 5 TiB is `EntityTooLarge`.
- **Conditional writes:** `If-Match` and `If-None-Match` are honored (`412`; `If-Match` with no object: `404`). 🟡 Unlike PutObject, an `If-None-Match` with an ETag (not `*`) is accepted and evaluated.
- **SSE-C:** the key is needed only if the upload is SSE-C *and* has an explicit checksum algorithm.
- **Refused:** `x-amz-tagging` gets `400`. SSE headers get `501`.
- **ETag:** `"hex(MD5(binary part ETags))-N"`.
- **Response:**
  - `<CompleteMultipartUploadResult>` with `Bucket`, `Key`, `ETag` and the checksum elements (by default `ChecksumCRC64NVME` and `ChecksumType FULL_OBJECT`). **There is no `<Location>` element.**
  - `x-amz-version-id` and the encryption headers.
- **Retries:** a retry after success returns the original result, if the version it made is still current.

### AbortMultipartUpload

`DELETE …?uploadId=U`

- `204` on success. A missing upload is `404 NoSuchUpload`.
- `x-amz-if-match-initiated-time` is ignored.

### Cleaning up incomplete uploads

- Incomplete uploads are removed only by a lifecycle `AbortIncompleteMultipartUpload` rule ([§14](#14-lifecycle)), applied by the daily sweep, or when the bucket is deleted.
- Without such a rule, they stay until aborted.

---

## 10. Checksums and payload integrity

### `x-amz-content-sha256`

| Value | Status |
| --- | --- |
| A hex SHA-256 | ✅ Verified as the body arrives. Mismatch: `400 XAmzContentSHA256Mismatch`, with `ClientComputedContentSHA256`/`S3ComputedContentSHA256`. |
| `UNSIGNED-PAYLOAD` | ✅ |
| `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` | ✅ aws-chunked; every chunk signature is verified. |
| `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` | ✅ Also verifies the trailer checksum and `x-amz-trailer-signature`. |
| `STREAMING-UNSIGNED-PAYLOAD-TRAILER` | ✅ aws-chunked with a trailer checksum. |
| `STREAMING-UNSIGNED-PAYLOAD` (without trailer) | ❌ `400 InvalidArgument`. |
| `STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD[-TRAILER]` (SigV4A) | ❌ `400 InvalidArgument`. |
| Missing | ❌ `400 InvalidRequest` on header-signed requests. Presigned and anonymous requests are treated as `UNSIGNED-PAYLOAD`. |

### Streaming (aws-chunked)

- **Framing:** only `x-amz-content-sha256` decides aws-chunked framing. `Content-Encoding: aws-chunked` alone does not.
- **Decoded length:** `x-amz-decoded-content-length` is required, else `411 MissingContentLength`. A decoded length that differs from it is `400 IncompleteBody`.
- **Chunk size:** a signed chunk smaller than 8 KiB, other than the last, is `400 InvalidChunkSizeError`.
- **Signatures and framing:** a bad chunk or trailer signature is `403 SignatureDoesNotMatch`. Bad framing is `400 IncompleteBody`.
- **Trailers:**
  - `x-amz-trailer` must name one checksum header; otherwise `400 InvalidRequest`.
  - A missing or malformed trailer is `400 MalformedTrailerError`. A mismatch is `400 BadDigest`.
- **Auth:** a signed streaming body on a presigned or anonymous request is `403 AccessDenied`.

### Content-MD5 and additional checksums

- **`Content-MD5`:** must be base64 of 16 bytes (`400 InvalidDigest`), and must match (`400 BadDigest`).
- **Algorithms:** `x-amz-checksum-crc32`, `-crc32c`, `-crc64nvme`, `-sha1` and `-sha256` (✅). The newer MD5, SHA-512 and XXHash algorithms are not supported.
- **One at a time:** more than one checksum header is `400 InvalidRequest`. A malformed value is `400 InvalidRequest`. A mismatch is `400 BadDigest`.
- **`x-amz-sdk-checksum-algorithm`:** must have a matching header or trailer. Otherwise `400 InvalidRequest`, or `400 BadDigest` for a different algorithm.
- **Every object has a checksum:** objects written by PutObject, POST, CopyObject or a default multipart upload get a **CRC64NVME FULL_OBJECT checksum** when the client sends none. S3 does the same for new objects.
- **Composite checksums:** these exist only for multipart uploads created with CRC32, CRC32C, SHA1 or SHA256 and type COMPOSITE.

### Requests that require a checksum

`Content-MD5` or an `x-amz-checksum-*` header is required, else `400 InvalidRequest` "Missing required header for this request: Content-MD5 OR x-amz-checksum-*", on:

- DeleteObjects
- PutBucketLifecycleConfiguration, PutBucketCors, PutBucketWebsite, PutBucketTagging
- PutPublicAccessBlock (bucket)
- PutObjectLockConfiguration, PutObjectRetention, PutObjectLegalHold
- PutObject of an object that will be retained, by its own headers or by the bucket's default retention. Here `x-amz-sdk-checksum-algorithm`, or a checksum trailer, also counts.

Not required: PutBucketVersioning, PutBucketPolicy (probed), PutBucketEncryption, PutBucketAcl, PutObjectTagging, S3 Control's PutPublicAccessBlock.

---

## 11. Tags

### Object tags

- **Limits:** at most **10** per object. Keys are 1–128 and values 0–256 UTF-16 code units, of `[\p{L}\p{Z}\p{N}_.:/=+\-@]`. Keys may not begin with `aws:`.
- **Errors** (probed messages):
  - more than 10: `400 BadRequest`;
  - invalid characters or lengths, a duplicate key, or `aws:`: `400 InvalidTag`.
- **`x-amz-tagging` header** (PutObject, CreateMultipartUpload, CopyObject with `REPLACE`):
  - URL query form; `+` is a space.
  - A malformed value or duplicate key: `400 InvalidArgument`.
  - On UploadPart or CompleteMultipartUpload: `400 InvalidArgument` "The specified header is not valid in this context".
- **GetObjectTagging:** `<Tagging><TagSet>`, sorted by key, with `x-amz-version-id`.
- **PutObjectTagging:**
  - The body checksum is **not** required.
  - Tags are replaced in place: no new version, and the ETag and `Last-Modified` stay the same.
  - Answers `200`.
- **DeleteObjectTagging:** `204`.
- **Version and key handling:**
  - `versionId` is supported; it needs the `…VersionTagging` actions.
  - A delete marker gets `405 MethodNotAllowed` with `Allow: DELETE` (as observed on S3).
  - SSE-C objects' tags need no key (as observed on S3).
- `x-amz-tagging-count` is returned on GET/HEAD when there are tags.

### Bucket tags

- **Limits:** at most **50** (`400 BadRequest`). The same character and length rules; `aws:` keys get "System tags cannot be added/updated by requester".
- **PutBucketTagging:**
  - It requires a body checksum and answers `204`.
  - An empty `TagSet` removes the tags (observed).
- **GetBucketTagging:** when there are no tags, `404 NoSuchTagSet`.
- **DeleteBucketTagging:** `204`.

Tags are not available as policy condition keys on S3 requests ([§20](#condition-keys)). They are stored unencrypted, whatever the object's encryption.

---

## 12. Versioning

- **States:** unversioned, `Enabled` and `Suspended`. A bucket can't return to unversioned.
- **PutBucketVersioning:**
  - `Status` must be `Enabled` or `Suspended`, case-sensitive; otherwise `400 MalformedXML`. No `Status` is a no-op.
  - `MfaDelete=Enabled` is `501 NotImplemented`. `x-amz-mfa` is ignored.
  - No body checksum is required.
  - Suspending a bucket with Object Lock is `409 InvalidBucketState`.
- **GetBucketVersioning:** empty when unversioned, otherwise `Status`. `MfaDelete` is never returned.
- **Version IDs:** 32 characters of `[A-Za-z0-9._-]` (192 random bits), or `null`. Anything else in a request is `400 InvalidArgument` "Invalid version id specified".
- **The null version:** in an unversioned or suspended bucket, a write replaces the `null` version.
  - **Writes report no `x-amz-version-id` for the null version**, in either state.
  - Reads and deletes in a suspended bucket report `null`.
- **Deletes:** see [DeleteObject](#deleteobject). A named delete removes the version for good and makes the newest remaining version current.
- **Reporting:** `x-amz-version-id` is reported once the bucket has been versioned (enabled or suspended).

---

## 13. Object Lock

### Enabling

- **At creation:** `x-amz-bucket-object-lock-enabled: true` on CreateBucket, which also enables versioning.
- **Later:** PutObjectLockConfiguration on a bucket whose versioning is `Enabled`. Otherwise `409 InvalidBucketState`.
- **Permanence:** Object Lock can't be turned off, and versioning can't be suspended afterwards.
- `x-amz-bucket-object-lock-token` is ignored.

### Bucket configuration

- **GetObjectLockConfiguration:** returns `ObjectLockEnabled` and the optional `Rule/DefaultRetention`. When Object Lock isn't enabled: `404 ObjectLockConfigurationNotFoundError`.
- **PutObjectLockConfiguration:**
  - A body checksum is required. It answers `200`.
  - `ObjectLockEnabled=Enabled` is required.
  - Leaving out `Rule` **removes** the default retention.
  - `Mode` must be `GOVERNANCE` or `COMPLIANCE`, uppercase.
  - Exactly one of `Days` (1–36500) or `Years` (1–100).
  - Out of range: `400 InvalidArgument`. Otherwise malformed: `400 MalformedXML`.

### Per-object lock

- **Headers** on PutObject, CopyObject, CreateMultipartUpload, and the POST form fields:
  - `x-amz-object-lock-mode` and `x-amz-object-lock-retain-until-date` must come together. The date is ISO 8601, in the future, and kept to the millisecond.
  - `x-amz-object-lock-legal-hold` is `ON` or `OFF`.
  - Errors are `400 InvalidArgument`. Any lock header on a bucket without Object Lock is `400 InvalidRequest`.
- **Default retention:** applies when a write asks for no retention. Retain-until is the write time plus the default period.
- **Copies:** a copy never inherits its source's lock.
- **Checksum required** when an object will be retained (or held): `400 InvalidRequest` otherwise.
- **Permissions:** writing a retention or a hold also needs `s3:PutObjectRetention` / `s3:PutObjectLegalHold`.
- **Reads:** GET/HEAD return `x-amz-object-lock-mode`, `-retain-until-date` and `-legal-hold` only to callers allowed `s3:GetObjectRetention` / `s3:GetObjectLegalHold`.

### Retention and legal-hold operations

- **GetObjectRetention / GetObjectLegalHold:**
  - With nothing set: `404 NoSuchObjectLockConfiguration`.
  - A bucket without Object Lock: `400 InvalidRequest`.
  - A delete marker: `405` with `Allow: DELETE`.
- **PutObjectRetention / PutObjectLegalHold:**
  - A body checksum is required.
  - The body is read *before* authorization, so policies can test the values it asks for.
  - A retention body with neither `Mode` nor `RetainUntilDate` removes the retention, which needs bypass under GOVERNANCE.
  - Success is `200`, **without `x-amz-version-id`**.
- **Changing a retention still in force:**
  - **COMPLIANCE** may only be extended. Nobody can bypass it, and the database enforces it too.
  - **GOVERNANCE** may be extended, or changed to COMPLIANCE with an equal or later date. Shortening or removing it needs `x-amz-bypass-governance-retention: true` *and* `s3:BypassGovernanceRetention`.
  - A violation is `403 AccessDenied` "Access Denied because object protected by object lock.".
- **Deleting locked versions:**
  - Deleting a held or retained version is refused the same way. GOVERNANCE can be bypassed on DeleteObject and on DeleteObjects (per key).
  - Deleting without a version ID still adds a delete marker.
- **Lifecycle rules never remove locked versions.**
- **Policy condition keys:** `s3:object-lock-mode`, `s3:object-lock-retain-until-date`, `s3:object-lock-remaining-retention-days` and `s3:object-lock-legal-hold`.
- **Event-based holds** (`s3:object-lock-event-hold*`) are not supported.

---

## 14. Lifecycle

### Configuration API

- **PUT** `?lifecycle`: requires a body checksum. It replaces the whole configuration, answers `200`, and starts a sweep.
- **GET:** returns the configuration, or `404 NoSuchLifecycleConfiguration`.
- **DELETE:** `204`.
- **IAM actions:** `s3:GetLifecycleConfiguration` and `s3:PutLifecycleConfiguration`. DELETE uses the Put action.

### Supported rule elements

| Element | Status |
| --- | --- |
| `ID` | ✅ ≤ 255. Generated if absent. Unique, else `400 InvalidArgument`. |
| `Status` | ✅ `Enabled` or `Disabled`. |
| `Prefix` (rule-level, legacy) | ✅ GET writes it back as `<Filter><Prefix>`. |
| `Filter` with `Prefix`, `Tag`, `ObjectSizeGreaterThan`, `ObjectSizeLessThan`, `And` | ✅ An empty `<Filter/>` matches everything. Tag keys and values are length-checked, but not character-checked. |
| `Expiration/Days` | ✅ ≥ 1. |
| `Expiration/Date` | ✅ Must be midnight UTC. |
| `Expiration/ExpiredObjectDeleteMarker` | ✅ Not with Days or Date, nor with a Tag filter. |
| `NoncurrentVersionExpiration/NoncurrentDays` | ✅ ≥ 1. |
| `NoncurrentVersionExpiration/NewerNoncurrentVersions` | ✅ 1–100. |
| `AbortIncompleteMultipartUpload/DaysAfterInitiation` | ✅ ≥ 1. Not with Tag or size filters. |
| `Transition`, `NoncurrentVersionTransition` | ❌ `501 NotImplemented`: Cairn has one storage class. |
| `x-amz-transition-default-minimum-object-size` | ⚪ |

Other validation:

- At most 1000 rules.
- At least one action per rule.
- Unknown elements are `400 MalformedXML`.
- Errors use S3's codes: MalformedXML, InvalidArgument and InvalidRequest.

### Evaluation

- **Timing:** rules are applied by a background **sweep of each bucket once a day**, never at read time. An expired object stays readable until the sweep reaches it.
- **Rate:** the sweep is limited by the cluster setting `lifecycle-rate` (default 1,000,000 versions read per hour; `0` pauses it).
- **Day counting:** days are counted as S3 counts them: to the next midnight UTC after N days.
- **What each action does:**
  - Expiring a current version acts like DeleteObject: a delete marker in a versioned bucket.
  - Noncurrent days count from when the version became noncurrent.
  - `ExpiredObjectDeleteMarker` removes a delete marker that is the key's only version.
- **Locked versions:** Object Lock is never bypassed.
- **Headers never sent:** `x-amz-expiration`, `x-amz-abort-date` and `x-amz-abort-rule-id`.

---

## 15. CORS

### Configuration

- **PUT** `?cors`: requires a body checksum. Bodies are limited to 64 KiB. It answers `200`.
- **GET:** returns the configuration, or `404 NoSuchCORSConfiguration`.
- **DELETE:** `204`.
- **Rules:** at most **100**, each with `ID` (≤ 255), `AllowedOrigin`+, `AllowedMethod`+, `AllowedHeader`*, `ExposeHeader`* and `MaxAgeSeconds`.
- **Validation:**
  - `AllowedMethod` must be one of `GET`, `PUT`, `HEAD`, `POST`, `DELETE`, case-sensitive.
  - Origins and allowed headers may contain at most one `*`.
  - `ExposeHeader` may contain none.
  - Values must be valid HTTP header values or names.
  - Negative `MaxAgeSeconds` is accepted.
  - Errors are `400 InvalidRequest` or `400 MalformedXML`.

### Preflight requests

`OPTIONS /bucket[/key]`, never authenticated.

- **Missing `Origin`, or a bad `Access-Control-Request-Method`:** `400 BadRequest`.
- **No configuration, or no matching rule:** `403 AccessForbidden`, with `Method` and `ResourceType`.
- **Matching:** the first rule whose origin, method (exact, case-sensitive) and *every* requested header match.
- **Answer** (`200`):
  - `Access-Control-Allow-Origin`: the origin, or `*` for a bare `*` rule.
  - `Access-Control-Allow-Credentials: true`, except for `*`.
  - `Access-Control-Allow-Methods`: **all of the rule's methods**.
  - `Access-Control-Allow-Headers`: the requested headers echoed.
  - `Access-Control-Expose-Headers` and `Access-Control-Max-Age`.
  - `Vary`.

### Actual requests

- **Scope:** any request with an `Origin` to a bucket that has a configuration, websites included, whatever the response status (errors too).
- **Headers:** `Vary`, plus the allow, expose and max-age headers when a rule matches.
- **Access:** CORS grants no access by itself.
- **Scope of configuration:** there is no cluster-wide CORS; it is configured per bucket only.

---

## 16. Static website hosting

### Configuration

- **PUT** `?website`: requires a body checksum (64 KiB at most) and answers `200`.
- **GET:** returns the configuration, or `404 NoSuchWebsiteConfiguration`.
- **DELETE:** `204`.
- **IAM actions:** `s3:GetBucketWebsite`, `s3:PutBucketWebsite` and `s3:DeleteBucketWebsite`.

Supported elements:

- `IndexDocument/Suffix`: required unless redirecting all requests; no `/`.
- `ErrorDocument/Key`.
- `RedirectAllRequestsTo/{HostName, Protocol}`: exclusive of all the others.
- `RoutingRules`, up to 50:
  - `Condition/{KeyPrefixEquals, HttpErrorCodeReturnedEquals (400–599)}`;
  - `Redirect/{HostName, HttpRedirectCode (301–399), Protocol, ReplaceKeyPrefixWith | ReplaceKeyWith}`.
- Host names are limited to `[A-Za-z0-9.\-_:[]]`.
- These rules follow AWS's documentation, but haven't been probed against S3 yet.

### Endpoints

- `bucket.<--website-domain>`, and custom domains when `--domain` is set ([§2](#addressing)).
- Websites are served on the S3 API port.
- HTTPS is up to the proxy. The peer endpoint's `GET /tls/ask?domain=` answers Caddy's on-demand TLS check for the API domain, existing buckets' hosts and website hosts.

### Serving

- **Methods:** GET and HEAD; OPTIONS is a CORS preflight. Others get a `405` HTML page.
- **Access:**
  - Requests are **always anonymous**, whatever they carry.
  - Objects must be public by bucket policy (`s3:GetObject` to `*`), subject to Block Public Access.
  - A missing key is shown as `403` unless the policy also allows `s3:ListBucket`.
- **Order of evaluation:**
  1. `RedirectAllRequestsTo`: `301`.
  2. Routing rules without an error-code condition, before fetching.
  3. The index document for `/` and keys ending in `/`.
  4. An object with `x-amz-website-redirect-location`: `301` to it.
  5. A missing `key` whose `key/<index>` exists: `302` to `key/`.
  6. Routing rules with an error-code condition.
  7. For 4XX errors, the error document (which must be public), with the error's status.
  8. Otherwise, S3-style HTML error pages, with `x-amz-error-code`, `x-amz-error-message` and `x-amz-error-detail-*` headers.
- **Requests:** the query string is ignored and not kept through redirects. Range and conditional headers work on objects.
- **Responses:** `x-amz-*` headers are removed, except `x-amz-meta-*` and `x-amz-request-id`.

---

## 17. Server-side encryption

### How encryption works in Cairn

- **Supported modes:** SSE-C, SSE-KMS and SSE-S3. Each object has a random 256-bit key, sealed under the customer's key, a KMS data key, or Cairn's SSE-S3 data key.
- **Cipher:** **XChaCha20-Poly1305**, in 64 KiB segments, even though the API calls SSE-C and SSE-S3 `AES256`.
- **What isn't encrypted:** key names, sizes, times, `Content-Type`, user metadata and tags.
- 🟡 **Objects written without encryption are not encrypted at rest.** S3 encrypts every object with SSE-S3 by default since 2023. In Cairn, buckets have no default encryption unless one is set, and GetBucketEncryption answers `404 ServerSideEncryptionConfigurationNotFoundError` (as S3 did before, and as MinIO does).

### SSE-C

- **Headers:** `x-amz-server-side-encryption-customer-algorithm` (exactly `AES256`), `-customer-key` (base64 of 32 bytes) and `-customer-key-MD5`. For a copy's source: `x-amz-copy-source-server-side-encryption-customer-*`.
- **Validation, in order** (all `400`):
  1. Missing algorithm: `InvalidArgument`.
  2. Another algorithm: `InvalidEncryptionAlgorithmError`.
  3. Missing key or MD5: `InvalidArgument`.
  4. Bad key: `InvalidArgument`.
  5. MD5 mismatch: `InvalidArgument`.
  6. Not over HTTPS: `InvalidRequest`.
- **HTTPS:** taken from a trusted proxy's `X-Forwarded-Proto`/`Forwarded`. `--allow-sse-c-over-http` lifts the requirement.
- **Where the key is needed:**
  - Required for reading SSE-C objects: GetObject, HeadObject, GetObjectAttributes. A missing or wrong key is `400 InvalidRequest`.
  - Every UploadPart of an SSE-C upload needs it.
  - CompleteMultipartUpload needs it only when the upload has a checksum algorithm.
  - ListParts takes it optionally.
  - Object tagging never needs it.
- **Misplaced keys:** a key sent for an unencrypted, SSE-KMS or SSE-S3 object is `400 InvalidRequest`.
- **Malformed headers:** these are refused on any object request, DELETE included.
- **Response:** the algorithm and key MD5 are echoed only when the request carried the key.

### SSE-KMS

- **KMS backend:** an **OpenBao or HashiCorp Vault Transit** engine (`--kms-address`). There is no AWS KMS API, KMIP or local key. Cairn only calls `datakey/plaintext` and `decrypt`, so it never creates keys. Without a KMS: `501 NotImplemented`.
- **Headers:** `x-amz-server-side-encryption: aws:kms`, `x-amz-server-side-encryption-aws-kms-key-id`, `x-amz-server-side-encryption-context` and `x-amz-server-side-encryption-bucket-key-enabled`.
- **Key IDs:**
  - `<transit-mount>/<key>`, or `<key>` alone for the `transit` mount. An `arn:aws:kms:` prefix is stripped.
  - Real AWS key ARNs are refused (`400 InvalidRequest`), and **aliases have no meaning**: `alias/x` is mount `alias`, key `x`.
  - Responses name the key as `arn:aws:kms:<mount>/<key>`.
- **No default key:** 🟡 `aws:kms` without a key ID is `400 InvalidArgument`. There is no `aws/s3` managed key.
- **Encryption context:**
  - It must be base64 JSON of string pairs.
  - Cairn adds `aws:s3:arn`. A client-supplied `aws:s3:arn` must be the object's own ARN. A case variant of it is `400 KMS.ValidationException` (probed).
  - The data key is bound to the context and object.
- **Bucket keys:** `bucket-key-enabled` is validated (`true`/`false`) and otherwise ignored, never echoed.
- **Permissions:**
  - Not IAM `kms:*` actions. Cairn calls the KMS **as the requesting role**, and OpenBao's policies decide.
  - A request without a role (the console's root) is `403`.
  - The KMS refusing is `403 AccessDenied`. An unknown key is `400 KMS.NotFoundException`. The KMS being unavailable is `503`.
- **Reads:** HeadObject doesn't need the KMS, unless checksums are asked for.

### SSE-S3

- **Enabling:** with a KMS (`--kms-address`) and `--kms-sse-s3-key <mount>/<key>`. Without either, `x-amz-server-side-encryption: AES256` is `501 NotImplemented`. It is never silently stored unencrypted.
- **Behavior:**
  - Cairn uses the key as itself. Each node uses one data key per hour of writes.
  - SSE-S3 objects' ETags are MD5s, as in S3. They are stored sealed, so GET, HEAD and listings of them need the KMS, or a cached data key.

### DSSE-KMS

❌ `aws:kms:dsse` is refused: `400 InvalidArgument` on objects, `400 MalformedXML` in bucket defaults.

### Where encryption headers are accepted

- **Object writes:** PutObject, POST Object, CopyObject (the destination) and CreateMultipartUpload.
- **Reads:** on GET and HEAD, `x-amz-server-side-encryption`, `-aws-kms-key-id` and `-context` are `400 BadRequest`. S3 answers `400 InvalidArgument`.
- **Other writes:** on UploadPart, UploadPartCopy, CompleteMultipartUpload and `PUT ?acl`, they are `501 NotImplemented` (as MinIO).
- **Deletes:** on DELETE they are ignored.
- **Echoed:** the encryption headers are echoed on PUT, GET, HEAD, CopyObject, CreateMultipartUpload, UploadPart, UploadPartCopy and CompleteMultipartUpload. GetObjectAttributes echoes none.

### Copies

- **Destination encryption:** the request's, else the bucket default, else none. Copying an encrypted object without destination headers to a bucket without a default makes an **unencrypted** copy.
- **Shared data:** copies between SSE-C and SSE-KMS share the data and only reseal the object key, so re-keying by copy doesn't re-encrypt the data.

### Bucket default encryption

- **PutBucketEncryption:**
  - One `Rule`, with `ApplyServerSideEncryptionByDefault/{SSEAlgorithm (AES256 | aws:kms), KMSMasterKeyID (required with aws:kms)}` and `BucketKeyEnabled`.
  - Unknown elements, such as `BlockedEncryptionTypes`, are silently ignored.
  - Malformed: `400 MalformedXML`. No KMS: `501` (for `AES256` too). An unknown key: `400 KMS.NotFoundException`.
  - A key the caller may not use is accepted; writes then fail.
  - No checksum is required.
- **GetBucketEncryption:** returns the rule, or `404 ServerSideEncryptionConfigurationNotFoundError`.
- **DeleteBucketEncryption:** `204`.
- **When the default applies:** to object writes (PutObject, POST, CopyObject, CreateMultipartUpload) that carry no encryption headers of their own.

---

## 18. ACLs and Object Ownership

Cairn has no ACLs. Every bucket behaves as S3's `BucketOwnerEnforced`, and access is decided by policies only.

| Request | Answer |
| --- | --- |
| GetBucketAcl, GetObjectAcl | 🔹 A fixed `AccessControlPolicy`: owner and grantee `cairn`, `FULL_CONTROL`. GetObjectAcl answers even for missing keys. |
| PutBucketAcl | 🔹 `200` only with `x-amz-acl: private`, no grant headers and no body. Otherwise `400 AccessControlListNotSupported`. |
| PutObjectAcl | 🔹 `200` only with `x-amz-acl: bucket-owner-full-control`, no grant headers and no body. Otherwise `400 AccessControlListNotSupported`. The version must exist. |
| `x-amz-acl` on object writes | 🔹 Only `bucket-owner-full-control`; **`private` is refused**. |
| `x-amz-acl` on CreateBucket | 🔹 Only `private`. |
| `x-amz-grant-*` anywhere | ❌ `400 AccessControlListNotSupported` (objects), or `400 InvalidBucketAclWithObjectOwnership` (CreateBucket). |
| GetBucketOwnershipControls | 🔹 Always `BucketOwnerEnforced`. |
| Put/DeleteBucketOwnershipControls | ❌ `501` |
| `x-amz-object-ownership` | ⚪ |

---

## 19. Bucket policies and Block Public Access

### Bucket policies

- **PutBucketPolicy:**
  - It answers `204`. **No body checksum is required** (probed).
  - The normalized document may be at most **20480 bytes**.
  - Errors are `400 MalformedPolicy`, with S3's messages.
  - A condition key Cairn can't evaluate is `501 NotImplemented`.
  - Principals naming users, roles or accounts that don't exist are `400 MalformedPolicy` "Invalid principal in policy".
  - A public policy blocked by `BlockPublicPolicy` is `403 AccessDenied`.
- **GetBucketPolicy:**
  - It returns the **normalized** policy, not the text that was put: compact, single values unwrapped, accounts as root ARNs, and `Version` defaulting to `2008-10-17`.
  - Deleted principals are shown by ID, and renamed ones by their new ARN (probed).
  - With no policy: `404 NoSuchBucketPolicy`.
- **DeleteBucketPolicy:** `204`, whether or not there was a policy (probed).
- **GetBucketPolicyStatus:** `IsPublic`. With no policy: `404 NoSuchBucketPolicy`.
- **Restrictions:**
  - A bucket policy may name only its own bucket, and only S3 bucket and object actions (not CreateBucket).
  - Bucket-policy operations by another account, or anonymously, are `405` even if the policy allows them.
  - `cairn bucket-policy get|put|delete` on a node bypasses all of this: it is the break-glass.

The grammar and evaluation are in [§20](#20-authorization-and-the-policy-language).

### Block Public Access

- **Bucket level:** `?publicAccessBlock`.
  - PUT requires a body checksum and answers `200`.
  - GET always lists all four flags, or answers `404 NoSuchPublicAccessBlockConfiguration`.
  - DELETE answers `204`.
- **Account level** (S3 Control): `/v20180820/configuration/publicAccessBlock` with `x-amz-account-id`.
  - The account ID must be the signer's own, else `403`.
  - It needs `s3:GetAccountPublicAccessBlock` / `s3:PutAccountPublicAccessBlock`.
  - PUT needs no checksum. DELETE answers `200`, as botocore's model has it.
  - The `{account-id}.s3-control…` host prefix is not needed and is ignored.
- **Defaults:** new buckets have all four flags on. Bucket and account flags combine with OR.

| Flag | Effect |
| --- | --- |
| `BlockPublicPolicy` | ✅ Refuses putting a public policy. It doesn't revoke an existing one. |
| `RestrictPublicBuckets` | ✅ A public policy grants nothing to anyone outside the bucket's account, anonymous requests included. |
| `BlockPublicAcls`, `IgnorePublicAcls` | 🔹 Stored and reported. They always hold anyway, since only owner-only ACLs exist. |

A policy is *public* when some `Allow` for `*` isn't fixed by a condition on one of:

- `aws:SourceIp`, no wider than `/8` for IPv4 or `/32` for IPv6;
- `aws:SourceArn`, `aws:SourceVpc`, `aws:SourceVpce`, `aws:SourceOwner`, `aws:SourceAccount`;
- `aws:PrincipalArn`, `aws:PrincipalAccount`, `aws:PrincipalOrgID`, `aws:userid`;
- `s3:x-amz-server-side-encryption-aws-kms-key-id`, `s3:DataAccessPointArn`, `s3:DataAccessPointAccount`.

---

## 20. Authorization and the policy language

Every S3, IAM and STS request is authorized by one engine that follows IAM's evaluation logic.

### Policy types

| Type | Support |
| --- | --- |
| Identity policies: inline and managed, attached to users and roles | ✅ |
| Permissions boundaries (users and roles) | ✅ |
| Session policies (STS `Policy`, `PolicyArns`) | ✅ |
| Resource policies: bucket policies | ✅ |
| Resource policies: role trust policies | ✅ |
| ACLs | ❌ ([§18](#18-acls-and-object-ownership)) |
| Access point, VPC endpoint and SCP/RCP (Organizations) policies | ❌ |

### Evaluation

1. An explicit `Deny` in any policy (identity, boundary, session or bucket) denies.
2. Within one account, a request is allowed if:
   - the identity policies allow it, within the boundary and the session policies; **or**
   - the bucket policy allows it by naming the principal itself (or `*`). Such an allow is not capped by boundaries or session policies (probed); **or**
   - the bucket policy allows it by naming the session's role, within the caps.
3. Across accounts, both the identity side and the bucket policy must allow it.
4. Naming an account in a same-account `Allow` delegates to identity policies; in a `Deny`, it denies all of the account's principals (probed).

There is no root user that bypasses policies. Anonymous requests skip identity policies, so only bucket policies can allow them.

Denials of signed requests carry IAM's message: `User: <arn> is not authorized to perform: <action> on resource: "<arn>" because no identity-based policy allows the <action> action`. Other reasons include an explicit deny in an identity-based or resource-based policy, a permissions boundary, or a session policy. Anonymous requests get "Access Denied".

### Grammar

- **Top level:**
  - `Version`: `2012-10-17` or `2008-10-17`. Policy variables need `2012-10-17`.
  - `Id`: bucket and trust policies only.
  - `Statement`: an object or a non-empty array. Unknown fields are refused.
  - Duplicate JSON keys are refused.
- **Statement fields:** `Sid`, `Effect` (either case, probed), `Principal`/`NotPrincipal` (`NotPrincipal` only with `Deny`), `Action`/`NotAction`, `Resource`/`NotResource`, `Condition`.
  - Sids must be unique in identity and trust policies. Bucket policies accept duplicates (probed).
- **Principals:**
  - `"*"` and `{"AWS": …}` with `*`, account IDs, `arn:aws:iam::<acct>:root`, users, roles and assumed-role sessions. No wildcards inside ARNs.
  - `Federated` (OIDC providers) in trust policies.
  - `Service` is accepted but never matches.
  - `CanonicalUser` is refused.
  - Users and roles are bound by their ID: a deleted and re-created user isn't matched, a renamed one still is (probed).
- **Actions:**
  - `s3:` actions are checked against AWS's list of 180 S3 actions. An unknown action, or a pattern matching none, is refused.
  - Matching is case-insensitive, with `*` and `?`.
  - In identity policies, other services' actions (`iam:`, `sts:`, `cairn:`, …) are accepted as written.
- **Resources:**
  - ARN patterns, case-sensitive. Wildcards don't cross `:`.
  - In bucket policies, each action must apply to some resource of its statement, and condition keys must apply to the statement's actions (S3's checks).

### Condition operators

All of IAM's are supported:

- `String*` (Equals, NotEquals, EqualsIgnoreCase, NotEqualsIgnoreCase, Like, NotLike)
- `Numeric*`
- `Date*` (ISO 8601 or epoch seconds)
- `Bool`, `BinaryEquals`
- `IpAddress`, `NotIpAddress` (IPv4 and IPv6)
- `Arn*`. `ArnEquals` matches like `ArnLike`.
- `Null`
- the `…IfExists` variant of each operator except `Null`
- the `ForAllValues:` and `ForAnyValue:` qualifiers

Semantics:

- A missing key makes positive operators false and negated operators true.
- Values that don't parse for their operator match nothing (probed).
- Key names are case-insensitive.

### Policy variables

- `${key}`, `${key, 'default'}`, `${*}`, `${?}` and `${$}`, for any single-valued key: `${aws:username}`, `${aws:userid}`, `${aws:PrincipalTag/team}`, …
- They are allowed in the resource part of `Resource`/`NotResource` and in condition values.

### Condition keys

Global keys **evaluated**:

| Key | Value in Cairn |
| --- | --- |
| `aws:CurrentTime`, `aws:EpochTime` | Now. |
| `aws:SourceIp` | The client address ([trusted proxies](#trusted-proxies)). |
| `aws:SecureTransport` | `true` only through a trusted proxy that says HTTPS. |
| `aws:UserAgent`, `aws:Referer` | From the request. |
| `aws:username` | Users only; absent for role and federated sessions (probed). |
| `aws:userid` | `AIDA…`, `AROA…:<session>`, `<acct>:<name>` or `anonymous`. |
| `aws:PrincipalArn` | The user, or the role for role sessions (probed). |
| `aws:PrincipalAccount`, `aws:PrincipalType` | The principal's account; `User`, `AssumedRole`, `FederatedUser` or `Anonymous`. |
| `aws:PrincipalTag/*` | The principal's tags plus session tags. |
| `aws:PrincipalIsAWSService`, `aws:ViaAWSService` | Always `false`. |
| `aws:ResourceAccount` | The bucket's account. |
| `aws:RequestedRegion` | The credential scope's region. |
| `aws:TokenIssueTime`, `aws:SourceIdentity`, `aws:FederatedProvider` | Sessions only. |
| `aws:MultiFactorAuthPresent`, `aws:MultiFactorAuthAge` | `false` for STS sessions; absent for access keys. In the console: `true` (with the age) for passkey sign-ins, `false` for OIDC. |

Global keys **accepted but never present** on S3 requests:

- `aws:RequestTag/*`, `aws:ResourceTag/*` and `aws:TagKeys`: IAM requests set these, S3 requests never do. There is no bucket ABAC.
- `aws:CalledVia*`, `aws:Ec2InstanceSource*`, `aws:PrincipalOrg*`, `aws:PrincipalServiceName*`, `aws:ResourceOrg*`, `aws:SourceAccount`, `aws:SourceArn`, `aws:SourceOrg*`, `aws:SourceVpc*`, `aws:SourceVpce`, `aws:VpcSourceIp`.
- Any other unknown `aws:` key.

S3 keys **evaluated**. Each action sees only the keys AWS's service reference lists for it (probed):

- `s3:authType` (`REST-HEADER`, `REST-QUERY-STRING`, `POST`)
- `s3:signatureversion` (`AWS4-HMAC-SHA256`)
- `s3:signatureAge`: presigned URLs only
- `s3:prefix`, `s3:delimiter`, `s3:max-keys`
- `s3:versionid`
- `s3:x-amz-acl`, `s3:x-amz-grant-*`
- `s3:x-amz-copy-source`, `s3:x-amz-metadata-directive`
- `s3:x-amz-server-side-encryption`, `s3:x-amz-server-side-encryption-aws-kms-key-id`, `s3:x-amz-server-side-encryption-customer-algorithm`: the request's headers, not the bucket's defaults
- `s3:x-amz-storage-class`, `s3:x-amz-website-redirect-location`, `s3:x-amz-content-sha256`
- `s3:if-match`, `s3:if-none-match`: PUT only
- `s3:object-lock-mode`, `s3:object-lock-retain-until-date`, `s3:object-lock-remaining-retention-days`, `s3:object-lock-legal-hold`
- `s3:ResourceAccount`

S3 keys **accepted but never present**: access point, access grant, batch job, replication, inventory, log delivery and annotation keys (`s3:DataAccessPoint*`, `s3:AccessGrant*`, `s3:ExistingJob*`, …).

S3 keys **refused** with `501 NotImplemented` when a policy uses them:

- `s3:ExistingObjectTag/*`, `s3:RequestObjectTag/*`, `s3:RequestObjectTagKeys`, `s3:BucketTag/*`
- `s3:TlsVersion`, `s3:locationconstraint`
- `s3:object-lock-event-hold`, `s3:object-lock-event-hold-duration-days`
- `s3:ObjectCreationOperation`, `s3:x-amz-object-ownership`, `s3:x-amz-object-if-match`, `s3:x-amz-bucket-namespace`, `s3:resourceArnBeingAuthorized`

STS keys in trust policies: `sts:ExternalId`, `sts:RoleSessionName`, `sts:SourceIdentity` and `sts:TransitiveTagKeys` are evaluated. Others are `501`.

### Actions each S3 request needs

With a `versionId`, the `…Version…` variant of an action is checked instead.

| Request | Actions |
| --- | --- |
| ListBuckets | `s3:ListAllMyBuckets`. Without it, the list is filtered. |
| ListObjects(V2), HeadBucket | `s3:ListBucket` |
| ListObjectVersions | `s3:ListBucketVersions` |
| ListMultipartUploads | `s3:ListBucketMultipartUploads` |
| ListParts | `s3:ListMultipartUploadParts` |
| CreateBucket | `s3:CreateBucket` (+ `s3:PutBucketAcl` with ACL headers; + `s3:PutBucketObjectLockConfiguration` and `s3:PutBucketVersioning` with Object Lock) |
| DeleteBucket | `s3:DeleteBucket` |
| Bucket versioning, encryption, lifecycle, CORS, tagging, public access block | `s3:Get…`/`s3:Put…` of each (`GetEncryptionConfiguration`, `GetLifecycleConfiguration`, `GetBucketCORS`, …). Their DELETEs use the Put action. |
| Bucket policy, website | `s3:Get/Put/DeleteBucketPolicy`, `s3:Get/Put/DeleteBucketWebsite` |
| Policy status, ACL, ownership, location, Object Lock configuration, the stubs | Their `s3:Get…` actions; `s3:PutBucketAcl`; `s3:PutBucketObjectLockConfiguration`. |
| GetObject, HeadObject | `s3:GetObject` / `s3:GetObjectVersion` |
| GetObjectAttributes | `s3:GetObjectAttributes` **and** `s3:GetObject` (or their Version variants) |
| PutObject, CreateMultipartUpload, POST Object | `s3:PutObject` (+ `s3:PutObjectTagging` with tags, `s3:PutObjectRetention` / `s3:PutObjectLegalHold` with lock headers, `s3:PutObjectAcl` with ACL headers) |
| UploadPart, CompleteMultipartUpload | `s3:PutObject` |
| CopyObject, UploadPartCopy | As PutObject, plus `s3:GetObject(Version)` on the source. Tagging only with `REPLACE`. |
| AbortMultipartUpload | `s3:AbortMultipartUpload` |
| DeleteObject | `s3:DeleteObject` / `s3:DeleteObjectVersion` (+ `s3:BypassGovernanceRetention` with bypass) |
| DeleteObjects | The same, per key. |
| Object tagging | `s3:Get/Put/DeleteObject(Version)Tagging` |
| Object ACL | `s3:GetObject(Version)Acl`, `s3:PutObject(Version)Acl` |
| Retention, legal hold | `s3:Get/PutObjectRetention`, `s3:Get/PutObjectLegalHold` |
| Account public access block | `s3:GetAccountPublicAccessBlock`, `s3:PutAccountPublicAccessBlock` |

GET and HEAD of objects also check `s3:GetObjectRetention` and `s3:GetObjectLegalHold`, to decide whether to show the lock headers.

### Managed policies

- **Built-in** (`arn:aws:iam::aws:policy/…`):
  - `AdministratorAccess` (`*`).
  - `AmazonS3FullAccess` and `AmazonS3ReadOnlyAccess`, with AWS's documents.
  - Cairn's own `CairnOperatorAccess` (`cairn:*`).
  - Other AWS-managed ARNs don't exist.
- **The account's own:** up to 5 versions each.

---

## 21. IAM API

### Protocol

- **Endpoint:** the IAM API is served **on the S3 port**. A request is IAM when its SigV4 credential scope names service `iam`, whatever its host or path. Point clients there with `aws iam --endpoint-url`, or Terraform's `endpoints { iam = … }`.
- **Protocol:** AWS's **Query protocol** only (`Action=…`, form-encoded in the query and/or body). There is no JSON protocol.
  - A parameter given twice is `400 MalformedQueryString`.
  - Bodies are limited to 64 KiB.
  - `Version` is ignored.
- **Responses:** XML in IAM's namespace, `text/xml`, with an `x-amzn-requestid` header. Errors use `<ErrorResponse>` with `Type`, `Code` and `Message`.
- **Signatures:** SigV4, header or presigned, with the body's SHA-256 bound into the signature.
- **Credential errors:** `403 InvalidClientTokenId` and `403 ExpiredToken`.
- **Unknown or unimplemented action:** 🟡 `501 NotImplemented`. IAM answers `400 InvalidAction`.
- **Authorization:** every action is authorized as `iam:<Action>` on its resource, by the same engine as S3.
- **Session restrictions:** sessions from GetSessionToken or GetFederationToken can't call IAM at all (`403 InvalidClientTokenId`, probed). Role sessions can.

### Actions

| Area | Implemented | Not implemented (`501`) |
| --- | --- | --- |
| Users | CreateUser, GetUser, ListUsers, UpdateUser, DeleteUser, TagUser, UntagUser, ListUserTags, PutUserPermissionsBoundary, DeleteUserPermissionsBoundary | — |
| Access keys | CreateAccessKey, ListAccessKeys, UpdateAccessKey, DeleteAccessKey | GetAccessKeyLastUsed |
| User inline policies | PutUserPolicy, GetUserPolicy, ListUserPolicies, DeleteUserPolicy | — |
| Managed policies | CreatePolicy, GetPolicy, ListPolicies, DeletePolicy, CreatePolicyVersion, GetPolicyVersion, ListPolicyVersions, DeletePolicyVersion, SetDefaultPolicyVersion, ListEntitiesForPolicy, TagPolicy, UntagPolicy, ListPolicyTags, AttachUserPolicy, DetachUserPolicy, ListAttachedUserPolicies | — |
| Roles | CreateRole, GetRole, ListRoles, UpdateRole, UpdateRoleDescription, UpdateAssumeRolePolicy, DeleteRole, PutRolePermissionsBoundary, DeleteRolePermissionsBoundary, TagRole, UntagRole, ListRoleTags, PutRolePolicy, GetRolePolicy, ListRolePolicies, DeleteRolePolicy, AttachRolePolicy, DetachRolePolicy, ListAttachedRolePolicies | Service-linked roles, instance profiles (ListInstanceProfilesForRole, …) |
| OIDC providers | CreateOpenIDConnectProvider, GetOpenIDConnectProvider, ListOpenIDConnectProviders, DeleteOpenIDConnectProvider, AddClientIDToOpenIDConnectProvider, RemoveClientIDFromOpenIDConnectProvider, UpdateOpenIDConnectProviderThumbprint, TagOpenIDConnectProvider, UntagOpenIDConnectProvider, ListOpenIDConnectProviderTags | — |
| Everything else | — | Groups; login profiles and passwords; MFA devices; SAML providers; account aliases, password policy and summary; GetAccountAuthorizationDetails; policy simulation and context keys; server and signing certificates; SSH keys; service-specific credentials; credential reports; service last-accessed details |

`iam:PassRole` is never checked, since there are no services to pass roles to.

### Behavior and limits

| Item | Cairn |
| --- | --- |
| User names | 🟡 Only `[A-Za-z0-9._-]`, case-insensitively unique, with no length cap. AWS also allows `+=,@`, up to 64. |
| Role names | 1–64 of `[\w+=,.@-]`, case-insensitively unique. |
| Policy names | 1–128 of `[\w+=,.@-]`. Bad managed names: `400 InvalidInput` (AWS: ValidationError). |
| Paths | 🟡 `/…/`, ≤ 512, but only `[\w+=,.@/-]`. AWS allows all printable ASCII. |
| Access keys | At most 2 per user. Key IDs are 20 random base32 characters (**no `AKIA` prefix**); secrets are 40 characters of URL-safe base64. |
| Inline policy size | 2048 non-whitespace characters total per user; 10240 per role. |
| Managed policy documents | 6144 characters. Description ≤ 1000. |
| Attached managed policies | 10 per user or role (the admin flag counts). |
| Policy versions | 5 per policy. |
| Trust policy size | 2048 (probed). |
| Tags | 50 per user, role, policy or provider. Key 1–128 and value 0–256, of `[\p{L}\p{Z}\p{N}_.:/=+\-@]`, with no `aws:` keys. Adding tags needs `iam:Tag…` too (probed). |
| `MaxSessionDuration` | 3600–43200, default 3600. |
| `MaxItems` | 1–1000, default 100. |
| Paging | 🟡 Honored by ListUsers, ListRoles, ListPolicies, ListPolicyVersions and the tag lists. **Ignored** (everything returned, `IsTruncated=false`) by ListAccessKeys, ListUserPolicies, ListAttachedUserPolicies, ListRolePolicies, ListAttachedRolePolicies and ListEntitiesForPolicy. ListPolicies ignores `PolicyUsageFilter`. |
| Policy documents | Validated by the engine of [§20](#20-authorization-and-the-policy-language). Errors: `400 MalformedPolicyDocument`; unsupported keys: `501`. Returned URL-encoded, as IAM does. |
| IDs | `AIDA…` (users), `AROA…` (roles), `ANPA…` (policies). |
| DeleteUser / DeleteRole | `409 DeleteConflict` while access keys or policies remain. Deleting a role ends its sessions. |
| GetUser / GetRole | No `PasswordLastUsed`. `RoleLastUsed` is always empty. |

---

## 22. STS API

### Protocol

- **Endpoint:** served on the S3 port when the credential scope names service `sts`. Use `aws sts --endpoint-url` or `AWS_ENDPOINT_URL_STS`.
- **Responses:** XML in STS's namespace.
- **Unsigned requests:** AssumeRoleWithWebIdentity is accepted **unsigned only**, as a form `POST /` or `GET /?Action=…`. Signed, it is `400 InvalidAction`.
  - Other unsigned actions are `403 MissingAuthenticationToken`.
  - An anonymous `GET /?Action=…` is therefore STS, not ListBuckets.
- **Unknown actions:** `400 InvalidAction`.

### Actions

| Action | Status |
| --- | --- |
| GetCallerIdentity | ✅ No permission needed. Returns the user, `assumed-role/<role>/<session>` or `federated-user/<name>` ARN. |
| AssumeRole | ✅ |
| AssumeRoleWithWebIdentity | ✅ Unsigned. [§23](#23-openid-connect-providers-and-web-identity) |
| GetSessionToken | ✅ Long-term credentials only. |
| GetFederationToken | 🟡 Long-term credentials only. |
| GetAccessKeyInfo | ✅ Needs `sts:GetAccessKeyInfo`. |
| AssumeRoleWithSAML | ❌ `400 InvalidAction` |
| DecodeAuthorizationMessage | ❌ `400 InvalidAction`. Denial messages aren't encoded. |
| AssumeRoot, GetDelegatedAccessToken, GetWebIdentityToken | ❌ `400 InvalidAction` |

### Credentials

- **Format:**
  - Access key IDs are `ASIA` plus 16 characters. Secrets are 40 characters.
  - Session tokens are stateless and sealed (XChaCha20-Poly1305) under a cluster key rotated daily. Issuing one writes nothing to the database.
- **Extra response fields:** `PackedPolicySize`, `SessionTokenUtilization` and `SessionTokenSize`.
- **Validation:**
  - The user or role is re-read on every request. Deleting the role or user ends its sessions.
  - Deleting a user's long-term key does not end that user's sessions.
- **Revocation:**
  - A `Deny` on `aws:TokenIssueTime`. The console's "Revoke sessions" writes AWS's `AWSRevokeOlderSessions` policy.
  - Deleting the role.
  - `cairn sessions revoke-all`, which ends every session in the cluster within a minute.
- **MFA:** `SerialNumber`/`TokenCode` always fail with `403 AccessDenied`; there are no MFA devices. Sessions carry `aws:MultiFactorAuthPresent=false`.

### AssumeRole

- **Parameters:**
  - `RoleArn`: exact path and name, in this account.
  - `RoleSessionName`: 2–64.
  - `DurationSeconds`: 900–43200, capped by the role's `MaxSessionDuration`. The default is 3600, or the role's maximum if lower.
  - `ExternalId`, `SourceIdentity`.
  - `Policy` (≤ 2048) and `PolicyArns` (≤ 10).
  - `Tags` (≤ 50) and `TransitiveTagKeys`.
- **Who may call:** users, GetSessionToken sessions, and role sessions (chaining). Federated users may not.
- **Chaining:**
  - At most 1 hour.
  - Transitive tags and source identity are carried, and can't be changed.
  - The web-identity provider carries down the chain.
- **Trust policy:**
  - A statement naming the principal itself (or `*`) allows it on its own.
  - One naming the account also needs the caller's identity policies to allow `sts:AssumeRole`.
  - Tags need `sts:TagSession`. `SourceIdentity` needs `sts:SetSourceIdentity`.
  - Condition keys include `sts:ExternalId`, `sts:RoleSessionName`, `sts:SourceIdentity`, `aws:RequestTag/*`, `aws:TagKeys` and `sts:TransitiveTagKeys`.
- **Missing or untrusted roles:** both answer `403 AccessDenied` (probed).
- **Validation gaps:** session tags aren't checked against the character pattern. A `SourceIdentity` beginning with `aws:` isn't refused.
- **Ignored:** `ProvidedContexts`. `sts:SetContext` is accepted in trust policies but has no effect.

### GetSessionToken

- `DurationSeconds` 900–129600, default 43200.
- The session has the user's permissions, but can't call IAM.

### GetFederationToken

- **Parameters:** `Name` (2–32), `DurationSeconds` 900–129600 (default 43200), `Policy`, `PolicyArns` and `Tags`.
- **Permission:** `sts:GetFederationToken` on `federated-user/<name>`.
- **Effective permissions:** the user's policies ∩ the session policies. With no session policy, nothing is allowed.
- 🟡 **Tags:** they don't need `sts:TagSession`, and `TransitiveTagKeys` isn't taken.
- **Session restrictions:** federated sessions can't call IAM, AssumeRole, GetSessionToken or GetFederationToken.

---

## 23. OpenID Connect providers and web identity

### Providers (IAM)

- **`Url`:** `https://` only, at most 255 characters.
- **`ClientIDList`:** at most 100 client IDs.
- **`ThumbprintList`:** at most 5, each 40 hex characters.
- 🟡 **Cairn contacts the issuer when a provider is created.** It fetches the discovery document and JWKS, and fails with `400 OpenIdIdpCommunicationError` if the issuer is unreachable.
- **Public addresses only:** issuers are fetched over HTTPS at public addresses only, checked after DNS resolution too. `cairn config set oidc-private-issuers 1` allows private ones.
- 🟡 **Thumbprints are real certificate pins:** they are used as trust anchors when the public roots don't verify the issuer. That lets issuers on private CAs work.
- **Deleting a provider:** its existing sessions are not revoked.

### AssumeRoleWithWebIdentity

- **Parameters:**
  - `RoleArn`, `RoleSessionName`.
  - `WebIdentityToken` (4–20000).
  - `DurationSeconds` 900–43200, capped by the role.
  - `Policy`, `PolicyArns`.
  - `ProviderId` is refused: OAuth 2.0 access tokens aren't supported.
- **Token validation:**
  - **Provider:** chosen by the token's `iss` before anything is fetched. An unknown issuer is `400 InvalidIdentityToken`.
  - **Signature:** RS256/384/512, PS256/384/512, ES256, ES384 or EdDSA. `none` and HMAC are never accepted.
  - **Claims:** `aud` must be one of the client IDs. `exp` is required, with 60 s leeway (`400 ExpiredTokenException`). `sub` is required.
  - **Keys:** cached 1 h. They are re-fetched once when the token's `kid` is unknown. A fetch failure is `400 IDPCommunicationError`.
- **Session tags and source identity:** taken from the `https://aws.amazon.com/tags` and `https://aws.amazon.com/source_identity` claims. They need `sts:TagSession` / `sts:SetSourceIdentity`.
- **Trust:** only statements whose `Principal.Federated` is the provider's ARN can allow it.
- **Condition keys:**
  - Set: `<provider-url>:sub`, `<provider-url>:aud`, `<provider-url>:amr`, `aws:FederatedProvider`, `sts:RoleSessionName`, `sts:SourceIdentity`, `aws:RequestTag/*`, `aws:TagKeys`, `sts:TransitiveTagKeys`.
  - 🟡 **Not set:** other claim keys, such as `:oaud`, `:azp`, `:email`, or GitHub's `job_workflow_ref`. They are accepted in trust policies but are never present, so conditions on them never match.
- **Denial:** `403 AccessDenied` "Not authorized to perform sts:AssumeRoleWithWebIdentity".

IAM's OIDC providers are separate from the console's OIDC sign-in (`cairn oidc`).

---

## 24. Cairn-specific concepts

- **One account:** a cluster has exactly one account with a 12-digit ID (`cairn account show`), which owns every bucket, user, role and policy. Cross-account logic exists in the policy engine, but there is only one account.
- **Admins and operators:**
  - Admin users have `AdministratorAccess`.
  - *Operators* are users whose policies allow `cairn:` actions on `arn:aws:cairn:::cluster`: `cairn:GetCluster`, `cairn:PutSetting`, `cairn:RemoveNode` and `cairn:IdentifyUsers`. `CairnOperatorAccess` allows them all. These are used by the console.
- **Grants:** `cairn user grant <user> <bucket> read|write|delete-version` attaches an ordinary managed policy, named `<bucket>-<permission>`. IAM tools can see and edit it like any other.
  - `read` allows the object reads and listings.
  - `write` allows object writes, deletes and multipart aborts.
  - `delete-version` allows `s3:DeleteObjectVersion`.
  - Each grant also allows reading the bucket's configuration, except its policy.
- **The `cairn` CLI:** runs on a node through the peer endpoint and is not subject to policies. It is the break-glass for users, keys, policies, bucket policies, settings and sessions.
- **The console:** a web UI on its own listener, with passkey or OIDC sign-in. It acts as the signed-in user, and every operation is checked as the matching `s3:`, `iam:` or `cairn:` action.

---

## 25. Request header reference

The status of every S3 request header, across operations. "Writes" means PutObject, POST Object, CopyObject and CreateMultipartUpload.

### Standard HTTP headers

| Header | Status |
| --- | --- |
| `Authorization` | ✅ SigV4 only ([§3](#3-authentication)). |
| `Host` | ✅ Must be signed. Virtual-hosted and website routing use it. |
| `Content-Length` | ✅ Up to 5 GiB per request body. 🟡 Optional (chunked transfer encoding works). |
| `Content-Type` | ✅ Stored on writes; default `binary/octet-stream`. |
| `Content-MD5` | ✅ Verified everywhere a body is read. Becomes the ETag of a PUT or part. |
| `Content-Encoding` | ✅ Stored, without `aws-chunked`. |
| `Content-Disposition`, `Content-Language`, `Cache-Control`, `Expires` | ✅ Stored. |
| `Range` | 🟡 Single ranges only ([§8](#getobject-and-headobject)). |
| `If-Match` | ✅ On reads, PutObject, CopyObject and CompleteMultipartUpload. ⚪ On DeleteObject. ⚪ On GetObjectAttributes. |
| `If-None-Match` | ✅ On reads. On PutObject and CopyObject, `*` only (else 501). Any value on CompleteMultipartUpload. ⚪ On GetObjectAttributes. |
| `If-Modified-Since`, `If-Unmodified-Since` | ✅ On reads. ⚪ On writes and GetObjectAttributes. |
| `Expect` | ✅ `100-continue` is answered by the HTTP server. |
| `Origin`, `Access-Control-Request-Method`, `Access-Control-Request-Headers` | ✅ CORS ([§15](#15-cors)). |
| `Date` | ⚪ Never the request time; `x-amz-date` is required. |
| `X-Forwarded-For`, `X-Forwarded-Proto`, `Forwarded` | ✅ From trusted proxies only ([§2](#trusted-proxies)). |
| `User-Agent`, `Referer` | ✅ Policy keys only. |

### `x-amz-*` headers

| Header | Status |
| --- | --- |
| `x-amz-date` | ✅ Required for header auth. |
| `x-amz-content-sha256` | ✅ Required for header auth ([§10](#10-checksums-and-payload-integrity)). |
| `x-amz-decoded-content-length` | ✅ Required with streaming. |
| `x-amz-trailer` | ✅ Trailer modes. |
| `x-amz-security-token` | ✅ |
| `x-amz-meta-*` | ✅ Stored. 2 KiB. ASCII only. |
| `x-amz-checksum-crc32`, `-crc32c`, `-crc64nvme`, `-sha1`, `-sha256` | ✅ |
| `x-amz-sdk-checksum-algorithm` | ✅ |
| `x-amz-checksum-algorithm` | ✅ CreateMultipartUpload and CopyObject. ⚪ PutObject and UploadPartCopy. |
| `x-amz-checksum-type` | 🟡 PutObject (MinIO's rule), CreateMultipartUpload and CompleteMultipartUpload. |
| `x-amz-checksum-mode` | ✅ `ENABLED` on GET and HEAD. |
| `x-amz-copy-source` | ✅ |
| `x-amz-copy-source-range` | ✅ UploadPartCopy. ⚪ CopyObject. |
| `x-amz-copy-source-if-match`, `-if-none-match`, `-if-modified-since`, `-if-unmodified-since` | ✅ |
| `x-amz-copy-source-server-side-encryption-customer-*` | ✅ |
| `x-amz-metadata-directive`, `x-amz-tagging-directive` | ✅ Case-sensitive. |
| `x-amz-tagging` | ✅ Writes. ❌ UploadPart and Complete (400). |
| `x-amz-website-redirect-location` | ✅ Stored. ⚪ As a POST form field. |
| `x-amz-storage-class` | ⚪ Any value. Policy key only. |
| `x-amz-acl` | 🔹 Owner-only values only ([§18](#18-acls-and-object-ownership)). |
| `x-amz-grant-read`, `-write`, `-read-acp`, `-write-acp`, `-full-control` | ❌ 400 |
| `x-amz-server-side-encryption` | ✅ `aws:kms` or `AES256` on writes. ❌ `aws:kms:dsse`. ❌ On reads (400) and other writes (501). |
| `x-amz-server-side-encryption-aws-kms-key-id`, `-context` | ✅ Writes ([§17](#sse-kms)). |
| `x-amz-server-side-encryption-bucket-key-enabled` | 🔹 Validated, then ignored. |
| `x-amz-server-side-encryption-customer-algorithm`, `-key`, `-key-MD5` | ✅ |
| `x-amz-object-lock-mode`, `-retain-until-date`, `-legal-hold` | ✅ Writes. |
| `x-amz-bypass-governance-retention` | ✅ DeleteObject, DeleteObjects and PutObjectRetention. |
| `x-amz-bucket-object-lock-enabled` | ✅ CreateBucket. |
| `x-amz-bucket-object-lock-token` | ⚪ |
| `x-amz-object-ownership` | ⚪ |
| `x-amz-mp-object-size` | ✅ CompleteMultipartUpload. |
| `x-amz-object-attributes`, `x-amz-max-parts`, `x-amz-part-number-marker` | ✅ GetObjectAttributes. |
| `x-amz-account-id` | ✅ S3 Control. |
| `x-amz-expected-bucket-owner`, `x-amz-source-expected-bucket-owner` | ⚪ Never checked: a mismatch is never a 403. |
| `x-amz-request-payer` | ⚪ No requester pays. |
| `x-amz-mfa` | ⚪ No MFA delete. |
| `x-amz-write-offset-bytes` | ⚪ No appends: the PUT overwrites. |
| `x-amz-if-match-last-modified-time`, `x-amz-if-match-size`, `x-amz-if-match-initiated-time` | ⚪ |
| `x-amz-optional-object-attributes` | ⚪ No `RestoreStatus`. |
| `x-amz-transition-default-minimum-object-size` | ⚪ |
| `x-amz-restore-*`, `x-amz-select-*`, `x-amz-confirm-remove-self-bucket-access`, `x-amz-sdk-*` (other than above) | ⚪ |

---

## 26. Response header reference

| Header | Sent by |
| --- | --- |
| `x-amz-request-id` | Every S3 response (16 hex characters). IAM and STS send `x-amzn-requestid`. |
| `ETag` | PUT, GET, HEAD, UploadPart, POST. Multipart objects: `"<md5>-N"`. SSE-C and SSE-KMS objects and parts: random. |
| `Last-Modified` | GET, HEAD, GetObjectAttributes, and 304s. |
| `Accept-Ranges: bytes`, `Content-Range` | GET and HEAD (range on 206). |
| `x-amz-version-id` | Writes in versioning-enabled buckets. Reads and deletes once the bucket has been versioned. Tagging. Not on PutObjectRetention or PutObjectLegalHold. |
| `x-amz-copy-source-version-id` | CopyObject and UploadPartCopy, from versioned sources. |
| `x-amz-delete-marker` | Deletes that make or remove markers, and reads of markers. |
| `x-amz-checksum-<alg>`, `x-amz-checksum-type` | PutObject and POST (always). GET and HEAD with checksum mode. UploadPart. CreateMultipartUpload (`x-amz-checksum-algorithm` too). |
| `x-amz-mp-parts-count` | Part reads of multipart objects. |
| `x-amz-tagging-count` | GET and HEAD of tagged objects. |
| `x-amz-meta-*` and stored standard headers | GET and HEAD. |
| `x-amz-website-redirect-location` | GET and HEAD. |
| `x-amz-object-lock-mode`, `-retain-until-date`, `-legal-hold` | GET and HEAD, to permitted callers. |
| `x-amz-server-side-encryption`, `-aws-kms-key-id`, `-context`, `-customer-algorithm`, `-customer-key-MD5` | Encrypted writes and reads ([§17](#17-server-side-encryption)). |
| `Location` | CreateBucket (`/bucket`), POST Object. |
| `Access-Control-*`, `Vary` | CORS. |
| `x-amz-error-code`, `x-amz-error-message`, `x-amz-error-detail-*` | Website error pages. |
| **Never sent** | `x-amz-id-2`, `x-amz-storage-class`, `x-amz-expiration`, `x-amz-restore`, `x-amz-replication-status`, `x-amz-missing-meta`, `x-amz-request-charged`, `x-amz-abort-date`, `x-amz-abort-rule-id`, `x-amz-bucket-region`, `x-amz-access-point-alias`, `x-amz-server-side-encryption-bucket-key-enabled`, `x-amz-object-size` |

---

## 27. Limits

| Limit | Value |
| --- | --- |
| Key length | 1024 bytes of UTF-8. No NUL. |
| Bucket name | 3–63 characters (see [CreateBucket](#createbucket)). |
| Single PUT, POST file, CopyObject source, part, part-copy range | 5 GiB |
| Object size | 5 TiB |
| Parts per upload | 10,000 (part numbers 1–10000) |
| Minimum part size | 5 MiB, except the last |
| User metadata | 2048 bytes (names without prefix, plus values) |
| Object tags | 10; key 128 and value 256 UTF-16 units |
| Bucket tags | 50 |
| DeleteObjects keys | 1000 |
| Whole XML bodies | 8 MiB; CORS and website: 64 KiB |
| POST form fields before the file | 20 KiB |
| Listing page size | 1000. ListBuckets: 10000. |
| Lifecycle rules | 1000 |
| CORS rules | 100 |
| Website routing rules | 50 |
| Bucket policy | 20480 bytes, normalized |
| Object Lock default retention | 36500 days or 100 years |
| Presigned URL lifetime | 7 days |
| Clock skew | ±15 minutes |
| aws-chunked signed chunk | ≥ 8 KiB, except the last |
| Version IDs | 32 characters, or `null` |
| IAM and STS limits | [§21](#behavior-and-limits), [§22](#22-sts-api) |

---

## 28. Summary of deviations from AWS

The most significant differences, for quick reference. Each is described in its section above.

**Transport and authentication**
- **TLS and HTTP/2:** HTTP/1.1 only, without TLS. A TLS proxy is needed.
- **Signatures:** SigV2 and SigV4A are unsupported. SigV2 presigned URLs are treated as anonymous.
- **Request time:** `Date` is not accepted in place of `x-amz-date`.
- **Scope:** the region and service in the credential scope aren't validated.
- **Error codes:** `AuthorizationHeaderMalformed` is never returned. Signature and skew errors have no detail elements.
- **Canonicalization:** the canonical query string uses the wire encoding as-is.
- **Host names:** only one `--domain` is possible.

**Buckets and listings**
- **CreateBucket:** for the caller's own existing bucket it answers `200`, never `BucketAlreadyOwnedByYou`. `LocationConstraint` is ignored.
- **Regions:** none. `GetBucketLocation` is empty, and no region headers or fields are sent.
- **ListBuckets:** it has no XML namespace and no `BucketRegion`.
- **Tokens and markers:** ListObjectsV2 tokens are transparent. A marker naming a common prefix skips it (as MinIO).
- **ListObjects v1:** `NextMarker` is sent without a delimiter, and `Prefix` isn't URL-encoded. An unknown `list-type` gives v1.
- **ListParts:** an invalid marker is read as 0. `max-parts=0` can report truncation forever.

**Objects**
- **Storage classes:** STANDARD only. `x-amz-storage-class` is accepted and ignored. There are no transitions or restore.
- **ETags:** SSE-C and SSE-KMS ETags are random.
- **Ranges:** multiple or malformed ranges return the whole object. `bytes=b-a` is 416. 416s carry no `Content-Range`.
- **Conditional writes:** there is no `409 ConditionalRequestConflict`. Date conditions on writes are ignored. There are no conditional deletes.
- **Ignored headers:** `x-amz-expected-bucket-owner`, `x-amz-request-payer`, `x-amz-mfa` and `x-amz-write-offset-bytes` are all ignored.
- **Metadata:** non-ASCII values are refused. The 2 KiB limit doesn't count the `x-amz-meta-` prefix.
- **GetObjectAttributes:** ignores conditional headers.
- **Content-Length:** a PutObject without it is accepted.
- **CopyObject:** a self-copy changing only the storage class or redirect is refused. The copy's checksum is always FULL_OBJECT. `CopyObjectResult` and `CopyPartResult` have no XML namespace.
- **POST Object:** there is no clock-skew check. `x-amz-website-redirect-location` and a field named `x-amz-acl` are dropped. The SSE-C fields are exempt from policy conditions, and `content-length-range` bounds may be strings (as MinIO).

**Multipart**
- **CompleteMultipartUpload:**
  - There is no `<Location>`.
  - InvalidPartOrder is checked before NoSuchUpload.
  - `If-None-Match` with an ETag is evaluated, not answered with 501.
- **Checksums:** CRC64NVME COMPOSITE becomes FULL_OBJECT. Uploads get a CRC64NVME checksum by default.
- **Refused and missing headers:** SSE headers on part and complete requests get 501. There is no `x-amz-abort-date`.

**Features**
- **ACLs:** only owner-only ACLs, and `private` is refused on objects. Ownership is fixed at `BucketOwnerEnforced`.
- **Unimplemented features:** MFA delete, lifecycle transitions, replication, logging, notifications, inventory, analytics, metrics, Intelligent-Tiering, Select, torrents, S3 Express, metadata tables, access points and Object Lambda.
- **Lifecycle:** rules run in a daily, rate-limited sweep. `x-amz-expiration` is never sent.
- **Versioning:** writes to the null version in a suspended bucket report no version ID.

**Encryption**
- **Defaults:** objects aren't encrypted unless asked to be, or unless the bucket has a default.
- **Cipher:** XChaCha20-Poly1305, under the `AES256` name.
- **SSE-KMS:**
  - It runs on OpenBao/Vault Transit.
  - Key IDs are `<mount>/<key>`; there are no AWS ARNs and no aliases.
  - There is no default `aws/s3` key.
  - Access is decided by OpenBao's policies, not `kms:` actions.
  - Bucket keys are ignored. DSSE-KMS is refused.
- **Misplaced headers:** SSE headers on reads are `400 BadRequest`.

**Policies**
- **Unsupported condition keys:** 13 `s3:` keys are refused with 501, including the object-tag and bucket-tag keys and `s3:TlsVersion`.
- **Tags in conditions:** `aws:RequestTag`, `aws:ResourceTag` and `aws:TagKeys` are never set on S3 requests.
- **Absent keys:** organization, VPC and service keys are never present.
- **Missing keys:** they are hidden as 403 only on GetObject, HeadObject and GetObjectAttributes.

**IAM and STS**
- **Unknown IAM actions:** `501`, not `400 InvalidAction`.
- **Missing features:** groups, MFA devices, login profiles, SAML, instance profiles and policy simulation.
- **Identifiers:** access key IDs have no `AKIA` prefix. User names and paths allow fewer characters.
- **Paging:** several IAM list actions ignore paging.
- **AssumeRoleWithWebIdentity:** unsigned only. Only the `sub`, `aud` and `amr` claims become condition keys.
- **OIDC providers:** contacted at creation. Thumbprints are enforced as pins.
- **GetFederationToken:** tags don't need `sts:TagSession`.
- **Accounts:** one account per cluster.
