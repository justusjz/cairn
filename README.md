# Cairn

A simple, reliable S3-compatible object storage system. Run it on one machine,
or spread it across several for redundancy. Cairn keeps your data safe and
serves it through the familiar S3 API, using PostgreSQL to keep everything
consistent.

## Requirements

- A reachable **PostgreSQL** database (shared by every node), with UTF-8
  encoding (the default), so that keys sort as S3 sorts them. Cairn creates its
  own schema on first start.
- A local **data directory** per node for storing blobs.

The schema is created automatically; just point Cairn at an empty database.

> [!WARNING]
> The peer endpoint (`--listen-peer`, default `127.0.0.1:9431`) is
> unauthenticated: it can read and delete blobs, and it serves the
> [dashboard](#dashboard), which manages roles. Only bind it to a
> trusted/private network — never expose it to the public internet.

## Installing

Download the static binary from the
[releases page](https://github.com/justusjz/cairn/releases) and extract it
(replace `<version>` with the release you downloaded, e.g. `0.5.1`, and
`x86_64` with `aarch64` on 64-bit ARM):

```sh
tar xzf cairn-v<version>-x86_64-unknown-linux-musl.tar.gz
sudo install -m755 cairn-v<version>-x86_64-unknown-linux-musl/cairn /usr/local/bin/cairn
```

It is statically linked (musl), so it runs on any x86-64 or ARM64 Linux with no
dependencies.

### Docker

Every release is also published as an image, for amd64 and arm64:
`ghcr.io/justusjz/cairn:<version>` (and `:latest`). It runs `cairn serve`,
configured through the [environment](#serve-flags), with these defaults:
the S3 API on `0.0.0.0:9000`, the peer endpoint on `0.0.0.0:9431`, and data in
the volume `/var/lib/cairn`. Only the database has to be set:

```sh
docker run -d --name cairn -p 9000:9000 \
    -e CAIRN_DATABASE="postgres://user:pass@db.internal:5432/cairn" \
    -v cairn-data:/var/lib/cairn \
    ghcr.io/justusjz/cairn:<version>
docker exec cairn cairn user create admin --admin
```

For a cluster, also set `CAIRN_PEER_URL` to an address the other nodes can
reach this container at, and `CAIRN_REPLICATION_FACTOR`.

## Running a single node

The simplest deployment — one node, replication factor 1, no redundancy:

```sh
cairn serve \
    --database "postgres://user:pass@localhost:5432/cairn" \
    --listen-client 0.0.0.0:9000 \
    --data-dir /var/lib/cairn/data
```

The S3 API is now served on `:9000`. Every request must be signed (SigV4) with
the credentials of a user, and a fresh database has none. Create an admin user
to manage buckets, and an application user with access to a bucket (see
[Users and permissions](#users-and-permissions)):

```sh
DB="postgres://user:pass@localhost:5432/cairn"
cairn user --database "$DB" create admin --admin        # prints a generated secret
cairn user --database "$DB" create app                  # prints a generated secret
```

Create a bucket as the admin, grant the application user access to it, and use
it:

```sh
s3cmd --host=localhost:9000 --host-bucket=localhost:9000 --no-ssl \
    --access_key=admin --secret_key=<admin secret> mb s3://my-bucket
cairn user --database "$DB" grant app my-bucket read write
s3cmd --host=localhost:9000 --host-bucket=localhost:9000 --no-ssl \
    --access_key=app --secret_key=<app secret> put file.txt s3://my-bucket/
```

### `serve` flags

Every flag can also be set through its environment variable; a flag on the
command line wins. `cairn user` reads `CAIRN_DATABASE` as well.

| Flag | Environment | Default | Description |
| --- | --- | --- | --- |
| `--database <URL>` | `CAIRN_DATABASE` | *required* | PostgreSQL connection string. Shared by all nodes. |
| `--listen-client <ADDR>` | `CAIRN_LISTEN_CLIENT` | *required* | Bind address for the S3 API. |
| `--listen-peer <ADDR>` | `CAIRN_LISTEN_PEER` | `127.0.0.1:9431` | Bind address for the peer endpoint (replica traffic between nodes). Always runs. |
| `--peer-url <URL>` | `CAIRN_PEER_URL` | `http://<listen-peer>` | URL other nodes use to reach this node. Set explicitly when `--listen-peer` is a wildcard/private address (e.g. `http://10.0.0.1:9431`). |
| `--replication-factor <N>` | `CAIRN_REPLICATION_FACTOR` | `1` | How many distinct nodes each blob is stored on, until the cluster's `parity-shards` setting is set (see below), which overrides it on every node. |
| `--data-dir <PATH>` | `CAIRN_DATA_DIR` | *required* | Local directory for blobs. |
| `--allow-sse-c-over-http` | `CAIRN_ALLOW_SSE_C_OVER_HTTP` | off | Accept [SSE-C](#sse-c) keys in requests no proxy marked as HTTPS. Only for a network that's encrypted itself. |
| `--trusted-proxy <CIDR>` | `CAIRN_TRUSTED_PROXIES` (comma-separated) | none | A proxy in front of Cairn, whose `X-Forwarded-For` and `X-Forwarded-Proto` [policies](#users-and-permissions) believe (`aws:SourceIp`, `aws:SecureTransport`). May be given several times. |
| `--domain <NAME>` | `CAIRN_DOMAIN` | none | The domain the S3 API is reached at, e.g. `s3.example.com`, to take [virtual-hosted-style](#virtual-hosted-style-requests) requests. |
| `--listen-console <ADDR>` | `CAIRN_LISTEN_CONSOLE` | off | Bind address for the [console](#console), the web UI people sign in to with passkeys. Requires `--console-url`. |
| `--console-url <URL>` | `CAIRN_CONSOLE_URL` | none | The URL the console is reached at, as browsers see it, e.g. `https://console.example.com`: an origin of its own (not the S3 API's), over HTTPS, or on `localhost`. Passkeys are bound to its host. |
| `--kms-address <URL>` | `CAIRN_KMS_ADDRESS` | none | OpenBao (or Vault) server holding the keys for [SSE-KMS](#sse-kms), e.g. `https://bao.internal:8200`. Without it, SSE-KMS is refused. |
| `--kms-jwt-key <PATH>` | `CAIRN_KMS_JWT_KEY` | *required with a KMS* | PEM file of the Ed25519 private key Cairn signs its roles' logins to the KMS with. The same on every node. |
| `--kms-auth-mount <PATH>` | `CAIRN_KMS_AUTH_MOUNT` | `cairn` | Where the KMS's JWT auth method for Cairn is mounted. |
| `--kms-auth-role <NAME>` | `CAIRN_KMS_AUTH_ROLE` | `s3` | The role of that auth method Cairn's logins use. |
| `--kms-sse-s3-key <ID>` | `CAIRN_KMS_SSE_S3_KEY` | none | The key for [SSE-S3](#sse-s3) (`<mount>/<key>`), which Cairn uses as itself. Without it, SSE-S3 is refused. |
| `--kms-ca-cert <PATH>` | `CAIRN_KMS_CA_CERT` | public roots | PEM file of the CA certificates to trust for the KMS's TLS. |
| `--scrub-rate <RATE>` | `CAIRN_SCRUB_RATE` | `25MiB` | How many bytes per second the [scrubber](#scrubbing) reads, e.g. `100MB`. `0` turns it off. |

On SIGTERM or Ctrl-C, a node stops accepting connections and finishes the
requests in flight before it exits; a second signal exits right away. Anything
cut off is cleaned up by [garbage collection](#garbage-collection), as after a
crash.

### Virtual-hosted-style requests

Clients reach a bucket path-style by default (`s3.example.com/bucket/key`).
With `--domain s3.example.com`, they may also name it in the host, as
`bucket.s3.example.com/key`, which some clients do by default. A request to
any other host (the domain itself, an IP address) is still path-style, so both
work side by side. As in S3, the bucket is all of the host before the domain,
so `my.bucket.s3.example.com` is the bucket `my.bucket`.

Cairn only reads the `Host` header, which the proxy in front of it must pass on
as the client sent it (the request's signature covers it, too). DNS and TLS
are up to you: a wildcard record for `*.s3.example.com`, and a certificate for
it. A wildcard certificate covers one label only, so it doesn't cover buckets
with dots in their names; clients reach those path-style instead, as with S3.

## Running a highly-available cluster

For redundancy, run several nodes against the **same Postgres database** with a
`--replication-factor` greater than 1. Each node needs its own
`--listen-client`, its own `--listen-peer`, and its own `--data-dir`. Because
the peer endpoint must be reachable by the other nodes, set `--peer-url` to an
address they can actually connect to.

Example: a 3-node cluster with replication factor 2 (every blob stored on 2 of
the 3 nodes), where the nodes reach each other at `10.0.0.1`–`10.0.0.3`:

```sh
# Node 1 (on 10.0.0.1)
cairn serve \
    --database "postgres://user:pass@db.internal:5432/cairn" \
    --listen-client 0.0.0.0:9000 \
    --listen-peer   0.0.0.0:9431 \
    --peer-url      http://10.0.0.1:9431 \
    --replication-factor 2 \
    --data-dir /var/lib/cairn/data

# Node 2 (on 10.0.0.2)
cairn serve \
    --database "postgres://user:pass@db.internal:5432/cairn" \
    --listen-client 0.0.0.0:9000 \
    --listen-peer   0.0.0.0:9431 \
    --peer-url      http://10.0.0.2:9431 \
    --replication-factor 2 \
    --data-dir /var/lib/cairn/data

# Node 3 (on 10.0.0.3) — same as above with --peer-url http://10.0.0.3:9431
```

Nodes discover each other through Postgres (each heartbeats every 5 seconds), so
there is no peer list to configure — just point them all at the same database.
A node is considered live if it has been seen in the last 10 seconds. Clients
can talk to any node; reads are transparently served from whichever replica
holds the data.

With replication factor `N`, writes succeed as long as at least `N` nodes are
live; if fewer than `N` are available, uploads are rejected (metadata operations
still work, since they live in Postgres).

The replication factor is better set once for the whole cluster, in the
database, than on every node, where the nodes can disagree. It's the
`parity-shards` setting plus 1: the copies besides the first. Once it's set,
every node goes by it (within a heartbeat), and ignores its flag:

```sh
cairn config --database "$DB" set parity-shards 2     # 3 copies of every new blob
cairn config --database "$DB" unset parity-shards     # back to each node's flag
```

A change applies to blobs written from then on, and existing blobs are
brought to it in the background: the mover adds or drops copies, and the
packer rewrites erasure-coded blobs. While the setting isn't set, existing
blobs keep their copies, since nodes may go by different flags.

Large blobs can be stored with less overhead than full copies, with the same
tolerance for lost nodes: see [Erasure coding](#erasure-coding).

### Removing nodes, and repair

Every blob is stored as shards, each on a node of its own (a copy of the
blob, or a piece of it if it's [erasure-coded](#erasure-coding)). To take a
node out of the cluster, remove it:

```sh
cairn node --database "$DB" list          # nodes, their state, the shards they hold
cairn node --database "$DB" remove 3
```

A node that's being removed gets no new data, and every node moves its shards
to other nodes in the background: copied from it while it's up, so redundancy
never drops, or rebuilt from the other shards if it's down, which is how a
node that's gone for good is replaced. The blobs with the least redundancy
left go first. A shard moves only to a node that holds no other shard of its
blob, so with no such node to spare, it waits. Once the node holds nothing,
its state is `removed`, and it can be shut down. `cairn node keep 3` stops a
removal; whatever has moved stays moved.

A node that's merely down keeps its shards: reads get them from the others
meanwhile, and nothing moves, since rebuilding moves a lot of data, and a
node back from a reboot needs none of it. To have a node's shards rebuilt
once it has been down for long enough, without removing it, set:

```sh
cairn config --database "$DB" set repair-after 60   # minutes; 0, the default, is off
```

The dashboard's Overview shows each node's state, and its Jobs page how many
shards are waiting to move.

## Users and permissions

A **user** (called a role before; `cairn role` still works) is who makes S3
requests. It has **access keys**: up to two, as in IAM, each an access key ID
and a secret; its first key's ID is the user's name. Users are stored in
Postgres, so every node picks up a change on the very next request; there is
nothing to restart or sync.

What a user may do is decided by policies, in IAM's policy language, as in
S3: an explicit `Deny` in any that applies wins; else an `Allow` in any
allows; else it's denied. They are:

- **admin** (`--admin`): the built-in managed policy `AdministratorAccess`,
  as AWS's: everything in the user's account (its buckets, their objects
  and configuration), but what a bucket's policy denies it.
- its **grants**, the simple way, which are statements of the bucket's
  policy (`CairnGrantRead`, `CairnGrantWrite`, `CairnGrantDeleteVersion`,
  each naming the users granted it), so they go with the bucket, and show
  in GetBucketPolicy as what they are. Setting a bucket's policy over S3
  replaces its grants too, as it replaces any statement; the dashboard and
  console show them as grants, and leave the policy's other statements
  alone:
  - **`read`** on a bucket: GetObject, HeadObject, GetObjectAttributes,
    HeadBucket, ListObjects, reading an object's [tags](#tags), and being the
    source of a
    CopyObject / UploadPartCopy.
  - **`write`** on a bucket: PutObject, DeleteObject(s), multipart uploads
    (listing them and their parts too, to resume one), changing an object's
    tags (any version's), and being the destination of a copy. In a
    versioned bucket, a delete only adds a delete marker.
  - **`delete-version`** on a bucket: DeleteObject(s) naming a version ID,
    which removes that version for good.
- its **inline policies**: identity policies of its own, for anything finer
  (per key prefix, by condition, ...), set with `cairn user policy`;
- each bucket's **bucket policy**, set with PutBucketPolicy (by an admin), as
  in S3. A bucket policy can allow other users, or anyone: unsigned requests
  are **anonymous**, and only a bucket policy with `"Principal": "*"` can
  allow them (a public bucket, say). Users are named in policies as
  `arn:aws:iam::<account>:user/<name>`; their account's ID is in
  `cairn user list`. As in S3, a bucket policy names the user that
  had the name when the policy was set: a user deleted and created again
  under the same name isn't allowed what the first was, and the policy then
  shows the first by its ID.

**Accounts**, as AWS's: every user and bucket belongs to one (a 12-digit ID,
and a name). The users and buckets from before accounts are the `default`
account's. A user's policies reach only its own account's buckets: another
account's bucket also needs that bucket's policy to allow the request, as in
AWS. Bucket names stay global; a name another account has is
`BucketAlreadyExists`. The **operator account** is the superadmins': it owns
no buckets. `cairn account list`, `cairn account create <name>`, and
`cairn user create --account <name>` manage them. Each account has a
**root**, the account itself (`arn:aws:iam::<account>:root`), which signs in
to the [console](#console) only (no access keys): it may do anything in its
account but what its buckets' policies deny it, and it may always get, set
and delete those policies, as AWS's root may, so a policy that denies
everyone can't lock its bucket for good. `cairn account enroll <name>` makes
its enrollment link (a new account's first, or one for a root that lost its
passkeys).

```sh
aws s3api put-bucket-policy --bucket my-bucket --policy '{"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
     "Resource": "arn:aws:s3:::my-bucket/public/*"}]}'
```

Policies are checked as S3 checks them when they're set (with S3's error
messages), and decide requests as S3's do, condition keys and all. A policy
naming a condition key Cairn can't decide yet (an object's existing tags,
say) is refused with `501 NotImplemented`, rather than taken and decided
wrongly. A denied request gets S3's `403 AccessDenied`, which tells a user
why (`... with an explicit deny in a resource-based policy`); a key that
doesn't exist is a 403 too, to whom may not list the bucket, so that keys
can't be found by guessing.

**Block Public Access** guards against making a bucket public by accident,
as in S3. A bucket's public access block (PutPublicAccessBlock, or the
bucket's *Policy and public access* on the dashboard) has S3's four flags:
`BlockPublicPolicy` refuses a bucket policy that makes the bucket public
(one that allows everyone something, with no condition that limits it to
fixed addresses, accounts or the like), and `RestrictPublicBuckets` makes a
public policy allow anonymous requests nothing (the cluster's users keep what
it allows them). `BlockPublicAcls` and `IgnorePublicAcls` are kept for S3
clients; Cairn refuses every ACL but `private` anyway. **New buckets have all
four on**, as S3's do, so making one public takes turning its block off first
(`aws s3api delete-public-access-block`); buckets made before Cairn had
blocks have none. The cluster has a block of its own, which every bucket gets
too, whatever its own says: `cairn config set block-public-policy 1` and
`cairn config set restrict-public-buckets 1` (or the switches on the
dashboard's Buckets page).

```sh
aws s3api delete-public-access-block --bucket my-bucket   # then put the public policy above
```

`aws:SourceIp` and `aws:SecureTransport` (and so policies that ask for an
address, or for HTTPS) take the client's address and protocol from
`X-Forwarded-For` and `X-Forwarded-Proto` only if the request came from a
`--trusted-proxy`; otherwise, the connection's own address counts, and it's
not HTTPS (Cairn speaks only HTTP).

A user sees the buckets it holds a grant on in ListBuckets (or all of them,
if a policy allows it `s3:ListAllMyBuckets`, as admin does). A bucket must
exist before you can grant access to it, so the setup order is: an admin
creates the bucket (with any S3 client), then you grant users access.
Deleting a bucket removes its grants, so a bucket re-created under the same
name starts with no access for anyone; inline policies name buckets by name,
and outlive them, as in AWS.

There are no ACLs: as with S3's default for new buckets ("bucket owner
enforced"), access is a matter of grants alone. A request that asks for an ACL
other than the owner's (`bucket-owner-full-control` for an object, `private`
for a bucket) is refused with `AccessControlListNotSupported`, as S3 refuses
it; one asking for the owner's is fine, and reading an ACL shows the owner with
full control.

Bucket names follow S3's rules: 3 to 63 lowercase letters, digits, dots and
hyphens, starting and ending with a letter or digit, not formatted like an IP
address, and without the prefixes and suffixes S3 reserves (such as `xn--` or
`-s3alias`).

Manage users with `cairn user --database <URL> <command>`:

| Command | Description |
| --- | --- |
| `create <name> [--admin] [--secret <S>] [--account <A>]` | Create a user, with an access key named as it. Prints a generated 40-char secret unless `--secret` is given (min. 8 chars). |
| `update <name> [--admin true\|false] [--rotate-secret \| --secret <S>]` | Toggle admin, or replace the secret of the key named as the user (`--rotate-secret` prints the new one). |
| `delete <name>` | Delete a user, with its keys, grants and policies. |
| `grant <name> <bucket> <read\|write\|delete-version>...` | Grant permissions on an existing bucket. |
| `revoke <name> <bucket> [read\|write\|delete-version]...` | Revoke permissions on a bucket; all of them if none are listed. |
| `key create <name> [--id <ID>] [--secret <S>]` | Make the user another access key (at most two). Prints its ID and secret. |
| `key activate\|deactivate\|delete <ID>` | Let a key sign requests, stop it, or delete it. |
| `policy put <name> <policy> <file>` | Set an inline policy (JSON; `-` reads stdin). A user's policies hold at most 2048 characters together, as in IAM. |
| `policy get\|delete <name> <policy>` | Show or delete an inline policy. |
| `list` | List users, their ARNs, admin flags, keys, grants and policies (secrets are not shown). |
| `enroll <name> [--console-url <URL>]` | Print a one-time link (24 hours) for the user to sign in to the [console](#console): a new login with a passkey, or (opened signed in) added to the login. A new link replaces the last. |

**The IAM API** is on the S3 endpoint too: requests signed for the `iam`
service (SigV4's credential scope) are IAM's, whatever their path, so the AWS
CLI, SDKs and Terraform manage users with Cairn as their IAM endpoint (the
same URL as for S3: `aws iam --endpoint-url ...`, or Terraform's
`endpoints { iam = ... }`). Each request acts as its signer, in its account,
checked as IAM's actions on the user's ARN (`iam:CreateUser`,
`iam:CreateAccessKey`, `iam:PutUserPolicy`, ...): an admin may do all of it,
another user what its policies allow (its own keys, with a policy on
`arn:aws:iam::*:user/${aws:username}`, say). There are users (CreateUser,
GetUser, ListUsers, DeleteUser, which refuses while keys or policies are
left, as IAM does), access keys (Create, List, Update, Delete), inline
policies (Put, Get, List, Delete), and the one managed policy,
`arn:aws:iam::aws:policy/AdministratorAccess` (Attach, Detach,
ListAttached: the admin flag). Groups, roles, managed policies of one's own,
paths, tags and permissions boundaries are NotImplemented. STS's
`GetCallerIdentity` answers too (signed for `sts`), which Terraform's AWS
provider calls as it starts. The AWS CLI refuses access key IDs shorter than
16 characters as parameters (`--access-key-id`): the keys IAM makes are 20,
but a user's first key is named as the user.

A bucket policy can deny everyone everything, its admins too, as in S3. The
superadmin, with access to the database, can always remove it, as an AWS
account's root user can: `cairn bucket-policy --database <URL> delete
<bucket>` (or `get`, or `put <bucket> <file>`).

Secrets are stored in plaintext in the `access_keys` table: SigV4 is an HMAC scheme,
so verifying a signature needs the secret itself. Restrict access to the
database accordingly.

A signed request is only accepted within **15 minutes** of its timestamp
(either way), as in S3, so a captured request can't be replayed later. Keep the
clocks of nodes and clients in sync (e.g. NTP); otherwise requests fail with
`RequestTimeTooSkewed`.

**Presigned URLs** (SigV4 in the query string) work as in S3: a URL signed
with a user's credentials makes exactly that request, as that user, for as
long as it says (`X-Amz-Expires`, at most 7 days), with nothing but an HTTP
client, a browser say. Its body is unsigned. GetObject and HeadObject take
S3's `response-*` parameters (`response-content-disposition`,
`response-content-type`, …), which set those headers of the response, so that
a link can download an object under a name of its own. Only SigV4 is
supported: `aws s3 presign` makes SigV2 URLs unless its config has
`signature_version = s3v4` under `s3`. For an SSE-C object, the URL has to be
signed with the key's headers, and the client has to send them.

**POST Object** (browser-based uploads) works as in S3: a `multipart/form-data`
form posted to a bucket, with a POST policy signed with a user's credentials
(SigV4, as boto3's `generate_presigned_post` makes them), uploads its file as
that user, if the policy allows the form (and the user may make that
PutObject): until its expiration, with a key
under a prefix, say, or of a size in `content-length-range`. A file over the
size is refused as soon as it's over. The form's fields are what a PutObject's
headers would be (content headers, `x-amz-meta-*`, checksums, SSE-S3, SSE-KMS,
SSE-C, which is exempt from the policy's conditions, as in MinIO), and every
one of them must be in the policy. `success_action_status` and
`success_action_redirect` say how to answer. For a page on another site to
send it with `fetch` (or to use a presigned URL), the bucket needs a
[CORS configuration](#cors). A form without any signature (no policy, no
credential) is anonymous: like any anonymous request, only a
[bucket policy](#users-and-permissions) that allows everyone `s3:PutObject`
on its key takes it.

> [!NOTE]
> Cairn speaks plain HTTP. To expose it publicly, put a TLS-terminating reverse
> proxy in front of it. The proxy must pass the `Host` header through unchanged,
> since it is part of the signature.

## Dashboard

Every node serves a web dashboard for watching and managing the cluster, on its
peer endpoint, under `/_dashboard`: open the peer URL in a browser, e.g.
`http://10.0.0.1:9431/` (or `http://127.0.0.1:9431/` with the default
`--listen-peer`), which leads there. Any node's dashboard shows the whole
cluster:

- **Overview:** which nodes are live, how full their disks are, and request
  rates, errors, throughput and latency over the last hour, by S3 operation.
  Nodes can be [removed](#removing-nodes-and-repair) (and kept) there.
- **Storage:** how much data there is, in which layouts (replicated, or
  [erasure-coded](#erasure-coding)), how much of it has fewer live shards
  than it should, and what each node holds; and the redundancy settings,
  which can be changed there: `parity-shards`, `data-shards` and
  `repair-after`.
- **Integrity:** what the [scrubbers](#scrubbing) checked and found: per
  node, how long a full check takes at its rate and how recently its data was
  checked; damaged and missing copies, and whether they were repaired; and
  the objects with data that's intact on no replica. The navigation shows how
  many of those there are (in red), or else how many findings are still
  open. The bucket explorer marks objects with lost data, and an object's
  details name the bytes that are lost.
- **Jobs:** how the background passes (garbage collection and packing) are
  doing on each node, what they still have to do, and what they did recently;
  and the [lifecycle](#lifecycle-rules) sweeps: each bucket's, how long a
  round of them takes, and the rate they go at, which can be changed there.
- **Buckets:** browse buckets by prefix, see every version of a key with how
  it's encrypted, the blobs its parts are stored in and the nodes holding
  them, and download any version (but an encrypted one: Cairn doesn't have
  an SSE-C object's key, and the KMS opens an SSE-KMS one only for a role).
  Buckets can be created and (when empty) deleted, and their
  [lifecycle rules](#lifecycle-rules), bucket policies and public access
  blocks edited; the list shows which buckets are public, and has the
  cluster's own public access block.
- **Users:** everything `cairn user` does: create and delete users, grant and
  revoke permissions, toggle admin, make, deactivate and delete access keys
  (replacing the secret of the one named as the user in place), write
  inline policies, which the server checks as IAM does, and make
  [console](#console) enrollment links. Each user's ID and
  its identity in the KMS are shown, for granting it [KMS keys](#sse-kms).

To keep other websites from reaching it through DNS rebinding, the dashboard
only answers when it's opened by IP address, as `localhost`, or by the host of
the node's `--peer-url`.

Request metrics are kept in memory by each node, so they start over when it
restarts; everything else is read from the database.

The dashboard's JSON API is under `/_dashboard/api/`, described by an OpenAPI
spec at `/_dashboard/api/openapi.json` (also committed as `ui/openapi.json`).

> [!WARNING]
> Like the rest of the peer endpoint, the dashboard has no authentication:
> anyone who can reach it can read every unencrypted object and manage every
> role, and so act as any role, with the KMS keys it may use. Keep the peer
> endpoint on a trusted network.

### Building the dashboard

The dashboard's UI lives in `ui/` (SolidJS and TypeScript, built with Vite)
and is embedded into the binary when Cairn is built, so build it first (with
Node.js 26 or later). Cargo doesn't run npm itself: without a build of the UI,
building Cairn (or running its tests) fails and says how to build it, and it
warns when the build is older than the UI's sources.

```sh
(cd ui && npm ci && npm run build)
cargo build --release
```

`./build-release.sh` does both. While working on the UI, `npm run dev` in
`ui/` serves it with hot reloading, passing API requests on to the node at
`CAIRN_URL` (default `http://127.0.0.1:9431`). The [console](#console) is a
second page of the same UI (`ui/console.html`, built into `ui/dist/console/`);
`npm run dev:console` serves it, passing its API on to `CAIRN_CONSOLE`
(default `http://localhost:9480`).

The UI's types come from the API's OpenAPI spec, which is generated from the
Rust code (with [utoipa](https://github.com/juhaku/utoipa)). Both the specs
(`ui/openapi.json`, and the console's `ui/console-openapi.json`) and the
TypeScript types made from them for
[openapi-fetch](https://openapi-ts.dev/openapi-fetch/) (`ui/src/schema.d.ts`,
`ui/src/console/schema.d.ts`) are committed, so building needs neither generator. A test fails when the
committed spec no longer matches the API; after changing the API, regenerate
both:

```sh
CAIRN_UPDATE_OPENAPI=1 cargo test openapi
(cd ui && npm run gen)
```

`npm run gen` runs [openapi-typescript](https://openapi-ts.dev/) through `npx`,
with pinned versions and the TypeScript 5 it needs (the UI itself uses
TypeScript 7), so it needs network access.

## Console

The console is a web UI for the account's people, apart from the dashboard
(which is the operator's, on the private network, without a sign-in). It's
off unless a node is started with `--listen-console` and `--console-url`.
People sign in with **passkeys** only: there are no passwords, and access
keys are for S3, never for the console. A **login** (a person, with
passkeys) acts in each account it's in as one identity there, a user or the
account's root, and switches between them; switching into the operator
account takes the passkey again, unless it was used in the last five
minutes. An enrollment link is for an identity: opened signed out, it makes
a new login; signed in, it adds the identity to that login. Signed in,
people manage their passkeys, their account's users (as IAM's actions
allow them: an admin may do all of it; others what their policies say, as
`iam:CreateAccessKey` on their own user, say), and the buckets and objects: create and delete buckets, browse,
upload (up to 5 GiB a file), download and delete objects and versions,
versioning, lifecycle rules, bucket policies and public access blocks.
Superadmins (the operator account's users) see the cluster instead: the
dashboard's Overview, Storage, Integrity and Jobs pages, the accounts (making
one, and its root's enrollment link), and each other, but no tenant's
buckets. Their actions are `cairn:` ones (`cairn:GetCluster`,
`cairn:PutSetting`, `cairn:RemoveNode`, `cairn:CreateAccount`, …) on the
cluster, which is the operator account's, so a tenant's policies can't allow
them.

The console acts as its user: it allows exactly what that user's S3 requests
would be allowed, by the same policies (the user's grants, admin flag and
inline policies, and the bucket's policy; an explicit Deny wins), and denies
with S3's messages. An admin creates buckets, but reads and writes objects
only with a grant or a policy that allows it, as over S3. The bucket and
object pages are the dashboard's, and so is their API: the dashboard serves
it to the operator (everything is allowed), the console to the signed-in
user. Downloads are always attachments, sandboxed, so that nothing of an
object is shown in the console's origin; SSE-KMS objects open with the keys
the user may use.

- **Its own origin.** Serve it at a host name of its own, never the S3 API's:
  objects are served from that origin with whatever `Content-Type` they were
  uploaded with, so an HTML object there could act in the console as whoever
  opens it. Cairn speaks plain HTTP: put a TLS-terminating proxy in front
  (`http://localhost` works for trying it out, as browsers treat it as
  secure). Passkeys are bound to the console URL's host, so changing it
  makes everyone enroll again.
- **Enrollment.** A user gets a first passkey through a one-time link, valid
  24 hours: `cairn user enroll <name> --console-url <URL>`, or the Users page
  of the dashboard. Once signed in, people add more passkeys (at most 8; a
  second one, on another device, keeps them from being locked out) and remove
  them, but never their last. A lost passkey takes a new link.
- **Sessions** last 12 hours at most, and end after an hour unused. They're a
  cookie (`__Host-`, Secure, HttpOnly, SameSite=Strict), kept in the database
  as a hash, so every node serves them. Removing a passkey or the user ends
  the sessions signed in with it. Changes must come from the console's own
  page (its `Origin`).
- **Passkeys** are checked by Cairn itself (WebAuthn, with EdDSA, ES256 or
  RS256 keys), with user verification (a PIN or biometrics) every time, and
  without attestation: any authenticator works. A passkey whose signature
  counter goes backwards (a cloned security key) is refused.

```sh
cairn serve ... --listen-console 0.0.0.0:9480 --console-url https://console.example.com
cairn user enroll ada --console-url https://console.example.com
```

## Versioning

Buckets support S3 versioning, which keeps every version of an object instead
of overwriting it. This is what makes Cairn a ransomware-resistant backup
target: a client that can write and delete (e.g. restic) can't destroy the
history, as long as it isn't granted `delete-version`, nor is an admin. Admins
can set [lifecycle rules](#lifecycle-rules), which may remove old versions, as
a bucket's owner can in S3; keep admin credentials away from the machines
being backed up.

An admin enables it per bucket with any S3 client:

```sh
aws s3api put-bucket-versioning --bucket my-bucket \
    --versioning-configuration Status=Enabled
```

A bucket starts out unversioned, and once enabled can only be switched between
`Enabled` and `Suspended`, never back. As in S3:

- **Enabled:** every write creates a new version with its own ID, and a delete
  without a version ID only adds a *delete marker*, hiding the object from
  GET and listings while every version stays readable by ID.
- **Suspended:** existing versions are kept, but new writes replace the single
  `null` version, and a delete replaces it with a `null` delete marker.
  Overwriting or deleting an object then destroys its `null` version, so
  suspending versioning gives up the protection for new writes.
- Reading a specific version (`?versionId=`) needs `read`; removing one for
  good needs `delete-version`. A bucket with any versions or delete markers
  left counts as non-empty and can't be deleted.

To find old versions, list them (ListObjectVersions, which needs `read`); to
restore one, copy it onto its own key, which makes it the current version again:

```sh
aws s3api list-object-versions --bucket my-bucket --prefix some/key
aws s3api copy-object --bucket my-bucket --key some/key \
    --copy-source 'my-bucket/some/key?versionId=<version id>'
```

Old versions take up space until they're deleted, by hand or by
[lifecycle rules](#lifecycle-rules).

## Lifecycle rules

A bucket's lifecycle configuration expires objects automatically, as in S3.
Setting one is bucket management, as `PutLifecycleConfiguration` is its own
permission in S3, so only an admin can, and needs no grant on the bucket's
objects: the rules are carried out by Cairn, not as the admin. A role that may
only write can't make its writes expire, nor stop an admin's rules. (S3 keeps
versions from lifecycle rules with Object Lock, which Cairn doesn't have yet.)

```sh
aws s3api put-bucket-lifecycle-configuration --bucket my-bucket \
    --lifecycle-configuration '{"Rules": [{
        "ID": "logs", "Filter": {"Prefix": "logs/"}, "Status": "Enabled",
        "Expiration": {"Days": 30},
        "NoncurrentVersionExpiration": {"NoncurrentDays": 7}}]}'
aws s3api get-bucket-lifecycle-configuration --bucket my-bucket
aws s3api delete-bucket-lifecycle --bucket my-bucket
```

Or on the dashboard: a bucket's page links to an editor of its rules, which
the dashboard checks as S3's requests are checked, and writes back in the same
form, so S3 clients see the same rules.

What a rule can do:

- **`Expiration`** with `Days` or a `Date`: the current version expires that
  many days after it was written, or from that date on. Expiring is a delete,
  as DeleteObject's: the object is gone in an unversioned bucket, and gets a
  delete marker in a versioned one, keeping it as a noncurrent version.
- **`Expiration`** with `ExpiredObjectDeleteMarker`: a delete marker that's
  the only version of its key left is removed.
- **`NoncurrentVersionExpiration`**: a noncurrent version is removed for good
  `NoncurrentDays` after it became noncurrent (a newer version, or a delete
  marker, was written), keeping the `NewerNoncurrentVersions` newest ones.
- **`AbortIncompleteMultipartUpload`**: an upload is aborted
  `DaysAfterInitiation` days after it was started.

A rule's `Filter` picks objects by key prefix (`Prefix`), by size
(`ObjectSizeGreaterThan`, `ObjectSizeLessThan`; not for delete markers or
uploads), and by [tags](#tags) (`Tag`: a version must have each, with that
value; a noncurrent version by its own tags; never a delete marker or an
upload, so not with `ExpiredObjectDeleteMarker` or
`AbortIncompleteMultipartUpload`), one alone, or several under `And`. As in S3, days are counted to the next
midnight UTC: an object written at 10:30 on the 1st, under a rule of one day,
expires at the start of the 3rd.

Rules are applied in the background, not as objects are read: an expired
object stays readable until a sweep gets to it. Each bucket with rules is
swept once a day, starting when the rules are set: a sweep walks the keys
under the prefixes of the rules that expire anything, and expires what's due.

Sweeps go at a rate you set for the whole cluster, in object versions read
per hour (1,000,000 by default; 0 pauses them), so that however much there is
to sweep, they never take more of the database than that:

```sh
cairn config --database "$DB" set lifecycle-rate 2000000
cairn config --database "$DB" get              # every setting, with its default
```

Or on the dashboard's Jobs page, which also shows each bucket's sweep, the rate
sweeps actually reach when they're busy, and how long a round of every
bucket's sweep takes at it. If that's more than a day, sweeps fall behind, and
expirations come that much later: raise the rate, or, if sweeps don't reach
the rate set (one step at a time goes only as fast as the database answers),
give the database more resources. The rate is the cluster's,
not each node's: there's one lifecycle step at a time across the cluster,
about once a minute, on whichever node takes it, and the buckets take turns,
so that a huge one doesn't hold up the others.

Where a sweep has got to is saved as it goes, so if its node dies, another
carries on from there within minutes. A version written or deleted since a
sweep read it is never mistaken for the one that was due, and deleting (or
changing) the configuration stops a sweep before its next expiration. Nor is
a version whose tags changed since a sweep read it. Every
node uses the database's clock, so a node whose clock is off doesn't expire
anything early.

Not supported, and refused with `501 NotImplemented`: transitions to other
storage classes (`Transition`, `NoncurrentVersionTransition`; Cairn has one).

## Tags

Objects and buckets have tags, as in S3: key-value pairs for your own use, and
for [lifecycle rules](#lifecycle-rules) to pick objects by. An object version
has up to 10, given with its write (`x-amz-tagging`: PutObject, CopyObject,
CreateMultipartUpload; POST Object's `tagging` field) or set later:

```sh
aws s3api put-object --bucket my-bucket --key a.log --body a.log --tagging 'tmp=yes&team=storage'
aws s3api put-object-tagging --bucket my-bucket --key a.log \
    --tagging 'TagSet=[{Key=tmp,Value=no}]'      # replaces them all; --version-id for another version
aws s3api get-object-tagging --bucket my-bucket --key a.log
aws s3api delete-object-tagging --bucket my-bucket --key a.log
```

Changing an object's tags doesn't make a new version, nor change its ETag or
Last-Modified. GetObject and HeadObject tell how many it has
(`x-amz-tagging-count`). A copy keeps its source's, unless
`x-amz-tagging-directive: REPLACE` gives it the request's; an upload's are
given when it's created. Reading them takes `read`, changing them `write`.

A bucket has up to 50, which only an admin may set:

```sh
aws s3api put-bucket-tagging --bucket my-bucket --tagging 'TagSet=[{Key=team,Value=storage}]'
aws s3api get-bucket-tagging --bucket my-bucket
aws s3api delete-bucket-tagging --bucket my-bucket
```

Keys are 1 to 128 characters, values up to 256; both may have letters,
digits, spaces and `+ - = . _ : / @`, and keys can't start with `aws:`, as in
S3. Tags are stored in plaintext, whatever an object's
[encryption](#encryption), as S3 keeps them: an SSE-C object's are read and
changed without its key, and lifecycle sweeps, which have no keys, read them.
Don't put secrets in them. The dashboard shows both.

## CORS

A bucket's CORS configuration lets web pages on other sites use it from the
browser, with presigned URLs or POST Object, as in S3. Setting one is bucket
management, so only an admin can:

```sh
aws s3api put-bucket-cors --bucket my-bucket --cors-configuration '{"CORSRules": [{
    "AllowedOrigins": ["https://app.example.com"], "AllowedMethods": ["GET", "PUT", "POST"],
    "AllowedHeaders": ["content-type", "x-amz-*"], "ExposeHeaders": ["ETag"],
    "MaxAgeSeconds": 3000}]}'
aws s3api get-bucket-cors --bucket my-bucket
aws s3api delete-bucket-cors --bucket my-bucket
```

A request is allowed by the first rule that allows its origin (one `*` in an
`AllowedOrigin` stands for anything, `*` alone for any origin) and its method,
and, for a browser's preflight (an unsigned `OPTIONS`), every header it asks to
send (`AllowedHeader`, which may have one `*` too, matched regardless of case).
A preflight that no rule allows is refused with `403 AccessForbidden`. Every
other response to a request from an allowed origin gets its CORS headers,
errors too, so that the page can read them. CORS doesn't grant anything: a
request still has to be allowed, signed by a user that may make it, or
anonymous and allowed by the bucket's policy.

There's no CORS setting for the whole cluster, only these, per bucket, as in
S3.

## Limits

As in S3: a PutObject, an UploadPart, an UploadPartCopy's range and a
CopyObject's source may hold up to **5 GiB**, and an object up to **5 TiB**
(10,000 parts). Every part of a multipart upload but the last must be at least
**5 MiB**. Larger objects are uploaded in parts, and copied part by part,
which S3 clients do by themselves. A request declaring more is refused before
its body is read.

## Encryption

Objects can be encrypted with a key their client supplies (**SSE-C**), with
keys from a KMS that their owners let roles use (**SSE-KMS**), or with a key
of Cairn's own in that KMS (**SSE-S3**). Either way, Cairn encrypts the data
before it's stored, so no disk ever holds it in the clear.

- The algorithm is XChaCha20-Poly1305 (S3's API calls SSE-C and SSE-S3
  `AES256`, and Cairn answers the same way), in 64 KiB segments, so a range
  reads only the segments it covers, and altered data is detected.
- Only the content is encrypted. Its key (name), size, times, Content-Type,
  metadata (`x-amz-meta-*` and the like) and [tags](#tags) are stored as they
  are, as in S3: don't put anything secret there.
- An SSE-C or SSE-KMS object's ETag is random, not the MD5 of its content,
  as in S3. An SSE-S3 object's is the MD5, as in S3 (clients like s3cmd check
  it), but it's stored encrypted, with a fresh nonce each time, so that the
  database doesn't give away whether the content is a guessed one.
- Keys are only ever in a node's memory, and wiped once they're no longer
  needed. A node can't be core-dumped or debugged by another process of its
  user. But its memory can be swapped out: run nodes without swap, or with
  encrypted swap (and without hibernation), as you would OpenBao.

A bucket's [default encryption](#bucket-default-encryption) can be SSE-KMS or
SSE-S3. A request for encryption Cairn can't give (SSE-KMS or SSE-S3 without a
KMS) is refused with `501 NotImplemented`, rather than stored unencrypted.

### SSE-C

Send the
`x-amz-server-side-encryption-customer-*` headers with the PUT, as with S3
(`aws s3api put-object --sse-customer-algorithm AES256 --sse-customer-key
fileb://key`), and the same key with every GET and HEAD of the object. Cairn
never stores the key: only a salted HMAC of it, to refuse a wrong one.
Without the key, the data can't be read, by anyone.

- The key travels in a request header, so it's only accepted over HTTPS: a
  request must come through a proxy that sets `X-Forwarded-Proto: https` (or
  `Forwarded: proto=https`). Behind an encrypted network instead, allow it with
  `--allow-sse-c-over-http`. Lose the key and the object is lost.
- Multipart uploads: send the key with CreateMultipartUpload and every
  UploadPart (CompleteMultipartUpload doesn't need it).
- Copies: send the source's key in the `x-amz-copy-source-server-side-encryption-customer-*`
  headers, and the copy's (if any) in the usual ones. A copy with the same key
  shares the source's data; one with another key, or none, is written anew.
  Copying an object onto itself with another key changes its key.

### SSE-KMS

With a KMS configured (`--kms-*` flags), a write may ask for SSE-KMS, as with
S3: `aws s3api put-object --server-side-encryption aws:kms --ssekms-key-id
<key ID>`, optionally with `--ssekms-encryption-context <base64 JSON>`. Reads
need nothing more. A request must name its key (or leave it to its bucket's
default): Cairn has no key every role may use, as S3's `aws/s3` is. The KMS is
[OpenBao](https://openbao.org) (or Vault): its Transit engines hold the keys,
which never leave it.

The keys are their owners'. Whoever manages a key in OpenBao decides there
which of Cairn's roles may use it, as with AWS's customer managed keys: Cairn
asks OpenBao as the role that made the request, so a role may read an
SSE-KMS object only if it may read the bucket (Cairn's grants) *and* use the
key (OpenBao's). Key owners rotate, revoke and delete their keys themselves;
deleting a key makes its objects unreadable for good (crypto-shredding).

- **Key IDs** are `<mount>/<key>`: the path of a Transit engine (which may
  start with OpenBao namespaces, e.g. `finance/transit`) and a key's name in
  it. A bare name is in the mount `transit`. Responses tell the key as
  `arn:aws:kms:<mount>/<key>`, and a request may name it so too.
- **Roles in OpenBao.** Every Cairn role is an identity (an *entity*) in
  OpenBao, which Cairn logs in as through a JWT auth mount of its own,
  naming the role by its ID, which is never reused. Cairn logs in once for
  each new role (when the dashboard creates it, or within a minute), so that
  OpenBao makes its entity right away. `cairn role list` and the dashboard
  show each role's ID and entity; the dashboard's Users page also shows
  Cairn's public key, whether each node reaches OpenBao, and how its logins
  went, with what's wrong in OpenBao's setup if they fail. A deleted role's
  entity stays in OpenBao,
  harmlessly (no role will have its ID again), until its key owners remove
  it.
- **Trust.** OpenBao trusts Cairn to say which role asks, as AWS KMS trusts
  S3. So a Cairn admin can use every key any role may use. But Cairn can't
  use anything OpenBao doesn't grant one of its roles, and nothing granted to
  anyone else.
- **Cairn's private key** (`--kms-jwt-key`) is what lets it log in. Whoever
  has it, and can reach OpenBao, can do what Cairn can: keep it off the data
  disks and out of backups (a Kubernetes secret, a tmpfs, a systemd
  credential), and keep OpenBao on a private network. If it may have leaked,
  replace it, and the public key in the mount's `jwt_validation_pubkeys`:
  the old one is worthless then. Without it, Cairn's disks, its database and
  their backups hold nothing readable.
- Every object gets a random key of its own, which Cairn keeps sealed under a
  data key from the KMS, and keeps that data key only as the KMS encrypted it.
  The KMS binds it to the object's name (`bucket/key`) and encryption context:
  it opens for that object only, and only with that context.
- `x-amz-server-side-encryption-bucket-key-enabled` is accepted and ignored,
  as in MinIO: every object has keys of its own anyway.
- Multipart uploads: ask for SSE-KMS with CreateMultipartUpload. Its parts
  need the role's use of the key, but no headers.
- Copies to another SSE-KMS key or context share the source's data, as copies
  under the same SSE-C key do: the copy seals the same object key under a data
  key of its own. That changes who may open it, but not the key the data is
  encrypted with: anyone who could open the source's can read the copy's
  data. To change that (if a key may have leaked, say), copy to a plain or
  SSE-C object and back, which writes the data anew.
- If the KMS can't be reached, reads and writes of SSE-KMS objects fail with
  `503`, and nothing else is affected (HEAD needs no KMS).

Setting up OpenBao for Cairn, once (Vault's commands are the same, with `vault`
for `bao`). Cairn's key pair:

```bash
openssl genpkey -algorithm ed25519 -out cairn-kms.pem   # --kms-jwt-key, on every node
openssl pkey -in cairn-kms.pem -pubout -out cairn-kms.pub
```

The JWT auth mount Cairn logs in through, trusting only that key:

```bash
bao auth enable -path=cairn jwt
bao write auth/cairn/config jwt_validation_pubkeys=@cairn-kms.pub
bao write auth/cairn/role/s3 role_type=jwt user_claim=sub bound_audiences=cairn \
    token_type=batch token_ttl=5m
bao read -field=accessor sys/auth/cairn    # the mount's accessor, to find roles' entities by
```

Keep it as it is: then Cairn can use exactly what key owners grant its roles.
That mount must be Cairn's alone, and must not map JWT claims to groups or
metadata (`groups_claim`, `claim_mappings`), nor give tokens policies of its
own (`token_policies`): Cairn would choose them. And never attach an alias of
Cairn's mount to an entity of anyone else: Cairn could then act as them.

Then a key owner makes a key, and lets roles use it, by their entities (as
shown by Cairn) or through a group:

```bash
bao secrets enable -path=finance-transit transit
bao write -f finance-transit/keys/invoices
bao policy write finance-invoices - <<'POLICY'
path "finance-transit/datakey/plaintext/invoices" { capabilities = ["update"] }
path "finance-transit/decrypt/invoices" { capabilities = ["update"] }
POLICY
bao write identity/group name=finance-invoices policies=finance-invoices \
    member_entity_ids=<the entity of Cairn's role "billing">
```

A role then writes with `--ssekms-key-id finance-transit/invoices`. Grants and
revocations take effect at once. The group (or policy on an entity) must be
in the namespace of Cairn's mount: a key in a child namespace is granted by
its path there (`finance/transit/...`), since OpenBao's groups can't hold
another namespace's entities.

Don't grant `encrypt` on the keys: OpenBao creates a missing key on an
encrypt, so a mistyped key name would make a new key. Cairn never calls it.

### SSE-S3

With an SSE-S3 key configured (`--kms-sse-s3-key`), a write may ask for SSE-S3,
as with S3: `aws s3api put-object --server-side-encryption AES256`. Reads need
nothing. Cairn uses that key as itself, not as the role that asks, so any role
that may read an object reads it, and the dashboard can download it: it
protects the data at rest (disks, the database, backups), not from Cairn's
roles.

- Cairn logs in to OpenBao through its JWT mount as itself, with the subject
  `cairn` (roles' are their IDs), and its entity must be allowed
  `datakey/plaintext` and `decrypt` on the key. The dashboard's Users page
  shows that entity.
- As S3's bucket keys do, a node uses one data key from OpenBao for an hour of
  writes, and keeps the data keys it opened for an hour after their last use.
  So OpenBao sees a few calls an hour, not one a request. Every object still
  has a key of its own, bound to its name.
- That also means revoking Cairn's access to the key, or deleting the key (to
  shred every SSE-S3 object at once), stops nodes reading SSE-S3 objects
  within an hour, and at once only after they restart.
- Copies between SSE-S3 and SSE-KMS objects share their data, as copies among
  SSE-KMS objects do.

Setting it up, after the JWT mount above:

```bash
bao write -f transit/keys/cairn-sse-s3                     # --kms-sse-s3-key transit/cairn-sse-s3
bao policy write cairn-sse-s3 - <<'POLICY'
path "transit/datakey/plaintext/cairn-sse-s3" { capabilities = ["update"] }
path "transit/decrypt/cairn-sse-s3" { capabilities = ["update"] }
POLICY
bao write identity/entity/id/<Cairn's entity> policies=cairn-sse-s3
```

### Bucket default encryption

A bucket can have a default, as in S3: SSE-KMS under a key, or SSE-S3
(`AES256`), set by an admin with PutBucketEncryption, read with
GetBucketEncryption, removed with DeleteBucketEncryption:

```bash
aws s3api put-bucket-encryption --bucket demo --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"finance/invoices"}}]}'
```

- A write that asks for no encryption of its own (no SSE-C, SSE-KMS or
  SSE-S3 headers: PutObject, CopyObject's destination, CreateMultipartUpload)
  gets the default. One that asks for one gets that.
- With an SSE-KMS default, the writing role must be allowed to use the key,
  as when it names the key itself: a role that may write the bucket but not
  use its default key can write only by asking for other encryption.
- An SSE-KMS default's key must exist when it's set: Cairn tries it as the
  admin setting it (who needn't be allowed to use it). An SSE-S3 default
  needs `--kms-sse-s3-key`. `BucketKeyEnabled` is told back, but changes
  nothing.
- Changing or removing the default leaves what's written as it is. A write
  under way keeps the default it began with.
- The dashboard's Buckets page shows each bucket's default.

## Data integrity

Every stored blob is checksummed (CRC32C per 64 KiB block), and every read is
verified against those checksums before any byte reaches the client. If a
replica serves a damaged block, or fails mid-read, the read carries on from the
same block on another replica, so the client only ever gets intact data. If no
replica has an intact copy of a block, the response is cut off there (its
`Content-Length` tells the client it's incomplete), and the node logs a
`CORRUPTION:` line naming the blob and node. Data written by earlier versions
of Cairn has no checksums and is read unverified, until the packer
[rewrites it with checksums](#scrubbing).

Every request body is checked against everything the request claims about it,
as S3 checks it: the SHA-256 it's signed with (`x-amz-content-sha256`), the
signatures of its chunks, `Content-MD5`, and `x-amz-checksum-*` checksums, in
a header or a trailer. A body that doesn't match is refused before any of it
is stored. When writing, each replica reports a checksum of what it stored,
and the upload fails unless every replica stored exactly the bytes that were
sent.

Objects keep their S3 checksums, as S3 does: the one the client uploaded
(CRC32, CRC32C, CRC64NVME, SHA-1 or SHA-256), or else a CRC64NVME that Cairn
computes. A multipart upload gets the algorithm and type (`COMPOSITE` or
`FULL_OBJECT`) it was created with, or else a full-object CRC64NVME. As in
S3, a `COMPOSITE` upload's parts must each carry their checksum, and be
listed with it on completion; a `FULL_OBJECT` upload's needn't, Cairn works
them out itself (and checks any that are sent or listed). An
SSE-C upload created without an algorithm gets no checksum, so it can be
completed without the key, as in S3. A read with `x-amz-checksum-mode:
ENABLED` returns the checksum, so clients can verify what they download.
Listings, ListParts, CompleteMultipartUpload and copies report checksums too.
The checksums of encrypted objects are stored encrypted, as their data is, so
they can't be used to test guesses at the content. Objects written by earlier
versions of Cairn have no checksum, but a copy of one gets one.

A multipart object can be read part by part, as S3 reads it (GetObject and
HeadObject with `partNumber`, which SDKs' transfer managers use to download
in parallel): its parts are numbered from 1 in order, whatever numbers they
were uploaded as, and each read tells how many there are
(`x-amz-mp-parts-count`) and, with `x-amz-checksum-mode`, the part's own
checksum, if the object's is composite. Any other object is a single part.
**GetObjectAttributes** tells an object's ETag, checksum, size, storage class
and parts (each part's size and checksum, for a composite checksum) without
reading it. A CompleteMultipartUpload with `x-amz-mp-object-size` is refused
unless its parts add up to that size.

### Scrubbing

Every node checks the data it holds in the background, so that damage is
found before a client runs into it, even in data nobody reads. It reads each
copy from its own disk (not the page cache), and checks it as a whole: every
block against its checksum, the file's length and blob ID, and a CRC of the
whole file that the database keeps. It reads at a fixed rate,
`--scrub-rate` (25 MiB/s by default), copies that have gone unchecked longest
first, and checks a copy at most once a week. So a node checks all it holds
every *held bytes ÷ rate*: at 25 MiB/s, which is about 2 TiB a day, that's
every 2 days for 4 TiB, and every 8 days for 16 TiB. Set the rate to what the
disks can spare next to the clients' reads: 25 MiB/s is about a seventh of a
hard disk, and little for an SSD.

A read that runs into a damaged or missing copy has that copy checked next.

A damaged or missing copy is repaired: rebuilt from its own intact blocks and
the other replicas' (so a bad block costs one block of network traffic), and
checked against the database's CRC before it replaces the old file. A shard of
an [erasure-coded](#erasure-coding) blob is rebuilt the same way, its damaged
rows decoded from the other shards. Copies
damaged in different places repair each other. Bytes that no replica holds
intact are *lost*: the copies are left as they are, and the lost byte ranges
are recorded (`lost_ranges`). If a replica's node was down, the scrubber tries
again within the hour; once any copy turns out to hold the bytes after all
(that node came back, or a file was restored from a backup), the lost ranges
are cleared, and the other copies are repaired from it.

Once bytes are known to be lost, a GET whose range overlaps them fails with
`500 InternalError` before sending anything (rather than being cut off where
the damage is), and so does a copy of them (CopyObject, UploadPartCopy), so
that the damage doesn't spread to new objects unnoticed. A range that misses
them reads as usual, and HEAD works. Damage the scrubber hasn't found yet still
cuts a read off. The packer leaves a blob alone while a part of it is on lost
data; once those objects are deleted, it's compacted as usual.

What the scrubber finds is logged as a `CORRUPTION:` line, recorded in the
database (`scrub_findings`), and shown on the dashboard's
[Integrity](#dashboard) page.

Data written by versions of Cairn without checksums can't be checked as it
is. The packer rewrites it with checksums, the oldest first, reading at the
scrub rate (and not at all if scrubbing is off), and verifying each object's
bytes against its MD5 (its ETag). A replica whose copy doesn't match is passed
over for the next; if none matches, the data is recorded as lost. The
Integrity page shows how much is still left.

`POST /scrub` on a node's peer endpoint checks what's due right away, at
full speed (`?all`: every copy), and reports what it found.

## Packing

Every blob takes up rows in the database (one per replica), and is the unit
data is moved around in. So every node runs a packer in the background, once a
minute, which keeps blobs large without wasting much space:

- **Smaller objects are packed together.** Blobs up to 64 MiB are packed into
  blobs of 256 MiB, once there are enough of them to fill one. Packing writes
  the data a second time, but normally only once: the packed blobs are too
  large to be packed again. Lots of tiny objects are packed even before they
  fill a blob, once 10,000 of them are waiting; such a blob may be packed again
  later.
- **Packed blobs are compacted.** Deleting an object that lives in a packed blob
  frees no disk space by itself. Once at least a quarter of a packed blob is
  garbage, its remaining data is rewritten, together with that
  of other such blobs, into as few new blobs as hold it.

Data is laid out by age, so data that is likely to be deleted together is
stored together. Packed data is verified against its checksums before it
replaces the original, and reads in progress follow the data to its new blob.
The nodes coordinate through the database, so each blob is packed only once.

## Erasure coding

Every blob is stored as *k* data shards and *m* parity shards, each on a node
of its own, any *k* of which hold all of its data. Replication is *k* = 1: the
one data shard is the blob, and each parity shard is a copy of it. *m* is the
`parity-shards` setting (or, while it isn't set, each node's
`--replication-factor` − 1). Blobs over 64 MiB can be stored with *k* > 1,
which survives losing as many nodes, *m*, but stores *(k + m) / k* times the
data rather than *m + 1* times: with replication factor 3, coding 4+2 stores
1.5× instead of 3×. Smaller blobs are replicated until the packer packs them
into larger ones.

Coding is off until you choose *k*, for the whole cluster, next to *m*:

```sh
cairn config --database "$DB" set parity-shards 2
cairn config --database "$DB" set data-shards 4      # blobs over 64 MiB are coded 4+2
```

Cairn never picks *k* itself: only you know how many nodes the cluster will
keep. It needs *k + m* live nodes, one per shard; while fewer are live, new
blobs are replicated, and existing ones stay as they are.

An upload over 64 MiB that declares its size up front (as almost every client
does) is coded as it's written. The packer converts the other blobs over
64 MiB, whatever their age: uploads whose size wasn't known, those written
while too few nodes were live, and every blob in another layout after a
change of `data-shards` or `parity-shards` (coded blobs are rewritten in the
new layout, or replicated once coding is turned off), one job of up to 1 GiB
per node a minute. Packing and compacting write blobs over 64 MiB coded
directly, so coded data stays coded. Each shard holds
the blob in cells of 1 MiB, so a read of a small object in a coded blob mostly
reads a single shard, without decoding. A read that can't get a cell from its
data shard (a node is down, or a block is damaged) decodes it from the other
shards' cells of its row, and verifies the result against its checksums. The
dashboard's Storage page shows each layout's health, and the Jobs page how
much is waiting to be converted, and how many copies to be added or dropped.

## Garbage collection

Deleting data deletes its files right away, and so does an upload that fails.
What a crash leaves behind (or a cleanup that failed itself) is cleaned up in
the background, as part of the same pass that packs data, once a minute on
every node:

- Data whose upload has been unfinished for a day is deleted: its upload (or
  packing job) has died. Multipart uploads that were never completed are kept
  until they're aborted, or their bucket is deleted.
- Each node checks its data directory for files the database doesn't know,
  and deletes them. It checks a slice at a time, getting through all of it in
  a day.
- Data that no object refers to anymore (because its last object was
  deleted while other data shared its file, or a crash got in the way) is
  deleted on the next pass.

There's nothing to run or configure.

## License

Licensed under the [GNU Affero General Public License, Version 3](LICENSE) or later.
