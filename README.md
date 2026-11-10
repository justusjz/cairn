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
(replace `<version>` with the release you downloaded, e.g. `0.4.2`, and
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
docker exec cairn cairn role create admin --admin
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
the credentials of a role, and a fresh database has none. Create an admin role
to manage buckets, and an application role with access to a bucket (see
[Roles and permissions](#roles-and-permissions)):

```sh
DB="postgres://user:pass@localhost:5432/cairn"
cairn role --database "$DB" create admin --admin        # prints a generated secret
cairn role --database "$DB" create app                  # prints a generated secret
```

Create a bucket as the admin, grant the application role access to it, and use
it:

```sh
s3cmd --host=localhost:9000 --host-bucket=localhost:9000 --no-ssl \
    --access_key=admin --secret_key=<admin secret> mb s3://my-bucket
cairn role --database "$DB" grant app my-bucket read write
s3cmd --host=localhost:9000 --host-bucket=localhost:9000 --no-ssl \
    --access_key=app --secret_key=<app secret> put file.txt s3://my-bucket/
```

### `serve` flags

Every flag can also be set through its environment variable; a flag on the
command line wins. `cairn role` reads `CAIRN_DATABASE` as well.

| Flag | Environment | Default | Description |
| --- | --- | --- | --- |
| `--database <URL>` | `CAIRN_DATABASE` | *required* | PostgreSQL connection string. Shared by all nodes. |
| `--listen-client <ADDR>` | `CAIRN_LISTEN_CLIENT` | *required* | Bind address for the S3 API. |
| `--listen-peer <ADDR>` | `CAIRN_LISTEN_PEER` | `127.0.0.1:9431` | Bind address for the peer endpoint (replica traffic between nodes). Always runs. |
| `--peer-url <URL>` | `CAIRN_PEER_URL` | `http://<listen-peer>` | URL other nodes use to reach this node. Set explicitly when `--listen-peer` is a wildcard/private address (e.g. `http://10.0.0.1:9431`). |
| `--replication-factor <N>` | `CAIRN_REPLICATION_FACTOR` | `1` | How many distinct nodes each blob is stored on. |
| `--data-dir <PATH>` | `CAIRN_DATA_DIR` | *required* | Local directory for blobs. |
| `--allow-sse-c-over-http` | `CAIRN_ALLOW_SSE_C_OVER_HTTP` | off | Accept [SSE-C](#sse-c) keys in requests no proxy marked as HTTPS. Only for a network that's encrypted itself. |
| `--kms-address <URL>` | `CAIRN_KMS_ADDRESS` | none | OpenBao (or Vault) server holding the keys for [SSE-KMS](#sse-kms), e.g. `https://bao.internal:8200`. Without it, SSE-KMS is refused. |
| `--kms-jwt-key <PATH>` | `CAIRN_KMS_JWT_KEY` | *required with a KMS* | PEM file of the Ed25519 private key Cairn signs its roles' logins to the KMS with. The same on every node. |
| `--kms-auth-mount <PATH>` | `CAIRN_KMS_AUTH_MOUNT` | `cairn` | Where the KMS's JWT auth method for Cairn is mounted. |
| `--kms-auth-role <NAME>` | `CAIRN_KMS_AUTH_ROLE` | `s3` | The role of that auth method Cairn's logins use. |
| `--kms-sse-s3-key <ID>` | `CAIRN_KMS_SSE_S3_KEY` | none | The key for [SSE-S3](#sse-s3) (`<mount>/<key>`), which Cairn uses as itself. Without it, SSE-S3 is refused. |
| `--kms-ca-cert <PATH>` | `CAIRN_KMS_CA_CERT` | public roots | PEM file of the CA certificates to trust for the KMS's TLS. |

On SIGTERM or Ctrl-C, a node stops accepting connections and finishes the
requests in flight before it exits; a second signal exits right away. Anything
cut off is cleaned up by [garbage collection](#garbage-collection), as after a
crash.

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

## Roles and permissions

A **role** is a set of S3 credentials: its name is the access key ID, and it has
a secret. Roles are stored in Postgres, so every node picks up a change on the
very next request; there is nothing to restart or sync.

What a role may do:

- **admin** (`--admin`): create and delete buckets, configure their
  [versioning](#versioning), HEAD any bucket and read its configuration, and
  see every bucket in ListBuckets. Admin does **not** grant access to objects.
- **`read`** on a bucket: GetObject, HeadObject, ListObjects, and being the
  source of a CopyObject / UploadPartCopy.
- **`write`** on a bucket: PutObject, DeleteObject(s), multipart uploads
  (listing them and their parts too, to resume one), and being the destination
  of a copy. In a versioned bucket, a delete only adds a
  delete marker.
- **`delete-version`** on a bucket: DeleteObject(s) naming a version ID, which
  removes that version for good.

A role sees only the buckets it holds a grant on (or all of them, if admin).
Permissions are per bucket; there are no per-key permissions. A bucket must
exist before you can grant access to it, so the setup order is: an admin creates
the bucket (with any S3 client), then you grant roles access. Deleting a bucket
removes its grants, so a bucket re-created under the same name starts with no
access for anyone.

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

Manage roles with `cairn role --database <URL> <command>`:

| Command | Description |
| --- | --- |
| `create <name> [--admin] [--secret <S>]` | Create a role. Prints a generated 40-char secret unless `--secret` is given (min. 8 chars). |
| `update <name> [--admin true\|false] [--rotate-secret \| --secret <S>]` | Toggle admin, or replace the secret (`--rotate-secret` prints the new one). |
| `delete <name>` | Delete a role and all its grants. |
| `grant <name> <bucket> <read\|write\|delete-version>...` | Grant permissions on an existing bucket. |
| `revoke <name> <bucket> [read\|write\|delete-version]...` | Revoke permissions on a bucket; all of them if none are listed. |
| `list` | List roles, their admin flag, and their grants (secrets are not shown). |

Secrets are stored in plaintext in the `roles` table: SigV4 is an HMAC scheme,
so verifying a signature needs the secret itself. Restrict access to the
database accordingly.

A signed request is only accepted within **15 minutes** of its timestamp
(either way), as in S3, so a captured request can't be replayed later. Keep the
clocks of nodes and clients in sync (e.g. NTP); otherwise requests fail with
`RequestTimeTooSkewed`.

**Presigned URLs** (SigV4 in the query string) work as in S3: a URL signed
with a role's credentials makes exactly that request, as that role, for as
long as it says (`X-Amz-Expires`, at most 7 days), with nothing but an HTTP
client, a browser say. Its body is unsigned. GetObject and HeadObject take
S3's `response-*` parameters (`response-content-disposition`,
`response-content-type`, …), which set those headers of the response, so that
a link can download an object under a name of its own. Only SigV4 is
supported: `aws s3 presign` makes SigV2 URLs unless its config has
`signature_version = s3v4` under `s3`. For an SSE-C object, the URL has to be
signed with the key's headers, and the client has to send them.

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
- **Storage:** how much data there is, how much of it has fewer live copies
  than the replication factor, and what each node holds.
- **Jobs:** how the background passes (garbage collection and packing) are
  doing on each node, what they still have to do, and what they did recently.
- **Buckets:** browse buckets by prefix, see every version of a key with how
  it's encrypted, the blobs its parts are stored in and the nodes holding
  them, and download any version (but an encrypted one: Cairn doesn't have
  an SSE-C object's key, and the KMS opens an SSE-KMS one only for a role).
  Buckets can be created and (when empty) deleted.
- **Roles:** everything `cairn role` does: create and delete roles, grant and
  revoke permissions, rotate secrets, and toggle admin. Each role's ID and
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
`CAIRN_URL` (default `http://127.0.0.1:9431`).

The UI's types come from the API's OpenAPI spec, which is generated from the
Rust code (with [utoipa](https://github.com/juhaku/utoipa)). Both the spec
(`ui/openapi.json`) and the TypeScript types made from it for
[openapi-fetch](https://openapi-ts.dev/openapi-fetch/) (`ui/src/schema.d.ts`)
are committed, so building needs neither generator. A test fails when the
committed spec no longer matches the API; after changing the API, regenerate
both:

```sh
CAIRN_UPDATE_OPENAPI=1 cargo test openapi
(cd ui && npm run gen)
```

`npm run gen` runs [openapi-typescript](https://openapi-ts.dev/) through `npx`,
with pinned versions and the TypeScript 5 it needs (the UI itself uses
TypeScript 7), so it needs network access.

## Versioning

Buckets support S3 versioning, which keeps every version of an object instead
of overwriting it. This is what makes Cairn a ransomware-resistant backup
target: a client that can write and delete (e.g. restic) can't destroy the
history, as long as it isn't granted `delete-version`.

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

Old versions take up space until they're deleted. There are no lifecycle rules
yet to expire them automatically.

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
- Only the content is encrypted. Its key (name), size, times, Content-Type
  and metadata (`x-amz-meta-*` and the like) are stored as they are, as in S3:
  don't put anything secret there.
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
  show each role's ID and entity; the dashboard's Roles page also shows
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
  `datakey/plaintext` and `decrypt` on the key. The dashboard's Roles page
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
of Cairn has no checksums and is read unverified.

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
`FULL_OBJECT`) it was created with, or else a full-object CRC64NVME. An
SSE-C upload created without an algorithm gets no checksum, so it can be
completed without the key, as in S3. A read with `x-amz-checksum-mode:
ENABLED` returns the checksum, so clients can verify what they download.
Listings, ListParts, CompleteMultipartUpload and copies report checksums too.
The checksums of encrypted objects are stored encrypted, as their data is, so
they can't be used to test guesses at the content. Objects written by earlier
versions of Cairn have no checksum, but a copy of one gets one.

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
