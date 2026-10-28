# Cairn

A simple, reliable S3-compatible object storage system. Run it on one machine,
or spread it across several for redundancy. Cairn keeps your data safe and
serves it through the familiar S3 API, using PostgreSQL to keep everything
consistent.

## Requirements

- A reachable **PostgreSQL** database (shared by every node). Cairn creates its
  own schema on first start.
- A local **data directory** per node for storing blobs.

The schema is created automatically; just point Cairn at an empty database.

> [!WARNING]
> The peer endpoint (`--listen-peer`, default `:9431`) is unauthenticated: it
> can read and delete blobs, and it serves the [dashboard](#dashboard), which
> manages roles. Only bind it to a trusted/private network — never expose it to
> the public internet.

## Installing

Download the static binary from the
[releases page](https://github.com/justusjz/cairn/releases) and extract it
(replace `<version>` with the release you downloaded, e.g. `0.3.0`):

```sh
tar xzf cairn-v<version>-x86_64-unknown-linux-musl.tar.gz
sudo install -m755 cairn-v<version>-x86_64-unknown-linux-musl/cairn /usr/local/bin/cairn
```

It is statically linked (musl), so it runs on any x86-64 Linux with no
dependencies.

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
  [versioning](#versioning), HEAD any bucket, and see every bucket in
  ListBuckets. Admin does **not** grant access to objects.
- **`read`** on a bucket: GetObject, HeadObject, ListObjects, and being the
  source of a CopyObject / UploadPartCopy.
- **`write`** on a bucket: PutObject, DeleteObject(s), multipart uploads, and
  being the destination of a copy. In a versioned bucket, a delete only adds a
  delete marker.
- **`delete-version`** on a bucket: DeleteObject(s) naming a version ID, which
  removes that version for good.

A role sees only the buckets it holds a grant on (or all of them, if admin).
Permissions are per bucket; there are no per-key permissions. A bucket must
exist before you can grant access to it, so the setup order is: an admin creates
the bucket (with any S3 client), then you grant roles access. Deleting a bucket
removes its grants, so a bucket re-created under the same name starts with no
access for anyone.

Bucket names follow S3's rules: 3 to 63 lowercase letters, digits, dots and
hyphens, starting and ending with a letter or digit.

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
- **Buckets:** browse buckets by prefix, see every version of a key with the
  blobs its parts are stored in and the nodes holding them, and download any
  version. Buckets can be created and (when empty) deleted.
- **Roles:** everything `cairn role` does: create and delete roles, grant and
  revoke permissions, rotate secrets, and toggle admin.

To keep other websites from reaching it through DNS rebinding, the dashboard
only answers when it's opened by IP address, as `localhost`, or by the host of
the node's `--peer-url`.

Request metrics are kept in memory by each node, so they start over when it
restarts; everything else is read from the database.

The dashboard's JSON API is under `/_dashboard/api/`, described by an OpenAPI
spec at `/_dashboard/api/openapi.json` (also committed as `ui/openapi.json`).

> [!WARNING]
> Like the rest of the peer endpoint, the dashboard has no authentication:
> anyone who can reach it can read every object and manage every role. Keep
> the peer endpoint on a trusted network.

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

## Data integrity

Every stored blob is checksummed (CRC32C per 64 KiB block), and every read is
verified against those checksums before any byte reaches the client. If a
replica serves a damaged block, or fails mid-read, the read carries on from the
same block on another replica, so the client only ever gets intact data. If no
replica has an intact copy of a block, the response is cut off there (its
`Content-Length` tells the client it's incomplete), and the node logs a
`CORRUPTION:` line naming the blob and node. Data written by earlier versions
of Cairn has no checksums and is read unverified.

When writing, each replica reports a checksum of what it stored, and the upload
fails unless every replica stored exactly the bytes that were sent.

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

Deleting data deletes its files right away. What a crash or a failed upload
leaves behind is cleaned up in the background, as part of the same pass that
packs data, once a minute on every node:

- Uploads that have been pending for a day are given up, and their data
  deleted.
- Each node checks its data directory for files the database doesn't know,
  and deletes them. It checks a slice at a time, getting through all of it in
  a day.
- Data that no object refers to anymore (because its last object was
  deleted while other data shared its file, or a crash got in the way) is
  deleted on the next pass.

There's nothing to run or configure.

## License

Licensed under the [GNU Affero General Public License, Version 3](LICENSE) or later.
