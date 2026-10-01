# Cairn

A simple, reliable S3-compatible object storage system. Run it on one machine,
or spread it across several for redundancy. Cairn keeps your data safe and
serves it through the familiar S3 API, using PostgreSQL to keep everything
consistent.

## Requirements

- A reachable **PostgreSQL** database (shared by every node). Cairn creates its
  own schema on first start.
- A local **data directory** per node for storing part blobs.

The schema is created automatically; just point Cairn at an empty database.

> [!WARNING]
> The peer endpoint (`--listen-peer`, default `:9431`) is unauthenticated and
> its prune action is destructive. Only bind it to a trusted/private network —
> never expose it to the public internet.

## Installing

Download the static binary from the
[releases page](https://codeberg.org/justusjz/cairn/releases) and extract it:

```sh
tar xzf cairn-v0.1.3-x86_64-unknown-linux-musl.tar.gz
sudo install -m755 cairn-v0.1.3-x86_64-unknown-linux-musl/cairn /usr/local/bin/cairn
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

| Flag | Default | Description |
| --- | --- | --- |
| `--database <URL>` | *required* | PostgreSQL connection string. Shared by all nodes. |
| `--listen-client <ADDR>` | *required* | Bind address for the S3 API. |
| `--listen-peer <ADDR>` | `127.0.0.1:9431` | Bind address for the peer endpoint (replica traffic + prune). Always runs. |
| `--peer-url <URL>` | `http://<listen-peer>` | URL other nodes use to reach this node. Set explicitly when `--listen-peer` is a wildcard/private address (e.g. `http://10.0.0.1:9431`). |
| `--replication-factor <N>` | `1` | How many distinct nodes each part is stored on. |
| `--data-dir <PATH>` | *required* | Local directory for part blobs. |

## Running a highly-available cluster

For redundancy, run several nodes against the **same Postgres database** with a
`--replication-factor` greater than 1. Each node needs its own
`--listen-client`, its own `--listen-peer`, and its own `--data-dir`. Because
the peer endpoint must be reachable by the other nodes, set `--peer-url` to an
address they can actually connect to.

Example: a 3-node cluster with replication factor 2 (every part stored on 2 of
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
holds the part.

With replication factor `N`, writes succeed as long as at least `N` nodes are
live; if fewer than `N` are available, uploads are rejected (metadata operations
still work, since they live in Postgres).

## Roles and permissions

A **role** is a set of S3 credentials: its name is the access key ID, and it has
a secret. Roles are stored in Postgres, so every node picks up a change on the
very next request; there is nothing to restart or sync.

What a role may do:

- **admin** (`--admin`): create and delete buckets, HEAD any bucket, and see
  every bucket in ListBuckets. Admin does **not** grant access to objects.
- **`read`** on a bucket: GetObject, HeadObject, ListObjects, and being the
  source of a CopyObject / UploadPartCopy.
- **`write`** on a bucket: PutObject, DeleteObject(s), multipart uploads, and
  being the destination of a copy.

A role sees only the buckets it holds a grant on (or all of them, if admin).
Permissions are per bucket; there are no per-key permissions. A bucket must
exist before you can grant access to it, so the setup order is: an admin creates
the bucket (with any S3 client), then you grant roles access. Deleting a bucket
removes its grants, so a bucket re-created under the same name starts with no
access for anyone.

Manage roles with `cairn role --database <URL> <command>`:

| Command | Description |
| --- | --- |
| `create <name> [--admin] [--secret <S>]` | Create a role. Prints a generated 40-char secret unless `--secret` is given (min. 8 chars). |
| `update <name> [--admin true\|false] [--rotate-secret \| --secret <S>]` | Toggle admin, or replace the secret (`--rotate-secret` prints the new one). |
| `delete <name>` | Delete a role and all its grants. |
| `grant <name> <bucket> <read\|write>...` | Grant permissions on an existing bucket. |
| `revoke <name> <bucket> [read\|write]...` | Revoke permissions on a bucket; all of them if none are listed. |
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

## Garbage collection

Failed uploads and orphaned parts (e.g. left behind by a crash or re-balancing)
are reclaimed by the `prune` command, run **per node** against that node's peer
endpoint. It is a manual repair operation.

Dry run — report what would be removed, change nothing (default):

```sh
cairn prune --peer http://10.0.0.1:9431
```

Actually delete:

```sh
cairn prune --peer http://10.0.0.1:9431 --apply
```

### `prune` flags

| Flag | Default | Description |
| --- | --- | --- |
| `--peer <URL>` | `http://127.0.0.1:9431` | Peer URL of the node to prune. |
| `--apply` | *(off)* | Actually delete. Without it, prune only reports (dry run). |

Run `prune` against each node in turn to sweep the whole cluster.

## License

Licensed under the [GNU Affero General Public License, Version 3](LICENSE) or later.
