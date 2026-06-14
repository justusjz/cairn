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

The S3 API is now served on `:9000`. Point any S3 client at it (Cairn does not
verify credentials, so any access/secret key works):

```sh
s3cmd --host=localhost:9000 --host-bucket=localhost:9000 --no-ssl mb s3://my-bucket
s3cmd --host=localhost:9000 --host-bucket=localhost:9000 --no-ssl put file.txt s3://my-bucket/
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

Licensed under the [Apache License, Version 2.0](LICENSE).
