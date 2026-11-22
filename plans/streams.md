# Streams

Append-only logs of records, as Kafka and Kinesis Data Streams keep them,
in Cairn's own storage: replicated or erasure-coded as objects are,
without nodes that own partitions, and so without failover. Kinesis's API
first, since it's AWS's (JSON over HTTP, SigV4, IAM) and needs no consumer
groups; Kafka's protocol is the goal.

## Why in Cairn

Every "Kafka on object storage" (WarpStream, Bufstream, AutoMQ, Kafka's own
KIP-1150) sits on S3 as a black box, whose writes take 50 to 200 ms, and
works around that: batching for 250 ms or more, a WAL elsewhere (AutoMQ's
on EBS), caches. Cairn *is* the object store: a write is an fsync on each
of the nodes that get a copy, and a commit in Postgres. So records get the
object store's architecture (any node takes any shard's records; erasure
coding for what's kept long; the packer, GC, scrubbing, repair, tiers,
backups, IAM, KMS, the audit log) without its latency. In a cluster spread
over sites, a write waits for the farthest node that gets a copy, and for
Postgres: tens of milliseconds within a continent, as Kafka with
`acks=all` across the same sites would.

## Terms

| Kinesis | Kafka | Cairn |
| --- | --- | --- |
| stream | topic | a row in `streams` |
| shard | partition | a row in `stream_shards`: its next sequence number |
| sequence number | offset | each shard's count from 0 |
| — | record batch | a batch: a shard's records in one flush (`stream_batches`) |

## What's built (Kinesis's basics)

**Writing.** A node gathers what it's given, from every stream, for up to
10 ms (or 4 MiB), and *flushes* it: one object of the internal bucket,
`streams/<node>/<uuid>`, written as any object is, then one transaction
(`cairn_stream_append`) that, for each shard in it, in (stream, shard)
order, draws its sequence numbers by updating its row, and inserts a row
of the index: the batch's first number, its count, its object and byte
range. Only then are the writers answered. Up to 4 flushes are in flight
per node.

Each shard's row is locked from its UPDATE to the commit, so its batches
commit in the order of their numbers: readers never see a gap, and never a
record before those numbered before it. A sequence (Postgres's) would hand
out numbers in the order they're asked for, not committed, and wouldn't do.
The lock is held for about one commit, since the transaction is one round
trip (a function); a shard written to from many nodes at once takes at
most about one flush per commit's time.

**Reading.** The index's rows from a sequence number (the one at or before
it, and those after), then their objects' byte ranges, read as any object's
data is. GetRecords doesn't wait for records: Kinesis's doesn't.

**Cleaning up.** Each node, each minute: deletes the index's rows past
their stream's retention, then the objects no row refers to, once they're
older than 10 minutes (an object that's written and not yet appended is
referred to by nothing; a flush gives up if its append comes more than 5
minutes after its write, so it never refers to an object being deleted).
Deleting a stream deletes its shards and index rows (locking the shards
in order first, so it waits for appends rather than deadlocking with
them), and its objects go the same way.

**Guarantees.** An answered record is as durable as an object, and in the
index. A shard's records are numbered in the order they commit, without
gaps. A flush whose commit is cut off may have appended its records
anyway, so a writer that retries may write them twice: at least once, as
Kinesis is.

**Load on Postgres.** Two transactions per flush (the object's and the
append), whatever the number of records: a few dozen busy nodes flush a
few hundred to a thousand times a second. A row per shard per flush in the
index, until packing merges them.

## Next

1. **Packing a shard's records together.** A flush's object holds every
   shard's records of that moment; reading a shard's history reads a
   batch from each. The packer should rewrite old batches into each
   shard's own objects (a shard's records in order, 256 MiB, erasure-coded
   over 64 MiB), and replace their index rows with one per object, in the
   same transaction as the swap. Retention then deletes whole objects.
2. **One transaction per flush.** The object's metadata and the append
   in one function, rather than PutObject's and then the append's.
3. **The recent index in memory.** Consumers at a shard's end ask again
   and again; each asks Postgres. A node that appends should send its new
   index rows to the others (over the peer endpoint), so that reads of
   recent records find them in memory. This is also how Kafka's Fetch,
   which waits for records, would be woken.
4. **Resharding** (UpdateShardCount: closing shards and opening their
   children, with parent shards in ListShards).
5. **CloudTrail's data events** for Kinesis, if trails select them.
6. **Kafka's protocol**: ApiVersions, Metadata (every node claims to lead
   every partition), Produce, Fetch (storing Kafka's record batches as
   they're sent, their base offsets set as they're read), ListOffsets,
   topics, offsets committed in Postgres, and consumer groups as KIP-848
   has them (the broker assigns partitions), coordinated by a node chosen
   by the group's hash. `AWS_MSK_IAM` (SigV4) and SCRAM to sign in.
   Idempotent producers' sequence numbers checked in the append.
   Transactions and compacted topics after that, if ever.

## The audit log

CloudTrail's audit log stays as it is: it records a call before
answering it with one local `fdatasync` (a millisecond), with nothing in
Postgres, which KMS's Decrypt needs; a stream's append would add the
farthest copy and a commit. The two already work alike (records gathered,
then written as objects of the internal bucket); later, the audit log's
records could also be put into a stream, as AWS sends CloudTrail's events
to EventBridge.
