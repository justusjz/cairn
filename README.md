# Cairn

A simple, reliable S3-compatible object storage system. Run it on one machine,
or spread it across several for redundancy. Cairn keeps your data safe and
serves it through the familiar S3 API, using PostgreSQL to keep everything
consistent. [S3-COMPATIBILITY.md](S3-COMPATIBILITY.md) describes exactly which
parts of the S3, IAM and STS APIs it implements, and how they differ from AWS's.

## Requirements

- A reachable **PostgreSQL** database (shared by every node), with UTF-8
  encoding (the default), so that keys sort as S3 sorts them. Cairn creates its
  own schema on first start.
- A local **data directory** per node for storing blobs.

The schema is created automatically; just point Cairn at an empty database.

> [!WARNING]
> The peer endpoint (`--listen-peer`, default `127.0.0.1:9431`) is
> unauthenticated: it can read and delete blobs, and it takes the `cairn`
> CLI's commands, which manage users and settings. Only bind it to a
> trusted/private network — never expose it to the public internet.
> So that no web page a browser on that network opens can use it, it only
> takes requests to an IP address, `localhost`, or the host of the node's
> `--peer-url`.

## Installing

Download the static binary from the
[releases page](https://github.com/justusjz/cairn/releases) and extract it
(replace `<version>` with the release you downloaded, e.g. `0.10.0`, and
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

### Docker Compose

[`deploy/compose`](deploy/compose) runs Cairn on one host, ready to use:
Postgres, Cairn, and [Caddy](https://caddyserver.com) in front of it, which
serves the S3 API, the [console](#console) and buckets'
[websites](#websites) over HTTPS, with certificates it gets from Let's
Encrypt as they're needed. Only Caddy is published, on ports 80 and 443.

1. Point DNS at the host, for the three domains in `.env` (the examples'
   here):

   | Record | For |
   | --- | --- |
   | `s3.example.com`, `*.s3.example.com` | The S3 API, and buckets virtual-hosted. |
   | `console.example.com` | The console. |
   | `*.s3-website.example.com` | Buckets' websites. |

2. Configure it, and start it:

   ```sh
   cd deploy/compose
   cp .env.example .env      # set the domains, and POSTGRES_PASSWORD
   docker compose up -d
   ```

3. Make the first administrator, a [directory user](#directory-users), and
   set up a passkey for the console with the link it prints (the console's
   sign-in page says so too, until someone can sign in):

   ```sh
   docker compose exec cairn cairn directory-user create admin --admin
   ```

Caddy gets a certificate for `s3.example.com` and `console.example.com` as
it starts, and one for any other host the first time a client asks for it,
if Cairn [serves something there](#https-for-websites-and-buckets); plain
HTTP is redirected to HTTPS. Back up the `postgres` and `cairn` volumes: the
database, and the data; or let Cairn [back itself up](#backups) to another S3
service.

**Wildcard certificates.** A certificate per bucket is fine for a few, but
Let's Encrypt issues at most 50 a week per registered domain. With more
buckets (or websites) than that, have Caddy get one wildcard certificate for
`*.s3.example.com` and one for `*.s3-website.example.com`, by ACME's DNS
challenge: `compose.wildcard.yaml` builds Caddy with a DNS provider's module
(Cloudflare's; for another, see `caddy/Dockerfile`), and serves
`Caddyfile.wildcard`. Set its two lines in `.env`, the token one that may
edit DNS records in the domains' zones, and start it with `--build`:

```sh
# in .env
COMPOSE_FILE=compose.yaml:compose.wildcard.yaml
CLOUDFLARE_API_TOKEN=...
```

Custom domains, and buckets with dots in their names (which a wildcard
covers one label of), still get certificates on demand.

## Running a single node

The simplest deployment — one node, replication factor 1, no redundancy:

```sh
cairn serve \
    --database "postgres://user:pass@localhost:5432/cairn" \
    --listen-client 0.0.0.0:9000 \
    --data-dir /var/lib/cairn/data
```

The S3 API is now served on `:9000`. Every request must be signed (SigV4, or SigV2) with
the credentials of a user, and a fresh database has none. Create the first
admin (see [Users and permissions](#users-and-permissions)):

```sh
cairn user create admin --admin  # prints its access key ID and secret
```

The `cairn` commands that manage the cluster (`user`, `account`, `oidc`,
`config`, `node`, `backup` and `sessions`) don't touch the database themselves:
they run on a node, sent to its peer endpoint. That's the node on this
host by default (`http://127.0.0.1:9431`, the default `--listen-peer`), or
the one `--peer-url` (`CAIRN_PEER_URL`, as `cairn serve` has it) names, so
a node's own environment points them at it. Any node does, as they share the
database; it has to be running.

Everything else goes through the S3 and IAM APIs (both on the S3 endpoint)
or the [console](#console). As the admin, with the AWS CLI, create a bucket
and an application user that may use it:

```sh
export AWS_ENDPOINT_URL=http://localhost:9000 AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=<admin key ID> AWS_SECRET_ACCESS_KEY=<admin secret>
aws s3 mb s3://my-bucket
aws iam create-user --user-name app
aws iam put-user-policy --user-name app --policy-name my-bucket --policy-document '{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow",
    "Action": ["s3:ListBucket", "s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
    "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]}]}'
aws iam create-access-key --user-name app   # prints its access key ID and secret
```

Cairn has no regions: every bucket is in `us-east-1`, whatever region a
client names, and behaves as S3's buckets there do. Creating a bucket you
already own succeeds again and changes nothing (other regions answer
`409 BucketAlreadyOwnedByYou`).

And use it as the application:

```sh
AWS_ACCESS_KEY_ID=<app key ID> AWS_SECRET_ACCESS_KEY=<app secret> \
    aws s3 cp file.txt s3://my-bucket/
```

### `serve` flags

Every flag can also be set through its environment variable; a flag on the
command line wins. The other commands read `CAIRN_PEER_URL` as well.

| Flag | Environment | Default | Description |
| --- | --- | --- | --- |
| `--database <URL>` | `CAIRN_DATABASE` | *required* | PostgreSQL connection string. Shared by all nodes. |
| `--listen-client <ADDR>` | `CAIRN_LISTEN_CLIENT` | *required* | Bind address for the S3 API. |
| `--listen-peer <ADDR>` | `CAIRN_LISTEN_PEER` | `127.0.0.1:9431` | Bind address for the peer endpoint (replica traffic between nodes). Always runs. |
| `--peer-url <URL>` | `CAIRN_PEER_URL` | `http://<listen-peer>` | URL other nodes use to reach this node. Set explicitly when `--listen-peer` is a wildcard/private address (e.g. `http://10.0.0.1:9431`). |
| `--replication-factor <N>` | `CAIRN_REPLICATION_FACTOR` | `1` | How many distinct nodes each blob is stored on, until the cluster's `parity-shards` setting is set (see below), which overrides it on every node. |
| `--data-dir [<POOL>=]<PATH>` | `CAIRN_DATA_DIR` (comma-separated) | *required* | Local directory for blobs, of the pool `POOL` (`default` if none is named), which [storage classes](#storage-classes) keep their data in. May be given several times, a pool each. |
| `--allow-sse-c-over-http` | `CAIRN_ALLOW_SSE_C_OVER_HTTP` | off | Accept [SSE-C](#sse-c) keys in requests no proxy marked as HTTPS. Only for a network that's encrypted itself. |
| `--trusted-proxy <CIDR>` | `CAIRN_TRUSTED_PROXIES` (comma-separated) | none | A proxy in front of Cairn, whose `X-Forwarded-For` and `X-Forwarded-Proto` [policies](#users-and-permissions) believe (`aws:SourceIp`, `aws:SecureTransport`). May be given several times. |
| `--domain <NAME>` | `CAIRN_DOMAIN` | none | The domain the S3 API is reached at, e.g. `s3.example.com`, to take [virtual-hosted-style](#virtual-hosted-style-requests) requests. Any other host name (but IP addresses and `localhost`) is then a [website's](#websites) custom domain. |
| `--website-domain <NAME>` | `CAIRN_WEBSITE_DOMAIN` | none | The domain buckets' [websites](#websites) are reached at, e.g. `s3-website.example.com`: `bucket.s3-website.example.com` is the bucket's website. |
| `--listen-console <ADDR>` | `CAIRN_LISTEN_CONSOLE` | off | Bind address for the [console](#console), Cairn's web UI, which people sign in to with passkeys or OIDC. Requires `--console-url`. |
| `--console-url <URL>` | `CAIRN_CONSOLE_URL` | none | The URL the console is reached at, as browsers see it, e.g. `https://console.example.com`: an origin of its own (not the S3 API's), over HTTPS, or on `localhost`. Passkeys are bound to its host. |
| `--kms-root-key-file <PATH>`, `--kms-address <URL>`, ... | `CAIRN_KMS_*` | none | The [KMS](#kms)'s root key: a file, or a key of OpenBao's. Without one, SSE-KMS, SSE-S3 and KMS's API are refused. See [the root key](#the-root-key) for the rest of the `--kms-*` flags. |
| `--scrub-rate <RATE>` | `CAIRN_SCRUB_RATE` | `25MiB` | How many bytes per second the [scrubber](#scrubbing) reads, e.g. `100MB`. `0` turns it off. |
| `--max-connections <N>` | `CAIRN_MAX_CONNECTIONS` | `4096` | How many connections the S3 API serves at once; more wait to be accepted. Cairn raises its limit on open files to the hard limit (`LimitNOFILE=` under systemd), and warns if that leaves too few. |

The S3 API and the console close a connection that sits idle, or takes its
time sending a request's head, for 30 seconds; a request whose body sends
nothing for 30 seconds fails with `RequestTimeout`, and a response the client
takes none of for a minute is cut off.

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
so `my.bucket.s3.example.com` is the bucket `my.bucket`. Any other host name
is a [website's](#websites) custom domain then: clients that reach the S3 API
by another name (`cairn.internal`, say) must use the domain, an IP address
or `localhost` instead.

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
cairn config set parity-shards 2     # 3 copies of every new blob
cairn config unset parity-shards     # back to each node's flag
```

A change applies to blobs written from then on, and existing blobs are
brought to it in the background: the mover adds or drops copies, and the
packer rewrites erasure-coded blobs. While the setting isn't set, existing
blobs keep their copies, since nodes may go by different flags.

Large blobs can be stored with less overhead than full copies, with the same
tolerance for lost nodes: see [Erasure coding](#erasure-coding). Both settings
are the layout of STANDARD, and of every [storage class](#storage-classes)
that doesn't set its own.

### Removing nodes, and repair

Every blob is stored as shards, each on a node of its own (a copy of the
blob, or a piece of it if it's [erasure-coded](#erasure-coding)). To take a
node out of the cluster, remove it:

```sh
cairn node list          # nodes, their state, the shards they hold
cairn node remove 3
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
cairn config set repair-after 60   # minutes; 0, the default, is off
```

The console's Overview shows each node's state, and its Jobs page how many
shards are waiting to move.

### Storage classes

A **storage class** says where an object's data is kept and how much
redundancy it has: the **pool** its blobs go to, and their data and parity
shards (see [Erasure coding](#erasure-coding)). So objects can be on SSDs or
on HDDs, or kept with more or fewer copies, side by side. Clients ask for a
class as they ask S3 for one, with `x-amz-storage-class` on PutObject,
CreateMultipartUpload, CopyObject or a POST form:

```sh
aws s3 cp backup.tar s3://my-bucket/ --storage-class STANDARD_IA
```

A node keeps each pool it has in a data dir of its own, named by
`--data-dir <pool>=<path>` (given once per pool; a bare path is the pool
`default`). A node's shards of a blob are in the blob's pool, and a blob's
shards are each on a node of their own, as ever, so every pool spreads its
data over the nodes that have it:

```sh
# Nodes with SSDs and HDDs
cairn serve ... --data-dir default=/mnt/nvme/cairn --data-dir hdd=/mnt/disks/cairn
# A node with HDDs only
cairn serve ... --data-dir hdd=/mnt/disks/cairn
```

Then define the classes, for the whole cluster:

```sh
cairn class set STANDARD_IA --pool hdd --parity-shards 2 --data-shards 4
cairn class set REDUCED_REDUNDANCY --pool default --parity-shards 0
cairn class list
```

`--data-shards` and `--parity-shards` are the class's own layout: unset (or
set to `default`), it goes by the cluster's `data-shards` and `parity-shards`
settings, as STANDARD does until it sets its own. STANDARD always exists, in
the pool `default`; `cairn class set STANDARD --pool ssd` moves it. A class
can be named anything in capitals, digits and underscores, but S3's names are
safest, since some SDKs only send those. An object that asks for no class is
STANDARD, and so is one that asks for one of S3's classes that isn't defined
(as before Cairn had classes, so clients configured for, say, `STANDARD_IA`
keep working); any other class that isn't defined is refused with
`InvalidStorageClass`. `cairn class delete` deletes a class that holds no
objects or uploads.

An object reports its class as S3 does (HEAD and GET tell
`x-amz-storage-class` for any but STANDARD, listings, GetObjectAttributes and
inventory reports tell it always). It changes class by being copied into
another, onto itself, say:

```sh
aws s3 cp s3://my-bucket/backup.tar s3://my-bucket/backup.tar --storage-class STANDARD
```

A copy within a class shares its source's bytes, and so does one into a
[lower class](#the-order-of-classes) than its source's; one into another
class (a copy that names no class is STANDARD, as in S3) writes them again,
in its pool. A multipart upload's parts are of the class it was created in.

A change of a class applies to new objects within a heartbeat. Its existing
data is rewritten by the [packer](#packing), as after a change of the
redundancy settings: into its new pool (once the pool has nodes enough for
the class's copies), and its new layout; the mover adds or drops copies of
replicated blobs. A class needs as many active nodes with its pool as its
blobs take shards, as a cluster does for STANDARD: `cairn class set` warns
when it hasn't. A node that holds shards in a pool won't start without the
pool's `--data-dir`, which would lose them; [remove](#removing-nodes-and-repair)
the node first. `cairn node list` shows the nodes' pools, and the console's
Storage page each class's pool, layout, nodes and data; operators define,
change and delete classes there too.

#### The order of classes

Give the classes a **rank**, the warmest highest, for
[lifecycle rules](#lifecycle-rules) to move objects down into colder ones
(`Transition`):

```sh
cairn class set STANDARD_IA --rank -10
cairn class set GLACIER_IR --rank -20
cairn class set FAST --pool nvme --rank 10   # above STANDARD, which is 0
```

A class stands in for every class below it: its blobs may hold their
objects' data, and do, for a while. That's your promise, which Cairn takes
as given: keeping data in a higher class than it needs costs more, but is
otherwise as good. (A colder pool may well have more parity shards, for
less reliable disks: that's fine, as long as the warmer class is at least as
safe.) A class without a rank (`--rank none`, as every class but STANDARD
has until it's given one) is no other's, and lifecycle rules don't
transition objects into or out of it. No two classes share a rank.

A transition changes only the object's class: its data stays where it is,
and the [packer](#packing) moves it into the new class's pool the next time
it rewrites the blob it's in, which it does once enough of the blob is
garbage or data that belongs in lower classes (a quarter, together). Data
that a version of a higher class shares (a copy, say) stays where that one
needs it. `cairn class list` shows the ranks.

Upgrade every node: once one runs a Cairn with storage classes, older ones
can no longer write (they'd place shards on nodes without their pool), as
their log says.

### Remote tiers

A class can keep its data in a **tier** instead of a pool: a bucket of
another S3 service (AWS, or any other), for data that's rarely read and
cheaper to keep elsewhere. Add the tier, then point a class at it:

```sh
cairn tier add archive --endpoint https://s3.eu-central-1.amazonaws.com --region eu-central-1 \
    --bucket my-archive --prefix cairn/ --remote-class STANDARD_IA \
    --access-key-id AKIA... --secret-access-key ...   # or CAIRN_TIER_ACCESS_KEY_ID/_SECRET_ACCESS_KEY
cairn class set GLACIER_IR --tier archive
cairn tier list
```

Objects are written into the class as into any other (`--storage-class
GLACIER_IR`), and report it as theirs. Nothing waits on the tier: a write
lands in the cluster first, in STANDARD's pool and layout, and the
[packer](#packing) moves it into the tier in the background, packed into
objects of 256 MiB, once there's that much or a day has passed. So the
tier holds few, large objects, however many small ones the class has,
which matters for services that charge per request or per object. Reads
fetch the ranges they need from the tier; nothing is cached in the cluster.

Everything in the tier is encrypted (XChaCha20-Poly1305, as
[backups](#backups) are), with a key of the tier's own, which Cairn makes and
keeps in the database (and so in its backup), wrapped by the [KMS](#kms)'s
root key if there's one. The tier holds nothing
readable without it, and nothing it holds can be altered or swapped
unnoticed. `--remote-class` is the storage class the objects are written in
there (the service's default if not given); classes whose objects can't be
read without restoring them first (`GLACIER`, `DEEP_ARCHIVE`) are refused,
for now. The prefix must be the tier's own: `cairn tier add` refuses one
that holds objects. The console's Storage page adds, changes and deletes
tiers as well (it never shows their secrets, or their keys).

Objects deleted from a tier's class leave garbage in the tier's objects: one
that's at least half garbage is rewritten without it (which reads it from the
tier), and one that nothing needs anymore is deleted from the tier, once the
backup's retention (an hour at least) has passed, so that a restore finds
every object it points at. Checking the tier's data for damage is the
tier's job: Cairn doesn't scrub it. Give the bucket a lifecycle rule that
aborts incomplete multipart uploads, which a node that crashes mid-upload
leaves behind.

`cairn class set GLACIER_IR --tier other` moves the class's data to another
tier; `cairn class set GLACIER_IR --pool hdd` brings it back into the
cluster. Either way, the packer does it in the background. `cairn tier
delete` deletes a tier that no class names and that holds nothing anymore.

## Users and permissions

A **user** (called a role before; `cairn role` still works) is who makes S3
requests. Its name is unique in its [account](#users-and-permissions)
regardless of case, as in IAM (an account can't have both `Ada` and `ada`,
and looks either up as the other).
It may have a **path** (`/team-a/`, say; `/` if not), which its ARN has
before its name (`arn:aws:iam::<account>:user/team-a/ada`), and up to 50
**tags** (keys unique regardless of case), which policies see as
`aws:ResourceTag/<key>` (IAM's actions on the user) and
`aws:PrincipalTag/<key>` (the user's own requests). It has **access keys**: up to two,
as in IAM, each an access key ID and a secret. IDs are random, 20
characters, as IAM's (`cairn user create` prints the first); only a role
migrated from before access keys keeps a key named as it. Access key IDs are unique across the
cluster. Users are stored in
Postgres, so every node picks up a change on the very next request; there is
nothing to restart or sync.

What a user may do is decided by policies, in IAM's policy language, as in
S3: an explicit `Deny` in any that applies wins; else an `Allow` in any
allows; else it's denied. They are:

- its **managed policies**, as in IAM: documents of their own, attached to
  any number of users. There are Cairn's, which have AWS's names and say what
  AWS's do, so that policies and tools written for AWS work as they are:
  - **admin** (`--admin`) is `AdministratorAccess`: everything in the
    user's account (its buckets, their objects and configuration), but what
    a bucket's policy denies it.
  - `AmazonS3FullAccess` (`s3:*`, on every bucket of the account) and
    `AmazonS3ReadOnlyAccess` (`s3:Get*`, `s3:List*`).

  And the account's own (`arn:aws:iam::<account>:policy/<name>`), made with
  the console's Policies page or the IAM API: a document of up to 6,144
  characters (but whitespace); a user has at most 10 attached, as in IAM.
  **Grants** were the simple way to make them (the console's bucket
  access template still makes them): a grant attaches
  the account's policy `/cairn/grants/<bucket>-<permission>` (making it,
  the first time; with a suffix if another policy has the name). Only
  policies at that path are taken for grants: IAM decides who may change a
  policy by its path, so one made elsewhere could be changed after a grant
  attached it. A grant allows:
  - **`read`** on a bucket: GetObject, HeadObject, GetObjectAttributes,
    HeadBucket, ListObjects, reading an object's [tags](#tags) and its
    [Object Lock](#object-lock), and being the source of a
    CopyObject / UploadPartCopy.
  - **`write`** on a bucket: PutObject, DeleteObject(s), multipart uploads
    (listing them and their parts too, to resume one), changing an object's
    tags (any version's), and being the destination of a copy. In a
    versioned bucket, a delete only adds a delete marker. Not setting a
    version's Object Lock: a writer's versions get only the bucket's
    default retention.
  - **`delete-version`** on a bucket: DeleteObject(s) naming a version ID,
    which removes that version for good.

  (Grants used to be statements of the bucket's policy, `CairnGrantRead`
  and the like. A Cairn moves any it finds into these managed policies as
  it starts, attached to the same users, and takes them out of the
  bucket's policy; the access is the same. Upgrade every node: one from
  before doesn't know managed policies, and denies what they allow.)
- its **inline policies**: identity policies of its own, for anything finer
  (per key prefix, by condition, ...), set with PutUserPolicy;
- its **groups'** policies, as if they were its own: a **group** has inline
  policies (at most 5,120 characters together) and managed ones (at most
  10) as a user has, and members, the account's users, each in at most 10
  groups, as in IAM. So `invoices-read` is attached to the group of those
  who read invoices, not to each of them. A group has a path and a name
  (`arn:aws:iam::<account>:group/<path…/name>`, unique regardless of case),
  but no tags or boundary, and it's no principal: policies name it only as
  the resource of IAM's actions on it. A member's permissions boundary caps
  what its groups' policies allow too, as its own. Older Cairns know no
  groups: to them, a user in any has an inline policy that denies it
  everything; upgrade every node.
- its **permissions boundary**, if it has one: a managed policy (the
  account's own, or Cairn's) that caps what its identity policies (managed
  and inline) allow: they allow only what the boundary allows too, and a
  `Deny` in it denies, as in AWS. A bucket policy that names the user (or
  everyone) still allows it within the account, beyond the boundary; one
  that names the account doesn't. That's how a non-admin can be let manage
  users: a policy that allows `iam:CreateUser` and the like only under a path
  of theirs and with a boundary (the condition key `iam:PermissionsBoundary`),
  and denies changing that policy or taking boundaries off, lets them make
  users who can never do more than the boundary (the [team
  template](#teams-and-policy-templates) makes such policies, done right).
  Older Cairns know no boundaries:
  to them, a user with one has an inline policy that denies it everything,
  and they can't change users, keys or policies at all; upgrade every node.
- each bucket's **bucket policy**, set with PutBucketPolicy (by an admin), as
  in S3. A bucket policy can allow other users, or anyone: unsigned requests
  are **anonymous**, and only a bucket policy with `"Principal": "*"` can
  allow them (a public bucket, say). Users are named in policies as
  `arn:aws:iam::<account>:user/<path…/name>` (`aws sts
  get-caller-identity` says the account's ID). As in S3, a bucket policy names the user that
  had the name when the policy was set: a user deleted and created again
  under the same name isn't allowed what the first was, and the policy then
  shows the first by its ID; one renamed or moved since still is, and the
  policy shows its ARN as it is now.

**Accounts**, as AWS's, in an organization as AWS Organizations has them.
The account Cairn starts with (a 12-digit ID) is the **management
account**: it owns the cluster (`cairn:` actions) and Identity Center, and
makes **member accounts**. Each account has its own users, roles, policies,
buckets (whose names are global, as in S3) and public access block, and
nothing of another's unless a policy allows it, as between AWS accounts.
Teams can also be kept apart within an account by IAM: users' paths
(`/team-a/`), permissions boundaries, and policies that give each team its
own buckets, down to the names it may create (`s3:CreateBucket` on
`arn:aws:s3:::team-a-*`).

A member account is made in the console's Organization page, or with
Organizations' API (`aws organizations create-account`, with
`AWS_ENDPOINT_URL_ORGANIZATIONS` pointed at the S3 endpoint). It gets
`OrganizationAccountAccessRole`, allowing everything and trusting the
management account, as AWS's does: the management account's principals
whose own policies allow `sts:AssumeRole` on it get into the member account
by assuming it, and directory users with the permission sets assigned to
them there ([Directory users](#directory-users)). Between accounts,
resource policies decide, as in AWS: a bucket's policy, a role's trust
policy, an SNS topic's (`aws sns add-permission`), an Access Grants
instance's; the caller's own policies must allow it too. Member accounts
have no root user, as AWS recommends. Closing one (`close-account`, or the console)
is at once, once it has no buckets: its users, roles and sessions stop
working.

```sh
export AWS_ENDPOINT_URL_ORGANIZATIONS=https://s3.example.com
aws organizations create-account --account-name "Team A" --email team-a@example.com
aws sts assume-role --role-arn arn:aws:iam::<member>:role/OrganizationAccountAccessRole \
    --role-session-name setup
```

In the console, **Switch role** (in the menu at the top right, or by an
account on the Organization page) does the same, as AWS's console does: the
session acts as a session of the role
(`arn:aws:sts::<member>:assumed-role/OrganizationAccountAccessRole/<you>`)
for an hour at most, or until it switches back. Who may switch to a role is
who may assume it with STS: the role's trust policy must allow them, and for
another account's role their own policies must too (`AdministratorAccess`
does). That's checked when they switch, from who they signed in as (a user,
or a directory user's permission set's role's session); the root user
switches to no role, as in AWS. The roles switched to lately are kept in the
browser.

Accounts are grouped in **organizational units** (OUs), nested under the
organization's root (five deep at most), and **service control policies**
(SCPs) set the most that a member account's principals may do, as AWS's:
once SCPs are enabled, every request by a user or role of a member account
must be allowed by an SCP at every level from the root down to its account
(the root, each OU on the way, the account), and denied by none, whatever
its IAM policies or a bucket's policy allow. They grant nothing. Enabling
them attaches AWS's `FullAWSAccess` (allowing everything) to the root,
every OU and every account, and to each made later; every one keeps an SCP
at least, so replace it before detaching it. The management account is
under none. SCPs are an identity policy's language, with a `Version`, and
only `"Resource": "*"` in an Allow. The console's Organization page makes,
renames and deletes OUs, moves accounts, enables and disables SCPs, and
makes, edits, attaches and detaches them, as Organizations' API does.

```sh
root=$(aws organizations list-roots --query 'Roots[0].Id' --output text)
aws organizations enable-policy-type --root-id $root --policy-type SERVICE_CONTROL_POLICY
ou=$(aws organizations create-organizational-unit --parent-id $root --name Prod \
    --query OrganizationalUnit.Id --output text)
aws organizations move-account --account-id <member> --source-parent-id $root --destination-parent-id $ou
policy=$(aws organizations create-policy --type SERVICE_CONTROL_POLICY --name NoBucketDeletes \
    --description "" --query Policy.PolicySummary.Id --output text --content \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"}]}')
aws organizations attach-policy --policy-id $policy --target-id $ou
```

The management account has a **root user**, as AWS's, for getting back in when
policies lock everyone out. Only the command line on a node can make
someone the root: it has no passkeys, long-term keys or password. Either of
two commands on a node makes it, for a while:

- `cairn account root-link` prints a one-time link to sign in to the
  [console](#console) (valid 15 minutes; its session lasts an hour at most,
  and 15 minutes unused);
- `cairn account root-key` prints temporary credentials for the S3, IAM and
  STS APIs, valid 15 minutes (as AWS's `AssumeRoot`'s at most), as shell
  `export`s: `eval "$(cairn account root-key)"`, then `aws s3api
  delete-bucket-policy ...`. `cairn sessions revoke-all` ends them sooner
  (no policy can).

Whoever can run those could change the database anyway, so the root adds no
way in; each link and key made, and each sign-in, is logged on its node.
As in AWS:

- no identity policy restricts it: no policy can be attached to it, and no
  permissions boundary or group applies. It may do anything in the account,
  IAM and the cluster's `cairn:` actions included;
- a bucket's (or topic's) policy that denies everyone (`"*"`), or the
  account (`arn:aws:iam::<account>:root`, or its ID), denies it too; but it
  may always get, set and delete its own buckets' policies, whatever they
  say: that's the way out of a policy that denies everyone;
- its session isn't multi-factor (`aws:MultiFactorAuthPresent` is false),
  so a policy that denies requests without MFA denies it too (but for the
  policy itself). It has `aws:PrincipalType` `Account`, and its
  `aws:userid` is the account's ID;
- Object Lock's compliance mode holds against it, and it assumes no
  roles; the KMS doesn't know it, so it can't read SSE-KMS objects;
- it's no user: IAM's actions on the signer's own user (CreateAccessKey or
  ListAccessKeys without `UserName`, say) must name one, and STS makes no
  sessions of it (GetSessionToken, GetFederationToken, AssumeRole), nor S3
  Express of its directory buckets;
- only it can enable **MFA delete** on a bucket, with a code of its virtual
  MFA device, which `cairn account root-mfa` makes (and prints, for an
  authenticator app). Then deleting a version, or changing the bucket's
  versioning, takes the root's credentials and a code, over HTTPS; and the
  bucket can't have a lifecycle configuration. The device is a second
  factor, not a way in: it's only asked for with the root's credentials.

```sh
cairn account root-mfa             # once: add it to an authenticator app
eval "$(cairn account root-key)"
SERIAL=arn:aws:iam::<account>:mfa/root-account-mfa-device
aws s3api put-bucket-versioning --bucket my-bucket \
  --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa "$SERIAL 123456"
aws s3api delete-object --bucket my-bucket --key k --version-id <version> --mfa "$SERIAL 654321"
```

So the root is how to undo whatever policies lock: an admin's
`AdministratorAccess` taken away, a boundary or a group's deny that keeps
everyone out, a bucket policy that denies everyone. With the console, or
without one, through the IAM and S3 APIs:

```sh
eval "$(cairn account root-key)"   # with AWS_ENDPOINT_URL set, as above
aws iam delete-user-permissions-boundary --user-name ada
aws iam attach-user-policy --user-name ada --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws s3api delete-bucket-policy --bucket my-bucket
```

In a bucket policy, `arn:aws:iam::<account>:root` (or the account's ID)
means what it does in AWS: the account, whose users' own policies then
decide, and its root user.

**Operators** run the cluster: they're users whose policies allow Cairn's
own actions, `cairn:` ones (`cairn:GetCluster`, `cairn:PutSetting`,
`cairn:RemoveNode`, `cairn:PutStorageClass`, `cairn:DeleteStorageClass`,
`cairn:PutTier`, `cairn:DeleteTier`, `cairn:PutReplicationRemote`,
`cairn:DeleteReplicationRemote`, `cairn:PutBackup`, `cairn:StartBackup`, …),
on the cluster. `AdministratorAccess` (`*`) includes
them; Cairn's managed policy `CairnOperatorAccess` allows them and nothing
else (the cluster, without the data).

A console session of a [directory user](#directory-users) signed in with
a passkey has `aws:MultiFactorAuthPresent` (`true`) and
`aws:MultiFactorAuthAge` (seconds since it was signed in); one signed in at
an identity source has it `false`,
and access keys never have it, as AWS's long-term keys don't. AWS's guard
then keeps a leaked key from doing what matters, in any identity policy:

```json
{"Effect": "Deny", "Action": ["cairn:*", "iam:*"], "Resource": "*",
 "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}}
```

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
bucket's *Access and policy* in the console) has S3's four flags:
`BlockPublicPolicy` refuses a bucket policy that makes the bucket public
(one that allows everyone something, with no condition that limits it to
fixed addresses, accounts or the like), and `RestrictPublicBuckets` makes a
public policy allow nothing to anyone outside the bucket's account,
anonymous requests included (the account's own users keep what it allows
them). `BlockPublicAcls` refuses an ACL (see below) that grants everyone (or
any signed request) something, and `IgnorePublicAcls` makes such grants
allow nothing. **New buckets have all four
on**, as S3's do, so making one public takes turning its block off first
(`aws s3api delete-public-access-block`); buckets made before Cairn had
blocks have none.

Each account has a block of its own too, as in S3, which every one of its
buckets gets, whatever their own says. A new account has none. Users allowed
`s3:PutAccountPublicAccessBlock` set it through S3 Control's
API (`aws s3control`), or with the switches above the console's bucket list.
It's the account's alone: the operator doesn't set it. S3 Control's clients
put the account ID in front of the endpoint's host
(`123456789012.s3.example.com`), so they need a host name that resolves for
any subdomain, as virtual-hosted buckets do, not an IP address.

```sh
aws s3api delete-public-access-block --bucket my-bucket   # then put the public policy above
aws s3control put-public-access-block --account-id 123456789012 \
    --public-access-block-configuration BlockPublicPolicy=true,RestrictPublicBuckets=true
```

`aws:SourceIp` and `aws:SecureTransport` (and so policies that ask for an
address, or for HTTPS) take the client's address and protocol from
`X-Forwarded-For` and `X-Forwarded-Proto` only if the request came from a
`--trusted-proxy`; otherwise, the connection's own address counts, and it's
not HTTPS (Cairn speaks only HTTP).

ListBuckets lists every bucket of the account, to a user whose policies
allow it `s3:ListAllMyBuckets` (as AdministratorAccess does); to anyone
else it's AccessDenied, as in S3, which has no way to list only some
buckets. The console's bucket list is friendlier: without
`s3:ListAllMyBuckets` it shows the buckets the user's policies let it list
(`s3:ListBucket`), and those whose policies name it, so teams sharing the
account needn't see each other's bucket names.
Policies name buckets by name, and outlive them, as in AWS: a bucket deleted
and made again under the same name is open to whoever's policies name it.

**ACLs** are S3's older way to share buckets and objects, which AWS discourages
but some tools still use, so Cairn has them as S3 does. They're off on a new
bucket, as on S3's (Object Ownership "bucket owner enforced"): access is a
matter of policies alone, the bucket's account owns everything in it, a
request that asks for an ACL other than the owner's (`bucket-owner-full-control`
for an object, `private` for a bucket) is refused with
`AccessControlListNotSupported`, and reading an ACL shows the owner with full
control.

A bucket's Object Ownership turns them on, when it's made or later:

```sh
aws s3api create-bucket --bucket shared --object-ownership ObjectWriter
aws s3api put-bucket-ownership-controls --bucket my-bucket \
    --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerPreferred}]'
```

With `ObjectWriter`, an object belongs to the account that wrote it; with
`BucketOwnerPreferred`, to the bucket's account if the writer gives it full
control (`--acl bucket-owner-full-control`), as is the usual way to hand
uploads over. A bucket's and an object's ACL grant `READ`, `WRITE`,
`READ_ACP`, `WRITE_ACP` or `FULL_CONTROL` to accounts (by canonical ID, the
`Owner` `get-bucket-acl` shows, or account ID or e-mail address), to everyone,
to any signed request, or to S3's log delivery. They're set as a write's
canned ACL (`--acl public-read`) or grants (`--grant-read id=…`), or with
`put-bucket-acl` and `put-object-acl`. A grant allows what a bucket policy's
statement naming its grantee would: to an account's root user, and to its
users whose own policies allow it too. An object another account owns is
that account's to share: the bucket's policy can't allow reading it (but can
deny it), while its ACL can; the bucket's owner may still delete it.

ACLs that make something public are refused, or ignored, while Block Public
Access says so (above), as new buckets' does. Setting the
ownership back to `BucketOwnerEnforced` turns ACLs off again (once the
bucket's own grants no one else anything) and makes the bucket's account
own everything; the ACLs are kept, and come back if they're turned on again.

Bucket names follow S3's rules: 3 to 63 lowercase letters, digits, dots and
hyphens, starting and ending with a letter or digit, not formatted like an IP
address, and without the prefixes and suffixes S3 reserves (such as `xn--` or
`-s3alias`).

Manage users with the IAM API or the console. The command line only makes
the first ones, to set a cluster up (it acts on the database, whatever the
policies say); after that, the account's [root
user](#users-and-permissions) is the way back in:

| Command | Description |
| --- | --- |
| `cairn user create <name> [--admin] [--id <ID>] [--secret <S>]` | Create an IAM user with an access key of a random 20-char ID (or `--id`), whose ID is printed, with a generated 40-char secret unless `--secret` is given (min. 8 chars): a service's. `--admin` gives it `AdministratorAccess`. `cairn role create` does the same. |
| `cairn directory-user create <user-name> [--admin] [--display-name <N>] [--email <E>]` | Create a user of Cairn's own [directory](#directory-users), and print a link (valid 7 days) for it to set up a passkey for the [console](#console) with: made from the console URL of the node the command runs on; one that serves no console prints the link's path. `--admin` assigns it the permission set `AdministratorAccess` (made if there's none) in the management account; given for a user that exists already, it does that and prints a new link. |
| `cairn directory-user link <user-name>` | Print a new setup link for a user of Cairn's own directory (after it lost its passkeys, say). |
| `cairn account root-link` | Print a one-time link (15 minutes) to sign in to the console as the account's root user. |
| `cairn account root-key` | Print temporary credentials (15 minutes) of the account's root user, as shell `export`s. |
| `cairn account root-mfa [--replace]` | Make the account's root user's virtual MFA device, for MFA delete, and print its serial number and secret (as an `otpauth://` URI). `--replace` makes a new one; the old one's codes stop working. |
| `cairn sessions revoke-all` | End every temporary credential issued so far (AssumeRole's, GetSessionToken's, root keys, ...). |

**The IAM API** is on the S3 endpoint too: requests signed for the `iam`
service (SigV4's credential scope) are IAM's, whatever their path, so the AWS
CLI, SDKs and Terraform manage users with Cairn as their IAM endpoint (the
same URL as for S3: `aws iam --endpoint-url ...`, or Terraform's
`endpoints { iam = ... }`). Each request acts as its signer, in its account,
checked as IAM's actions on the user's ARN (`iam:CreateUser`,
`iam:CreateAccessKey`, `iam:PutUserPolicy`, ...): an admin may do all of it,
another user what its policies allow (its own keys, with a policy on
`arn:aws:iam::*:user/${aws:username}`, say). There are users (CreateUser,
with a path, tags and a permissions boundary; GetUser; ListUsers, by path
prefix; UpdateUser, which renames or moves one; DeleteUser, which refuses
while keys or policies are left, as IAM does), their tags (TagUser,
UntagUser, ListUserTags) and permissions boundaries
(PutUserPermissionsBoundary, DeleteUserPermissionsBoundary), access keys
(Create, List, Update, Delete), inline policies (Put, Get, List, Delete),
and managed policies: CreatePolicy (with a path and tags), GetPolicy, ListPolicies,
DeletePolicy (refused while attached, or a boundary),
ListEntitiesForPolicy, and AttachUserPolicy, DetachUserPolicy and
ListAttachedUserPolicies, of Cairn's (AWS's ARNs) or the account's own, and
their tags (TagPolicy, UntagPolicy, ListPolicyTags; keys case-sensitive, as
on AWS, and `aws:ResourceTag/…` in IAM actions on the policy).
Condition keys are IAM's: `iam:PermissionsBoundary`, `iam:PolicyARN`,
`aws:ResourceTag/…` (and `iam:ResourceTag/…`), `aws:RequestTag/…` and
`aws:TagKeys`, decided as AWS decides them (probed). A policy keeps up to
five versions (`v1`, `v2`, ..., never numbered again), as in IAM: the default
decides (CreatePolicyVersion, with SetAsDefault or not; SetDefaultPolicyVersion
rolls back; GetPolicyVersion, ListPolicyVersions, DeletePolicyVersion but of
the default), and a policy with more than one can't be deleted. The console's
edit makes a new default version, deleting the oldest that isn't the default
if there are five already, as Terraform does. [Roles](#roles-and-temporary-credentials)
are there too (CreateRole, GetRole, ListRoles, UpdateRole,
UpdateRoleDescription, UpdateAssumeRolePolicy, DeleteRole, and their
policies, boundaries and tags, as users'), and OpenID Connect providers
(CreateOpenIDConnectProvider and the rest), and groups: CreateGroup (with a
path), GetGroup (with its members), ListGroups (by path prefix), UpdateGroup
(which renames or moves one, checked on where it goes too), DeleteGroup
(which refuses while members or policies are left, as IAM does),
AddUserToGroup and RemoveUserFromGroup (checked on the group),
ListGroupsForUser (on the user), their inline policies (PutGroupPolicy,
GetGroupPolicy, ListGroupPolicies, DeleteGroupPolicy) and managed ones
(AttachGroupPolicy, DetachGroupPolicy, ListAttachedGroupPolicies); a user in
a group isn't deleted, nor a managed policy attached to one. STS
answers on the same endpoint (requests signed for `sts`): GetCallerIdentity,
which Terraform's AWS provider calls as it starts, and the actions that issue
temporary credentials. The AWS CLI refuses access key IDs shorter than
16 characters as parameters (`--access-key-id`): the keys Cairn makes are
20, as IAM's, but a role migrated from before access keys keeps its key named
as it.

A bucket policy can deny everyone everything, its admins too, as in S3. The
account's [root user](#users-and-permissions) can always change or remove it,
as in AWS: `eval "$(cairn account root-key)"`, then `aws s3api
delete-bucket-policy --bucket <bucket>`.

Secrets are stored in plaintext in the `access_keys` table: SigV4 (as SigV2) is an HMAC scheme,
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
a link can download an object under a name of its own. For an SSE-C object,
the URL has to be signed with the key's headers, and the client has to send
them.

**SigV2** is taken as well, in the `Authorization` header (`AWS
<key>:<signature>`) or a presigned URL (`AWSAccessKeyId`, `Expires`,
`Signature`), since some clients still presign with it by default
(`aws s3 presign`, boto3's `generate_presigned_url` without a
`signature_version`). It signs neither the host nor the body (but for a
`Content-MD5`) nor any query parameter but a subresource's, so prefer SigV4
where a client lets you choose. A SigV2 URL is valid until its `Expires`,
however far away, as in S3 (a SigV4 one for at most a week), and a
header-signed request must be within the same 15 minutes of its `Date` or
`x-amz-date`. POST forms may be signed with SigV2 too (`AWSAccessKeyId`,
`signature`, as boto3's `generate_presigned_post` makes them by default).
Policies tell it apart by `s3:signatureversion`, `AWS` (SigV4's is
`AWS4-HMAC-SHA256`), and can deny it everywhere with a `StringNotEquals` on
that key.

**POST Object** (browser-based uploads) works as in S3: a `multipart/form-data`
form posted to a bucket, with a POST policy signed with a user's credentials
(SigV4, or SigV2, as boto3's `generate_presigned_post` makes them), uploads its file as
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

### Teams and policy templates

One Cairn account can be shared by teams (tenants) that mustn't reach each
other's data, users or policies. IAM can do that, with paths, permissions
boundaries and conditions, but it's easy to get wrong; Cairn's **policy
templates** write the policies for it, and the console's Policies page
makes them (*From a template*: the documents are shown first). A template
makes ordinary managed policies, tagged `cairn:template` and
`cairn:template-version`, as IAM's CreatePolicy by whoever uses it, so it
allows nothing by itself: a team's admin may use templates within its team,
and nothing outside it. Their documents work as they are with `aws iam
create-policy` too.

- **Team** (the account's admins make it): for team `T` with bucket prefix
  `p-` (default: `t-`, the name in lowercase), two policies at
  `/cairn/teams/T/`, where the team can't change them:
  - `T-team`, everything the team may do: `s3:*` on the buckets `p-*`
    (making them too), `iam:*` on the users, roles and policies at `/T/`,
    reading Cairn's policies and the team's, `sts:AssumeRole` on the team's
    roles; and the guardrails: no user or role made or bounded without
    `T-team` as its permissions boundary, no permissions given to or taken
    from one that hasn't it, no boundary taken off. It's both the team
    admins' policy and everyone's boundary: attach it to a user or a role at
    `/T/` and make it that one's boundary too, and it's an admin of the
    team. (An admin policy narrower than the boundary would only look
    narrower: an admin may give the team's users and roles anything up to
    the boundary.) The guardrails hold either way: for a member the admin
    gave AdministratorAccess (the boundary has them), and for an admin
    without the boundary.
  - `T-member`: reading and writing the team's buckets, and one's own
    access keys.

  Opt-ins: `s3:ListAllMyBuckets` (ListBuckets lists every bucket of the
  account, as in S3: there's no listing only some) and `iam:ListPolicies`
  (likewise every policy). Without them, the console still lists a team's
  buckets and policies to it. What stays outside IAM: bucket names are one
  namespace (a team learns that a name is taken), a team's bucket policy may
  name anyone (and make a bucket public, unless the account's
  [public access block](#users-and-permissions) stops it).
- **Bucket access**: reading, writing, deleting versions for good, and
  managing (configuration, policy, deleting it) a bucket, or the buckets a
  pattern names (`logs-*`). A grant is one level of it on one bucket.
- **MFA guard**: denies `iam:*` and `cairn:*` without MFA: to directory
  users, signed in at an identity source, and to access keys, which never
  carry MFA, as in AWS.

## Roles and temporary credentials

A **role** is an identity no one signs as with keys of its own: whoever its
**trust policy** lets in *assumes* it, and gets **temporary credentials**
(an access key ID starting `ASIA`, a secret and a session token) that act
as the role, with its policies, until they expire. That's how a program
gets access without a long-lived secret, and how people switch to more
access only when they need it. Roles are made with the console's Roles page,
or the IAM API (`aws iam create-role`, Terraform's `aws_iam_role`). A role
has a path, a description, tags, inline and managed policies and a
permissions boundary, as a user has, and a longest session it allows (1 to
12 hours; `--max-session-duration`). Its ARN is
`arn:aws:iam::<account>:role/<path…/name>`.

A trust policy is a policy whose statements name who may assume the role:

- `{"AWS": "arn:aws:iam::<account>:user/ada"}`, a user (or a role, for
  chaining): it may, whatever its own policies say;
- `{"AWS": "arn:aws:iam::<account>:root"}`, the account: then the users'
  own policies decide (they need `sts:AssumeRole` on the role), as in AWS;
- `{"Federated": "arn:aws:iam::<account>:oidc-provider/<url>"}`, the web
  identities of an [OpenID Connect provider](#web-identities) (CI jobs,
  Kubernetes service accounts).

Its conditions see `sts:ExternalId`, `sts:RoleSessionName`,
`sts:SourceIdentity`, `sts:TransitiveTagKeys`, session tags
(`aws:RequestTag/…`), and a web identity's claims. Statements allowing
`sts:TagSession` and `sts:SetSourceIdentity` let a session have tags or a
source identity.

**STS** is on the S3 endpoint, as IAM is: point the AWS CLI's or SDKs' STS
endpoint at Cairn (`aws sts --endpoint-url ...`, `AWS_ENDPOINT_URL_STS`, or
`endpoint_url` in a profile). It has:

- **AssumeRole**: a role's credentials, for 15 minutes up to the role's
  longest session (an hour by default; an hour at most when a role's session
  assumes another, *chaining*), with an optional session policy (`Policy`,
  `PolicyArns`) that narrows what the session may do, session tags, an
  external ID and a source identity, as in AWS. AWS CLI profiles with
  `role_arn` and `source_profile`, and Terraform's `assume_role`, use it.
- **AssumeRoleWithWebIdentity**: the same, for an OIDC provider's ID token,
  and unsigned: the token is the authentication. See
  [web identities](#web-identities).
- **GetSessionToken**: a user's own credentials, for 15 minutes to 36 hours
  (12 by default). They may call STS's AssumeRole and GetCallerIdentity but
  not IAM, as AWS's without MFA.
- **GetFederationToken**: credentials of a *federated user* (a name of your
  choosing, `arn:aws:sts::<account>:federated-user/<name>`), which may do what
  both the calling user's policies and the session policy given allow.
- **GetCallerIdentity**, **GetAccessKeyInfo**.

```sh
aws iam create-role --role-name deployer --assume-role-policy-document \
    '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
      "Principal": {"AWS": "arn:aws:iam::123456789012:user/ada"}}]}'
aws iam attach-role-policy --role-name deployer --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/deployer --role-session-name ada
```

A session may do what its role's policies allow, capped by the role's
boundary and the session policy; a bucket policy that names the session
(`arn:aws:sts::<account>:assumed-role/<role>/<session>`) allows it beyond
both, one that names the role doesn't (probed). Its requests carry
`aws:PrincipalType` `AssumedRole`, `aws:userid` `AROA…:<session>`,
`aws:PrincipalArn` (the role's ARN), `aws:TokenIssueTime`,
`aws:SourceIdentity`, `aws:PrincipalTag/…` (the role's tags and the
session's, which win) and, for a web identity's, `aws:FederatedProvider`.
The role's policies are read on every request, so a change applies to its
sessions at once. A session using SSE-KMS acts as its role: its policies
(and the key's) decide which [KMS](#kms) keys it may use.

A session's token holds everything about it, sealed (XChaCha20-Poly1305)
with a key of the cluster's, so issuing one writes nothing and any node
checks it. The keys are in the database; a new one is made every day, and
old ones are dropped once no session they sealed can still be valid. To end
a role's sessions before they expire, do as AWS does: deny them by
`aws:TokenIssueTime` (the console's *Revoke sessions* writes AWS's
`AWSRevokeOlderSessions` inline policy, which denies everything to sessions
issued before now). Deleting a role ends its sessions too (a role made again
with its name doesn't revive them). `cairn sessions revoke-all` is the
break-glass: it drops the keys, so every temporary credential stops working,
on every node within a minute. A node older than roles refuses `ASIA` keys,
so upgrade every node before relying on sessions.

### Web identities

A program that has an **ID token** of an OpenID Connect issuer (a GitHub
Actions job, a GitLab CI job, a Kubernetes service account, your own
Keycloak's clients) can assume a role with it, without any secret stored in
Cairn or the program: STS's AssumeRoleWithWebIdentity, which AWS's SDKs and
CLI call by themselves given `AWS_ROLE_ARN` and
`AWS_WEB_IDENTITY_TOKEN_FILE`.

First, the issuer is made an **OIDC provider** of the account (on the Roles
page, or `aws iam create-open-id-connect-provider`, Terraform's
`aws_iam_openid_connect_provider`), with the client IDs its tokens may be
for (their audience; AWS's tools ask for `sts.amazonaws.com`). These are
IAM's providers, for workloads, apart from the console's [identity
sources](#directory-users), for people: an issuer may be both, configured
in each place.
Then a role trusts it, naming the subjects that may assume it, by the
token's claims `<url>:sub`, `<url>:aud` and `<url>:amr`:

```sh
aws iam create-open-id-connect-provider --url https://token.actions.githubusercontent.com \
    --client-id-list sts.amazonaws.com
aws iam create-role --role-name ci --assume-role-policy-document '{"Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
    "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
    "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
                  "StringLike": {"token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:*"}}}]}'
```

Always condition on the subject: without it, every identity the issuer
vouches for (every repository on GitHub, say) may assume the role.

Cairn takes a token only if its issuer (`iss`) is one of the account's
providers, checked before Cairn fetches anything; its signature is by the
keys of the issuer's discovery document (RS256–512, PS256–512, ES256, ES384,
EdDSA; never `none` or HMAC); its audience is one of the provider's client
IDs; and it hasn't expired. It's refused with STS's errors
(`InvalidIdentityToken`, `ExpiredTokenException`, `IDPCommunicationError`).
A token may carry session tags (`https://aws.amazon.com/tags`) and a source
identity (`https://aws.amazon.com/source_identity`), as AWS takes them, which
need `sts:TagSession` and `sts:SetSourceIdentity` in the trust policy.

**Where issuers may be.** Any IAM user allowed
`iam:CreateOpenIDConnectProvider` picks an issuer's URL, which Cairn then
fetches from, so by default issuers are reached over HTTPS at **public
addresses only**: not loopback, private ranges, link-local (cloud metadata
services), shared or unique-local ones, whatever the name resolves to. An
issuer inside the cluster's network (a Kubernetes API server's) needs the
operator to allow it, for the whole cluster:

```sh
cairn config set oidc-private-issuers 1
```

**Thumbprints.** An issuer's HTTPS certificate is checked against the public
roots. One of a private CA is trusted if the provider has the SHA-1 of a
certificate the server presents (its own, or a CA's in its chain) among its
`ThumbprintList` (up to five; `openssl x509 -fingerprint -sha1`): that
certificate becomes the anchor the chain is verified to, name and expiry
included. AWS no longer uses thumbprints; in Cairn they're what lets a
self-hosted issuer with its own CA work.

### S3 Access Grants

**S3 Access Grants** map who may read or write which part of S3, as a list
of grants rather than policies: each gives an IAM user or role `READ`,
`WRITE` or `READWRITE` on a scope (`s3://bucket/prefix/*`, or one object).
Grants decide no request themselves. A grantee calls **GetDataAccess** for
what it wants, and gets temporary credentials of a role that S3 Access
Grants assumes for it, narrowed by a session policy to what its grant
allows (or, with `--privilege Minimal`, to what it asked for). It then uses
those, as AWS's SDK plugins, EMR and Spark do. So a grant needs no change to
any policy, and tens of thousands of them fit where a bucket policy's 20 KB
wouldn't.

It's S3 Control's API (`aws s3control`, which puts the account's ID in
front of the endpoint's host, `123456789012.s3.example.com`: that name must
reach Cairn too, as a bucket's does with [virtual-hosted-style
requests](#virtual-hosted-style-requests)):

1. An account has one **instance**: `create-access-grants-instance`.
2. A **location** is a scope (`s3://`, a bucket, a prefix) and the **role**
   whose sessions its grants vend. The role's policies must allow what the
   grants do, and its trust policy must let the service in:

   ```json
   {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
     "Principal": {"Service": "access-grants.s3.amazonaws.com"},
     "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"},
                   "ArnEquals": {"aws:SourceArn": "arn:aws:s3:us-east-1:123456789012:access-grants/default"}}}]}
   ```

   Making or changing a location needs `iam:PassRole` on its role.
3. A **grant** is on a location, with a sub-prefix (`data/logs/*`), or an
   object's key with `--s3-prefix-type Object`.

```sh
aws s3control create-access-grants-instance --account-id 123456789012
aws s3control create-access-grants-location --account-id 123456789012 \
    --location-scope s3:// --iam-role-arn arn:aws:iam::123456789012:role/access-grants
aws s3control create-access-grant --account-id 123456789012 --access-grants-location-id default \
    --access-grants-location-configuration S3SubPrefix='data/logs/*' --permission READ \
    --grantee GranteeType=IAM,GranteeIdentifier=arn:aws:iam::123456789012:user/ada
# As ada, who needs s3:GetDataAccess:
aws s3control get-data-access --account-id 123456789012 --target 's3://data/logs/*' --permission READ
```

GetDataAccess takes the grantee's narrowest grant that covers the target
with the permission asked for (`READWRITE` covers either), and answers
which it matched. Its session lasts an hour by default (15 minutes to the
role's longest), and its requests are decided as the role's other
sessions' are: by the role's policies, capped by the session policy, and
the buckets' policies; they carry the instance's ARN as
`s3:AccessGrantsInstanceArn`, so a role's or bucket's policy can tell them
apart. `READ` allows reading objects (and their versions) and listing
under the scope; `WRITE` writing and deleting them (versions too), and
multipart uploads. Each operation needs its `s3:` action (`s3:CreateAccessGrant`,
`s3:GetDataAccess`, …) on the instance's, location's or grant's ARN, with
`s3:AccessGrantScope` and `s3:AccessGrantsLocationScope` to condition on;
`list-caller-access-grants` shows a grantee its own grants. The root user
may manage all of it, but is no grantee.

**Another account's** users and roles may be grantees too. They call
GetDataAccess with the instance's account ID, and need it allowed both by
their own policies and by the instance's **resource policy**:

```sh
aws s3control put-access-grants-instance-resource-policy --account-id 123456789012 --policy '{
  "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "444455556666"},
    "Action": ["s3:GetDataAccess", "s3:ListCallerAccessGrants"],
    "Resource": "arn:aws:s3:us-east-1:123456789012:access-grants/default"}]}'
```

These are AWS's *Access Grants*, not Cairn's old [grants](#users-and-permissions),
which were managed policies. Grantees are IAM users and roles only:
Identity Center's directory users and groups aren't, yet (see
[S3-COMPATIBILITY.md](S3-COMPATIBILITY.md#access-grants)).

## Console

The console is Cairn's web UI: people manage the accounts' buckets,
objects, users and policies there, and its operators watch and run the
cluster. It's off unless a node is started with `--listen-console` and
`--console-url`; any number of nodes may serve it, behind one URL. People
sign in as [directory users](#directory-users), as at IAM Identity
Center's access portal: with **passkeys** (users of Cairn's own directory),
or at an **identity source**, an OpenID Connect provider. There are no
passwords, IAM users don't sign in (they have access keys, for S3 and the
IAM API, never for the console), and the root user only with a link from a
node.

```sh
cairn serve ... --listen-console 0.0.0.0:9480 --console-url https://console.example.com
```

The first person comes from the command line: a directory user with the
permission set `AdministratorAccess`, and the link it prints to set up a
passkey with (the console's sign-in page shows the command until someone
can sign in). Everyone after that is made in the console.

```sh
cairn directory-user create ada --admin    # on a node that serves the console
```

The console acts as its identity, the session of the permission set's role
(or of a role switched to): it allows exactly what that identity's S3, IAM
and `cairn:` requests would be allowed, by the same policies (the role's
policies, and the bucket's policy; an explicit Deny wins), and denies with
S3's messages.

The menu at the top right is the person's: who the session acts as, its
passkeys (a directory user's permission sets and credentials), and signing
out.

### The account's pages

- **Buckets:** create and (when empty) delete buckets, browse them by prefix,
  upload (a file over 64 MiB in parts, so of any size S3 takes), download
  and delete objects and versions; see every version of a key, with how
  it's encrypted, its tags, and whether any of its data is lost. A bucket's
  versioning, tags, CORS, [lifecycle rules](#lifecycle-rules),
  [event notifications](#event-notifications), [inventory](#inventory)
  configurations (with how their reports are going), bucket policy
  and public access block are edited there; the list shows which buckets
  are public. An admin creates buckets, but reads and writes objects only
  with a policy that allows it, as over S3. Downloads are always
  attachments, sandboxed, so that nothing of an object is shown in the
  console's origin; SSE-KMS objects open with the keys the user may use (an
  SSE-C object, whose key Cairn doesn't have, can't be downloaded).
- **Table buckets:** [S3 Tables](#s3-tables)' table buckets, as their
  actions allow: make and delete table buckets, namespaces and (empty)
  tables, see each table's storage and current metadata file, and edit a
  table bucket's policy.
- **Topics:** SNS [topics](#event-notifications), as SNS's actions allow:
  make and delete them, subscribe HTTP(S) endpoints (their confirmations'
  links point to the console, at `/sns/`) and unsubscribe them, publish a
  message to try them, and edit their policies (adding the statement that
  lets S3 publish a bucket's events), delivery policies, signature
  versions and tags.
- **Users:** everything `cairn user` does, as IAM's actions allow (an admin
  may do all of it; others what their policies say, as `iam:CreateAccessKey`
  on their own user, say): create and delete users, attach and detach
  managed policies (AdministratorAccess makes an admin), make, deactivate
  and delete access keys (a key's secret never changes, as in IAM: rotate a
  key by making a second one, moving its clients over, and deleting the
  first), and write inline policies, which the server checks as IAM does.
  IAM users are for services and scripts: they don't sign in to the console
  (people are directory users). Each user shows the groups it's in.
- **Groups:** [groups](#users-and-permissions), as IAM's actions allow:
  make one (with a path), add and remove members, attach and write
  policies, rename or move it, and delete it once it has no members or
  policies left. A group's members show to whom may `iam:GetGroup` it.
- **Roles:** [roles](#roles-and-temporary-credentials), with who their
  trust policies let in, as IAM's actions allow: make one (the trust
  policy's templates write statements for the account, a user or role, or a
  provider's web identities with an audience and a subject), change its
  trust policy, description, longest session, boundary and tags, attach and
  write policies, revoke its sessions, and delete it. And the account's
  [OpenID Connect providers](#web-identities): add one (checked against its
  issuer), change its client IDs, thumbprints and tags, see which roles
  trust it, and delete it.
- **Policies:** the account's managed policies and Cairn's, which users,
  groups and roles have each attached, and making, changing (a new version) and
  deleting the account's own. *From a template* makes policies from one of
  the [templates](#teams-and-policy-templates), shown before they're made.
  The editor adds the bucket-access template's statement for a bucket (or a
  pattern of them) at a level: read, read and write, and so on. To whom
  `iam:ListPolicies` isn't allowed (a team's admin, say), the page lists
  the policies it may read (`iam:GetPolicy`); a policy's users and roles
  show to whom `iam:ListEntitiesForPolicy` on it is allowed.
  A bucket's *Access and policy* shows which of the account's users its
  policies give access to the whole bucket, and what, besides its bucket
  policy and public access block.
- **Identity Center** (the management account's only): permission sets,
  their policies, the accounts they're provisioned to (and provisioning
  them again, when their roles don't hold their latest version), and their
  assignments to [directory users](#directory-users) and groups in the
  organization's accounts; Cairn's own directory's users (made, changed,
  their setup links and passkeys) and groups (made, changed, their
  members); and the identity sources' users and groups that have signed
  in. As Identity Center's actions allow.

### The operators' pages

Operators (whose policies allow `cairn:GetCluster`) see the cluster too, and
what else their policies allow (`CairnOperatorAccess` alone: no buckets, no
users). Whichever node answers shows the whole cluster:

- **Overview:** which nodes are live, how full their disks are, and request
  rates, errors, throughput and latency over the last hour, by S3 operation.
  Nodes can be [removed](#removing-nodes-and-repair) (and kept) there.
- **Storage:** how much data there is, in which layouts (replicated, or
  [erasure-coded](#erasure-coding)), how much of it has fewer live shards
  than it should, and what each node holds; and the redundancy settings,
  which can be changed there: `parity-shards`, `data-shards` and
  `repair-after`. And the [KMS](#kms)'s root key: a file's or OpenBao's, and
  for OpenBao, Cairn's public key, and whether each node reaches it.
- **Integrity:** what the [scrubbers](#scrubbing) checked and found: per
  node, how long a full check takes at its rate and how recently its data was
  checked; damaged and missing copies, and whether they were repaired; and
  the objects with data that's intact on no replica. The navigation shows how
  many of those there are (in red), or else how many findings are still
  open.
- **Jobs:** how the background passes (garbage collection and packing) are
  doing on each node, what they still have to do, and what they did recently;
  and the [lifecycle](#lifecycle-rules) sweeps: each bucket's, how long a
  round of them takes, and the rate they go at, which can be changed there.
- **Organization:** the organization's accounts (made, moved and closed),
  its organizational units and its service control policies (see
  [Users and permissions](#users-and-permissions)).
- **Sign-in:** the identity sources directory users sign in at.

Request metrics are kept in memory by each node, so they start over when it
restarts; everything else is read from the database.

### Directory users

People sign in to the console as **directory users**, as in IAM Identity
Center, with no IAM user behind them: users of **Cairn's own directory**,
who sign in with passkeys, and whoever an identity source vouches for. An
administrator decides what they may do with **permission sets** and
**assignments**, on the console's Identity Center page, or through
Identity Center's APIs (below):

- A **permission set** is a set of policies (an inline one,
  `AwsSSOInlinePolicy`, AWS's managed policies, the account's own as
  *customer managed policy references*, and a permissions boundary) and a
  session length (1 to 12 hours). When it's first assigned in an account,
  Cairn **provisions** it there, as Identity Center does: makes a role
  holding those policies, at
  `/aws-reserved/sso.amazonaws.com/AWSReservedSSO_<set>_<suffix>`, with
  the account's own policies the references name (which it must have).
  Changes to the set reach its roles when it's provisioned again: the
  console does that when you save, sso-admin's `ProvisionPermissionSet`
  otherwise. The role
  trusts only `sso.amazonaws.com`, so no one assumes it through STS, and IAM
  refuses to change it (`UnmodifiableEntity`), or to make roles under
  `/aws-reserved/`.
- An **assignment** gives a permission set to a user or a group of the
  **identity store**, in an account (so far always the cluster's one
  account). Each has an ID of its own, as Identity Center's users and
  groups do. The identity store holds:
  - **Cairn's own directory's** users and groups, which an administrator
    makes in the console or with identitystore's API (users, groups and
    their members, who may be any directory users).
  - **Identity sources'**: the users that have signed in, and the groups
    their sources' group claims (`groups` by default; set per source)
    named. A user's user name is its `preferred_username`, e-mail or
    subject, the first no one else has. There's no directory sync (SCIM):
    they're there once someone has signed in with them, and a user's
    groups of its source are what its last sign-in said.

A user of Cairn's own directory makes its first passkey with a **setup
link**, valid 7 days and working once: the console makes one when it
makes the user, and the user's row makes more (after an administrator
removed a lost passkey, say), as does the command line on a node. Signed
in, they add more passkeys on their own page (at most 8), rename them and
remove them, but never their last. Their passkeys sign them in as
multi-factor.

```sh
cairn directory-user create grace --admin   # the first administrator
cairn directory-user link grace             # a new link, for a lost passkey
```


At sign-in at an identity source, Cairn reads the person's subject and
groups from the ID token; with a passkey, it knows them by it. It then finds
their permission sets. With none, they don't get in; with one,
it's used; with several, they pick one, by account and permission set
(and can switch on their own page).
They then act as a session of the set's role,
`arn:aws:sts::<account>:assumed-role/AWSReservedSSO_<set>_<suffix>/<user name>`,
in the console and in policies (with MFA if they signed in with a passkey,
without at an identity source). Their page hands out
temporary credentials of that session, for the AWS CLI and SDKs, valid for
the set's session length, and the AWS CLI and SDKs sign in themselves
with [`aws sso login`](#the-aws-cli-and-sdks-aws-sso-login). Taking an
assignment away ends its users' access in the console at once;
credentials already handed out last until they expire.

```sh
cairn oidc set company --issuer https://sso.example.com/realms/main \
    --client-id cairn --client-secret ... --group-claim groups
```

**Identity Center's APIs** are on the S3 endpoint, as IAM's are:
**sso-admin** (instances, permission sets and their policies,
assignments, provisioning, tags) and **identitystore** (users, groups and
memberships; its writes change Cairn's own directory's, while identity
sources' are what their sign-ins say).
Point the AWS CLI, SDKs or Terraform at it (`AWS_ENDPOINT_URL_SSO_ADMIN`,
`AWS_ENDPOINT_URL_IDENTITYSTORE`, or Terraform's `endpoints { ssoadmin,
identitystore }`). The account's instance is its only one, and the
account the only target; what's asked is done when it's answered, so
assignments' and provisioning's statuses are `SUCCEEDED` at once. Each
operation is decided as its action (`sso:CreatePermissionSet` on the
instance, `sso:CreateAccountAssignment` on the permission set,
`identitystore:GetUserId` on the identity store, …), which
`AdministratorAccess` allows.

```sh
store=$(aws sso-admin list-instances --query 'Instances[0].IdentityStoreId' --output text)
group=$(aws identitystore get-group-id --identity-store-id $store \
    --alternate-identifier '{"UniqueAttribute": {"AttributePath": "DisplayName", "AttributeValue": "data"}}' \
    --query GroupId --output text)
aws sso-admin create-account-assignment --instance-arn ... --permission-set-arn ... \
    --target-type AWS_ACCOUNT --target-id 123456789012 --principal-type GROUP --principal-id $group
```

### Signing in

- **Its own origin.** Serve it at a host name of its own, never the S3 API's:
  objects are served from that origin with whatever `Content-Type` they were
  uploaded with, so an HTML object there could act in the console as whoever
  opens it. Cairn speaks plain HTTP: put a TLS-terminating proxy in front
  (`http://localhost` works for trying it out, as browsers treat it as
  secure). Passkeys are bound to the console URL's host, so changing it
  makes everyone set theirs up again.
- **Setup links.** A user of Cairn's own directory gets a first passkey
  through a one-time link, valid 7 days: `cairn directory-user create
  <name>` prints the first, the Identity Center page in the console makes
  more. Once signed in, people add more passkeys (at most 8; a second one,
  on another device, keeps them from being locked out) and remove them, but
  never their last. A lost passkey takes a new link.
- **The root user** signs in with a link from `cairn account root-link`
  (see [Users and permissions](#users-and-permissions)), opened at
  `/root`: it works once, within 15 minutes, and a new one replaces the
  last. Its session lasts an hour at most (15 minutes unused), and every
  page says it's the root's. Each link made and each sign-in is logged on
  its node.
- **Sessions** last 12 hours at most, and end after an hour unused. They're a
  cookie (`__Host-`, Secure, HttpOnly, SameSite=Strict), kept in the database
  as a hash, so every node serves them. Removing a passkey or the user ends
  the sessions signed in with it. Changes must come from the console's own
  page (its `Origin`).
- **Identity sources**: people sign in at any OpenID Connect provider that
  follows the standard (Keycloak, Authentik, Dex, Entra ID, Google, Okta,
  ...) as [directory users](#directory-users), not as IAM users. An operator
  adds one on the console's Sign-in page (or with `cairn oidc set <name>
  --issuer <URL> --client-id <ID> [--client-secret <S>] [--group-claim
  <claim>]`): Cairn reads the rest from the issuer's discovery document.
  Register `<console URL>/api/oidc/callback` with the provider as the
  client's redirect URI. Cairn uses the authorization code flow with PKCE,
  and checks the ID token's signature by the provider's keys (RS*, PS*,
  ES256, ES384, EdDSA), issuer, audience, expiry and nonce.
- **Passkeys** are checked by Cairn itself (WebAuthn, with EdDSA, ES256 or
  RS256 keys), with user verification (a PIN or biometrics) every time, and
  without attestation: any authenticator works. A passkey whose signature
  counter goes backwards (a cloned security key) is refused.

The console's JSON API is under `/api/`, described by an OpenAPI spec at
`/api/openapi.json` (also committed as `ui/openapi.json`).

### The AWS CLI and SDKs (`aws sso login`)

The console is also an **access portal**, as Identity Center's: directory
users sign the AWS CLI, SDKs and Terraform in with `aws sso login`, and
they then get and renew credentials of the permission sets assigned to
them, by themselves. Its APIs (`sso-oidc` and `sso`) are at the console's
URL; point the clients there, and use `<console URL>/start` as the start
URL:

```ini
# ~/.aws/config
[sso-session cairn]
sso_start_url = https://console.example.com/start
sso_region = us-east-1                  # any region: it's only a label
sso_registration_scopes = sso:account:access

[services cairn]
sso =
  endpoint_url = https://console.example.com
sso_oidc =
  endpoint_url = https://console.example.com

[profile dev]
sso_session = cairn
sso_account_id = 123456789012
sso_role_name = AdministratorAccess     # a permission set
services = cairn
```

```sh
aws sso login --profile dev              # opens the console: sign in, and Allow
aws s3 ls --profile dev                  # credentials of the set's role, renewed as needed
aws sso logout
```

The JavaScript SDK doesn't read `services` sections for these, and the Go
SDK (and so Terraform) ignores `AWS_ENDPOINT_URL` for them: the
environment variables work everywhere, so set them where a profile's
`services` section isn't enough:

```sh
export AWS_ENDPOINT_URL_SSO=https://console.example.com
export AWS_ENDPOINT_URL_SSO_OIDC=https://console.example.com
```

- **Signing in.** `aws sso login` opens the console in a browser: the
  person signs in (if they haven't), sees which program asks, and allows
  it or denies it, and the browser goes back to the CLI (the authorization
  code flow, with PKCE). With `--use-device-code`, or a profile without an
  `sso_session`, the CLI shows a code instead, to confirm at
  `<console URL>/device`. Only directory users allow sign-ins, as
  themselves; the root user doesn't.
- **What it gets.** The sign-in lasts `sso-session-hours` (8 by default,
  as Identity Center's; `cairn config set sso-session-hours 12`): an access
  token renewed every hour, with which the CLI and SDKs list the accounts
  and permission sets assigned to the user (`aws sso list-accounts`,
  `aws sso list-account-roles`) and get credentials of a set's role, for the set's
  session duration, as the console's credentials are. Taking an assignment
  away refuses credentials of it at once; deleting the user, or `aws sso
  logout`, ends the sign-in. Credentials already handed out last until they
  expire.
- **The start URL.** The AWS CLI only signs in at an AWS-owned start URL, or
  one that redirects to one: `<console URL>/start` redirects to
  `https://identitycenter.amazonaws.com/cairn/<console host>`, which the
  CLI takes as it is, without ever opening it (a browser opening `/start`
  goes to the console instead). It must be HTTPS, so the CLI needs the
  console behind TLS, even to try it on `localhost`. The clients send the
  start URL to Cairn, which refuses another portal's: a profile pointed at
  the wrong cluster says so.
- **What isn't there.** Scopes other than `sso:account:access`, Identity
  Center's applications and trusted token issuers, and its SSO token
  exchange (`CreateTokenWithIAM`).

### Building the console

The console's UI lives in `ui/` (SolidJS and TypeScript, built with Vite)
and is embedded into the binary when Cairn is built, so build it first (with
Node.js 26 or later). Cargo doesn't run npm itself: without a build of the UI,
building Cairn (or running its tests) fails and says how to build it, and it
warns when the build is older than the UI's sources.

```sh
(cd ui && npm ci && npm run build)
cargo build --release
```

`./build-release.sh` does both. While working on the UI, `npm run dev` in
`ui/` serves it with hot reloading, passing API requests on to the console
at `CAIRN_CONSOLE` (default `http://localhost:9480`).

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

To keep versions even from admins, use [Object Lock](#object-lock).

## Object Lock

Object Lock keeps object versions from being deleted or overwritten for a
fixed time, or indefinitely, as in S3 (write once, read many): by anyone, and
by lifecycle rules. That makes history safe from stolen admin credentials too.

A bucket has it enabled when it's created, or later, once it's versioned
(PutObjectLockConfiguration); it can't be disabled again, and the bucket's
versioning can't be suspended:

```sh
aws s3api create-bucket --bucket backups --object-lock-enabled-for-bucket
aws s3api put-object-lock-configuration --bucket backups --object-lock-configuration \
    '{"ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 30}}}'
aws s3api get-object-lock-configuration --bucket backups
```

A version can have a **retention**, a mode and a date it lasts until, and a
**legal hold**, independently. The bucket's default retention (days or
years, optional) applies to every new version that asks for none. While a
retention lasts, or a legal hold is on, the version can't be deleted
(DeleteObject with its version ID is `403 AccessDenied`), and lifecycle rules
leave it alone; deleting the key without a version ID still adds a delete
marker on top, as ever. The modes are S3's:

- **`GOVERNANCE`:** whom `s3:BypassGovernanceRetention` is allowed (admins,
  say) may delete the version, or shorten or remove its retention, by
  asking to (`x-amz-bypass-governance-retention: true`, aws-cli's
  `--bypass-governance-retention`).
- **`COMPLIANCE`:** no one can, until the date has passed: not an admin,
  not an operator, not even with access to the
  database, whose triggers refuse it too. The retention can only be
  lengthened. The bucket can't be deleted while it has versions.

A legal hold lasts until it's lifted (`s3:PutObjectLegalHold`), whatever the
retention. A write sets both with its headers (PutObject, CopyObject, which
doesn't copy its source's, CreateMultipartUpload, whose upload completes
with them, and POST Object's fields of the same names), or they're changed
later; a PutObject that's retained (by its headers or the bucket's default)
must declare a checksum of its body, as in S3:

```sh
aws s3api put-object --bucket backups --key db.dump --body db.dump \
    --object-lock-mode GOVERNANCE --object-lock-retain-until-date 2027-01-01T00:00:00Z \
    --object-lock-legal-hold-status ON
aws s3api put-object-retention --bucket backups --key db.dump --version-id <id> \
    --retention '{"Mode": "COMPLIANCE", "RetainUntilDate": "2028-01-01T00:00:00Z"}'
aws s3api put-object-legal-hold --bucket backups --key db.dump --legal-hold Status=OFF
aws s3api get-object-retention --bucket backups --key db.dump
aws s3api get-object-legal-hold --bucket backups --key db.dump
```

GET and HEAD tell a version's lock (`x-amz-object-lock-mode`,
`-retain-until-date`, `-legal-hold`) to whom may read it
(`s3:GetObjectRetention`, `s3:GetObjectLegalHold`, which `read` grants).
Setting a lock takes `s3:PutObjectRetention` or `s3:PutObjectLegalHold`,
which no grant gives (an admin has them), and creating a bucket with Object
Lock takes `s3:PutBucketObjectLockConfiguration` and `s3:PutBucketVersioning`.
Policies can test what a request asks for with S3's condition keys
`s3:object-lock-mode`, `s3:object-lock-retain-until-date`,
`s3:object-lock-remaining-retention-days` and `s3:object-lock-legal-hold`,
to cap retention periods, say. The console creates buckets with Object Lock,
sets their default retention, and versions' retentions (with the bypass,
where it's allowed) and legal holds, checked with the same condition keys;
it deletes versions as DeleteObject does, without a bypass.

## Lifecycle rules

A bucket's lifecycle configuration expires objects automatically, and moves
them into colder [storage classes](#the-order-of-classes), as in S3.
Setting one is bucket management, as `PutLifecycleConfiguration` is its own
permission in S3, so only an admin can, and needs no grant on the bucket's
objects: the rules are carried out by Cairn, not as the admin. A role that may
only write can't make its writes expire, nor stop an admin's rules. Versions
that [Object Lock](#object-lock) keeps aren't expired, as in S3 (a current
one still gets its delete marker).

```sh
aws s3api put-bucket-lifecycle-configuration --bucket my-bucket \
    --lifecycle-configuration '{"Rules": [{
        "ID": "logs", "Filter": {"Prefix": "logs/"}, "Status": "Enabled",
        "Expiration": {"Days": 30},
        "NoncurrentVersionExpiration": {"NoncurrentDays": 7}}]}'
aws s3api get-bucket-lifecycle-configuration --bucket my-bucket
aws s3api delete-bucket-lifecycle --bucket my-bucket
```

Or in the console: a bucket's page links to an editor of its rules, which
the console checks as S3's requests are checked, and writes back in the same
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
- **`Transition`** with `Days` (0 or more) or a `Date`, and a
  `StorageClass`: the current version moves into that class that many days
  after it was written, or from that date on. A rule may have several, each
  into a class of its own.
- **`NoncurrentVersionTransition`**: a noncurrent version moves into its
  `StorageClass` `NoncurrentDays` after it became noncurrent, but the
  `NewerNoncurrentVersions` newest ones.

Transitions go into lower [ranked](#the-order-of-classes) classes only:
of the transitions due for a version, the one into the lowest class, if
that's below the version's own; a rule's class must be defined and ranked
when the rule is set. A version due to expire isn't transitioned. As in S3,
a rule without a size filter doesn't transition objects under 128 KiB,
unless the request that set the rules said
`x-amz-transition-default-minimum-object-size: varies_by_storage_class`
(then objects of any size go into `GLACIER` and `DEEP_ARCHIVE`); S3's rules
on the days between transitions into its own classes don't apply, since the
classes are yours. A transition only changes the version's class, at the cost
of an expiration (Object Lock doesn't keep a version from it, as in S3): its
data follows when the packer gets to it.

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
under the prefixes of the rules that expire or transition anything, and
expires and transitions what's due.

Sweeps go at a rate you set for the whole cluster, in object versions read
per hour (1,000,000 by default; 0 pauses them), so that however much there is
to sweep, they never take more of the database than that. [Inventory
reports](#inventory) share it with them:

```sh
cairn config set lifecycle-rate 2000000
cairn config get              # every setting, with its default
```

Or on the console's Jobs page, which also shows each bucket's sweep, the rate
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

## Inventory

S3 Inventory: a bucket's inventory configurations
(`PutBucketInventoryConfiguration`, `aws s3api put-bucket-inventory-configuration`)
have Cairn write a report of its objects, daily or weekly, into a bucket, as
S3 writes it: data files in gzipped CSV or Parquet, a `manifest.json` listing
them (with `manifest.checksum`), and a Hive `symlink.txt`, under
`<prefix>/<bucket>/<id>/`, so tools that read S3's reports (Athena, Spark,
DuckDB, scripts) read Cairn's. A report lists the current objects, or every
version and delete marker, under a prefix, with the optional fields asked for:
size, last-modified date, ETag, encryption status, Object Lock, checksum
algorithm, lifecycle expiration date and the rest. ORC is refused.

Parquet files have S3's schema (`bucket`, `key`, `size`, `last_modified_date`
and so on, with sizes as integers and dates as timestamps), so S3's Athena
table for them reads Cairn's. They're cheaper to query than CSV: a query reads
only the columns it needs.

As in S3, the destination bucket's policy must let the `s3.amazonaws.com`
service write the reports; S3's user guide gives the policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "s3.amazonaws.com" },
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::reports/*",
    "Condition": {
      "ArnLike": { "aws:SourceArn": "arn:aws:s3:::photos" },
      "StringEquals": {
        "aws:SourceAccount": "<account ID>",
        "s3:x-amz-acl": "bucket-owner-full-control"
      }
    }
  }]
}
```

Without it, nothing is written; Cairn logs why, shows it on the console's
Jobs page among its events, and tries again an hour later. Reports are
otherwise ordinary writes: the destination's versioning, Object Lock and
default encryption apply, and a configuration's `SSE-S3` or `SSE-KMS`
encrypts them.

A configuration's first report starts within minutes of setting it; the next
a day later (`Daily`), or on the Sunday after (`Weekly`). Reports take turns
with [lifecycle sweeps](#lifecycle-rules) and share their rate
(`lifecycle-rate`, versions read per hour across the cluster): when only one
of them has work, it gets the whole rate. A report is written a data file
at a time, each about ten minutes of the rate (between 10,000 and 1,000,000
versions), and where it has got to is saved after each, so if its node dies,
another carries on from there; a bucket of a billion versions at the
default rate takes about six weeks, so raise the rate for buckets that
large. A report is streamed as it's read, so it takes the same little memory
however large the bucket is: a CSV report a page of versions, a Parquet one at
most a row group (about 16 MiB of rows) besides. Like S3's, it's as of no single moment: what's
written or deleted while it's made may or may not be in it.

## Batch Operations

S3 Batch Operations: a job (S3 Control's `CreateJob`,
`aws s3control create-job`) does one operation to every object a manifest
lists, as a role. Cairn does `S3PutObjectTagging` (replacing each object's
tags), `S3DeleteObjectTagging`, `S3PutObjectRetention`,
`S3PutObjectLegalHold` ([Object Lock](#object-lock)),
`S3ReplicateObject` ([Batch Replication](#batch-replication)),
`S3PutObjectCopy` (copies, below), `S3PutObjectAcl` ([ACLs](#acls)),
`S3ComputeObjectChecksum` and `S3UpdateObjectEncryption` (below). Its
manifest is
[generated](#generated-manifests) from a bucket's objects, or a
CSV object of lines `bucket,key` (or `bucket,key,versionId`, as its
`Fields` say), keys URL-encoded, or an [inventory report](#inventory)'s
`manifest.json` (`S3InventoryReport_CSV_20161130`, or
`S3InventoryReport_CSV_20211130`, without `Fields`), of CSV
or Parquet: its tasks are then the report's rows, so a job can do something
to every object (or every version) a report lists. A Parquet report's files
are read a row group at a time, and only their `bucket`, `key` and
`version_id` columns. Other operations aren't done yet
(see [S3-COMPATIBILITY.md](S3-COMPATIBILITY.md#batch-operations)).
A job can write a completion report, of all its tasks or only those that
failed, as S3 writes it.

A job acts as its role, as S3 does: the role's trust policy must let the
`batchoperations.s3.amazonaws.com` service assume it, and its policies must
let it read the manifest and do the operation on each object. Whoever
creates the job needs `s3:CreateJob` and `iam:PassRole` on the role:

```sh
aws iam create-role --role-name batch --assume-role-policy-document \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
    "Principal":{"Service":"batchoperations.s3.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam put-role-policy --role-name batch --policy-name tagging --policy-document \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Resource":"arn:aws:s3:::photos/*",
    "Action":["s3:GetObject","s3:PutObjectTagging","s3:PutObjectVersionTagging"]}]}'
printf 'photos,a.jpg\nphotos,b.jpg\n' > manifest.csv
etag=$(aws s3api put-object --bucket photos --key manifest.csv --body manifest.csv \
    --query ETag --output text)
aws s3control create-job --account-id <account ID> --priority 10 --no-confirmation-required \
  --role-arn arn:aws:iam::<account ID>:role/batch --report '{"Enabled":false}' \
  --operation '{"S3PutObjectTagging":{"TagSet":[{"Key":"team","Value":"red"}]}}' \
  --manifest '{"Spec":{"Format":"S3BatchOperations_CSV_20180820","Fields":["Bucket","Key"]},
    "Location":{"ObjectArn":"arn:aws:s3:::photos/manifest.csv","ETag":'"$etag"'}}'
```

(S3 Control's clients put the account ID in the host name, so it must
resolve to Cairn too, as for the account's public access block.)

A job is first prepared: its manifest is read through, each line checked
and counted. A job created with `--confirmation-required` then waits
(`Suspended`) until `aws s3control update-job-status --requested-job-status
Ready` confirms it; `--requested-job-status Cancelled` cancels a job that
hasn't ended. Then its tasks run, and `describe-job` shows how many
succeeded and failed. A job fails, saying why in its `FailureReasons`, if
its role or manifest can't be used, if its manifest changes (it's pinned to
the ETag it was created with), or if more than half its tasks fail once a
thousand have run. Jobs are kept for 90 days after they end.

Retention and legal holds are set as PutObjectRetention and
PutObjectLegalHold set them, so the role needs `s3:PutObjectRetention` or
`s3:PutObjectLegalHold`, and the objects' bucket Object Lock. A retention
can only be lengthened, unless the job asks to bypass governance mode
(`BypassGovernanceRetention`) and the role is allowed
`s3:BypassGovernanceRetention`; a compliance-mode one can't be shortened at
all. Each task that can't is a failed task:

```sh
  --operation '{"S3PutObjectRetention":{"Retention":{"Mode":"GOVERNANCE",
    "RetainUntilDate":"2030-01-01T00:00:00Z"}}}'
  --operation '{"S3PutObjectLegalHold":{"LegalHold":{"Status":"ON"}}}'
```

A copy job copies each object into its bucket (`TargetResource`), at its
key after the job's `TargetKeyPrefix`, as a CopyObject request would: so
the role needs `s3:GetObject` (`s3:GetObjectVersion`, for a manifest with
version IDs) on each object and `s3:PutObject` on its copy, and
`s3:PutObjectTagging` if the job gives copies tags. A copy keeps its
source's metadata and tags, unless the job replaces them
(`MetadataDirective` `REPLACE` with `NewObjectMetadata`, and
`NewObjectTagging`); it can also ask for a storage class, encryption
(`SSEAlgorithm`, `SSEAwsKmsKeyId`), an ACL, Object Lock and a checksum
algorithm, and copy only objects modified since or before a time. A task
fails as its CopyObject would: an SSE-C object can't be copied (the job has
no key for it), nor one larger than 5 GiB. Each copy is made once, even if
the node doing it dies before it saved where its job had got to:

```sh
  --operation '{"S3PutObjectCopy":{"TargetResource":"arn:aws:s3:::archive",
    "TargetKeyPrefix":"2026/","StorageClass":"STANDARD_IA",
    "NewObjectTagging":[{"Key":"copied","Value":"yes"}]}}'
```

An ACL job sets each object's ACL as PutObjectAcl would, to a canned ACL
or to a list of grants, so the role needs `s3:PutObjectAcl`
(`s3:PutObjectVersionAcl` for versions), and a task fails where
PutObjectAcl would: in a bucket with ACLs disabled, say:

```sh
  --operation '{"S3PutObjectAcl":{"AccessControlPolicy":{"CannedAccessControlList":"public-read"}}}'
```

A checksum job works out each object's checksum from its data, in any of
S3's algorithms, of the whole object (`FULL_OBJECT`) or, for a multipart
object, of its parts' checksums (`COMPOSITE`, not for `CRC64NVME`), and
reports it in the task's line of the completion report, as S3 does: JSON,
`{"checksum_base64":…,"etag":…,"checksumAlgorithm":…,"checksumType":…,"checksum_hex":…}`.
The role needs `s3:GetObject` (and the use of an SSE-KMS object's key); an
SSE-C object's task fails, as Cairn has no key for it:

```sh
  --operation '{"S3ComputeObjectChecksum":{"ChecksumAlgorithm":"SHA256","ChecksumType":"FULL_OBJECT"}}'
```

An encryption job changes each SSE-S3 or SSE-KMS object to SSE-KMS under
the key it names, in place: its data isn't read or written again, only its
key sealed under a new data key, and it keeps its ETag, checksum and last
modified time. So an SSE-S3 object's ETag, its MD5, is then stored in the
clear, as on S3, where SSE-KMS objects' ETags tell nothing of their
content. The role needs `s3:UpdateObjectEncryption`, and the KMS must let
it use the key (and an SSE-KMS object's old one). A plain or SSE-C object's
task fails, and so does one of an object that's retained or under a legal
hold, as on S3:

```sh
  --operation '{"S3UpdateObjectEncryption":{"ObjectEncryption":{"SSEKMS":
    {"KMSKeyArn":"arn:aws:kms:us-east-1:<account ID>:key/transit/invoices"}}}}'
```

A completion report (`--report`) goes to a bucket, under its prefix, as S3
writes it: `<prefix>/job-<id>/results/*.csv`, a line per task (bucket, key,
version ID, `succeeded` or `failed`, the HTTP status, the error code and a
message), and `<prefix>/job-<id>/manifest.json`, which lists those files
once the job ends (complete, failed after its tasks did, or cancelled while
it ran). The role writes it, so it needs `s3:PutObject` there too; a job
whose report can't be written fails while it's prepared, before it does
anything:

```sh
  --report '{"Bucket":"arn:aws:s3:::reports","Format":"Report_CSV_20180820","Enabled":true,
    "Prefix":"batch","ReportScope":"AllTasks"}'
```

Jobs take turns with [lifecycle sweeps](#lifecycle-rules) and
[inventory reports](#inventory), and share their rate (`lifecycle-rate`):
each task counts as a version read. Among jobs, the highest priority goes
first. Where a job has got to in its manifest is saved after each page of
a thousand tasks, with the page's report files, so if its node dies,
another carries on from there; the tasks of the page it was on are done
again, which is harmless for the operations Cairn does, and their report
files written again, over the old ones.

### Generated manifests

Instead of a manifest, a job can name a bucket (`--manifest-generator`,
S3's `S3JobManifestGenerator`), and filters its objects must pass: while
it's prepared, the job walks the bucket and writes what passes as a
manifest, then runs from that. The manifest is a snapshot: the job does
what was in the bucket when it was walked, so its task count is what it
does, and a copy into the bucket it walked doesn't copy its own copies. In
a bucket that's versioned (or was), it has each version but delete
markers, with its version ID; in one that never was, each object.

The filters are S3's: `CreatedAfter` and `CreatedBefore`,
`ObjectSizeGreaterThanBytes` and `ObjectSizeLessThanBytes`,
`MatchAnyStorageClass`, `ObjectReplicationStatuses` (`NONE`, `COMPLETED`,
`FAILED`, `REPLICA`), `EligibleForReplication` (what the bucket's
[replication configuration](#replication) replicates: Batch Replication of
what's never been replicated, say), and `KeyNameConstraint` (a key must
start with one of its `MatchAnyPrefix`, end with one of its
`MatchAnySuffix`, and contain one of its `MatchAnySubstring`, of those it
gives). `MatchAnyObjectEncryption` isn't done yet. The role needs
`s3:PutInventoryConfiguration` on the bucket, as S3 asks (its generated
manifests are inventory reports), besides what its operation needs:

```sh
aws s3control create-job --account-id <account ID> --priority 10 --no-confirmation-required \
  --role-arn arn:aws:iam::<account ID>:role/batch --report '{"Enabled":false}' \
  --operation '{"S3PutObjectTagging":{"TagSet":[{"Key":"team","Value":"red"}]}}' \
  --manifest-generator '{"S3JobManifestGenerator":{"SourceBucket":"arn:aws:s3:::photos",
    "EnableManifestOutput":false,"Filter":{"KeyNameConstraint":{"MatchAnySuffix":[".jpg"]},
    "CreatedBefore":"2026-11-01T00:00:00Z"}}}'
```

With `EnableManifestOutput`, the manifest is written to its
`ManifestOutputLocation`, as an inventory report is
(`S3InventoryReport_CSV_20211130`): `<prefix>/job-<id>/manifest.json`, and
gzipped CSV data files of bucket, key and version ID under
`<prefix>/job-<id>/data/`, encrypted as its `ManifestEncryption` says (or
as the bucket's default encryption does). The role writes it, so it needs
`s3:PutObject` there; `describe-job` tells where it is
(`GeneratedManifestDescriptor`), and it stays, for other jobs to use as
their manifest. Without it, the manifest is kept where no one can see it,
in a bucket of Cairn's own (`cairn_internal`, of an account of Cairn's
own, which no request can reach), and deleted once the job ends.

The walk takes turns with the rest, as preparing does, but reads versions,
so they count against the rate as tasks do: each turn reads at least ten
thousand of them (at most a hundred thousand) and writes those that pass
as a data file, so if its node dies, another carries on from the last
file written.

### Batch Replication

A job of `S3ReplicateObject` replicates the versions its manifest lists by
their bucket's [replication configuration](#replication), however they
were replicated before: versions written before a rule existed, versions
that failed, and versions that were replicated already (to backfill a new
destination), as S3's Batch Replication does. Each is queued as a new
version is, to the destinations its rules send it to now, and replicated
by the configuration's role, so the task succeeds once it's queued; the
version is `PENDING` until it's replicated, then `COMPLETED` or `FAILED`.
A version no rule picks fails its task (`SrcObjectNotEligible`), as does
one in a bucket with no replication configuration
(`SrcBucketReplicationConfigMissing`). The job's role needs
`s3:InitiateReplication` on the objects (and to read the manifest), not
the permissions to replicate them, which are the configuration's role's:

```sh
aws iam put-role-policy --role-name batch --policy-name replicate --policy-document \
  '{"Version":"2012-10-17","Statement":[
    {"Effect":"Allow","Action":"s3:InitiateReplication","Resource":"arn:aws:s3:::photos/*"},
    {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::manifests/*"}]}'
aws s3control create-job --account-id <account ID> --priority 10 --no-confirmation-required \
  --role-arn arn:aws:iam::<account ID>:role/batch --report '{"Enabled":false}' \
  --operation '{"S3ReplicateObject":{}}' \
  --manifest '{"Spec":{"Format":"S3InventoryReport_CSV_20161130"},
    "Location":{"ObjectArn":"arn:aws:s3:::manifests/photos/all/2026-11-19T00-00Z/manifest.json",
    "ETag":'"$etag"'}}'
```

An [inventory report](#inventory) of all versions lists every version
there is (its `VersionId` field is needed: a task without one replicates
the key's current version). The manifest may list a key's versions in any
order: a replica lands among its destination's versions by its
last-modified time, which is its source's, so the destination ends up with
them in the source's order, and the source's current version current.

## Replication

A bucket's replication configuration (`aws s3api put-bucket-replication`,
in either of S3's schemas) copies each new version it picks into another
bucket of the cluster, as S3 replicates one: same key, version ID,
last-modified time, ETag, metadata, tags and Object Lock. A rule picks
versions by a prefix or tags (`Filter`), and says whether delete markers
are replicated too (`DeleteMarkerReplication`). Both buckets must be
versioned, and the destination may be another account's.

A replica shares its source's bytes, as a CopyObject copy does, so it costs
only metadata, whatever its size. The bytes are written again only if the
rule names another `StorageClass`. That makes a replica a safeguard against
deletes and overwrites, and, in a bucket with [Object Lock](#object-lock),
against tampering. It isn't extra protection against losing data: the
replica is on the same blobs, which [erasure coding](#erasure-coding) and the
replication factor protect.

Replication acts as its role, which must trust `s3.amazonaws.com`, and be
allowed to read the source's versions for replication and replicate onto
the destination. Whoever sets the configuration needs `iam:PassRole` on it:

```sh
aws iam create-role --role-name replication --assume-role-policy-document \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
    "Principal":{"Service":"s3.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam put-role-policy --role-name replication --policy-name replicate --policy-document \
  '{"Version":"2012-10-17","Statement":[
    {"Effect":"Allow","Action":"s3:GetObjectVersionForReplication","Resource":"arn:aws:s3:::photos/*"},
    {"Effect":"Allow","Action":["s3:ReplicateObject","s3:ReplicateDelete","s3:ReplicateTags"],
     "Resource":"arn:aws:s3:::photos-backup/*"}]}'
aws s3api put-bucket-replication --bucket photos --replication-configuration \
  '{"Role":"arn:aws:iam::<account ID>:role/replication","Rules":[{"ID":"all","Priority":1,
    "Filter":{},"Status":"Enabled","DeleteMarkerReplication":{"Status":"Enabled"},
    "Destination":{"Bucket":"arn:aws:s3:::photos-backup"}}]}'
```

Versions are replicated within a second or so of being written, by any
node. A version is queued in the same transaction that writes it, so
none is lost to a crash. A key's versions are ordered by their
last-modified times, as S3 orders them, and a replica keeps its source's,
so it lands below any version of its key written to the destination since:
that one stays current. GET and HEAD report `x-amz-replication-status`:
`PENDING`, then `COMPLETED` or `FAILED` on the source, and `REPLICA` on the
replica. A version fails if the role may not replicate it, or if its
destination is gone or no longer versioned. A failed version isn't tried
again; other errors are retried with backoff. While it has a replication
configuration, the source bucket's versioning can't be suspended.

Replicas aren't replicated again, so two buckets can replicate to each
other. Like S3, Cairn doesn't replicate versions written before a rule
existed (a [Batch Replication](#batch-replication) job does), deletes of a
version by its ID, or delete markers made by lifecycle rules. SSE-KMS objects are replicated only if their rule asks for
it (`SseKmsEncryptedObjects`), sealed under its `ReplicaKmsKeyID`. SSE-C
objects are replicated as they're stored, and open with the same customer
key. Unlike S3, Cairn doesn't replicate later changes to a version's tags
or Object Lock (see
[S3-COMPATIBILITY.md](S3-COMPATIBILITY.md#replication)).

### Replicating to and from other clusters

A rule can also name a bucket of another cluster: another Cairn, or
[MinIO](https://min.io) or [RustFS](https://rustfs.com). Cairn speaks MinIO's
bucket replication protocol, which RustFS also uses, in both directions. So
Cairn can replicate to either of them, they can replicate to Cairn, and two
clusters can replicate to each other (active-active). Replicas keep their
sources' version IDs, last-modified times, ETags, metadata, tags and Object
Lock, as within the cluster.

Register the other cluster as a **remote**, with credentials that may write
replicas to its bucket, and its kind:

```sh
cairn remote add dc2 --endpoint https://s3.dc2.example.com --path-style \
    --kind cairn --access-key-id … --secret-access-key …
```

Or on the console's Storage page, which lists the remotes, and the buckets
that replicate to each.

A rule then names the remote's bucket by
`arn:cairn:replication::<remote>:<bucket>`. A configuration written for MinIO
can be used as it is: it names `arn:minio:replication:<region>:<ID>:<bucket>`,
which Cairn takes too, if the remote is registered under that ID. The bucket
must exist there and be versioned (and have Object Lock if the source has
it), which is checked as the configuration is set:

```sh
aws s3api put-bucket-replication --bucket photos --replication-configuration \
  '{"Role":"arn:aws:iam::<account ID>:role/replication","Rules":[{"ID":"dc2","Priority":1,
    "Filter":{},"Status":"Enabled","DeleteMarkerReplication":{"Status":"Enabled"},
    "Destination":{"Bucket":"arn:cairn:replication::dc2:photos"}}]}'
```

The role needs only `s3:GetObjectVersionForReplication` on the source. What
may be written over there is up to the remote's credentials: on a Cairn,
`s3:ReplicateObject`, `s3:ReplicateTags` and `s3:ReplicateDelete` on the
bucket (a replication request is authorized as these, not as `s3:PutObject`
and `s3:DeleteObject`). MinIO wants its usual replication user's policy.

What's replicated:

- **Versions**, read as the role and written with MinIO's requests: one
  PutObject up to 16 MiB, else a multipart upload. A version that's there
  already isn't written again. SSE-S3 versions ask for SSE-S3 there, and
  SSE-KMS ones for the rule's `ReplicaKmsKeyID`, as the remote names its
  key. SSE-C versions fail, since their data can't be read without the
  client's key.
- **Delete markers**, where the rule says so, with the marker's own
  version ID.
- **Deletions of versions**, by their IDs, where the rule has MinIO's
  `<DeleteReplication><Status>Enabled</Status></DeleteReplication>`. Within
  the cluster, a rule with it deletes the version's replica, if it's still
  a replica.

A 4xx from the remote fails the version (`FAILED`); anything else (the
network, 5xx) is retried with backoff, as within the cluster.

MinIO and RustFS only take UUIDs as version IDs. To them, a Cairn version
ID is sent as a UUID made from its first 16 random bytes (`--kind minio` or
`--kind rustfs`). A deletion naming that UUID finds the Cairn version again,
so deletes and delete markers stay in sync both ways. Versions that MinIO or
RustFS replicate into Cairn keep their UUIDs as their IDs, which Cairn takes
alongside its own.

For MinIO or RustFS to replicate into Cairn, add Cairn as their remote
target (`mc admin bucket remote add` / `mc replicate add` with Cairn's S3
endpoint, a Cairn user's keys, and the destination bucket, which must be
versioned). `mc` checks the target's health at `/minio/health/live` and
`/minio/health/ready`, which Cairn answers on its S3 endpoint. Replicas land
as `REPLICA`, at their sources' times. Later changes to their tags and
Object Lock, which MinIO sends as a copy of the version onto itself, are
applied to the replica. Cairn's own sources don't yet send such changes.

`cairn remote list` shows the remotes and the buckets replicating to each.
`cairn remote set` changes a remote's endpoint or credentials. `cairn remote
delete` removes a remote once no bucket's rules name it.

## Event notifications

S3's event notifications, delivered through SNS topics, which Cairn has on
the same endpoint: requests signed for the `sns` service are SNS's (`aws sns
--endpoint-url …`, Terraform's `aws_sns_topic` and
`aws_sns_topic_subscription`), as IAM's are. A bucket's notification
configuration (`aws s3api put-bucket-notification-configuration`, or the
console's *Notifications*) sends the events of the keys it matches (by
prefix and suffix) to topics: objects created (put, POST, copy, multipart),
deleted (and delete markers), tagged, and expired by lifecycle rules. A
topic sends each to its subscriptions, HTTP(S) endpoints only, in SNS's
envelope, signed as SNS signs it:

```sh
aws sns create-topic --name uploads
aws sns subscribe --topic-arn arn:aws:sns:us-east-1:<account>:uploads \
    --protocol https --notification-endpoint https://hooks.example.com/uploads
aws sns set-topic-attributes --topic-arn arn:aws:sns:us-east-1:<account>:uploads \
    --attribute-name Policy --attribute-value file://allow-s3.json
aws s3api put-bucket-notification-configuration --bucket photos --notification-configuration \
    '{"TopicConfigurations":[{"TopicArn":"arn:aws:sns:us-east-1:<account>:uploads","Events":["s3:ObjectCreated:*"]}]}'
```

As in AWS:

- A subscription is first sent a confirmation, whose `SubscribeURL` the
  endpoint visits (or whose token it gives ConfirmSubscription); only
  confirmed subscriptions get messages.
- The topic's policy must let S3 (`s3.amazonaws.com`) publish the bucket's
  events (`aws:SourceArn`), or the configuration is refused; each
  configuration's topic is sent S3's test event when it's set.
- A failed delivery (a 5xx, a 429, no answer) is retried as the topic's or
  subscription's delivery policy says: three times, 20 seconds apart, by
  default. A 4xx is final.
- Messages are signed (`SignatureVersion` 1, SHA1, or 2, SHA256) with keys
  of Cairn's own, whose certificates its endpoint serves. AWS's SDK
  validators take certificates from `sns.<region>.amazonaws.com` only:
  check signatures with one whose host you can set, or yourself.

Events are written in the same transaction as the change they report, so
none is lost to a crash, and deliveries are retried from any node; writes
never wait for them. Subscriptions reach public addresses only: to deliver
inside the cluster's network, set `cairn config set
notification-private-endpoints 1`. See [S3 compatibility](S3-COMPATIBILITY.md#event-notifications)
for what's not supported (SQS, Lambda, EventBridge, filter policies).

## S3 Tables

Table buckets of Apache Iceberg tables, as Amazon S3 Tables has them, on the
same endpoint: requests signed for the `s3tables` service are S3 Tables'
(`aws s3tables --endpoint-url …`, the SDKs, Terraform's
`aws_s3tables_table_bucket`), as IAM's are. A table bucket holds namespaces
(one level), and they hold tables. A table is a pointer to its current
Iceberg metadata file, and has its own storage (its warehouse location,
`s3://…--table-s3`), where clients write its data and metadata files
through the S3 API. A commit writes a new metadata file there, and swaps
the pointer against the table's version token, which fails (409) if
another commit came first:

```sh
aws s3tables create-table-bucket --name lake
aws s3tables create-namespace --table-bucket-arn arn:aws:s3tables:us-east-1:<account>:bucket/lake \
    --namespace sales
aws s3tables create-table --table-bucket-arn arn:aws:s3tables:us-east-1:<account>:bucket/lake \
    --namespace sales --name orders --format ICEBERG
aws s3tables get-table --table-bucket-arn arn:aws:s3tables:us-east-1:<account>:bucket/lake \
    --namespace sales --name orders   # its warehouseLocation and versionToken
aws s3tables update-table-metadata-location --table-bucket-arn … --namespace sales --name orders \
    --version-token <token> --metadata-location s3://<warehouse>/metadata/00001-….metadata.json
```

That's what AWS's Iceberg catalog for S3 Tables (`s3-tables-catalog-for-iceberg`,
for Spark and other Java engines) does.

### Iceberg's REST catalog

Engines that speak Iceberg's REST catalog protocol use the endpoint's
`/iceberg`, as they would S3 Tables' (`https://s3tables.<region>.amazonaws.com/iceberg`):
the warehouse is the table bucket's ARN, and requests are signed with SigV4
for `s3tables`. The catalog writes tables' metadata files itself: a commit's
requirements are checked, its changes applied, the new metadata file
written into the table's storage, and the table's pointer swapped to it, so
that of two writers racing, one's commit is refused (409) and retried by
its engine. Its config tells engines to reach table storage at the same
endpoint, path-style, unless they say otherwise. With PyIceberg (and the
credentials in the environment, as for the AWS CLI):

```python
from pyiceberg.catalog import load_catalog

catalog = load_catalog("lake", **{
    "type": "rest",
    "uri": "https://s3.example.com/iceberg",
    "warehouse": "arn:aws:s3tables:us-east-1:<account>:bucket/lake",
    "rest.sigv4-enabled": "true",
    "rest.signing-name": "s3tables",
    "rest.signing-region": "us-east-1",
})
catalog.create_namespace("sales")
orders = catalog.create_table("sales.orders", schema=schema)
orders.append(rows)
```

DuckDB's `iceberg` extension works too: it takes the service it signs for
from the endpoint's host name, as AWS's (`s3tables.<region>.…`), so give it
a name of that shape for Cairn, which the S3 API's wildcard name covers
(`s3tables.us-east-1.s3.example.com`), and an S3 secret for the files:

```sql
CREATE SECRET (TYPE s3, KEY_ID '…', SECRET '…', REGION 'us-east-1',
               ENDPOINT 's3.example.com', URL_STYLE 'path');
ATTACH 'arn:aws:s3tables:us-east-1:<account>:bucket/lake' AS lake
    (TYPE iceberg, ENDPOINT 'https://s3tables.us-east-1.s3.example.com/iceberg',
     AUTHORIZATION_TYPE 'sigv4');
SELECT * FROM lake.sales.orders;
```

Spark's and Trino's REST catalogs take the same settings (`rest.sigv4-enabled`,
`rest.signing-name`, …, with `S3FileIO`); they haven't been tried against
Cairn yet. As S3 Tables' catalog, it has namespaces of one level, and no
views, staged creates, registering, multi-table transactions or OAuth;
namespaces' properties aren't kept; and a table is dropped with its files
only (`purge_table`, `purgeRequested=true`).

As in AWS:

- Every operation is checked as its `s3tables:` action, on the table
  bucket's ARN or the table's (`…:bucket/lake/table/<id>`, which a rename
  keeps), by the principal's policies and the table bucket's and table's
  own (`put-table-bucket-policy`, `put-table-policy`), with S3 Tables'
  condition keys (`s3tables:namespace`, `s3tables:tableName`,
  `s3tables:TableBucketTag/…`, …). Policies that would make one public are
  refused. AWS's managed policies `AmazonS3TablesFullAccess` and
  `AmazonS3TablesReadOnlyAccess` are there to attach.
- A table's storage takes only what AWS's does: GetObject, HeadObject,
  PutObject, the multipart operations and ListParts, signed with SigV4 (not
  presigned), each checked as `s3tables:GetTableData` or
  `s3tables:PutTableData` on the table. It isn't listed, its files aren't
  deleted by clients, and it's in no listing of buckets. A deleted table's
  files are deleted in the background.
- Table buckets have an encryption configuration and a storage class, which
  new tables get unless they ask for their own. SSE-KMS keys are
  [Cairn's](#sse-kms), as ARNs: `arn:aws:kms:us-east-1:<account>:key/<mount>/<key>`.
  Without a KMS, SSE-S3 (the default) leaves table files unencrypted, as
  [Cairn's SSE-S3](#sse-s3) needs one. A storage class the operator hasn't
  defined (`INTELLIGENT_TIERING`, say) is `STANDARD`, as for objects.

### Maintenance

Cairn maintains tables as S3 Tables does, in the background, by the same
configurations (`put-table-maintenance-configuration`,
`put-table-bucket-maintenance-configuration`), and reports each job's last
run (`get-table-maintenance-job-status`):

- **Snapshot management**, hourly: snapshots of `main` beyond the newest
  `minSnapshotsToKeep` (1), and older than `maxSnapshotAgeHours` (120),
  expire, and so do snapshots off `main` that old. The expiry is a commit,
  as an engine's is. Not for tables with branches or tags other than
  `main`, `history.expire.*` properties, or `gc.enabled=false`.
- **Unreferenced file removal**, daily: a file of a table's storage that
  none of its snapshots, metadata files or statistics references is
  noncurrent after `unreferencedDays` (3), and deleted `nonCurrentDays`
  (10) after that; the files of expired snapshots are noncurrent at once.
  What's referenced is read from the table's manifests; if one can't be
  read, nothing is deleted, and the job fails, saying why.
- **Compaction**, on by default, hourly (and again soon while there's more
  to do): small data files (under 75% of `targetFileSizeMB`, 512 by
  default), oversized ones (over 180%), and those with deletes are
  rewritten into files of the target size, per partition, their deletes
  applied, as a `replace` snapshot: the same rows, in fewer files. Delete
  files that apply to nothing any more go with them. A partition's files
  are rewritten when there are 5 or more of them, or 2 that together reach
  the target, or any has deletes. Its `strategy`:
  - `binpack`: rows as they are;
  - `sort`: by the table's sort order (`write-order`, or Spark's
    `WRITE ORDERED BY`);
  - `z-order`: by the z-order of the sort order's columns, which clusters
    rows by all of them at once;
  - `auto` (the default): `sort` if the table has a sort order, else
    `binpack`.

  Compaction takes little memory whatever the files' sizes: input files
  are read one at a time, sorting what's more than 64 MiB spills to the
  node's first data dir, and files being written are spooled there too
  (past 8 MiB) and streamed into the object store as they're closed. What
  a crash leaves there is removed as the node starts.
  Files are written as Parquet, in row groups of at most 32 MiB (or the
  table's `write.parquet.row-group-size-bytes`, if less), compressed as the
  table's `write.parquet.compression-codec` says (zstd by default); a format
  version 3 table's rows keep their lineage (`_row_id`). A commit that came
  in while compaction ran is fine if it only appended; any other drops the
  rewrite, which is tried again at the next run.

Maintenance acts as Cairn, which can't open SSE-KMS keys: a table encrypted
with SSE-KMS isn't maintained (its jobs fail, saying so). See [S3 compatibility](S3-COMPATIBILITY.md#s3-tables) for
the rest.

## Server access logs

A bucket's logging configuration (`PutBucketLogging`, `aws s3api
put-bucket-logging`) has Cairn record every request to it, as S3 records
them: a line per request, in S3's format, in log objects written to the
target bucket under the target prefix, so tools that read S3's access logs
(Athena, GoAccess, scripts) read Cairn's. The target must be a bucket of the
same account, and, as in S3, its policy must let the
`logging.s3.amazonaws.com` service write the logs:

```sh
aws s3api put-bucket-logging --bucket photos --bucket-logging-status \
    '{"LoggingEnabled":{"TargetBucket":"logs","TargetPrefix":"photos/"}}'
```

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "logging.s3.amazonaws.com" },
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::logs/photos/*",
    "Condition": {
      "ArnLike": { "aws:SourceArn": "arn:aws:s3:::photos" },
      "StringEquals": { "aws:SourceAccount": "<account ID>" }
    }
  }]
}
```

Each node appends its requests' records to a spool in its data dir
(`access-logs/`), and every five minutes (or 64 MiB) closes the file, whose
records it writes, a log object per bucket, within a minute. So logs arrive
within about six minutes, and a node's spool costs a request a write to a
file, not to the database; requests to buckets that don't log cost nothing.
The spool isn't synced: a crash of Cairn loses nothing written to it, a
crash of the machine may lose its last records. As in S3, delivery is best
effort: records are dropped, and Cairn logs why, if the target is gone or
doesn't allow them, or would keep them under SSE-KMS or a default Object Lock
retention (SSE-S3 is fine). Records that fail otherwise (the storage nodes
down, say) are tried again each minute, for a day.

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
Don't put secrets in them. The console shows both.

### Tags in policies (ABAC)

Policies can decide by tags, as in S3:

- `s3:ExistingObjectTag/<key>`: the tags of the object version a request reads
  or annotates (GetObject, HeadObject, the tagging and ACL requests), and of a
  copy's source.
- `s3:RequestObjectTag/<key>` and `s3:RequestObjectTagKeys`: the tags a write
  gives its object (`x-amz-tagging`, PutObjectTagging's), and an upload's, for
  its parts and its completion.
- `aws:ResourceTag/<key>` and `s3:BucketTag/<key>`: a bucket's tags, on
  requests on the bucket and its objects, but only with the bucket's ABAC
  enabled. It's disabled by default, as in S3:

```sh
aws s3api put-bucket-abac --bucket my-bucket --abac-status Status=Enabled
aws s3api get-bucket-abac --bucket my-bucket
```

With ABAC enabled, PutBucketTagging and DeleteBucketTagging are refused: only
S3 Control's TagResource and UntagResource change the bucket's tags, and they
carry `aws:RequestTag/<key>` and `aws:TagKeys`, so a policy can say who may
tag what. CreateBucket can tag the new bucket too, which takes
`s3:TagResource` as well. (S3 Control's clients need a host name that
resolves for any subdomain, as for the account's public access block.)

```sh
aws s3control tag-resource --account-id 123456789012 --resource-arn arn:aws:s3:::my-bucket \
    --tags Key=team,Value=storage
aws s3control untag-resource --account-id 123456789012 --resource-arn arn:aws:s3:::my-bucket --tag-keys team
aws s3control list-tags-for-resource --account-id 123456789012 --resource-arn arn:aws:s3:::my-bucket
```

A user may then use every bucket of its team, without a policy per bucket:

```json
{"Effect": "Allow", "Action": "s3:*", "Resource": ["arn:aws:s3:::*", "arn:aws:s3:::*/*"],
 "Condition": {"StringEquals": {"aws:ResourceTag/team": "${aws:PrincipalTag/team}"}}}
```

Whoever may tag a bucket, or enable its ABAC, decides who such policies let
in: keep `s3:TagResource`, `s3:PutBucketTagging` and `s3:PutBucketAbac` to
admins, or condition them on `aws:RequestTag`.

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

## Websites

A bucket can be served as a static website, as S3's static website hosting
serves one: PutBucketWebsite, GetBucketWebsite and DeleteBucketWebsite
(`s3:PutBucketWebsite`, `s3:GetBucketWebsite`, `s3:DeleteBucketWebsite`), and
a website endpoint that serves its pages. The console has a Website dialog on
each bucket's page, too.

```sh
aws s3 website s3://my-site --index-document index.html --error-document 404.html
aws s3api get-bucket-website --bucket my-site
aws s3api delete-bucket-website --bucket my-site
```

Websites are served on the S3 API's port, at hosts of their own, which is
how Cairn tells a website's request from the API's:

- **At the website domain.** As S3's website endpoints
  (`bucket.s3-website-<region>.amazonaws.com`): with
  `--website-domain s3-website.example.com`, `my-site.s3-website.example.com`
  is `my-site`'s website. It needs a wildcard DNS record,
  `*.s3-website.example.com`, pointing at Cairn (or the proxy in front of
  it). The website domain may be a subdomain of the API's, not the API's
  itself.
- **At a custom domain.** As on S3, a host that isn't one of the S3 API's
  names a bucket by all of itself: create the bucket `www.example.com`, give
  it a website, and point `www.example.com` at Cairn (a `CNAME` to, say,
  `www.example.com.s3-website.example.com`), and it's served there. Cairn
  knows the S3 API's hosts by `--domain`: the domain, its subdomains, IP
  addresses and `localhost` are the API's; with `--domain` set, any other is
  a custom domain. An apex domain (`example.com`) can't be a `CNAME`; give it
  an `A` record, and, as on S3, a bucket `example.com` whose website
  redirects every request to `www.example.com`.

Nothing has to be set up per website in the proxy, as long as it passes on
requests for any host to Cairn, with their `Host` as the client sent it (a
catch-all, or default, server).

### HTTPS for websites and buckets

Websites are served over whatever the proxy in front of Cairn serves them
over. S3's are plain HTTP (on AWS, CloudFront serves them over HTTPS); in
Cairn, the proxy needs a certificate for each host: a website's, at the
website domain or a custom domain, and a bucket's, virtual-hosted. A
wildcard certificate covers the website domain's and the API's (but buckets
with dots in their names), but no custom domain.

So the proxy may get them as they're needed, as
[Caddy's on-demand TLS](https://caddyserver.com/on-demand-tls) does: when a
TLS handshake asks for a host it has no certificate for, it asks Cairn's peer
endpoint whether to get one, at `/tls/ask?domain=<host>`. That answers 200
for exactly the hosts Cairn serves something at, and 404 for any other:

- the S3 API's domain (`--domain`);
- `<bucket>.<domain>`, if the bucket exists;
- `<bucket>.<website domain>`, and a custom domain, if the bucket has a
  website configuration.

That keeps anyone from having the proxy ask for certificates for names of
their own, which would use up the CA's rate limits. The proxy has to reach
the peer endpoint for it, by an IP address or the node's peer URL's host (as
the CLI does). In Caddy's global options:

```caddyfile
{
	on_demand_tls {
		ask http://cairn:9431/tls/ask
	}
}

https:// {
	tls {
		on_demand
	}
	reverse_proxy cairn:9000
}
```

Caddy redirects plain HTTP to HTTPS by itself. A certificate is got the
first time a host is asked for, which takes a few seconds. Let's Encrypt
issues at most 50 certificates a week per registered domain, so a cluster
with more buckets than that at the website domain (or virtual-hosted)
should have Caddy get a wildcard certificate for each instead, by a DNS
challenge, and on-demand ones only for the rest (custom domains, which are
registered domains of their own). [`deploy/compose`](#docker-compose) has
both configurations.

What a website serves, as S3's website endpoints do:

- **Only what anyone may read.** Requests to a website are never signed, so
  they're anonymous: a page is served if the bucket's policy allows
  `s3:GetObject` to `"*"`, and no public access block restricts it (a new
  bucket blocks public policies until its block is removed: see
  [Users and permissions](#users-and-permissions)). A page that isn't there is a 403, not a 404, unless the policy
  allows `s3:ListBucket` to anyone too.
- **Index documents.** The root, and any key ending in `/`, is served its
  index document: `docs/` serves `docs/index.html`, with the configuration's
  `index.html`. A request for `docs`, if there's no such object but there is
  `docs/index.html`, is redirected to `docs/` (302).
- **Error documents.** A 4XX (a page that isn't there, or isn't public) is
  answered with the error document, with the error's status. Without one, or
  if it can't be served either, it's S3's HTML error page, which says what
  went wrong (and why the error document couldn't be served); its
  `x-amz-error-code` and `x-amz-error-message` headers say so too, for a HEAD.
- **Redirects.** An object with a website redirect location
  (`--website-redirect-location` on upload: `/other/page.html` or a URL) is a
  301 there. Routing rules (`RoutingRules`, up to 50) redirect the requests
  they match, by key prefix before anything's served
  (`KeyPrefixEquals`), or by the error a request got (`HttpErrorCodeReturnedEquals`),
  to another host, protocol or key (`ReplaceKeyWith`, or
  `ReplaceKeyPrefixWith` in place of the condition's prefix), with a status
  of choice (301 by default). `RedirectAllRequestsTo` redirects every request
  to the same path on another host, and can't be combined with the rest.
  Redirects that keep the request's host and protocol take them from its
  `Host` and `X-Forwarded-Proto`.
- **Only GET and HEAD**, with ranges and conditional requests, and CORS: a
  browser's preflight is answered by the bucket's [CORS](#cors) rules, as on
  its S3 API. Any other method is a 405.

The configuration's rules and their errors are AWS's, as documented; they
haven't been probed against S3 yet. Neither has whether S3 keeps a request's
query string through a redirect: Cairn doesn't.

## Limits

As in S3: a PutObject, an UploadPart, an UploadPartCopy's range and a
CopyObject's source may hold up to **5 GiB**, and an object up to **5 TiB**
(10,000 parts). Every part of a multipart upload but the last must be at least
**5 MiB**. Larger objects are uploaded in parts, and copied part by part,
which S3 clients do by themselves. A request declaring more is refused before
its body is read.

## Encryption

Objects can be encrypted with a key their client supplies (**SSE-C**), with
keys of Cairn's [KMS](#kms) that IAM lets their users use (**SSE-KMS**), or
with keys no one need be granted, wrapped by the KMS's root key
(**SSE-S3**). Either way, Cairn encrypts the data before it's stored, so no
disk ever holds it in the clear.

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
  encrypted swap (and without hibernation), as you would OpenBao. The KMS's
  root key, and the key material it unwraps, are no exception.

A bucket's [default encryption](#bucket-default-encryption) can be SSE-KMS or
SSE-S3. A request for encryption Cairn can't give (SSE-KMS or SSE-S3 without a
KMS) is refused with `501 NotImplemented`, rather than stored unencrypted.

### SSE-C

Send the
`x-amz-server-side-encryption-customer-*` headers with the PUT, as with S3
(`aws s3api put-object --sse-customer-algorithm AES256 --sse-customer-key
fileb://key`), and the same key with every GET and HEAD of the object. Cairn
never stores the key. The object has a random key of its own, which encrypts
its data, kept encrypted under yours (as MinIO does): a wrong key fails to
open it. Without your key, the data can't be read, by anyone.

- The key travels in a request header, so it's only accepted over HTTPS: a
  request must come through a proxy that sets `X-Forwarded-Proto: https` (or
  `Forwarded: proto=https`). Behind an encrypted network instead, allow it with
  `--allow-sse-c-over-http`. Lose the key and the object is lost.
- Multipart uploads: send the key with CreateMultipartUpload and every
  UploadPart (CompleteMultipartUpload doesn't need it).
- Copies: send the source's key in the `x-amz-copy-source-server-side-encryption-customer-*`
  headers, and the copy's (if any) in the usual ones. A copy with a key
  (yours, the same or another, or an SSE-KMS one) shares the source's data:
  it keeps the source's object key, encrypted under its own. So changing an
  object's key, by copying it onto itself, doesn't rewrite it, and the old key
  opens nothing of it after. A copy without a key is written anew.
  Copying an object onto itself with another key changes its key.

### KMS

Cairn has a KMS of its own, with AWS KMS's API: keys of an account, which
SSE-KMS uses, and which clients may use directly too (`aws kms encrypt`,
an envelope encryption SDK, ...). Requests signed for the `kms` service
are KMS's, on the S3 port (as SNS's are):

```bash
aws --endpoint-url https://s3.example.com kms create-key --description invoices
aws --endpoint-url https://s3.example.com kms create-alias \
    --alias-name alias/invoices --target-key-id <key ID>
aws --endpoint-url https://s3.example.com kms encrypt --key-id alias/invoices \
    --plaintext fileb://secret.txt --encryption-context project=x
```

- **Keys** are symmetric (`SYMMETRIC_DEFAULT`, `ENCRYPT_DECRYPT`, of origin
  `AWS_KMS`): CreateKey, DescribeKey, ListKeys, Enable/DisableKey,
  UpdateKeyDescription, Get/PutKeyPolicy, ListKeyPolicies, Tag/UntagResource,
  ListResourceTags; aliases (Create/Update/DeleteAlias, ListAliases);
  Encrypt, Decrypt, ReEncrypt, GenerateDataKey(WithoutPlaintext),
  GenerateRandom. Key IDs are UUIDs, ARNs
  `arn:aws:kms:us-east-1:<account>:key/<id>`, and a request may name a key
  by its alias too (`alias/<name>`, or its ARN). Ciphertexts are bound to
  their encryption context, and name their key, as KMS's.
- **Rotation**: on demand (RotateKeyOnDemand, up to 25 times), or every
  90 to 2560 days (EnableKeyRotation). A rotation makes a new key version,
  which encrypts from then on; what the older ones encrypted still opens.
- **Deletion** is scheduled, 7 to 30 days ahead (ScheduleKeyDeletion), and
  can be cancelled until then. Then the key and its material are gone, and
  nothing it encrypted opens again (crypto-shredding): but backups of the
  database hold the material, wrapped by the root key, until they're past
  their [retention](#backups). So a key is shredded for good its pending
  window plus the backup's retention after it's scheduled for deletion.
- **Who may use a key** is IAM's to decide, as in AWS: its key policy and the
  principal's own policies (`kms:Encrypt`, `kms:Decrypt`, ... on the key's
  ARN). A key policy must allow a request: by naming the principal, which is
  enough, or by naming its account (`arn:aws:iam::<account>:root`), which
  leaves it to the principal's identity policies. The default key policy
  does the latter, so a new key is as usable as its users' policies say. A
  Deny in either denies. The account's root user is no exception: a key
  policy that names neither it nor its account locks it out, which
  PutKeyPolicy refuses unless `BypassPolicyLockoutSafetyCheck` is given.
  Conditions may use KMS's keys (`kms:EncryptionContext:<key>`,
  `kms:ViaService`, `kms:CallerAccount`, `kms:RequestAlias`, ...) and the
  key's tags (`aws:ResourceTag/<key>`).
- Not there: grants, asymmetric, HMAC, imported and multi-Region keys,
  custom key stores. Their operations answer `UnsupportedOperationException`.

#### The root key

Every key's material (a 256-bit key per version) is kept in the database,
wrapped by one **root key**, and unwrapped when it's used (a node keeps it
in memory for an hour after its last use). The root key is either a file or
a key of OpenBao's (or Vault's) Transit engine; a cluster has one or the
other, the same on every node. Without either, there's no KMS: SSE-KMS and
SSE-S3 are refused (`501`), and so is KMS's API.

**A file** (`--kms-root-key-file`): 32 random bytes, raw or in base64.

```bash
openssl rand -base64 32 > cairn-root.key    # on every node, the same
```

Keep it on a tmpfs, off the data disks and out of backups: a Kubernetes
secret, a systemd credential (`LoadCredentialEncrypted=`), Docker's or
Podman's secrets. Whoever has it and a copy of the database (or of its
backup) can read everything; and without it, nothing is readable: keep a
copy of it somewhere safe, apart from the cluster.

**OpenBao** (`--kms-address`): the root key is a Transit key, which never
leaves OpenBao; Cairn asks it to wrap and unwrap (`encrypt` and `decrypt`).
OpenBao's audit log tells each unwrap, and revoking Cairn's access cuts
every node off within an hour (at once, for a node that just started).
Cairn logs in as itself, through a JWT auth mount of its own, with the
Ed25519 key `--kms-jwt-key`, as the subject `cairn`. Setting it up, once:

```bash
openssl genpkey -algorithm ed25519 -out cairn-kms.pem   # --kms-jwt-key, on every node
openssl pkey -in cairn-kms.pem -pubout -out cairn-kms.pub
bao secrets enable transit
bao write -f transit/keys/cairn                          # --kms-transit-key transit/cairn
bao policy write cairn - <<'POLICY'
path "transit/encrypt/cairn" { capabilities = ["update"] }
path "transit/decrypt/cairn" { capabilities = ["update"] }
POLICY
bao auth enable -path=cairn jwt                          # --kms-auth-mount
bao write auth/cairn/config jwt_validation_pubkeys=@cairn-kms.pub
bao write auth/cairn/role/cairn role_type=jwt user_claim=sub \
    bound_subject=cairn bound_audiences=cairn \
    token_policies=cairn token_type=batch token_ttl=5m  # --kms-auth-role
```

Don't grant `create` on the key's paths: OpenBao makes a missing key on an
`encrypt` that may, so a mistyped key name would make a new root. Keep
OpenBao itself backed up (Raft snapshots): without its key, nothing Cairn
wrapped opens. The console's Storage page shows each node's root key, and
for OpenBao, whether it's reachable, how its logins went (and what's wrong
with its setup if they fail), and Cairn's public key.

The database keeps a canary that the cluster's first root wrapped: a node
whose root doesn't unwrap it refuses to start, and so does a node without a
root once the cluster has one. The root also wraps the
[backup's](#backups) key and the [tiers'](#remote-tiers), which the database
keeps in the clear without a KMS (wrapped as soon as a node with a root
starts).

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `--kms-root-key-file <PATH>` | `CAIRN_KMS_ROOT_KEY_FILE` | none | The root key, a file of 32 bytes (raw or base64). |
| `--kms-address <URL>` | `CAIRN_KMS_ADDRESS` | none | OpenBao (or Vault) server whose Transit key is the root key, e.g. `https://bao.internal:8200`. |
| `--kms-transit-key <ID>` | `CAIRN_KMS_TRANSIT_KEY` | `transit/cairn` | The root key in OpenBao: `<mount>/<key>`. |
| `--kms-jwt-key <PATH>` | `CAIRN_KMS_JWT_KEY` | *required with OpenBao* | PEM file of the Ed25519 private key Cairn signs its logins to OpenBao with. The same on every node. |
| `--kms-auth-mount <PATH>` | `CAIRN_KMS_AUTH_MOUNT` | `cairn` | Where OpenBao's JWT auth method for Cairn is mounted. |
| `--kms-auth-role <NAME>` | `CAIRN_KMS_AUTH_ROLE` | `cairn` | The role of that auth method Cairn's logins use. |
| `--kms-ca-cert <PATH>` | `CAIRN_KMS_CA_CERT` | public roots | PEM file of the CA certificates to trust for OpenBao's TLS. |

#### Audit log

Every call to KMS's API is recorded, as CloudTrail records it: an event in
CloudTrail's format (`eventSource` `kms.amazonaws.com`), with who made it
(`userIdentity`), from where, its parameters (never a plaintext or a
ciphertext), the keys it was about (`resources`), and its outcome, denials
and errors included. Calls that are refused before they're authenticated
(an unknown access key, a bad signature) aren't recorded.

A record is durable before its call is answered: each node appends its
records to a log in its data dir (`audit/`), and syncs it (once for all the
calls that arrive together) before answering them. So every answer a
client got has its record. If a record can't be written (the disk failing
or full), the call fails (`500`) rather than going unrecorded.

Every five minutes (on the clock's marks: :00, :05, ...), each node that
logged anything ships it into the cluster's own storage (an internal
bucket no request reaches), where it's replicated as objects are, and kept
for 90 days. So a node's disk failing loses at most its last five minutes
of records.

The records are read with CloudTrail's `LookupEvents`, as an account's
event history: `aws cloudtrail lookup-events`, with Cairn as the endpoint
(requests signed for `cloudtrail`, on the S3 port). It answers the
caller's account's events, newest first, with at most one lookup
attribute (`EventName`, `Username`, `ResourceName`, `AccessKeyId`, ...)
and a time range, 50 at most a page, and needs `cloudtrail:LookupEvents`
in the caller's identity policies. As in AWS, an event is found once
it's shipped: within five minutes (and a few seconds) of its call. Calls to
`LookupEvents` are recorded too (`eventSource` `cloudtrail.amazonaws.com`).
A lookup over a long time with few matches may answer fewer events than
asked for, none even, with a `NextToken` to go on with; the CLI follows it
on its own. Each shipped object's metadata lists the accounts and the
events it has, so a lookup reads only the objects that may have what it's
after.

##### Trails

A trail delivers an account's events to a bucket, as CloudTrail's log
files, so that tools that read CloudTrail's (SIEMs, Athena's tables,
`jq`) read Cairn's: `aws cloudtrail create-trail --name main
--s3-bucket-name logs`, then `aws cloudtrail start-logging --name main`.
Its files are gzipped JSON (`{"Records":[...]}`), at
`[<prefix>/]AWSLogs/<account>/CloudTrail/us-east-1/<y>/<m>/<d>/<account>_CloudTrail_us-east-1_<time>_<unique>.json.gz`.

- As in AWS, the bucket's policy must let the service
  `cloudtrail.amazonaws.com` read its ACL (`s3:GetBucketAcl`) and write the
  trail's files (`s3:PutObject` on `<prefix>/AWSLogs/<account>/*`, with
  `s3:x-amz-acl` `bucket-owner-full-control`); `aws:SourceArn` is the
  trail's ARN. CloudTrail's own example policy works as it is. Creating or
  changing a trail checks it (`InsufficientS3BucketPolicyException`). The
  bucket may be another account's.
- With `--kms-key-id`, its files are encrypted with that key (SSE-KMS),
  whose policy must let `cloudtrail.amazonaws.com` use it
  (`kms:GenerateDataKey*`, with the encryption context
  `aws:cloudtrail:arn` the trail's ARN, and `aws:SourceArn` too), as in
  AWS; otherwise, with the bucket's default encryption.
- Event selectors choose what it delivers (`put-event-selectors`): basic
  ones (read, write or all management events, but KMS's) or advanced ones
  (conditions on `eventSource`, `eventName`, `readOnly`, `resources.ARN`,
  ...). Every event Cairn records is a management event: a selector of data
  events is kept, but selects nothing yet.
- `get-trail-status` says whether it's logging, when it last delivered a
  file, and its last error, if delivery failed.
- An account has at most five trails. Trails also have tags (`add-tags`,
  ...). Each needs its `cloudtrail:` action in the caller's identity
  policies, on the trail's ARN (`DescribeTrails` and `ListTrails` on
  `*`).
- Not yet: log file validation (digest files), SNS notifications,
  organization trails. Not planned: CloudWatch Logs, Insights.

A trail delivers about 30 seconds after each five-minute mark, once every
node has shipped its last five minutes: an event is in a file within about
five and a half minutes of its call, under three on average. One node
delivers at a time, from what the nodes shipped, so a node that's down
holds up only its own records. Each event is delivered at least once:
rarely twice (a node ending as it delivers), as CloudTrail may, so readers
should tell events apart by `eventID`. If the bucket doesn't take the
files (it's gone, or its policy changed), they're tried again every five
minutes for 30 days, the error in `get-trail-status`. A trail delivers the
events of while it was logging: those after `start-logging`, until
`stop-logging`.

### SSE-KMS

With a KMS, a write may ask for SSE-KMS, as with S3: `aws s3api put-object
--server-side-encryption aws:kms --ssekms-key-id <key>`, optionally with
`--ssekms-encryption-context <base64 JSON>`. Reads need nothing more. The
key is named by its ID, its ARN, or an alias (an ID or alias is the
writer's account's; another account's key, of the organization, by its
ARN). A write that names none gets its bucket's owner's `aws/s3` key, an
AWS managed key that's made the first time it's needed, as in S3.

- The writer must be allowed `kms:GenerateDataKey` on the key, and a reader
  `kms:Decrypt`, as in S3: by the key's policy and their own (see
  [KMS](#kms)), through S3 (`kms:ViaService` is
  `s3.us-east-1.amazonaws.com`). So a principal may read an SSE-KMS object
  only if it may read the object *and* use its key. Anonymously, never.
- Every object gets a random key of its own, which Cairn keeps sealed under
  a data key of the KMS key, and keeps that data key only as the KMS
  encrypted it, bound to the object's name (`aws:s3:arn`) and the
  encryption context: it opens for that object only, and only with that
  context. Responses name the key by its ARN.
- `x-amz-server-side-encryption-bucket-key-enabled` is accepted and ignored,
  as in MinIO: every object has keys of its own anyway.
- Multipart uploads: ask for SSE-KMS with CreateMultipartUpload. Its parts
  need the use of the key, but no headers.
- Copies to another SSE-KMS key or context, or to SSE-C, share the source's
  data: the copy seals the same object key under a data key of its own. That
  changes who may open it, but not the key the data is encrypted with. To
  change that too (if an object's key may have leaked, say), copy to SSE-S3
  or a plain object and back, which writes the data anew.
- A disabled key, or one pending deletion, opens nothing: reads and writes
  of its objects fail (`KMS.DisabledException`,
  `KMS.KMSInvalidStateException`), and nothing else is affected (HEAD needs
  no key). If OpenBao can't be reached and a node hasn't the key's material
  yet, they fail with `503`.

### SSE-S3

With a KMS, a write may ask for SSE-S3, as with S3: `aws s3api put-object
--server-side-encryption AES256`. Reads need nothing. Its keys are no one's
to grant: any principal that may read an object reads it, and so can the
console's downloads. It protects the data at rest (disks, the database,
backups), not from Cairn's users.

- As S3's bucket keys do, a node uses one data key for an hour of writes,
  wrapped by the root key, and keeps the data keys it unwrapped for an hour
  after their last use. So OpenBao sees a few calls an hour, not one a
  request. Every object still has a key of its own, bound to its name.
- Copies among SSE-S3 objects share their data. Copies between SSE-S3 and the
  other kinds are written anew, as their ETags differ (an SSE-S3 object's is
  its content's MD5).

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
- With an SSE-KMS default, the writer must be allowed to use the key, as
  when it names the key itself: one that may write the bucket but not use
  its default key can write only by asking for other encryption.
- An SSE-KMS default's key is kept as it's given (its ID, ARN or alias), as
  in S3: a write resolves it, in the writer's account unless it's an ARN.
  `BucketKeyEnabled` is told back, but changes nothing.
- Changing or removing the default leaves what's written as it is. A write
  under way keeps the default it began with.
- The console's Buckets page shows each bucket's default.

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
(CRC32, CRC32C, CRC64NVME, SHA-1, SHA-256, SHA-512, MD5, XXHash64, XXHash3
or XXHash128), or else a CRC64NVME that Cairn computes. A multipart upload
gets the algorithm and type (`COMPOSITE` or `FULL_OBJECT`) it was created
with, or else a full-object CRC64NVME. Only the CRCs can be `FULL_OBJECT`,
as in S3. As in
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
database (`scrub_findings`), and shown on the console's
[Integrity](#the-operators-pages) page.

Data written by versions of Cairn without checksums can't be checked as it
is. The packer rewrites it with checksums, the oldest first, reading at the
scrub rate (and not at all if scrubbing is off), and verifying each object's
bytes against its MD5 (its ETag). A replica whose copy doesn't match is passed
over for the next; if none matches, the data is recorded as lost. The
Integrity page shows how much is still left.

`POST /scrub` on a node's peer endpoint checks what's due right away, at
full speed (`?all`: every copy), and reports what it found. Like everything
on the peer endpoint that isn't blob traffic, it needs the header
`x-cairn-cli` (any value), so that no web page can start it: e.g.
`curl -X POST -H 'x-cairn-cli: 1' http://10.0.0.1:9431/scrub`.

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
- **Data of tiers' classes goes there.** It's packed into the
  [tier](#remote-tiers)'s objects as it's moved, rather than in the cluster
  first, and compacted there once half of an object is garbage.

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
cairn config set parity-shards 2
cairn config set data-shards 4      # blobs over 64 MiB are coded 4+2
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
console's Storage page shows each layout's health, and the Jobs page how
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

## Backups

Cairn backs the whole cluster up to a bucket of another S3 service: its data,
and everything in its database (buckets, objects and their versions, users,
policies, settings, ...). A new cluster can be restored from that bucket
alone: no copy of the database is needed, and none has to be made. Changes
reach the backup every 5 minutes (the most a restore can lose), and the
backup holds few, large objects, however many the cluster has.

```sh
cairn backup enable --endpoint https://s3.eu-central-1.amazonaws.com --region eu-central-1 \
    --bucket my-backups --prefix cairn/ \
    --access-key-id AKIA... --secret-access-key ...   # or CAIRN_BACKUP_ACCESS_KEY_ID/_SECRET_ACCESS_KEY
# backing up to s3://my-backups/cairn/ at https://s3.eu-central-1.amazonaws.com, every 300s
# key: 3q2+7wD...
cairn backup status
```

**Keep the key it prints**, somewhere other than the cluster (`cairn backup
key` prints it again while the cluster is there): everything in the backup
is encrypted with it, and a restore needs it (or the KMS's root key: see
below). With a [KMS](#kms), the database keeps it wrapped by the root key,
and so does the object `key.wrapped` next to the backup. The bucket should have
versioning on (and, better, Object Lock, or a lifecycle rule that keeps
noncurrent versions for a while), so that what's deleted there, by mistake
or by whoever has the credentials, can be got back. The prefix must be the
backup's own: `enable` refuses one that holds objects already. Use
`--path-style` for services that don't take the bucket in the host name
(most but AWS).

| Flag | Default | |
| --- | --- | --- |
| `--interval` | `5m` | How often changes are shipped: the RPO. |
| `--retention` | `7d` | How long what the cluster no longer needs is kept in the backup: how far back a restore can go. |
| `--pack-size` | `256MiB` | How large the backup's objects of data are. |

`cairn backup enable` again changes them (or, with another bucket or
prefix, starts a new backup there); `cairn backup disable` stops it (what's
in the bucket stays, and enabling it again there carries on); `cairn backup
now [--base]` runs a cycle at once. The console's Backup page does all of
these and shows the status, but never the key: only `cairn backup key`, on
a node, prints it.

### How it works

One node at a time runs the backup (any node takes over if it's gone). While
a backup is on, triggers log every change to the database's tables in the
transaction that makes it. Every interval, the node ships what was logged,
in a **journal**, together with the bytes of the parts it added, copied from
the cluster and checked against their checksums. Up to a pack's worth of
bytes goes into the journal; more goes into **packs** of `--pack-size`. So a
cycle writes one object, or a few, whatever was written; a cluster that's
idle writes none. A copy (CopyObject) shares its source's bytes in the
backup, as in the cluster. Every so often (once the journals since add up to
its size, after 2016 journals, or after an upgrade changed the schema), a
**base** snapshot of the database follows. A large one (hundreds of GiB, for
hundreds of millions of objects) takes a while: it's written in chunks, in
between the journals, which go on every 5 minutes meanwhile, and it carries
on from its last chunk after an interruption (a node going down, the target
being unreachable), on whichever node runs the backup next. Until it's
complete, the base before it is the one a restore uses. Data that was there before the
backup was turned on is copied a batch every few seconds, until it's all in:
`cairn backup status` shows how much is left.

The backup doesn't rewrite its objects to reclaim space: with versioning on
the bucket, that would only keep another copy around. A pack is deleted once
nothing in it is needed anymore (after the retention). Just two things are
written again, both bounded: the bytes in journals are moved into a pack
once there's a pack's worth, or a day has passed (so a trickle of small
writes doesn't leave an object behind every 5 minutes), and a pack of which
less than half is still needed has that half rewritten, together with that
of other such packs. So the backup holds at most about twice what's live for
good, and a rewrite adds at most half a pack's size while the old pack is
still kept.

Data in [remote tiers](#remote-tiers) isn't copied into the backup: the
backup points at the tier's objects, which a restore reads from where they
are. (Their deletion from the tier waits for the backup's retention, so that
they're there for any restore within it.)

Everything is encrypted (XChaCha20-Poly1305, with a key of each object's own
derived from the backup's key and its name), so that the target holds
nothing readable without the key, and nothing it holds can be altered,
swapped or cut short unnoticed. Objects encrypted with SSE-KMS or SSE-S3
stay encrypted as they are: the KMS's keys are in the backup (the
database's tables), wrapped by the root key, so restoring them needs the
same root key (the file, or OpenBao's key), which isn't. Nor are the nodes'
flags.

### Restoring

Restore into a new, empty database, before starting any node on it:

```sh
createdb cairn_restored
cairn restore --database postgres://user:pass@db.internal/cairn_restored \
    --endpoint https://s3.eu-central-1.amazonaws.com --region eu-central-1 \
    --bucket my-backups --prefix cairn/ \
    --access-key-id AKIA... --secret-access-key ... --key 3q2+7wD...
# restoring to 2026-11-18T09:30:12Z (schema 74): the base after journal 812 and 140 journals
```

Instead of `--key`, `cairn restore` takes the old cluster's root key
(`--kms-root-key-file`, or `--kms-address` and the rest): it reads the
backup's key from `key.wrapped` in the backup, and unwraps it. The new
cluster's nodes need that root key too.

It loads the database as it was at the last journal (or as of `--at
2026-11-18T08:00:00Z`, any time within the retention; `--list`, which
needs no `--database`, shows what's there and what a restore would restore
to). An object of the backup that can't be read (damaged, say) is reported
and skipped: a restore uses the newest base it can read, and the journals
after it up to the first it can't. Then start the new cluster's nodes on that database, as usual (they
can be other machines, and more or fewer of them, with the same pools as the
storage classes need). Every object is readable at once: what isn't in the
cluster yet is read from the backup. Meanwhile, the nodes copy the data into
the cluster in the background, checked against its checksums: `cairn
backup status` and the console (its Backup page, and the dashboard while
it's copying) show how much is left, and the parts the backup lacked, if
any. The restored cluster isn't backed up until you
turn that on, to a new prefix.

Objects in [remote tiers](#remote-tiers) are read from the tiers, and stay
there. But the old cluster may still be running (a restore that's a test,
say), and deleting from the tiers what it no longer needs, so the restored
cluster's tiers are **read-only**: it reads from them, but writes its
objects of their classes into the cluster, and deletes nothing from them.
Once the old cluster is gone for good, `cairn tier set <name> --writable
true` (or `cairn restore --writable-tiers`) gives the tier to the new one.

The cluster comes back with its settings, such as `parity-shards`: a new
cluster with fewer nodes than those need has to change them first. Parts
whose bytes the backup lacks (written in the moments before the last
journal, or deleted from the cluster then) are reported, and reads of them
fail, as of data lost to damage.

## License

Licensed under the [GNU Affero General Public License, Version 3](LICENSE) or later.
