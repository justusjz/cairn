//! Remote storage tiers: buckets of other S3 services that storage classes
//! keep their data in, rather than in a pool of the nodes' disks.
//!
//! A **tier** is a bucket and prefix of an S3 service (`cairn tier add`),
//! with credentials, the storage class its objects are written in there
//! (`--remote-class`, the service's default if none), and a key of its
//! own, which Cairn makes. A storage class names the tier it keeps its data
//! in (`cairn class set COLD --tier archive`). Objects ask for the class as
//! for any other, and report it as theirs.
//!
//! ## Writing
//!
//! Nothing waits on the tier: a write into a tier's class is written into
//! the cluster first, as a class of STANDARD's pool and layout would be
//! (see `classes`), so its blobs are committed as any others. Then the
//! packer moves them into the tier, in jobs of their own (`Kind::Offload`,
//! claimed by T69): once their live bytes fill a blob (256 MiB), or the
//! oldest has waited a day (`packer::Config::offload_after`). A job lays
//! the parts out as a packing job does (`packer::lay_out`), and writes each
//! new blob as an object of the tier, `blobs/<blob id>`, from the parts'
//! bytes, read from the cluster and checked against their checksums as
//! they're copied. Then it commits (T70): the new blobs are **remote**
//! blobs (`tier_blobs` says which object each is), which no node holds,
//! and the parts point into them, as a packing job's do.
//!
//! So a tier holds few, large objects, however many small ones its class
//! has: what matters for providers that charge per request, or per object.
//!
//! ## Reading
//!
//! A read of a remote blob reads the range it needs of its object
//! ([`stream`]): the reads of a blob no node holds come here (see
//! `blobs::stream_blob_range`), as a restore's do. Nothing is cached in the
//! cluster.
//!
//! ## Encryption
//!
//! Every object is sealed as a backup's are (see `backup::crypt`): its
//! plaintext in segments of 64 KiB, each sealed with XChaCha20-Poly1305,
//! under a key of the object's own, derived from the tier's key and the
//! object's name. So the tier holds nothing readable without the key, and
//! nothing it holds can be altered, swapped or cut short unnoticed; and a
//! range is read by reading the segments it overlaps. Objects encrypted
//! with SSE are sealed again, as they're stored.
//!
//! The tier's key is in the database, and so in the backup (see below).
//!
//! ## Garbage
//!
//! Remote blobs are folded as any others (`packer::fold_garbage`): one that
//! no part references anymore is dropped, and one with at least half of it
//! garbage (`Config::remote_compact_threshold`, higher than in the cluster,
//! since rewriting it is reading it from the tier) is compacted, by the same
//! jobs as offloads, into new objects. Scrubbing a tier is the tier's job.
//!
//! An object whose blob is dropped is deleted from the tier ([`sweep`]),
//! but not right away: only once it's been unneeded for the backup's
//! retention (an hour at least, `Config::tier_hold`), so that a restore to
//! any time within it finds every object it points at.
//!
//! ## Misplaced data
//!
//! A version transitioned into a lower class than its tier's class (see
//! `classes`) leaves its bytes in the tier, misplaced, until a job takes
//! their blob: compaction does once its garbage and misplaced bytes are
//! enough of it, and moves them into the cluster, as new blobs of their
//! class, first (`packer::relocate`). Likewise, a job moving blobs into the
//! tier moves the misplaced bytes on them into their class instead.
//!
//! ## Changing a class's tier
//!
//! A class moved to another tier has its remote blobs moved there too, by
//! the same jobs; one that's no longer a tier's (`cairn class set --pool`)
//! has its remote blobs copied back into the cluster, by conversions (see
//! `packer`), which read them as any reads do.
//!
//! ## Backups and restores
//!
//! The backup doesn't copy a tier's data: it points the parts there at
//! the tier's objects (see `backup::cycle`), which it never writes or
//! deletes. A restore makes them remote blobs again, readable at once, and
//! leaves them there, rather than copying them into the new cluster.
//!
//! But the old cluster may still be running (a restore that's a test, say),
//! and deleting the objects it no longer needs: so a restored cluster's
//! tiers are **read-only** (`writable` false). It reads from them, but
//! never writes to them or deletes from them: its objects of the tiers'
//! classes stay in the cluster. Once the old cluster is gone for good,
//! `cairn tier set <name> --writable true` (or `cairn restore
//! --writable-tiers`) gives it the tier, and the objects it no longer needs
//! are deleted after all.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use clap::{Args, Subcommand};
use deadpool_postgres::GenericClient;
use hyper::body::Frame;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::App;
use crate::admin::{Output, outln};
use crate::backup::crypt::{self, ObjectReader, ObjectWriter};
use crate::backup::s3::{Location, Target};
use crate::blobs::{BlobSlice, Location as BlobLocation, reap_blobs, reap_columns, stream_blob_range};
use crate::body::FrameSender;
use crate::classes::Class;
use crate::db::{self, Cached};
use crate::packer::{self, JobReport, Kind, Part, Run, Verifier};
use crate::shards::Layout;

/// How many new blobs' worth of live data a job takes at most.
const OUTPUTS_PER_JOB: u64 = 4;
/// How long a job may hold its sources.
const LEASE: Duration = Duration::from_secs(3600);
/// How many jobs a class gets per pass, at most.
const JOBS_PER_PASS: usize = 4;
/// How many of a tier's objects a sweep deletes at most.
const SWEEP_BATCH: i64 = 1000;
/// Remote storage classes a tier's objects can't be read from without a
/// restore, which tiers can't do (yet).
const COLD_CLASSES: &[&str] = &["GLACIER", "DEEP_ARCHIVE"];

/// A tier.
#[derive(Clone)]
pub struct Tier {
    pub name: String,
    pub location: Location,
    pub key: [u8; 32],
    /// The storage class its objects are written in, if not the service's
    /// default.
    pub remote_class: Option<String>,
    /// Whether this cluster writes to it and deletes from it.
    pub writable: bool,
}

const COLUMNS: &str =
    "name, endpoint, region, bucket, prefix, path_style, access_key_id, secret_access_key, key, remote_class, writable";

fn tier_at(row: &tokio_postgres::Row, first: usize) -> anyhow::Result<Tier> {
    let key: Vec<u8> = row.get(first + 8);
    Ok(Tier {
        name: row.get(first),
        location: Location {
            endpoint: row.get(first + 1),
            region: row.get(first + 2),
            bucket: row.get(first + 3),
            prefix: row.get(first + 4),
            path_style: row.get(first + 5),
            access_key_id: row.get(first + 6),
            secret_access_key: row.get(first + 7),
        },
        key: key.try_into().map_err(|_| anyhow::anyhow!("a tier's key isn't 32 bytes"))?,
        remote_class: row.get(first + 9),
        writable: row.get(first + 10),
    })
}

/// Every tier, by name.
pub async fn load<C: GenericClient>(client: &C) -> anyhow::Result<BTreeMap<String, Tier>> {
    let rows = client.query_cached(&format!("SELECT {COLUMNS} FROM tiers"), &[]).await?;
    rows.iter().map(|r| tier_at(r, 0).map(|t| (t.name.clone(), t))).collect()
}

/// Whether `name` may name a tier: as a pool's name.
pub fn valid_name(name: &str) -> bool {
    crate::classes::valid_pool(name)
}

/// The name of a remote blob's object in its tier.
pub fn object_name(blob_id: Uuid) -> String {
    format!("blobs/{blob_id}")
}

/// Clients of the tiers, by name, as they were last configured.
type Targets = HashMap<String, (Location, Option<String>, Target)>;
static TARGETS: Mutex<Option<Targets>> = Mutex::new(None);

/// A client of `tier`, cached.
pub fn target(tier: &Tier) -> anyhow::Result<Target> {
    let mut cached = TARGETS.lock().unwrap();
    let cached = cached.get_or_insert_with(HashMap::new);
    if let Some((location, class, target)) = cached.get(&tier.name)
        && *location == tier.location
        && *class == tier.remote_class
    {
        return Ok(target.clone());
    }
    let target = Target::new(tier.location.clone())?.with_storage_class(tier.remote_class.clone());
    cached.insert(tier.name.clone(), (tier.location.clone(), tier.remote_class.clone(), target.clone()));
    Ok(target)
}

/// Streams the bytes of a remote blob that `slice` asks for to `tx`, from
/// its tier's object: `false` if it isn't a remote blob (or is gone). On
/// failure, `slice` is narrowed to the bytes that weren't sent, as
/// `stream_blob_range` does.
pub async fn stream(app: &App, slice: &mut BlobSlice, tx: &FrameSender) -> std::io::Result<bool> {
    let client = app.pool.get().await.map_err(std::io::Error::other)?;
    let row = client
        .query_opt_cached(
            &format!(
                "SELECT tb.name, tb.size, {} FROM tier_blobs tb JOIN tiers t ON t.name = tb.tier WHERE tb.blob_id = $1",
                COLUMNS.split(", ").map(|c| format!("t.{c}")).collect::<Vec<_>>().join(", ")
            ),
            &[&slice.blob_id],
        )
        .await
        .map_err(std::io::Error::other)?;
    drop(client);
    let Some(row) = row else { return Ok(false) };
    let (name, size): (String, i64) = (row.get(0), row.get(1));
    let tier = tier_at(&row, 2).map_err(std::io::Error::other)?;
    let target = target(&tier).map_err(std::io::Error::other)?;
    let reader = ObjectReader::new(&target, &tier.key, &name, size as u64);
    let (start, end) = (slice.offset, slice.offset + slice.length);
    let mut sent = 0u64;
    let result = async {
        if start >= end {
            return anyhow::Ok(());
        }
        let mut range = reader.range(start, end, 8 << 20).await?;
        while let Some(pieces) = range.next().await? {
            for piece in pieces {
                sent += piece.len() as u64;
                tx.send(Ok(Frame::data(piece))).await.map_err(|_| anyhow::anyhow!("the reader went away"))?;
            }
        }
        Ok(())
    }
    .await;
    slice.offset += sent;
    slice.length -= sent.min(slice.length);
    match result {
        Ok(()) => Ok(true),
        Err(e) => Err(std::io::Error::other(format!("reading {name} of tier {}: {e:#}", tier.name))),
    }
}

// ─── Jobs ────────────────────────────────────────────────────────────────────

/// Runs the jobs that are due for class `class`, whose tier is `tier`
/// (writable): moves its blobs in the cluster there, its remote blobs in
/// other tiers too, and compacts those that are mostly garbage. Adds what
/// they did to `reports`; a failed job is logged, and its sources stay
/// leased for a while.
pub(crate) async fn run_jobs(app: &Arc<App>, class: &Class, tier: &Tier, reports: &mut Vec<JobReport>) {
    let mut jobs = 0;
    for kind in ["compact", "move", "stage"] {
        while jobs < JOBS_PER_PASS {
            let sources = match claim(app, kind, class, Some(&tier.name)).await {
                Ok(Some(sources)) => sources,
                Ok(None) => break,
                Err(e) => {
                    eprintln!("packer: claiming {class}'s blobs for its tier: {e:#}", class = class.name);
                    return;
                }
            };
            jobs += 1;
            match offload(app, &sources, class, tier).await {
                Ok(report) => reports.push(report),
                Err(e) => {
                    let message = format!(
                        "moving {} blobs of {} into tier {} failed: {e:#}",
                        sources.len(),
                        class.name,
                        tier.name
                    );
                    eprintln!("packer: {message}");
                    app.metrics.pack_failed(message);
                }
            }
        }
    }
}

/// Claims sources for a job of `kind` (see T69) for class `class`, whose
/// tier is `tier`, if there's one worth running.
pub(crate) async fn claim(app: &App, kind: &str, class: &Class, tier: Option<&str>) -> anyhow::Result<Option<Vec<Uuid>>> {
    let config = &app.pack;
    let budget = OUTPUTS_PER_JOB * config.target_size;
    let sources: Vec<Uuid> = app
        .pool
        .get()
        .await?
        .query_one_cached(
            "SELECT pg_temp.cairn_claim_tier($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            &[
                &kind,
                &class.name,
                &tier,
                &config.remote_compact_threshold,
                &config.max_sources,
                &(config.target_size as i64),
                &(budget as i64),
                &config.offload_after.as_secs_f64(),
                &LEASE.as_secs_f64(),
            ],
        )
        .await?
        .get(0);
    Ok((!sources.is_empty()).then_some(sources))
}

/// A new remote blob: its object, and the parts that go into it.
struct NewBlob {
    blob_id: Uuid,
    size: u64,
    runs: Vec<Run>,
}

/// Moves the live parts of `sources` (blobs of class `class`, in the
/// cluster or remote) into new remote blobs in `tier`, as a packing job
/// does into new blobs of the cluster. On failure, the new blobs are
/// deleted (their objects in time, by the sweep), and the sources stay
/// leased.
pub(crate) async fn offload(app: &Arc<App>, sources: &[Uuid], class: &Class, tier: &Tier) -> anyhow::Result<JobReport> {
    let mut outputs = Vec::new();
    let result = write_outputs(app, sources, class, tier, &mut outputs).await;
    if result.is_err() {
        for blob_id in outputs {
            crate::blobs::discard(app, blob_id).await;
        }
    }
    result
}

async fn write_outputs(
    app: &Arc<App>,
    sources: &[Uuid],
    class: &Class,
    tier: &Tier,
    created: &mut Vec<Uuid>,
) -> anyhow::Result<JobReport> {
    let client = app.pool.get().await?;
    let parts = packer::load_parts(&client, sources).await?;
    let blobs = packer::load_blobs(&client, app.node, sources).await?;
    drop(client);
    // What belongs in a lower class than this one goes there first, into
    // the cluster (or, by way of it, into that class's tier).
    let (mut parts, relocated) = packer::relocate(app, sources, parts, &blobs).await?;
    let runs = if parts.is_empty() { Vec::new() } else { packer::lay_out(&mut parts, app.pack.target_size) };
    let mut outputs: Vec<NewBlob> = Vec::new();
    for run in runs {
        if outputs.len() <= run.output {
            outputs.push(NewBlob { blob_id: Uuid::new_v4(), size: 0, runs: Vec::new() });
        }
        let output = &mut outputs[run.output];
        output.size += run.length;
        output.runs.push(run);
    }
    let target = target(tier)?;
    let mut vanished: Vec<std::ops::Range<usize>> = Vec::new();
    for output in &outputs {
        // Pending until the commit, so that the GC takes it (and its
        // object) if the job dies.
        let name = object_name(output.blob_id);
        app.pool
            .get()
            .await?
            .execute_cached(
                "WITH blob AS (
                     INSERT INTO blobs (blob_id, size, state, created_at, storage_class, pool)
                     VALUES ($1, $2, 'pending', now(), $3, $4) RETURNING blob_id
                 )
                 INSERT INTO tier_blobs (blob_id, tier, name, size) SELECT blob_id, $5, $6, $2 FROM blob",
                &[&output.blob_id, &(output.size as i64), &class.name, &class.pool, &tier.name, &name],
            )
            .await?;
        created.push(output.blob_id);
        let mut writer = ObjectWriter::new(&target, &tier.key, &name);
        let mut position = 0;
        let result = async {
            for run in &output.runs {
                let (layout, locations) = blobs.get(&run.blob_id).cloned().unwrap_or_default();
                if !copy_run(app, run, &parts[run.parts.clone()], position, layout, &locations, &mut writer).await? {
                    vanished.push(run.parts.clone());
                }
                position += run.length;
            }
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = result {
            writer.abort().await;
            return Err(e);
        }
        let plain = writer.finish().await?;
        anyhow::ensure!(plain == output.size, "{name}: wrote {plain} bytes of {}", output.size);
        // What the tier says it holds, which a failed upload may not be.
        let stored = target.size(&name).await?;
        anyhow::ensure!(
            stored == Some(crypt::stored_len(plain)),
            "{name}: the tier holds {stored:?} bytes, not {}",
            crypt::stored_len(plain)
        );
    }
    vanished.sort_by_key(|r| std::cmp::Reverse(r.start));
    for range in vanished {
        parts.drain(range);
    }
    commit(app, sources, &outputs, &parts).await?;
    Ok(JobReport {
        kind: Kind::Offload,
        sources: sources.len(),
        parts: parts.len(),
        bytes: outputs.iter().map(|o| o.size).sum(),
        outputs: outputs.iter().map(|o| o.blob_id).collect(),
        relocated,
    })
}

/// Copies `run` from its source into `writer`, where its first byte is at
/// `at`, checking its parts (`parts`, in order of their new offsets) against
/// their checksums on the way. If the source can't be read because it was
/// deleted meanwhile, pads the run with zeros instead, and returns false:
/// its parts are gone, so nothing will point at those bytes.
async fn copy_run(
    app: &App,
    run: &Run,
    parts: &[Part],
    at: u64,
    layout: Option<Layout>,
    locations: &[BlobLocation],
    writer: &mut ObjectWriter,
) -> anyhow::Result<bool> {
    // The run's parts, as offsets into the run.
    let local: Vec<Part> = parts
        .iter()
        .map(|p| Part {
            id: p.id,
            blob_id: p.blob_id,
            offset: p.offset,
            size: p.size,
            output: p.output,
            new_offset: p.new_offset - at,
            run: p.run,
            crc64nvme: p.crc64nvme,
            etag: p.etag.clone(),
        })
        .collect();
    let mut verifier = Verifier::new(&local);
    let mut slice = BlobSlice {
        blob_id: run.blob_id,
        layout,
        locations: locations.to_vec(),
        offset: run.offset,
        length: run.length,
        part: None,
    };
    let (tx, mut rx) = mpsc::channel(4);
    let read = async move {
        let result = stream_blob_range(app, &mut slice, &tx).await;
        drop(tx);
        result
    };
    let forward = async {
        let mut copied = 0u64;
        while let Some(Ok(frame)) = rx.recv().await {
            if let Ok(data) = frame.into_data() {
                copied += data.len() as u64;
                verifier.update(&data);
                writer.write(&data).await?;
            }
        }
        anyhow::Ok(copied)
    };
    let (read, copied) = tokio::join!(read, forward);
    let copied = copied?;
    if let Err(e) = read {
        let exists = app
            .pool
            .get()
            .await?
            .query_opt_cached("SELECT 1 FROM blobs WHERE blob_id = $1", &[&run.blob_id])
            .await?
            .is_some();
        if exists {
            return Err(anyhow::anyhow!("reading blob {}: {e}", run.blob_id));
        }
        let mut padding = run.length - copied;
        while padding > 0 {
            let len = padding.min(1 << 20);
            writer.write(&vec![0; len as usize]).await?;
            padding -= len;
        }
        return Ok(false);
    }
    anyhow::ensure!(copied == run.length, "blob {} ended early", run.blob_id);
    verifier
        .finish()
        .map_err(|e| packer::Mismatch(format!("blob {}, moving it into a tier: {e}", run.blob_id)))?;
    Ok(true)
}

/// The transaction that ends a job (T70), retried on conflicts.
async fn commit(app: &Arc<App>, sources: &[Uuid], outputs: &[NewBlob], parts: &[Part]) -> anyhow::Result<()> {
    let out_blobs: Vec<Uuid> = outputs.iter().map(|o| o.blob_id).collect();
    let out_sizes: Vec<i64> = outputs.iter().map(|o| o.size as i64).collect();
    let ids: Vec<i64> = parts.iter().map(|p| p.id).collect();
    let old_blobs: Vec<Uuid> = parts.iter().map(|p| p.blob_id).collect();
    let old_offsets: Vec<i64> = parts.iter().map(|p| p.offset as i64).collect();
    let new_blobs: Vec<Uuid> = parts.iter().map(|p| outputs[p.output].blob_id).collect();
    let new_offsets: Vec<i64> = parts.iter().map(|p| p.new_offset as i64).collect();
    let client = app.pool.get().await?;
    for attempt in 0..db::MAX_TX_ATTEMPTS {
        db::backoff(attempt).await;
        let row = match client
            .query_one_cached(
                "SELECT status, reap_blob, reap_node, reap_peer
                 FROM pg_temp.cairn_tier_commit($1, $2, $3, $4, $5, $6, $7, $8)",
                &[&sources, &out_blobs, &out_sizes, &ids, &old_blobs, &old_offsets, &new_blobs, &new_offsets],
            )
            .await
        {
            Ok(row) => row,
            Err(e) if db::is_conflict(&e) => continue,
            Err(e) => return Err(e.into()),
        };
        match row.get::<_, &str>(0) {
            "committed" => {
                reap_blobs(app, reap_columns(&row, 1));
                return Ok(());
            }
            "gone" => anyhow::bail!("a new blob was deleted before it was committed"),
            status => unreachable!("cairn_tier_commit: unknown status {status}"),
        }
    }
    anyhow::bail!("commit kept conflicting with concurrent ones")
}

/// Deletes the tiers' objects that have been unneeded for long enough (see
/// the module's docs), from the tiers this cluster may write to: a batch,
/// on whichever node gets to them first. How many it deleted.
pub(crate) async fn sweep(app: &App) -> anyhow::Result<usize> {
    let mut client = app.pool.get().await?;
    let retention: f64 = client
        .query_opt_cached("SELECT retention_secs::float8 FROM backup_config", &[])
        .await?
        .map_or(0.0, |r| r.get(0));
    let hold = retention.max(app.pack.tier_hold.as_secs_f64());
    let tx = client.transaction().await?;
    let rows = tx
        .query_cached(
            "SELECT g.seq, g.tier, g.name FROM tier_garbage g JOIN tiers t ON t.name = g.tier
             WHERE t.writable AND g.dropped_at < now() - make_interval(secs => $1)
             ORDER BY g.seq LIMIT $2 FOR UPDATE OF g SKIP LOCKED",
            &[&hold, &SWEEP_BATCH],
        )
        .await?;
    if rows.is_empty() {
        return Ok(0);
    }
    let tiers = load(&tx).await?;
    let mut by_tier: BTreeMap<String, (Vec<i64>, Vec<String>)> = BTreeMap::new();
    for row in &rows {
        let entry = by_tier.entry(row.get(1)).or_default();
        entry.0.push(row.get(0));
        entry.1.push(row.get(2));
    }
    let mut deleted = Vec::new();
    for (name, (seqs, names)) in by_tier {
        let Some(tier) = tiers.get(&name) else { continue };
        match target(tier)?.delete(&names).await {
            Ok(()) => deleted.extend(seqs),
            Err(e) => eprintln!("tier {name}: deleting {} objects that are no longer needed failed: {e:#}", names.len()),
        }
    }
    tx.execute_cached("DELETE FROM tier_garbage WHERE seq = ANY($1)", &[&deleted]).await?;
    tx.commit().await?;
    Ok(deleted.len())
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Args, Debug, Serialize, Deserialize)]
pub struct TierArgs {
    #[command(flatten)]
    #[serde(skip)]
    pub remote: crate::admin::Remote,
    #[command(subcommand)]
    command: TierCommand,
}

#[derive(Subcommand, Debug, Serialize, Deserialize)]
enum TierCommand {
    /// List the tiers: where they are, and what they hold.
    List,
    /// Add a tier: a bucket (and prefix of its own) of an S3 service that
    /// storage classes can keep their data in (`cairn class set <class>
    /// --tier <name>`).
    Add {
        /// Its name: lowercase letters, digits, - and _.
        name: String,
        #[command(flatten)]
        location: TierLocationArgs,
        /// The storage class its objects are written in there (e.g.
        /// STANDARD_IA, GLACIER_IR), rather than the service's default.
        #[arg(long)]
        remote_class: Option<String>,
    },
    /// Change a tier: its credentials, the storage class new objects are
    /// written in there, or whether this cluster may write to it and
    /// delete from it (a restored cluster's tiers are read-only, since the
    /// old cluster may still use them).
    Set {
        name: String,
        #[arg(long)]
        writable: Option<bool>,
        /// The storage class new objects are written in there; `default`
        /// for the service's default.
        #[arg(long)]
        remote_class: Option<String>,
        #[arg(long, requires = "secret_access_key")]
        access_key_id: Option<String>,
        #[arg(long, requires = "access_key_id", hide_env_values = true)]
        secret_access_key: Option<String>,
    },
    /// Delete a tier that no class keeps its data in, and that holds
    /// nothing anymore.
    Delete { name: String },
}

/// Where a tier is, as the CLI takes it.
#[derive(Args, Debug, Clone, Serialize, Deserialize)]
pub struct TierLocationArgs {
    /// The S3 service's URL, e.g. https://s3.eu-central-1.amazonaws.com.
    #[arg(long)]
    pub endpoint: String,
    /// Its region, which requests are signed for.
    #[arg(long, default_value = "us-east-1")]
    pub region: String,
    #[arg(long)]
    pub bucket: String,
    /// Where in the bucket: a prefix of its own.
    #[arg(long, default_value = "")]
    pub prefix: String,
    /// Name the bucket in the path (host/bucket/key) rather than the host
    /// (bucket.host/key), as most services other than AWS need.
    #[arg(long)]
    pub path_style: bool,
    #[arg(long, env = "CAIRN_TIER_ACCESS_KEY_ID")]
    pub access_key_id: String,
    #[arg(long, env = "CAIRN_TIER_SECRET_ACCESS_KEY", hide_env_values = true)]
    pub secret_access_key: String,
}

/// A `--remote-class`: one a tier can read its objects back from.
fn remote_class_arg(class: &str) -> anyhow::Result<Option<String>> {
    if class == "default" {
        return Ok(None);
    }
    anyhow::ensure!(
        crate::classes::valid_name(class),
        "--remote-class must be a storage class's name, such as STANDARD_IA"
    );
    anyhow::ensure!(
        !COLD_CLASSES.contains(&class),
        "{class} can't be a tier's class: its objects can't be read without restoring them first, \
         which tiers can't do yet"
    );
    Ok(Some(class.to_owned()))
}

/// `cairn tier …`, on a node (see `admin`).
pub async fn run(app: &Arc<App>, args: TierArgs, out: &mut Output) -> anyhow::Result<()> {
    let client = app.pool.get().await?;
    match args.command {
        TierCommand::List => {
            let rows = client
                .query_cached(
                    "SELECT t.name, t.endpoint, t.bucket, t.prefix, t.remote_class, t.writable,
                            (SELECT count(*) FROM tier_blobs tb WHERE tb.tier = t.name),
                            (SELECT coalesce(sum(b.size - b.dead_size), 0)::bigint FROM tier_blobs tb
                             JOIN blobs b ON b.blob_id = tb.blob_id WHERE tb.tier = t.name AND b.state = 'remote'),
                            (SELECT count(*) FROM tier_garbage g WHERE g.tier = t.name),
                            (SELECT string_agg(c.name, ',' ORDER BY c.name) FROM storage_classes c WHERE c.tier = t.name)
                     FROM tiers t ORDER BY t.name",
                    &[],
                )
                .await?;
            if rows.is_empty() {
                outln!(out, "no tiers (cairn tier add)");
            }
            for r in rows {
                let (name, endpoint, bucket, prefix): (String, String, String, String) =
                    (r.get(0), r.get(1), r.get(2), r.get(3));
                let remote: Option<String> = r.get(4);
                let writable: bool = r.get(5);
                let (objects, bytes, garbage): (i64, i64, i64) = (r.get(6), r.get(7), r.get(8));
                let classes: Option<String> = r.get(9);
                outln!(
                    out,
                    "{name}: s3://{bucket}/{prefix} at {endpoint}{}{}",
                    remote.map(|c| format!(", as {c}")).unwrap_or_default(),
                    if writable { "" } else { ", read-only" }
                );
                outln!(
                    out,
                    "  classes: {}; {objects} objects, {bytes} bytes live; {garbage} objects to delete",
                    classes.unwrap_or_else(|| "none".into())
                );
            }
        }
        TierCommand::Add { name, location, remote_class } => {
            anyhow::ensure!(
                valid_name(&name),
                "a tier's name is up to 32 lowercase letters, digits, - and _, starting with a letter or digit"
            );
            let remote_class = remote_class.as_deref().map(remote_class_arg).transpose()?.flatten();
            let location = Location {
                endpoint: location.endpoint,
                region: location.region,
                bucket: location.bucket,
                prefix: location.prefix,
                path_style: location.path_style,
                access_key_id: location.access_key_id,
                secret_access_key: location.secret_access_key,
            }
            .normalized()?;
            let exists = client.query_opt_cached("SELECT 1 FROM tiers WHERE name = $1", &[&name]).await?.is_some();
            anyhow::ensure!(!exists, "there's a tier {name} already");
            let target = Target::new(location.clone())?;
            target.check().await.map_err(|e| e.context(format!("reaching {}", location.describe())))?;
            anyhow::ensure!(
                target.list("").await?.is_empty(),
                "{} holds objects already: a tier needs a prefix of its own",
                location.describe()
            );
            let others = load(&client).await?;
            anyhow::ensure!(
                !others.values().any(|t| t.location.endpoint == location.endpoint
                    && t.location.bucket == location.bucket
                    && t.location.prefix == location.prefix),
                "another tier is at {} already",
                location.describe()
            );
            let mut key = [0u8; 32];
            getrandom::fill(&mut key).expect("the OS random number generator failed");
            client
                .execute_cached(
                    "INSERT INTO tiers (name, endpoint, region, bucket, prefix, path_style, access_key_id,
                                        secret_access_key, key, remote_class)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                    &[
                        &name,
                        &location.endpoint,
                        &location.region,
                        &location.bucket,
                        &location.prefix,
                        &location.path_style,
                        &location.access_key_id,
                        &location.secret_access_key,
                        &key.to_vec(),
                        &remote_class,
                    ],
                )
                .await?;
            outln!(out, "tier {name}: s3://{}/{} at {}", location.bucket, location.prefix, location.endpoint);
            outln!(
                out,
                "key: {} (it's in the database, and in its backup: only needed if both are lost)",
                base64::engine::general_purpose::STANDARD.encode(key)
            );
            outln!(out, "keep a class's data there with: cairn class set <class> --tier {name}");
        }
        TierCommand::Set { name, writable, remote_class, access_key_id, secret_access_key } => {
            let tiers = load(&client).await?;
            let Some(tier) = tiers.get(&name) else { anyhow::bail!("there's no tier {name}") };
            let class_given = remote_class.is_some();
            let remote_class = remote_class.as_deref().map(remote_class_arg).transpose()?.flatten();
            if let (Some(id), Some(secret)) = (&access_key_id, &secret_access_key) {
                let location = Location {
                    access_key_id: id.clone(),
                    secret_access_key: secret.clone(),
                    ..tier.location.clone()
                };
                Target::new(location.clone())?
                    .check()
                    .await
                    .map_err(|e| e.context(format!("reaching {} with the new credentials", location.describe())))?;
            }
            client
                .execute_cached(
                    "UPDATE tiers SET writable = coalesce($2, writable),
                         remote_class = CASE WHEN $3 THEN $4 ELSE remote_class END,
                         access_key_id = coalesce($5, access_key_id),
                         secret_access_key = coalesce($6, secret_access_key)
                     WHERE name = $1",
                    &[&name, &writable, &class_given, &remote_class, &access_key_id, &secret_access_key],
                )
                .await?;
            if writable == Some(true) && !tier.writable {
                out.warn(format!(
                    "{name} is writable now: this cluster deletes the objects there it doesn't need, \
                     which another cluster restored from the same backup (or the one this was restored from) \
                     may still need"
                ));
            }
            let tier = load(&client).await?.remove(&name).expect("it was there");
            outln!(
                out,
                "tier {name}: {}{}",
                tier.remote_class.map(|c| format!("objects written as {c}, ")).unwrap_or_default(),
                if tier.writable { "writable" } else { "read-only" }
            );
        }
        TierCommand::Delete { name } => {
            let deleted = client
                .execute_cached(
                    "DELETE FROM tiers t WHERE t.name = $1
                       AND NOT EXISTS (SELECT 1 FROM storage_classes c WHERE c.tier = t.name)
                       AND NOT EXISTS (SELECT 1 FROM tier_blobs b WHERE b.tier = t.name)
                       AND NOT EXISTS (SELECT 1 FROM tier_garbage g WHERE g.tier = t.name)",
                    &[&name],
                )
                .await?;
            if deleted == 0 {
                let exists = client.query_opt_cached("SELECT 1 FROM tiers WHERE name = $1", &[&name]).await?.is_some();
                anyhow::bail!(match exists {
                    true => format!(
                        "{name} still has classes, or holds objects (or ones still to delete): \
                         point its classes elsewhere, and wait for its data to move"
                    ),
                    false => format!("there's no tier {name}"),
                });
            }
            outln!(out, "deleted tier {name}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod e2e;
