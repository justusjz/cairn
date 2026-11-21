//! Restoring a cluster from its backup, into a new, empty database.
//!
//! `cairn restore` loads the database: it migrates it to the schema the
//! backup's base was taken at, loads the base, replays the journals after
//! it (up to `--at`, if given), and then lays the data out anew. Every part's
//! bytes are still in the backup's objects at that point: each object (one
//! per storage class of the parts in it) becomes a blob in the state
//! `restoring`, which no node holds (`restore_blobs` says which object of
//! the backup it is), and its parts point into it. Then the rest of the
//! migrations run, as on any upgrade.
//!
//! Then the nodes start, as usual, against that database. The objects are
//! readable at once: a read of a restoring blob reads the backup's object
//! ([`stream`]). Meanwhile every node's restorer ([`run`]) copies the
//! restoring blobs into the cluster, a blob at a time: as a packing job, whose
//! source is the backup's object rather than a blob of the cluster (see
//! `packer`), so that the parts' bytes are checked against their checksums
//! before they move. Once none is left, the restore is done.
//!
//! A part whose bytes the backup lacks (it was deleted right after the last
//! journal, or lost in the cluster before it was backed up) is lost: its
//! bytes are a blob of their own, whose `lost_ranges` keep reads off them.
//!
//! Parts in a tier (see `tiers`) aren't in the backup: it points them at
//! the tier's objects, which become remote blobs again, as they were, and
//! stay in the tier. The tiers are read-only (unless `--writable-tiers`),
//! since the old cluster may still be using them.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use clap::Args;
use deadpool_postgres::GenericClient;
use deadpool_postgres::Transaction;
use futures_util::SinkExt;
use hyper::body::{Bytes, Frame};
use uuid::Uuid;

use super::LocationArgs;
use super::capture::{self, quote};
use super::crypt::{self, ObjectReader};
use super::format::{self, BaseManifest, JournalMeta};
use super::s3::{Location, Target};
use crate::App;
use crate::admin::{Output, outln};
use crate::body::FrameSender;
use crate::db::Cached;

/// `cairn restore`.
#[derive(Args, Debug)]
pub struct RestoreArgs {
    /// The new cluster's database: an empty one.
    #[arg(long, env = "CAIRN_DATABASE", hide_env_values = true)]
    pub database: String,
    #[command(flatten)]
    pub location: LocationArgs,
    /// The backup's key (base64), as `cairn backup enable` printed it.
    /// Without it, the key is read from the backup, wrapped by the KMS's
    /// root key, which the KMS flags give (the old cluster's).
    #[arg(long, env = "CAIRN_BACKUP_KEY", hide_env_values = true)]
    pub key: Option<String>,
    #[command(flatten)]
    pub kms: crate::kms::KmsArgs,
    /// Restore the cluster as it was at this time (e.g. 2026-11-18T09:30:00Z,
    /// or Unix seconds), rather than the latest.
    #[arg(long, value_parser = parse_time)]
    pub at: Option<i64>,
    /// Only list what the backup can be restored to.
    #[arg(long)]
    pub list: bool,
    /// Let the new cluster write to the tiers it keeps data in, and delete
    /// what it doesn't need from them. Only once the old cluster is gone
    /// for good: it may need what this one deletes. (`cairn tier set
    /// <name> --writable true` does it later.)
    #[arg(long)]
    pub writable_tiers: bool,
}

/// `2026-11-18T09:30:00Z` (or with an offset, `+01:00`), or Unix seconds:
/// Unix milliseconds.
pub fn parse_time(text: &str) -> Result<i64, String> {
    let text = text.trim();
    if let Ok(secs) = text.parse::<i64>() {
        return Ok(secs * 1000);
    }
    let bad = || format!("{text:?} isn't a time such as 2026-11-18T09:30:00Z");
    let (stamp, offset) = if let Some(stamp) = text.strip_suffix('Z') {
        (stamp, 0)
    } else if text.len() > 6 && matches!(text.as_bytes()[text.len() - 6], b'+' | b'-') {
        let (stamp, zone) = text.split_at(text.len() - 6);
        let sign = if zone.starts_with('-') { -1 } else { 1 };
        let (h, m) = zone[1..].split_once(':').ok_or_else(bad)?;
        let minutes =
            h.parse::<i64>().map_err(|_| bad())? * 60 + m.parse::<i64>().map_err(|_| bad())?;
        (stamp, sign * minutes * 60)
    } else {
        return Err(bad());
    };
    let compact: String = stamp.chars().filter(|c| *c != '-' && *c != ':').collect();
    let secs = crate::auth::parse_amz_date(&format!("{compact}Z")).ok_or_else(bad)?;
    Ok((secs - offset) * 1000)
}

fn format_time(millis: i64) -> String {
    let secs = millis.div_euclid(1000);
    let day = crate::auth::day_of(secs);
    let t = secs.rem_euclid(86_400);
    format!(
        "{}-{}-{}T{:02}:{:02}:{:02}Z",
        &day[..4],
        &day[4..6],
        &day[6..],
        t / 3600,
        t / 60 % 60,
        t % 60
    )
}

/// Whether the transaction `xid` is visible in `snapshot`
/// (`pg_current_snapshot()`'s text): it had committed when the snapshot was
/// taken.
pub fn visible(xid: u64, snapshot: &str) -> anyhow::Result<bool> {
    let mut fields = snapshot.split(':');
    let (Some(xmin), Some(xmax), Some(xip)) = (fields.next(), fields.next(), fields.next()) else {
        anyhow::bail!("{snapshot:?} isn't a snapshot");
    };
    let (xmin, xmax): (u64, u64) = (xmin.parse()?, xmax.parse()?);
    if xid < xmin {
        return Ok(true);
    }
    if xid >= xmax {
        return Ok(false);
    }
    Ok(!xip
        .split(',')
        .filter(|s| !s.is_empty())
        .any(|s| s.parse() == Ok(xid)))
}

/// The objects of a backup, as listed.
struct Listing {
    bases: Vec<(i64, Uuid, String)>,
    journals: BTreeMap<i64, Vec<(Uuid, String)>>,
    /// Every object's plaintext size, by name.
    sizes: HashMap<String, u64>,
}

async fn listing(target: &Target) -> anyhow::Result<Listing> {
    let mut listing = Listing {
        bases: Vec::new(),
        journals: BTreeMap::new(),
        sizes: HashMap::new(),
    };
    for (name, stored) in target.list("").await? {
        let Some(plain) = crypt::plain_len(stored) else {
            continue;
        };
        if name.starts_with("base/") {
            if let Some((seq, id)) = format::parse_manifest(&name) {
                listing.bases.push((seq, id, name.clone()));
            }
        } else if name.starts_with("journal/")
            && let Some((seq, id)) = format::parse_name(&name)
        {
            listing
                .journals
                .entry(seq)
                .or_default()
                .push((id, name.clone()));
        }
        listing.sizes.insert(name, plain);
    }
    listing.bases.sort();
    Ok(listing)
}

/// Reads a decrypted object in the background, a chunk at a time.
fn read_object(
    target: Target,
    key: [u8; 32],
    name: String,
    plain: u64,
) -> tokio::sync::mpsc::Receiver<anyhow::Result<Bytes>> {
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        let reader = ObjectReader::new(&target, &key, &name, plain);
        let result = async {
            let mut range = reader.range(0, plain, 16 << 20).await?;
            while let Some(pieces) = range.next().await? {
                for piece in pieces {
                    tx.send(Ok(piece))
                        .await
                        .map_err(|_| anyhow::anyhow!("the reader went away"))?;
                }
            }
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = result {
            let _ = tx.send(Err(e)).await;
        }
    });
    rx
}

/// The lines of a base, decompressed as they're read.
struct Lines {
    rx: tokio::sync::mpsc::Receiver<anyhow::Result<Bytes>>,
    gz: Option<flate2::write::GzDecoder<Vec<u8>>>,
    buf: Vec<u8>,
    pos: usize,
}

impl Lines {
    fn new(rx: tokio::sync::mpsc::Receiver<anyhow::Result<Bytes>>) -> Lines {
        Lines {
            rx,
            gz: Some(flate2::write::GzDecoder::new(Vec::new())),
            buf: Vec::new(),
            pos: 0,
        }
    }

    /// Reads more; false at the end.
    async fn fill(&mut self) -> anyhow::Result<bool> {
        use std::io::Write;
        let Some(gz) = self.gz.as_mut() else {
            return Ok(false);
        };
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        match self.rx.recv().await {
            Some(chunk) => {
                gz.write_all(&chunk?)?;
                self.buf.append(gz.get_mut());
            }
            None => {
                let rest = self.gz.take().unwrap().finish()?;
                self.buf.extend_from_slice(&rest);
            }
        }
        Ok(true)
    }

    /// The next line, without its newline.
    async fn line(&mut self) -> anyhow::Result<Option<Vec<u8>>> {
        loop {
            if let Some(n) = self.buf[self.pos..].iter().position(|&b| b == b'\n') {
                let line = self.buf[self.pos..self.pos + n].to_vec();
                self.pos += n + 1;
                return Ok(Some(line));
            }
            if !self.fill().await? {
                return Ok(None);
            }
        }
    }

    /// Hands the lines of a table (through the line `\.`) to `each`, in
    /// chunks of whole lines.
    async fn section<F>(&mut self, mut each: F) -> anyhow::Result<()>
    where
        F: AsyncFnMut(Bytes) -> anyhow::Result<()>,
    {
        loop {
            let mut end = None;
            let mut cut = self.pos;
            let mut at = self.pos;
            while let Some(n) = self.buf[at..].iter().position(|&b| b == b'\n') {
                if &self.buf[at..at + n] == b"\\." {
                    end = Some(at + n + 1);
                    break;
                }
                at += n + 1;
                cut = at;
            }
            if cut > self.pos {
                each(Bytes::copy_from_slice(&self.buf[self.pos..cut])).await?;
                self.pos = cut;
            }
            if let Some(end) = end {
                self.pos = end;
                return Ok(());
            }
            anyhow::ensure!(
                self.fill().await?,
                "the base ended in the middle of a table"
            );
        }
    }
}

/// Reads the metadata at the end of an object (a journal's, a pack's, or a
/// base's manifest).
async fn read_meta<T: serde::de::DeserializeOwned>(
    target: &Target,
    key: &[u8; 32],
    name: &str,
    plain: u64,
) -> anyhow::Result<T> {
    let reader = ObjectReader::new(target, key, name, plain);
    anyhow::ensure!(plain >= format::TRAILER, "{name} is too short");
    let trailer = reader.read_all(plain - format::TRAILER, plain).await?;
    let len = format::trailer_len(&trailer)?;
    let start = (plain - format::TRAILER)
        .checked_sub(len)
        .ok_or_else(|| anyhow::anyhow!("{name}: its trailer is wrong"))?;
    let meta = reader.read_all(start, plain - format::TRAILER).await?;
    format::open_meta(&meta)
}

async fn journal_meta(
    target: &Target,
    key: &[u8; 32],
    name: &str,
    plain: u64,
) -> anyhow::Result<JournalMeta> {
    read_meta(target, key, name, plain).await
}

/// What a restore restores to: a base, and the journals after it.
struct Plan {
    base: BaseManifest,
    /// The journals' names, and when each was taken.
    journals: Vec<(String, i64)>,
    /// The journals after those (after the time restored to, or not
    /// complete), whose changes aren't replayed, but whose records of where
    /// parts' bytes are count all the same: a part's ID always means the
    /// same bytes, wherever they've been copied to since (the backlog of
    /// what was there before the backup, a pack at a time, packing, rewrites).
    later: Vec<String>,
}

/// What a restore needs to know of a journal to pick it (its changes are
/// read again when they're replayed, a journal at a time).
#[derive(Clone)]
struct JournalInfo {
    id: Uuid,
    seq: i64,
    prev: Option<Uuid>,
    version: i32,
    time: i64,
    complete: bool,
}

async fn journal_info(
    target: &Target,
    key: &[u8; 32],
    name: &str,
    plain: u64,
) -> anyhow::Result<JournalInfo> {
    let meta = journal_meta(target, key, name, plain).await?;
    Ok(JournalInfo {
        id: meta.id,
        seq: meta.seq,
        prev: meta.prev,
        version: meta.version,
        time: meta.time,
        complete: meta.complete,
    })
}

/// The chain of journals after journal `after` (whose ID is `prev`), as
/// long as `fits` takes them. Of two with the same number (a node that lost
/// its lease wrote one), the one the chain goes on from is taken, else the
/// later.
async fn follow(
    target: &Target,
    key: &[u8; 32],
    listing: &Listing,
    infos: &mut HashMap<String, JournalInfo>,
    after: i64,
    mut prev: Option<Uuid>,
    fits: impl Fn(&JournalInfo) -> bool,
) -> anyhow::Result<Vec<(String, JournalInfo)>> {
    let mut journals: Vec<(String, JournalInfo)> = Vec::new();
    let mut next = after + 1;
    while let Some(candidates) = listing.journals.get(&next) {
        let mut fitting: Vec<(String, JournalInfo)> = Vec::new();
        for (_, name) in candidates {
            if !infos.contains_key(name) {
                infos.insert(
                    name.clone(),
                    journal_info(target, key, name, listing.sizes[name]).await?,
                );
            }
            let info = &infos[name];
            if info.prev == prev && fits(info) {
                fitting.push((name.clone(), info.clone()));
            }
        }
        let (chosen, info) = match fitting.len() {
            0 => break,
            1 => fitting.pop().unwrap(),
            _ => {
                // The one a journal after it follows, else the later.
                let mut followed = None;
                for (_, name) in listing.journals.get(&(next + 1)).into_iter().flatten() {
                    let after = journal_info(target, key, name, listing.sizes[name]).await?;
                    followed = fitting
                        .iter()
                        .find(|(_, info)| Some(info.id) == after.prev)
                        .cloned()
                        .or(followed);
                }
                followed.unwrap_or_else(|| {
                    fitting
                        .iter()
                        .max_by_key(|(_, info)| info.time)
                        .unwrap()
                        .clone()
                })
            }
        };
        prev = Some(info.id);
        journals.push((chosen, info));
        next += 1;
    }
    Ok(journals)
}

/// Picks the latest complete base (by `at`, if given) that a journal
/// follows, and the chain of journals after it, up to the last that shipped
/// all it could (by `at`): a moment the cluster was consistent at. A base
/// is restorable only with a journal after it was complete, since its
/// chunks are of different moments. Of two journals with the same number (a
/// node that lost its lease wrote one), the one the chain goes on from is
/// taken, else the later.
async fn plan(
    target: &Target,
    key: &[u8; 32],
    listing: &Listing,
    at: Option<i64>,
) -> anyhow::Result<Plan> {
    let mut fallback = None;
    let mut infos: HashMap<String, JournalInfo> = HashMap::new();
    for (seq, _, name) in listing.bases.iter().rev() {
        let base: BaseManifest = read_meta(target, key, name, listing.sizes[name]).await?;
        if at.is_some_and(|at| base.time > at) {
            continue;
        }
        let mut journals = follow(
            target,
            key,
            listing,
            &mut infos,
            *seq,
            base.after_id,
            |info| info.version == base.version && at.is_none_or(|at| info.time <= at),
        )
        .await?;
        // Up to the last that shipped all it could.
        while journals.last().is_some_and(|(_, info)| !info.complete) {
            journals.pop();
        }
        let ready = journals
            .last()
            .is_some_and(|(_, info)| info.seq > base.ready_after);
        let (after, prev) = journals
            .last()
            .map_or((*seq, base.after_id), |(_, info)| (info.seq, Some(info.id)));
        let later = follow(target, key, listing, &mut infos, after, prev, |_| true)
            .await?
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        let plan = Plan {
            base,
            journals: journals
                .into_iter()
                .map(|(name, info)| (name, info.time))
                .collect(),
            later,
        };
        if ready {
            return Ok(plan);
        }
        fallback.get_or_insert(plan);
    }
    match fallback {
        Some(plan) => {
            eprintln!(
                "warning: no journal follows the base since it was complete, so it may be inconsistent, and \
                 parts written just before it may be missing"
            );
            Ok(plan)
        }
        None => anyhow::bail!(
            "{} holds no base to restore{}",
            target.location.describe(),
            match at {
                Some(at) => format!(" from by {}", format_time(at)),
                None => String::new(),
            }
        ),
    }
}

/// The backup's key, from the backup (`backup::WRAPPED_KEY`), unwrapped by
/// the KMS's root key that `kms` gives.
async fn wrapped_key(target: &Target, kms: &crate::kms::KmsArgs) -> anyhow::Result<[u8; 32]> {
    let kms = crate::kms::Kms::new(kms)?.ok_or_else(|| {
        anyhow::anyhow!(
            "give the backup's key (--key), or the KMS's root key it's wrapped by \
             (--kms-root-key-file, or --kms-address)"
        )
    })?;
    let name = crate::backup::WRAPPED_KEY;
    let size = target.size(name).await?.ok_or_else(|| {
        anyhow::anyhow!("the backup has no wrapped key ({name}): give its key (--key)")
    })?;
    let wrapped = target.get_range(name, 0, size).await?;
    let key = crate::kms::StoredKey::Wrapped(wrapped.to_vec())
        .open(Some(&kms), crate::kms::BACKUP_KEY_AD)
        .await?;
    Ok(*key)
}

/// Runs `cairn restore`.
pub async fn restore_main(args: RestoreArgs) -> anyhow::Result<()> {
    let location = args.location.location()?;
    let target = Target::new(location.clone())?;
    let key: [u8; 32] = match &args.key {
        Some(key) => base64::engine::general_purpose::STANDARD
            .decode(key.trim())
            .map_err(|_| anyhow::anyhow!("the key must be base64"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("the key must be 32 bytes"))?,
        None => wrapped_key(&target, &args.kms).await?,
    };
    let listing = listing(&target).await?;
    if args.list {
        for (seq, _, name) in &listing.bases {
            let base: BaseManifest = read_meta(&target, &key, name, listing.sizes[name]).await?;
            println!(
                "base after journal {seq}, complete after journal {}: {} (schema {}, {} chunks)",
                base.ready_after,
                format_time(base.time),
                base.version,
                base.chunks.len()
            );
        }
        if let (Some((first, _)), Some((last, names))) = (
            listing.journals.first_key_value(),
            listing.journals.last_key_value(),
        ) {
            let meta = journal_meta(&target, &key, &names[0].1, listing.sizes[&names[0].1]).await?;
            println!(
                "journals {first} to {last}, the last at {}",
                format_time(meta.time)
            );
        }
        return Ok(());
    }
    let plan = plan(&target, &key, &listing, args.at).await?;
    let restored_to = plan
        .journals
        .last()
        .map_or(plan.base.time, |(_, time)| *time);
    eprintln!(
        "restoring to {} (schema {}): the base after journal {} and {} journals",
        format_time(restored_to),
        plan.base.version,
        plan.base.after,
        plan.journals.len()
    );
    anyhow::ensure!(
        plan.base.version as usize <= crate::db::schema_version() as usize,
        "the backup is of schema {}, newer than this Cairn knows: restore with a newer Cairn",
        plan.base.version
    );

    // An empty database, or one a restore that failed left migrated.
    {
        let (client, connection) =
            tokio_postgres::connect(&args.database, tokio_postgres::NoTls).await?;
        tokio::spawn(connection);
        let migrated: bool = client
            .query_one("SELECT to_regclass('schema_migrations') IS NOT NULL", &[])
            .await?
            .get(0);
        if migrated {
            let version: i32 = client
                .query_one(
                    "SELECT coalesce(max(version), 0) FROM schema_migrations",
                    &[],
                )
                .await?
                .get(0);
            let restoring: bool = client
                .query_one(
                    "SELECT to_regclass('restore_source') IS NOT NULL
                       AND EXISTS (SELECT 1 FROM restore_source WHERE state = 'loading')",
                    &[],
                )
                .await
                .map(|r| r.get(0))
                .unwrap_or(false);
            anyhow::ensure!(
                restoring && version == plan.base.version,
                "the database isn't empty: restore into a new database"
            );
        }
    }
    let pool = crate::db::connect_through(&args.database, plan.base.version as usize).await?;
    pool.get()
        .await?
        .execute(
            "INSERT INTO restore_source (endpoint, region, bucket, prefix, path_style, access_key_id,
                                         secret_access_key, key, state)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'loading')
             ON CONFLICT (id) DO UPDATE SET endpoint = $1, region = $2, bucket = $3, prefix = $4,
                 path_style = $5, access_key_id = $6, secret_access_key = $7, key = $8, state = 'loading'",
            &[
                &location.endpoint,
                &location.region,
                &location.bucket,
                &location.prefix,
                &location.path_style,
                &location.access_key_id,
                &location.secret_access_key,
                &key.to_vec(),
            ],
        )
        .await?;
    let summary = {
        let mut client = pool.get().await?;
        let tx = client.transaction().await?;
        let summary = load(
            &tx,
            &target,
            &key,
            &listing,
            &plan,
            restored_to,
            args.writable_tiers,
        )
        .await?;
        tx.commit().await?;
        summary
    };
    drop(pool);
    // The rest of the migrations, as on an upgrade.
    crate::db::connect(&args.database).await?;
    println!(
        "restored {} parts ({} bytes) in {} objects of the backup, to {}",
        summary.parts,
        summary.bytes,
        summary.blobs,
        format_time(restored_to)
    );
    if summary.remote > 0 {
        println!(
            "{} objects of tiers are read from where they are{}",
            summary.remote,
            if args.writable_tiers {
                ""
            } else {
                ", and the tiers are read-only: once the old cluster is gone for good, \
                 `cairn tier set <name> --writable true` gives them to this one"
            }
        );
    }
    if summary.lost > 0 {
        println!(
            "warning: the backup lacks the bytes of {} parts, which are lost",
            summary.lost
        );
    }
    println!(
        "now start the nodes on this database: the data is readable at once, from the backup, and copied into \
         the cluster in the background (cairn backup status shows how far)"
    );
    Ok(())
}

#[derive(Default)]
struct Summary {
    parts: i64,
    bytes: i64,
    blobs: i64,
    lost: i64,
    /// Remote blobs: objects of tiers.
    remote: i64,
}

/// A table's changes being replayed, run by run.
struct Replay<'a> {
    tables: HashMap<String, capture::Table>,
    /// Each table's slices in the base, in order: the key each ends at, and
    /// the snapshot it was read in.
    slices: HashMap<String, Vec<(Option<String>, String)>>,
    tx: &'a Transaction<'a>,
}

/// A change to replay: its transaction, the row's key, and the row.
type Row = (u64, Option<String>, Option<String>);

/// What a change does to its row.
#[derive(PartialEq, Clone, Copy)]
enum Kind {
    Upsert,
    Delete,
    Truncate,
}

impl Replay<'_> {
    /// The changes of `rows` that the base doesn't hold already: those of
    /// transactions its row's slice didn't see.
    async fn unseen(
        &self,
        info: &capture::Table,
        kind: Kind,
        rows: Vec<Row>,
    ) -> anyhow::Result<Vec<Row>> {
        let Some(slices) = self.slices.get(&info.name) else {
            return Ok(rows);
        };
        let slice_of: Vec<usize> =
            if slices.len() == 1 || info.key.is_none() || kind == Kind::Truncate {
                vec![0; rows.len()]
            } else {
                let keys: Vec<Option<String>> =
                    rows.iter().map(|(_, key, _)| key.clone()).collect();
                let uppers: Vec<Option<String>> =
                    slices.iter().map(|(upper, _)| upper.clone()).collect();
                let statement = format!(
                    "SELECT (SELECT min(s.i) FROM unnest($2::text[]) WITH ORDINALITY AS s(upper, i)
                         WHERE s.upper IS NULL OR {} <= {})::bigint
                 FROM unnest($1::text[]) WITH ORDINALITY AS u(k, n) ORDER BY u.n",
                    info.key_of("u.k::jsonb"),
                    info.key_of("s.upper::jsonb")
                );
                self.tx
                    .query(&statement, &[&keys, &uppers])
                    .await?
                    .iter()
                    .map(|r| {
                        r.get::<_, Option<i64>>(0)
                            .map_or(slices.len() - 1, |i| i as usize - 1)
                    })
                    .collect()
            };
        let mut unseen = Vec::with_capacity(rows.len());
        for (row, slice) in rows.into_iter().zip(slice_of) {
            if !visible(row.0, &slices[slice].1)? {
                unseen.push(row);
            }
        }
        Ok(unseen)
    }

    /// Applies a run of changes of one kind to one table, but those the base
    /// holds already; how many it applied.
    async fn apply(&self, table: &str, kind: Kind, rows: Vec<Row>) -> anyhow::Result<usize> {
        let info = self.tables.get(table).ok_or_else(|| {
            anyhow::anyhow!("the backup has changes of a table {table} that this schema hasn't")
        })?;
        let key_types = &info.key_types();
        let rows: Vec<(Option<String>, Option<String>)> = self
            .unseen(info, kind, rows)
            .await?
            .into_iter()
            .map(|(_, key, row)| (key, row))
            .collect();
        let applied = rows.len();
        if applied == 0 {
            return Ok(0);
        }
        let t = quote(table);
        match kind {
            Kind::Truncate => {
                self.tx.batch_execute(&format!("TRUNCATE {t}")).await?;
            }
            Kind::Delete => match &info.key {
                Some(cols) => {
                    let mut keys: Vec<String> = rows.into_iter().filter_map(|(k, _)| k).collect();
                    keys.sort();
                    keys.dedup();
                    let picked = cols
                        .iter()
                        .zip(key_types)
                        .enumerate()
                        .map(|(i, (_, ty))| format!("(j->>{i})::{ty}"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let cols = cols.iter().map(|c| quote(c)).collect::<Vec<_>>().join(", ");
                    self.tx
                        .execute(
                            &format!(
                                "DELETE FROM {t} WHERE ({cols}) IN (
                                     SELECT {picked} FROM unnest($1::text[]) AS u(k), LATERAL (SELECT k::jsonb AS j) AS x)"
                            ),
                            &[&keys],
                        )
                        .await?;
                }
                None => {
                    let statement = format!(
                        "DELETE FROM {t} WHERE ctid = (SELECT ctid FROM {t} x WHERE x::text = $1 LIMIT 1)"
                    );
                    for (_, row) in rows {
                        self.tx.execute(&statement, &[&row]).await?;
                    }
                }
            },
            Kind::Upsert => {
                // Of the upserts of a row in a run, the last is what counts.
                let mut images: Vec<String> = Vec::new();
                match &info.key {
                    Some(_) => {
                        let mut last: HashMap<String, usize> = HashMap::new();
                        let rows: Vec<(Option<String>, Option<String>)> = rows;
                        for (i, (key, _)) in rows.iter().enumerate() {
                            last.insert(key.clone().unwrap_or_default(), i);
                        }
                        for (i, (key, row)) in rows.into_iter().enumerate() {
                            if last[&key.unwrap_or_default()] == i {
                                images.extend(row);
                            }
                        }
                    }
                    None => images.extend(rows.into_iter().filter_map(|(_, row)| row)),
                }
                let writable: Vec<&String> = info
                    .columns
                    .iter()
                    .filter(|(_, generated)| !generated)
                    .map(|(c, _)| c)
                    .collect();
                let cols = writable
                    .iter()
                    .map(|c| quote(c))
                    .collect::<Vec<_>>()
                    .join(", ");
                let values = writable
                    .iter()
                    .map(|c| format!("(s.r).{}", quote(c)))
                    .collect::<Vec<_>>()
                    .join(", ");
                let overriding = if info.identity {
                    "OVERRIDING SYSTEM VALUE"
                } else {
                    ""
                };
                let conflict = match &info.key {
                    Some(key) => {
                        let rest: Vec<String> = writable
                            .iter()
                            .filter(|c| !key.contains(c))
                            .map(|c| format!("{q} = EXCLUDED.{q}", q = quote(c)))
                            .collect();
                        let key = key.iter().map(|c| quote(c)).collect::<Vec<_>>().join(", ");
                        if rest.is_empty() {
                            format!("ON CONFLICT ({key}) DO NOTHING")
                        } else {
                            format!("ON CONFLICT ({key}) DO UPDATE SET {}", rest.join(", "))
                        }
                    }
                    None => String::new(),
                };
                let statement = format!(
                    "INSERT INTO {t} ({cols}) {overriding}
                     SELECT {values} FROM (SELECT u::{t} AS r FROM unnest($1::text[]) WITH ORDINALITY AS x(u, n) ORDER BY n) AS s
                     {conflict}"
                );
                // All at once; if that runs into a unique index other than
                // the key's (a row taking a value another gave up within
                // the run), one at a time, in order.
                self.tx.batch_execute("SAVEPOINT replay").await?;
                match self.tx.execute(&statement, &[&images]).await {
                    Ok(_) => self.tx.batch_execute("RELEASE SAVEPOINT replay").await?,
                    Err(_) => {
                        self.tx
                            .batch_execute("ROLLBACK TO SAVEPOINT replay")
                            .await?;
                        for image in images {
                            self.tx.execute(&statement, &[&vec![image]]).await?;
                        }
                    }
                }
            }
        }
        Ok(applied)
    }

    /// Replays changes, in order, but those the base holds already.
    async fn changes(&self, changes: Vec<format::Change>) -> anyhow::Result<usize> {
        let mut applied = 0;
        let mut run: Option<(String, Kind)> = None;
        let mut rows = Vec::new();
        for (xid, table, op, key, row) in changes {
            let kind = match op.as_str() {
                "I" | "U" => Kind::Upsert,
                "D" => Kind::Delete,
                "T" => Kind::Truncate,
                other => anyhow::bail!("a change {other:?} of {table}"),
            };
            if run.as_ref() != Some(&(table.clone(), kind)) || kind == Kind::Truncate {
                if let Some((t, k)) = run.take() {
                    applied += self.apply(&t, k, std::mem::take(&mut rows)).await?;
                }
                run = Some((table, kind));
            }
            rows.push((xid, key, row));
        }
        if let Some((t, k)) = run {
            applied += self.apply(&t, k, rows).await?;
        }
        Ok(applied)
    }
}

/// Records where a journal says parts' bytes are (the last place of each
/// counts), and the objects they're in: those parts aren't lost after all.
async fn record_places(tx: &Transaction<'_>, meta: &JournalMeta) -> anyhow::Result<()> {
    let (ids, names, sizes): (Vec<Uuid>, Vec<String>, Vec<i64>) = meta
        .objects
        .iter()
        .map(|o| (o.id, o.name.clone(), o.size as i64))
        .fold(
            (Vec::new(), Vec::new(), Vec::new()),
            |(mut a, mut b, mut c), (x, y, z)| {
                a.push(x);
                b.push(y);
                c.push(z);
                (a, b, c)
            },
        );
    tx.execute(
        "INSERT INTO restore_objects (id, name, size) SELECT * FROM unnest($1::uuid[], $2::text[], $3::bigint[])
         ON CONFLICT (id) DO NOTHING",
        &[&ids, &names, &sizes],
    )
    .await?;
    let mut last: HashMap<i64, &format::PartRef> = HashMap::new();
    for part in &meta.parts {
        last.insert(part.0, part);
    }
    let parts: Vec<i64> = last.keys().copied().collect();
    let objects: Vec<Uuid> = parts.iter().map(|p| last[p].1).collect();
    let offsets: Vec<i64> = parts.iter().map(|p| last[p].2 as i64).collect();
    let sizes: Vec<i64> = parts.iter().map(|p| last[p].3 as i64).collect();
    let classes: Vec<String> = parts.iter().map(|p| last[p].4.clone()).collect();
    tx.execute(
        "INSERT INTO restore_map (part_id, object, \"offset\", size, class)
         SELECT * FROM unnest($1::bigint[], $2::uuid[], $3::bigint[], $4::bigint[], $5::text[])
         ON CONFLICT (part_id) DO UPDATE SET object = EXCLUDED.object, \"offset\" = EXCLUDED.\"offset\",
             size = EXCLUDED.size, class = EXCLUDED.class",
        &[&parts, &objects, &offsets, &sizes, &classes],
    )
    .await?;
    tx.execute(
        "DELETE FROM restore_lost WHERE part_id = ANY($1)",
        &[&parts],
    )
    .await?;
    Ok(())
}

/// Loads the database from the backup, in one transaction.
async fn load(
    tx: &Transaction<'_>,
    target: &Target,
    key: &[u8; 32],
    listing: &Listing,
    plan: &Plan,
    restored_to: i64,
    writable_tiers: bool,
) -> anyhow::Result<Summary> {
    tx.batch_execute(
        "SET LOCAL DateStyle = 'ISO, YMD'; SET LOCAL TimeZone = 'UTC'; SET LOCAL cairn.backup_capture = 'off';",
    )
    .await?;
    // Every table but the migrations' and this restore's, without triggers
    // or foreign keys while it's loaded (they're restored after).
    let all: Vec<String> = tx
        .query(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace ns ON ns.oid = c.relnamespace
             WHERE ns.nspname = 'public' AND c.relkind = 'r'
               AND c.relname NOT IN ('schema_migrations', 'restore_source')
             ORDER BY 1",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let foreign: Vec<(String, String, String)> = tx
        .query(
            "SELECT conrelid::regclass::text, conname, pg_get_constraintdef(oid) FROM pg_constraint
             WHERE contype = 'f' AND connamespace = 'public'::regnamespace",
            &[],
        )
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect();
    for (table, name, _) in &foreign {
        tx.batch_execute(&format!(
            "ALTER TABLE {table} DROP CONSTRAINT {}",
            quote(name)
        ))
        .await?;
    }
    for table in &all {
        tx.batch_execute(&format!(
            "ALTER TABLE {} DISABLE TRIGGER USER",
            quote(table)
        ))
        .await?;
    }
    let list = all.iter().map(|t| quote(t)).collect::<Vec<_>>().join(", ");
    tx.batch_execute(&format!("TRUNCATE {list}")).await?;
    tx.batch_execute(
        "INSERT INTO backup_state DEFAULT VALUES;
         CREATE TEMP TABLE restore_objects (id uuid PRIMARY KEY, name text NOT NULL, size bigint NOT NULL) ON COMMIT DROP;
         CREATE TEMP TABLE restore_map (part_id bigint PRIMARY KEY, object uuid NOT NULL, \"offset\" bigint NOT NULL,
                                        size bigint NOT NULL, class text NOT NULL) ON COMMIT DROP;
         CREATE TEMP TABLE restore_lost (part_id bigint PRIMARY KEY) ON COMMIT DROP;",
    )
    .await?;

    // The base, chunk by chunk.
    let mut slices: HashMap<String, Vec<(Option<String>, String)>> = HashMap::new();
    for chunk in &plan.base.chunks {
        let size = *listing
            .sizes
            .get(&chunk.name)
            .ok_or_else(|| anyhow::anyhow!("the base's chunk {} is missing", chunk.name))?;
        eprintln!("loading {}", chunk.name);
        let mut lines = Lines::new(read_object(target.clone(), *key, chunk.name.clone(), size));
        let header = lines
            .line()
            .await?
            .ok_or_else(|| anyhow::anyhow!("{} is empty", chunk.name))?;
        let header: format::ChunkHeader = serde_json::from_slice(&header)?;
        loop {
            let line = lines
                .line()
                .await?
                .ok_or_else(|| anyhow::anyhow!("{} ends early", chunk.name))?;
            if line == b"end" {
                break;
            }
            let section: format::Section = serde_json::from_slice(&line)?;
            let into = match section.table.as_str() {
                format::OBJECTS => "restore_objects".to_owned(),
                format::PARTS => "restore_map".to_owned(),
                table => quote(table),
            };
            let cols = section
                .columns
                .iter()
                .map(|c| quote(c))
                .collect::<Vec<_>>()
                .join(", ");
            let sink = tx
                .copy_in::<_, Bytes>(&format!("COPY {into} ({cols}) FROM STDIN"))
                .await?;
            let mut sink = std::pin::pin!(sink);
            lines
                .section(async |data: Bytes| {
                    sink.send(data).await?;
                    Ok(())
                })
                .await?;
            sink.as_mut().finish().await?;
            slices
                .entry(section.table)
                .or_default()
                .push((section.upper, header.snapshot.clone()));
        }
    }

    // The journals after it.
    let tables = capture::tables(tx).await?;
    let replay = Replay {
        tables: tables.into_iter().map(|t| (t.name.clone(), t)).collect(),
        slices,
        tx,
    };
    let mut sequences = plan.base.sequences.clone();
    for (name, _) in &plan.journals {
        let mut meta = journal_meta(target, key, name, listing.sizes[name]).await?;
        let changes = meta.changes.len();
        let applied = replay.changes(std::mem::take(&mut meta.changes)).await?;
        eprintln!(
            "replayed {name}: {applied} of {changes} changes, {} parts",
            meta.parts.len()
        );
        record_places(tx, &meta).await?;
        tx.execute(
            "INSERT INTO restore_lost SELECT unnest($1::bigint[]) ON CONFLICT DO NOTHING",
            &[&meta.unavailable],
        )
        .await?;
        sequences = meta.sequences.clone();
    }
    // Where the journals after the time restored to put parts' bytes: the
    // same parts' (their IDs are never reused), so the backlog copied since,
    // say, is restored too. Up to a journal that emptied the parts table,
    // after which an ID may not be the same part.
    for name in &plan.later {
        let meta = journal_meta(target, key, name, listing.sizes[name]).await?;
        let truncated = meta
            .changes
            .iter()
            .any(|(_, table, op, _, _)| table == "parts" && op == "T");
        if truncated {
            break;
        }
        record_places(tx, &meta).await?;
        eprintln!(
            "took where {} parts are from {name}, after the time restored to",
            meta.parts.len()
        );
    }

    // The objects as they are in the bucket: one that isn't there (it
    // shouldn't be missing) holds nothing.
    let names: Vec<String> = listing.sizes.keys().cloned().collect();
    let sizes: Vec<i64> = names.iter().map(|n| listing.sizes[n] as i64).collect();
    tx.execute(
        "WITH listed AS (SELECT * FROM unnest($1::text[], $2::bigint[]) AS l(name, size))
         UPDATE restore_objects o SET size = l.size FROM listed l WHERE l.name = o.name",
        &[&names, &sizes],
    )
    .await?;
    // Tiers' objects aren't in the bucket (see `tiers`).
    tx.execute(
        "DELETE FROM restore_objects WHERE name <> ALL($1) AND name NOT LIKE 'tier:%'",
        &[&names],
    )
    .await?;

    // Lay the data out: a restoring blob per object and storage class, and
    // the parts in it where they are in the object.
    tx.batch_execute(
        "DELETE FROM restore_map m WHERE NOT EXISTS (SELECT 1 FROM restore_objects o WHERE o.id = m.object)
             OR \"offset\" + size > (SELECT o.size FROM restore_objects o WHERE o.id = m.object);
         UPDATE restore_map m SET class = 'STANDARD'
             WHERE NOT EXISTS (SELECT 1 FROM storage_classes c WHERE c.name = m.class);
         CREATE TEMP TABLE restore_targets ON COMMIT DROP AS
             SELECT m.object, m.class, gen_random_uuid() AS blob_id
             FROM restore_map m JOIN parts p ON p.id = m.part_id
             JOIN restore_objects o ON o.id = m.object AND o.name NOT LIKE 'tier:%'
             GROUP BY m.object, m.class;
         INSERT INTO blobs (blob_id, size, state, created_at, storage_class, pool)
             SELECT t.blob_id, o.size, 'restoring', now(), t.class, c.pool
             FROM restore_targets t JOIN restore_objects o ON o.id = t.object
             JOIN storage_classes c ON c.name = t.class;
         INSERT INTO restore_blobs (blob_id, name, size)
             SELECT t.blob_id, o.name, o.size FROM restore_targets t JOIN restore_objects o ON o.id = t.object;
         UPDATE parts p SET blob_id = t.blob_id, blob_offset = m.\"offset\"
             FROM restore_map m JOIN restore_targets t ON t.object = m.object AND t.class = m.class
             WHERE p.id = m.part_id;",
    )
    .await?;
    // Parts in tiers: remote blobs again, the tiers' objects, which keep
    // their blobs' IDs (a backup's object of a tier is its blob's). One
    // blob per object, whatever the parts' classes say, so that no other
    // blob deletes its object.
    let remote: i64 = tx
        .query_one(
            "SELECT count(*) FROM restore_objects WHERE name LIKE 'tier:%'",
            &[],
        )
        .await?
        .get(0);
    if remote > 0 {
        tx.batch_execute(
            "CREATE TEMP TABLE restore_tier_targets ON COMMIT DROP AS
                 SELECT m.object, min(m.class) AS class, o.size,
                        split_part(substr(o.name, 6), ':', 1) AS tier,
                        substr(o.name, 7 + length(split_part(substr(o.name, 6), ':', 1))) AS name
                 FROM restore_map m JOIN parts p ON p.id = m.part_id
                 JOIN restore_objects o ON o.id = m.object AND o.name LIKE 'tier:%'
                 GROUP BY m.object, o.name, o.size;
             INSERT INTO blobs (blob_id, size, state, created_at, storage_class, pool)
                 SELECT t.object, t.size, 'remote', now(), t.class, c.pool
                 FROM restore_tier_targets t JOIN storage_classes c ON c.name = t.class;
             INSERT INTO tier_blobs (blob_id, tier, name, size)
                 SELECT object, tier, name, size FROM restore_tier_targets;
             UPDATE parts p SET blob_id = m.object, blob_offset = m.\"offset\"
                 FROM restore_map m JOIN restore_tier_targets t ON t.object = m.object
                 WHERE p.id = m.part_id;",
        )
        .await?;
    }
    if tx
        .query_one("SELECT to_regclass('tiers') IS NOT NULL", &[])
        .await?
        .get::<_, bool>(0)
    {
        tx.execute("UPDATE tiers SET writable = $1", &[&writable_tiers])
            .await?;
    }
    // The parts the backup lacks: lost, in a blob of their own.
    let lost: i64 = tx
        .query_one(
            "SELECT count(*) FROM parts p WHERE NOT EXISTS (SELECT 1 FROM restore_map m WHERE m.part_id = p.id)",
            &[],
        )
        .await?
        .get(0);
    if lost > 0 {
        tx.batch_execute(
            "CREATE TEMP TABLE restore_lost_parts ON COMMIT DROP AS
                 SELECT p.id, sum(p.size) OVER (ORDER BY p.id) - p.size AS at, p.size
                 FROM parts p WHERE NOT EXISTS (SELECT 1 FROM restore_map m WHERE m.part_id = p.id);
             CREATE TEMP TABLE restore_lost_blob ON COMMIT DROP AS
                 SELECT gen_random_uuid() AS blob_id, (SELECT coalesce(sum(size), 0) FROM restore_lost_parts)::bigint AS size;
             INSERT INTO blobs (blob_id, size, state, created_at, storage_class, pool)
                 SELECT blob_id, size, 'restoring', now(), 'STANDARD', c.pool
                 FROM restore_lost_blob, storage_classes c WHERE c.name = 'STANDARD';
             INSERT INTO restore_blobs (blob_id, name, size) SELECT blob_id, NULL, size FROM restore_lost_blob;
             INSERT INTO lost_ranges (blob_id, start, stop, found_at)
                 SELECT blob_id, 0, size, now() FROM restore_lost_blob WHERE size > 0;
             UPDATE parts p SET blob_id = b.blob_id, blob_offset = l.at
                 FROM restore_lost_parts l, restore_lost_blob b WHERE p.id = l.id;",
        )
        .await?;
    }
    for (name, value, called) in &sequences {
        tx.execute(
            "SELECT setval($1::text::regclass, $2, $3)",
            &[&quote(name), value, called],
        )
        .await?;
    }
    let summary = tx
        .query_one(
            "SELECT (SELECT count(*) FROM parts), (SELECT coalesce(sum(size), 0)::bigint FROM parts),
                    (SELECT count(*) FROM restore_blobs WHERE name IS NOT NULL)",
            &[],
        )
        .await?;
    tx.execute(
        "UPDATE restore_source SET state = 'restoring', restored_to = to_timestamp($1::float8 / 1000)",
        &[&(restored_to as f64)],
    )
    .await?;
    for table in &all {
        tx.batch_execute(&format!("ALTER TABLE {} ENABLE TRIGGER USER", quote(table)))
            .await?;
    }
    for (table, name, definition) in &foreign {
        tx.batch_execute("SAVEPOINT fk").await?;
        let add = format!(
            "ALTER TABLE {table} ADD CONSTRAINT {} {definition}",
            quote(name)
        );
        if let Err(e) = tx.batch_execute(&add).await {
            // Rows that don't hold to it, which a consistent backup doesn't
            // have: kept, but the constraint isn't checked against them.
            tx.batch_execute("ROLLBACK TO SAVEPOINT fk").await?;
            eprintln!(
                "warning: {name} on {table} doesn't hold for every row ({e}); it's added without checking them"
            );
            tx.batch_execute(&format!("{add} NOT VALID")).await?;
        }
        tx.batch_execute("RELEASE SAVEPOINT fk").await?;
    }
    Ok(Summary {
        parts: summary.get(0),
        bytes: summary.get(1),
        blobs: summary.get(2),
        lost,
        remote,
    })
}

/// The backup a restore reads from, with a client for it, cached.
static SOURCE: Mutex<Option<(Location, [u8; 32], Target)>> = Mutex::new(None);

async fn source<C: GenericClient>(client: &C) -> anyhow::Result<Option<(Target, [u8; 32])>> {
    let Some(row) = client
        .query_opt_cached(
            "SELECT endpoint, region, bucket, prefix, path_style, access_key_id, secret_access_key, key
             FROM restore_source WHERE state <> 'loading'",
            &[],
        )
        .await?
    else {
        return Ok(None);
    };
    let location = Location {
        endpoint: row.get(0),
        region: row.get(1),
        bucket: row.get(2),
        prefix: row.get(3),
        path_style: row.get(4),
        access_key_id: row.get(5),
        secret_access_key: row.get(6),
    };
    let key: [u8; 32] = row
        .get::<_, Vec<u8>>(7)
        .try_into()
        .map_err(|_| anyhow::anyhow!("a key of 32 bytes"))?;
    let mut cached = SOURCE.lock().unwrap();
    if let Some((l, k, target)) = cached.as_ref()
        && *l == location
        && *k == key
    {
        return Ok(Some((target.clone(), key)));
    }
    let target = Target::new(location.clone())?;
    *cached = Some((location, key, target.clone()));
    Ok(Some((target, key)))
}

/// Streams the bytes of a restoring blob that `slice` asks for to `tx`, from
/// the backup. False if the blob isn't one.
pub async fn stream(
    app: &App,
    slice: &mut crate::blobs::BlobSlice,
    tx: &FrameSender,
) -> std::io::Result<bool> {
    let client = app.pool.get().await.map_err(std::io::Error::other)?;
    let Some(row) = client
        .query_opt_cached(
            "SELECT name, size FROM restore_blobs WHERE blob_id = $1",
            &[&slice.blob_id],
        )
        .await
        .map_err(std::io::Error::other)?
    else {
        return Ok(false);
    };
    let (name, size): (Option<String>, i64) = (row.get(0), row.get(1));
    let Some(name) = name else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the backup lacks these bytes",
        ));
    };
    let (target, key) = source(&client)
        .await
        .map_err(|e| std::io::Error::other(format!("{e:#}")))?
        .ok_or_else(|| std::io::Error::other("a restoring blob, and no backup"))?;
    drop(client);
    let reader = ObjectReader::new(&target, &key, &name, size as u64);
    let (start, end) = (slice.offset, slice.offset + slice.length);
    let mut sent = 0u64;
    let result = async {
        let mut range = reader.range(start, end, 8 << 20).await?;
        while let Some(pieces) = range.next().await? {
            for piece in pieces {
                sent += piece.len() as u64;
                tx.send(Ok(Frame::data(piece)))
                    .await
                    .map_err(|_| anyhow::anyhow!("the reader went away"))?;
            }
        }
        anyhow::Ok(())
    }
    .await;
    slice.offset += sent;
    slice.length -= sent.min(slice.length);
    match result {
        Ok(()) => Ok(true),
        Err(e) => Err(std::io::Error::other(format!(
            "reading {name} of the backup: {e:#}"
        ))),
    }
}

/// How long a restorer holds a blob it copies, and how long it waits after
/// one failed.
const LEASE_SECS: f64 = 900.0;
const RETRY_SECS: f64 = 60.0;
/// How many blobs a node copies at once.
const WORKERS: usize = 2;

/// Copies the restoring blobs into the cluster, on every node, while there
/// are any.
pub async fn run(app: Arc<App>) {
    for _ in 0..WORKERS {
        let app = app.clone();
        tokio::spawn(async move {
            loop {
                let task_app = app.clone();
                let pass = tokio::spawn(async move { restore_one(&task_app).await });
                match pass.await {
                    Ok(Ok(true)) => continue,
                    Ok(Ok(false)) => {}
                    Ok(Err(e)) => eprintln!("restore: {e:#}"),
                    Err(e) => eprintln!("restore: the pass failed: {e}"),
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });
    }
}

/// Copies a restoring blob into the cluster, if there's one to: whether
/// there was.
pub async fn restore_one(app: &Arc<App>) -> anyhow::Result<bool> {
    let client = app.pool.get().await?;
    let restoring = client
        .query_opt_cached(
            "SELECT 1 FROM restore_source WHERE state = 'restoring'",
            &[],
        )
        .await?
        .is_some();
    if !restoring {
        return Ok(false);
    }
    let claimed = client
        .query_opt_cached(
            "UPDATE blobs SET pack_lease_until = now() + make_interval(secs => $1)
             WHERE blob_id = (
                 SELECT b.blob_id FROM blobs b JOIN restore_blobs r ON r.blob_id = b.blob_id
                 WHERE b.state = 'restoring' AND r.name IS NOT NULL
                   AND (b.pack_lease_until IS NULL OR b.pack_lease_until < now())
                 ORDER BY b.created_at LIMIT 1 FOR UPDATE OF b SKIP LOCKED)
             RETURNING blob_id, storage_class",
            &[&LEASE_SECS],
        )
        .await?;
    let Some(row) = claimed else {
        // Done, once no node is copying one either.
        client
            .execute_cached(
                "UPDATE restore_source SET state = 'done', finished_at = now(), secret_access_key = '',
                     key = '\\x0000000000000000000000000000000000000000000000000000000000000000'::bytea
                 WHERE state = 'restoring' AND NOT EXISTS (
                     SELECT 1 FROM blobs b JOIN restore_blobs r ON r.blob_id = b.blob_id
                     WHERE b.state = 'restoring' AND r.name IS NOT NULL)",
                &[],
            )
            .await?;
        return Ok(false);
    };
    drop(client);
    let (blob_id, class): (Uuid, String) = (row.get(0), row.get(1));
    let class = app.classes.get(&class);
    let coding = crate::packer::coding(app, &class).await?;
    match crate::packer::run_job(
        app,
        crate::packer::Kind::Restore,
        &[blob_id],
        &class,
        coding,
    )
    .await
    {
        Ok(report) => {
            eprintln!("restore: {report}");
            Ok(true)
        }
        Err(e) => {
            let _ = app
                .pool
                .get()
                .await?
                .execute(
                    "UPDATE blobs SET pack_lease_until = now() + make_interval(secs => $2) WHERE blob_id = $1",
                    &[&blob_id, &RETRY_SECS],
                )
                .await;
            Err(e.context(format!("copying blob {blob_id} from the backup")))
        }
    }
}

/// How a restore is going, for `cairn backup status`.
pub async fn status<C: GenericClient>(client: &C, out: &mut Output) -> anyhow::Result<()> {
    let Some(row) = client
        .query_opt(
            "SELECT state, endpoint, bucket, prefix, restored_to::text, extract(epoch FROM now() - started_at)::bigint
             FROM restore_source",
            &[],
        )
        .await?
    else {
        return Ok(());
    };
    let state: String = row.get(0);
    outln!(
        out,
        "restore from s3://{}/{} at {}, to {}: {}",
        row.get::<_, String>(2),
        row.get::<_, String>(3),
        row.get::<_, String>(1),
        row.get::<_, Option<String>>(4).unwrap_or_default(),
        match state.as_str() {
            "done" => "done",
            "restoring" => "copying the data into the cluster",
            _ => "loading the database",
        }
    );
    let row = client
        .query_one(
            "SELECT count(*) FILTER (WHERE r.name IS NOT NULL), coalesce(sum(p.bytes) FILTER (WHERE r.name IS NOT NULL), 0)::bigint,
                    count(*) FILTER (WHERE r.name IS NULL)
             FROM restore_blobs r
             LEFT JOIN (SELECT blob_id, sum(size) AS bytes FROM parts GROUP BY blob_id) AS p ON p.blob_id = r.blob_id",
            &[],
        )
        .await?;
    let (blobs, bytes, lost): (i64, i64, i64) = (row.get(0), row.get(1), row.get(2));
    if blobs > 0 {
        outln!(
            out,
            "  still in the backup: {blobs} objects, {bytes} bytes of parts"
        );
    }
    if lost > 0 {
        outln!(out, "  lost: parts the backup lacked the bytes of");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_tell_whats_visible() {
        let snapshot = "100:110:102,105";
        assert!(visible(99, snapshot).unwrap());
        assert!(visible(101, snapshot).unwrap());
        assert!(!visible(102, snapshot).unwrap());
        assert!(visible(104, snapshot).unwrap());
        assert!(!visible(105, snapshot).unwrap());
        assert!(!visible(110, snapshot).unwrap());
        assert!(visible(5, "10:10:").unwrap());
    }

    #[test]
    fn times_parse() {
        assert_eq!(parse_time("1700000000"), Ok(1_700_000_000_000));
        assert_eq!(parse_time("2023-11-14T22:13:20Z"), Ok(1_700_000_000_000));
        assert_eq!(
            parse_time("2023-11-14T23:13:20+01:00"),
            Ok(1_700_000_000_000)
        );
        assert!(parse_time("yesterday").is_err());
        assert_eq!(format_time(1_700_000_000_000), "2023-11-14T22:13:20Z");
    }
}
