//! Backups of the whole cluster to another S3 service, from which a new
//! cluster can be restored with nothing else: no copy of the database.
//!
//! ## What's backed up, and how
//!
//! The database, but for what says where data is (see `capture`), and the
//! bytes of every part. A node at a time runs the backup (holding a lease in
//! `backup_state`), a **cycle** every `interval` (5 minutes by default, the
//! RPO):
//!
//! 1. It reads, in a snapshot, the changes the capture triggers logged since
//!    the last cycle (`backup_changes`): every row inserted, updated or
//!    deleted in the tables that are backed up, in the order they were made.
//! 2. It copies the bytes of the parts those changes added, from the
//!    cluster, checked against their checksums as they're read. Parts that
//!    share bytes (copies) are copied once: a part whose bytes are backed up
//!    already, as another's, just points there.
//! 3. It writes a **journal**: the changes, and the parts' bytes, if they're
//!    less than a pack's worth (`pack-size`, 256 MiB by default); a larger
//!    batch goes to **packs** of about that size. So the target gets a
//!    handful of objects a cycle, however many objects were written, and an
//!    idle cluster none.
//! 4. In one transaction, it deletes the changes it shipped, and records
//!    where each part's bytes are (`backup_parts`), and how many parts each
//!    object of the backup still holds (`backup_objects`).
//!
//! Every so often (once the journals since add up to its size, but for the
//! parts' bytes they hold; or after 2016 of them, a week's at 5 minutes; or
//! when the schema changed), it takes a **base**: every table, and where
//! every part is. A base is built a chunk at a time, between cycles, and
//! resumes after an interruption (see `base`). A restore loads the latest complete base, and replays the
//! journals after it.
//!
//! The objects journals and packs hold parts' bytes in are addressed by
//! `backup_parts` alone, part by part (a copy has a row of its own, pointing
//! at the same bytes as its source). A base holds that table too, so a
//! restore from it reads the bytes from wherever they were then, an old
//! journal's data included; a journal that moves parts (packing journals,
//! rewriting packs) records where each went, which a restore from an
//! earlier base replays. No object is ever changed once it's written.
//!
//! Parts that were there before the backup was turned on are copied a batch
//! a cycle (`backfill_after`), as are those of a parts table that was ever
//! truncated: until that's done, a restore would lack them.
//!
//! Parts in remote tiers (see `tiers`) aren't copied: they're recorded as
//! being in the tier's object, which the backup lists among its objects (of
//! the kind `tier`, by the remote blob's ID) but never writes or deletes. The
//! packer queues the parts it moves into or out of a tier
//! (`backup_tier_moves`), and the next cycle records them anew: pointed at
//! the tier, or backed up again if they came back into the cluster (whose
//! tier object is going). A restore makes those parts remote blobs again.
//!
//! ## Few objects, and little rewriting
//!
//! Objects aren't rewritten to reclaim space, which with versioning on the
//! target (as it should be) would only add a copy of what was kept while the
//! old version is retained. A pack is deleted once nothing in it is needed
//! anymore. There are only two exceptions, both bounded:
//!
//! - The parts in journals are moved into a pack once there's a pack's
//!   worth, or the oldest has waited a day, so that a trickle of small
//!   writes doesn't leave a journal behind every cycle. That writes those
//!   bytes twice, but small ones only, and at most a pack a day for a quiet
//!   cluster.
//! - A pack that's less than half live ([`cycle::COMPACT_BELOW`]) has
//!   what's live rewritten (with that of other such packs, into full
//!   packs). So the target never holds more than about twice what's live
//!   for good, and a rewrite adds at most half a pack's size, while the old
//!   pack is kept (by the retention, and the bucket's versioning).
//!
//! ## Point in time, and retention
//!
//! Nothing is deleted until it's been unneeded for the `retention` (7 days
//! by default): so a restore can go back to any journal within it
//! (`--at`), and a restore that takes a while (or a test of one) isn't
//! pulled from under it.
//!
//! ## Encryption
//!
//! Everything is encrypted with the backup's key (see `crypt`), which Cairn
//! makes when the backup is turned on, and keeps in the database to write
//! with. A restore needs it: keep it somewhere else too.
//!
//! What isn't backed up: the KMS's keys (OpenBao's), without which SSE-KMS
//! and SSE-S3 objects can't be read, restored or not; and the nodes' flags.

pub mod base;
pub mod capture;
pub mod crypt;
pub mod cycle;
pub mod format;
pub mod restore;
pub mod s3;

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use clap::{Args, Subcommand};
use deadpool_postgres::GenericClient;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::App;
use crate::admin::{Output, outln};

/// How often every node checks whether a cycle is due.
const POLL: Duration = Duration::from_secs(5);
/// How long the runner's lease lasts, unless it's renewed.
const LEASE_SECS: f64 = 120.0;
/// How often a runner renews its lease while it works.
const RENEW: Duration = Duration::from_secs(30);
/// How long a runner waits after a failure.
const RETRY: Duration = Duration::from_secs(60);

/// The object next to a backup's that holds its key, wrapped by the KMS's
/// root key (as `backup_config` keeps it), if the cluster has a KMS: a
/// restore with the root key reads its key from there (see `restore`).
pub const WRAPPED_KEY: &str = "key.wrapped";

/// The backup's settings.
#[derive(Clone)]
pub struct Config {
    pub location: s3::Location,
    /// Its key, as the database keeps it: wrapped by the KMS's root key, if
    /// there's a KMS (see `kms`).
    pub key: crate::kms::StoredKey,
    pub interval: Duration,
    pub retention: Duration,
    pub pack_size: u64,
    pub enabled: bool,
}

impl Config {
    /// Its key, unwrapped by the KMS's root key if it's wrapped.
    pub async fn open_key(&self, app: &App) -> anyhow::Result<zeroize::Zeroizing<[u8; 32]>> {
        self.key
            .open(app.kms.as_deref(), crate::kms::BACKUP_KEY_AD)
            .await
    }
}

/// Where the backup has got to.
#[derive(Clone, Debug, Default)]
pub struct State {
    pub journal_seq: i64,
    pub journal_id: Option<Uuid>,
    /// The last journal before the base began, and before it was complete.
    pub base_seq: Option<i64>,
    pub base_ready_seq: Option<i64>,
    /// The base being built, if one is.
    pub building: Option<format::Building>,
    pub base_id: Option<Uuid>,
    pub base_version: Option<i32>,
    pub base_size: Option<i64>,
    pub journals_since_base: i64,
    pub bytes_since_base: i64,
    pub backfill_after: Option<i64>,
    pub requested: Option<String>,
    /// Seconds since the last cycle, if there was one.
    pub since_cycle: Option<f64>,
}

pub async fn load_config<C: GenericClient>(client: &C) -> anyhow::Result<Option<Config>> {
    let Some(row) = client
        .query_opt(
            "SELECT endpoint, region, bucket, prefix, path_style, access_key_id, secret_access_key, key,
                    interval_secs, retention_secs, pack_size, enabled, key_wrapped
             FROM backup_config",
            &[],
        )
        .await?
    else {
        return Ok(None);
    };
    let key: Vec<u8> = row.get(7);
    Ok(Some(Config {
        location: s3::Location {
            endpoint: row.get(0),
            region: row.get(1),
            bucket: row.get(2),
            prefix: row.get(3),
            path_style: row.get(4),
            access_key_id: row.get(5),
            secret_access_key: row.get(6),
        },
        key: crate::kms::StoredKey::from_columns(key, row.get(12))?,
        interval: Duration::from_secs(row.get::<_, i32>(8) as u64),
        retention: Duration::from_secs(row.get::<_, i64>(9) as u64),
        pack_size: row.get::<_, i64>(10) as u64,
        enabled: row.get(11),
    }))
}

pub async fn load_state<C: GenericClient>(client: &C) -> anyhow::Result<State> {
    let row = client
        .query_one(
            "SELECT generation, journal_seq, journal_id, base_seq, base_id, base_version, base_size,
                    journals_since_base, bytes_since_base, backfill_after, requested,
                    extract(epoch FROM now() - cycled_at)::float8, base_ready_seq, building
             FROM backup_state",
            &[],
        )
        .await?;
    Ok(State {
        journal_seq: row.get(1),
        journal_id: row.get(2),
        base_seq: row.get(3),
        base_id: row.get(4),
        base_version: row.get(5),
        base_size: row.get(6),
        journals_since_base: row.get(7),
        bytes_since_base: row.get(8),
        backfill_after: row.get(9),
        requested: row.get(10),
        since_cycle: row.get(11),
        base_ready_seq: row.get(12),
        building: row
            .get::<_, Option<String>>(13)
            .map(|text| serde_json::from_str(&text))
            .transpose()?,
    })
}

/// Makes sure every table that's backed up has its capture trigger, while a
/// backup is on (after migrations, which may have added tables, and on
/// turning it on); asks for a base if one had none. In the caller's
/// transaction, which holds the migrations' lock.
pub async fn refresh_capture<C: GenericClient>(client: &C) -> anyhow::Result<()> {
    let exists: bool = client
        .query_one("SELECT to_regclass('backup_config') IS NOT NULL", &[])
        .await?
        .get(0);
    if !exists {
        return Ok(());
    }
    let enabled = client
        .query_opt("SELECT enabled FROM backup_config", &[])
        .await?
        .is_some_and(|row| row.get(0));
    if !enabled {
        return Ok(());
    }
    let added = capture::install(client).await?;
    if !added.is_empty() {
        eprintln!(
            "backup: capturing the changes of {} new tables, which a new base will hold",
            added.len()
        );
        client
            .execute("UPDATE backup_state SET requested = 'base'", &[])
            .await?;
    }
    Ok(())
}

/// The backup's runner, on every node: every few seconds, it checks whether
/// a cycle is due, and if so, and no other node holds the lease, runs it.
pub async fn run(app: Arc<App>) {
    let token = Uuid::new_v4();
    loop {
        tokio::time::sleep(POLL).await;
        let task_app = app.clone();
        // A task of its own, so that a panic (a bug) fails this pass only.
        let pass = tokio::spawn(async move { step(&task_app, token).await });
        let failure = match pass.await {
            Ok(Ok(_)) => continue,
            Ok(Err(e)) => format!("{e:#}"),
            Err(e) => format!("the backup's pass failed: {e}"),
        };
        eprintln!("backup: {failure}");
        if let Ok(client) = app.pool.get().await {
            let _ = client
                .execute(
                    "UPDATE backup_state SET last_error = $1, last_error_at = now() WHERE holder = $2",
                    &[&failure, &token],
                )
                .await;
        }
        // Not again right away: what failed (the target, say) may take a
        // while to come back.
        tokio::time::sleep(RETRY).await;
    }
}

/// What a step did.
#[derive(Debug, Default)]
pub struct Report {
    pub base: Option<u64>,
    pub cycles: Vec<cycle::Cycle>,
    pub swept: usize,
}

/// Renews a runner's lease until it's dropped.
struct Renewal(tokio::task::JoinHandle<()>);

impl Drop for Renewal {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Runs what's due of the backup, if this node may: `None` if nothing was.
pub async fn step(app: &Arc<App>, token: Uuid) -> anyhow::Result<Option<Report>> {
    let client = app.pool.get().await?;
    let Some(config) = load_config(&client).await? else {
        return Ok(None);
    };
    if !config.enabled {
        return Ok(None);
    }
    let mut state = load_state(&client).await?;
    let interval = config.interval.as_secs_f64();
    let cycle_due = |state: &State| {
        state.requested.is_some()
            || state.backfill_after.is_some()
            || state.since_cycle.is_none_or(|secs| secs >= interval)
    };
    if !cycle_due(&state) && state.building.is_none() {
        return Ok(None);
    }
    // A node whose Cairn is older than the schema leaves the backup to the
    // newer ones (an upgrade in progress).
    let version: i32 = client
        .query_one("SELECT max(version) FROM schema_migrations", &[])
        .await?
        .get(0);
    if version > crate::db::schema_version() {
        return Ok(None);
    }
    let Some(row) = client
        .query_opt(
            "UPDATE backup_state SET holder = $1, lease_until = now() + make_interval(secs => $2)
             WHERE holder IS NULL OR holder = $1 OR lease_until < now()
             RETURNING generation",
            &[&token, &LEASE_SECS],
        )
        .await?
    else {
        return Ok(None);
    };
    let generation: i64 = row.get(0);
    let _renewal = Renewal(tokio::spawn({
        let app = app.clone();
        async move {
            loop {
                tokio::time::sleep(RENEW).await;
                if let Ok(client) = app.pool.get().await {
                    let _ = client
                        .execute(
                            "UPDATE backup_state SET lease_until = now() + make_interval(secs => $2) WHERE holder = $1",
                            &[&token, &LEASE_SECS],
                        )
                        .await;
                }
            }
        }
    }));
    let target = s3::Target::new(config.location.clone())?;
    let key = config.open_key(app).await?;
    // The wrapped key next to the backup, once a process: a key wrapped
    // since the backup began (see `kms::wrap_stored_keys`) gets there too.
    static WROTE_WRAPPED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if let crate::kms::StoredKey::Wrapped(wrapped) = &config.key
        && !WROTE_WRAPPED.swap(true, std::sync::atomic::Ordering::Relaxed)
        && let Err(e) = target
            .put(WRAPPED_KEY, bytes::Bytes::from(wrapped.clone()))
            .await
    {
        WROTE_WRAPPED.store(false, std::sync::atomic::Ordering::Relaxed);
        eprintln!("backup: writing the wrapped key: {e:#}");
    }
    let mut runner = cycle::Runner {
        app,
        key,
        config,
        target,
        token,
        generation,
    };
    let mut report = Report::default();

    // Tables without a trigger (made while the backup was off on some
    // node's Cairn, say) need it, and a base.
    if !capture::missing(&client).await?.is_empty() {
        let mut client = app.pool.get().await?;
        let tx = client.transaction().await?;
        tx.execute(
            "SELECT pg_advisory_xact_lock($1)",
            &[&crate::db::MIGRATION_LOCK],
        )
        .await?;
        capture::install(&tx).await?;
        tx.execute("UPDATE backup_state SET requested = 'base'", &[])
            .await?;
        tx.commit().await?;
        state = load_state(&client).await?;
    }
    drop(client);
    let reload = async || load_state(&app.pool.get().await?).await;
    // A base: begun when one is due, and built a chunk at a time, for a
    // while each step, between the journals.
    if state
        .building
        .as_ref()
        .is_some_and(|b| b.version != version)
    {
        runner.abandon_base().await?;
        state = reload().await?;
    }
    if state.building.is_none() && cycle::Runner::base_due(&state, version) {
        runner.start_base(&state, version).await?;
        state = reload().await?;
    }
    if state.building.is_some() {
        report.base = runner.build_base(&state, base::BUDGET).await?;
        state = reload().await?;
        if let Some(size) = report.base {
            eprintln!("backup: base complete, {size} bytes");
        }
    }
    let mut cycled = false;
    while cycle_due(&state) && report.cycles.len() < 1000 {
        let done = runner.cycle(&state).await?;
        state = reload().await?;
        cycled = true;
        if done.needs_base {
            // The schema changed: the next step begins a base for it.
            break;
        }
        let again = done.again;
        if let Some(seq) = done.journal {
            eprintln!(
                "backup: journal {seq}: {} changes, {} parts, {} bytes",
                done.changes, done.parts, done.bytes
            );
        }
        report.cycles.push(done);
        if !again {
            break;
        }
    }
    if cycled {
        app.pool
            .get()
            .await?
            .execute(
                "UPDATE backup_state SET cycled_at = now(),
                     requested = CASE WHEN requested = 'now' THEN NULL ELSE requested END
                 WHERE holder = $1",
                &[&token],
            )
            .await?;
        state = reload().await?;
    }
    report.swept = runner.sweep(&state).await?;
    Ok(Some(report))
}

/// `cairn backup`.
#[derive(Args, Debug, Serialize, Deserialize)]
pub struct BackupArgs {
    #[command(subcommand)]
    pub command: BackupCommand,
    #[command(flatten)]
    #[serde(skip)]
    pub remote: crate::admin::Remote,
}

/// Where a backup is, as the CLI takes it.
#[derive(Args, Debug, Clone, Serialize, Deserialize)]
pub struct LocationArgs {
    /// The S3 service's URL, e.g. https://s3.eu-central-1.amazonaws.com.
    #[arg(long)]
    pub endpoint: String,
    /// Its region, which requests are signed for.
    #[arg(long, default_value = "us-east-1")]
    pub region: String,
    /// The bucket. Turn versioning on for it, so that the target keeps what
    /// a mistake (or an attacker with these credentials) deletes.
    #[arg(long)]
    pub bucket: String,
    /// Where in the bucket: a prefix of its own.
    #[arg(long, default_value = "")]
    pub prefix: String,
    /// Name the bucket in the path (host/bucket/key) rather than the host
    /// (bucket.host/key), as most services other than AWS need.
    #[arg(long)]
    pub path_style: bool,
    #[arg(long, env = "CAIRN_BACKUP_ACCESS_KEY_ID")]
    pub access_key_id: String,
    #[arg(long, env = "CAIRN_BACKUP_SECRET_ACCESS_KEY", hide_env_values = true)]
    pub secret_access_key: String,
}

impl LocationArgs {
    pub fn location(&self) -> anyhow::Result<s3::Location> {
        s3::Location {
            endpoint: self.endpoint.clone(),
            region: self.region.clone(),
            bucket: self.bucket.clone(),
            prefix: self.prefix.clone(),
            path_style: self.path_style,
            access_key_id: self.access_key_id.clone(),
            secret_access_key: self.secret_access_key.clone(),
        }
        .normalized()
    }
}

#[derive(Subcommand, Debug, Serialize, Deserialize)]
pub enum BackupCommand {
    /// Back the cluster up to an S3 bucket, from now on (or change where
    /// to, or how). Prints the backup's key, which a restore needs.
    Enable {
        #[command(flatten)]
        location: LocationArgs,
        /// The backup's key (base64, 32 bytes), to use one of your own.
        /// Otherwise the backup keeps its key, or gets a new one.
        #[arg(long, env = "CAIRN_BACKUP_KEY", hide_env_values = true)]
        key: Option<String>,
        /// How often changes are shipped: the most that a restore can lose.
        #[arg(long, default_value = "5m", value_parser = parse_duration)]
        interval: u64,
        /// How long what's no longer needed is kept, so that a restore can
        /// go back that far.
        #[arg(long, default_value = "7d", value_parser = parse_duration)]
        retention: u64,
        /// How large packs of data are.
        #[arg(long, default_value = "256MiB", value_parser = crate::scrub::parse_rate)]
        pack_size: u64,
    },
    /// Stop backing up. What's in the bucket stays.
    Disable,
    /// Where the backup is, how far it's got, and how a restore is going.
    Status,
    /// Run a cycle now (with --base, take a base first).
    Now {
        #[arg(long)]
        base: bool,
    },
    /// Print the backup's key.
    Key,
}

/// `5m`, `30s`, `7d`, `12h`, or seconds: in seconds.
pub fn parse_duration(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let number: u64 = number
        .parse()
        .map_err(|_| format!("{text:?} isn't a duration, such as 5m or 7d"))?;
    let unit = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        other => {
            return Err(format!(
                "unknown unit {other:?} in {text:?}; use s, m, h or d"
            ));
        }
    };
    Ok(number * unit)
}

/// Carries out `cairn backup` on a node.
pub async fn run_command(app: &Arc<App>, args: BackupArgs, out: &mut Output) -> anyhow::Result<()> {
    match args.command {
        BackupCommand::Enable {
            location,
            key,
            interval,
            retention,
            pack_size,
        } => {
            let enabled = enable(
                app,
                Enable {
                    location: location.location()?,
                    key,
                    interval,
                    retention,
                    pack_size,
                },
            )
            .await?;
            outln!(
                out,
                "backing up to {}, every {}s",
                enabled.location.describe(),
                interval
            );
            if let Some(key) = enabled.new_key {
                outln!(
                    out,
                    "key: {}",
                    base64::engine::general_purpose::STANDARD.encode(key)
                );
                out.warn(
                    "keep this key safe, and apart from the cluster: a restore needs it, and without it the backup is \
                     unreadable (`cairn backup key` prints it again)",
                );
            }
            Ok(())
        }
        BackupCommand::Disable => {
            if disable(app).await? {
                outln!(
                    out,
                    "backup off: what's in the bucket stays, and turning it back on there carries on"
                );
            } else {
                outln!(out, "the backup was off already");
            }
            Ok(())
        }
        BackupCommand::Status => print_status(app, out).await,
        BackupCommand::Now { base } => {
            request(app, base).await?;
            outln!(
                out,
                "a cycle runs within seconds{}",
                if base { ", after a base" } else { "" }
            );
            Ok(())
        }
        BackupCommand::Key => {
            let client = app.pool.get().await?;
            let config = load_config(&client)
                .await?
                .ok_or_else(|| anyhow::anyhow!("there's no backup"))?;
            let key = config.open_key(app).await?;
            outln!(
                out,
                "{}",
                base64::engine::general_purpose::STANDARD.encode(*key)
            );
            Ok(())
        }
    }
}

/// How the backup is to be turned on, or changed, as `cairn backup enable`
/// takes it.
pub struct Enable {
    /// Where to: normalized (see `s3::Location::normalized`) as it's taken.
    pub location: s3::Location,
    /// The backup's key (base64, 32 bytes), to use one of one's own;
    /// otherwise the backup keeps its key, or gets a new one.
    pub key: Option<String>,
    /// Seconds between cycles: the most a restore can lose.
    pub interval: u64,
    /// Seconds what's no longer needed is kept, so that a restore can go
    /// back that far.
    pub retention: u64,
    /// Bytes of a pack of data.
    pub pack_size: u64,
}

/// What turning the backup on came to.
pub struct Enabled {
    /// Where it backs up to.
    pub location: s3::Location,
    /// The key it made, if it made one: a restore needs it.
    pub new_key: Option<[u8; 32]>,
}

/// Turns the backup on, or changes where to, or how (see the module's
/// docs): a new location starts a new backup, from a base.
pub async fn enable(app: &Arc<App>, enable: Enable) -> anyhow::Result<Enabled> {
    use crate::classes::bad_input;
    let Enable {
        location,
        key,
        interval,
        retention,
        pack_size,
    } = enable;
    let location = location
        .normalized()
        .map_err(|e| bad_input(format!("{e:#}")))?;
    if interval == 0 || interval > i32::MAX as u64 {
        return Err(bad_input("the interval must be a positive duration"));
    }
    if retention > i64::MAX as u64 {
        return Err(bad_input("the retention is too long"));
    }
    if pack_size < 5 << 20 || pack_size > i64::MAX as u64 {
        return Err(bad_input("packs must be at least 5 MiB"));
    }
    let key = match key {
        Some(text) => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(text.trim())
                .map_err(|_| bad_input("the key must be base64"))?;
            Some(<[u8; 32]>::try_from(bytes).map_err(|_| bad_input("the key must be 32 bytes"))?)
        }
        None => None,
    };
    let target = s3::Target::new(location.clone())?;
    target
        .check()
        .await
        .map_err(|e| bad_input(format!("can't list {}: {e:#}", location.describe())))?;
    let client = app.pool.get().await?;
    let old = load_config(&client).await?;
    drop(client);
    let same = old.as_ref().is_some_and(|old| {
        let (a, b) = (&old.location, &location);
        (&a.endpoint, &a.bucket, &a.prefix) == (&b.endpoint, &b.bucket, &b.prefix)
    });
    if !same && !target.list("").await?.is_empty() {
        return Err(bad_input(format!(
            "{} holds objects already: a backup needs a prefix of its own",
            location.describe()
        )));
    }
    let old_key = match &old {
        Some(old) if same => Some(old.open_key(app).await?),
        _ => None,
    };
    let (key, new_key) = match (key, &old_key) {
        (Some(key), _) => (key, false),
        (None, Some(old)) => (**old, false),
        (None, None) => {
            let mut key = [0; 32];
            getrandom::fill(&mut key).expect("the OS random number generator failed");
            (key, true)
        }
    };
    if old_key.is_some_and(|old| *old != key) {
        return Err(crate::managed::Refused::Conflict(
            "this backup has a key already, and a new one would leave what's in it unreadable"
                .into(),
        )
        .into());
    }
    // Wrapped by the root key, if there's a KMS; and next to the backup
    // too, so that a restore with the root key needs nothing else (see
    // `restore`).
    let stored =
        crate::kms::StoredKey::seal(app.kms.as_deref(), &key, crate::kms::BACKUP_KEY_AD).await?;
    let (stored_key, wrapped) = stored.columns();
    if wrapped {
        target
            .put(WRAPPED_KEY, bytes::Bytes::from(stored_key.clone()))
            .await
            .map_err(|e| {
                bad_input(format!(
                    "writing the wrapped key to {}: {e:#}",
                    location.describe()
                ))
            })?;
    }
    let mut client = app.pool.get().await?;
    let tx = client.transaction().await?;
    tx.execute(
        "SELECT pg_advisory_xact_lock($1)",
        &[&crate::db::MIGRATION_LOCK],
    )
    .await?;
    tx.execute(
        "INSERT INTO backup_config (endpoint, region, bucket, prefix, path_style, access_key_id,
                                    secret_access_key, key, interval_secs, retention_secs, pack_size, enabled,
                                    key_wrapped)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, true, $12)
         ON CONFLICT (id) DO UPDATE SET endpoint = $1, region = $2, bucket = $3, prefix = $4, path_style = $5,
             access_key_id = $6, secret_access_key = $7, key = $8, interval_secs = $9, retention_secs = $10,
             pack_size = $11, enabled = true, key_wrapped = $12",
        &[
            &location.endpoint,
            &location.region,
            &location.bucket,
            &location.prefix,
            &location.path_style,
            &location.access_key_id,
            &location.secret_access_key,
            &stored_key,
            &(interval as i32),
            &(retention as i64),
            &(pack_size as i64),
            &wrapped,
        ],
    )
    .await?;
    let was_on = old.as_ref().is_some_and(|old| old.enabled);
    if !same {
        // A new backup, from scratch.
        tx.batch_execute(
            "DELETE FROM backup_parts;
             DELETE FROM backup_objects;
             DELETE FROM backup_changes;
             DELETE FROM backup_tier_moves;
             UPDATE backup_state SET journal_seq = 0, journal_id = NULL, journal_at = NULL, base_seq = NULL,
                 base_id = NULL, base_at = NULL, base_version = NULL, base_size = NULL,
                 journals_since_base = 0, bytes_since_base = 0, backfill_after = 0, cycled_at = NULL,
                 requested = 'base', last_error = NULL, last_error_at = NULL;",
        )
        .await?;
    } else if !was_on {
        // What changed while it was off wasn't captured: the parts deleted
        // meanwhile are dropped, those added are backed up, and a base holds
        // the rest.
        tx.batch_execute(
            "DELETE FROM backup_changes;
             DELETE FROM backup_parts bp WHERE NOT EXISTS (SELECT 1 FROM parts p WHERE p.id = bp.part_id);
             UPDATE backup_objects o SET refs = coalesce(c.n, 0), live_bytes = coalesce(c.bytes, 0),
                 dead_since = CASE WHEN c.n IS NULL THEN coalesce(o.dead_since, now()) END
             FROM backup_objects x
             LEFT JOIN (SELECT object, count(*) AS n, sum(size)::bigint AS bytes FROM backup_parts GROUP BY object) AS c
                 ON c.object = x.id
             WHERE o.id = x.id;
             UPDATE backup_state SET backfill_after = 0, requested = 'base';",
        )
        .await?;
    }
    capture::install(&tx).await?;
    // A cycle under way when the backup changed commits nothing.
    tx.execute(
        "UPDATE backup_state SET generation = generation + 1, holder = NULL, lease_until = NULL",
        &[],
    )
    .await?;
    tx.commit().await?;
    Ok(Enabled {
        location,
        new_key: new_key.then_some(key),
    })
}

/// Stops backing up; what's in the bucket stays. Whether it was on.
pub async fn disable(app: &App) -> anyhow::Result<bool> {
    let mut client = app.pool.get().await?;
    let tx = client.transaction().await?;
    tx.execute(
        "SELECT pg_advisory_xact_lock($1)",
        &[&crate::db::MIGRATION_LOCK],
    )
    .await?;
    capture::uninstall(&tx).await?;
    let changed = tx
        .execute(
            "UPDATE backup_config SET enabled = false WHERE enabled",
            &[],
        )
        .await?;
    tx.execute(
        "UPDATE backup_state SET generation = generation + 1, holder = NULL, lease_until = NULL, requested = NULL",
        &[],
    )
    .await?;
    tx.commit().await?;
    Ok(changed > 0)
}

/// Asks for a cycle within seconds (after a base, if `base`), which the
/// node holding the backup's lease, or the next to take it, runs.
pub async fn request(app: &App, base: bool) -> anyhow::Result<()> {
    let client = app.pool.get().await?;
    let config = load_config(&client).await?;
    if !config.is_some_and(|c| c.enabled) {
        return Err(crate::managed::Refused::Conflict(
            "the backup is off (cairn backup enable)".into(),
        )
        .into());
    }
    let what = if base { "base" } else { "now" };
    client
        .execute(
            "UPDATE backup_state SET requested = $1 WHERE requested IS DISTINCT FROM 'base'",
            &[&what],
        )
        .await?;
    Ok(())
}

/// Where the backup is, and how far it's got, as `cairn backup status` and
/// the console show it. Ages are in seconds. Neither its key nor its
/// credentials' secret are shown.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BackupStatus {
    pub enabled: bool,
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    /// Empty, or ending in `/`.
    pub prefix: String,
    pub path_style: bool,
    pub access_key_id: String,
    /// Seconds between cycles, how long what's unneeded is kept, and the
    /// bytes of a pack.
    pub interval: u64,
    pub retention: u64,
    pub pack_size: u64,
    /// The last journal's number, and its age, if there's one yet.
    pub journal: i64,
    pub journal_age: Option<i64>,
    /// How long ago a cycle last ran (found something to ship or not).
    pub checked_age: Option<i64>,
    /// The last complete base's age and size: until there's one, nothing
    /// can be restored.
    pub base_age: Option<i64>,
    pub base_size: Option<i64>,
    /// The base being built, if one is.
    pub building: Option<BaseProgress>,
    /// Changes captured and not yet shipped.
    pub changes: i64,
    /// Parts from before the backup still to copy, while there are any.
    pub backfill: Option<i64>,
    /// The last failure, and its age.
    pub last_error: Option<String>,
    pub last_error_age: Option<i64>,
    /// The backup's objects, by kind.
    pub objects: Vec<BackupObjects>,
}

/// How far the base being built has got.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BaseProgress {
    /// The table it's at (from 1), of how many, and its name.
    pub table: usize,
    pub tables: usize,
    pub name: String,
    pub chunks: usize,
    pub bytes: u64,
}

/// The backup's objects of a kind: `journal`, `pack`, `base`, or `tier`
/// (a tier's objects, which the backup points at but doesn't copy).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BackupObjects {
    pub kind: String,
    pub count: i64,
    pub bytes: i64,
    /// Packs nothing needs anymore, which are kept for the retention.
    pub unneeded: i64,
}

/// The backup's status, if it was ever set up.
pub async fn status<C: GenericClient>(client: &C) -> anyhow::Result<Option<BackupStatus>> {
    let Some(config) = load_config(client).await? else {
        return Ok(None);
    };
    let row = client
        .query_one(
            "SELECT journal_seq, extract(epoch FROM now() - journal_at)::bigint,
                    extract(epoch FROM now() - base_at)::bigint, base_size, backfill_after,
                    last_error, extract(epoch FROM now() - last_error_at)::bigint,
                    (SELECT count(*) FROM backup_changes), extract(epoch FROM now() - cycled_at)::bigint
             FROM backup_state",
            &[],
        )
        .await?;
    let building = load_state(client).await?.building.map(|b| BaseProgress {
        table: b.table + 1,
        tables: b.tables.len(),
        name: b.tables.get(b.table).cloned().unwrap_or_default(),
        chunks: b.chunks.len(),
        bytes: b.bytes,
    });
    let backfill = match row.get::<_, Option<i64>>(4) {
        Some(after) => Some(
            client
                .query_one(
                    "SELECT count(*) FROM parts p WHERE p.id > $1
                       AND NOT EXISTS (SELECT 1 FROM backup_parts bp WHERE bp.part_id = p.id)",
                    &[&after],
                )
                .await?
                .get(0),
        ),
        None => None,
    };
    let objects = client
        .query(
            "SELECT kind, count(*), coalesce(sum(size), 0)::bigint, count(*) FILTER (WHERE refs = 0 AND kind = 'pack')
             FROM backup_objects GROUP BY kind ORDER BY kind",
            &[],
        )
        .await?
        .iter()
        .map(|r| BackupObjects {
            kind: r.get(0),
            count: r.get(1),
            bytes: r.get(2),
            unneeded: r.get(3),
        })
        .collect();
    let location = config.location;
    Ok(Some(BackupStatus {
        enabled: config.enabled,
        endpoint: location.endpoint,
        region: location.region,
        bucket: location.bucket,
        prefix: location.prefix,
        path_style: location.path_style,
        access_key_id: location.access_key_id,
        interval: config.interval.as_secs(),
        retention: config.retention.as_secs(),
        pack_size: config.pack_size,
        journal: row.get(0),
        journal_age: row.get(1),
        checked_age: row.get(8),
        base_age: row.get(2),
        base_size: row.get(3),
        building,
        changes: row.get(7),
        backfill,
        last_error: row.get(5),
        last_error_age: row.get(6),
        objects,
    }))
}

async fn print_status(app: &Arc<App>, out: &mut Output) -> anyhow::Result<()> {
    let client = app.pool.get().await?;
    match status(&client).await? {
        None => outln!(out, "backup: never set up (cairn backup enable)"),
        Some(s) => {
            outln!(
                out,
                "backup: {} to s3://{}/{} at {}",
                if s.enabled { "on" } else { "off" },
                s.bucket,
                s.prefix,
                s.endpoint
            );
            outln!(
                out,
                "  every {}s, keeping what's unneeded {}s, packs of {} bytes",
                s.interval,
                s.retention,
                s.pack_size
            );
            match s.journal_age {
                Some(age) => outln!(out, "  last journal: {}, {age}s ago", s.journal),
                None => outln!(out, "  no journal yet"),
            }
            if let Some(age) = s.checked_age {
                outln!(out, "  last checked: {age}s ago");
            }
            match s.base_age {
                Some(age) => outln!(
                    out,
                    "  last base: {age}s ago, {} bytes",
                    s.base_size.unwrap_or(0)
                ),
                None => outln!(out, "  no base yet: nothing can be restored yet"),
            }
            if let Some(b) = &s.building {
                outln!(
                    out,
                    "  building a base: table {} of {} ({}), {} chunks, {} bytes so far",
                    b.table,
                    b.tables,
                    b.name,
                    b.chunks,
                    b.bytes
                );
            }
            outln!(out, "  changes waiting: {}", s.changes);
            if let Some(left) = s.backfill {
                outln!(
                    out,
                    "  copying the data from before the backup: {left} parts to go"
                );
            }
            if let (Some(error), Some(age)) = (&s.last_error, s.last_error_age) {
                outln!(out, "  last error, {age}s ago: {error}");
            }
            for o in &s.objects {
                if o.kind == "tier" {
                    outln!(
                        out,
                        "  in tiers, not copied: {} objects ({} bytes)",
                        o.count,
                        o.bytes
                    );
                    continue;
                }
                outln!(
                    out,
                    "  {}s: {} ({} bytes{})",
                    o.kind,
                    o.count,
                    o.bytes,
                    match o.unneeded {
                        0 => String::new(),
                        n => format!(", {n} unneeded, kept for the retention"),
                    }
                );
            }
        }
    }
    restore::status(&client, out).await
}

#[cfg(test)]
pub(crate) mod e2e;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_parse() {
        assert_eq!(parse_duration("5m"), Ok(300));
        assert_eq!(parse_duration("7d"), Ok(7 * 86_400));
        assert_eq!(parse_duration("90"), Ok(90));
        assert!(parse_duration("5 minutes").is_err());
    }
}
