//! Storage classes, and the pools they keep their data in.
//!
//! A node keeps its data in one or more pools, a data dir each
//! (`--data-dir ssd=/mnt/nvme --data-dir hdd=/mnt/disks`; a bare path is the
//! pool `default`). A storage class names the pool its blobs go to, and the
//! data and parity shards they're stored in (see `shards`): unset, as the
//! cluster's `data-shards` and `parity-shards` settings say, as STANDARD's
//! are, unless it sets them. So classes differ in where their data is (SSDs,
//! HDDs) and in how much redundancy it has, or both.
//!
//! Every blob is of a class, and all of its shards are in one pool, each on a
//! node of its own, as before. An object version is of the class its parts'
//! blobs are: an upload writes its blobs in the class it asks for (the
//! `x-amz-storage-class` header), a copy into another class writes its data
//! again, and the packer packs a class's blobs only with one another (see
//! `packer`). A change of a class's pool or layout applies to new blobs
//! within a heartbeat, and the packer rewrites its existing blobs, as it does
//! after a change of the settings.
//!
//! A class may keep its data in a remote **tier** instead (see `tiers`): a
//! bucket of another S3 service. Its blobs are written into the cluster
//! first, in STANDARD's pool and layout (which it goes by, whatever its own
//! row says), and the packer moves them into the tier.
//!
//! ## Their order
//!
//! The operator ranks classes (`cairn class set COLD --rank -10`): the
//! warmest highest, STANDARD at 0. A class of a higher rank **stands in**
//! for one of a lower rank: a blob of it may hold the bytes of versions of
//! the lower one. That's the operator's promise, which Cairn doesn't check
//! (a cold pool's disks may be less reliable, and its class have more
//! parity shards for it): keeping bytes in a higher class than they need
//! costs more, but is otherwise as good. A class without a rank stands in
//! for none other, and none for it.
//!
//! So a version's class is its parts' blobs' class, or one they stand in
//! for. That's how lifecycle transitions work (see `lifecycle`): a
//! transition only changes the version's class, to a lower one, and leaves
//! its bytes where they are. A blob's bytes that only versions of lower
//! classes reference are **misplaced** (`blobs.misplaced_size`), and the
//! packer moves them into the class they belong in, the highest of their
//! versions' classes, as it rewrites the blob: once enough of it is
//! misplaced or garbage (see `packer`). Likewise, a copy into a lower class
//! than its source's shares the source's bytes.
//!
//! STANDARD always exists, in the pool `default` until it's moved. A class
//! that's named as S3 names its classes but isn't defined is taken as
//! STANDARD, as before Cairn had classes, so that clients that ask for one
//! (STANDARD_IA, say) keep working; any other undefined class is refused.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use clap::{Args, Subcommand};
use deadpool_postgres::GenericClient;
use serde::{Deserialize, Serialize};

use crate::{
    App,
    admin::{Output, outln},
    db::Cached,
    topology::{self, Tolerance},
};

/// The class every object is of unless it asks for another.
pub const STANDARD: &str = "STANDARD";
/// The pool of a bare `--data-dir`, which STANDARD starts out in.
pub const DEFAULT_POOL: &str = "default";

/// The storage classes S3 has. One that isn't defined is taken as STANDARD.
pub const S3_CLASSES: &[&str] = &[
    "STANDARD",
    "REDUCED_REDUNDANCY",
    "STANDARD_IA",
    "ONEZONE_IA",
    "INTELLIGENT_TIERING",
    "GLACIER",
    "DEEP_ARCHIVE",
    "OUTPOSTS",
    "GLACIER_IR",
    "SNOW",
    "EXPRESS_ONEZONE",
    "FSX_OPENZFS",
    "FSX_ONTAP",
];

/// A storage class: its pool, and its layout, where it sets one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Class {
    pub name: String,
    pub pool: String,
    /// Unset (`None`): the `data-shards` setting.
    pub data_shards: Option<u32>,
    /// Unset (`None`): the `parity-shards` setting, or the node's
    /// `--replication-factor` - 1 while that isn't set.
    pub parity_shards: Option<u32>,
    /// The tier it keeps its data in, if it's a tier's (see `tiers`): then
    /// its pool and layout are STANDARD's, for its data on the way there.
    pub tier: Option<String>,
    /// Its place in the classes' order, the warmest highest (see the
    /// module's docs); `None` if it has none.
    #[serde(default)]
    pub rank: Option<i32>,
    /// How many failure domains of each level its blobs survive losing
    /// (see `topology`); a tier's class goes by STANDARD's.
    #[serde(default, with = "tolerance_serde")]
    pub tolerance: Tolerance,
}

/// A tolerance as its counts, the widest level first.
mod tolerance_serde {
    use super::Tolerance;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(t: &Tolerance, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(t.0)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Tolerance, D::Error> {
        let counts: Vec<i16> = Vec::deserialize(d)?;
        Ok(Tolerance::from_counts(&counts))
    }
}

impl Class {
    /// STANDARD as a fresh cluster has it.
    pub fn standard() -> Class {
        Class {
            name: STANDARD.to_owned(),
            pool: DEFAULT_POOL.to_owned(),
            data_shards: None,
            parity_shards: None,
            tier: None,
            rank: Some(0),
            tolerance: Tolerance::default(),
        }
    }
}

/// Whether a blob of class `blob` may hold the bytes of a version (or
/// upload) of class `class`, as `classes` rank them: it's the same class,
/// or one ranked above it.
pub fn stands_in(classes: &BTreeMap<String, Class>, blob: &str, class: &str) -> bool {
    blob == class || matches!(rank_pair(classes, blob, class), Some((b, c)) if b > c)
}

fn rank_pair(classes: &BTreeMap<String, Class>, a: &str, b: &str) -> Option<(i32, i32)> {
    Some((classes.get(a)?.rank?, classes.get(b)?.rank?))
}

/// Whether `name` may name a class.
pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_uppercase())
        && name.len() <= 64
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Whether `name` may name a pool.
pub fn valid_pool(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name.len() <= 32
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// Every class, by name. A tier's class goes by STANDARD's pool and
/// layout (see the module's docs).
pub async fn load<C: GenericClient>(client: &C) -> anyhow::Result<BTreeMap<String, Class>> {
    let rows = client
        .query_cached(
            "SELECT name, pool, data_shards, parity_shards, tier, rank, tolerate FROM storage_classes",
            &[],
        )
        .await?;
    let mut classes: BTreeMap<String, Class> = rows
        .iter()
        .map(|r| {
            let class = Class {
                name: r.get(0),
                pool: r.get(1),
                data_shards: r.get::<_, Option<i16>>(2).map(|k| k as u32),
                parity_shards: r.get::<_, Option<i16>>(3).map(|m| m as u32),
                tier: r.get(4),
                rank: r.get(5),
                tolerance: Tolerance::from_counts(&r.get::<_, Vec<i16>>(6)),
            };
            (class.name.clone(), class)
        })
        .collect();
    let standard = classes
        .get(STANDARD)
        .cloned()
        .unwrap_or_else(Class::standard);
    for class in classes.values_mut() {
        if class.tier.is_some() {
            class.pool = standard.pool.clone();
            class.data_shards = standard.data_shards;
            class.parity_shards = standard.parity_shards;
            class.tolerance = standard.tolerance;
        }
    }
    Ok(classes)
}

/// The classes as a node last read them (at its last heartbeat, or when a
/// request named one it didn't know).
#[derive(Default)]
pub struct Classes(RwLock<Arc<BTreeMap<String, Class>>>);

impl Classes {
    pub fn set(&self, classes: BTreeMap<String, Class>) {
        *self.0.write().unwrap() = Arc::new(classes);
    }

    pub fn all(&self) -> Arc<BTreeMap<String, Class>> {
        self.0.read().unwrap().clone()
    }

    /// Class `name`, or STANDARD as a fresh cluster has it if this node
    /// doesn't know it (yet).
    pub fn get(&self, name: &str) -> Class {
        let all = self.all();
        match all.get(name).or_else(|| all.get(STANDARD)) {
            Some(class) => class.clone(),
            None => Class::standard(),
        }
    }
}

/// What a write's `x-amz-storage-class` header names: the class to store it
/// in, or `Err` with the name if there's no such class. No header is
/// STANDARD, and so is an undefined class of S3's (see the module's docs).
pub async fn resolve(app: &App, header: Option<&str>) -> anyhow::Result<Result<String, String>> {
    let Some(name) = header.map(str::trim).filter(|n| !n.is_empty()) else {
        return Ok(Ok(STANDARD.to_owned()));
    };
    if app.classes.all().contains_key(name) {
        return Ok(Ok(name.to_owned()));
    }
    // Perhaps defined since this node last read them.
    let classes = load(&app.pool.get().await?).await?;
    let known = classes.contains_key(name);
    app.classes.set(classes);
    Ok(if known {
        Ok(name.to_owned())
    } else if S3_CLASSES.contains(&name) {
        Ok(STANDARD.to_owned())
    } else {
        Err(name.to_owned())
    })
}

/// S3's answer to a write that names a class there's none of.
pub fn invalid(name: &str) -> hyper::Response<http_body_util::Full<hyper::body::Bytes>> {
    crate::s3::util::format_s3_error(
        hyper::StatusCode::BAD_REQUEST,
        "InvalidStorageClass",
        &format!("The storage class you specified is not valid: there's no class {name}"),
    )
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Args, Debug, Serialize, Deserialize)]
pub struct ClassArgs {
    #[command(flatten)]
    #[serde(skip)]
    pub remote: crate::admin::Remote,
    #[command(subcommand)]
    command: ClassCommand,
}

#[derive(Subcommand, Debug, Serialize, Deserialize)]
enum ClassCommand {
    /// List the storage classes: their pools and layouts, the nodes that
    /// have their pools, and how much data they hold.
    List,
    /// Define a storage class, or change one. A change applies to new
    /// objects within a heartbeat, and the packer rewrites the class's
    /// existing data into its new pool and layout over time.
    Set {
        /// Its name, as clients name it in `x-amz-storage-class`, e.g.
        /// STANDARD_IA: capitals, digits and underscores.
        name: String,
        /// The pool its data goes to: nodes' `--data-dir <pool>=<path>`.
        /// A new class needs this or --tier; a tier's class given a pool
        /// has its data copied back from the tier.
        #[arg(long, conflicts_with = "tier")]
        pool: Option<String>,
        /// The remote tier its data goes to (see `cairn tier`), rather than
        /// a pool. Its data waits in STANDARD's pool, and the packer moves
        /// it there.
        #[arg(long)]
        tier: Option<String>,
        /// Data shards its blobs over 64 MiB are erasure-coded into (1 keeps
        /// them replicated), or `default` for the `data-shards` setting.
        #[arg(long)]
        data_shards: Option<String>,
        /// Parity shards of its blobs: the nodes they survive losing (copies
        /// besides the first, if replicated), or `default` for the
        /// `parity-shards` setting.
        #[arg(long)]
        parity_shards: Option<String>,
        /// Its place in the classes' order, the warmest highest (STANDARD
        /// is 0), or `none`. Lifecycle rules transition objects into lower
        /// classes, and a class stands in for those below it: its blobs may
        /// hold their objects' data, as they do until the packer moves it.
        /// No two classes share a rank.
        #[arg(long, allow_hyphen_values = true)]
        rank: Option<String>,
        /// How many failure domains of each level its blobs survive losing,
        /// each on its own: e.g. region=1,zone=2,node=4, of the levels
        /// region, zone, rack, node and disk (see `cairn serve
        /// --location`), or `none`. At most its parity shards each. New
        /// blobs are placed so, or their uploads fail; existing ones are
        /// moved by the mover.
        #[arg(long)]
        tolerate: Option<String>,
    },
    /// Delete a storage class that holds no data and no uploads. STANDARD
    /// can't be deleted.
    Delete { name: String },
}

/// A `--data-shards` or `--parity-shards`: a number, or `default` (`None`).
fn shards_arg(flag: &str, value: &str) -> anyhow::Result<Option<u32>> {
    if value == "default" {
        return Ok(None);
    }
    value
        .parse()
        .map(Some)
        .map_err(|_| anyhow::anyhow!("--{flag} must be a number or `default`, not {value:?}"))
}

/// A `--rank`: a number, or `none` (`None`).
fn rank_arg(value: &str) -> anyhow::Result<Option<i32>> {
    if value == "none" {
        return Ok(None);
    }
    value
        .parse()
        .map(Some)
        .map_err(|_| anyhow::anyhow!("--rank must be a number or `none`, not {value:?}"))
}

/// `cairn class …`, on a node (see `admin`).
pub async fn run(app: &Arc<App>, args: ClassArgs, out: &mut Output) -> anyhow::Result<()> {
    let client = app.pool.get().await?;
    match args.command {
        ClassCommand::List => {
            crate::refresh_settings(app).await?;
            let classes = app.classes.all();
            let rows = client
                .query_cached(
                    "SELECT c.name,
                            (SELECT coalesce(sum(b.size - b.dead_size), 0)::bigint FROM blobs b
                             WHERE b.storage_class = c.name AND b.state = 'committed'),
                            (SELECT coalesce(sum(b.size - b.dead_size), 0)::bigint FROM blobs b
                             WHERE b.storage_class = c.name AND b.state = 'remote')
                     FROM storage_classes c ORDER BY c.name",
                    &[],
                )
                .await?;
            outln!(
                out,
                "{:<24} {:>6} {:<16} {:>6} {:>6} {:>7} {:>16} {:>16}  tolerate",
                "class",
                "rank",
                "pool",
                "data",
                "parity",
                "nodes",
                "bytes",
                "in a tier"
            );
            let shards = |v: Option<u32>| v.map_or("-".to_owned(), |v| v.to_string());
            for r in rows {
                let name: String = r.get(0);
                let (bytes, remote): (i64, i64) = (r.get(1), r.get(2));
                let class = classes
                    .get(&name)
                    .cloned()
                    .unwrap_or_else(|| app.classes.get(&name));
                let (active, live): (i64, i64) = {
                    let row = client
                        .query_one_cached(
                            "SELECT count(*) FILTER (WHERE n.state = 'active'),
                                    count(*) FILTER (WHERE n.state = 'active' AND n.last_seen > NOW() - INTERVAL '10 seconds')
                             FROM node_pools np JOIN nodes n ON n.id = np.node WHERE np.pool = $1",
                            &[&class.pool],
                        )
                        .await?;
                    (row.get(0), row.get(1))
                };
                let place = match &class.tier {
                    Some(tier) => format!("tier:{tier}"),
                    None => class.pool.clone(),
                };
                let rank = class.rank.map_or("-".to_owned(), |r| r.to_string());
                outln!(
                    out,
                    "{name:<24} {rank:>6} {place:<16} {:>6} {:>6} {:>7} {bytes:>16} {remote:>16}  {}",
                    shards(class.data_shards),
                    shards(class.parity_shards),
                    format!("{live}/{active}"),
                    class.tolerance
                );
            }
            outln!(
                out,
                "(rank: the warmest highest, - for none; data, parity: - is the cluster's setting; \
                 nodes: live/active with the pool; a tier's class waits in STANDARD's pool, layout and tolerance)"
            );
        }
        ClassCommand::Set {
            name,
            pool,
            tier,
            data_shards,
            parity_shards,
            rank,
            tolerate,
        } => {
            let change = Change {
                tolerance: tolerate
                    .as_deref()
                    .map(Tolerance::parse)
                    .transpose()
                    .map_err(|e| anyhow::anyhow!("--tolerate: {e}"))?,
                pool,
                tier,
                data_shards: data_shards
                    .as_deref()
                    .map(|v| shards_arg("data-shards", v))
                    .transpose()?,
                parity_shards: parity_shards
                    .as_deref()
                    .map(|v| shards_arg("parity-shards", v))
                    .transpose()?,
                rank: rank.as_deref().map(rank_arg).transpose()?,
            };
            let changed = set(app, &name, change).await?;
            for warning in changed.warnings {
                out.warn(warning);
            }
            outln!(out, "{}", describe(app, &changed.class));
        }
        ClassCommand::Delete { name } => {
            delete(app, &name).await?;
            outln!(out, "deleted {name}");
        }
    }
    Ok(())
}

/// A change to a class, or a new one, as `cairn class set` takes it: what's
/// `None` stays as it is (a new class's, unset). `Some(None)` unsets a
/// layout (back to the settings') or a rank.
#[derive(Debug, Default)]
pub struct Change {
    /// The pool its data goes to; makes a tier's class a pool's again.
    pub pool: Option<String>,
    /// The tier its data goes to (see `tiers`), rather than a pool.
    pub tier: Option<String>,
    pub data_shards: Option<Option<u32>>,
    pub parity_shards: Option<Option<u32>>,
    pub rank: Option<Option<i32>>,
    /// How many failure domains of each level its blobs survive losing.
    pub tolerance: Option<Tolerance>,
}

/// A class as it is after a change, and what's wrong with where it keeps
/// its data (see [`placement_warnings`]), if anything.
pub struct Changed {
    pub class: Class,
    pub warnings: Vec<String>,
}

/// A request that can't be carried out as asked: the console's API answers
/// it with a 400, the CLI prints it.
pub(crate) fn bad_input(message: impl Into<String>) -> anyhow::Error {
    crate::managed::Refused::Invalid(message.into()).into()
}

/// Defines class `name`, or changes it, as `change` says (see the module's
/// docs). This node goes by the change right away, the others within a
/// heartbeat.
pub async fn set(app: &App, name: &str, change: Change) -> anyhow::Result<Changed> {
    use crate::managed::Refused;
    let Change {
        pool,
        tier,
        data_shards,
        parity_shards,
        rank,
        tolerance,
    } = change;
    if !valid_name(name) {
        return Err(bad_input(
            "a class's name is up to 64 capitals, digits and underscores, starting with a capital",
        ));
    }
    if pool.is_some() && tier.is_some() {
        return Err(bad_input(
            "a class keeps its data in a pool or in a tier, not both",
        ));
    }
    if let Some(pool) = &pool
        && !valid_pool(pool)
    {
        return Err(bad_input(
            "a pool's name is up to 32 lowercase letters, digits, - and _, starting with a letter or digit",
        ));
    }
    let max_data = crate::shards::MAX_DATA_SHARDS;
    if let Some(Some(k)) = data_shards
        && !(1..=max_data).contains(&k)
    {
        return Err(bad_input(format!(
            "data shards must be between 1 and {max_data}"
        )));
    }
    if let Some(Some(m)) = parity_shards
        && m > 16
    {
        return Err(bad_input("parity shards must be between 0 and 16"));
    }
    let data = data_shards.map(|k| k.map(|k| k as i16));
    let parity = parity_shards.map(|m| m.map(|m| m as i16));
    let client = app.pool.get().await?;
    if let Some(Some(rank)) = rank {
        let taken: Option<String> = client
            .query_opt_cached(
                "SELECT name FROM storage_classes WHERE rank = $1 AND name <> $2",
                &[&rank, &name],
            )
            .await?
            .map(|r| r.get(0));
        if let Some(other) = taken {
            return Err(Refused::Conflict(format!(
                "{other} has rank {rank} already: no two classes share one"
            ))
            .into());
        }
    }
    if let Some(tier) = &tier {
        if name == STANDARD {
            return Err(bad_input(
                "STANDARD can't be a tier's: tiers' classes wait in its pool",
            ));
        }
        if data.is_some() || parity.is_some() || tolerance.is_some_and(|t| t.any()) {
            return Err(bad_input(
                "a tier's class goes by STANDARD's layout: it has no data or parity shards, \
                 or tolerance, of its own",
            ));
        }
        let exists = client
            .query_opt_cached("SELECT 1 FROM tiers WHERE name = $1", &[tier])
            .await?
            .is_some();
        if !exists {
            return Err(bad_input(format!(
                "there's no tier {tier} (cairn tier add)"
            )));
        }
    }
    let existing = app.classes.all().get(name).cloned();
    let existing = match existing {
        Some(class) => Some(class),
        // Perhaps defined since this node last read them.
        None => load(&client).await?.remove(name),
    };
    // Its tolerance may be no more than its parity shards, as they'll be.
    if existing.as_ref().is_none_or(|c| c.tier.is_none()) || pool.is_some() {
        let parity = match parity_shards {
            Some(Some(m)) => m,
            Some(None) => app.parity_shards(),
            None => existing
                .as_ref()
                .filter(|c| c.tier.is_none())
                .and_then(|c| c.parity_shards)
                .unwrap_or_else(|| app.parity_shards()),
        };
        let tolerance = tolerance
            .or_else(|| existing.as_ref().map(|c| c.tolerance))
            .unwrap_or_default();
        if tolerance.max() > parity {
            return Err(bad_input(format!(
                "{name} would have {parity} parity shards, and a blob survives losing no more \
                 shards than that: it can't tolerate {tolerance}"
            )));
        }
    }
    let tolerate = tolerance.map(|t| t.counts());
    let existing = existing.is_some();
    let mut warnings = Vec::new();
    if existing {
        // A pool makes it a pool's class again; a tier, a tier's.
        client
            .execute_cached(
                "UPDATE storage_classes SET
                     pool = coalesce($2, pool),
                     data_shards = CASE WHEN $3 THEN $4 ELSE data_shards END,
                     parity_shards = CASE WHEN $5 THEN $6 ELSE parity_shards END,
                     tier = CASE WHEN $2 IS NOT NULL THEN NULL ELSE coalesce($7, tier) END,
                     rank = CASE WHEN $8 THEN $9 ELSE rank END,
                     tolerate = coalesce($10, tolerate)
                 WHERE name = $1",
                &[
                    &name,
                    &pool,
                    &data.is_some(),
                    &data.flatten(),
                    &parity.is_some(),
                    &parity.flatten(),
                    &tier,
                    &rank.is_some(),
                    &rank.flatten(),
                    &tolerate,
                ],
            )
            .await?;
    } else {
        // A tier's class's own pool is STANDARD's, as it was when it was
        // made; it goes by STANDARD's as it is (see `load`).
        let pool = match (&pool, &tier) {
            (Some(pool), _) => pool.clone(),
            (None, Some(_)) => app.classes.get(STANDARD).pool,
            (None, None) => return Err(bad_input("a new class needs a pool or a tier")),
        };
        client
            .execute_cached(
                "INSERT INTO storage_classes (name, pool, data_shards, parity_shards, tier, rank, tolerate)
                 VALUES ($1, $2, $3, $4, $5, $6, coalesce($7::smallint[], '{0,0,0,0,0}'))",
                &[
                    &name,
                    &pool,
                    &data.flatten(),
                    &parity.flatten(),
                    &tier,
                    &rank.flatten(),
                    &tolerate,
                ],
            )
            .await?;
        if !S3_CLASSES.contains(&name) {
            warnings.push(format!(
                "{name} isn't one of S3's storage classes: clients that check the names they \
                 send (some SDKs do) may refuse it"
            ));
        }
    }
    crate::refresh_settings(app).await?;
    let class = app.classes.get(name);
    warnings.extend(placement_warnings(app, &client, &class).await?);
    Ok(Changed { class, warnings })
}

/// Deletes class `name`, which must hold no objects, uploads or data.
/// STANDARD can't be deleted.
pub async fn delete(app: &App, name: &str) -> anyhow::Result<()> {
    use crate::managed::Refused;
    if name == STANDARD {
        return Err(bad_input("STANDARD can't be deleted"));
    }
    let client = app.pool.get().await?;
    let deleted = client
        .execute_cached(
            "DELETE FROM storage_classes c WHERE c.name = $1
               AND NOT EXISTS (SELECT 1 FROM objects o WHERE o.storage_class = c.name)
               AND NOT EXISTS (SELECT 1 FROM multipart_uploads u WHERE u.storage_class = c.name)
               AND NOT EXISTS (SELECT 1 FROM blobs b WHERE b.storage_class = c.name)",
            &[&name],
        )
        .await?;
    if deleted == 0 {
        let exists = client
            .query_opt_cached("SELECT 1 FROM storage_classes WHERE name = $1", &[&name])
            .await?
            .is_some();
        return Err(match exists {
            true => Refused::Conflict(format!(
                "{name} still holds objects, uploads or data: delete or copy them into another class first"
            )),
            false => Refused::NoSuch(format!("there's no class {name}")),
        }
        .into());
    }
    crate::refresh_settings(app).await?;
    Ok(())
}

/// A class's pool and layout as this node goes by them, in words.
pub fn describe(app: &App, class: &Class) -> String {
    let rank = match class.rank {
        Some(rank) => format!(", rank {rank}"),
        None => ", no rank".to_owned(),
    };
    if let Some(tier) = &class.tier {
        return format!(
            "{}: tier {tier}, by way of STANDARD's pool {}{rank}",
            class.name, class.pool
        );
    }
    let parity = app.parity_shards_of(class);
    let data = app.coding_of(class);
    let layout = match data {
        Some(k) => format!(
            "blobs over 64 MiB coded {k}+{parity}, smaller ones {} copies",
            parity + 1
        ),
        None => format!("{} copies", parity + 1),
    };
    let tolerance = match class.tolerance.any() {
        true => format!(", surviving the loss of any {}", class.tolerance),
        false => String::new(),
    };
    format!(
        "{}: pool {}, {layout}{tolerance}{rank}",
        class.name, class.pool
    )
}

/// What's wrong with where class `class` keeps its data: its pool has too
/// few active nodes for its blobs' shards (or none that spread them as its
/// tolerance takes, see `topology`), so uploads into it fail, or coding
/// waits, until it has; or losing a single domain that it tolerates the
/// loss of would make it so. For whoever just changed it, or the settings.
pub async fn placement_warnings<C: GenericClient>(
    app: &App,
    client: &C,
    class: &Class,
) -> anyhow::Result<Vec<String>> {
    let nodes = topology::active(client, &class.pool).await?;
    let active = nodes.len();
    let parity = app.parity_shards_of(class);
    let tolerance = class.tolerance;
    let fits = |nodes: &[topology::Candidate], count: u32| {
        topology::choose(nodes, &[], count as usize, &tolerance, parity).is_some()
    };
    let spread = match tolerance.any() {
        true => format!(" spread as its tolerance takes ({tolerance})"),
        false => String::new(),
    };
    let mut warnings = Vec::new();
    if tolerance.max() > parity {
        warnings.push(format!(
            "{} has {parity} parity shards, fewer than its tolerance ({tolerance}) asks: \
             a level tolerates no more losses than that",
            class.name
        ));
    }
    if !fits(&nodes, 1 + parity) {
        warnings.push(format!(
            "{}'s blobs take {} nodes with the pool {}{spread}, but the cluster has {active} active: \
             its uploads fail until it has",
            class.name,
            1 + parity,
            class.pool
        ));
        return Ok(warnings);
    }
    if let Some(data) = app.coding_of(class)
        && !fits(&nodes, data + parity)
    {
        warnings.push(format!(
            "coding {data}+{parity} takes {} nodes with the pool {}{spread}, but the cluster has \
             {active} active: {}'s blobs stay replicated until it has",
            data + parity,
            class.pool,
            class.name
        ));
    } else if class.data_shards.is_some_and(|k| k > 1) && parity == 0 {
        warnings.push(format!(
            "with no parity shards, nothing of {} is coded: it would survive no lost node",
            class.name
        ));
    }
    // The domains whose loss it survives, but whose loss stops its uploads.
    for (level, name) in topology::LEVELS.iter().enumerate() {
        if tolerance.0[level] == 0 {
            continue;
        }
        let mut domains: Vec<&str> = nodes.iter().map(|n| n.domains.0[level].as_str()).collect();
        domains.sort_unstable();
        domains.dedup();
        for domain in domains {
            let rest: Vec<topology::Candidate> = nodes
                .iter()
                .filter(|n| n.domains.0[level] != domain)
                .cloned()
                .collect();
            if !fits(&rest, 1 + parity) {
                let shown = topology::describe_domain(domain);
                warnings.push(format!(
                    "with the {name} {shown} down, {} has too few nodes left for its blobs{spread}: \
                     its data survives that, but its uploads fail until it's back",
                    class.name
                ));
                break;
            }
        }
    }
    Ok(warnings)
}

#[cfg(test)]
mod e2e;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dirs_name_their_pools() {
        let parse = |text: &str| {
            crate::parse_data_dir(text).map(|(pool, path)| (pool, path.display().to_string()))
        };
        assert_eq!(
            parse("/var/lib/cairn"),
            Ok(("default".to_owned(), "/var/lib/cairn".to_owned()))
        );
        assert_eq!(
            parse("hdd=/mnt/disks"),
            Ok(("hdd".to_owned(), "/mnt/disks".to_owned()))
        );
        // Not a pool's name: all of it is the path.
        assert_eq!(parse("/a=b"), Ok(("default".to_owned(), "/a=b".to_owned())));
        assert!(
            parse("HDD=/x").is_err(),
            "a pool's name, but not a valid one"
        );
        assert!(parse("hdd=").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn names() {
        for name in ["STANDARD", "STANDARD_IA", "HDD2", "A"] {
            assert!(valid_name(name), "{name}");
        }
        for name in ["", "standard", "2HDD", "STANDARD-IA", &"A".repeat(65)] {
            assert!(!valid_name(name), "{name}");
        }
        for pool in ["default", "ssd", "hdd-2", "nvme_0", "0"] {
            assert!(valid_pool(pool), "{pool}");
        }
        for pool in ["", "SSD", "-x", "a b", "a=b", &"a".repeat(33)] {
            assert!(!valid_pool(pool), "{pool}");
        }
    }

    #[test]
    fn higher_classes_stand_in_for_lower_ones() {
        let class = |name: &str, rank: Option<i32>| {
            (
                name.to_owned(),
                Class {
                    name: name.to_owned(),
                    rank,
                    ..Class::standard()
                },
            )
        };
        let classes: BTreeMap<String, Class> = [
            class("FAST", Some(10)),
            class("STANDARD", Some(0)),
            class("COLD", Some(-10)),
            class("ODD", None),
        ]
        .into_iter()
        .collect();
        assert!(stands_in(&classes, "STANDARD", "STANDARD"));
        assert!(stands_in(&classes, "FAST", "COLD"));
        assert!(stands_in(&classes, "STANDARD", "COLD"));
        assert!(!stands_in(&classes, "COLD", "STANDARD"));
        // Unranked: only itself.
        assert!(stands_in(&classes, "ODD", "ODD"));
        assert!(!stands_in(&classes, "ODD", "COLD"));
        assert!(!stands_in(&classes, "FAST", "ODD"));
        // Unknown classes stand in for nothing.
        assert!(!stands_in(&classes, "FAST", "GONE"));
    }
}
