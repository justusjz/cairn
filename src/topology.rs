//! Where nodes are, and how a blob's shards are spread over them so that it
//! survives the failures its storage class says it must.
//!
//! ## Locations
//!
//! Every node says where it is with `--location`: a path of four labels,
//! `region/zone/rack/node`, e.g. `eu-nbg/zone-4/rack-5/host-1`. Each is a
//! **level** of failure domains, from the widest to the narrowest:
//!
//! | Level  | What fails together |
//! | ------ | ------------------- |
//! | region | distant cities: a wide disaster |
//! | zone   | close together, but power and cooling of its own |
//! | rack   | within a zone, but its own router and power supplies |
//! | node   | a machine: its OS, its reboots |
//! | disk   | a disk of a machine |
//!
//! A node has one data dir per pool, so for now a Cairn node is a disk:
//! the disk level holds one shard per Cairn node, as ever. Several Cairn
//! nodes on one machine (a disk each) share its `node` label.
//!
//! A label may be empty, for a level the operator doesn't tell apart. An
//! empty region, zone or rack is its parent's: with no zones, each region
//! is a single zone. That's the cautious reading: Cairn doesn't take nodes
//! it knows nothing about as independent. An empty node label is the Cairn
//! node's own (each Cairn node is a machine of its own, as before
//! locations), so a cluster without locations is one region, zone and
//! rack, of a node per Cairn node.
//!
//! ## Tolerances
//!
//! A storage class may say how many failure domains of each level its blobs
//! survive losing (`--tolerate region=1,zone=2,node=4`): each a scenario of
//! its own, not all of them at once. A blob of *m* parity shards survives
//! losing a set of domains as long as they hold no more than *m* of its
//! shards, so it survives losing any *t* domains of a level if **its *t*
//! domains of that level that hold the most of its shards hold at most *m*
//! of them**. That's the rule, one per level. A level's tolerance is at
//! most *m* (more could never hold); one of 0 says nothing.
//!
//! The rule only caps how many shards a domain may hold: within it, shards
//! go to the nodes with the most free space, as before, and aren't spread
//! further than asked.
//!
//! A new blob is placed strictly: if no choice of nodes keeps the rule, its
//! upload fails, as when there are too few nodes. A shard that moves (off a
//! node that's down or being removed, or a copy that's added) goes where it
//! breaks the rule least, the widest level first, so that repair never
//! waits on it; the mover moves blobs that break it again once a better
//! place is there (see `mover`).

use std::collections::HashMap;
use std::fmt;

use deadpool_postgres::GenericClient;

use crate::{App, classes::Class, db::Cached};

/// The levels, the widest first.
pub const LEVELS: [&str; 5] = ["region", "zone", "rack", "node", "disk"];
const NODE: usize = 3;
const DISK: usize = 4;

/// A node's `--location`: its labels of the levels but the disk, which is
/// the node's data dir in a pool (see the module's docs).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Location(pub [String; 4]);

impl Location {
    /// A `--location`: `region/zone/rack/node`, of which the narrowest may
    /// be left out (`eu-nbg` is `eu-nbg///`), and any be empty.
    pub fn parse(text: &str) -> Result<Location, String> {
        let text = text.trim();
        let parts: Vec<&str> = if text.is_empty() {
            Vec::new()
        } else {
            text.split('/').collect()
        };
        if parts.len() > 4 {
            return Err(format!(
                "a location is up to four labels, region/zone/rack/node, not {}",
                parts.len()
            ));
        }
        let mut labels: [String; 4] = Default::default();
        for (label, part) in labels.iter_mut().zip(parts) {
            if !valid_label(part) {
                return Err(format!(
                    "{part:?} can't be a location's label: up to 64 letters, digits, ., - and _"
                ));
            }
            *label = part.to_owned();
        }
        Ok(Location(labels))
    }

    /// From the database (`nodes.location`): anything else but four labels
    /// is none (a row of an older node, say).
    pub fn from_labels(labels: Vec<String>) -> Location {
        match <[String; 4]>::try_from(labels) {
            Ok(labels) => Location(labels),
            Err(_) => Location::default(),
        }
    }

    pub fn labels(&self) -> Vec<String> {
        self.0.to_vec()
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.join("/"))
    }
}

fn valid_label(label: &str) -> bool {
    label.len() <= 64
        && label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// The failure domains a node is in, one per level: two nodes are in the
/// same domain of a level if they have the same key for it (see the
/// module's docs for empty labels).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Domains(pub [String; 5]);

impl Domains {
    /// Those of node `node`, at `location`.
    pub fn of(node: i32, location: &Location) -> Domains {
        let labels = &location.0;
        let mut keys: [String; 5] = Default::default();
        // Each wider level's key, and the label: an empty label is its
        // parent's domain. Labels hold no `/`.
        let mut key = String::new();
        for level in 0..NODE {
            key.push('/');
            key.push_str(&labels[level]);
            keys[level] = key.clone();
        }
        keys[NODE] = match labels[NODE].as_str() {
            // The Cairn node's own (`#` is no label's).
            "" => format!("#{node}"),
            label => format!("{key}/{label}"),
        };
        keys[DISK] = format!("#{node}");
        Domains(keys)
    }
}

/// A domain's key (see [`Domains`]), as an operator would name it.
pub fn describe_domain(key: &str) -> String {
    if let Some(node) = key.strip_prefix('#') {
        return format!("of node {node}");
    }
    match key.trim_start_matches('/') {
        "" => "without a label".to_owned(),
        path => path.to_owned(),
    }
}

/// How many domains of each level a class's blobs survive losing, the
/// widest first (see the module's docs).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Tolerance(pub [u32; 5]);

impl Tolerance {
    /// A `--tolerate`: `level=n` for the levels to tolerate losses of,
    /// comma-separated (`region=1,node=2`); `none`, or nothing, tolerates
    /// none.
    pub fn parse(text: &str) -> Result<Tolerance, String> {
        let mut tolerance = Tolerance::default();
        let text = text.trim();
        if text.is_empty() || text == "none" {
            return Ok(tolerance);
        }
        for part in text.split(',') {
            let Some((level, count)) = part.split_once('=') else {
                return Err(format!(
                    "{part:?} isn't level=count, e.g. region=1 (levels: {})",
                    LEVELS.join(", ")
                ));
            };
            let Some(i) = LEVELS.iter().position(|l| *l == level.trim()) else {
                return Err(format!(
                    "there's no level {:?}: the levels are {}",
                    level.trim(),
                    LEVELS.join(", ")
                ));
            };
            tolerance.0[i] = count
                .trim()
                .parse()
                .ok()
                .filter(|n| *n <= 16)
                .ok_or_else(|| format!("{level}'s count must be between 0 and 16"))?;
        }
        Ok(tolerance)
    }

    /// From the database (`storage_classes.tolerate`).
    pub fn from_counts(counts: &[i16]) -> Tolerance {
        let mut tolerance = Tolerance::default();
        for (t, n) in tolerance.0.iter_mut().zip(counts) {
            *t = (*n).max(0) as u32;
        }
        tolerance
    }

    pub fn counts(&self) -> Vec<i16> {
        self.0.iter().map(|t| *t as i16).collect()
    }

    /// Whether it asks for anything.
    pub fn any(&self) -> bool {
        self.0.iter().any(|t| *t > 0)
    }

    /// The most of any level.
    pub fn max(&self) -> u32 {
        self.0.iter().copied().max().unwrap_or(0)
    }
}

impl fmt::Display for Tolerance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> = LEVELS
            .iter()
            .zip(self.0)
            .filter(|(_, t)| *t > 0)
            .map(|(level, t)| format!("{level}={t}"))
            .collect();
        match parts.is_empty() {
            true => f.write_str("none"),
            false => f.write_str(&parts.join(",")),
        }
    }
}

/// How far the shards in `shards` (their nodes' domains) break the rule of
/// `tolerance` for a blob of `parity` parity shards: for each level, the
/// widest first, how many more shards than `parity` its most loaded
/// domains hold. All zeros keeps it; compared as they are, the less the
/// better.
pub fn excess<'a>(
    shards: impl IntoIterator<Item = &'a Domains> + Clone,
    tolerance: &Tolerance,
    parity: u32,
) -> [u32; 5] {
    let mut excess = [0; 5];
    for (level, out) in excess.iter_mut().enumerate() {
        let t = tolerance.0[level].min(parity) as usize;
        if t == 0 {
            continue;
        }
        let mut counts: HashMap<&str, u32> = HashMap::new();
        for domains in shards.clone() {
            *counts.entry(domains.0[level].as_str()).or_default() += 1;
        }
        *out = top_sum(counts.into_values().collect(), t).saturating_sub(parity);
    }
    excess
}

/// The sum of the `t` largest of `counts`.
fn top_sum(mut counts: Vec<u32>, t: usize) -> u32 {
    counts.sort_unstable_by(|a, b| b.cmp(a));
    counts.iter().take(t).sum()
}

/// A node a shard may go to.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub node: i32,
    pub peer_url: String,
    pub domains: Domains,
}

/// Chooses `count` of `candidates` (each a node of its own, the most free
/// space first) for shards of a blob of `parity` parity shards, besides
/// those it has on nodes in `fixed`, so that all of them keep the rule of
/// `tolerance`. Their indexes, in order: of the choices that keep it, the
/// one nearest the candidates' order (the least sum of their places in
/// it), so unless the rule is in the way, the first `count`. `None` if
/// there's no such choice. Exact (see [`solve`]).
pub fn choose(
    candidates: &[Candidate],
    fixed: &[Domains],
    count: usize,
    tolerance: &Tolerance,
    parity: u32,
) -> Option<Vec<usize>> {
    if candidates.len() < count || !may_hold(candidates, fixed, count, tolerance, parity) {
        return None;
    }
    // The first `count`, if they keep it, as they do unless the rule is in
    // the way: the best there is.
    let first = fixed
        .iter()
        .chain(candidates[..count].iter().map(|c| &c.domains));
    if excess(first, tolerance, parity) == [0; 5] {
        return Some((0..count).collect());
    }
    let items: Vec<Item> = fixed
        .iter()
        .map(|domains| Item {
            domains,
            cost: 0,
            forced: true,
        })
        .chain(candidates.iter().enumerate().map(|(i, c)| Item {
            domains: &c.domains,
            cost: i as u64,
            forced: false,
        }))
        .collect();
    let limits = [Some(parity); 5];
    let chosen = solve(
        &items,
        fixed.len() + count,
        tolerance,
        parity,
        limits,
        false,
    )?;
    Some(
        chosen
            .into_iter()
            .filter(|&i| i >= fixed.len())
            .map(|i| i - fixed.len())
            .collect(),
    )
}

/// Where a blob's shards are to be, now on the nodes `nodes` marks as
/// `held` (the others the candidates, the most free space first), for a
/// blob of `parity` parity shards and its class's `tolerance`: of the
/// placements on `nodes` that break the rule least (see [`excess`], the
/// widest level first), the one that moves the fewest shards, and of
/// those, the one nearest the candidates' order. The indexes of the nodes
/// to hold them, in order, and how far that breaks the rule. A blob that
/// keeps the rule, or can't do better, is where it is.
pub fn plan(
    nodes: &[Candidate],
    held: &[bool],
    tolerance: &Tolerance,
    parity: u32,
) -> (Vec<usize>, [u32; 5]) {
    let now: Vec<usize> = (0..nodes.len()).filter(|&i| held[i]).collect();
    let current = excess(now.iter().map(|&i| &nodes[i].domains), tolerance, parity);
    if current == [0; 5] {
        return (now, current);
    }
    let items: Vec<Item> = nodes
        .iter()
        .enumerate()
        .map(|(i, n)| Item {
            domains: &n.domains,
            // A shard that stays costs nothing; a move more than any choice
            // of the candidates' order could.
            cost: if held[i] { 0 } else { (1 << 32) + i as u64 },
            forced: false,
        })
        .collect();
    let count = now.len();
    // The least excess of each level in turn, given the wider levels'.
    let mut limits: [Option<u32>; 5] = [None; 5];
    let mut least = [0u32; 5];
    for level in 0..LEVELS.len() {
        if tolerance.0[level].min(parity) == 0 {
            continue;
        }
        least[level] = (0..=count as u32)
            .find(|&e| {
                limits[level] = Some(parity + e);
                solve(&items, count, tolerance, parity, limits, true).is_some()
            })
            .unwrap_or(count as u32);
        limits[level] = Some(parity + least[level]);
    }
    match solve(&items, count, tolerance, parity, limits, false) {
        Some(chosen) => (chosen, least),
        None => (now, current),
    }
}

/// Whether the rule may let `fixed` and `count` more shards be on the
/// candidates, as far as a quick bound tells: if not, no choice does. At a
/// level of tolerance *t* (of *m* parity shards), the *t* domains holding
/// the most hold *m* at most, and every other domain no more than the
/// least of them, so *m* / *t* at most, and no more than it has nodes for.
fn may_hold(
    candidates: &[Candidate],
    fixed: &[Domains],
    count: usize,
    tolerance: &Tolerance,
    parity: u32,
) -> bool {
    let total = (fixed.len() + count) as u32;
    (0..LEVELS.len()).all(|level| {
        let t = tolerance.0[level].min(parity);
        if t == 0 {
            return true;
        }
        let mut room: HashMap<&str, u32> = HashMap::new();
        let domains = fixed.iter().chain(candidates.iter().map(|c| &c.domains));
        for d in domains {
            *room.entry(d.0[level].as_str()).or_default() += 1;
        }
        let each = parity / t;
        let mut rest: Vec<u32> = room.into_values().map(|n| n.min(each)).collect();
        // The domains beyond the most loaded t hold at most what all but
        // the t of the least room could.
        rest.sort_unstable();
        let beyond: u32 = rest.iter().skip(t as usize).sum();
        parity + beyond >= total
    })
}

/// A node that [`solve`] may choose.
struct Item<'a> {
    domains: &'a Domains,
    /// What choosing it costs: the less, the better.
    cost: u64,
    /// Whether it has to be chosen (holds a shard already).
    forced: bool,
}

/// The nodes as their domains nest: regions of zones of racks of nodes of
/// disks, of items.
enum Tree {
    Item(usize),
    Domain { level: usize, children: Vec<Tree> },
}

/// The trees of `items` (indexes into them) below a domain of the level
/// above `level`: a domain of `level` for each of their keys, in the order
/// of their first item.
fn build(items: &[Item], indexes: Vec<usize>, level: usize) -> Vec<Tree> {
    if level == LEVELS.len() {
        return indexes.into_iter().map(Tree::Item).collect();
    }
    let mut groups: Vec<(&str, Vec<usize>)> = Vec::new();
    for i in indexes {
        let key = items[i].domains.0[level].as_str();
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, group)) => group.push(i),
            None => groups.push((key, vec![i])),
        }
    }
    groups
        .into_iter()
        .map(|(_, group)| Tree::Domain {
            level,
            children: build(items, group, level + 1),
        })
        .collect()
}

/// A way of choosing items within a tree: how many, and how much overflow
/// of each level (see [`solve`]) they take; what it costs, and which they
/// are (in order).
type Key = (u8, [u8; 5]);
#[derive(Clone)]
struct Way {
    cost: u64,
    chosen: Vec<u16>,
}
/// The cheapest way for each key.
type Ways = HashMap<Key, Way>;

impl Way {
    /// Whether it's better than `other`: cheaper, or as cheap and earlier.
    fn beats(&self, other: &Way) -> bool {
        (self.cost, &self.chosen) < (other.cost, &other.chosen)
    }
}

/// What [`solve`] fixes for each choice of caps.
struct Caps {
    /// The levels with a rule that may bind, and their tolerance.
    t: [u32; 5],
    /// Each such level's cap λ, and the overflow above the caps its
    /// domains may have together.
    cap: [u32; 5],
    budget: [u32; 5],
    count: usize,
}

/// Chooses `count` of `items` (all those `forced`, and the cheapest choice
/// of the rest) so that at each level, the `tolerance` (of `parity` parity
/// shards, no more) domains holding the most of them hold no more than its
/// `limits` (none: as many as they like). The items chosen, in order;
/// with `any`, the first choice found, rather than the cheapest.
///
/// Exact, by way of a fact about the most loaded domains: *t* of them hold
/// at most *L* if and only if there's a cap λ such that *t*·λ plus how far
/// all of the domains go above λ, together, is at most *L* (λ the *t*-th
/// most loaded's count does it). For each choice of caps, one per level
/// whose rule may bind, that's a budget of overflow per level, which each
/// domain spends on its own, so the cheapest choice that keeps to the
/// budgets is found by going up the tree of domains, combining the
/// cheapest ways of choosing each number of items, with each overflow
/// spent, of each domain's children. That takes time in proportion to the
/// nodes, times the ways' number (shards, times the budgets' sizes: small,
/// since overflow is at most the parity shards), squared, times the
/// choices of caps (at most *m* / *t* + 1 per level): polynomial in the
/// cluster's size, whatever the rule, and with nothing left out.
fn solve(
    items: &[Item],
    count: usize,
    tolerance: &Tolerance,
    parity: u32,
    limits: [Option<u32>; 5],
    any: bool,
) -> Option<Vec<usize>> {
    let forced = items.iter().filter(|i| i.forced).count();
    if forced > count || items.len() < count || count > u8::MAX as usize {
        return None;
    }
    // The levels whose rule may bind: one that the domains' sizes can't
    // break needs no caps.
    let mut t = [0u32; 5];
    for level in 0..LEVELS.len() {
        let (tl, Some(limit)) = (tolerance.0[level].min(parity), limits[level]) else {
            continue;
        };
        if tl == 0 {
            continue;
        }
        let mut sizes: HashMap<&str, u32> = HashMap::new();
        for item in items {
            *sizes.entry(item.domains.0[level].as_str()).or_default() += 1;
        }
        let mut sizes: Vec<u32> = sizes.into_values().map(|s| s.min(count as u32)).collect();
        if top_sum(std::mem::take(&mut sizes), tl as usize) > limit {
            t[level] = tl;
        }
    }
    let levels: Vec<usize> = (0..LEVELS.len()).filter(|&l| t[l] > 0).collect();
    // λ ranges over 0..=limit / t, no more than `count` (above it, no
    // domain overflows).
    let most = |l: usize| (limits[l].unwrap() / t[l]).min(count as u32);
    let trees = build(items, (0..items.len()).collect(), 0);
    // As good as it gets: the forced items and the cheapest of the rest.
    let mut costs: Vec<u64> = items.iter().filter(|i| !i.forced).map(|i| i.cost).collect();
    costs.sort_unstable();
    let floor: u64 = items
        .iter()
        .filter(|i| i.forced)
        .map(|i| i.cost)
        .sum::<u64>()
        + costs.iter().take(count - forced).sum::<u64>();
    let mut best: Option<Way> = None;
    let mut cap = [0u32; 5];
    loop {
        let mut budget = [0u32; 5];
        for &l in &levels {
            budget[l] = limits[l].unwrap() - t[l] * cap[l];
        }
        let caps = Caps {
            t,
            cap,
            budget,
            count,
        };
        let mut ways = start();
        for tree in &trees {
            ways = combine(&ways, &eval(tree, items, &caps), &caps);
        }
        if let Some(way) = ways
            .into_iter()
            .filter(|((n, _), _)| *n as usize == count)
            .map(|(_, way)| way)
            .reduce(|a, b| if b.beats(&a) { b } else { a })
            && best.as_ref().is_none_or(|b| way.beats(b))
        {
            let done = any || way.cost == floor;
            best = Some(way);
            if done {
                break;
            }
        }
        // The next choice of caps.
        let Some(&l) = levels.iter().find(|&&l| cap[l] < most(l)) else {
            break;
        };
        cap[l] += 1;
        for &before in levels.iter().take_while(|&&b| b != l) {
            cap[before] = 0;
        }
    }
    best.map(|way| way.chosen.into_iter().map(usize::from).collect())
}

/// The one way of choosing nothing.
fn start() -> Ways {
    HashMap::from([(
        (0, [0; 5]),
        Way {
            cost: 0,
            chosen: Vec::new(),
        },
    )])
}

/// The cheapest ways of choosing items of a tree.
fn eval(tree: &Tree, items: &[Item], caps: &Caps) -> Ways {
    match tree {
        Tree::Item(i) => {
            let mut ways = if items[*i].forced {
                Ways::new()
            } else {
                start()
            };
            ways.insert(
                (1, [0; 5]),
                Way {
                    cost: items[*i].cost,
                    chosen: vec![*i as u16],
                },
            );
            ways
        }
        Tree::Domain { level, children } => {
            let mut ways = start();
            for child in children {
                ways = combine(&ways, &eval(child, items, caps), caps);
            }
            if caps.t[*level] == 0 {
                return ways;
            }
            // The domain's overflow above its level's cap.
            let (cap, budget) = (caps.cap[*level], caps.budget[*level]);
            ways.into_iter()
                .filter_map(|((n, mut spent), way)| {
                    let over = (n as u32).saturating_sub(cap) + spent[*level] as u32;
                    spent[*level] = u8::try_from(over).ok().filter(|o| *o as u32 <= budget)?;
                    Some(((n, spent), way))
                })
                .collect()
        }
    }
}

/// The cheapest ways of choosing items of two disjoint sets of trees.
fn combine(a: &Ways, b: &Ways, caps: &Caps) -> Ways {
    let mut ways = Ways::new();
    for ((na, sa), wa) in a {
        for ((nb, sb), wb) in b {
            let n = na + nb;
            if n as usize > caps.count {
                continue;
            }
            let mut spent = [0u8; 5];
            let mut fits = true;
            for l in 0..LEVELS.len() {
                spent[l] = sa[l].saturating_add(sb[l]);
                fits &= spent[l] as u32 <= caps.budget[l];
            }
            if !fits {
                continue;
            }
            let way = Way {
                cost: wa.cost + wb.cost,
                chosen: merged(&wa.chosen, &wb.chosen),
            };
            match ways.get(&(n, spent)) {
                Some(other) if !way.beats(other) => {}
                _ => {
                    ways.insert((n, spent), way);
                }
            }
        }
    }
    ways
}

/// Two ordered lists, as one.
fn merged(a: &[u16], b: &[u16]) -> Vec<u16> {
    let mut out = Vec::with_capacity(a.len() + b.len());
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        if j == b.len() || (i < a.len() && a[i] < b[j]) {
            out.push(a[i]);
            i += 1;
        } else {
            out.push(b[j]);
            j += 1;
        }
    }
    out
}

/// The best of `candidates` (the most free space first) for one more shard
/// of a blob of `parity` parity shards, whose others are on nodes in
/// `fixed`: the one that breaks the rule of `tolerance` least (see
/// [`excess`]), the first of those. Its index, and how far the blob breaks
/// the rule with it; `None` if there are no candidates.
pub fn best(
    candidates: &[Candidate],
    fixed: &[Domains],
    tolerance: &Tolerance,
    parity: u32,
) -> Option<(usize, [u32; 5])> {
    candidates
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let shards = fixed.iter().chain(std::iter::once(&c.domains));
            (i, excess(shards, tolerance, parity))
        })
        .min_by_key(|(i, excess)| (*excess, *i))
}

/// The nodes that may take shards in pool `pool`: the active, live ones
/// that have it, those with the most free space in it first. Nodes being
/// removed get none (see `mover`).
pub async fn candidates<C: GenericClient>(
    client: &C,
    pool: &str,
) -> anyhow::Result<Vec<Candidate>> {
    let rows = client
        .query_cached(
            "SELECT n.id, n.peer_url, n.location FROM nodes n
             JOIN node_pools np ON np.node = n.id AND np.pool = $1
             WHERE n.state = 'active' AND n.last_seen > NOW() - INTERVAL '10 seconds'
             ORDER BY np.free_space DESC, n.id",
            &[&pool],
        )
        .await?;
    Ok(rows.iter().map(candidate_at).collect())
}

/// As [`candidates`], of the active nodes with pool `pool`, whether or not
/// they're live: those the cluster has for it, as an operator sees it.
pub async fn active<C: GenericClient>(client: &C, pool: &str) -> anyhow::Result<Vec<Candidate>> {
    let rows = client
        .query_cached(
            "SELECT n.id, n.peer_url, n.location FROM nodes n
             JOIN node_pools np ON np.node = n.id AND np.pool = $1
             WHERE n.state = 'active'
             ORDER BY np.free_space DESC, n.id",
            &[&pool],
        )
        .await?;
    Ok(rows.iter().map(candidate_at).collect())
}

fn candidate_at(row: &tokio_postgres::Row) -> Candidate {
    let node: i32 = row.get(0);
    Candidate {
        node,
        peer_url: row.get(1),
        domains: Domains::of(node, &Location::from_labels(row.get(2))),
    }
}

/// The domains of every node, by its number.
pub async fn all_domains<C: GenericClient>(client: &C) -> anyhow::Result<HashMap<i32, Domains>> {
    let rows = client
        .query_cached("SELECT id, location FROM nodes", &[])
        .await?;
    Ok(rows
        .iter()
        .map(|r| {
            let node: i32 = r.get(0);
            (node, Domains::of(node, &Location::from_labels(r.get(1))))
        })
        .collect())
}

/// Whether `count` shards of a blob of class `class`, with `parity` parity
/// shards, can be placed on the live nodes now, keeping its tolerance.
pub async fn placeable(app: &App, class: &Class, count: u32, parity: u32) -> anyhow::Result<bool> {
    let live = candidates(&app.pool.get().await?, &class.pool).await?;
    Ok(choose(&live, &[], count as usize, &class.tolerance, parity).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(node: i32, path: &str) -> Candidate {
        Candidate {
            node,
            peer_url: String::new(),
            domains: Domains::of(node, &Location::parse(path).unwrap()),
        }
    }

    fn tolerate(text: &str) -> Tolerance {
        Tolerance::parse(text).unwrap()
    }

    fn nodes(chosen: &[usize], candidates: &[Candidate]) -> Vec<i32> {
        chosen.iter().map(|&i| candidates[i].node).collect()
    }

    #[test]
    fn locations_parse() {
        let parse = |text: &str| Location::parse(text).map(|l| l.0.to_vec());
        assert_eq!(
            parse("eu-nbg/zone-4/rack-5/host-1"),
            Ok(vec![
                "eu-nbg".into(),
                "zone-4".into(),
                "rack-5".into(),
                "host-1".into()
            ])
        );
        assert_eq!(
            parse("eu-nbg"),
            Ok(vec!["eu-nbg".into(), "".into(), "".into(), "".into()])
        );
        assert_eq!(
            parse("eu-nbg///h1"),
            Ok(vec!["eu-nbg".into(), "".into(), "".into(), "h1".into()])
        );
        assert_eq!(parse(""), Ok(vec!["".into(); 4]));
        assert!(parse("a/b/c/d/e").is_err(), "the disk isn't a label");
        assert!(parse("a b").is_err());
        assert!(parse("#1").is_err(), "# is the nodes' own");
        let location = Location::parse("eu/z1//h").unwrap();
        assert_eq!(Location::parse(&location.to_string()), Ok(location));
    }

    #[test]
    fn empty_labels_are_their_parents() {
        let a = at(1, "eu");
        let b = at(2, "eu");
        let c = at(3, "eu/z1/r1/h1");
        let d = at(4, "eu/z1/r1/h1");
        // The same region, zone and rack, but nodes of their own.
        assert_eq!(a.domains.0[..3], b.domains.0[..3]);
        assert_ne!(a.domains.0[3], b.domains.0[3]);
        // Two Cairn nodes on one machine: one node, two disks.
        assert_eq!(c.domains.0[..4], d.domains.0[..4]);
        assert_ne!(c.domains.0[4], d.domains.0[4]);
        // No zone isn't a zone of its own beside z1.
        assert_eq!(a.domains.0[0], c.domains.0[0]);
        // Labels are within their parents: rack r1 of another zone is
        // another rack.
        assert_ne!(
            at(5, "eu/z1/r1").domains.0[2],
            at(6, "eu/z2/r1").domains.0[2]
        );
    }

    #[test]
    fn tolerances_parse() {
        assert_eq!(tolerate("region=1,zone=2,node=4").0, [1, 2, 0, 4, 0]);
        assert_eq!(tolerate("none"), Tolerance::default());
        assert_eq!(tolerate(""), Tolerance::default());
        assert_eq!(tolerate("region=1,node=2").to_string(), "region=1,node=2");
        assert_eq!(Tolerance::default().to_string(), "none");
        assert!(Tolerance::parse("country=1").is_err());
        assert!(Tolerance::parse("region").is_err());
        assert!(Tolerance::parse("region=x").is_err());
        assert!(Tolerance::parse("region=17").is_err());
    }

    #[test]
    fn the_rule_counts_the_most_loaded_domains() {
        // 4+2 over regions a, a, b, b, c, c: any one region holds 2.
        let shards: Vec<Domains> = ["a", "a", "b", "b", "c", "c"]
            .iter()
            .enumerate()
            .map(|(i, r)| at(i as i32, r).domains)
            .collect();
        assert_eq!(excess(&shards, &tolerate("region=1"), 2), [0; 5]);
        // Any two hold 4: two more than the parity shards.
        assert_eq!(excess(&shards, &tolerate("region=2"), 2), [2, 0, 0, 0, 0]);
        // More than the parity shards is as much as there are.
        assert_eq!(
            excess(&shards, &tolerate("region=2"), 2),
            excess(&shards, &tolerate("region=9"), 2)
        );
        // Nodes of their own: any two nodes hold 2.
        assert_eq!(excess(&shards, &tolerate("node=2,disk=2"), 2), [0; 5]);
        assert_eq!(excess(&shards, &tolerate("node=1"), 0), [0; 5]);
    }

    #[test]
    fn without_a_tolerance_the_freest_nodes_are_chosen() {
        let candidates: Vec<Candidate> = (0..6).map(|i| at(i, "eu")).collect();
        let chosen = choose(&candidates, &[], 3, &Tolerance::default(), 2).unwrap();
        assert_eq!(nodes(&chosen, &candidates), [0, 1, 2]);
        assert!(choose(&candidates, &[], 7, &Tolerance::default(), 2).is_none());
    }

    #[test]
    fn regions_cap_their_shards_but_no_more() {
        // Five regions, two nodes each; the freest are a's and b's.
        let candidates: Vec<Candidate> = ["a", "a", "b", "b", "c", "c", "d", "d", "e", "e"]
            .iter()
            .enumerate()
            .map(|(i, r)| at(i as i32, r))
            .collect();
        // 4+2, surviving any region: two shards a region at most, and the
        // freest nodes otherwise, not one a region.
        let chosen = choose(&candidates, &[], 6, &tolerate("region=1"), 2).unwrap();
        assert_eq!(nodes(&chosen, &candidates), [0, 1, 2, 3, 4, 5]);
        // 3+2, surviving any two regions: one shard each.
        let chosen = choose(&candidates, &[], 5, &tolerate("region=2"), 2).unwrap();
        assert_eq!(nodes(&chosen, &candidates), [0, 2, 4, 6, 8]);
        // 4+2 surviving two regions takes six regions.
        assert!(choose(&candidates, &[], 6, &tolerate("region=2"), 2).is_none());
        // Replicated, 5 copies, surviving four regions: one in each.
        let chosen = choose(&candidates, &[], 5, &tolerate("region=4"), 4).unwrap();
        assert_eq!(nodes(&chosen, &candidates), [0, 2, 4, 6, 8]);
    }

    #[test]
    fn shards_already_placed_count() {
        let candidates: Vec<Candidate> = ["a", "b", "c"]
            .iter()
            .enumerate()
            .map(|(i, r)| at(i as i32, r))
            .collect();
        let fixed = vec![at(10, "a").domains, at(11, "b").domains];
        // A third copy, surviving any two regions: only c.
        let chosen = choose(&candidates, &fixed, 1, &tolerate("region=2"), 2).unwrap();
        assert_eq!(nodes(&chosen, &candidates), [2]);
        assert_eq!(
            best(&candidates, &fixed, &tolerate("region=2"), 2),
            Some((2, [0; 5]))
        );
        // With c gone, the least bad.
        let (i, excess) = best(&candidates[..2], &fixed, &tolerate("region=2"), 2).unwrap();
        assert_eq!((i, excess), (0, [1, 0, 0, 0, 0]));
    }

    #[test]
    fn a_greedy_choice_is_backed_out_of() {
        // Regions a (two zones) and b (one zone, of many nodes): 4 shards,
        // m = 2, surviving any region and any two zones. Taking the freest
        // nodes, b's, fills b's one zone; only a, a, b, b over zones a1, a2
        // and b1 (b1 holding 2) keeps both rules... which it doesn't (two
        // zones hold 3), so it can't be done; with a third zone in b, it can.
        let mut candidates = vec![
            at(0, "b/b1"),
            at(1, "b/b1"),
            at(2, "b/b1"),
            at(3, "a/a1"),
            at(4, "a/a2"),
        ];
        let rule = tolerate("region=1,zone=2");
        assert!(choose(&candidates, &[], 4, &rule, 2).is_none());
        candidates.push(at(5, "b/b2"));
        let chosen = choose(&candidates, &[], 4, &rule, 2).unwrap();
        assert_eq!(nodes(&chosen, &candidates), [0, 3, 4, 5]);
    }

    #[test]
    fn machines_with_several_cairn_nodes() {
        // Three machines, of four Cairn nodes (disks) each; 8+4 surviving
        // any one machine (four shards each at most) and any four disks.
        let candidates: Vec<Candidate> = (0..12)
            .map(|i| at(i, &format!("eu///h{}", i / 4)))
            .collect();
        let chosen = choose(&candidates, &[], 12, &tolerate("node=1,disk=4"), 4).unwrap();
        assert_eq!(chosen.len(), 12);
        // Any two machines: not with three of them.
        assert!(choose(&candidates, &[], 12, &tolerate("node=2"), 4).is_none());
    }

    /// A small, fixed-seed pseudo-random sequence.
    struct Rng(u64);

    impl Rng {
        fn below(&mut self, n: u64) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 % n
        }
    }

    /// Every choice of `k` of `0..n`.
    fn subsets(n: usize, k: usize) -> Vec<Vec<usize>> {
        if k == 0 {
            return vec![Vec::new()];
        }
        if n < k {
            return Vec::new();
        }
        let mut all = subsets(n - 1, k);
        for mut s in subsets(n - 1, k - 1) {
            s.push(n - 1);
            all.push(s);
        }
        all
    }

    fn random_nodes(rng: &mut Rng, n: usize) -> Vec<Candidate> {
        (0..n as i32)
            .map(|i| {
                let host = match rng.below(3) {
                    0 => String::new(),
                    h => format!("h{h}"),
                };
                let path = format!(
                    "r{}/z{}/k{}/{host}",
                    rng.below(3),
                    rng.below(2),
                    rng.below(2)
                );
                at(i, &path)
            })
            .collect()
    }

    #[test]
    fn choices_are_those_of_an_exhaustive_search() {
        let mut rng = Rng(0x5eed);
        for _ in 0..400 {
            let n = 3 + rng.below(7) as usize;
            let nodes = random_nodes(&mut rng, n);
            let count = 2 + rng.below(n as u64 - 1) as usize;
            let parity = 1 + rng.below(count as u64 - 1) as u32;
            let mut tolerance = Tolerance::default();
            for t in &mut tolerance.0 {
                *t = rng.below(parity as u64 + 1) as u32;
            }
            // The keeping choice of the least sum of places, the earliest.
            let expected = subsets(n, count)
                .into_iter()
                .filter(|s| {
                    excess(s.iter().map(|&i| &nodes[i].domains), &tolerance, parity) == [0; 5]
                })
                .min_by_key(|s| (s.iter().sum::<usize>(), s.clone()));
            let chosen = choose(&nodes, &[], count, &tolerance, parity);
            assert_eq!(chosen, expected, "{nodes:?} {count} {tolerance} m={parity}");
        }
    }

    #[test]
    fn plans_are_those_of_an_exhaustive_search() {
        let mut rng = Rng(0xfeed);
        for _ in 0..300 {
            let n = 3 + rng.below(7) as usize;
            let nodes = random_nodes(&mut rng, n);
            let count = 2 + rng.below(n as u64 - 1) as usize;
            let parity = 1 + rng.below(count as u64 - 1) as u32;
            let mut tolerance = Tolerance::default();
            for t in &mut tolerance.0 {
                *t = rng.below(parity as u64 + 1) as u32;
            }
            let all = subsets(n, count);
            let now = &all[rng.below(all.len() as u64) as usize];
            let held: Vec<bool> = (0..n).map(|i| now.contains(&i)).collect();
            let score =
                |s: &[usize]| excess(s.iter().map(|&i| &nodes[i].domains), &tolerance, parity);
            // The least excess, then the fewest moves, then the earliest.
            let expected = all
                .iter()
                .min_by_key(|s| {
                    let moved = s.iter().filter(|i| !held[**i]).count();
                    let places: usize = s.iter().filter(|i| !held[**i]).sum();
                    (score(s), moved, places, (*s).clone())
                })
                .unwrap();
            let (planned, left) = plan(&nodes, &held, &tolerance, parity);
            assert_eq!(left, score(&planned));
            assert_eq!(
                (
                    score(&planned),
                    planned.iter().filter(|i| !held[**i]).count()
                ),
                (
                    score(expected),
                    expected.iter().filter(|i| !held[**i]).count()
                ),
                "{nodes:?} {count} {tolerance} m={parity} from {now:?}: {planned:?}, not {expected:?}"
            );
        }
    }

    #[test]
    fn a_plan_takes_moves_that_help_only_together() {
        // One parity shard, one shard a rack at most: racks k1 and k2 hold
        // two each. Moving one of k1's fixes k1, but k2 still holds two, so
        // the excess (the fullest rack's) doesn't change until a second
        // move: both are planned.
        let nodes = vec![
            at(0, "r/z/k1"),
            at(1, "r/z/k1"),
            at(2, "r/z/k2"),
            at(3, "r/z/k2"),
            at(4, "r/z/k3"),
            at(5, "r/z/k4"),
            at(6, "r/z/k5"),
        ];
        let held = [true, true, true, true, false, false, false];
        let rule = tolerate("rack=1");
        let now: Vec<&Domains> = nodes[..4].iter().map(|n| &n.domains).collect();
        assert_eq!(excess(now, &rule, 1), [0, 0, 1, 0, 0]);
        let (planned, left) = plan(&nodes, &held, &rule, 1);
        assert_eq!(left, [0; 5]);
        assert_eq!(planned, [0, 2, 4, 5], "two shards stay, two move");
        // A blob that keeps the rule stays where it is.
        let held = [true, false, true, false, true, true, false];
        let (planned, _) = plan(&nodes, &held, &rule, 1);
        assert_eq!(planned, [0, 2, 4, 5]);
    }

    #[test]
    fn large_clusters_are_solved_quickly() {
        // 300 nodes in 3 regions of 4 zones of 5 racks of 5 machines, 20
        // shards, a rule at every level.
        let nodes: Vec<Candidate> = (0..300)
            .map(|i| at(i, &format!("r{}/z{}/k{}/h{}", i % 3, i % 12, i % 60, i)))
            .collect();
        let started = std::time::Instant::now();
        let rule = tolerate("region=1,zone=2,rack=4,node=4");
        let chosen = choose(&nodes, &[], 20, &rule, 8).unwrap();
        let shards = chosen.iter().map(|&i| &nodes[i].domains);
        assert_eq!(excess(shards, &rule, 8), [0; 5]);
        assert!(choose(&nodes, &[], 20, &tolerate("region=2"), 8).is_none());
        let elapsed = started.elapsed();
        assert!(elapsed.as_secs() < 2, "{elapsed:?}");
    }

    #[test]
    fn a_large_infeasible_search_ends() {
        // Many alike nodes in one region, a rule that can't hold.
        let candidates: Vec<Candidate> = (0..200).map(|i| at(i, "a")).collect();
        assert!(choose(&candidates, &[], 16, &tolerate("region=1"), 4).is_none());
        let mixed: Vec<Candidate> = (0..200)
            .map(|i| at(i, &format!("r{}/z{}/k{}", i % 3, i % 7, i % 11)))
            .collect();
        assert!(choose(&mixed, &[], 20, &tolerate("region=2,zone=3"), 4).is_none());
    }
}

#[cfg(test)]
mod e2e;
