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

use std::collections::{HashMap, HashSet};
use std::fmt;

use deadpool_postgres::GenericClient;

use crate::{App, classes::Class, db::Cached};

/// The levels, the widest first.
pub const LEVELS: [&str; 5] = ["region", "zone", "rack", "node", "disk"];
const REGION: usize = 0;
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

/// How many choices `choose` tries at most, before it gives up: a few
/// tens of milliseconds' worth.
const MAX_STEPS: usize = 20_000;

/// Chooses `count` of `candidates` (each a node of its own, the most free
/// space first) for shards of a blob of `parity` parity shards, besides
/// those it has on nodes in `fixed`, so that all of them keep the rule of
/// `tolerance`. Their indexes, as near the candidates' order as the rule
/// lets them be: unless it's in the way, the first `count`. `None` if
/// there's no such choice (or none was found within `MAX_STEPS`).
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
    let mut search = Search {
        candidates,
        fixed,
        tolerance,
        parity,
        groups: groups(candidates),
        chosen: Vec::new(),
        seen: HashSet::new(),
        steps: 0,
    };
    let mut taken = vec![0; search.groups.len()];
    search.extend(&mut taken, count).then_some(search.chosen)
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

/// The candidates by what they're alike in: the same domains of the levels
/// that can tell them apart. A node's own node label (empty) or disk is no
/// other's, and never holds another shard of the blob, so nodes that differ
/// only in those are alike. Each group's indexes, in the candidates' order;
/// the groups in the order of their first.
fn groups(candidates: &[Candidate]) -> Vec<Vec<usize>> {
    let mut by_key: HashMap<[&str; 4], usize> = HashMap::new();
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for (i, c) in candidates.iter().enumerate() {
        let d = &c.domains.0;
        let node = if d[NODE].starts_with('#') {
            "#"
        } else {
            &d[NODE]
        };
        let key = [d[REGION].as_str(), d[1].as_str(), d[2].as_str(), node];
        let group = *by_key.entry(key).or_insert_with(|| {
            groups.push(Vec::new());
            groups.len() - 1
        });
        groups[group].push(i);
    }
    groups
}

struct Search<'a> {
    candidates: &'a [Candidate],
    fixed: &'a [Domains],
    tolerance: &'a Tolerance,
    parity: u32,
    groups: Vec<Vec<usize>>,
    /// The candidates chosen so far.
    chosen: Vec<usize>,
    /// How many of each group were taken, in choices that led nowhere.
    seen: HashSet<Vec<usize>>,
    steps: usize,
}

impl Search<'_> {
    /// Chooses `left` more, after `taken` of each group (the first of each,
    /// in `chosen`): each time, the next node of the group whose next is
    /// first among the candidates that keep the rule, and then the rest,
    /// backing out of choices that leave none.
    fn extend(&mut self, taken: &mut Vec<usize>, left: usize) -> bool {
        if left == 0 {
            return true;
        }
        if self.seen.contains(taken) {
            return false;
        }
        // Each group's next node, the first first.
        let mut next: Vec<(usize, usize)> = (0..self.groups.len())
            .filter_map(|g| self.groups[g].get(taken[g]).map(|&i| (i, g)))
            .collect();
        next.sort_unstable();
        for (i, g) in next {
            if self.steps >= MAX_STEPS {
                return false;
            }
            self.steps += 1;
            self.chosen.push(i);
            let shards = self
                .fixed
                .iter()
                .chain(self.chosen.iter().map(|&i| &self.candidates[i].domains));
            if excess(shards, self.tolerance, self.parity) == [0; 5] {
                taken[g] += 1;
                if self.extend(taken, left - 1) {
                    return true;
                }
                taken[g] -= 1;
            }
            self.chosen.pop();
        }
        self.seen.insert(taken.clone());
        false
    }
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
