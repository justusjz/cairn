//! Placement: which nodes a blob's shards go to, spread over the cluster's
//! failure domains.
//!
//! Every node has a **location** (`--location`): a path of failure domains,
//! the widest first, such as `eu-west/eu-west-1a/rack-3/host-7`. Its levels
//! are whatever the operator makes of them (regions, zones, racks, hosts);
//! a node's own place is below its path, so several nodes (Cairn instances
//! on one host, say) may share one. Nodes without a location share the
//! empty path, the root, and a cluster without locations places shards as
//! it always did: each on a node of its own, those with the most free space
//! first.
//!
//! A blob is placed to survive the loss of as many domains as can be, the
//! widest first. With `parity` parity shards, it survives the loss of any t
//! domains of a level if its t fullest there hold `parity` shards at most:
//! its **tolerance** there is the most such t. It's placed with the most
//! tolerance at the first level (regions, say) that any placement has; of
//! those placements, with the most at the second level; and so on: l1 =
//! max l1, l2 = max l2 given l1, l3 = max l3 given l1 and l2. (Being the
//! best at every level at once can be impossible: with a region of one rack
//! of 2 nodes and one of 3 racks of a node each, 2 + 2 survives the loss of
//! a region only as 2 and 2, which puts 2 in a rack; as 1 and 3, it
//! survives the loss of any two racks, but not of the region of 3.) Of the
//! placements that are best so, it takes the most even (per level, the
//! sums of squares of the domains' shards, the widest first), then the one
//! on the emptiest nodes.
//!
//! With 3 copies over 5 regions, that's 3 regions. 6 shards (4 + 2) over 5
//! regions puts 2 in one region, and if only some regions have two racks
//! (or zones), it's one of those, its 2 shards in different racks: in a
//! region of one rack, they'd share it, and that rack with any other is 3
//! shards, more than the blob can lose. However many nodes are added to a
//! region, a blob gets no more of its shards there than that takes. A
//! domain takes no more shards than it has nodes.
//!
//! The best placement is worked out exactly (see `optimize`), not searched
//! for, and is remembered for the nodes, shards and parity shards. A blob
//! that can't be placed as well on its live nodes as on all of the active
//! ones (a region is down, say) is placed as well as the live ones allow,
//! and marked uneven; the mover places it best once it can, moving as few
//! of its shards as that takes (see `mover`), as it does blobs that a
//! change of the nodes (a new region, locations set where there were none)
//! left worse than they could be.

use std::collections::HashMap;

/// The most levels a location may have.
pub const MAX_LEVELS: usize = 8;

/// Checks a location given to `--location`: domains separated by `/`, each
/// of letters, digits, `.`, `_` and `-`, at most 63 characters and
/// starting with a letter or digit, at most [`MAX_LEVELS`] of them. The
/// empty string is no location (the root).
pub fn parse_location(location: &str) -> Result<String, String> {
    if location.is_empty() {
        return Ok(String::new());
    }
    let domains: Vec<&str> = location.split('/').collect();
    if domains.len() > MAX_LEVELS {
        return Err(format!(
            "a location has at most {MAX_LEVELS} levels, e.g. region/zone/rack/host"
        ));
    }
    for domain in &domains {
        let ok = !domain.is_empty()
            && domain.len() <= 63
            && domain.starts_with(|c: char| c.is_ascii_alphanumeric())
            && domain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        if !ok {
            return Err(format!(
                "{domain:?} isn't a valid domain of a location: domains are separated by '/', \
                 and are letters, digits, '.', '_' and '-', starting with a letter or digit, \
                 at most 63 characters"
            ));
        }
    }
    Ok(location.to_owned())
}

/// A node as placement sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub id: i32,
    pub peer_url: String,
    /// Its location's domains, the widest first.
    pub path: Vec<String>,
    /// Whether it's live: only live nodes take new shards.
    pub live: bool,
    /// Its free space in the pool placed in.
    pub free_space: i64,
}

impl Node {
    pub fn new(id: i32, peer_url: String, location: &str, live: bool, free_space: i64) -> Node {
        Node {
            id,
            peer_url,
            path: split(location),
            live,
            free_space,
        }
    }

    /// Its location, as given.
    pub fn location(&self) -> String {
        self.path.join("/")
    }

    /// The domain it's in `depth` levels down: its location's first
    /// `depth` domains, or below the end of its location, itself (it's a
    /// domain of its own there).
    fn domain(&self, depth: usize) -> Domain<'_> {
        match self.path.get(..depth) {
            Some(path) => Domain::Path(path),
            None => Domain::Node(self.id),
        }
    }
}

/// A domain at some level: a prefix of locations, or a node, below the end
/// of its location.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Domain<'a> {
    Path(&'a [String]),
    Node(i32),
}

/// A location's domains.
pub fn split(location: &str) -> Vec<String> {
    if location.is_empty() {
        Vec::new()
    } else {
        location.split('/').map(str::to_owned).collect()
    }
}

/// How evenly a blob whose shards are on `held` is spread, over `levels`
/// levels: for each, its domains' shard counts, the most first. Less is
/// more even: placements that survive as much (see [`tolerance`]) are told
/// apart by it.
pub fn spread_of(held: &[&Node], levels: usize) -> Vec<Vec<usize>> {
    (1..=levels)
        .map(|depth| {
            let mut counts: HashMap<Domain, usize> = HashMap::new();
            for h in held {
                *counts.entry(h.domain(depth)).or_default() += 1;
            }
            let mut counts: Vec<usize> = counts.into_values().collect();
            counts.sort_unstable_by(|a, b| b.cmp(a));
            counts
        })
        .collect()
}

/// How many levels the locations of `nodes` have, at most.
fn levels<'a>(nodes: impl IntoIterator<Item = &'a Node>) -> usize {
    nodes.into_iter().map(|n| n.path.len()).max().unwrap_or(0)
}

/// How many domains a blob with its shards on `held` and `parity` parity
/// shards survives the loss of at each of `levels` levels, widest first:
/// the most domains of the level whose shards, whichever they are, are
/// `parity` at most together. (Below every location, where each node is a
/// domain of its own, it's `parity`.)
pub fn tolerance(held: &[&Node], levels: usize, parity: usize) -> Vec<usize> {
    spread_of(held, levels)
        .iter()
        .map(|counts| {
            let mut lost = 0;
            counts
                .iter()
                .take_while(|&&c| {
                    lost += c;
                    lost <= parity
                })
                .count()
        })
        .collect()
}

/// `tolerance` extended to `levels` levels: those below every location
/// survive the loss of `parity` domains.
fn padded(mut tolerance: Vec<usize>, levels: usize, parity: usize) -> Vec<usize> {
    tolerance.resize(levels.max(tolerance.len()), parity);
    tolerance
}

// The optimizer.
//
// A blob survives the loss of any t domains of a level if its t fullest
// domains there hold `parity` shards at most. The sum of the t largest of
// counts c_i is the least, over integers λ, of t·λ + Σ max(0, c_i − λ) (at
// λ = the t-th largest, it's the sum; at any λ, it's at least the sum). So
// it's `parity` at most if and only if, for some λ ≥ 1 (λ = 0 would take
// every shard, more than `parity`), every domain's shards beyond λ add up
// to at most `parity` − t·λ: its budget. With λ chosen for every level, that's
// a sum over domains, which a dynamic program over the tree of domains
// decides exactly: for each domain and number of shards in it, the least
// overflows (shards beyond λ, per level) that its subtree can have, of all
// ways of placing them. (A budget of 0 makes λ a cap, with nothing to
// track.)
//
// The best placement then comes from the widest level down: the most
// domains of the first level it can survive the loss of, then, of the
// placements that do, the most of the second, and so on: for each level,
// the largest number for which some λ for each level so far is feasible.
// Of the placements that reach those numbers, it takes the one that keeps
// the most of the shards there are already (when spreading a blob), then
// the most even (`spread_of`, as sums of squares, the widest level first),
// then the one on the emptiest nodes.

/// A node that a blob's shards may be placed on.
struct Candidate<'a> {
    node: &'a Node,
    /// It holds a shard already, which may stay.
    held: bool,
    /// Its place by free space among those that don't, the emptiest first.
    rank: u64,
}

/// A domain of the tree of domains, or the root.
struct Vertex {
    depth: usize,
    children: Vec<usize>,
    /// The candidates whose locations end here, the cheapest first.
    leaves: Vec<usize>,
}

/// The tree of the domains of `candidates`; the root is the first.
fn tree(candidates: &[Candidate]) -> Vec<Vertex> {
    let mut vertices = vec![Vertex {
        depth: 0,
        children: Vec::new(),
        leaves: Vec::new(),
    }];
    let mut index: HashMap<&[String], usize> = HashMap::new();
    for (i, c) in candidates.iter().enumerate() {
        let mut at = 0;
        for depth in 1..=c.node.path.len() {
            let prefix = &c.node.path[..depth];
            at = match index.get(prefix) {
                Some(&v) => v,
                None => {
                    vertices.push(Vertex {
                        depth,
                        children: Vec::new(),
                        leaves: Vec::new(),
                    });
                    let v = vertices.len() - 1;
                    vertices[at].children.push(v);
                    index.insert(prefix, v);
                    v
                }
            };
        }
        vertices[at].leaves.push(i);
    }
    for v in &mut vertices {
        v.leaves.sort_by_key(|&i| leaf_cost(&candidates[i]));
    }
    vertices
}

/// What a placement costs beyond its tolerance, the least first: shards
/// moved, then unevenness, then fuller nodes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
struct Cost {
    moved: u32,
    squares: [u32; MAX_LEVELS],
    rank: u64,
}

impl std::ops::Add for Cost {
    type Output = Cost;
    fn add(mut self, other: Cost) -> Cost {
        self.moved += other.moved;
        for (a, b) in self.squares.iter_mut().zip(other.squares) {
            *a += b;
        }
        self.rank += other.rank;
        self
    }
}

fn leaf_cost(c: &Candidate) -> Cost {
    if c.held {
        Cost::default()
    } else {
        Cost {
            moved: 1,
            rank: c.rank,
            ..Cost::default()
        }
    }
}

/// For each level, nothing (the placement needn't survive any loss there),
/// or λ and the budget for the shards beyond it.
type Limits = Vec<Option<(usize, usize)>>;

/// A way of placing some shards in a subtree.
#[derive(Clone)]
struct Entry {
    /// Per level, the shards beyond its λ.
    over: [u8; MAX_LEVELS],
    cost: Cost,
    /// The candidates chosen, when they're tracked.
    picks: Vec<u32>,
}

/// The ways of placing shards in a subtree that are worth keeping: no other
/// overflows no more at every level and costs no more.
fn prune(entries: &mut Vec<Entry>) {
    entries.sort_by_key(|a| (a.cost, a.over));
    let mut kept: Vec<Entry> = Vec::new();
    for e in entries.drain(..) {
        // Cheaper ones come first: one that overflows no more beats it.
        if !kept
            .iter()
            .any(|k| k.over.iter().zip(&e.over).all(|(a, b)| a <= b))
        {
            kept.push(e);
        }
    }
    *entries = kept;
}

/// The cheapest placement of `n` shards on `candidates` within `limits`,
/// if there's one: its candidates, if `track`, and cost.
fn solve(
    candidates: &[Candidate],
    tree: &[Vertex],
    limits: &Limits,
    n: usize,
    track: bool,
) -> Option<Entry> {
    let mut table = place(candidates, tree, 0, limits, n, track);
    table.truncate(n + 1);
    table.pop()?.into_iter().min_by_key(|e| e.cost)
}

/// For each number of shards, the ways of placing them in the subtree of
/// vertex `v` worth keeping.
fn place(
    candidates: &[Candidate],
    tree: &[Vertex],
    v: usize,
    limits: &Limits,
    n: usize,
    track: bool,
) -> Vec<Vec<Entry>> {
    let vertex = &tree[v];
    // The leaves: the cheapest of them.
    let mut table: Vec<Vec<Entry>> = Vec::new();
    let mut cost = Cost::default();
    for k in 0..=vertex.leaves.len().min(n) {
        if k > 0 && track {
            cost = cost + leaf_cost(&candidates[vertex.leaves[k - 1]]);
        }
        let picks = if track {
            vertex.leaves[..k].iter().map(|&i| i as u32).collect()
        } else {
            Vec::new()
        };
        table.push(vec![Entry {
            over: [0; MAX_LEVELS],
            cost,
            picks,
        }]);
    }
    for &child in &vertex.children {
        let other = place(candidates, tree, child, limits, n, track);
        let mut merged: Vec<Vec<Entry>> =
            vec![Vec::new(); (table.len() + other.len() - 1).min(n + 1)];
        for (ka, a) in table.iter().enumerate() {
            for (kb, b) in other.iter().enumerate() {
                if ka + kb > n {
                    break;
                }
                for ea in a {
                    'b: for eb in b {
                        let mut over = [0u8; MAX_LEVELS];
                        for (level, limit) in limits.iter().enumerate() {
                            let sum = ea.over[level] + eb.over[level];
                            if let Some((_, budget)) = limit
                                && sum as usize > *budget
                            {
                                continue 'b;
                            }
                            over[level] = sum;
                        }
                        let picks = if track {
                            [&ea.picks[..], &eb.picks[..]].concat()
                        } else {
                            Vec::new()
                        };
                        merged[ka + kb].push(Entry {
                            over,
                            cost: ea.cost + eb.cost,
                            picks,
                        });
                    }
                }
            }
        }
        for entries in &mut merged {
            prune(entries);
        }
        table = merged;
    }
    // The domain itself, at its level.
    if vertex.depth > 0 {
        let level = vertex.depth - 1;
        for (k, entries) in table.iter_mut().enumerate() {
            if let Some(Some((lambda, budget))) = limits.get(level) {
                let beyond = k.saturating_sub(*lambda);
                entries.retain_mut(|e| {
                    e.over[level] += beyond as u8;
                    e.over[level] as usize <= *budget
                });
            }
            if track {
                for e in entries.iter_mut() {
                    e.cost.squares[level] += (k * k) as u32;
                }
            }
        }
    }
    table
}

/// The choices of a level's limit for surviving the loss of `t` of its
/// domains, given that λ is at most `most` (see `optimize`).
fn choices(t: usize, parity: usize, most: usize) -> Vec<Option<(usize, usize)>> {
    match t {
        0 => vec![None],
        // Losing the fullest domain: λ = `parity` is a cap, and as good as
        // any (it's at least the λ of every level below).
        1 => vec![Some((parity, 0))],
        _ => (1..=(parity / t).min(most))
            .map(|l| Some((l, parity - t * l)))
            .collect(),
    }
}

/// The least λ of `limits` (`parity` if there's none): λ never grows from a
/// level to those below (see `optimize`).
fn last_lambda(limits: &Limits, parity: usize) -> usize {
    limits
        .iter()
        .flatten()
        .map(|(lambda, _)| *lambda)
        .min()
        .unwrap_or(parity)
}

/// The most domains of level `depth` that a placement of `n` shards on
/// `candidates` can survive the loss of, regardless of the other levels: as
/// evenly as their nodes allow, which leaves the fewest in its fullest
/// domains, however many.
fn bound(candidates: &[Candidate], depth: usize, n: usize, parity: usize) -> usize {
    let mut sizes: HashMap<Domain, usize> = HashMap::new();
    for c in candidates {
        *sizes.entry(c.node.domain(depth)).or_default() += 1;
    }
    let mut room: Vec<(usize, usize)> = sizes.into_values().map(|size| (0, size)).collect();
    for _ in 0..n {
        let Some(least) = room
            .iter_mut()
            .filter(|(count, size)| count < size)
            .min_by_key(|(count, _)| *count)
        else {
            break;
        };
        least.0 += 1;
    }
    let mut counts: Vec<usize> = room.into_iter().map(|(count, _)| count).collect();
    counts.sort_unstable_by(|a, b| b.cmp(a));
    let mut lost = 0;
    counts
        .iter()
        .take_while(|&&c| {
            lost += c;
            lost <= parity
        })
        .count()
}

/// The best a blob of `n` shards with `parity` parity shards can do on a set
/// of nodes: the most domains it can survive the loss of at each level,
/// widest first, each the most given those above; and every choice of
/// limits that reaches it.
#[derive(Debug)]
pub struct Optimum {
    pub tolerance: Vec<usize>,
    limits: Vec<Limits>,
    /// How many levels, from the widest, are the best there is: all of
    /// them, unless working it out took too long (see [`MAX_RUNS`]). Those
    /// below survive as much as the last of them, at least.
    pub exact: usize,
    /// How many times the dynamic program ran.
    pub runs: usize,
}

/// How many times `optimize` runs the dynamic program at most: beyond that,
/// it leaves the levels it hasn't got to as good as those above make them.
/// No layout of domains the tests know takes more than a few hundred (and
/// the reasoning in `optimize` bounds the choices of limits to 356 at each
/// level for 16 parity shards), so this is a guard against what they don't.
pub const MAX_RUNS: usize = 4000;

/// The best for `n` shards on `candidates`, worked out (see above).
///
/// Three facts keep the choices of limits few. A level survives the loss of
/// as many domains as the level above it at least: its domains split those
/// above, so its t fullest hold no more than theirs. So the search for a
/// level starts above the level above's, and a level that can't do better
/// needs no limit of its own: the one above's implies it. And for any
/// placement, λ = its t-th fullest domain's shards works at each level, which
/// never grows from a level to those below (they split those above, and t
/// doesn't shrink), so λ is chosen no greater than above's. And only the
/// choices of limits that work for the levels above are extended.
fn optimize(candidates: &[Candidate], n: usize, parity: usize) -> Option<Optimum> {
    if candidates.len() < n {
        return None;
    }
    let tree = tree(candidates);
    let levels = levels(candidates.iter().map(|c| c.node));
    let runs = std::cell::Cell::new(0);
    let feasible = |limits: &Limits| {
        runs.set(runs.get() + 1);
        solve(candidates, &tree, limits, n, false).is_some()
    };
    let mut tolerance: Vec<usize> = Vec::with_capacity(levels);
    let mut prefixes: Vec<Limits> = vec![Vec::new()];
    let mut exact = levels;
    for depth in 1..=levels {
        let above = tolerance.last().copied().unwrap_or(0);
        let most = bound(candidates, depth, n, parity);
        let mut reached = None;
        for t in (above + 1..=most).rev() {
            let mut found = Vec::new();
            for prefix in &prefixes {
                for choice in choices(t, parity, last_lambda(prefix, parity)) {
                    let mut limits = prefix.clone();
                    limits.push(choice);
                    if feasible(&limits) {
                        found.push(limits);
                    }
                }
            }
            if !found.is_empty() {
                reached = Some((t, found));
                break;
            }
        }
        match reached {
            Some((t, found)) => {
                tolerance.push(t);
                prefixes = found;
            }
            None => {
                tolerance.push(above);
                for prefix in &mut prefixes {
                    prefix.push(None);
                }
            }
        }
        if runs.get() > MAX_RUNS && depth < levels {
            exact = depth;
            let last = tolerance[depth - 1];
            tolerance.resize(levels, last);
            for prefix in &mut prefixes {
                prefix.resize(levels, None);
            }
            break;
        }
    }
    Some(Optimum {
        tolerance,
        limits: prefixes,
        exact,
        runs: runs.get(),
    })
}

/// The best placements worked out lately, by the nodes (`topology`, and
/// which hold a shard), shards and parity shards: nodes rarely change.
type Optima = HashMap<(String, usize, usize), std::sync::Arc<Optimum>>;
static OPTIMA: std::sync::Mutex<Option<Optima>> = std::sync::Mutex::new(None);

/// [`optimize`], remembered.
fn optimum(candidates: &[Candidate], n: usize, parity: usize) -> Option<std::sync::Arc<Optimum>> {
    let nodes: Vec<Node> = candidates.iter().map(|c| c.node.clone()).collect();
    let key = (topology(&nodes), n, parity);
    if let Some(found) = OPTIMA.lock().unwrap().get_or_insert_default().get(&key) {
        return Some(found.clone());
    }
    let found = std::sync::Arc::new(optimize(candidates, n, parity)?);
    if found.exact < found.tolerance.len() {
        eprintln!(
            "placement: working out the best placement of {n} shards ({parity} parity) on {} \
             nodes took {} runs, too many: levels below the {} widest are as good as those \
             make them, not necessarily the best",
            candidates.len(),
            found.runs,
            found.exact
        );
    }
    let mut optima = OPTIMA.lock().unwrap();
    let optima = optima.get_or_insert_default();
    if optima.len() >= 4096 {
        optima.clear();
    }
    optima.insert(key, found.clone());
    Some(found)
}

/// The best placement of `n` shards on `candidates` (see above), as indices
/// into them, and its tolerance. `None` if there aren't as many.
fn best(candidates: &[Candidate], n: usize, parity: usize) -> Option<(Vec<usize>, Vec<usize>)> {
    let optimum = optimum(candidates, n, parity)?;
    let tree = tree(candidates);
    let picks = optimum
        .limits
        .iter()
        .filter_map(|limits| solve(candidates, &tree, limits, n, true))
        .min_by_key(|e| e.cost)?
        .picks;
    Some((
        picks.into_iter().map(|i| i as usize).collect(),
        optimum.tolerance.clone(),
    ))
}

/// The candidates for placing a blob's shards: its shards on `held`, which
/// may stay where they are, and the live `nodes` that hold none and aren't
/// in `exclude`, ranked by free space.
fn candidates<'a>(nodes: &'a [Node], held: &[&'a Node], exclude: &[i32]) -> Vec<Candidate<'a>> {
    let mut free: Vec<&Node> = nodes
        .iter()
        .filter(|n| n.live && !exclude.contains(&n.id) && !held.iter().any(|h| h.id == n.id))
        .collect();
    // Stable: the first of `nodes` among equals.
    free.sort_by_key(|n| std::cmp::Reverse(n.free_space));
    held.iter()
        .map(|&node| Candidate {
            node,
            held: true,
            rank: 0,
        })
        .chain(free.into_iter().enumerate().map(|(rank, node)| Candidate {
            node,
            held: false,
            rank: rank as u64,
        }))
        .collect()
}

/// Chooses `shards` of the live `nodes` for a new blob's shards, `parity`
/// of them parity, placed best (see the module's docs): the node for shard
/// i is the i-th. `None` if there aren't as many.
pub fn choose_all(nodes: &[Node], shards: usize, parity: usize) -> Option<Vec<&Node>> {
    let candidates = candidates(nodes, &[], &[]);
    let (picks, _) = best(&candidates, shards, parity)?;
    let mut chosen: Vec<&Candidate> = picks.iter().map(|&i| &candidates[i]).collect();
    chosen.sort_by_key(|c| c.rank);
    Some(chosen.into_iter().map(|c| c.node).collect())
}

/// The node to place one more shard of a blob on, whose other shards are on
/// `held`, and that has `shards` shards with `parity` parity shards once
/// it has all of them: one of the live `nodes` that holds none of them and
/// isn't in `exclude`, as in the best placement of all of its shards that
/// keeps those on `held` (where they are to stay: shards still to move
/// aren't among them), the emptiest of the new nodes there. If no best
/// placement keeps them (the blob isn't placed as well as it could be: the
/// mover sees to it), where it's spread most evenly. `None` if there's no
/// such node.
pub fn choose<'a>(
    nodes: &'a [Node],
    held: &[&'a Node],
    exclude: &[i32],
    shards: usize,
    parity: usize,
) -> Option<&'a Node> {
    let candidates = candidates(nodes, held, exclude);
    if candidates.len() == held.len() {
        return None;
    }
    let n = shards.min(candidates.len()).max(held.len() + 1);
    if let Some((picks, _)) = best(&candidates, n, parity)
        && picks.iter().filter(|&&i| candidates[i].held).count() == held.len()
    {
        return picks
            .iter()
            .map(|&i| &candidates[i])
            .filter(|c| !c.held)
            .min_by_key(|c| c.rank)
            .map(|c| c.node);
    }
    let levels = levels(candidates.iter().map(|c| c.node));
    let mut with = held.to_vec();
    candidates
        .iter()
        .filter(|c| !c.held)
        .min_by_key(|c| {
            with.push(c.node);
            let spread = spread_of(&with, levels);
            with.pop();
            (spread, c.rank)
        })
        .map(|c| c.node)
}

/// A shard to move, to place its blob better.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Move {
    /// The node it's on.
    pub from: i32,
    /// The node it's to go to.
    pub to: i32,
}

/// The shards to move so that the blob with its shards on `held` and
/// `parity` parity shards is placed best on the live `nodes` (but those in
/// `exclude`), if that survives more than it does now (see the module's
/// docs): as few as that takes. `None` if it's as good as it gets there.
pub fn respread(
    nodes: &[Node],
    held: &[&Node],
    exclude: &[i32],
    parity: usize,
) -> Option<Vec<Move>> {
    let candidates = candidates(nodes, held, exclude);
    let (picks, best) = best(&candidates, held.len(), parity)?;
    let levels = levels(candidates.iter().map(|c| c.node));
    let now = padded(tolerance(held, levels, parity), levels, parity);
    if padded(best, levels, parity) <= now {
        return None;
    }
    let to = picks.iter().map(|&i| &candidates[i]).filter(|c| !c.held);
    let from = held
        .iter()
        .filter(|h| !picks.iter().any(|&i| candidates[i].node.id == h.id));
    Some(
        from.zip(to)
            .map(|(from, to)| Move {
                from: from.id,
                to: to.node.id,
            })
            .collect(),
    )
}

/// Whether the blob with its shards on `held` and `parity` parity shards
/// could survive more than it does on `nodes` (live or not, as if all were
/// live; those holding its shards on them or not).
pub fn uneven(nodes: &[Node], held: &[&Node], parity: usize) -> bool {
    let all: Vec<Node> = nodes
        .iter()
        .map(|n| Node {
            live: true,
            ..n.clone()
        })
        .collect();
    let held_here: Vec<&Node> = held
        .iter()
        .map(|h| all.iter().find(|n| n.id == h.id).unwrap_or(h))
        .collect();
    let candidates = candidates(&all, &held_here, &[]);
    let Some(optimum) = optimum(&candidates, held.len(), parity) else {
        return false;
    };
    let levels = levels(candidates.iter().map(|c| c.node));
    padded(tolerance(held, levels, parity), levels, parity)
        < padded(optimum.tolerance.clone(), levels, parity)
}

/// Checks many blobs on the same nodes for being uneven (see [`uneven`]),
/// working out the best placement on them once for each number of shards
/// and parity shards.
pub struct Checker<'a> {
    nodes: &'a [Node],
    levels: usize,
    best: HashMap<(usize, usize), Option<Vec<usize>>>,
}

impl<'a> Checker<'a> {
    pub fn new(nodes: &'a [Node]) -> Checker<'a> {
        Checker {
            nodes,
            levels: levels(nodes),
            best: HashMap::new(),
        }
    }

    /// Whether the blob with its shards on `held` and `parity` parity shards
    /// could survive more than it does on the nodes.
    pub fn uneven(&mut self, held: &[&Node], parity: usize) -> bool {
        // On a node that's not among them (being removed): as `uneven` says.
        if held
            .iter()
            .any(|h| h.path.len() > self.levels || !self.nodes.iter().any(|n| n.id == h.id))
        {
            return uneven(self.nodes, held, parity);
        }
        let nodes = self.nodes;
        let best = self.best.entry((held.len(), parity)).or_insert_with(|| {
            let all: Vec<Node> = nodes
                .iter()
                .map(|n| Node {
                    live: true,
                    ..n.clone()
                })
                .collect();
            let candidates = candidates(&all, &[], &[]);
            optimum(&candidates, held.len(), parity).map(|o| o.tolerance.clone())
        });
        match best {
            None => false,
            Some(best) => {
                padded(tolerance(held, self.levels, parity), self.levels, parity)
                    < padded(best.clone(), self.levels, parity)
            }
        }
    }
}

/// Of the nodes holding a blob's copies, `held`, the one whose copy to drop
/// so that the rest survives the most (with one copy fewer), then is the
/// most even. Among equals, the first of `held`.
pub fn crowded_copy(held: &[&Node]) -> Option<i32> {
    let levels = levels(held.iter().copied());
    let parity = held.len().checked_sub(2)?;
    (0..held.len())
        .map(|i| {
            let mut rest = held.to_vec();
            rest.remove(i);
            let tolerance = tolerance(&rest, levels, parity);
            (
                std::cmp::Reverse(tolerance),
                spread_of(&rest, levels),
                held[i].id,
            )
        })
        .min_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)))
        .map(|(_, _, id)| id)
}

/// A fingerprint of the nodes a pool's blobs are spread over (active ones,
/// live or not, with their locations): whenever it changes, every blob's
/// spread is checked again (see `mover`).
pub fn topology(nodes: &[Node]) -> String {
    use sha2::Digest;
    let mut entries: Vec<String> = nodes
        .iter()
        .map(|n| format!("{}\t{}", n.id, n.location()))
        .collect();
    entries.sort();
    let digest = sha2::Sha256::digest(entries.join("\n").as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: i32, location: &str, free_space: i64) -> Node {
        Node::new(id, format!("http://n{id}"), location, true, free_space)
    }

    /// The first `depth` domains of the locations of `chosen`, sorted.
    fn domains(chosen: &[&Node], depth: usize) -> Vec<String> {
        let mut d: Vec<String> = chosen.iter().map(|n| n.path[..depth].join("/")).collect();
        d.sort();
        d
    }

    fn ids(chosen: &[&Node]) -> Vec<i32> {
        chosen.iter().map(|n| n.id).collect()
    }

    #[test]
    fn locations_are_checked() {
        assert_eq!(parse_location("").unwrap(), "");
        assert_eq!(
            parse_location("eu-west/eu-west-1a/rack.3/host_7").unwrap(),
            "eu-west/eu-west-1a/rack.3/host_7"
        );
        for bad in ["/eu", "eu/", "eu//a", "-eu", "eu west", "a/b/c/d/e/f/g/h/i"] {
            assert!(parse_location(bad).is_err(), "{bad}");
        }
        assert!(parse_location(&"a".repeat(64)).is_err());
    }

    /// Without locations, the nodes with the most free space, as ever.
    #[test]
    fn without_locations_the_emptiest_nodes() {
        let nodes: Vec<Node> = (1..=5).map(|i| node(i, "", i as i64 * 10)).collect();
        assert_eq!(ids(&choose_all(&nodes, 3, 2).unwrap()), [5, 4, 3]);
        assert!(choose_all(&nodes, 6, 2).is_none());
    }

    /// The case that matters: new, empty nodes in one region have the most
    /// free space, and still get one copy at most.
    #[test]
    fn new_nodes_in_a_region_dont_take_every_copy() {
        let mut nodes: Vec<Node> = ["us", "eu", "ap", "sa", "af"]
            .iter()
            .zip(1..)
            .map(|(r, i)| node(i, &format!("{r}/{r}-1/rack-1/host-1"), 100))
            .collect();
        for i in 10..14 {
            nodes.push(node(i, &format!("eu/eu-1/rack-2/host-{i}"), 1000));
        }
        let chosen = choose_all(&nodes, 3, 2).unwrap();
        let mut r = domains(&chosen, 1);
        r.dedup();
        assert_eq!(r.len(), 3, "{r:?}");
        // eu's is on the emptiest node of eu.
        assert!(chosen.iter().any(|n| n.id >= 10));
        assert!(!uneven(&nodes, &chosen, 2));
    }

    /// 4 + 2 over 5 datacenters, two of them with two racks: the datacenter
    /// with two shards must be one with two racks, so that no rack holds two,
    /// however much emptier the others are.
    #[test]
    fn the_doubled_datacenter_has_two_racks() {
        let nodes = vec![
            node(1, "a/r1/h1", 100),
            node(2, "b/r1/h1", 100),
            node(3, "c/r1/h1", 100),
            node(4, "c/r1/h2", 100),
            node(5, "d/r1/h1", 10),
            node(6, "d/r2/h1", 10),
            node(7, "e/r1/h1", 10),
            node(8, "e/r2/h1", 10),
        ];
        let chosen = choose_all(&nodes, 6, 2).unwrap();
        let mut racks = domains(&chosen, 2);
        racks.dedup();
        assert_eq!(racks.len(), 6, "{racks:?}");
        assert_eq!(tolerance(&chosen, 3, 2), [1, 2, 2]);
        assert!(!uneven(&nodes, &chosen, 2));
        // Placed the other way, it's uneven, and one move fixes it.
        let bad: Vec<&Node> = [1, 2, 3, 4, 5, 7]
            .iter()
            .map(|id| nodes.iter().find(|n| n.id == *id).unwrap())
            .collect();
        assert_eq!(tolerance(&bad, 3, 2), [1, 1, 2]);
        assert!(uneven(&nodes, &bad, 2));
        let moves = respread(&nodes, &bad, &[], 2).unwrap();
        assert_eq!(moves.len(), 1, "{moves:?}");
        assert!([3, 4].contains(&moves[0].from), "{moves:?}");
        assert!([6, 8].contains(&moves[0].to), "{moves:?}");
    }

    /// Two regions of one rack of 2 nodes each, and one of 3 racks of a node
    /// each: 3 + 3 survives the loss of a region either as 2/2/2 or as
    /// 3/2/1 (3 in the region of 3 racks), but only the latter survives the
    /// loss of two racks. Even isn't what counts: surviving is.
    #[test]
    fn surviving_beats_evenness() {
        let nodes = vec![
            node(1, "a/r1/h1", 1),
            node(2, "a/r1/h2", 1),
            node(3, "b/r1/h1", 1),
            node(4, "b/r1/h2", 1),
            node(5, "c/r1/h1", 1),
            node(6, "c/r2/h1", 1),
            node(7, "c/r3/h1", 1),
        ];
        let chosen = choose_all(&nodes, 6, 3).unwrap();
        assert_eq!(tolerance(&chosen, 3, 3), [1, 2, 3]);
        assert_eq!(domains(&chosen, 1).iter().filter(|r| *r == "c").count(), 3);
    }

    /// Where the levels conflict, the wider wins: a region of one rack of
    /// 2 nodes and one of 3 racks of a node each, for 2 + 2. Surviving the
    /// loss of a region takes 2 in each, which puts 2 in a rack.
    #[test]
    fn regions_come_before_racks() {
        let nodes = vec![
            node(1, "x/r1/h1", 1),
            node(2, "x/r1/h2", 1),
            node(3, "y/r1/h1", 1),
            node(4, "y/r2/h1", 1),
            node(5, "y/r3/h1", 1),
        ];
        let chosen = choose_all(&nodes, 4, 2).unwrap();
        assert_eq!(tolerance(&chosen, 3, 2), [1, 1, 2]);
    }

    #[test]
    fn several_instances_per_host_spread_over_hosts_first() {
        let nodes = vec![
            node(1, "r/z/h1", 10),
            node(2, "r/z/h1", 9),
            node(3, "r/z/h2", 8),
            node(4, "r/z/h2", 7),
        ];
        assert_eq!(ids(&choose_all(&nodes, 2, 1).unwrap()), [1, 3]);
        let mut all = ids(&choose_all(&nodes, 4, 2).unwrap());
        all.sort();
        assert_eq!(all, [1, 2, 3, 4]);
    }

    /// Down nodes take nothing; what's placed without them is uneven for
    /// the nodes as a whole, and is spread once they're back.
    #[test]
    fn a_region_down_leaves_blobs_to_spread() {
        let mut nodes = vec![
            node(1, "a/1", 1),
            node(2, "a/2", 1),
            node(3, "b/1", 1),
            node(4, "c/1", 1),
        ];
        nodes[3].live = false;
        let chosen: Vec<Node> = choose_all(&nodes, 3, 2)
            .unwrap()
            .into_iter()
            .cloned()
            .collect();
        let held: Vec<&Node> = chosen.iter().collect();
        assert_eq!(domains(&held, 1), ["a", "a", "b"]);
        assert!(uneven(&nodes, &held, 2));
        // Not while c is down.
        assert!(respread(&nodes, &held, &[], 2).is_none());
        nodes[3].live = true;
        let moves = respread(&nodes, &held, &[], 2).unwrap();
        assert_eq!(moves.len(), 1);
        assert!([1, 2].contains(&moves[0].from));
        assert_eq!(moves[0].to, 4);
    }

    /// A shard to move goes where the blob, with the others where they are,
    /// is placed best.
    #[test]
    fn a_moving_shard_goes_where_its_blob_is_best() {
        let nodes = vec![
            node(1, "a/1", 1),
            node(2, "a/2", 1),
            node(3, "b/1", 5),
            node(4, "b/1", 9),
            node(5, "c/1", 1),
        ];
        // a and b hold a copy each; the third belongs in c, emptier as b is.
        let held = vec![&nodes[0], &nodes[2]];
        assert_eq!(choose(&nodes, &held, &[], 3, 2).unwrap().id, 5);
        // Unless c is excluded: then a's other zone, though b's node is
        // emptier, which would put two copies in one zone.
        assert_eq!(choose(&nodes, &held, &[5], 3, 2).unwrap().id, 2);
    }

    #[test]
    fn a_full_region_isnt_uneven() {
        // a has one node only: 2 shards in b is as good as it gets.
        let nodes = vec![node(1, "a", 1), node(2, "b", 1), node(3, "b", 1)];
        let held: Vec<&Node> = nodes.iter().collect();
        assert!(!uneven(&nodes, &held, 2));
    }

    #[test]
    fn the_copy_to_drop_is_the_most_crowded() {
        let nodes = [
            node(1, "a/1", 1),
            node(2, "b/1", 1),
            node(3, "b/2", 1),
            node(4, "b/2", 1),
        ];
        let held: Vec<&Node> = nodes.iter().collect();
        assert_eq!(crowded_copy(&held), Some(3));
        let held = vec![&nodes[0], &nodes[1]];
        assert_eq!(crowded_copy(&held), Some(1));
    }

    #[test]
    fn topologies_ignore_order_and_liveness() {
        let mut a = vec![node(1, "a", 1), node(2, "b", 5)];
        let mut b = vec![node(2, "b", 9), node(1, "a", 1)];
        b[0].live = false;
        assert_eq!(topology(&a), topology(&b));
        a[0].path = split("c");
        assert_ne!(topology(&a), topology(&b));
    }

    /// Layouts whose levels all survive the loss of as many domains take
    /// few runs: a chain of single domains (instances on hosts that are
    /// alone in their racks, say), and domains that split into a big part
    /// and a tiny one at every level. Before levels that can't do better than
    /// those above dropped their limits, 8 levels of either took millions.
    #[test]
    fn deep_layouts_take_few_runs() {
        let mut chain = Vec::new();
        for r in 0..6 {
            for _ in 0..8 {
                chain.push(node(chain.len() as i32, &format!("r{r}/z/k/h/a/b/c/d"), 1));
            }
        }
        let mut lopsided = Vec::new();
        for r in 0..6 {
            let mut prefix = format!("r{r}");
            for d in 0..7 {
                lopsided.push(node(lopsided.len() as i32, &format!("{prefix}/t{d}"), 1));
                prefix = format!("{prefix}/b{d}");
            }
            for _ in 0..8 {
                lopsided.push(node(lopsided.len() as i32, &prefix, 1));
            }
        }
        for (name, nodes) in [("chain", &chain), ("lopsided", &lopsided)] {
            let candidates = candidates(nodes, &[], &[]);
            let optimum = optimize(&candidates, 48, 16).unwrap();
            assert_eq!(optimum.exact, 8, "{name}");
            assert!(optimum.runs < 200, "{name}: {} runs", optimum.runs);
            let chosen = choose_all(nodes, 48, 16).unwrap();
            assert_eq!(tolerance(&chosen, 8, 16), optimum.tolerance, "{name}");
        }
    }

    /// The optimizer's placement survives, level by level from the widest,
    /// the loss of as many domains as any placement does that survives as
    /// many at the levels above (l1 = max l1, l2 = max l2 given l1, ...), as
    /// trying every placement shows, for random layouts of up to 4 levels
    /// and 10 nodes, every number of shards and parity shards. And a
    /// placement is uneven exactly when it's worse than that; spreading it
    /// makes it the best.
    #[test]
    fn placement_is_the_best_level_by_level() {
        let mut x = 0x2545_f491_4f6c_dd1d_u64;
        let mut rand = |n: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % n
        };
        for _ in 0..300 {
            let count = 2 + rand(9) as i32;
            let nodes: Vec<Node> = (0..count)
                .map(|id| {
                    let depth = 1 + rand(4);
                    let path: Vec<String> = (0..depth).map(|_| format!("{}", rand(3))).collect();
                    node(id, &path.join("/"), rand(4) as i64)
                })
                .collect();
            let levels = levels(&nodes);
            let mut checker = Checker::new(&nodes);
            for shards in 2..=nodes.len() {
                let subsets: Vec<Vec<&Node>> = (0u32..1 << nodes.len())
                    .filter(|mask| mask.count_ones() as usize == shards)
                    .map(|mask| {
                        (0..nodes.len())
                            .filter(|i| mask & (1 << i) != 0)
                            .map(|i| &nodes[i])
                            .collect()
                    })
                    .collect();
                for parity in 0..shards {
                    let best = subsets
                        .iter()
                        .map(|s| tolerance(s, levels, parity))
                        .max()
                        .unwrap();
                    let chosen = choose_all(&nodes, shards, parity).unwrap();
                    let paths: Vec<&Vec<String>> = nodes.iter().map(|n| &n.path).collect();
                    assert_eq!(
                        tolerance(&chosen, levels, parity),
                        best,
                        "{paths:?}, {shards} shards, {parity} parity"
                    );
                    for subset in subsets.iter().step_by(7) {
                        let worse = tolerance(subset, levels, parity) < best;
                        assert_eq!(uneven(&nodes, subset, parity), worse, "{paths:?}");
                        assert_eq!(checker.uneven(subset, parity), worse, "{paths:?}");
                        if worse {
                            let moves = respread(&nodes, subset, &[], parity).unwrap();
                            let mut after: Vec<&Node> = subset.clone();
                            for m in &moves {
                                let i = after.iter().position(|n| n.id == m.from).unwrap();
                                after[i] = nodes.iter().find(|n| n.id == m.to).unwrap();
                            }
                            assert_eq!(tolerance(&after, levels, parity), best);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod e2e;
