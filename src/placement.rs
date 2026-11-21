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
//! A blob's shards are spread so that losing domains loses as few of them
//! as can be, the widest domains first. Precisely, a blob's **spread** is,
//! for each level from the top, its domains' shard counts, the most first;
//! and one spread is better than another if it's better at the widest level
//! where they differ, where the counts are compared one by one: fewer shards
//! in the fullest region, then in the next fullest, and so on, and only
//! then the same for zones (or racks), and below. A blob is placed with the
//! best spread its nodes allow. So the fullest region holds as few of its
//! shards as can be (losing it loses the fewest), and losing any two regions
//! loses as few as can be given that, and so on; among placements as good
//! for regions, the fullest rack holds as few as can be, and so on down.
//!
//! With 3 copies over 5 regions, that's 3 regions. 6 shards (4 + 2) over 5
//! regions puts 2 in one region, and if only some regions have two racks
//! (or zones), it's one of those, its 2 shards in different racks: in a
//! region of one rack, they'd be in one rack, which with any other rack is
//! 3 shards, more than the 2 the blob can lose. However many nodes are added
//! to a region, a blob gets no more of its shards there. A domain takes no
//! more shards than it has nodes.
//!
//! New shards are placed one at a time ([`choose`]), each where it makes
//! the spread best, then improved by moving one shard at a time while that
//! makes it better ([`improvement`]); among places as good, on the node
//! with the most free space. That's the best spread for every layout of
//! domains the tests try against all placements. A blob that can't be
//! spread as well over its live nodes as over all of the active ones (a
//! region is down, say) is placed as well as the live ones allow, and
//! marked uneven; the mover spreads it once it can (see `mover`), as it
//! does blobs whose spread a change of the nodes (a new region, locations
//! set where there were none) made worse than it could be.

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

/// How a blob whose shards are on `held` is spread (see the module's docs),
/// over `levels` levels: for each, its domains' shard counts, the most
/// first. Less is better.
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

/// Of `targets`, one of each kind as far as the spread of a blob with its
/// shards on `held` (or some of them) goes: nodes whose locations share the
/// same widest domain that holds any of them place a shard alike, since
/// below it, every domain is empty. The emptiest of each kind (the first
/// of equals).
fn kinds<'a>(targets: impl IntoIterator<Item = &'a Node>, held: &[&Node]) -> Vec<&'a Node> {
    let mut kinds: Vec<((usize, &[String]), &Node)> = Vec::new();
    for t in targets {
        let depth = (1..=t.path.len())
            .take_while(|&d| held.iter().any(|h| h.domain(d) == t.domain(d)))
            .last()
            .unwrap_or(0);
        let kind = (depth, &t.path[..depth]);
        match kinds.iter_mut().find(|(k, _)| *k == kind) {
            Some((_, first)) if t.free_space > first.free_space => *first = t,
            Some(_) => {}
            None => kinds.push((kind, t)),
        }
    }
    kinds.into_iter().map(|(_, t)| t).collect()
}

/// The nodes of `nodes` that may take a new shard of a blob with its shards
/// on `held`: those that hold none and aren't in `exclude`, and if
/// `live_only`, are live.
fn targets<'a>(
    nodes: &'a [Node],
    held: &[&Node],
    exclude: &[i32],
    live_only: bool,
) -> impl Iterator<Item = &'a Node> {
    let held: Vec<i32> = held.iter().map(|h| h.id).collect();
    let exclude = exclude.to_vec();
    nodes.iter().filter(move |n| {
        (n.live || !live_only) && !exclude.contains(&n.id) && !held.contains(&n.id)
    })
}

/// The node to place one more shard of a blob on, whose other shards are on
/// `held`: one of the live `nodes` that holds none of them and isn't in
/// `exclude`, where the blob is spread best; among equals, the one with the
/// most free space (then the first of `nodes`). `None` if there's no such
/// node.
pub fn choose<'a>(nodes: &'a [Node], held: &[&Node], exclude: &[i32]) -> Option<&'a Node> {
    let levels = levels(nodes.iter().chain(held.iter().copied()));
    let mut with: Vec<&Node> = held.to_vec();
    kinds(targets(nodes, held, exclude, true), held)
        .into_iter()
        .map(|t| {
            with.push(t);
            let spread = spread_of(&with, levels);
            with.pop();
            (spread, std::cmp::Reverse(t.free_space), t)
        })
        // `min_by` keeps the first of equals.
        .min_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)))
        .map(|(_, _, t)| t)
}

/// Chooses `count` of the live `nodes` for a new blob's shards, spread best
/// (see the module's docs): the node for shard i is the i-th. `None` if
/// there aren't as many.
pub fn choose_all(nodes: &[Node], count: usize) -> Option<Vec<&Node>> {
    let mut chosen: Vec<&Node> = Vec::with_capacity(count);
    for _ in 0..count {
        let node = choose(nodes, &chosen, &[])?;
        chosen.push(node);
    }
    while let Some(better) = improvement(nodes, &chosen, &[], true) {
        let i = chosen.iter().position(|n| n.id == better.from).unwrap();
        chosen[i] = nodes.iter().find(|n| n.id == better.to).unwrap();
    }
    Some(chosen)
}

/// A shard to move, to spread its blob better.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Move {
    /// The node it's on.
    pub from: i32,
    /// The node it's to go to.
    pub to: i32,
}

/// The move of one shard of a blob with its shards on `held` to another of
/// `nodes` (that holds none, isn't in `exclude`, and if `live_only`, is live)
/// that spreads it best, if that's better than it is. Among equals, one
/// from a live node (whose shard is copied, not rebuilt), to the node with
/// the most free space.
pub fn improvement(
    nodes: &[Node],
    held: &[&Node],
    exclude: &[i32],
    live_only: bool,
) -> Option<Move> {
    let levels = levels(nodes.iter().chain(held.iter().copied()));
    let now = spread_of(held, levels);
    let targets = kinds(targets(nodes, held, exclude, live_only), held);
    let mut best: Option<(Vec<Vec<usize>>, bool, i64, Move)> = None;
    let mut seen: Vec<&[String]> = Vec::new();
    for (i, from) in held.iter().enumerate() {
        // Shards on nodes at the same location move alike.
        if seen.contains(&from.path.as_slice()) && from.live {
            continue;
        }
        if from.live {
            seen.push(&from.path);
        }
        let mut with: Vec<&Node> = held.to_vec();
        for to in &targets {
            with[i] = to;
            let spread = spread_of(&with, levels);
            if spread >= now {
                continue;
            }
            let better = match &best {
                None => true,
                Some((s, live, free, _)) => {
                    (&spread, !from.live, std::cmp::Reverse(to.free_space))
                        < (s, !*live, std::cmp::Reverse(*free))
                }
            };
            if better {
                best = Some((
                    spread,
                    from.live,
                    to.free_space,
                    Move {
                        from: from.id,
                        to: to.id,
                    },
                ));
            }
        }
    }
    best.map(|(_, _, _, m)| m)
}

/// Whether the blob with its shards on `held` could be spread better over
/// `nodes` (live or not) than it is: by moving a shard, which is all the
/// mover does (see [`improvement`]).
pub fn uneven(nodes: &[Node], held: &[&Node]) -> bool {
    improvement(nodes, held, &[], false).is_some()
}

/// Of the nodes holding a blob's copies, `held`, the one whose copy to drop
/// so that the rest is spread best. Among equals, the first of `held`.
pub fn crowded_copy(held: &[&Node]) -> Option<i32> {
    let levels = levels(held.iter().copied());
    (0..held.len())
        .map(|i| {
            let mut rest = held.to_vec();
            rest.remove(i);
            (spread_of(&rest, levels), held[i].id)
        })
        .min_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, id)| id)
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
        assert_eq!(ids(&choose_all(&nodes, 3).unwrap()), [5, 4, 3]);
        assert!(choose_all(&nodes, 6).is_none());
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
        let chosen = choose_all(&nodes, 3).unwrap();
        let mut r = domains(&chosen, 1);
        r.dedup();
        assert_eq!(r.len(), 3, "{r:?}");
        // eu's is on the emptiest node of eu.
        assert!(chosen.iter().any(|n| n.id >= 10));
        assert!(!uneven(&nodes, &chosen));
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
        let chosen = choose_all(&nodes, 6).unwrap();
        let mut racks = domains(&chosen, 2);
        racks.dedup();
        assert_eq!(racks.len(), 6, "{racks:?}");
        assert!(!uneven(&nodes, &chosen));
        // Placed the other way, it's uneven, and one move fixes it.
        let bad: Vec<&Node> = [1, 2, 3, 4, 5, 7]
            .iter()
            .map(|id| nodes.iter().find(|n| n.id == *id).unwrap())
            .collect();
        assert!(uneven(&nodes, &bad));
        let better = improvement(&nodes, &bad, &[], true).unwrap();
        assert!([3, 4].contains(&better.from), "{better:?}");
        assert!([6, 8].contains(&better.to), "{better:?}");
    }

    #[test]
    fn coded_blobs_are_spread_as_evenly_as_can_be() {
        // 6 shards over 5 regions of 2 zones of 2 nodes each.
        let mut nodes = Vec::new();
        let mut id = 0;
        for r in ["a", "b", "c", "d", "e"] {
            for z in ["1", "2"] {
                for h in ["x", "y"] {
                    id += 1;
                    nodes.push(node(id, &format!("{r}/{z}/{h}"), id as i64));
                }
            }
        }
        let chosen = choose_all(&nodes, 6).unwrap();
        let mut r = domains(&chosen, 1);
        r.dedup();
        assert_eq!(r.len(), 5);
        let mut zones = domains(&chosen, 2);
        zones.dedup();
        assert_eq!(zones.len(), 6, "the region with two has them in two zones");
    }

    #[test]
    fn several_instances_per_host_spread_over_hosts_first() {
        let nodes = vec![
            node(1, "r/z/h1", 10),
            node(2, "r/z/h1", 9),
            node(3, "r/z/h2", 8),
            node(4, "r/z/h2", 7),
        ];
        assert_eq!(ids(&choose_all(&nodes, 2).unwrap()), [1, 3]);
        let mut all = ids(&choose_all(&nodes, 4).unwrap());
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
        let chosen: Vec<Node> = choose_all(&nodes, 3)
            .unwrap()
            .into_iter()
            .cloned()
            .collect();
        let held: Vec<&Node> = chosen.iter().collect();
        assert_eq!(domains(&held, 1), ["a", "a", "b"]);
        assert!(uneven(&nodes, &held));
        // Not while c is down.
        assert!(improvement(&nodes, &held, &[], true).is_none());
        nodes[3].live = true;
        let better = improvement(&nodes, &held, &[], true).unwrap();
        assert!([1, 2].contains(&better.from));
        assert_eq!(better.to, 4);
    }

    #[test]
    fn a_full_region_isnt_uneven() {
        // a has one node only: 2 shards in b is as good as it gets.
        let nodes = vec![node(1, "a", 1), node(2, "b", 1), node(3, "b", 1)];
        let held: Vec<&Node> = nodes.iter().collect();
        assert!(!uneven(&nodes, &held));
        // Nor are shards on nodes being removed, outside `nodes`, a reason.
        let leaving = node(9, "b", 1);
        let held = vec![&nodes[0], &nodes[1], &leaving];
        assert!(!uneven(&nodes, &held));
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

    /// Placing shards one at a time and then moving them one at a time while
    /// that helps finds the best spread there is, as trying every placement
    /// does, for random layouts of up to 3 levels and 10 nodes, and shards
    /// from 1 to all of them. And no blob placed so is uneven, and every
    /// placement that isn't the best can be moved toward it.
    #[test]
    fn placement_finds_the_best_spread() {
        let mut x = 0x2545_f491_4f6c_dd1d_u64;
        let mut rand = |n: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % n
        };
        for _ in 0..400 {
            let count = 2 + rand(9) as i32;
            let nodes: Vec<Node> = (0..count)
                .map(|id| {
                    let depth = 1 + rand(3);
                    let path: Vec<String> = (0..depth).map(|_| format!("{}", rand(3))).collect();
                    node(id, &path.join("/"), rand(4) as i64)
                })
                .collect();
            let levels = levels(&nodes);
            for shards in 1..=nodes.len() {
                let chosen = choose_all(&nodes, shards).unwrap();
                let got = spread_of(&chosen, levels);
                // Every subset of `shards` nodes.
                let subsets: Vec<Vec<&Node>> = (0u32..1 << nodes.len())
                    .filter(|mask| mask.count_ones() as usize == shards)
                    .map(|mask| {
                        (0..nodes.len())
                            .filter(|i| mask & (1 << i) != 0)
                            .map(|i| &nodes[i])
                            .collect()
                    })
                    .collect();
                let best = subsets.iter().map(|s| spread_of(s, levels)).min();
                let paths: Vec<&Vec<String>> = nodes.iter().map(|n| &n.path).collect();
                for subset in &subsets {
                    // A placement no move improves is the best (else the
                    // mover could leave a blob worse than it could be).
                    if improvement(&nodes, subset, &[], false).is_none() {
                        assert_eq!(
                            Some(spread_of(subset, levels)),
                            best,
                            "{paths:?}: {:?} can't be improved by a move",
                            ids(subset)
                        );
                    }
                }
                let paths: Vec<&Vec<String>> = nodes.iter().map(|n| &n.path).collect();
                assert_eq!(Some(&got), best.as_ref(), "{paths:?}, {shards} shards");
                assert!(!uneven(&nodes, &chosen));
            }
        }
    }
}

#[cfg(test)]
mod e2e;
