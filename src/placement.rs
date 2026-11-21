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
//! A blob's shards are spread as evenly as the nodes allow, level by level
//! from the top: they go to as many regions as there are (or as there are
//! shards), as evenly as can be; within each region, over its zones, and so
//! on. Precisely, a blob is **spread** over a set of nodes if in no domain
//! one child (a domain below it, or a node) holds at least two of its
//! shards more than another child that has a node of the set holding none
//! (there'd be a better place for one of them). With 3 copies over 5
//! regions, that's 3 regions; 6 shards (4 + 2) over 5 regions, no region
//! with more than 2; 3 copies over 2 regions, 2 and 1, the 2 in different
//! zones of their region, if it has several. However many nodes are added
//! to a region, a blob gets no more of its shards there.
//!
//! New shards are placed one at a time ([`choose`]): from the top, into the
//! child domain that holds the fewest of the blob's shards and has a live
//! node to spare, those with the most free space first among equals. That
//! spreads a blob over the live nodes. A blob that can't be spread over all
//! of the active nodes (a region is down, say) is placed as well as the live
//! ones allow, and marked uneven; the mover spreads it once it can (see
//! `mover`), as it does blobs whose spread a change of the nodes (a new
//! region, locations set where there were none) made uneven.

use std::collections::BTreeMap;

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

    /// Whether it's within the domain `domain` (a path; empty: the root).
    fn within(&self, domain: &[String]) -> bool {
        self.path.starts_with(domain)
    }

    /// Its child of the domain `depth` levels down that it's within: a
    /// domain, or itself, at the bottom of its path.
    fn child(&self, depth: usize) -> Child<'_> {
        match self.path.get(depth) {
            Some(domain) => Child::Domain(domain),
            None => Child::Node(self.id),
        }
    }
}

/// A location's domains.
pub fn split(location: &str) -> Vec<String> {
    if location.is_empty() {
        Vec::new()
    } else {
        location.split('/').map(str::to_owned).collect()
    }
}

/// A child of a domain: a domain below it, or a node directly in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Child<'a> {
    Domain(&'a str),
    Node(i32),
}

/// The node to place one more shard of a blob on, whose other shards are on
/// `held`: one of the live `nodes` that holds none of them, isn't in
/// `exclude`, and is within the domain `within` (empty: anywhere). From
/// there down, level by level, it's in the child that holds the fewest of
/// the blob's shards, of those that have such a node; among equals, the one
/// with the node with the most free space (then the first of `nodes`).
/// `None` if there's no such node.
pub fn choose<'a>(
    nodes: &'a [Node],
    held: &[&Node],
    exclude: &[i32],
    within: &[String],
) -> Option<&'a Node> {
    let mut eligible: Vec<&Node> = nodes
        .iter()
        .filter(|n| {
            n.live
                && n.within(within)
                && !exclude.contains(&n.id)
                && !held.iter().any(|h| h.id == n.id)
        })
        .collect();
    let mut domain = within.to_vec();
    loop {
        let depth = domain.len();
        let held_here: Vec<&&Node> = held.iter().filter(|h| h.within(&domain)).collect();
        let best = eligible
            .iter()
            .map(|n| {
                let child = n.child(depth);
                let count = held_here.iter().filter(|h| h.child(depth) == child).count();
                (count, std::cmp::Reverse(n.free_space), child)
            })
            // `min_by_key` keeps the first of equals.
            .min_by_key(|(count, free, _)| (*count, *free))?;
        match best.2 {
            Child::Node(id) => return eligible.into_iter().find(|n| n.id == id),
            Child::Domain(name) => {
                let name = name.to_owned();
                eligible.retain(|n| n.path.get(depth) == Some(&name));
                domain.push(name);
            }
        }
    }
}

/// Chooses `count` of the live `nodes` for a new blob's shards, spread (see
/// [`choose`]): the node for shard i is the i-th. `None` if there aren't as
/// many.
pub fn choose_all(nodes: &[Node], count: usize) -> Option<Vec<&Node>> {
    let mut chosen: Vec<&Node> = Vec::with_capacity(count);
    for _ in 0..count {
        let node = choose(nodes, &chosen, &[], &[])?;
        chosen.push(node);
    }
    Some(chosen)
}

/// Where a blob is spread less evenly than it could be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Imbalance {
    /// The domain: one of its children holds at least two of the blob's
    /// shards more than another, which has a node to spare.
    pub domain: Vec<String>,
    /// A shard to move elsewhere within the domain: the node holding it, in
    /// the most crowded part of the crowded child.
    pub from: i32,
    /// How many shards the crowded child holds.
    pub crowded: usize,
}

/// Whether, and where, the blob whose shards are on `held` isn't spread over
/// `nodes`, the nodes that may hold them (live or not): the widest domain
/// where it isn't (see the module's docs). Shards on nodes that aren't among
/// `nodes` (being removed, say) count where they are.
pub fn imbalance(nodes: &[Node], held: &[&Node]) -> Option<Imbalance> {
    // Breadth first, so that the widest domain is found first. Only domains
    // with two shards or more can be uneven within.
    let mut domains: std::collections::VecDeque<Vec<String>> = [Vec::new()].into();
    while let Some(domain) = domains.pop_front() {
        let depth = domain.len();
        // Each child's shards, and whether it has a node to spare.
        let mut children: BTreeMap<Child, (usize, bool)> = BTreeMap::new();
        for h in held.iter().filter(|h| h.within(&domain)) {
            children.entry(h.child(depth)).or_default().0 += 1;
        }
        for n in nodes.iter().filter(|n| n.within(&domain)) {
            if !held.iter().any(|h| h.id == n.id) {
                children.entry(n.child(depth)).or_default().1 = true;
            }
        }
        // The first of the most crowded.
        let Some((&crowded, &(most, _))) =
            children.iter().rev().max_by_key(|(_, (count, _))| *count)
        else {
            continue;
        };
        if children
            .values()
            .any(|&(count, spare)| spare && count + 2 <= most)
        {
            let from = crowdest(held, &domain, crowded);
            return Some(Imbalance {
                domain,
                from,
                crowded: most,
            });
        }
        for (child, (count, _)) in children {
            if let (Child::Domain(name), 2..) = (child, count) {
                let mut below = domain.clone();
                below.push(name.to_owned());
                domains.push_back(below);
            }
        }
    }
    None
}

/// A node holding a shard in `child` of `domain`, in its most crowded part:
/// down from it, level by level, in the child with the most shards.
fn crowdest(held: &[&Node], domain: &[String], child: Child) -> i32 {
    let mut domain = domain.to_vec();
    let mut child = child;
    loop {
        match child {
            Child::Node(id) => return id,
            Child::Domain(name) => domain.push(name.to_owned()),
        }
        let depth = domain.len();
        let mut counts: BTreeMap<Child, usize> = BTreeMap::new();
        for h in held.iter().filter(|h| h.within(&domain)) {
            *counts.entry(h.child(depth)).or_default() += 1;
        }
        child = *counts
            .iter()
            .rev()
            .max_by_key(|(_, count)| **count)
            .expect("a crowded child holds shards")
            .0;
    }
}

/// Whether moving the shard on `from` (see [`Imbalance`]) to `to` makes the
/// blob more even: whether `to`'s child of the imbalance's domain holds at
/// least two shards fewer than the crowded one, the shard aside. `held` is
/// where the blob's shards are, the moving one among them.
pub fn evens(imbalance: &Imbalance, held: &[&Node], to: &Node) -> bool {
    let depth = imbalance.domain.len();
    let child = to.child(depth);
    let there = held
        .iter()
        .filter(|h| h.within(&imbalance.domain) && h.id != imbalance.from)
        .filter(|h| h.child(depth) == child)
        .count();
    there + 2 <= imbalance.crowded
}

/// Of the nodes holding a blob's copies, `held`, the one whose copy to drop
/// so that the rest stays the most spread: in the most crowded domain, level
/// by level from the top. Among equals, the first of `held`.
pub fn crowded_copy(held: &[&Node]) -> Option<i32> {
    let mut candidates: Vec<&Node> = held.to_vec();
    let mut domain: Vec<String> = Vec::new();
    loop {
        let depth = domain.len();
        let mut counts: BTreeMap<Child, usize> = BTreeMap::new();
        for h in &candidates {
            *counts.entry(h.child(depth)).or_default() += 1;
        }
        let most = *counts.values().max()?;
        // The first of `held` in a child with the most.
        let first = candidates
            .iter()
            .find(|h| counts[&h.child(depth)] == most)?
            .child(depth);
        match first {
            Child::Node(id) => return Some(id),
            Child::Domain(name) => {
                let name = name.to_owned();
                candidates.retain(|h| h.path.get(depth) == Some(&name));
                domain.push(name);
            }
        }
    }
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

    fn by_id(nodes: &[Node], ids: &[i32]) -> Vec<Node> {
        ids.iter()
            .map(|id| nodes.iter().find(|n| n.id == *id).unwrap().clone())
            .collect()
    }

    fn regions(chosen: &[&Node]) -> Vec<String> {
        let mut r: Vec<String> = chosen.iter().map(|n| n.path[0].clone()).collect();
        r.sort();
        r
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
        let chosen: Vec<i32> = choose_all(&nodes, 3)
            .unwrap()
            .iter()
            .map(|n| n.id)
            .collect();
        assert_eq!(chosen, [5, 4, 3]);
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
        let r = regions(&chosen);
        assert_eq!(r.iter().filter(|r| *r == "eu").count(), 1, "{r:?}");
        assert_eq!(r.len(), 3);
        r.windows(2).for_each(|w| assert_ne!(w[0], w[1], "{r:?}"));
        // The emptiest node of eu.
        assert!(chosen.iter().any(|n| n.id >= 10));
        assert!(imbalance(&nodes, &chosen).is_none());
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
        let r = regions(&chosen);
        for region in ["a", "b", "c", "d", "e"] {
            assert!(r.iter().any(|x| x == region), "{r:?}");
        }
        // The region with two has them in different zones.
        let twice = r.windows(2).find(|w| w[0] == w[1]).unwrap()[0].clone();
        let zones: Vec<&String> = chosen
            .iter()
            .filter(|n| n.path[0] == twice)
            .map(|n| &n.path[1])
            .collect();
        assert_ne!(zones[0], zones[1]);
        assert!(imbalance(&nodes, &chosen).is_none());
    }

    #[test]
    fn several_instances_per_host_spread_over_hosts_first() {
        let nodes = vec![
            node(1, "r/z/h1", 10),
            node(2, "r/z/h1", 9),
            node(3, "r/z/h2", 8),
            node(4, "r/z/h2", 7),
        ];
        let chosen: Vec<i32> = choose_all(&nodes, 2)
            .unwrap()
            .iter()
            .map(|n| n.id)
            .collect();
        assert_eq!(chosen, [1, 3]);
        let chosen: Vec<i32> = choose_all(&nodes, 4)
            .unwrap()
            .iter()
            .map(|n| n.id)
            .collect();
        assert_eq!(chosen, [1, 3, 2, 4]);
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
        assert_eq!(regions(&held), ["a", "a", "b"]);
        let found = imbalance(&nodes, &held).unwrap();
        assert_eq!(found.domain, Vec::<String>::new());
        assert_eq!(found.crowded, 2);
        assert!([1, 2].contains(&found.from));
        // Not while c is down.
        assert!(choose(&nodes, &held, &[], &[]).is_none());
        nodes[3].live = true;
        let rest: Vec<&Node> = held
            .iter()
            .copied()
            .filter(|n| n.id != found.from)
            .collect();
        let to = choose(&nodes, &rest, &[found.from], &found.domain).unwrap();
        assert_eq!(to.id, 4);
        assert!(evens(&found, &held, to));
        let after: Vec<&Node> = rest.into_iter().chain([to]).collect();
        assert!(imbalance(&nodes, &after).is_none());
    }

    /// A region with as many shards as it should have, but in one zone of
    /// two, is uneven within.
    #[test]
    fn imbalances_are_found_below_the_top() {
        let nodes = vec![
            node(1, "a/1/x", 1),
            node(2, "a/1/y", 1),
            node(3, "a/2/x", 1),
            node(4, "b/1/x", 1),
            node(5, "b/1/y", 1),
        ];
        let held = by_id(&nodes, &[1, 2, 4, 5]);
        let held: Vec<&Node> = held.iter().collect();
        // b has no other zone: only a is uneven.
        let found = imbalance(&nodes, &held).unwrap();
        assert_eq!(found.domain, ["a"]);
        assert_eq!(found.crowded, 2);
        let rest: Vec<&Node> = held
            .iter()
            .copied()
            .filter(|n| n.id != found.from)
            .collect();
        let to = choose(&nodes, &rest, &[found.from], &found.domain).unwrap();
        assert_eq!(to.id, 3);
        assert!(evens(&found, &held, to));
    }

    #[test]
    fn a_full_region_isnt_uneven() {
        // a has one node only: 2 shards in b is as good as it gets.
        let nodes = vec![node(1, "a", 1), node(2, "b", 1), node(3, "b", 1)];
        let held: Vec<&Node> = nodes.iter().collect();
        assert!(imbalance(&nodes, &held).is_none());
        // Nor are shards on nodes being removed, outside `nodes`, a reason.
        let leaving = node(9, "b", 1);
        let held = vec![&nodes[0], &nodes[1], &leaving];
        assert!(imbalance(&nodes, &held).is_none());
    }

    #[test]
    fn evens_wants_two_fewer() {
        let nodes = vec![
            node(1, "a", 1),
            node(2, "a", 1),
            node(3, "b", 1),
            node(4, "c", 1),
        ];
        let held = vec![&nodes[0], &nodes[1], &nodes[2]];
        let found = imbalance(&nodes, &held).unwrap();
        assert!(evens(&found, &held, &nodes[3]));
        // Not into b, which has one already.
        assert!(!evens(&found, &held, &nodes[2]));
    }

    #[test]
    fn the_copy_to_drop_is_the_most_crowded() {
        let nodes = vec![
            node(1, "a/1", 1),
            node(2, "b/1", 1),
            node(3, "b/2", 1),
            node(4, "b/2", 1),
        ];
        let held: Vec<&Node> = nodes.iter().collect();
        assert!([3, 4].contains(&crowded_copy(&held).unwrap()));
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
}

#[cfg(test)]
mod e2e;
