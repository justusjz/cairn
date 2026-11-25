//! Where a blob's shards go: spread over failure domains.
//!
//! A node says where it is with up to five labels, from the widest domain to
//! the narrowest: `--continent`, `--region`, `--az`, `--rack` and `--host`
//! (a [`Location`]). Each is optional, and is scoped by those above it: the
//! region `fsn` on the continent `eu` is another region than `fsn` on `us`,
//! and a rack is a rack of its AZ. A storage class caps how many of a blob's
//! shards one domain of a level may hold ([`Caps`]: `cairn class set
//! STANDARD --max-per region=2,rack=1`); every node holds at most one, as
//! ever. A blob of *k* + *m* shards survives losing any domains that hold *m*
//! of its shards between them, so `region=2` with 2+2 survives a region, and
//! `rack=1` any two racks.
//!
//! ## Placing
//!
//! Nested caps like these (each domain inside one of the level above, and a
//! cap on each) make the sets of nodes a blob's shards may be on a *laminar
//! matroid*. What matters about that: every set of nodes that respects the
//! caps, and can't take another node without breaking one, is of the same
//! size, the *rank*. So nodes can be taken one at a time, in whatever order
//! is preferred, each one that breaks no cap given the ones taken before:
//! that never paints itself into a corner, and always ends with as many
//! nodes as can be had at all. No search, and no backtracking: a placement
//! takes one pass over the candidates per shard, and a check per level. The
//! order is only a preference: here, the least crowded domains first, from
//! the widest level down (a spread as even as the caps allow), then the most
//! free space. Of 5 regions where 2 have 2 racks each and 3 have one, with
//! `region=2,rack=1`, a 4+2 blob always ends up with 2 shards in each of the
//! regions with 2 racks, whatever the order: no other region can take 2.
//!
//! Moving shards is the same, with the nodes that hold the blob's shards
//! already taken first: as many of them as keep to the caps stay where they
//! are (the most that can), and the others' shards move (see `mover`).
//!
//! A level a class caps is one its pool's nodes must say: a node without
//! the label can't be told apart from its neighbours there, so it takes none
//! of the class's shards (and `cairn class set` warns of it). Levels no
//! class caps cost nothing, labelled or not.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// How many levels there are.
pub const DEPTH: usize = 5;

/// The levels, from the widest to the narrowest: their flags' and caps'
/// names.
pub const LEVELS: [&str; DEPTH] = ["continent", "region", "az", "rack", "host"];

/// The most a cap may be.
pub const MAX_CAP: u32 = 64;

/// Where a node is: its label at each level, if it has one (see the
/// module's docs).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Location(pub [Option<String>; DEPTH]);

impl Location {
    /// The domain it's in at `level`: its labels down to that level, which
    /// is what tells domains apart (they're scoped by those above). `None`
    /// if it has no label at that level.
    fn domain(&self, level: usize) -> Option<&[Option<String>]> {
        self.0[level].as_ref()?;
        Some(&self.0[..=level])
    }

    /// Whether it has no labels at all.
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(Option::is_none)
    }
}

impl fmt::Display for Location {
    /// The labels it has, as `region=fsn rack=r1`; `-` for none.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("-");
        }
        let mut first = true;
        for (level, label) in LEVELS.iter().zip(&self.0) {
            if let Some(label) = label {
                if !first {
                    f.write_str(" ")?;
                }
                write!(f, "{level}={label}")?;
                first = false;
            }
        }
        Ok(())
    }
}

/// Whether `label` may be a node's label at a level: 1 to 64 letters,
/// digits, `.`, `-` and `_`.
pub fn valid_label(label: &str) -> bool {
    (1..=64).contains(&label.len())
        && label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// A `--continent`, `--region`, … flag's value.
pub fn parse_label(text: &str) -> Result<String, String> {
    let text = text.trim();
    if valid_label(text) {
        Ok(text.to_owned())
    } else {
        Err(format!(
            "{text:?} can't be a label: 1 to 64 letters, digits, '.', '-' and '_'"
        ))
    }
}

/// How many of a blob's shards a domain of each level may hold, where it's
/// capped (see the module's docs).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caps(pub [Option<u32>; DEPTH]);

impl Caps {
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(Option::is_none)
    }

    /// The levels it caps, with their caps.
    pub fn capped(&self) -> impl Iterator<Item = (usize, u32)> + '_ {
        self.0
            .iter()
            .enumerate()
            .filter_map(|(level, cap)| cap.map(|cap| (level, cap)))
    }

    /// Parses `region=2,rack=1` (or `none`, for no caps), as `cairn class
    /// set --max-per` takes it.
    pub fn parse(text: &str) -> Result<Caps, String> {
        let text = text.trim();
        let mut caps = Caps::default();
        if text.is_empty() || text == "none" {
            return Ok(caps);
        }
        for item in text.split(',') {
            let (name, value) = item.trim().split_once('=').ok_or_else(|| {
                format!(
                    "{item:?} isn't <level>=<shards>, e.g. region=2 (levels: {})",
                    LEVELS.join(", ")
                )
            })?;
            let level = LEVELS
                .iter()
                .position(|l| *l == name.trim())
                .ok_or_else(|| format!("there's no level {name:?}: {}", LEVELS.join(", ")))?;
            let cap: u32 = value
                .trim()
                .parse()
                .ok()
                .filter(|c| (1..=MAX_CAP).contains(c))
                .ok_or_else(|| {
                    format!("{name}'s cap must be between 1 and {MAX_CAP}, not {value:?}")
                })?;
            if caps.0[level].replace(cap).is_some() {
                return Err(format!("{name} is capped twice"));
            }
        }
        Ok(caps)
    }

    /// As a catalog column: a cap per level, NULL where there's none.
    pub fn to_column(self) -> Vec<Option<i16>> {
        self.0.iter().map(|c| c.map(|c| c as i16)).collect()
    }

    /// From a catalog column (see `to_column`); NULL is no caps.
    pub fn from_column(column: Option<Vec<Option<i16>>>) -> Caps {
        let mut caps = Caps::default();
        for (level, cap) in column
            .unwrap_or_default()
            .into_iter()
            .enumerate()
            .take(DEPTH)
        {
            caps.0[level] = cap.map(|c| c.max(1) as u32);
        }
        caps
    }

    /// Whether a node at `location` may take the shards of a blob with
    /// these caps: it has a label at every level they cap.
    pub fn eligible(&self, location: &Location) -> bool {
        self.capped().all(|(level, _)| location.0[level].is_some())
    }

    /// What's odd about the caps, as warnings: a level capped higher than
    /// one above it, whose cap then never bites.
    pub fn oddities(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        let mut above: Option<(usize, u32)> = None;
        for (level, cap) in self.capped() {
            if let Some((wider, wider_cap)) = above
                && cap > wider_cap
            {
                warnings.push(format!(
                    "{} is capped at {cap}, but a {} holds at most {wider_cap}: the {} cap never bites",
                    LEVELS[level], LEVELS[wider], LEVELS[level]
                ));
            }
            if above.is_none_or(|(_, c)| cap <= c) {
                above = Some((level, cap));
            }
        }
        warnings
    }

    /// What a blob of `parity_shards` parity shards survives losing with
    /// these caps, in words: per level, as many whole domains as hold no
    /// more than its parity shards between them, and any `parity_shards`
    /// nodes. And the levels at which losing one domain can lose data.
    pub fn survives(&self, parity_shards: u32) -> String {
        let mut parts = Vec::new();
        let mut effective = u32::MAX;
        for (level, cap) in self.0.iter().enumerate() {
            let Some(cap) = cap else { continue };
            effective = effective.min(*cap);
            let name = LEVELS[level];
            let lost = parity_shards / effective;
            parts.push(match lost {
                0 => format!("no lost {name}"),
                1 => format!("1 {name}"),
                n => format!("{n} {name}s"),
            });
        }
        parts.push(match parity_shards {
            1 => "1 node".to_owned(),
            n => format!("{n} nodes"),
        });
        parts.join(", or ")
    }
}

impl fmt::Display for Caps {
    /// As `cairn class set --max-per` takes them: `region=2,rack=1`, or
    /// `-` for none.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("-");
        }
        let items: Vec<String> = self
            .capped()
            .map(|(level, cap)| format!("{}={cap}", LEVELS[level]))
            .collect();
        f.write_str(&items.join(","))
    }
}

/// Chooses up to `count` of `candidates` (each a node, at its location) for
/// a blob's shards, as the module's docs describe, keeping to `caps`: the
/// first `keep` candidates are the nodes that hold its shards already
/// (unless placing anew), which are taken first, as many as keep to the
/// caps, in their order; then the others, the least crowded domains first,
/// widest level first, and in their order among equals (the most preferred
/// first: the most free space, say). Candidates that can't take the class's
/// shards (see [`Caps::eligible`]) are passed over.
///
/// Returns the indexes of the chosen candidates, in the order they were
/// chosen: fewer than `count` if no more can be had (the rank, see the
/// module's docs).
pub fn place(candidates: &[&Location], keep: usize, caps: &Caps, count: usize) -> Vec<usize> {
    let mut placer = Placer::new(caps);
    let mut chosen = Vec::new();
    for (i, location) in candidates.iter().enumerate().take(keep) {
        if chosen.len() == count {
            return chosen;
        }
        if caps.eligible(location) && placer.fits(location) {
            placer.take(location);
            chosen.push(i);
        }
    }
    let mut left: Vec<usize> = (keep..candidates.len())
        .filter(|&i| caps.eligible(candidates[i]))
        .collect();
    while chosen.len() < count {
        // The candidate that fits in the least crowded domains, widest level
        // first, then the earliest.
        let best = left
            .iter()
            .enumerate()
            .filter(|&(_, &i)| placer.fits(candidates[i]))
            .min_by_key(|&(_, &i)| (placer.crowding(candidates[i]), i));
        let Some((at, &i)) = best else { break };
        placer.take(candidates[i]);
        chosen.push(i);
        left.remove(at);
    }
    chosen
}

/// The one of `candidates` to take another shard of a blob whose other
/// shards are on nodes at `held`, keeping to `caps` (where `held` keeps to
/// them; else as well as they allow): the one in the least crowded domains,
/// widest level first, then the earliest. `None` if none can.
pub fn next(held: &[&Location], candidates: &[&Location], caps: &Caps) -> Option<usize> {
    let mut placer = Placer::new(caps);
    for location in held {
        placer.take(location);
    }
    candidates
        .iter()
        .enumerate()
        .filter(|(_, location)| caps.eligible(location) && placer.fits(location))
        .min_by_key(|&(i, location)| (placer.crowding(location), i))
        .map(|(i, _)| i)
}

/// How many levels, from the widest, nodes at `a` and `b` share a domain
/// at: 0 if they're on different continents (or either has none).
pub fn shared_depth(a: &Location, b: &Location) -> usize {
    (0..DEPTH)
        .take_while(|&level| a.0[level].is_some() && a.0[..=level] == b.0[..=level])
        .count()
}

/// How many shards of a blob with `caps` can be placed on `candidates` at
/// most: the rank (see the module's docs).
pub fn rank(candidates: &[&Location], caps: &Caps) -> usize {
    place(candidates, 0, caps, usize::MAX).len()
}

/// Whether the shards of a blob on nodes at `locations` (one shard each)
/// keep to `caps`.
#[cfg(test)]
pub fn keeps_to(locations: &[&Location], caps: &Caps) -> bool {
    let mut placer = Placer::new(caps);
    locations.iter().all(|location| {
        let fits = placer.fits(location);
        placer.take(location);
        fits
    })
}

/// The shards of a blob taken so far: how many each domain holds.
struct Placer<'a> {
    caps: &'a Caps,
    held: HashMap<Vec<Option<String>>, u32>,
}

impl<'a> Placer<'a> {
    fn new(caps: &'a Caps) -> Self {
        Placer {
            caps,
            held: HashMap::new(),
        }
    }

    fn held(&self, domain: &[Option<String>]) -> u32 {
        self.held.get(domain).copied().unwrap_or(0)
    }

    /// Whether a node at `location` can take a shard without a domain it's
    /// in holding more than its level's cap. One without the label of a
    /// capped level fits nowhere but on its own (see `Caps::eligible`):
    /// it's counted in the domain of all such nodes, which errs towards
    /// crowding.
    fn fits(&self, location: &Location) -> bool {
        self.caps
            .capped()
            .all(|(level, cap)| self.held(&location.0[..=level]) < cap)
    }

    /// Counts a shard on a node at `location`.
    fn take(&mut self, location: &Location) {
        for level in 0..DEPTH {
            *self.held.entry(location.0[..=level].to_vec()).or_default() += 1;
        }
    }

    /// How many shards the domains of a node at `location` hold already,
    /// widest level first (0 at levels it has no label at: they don't count
    /// towards a spread).
    fn crowding(&self, location: &Location) -> [u32; DEPTH] {
        let mut crowding = [0; DEPTH];
        for (level, slot) in crowding.iter_mut().enumerate() {
            if let Some(domain) = location.domain(level) {
                *slot = self.held(domain);
            }
        }
        crowding
    }
}

#[cfg(test)]
mod e2e;

#[cfg(test)]
mod tests {
    use super::*;

    /// A location from `region/rack`-style labels, at levels from `first`.
    fn at(first: usize, labels: &str) -> Location {
        let mut location = Location::default();
        for (i, label) in labels.split('/').enumerate() {
            if !label.is_empty() && label != "-" {
                location.0[first + i] = Some(label.to_owned());
            }
        }
        location
    }

    /// Regions and racks (levels 1 and 3), as `region/rack`.
    fn racked(labels: &str) -> Location {
        let (region, rack) = labels.split_once('/').unwrap();
        let mut location = Location::default();
        location.0[1] = Some(region.to_owned());
        location.0[3] = Some(rack.to_owned());
        location
    }

    fn refs(locations: &[Location]) -> Vec<&Location> {
        locations.iter().collect()
    }

    fn regions_of(locations: &[Location], chosen: &[usize]) -> Vec<String> {
        let mut regions: Vec<String> = chosen
            .iter()
            .map(|&i| locations[i].0[1].clone().unwrap())
            .collect();
        regions.sort();
        regions
    }

    #[test]
    fn caps_parse_and_print() {
        let caps = Caps::parse("region=2, rack=1").unwrap();
        assert_eq!(caps.0, [None, Some(2), None, Some(1), None]);
        assert_eq!(caps.to_string(), "region=2,rack=1");
        assert_eq!(Caps::parse("none").unwrap(), Caps::default());
        assert_eq!(Caps::default().to_string(), "-");
        assert!(Caps::parse("zone=2").is_err());
        assert!(Caps::parse("region=0").is_err());
        assert!(Caps::parse("region=two").is_err());
        assert!(Caps::parse("region").is_err());
        assert!(Caps::parse("region=1,region=2").is_err());
        assert_eq!(Caps::from_column(Some(caps.to_column())), caps);
        assert_eq!(Caps::from_column(None), Caps::default());
    }

    #[test]
    fn labels() {
        for label in ["fsn", "eu-central", "r1.2", "A_b"] {
            assert!(valid_label(label), "{label}");
        }
        for label in ["", "a b", "a/b", "ä", &"a".repeat(65)] {
            assert!(!valid_label(label), "{label}");
        }
        assert_eq!(at(1, "fsn/-/r1").to_string(), "region=fsn rack=r1");
        assert_eq!(Location::default().to_string(), "-");
    }

    /// The case from the module's docs: 5 regions, 2 with 2 racks, and 4+2
    /// with at most 2 shards a region and 1 a rack. The regions with 2
    /// shards must be the ones with 2 racks, whichever way the candidates
    /// are ordered.
    #[test]
    fn two_shards_go_only_where_there_are_two_racks() {
        let caps = Caps::parse("region=2,rack=1").unwrap();
        let base = [
            "fsn/r1", "fsn/r2", "hel/r1", "hel/r2", "ams/r1", "par/r1", "waw/r1",
        ];
        // A second node in each single-rack region, which mustn't help.
        let extra = ["ams/r1", "par/r1", "waw/r1"];
        let all: Vec<&str> = base.iter().chain(&extra).copied().collect();
        // Every rotation, and its reverse, of the candidates.
        for shift in 0..all.len() {
            for reverse in [false, true] {
                let mut order = all.clone();
                order.rotate_left(shift);
                if reverse {
                    order.reverse();
                }
                let locations: Vec<Location> = order.iter().map(|l| racked(l)).collect();
                let chosen = place(&refs(&locations), 0, &caps, 6);
                assert_eq!(chosen.len(), 6, "{order:?}");
                let picked: Vec<&Location> = chosen.iter().map(|&i| &locations[i]).collect();
                assert!(keeps_to(&picked, &caps));
                let mut counts: HashMap<String, usize> = HashMap::new();
                for r in regions_of(&locations, &chosen) {
                    *counts.entry(r).or_default() += 1;
                }
                // Every region has one, and the one with two has two racks.
                assert_eq!(counts.len(), 5, "{order:?}");
                for (region, n) in &counts {
                    assert!(*n == 1 || region == "fsn" || region == "hel", "{order:?}");
                }
            }
        }
        let locations: Vec<Location> = all.iter().map(|l| racked(l)).collect();
        assert_eq!(rank(&refs(&locations), &caps), 7);
        // With hel down, the 2 must be fsn's: 2 + 1 + 1 + 1 is only 5, so a
        // sixth shard can't be had at all, whatever the order.
        let without_hel: Vec<Location> = all
            .iter()
            .filter(|l| !l.starts_with("hel"))
            .map(|l| racked(l))
            .collect();
        assert_eq!(rank(&refs(&without_hel), &caps), 5);
        let chosen = place(&refs(&without_hel), 0, &caps, 5);
        let fsn = chosen
            .iter()
            .filter(|&&i| without_hel[i].0[1].as_deref() == Some("fsn"))
            .count();
        assert_eq!(fsn, 2);
    }

    #[test]
    fn fewer_than_wanted_when_the_caps_allow_no_more() {
        // 3+1 with one shard a region needs 4 regions; 3 are up.
        let caps = Caps::parse("region=1").unwrap();
        let locations: Vec<Location> = ["fsn/a", "fsn/b", "hel/a", "ams/a"]
            .iter()
            .map(|l| racked(l))
            .collect();
        let chosen = place(&refs(&locations), 0, &caps, 4);
        assert_eq!(chosen.len(), 3);
        assert_eq!(rank(&refs(&locations), &caps), 3);
    }

    #[test]
    fn spreads_evenly_without_caps_but_prefers_order_among_equals() {
        // No caps: still one region each before a second in any.
        let locations: Vec<Location> = ["fsn/a", "fsn/b", "fsn/c", "hel/a", "ams/a"]
            .iter()
            .map(|l| racked(l))
            .collect();
        let chosen = place(&refs(&locations), 0, &Caps::default(), 3);
        assert_eq!(chosen, vec![0, 3, 4]);
        // A fourth goes to the first region again, on another rack.
        let chosen = place(&refs(&locations), 0, &Caps::default(), 4);
        assert_eq!(chosen, vec![0, 3, 4, 1]);
    }

    #[test]
    fn regions_are_scoped_by_continent() {
        let caps = Caps::parse("region=1").unwrap();
        let locations = vec![at(0, "eu/fsn"), at(0, "us/fsn"), at(0, "eu/fsn")];
        let chosen = place(&refs(&locations), 0, &caps, 3);
        assert_eq!(chosen, vec![0, 1], "two fsn regions, one shard each");
    }

    #[test]
    fn unlabelled_nodes_take_no_shards_at_a_capped_level() {
        let caps = Caps::parse("rack=1").unwrap();
        let locations = vec![at(1, "fsn"), at(1, "fsn/-/r1"), at(1, "fsn/-/r2")];
        assert_eq!(place(&refs(&locations), 0, &caps, 3), vec![1, 2]);
        // Uncapped, they're as good as any.
        assert_eq!(place(&refs(&locations), 0, &Caps::default(), 3).len(), 3);
    }

    #[test]
    fn holders_stay_where_they_can() {
        let caps = Caps::parse("region=1").unwrap();
        // Shards on fsn, fsn, hel (fsn has one too many); ams and par are free.
        let locations: Vec<Location> = ["fsn/a", "fsn/b", "hel/a", "ams/a", "par/a"]
            .iter()
            .map(|l| racked(l))
            .collect();
        let chosen = place(&refs(&locations), 3, &caps, 3);
        assert_eq!(chosen.len(), 3);
        // Two of the holders stay, the second fsn one moves.
        assert_eq!(&chosen[..2], &[0, 2]);
        assert!(chosen[2] >= 3);
        // Holders that keep to the caps all stay.
        let chosen = place(&refs(&locations), 3, &Caps::default(), 3);
        assert_eq!(chosen, vec![0, 1, 2]);
    }

    #[test]
    fn keeps_to_checks_every_level() {
        let caps = Caps::parse("region=2,rack=1").unwrap();
        let ok = [racked("fsn/a"), racked("fsn/b"), racked("hel/a")];
        assert!(keeps_to(&refs(&ok), &caps));
        let same_rack = [racked("fsn/a"), racked("fsn/a")];
        assert!(!keeps_to(&refs(&same_rack), &caps));
        let crowded = [racked("fsn/a"), racked("fsn/b"), racked("fsn/c")];
        assert!(!keeps_to(&refs(&crowded), &caps));
    }

    #[test]
    fn guarantees_in_words() {
        let caps = Caps::parse("region=2,rack=1").unwrap();
        assert_eq!(caps.survives(2), "1 region, or 2 racks, or 2 nodes");
        assert_eq!(
            Caps::parse("region=1").unwrap().survives(1),
            "1 region, or 1 node"
        );
        assert_eq!(
            Caps::parse("region=3").unwrap().survives(2),
            "no lost region, or 2 nodes"
        );
        assert_eq!(Caps::default().survives(2), "2 nodes");
        // A rack capped above its region goes by the region's.
        assert_eq!(
            Caps::parse("region=1,rack=2").unwrap().survives(2),
            "2 regions, or 2 racks, or 2 nodes"
        );
        assert_eq!(Caps::parse("region=1,rack=2").unwrap().oddities().len(), 1);
        assert!(caps.oddities().is_empty());
    }

    /// Random clusters and caps: greedy in any order reaches the rank, and
    /// the rank is what an exhaustive search finds.
    #[test]
    fn greedy_reaches_the_most_there_is() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        for _ in 0..300 {
            let nodes = 1 + next(9) as usize;
            let locations: Vec<Location> = (0..nodes)
                .map(|_| {
                    let mut l = Location::default();
                    l.0[0] = Some(format!("c{}", next(2)));
                    l.0[1] = Some(format!("r{}", next(3)));
                    l.0[3] = Some(format!("k{}", next(2)));
                    l
                })
                .collect();
            let mut caps = Caps::default();
            for level in [0, 1, 3] {
                if next(2) == 0 {
                    caps.0[level] = Some(1 + next(3) as u32);
                }
            }
            // The largest subset that keeps to the caps, by brute force.
            let best = (0u32..1 << nodes)
                .filter(|mask| {
                    let set: Vec<&Location> = (0..nodes)
                        .filter(|i| mask & (1 << i) != 0)
                        .map(|i| &locations[i])
                        .collect();
                    keeps_to(&set, &caps)
                })
                .map(u32::count_ones)
                .max()
                .unwrap() as usize;
            let all = refs(&locations);
            assert_eq!(rank(&all, &caps), best, "{locations:?} {caps:?}");
            // Taking any holders first doesn't lose any either.
            let keep = next(nodes as u64 + 1) as usize;
            let chosen = place(&all, keep, &caps, usize::MAX);
            assert_eq!(chosen.len(), best);
            let picked: Vec<&Location> = chosen.iter().map(|&i| &locations[i]).collect();
            assert!(keeps_to(&picked, &caps));
        }
    }
}
