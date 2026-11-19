//! The backup's runner: one node at a time ships the cluster's changes to
//! the target, a cycle every `interval` (see `backup` for the design).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use deadpool_postgres::Object;
use tokio::sync::mpsc;
use tokio_postgres::IsolationLevel;
use uuid::Uuid;

use super::crypt::ObjectWriter;
use super::format::{self, JournalMeta, ObjectRef, PackMeta, PartRef};
use super::s3::Target;
use super::{Config, State, capture};
use crate::App;
use crate::blobs::{BlobSlice, Location, stream_blob_range};
use crate::packer::{Part, Run, Verifier, lay_out, load_blobs};
use crate::shards::Layout;

/// The most changes a journal ships. A larger backlog is shipped by several
/// journals, one right after another.
const CHANGES_PER_JOURNAL: i64 = 200_000;
/// How many bytes of parts that were there before the backup began (or
/// that a reset lost track of) a cycle backs up at most, in packs' sizes.
const BACKFILL_PACKS: u64 = 16;
/// How many such parts a cycle looks at, at most.
const BACKFILL_ROWS: i64 = 100_000;
/// How many parts that moved into or out of a tier a cycle takes, at most.
const MOVES_PER_JOURNAL: i64 = 100_000;
/// How long a journal's parts may wait to be packed: until there are a
/// pack's worth, or a day has passed.
const SEAL_AFTER_SECS: i64 = 24 * 3600;
/// A pack is rewritten once less than this fraction of it is still needed
/// (see `backup`): so the target holds at most about twice what's live, and a
/// rewrite adds at most half a pack, while the old one is retained.
pub const COMPACT_BELOW: f64 = 0.5;
/// How many bytes, in packs' sizes, a cycle rewrites at most.
const REWRITE_PACKS: u64 = 4;
/// A base is taken once the journals since the last one add up to its size,
/// but at least this much, or once there have been this many.
const MIN_REBASE_BYTES: i64 = 64 << 20;
const MAX_JOURNALS_PER_BASE: i64 = 2016;

/// What a cycle did.
#[derive(Debug, Default)]
pub struct Cycle {
    /// The journal it wrote, if there was anything to ship.
    pub journal: Option<i64>,
    pub changes: usize,
    pub parts: usize,
    pub bytes: u64,
    /// Whether there's more to ship right away.
    pub again: bool,
    /// Whether the schema changed since the last base, which has to come
    /// first.
    pub needs_base: bool,
}

/// A node's turn at running the backup: holds the lease (`token`) and the
/// generation it last saw, which every commit checks and bumps, so that a
/// runner that lost its lease commits nothing.
pub struct Runner<'a> {
    pub app: &'a Arc<App>,
    pub config: Config,
    pub target: Target,
    pub token: Uuid,
    pub generation: i64,
}

/// A part to back up, where it is now, and its class.
struct Candidate {
    part: Part,
    class: String,
}

/// An object being filled with parts: its runs, and its parts in order of
/// their places in it.
struct Output {
    runs: Vec<Run>,
    parts: Vec<Part>,
}

/// Lays `candidates` out into outputs of about `target` bytes each.
fn outputs(candidates: Vec<Candidate>, target: u64, classes: &mut HashMap<i64, String>) -> Vec<Output> {
    let mut parts = Vec::with_capacity(candidates.len());
    for c in candidates {
        classes.insert(c.part.id, c.class);
        parts.push(c.part);
    }
    if parts.is_empty() {
        return Vec::new();
    }
    let runs = lay_out(&mut parts, target);
    let count = runs.iter().map(|r| r.output + 1).max().unwrap_or(0);
    let mut outputs: Vec<Output> = (0..count).map(|_| Output { runs: Vec::new(), parts: Vec::new() }).collect();
    let mut parts_by_run: Vec<Vec<Part>> = (0..runs.len()).map(|_| Vec::new()).collect();
    for part in parts {
        parts_by_run[part.run].push(part);
    }
    for (run, parts) in runs.into_iter().zip(parts_by_run) {
        let output = &mut outputs[run.output];
        let first = output.parts.len();
        output.parts.extend(parts);
        output.runs.push(Run { parts: first..output.parts.len(), ..run });
    }
    outputs
}

fn candidate(row: &tokio_postgres::Row) -> Candidate {
    Candidate {
        part: Part {
            id: row.get(0),
            blob_id: row.get(1),
            offset: row.get::<_, i64>(2) as u64,
            size: row.get::<_, i64>(3) as u64,
            output: 0,
            new_offset: 0,
            run: 0,
            crc64nvme: row.get::<_, Option<i64>>(4).map(|crc| crc as u64),
            etag: row.get(5),
        },
        class: row.get(6),
    }
}

/// The columns `candidate` reads, of `parts p` and `blobs b`.
const CANDIDATE_COLUMNS: &str = "p.id, p.blob_id, p.blob_offset, p.size, p.crc64nvme, p.etag, b.storage_class";

/// Whether a part's bytes are known lost in the cluster (see `scrub`).
const LOST: &str = "EXISTS (SELECT 1 FROM lost_ranges l WHERE l.blob_id = p.blob_id
                            AND l.start < p.blob_offset + p.size AND l.stop > p.blob_offset)";

/// Copies an output's parts from the cluster into `writer`, where they
/// start at `base`, checking each against its checksum on the way.
async fn copy_output(
    app: &App,
    blobs: &HashMap<Uuid, (Option<Layout>, Vec<Location>)>,
    output: &Output,
    writer: &mut ObjectWriter,
) -> anyhow::Result<()> {
    let mut verifier = Verifier::new(&output.parts);
    for run in &output.runs {
        let (layout, locations) = blobs.get(&run.blob_id).cloned().unwrap_or_default();
        let mut slice = BlobSlice {
            blob_id: run.blob_id,
            layout,
            locations,
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
        read.map_err(|e| anyhow::anyhow!("reading blob {}: {e}", run.blob_id))?;
        anyhow::ensure!(copied? == run.length, "blob {} ended early", run.blob_id);
    }
    verifier.finish().map_err(|e| anyhow::anyhow!("backing up parts: {e}"))
}

/// A byte range of a blob whose bytes are backed up, and where.
#[derive(Clone, Copy)]
struct Backed {
    start: u64,
    end: u64,
    object: Uuid,
    at: u64,
}

/// The backed-up ranges of a blob, to find one that covers a range in.
struct Covers {
    /// By start; and of those up to each, the one that ends last.
    ranges: Vec<Backed>,
    furthest: Vec<usize>,
}

impl Covers {
    fn new(mut ranges: Vec<Backed>) -> Covers {
        ranges.sort_by_key(|r| r.start);
        let mut furthest: Vec<usize> = Vec::with_capacity(ranges.len());
        for (i, r) in ranges.iter().enumerate() {
            let best = match furthest.last() {
                Some(&j) if ranges[j].end >= r.end => j,
                _ => i,
            };
            furthest.push(best);
        }
        Covers { ranges, furthest }
    }

    /// A range that holds all of [`start`, `end`).
    fn find(&self, start: u64, end: u64) -> Option<Backed> {
        let n = self.ranges.partition_point(|r| r.start <= start);
        let best = self.ranges[*self.furthest.get(n.checked_sub(1)?)?];
        (best.end >= end).then_some(best)
    }
}

/// The ID in a change's key (`[id]`).
fn key_id(key: &Option<String>) -> Option<i64> {
    let key: Vec<serde_json::Value> = serde_json::from_str(key.as_deref()?).ok()?;
    key.first()?.as_i64()
}

impl Runner<'_> {
    async fn client(&self) -> anyhow::Result<Object> {
        Ok(self.app.pool.get().await?)
    }

    /// Runs a cycle: ships the changes logged since the last one in a
    /// journal, with the parts they added (and some of those that were there
    /// before the backup began), and rewrites what's due.
    pub async fn cycle(&mut self, state: &State) -> anyhow::Result<Cycle> {
        let mut client = self.client().await?;
        // The changes of committed transactions, as of a snapshot.
        let tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await?;
        let snapshot: String = tx.query_one("SELECT pg_current_snapshot()::text", &[]).await?.get(0);
        let version: i32 = tx.query_one("SELECT max(version) FROM schema_migrations", &[]).await?.get(0);
        // Changes are rows of the schema of the base they follow: the one
        // being built, if one is.
        let expected = state.building.as_ref().map(|b| b.version).or(state.base_version);
        if expected != Some(version) {
            return Ok(Cycle { needs_base: true, ..Cycle::default() });
        }
        let rows = tx
            .query(
                "SELECT seq, xid::text, tbl, op::text, key, row FROM backup_changes ORDER BY seq LIMIT $1",
                &[&CHANGES_PER_JOURNAL],
            )
            .await?;
        let sequences = capture::sequences(&tx).await?;
        tx.commit().await?;
        let full = rows.len() as i64 == CHANGES_PER_JOURNAL;

        let mut consumed = Vec::with_capacity(rows.len());
        let mut changes = Vec::with_capacity(rows.len());
        let mut inserted: Vec<i64> = Vec::new();
        let mut deleted: HashSet<i64> = HashSet::new();
        let mut truncated = false;
        for row in rows {
            let (seq, xid, tbl, op, key, image): (i64, String, String, String, Option<String>, Option<String>) =
                (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4), row.get(5));
            if tbl == "parts" {
                match (op.as_str(), key_id(&key)) {
                    ("I", Some(id)) => inserted.push(id),
                    ("D", Some(id)) => {
                        deleted.insert(id);
                    }
                    ("T", _) => {
                        truncated = true;
                        inserted.clear();
                        deleted.clear();
                    }
                    _ => {}
                }
            }
            consumed.push(seq);
            changes.push((xid.parse::<u64>()?, tbl, op, key, image));
        }
        let new_ids: Vec<i64> = inserted.into_iter().filter(|id| !deleted.contains(id)).collect();
        // Parts that moved into or out of a tier since (see `tiers`): the
        // backup points those in a tier at its objects, and backs up
        // anew those that came back, whose tier object is going.
        let moves = self
            .client()
            .await?
            .query(
                "SELECT seq, part_id FROM backup_tier_moves ORDER BY seq LIMIT $1",
                &[&MOVES_PER_JOURNAL],
            )
            .await?;
        let moved_seqs: Vec<i64> = moves.iter().map(|r| r.get(0)).collect();
        let moved_ids: Vec<i64> = moves.iter().map(|r| r.get::<_, i64>(1)).filter(|id| !deleted.contains(id)).collect();

        // The parts to back up: those just added (unless they're there
        // already, as copies of what is), and some of those from before.
        let client = self.client().await?;
        let mut mappings: Vec<PartRef> = Vec::new();
        let mut unavailable: Vec<i64> = Vec::new();
        let mut fresh: Vec<Candidate> = Vec::new();
        let rows = client
            .query(
                &format!(
                    "SELECT {CANDIDATE_COLUMNS},
                            EXISTS (SELECT 1 FROM backup_parts bp WHERE bp.part_id = p.id), {LOST}
                     FROM parts p JOIN blobs b ON b.blob_id = p.blob_id
                     WHERE p.id = ANY($1)"
                ),
                &[&new_ids],
            )
            .await?;
        let mut seen: HashSet<i64> = HashSet::new();
        for row in &rows {
            let id: i64 = row.get(0);
            seen.insert(id);
            if truncated || !row.get::<_, bool>(7) {
                if row.get::<_, bool>(8) {
                    unavailable.push(id);
                } else {
                    fresh.push(candidate(row));
                }
            }
        }
        unavailable.extend(new_ids.iter().filter(|id| !seen.contains(id)));
        let mut backfill = if truncated { Some(0) } else { state.backfill_after };
        if let Some(after) = backfill {
            let budget = BACKFILL_PACKS * self.config.pack_size;
            let rows = client
                .query(
                    &format!(
                        "SELECT {CANDIDATE_COLUMNS}, {LOST}
                         FROM parts p JOIN blobs b ON b.blob_id = p.blob_id
                         WHERE p.id > $1 AND ($3 OR NOT EXISTS (SELECT 1 FROM backup_parts bp WHERE bp.part_id = p.id))
                         ORDER BY p.id LIMIT $2"
                    ),
                    &[&after, &BACKFILL_ROWS, &truncated],
                )
                .await?;
            let mut bytes = 0;
            let mut last = after;
            let mut stopped = false;
            for row in &rows {
                let id: i64 = row.get(0);
                if bytes >= budget {
                    stopped = true;
                    break;
                }
                last = id;
                if seen.contains(&id) || deleted.contains(&id) {
                    continue;
                }
                if row.get::<_, bool>(7) {
                    unavailable.push(id);
                    continue;
                }
                let c = candidate(row);
                bytes += c.part.size;
                fresh.push(c);
            }
            backfill = (stopped || rows.len() as i64 == BACKFILL_ROWS).then_some(last);
        }
        // Parts that came back from a tier, whose record points at the
        // tier's object: backed up anew.
        if !moved_ids.is_empty() && !truncated {
            let rows = client
                .query(
                    &format!(
                        "SELECT {CANDIDATE_COLUMNS}, {LOST}
                         FROM parts p JOIN blobs b ON b.blob_id = p.blob_id
                         WHERE p.id = ANY($1) AND b.state <> 'remote'
                           AND NOT EXISTS (SELECT 1 FROM backup_parts bp JOIN backup_objects o ON o.id = bp.object
                                           WHERE bp.part_id = p.id AND o.kind <> 'tier')"
                    ),
                    &[&moved_ids],
                )
                .await?;
            let taken: HashSet<i64> = fresh.iter().map(|c| c.part.id).collect();
            for row in &rows {
                let id: i64 = row.get(0);
                if taken.contains(&id) {
                    continue;
                }
                if row.get::<_, bool>(7) {
                    unavailable.push(id);
                } else {
                    fresh.push(candidate(row));
                }
            }
        }
        // Parts in a tier: pointed at its objects, rather than copied.
        let mut tier_objects: Vec<ObjectRef> = Vec::new();
        {
            let ids: Vec<i64> = fresh.iter().map(|c| c.part.id).chain(moved_ids.iter().copied()).collect();
            let rows = client
                .query(
                    "SELECT p.id, p.blob_id, p.blob_offset, p.size, b.storage_class, tb.tier, tb.name, tb.size
                     FROM parts p JOIN blobs b ON b.blob_id = p.blob_id JOIN tier_blobs tb ON tb.blob_id = p.blob_id
                     WHERE p.id = ANY($1) AND b.state = 'remote'",
                    &[&ids],
                )
                .await?;
            let mut tiered: HashSet<i64> = HashSet::new();
            let mut objects: HashSet<Uuid> = HashSet::new();
            for row in &rows {
                let id: i64 = row.get(0);
                if !tiered.insert(id) {
                    continue;
                }
                let blob: Uuid = row.get(1);
                mappings.push((id, blob, row.get::<_, i64>(2) as u64, row.get::<_, i64>(3) as u64, row.get(4)));
                if objects.insert(blob) {
                    let (tier, name, size): (String, String, i64) = (row.get(5), row.get(6), row.get(7));
                    tier_objects.push(ObjectRef { id: blob, name: format::tier_object_name(&tier, &name), size: size as u64 });
                }
            }
            fresh.retain(|c| !tiered.contains(&c.part.id));
        }
        // Parts whose bytes are backed up already, as another part's: a copy.
        if !fresh.is_empty() && !truncated {
            let mut blobs: Vec<Uuid> = fresh.iter().map(|c| c.part.blob_id).collect();
            blobs.sort();
            blobs.dedup();
            let rows = client
                .query(
                    "SELECT q.blob_id, q.blob_offset, q.size, bp.object, bp.\"offset\"
                     FROM parts q JOIN backup_parts bp ON bp.part_id = q.id
                     JOIN backup_objects o ON o.id = bp.object AND o.kind <> 'tier'
                     WHERE q.blob_id = ANY($1)",
                    &[&blobs],
                )
                .await?;
            let mut backed: HashMap<Uuid, Vec<Backed>> = HashMap::new();
            for row in &rows {
                backed.entry(row.get(0)).or_default().push(Backed {
                    start: row.get::<_, i64>(1) as u64,
                    end: (row.get::<_, i64>(1) + row.get::<_, i64>(2)) as u64,
                    object: row.get(3),
                    at: row.get::<_, i64>(4) as u64,
                });
            }
            let covers: HashMap<Uuid, Covers> = backed.into_iter().map(|(blob, b)| (blob, Covers::new(b))).collect();
            fresh.retain(|c| {
                let found = covers.get(&c.part.blob_id).and_then(|covers| covers.find(c.part.offset, c.part.offset + c.part.size));
                match found {
                    Some(b) => {
                        mappings.push((c.part.id, b.object, b.at + (c.part.offset - b.start), c.part.size, c.class.clone()));
                        false
                    }
                    None => true,
                }
            });
        }

        // What's due to be rewritten: the parts in journals, once there's a
        // pack's worth or the oldest has waited long enough, and those of
        // packs that are mostly garbage.
        let pack_size = self.config.pack_size as i64;
        let rows = client
            .query(
                "SELECT id, kind, live_bytes, extract(epoch FROM now() - created_at)::bigint
                 FROM backup_objects
                 WHERE refs > 0 AND (kind = 'journal' OR (kind = 'pack' AND live_bytes < size * $1::float8))
                 ORDER BY kind = 'pack', created_at",
                &[&COMPACT_BELOW],
            )
            .await?;
        let journal_live: i64 = rows.iter().filter(|r| r.get::<_, &str>(1) == "journal").map(|r| r.get::<_, i64>(2)).sum();
        let oldest = rows
            .iter()
            .filter(|r| r.get::<_, &str>(1) == "journal")
            .map(|r| r.get::<_, i64>(3))
            .max()
            .unwrap_or(0);
        let seal = journal_live >= pack_size || oldest >= SEAL_AFTER_SECS;
        let mut rewrite: Vec<Uuid> = Vec::new();
        let mut budget = (REWRITE_PACKS * self.config.pack_size) as i64;
        for row in &rows {
            let live: i64 = row.get(2);
            if (row.get::<_, &str>(1) == "journal" && !seal) || (live > budget && !rewrite.is_empty()) {
                continue;
            }
            budget -= live;
            rewrite.push(row.get(0));
        }
        let mut moved: Vec<Candidate> = Vec::new();
        if !rewrite.is_empty() {
            let rows = client
                .query(
                    &format!(
                        "SELECT {CANDIDATE_COLUMNS}, {LOST}
                         FROM backup_parts bp JOIN parts p ON p.id = bp.part_id
                         JOIN blobs b ON b.blob_id = p.blob_id
                         WHERE bp.object = ANY($1) AND b.state <> 'remote'"
                    ),
                    &[&rewrite],
                )
                .await?;
            let mapped: HashSet<i64> = mappings.iter().map(|m| m.0).collect();
            for row in &rows {
                if !deleted.contains(&row.get(0)) && !mapped.contains(&row.get(0)) && !row.get::<_, bool>(7) {
                    moved.push(candidate(row));
                }
            }
        }
        drop(client);

        let mut classes = HashMap::new();
        let fresh_bytes: u64 = fresh.iter().map(|c| c.part.size).sum();
        let (packs, inline) = if fresh_bytes >= self.config.pack_size {
            (outputs(fresh, self.config.pack_size, &mut classes), None)
        } else {
            (Vec::new(), outputs(fresh, u64::MAX, &mut classes).pop())
        };
        let packs: Vec<Output> = packs.into_iter().chain(outputs(moved, self.config.pack_size, &mut classes)).collect();
        // A base just complete needs a journal after it, even an empty one,
        // to be restorable.
        let base_waits = state.base_ready_seq.is_some_and(|ready| state.journal_seq <= ready);
        if changes.is_empty() && packs.is_empty() && inline.is_none() && mappings.is_empty() && !truncated && !base_waits {
            if backfill != state.backfill_after || !moved_seqs.is_empty() {
                self.commit_backfill(backfill, &moved_seqs).await?;
            }
            let more_moves = moved_seqs.len() as i64 == MOVES_PER_JOURNAL;
            return Ok(Cycle { again: backfill.is_some() || more_moves, ..Cycle::default() });
        }

        // Every object is recorded before it's written, as garbage until the
        // commit says otherwise, so that one a failed cycle leaves behind is
        // deleted.
        let seq = state.journal_seq + 1;
        let journal_id = Uuid::now_v7();
        let journal = format::journal_name(seq, journal_id);
        let pack_ids: Vec<Uuid> = packs.iter().map(|_| Uuid::now_v7()).collect();
        let mut written: Vec<String> = Vec::new();
        {
            let client = self.client().await?;
            let names: Vec<String> = pack_ids.iter().map(|id| format::pack_name(*id)).collect();
            client
                .execute(
                    "INSERT INTO backup_objects (id, name, kind, size, dead_since)
                     SELECT id, name, 'pack', 0, now() FROM unnest($1::uuid[], $2::text[]) AS t(id, name)",
                    &[&pack_ids, &names],
                )
                .await?;
            client
                .execute(
                    "INSERT INTO backup_objects (id, name, kind, seq, size, dead_since, superseded_at)
                     VALUES ($1, $2, 'journal', $3, 0, now(), now())",
                    &[&journal_id, &journal, &seq],
                )
                .await?;
        }
        let any_unavailable = !unavailable.is_empty();
        let result = self
            .write_cycle(
                state, seq, journal_id, &journal, &snapshot, version, changes, sequences, &packs, &pack_ids, inline,
                &classes, mappings, tier_objects.clone(), unavailable, !full, &mut written,
            )
            .await;
        let (meta_parts, sizes, journal_size) = match result {
            Ok(done) => done,
            Err(e) => {
                // The journal mustn't be mistaken for one that was committed.
                if written.contains(&journal) && self.target.delete(std::slice::from_ref(&journal)).await.is_ok() {
                    let _ = self
                        .client()
                        .await?
                        .execute("DELETE FROM backup_objects WHERE id = $1", &[&journal_id])
                        .await;
                }
                return Err(e);
            }
        };
        let parts = meta_parts.len();
        let bytes: u64 = sizes.iter().sum::<u64>() + journal_size;
        self.commit(
            state, seq, journal_id, journal_size, &consumed, &deleted, truncated, &meta_parts, &pack_ids, &sizes,
            &tier_objects, &moved_seqs, backfill, !full,
        )
        .await?;
        let more_moves = moved_seqs.len() as i64 == MOVES_PER_JOURNAL;
        Ok(Cycle {
            journal: Some(seq),
            changes: consumed.len(),
            parts,
            bytes,
            again: full || backfill.is_some() || any_unavailable || more_moves,
            needs_base: false,
        })
    }

    /// Writes a cycle's packs and journal. Returns where its parts are, the
    /// packs' sizes, and the journal's.
    #[allow(clippy::too_many_arguments)]
    async fn write_cycle(
        &self,
        state: &State,
        seq: i64,
        journal_id: Uuid,
        journal: &str,
        snapshot: &str,
        version: i32,
        changes: Vec<format::Change>,
        sequences: Vec<(String, i64, bool)>,
        packs: &[Output],
        pack_ids: &[Uuid],
        inline: Option<Output>,
        classes: &HashMap<i64, String>,
        mut mappings: Vec<PartRef>,
        tier_objects: Vec<ObjectRef>,
        unavailable: Vec<i64>,
        complete: bool,
        written: &mut Vec<String>,
    ) -> anyhow::Result<(Vec<PartRef>, Vec<u64>, u64)> {
        let all: Vec<Uuid> = packs
            .iter()
            .chain(inline.iter())
            .flat_map(|o| o.runs.iter().map(|r| r.blob_id))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let blobs = load_blobs(&self.client().await?, self.app.node, &all).await?;
        let mut objects = tier_objects;
        let mut sizes = Vec::new();
        for (output, id) in packs.iter().zip(pack_ids) {
            let name = format::pack_name(*id);
            let mut writer = ObjectWriter::new(&self.target, &self.config.key, &name);
            let result = async {
                copy_output(self.app, &blobs, output, &mut writer).await?;
                let data = writer.position();
                let meta = PackMeta {
                    format: format::FORMAT,
                    id: *id,
                    parts: output.parts.iter().map(|p| (p.id, p.new_offset, p.size)).collect(),
                };
                writer.write(&format::seal_meta(&meta)?).await?;
                anyhow::Ok(data)
            }
            .await;
            if let Err(e) = result {
                writer.abort().await;
                return Err(e);
            }
            let size = writer.finish().await?;
            written.push(name.clone());
            for p in &output.parts {
                mappings.push((p.id, *id, p.new_offset, p.size, classes[&p.id].clone()));
            }
            objects.push(ObjectRef { id: *id, name, size });
            sizes.push(size);
        }
        let mut writer = ObjectWriter::new(&self.target, &self.config.key, journal);
        let result = async {
            if let Some(output) = &inline {
                copy_output(self.app, &blobs, output, &mut writer).await?;
                for p in &output.parts {
                    mappings.push((p.id, journal_id, p.new_offset, p.size, classes[&p.id].clone()));
                }
                objects.push(ObjectRef { id: journal_id, name: journal.to_owned(), size: writer.position() });
            }
            let meta = JournalMeta {
                format: format::FORMAT,
                id: journal_id,
                seq,
                prev: state.journal_id,
                version,
                time: now_millis(),
                snapshot: snapshot.to_owned(),
                changes,
                sequences,
                objects,
                parts: mappings,
                complete,
                unavailable,
            };
            writer.write(&format::seal_meta(&meta)?).await?;
            anyhow::Ok(meta.parts)
        }
        .await;
        let mappings = match result {
            Ok(mappings) => mappings,
            Err(e) => {
                writer.abort().await;
                return Err(e);
            }
        };
        written.push(journal.to_owned());
        let size = writer.finish().await?;
        Ok((mappings, sizes, size))
    }

    /// Records a cycle: drops the changes it shipped, and moves the parts'
    /// records to where it put them. Fails, changing nothing, if this runner
    /// isn't the backup's anymore.
    #[allow(clippy::too_many_arguments)]
    async fn commit(
        &mut self,
        state: &State,
        seq: i64,
        journal_id: Uuid,
        journal_size: u64,
        consumed: &[i64],
        deleted: &HashSet<i64>,
        truncated: bool,
        mappings: &[PartRef],
        pack_ids: &[Uuid],
        pack_sizes: &[u64],
        tier_objects: &[ObjectRef],
        moved_seqs: &[i64],
        backfill: Option<i64>,
        complete: bool,
    ) -> anyhow::Result<()> {
        let mut client = self.client().await?;
        let tx = client.transaction().await?;
        self.check_generation(&tx).await?;
        tx.execute("DELETE FROM backup_changes WHERE seq = ANY($1)", &[&consumed]).await?;
        tx.execute("DELETE FROM backup_tier_moves WHERE seq = ANY($1)", &[&moved_seqs]).await?;
        // The tiers' objects that parts are in now: recorded, but never
        // written or deleted by the backup.
        let ids: Vec<Uuid> = tier_objects.iter().map(|o| o.id).collect();
        let names: Vec<String> = tier_objects.iter().map(|o| o.name.clone()).collect();
        let sizes: Vec<i64> = tier_objects.iter().map(|o| o.size as i64).collect();
        tx.execute(
            "INSERT INTO backup_objects (id, name, kind, size, dead_since)
             SELECT id, name, 'tier', size, now() FROM unnest($1::uuid[], $2::text[], $3::bigint[]) AS t(id, name, size)
             ON CONFLICT (id) DO NOTHING",
            &[&ids, &names, &sizes],
        )
        .await?;
        if truncated {
            tx.batch_execute(
                "DELETE FROM backup_parts;
                 UPDATE backup_objects SET refs = 0, live_bytes = 0 WHERE refs <> 0;",
            )
            .await?;
        }
        // The parts that are gone, and where those that moved were.
        let deleted: Vec<i64> = deleted.iter().copied().chain(mappings.iter().map(|m| m.0)).collect();
        tx.execute(
            "WITH gone AS (DELETE FROM backup_parts WHERE part_id = ANY($1) RETURNING object, size)
             UPDATE backup_objects o SET refs = o.refs - g.n, live_bytes = o.live_bytes - g.bytes
             FROM (SELECT object, count(*) AS n, sum(size)::bigint AS bytes FROM gone GROUP BY object) AS g
             WHERE o.id = g.object",
            &[&deleted],
        )
        .await?;
        let ids: Vec<i64> = mappings.iter().map(|m| m.0).collect();
        let objects: Vec<Uuid> = mappings.iter().map(|m| m.1).collect();
        let offsets: Vec<i64> = mappings.iter().map(|m| m.2 as i64).collect();
        let sizes: Vec<i64> = mappings.iter().map(|m| m.3 as i64).collect();
        let classes: Vec<String> = mappings.iter().map(|m| m.4.clone()).collect();
        tx.execute(
            "WITH added AS (
                 INSERT INTO backup_parts (part_id, object, \"offset\", size, class)
                 SELECT * FROM unnest($1::bigint[], $2::uuid[], $3::bigint[], $4::bigint[], $5::text[])
                 RETURNING object, size
             )
             UPDATE backup_objects o SET refs = o.refs + a.n, live_bytes = o.live_bytes + a.bytes
             FROM (SELECT object, count(*) AS n, sum(size)::bigint AS bytes FROM added GROUP BY object) AS a
             WHERE o.id = a.object",
            &[&ids, &objects, &offsets, &sizes, &classes],
        )
        .await?;
        let sizes: Vec<i64> = pack_sizes.iter().map(|&s| s as i64).collect();
        tx.execute(
            "UPDATE backup_objects o SET size = t.size FROM unnest($1::uuid[], $2::bigint[]) AS t(id, size)
             WHERE o.id = t.id",
            &[&pack_ids, &sizes],
        )
        .await?;
        tx.execute(
            "UPDATE backup_objects SET size = $2, superseded_at = NULL WHERE id = $1",
            &[&journal_id, &(journal_size as i64)],
        )
        .await?;
        tx.execute(
            "UPDATE backup_objects SET dead_since = CASE WHEN refs = 0 THEN coalesce(dead_since, now()) END
             WHERE (refs = 0) <> (dead_since IS NOT NULL)",
            &[],
        )
        .await?;
        // A complete journal after a base was complete makes it the one to
        // restore from: what came before it is superseded.
        if let (true, Some(ready), Some(after)) = (complete, state.base_ready_seq, state.base_seq)
            && seq > ready
        {
            tx.execute(
                "UPDATE backup_objects SET superseded_at = now()
                 WHERE superseded_at IS NULL
                   AND ((kind = 'base' AND base IS DISTINCT FROM $1) OR (kind = 'journal' AND seq <= $2))",
                &[&state.base_id, &after],
            )
            .await?;
        }
        tx.execute(
            "UPDATE backup_state SET journal_seq = $1, journal_id = $2, journal_at = now(),
                 journals_since_base = journals_since_base + 1, bytes_since_base = bytes_since_base + $3,
                 backfill_after = $4, last_error = NULL",
            &[&seq, &journal_id, &(journal_size as i64), &backfill],
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn commit_backfill(&mut self, backfill: Option<i64>, moved_seqs: &[i64]) -> anyhow::Result<()> {
        let mut client = self.client().await?;
        let tx = client.transaction().await?;
        self.check_generation(&tx).await?;
        tx.execute("UPDATE backup_state SET backfill_after = $1", &[&backfill]).await?;
        tx.execute("DELETE FROM backup_tier_moves WHERE seq = ANY($1)", &[&moved_seqs]).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Bumps the generation, if it's still the one this runner saw, and the
    /// lease still its own (in the caller's transaction).
    pub(super) async fn check_generation(&mut self, tx: &deadpool_postgres::Transaction<'_>) -> anyhow::Result<()> {
        let bumped = tx
            .execute(
                "UPDATE backup_state SET generation = generation + 1 WHERE generation = $1 AND holder = $2",
                &[&self.generation, &self.token],
            )
            .await?;
        anyhow::ensure!(bumped == 1, "another node took over the backup");
        self.generation += 1;
        Ok(())
    }

    /// Whether a base is due: there's none for the schema as it is, one was
    /// asked for, or the journals since the last one add up to enough that
    /// replaying them would take longer than loading a new one.
    pub fn base_due(state: &State, version: i32) -> bool {
        state.base_id.is_none()
            || state.base_version != Some(version)
            || state.requested.as_deref() == Some("base")
            || state.bytes_since_base >= state.base_size.unwrap_or(0).max(MIN_REBASE_BYTES)
            || state.journals_since_base >= MAX_JOURNALS_PER_BASE
    }

    /// Deletes the objects that nothing needs anymore, and no restore to a
    /// time within the retention could: packs whose parts are all gone, and
    /// journals and bases that a later base superseded, that long ago.
    pub async fn sweep(&self, state: &State) -> anyhow::Result<usize> {
        let client = self.client().await?;
        let retention = self.config.retention.as_secs_f64();
        let building = state.building.as_ref().map(|b| b.id);
        let rows = client
            .query(
                "SELECT id, name FROM backup_objects
                 WHERE (kind = 'pack' AND refs = 0 AND dead_since < now() - make_interval(secs => $1))
                    OR (kind = 'journal' AND refs = 0 AND superseded_at < now() - make_interval(secs => $1)
                        AND (dead_since IS NULL OR dead_since < now() - make_interval(secs => $1)))
                    OR (kind = 'base' AND superseded_at < now() - make_interval(secs => $1)
                        AND base IS DISTINCT FROM $2)
                 LIMIT 1000",
                &[&retention, &building],
            )
            .await?;
        // The tiers' objects that nothing points at anymore, that long:
        // forgotten, but left where they are (they're the tiers', see
        // `tiers`).
        client
            .execute(
                "DELETE FROM backup_objects WHERE kind = 'tier' AND refs = 0
                     AND dead_since < now() - make_interval(secs => $1)",
                &[&retention],
            )
            .await?;
        if rows.is_empty() {
            return Ok(0);
        }
        let ids: Vec<Uuid> = rows.iter().map(|r| r.get(0)).collect();
        let names: Vec<String> = rows.iter().map(|r| r.get(1)).collect();
        self.target.delete(&names).await?;
        client.execute("DELETE FROM backup_objects WHERE id = ANY($1) AND refs = 0", &[&ids]).await?;
        Ok(ids.len())
    }
}

pub fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_ranges_that_cover_others() {
        let b = |start, end, at| Backed { start, end, object: Uuid::nil(), at };
        let covers = Covers::new(vec![b(100, 200, 0), b(0, 50, 1000), b(150, 400, 2000), b(10, 20, 3000)]);
        assert_eq!(covers.find(0, 50).map(|b| b.at), Some(1000));
        assert_eq!(covers.find(12, 18).map(|b| b.at), Some(1000));
        assert_eq!(covers.find(160, 390).map(|b| b.at), Some(2000));
        assert_eq!(covers.find(120, 180).map(|b| b.at), Some(0));
        assert!(covers.find(40, 60).is_none());
        assert!(covers.find(390, 410).is_none());
        assert!(Covers::new(Vec::new()).find(0, 1).is_none());
    }
}
