//! Repairing a shard the scrubber found damaged or missing: replacing its
//! file, as a whole, with a new one assembled from intact blocks.
//!
//! The blocks that verified in the local file are taken from it; all others
//! (all of them, if the file is missing, or isn't the shard's) come from the
//! blob's other shards. A replicated blob's shards are copies of it, so the
//! blocks are read from them, through the same verified reads that serve
//! clients, which fail over block by block. A coded blob's shard is rebuilt
//! row by row, decoded from k other shards' cells of each row (see
//! `blobs::reconstruct`). So bit rot in one block of a large blob costs a
//! block (or a row) of network traffic, and a blob whose shards are damaged in
//! different places can still be repaired from them together.
//!
//! The new file is written next to the old one, as `<blob-id>.repair`,
//! checksummed on the way as a shard write is, then synced, and checked
//! against the catalog's CRC64/NVME of the shard's file: an intact file
//! matches it exactly, since the trailer is determined by the blob. A coded
//! shard's file holds the other shards' tables too, which are read from their
//! files. Only then does it replace the old file, by a rename. Readers that
//! have the old file open go on reading it, and verify every block as always.
//! A crash leaves the `.repair` file, which the GC deletes (see `gc`).
//!
//! No catalog change is needed: the location was right all along, only its file
//! was bad. If the blob is deleted meanwhile, the rename may recreate a file
//! whose location is gone, so the repair checks afterwards, and deletes it (and
//! the GC would, as any orphan).
//!
//! A block that can't be had intact from anywhere is lost. Then the file is
//! left as it is: rebuilding it would mean writing checksums for the lost
//! blocks, computed from damaged bytes, which would then pass verification.
//! What's lost is recorded in bytes of the blob: the shard's own blocks that
//! couldn't be rebuilt, if it holds the blob's bytes (all of them, for a
//! replicated blob; a coded blob's data shard holds some). A coded blob's
//! other shards record what's lost of theirs when they're scrubbed. A parity
//! shard that can't be rebuilt holds none of the blob's bytes to lose; its
//! file is left as it is all the same.

use std::sync::{Arc, Mutex};

use tokio::{
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    sync::mpsc,
};
use uuid::Uuid;

use super::{CHUNK, Pacer};
use crate::db::Cached;
use crate::{
    App,
    blob_file::{self, ShardFile},
    blobs::{BlobSlice, LOCATION_COLUMNS, Location, location_at, reconstruct, stream_blob_range},
    checksum::{BlobSummer, BlockCrcs},
};

/// How a repair ended.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    /// The copy was replaced with an intact one.
    Repaired,
    /// Some blocks can't be had intact from anywhere: the byte ranges of the
    /// blob that are lost with them (none, for a parity shard). The copy is
    /// left as it is. `provisional` if some shards weren't asked, their nodes
    /// being down: they may hold the blocks.
    Lost {
        ranges: Vec<(i64, i64)>,
        provisional: bool,
    },
    /// The new copy was assembled from blocks that all verified, but doesn't
    /// match the catalog's CRC of the whole file. The catalog is the likelier
    /// culprit (or the data was wrong when written, everywhere). The copy is
    /// left as it is.
    Mismatch(String),
}

/// The new copy being written: its file, and its checksums so far.
struct NewCopy {
    file: tokio::fs::File,
    summer: BlobSummer,
    digest: crc64fast_nvme::Digest,
}

impl NewCopy {
    async fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.summer.update(data);
        self.digest.write(data);
        self.file.write_all(data).await
    }
}

/// Repairs this node's copy of a blob's shard, `expected`, of which the
/// blocks `bad` failed their check (`None`: the whole file is at fault).
/// Reads its local blocks at the pacer's rate.
pub async fn repair(
    app: &Arc<App>,
    expected: &ShardFile,
    crc: u64,
    bad: Option<&[i64]>,
    pacer: &Arc<Mutex<Pacer>>,
) -> anyhow::Result<Outcome> {
    let outcome = repair_once(app, expected, crc, bad, pacer).await?;
    // With no block of its data known bad, the damage was taken to be in the
    // rest of the file. If keeping its data doesn't give the catalog's CRC,
    // the data is wrong after all, though consistent with its table: the
    // whole file is rebuilt from the other shards.
    match outcome {
        Outcome::Mismatch(_) if bad.is_some_and(<[i64]>::is_empty) => {
            repair_once(app, expected, crc, None, pacer).await
        }
        outcome => Ok(outcome),
    }
}

/// `repair`, once.
async fn repair_once(
    app: &Arc<App>,
    expected: &ShardFile,
    crc: u64,
    bad: Option<&[i64]>,
    pacer: &Arc<Mutex<Pacer>>,
) -> anyhow::Result<Outcome> {
    let blob_id = expected.blob_id;
    let file = app.store.create_repair(blob_id).await?;
    let mut copy = NewCopy {
        file,
        summer: BlobSummer::new(expected.layout.block_size as u32),
        digest: crc64fast_nvme::Digest::new(),
    };
    let result = async {
        let (others, provisional) = other_shards(app, blob_id).await?;
        let lost = assemble(app, expected, &others, bad, pacer, &mut copy).await?;
        if lost.incomplete {
            return Ok(Outcome::Lost {
                ranges: lost.ranges,
                provisional,
            });
        }
        let NewCopy {
            mut file,
            summer,
            mut digest,
        } = copy;
        let trailer = trailer(app, expected, &others, summer.finish(), &digest, crc).await?;
        digest.write(&trailer);
        file.write_all(&trailer).await?;
        file.sync_all().await?;
        let actual = digest.sum64();
        if actual != crc {
            return Ok(Outcome::Mismatch(format!(
                "a copy assembled from intact blocks has the CRC64/NVME {actual:016x}, \
                 not the catalog's {crc:016x}"
            )));
        }
        app.store.install_repair(blob_id).await?;
        // Installed: it's the blob's file now, unless the blob is gone.
        if !location_exists(app, blob_id).await? {
            crate::blobs::remove_unplaced(app, blob_id).await?;
        }
        Ok(Outcome::Repaired)
    }
    .await;
    // Whatever didn't replace the blob's file is of no use.
    if !matches!(result, Ok(Outcome::Repaired)) {
        app.store.remove_repair(blob_id).await?;
    }
    result
}

/// The trailer of the new file, which makes it match the catalog's CRC
/// (`crc`), given the CRC of its data so far (`digest`): its own table
/// (`ours`, computed from what was written), and for a coded blob every other
/// shard's, as the other shards' files hold them. Each of those files holds a
/// copy of all of them; the first whose copies give the catalog's CRC is
/// taken, so a damaged copy in one file doesn't keep this one from being
/// repaired. If none does, the first file's, which the caller finds wrong.
pub(crate) async fn trailer(
    app: &App,
    expected: &ShardFile,
    others: &[Location],
    ours: BlockCrcs,
    digest: &crc64fast_nvme::Digest,
    crc: u64,
) -> anyhow::Result<Vec<u8>> {
    let matches = |trailer: &[u8]| {
        let mut digest = digest.clone();
        digest.write(trailer);
        digest.sum64() == crc
    };
    if expected.layout.replicated() {
        return Ok(blob_file::trailer(expected, &[ours]));
    }
    let mut first: Option<Vec<u8>> = None;
    let mut last_error = anyhow::anyhow!("no other shard's file to read the checksums from");
    'files: for location in others {
        let mut tables = Vec::new();
        for of in 0..expected.layout.shards() {
            if of == expected.shard {
                tables.push(BlockCrcs(ours.0.clone()));
                continue;
            }
            let size = expected.layout.shard_size(of);
            match crate::blobs::fetch_table(app, location, expected, of, 0, size).await {
                Ok(crcs) => tables.push(BlockCrcs(crcs)),
                Err(e) => {
                    last_error = e.into();
                    continue 'files;
                }
            }
        }
        let trailer = blob_file::trailer(expected, &tables);
        if matches(&trailer) {
            return Ok(trailer);
        }
        first.get_or_insert(trailer);
    }
    match first {
        Some(trailer) => Ok(trailer),
        None => Err(last_error),
    }
}

/// What assembling found lost.
#[derive(Default)]
struct Lost {
    /// Whether some blocks couldn't be had.
    incomplete: bool,
    /// The blob's bytes that are lost with them.
    ranges: Vec<(i64, i64)>,
}

impl Lost {
    /// Adds [start, stop) of the blob, merged with the range before it if
    /// they touch: for a replicated blob, whose shard is the blob.
    fn add(&mut self, start: u64, stop: u64) {
        self.incomplete = true;
        let (start, stop) = (start as i64, stop as i64);
        match self.ranges.last_mut() {
            Some(last) if last.1 == start => last.1 = stop,
            _ => self.ranges.push((start, stop)),
        }
    }

    /// Adds [start, stop) of a coded blob, which lies in one cell, as a range
    /// of its own: the scrubber clears a coded blob's lost ranges cell by
    /// cell, as their shards turn up intact.
    fn add_in_cell(&mut self, start: u64, stop: u64) {
        self.incomplete = true;
        self.ranges.push((start as i64, stop as i64));
    }
}

/// Writes the shard's data to `copy`, block by block: those that verified
/// locally from the local file, all others from the other shards. Lost
/// blocks are written as zeros, so that the rest can still be looked for.
async fn assemble(
    app: &Arc<App>,
    expected: &ShardFile,
    others: &[Location],
    bad: Option<&[i64]>,
    pacer: &Arc<Mutex<Pacer>>,
    copy: &mut NewCopy,
) -> anyhow::Result<Lost> {
    let blob_id = expected.blob_id;
    let mut lost = Lost::default();
    let mut local = match bad {
        Some(_) => app.store.open_blob(blob_id).await?,
        None => None,
    };
    let layout = expected.blocks_of(expected.shard);
    let block_size = layout.block_size;
    let blocks = layout.blob_size.div_ceil(block_size);
    let is_local = |block: u64, local: &Option<tokio::fs::File>| {
        local.is_some() && bad.is_some_and(|bad| bad.binary_search(&(block as i64)).is_err())
    };
    let mut block = 0;
    while block < blocks {
        let from_local = is_local(block, &local);
        let mut end = block + 1;
        while end < blocks && is_local(end, &local) == from_local {
            end += 1;
        }
        let start = block * block_size;
        let stop = (end * block_size).min(layout.blob_size);
        match &mut local {
            Some(file) if from_local => copy_local(file, start, stop, pacer, copy).await?,
            _ if expected.layout.replicated() => {
                fetch(app, expected, others, start, stop, copy, &mut lost).await?
            }
            _ => rebuild(app, expected, others, start, stop, copy, &mut lost).await?,
        }
        block = end;
    }
    Ok(lost)
}

/// Copies [start, stop) of the local file to `copy`.
async fn copy_local(
    file: &mut tokio::fs::File,
    start: u64,
    stop: u64,
    pacer: &Arc<Mutex<Pacer>>,
    copy: &mut NewCopy,
) -> anyhow::Result<()> {
    file.seek(std::io::SeekFrom::Start(start)).await?;
    let mut buf = vec![0u8; CHUNK as usize];
    let mut pos = start;
    while pos < stop {
        let len = CHUNK.min(stop - pos) as usize;
        let delay = pacer.lock().unwrap().delay(len as u64);
        tokio::time::sleep(delay).await;
        file.read_exact(&mut buf[..len]).await?;
        copy.write(&buf[..len]).await?;
        pos += len as u64;
    }
    Ok(())
}

/// Copies [start, stop) of a replicated blob, verified, from its other
/// shards to `copy`, noting the blocks none of them could serve as lost.
#[allow(clippy::too_many_arguments)]
async fn fetch(
    app: &App,
    expected: &ShardFile,
    others: &[Location],
    start: u64,
    stop: u64,
    copy: &mut NewCopy,
    lost: &mut Lost,
) -> anyhow::Result<()> {
    let blocks = expected.blocks_of(expected.shard);
    let mut pos = start;
    while pos < stop {
        let mut slice = BlobSlice {
            blob_id: expected.blob_id,
            layout: Some(expected.layout),
            locations: others.to_vec(),
            offset: pos,
            length: stop - pos,
            part: None,
        };
        let read = if others.is_empty() {
            Err(std::io::Error::other("no other shard"))
        } else {
            let (tx, mut rx) = mpsc::channel(4);
            let reading = async {
                let result = stream_blob_range(app, &mut slice, &tx).await;
                drop(tx);
                result
            };
            let writing = async {
                while let Some(Ok(frame)) = rx.recv().await {
                    if let Ok(data) = frame.into_data() {
                        copy.write(&data).await?;
                    }
                }
                std::io::Result::Ok(())
            };
            let (read, written) = tokio::join!(reading, writing);
            written?;
            read
        };
        if read.is_ok() {
            return Ok(());
        }
        // Everything before `slice.offset` was copied, whole blocks from the
        // aligned start; no shard has the block there intact.
        let at = slice.offset;
        let len = blocks.block_len(at);
        lost.add(at, at + len);
        copy.write(&vec![0u8; len as usize]).await?;
        pos = at + len;
    }
    Ok(())
}

/// Rebuilds [start, stop) of a coded blob's shard, row by row, decoding each
/// row's cell from the other shards (see `blobs::reconstruct`), to `copy`. A
/// row that can't be decoded is written as zeros, and if this is a data
/// shard, its bytes in that row are lost.
#[allow(clippy::too_many_arguments)]
async fn rebuild(
    app: &App,
    expected: &ShardFile,
    others: &[Location],
    start: u64,
    stop: u64,
    copy: &mut NewCopy,
    lost: &mut Lost,
) -> anyhow::Result<()> {
    let layout = expected.layout;
    let su = layout.stripe_unit;
    let shard = expected.shard;
    let mut pos = start;
    while pos < stop {
        let row = pos / su;
        let row_start = row * su;
        let row_stop = (row_start + layout.row_len_on(row, shard)).min(stop);
        let (from, to) = ((pos - row_start) as usize, (row_stop - row_start) as usize);
        match reconstruct(app, expected.blob_id, layout, others, row, shard).await {
            Ok(cell) => copy.write(&cell[from..to]).await?,
            Err(e) => {
                eprintln!("blob {} (repair): shard {shard}'s row {row} can't be rebuilt: {e}", expected.blob_id);
                if shard < layout.data_shards {
                    let cell = layout.cell(row, shard);
                    lost.add_in_cell(cell.start + from as u64, cell.start + to as u64);
                } else {
                    lost.incomplete = true;
                }
                copy.write(&vec![0u8; to - from]).await?;
            }
        }
        pos = row_stop;
    }
    Ok(())
}

/// The blob's other shards on live nodes, the freshest first, and whether
/// some are on nodes that are down, which can't be asked.
async fn other_shards(app: &App, blob_id: Uuid) -> anyhow::Result<(Vec<Location>, bool)> {
    let rows = app
        .pool
        .get()
        .await?
        .query_cached(
            &format!(
                "SELECT {LOCATION_COLUMNS}, n.last_seen > NOW() - INTERVAL '10 seconds'
                 FROM blob_locations bl JOIN nodes n ON n.id = bl.node
                 WHERE bl.blob_id = $1 AND bl.node <> $2
                 ORDER BY n.last_seen DESC"
            ),
            &[&blob_id, &app.node],
        )
        .await?;
    let live = rows
        .iter()
        .filter(|r| r.get::<_, bool>(3))
        .map(|r| location_at(r, 0))
        .collect();
    let down = rows.iter().any(|r| !r.get::<_, bool>(3));
    Ok((live, down))
}

async fn location_exists(app: &App, blob_id: Uuid) -> anyhow::Result<bool> {
    let rows = app
        .pool
        .get()
        .await?
        .query_cached(
            "SELECT 1 FROM blob_locations WHERE blob_id = $1 AND node = $2",
            &[&blob_id, &app.node],
        )
        .await?;
    Ok(!rows.is_empty())
}
