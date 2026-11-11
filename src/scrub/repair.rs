//! Repairing a copy the scrubber found damaged or missing: replacing it, as a
//! whole, with a new copy assembled from intact blocks.
//!
//! The blocks that verified in the local copy are taken from it; all others
//! (all of them, if the file is missing, or isn't the blob's) are fetched
//! from the blob's other replicas, through the same verified reads that serve
//! clients, which fail over block by block. So bit rot in one block of a
//! large blob costs a block of network traffic, and a blob whose replicas are
//! damaged in different places can still be repaired from them together.
//!
//! The new copy is written next to the old one, as `<blob-id>.repair`,
//! checksummed on the way as a replica write is, then synced, and checked
//! against the catalog's CRC64/NVME of the whole file: an intact copy matches
//! it exactly, since the trailer is determined by the data. Only then does it
//! replace the old file, by a rename. Readers that have the old file open go on
//! reading it, and verify every block as always. A crash leaves the `.repair`
//! file, which the GC deletes (see `gc`).
//!
//! No catalog change is needed: the location was right all along, only its file
//! was bad. If the blob is deleted meanwhile, the rename may recreate a file
//! whose location is gone, so the repair checks afterwards, and deletes it (and
//! the GC would, as any orphan).
//!
//! A block that no replica holds intact is lost. Then the copy is left as it
//! is: rebuilding it would mean writing checksums for the lost blocks, computed
//! from damaged bytes, which would then pass verification.

use std::sync::{Arc, Mutex};

use tokio::{
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    sync::mpsc,
};
use uuid::Uuid;

use super::{CHUNK, Pacer};
use crate::db::Cached;
use crate::{
    App, blob_file,
    blobs::{BlobSlice, Location, stream_blob_range},
    checksum::{BlobSummer, BlockLayout},
};

/// How a repair ended.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    /// The copy was replaced with an intact one.
    Repaired,
    /// Some blocks are intact nowhere: their byte ranges, merged. The copy is
    /// left as it is. `provisional` if some replicas weren't asked, their nodes
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

/// Repairs this node's copy of a blob, of which the blocks `bad` failed their
/// check (`None`: the whole file is at fault). Reads its local blocks at the
/// pacer's rate.
pub async fn repair(
    app: &Arc<App>,
    blob_id: Uuid,
    layout: BlockLayout,
    crc: u64,
    bad: Option<&[i64]>,
    pacer: &Arc<Mutex<Pacer>>,
) -> anyhow::Result<Outcome> {
    let file = app.store.create_repair(blob_id).await?;
    let mut copy = NewCopy {
        file,
        summer: BlobSummer::new(layout.block_size as u32),
        digest: crc64fast_nvme::Digest::new(),
    };
    let result = async {
        let lost = assemble(app, blob_id, layout, bad, pacer, &mut copy).await?;
        if !lost.ranges.is_empty() {
            return Ok(Outcome::Lost {
                ranges: lost.ranges,
                provisional: lost.provisional,
            });
        }
        let NewCopy {
            mut file,
            summer,
            mut digest,
        } = copy;
        let trailer = blob_file::trailer(blob_id, &summer.finish());
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
            app.store.remove_blob(blob_id).await?;
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

/// What assembling found lost.
#[derive(Default)]
struct Lost {
    ranges: Vec<(i64, i64)>,
    provisional: bool,
}

impl Lost {
    fn add(&mut self, start: u64, stop: u64) {
        let (start, stop) = (start as i64, stop as i64);
        match self.ranges.last_mut() {
            Some(last) if last.1 == start => last.1 = stop,
            _ => self.ranges.push((start, stop)),
        }
    }
}

/// Writes the blob's data to `copy`, block by block: those that verified
/// locally from the local file, all others from the other replicas. Lost
/// blocks are written as zeros, so that the rest can still be looked for.
async fn assemble(
    app: &Arc<App>,
    blob_id: Uuid,
    layout: BlockLayout,
    bad: Option<&[i64]>,
    pacer: &Arc<Mutex<Pacer>>,
    copy: &mut NewCopy,
) -> anyhow::Result<Lost> {
    let (others, provisional) = other_replicas(app, blob_id).await?;
    let mut lost = Lost::default();
    let mut local = match bad {
        Some(_) => app.store.open_blob(blob_id).await?,
        None => None,
    };
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
            _ => fetch(app, blob_id, layout, &others, start, stop, copy, &mut lost).await?,
        }
        block = end;
    }
    lost.provisional = provisional;
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

/// Copies [start, stop) of the blob, verified, from the other replicas to
/// `copy`, noting the blocks none of them could serve as lost.
#[allow(clippy::too_many_arguments)]
async fn fetch(
    app: &App,
    blob_id: Uuid,
    layout: BlockLayout,
    others: &[Location],
    start: u64,
    stop: u64,
    copy: &mut NewCopy,
    lost: &mut Lost,
) -> anyhow::Result<()> {
    let mut pos = start;
    while pos < stop {
        let mut slice = BlobSlice {
            blob_id,
            layout: Some(layout),
            locations: others.to_vec(),
            offset: pos,
            length: stop - pos,
            part: None,
        };
        let read = if others.is_empty() {
            Err(std::io::Error::other("no other replica"))
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
        // aligned start; no replica has the block there intact.
        let at = slice.offset;
        let len = layout.block_len(at);
        lost.add(at, at + len);
        copy.write(&vec![0u8; len as usize]).await?;
        pos = at + len;
    }
    Ok(())
}

/// The blob's replicas on other live nodes, the freshest first, and whether
/// some are on nodes that are down, which can't be asked.
async fn other_replicas(app: &App, blob_id: Uuid) -> anyhow::Result<(Vec<Location>, bool)> {
    let rows = app
        .pool
        .get()
        .await?
        .query_cached(
            "SELECT bl.node, n.peer_url, n.last_seen > NOW() - INTERVAL '10 seconds'
             FROM blob_locations bl JOIN nodes n ON n.id = bl.node
             WHERE bl.blob_id = $1 AND bl.node <> $2
             ORDER BY n.last_seen DESC",
            &[&blob_id, &app.node],
        )
        .await?;
    let live = rows
        .iter()
        .filter(|r| r.get::<_, bool>(2))
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    let down = rows.iter().any(|r| !r.get::<_, bool>(2));
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
