//! Blobs: the files on disk. Every blob is stored as shards, each on a node
//! of its own (`blob_locations`), and parts reference a byte range of a
//! blob. A replicated blob's shards are copies of it; a coded blob's are cut
//! from it and encoded (see `shards`). A blob is garbage once no part
//! references it anymore; deleting its row cascades its locations, after
//! which its files are reaped.

use std::collections::BTreeMap;
use std::io::{self, SeekFrom};
use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::{
    Method, Request, StatusCode,
    body::{Bytes, Frame, Incoming},
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt},
};
use uuid::Uuid;

use crate::db::Cached;
use crate::{
    App,
    blob_file::{self, ShardFile},
    body::FrameSender,
    checksum::BlockSums,
    peer::PeerClient,
    shards::{self, Layout},
};

/// A node holding a shard of a blob: the node's number (`nodes.id`), its
/// peer URL, and which shard it holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Location {
    pub node: i32,
    pub peer_url: String,
    pub shard: u32,
}

/// The columns a blob's layout is read from, of `blobs b`, in the order
/// `layout_at` takes them.
pub(crate) const LAYOUT_COLUMNS: &str = "b.size, b.block_size, b.data_shards, b.parity_shards, b.stripe_unit";

/// A blob's layout, from `LAYOUT_COLUMNS` starting at column `first` of
/// `row`. `None` for a blob from before checksums, whose shards are bare
/// copies of it.
pub(crate) fn layout_at(row: &tokio_postgres::Row, first: usize) -> Option<Layout> {
    let block_size: i32 = row.get::<_, Option<i32>>(first + 1)?;
    Some(Layout {
        size: row.get::<_, i64>(first) as u64,
        block_size: block_size as u64,
        data_shards: row.get::<_, i16>(first + 2) as u32,
        parity_shards: row.get::<_, i16>(first + 3) as u32,
        stripe_unit: row.get::<_, i32>(first + 4) as u64,
    })
}

/// The columns a location is read from (`blob_locations bl`, `nodes n`), in
/// the order `location_at` takes them.
pub(crate) const LOCATION_COLUMNS: &str = "bl.node, n.peer_url, bl.shard";

/// A location, from `LOCATION_COLUMNS` starting at column `first` of `row`.
pub(crate) fn location_at(row: &tokio_postgres::Row, first: usize) -> Location {
    Location {
        node: row.get(first),
        peer_url: row.get(first + 1),
        shard: row.get::<_, i16>(first + 2) as u32,
    }
}

/// A blob file to reap, and where it lives: (blob_id, holder node, holder
/// peer_url). One per replica.
pub(crate) type ReapTarget = (Uuid, i32, String);

/// Maps location rows (blob_id, node, peer_url) into reap targets.
pub(crate) fn reap_targets(rows: &[tokio_postgres::Row]) -> Vec<ReapTarget> {
    rows.iter()
        .map(|r| (r.get::<_, Uuid>(0), r.get::<_, i32>(1), r.get::<_, String>(2)))
        .collect()
}

/// The reap targets a catalog function returns, as three parallel arrays
/// (blobs, nodes, peer URLs) starting at column `first` of `row`.
pub(crate) fn reap_columns(row: &tokio_postgres::Row, first: usize) -> Vec<ReapTarget> {
    let blobs: Vec<Uuid> = row.get(first);
    let nodes: Vec<i32> = row.get(first + 1);
    let peers: Vec<String> = row.get(first + 2);
    blobs
        .into_iter()
        .zip(nodes)
        .zip(peers)
        .map(|((blob, node), peer)| (blob, node, peer))
        .collect()
}

/// Deletes a blob whose write was given up, if it's still pending, and reaps
/// its files. A committed blob is never touched (the condition is re-checked
/// once a concurrent commit lets go of the row), so this is safe whatever the
/// outcome of an attempt to commit it was, even an unknown one. The GC is the
/// backstop for blobs that a crash keeps from getting here.
///
/// A replica that records its location after this has deleted the row fails
/// its FK check, and deletes its file itself (`write_blob_streaming`).
pub(crate) async fn abandon(app: &Arc<App>, blob_id: Uuid) -> anyhow::Result<()> {
    let client = app.pool.get().await?;
    // The outer SELECT still sees the locations that the DELETE cascades away.
    let rows = client
        .query_cached(
            "WITH gone AS (
                 DELETE FROM blobs WHERE blob_id = $1 AND state = 'pending' RETURNING blob_id
             )
             SELECT bl.blob_id, bl.node, n.peer_url
             FROM gone
             JOIN blob_locations bl ON bl.blob_id = gone.blob_id
             JOIN nodes n ON n.id = bl.node",
            &[&blob_id],
        )
        .await?;
    reap_blobs(app, reap_targets(&rows));
    Ok(())
}

/// Like `abandon`, for a caller with nothing better to do on failure than to
/// leave the blob to the GC: logs the error instead of returning it.
pub(crate) async fn discard(app: &Arc<App>, blob_id: Uuid) {
    if let Err(e) = abandon(app, blob_id).await {
        eprintln!("deleting the given-up blob {blob_id} failed, leaving it to the GC: {e:#}");
    }
}

/// Discards a pending blob in the background when dropped, unless `disarm`ed:
/// for the stretch between a blob being written and its commit, so that a
/// dropped request (a client hanging up) doesn't leave the blob to the GC.
/// Safe even if a commit is underway: a committed blob isn't touched, and a
/// commit that comes after finds the blob gone, and commits nothing.
pub(crate) struct DiscardOnDrop {
    app: Arc<App>,
    blob_id: Option<Uuid>,
}

impl DiscardOnDrop {
    pub(crate) fn new(app: &Arc<App>, blob_id: Uuid) -> DiscardOnDrop {
        DiscardOnDrop {
            app: app.clone(),
            blob_id: Some(blob_id),
        }
    }

    /// The blob has been committed, or discarded: there's nothing left to do.
    pub(crate) fn disarm(&mut self) {
        self.blob_id = None;
    }
}

impl Drop for DiscardOnDrop {
    fn drop(&mut self) {
        if let Some(blob_id) = self.blob_id.take() {
            let app = self.app.clone();
            tokio::spawn(async move { discard(&app, blob_id).await });
        }
    }
}

/// Best-effort: once a set of blobs has been removed from the catalog, ask each
/// holder to delete the file from disk *now*: locally if that's us, else via the
/// peer's `DELETE /blobs/{id}`. The rows are already gone, so any deletion that
/// fails (peer down, network) is harmless: the GC reclaims the leftovers.
/// Runs in the background so it never delays the response.
pub(crate) fn reap_blobs(app: &Arc<App>, targets: Vec<ReapTarget>) {
    if targets.is_empty() {
        return;
    }
    let app = app.clone();
    tokio::spawn(async move {
        for (blob_id, node, peer_url) in targets {
            let result = if node == app.node {
                app.store.remove_blob(blob_id).await
            } else {
                delete_from_replica(&app.peers, &peer_url, blob_id).await
            };
            if let Err(e) = result {
                eprintln!("best-effort reap of blob {blob_id} on {peer_url} failed: {e}");
            }
        }
    });
}

async fn delete_from_replica(
    peers: &PeerClient,
    peer_url: &str,
    blob_id: Uuid,
) -> anyhow::Result<()> {
    let req = Request::builder()
        .method(Method::DELETE)
        .uri(format!("{peer_url}/blobs/{blob_id}"))
        .body(PeerClient::empty())?;
    let res = peers.request(req).await?;
    if res.status() != StatusCode::OK {
        anyhow::bail!("replica {peer_url} returned status {}", res.status());
    }
    Ok(())
}


/// A byte range of a blob to read, the blob's layout (`None` for a blob
/// written before checksums), and the nodes holding its shards, freshest
/// first.
pub(crate) struct BlobSlice {
    pub blob_id: Uuid,
    pub layout: Option<Layout>,
    pub locations: Vec<Location>,
    pub offset: u64,
    pub length: u64,
    /// The part whose bytes these are (`parts.id`) and its offset in this blob,
    /// to find them again if the packer moves the part to another blob while
    /// they're being read.
    pub part: Option<(i64, u64)>,
}

/// The shard file that `location` holds, as the catalog describes it; `None`
/// for a blob from before checksums.
fn shard_file(blob_id: Uuid, layout: Option<Layout>, location: &Location) -> Option<ShardFile> {
    layout.map(|layout| ShardFile {
        blob_id,
        layout,
        shard: location.shard,
    })
}

/// Logs a shard that failed a read, and flags it for its node's scrubber if
/// it's damaged or missing.
fn report(app: &App, blob_id: Uuid, location: &Location, e: &io::Error) {
    let Location { node, peer_url, .. } = location;
    match e.kind() {
        // The catalog places the shard on that node, so it ought to have it,
        // unless the blob was deleted meanwhile; then flagging it does
        // nothing. Either way, its node checks its copy next.
        io::ErrorKind::NotFound => crate::scrub::suspect(app, blob_id, *node),
        io::ErrorKind::InvalidData => {
            eprintln!("CORRUPTION: blob {blob_id} on node {node} ({peer_url}): {e}");
            crate::scrub::suspect(app, blob_id, *node);
        }
        _ => eprintln!("reading blob {blob_id} from {peer_url} failed: {e}"),
    }
}

/// Streams `slice` to `tx`, verifying it against the blob's block checksums.
///
/// Each node serves the checksums of the blocks it's asked for along with the
/// data, from the table in its shard file. Only verified bytes are forwarded,
/// block by block, so the client never sees bad bytes. A replicated blob's
/// shards all hold its bytes: when one fails mid-stream, returns a short read,
/// or serves a block that doesn't match its checksum, the read moves on to
/// the next from the first unsent block. A coded blob's cells are read from
/// their data shards, and those a data shard can't serve are decoded from
/// the other shards. A damaged shard is logged loudly, and flagged for its
/// node's scrubber to check. Blobs written before checksums existed are
/// streamed unverified, but still with failover.
///
/// On failure, `slice` is narrowed to the bytes that weren't forwarded.
pub(crate) async fn stream_blob_range(
    app: &App,
    slice: &mut BlobSlice,
    tx: &FrameSender,
) -> io::Result<()> {
    match slice.layout {
        Some(layout) if !layout.replicated() => stream_coded(app, slice, layout, tx).await,
        _ => stream_replicated(app, slice, tx).await,
    }
}

/// `stream_blob_range` for a replicated blob, every shard of which holds it.
async fn stream_replicated(
    app: &App,
    slice: &mut BlobSlice,
    tx: &FrameSender,
) -> io::Result<()> {
    let blob_id = slice.blob_id;
    let end = slice.offset + slice.length;
    // Everything before `pos` has been forwarded.
    let mut pos = slice.offset;
    // Cycle through the shards for as long as one makes progress: when two are
    // damaged in different places, each can still serve what the other can't.
    // Give up once every shard has failed at the current position.
    let mut failed_here = 0;
    for location in slice.locations.iter().cycle() {
        if failed_here == slice.locations.len() {
            break;
        }
        let file = shard_file(blob_id, slice.layout, location);
        let blocks = file.map(|f| f.blocks_of(f.shard));
        let (start, stop) = match &blocks {
            Some(blocks) => blocks.aligned(pos, end),
            None => (pos, end),
        };
        let before = pos;
        let result = async {
            let source = Source::open(app, blob_id, location, file.as_ref(), start, stop - start).await?;
            let Some((mut source, crcs)) = source else {
                return Err(io::Error::new(io::ErrorKind::NotFound, "the node doesn't have it"));
            };
            match blocks {
                Some(layout) => {
                    let sums = BlockSums {
                        layout,
                        first_block: start / layout.block_size,
                        crcs,
                    };
                    pump_verified(&mut source, &sums, start, &mut pos, end, tx).await
                }
                None => pump_unverified(&mut source, &mut pos, end, tx).await,
            }
        }
        .await;
        match result {
            Ok(()) => return Ok(()),
            Err(e) => report(app, blob_id, location, &e),
        }
        failed_here = if pos > before { 1 } else { failed_here + 1 };
    }
    slice.offset = pos;
    slice.length = end - pos;
    Err(io::Error::other(format!(
        "no shard could serve blob {blob_id} from offset {pos}"
    )))
}

/// Forwards the bytes of [`*pos`, `end`) from `source`, which reads the blob from
/// the block-aligned `cursor` on, verifying each block before forwarding it.
async fn pump_verified(
    source: &mut Source,
    sums: &BlockSums,
    mut cursor: u64,
    pos: &mut u64,
    end: u64,
    tx: &FrameSender,
) -> io::Result<()> {
    let mut block = Vec::with_capacity(sums.layout.block_size as usize);
    while *pos < end {
        let Some(chunk) = source.next().await? else {
            return Err(io::Error::other("the node returned a short read"));
        };
        block.extend_from_slice(&chunk);
        loop {
            let len = sums.layout.block_len(cursor) as usize;
            if block.len() < len {
                break;
            }
            if !sums.verify(cursor, &block[..len]) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("block at offset {cursor} failed its checksum"),
                ));
            }
            // The block starts at or before `pos` (the first one may begin
            // before the requested range), so forward its tail up to `end`.
            let from = (*pos - cursor) as usize;
            let to = (end.min(cursor + len as u64) - cursor) as usize;
            let data = Bytes::copy_from_slice(&block[from..to]);
            block.drain(..len);
            cursor += len as u64;
            *pos = cursor.min(end);
            if tx.send(Ok(Frame::data(data))).await.is_err() {
                return Ok(()); // receiver gone (client hung up)
            }
            if *pos == end {
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Forwards the bytes of [`*pos`, `end`) from `source`, which reads the blob from
/// `*pos` on, without verification.
async fn pump_unverified(
    source: &mut Source,
    pos: &mut u64,
    end: u64,
    tx: &FrameSender,
) -> io::Result<()> {
    while *pos < end {
        let Some(mut chunk) = source.next().await? else {
            return Err(io::Error::other("the node returned a short read"));
        };
        chunk.truncate((end - *pos).min(chunk.len() as u64) as usize);
        *pos += chunk.len() as u64;
        if tx.send(Ok(Frame::data(chunk))).await.is_err() {
            return Ok(()); // receiver gone (client hung up)
        }
    }
    Ok(())
}

/// How a coded read gets at a data shard's cells.
enum Direct {
    /// Not opened yet, or opened again at its next cell, after it failed.
    Unopened,
    Open(Box<ShardStream>),
    /// It can't be opened: its cells are decoded from the other shards.
    Failed,
}

/// `stream_blob_range` for a coded blob (k > 1). Each data shard that the
/// range touches is read in one stream, over all of its cells in the range,
/// and the streams take turns, cell by cell. What of a cell its data shard
/// can't serve is decoded from the other shards. A stream that fails (a
/// damaged block, say) is opened again at the shard's next cell; a shard that
/// can't be opened (its node is down, say) is decoded for the rest of the
/// read.
async fn stream_coded(
    app: &App,
    slice: &mut BlobSlice,
    layout: Layout,
    tx: &FrameSender,
) -> io::Result<()> {
    let end = slice.offset + slice.length;
    let mut pos = slice.offset;
    let mut streams: Vec<Direct> = (0..layout.data_shards).map(|_| Direct::Unopened).collect();
    let result = async {
        while pos < end {
            let cell = layout.cell_at(pos);
            let stop = end.min(cell.start + cell.len);
            let j = cell.shard as usize;
            if let Direct::Unopened = streams[j] {
                streams[j] = open_direct(app, slice, layout, cell.shard, pos, end).await;
            }
            if let Direct::Open(stream) = &mut streams[j] {
                let (from, to) = (layout.shard_offset(pos), layout.shard_offset(stop - 1) + 1);
                match stream.forward(from, to, &mut pos, tx).await {
                    Ok(true) => continue,
                    Ok(false) => return Ok(()), // receiver gone (client hung up)
                    Err(e) => {
                        report(app, slice.blob_id, &stream.location, &e);
                        streams[j] = Direct::Unopened;
                    }
                }
            }
            // `pos` may have moved within the cell before the stream failed.
            let bytes = reconstruct(app, slice.blob_id, layout, &slice.locations, cell.row, cell.shard).await?;
            let data = Bytes::copy_from_slice(&bytes[(pos - cell.start) as usize..(stop - cell.start) as usize]);
            if tx.send(Ok(Frame::data(data))).await.is_err() {
                return Ok(());
            }
            pos = stop;
        }
        Ok(())
    }
    .await;
    if result.is_err() {
        slice.offset = pos;
        slice.length = end - pos;
    }
    result
}

/// Opens a stream of data shard `shard`'s cells within the blob's bytes
/// [`pos`, `end`), `pos` being in one of them, from a node holding it, or
/// gives up on it.
async fn open_direct(
    app: &App,
    slice: &BlobSlice,
    layout: Layout,
    shard: u32,
    pos: u64,
    end: u64,
) -> Direct {
    let blocks = layout.shard_blocks(shard);
    let (start, stop) = blocks.aligned(layout.shard_offset(pos), shard_end(layout, shard, end));
    for location in slice.locations.iter().filter(|l| l.shard == shard) {
        let file = ShardFile {
            blob_id: slice.blob_id,
            layout,
            shard,
        };
        let opened = Source::open(app, slice.blob_id, location, Some(&file), start, stop - start).await;
        match opened {
            Ok(Some((source, crcs))) => {
                return Direct::Open(Box::new(ShardStream {
                    location: location.clone(),
                    source,
                    sums: BlockSums {
                        layout: blocks,
                        first_block: start / blocks.block_size,
                        crcs,
                    },
                    cursor: start,
                    block: Vec::new(),
                }));
            }
            Ok(None) => report(app, slice.blob_id, location, &io::Error::new(io::ErrorKind::NotFound, "the node doesn't have it")),
            Err(e) => report(app, slice.blob_id, location, &e),
        }
    }
    Direct::Failed
}

/// Where data shard `shard`'s bytes among the blob's bytes before `end` end,
/// in the shard.
fn shard_end(layout: Layout, shard: u32, end: u64) -> u64 {
    if end == 0 {
        return 0;
    }
    let last = layout.cell_at(end - 1);
    let su = layout.stripe_unit;
    if shard < last.shard {
        last.row * su + layout.cell(last.row, shard).len
    } else if shard == last.shard {
        layout.shard_offset(end - 1) + 1
    } else if last.row == 0 {
        0
    } else {
        (last.row - 1) * su + layout.cell(last.row - 1, shard).len
    }
}

/// A shard's blocks, streamed from one node and verified.
struct ShardStream {
    location: Location,
    source: Source,
    sums: BlockSums,
    /// Where the next block to come starts, in the shard.
    cursor: u64,
    /// What has come of it so far (and maybe of the ones after it).
    block: Vec<u8>,
}

impl ShardStream {
    /// Forwards the shard's bytes [`from`, `to`), moving `*pos` (the blob
    /// offset of the next byte to forward) along with them. They mustn't
    /// start before the block that comes next. False if the receiver is gone.
    async fn forward(&mut self, mut from: u64, to: u64, pos: &mut u64, tx: &FrameSender) -> io::Result<bool> {
        if from < self.cursor {
            return Err(io::Error::other("a coded read went back in a shard"));
        }
        while from < to {
            let len = self.sums.layout.block_len(self.cursor);
            while (self.block.len() as u64) < len {
                let Some(chunk) = self.source.next().await? else {
                    return Err(io::Error::other("the node returned a short read"));
                };
                self.block.extend_from_slice(&chunk);
            }
            let block = &self.block[..len as usize];
            if !self.sums.verify(self.cursor, block) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("shard block at offset {} failed its checksum", self.cursor),
                ));
            }
            let a = from.saturating_sub(self.cursor).min(len) as usize;
            let b = (to.min(self.cursor + len) - self.cursor) as usize;
            if a < b {
                let data = Bytes::copy_from_slice(&block[a..b]);
                if tx.send(Ok(Frame::data(data))).await.is_err() {
                    return Ok(false);
                }
                *pos += (b - a) as u64;
                from = self.cursor + b as u64;
            }
            // A block is left for the next call only if the range ends inside
            // it, which only the end of the read does.
            if from >= self.cursor + len {
                self.block.drain(..len as usize);
                self.cursor += len;
            }
        }
        Ok(true)
    }
}

/// Decodes row `row`'s cell on shard `want` (data or parity) of a coded blob,
/// from k other shards' cells of the row, from the nodes in `locations` (the
/// one holding `want` itself is skipped), each verified against its own
/// table. The result is verified against `want`'s table, which every shard's
/// file holds.
pub(crate) async fn reconstruct(
    app: &App,
    blob_id: Uuid,
    layout: Layout,
    locations: &[Location],
    row: u64,
    want: u32,
) -> io::Result<Vec<u8>> {
    let su = layout.stripe_unit;
    let k = layout.data_shards;
    let len = layout.row_len_on(row, want);
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut cells: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    // Where a cell came from: the nodes to fetch `want`'s table from.
    let mut sources: Vec<&Location> = Vec::new();
    // The data shards first: they need no decoding to be used.
    for shard in (0..layout.shards()).filter(|&s| s != want) {
        if cells.len() == k as usize {
            break;
        }
        let cell_len = layout.row_len_on(row, shard);
        if cell_len == 0 {
            // The last row's empty cells are known: they hold nothing.
            cells.insert(shard, Vec::new());
            continue;
        }
        let file = ShardFile { blob_id, layout, shard };
        for location in locations.iter().filter(|l| l.shard == shard) {
            match fetch_range(app, location, &file, row * su, cell_len).await {
                Ok(bytes) => {
                    cells.insert(shard, bytes);
                    sources.push(location);
                    break;
                }
                Err(e) => report(app, blob_id, location, &e),
            }
        }
    }
    if cells.len() < k as usize {
        return Err(io::Error::other(format!(
            "blob {blob_id}: only {} of the {k} cells needed to decode row {row} could be read",
            cells.len()
        )));
    }
    let lens: Vec<u64> = (0..k).map(|s| layout.cell(row, s).len).collect();
    let (m, unit) = (layout.parity_shards, su as usize);
    let decoded = tokio::task::spawn_blocking(move || shards::decode(k, m, unit, &cells, &lens, &[want]))
        .await
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::other("decoding failed"))?;
    let cell = decoded.into_values().next().expect("decode returns what it's asked for");
    // Checked against `want`'s own table, from any file that has it. Every
    // file holds a copy of it: one that disagrees is damaged (the decoded
    // cells all verified against their own tables), so its node checks its
    // file, and the next copy is asked.
    let blocks = layout.shard_blocks(want);
    let start = row * su;
    let (from, to) = blocks.aligned(start, start + len);
    debug_assert_eq!((from, to), (start, start + len), "cells are whole blocks");
    let file = ShardFile { blob_id, layout, shard: want };
    let mut last_error = io::Error::other("no node to read the shard's checksums from");
    for location in sources {
        let crcs = match fetch_table(app, location, &file, want, from, to - from).await {
            Ok(crcs) => crcs,
            Err(e) => {
                report(app, blob_id, location, &e);
                last_error = e;
                continue;
            }
        };
        let sums = BlockSums {
            layout: blocks,
            first_block: from / blocks.block_size,
            crcs,
        };
        let mut at = from;
        let failed = cell.chunks(blocks.block_size as usize).find_map(|chunk| {
            let block = at;
            at += chunk.len() as u64;
            (!sums.verify(block, chunk)).then_some(block)
        });
        match failed {
            None => return Ok(cell),
            Some(at) => {
                let e = io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("blob {blob_id}: shard {want} decoded at offset {at} fails its checksum in this file"),
                );
                report(app, blob_id, location, &e);
                last_error = e;
            }
        }
    }
    Err(last_error)
}

/// Reads [`offset`, `offset + len`) of the shard `location` holds (whole
/// blocks), verified against its table.
async fn fetch_range(
    app: &App,
    location: &Location,
    file: &ShardFile,
    offset: u64,
    len: u64,
) -> io::Result<Vec<u8>> {
    let file = ShardFile { shard: location.shard, ..*file };
    let Some((mut source, crcs)) = Source::open(app, file.blob_id, location, Some(&file), offset, len).await?
    else {
        return Err(io::Error::new(io::ErrorKind::NotFound, "the node doesn't have it"));
    };
    let sums = BlockSums {
        layout: file.blocks_of(file.shard),
        first_block: offset / file.layout.block_size,
        crcs,
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let mut pos = offset;
    let read = async {
        let result = pump_verified(&mut source, &sums, offset, &mut pos, offset + len, &tx).await;
        drop(tx);
        result
    };
    let collect = async {
        let mut bytes = Vec::with_capacity(len as usize);
        while let Some(Ok(frame)) = rx.recv().await {
            if let Ok(data) = frame.into_data() {
                bytes.extend_from_slice(&data);
            }
        }
        bytes
    };
    let (read, bytes) = tokio::join!(read, collect);
    read?;
    if bytes.len() as u64 != len {
        return Err(io::Error::other("the node returned a short read"));
    }
    Ok(bytes)
}

/// Reads shard `of`'s checksums of its block-aligned range [`offset`,
/// `offset + len`) from the file of the shard that `location` holds.
pub(crate) async fn fetch_table(
    app: &App,
    location: &Location,
    file: &ShardFile,
    of: u32,
    offset: u64,
    len: u64,
) -> io::Result<Vec<u8>> {
    let file = ShardFile { shard: location.shard, ..*file };
    if location.node == app.node {
        let Some(mut f) = app.store.open_blob(file.blob_id).await.map_err(io::Error::other)? else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "the node doesn't have it"));
        };
        return blob_file::read_table(&mut f, &file, of, offset, len).await;
    }
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "{}/blobs/{}/table?of={of}&offset={offset}&length={len}{}",
            location.peer_url,
            file.blob_id,
            crate::peer::layout_query(&file)
        ))
        .body(PeerClient::empty())
        .map_err(io::Error::other)?;
    let res = app.peers.request(req).await.map_err(io::Error::other)?;
    match res.status() {
        StatusCode::OK => {}
        StatusCode::NOT_FOUND => return Err(io::Error::new(io::ErrorKind::NotFound, "the node doesn't have it")),
        status => return Err(io::Error::other(format!("the node returned {status}"))),
    }
    let crcs = res.into_body().collect().await.map_err(io::Error::other)?.to_bytes();
    let expected = file.blocks_of(of).crc_bytes(offset, offset + len);
    if crcs.len() != expected {
        return Err(io::Error::other("the node sent the wrong number of checksums"));
    }
    Ok(crcs.to_vec())
}

const READ_CHUNK: usize = 64 * 1024;

/// A byte range of one node's shard of a blob, read as a stream of chunks.
enum Source {
    Local {
        file: File,
        remaining: u64,
    },
    Remote {
        body: Incoming,
        /// Data that arrived in the same frame as the end of the checksums.
        leftover: Option<Bytes>,
    },
}

/// A source positioned at the start of its range, and the checksums of the
/// range's blocks (empty for an unchecksummed blob). `None` if the node
/// doesn't have the shard.
type Opened = Option<(Source, Vec<u8>)>;

impl Source {
    /// Opens [`offset`, `offset + length`) of the shard that `location`
    /// holds, which the catalog describes as `file` (`None` for a blob from
    /// before checksums). With a `file`, the range must be block-aligned.
    async fn open(
        app: &App,
        blob_id: Uuid,
        location: &Location,
        file: Option<&ShardFile>,
        offset: u64,
        length: u64,
    ) -> io::Result<Opened> {
        if location.node == app.node {
            Source::local(app, blob_id, file, offset, length).await
        } else {
            Source::remote(&app.peers, &location.peer_url, blob_id, file, offset, length).await
        }
    }

    /// Opens the local shard.
    async fn local(
        app: &App,
        blob_id: Uuid,
        expected: Option<&ShardFile>,
        offset: u64,
        length: u64,
    ) -> io::Result<Opened> {
        let Some(mut file) = app.store.open_blob(blob_id).await.map_err(io::Error::other)? else {
            return Ok(None);
        };
        let crcs = match expected {
            Some(expected) => blob_file::open_range(&mut file, expected, offset, length).await?,
            None => {
                file.seek(SeekFrom::Start(offset)).await?;
                Vec::new()
            }
        };
        let source = Source::Local {
            file,
            remaining: length,
        };
        Ok(Some((source, crcs)))
    }

    /// Requests the range from a peer. With an `expected` file, the peer
    /// answers with the range's block checksums ahead of the data. It checks
    /// its file against the layout we send, which comes from the catalog.
    async fn remote(
        peers: &PeerClient,
        peer_url: &str,
        blob_id: Uuid,
        expected: Option<&ShardFile>,
        offset: u64,
        length: u64,
    ) -> io::Result<Opened> {
        let checksums = expected.map_or(String::new(), crate::peer::layout_query);
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!(
                "{peer_url}/blobs/{blob_id}?offset={offset}&length={length}{checksums}"
            ))
            .body(PeerClient::empty())
            .map_err(io::Error::other)?;
        let res = peers.request(req).await.map_err(io::Error::other)?;
        match res.status() {
            StatusCode::OK => {}
            StatusCode::NOT_FOUND => return Ok(None),
            status => return Err(io::Error::other(format!("the node returned {status}"))),
        }
        let mut source = Source::Remote {
            body: res.into_body(),
            leftover: None,
        };
        let crc_len = expected.map_or(0, |f| f.blocks_of(f.shard).crc_bytes(offset, offset + length));
        let mut crcs = Vec::with_capacity(crc_len);
        while crcs.len() < crc_len {
            let Some(mut chunk) = source.next().await? else {
                return Err(io::Error::other("the node sent too few checksums"));
            };
            let take = chunk.len().min(crc_len - crcs.len());
            crcs.extend_from_slice(&chunk.split_to(take));
            if !chunk.is_empty()
                && let Source::Remote { leftover, .. } = &mut source
            {
                *leftover = Some(chunk);
            }
        }
        Ok(Some((source, crcs)))
    }

    /// The next chunk of the range, or `None` at its end (or the file's, if
    /// that comes first).
    async fn next(&mut self) -> io::Result<Option<Bytes>> {
        match self {
            Source::Local { file, remaining } => {
                if *remaining == 0 {
                    return Ok(None);
                }
                let mut buf = vec![0u8; (*remaining).min(READ_CHUNK as u64) as usize];
                let n = file.read(&mut buf).await?;
                if n == 0 {
                    return Ok(None);
                }
                buf.truncate(n);
                *remaining -= n as u64;
                Ok(Some(Bytes::from(buf)))
            }
            Source::Remote { body, leftover, .. } => {
                if let Some(data) = leftover.take() {
                    return Ok(Some(data));
                }
                while let Some(frame) = body.frame().await {
                    if let Ok(data) = frame.map_err(io::Error::other)?.into_data() {
                        return Ok(Some(data));
                    }
                }
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_ends_cover_the_range() {
        // 3 data shards, stripe unit 16: rows of 48 bytes; 100 bytes.
        let layout = Layout {
            size: 100,
            block_size: 4,
            data_shards: 3,
            parity_shards: 1,
            stripe_unit: 16,
        };
        for end in 0..=100 {
            for shard in 0..3 {
                // The shard's bytes among the first `end`, counted directly.
                let count = (0..end).filter(|&o| layout.cell_at(o).shard == shard).count() as u64;
                assert_eq!(shard_end(layout, shard, end), count, "end {end} shard {shard}");
            }
        }
    }
}
