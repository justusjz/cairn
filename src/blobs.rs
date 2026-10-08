//! Blobs: the files on disk. Every blob is replicated to one or more nodes
//! (`blob_locations`), and parts reference a byte range of a blob. A blob is
//! garbage once no part references it anymore; deleting its row cascades its
//! locations, after which its files are reaped.

use std::io::{self, SeekFrom};
use std::sync::Arc;

use deadpool_postgres::GenericClient;
use http_body_util::{BodyExt, Empty};
use hyper::{
    Method, Request, StatusCode,
    body::{Bytes, Frame, Incoming},
};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt},
};
use uuid::Uuid;

use crate::{
    App, blob_file,
    body::FrameSender,
    checksum::{BlockLayout, BlockSums},
};

/// A replica holding a blob: the node's number (`nodes.id`) and peer URL.
pub(crate) type Location = (i32, String);

/// A blob file to reap, and where it lives: (blob_id, holder node, holder
/// peer_url). One per replica.
pub(crate) type ReapTarget = (Uuid, i32, String);

/// Maps location rows (blob_id, node, peer_url) into reap targets.
pub(crate) fn reap_targets(rows: &[tokio_postgres::Row]) -> Vec<ReapTarget> {
    rows.iter()
        .map(|r| (r.get::<_, Uuid>(0), r.get::<_, i32>(1), r.get::<_, String>(2)))
        .collect()
}

/// The `blob_id`s of `DELETE FROM parts … RETURNING blob_id` rows.
pub(crate) fn blob_ids(rows: &[tokio_postgres::Row]) -> Vec<Uuid> {
    rows.iter().map(|r| r.get(0)).collect()
}

/// Deletes those of `blob_ids` that no part references anymore (typically the
/// blobs of parts just deleted in the same transaction), cascading their
/// locations away. Returns those locations, for the caller to reap after commit.
///
/// The `parts.blob_id` FK guards against a concurrent transaction attaching a
/// new part to one of these blobs: either it or this delete fails.
pub(crate) async fn drop_unreferenced_blobs<C: GenericClient>(
    client: &C,
    blob_ids: &[Uuid],
) -> Result<Vec<ReapTarget>, tokio_postgres::Error> {
    if blob_ids.is_empty() {
        return Ok(Vec::new());
    }
    // All parts of a statement see the same snapshot, so the outer SELECT still
    // sees the locations that the DELETE cascades away.
    let rows = client
        .query(
            "WITH gone AS (
                 DELETE FROM blobs b
                 WHERE b.blob_id = ANY($1)
                   AND NOT EXISTS (SELECT 1 FROM parts p WHERE p.blob_id = b.blob_id)
                 RETURNING b.blob_id
             )
             SELECT bl.blob_id, bl.node, n.peer_url
             FROM gone
             JOIN blob_locations bl ON bl.blob_id = gone.blob_id
             JOIN nodes n ON n.id = bl.node",
            &[&blob_ids],
        )
        .await?;
    Ok(reap_targets(&rows))
}

/// Best-effort: once a set of blobs has been removed from the catalog, ask each
/// holder to delete the file from disk *now*: locally if that's us, else via the
/// peer's `DELETE /blobs/{id}`. The rows are already gone, so any deletion that
/// fails (peer down, network) is harmless: `cairn prune` reclaims the leftovers.
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
                delete_from_replica(&peer_url, blob_id).await
            };
            if let Err(e) = result {
                eprintln!("best-effort reap of blob {blob_id} on {peer_url} failed: {e}");
            }
        }
    });
}

async fn delete_from_replica(peer_url: &str, blob_id: Uuid) -> anyhow::Result<()> {
    let client = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method(Method::DELETE)
        .uri(format!("{peer_url}/blobs/{blob_id}"))
        .body(Empty::<Bytes>::new())?;
    let res = client.request(req).await?;
    if res.status() != StatusCode::OK {
        anyhow::bail!("replica {peer_url} returned status {}", res.status());
    }
    Ok(())
}

/// A byte range of a blob to read, the blob's block layout (`None` for a blob
/// written before checksums), and the candidate replicas holding it, freshest
/// first.
pub(crate) struct BlobSlice {
    pub blob_id: Uuid,
    pub layout: Option<BlockLayout>,
    pub locations: Vec<Location>,
    pub offset: u64,
    pub length: u64,
}

/// Streams `slice` to `tx`, verifying it against the blob's block checksums.
///
/// Each replica serves the checksums of the blocks it's asked for along with
/// the data, from the table in its blob file. Only verified bytes are
/// forwarded, block by block. So when a replica fails mid-stream, returns a
/// short read, or serves a block that doesn't match its checksum, the read moves
/// on to the next replica from the first unsent block, and the client never
/// sees the bad bytes. A corrupt block is logged loudly; repairing it is left to
/// a future scrub/repair job. Blobs written before checksums existed are
/// streamed unverified, but still with failover.
pub(crate) async fn stream_blob_range(
    app: &App,
    slice: &BlobSlice,
    tx: &FrameSender,
) -> io::Result<()> {
    let blob_id = slice.blob_id;
    let end = slice.offset + slice.length;
    // Everything before `pos` has been forwarded.
    let mut pos = slice.offset;
    // Cycle through the replicas for as long as one makes progress: when two are
    // damaged in different places, each can still serve what the other can't.
    // Give up once every replica has failed at the current position.
    let mut failed_here = 0;
    for (node, peer_url) in slice.locations.iter().cycle() {
        if failed_here == slice.locations.len() {
            break;
        }
        let (start, stop) = match &slice.layout {
            Some(layout) => layout.aligned(pos, end),
            None => (pos, end),
        };
        let before = pos;
        let result = async {
            let source = if *node == app.node {
                Source::local(app, blob_id, slice.layout, start, stop - start).await?
            } else {
                Source::remote(peer_url, blob_id, slice.layout, start, stop - start).await?
            };
            let Some((mut source, crcs)) = source else {
                return Err(io::Error::new(io::ErrorKind::NotFound, "replica doesn't have it"));
            };
            match slice.layout {
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
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                eprintln!("CORRUPTION: blob {blob_id} on node {node} ({peer_url}): {e}");
            }
            Err(e) => eprintln!("reading blob {blob_id} from {peer_url} failed: {e}"),
        }
        failed_here = if pos > before { 1 } else { failed_here + 1 };
    }
    Err(io::Error::other(format!(
        "no replica could serve blob {blob_id} from offset {pos}"
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
            return Err(io::Error::other("replica returned a short read"));
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
            return Err(io::Error::other("replica returned a short read"));
        };
        chunk.truncate((end - *pos).min(chunk.len() as u64) as usize);
        *pos += chunk.len() as u64;
        if tx.send(Ok(Frame::data(chunk))).await.is_err() {
            return Ok(()); // receiver gone (client hung up)
        }
    }
    Ok(())
}

const READ_CHUNK: usize = 64 * 1024;

/// A byte range of one replica's copy of a blob, read as a stream of chunks.
enum Source {
    Local {
        file: File,
        remaining: u64,
    },
    Remote {
        body: Incoming,
        /// Data that arrived in the same frame as the end of the checksums.
        leftover: Option<Bytes>,
        // Kept alive while the body streams.
        _client: Client<HttpConnector, Empty<Bytes>>,
    },
}

/// A source positioned at the start of its range, and the checksums of the
/// range's blocks (empty for an unchecksummed blob). `None` if the replica
/// doesn't have the blob.
type Opened = Option<(Source, Vec<u8>)>;

impl Source {
    /// Opens the local copy. With a `layout`, the range must be block-aligned.
    async fn local(
        app: &App,
        blob_id: Uuid,
        layout: Option<BlockLayout>,
        offset: u64,
        length: u64,
    ) -> io::Result<Opened> {
        let Some(mut file) = app.store.open_blob(blob_id).await.map_err(io::Error::other)? else {
            return Ok(None);
        };
        let crcs = match layout {
            Some(layout) => blob_file::open_range(&mut file, blob_id, layout, offset, length).await?,
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

    /// Requests the range from a peer. With a `layout`, the range must be
    /// block-aligned, and the peer answers with the range's block checksums
    /// ahead of the data. It checks its file against the layout we send, which
    /// comes from the catalog.
    async fn remote(
        peer_url: &str,
        blob_id: Uuid,
        layout: Option<BlockLayout>,
        offset: u64,
        length: u64,
    ) -> io::Result<Opened> {
        let client = Client::builder(TokioExecutor::new()).build_http();
        let checksums = match layout {
            Some(l) => format!("&blob_size={}&block_size={}", l.blob_size, l.block_size),
            None => String::new(),
        };
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!(
                "{peer_url}/blobs/{blob_id}?offset={offset}&length={length}{checksums}"
            ))
            .body(Empty::<Bytes>::new())
            .map_err(io::Error::other)?;
        let res = client.request(req).await.map_err(io::Error::other)?;
        match res.status() {
            StatusCode::OK => {}
            StatusCode::NOT_FOUND => return Ok(None),
            status => return Err(io::Error::other(format!("replica returned {status}"))),
        }
        let mut source = Source::Remote {
            body: res.into_body(),
            leftover: None,
            _client: client,
        };
        let crc_len = layout.map_or(0, |l| l.crc_bytes(offset, offset + length));
        let mut crcs = Vec::with_capacity(crc_len);
        while crcs.len() < crc_len {
            let Some(mut chunk) = source.next().await? else {
                return Err(io::Error::other("replica sent too few checksums"));
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
