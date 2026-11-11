//! The on-disk format of a shard file, which holds one shard of a blob (see
//! `shards`):
//!
//! ```text
//! [ data ][ checksum tables ][ shard index: 2 bytes ][ blob ID: 16 bytes ]
//! ```
//!
//! The data comes first, so offsets into the shard are offsets into the file.
//! A checksum table holds the CRC32C of each `block_size` block of a shard's
//! data (the last block may be short), big-endian. The tables are written
//! after the data because they're only known once the data has streamed
//! through.
//!
//! The file holds the table of every shard of the blob, its own and the
//! others', in shard order: a reader that decodes a shard it couldn't read
//! verifies what it decoded against the shard's table, from any other shard's
//! file. The shard index (big-endian) keeps one shard's file from being read
//! as another's, which its own table would pass.
//!
//! A replicated blob's shards (k = 1) all hold the same bytes, so they share a
//! table, and need no index: their file is `[ data ][ table ][ blob ID ]`,
//! the same for every shard, and the format of every blob written before
//! erasure coding.
//!
//! The file doesn't describe itself: its layout comes from the catalog
//! (`blobs`), which a reader already consults to find the blob. The blob ID at
//! the end guards against reading the wrong file, which would otherwise pass
//! verification against its own (self-consistent) table. A file whose length
//! doesn't fit the catalog's layout is damaged. A damaged table entry makes
//! its block fail verification, which a reader treats like damaged data. The
//! catalog also keeps the CRC64/NVME of each shard's whole file
//! (`blobs.shard_crcs`), which a scrub checks everything against. The trailer
//! is fully determined by the blob, so a shard's file is the same wherever
//! it's written.
//!
//! Blobs written before checksums existed are bare data with no tables or blob
//! ID; the catalog records which kind a blob is (`blobs.block_size`).

use std::io::{self, SeekFrom};

use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt},
};
use uuid::Uuid;

use crate::checksum::{BlockCrcs, BlockLayout};
use crate::shards::Layout;

/// Length of the blob ID that ends the file.
const ID_LEN: u64 = 16;
/// Length of the shard index before it, in a coded blob's files.
const INDEX_LEN: u64 = 2;

/// A shard file as the catalog describes it: which shard it holds, of which
/// blob.
#[derive(Clone, Copy, Debug)]
pub struct ShardFile {
    pub blob_id: Uuid,
    pub layout: Layout,
    pub shard: u32,
}

impl ShardFile {
    /// How many tables it holds: one per shard, or one for all of a
    /// replicated blob's.
    fn tables(&self) -> u32 {
        if self.layout.replicated() { 1 } else { self.layout.shards() }
    }

    /// Bytes of shard data.
    pub fn data_len(&self) -> u64 {
        self.layout.shard_size(self.shard)
    }

    /// The blocks of shard `of`'s data, which its table covers.
    pub fn blocks_of(&self, of: u32) -> BlockLayout {
        self.layout.shard_blocks(of)
    }

    fn table_len(&self, of: u32) -> u64 {
        4 * self.blocks_of(of).blob_size.div_ceil(self.layout.block_size)
    }

    /// Where shard `of`'s table starts in the file: the one table, for a
    /// replicated blob.
    fn table_start(&self, of: u32) -> u64 {
        let before = if self.layout.replicated() { 0 } else { of };
        self.data_len() + (0..before).map(|i| self.table_len(i)).sum::<u64>()
    }

    /// How long the tables are, together.
    fn tables_len(&self) -> u64 {
        (0..self.tables()).map(|i| self.table_len(i)).sum()
    }

    fn tail_len(&self) -> u64 {
        if self.layout.replicated() { ID_LEN } else { INDEX_LEN + ID_LEN }
    }

    /// The length of the whole file.
    pub fn len(&self) -> u64 {
        self.data_len() + self.tables_len() + self.tail_len()
    }
}

/// What follows a shard's data: the tables of the blob's shards (`tables`,
/// one per shard in shard order, or one for a replicated blob), then its
/// index and the blob ID.
pub fn trailer(file: &ShardFile, tables: &[BlockCrcs]) -> Vec<u8> {
    debug_assert_eq!(tables.len(), file.tables() as usize);
    let mut trailer = Vec::with_capacity((file.len() - file.data_len()) as usize);
    for table in tables {
        trailer.extend_from_slice(&table.0);
    }
    trailer.extend_from_slice(&tail(file));
    trailer
}

/// What ends a shard file, after its tables: its index, and the blob ID.
pub fn tail(file: &ShardFile) -> Vec<u8> {
    let mut tail = Vec::with_capacity(file.tail_len() as usize);
    if !file.layout.replicated() {
        tail.extend_from_slice(&(file.shard as u16).to_be_bytes());
    }
    tail.extend_from_slice(file.blob_id.as_bytes());
    tail
}

/// Splits the trailer of a shard file (everything after its data) into its
/// tables, in shard order, and the tail (shard index and blob ID). `None` if
/// it's too short.
pub fn split_trailer<'a>(file: &ShardFile, trailer: &'a [u8]) -> Option<(Vec<&'a [u8]>, &'a [u8])> {
    if trailer.len() as u64 != file.len() - file.data_len() {
        return None;
    }
    let mut tables = Vec::new();
    let mut rest = trailer;
    for of in 0..file.tables() {
        let (table, after) = rest.split_at(file.table_len(of) as usize);
        tables.push(table);
        rest = after;
    }
    Some((tables, rest))
}

/// Checks a trailer's tail against the shard it should end: the right
/// index, and the blob ID. The reason, if it's wrong.
pub fn check_tail(file: &ShardFile, tail: &[u8]) -> Result<(), &'static str> {
    let (index, id) = tail.split_at(tail.len() - ID_LEN as usize);
    if id != file.blob_id.as_bytes() {
        return Err("the file ends in another blob's ID");
    }
    if !file.layout.replicated() && index != (file.shard as u16).to_be_bytes() {
        return Err("the file holds another shard of the blob");
    }
    Ok(())
}

fn damaged(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("blob file damaged: {what}"))
}

/// Checks that a checksummed shard file is the one the catalog describes: its
/// length fits the layout, and it ends in the shard's index and blob ID.
async fn check_identity(file: &mut File, expected: &ShardFile) -> io::Result<()> {
    let file_len = file.metadata().await?.len();
    if file_len != expected.len() {
        return Err(damaged("file length doesn't match the blob"));
    }
    let mut tail = vec![0u8; expected.tail_len() as usize];
    file.seek(SeekFrom::Start(file_len - expected.tail_len())).await?;
    file.read_exact(&mut tail).await?;
    check_tail(expected, &tail).map_err(damaged)
}

/// Opens the block-aligned range [`offset`, `offset + length`) of a
/// checksummed shard file's data: checks the file is the shard the catalog
/// describes (`expected`), reads the checksums of the blocks in the range,
/// and leaves `file` positioned at `offset`. `offset` must be a multiple of
/// the block size, and the range must end at a block boundary or at the end
/// of the data.
pub async fn open_range(
    file: &mut File,
    expected: &ShardFile,
    offset: u64,
    length: u64,
) -> io::Result<Vec<u8>> {
    let crcs = read_table(file, expected, expected.shard, offset, length).await?;
    file.seek(SeekFrom::Start(offset)).await?;
    Ok(crcs)
}

/// Reads the checksums of shard `of`'s blocks over the block-aligned range
/// [`offset`, `offset + length`) of its data, from a checksummed shard file of
/// the same blob (`expected`), which is checked as `open_range` checks it.
pub async fn read_table(
    file: &mut File,
    expected: &ShardFile,
    of: u32,
    offset: u64,
    length: u64,
) -> io::Result<Vec<u8>> {
    let blocks = expected.blocks_of(of);
    let block_size = blocks.block_size;
    let end = offset + length;
    if block_size == 0
        || of >= expected.layout.shards()
        || !offset.is_multiple_of(block_size)
        || end > blocks.blob_size
        || (!end.is_multiple_of(block_size) && end != blocks.blob_size)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "range is not block-aligned within the shard",
        ));
    }
    check_identity(file, expected).await?;
    let mut crcs = vec![0u8; blocks.crc_bytes(offset, end)];
    file.seek(SeekFrom::Start(expected.table_start(of) + 4 * (offset / block_size))).await?;
    file.read_exact(&mut crcs).await?;
    Ok(crcs)
}

/// Checks a whole shard file: its identity and every block of its data.
/// Returns the CRC64/NVME of the whole file, for comparing with the catalog's.
/// For tests.
#[cfg(test)]
pub async fn verify(file: &mut File, expected: &ShardFile) -> io::Result<u64> {
    let blocks = expected.blocks_of(expected.shard);
    let crcs = open_range(file, expected, 0, blocks.blob_size).await?;
    file.seek(SeekFrom::Start(0)).await?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).await?;
    let sums = crate::checksum::BlockSums {
        layout: blocks,
        first_block: 0,
        crcs,
    };
    let data = &bytes[..blocks.blob_size as usize];
    for (i, block) in data.chunks(blocks.block_size as usize).enumerate() {
        if !sums.verify(i as u64 * blocks.block_size, block) {
            return Err(damaged("block failed its checksum"));
        }
    }
    Ok(crc64(&bytes))
}

#[cfg(test)]
fn crc64(bytes: &[u8]) -> u64 {
    let mut digest = crc64fast_nvme::Digest::new();
    digest.write(bytes);
    digest.sum64()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::BlobSummer;
    use tokio::io::AsyncWriteExt;

    /// Writes a shard file of `shards` (every shard's data, in shard order)
    /// the way a sink does; returns its file CRC.
    async fn write_shard(path: &std::path::Path, file: &ShardFile, shards: &[&[u8]]) -> u64 {
        let tables: Vec<BlockCrcs> = shards
            .iter()
            .take(file.tables() as usize)
            .map(|data| {
                let mut summer = BlobSummer::new(file.layout.block_size as u32);
                summer.update(data);
                summer.finish()
            })
            .collect();
        let trailer = trailer(file, &tables);
        let data = shards[file.shard as usize];
        let mut f = File::create(path).await.unwrap();
        f.write_all(data).await.unwrap();
        f.write_all(&trailer).await.unwrap();
        f.flush().await.unwrap();
        let mut digest = crc64fast_nvme::Digest::new();
        digest.write(data);
        digest.write(&trailer);
        digest.sum64()
    }

    fn replicated(size: u64, bs: u64) -> Layout {
        Layout {
            size,
            block_size: bs,
            data_shards: 1,
            parity_shards: 2,
            stripe_unit: bs,
        }
    }

    #[tokio::test]
    async fn round_trip_and_damage() {
        let dir = std::env::temp_dir().join(format!("cairn-blobfile-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("blob");
        let id = Uuid::now_v7();
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
        let l = replicated(1000, 256);
        let f = ShardFile { blob_id: id, layout: l, shard: 0 };
        let crc = write_shard(&path, &f, &[&data]).await;
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 1000 + 4 * 4 + ID_LEN);
        assert_eq!(crc, crc64(&std::fs::read(&path).unwrap()), "file CRC covers the file");
        let mut file = File::open(&path).await.unwrap();
        assert_eq!(verify(&mut file, &f).await.unwrap(), crc);
        // Every shard of a replicated blob is the same file.
        let other = ShardFile { shard: 2, ..f };
        assert_eq!(verify(&mut file, &other).await.unwrap(), crc);

        // A range from block 1 to the (short) last block.
        let crcs = open_range(&mut file, &f, 256, 1000 - 256).await.unwrap();
        assert_eq!(crcs.len(), 3 * 4);
        let mut rest = Vec::new();
        file.read_to_end(&mut rest).await.unwrap();
        assert_eq!(&rest[..1000 - 256], &data[256..]);

        assert!(open_range(&mut file, &f, 100, 10).await.is_err(), "unaligned");
        let wrong_blob = ShardFile { blob_id: Uuid::now_v7(), ..f };
        assert!(open_range(&mut file, &wrong_blob, 0, 256).await.is_err());
        // A wrong block size with the same block count (and so the same file
        // length) gets past the identity check, but cuts the blocks at the
        // wrong boundaries, so they fail their checksums.
        let wrong_bs = ShardFile { layout: replicated(1000, 255), ..f };
        assert_eq!(verify(&mut file, &wrong_bs).await.unwrap_err().kind(), io::ErrorKind::InvalidData);

        // Flip a data bit: the file is still the right one, but the block fails.
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[300] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        let mut file = File::open(&path).await.unwrap();
        assert!(verify(&mut file, &f).await.is_err());
        bytes[300] ^= 1;

        // Flip a bit of the blob ID.
        let at = bytes.len() - 2;
        bytes[at] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        let mut file = File::open(&path).await.unwrap();
        assert!(open_range(&mut file, &f, 0, 256).await.is_err());
        bytes[at] ^= 1;

        // A truncated file no longer matches the blob.
        bytes.truncate(bytes.len() - 1);
        std::fs::write(&path, &bytes).unwrap();
        let mut file = File::open(&path).await.unwrap();
        assert!(open_range(&mut file, &f, 0, 256).await.is_err());

        // An empty blob is just its ID.
        let empty = ShardFile { layout: replicated(0, 256), ..f };
        let crc = write_shard(&path, &empty, &[&[]]).await;
        let mut file = File::open(&path).await.unwrap();
        assert_eq!(verify(&mut file, &empty).await.unwrap(), crc);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn coded_shards_carry_every_table() {
        let dir = std::env::temp_dir().join(format!("cairn-blobfile-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("blob");
        let id = Uuid::now_v7();
        // 2+1, stripe unit 512, blocks of 256: 1300 bytes are two rows, the
        // second holding 276 bytes, all on shard 0.
        let layout = Layout {
            size: 1300,
            block_size: 256,
            data_shards: 2,
            parity_shards: 1,
            stripe_unit: 512,
        };
        let blob: Vec<u8> = (0..1300u32).map(|i| (i * 13) as u8).collect();
        let shard0: Vec<u8> = [&blob[..512], &blob[1024..]].concat();
        let shard1 = blob[512..1024].to_vec();
        let parity = vec![0x5a; 1024];
        let shards: [&[u8]; 3] = [&shard0, &shard1, &parity];
        assert_eq!([layout.shard_size(0), layout.shard_size(1), layout.shard_size(2)], [788, 512, 1024]);
        for shard in 0..3 {
            let f = ShardFile { blob_id: id, layout, shard };
            let crc = write_shard(&path, &f, &shards).await;
            let tables = 4 * (4 + 2 + 4);
            assert_eq!(std::fs::metadata(&path).unwrap().len(), shards[shard as usize].len() as u64 + tables + 18);
            let mut file = File::open(&path).await.unwrap();
            assert_eq!(verify(&mut file, &f).await.unwrap(), crc);
            // Another shard's table, from this file.
            let crcs = read_table(&mut file, &f, 0, 512, 276).await.unwrap();
            assert_eq!(crcs, crate::checksum::BlobSummer::new(256).tap(&shard0[512..]).0);
            // Read as another shard, it's the wrong file.
            let other = ShardFile { shard: (shard + 1) % 3, ..f };
            assert_eq!(verify(&mut file, &other).await.unwrap_err().kind(), io::ErrorKind::InvalidData);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    impl BlobSummer {
        /// The table of `data` alone.
        fn tap(mut self, data: &[u8]) -> BlockCrcs {
            self.update(data);
            self.finish()
        }
    }
}
