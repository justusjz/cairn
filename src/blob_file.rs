//! The on-disk format of a blob file:
//!
//! ```text
//! [ data: size bytes ][ checksum table: 4 bytes per block ][ blob ID: 16 bytes ]
//! ```
//!
//! The data comes first, so offsets into the blob are offsets into the file.
//! The checksum table holds the CRC32C of each `block_size` block of the data
//! (the last block may be short), big-endian. It's written after the data
//! because it's only known once the data has streamed through.
//!
//! The file doesn't describe itself: its format, data size and block size come
//! from the catalog (`blobs`), which a reader already consults to find the
//! blob. The blob ID at the end guards against reading the wrong file, which
//! would otherwise pass verification against its own (self-consistent) table.
//! A file whose length doesn't fit the catalog's size is damaged. A damaged
//! table entry makes its block fail verification, which a reader treats like
//! damaged data. The catalog also keeps the CRC64/NVME of the whole file
//! (`blobs.crc64nvme`), which a scrub checks everything against.
//!
//! The trailer is fully determined by the data, the block size and the blob
//! ID, so every replica's file is byte-for-byte identical.
//!
//! Blobs written before checksums existed are bare data with no table or blob
//! ID; the catalog records which kind a blob is (`blobs.block_size`).

use std::io::{self, SeekFrom};

use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt},
};
use uuid::Uuid;

use crate::checksum::{BlockCrcs, BlockLayout};

/// Length of the blob ID that ends the file.
const ID_LEN: u64 = 16;

/// The checksum table and blob ID that follow a blob's data.
pub fn trailer(blob_id: Uuid, block_crcs: &BlockCrcs) -> Vec<u8> {
    let mut trailer = Vec::with_capacity(block_crcs.0.len() + ID_LEN as usize);
    trailer.extend_from_slice(&block_crcs.0);
    trailer.extend_from_slice(blob_id.as_bytes());
    trailer
}

fn damaged(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("blob file damaged: {what}"))
}

/// Checks that a checksummed blob file is the one the catalog describes: its
/// length fits the blob's size, and it ends in the blob's ID.
async fn check_identity(file: &mut File, blob_id: Uuid, layout: BlockLayout) -> io::Result<()> {
    let file_len = file.metadata().await?.len();
    let blocks = layout.blob_size.div_ceil(layout.block_size);
    if file_len != layout.blob_size + 4 * blocks + ID_LEN {
        return Err(damaged("file length doesn't match the blob"));
    }
    let mut id = [0u8; ID_LEN as usize];
    file.seek(SeekFrom::Start(file_len - ID_LEN)).await?;
    file.read_exact(&mut id).await?;
    if id != *blob_id.as_bytes() {
        return Err(damaged("file ends in another blob's ID"));
    }
    Ok(())
}

/// Opens the block-aligned range [`offset`, `offset + length`) of a checksummed
/// blob file: checks the file is the blob `layout` (the catalog's view of it)
/// describes, reads the checksums of the blocks in the range, and leaves `file`
/// positioned at `offset`. `offset` must be a multiple of the block size, and
/// the range must end at a block boundary or at the end of the data.
pub async fn open_range(
    file: &mut File,
    blob_id: Uuid,
    layout: BlockLayout,
    offset: u64,
    length: u64,
) -> io::Result<Vec<u8>> {
    let block_size = layout.block_size;
    let end = offset + length;
    if block_size == 0
        || !offset.is_multiple_of(block_size)
        || end > layout.blob_size
        || (!end.is_multiple_of(block_size) && end != layout.blob_size)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "range is not block-aligned within the blob",
        ));
    }
    check_identity(file, blob_id, layout).await?;
    let first = offset / block_size;
    let mut crcs = vec![0u8; layout.crc_bytes(offset, end)];
    file.seek(SeekFrom::Start(layout.blob_size + 4 * first)).await?;
    file.read_exact(&mut crcs).await?;
    file.seek(SeekFrom::Start(offset)).await?;
    Ok(crcs)
}

/// Checks a whole blob file: its identity and every block. Returns the CRC64/NVME of
/// the whole file, for comparing with the catalog's. For a future scrub, and
/// for tests.
#[cfg(test)]
pub async fn verify(file: &mut File, blob_id: Uuid, layout: BlockLayout) -> io::Result<u64> {
    let crcs = open_range(file, blob_id, layout, 0, layout.blob_size).await?;
    file.seek(SeekFrom::Start(0)).await?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).await?;
    let sums = crate::checksum::BlockSums {
        layout,
        first_block: 0,
        crcs,
    };
    let data = &bytes[..layout.blob_size as usize];
    for (i, block) in data.chunks(layout.block_size as usize).enumerate() {
        if !sums.verify(i as u64 * layout.block_size, block) {
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

    /// Writes a blob file the way a replica does; returns its file CRC.
    async fn write_blob(path: &std::path::Path, id: Uuid, data: &[u8], bs: u32) -> u64 {
        let mut summer = BlobSummer::new(bs);
        summer.update(data);
        let trailer = trailer(id, &summer.finish());
        let mut file = File::create(path).await.unwrap();
        file.write_all(data).await.unwrap();
        file.write_all(&trailer).await.unwrap();
        file.flush().await.unwrap();
        let mut digest = crc64fast_nvme::Digest::new();
        digest.write(data);
        digest.write(&trailer);
        digest.sum64()
    }

    fn layout(size: u64, bs: u64) -> BlockLayout {
        BlockLayout {
            block_size: bs,
            blob_size: size,
        }
    }

    #[tokio::test]
    async fn round_trip_and_damage() {
        let dir = std::env::temp_dir().join(format!("cairn-blobfile-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("blob");
        let id = Uuid::now_v7();
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
        let l = layout(1000, 256);
        let crc = write_blob(&path, id, &data, 256).await;
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 1000 + 4 * 4 + ID_LEN);
        assert_eq!(crc, crc64(&std::fs::read(&path).unwrap()), "file CRC covers the file");
        let mut file = File::open(&path).await.unwrap();
        assert_eq!(verify(&mut file, id, l).await.unwrap(), crc);

        // A range from block 1 to the (short) last block.
        let crcs = open_range(&mut file, id, l, 256, 1000 - 256).await.unwrap();
        assert_eq!(crcs.len(), 3 * 4);
        let mut rest = Vec::new();
        file.read_to_end(&mut rest).await.unwrap();
        assert_eq!(&rest[..1000 - 256], &data[256..]);

        assert!(open_range(&mut file, id, l, 100, 10).await.is_err(), "unaligned");
        let wrong_blob = open_range(&mut file, Uuid::now_v7(), l, 0, 256).await;
        assert!(wrong_blob.is_err());
        // A wrong block size with the same block count (and so the same file
        // length) gets past the identity check, but cuts the blocks at the
        // wrong boundaries, so they fail their checksums.
        let wrong_bs = verify(&mut file, id, layout(1000, 255)).await;
        assert_eq!(wrong_bs.unwrap_err().kind(), io::ErrorKind::InvalidData);

        // Flip a data bit: the file is still the right one, but the block fails.
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[300] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        let mut file = File::open(&path).await.unwrap();
        assert!(verify(&mut file, id, l).await.is_err());
        bytes[300] ^= 1;

        // Flip a bit of the blob ID.
        let at = bytes.len() - 2;
        bytes[at] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        let mut file = File::open(&path).await.unwrap();
        assert!(open_range(&mut file, id, l, 0, 256).await.is_err());
        bytes[at] ^= 1;

        // A truncated file no longer matches the blob.
        bytes.truncate(bytes.len() - 1);
        std::fs::write(&path, &bytes).unwrap();
        let mut file = File::open(&path).await.unwrap();
        assert!(open_range(&mut file, id, l, 0, 256).await.is_err());

        // An empty blob is just its ID.
        let crc = write_blob(&path, id, &[], 256).await;
        let mut file = File::open(&path).await.unwrap();
        assert_eq!(verify(&mut file, id, layout(0, 256)).await.unwrap(), crc);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
