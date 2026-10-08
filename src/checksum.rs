//! Data checksums.
//!
//! - **Blob blocks (CRC32C).** Every blob is checksummed in fixed-size blocks,
//!   stored in a table inside the blob file (see `blob_file`). Any byte range
//!   can be verified by reading just the blocks it overlaps, which matters once
//!   a blob packs many small parts: a read of one part must not have to read (or
//!   trust) the whole blob. It also pins corruption down to a block, so a reader
//!   can fail over to another replica mid-stream rather than serve bad bytes.
//!   CRC32C has a dedicated CPU instruction, and 32 bits are plenty for 64 KiB.
//! - **Blob files (CRC64/NVME).** The catalog keeps a CRC of each blob's whole
//!   file, for a scrub to check against. It uses a different algorithm than the
//!   blocks on purpose: CRCs are linear, so damage that one CRC32C misses would
//!   be missed by a CRC32C of the whole file too. A second, independent
//!   algorithm makes it a real second check.
//! - **Parts (CRC64/NVME).** Each part carries a CRC of its own bytes in the
//!   catalog. Unlike the block checksums it doesn't depend on where the part
//!   lives, so it stays valid when the part is moved into another blob (packing,
//!   erasure coding), for checking the move. It's also the checksum S3 computes
//!   for objects by default.
//!
//! The part's MD5 (its ETag) is a checksum too, but it's slow to compute and
//! can't verify a range, so it isn't used for integrity checks.

use crc32c::{crc32c, crc32c_append};

/// Bytes covered by one block checksum, for new blobs. Small enough that
/// verifying a small part in a packed blob reads little extra, large enough that
/// a blob's checksum table stays a small fraction of its size (4 bytes per
/// 64 KiB, or 64 KiB per 1 GiB).
pub const BLOCK_SIZE: u32 = 64 * 1024;

/// The block checksums of a fully written blob: the CRC32C of each block,
/// big-endian, concatenated. The last block may be short; an empty blob has no
/// blocks.
pub struct BlockCrcs(pub Vec<u8>);

/// Computes a blob's [`BlockCrcs`] as its bytes stream past.
pub struct BlobSummer {
    block_size: u32,
    block_crcs: Vec<u8>,
    /// CRC and length of the block being filled.
    block: u32,
    block_len: u32,
}

impl BlobSummer {
    pub fn new(block_size: u32) -> Self {
        BlobSummer {
            block_size,
            block_crcs: Vec::new(),
            block: 0,
            block_len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = data.len().min((self.block_size - self.block_len) as usize);
            self.block = crc32c_append(self.block, &data[..take]);
            self.block_len += take as u32;
            data = &data[take..];
            if self.block_len == self.block_size {
                self.end_block();
            }
        }
    }

    fn end_block(&mut self) {
        self.block_crcs.extend_from_slice(&self.block.to_be_bytes());
        self.block = 0;
        self.block_len = 0;
    }

    pub fn finish(mut self) -> BlockCrcs {
        if self.block_len > 0 {
            self.end_block();
        }
        BlockCrcs(self.block_crcs)
    }
}

/// How a checksummed blob is divided into blocks.
#[derive(Clone, Copy)]
pub struct BlockLayout {
    pub block_size: u64,
    pub blob_size: u64,
}

impl BlockLayout {
    /// Widens [start, end) to whole blocks, the range a verified read must fetch.
    pub fn aligned(&self, start: u64, end: u64) -> (u64, u64) {
        let start = start / self.block_size * self.block_size;
        let end = end.div_ceil(self.block_size) * self.block_size;
        (start, end.min(self.blob_size))
    }

    /// Length of the block starting at `block_start` (the last one may be short).
    pub fn block_len(&self, block_start: u64) -> u64 {
        self.block_size.min(self.blob_size.saturating_sub(block_start))
    }

    /// Bytes of checksums covering the block-aligned range [start, end).
    pub fn crc_bytes(&self, start: u64, end: u64) -> usize {
        (4 * (end.div_ceil(self.block_size) - start / self.block_size)) as usize
    }
}

/// The block checksums covering a range of a blob, for verifying a read of it.
pub struct BlockSums {
    pub layout: BlockLayout,
    /// Index of the block `crcs` starts at.
    pub first_block: u64,
    /// Big-endian CRC32Cs of consecutive blocks, from `first_block` on.
    pub crcs: Vec<u8>,
}

impl BlockSums {
    /// Whether `data` is the intact content of the block starting at
    /// `block_start`. A block outside the loaded checksums never verifies.
    pub fn verify(&self, block_start: u64, data: &[u8]) -> bool {
        let Some(index) = (block_start / self.layout.block_size).checked_sub(self.first_block)
        else {
            return false;
        };
        let at = index as usize * 4;
        match self.crcs.get(at..at + 4) {
            Some(expected) => crc32c(data).to_be_bytes() == expected,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn crc64_is_the_nvme_variant() {
        // The standard check value of CRC-64/NVME, the variant S3 uses.
        let mut digest = crc64fast_nvme::Digest::new();
        digest.write(b"123456789");
        assert_eq!(digest.sum64(), 0xae8b_1486_0a79_9888);
    }

    #[test]
    fn summer_matches_one_shot_crcs_across_chunkings() {
        let bs = BLOCK_SIZE as usize;
        for len in [0, 1, bs - 1, bs, bs + 1, 3 * bs + 17] {
            let bytes = data(len);
            for chunk in [1, 1000, bs, 3 * bs] {
                let mut summer = BlobSummer::new(BLOCK_SIZE);
                for piece in bytes.chunks(chunk) {
                    summer.update(piece);
                }
                let sums = summer.finish().0;
                let expected: Vec<u8> = bytes
                    .chunks(bs)
                    .flat_map(|b| crc32c(b).to_be_bytes())
                    .collect();
                assert_eq!(sums, expected, "len {len} chunk {chunk}");
            }
        }
    }

    #[test]
    fn block_sums_verify_a_suffix_of_blocks() {
        let bs = BLOCK_SIZE as u64;
        let bytes = data(3 * BLOCK_SIZE as usize + 100);
        let mut summer = BlobSummer::new(BLOCK_SIZE);
        summer.update(&bytes);
        let all = summer.finish().0;
        let layout = BlockLayout {
            block_size: bs,
            blob_size: bytes.len() as u64,
        };
        assert_eq!(layout.aligned(bs + 5, 2 * bs + 1), (bs, 3 * bs));
        assert_eq!(layout.aligned(3 * bs + 1, 3 * bs + 2), (3 * bs, 3 * bs + 100));
        assert_eq!(layout.block_len(3 * bs), 100);
        assert_eq!(layout.crc_bytes(bs, 3 * bs + 100), 12);
        // Loaded from block 1 on, as a read starting inside block 1 would.
        let sums = BlockSums {
            layout,
            first_block: 1,
            crcs: all[4..].to_vec(),
        };
        let block = |i: usize| &bytes[i * bs as usize..((i + 1) * bs as usize).min(bytes.len())];
        assert!(sums.verify(bs, block(1)));
        assert!(sums.verify(3 * bs, block(3)));
        assert!(!sums.verify(0, block(0)), "block before the loaded range");
        assert!(!sums.verify(2 * bs, block(1)), "wrong content");
        let mut flipped = block(2).to_vec();
        flipped[1234] ^= 0x10;
        assert!(!sums.verify(2 * bs, &flipped), "single bit flip");
    }
}
