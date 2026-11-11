//! Shards: how a blob is spread over nodes.
//!
//! Every blob is stored as k data shards and m parity shards, each on a node
//! of its own, and any k of them hold all of its data: it survives the loss of
//! any m. Replication is k = 1: the one data shard is the blob, and every
//! parity shard is a copy of it (a code whose parity rows are all ones, which
//! is as much an MDS code as any). So a replica is a shard, encoding is a copy,
//! any shard serves any read, and rebuilding a shard is copying another.
//! Blobs larger than `packer::SMALL_SIZE` are stored with k > 1, which stores
//! them with less overhead, once the operator sets it (the `data-shards`
//! setting): coded as they're written, if their size is known up front, else
//! rewritten by the packer (see `packer`). Smaller blobs are replicated until
//! they're packed into larger ones.
//!
//! With k > 1, the blob is cut into rows of k cells of [`STRIPE_UNIT`] bytes
//! each, the stripe unit: row r is the blob's bytes [r·k·su, (r+1)·k·su), and
//! its cell j is on data shard j, at r·su in it. The cells of a row are
//! encoded into m parity cells, one on each parity shard, at the same offset.
//! So every shard holds row r at r·su, and a read of up to a stripe unit of
//! the blob (a small object in a packed blob) usually reads one shard. The
//! stripe unit is a whole number of checksum blocks (see `checksum`), so a
//! data shard's blocks are the blob's blocks, rearranged.
//!
//! A data shard holds just its bytes: the last row may be short, and some of
//! its cells shorter, or empty. Parity shards hold whole rows, `rows · su`
//! bytes: the last row is encoded as if its cells were padded with zeros. That
//! costs at most m stripe units per blob, and only large blobs are coded.
//!
//! The coding is Reed–Solomon (`reed_solomon_simd`), systematic: the data
//! shards hold the data as it is, so an intact blob is read without decoding.

use std::collections::BTreeMap;

use crate::checksum::BlockLayout;

/// How much of a row each data shard holds: 1 MiB, 16 checksum blocks. A
/// read of up to that much of a coded blob mostly reads one shard.
pub const STRIPE_UNIT: u32 = 1024 * 1024;

/// The most data shards a blob may have (`cairn config set data-shards`).
/// Rows grow with them, and every coded read or rebuild of a row holds one in
/// memory, k stripe units.
pub const MAX_DATA_SHARDS: u32 = 32;

/// How a blob is stored, as the catalog describes it: its size, its block
/// size (see `checksum`), and its shards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub size: u64,
    pub block_size: u64,
    /// k: the shards that hold the data; any k of all of them do.
    pub data_shards: u32,
    /// m: the shards that hold its parity; the blob survives losing any m.
    pub parity_shards: u32,
    /// How much of a row each data shard holds.
    pub stripe_unit: u64,
}

/// A row's cell on a data shard: where its bytes are in the blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell {
    pub row: u64,
    pub shard: u32,
    /// The cell's first byte, in the blob.
    pub start: u64,
    /// How many bytes of the blob it holds (the last row's may hold fewer
    /// than a stripe unit, or none).
    pub len: u64,
}

impl Layout {
    /// A layout of `size` bytes in the given shards, with the block size and
    /// stripe unit that Cairn writes.
    pub fn new(size: u64, data_shards: u32, parity_shards: u32) -> Layout {
        Layout {
            size,
            block_size: crate::checksum::BLOCK_SIZE as u64,
            data_shards,
            parity_shards,
            stripe_unit: STRIPE_UNIT as u64,
        }
    }

    /// k + m: how many shards there are.
    pub fn shards(&self) -> u32 {
        self.data_shards + self.parity_shards
    }

    /// Whether every shard holds the blob as it is (k = 1).
    pub fn replicated(&self) -> bool {
        self.data_shards == 1
    }

    fn row_len(&self) -> u64 {
        self.data_shards as u64 * self.stripe_unit
    }

    /// How many rows the blob has.
    pub fn rows(&self) -> u64 {
        self.size.div_ceil(self.row_len())
    }

    /// How many bytes shard `shard` holds.
    pub fn shard_size(&self, shard: u32) -> u64 {
        if self.replicated() {
            return self.size;
        }
        if shard >= self.data_shards {
            return self.rows() * self.stripe_unit;
        }
        let (full, rest) = (self.size / self.row_len(), self.size % self.row_len());
        full * self.stripe_unit + rest.saturating_sub(shard as u64 * self.stripe_unit).min(self.stripe_unit)
    }

    /// Shard `shard`'s bytes as checksum blocks.
    pub fn shard_blocks(&self, shard: u32) -> BlockLayout {
        BlockLayout {
            block_size: self.block_size,
            blob_size: self.shard_size(shard),
        }
    }

    /// The cell holding byte `offset` of the blob. For k = 1, that's the
    /// stripe unit around it, on shard 0.
    pub fn cell_at(&self, offset: u64) -> Cell {
        let row = offset / self.row_len();
        let shard = ((offset % self.row_len()) / self.stripe_unit) as u32;
        self.cell(row, shard)
    }

    /// Row `row`'s cell on data shard `shard`.
    pub fn cell(&self, row: u64, shard: u32) -> Cell {
        let start = row * self.row_len() + shard as u64 * self.stripe_unit;
        Cell {
            row,
            shard,
            start,
            len: self.size.saturating_sub(start).min(self.stripe_unit),
        }
    }

    /// Where blob offset `offset` is in its data shard.
    pub fn shard_offset(&self, offset: u64) -> u64 {
        let cell = self.cell_at(offset);
        cell.row * self.stripe_unit + (offset - cell.start)
    }

    /// How many bytes of row `row` shard `shard` holds: its cell's length for
    /// a data shard, a stripe unit for a parity shard.
    pub fn row_len_on(&self, row: u64, shard: u32) -> u64 {
        if shard < self.data_shards {
            self.cell(row, shard).len
        } else {
            self.stripe_unit
        }
    }
}

/// Encodes a row of a coded blob (k > 1): its data cells, the last row's
/// short ones as if padded with zeros, into its `m` parity cells of `su`
/// bytes each.
pub fn encode(cells: &[&[u8]], m: u32, su: usize) -> Vec<Vec<u8>> {
    let padded: Vec<std::borrow::Cow<[u8]>> = cells.iter().map(|cell| pad(cell, su)).collect();
    reed_solomon_simd::encode(cells.len(), m as usize, &padded)
        .expect("a row of whole, even-sized cells within the supported counts encodes")
}

/// Decodes a row of a coded blob (k > 1), or the same bytes of each of its
/// cells, `su` of them (see `blobs::reconstruct`), from any `k` of its
/// cells, given by shard (data cells as long as they hold bytes of the
/// range, parity cells whole): returns every cell `wanted` asks for, data or
/// parity, data cells cut to `lens` (by data shard). `None` if there are
/// fewer than k cells.
pub fn decode(
    k: u32,
    m: u32,
    su: usize,
    cells: &BTreeMap<u32, Vec<u8>>,
    lens: &[u64],
    wanted: &[u32],
) -> Option<BTreeMap<u32, Vec<u8>>> {
    if cells.len() < k as usize {
        return None;
    }
    let mut data: BTreeMap<u32, Vec<u8>> = cells
        .iter()
        .filter(|(shard, _)| **shard < k)
        .map(|(shard, cell)| (*shard, pad(cell, su).into_owned()))
        .collect();
    if data.len() < k as usize {
        let originals = data.iter().map(|(shard, cell)| (*shard as usize, cell));
        let recovery = cells
            .iter()
            .filter(|(shard, _)| **shard >= k)
            .map(|(shard, cell)| ((shard - k) as usize, cell));
        let restored = reed_solomon_simd::decode(k as usize, m as usize, originals, recovery).ok()?;
        for (shard, cell) in restored {
            data.insert(shard as u32, cell);
        }
    }
    let parity = if wanted.iter().any(|&shard| shard >= k) {
        let row: Vec<&[u8]> = data.values().map(Vec::as_slice).collect();
        encode(&row, m, su)
    } else {
        Vec::new()
    };
    let mut out = BTreeMap::new();
    for &shard in wanted {
        let cell = if shard < k {
            let mut cell = data[&shard].clone();
            cell.truncate(lens[shard as usize] as usize);
            cell
        } else {
            parity[(shard - k) as usize].clone()
        };
        out.insert(shard, cell);
    }
    Some(out)
}

/// `cell` padded with zeros to `su` bytes.
fn pad(cell: &[u8], su: usize) -> std::borrow::Cow<'_, [u8]> {
    if cell.len() == su {
        std::borrow::Cow::Borrowed(cell)
    } else {
        let mut padded = cell.to_vec();
        padded.resize(su, 0);
        std::borrow::Cow::Owned(padded)
    }
}

#[cfg(test)]
pub(crate) mod e2e;

#[cfg(test)]
mod tests {
    use super::*;

    fn layout(size: u64, k: u32, m: u32, su: u64) -> Layout {
        Layout {
            size,
            block_size: 4,
            data_shards: k,
            parity_shards: m,
            stripe_unit: su,
        }
    }

    #[test]
    fn replicas_hold_the_blob() {
        let l = layout(1000, 1, 2, 16);
        for shard in 0..3 {
            assert_eq!(l.shard_size(shard), 1000);
        }
        assert_eq!(l.shard_offset(999), 999);
        assert_eq!(l.cell_at(999), Cell { row: 62, shard: 0, start: 992, len: 8 });
    }

    #[test]
    fn shard_sizes_cover_the_blob() {
        // Rows of 3 × 16 = 48 bytes.
        for size in [0, 1, 15, 16, 17, 47, 48, 49, 100, 96] {
            let l = layout(size, 3, 2, 16);
            let data: u64 = (0..3).map(|s| l.shard_size(s)).sum();
            assert_eq!(data, size, "size {size}");
            for parity in 3..5 {
                assert_eq!(l.shard_size(parity), size.div_ceil(48) * 16);
            }
        }
        let l = layout(100, 3, 2, 16);
        // Two full rows, then 4 bytes on shard 0.
        assert_eq!([l.shard_size(0), l.shard_size(1), l.shard_size(2)], [36, 32, 32]);
    }

    #[test]
    fn offsets_map_to_cells_and_back() {
        let l = layout(100, 3, 2, 16);
        let mut per_shard = [0u64; 3];
        for offset in 0..100 {
            let cell = l.cell_at(offset);
            assert!(cell.start <= offset && offset < cell.start + cell.len);
            // Bytes reach each shard in order, contiguously.
            assert_eq!(l.shard_offset(offset), per_shard[cell.shard as usize]);
            per_shard[cell.shard as usize] += 1;
        }
        assert_eq!(l.cell(2, 1).len, 0, "the last row's cell 1 is empty");
        assert_eq!(l.row_len_on(2, 0), 4);
        assert_eq!(l.row_len_on(2, 4), 16);
    }

    /// The code works byte by byte across a row's cells: the same block of
    /// each cell encodes and decodes as the whole cells do, which lets a
    /// block be rebuilt from a block of each of k shards (`blobs::
    /// reconstruct`). `reed_solomon_simd` doesn't promise it (it works in
    /// 64-byte chunks of its shards), so this pins it: a version that breaks
    /// it fails here. (A decoded block that came out wrong would fail its
    /// checksum, never reach a client.)
    #[test]
    fn ranges_decode_as_whole_cells() {
        let su = STRIPE_UNIT as usize;
        let block = crate::checksum::BLOCK_SIZE as usize;
        for (k, m) in [(2u32, 1u32), (4, 2), (8, 3), (10, 4)] {
            let mut x = 0x9e37_79b9_7f4a_7c15_u64 ^ k as u64;
            let cells: Vec<Vec<u8>> = (0..k)
                .map(|_| {
                    (0..su)
                        .map(|_| {
                            x ^= x << 13;
                            x ^= x >> 7;
                            x ^= x << 17;
                            x as u8
                        })
                        .collect()
                })
                .collect();
            let refs: Vec<&[u8]> = cells.iter().map(Vec::as_slice).collect();
            let parity = encode(&refs, m, su);
            let all: Vec<&Vec<u8>> = cells.iter().chain(parity.iter()).collect();
            for (first, blocks) in [(0, 1), (7, 2), (15, 1)] {
                let range = first * block..(first + blocks) * block;
                // The first m cells are lost.
                let present: BTreeMap<u32, Vec<u8>> =
                    (m..k + m).map(|s| (s, all[s as usize][range.clone()].to_vec())).collect();
                let lens = vec![range.len() as u64; k as usize];
                let lost: Vec<u32> = (0..m).collect();
                let got = decode(k, m, range.len(), &present, &lens, &lost).unwrap();
                for s in lost {
                    assert!(got[&s] == all[s as usize][range.clone()], "{k}+{m}, blocks {range:?}");
                }
            }
        }
    }

    #[test]
    fn rows_decode_from_any_k_cells() {
        let (k, m, su) = (4u32, 2u32, 64usize);
        // A short last row: cells of 64, 64, 10 and 0 bytes.
        let lens = [64u64, 64, 10, 0];
        let cells: Vec<Vec<u8>> = lens
            .iter()
            .enumerate()
            .map(|(j, &len)| (0..len).map(|i| (i as u8).wrapping_mul(31) ^ j as u8).collect())
            .collect();
        let refs: Vec<&[u8]> = cells.iter().map(Vec::as_slice).collect();
        let parity = encode(&refs, m, su);
        assert_eq!(parity.len(), 2);
        let all: Vec<Vec<u8>> = cells.iter().cloned().chain(parity.iter().cloned()).collect();
        // Every way of losing two shards.
        for a in 0..k + m {
            for b in a + 1..k + m {
                let present: BTreeMap<u32, Vec<u8>> = (0..k + m)
                    .filter(|&s| s != a && s != b)
                    .map(|s| (s, all[s as usize].clone()))
                    .collect();
                let got = decode(k, m, su, &present, &lens, &[a, b]).unwrap();
                assert_eq!(got[&a], all[a as usize], "lost {a} and {b}");
                assert_eq!(got[&b], all[b as usize], "lost {a} and {b}");
            }
        }
        let too_few: BTreeMap<u32, Vec<u8>> = (0..3).map(|s| (s, all[s as usize].clone())).collect();
        assert!(decode(k, m, su, &too_few, &lens, &[3]).is_none());
    }
}
