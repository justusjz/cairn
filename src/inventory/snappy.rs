//! Snappy compression, as Parquet's `SNAPPY` codec has it (and as S3
//! compresses its Parquet inventory reports): the raw format, a block
//! without framing or checksums. Only compression: Cairn never reads what
//! it writes this way.
//!
//! The format (Snappy's `format_description.txt`): the uncompressed length,
//! as a varint, then elements, each a tag byte whose low two bits say what
//! it is: a literal (`00`), bytes copied as they are, or a copy of bytes
//! already written, from an offset back (`01`, `10`, `11`, with offsets of
//! 11, 16 and 32 bits). It's LZ77 and nothing more: no entropy coding.
//!
//! Compression finds matches with a hash table of where each four bytes
//! were last seen, in blocks of 64 KiB (as Snappy's own does), so that
//! offsets fit in 16 bits and the table in `u16`s. It's simpler than
//! Snappy's own, and compresses a little less: it takes no bigger steps
//! through input that doesn't match, and hashes no positions within a
//! match.

/// The most bytes a block holds: offsets within it fit in 16 bits.
const BLOCK: usize = 1 << 16;
/// Of the hash table: how many bits a hash has.
const HASH_BITS: u32 = 14;
/// The shortest match worth a copy.
const MIN_MATCH: usize = 4;
/// The longest copy an element holds.
const MAX_COPY: usize = 64;

/// `input`, compressed.
pub fn compress(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() / 2 + 16);
    let len = u32::try_from(input.len()).expect("Snappy compresses under 4 GiB at a time");
    varint(&mut out, len);
    let mut table = vec![0u16; 1 << HASH_BITS];
    for block in input.chunks(BLOCK) {
        table.fill(0);
        compress_block(block, &mut table, &mut out);
    }
    out
}

fn varint(out: &mut Vec<u8>, mut n: u32) {
    while n >= 0x80 {
        out.push(n as u8 | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

fn load(block: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(block[i..i + 4].try_into().expect("four bytes"))
}

fn hash(bytes: u32) -> usize {
    (bytes.wrapping_mul(0x1e35_a7bd) >> (32 - HASH_BITS)) as usize
}

fn compress_block(block: &[u8], table: &mut [u16], out: &mut Vec<u8>) {
    // Where the bytes not yet written start.
    let mut pending = 0;
    let mut i = 0;
    while i + MIN_MATCH <= block.len() {
        let bytes = load(block, i);
        let h = hash(bytes);
        // (A stale entry, or the table's zeros, are only a match if the
        // bytes there are the same.)
        let candidate = usize::from(table[h]);
        table[h] = i as u16;
        if candidate < i && load(block, candidate) == bytes {
            let mut len = MIN_MATCH;
            // A match may run into the bytes it's copied to, as a copy may.
            while i + len < block.len() && block[candidate + len] == block[i + len] {
                len += 1;
            }
            literal(out, &block[pending..i]);
            copy(out, i - candidate, len);
            i += len;
            pending = i;
        } else {
            i += 1;
        }
    }
    literal(out, &block[pending..]);
}

/// A literal of `bytes`: its length less one in the tag, up to 60, or else
/// in the 1 to 4 bytes after it (the tag saying how many: 60 to 63).
fn literal(out: &mut Vec<u8>, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let n = bytes.len() - 1;
    if n < 60 {
        out.push((n as u8) << 2);
    } else {
        let width = (usize::BITS - n.leading_zeros()).div_ceil(8) as usize;
        out.push(((59 + width) as u8) << 2);
        out.extend_from_slice(&n.to_le_bytes()[..width]);
    }
    out.extend_from_slice(bytes);
}

/// Copies of `len` bytes from `offset` back, as few elements as hold them:
/// a 1-byte offset's (`01`: lengths 4 to 11, offsets under 2048) where one
/// does, else a 2-byte offset's (`10`: lengths 1 to 64).
fn copy(out: &mut Vec<u8>, offset: usize, mut len: usize) {
    debug_assert!((1..BLOCK).contains(&offset));
    while len > 0 {
        let n = len.min(MAX_COPY);
        if (4..=11).contains(&n) && offset < 2048 {
            out.push(((offset >> 8) as u8) << 5 | ((n - 4) as u8) << 2 | 0b01);
            out.push(offset as u8);
        } else {
            out.push(((n - 1) as u8) << 2 | 0b10);
            out.extend_from_slice(&(offset as u16).to_le_bytes());
        }
        len -= n;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Snappy's decompression, as the format describes it, to check
    /// compression against.
    fn decompress(input: &[u8]) -> Vec<u8> {
        let mut i = 0;
        let mut len = 0usize;
        let mut shift = 0;
        loop {
            let b = input[i];
            i += 1;
            len |= usize::from(b & 0x7f) << shift;
            shift += 7;
            if b < 0x80 {
                break;
            }
        }
        let mut out: Vec<u8> = Vec::with_capacity(len);
        let le = |bytes: &[u8]| bytes.iter().rev().fold(0usize, |n, b| n << 8 | usize::from(*b));
        while i < input.len() {
            let tag = input[i];
            i += 1;
            let (offset, n) = match tag & 0b11 {
                0b00 => {
                    let mut n = usize::from(tag >> 2);
                    if n >= 60 {
                        let width = n - 59;
                        n = le(&input[i..i + width]);
                        i += width;
                    }
                    out.extend_from_slice(&input[i..i + n + 1]);
                    i += n + 1;
                    continue;
                }
                0b01 => {
                    let offset = usize::from(tag >> 5) << 8 | usize::from(input[i]);
                    i += 1;
                    (offset, usize::from(tag >> 2 & 0b111) + 4)
                }
                0b10 => {
                    i += 2;
                    (le(&input[i - 2..i]), usize::from(tag >> 2) + 1)
                }
                _ => {
                    i += 4;
                    (le(&input[i - 4..i]), usize::from(tag >> 2) + 1)
                }
            };
            assert!(offset > 0 && offset <= out.len(), "offset {offset} of {}", out.len());
            for _ in 0..n {
                out.push(out[out.len() - offset]);
            }
        }
        assert_eq!(out.len(), len);
        out
    }

    fn round_trip(input: &[u8]) -> usize {
        let compressed = compress(input);
        assert_eq!(decompress(&compressed), input);
        compressed.len()
    }

    /// Bytes that look random, from a seed.
    fn noise(n: usize, mut seed: u64) -> Vec<u8> {
        (0..n)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed as u8
            })
            .collect()
    }

    #[test]
    fn compresses_what_repeats() {
        assert_eq!(compress(b""), [0]);
        round_trip(b"a");
        round_trip(b"abcd");
        // A run is a copy of what it's still writing.
        assert!(round_trip(&[7; 100_000]) < 5000);
        let rows: Vec<u8> = (0..20_000).flat_map(|i| format!("photos/2026/img-{i:06}.jpg STANDARD\n").into_bytes()).collect();
        assert!(round_trip(&rows) < rows.len() / 3);
    }

    #[test]
    fn literals_of_every_length() {
        // What's random doesn't compress: literals, of lengths that take
        // the tag alone, and one to three bytes after it.
        for n in [59, 60, 61, 255, 256, 257, 65_535, 65_536, 65_537, 200_000] {
            let input = noise(n, n as u64 + 1);
            assert!(round_trip(&input) <= n + n / 1000 + 16);
        }
    }

    #[test]
    fn copies_near_and_far() {
        // Matches at offsets that take one byte and two, of lengths that
        // take one element and several, across blocks.
        let mut input = Vec::new();
        for (i, offset) in [5, 100, 2047, 2048, 3000, 40_000].into_iter().enumerate() {
            let chunk = noise(offset, i as u64 + 7);
            input.extend_from_slice(&chunk);
            let n = [4, 11, 12, 64, 65, 300][i];
            input.extend_from_slice(&chunk[..n.min(chunk.len())]);
        }
        for _ in 0..3 {
            input.extend_from_within(..40_000);
        }
        round_trip(&input);
        // And whatever mixes of them noise with repeats makes.
        for seed in 1..50 {
            let mut input = noise(5000, seed);
            for j in 0..200 {
                let start = (j * 37 + seed as usize) % input.len();
                let end = (start + (j % 70) + 1).min(input.len());
                input.extend_from_within(start..end);
            }
            round_trip(&input);
        }
    }
}
