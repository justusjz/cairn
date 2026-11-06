//! The format of an encrypted part.
//!
//! A part's plaintext is cut into segments of [`SEGMENT`] bytes (the last may
//! be shorter, and is empty only for an empty part), and each is sealed with
//! XChaCha20-Poly1305 on its own, its 16-byte tag following it:
//!
//! ```text
//! [ segment 0 ciphertext ][ tag ][ segment 1 ciphertext ][ tag ] ... [ last ][ tag ]
//! ```
//!
//! Every segment's nonce is the part's random salt, then the segment's index
//! and whether it's the last:
//!
//! ```text
//! salt (16 bytes) ‖ index (7 bytes, big-endian) ‖ last (1 byte: 0 or 1)
//! ```
//!
//! XChaCha20 derives a subkey from the key and the nonce's first 16 bytes, so
//! every part has a subkey of its own, under which no nonce repeats. The index
//! and the last flag are the STREAM construction (as `age` uses it): a segment
//! can't be moved to another place, and a part can't be cut short at a segment
//! boundary, since then no segment carries the last flag. Nothing about where
//! the part is stored is part of it: the packer moves parts between blobs, and
//! copies share them.
//!
//! The salt isn't secret. It's stored with the part, and serves as its ETag.

use bytes::{Bytes, BytesMut};
use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305, XNonce, aead::Tag};

/// Plaintext bytes per segment.
pub const SEGMENT: u64 = 64 * 1024;
/// Bytes of tag after each segment.
pub const TAG: u64 = 16;
/// Stored bytes of a full segment.
pub const STORED_SEGMENT: u64 = SEGMENT + TAG;
/// Bytes of salt per part.
pub const SALT_LEN: usize = 16;

/// An encryption key, 256 bits.
pub type Key = [u8; 32];
/// A part's salt.
pub type Salt = [u8; SALT_LEN];

/// A fresh random salt, for a new part.
pub fn new_salt() -> Salt {
    let mut salt = [0; SALT_LEN];
    getrandom::fill(&mut salt).expect("the OS random number generator failed");
    salt
}

/// How many segments a part of `plain` bytes has: one at least.
pub fn segments(plain: u64) -> u64 {
    plain.div_ceil(SEGMENT).max(1)
}

/// How many bytes a part of `plain` bytes takes, stored.
pub fn stored_len(plain: u64) -> u64 {
    plain + segments(plain) * TAG
}

/// What of a part to read for the plaintext range [`start`, `end`) of it,
/// which holds `plain` bytes: whole segments, as a stored range, and where in
/// their plaintext the range starts.
#[derive(Debug, PartialEq, Eq)]
pub struct SegmentRange {
    /// The first segment to read.
    pub first: u64,
    /// The stored range of the segments, relative to the part's start.
    pub stored_start: u64,
    pub stored_end: u64,
    /// Plaintext bytes to skip at the start of the first segment.
    pub skip: u64,
    /// Plaintext bytes of the range.
    pub len: u64,
}

/// The [`SegmentRange`] covering [`start`, `end`) of a part of `plain` bytes.
/// `start < end <= plain`.
pub fn segment_range(plain: u64, start: u64, end: u64) -> SegmentRange {
    debug_assert!(start < end && end <= plain);
    let first = start / SEGMENT;
    let last = (end - 1) / SEGMENT;
    SegmentRange {
        first,
        stored_start: first * STORED_SEGMENT,
        stored_end: (last * STORED_SEGMENT + STORED_SEGMENT).min(stored_len(plain)),
        skip: start - first * SEGMENT,
        len: end - start,
    }
}

fn nonce(salt: &Salt, index: u64, last: bool) -> XNonce {
    assert!(index < 1 << 56, "a part can't have this many segments");
    let mut nonce = [0; 24];
    nonce[..SALT_LEN].copy_from_slice(salt);
    nonce[SALT_LEN..23].copy_from_slice(&index.to_be_bytes()[1..]);
    nonce[23] = last as u8;
    nonce.into()
}

/// Encrypts a part as its plaintext streams through.
pub struct Sealer {
    cipher: XChaCha20Poly1305,
    salt: Salt,
    index: u64,
    /// The plaintext of the segment being filled. A full segment stays here
    /// until more plaintext comes (or none does): only then is it known
    /// whether it's the last.
    pending: BytesMut,
    plain: u64,
}

impl Sealer {
    pub fn new(key: &Key, salt: Salt) -> Self {
        Sealer {
            cipher: XChaCha20Poly1305::new(key.into()),
            salt,
            index: 0,
            pending: BytesMut::with_capacity(SEGMENT as usize + TAG as usize),
            plain: 0,
        }
    }

    /// The part's salt.
    pub fn salt(&self) -> Salt {
        self.salt
    }

    /// Takes more plaintext, and returns the stored bytes of the segments it
    /// completed (if any).
    pub fn update(&mut self, mut data: &[u8]) -> Option<Bytes> {
        let mut out = BytesMut::new();
        self.plain += data.len() as u64;
        while !data.is_empty() {
            if self.pending.len() as u64 == SEGMENT {
                out.extend_from_slice(&self.seal(false));
            }
            let take = (SEGMENT as usize - self.pending.len()).min(data.len());
            self.pending.extend_from_slice(&data[..take]);
            data = &data[take..];
        }
        (!out.is_empty()).then(|| out.freeze())
    }

    /// Seals the last segment, and returns its stored bytes, with the
    /// plaintext's length.
    pub fn finish(mut self) -> (Bytes, u64) {
        (self.seal(true), self.plain)
    }

    fn seal(&mut self, last: bool) -> Bytes {
        let mut segment = self.pending.split();
        let tag = self
            .cipher
            .encrypt_inout_detached(
                &nonce(&self.salt, self.index, last),
                &[],
                segment.as_mut().into(),
            )
            .expect("a segment is far below XChaCha20-Poly1305's limit");
        segment.extend_from_slice(&tag);
        self.index += 1;
        segment.freeze()
    }
}

/// A segment that didn't decrypt: the wrong key, or damaged or altered bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unauthentic {
    pub segment: u64,
}

impl std::fmt::Display for Unauthentic {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "segment {} of an encrypted part failed authentication",
            self.segment
        )
    }
}

impl std::error::Error for Unauthentic {}

/// Decrypts whole segments of a part, from a given one on, as their stored
/// bytes stream through, in order. Bytes may come in pieces of any size.
pub struct Opener {
    cipher: XChaCha20Poly1305,
    salt: Salt,
    index: u64,
    /// The index of the part's last segment.
    last: u64,
    /// Stored bytes of the segment being received.
    pending: BytesMut,
    /// Stored bytes of the last segment.
    last_stored: u64,
}

impl Opener {
    /// An opener for the part of `plain` bytes, from segment `first` on.
    pub fn new(key: &Key, salt: Salt, plain: u64, first: u64) -> Self {
        let last = segments(plain) - 1;
        Opener {
            cipher: XChaCha20Poly1305::new(key.into()),
            salt,
            index: first,
            last,
            pending: BytesMut::with_capacity(STORED_SEGMENT as usize),
            last_stored: stored_len(plain) - last * STORED_SEGMENT,
        }
    }

    /// Takes more stored bytes, and returns the plaintext of the segments
    /// they completed (if any).
    pub fn update(&mut self, mut data: &[u8]) -> Result<Option<Bytes>, Unauthentic> {
        let mut out = BytesMut::new();
        while !data.is_empty() {
            // No bytes belong past the last segment.
            if self.index > self.last {
                return Err(Unauthentic {
                    segment: self.index,
                });
            }
            let take = (self.segment_stored() - self.pending.len()).min(data.len());
            self.pending.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.pending.len() == self.segment_stored() {
                out.extend_from_slice(&self.open()?);
            }
        }
        Ok((!out.is_empty()).then(|| out.freeze()))
    }

    /// Checks that the bytes ended at a segment boundary.
    pub fn finish(self) -> Result<(), Unauthentic> {
        match self.pending.is_empty() {
            true => Ok(()),
            false => Err(Unauthentic {
                segment: self.index,
            }),
        }
    }

    /// Stored bytes of the segment being received.
    fn segment_stored(&self) -> usize {
        match self.index == self.last {
            true => self.last_stored as usize,
            false => STORED_SEGMENT as usize,
        }
    }

    fn open(&mut self) -> Result<Bytes, Unauthentic> {
        let unauthentic = Unauthentic {
            segment: self.index,
        };
        let mut segment = self.pending.split();
        let tag = segment.split_off(segment.len() - TAG as usize);
        let tag = Tag::<XChaCha20Poly1305>::try_from(&tag[..]).map_err(|_| unauthentic)?;
        let nonce = nonce(&self.salt, self.index, self.index == self.last);
        self.cipher
            .decrypt_inout_detached(&nonce, &[], segment.as_mut().into(), &tag)
            .map_err(|_| unauthentic)?;
        self.index += 1;
        Ok(segment.freeze())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: Key = [7; 32];
    const SALT: Salt = [9; SALT_LEN];

    fn plaintext(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    /// Seals `data`, handing it over `chunk` bytes at a time.
    fn seal(data: &[u8], chunk: usize) -> Vec<u8> {
        let mut sealer = Sealer::new(&KEY, SALT);
        let mut stored = Vec::new();
        for piece in data.chunks(chunk.max(1)) {
            if let Some(out) = sealer.update(piece) {
                stored.extend_from_slice(&out);
            }
        }
        let (out, plain) = sealer.finish();
        stored.extend_from_slice(&out);
        assert_eq!(plain, data.len() as u64);
        stored
    }

    /// Opens `stored`, from segment `first` of a part of `plain` bytes.
    fn open(
        key: &Key,
        stored: &[u8],
        plain: u64,
        first: u64,
        chunk: usize,
    ) -> Result<Vec<u8>, Unauthentic> {
        let mut opener = Opener::new(key, SALT, plain, first);
        let mut out = Vec::new();
        for piece in stored.chunks(chunk.max(1)) {
            if let Some(got) = opener.update(piece)? {
                out.extend_from_slice(&got);
            }
        }
        opener.finish()?;
        Ok(out)
    }

    const SIZES: [usize; 8] = [0, 1, 65535, 65536, 65537, 131072, 131073, 3 * 65536 + 5];

    #[test]
    fn round_trips_in_pieces_of_any_size() {
        for len in SIZES {
            let data = plaintext(len);
            for chunk in [1, 1000, 65536, 70000, len] {
                if chunk == 1 && len > 70000 {
                    continue;
                }
                let stored = seal(&data, chunk);
                assert_eq!(
                    stored.len() as u64,
                    stored_len(len as u64),
                    "{len} by {chunk}"
                );
                assert_eq!(
                    open(&KEY, &stored, len as u64, 0, chunk).unwrap(),
                    data,
                    "{len} by {chunk}"
                );
            }
        }
    }

    #[test]
    fn stored_lengths() {
        assert_eq!(stored_len(0), 16);
        assert_eq!(stored_len(1), 17);
        assert_eq!(stored_len(65536), 65552);
        assert_eq!(stored_len(65537), 65552 + 17);
    }

    /// Pins the format: a change to it fails this, instead of making stored
    /// parts unreadable.
    #[test]
    fn the_format_is_stable() {
        let stored = seal(&plaintext(65536 + 3), 65536 + 3);
        let digest = |bytes: &[u8]| {
            use sha2::Digest;
            sha2::Sha256::digest(bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        assert_eq!(
            digest(&stored),
            "aed66dd4855012ff7799bfaa648e787daa59f3b49294410b57bc56e81469b185",
            "the encrypted part format changed"
        );
    }

    /// The nonces are laid out as documented: salt, index, last flag.
    #[test]
    fn segments_are_sealed_with_the_documented_nonces() {
        let data = plaintext(65536 + 3);
        let stored = seal(&data, data.len());
        let cipher = XChaCha20Poly1305::new((&KEY).into());
        let mut expected = Vec::new();
        for (index, last, piece) in [(0u8, 0u8, &data[..65536]), (1, 1, &data[65536..])] {
            let mut nonce = SALT.to_vec();
            nonce.extend_from_slice(&[0, 0, 0, 0, 0, 0, index, last]);
            let nonce = XNonce::try_from(&nonce[..]).unwrap();
            let mut buffer = piece.to_vec();
            let tag = cipher
                .encrypt_inout_detached(&nonce, &[], buffer.as_mut_slice().into())
                .unwrap();
            expected.extend_from_slice(&buffer);
            expected.extend_from_slice(&tag);
        }
        assert_eq!(stored, expected);
    }

    #[test]
    fn opens_from_any_segment() {
        let len = 3 * 65536 + 5;
        let data = plaintext(len);
        let stored = seal(&data, len);
        for (start, end) in [
            (0, 1),
            (65535, 65537),
            (65536, 131072),
            (100, len),
            (len - 1, len),
            (0, len),
        ] {
            let range = segment_range(len as u64, start as u64, end as u64);
            let bytes = &stored[range.stored_start as usize..range.stored_end as usize];
            let plain = open(&KEY, bytes, len as u64, range.first, 777).unwrap();
            let got = &plain[range.skip as usize..(range.skip + range.len) as usize];
            assert_eq!(got, &data[start..end], "{start}..{end}");
        }
    }

    #[test]
    fn refuses_what_isnt_the_part() {
        let len = 2 * 65536 + 10;
        let stored = seal(&plaintext(len), len);
        let plain = len as u64;
        let seg = STORED_SEGMENT as usize;
        // The wrong key.
        assert_eq!(
            open(&[8; 32], &stored, plain, 0, len),
            Err(Unauthentic { segment: 0 })
        );
        // A flipped bit, in a ciphertext or a tag.
        for at in [5, seg - 1, seg + 3, stored.len() - 1] {
            let mut flipped = stored.clone();
            flipped[at] ^= 1;
            assert!(open(&KEY, &flipped, plain, 0, len).is_err(), "bit at {at}");
        }
        // Two segments swapped.
        let mut swapped = stored[seg..2 * seg].to_vec();
        swapped.extend_from_slice(&stored[..seg]);
        swapped.extend_from_slice(&stored[2 * seg..]);
        assert_eq!(
            open(&KEY, &swapped, plain, 0, len),
            Err(Unauthentic { segment: 0 })
        );
        // A segment read as another index.
        assert!(open(&KEY, &stored[seg..2 * seg], plain, 0, len).is_err());
        // Cut short at a segment boundary, and claimed to be that short: the
        // segment that's now last doesn't carry the last flag.
        assert_eq!(
            open(&KEY, &stored[..seg], 65536, 0, len),
            Err(Unauthentic { segment: 0 })
        );
        // Cut short mid-segment.
        assert!(open(&KEY, &stored[..seg + 5], plain, 0, len).is_err());
        // Bytes past the end.
        let mut longer = stored.clone();
        longer.extend_from_slice(&[0; 20]);
        assert!(open(&KEY, &longer, plain, 0, len).is_err());
    }

    #[test]
    fn another_salt_is_another_part() {
        let data = plaintext(100);
        let mut sealer = Sealer::new(&KEY, [1; SALT_LEN]);
        assert!(sealer.update(&data).is_none());
        let (stored, _) = sealer.finish();
        assert!(open(&KEY, &stored, 100, 0, 100).is_err());
        assert_ne!(stored.to_vec(), seal(&data, 100));
    }
}
