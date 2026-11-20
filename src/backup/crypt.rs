//! How a backup's objects are stored: encrypted, so that the target holds
//! nothing readable without the backup's key.
//!
//! Every object is sealed as an encrypted part is (see `encryption`): its
//! plaintext in segments of 64 KiB, each sealed with XChaCha20-Poly1305,
//! under a key of the object's own, with a random salt:
//!
//! ```text
//! "CAIRNBK1" ‖ salt (16 bytes) ‖ segments, as `encryption` seals a part's
//! ```
//!
//! The object's key is HMAC-SHA256 of its name (relative to the backup's
//! prefix) under the backup's key, so an object only opens under its own
//! name: none can be passed off as another. The segments' nonces carry
//! their index and whether they're the last, so none can be moved, and an
//! object can't be cut short. And since segments open on their own, a range
//! of an object is read by reading the segments it overlaps.

use std::collections::VecDeque;

use hyper::body::Bytes;
use tokio::task::JoinHandle;

use super::s3::Target;
use crate::encryption::{self, Key, Opener, Salt, Sealer};

const MAGIC: &[u8; 8] = b"CAIRNBK1";
/// Bytes before the segments: the magic and the salt.
pub const HEADER: u64 = 8 + encryption::SALT_LEN as u64;
/// What a multipart upload's parts hold, and the size up to which an object
/// is stored with a single PUT.
pub const UPLOAD_PART: usize = 16 << 20;
/// How many of an object's parts are uploaded at once: a single upload
/// rarely fills the link to a remote service, but more hold more in memory
/// (a part each).
const UPLOADS_IN_FLIGHT: usize = 4;

/// The key of the object `name`, under the backup's key `key`.
pub fn object_key(key: &Key, name: &str) -> Key {
    let mut data = b"cairn backup object v1\0".to_vec();
    data.extend_from_slice(name.as_bytes());
    crate::auth::hmac_sha256(key, &data)
}

/// How many bytes an object of `plain` bytes takes, stored.
pub fn stored_len(plain: u64) -> u64 {
    HEADER + encryption::stored_len(plain)
}

/// How many bytes of plaintext an object `stored` bytes long holds, if it
/// can be one.
pub fn plain_len(stored: u64) -> Option<u64> {
    let sealed = stored.checked_sub(HEADER)?;
    let segments = sealed.div_ceil(encryption::STORED_SEGMENT).max(1);
    let plain = sealed.checked_sub(segments * encryption::TAG)?;
    (stored_len(plain) == stored).then_some(plain)
}

/// Writes an object as its plaintext streams through: seals it, and uploads
/// it, in parts once it's larger than one, so that what's held in memory
/// stays small, however large it is.
pub struct ObjectWriter {
    target: Target,
    name: String,
    sealer: Option<Sealer>,
    /// Sealed bytes not yet uploaded.
    buffer: Vec<u8>,
    upload: Option<Upload>,
    plain: u64,
}

/// A multipart upload under way.
struct Upload {
    id: String,
    /// The ETags of the parts uploaded, in order.
    etags: Vec<String>,
    /// The uploads of the parts after them, in order.
    in_flight: VecDeque<JoinHandle<anyhow::Result<String>>>,
}

impl Upload {
    /// Waits for the oldest part's upload.
    async fn settle_one(&mut self) -> anyhow::Result<()> {
        if let Some(part) = self.in_flight.pop_front() {
            let etag = part
                .await
                .map_err(|e| anyhow::anyhow!("uploading a part failed: {e}"))??;
            self.etags.push(etag);
        }
        Ok(())
    }
}

impl Drop for ObjectWriter {
    /// Stops the uploads in flight of an object given up (by dropping it).
    fn drop(&mut self) {
        if let Some(upload) = &self.upload {
            for part in &upload.in_flight {
                part.abort();
            }
        }
    }
}

impl ObjectWriter {
    pub fn new(target: &Target, key: &Key, name: &str) -> ObjectWriter {
        let salt: Salt = encryption::new_salt();
        let mut buffer = Vec::with_capacity(UPLOAD_PART + encryption::STORED_SEGMENT as usize);
        buffer.extend_from_slice(MAGIC);
        buffer.extend_from_slice(&salt);
        ObjectWriter {
            target: target.clone(),
            name: name.to_owned(),
            sealer: Some(Sealer::new(&object_key(key, name), salt)),
            buffer,
            upload: None,
            plain: 0,
        }
    }

    /// How many bytes of plaintext it holds so far: where the next byte goes.
    pub fn position(&self) -> u64 {
        self.plain
    }

    /// Appends `data`.
    pub async fn write(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.plain += data.len() as u64;
        let sealer = self.sealer.as_mut().expect("written after finishing");
        for segment in sealer.update(data) {
            self.buffer.extend_from_slice(&segment);
        }
        if self.buffer.len() >= UPLOAD_PART {
            self.flush(false).await?;
        }
        Ok(())
    }

    /// Uploads the buffer's full parts (or everything, if `all`, and waits
    /// for every upload), up to `UPLOADS_IN_FLIGHT` at once.
    async fn flush(&mut self, all: bool) -> anyhow::Result<()> {
        while self.buffer.len() >= UPLOAD_PART || (all && !self.buffer.is_empty()) {
            if self.upload.is_none() {
                let id = self.target.create_upload(&self.name).await?;
                self.upload = Some(Upload {
                    id,
                    etags: Vec::new(),
                    in_flight: VecDeque::new(),
                });
            }
            let upload = self.upload.as_mut().unwrap();
            if upload.in_flight.len() >= UPLOADS_IN_FLIGHT {
                upload.settle_one().await?;
            }
            let take = self.buffer.len().min(UPLOAD_PART);
            let part = Bytes::from(self.buffer.drain(..take).collect::<Vec<u8>>());
            let number = (upload.etags.len() + upload.in_flight.len() + 1) as u32;
            let (target, name, id) = (self.target.clone(), self.name.clone(), upload.id.clone());
            upload.in_flight.push_back(tokio::spawn(async move {
                target.upload_part(&name, &id, number, part).await
            }));
        }
        if all && let Some(upload) = &mut self.upload {
            while !upload.in_flight.is_empty() {
                upload.settle_one().await?;
            }
        }
        Ok(())
    }

    /// Seals the last segment and stores the object; its plaintext size. A
    /// failure leaves no upload behind (as far as aborting it works).
    pub async fn finish(mut self) -> anyhow::Result<u64> {
        let (last, plain) = self.sealer.take().expect("finished once").finish();
        self.buffer.extend_from_slice(&last);
        let result = async {
            if self.upload.is_none() {
                self.target
                    .put(&self.name, Bytes::from(std::mem::take(&mut self.buffer)))
                    .await
            } else {
                self.flush(true).await?;
                let upload = self.upload.as_ref().unwrap();
                self.target
                    .complete_upload(&self.name, &upload.id, &upload.etags)
                    .await
            }
        }
        .await;
        if let Err(e) = result {
            self.abort().await;
            return Err(e);
        }
        self.upload = None;
        Ok(plain)
    }

    /// Gives the object up.
    pub async fn abort(&mut self) {
        if let Some(upload) = self.upload.take() {
            for part in &upload.in_flight {
                part.abort();
            }
            self.target.abort_upload(&self.name, &upload.id).await;
        }
    }
}

/// Reads plaintext ranges of an object, `plain` bytes long.
pub struct ObjectReader<'a> {
    pub target: &'a Target,
    pub key: Key,
    pub name: &'a str,
    pub plain: u64,
}

impl<'a> ObjectReader<'a> {
    pub fn new(
        target: &'a Target,
        backup_key: &Key,
        name: &'a str,
        plain: u64,
    ) -> ObjectReader<'a> {
        ObjectReader {
            target,
            key: object_key(backup_key, name),
            name,
            plain,
        }
    }

    /// The object's salt, from its header (read once, for the reads of a
    /// restore, which come a range at a time).
    async fn salt(&self) -> anyhow::Result<Salt> {
        static SALTS: std::sync::Mutex<Option<std::collections::HashMap<String, Salt>>> =
            std::sync::Mutex::new(None);
        let location = &self.target.location;
        let id = format!(
            "{}/{}/{}{}",
            location.endpoint, location.bucket, location.prefix, self.name
        );
        if let Some(salt) = SALTS
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|salts| salts.get(&id))
        {
            return Ok(*salt);
        }
        let header = self.target.get_range(self.name, 0, HEADER).await?;
        anyhow::ensure!(
            &header[..8] == MAGIC,
            "{} isn't an object of a backup",
            self.name
        );
        let salt: Salt = header[8..].try_into().expect("16 bytes");
        let mut salts = SALTS.lock().unwrap();
        let salts = salts.get_or_insert_with(Default::default);
        if salts.len() >= 100_000 {
            salts.clear();
        }
        salts.insert(id, salt);
        Ok(salt)
    }

    /// The plaintext [`start`, `end`), to be read in calls of up to
    /// `chunk` stored bytes. Reading fails if any of it doesn't open: the
    /// wrong key, or bytes damaged or altered.
    pub async fn range(&self, start: u64, end: u64, chunk: u64) -> anyhow::Result<Range<'_>> {
        anyhow::ensure!(
            end <= self.plain && start <= end,
            "bytes {start}-{end} of {} are past its end",
            self.name
        );
        // Whole segments a call.
        let chunk = (chunk / encryption::STORED_SEGMENT).max(1) * encryption::STORED_SEGMENT;
        if start == end {
            let opener = Opener::new(&self.key, [0; encryption::SALT_LEN], self.plain, 0);
            return Ok(Range {
                reader: self,
                opener,
                skip: 0,
                left: 0,
                at: 0,
                stop: 0,
                chunk,
            });
        }
        let range = encryption::segment_range(self.plain, start, end);
        let salt = self.salt().await?;
        Ok(Range {
            reader: self,
            opener: Opener::new(&self.key, salt, self.plain, range.first),
            skip: range.skip as usize,
            left: (end - start) as usize,
            at: range.stored_start,
            stop: range.stored_end,
            chunk,
        })
    }

    /// The plaintext [`start`, `end`), handed to `each` a piece at a time.
    pub async fn read<F>(&self, start: u64, end: u64, chunk: u64, mut each: F) -> anyhow::Result<()>
    where
        F: AsyncFnMut(Bytes) -> anyhow::Result<()>,
    {
        let mut range = self.range(start, end, chunk).await?;
        while let Some(pieces) = range.next().await? {
            for piece in pieces {
                each(piece).await?;
            }
        }
        Ok(())
    }

    /// The plaintext [`start`, `end`), whole.
    pub async fn read_all(&self, start: u64, end: u64) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::with_capacity((end - start) as usize);
        self.read(start, end, 64 << 20, async |data: Bytes| {
            out.extend_from_slice(&data);
            Ok(())
        })
        .await?;
        Ok(out)
    }
}

/// A range of an object being read.
pub struct Range<'a> {
    reader: &'a ObjectReader<'a>,
    opener: Opener,
    skip: usize,
    left: usize,
    /// The stored bytes still to read.
    at: u64,
    stop: u64,
    chunk: u64,
}

impl Range<'_> {
    /// The next pieces of plaintext, `None` at the end.
    pub async fn next(&mut self) -> anyhow::Result<Option<Vec<Bytes>>> {
        let name = self.reader.name;
        if self.at >= self.stop {
            anyhow::ensure!(self.left == 0, "{name} ended early");
            return Ok(None);
        }
        let to = (self.at + self.chunk).min(self.stop);
        let stored = self
            .reader
            .target
            .get_range(name, HEADER + self.at, HEADER + to)
            .await?;
        self.at = to;
        let opened = self
            .opener
            .update(&stored)
            .map_err(|e| anyhow::anyhow!("{name}: {e} (the wrong key, or damaged)"))?;
        let mut out = Vec::new();
        for mut plain in opened {
            let skipped = self.skip.min(plain.len());
            plain = plain.slice(skipped..);
            self.skip -= skipped;
            let take = self.left.min(plain.len());
            if take > 0 {
                self.left -= take;
                out.push(plain.slice(..take));
            }
        }
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_and_stored_lengths_invert() {
        for plain in [0, 1, 65535, 65536, 65537, 131072, 1 << 20, 5 * 65536 + 3] {
            assert_eq!(plain_len(stored_len(plain)), Some(plain), "{plain}");
        }
        assert_eq!(plain_len(10), None);
        assert_eq!(plain_len(HEADER + 15), None);
    }

    #[test]
    fn objects_have_keys_of_their_own() {
        let key = [3; 32];
        assert_ne!(object_key(&key, "journal/1"), object_key(&key, "journal/2"));
        assert_ne!(
            object_key(&key, "journal/1"),
            object_key(&[4; 32], "journal/1")
        );
    }
}
