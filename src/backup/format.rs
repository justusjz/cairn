//! What a backup's objects hold, as plaintext (each is stored encrypted, see
//! `crypt`). Their names say what they are:
//!
//! - `base/<seq>-<id>`: a base snapshot of the database, taken after journal
//!   `<seq>`. A header line (JSON, [`BaseHeader`]), then every table it holds,
//!   one after another, each in `COPY`'s text format and ended by a line
//!   `\.`; all of it gzipped.
//! - `journal/<seq>-<id>`: the changes of a cycle ([`JournalMeta`]), and the
//!   bytes of parts too few to fill a pack, back to back.
//! - `pack/<id>`: the bytes of parts, back to back, about `pack-size` of
//!   them, and an index of them ([`PackMeta`]).
//!
//! A journal and a pack are both data, then their metadata (gzipped JSON),
//! then a trailer: the metadata's length (8 bytes, little-endian) and
//! [`TRAILER_MAGIC`]. A part's bytes are where `backup_parts` says, as an
//! offset from the object's start.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use uuid::Uuid;

/// What a journal's or pack's plaintext ends with.
pub const TRAILER_MAGIC: &[u8; 8] = b"CAIRNMD1";
/// Bytes of the trailer.
pub const TRAILER: u64 = 16;
/// The version of these formats.
pub const FORMAT: u32 = 1;

/// The name of journal `seq`.
pub fn journal_name(seq: i64, id: Uuid) -> String {
    format!("journal/{seq:020}-{id}")
}

/// The name of a base taken after journal `seq`.
pub fn base_name(seq: i64, id: Uuid) -> String {
    format!("base/{seq:020}-{id}")
}

/// The name of a pack.
pub fn pack_name(id: Uuid) -> String {
    format!("pack/{id}")
}

/// The sequence number and ID in a journal's or base's name (after its
/// directory).
pub fn parse_name(name: &str) -> Option<(i64, Uuid)> {
    let (_, rest) = name.split_once('/')?;
    let (seq, id) = rest.split_once('-')?;
    Some((seq.parse().ok()?, Uuid::parse_str(id).ok()?))
}

/// A row change, as `capture` logs it: the transaction's ID, the table,
/// the operation, the row's key and its text.
pub type Change = (u64, String, String, Option<String>, Option<String>);

/// Where a part's bytes are: the part, the object, the offset in it, its
/// size, and its storage class.
pub type PartRef = (i64, Uuid, u64, u64, String);

/// An object of the backup that holds data.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ObjectRef {
    pub id: Uuid,
    pub name: String,
    /// Its plaintext's size.
    pub size: u64,
}

/// A cycle: the changes it shipped, and where the parts it backed up are.
#[derive(Serialize, Deserialize, Debug)]
pub struct JournalMeta {
    pub format: u32,
    pub id: Uuid,
    pub seq: i64,
    /// The journal before it, if any.
    pub prev: Option<Uuid>,
    /// The schema's version, which its changes are rows of.
    pub version: i32,
    /// When it was taken, Unix milliseconds.
    pub time: i64,
    /// The snapshot its changes were read in.
    pub snapshot: String,
    pub changes: Vec<Change>,
    /// The schema's sequences, their values and whether they were drawn.
    pub sequences: Vec<(String, i64, bool)>,
    /// The objects it wrote (its packs, and itself if it holds data).
    pub objects: Vec<ObjectRef>,
    /// Where parts are now: those it backed up, and those it moved.
    pub parts: Vec<PartRef>,
    /// Parts whose bytes it couldn't read, since they were deleted after
    /// its snapshot (their deletion is in a later journal).
    pub unavailable: Vec<i64>,
}

/// What's in a pack.
#[derive(Serialize, Deserialize, Debug)]
pub struct PackMeta {
    pub format: u32,
    pub id: Uuid,
    /// (part, offset, size).
    pub parts: Vec<(i64, u64, u64)>,
}

/// The first line of a base.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BaseHeader {
    pub format: u32,
    pub id: Uuid,
    /// The last journal before it: the journals after `after` follow it.
    pub after: i64,
    pub after_id: Option<Uuid>,
    pub version: i32,
    pub time: i64,
    /// The snapshot it was taken in: a change of a transaction it shows was
    /// in it already.
    pub snapshot: String,
    pub sequences: Vec<(String, i64, bool)>,
    /// The tables that follow, in order, with the columns of their rows.
    /// Two of them are the backup's own: [`OBJECTS`] and [`PARTS`].
    pub tables: Vec<(String, Vec<String>)>,
}

/// The base's table of the objects that hold data: id, name, size.
pub const OBJECTS: &str = "@objects";
/// The base's table of where parts are: part, object, offset, size, class.
pub const PARTS: &str = "@parts";

/// `meta`, gzipped JSON, with the trailer.
pub fn seal_meta<T: Serialize>(meta: &T) -> anyhow::Result<Vec<u8>> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    serde_json::to_writer(&mut gz, meta)?;
    let mut out = gz.finish()?;
    let len = out.len() as u64;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(TRAILER_MAGIC);
    Ok(out)
}

/// The length of the metadata a trailer says comes before it.
pub fn trailer_len(trailer: &[u8]) -> anyhow::Result<u64> {
    anyhow::ensure!(
        trailer.len() == TRAILER as usize && &trailer[8..] == TRAILER_MAGIC,
        "not a journal's or pack's trailer"
    );
    Ok(u64::from_le_bytes(trailer[..8].try_into().unwrap()))
}

/// Metadata, from its gzipped JSON.
pub fn open_meta<T: DeserializeOwned>(gzipped: &[u8]) -> anyhow::Result<T> {
    let mut json = Vec::new();
    flate2::read::GzDecoder::new(gzipped).read_to_end(&mut json)?;
    Ok(serde_json::from_slice(&json)?)
}

/// A gzip stream being written, whose output is taken as it comes.
pub struct Gzip(flate2::write::GzEncoder<Vec<u8>>);

impl Gzip {
    pub fn new() -> Gzip {
        Gzip(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast()))
    }

    /// Compresses `data`; what came out of it so far.
    pub fn write(&mut self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        self.0.write_all(data)?;
        Ok(std::mem::take(self.0.get_mut()))
    }

    /// Ends the stream; the rest of its output.
    pub fn finish(self) -> std::io::Result<Vec<u8>> {
        self.0.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_parse() {
        let id = Uuid::now_v7();
        assert_eq!(parse_name(&journal_name(42, id)), Some((42, id)));
        assert_eq!(parse_name(&base_name(0, id)), Some((0, id)));
        assert!(journal_name(42, id) < journal_name(100, id));
        assert_eq!(parse_name("pack/x"), None);
    }

    #[test]
    fn metadata_round_trips() {
        let meta = PackMeta { format: FORMAT, id: Uuid::nil(), parts: vec![(1, 0, 5), (2, 5, 0)] };
        let sealed = seal_meta(&meta).unwrap();
        let len = trailer_len(&sealed[sealed.len() - 16..]).unwrap() as usize;
        assert_eq!(len, sealed.len() - 16);
        let opened: PackMeta = open_meta(&sealed[..len]).unwrap();
        assert_eq!(opened.parts, meta.parts);
    }
}
