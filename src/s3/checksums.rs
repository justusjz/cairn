//! S3's checksums of objects and parts (`x-amz-checksum-*`), as clients see
//! them: computed over the plaintext, in an algorithm of the client's choice,
//! or CRC64/NVME by default, as S3 does. (`checksum` is about Cairn's own,
//! over what it stores.)
//!
//! An object's checksum is of one of two types:
//!
//! - FULL_OBJECT: of the whole object's data. A single PUT's always is. A
//!   multipart object's can be, for the CRCs: it's combined from its parts'
//!   CRCs and sizes (`combine`), without reading the data again.
//! - COMPOSITE: a multipart object's, the same algorithm over its parts'
//!   checksums, as raw bytes, in order (`composite`), reported with `-N`
//!   for the number of parts, like a multipart ETag. Not for CRC64/NVME.
//!
//! The values are kept as they're reported (base64, with any `-N`). An
//! encrypted object's (and its parts') would let whoever holds the catalog
//! test guesses at the plaintext, so they're stored sealed under a key of the
//! object's (`ChecksumKey`), as SSE-S3 ETags are; algorithm and type aren't.

use base64::{Engine, engine::general_purpose::STANDARD};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::encryption::Key;

/// The algorithms of S3's `x-amz-checksum-*` headers and trailers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Crc32,
    Crc32c,
    Crc64Nvme,
    Sha1,
    Sha256,
}

impl Algorithm {
    pub const ALL: [Algorithm; 5] = [
        Algorithm::Crc32,
        Algorithm::Crc32c,
        Algorithm::Crc64Nvme,
        Algorithm::Sha1,
        Algorithm::Sha256,
    ];

    /// The header (or trailer) that carries it.
    pub fn header(self) -> &'static str {
        match self {
            Algorithm::Crc32 => "x-amz-checksum-crc32",
            Algorithm::Crc32c => "x-amz-checksum-crc32c",
            Algorithm::Crc64Nvme => "x-amz-checksum-crc64nvme",
            Algorithm::Sha1 => "x-amz-checksum-sha1",
            Algorithm::Sha256 => "x-amz-checksum-sha256",
        }
    }

    pub fn from_header(name: &str) -> Option<Algorithm> {
        Algorithm::ALL.into_iter().find(|a| a.header().eq_ignore_ascii_case(name.trim()))
    }

    /// Its name, as S3's headers, XML and error messages give it.
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Crc32 => "CRC32",
            Algorithm::Crc32c => "CRC32C",
            Algorithm::Crc64Nvme => "CRC64NVME",
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
        }
    }

    /// The algorithm a name (`x-amz-checksum-algorithm`, and the catalog's)
    /// gives, in any case, as MinIO takes it.
    pub fn from_name(name: &str) -> Option<Algorithm> {
        Algorithm::ALL.into_iter().find(|a| a.name().eq_ignore_ascii_case(name.trim()))
    }

    /// The XML element that carries a value of it (`ChecksumCRC32`, ...).
    pub fn element(self) -> String {
        format!("Checksum{}", self.name())
    }

    /// How many bytes a checksum has.
    pub fn len(self) -> usize {
        match self {
            Algorithm::Crc32 | Algorithm::Crc32c => 4,
            Algorithm::Crc64Nvme => 8,
            Algorithm::Sha1 => 20,
            Algorithm::Sha256 => 32,
        }
    }

    /// The checksum a base64 `value` names, if it's a valid one.
    pub fn decode(self, value: &str) -> Option<Vec<u8>> {
        STANDARD.decode(value.trim()).ok().filter(|bytes| bytes.len() == self.len())
    }

    /// Whether checksums of pieces combine into the whole's (`combine`):
    /// the CRCs'.
    pub fn combines(self) -> bool {
        self.crc().is_some()
    }

    /// The reflected polynomial and width of a CRC.
    fn crc(self) -> Option<(u64, u32)> {
        match self {
            Algorithm::Crc32 => Some((0xedb8_8320, 32)),
            Algorithm::Crc32c => Some((0x82f6_3b78, 32)),
            Algorithm::Crc64Nvme => Some((0x9a6c_9329_ac4b_c9b5, 64)),
            Algorithm::Sha1 | Algorithm::Sha256 => None,
        }
    }
}

/// The type of an object's checksum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type {
    FullObject,
    Composite,
}

impl Type {
    pub fn name(self) -> &'static str {
        match self {
            Type::FullObject => "FULL_OBJECT",
            Type::Composite => "COMPOSITE",
        }
    }

    pub fn from_name(name: &str) -> Option<Type> {
        [Type::FullObject, Type::Composite].into_iter().find(|t| t.name().eq_ignore_ascii_case(name.trim()))
    }
}

/// The request header asking for checksums on a read.
pub const MODE: &str = "x-amz-checksum-mode";
/// The headers naming an upload's algorithm and type (CreateMultipartUpload,
/// and CopyObject's algorithm), and a checksum's type (on responses, and
/// CompleteMultipartUpload's).
pub const ALGORITHM: &str = "x-amz-checksum-algorithm";
pub const TYPE: &str = "x-amz-checksum-type";
/// The header an SDK names the algorithm of an upload's checksum with.
pub const SDK_ALGORITHM: &str = "x-amz-sdk-checksum-algorithm";

/// A checksum being computed.
pub enum Hasher {
    Crc32(crc32fast::Hasher),
    Crc32c(u32),
    Crc64Nvme(crc64fast_nvme::Digest),
    Sha1(Sha1),
    Sha256(Sha256),
}

impl Hasher {
    pub fn new(algorithm: Algorithm) -> Hasher {
        match algorithm {
            Algorithm::Crc32 => Hasher::Crc32(crc32fast::Hasher::new()),
            Algorithm::Crc32c => Hasher::Crc32c(0),
            Algorithm::Crc64Nvme => Hasher::Crc64Nvme(crc64fast_nvme::Digest::new()),
            Algorithm::Sha1 => Hasher::Sha1(Sha1::new()),
            Algorithm::Sha256 => Hasher::Sha256(Sha256::new()),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Crc32(h) => h.update(data),
            Hasher::Crc32c(crc) => *crc = crc32c::crc32c_append(*crc, data),
            Hasher::Crc64Nvme(h) => h.write(data),
            Hasher::Sha1(h) => h.update(data),
            Hasher::Sha256(h) => h.update(data),
        }
    }

    /// The checksum's bytes, big-endian for the CRCs, as S3 encodes them.
    pub fn finish(self) -> Vec<u8> {
        match self {
            Hasher::Crc32(h) => h.finalize().to_be_bytes().to_vec(),
            Hasher::Crc32c(crc) => crc.to_be_bytes().to_vec(),
            Hasher::Crc64Nvme(h) => h.sum64().to_be_bytes().to_vec(),
            Hasher::Sha1(h) => h.finalize().to_vec(),
            Hasher::Sha256(h) => h.finalize().to_vec(),
        }
    }
}

/// The `algorithm` checksum of `data`.
pub fn digest(algorithm: Algorithm, data: &[u8]) -> Vec<u8> {
    let mut hasher = Hasher::new(algorithm);
    hasher.update(data);
    hasher.finish()
}

/// A checksum as it's reported: base64.
pub fn encode(raw: &[u8]) -> String {
    STANDARD.encode(raw)
}

/// The checksum of two pieces of data, one after the other, from theirs
/// (`first`, `second`, raw) and the second's length: for the CRCs (see
/// `Algorithm::combines`), as zlib's `crc32_combine`. Every CRC here starts
/// from all ones and is inverted at the end, which this relies on.
pub fn combine(algorithm: Algorithm, first: &[u8], second: &[u8], second_len: u64) -> Vec<u8> {
    let (poly, width) = algorithm.crc().expect("only CRCs combine");
    let bytes = (width / 8) as usize;
    let read = |raw: &[u8]| raw.iter().fold(0u64, |acc, b| acc << 8 | *b as u64);
    let combined = crc_combine(read(first), read(second), second_len, poly, width);
    combined.to_be_bytes()[8 - bytes..].to_vec()
}

/// zlib's `crc32_combine`, for a reflected CRC of any width up to 64: appends
/// `len2` zero bytes to `crc1` (by squaring the matrix of one zero bit), then
/// adds `crc2`.
fn crc_combine(mut crc1: u64, crc2: u64, mut len2: u64, poly: u64, width: u32) -> u64 {
    if len2 == 0 {
        return crc1;
    }
    let width = width as usize;
    let times = |mat: &[u64], mut vec: u64| {
        let mut sum = 0;
        let mut i = 0;
        while vec != 0 {
            if vec & 1 == 1 {
                sum ^= mat[i];
            }
            vec >>= 1;
            i += 1;
        }
        sum
    };
    let square = |mat: &[u64]| (0..width).map(|n| times(mat, mat[n])).collect::<Vec<u64>>();
    // The operator for one zero bit, then two, then four.
    let mut odd = vec![0u64; width];
    odd[0] = poly;
    for (n, row) in odd.iter_mut().enumerate().skip(1) {
        *row = 1 << (n - 1);
    }
    let mut even = square(&odd);
    odd = square(&even);
    // Then for each bit of len2's bytes, a byte (eight bits) on.
    loop {
        even = square(&odd);
        if len2 & 1 == 1 {
            crc1 = times(&even, crc1);
        }
        len2 >>= 1;
        if len2 == 0 {
            break;
        }
        odd = square(&even);
        if len2 & 1 == 1 {
            crc1 = times(&odd, crc1);
        }
        len2 >>= 1;
        if len2 == 0 {
            break;
        }
    }
    crc1 ^ crc2
}

/// A FULL_OBJECT checksum of pieces, from theirs (raw) and their lengths, in
/// order: for the CRCs.
pub fn combine_all<'a>(algorithm: Algorithm, pieces: impl IntoIterator<Item = (&'a [u8], u64)>) -> Vec<u8> {
    pieces
        .into_iter()
        .fold(digest(algorithm, b""), |acc, (raw, len)| combine(algorithm, &acc, raw, len))
}

/// A COMPOSITE checksum of `parts` (raw, in order), as it's reported: the
/// algorithm over their bytes, with `-N`.
pub fn composite(algorithm: Algorithm, parts: &[Vec<u8>]) -> String {
    format!("{}-{}", encode(&digest(algorithm, &parts.concat())), parts.len())
}

/// MinIO's 400 for a checksum header (or algorithm, or type) it can't take.
pub fn invalid() -> hyper::Response<http_body_util::Full<hyper::body::Bytes>> {
    crate::s3::util::format_s3_error(hyper::StatusCode::BAD_REQUEST, "InvalidArgument", "Invalid checksum provided.")
}

/// Checks a PutObject's `x-amz-checksum-type`, as MinIO does (S3 documents
/// none): FULL_OBJECT only with a CRC, COMPOSITE taken and ignored, and
/// nothing else. `sent` is the algorithm of the checksum the body comes with.
pub fn check_put_type(
    headers: &hyper::HeaderMap,
    sent: Option<Algorithm>,
) -> Result<(), hyper::Response<http_body_util::Full<hyper::body::Bytes>>> {
    let Some(value) = headers.get(TYPE) else { return Ok(()) };
    match value.to_str().ok().and_then(Type::from_name) {
        Some(Type::Composite) => Ok(()),
        Some(Type::FullObject) if sent.is_none_or(Algorithm::combines) => Ok(()),
        _ => Err(invalid()),
    }
}

/// What a CreateMultipartUpload asks for (`x-amz-checksum-algorithm`,
/// `x-amz-checksum-type`), as MinIO takes it (S3 documents only that
/// CRC64NVME is always FULL_OBJECT): an algorithm's type defaults to
/// COMPOSITE, but CRC64NVME's, which is always FULL_OBJECT; the SHAs can't
/// be FULL_OBJECT; a type without an algorithm is no checksum, unless it's
/// FULL_OBJECT, which needs one. `None` for no checksum.
pub fn requested_upload(
    headers: &hyper::HeaderMap,
) -> Result<Option<(Algorithm, Type)>, hyper::Response<http_body_util::Full<hyper::body::Bytes>>> {
    let header = |name| headers.get(name).map(|v| v.to_str().unwrap_or("\u{0}"));
    let kind = match header(TYPE) {
        None => None,
        Some(value) => Some(Type::from_name(value).ok_or_else(invalid)?),
    };
    let Some(algorithm) = header(ALGORITHM) else {
        return match kind {
            Some(Type::FullObject) => Err(invalid()),
            _ => Ok(None),
        };
    };
    let algorithm = Algorithm::from_name(algorithm).ok_or_else(invalid)?;
    let kind = match (algorithm, kind) {
        (Algorithm::Crc64Nvme, _) => Type::FullObject,
        (Algorithm::Sha1 | Algorithm::Sha256, Some(Type::FullObject)) => return Err(invalid()),
        (_, kind) => kind.unwrap_or(Type::Composite),
    };
    Ok(Some((algorithm, kind)))
}

/// A checksum claimed: its algorithm, its value, and its type, if named.
pub type Claim = (Algorithm, String, Option<Type>);

/// A checksum a CompleteMultipartUpload claims for its object: the
/// `x-amz-checksum-*` header (only one), and `x-amz-checksum-type`, if it
/// names one. `Err` if one's malformed.
pub fn claimed(
    headers: &hyper::HeaderMap,
) -> Result<Option<Claim>, hyper::Response<http_body_util::Full<hyper::body::Bytes>>> {
    let mut declared = Algorithm::ALL.into_iter().filter(|a| headers.contains_key(a.header()));
    let Some(algorithm) = declared.next() else { return Ok(None) };
    if declared.next().is_some() {
        return Err(invalid());
    }
    let value = headers[algorithm.header()].to_str().map_err(|_| invalid())?.trim().to_owned();
    let kind = match headers.get(TYPE) {
        None => None,
        Some(kind) => Some(kind.to_str().ok().and_then(Type::from_name).ok_or_else(invalid)?),
    };
    Ok(Some((algorithm, value, kind)))
}

/// Whether a claimed value (perhaps without its `-N`) is `checksum`'s.
pub fn matches(checksum: &Checksum, claimed: &str) -> bool {
    match (checksum.value.split_once('-'), claimed.contains('-')) {
        (Some((value, _)), false) => value == claimed,
        _ => checksum.value == claimed,
    }
}

/// S3's 400 for a checksum that doesn't match the object's.
pub fn bad_digest(algorithm: Algorithm) -> hyper::Response<http_body_util::Full<hyper::body::Bytes>> {
    crate::s3::util::format_s3_error(
        hyper::StatusCode::BAD_REQUEST,
        "BadDigest",
        &format!("The {} you specified did not match the calculated checksum.", algorithm.name()),
    )
}

/// An object's checksum: what it's of, and its value as it's reported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checksum {
    pub algorithm: Algorithm,
    pub kind: Type,
    pub value: String,
}

impl Checksum {
    /// A FULL_OBJECT checksum of raw bytes.
    pub fn full(algorithm: Algorithm, raw: &[u8]) -> Checksum {
        Checksum { algorithm, kind: Type::FullObject, value: encode(raw) }
    }

    /// The checksum a response tells: its value, and its type.
    pub fn headers(&self, builder: hyper::http::response::Builder) -> hyper::http::response::Builder {
        builder.header(self.algorithm.header(), &self.value).header(TYPE, self.kind.name())
    }

    /// The elements of an XML result that tell it (CompleteMultipartUpload's,
    /// CopyObject's).
    pub fn xml(&self) -> String {
        let element = self.algorithm.element();
        format!("<{element}>{}</{element}><ChecksumType>{}</ChecksumType>", self.value, self.kind.name())
    }
}

/// Which checksum an upload's data is stored with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wanted {
    /// The one the client sent, else one of this algorithm (a single PUT:
    /// CRC64NVME, S3's default).
    ClientsOr(Algorithm),
    /// One of this algorithm: a part of an upload of it (whose client must
    /// send it, which `put_part` sees to), or a copy's.
    Exactly(Algorithm),
    /// None: a part of an SSE-C upload without an algorithm (see `upload`).
    Nothing,
}

impl Wanted {
    /// The algorithm, given which one the client sent.
    pub fn algorithm(self, sent: Option<Algorithm>) -> Option<Algorithm> {
        match self {
            Wanted::ClientsOr(default) => Some(sent.unwrap_or(default)),
            Wanted::Exactly(algorithm) => Some(algorithm),
            Wanted::Nothing => None,
        }
    }
}

/// The elements a listing tells an object's (or upload's) checksum with:
/// its algorithm and type, from a row's two columns, from `first` on.
pub fn listed(row: &tokio_postgres::Row, first: usize) -> String {
    let algorithm: Option<&str> = row.get(first);
    let kind: Option<&str> = row.get(first + 1);
    match algorithm.and_then(Algorithm::from_name).zip(kind.and_then(Type::from_name)) {
        Some((algorithm, kind)) => format!(
            "<ChecksumAlgorithm>{}</ChecksumAlgorithm><ChecksumType>{}</ChecksumType>",
            algorithm.name(),
            kind.name()
        ),
        None => String::new(),
    }
}

/// An object's checksum as the catalog has it: its value perhaps sealed.
#[derive(Clone, Debug)]
pub struct StoredChecksum {
    pub algorithm: Algorithm,
    pub kind: Type,
    /// The value as it's stored.
    pub stored: String,
}

impl StoredChecksum {
    /// From a row's three columns (algorithm, type, value), from `first` on.
    pub fn from_row(row: &tokio_postgres::Row, first: usize) -> Option<StoredChecksum> {
        let algorithm: Option<&str> = row.get(first);
        let kind: Option<&str> = row.get(first + 1);
        Some(StoredChecksum {
            algorithm: Algorithm::from_name(algorithm?)?,
            kind: Type::from_name(kind?)?,
            stored: row.get(first + 2),
        })
    }

    /// The checksum, as clients know it.
    pub fn read(&self, storing: &Storing) -> anyhow::Result<Checksum> {
        Ok(Checksum { algorithm: self.algorithm, kind: self.kind, value: storing.read(&self.stored)? })
    }
}

/// The key an encrypted object's (or upload's) checksums are sealed under,
/// derived from its object key (SSE-C's: the client's) with HKDF.
pub struct ChecksumKey(Zeroizing<Key>);

/// HKDF's info for the checksum key; ETags' differs (see `s3::sse`).
const CHECKSUM_KEY_INFO: &[u8] = b"cairn checksum v1";

impl ChecksumKey {
    pub fn new(object_key: &Key) -> ChecksumKey {
        let mut key = Zeroizing::new([0; 32]);
        hkdf::Hkdf::<sha2::Sha256>::new(None, object_key)
            .expand(CHECKSUM_KEY_INFO, key.as_mut_slice())
            .expect("32 bytes is a valid HKDF output length");
        ChecksumKey(key)
    }

    /// `value`, sealed to store: hex of a fresh nonce, the sealed value, and
    /// the tag, as an SSE-S3 ETag is.
    pub fn seal(&self, value: &str) -> String {
        crate::s3::sse::seal_hex(&self.0, value.as_bytes())
    }

    /// The value `stored` (from `seal` under the same key) holds.
    pub fn open(&self, stored: &str) -> anyhow::Result<String> {
        crate::s3::sse::open_hex(&self.0, stored)
            .and_then(|plain| String::from_utf8(plain).ok())
            .ok_or_else(|| anyhow::anyhow!("a stored checksum doesn't open under its key"))
    }
}

/// How an object's (or upload's) checksums are stored: as they are (plain),
/// or sealed (encrypted, under its `ChecksumKey`).
pub enum Storing<'a> {
    Plain,
    Sealed(&'a ChecksumKey),
}

impl Storing<'_> {
    pub fn store(&self, value: &str) -> String {
        match self {
            Storing::Plain => value.to_owned(),
            Storing::Sealed(key) => key.seal(value),
        }
    }

    pub fn read(&self, stored: &str) -> anyhow::Result<String> {
        match self {
            Storing::Plain => Ok(stored.to_owned()),
            Storing::Sealed(key) => key.open(stored),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_values() {
        // The algorithms' check values, over "123456789".
        let check = |a| encode(&digest(a, b"123456789"));
        assert_eq!(check(Algorithm::Crc32), encode(&0xcbf43926u32.to_be_bytes()));
        assert_eq!(check(Algorithm::Crc32c), encode(&0xe3069283u32.to_be_bytes()));
        assert_eq!(check(Algorithm::Crc64Nvme), encode(&0xae8b14860a799888u64.to_be_bytes()));
    }

    #[test]
    fn crcs_combine() {
        let data: Vec<u8> = (0..100_000u32).map(|i| (i * 7 + i / 13) as u8).collect();
        for algorithm in [Algorithm::Crc32, Algorithm::Crc32c, Algorithm::Crc64Nvme] {
            let whole = digest(algorithm, &data);
            for split in [0, 1, 7, 8, 4096, 65_537, 99_999, 100_000] {
                let (a, b) = data.split_at(split);
                let combined = combine(algorithm, &digest(algorithm, a), &digest(algorithm, b), b.len() as u64);
                assert_eq!(combined, whole, "{algorithm:?} split at {split}");
            }
            let pieces: Vec<(Vec<u8>, u64)> =
                data.chunks(30_000).map(|c| (digest(algorithm, c), c.len() as u64)).collect();
            let all = combine_all(algorithm, pieces.iter().map(|(raw, len)| (raw.as_slice(), *len)));
            assert_eq!(all, whole, "{algorithm:?} in pieces");
        }
    }

    #[test]
    fn composite_checksums() {
        // SHA-256 over the parts' raw checksums, then the count.
        let parts = vec![digest(Algorithm::Sha256, b"a"), digest(Algorithm::Sha256, b"b")];
        let expected = encode(&Sha256::digest([parts[0].clone(), parts[1].clone()].concat()));
        assert_eq!(composite(Algorithm::Sha256, &parts), format!("{expected}-2"));
    }

    #[test]
    fn sealed_values_open() {
        let key = ChecksumKey::new(&[7; 32]);
        let sealed = key.seal("AAAAAA==");
        assert_ne!(sealed, key.seal("AAAAAA=="), "a fresh nonce each time");
        assert_eq!(key.open(&sealed).unwrap(), "AAAAAA==");
        assert!(ChecksumKey::new(&[8; 32]).open(&sealed).is_err());
    }

    fn upload(pairs: &[(&'static str, &str)]) -> Result<Option<(Algorithm, Type)>, u16> {
        let mut headers = hyper::HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(*name, value.parse().unwrap());
        }
        requested_upload(&headers).map_err(|r| r.status().as_u16())
    }

    #[test]
    fn upload_algorithms_and_types() {
        use Algorithm::*;
        use Type::*;
        assert_eq!(upload(&[]), Ok(None));
        assert_eq!(upload(&[(ALGORITHM, "crc32")]), Ok(Some((Crc32, Composite))));
        assert_eq!(upload(&[(ALGORITHM, "CRC32C"), (TYPE, "FULL_OBJECT")]), Ok(Some((Crc32c, FullObject))));
        assert_eq!(upload(&[(ALGORITHM, "CRC64NVME")]), Ok(Some((Crc64Nvme, FullObject))));
        assert_eq!(upload(&[(ALGORITHM, "CRC64NVME"), (TYPE, "COMPOSITE")]), Ok(Some((Crc64Nvme, FullObject))));
        assert_eq!(upload(&[(ALGORITHM, "SHA256")]), Ok(Some((Sha256, Composite))));
        assert_eq!(upload(&[(ALGORITHM, "SHA1"), (TYPE, "FULL_OBJECT")]), Err(400));
        assert_eq!(upload(&[(TYPE, "COMPOSITE")]), Ok(None));
        assert_eq!(upload(&[(TYPE, "FULL_OBJECT")]), Err(400));
        assert_eq!(upload(&[(ALGORITHM, "MD5")]), Err(400));
        assert_eq!(upload(&[(ALGORITHM, "CRC32"), (TYPE, "PARTIAL")]), Err(400));
    }

    #[test]
    fn names() {
        for algorithm in Algorithm::ALL {
            assert_eq!(Algorithm::from_name(&algorithm.name().to_lowercase()), Some(algorithm));
            assert_eq!(Algorithm::from_header(algorithm.header()), Some(algorithm));
        }
        assert_eq!(Type::from_name("composite"), Some(Type::Composite));
        assert_eq!(Algorithm::from_name("MD5"), None);
    }
}
