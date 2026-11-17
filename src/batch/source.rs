//! Where a job's tasks come from: the lines of its manifest, read a page at
//! a time from where the job has got to (a `Position`).
//!
//! - A CSV manifest (`S3BatchOperations_CSV_20180820`) is one object, read
//!   by byte ranges, pinned to the ETag CreateJob gave (If-Match).
//! - An inventory report (`S3InventoryReport_CSV_20161130`) is its
//!   `manifest.json`, pinned the same way, which lists its data files:
//!   gzipped CSV, whose columns its `fileSchema` names. Preparing the job
//!   reads each data file whole, checks it against the MD5 the manifest
//!   gives, and records its ETag (`batch_jobs.inventory`); running it reads
//!   each pinned to that ETag. A data file is decompressed as it's read, so
//!   memory stays bounded however large it is; a position is an offset in
//!   its decompressed lines, so a turn that starts in the middle of a file
//!   decompresses it from its start to there, and goes on.
//!
//! Only CSV inventory reports, as the format's name says: one in Parquet or
//! ORC fails the job while it's prepared.

use std::{io::Write, sync::Arc};

use flate2::write::GzDecoder;
use http_body_util::BodyExt;
use hyper::{HeaderMap, StatusCode, body::Bytes, header};
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{CHUNK, Failure, Manifest, manifest, manifest::Field, may_read};
use crate::{
    App,
    body::ResBody,
    users::Principal,
    s3::{conditional::Preconditions, objects::get::get_object},
};

/// The most of an inventory report's `manifest.json` that's read.
const MAX_INVENTORY_MANIFEST: u64 = 16 << 20;

/// Where a job has got to in its manifest: a data file (an inventory
/// report's, by its index; 0 for a CSV manifest), and an offset in it
/// (bytes; of its decompressed lines, for a data file).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Position {
    pub file: i32,
    pub offset: u64,
}

/// An inventory report, as a job reads it: its lines' columns, and its
/// data files, as its manifest lists them.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Inventory {
    pub fields: Vec<String>,
    pub files: Vec<DataFile>,
}

impl Inventory {
    pub fn fields(&self) -> Vec<Field> {
        self.fields.iter().filter_map(|f| Field::parse(f)).collect()
    }
}

/// A data file of an inventory report.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DataFile {
    pub bucket: String,
    pub key: String,
    /// Its MD5 (hex), as the manifest gives it.
    pub md5: String,
    /// Its ETag, once preparing the job has read it.
    pub etag: Option<String>,
}

/// An inventory report's `manifest.json`, as S3 (and Cairn, see
/// `inventory`) writes it: what a job needs of it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InventoryManifest {
    destination_bucket: String,
    file_format: String,
    file_schema: String,
    files: Vec<InventoryFile>,
}

#[derive(Deserialize)]
struct InventoryFile {
    key: String,
    #[serde(rename = "MD5checksum")]
    md5: String,
}

/// The inventory report a job's manifest (its `manifest.json`) is, read as
/// the role `role`; why it can't be a job's manifest, if it can't.
pub async fn read_inventory(app: &Arc<App>, manifest: &Manifest, role: Uuid) -> anyhow::Result<Result<Inventory, Failure>> {
    let invalid = |why: String| Ok(Err(Failure::new("ManifestInvalid", format!("The inventory report {} {why}.", manifest.arn))));
    let mut data = Vec::new();
    let mut from = 0;
    loop {
        let chunk = match read(app, manifest, role, from).await? {
            Ok(chunk) => chunk,
            Err(failure) => return Ok(Err(failure)),
        };
        data.extend_from_slice(&chunk.data);
        from += chunk.data.len() as u64;
        if chunk.last {
            break;
        }
        if from > MAX_INVENTORY_MANIFEST {
            return invalid("is larger than 16 MiB".to_owned());
        }
    }
    let parsed: InventoryManifest = match serde_json::from_slice(&data) {
        Ok(parsed) => parsed,
        Err(e) => return invalid(format!("isn't an inventory report's manifest ({e})")),
    };
    if parsed.file_format != "CSV" {
        return invalid(format!("is in {}, not CSV", parsed.file_format));
    }
    let fields: Vec<Field> = parsed
        .file_schema
        .split(',')
        .map(|name| Field::parse(name.trim()).filter(|f| *f != Field::Ignore).unwrap_or(Field::Ignore))
        .collect();
    if let Err(why) = manifest::check_fields(&fields) {
        return invalid(format!("has a schema without its objects' buckets and keys ({why})"));
    }
    let Some(bucket) = parsed.destination_bucket.strip_prefix("arn:aws:s3:::").filter(|b| !b.is_empty()) else {
        return invalid(format!("names no bucket of its files ({})", parsed.destination_bucket));
    };
    let files = parsed
        .files
        .into_iter()
        .map(|f| DataFile { bucket: bucket.to_owned(), key: f.key, md5: f.md5.to_ascii_lowercase(), etag: None })
        .collect();
    Ok(Ok(Inventory { fields: fields.iter().map(|f| f.name().to_owned()).collect(), files }))
}

/// Some of a manifest, read from an offset.
pub struct Chunk {
    pub data: Bytes,
    /// Whether it's the rest of the manifest.
    pub last: bool,
}

/// Reads up to `CHUNK` bytes of the manifest from `from`, as long as it's
/// still the one of its ETag (as the role `role` asks the KMS for its key,
/// if it's SSE-KMS); why it can't be, if it can't.
pub async fn read(app: &Arc<App>, manifest: &Manifest, role: Uuid, from: u64) -> anyhow::Result<Result<Chunk, Failure>> {
    let range = format!("bytes={from}-{}", from + CHUNK - 1);
    let object = Object { bucket: &manifest.bucket, key: &manifest.key, version_id: manifest.version_id.as_deref(), arn: &manifest.arn };
    let response = match get(app, &object, &manifest.etag, Some(&range), role).await? {
        Ok(response) => response,
        // Past its end: there's no more.
        Err(None) => return Ok(Ok(Chunk { data: Bytes::new(), last: true })),
        Err(Some(failure)) => return Ok(Err(failure)),
    };
    let status = response.status();
    // Its size, from `Content-Range` (`bytes a-b/size`).
    let size = response
        .headers()
        .get(header::CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit_once('/'))
        .and_then(|(_, size)| size.parse::<u64>().ok());
    let data = response.into_body().collect().await.map_err(|e| anyhow::anyhow!("reading the manifest: {e}"))?.to_bytes();
    let last = match size {
        Some(size) => from + data.len() as u64 >= size,
        // The whole of it.
        None => status == StatusCode::OK,
    };
    Ok(Ok(Chunk { data, last }))
}

/// An object a job reads.
struct Object<'a> {
    bucket: &'a str,
    key: &'a str,
    version_id: Option<&'a str>,
    /// How failures name it.
    arn: &'a str,
}

/// GETs `object` (`range` of it), as long as its ETag is `etag` (none:
/// whatever it is); why not, if it can't be read (`None`: the range is past
/// its end).
async fn get(
    app: &Arc<App>,
    object: &Object<'_>,
    etag: &str,
    range: Option<&str>,
    role: Uuid,
) -> anyhow::Result<Result<hyper::Response<ResBody>, Option<Failure>>> {
    let mut headers = HeaderMap::new();
    if !etag.is_empty() {
        headers.insert(header::IF_MATCH, format!("\"{}\"", etag.trim_matches('"')).parse()?);
    }
    let preconditions = Preconditions::from_headers(&headers);
    let response =
        get_object(app, object.bucket, object.key, object.version_id, range, None, &preconditions, None, Some(role), false).await?;
    let status = response.status();
    let unreadable = |why: String| Failure::new("ManifestUnreadable", format!("Reading {} failed: {why}.", object.arn));
    match status {
        StatusCode::OK | StatusCode::PARTIAL_CONTENT => Ok(Ok(response)),
        StatusCode::RANGE_NOT_SATISFIABLE => Ok(Err(None)),
        StatusCode::PRECONDITION_FAILED => Ok(Err(Some(Failure::new(
            "ManifestETagMismatch",
            format!("{} isn't the one of ETag {} any more.", object.arn, etag),
        )))),
        _ => {
            let body = response.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
            let body = String::from_utf8_lossy(&body);
            let code = body.split("<Code>").nth(1).and_then(|s| s.split("</Code>").next()).unwrap_or("");
            Ok(Err(Some(unreadable(format!("{} {code}", status.as_u16())))))
        }
    }
}

/// A data file's lines, as they're read and decompressed.
pub struct DataLines {
    body: ResBody,
    decoder: GzDecoder<Vec<u8>>,
    /// Decompressed bytes not yet taken as lines, from `taken` on.
    pending: Vec<u8>,
    taken: usize,
    /// The offset (decompressed) of the next line.
    pub offset: u64,
    ended: bool,
    /// The MD5 of what's been read (compressed), and how much.
    md5: Md5,
    pub size: u64,
    /// The file's ETag, as its GET told it.
    pub etag: String,
    arn: String,
}

impl DataLines {
    /// Opens data file `file` of the inventory, as the role session
    /// `principal`, which must be allowed to read it, pinned to its ETag if
    /// preparing recorded one.
    pub async fn open(app: &Arc<App>, file: &DataFile, principal: &Principal) -> anyhow::Result<Result<DataLines, Failure>> {
        let arn = format!("arn:aws:s3:::{}/{}", file.bucket, file.key);
        if let Err(failure) = may_read(app, principal, &file.bucket, &file.key, None, &arn).await? {
            return Ok(Err(failure));
        }
        let role = principal.id;
        let object = Object { bucket: &file.bucket, key: &file.key, version_id: None, arn: &arn };
        let response = match get(app, &object, file.etag.as_deref().unwrap_or(""), None, role).await? {
            Ok(response) => response,
            Err(failure) => {
                let failure = failure.unwrap_or_else(|| Failure::new("ManifestUnreadable", format!("Reading {arn} failed.")));
                return Ok(Err(failure));
            }
        };
        let etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .trim_matches('"')
            .to_owned();
        Ok(Ok(DataLines {
            body: response.into_body(),
            decoder: GzDecoder::new(Vec::new()),
            pending: Vec::new(),
            taken: 0,
            offset: 0,
            ended: false,
            md5: Md5::new(),
            size: 0,
            etag,
            arn,
        }))
    }

    /// The next line (without its line ending), or `None` at the file's end;
    /// why the file isn't one, if it isn't.
    pub async fn line(&mut self) -> anyhow::Result<Result<Option<Vec<u8>>, Failure>> {
        let invalid = |arn: &str, why: &str| Failure::new("ManifestInvalid", format!("The data file {arn} {why}."));
        loop {
            let rest = &self.pending[self.taken..];
            if let Some(end) = rest.iter().position(|&b| b == b'\n') {
                let line = rest[..end].strip_suffix(b"\r").unwrap_or(&rest[..end]).to_vec();
                self.taken += end + 1;
                self.offset += end as u64 + 1;
                return Ok(Ok(Some(line)));
            }
            if self.ended {
                if rest.is_empty() {
                    return Ok(Ok(None));
                }
                let line = rest.strip_suffix(b"\r").unwrap_or(rest).to_vec();
                self.offset += rest.len() as u64;
                self.taken = self.pending.len();
                return Ok(Ok(Some(line)));
            }
            if rest.len() as u64 > CHUNK {
                return Ok(Err(invalid(&self.arn, "has a line longer than 1 MiB")));
            }
            // More of it, decompressed.
            self.pending.drain(..self.taken);
            self.taken = 0;
            match self.body.frame().await {
                Some(frame) => {
                    let frame = frame.map_err(|e| anyhow::anyhow!("reading {}: {e}", self.arn))?;
                    let Ok(data) = frame.into_data() else { continue };
                    self.md5.update(&data);
                    self.size += data.len() as u64;
                    if self.decoder.write_all(&data).is_err() {
                        return Ok(Err(invalid(&self.arn, "isn't gzipped")));
                    }
                }
                None => {
                    if self.decoder.try_finish().is_err() {
                        return Ok(Err(invalid(&self.arn, "is cut short")));
                    }
                    self.ended = true;
                }
            }
            self.pending.append(self.decoder.get_mut());
        }
    }

    /// Skips lines up to `offset` (a line's start).
    pub async fn skip_to(&mut self, offset: u64) -> anyhow::Result<Result<(), Failure>> {
        while self.offset < offset {
            match self.line().await? {
                Ok(Some(_)) => {}
                Ok(None) => {
                    let failure = Failure::new("ManifestInvalid", format!("The data file {} is shorter than it was.", self.arn));
                    return Ok(Err(failure));
                }
                Err(failure) => return Ok(Err(failure)),
            }
        }
        Ok(Ok(()))
    }

    /// The MD5 (hex) of all it read, compressed: the file's, once it's read
    /// to its end.
    pub fn md5(&self) -> String {
        self.md5.clone().finalize().iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// A page of a manifest's lines.
pub struct Page {
    pub lines: Vec<Vec<u8>>,
    /// Where the page ends: where the next one starts.
    pub end: Position,
    /// Whether it's the manifest's last.
    pub finished: bool,
}

/// A job's manifest, read a page at a time.
pub enum Source<'a> {
    Csv(&'a Manifest),
    /// An inventory report's data files, and the one being read, if one is.
    Inventory(&'a Inventory, Option<(i32, Box<DataLines>)>),
}

impl Source<'_> {
    /// The page of up to `limit` lines at `at`, as the role session
    /// `principal` reads it: a page ends at its data file's end.
    pub async fn page(
        &mut self,
        app: &Arc<App>,
        principal: &Principal,
        at: Position,
        limit: usize,
    ) -> anyhow::Result<Result<Page, Failure>> {
        let role = principal.id;
        match self {
            Source::Csv(manifest) => {
                let chunk = match read(app, manifest, role, at.offset).await? {
                    Ok(chunk) => chunk,
                    Err(failure) => return Ok(Err(failure)),
                };
                let (lines, consumed) = manifest::lines(&chunk.data, chunk.last, limit);
                let finished = chunk.last && consumed == chunk.data.len();
                if lines.is_empty() && !finished {
                    return Ok(Err(Failure::new("ManifestInvalid", "A line of the manifest is too long.")));
                }
                let lines = lines.into_iter().map(<[u8]>::to_vec).collect();
                Ok(Ok(Page { lines, end: Position { file: 0, offset: at.offset + consumed as u64 }, finished }))
            }
            Source::Inventory(inventory, open) => {
                let count = inventory.files.len() as i32;
                if at.file >= count {
                    return Ok(Ok(Page { lines: Vec::new(), end: at, finished: true }));
                }
                // The data file at `at`, open there.
                if !matches!(open, Some((file, lines)) if *file == at.file && lines.offset == at.offset) {
                    let mut lines = match DataLines::open(app, &inventory.files[at.file as usize], principal).await? {
                        Ok(lines) => lines,
                        Err(failure) => return Ok(Err(failure)),
                    };
                    if let Err(failure) = lines.skip_to(at.offset).await? {
                        return Ok(Err(failure));
                    }
                    *open = Some((at.file, Box::new(lines)));
                }
                let (_, data) = open.as_mut().expect("just opened");
                let mut page = Vec::new();
                while page.len() < limit {
                    match data.line().await? {
                        Ok(Some(line)) => page.push(line),
                        Ok(None) => {
                            *open = None;
                            let end = Position { file: at.file + 1, offset: 0 };
                            return Ok(Ok(Page { lines: page, end, finished: end.file >= count }));
                        }
                        Err(failure) => return Ok(Err(failure)),
                    }
                }
                Ok(Ok(Page { lines: page, end: Position { file: at.file, offset: data.offset }, finished: false }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_manifests_are_parsed() {
        let json = r#"{"sourceBucket":"photos","destinationBucket":"arn:aws:s3:::reports","version":"2016-11-30",
            "creationTimestamp":"1","fileFormat":"CSV","fileSchema":"Bucket, Key, VersionId, IsLatest, Size",
            "files":[{"key":"inv/photos/a/data/1.csv.gz","size":10,"MD5checksum":"ABC"}]}"#;
        let parsed: InventoryManifest = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.destination_bucket, "arn:aws:s3:::reports");
        assert_eq!(parsed.files[0].md5, "ABC");
        assert_eq!(parsed.file_schema.split(',').count(), 5);
    }
}
