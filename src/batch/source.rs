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
//! - A Parquet inventory report's data files (see `parquet`) are read by
//!   ranged GETs: preparing reads each whole for its MD5, as a CSV one's,
//!   then its footer, then a row group at a time, its chunks of the columns
//!   a job needs (pinned to the ETag the first read got, as running it is);
//!   a position is a row's index in its file, so a turn that starts in the
//!   middle of a file reads the row group it's in, from its start.
//!
//! An inventory report in ORC fails the job while it's prepared.

use std::{io::Write, sync::Arc};

use flate2::write::GzDecoder;
use http_body_util::BodyExt;
use hyper::{HeaderMap, StatusCode, body::Bytes, header};
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};

use super::{
    CHUNK, Failure, Manifest, manifest,
    manifest::{Field, Task},
    may_read,
    parquet::{self, Columns, Fetched, Group},
};
use crate::{
    App,
    body::ResBody,
    s3::{conditional::Preconditions, objects::get::get_object},
    users::Principal,
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

/// What an inventory report's data files are.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataFormat {
    /// Gzipped CSV (and what jobs prepared before Parquet was read have).
    #[default]
    #[serde(rename = "CSV")]
    Csv,
    Parquet,
}

/// An inventory report, as a job reads it: its data files' format, their
/// lines' columns (of CSV; Parquet files name theirs), and the files, as
/// its manifest lists them.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Inventory {
    #[serde(default)]
    pub format: DataFormat,
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
    /// Whether the job generated it (see `generate`), so that the role
    /// need not be allowed to read it, as with its manifest.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub generated: bool,
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
pub async fn read_inventory(
    app: &Arc<App>,
    manifest: &Manifest,
    role: &crate::kms::Caller,
) -> anyhow::Result<Result<Inventory, Failure>> {
    let invalid = |why: String| {
        Ok(Err(Failure::new(
            "ManifestInvalid",
            format!("The inventory report {} {why}.", manifest.arn),
        )))
    };
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
    let format = match parsed.file_format.as_str() {
        "CSV" => DataFormat::Csv,
        "Parquet" => DataFormat::Parquet,
        other => return invalid(format!("is in {other}, not CSV or Parquet")),
    };
    let fields: Vec<Field> = match format {
        DataFormat::Csv => {
            let fields: Vec<Field> = parsed
                .file_schema
                .split(',')
                .map(|name| {
                    Field::parse(name.trim())
                        .filter(|f| *f != Field::Ignore)
                        .unwrap_or(Field::Ignore)
                })
                .collect();
            if let Err(why) = manifest::check_fields(&fields) {
                return invalid(format!(
                    "has a schema without its objects' buckets and keys ({why})"
                ));
            }
            fields
        }
        // Each file's own schema says which of its columns are which.
        DataFormat::Parquet => match Columns::of_message(&parsed.file_schema) {
            Ok(_) => Vec::new(),
            Err(why) => {
                return invalid(format!(
                    "has a schema without its objects' buckets and keys ({why})"
                ));
            }
        },
    };
    let Some(bucket) = parsed
        .destination_bucket
        .strip_prefix("arn:aws:s3:::")
        .filter(|b| !b.is_empty())
    else {
        return invalid(format!(
            "names no bucket of its files ({})",
            parsed.destination_bucket
        ));
    };
    let files = parsed
        .files
        .into_iter()
        .map(|f| DataFile {
            bucket: bucket.to_owned(),
            key: f.key,
            md5: f.md5.to_ascii_lowercase(),
            etag: None,
            generated: manifest.generated,
        })
        .collect();
    Ok(Ok(Inventory {
        format,
        fields: fields.iter().map(|f| f.name().to_owned()).collect(),
        files,
    }))
}

/// Some of a manifest, read from an offset.
pub struct Chunk {
    pub data: Bytes,
    /// Whether it's the rest of the manifest.
    pub last: bool,
}

/// Reads up to `CHUNK` bytes of the manifest from `from`, as long as it's
/// still the one of its ETag (as `role`, which asks for its KMS key's use,
/// if it's SSE-KMS); why it can't be, if it can't.
pub async fn read(
    app: &Arc<App>,
    manifest: &Manifest,
    role: &crate::kms::Caller,
    from: u64,
) -> anyhow::Result<Result<Chunk, Failure>> {
    let range = format!("bytes={from}-{}", from + CHUNK - 1);
    let object = Object {
        bucket: &manifest.bucket,
        key: &manifest.key,
        version_id: manifest.version_id.as_deref(),
        arn: &manifest.arn,
    };
    let response = match get(app, &object, &manifest.etag, Some(&range), role).await? {
        Ok(response) => response,
        // Past its end: there's no more.
        Err(None) => {
            return Ok(Ok(Chunk {
                data: Bytes::new(),
                last: true,
            }));
        }
        Err(Some(failure)) => return Ok(Err(failure)),
    };
    let status = response.status();
    let size = size_of(response.headers());
    let data = response
        .into_body()
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("reading the manifest: {e}"))?
        .to_bytes();
    let last = match size {
        Some(size) => from + data.len() as u64 >= size,
        // The whole of it.
        None => status == StatusCode::OK,
    };
    Ok(Ok(Chunk { data, last }))
}

/// The size of the object a ranged GET's response is part of, from its
/// `Content-Range` (`bytes a-b/size`).
fn size_of(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit_once('/'))
        .and_then(|(_, size)| size.parse::<u64>().ok())
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
    role: &crate::kms::Caller,
) -> anyhow::Result<Result<hyper::Response<ResBody>, Option<Failure>>> {
    let mut headers = HeaderMap::new();
    if !etag.is_empty() {
        headers.insert(
            header::IF_MATCH,
            format!("\"{}\"", etag.trim_matches('"')).parse()?,
        );
    }
    let preconditions = Preconditions::from_headers(&headers);
    let response = get_object(
        app,
        object.bucket,
        object.key,
        object.version_id,
        range,
        None,
        &preconditions,
        None,
        Some(role.clone()),
        false,
    )
    .await?;
    let status = response.status();
    let unreadable = |why: String| {
        Failure::new(
            "ManifestUnreadable",
            format!("Reading {} failed: {why}.", object.arn),
        )
    };
    match status {
        StatusCode::OK | StatusCode::PARTIAL_CONTENT => Ok(Ok(response)),
        StatusCode::RANGE_NOT_SATISFIABLE => Ok(Err(None)),
        StatusCode::PRECONDITION_FAILED => Ok(Err(Some(Failure::new(
            "ManifestETagMismatch",
            format!("{} isn't the one of ETag {} any more.", object.arn, etag),
        )))),
        _ => {
            let body = response
                .into_body()
                .collect()
                .await
                .map(|b| b.to_bytes())
                .unwrap_or_default();
            let body = String::from_utf8_lossy(&body);
            let code = body
                .split("<Code>")
                .nth(1)
                .and_then(|s| s.split("</Code>").next())
                .unwrap_or("");
            Ok(Err(Some(unreadable(format!("{} {code}", status.as_u16())))))
        }
    }
}

/// GETs `range` of `object`, pinned to `etag`: the bytes, and the
/// object's size.
async fn get_range(
    app: &Arc<App>,
    object: &Object<'_>,
    etag: &str,
    range: &str,
    role: &crate::kms::Caller,
) -> anyhow::Result<Result<(Bytes, u64), Failure>> {
    let response = match get(app, object, etag, Some(range), role).await? {
        Ok(response) => response,
        Err(failure) => {
            let failure = failure.unwrap_or_else(|| {
                Failure::new(
                    "ManifestInvalid",
                    format!("The data file {} is empty.", object.arn),
                )
            });
            return Ok(Err(failure));
        }
    };
    let size = size_of(response.headers());
    let data = response
        .into_body()
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", object.arn))?
        .to_bytes();
    let size = size.unwrap_or(data.len() as u64);
    Ok(Ok((data, size)))
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
    pub async fn open(
        app: &Arc<App>,
        file: &DataFile,
        principal: &Principal,
    ) -> anyhow::Result<Result<DataLines, Failure>> {
        let arn = format!("arn:aws:s3:::{}/{}", file.bucket, file.key);
        if !file.generated
            && let Err(failure) =
                may_read(app, principal, &file.bucket, &file.key, None, &arn).await?
        {
            return Ok(Err(failure));
        }
        let role = &principal.kms_caller()?;
        let object = Object {
            bucket: &file.bucket,
            key: &file.key,
            version_id: None,
            arn: &arn,
        };
        let response =
            match get(app, &object, file.etag.as_deref().unwrap_or(""), None, role).await? {
                Ok(response) => response,
                Err(failure) => {
                    let failure = failure.unwrap_or_else(|| {
                        Failure::new("ManifestUnreadable", format!("Reading {arn} failed."))
                    });
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
        let invalid = |arn: &str, why: &str| {
            Failure::new("ManifestInvalid", format!("The data file {arn} {why}."))
        };
        loop {
            let rest = &self.pending[self.taken..];
            if let Some(end) = rest.iter().position(|&b| b == b'\n') {
                let line = rest[..end]
                    .strip_suffix(b"\r")
                    .unwrap_or(&rest[..end])
                    .to_vec();
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
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
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

    /// Reads it to its end, as it is (for its MD5): it isn't gzipped CSV.
    pub async fn read_through(&mut self) -> anyhow::Result<Result<(), Failure>> {
        while let Some(frame) = self.body.frame().await {
            let frame = frame.map_err(|e| anyhow::anyhow!("reading {}: {e}", self.arn))?;
            if let Ok(data) = frame.into_data() {
                self.md5.update(&data);
                self.size += data.len() as u64;
            }
        }
        Ok(Ok(()))
    }

    /// Skips lines up to `offset` (a line's start).
    pub async fn skip_to(&mut self, offset: u64) -> anyhow::Result<Result<(), Failure>> {
        while self.offset < offset {
            match self.line().await? {
                Ok(Some(_)) => {}
                Ok(None) => {
                    let failure = Failure::new(
                        "ManifestInvalid",
                        format!("The data file {} is shorter than it was.", self.arn),
                    );
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
        self.md5
            .clone()
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

/// An entry of a manifest that isn't a task: its object as a report names
/// it (a CSV line is its key), and why it isn't one.
pub struct Bad {
    pub bucket: String,
    pub key: String,
    pub why: String,
}

/// An entry of a manifest: a line of CSV, or a row of Parquet.
pub type Entry = Result<Task, Bad>;

/// The task of a CSV line, whose columns are `fields`.
fn csv_entry(line: &[u8], fields: &[Field]) -> Entry {
    std::str::from_utf8(line)
        .map_err(|_| "it isn't UTF-8".to_owned())
        .and_then(|text| manifest::parse_line(text, fields))
        .map_err(|why| Bad {
            bucket: String::new(),
            key: String::from_utf8_lossy(line).into_owned(),
            why,
        })
}

/// The task of a Parquet row.
fn parquet_entry(row: parquet::Row) -> Entry {
    let [bucket, key, version_id] = row.map(|v| v.unwrap_or_default());
    match (
        String::from_utf8(bucket),
        String::from_utf8(key),
        String::from_utf8(version_id),
    ) {
        (Ok(bucket), Ok(key), Ok(version_id)) => {
            manifest::task(bucket.clone(), key.clone(), Some(version_id)).map_err(|why| Bad {
                bucket,
                key,
                why,
            })
        }
        (bucket, key, _) => {
            let lossy = |s: Result<String, std::string::FromUtf8Error>| {
                s.unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
            };
            Err(Bad {
                bucket: lossy(bucket),
                key: lossy(key),
                why: "it isn't UTF-8".to_owned(),
            })
        }
    }
}

/// A Parquet data file's rows, as they're read, a row group at a time.
pub struct ParquetRows {
    app: Arc<App>,
    role: crate::kms::Caller,
    bucket: String,
    key: String,
    arn: String,
    /// The file's ETag, which every read is pinned to; its MD5 and size.
    pub etag: String,
    pub md5: String,
    pub size: u64,
    metadata: ::parquet::file::metadata::ParquetMetaData,
    columns: Columns,
    /// The row group being read, if one is (`open`); else the next.
    group: usize,
    open: Option<Group>,
    /// The index of the next row.
    pub offset: u64,
}

impl ParquetRows {
    /// Opens data file `file`, as the role session `principal`, which must
    /// be allowed to read it, pinned to its ETag if preparing recorded one;
    /// if it didn't, reads it whole first, for its MD5 and ETag.
    pub async fn open(
        app: &Arc<App>,
        file: &DataFile,
        principal: &Principal,
    ) -> anyhow::Result<Result<ParquetRows, Failure>> {
        let arn = format!("arn:aws:s3:::{}/{}", file.bucket, file.key);
        if !file.generated
            && let Err(failure) =
                may_read(app, principal, &file.bucket, &file.key, None, &arn).await?
        {
            return Ok(Err(failure));
        }
        let caller = principal.kms_caller()?;
        let invalid = |why: String| {
            Ok(Err(Failure::new(
                "ManifestInvalid",
                format!("The data file {arn} {why}."),
            )))
        };
        let mut etag = file.etag.clone().unwrap_or_default();
        if file.etag.is_none() {
            let mut lines = match DataLines::open(app, file, principal).await? {
                Ok(lines) => lines,
                Err(failure) => return Ok(Err(failure)),
            };
            if let Err(failure) = lines.read_through().await? {
                return Ok(Err(failure));
            }
            if lines.md5() != file.md5 {
                return invalid(
                    "isn't the one the inventory report lists (its MD5 differs)".to_owned(),
                );
            }
            etag = lines.etag.clone();
        }
        let object = Object {
            bucket: &file.bucket,
            key: &file.key,
            version_id: None,
            arn: &arn,
        };
        // Its footer: its last bytes, and more if they aren't all of it.
        let (mut end, size) = match get_range(
            app,
            &object,
            &etag,
            &format!("bytes=-{}", parquet::FOOTER_GUESS),
            &caller,
        )
        .await?
        {
            Ok(got) => got,
            Err(failure) => return Ok(Err(failure)),
        };
        let footer = match parquet::metadata_length(&end) {
            Ok(length) => length + ::parquet::file::FOOTER_SIZE as u64,
            Err(e) => return invalid(format!("isn't Parquet ({e})")),
        };
        if footer > parquet::MAX_FOOTER || footer > size {
            return invalid(format!("isn't Parquet (its footer is {footer} bytes long)"));
        }
        if footer > end.len() as u64 {
            end = match get_range(
                app,
                &object,
                &etag,
                &format!("bytes={}-{}", size - footer, size - 1),
                &caller,
            )
            .await?
            {
                Ok((end, _)) => end,
                Err(failure) => return Ok(Err(failure)),
            };
        }
        let metadata = match parquet::metadata(&end) {
            Ok(metadata) => metadata,
            Err(e) => return invalid(format!("isn't Parquet ({e})")),
        };
        let columns = match Columns::of(metadata.file_metadata().schema_descr()) {
            Ok(columns) => columns,
            Err(why) => return invalid(format!("isn't an inventory report's: {why}")),
        };
        Ok(Ok(ParquetRows {
            app: app.clone(),
            role: caller,
            bucket: file.bucket.clone(),
            key: file.key.clone(),
            arn,
            etag,
            md5: file.md5.clone(),
            size,
            metadata,
            columns,
            group: 0,
            open: None,
            offset: 0,
        }))
    }

    fn invalid(&self, why: impl std::fmt::Display) -> Failure {
        Failure::new(
            "ManifestInvalid",
            format!("The data file {} isn't Parquet ({why}).", self.arn),
        )
    }

    /// Reads row group `index`: its chunks of the columns a job reads.
    async fn read_group(&mut self, index: usize) -> anyhow::Result<Result<Group, Failure>> {
        let ranges = match parquet::ranges(self.metadata.row_group(index), self.columns) {
            Ok(ranges) => ranges,
            Err(e) => return Ok(Err(self.invalid(e))),
        };
        let mut parts = Vec::new();
        for (start, length) in ranges {
            if length == 0 {
                continue;
            }
            let object = Object {
                bucket: &self.bucket,
                key: &self.key,
                version_id: None,
                arn: &self.arn,
            };
            let range = format!("bytes={start}-{}", start + length - 1);
            let data = match get_range(&self.app, &object, &self.etag, &range, &self.role).await? {
                Ok((data, _)) => data,
                Err(failure) => return Ok(Err(failure)),
            };
            if data.len() as u64 != length {
                return Ok(Err(self.invalid("a row group is past its end")));
            }
            parts.push((start, data));
        }
        let fetched = Arc::new(Fetched {
            size: self.size,
            parts,
        });
        Ok(Group::new(fetched, &self.metadata, index, self.columns).map_err(|e| self.invalid(e)))
    }

    /// Its next rows' entries, up to `limit` (none: it's at its end).
    pub async fn rows(&mut self, limit: usize) -> anyhow::Result<Result<Vec<Entry>, Failure>> {
        loop {
            let group = match &mut self.open {
                Some(group) if group.left > 0 => group,
                Some(_) => {
                    self.open = None;
                    self.group += 1;
                    continue;
                }
                None if self.group >= self.metadata.num_row_groups() => return Ok(Ok(Vec::new())),
                None => match self.read_group(self.group).await? {
                    Ok(group) => self.open.insert(group),
                    Err(failure) => return Ok(Err(failure)),
                },
            };
            let rows = match group.read(limit) {
                Ok(rows) => rows,
                Err(e) => return Ok(Err(self.invalid(e))),
            };
            self.offset += rows.len() as u64;
            return Ok(Ok(rows.into_iter().map(parquet_entry).collect()));
        }
    }

    /// Skips rows up to `offset` (a row's index): reads the row group it's
    /// in, from its start.
    pub async fn skip_to(&mut self, offset: u64) -> anyhow::Result<Result<(), Failure>> {
        let mut start = 0;
        for index in 0..self.metadata.num_row_groups() {
            let rows = self.metadata.row_group(index).num_rows().max(0) as u64;
            if offset < start + rows {
                let mut group = match self.read_group(index).await? {
                    Ok(group) => group,
                    Err(failure) => return Ok(Err(failure)),
                };
                if let Err(e) = group.skip(offset - start) {
                    return Ok(Err(self.invalid(e)));
                }
                (self.group, self.open, self.offset) = (index, Some(group), offset);
                return Ok(Ok(()));
            }
            start += rows;
        }
        if offset > start {
            return Ok(Err(Failure::new(
                "ManifestInvalid",
                format!("The data file {} is shorter than it was.", self.arn),
            )));
        }
        (self.group, self.open, self.offset) = (self.metadata.num_row_groups(), None, offset);
        Ok(Ok(()))
    }
}

/// A data file of an inventory report, as it's read: its lines, or its rows.
pub enum DataRows {
    Csv(Box<DataLines>, Vec<Field>),
    Parquet(Box<ParquetRows>),
}

impl DataRows {
    /// Opens data file `index` of `inventory`, as the role session
    /// `principal` (see `DataLines::open` and `ParquetRows::open`).
    pub async fn open(
        app: &Arc<App>,
        inventory: &Inventory,
        index: usize,
        principal: &Principal,
    ) -> anyhow::Result<Result<DataRows, Failure>> {
        let file = &inventory.files[index];
        Ok(match inventory.format {
            DataFormat::Csv => DataLines::open(app, file, principal)
                .await?
                .map(|l| DataRows::Csv(Box::new(l), inventory.fields())),
            DataFormat::Parquet => ParquetRows::open(app, file, principal)
                .await?
                .map(|r| DataRows::Parquet(Box::new(r))),
        })
    }

    /// What its entries are called.
    pub fn entry_name(&self) -> &'static str {
        match self {
            DataRows::Csv(..) => "Line",
            DataRows::Parquet(_) => "Row",
        }
    }

    /// Its next entries, up to `limit` (none: it's at its end).
    pub async fn entries(&mut self, limit: usize) -> anyhow::Result<Result<Vec<Entry>, Failure>> {
        match self {
            DataRows::Csv(lines, fields) => {
                let mut entries = Vec::new();
                while entries.len() < limit {
                    match lines.line().await? {
                        Ok(Some(line)) => entries.push(csv_entry(&line, fields)),
                        Ok(None) => break,
                        Err(failure) => return Ok(Err(failure)),
                    }
                }
                Ok(Ok(entries))
            }
            DataRows::Parquet(rows) => rows.rows(limit).await,
        }
    }

    /// Where its next entry is.
    pub fn offset(&self) -> u64 {
        match self {
            DataRows::Csv(lines, _) => lines.offset,
            DataRows::Parquet(rows) => rows.offset,
        }
    }

    pub async fn skip_to(&mut self, offset: u64) -> anyhow::Result<Result<(), Failure>> {
        match self {
            DataRows::Csv(lines, _) => lines.skip_to(offset).await,
            DataRows::Parquet(rows) => rows.skip_to(offset).await,
        }
    }

    /// The file's MD5 (hex; once it's read to its end), size and ETag.
    pub fn digest(&self) -> (String, u64, String) {
        match self {
            DataRows::Csv(lines, _) => (lines.md5(), lines.size, lines.etag.clone()),
            DataRows::Parquet(rows) => (rows.md5.clone(), rows.size, rows.etag.clone()),
        }
    }
}

/// A page of a manifest's entries.
pub struct Page {
    pub entries: Vec<Entry>,
    /// Where the page ends: where the next one starts.
    pub end: Position,
    /// Whether it's the manifest's last.
    pub finished: bool,
}

/// A job's manifest, read a page at a time.
pub enum Source<'a> {
    Csv(&'a Manifest),
    /// An inventory report's data files, and the one being read, if one is.
    Inventory(&'a Inventory, Option<(i32, Box<DataRows>)>),
}

impl Source<'_> {
    /// The page of up to `limit` entries at `at`, as the role session
    /// `principal` reads it: a page ends at its data file's end.
    pub async fn page(
        &mut self,
        app: &Arc<App>,
        principal: &Principal,
        at: Position,
        limit: usize,
    ) -> anyhow::Result<Result<Page, Failure>> {
        let role = &principal.kms_caller()?;
        match self {
            Source::Csv(manifest) => {
                let chunk = match read(app, manifest, role, at.offset).await? {
                    Ok(chunk) => chunk,
                    Err(failure) => return Ok(Err(failure)),
                };
                let (lines, consumed) = manifest::lines(&chunk.data, chunk.last, limit);
                let finished = chunk.last && consumed == chunk.data.len();
                if lines.is_empty() && !finished {
                    return Ok(Err(Failure::new(
                        "ManifestInvalid",
                        "A line of the manifest is too long.",
                    )));
                }
                let fields = manifest.fields();
                let entries = lines
                    .into_iter()
                    .map(|line| csv_entry(line, &fields))
                    .collect();
                Ok(Ok(Page {
                    entries,
                    end: Position {
                        file: 0,
                        offset: at.offset + consumed as u64,
                    },
                    finished,
                }))
            }
            Source::Inventory(inventory, open) => {
                let count = inventory.files.len() as i32;
                if at.file >= count {
                    return Ok(Ok(Page {
                        entries: Vec::new(),
                        end: at,
                        finished: true,
                    }));
                }
                // The data file at `at`, open there.
                if !matches!(open, Some((file, rows)) if *file == at.file && rows.offset() == at.offset)
                {
                    let mut rows =
                        match DataRows::open(app, inventory, at.file as usize, principal).await? {
                            Ok(rows) => rows,
                            Err(failure) => return Ok(Err(failure)),
                        };
                    if let Err(failure) = rows.skip_to(at.offset).await? {
                        return Ok(Err(failure));
                    }
                    *open = Some((at.file, Box::new(rows)));
                }
                let (_, data) = open.as_mut().expect("just opened");
                let mut page = Vec::new();
                while page.len() < limit {
                    let entries = match data.entries(limit - page.len()).await? {
                        Ok(entries) => entries,
                        Err(failure) => return Ok(Err(failure)),
                    };
                    if entries.is_empty() {
                        *open = None;
                        let end = Position {
                            file: at.file + 1,
                            offset: 0,
                        };
                        return Ok(Ok(Page {
                            entries: page,
                            end,
                            finished: end.file >= count,
                        }));
                    }
                    page.extend(entries);
                }
                Ok(Ok(Page {
                    entries: page,
                    end: Position {
                        file: at.file,
                        offset: data.offset(),
                    },
                    finished: false,
                }))
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
