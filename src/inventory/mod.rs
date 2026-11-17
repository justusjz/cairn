//! S3 Inventory: reports of a bucket's objects, made as its inventory
//! configurations say (see `config`, and `s3::buckets::inventory` for how
//! they're set), and written as files to their destination buckets, as S3
//! writes them (see `plans/inventory.md`).
//!
//! A report is a walk over the bucket's versions (or its current objects)
//! under the configuration's prefix, in key order, each key's versions
//! newest first. It's written as data files, each one object of gzipped CSV,
//! `<prefix>/<bucket>/<id>/data/<uuid>.csv.gz`, or of Parquet (see
//! `parquet`), `….parquet`, as the configuration says; once the last is
//! written,
//! the files are listed in `<prefix>/<bucket>/<id>/<time>/manifest.json`
//! (with `manifest.checksum` beside it) and in a Hive symlink file,
//! `<prefix>/<bucket>/<id>/hive/dt=<time>/symlink.txt`.
//!
//! Reports take turns with lifecycle sweeps, in the steps the cluster takes
//! them in, sharing their budget of versions read an hour (see `lifecycle`).
//! A turn of a report writes one data file: it's written whole, streamed as
//! it's read, so a turn reads all the versions it holds, `rows_per_file` of
//! them (about ten minutes of the rate), however much is left of the step's
//! budget; what it reads beyond that, the steps after it pay off. After the
//! file's written, where the report has got to is saved with it
//! (`cairn_inventory_file`), so a report resumes there, on any node; a node
//! that dies while writing one loses that file's work only (its write never
//! commits, and the garbage collector cleans up after it).
//!
//! Nothing of a report is ever held whole in memory: a turn holds a page of
//! versions, the gzip encoder's window (or a Parquet row group, of up to
//! `ROW_GROUP_BYTES`), and a few chunks on their way into the write (a
//! bounded channel). The manifest and symlink files are streamed from the
//! data files' rows the same way.
//!
//! Its files are written as S3 writes them, as the `s3.amazonaws.com`
//! service: the destination bucket's policy must allow that, as in S3 (see
//! `authorized`). A delivery that fails is tried again an hour later, from
//! where the report had got to.
//!
//! Like S3's, a report is as of no single moment: what's written or deleted
//! while it's made may or may not be in it.

pub mod config;
pub mod parquet;
mod snappy;

use std::{
    io,
    sync::Arc,
    time::{Duration, SystemTime},
};

use deadpool_postgres::Object;
use flate2::{Compression, write::GzEncoder};
use http_body_util::BodyExt;
use hyper::{
    StatusCode,
    body::{Body, Bytes, Frame},
};
use md5::{Digest, Md5};
use std::io::Write;

use crate::db::Cached;
use crate::{
    App,
    body::{FrameSender, channel_body},
    lifecycle::rules::{self as lifecycle_rules, Day},
    payload::Payload,
    policy::Context,
    s3::{
        conditional::Preconditions,
        object_lock::Lock,
        service::Destination,
        sse::{KmsRequest, ServerSide, Wanted},
        util::{Encoding, MAX_UPLOAD},
    },
};

use config::{Column, Configuration, Encryption, Field, Format, Frequency};
use parquet::Value;

/// The most versions read at a time.
const PAGE: i64 = 1000;
/// The fewest and most versions a data file holds (but the last).
const MIN_FILE_ROWS: i64 = 10_000;
const MAX_FILE_ROWS: i64 = 1_000_000;
/// About how many bytes (uncompressed) a Parquet data file's row groups
/// hold, but its last.
const ROW_GROUP_BYTES: usize = 16 << 20;
/// How long after a failed delivery it's tried again.
const RETRY: Duration = Duration::from_secs(3600);
const DAY: Duration = Duration::from_secs(24 * 3600);
/// The service a report's files are written as.
pub const SERVICE: &str = "s3.amazonaws.com";

/// How many versions a data file holds, at `rate` versions read an hour:
/// about ten minutes of it, so that a turn, which reads a whole file, never
/// runs far ahead of the rate.
pub fn rows_per_file(rate: i64) -> i64 {
    (rate / 6).clamp(MIN_FILE_ROWS, MAX_FILE_ROWS)
}

/// A configuration's report, as a step gets to it.
pub(crate) struct Report {
    pub bucket: String,
    pub id: String,
    /// Its configuration, as stored, and its generation.
    config: String,
    generation: i64,
    /// The user that set it, as whom it asks the KMS for keys.
    setter: Option<uuid::Uuid>,
    /// When it started; `None` if it's yet to.
    started: Option<SystemTime>,
    /// The last version it wrote: its key, and (of all versions) its row
    /// ID; `None` before its first file.
    cursor: Option<(String, Option<i64>)>,
    /// Versions read, and data files written, so far.
    seen: i64,
    files: i32,
}

/// What a turn of a report did.
#[derive(Debug, Default, PartialEq)]
pub struct Turn {
    pub bucket: String,
    pub id: String,
    /// Versions read.
    pub read: i64,
    /// Whether it wrote a data file.
    pub file: bool,
    /// Whether it ended the report (wrote its manifest).
    pub finished: bool,
    /// Why its delivery failed, if it did: it's tried again later.
    pub failure: Option<String>,
    /// Whether the configuration changed (or went) under it.
    pub interrupted: bool,
}

impl std::fmt::Display for Turn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bucket {}, inventory {}: ", self.bucket, self.id)?;
        match (&self.failure, self.interrupted, self.finished) {
            (Some(why), _, _) => write!(f, "delivery failed, trying again in an hour: {why}"),
            (None, true, _) => write!(f, "its configuration changed; starting over"),
            (None, false, true) => write!(f, "report delivered"),
            (None, false, false) => write!(f, "wrote a data file of {} versions", self.read),
        }
    }
}

/// A report's last whole run, as `inventories.last` keeps it. Times are
/// seconds since the Unix epoch.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LastReport {
    pub started: f64,
    pub finished: f64,
    /// Versions read, and data files written.
    pub read: i64,
    pub files: i32,
    /// Its manifest's key, in the destination bucket.
    pub manifest: String,
}

/// The report due as of `now` that has waited longest, but for those
/// `visited` this step already (`<bucket>/<id>`), and when it was due.
pub(crate) async fn next(client: &Object, now: SystemTime, visited: &[String]) -> anyhow::Result<Option<(SystemTime, Report)>> {
    let row = client
        .query_opt_cached(
            "SELECT bucket, id, config, generation, setter, due, started, cursor_key, cursor_id, seen, files
             FROM inventories
             WHERE enabled AND due <= $1 AND NOT (bucket || '/' || id = ANY($2))
             ORDER BY due LIMIT 1",
            &[&now, &visited],
        )
        .await?;
    Ok(row.map(|row| {
        let cursor_key: Option<String> = row.get(7);
        let report = Report {
            bucket: row.get(0),
            id: row.get(1),
            config: row.get(2),
            generation: row.get(3),
            setter: row.get(4),
            started: row.get(6),
            cursor: cursor_key.map(|key| (key, row.get(8))),
            seen: row.get(9),
            files: row.get(10),
        };
        (row.get(5), report)
    }))
}

impl Report {
    /// Its name, as `next` takes the visited ones.
    pub fn name(&self) -> String {
        format!("{}/{}", self.bucket, self.id)
    }
}

/// What a turn needs to know, once.
struct Target<'a> {
    report: &'a Report,
    config: &'a Configuration,
    /// The account that owns the source bucket.
    account: String,
    started: SystemTime,
    /// The step's time (see `lifecycle`).
    now: SystemTime,
}

impl Target<'_> {
    /// What all of the report's keys start with: `<prefix>/<bucket>/<id>/`.
    fn base(&self) -> String {
        let prefix = match &self.config.destination.prefix {
            Some(prefix) => format!("{}/", prefix.trim_end_matches('/')),
            None => String::new(),
        };
        format!("{prefix}{}/{}/", self.report.bucket, self.config.id)
    }
}

/// Takes the report one data file further (or, at its end, writes its
/// manifest). `rows` is how many versions a file holds.
pub(crate) async fn turn(app: &Arc<App>, client: &Object, report: Report, now: SystemTime, rows: i64) -> anyhow::Result<Turn> {
    let mut turn = Turn { bucket: report.bucket.clone(), id: report.id.clone(), ..Turn::default() };
    let config = Configuration::from_json(&report.config).map_err(|e| {
        anyhow::anyhow!("its inventory configuration isn't one this Cairn knows (written by a newer one?): {e}")
    })?;
    let account = crate::s3::util::bucket_owner(client, &report.bucket).await?;
    let target = Target { report: &report, config: &config, account, started: report.started.unwrap_or(now), now };
    let source = Source::load(client, &report.bucket).await?;
    let after = report.cursor.clone().unwrap_or_default();
    // The first page first: none, and there's no file to write.
    let first = page(client, &report.bucket, &config, &after, PAGE.min(rows)).await?;
    if !first.is_empty() {
        let (extension, content_type) = match config.destination.format {
            Format::Csv => ("csv.gz", "application/x-gzip"),
            Format::Parquet => ("parquet", "application/octet-stream"),
        };
        let key = format!("{}data/{}.{extension}", target.base(), uuid::Uuid::new_v4());
        let (sender, body) = channel_body();
        let writing = write_rows(app, client, &target, &source, first, after, rows, sender);
        let delivering = deliver(app, &target, &key, content_type, body);
        let (written, delivered) = tokio::join!(writing, delivering);
        match delivered {
            // A delivery that failed is why the rows stopped, if they did.
            Ok(Err(why)) => {
                turn.read = written.map_or(0, |w| w.rows);
                return failed(client, &report, turn, why, now).await;
            }
            Ok(Ok(())) => {}
            // Rows that failed are why the write did, if they did.
            Err(e) => return Err(written.err().unwrap_or(e)),
        }
        let written = written?;
        turn.read = written.rows;
        turn.file = true;
        let (cursor_key, cursor_id) = &written.cursor;
        let saved: bool = client
            .query_one_cached(
                "SELECT pg_temp.cairn_inventory_file($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                &[
                    &report.bucket,
                    &report.id,
                    &report.generation,
                    &target.started,
                    &key,
                    &(written.size as i64),
                    &written.md5,
                    cursor_key,
                    cursor_id,
                    &written.rows,
                ],
            )
            .await?
            .get(0);
        if !saved {
            turn.interrupted = true;
            return Ok(turn);
        }
        if !written.end {
            // To the back of the line.
            let updated = client
                .execute_cached(
                    "UPDATE inventories SET due = $4 WHERE bucket = $1 AND id = $2 AND generation = $3",
                    &[&report.bucket, &report.id, &report.generation, &now],
                )
                .await?;
            turn.interrupted = updated == 0;
            return Ok(turn);
        }
    }
    if let Err(why) = finish(app, client, &target, turn.read, now).await? {
        return failed(client, &report, turn, why, now).await;
    }
    turn.finished = true;
    Ok(turn)
}

/// Records why the report's delivery failed, and makes it due again in an
/// hour, from where it had got to.
async fn failed(client: &Object, report: &Report, mut turn: Turn, why: String, now: SystemTime) -> anyhow::Result<Turn> {
    let updated = client
        .execute_cached(
            "UPDATE inventories SET failure = $4, failed_at = $5, due = $6
             WHERE bucket = $1 AND id = $2 AND generation = $3",
            &[&report.bucket, &report.id, &report.generation, &why, &now, &(now + RETRY)],
        )
        .await?;
    turn.interrupted = updated == 0;
    turn.failure = Some(why);
    Ok(turn)
}

/// What a report needs of its source bucket.
struct Source {
    /// Its lifecycle configuration, for `LifecycleExpirationDate`.
    lifecycle: Option<lifecycle_rules::Configuration>,
    /// Whether it has Object Lock (whose versions' legal holds are `OFF`
    /// when they have none).
    object_lock: bool,
}

impl Source {
    async fn load(client: &Object, bucket: &str) -> anyhow::Result<Source> {
        let row = client
            .query_opt_cached("SELECT lifecycle, object_lock FROM buckets WHERE name = $1", &[&bucket])
            .await?;
        let Some(row) = row else { return Ok(Source { lifecycle: None, object_lock: false }) };
        let lifecycle = row.get::<_, Option<String>>(0).and_then(|json| lifecycle_rules::Configuration::from_json(&json).ok());
        Ok(Source { lifecycle, object_lock: row.get(1) })
    }
}

/// The columns a page has (see `values`).
const COLUMNS: &str = "key, id, version_id, is_latest, is_delete_marker, size, etag,
    sse_s3, sse_kms_key_id, sse_kms_data_key, sse_kms_sealed, last_modified,
    sse_c_key IS NOT NULL, checksum_algorithm, retain_mode, retain_until,
    legal_hold, upload_id IS NOT NULL, tags";

/// The next page of up to `limit` of the bucket's versions (or current
/// objects) under the configuration's prefix, after `after`: a key, and
/// for all versions the row ID of the last of its versions read (they're
/// read newest, highest, first), if not all of them were.
async fn page(
    client: &Object,
    bucket: &str,
    config: &Configuration,
    after: &(String, Option<i64>),
    limit: i64,
) -> anyhow::Result<Vec<tokio_postgres::Row>> {
    let prefix = config.prefix.clone().unwrap_or_default();
    let end = lifecycle_rules::prefix_end(&prefix);
    let (after_key, after_id) = after;
    let mut rows = Vec::new();
    // The rest of a key whose versions a file ended within.
    if let (true, Some(id)) = (config.all_versions, after_id) {
        rows = client
            .query_cached(
                &format!(
                    "SELECT {COLUMNS} FROM objects WHERE bucket = $1 AND key = $2 AND id < $3
                     ORDER BY id DESC LIMIT $4"
                ),
                &[&bucket, after_key, id, &limit],
            )
            .await?;
        if rows.len() as i64 == limit {
            return Ok(rows);
        }
    }
    let limit = limit - rows.len() as i64;
    let current = if config.all_versions { "" } else { "AND is_latest AND NOT is_delete_marker" };
    let order = if config.all_versions { "key, id DESC" } else { "key" };
    let more = match &end {
        Some(end) => {
            client
                .query_cached(
                    &format!(
                        "SELECT {COLUMNS} FROM objects
                         WHERE bucket = $1 AND key > $2 AND key >= $3 AND key < $4 {current}
                         ORDER BY {order} LIMIT $5"
                    ),
                    &[&bucket, after_key, &prefix, end, &limit],
                )
                .await?
        }
        None => {
            client
                .query_cached(
                    &format!(
                        "SELECT {COLUMNS} FROM objects WHERE bucket = $1 AND key > $2 AND key >= $3 {current}
                         ORDER BY {order} LIMIT $4"
                    ),
                    &[&bucket, after_key, &prefix, &limit],
                )
                .await?
        }
    };
    rows.extend(more);
    Ok(rows)
}

/// What a data file holds.
struct Written {
    rows: i64,
    /// The last version in it (see `page`).
    cursor: (String, Option<i64>),
    /// Whether it ends the report.
    end: bool,
    /// Its size and MD5 (hex), as written: compressed.
    size: u64,
    md5: String,
}

/// A data file on its way into a write: its bytes, as they're made,
/// counted and hashed.
struct DataFile {
    encoder: Encoder,
    md5: Md5,
    size: u64,
    sender: FrameSender,
}

enum Encoder {
    /// A line at a time, gzipped.
    Csv { gzip: GzEncoder<Vec<u8>>, line: String },
    /// A row group at a time.
    Parquet(parquet::Writer),
}

impl DataFile {
    fn new(format: Format, columns: &[Column], sender: FrameSender) -> DataFile {
        let encoder = match format {
            Format::Csv => Encoder::Csv { gzip: GzEncoder::new(Vec::new(), Compression::default()), line: String::new() },
            Format::Parquet => Encoder::Parquet(parquet::Writer::new(columns.iter().map(|c| c.parquet()).collect())),
        };
        DataFile { encoder, md5: Md5::new(), size: 0, sender }
    }

    /// Adds a version's row: a value of each of `columns`.
    fn push(&mut self, columns: &[Column], values: &[Value]) -> io::Result<()> {
        match &mut self.encoder {
            Encoder::Csv { gzip, line } => {
                line.clear();
                for (column, value) in columns.iter().zip(values) {
                    push_value(line, &csv_value(*column, value));
                }
                line.push('\n');
                gzip.write_all(line.as_bytes())
            }
            Encoder::Parquet(writer) => {
                writer.push(values);
                Ok(())
            }
        }
    }

    /// Sends what's made so far: what the gzip encoder has put out, or a
    /// row group, once it's big enough.
    async fn flush(&mut self) -> anyhow::Result<()> {
        let out = match &mut self.encoder {
            Encoder::Csv { gzip, .. } => std::mem::take(gzip.get_mut()),
            Encoder::Parquet(writer) if writer.buffered() >= ROW_GROUP_BYTES => writer.row_group(),
            Encoder::Parquet(_) => return Ok(()),
        };
        self.send(out).await
    }

    async fn send(&mut self, out: Vec<u8>) -> anyhow::Result<()> {
        if out.is_empty() {
            return Ok(());
        }
        self.md5.update(&out);
        self.size += out.len() as u64;
        // A write that ended (refused, or failed) has dropped the body.
        self.sender.send(Ok(Frame::data(Bytes::from(out)))).await.map_err(|_| anyhow::anyhow!("the write stopped"))
    }

    /// Ends the stream, and the write with it: its size and MD5.
    async fn finish(mut self) -> anyhow::Result<(u64, String)> {
        let encoder = std::mem::replace(&mut self.encoder, Encoder::Parquet(parquet::Writer::new(Vec::new())));
        let out = match encoder {
            Encoder::Csv { gzip, .. } => gzip.finish()?,
            Encoder::Parquet(writer) => writer.finish(),
        };
        self.send(out).await?;
        Ok((self.size, hex(&self.md5.finalize())))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Writes a data file's rows into `sender`, from `first` (the first page,
/// read after `after`) up to `limit` versions. A failure faults the body,
/// so that the write fails rather than commit a file cut short.
#[allow(clippy::too_many_arguments)]
async fn write_rows(
    app: &Arc<App>,
    client: &Object,
    target: &Target<'_>,
    source: &Source,
    first: Vec<tokio_postgres::Row>,
    after: (String, Option<i64>),
    limit: i64,
    sender: FrameSender,
) -> anyhow::Result<Written> {
    let fault = sender.clone();
    let columns = target.config.columns();
    let out = DataFile::new(target.config.destination.format, &columns, sender);
    let written = write_rows_into(app, client, target, source, &columns, first, after, limit, out).await;
    if let Err(e) = &written {
        let _ = fault.send(Err(io::Error::other(format!("{e:#}")))).await;
    }
    written
}

#[allow(clippy::too_many_arguments)]
async fn write_rows_into(
    app: &Arc<App>,
    client: &Object,
    target: &Target<'_>,
    source: &Source,
    columns: &[Column],
    first: Vec<tokio_postgres::Row>,
    mut after: (String, Option<i64>),
    limit: i64,
    mut out: DataFile,
) -> anyhow::Result<Written> {
    let owner = crate::s3::util::canonical_id(&target.account);
    let mut rows = 0;
    let mut page_rows = first;
    let mut row_values = Vec::new();
    let end = loop {
        let asked = PAGE.min(limit - rows);
        let got = page_rows.len() as i64;
        for row in &page_rows {
            row_values.clear();
            values(app, target, source, columns, &owner, row, &mut row_values).await?;
            out.push(columns, &row_values)?;
        }
        out.flush().await?;
        rows += got;
        // However long the file takes, no other node takes the step over.
        crate::lifecycle::extend(client, target.now).await?;
        if let Some(last) = page_rows.last() {
            let key: String = last.get(0);
            after = (key, target.config.all_versions.then(|| last.get(1)));
        }
        // A short page is the end (the first page's is asked for as this
        // one's is).
        if got < asked {
            break true;
        }
        if rows >= limit {
            break page(client, &target.report.bucket, target.config, &after, 1).await?.is_empty();
        }
        page_rows = page(client, &target.report.bucket, target.config, &after, PAGE.min(limit - rows)).await?;
    };
    let (size, md5) = out.finish().await?;
    Ok(Written { rows, cursor: after, end, size, md5 })
}

/// A CSV value: quoted, with its quotes doubled.
fn push_value(line: &mut String, value: &str) {
    if !line.is_empty() {
        line.push(',');
    }
    line.push('"');
    line.push_str(&value.replace('"', "\"\""));
    line.push('"');
}

/// A value as CSV has it: keys URL-encoded (as S3's are, and as
/// `encoding-type=url` writes them), times in ISO 8601, to the millisecond;
/// nothing for none.
fn csv_value(column: Column, value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Text(text) if column == Column::Key => Encoding::Url.xml(text),
        Value::Text(text) => text.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Int(n) => n.to_string(),
        Value::Millis(ms) => iso_millis(*ms),
    }
}

/// Milliseconds since the epoch, as `2026-11-16T05:00:00.000Z`.
fn iso_millis(ms: i64) -> String {
    let day = Day(ms.div_euclid(DAY_MILLIS));
    let (year, month, date) = day.civil();
    let of_day = ms.rem_euclid(DAY_MILLIS);
    let (h, m, s, ms) = (of_day / 3_600_000, of_day / 60_000 % 60, of_day / 1000 % 60, of_day % 1000);
    format!("{year:04}-{month:02}-{date:02}T{h:02}:{m:02}:{s:02}.{ms:03}Z")
}

const DAY_MILLIS: i64 = 24 * 3600 * 1000;

/// Milliseconds since the epoch.
fn millis(time: SystemTime) -> i64 {
    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => d.as_millis() as i64,
        Err(e) => -(e.duration().as_millis() as i64),
    }
}

/// A version's row of the report, from a row of `page`: a value of each
/// of `columns`, into `values`.
async fn values(
    app: &App,
    target: &Target<'_>,
    source: &Source,
    columns: &[Column],
    owner: &str,
    row: &tokio_postgres::Row,
    values: &mut Vec<Value>,
) -> anyhow::Result<()> {
    let bucket = &target.report.bucket;
    let key: &str = row.get(0);
    let version_id: &str = row.get(2);
    let is_latest: bool = row.get(3);
    let marker: bool = row.get(4);
    let text = |s: &str| Value::Text(s.to_owned());
    let optional = |s: Option<String>| s.map_or(Value::Null, Value::Text);
    for column in columns {
        let value = match column {
            Column::Bucket => text(bucket),
            Column::Key => text(key),
            Column::VersionId if version_id == "null" => Value::Null,
            Column::VersionId => text(version_id),
            Column::IsLatest => Value::Bool(is_latest),
            Column::IsDeleteMarker => Value::Bool(marker),
            Column::Field(Field::LastModifiedDate) => Value::Millis(millis(row.get(11))),
            Column::Field(Field::ObjectOwner) => text(owner),
            // A delete marker has nothing else.
            _ if marker => Value::Null,
            Column::Field(field) => match field {
                Field::Size => Value::Int(row.get(5)),
                Field::ETag => optional(crate::s3::objects::list::listed_etag(app, bucket, key, row, 6, 7).await?),
                Field::StorageClass => text("STANDARD"),
                Field::IsMultipartUploaded => Value::Bool(row.get(17)),
                Field::EncryptionStatus => {
                    let sse_s3: bool = row.get(7);
                    let kms: Option<&str> = row.get(8);
                    let sse_c: bool = row.get(12);
                    text(match (sse_s3, kms, sse_c) {
                        (true, _, _) => "SSE-S3",
                        (false, Some(_), _) => "SSE-KMS",
                        (false, None, true) => "SSE-C",
                        _ => "NOT-SSE",
                    })
                }
                Field::ObjectLockRetainUntilDate => {
                    row.get::<_, Option<SystemTime>>(15).map_or(Value::Null, |t| Value::Millis(millis(t)))
                }
                Field::ObjectLockMode => optional(row.get(14)),
                Field::ObjectLockLegalHoldStatus => match row.get::<_, Option<bool>>(16) {
                    Some(true) => text("ON"),
                    Some(false) => text("OFF"),
                    None if source.object_lock => text("OFF"),
                    None => Value::Null,
                },
                Field::ChecksumAlgorithm => optional(row.get(13)),
                // The owner's full control: ACLs are always disabled.
                Field::ObjectAccessControlList => Value::Text(acl(owner)),
                // Of the current version only: what a rule's expiration
                // says.
                Field::LifecycleExpirationDate => match (&source.lifecycle, is_latest) {
                    (Some(rules), true) => {
                        let tags: &str = row.get(18);
                        let written: SystemTime = row.get(11);
                        rules
                            .expiry(key, row.get(5), tags, written)
                            .map_or(Value::Null, |(day, _)| Value::Millis(millis(day.midnight())))
                    }
                    _ => Value::Null,
                },
                // What Cairn has none of: replication, storage tiers,
                // bucket keys, event holds.
                Field::ReplicationStatus
                | Field::IntelligentTieringAccessTier
                | Field::BucketKeyStatus
                | Field::ObjectLockEventHoldStatus
                | Field::ObjectLockEventHoldDuration
                | Field::LastModifiedDate
                | Field::ObjectOwner => Value::Null,
            },
            Column::EventHoldDurationUnit => Value::Null,
        };
        values.push(value);
    }
    Ok(())
}

/// The ACL of a version, as S3's report has it: its JSON, in base64.
fn acl(owner: &str) -> String {
    use base64::Engine;
    let json = serde_json::json!({
        "version": "2022-11-10",
        "status": "AVAILABLE",
        "grants": [{"canonicalId": owner, "type": "CanonicalUser", "permission": "FULL_CONTROL"}],
    });
    base64::engine::general_purpose::STANDARD.encode(json.to_string())
}

/// Ends the report: writes its symlink file, manifest and the manifest's
/// checksum, from its data files' rows, and makes the next one due. `read`
/// is what this turn read already. Why its delivery failed, if it did.
async fn finish(
    app: &Arc<App>,
    client: &Object,
    target: &Target<'_>,
    read: i64,
    now: SystemTime,
) -> anyhow::Result<Result<(), String>> {
    let report = target.report;
    let (date, time) = timestamp(target.started);
    let base = target.base();
    let dest = &target.config.destination.bucket;
    // The symlink file: the data files' URLs, a line each.
    let symlink = format!("{base}hive/dt={date}-{}/symlink.txt", time.replace(':', "-"));
    let line = |file: &File| format!("s3://{dest}/{}\n", file.key);
    if let Err(why) = deliver_listing(app, client, target, &symlink, "text/plain", String::new(), line, "").await? {
        return Ok(Err(why));
    }
    // The manifest, and its MD5.
    let manifest = format!("{base}{date}T{}Z/manifest.json", time.replace(':', "-"));
    let created = target.started.duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_millis());
    let columns = target.config.columns();
    let format = target.config.destination.format;
    let schema = match format {
        Format::Csv => columns.iter().map(|c| c.name()).collect::<Vec<_>>().join(", "),
        Format::Parquet => parquet::schema(&columns.iter().map(|c| c.parquet()).collect::<Vec<_>>()),
    };
    let head = format!(
        "{{\"sourceBucket\":{},\"destinationBucket\":{},\"version\":\"2016-11-30\",\
         \"creationTimestamp\":\"{created}\",\"fileFormat\":\"{}\",\"fileSchema\":{},\"files\":[",
        serde_json::to_string(&report.bucket)?,
        serde_json::to_string(&target.config.destination.arn())?,
        format.name(),
        serde_json::to_string(&schema)?,
    );
    let mut first = true;
    let entry = move |file: &File| {
        let entry = format!(
            "{}{{\"key\":{},\"size\":{},\"MD5checksum\":\"{}\"}}",
            if first { "" } else { "," },
            serde_json::to_string(&file.key).expect("a string serializes"),
            file.size,
            file.md5
        );
        first = false;
        entry
    };
    let md5 = match deliver_listing(app, client, target, &manifest, "application/json", head, entry, "]}").await? {
        Ok(md5) => md5,
        Err(why) => return Ok(Err(why)),
    };
    let checksum = manifest.replace("/manifest.json", "/manifest.checksum");
    if let Err(why) = deliver(app, target, &checksum, "text/plain", http_body_util::Full::new(Bytes::from(md5))).await? {
        return Ok(Err(why));
    }
    let secs = |t: SystemTime| t.duration_since(SystemTime::UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64());
    let last = LastReport {
        started: secs(target.started),
        finished: secs(now),
        read: report.seen + read,
        files: report.files + i32::from(read > 0),
        manifest: manifest.clone(),
    };
    let next = next_due(target.config.frequency, target.started, now);
    let done: bool = client
        .query_one_cached(
            "SELECT pg_temp.cairn_inventory_done($1, $2, $3, $4, $5)",
            &[&report.bucket, &report.id, &report.generation, &serde_json::to_string(&last)?, &next],
        )
        .await?
        .get(0);
    // (A configuration changed meanwhile has its own report, due already.)
    let _ = done;
    Ok(Ok(()))
}

/// When the next report is due, after one that started at `started`: a
/// day after it (`Daily`), or the Sunday (UTC) after it (`Weekly`, as
/// S3's are); `now`, if that's past.
fn next_due(frequency: Frequency, started: SystemTime, now: SystemTime) -> SystemTime {
    let next = match frequency {
        Frequency::Daily => started + DAY,
        Frequency::Weekly => {
            // Day 0, the epoch, was a Thursday; Sunday is day 3 of a week.
            let today = Day::of(started).0;
            let sunday = today + 7 - (today - 3).rem_euclid(7);
            Day(sunday).midnight()
        }
    };
    next.max(now)
}

/// A time's date (`YYYY-MM-DD`) and time of day (`HH:MM`), UTC.
fn timestamp(time: SystemTime) -> (String, String) {
    let day = Day::of(time);
    let (year, month, date) = day.civil();
    let secs = time.duration_since(day.midnight()).map_or(0, |d| d.as_secs());
    (format!("{year:04}-{month:02}-{date:02}"), format!("{:02}:{:02}", secs / 3600, secs / 60 % 60))
}

/// A data file of a report, as `inventory_files` keeps it.
struct File {
    key: String,
    size: i64,
    md5: String,
}

/// Writes `head`, each of the report's data files as `each` writes it (read
/// a page at a time), and `tail` to `key`, streamed: its MD5 (hex), or why
/// the delivery failed.
#[allow(clippy::too_many_arguments)]
async fn deliver_listing(
    app: &Arc<App>,
    client: &Object,
    target: &Target<'_>,
    key: &str,
    content_type: &str,
    head: String,
    mut each: impl FnMut(&File) -> String + Send,
    tail: &str,
) -> anyhow::Result<Result<String, String>> {
    let report = target.report;
    let (sender, body) = channel_body();
    let sending = async move {
        let mut md5 = Md5::new();
        let mut send = async |chunk: String| -> anyhow::Result<()> {
            if chunk.is_empty() {
                return Ok(());
            }
            md5.update(chunk.as_bytes());
            sender.send(Ok(Frame::data(Bytes::from(chunk)))).await.map_err(|_| anyhow::anyhow!("the write stopped"))
        };
        let listed: anyhow::Result<()> = async {
            send(head).await?;
            let mut after = 0;
            loop {
                let rows = client
                    .query_cached(
                        "SELECT seq, key, size, md5 FROM inventory_files
                         WHERE bucket = $1 AND id = $2 AND generation = $3 AND seq > $4
                         ORDER BY seq LIMIT $5",
                        &[&report.bucket, &report.id, &report.generation, &after, &PAGE],
                    )
                    .await?;
                let mut chunk = String::new();
                for row in &rows {
                    after = row.get(0);
                    chunk.push_str(&each(&File { key: row.get(1), size: row.get(2), md5: row.get(3) }));
                }
                send(chunk).await?;
                if (rows.len() as i64) < PAGE {
                    break;
                }
            }
            send(tail.to_owned()).await
        }
        .await;
        match listed {
            Ok(()) => Ok(hex(&md5.finalize())),
            Err(e) => {
                let _ = sender.send(Err(io::Error::other(format!("{e:#}")))).await;
                Err(e)
            }
        }
    };
    let (md5, delivered) = tokio::join!(sending, deliver(app, target, key, content_type, body));
    if let Err(why) = delivered? {
        return Ok(Err(why));
    }
    Ok(Ok(md5?))
}

/// Writes `body` to `key` in the destination bucket, as S3 writes a
/// report's files: as the service, if the bucket's policy allows it (see
/// `authorized`), encrypted as the configuration says (else as the bucket's
/// default encryption does). Why it failed, if it did.
async fn deliver<B>(
    app: &Arc<App>,
    target: &Target<'_>,
    key: &str,
    content_type: &str,
    body: B,
) -> anyhow::Result<Result<(), String>>
where
    B: Body<Data = Bytes> + Unpin + Send,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let dest = &target.config.destination.bucket;
    if let Err(why) = authorized(app, target, key).await? {
        return Ok(Err(why));
    }
    let server = match &target.config.destination.encryption {
        Some(Encryption::S3) => Some(ServerSide::S3),
        Some(Encryption::Kms(id)) => {
            let key_id = crate::kms::KeyId::parse(id).ok_or_else(|| anyhow::anyhow!("the stored KMS key ID {id:?} isn't one"))?;
            Some(ServerSide::Kms(KmsRequest { key_id, context: None }))
        }
        None => match crate::s3::buckets::encryption::default_request(app, dest).await? {
            Ok(server) => server,
            Err(refused) => return Ok(Err(refusal(refused).await)),
        },
    };
    let payload = Payload::unchecked().at_most(MAX_UPLOAD).map_err(|_| anyhow::anyhow!("an unchecked payload has no length"))?;
    let response = crate::s3::objects::put::put_object(
        app,
        dest,
        key,
        content_type,
        "",
        "",
        body,
        payload,
        &Preconditions::default(),
        Wanted::new(None, server.as_ref()),
        target.report.setter,
        Lock::default(),
    )
    .await?;
    if response.status() == StatusCode::OK {
        return Ok(Ok(()));
    }
    Ok(Err(format!("writing {key} to bucket {dest}: {}", refusal(response).await)))
}

/// What an S3 error response says: its code and message.
async fn refusal(response: hyper::Response<http_body_util::Full<Bytes>>) -> String {
    let status = response.status();
    let body = response.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
    let body = String::from_utf8_lossy(&body);
    let element = |name: &str| {
        let open = format!("<{name}>");
        let start = body.find(&open)? + open.len();
        let end = body[start..].find(&format!("</{name}>"))? + start;
        Some(body[start..end].to_owned())
    };
    match (element("Code"), element("Message")) {
        (Some(code), Some(message)) => format!("{code}: {message}"),
        (Some(code), None) => code,
        _ => status.to_string(),
    }
}

/// Whether the destination bucket's policy allows the report's write of
/// `key`, as S3 checks it: `s3:PutObject` by the `s3.amazonaws.com`
/// service (see `s3::service`), with `s3:x-amz-acl`
/// `bucket-owner-full-control`. Why not, if it doesn't.
async fn authorized(app: &App, target: &Target<'_>, key: &str) -> anyhow::Result<Result<(), String>> {
    let dest = &target.config.destination.bucket;
    let Some(destination) = Destination::load(app, dest).await? else {
        return Ok(Err(format!("the destination bucket {dest} doesn't exist")));
    };
    if let Some(expected) = &target.config.destination.account
        && *expected != destination.owner
    {
        return Ok(Err(format!("the destination bucket {dest} isn't account {expected}'s")));
    }
    let mut context = Context::default();
    context.set("s3:x-amz-acl", "bucket-owner-full-control");
    match &target.config.destination.encryption {
        Some(Encryption::S3) => context.set("s3:x-amz-server-side-encryption", "AES256"),
        Some(Encryption::Kms(id)) => {
            context.set("s3:x-amz-server-side-encryption", "aws:kms");
            context.set("s3:x-amz-server-side-encryption-aws-kms-key-id", format!("arn:aws:kms:{id}"));
        }
        None => {}
    }
    Ok(match destination.allows_put(SERVICE, &target.report.bucket, &target.account, key, context) {
        true => Ok(()),
        false => Err(format!(
            "the policy of bucket {dest} doesn't allow {SERVICE} to write {key} (see S3's inventory destination policy)"
        )),
    })
}

#[cfg(test)]
mod e2e;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_are_about_ten_minutes_of_the_rate() {
        assert_eq!(rows_per_file(1_000_000), 166_666);
        assert_eq!(rows_per_file(1000), MIN_FILE_ROWS);
        assert_eq!(rows_per_file(i64::MAX), MAX_FILE_ROWS);
    }

    #[test]
    fn weekly_reports_are_due_on_sundays() {
        // 2026-11-16 was a Monday.
        let monday = Day(20_773).midnight() + Duration::from_secs(5 * 3600);
        assert_eq!(timestamp(monday), ("2026-11-16".to_owned(), "05:00".to_owned()));
        let sunday = next_due(Frequency::Weekly, monday, monday);
        assert_eq!(timestamp(sunday), ("2026-11-22".to_owned(), "00:00".to_owned()));
        // A report that started on a Sunday is next due the Sunday after.
        assert_eq!(timestamp(next_due(Frequency::Weekly, sunday, sunday)).0, "2026-11-29");
        assert_eq!(next_due(Frequency::Daily, monday, monday), monday + DAY);
        // Late, it's due right away.
        let late = monday + 30 * DAY;
        assert_eq!(next_due(Frequency::Daily, monday, late), late);
    }

    #[test]
    fn times_are_iso_to_the_millisecond() {
        assert_eq!(iso_millis(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_millis(1_763_269_323_045), "2025-11-16T05:02:03.045Z");
        assert_eq!(iso_millis(-1), "1969-12-31T23:59:59.999Z");
        // As lifecycle expiration dates were.
        assert_eq!(iso_millis(millis(Day(20_773).midnight())), Day(20_773).to_iso());
        let key = csv_value(Column::Key, &Value::Text("a b/ü".to_owned()));
        assert_eq!(key, Encoding::Url.xml("a b/ü"));
        assert_eq!(csv_value(Column::Bucket, &Value::Null), "");
    }

    #[test]
    fn values_are_quoted() {
        let mut line = String::new();
        push_value(&mut line, "a");
        push_value(&mut line, "say \"hi\"");
        push_value(&mut line, "");
        assert_eq!(line, "\"a\",\"say \"\"hi\"\"\",\"\"");
    }
}
