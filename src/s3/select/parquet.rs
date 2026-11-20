//! Parquet input (`<InputSerialization><Parquet/>`), with the `parquet`
//! crate, as AWS's user guide describes it.
//!
//! A Parquet file isn't read through, as a CSV or JSON one is: its footer,
//! at its end, says where its row groups and their columns' chunks are. So
//! the footer is read by a ranged GET, and then, of each row group the
//! query's condition doesn't rule out by its columns' statistics (see
//! `prune`), only the chunks of the columns the query reads. Each chunk is
//! read by one GET that streams as its pages are decoded (`Streamed`), on a
//! blocking thread, while what the query selects streams out: what a query
//! holds is a few frames and a page or so of each column it reads, however
//! large the file and its row groups are. Every read after the first is of
//! the version the first read (`If-Match`).
//!
//! A row is a record as a JSON object is: a struct of its columns, by
//! name. Types, as S3 Select maps them: integers (`INT(8)` to `INT(64)`,
//! and unsigned ones) as integers; `DECIMAL` as a decimal (a float here,
//! as elsewhere); strings and `ENUM` as strings; `DATE` and `TIMESTAMP`
//! (`MILLIS`, `MICROS`, `NANOS`) as timestamps, at `Z` if adjusted to UTC,
//! else at an unknown offset; `LIST`s as lists. And what S3 Select's guide
//! doesn't name: booleans, floats and doubles as themselves, groups and
//! `MAP`s as structs, and `BINARY` without a type as a string, if it's
//! UTF-8. `INT96` timestamps aren't supported, as in S3, nor are `TIME`s:
//! a query that reads such a column is refused (`UnsupportedParquetType`).
//! Columns may be uncompressed, or compressed with Snappy or GZIP, S3
//! Select's (`ParquetUnsupportedCompressionCodec` otherwise).
//!
//! A `ScanRange` reads the row groups that start in it, as in S3.

mod prune;

use std::io::{self, Read};
use std::sync::{Arc, Mutex};

use bytes::{Buf, Bytes, BytesMut};
use http_body_util::BodyExt;
use hyper::{HeaderMap, Response, StatusCode, header::HeaderValue};
use parquet::{
    basic::{Compression, ConvertedType, LogicalType, TimeUnit, Type as PhysicalType},
    file::{
        metadata::ParquetMetaData,
        properties::ReaderProperties,
        reader::{ChunkReader, Length},
        serialized_reader::SerializedRowGroupReader,
    },
    record::{Field, Row, reader::RowIter},
    schema::types::{Type, TypePtr},
};
use tokio::sync::mpsc;
use uuid::Uuid;

use super::{
    Events, KEEP_ALIVE, Parsed, Scanner, SelectError, eventstream,
    output::Output,
    request::{Input, ScanRange},
    sql::{Query, Step},
    timestamp::{Precision, Timestamp},
    value::Value,
};
use crate::{
    App,
    batch::parquet::{FOOTER_GUESS, MAX_FOOTER, metadata, metadata_length},
    body::{FrameSender, ResBody, channel_body},
    s3::{conditional::Preconditions, sse_c::CustomerKey},
};

/// The largest row group S3 Select reads, uncompressed.
pub const MAX_GROUP: u64 = 512 << 20;

fn not_parquet(why: impl std::fmt::Display) -> SelectError {
    SelectError::new(
        "ParquetParsingError",
        format!("The object isn't a Parquet file S3 Select can read: {why}."),
    )
}

fn unsupported_type(column: &str, what: &str) -> SelectError {
    SelectError::new(
        "UnsupportedParquetType",
        format!("The column {column} is of a type S3 Select doesn't read: {what}."),
    )
}

/// Where a Parquet object's bytes are read from: ranged GETs of the version
/// the request's first read found.
pub struct Source {
    pub app: Arc<App>,
    pub bucket: String,
    pub key: String,
    pub customer_key: Option<CustomerKey>,
    pub role: Option<Uuid>,
    pub etag: Option<HeaderValue>,
    pub size: u64,
}

impl Source {
    /// Its `length` bytes from `start`, or the response refusing to read
    /// them.
    async fn read(
        &self,
        start: u64,
        length: u64,
    ) -> anyhow::Result<Result<Bytes, Response<ResBody>>> {
        Ok(match self.open(start, start + length).await? {
            Ok(body) => Ok(body.collect().await?.to_bytes()),
            Err(refused) => Err(refused),
        })
    }

    /// Its bytes from `start` to `end` (exclusive), as they stream, or the
    /// response refusing to read them.
    async fn open(
        &self,
        start: u64,
        end: u64,
    ) -> anyhow::Result<Result<ResBody, Response<ResBody>>> {
        let mut conditions = HeaderMap::new();
        if let Some(etag) = &self.etag {
            conditions.insert(hyper::header::IF_MATCH, etag.clone());
        }
        let range = format!("bytes={start}-{}", end - 1);
        let response = crate::s3::objects::get::get_object(
            &self.app,
            &self.bucket,
            &self.key,
            None,
            Some(&range),
            None,
            &Preconditions::from_headers(&conditions),
            self.customer_key.as_ref(),
            self.role,
            false,
        )
        .await?;
        if !matches!(
            response.status(),
            StatusCode::OK | StatusCode::PARTIAL_CONTENT
        ) {
            return Ok(Err(response));
        }
        Ok(Ok(response.into_body()))
    }
}

/// A row group's chunks of the columns a query reads, each read by one GET
/// that streams as the chunk's pages are decoded, from a blocking thread:
/// only what's in flight, and the page being read, is held. (Its pages are
/// read in order; a read before where its GET is starts another.)
struct Streamed {
    size: u64,
    streams: Arc<Mutex<Streams>>,
}

struct Streams {
    source: Arc<Source>,
    runtime: tokio::runtime::Handle,
    chunks: Vec<Chunk>,
    /// The object's bytes read.
    scanned: u64,
    /// Why reading failed, if it did: what the query fails with.
    failure: Option<SelectError>,
}

/// A column's chunk, and its GET.
struct Chunk {
    start: u64,
    /// Exclusive.
    end: u64,
    /// Where `pending` starts.
    at: u64,
    /// What the GET has sent and nothing has read yet.
    pending: Bytes,
    body: Option<ResBody>,
}

impl Streamed {
    /// The chunks (start, length) of `source` a row group's reading reads.
    fn new(source: Arc<Source>, chunks: &[(u64, u64)]) -> Streamed {
        let streams = Streams {
            runtime: tokio::runtime::Handle::current(),
            chunks: chunks
                .iter()
                .map(|&(start, length)| Chunk {
                    start,
                    end: start + length,
                    at: start,
                    pending: Bytes::new(),
                    body: None,
                })
                .collect(),
            scanned: 0,
            failure: None,
            source,
        };
        Streamed {
            size: streams.source.size,
            streams: Arc::new(Mutex::new(streams)),
        }
    }

    /// How many of the object's bytes it read, and why it failed, if it did.
    fn finish(&self) -> (u64, Option<SelectError>) {
        let mut streams = self.streams.lock().unwrap_or_else(|e| e.into_inner());
        (streams.scanned, streams.failure.take())
    }
}

impl Streams {
    /// The chunk holding `offset`; or that ends there (for a read of
    /// nothing), if none does: chunks can be next to each other.
    fn chunk(&self, offset: u64) -> io::Result<usize> {
        self.chunks
            .iter()
            .position(|c| c.start <= offset && offset < c.end)
            .or_else(|| self.chunks.iter().position(|c| c.end == offset))
            .ok_or_else(|| io::Error::other(format!("byte {offset} isn't in a chunk being read")))
    }

    /// Fails with `failure`, which the query fails with.
    fn fail(&mut self, failure: SelectError) -> io::Error {
        let error = io::Error::other(failure.message.clone());
        self.failure.get_or_insert(failure);
        error
    }

    /// Chunk `i`'s GET from `offset`.
    fn open(&mut self, i: usize, offset: u64) -> io::Result<()> {
        let end = self.chunks[i].end;
        let opened = self.runtime.block_on(self.source.open(offset, end));
        let body = match opened {
            Ok(Ok(body)) => body,
            // The object changed (or went) since its footer was read.
            Ok(Err(_)) => {
                return Err(self.fail(SelectError::new(
                    "InternalError",
                    "The object changed while it was being read. Please try again.",
                )));
            }
            Err(e) => {
                eprintln!("S3 Select: reading the object failed: {e:#}");
                return Err(self.fail(internal()));
            }
        };
        let chunk = &mut self.chunks[i];
        chunk.body = Some(body);
        chunk.at = offset;
        chunk.pending = Bytes::new();
        Ok(())
    }

    /// More of chunk `i`, into its `pending`: `false` if there's none.
    fn fill(&mut self, i: usize) -> io::Result<bool> {
        let chunk = &mut self.chunks[i];
        let Some(body) = chunk.body.as_mut() else {
            return Ok(false);
        };
        loop {
            match self.runtime.block_on(body.frame()) {
                None => return Ok(false),
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        self.scanned += data.len() as u64;
                        chunk.pending = data;
                        return Ok(true);
                    }
                }
                Some(Err(e)) => {
                    eprintln!("S3 Select: reading the object failed: {e}");
                    return Err(self.fail(internal()));
                }
            }
        }
    }

    /// Takes chunk `i`'s GET to `offset`: on, if it's ahead, else a new one.
    fn seek(&mut self, i: usize, offset: u64) -> io::Result<()> {
        if self.chunks[i].body.is_none() || offset < self.chunks[i].at {
            return self.open(i, offset);
        }
        while self.chunks[i].at < offset {
            if self.chunks[i].pending.is_empty() && !self.fill(i)? {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let chunk = &mut self.chunks[i];
            let n = chunk.pending.len().min((offset - chunk.at) as usize);
            chunk.pending.advance(n);
            chunk.at += n as u64;
        }
        Ok(())
    }

    /// Reads what of `out` it can from `offset`.
    fn read(&mut self, offset: u64, out: &mut [u8]) -> io::Result<usize> {
        let i = self.chunk(offset)?;
        self.seek(i, offset)?;
        if self.chunks[i].pending.is_empty() && !self.fill(i)? {
            return Ok(0);
        }
        let chunk = &mut self.chunks[i];
        let n = out.len().min(chunk.pending.len());
        chunk.pending.copy_to_slice(&mut out[..n]);
        chunk.at += n as u64;
        Ok(n)
    }

    /// The `length` bytes from `offset`.
    fn bytes(&mut self, offset: u64, length: usize) -> io::Result<Bytes> {
        let i = self.chunk(offset)?;
        self.seek(i, offset)?;
        // Within what's arrived: shared, not copied.
        if self.chunks[i].pending.len() >= length {
            let chunk = &mut self.chunks[i];
            chunk.at += length as u64;
            return Ok(chunk.pending.split_to(length));
        }
        let mut out = BytesMut::with_capacity(length);
        while out.len() < length {
            if self.chunks[i].pending.is_empty() && !self.fill(i)? {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let chunk = &mut self.chunks[i];
            let n = (length - out.len()).min(chunk.pending.len());
            out.extend_from_slice(&chunk.pending.split_to(n));
            chunk.at += n as u64;
        }
        Ok(out.freeze())
    }
}

/// A reader of a chunk from where it was asked for, which reads (and moves)
/// the chunk's GET.
struct ChunkRead {
    streams: Arc<Mutex<Streams>>,
    at: u64,
}

impl Read for ChunkRead {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut streams = self.streams.lock().unwrap_or_else(|e| e.into_inner());
        let n = streams.read(self.at, out)?;
        self.at += n as u64;
        Ok(n)
    }
}

impl Length for Streamed {
    fn len(&self) -> u64 {
        self.size
    }
}

impl ChunkReader for Streamed {
    type T = ChunkRead;

    fn get_read(&self, start: u64) -> parquet::errors::Result<ChunkRead> {
        Ok(ChunkRead {
            streams: self.streams.clone(),
            at: start,
        })
    }

    fn get_bytes(&self, start: u64, length: usize) -> parquet::errors::Result<Bytes> {
        let mut streams = self.streams.lock().unwrap_or_else(|e| e.into_inner());
        streams
            .bytes(start, length)
            .map_err(|e| parquet::errors::ParquetError::External(Box::new(e)))
    }
}

/// What a query reads of a file.
struct Plan {
    /// The top-level fields it reads, in the file's order.
    fields: Vec<TypePtr>,
    /// Their leaf columns, by their index among the file's.
    columns: Vec<usize>,
    /// The schema of what it reads; `None` if it reads no column (`COUNT(*)`).
    projection: Option<Type>,
    /// The row groups it reads.
    groups: Vec<usize>,
}

impl Plan {
    fn new(
        metadata: &ParquetMetaData,
        query: &Query,
        scan_range: Option<ScanRange>,
        size: u64,
    ) -> Result<Plan, SelectError> {
        let schema = metadata.file_metadata().schema_descr();
        let root = schema.root_schema();
        // The fields its paths start with (by name, regardless of case
        // unless quoted), or all of them.
        let (paths, all) = query.paths();
        let reads = |name: &str| {
            all || paths.iter().any(|path| match path.first() {
                Some(Step::Field {
                    name: n,
                    quoted: true,
                }) => n == name,
                Some(Step::Field {
                    name: n,
                    quoted: false,
                }) => n.eq_ignore_ascii_case(name),
                _ => false,
            })
        };
        let fields: Vec<TypePtr> = root
            .get_fields()
            .iter()
            .filter(|f| reads(f.name()))
            .cloned()
            .collect();
        let columns: Vec<usize> = (0..schema.num_columns())
            .filter(|&i| reads(schema.get_column_root(i).name()))
            .collect();
        for &i in &columns {
            let column = schema.column(i);
            let name = column.path().string();
            if column.physical_type() == PhysicalType::INT96 {
                return Err(unsupported_type(&name, "INT96 timestamps"));
            }
            let time = matches!(column.logical_type_ref(), Some(LogicalType::Time { .. }))
                || matches!(
                    column.converted_type(),
                    ConvertedType::TIME_MILLIS | ConvertedType::TIME_MICROS
                );
            if time {
                return Err(unsupported_type(&name, "TIME"));
            }
        }
        let projection = match fields.is_empty() {
            true => None,
            false => Some(
                Type::group_type_builder(root.name())
                    .with_fields(fields.clone())
                    .build()
                    .map_err(not_parquet)?,
            ),
        };
        // A range's row groups are those that start in it.
        let range = scan_range.map(|range| range.bytes(size));
        let groups: Vec<usize> = (0..metadata.num_row_groups())
            .filter(|&g| match range {
                None => true,
                Some(None) => false,
                Some(Some((first, last))) => {
                    let group = metadata.row_group(g);
                    let start = (0..group.num_columns())
                        .map(|i| group.column(i).byte_range().0)
                        .min()
                        .unwrap_or(0);
                    (first..=last).contains(&start)
                }
            })
            // And of those, the ones its condition doesn't rule out.
            .filter(|&g| match &query.condition {
                None => true,
                Some(condition) => prune::may_match(metadata.row_group(g), schema, condition),
            })
            .collect();
        for &g in &groups {
            let group = metadata.row_group(g);
            if group.total_byte_size() as u64 > MAX_GROUP {
                return Err(SelectError::new(
                    "OverMaxParquetBlockSize",
                    format!(
                        "The Parquet file has a row group of more than {} MB, uncompressed: S3 Select's most.",
                        MAX_GROUP >> 20
                    ),
                ));
            }
            for &i in &columns {
                let codec = group.column(i).compression();
                if !matches!(
                    codec,
                    Compression::UNCOMPRESSED | Compression::SNAPPY | Compression::GZIP(_)
                ) {
                    return Err(SelectError::new(
                        "ParquetUnsupportedCompressionCodec",
                        format!(
                            "The column {} is compressed with {}: S3 Select reads only uncompressed, Snappy and GZIP columns.",
                            schema.column(i).path().string(),
                            // Its name, without its level.
                            codec.to_string().split('(').next().unwrap_or_default()
                        ),
                    ));
                }
            }
        }
        Ok(Plan {
            fields,
            columns,
            projection,
            groups,
        })
    }
}

/// Reads `source`'s footer: its metadata, and how many bytes reading it
/// took.
async fn footer(
    source: &Source,
) -> anyhow::Result<Result<(ParquetMetaData, u64), Response<ResBody>>> {
    // "PAR1", the footer's length, "PAR1".
    if source.size < 12 {
        return Ok(Err(not_parquet("it's too short").response()));
    }
    let guess = FOOTER_GUESS.min(source.size);
    let mut end = match source.read(source.size - guess, guess).await? {
        Ok(end) => end,
        Err(refused) => return Ok(Err(refused)),
    };
    let needed = match metadata_length(&end) {
        Ok(length) => length + 8,
        Err(e) => return Ok(Err(not_parquet(e).response())),
    };
    if needed > MAX_FOOTER || needed > source.size {
        return Ok(Err(not_parquet("its footer is too long").response()));
    }
    if needed > end.len() as u64 {
        end = match source.read(source.size - needed, needed).await? {
            Ok(end) => end,
            Err(refused) => return Ok(Err(refused)),
        };
    }
    match metadata(&end) {
        Ok(metadata) => Ok(Ok((metadata, end.len() as u64))),
        Err(e) => Ok(Err(not_parquet(e).response())),
    }
}

/// Runs `query` over the Parquet object `source`: the response refusing it,
/// if its footer says it can't be (or isn't Parquet), else a 200 streaming
/// its events.
pub async fn select(
    source: Source,
    query: Query,
    output: Output,
    scan_range: Option<ScanRange>,
    progress: bool,
) -> anyhow::Result<Response<ResBody>> {
    let (metadata, footer_size) = match footer(&source).await? {
        Ok(footer) => footer,
        Err(refused) => return Ok(refused),
    };
    let plan = match Plan::new(&metadata, &query, scan_range, source.size) {
        Ok(plan) => plan,
        Err(refused) => return Ok(refused.response()),
    };
    let scanner = Scanner::new(query, Input::Parquet, output);
    let (tx, events) = channel_body();
    tokio::spawn(stream(
        Arc::new(source),
        Arc::new(metadata),
        Arc::new(plan),
        scanner,
        tx,
        progress,
        footer_size,
    ));
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/octet-stream")
        .body(events)
        .expect("a valid response"))
}

fn internal() -> SelectError {
    SelectError::new(
        "InternalError",
        "We encountered an internal error reading the object. Please try again.",
    )
}

/// Streams what `scanner` selects from `plan`'s row groups to `tx`, as
/// events.
async fn stream(
    source: Arc<Source>,
    metadata: Arc<ParquetMetaData>,
    plan: Arc<Plan>,
    mut scanner: Scanner,
    tx: FrameSender,
    progress: bool,
    footer_size: u64,
) {
    let mut events = Events::new(tx, progress, footer_size);
    let result: Result<(), SelectError> = async {
        for &group in &plan.groups {
            if scanner.done {
                break;
            }
            let meta = metadata.row_group(group);
            // Its chunks of the columns read, each by a GET of its own.
            let reader = (!plan.columns.is_empty()).then(|| {
                let chunks: Vec<(u64, u64)> = plan
                    .columns
                    .iter()
                    .map(|&i| meta.column(i).byte_range())
                    .collect();
                Arc::new(Streamed::new(source.clone(), &chunks))
            });
            events.stats.processed += plan
                .columns
                .iter()
                .map(|&i| meta.column(i).uncompressed_size() as u64)
                .sum::<u64>();
            // Decoded on a blocking thread, which sends what it writes as
            // it goes.
            let (pieces, mut written) = mpsc::channel::<Vec<u8>>(4);
            let (metadata, plan, read) = (metadata.clone(), plan.clone(), reader.clone());
            let job = tokio::task::spawn_blocking(move || {
                let result = decode(&metadata, &plan, group, read, &mut scanner, &pieces);
                (scanner, result)
            });
            loop {
                match tokio::time::timeout(KEEP_ALIVE, written.recv()).await {
                    Ok(Some(piece)) => {
                        if !events.records(&piece).await {
                            return Ok(());
                        }
                    }
                    Ok(None) => break,
                    // Nothing yet: say so, now and then.
                    Err(_) => {}
                }
                if !events.tick().await {
                    return Ok(());
                }
            }
            let (returned, result) = job.await.map_err(|_| internal())?;
            scanner = returned;
            // A read's failure is why decoding failed, if one failed.
            let (scanned, failure) = reader.as_ref().map(|r| r.finish()).unwrap_or_default();
            events.stats.scanned += scanned;
            if let Some(failure) = failure {
                return Err(failure);
            }
            result?;
        }
        scanner.finish()?;
        if !events.flush(&mut scanner).await {
            return Ok(());
        }
        let stats = events.stats;
        if events.send(stats.stats()).await {
            events.send(eventstream::end()).await;
        }
        Ok(())
    }
    .await;
    if let Err(e) = result {
        events.send(eventstream::error(e.code, &e.message)).await;
    }
}

/// Runs `scanner` over row group `group`'s rows, from `reader` (of its
/// chunks of `plan`'s columns), sending what it writes to `pieces`.
fn decode<R: ChunkReader + 'static>(
    metadata: &ParquetMetaData,
    plan: &Plan,
    group: usize,
    reader: Option<Arc<R>>,
    scanner: &mut Scanner,
    pieces: &mpsc::Sender<Vec<u8>>,
) -> Result<(), SelectError> {
    // Whether what's written could be sent (the client is still there).
    let send = |scanner: &mut Scanner, at_least: usize| {
        if scanner.out.len() < at_least.max(1) {
            return true;
        }
        pieces
            .blocking_send(std::mem::take(&mut scanner.out))
            .is_ok()
    };
    let meta = metadata.row_group(group);
    match (reader, &plan.projection) {
        // No columns: only how many rows there are.
        (None, _) | (_, None) => {
            for _ in 0..meta.num_rows() {
                scanner.record(Parsed::Json(Value::Struct(Vec::new())))?;
                if scanner.done || !send(scanner, super::MAX_EVENT) {
                    break;
                }
            }
        }
        (Some(reader), Some(projection)) => {
            let reader = SerializedRowGroupReader::new(
                reader,
                meta,
                None,
                Arc::new(ReaderProperties::builder().build()),
            )
            .map_err(not_parquet)?;
            let rows =
                RowIter::from_row_group(Some(projection.clone()), &reader).map_err(not_parquet)?;
            for row in rows {
                let row = row.map_err(not_parquet)?;
                scanner.record(Parsed::Json(record(&row, &plan.fields)?))?;
                if scanner.done || !send(scanner, super::MAX_EVENT) {
                    break;
                }
            }
        }
    }
    send(scanner, 1);
    Ok(())
}

/// A row, as a record: a struct of its columns, as their `fields` say.
fn record(row: &Row, fields: &[TypePtr]) -> Result<Value, SelectError> {
    let mut out = Vec::with_capacity(fields.len());
    for ((name, field), ty) in row.get_column_iter().zip(fields) {
        out.push((name.clone(), value(field, Some(ty))?));
    }
    Ok(Value::Struct(out))
}

/// A field's value. `ty` is its column's type, if known (for a top-level
/// column): what says a timestamp's unit and whether it's at UTC.
fn value(field: &Field, ty: Option<&TypePtr>) -> Result<Value, SelectError> {
    let timestamp = ty.and_then(|ty| match ty.get_basic_info().logical_type_ref() {
        Some(LogicalType::Timestamp {
            unit,
            is_adjusted_to_u_t_c,
        }) => Some((*unit, *is_adjusted_to_u_t_c)),
        _ => None,
    });
    let utc = timestamp.as_ref().is_none_or(|(_, utc)| *utc);
    let at = |nanos: i128, precision| {
        Ok(Value::Timestamp(Timestamp::from_unix(
            nanos, precision, utc,
        )?))
    };
    Ok(match field {
        Field::Null => Value::Null,
        Field::Bool(b) => Value::Bool(*b),
        Field::Byte(i) => Value::Int(i64::from(*i)),
        Field::Short(i) => Value::Int(i64::from(*i)),
        Field::Int(i) => Value::Int(i64::from(*i)),
        // Nanoseconds since 1970 have no field of their own.
        Field::Long(n) if matches!(timestamp, Some((TimeUnit::NANOS, _))) => {
            return at(i128::from(*n), Precision::Fraction(9));
        }
        Field::Long(i) => Value::Int(*i),
        Field::UByte(i) => Value::Int(i64::from(*i)),
        Field::UShort(i) => Value::Int(i64::from(*i)),
        Field::UInt(i) => Value::Int(i64::from(*i)),
        Field::ULong(i) => match i64::try_from(*i) {
            Ok(i) => Value::Int(i),
            Err(_) => Value::Float(*i as f64),
        },
        Field::Float16(f) => Value::Float(f.to_f64()),
        Field::Float(f) => Value::Float(f64::from(*f)),
        Field::Double(f) => Value::Float(*f),
        // Its text is exact; a float is what decimals are here.
        Field::Decimal(_) => Value::Float(field.to_string().parse().unwrap_or(f64::NAN)),
        Field::Str(s) => Value::Str(s.clone()),
        Field::Bytes(b) => match std::str::from_utf8(b.data()) {
            Ok(s) => Value::Str(s.to_owned()),
            Err(_) => return Err(unsupported_type("a column", "BINARY that isn't UTF-8")),
        },
        Field::Date(days) => return at(i128::from(*days) * 86_400 * 1_000_000_000, Precision::Day),
        Field::TimestampMillis(ms) => {
            return at(i128::from(*ms) * 1_000_000, Precision::Fraction(3));
        }
        Field::TimestampMicros(us) => return at(i128::from(*us) * 1_000, Precision::Fraction(6)),
        Field::TimeMillis(_) | Field::TimeMicros(_) => {
            return Err(unsupported_type("a column", "TIME"));
        }
        Field::Group(row) => {
            let mut fields = Vec::new();
            for (name, field) in row.get_column_iter() {
                fields.push((name.clone(), value(field, None)?));
            }
            Value::Struct(fields)
        }
        Field::ListInternal(list) => Value::List(
            list.elements()
                .iter()
                .map(|f| value(f, None))
                .collect::<Result<_, _>>()?,
        ),
        Field::MapInternal(map) => {
            let mut fields = Vec::new();
            for (key, field) in map.entries() {
                fields.push((value(key, None)?.to_text(), value(field, None)?));
            }
            Value::Struct(fields)
        }
    })
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::{batch::parquet::Fetched, s3::select::sql};
    use parquet::{
        data_type::{BoolType, ByteArray, ByteArrayType, DoubleType, Int32Type, Int64Type},
        file::{properties::WriterProperties, writer::SerializedFileWriter},
        schema::parser::parse_message_type,
    };

    /// The schema of `file`'s files.
    const SCHEMA: &str = "message schema {
        REQUIRED INT64 id;
        OPTIONAL BYTE_ARRAY name (UTF8);
        OPTIONAL DOUBLE score;
        OPTIONAL INT32 day (DATE);
        OPTIONAL INT64 at (TIMESTAMP(MILLIS,true));
        OPTIONAL INT64 local (TIMESTAMP(NANOS,false));
        OPTIONAL INT32 price (DECIMAL(9,2));
        OPTIONAL BOOLEAN flag;
        OPTIONAL group tags (LIST) {
            REPEATED group list {
                OPTIONAL BYTE_ARRAY element (UTF8);
            }
        }
    }";

    /// A file of `rows` rows, `per_group` to a row group, its columns
    /// compressed with `codec`. Row `i`: `id` i; `name` "name i", but null
    /// every 5th; `score` 1.5 i; `day` i days after 2022-01-08; `at` i
    /// seconds after 2023-11-14T22:13:20Z; `local` (not at UTC) i ns after
    /// 2023-11-14T22:13:20; `price` i.25; `flag` whether i is even; `tags`
    /// null, empty, or `["a i", null]`, in turn.
    pub fn file(rows: usize, per_group: usize, codec: Compression) -> Vec<u8> {
        let props = WriterProperties::builder().set_compression(codec).build();
        file_with(rows, per_group, props)
    }

    /// `file`'s, written with `props`.
    fn file_with(rows: usize, per_group: usize, props: WriterProperties) -> Vec<u8> {
        let schema = Arc::new(parse_message_type(SCHEMA).unwrap());
        let mut writer = SerializedFileWriter::new(Vec::new(), schema, Arc::new(props)).unwrap();
        for start in (0..rows).step_by(per_group) {
            let ids: Vec<i64> = (start..rows.min(start + per_group))
                .map(|i| i as i64)
                .collect();
            // Present everywhere (1), or as `present` says.
            let levels = |present: &dyn Fn(i64) -> bool| -> Vec<i16> {
                ids.iter().map(|&i| i16::from(present(i))).collect()
            };
            let all = levels(&|_| true);
            let mut group = writer.next_row_group().unwrap();
            let mut column = 0;
            while let Some(mut writer) = group.next_column().unwrap() {
                match column {
                    0 => {
                        writer
                            .typed::<Int64Type>()
                            .write_batch(&ids, None, None)
                            .unwrap();
                    }
                    1 => {
                        let named = |i: i64| i % 5 != 0;
                        let names: Vec<ByteArray> = ids
                            .iter()
                            .filter(|&&i| named(i))
                            .map(|i| ByteArray::from(format!("name {i}").as_str()))
                            .collect();
                        writer
                            .typed::<ByteArrayType>()
                            .write_batch(&names, Some(&levels(&named)), None)
                            .unwrap();
                    }
                    2 => {
                        let scores: Vec<f64> = ids.iter().map(|&i| i as f64 * 1.5).collect();
                        writer
                            .typed::<DoubleType>()
                            .write_batch(&scores, Some(&all), None)
                            .unwrap();
                    }
                    3 => {
                        let days: Vec<i32> = ids.iter().map(|&i| 19_000 + i as i32).collect();
                        writer
                            .typed::<Int32Type>()
                            .write_batch(&days, Some(&all), None)
                            .unwrap();
                    }
                    4 => {
                        let at: Vec<i64> =
                            ids.iter().map(|&i| 1_700_000_000_000 + i * 1000).collect();
                        writer
                            .typed::<Int64Type>()
                            .write_batch(&at, Some(&all), None)
                            .unwrap();
                    }
                    5 => {
                        let local: Vec<i64> =
                            ids.iter().map(|&i| 1_700_000_000_000_000_000 + i).collect();
                        writer
                            .typed::<Int64Type>()
                            .write_batch(&local, Some(&all), None)
                            .unwrap();
                    }
                    6 => {
                        let prices: Vec<i32> = ids.iter().map(|&i| i as i32 * 100 + 25).collect();
                        writer
                            .typed::<Int32Type>()
                            .write_batch(&prices, Some(&all), None)
                            .unwrap();
                    }
                    7 => {
                        let flags: Vec<bool> = ids.iter().map(|&i| i % 2 == 0).collect();
                        writer
                            .typed::<BoolType>()
                            .write_batch(&flags, Some(&all), None)
                            .unwrap();
                    }
                    _ => {
                        // Null (definition 0), empty (1), or two elements:
                        // one (3), and a null (2).
                        let (mut values, mut defs, mut reps) = (Vec::new(), Vec::new(), Vec::new());
                        for &i in &ids {
                            match i % 3 {
                                0 => (defs.push(0), reps.push(0)),
                                1 => (defs.push(1), reps.push(0)),
                                _ => {
                                    values.push(ByteArray::from(format!("a {i}").as_str()));
                                    defs.extend([3, 2]);
                                    reps.extend([0, 1]);
                                    ((), ())
                                }
                            };
                        }
                        writer
                            .typed::<ByteArrayType>()
                            .write_batch(&values, Some(&defs), Some(&reps))
                            .unwrap();
                    }
                }
                writer.close().unwrap();
                column += 1;
            }
            group.close().unwrap();
        }
        writer.into_inner().unwrap()
    }

    /// What `sql` selects from `file` (in a `range` of it), written as
    /// JSON, reading only the chunks `stream` would.
    fn run(sql: &str, file: &[u8], range: Option<ScanRange>) -> Result<String, SelectError> {
        let metadata = metadata(file).unwrap();
        let query = sql::parse(sql)?;
        let plan = Plan::new(&metadata, &query, range, file.len() as u64)?;
        let output = Output::Json {
            record_delimiter: b"\n".to_vec(),
        };
        let mut scanner = Scanner::new(query, Input::Parquet, output);
        let mut out = Vec::new();
        for &group in &plan.groups {
            let meta = metadata.row_group(group);
            let fetched = (!plan.columns.is_empty()).then(|| Fetched {
                size: file.len() as u64,
                parts: plan
                    .columns
                    .iter()
                    .map(|&i| {
                        let (start, length) = meta.column(i).byte_range();
                        let bytes = &file[start as usize..(start + length) as usize];
                        (start, Bytes::copy_from_slice(bytes))
                    })
                    .collect(),
            });
            let (pieces, mut written) = mpsc::channel(1 << 16);
            decode(
                &metadata,
                &plan,
                group,
                fetched.map(Arc::new),
                &mut scanner,
                &pieces,
            )?;
            drop(pieces);
            while let Ok(piece) = written.try_recv() {
                out.extend(piece);
            }
            if scanner.done {
                break;
            }
        }
        scanner.finish()?;
        out.extend(std::mem::take(&mut scanner.out));
        Ok(String::from_utf8(out).unwrap())
    }

    #[test]
    fn reads_its_types() {
        let file = file(3, 10, Compression::SNAPPY);
        let got = run("SELECT * FROM S3Object s WHERE s.id = 2", &file, None).unwrap();
        assert_eq!(
            got,
            "{\"id\":2,\"name\":\"name 2\",\"score\":3.0,\"day\":\"2022-01-10T\",\
             \"at\":\"2023-11-14T22:13:22.000Z\",\"local\":\"2023-11-14T22:13:20.000000002-00:00\",\
             \"price\":2.25,\"flag\":true,\"tags\":[\"a 2\",null]}\n"
        );
        let got = run("SELECT s.name, s.tags FROM S3Object s", &file, None).unwrap();
        assert_eq!(
            got,
            "{\"name\":null,\"tags\":null}\n{\"name\":\"name 1\",\"tags\":[]}\n{\"name\":\"name 2\",\"tags\":[\"a 2\",null]}\n"
        );
    }

    #[test]
    fn queries_its_columns() {
        let file = file(100, 30, Compression::GZIP(Default::default()));
        let q = |sql: &str| run(sql, &file, None).unwrap();
        assert_eq!(q("SELECT COUNT(*) FROM S3Object"), "{\"_1\":100}\n");
        assert_eq!(
            q("SELECT COUNT(*), SUM(s.ID), MAX(s.price) FROM S3Object s WHERE s.flag"),
            "{\"_1\":50,\"_2\":2450,\"_3\":98.25}\n"
        );
        assert_eq!(
            q("SELECT s.id FROM S3Object s WHERE s.at >= `2023-11-14T22:14:55Z` LIMIT 2"),
            "{\"id\":95}\n{\"id\":96}\n"
        );
        assert_eq!(
            q("SELECT EXTRACT(day FROM s.day) AS d FROM S3Object s WHERE s.id = 40"),
            "{\"d\":17}\n"
        );
        assert_eq!(
            q("SELECT s.tags[0] AS t FROM S3Object s WHERE s.id = 5"),
            "{\"t\":\"a 5\"}\n"
        );
        // Not a column: nothing to read, and nothing there.
        assert_eq!(q("SELECT s.nope FROM S3Object s LIMIT 1"), "{}\n");
    }

    #[test]
    fn scan_ranges_read_the_row_groups_that_start_in_them() {
        let file = file(100, 10, Compression::UNCOMPRESSED);
        let metadata = metadata(&file).unwrap();
        let whole = run("SELECT s.id FROM S3Object s", &file, None).unwrap();
        // Ranges from each row group's start to just before the next's.
        let starts: Vec<u64> = (0..metadata.num_row_groups())
            .map(|g| metadata.row_group(g).column(0).byte_range().0)
            .collect();
        let mut split = String::new();
        for (i, &start) in starts.iter().enumerate() {
            let end = starts
                .get(i + 1)
                .map_or(file.len() as u64 - 1, |next| next - 1);
            let range = ScanRange::From {
                start,
                end: Some(end),
            };
            split += &run("SELECT s.id FROM S3Object s", &file, Some(range)).unwrap();
        }
        assert_eq!(split, whole);
        // A range within a row group, after its start: none of it.
        let inside = ScanRange::From {
            start: starts[3] + 1,
            end: Some(starts[4] - 1),
        };
        assert_eq!(
            run("SELECT s.id FROM S3Object s", &file, Some(inside)).unwrap(),
            ""
        );
    }

    /// The row groups of `file` that `sql` reads.
    fn groups(sql: &str, file: &[u8]) -> Vec<usize> {
        let metadata = metadata(file).unwrap();
        let query = sql::parse(sql).unwrap();
        Plan::new(&metadata, &query, None, file.len() as u64)
            .unwrap()
            .groups
    }

    /// Row groups of 10 rows each: `id`s 0-9 in the first, 10-19 in the
    /// next, ...
    #[test]
    fn skips_row_groups_its_condition_rules_out() {
        let file = file(100, 10, Compression::SNAPPY);
        let all: Vec<usize> = (0..10).collect();
        let cases: &[(&str, Vec<usize>)] = &[
            ("s.id = 35", vec![3]),
            ("35 = s.id", vec![3]),
            ("s.id < 20", vec![0, 1]),
            ("s.id <= 20", vec![0, 1, 2]),
            ("s.id > 89", vec![9]),
            ("s.id > 88", vec![8, 9]),
            ("90 < s.id", vec![9]),
            ("s.id >= 90 OR s.id = 5", vec![0, 9]),
            ("s.id >= 50 AND s.id < 60", vec![5]),
            ("s.id BETWEEN 15 AND 25", vec![1, 2]),
            ("s.id IN (3, 77)", vec![0, 7]),
            ("s.ID = 35.0", vec![3]),
            ("s.price > 98.0", vec![9]),
            ("s.score = 3", vec![0]),
            ("s.at >= `2023-11-14T22:14:55Z`", vec![9]),
            ("s.day = `2022-01-09T`", vec![0]),
            ("s.local < `2023-11-14T22:13:20.000000010Z`", vec![0]),
            ("s.local <= `2023-11-14T22:13:20.000000010Z`", vec![0, 1]),
            // ("name 42" is between group 0's "name 1" and "name 9".)
            ("s.name = 'name 42'", vec![0, 4]),
            ("s.name = 'name 95'", vec![9]),
            // Nulls (every 5th name) in every row group.
            ("s.name IS NULL", all.clone()),
            ("s.id IS NULL", vec![]),
            // What the statistics can't say.
            ("s.id <> 35", all.clone()),
            ("NOT s.id = 35", all.clone()),
            ("s.id + 1 = 36", all.clone()),
            ("s.id = '35'", all.clone()),
            ("s.name = 42", all.clone()),
            ("s.flag", all.clone()),
            ("s.nope = 1", all.clone()),
        ];
        for (condition, want) in cases {
            let sql = format!("SELECT s.id FROM S3Object s WHERE {condition}");
            assert_eq!(&groups(&sql, &file), want, "{condition}");
            // And it reads what it would have read: the same records.
            let read = run(&sql, &file, None).unwrap();
            let every = file_without_statistics(100, 10);
            assert_eq!(groups(&sql, &every), all, "{condition}");
            assert_eq!(read, run(&sql, &every, None).unwrap(), "{condition}");
        }
    }

    /// `file`'s, without statistics: nothing to rule row groups out by.
    fn file_without_statistics(rows: usize, per_group: usize) -> Vec<u8> {
        use parquet::file::properties::EnabledStatistics;
        let props = WriterProperties::builder()
            .set_compression(Compression::SNAPPY)
            .set_statistics_enabled(EnabledStatistics::None)
            .build();
        file_with(rows, per_group, props)
    }

    #[test]
    fn refuses_what_s3_select_does() {
        let int96 = {
            let schema = Arc::new(
                parse_message_type("message m { OPTIONAL INT96 t; OPTIONAL INT32 n; }").unwrap(),
            );
            let mut writer =
                SerializedFileWriter::new(Vec::new(), schema, Default::default()).unwrap();
            let mut group = writer.next_row_group().unwrap();
            let mut t = group.next_column().unwrap().unwrap();
            let time = parquet::data_type::Int96::from(vec![0, 0, 2_440_588]);
            t.typed::<parquet::data_type::Int96Type>()
                .write_batch(&[time], Some(&[1]), None)
                .unwrap();
            t.close().unwrap();
            let mut n = group.next_column().unwrap().unwrap();
            n.typed::<Int32Type>()
                .write_batch(&[7], Some(&[1]), None)
                .unwrap();
            n.close().unwrap();
            group.close().unwrap();
            writer.into_inner().unwrap()
        };
        let code = |sql: &str, file: &[u8]| run(sql, file, None).unwrap_err().code;
        assert_eq!(
            code("SELECT * FROM S3Object", &int96),
            "UnsupportedParquetType"
        );
        assert_eq!(
            code("SELECT s.t FROM S3Object s", &int96),
            "UnsupportedParquetType"
        );
        // A column it doesn't read can be anything.
        assert_eq!(
            run("SELECT s.n FROM S3Object s", &int96, None).unwrap(),
            "{\"n\":7}\n"
        );
    }
}
