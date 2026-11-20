//! SelectObjectContent (S3 Select): `POST /{bucket}/{key}?select&select-type=2`,
//! which runs a SQL `SELECT` over a CSV or JSON object and answers with the
//! records it selects, framed as an event stream (see `eventstream`).
//!
//! What's supported: CSV (all of its options) and JSON (`LINES`, and
//! `DOCUMENT` as values one after another) input, uncompressed or gzipped,
//! and Parquet (see `parquet`);
//! CSV or JSON output; Progress events; `ScanRange`; and the SQL `sql`
//! describes, timestamps (see `timestamp`) among it. Not (yet): BZIP2,
//! and paths in `FROM`, which are refused as `NotImplemented` (501) or
//! `UnsupportedSyntax` (400).
//!
//! A `ScanRange` reads the records whose first byte is in it, as AWS's API
//! reference says ("A record is processed when its first byte is contained
//! by the range"), each to its end. The object is read from just before
//! the range, so that a delimiter there says whether the range's first byte
//! starts a record; and stops at the first record that starts after it. A
//! CSV object's header is its first record, whatever the range: it's read
//! from the object's start first. Ranges that split an object into
//! consecutive pieces (`0-99`, `100-199`, ...) read each record once.
//!
//! The object is read as it streams, a record at a time: no record may be
//! longer than `input::MAX_RECORD`, as in S3, so a query's memory doesn't
//! grow with its object. A query with a `LIMIT` stops reading once it has
//! its records.
//!
//! Its semantics are AWS's, but where AWS's are stricter than they need be:
//! a string compares with a number as a number, if it reads as one (CSV's
//! fields are all strings), and arithmetic takes such strings too; and a
//! quoted CSV field may always hold the record delimiter (whatever
//! `AllowQuotedRecordDelimiter` says).

#[cfg(test)]
mod e2e;
mod eval;
mod eventstream;
mod input;
mod output;
mod parquet;
mod request;
mod sql;
mod timestamp;
mod value;

use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

use http_body_util::BodyExt;
use hyper::{
    Response, StatusCode,
    body::{Bytes, Frame},
};

use crate::{
    App,
    body::{FrameSender, ResBody, box_response, channel_body},
    s3::{
        conditional::Preconditions, sse_c::CustomerKey, util::format_s3_error, util::query_param,
    },
};
use eval::{Accumulator, Record, column_name};
use eventstream::Stats;
use input::{CsvInput, HeaderInfo, MAX_RECORD, Read};
use output::Output;
use request::Input;
use sql::{Projection, Query};
use value::Value;

/// Why a query was refused, or failed: an S3 error code and its message.
#[derive(Debug, Clone)]
pub struct SelectError {
    pub code: &'static str,
    pub message: String,
}

impl SelectError {
    pub fn new(code: &'static str, message: impl Into<String>) -> SelectError {
        SelectError {
            code,
            message: message.into(),
        }
    }

    /// The error, as the response to a request refused before it started.
    fn response(&self) -> Response<ResBody> {
        let status = match self.code {
            "NotImplemented" => StatusCode::NOT_IMPLEMENTED,
            _ => StatusCode::BAD_REQUEST,
        };
        box_response(format_s3_error(status, self.code, &self.message))
    }
}

/// The request's parts that SelectObjectContent's handler checks before it
/// reads the object: its `select-type`, its document, and its SQL.
pub struct Prepared {
    request: request::SelectRequest,
    query: Query,
}

/// Checks a SelectObjectContent's query string and body: what it asks, or
/// the response refusing it.
pub fn prepare(query: &str, body: &[u8]) -> Result<Prepared, Response<ResBody>> {
    if query_param(query, "select-type").as_deref() != Some("2") {
        return Err(SelectError::new(
            "InvalidArgument",
            "SelectObjectContent's select-type must be 2.",
        )
        .response());
    }
    let request = request::parse(body).map_err(|e| e.response())?;
    let query = sql::parse(&request.expression).map_err(|e| e.response())?;
    Ok(Prepared { request, query })
}

/// Runs a prepared SelectObjectContent on `key`: the object's own error if
/// it can't be read (as GetObject's), else a 200 streaming its events.
pub async fn select_object_content(
    app: &Arc<App>,
    bucket: &str,
    key: &str,
    prepared: Prepared,
    customer_key: Option<&CustomerKey>,
    role: Option<crate::kms::Caller>,
) -> anyhow::Result<Response<ResBody>> {
    let read = |range: Option<String>, conditions: Preconditions| {
        let role = role.clone();
        async move {
            crate::s3::objects::get::get_object(
                app,
                bucket,
                key,
                None,
                range.as_deref(),
                None,
                &conditions,
                customer_key,
                role,
                false,
            )
            .await
        }
    };
    let object = read(None, Preconditions::default()).await?;
    if object.status() != StatusCode::OK {
        return Ok(object);
    }
    let Prepared { request, query } = prepared;
    let size = object
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let etag = object.headers().get(hyper::header::ETAG).cloned();
    // Parquet is read by its footer and its columns' chunks (see `parquet`).
    if let Input::Parquet = request.input {
        let source = parquet::Source {
            app: app.clone(),
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            customer_key: customer_key.cloned(),
            role: role.clone(),
            etag,
            size,
        };
        drop(object);
        return parquet::select(
            source,
            query,
            request.output,
            request.scan_range,
            request.progress,
        )
        .await;
    }
    let mut scanner = Scanner::new(query, request.input, request.output);
    let mut body = object.into_body();
    // What reading a range's header took.
    let mut scanned = 0;
    if let Some(range) = request.scan_range {
        match range.bytes(size) {
            // Nothing of the object is in it: no records.
            None => {
                body = http_body_util::Empty::new()
                    .map_err(|never| match never {})
                    .boxed_unsync();
            }
            Some((first, last)) => {
                // Read from just before the range, to tell whether its
                // first byte starts a record (follows a delimiter).
                let from = first.saturating_sub(scanner.delimiter().len() as u64);
                if from > 0 {
                    // The header's names are the object's first record's.
                    if scanner.header_pending {
                        let header = match read_header(&mut body, &scanner.input).await? {
                            Ok(header) => header,
                            Err(refused) => return Ok(refused.response()),
                        };
                        scanned = header.1;
                        scanner.set_header(header.0);
                    }
                    // The same version as the header's: it's what the first
                    // read found.
                    let mut conditions = hyper::HeaderMap::new();
                    if let Some(etag) = etag {
                        conditions.insert(hyper::header::IF_MATCH, etag);
                    }
                    let conditions = Preconditions::from_headers(&conditions);
                    let ranged = read(Some(format!("bytes={from}-")), conditions).await?;
                    if ranged.status() != StatusCode::PARTIAL_CONTENT {
                        return Ok(ranged);
                    }
                    body = ranged.into_body();
                }
                scanner.set_range(from, first, last);
            }
        }
    }
    let (tx, events) = channel_body();
    tokio::spawn(stream(
        body,
        scanner,
        tx,
        request.gzip,
        request.progress,
        scanned,
    ));
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/octet-stream")
        .body(events)
        .expect("a valid response"))
}

/// A CSV object's header (its first record, after any comments), and how
/// many bytes reading it took; `None` if it has no records.
async fn read_header(
    body: &mut ResBody,
    input: &Input,
) -> anyhow::Result<Result<(Option<Vec<String>>, u64), SelectError>> {
    let Input::Csv(csv) = input else {
        return Ok(Ok((None, 0)));
    };
    let mut buf = Vec::new();
    let mut at = 0;
    let mut eof = false;
    loop {
        match csv.read(&buf, at, eof) {
            Err(e) => return Ok(Err(e)),
            Ok(Read::Record(fields, _)) => return Ok(Ok((Some(fields), buf.len() as u64))),
            Ok(Read::Skip(next)) => at = next,
            Ok(Read::More) if eof => return Ok(Ok((None, buf.len() as u64))),
            Ok(Read::More) => {
                if buf.len() - at > MAX_RECORD {
                    return Ok(Err(too_long()));
                }
                match body.frame().await {
                    None => eof = true,
                    Some(frame) => {
                        if let Ok(data) = frame?.into_data() {
                            buf.extend_from_slice(&data);
                        }
                    }
                }
            }
        }
    }
}

/// How much a Records event holds at most.
const MAX_EVENT: usize = 256 * 1024;

/// How long the stream may go without a message before it sends a Cont.
const KEEP_ALIVE: Duration = Duration::from_secs(5);

/// How often Progress events are sent, if they're asked for.
const PROGRESS_EVERY: Duration = Duration::from_secs(1);

/// How much compressed input is decompressed at once: deflate expands by
/// about 1000 at most, so this bounds what one step holds.
const GZIP_STEP: usize = 4 * 1024;

/// The events' sender, which keeps the stream's tallies.
struct Events {
    tx: FrameSender,
    stats: Stats,
    last_sent: Instant,
    last_progress: Instant,
    progress: bool,
}

impl Events {
    /// Events to `tx`, of a stream that has read `scanned` bytes so far.
    fn new(tx: FrameSender, progress: bool, scanned: u64) -> Events {
        Events {
            tx,
            stats: Stats {
                scanned,
                processed: scanned,
                returned: 0,
            },
            last_sent: Instant::now(),
            last_progress: Instant::now(),
            progress,
        }
    }

    /// Sends `message`. `false` if the client is gone.
    async fn send(&mut self, message: Bytes) -> bool {
        self.last_sent = Instant::now();
        self.tx.send(Ok(Frame::data(message))).await.is_ok()
    }

    /// Sends what `scanner` has written as Records events, and a Progress
    /// or Cont event if it's time for one. `false` if the client is gone.
    async fn flush(&mut self, scanner: &mut Scanner) -> bool {
        let out = std::mem::take(&mut scanner.out);
        self.records(&out).await && self.tick().await
    }

    /// Sends `out` as Records events. `false` if the client is gone.
    async fn records(&mut self, out: &[u8]) -> bool {
        for piece in out.chunks(MAX_EVENT) {
            self.stats.returned += piece.len() as u64;
            if !self.send(eventstream::records(piece)).await {
                return false;
            }
        }
        true
    }

    /// Sends a Progress or Cont event if it's time for one. `false` if the
    /// client is gone.
    async fn tick(&mut self) -> bool {
        if self.progress && self.last_progress.elapsed() >= PROGRESS_EVERY {
            self.last_progress = Instant::now();
            if !self.send(self.stats.progress()).await {
                return false;
            }
        }
        if self.last_sent.elapsed() >= KEEP_ALIVE && !self.send(eventstream::cont()).await {
            return false;
        }
        true
    }
}

/// Streams `object` through `scanner` to `tx`, as events.
async fn stream(
    mut object: ResBody,
    mut scanner: Scanner,
    tx: FrameSender,
    gzip: bool,
    progress: bool,
    scanned: u64,
) {
    let mut events = Events::new(tx, progress, scanned);
    let mut gunzip = gzip.then(|| flate2::write::MultiGzDecoder::new(Vec::new()));
    let not_gzip = || {
        SelectError::new(
            "InvalidCompressionFormat",
            "GZIP is not applicable to the queried object. Please correct the request and try again.",
        )
    };
    let result: Result<(), SelectError> = async {
        while !scanner.done {
            let frame = match object.frame().await {
                None => break,
                Some(Ok(frame)) => frame,
                Some(Err(e)) => {
                    eprintln!("S3 Select: reading the object failed: {e}");
                    return Err(SelectError::new(
                        "InternalError",
                        "We encountered an internal error reading the object. Please try again.",
                    ));
                }
            };
            let Ok(data) = frame.into_data() else {
                continue;
            };
            events.stats.scanned += data.len() as u64;
            match &mut gunzip {
                None => {
                    events.stats.processed += data.len() as u64;
                    scanner.feed(&data)?;
                }
                Some(gunzip) => {
                    for piece in data.chunks(GZIP_STEP) {
                        gunzip.write_all(piece).map_err(|_| not_gzip())?;
                        let out = std::mem::take(gunzip.get_mut());
                        events.stats.processed += out.len() as u64;
                        scanner.feed(&out)?;
                        if scanner.done {
                            break;
                        }
                    }
                }
            }
            if !events.flush(&mut scanner).await {
                return Ok(());
            }
        }
        if let Some(gunzip) = &mut gunzip
            && !scanner.done
        {
            gunzip.try_finish().map_err(|_| not_gzip())?;
            let out = std::mem::take(gunzip.get_mut());
            events.stats.processed += out.len() as u64;
            scanner.feed(&out)?;
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

/// Runs a query over an object's bytes as they're fed to it, writing what
/// it selects to `out`.
struct Scanner {
    query: Query,
    input: Input,
    output: Output,
    /// What's been fed and not yet read, from `at`.
    buf: Vec<u8>,
    at: usize,
    /// Where in the object `buf` starts.
    offset: u64,
    /// The `ScanRange`'s first and last byte, if it has one: records that
    /// start in it are read.
    range: Option<(u64, u64)>,
    /// Whether the first record in the range is still to be found.
    seeking: bool,
    /// Whether `at` is known to be where a record starts: the object's
    /// start, or right after a record (or a delimiter).
    boundary: bool,
    /// A CSV object's header's names (`FileHeaderInfo` `USE`).
    header: Option<Vec<String>>,
    /// Whether the first CSV record is still to come and is a header.
    header_pending: bool,
    accumulators: Vec<Accumulator>,
    /// How many records have been written.
    written: u64,
    /// Whether it needs nothing more (its `LIMIT` is reached).
    done: bool,
    /// What it has written, which its caller takes.
    out: Vec<u8>,
}

impl Scanner {
    fn new(query: Query, input: Input, output: Output) -> Scanner {
        let header_pending = matches!(
            &input,
            Input::Csv(CsvInput {
                header: HeaderInfo::Use | HeaderInfo::Ignore,
                ..
            })
        );
        let accumulators = query.aggregates.iter().map(Accumulator::new).collect();
        let done = query.limit == Some(0) && query.aggregates.is_empty();
        Scanner {
            query,
            input,
            output,
            buf: Vec::new(),
            at: 0,
            offset: 0,
            range: None,
            seeking: false,
            boundary: true,
            header: None,
            header_pending,
            accumulators,
            written: 0,
            done,
            out: Vec::new(),
        }
    }

    /// What ends a record: what a `ScanRange` looks for to find the first
    /// one in it. (Quotes aren't taken into account, which is why S3 takes
    /// no ranges with `AllowQuotedRecordDelimiter`.)
    fn delimiter(&self) -> &[u8] {
        match &self.input {
            Input::Csv(csv) => &csv.record_delimiter,
            // (Parquet's ranges are of its row groups: see `parquet`.)
            Input::Json(_) | Input::Parquet => b"\n",
        }
    }

    /// Reads only the records whose first byte is from `first` to `last`,
    /// of what's fed from the object's byte `from` on (no later than
    /// `first`).
    fn set_range(&mut self, from: u64, first: u64, last: u64) {
        self.offset = from;
        self.range = Some((first, last));
        self.seeking = true;
        self.boundary = from == 0;
        // Fed from the middle, it doesn't see the header (see `set_header`).
        if from > 0 {
            self.header_pending = false;
        }
    }

    /// The header's names (`FileHeaderInfo` `USE`), read on their own.
    fn set_header(&mut self, names: Option<Vec<String>>) {
        if let Input::Csv(CsvInput {
            header: HeaderInfo::Use,
            ..
        }) = &self.input
        {
            self.header = names;
        }
        self.header_pending = false;
    }

    /// Takes `at` to the first record in the range, if it can be found in
    /// what's been fed: whether it was.
    fn seek(&mut self, eof: bool) -> bool {
        let Some((first, _)) = self.range else {
            return true;
        };
        loop {
            if self.boundary && self.offset + self.at as u64 >= first {
                return true;
            }
            let delimiter = self.delimiter();
            let len = delimiter.len();
            let found = self.buf[self.at..]
                .windows(len)
                .position(|w| w == delimiter);
            match found {
                Some(i) => {
                    self.at += i + len;
                    self.boundary = true;
                }
                None => {
                    // A delimiter may be cut in two: keep what may be its
                    // start.
                    if !eof {
                        self.at = self.at.max(self.buf.len().saturating_sub(len - 1));
                        self.boundary = false;
                    } else {
                        self.at = self.buf.len();
                    }
                    return false;
                }
            }
        }
    }

    /// Reads what records `data` completes.
    fn feed(&mut self, data: &[u8]) -> Result<(), SelectError> {
        if self.done {
            return Ok(());
        }
        self.buf.extend_from_slice(data);
        self.run(false)
    }

    /// Reads the rest, and writes the aggregates' record, if the query has
    /// any.
    fn finish(&mut self) -> Result<(), SelectError> {
        if !self.done {
            self.run(true)?;
        }
        if self.query.aggregates.is_empty() || self.query.limit == Some(0) {
            return Ok(());
        }
        let results: Vec<Value> = std::mem::take(&mut self.accumulators)
            .into_iter()
            .map(Accumulator::result)
            .collect();
        let Projection::Items(items) = &self.query.projection else {
            return Ok(());
        };
        let empty = Value::Struct(Vec::new());
        let record = Record::Json(&empty);
        let mut fields = Vec::with_capacity(items.len());
        for item in items {
            fields.push((
                item.name.clone(),
                eval::eval(&item.expr, &record, &results)?,
            ));
        }
        self.output.write(&fields, &mut self.out);
        self.done = true;
        Ok(())
    }

    fn run(&mut self, eof: bool) -> Result<(), SelectError> {
        while !self.done {
            // A range's first record: after the header, if the header is
            // in what's fed.
            if self.seeking && !self.header_pending {
                if !self.seek(eof) {
                    break;
                }
                self.seeking = false;
            }
            // Past the range's last byte: a record starting there isn't in
            // it.
            if let Some((_, last)) = self.range
                && !self.seeking
                && self.offset + self.at as u64 > last
            {
                self.done = true;
                break;
            }
            let read = match &self.input {
                Input::Csv(csv) => match csv.read(&self.buf, self.at, eof)? {
                    Read::Record(fields, next) => Read::Record(Parsed::Csv(fields), next),
                    Read::Skip(next) => Read::Skip(next),
                    Read::More => Read::More,
                },
                Input::Json(json) => match json.read(&self.buf, self.at, eof)? {
                    Read::Record(value, next) => Read::Record(Parsed::Json(value), next),
                    Read::Skip(next) => Read::Skip(next),
                    Read::More => Read::More,
                },
                // Its records are given to `record` (see `parquet`).
                Input::Parquet => Read::More,
            };
            match read {
                Read::Record(record, next) => {
                    if next - self.at > MAX_RECORD {
                        return Err(too_long());
                    }
                    self.at = next;
                    self.record(record)?;
                }
                Read::Skip(next) => self.at = next,
                Read::More => {
                    if !eof && self.buf.len() - self.at > MAX_RECORD {
                        return Err(too_long());
                    }
                    break;
                }
            }
        }
        self.offset += self.at as u64;
        self.buf.drain(..self.at);
        self.at = 0;
        Ok(())
    }

    fn record(&mut self, parsed: Parsed) -> Result<(), SelectError> {
        let fields;
        let record = match &parsed {
            Parsed::Csv(f) => {
                if self.header_pending {
                    self.header_pending = false;
                    if let Input::Csv(CsvInput {
                        header: HeaderInfo::Use,
                        ..
                    }) = &self.input
                    {
                        self.header = Some(f.clone());
                    }
                    return Ok(());
                }
                fields = f;
                Record::Csv {
                    fields,
                    header: self.header.as_deref(),
                }
            }
            Parsed::Json(value) => Record::Json(value),
        };
        if let Some(condition) = &self.query.condition
            && eval::truth(&eval::eval(condition, &record, &[])?) != Some(true)
        {
            return Ok(());
        }
        if !self.query.aggregates.is_empty() {
            for (accumulator, aggregate) in self.accumulators.iter_mut().zip(&self.query.aggregates)
            {
                accumulator.add(aggregate, &record)?;
            }
            return Ok(());
        }
        let row: Vec<(String, Value)> = match &self.query.projection {
            Projection::Star => match &record {
                Record::Csv { fields, header } => fields
                    .iter()
                    .enumerate()
                    .map(|(i, f)| (column_name(*header, i), Value::Str(f.clone())))
                    .collect(),
                Record::Json(Value::Struct(fields)) => fields.clone(),
                Record::Json(value) => vec![("_1".to_owned(), (*value).clone())],
            },
            Projection::Items(items) => {
                let mut row = Vec::with_capacity(items.len());
                for item in items {
                    row.push((item.name.clone(), eval::eval(&item.expr, &record, &[])?));
                }
                row
            }
        };
        self.output.write(&row, &mut self.out);
        self.written += 1;
        if self.query.limit.is_some_and(|limit| self.written >= limit) {
            self.done = true;
        }
        Ok(())
    }
}

/// A record as read.
enum Parsed {
    Csv(Vec<String>),
    Json(Value),
}

fn too_long() -> SelectError {
    SelectError::new(
        "OverMaxRecordSize",
        "The character number in one record is more than our max threshold, maxCharsPerRecord: 1,048,576",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use input::JsonType;

    /// What `sql` selects from `object`, read as `input` and written as
    /// `output`, fed `step` bytes at a time.
    fn run(
        sql: &str,
        input: Input,
        output: Output,
        object: &[u8],
        step: usize,
    ) -> Result<String, SelectError> {
        let mut scanner = Scanner::new(sql::parse(sql)?, input, output);
        for piece in object.chunks(step) {
            scanner.feed(piece)?;
        }
        scanner.finish()?;
        Ok(String::from_utf8(scanner.out).unwrap())
    }

    fn csv(header: HeaderInfo) -> Input {
        Input::Csv(CsvInput {
            header,
            comments: Some(b"#".to_vec()),
            ..CsvInput::default()
        })
    }

    fn csv_out() -> Output {
        Output::Csv(output::CsvOutput::default())
    }

    fn json_out() -> Output {
        Output::Json {
            record_delimiter: b"\n".to_vec(),
        }
    }

    const PEOPLE: &[u8] = b"name,age,city\nAda,36,London\n# a comment\nAlan,41,Wilmslow\n\"Grace, RA\",85,New York\nLinus,,Helsinki\n";

    #[test]
    fn selects_from_csv() {
        let cases: &[(&str, HeaderInfo, bool, &str)] = &[
            (
                "SELECT * FROM S3Object",
                HeaderInfo::Ignore,
                false,
                "Ada,36,London\nAlan,41,Wilmslow\n\"Grace, RA\",85,New York\nLinus,,Helsinki\n",
            ),
            (
                "SELECT s.name FROM S3Object s WHERE s.age > 40",
                HeaderInfo::Use,
                false,
                "Alan\n\"Grace, RA\"\n",
            ),
            (
                "SELECT s._1, s._3 FROM S3Object s LIMIT 1",
                HeaderInfo::None,
                false,
                "name,city\n",
            ),
            (
                "SELECT * FROM S3Object s WHERE s.city LIKE '%on'",
                HeaderInfo::Use,
                true,
                "{\"name\":\"Ada\",\"age\":\"36\",\"city\":\"London\"}\n",
            ),
            (
                "SELECT s.name, CAST(s.age AS INT) AS age FROM S3Object s WHERE s.name = 'Ada'",
                HeaderInfo::Use,
                true,
                "{\"name\":\"Ada\",\"age\":36}\n",
            ),
            (
                "SELECT COUNT(*), SUM(CAST(s.age AS INT)), AVG(s.age), MIN(s.age), MAX(s.name) FROM S3Object s WHERE s.age <> ''",
                HeaderInfo::Use,
                false,
                "3,162,54.0,36,\"Grace, RA\"\n",
            ),
            (
                "SELECT COUNT(s.age) FROM S3Object s WHERE s.age = ''",
                HeaderInfo::Use,
                false,
                "1\n",
            ),
            (
                "SELECT COUNT(*) FROM S3Object s WHERE s.age > 100",
                HeaderInfo::Use,
                true,
                "{\"_1\":0}\n",
            ),
            (
                "SELECT s.name FROM S3Object s LIMIT 0",
                HeaderInfo::Use,
                false,
                "",
            ),
            (
                "SELECT s.nope FROM S3Object s LIMIT 1",
                HeaderInfo::Use,
                true,
                "{}\n",
            ),
        ];
        for (sql, header, json, want) in cases {
            for step in [1, 5, 1000] {
                let output = if *json { json_out() } else { csv_out() };
                let got = run(sql, csv(*header), output, PEOPLE, step).unwrap();
                assert_eq!(got, *want, "{sql} ({step})");
            }
        }
    }

    #[test]
    fn selects_from_json() {
        let object = b"{\"id\":1,\"tags\":[\"a\"],\"user\":{\"name\":\"x\"}}\n{\"id\":2,\"user\":{\"name\":\"y\"}}\n";
        let lines = || Input::Json(JsonType::Lines);
        assert_eq!(
            run("SELECT * FROM S3Object", lines(), json_out(), object, 7).unwrap(),
            String::from_utf8(object.to_vec()).unwrap()
        );
        assert_eq!(
            run(
                "SELECT s.user.name, s.tags[0] AS t FROM S3Object[*] s WHERE s.id >= 1",
                lines(),
                csv_out(),
                object,
                3
            )
            .unwrap(),
            "x,a\ny,\n"
        );
        assert_eq!(
            run(
                "SELECT s.tags FROM S3Object s",
                lines(),
                json_out(),
                object,
                100
            )
            .unwrap(),
            "{\"tags\":[\"a\"]}\n{}\n"
        );
        assert_eq!(
            run(
                "SELECT SUM(s.id) AS total FROM S3Object s",
                Input::Json(JsonType::Document),
                json_out(),
                object,
                4
            )
            .unwrap(),
            "{\"total\":3}\n"
        );
    }

    #[test]
    fn fails_on_bad_records() {
        let long = vec![b'x'; MAX_RECORD + 10];
        let err = run(
            "SELECT * FROM S3Object",
            csv(HeaderInfo::None),
            csv_out(),
            &long,
            4096,
        )
        .unwrap_err();
        assert_eq!(err.code, "OverMaxRecordSize");
        let err = run(
            "SELECT CAST(s.name AS INT) FROM S3Object s",
            csv(HeaderInfo::Use),
            csv_out(),
            PEOPLE,
            100,
        )
        .unwrap_err();
        assert_eq!(err.code, "CastFailed");
    }

    #[test]
    fn stops_at_its_limit() {
        let mut scanner = Scanner::new(
            sql::parse("SELECT * FROM S3Object LIMIT 2").unwrap(),
            csv(HeaderInfo::None),
            csv_out(),
        );
        scanner.feed(b"1\n2\n3\n").unwrap();
        assert!(scanner.done);
        // What follows isn't read: a broken record there doesn't matter.
        scanner.feed(b"\"broken").unwrap();
        scanner.finish().unwrap();
        assert_eq!(scanner.out, b"1\n2\n");
    }

    /// What `sql` selects from the bytes `first` to `last` of `object`, as
    /// `select_object_content` reads them, fed `step` bytes at a time.
    fn ranged(
        sql: &str,
        input: Input,
        output: Output,
        object: &[u8],
        (first, last): (u64, u64),
        step: usize,
    ) -> Result<String, SelectError> {
        let mut scanner = Scanner::new(sql::parse(sql)?, input, output);
        let from = first.saturating_sub(scanner.delimiter().len() as u64);
        if from > 0 && scanner.header_pending {
            // The object's first record, as `read_header` reads it.
            let Input::Csv(csv) = &scanner.input else {
                panic!()
            };
            let mut at = 0;
            let header = loop {
                match csv.read(object, at, true)? {
                    Read::Record(fields, _) => break Some(fields),
                    Read::Skip(next) => at = next,
                    Read::More => break None,
                }
            };
            scanner.set_header(header);
        }
        scanner.set_range(from, first, last);
        for piece in object[from as usize..].chunks(step) {
            scanner.feed(piece)?;
        }
        scanner.finish()?;
        Ok(String::from_utf8(scanner.out).unwrap())
    }

    /// The ranges `size` bytes split into, `chunk` bytes each.
    fn pieces(size: u64, chunk: u64) -> Vec<(u64, u64)> {
        (0..size)
            .step_by(chunk as usize)
            .map(|i| (i, (i + chunk - 1).min(size - 1)))
            .collect()
    }

    /// A query, how its object is read, and the object.
    type Case = (&'static str, fn() -> Input, &'static [u8]);

    #[test]
    fn scan_ranges_split_an_object_into_its_records() {
        let lines = b"{\"a\":1}\n{\"a\":22}\n\n{\"a\":333,\"b\":[1,2]}\r\n{\"a\":4}\n{\"a\":55555}";
        let multi = b"x|y|;long field|2|;|;3|z|;4|";
        let cases: Vec<Case> = vec![
            ("SELECT * FROM S3Object", || csv(HeaderInfo::Use), PEOPLE),
            (
                "SELECT s.name FROM S3Object s",
                || csv(HeaderInfo::Use),
                PEOPLE,
            ),
            ("SELECT * FROM S3Object", || csv(HeaderInfo::Ignore), PEOPLE),
            ("SELECT * FROM S3Object", || csv(HeaderInfo::None), PEOPLE),
            (
                "SELECT s.a FROM S3Object s",
                || Input::Json(JsonType::Lines),
                lines,
            ),
            (
                "SELECT * FROM S3Object",
                || {
                    Input::Csv(CsvInput {
                        field_delimiter: b"|".to_vec(),
                        record_delimiter: b"|;".to_vec(),
                        ..CsvInput::default()
                    })
                },
                multi,
            ),
        ];
        for (sql, input, object) in cases {
            let whole = run(sql, input(), json_out(), object, 1000).unwrap();
            let size = object.len() as u64;
            for chunk in 1..=size {
                for step in [1, 3, 1000] {
                    let mut split = String::new();
                    for range in pieces(size, chunk) {
                        split += &ranged(sql, input(), json_out(), object, range, step).unwrap();
                    }
                    assert_eq!(
                        split, whole,
                        "{sql} in pieces of {chunk}, fed {step} at a time"
                    );
                }
            }
        }
    }

    #[test]
    fn scan_ranges_read_the_records_that_start_in_them() {
        // "name,age,city\n" is bytes 0 to 13; "Ada,36,London\n" 14 to 27;
        // "# a comment\n" 28 to 39; "Alan,41,Wilmslow\n" 40 to 56.
        let names = |range| {
            ranged(
                "SELECT s.name FROM S3Object s",
                csv(HeaderInfo::Use),
                csv_out(),
                PEOPLE,
                range,
                1000,
            )
            .unwrap()
        };
        // A record's first byte, to its last.
        assert_eq!(names((14, 27)), "Ada\n");
        // Its first byte only: it's read to its end.
        assert_eq!(names((14, 14)), "Ada\n");
        // Its second byte on: it isn't in the range.
        assert_eq!(names((15, 39)), "");
        // The header's bytes: the header isn't a record.
        assert_eq!(names((0, 13)), "");
        assert_eq!(names((0, 14)), "Ada\n");
        assert_eq!(names((15, 40)), "Alan\n");
        // Aggregates count what's in the range.
        let count = ranged(
            "SELECT COUNT(*) FROM S3Object",
            csv(HeaderInfo::Use),
            csv_out(),
            PEOPLE,
            (14, 40),
            7,
        )
        .unwrap();
        assert_eq!(count, "2\n");
    }
}
