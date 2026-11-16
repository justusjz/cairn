//! A Parquet writer for inventory reports: only what they need, so that
//! Cairn needn't take on Arrow. A file's columns are flat (no nesting or
//! repetition), each a string, boolean, 32- or 64-bit integer, or
//! timestamp (milliseconds since the epoch, UTC), required or optional, as
//! S3's inventory schema has them (see `schema`).
//!
//! Rows are buffered column by column and written out as a row group when
//! asked (`row_group`), so a file's written as it's made and only a row
//! group of it is ever held: each column of a row group is one data page
//! (v1), PLAIN-encoded with its definition levels bit-packed, and
//! Snappy-compressed, as S3's are (see `snappy`). The footer (`finish`) lists the row groups, written
//! with Thrift's compact protocol by hand (`Thrift`).
//!
//! The format: <https://parquet.apache.org/docs/file-format/>, and its
//! Thrift definitions, `parquet.thrift`.

use super::snappy;

/// A column's type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type {
    /// UTF-8, as `binary (UTF8)`.
    Text,
    Boolean,
    Int32,
    Int64,
    /// Milliseconds since the epoch, UTC, as `int64 (TIMESTAMP_MILLIS)`.
    Timestamp,
}

/// A column of a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Column {
    pub name: &'static str,
    pub ty: Type,
    /// Whether every row has a value (`required`), or may have none
    /// (`optional`).
    pub required: bool,
}

/// A row's value of a column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Null,
    Text(String),
    Bool(bool),
    /// Of an `Int32` or `Int64` column.
    Int(i64),
    /// Of a `Timestamp` column: milliseconds since the epoch.
    Millis(i64),
}

/// The file's schema as the manifest's `fileSchema` has it, as S3 writes it:
/// `message s3.inventory { required binary bucket (UTF8); … }`.
pub fn schema(columns: &[Column]) -> String {
    let fields: Vec<String> = columns
        .iter()
        .map(|c| {
            let repetition = if c.required { "required" } else { "optional" };
            let ty = match c.ty {
                Type::Text => "binary",
                Type::Boolean => "boolean",
                Type::Int32 => "int32",
                Type::Int64 | Type::Timestamp => "int64",
            };
            let annotation = match c.ty {
                Type::Text => " (UTF8)",
                Type::Timestamp => " (TIMESTAMP_MILLIS)",
                _ => "",
            };
            format!("{repetition} {ty} {}{annotation};", c.name)
        })
        .collect();
    format!("message s3.inventory {{ {}}}", fields.join(" "))
}

/// What the file starts and ends with.
const MAGIC: &[u8] = b"PAR1";

// parquet.thrift's enums.
const BOOLEAN: i32 = 0;
const INT32: i32 = 1;
const INT64: i32 = 2;
const BYTE_ARRAY: i32 = 6;
const REQUIRED: i32 = 0;
const OPTIONAL: i32 = 1;
const UTF8: i32 = 0;
const TIMESTAMP_MILLIS: i32 = 9;
const PLAIN: i32 = 0;
const RLE: i32 = 3;
const SNAPPY: i32 = 1;
const DATA_PAGE: i32 = 0;

/// A column's rows of the row group being made.
#[derive(Default)]
struct Buffer {
    /// Whether each row has a value (of optional columns).
    defined: Vec<bool>,
    /// The values, PLAIN-encoded (but booleans').
    plain: Vec<u8>,
    /// Booleans' values, bit-packed when the page is written.
    bools: Vec<bool>,
}

/// A column chunk written, for the footer.
struct Chunk {
    offset: i64,
    values: i64,
    uncompressed: i64,
    compressed: i64,
}

struct RowGroup {
    rows: i64,
    chunks: Vec<Chunk>,
}

/// A Parquet file being written.
pub struct Writer {
    columns: Vec<Column>,
    buffers: Vec<Buffer>,
    rows: i64,
    /// Bytes buffered, about.
    buffered: usize,
    /// Bytes written (handed out) so far.
    offset: i64,
    groups: Vec<RowGroup>,
}

impl Writer {
    pub fn new(columns: Vec<Column>) -> Writer {
        let buffers = columns.iter().map(|_| Buffer::default()).collect();
        Writer { columns, buffers, rows: 0, buffered: 0, offset: 0, groups: Vec::new() }
    }

    /// Adds a row, a value for each column. A value that isn't of its
    /// column's type, or a null of a required column, is a bug.
    pub fn push(&mut self, row: &[Value]) {
        assert_eq!(row.len(), self.columns.len(), "a value for each column");
        for ((column, buffer), value) in self.columns.iter().zip(&mut self.buffers).zip(row) {
            if !column.required {
                buffer.defined.push(*value != Value::Null);
            }
            let before = buffer.plain.len();
            match (column.ty, value) {
                (_, Value::Null) => assert!(!column.required, "a value of required column {}", column.name),
                (Type::Text, Value::Text(text)) => {
                    buffer.plain.extend_from_slice(&(text.len() as u32).to_le_bytes());
                    buffer.plain.extend_from_slice(text.as_bytes());
                }
                (Type::Boolean, Value::Bool(b)) => buffer.bools.push(*b),
                (Type::Int32, Value::Int(i)) => {
                    let i = i32::try_from(*i).expect("an int32 in range");
                    buffer.plain.extend_from_slice(&i.to_le_bytes());
                }
                (Type::Int64, Value::Int(i)) | (Type::Timestamp, Value::Millis(i)) => {
                    buffer.plain.extend_from_slice(&i.to_le_bytes())
                }
                (ty, value) => panic!("column {} is {ty:?}, not {value:?}", column.name),
            }
            self.buffered += buffer.plain.len() - before + 1;
        }
        self.rows += 1;
    }

    /// About how many bytes of rows are buffered, uncompressed.
    pub fn buffered(&self) -> usize {
        self.buffered
    }

    /// The buffered rows, as a row group (after the file's magic, at its
    /// start): what's to be written next. Nothing if no rows are buffered
    /// (but the magic).
    pub fn row_group(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.offset == 0 {
            out.extend_from_slice(MAGIC);
        }
        if self.rows > 0 {
            let mut chunks = Vec::new();
            for (column, buffer) in self.columns.iter().zip(std::mem::take(&mut self.buffers)) {
                let offset = self.offset + out.len() as i64;
                let (uncompressed, compressed) = page(column, buffer, self.rows, &mut out);
                chunks.push(Chunk { offset, values: self.rows, uncompressed, compressed });
            }
            self.buffers = self.columns.iter().map(|_| Buffer::default()).collect();
            self.groups.push(RowGroup { rows: self.rows, chunks });
            self.rows = 0;
            self.buffered = 0;
        }
        self.offset += out.len() as i64;
        out
    }

    /// The rest of the file: the buffered rows' row group, and the footer.
    pub fn finish(mut self) -> Vec<u8> {
        let mut out = self.row_group();
        let footer = self.footer();
        out.extend_from_slice(&footer);
        out.extend_from_slice(&(footer.len() as u32).to_le_bytes());
        out.extend_from_slice(MAGIC);
        out
    }

    /// The `FileMetaData`.
    fn footer(&self) -> Vec<u8> {
        let mut t = Thrift::default();
        t.i32(1, 1); // version
        t.list(2, Thrift::STRUCT, self.columns.len() + 1); // schema
        t.element(|t| {
            t.binary(4, b"s3.inventory");
            t.i32(5, self.columns.len() as i32);
        });
        for column in &self.columns {
            t.element(|t| {
                let ty = match column.ty {
                    Type::Text => BYTE_ARRAY,
                    Type::Boolean => BOOLEAN,
                    Type::Int32 => INT32,
                    Type::Int64 | Type::Timestamp => INT64,
                };
                t.i32(1, ty);
                t.i32(3, if column.required { REQUIRED } else { OPTIONAL });
                t.binary(4, column.name.as_bytes());
                match column.ty {
                    Type::Text => {
                        t.i32(6, UTF8);
                        // logicalType: STRING.
                        t.structure(10, |t| t.structure(1, |_| {}));
                    }
                    Type::Timestamp => {
                        t.i32(6, TIMESTAMP_MILLIS);
                        // logicalType: TIMESTAMP, adjusted to UTC, in MILLIS.
                        t.structure(10, |t| {
                            t.structure(8, |t| {
                                t.bool(1, true);
                                t.structure(2, |t| t.structure(1, |_| {}));
                            })
                        });
                    }
                    _ => {}
                }
            });
        }
        let rows: i64 = self.groups.iter().map(|g| g.rows).sum();
        t.i64(3, rows); // num_rows
        t.list(4, Thrift::STRUCT, self.groups.len()); // row_groups
        for group in &self.groups {
            t.element(|t| {
                t.list(1, Thrift::STRUCT, group.chunks.len()); // columns
                for (column, chunk) in self.columns.iter().zip(&group.chunks) {
                    t.element(|t| {
                        t.i64(2, chunk.offset); // file_offset
                        t.structure(3, |t| {
                            // meta_data
                            let ty = match column.ty {
                                Type::Text => BYTE_ARRAY,
                                Type::Boolean => BOOLEAN,
                                Type::Int32 => INT32,
                                Type::Int64 | Type::Timestamp => INT64,
                            };
                            t.i32(1, ty);
                            let encodings: &[i32] = if column.required { &[PLAIN] } else { &[PLAIN, RLE] };
                            t.list(2, Thrift::I32, encodings.len());
                            for e in encodings {
                                t.varint(zigzag(i64::from(*e)));
                            }
                            t.list(3, Thrift::BINARY, 1); // path_in_schema
                            t.varint(column.name.len() as u64);
                            t.out.extend_from_slice(column.name.as_bytes());
                            t.i32(4, SNAPPY);
                            t.i64(5, chunk.values);
                            t.i64(6, chunk.uncompressed);
                            t.i64(7, chunk.compressed);
                            t.i64(9, chunk.offset); // data_page_offset
                        });
                    });
                }
                let uncompressed: i64 = group.chunks.iter().map(|c| c.uncompressed).sum();
                let compressed: i64 = group.chunks.iter().map(|c| c.compressed).sum();
                t.i64(2, uncompressed); // total_byte_size
                t.i64(3, group.rows);
                t.i64(5, group.chunks.first().map_or(0, |c| c.offset)); // file_offset
                t.i64(6, compressed); // total_compressed_size
            });
        }
        t.binary(6, format!("cairn version {}", env!("CARGO_PKG_VERSION")).as_bytes()); // created_by
        t.stop();
        t.out
    }
}

/// Writes a column's rows as a data page into `out`: its sizes (with its
/// header), uncompressed and compressed.
fn page(column: &Column, buffer: Buffer, rows: i64, out: &mut Vec<u8>) -> (i64, i64) {
    let mut body = Vec::new();
    if !column.required {
        // Definition levels, bit-packed (bit width 1) in the RLE/bit-packing
        // hybrid, after their length.
        let levels = bit_packed_run(&buffer.defined);
        body.extend_from_slice(&(levels.len() as u32).to_le_bytes());
        body.extend_from_slice(&levels);
    }
    if column.ty == Type::Boolean {
        body.extend_from_slice(&pack_bits(&buffer.bools));
    } else {
        body.extend_from_slice(&buffer.plain);
    }
    let compressed = snappy::compress(&body);
    let mut header = Thrift::default();
    header.i32(1, DATA_PAGE);
    header.i32(2, i32::try_from(body.len()).expect("a page under 2 GiB"));
    header.i32(3, i32::try_from(compressed.len()).expect("a page under 2 GiB"));
    header.structure(5, |t| {
        t.i32(1, i32::try_from(rows).expect("fewer rows than 2^31"));
        t.i32(2, PLAIN);
        t.i32(3, RLE);
        t.i32(4, RLE);
    });
    header.stop();
    out.extend_from_slice(&header.out);
    out.extend_from_slice(&compressed);
    let header = header.out.len() as i64;
    (header + body.len() as i64, header + compressed.len() as i64)
}

/// Bits, packed least significant first, the last byte padded with zeros.
fn pack_bits(bits: &[bool]) -> Vec<u8> {
    let mut bytes = vec![0u8; bits.len().div_ceil(8)];
    for (i, _) in bits.iter().enumerate().filter(|(_, b)| **b) {
        bytes[i / 8] |= 1 << (i % 8);
    }
    bytes
}

/// Bits as one bit-packed run of the RLE/bit-packing hybrid: its header
/// (the number of groups of eight, shifted, with the low bit set), then the
/// bits.
fn bit_packed_run(bits: &[bool]) -> Vec<u8> {
    let mut t = Thrift::default();
    let groups = bits.len().div_ceil(8) as u64;
    t.varint(groups << 1 | 1);
    t.out.extend_from_slice(&pack_bits(bits));
    t.out
}

fn zigzag(n: i64) -> u64 {
    ((n << 1) ^ (n >> 63)) as u64
}

/// A struct being written with Thrift's compact protocol.
#[derive(Default)]
struct Thrift {
    out: Vec<u8>,
    /// The last field ID of each struct being written (the innermost last).
    last: Vec<i16>,
}

impl Thrift {
    const BOOL_TRUE: u8 = 1;
    const BOOL_FALSE: u8 = 2;
    const I32: u8 = 5;
    const I64: u8 = 6;
    const BINARY: u8 = 8;
    const LIST: u8 = 9;
    const STRUCT: u8 = 12;

    fn varint(&mut self, mut n: u64) {
        while n >= 0x80 {
            self.out.push(n as u8 | 0x80);
            n >>= 7;
        }
        self.out.push(n as u8);
    }

    fn field(&mut self, id: i16, ty: u8) {
        if self.last.is_empty() {
            self.last.push(0);
        }
        let last = self.last.last_mut().expect("a struct");
        let delta = id - std::mem::replace(last, id);
        if (1..=15).contains(&delta) {
            self.out.push((delta as u8) << 4 | ty);
        } else {
            self.out.push(ty);
            self.varint(zigzag(i64::from(id)));
        }
    }

    fn i32(&mut self, id: i16, n: i32) {
        self.field(id, Self::I32);
        self.varint(zigzag(i64::from(n)));
    }

    fn i64(&mut self, id: i16, n: i64) {
        self.field(id, Self::I64);
        self.varint(zigzag(n));
    }

    fn bool(&mut self, id: i16, b: bool) {
        self.field(id, if b { Self::BOOL_TRUE } else { Self::BOOL_FALSE });
    }

    fn binary(&mut self, id: i16, bytes: &[u8]) {
        self.field(id, Self::BINARY);
        self.varint(bytes.len() as u64);
        self.out.extend_from_slice(bytes);
    }

    /// A list's header: its elements follow, as `element` writes structs.
    fn list(&mut self, id: i16, element: u8, len: usize) {
        self.field(id, Self::LIST);
        if len < 15 {
            self.out.push((len as u8) << 4 | element);
        } else {
            self.out.push(0xf0 | element);
            self.varint(len as u64);
        }
    }

    /// A struct field, written by `fields`.
    fn structure(&mut self, id: i16, fields: impl FnOnce(&mut Thrift)) {
        self.field(id, Self::STRUCT);
        self.element(fields);
    }

    /// A struct (a list's element, or a field's value, after its header).
    fn element(&mut self, fields: impl FnOnce(&mut Thrift)) {
        self.last.push(0);
        fields(self);
        self.out.push(0);
        self.last.pop();
    }

    /// Ends the outermost struct.
    fn stop(&mut self) {
        self.out.push(0);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn columns() -> Vec<Column> {
        vec![
            Column { name: "bucket", ty: Type::Text, required: true },
            Column { name: "key", ty: Type::Text, required: true },
            Column { name: "is_latest", ty: Type::Boolean, required: false },
            Column { name: "size", ty: Type::Int64, required: false },
            Column { name: "last_modified_date", ty: Type::Timestamp, required: false },
            Column { name: "object_lock_event_hold_duration", ty: Type::Int32, required: false },
            Column { name: "e_tag", ty: Type::Text, required: false },
        ]
    }

    fn row(i: i64) -> Vec<Value> {
        vec![
            Value::Text("b".to_owned()),
            Value::Text(format!("k{i:05} é")),
            if i % 3 == 0 { Value::Null } else { Value::Bool(i % 2 == 0) },
            Value::Int(i * 1000),
            Value::Millis(1_763_251_200_123 + i),
            Value::Null,
            if i % 5 == 0 { Value::Null } else { Value::Text(format!("etag{i}")) },
        ]
    }

    #[test]
    fn the_schema_is_s3s() {
        let columns = [
            Column { name: "bucket", ty: Type::Text, required: true },
            Column { name: "is_latest", ty: Type::Boolean, required: false },
            Column { name: "last_modified_date", ty: Type::Timestamp, required: false },
        ];
        assert_eq!(
            schema(&columns),
            "message s3.inventory { required binary bucket (UTF8); optional boolean is_latest; \
             optional int64 last_modified_date (TIMESTAMP_MILLIS);}"
        );
    }

    #[test]
    fn thrift_is_compact() {
        let mut t = Thrift::default();
        t.i32(1, 1);
        t.i64(3, -2);
        t.binary(20, b"ab");
        t.stop();
        // Deltas in the header, zigzag varints; a long jump spells its ID.
        assert_eq!(t.out, [0x15, 0x02, 0x26, 0x03, 0x08, 0x28, 0x02, b'a', b'b', 0x00]);
        assert_eq!(bit_packed_run(&[true, false, true]), [0x03, 0b101]);
    }

    /// Writes a file of `rows` rows, in row groups of about `group` bytes.
    fn file(rows: i64, group: usize) -> Vec<u8> {
        let mut writer = Writer::new(columns());
        let mut out = Vec::new();
        for i in 0..rows {
            writer.push(&row(i));
            if writer.buffered() >= group {
                out.extend(writer.row_group());
            }
        }
        out.extend(writer.finish());
        out
    }

    #[test]
    fn files_are_framed() {
        let data = file(100, 1000);
        assert_eq!(&data[..4], MAGIC);
        assert_eq!(&data[data.len() - 4..], MAGIC);
        let footer = u32::from_le_bytes(data[data.len() - 8..data.len() - 4].try_into().unwrap()) as usize;
        assert!(footer < data.len() - 12);
    }

    /// What pyarrow and DuckDB read of a file, checked by `check` (a
    /// Python script, with the file's path in `path`); skipped where
    /// Python has neither.
    pub(crate) fn read_back(data: &[u8], check: &str) {
        let path = std::env::temp_dir().join(format!("cairn-{}.parquet", uuid::Uuid::new_v4()));
        std::fs::write(&path, data).unwrap();
        let script = format!(
            "import sys\ntry:\n    import pyarrow.parquet as pq, duckdb\nexcept ImportError:\n    sys.exit(77)\n\
             path = sys.argv[1]\n{check}\n"
        );
        let output = std::process::Command::new("python3").arg("-I").arg("-c").arg(&script).arg(&path).output();
        let _ = std::fs::remove_file(&path);
        match output {
            Ok(output) if output.status.code() == Some(77) => eprintln!("skipped: no pyarrow and DuckDB to read Parquet"),
            Ok(output) => assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(_) => eprintln!("skipped: no python3 to read Parquet"),
        }
    }

    #[test]
    fn readers_read_files_back() {
        // Several row groups, and a last one cut short.
        let data = file(2500, 20_000);
        read_back(
            &data,
            r#"
import datetime
f = pq.ParquetFile(path)
assert f.metadata.num_row_groups > 2, f.metadata.num_row_groups
for g in range(f.metadata.num_row_groups):
    for c in range(f.metadata.num_columns):
        assert f.metadata.row_group(g).column(c).compression == "SNAPPY"
t = f.read().to_pylist()
assert len(t) == 2500
for i, r in enumerate(t):
    assert r["bucket"] == "b"
    assert r["key"] == "k%05d é" % i, r
    assert r["is_latest"] == (None if i % 3 == 0 else i % 2 == 0), r
    assert r["size"] == i * 1000
    ms = 1763251200123 + i
    assert r["last_modified_date"] == datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc), r
    assert r["object_lock_event_hold_duration"] is None
    assert r["e_tag"] == (None if i % 5 == 0 else "etag%d" % i), r
s = f.schema_arrow
assert str(s.field("last_modified_date").type) == "timestamp[ms, tz=UTC]", s
assert str(s.field("key").type) == "string", s
assert not s.field("key").nullable and s.field("size").nullable
n = duckdb.connect().execute(f"SELECT count(*), sum(size), count(e_tag), max(key) FROM '{path}'").fetchone()
assert n == (2500, sum(i * 1000 for i in range(2500)), 2000, "k02499 é"), n
"#,
        );
    }

    #[test]
    fn a_file_of_one_row() {
        read_back(&file(1, usize::MAX), "assert pq.read_table(path).num_rows == 1");
    }
}
