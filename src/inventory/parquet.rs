//! Parquet inventory reports' files, written with the `parquet` crate (its
//! low-level, column-at-a-time API, so that Cairn needn't take on Arrow).
//! A file's columns are flat (no nesting or repetition), each a string,
//! boolean, 32- or 64-bit integer, or timestamp (milliseconds since the
//! epoch, UTC), required or optional, as S3's inventory schema has them
//! (see `schema`).
//!
//! Rows are buffered column by column and written out as a row group when
//! asked (`row_group`), so a file's written as it's made and only a row
//! group of it is ever held. Its pages are v1 and Snappy-compressed, as
//! S3's are.

use std::sync::Arc;

use parquet::{
    basic::Compression,
    data_type::{BoolType, ByteArray, ByteArrayType, Int32Type, Int64Type},
    file::{
        properties::{WriterProperties, WriterVersion},
        writer::SerializedFileWriter,
    },
    schema::parser::parse_message_type,
};

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
/// `message s3.inventory { required binary bucket (UTF8); … }`. It's the
/// schema the file is written with, too.
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

/// A column's values of the row group being made, as its writer takes
/// them: the values (nulls left out), and each row's definition level
/// (1: it has a value; 0: it hasn't), of optional columns.
enum Values {
    Text(Vec<ByteArray>),
    Bool(Vec<bool>),
    Int32(Vec<i32>),
    Int64(Vec<i64>),
}

struct Buffer {
    values: Values,
    levels: Vec<i16>,
}

impl Buffer {
    fn new(column: &Column) -> Buffer {
        let values = match column.ty {
            Type::Text => Values::Text(Vec::new()),
            Type::Boolean => Values::Bool(Vec::new()),
            Type::Int32 => Values::Int32(Vec::new()),
            Type::Int64 | Type::Timestamp => Values::Int64(Vec::new()),
        };
        Buffer { values, levels: Vec::new() }
    }
}

/// A Parquet file being written.
pub struct Writer {
    columns: Vec<Column>,
    /// Writes into its `Vec`, which is taken from it as it's written.
    file: SerializedFileWriter<Vec<u8>>,
    buffers: Vec<Buffer>,
    rows: usize,
    /// Bytes buffered, about.
    buffered: usize,
}

impl Writer {
    pub fn new(columns: Vec<Column>) -> parquet::errors::Result<Writer> {
        let schema = Arc::new(parse_message_type(&schema(&columns))?);
        let properties = WriterProperties::builder()
            .set_writer_version(WriterVersion::PARQUET_1_0)
            .set_compression(Compression::SNAPPY)
            .set_created_by(format!("Cairn {}", env!("CARGO_PKG_VERSION")))
            .build();
        let file = SerializedFileWriter::new(Vec::new(), schema, Arc::new(properties))?;
        let buffers = columns.iter().map(Buffer::new).collect();
        Ok(Writer { columns, file, buffers, rows: 0, buffered: 0 })
    }

    /// Adds a row, a value for each column. A value that isn't of its
    /// column's type, or a null of a required column, is a bug.
    pub fn push(&mut self, row: &[Value]) {
        assert_eq!(row.len(), self.columns.len(), "a value for each column");
        for ((column, buffer), value) in self.columns.iter().zip(&mut self.buffers).zip(row) {
            if !column.required {
                buffer.levels.push(i16::from(*value != Value::Null));
            }
            self.buffered += match (&mut buffer.values, column.ty, value) {
                (_, _, Value::Null) => {
                    assert!(!column.required, "a value of required column {}", column.name);
                    0
                }
                (Values::Text(values), Type::Text, Value::Text(text)) => {
                    values.push(ByteArray::from(text.as_bytes().to_vec()));
                    4 + text.len()
                }
                (Values::Bool(values), Type::Boolean, Value::Bool(b)) => {
                    values.push(*b);
                    1
                }
                (Values::Int32(values), Type::Int32, Value::Int(i)) => {
                    values.push(i32::try_from(*i).expect("an int32 in range"));
                    4
                }
                (Values::Int64(values), Type::Int64, Value::Int(i))
                | (Values::Int64(values), Type::Timestamp, Value::Millis(i)) => {
                    values.push(*i);
                    8
                }
                (_, ty, value) => panic!("column {} is {ty:?}, not {value:?}", column.name),
            } + 1;
        }
        self.rows += 1;
    }

    /// About how many bytes of rows are buffered, uncompressed.
    pub fn buffered(&self) -> usize {
        self.buffered
    }

    /// The buffered rows, as a row group (after the file's magic, at its
    /// start): what's to be written next. Nothing if no rows are buffered
    /// (but the magic, at first).
    pub fn row_group(&mut self) -> parquet::errors::Result<Vec<u8>> {
        if self.rows > 0 {
            let mut group = self.file.next_row_group()?;
            for (column, buffer) in self.columns.iter().zip(std::mem::take(&mut self.buffers)) {
                let mut writer = group.next_column()?.expect("a writer for each column");
                let levels = (!column.required).then_some(&buffer.levels[..]);
                match buffer.values {
                    Values::Text(values) => writer.typed::<ByteArrayType>().write_batch(&values, levels, None)?,
                    Values::Bool(values) => writer.typed::<BoolType>().write_batch(&values, levels, None)?,
                    Values::Int32(values) => writer.typed::<Int32Type>().write_batch(&values, levels, None)?,
                    Values::Int64(values) => writer.typed::<Int64Type>().write_batch(&values, levels, None)?,
                };
                writer.close()?;
            }
            group.close()?;
            self.buffers = self.columns.iter().map(Buffer::new).collect();
            self.rows = 0;
            self.buffered = 0;
        }
        Ok(self.take()?)
    }

    /// The rest of the file: the buffered rows' row group, and the footer.
    pub fn finish(&mut self) -> parquet::errors::Result<Vec<u8>> {
        let mut out = self.row_group()?;
        self.file.finish()?;
        out.extend(self.take()?);
        Ok(out)
    }

    /// What's been written since it was last taken.
    fn take(&mut self) -> std::io::Result<Vec<u8>> {
        self.file.flush()?;
        Ok(std::mem::take(self.file.inner_mut()))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use parquet::{
        file::reader::{FileReader, SerializedFileReader},
        record::Field,
    };

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

    /// Writes a file of `rows` rows, in row groups of about `group` bytes.
    pub(crate) fn file(rows: i64, group: usize) -> Vec<u8> {
        let mut writer = Writer::new(columns()).unwrap();
        let mut out = Vec::new();
        for i in 0..rows {
            writer.push(&row(i));
            if writer.buffered() >= group {
                out.extend(writer.row_group().unwrap());
            }
        }
        out.extend(writer.finish().unwrap());
        out
    }

    #[test]
    fn files_are_read_back() {
        // Several row groups, and a last one cut short.
        let reader = SerializedFileReader::new(bytes::Bytes::from(file(2500, 20_000))).unwrap();
        let metadata = reader.metadata();
        assert!(metadata.num_row_groups() > 2, "{}", metadata.num_row_groups());
        for group in metadata.row_groups() {
            assert!(group.columns().iter().all(|c| c.compression() == Compression::SNAPPY));
        }
        let rows: Vec<_> = reader.get_row_iter(None).unwrap().map(Result::unwrap).collect();
        assert_eq!(rows.len(), 2500);
        for (i, row) in rows.iter().enumerate() {
            let i = i as i64;
            let fields: Vec<&Field> = row.get_column_iter().map(|(_, f)| f).collect();
            assert_eq!(fields[0], &Field::Str("b".to_owned()));
            assert_eq!(fields[1], &Field::Str(format!("k{i:05} é")));
            assert_eq!(fields[2], &if i % 3 == 0 { Field::Null } else { Field::Bool(i % 2 == 0) });
            assert_eq!(fields[3], &Field::Long(i * 1000));
            assert_eq!(fields[4], &Field::TimestampMillis(1_763_251_200_123 + i));
            assert_eq!(fields[5], &Field::Null);
            assert_eq!(fields[6], &if i % 5 == 0 { Field::Null } else { Field::Str(format!("etag{i}")) });
        }
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
