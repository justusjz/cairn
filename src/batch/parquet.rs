//! Reading a Parquet inventory report's data files: the `bucket`, `key`
//! and `version_id` columns of S3's inventory schema (see
//! `inventory::parquet`), a row group at a time, with the `parquet` crate.
//!
//! A file's metadata is at its end, and its columns are each in a chunk of
//! their own in each row group, so a file isn't read through, as a CSV one
//! is: `source` reads its footer by a ranged GET, then, of each row group,
//! the chunks of the columns a job needs (`Fetched`), and decodes them here
//! (`Group`) a page at a time. Only those chunks are held, however large
//! the file is, and at most `MAX_GROUP` bytes of them.
//!
//! Keys are as they are, not URL-encoded as CSV reports' are.

use std::sync::Arc;

use bytes::{Buf, Bytes};
use parquet::{
    basic::Type as PhysicalType,
    column::reader::{ColumnReaderImpl, get_column_reader, get_typed_column_reader},
    data_type::{ByteArray, ByteArrayType},
    errors::{ParquetError, Result},
    file::{
        FOOTER_SIZE,
        metadata::{FooterTail, ParquetMetaData, ParquetMetaDataReader, RowGroupMetaData},
        reader::{ChunkReader, Length},
        serialized_reader::SerializedPageReader,
    },
    schema::{parser::parse_message_type, types::SchemaDescriptor},
};

/// How much of a file's end is read first, for its footer: all of it, if
/// it's no longer, as an inventory report's is.
pub const FOOTER_GUESS: u64 = 64 << 10;
/// The longest footer read.
pub const MAX_FOOTER: u64 = 16 << 20;
/// The most of a row group read at once: its chunks of the columns a job
/// reads, compressed.
pub const MAX_GROUP: u64 = 64 << 20;

fn invalid(why: impl Into<String>) -> ParquetError {
    ParquetError::General(why.into())
}

/// The columns of a file a job reads, by their index among its columns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Columns {
    pub bucket: usize,
    pub key: usize,
    pub version_id: Option<usize>,
}

impl Columns {
    /// The columns of `schema` a job reads: `bucket` and `key`, which
    /// every file has, and `version_id`, if it's a report of all versions;
    /// each a string, at the top level. Why they aren't, if they aren't.
    pub fn of(schema: &SchemaDescriptor) -> std::result::Result<Columns, String> {
        let find = |name: &str| {
            let Some(i) = schema
                .columns()
                .iter()
                .position(|c| matches!(c.path().parts(), [only] if only == name))
            else {
                return Ok(None);
            };
            let column = schema.column(i);
            if column.physical_type() != PhysicalType::BYTE_ARRAY || column.max_rep_level() > 0 {
                return Err(format!("its {name} column isn't a string"));
            }
            Ok(Some(i))
        };
        let bucket = find("bucket")?.ok_or("it has no bucket column")?;
        let key = find("key")?.ok_or("it has no key column")?;
        Ok(Columns {
            bucket,
            key,
            version_id: find("version_id")?,
        })
    }

    /// The columns of a schema as a manifest's `fileSchema` gives it
    /// (`message s3.inventory { … }`).
    pub fn of_message(message: &str) -> std::result::Result<Columns, String> {
        let schema =
            parse_message_type(message).map_err(|e| format!("isn't a Parquet schema ({e})"))?;
        Columns::of(&SchemaDescriptor::new(Arc::new(schema)))
    }

    fn all(self) -> impl Iterator<Item = usize> {
        [Some(self.bucket), Some(self.key), self.version_id]
            .into_iter()
            .flatten()
    }
}

/// The length of the metadata a file's last bytes, `end`, end with.
pub fn metadata_length(end: &[u8]) -> Result<u64> {
    let tail: &[u8; FOOTER_SIZE] = end
        .get(end.len().saturating_sub(FOOTER_SIZE)..)
        .and_then(|tail| tail.try_into().ok())
        .ok_or_else(|| invalid("it's too short"))?;
    let tail = FooterTail::try_new(tail)?;
    if tail.is_encrypted_footer() {
        return Err(invalid("its footer is encrypted"));
    }
    Ok(tail.metadata_length() as u64)
}

/// The metadata a file's last bytes, `end`, end with, if they're all of
/// its footer.
pub fn metadata(end: &[u8]) -> Result<ParquetMetaData> {
    let length = metadata_length(end)? as usize;
    let start = (end.len() - FOOTER_SIZE)
        .checked_sub(length)
        .ok_or_else(|| invalid("its footer is cut short"))?;
    ParquetMetaDataReader::decode_metadata(&end[start..end.len() - FOOTER_SIZE])
}

/// The byte ranges of a row group that a job reads: its chunks of
/// `columns` (their start and length); too many of them to read at once
/// is why not.
pub fn ranges(group: &RowGroupMetaData, columns: Columns) -> Result<Vec<(u64, u64)>> {
    let ranges: Vec<(u64, u64)> = columns
        .all()
        .map(|i| group.column(i).byte_range())
        .collect();
    if ranges.iter().map(|(_, length)| length).sum::<u64>() > MAX_GROUP {
        return Err(invalid(format!(
            "it has a row group of more than {} MiB of buckets and keys",
            MAX_GROUP >> 20
        )));
    }
    Ok(ranges)
}

/// Parts of a file, as they've been read: what its chunks are read from.
pub struct Fetched {
    pub size: u64,
    /// Each part's start, and its bytes.
    pub parts: Vec<(u64, Bytes)>,
}

impl Fetched {
    /// The part holding `length` bytes from `start` (at least the one
    /// there, so that a read from where one part ends and the next starts
    /// is of the next), and where they are in it.
    fn find(&self, start: u64, length: usize) -> Result<(&Bytes, usize)> {
        self.parts
            .iter()
            .find(|(from, data)| {
                *from <= start && start + length.max(1) as u64 <= from + data.len() as u64
            })
            .map(|(from, data)| (data, (start - from) as usize))
            .ok_or_else(|| invalid(format!("its bytes {start}..+{length} weren't read")))
    }
}

impl Length for Fetched {
    fn len(&self) -> u64 {
        self.size
    }
}

impl ChunkReader for Fetched {
    type T = bytes::buf::Reader<Bytes>;

    fn get_read(&self, start: u64) -> Result<Self::T> {
        let (data, at) = self.find(start, 0)?;
        Ok(data.slice(at..).reader())
    }

    fn get_bytes(&self, start: u64, length: usize) -> Result<Bytes> {
        let (data, at) = self.find(start, length)?;
        Ok(data.slice(at..at + length))
    }
}

/// A row: its bucket, key, and version ID (`None`: null).
pub type Row = [Option<Vec<u8>>; 3];

/// A column of a row group, being read.
struct Column {
    reader: ColumnReaderImpl<ByteArrayType>,
    /// Whether it's optional: whether its rows have definition levels.
    optional: bool,
}

impl Column {
    /// Its next `n` rows' values.
    fn read(&mut self, n: usize) -> Result<Vec<Option<Vec<u8>>>> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            let (mut levels, mut values) = (Vec::new(), Vec::<ByteArray>::new());
            let (records, _, _) = self.reader.read_records(
                n - out.len(),
                self.optional.then_some(&mut levels),
                None,
                &mut values,
            )?;
            if records == 0 {
                return Err(invalid("a column ends before its row group does"));
            }
            let mut values = values.into_iter().map(|v| v.data().to_vec());
            if self.optional {
                for level in levels {
                    out.push(if level > 0 {
                        Some(
                            values
                                .next()
                                .ok_or_else(|| invalid("a column is cut short"))?,
                        )
                    } else {
                        None
                    });
                }
            } else {
                out.extend(values.map(Some));
            }
        }
        Ok(out)
    }
}

/// A row group's rows, being read.
pub struct Group {
    columns: Vec<Column>,
    /// Whether it has version IDs.
    versioned: bool,
    /// Rows not yet read.
    pub left: u64,
}

impl Group {
    /// Reads row group `index` of a file of `metadata`, from what was
    /// fetched of it (its `ranges`).
    pub fn new(
        data: Arc<Fetched>,
        metadata: &ParquetMetaData,
        index: usize,
        columns: Columns,
    ) -> Result<Group> {
        let group = metadata.row_group(index);
        let schema = metadata.file_metadata().schema_descr();
        let rows = usize::try_from(group.num_rows())
            .map_err(|_| invalid("a row group has fewer than no rows"))?;
        let column = |i: usize| -> Result<Column> {
            let pages = SerializedPageReader::new(data.clone(), group.column(i), rows, None)?;
            let descr = schema.column(i);
            let optional = descr.max_def_level() > 0;
            Ok(Column {
                reader: get_typed_column_reader(get_column_reader(descr, Box::new(pages))),
                optional,
            })
        };
        Ok(Group {
            columns: columns.all().map(column).collect::<Result<_>>()?,
            versioned: columns.version_id.is_some(),
            left: rows as u64,
        })
    }

    /// Skips its next `n` rows (no more than are left).
    pub fn skip(&mut self, n: u64) -> Result<()> {
        for column in &mut self.columns {
            if column.reader.skip_records(n as usize)? != n as usize {
                return Err(invalid("a column ends before its row group does"));
            }
        }
        self.left -= n;
        Ok(())
    }

    /// Its next rows, up to `n`.
    pub fn read(&mut self, n: usize) -> Result<Vec<Row>> {
        let n = n.min(self.left as usize);
        let mut columns = self
            .columns
            .iter_mut()
            .map(|c| c.read(n))
            .collect::<Result<Vec<_>>>()?
            .into_iter();
        let (buckets, keys) = (
            columns.next().expect("a bucket column"),
            columns.next().expect("a key column"),
        );
        let versions = match self.versioned {
            true => columns.next().expect("a version ID column"),
            false => vec![None; n],
        };
        self.left -= n as u64;
        Ok(buckets
            .into_iter()
            .zip(keys)
            .zip(versions)
            .map(|((b, k), v)| [b, k, v])
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::parquet::{Column as Out, Type, Value, Writer};

    /// A file of `rows` rows of an inventory of all versions (but every
    /// third row has none), in row groups of about `group` bytes.
    fn file(rows: usize, group: usize) -> Vec<u8> {
        let columns = vec![
            Out {
                name: "bucket",
                ty: Type::Text,
                required: true,
            },
            Out {
                name: "key",
                ty: Type::Text,
                required: true,
            },
            Out {
                name: "size",
                ty: Type::Int64,
                required: false,
            },
            Out {
                name: "version_id",
                ty: Type::Text,
                required: false,
            },
        ];
        let mut writer = Writer::new(columns).unwrap();
        let mut out = Vec::new();
        for i in 0..rows {
            let version = if i % 3 == 0 {
                Value::Null
            } else {
                Value::Text(format!("v{i}"))
            };
            writer.push(&[
                Value::Text("b".to_owned()),
                Value::Text(format!("k {i}")),
                Value::Int(i as i64),
                version,
            ]);
            if writer.buffered() >= group {
                out.extend(writer.row_group().unwrap());
            }
        }
        out.extend(writer.finish().unwrap());
        out
    }

    fn row(i: usize) -> Row {
        [
            Some(b"b".to_vec()),
            Some(format!("k {i}").into_bytes()),
            (!i.is_multiple_of(3)).then(|| format!("v{i}").into_bytes()),
        ]
    }

    /// Reads row group `index`, fetching only its ranges.
    fn group(data: &[u8], metadata: &ParquetMetaData, index: usize, columns: Columns) -> Group {
        let parts = ranges(metadata.row_group(index), columns)
            .unwrap()
            .into_iter()
            .map(|(start, length)| {
                (
                    start,
                    Bytes::copy_from_slice(&data[start as usize..(start + length) as usize]),
                )
            })
            .collect();
        Group::new(
            Arc::new(Fetched {
                size: data.len() as u64,
                parts,
            }),
            metadata,
            index,
            columns,
        )
        .unwrap()
    }

    #[test]
    fn rows_are_read_a_group_at_a_time() {
        let data = file(1000, 4000);
        let footer = metadata_length(&data).unwrap() as usize + FOOTER_SIZE;
        let metadata = metadata(&data[data.len() - footer..]).unwrap();
        assert!(
            metadata.num_row_groups() > 2,
            "{}",
            metadata.num_row_groups()
        );
        let columns = Columns::of(metadata.file_metadata().schema_descr()).unwrap();
        assert_eq!(
            columns,
            Columns {
                bucket: 0,
                key: 1,
                version_id: Some(3)
            }
        );
        let mut rows = Vec::new();
        for index in 0..metadata.num_row_groups() {
            let mut group = group(&data, &metadata, index, columns);
            while group.left > 0 {
                rows.extend(group.read(7).unwrap());
            }
            assert!(group.read(7).unwrap().is_empty());
        }
        assert_eq!(rows, (0..1000).map(row).collect::<Vec<_>>());
    }

    #[test]
    fn rows_are_skipped() {
        let data = file(100, usize::MAX);
        let metadata = metadata(&data).unwrap();
        let columns = Columns::of(metadata.file_metadata().schema_descr()).unwrap();
        let mut group = group(&data, &metadata, 0, columns);
        group.skip(40).unwrap();
        assert_eq!(group.read(2).unwrap(), vec![row(40), row(41)]);
        assert_eq!(group.left, 58);
        // Without its version IDs.
        let mut group = group_without_versions(&data, &metadata);
        group.skip(99).unwrap();
        assert_eq!(
            group.read(5).unwrap(),
            vec![[row(99)[0].clone(), row(99)[1].clone(), None]]
        );
    }

    fn group_without_versions(data: &[u8], metadata: &ParquetMetaData) -> Group {
        group(
            data,
            metadata,
            0,
            Columns {
                bucket: 0,
                key: 1,
                version_id: None,
            },
        )
    }

    #[test]
    fn footers_are_found() {
        let data = file(10, usize::MAX);
        let length = metadata_length(&data).unwrap();
        assert!(length > 0 && length < data.len() as u64);
        // Too little of it read.
        assert!(metadata(&data[data.len() - 10..]).is_err());
        assert!(metadata_length(b"PAR1").is_err());
        assert!(metadata_length(b"not a parquet file").is_err());
    }

    #[test]
    fn schemas_name_buckets_and_keys() {
        let columns = Columns::of_message(
            "message s3.inventory { required binary bucket (UTF8); required binary key (STRING); \
             optional binary version_id (UTF8); optional boolean is_latest; }",
        );
        assert_eq!(
            columns,
            Ok(Columns {
                bucket: 0,
                key: 1,
                version_id: Some(2)
            })
        );
        let current = Columns::of_message(
            "message s3.inventory { optional int64 size; required binary key; required binary bucket; }",
        );
        assert_eq!(
            current,
            Ok(Columns {
                bucket: 2,
                key: 1,
                version_id: None
            })
        );
        assert!(Columns::of_message("message s3.inventory { required binary bucket; }").is_err());
        assert!(
            Columns::of_message(
                "message s3.inventory { required int64 bucket; required binary key; }"
            )
            .is_err()
        );
        assert!(
            Columns::of_message(
                "message s3.inventory { required binary bucket; repeated binary key; }"
            )
            .is_err()
        );
        assert!(Columns::of_message("Bucket, Key").is_err());
    }
}
