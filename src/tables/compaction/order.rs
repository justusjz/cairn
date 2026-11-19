//! Ordering the rows compaction rewrites, as its strategy says: by the
//! table's sort order (`sort`), or by the z-order of the sort order's
//! columns (`z-order`), in as little memory as it's given. Rows are
//! compared by Arrow's row format (`arrow_row`): their keys converted once
//! to bytes that compare as the keys do, with each key's direction and
//! null order.
//!
//! What's more than the budget is sorted in chunks, each spilled to a
//! local Parquet file (a run), and the runs merged; so a file group of any
//! size is sorted as a whole, as Spark's rewrites sort theirs.
//!
//! Z-order is as Iceberg's (Spark's `ZOrderByteUtils`): each column's value
//! as 8 bytes that order as the value does (numbers with their sign bit
//! flipped, floats with their bits flipped as their sign says, strings and
//! binaries truncated or padded to 8 bytes, null as zeros), and the
//! columns' bits interleaved, most significant first; rows sorted by that.
//! Floats' bits are flipped exactly (Iceberg's shifts them by 31, which
//! orders negative floats slightly off); any z-order is a valid layout.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;

use arrow_array::cast::AsArray;
use arrow_array::types::{
    Date32Type, Float32Type, Float64Type, Int8Type, Int16Type, Int32Type, Int64Type,
    Time64MicrosecondType, TimestampMicrosecondType, TimestampNanosecondType,
};
use arrow_array::{Array, ArrayRef, BinaryArray, RecordBatch, StructArray};
use arrow_row::{OwnedRow, RowConverter, Rows, SortField};
use arrow_schema::{DataType, SortOptions, TimeUnit};
use iceberg::spec::{NullOrder, Schema, SortDirection, SortOrder, Transform};
use parquet::arrow::ArrowWriter;
use parquet::arrow::arrow_reader::{ParquetRecordBatchReader, ParquetRecordBatchReaderBuilder};

/// Why rows can't be ordered.
pub type Error = String;

/// How many rows a batch the sorter gives out holds, at most.
const OUT_ROWS: usize = 8192;

/// The fewest rows a batch of a run being merged holds.
const MERGE_ROWS: usize = 64;

/// The row groups and pages runs are spilled in, at most.
const SPILL_ROW_GROUP: usize = 8 << 20;
const SPILL_PAGE: usize = 64 << 10;

/// The bytes each column contributes to a z-value.
const Z_BYTES: usize = 8;

/// What rows are ordered by.
#[derive(Clone, Debug)]
pub enum Key {
    /// A sort order's fields: a source column (by field ID), its
    /// transform, its direction and null order.
    Sort(Vec<(i32, Transform, SortOptions)>),
    /// The z-order of these columns (by field ID).
    ZOrder(Vec<i32>),
}

impl Key {
    /// Sorting by `order`.
    pub fn sort(order: &SortOrder) -> Key {
        Key::Sort(
            order
                .fields
                .iter()
                .map(|f| {
                    let options = SortOptions {
                        descending: f.direction == SortDirection::Descending,
                        nulls_first: f.null_order == NullOrder::First,
                    };
                    (f.source_id, f.transform, options)
                })
                .collect(),
        )
    }

    /// The z-order of `order`'s source columns.
    pub fn z_order(order: &SortOrder) -> Key {
        let mut ids: Vec<i32> = Vec::new();
        for field in &order.fields {
            if !ids.contains(&field.source_id) {
                ids.push(field.source_id);
            }
        }
        Key::ZOrder(ids)
    }

    /// The columns `batch` is ordered by, and how.
    fn columns(
        &self,
        batch: &RecordBatch,
        schema: &Schema,
    ) -> Result<(Vec<ArrayRef>, Vec<SortField>), Error> {
        match self {
            Key::Sort(fields) => {
                let mut columns = Vec::new();
                let mut sort_fields = Vec::new();
                for (id, transform, options) in fields {
                    let column = column(batch, schema, *id)?;
                    let column = match transform {
                        Transform::Identity => column,
                        transform => iceberg::transform::create_transform_function(transform)
                            .and_then(|f| f.transform(column))
                            .map_err(|e| {
                                format!("Transforming sort field {id}: {}", e.message())
                            })?,
                    };
                    sort_fields.push(SortField::new_with_options(
                        column.data_type().clone(),
                        *options,
                    ));
                    columns.push(column);
                }
                Ok((columns, sort_fields))
            }
            Key::ZOrder(ids) => {
                let columns = ids
                    .iter()
                    .map(|id| column(batch, schema, *id))
                    .collect::<Result<Vec<_>, _>>()?;
                let z = z_values(&columns)?;
                Ok((vec![Arc::new(z)], vec![SortField::new(DataType::Binary)]))
            }
        }
    }
}

/// The column of `batch` that's field `id` of `schema` (nested in structs,
/// by its path).
fn column(batch: &RecordBatch, schema: &Schema, id: i32) -> Result<ArrayRef, Error> {
    let name = schema
        .name_by_field_id(id)
        .ok_or_else(|| format!("The sort order's field {id} isn't in the table's schema."))?;
    let mut parts = name.split('.');
    let first = parts.next().unwrap_or_default();
    let mut array = batch
        .column_by_name(first)
        .cloned()
        .ok_or_else(|| format!("The column {name} isn't in the data."))?;
    for part in parts {
        let parent: &StructArray = array
            .as_struct_opt()
            .ok_or_else(|| format!("The column {name} isn't in a struct."))?;
        array = parent
            .column_by_name(part)
            .cloned()
            .ok_or_else(|| format!("The column {name} isn't in the data."))?;
    }
    Ok(array)
}

/// A value as 8 bytes that order as it does: a signed integer with its sign
/// bit flipped, big-endian.
fn ordered_i64(v: i64) -> [u8; 8] {
    ((v as u64) ^ 0x8000_0000_0000_0000).to_be_bytes()
}

/// A float as 8 bytes that order as it does: its bits, all flipped if it's
/// negative, its sign bit flipped if not.
fn ordered_f64(v: f64) -> [u8; 8] {
    let bits = v.to_bits() as i64;
    let flipped = bits ^ ((bits >> 63) | i64::MIN);
    (flipped as u64).to_be_bytes()
}

/// Bytes (a string's, a binary's) truncated or zero-padded to 8.
fn ordered_bytes(v: &[u8]) -> [u8; 8] {
    let mut out = [0; 8];
    let n = v.len().min(8);
    out[..n].copy_from_slice(&v[..n]);
    out
}

/// Each row's value of `column`, as 8 ordered bytes (zeros for null).
fn ordered_column(column: &ArrayRef) -> Result<Vec<[u8; 8]>, Error> {
    let n = column.len();
    // Each valid row's bytes, as `value` makes them.
    let fill = |value: &dyn Fn(usize) -> [u8; 8]| {
        (0..n)
            .map(|i| match column.is_valid(i) {
                true => value(i),
                false => [0u8; 8],
            })
            .collect::<Vec<_>>()
    };
    macro_rules! ints {
        ($t:ty) => {{
            let a = column.as_primitive::<$t>();
            fill(&|i| ordered_i64(a.value(i) as i64))
        }};
    }
    Ok(match column.data_type() {
        DataType::Int8 => ints!(Int8Type),
        DataType::Int16 => ints!(Int16Type),
        DataType::Int32 => ints!(Int32Type),
        DataType::Int64 => ints!(Int64Type),
        DataType::Date32 => ints!(Date32Type),
        DataType::Time64(TimeUnit::Microsecond) => ints!(Time64MicrosecondType),
        DataType::Timestamp(TimeUnit::Microsecond, _) => ints!(TimestampMicrosecondType),
        DataType::Timestamp(TimeUnit::Nanosecond, _) => ints!(TimestampNanosecondType),
        DataType::Float32 => {
            let a = column.as_primitive::<Float32Type>();
            fill(&|i| ordered_f64(a.value(i) as f64))
        }
        DataType::Float64 => {
            let a = column.as_primitive::<Float64Type>();
            fill(&|i| ordered_f64(a.value(i)))
        }
        DataType::Boolean => {
            let a = column.as_boolean();
            fill(&|i| {
                let mut out = [0u8; 8];
                if a.value(i) {
                    out[0] = 0x81;
                }
                out
            })
        }
        DataType::Utf8 => {
            let a = column.as_string::<i32>();
            fill(&|i| ordered_bytes(a.value(i).as_bytes()))
        }
        DataType::LargeUtf8 => {
            let a = column.as_string::<i64>();
            fill(&|i| ordered_bytes(a.value(i).as_bytes()))
        }
        DataType::Binary => {
            let a = column.as_binary::<i32>();
            fill(&|i| ordered_bytes(a.value(i)))
        }
        DataType::LargeBinary => {
            let a = column.as_binary::<i64>();
            fill(&|i| ordered_bytes(a.value(i)))
        }
        DataType::FixedSizeBinary(_) => {
            let a = column.as_fixed_size_binary();
            fill(&|i| ordered_bytes(a.value(i)))
        }
        other => {
            return Err(format!(
                "Z-order isn't supported for columns of type {other}."
            ));
        }
    })
}

/// The z-values of `columns`' rows: their ordered bytes' bits interleaved,
/// the columns' most significant first.
pub fn z_values(columns: &[ArrayRef]) -> Result<BinaryArray, Error> {
    let n = columns.first().map_or(0, |c| c.len());
    let ordered = columns
        .iter()
        .map(ordered_column)
        .collect::<Result<Vec<_>, _>>()?;
    let width = Z_BYTES * columns.len();
    let mut values: Vec<Vec<u8>> = Vec::with_capacity(n);
    for row in 0..n {
        let mut z = vec![0u8; width];
        let mut out_bit = 0;
        for bit in 0..Z_BYTES * 8 {
            for column in &ordered {
                let byte = column[row][bit / 8];
                if byte & (0x80 >> (bit % 8)) != 0 {
                    z[out_bit / 8] |= 0x80 >> (out_bit % 8);
                }
                out_bit += 1;
            }
        }
        values.push(z);
    }
    Ok(BinaryArray::from_iter_values(values))
}

/// Orders the rows of the batches it's given by its key, in `budget` bytes
/// of memory or so, spilling to `spill_dir` what's more.
pub struct Sorter {
    key: Key,
    schema: Arc<Schema>,
    budget: usize,
    spill_dir: PathBuf,
    converter: Option<RowConverter>,
    buffered: Vec<RecordBatch>,
    buffered_bytes: usize,
    /// All the rows given, and their bytes: what a row takes, on average.
    total_rows: usize,
    total_bytes: usize,
    runs: Vec<PathBuf>,
}

impl Sorter {
    pub fn new(key: Key, schema: Arc<Schema>, budget: usize, spill_dir: PathBuf) -> Sorter {
        Sorter {
            key,
            schema,
            budget,
            spill_dir,
            converter: None,
            buffered: Vec::new(),
            buffered_bytes: 0,
            total_rows: 0,
            total_bytes: 0,
            runs: Vec::new(),
        }
    }

    /// The rows of `batch`'s keys.
    fn rows(&mut self, batch: &RecordBatch) -> Result<Rows, Error> {
        let (columns, fields) = self.key.columns(batch, &self.schema)?;
        if self.converter.is_none() {
            self.converter = Some(RowConverter::new(fields).map_err(|e| e.to_string())?);
        }
        self.converter
            .as_ref()
            .expect("made")
            .convert_columns(&columns)
            .map_err(|e| e.to_string())
    }

    pub fn push(&mut self, batch: RecordBatch) -> Result<(), Error> {
        if batch.num_rows() == 0 {
            return Ok(());
        }
        let bytes = batch.get_array_memory_size();
        self.buffered_bytes += bytes;
        self.total_bytes += bytes;
        self.total_rows += batch.num_rows();
        self.buffered.push(batch);
        if self.buffered_bytes > self.budget {
            self.spill()?;
        }
        Ok(())
    }

    /// The buffered rows, ordered (none, if there are none): the batches
    /// stay as they are, their rows' order is worked out, and the rows are
    /// given out in that order a batch at a time (see `Ordered`); so
    /// sorting takes little memory besides the rows' own.
    fn sort_buffered(&mut self) -> Result<Option<Ordered>, Error> {
        if self.buffered.is_empty() {
            return Ok(None);
        }
        let batches = std::mem::take(&mut self.buffered);
        self.buffered_bytes = 0;
        let rows = batches
            .iter()
            .map(|batch| self.rows(batch))
            .collect::<Result<Vec<_>, _>>()?;
        let mut order: Vec<(usize, usize)> = batches
            .iter()
            .enumerate()
            .flat_map(|(i, batch)| (0..batch.num_rows()).map(move |row| (i, row)))
            .collect();
        order.sort_by(|a, b| rows[a.0].row(a.1).cmp(&rows[b.0].row(b.1)));
        Ok(Some(Ordered {
            batches,
            order,
            offset: 0,
        }))
    }

    /// Sorts what's buffered, and writes it as a run: in small row groups
    /// and pages, so it's written, and read back as it's merged, in little
    /// memory.
    fn spill(&mut self) -> Result<(), Error> {
        let Some(mut ordered) = self.sort_buffered()? else {
            return Ok(());
        };
        std::fs::create_dir_all(&self.spill_dir)
            .map_err(|e| format!("Making the spill directory: {e}"))?;
        let path = self
            .spill_dir
            .join(format!("run-{}.parquet", self.runs.len()));
        let file = File::create(&path).map_err(|e| format!("Spilling: {e}"))?;
        let properties = parquet::file::properties::WriterProperties::builder()
            .set_max_row_group_bytes(Some(SPILL_ROW_GROUP))
            .set_data_page_size_limit(SPILL_PAGE)
            .build();
        let schema = ordered.batches[0].schema();
        let mut writer =
            ArrowWriter::try_new(file, schema, Some(properties)).map_err(|e| e.to_string())?;
        while let Some(batch) = ordered.next_batch(OUT_ROWS)? {
            writer.write(&batch).map_err(|e| e.to_string())?;
        }
        writer.close().map_err(|e| e.to_string())?;
        self.runs.push(path);
        Ok(())
    }

    /// The rows it was given, ordered.
    pub fn finish(mut self) -> Result<Sorted, Error> {
        if self.runs.is_empty() {
            let sorted = self.sort_buffered()?;
            return Ok(Sorted::Memory(sorted));
        }
        self.spill()?;
        // Each run being merged holds a batch: together, about the budget.
        let row_bytes = (self.total_bytes / self.total_rows.max(1)).max(1);
        let batch_rows = (self.budget / self.runs.len() / row_bytes).clamp(MERGE_ROWS, OUT_ROWS);
        let mut runs = Vec::new();
        for path in &self.runs {
            let file = File::open(path).map_err(|e| format!("Reading a spill: {e}"))?;
            let reader = ParquetRecordBatchReaderBuilder::try_new(file)
                .and_then(|b| b.with_batch_size(batch_rows).build())
                .map_err(|e| e.to_string())?;
            runs.push(Run {
                reader,
                batch: None,
                rows: None,
                position: 0,
            });
        }
        let mut merge = Merge {
            sorter: self,
            runs,
            heap: BinaryHeap::new(),
            pending: Vec::new(),
            reload: None,
        };
        for i in 0..merge.runs.len() {
            merge.load(i)?;
        }
        Ok(Sorted::Merge(Box::new(merge)))
    }
}

/// A spilled run, being merged: its current batch, its rows' keys, and
/// where in it the merge is.
struct Run {
    reader: ParquetRecordBatchReader,
    batch: Option<RecordBatch>,
    rows: Option<Rows>,
    position: usize,
}

/// Merging runs: the heap holds each run's next row's key.
pub struct Merge {
    sorter: Sorter,
    runs: Vec<Run>,
    heap: BinaryHeap<Reverse<(OwnedRow, usize)>>,
    /// The rows of the batch being made: (run, row).
    pending: Vec<(usize, usize)>,
    /// A run whose batch is used up, once the pending rows are out.
    reload: Option<usize>,
}

impl Merge {
    /// Loads run `i`'s next batch, and puts its first row in the heap.
    fn load(&mut self, i: usize) -> Result<(), Error> {
        let next = self.runs[i]
            .reader
            .next()
            .transpose()
            .map_err(|e| e.to_string())?;
        match next {
            Some(batch) if batch.num_rows() > 0 => {
                let rows = self.sorter.rows(&batch)?;
                let run = &mut self.runs[i];
                self.heap.push(Reverse((rows.row(0).owned(), i)));
                run.rows = Some(rows);
                run.batch = Some(batch);
                run.position = 0;
            }
            Some(_) => return self.load(i),
            None => {
                let run = &mut self.runs[i];
                run.batch = None;
                run.rows = None;
            }
        }
        Ok(())
    }

    /// The pending rows, as a batch.
    fn flush(&mut self) -> Result<Option<RecordBatch>, Error> {
        if self.pending.is_empty() {
            return Ok(None);
        }
        // Interleave from the runs' current batches (each pending row's run
        // still has the batch it came from: a run is reloaded only after a
        // flush).
        let mut sources: Vec<&RecordBatch> = Vec::new();
        let mut index = vec![usize::MAX; self.runs.len()];
        let mut picks = Vec::with_capacity(self.pending.len());
        for (run, row) in &self.pending {
            if index[*run] == usize::MAX {
                index[*run] = sources.len();
                sources.push(
                    self.runs[*run]
                        .batch
                        .as_ref()
                        .expect("a pending row's batch"),
                );
            }
            picks.push((index[*run], *row));
        }
        let batch = arrow_select::interleave::interleave_record_batch(&sources, &picks)
            .map_err(|e| e.to_string())?;
        self.pending.clear();
        Ok(Some(batch))
    }

    fn next(&mut self) -> Result<Option<RecordBatch>, Error> {
        if let Some(i) = self.reload.take() {
            self.load(i)?;
        }
        loop {
            if self.pending.len() == OUT_ROWS {
                return self.flush();
            }
            let Some(Reverse((_, i))) = self.heap.pop() else {
                return self.flush();
            };
            let run = &mut self.runs[i];
            self.pending.push((i, run.position));
            run.position += 1;
            let length = run.batch.as_ref().map_or(0, RecordBatch::num_rows);
            if run.position < length {
                let row = run.rows.as_ref().expect("rows").row(run.position).owned();
                self.heap.push(Reverse((row, i)));
            } else {
                // Its batch is used up: the pending rows (some of it) go
                // out before it's replaced.
                self.reload = Some(i);
                return self.flush();
            }
        }
    }
}

/// Batches, and the order of their rows: (batch, row) each, and how many
/// are given out.
pub struct Ordered {
    batches: Vec<RecordBatch>,
    order: Vec<(usize, usize)>,
    offset: usize,
}

impl Ordered {
    /// The next `rows` rows, in order, as a batch.
    fn next_batch(&mut self, rows: usize) -> Result<Option<RecordBatch>, Error> {
        if self.offset >= self.order.len() {
            return Ok(None);
        }
        let end = (self.offset + rows).min(self.order.len());
        let sources: Vec<&RecordBatch> = self.batches.iter().collect();
        let batch = arrow_select::interleave::interleave_record_batch(
            &sources,
            &self.order[self.offset..end],
        )
        .map_err(|e| e.to_string())?;
        self.offset = end;
        Ok(Some(batch))
    }
}

/// Sorted rows, as batches.
pub enum Sorted {
    /// In memory.
    Memory(Option<Ordered>),
    Merge(Box<Merge>),
}

impl Sorted {
    /// The next batch of rows, in order.
    pub fn next_batch(&mut self) -> Result<Option<RecordBatch>, Error> {
        match self {
            Sorted::Memory(None) => Ok(None),
            Sorted::Memory(Some(ordered)) => ordered.next_batch(OUT_ROWS),
            Sorted::Merge(merge) => merge.next(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_array::{Int64Array, StringArray};
    use arrow_schema::{Field, Schema as ArrowSchema};
    use iceberg::spec::{NestedField, PrimitiveType, Type};

    fn schema() -> Arc<Schema> {
        Arc::new(
            Schema::builder()
                .with_fields(vec![
                    NestedField::optional(1, "a", Type::Primitive(PrimitiveType::Long)).into(),
                    NestedField::optional(2, "b", Type::Primitive(PrimitiveType::String)).into(),
                ])
                .build()
                .unwrap(),
        )
    }

    fn batch(a: Vec<Option<i64>>, b: Vec<Option<&str>>) -> RecordBatch {
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new("a", DataType::Int64, true),
            Field::new("b", DataType::Utf8, true),
        ]));
        RecordBatch::try_new(
            schema,
            vec![
                Arc::new(Int64Array::from(a)),
                Arc::new(StringArray::from(b)),
            ],
        )
        .unwrap()
    }

    fn drain(mut sorted: Sorted) -> (Vec<Option<i64>>, Vec<Option<String>>) {
        let (mut a, mut b) = (Vec::new(), Vec::new());
        while let Some(batch) = sorted.next_batch().unwrap() {
            a.extend(batch.column(0).as_primitive::<Int64Type>().iter());
            b.extend(
                batch
                    .column(1)
                    .as_string::<i32>()
                    .iter()
                    .map(|s| s.map(str::to_owned)),
            );
        }
        (a, b)
    }

    fn by_a_desc_nulls_first() -> Key {
        Key::Sort(vec![(
            1,
            Transform::Identity,
            SortOptions {
                descending: true,
                nulls_first: true,
            },
        )])
    }

    #[test]
    fn sorts_in_memory_and_by_spilling() {
        // Pseudo-random values, in batches.
        let mut values: Vec<i64> = (0..20_000).map(|i| (i * 7919 + 13) % 10_007).collect();
        let dir = std::env::temp_dir().join(format!("cairn-sort-{}", uuid::Uuid::new_v4()));
        for budget in [usize::MAX, 64 * 1024] {
            let mut sorter = Sorter::new(
                by_a_desc_nulls_first(),
                schema(),
                budget,
                dir.join(budget.to_string()),
            );
            for chunk in values.chunks(1000) {
                let mut a: Vec<Option<i64>> = chunk.iter().map(|v| Some(*v)).collect();
                a.push(None);
                let b = a.iter().map(|v| v.map(|_| "x")).collect();
                sorter.push(batch(a, b)).unwrap();
            }
            let spilled = !sorter.runs.is_empty();
            assert_eq!(spilled, budget != usize::MAX);
            let (a, _) = drain(sorter.finish().unwrap());
            // Nulls first, then descending.
            assert_eq!(a.len(), 20_020);
            assert!(a[..20].iter().all(Option::is_none));
            let rest: Vec<i64> = a[20..].iter().map(|v| v.unwrap()).collect();
            let mut expected = values.clone();
            expected.sort_unstable_by(|x, y| y.cmp(x));
            assert_eq!(rest, expected, "budget {budget}");
        }
        values.clear();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sorts_by_several_fields_and_transforms() {
        let key = Key::Sort(vec![
            (2, Transform::Truncate(1), SortOptions::default()),
            (
                1,
                Transform::Identity,
                SortOptions {
                    descending: false,
                    nulls_first: false,
                },
            ),
        ]);
        let mut sorter = Sorter::new(key, schema(), usize::MAX, std::env::temp_dir());
        sorter
            .push(batch(
                vec![Some(3), None, Some(1), Some(2)],
                vec![Some("bz"), Some("ba"), Some("bq"), Some("az")],
            ))
            .unwrap();
        let (a, b) = drain(sorter.finish().unwrap());
        // By b's first letter, then a (nulls last): "a…", then the "b…"s.
        assert_eq!(a, [Some(2), Some(1), Some(3), None]);
        assert_eq!(b[0].as_deref(), Some("az"));
    }

    #[test]
    fn z_values_interleave_ordered_bits() {
        let a: ArrayRef = Arc::new(Int64Array::from(vec![Some(-1), Some(0), Some(1), None]));
        let b: ArrayRef = Arc::new(StringArray::from(vec![
            Some("a"),
            Some("a"),
            Some("b"),
            None,
        ]));
        let z = z_values(&[a.clone(), b]).unwrap();
        assert_eq!(z.value(0).len(), 16);
        // Ordered bytes: -1 < 0 < 1, and the signs' bits come first.
        assert!(z.value(0) < z.value(1) && z.value(1) < z.value(2));
        // Null is all zeros.
        assert!(z.value(3).iter().all(|b| *b == 0));
        // Interleaving: the first column's top bit, then the second's.
        let one = z_values(&[a.slice(2, 1)]).unwrap();
        assert_eq!(one.value(0), ordered_i64(1));
        assert_eq!(ordered_i64(0)[0], 0x80);
        assert!(ordered_f64(-2.0) < ordered_f64(-1.0));
        assert!(ordered_f64(-1.0) < ordered_f64(0.0) && ordered_f64(0.0) < ordered_f64(1.5));
    }

    #[test]
    fn z_order_clusters_both_columns() {
        // A 16x16 grid: sorted by z-value, each quadrant's points come
        // together.
        let (mut xs, mut ys) = (Vec::new(), Vec::new());
        for x in 0..16i64 {
            for y in 0..16i64 {
                xs.push(x);
                ys.push(y);
            }
        }
        let z = z_values(&[
            Arc::new(Int64Array::from(xs.clone())),
            Arc::new(Int64Array::from(ys.clone())),
        ])
        .unwrap();
        let mut order: Vec<usize> = (0..xs.len()).collect();
        order.sort_by(|a, b| z.value(*a).cmp(z.value(*b)));
        let first: Vec<(i64, i64)> = order[..64].iter().map(|i| (xs[*i], ys[*i])).collect();
        assert!(first.iter().all(|(x, y)| *x < 8 && *y < 8), "{first:?}");
    }
}
