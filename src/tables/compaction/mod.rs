//! Compaction, as S3 Tables' (`icebergCompaction`): a table's small data
//! files (and those with deletes, and oversized ones) rewritten into files
//! of its target size, its deletes applied, its rows ordered as its
//! strategy says, committed as a `replace` snapshot: the same rows, stored
//! better. A maintenance job (see `maintenance`), on by default, as AWS's.
//!
//! - **Planning.** The current snapshot's data files, by partition (spec
//!   and value). A file is a candidate if it's under 75% of the target
//!   size, over 180% of it, or has delete files; a partition's candidates
//!   are rewritten if there are 5 or more, or 2 or more that together reach
//!   the target, or any has deletes or is oversized (Iceberg's Java
//!   rewrite's defaults). A run rewrites at most `MAX_RUN_BYTES`; the rest
//!   is soon after.
//! - **Rewriting** (the `iceberg` crate): a group's files read with their
//!   deletes applied (position, equality, deletion vectors), in the
//!   table's current schema, ordered (`order`), and written as Parquet
//!   files rolling over at the target size, in the group's partition, with
//!   their metrics; compressed as the table's
//!   `write.parquet.compression-codec` says (zstd by default). Of format
//!   version 3, each row keeps its lineage (`_row_id`,
//!   `_last_updated_sequence_number`), written into the new files.
//! - **Strategies.** `binpack`: rows as they're read. `sort`: by the
//!   table's sort order. `z-order`: by the z-order of its sort order's
//!   columns. `auto`: `sort` if the table has a sort order, else
//!   `binpack`. `sort` and `z-order` need a sort order.
//! - **Committing.** A `replace` snapshot: manifests holding rewritten
//!   files rewritten, those files in them deleted; the new files in new
//!   manifests; the rest as they were. Delete files that apply to nothing
//!   any more (no data file they could apply to is left that isn't newer)
//!   are removed too, as Iceberg's rewrites remove dangling deletes. The pointer is swapped against the table's version token,
//!   as any commit's. A commit that came in meanwhile is fine if it only
//!   appended (the replace is made again on top of it); any other (a
//!   delete, an overwrite: it may have deleted rows of the rewritten files)
//!   drops the rewrite, which is tried again at the next run. Its files are
//!   then unreferenced, and removed as such.
//!
//! The files it replaces stay as long as snapshots reference them: snapshot
//! management expires those, and unreferenced file removal deletes the
//! files.

pub mod order;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::StreamExt;
use iceberg::spec::{
    DataFile, DataFileFormat, FormatVersion, ManifestContentType, ManifestFile, ManifestListWriter,
    ManifestWriterBuilder, PartitionKey, Schema, Struct, TableMetadata, TableMetadataBuilder,
};
use iceberg::writer::base_writer::data_file_writer::DataFileWriterBuilder;
use iceberg::writer::file_writer::ParquetWriterBuilder;
use iceberg::writer::file_writer::location_generator::{
    DefaultFileNameGenerator, DefaultLocationGenerator,
};
use iceberg::writer::file_writer::rolling_writer::RollingFileWriterBuilder;
use iceberg::writer::{IcebergWriter, IcebergWriterBuilder};
use iceberg::{TableUpdate, scan::FileScanTask};
use parquet::basic::{Compression, GzipLevel, ZstdLevel};
use parquet::file::properties::WriterProperties;
use serde_json::json;
use uuid::Uuid;

use super::{
    Table,
    iceberg::{self as cairn_iceberg, FileError},
    maintenance::Outcome,
    table::table_maintenance,
};
use crate::App;
use order::{Key, Sorter};

pub const COMPACTION: &str = "icebergCompaction";

/// The directory (in the node's first data dir) sorts spill to, emptied as
/// the node starts (see `iceberg::io::clean`) and as a job starts.
pub const SPILL: &str = "table-compaction";

/// Which files are candidates: under this share of the target size, or
/// over that.
const MIN_RATIO: f64 = 0.75;
const MAX_RATIO: f64 = 1.8;
/// How many candidates of a partition make it worth rewriting, by
/// themselves.
const MIN_INPUT_FILES: usize = 5;
/// The most a run rewrites, and a group holds.
const MAX_RUN_BYTES: u64 = 16 << 30;
/// The memory a sort takes before it spills.
const SORT_BUDGET: usize = 64 << 20;
/// How many times a commit is made again, on top of others' appends.
const COMMIT_ATTEMPTS: usize = 5;

/// How rows are ordered.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Strategy {
    Binpack,
    Sort,
    ZOrder,
}

/// What a group of files is: its partition spec's ID and partition, and
/// its files' scan tasks.
struct Group {
    spec_id: i32,
    partition: Option<Struct>,
    tasks: Vec<FileScanTask>,
}

fn ms(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

/// The groups worth rewriting, of `tasks` (a snapshot's files), at most
/// `MAX_RUN_BYTES` of them; and whether there's more.
fn plan(tasks: Vec<FileScanTask>, target: u64) -> (Vec<Group>, bool) {
    let mut partitions: Vec<Group> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for task in tasks {
        if task.data_file_format() != DataFileFormat::Parquet {
            continue;
        }
        let spec_id = task.partition_spec().map_or(0, |s| s.spec_id());
        let partition = task.partition().cloned();
        let key = format!("{spec_id}/{partition:?}");
        let i = *index.entry(key).or_insert_with(|| {
            partitions.push(Group {
                spec_id,
                partition,
                tasks: Vec::new(),
            });
            partitions.len() - 1
        });
        // A file's tasks are one, or its splits: once.
        if !partitions[i]
            .tasks
            .iter()
            .any(|t| t.data_file_path() == task.data_file_path())
        {
            partitions[i].tasks.push(task);
        }
    }
    let small = (target as f64 * MIN_RATIO) as u64;
    let large = (target as f64 * MAX_RATIO) as u64;
    let mut groups = Vec::new();
    let mut total = 0;
    let mut more = false;
    for partition in partitions {
        let candidates: Vec<FileScanTask> = partition
            .tasks
            .into_iter()
            .filter(|t| {
                let size = t.file_size_in_bytes();
                size < small || size > large || !t.deletes().is_empty()
            })
            .collect();
        let bytes: u64 = candidates
            .iter()
            .map(FileScanTask::file_size_in_bytes)
            .sum();
        let forced = candidates
            .iter()
            .any(|t| !t.deletes().is_empty() || t.file_size_in_bytes() > large);
        let worth = candidates.len() >= MIN_INPUT_FILES
            || (candidates.len() >= 2 && bytes >= target)
            || forced;
        if !worth {
            continue;
        }
        // In groups of at most MAX_RUN_BYTES, as many as a run takes.
        let mut group = Vec::new();
        let mut group_bytes = 0;
        for task in candidates {
            if total + task.file_size_in_bytes() > MAX_RUN_BYTES && total > 0 {
                more = true;
                break;
            }
            if group_bytes + task.file_size_in_bytes() > MAX_RUN_BYTES && !group.is_empty() {
                groups.push(Group {
                    spec_id: partition.spec_id,
                    partition: partition.partition.clone(),
                    tasks: std::mem::take(&mut group),
                });
                group_bytes = 0;
            }
            total += task.file_size_in_bytes();
            group_bytes += task.file_size_in_bytes();
            group.push(task);
        }
        if !group.is_empty() {
            groups.push(Group {
                spec_id: partition.spec_id,
                partition: partition.partition.clone(),
                tasks: group,
            });
        }
        if more {
            break;
        }
    }
    (groups, more)
}

/// Writer properties as `metadata`'s say: its compression.
fn writer_properties(metadata: &TableMetadata) -> Result<WriterProperties, String> {
    let properties = metadata.properties();
    let level = properties
        .get("write.parquet.compression-level")
        .and_then(|l| l.parse::<i32>().ok());
    let codec = properties
        .get("write.parquet.compression-codec")
        .map(|c| c.to_ascii_lowercase())
        .unwrap_or_else(|| "zstd".to_owned());
    let compression = match codec.as_str() {
        "zstd" => Compression::ZSTD(
            level
                .map(ZstdLevel::try_new)
                .transpose()
                .map_err(|e| e.to_string())?
                .unwrap_or_default(),
        ),
        "gzip" => Compression::GZIP(
            level
                .map(|l| GzipLevel::try_new(l as u32))
                .transpose()
                .map_err(|e| e.to_string())?
                .unwrap_or_default(),
        ),
        "snappy" => Compression::SNAPPY,
        "uncompressed" | "none" => Compression::UNCOMPRESSED,
        other => {
            return Err(format!(
                "Compaction doesn't write the compression codec {other}."
            ));
        }
    };
    // A row group is held in memory, encoded, until it's complete: so it's
    // kept to `write.parquet.row-group-size-bytes`, at most `ROW_GROUP`.
    let row_group = properties
        .get("write.parquet.row-group-size-bytes")
        .and_then(|b| b.parse::<usize>().ok())
        .filter(|b| *b > 0)
        .map_or(ROW_GROUP, |b| b.min(ROW_GROUP));
    Ok(WriterProperties::builder()
        .set_compression(compression)
        .set_max_row_group_bytes(Some(row_group))
        .build())
}

/// The largest row group compaction writes (Iceberg's default is 128 MiB):
/// what a file being written holds in memory, at most.
const ROW_GROUP: usize = 32 << 20;

/// The table's strategy, as its configuration (`strategy`) and sort order
/// say it.
fn strategy(name: &str, metadata: &TableMetadata) -> Result<Strategy, String> {
    let sorted = !metadata.default_sort_order().fields.is_empty();
    match (name, sorted) {
        ("auto", true) => Ok(Strategy::Sort),
        ("auto" | "binpack", _) => Ok(Strategy::Binpack),
        ("sort", true) => Ok(Strategy::Sort),
        ("z-order", true) => Ok(Strategy::ZOrder),
        (s @ ("sort" | "z-order"), false) => Err(format!(
            "The {s} strategy needs a sort order, which the table hasn't."
        )),
        (other, _) => Err(format!("The strategy {other} isn't one.")),
    }
}

/// The schema files are written in: the table's, and (of format version
/// 3) its rows' lineage.
fn write_schema(metadata: &TableMetadata) -> Result<Arc<Schema>, String> {
    let schema = metadata.current_schema();
    if metadata.format_version() < FormatVersion::V3 {
        return Ok(schema.clone());
    }
    let mut fields: Vec<_> = schema.as_struct().fields().to_vec();
    fields.push(iceberg::metadata_columns::row_id_field().clone());
    fields.push(iceberg::metadata_columns::last_updated_sequence_number_field().clone());
    Schema::builder()
        .with_schema_id(schema.schema_id())
        .with_fields(fields)
        .build()
        .map(Arc::new)
        .map_err(|e| e.message().to_owned())
}

/// Compacts `table`, as of `now`.
pub async fn compact(app: &Arc<App>, table: &Table, now: SystemTime) -> anyhow::Result<Outcome> {
    let configuration = table_maintenance(&table.maintenance);
    let value = &configuration[COMPACTION];
    if value["status"] != "enabled" {
        return Ok(Outcome::Disabled);
    }
    let settings = &value["settings"][COMPACTION];
    let target = settings["targetFileSizeMB"].as_u64().unwrap_or(512) << 20;
    let name = settings["strategy"].as_str().unwrap_or("auto").to_owned();
    let (_, metadata) = match super::maintenance::current(app, table).await? {
        Ok(current) => current,
        Err(why) => return Ok(Outcome::Failed(why)),
    };
    if !cairn_iceberg::supported(metadata.format_version()) {
        return Ok(Outcome::Failed(format!(
            "Compaction isn't supported for format version {}.",
            metadata.format_version()
        )));
    }
    if let Some(format) = metadata.properties().get("write.format.default")
        && !format.eq_ignore_ascii_case("parquet")
    {
        return Ok(Outcome::Failed(format!(
            "Compaction writes Parquet, not the table's {format}."
        )));
    }
    let Some(snapshot) = metadata.current_snapshot().cloned() else {
        return Ok(Outcome::Successful("nothing to compact".into()));
    };
    let strategy = match strategy(&name, &metadata) {
        Ok(strategy) => strategy,
        Err(why) => return Ok(Outcome::Failed(why)),
    };
    let properties = match writer_properties(&metadata) {
        Ok(properties) => properties,
        Err(why) => return Ok(Outcome::Failed(why)),
    };
    let io = cairn_iceberg::io::file_io(app, table, None);
    let reader = iceberg::table::Table::builder()
        .metadata(metadata.clone())
        .identifier(iceberg::TableIdent::from_strs(["compaction", "table"])?)
        .file_io(io.clone())
        .runtime(iceberg::Runtime::current())
        .readonly(true)
        .build()?;
    let v3 = metadata.format_version() >= FormatVersion::V3;
    let mut columns: Vec<String> = metadata
        .current_schema()
        .as_struct()
        .fields()
        .iter()
        .map(|f| f.name.clone())
        .collect();
    if v3 {
        columns.push(iceberg::metadata_columns::RESERVED_COL_NAME_ROW_ID.to_owned());
        columns.push(
            iceberg::metadata_columns::RESERVED_COL_NAME_LAST_UPDATED_SEQUENCE_NUMBER.to_owned(),
        );
    }
    let scan = reader
        .scan()
        .snapshot_id(snapshot.snapshot_id())
        .select(columns)
        .build()?;
    let mut tasks = Vec::new();
    let mut planned = scan.plan_files().await?;
    while let Some(task) = planned.next().await {
        tasks.push(task?);
    }
    let (groups, more) = plan(tasks, target);
    if groups.is_empty() {
        return Ok(Outcome::Successful("nothing to compact".into()));
    }
    let schema = match write_schema(&metadata) {
        Ok(schema) => schema,
        Err(why) => return Ok(Outcome::Failed(why)),
    };
    let key = match strategy {
        Strategy::Binpack => None,
        Strategy::Sort => Some(Key::sort(metadata.default_sort_order())),
        Strategy::ZOrder => Some(Key::z_order(metadata.default_sort_order())),
    };
    let spill_root = app.store.data_dir().join(SPILL);
    // Only one job runs on a node at a time (see `maintenance::pass`):
    // what's there is a crashed one's.
    let _ = std::fs::remove_dir_all(&spill_root);
    let mut rewritten = HashSet::new();
    let mut added: Vec<(i32, Vec<DataFile>)> = Vec::new();
    let mut input_files = 0;
    for group in groups {
        let spill = spill_root.join(Uuid::new_v4().to_string());
        let files = rewrite(
            &reader,
            &metadata,
            &group,
            key.clone(),
            schema.clone(),
            properties.clone(),
            target,
            spill.clone(),
        )
        .await;
        let _ = std::fs::remove_dir_all(&spill);
        let files = match files {
            Ok(files) => files,
            Err(why) => return Ok(Outcome::Failed(why)),
        };
        input_files += group.tasks.len();
        rewritten.extend(group.tasks.iter().map(|t| t.data_file_path().to_owned()));
        added.push((group.spec_id, files));
    }
    let output_files: usize = added.iter().map(|(_, f)| f.len()).sum();
    match commit(
        app,
        table.id,
        snapshot.snapshot_id(),
        &rewritten,
        added,
        now,
    )
    .await?
    {
        Ok(()) => {
            let report = format!("{input_files} file(s) rewritten into {output_files}");
            Ok(match more {
                true => Outcome::More(report),
                false => Outcome::Successful(report),
            })
        }
        Err(why) => Ok(Outcome::Failed(why)),
    }
}

/// Rewrites `group`'s files: their rows, ordered by `key` (if any), into
/// new files of about `target` bytes.
#[allow(clippy::too_many_arguments)]
async fn rewrite(
    reader: &iceberg::table::Table,
    metadata: &TableMetadata,
    group: &Group,
    key: Option<Key>,
    schema: Arc<Schema>,
    properties: WriterProperties,
    target: u64,
    spill: std::path::PathBuf,
) -> Result<Vec<DataFile>, String> {
    // The error, and what caused it.
    let e = |e: iceberg::Error| {
        let mut why = e.message().to_owned();
        let mut source = std::error::Error::source(&e);
        while let Some(cause) = source {
            why.push_str(&format!(": {cause}"));
            source = cause.source();
        }
        why
    };
    let tasks: Vec<iceberg::Result<FileScanTask>> = group.tasks.iter().cloned().map(Ok).collect();
    // One file at a time: the rows are written in order anyway, and each
    // file read holds a row group in memory.
    let mut batches = reader
        .reader_builder()
        .with_data_file_concurrency_limit(1)
        .build()
        .read(Box::pin(futures_util::stream::iter(tasks)))
        .map_err(e)?
        .stream();
    let spec = metadata
        .partition_spec_by_id(group.spec_id)
        .ok_or_else(|| format!("The table has no partition spec {}.", group.spec_id))?;
    let partition_key = match (&group.partition, spec.is_unpartitioned()) {
        (Some(partition), false) => Some(PartitionKey::new(
            spec.as_ref().clone(),
            metadata.current_schema().clone(),
            partition.clone(),
        )),
        _ => None,
    };
    let location = DefaultLocationGenerator::new(metadata).map_err(e)?;
    let names = DefaultFileNameGenerator::new(
        format!("compaction-{}", Uuid::new_v4()),
        None,
        DataFileFormat::Parquet,
    );
    let parquet = ParquetWriterBuilder::new(properties, schema.clone());
    let rolling = RollingFileWriterBuilder::new(
        parquet,
        target as usize,
        reader.file_io().clone(),
        location,
        names,
    );
    let mut writer = DataFileWriterBuilder::new(rolling)
        .build(partition_key)
        .await
        .map_err(e)?;
    match key {
        None => {
            while let Some(batch) = batches.next().await {
                writer.write(plain(batch.map_err(e)?)?).await.map_err(e)?;
            }
        }
        Some(key) => {
            let mut sorter = Sorter::new(key, schema, SORT_BUDGET, spill);
            while let Some(batch) = batches.next().await {
                sorter.push(plain(batch.map_err(e)?)?)?;
            }
            let mut sorted = sorter.finish()?;
            while let Some(batch) = sorted.next_batch()? {
                writer.write(batch).await.map_err(e)?;
            }
        }
    }
    writer.close().await.map_err(e)
}

/// `batch` as files are written: its run-end encoded columns (the rows'
/// lineage, of format version 3, which the reader makes so) plain.
fn plain(batch: arrow_array::RecordBatch) -> Result<arrow_array::RecordBatch, String> {
    use arrow_schema::{DataType, Field, Schema as ArrowSchema};
    if !batch
        .columns()
        .iter()
        .any(|c| matches!(c.data_type(), DataType::RunEndEncoded(..)))
    {
        return Ok(batch);
    }
    let schema = batch.schema();
    let mut fields = Vec::new();
    let mut columns = Vec::new();
    for (field, column) in schema.fields().iter().zip(batch.columns()) {
        match column.data_type() {
            DataType::RunEndEncoded(_, values) => {
                let plain =
                    arrow_cast::cast(column, values.data_type()).map_err(|e| e.to_string())?;
                fields.push(Arc::new(
                    Field::new(
                        field.name(),
                        values.data_type().clone(),
                        field.is_nullable(),
                    )
                    .with_metadata(field.metadata().clone()),
                ));
                columns.push(plain);
            }
            _ => {
                fields.push(field.clone());
                columns.push(column.clone());
            }
        }
    }
    let schema = Arc::new(ArrowSchema::new_with_metadata(
        fields,
        schema.metadata().clone(),
    ));
    arrow_array::RecordBatch::try_new(schema, columns).map_err(|e| e.to_string())
}

/// Commits the rewrite: `rewritten` (data files' paths) replaced by
/// `added` (by partition spec), on table `id`, planned on snapshot
/// `planned`. `Err` with why, if a commit that came in meanwhile wasn't
/// only an append.
pub(crate) async fn commit(
    app: &Arc<App>,
    id: Uuid,
    planned: i64,
    rewritten: &HashSet<String>,
    added: Vec<(i32, Vec<DataFile>)>,
    now: SystemTime,
) -> anyhow::Result<Result<(), String>> {
    for _ in 0..COMMIT_ATTEMPTS {
        let storage: Option<String> = app
            .pool
            .get()
            .await?
            .query_opt("SELECT storage FROM tables WHERE id = $1", &[&id])
            .await?
            .map(|r| r.get(0));
        let Some(storage) = storage else {
            return Ok(Err("The table was deleted.".into()));
        };
        let Some((_, table)) = Table::by_storage(&app.pool.get().await?, &storage).await? else {
            return Ok(Err("The table was deleted.".into()));
        };
        let (location, metadata) = match super::maintenance::current(app, &table).await? {
            Ok(current) => current,
            Err(why) => return Ok(Err(why)),
        };
        let Some(current) = metadata.current_snapshot().cloned() else {
            return Ok(Err("The table's snapshots are gone.".into()));
        };
        // Only appends since what was planned on.
        let mut at = Some(current.clone());
        loop {
            let Some(snapshot) = at else {
                return Ok(Err(
                    "The snapshot compaction started from is gone: it's tried again later.".into(),
                ));
            };
            if snapshot.snapshot_id() == planned {
                break;
            }
            let operation = snapshot.summary().operation.as_str();
            if operation != "append" {
                return Ok(Err(format!(
                    "A commit came in meanwhile ({operation}), which may have changed the rewritten \
                     files: compaction is tried again later."
                )));
            }
            at = snapshot
                .parent_snapshot_id()
                .and_then(|p| metadata.snapshot_by_id(p).cloned());
        }
        let built = replace(
            app, &table, &location, &metadata, &current, rewritten, &added, now,
        )
        .await?;
        let built = match built {
            Ok(built) => built,
            Err(why) => return Ok(Err(why)),
        };
        let file = cairn_iceberg::next_file(
            &table.warehouse_location(),
            Some(&location),
            &Uuid::new_v4().to_string(),
        );
        if let Err(FileError::Unusable(why) | FileError::Refused(why)) =
            cairn_iceberg::write(app, &table, None, &file, &built).await?
        {
            return Ok(Err(why));
        }
        let swapped = app
            .pool
            .get()
            .await?
            .query_opt(
                "UPDATE tables SET metadata_location = $3, version_token = $4, modified_at = now()
                 WHERE id = $1 AND version_token = $2 RETURNING id",
                &[
                    &table.id,
                    &table.version_token,
                    &file,
                    &super::version_token(),
                ],
            )
            .await?;
        if swapped.is_some() {
            return Ok(Ok(()));
        }
        // Another commit: made again on top of it, if it appended.
    }
    Ok(Err(
        "The table kept changing as compaction committed: it's tried again later.".into(),
    ))
}

/// The metadata of a `replace` snapshot on top of `current`: `rewritten`'s
/// files deleted, `added`'s added.
#[allow(clippy::too_many_arguments)]
async fn replace(
    app: &Arc<App>,
    table: &Table,
    location: &str,
    metadata: &TableMetadata,
    current: &iceberg::spec::SnapshotRef,
    rewritten: &HashSet<String>,
    added: &[(i32, Vec<DataFile>)],
    now: SystemTime,
) -> anyhow::Result<Result<TableMetadata, String>> {
    let io = cairn_iceberg::io::file_io(app, table, None);
    let reader = iceberg::table::Table::builder()
        .metadata(metadata.clone())
        .identifier(iceberg::TableIdent::from_strs(["compaction", "table"])?)
        .file_io(io.clone())
        .runtime(iceberg::Runtime::current())
        .readonly(true)
        .build()?;
    let v3 = metadata.format_version() >= FormatVersion::V3;
    let snapshot_id = loop {
        let id = (Uuid::new_v4().as_u128() as i64) & i64::MAX;
        if id != 0 && metadata.snapshot_by_id(id).is_none() {
            break id;
        }
    };
    let sequence = metadata.next_sequence_number();
    let warehouse = table.warehouse_location();
    let manifest_path = || format!("{warehouse}/metadata/{}-compaction.avro", Uuid::new_v4());
    let schema = metadata.current_schema().clone();
    let spec_of = |id: i32| {
        metadata
            .partition_spec_by_id(id)
            .map(|s| s.as_ref().clone())
            .ok_or_else(|| format!("The table has no partition spec {id}."))
    };
    let new_writer = |path: String, spec| -> iceberg::Result<iceberg::spec::ManifestWriter> {
        let builder = ManifestWriterBuilder::new(
            io.new_output(&path)?,
            Some(snapshot_id),
            schema.clone(),
            spec,
        );
        Ok(match v3 {
            true => builder.build_v3_data(),
            false => builder.build_v2_data(),
        })
    };
    let mut manifests: Vec<ManifestFile> = Vec::new();
    let (mut added_files, mut added_records, mut deleted_files, mut deleted_records) =
        (0u64, 0u64, 0u64, 0u64);
    // The new files' manifests first, as Iceberg's.
    for (spec_id, files) in added {
        if files.is_empty() {
            continue;
        }
        let spec = match spec_of(*spec_id) {
            Ok(spec) => spec,
            Err(why) => return Ok(Err(why)),
        };
        let mut writer = new_writer(manifest_path(), spec)?;
        for file in files {
            added_files += 1;
            added_records += file.record_count();
            writer.add_file(file.clone(), -1)?;
        }
        manifests.push(writer.write_manifest_file().await?);
    }
    let list = reader.manifest_list_reader(current).load().await?;
    let mut read = Vec::new();
    for manifest in list.entries() {
        read.push((
            manifest.clone(),
            reader.manifest_reader().read(manifest).await?,
        ));
    }
    // The oldest data a delete file could still apply to, by partition
    // (its spec and value), once the rewrite is in: the live data files'
    // sequence numbers (the new ones', this snapshot's), and of all of them
    // for an unpartitioned spec's deletes, which apply everywhere.
    let partition_of = |spec: i32, partition: &Struct| format!("{spec}/{partition:?}");
    let mut oldest: HashMap<String, i64> = HashMap::new();
    let mut oldest_anywhere = i64::MAX;
    let mut note = |key: String, sequence: i64| {
        let at = oldest.entry(key).or_insert(i64::MAX);
        *at = (*at).min(sequence);
        oldest_anywhere = oldest_anywhere.min(sequence);
    };
    for (manifest, entries) in &read {
        if manifest.content != ManifestContentType::Data {
            continue;
        }
        for entry in entries.entries() {
            if entry.is_alive() && !rewritten.contains(entry.file_path()) {
                let file = entry.data_file();
                note(
                    partition_of(manifest.partition_spec_id, file.partition()),
                    entry.sequence_number().unwrap_or(0),
                );
            }
        }
    }
    for (spec_id, files) in added {
        for file in files {
            note(partition_of(*spec_id, file.partition()), sequence);
        }
    }
    // A delete applies to data no newer than it: if there's none left (all
    // of its data was rewritten, its deletes applied), it's dangling, and
    // goes, as Iceberg's rewrites remove dangling deletes.
    let dangling = |manifest: &ManifestFile, entry: &iceberg::spec::ManifestEntry| {
        let delete_sequence = entry.sequence_number().unwrap_or(i64::MAX);
        let unpartitioned = metadata
            .partition_spec_by_id(manifest.partition_spec_id)
            .is_none_or(|s| s.is_unpartitioned());
        let oldest = match unpartitioned {
            true => oldest_anywhere,
            false => *oldest
                .get(&partition_of(
                    manifest.partition_spec_id,
                    entry.data_file().partition(),
                ))
                .unwrap_or(&i64::MAX),
        };
        oldest > delete_sequence
    };
    let mut removed_deletes = 0u64;
    for (manifest, entries) in &read {
        let deletes = manifest.content == ManifestContentType::Deletes;
        let touches = entries.entries().iter().any(|e| {
            e.is_alive()
                && match deletes {
                    true => dangling(manifest, e),
                    false => rewritten.contains(e.file_path()),
                }
        });
        if !touches {
            manifests.push(manifest.clone());
            continue;
        }
        let spec = match spec_of(manifest.partition_spec_id) {
            Ok(spec) => spec,
            Err(why) => return Ok(Err(why)),
        };
        let mut writer = match deletes {
            false => new_writer(manifest_path(), spec)?,
            true => {
                let builder = ManifestWriterBuilder::new(
                    io.new_output(manifest_path())?,
                    Some(snapshot_id),
                    schema.clone(),
                    spec,
                );
                match v3 {
                    true => builder.build_v3_deletes(),
                    false => builder.build_v2_deletes(),
                }
            }
        };
        for entry in entries.entries() {
            if !entry.is_alive() {
                continue;
            }
            let file = entry.data_file().clone();
            let sequence_number = entry.sequence_number().unwrap_or(0);
            let goes = match deletes {
                true => dangling(manifest, entry),
                false => rewritten.contains(entry.file_path()),
            };
            if goes {
                match deletes {
                    true => removed_deletes += 1,
                    false => {
                        deleted_files += 1;
                        deleted_records += file.record_count();
                    }
                }
                writer.add_delete_file(file, sequence_number, entry.file_sequence_number)?;
            } else {
                let added_by = entry.snapshot_id().unwrap_or(manifest.added_snapshot_id);
                writer.add_existing_file(
                    file,
                    added_by,
                    sequence_number,
                    entry.file_sequence_number,
                )?;
            }
        }
        manifests.push(writer.write_manifest_file().await?);
    }
    let list_path = format!(
        "{warehouse}/metadata/snap-{snapshot_id}-1-{}.avro",
        Uuid::new_v4()
    );
    let output = io.new_output(&list_path)?;
    let first_row_id = metadata.next_row_id();
    let mut list_writer = match v3 {
        true => ManifestListWriter::v3(
            output.writer().await?,
            snapshot_id,
            Some(current.snapshot_id()),
            sequence,
            Some(first_row_id),
        ),
        false => ManifestListWriter::v2(
            output.writer().await?,
            snapshot_id,
            Some(current.snapshot_id()),
            sequence,
        ),
    };
    list_writer.add_manifests(manifests.into_iter())?;
    let next_row_id = list_writer.next_row_id();
    list_writer.close().await?;
    let mut snapshot = json!({
        "snapshot-id": snapshot_id,
        "parent-snapshot-id": current.snapshot_id(),
        "sequence-number": sequence,
        "timestamp-ms": ms(now).max(metadata.last_updated_ms()),
        "manifest-list": list_path,
        "summary": {
            "operation": "replace",
            "added-data-files": added_files.to_string(),
            "deleted-data-files": deleted_files.to_string(),
            "added-records": added_records.to_string(),
            "deleted-records": deleted_records.to_string(),
            "removed-delete-files": removed_deletes.to_string(),
        },
        "schema-id": metadata.current_schema_id(),
    });
    if v3 {
        snapshot["first-row-id"] = json!(first_row_id);
        snapshot["added-rows"] = json!(next_row_id.unwrap_or(first_row_id) - first_row_id);
    }
    let updates: Vec<TableUpdate> = serde_json::from_value(json!([
        { "action": "add-snapshot", "snapshot": snapshot },
        { "action": "set-snapshot-ref", "ref-name": "main", "type": "branch", "snapshot-id": snapshot_id },
    ]))?;
    let mut builder =
        TableMetadataBuilder::new_from_metadata(metadata.clone(), Some(location.to_owned()));
    for update in updates {
        builder = match update.apply(builder) {
            Ok(builder) => builder,
            Err(e) => return Ok(Err(e.message().to_owned())),
        };
    }
    Ok(match builder.build() {
        Ok(built) => Ok(built.metadata),
        Err(e) => Err(e.message().to_owned()),
    })
}
