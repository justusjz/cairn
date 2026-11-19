//! Apache Iceberg, as S3 Tables has it, through the `iceberg` crate (Apache
//! Iceberg's Rust implementation): tables' metadata, built and changed as
//! Iceberg's Java builder does (`iceberg::spec::TableMetadataBuilder`), its
//! files read and written in tables' storage (`io`), and Iceberg's REST
//! catalog (`rest`).

pub mod io;
pub(crate) mod rest;

use std::collections::HashMap;
use std::sync::Arc;

use hyper::body::Bytes;
use iceberg::spec::{
    FormatVersion, Schema, SortOrder, TableMetadata, TableMetadataBuilder, UnboundPartitionSpec,
};
use iceberg::{ErrorKind, TableCreation};
use serde_json::{Map, Value};
use uuid::Uuid;

use super::Table;
use crate::App;

/// The largest metadata file the catalog reads, as S3 Tables' (50 MB).
pub const MAX_METADATA: u64 = 50 * 1024 * 1024;

/// Why a metadata file couldn't be read or written.
#[derive(Debug)]
pub enum FileError {
    /// It isn't there, isn't a table's metadata, or is too large: the
    /// table's broken (or a client wrote it so).
    Unusable(String),
    /// Writing it was refused (its encryption, say).
    Refused(String),
}

/// Why metadata can't be built: what was asked doesn't make sense
/// (`Invalid`, a 400), or the table isn't as a commit requires
/// (`Conflict`, a 409 CommitFailedException, which clients retry).
#[derive(Debug, PartialEq)]
pub enum Failure {
    Invalid(String),
    Conflict(String),
}

impl From<iceberg::Error> for Failure {
    fn from(e: iceberg::Error) -> Failure {
        match e.kind() {
            ErrorKind::CatalogCommitConflicts => Failure::Conflict(e.message().to_owned()),
            _ => Failure::Invalid(e.message().to_owned()),
        }
    }
}

/// Reads the metadata file at `location` in `table`'s storage (gzipped, if
/// its name says so), as the principal `role` (none: Cairn itself).
pub async fn read(
    app: &Arc<App>,
    table: &Table,
    role: Option<Uuid>,
    location: &str,
) -> anyhow::Result<Result<TableMetadata, FileError>> {
    let io = io::file_io(app, table, role);
    let size = io
        .new_input(location)
        .map(|input| async move { input.metadata().await })
        .map_err(|e| e.to_string());
    let size = match size {
        Ok(size) => size.await.map(|m| m.size).map_err(|e| e.to_string()),
        Err(e) => Err(e),
    };
    match size {
        Ok(size) if size > MAX_METADATA => {
            return Ok(Err(FileError::Unusable(format!(
                "The table's metadata file is larger than {} MB.",
                MAX_METADATA / 1024 / 1024
            ))));
        }
        Ok(_) => {}
        Err(why) => {
            return Ok(Err(FileError::Unusable(format!(
                "The table's metadata file {location} can't be read: {why}"
            ))));
        }
    }
    Ok(TableMetadata::read_from(&io, location).await.map_err(|e| {
        FileError::Unusable(format!(
            "The table's metadata file {location} can't be read: {}",
            e.message()
        ))
    }))
}

/// Writes `metadata` to `location` in `table`'s storage, as the principal
/// `role` (none: Cairn itself).
pub async fn write(
    app: &Arc<App>,
    table: &Table,
    role: Option<Uuid>,
    location: &str,
    metadata: &TableMetadata,
) -> anyhow::Result<Result<(), FileError>> {
    let io = io::file_io(app, table, role);
    let body = Bytes::from(serde_json::to_vec(metadata)?);
    let written = match io.new_output(location) {
        Ok(output) => output.write(body).await,
        Err(e) => Err(e),
    };
    Ok(written
        .map_err(|e| FileError::Refused(format!("Writing {location} failed: {}", e.message()))))
}

/// The name of the metadata file after `previous` (none, for a table's
/// first): `<location>/metadata/<version>-<uuid>.metadata.json`, its
/// version (five digits) one more than the previous's, as Iceberg names
/// them.
pub fn next_file(location: &str, previous: Option<&str>, uuid: &str) -> String {
    let version = previous
        .and_then(|p| p.rsplit('/').next())
        .and_then(|name| name.split('-').next())
        .and_then(|v| v.parse::<u64>().ok())
        .map_or(0, |v| v + 1);
    format!(
        "{}/metadata/{version:05}-{uuid}.metadata.json",
        location.trim_end_matches('/')
    )
}

/// What a table is created with: the REST spec's `CreateTableRequest`, but
/// its name and location, as JSON.
#[derive(Debug, Default)]
pub struct Creation {
    pub schema: Value,
    pub partition_spec: Option<Value>,
    pub write_order: Option<Value>,
    pub properties: Map<String, Value>,
}

/// The format versions tables are made in, or committed to.
pub fn supported(version: FormatVersion) -> bool {
    matches!(version, FormatVersion::V2 | FormatVersion::V3)
}

/// A new table's metadata, at `location`: its schema, partition spec and
/// sort order with fresh IDs, as Iceberg's `newTableMetadata` makes them.
/// Of format version 2, unless its `format-version` property says 3.
pub fn new_table(creation: &Creation, location: &str) -> Result<TableMetadata, Failure> {
    let invalid = |what: &str, e: serde_json::Error| {
        Failure::Invalid(format!("The table's {what} isn't one: {e}"))
    };
    let mut schema = creation.schema.clone();
    if let Some(object) = schema.as_object_mut() {
        object.entry("schema-id").or_insert(Value::from(0));
    }
    let schema: Schema = serde_json::from_value(schema).map_err(|e| invalid("schema", e))?;
    let spec: Option<UnboundPartitionSpec> = creation
        .partition_spec
        .clone()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| invalid("partition spec", e))?;
    let order: Option<SortOrder> = creation
        .write_order
        .clone()
        .map(|mut order| {
            if let Some(object) = order.as_object_mut() {
                let sorted = object
                    .get("fields")
                    .and_then(Value::as_array)
                    .is_some_and(|f| !f.is_empty());
                object
                    .entry("order-id")
                    .or_insert(Value::from(i64::from(sorted)));
            }
            serde_json::from_value(order)
        })
        .transpose()
        .map_err(|e| invalid("sort order", e))?;
    let mut properties = HashMap::new();
    for (key, value) in &creation.properties {
        let Some(value) = value.as_str() else {
            return Err(Failure::Invalid(
                "A table's properties must be strings.".into(),
            ));
        };
        properties.insert(key.clone(), value.to_owned());
    }
    let format_version = match properties.remove("format-version").as_deref() {
        None | Some("2") => FormatVersion::V2,
        Some("3") => FormatVersion::V3,
        Some(other) => {
            return Err(Failure::Invalid(format!(
                "Format version {other} isn't supported: 2 or 3 only."
            )));
        }
    };
    let creation = TableCreation::builder()
        .name("table".into())
        .location(location.to_owned())
        .schema(schema)
        .partition_spec_opt(spec)
        .sort_order_opt(order)
        .properties(properties)
        .format_version(format_version)
        .build();
    let built = TableMetadataBuilder::from_table_creation(creation)?.build()?;
    Ok(built.metadata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn file_names() {
        assert_eq!(
            next_file("s3://t", None, "u"),
            "s3://t/metadata/00000-u.metadata.json"
        );
        assert_eq!(
            next_file("s3://t", Some("s3://t/metadata/00041-x.metadata.json"), "u"),
            "s3://t/metadata/00042-u.metadata.json"
        );
        assert_eq!(
            next_file("s3://t", Some("s3://t/metadata/v3.metadata.json"), "u"),
            "s3://t/metadata/00000-u.metadata.json"
        );
    }

    #[test]
    fn new_tables_get_fresh_ids() {
        let creation = Creation {
            schema: json!({ "type": "struct", "identifier-field-ids": [10], "fields": [
                { "id": 10, "name": "id", "required": true, "type": "long" },
                { "id": 20, "name": "point", "required": false, "type": { "type": "struct", "fields": [
                    { "id": 21, "name": "x", "required": true, "type": "double" } ] } },
                { "id": 30, "name": "ts", "required": false, "type": "timestamptz" },
            ]}),
            partition_spec: Some(
                json!({ "fields": [{ "source-id": 30, "transform": "day", "name": "ts_day" }] }),
            ),
            write_order: Some(
                json!({ "fields": [{ "source-id": 10, "transform": "identity", "direction": "asc", "null-order": "nulls-first" }] }),
            ),
            properties: json!({ "owner": "me", "format-version": "3" })
                .as_object()
                .cloned()
                .unwrap(),
        };
        let m = new_table(&creation, "s3://t--table-s3").unwrap();
        let m = serde_json::to_value(&m).unwrap();
        let ids: Vec<i64> = m["schemas"][0]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["id"].as_i64().unwrap())
            .collect();
        assert_eq!(ids, [1, 2, 3]);
        assert_eq!(m["schemas"][0]["fields"][1]["type"]["fields"][0]["id"], 4);
        assert_eq!(m["schemas"][0]["identifier-field-ids"], json!([1]));
        assert_eq!(m["partition-specs"][0]["fields"][0]["source-id"], 3);
        assert_eq!(m["partition-specs"][0]["fields"][0]["field-id"], 1000);
        assert_eq!(
            m["sort-orders"]
                .as_array()
                .unwrap()
                .iter()
                .find(|o| o["order-id"] == m["default-sort-order-id"])
                .unwrap()["fields"][0]["source-id"],
            1
        );
        assert_eq!(m["format-version"], 3);
        assert_eq!(m["properties"]["owner"], "me");
        assert!(m["properties"].get("format-version").is_none());
        assert_eq!(m["location"], "s3://t--table-s3");
        let mut v1 = creation;
        v1.properties.insert("format-version".into(), json!("1"));
        assert!(matches!(new_table(&v1, "s3://t"), Err(Failure::Invalid(_))));
    }
}
