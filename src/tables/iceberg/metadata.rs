//! Iceberg's table metadata (`metadata.json`), as the REST catalog builds
//! it: a new table's, and what a commit makes of a table's, by its
//! requirements and updates, as Iceberg's own `TableMetadata.Builder` (Java)
//! does (the REST spec's `TableRequirement` and `TableUpdate`).
//!
//! Metadata is kept as JSON, read with typed views of what's checked and
//! changed, so that fields Cairn doesn't know survive a commit. Format
//! versions 2 and 3 only, as tables made here are.

use serde_json::{Map, Value, json};

/// Why metadata can't be built: what the client asked for doesn't make
/// sense (`Invalid`, a 400), or the table isn't as the commit requires
/// (`Conflict`, a 409 CommitFailedException, which clients retry).
#[derive(Debug, PartialEq)]
pub enum Failure {
    Invalid(String),
    Conflict(String),
}

type Result<T> = std::result::Result<T, Failure>;

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(Failure::Invalid(message.into()))
}

fn conflict<T>(message: impl Into<String>) -> Result<T> {
    Err(Failure::Conflict(message.into()))
}

/// The newest format version Cairn writes, and the one new tables get.
pub const MAX_FORMAT_VERSION: i64 = 3;
pub const DEFAULT_FORMAT_VERSION: i64 = 2;

/// Where partition fields' IDs start, as Iceberg's.
const PARTITION_DATA_ID_START: i64 = 1000;

/// How many previous metadata files the log keeps, by default.
const PREVIOUS_VERSIONS_MAX: usize = 100;

/// The properties a table's creation takes as settings, not properties.
const RESERVED_PROPERTIES: [&str; 1] = ["format-version"];

fn int(value: &Value, name: &str) -> Result<i64> {
    match value.get(name).and_then(Value::as_i64) {
        Some(n) => Ok(n),
        None => invalid(format!("{name} must be an integer.")),
    }
}

fn opt_int(value: &Value, name: &str) -> Option<i64> {
    value.get(name).and_then(Value::as_i64)
}

fn list<'a>(value: &'a Value, name: &str) -> &'a [Value] {
    value
        .get(name)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

// ─── Schemas ────────────────────────────────────────────────────────────────

/// The IDs a type's fields, elements, keys and values have, nested.
fn type_ids(t: &Value, out: &mut Vec<i64>) {
    let Some(object) = t.as_object() else {
        return;
    };
    match object.get("type").and_then(Value::as_str) {
        Some("struct") => {
            for field in object
                .get("fields")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(id) = opt_int(field, "id") {
                    out.push(id);
                }
                if let Some(t) = field.get("type") {
                    type_ids(t, out);
                }
            }
        }
        Some("list") => {
            out.extend(opt_int(t, "element-id"));
            if let Some(t) = object.get("element") {
                type_ids(t, out);
            }
        }
        Some("map") => {
            out.extend(opt_int(t, "key-id"));
            out.extend(opt_int(t, "value-id"));
            for name in ["key", "value"] {
                if let Some(t) = object.get(name) {
                    type_ids(t, out);
                }
            }
        }
        _ => {}
    }
}

/// A schema's highest field ID (0 for none).
pub fn highest_field_id(schema: &Value) -> i64 {
    let mut ids = Vec::new();
    type_ids(schema, &mut ids);
    ids.into_iter().max().unwrap_or(0)
}

/// Checks that `schema` is one: a struct, whose IDs are unique and
/// positive.
fn check_schema(schema: &Value) -> Result<()> {
    if schema.get("type").and_then(Value::as_str) != Some("struct")
        || !schema.get("fields").is_some_and(Value::is_array)
    {
        return invalid("A schema must be a struct with fields.");
    }
    let mut ids = Vec::new();
    type_ids(schema, &mut ids);
    let count = ids.len();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() != count || ids.first().is_some_and(|id| *id <= 0) {
        return invalid("A schema's field IDs must be unique and positive.");
    }
    Ok(())
}

/// `t` with fresh IDs, from `next`, as Iceberg's `AssignFreshIds` assigns
/// them: a struct's fields first, then what's in each, in order; and the
/// old IDs' new ones, in `ids`.
fn fresh_type(t: &Value, next: &mut i64, ids: &mut Vec<(i64, i64)>) -> Result<Value> {
    let Some(object) = t.as_object() else {
        // A primitive.
        return Ok(t.clone());
    };
    let mut out = object.clone();
    fn assign(old: Option<i64>, next: &mut i64, ids: &mut Vec<(i64, i64)>) -> i64 {
        *next += 1;
        if let Some(old) = old {
            ids.push((old, *next));
        }
        *next
    }
    match object.get("type").and_then(Value::as_str) {
        Some("struct") => {
            let fields = object
                .get("fields")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let mut new_fields = Vec::new();
            for field in &fields {
                let mut field = field.as_object().cloned().unwrap_or_default();
                let id = assign(opt_int(&Value::Object(field.clone()), "id"), next, ids);
                field.insert("id".into(), json!(id));
                new_fields.push(field);
            }
            for (field, old) in new_fields.iter_mut().zip(&fields) {
                let t = old
                    .get("type")
                    .ok_or_else(|| Failure::Invalid("A field needs a type.".into()))?;
                field.insert("type".into(), fresh_type(t, next, ids)?);
            }
            out.insert(
                "fields".into(),
                Value::Array(new_fields.into_iter().map(Value::Object).collect()),
            );
        }
        Some("list") => {
            let id = assign(opt_int(t, "element-id"), next, ids);
            out.insert("element-id".into(), json!(id));
            let element = object
                .get("element")
                .ok_or_else(|| Failure::Invalid("A list needs an element.".into()))?;
            out.insert("element".into(), fresh_type(element, next, ids)?);
        }
        Some("map") => {
            let key = assign(opt_int(t, "key-id"), next, ids);
            let value = assign(opt_int(t, "value-id"), next, ids);
            out.insert("key-id".into(), json!(key));
            out.insert("value-id".into(), json!(value));
            for name in ["key", "value"] {
                let inner = object
                    .get(name)
                    .ok_or_else(|| Failure::Invalid(format!("A map needs a {name}.")))?;
                out.insert(name.into(), fresh_type(inner, next, ids)?);
            }
        }
        _ => return invalid("A type must be a primitive, a struct, a list or a map."),
    }
    Ok(Value::Object(out))
}

/// Two schemas are the same, but for their IDs.
fn same_schema(a: &Value, b: &Value) -> bool {
    a.get("fields") == b.get("fields")
        && a.get("identifier-field-ids").cloned().unwrap_or(json!([]))
            == b.get("identifier-field-ids").cloned().unwrap_or(json!([]))
}

// ─── A new table ────────────────────────────────────────────────────────────

/// What a table is created with: the REST spec's `CreateTableRequest`, but
/// its name and location.
#[derive(Debug, Default)]
pub struct Creation {
    pub schema: Value,
    pub partition_spec: Option<Value>,
    pub write_order: Option<Value>,
    pub properties: Map<String, Value>,
}

/// A new table's metadata, at `location`, as of `now` (ms), with UUID
/// `uuid`: its schema, partition spec and sort order with fresh IDs, as
/// Iceberg's `TableMetadata.newTableMetadata` makes them.
pub fn new_table(
    creation: &Creation,
    location: &str,
    uuid: &str,
    now: i64,
) -> Result<Map<String, Value>> {
    check_schema(&creation.schema)?;
    let mut properties = creation.properties.clone();
    let format_version = match properties.get("format-version") {
        None => DEFAULT_FORMAT_VERSION,
        Some(v) => match v
            .as_str()
            .and_then(|s| s.parse::<i64>().ok())
            .or_else(|| v.as_i64())
        {
            Some(n) if (2..=MAX_FORMAT_VERSION).contains(&n) => n,
            _ => return invalid(format!("Format version {v} isn't supported: 2 or 3 only.")),
        },
    };
    for reserved in RESERVED_PROPERTIES {
        properties.remove(reserved);
    }
    if properties.values().any(|v| !v.is_string()) {
        return invalid("A table's properties must be strings.");
    }
    // The schema, with fresh IDs.
    let mut next = 0;
    let mut ids = Vec::new();
    let mut schema = fresh_type(&creation.schema, &mut next, &mut ids)?
        .as_object()
        .cloned()
        .unwrap_or_default();
    let fresh = |old: i64| ids.iter().find(|(o, _)| *o == old).map(|(_, n)| *n);
    let identifiers: Vec<i64> = list(&creation.schema, "identifier-field-ids")
        .iter()
        .filter_map(Value::as_i64)
        .map(|old| {
            fresh(old).ok_or_else(|| {
                Failure::Invalid(format!("Identifier field {old} isn't in the schema."))
            })
        })
        .collect::<Result<_>>()?;
    schema.insert("schema-id".into(), json!(0));
    schema.insert("identifier-field-ids".into(), json!(identifiers));
    // The partition spec: its sources' fresh IDs, and fields from 1000.
    let mut spec_fields = Vec::new();
    for (i, field) in creation
        .partition_spec
        .as_ref()
        .map(|s| list(s, "fields"))
        .unwrap_or(&[])
        .iter()
        .enumerate()
    {
        let mut field = field.as_object().cloned().unwrap_or_default();
        let source = int(&Value::Object(field.clone()), "source-id")?;
        let source = fresh(source).ok_or_else(|| {
            Failure::Invalid(format!("Partition source {source} isn't in the schema."))
        })?;
        if !field.get("transform").is_some_and(Value::is_string)
            || !field.get("name").is_some_and(Value::is_string)
        {
            return invalid("A partition field needs a transform and a name.");
        }
        field.insert("source-id".into(), json!(source));
        field.insert("field-id".into(), json!(PARTITION_DATA_ID_START + i as i64));
        spec_fields.push(Value::Object(field));
    }
    let last_partition_id = PARTITION_DATA_ID_START - 1 + spec_fields.len() as i64;
    // The sort order: its sources' fresh IDs; 1, unless it's unsorted (0).
    let mut order_fields = Vec::new();
    for field in creation
        .write_order
        .as_ref()
        .map(|o| list(o, "fields"))
        .unwrap_or(&[])
    {
        let mut field = field.as_object().cloned().unwrap_or_default();
        let source = int(&Value::Object(field.clone()), "source-id")?;
        let source = fresh(source).ok_or_else(|| {
            Failure::Invalid(format!("Sort source {source} isn't in the schema."))
        })?;
        field.insert("source-id".into(), json!(source));
        order_fields.push(Value::Object(field));
    }
    let mut sort_orders = vec![json!({ "order-id": 0, "fields": [] })];
    let default_sort_order = match order_fields.is_empty() {
        true => 0,
        false => {
            sort_orders = vec![json!({ "order-id": 1, "fields": order_fields })];
            1
        }
    };
    let mut metadata = json!({
        "format-version": format_version,
        "table-uuid": uuid,
        "location": location,
        "last-sequence-number": 0,
        "last-updated-ms": now,
        "last-column-id": next,
        "current-schema-id": 0,
        "schemas": [Value::Object(schema)],
        "default-spec-id": 0,
        "partition-specs": [{ "spec-id": 0, "fields": spec_fields }],
        "last-partition-id": last_partition_id,
        "default-sort-order-id": default_sort_order,
        "sort-orders": sort_orders,
        "properties": Value::Object(properties),
        "current-snapshot-id": -1,
        "refs": {},
        "snapshots": [],
        "statistics": [],
        "partition-statistics": [],
        "snapshot-log": [],
        "metadata-log": [],
    });
    if format_version >= 3 {
        metadata["next-row-id"] = json!(0);
    }
    Ok(metadata.as_object().cloned().expect("an object"))
}

/// A table with no metadata yet, which a commit's updates (as a staged
/// creation's) make: at `location`, of format version 2 until an update
/// says otherwise.
pub fn empty(location: &str, now: i64) -> Map<String, Value> {
    json!({
        "format-version": DEFAULT_FORMAT_VERSION,
        "location": location,
        "last-sequence-number": 0,
        "last-updated-ms": now,
        "last-column-id": 0,
        "current-schema-id": -1,
        "schemas": [],
        "default-spec-id": -1,
        "partition-specs": [],
        "last-partition-id": PARTITION_DATA_ID_START - 1,
        "default-sort-order-id": -1,
        "sort-orders": [],
        "properties": {},
        "current-snapshot-id": -1,
        "refs": {},
        "snapshots": [],
        "statistics": [],
        "partition-statistics": [],
        "snapshot-log": [],
        "metadata-log": [],
    })
    .as_object()
    .cloned()
    .expect("an object")
}

/// Checks that `metadata` (read from a table's metadata file) is of a
/// format version Cairn commits to.
pub fn check_readable(metadata: &Map<String, Value>) -> Result<()> {
    match metadata.get("format-version").and_then(Value::as_i64) {
        Some(v) if (2..=MAX_FORMAT_VERSION).contains(&v) => Ok(()),
        Some(v) => invalid(format!(
            "The table's format version {v} isn't supported: 2 or 3 only."
        )),
        None => invalid("The table's metadata has no format version."),
    }
}

// ─── Requirements ───────────────────────────────────────────────────────────

/// Checks a commit's requirements against the table's current metadata
/// (`None`: it has none yet).
pub fn check_requirements(base: Option<&Map<String, Value>>, requirements: &[Value]) -> Result<()> {
    for requirement in requirements {
        let kind = requirement
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("");
        if kind == "assert-create" {
            if base.is_some() {
                return conflict("Requirement failed: table already exists");
            }
            continue;
        }
        let Some(base) = base else {
            return conflict(format!(
                "Requirement failed: {kind}: the table has no metadata yet"
            ));
        };
        let base = Value::Object(base.clone());
        let expect = |field: &str, given: &str| -> Result<()> {
            let want = requirement.get(given).cloned().unwrap_or(Value::Null);
            let have = base.get(field).cloned().unwrap_or(Value::Null);
            match have == want {
                true => Ok(()),
                false => conflict(format!(
                    "Requirement failed: {kind}: expected {want}, found {have}"
                )),
            }
        };
        match kind {
            "assert-table-uuid" => expect("table-uuid", "uuid")?,
            "assert-current-schema-id" => expect("current-schema-id", "current-schema-id")?,
            "assert-last-assigned-field-id" => expect("last-column-id", "last-assigned-field-id")?,
            "assert-last-assigned-partition-id" => {
                expect("last-partition-id", "last-assigned-partition-id")?
            }
            "assert-default-spec-id" => expect("default-spec-id", "default-spec-id")?,
            "assert-default-sort-order-id" => {
                expect("default-sort-order-id", "default-sort-order-id")?
            }
            "assert-ref-snapshot-id" => {
                let name = requirement.get("ref").and_then(Value::as_str).unwrap_or("");
                let want = requirement.get("snapshot-id").and_then(Value::as_i64);
                let have = base
                    .get("refs")
                    .and_then(|r| r.get(name))
                    .and_then(|r| r.get("snapshot-id"))
                    .and_then(Value::as_i64);
                if want != have {
                    return conflict(format!(
                        "Requirement failed: branch or tag {name}: expected {}, found {}",
                        want.map_or("none".to_owned(), |n| n.to_string()),
                        have.map_or("none".to_owned(), |n| n.to_string()),
                    ));
                }
            }
            other => return invalid(format!("Unknown requirement: {other}")),
        }
    }
    Ok(())
}

// ─── Updates ────────────────────────────────────────────────────────────────

/// A commit's updates applied to `metadata`, as Iceberg's builder applies
/// them; `now` (ms) is when. What's built is checked to be a table.
pub struct Builder {
    m: Map<String, Value>,
    now: i64,
    changed: bool,
    /// The IDs last added (`-1` in a later update names them).
    last_schema: Option<i64>,
    last_spec: Option<i64>,
    last_order: Option<i64>,
    /// Snapshots this commit adds, by ID, and their timestamps.
    added: Vec<(i64, i64)>,
    /// When this change happened, if a snapshot it added says.
    updated_at: Option<i64>,
}

impl Builder {
    pub fn new(metadata: Map<String, Value>, now: i64) -> Builder {
        Builder {
            m: metadata,
            now,
            changed: false,
            last_schema: None,
            last_spec: None,
            last_order: None,
            added: Vec::new(),
            updated_at: None,
        }
    }

    fn get_i64(&self, name: &str) -> i64 {
        self.m.get(name).and_then(Value::as_i64).unwrap_or(-1)
    }

    fn array(&mut self, name: &str) -> &mut Vec<Value> {
        let entry = self.m.entry(name.to_owned()).or_insert_with(|| json!([]));
        if !entry.is_array() {
            *entry = json!([]);
        }
        entry.as_array_mut().expect("an array")
    }

    fn object(&mut self, name: &str) -> &mut Map<String, Value> {
        let entry = self.m.entry(name.to_owned()).or_insert_with(|| json!({}));
        if !entry.is_object() {
            *entry = json!({});
        }
        entry.as_object_mut().expect("an object")
    }

    fn format_version(&self) -> i64 {
        self.get_i64("format-version")
    }

    fn set(&mut self, name: &str, value: Value) {
        if self.m.get(name) != Some(&value) {
            self.m.insert(name.to_owned(), value);
            self.changed = true;
        }
    }

    /// Applies `updates`, in order.
    pub fn apply(&mut self, updates: &[Value]) -> Result<()> {
        for update in updates {
            self.apply_one(update)?;
        }
        Ok(())
    }

    fn apply_one(&mut self, u: &Value) -> Result<()> {
        let action = u.get("action").and_then(Value::as_str).unwrap_or("");
        match action {
            "assign-uuid" => {
                let uuid = u
                    .get("uuid")
                    .and_then(Value::as_str)
                    .ok_or_else(|| Failure::Invalid("uuid is required.".into()))?;
                match self.m.get("table-uuid").and_then(Value::as_str) {
                    Some(have) if have != uuid => {
                        return conflict(format!(
                            "Cannot reassign the table's UUID {have} to {uuid}"
                        ));
                    }
                    _ => self.set("table-uuid", json!(uuid)),
                }
            }
            "upgrade-format-version" => {
                let version = int(u, "format-version")?;
                if version > MAX_FORMAT_VERSION {
                    return invalid(format!(
                        "Format version {version} isn't supported: at most {MAX_FORMAT_VERSION}."
                    ));
                }
                if version < self.format_version() {
                    return invalid(format!(
                        "Cannot downgrade the format version from {} to {version}",
                        self.format_version()
                    ));
                }
                if version >= 3 && self.format_version() < 3 {
                    self.set("next-row-id", json!(0));
                }
                self.set("format-version", json!(version));
            }
            "add-schema" => self.add_schema(u)?,
            "set-current-schema" => {
                let id = self.resolve(int(u, "schema-id")?, self.last_schema, "schema")?;
                if !self.has("schemas", "schema-id", id) {
                    return invalid(format!(
                        "Cannot set the current schema to unknown schema {id}"
                    ));
                }
                self.set("current-schema-id", json!(id));
            }
            "add-spec" => self.add_spec(u)?,
            "set-default-spec" => {
                let id = self.resolve(int(u, "spec-id")?, self.last_spec, "partition spec")?;
                if !self.has("partition-specs", "spec-id", id) {
                    return invalid(format!(
                        "Cannot set the default partition spec to unknown spec {id}"
                    ));
                }
                self.set("default-spec-id", json!(id));
            }
            "add-sort-order" => self.add_sort_order(u)?,
            "set-default-sort-order" => {
                let id = self.resolve(int(u, "sort-order-id")?, self.last_order, "sort order")?;
                if !self.has("sort-orders", "order-id", id) {
                    return invalid(format!(
                        "Cannot set the default sort order to unknown order {id}"
                    ));
                }
                self.set("default-sort-order-id", json!(id));
            }
            "add-snapshot" => self.add_snapshot(u)?,
            "set-snapshot-ref" => self.set_ref(u)?,
            "remove-snapshots" => {
                let ids: Vec<i64> = list(u, "snapshot-ids")
                    .iter()
                    .filter_map(Value::as_i64)
                    .collect();
                self.remove_snapshots(&ids);
            }
            "remove-snapshot-ref" => {
                let name = u
                    .get("ref-name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                if self.object("refs").remove(&name).is_some() {
                    self.changed = true;
                    if name == "main" {
                        self.set("current-snapshot-id", json!(-1));
                    }
                }
            }
            "set-location" => {
                let location = u.get("location").and_then(Value::as_str).unwrap_or("");
                if self.m.get("location").and_then(Value::as_str) != Some(location) {
                    return invalid(
                        "A table's location is its warehouse location, which can't be changed.",
                    );
                }
            }
            "set-properties" => {
                let Some(updates) = u.get("updates").and_then(Value::as_object) else {
                    return invalid("updates must be a map.");
                };
                if updates.values().any(|v| !v.is_string()) {
                    return invalid("A table's properties must be strings.");
                }
                for (key, value) in updates.clone() {
                    if self.object("properties").get(&key) != Some(&value) {
                        self.object("properties").insert(key, value);
                        self.changed = true;
                    }
                }
            }
            "remove-properties" => {
                for key in list(u, "removals").iter().filter_map(Value::as_str) {
                    if self.object("properties").remove(key).is_some() {
                        self.changed = true;
                    }
                }
            }
            "set-statistics" | "set-partition-statistics" => {
                let (field, name) = match action {
                    "set-statistics" => ("statistics", "statistics"),
                    _ => ("partition-statistics", "partition-statistics"),
                };
                let Some(statistics) = u.get(name).filter(|s| s.is_object()).cloned() else {
                    return invalid(format!("{name} is required."));
                };
                let id = int(&statistics, "snapshot-id")?;
                let entries = self.array(field);
                entries.retain(|s| opt_int(s, "snapshot-id") != Some(id));
                entries.push(statistics);
                self.changed = true;
            }
            "remove-statistics" | "remove-partition-statistics" => {
                let field = match action {
                    "remove-statistics" => "statistics",
                    _ => "partition-statistics",
                };
                let id = int(u, "snapshot-id")?;
                let entries = self.array(field);
                let before = entries.len();
                entries.retain(|s| opt_int(s, "snapshot-id") != Some(id));
                if entries.len() != before {
                    self.changed = true;
                }
            }
            "remove-partition-specs" => {
                let ids: Vec<i64> = list(u, "spec-ids")
                    .iter()
                    .filter_map(Value::as_i64)
                    .collect();
                if ids.contains(&self.get_i64("default-spec-id")) {
                    return invalid("Cannot remove the default partition spec");
                }
                let specs = self.array("partition-specs");
                let before = specs.len();
                specs.retain(|s| !opt_int(s, "spec-id").is_some_and(|id| ids.contains(&id)));
                if specs.len() != before {
                    self.changed = true;
                }
            }
            "remove-schemas" => {
                let ids: Vec<i64> = list(u, "schema-ids")
                    .iter()
                    .filter_map(Value::as_i64)
                    .collect();
                if ids.contains(&self.get_i64("current-schema-id")) {
                    return invalid("Cannot remove the current schema");
                }
                let schemas = self.array("schemas");
                let before = schemas.len();
                schemas.retain(|s| !opt_int(s, "schema-id").is_some_and(|id| ids.contains(&id)));
                if schemas.len() != before {
                    self.changed = true;
                }
            }
            "add-encryption-key" => {
                let Some(key) = u.get("encryption-key").filter(|k| k.is_object()).cloned() else {
                    return invalid("encryption-key is required.");
                };
                let id = key.get("key-id").cloned();
                let keys = self.array("encryption-keys");
                keys.retain(|k| k.get("key-id") != id.as_ref());
                keys.push(key);
                self.changed = true;
            }
            "remove-encryption-key" => {
                let id = u.get("key-id").cloned();
                let keys = self.array("encryption-keys");
                let before = keys.len();
                keys.retain(|k| k.get("key-id") != id.as_ref());
                if keys.len() != before {
                    self.changed = true;
                }
            }
            "" => return invalid("An update needs an action."),
            other => return invalid(format!("Unknown update: {other}")),
        }
        Ok(())
    }

    /// `id`, or (`-1`) the one this commit last added.
    fn resolve(&self, id: i64, last: Option<i64>, what: &str) -> Result<i64> {
        match id {
            -1 => last.ok_or_else(|| {
                Failure::Invalid(format!("Cannot use the last added {what}: none was added"))
            }),
            id => Ok(id),
        }
    }

    fn has(&self, list_name: &str, id_name: &str, id: i64) -> bool {
        self.m
            .get(list_name)
            .and_then(Value::as_array)
            .is_some_and(|items| items.iter().any(|i| opt_int(i, id_name) == Some(id)))
    }

    fn ids(&self, list_name: &str, id_name: &str) -> Vec<i64> {
        self.m
            .get(list_name)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|i| opt_int(i, id_name))
            .collect()
    }

    fn add_schema(&mut self, u: &Value) -> Result<()> {
        let Some(schema) = u.get("schema").filter(|s| s.is_object()) else {
            return invalid("schema is required.");
        };
        check_schema(schema)?;
        let existing = self
            .m
            .get("schemas")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|s| same_schema(s, schema))
            .and_then(|s| opt_int(s, "schema-id"));
        let id = match existing {
            Some(id) => id,
            None => {
                let id = self
                    .ids("schemas", "schema-id")
                    .into_iter()
                    .max()
                    .map_or(0, |m| m + 1);
                let mut schema = schema.as_object().cloned().expect("an object");
                schema.insert("schema-id".into(), json!(id));
                schema
                    .entry("identifier-field-ids")
                    .or_insert_with(|| json!([]));
                self.array("schemas").push(Value::Object(schema));
                self.changed = true;
                id
            }
        };
        let highest = highest_field_id(schema).max(opt_int(u, "last-column-id").unwrap_or(0));
        if highest > self.get_i64("last-column-id") {
            self.set("last-column-id", json!(highest));
        }
        self.last_schema = Some(id);
        Ok(())
    }

    fn add_spec(&mut self, u: &Value) -> Result<()> {
        let Some(spec) = u.get("spec").filter(|s| s.is_object()) else {
            return invalid("spec is required.");
        };
        // Fields without IDs get the next ones.
        let mut last = self
            .get_i64("last-partition-id")
            .max(PARTITION_DATA_ID_START - 1);
        let mut fields = Vec::new();
        for field in list(spec, "fields") {
            let mut field = field.as_object().cloned().unwrap_or_default();
            if !field.get("transform").is_some_and(Value::is_string)
                || !field.get("name").is_some_and(Value::is_string)
                || !field.get("source-id").is_some_and(Value::is_i64)
            {
                return invalid("A partition field needs a source, a transform and a name.");
            }
            let id = match field.get("field-id").and_then(Value::as_i64) {
                Some(id) => id,
                None => {
                    last += 1;
                    last
                }
            };
            field.insert("field-id".into(), json!(id));
            last = last.max(id);
            fields.push(Value::Object(field));
        }
        let existing = self
            .m
            .get("partition-specs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|s| s.get("fields").and_then(Value::as_array) == Some(&fields))
            .and_then(|s| opt_int(s, "spec-id"));
        let id = match existing {
            Some(id) => id,
            None => {
                let id = self
                    .ids("partition-specs", "spec-id")
                    .into_iter()
                    .max()
                    .map_or(0, |m| m + 1);
                self.array("partition-specs")
                    .push(json!({ "spec-id": id, "fields": fields }));
                self.changed = true;
                id
            }
        };
        if last > self.get_i64("last-partition-id") {
            self.set("last-partition-id", json!(last));
        }
        self.last_spec = Some(id);
        Ok(())
    }

    fn add_sort_order(&mut self, u: &Value) -> Result<()> {
        let Some(order) = u.get("sort-order").filter(|s| s.is_object()) else {
            return invalid("sort-order is required.");
        };
        let fields = list(order, "fields").to_vec();
        let existing = self
            .m
            .get("sort-orders")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|o| o.get("fields").and_then(Value::as_array) == Some(&fields))
            .and_then(|o| opt_int(o, "order-id"));
        let id = match existing {
            Some(id) => id,
            None => {
                let id = match fields.is_empty() {
                    true => 0,
                    false => self
                        .ids("sort-orders", "order-id")
                        .into_iter()
                        .max()
                        .map_or(1, |m| (m + 1).max(1)),
                };
                self.array("sort-orders")
                    .push(json!({ "order-id": id, "fields": fields }));
                self.changed = true;
                id
            }
        };
        self.last_order = Some(id);
        Ok(())
    }

    fn add_snapshot(&mut self, u: &Value) -> Result<()> {
        let Some(snapshot) = u.get("snapshot").filter(|s| s.is_object()).cloned() else {
            return invalid("snapshot is required.");
        };
        let id = int(&snapshot, "snapshot-id")?;
        let timestamp = int(&snapshot, "timestamp-ms")?;
        if self.has("snapshots", "snapshot-id", id) {
            return conflict(format!("Snapshot already exists: {id}"));
        }
        let sequence = opt_int(&snapshot, "sequence-number").unwrap_or(0);
        let parent = opt_int(&snapshot, "parent-snapshot-id");
        let last_sequence = self.get_i64("last-sequence-number").max(0);
        if sequence <= last_sequence && parent.is_some() {
            return conflict(format!(
                "Cannot add snapshot with sequence number {sequence} older than last sequence number {last_sequence}"
            ));
        }
        if self.format_version() >= 3 {
            let next_row_id = self.get_i64("next-row-id").max(0);
            let first_row_id = opt_int(&snapshot, "first-row-id");
            let Some(first_row_id) = first_row_id.filter(|f| *f >= next_row_id) else {
                return conflict(format!(
                    "Cannot add a snapshot whose first-row-id is behind the table's next-row-id {next_row_id}"
                ));
            };
            let added = opt_int(&snapshot, "added-rows").unwrap_or(0);
            self.set("next-row-id", json!(first_row_id + added));
        }
        self.array("snapshots").push(snapshot);
        self.changed = true;
        if sequence > last_sequence {
            self.set("last-sequence-number", json!(sequence));
        }
        self.added.push((id, timestamp));
        self.updated_at = Some(timestamp);
        Ok(())
    }

    fn set_ref(&mut self, u: &Value) -> Result<()> {
        let name = u
            .get("ref-name")
            .and_then(Value::as_str)
            .ok_or_else(|| Failure::Invalid("ref-name is required.".into()))?
            .to_owned();
        let id = int(u, "snapshot-id")?;
        let kind = u.get("type").and_then(Value::as_str).unwrap_or("branch");
        if kind != "branch" && kind != "tag" {
            return invalid(format!("A ref's type is branch or tag, not {kind}"));
        }
        if !self.has("snapshots", "snapshot-id", id) {
            return invalid(format!("Cannot set {name} to unknown snapshot {id}"));
        }
        let mut reference = json!({ "snapshot-id": id, "type": kind });
        for field in [
            "min-snapshots-to-keep",
            "max-snapshot-age-ms",
            "max-ref-age-ms",
        ] {
            if let Some(v) = u.get(field).filter(|v| !v.is_null()) {
                reference[field] = v.clone();
            }
        }
        if self.object("refs").get(&name) == Some(&reference) {
            return Ok(());
        }
        self.object("refs").insert(name.clone(), reference);
        self.changed = true;
        if name == "main" {
            self.set("current-snapshot-id", json!(id));
            let at = self
                .added
                .iter()
                .find(|(added, _)| *added == id)
                .map(|(_, at)| *at)
                .unwrap_or(self.now);
            self.updated_at.get_or_insert(at);
            self.array("snapshot-log")
                .push(json!({ "snapshot-id": id, "timestamp-ms": at }));
        }
        Ok(())
    }

    fn remove_snapshots(&mut self, ids: &[i64]) {
        let snapshots = self.array("snapshots");
        let before = snapshots.len();
        snapshots.retain(|s| !opt_int(s, "snapshot-id").is_some_and(|id| ids.contains(&id)));
        if snapshots.len() == before {
            return;
        }
        self.changed = true;
        // Refs to them go too.
        let gone: Vec<String> = self
            .object("refs")
            .iter()
            .filter(|(_, r)| opt_int(r, "snapshot-id").is_some_and(|id| ids.contains(&id)))
            .map(|(name, _)| name.clone())
            .collect();
        for name in gone {
            self.object("refs").remove(&name);
            if name == "main" {
                self.set("current-snapshot-id", json!(-1));
            }
        }
        for field in ["statistics", "partition-statistics"] {
            self.array(field)
                .retain(|s| !opt_int(s, "snapshot-id").is_some_and(|id| ids.contains(&id)));
        }
        // The snapshot log keeps what follows the last snapshot that's gone,
        // as Iceberg's does.
        let remaining = self.ids("snapshots", "snapshot-id");
        let log = std::mem::take(self.array("snapshot-log"));
        let mut kept = Vec::new();
        for entry in log {
            match opt_int(&entry, "snapshot-id").is_some_and(|id| remaining.contains(&id)) {
                true => kept.push(entry),
                false => kept.clear(),
            }
        }
        *self.array("snapshot-log") = kept;
    }

    /// Whether anything changed.
    pub fn changed(&self) -> bool {
        self.changed
    }

    /// The metadata built, after a file at `previous` (with its own
    /// last-updated-ms `previous_updated`), if there was one: logged.
    /// Checked to be a whole table.
    pub fn build(mut self, previous: Option<(&str, i64)>) -> Result<Map<String, Value>> {
        if self.changed {
            let at = self.updated_at.unwrap_or(self.now);
            self.m.insert("last-updated-ms".into(), json!(at));
            if let Some((file, at)) = previous {
                let max = self
                    .m
                    .get("properties")
                    .and_then(|p| p.get("write.metadata.previous-versions-max"))
                    .and_then(Value::as_str)
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(PREVIOUS_VERSIONS_MAX);
                let log = self.array("metadata-log");
                log.push(json!({ "metadata-file": file, "timestamp-ms": at }));
                let excess = log.len().saturating_sub(max);
                log.drain(..excess);
            }
        }
        // What every table has.
        if !self.m.get("table-uuid").is_some_and(Value::is_string) {
            return invalid("The table has no UUID: assign one.");
        }
        let current = self.get_i64("current-schema-id");
        if !self.has("schemas", "schema-id", current) {
            return invalid("The table has no current schema.");
        }
        let spec = self.get_i64("default-spec-id");
        if !self.has("partition-specs", "spec-id", spec) {
            return invalid("The table has no default partition spec.");
        }
        let order = self.get_i64("default-sort-order-id");
        if !self.has("sort-orders", "order-id", order) {
            return invalid("The table has no default sort order.");
        }
        Ok(self.m)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn creation() -> Creation {
        Creation {
            schema: json!({
                "type": "struct", "schema-id": 7, "identifier-field-ids": [10],
                "fields": [
                    { "id": 10, "name": "id", "required": true, "type": "long" },
                    { "id": 20, "name": "point", "required": false, "type": {
                        "type": "struct", "fields": [
                            { "id": 21, "name": "x", "required": true, "type": "double" },
                            { "id": 22, "name": "y", "required": true, "type": "double" },
                        ]
                    }},
                    { "id": 30, "name": "tags", "required": false, "type": {
                        "type": "list", "element-id": 31, "element": "string", "element-required": false
                    }},
                    { "id": 40, "name": "attrs", "required": false, "type": {
                        "type": "map", "key-id": 41, "key": "string", "value-id": 42, "value": "string", "value-required": false
                    }},
                    { "id": 50, "name": "ts", "required": false, "type": "timestamptz" },
                ]
            }),
            partition_spec: Some(json!({ "spec-id": 3, "fields": [
                { "source-id": 50, "transform": "day", "name": "ts_day", "field-id": 1005 }
            ]})),
            write_order: Some(json!({ "order-id": 5, "fields": [
                { "source-id": 10, "transform": "identity", "direction": "asc", "null-order": "nulls-first" }
            ]})),
            properties: json!({ "owner": "me", "format-version": "2" })
                .as_object()
                .cloned()
                .unwrap(),
        }
    }

    #[test]
    fn a_new_table_has_fresh_ids() {
        let m = new_table(&creation(), "s3://t--table-s3", "u", 1000).unwrap();
        let m = Value::Object(m);
        let schema = &m["schemas"][0];
        // Top-level fields first (1..5), then what's in each, in order.
        let ids: Vec<i64> = schema["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["id"].as_i64().unwrap())
            .collect();
        assert_eq!(ids, [1, 2, 3, 4, 5]);
        assert_eq!(schema["fields"][1]["type"]["fields"][0]["id"], 6);
        assert_eq!(schema["fields"][1]["type"]["fields"][1]["id"], 7);
        assert_eq!(schema["fields"][2]["type"]["element-id"], 8);
        assert_eq!(schema["fields"][3]["type"]["key-id"], 9);
        assert_eq!(schema["fields"][3]["type"]["value-id"], 10);
        assert_eq!(schema["schema-id"], 0);
        assert_eq!(schema["identifier-field-ids"], json!([1]));
        assert_eq!(m["last-column-id"], 10);
        assert_eq!(m["partition-specs"][0]["fields"][0]["source-id"], 5);
        assert_eq!(m["partition-specs"][0]["fields"][0]["field-id"], 1000);
        assert_eq!(m["last-partition-id"], 1000);
        assert_eq!(m["default-sort-order-id"], 1);
        assert_eq!(m["sort-orders"][0]["fields"][0]["source-id"], 1);
        assert_eq!(m["properties"], json!({ "owner": "me" }));
        assert_eq!(m["format-version"], 2);
        assert!(m.get("next-row-id").is_none());
    }

    #[test]
    fn format_versions() {
        let mut c = creation();
        c.properties.insert("format-version".into(), json!("3"));
        let m = new_table(&c, "s3://l", "u", 1).unwrap();
        assert_eq!(m["format-version"], 3);
        assert_eq!(m["next-row-id"], 0);
        c.properties.insert("format-version".into(), json!("1"));
        assert!(matches!(
            new_table(&c, "s3://l", "u", 1),
            Err(Failure::Invalid(_))
        ));
    }

    fn table() -> Map<String, Value> {
        new_table(&creation(), "s3://t--table-s3", "uuid-1", 1000).unwrap()
    }

    fn snapshot(id: i64, parent: Option<i64>, sequence: i64, at: i64) -> Value {
        json!({ "action": "add-snapshot", "snapshot": {
            "snapshot-id": id, "parent-snapshot-id": parent, "sequence-number": sequence,
            "timestamp-ms": at, "manifest-list": format!("s3://t--table-s3/metadata/snap-{id}.avro"),
            "summary": { "operation": "append" }, "schema-id": 0,
        }})
    }

    fn main(id: i64) -> Value {
        json!({ "action": "set-snapshot-ref", "ref-name": "main", "type": "branch", "snapshot-id": id })
    }

    #[test]
    fn appends_and_logs() {
        let base = table();
        check_requirements(
            Some(&base),
            &[json!({ "type": "assert-ref-snapshot-id", "ref": "main", "snapshot-id": null })],
        )
        .unwrap();
        let mut b = Builder::new(base, 5000);
        b.apply(&[snapshot(1, None, 1, 2000), main(1)]).unwrap();
        let m = Value::Object(
            b.build(Some((
                "s3://t--table-s3/metadata/00000-a.metadata.json",
                1000,
            )))
            .unwrap(),
        );
        assert_eq!(m["current-snapshot-id"], 1);
        assert_eq!(m["last-sequence-number"], 1);
        assert_eq!(m["last-updated-ms"], 2000);
        assert_eq!(
            m["refs"]["main"],
            json!({ "snapshot-id": 1, "type": "branch" })
        );
        assert_eq!(
            m["snapshot-log"],
            json!([{ "snapshot-id": 1, "timestamp-ms": 2000 }])
        );
        assert_eq!(
            m["metadata-log"][0]["metadata-file"],
            "s3://t--table-s3/metadata/00000-a.metadata.json"
        );
        // A second writer that saw no snapshot fails its requirement.
        let base = m.as_object().cloned().unwrap();
        assert!(matches!(
            check_requirements(
                Some(&base),
                &[json!({ "type": "assert-ref-snapshot-id", "ref": "main", "snapshot-id": null })]
            ),
            Err(Failure::Conflict(_))
        ));
        check_requirements(
            Some(&base),
            &[json!({ "type": "assert-ref-snapshot-id", "ref": "main", "snapshot-id": 1 })],
        )
        .unwrap();
        // An older sequence number can't follow.
        let mut b = Builder::new(base.clone(), 6000);
        assert!(matches!(
            b.apply(&[snapshot(2, Some(1), 1, 3000)]),
            Err(Failure::Conflict(_))
        ));
        let mut b = Builder::new(base, 6000);
        b.apply(&[snapshot(2, Some(1), 2, 3000), main(2)]).unwrap();
        let m = Value::Object(
            b.build(Some((
                "s3://t--table-s3/metadata/00001-b.metadata.json",
                2000,
            )))
            .unwrap(),
        );
        assert_eq!(m["snapshot-log"].as_array().unwrap().len(), 2);
        // Expiring the first: its log entry, and what's before it, go.
        let mut b = Builder::new(m.as_object().cloned().unwrap(), 7000);
        b.apply(&[json!({ "action": "remove-snapshots", "snapshot-ids": [1] })])
            .unwrap();
        let m = Value::Object(b.build(None).unwrap());
        assert_eq!(m["snapshots"].as_array().unwrap().len(), 1);
        assert_eq!(
            m["snapshot-log"],
            json!([{ "snapshot-id": 2, "timestamp-ms": 3000 }])
        );
        assert_eq!(m["current-snapshot-id"], 2);
    }

    #[test]
    fn schema_evolution() {
        let base = table();
        let mut schema = base["schemas"][0].clone();
        schema["fields"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "id": 11, "name": "note", "required": false, "type": "string" }));
        let mut b = Builder::new(base.clone(), 5000);
        b.apply(&[
            json!({ "action": "add-schema", "schema": schema, "last-column-id": 11 }),
            json!({ "action": "set-current-schema", "schema-id": -1 }),
        ])
        .unwrap();
        let m = Value::Object(b.build(None).unwrap());
        assert_eq!(m["current-schema-id"], 1);
        assert_eq!(m["last-column-id"], 11);
        assert_eq!(m["schemas"].as_array().unwrap().len(), 2);
        // The same schema again is the one there is.
        let mut b = Builder::new(m.as_object().cloned().unwrap(), 6000);
        b.apply(&[
            json!({ "action": "add-schema", "schema": schema }),
            json!({ "action": "set-current-schema", "schema-id": -1 }),
        ])
        .unwrap();
        assert!(!b.changed());
        // The current one can't be removed.
        let mut b = Builder::new(m.as_object().cloned().unwrap(), 6000);
        assert!(
            b.apply(&[json!({ "action": "remove-schemas", "schema-ids": [1] })])
                .is_err()
        );
        // A schema-id requirement holds a racing evolution off.
        assert!(matches!(
            check_requirements(
                Some(m.as_object().unwrap()),
                &[json!({ "type": "assert-current-schema-id", "current-schema-id": 0 })]
            ),
            Err(Failure::Conflict(_))
        ));
    }

    #[test]
    fn specs_orders_and_properties() {
        let mut b = Builder::new(table(), 5000);
        b.apply(&[
            json!({ "action": "add-spec", "spec": { "fields": [
                { "source-id": 5, "transform": "day", "name": "ts_day", "field-id": 1000 },
                { "source-id": 1, "transform": "bucket[16]", "name": "id_bucket" },
            ]}}),
            json!({ "action": "set-default-spec", "spec-id": -1 }),
            json!({ "action": "add-sort-order", "sort-order": { "fields": [] } }),
            json!({ "action": "set-default-sort-order", "sort-order-id": -1 }),
            json!({ "action": "set-properties", "updates": { "a": "1", "write.metadata.previous-versions-max": "1" } }),
            json!({ "action": "remove-properties", "removals": ["owner"] }),
        ])
        .unwrap();
        let m = Value::Object(b.build(Some(("s3://x/0", 1))).unwrap());
        assert_eq!(m["default-spec-id"], 1);
        assert_eq!(m["partition-specs"][1]["fields"][1]["field-id"], 1001);
        assert_eq!(m["last-partition-id"], 1001);
        assert_eq!(m["default-sort-order-id"], 0);
        assert_eq!(
            m["properties"],
            json!({ "a": "1", "write.metadata.previous-versions-max": "1" })
        );
        // The log keeps one previous file.
        let mut b = Builder::new(m.as_object().cloned().unwrap(), 6000);
        b.apply(&[json!({ "action": "set-properties", "updates": { "a": "2" } })])
            .unwrap();
        let m = Value::Object(b.build(Some(("s3://x/1", 2))).unwrap());
        assert_eq!(
            m["metadata-log"],
            json!([{ "metadata-file": "s3://x/1", "timestamp-ms": 2 }])
        );
        let mut b = Builder::new(m.as_object().cloned().unwrap(), 6000);
        assert!(
            b.apply(&[json!({ "action": "set-location", "location": "s3://elsewhere" })])
                .is_err()
        );
        assert!(b.apply(&[json!({ "action": "unknown-thing" })]).is_err());
    }

    #[test]
    fn a_staged_creation() {
        let m = table();
        let schema = m["schemas"][0].clone();
        check_requirements(None, &[json!({ "type": "assert-create" })]).unwrap();
        assert!(check_requirements(Some(&m), &[json!({ "type": "assert-create" })]).is_err());
        let mut b = Builder::new(empty("s3://t--table-s3", 10), 10);
        b.apply(&[
            json!({ "action": "assign-uuid", "uuid": "u-2" }),
            json!({ "action": "upgrade-format-version", "format-version": 3 }),
            json!({ "action": "add-schema", "schema": schema }),
            json!({ "action": "set-current-schema", "schema-id": -1 }),
            json!({ "action": "add-spec", "spec": { "fields": [] } }),
            json!({ "action": "set-default-spec", "spec-id": -1 }),
            json!({ "action": "add-sort-order", "sort-order": { "fields": [] } }),
            json!({ "action": "set-default-sort-order", "sort-order-id": -1 }),
        ])
        .unwrap();
        let m = Value::Object(b.build(None).unwrap());
        assert_eq!(m["format-version"], 3);
        assert_eq!(m["next-row-id"], 0);
        assert_eq!(m["current-schema-id"], 0);
        assert_eq!(m["default-spec-id"], 0);
        // Without a schema, it's no table.
        let mut b = Builder::new(empty("s3://t", 10), 10);
        b.apply(&[json!({ "action": "assign-uuid", "uuid": "u" })])
            .unwrap();
        assert!(b.build(None).is_err());
    }

    #[test]
    fn row_lineage() {
        let mut c = creation();
        c.properties.insert("format-version".into(), json!("3"));
        let base = new_table(&c, "s3://l", "u", 1).unwrap();
        let mut add = snapshot(1, None, 1, 2);
        add["snapshot"]["first-row-id"] = json!(0);
        add["snapshot"]["added-rows"] = json!(10);
        let mut b = Builder::new(base.clone(), 3);
        b.apply(&[add, main(1)]).unwrap();
        let m = b.build(None).unwrap();
        assert_eq!(m["next-row-id"], 10);
        let mut behind = snapshot(2, Some(1), 2, 3);
        behind["snapshot"]["first-row-id"] = json!(5);
        let mut b = Builder::new(m, 4);
        assert!(matches!(b.apply(&[behind]), Err(Failure::Conflict(_))));
    }

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
}
