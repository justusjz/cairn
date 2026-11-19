//! What a backup captures of the database: every change to the tables it
//! backs up, row by row, logged by triggers into `backup_changes` in the
//! transaction that made it, while a backup is on.
//!
//! Each change is the table, what happened (`I`nsert, `U`pdate, `D`elete;
//! `T`runcate), the row's key (its primary key, as a JSON array, or `NULL`
//! for a table without a usable key), and the row as it is afterwards, in
//! Postgres's text form of a record (exact for every type; `NULL` for a
//! delete of a row with a key). An update that changes a row's key is logged
//! as a delete of the old row and an insert of the new one, and so is every
//! update of a table without a key. The transaction's ID (`xid`) comes too,
//! so that a restore can tell which changes a base snapshot holds already.
//!
//! A change's sequence number is drawn by the trigger, after the change took
//! its row lock. So any two changes of one row are numbered in the order they
//! committed, and replaying a table's changes in sequence order, those of
//! committed transactions only, ends at its state as of the last one. (Rows
//! of different transactions interleave in any order, but no two touch the
//! same row out of order.)
//!
//! What isn't backed up is where the data is ([`EXCLUDED`]): the nodes, blobs
//! and shards, which a restore lays out anew; and the backup's own state. A
//! part's blob and offset in it are where it is, too: an update of nothing
//! else (the packer moving it) isn't logged.
//!
//! Migrations run with capture off (`cairn.backup_capture`); a base snapshot
//! follows every change of the schema's version (see `backup`).

use deadpool_postgres::GenericClient;

/// Tables that aren't backed up. Every other table of the schema is, and a
/// test checks that every table is one or the other, so that a new table
/// can't be left out unseen.
pub const EXCLUDED: &[&str] = &[
    // Migrations' own.
    "schema_migrations",
    // Where data is: laid out anew by a restore.
    "nodes",
    "node_pools",
    "blobs",
    "blob_locations",
    "blob_garbage",
    "lost_ranges",
    "scrub_findings",
    // The backup's own, and a restore's.
    "backup_config",
    "backup_state",
    "backup_changes",
    "backup_objects",
    "backup_parts",
    "restore_source",
    "restore_blobs",
];

/// A table's columns that say where its data is, rather than what it is:
/// an update of nothing but these isn't logged.
const PHYSICAL: &[(&str, &[&str])] = &[("parts", &["blob_id", "blob_offset"])];

/// The name of the trigger on every captured table.
pub const TRIGGER: &str = "cairn_backup_capture";

/// A table that's backed up.
#[derive(Clone, Debug)]
pub struct Table {
    pub name: String,
    /// Its columns, in order, and whether each is generated (and so can't be
    /// written).
    pub columns: Vec<(String, bool)>,
    /// Columns whose values are drawn from an identity (`GENERATED ALWAYS`),
    /// which an insert has to override.
    pub identity: bool,
    /// Its columns' types, as `format_type` names them, in order.
    pub types: Vec<String>,
    /// The columns of its key: its primary key, or else a unique index
    /// of plain columns that are never NULL. `None`: rows are known by all
    /// their columns.
    pub key: Option<Vec<String>>,
}

impl Table {
    /// The types of its key's columns.
    pub fn key_types(&self) -> Vec<String> {
        let key = self.key.as_deref().unwrap_or_default();
        key.iter()
            .map(|k| self.types[self.columns.iter().position(|(c, _)| c == k).expect("a key's column")].clone())
            .collect()
    }

    /// An expression of a key given as a JSON array (`json`, an
    /// expression of type jsonb), as a row of the key's types, to compare
    /// keys by.
    pub fn key_of(&self, json: &str) -> String {
        let fields: Vec<String> =
            self.key_types().iter().enumerate().map(|(i, ty)| format!("({json}->>{i})::{ty}")).collect();
        format!("ROW({})", fields.join(", "))
    }

    /// The key's columns, as a row.
    pub fn key_row(&self, alias: &str) -> String {
        let key = self.key.as_deref().unwrap_or_default();
        let cols: Vec<String> = key.iter().map(|c| format!("{alias}.{}", quote(c))).collect();
        format!("ROW({})", cols.join(", "))
    }
}

/// `name`, quoted as an identifier.
pub fn quote(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// The tables of the schema that are backed up, by name.
pub async fn tables<C: GenericClient>(client: &C) -> Result<Vec<Table>, tokio_postgres::Error> {
    let rows = client
        .query(
            "SELECT c.relname,
                    array_agg(a.attname::text ORDER BY a.attnum),
                    array_agg(a.attgenerated <> '' ORDER BY a.attnum),
                    bool_or(a.attidentity = 'a'),
                    array_agg(format_type(a.atttypid, a.atttypmod) ORDER BY a.attnum),
                    (SELECT array_agg(k.attname::text ORDER BY array_position(i.indkey::int2[], k.attnum))
                     FROM pg_index i JOIN pg_attribute k ON k.attrelid = i.indrelid AND k.attnum = ANY(i.indkey)
                     WHERE i.indrelid = c.oid AND i.indisprimary),
                    (SELECT array_agg(k.attname::text ORDER BY array_position(i.indkey::int2[], k.attnum))
                     FROM (SELECT * FROM pg_index i
                           WHERE i.indrelid = c.oid AND i.indisunique AND i.indpred IS NULL
                             AND i.indexprs IS NULL
                             AND NOT EXISTS (SELECT 1 FROM pg_attribute n
                                             WHERE n.attrelid = c.oid AND n.attnum = ANY(i.indkey)
                                               AND NOT n.attnotnull)
                           ORDER BY i.indnatts, i.indexrelid LIMIT 1) i
                     JOIN pg_attribute k ON k.attrelid = i.indrelid AND k.attnum = ANY(i.indkey))
             FROM pg_class c
             JOIN pg_namespace ns ON ns.oid = c.relnamespace
             JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
             WHERE ns.nspname = 'public' AND c.relkind = 'r' AND c.relname::text <> ALL($1::text[])
             GROUP BY c.oid, c.relname
             ORDER BY c.relname",
            &[&EXCLUDED],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| {
            let names: Vec<String> = row.get(1);
            let generated: Vec<bool> = row.get(2);
            let types: Vec<String> = row.get(4);
            let primary: Option<Vec<String>> = row.get(5);
            let unique: Option<Vec<String>> = row.get(6);
            Table {
                name: row.get(0),
                columns: names.into_iter().zip(generated).collect(),
                identity: row.get(3),
                types,
                key: primary.or(unique),
            }
        })
        .collect())
}

/// The name of `table`'s capture function.
fn function(table: &str) -> String {
    format!("cairn_backup_capture_{table}")
}

/// The capture function of `table`.
fn function_sql(table: &Table) -> String {
    let t = &table.name;
    let literal = |s: &str| format!("'{}'", s.replace('\'', "''"));
    let key = |row: &str| match &table.key {
        Some(cols) => format!(
            "jsonb_build_array({})::text",
            cols.iter().map(|c| format!("{row}.{}", quote(c))).collect::<Vec<_>>().join(", ")
        ),
        None => "NULL".to_owned(),
    };
    let log = |op: char, row: &str, image: bool| {
        format!(
            "INSERT INTO backup_changes (xid, tbl, op, key, row) VALUES (pg_current_xact_id(), {}, '{op}', {}, {});",
            literal(t),
            key(row),
            if image { format!("{row}::text") } else { "NULL".to_owned() }
        )
    };
    // A delete needs the whole old row only if the table has no key.
    let keyless = table.key.is_none();
    let physical: &[&str] = PHYSICAL.iter().find(|(name, _)| *name == t).map_or(&[], |(_, cols)| cols);
    let unchanged = if physical.is_empty() {
        "OLD::text = NEW::text".to_owned()
    } else {
        let rest = |row: &str| {
            table
                .columns
                .iter()
                .filter(|(c, _)| !physical.contains(&c.as_str()))
                .map(|(c, _)| format!("{row}.{}", quote(c)))
                .collect::<Vec<_>>()
                .join(", ")
        };
        format!("ROW({})::text = ROW({})::text", rest("OLD"), rest("NEW"))
    };
    let key_changed = match &table.key {
        Some(cols) => {
            let of = |row: &str| cols.iter().map(|c| format!("{row}.{}", quote(c))).collect::<Vec<_>>().join(", ");
            format!("ROW({}) IS DISTINCT FROM ROW({})", of("OLD"), of("NEW"))
        }
        None => "true".to_owned(),
    };
    format!(
        "CREATE OR REPLACE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $capture$
BEGIN
    IF current_setting('cairn.backup_capture', true) = 'off' THEN
        RETURN NULL;
    END IF;
    IF TG_OP = 'INSERT' THEN
        {insert}
    ELSIF TG_OP = 'UPDATE' THEN
        IF {unchanged} THEN
            RETURN NULL;
        END IF;
        IF {key_changed} THEN
            {delete}
            {insert}
        ELSE
            {update}
        END IF;
    ELSIF TG_OP = 'DELETE' THEN
        {delete}
    ELSE
        INSERT INTO backup_changes (xid, tbl, op) VALUES (pg_current_xact_id(), {name}, 'T');
    END IF;
    RETURN NULL;
END
$capture$",
        function = quote(&function(t)),
        insert = log('I', "NEW", true),
        update = log('U', "NEW", true),
        delete = log('D', "OLD", keyless),
        name = literal(t),
    )
}

/// Creates (or replaces) the capture function of every table that's backed
/// up, and its trigger where it has none yet. Returns the tables that got a
/// new trigger: their changes until now weren't captured, so the backup
/// needs a new base snapshot.
pub async fn install<C: GenericClient>(client: &C) -> Result<Vec<String>, tokio_postgres::Error> {
    let tables = tables(client).await?;
    let triggered: Vec<String> = client
        .query(
            "SELECT c.relname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
             JOIN pg_namespace ns ON ns.oid = c.relnamespace
             WHERE ns.nspname = 'public' AND t.tgname = $1",
            &[&TRIGGER],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let mut added = Vec::new();
    for table in &tables {
        client.batch_execute(&function_sql(table)).await?;
        if !triggered.contains(&table.name) {
            client
                .batch_execute(&format!(
                    "CREATE TRIGGER {TRIGGER} AFTER INSERT OR UPDATE OR DELETE ON {table}
                         FOR EACH ROW EXECUTE FUNCTION {function}();
                     CREATE TRIGGER {TRIGGER}_truncate AFTER TRUNCATE ON {table}
                         FOR EACH STATEMENT EXECUTE FUNCTION {function}();",
                    table = quote(&table.name),
                    function = quote(&function(&table.name)),
                ))
                .await?;
            added.push(table.name.clone());
        }
    }
    Ok(added)
}

/// Drops every capture trigger and function, and the changes logged.
pub async fn uninstall<C: GenericClient>(client: &C) -> Result<(), tokio_postgres::Error> {
    let rows = client
        .query(
            "SELECT c.relname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
             JOIN pg_namespace ns ON ns.oid = c.relnamespace
             WHERE ns.nspname = 'public' AND t.tgname = $1",
            &[&TRIGGER],
        )
        .await?;
    for row in rows {
        let table: String = row.get(0);
        client
            .batch_execute(&format!(
                "DROP TRIGGER IF EXISTS {TRIGGER} ON {t}; DROP TRIGGER IF EXISTS {TRIGGER}_truncate ON {t};",
                t = quote(&table)
            ))
            .await?;
    }
    let functions = client
        .query(
            "SELECT p.proname FROM pg_proc p JOIN pg_namespace ns ON ns.oid = p.pronamespace
             WHERE ns.nspname = 'public' AND p.proname LIKE 'cairn\\_backup\\_capture\\_%'",
            &[],
        )
        .await?;
    for row in functions {
        let name: String = row.get(0);
        client.batch_execute(&format!("DROP FUNCTION IF EXISTS {}()", quote(&name))).await?;
    }
    client.batch_execute("DELETE FROM backup_changes").await?;
    Ok(())
}

/// The captured tables that have no capture trigger.
pub async fn missing<C: GenericClient>(client: &C) -> Result<Vec<String>, tokio_postgres::Error> {
    let rows = client
        .query(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace ns ON ns.oid = c.relnamespace
             WHERE ns.nspname = 'public' AND c.relkind = 'r' AND c.relname::text <> ALL($1::text[])
               AND NOT EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgrelid = c.oid AND t.tgname = $2)
             ORDER BY 1",
            &[&EXCLUDED, &TRIGGER],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}

/// The schema's sequences, the values they're at, and whether those were
/// drawn yet (`setval`'s `is_called`).
pub async fn sequences<C: GenericClient>(client: &C) -> Result<Vec<(String, i64, bool)>, tokio_postgres::Error> {
    let rows = client
        .query(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace ns ON ns.oid = c.relnamespace
             WHERE ns.nspname = 'public' AND c.relkind = 'S' ORDER BY 1",
            &[],
        )
        .await?;
    let mut values = Vec::new();
    for row in rows {
        let name: String = row.get(0);
        let row = client
            .query_one(&format!("SELECT last_value, is_called FROM {}", quote(&name)), &[])
            .await?;
        values.push((name, row.get(0), row.get(1)));
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    /// The tables that are backed up, as of the last migration that added
    /// one. A new table has to go here or in `EXCLUDED`: whether a restore
    /// needs it is a choice to make, not a default to fall into.
    const CAPTURED: &[&str] = &[
        "access_grants", "access_grants_instances", "access_grants_locations", "access_keys", "accounts",
        "batch_job_results", "batch_jobs", "bucket_notifications", "buckets", "console_challenges",
        "console_directory_sessions", "console_enrollments", "console_root_links", "console_root_sessions",
        "console_sessions", "console_switched_roles", "directory_passkeys", "directory_setup_links",
        "iam_group_attached_policies", "iam_group_members", "iam_group_policies", "iam_groups",
        "iam_oidc_provider_client_ids", "iam_oidc_provider_tags", "iam_oidc_provider_thumbprints",
        "iam_oidc_providers", "iam_role_attached_policies", "iam_role_policies", "iam_role_tags", "iam_roles",
        "identity_group_members", "identity_groups", "identity_users", "inventories", "inventory_files",
        "lifecycle_runs", "lifecycle_sweeps", "login_identities", "logins", "managed_policies",
        "managed_policy_tags", "managed_policy_versions", "multipart_uploads", "notification_events", "objects",
        "oidc_flows", "oidc_providers", "organization_policies", "organization_policy_attachments",
        "organization_policy_types", "organization_requests", "organizational_units", "parts", "passkeys",
        "permission_set_assignments", "permission_set_customer_policies", "permission_set_managed_policies",
        "permission_set_provisions", "permission_sets", "replication_queue", "role_grants", "root_mfa_devices",
        "session_keys",
        "settings", "sns_deliveries", "sns_signing_keys", "sns_subscriptions", "sns_tokens", "sns_topics",
        "sso_operations", "storage_classes", "user_attached_policies", "user_policies", "user_tags", "users",
    ];

    #[tokio::test]
    async fn every_table_is_backed_up_or_excluded() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else { return };
        let client = app.pool.get().await.unwrap();
        let tables: Vec<String> = super::tables(&client).await.unwrap().into_iter().map(|t| t.name).collect();
        let captured: Vec<String> = CAPTURED.iter().map(|t| t.to_string()).collect();
        assert_eq!(tables, captured, "a table was added or removed: back it up, or add it to EXCLUDED");
        for table in super::EXCLUDED {
            let exists: bool = client
                .query_one("SELECT to_regclass($1) IS NOT NULL", &[table])
                .await
                .unwrap()
                .get(0);
            assert!(exists, "{table} is excluded, but there's no such table");
        }
        // Every table has a key, but these, whose rows are known by all of
        // their columns.
        let keyless: Vec<String> = super::tables(&client)
            .await
            .unwrap()
            .into_iter()
            .filter(|t| t.key.is_none())
            .map(|t| t.name)
            .collect();
        assert_eq!(
            keyless,
            [
                "iam_group_attached_policies",
                "iam_oidc_provider_tags",
                "iam_role_attached_policies",
                "iam_role_tags",
                "user_attached_policies",
                "user_tags"
            ]
        );
    }
}
