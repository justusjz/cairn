//! Tables' operations: creating, getting, listing, renaming and deleting
//! them, their metadata location, and their policies, encryption, storage
//! classes and maintenance configurations.

use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::{
    Answer, Ctx, Input, MAX_TABLES, Page, Result, Table, TableBucket, Tags, Target, bad_request,
    buckets::{bucket_maintenance, maintenance_value, taken},
    checked_policy, configuration_context, conflict, encryption_json, encryption_of, names,
    no_bucket, no_namespace, no_table, not_found, storage_class_of, version_token,
};
use crate::policy::Context;

const COMPACTION: &str = "icebergCompaction";
const SNAPSHOTS: &str = "icebergSnapshotManagement";

/// The suffixes a metadata file's name ends with.
const METADATA_SUFFIXES: [&str; 2] = [".metadata.json", ".metadata.json.gz"];

/// A table's maintenance configuration: AWS's defaults, unless set.
pub(super) fn table_maintenance(stored: &Map<String, Value>) -> Value {
    let compaction = stored.get(COMPACTION).cloned().unwrap_or_else(|| {
        json!({
            "status": "enabled",
            "settings": { COMPACTION: { "targetFileSizeMB": 512, "strategy": "auto" } },
        })
    });
    let snapshots = stored.get(SNAPSHOTS).cloned().unwrap_or_else(|| {
        json!({
            "status": "enabled",
            "settings": { SNAPSHOTS: { "minSnapshotsToKeep": 1, "maxSnapshotAgeHours": 120 } },
        })
    });
    json!({ COMPACTION: compaction, SNAPSHOTS: snapshots })
}

/// A table, as GetTable writes it.
fn table_json(bucket: &TableBucket, table: &Table) -> Value {
    let mut out = json!({
        "name": table.name,
        "type": "customer",
        "tableARN": table.arn(bucket),
        "namespace": [table.namespace],
        "namespaceId": table.namespace_id.to_string(),
        "versionToken": table.version_token,
        "warehouseLocation": table.warehouse_location(),
        "createdAt": table.created,
        "createdBy": table.created_by,
        "modifiedAt": table.modified,
        "modifiedBy": table.modified_by,
        "ownerAccountId": bucket.account,
        "format": "ICEBERG",
        "tableBucketId": bucket.id.to_string(),
    });
    if let Some(location) = &table.metadata_location {
        out["metadataLocation"] = json!(location);
    }
    out
}

/// A table, as ListTables summarizes it.
fn summary_json(bucket: &TableBucket, table: &Table) -> Value {
    json!({
        "namespace": [table.namespace],
        "name": table.name,
        "type": "customer",
        "tableARN": table.arn(bucket),
        "createdAt": table.created,
        "modifiedAt": table.modified,
        "namespaceId": table.namespace_id.to_string(),
        "tableBucketId": bucket.id.to_string(),
    })
}

impl Ctx<'_> {
    /// CreateTable: with `metadata`, its first metadata file too, which
    /// S3 Tables writes (see `iceberg::rest`).
    pub(super) async fn create_table(
        &mut self,
        arn: &str,
        namespace: &str,
        input: &Input,
    ) -> Result<Answer> {
        let Some(metadata) = input.get("metadata") else {
            return self.create_table_plain(arn, namespace, input).await;
        };
        let name = input.required("name")?.to_owned();
        names::name("table", &name).map_err(bad_request)?;
        names::name("namespace", namespace).map_err(bad_request)?;
        let creation = super::iceberg::rest::creation_of(metadata).map_err(bad_request)?;
        let made = self
            .create_with_metadata(arn, namespace, &name, &creation, Some(input))
            .await;
        let (table_arn, _, _) = made.map_err(super::iceberg::rest::to_tables)?;
        let token: String =
            self.client
                .query_one(
                    "SELECT version_token FROM tables WHERE id = $1",
                    &[&Uuid::parse_str(table_arn.rsplit('/').next().unwrap_or(""))
                        .unwrap_or_default()],
                )
                .await?
                .get(0);
        Ok(Answer::Json(json!({
            "tableARN": table_arn,
            "versionToken": token,
        })))
    }

    /// CreateTable, without metadata: the table has none until its first
    /// writer gives it.
    pub(super) async fn create_table_plain(
        &mut self,
        arn: &str,
        namespace: &str,
        input: &Input,
    ) -> Result<Answer> {
        let name = input.required("name")?.to_owned();
        names::name("table", &name).map_err(bad_request)?;
        names::name("namespace", namespace).map_err(bad_request)?;
        match input.required("format")? {
            "ICEBERG" => {}
            other => {
                return Err(bad_request(format!(
                    "The table format is not valid: {other}"
                )));
            }
        }
        let encryption = encryption_of(input)?;
        let class = storage_class_of(input)?;
        let tags = Tags::from_input(input)?;
        let (account, bucket_name, bucket) = self.bucket_of(arn).await?;
        let target = Target::Bucket {
            account: &account,
            name: &bucket_name,
            bucket: bucket.as_ref(),
            namespace: Some(namespace),
        };
        let mut extra = configuration_context(encryption.as_ref(), class.as_deref());
        extra.set("s3tables:tableName", &name);
        tags.set_request_context(&mut extra);
        self.check("s3tables:CreateTable", &target, &extra)?;
        if encryption.is_some() {
            self.check("s3tables:PutTableEncryption", &target, &extra)?;
        }
        if class.is_some() {
            self.check("s3tables:PutTableStorageClass", &target, &extra)?;
        }
        if !tags.0.is_empty() {
            self.check("s3tables:TagResource", &target, &extra)?;
        }
        let bucket = bucket.ok_or_else(no_bucket)?;
        if let Some((algorithm, key)) = &encryption {
            self.encryption_usable(algorithm, key.as_deref())?;
        }
        let (algorithm, key) =
            encryption.unwrap_or_else(|| (bucket.sse_algorithm.clone(), bucket.kms_key.clone()));
        let class = match class {
            Some(class) => self.effective_class(&class).await?,
            None => bucket.storage_class.clone(),
        };
        let id = Uuid::new_v4();
        let storage = names::storage_name(&id);
        let token = version_token();
        let by = self.principal.account.clone();
        let tx = self.client.transaction().await?;
        // One at a time per bucket, so that the quota holds; and not into a
        // namespace being deleted (which locks it).
        let locked = tx
            .query_opt(
                "SELECT 1 FROM table_buckets WHERE id = $1 FOR UPDATE",
                &[&bucket.id],
            )
            .await?;
        if locked.is_none() {
            return Err(no_bucket());
        }
        let namespace_id: Uuid = tx
            .query_opt(
                "SELECT id FROM table_namespaces WHERE table_bucket_id = $1 AND name = $2 FOR SHARE",
                &[&bucket.id, &namespace],
            )
            .await?
            .ok_or_else(no_namespace)?
            .get(0);
        let count: i64 = tx
            .query_one(
                "SELECT count(*) FROM tables WHERE table_bucket_id = $1",
                &[&bucket.id],
            )
            .await?
            .get(0);
        if count >= MAX_TABLES {
            return Err(bad_request(format!(
                "The table bucket has reached the quota of {MAX_TABLES} tables."
            )));
        }
        super::storage::create(&tx, &storage, &bucket.account).await?;
        let inserted = tx
            .execute(
                "INSERT INTO tables (id, table_bucket_id, namespace_id, name, storage, version_token,
                                     created_by, modified_by, sse_algorithm, kms_key, storage_class, tags)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8, $9, $10, $11)",
                &[
                    &id,
                    &bucket.id,
                    &namespace_id,
                    &name,
                    &storage,
                    &token,
                    &by,
                    &algorithm,
                    &key,
                    &class,
                    &tags.stored(),
                ],
            )
            .await;
        match inserted {
            Ok(_) => {}
            Err(e) if taken(&e) => {
                return Err(conflict(
                    "A table with an identical name already exists in the namespace.",
                ));
            }
            Err(e) => return Err(e.into()),
        }
        tx.commit().await?;
        Ok(Answer::Json(json!({
            "tableARN": names::table_arn(&bucket.arn(), &id.to_string()),
            "versionToken": token,
        })))
    }

    pub(super) async fn get_table(&mut self, query: &str) -> Result<Answer> {
        let q = |name: &str| crate::s3::util::query_param(query, name);
        let (bucket, table) = match (
            q("tableArn"),
            q("tableBucketARN"),
            q("namespace"),
            q("name"),
        ) {
            (Some(arn), None, None, None) => self.table_by_arn(&arn, "s3tables:GetTable").await?,
            (None, Some(arn), Some(namespace), Some(name)) => {
                self.checked_table(
                    &arn,
                    &namespace,
                    &name,
                    "s3tables:GetTable",
                    &Context::default(),
                )
                .await?
            }
            _ => {
                return Err(bad_request(
                    "Specify either tableArn, or tableBucketARN, namespace and name.",
                ));
            }
        };
        Ok(Answer::Json(table_json(&bucket, &table)))
    }

    /// The table a table's ARN names, if `action` on it is allowed.
    async fn table_by_arn(
        &mut self,
        arn: &str,
        action: &'static str,
    ) -> Result<(TableBucket, Table)> {
        let Some(names::Arn::Table {
            account,
            bucket: name,
            id,
        }) = names::parse_arn(arn).map_err(bad_request)?
        else {
            return Err(bad_request(format!(
                "The specified ARN is not a table's: {arn}"
            )));
        };
        let bucket = TableBucket::load(&self.client, &account, &name).await?;
        let table = match (&bucket, Uuid::parse_str(&id)) {
            (Some(bucket), Ok(id)) => Table::by_id(&self.client, bucket.id, id).await?,
            _ => None,
        };
        match (bucket, table) {
            (Some(bucket), Some(table)) => {
                self.check(
                    action,
                    &Target::Table {
                        bucket: &bucket,
                        table: &table,
                    },
                    &Context::default(),
                )?;
                Ok((bucket, table))
            }
            (bucket, _) => {
                self.check(
                    action,
                    &Target::Bucket {
                        account: &account,
                        name: &name,
                        bucket: bucket.as_ref(),
                        namespace: None,
                    },
                    &Context::default(),
                )?;
                Err(no_table())
            }
        }
    }

    pub(super) async fn list_tables(&mut self, arn: &str, query: &str) -> Result<Answer> {
        let page = Page::of(query, "maxTables")?;
        let q = |name: &str| crate::s3::util::query_param(query, name);
        let prefix = q("prefix").unwrap_or_default();
        let namespace = q("namespace");
        let (account, name, bucket) = self.bucket_of(arn).await?;
        self.check(
            "s3tables:ListTables",
            &Target::Bucket {
                account: &account,
                name: &name,
                bucket: bucket.as_ref(),
                namespace: namespace.as_deref(),
            },
            &Context::default(),
        )?;
        let bucket = bucket.ok_or_else(no_bucket)?;
        // After a page's last table: its namespace, then its name.
        let (after_namespace, after_name) = match &page.after {
            Some(after) => match after.split_once('/') {
                Some((n, t)) => (Some(n.to_owned()), Some(t.to_owned())),
                None => return Err(bad_request("The continuation token is not valid.")),
            },
            None => (None, None),
        };
        let sql = format!(
            "SELECT {} FROM tables t JOIN table_namespaces n ON n.id = t.namespace_id
             WHERE t.table_bucket_id = $1 AND ($2::text IS NULL OR n.name = $2)
               AND starts_with(t.name, $3)
               AND ($4::text IS NULL OR (n.name, t.name) > ($4, $5))
             ORDER BY n.name, t.name LIMIT $6",
            Table::columns()
        );
        let rows = self
            .client
            .query(
                &sql,
                &[
                    &bucket.id,
                    &namespace,
                    &prefix,
                    &after_namespace,
                    &after_name,
                    &page.max,
                ],
            )
            .await?;
        let tables: Vec<Table> = rows.iter().map(Table::from_row).collect();
        let mut out = json!({
            "tables": tables.iter().map(|t| summary_json(&bucket, t)).collect::<Vec<_>>(),
        });
        let last = tables.last().map(|t| format!("{}/{}", t.namespace, t.name));
        if let Some(token) = page.next(tables.len(), last) {
            out["continuationToken"] = json!(token);
        }
        Ok(Answer::Json(out))
    }

    pub(super) async fn delete_table(
        &mut self,
        arn: &str,
        namespace: &str,
        name: &str,
        token: Option<String>,
    ) -> Result<Answer> {
        let (bucket, table) = self
            .checked_table(
                arn,
                namespace,
                name,
                "s3tables:DeleteTable",
                &Context::default(),
            )
            .await?;
        let tx = self.client.transaction().await?;
        let Some(locked) = Table::load(&tx, bucket.id, namespace, name, true).await? else {
            return Err(no_table());
        };
        if locked.id != table.id {
            return Err(no_table());
        }
        if token.as_ref().is_some_and(|t| *t != locked.version_token) {
            return Err(stale());
        }
        tx.execute("DELETE FROM tables WHERE id = $1", &[&locked.id])
            .await?;
        tx.commit().await?;
        // Its storage goes in the background (see `storage`).
        Ok(Answer::NoContent)
    }

    pub(super) async fn rename_table(
        &mut self,
        arn: &str,
        namespace: &str,
        name: &str,
        input: &Input,
    ) -> Result<Answer> {
        let new_namespace = input.str("newNamespaceName")?.map(str::to_owned);
        let new_name = input.str("newName")?.map(str::to_owned);
        let token = input.str("versionToken")?.map(str::to_owned);
        if let Some(n) = &new_namespace {
            names::name("namespace", n).map_err(bad_request)?;
        }
        if let Some(n) = &new_name {
            names::name("table", n).map_err(bad_request)?;
        }
        let (bucket, table) = self
            .checked_table(
                arn,
                namespace,
                name,
                "s3tables:RenameTable",
                &Context::default(),
            )
            .await?;
        let tx = self.client.transaction().await?;
        let Some(locked) = Table::load(&tx, bucket.id, namespace, name, true).await? else {
            return Err(no_table());
        };
        if locked.id != table.id {
            return Err(no_table());
        }
        if token.as_ref().is_some_and(|t| *t != locked.version_token) {
            return Err(stale());
        }
        let namespace_id: Uuid = match &new_namespace {
            Some(n) => tx
                .query_opt(
                    "SELECT id FROM table_namespaces WHERE table_bucket_id = $1 AND name = $2 FOR SHARE",
                    &[&bucket.id, n],
                )
                .await?
                .ok_or_else(no_namespace)?
                .get(0),
            None => locked.namespace_id,
        };
        let new_name = new_name.unwrap_or_else(|| locked.name.clone());
        let updated = tx
            .execute(
                "UPDATE tables SET namespace_id = $2, name = $3, modified_at = now(), modified_by = $4
                 WHERE id = $1",
                &[&locked.id, &namespace_id, &new_name, &self.principal.account],
            )
            .await;
        match updated {
            Ok(_) => {}
            Err(e) if taken(&e) => {
                return Err(conflict(
                    "A table with an identical name already exists in the namespace.",
                ));
            }
            Err(e) => return Err(e.into()),
        }
        tx.commit().await?;
        Ok(Answer::NoContent)
    }

    pub(super) async fn get_metadata_location(
        &mut self,
        arn: &str,
        namespace: &str,
        name: &str,
    ) -> Result<Answer> {
        let (_, table) = self
            .checked_table(
                arn,
                namespace,
                name,
                "s3tables:GetTableMetadataLocation",
                &Context::default(),
            )
            .await?;
        let mut out = json!({
            "versionToken": table.version_token,
            "warehouseLocation": table.warehouse_location(),
        });
        if let Some(location) = &table.metadata_location {
            out["metadataLocation"] = json!(location);
        }
        Ok(Answer::Json(out))
    }

    pub(super) async fn update_metadata_location(
        &mut self,
        arn: &str,
        namespace: &str,
        name: &str,
        input: &Input,
    ) -> Result<Answer> {
        let token = input.required("versionToken")?.to_owned();
        let location = input.required("metadataLocation")?.to_owned();
        if location.is_empty() || location.len() > 2048 {
            return Err(bad_request(
                "metadataLocation must be 1 to 2048 characters.",
            ));
        }
        let (bucket, table) = self
            .checked_table(
                arn,
                namespace,
                name,
                "s3tables:UpdateTableMetadataLocation",
                &Context::default(),
            )
            .await?;
        let under = location
            .strip_prefix(&table.warehouse_location())
            .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1);
        if !under || !METADATA_SUFFIXES.iter().any(|s| location.ends_with(s)) {
            return Err(bad_request(format!(
                "The metadata location must be a .metadata.json (or .metadata.json.gz) file in the \
                 table's warehouse location, {}.",
                table.warehouse_location()
            )));
        }
        let new_token = version_token();
        let row = self
            .client
            .query_opt(
                "UPDATE tables SET metadata_location = $3, version_token = $4, modified_at = now(),
                        modified_by = $5
                 WHERE id = $1 AND version_token = $2 RETURNING id",
                &[
                    &table.id,
                    &token,
                    &location,
                    &new_token,
                    &self.principal.account,
                ],
            )
            .await?;
        if row.is_none() {
            return Err(stale());
        }
        Ok(Answer::Json(json!({
            "name": table.name,
            "tableARN": table.arn(&bucket),
            "namespace": [table.namespace],
            "versionToken": new_token,
            "metadataLocation": location,
        })))
    }

    pub(super) async fn put_table_policy(
        &mut self,
        arn: &str,
        namespace: &str,
        name: &str,
        input: &Input,
    ) -> Result<Answer> {
        let (bucket, table) = self
            .checked_table(
                arn,
                namespace,
                name,
                "s3tables:PutTablePolicy",
                &Context::default(),
            )
            .await?;
        let policy = checked_policy(input, &table.arn(&bucket))?;
        self.client
            .execute(
                "UPDATE tables SET policy = $2 WHERE id = $1",
                &[&table.id, &policy],
            )
            .await?;
        Ok(Answer::Json(json!({})))
    }

    pub(super) async fn get_table_policy(
        &mut self,
        arn: &str,
        namespace: &str,
        name: &str,
    ) -> Result<Answer> {
        let (_, table) = self
            .checked_table(
                arn,
                namespace,
                name,
                "s3tables:GetTablePolicy",
                &Context::default(),
            )
            .await?;
        match table.policy {
            Some(policy) => Ok(Answer::Json(json!({ "resourcePolicy": policy }))),
            None => Err(not_found(
                "The specified table does not have a table policy.",
            )),
        }
    }

    pub(super) async fn delete_table_policy(
        &mut self,
        arn: &str,
        namespace: &str,
        name: &str,
    ) -> Result<Answer> {
        let (_, table) = self
            .checked_table(
                arn,
                namespace,
                name,
                "s3tables:DeleteTablePolicy",
                &Context::default(),
            )
            .await?;
        self.client
            .execute(
                "UPDATE tables SET policy = NULL WHERE id = $1",
                &[&table.id],
            )
            .await?;
        Ok(Answer::NoContent)
    }

    pub(super) async fn get_table_encryption(
        &mut self,
        arn: &str,
        namespace: &str,
        name: &str,
    ) -> Result<Answer> {
        let (_, table) = self
            .checked_table(
                arn,
                namespace,
                name,
                "s3tables:GetTableEncryption",
                &Context::default(),
            )
            .await?;
        Ok(Answer::Json(encryption_json(
            &table.sse_algorithm,
            table.kms_key.as_deref(),
        )))
    }

    pub(super) async fn get_table_storage_class(
        &mut self,
        arn: &str,
        namespace: &str,
        name: &str,
    ) -> Result<Answer> {
        let (_, table) = self
            .checked_table(
                arn,
                namespace,
                name,
                "s3tables:GetTableStorageClass",
                &Context::default(),
            )
            .await?;
        Ok(Answer::Json(json!({
            "storageClassConfiguration": { "storageClass": table.storage_class },
        })))
    }

    pub(super) async fn get_table_maintenance(
        &mut self,
        arn: &str,
        namespace: &str,
        name: &str,
    ) -> Result<Answer> {
        let (bucket, table) = self
            .checked_table(
                arn,
                namespace,
                name,
                "s3tables:GetTableMaintenanceConfiguration",
                &Context::default(),
            )
            .await?;
        Ok(Answer::Json(json!({
            "tableARN": table.arn(&bucket),
            "configuration": table_maintenance(&table.maintenance),
        })))
    }

    pub(super) async fn put_table_maintenance(
        &mut self,
        arn: &str,
        namespace: &str,
        name: &str,
        kind: &str,
        input: &Input,
    ) -> Result<Answer> {
        let value = match kind {
            SNAPSHOTS => {
                maintenance_value(
                    input,
                    SNAPSHOTS,
                    &[
                        ("minSnapshotsToKeep", 1, 1),
                        ("maxSnapshotAgeHours", 120, 1),
                    ],
                )?
                .0
            }
            COMPACTION => compaction_value(input)?,
            other => {
                return Err(bad_request(format!(
                    "The maintenance type is not valid: {other}"
                )));
            }
        };
        let (_, table) = self
            .checked_table(
                arn,
                namespace,
                name,
                "s3tables:PutTableMaintenanceConfiguration",
                &Context::default(),
            )
            .await?;
        let mut maintenance = table.maintenance.clone();
        maintenance.insert(kind.to_owned(), value);
        self.client
            .execute(
                "UPDATE tables SET maintenance = $2::text::jsonb WHERE id = $1",
                &[&table.id, &Value::Object(maintenance).to_string()],
            )
            .await?;
        Ok(Answer::NoContent)
    }

    /// GetTableMaintenanceJobStatus: each job's last run (see
    /// `maintenance`), or that it hasn't run yet; those disabled say so.
    pub(super) async fn get_table_maintenance_status(
        &mut self,
        arn: &str,
        namespace: &str,
        name: &str,
    ) -> Result<Answer> {
        let (bucket, table) = self
            .checked_table(
                arn,
                namespace,
                name,
                "s3tables:GetTableMaintenanceJobStatus",
                &Context::default(),
            )
            .await?;
        let mut configuration = table_maintenance(&table.maintenance);
        let unreferenced = bucket_maintenance(&bucket.maintenance);
        configuration["icebergUnreferencedFileRemoval"] =
            unreferenced["icebergUnreferencedFileRemoval"].clone();
        let sql = format!(
            "SELECT kind, status, failure, {} FROM table_maintenance_runs
             WHERE table_id = $1 AND status IS NOT NULL",
            super::iso("last_run")
        );
        let runs = self.client.query(&sql, &[&table.id]).await?;
        let status: Map<String, Value> = configuration
            .as_object()
            .expect("an object")
            .iter()
            .map(|(kind, value)| {
                let run = runs.iter().find(|r| r.get::<_, &str>(0) == kind);
                let status = match (value["status"].as_str(), run) {
                    (Some("enabled"), Some(run)) => {
                        let mut status = json!({
                            "status": run.get::<_, &str>(1),
                            "lastRunTimestamp": run.get::<_, Option<String>>(3),
                        });
                        if let Some(failure) = run.get::<_, Option<String>>(2) {
                            status["failureMessage"] = json!(failure);
                        }
                        status
                    }
                    (Some("enabled"), None) => json!({ "status": "Not_Yet_Run" }),
                    _ => json!({ "status": "Disabled" }),
                };
                (kind.clone(), status)
            })
            .collect();
        Ok(Answer::Json(json!({
            "tableARN": table.arn(&bucket),
            "status": status,
        })))
    }
}

/// A compaction configuration's value (see `compaction`).
fn compaction_value(input: &Input) -> Result<Value> {
    let value = input
        .object("value")?
        .ok_or_else(|| bad_request("value is required."))?;
    let settings = value
        .object("settings")?
        .map(|s| s.object(COMPACTION))
        .transpose()?
        .flatten();
    let size = match settings
        .as_ref()
        .map(|s| s.int("targetFileSizeMB"))
        .transpose()?
        .flatten()
    {
        Some(n) if !(64..=512).contains(&n) => {
            return Err(bad_request("targetFileSizeMB must be between 64 and 512."));
        }
        Some(n) => n,
        None => 512,
    };
    let strategy = match settings
        .as_ref()
        .map(|s| s.str("strategy"))
        .transpose()?
        .flatten()
    {
        Some(s @ ("auto" | "binpack" | "sort" | "z-order")) => s.to_owned(),
        Some(other) => return Err(bad_request(format!("The strategy is not valid: {other}"))),
        None => "auto".to_owned(),
    };
    let status = match value.str("status")? {
        None | Some("enabled") => "enabled",
        Some("disabled") => "disabled",
        Some(other) => return Err(bad_request(format!("The status is not valid: {other}"))),
    };
    Ok(json!({
        "status": status,
        "settings": { COMPACTION: { "targetFileSizeMB": size, "strategy": strategy } },
    }))
}

/// S3 Tables' 409 for a version token that isn't the table's.
fn stale() -> super::Error {
    conflict("Provided version token does not match the table version token.")
}
