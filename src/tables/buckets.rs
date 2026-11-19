//! Table buckets' operations: creating, getting, listing and deleting
//! them, and their policies, encryption, storage class, maintenance and
//! metrics configurations.

use serde_json::{Map, Value, json};
use tokio_postgres::error::SqlState;
use uuid::Uuid;

use super::{
    Answer, Ctx, Input, MAX_BUCKETS, Page, Result, TableBucket, Tags, Target, bad_request,
    checked_policy, configuration_context, conflict, encryption_json, encryption_of, names,
    not_found, storage_class_of,
};
use crate::{db::Cached, policy::Context};

/// The maintenance type of a table bucket's.
const UNREFERENCED: &str = "icebergUnreferencedFileRemoval";

/// A table bucket's maintenance configuration: AWS's defaults, unless set.
pub(super) fn bucket_maintenance(stored: &Map<String, Value>) -> Value {
    let value = stored.get(UNREFERENCED).cloned().unwrap_or_else(|| {
        json!({
            "status": "enabled",
            "settings": { UNREFERENCED: { "unreferencedDays": 3, "nonCurrentDays": 10 } },
        })
    });
    json!({ UNREFERENCED: value })
}

/// A maintenance configuration's `value`, of a type whose settings are
/// `settings` (their names, and defaults): its status (`enabled`, if it
/// says none), and its settings, each given (a positive integer, at least
/// its minimum) or its default.
pub(super) fn maintenance_value(
    input: &Input,
    kind: &str,
    settings: &[(&str, i64, i64)],
) -> Result<(Value, bool)> {
    let value = input
        .object("value")?
        .ok_or_else(|| bad_request("value is required."))?;
    let enabled = match value.str("status")? {
        None | Some("enabled") => true,
        Some("disabled") => false,
        Some(other) => return Err(bad_request(format!("The status is not valid: {other}"))),
    };
    let given = value
        .object("settings")?
        .map(|s| s.object(kind))
        .transpose()?
        .flatten();
    let mut out = Map::new();
    for (name, default, min) in settings {
        let n = match given.as_ref().map(|g| g.int(name)).transpose()?.flatten() {
            Some(n) if n < *min => {
                return Err(bad_request(format!("{name} must be at least {min}.")));
            }
            Some(n) => n,
            None => *default,
        };
        out.insert((*name).to_owned(), json!(n));
    }
    Ok((
        json!({
            "status": if enabled { "enabled" } else { "disabled" },
            "settings": { kind: Value::Object(out) },
        }),
        enabled,
    ))
}

impl Ctx<'_> {
    pub(super) async fn create_bucket(&mut self, input: &Input) -> Result<Answer> {
        let name = input.required("name")?.to_owned();
        names::bucket_name(&name).map_err(bad_request)?;
        let encryption = encryption_of(input)?;
        let class = storage_class_of(input)?;
        let tags = Tags::from_input(input)?;
        let account = self.account().to_owned();
        let target = Target::Bucket {
            account: &account,
            name: &name,
            bucket: None,
            namespace: None,
        };
        let mut extra = Context::default();
        tags.set_request_context(&mut extra);
        extra.extend(&configuration_context(
            encryption.as_ref(),
            class.as_deref(),
        ));
        self.check("s3tables:CreateTableBucket", &target, &extra)?;
        if encryption.is_some() {
            self.check("s3tables:PutTableBucketEncryption", &target, &extra)?;
        }
        if class.is_some() {
            self.check("s3tables:PutTableBucketStorageClass", &target, &extra)?;
        }
        if !tags.0.is_empty() {
            self.check("s3tables:TagResource", &target, &extra)?;
        }
        let class = match class {
            Some(class) => Some(self.effective_class(&class).await?),
            None => None,
        };
        if let Some((algorithm, key)) = &encryption {
            self.encryption_usable(algorithm, key.as_deref())?;
        }
        let (algorithm, key) = encryption.unwrap_or(("AES256".into(), None));
        let tx = self.client.transaction().await?;
        // One at a time per account, so that the quota holds.
        tx.execute(
            "SELECT 1 FROM accounts WHERE id = $1 FOR UPDATE",
            &[&account],
        )
        .await?;
        let count: i64 = tx
            .query_one(
                "SELECT count(*) FROM table_buckets WHERE account_id = $1",
                &[&account],
            )
            .await?
            .get(0);
        if count >= MAX_BUCKETS {
            return Err(bad_request(format!(
                "You have reached the quota of {MAX_BUCKETS} table buckets."
            )));
        }
        let inserted = tx
            .execute(
                "INSERT INTO table_buckets (id, account_id, name, sse_algorithm, kms_key, storage_class, tags)
                 VALUES ($1, $2, $3, $4, $5, coalesce($6, 'STANDARD'), $7) ON CONFLICT DO NOTHING",
                &[
                    &Uuid::new_v4(),
                    &account,
                    &name,
                    &algorithm,
                    &key,
                    &class,
                    &tags.stored(),
                ],
            )
            .await?;
        if inserted == 0 {
            return Err(conflict(
                "The bucket that you tried to create already exists, and you own it.",
            ));
        }
        tx.commit().await?;
        Ok(Answer::Json(
            json!({ "arn": names::bucket_arn(&account, &name) }),
        ))
    }

    pub(super) async fn get_bucket(&mut self, arn: &str) -> Result<Answer> {
        let bucket = self
            .checked_bucket(arn, "s3tables:GetTableBucket", &Context::default())
            .await?;
        Ok(Answer::Json(bucket.summary()))
    }

    pub(super) async fn list_buckets(&mut self, query: &str) -> Result<Answer> {
        let page = Page::of(query, "maxBuckets")?;
        let prefix = crate::s3::util::query_param(query, "prefix").unwrap_or_default();
        if prefix.len() > 63 {
            return Err(bad_request("prefix must be at most 63 characters."));
        }
        let kind = crate::s3::util::query_param(query, "type");
        if kind
            .as_deref()
            .is_some_and(|k| k != "customer" && k != "aws")
        {
            return Err(bad_request("type must be customer or aws."));
        }
        self.check(
            "s3tables:ListTableBuckets",
            &Target::Account,
            &Context::default(),
        )?;
        // Cairn has no AWS managed table buckets.
        if kind.as_deref() == Some("aws") {
            return Ok(Answer::Json(json!({ "tableBuckets": [] })));
        }
        let sql = format!(
            "SELECT {} FROM table_buckets b WHERE b.account_id = $1
               AND starts_with(b.name, $2) AND b.name > coalesce($3, '')
             ORDER BY b.name LIMIT $4",
            TableBucket::columns()
        );
        let rows = self
            .client
            .query(&sql, &[&self.account(), &prefix, &page.after, &page.max])
            .await?;
        let buckets: Vec<TableBucket> = rows.iter().map(TableBucket::from_row).collect();
        let mut out = json!({
            "tableBuckets": buckets.iter().map(TableBucket::summary).collect::<Vec<_>>(),
        });
        if let Some(token) = page.next(buckets.len(), buckets.last().map(|b| b.name.clone())) {
            out["continuationToken"] = json!(token);
        }
        Ok(Answer::Json(out))
    }

    pub(super) async fn delete_bucket(&mut self, arn: &str) -> Result<Answer> {
        let bucket = self
            .checked_bucket(arn, "s3tables:DeleteTableBucket", &Context::default())
            .await?;
        let tx = self.client.transaction().await?;
        let row = tx
            .query_opt(
                "SELECT 1 FROM table_buckets WHERE id = $1 FOR UPDATE",
                &[&bucket.id],
            )
            .await?;
        if row.is_none() {
            return Err(super::no_bucket());
        }
        let used = tx
            .query_opt(
                "SELECT 1 FROM table_namespaces WHERE table_bucket_id = $1 LIMIT 1",
                &[&bucket.id],
            )
            .await?;
        if used.is_some() {
            return Err(conflict(
                "The table bucket is not empty. Delete its namespaces and tables first.",
            ));
        }
        tx.execute("DELETE FROM table_buckets WHERE id = $1", &[&bucket.id])
            .await?;
        tx.commit().await?;
        Ok(Answer::NoContent)
    }

    pub(super) async fn put_bucket_policy(&mut self, arn: &str, input: &Input) -> Result<Answer> {
        let bucket = self
            .checked_bucket(arn, "s3tables:PutTableBucketPolicy", &Context::default())
            .await?;
        let policy = checked_policy(input, &bucket.arn())?;
        self.client
            .execute_cached(
                "UPDATE table_buckets SET policy = $2 WHERE id = $1",
                &[&bucket.id, &policy],
            )
            .await?;
        Ok(Answer::Json(json!({})))
    }

    pub(super) async fn get_bucket_policy(&mut self, arn: &str) -> Result<Answer> {
        let bucket = self
            .checked_bucket(arn, "s3tables:GetTableBucketPolicy", &Context::default())
            .await?;
        match bucket.policy {
            Some(policy) => Ok(Answer::Json(json!({ "resourcePolicy": policy }))),
            None => Err(not_found(
                "The specified bucket does not have a bucket policy.",
            )),
        }
    }

    pub(super) async fn delete_bucket_policy(&mut self, arn: &str) -> Result<Answer> {
        let bucket = self
            .checked_bucket(arn, "s3tables:DeleteTableBucketPolicy", &Context::default())
            .await?;
        self.client
            .execute_cached(
                "UPDATE table_buckets SET policy = NULL WHERE id = $1",
                &[&bucket.id],
            )
            .await?;
        Ok(Answer::NoContent)
    }

    pub(super) async fn put_bucket_encryption(
        &mut self,
        arn: &str,
        input: &Input,
    ) -> Result<Answer> {
        let Some((algorithm, key)) = encryption_of(input)? else {
            return Err(bad_request("encryptionConfiguration is required."));
        };
        let extra = configuration_context(Some(&(algorithm.clone(), key.clone())), None);
        let bucket = self
            .checked_bucket(arn, "s3tables:PutTableBucketEncryption", &extra)
            .await?;
        self.encryption_usable(&algorithm, key.as_deref())?;
        self.client
            .execute_cached(
                "UPDATE table_buckets SET sse_algorithm = $2, kms_key = $3 WHERE id = $1",
                &[&bucket.id, &algorithm, &key],
            )
            .await?;
        Ok(Answer::Json(json!({})))
    }

    pub(super) async fn get_bucket_encryption(&mut self, arn: &str) -> Result<Answer> {
        let bucket = self
            .checked_bucket(
                arn,
                "s3tables:GetTableBucketEncryption",
                &Context::default(),
            )
            .await?;
        Ok(Answer::Json(encryption_json(
            &bucket.sse_algorithm,
            bucket.kms_key.as_deref(),
        )))
    }

    /// DeleteTableBucketEncryption: back to S3 Tables' default, SSE-S3.
    pub(super) async fn delete_bucket_encryption(&mut self, arn: &str) -> Result<Answer> {
        let bucket = self
            .checked_bucket(
                arn,
                "s3tables:DeleteTableBucketEncryption",
                &Context::default(),
            )
            .await?;
        self.client
            .execute_cached(
                "UPDATE table_buckets SET sse_algorithm = 'AES256', kms_key = NULL WHERE id = $1",
                &[&bucket.id],
            )
            .await?;
        Ok(Answer::NoContent)
    }

    pub(super) async fn put_bucket_storage_class(
        &mut self,
        arn: &str,
        input: &Input,
    ) -> Result<Answer> {
        let Some(class) = storage_class_of(input)? else {
            return Err(bad_request("storageClassConfiguration is required."));
        };
        let extra = configuration_context(None, Some(&class));
        let bucket = self
            .checked_bucket(arn, "s3tables:PutTableBucketStorageClass", &extra)
            .await?;
        let class = self.effective_class(&class).await?;
        self.client
            .execute_cached(
                "UPDATE table_buckets SET storage_class = $2 WHERE id = $1",
                &[&bucket.id, &class],
            )
            .await?;
        Ok(Answer::Json(json!({})))
    }

    pub(super) async fn get_bucket_storage_class(&mut self, arn: &str) -> Result<Answer> {
        let bucket = self
            .checked_bucket(
                arn,
                "s3tables:GetTableBucketStorageClass",
                &Context::default(),
            )
            .await?;
        Ok(Answer::Json(json!({
            "storageClassConfiguration": { "storageClass": bucket.storage_class },
        })))
    }

    pub(super) async fn get_bucket_maintenance(&mut self, arn: &str) -> Result<Answer> {
        let bucket = self
            .checked_bucket(
                arn,
                "s3tables:GetTableBucketMaintenanceConfiguration",
                &Context::default(),
            )
            .await?;
        Ok(Answer::Json(json!({
            "tableBucketARN": bucket.arn(),
            "configuration": bucket_maintenance(&bucket.maintenance),
        })))
    }

    pub(super) async fn put_bucket_maintenance(
        &mut self,
        arn: &str,
        kind: &str,
        input: &Input,
    ) -> Result<Answer> {
        if kind != UNREFERENCED {
            return Err(bad_request(format!(
                "The maintenance type is not valid: {kind}"
            )));
        }
        let (value, _) = maintenance_value(
            input,
            UNREFERENCED,
            &[("unreferencedDays", 3, 1), ("nonCurrentDays", 10, 1)],
        )?;
        let bucket = self
            .checked_bucket(
                arn,
                "s3tables:PutTableBucketMaintenanceConfiguration",
                &Context::default(),
            )
            .await?;
        let mut maintenance = bucket.maintenance.clone();
        maintenance.insert(UNREFERENCED.to_owned(), value);
        self.client
            .execute_cached(
                "UPDATE table_buckets SET maintenance = $2::text::jsonb WHERE id = $1",
                &[&bucket.id, &Value::Object(maintenance).to_string()],
            )
            .await?;
        Ok(Answer::NoContent)
    }

    /// PutTableBucketMetricsConfiguration (`on`), and
    /// DeleteTableBucketMetricsConfiguration: kept, without effect (Cairn
    /// has metrics of its own, and no CloudWatch).
    pub(super) async fn put_bucket_metrics(&mut self, arn: &str, on: bool) -> Result<Answer> {
        let action = match on {
            true => "s3tables:PutTableBucketMetricsConfiguration",
            false => "s3tables:DeleteTableBucketMetricsConfiguration",
        };
        let bucket = self
            .checked_bucket(arn, action, &Context::default())
            .await?;
        if !on && !bucket.metrics {
            return Err(not_found(
                "The specified bucket does not have a metrics configuration.",
            ));
        }
        self.client
            .execute_cached(
                "UPDATE table_buckets SET metrics = $2 WHERE id = $1",
                &[&bucket.id, &on],
            )
            .await?;
        Ok(Answer::NoContent)
    }

    pub(super) async fn get_bucket_metrics(&mut self, arn: &str) -> Result<Answer> {
        let bucket = self
            .checked_bucket(
                arn,
                "s3tables:GetTableBucketMetricsConfiguration",
                &Context::default(),
            )
            .await?;
        if !bucket.metrics {
            return Err(not_found(
                "The specified bucket does not have a metrics configuration.",
            ));
        }
        Ok(Answer::Json(json!({
            "tableBucketARN": bucket.arn(),
            "id": bucket.id.to_string(),
        })))
    }

    /// The storage class a table bucket or table that asks for `class`
    /// gets: it, if the operator has defined it, else `STANDARD`, as an
    /// object's (see `classes`).
    pub(super) async fn effective_class(&self, class: &str) -> Result<String> {
        // INTELLIGENT_TIERING is one of S3's, so it's that or STANDARD.
        Ok(crate::classes::resolve(self.app, Some(class))
            .await?
            .unwrap_or_else(|_| crate::classes::STANDARD.to_owned()))
    }

    /// Refuses an encryption configuration that Cairn can't apply: SSE-KMS
    /// without a KMS (see `kms`). (SSE-S3, S3 Tables' default, is taken
    /// without one: the table's objects are then stored as they come; see
    /// `storage`.)
    pub(super) fn encryption_usable(&self, algorithm: &str, key: Option<&str>) -> Result<()> {
        if algorithm == "aws:kms" && self.app.kms.is_none() {
            return Err(bad_request(format!(
                "SSE-KMS needs a KMS, which this cluster hasn't: {}",
                key.unwrap_or("")
            )));
        }
        Ok(())
    }
}

/// Whether `error` is a unique violation (a name that's taken).
pub(super) fn taken(error: &tokio_postgres::Error) -> bool {
    error.code() == Some(&SqlState::UNIQUE_VIOLATION)
}
