//! Namespaces' operations: one level of them in a table bucket, each
//! holding tables.

use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    Answer, Ctx, Input, MAX_NAMESPACES, Page, Result, TableBucket, Target, bad_request, conflict,
    iso, names, no_bucket, no_namespace,
};
use crate::policy::Context;

/// A namespace, as S3 Tables writes one.
fn namespace_json(bucket: &TableBucket, row: &tokio_postgres::Row) -> Value {
    json!({
        "namespace": [row.get::<_, String>(1)],
        "createdAt": row.get::<_, String>(2),
        "createdBy": row.get::<_, String>(3),
        "ownerAccountId": bucket.account,
        "namespaceId": row.get::<_, Uuid>(0).to_string(),
        "tableBucketId": bucket.id.to_string(),
    })
}

fn columns() -> String {
    format!("id, name, {}, created_by", iso("created_at"))
}

impl Ctx<'_> {
    /// The table bucket `arn` names, and namespace `namespace` in it, if
    /// `action` on it is allowed (with `s3tables:namespace`).
    async fn checked_namespace(
        &mut self,
        arn: &str,
        namespace: &str,
        action: &'static str,
    ) -> Result<(TableBucket, tokio_postgres::Row)> {
        let (account, name, bucket) = self.bucket_of(arn).await?;
        self.check(
            action,
            &Target::Bucket {
                account: &account,
                name: &name,
                bucket: bucket.as_ref(),
                namespace: Some(namespace),
            },
            &Context::default(),
        )?;
        let bucket = bucket.ok_or_else(no_bucket)?;
        let sql = format!(
            "SELECT {} FROM table_namespaces WHERE table_bucket_id = $1 AND name = $2",
            columns()
        );
        let row = self
            .client
            .query_opt(&sql, &[&bucket.id, &namespace])
            .await?
            .ok_or_else(no_namespace)?;
        Ok((bucket, row))
    }

    pub(super) async fn create_namespace(&mut self, arn: &str, input: &Input) -> Result<Answer> {
        let namespace = match input.get("namespace") {
            Some(Value::Array(items)) if items.len() == 1 => match &items[0] {
                Value::String(name) => name.clone(),
                _ => return Err(bad_request("namespace must be a list of one name.")),
            },
            Some(_) => return Err(bad_request("namespace must be a list of one name.")),
            None => return Err(bad_request("namespace is required.")),
        };
        names::name("namespace", &namespace).map_err(bad_request)?;
        let bucket = self
            .checked_bucket(arn, "s3tables:CreateNamespace", &Context::default())
            .await?;
        let tx = self.client.transaction().await?;
        // One at a time per bucket, so that the quota holds; and not into
        // a bucket being deleted.
        let locked = tx
            .query_opt(
                "SELECT 1 FROM table_buckets WHERE id = $1 FOR UPDATE",
                &[&bucket.id],
            )
            .await?;
        if locked.is_none() {
            return Err(no_bucket());
        }
        let count: i64 = tx
            .query_one(
                "SELECT count(*) FROM table_namespaces WHERE table_bucket_id = $1",
                &[&bucket.id],
            )
            .await?
            .get(0);
        if count >= MAX_NAMESPACES {
            return Err(bad_request(format!(
                "The table bucket has reached the quota of {MAX_NAMESPACES} namespaces."
            )));
        }
        let inserted = tx
            .execute(
                "INSERT INTO table_namespaces (id, table_bucket_id, name, created_by)
                 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                &[
                    &Uuid::new_v4(),
                    &bucket.id,
                    &namespace,
                    &self.principal.account,
                ],
            )
            .await?;
        if inserted == 0 {
            return Err(conflict(
                "A namespace with an identical name already exists in the bucket.",
            ));
        }
        tx.commit().await?;
        Ok(Answer::Json(json!({
            "tableBucketARN": bucket.arn(),
            "namespace": [namespace],
        })))
    }

    pub(super) async fn get_namespace(&mut self, arn: &str, namespace: &str) -> Result<Answer> {
        let (bucket, row) = self
            .checked_namespace(arn, namespace, "s3tables:GetNamespace")
            .await?;
        Ok(Answer::Json(namespace_json(&bucket, &row)))
    }

    pub(super) async fn list_namespaces(&mut self, arn: &str, query: &str) -> Result<Answer> {
        let page = Page::of(query, "maxNamespaces")?;
        let prefix = crate::s3::util::query_param(query, "prefix").unwrap_or_default();
        let bucket = self
            .checked_bucket(arn, "s3tables:ListNamespaces", &Context::default())
            .await?;
        let sql = format!(
            "SELECT {} FROM table_namespaces WHERE table_bucket_id = $1
               AND starts_with(name, $2) AND name > coalesce($3, '')
             ORDER BY name LIMIT $4",
            columns()
        );
        let rows = self
            .client
            .query(&sql, &[&bucket.id, &prefix, &page.after, &page.max])
            .await?;
        let mut out = json!({
            "namespaces": rows.iter().map(|r| namespace_json(&bucket, r)).collect::<Vec<_>>(),
        });
        if let Some(token) = page.next(rows.len(), rows.last().map(|r| r.get(1))) {
            out["continuationToken"] = json!(token);
        }
        Ok(Answer::Json(out))
    }

    pub(super) async fn delete_namespace(&mut self, arn: &str, namespace: &str) -> Result<Answer> {
        let (_, row) = self
            .checked_namespace(arn, namespace, "s3tables:DeleteNamespace")
            .await?;
        let id: Uuid = row.get(0);
        let tx = self.client.transaction().await?;
        let locked = tx
            .query_opt(
                "SELECT 1 FROM table_namespaces WHERE id = $1 FOR UPDATE",
                &[&id],
            )
            .await?;
        if locked.is_none() {
            return Err(no_namespace());
        }
        let used = tx
            .query_opt(
                "SELECT 1 FROM tables WHERE namespace_id = $1 LIMIT 1",
                &[&id],
            )
            .await?;
        if used.is_some() {
            return Err(conflict(
                "The namespace is not empty. Delete its tables first, or move them to another namespace.",
            ));
        }
        tx.execute("DELETE FROM table_namespaces WHERE id = $1", &[&id])
            .await?;
        tx.commit().await?;
        Ok(Answer::NoContent)
    }
}
