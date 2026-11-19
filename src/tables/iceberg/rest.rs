//! Iceberg's REST catalog, as S3 Tables serves it (`/iceberg/v1/…`, signed
//! for `s3tables`): a table bucket is a warehouse, whose ARN (URL-encoded)
//! is the URL's prefix; its namespaces (one level) and tables are the
//! catalog's. Each operation is authorized as S3 Tables' actions are for
//! it (AWS's mapping: loading a table needs `s3tables:GetTableMetadataLocation`
//! and `s3tables:GetTableData`, say), and does what the `s3tables` API's
//! does, but that the catalog writes tables' metadata files itself: a
//! commit's requirements are checked, its updates applied (see
//! `metadata`), the new file written into the table's storage, and the
//! table's pointer swapped to it against its version token, so that of two
//! racing commits one fails (409, `CommitFailedException`) and is retried by
//! its client.
//!
//! As AWS's: no views, multi-level namespaces, staged creates, register,
//! multi-table transactions or OAuth; namespaces' properties aren't kept;
//! dropping a table purges it (`purgeRequested=true`). Its config hands out
//! the warehouse's prefix and, as defaults, where clients reach table
//! storage (this endpoint, path-style).

use hyper::{Method, StatusCode};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::{Creation, Failure, FileError};
use crate::{
    policy::Context,
    tables::{Answer, Ctx, Error, Input, NO_NAMESPACE, NO_TABLE, Table, TableBucket, Target},
};
use iceberg::spec::{TableMetadata, TableMetadataBuilder};
use iceberg::{TableRequirement, TableUpdate};

/// An Iceberg REST error: its status, its exception's type, its message.
pub(crate) fn rest_error(status: StatusCode, kind: &str, message: impl Into<String>) -> Answer {
    Answer::Raw(
        status,
        Some(json!({ "error": {
            "message": message.into(),
            "type": kind,
            "code": status.as_u16(),
        }})),
    )
}

fn bad_request(message: impl Into<String>) -> Answer {
    rest_error(StatusCode::BAD_REQUEST, "BadRequestException", message)
}

fn unsupported(what: &str) -> Answer {
    rest_error(
        StatusCode::NOT_ACCEPTABLE,
        "UnsupportedOperationException",
        format!("S3 Tables' catalog doesn't support {what}."),
    )
}

fn commit_failed(message: impl Into<String>) -> Answer {
    rest_error(StatusCode::CONFLICT, "CommitFailedException", message)
}

/// An `s3tables` operation's error, as the catalog's: a conflict as
/// `conflict` says (what it means where it happened).
fn from_tables(e: Error, conflict: &str) -> Answer {
    let kind = match e.status {
        StatusCode::NOT_FOUND if e.message == NO_TABLE => "NoSuchTableException",
        StatusCode::NOT_FOUND if e.message == NO_NAMESPACE => "NoSuchNamespaceException",
        StatusCode::NOT_FOUND => "NotFoundException",
        StatusCode::FORBIDDEN => "ForbiddenException",
        StatusCode::CONFLICT => conflict,
        StatusCode::NOT_IMPLEMENTED | StatusCode::METHOD_NOT_ALLOWED => {
            return rest_error(
                StatusCode::NOT_ACCEPTABLE,
                "UnsupportedOperationException",
                e.message,
            );
        }
        s if s.is_client_error() => "BadRequestException",
        _ => {
            return rest_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ServiceFailureException",
                e.message,
            );
        }
    };
    rest_error(e.status, kind, e.message)
}

/// A catalog's error as the `s3tables` API's (for CreateTable's metadata).
pub(crate) fn to_tables(answer: Answer) -> Error {
    let Answer::Raw(status, body) = answer else {
        return crate::tables::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerErrorException",
            "",
        );
    };
    let message = body
        .as_ref()
        .and_then(|b| b["error"]["message"].as_str())
        .unwrap_or("")
        .to_owned();
    let code = match status {
        StatusCode::BAD_REQUEST => "BadRequestException",
        StatusCode::FORBIDDEN => "AccessDeniedException",
        StatusCode::NOT_FOUND => "NotFoundException",
        StatusCode::CONFLICT => "ConflictException",
        StatusCode::NOT_ACCEPTABLE => {
            return crate::tables::error(StatusCode::NOT_IMPLEMENTED, "NotImplemented", message);
        }
        _ => "InternalServerErrorException",
    };
    crate::tables::error(status, code, message)
}

fn from_failure(f: Failure) -> Answer {
    match f {
        Failure::Invalid(m) => bad_request(m),
        Failure::Conflict(m) => commit_failed(m),
    }
}

fn from_file(e: FileError) -> Answer {
    match e {
        FileError::Unusable(m) => bad_request(m),
        FileError::Refused(m) => rest_error(StatusCode::FORBIDDEN, "ForbiddenException", m),
    }
}

/// Unwraps a result, or answers with its error.
macro_rules! or_answer {
    ($result:expr, $map:expr) => {
        match $result {
            Ok(value) => value,
            Err(e) => return $map(e),
        }
    };
}

/// The endpoints the catalog has, as its config lists them.
const ENDPOINTS: &[&str] = &[
    "GET /v1/{prefix}/namespaces",
    "POST /v1/{prefix}/namespaces",
    "GET /v1/{prefix}/namespaces/{namespace}",
    "HEAD /v1/{prefix}/namespaces/{namespace}",
    "DELETE /v1/{prefix}/namespaces/{namespace}",
    "GET /v1/{prefix}/namespaces/{namespace}/tables",
    "POST /v1/{prefix}/namespaces/{namespace}/tables",
    "GET /v1/{prefix}/namespaces/{namespace}/tables/{table}",
    "HEAD /v1/{prefix}/namespaces/{namespace}/tables/{table}",
    "POST /v1/{prefix}/namespaces/{namespace}/tables/{table}",
    "DELETE /v1/{prefix}/namespaces/{namespace}/tables/{table}",
    "POST /v1/{prefix}/tables/rename",
];

fn encode(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

/// A request's JSON body, as an object.
fn body_of(body: &[u8]) -> Result<Map<String, Value>, Answer> {
    match serde_json::from_slice(body) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(bad_request("The request's body isn't a JSON object.")),
    }
}

/// A namespace a request names: one level only (Iceberg separates levels
/// with `\x1F` in paths, and gives them as lists in bodies).
fn single(namespace: &str) -> Result<&str, Answer> {
    match namespace.contains('\u{1f}') {
        true => Err(bad_request("S3 Tables' namespaces have a single level.")),
        false => Ok(namespace),
    }
}

fn single_of(value: Option<&Value>) -> Result<String, Answer> {
    match value.and_then(Value::as_array).map(Vec::as_slice) {
        Some([Value::String(name)]) => Ok(name.clone()),
        Some(_) => Err(bad_request("S3 Tables' namespaces have a single level.")),
        None => Err(bad_request("A namespace is required.")),
    }
}

/// A `s3tables` answer's output.
fn json_of(answer: Answer) -> Value {
    match answer {
        Answer::Json(value) => value,
        _ => Value::Null,
    }
}

/// A table's metadata, as the catalog answers it when it's loaded.
fn load_result(location: &str, metadata: &TableMetadata) -> Value {
    json!({
        "metadata-location": location,
        "metadata": metadata,
        "config": {},
    })
}

impl Ctx<'_> {
    /// Answers a request to the catalog: `segments` are its path's after
    /// `/iceberg`, decoded.
    pub(crate) async fn iceberg(
        &mut self,
        method: &Method,
        segments: &[&str],
        query: &str,
        body: &[u8],
    ) -> Answer {
        use Method as M;
        let q = |name: &str| crate::s3::util::query_param(query, name);
        match (method, segments) {
            (&M::GET, ["v1", "config"]) => self.config(q("warehouse")).await,
            (_, ["v1", "oauth", "tokens"]) => unsupported("OAuth (sign requests with SigV4)"),
            (&M::GET, ["v1", arn, "namespaces"]) => self.list_namespaces_rest(arn, query).await,
            (&M::POST, ["v1", arn, "namespaces"]) => self.create_namespace_rest(arn, body).await,
            (&M::GET | &M::HEAD, ["v1", arn, "namespaces", ns]) => {
                let ns = or_answer!(single(ns), |e| e);
                let answer = self.get_namespace(arn, ns).await;
                let answer = or_answer!(answer, |e| from_tables(e, "AlreadyExistsException"));
                match *method == M::HEAD {
                    true => Answer::Raw(StatusCode::NO_CONTENT, None),
                    false => {
                        let name = json_of(answer)["namespace"].clone();
                        Answer::Raw(
                            StatusCode::OK,
                            Some(json!({ "namespace": name, "properties": {} })),
                        )
                    }
                }
            }
            (&M::DELETE, ["v1", arn, "namespaces", ns]) => {
                let ns = or_answer!(single(ns), |e| e);
                match self.delete_namespace(arn, ns).await {
                    Ok(_) => Answer::Raw(StatusCode::NO_CONTENT, None),
                    Err(e) => from_tables(e, "NamespaceNotEmptyException"),
                }
            }
            (&M::POST, ["v1", _, "namespaces", _, "properties"]) => {
                unsupported("namespaces' properties")
            }
            (&M::GET, ["v1", arn, "namespaces", ns, "tables"]) => {
                let ns = or_answer!(single(ns), |e| e);
                self.list_tables_rest(arn, ns, query).await
            }
            (&M::POST, ["v1", arn, "namespaces", ns, "tables"]) => {
                let ns = or_answer!(single(ns), |e| e);
                self.create_table_rest(arn, ns, body).await
            }
            (&M::GET, ["v1", arn, "namespaces", ns, "tables", table]) => {
                let ns = or_answer!(single(ns), |e| e);
                self.load_table(arn, ns, table).await
            }
            (&M::HEAD, ["v1", arn, "namespaces", ns, "tables", table]) => {
                let ns = or_answer!(single(ns), |e| e);
                match self
                    .checked_table(arn, ns, table, "s3tables:GetTable", &Context::default())
                    .await
                {
                    Ok(_) => Answer::Raw(StatusCode::NO_CONTENT, None),
                    Err(e) => from_tables(e, "AlreadyExistsException"),
                }
            }
            (&M::POST, ["v1", arn, "namespaces", ns, "tables", table]) => {
                let ns = or_answer!(single(ns), |e| e);
                self.commit(arn, ns, table, body).await
            }
            (&M::DELETE, ["v1", arn, "namespaces", ns, "tables", table]) => {
                let ns = or_answer!(single(ns), |e| e);
                if !q("purgeRequested").is_some_and(|p| p.eq_ignore_ascii_case("true")) {
                    return bad_request(
                        "S3 Tables purges a table's files as it drops it: drop it with purgeRequested=true.",
                    );
                }
                match self.delete_table(arn, ns, table, None).await {
                    Ok(_) => Answer::Raw(StatusCode::NO_CONTENT, None),
                    Err(e) => from_tables(e, "CommitFailedException"),
                }
            }
            // Metrics reports, which clients send after scans and commits:
            // taken, and dropped (S3 Tables' guide has clients not send them).
            (&M::POST, ["v1", _, "namespaces", _, "tables", _, "metrics"]) => {
                Answer::Raw(StatusCode::NO_CONTENT, None)
            }
            (&M::POST, ["v1", arn, "tables", "rename"]) => self.rename_rest(arn, body).await,
            (_, ["v1", _, "namespaces", _, "register"]) => unsupported("registering tables"),
            (_, ["v1", _, "namespaces", _, "views", ..] | ["v1", _, "views", ..]) => {
                unsupported("views")
            }
            (_, ["v1", _, "transactions", "commit"]) => unsupported("multi-table transactions"),
            (
                _,
                [
                    "v1",
                    _,
                    "namespaces",
                    _,
                    "tables",
                    _,
                    "plan" | "credentials",
                    ..,
                ],
            ) => unsupported("scan planning or credential vending"),
            _ => rest_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!(
                    "No catalog operation is {method} /iceberg/{}.",
                    segments.join("/")
                ),
            ),
        }
    }

    /// GET /v1/config: the warehouse's prefix (its ARN, URL-encoded), and
    /// where clients reach table storage (as defaults, which their own
    /// settings override).
    async fn config(&mut self, warehouse: Option<String>) -> Answer {
        let Some(arn) = warehouse else {
            return bad_request("Specify the warehouse: the table bucket's ARN.");
        };
        let found = self
            .checked_bucket(&arn, "s3tables:GetTableBucket", &Context::default())
            .await;
        or_answer!(found, |e| from_tables(e, "BadRequestException"));
        let mut defaults = json!({
            "client.region": crate::s3::buckets::head::REGION,
            "rest-metrics-reporting-enabled": "false",
        });
        if let Some(endpoint) = &self.endpoint {
            defaults["s3.endpoint"] = json!(endpoint);
            defaults["s3.path-style-access"] = json!("true");
        }
        Answer::Raw(
            StatusCode::OK,
            Some(json!({
                "defaults": defaults,
                "overrides": { "prefix": encode(&arn) },
                "endpoints": ENDPOINTS,
            })),
        )
    }

    async fn list_namespaces_rest(&mut self, arn: &str, query: &str) -> Answer {
        let q = |name: &str| crate::s3::util::query_param(query, name);
        // One level: a namespace has none under it.
        if let Some(parent) = q("parent").filter(|p| !p.is_empty()) {
            let parent = or_answer!(single(&parent), |e| e).to_owned();
            let found = self.get_namespace(arn, &parent).await;
            or_answer!(found, |e| from_tables(e, "BadRequestException"));
            return Answer::Raw(
                StatusCode::OK,
                Some(json!({ "namespaces": [], "next-page-token": null })),
            );
        }
        let query = page_query(query, "maxNamespaces");
        let answer = self.list_namespaces(arn, &query).await;
        let page = json_of(or_answer!(answer, |e| from_tables(
            e,
            "BadRequestException"
        )));
        let namespaces: Vec<Value> = page["namespaces"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|n| n["namespace"].clone())
            .collect();
        Answer::Raw(
            StatusCode::OK,
            Some(json!({ "namespaces": namespaces, "next-page-token": page["continuationToken"] })),
        )
    }

    async fn create_namespace_rest(&mut self, arn: &str, body: &[u8]) -> Answer {
        let body = or_answer!(body_of(body), |e| e);
        let name = or_answer!(single_of(body.get("namespace")), |e| e);
        let input = Input(
            json!({ "namespace": [name] })
                .as_object()
                .cloned()
                .expect("an object"),
        );
        let answer = self.create_namespace(arn, &input).await;
        or_answer!(answer, |e| from_tables(e, "AlreadyExistsException"));
        Answer::Raw(
            StatusCode::OK,
            Some(json!({ "namespace": [name], "properties": {} })),
        )
    }

    async fn list_tables_rest(&mut self, arn: &str, namespace: &str, query: &str) -> Answer {
        // The namespace must be there, as Iceberg's catalogs say.
        let found = self.get_namespace(arn, namespace).await;
        or_answer!(found, |e| from_tables(e, "BadRequestException"));
        let query = format!(
            "{}&namespace={}",
            page_query(query, "maxTables"),
            encode(namespace)
        );
        let answer = self.list_tables(arn, &query).await;
        let page = json_of(or_answer!(answer, |e| from_tables(
            e,
            "BadRequestException"
        )));
        let identifiers: Vec<Value> = page["tables"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|t| json!({ "namespace": t["namespace"], "name": t["name"] }))
            .collect();
        Answer::Raw(
            StatusCode::OK,
            Some(
                json!({ "identifiers": identifiers, "next-page-token": page["continuationToken"] }),
            ),
        )
    }

    /// The table, if the request may load it: `s3tables:GetTableMetadataLocation`
    /// and `s3tables:GetTableData` on it.
    async fn readable(
        &mut self,
        arn: &str,
        namespace: &str,
        name: &str,
    ) -> Result<(TableBucket, Table), Answer> {
        let (bucket, table) = self
            .checked_table(
                arn,
                namespace,
                name,
                "s3tables:GetTableMetadataLocation",
                &Context::default(),
            )
            .await
            .map_err(|e| from_tables(e, "BadRequestException"))?;
        self.check(
            "s3tables:GetTableData",
            &Target::Table {
                bucket: &bucket,
                table: &table,
            },
            &Context::default(),
        )
        .map_err(|e| from_tables(e, "BadRequestException"))?;
        Ok((bucket, table))
    }

    /// A table's current metadata, if it has any.
    async fn current(&self, table: &Table) -> Result<Option<TableMetadata>, Answer> {
        let Some(location) = &table.metadata_location else {
            return Ok(None);
        };
        let read = super::read(self.app, table, Some(self.principal.id), location)
            .await
            .map_err(|e| from_tables(e.into(), ""))?;
        let current = read.map_err(from_file)?;
        Ok(Some(current))
    }

    async fn load_table(&mut self, arn: &str, namespace: &str, name: &str) -> Answer {
        let (_, table) = or_answer!(self.readable(arn, namespace, name).await, |e| e);
        match self.current(&table).await {
            Ok(Some(metadata)) => Answer::Raw(
                StatusCode::OK,
                Some(load_result(
                    table.metadata_location.as_deref().unwrap_or(""),
                    &metadata,
                )),
            ),
            Ok(None) => rest_error(
                StatusCode::NOT_FOUND,
                "NoSuchTableException",
                format!("Table {namespace}.{name} has no metadata yet: its first commit makes it."),
            ),
            Err(e) => e,
        }
    }

    async fn create_table_rest(&mut self, arn: &str, namespace: &str, body: &[u8]) -> Answer {
        let body = or_answer!(body_of(body), |e| e);
        let Some(name) = body.get("name").and_then(Value::as_str).map(str::to_owned) else {
            return bad_request("A table's name is required.");
        };
        if body.get("stage-create").and_then(Value::as_bool) == Some(true) {
            return bad_request("S3 Tables doesn't take staged creates.");
        }
        if body.get("location").is_some_and(|l| !l.is_null()) {
            return bad_request("A table's location is its own storage, which S3 Tables chooses.");
        }
        let Some(schema) = body.get("schema").filter(|s| s.is_object()).cloned() else {
            return bad_request("A table's schema is required.");
        };
        let properties = match body.get("properties") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(p)) => p.clone(),
            Some(_) => return bad_request("properties must be a map."),
        };
        let creation = Creation {
            schema,
            partition_spec: body.get("partition-spec").filter(|v| !v.is_null()).cloned(),
            write_order: body.get("write-order").filter(|v| !v.is_null()).cloned(),
            properties,
        };
        match self
            .create_with_metadata(arn, namespace, &name, &creation, None)
            .await
        {
            Ok((_, location, metadata)) => {
                Answer::Raw(StatusCode::OK, Some(load_result(&location, &metadata)))
            }
            Err(answer) => answer,
        }
    }

    /// Makes table `name` in `namespace` of the table bucket `arn` (as
    /// CreateTable does, with `input`'s settings if given), and its first
    /// metadata file, from `creation`; checked as `s3tables:PutTableData`
    /// too. Its ARN, metadata location and metadata.
    pub(crate) async fn create_with_metadata(
        &mut self,
        arn: &str,
        namespace: &str,
        name: &str,
        creation: &Creation,
        input: Option<&Input>,
    ) -> Result<(String, String, TableMetadata), Answer> {
        // What it's made with is checked before it's made.
        let check = super::new_table(creation, "s3://check");
        check.map_err(from_failure)?;
        let (account, bucket_name, bucket) = self
            .bucket_of(arn)
            .await
            .map_err(|e| from_tables(e, "BadRequestException"))?;
        let target = match &bucket {
            Some(bucket) => Target::NoTable {
                bucket,
                namespace,
                name,
            },
            None => Target::Bucket {
                account: &account,
                name: &bucket_name,
                bucket: None,
                namespace: Some(namespace),
            },
        };
        let mut extra = Context::default();
        extra.set("s3tables:tableName", name);
        self.check("s3tables:PutTableData", &target, &extra)
            .map_err(|e| from_tables(e, "BadRequestException"))?;
        let mut input = input.map(|i| i.0.clone()).unwrap_or_default();
        input.insert("name".into(), json!(name));
        input.insert("format".into(), json!("ICEBERG"));
        input.remove("metadata");
        let created = self
            .create_table_plain(arn, namespace, &Input(input))
            .await
            .map_err(|e| from_tables(e, "AlreadyExistsException"))?;
        let created = json_of(created);
        let table_arn = created["tableARN"].as_str().unwrap_or("").to_owned();
        let token = created["versionToken"].as_str().unwrap_or("").to_owned();
        let bucket = bucket.ok_or_else(|| from_tables(crate::tables::no_bucket(), ""))?;
        let Some(table) = Table::load(&self.client, bucket.id, namespace, name, false)
            .await
            .map_err(|e| from_tables(e.into(), ""))?
        else {
            return Err(commit_failed("The table was deleted as it was made."));
        };
        let location = table.warehouse_location();
        let built = super::new_table(creation, &location).map_err(from_failure)?;
        let file = super::next_file(&location, None, &Uuid::new_v4().to_string());
        match self.swap(&table, &token, &file, &built).await {
            Ok(()) => Ok((table_arn, file, built)),
            Err(answer) => {
                // Not left half made: it goes, as it came.
                let _ = self
                    .client
                    .execute("DELETE FROM tables WHERE id = $1", &[&table.id])
                    .await;
                Err(answer)
            }
        }
    }

    /// Writes `metadata` to `file` in `table`'s storage, and points the
    /// table at it, if its version token is still `token`.
    async fn swap(
        &mut self,
        table: &Table,
        token: &str,
        file: &str,
        metadata: &TableMetadata,
    ) -> Result<(), Answer> {
        let written = super::write(self.app, table, Some(self.principal.id), file, metadata)
            .await
            .map_err(|e| from_tables(e.into(), ""))?;
        written.map_err(from_file)?;
        let new_token = crate::tables::version_token();
        let row = self
            .client
            .query_opt(
                "UPDATE tables SET metadata_location = $3, version_token = $4, modified_at = now(),
                        modified_by = $5
                 WHERE id = $1 AND version_token = $2 RETURNING id",
                &[
                    &table.id,
                    &token,
                    &file,
                    &new_token,
                    &self.principal.account,
                ],
            )
            .await
            .map_err(|e| from_tables(e.into(), ""))?;
        match row {
            Some(_) => Ok(()),
            None => Err(commit_failed(
                "The table was changed by another commit: retry against its new metadata.",
            )),
        }
    }

    async fn commit(&mut self, arn: &str, namespace: &str, name: &str, body: &[u8]) -> Answer {
        let body = or_answer!(body_of(body), |e| e);
        let requirements = body
            .get("requirements")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let updates = body
            .get("updates")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let checked = self
            .checked_table(
                arn,
                namespace,
                name,
                "s3tables:UpdateTableMetadataLocation",
                &Context::default(),
            )
            .await;
        let (bucket, table) = or_answer!(checked, |e| from_tables(e, "CommitFailedException"));
        for action in ["s3tables:PutTableData", "s3tables:GetTableData"] {
            let checked = self.check(
                action,
                &Target::Table {
                    bucket: &bucket,
                    table: &table,
                },
                &Context::default(),
            );
            or_answer!(checked, |e| from_tables(e, "CommitFailedException"));
        }
        let current = or_answer!(self.current(&table).await, |e| e);
        let requirements: Vec<TableRequirement> = or_answer!(
            serde_json::from_value(Value::Array(requirements)),
            |e: serde_json::Error| bad_request(format!("The commit's requirements aren't: {e}"))
        );
        let updates: Vec<TableUpdate> = or_answer!(
            serde_json::from_value(Value::Array(updates)),
            |e: serde_json::Error| bad_request(format!("The commit's updates aren't: {e}"))
        );
        for requirement in &requirements {
            or_answer!(requirement.check(current.as_ref()), |e: iceberg::Error| {
                from_failure(e.into())
            });
        }
        let (Some(current), Some(previous)) = (current, table.metadata_location.clone()) else {
            return bad_request(
                "The table has no metadata yet: create it through the catalog, or give it its \
                 first metadata file with UpdateTableMetadataLocation.",
            );
        };
        if !super::supported(current.format_version()) {
            return bad_request(format!(
                "The table's format version {} isn't supported: 2 or 3 only.",
                current.format_version()
            ));
        }
        let mut builder =
            TableMetadataBuilder::new_from_metadata(current.clone(), Some(previous.clone()));
        for update in updates {
            builder = or_answer!(update.apply(builder), |e: iceberg::Error| from_failure(
                e.into()
            ));
        }
        let built = or_answer!(builder.build(), |e: iceberg::Error| from_failure(e.into()));
        if built.changes.is_empty() {
            return Answer::Raw(
                StatusCode::OK,
                Some(json!({ "metadata-location": previous, "metadata": current })),
            );
        }
        let built = built.metadata;
        let location = table.warehouse_location();
        if built.location() != location {
            return bad_request("A table's location is its storage's, which can't be changed.");
        }
        if !super::supported(built.format_version()) {
            return bad_request("Tables' format versions are 2 or 3 only.");
        }
        let file = super::next_file(&location, Some(&previous), &Uuid::new_v4().to_string());
        or_answer!(
            self.swap(&table, &table.version_token, &file, &built).await,
            |e| e
        );
        Answer::Raw(
            StatusCode::OK,
            Some(json!({ "metadata-location": file, "metadata": built })),
        )
    }

    async fn rename_rest(&mut self, arn: &str, body: &[u8]) -> Answer {
        let body = or_answer!(body_of(body), |e| e);
        let (Some(source), Some(destination)) = (body.get("source"), body.get("destination"))
        else {
            return bad_request("A rename needs a source and a destination.");
        };
        let from_namespace = or_answer!(single_of(source.get("namespace")), |e| e);
        let to_namespace = or_answer!(single_of(destination.get("namespace")), |e| e);
        let (Some(from), Some(to)) = (
            source.get("name").and_then(Value::as_str),
            destination.get("name").and_then(Value::as_str),
        ) else {
            return bad_request("A rename's source and destination need names.");
        };
        let input = Input(
            json!({ "newNamespaceName": to_namespace, "newName": to })
                .as_object()
                .cloned()
                .expect("an object"),
        );
        match self.rename_table(arn, &from_namespace, from, &input).await {
            Ok(_) => Answer::Raw(StatusCode::NO_CONTENT, None),
            Err(e) => from_tables(e, "AlreadyExistsException"),
        }
    }
}

/// An Iceberg page's query (`pageToken`, `pageSize`) as S3 Tables' (its
/// continuation token, and `max`).
fn page_query(query: &str, max: &str) -> String {
    let q = |name: &str| crate::s3::util::query_param(query, name);
    let mut out = Vec::new();
    if let Some(token) = q("pageToken").filter(|t| !t.is_empty()) {
        out.push(format!("continuationToken={}", encode(&token)));
    }
    if let Some(size) = q("pageSize") {
        out.push(format!("{max}={}", encode(&size)));
    }
    out.join("&")
}

/// The metadata CreateTable's `metadata` (S3 Tables' `TableMetadata`, its
/// `iceberg`) asks for, as a creation.
pub(crate) fn creation_of(metadata: &Value) -> Result<Creation, String> {
    let iceberg = metadata
        .get("iceberg")
        .filter(|v| v.is_object())
        .ok_or("metadata needs iceberg.")?;
    let schema = match (iceberg.get("schemaV2"), iceberg.get("schema")) {
        (Some(v2), _) if v2.is_object() => {
            let mut schema = json!({ "type": "struct", "fields": v2.get("fields").cloned().unwrap_or(json!([])) });
            if let Some(ids) = v2.get("identifierFieldIds") {
                schema["identifier-field-ids"] = ids.clone();
            }
            schema
        }
        (_, Some(v1)) if v1.is_object() => {
            // Primitive fields, with IDs given or not.
            let fields: Vec<Value> = v1
                .get("fields")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .enumerate()
                .map(|(i, f)| {
                    json!({
                        "id": f.get("id").and_then(Value::as_i64).unwrap_or(i as i64 + 1),
                        "name": f.get("name").cloned().unwrap_or(Value::Null),
                        "type": f.get("type").cloned().unwrap_or(Value::Null),
                        "required": f.get("required").and_then(Value::as_bool).unwrap_or(false),
                    })
                })
                .collect();
            json!({ "type": "struct", "fields": fields })
        }
        _ => return Err("metadata's iceberg needs a schema.".into()),
    };
    let properties = match iceberg.get("properties") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(p)) => p.clone(),
        Some(_) => return Err("properties must be a map.".into()),
    };
    Ok(Creation {
        schema,
        // S3 Tables' shapes, as Iceberg's (its IDs in camel case).
        partition_spec: iceberg
            .get("partitionSpec")
            .filter(|v| v.is_object())
            .map(|spec| {
                let mut spec =
                    json!({ "fields": spec.get("fields").cloned().unwrap_or(json!([])) });
                if let Some(id) = iceberg["partitionSpec"].get("specId") {
                    spec["spec-id"] = id.clone();
                }
                spec
            }),
        write_order: iceberg
            .get("writeOrder")
            .filter(|v| v.is_object())
            .map(|order| {
                let mut out =
                    json!({ "fields": order.get("fields").cloned().unwrap_or(json!([])) });
                if let Some(id) = order.get("orderId") {
                    out["order-id"] = id.clone();
                }
                out
            }),
        properties,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_tables_metadata() {
        let creation = creation_of(&json!({ "iceberg": { "schema": { "fields": [
            { "name": "id", "type": "long", "required": true },
            { "name": "name", "type": "string" },
        ]}, "partitionSpec": { "fields": [{ "source-id": 1, "transform": "bucket[4]", "name": "b" }] } } }))
        .unwrap();
        let m =
            serde_json::to_value(super::super::new_table(&creation, "s3://t").unwrap()).unwrap();
        assert_eq!(m["schemas"][0]["fields"][1]["id"], 2);
        assert_eq!(m["partition-specs"][0]["fields"][0]["source-id"], 1);
        assert!(creation_of(&json!({})).is_err());
    }

    #[test]
    fn pages() {
        assert_eq!(
            page_query("pageToken=abc&pageSize=10", "maxTables"),
            "continuationToken=abc&maxTables=10"
        );
        assert_eq!(page_query("", "maxTables"), "");
    }

    #[test]
    fn namespaces() {
        assert!(single("a\u{1f}b").is_err());
        assert_eq!(single_of(Some(&json!(["a"]))).unwrap(), "a");
        assert!(single_of(Some(&json!(["a", "b"]))).is_err());
    }
}
