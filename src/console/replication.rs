//! The console's API for buckets' replication (see `replication`,
//! `s3::buckets::replication`): a bucket's configuration, read in a form of
//! the console's and set and deleted through S3's own handlers, as the
//! session's identity, so it's checked as PutBucketReplication checks it
//! (`iam:PassRole` on its role too); what's queued for its destinations; the
//! remotes a rule can name; and what's queued of a key's versions.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::actor::Actor;
use super::manage::{AppState, Result, Tag, s3_error};
use super::web::{ApiError, ErrorBody};
use crate::{
    App,
    db::Cached,
    replication::config::{Configuration, Destination, Filter, Rule},
    s3::{
        actions::{Check, On},
        util::xml_escape,
    },
};

/// How many of a key's queued versions are listed.
const MAX_QUEUED: i64 = 200;

pub(super) fn router() -> OpenApiRouter<Arc<App>> {
    OpenApiRouter::new()
        .routes(routes!(
            get_replication,
            put_replication,
            delete_replication
        ))
        .routes(routes!(list_bucket_replication_remotes))
        .routes(routes!(list_replication_queue))
}

/// A replication configuration, as the console edits it.
#[derive(Serialize, Deserialize, ToSchema)]
struct ReplicationForm {
    /// The IAM role it replicates as, by its ARN: the bucket's account's.
    role: String,
    rules: Vec<ReplicationRuleForm>,
}

/// One of its rules.
#[derive(Serialize, Deserialize, ToSchema)]
struct ReplicationRuleForm {
    /// Made up if empty.
    #[serde(default)]
    id: String,
    /// Which rule decides where rules overlap: the highest. Ignored for a
    /// rule of S3's first schema (`legacy`).
    #[serde(default)]
    priority: Option<i32>,
    enabled: bool,
    /// A rule of S3's first schema: a prefix of its own, no filter by tags,
    /// no priority, and it replicates delete markers. A configuration's
    /// rules are all of one schema.
    #[serde(default)]
    legacy: bool,
    /// Only keys with this prefix (empty: all).
    #[serde(default)]
    prefix: String,
    /// Tags a version must have, with these values.
    #[serde(default)]
    tags: Vec<Tag>,
    /// Whether delete markers are replicated (`DeleteMarkerReplication`);
    /// not with tags.
    #[serde(default)]
    delete_markers: bool,
    /// Whether deletions of versions, by their IDs, are replicated: MinIO's
    /// `DeleteReplication`, which S3 hasn't.
    #[serde(default)]
    delete_versions: bool,
    /// Whether SSE-KMS objects are replicated (`SseKmsEncryptedObjects`),
    /// which needs the destination's `kms_key`.
    #[serde(default)]
    kms_objects: bool,
    /// `ReplicaModifications`, if it's given: kept, without effect.
    #[serde(default)]
    replica_modifications: Option<bool>,
    destination: ReplicationDestinationForm,
}

/// Where a rule replicates to.
#[derive(Serialize, Deserialize, ToSchema)]
struct ReplicationDestinationForm {
    /// The bucket, by its name.
    bucket: String,
    /// The remote (`cairn remote`) the bucket is on, if it isn't in this
    /// cluster.
    #[serde(default)]
    remote: Option<String>,
    /// The ARN a remote bucket was named by, if MinIO's or RustFS's form:
    /// kept while it names the same remote and bucket.
    #[serde(default)]
    arn: Option<String>,
    /// The account that must own the bucket, if it's to be checked.
    #[serde(default)]
    account: Option<String>,
    /// The storage class replicas are stored in, if not their source's.
    #[serde(default)]
    storage_class: Option<String>,
    /// Whether replicas are owned by the bucket's owner
    /// (`AccessControlTranslation`), which needs `account`.
    #[serde(default)]
    owner_override: bool,
    /// The KMS key SSE-KMS replicas are encrypted under (`<mount>/<key>`,
    /// or its ARN).
    #[serde(default)]
    kms_key: Option<String>,
}

/// What's queued for one of a bucket's destinations.
#[derive(Serialize, ToSchema)]
struct ReplicationBacklog {
    /// The bucket, by its name, or `<remote>:<bucket>`.
    destination: String,
    /// Versions, delete markers and deletions waiting to be replicated.
    queued: i64,
    /// Of them, those that failed for what may pass, and wait to be tried
    /// again.
    retrying: i64,
    /// When the oldest was queued.
    oldest: Option<f64>,
    /// The latest failure of one that's retrying.
    failure: Option<String>,
}

/// A bucket's replication configuration, and what's queued.
#[derive(Serialize, ToSchema)]
struct BucketReplication {
    /// `null` if it has none.
    configuration: Option<ReplicationForm>,
    /// What's queued, by destination (whatever names them now).
    backlog: Vec<ReplicationBacklog>,
}

fn form_of(config: Configuration) -> ReplicationForm {
    ReplicationForm {
        role: config.role,
        rules: config.rules.into_iter().map(rule_form).collect(),
    }
}

fn rule_form(rule: Rule) -> ReplicationRuleForm {
    let Destination {
        bucket,
        remote,
        arn,
        account,
        storage_class,
        owner_override,
        kms_key,
        ..
    } = rule.destination;
    ReplicationRuleForm {
        id: rule.id,
        priority: rule.priority,
        enabled: rule.enabled,
        legacy: rule.filter == Filter::Legacy,
        prefix: rule.prefix,
        tags: rule
            .tags
            .into_iter()
            .map(|(key, value)| Tag { key, value })
            .collect(),
        delete_markers: rule.delete_markers,
        delete_versions: rule.delete_versions,
        kms_objects: rule.kms_objects,
        replica_modifications: rule.replica_modifications,
        destination: ReplicationDestinationForm {
            bucket,
            remote,
            arn,
            account,
            storage_class,
            owner_override,
            kms_key,
        },
    }
}

fn status(enabled: bool) -> &'static str {
    if enabled { "Enabled" } else { "Disabled" }
}

/// Some non-empty text, trimmed.
fn given(value: &Option<String>) -> Option<&str> {
    value.as_deref().map(str::trim).filter(|v| !v.is_empty())
}

/// The form as S3's PutBucketReplication takes it, which checks it.
fn xml_of(form: &ReplicationForm) -> String {
    let mut xml = format!(
        "<ReplicationConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Role>{}</Role>",
        xml_escape(form.role.trim())
    );
    for rule in &form.rules {
        xml.push_str("<Rule>");
        if !rule.id.trim().is_empty() {
            xml.push_str(&format!("<ID>{}</ID>", xml_escape(rule.id.trim())));
        }
        let tag = |t: &Tag| {
            format!(
                "<Tag><Key>{}</Key><Value>{}</Value></Tag>",
                xml_escape(&t.key),
                xml_escape(&t.value)
            )
        };
        if rule.legacy {
            xml.push_str(&format!("<Prefix>{}</Prefix>", xml_escape(&rule.prefix)));
        } else {
            xml.push_str(&format!(
                "<Priority>{}</Priority>",
                rule.priority.unwrap_or(0)
            ));
            let tags: String = rule.tags.iter().map(tag).collect();
            match (rule.prefix.is_empty(), rule.tags.len()) {
                (true, 0) => xml.push_str("<Filter/>"),
                (false, 0) => xml.push_str(&format!(
                    "<Filter><Prefix>{}</Prefix></Filter>",
                    xml_escape(&rule.prefix)
                )),
                (true, 1) => xml.push_str(&format!("<Filter>{tags}</Filter>")),
                (true, _) => xml.push_str(&format!("<Filter><And>{tags}</And></Filter>")),
                (false, _) => xml.push_str(&format!(
                    "<Filter><And><Prefix>{}</Prefix>{tags}</And></Filter>",
                    xml_escape(&rule.prefix)
                )),
            }
        }
        xml.push_str(&format!("<Status>{}</Status>", status(rule.enabled)));
        if rule.kms_objects || rule.replica_modifications.is_some() {
            xml.push_str("<SourceSelectionCriteria>");
            if rule.kms_objects {
                xml.push_str(
                    "<SseKmsEncryptedObjects><Status>Enabled</Status></SseKmsEncryptedObjects>",
                );
            }
            if let Some(modifications) = rule.replica_modifications {
                xml.push_str(&format!(
                    "<ReplicaModifications><Status>{}</Status></ReplicaModifications>",
                    status(modifications)
                ));
            }
            xml.push_str("</SourceSelectionCriteria>");
        }
        push_destination(&mut xml, &rule.destination);
        if !rule.legacy {
            xml.push_str(&format!(
                "<DeleteMarkerReplication><Status>{}</Status></DeleteMarkerReplication>",
                status(rule.delete_markers)
            ));
        }
        if rule.delete_versions {
            xml.push_str("<DeleteReplication><Status>Enabled</Status></DeleteReplication>");
        }
        xml.push_str("</Rule>");
    }
    xml.push_str("</ReplicationConfiguration>");
    xml
}

fn push_destination(xml: &mut String, d: &ReplicationDestinationForm) {
    let bucket = d.bucket.trim();
    let arn = match given(&d.remote) {
        None => format!("arn:aws:s3:::{bucket}"),
        // MinIO's form, as it was given, while it names the same bucket.
        Some(remote) => match &d.arn {
            Some(arn)
                if arn.starts_with("arn:") && arn.ends_with(&format!(":{remote}:{bucket}")) =>
            {
                arn.clone()
            }
            _ => format!("arn:cairn:replication::{remote}:{bucket}"),
        },
    };
    xml.push_str(&format!(
        "<Destination><Bucket>{}</Bucket>",
        xml_escape(&arn)
    ));
    if let Some(account) = given(&d.account) {
        xml.push_str(&format!("<Account>{}</Account>", xml_escape(account)));
    }
    if let Some(class) = given(&d.storage_class) {
        xml.push_str(&format!(
            "<StorageClass>{}</StorageClass>",
            xml_escape(class)
        ));
    }
    if d.owner_override {
        xml.push_str(
            "<AccessControlTranslation><Owner>Destination</Owner></AccessControlTranslation>",
        );
    }
    if let Some(key) = given(&d.kms_key) {
        xml.push_str(&format!(
            "<EncryptionConfiguration><ReplicaKmsKeyID>{}</ReplicaKmsKeyID></EncryptionConfiguration>",
            xml_escape(key)
        ));
    }
    xml.push_str("</Destination>");
}

/// A bucket's replication configuration, and what's queued for its
/// destinations.
#[utoipa::path(get, path = "/buckets/{bucket}/replication", params(("bucket" = String, Path)), responses(
    (status = 200, body = BucketReplication),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn get_replication(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
) -> Result<Json<BucketReplication>> {
    actor
        .check(
            &app,
            "s3:GetReplicationConfiguration",
            On::Bucket(bucket.clone()),
        )
        .await?;
    let configuration = crate::s3::buckets::replication::load(&app, &bucket)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("no bucket named {bucket:?}")))?;
    let backlog = app
        .pool
        .get()
        .await?
        .query_cached(
            "SELECT destination, count(*), count(*) FILTER (WHERE failure IS NOT NULL),
                    extract(epoch FROM min(created_at))::float8,
                    (array_agg(failure ORDER BY next_at DESC) FILTER (WHERE failure IS NOT NULL))[1]
             FROM replication_queue WHERE bucket = $1
             GROUP BY destination ORDER BY destination",
            &[&bucket],
        )
        .await?
        .iter()
        .map(|r| ReplicationBacklog {
            destination: r.get(0),
            queued: r.get(1),
            retrying: r.get(2),
            oldest: r.get(3),
            failure: r.get(4),
        })
        .collect();
    Ok(Json(BucketReplication {
        configuration: configuration.map(form_of),
        backlog,
    }))
}

/// Sets a bucket's replication configuration, checked as
/// PutBucketReplication checks it: the bucket and its destinations must be
/// versioned, a remote's bucket is asked there, and the caller must be
/// allowed to pass the role (`iam:PassRole`).
#[utoipa::path(put, path = "/buckets/{bucket}/replication", params(("bucket" = String, Path)),
    request_body = ReplicationForm, responses(
        (status = 204, description = "Set"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn put_replication(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Json(form): Json<ReplicationForm>,
) -> Result<StatusCode> {
    actor
        .check(
            &app,
            "s3:PutReplicationConfiguration",
            On::Bucket(bucket.clone()),
        )
        .await?;
    // S3's handler checks `iam:PassRole`, as the session's identity.
    let access = actor.access_for(&app).await?;
    let resp =
        crate::s3::buckets::replication::put(&app, &bucket, xml_of(&form).into(), &access).await?;
    match resp.status() {
        s if s.is_success() => Ok(StatusCode::NO_CONTENT),
        _ => Err(s3_error(resp).await),
    }
}

/// Removes a bucket's replication configuration: nothing more is queued,
/// and what's queued fails.
#[utoipa::path(delete, path = "/buckets/{bucket}/replication", params(("bucket" = String, Path)), responses(
    (status = 204, description = "Removed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_replication(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
) -> Result<StatusCode> {
    // DeleteBucketReplication is authorized as its put, in S3.
    actor
        .check(
            &app,
            "s3:PutReplicationConfiguration",
            On::Bucket(bucket.clone()),
        )
        .await?;
    let resp = crate::s3::buckets::replication::delete(&app, &bucket).await?;
    match resp.status() {
        s if s.is_success() => Ok(StatusCode::NO_CONTENT),
        _ => Err(s3_error(resp).await),
    }
}

/// A registered remote, as a rule names it: never its endpoint or
/// credentials.
#[derive(Serialize, ToSchema)]
struct ReplicationRemote {
    name: String,
    /// `cairn`, `minio` or `rustfs`.
    kind: String,
}

/// The remotes (`cairn remote`) the bucket's rules can name, to whom may
/// set its configuration: PutBucketReplication's errors tell them which
/// remotes there are anyway ("There's no remote …").
#[utoipa::path(get, path = "/buckets/{bucket}/replication/remotes", params(("bucket" = String, Path)), responses(
    (status = 200, body = Vec<ReplicationRemote>),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn list_bucket_replication_remotes(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
) -> Result<Json<Vec<ReplicationRemote>>> {
    actor
        .check(
            &app,
            "s3:PutReplicationConfiguration",
            On::Bucket(bucket.clone()),
        )
        .await?;
    let remotes = app
        .pool
        .get()
        .await?
        .query_cached(
            "SELECT name, kind FROM replication_remotes ORDER BY name",
            &[],
        )
        .await?
        .iter()
        .map(|r| ReplicationRemote {
            name: r.get(0),
            kind: r.get(1),
        })
        .collect();
    Ok(Json(remotes))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct QueueParams {
    key: String,
}

/// A version of a key queued for one of its destinations.
#[derive(Serialize, ToSchema)]
struct QueuedReplication {
    version_id: String,
    /// The bucket, by its name, or `<remote>:<bucket>`.
    destination: String,
    rule_id: String,
    /// Whether it's a delete marker.
    marker: bool,
    /// Whether it's a deletion of the version (`DeleteReplication`).
    purge: bool,
    /// How many times it was taken to be replicated.
    attempts: i32,
    /// Why it failed last, if it did, for what may pass.
    failure: Option<String>,
    /// When it's next tried.
    next_at: f64,
}

/// What's queued of a key's versions, by destination: to whom may read the
/// object and its bucket's replication configuration, which names the
/// destinations; older versions' only to whom may list them.
#[utoipa::path(get, path = "/buckets/{bucket}/replication/queue", params(("bucket" = String, Path), QueueParams),
    responses(
        (status = 200, body = Vec<QueuedReplication>),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn list_replication_queue(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Query(params): Query<QueueParams>,
) -> Result<Json<Vec<QueuedReplication>>> {
    let key = params.key;
    actor
        .check_all(
            &app,
            &[
                Check {
                    action: "s3:GetObject",
                    on: On::Object(bucket.clone(), key.clone()),
                },
                Check {
                    action: "s3:GetReplicationConfiguration",
                    on: On::Bucket(bucket.clone()),
                },
            ],
        )
        .await?;
    let all = actor
        .allows(&app, "s3:ListBucketVersions", On::Bucket(bucket.clone()))
        .await?;
    let rows = app
        .pool
        .get()
        .await?
        .query_cached(
            "SELECT q.version_id, q.destination, q.rule_id, q.marker, q.purge, q.attempt, q.failure,
                    extract(epoch FROM q.next_at)::float8
             FROM replication_queue q
             WHERE q.bucket = $1 AND q.key = $2
               AND ($3 OR q.version_id = (SELECT version_id FROM objects
                                          WHERE bucket = $1 AND key = $2 AND is_latest))
             ORDER BY q.seq LIMIT $4",
            &[&bucket, &key, &all, &MAX_QUEUED],
        )
        .await?;
    Ok(Json(
        rows.iter()
            .map(|r| QueuedReplication {
                version_id: r.get(0),
                destination: r.get(1),
                rule_id: r.get(2),
                marker: r.get(3),
                purge: r.get(4),
                attempts: r.get(5),
                failure: r.get(6),
                next_at: r.get(7),
            })
            .collect(),
    ))
}

#[cfg(test)]
mod e2e {
    use axum::http::StatusCode;
    use hyper::body::Bytes;
    use serde_json::{Value, json};

    use super::super::e2e::{console_of, signed_in};
    use crate::{App, e2e::BUCKET, roles, users};

    /// The destination bucket in the cluster.
    const BACKUP: &str = "backup";

    async fn versioning(app: &App, bucket: &str) {
        let body = "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";
        let resp = crate::s3::buckets::versioning::put_bucket_versioning(
            app,
            bucket,
            Bytes::from(body),
            crate::mfa::Presented::Absent,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// The role replication acts as, trusting S3: its ARN.
    async fn role(app: &App) -> String {
        let client = app.pool.get().await.unwrap();
        let account = users::account(&client).await.unwrap();
        let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"s3.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
        let trust = roles::check_trust(&client, &account, trust).await.unwrap();
        let new = roles::New {
            name: "replication",
            path: "/",
            trust: &trust,
            description: "",
            max_session_duration: 3600,
            boundary: None,
            tags: &[],
        };
        roles::create(&client, &account, &new).await.unwrap();
        format!("arn:aws:iam::{account}:role/replication")
    }

    fn rule(id: &str, priority: i32, destination: Value) -> Value {
        json!({
            "id": id,
            "priority": priority,
            "enabled": true,
            "prefix": "docs/",
            "tags": [],
            "delete_markers": true,
            "delete_versions": false,
            "kms_objects": false,
            "destination": destination,
        })
    }

    /// A bucket's replication configuration, set, read and removed on the
    /// console, checked as PutBucketReplication checks it (`iam:PassRole`
    /// too); what's queued, by destination and of a key's versions; and a
    /// rule to a bucket of a registered remote.
    #[tokio::test]
    async fn edits_replication() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = console_of(&app);
        let client = app.pool.get().await.unwrap();
        let account = users::account(&client).await.unwrap();
        client
            .execute("INSERT INTO buckets (name) VALUES ($1)", &[&BACKUP])
            .await
            .unwrap();
        let role = role(&app).await;
        let mut admin = signed_in(&console, "admin", true).await;
        let mut nobody = signed_in(&console, "nobody", false).await;
        // May set configurations, but not pass roles.
        let mut setter = signed_in(&console, "setter", false).await;
        users::put_policy(
            &client,
            &account,
            "setter",
            "p",
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#,
        )
        .await
        .unwrap();

        let path = format!("/api/buckets/{BUCKET}/replication");
        let (status, got) = admin.send("GET", &path, None).await;
        assert_eq!(status, StatusCode::OK, "{got}");
        assert_eq!(got["configuration"], Value::Null);
        assert_eq!(got["backlog"], json!([]));
        assert_eq!(
            nobody.send("GET", &path, None).await.0,
            StatusCode::FORBIDDEN
        );

        let form = json!({ "role": role, "rules": [rule("docs", 1, json!({ "bucket": BACKUP }))] });
        // The bucket must be versioned, as S3 says.
        let (status, err) = admin.send("PUT", &path, Some(form.clone())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
        assert!(
            err["error"].as_str().unwrap().contains("Versioning"),
            "{err}"
        );
        versioning(&app, BUCKET).await;
        // So must the destination.
        let (status, err) = admin.send("PUT", &path, Some(form.clone())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
        assert!(
            err["error"].as_str().unwrap().contains("versioning"),
            "{err}"
        );
        versioning(&app, BACKUP).await;
        assert_eq!(
            nobody.send("PUT", &path, Some(form.clone())).await.0,
            StatusCode::FORBIDDEN
        );
        let (status, err) = setter.send("PUT", &path, Some(form.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{err}");
        assert!(
            err["error"].as_str().unwrap().contains("iam:PassRole"),
            "{err}"
        );
        // Two rules of one priority.
        let twins = json!({ "role": role, "rules": [
            rule("a", 1, json!({ "bucket": BACKUP })),
            rule("b", 1, json!({ "bucket": BACKUP })),
        ] });
        let (status, err) = admin.send("PUT", &path, Some(twins)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
        let (status, err) = admin.send("PUT", &path, Some(form)).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
        let (_, got) = admin.send("GET", &path, None).await;
        let configuration = &got["configuration"];
        assert_eq!(configuration["role"], role);
        let rule0 = &configuration["rules"][0];
        assert_eq!(rule0["id"], "docs");
        assert_eq!(rule0["priority"], 1);
        assert_eq!(rule0["prefix"], "docs/");
        assert_eq!(rule0["legacy"], false);
        assert_eq!(rule0["delete_markers"], true);
        assert_eq!(rule0["destination"]["bucket"], BACKUP);
        assert_eq!(rule0["destination"]["remote"], Value::Null);

        // A write is queued, PENDING until it's replicated.
        crate::e2e::put(&app, "docs/a", b"a".to_vec()).await;
        let (_, got) = admin.send("GET", &path, None).await;
        assert_eq!(got["backlog"][0]["destination"], BACKUP);
        assert_eq!(got["backlog"][0]["queued"], 1);
        let (_, info) = admin
            .send(
                "GET",
                &format!("/api/buckets/{BUCKET}/object?key=docs/a"),
                None,
            )
            .await;
        assert_eq!(info["versions"][0]["replication_status"], "PENDING");
        let queue = format!("/api/buckets/{BUCKET}/replication/queue?key=docs/a");
        let (status, queued) = admin.send("GET", &queue, None).await;
        assert_eq!(status, StatusCode::OK, "{queued}");
        assert_eq!(queued[0]["destination"], BACKUP);
        assert_eq!(queued[0]["rule_id"], "docs");
        assert_eq!(queued[0]["version_id"], info["versions"][0]["version_id"]);
        assert_eq!(
            nobody.send("GET", &queue, None).await.0,
            StatusCode::FORBIDDEN
        );

        // Remotes, by name and kind, to whom may set the configuration.
        let remotes = format!("/api/buckets/{BUCKET}/replication/remotes");
        let (status, listed) = admin.send("GET", &remotes, None).await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(listed, json!([]));
        assert_eq!(
            nobody.send("GET", &remotes, None).await.0,
            StatusCode::FORBIDDEN
        );
        let Some(other) = crate::backup::e2e::target().await else {
            return;
        };
        versioning(&other.app, BUCKET).await;
        let endpoint = format!("http://{}", other.address);
        let out = crate::admin::e2e::cairn(
            &app,
            &[
                "remote",
                "add",
                "dc2",
                "--endpoint",
                &endpoint,
                "--path-style",
                "--kind",
                "cairn",
                "--access-key-id",
                &other.key_id,
                "--secret-access-key",
                &other.secret,
            ],
        )
        .await;
        assert_eq!(out.error, None, "{}", out.stderr);
        let (_, listed) = admin.send("GET", &remotes, None).await;
        assert_eq!(listed, json!([{ "name": "dc2", "kind": "cairn" }]));
        let mut remote = rule("dc2", 2, json!({ "bucket": BUCKET, "remote": "dc2" }));
        remote["prefix"] = json!("");
        remote["delete_versions"] = json!(true);
        let form = json!({ "role": role, "rules": [rule("docs", 1, json!({ "bucket": BACKUP })), remote] });
        let (status, err) = admin.send("PUT", &path, Some(form.clone())).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
        let (_, got) = admin.send("GET", &path, None).await;
        let rule1 = &got["configuration"]["rules"][1];
        assert_eq!(rule1["destination"]["remote"], "dc2");
        assert_eq!(rule1["destination"]["bucket"], BUCKET);
        assert_eq!(rule1["delete_versions"], true);
        // A remote that isn't registered, saying so.
        let mut unknown = form;
        unknown["rules"][1]["destination"]["remote"] = json!("dc3");
        let (status, err) = admin.send("PUT", &path, Some(unknown)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
        assert!(err["error"].as_str().unwrap().contains("dc3"), "{err}");

        assert_eq!(
            nobody.send("DELETE", &path, None).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            admin.send("DELETE", &path, None).await.0,
            StatusCode::NO_CONTENT
        );
        let (_, got) = admin.send("GET", &path, None).await;
        assert_eq!(got["configuration"], Value::Null);
    }

    /// The form makes the XML S3's handler parses, which reads back as the
    /// form.
    #[test]
    fn forms_round_trip() {
        let form: super::ReplicationForm = serde_json::from_value(json!({
            "role": "arn:aws:iam::123456789012:role/r",
            "rules": [{
                "id": "a", "priority": 3, "enabled": false, "prefix": "p/",
                "tags": [{ "key": "k", "value": "v w" }],
                "delete_markers": false, "delete_versions": true, "kms_objects": true,
                "destination": {
                    "bucket": "b", "remote": "dc2", "arn": "arn:minio:replication:us-east-1:dc2:b",
                    "storage_class": "COLD", "kms_key": "alias/k",
                },
            }],
        }))
        .unwrap();
        let config =
            crate::replication::config::Configuration::parse(&super::xml_of(&form)).unwrap();
        let back = serde_json::to_value(super::form_of(config)).unwrap();
        assert_eq!(back, serde_json::to_value(&form).unwrap());
    }
}
