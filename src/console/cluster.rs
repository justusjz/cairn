//! The console's API for the cluster's configuration that the CLI has
//! (`cairn class`, `cairn tier`, `cairn remote`, `cairn backup`): storage
//! classes, remote tiers, replication remotes, and the backup. Each handler
//! calls what the CLI's command does, checked as a `cairn:` action on the
//! cluster (reads as `cairn:GetCluster`).
//!
//! Secrets go one way: a tier's, a remote's or the backup's secret access
//! key is taken, but never shown, and a change that leaves it out keeps it,
//! as long as it goes to the same endpoint, with the same access key ID.
//! The backup's key isn't shown either: it stays the CLI's (`cairn backup
//! key`), for whoever runs the cluster's hosts.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::actor::Actor;
use super::manage::{AppState, Result};
use super::web::{ApiError, ErrorBody};
use crate::backup::{self, BackupStatus, s3::Location};
use crate::replication::remote::{self, Kind, RemoteSummary};
use crate::s3::actions::On;
use crate::tiers::{self, TierSummary};
use crate::{App, classes};

pub(super) fn router() -> OpenApiRouter<Arc<App>> {
    OpenApiRouter::new()
        .routes(routes!(put_storage_class, delete_storage_class))
        .routes(routes!(list_tiers, add_tier))
        .routes(routes!(set_tier, delete_tier))
        .routes(routes!(list_replication_remotes, add_replication_remote))
        .routes(routes!(set_replication_remote, delete_replication_remote))
        .routes(routes!(get_backup, enable_backup, disable_backup))
        .routes(routes!(run_backup))
}

/// What's wrong with how things are now, after a change: for the operator
/// to see, as the CLI prints its warnings.
#[derive(Serialize, ToSchema)]
struct Warnings {
    warnings: Vec<String>,
}

/// A secret that's left out (or empty), as the forms send it.
fn given(secret: Option<String>) -> Option<String> {
    secret.filter(|s| !s.is_empty())
}

/// The credentials to change to, from a form's access key ID and secret:
/// none if neither changes. A new access key ID takes its secret.
fn credentials(
    current: &str,
    access_key_id: Option<String>,
    secret: Option<String>,
) -> Result<Option<(String, String)>> {
    let id = access_key_id
        .map(|id| id.trim().to_owned())
        .filter(|id| !id.is_empty());
    match (id, given(secret)) {
        (id, Some(secret)) => Ok(Some((id.unwrap_or_else(|| current.to_owned()), secret))),
        (Some(id), None) if id != current => Err(ApiError::BadRequest(
            "a new access key ID needs its secret access key".into(),
        )),
        _ => Ok(None),
    }
}

// ─── Storage classes ─────────────────────────────────────────────────────────

/// A storage class, as the console sets it: all of it, in a pool or a tier.
#[derive(Deserialize, ToSchema)]
struct ClassForm {
    /// The pool its data goes to: nodes' `--data-dir <pool>=<path>`.
    pool: Option<String>,
    /// The remote tier its data goes to, rather than a pool (see `/tiers`):
    /// then it goes by STANDARD's layout, and has no shards of its own.
    tier: Option<String>,
    /// Data shards its blobs over 64 MiB are erasure-coded into (1 keeps
    /// them replicated); none for the `data-shards` setting.
    data_shards: Option<u32>,
    /// Parity shards of its blobs; none for the `parity-shards` setting.
    parity_shards: Option<u32>,
    /// Its place in the classes' order, the warmest highest (STANDARD is
    /// 0); none for no place.
    rank: Option<i32>,
}

/// What a class's change came to.
#[derive(Serialize, ToSchema)]
struct ClassChanged {
    /// Its pool and layout, in words.
    description: String,
    warnings: Vec<String>,
}

/// Defines a storage class, or changes one, as `cairn class set` does. A
/// change applies to new objects within a heartbeat, and the packer
/// rewrites the class's existing data into its new pool and layout over
/// time.
#[utoipa::path(put, path = "/storage-classes/{name}", params(("name" = String, Path)),
    request_body = ClassForm, responses(
        (status = 200, body = ClassChanged),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn put_storage_class(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<ClassForm>,
) -> Result<Json<ClassChanged>> {
    actor
        .check(&app, "cairn:PutStorageClass", On::Cluster)
        .await?;
    let pool = body.pool.filter(|p| !p.is_empty());
    let tier = body.tier.filter(|t| !t.is_empty());
    if pool.is_none() && tier.is_none() {
        return Err(ApiError::BadRequest(
            "a class needs a pool or a tier".into(),
        ));
    }
    // A tier's class has no layout of its own: its shards stay as they are.
    let layout = |shards: Option<u32>| tier.is_none().then_some(shards);
    let change = classes::Change {
        data_shards: layout(body.data_shards),
        parity_shards: layout(body.parity_shards),
        rank: Some(body.rank),
        pool,
        tier,
    };
    let changed = classes::set(&app, &name, change).await?;
    forget_storage(&app).await;
    Ok(Json(ClassChanged {
        description: classes::describe(&app, &changed.class),
        warnings: changed.warnings,
    }))
}

/// Deletes a storage class that holds no data and no uploads, as `cairn
/// class delete` does. STANDARD can't be deleted.
#[utoipa::path(delete, path = "/storage-classes/{name}", params(("name" = String, Path)), responses(
    (status = 204, description = "Deleted"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_storage_class(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
) -> Result<StatusCode> {
    actor
        .check(&app, "cairn:DeleteStorageClass", On::Cluster)
        .await?;
    classes::delete(&app, &name).await?;
    forget_storage(&app).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Drops the `/storage` report this node keeps a while, which lists the
/// classes: the next is made afresh.
async fn forget_storage(app: &App) {
    *app.console.storage.lock().await = None;
}

// ─── Tiers ───────────────────────────────────────────────────────────────────

/// The remote tiers, as `cairn tier list` lists them.
#[utoipa::path(get, path = "/tiers", responses(
    (status = 200, body = Vec<TierSummary>),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn list_tiers(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
) -> Result<Json<Vec<TierSummary>>> {
    actor.check(&app, "cairn:GetCluster", On::Cluster).await?;
    Ok(Json(tiers::list(&app.pool.get().await?).await?))
}

/// A tier to add: a bucket (and a prefix of its own) of an S3 service.
#[derive(Deserialize, ToSchema)]
struct NewTier {
    /// Lowercase letters, digits, - and _.
    name: String,
    /// The S3 service's URL, e.g. `https://s3.eu-central-1.amazonaws.com`.
    endpoint: String,
    /// `us-east-1` if not given.
    region: Option<String>,
    bucket: String,
    #[serde(default)]
    prefix: String,
    /// Name the bucket in the path (`host/bucket/key`) rather than the host.
    #[serde(default)]
    path_style: bool,
    access_key_id: String,
    secret_access_key: String,
    /// The storage class its objects are written in there; none for the
    /// service's default.
    remote_class: Option<String>,
}

/// Adds a tier, as `cairn tier add` does, once it's reachable and holds
/// nothing. Its key is made and kept in the database (and so in the
/// backup), and isn't shown.
#[utoipa::path(post, path = "/tiers", request_body = NewTier, responses(
    (status = 201, description = "Added"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn add_tier(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Json(body): Json<NewTier>,
) -> Result<StatusCode> {
    actor.check(&app, "cairn:PutTier", On::Cluster).await?;
    let location = Location {
        endpoint: body.endpoint.trim().to_owned(),
        region: region(body.region),
        bucket: body.bucket.trim().to_owned(),
        prefix: body.prefix,
        path_style: body.path_style,
        access_key_id: body.access_key_id.trim().to_owned(),
        secret_access_key: body.secret_access_key,
    };
    let remote_class = body.remote_class.unwrap_or_default();
    tiers::add(
        &app.pool.get().await?,
        app.kms.as_deref(),
        &body.name,
        location,
        &remote_class,
    )
    .await?;
    Ok(StatusCode::CREATED)
}

/// A region, as the forms send it: `us-east-1` if not given.
fn region(region: Option<String>) -> String {
    region
        .map(|r| r.trim().to_owned())
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| "us-east-1".to_owned())
}

/// A change to a tier: what's left out stays as it is.
#[derive(Deserialize, ToSchema)]
struct TierForm {
    /// Whether this cluster may write to it and delete from it.
    writable: Option<bool>,
    /// The storage class new objects are written in there; empty for the
    /// service's default.
    remote_class: Option<String>,
    /// New credentials. A new access key ID takes its secret; a secret
    /// alone goes with the current ID.
    access_key_id: Option<String>,
    secret_access_key: Option<String>,
}

/// Changes a tier, as `cairn tier set` does: new credentials are checked
/// to reach it first.
#[utoipa::path(put, path = "/tiers/{name}", params(("name" = String, Path)),
    request_body = TierForm, responses(
        (status = 200, body = Warnings),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn set_tier(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<TierForm>,
) -> Result<Json<Warnings>> {
    actor.check(&app, "cairn:PutTier", On::Cluster).await?;
    let client = app.pool.get().await?;
    let Some(tier) = tiers::load(&client).await?.remove(&name) else {
        return Err(ApiError::NotFound(format!("there's no tier {name}")));
    };
    let change = tiers::TierChange {
        writable: body.writable,
        remote_class: body.remote_class.map(|c| c.trim().to_owned()),
        credentials: credentials(
            &tier.location.access_key_id,
            body.access_key_id,
            body.secret_access_key,
        )?,
    };
    let (_, warnings) = tiers::set(&client, &name, change).await?;
    Ok(Json(Warnings { warnings }))
}

/// Deletes a tier that no class keeps its data in, and that holds nothing
/// anymore, as `cairn tier delete` does.
#[utoipa::path(delete, path = "/tiers/{name}", params(("name" = String, Path)), responses(
    (status = 204, description = "Deleted"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_tier(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
) -> Result<StatusCode> {
    actor.check(&app, "cairn:DeleteTier", On::Cluster).await?;
    tiers::delete(&app.pool.get().await?, &name).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Replication remotes ─────────────────────────────────────────────────────

/// The replication remotes, and the buckets whose rules name each, as
/// `cairn remote list` lists them.
#[utoipa::path(get, path = "/replication-remotes", responses(
    (status = 200, body = Vec<RemoteSummary>),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn list_replication_remotes(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
) -> Result<Json<Vec<RemoteSummary>>> {
    actor.check(&app, "cairn:GetCluster", On::Cluster).await?;
    Ok(Json(remote::list(&app.pool.get().await?).await?))
}

/// A remote to add: another cluster's S3 endpoint, which buckets'
/// replication rules name buckets of (`arn:cairn:replication::<name>:<bucket>`).
#[derive(Deserialize, ToSchema)]
struct NewRemoteForm {
    /// Lowercase letters, digits, - and _: for a configuration written for
    /// MinIO, the ID its ARNs have.
    name: String,
    /// e.g. `https://s3.dc2.example.com`.
    endpoint: String,
    /// `us-east-1` if not given.
    region: Option<String>,
    /// Name buckets in the path (`host/bucket/key`), as MinIO and RustFS
    /// are usually set up.
    #[serde(default)]
    path_style: bool,
    /// `cairn`, `minio` or `rustfs`: Cairn takes version IDs as they are;
    /// MinIO and RustFS take UUIDs, which Cairn's IDs are sent as.
    kind: String,
    access_key_id: String,
    secret_access_key: String,
}

/// Adds a replication remote, as `cairn remote add` does.
#[utoipa::path(post, path = "/replication-remotes", request_body = NewRemoteForm, responses(
    (status = 201, description = "Added"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn add_replication_remote(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Json(body): Json<NewRemoteForm>,
) -> Result<StatusCode> {
    actor
        .check(&app, "cairn:PutReplicationRemote", On::Cluster)
        .await?;
    let Some(kind) = Kind::parse(&body.kind) else {
        return Err(ApiError::BadRequest(
            "a remote's kind is cairn, minio or rustfs".into(),
        ));
    };
    let new = remote::NewRemote {
        name: body.name,
        endpoint: body.endpoint.trim().to_owned(),
        region: region(body.region),
        path_style: body.path_style,
        kind,
        access_key_id: body.access_key_id.trim().to_owned(),
        secret_access_key: body.secret_access_key,
    };
    remote::add(&app.pool.get().await?, new).await?;
    Ok(StatusCode::CREATED)
}

/// A change to a remote: what's left out stays as it is. Its kind can't
/// change, since the version IDs it was sent are its kind's. A new endpoint
/// takes the secret access key again.
#[derive(Deserialize, ToSchema)]
struct RemoteForm {
    endpoint: Option<String>,
    region: Option<String>,
    path_style: Option<bool>,
    /// New credentials. A new access key ID takes its secret; a secret
    /// alone goes with the current ID.
    access_key_id: Option<String>,
    secret_access_key: Option<String>,
}

/// Changes a replication remote, as `cairn remote set` does.
#[utoipa::path(put, path = "/replication-remotes/{name}", params(("name" = String, Path)),
    request_body = RemoteForm, responses(
        (status = 204, description = "Changed"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn set_replication_remote(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<RemoteForm>,
) -> Result<StatusCode> {
    actor
        .check(&app, "cairn:PutReplicationRemote", On::Cluster)
        .await?;
    let client = app.pool.get().await?;
    let Some(current) = remote::list(&client)
        .await?
        .into_iter()
        .find(|r| r.name == name)
    else {
        return Err(ApiError::NotFound(format!("there's no remote {name}")));
    };
    let change = remote::RemoteChange {
        endpoint: body
            .endpoint
            .map(|e| e.trim().to_owned())
            .filter(|e| !e.is_empty()),
        region: body
            .region
            .map(|r| r.trim().to_owned())
            .filter(|r| !r.is_empty()),
        path_style: body.path_style,
        credentials: credentials(
            &current.access_key_id,
            body.access_key_id,
            body.secret_access_key,
        )?,
    };
    // The secret is kept only for the same endpoint: it doesn't sign
    // requests to somewhere else.
    let moved = change
        .endpoint
        .as_deref()
        .is_some_and(|e| e.trim_end_matches('/') != current.endpoint);
    if moved && change.credentials.is_none() {
        return Err(ApiError::BadRequest(
            "a new endpoint needs the secret access key again".into(),
        ));
    }
    remote::set(&client, &name, change).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes a replication remote that no bucket's rules name, as `cairn
/// remote delete` does.
#[utoipa::path(delete, path = "/replication-remotes/{name}", params(("name" = String, Path)), responses(
    (status = 204, description = "Deleted"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_replication_remote(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
) -> Result<StatusCode> {
    actor
        .check(&app, "cairn:DeleteReplicationRemote", On::Cluster)
        .await?;
    remote::delete(&app.pool.get().await?, &name).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Backup ──────────────────────────────────────────────────────────────────

/// The backup, if it was ever set up, and the restore this cluster came
/// from, if it did.
#[derive(Serialize, ToSchema)]
struct Backup {
    status: Option<BackupStatus>,
    restore: Option<backup::restore::RestoreStatus>,
}

/// Where the backup is, and how far it's got, as `cairn backup status`
/// says.
#[utoipa::path(get, path = "/backup", responses(
    (status = 200, body = Backup),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn get_backup(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
) -> Result<Json<Backup>> {
    actor.check(&app, "cairn:GetCluster", On::Cluster).await?;
    let client = app.pool.get().await?;
    Ok(Json(Backup {
        status: backup::status(&client).await?,
        restore: backup::restore::progress(&client).await?,
    }))
}

/// Where to back up to, and how, as `cairn backup enable` takes it.
#[derive(Deserialize, ToSchema)]
struct BackupForm {
    /// The S3 service's URL, e.g. `https://s3.eu-central-1.amazonaws.com`.
    endpoint: String,
    /// `us-east-1` if not given.
    region: Option<String>,
    /// The bucket: turn versioning on for it, so that it keeps what a
    /// mistake (or an attacker with these credentials) deletes.
    bucket: String,
    /// A prefix of the backup's own.
    #[serde(default)]
    prefix: String,
    #[serde(default)]
    path_style: bool,
    access_key_id: String,
    /// Left out (or empty) to keep the backup's, for the same endpoint and
    /// access key ID.
    secret_access_key: Option<String>,
    /// The backup's key (base64, 32 bytes), to use one of one's own;
    /// otherwise the backup keeps its key, or gets a new one.
    key: Option<String>,
    /// How often changes are shipped, e.g. `5m` (the default): the most a
    /// restore can lose.
    interval: Option<String>,
    /// How long what's no longer needed is kept, e.g. `7d` (the default).
    retention: Option<String>,
    /// How large packs of data are, e.g. `256MiB` (the default).
    pack_size: Option<String>,
}

/// What turning the backup on came to.
#[derive(Serialize, ToSchema)]
struct BackupEnabled {
    /// Where it backs up to, in words.
    location: String,
    /// Whether it made a new key, which a restore needs: `cairn backup key`
    /// on a node shows it, to keep apart from the cluster.
    new_key: bool,
}

/// Turns the backup on, or changes where to or how, as `cairn backup
/// enable` does: a new location starts a new backup, from a base.
#[utoipa::path(put, path = "/backup", request_body = BackupForm, responses(
    (status = 200, body = BackupEnabled),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn enable_backup(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Json(body): Json<BackupForm>,
) -> Result<Json<BackupEnabled>> {
    actor.check(&app, "cairn:PutBackup", On::Cluster).await?;
    let access_key_id = body.access_key_id.trim().to_owned();
    let endpoint = body.endpoint.trim().trim_end_matches('/').to_owned();
    // The secret is kept only for the same service and key: it doesn't sign
    // requests to somewhere else.
    let secret_access_key = match given(body.secret_access_key) {
        Some(secret) => secret,
        None => match backup::load_config(&app.pool.get().await?).await? {
            Some(old)
                if old.location.access_key_id == access_key_id
                    && old.location.endpoint == endpoint =>
            {
                old.location.secret_access_key
            }
            _ => {
                return Err(ApiError::BadRequest(
                    "a secret access key is needed for a new endpoint or access key ID".into(),
                ));
            }
        },
    };
    let parse = |value: Option<String>,
                 default: &str,
                 parse: fn(&str) -> std::result::Result<u64, String>| {
        let value = value.filter(|v| !v.trim().is_empty());
        parse(value.as_deref().unwrap_or(default)).map_err(ApiError::BadRequest)
    };
    let enable = backup::Enable {
        location: Location {
            endpoint: body.endpoint.trim().to_owned(),
            region: region(body.region),
            bucket: body.bucket.trim().to_owned(),
            prefix: body.prefix,
            path_style: body.path_style,
            access_key_id,
            secret_access_key,
        },
        key: given(body.key),
        interval: parse(body.interval, "5m", backup::parse_duration)?,
        retention: parse(body.retention, "7d", backup::parse_duration)?,
        pack_size: parse(body.pack_size, "256MiB", crate::scrub::parse_rate)?,
    };
    let enabled = backup::enable(&app, enable).await?;
    Ok(Json(BackupEnabled {
        location: enabled.location.describe(),
        new_key: enabled.new_key.is_some(),
    }))
}

/// Stops backing up, as `cairn backup disable` does: what's in the bucket
/// stays, and turning it back on there carries on.
#[utoipa::path(delete, path = "/backup", responses(
    (status = 204, description = "Off"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn disable_backup(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
) -> Result<StatusCode> {
    actor.check(&app, "cairn:PutBackup", On::Cluster).await?;
    backup::disable(&app).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct RunBackup {
    /// Whether to take a base first.
    #[serde(default)]
    base: bool,
}

/// Runs a cycle of the backup within seconds (after a base, if asked), as
/// `cairn backup now` does.
#[utoipa::path(post, path = "/backup/run", request_body = RunBackup, responses(
    (status = 204, description = "Asked for"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn run_backup(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Json(body): Json<RunBackup>,
) -> Result<StatusCode> {
    actor.check(&app, "cairn:StartBackup", On::Cluster).await?;
    backup::request(&app, body.base).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod e2e {
    use std::sync::Arc;

    use axum::http::StatusCode;
    use serde_json::{Value, json};

    use super::super::Console;
    use super::super::e2e::{Browser, console_of, signed_in, superadmin};
    use crate::e2e::BUCKET;

    /// A user who may see the cluster (`cairn:GetCluster`), and change
    /// nothing of it.
    async fn viewer(console: &Arc<Console>) -> Browser {
        let browser = signed_in(console, "viewer", false).await;
        let client = console.app.pool.get().await.unwrap();
        let account = crate::users::account(&client).await.unwrap();
        let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cairn:GetCluster","Resource":"*"}]}"#;
        crate::users::put_policy(&client, &account, "viewer", "viewer", policy)
            .await
            .unwrap();
        browser
    }

    /// The error a response's body says.
    fn error(body: &Value) -> &str {
        body["error"].as_str().unwrap_or_default()
    }

    /// The Storage page's report of class `name`.
    async fn class_in_report(browser: &mut Browser, name: &str) -> Option<Value> {
        let (_, storage) = browser.send("GET", "/api/storage", None).await;
        storage["classes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .cloned()
    }

    /// An operator defines, changes and deletes storage classes, as `cairn
    /// class` does: refused what the CLI refuses, the request's fault as a
    /// 4xx; and the Storage page's report shows each change at once.
    #[tokio::test]
    async fn operators_set_storage_classes() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = console_of(&app);
        let mut ops = superadmin(&console, "ops").await;
        let mut viewer = viewer(&console).await;
        // The report is made, and kept a while.
        assert_eq!(
            ops.send("GET", "/api/storage", None).await.0,
            StatusCode::OK
        );

        let cold = json!({"pool": "default", "data_shards": 1, "parity_shards": 0, "rank": -10});
        let (status, body) = viewer
            .send("PUT", "/api/storage-classes/COLD", Some(cold.clone()))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        let (status, body) = ops
            .send("PUT", "/api/storage-classes/COLD", Some(cold))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body["description"]
                .as_str()
                .unwrap()
                .starts_with("COLD: pool default"),
            "{body}"
        );
        // Not one of S3's names: some SDKs refuse it.
        assert!(
            body["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|w| w.as_str().unwrap().contains("isn't one of S3's")),
            "{body}"
        );
        let class = class_in_report(&mut viewer, "COLD")
            .await
            .expect("the report shows the new class");
        assert_eq!(class["rank"], -10);
        assert_eq!(class["parity_shards"], 0);

        // Back to the settings' layout, and no rank.
        let (status, body) = ops
            .send(
                "PUT",
                "/api/storage-classes/COLD",
                Some(json!({"pool": "default", "data_shards": null, "parity_shards": null, "rank": null})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let class = class_in_report(&mut ops, "COLD").await.unwrap();
        assert_eq!(class["rank"], Value::Null);
        assert_eq!(class["parity_shards"], Value::Null);

        for (name, form, status, says) in [
            (
                "cold",
                json!({"pool": "default"}),
                StatusCode::BAD_REQUEST,
                "capitals",
            ),
            ("FAST", json!({}), StatusCode::BAD_REQUEST, "pool or a tier"),
            (
                "FAST",
                json!({"pool": "Fast"}),
                StatusCode::BAD_REQUEST,
                "pool's name",
            ),
            (
                "FAST",
                json!({"pool": "ssd", "data_shards": 99}),
                StatusCode::BAD_REQUEST,
                "data shards",
            ),
            (
                "FAST",
                json!({"pool": "ssd", "rank": 0}),
                StatusCode::CONFLICT,
                "STANDARD has rank 0",
            ),
            (
                "FAST",
                json!({"tier": "nowhere"}),
                StatusCode::BAD_REQUEST,
                "no tier nowhere",
            ),
        ] {
            let (got, body) = ops
                .send("PUT", &format!("/api/storage-classes/{name}"), Some(form))
                .await;
            assert_eq!(got, status, "{name}: {body}");
            assert!(error(&body).contains(says), "{name}: {body}");
        }

        // A class that an object is of can't go.
        crate::e2e::put(&app, "cold", b"cold".to_vec()).await;
        let client = app.pool.get().await.unwrap();
        let of_class = |class: &'static str| {
            let client = &client;
            async move {
                client
                    .execute(
                        "UPDATE objects SET storage_class = $1 WHERE key = 'cold'",
                        &[&class],
                    )
                    .await
                    .unwrap();
            }
        };
        of_class("COLD").await;
        let (status, body) = ops.send("DELETE", "/api/storage-classes/COLD", None).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(error(&body).contains("still holds"), "{body}");
        of_class("STANDARD").await;
        let (status, body) = viewer
            .send("DELETE", "/api/storage-classes/COLD", None)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        let (status, body) = ops.send("DELETE", "/api/storage-classes/COLD", None).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        assert_eq!(class_in_report(&mut ops, "COLD").await, None);
        let (status, body) = ops.send("DELETE", "/api/storage-classes/COLD", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        let (status, body) = ops
            .send("DELETE", "/api/storage-classes/STANDARD", None)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }

    /// An operator adds a tier, changes it, keeps a class's data there, and
    /// deletes both, as `cairn tier` and `cairn class` do; the tier's
    /// secret never comes back.
    #[tokio::test]
    async fn operators_manage_tiers() {
        let Some(target) = crate::backup::e2e::target().await else {
            return;
        };
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = console_of(&app);
        let mut ops = superadmin(&console, "ops").await;
        let mut viewer = viewer(&console).await;
        let endpoint = format!("http://{}", target.address);
        let tier = json!({
            "name": "archive",
            "endpoint": endpoint,
            "bucket": BUCKET,
            "prefix": "tier/",
            "path_style": true,
            "access_key_id": target.key_id,
            "secret_access_key": target.secret,
        });
        let (status, body) = viewer.send("POST", "/api/tiers", Some(tier.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        let (status, body) = ops.send("POST", "/api/tiers", Some(tier.clone())).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let (status, body) = ops.send("POST", "/api/tiers", Some(tier.clone())).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        // Somewhere it can't reach: the operator is told why.
        let mut unreachable = tier.clone();
        unreachable["name"] = json!("nowhere");
        unreachable["endpoint"] = json!("http://127.0.0.1:1");
        let (status, body) = ops.send("POST", "/api/tiers", Some(unreachable)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(error(&body).contains("reaching"), "{body}");

        let (status, tiers) = viewer.send("GET", "/api/tiers", None).await;
        assert_eq!(status, StatusCode::OK, "{tiers}");
        assert_eq!(tiers[0]["name"], "archive");
        assert_eq!(tiers[0]["prefix"], "tier/");
        assert_eq!(tiers[0]["access_key_id"], json!(target.key_id));
        assert_eq!(tiers[0]["writable"], true);
        assert!(!tiers.to_string().contains(&target.secret));

        let (status, body) = ops
            .send(
                "PUT",
                "/api/tiers/archive",
                Some(json!({"writable": false, "remote_class": "STANDARD_IA"})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = ops
            .send(
                "PUT",
                "/api/tiers/archive",
                Some(json!({"remote_class": "DEEP_ARCHIVE"})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let (status, body) = ops
            .send(
                "PUT",
                "/api/tiers/archive",
                Some(json!({"access_key_id": "OTHER"})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(error(&body).contains("needs its secret"), "{body}");
        // The same credentials again, checked to reach it; and writable
        // again, which is warned of.
        let (status, body) = ops
            .send(
                "PUT",
                "/api/tiers/archive",
                Some(json!({"writable": true, "secret_access_key": target.secret})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body["warnings"][0]
                .as_str()
                .unwrap()
                .contains("writable now"),
            "{body}"
        );
        let (_, tiers) = ops.send("GET", "/api/tiers", None).await;
        assert_eq!(tiers[0]["remote_class"], "STANDARD_IA");
        let (status, _) = ops
            .send("PUT", "/api/tiers/missing", Some(json!({"writable": true})))
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // A class there keeps the tier. Its shards are STANDARD's.
        let (status, body) = ops
            .send(
                "PUT",
                "/api/storage-classes/COLD",
                Some(json!({"tier": "archive", "data_shards": 2, "rank": -10})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body["description"]
                .as_str()
                .unwrap()
                .contains("tier archive"),
            "{body}"
        );
        let (_, tiers) = ops.send("GET", "/api/tiers", None).await;
        assert_eq!(tiers[0]["classes"], json!(["COLD"]));
        let (status, body) = ops.send("DELETE", "/api/tiers/archive", None).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let (status, body) = viewer.send("DELETE", "/api/tiers/archive", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        let (status, _) = ops.send("DELETE", "/api/storage-classes/COLD", None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, body) = ops.send("DELETE", "/api/tiers/archive", None).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        let (_, tiers) = ops.send("GET", "/api/tiers", None).await;
        assert_eq!(tiers, json!([]));
    }

    /// An operator adds, changes and deletes replication remotes, as `cairn
    /// remote` does; the list says which buckets replicate to each, which
    /// keeps it from being deleted, and never shows its secret.
    #[tokio::test]
    async fn operators_manage_replication_remotes() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = console_of(&app);
        let mut ops = superadmin(&console, "ops").await;
        let mut viewer = viewer(&console).await;
        let remote = json!({
            "name": "dc2",
            "endpoint": "https://s3.dc2.example.com/",
            "kind": "minio",
            "path_style": true,
            "access_key_id": "REPLICATOR",
            "secret_access_key": "s3cr3t-replicator",
        });
        let (status, body) = viewer
            .send("POST", "/api/replication-remotes", Some(remote.clone()))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        let (status, body) = ops
            .send("POST", "/api/replication-remotes", Some(remote.clone()))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let (status, body) = ops
            .send("POST", "/api/replication-remotes", Some(remote.clone()))
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        for (field, value) in [
            ("kind", "s3"),
            ("name", "DC 3"),
            ("endpoint", "ftp://example.com"),
        ] {
            let mut bad = remote.clone();
            bad["name"] = json!("dc3");
            bad[field] = json!(value);
            let (status, body) = ops
                .send("POST", "/api/replication-remotes", Some(bad))
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{field}: {body}");
        }

        let (status, remotes) = viewer.send("GET", "/api/replication-remotes", None).await;
        assert_eq!(status, StatusCode::OK, "{remotes}");
        assert_eq!(
            remotes,
            json!([{
                "name": "dc2",
                "endpoint": "https://s3.dc2.example.com",
                "region": "us-east-1",
                "path_style": true,
                "kind": "minio",
                "access_key_id": "REPLICATOR",
                "buckets": [],
            }])
        );

        // A secret alone goes with the current ID; a new ID needs one.
        let (status, body) = ops
            .send(
                "PUT",
                "/api/replication-remotes/dc2",
                Some(json!({"region": "eu-west-1", "path_style": false, "secret_access_key": "rotated"})),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        let (status, body) = ops
            .send(
                "PUT",
                "/api/replication-remotes/dc2",
                Some(json!({"access_key_id": "OTHER"})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        // Nor is a new endpoint, with the secret kept.
        let moved = json!({"endpoint": "https://s3.dc3.example.com"});
        let (status, body) = ops
            .send("PUT", "/api/replication-remotes/dc2", Some(moved))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let client = app.pool.get().await.unwrap();
        let row = client
            .query_one(
                "SELECT region, path_style, access_key_id, secret_access_key, kind
                 FROM replication_remotes WHERE name = 'dc2'",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, String>(0), "eu-west-1");
        assert!(!row.get::<_, bool>(1));
        assert_eq!(row.get::<_, String>(2), "REPLICATOR");
        assert_eq!(row.get::<_, String>(3), "rotated");
        assert_eq!(row.get::<_, String>(4), "minio");
        let (status, _) = ops
            .send(
                "PUT",
                "/api/replication-remotes/dc9",
                Some(json!({"region": "eu-west-1"})),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // A bucket whose rules name it keeps it.
        client
            .execute(
                "UPDATE buckets SET replication = $1 WHERE name = $2",
                &[
                    &r#"{"rules":[{"destination":{"remote":"dc2","bucket":"copies"}}]}"#,
                    &BUCKET,
                ],
            )
            .await
            .unwrap();
        let (_, remotes) = ops.send("GET", "/api/replication-remotes", None).await;
        assert_eq!(remotes[0]["buckets"], json!([BUCKET]));
        assert!(!remotes.to_string().contains("rotated"));
        let (status, body) = ops
            .send("DELETE", "/api/replication-remotes/dc2", None)
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(error(&body).contains(BUCKET), "{body}");
        client
            .execute("UPDATE buckets SET replication = NULL", &[])
            .await
            .unwrap();
        let (status, body) = viewer
            .send("DELETE", "/api/replication-remotes/dc2", None)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        let (status, body) = ops
            .send("DELETE", "/api/replication-remotes/dc2", None)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        let (status, _) = ops
            .send("DELETE", "/api/replication-remotes/dc2", None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// An operator turns the backup on, changes it, runs it and turns it
    /// off, as `cairn backup` does. Neither its key nor its secret ever
    /// comes back: the key stays the CLI's.
    #[tokio::test]
    async fn operators_run_the_backup() {
        let Some(target) = crate::backup::e2e::target().await else {
            return;
        };
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = console_of(&app);
        let mut ops = superadmin(&console, "ops").await;
        let mut viewer = viewer(&console).await;
        let (status, body) = viewer.send("GET", "/api/backup", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body, json!({"status": null}));
        let (status, body) = ops.send("POST", "/api/backup/run", Some(json!({}))).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");

        let endpoint = format!("http://{}", target.address);
        let form = json!({
            "endpoint": endpoint,
            "bucket": BUCKET,
            "prefix": "backup",
            "path_style": true,
            "access_key_id": target.key_id,
            "secret_access_key": target.secret,
            "interval": "10m",
            "pack_size": "8MiB",
        });
        let (status, body) = viewer.send("PUT", "/api/backup", Some(form.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        let mut bad = form.clone();
        bad["interval"] = json!("ten minutes");
        let (status, body) = ops.send("PUT", "/api/backup", Some(bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let (status, body) = ops.send("PUT", "/api/backup", Some(form.clone())).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["new_key"], true);
        let key = {
            use base64::Engine;
            let client = app.pool.get().await.unwrap();
            let config = crate::backup::load_config(&client).await.unwrap().unwrap();
            base64::engine::general_purpose::STANDARD.encode(*config.open_key(&app).await.unwrap())
        };
        assert!(!body.to_string().contains(&key));

        let (_, body) = viewer.send("GET", "/api/backup", None).await;
        let status_of = &body["status"];
        assert_eq!(status_of["enabled"], true);
        assert_eq!(status_of["prefix"], "backup/");
        assert_eq!(status_of["interval"], 600);
        assert_eq!(status_of["retention"], 7 * 86_400);
        assert_eq!(status_of["pack_size"], 8 << 20);
        assert_eq!(status_of["access_key_id"], json!(target.key_id));
        let text = body.to_string();
        assert!(
            !text.contains(&target.secret) && !text.contains(&key),
            "{text}"
        );

        // Changed without the secret: the same credentials go on, and so
        // does the key.
        let mut change = form.clone();
        change["secret_access_key"] = json!(null);
        change["retention"] = json!("1d");
        let (status, body) = ops.send("PUT", "/api/backup", Some(change.clone())).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["new_key"], false);
        let (_, body) = ops.send("GET", "/api/backup", None).await;
        assert_eq!(body["status"]["retention"], 86_400);
        // A new access key ID without its secret isn't.
        change["access_key_id"] = json!("OTHER");
        let (status, body) = ops.send("PUT", "/api/backup", Some(change)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        let (status, body) = viewer
            .send("POST", "/api/backup/run", Some(json!({"base": true})))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        let (status, body) = ops
            .send("POST", "/api/backup/run", Some(json!({"base": true})))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        let client = app.pool.get().await.unwrap();
        let requested: Option<String> = client
            .query_one("SELECT requested FROM backup_state", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(requested.as_deref(), Some("base"));

        let (status, body) = viewer.send("DELETE", "/api/backup", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        let (status, body) = ops.send("DELETE", "/api/backup", None).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        let (_, body) = ops.send("GET", "/api/backup", None).await;
        assert_eq!(body["status"]["enabled"], false);
        let (status, _) = ops.send("POST", "/api/backup/run", Some(json!({}))).await;
        assert_eq!(status, StatusCode::CONFLICT);
    }
}
