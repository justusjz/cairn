//! The dashboard's JSON API. Every handler is registered through
//! `utoipa_axum::routes!`, so the router and the OpenAPI spec are built from
//! the same annotations: a route can't be served without being in the spec.
//!
//! The numbers come from the catalog, as of the request, and from each node's
//! own metrics (see `metrics`), which every live node reports through its peer
//! endpoint. Some of the catalog's numbers take a scan of a whole table, which
//! is fine for a page an operator looks at, but not for anything that runs on
//! its own. Times are seconds since the Unix epoch.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    Json,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use http_body_util::{BodyExt, Empty, Limited};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;
use utoipa::{IntoParams, OpenApi as _, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{ApiError, ErrorBody, NodeStats, node_stats};
use crate::{
    App,
    roles::{self, Permission},
    s3::{
        buckets::{create, list as bucket_list},
        conditional::Preconditions,
        objects::list::{ListEntry, ListQuery},
        versions::Versioning,
    },
};

/// How long another node may take to report its metrics.
const STATS_TIMEOUT: Duration = Duration::from_secs(2);
/// The most a node's metrics may take up.
const MAX_STATS: usize = 4 * 1024 * 1024;
/// How long a `/storage` report is served before it's made again.
const STORAGE_TTL: Duration = Duration::from_secs(10);
/// How many entries a page of a bucket listing has.
const PAGE: i64 = 200;
/// How many versions of a key are shown.
const MAX_VERSIONS: i64 = 200;

type Result<T> = std::result::Result<T, ApiError>;
type AppState = State<Arc<App>>;

#[derive(utoipa::OpenApi)]
#[openapi(
    info(title = "Cairn dashboard", description = "The API of Cairn's dashboard."),
    servers((url = "/_dashboard/api")),
    components(schemas(ErrorBody))
)]
struct Doc;

pub(super) fn router() -> OpenApiRouter<Arc<App>> {
    OpenApiRouter::with_openapi(Doc::openapi())
        .routes(routes!(get_cluster))
        .routes(routes!(get_storage))
        .routes(routes!(list_buckets, create_bucket))
        .routes(routes!(delete_bucket))
        .routes(routes!(list_objects))
        .routes(routes!(get_object))
        .routes(routes!(download))
        .routes(routes!(list_roles, create_role))
        .routes(routes!(delete_role))
        .routes(routes!(rotate_secret))
        .routes(routes!(set_admin))
        .routes(routes!(grant, revoke))
}

/// The API's OpenAPI spec, as committed in `ui/openapi.json`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    router().split_for_parts().1
}

// ─── Cluster ─────────────────────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub(super) struct Cluster {
    /// The node answering.
    this_node: i32,
    replication_factor: usize,
    now: f64,
    nodes: Vec<ClusterNode>,
}

#[derive(Serialize, ToSchema)]
pub(super) struct ClusterNode {
    id: i32,
    node_id: String,
    peer_url: String,
    last_seen: f64,
    /// As of its last heartbeat.
    free_space: i64,
    /// Seen within the last 10 seconds.
    live: bool,
    /// What the node reported, if it's live and answered.
    stats: Option<NodeStats>,
    /// Why a live node's stats are missing.
    stats_error: Option<String>,
}

/// The nodes, each with the metrics it reports, if it's live.
#[utoipa::path(get, path = "/cluster", responses(
    (status = 200, body = Cluster),
    (status = "5XX", body = ErrorBody),
))]
async fn get_cluster(State(app): AppState) -> Result<Json<Cluster>> {
    Ok(Json(cluster(&app).await?))
}

pub(super) async fn cluster(app: &Arc<App>) -> anyhow::Result<Cluster> {
    let client = app.pool.get().await?;
    // Live as `choose_replicas` counts it: seen within the last 10 seconds.
    let rows = client
        .query(
            "SELECT id, node_id, peer_url, extract(epoch FROM last_seen)::float8, free_space,
                    last_seen > NOW() - INTERVAL '10 seconds'
             FROM nodes ORDER BY id",
            &[],
        )
        .await?;
    drop(client);
    let mut nodes: Vec<ClusterNode> = rows
        .iter()
        .map(|r| ClusterNode {
            id: r.get(0),
            node_id: r.get(1),
            peer_url: r.get(2),
            last_seen: r.get(3),
            free_space: r.get(4),
            live: r.get(5),
            stats: None,
            stats_error: None,
        })
        .collect();
    let mut fetches = JoinSet::new();
    for (index, node) in nodes.iter_mut().enumerate() {
        if node.id == app.node {
            node.stats = Some(node_stats(app));
        } else if node.live {
            let peer_url = node.peer_url.clone();
            fetches.spawn(async move { (index, fetch_stats(&peer_url).await) });
        }
    }
    while let Some(result) = fetches.join_next().await {
        match result? {
            (index, Ok(stats)) => nodes[index].stats = Some(stats),
            (index, Err(e)) => nodes[index].stats_error = Some(format!("{e:#}")),
        }
    }
    Ok(Cluster {
        this_node: app.node,
        replication_factor: app.replication_factor,
        now: crate::metrics::now_secs(),
        nodes,
    })
}

/// Asks another node for its metrics, through its peer endpoint.
async fn fetch_stats(peer_url: &str) -> anyhow::Result<NodeStats> {
    let client = Client::builder(TokioExecutor::new()).build_http::<Empty<hyper::body::Bytes>>();
    let fetch = async {
        let res = client.get(format!("{peer_url}/stats").parse()?).await?;
        if res.status() != StatusCode::OK {
            anyhow::bail!("{peer_url} answered with status {}", res.status());
        }
        let body = Limited::new(res.into_body(), MAX_STATS)
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(serde_json::from_slice(&body.to_bytes())?)
    };
    tokio::time::timeout(STATS_TIMEOUT, fetch)
        .await
        .map_err(|_| anyhow::anyhow!("{peer_url} didn't answer in time"))?
}

// ─── Storage ─────────────────────────────────────────────────────────────────

/// What's stored where, how well it's replicated, and what the background jobs
/// still have to do.
#[derive(Clone, Serialize, ToSchema)]
pub(super) struct Storage {
    replication_factor: usize,
    nodes: Vec<NodeHolding>,
    replicas: Vec<ReplicaGroup>,
    blobs: BlobTotals,
    objects: ObjectTotals,
    backlog: Backlog,
    packer: PackerSettings,
}

/// The committed blobs a node holds a copy of.
#[derive(Clone, Serialize, ToSchema)]
struct NodeHolding {
    node: i32,
    blobs: i64,
    bytes: i64,
}

/// The committed blobs with `copies` copies, `live` of them on live nodes.
#[derive(Clone, Serialize, ToSchema)]
struct ReplicaGroup {
    live: i64,
    copies: i64,
    blobs: i64,
    bytes: i64,
}

#[derive(Clone, Serialize, ToSchema)]
struct BlobTotals {
    committed: i64,
    bytes: i64,
    /// Bytes of packed blobs that no part references anymore.
    garbage_bytes: i64,
    pending: i64,
    oldest_pending: Option<f64>,
}

#[derive(Clone, Serialize, ToSchema)]
struct ObjectTotals {
    buckets: i64,
    current: i64,
    current_bytes: i64,
    noncurrent: i64,
    noncurrent_bytes: i64,
    delete_markers: i64,
}

#[derive(Clone, Serialize, ToSchema)]
struct Backlog {
    /// Blobs leased by packing jobs, right now.
    packing: i64,
    packing_bytes: i64,
    /// Blobs small enough to be consolidated.
    consolidate: i64,
    consolidate_bytes: i64,
    /// Blobs with enough garbage to be compacted.
    compact: i64,
    compact_garbage_bytes: i64,
    /// Deleted parts the packer hasn't folded yet.
    garbage_log: i64,
    uploads: i64,
    oldest_upload: Option<f64>,
    upload_bytes: i64,
}

#[derive(Clone, Serialize, ToSchema)]
struct PackerSettings {
    target_size: u64,
    small_size: u64,
    compact_threshold: f64,
    max_sources: i64,
}

#[utoipa::path(get, path = "/storage", responses(
    (status = 200, body = Storage),
    (status = "5XX", body = ErrorBody),
))]
async fn get_storage(State(app): AppState) -> Result<Json<Storage>> {
    // Requests that come in while a report is being made wait for it, rather
    // than make their own.
    let mut cached = app.dashboard.storage.lock().await;
    if let Some((made, storage)) = &*cached
        && made.elapsed() < STORAGE_TTL
    {
        return Ok(Json(storage.clone()));
    }
    let storage = storage(&app).await?;
    *cached = Some((Instant::now(), storage.clone()));
    Ok(Json(storage))
}

pub(super) async fn storage(app: &App) -> anyhow::Result<Storage> {
    let client = app.pool.get().await?;
    let nodes = client
        .query(
            "SELECT l.node, count(*), coalesce(sum(b.size), 0)::bigint
             FROM blob_locations l JOIN blobs b USING (blob_id)
             WHERE b.state = 'committed'
             GROUP BY l.node ORDER BY l.node",
            &[],
        )
        .await?
        .iter()
        .map(|r| NodeHolding {
            node: r.get(0),
            blobs: r.get(1),
            bytes: r.get(2),
        })
        .collect();
    // How many copies each committed blob has, and how many of them are on
    // live nodes.
    let replicas = client
        .query(
            "SELECT live, copies, count(*), coalesce(sum(size), 0)::bigint FROM (
                 SELECT b.size, count(l.node) AS copies,
                        count(l.node) FILTER (WHERE n.last_seen > NOW() - INTERVAL '10 seconds')
                            AS live
                 FROM blobs b
                 LEFT JOIN blob_locations l ON l.blob_id = b.blob_id
                 LEFT JOIN nodes n ON n.id = l.node
                 WHERE b.state = 'committed'
                 GROUP BY b.blob_id, b.size
             ) t
             GROUP BY live, copies ORDER BY live, copies",
            &[],
        )
        .await?
        .iter()
        .map(|r| ReplicaGroup {
            live: r.get(0),
            copies: r.get(1),
            blobs: r.get(2),
            bytes: r.get(3),
        })
        .collect();
    let small_size = app.pack.small_size as i64;
    let threshold = app.pack.compact_threshold;
    let b = client
        .query_one(
            "SELECT count(*) FILTER (WHERE state = 'committed'),
                    coalesce(sum(size) FILTER (WHERE state = 'committed'), 0)::bigint,
                    coalesce(sum(dead_size), 0)::bigint,
                    count(*) FILTER (WHERE state = 'pending'),
                    extract(epoch FROM min(created_at) FILTER (WHERE state = 'pending'))::float8,
                    count(*) FILTER (WHERE pack_lease_until > NOW()),
                    coalesce(sum(size) FILTER (WHERE pack_lease_until > NOW()), 0)::bigint,
                    count(*) FILTER (WHERE state = 'committed' AND size <= $1
                                     AND (pack_lease_until IS NULL OR pack_lease_until < NOW())),
                    coalesce(sum(size) FILTER (WHERE state = 'committed' AND size <= $1
                                     AND (pack_lease_until IS NULL OR pack_lease_until < NOW())),
                             0)::bigint,
                    count(*) FILTER (WHERE state = 'committed' AND dead_size > 0
                                     AND dead_size >= size * $2::float8),
                    coalesce(sum(dead_size) FILTER (WHERE state = 'committed' AND dead_size > 0
                                     AND dead_size >= size * $2::float8), 0)::bigint
             FROM blobs",
            &[&small_size, &threshold],
        )
        .await?;
    let o = client
        .query_one(
            "SELECT count(*) FILTER (WHERE is_latest AND NOT is_delete_marker),
                    coalesce(sum(size) FILTER (WHERE is_latest AND NOT is_delete_marker), 0)::bigint,
                    count(*) FILTER (WHERE NOT is_latest AND NOT is_delete_marker),
                    coalesce(sum(size) FILTER (WHERE NOT is_latest AND NOT is_delete_marker),
                             0)::bigint,
                    count(*) FILTER (WHERE is_delete_marker)
             FROM objects",
            &[],
        )
        .await?;
    let m = client
        .query_one(
            "SELECT (SELECT count(*) FROM multipart_uploads),
                    (SELECT extract(epoch FROM min(initiated_at))::float8 FROM multipart_uploads),
                    (SELECT coalesce(sum(size), 0)::bigint FROM parts WHERE upload_id IS NOT NULL),
                    (SELECT count(*) FROM blob_garbage),
                    (SELECT count(*) FROM buckets)",
            &[],
        )
        .await?;
    Ok(Storage {
        replication_factor: app.replication_factor,
        nodes,
        replicas,
        blobs: BlobTotals {
            committed: b.get(0),
            bytes: b.get(1),
            garbage_bytes: b.get(2),
            pending: b.get(3),
            oldest_pending: b.get(4),
        },
        objects: ObjectTotals {
            buckets: m.get(4),
            current: o.get(0),
            current_bytes: o.get(1),
            noncurrent: o.get(2),
            noncurrent_bytes: o.get(3),
            delete_markers: o.get(4),
        },
        backlog: Backlog {
            packing: b.get(5),
            packing_bytes: b.get(6),
            consolidate: b.get(7),
            consolidate_bytes: b.get(8),
            compact: b.get(9),
            compact_garbage_bytes: b.get(10),
            garbage_log: m.get(3),
            uploads: m.get(0),
            oldest_upload: m.get(1),
            upload_bytes: m.get(2),
        },
        packer: PackerSettings {
            target_size: app.pack.target_size,
            small_size: app.pack.small_size,
            compact_threshold: app.pack.compact_threshold,
            max_sources: app.pack.max_sources,
        },
    })
}

// ─── Buckets ─────────────────────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub(super) struct BucketSummary {
    name: String,
    created_at: f64,
    versioning: Versioning,
    /// Current versions that aren't delete markers.
    objects: i64,
    bytes: i64,
    /// Every version, delete markers too.
    versions: i64,
    version_bytes: i64,
    uploads: i64,
    /// Roles with a grant on the bucket.
    roles: i64,
}

#[utoipa::path(get, path = "/buckets", responses(
    (status = 200, body = Vec<BucketSummary>),
    (status = "5XX", body = ErrorBody),
))]
async fn list_buckets(State(app): AppState) -> Result<Json<Vec<BucketSummary>>> {
    Ok(Json(buckets(&app).await?))
}

/// Every bucket (as ListBuckets lists them), with what's in it.
pub(super) async fn buckets(app: &App) -> anyhow::Result<Vec<BucketSummary>> {
    let buckets = bucket_list::buckets(app).await?;
    let client = app.pool.get().await?;
    let mut objects: HashMap<String, [i64; 4]> = client
        .query(
            "SELECT bucket,
                    count(*) FILTER (WHERE is_latest AND NOT is_delete_marker),
                    coalesce(sum(size) FILTER (WHERE is_latest AND NOT is_delete_marker),
                             0)::bigint,
                    count(*),
                    coalesce(sum(size), 0)::bigint
             FROM objects GROUP BY bucket",
            &[],
        )
        .await?
        .iter()
        .map(|r| (r.get(0), [r.get(1), r.get(2), r.get(3), r.get(4)]))
        .collect();
    let counts = |sql: &str| {
        let client = &client;
        let sql = sql.to_owned();
        async move {
            let rows = client.query(&sql, &[]).await?;
            anyhow::Ok(
                rows.iter()
                    .map(|r| (r.get::<_, String>(0), r.get::<_, i64>(1)))
                    .collect::<HashMap<_, _>>(),
            )
        }
    };
    let uploads = counts("SELECT bucket, count(*) FROM multipart_uploads GROUP BY bucket").await?;
    let roles =
        counts("SELECT bucket, count(DISTINCT role) FROM role_grants GROUP BY bucket").await?;
    Ok(buckets
        .into_iter()
        .map(|b| {
            let [objects, bytes, versions, version_bytes] =
                objects.remove(&b.name).unwrap_or_default();
            BucketSummary {
                uploads: uploads.get(&b.name).copied().unwrap_or(0),
                roles: roles.get(&b.name).copied().unwrap_or(0),
                name: b.name,
                created_at: b.created_at.epoch,
                versioning: b.versioning,
                objects,
                bytes,
                versions,
                version_bytes,
            }
        })
        .collect())
}

#[derive(Deserialize, ToSchema)]
struct NewBucket {
    name: String,
}

#[utoipa::path(post, path = "/buckets", request_body = NewBucket, responses(
    (status = 201, description = "Created"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_bucket(State(app): AppState, Json(body): Json<NewBucket>) -> Result<StatusCode> {
    match create::create(&app, &body.name).await? {
        create::Creation::Created => Ok(StatusCode::CREATED),
        create::Creation::Exists => Err(ApiError::Conflict(format!(
            "a bucket named {:?} already exists",
            body.name
        ))),
        create::Creation::InvalidName => Err(ApiError::BadRequest(
            "a bucket name has 3 to 63 lowercase letters, digits, dots and hyphens, \
             and starts and ends with a letter or digit"
                .into(),
        )),
    }
}

/// Deletes an empty bucket.
#[utoipa::path(delete, path = "/buckets/{bucket}", params(("bucket" = String, Path)), responses(
    (status = 204, description = "Deleted"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_bucket(State(app): AppState, Path(bucket): Path<String>) -> Result<StatusCode> {
    let resp = crate::s3::buckets::delete::delete_bucket(&app, &bucket).await?;
    match resp.status() {
        StatusCode::NO_CONTENT => Ok(StatusCode::NO_CONTENT),
        StatusCode::NOT_FOUND => Err(ApiError::NotFound(format!("no bucket named {bucket:?}"))),
        StatusCode::CONFLICT => Err(ApiError::Conflict(format!(
            "bucket {bucket:?} isn't empty: delete its objects, versions and uploads first"
        ))),
        _ => Err(crate::Contended(format!("deleting bucket {bucket:?}")).into()),
    }
}

// ─── Objects ─────────────────────────────────────────────────────────────────

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct ListParams {
    /// List what's under this prefix.
    prefix: Option<String>,
    /// Resume after this key (a page's `next`).
    after: Option<String>,
    /// Also list keys whose current version is a delete marker.
    deleted: Option<bool>,
}

/// A page of a bucket's keys, rolled up at `/` like a directory listing.
#[derive(Serialize, ToSchema)]
pub(super) struct Listing {
    entries: Vec<Entry>,
    /// What to pass as `after` for the next page, if there is one.
    next: Option<String>,
}

#[derive(Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum Entry {
    /// A "directory": the keys whose names continue past the prefix with `/`.
    Prefix {
        prefix: String,
        objects: i64,
        bytes: i64,
        last_modified: f64,
    },
    /// A key's current version.
    Object {
        key: String,
        size: i64,
        etag: Option<String>,
        last_modified: f64,
        delete_marker: bool,
    },
}

#[utoipa::path(get, path = "/buckets/{bucket}/objects", params(("bucket" = String, Path), ListParams),
    responses(
        (status = 200, body = Listing),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn list_objects(
    State(app): AppState,
    Path(bucket): Path<String>,
    Query(params): Query<ListParams>,
) -> Result<Json<Listing>> {
    let query = ListQuery {
        prefix: params.prefix.as_deref().unwrap_or(""),
        delimiter: Some("/"),
        marker: params.after.as_deref().unwrap_or(""),
        max_keys: PAGE,
        delete_markers: params.deleted.unwrap_or(false),
    };
    Ok(Json(listing(&app, &bucket, &query).await?))
}

/// A page of `list`, for the dashboard.
pub(super) async fn listing(app: &App, bucket: &str, query: &ListQuery<'_>) -> Result<Listing> {
    let Some(listing) = crate::s3::objects::list::list(app, bucket, query).await? else {
        return Err(ApiError::NotFound(format!("no bucket named {bucket:?}")));
    };
    let entries = listing
        .entries
        .into_iter()
        .map(|e| match e {
            ListEntry::Prefix {
                prefix,
                objects,
                bytes,
                last_modified,
            } => Entry::Prefix {
                prefix,
                objects,
                bytes,
                last_modified: last_modified.epoch,
            },
            ListEntry::Object {
                key,
                size,
                etag,
                last_modified,
                delete_marker,
            } => Entry::Object {
                key,
                size,
                etag,
                last_modified: last_modified.epoch,
                delete_marker,
            },
        })
        .collect();
    Ok(Listing {
        entries,
        next: listing.next_marker,
    })
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct KeyParams {
    key: String,
}

/// Every version of a key (the newest 200), each with its parts and where their
/// blobs are stored.
#[derive(Serialize, ToSchema)]
pub(super) struct ObjectInfo {
    bucket: String,
    key: String,
    /// Newest first; empty if there's no such key.
    versions: Vec<VersionInfo>,
}

#[derive(Serialize, ToSchema)]
struct VersionInfo {
    version_id: String,
    latest: bool,
    delete_marker: bool,
    size: i64,
    etag: Option<String>,
    content_type: Option<String>,
    last_modified: f64,
    parts: Vec<PartInfo>,
}

#[derive(Serialize, ToSchema)]
struct PartInfo {
    number: i32,
    size: i64,
    etag: String,
    /// The CRC64/NVME of the part's bytes, in hex; none for old data.
    crc64nvme: Option<String>,
    blob_id: String,
    /// Where in the blob the part's bytes start.
    blob_offset: i64,
    blob_size: i64,
    blob_state: String,
    created_at: f64,
    /// The nodes holding a copy of the blob.
    nodes: Vec<i32>,
}

#[utoipa::path(get, path = "/buckets/{bucket}/object", params(("bucket" = String, Path), KeyParams),
    responses(
        (status = 200, body = ObjectInfo),
        (status = "5XX", body = ErrorBody),
    ))]
async fn get_object(
    State(app): AppState,
    Path(bucket): Path<String>,
    Query(params): Query<KeyParams>,
) -> Result<Json<ObjectInfo>> {
    Ok(Json(object(&app, &bucket, &params.key).await?))
}

pub(super) async fn object(app: &App, bucket: &str, key: &str) -> anyhow::Result<ObjectInfo> {
    let client = app.pool.get().await?;
    let versions = client
        .query(
            "SELECT id, version_id, is_latest, is_delete_marker, size, etag, content_type,
                    extract(epoch FROM last_modified)::float8
             FROM objects WHERE bucket = $1 AND key = $2
             ORDER BY id DESC LIMIT $3",
            &[&bucket, &key, &MAX_VERSIONS],
        )
        .await?;
    let ids: Vec<i64> = versions.iter().map(|r| r.get(0)).collect();
    let mut parts: HashMap<i64, Vec<PartInfo>> = HashMap::new();
    for p in client
        .query(
            "SELECT p.object_id, p.part_number, p.size, p.etag, p.crc64nvme, p.blob_id,
                    p.blob_offset, b.size, b.state, extract(epoch FROM p.created_at)::float8,
                    ARRAY(SELECT l.node FROM blob_locations l
                          WHERE l.blob_id = p.blob_id ORDER BY l.node)
             FROM parts p JOIN blobs b ON b.blob_id = p.blob_id
             WHERE p.object_id = ANY($1)
             ORDER BY p.object_id, p.part_number",
            &[&ids],
        )
        .await?
    {
        parts.entry(p.get(0)).or_default().push(PartInfo {
            number: p.get(1),
            size: p.get(2),
            etag: p.get(3),
            crc64nvme: p
                .get::<_, Option<i64>>(4)
                .map(|c| format!("{:016x}", c as u64)),
            blob_id: p.get::<_, uuid::Uuid>(5).to_string(),
            blob_offset: p.get(6),
            blob_size: p.get(7),
            blob_state: p.get(8),
            created_at: p.get(9),
            nodes: p.get(10),
        });
    }
    let versions = versions
        .iter()
        .map(|v| VersionInfo {
            version_id: v.get(1),
            latest: v.get(2),
            delete_marker: v.get(3),
            size: v.get(4),
            etag: v.get(5),
            content_type: v.get(6),
            last_modified: v.get(7),
            parts: parts.remove(&v.get::<_, i64>(0)).unwrap_or_default(),
        })
        .collect();
    Ok(ObjectInfo {
        bucket: bucket.to_owned(),
        key: key.to_owned(),
        versions,
    })
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct DownloadParams {
    key: String,
    /// The version to download; the current one if not given.
    version: Option<String>,
}

/// An object's data, as a file to save. It's always sent as an attachment of
/// no particular type, so that a browser never renders it as part of the UI.
#[utoipa::path(get, path = "/buckets/{bucket}/download", params(("bucket" = String, Path), DownloadParams),
    responses(
        (status = 200, description = "The object's data", content_type = "application/octet-stream"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn download(
    State(app): AppState,
    Path(bucket): Path<String>,
    Query(params): Query<DownloadParams>,
) -> Result<Response> {
    let resp = crate::s3::objects::get::get_object(
        &app,
        &bucket,
        &params.key,
        params.version.as_deref(),
        None,
        &Preconditions::default(),
    )
    .await?;
    if resp.status() != StatusCode::OK {
        return Err(ApiError::NotFound("the object can't be read".into()));
    }
    let (mut parts, body) = resp.into_parts();
    let name = params
        .key
        .rsplit('/')
        .next()
        .filter(|n| !n.is_empty())
        .unwrap_or("download");
    let disposition = format!(
        "attachment; filename*=UTF-8''{}",
        utf8_percent_encode(name, NON_ALPHANUMERIC)
    );
    let headers = &mut parts.headers;
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&disposition)?,
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox"),
    );
    Ok(Response::from_parts(parts, Body::new(body)))
}

// ─── Roles ───────────────────────────────────────────────────────────────────

/// A role, never with its secret.
#[derive(Serialize, ToSchema)]
pub(super) struct RoleSummary {
    name: String,
    admin: bool,
    created_at: f64,
    grants: Vec<Grant>,
}

#[derive(Serialize, ToSchema)]
struct Grant {
    bucket: String,
    permission: Permission,
}

#[utoipa::path(get, path = "/roles", responses(
    (status = 200, body = Vec<RoleSummary>),
    (status = "5XX", body = ErrorBody),
))]
async fn list_roles(State(app): AppState) -> Result<Json<Vec<RoleSummary>>> {
    let roles = roles::list(&app.pool.get().await?)
        .await?
        .into_iter()
        .map(|r| RoleSummary {
            name: r.name,
            admin: r.admin,
            created_at: r.created_at,
            grants: r
                .grants
                .into_iter()
                .map(|(bucket, permission)| Grant { bucket, permission })
                .collect(),
        })
        .collect();
    Ok(Json(roles))
}

#[derive(Deserialize, ToSchema)]
struct NewRole {
    name: String,
    /// At least 8 characters; one is generated if not given.
    secret: Option<String>,
    #[serde(default)]
    admin: bool,
}

/// A role's secret, which is shown only this once.
#[derive(Serialize, ToSchema)]
struct Secret {
    name: String,
    secret: String,
}

#[utoipa::path(post, path = "/roles", request_body = NewRole, responses(
    (status = 201, body = Secret),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_role(
    State(app): AppState,
    Json(body): Json<NewRole>,
) -> Result<(StatusCode, Json<Secret>)> {
    let client = app.pool.get().await?;
    let secret = body.secret.filter(|s| !s.is_empty());
    let secret = roles::create(&client, &body.name, secret, body.admin).await?;
    Ok((
        StatusCode::CREATED,
        Json(Secret {
            name: body.name,
            secret,
        }),
    ))
}

#[utoipa::path(delete, path = "/roles/{role}", params(("role" = String, Path)), responses(
    (status = 204, description = "Deleted, with its grants"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_role(State(app): AppState, Path(role): Path<String>) -> Result<StatusCode> {
    roles::delete(&app.pool.get().await?, &role).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct NewSecret {
    /// At least 8 characters; one is generated if not given.
    secret: Option<String>,
}

/// Replaces a role's secret.
#[utoipa::path(post, path = "/roles/{role}/secret", params(("role" = String, Path)),
    request_body = NewSecret, responses(
        (status = 200, body = Secret),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn rotate_secret(
    State(app): AppState,
    Path(role): Path<String>,
    Json(body): Json<NewSecret>,
) -> Result<Json<Secret>> {
    let secret = match body.secret.filter(|s| !s.is_empty()) {
        Some(s) => s,
        None => roles::generate_secret()?,
    };
    roles::update(&app.pool.get().await?, &role, None, Some(secret.clone())).await?;
    Ok(Json(Secret { name: role, secret }))
}

#[derive(Deserialize, ToSchema)]
struct AdminFlag {
    admin: bool,
}

/// Makes a role an admin, or not.
#[utoipa::path(put, path = "/roles/{role}/admin", params(("role" = String, Path)),
    request_body = AdminFlag, responses(
        (status = 204, description = "Changed"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn set_admin(
    State(app): AppState,
    Path(role): Path<String>,
    Json(body): Json<AdminFlag>,
) -> Result<StatusCode> {
    roles::update(&app.pool.get().await?, &role, Some(body.admin), None).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct NewGrant {
    bucket: String,
    permissions: Vec<Permission>,
}

/// Grants permissions on an existing bucket.
#[utoipa::path(post, path = "/roles/{role}/grants", params(("role" = String, Path)),
    request_body = NewGrant, responses(
        (status = 204, description = "Granted"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn grant(
    State(app): AppState,
    Path(role): Path<String>,
    Json(body): Json<NewGrant>,
) -> Result<StatusCode> {
    if body.permissions.is_empty() {
        return Err(ApiError::BadRequest("pick at least one permission".into()));
    }
    roles::grant(
        &app.pool.get().await?,
        &role,
        &body.bucket,
        &body.permissions,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct RevokeParams {
    bucket: String,
    /// The permission to revoke; all of them on the bucket if not given.
    permission: Option<Permission>,
}

#[utoipa::path(delete, path = "/roles/{role}/grants", params(("role" = String, Path), RevokeParams),
    responses(
        (status = 204, description = "Revoked"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn revoke(
    State(app): AppState,
    Path(role): Path<String>,
    Query(params): Query<RevokeParams>,
) -> Result<StatusCode> {
    let permissions: Vec<Permission> = params.permission.into_iter().collect();
    roles::revoke(&app.pool.get().await?, &role, &params.bucket, &permissions).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod e2e {
    use axum::http::Request;
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::*;
    use crate::e2e::{BUCKET, delete, node_with, put};

    async fn node() -> Option<Arc<App>> {
        node_with(crate::packer::Config::default(), None).await
    }

    #[tokio::test]
    async fn reports_the_catalog() {
        let Some(app) = node().await else { return };
        put(&app, "a/one", vec![1; 10]).await;
        put(&app, "a/two", vec![2; 20]).await;
        put(&app, "b", vec![3; 30]).await;
        put(&app, "gone", vec![4; 40]).await;
        delete(&app, "gone").await;

        let s = serde_json::to_value(storage(&app).await.unwrap()).unwrap();
        assert_eq!(s["objects"]["current"], 3);
        assert_eq!(s["objects"]["current_bytes"], 60);
        assert_eq!(s["blobs"]["committed"], 3);
        assert_eq!(
            s["replicas"],
            json!([{ "live": 1, "copies": 1, "blobs": 3, "bytes": 60 }])
        );
        assert_eq!(s["nodes"][0]["bytes"], 60);
        assert_eq!(s["backlog"]["consolidate"], 3);

        let b = serde_json::to_value(buckets(&app).await.unwrap()).unwrap();
        assert_eq!(b[0]["name"], BUCKET);
        assert_eq!(b[0]["objects"], 3);
        assert_eq!(b[0]["versioning"], "unversioned");

        // Rolled up at `/`, with each directory's count and size.
        let query = |prefix, marker, delete_markers| ListQuery {
            prefix,
            delimiter: Some("/"),
            marker,
            max_keys: PAGE,
            delete_markers,
        };
        let l = serde_json::to_value(listing(&app, BUCKET, &query("", "", false)).await.unwrap())
            .unwrap();
        assert_eq!(l["entries"].as_array().unwrap().len(), 2);
        assert_eq!(l["entries"][0]["kind"], "prefix");
        assert_eq!(l["entries"][0]["prefix"], "a/");
        assert_eq!(l["entries"][0]["objects"], 2);
        assert_eq!(l["entries"][0]["bytes"], 30);
        assert_eq!(l["entries"][1]["kind"], "object");
        assert_eq!(l["entries"][1]["key"], "b");
        assert!(l["next"].is_null());
        let l = serde_json::to_value(
            listing(&app, BUCKET, &query("a/", "a/one", false))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(l["entries"].as_array().unwrap().len(), 1);
        assert_eq!(l["entries"][0]["key"], "a/two");
        // A deleted key shows up only when asked for.
        let l = serde_json::to_value(listing(&app, BUCKET, &query("g", "", true)).await.unwrap())
            .unwrap();
        assert_eq!(
            l["entries"].as_array().unwrap().len(),
            0,
            "unversioned: the delete removed it"
        );
        assert!(matches!(
            listing(&app, "nope", &query("", "", false)).await,
            Err(ApiError::NotFound(_))
        ));

        let o = serde_json::to_value(object(&app, BUCKET, "a/two").await.unwrap()).unwrap();
        assert_eq!(o["versions"].as_array().unwrap().len(), 1);
        assert_eq!(o["versions"][0]["parts"][0]["size"], 20);
        assert_eq!(o["versions"][0]["parts"][0]["nodes"], json!([app.node]));

        let c = serde_json::to_value(cluster(&app).await.unwrap()).unwrap();
        assert_eq!(c["nodes"][0]["stats"]["node"], app.node);
        assert!(c["nodes"][0]["stats"]["requests"]["ops"].is_array());
    }

    /// Sends a request through the whole peer endpoint.
    async fn send(
        app: &Arc<App>,
        req: Request<axum::body::Body>,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let resp = crate::peer::router(app.clone()).oneshot(req).await.unwrap();
        let (parts, body) = resp.into_parts();
        let body = body.collect().await.unwrap().to_bytes().to_vec();
        (parts.status, parts.headers, body)
    }

    fn request(method: &str, uri: &str, body: Option<Value>) -> Request<axum::body::Body> {
        let builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "127.0.0.1:9431")
            .header("x-cairn-ui", "1")
            .header("content-type", "application/json");
        let body = body.map(|b| b.to_string()).unwrap_or_default();
        builder.body(axum::body::Body::from(body)).unwrap()
    }

    fn error_of(body: &[u8]) -> String {
        serde_json::from_slice::<Value>(body).unwrap()["error"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    use axum::http::HeaderMap;

    #[tokio::test]
    async fn serves_the_dashboard() {
        let Some(app) = node().await else { return };
        put(&app, "dir/file.txt", b"hello".to_vec()).await;
        let api = "/_dashboard/api";

        let (status, headers, body) =
            send(&app, request("GET", &format!("{api}/cluster"), None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["content-type"], "application/json");
        assert_eq!(headers["cache-control"], "no-store");
        assert!(headers.contains_key("content-security-policy"));
        let cluster: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(cluster["this_node"], app.node);

        // Changes need the header.
        let req = Request::builder()
            .method("POST")
            .uri(format!("{api}/buckets"))
            .header("host", "127.0.0.1:9431")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(r#"{"name":"new-bucket"}"#))
            .unwrap();
        let (status, _, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(error_of(&body), "missing x-cairn-ui header");

        // Nothing of the dashboard answers to a name that could have been
        // rebound to the node; the peer routes don't care.
        let rebound = |path: &str| {
            let mut req = request("GET", path, None);
            req.headers_mut()
                .insert("host", "evil.example:9431".parse().unwrap());
            req
        };
        for path in [&format!("{api}/roles"), "/_dashboard"] {
            assert_eq!(
                send(&app, rebound(path)).await.0,
                StatusCode::FORBIDDEN,
                "{path}"
            );
        }
        assert_eq!(send(&app, rebound("/stats")).await.0, StatusCode::OK);

        let create = |name: &str| {
            request(
                "POST",
                &format!("{api}/buckets"),
                Some(json!({ "name": name })),
            )
        };
        assert_eq!(
            send(&app, create("new-bucket")).await.0,
            StatusCode::CREATED
        );
        assert_eq!(
            send(&app, create("new-bucket")).await.0,
            StatusCode::CONFLICT
        );
        let (status, _, body) = send(&app, create("Bad_Name")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(error_of(&body).contains("bucket name"));
        let delete = |name: &str| request("DELETE", &format!("{api}/buckets/{name}"), None);
        assert_eq!(
            send(&app, delete("new-bucket")).await.0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            send(&app, delete("new-bucket")).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(send(&app, delete(BUCKET)).await.0, StatusCode::CONFLICT);

        let uri = format!("{api}/buckets/{BUCKET}/objects?prefix=dir%2F&deleted=false");
        let (status, _, body) = send(&app, request("GET", &uri, None)).await;
        assert_eq!(status, StatusCode::OK);
        let listing: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(listing["entries"][0]["key"], "dir/file.txt");

        let uri = format!("{api}/buckets/{BUCKET}/download?key=dir%2Ffile.txt");
        let (status, headers, body) = send(&app, request("GET", &uri, None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"hello");
        assert_eq!(headers["content-type"], "application/octet-stream");
        assert_eq!(
            headers["content-disposition"],
            "attachment; filename*=UTF-8''file%2Etxt"
        );
        assert_eq!(headers["content-security-policy"], "sandbox");
        let uri = format!("{api}/buckets/{BUCKET}/download?key=nope");
        assert_eq!(
            send(&app, request("GET", &uri, None)).await.0,
            StatusCode::NOT_FOUND
        );

        let new_role = json!({ "name": "ui-role", "admin": false });
        let (status, _, body) = send(
            &app,
            request("POST", &format!("{api}/roles"), Some(new_role)),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let secret: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(secret["secret"].as_str().unwrap().len(), 40);
        let grant = json!({ "bucket": BUCKET, "permissions": ["read", "delete-version"] });
        let uri = format!("{api}/roles/ui-role/grants");
        assert_eq!(
            send(&app, request("POST", &uri, Some(grant))).await.0,
            StatusCode::NO_CONTENT
        );
        let bad = json!({ "bucket": BUCKET, "permissions": ["admin"] });
        assert!(
            send(&app, request("POST", &uri, Some(bad)))
                .await
                .0
                .is_client_error()
        );
        let (_, _, body) = send(&app, request("GET", &format!("{api}/roles"), None)).await;
        let roles: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            roles[0]["grants"],
            json!([
                { "bucket": BUCKET, "permission": "delete-version" },
                { "bucket": BUCKET, "permission": "read" },
            ])
        );
        let uri = format!("{api}/roles/nobody");
        let (status, _, body) = send(&app, request("DELETE", &uri, None)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error_of(&body), "no role named \"nobody\"");

        // Unknown API routes are JSON 404s; everything else is the UI.
        let (status, _, body) = send(&app, request("GET", &format!("{api}/nope"), None)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(error_of(&body), "no such API route");
        let (status, headers, _) = send(&app, request("GET", "/_dashboard/buckets/x", None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["content-type"], "text/html; charset=utf-8");
        let (status, _, _) = send(&app, request("GET", "/_dashboard/assets/nope.js", None)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        for path in ["/", "/_dashboard/"] {
            let (status, headers, _) = send(&app, request("GET", path, None)).await;
            assert!(status.is_redirection(), "{path}");
            assert_eq!(headers["location"], "/_dashboard");
        }
        let (status, headers, _) = send(&app, request("GET", "/_dashboard", None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["content-type"], "text/html; charset=utf-8");
        let (_, _, body) = send(&app, request("GET", &format!("{api}/openapi.json"), None)).await;
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["servers"][0]["url"],
            api
        );

        // The peer routes are as before.
        assert_eq!(
            send(&app, request("GET", "/stats", None)).await.0,
            StatusCode::OK
        );
        assert_eq!(
            send(&app, request("GET", "/blobs/nope", None)).await.0,
            StatusCode::BAD_REQUEST
        );
        let missing = format!("/blobs/{}", uuid::Uuid::new_v4());
        assert_eq!(
            send(&app, request("GET", &missing, None)).await.0,
            StatusCode::NOT_FOUND
        );
    }

    /// S3's CreateBucket checks names the same way.
    #[tokio::test]
    async fn s3_refuses_invalid_bucket_names() {
        let Some(app) = node().await else { return };
        let resp = crate::s3::buckets::create::create_bucket(&app, "Bad_Name")
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let resp = crate::s3::buckets::create::create_bucket(&app, BUCKET)
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "re-creating a bucket succeeds"
        );
    }
}
