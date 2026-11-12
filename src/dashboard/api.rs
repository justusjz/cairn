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
    extract::{Extension, Path, Query, State},
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use http_body_util::{BodyExt, Limited};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;
use utoipa::{IntoParams, OpenApi as _, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::actor::Actor;
use super::{ApiError, ErrorBody, NodeStats, node_stats};
use crate::s3::actions::{Check, On};
use crate::db::Cached;
use crate::{
    App,
    peer::PeerClient,
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
        .routes(routes!(get_integrity))
        .routes(routes!(list_roles, create_role))
        .routes(routes!(delete_role))
        .routes(routes!(rotate_secret))
        .routes(routes!(set_admin))
        .routes(routes!(identify_roles))
        .routes(routes!(grant, revoke))
        .routes(routes!(create_enrollment))
        .routes(routes!(create_key))
        .routes(routes!(set_key, delete_key))
        .routes(routes!(get_policy, put_policy, delete_policy))
        .routes(routes!(get_lifecycle))
        .routes(routes!(set_lifecycle_rate))
        .routes(routes!(set_setting))
        .routes(routes!(remove_node))
        .routes(routes!(keep_node))
        .merge(shared_router())
}

/// The buckets and objects, which the console serves too, as its user (see
/// `actor`): every handler here checks what it does as its S3 operation's
/// actions.
pub(crate) fn shared_router() -> OpenApiRouter<Arc<App>> {
    OpenApiRouter::new()
        .routes(routes!(list_buckets, create_bucket))
        .routes(routes!(delete_bucket))
        .routes(routes!(list_objects))
        .routes(routes!(get_object))
        .routes(routes!(download))
        .routes(routes!(get_bucket_lifecycle, put_bucket_lifecycle, delete_bucket_lifecycle))
        .routes(routes!(get_bucket_access))
        .routes(routes!(put_bucket_policy, delete_bucket_policy))
        .routes(routes!(put_public_access_block, delete_public_access_block))
        .routes(routes!(get_public_access))
        .routes(routes!(upload, delete_object))
        .routes(routes!(set_versioning))
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
    /// `active`, `removing` (its shards are moving to other nodes, see
    /// `mover`) or `removed`.
    state: String,
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
        .query_cached(
            "SELECT id, node_id, peer_url, extract(epoch FROM last_seen)::float8, free_space,
                    last_seen > NOW() - INTERVAL '10 seconds', state
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
            state: r.get(6),
            stats: None,
            stats_error: None,
        })
        .collect();
    let mut fetches = JoinSet::new();
    for (index, node) in nodes.iter_mut().enumerate() {
        if node.id == app.node {
            node.stats = Some(node_stats(app).await);
        } else if node.live {
            let (peers, peer_url) = (app.peers.clone(), node.peer_url.clone());
            fetches.spawn(async move { (index, fetch_stats(&peers, &peer_url).await) });
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
        replication_factor: app.replication_factor(),
        now: crate::metrics::now_secs(),
        nodes,
    })
}

/// Asks another node for its metrics, through its peer endpoint.
async fn fetch_stats(peers: &PeerClient, peer_url: &str) -> anyhow::Result<NodeStats> {
    let fetch = async {
        let req = hyper::Request::get(format!("{peer_url}/stats")).body(PeerClient::empty())?;
        let res = peers.request(req).await?;
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
    integrity: Coverage,
}

/// How much of the data the scrubber has checked (see `scrub`).
#[derive(Clone, Serialize, ToSchema)]
struct Coverage {
    /// What each node holds of checksummed data, and how recently it was
    /// checked.
    nodes: Vec<NodeCoverage>,
    /// Committed blobs from before checksums, which can't be checked.
    legacy_blobs: i64,
    legacy_bytes: i64,
}

/// The copies of committed, checksummed blobs a node holds, and how recently
/// they were known intact.
#[derive(Clone, Serialize, ToSchema)]
struct NodeCoverage {
    node: i32,
    copies: i64,
    bytes: i64,
    /// Copies never checked (from before scrubbing), or flagged by a read:
    /// checked next.
    unchecked: i64,
    unchecked_bytes: i64,
    /// When the least recently checked of the others was known intact.
    oldest_checked: Option<f64>,
}

/// The committed blobs a node holds a shard of, and the bytes of those
/// shards.
#[derive(Clone, Serialize, ToSchema)]
struct NodeHolding {
    node: i32,
    blobs: i64,
    bytes: i64,
}

/// The committed blobs of `data_shards` data shards (1: replicated) with
/// `copies` shards in all, `live` of them on live nodes. A blob is readable
/// with `data_shards` live shards, and as redundant as the cluster's
/// replication factor asks with `data_shards` + replication factor − 1.
#[derive(Clone, Serialize, ToSchema)]
struct ReplicaGroup {
    data_shards: i64,
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
    /// Blobs large enough to be coded that aren't in the cluster's layout,
    /// which the packer converts (see `packer::Layouts`).
    convert: i64,
    convert_bytes: i64,
    /// Replicated blobs with more or fewer copies than the `parity-shards`
    /// setting says (none while it isn't set), and how many copies the
    /// mover is to add and to drop (see `mover`).
    copies: i64,
    copies_to_add: i64,
    copies_to_drop: i64,
    /// Shards to move off nodes being removed, or down for longer than the
    /// `repair-after` setting (see `mover`); and that setting, in minutes (0:
    /// off).
    moves: i64,
    repair_after: i64,
    /// Entries of the garbage log the packer hasn't folded yet: one per blob
    /// that a statement deleted parts from.
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
    /// What blobs larger than `small_size` are erasure-coded into (the
    /// `data-shards` setting, and the parity shards). One data shard: they
    /// aren't.
    data_shards: i64,
    parity_shards: u32,
    /// The `parity-shards` setting, if it's set; else every node goes by its
    /// `--replication-factor`.
    parity_setting: Option<i64>,
    /// The most data and parity shards the settings allow.
    max_data_shards: i64,
    max_parity_shards: i64,
    /// Whether blobs are brought to that layout now: it takes as many live
    /// nodes as shards.
    coding: bool,
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

/// The bytes of a shard file's data (`blob_locations bl` of `blobs b`): the
/// blob's for a replicated blob, the shard's cut of it for a coded one (see
/// `shards::Layout::shard_size`).
const SHARD_BYTES: &str = "CASE
    WHEN b.data_shards = 1 THEN b.size
    WHEN bl.shard >= b.data_shards
        THEN (b.size + b.data_shards::bigint * b.stripe_unit - 1)
             / (b.data_shards::bigint * b.stripe_unit) * b.stripe_unit
    ELSE b.size / (b.data_shards::bigint * b.stripe_unit) * b.stripe_unit
         + least(b.stripe_unit::bigint,
                 greatest(0, b.size % (b.data_shards::bigint * b.stripe_unit)
                             - bl.shard::bigint * b.stripe_unit))
END";

/// Of a committed blob of `blobs`, whether the packer is to convert it into
/// $3 data shards and, unless it's NULL, $4 parity shards (see
/// `cairn_claim`), if it's large enough.
const CONVERT: &str = "(data_shards <> $3 OR ($3 > 1 AND $4::smallint IS NOT NULL AND parity_shards <> $4))";

/// Of a blob of `blobs`, whether the mover is to add or drop copies of it,
/// to $4 parity shards, unless that's NULL: unless the packer is to code it,
/// as it is any larger than $1 while there are $3 > 1 data shards (see
/// `cairn_claim_copies`).
const COPIES: &str = "state = 'committed' AND data_shards = 1 AND block_size IS NOT NULL
    AND $4::smallint IS NOT NULL AND parity_shards <> $4 AND NOT ($3 > 1 AND size > $1)";

pub(super) async fn storage(app: &App) -> anyhow::Result<Storage> {
    let client = app.pool.get().await?;
    let nodes = client
        .query_cached(
            &format!(
                "SELECT bl.node, count(*), coalesce(sum({SHARD_BYTES}), 0)::bigint
                 FROM blob_locations bl JOIN blobs b USING (blob_id)
                 WHERE b.state = 'committed'
                 GROUP BY bl.node ORDER BY bl.node"
            ),
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
    // How many shards each committed blob has, and how many of them are on
    // live nodes.
    let replicas = client
        .query_cached(
            "SELECT data_shards, live, copies, count(*), coalesce(sum(size), 0)::bigint FROM (
                 SELECT b.size, b.data_shards::bigint, count(l.node) AS copies,
                        count(l.node) FILTER (WHERE n.last_seen > NOW() - INTERVAL '10 seconds')
                            AS live
                 FROM blobs b
                 LEFT JOIN blob_locations l ON l.blob_id = b.blob_id
                 LEFT JOIN nodes n ON n.id = l.node
                 WHERE b.state = 'committed'
                 GROUP BY b.blob_id, b.size, b.data_shards
             ) t
             GROUP BY data_shards, live, copies ORDER BY data_shards, live, copies",
            &[],
        )
        .await?
        .iter()
        .map(|r| ReplicaGroup {
            data_shards: r.get(0),
            live: r.get(1),
            copies: r.get(2),
            blobs: r.get(3),
            bytes: r.get(4),
        })
        .collect();
    let small_size = app.pack.small_size as i64;
    let threshold = app.pack.compact_threshold;
    // The layout blobs are to have: as the packer's and mover's claims see
    // it (see `cairn_claim`, `cairn_claim_copies`).
    let wanted = crate::packer::wanted_layouts(app).await?;
    let data_shards = wanted.data_shards as i16;
    let parity_shards = wanted.parity_settled.then_some(wanted.parity_shards as i16);
    let b = client
        .query_one_cached(
            &format!("SELECT count(*) FILTER (WHERE state = 'committed'),
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
                                     AND dead_size >= size * $2::float8), 0)::bigint,
                    count(*) FILTER (WHERE state = 'committed' AND block_size IS NOT NULL
                                     AND size - dead_size > $1 AND {CONVERT}),
                    coalesce(sum(size) FILTER (WHERE state = 'committed' AND block_size IS NOT NULL
                                     AND size - dead_size > $1 AND {CONVERT}), 0)::bigint,
                    count(*) FILTER (WHERE {COPIES}),
                    coalesce(sum(greatest($4 - parity_shards, 0)) FILTER (WHERE {COPIES}), 0)::bigint,
                    coalesce(sum(greatest(parity_shards - $4, 0)) FILTER (WHERE {COPIES}), 0)::bigint
             FROM blobs"),
            &[&small_size, &threshold, &data_shards, &parity_shards],
        )
        .await?;
    let o = client
        .query_one_cached(
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
    let coverage = client
        .query_cached(
            &format!(
                "SELECT bl.node, count(*), coalesce(sum({SHARD_BYTES}), 0)::bigint,
                        count(*) FILTER (WHERE bl.checked_at IS NULL OR bl.checked_at = '-infinity'),
                        coalesce(sum({SHARD_BYTES}) FILTER (WHERE bl.checked_at IS NULL
                                                     OR bl.checked_at = '-infinity'), 0)::bigint,
                        extract(epoch FROM min(bl.checked_at)
                                           FILTER (WHERE bl.checked_at > '-infinity'))::float8
                 FROM blob_locations bl JOIN blobs b ON b.blob_id = bl.blob_id
                 WHERE b.state = 'committed' AND b.block_size IS NOT NULL
                 GROUP BY bl.node ORDER BY bl.node"
            ),
            &[],
        )
        .await?
        .iter()
        .map(|r| NodeCoverage {
            node: r.get(0),
            copies: r.get(1),
            bytes: r.get(2),
            unchecked: r.get(3),
            unchecked_bytes: r.get(4),
            oldest_checked: r.get(5),
        })
        .collect();
    let legacy = client
        .query_one_cached(
            "SELECT count(*), coalesce(sum(size), 0)::bigint FROM blobs
             WHERE state = 'committed' AND block_size IS NULL",
            &[],
        )
        .await?;
    let repair_after = crate::settings::REPAIR_AFTER.get(&client).await?;
    let after = (repair_after > 0).then_some(repair_after as f64 * 60.0);
    let moves: i64 = client
        .query_one_cached(
            "SELECT count(*) FROM blob_locations bl JOIN nodes n ON n.id = bl.node
             WHERE n.state <> 'active' OR n.last_seen < NOW() - make_interval(secs => $1)",
            &[&after],
        )
        .await?
        .get(0);
    let m = client
        .query_one_cached(
            "SELECT (SELECT count(*) FROM multipart_uploads),
                    (SELECT extract(epoch FROM min(initiated_at))::float8 FROM multipart_uploads),
                    (SELECT coalesce(sum(size), 0)::bigint FROM parts WHERE upload_id IS NOT NULL),
                    (SELECT count(*) FROM blob_garbage),
                    (SELECT count(*) FROM buckets)",
            &[],
        )
        .await?;
    Ok(Storage {
        replication_factor: app.replication_factor(),
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
            convert: b.get(11),
            convert_bytes: b.get(12),
            copies: b.get(13),
            copies_to_add: b.get(14),
            copies_to_drop: b.get(15),
            moves,
            repair_after,
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
            data_shards: wanted.data_shards as i64,
            parity_shards: app.parity_shards(),
            parity_setting: crate::settings::PARITY_SHARDS.get_set(&client).await?,
            max_data_shards: crate::settings::DATA_SHARDS.max,
            max_parity_shards: crate::settings::PARITY_SHARDS.max,
            coding: crate::packer::layouts(app).await?.is_some(),
        },
        integrity: Coverage {
            nodes: coverage,
            legacy_blobs: legacy.get(0),
            legacy_bytes: legacy.get(1),
        },
    })
}

// ─── Integrity ───────────────────────────────────────────────────────────────

/// How many findings `/integrity` lists at most, and how many objects with
/// lost data.
const MAX_FINDINGS: i64 = 200;
const MAX_LOST: i64 = 500;
/// How long resolved findings are listed for.
const RESOLVED_DAYS: i32 = 30;

/// What the scrubber found (see `scrub`): damaged and missing copies, and the
/// objects with data that's intact on no replica.
#[derive(Serialize, ToSchema)]
pub(super) struct Integrity {
    /// The open findings, then those resolved in the last 30 days, newest
    /// first, up to 200.
    findings: Vec<FindingInfo>,
    open_findings: i64,
    /// Findings of the last day, by node: many of them in a short time are a
    /// sign of a failing disk.
    recent: Vec<NodeFindings>,
    /// The object versions (and uploads' parts) with lost bytes, the most
    /// recently lost first, up to 500.
    lost: Vec<LostObject>,
    /// How many there are, all told.
    lost_objects: i64,
}

#[derive(Serialize, ToSchema)]
struct FindingInfo {
    id: i64,
    blob_id: String,
    node: i32,
    found_at: f64,
    /// `missing`, `damaged`, or `catalog` (every block intact, but not the
    /// file's CRC).
    problem: String,
    /// How many blocks failed; none if the whole file is at fault.
    bad_blocks: Option<i64>,
    detail: String,
    /// `repaired`, `lost` (intact on no replica; still open), or `gone` (the
    /// blob was deleted); none while open.
    outcome: Option<String>,
    resolved_at: Option<f64>,
}

#[derive(Serialize, ToSchema)]
struct NodeFindings {
    node: i32,
    findings: i64,
}

#[derive(Serialize, ToSchema)]
struct LostObject {
    bucket: String,
    key: String,
    /// The version; none for a part of an upload in progress.
    version_id: Option<String>,
    upload_id: Option<String>,
    latest: bool,
    delete_marker: bool,
    size: i64,
    /// How many of its stored bytes are lost.
    lost_bytes: i64,
    /// When the first of them was found lost.
    since: f64,
}

#[utoipa::path(get, path = "/integrity", responses(
    (status = 200, body = Integrity),
    (status = "5XX", body = ErrorBody),
))]
async fn get_integrity(State(app): AppState) -> Result<Json<Integrity>> {
    Ok(Json(integrity(&app).await?))
}

pub(super) async fn integrity(app: &App) -> anyhow::Result<Integrity> {
    let client = app.pool.get().await?;
    let findings = client
        .query_cached(
            "SELECT id, blob_id, node, extract(epoch FROM found_at)::float8, problem,
                    cardinality(bad_blocks)::bigint, detail, outcome,
                    extract(epoch FROM resolved_at)::float8
             FROM scrub_findings
             WHERE resolved_at IS NULL OR resolved_at > NOW() - make_interval(days => $1)
             ORDER BY resolved_at IS NULL DESC, found_at DESC
             LIMIT $2",
            &[&RESOLVED_DAYS, &MAX_FINDINGS],
        )
        .await?
        .iter()
        .map(|r| FindingInfo {
            id: r.get(0),
            blob_id: r.get::<_, uuid::Uuid>(1).to_string(),
            node: r.get(2),
            found_at: r.get(3),
            problem: r.get(4),
            bad_blocks: r.get(5),
            detail: r.get(6),
            outcome: r.get(7),
            resolved_at: r.get(8),
        })
        .collect();
    let counts = client
        .query_one_cached(
            "SELECT count(*) FROM scrub_findings WHERE resolved_at IS NULL",
            &[],
        )
        .await?;
    let recent = client
        .query_cached(
            "SELECT node, count(*) FROM scrub_findings
             WHERE found_at > NOW() - INTERVAL '1 day'
             GROUP BY node ORDER BY node",
            &[],
        )
        .await?
        .iter()
        .map(|r| NodeFindings {
            node: r.get(0),
            findings: r.get(1),
        })
        .collect();
    // Each part's bytes that are lost, added up per object version or upload.
    // Lost ranges are disjoint, so their overlaps with a part add up.
    let lost_rows = client
        .query_cached(
            "WITH hit AS (
                 SELECT p.object_id, p.upload_id,
                        sum(least(l.stop, p.blob_offset + p.size)
                            - greatest(l.start, p.blob_offset))::bigint AS lost_bytes,
                        min(l.found_at) AS since
                 FROM lost_ranges l
                 JOIN parts p ON p.blob_id = l.blob_id
                             AND p.blob_offset < l.stop AND p.blob_offset + p.size > l.start
                 GROUP BY p.object_id, p.upload_id
             )
             SELECT coalesce(o.bucket, u.bucket), coalesce(o.key, u.key), o.version_id,
                    u.upload_id::text, coalesce(o.is_latest, false),
                    coalesce(o.is_delete_marker, false),
                    coalesce(o.size, (SELECT coalesce(sum(size), 0) FROM parts
                                      WHERE upload_id = u.upload_id))::bigint,
                    hit.lost_bytes, extract(epoch FROM hit.since)::float8,
                    count(*) OVER ()
             FROM hit
             LEFT JOIN objects o ON o.id = hit.object_id
             LEFT JOIN multipart_uploads u ON u.upload_id = hit.upload_id
             ORDER BY hit.since DESC
             LIMIT $1",
            &[&MAX_LOST],
        )
        .await?;
    let lost_objects = lost_rows.first().map_or(0, |r| r.get(9));
    let lost = lost_rows
        .iter()
        .map(|r| LostObject {
            bucket: r.get(0),
            key: r.get(1),
            version_id: r.get(2),
            upload_id: r.get(3),
            latest: r.get(4),
            delete_marker: r.get(5),
            size: r.get(6),
            lost_bytes: r.get(7),
            since: r.get(8),
        })
        .collect();
    Ok(Integrity {
        findings,
        open_findings: counts.get(0),
        recent,
        lost,
        lost_objects,
    })
}

// ─── Buckets ─────────────────────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub(super) struct BucketSummary {
    name: String,
    created_at: f64,
    versioning: Versioning,
    /// The KMS key of its default encryption (SSE-KMS), if it has one: what a
    /// write that asks for no encryption of its own is encrypted with.
    default_kms_key: Option<String>,
    /// Current versions that aren't delete markers.
    objects: i64,
    bytes: i64,
    /// Every version, delete markers too.
    versions: i64,
    version_bytes: i64,
    uploads: i64,
    /// Roles with a grant on the bucket.
    roles: i64,
    /// Its tags (PutBucketTagging), sorted by key.
    tags: Vec<Tag>,
    /// Whether its policy makes it public (GetBucketPolicyStatus).
    public: bool,
    /// Its public access block, if it has one.
    public_access_block: Option<crate::s3::buckets::public_access::Block>,
}

/// A tag of a bucket or an object version (see `s3::tags`).
#[derive(Serialize, ToSchema)]
pub(super) struct Tag {
    key: String,
    value: String,
}

/// Tags as the dashboard shows them, from their stored form.
fn tag_list(stored: &str) -> Vec<Tag> {
    crate::s3::tags::Tags::from_stored(stored)
        .iter()
        .map(|(key, value)| Tag { key: key.to_owned(), value: value.to_owned() })
        .collect()
}

#[utoipa::path(get, path = "/buckets", responses(
    (status = 200, body = Vec<BucketSummary>),
    (status = "5XX", body = ErrorBody),
))]
async fn list_buckets(State(app): AppState, Extension(actor): Extension<Actor>) -> Result<Json<Vec<BucketSummary>>> {
    let all = actor.allows(&app, "s3:ListAllMyBuckets", On::Account).await?;
    let mut buckets = buckets(&app).await?;
    buckets.retain(|b| actor.lists(all, &b.name));
    Ok(Json(buckets))
}

/// Every bucket (as ListBuckets lists them), with what's in it.
pub(super) async fn buckets(app: &App) -> anyhow::Result<Vec<BucketSummary>> {
    let buckets = bucket_list::buckets(app).await?;
    let client = app.pool.get().await?;
    let mut objects: HashMap<String, [i64; 4]> = client
        .query_cached(
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
            let rows = client.query_cached(&sql, &[]).await?;
            anyhow::Ok(
                rows.iter()
                    .map(|r| (r.get::<_, String>(0), r.get::<_, i64>(1)))
                    .collect::<HashMap<_, _>>(),
            )
        }
    };
    let uploads = counts("SELECT bucket, count(*) FROM multipart_uploads GROUP BY bucket").await?;
    let mut defaults: HashMap<String, String> = client
        .query_cached("SELECT name, sse_kms_key_id FROM buckets WHERE sse_kms_key_id IS NOT NULL", &[])
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    let roles =
        counts("SELECT bucket, count(DISTINCT role) FROM role_grants GROUP BY bucket").await?;
    let mut tags: HashMap<String, String> = client
        .query_cached("SELECT name, tags FROM buckets WHERE tags IS NOT NULL", &[])
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    // Each bucket's policy (whether it's public), and its block.
    let mut access: HashMap<String, (bool, Option<crate::s3::buckets::public_access::Block>)> = HashMap::new();
    for row in client.query_cached("SELECT name, policy, public_access_block FROM buckets", &[]).await? {
        let name: String = row.get(0);
        let public = match row.get::<_, Option<&str>>(1) {
            Some(text) => crate::policy::Policy::parse(text, crate::policy::Kind::Bucket(&name))
                .map_err(|e| anyhow::anyhow!("bucket {name}'s policy doesn't parse: {}", e.message))?
                .is_public(),
            None => false,
        };
        let block = row.get::<_, Option<i16>>(2).map(crate::s3::buckets::public_access::Block::from_bits);
        access.insert(name, (public, block));
    }
    Ok(buckets
        .into_iter()
        .map(|b| {
            let [objects, bytes, versions, version_bytes] =
                objects.remove(&b.name).unwrap_or_default();
            BucketSummary {
                uploads: uploads.get(&b.name).copied().unwrap_or(0),
                roles: roles.get(&b.name).copied().unwrap_or(0),
                default_kms_key: defaults.remove(&b.name),
                tags: tags.remove(&b.name).as_deref().map(tag_list).unwrap_or_default(),
                public: access.get(&b.name).is_some_and(|(public, _)| *public),
                public_access_block: access.remove(&b.name).and_then(|(_, block)| block),
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
async fn create_bucket(State(app): AppState, Extension(actor): Extension<Actor>, Json(body): Json<NewBucket>) -> Result<StatusCode> {
    actor.check(&app, "s3:CreateBucket", On::Bucket(body.name.clone())).await?;
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
async fn delete_bucket(State(app): AppState, Extension(actor): Extension<Actor>, Path(bucket): Path<String>) -> Result<StatusCode> {
    actor.check(&app, "s3:DeleteBucket", On::Bucket(bucket.clone())).await?;
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

// ─── Bucket access ───────────────────────────────────────────────────────────

/// Who may get at a bucket, besides its users' grants and policies: its
/// policy, and its public access block (see `s3::buckets::public_access`).
#[derive(Serialize, ToSchema)]
struct BucketAccess {
    /// Its policy, as GetBucketPolicy shows it; `null` if it has none.
    policy: Option<String>,
    /// Whether the policy makes the bucket public.
    public: bool,
    /// Its public access block; `null` if it has none.
    public_access_block: Option<crate::s3::buckets::public_access::Block>,
    /// The cluster's (only its policy flags count), which applies to every
    /// bucket as well.
    cluster: crate::s3::buckets::public_access::Block,
}

#[utoipa::path(get, path = "/buckets/{bucket}/access", params(("bucket" = String, Path)), responses(
    (status = 200, body = BucketAccess),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn get_bucket_access(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
) -> Result<Json<BucketAccess>> {
    use crate::s3::buckets::{policy, public_access};
    let on = || On::Bucket(bucket.clone());
    let checks = [
        Check { action: "s3:GetBucketPolicy", on: on() },
        Check { action: "s3:GetBucketPublicAccessBlock", on: on() },
    ];
    actor.check_all(&app, &checks).await?;
    let client = app.pool.get().await?;
    let no_bucket = || ApiError::NotFound(format!("no bucket named {bucket:?}"));
    let policy = policy::shown(&client, &bucket).await?.ok_or_else(no_bucket)?;
    let stored: Option<String> = client
        .query_opt_cached("SELECT policy FROM buckets WHERE name = $1", &[&bucket])
        .await?
        .ok_or_else(no_bucket)?
        .get(0);
    let public = match &stored {
        Some(text) => crate::policy::Policy::parse(text, crate::policy::Kind::Bucket(&bucket))
            .map_err(|e| anyhow::anyhow!("bucket {bucket}'s policy doesn't parse: {}", e.message))?
            .is_public(),
        None => false,
    };
    let public_access_block = public_access::get(&app, &bucket).await?.ok_or_else(no_bucket)?;
    Ok(Json(BucketAccess { policy, public, public_access_block, cluster: public_access::cluster(&client).await? }))
}

/// Sets a bucket's policy, as PutBucketPolicy does: checked as S3 checks
/// it, and refused if it's public while public policies are blocked.
#[utoipa::path(put, path = "/buckets/{bucket}/policy", params(("bucket" = String, Path)),
    request_body = PolicyDocument, responses(
        (status = 204, description = "Set"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn put_bucket_policy(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Json(body): Json<PolicyDocument>,
) -> Result<StatusCode> {
    actor.check(&app, "s3:PutBucketPolicy", On::Bucket(bucket.clone())).await?;
    use crate::s3::buckets::policy;
    let client = app.pool.get().await?;
    let checked = match policy::check(&client, &bucket, &body.document).await? {
        Ok(checked) => checked,
        Err(refused) => return Err(ApiError::BadRequest(refused.message)),
    };
    match policy::set(&client, &bucket, Some(&checked)).await? {
        policy::Set::Set => Ok(StatusCode::NO_CONTENT),
        policy::Set::Blocked => Err(ApiError::Forbidden(format!(
            "the policy makes the bucket public, and {}",
            policy::BLOCKED
        ))),
        policy::Set::NoSuchBucket => Err(ApiError::NotFound(format!("no bucket named {bucket:?}"))),
    }
}

/// Removes a bucket's policy.
#[utoipa::path(delete, path = "/buckets/{bucket}/policy", params(("bucket" = String, Path)), responses(
    (status = 204, description = "Removed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_bucket_policy(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
) -> Result<StatusCode> {
    actor.check(&app, "s3:DeleteBucketPolicy", On::Bucket(bucket.clone())).await?;
    use crate::s3::buckets::policy;
    match policy::set(&app.pool.get().await?, &bucket, None).await? {
        policy::Set::NoSuchBucket => Err(ApiError::NotFound(format!("no bucket named {bucket:?}"))),
        _ => Ok(StatusCode::NO_CONTENT),
    }
}

/// Sets a bucket's public access block, as PutPublicAccessBlock does.
#[utoipa::path(put, path = "/buckets/{bucket}/public-access-block", params(("bucket" = String, Path)),
    request_body = crate::s3::buckets::public_access::Block, responses(
        (status = 204, description = "Set"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn put_public_access_block(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Json(body): Json<crate::s3::buckets::public_access::Block>,
) -> Result<StatusCode> {
    actor.check(&app, "s3:PutBucketPublicAccessBlock", On::Bucket(bucket.clone())).await?;
    match crate::s3::buckets::public_access::set(&app, &bucket, Some(body)).await? {
        true => Ok(StatusCode::NO_CONTENT),
        false => Err(ApiError::NotFound(format!("no bucket named {bucket:?}"))),
    }
}

/// Removes a bucket's public access block: only the cluster's applies.
#[utoipa::path(delete, path = "/buckets/{bucket}/public-access-block", params(("bucket" = String, Path)), responses(
    (status = 204, description = "Removed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_public_access_block(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
) -> Result<StatusCode> {
    // DeletePublicAccessBlock is authorized as its put, in S3.
    actor.check(&app, "s3:PutBucketPublicAccessBlock", On::Bucket(bucket.clone())).await?;
    match crate::s3::buckets::public_access::set(&app, &bucket, None).await? {
        true => Ok(StatusCode::NO_CONTENT),
        false => Err(ApiError::NotFound(format!("no bucket named {bucket:?}"))),
    }
}

/// The cluster's public access block: its settings `block-public-policy`
/// and `restrict-public-buckets` (set with `PUT /settings/{name}`).
#[utoipa::path(get, path = "/public-access", responses(
    (status = 200, body = crate::s3::buckets::public_access::Block),
    (status = "5XX", body = ErrorBody),
))]
async fn get_public_access(State(app): AppState) -> Result<Json<crate::s3::buckets::public_access::Block>> {
    Ok(Json(crate::s3::buckets::public_access::cluster(&app.pool.get().await?).await?))
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
        /// Whether some of its bytes are intact on no replica (see `scrub`).
        lost: bool,
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
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Query(params): Query<ListParams>,
) -> Result<Json<Listing>> {
    // Delete markers are versions: listing them is ListObjectVersions.
    let action = if params.deleted.unwrap_or(false) { "s3:ListBucketVersions" } else { "s3:ListBucket" };
    actor.check(&app, action, On::Bucket(bucket.clone())).await?;
    let query = ListQuery {
        prefix: params.prefix.as_deref().unwrap_or(""),
        delimiter: Some("/"),
        marker: params.after.as_deref().unwrap_or(""),
        max_keys: PAGE,
        delete_markers: params.deleted.unwrap_or(false),
        totals: true,
    };
    Ok(Json(listing(&app, &bucket, &query).await?))
}

/// A page of `list`, for the dashboard.
pub(super) async fn listing(app: &App, bucket: &str, query: &ListQuery<'_>) -> Result<Listing> {
    let Some(listing) = crate::s3::objects::list::list(app, bucket, query).await? else {
        return Err(ApiError::NotFound(format!("no bucket named {bucket:?}")));
    };
    let mut entries = listing
        .entries
        .into_iter()
        .map(|e| match e {
            // The query asks for totals, and a common prefix holds a key.
            ListEntry::Prefix { prefix, totals } => {
                let totals = totals.expect("the dashboard's listings ask for totals");
                Entry::Prefix {
                    prefix,
                    objects: totals.objects,
                    bytes: totals.bytes,
                    last_modified: totals.last_modified.epoch,
                }
            }
            ListEntry::Object {
                key,
                size,
                etag,
                last_modified,
                delete_marker,
                ..
            } => Entry::Object {
                key,
                size,
                etag,
                last_modified: last_modified.epoch,
                delete_marker,
                lost: false,
            },
        })
        .collect::<Vec<_>>();
    mark_lost(app, bucket, &mut entries).await?;
    Ok(Listing {
        entries,
        next: listing.next_marker,
    })
}

/// Marks the objects in `entries` whose current version has lost bytes.
async fn mark_lost(app: &App, bucket: &str, entries: &mut [Entry]) -> anyhow::Result<()> {
    let client = app.pool.get().await?;
    // Almost always, nothing is lost anywhere: one cheap query.
    let any: bool = client
        .query_one_cached("SELECT EXISTS (SELECT 1 FROM lost_ranges)", &[])
        .await?
        .get(0);
    if !any {
        return Ok(());
    }
    let keys: Vec<&str> = entries
        .iter()
        .filter_map(|e| match e {
            Entry::Object { key, .. } => Some(key.as_str()),
            Entry::Prefix { .. } => None,
        })
        .collect();
    let lost: std::collections::HashSet<String> = client
        .query_cached(
            "SELECT DISTINCT o.key FROM objects o
             JOIN parts p ON p.object_id = o.id
             JOIN lost_ranges l ON l.blob_id = p.blob_id
                               AND l.start < p.blob_offset + p.size AND l.stop > p.blob_offset
             WHERE o.bucket = $1 AND o.key = ANY($2) AND o.is_latest",
            &[&bucket, &keys],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    for entry in entries {
        if let Entry::Object { key, lost: l, .. } = entry {
            *l = lost.contains(key.as_str());
        }
    }
    Ok(())
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
    /// How it's encrypted; none if it isn't.
    encryption: Option<EncryptionInfo>,
    /// Its tags, sorted by key.
    tags: Vec<Tag>,
    parts: Vec<PartInfo>,
    /// How many of its parts' bytes are intact on no replica.
    lost_bytes: i64,
}

/// How an object version is encrypted (see `s3::sse`).
#[derive(Serialize, ToSchema)]
struct EncryptionInfo {
    /// `SSE-C` (with its client's key, which Cairn doesn't have), `SSE-KMS`
    /// or `SSE-S3` (with Cairn's own key from the KMS).
    kind: String,
    /// SSE-KMS and SSE-S3: the name of the KMS key.
    kms_key_id: Option<String>,
    /// SSE-KMS and SSE-S3: the version of the KMS key its data key is from.
    kms_key_version: Option<i64>,
    /// SSE-KMS: the encryption context its client gave, as JSON.
    kms_context: Option<String>,
}

impl EncryptionInfo {
    fn of(stored: crate::s3::sse::Stored) -> Option<EncryptionInfo> {
        use crate::s3::sse::Stored;
        let s3 = matches!(stored, Stored::S3(_));
        match stored {
            Stored::Plain => None,
            Stored::Customer { .. } => Some(EncryptionInfo {
                kind: "SSE-C".to_owned(),
                kms_key_id: None,
                kms_key_version: None,
                kms_context: None,
            }),
            Stored::Kms(envelope) | Stored::S3(envelope) => Some(EncryptionInfo {
                kind: if s3 { "SSE-S3" } else { "SSE-KMS" }.to_owned(),
                // Transit's ciphertexts start `vault:v<version>:`.
                kms_key_version: envelope
                    .data_key
                    .strip_prefix("vault:v")
                    .and_then(|rest| rest.split(':').next())
                    .and_then(|version| version.parse().ok()),
                kms_key_id: Some(envelope.key_id),
                kms_context: envelope.context,
            }),
        }
    }
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
    /// The blob's data shards: 1 if it's replicated, else it's erasure-coded,
    /// and readable with as many live shards.
    data_shards: i32,
    created_at: f64,
    /// The nodes holding a shard of the blob.
    nodes: Vec<i32>,
    /// The byte ranges of the part (as stored) that are intact on no
    /// replica, as [start, stop) from its start (see `scrub`).
    lost: Vec<[i64; 2]>,
    /// Its salt, if it's encrypted, which its sealed ETag is bound to.
    #[serde(skip)]
    salt: Option<crate::encryption::Salt>,
}

#[utoipa::path(get, path = "/buckets/{bucket}/object", params(("bucket" = String, Path), KeyParams),
    responses(
        (status = 200, body = ObjectInfo),
        (status = "5XX", body = ErrorBody),
    ))]
async fn get_object(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Query(params): Query<KeyParams>,
) -> Result<Json<ObjectInfo>> {
    // As HeadObject, and its older versions as ListObjectVersions.
    actor.check(&app, "s3:GetObject", On::Object(bucket.clone(), params.key.clone())).await?;
    let mut info = object(&app, &bucket, &params.key).await?;
    if !actor.allows(&app, "s3:ListBucketVersions", On::Bucket(bucket.clone())).await? {
        info.versions.truncate(1);
    }
    // Where the parts are stored (blobs, nodes) is the operator's to know.
    if let Actor::User(_) = actor {
        info.versions.iter_mut().for_each(|v| v.parts.clear());
    }
    Ok(Json(info))
}

pub(super) async fn object(app: &App, bucket: &str, key: &str) -> anyhow::Result<ObjectInfo> {
    let client = app.pool.get().await?;
    let versions = client
        .query_cached(
            "SELECT id, version_id, is_latest, is_delete_marker, size, etag, content_type,
                    extract(epoch FROM last_modified)::float8, sse_c_key, sse_kms_key_id,
                    sse_kms_data_key, sse_kms_sealed, sse_kms_context, sse_s3, tags
             FROM objects WHERE bucket = $1 AND key = $2
             ORDER BY id DESC LIMIT $3",
            &[&bucket, &key, &MAX_VERSIONS],
        )
        .await?;
    let ids: Vec<i64> = versions.iter().map(|r| r.get(0)).collect();
    let mut parts: HashMap<i64, Vec<PartInfo>> = HashMap::new();
    for p in client
        .query_cached(
            "SELECT p.object_id, p.part_number, p.size, p.etag, p.crc64nvme, p.blob_id,
                    p.blob_offset, b.size, b.state, extract(epoch FROM p.created_at)::float8,
                    ARRAY(SELECT l.node FROM blob_locations l
                          WHERE l.blob_id = p.blob_id ORDER BY l.node),
                    b.data_shards::int, p.enc_salt
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
            data_shards: p.get(11),
            lost: Vec::new(),
            salt: p
                .get::<_, Option<&[u8]>>(12)
                .map(|salt| salt.try_into().expect("a salt is 16 bytes (parts_encrypted)")),
        });
    }
    // Where the parts' blobs have lost data, if anywhere.
    let blob_ids: Vec<uuid::Uuid> = parts
        .values()
        .flatten()
        .filter_map(|p| p.blob_id.parse().ok())
        .collect();
    let lost_ranges = client
        .query_cached(
            "SELECT blob_id, start, stop FROM lost_ranges WHERE blob_id = ANY($1) ORDER BY start",
            &[&blob_ids],
        )
        .await?;
    for part in parts.values_mut().flatten() {
        for r in &lost_ranges {
            let (start, stop): (i64, i64) = (r.get(1), r.get(2));
            let end = part.blob_offset + part.size;
            if r.get::<_, uuid::Uuid>(0).to_string() == part.blob_id
                && start < end
                && stop > part.blob_offset
            {
                part.lost.push([
                    start.max(part.blob_offset) - part.blob_offset,
                    stop.min(end) - part.blob_offset,
                ]);
            }
        }
    }
    let mut infos = Vec::with_capacity(versions.len());
    for v in &versions {
        let stored = crate::s3::sse::Stored::from_row(v, 8);
        let mut etag: Option<String> = v.get(5);
        let mut parts = parts.remove(&v.get::<_, i64>(0)).unwrap_or_default();
        // An SSE-S3 version's ETags (and its parts') are stored sealed; Cairn
        // can open them, as it can the version itself.
        if let Some(etag_key) = crate::s3::sse::etag_key(app, &stored, bucket, key).await?.ok().flatten() {
            let object = crate::encryption::Owner::Object { bucket, key };
            etag = etag.map(|e| etag_key.open(object, &e)).transpose()?;
            for part in &mut parts {
                let salt = part.salt.ok_or_else(|| anyhow::anyhow!("an SSE-S3 object's part has no salt"))?;
                part.etag = etag_key.open(crate::encryption::Owner::Part(&salt), &part.etag)?;
            }
        }
        infos.push(VersionInfo {
            version_id: v.get(1),
            latest: v.get(2),
            delete_marker: v.get(3),
            size: v.get(4),
            etag,
            content_type: v.get(6),
            last_modified: v.get(7),
            encryption: EncryptionInfo::of(stored),
            tags: tag_list(v.get(14)),
            lost_bytes: parts.iter().flat_map(|p| &p.lost).map(|[a, b]| b - a).sum(),
            parts,
        });
    }
    let versions = infos;
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
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Query(params): Query<DownloadParams>,
) -> Result<Response> {
    let action = if params.version.is_some() { "s3:GetObjectVersion" } else { "s3:GetObject" };
    actor.check(&app, action, On::Object(bucket.clone(), params.key.clone())).await?;
    let resp = crate::s3::objects::get::get_object(
        &app,
        &bucket,
        &params.key,
        params.version.as_deref(),
        None,
        None,
        &Preconditions::default(),
        None,
        // As the user, whom the KMS lets open SSE-KMS objects with keys
        // it may use; the operator has no identity there, so it can't (see
        // `s3::sse`).
        actor.kms_role(),
        false,
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

/// An S3 handler's error response as the API's: its status, and its
/// message (or code).
async fn s3_error(resp: hyper::Response<http_body_util::Full<hyper::body::Bytes>>) -> ApiError {
    let status = resp.status();
    let body = resp.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
    let text = String::from_utf8_lossy(&body);
    let element = |name: &str| {
        let open = format!("<{name}>");
        let start = text.find(&open)? + open.len();
        let end = text[start..].find(&format!("</{name}>"))?;
        Some(text[start..start + end].to_owned())
    };
    let message = element("Message").filter(|m| !m.is_empty()).or_else(|| element("Code")).unwrap_or_default();
    match status {
        StatusCode::NOT_FOUND => ApiError::NotFound(message),
        StatusCode::FORBIDDEN => ApiError::Forbidden(message),
        StatusCode::CONFLICT => ApiError::Conflict(message),
        s if s.is_client_error() => ApiError::BadRequest(message),
        _ => ApiError::Failed(anyhow::anyhow!("S3 handler answered {status}: {message}")),
    }
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct UploadParams {
    key: String,
}

/// Writes an object from the request's body, as PutObject does (with the
/// bucket's default encryption, and as the user for SSE-KMS); its
/// `Content-Type` is the object's. At most 5 GiB, as a single PutObject.
#[utoipa::path(put, path = "/buckets/{bucket}/object", params(("bucket" = String, Path), UploadParams),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses(
        (status = 204, description = "Written"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn upload(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Query(params): Query<UploadParams>,
    headers: axum::http::HeaderMap,
    body: Body,
) -> Result<StatusCode> {
    actor.check(&app, "s3:PutObject", On::Object(bucket.clone(), params.key.clone())).await?;
    if !crate::s3::util::is_well_formed(&params.key) || params.key.is_empty() || params.key.len() > 1024 {
        return Err(ApiError::BadRequest("a key is 1 to 1024 bytes of UTF-8, without control characters".into()));
    }
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .unwrap_or("application/octet-stream");
    let length = headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()?.parse().ok());
    let payload = length.map_or_else(crate::payload::Payload::unchecked, crate::payload::Payload::unchecked_of);
    let payload = payload
        .at_most(crate::s3::util::MAX_UPLOAD)
        .map_err(|_| ApiError::BadRequest("an upload is at most 5 GiB".into()))?;
    let resp = crate::s3::objects::put::put_object(
        &app,
        &bucket,
        &params.key,
        content_type,
        "",
        "",
        body,
        payload,
        &Preconditions::default(),
        crate::s3::sse::Wanted::Plain,
        actor.kms_role(),
    )
    .await?;
    match resp.status() {
        StatusCode::OK => Ok(StatusCode::NO_CONTENT),
        _ => Err(s3_error(resp).await),
    }
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct DeleteParams {
    key: String,
    /// The version to remove for good; without it, the key is deleted as
    /// DeleteObject does (a delete marker, in a versioned bucket).
    version: Option<String>,
}

/// Deletes a key, or one of its versions, as DeleteObject does.
#[utoipa::path(delete, path = "/buckets/{bucket}/object", params(("bucket" = String, Path), DeleteParams),
    responses(
        (status = 204, description = "Deleted"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn delete_object(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Query(params): Query<DeleteParams>,
) -> Result<StatusCode> {
    let action = crate::s3::actions::delete(params.version.is_some());
    actor.check(&app, action, On::Object(bucket.clone(), params.key.clone())).await?;
    let resp = crate::s3::objects::delete::delete_object(&app, &bucket, &params.key, params.version.as_deref()).await?;
    match resp.status() {
        StatusCode::NO_CONTENT | StatusCode::OK => Ok(StatusCode::NO_CONTENT),
        _ => Err(s3_error(resp).await),
    }
}

#[derive(Deserialize, ToSchema)]
struct NewVersioning {
    /// `Enabled` or `Suspended`.
    status: String,
}

/// Enables or suspends a bucket's versioning, as PutBucketVersioning does.
#[utoipa::path(put, path = "/buckets/{bucket}/versioning", params(("bucket" = String, Path)),
    request_body = NewVersioning, responses(
        (status = 204, description = "Set"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn set_versioning(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Json(body): Json<NewVersioning>,
) -> Result<StatusCode> {
    if !matches!(body.status.as_str(), "Enabled" | "Suspended") {
        return Err(ApiError::BadRequest("versioning is Enabled or Suspended".into()));
    }
    actor.check(&app, "s3:PutBucketVersioning", On::Bucket(bucket.clone())).await?;
    let xml = format!("<VersioningConfiguration><Status>{}</Status></VersioningConfiguration>", body.status);
    let resp = crate::s3::buckets::versioning::put_bucket_versioning(&app, &bucket, xml.into()).await?;
    match resp.status() {
        StatusCode::OK => Ok(StatusCode::NO_CONTENT),
        _ => Err(s3_error(resp).await),
    }
}

// ─── Roles ───────────────────────────────────────────────────────────────────

/// A role, never with its secret.
#[derive(Serialize, ToSchema)]
pub(super) struct RoleSummary {
    name: String,
    /// Its ID, which never changes or comes back: its name (alias) in the
    /// KMS's auth mount for Cairn.
    id: String,
    /// Its identity (entity) in the KMS, which key owners grant keys to;
    /// none until Cairn has logged in as it, or without a KMS.
    kms_entity_id: Option<String>,
    admin: bool,
    created_at: f64,
    grants: Vec<Grant>,
    /// Its access keys, oldest first (never their secrets).
    keys: Vec<AccessKey>,
    /// The names of its inline policies.
    policies: Vec<String>,
}

#[derive(Serialize, ToSchema)]
struct AccessKey {
    id: String,
    active: bool,
    created_at: f64,
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
            id: r.id.to_string(),
            kms_entity_id: r.kms_entity_id,
            admin: r.admin,
            created_at: r.created_at,
            grants: r
                .grants
                .into_iter()
                .map(|(bucket, permission)| Grant { bucket, permission })
                .collect(),
            keys: r
                .keys
                .into_iter()
                .map(|k| AccessKey { id: k.id, active: k.active, created_at: k.created_at })
                .collect(),
            policies: r.policies,
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
    // Its identity in the KMS, so that key owners can grant it keys now; if
    // the KMS can't be reached, the next maintenance pass makes it. In the
    // background: a slow KMS mustn't hold up the role.
    let identifying = app.clone();
    tokio::spawn(async move {
        if let Err(e) = roles::identify(&identifying).await {
            eprintln!("kms: identifying roles: {e:#}");
        }
    });
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

/// Logs in to the KMS as each role without an identity there yet, from this
/// node, now rather than at its next maintenance pass. Fails with what went
/// wrong.
#[utoipa::path(post, path = "/kms/identify", responses(
    (status = 204, description = "Every role has its identity in the KMS"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn identify_roles(State(app): AppState) -> Result<StatusCode> {
    if app.kms.is_none() {
        return Err(ApiError::BadRequest("this node has no KMS".into()));
    }
    roles::identify(&app).await.map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;
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

// ─── Console enrollment ──────────────────────────────────────────────────────

/// A one-time link for a role to register its first passkey for the
/// console, valid 24 hours.
#[derive(Serialize, ToSchema)]
struct Enrollment {
    /// The link, if this node serves the console (and so knows its URL).
    url: Option<String>,
    /// The link's path, for the console's URL.
    path: String,
}

/// Makes a role an enrollment link for the console, replacing its last.
#[utoipa::path(post, path = "/roles/{role}/enrollment", params(("role" = String, Path)), responses(
    (status = 201, body = Enrollment),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_enrollment(State(app): AppState, Path(role): Path<String>) -> Result<(StatusCode, Json<Enrollment>)> {
    let token = crate::console::store::create_enrollment(&app.pool.get().await?, &role).await?;
    let path = format!("/enroll#{token}");
    let url = app.dashboard.console_origin.as_ref().map(|origin| format!("{origin}{path}"));
    Ok((StatusCode::CREATED, Json(Enrollment { url, path })))
}

// ─── Access keys ─────────────────────────────────────────────────────────────

/// A new access key, whose secret is shown only this once.
#[derive(Serialize, ToSchema)]
struct NewKey {
    id: String,
    secret: String,
}

/// Makes a new access key for a role, with a random ID and secret; a role
/// has at most two.
#[utoipa::path(post, path = "/roles/{role}/keys", params(("role" = String, Path)), responses(
    (status = 201, body = NewKey),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_key(State(app): AppState, Path(role): Path<String>) -> Result<(StatusCode, Json<NewKey>)> {
    let (id, secret) = roles::create_key(&app.pool.get().await?, &role, None, None).await?;
    Ok((StatusCode::CREATED, Json(NewKey { id, secret })))
}

#[derive(Deserialize, ToSchema)]
struct KeyState {
    active: bool,
}

/// Lets one of the role's access keys sign requests, or stops it.
#[utoipa::path(put, path = "/roles/{role}/keys/{key}", params(("role" = String, Path), ("key" = String, Path)),
    request_body = KeyState, responses(
        (status = 204, description = "Changed"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn set_key(
    State(app): AppState,
    Path((role, key)): Path<(String, String)>,
    Json(body): Json<KeyState>,
) -> Result<StatusCode> {
    roles::set_key_active(&app.pool.get().await?, Some(&role), &key, body.active).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes one of the role's access keys.
#[utoipa::path(delete, path = "/roles/{role}/keys/{key}", params(("role" = String, Path), ("key" = String, Path)),
    responses(
        (status = 204, description = "Deleted"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn delete_key(State(app): AppState, Path((role, key)): Path<(String, String)>) -> Result<StatusCode> {
    roles::delete_key(&app.pool.get().await?, Some(&role), &key).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Inline policies ─────────────────────────────────────────────────────────

/// An inline policy: a JSON document in IAM's policy language.
#[derive(Serialize, Deserialize, ToSchema)]
struct PolicyDocument {
    document: String,
}

/// One of the role's inline policies, as it was set.
#[utoipa::path(get, path = "/roles/{role}/policies/{policy}",
    params(("role" = String, Path), ("policy" = String, Path)), responses(
        (status = 200, body = PolicyDocument),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn get_policy(State(app): AppState, Path((role, policy)): Path<(String, String)>) -> Result<Json<PolicyDocument>> {
    let document = roles::get_policy(&app.pool.get().await?, &role, &policy).await?;
    Ok(Json(PolicyDocument { document }))
}

/// Sets one of the role's inline policies, if it's a valid identity policy.
#[utoipa::path(put, path = "/roles/{role}/policies/{policy}",
    params(("role" = String, Path), ("policy" = String, Path)), request_body = PolicyDocument, responses(
        (status = 204, description = "Set"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn put_policy(
    State(app): AppState,
    Path((role, policy)): Path<(String, String)>,
    Json(body): Json<PolicyDocument>,
) -> Result<StatusCode> {
    roles::put_policy(&app.pool.get().await?, &role, &policy, &body.document).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes one of the role's inline policies.
#[utoipa::path(delete, path = "/roles/{role}/policies/{policy}",
    params(("role" = String, Path), ("policy" = String, Path)), responses(
        (status = 204, description = "Deleted"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn delete_policy(State(app): AppState, Path((role, policy)): Path<(String, String)>) -> Result<StatusCode> {
    roles::delete_policy(&app.pool.get().await?, &role, &policy).await?;
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

    /// What the scrubber found: coverage, findings, lost data, and which
    /// objects it's in.
    #[tokio::test]
    async fn reports_integrity() {
        let Some(app) = node().await else { return };
        put(&app, "damaged", vec![1; 300_000]).await;
        put(&app, "intact", vec![2; 1000]).await;
        let blob_id: uuid::Uuid = app
            .pool
            .get()
            .await
            .unwrap()
            .query_one(
                "SELECT p.blob_id FROM parts p JOIN objects o ON o.id = p.object_id
                 WHERE o.key = 'damaged'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let path = app.store.blob_path(blob_id);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[70_000] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        let pacer = crate::scrub::Pacer::new(None);
        crate::scrub::pass(&app, crate::scrub::Scope::Everything, &pacer).await.unwrap();

        let s = serde_json::to_value(storage(&app).await.unwrap()).unwrap();
        let coverage = &s["integrity"]["nodes"][0];
        assert_eq!((coverage["copies"].clone(), coverage["unchecked"].clone()), (json!(2), json!(0)));
        assert!(coverage["oldest_checked"].is_f64());
        assert_eq!(s["integrity"]["legacy_blobs"], 0);

        let i = serde_json::to_value(integrity(&app).await.unwrap()).unwrap();
        assert_eq!(i["open_findings"], 1);
        assert_eq!(i["findings"][0]["problem"], "damaged");
        assert_eq!(i["findings"][0]["outcome"], "lost");
        assert_eq!(i["findings"][0]["bad_blocks"], 1);
        assert_eq!(i["recent"], json!([{ "node": app.node, "findings": 1 }]));
        assert_eq!(i["lost_objects"], 1);
        assert_eq!(i["lost"][0]["key"], "damaged");
        assert_eq!(i["lost"][0]["latest"], true);
        assert_eq!(i["lost"][0]["lost_bytes"], 65536);

        let query = ListQuery {
            prefix: "",
            delimiter: Some("/"),
            marker: "",
            max_keys: PAGE,
            delete_markers: false,
            totals: true,
        };
        let l = serde_json::to_value(listing(&app, BUCKET, &query).await.unwrap()).unwrap();
        assert_eq!(l["entries"][0]["key"], "damaged");
        assert_eq!(l["entries"][0]["lost"], true);
        assert_eq!(l["entries"][1]["lost"], false);

        let o = serde_json::to_value(object(&app, BUCKET, "damaged").await.unwrap()).unwrap();
        assert_eq!(o["versions"][0]["lost_bytes"], 65536);
        assert_eq!(o["versions"][0]["parts"][0]["lost"], json!([[65536, 131072]]));

        // Once the object is deleted, it's not listed, and its finding is gone.
        delete(&app, "damaged").await;
        crate::scrub::pass(&app, crate::scrub::Scope::Everything, &pacer).await.unwrap();
        let i = serde_json::to_value(integrity(&app).await.unwrap()).unwrap();
        assert_eq!(i["lost_objects"], 0);
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
            json!([{ "data_shards": 1, "live": 1, "copies": 1, "blobs": 3, "bytes": 60 }])
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
            totals: true,
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
        assert!(o["versions"][0]["encryption"].is_null());

        let c = serde_json::to_value(cluster(&app).await.unwrap()).unwrap();
        assert_eq!(c["nodes"][0]["stats"]["node"], app.node);
        assert!(c["nodes"][0]["stats"]["requests"]["ops"].is_array());
    }

    #[test]
    fn tells_how_a_version_is_encrypted() {
        use crate::s3::sse::{Envelope, Stored};
        assert!(EncryptionInfo::of(Stored::Plain).is_none());
        let sse_c = EncryptionInfo::of(Stored::Customer { check: vec![0; 48] }).unwrap();
        assert_eq!((sse_c.kind.as_str(), sse_c.kms_key_id), ("SSE-C", None));
        let kms = EncryptionInfo::of(Stored::Kms(Envelope {
            key_id: "cairn-a".to_owned(),
            data_key: "vault:v12:AAAA".to_owned(),
            sealed: vec![0; 72],
            context: Some(r#"{"a":"b"}"#.to_owned()),
        }))
        .unwrap();
        assert_eq!(kms.kind, "SSE-KMS");
        assert_eq!(kms.kms_key_id.as_deref(), Some("cairn-a"));
        assert_eq!(kms.kms_key_version, Some(12));
        assert_eq!(kms.kms_context.as_deref(), Some(r#"{"a":"b"}"#));
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

    /// The redundancy settings, and removing nodes, as the dashboard
    /// changes them.
    #[tokio::test]
    async fn sets_redundancy_and_removes_nodes() {
        let Some(app) = node().await else { return };
        let client = app.pool.get().await.unwrap();
        let set = |name: &str, value: Value| {
            request("PUT", &format!("/_dashboard/api/settings/{name}"), Some(serde_json::json!({"value": value})))
        };
        // A single node: 3 copies take more than it has.
        let (status, _, body) = send(&app, set("parity-shards", 2.into())).await;
        assert_eq!(status, StatusCode::OK);
        let warnings = serde_json::from_slice::<Value>(&body).unwrap()["warnings"].clone();
        assert!(warnings[0].as_str().unwrap().contains("uploads fail"), "{warnings}");
        assert_eq!(crate::settings::PARITY_SHARDS.get_set(&client).await.unwrap(), Some(2));
        assert_eq!(app.parity_shards(), 2, "the node answering goes by it at once");
        let storage = serde_json::to_value(storage(&app).await.unwrap()).unwrap();
        assert_eq!(storage["packer"]["parity_setting"], 2);
        let (status, _, _) = send(&app, set("parity-shards", Value::Null)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(crate::settings::PARITY_SHARDS.get_set(&client).await.unwrap(), None);
        assert_eq!(app.parity_shards(), 0, "the flag again");
        let (status, _, _) = send(&app, set("repair-after", 30.into())).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(crate::settings::REPAIR_AFTER.get(&client).await.unwrap(), 30);
        let (status, _, body) = send(&app, set("data-shards", 0.into())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(error_of(&body).contains("from 1 to"), "{}", error_of(&body));
        assert_eq!(send(&app, set("lifecycle-rate", 1.into())).await.0, StatusCode::NOT_FOUND);

        let node = app.node;
        let remove = request("POST", &format!("/_dashboard/api/nodes/{node}/remove"), None);
        let (status, _, body) = send(&app, remove).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["shards"], 0);
        let again = request("POST", &format!("/_dashboard/api/nodes/{node}/remove"), None);
        assert_eq!(send(&app, again).await.0, StatusCode::CONFLICT);
        let keep = request("POST", &format!("/_dashboard/api/nodes/{node}/keep"), None);
        assert_eq!(send(&app, keep).await.0, StatusCode::NO_CONTENT);
        let cluster = serde_json::to_value(cluster(&app).await.unwrap()).unwrap();
        assert_eq!(cluster["nodes"][0]["state"], "active");
        let missing = request("POST", "/_dashboard/api/nodes/9999/keep", None);
        assert_eq!(send(&app, missing).await.0, StatusCode::NOT_FOUND);
    }

    fn error_of(body: &[u8]) -> String {
        serde_json::from_slice::<Value>(body).unwrap()["error"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    use axum::http::HeaderMap;

    #[tokio::test]
    async fn edits_lifecycle_rules() {
        let Some(app) = node().await else { return };
        let path = format!("/_dashboard/api/buckets/{}/lifecycle", crate::e2e::BUCKET);
        let (status, _, body) = send(&app, request("GET", &path, None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["configuration"], Value::Null);

        let rules = serde_json::json!({"rules": [
            {"enabled": true, "filter": {"prefix": "tmp/"}, "expiration": {"days": 1}},
        ]});
        let (status, _, _) = send(&app, request("PUT", &path, Some(rules))).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, _, body) = send(&app, request("GET", &path, None)).await;
        let stored: Value = serde_json::from_slice(&body).unwrap();
        let rule = &stored["configuration"]["rules"][0];
        assert_eq!(rule["filter"]["prefix"], "tmp/");
        // It was given a name.
        assert_eq!(rule["id"].as_str().unwrap().len(), 32);
        // S3 sees the same rules.
        let xml = crate::s3::buckets::lifecycle::get_bucket_lifecycle(&app, crate::e2e::BUCKET).await.unwrap();
        let xml = xml.into_body().collect().await.unwrap().to_bytes();
        assert!(std::str::from_utf8(&xml).unwrap().contains("<Prefix>tmp/</Prefix>"));
        // And the Jobs page lists the bucket.
        let (_, _, body) = send(&app, request("GET", "/_dashboard/api/lifecycle", None)).await;
        let status_: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(status_["buckets"][0]["bucket"], crate::e2e::BUCKET);
        assert_eq!(status_["rate"], crate::settings::LIFECYCLE_RATE.default);

        // Rules S3 would refuse are refused, with why.
        let bad = serde_json::json!({"rules": [
            {"id": "a", "enabled": true, "filter": {"size_less_than": 5}, "abort_upload_days": 1},
        ]});
        let (status, _, body) = send(&app, request("PUT", &path, Some(bad))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(error_of(&body).contains("cannot be specified with Object Size"), "{}", error_of(&body));
        let unknown = serde_json::json!({"rules": [{"id": "a", "enabled": true, "filter": {"tag": "x"}}]});
        assert!(send(&app, request("PUT", &path, Some(unknown))).await.0.is_client_error());
        let missing = request("PUT", "/_dashboard/api/buckets/nope/lifecycle", Some(serde_json::json!({"rules": [
            {"enabled": true, "filter": {}, "expiration": {"days": 1}},
        ]})));
        assert_eq!(send(&app, missing).await.0, StatusCode::NOT_FOUND);

        // The rate, for the cluster.
        let (status, _, _) =
            send(&app, request("PUT", "/_dashboard/api/lifecycle/rate", Some(serde_json::json!({"rate": 5})))).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(crate::settings::LIFECYCLE_RATE.get(&app.pool.get().await.unwrap()).await.unwrap(), 5);
        let negative = request("PUT", "/_dashboard/api/lifecycle/rate", Some(serde_json::json!({"rate": -1})));
        assert_eq!(send(&app, negative).await.0, StatusCode::BAD_REQUEST);

        let (status, _, _) = send(&app, request("DELETE", &path, None)).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, _, body) = send(&app, request("GET", &path, None)).await;
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["configuration"], Value::Null);
    }

    /// A bucket's policy and public access block, and the cluster's block.
    #[tokio::test]
    async fn edits_bucket_access() {
        let Some(app) = node().await else { return };
        let bucket = crate::e2e::BUCKET;
        let access = format!("/_dashboard/api/buckets/{bucket}/access");
        let get = || async { serde_json::from_slice::<Value>(&send(&app, request("GET", &access, None)).await.2).unwrap() };
        let all = serde_json::json!({
            "block_public_acls": true, "ignore_public_acls": true,
            "block_public_policy": true, "restrict_public_buckets": true,
        });
        let first = get().await;
        assert_eq!((&first["policy"], &first["public"]), (&Value::Null, &Value::Bool(false)));
        assert_eq!(first["public_access_block"], all);
        assert_eq!(first["cluster"]["block_public_policy"], false);

        let document = format!(
            r#"{{"Statement":[{{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::{bucket}/*"}}]}}"#
        );
        let policy = format!("/_dashboard/api/buckets/{bucket}/policy");
        let put = || request("PUT", &policy, Some(serde_json::json!({ "document": document })));
        let (status, _, body) = send(&app, put()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(error_of(&body).contains("BlockPublicPolicy"), "{}", error_of(&body));
        let block = format!("/_dashboard/api/buckets/{bucket}/public-access-block");
        let none = serde_json::json!({
            "block_public_acls": false, "ignore_public_acls": false,
            "block_public_policy": false, "restrict_public_buckets": true,
        });
        assert_eq!(send(&app, request("PUT", &block, Some(none.clone()))).await.0, StatusCode::NO_CONTENT);
        assert_eq!(send(&app, put()).await.0, StatusCode::NO_CONTENT);
        let after = get().await;
        assert_eq!((&after["public"], &after["public_access_block"]), (&Value::Bool(true), &none));
        assert!(after["policy"].as_str().unwrap().contains(r#""Principal":"*""#));
        let bad = request("PUT", &policy, Some(serde_json::json!({ "document": "{}" })));
        assert_eq!(send(&app, bad).await.0, StatusCode::BAD_REQUEST);
        // The bucket list tells too.
        let (_, _, body) = send(&app, request("GET", "/_dashboard/api/buckets", None)).await;
        let listed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(listed[0]["public"], true);

        // The cluster's block.
        let setting = |value| request("PUT", "/_dashboard/api/settings/block-public-policy", Some(serde_json::json!({ "value": value })));
        assert_eq!(send(&app, setting(1)).await.0, StatusCode::OK);
        assert_eq!(get().await["cluster"]["block_public_policy"], true);
        assert_eq!(send(&app, request("DELETE", &policy, None)).await.0, StatusCode::NO_CONTENT);
        assert_eq!(send(&app, put()).await.0, StatusCode::FORBIDDEN);
        let (_, _, body) = send(&app, request("GET", "/_dashboard/api/public-access", None)).await;
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["block_public_policy"], true);
        assert_eq!(send(&app, setting(2)).await.0, StatusCode::BAD_REQUEST);

        assert_eq!(send(&app, request("DELETE", &block, None)).await.0, StatusCode::NO_CONTENT);
        assert_eq!(get().await["public_access_block"], Value::Null);
        assert_eq!(send(&app, request("GET", "/_dashboard/api/buckets/nope/access", None)).await.0, StatusCode::NOT_FOUND);
    }

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
        // A link to enroll a passkey for the console (this node serves none).
        let (status, _, body) = send(&app, request("POST", &format!("{api}/roles/ui-role/enrollment"), None)).await;
        assert_eq!(status, StatusCode::CREATED);
        let enrollment: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(enrollment["url"], Value::Null);
        assert!(enrollment["path"].as_str().unwrap().starts_with("/enroll#"));
        // Its access keys and inline policies.
        let (status, _, body) = send(&app, request("POST", &format!("{api}/roles/ui-role/keys"), None)).await;
        assert_eq!(status, StatusCode::CREATED);
        let key: Value = serde_json::from_slice(&body).unwrap();
        let key = key["id"].as_str().unwrap().to_owned();
        let uri = format!("{api}/roles/ui-role/keys/{key}");
        let inactive = json!({ "active": false });
        assert_eq!(send(&app, request("PUT", &uri, Some(inactive))).await.0, StatusCode::NO_CONTENT);
        let (_, _, body) = send(&app, request("GET", &format!("{api}/roles"), None)).await;
        let roles: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(roles[0]["keys"][1]["id"], key.as_str());
        assert_eq!(roles[0]["keys"][1]["active"], false);
        // Only its own keys.
        let uri_other = format!("{api}/roles/ui-role/keys/nobody");
        assert_eq!(send(&app, request("DELETE", &uri_other, None)).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(send(&app, request("DELETE", &uri, None)).await.0, StatusCode::NO_CONTENT);
        let uri = format!("{api}/roles/ui-role/policies/nolist");
        let document = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:ListBucket","Resource":"*"}]}"#;
        let body = json!({ "document": document });
        assert_eq!(send(&app, request("PUT", &uri, Some(body))).await.0, StatusCode::NO_CONTENT);
        let (status, _, body) = send(&app, request("GET", &uri, None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["document"], document);
        let bad = json!({ "document": r#"{"Statement":[{"Effect":"Allow"}]}"# });
        let (status, _, body) = send(&app, request("PUT", &uri, Some(bad))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error_of(&body), "MalformedPolicy: Missing required field Action");
        let (_, _, body) = send(&app, request("GET", &format!("{api}/roles"), None)).await;
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()[0]["policies"], json!(["nolist"]));
        assert_eq!(send(&app, request("DELETE", &uri, None)).await.0, StatusCode::NO_CONTENT);
        assert_eq!(send(&app, request("GET", &uri, None)).await.0, StatusCode::BAD_REQUEST);

        let uri = format!("{api}/roles/nobody");
        let (status, _, body) = send(&app, request("DELETE", &uri, None)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error_of(&body), "no user named \"nobody\"");

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

// ─── Lifecycle ───────────────────────────────────────────────────────────────

/// How lifecycle sweeps are going (see `lifecycle`).
#[derive(Serialize, Deserialize, ToSchema)]
struct Lifecycle {
    /// Object versions sweeps may read per hour, across the cluster; 0 if
    /// they're paused.
    rate: i64,
    /// The rate's default.
    default_rate: i64,
    /// Versions a round of every bucket's sweep reads: the last whole sweep
    /// of each, or what its first has read so far.
    round_versions: i64,
    /// Whether some bucket has had no whole sweep yet, so that a round reads
    /// more than `round_versions`.
    round_partial: bool,
    /// The rate steps have actually reached when they had more to do than
    /// their share (an average over about the last hour), if they have.
    /// Below `rate` if a step at a time can't go faster.
    reached_rate: Option<f64>,
    /// When that was last measured.
    reached_at: Option<f64>,
    /// How long a round takes at the rate reached, or set if it's lower (or
    /// none was measured yet), in seconds; none if paused. Over a day, sweeps
    /// fall behind, and expirations come that much later.
    round_secs: Option<f64>,
    /// When the last step began, and whether one is running now.
    last_step: Option<f64>,
    stepping: bool,
    buckets: Vec<LifecycleBucket>,
}

/// A bucket's rules, and its sweep of them.
#[derive(Serialize, Deserialize, ToSchema)]
struct LifecycleBucket {
    bucket: String,
    /// How many rules it has, and how many of them are enabled.
    rules: usize,
    enabled: usize,
    /// When it gets its next turn: its next sweep, or, during one, its next
    /// step (it's due if that's past).
    due: Option<f64>,
    sweep: Option<SweepProgress>,
    last: Option<crate::lifecycle::LastSweep>,
}

/// A sweep in progress.
#[derive(Serialize, Deserialize, ToSchema)]
struct SweepProgress {
    started: f64,
    /// The key it has got to.
    key: String,
    read: i64,
    expired: i64,
    removed: i64,
    aborted: i64,
}

/// How lifecycle sweeps are going: the rate, how long a round takes at it,
/// and each bucket's sweep.
#[utoipa::path(get, path = "/lifecycle", responses(
    (status = 200, body = Lifecycle),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn get_lifecycle(State(app): AppState) -> Result<Json<Lifecycle>> {
    let client = app.pool.get().await?;
    let rate = crate::settings::LIFECYCLE_RATE.get(&client).await?;
    let runs = client
        .query_one_cached(
            "SELECT extract(epoch FROM last_step)::float8, coalesce(lease_until > now(), false),
                    reached_rate, extract(epoch FROM reached_at)::float8
             FROM lifecycle_runs WHERE id",
            &[],
        )
        .await?;
    let rows = client
        .query_cached(
            "SELECT b.name, b.lifecycle, extract(epoch FROM s.due)::float8,
                    extract(epoch FROM s.started)::float8, s.cursor, s.seen,
                    s.expired, s.removed, s.aborted, s.last
             FROM buckets b JOIN lifecycle_sweeps s ON s.bucket = b.name
             WHERE b.lifecycle IS NOT NULL ORDER BY b.name",
            &[],
        )
        .await?;
    let mut buckets = Vec::new();
    let (mut round_versions, mut round_partial) = (0, false);
    for row in rows {
        let bucket: String = row.get(0);
        let config = crate::lifecycle::rules::Configuration::from_json(row.get(1));
        let (rules, enabled) = match &config {
            Ok(config) => (config.rules.len(), config.rules.iter().filter(|r| r.enabled).count()),
            Err(_) => (0, 0),
        };
        let last: Option<String> = row.get(9);
        let last = last.and_then(|last| serde_json::from_str::<crate::lifecycle::LastSweep>(&last).ok());
        let started: Option<f64> = row.get(3);
        let sweep = started.map(|started| SweepProgress {
            started,
            key: row.get::<_, Option<String>>(4).unwrap_or_default(),
            read: row.get(5),
            expired: row.get(6),
            removed: row.get(7),
            aborted: row.get(8),
        });
        let read_now = sweep.as_ref().map_or(0, |s| s.read);
        match &last {
            Some(last) => round_versions += last.read.max(read_now),
            None => {
                round_versions += read_now;
                round_partial = true;
            }
        }
        buckets.push(LifecycleBucket { bucket, rules, enabled, due: row.get(2), sweep, last });
    }
    let reached_rate: Option<f64> = runs.get(2);
    let effective = reached_rate.map_or(rate as f64, |reached| reached.min(rate as f64));
    Ok(Json(Lifecycle {
        rate,
        reached_rate,
        reached_at: runs.get(3),
        default_rate: crate::settings::LIFECYCLE_RATE.default,
        round_versions,
        round_partial,
        round_secs: (rate > 0 && effective > 0.0).then(|| round_versions as f64 / effective * 3600.0),
        last_step: runs.get(0),
        stepping: runs.get(1),
        buckets,
    }))
}

#[derive(Deserialize, ToSchema)]
struct NewRate {
    /// Object versions per hour, across the cluster; 0 pauses sweeps.
    rate: i64,
}

/// Sets the rate lifecycle sweeps go at, for the whole cluster.
/// A cluster setting's new value; `null` unsets it (it's back to its
/// default, or for `parity-shards`, every node goes by its flag again).
#[derive(Deserialize, ToSchema)]
struct NewSetting {
    value: Option<i64>,
}

#[derive(Serialize, ToSchema)]
struct SettingChanged {
    /// What's wrong with the cluster's layouts now, if anything: too few
    /// nodes for them, say.
    warnings: Vec<String>,
}

/// The settings that the dashboard changes this way: those of how blobs are
/// stored, and repaired, and the cluster's public access block.
const REDUNDANCY: &[&crate::settings::Setting] = &[
    &crate::settings::DATA_SHARDS,
    &crate::settings::PARITY_SHARDS,
    &crate::settings::REPAIR_AFTER,
    &crate::settings::BLOCK_PUBLIC_POLICY,
    &crate::settings::RESTRICT_PUBLIC_BUCKETS,
];

/// Sets one of the redundancy settings (`data-shards`, `parity-shards`,
/// `repair-after`), or of the cluster's public access block
/// (`block-public-policy`, `restrict-public-buckets`: 0 or 1), for the whole
/// cluster, as `cairn config set` does. The node answering goes by it right
/// away, the others within a heartbeat (the public access block's, at once).
#[utoipa::path(put, path = "/settings/{name}", params(("name" = String, Path)),
    request_body = NewSetting, responses(
        (status = 200, body = SettingChanged),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn set_setting(
    State(app): AppState,
    Path(name): Path<String>,
    Json(body): Json<NewSetting>,
) -> Result<Json<SettingChanged>> {
    let Some(setting) = REDUNDANCY.iter().find(|s| s.name == name) else {
        return Err(ApiError::NotFound(format!("no setting {name:?} to set here")));
    };
    let client = app.pool.get().await?;
    match body.value {
        Some(value) if value < setting.min || value > setting.max => {
            return Err(ApiError::BadRequest(format!(
                "{name} must be from {} to {}",
                setting.min, setting.max
            )));
        }
        Some(value) => setting.set(&client, value).await?,
        None => setting.unset(&client).await?,
    }
    crate::refresh_settings(&app).await?;
    let redundancy = [crate::settings::DATA_SHARDS.name, crate::settings::PARITY_SHARDS.name];
    let warnings = if !redundancy.contains(&setting.name) {
        Vec::new()
    } else {
        crate::settings::placement_warnings(&client).await?
    };
    Ok(Json(SettingChanged { warnings }))
}

#[derive(Serialize, ToSchema)]
struct NodeRemoved {
    /// The shards it holds, which move to other nodes.
    shards: i64,
}

/// Starts removing a node, as `cairn node remove` does: it gets no new
/// shards, and its shards move to the other nodes (see `mover`).
#[utoipa::path(post, path = "/nodes/{id}/remove", params(("id" = i32, Path)), responses(
    (status = 200, body = NodeRemoved),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn remove_node(State(app): AppState, Path(id): Path<i32>) -> Result<Json<NodeRemoved>> {
    match crate::nodes::remove(&app.pool.get().await?, id).await? {
        Ok(shards) => Ok(Json(NodeRemoved { shards })),
        Err(why) => Err(node_unchanged(id, why)),
    }
}

/// Keeps a node that's being removed, or was, as `cairn node keep` does: it
/// gets shards again; those that moved stay where they are.
#[utoipa::path(post, path = "/nodes/{id}/keep", params(("id" = i32, Path)), responses(
    (status = 204, description = "Kept"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn keep_node(State(app): AppState, Path(id): Path<i32>) -> Result<StatusCode> {
    match crate::nodes::keep(&app.pool.get().await?, id).await? {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(why) => Err(node_unchanged(id, why)),
    }
}

/// Why a node's state didn't change, as an error.
fn node_unchanged(id: i32, why: String) -> ApiError {
    if why == "doesn't exist" {
        ApiError::NotFound(format!("node {id} {why}"))
    } else {
        ApiError::Conflict(format!("node {id} {why}"))
    }
}

#[utoipa::path(put, path = "/lifecycle/rate", request_body = NewRate, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn set_lifecycle_rate(State(app): AppState, Json(body): Json<NewRate>) -> Result<StatusCode> {
    if body.rate < 0 {
        return Err(ApiError::BadRequest("the rate can't be negative".into()));
    }
    crate::settings::LIFECYCLE_RATE.set(&app.pool.get().await?, body.rate).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// A bucket's lifecycle rules, if it has any.
#[derive(Serialize, Deserialize, ToSchema)]
struct BucketLifecycle {
    configuration: Option<crate::lifecycle::rules::Configuration>,
}

/// A bucket's lifecycle rules, as S3's GetBucketLifecycleConfiguration
/// gives them, but in the form they're stored in.
#[utoipa::path(get, path = "/buckets/{bucket}/lifecycle", params(("bucket" = String, Path)), responses(
    (status = 200, body = BucketLifecycle),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn get_bucket_lifecycle(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
) -> Result<Json<BucketLifecycle>> {
    actor.check(&app, "s3:GetLifecycleConfiguration", On::Bucket(bucket.clone())).await?;
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached("SELECT lifecycle FROM buckets WHERE name = $1", &[&bucket])
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("no bucket named {bucket:?}")))?;
    let configuration = match row.get::<_, Option<String>>(0) {
        None => None,
        Some(json) => Some(
            crate::lifecycle::rules::Configuration::from_json(&json)
                .map_err(|e| anyhow::anyhow!("bucket {bucket}'s lifecycle configuration doesn't parse: {e}"))?,
        ),
    };
    Ok(Json(BucketLifecycle { configuration }))
}

/// Replaces a bucket's lifecycle rules, as S3's
/// PutBucketLifecycleConfiguration does, which starts a new sweep of them.
/// Rules without an ID get one.
#[utoipa::path(put, path = "/buckets/{bucket}/lifecycle", params(("bucket" = String, Path)),
    request_body = crate::lifecycle::rules::Configuration, responses(
        (status = 204, description = "Set"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn put_bucket_lifecycle(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Json(body): Json<crate::lifecycle::rules::Configuration>,
) -> Result<StatusCode> {
    actor.check(&app, "s3:PutLifecycleConfiguration", On::Bucket(bucket.clone())).await?;
    let configuration = body.check().map_err(ApiError::BadRequest)?;
    match crate::s3::buckets::lifecycle::set(&app, &bucket, Some(&configuration.to_json())).await? {
        true => Ok(StatusCode::NO_CONTENT),
        false => Err(ApiError::NotFound(format!("no bucket named {bucket:?}"))),
    }
}

/// Removes a bucket's lifecycle rules, as S3's DeleteBucketLifecycle does:
/// nothing expires from then on.
#[utoipa::path(delete, path = "/buckets/{bucket}/lifecycle", params(("bucket" = String, Path)), responses(
    (status = 204, description = "Removed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_bucket_lifecycle(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
) -> Result<StatusCode> {
    // DeleteBucketLifecycle is authorized as its put, in S3.
    actor.check(&app, "s3:PutLifecycleConfiguration", On::Bucket(bucket.clone())).await?;
    match crate::s3::buckets::lifecycle::set(&app, &bucket, None).await? {
        true => Ok(StatusCode::NO_CONTENT),
        false => Err(ApiError::NotFound(format!("no bucket named {bucket:?}"))),
    }
}
