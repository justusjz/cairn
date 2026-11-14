//! The console's API for what a signed-in identity manages: the cluster (a
//! superadmin's), and an account's buckets, objects and users. Every handler
//! checks what it does as the session's identity (see `actor`), and is
//! registered through `utoipa_axum::routes!`, so the router and the OpenAPI
//! spec are built from the same annotations: a route can't be served
//! without being in the spec.
//!
//! The numbers come from the catalog, as of the request, and from each node's
//! own metrics (see `metrics`), which every live node reports through its peer
//! endpoint. Some of the catalog's numbers take a scan of a whole table, which
//! is fine for a page an operator looks at, but not for anything that runs on
//! its own. Times are seconds since the Unix epoch.

use std::collections::{HashMap, HashSet};
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
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::actor::Actor;
use super::web::{ApiError, ErrorBody};
use crate::peer::stats::{NodeStats, node_stats};
use crate::s3::actions::{Check, On};
use crate::policy::Context;
use crate::s3::util::xml_escape;
use crate::db::Cached;
use crate::{
    App,
    peer::PeerClient,
    users,
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

/// The routes, which the console serves as its session's identity (see
/// `actor`): every handler checks what it does as its S3 operation's
/// actions, IAM's, or Cairn's (`cairn:`, on the cluster, which operators'
/// policies allow).
pub(super) fn router() -> OpenApiRouter<Arc<App>> {
    OpenApiRouter::new()
        // The cluster's (`cairn:` actions).
        .routes(routes!(get_cluster))
        .routes(routes!(get_storage))
        .routes(routes!(get_integrity))
        .routes(routes!(identify_users))
        .routes(routes!(get_lifecycle))
        .routes(routes!(set_lifecycle_rate))
        .routes(routes!(set_setting))
        .routes(routes!(remove_node))
        .routes(routes!(keep_node))
        .routes(routes!(list_oidc_providers))
        .routes(routes!(set_oidc_provider, delete_oidc_provider))
        // Accounts' buckets and objects (`s3:`), and users (`iam:`).
        .routes(routes!(list_buckets, create_bucket))
        .routes(routes!(delete_bucket))
        .routes(routes!(list_objects))
        .routes(routes!(get_object))
        .routes(routes!(download))
        .routes(routes!(get_bucket_lifecycle, put_bucket_lifecycle, delete_bucket_lifecycle))
        .routes(routes!(get_bucket_access))
        .routes(routes!(put_bucket_policy, delete_bucket_policy))
        .routes(routes!(put_public_access_block, delete_public_access_block))
        .routes(routes!(get_account_block, put_account_block, delete_account_block))
        .routes(routes!(upload, delete_object))
        .routes(routes!(set_versioning))
        .routes(routes!(set_bucket_tags))
        .routes(routes!(create_upload))
        .routes(routes!(upload_part))
        .routes(routes!(complete_upload))
        .routes(routes!(abort_upload))
        .routes(routes!(set_object_tags))
        .routes(routes!(get_bucket_cors, put_bucket_cors, delete_bucket_cors))
        .routes(routes!(list_users, create_user))
        .routes(routes!(delete_user, update_user))
        .routes(routes!(set_boundary, delete_boundary))
        .routes(routes!(set_user_tags))
        .routes(routes!(rotate_secret))
        .routes(routes!(set_admin))
        .routes(routes!(list_policies, create_policy))
        .routes(routes!(update_policy, delete_policy_managed))
        .routes(routes!(set_policy_tags))
        .routes(routes!(list_policy_versions))
        .routes(routes!(set_default_version))
        .routes(routes!(delete_policy_version))
        .routes(routes!(attach_policy, detach_policy))
        .routes(routes!(create_enrollment))
        .routes(routes!(create_key))
        .routes(routes!(set_key, delete_key))
        .routes(routes!(get_policy, put_policy, delete_policy))
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
async fn get_cluster(State(app): AppState, Extension(actor): Extension<Actor>) -> Result<Json<Cluster>> {
    actor.check(&app, "cairn:GetCluster", On::Cluster).await?;
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
async fn get_storage(State(app): AppState, Extension(actor): Extension<Actor>) -> Result<Json<Storage>> {
    actor.check(&app, "cairn:GetCluster", On::Cluster).await?;
    // Requests that come in while a report is being made wait for it, rather
    // than make their own.
    let mut cached = app.console.storage.lock().await;
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
async fn get_integrity(State(app): AppState, Extension(actor): Extension<Actor>) -> Result<Json<Integrity>> {
    actor.check(&app, "cairn:GetCluster", On::Cluster).await?;
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
    /// The account that owns it.
    account: String,
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
    /// The account's users whose policies give them access to the whole
    /// bucket (see `who_has_access`).
    users: i64,
    /// Its tags (PutBucketTagging), sorted by key.
    tags: Vec<Tag>,
    /// Whether its policy makes it public (GetBucketPolicyStatus).
    public: bool,
    /// Its public access block, if it has one.
    public_access_block: Option<crate::s3::buckets::public_access::Block>,
    /// Its account's public access block, if it has one, which applies to
    /// the bucket as well.
    account_public_access_block: Option<crate::s3::buckets::public_access::Block>,
    /// Whether it has Object Lock enabled (see `s3::object_lock`).
    object_lock: bool,
}

/// A tag of a bucket, an object version (see `s3::tags`) or a user (whose
/// keys are unique regardless of case).
#[derive(Serialize, Deserialize, ToSchema, Clone)]
pub(super) struct Tag {
    key: String,
    value: String,
}

/// Tags as the console shows them, from their stored form.
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
    let buckets = buckets(&app).await?;
    let owners: Vec<(&str, &str)> = buckets.iter().map(|b| (b.name.as_str(), b.account.as_str())).collect();
    let listed = actor.listed(&app, &owners).await?;
    let mut listed: Vec<BucketSummary> = buckets.into_iter().zip(listed).filter(|(_, l)| *l).map(|(b, _)| b).collect();
    // How many of the account's users have access to its buckets, by their
    // policies, if the actor may see its users.
    if actor.allows(&app, "iam:ListUsers", On::users(actor.account(), "/")).await? {
        let own: Vec<String> = listed.iter().filter(|b| b.account == actor.account()).map(|b| b.name.clone()).collect();
        let counts = who_has_access(&app.pool.get().await?, actor.account(), &own).await?;
        for bucket in &mut listed {
            bucket.users = counts.get(&bucket.name).map_or(0, |users| users.len() as i64);
        }
    }
    Ok(Json(listed))
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
    let mut tags: HashMap<String, String> = client
        .query_cached("SELECT name, tags FROM buckets WHERE tags IS NOT NULL", &[])
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    // Each bucket's policy (whether it's public), its block and its
    // account's.
    type Blocks = (Option<crate::s3::buckets::public_access::Block>, Option<crate::s3::buckets::public_access::Block>);
    let mut access: HashMap<String, (bool, Blocks)> = HashMap::new();
    let mut locked: HashSet<String> = HashSet::new();
    let query = "SELECT b.name, b.policy, b.public_access_block, b.object_lock, a.public_access_block
                 FROM buckets b JOIN accounts a ON a.id = b.account_id";
    for row in client.query_cached(query, &[]).await? {
        let name: String = row.get(0);
        if row.get::<_, bool>(3) {
            locked.insert(name.clone());
        }
        let public = match row.get::<_, Option<&str>>(1) {
            Some(text) => crate::policy::Policy::parse(text, crate::policy::Kind::Bucket(&name))
                .map_err(|e| anyhow::anyhow!("bucket {name}'s policy doesn't parse: {}", e.message))?
                .is_public(),
            None => false,
        };
        let block = |i| row.get::<_, Option<i16>>(i).map(crate::s3::buckets::public_access::Block::from_bits);
        access.insert(name, (public, (block(2), block(4))));
    }
    Ok(buckets
        .into_iter()
        .map(|b| {
            let [objects, bytes, versions, version_bytes] =
                objects.remove(&b.name).unwrap_or_default();
            BucketSummary {
                uploads: uploads.get(&b.name).copied().unwrap_or(0),
                // Filled in as the actor lists them.
                users: 0,
                default_kms_key: defaults.remove(&b.name),
                tags: tags.remove(&b.name).as_deref().map(tag_list).unwrap_or_default(),
                public: access.get(&b.name).is_some_and(|(public, _)| *public),
                public_access_block: access.get(&b.name).and_then(|(_, (block, _))| *block),
                account_public_access_block: access.remove(&b.name).and_then(|(_, (_, block))| block),
                object_lock: locked.contains(&b.name),
                name: b.name,
                account: b.account,
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
    /// Whether it has Object Lock enabled (and so is versioned) from the
    /// start: it can't be disabled again.
    #[serde(default)]
    object_lock: bool,
}

#[utoipa::path(post, path = "/buckets", request_body = NewBucket, responses(
    (status = 201, description = "Created"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_bucket(State(app): AppState, Extension(actor): Extension<Actor>, Json(body): Json<NewBucket>) -> Result<StatusCode> {
    actor.check(&app, "s3:CreateBucket", On::Bucket(body.name.clone())).await?;
    // As S3's CreateBucket with Object Lock asks for.
    if body.object_lock {
        actor.check(&app, "s3:PutBucketObjectLockConfiguration", On::Bucket(body.name.clone())).await?;
        actor.check(&app, "s3:PutBucketVersioning", On::Bucket(body.name.clone())).await?;
    }
    // The console's user's account's.
    match create::create(&app, &body.name, actor.account(), body.object_lock).await? {
        create::Creation::Created => Ok(StatusCode::CREATED),
        create::Creation::Exists | create::Creation::OwnedByOther => Err(ApiError::Conflict(format!(
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
    /// Its account's public access block, if it has one, which applies to
    /// the bucket as well.
    account_public_access_block: Option<crate::s3::buckets::public_access::Block>,
    /// The bucket's account's users whose own policies (inline and
    /// attached) give them access to the whole bucket, and what.
    users: Vec<UserAccess>,
}

/// What a user's policies allow it on a whole bucket.
#[derive(Serialize, ToSchema)]
struct UserAccess {
    user: String,
    /// Of `list`, `read`, `write`, `delete-versions` and `manage` (its
    /// configuration and policy).
    levels: Vec<&'static str>,
}

/// What each level means: an action on the bucket (or on any object in it).
const LEVELS: &[(&str, &str, bool)] = &[
    ("list", "s3:ListBucket", false),
    ("read", "s3:GetObject", true),
    ("write", "s3:PutObject", true),
    ("delete-versions", "s3:DeleteObjectVersion", true),
    ("manage", "s3:PutBucketPolicy", false),
];

/// The users of `account` whose own policies (inline and attached: not
/// the bucket's) allow them something on the whole of each of `buckets`,
/// and what (see `LEVELS`), by bucket. A policy that allows only some keys
/// (a prefix), or only under conditions on the request, doesn't count.
async fn who_has_access(
    client: &deadpool_postgres::Object,
    account: &str,
    buckets: &[String],
) -> anyhow::Result<HashMap<String, Vec<(String, Vec<&'static str>)>>> {
    use crate::s3::access::{Access, Origin};
    let mut found: HashMap<String, Vec<(String, Vec<&'static str>)>> = HashMap::new();
    let users = client.query_cached("SELECT id, name FROM users WHERE account_id = $1 ORDER BY name", &[&account]).await?;
    let origin = Origin { peer: None, trusted_proxies: &[], signed: None, form: false };
    for row in users {
        let Some(principal) = users::Principal::load_user(client, row.get(0)).await? else { continue };
        let access = Access::new(Some(&principal), account, &axum::http::Method::GET, &Default::default(), "", &origin)?;
        for bucket in buckets {
            let levels: Vec<&'static str> = LEVELS
                .iter()
                .filter(|(_, action, object)| {
                    let on = match object {
                        true => On::Object(bucket.clone(), "*".to_owned()),
                        false => On::Bucket(bucket.clone()),
                    };
                    access.allows(&Check { action, on })
                })
                .map(|(level, _, _)| *level)
                .collect();
            if !levels.is_empty() {
                found.entry(bucket.clone()).or_default().push((row.get(1), levels));
            }
        }
    }
    Ok(found)
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
    // Its account's users, if the actor may see them.
    let owner: String = client.query_one_cached("SELECT account_id FROM buckets WHERE name = $1", &[&bucket]).await?.get(0);
    let account_public_access_block = public_access::account(&client, &owner).await?;
    let users = match owner == actor.account() && actor.allows(&app, "iam:ListUsers", On::users(&owner, "/")).await? {
        true => who_has_access(&client, &owner, std::slice::from_ref(&bucket))
            .await?
            .remove(&bucket)
            .unwrap_or_default()
            .into_iter()
            .map(|(user, levels)| UserAccess { user, levels })
            .collect(),
        false => Vec::new(),
    };
    Ok(Json(BucketAccess { policy, public, public_access_block, account_public_access_block, users }))
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

/// Removes a bucket's public access block: only its account's applies.
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

/// The actor's account's public access block, as S3 Control's
/// GetPublicAccessBlock gets it: `null` if it has none.
#[utoipa::path(get, path = "/account/public-access-block", responses(
    (status = 200, body = Option<crate::s3::buckets::public_access::Block>),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn get_account_block(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
) -> Result<Json<Option<crate::s3::buckets::public_access::Block>>> {
    actor.check(&app, "s3:GetAccountPublicAccessBlock", On::Account).await?;
    Ok(Json(crate::s3::buckets::public_access::account(&app.pool.get().await?, actor.account()).await?))
}

/// Sets the actor's account's public access block, which every one of its
/// buckets gets too, as S3 Control's PutPublicAccessBlock does.
#[utoipa::path(put, path = "/account/public-access-block",
    request_body = crate::s3::buckets::public_access::Block, responses(
        (status = 204, description = "Set"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn put_account_block(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Json(body): Json<crate::s3::buckets::public_access::Block>,
) -> Result<StatusCode> {
    actor.check(&app, "s3:PutAccountPublicAccessBlock", On::Account).await?;
    crate::s3::buckets::public_access::set_account(&app, actor.account(), Some(body)).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Removes the actor's account's public access block: only its buckets'
/// own apply.
#[utoipa::path(delete, path = "/account/public-access-block", responses(
    (status = 204, description = "Removed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_account_block(State(app): AppState, Extension(actor): Extension<Actor>) -> Result<StatusCode> {
    // DeletePublicAccessBlock is authorized as its put, in S3.
    actor.check(&app, "s3:PutAccountPublicAccessBlock", On::Account).await?;
    crate::s3::buckets::public_access::set_account(&app, actor.account(), None).await?;
    Ok(StatusCode::NO_CONTENT)
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

/// A page of `list`, for the console.
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
                let totals = totals.expect("the console's listings ask for totals");
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
    let lost: HashSet<String> = client
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

/// Every version of a key (the newest 200).
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
    // How many bytes of each version's parts are intact on no replica.
    let lost: HashMap<i64, i64> = client
        .query_cached(
            "SELECT p.object_id,
                    sum(least(l.stop, p.blob_offset + p.size) - greatest(l.start, p.blob_offset))::bigint
             FROM parts p JOIN lost_ranges l ON l.blob_id = p.blob_id
                  AND l.start < p.blob_offset + p.size AND l.stop > p.blob_offset
             WHERE p.object_id = ANY($1)
             GROUP BY p.object_id",
            &[&ids],
        )
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    let mut infos = Vec::with_capacity(versions.len());
    for v in &versions {
        let stored = crate::s3::sse::Stored::from_row(v, 8);
        let mut etag: Option<String> = v.get(5);
        // An SSE-S3 version's ETag is stored sealed; Cairn can open it, as
        // it can the version itself.
        if let Some(etag_key) = crate::s3::sse::etag_key(app, &stored, bucket, key).await?.ok().flatten() {
            let object = crate::encryption::Owner::Object { bucket, key };
            etag = etag.map(|e| etag_key.open(object, &e)).transpose()?;
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
            lost_bytes: lost.get(&v.get::<_, i64>(0)).copied().unwrap_or(0),
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
        // it may use; a root has no identity there, so it can't (see
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
        Default::default(),
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
    let resp = crate::s3::objects::delete::delete_object(&app, &bucket, &params.key, params.version.as_deref(), false).await?;
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

// ─── OIDC providers ──────────────────────────────────────────────────────────

/// An OpenID Connect provider people may sign in to the console at (see
/// `console::oidc`); never its client secret.
#[derive(Serialize, ToSchema)]
struct OidcProvider {
    name: String,
    label: String,
    issuer: String,
    client_id: String,
    /// Whether it has a client secret (else it's a public client).
    has_secret: bool,
    scopes: String,
    /// Logins it signs in.
    logins: i64,
}

/// The providers, and the redirect URI to register with them.
#[derive(Serialize, ToSchema)]
struct OidcProviders {
    providers: Vec<OidcProvider>,
    /// `<console URL>/api/oidc/callback`, if this node serves the console.
    redirect_uri: Option<String>,
}

#[utoipa::path(get, path = "/oidc-providers", responses(
    (status = 200, body = OidcProviders),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn list_oidc_providers(State(app): AppState, Extension(actor): Extension<Actor>) -> Result<Json<OidcProviders>> {
    actor.check(&app, "cairn:GetCluster", On::Cluster).await?;
    let client = app.pool.get().await?;
    let counts: HashMap<String, i64> = client
        .query_cached("SELECT provider, count(*) FROM login_oidc GROUP BY provider", &[])
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    let providers = crate::console::oidc::providers(&client)
        .await?
        .into_iter()
        .map(|p| OidcProvider {
            logins: counts.get(&p.name).copied().unwrap_or(0),
            has_secret: p.client_secret.is_some(),
            name: p.name,
            label: p.label,
            issuer: p.issuer,
            client_id: p.client_id,
            scopes: p.scopes,
        })
        .collect();
    let redirect_uri = app.console.origin.as_ref().map(|origin| format!("{origin}/api/oidc/callback"));
    Ok(Json(OidcProviders { providers, redirect_uri }))
}

#[derive(Deserialize, ToSchema)]
struct NewOidcProvider {
    /// What the sign-in button says, e.g. "Company SSO".
    label: String,
    /// The issuer's URL: its discovery document is at
    /// `<issuer>/.well-known/openid-configuration`.
    issuer: String,
    client_id: String,
    /// The client's secret; none for a public client. Left out when
    /// changing a provider: it keeps its secret.
    client_secret: Option<String>,
    /// `openid email profile` if not given.
    scopes: Option<String>,
}

/// Sets an OIDC provider, after checking its discovery document and keys.
#[utoipa::path(put, path = "/oidc-providers/{name}", params(("name" = String, Path)), request_body = NewOidcProvider, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn set_oidc_provider(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<NewOidcProvider>,
) -> Result<StatusCode> {
    actor.check(&app, "cairn:PutSetting", On::Cluster).await?;
    let client = app.pool.get().await?;
    let secret = match body.client_secret.filter(|s| !s.is_empty()) {
        Some(secret) => Some(secret),
        None => crate::console::oidc::provider(&client, &name).await?.and_then(|p| p.client_secret),
    };
    let provider = crate::console::oidc::Provider {
        name,
        label: body.label,
        issuer: body.issuer,
        client_id: body.client_id,
        client_secret: secret,
        scopes: body.scopes.filter(|s| !s.trim().is_empty()).unwrap_or_else(|| "openid email profile".to_owned()),
    };
    crate::console::oidc::set_provider(&client, &provider).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Removes an OIDC provider: the identities at it no longer sign anyone in.
#[utoipa::path(delete, path = "/oidc-providers/{name}", params(("name" = String, Path)), responses(
    (status = 204, description = "Removed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_oidc_provider(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
) -> Result<StatusCode> {
    actor.check(&app, "cairn:PutSetting", On::Cluster).await?;
    crate::console::oidc::remove_provider(&app.pool.get().await?, &name).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Multipart uploads ───────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
struct NewUpload {
    key: String,
    content_type: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct UploadStarted {
    upload_id: String,
}

/// The value of element `name` in an S3 handler's XML answer.
fn element(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&format!("</{name}>"))?;
    Some(xml[start..start + end].to_owned())
}

/// Starts a multipart upload, as CreateMultipartUpload does: for a file
/// larger than one upload may be (5 GiB), in parts.
#[utoipa::path(post, path = "/buckets/{bucket}/uploads", params(("bucket" = String, Path)), request_body = NewUpload,
    responses(
        (status = 201, body = UploadStarted),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn create_upload(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Json(body): Json<NewUpload>,
) -> Result<(StatusCode, Json<UploadStarted>)> {
    actor.check(&app, "s3:PutObject", On::Object(bucket.clone(), body.key.clone())).await?;
    if !crate::s3::util::is_well_formed(&body.key) || body.key.is_empty() || body.key.len() > 1024 {
        return Err(ApiError::BadRequest("a key is 1 to 1024 bytes of UTF-8, without control characters".into()));
    }
    let content_type = body.content_type.as_deref().filter(|t| !t.is_empty()).unwrap_or("application/octet-stream");
    let resp = crate::s3::multipart::create::create_multipart_upload(
        &app,
        &bucket,
        &body.key,
        content_type,
        "",
        "",
        crate::s3::sse::Wanted::Plain,
        actor.kms_role(),
        None,
        Default::default(),
    )
    .await?;
    if resp.status() != StatusCode::OK {
        return Err(s3_error(resp).await);
    }
    let xml = resp.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
    let upload_id = element(&String::from_utf8_lossy(&xml), "UploadId")
        .ok_or_else(|| anyhow::anyhow!("CreateMultipartUpload answered no upload ID"))?;
    Ok((StatusCode::CREATED, Json(UploadStarted { upload_id })))
}

#[derive(Serialize, ToSchema)]
struct PartUploaded {
    /// What to complete the upload with.
    etag: String,
}

/// Uploads one part (1 to 10000) of a multipart upload, from the request's
/// body: at least 5 MiB but for the last, at most 5 GiB.
#[utoipa::path(put, path = "/buckets/{bucket}/uploads/{upload}/parts/{part}",
    params(("bucket" = String, Path), ("upload" = String, Path), ("part" = u32, Path), UploadParams),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses(
        (status = 200, body = PartUploaded),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn upload_part(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((bucket, upload, part)): Path<(String, String, u32)>,
    Query(params): Query<UploadParams>,
    headers: axum::http::HeaderMap,
    body: Body,
) -> Result<Json<PartUploaded>> {
    actor.check(&app, "s3:PutObject", On::Object(bucket.clone(), params.key.clone())).await?;
    let length = headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()?.parse().ok());
    let payload = length.map_or_else(crate::payload::Payload::unchecked, crate::payload::Payload::unchecked_of);
    let payload = payload
        .at_most(crate::s3::util::MAX_UPLOAD)
        .map_err(|_| ApiError::BadRequest("a part is at most 5 GiB".into()))?;
    let resp = crate::s3::multipart::upload_part::put_part(
        &app,
        &bucket,
        &params.key,
        &upload,
        &part.to_string(),
        body,
        payload,
        None,
        actor.kms_role(),
    )
    .await?;
    if resp.status() != StatusCode::OK {
        return Err(s3_error(resp).await);
    }
    let etag = resp
        .headers()
        .get(header::ETAG)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("UploadPart answered no ETag"))?
        .to_owned();
    Ok(Json(PartUploaded { etag }))
}

#[derive(Deserialize, ToSchema)]
struct CompletedPart {
    number: u32,
    etag: String,
}

#[derive(Deserialize, ToSchema)]
struct CompleteUpload {
    parts: Vec<CompletedPart>,
}

/// Completes a multipart upload with its parts, in order, as
/// CompleteMultipartUpload does: the object is written then.
#[utoipa::path(post, path = "/buckets/{bucket}/uploads/{upload}/complete",
    params(("bucket" = String, Path), ("upload" = String, Path), UploadParams), request_body = CompleteUpload,
    responses(
        (status = 204, description = "Written"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn complete_upload(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((bucket, upload)): Path<(String, String)>,
    Query(params): Query<UploadParams>,
    Json(body): Json<CompleteUpload>,
) -> Result<StatusCode> {
    actor.check(&app, "s3:PutObject", On::Object(bucket.clone(), params.key.clone())).await?;
    let parts: String = body
        .parts
        .iter()
        .map(|p| format!("<Part><PartNumber>{}</PartNumber><ETag>{}</ETag></Part>", p.number, xml_escape(&p.etag)))
        .collect();
    let xml = format!("<CompleteMultipartUpload>{parts}</CompleteMultipartUpload>");
    let resp = crate::s3::multipart::complete::complete_multipart_upload(
        &app,
        &bucket,
        &params.key,
        &upload,
        xml.into(),
        &Preconditions::default(),
        None,
        actor.kms_role(),
        None,
        None,
    )
    .await?;
    let status = resp.status();
    let answer = resp.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
    let answer = String::from_utf8_lossy(&answer);
    // An error may come with a 200, once the answer has started (as S3's).
    if status != StatusCode::OK || answer.contains("<Error>") {
        let message = element(&answer, "Message").or_else(|| element(&answer, "Code")).unwrap_or_default();
        return Err(match status {
            s if s.is_server_error() => ApiError::Failed(anyhow::anyhow!("completing an upload: {message}")),
            _ => ApiError::BadRequest(message),
        });
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Aborts a multipart upload, as AbortMultipartUpload does: its parts go.
#[utoipa::path(delete, path = "/buckets/{bucket}/uploads/{upload}",
    params(("bucket" = String, Path), ("upload" = String, Path), UploadParams), responses(
        (status = 204, description = "Aborted"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn abort_upload(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((bucket, upload)): Path<(String, String)>,
    Query(params): Query<UploadParams>,
) -> Result<StatusCode> {
    actor.check(&app, "s3:AbortMultipartUpload", On::Object(bucket.clone(), params.key.clone())).await?;
    let resp = crate::s3::multipart::abort::abort_multipart_upload(&app, &bucket, &params.key, &upload).await?;
    match resp.status() {
        s if s.is_success() => Ok(StatusCode::NO_CONTENT),
        _ => Err(s3_error(resp).await),
    }
}

// ─── Tags and CORS ───────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
struct NewTags {
    /// The whole tag set (none: no tags).
    tags: Vec<Tag>,
}

/// A tag set as S3's `<Tagging>` document.
fn tagging_xml(tags: &[Tag]) -> String {
    let tags: String = tags
        .iter()
        .map(|t| format!("<Tag><Key>{}</Key><Value>{}</Value></Tag>", xml_escape(&t.key), xml_escape(&t.value)))
        .collect();
    format!("<Tagging><TagSet>{tags}</TagSet></Tagging>")
}

/// Replaces a bucket's tags, as PutBucketTagging does (or, with none,
/// DeleteBucketTagging).
#[utoipa::path(put, path = "/buckets/{bucket}/tags", params(("bucket" = String, Path)), request_body = NewTags,
    responses(
        (status = 204, description = "Set"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn set_bucket_tags(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Json(body): Json<NewTags>,
) -> Result<StatusCode> {
    // DeleteBucketTagging is authorized as its put, in S3.
    actor.check(&app, "s3:PutBucketTagging", On::Bucket(bucket.clone())).await?;
    use crate::s3::buckets::tagging;
    let resp = match body.tags.is_empty() {
        true => tagging::delete_bucket_tagging(&app, &bucket).await?,
        false => tagging::put_bucket_tagging(&app, &bucket, tagging_xml(&body.tags).into()).await?,
    };
    match resp.status() {
        s if s.is_success() => Ok(StatusCode::NO_CONTENT),
        _ => Err(s3_error(resp).await),
    }
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct ObjectTagParams {
    key: String,
    /// The version whose tags to set; the current one if not given.
    version: Option<String>,
}

/// Replaces a version's tags, as PutObjectTagging does (or, with none,
/// DeleteObjectTagging).
#[utoipa::path(put, path = "/buckets/{bucket}/object/tags", params(("bucket" = String, Path), ObjectTagParams),
    request_body = NewTags, responses(
        (status = 204, description = "Set"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn set_object_tags(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Query(params): Query<ObjectTagParams>,
    Json(body): Json<NewTags>,
) -> Result<StatusCode> {
    use crate::s3::objects::tagging;
    let version = params.version.as_deref();
    let action = match (body.tags.is_empty(), version.is_some()) {
        (false, false) => "s3:PutObjectTagging",
        (false, true) => "s3:PutObjectVersionTagging",
        (true, false) => "s3:DeleteObjectTagging",
        (true, true) => "s3:DeleteObjectVersionTagging",
    };
    actor.check(&app, action, On::Object(bucket.clone(), params.key.clone())).await?;
    let resp = match body.tags.is_empty() {
        true => tagging::delete_object_tagging(&app, &bucket, &params.key, version).await?,
        false => tagging::put_object_tagging(&app, &bucket, &params.key, version, tagging_xml(&body.tags).into()).await?,
    };
    match resp.status() {
        s if s.is_success() => Ok(StatusCode::NO_CONTENT),
        _ => Err(s3_error(resp).await),
    }
}

/// A bucket's CORS configuration.
#[derive(Serialize, ToSchema)]
struct BucketCors {
    /// `null` if it has none.
    configuration: Option<crate::s3::buckets::cors::Configuration>,
}

#[utoipa::path(get, path = "/buckets/{bucket}/cors", params(("bucket" = String, Path)), responses(
    (status = 200, body = BucketCors),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn get_bucket_cors(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
) -> Result<Json<BucketCors>> {
    actor.check(&app, "s3:GetBucketCORS", On::Bucket(bucket.clone())).await?;
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached("SELECT cors FROM buckets WHERE name = $1", &[&bucket])
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("no bucket named {bucket:?}")))?;
    let configuration = match row.get::<_, Option<String>>(0) {
        None => None,
        Some(json) => Some(
            crate::s3::buckets::cors::Configuration::from_json(&json)
                .map_err(|e| anyhow::anyhow!("bucket {bucket}'s CORS configuration doesn't parse: {e}"))?,
        ),
    };
    Ok(Json(BucketCors { configuration }))
}

/// Sets a bucket's CORS configuration, checked as PutBucketCors checks it.
#[utoipa::path(put, path = "/buckets/{bucket}/cors", params(("bucket" = String, Path)),
    request_body = crate::s3::buckets::cors::Configuration, responses(
        (status = 204, description = "Set"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn put_bucket_cors(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
    Json(body): Json<crate::s3::buckets::cors::Configuration>,
) -> Result<StatusCode> {
    actor.check(&app, "s3:PutBucketCORS", On::Bucket(bucket.clone())).await?;
    let resp = crate::s3::buckets::cors::put_bucket_cors(&app, &bucket, body.to_xml().into()).await?;
    match resp.status() {
        s if s.is_success() => Ok(StatusCode::NO_CONTENT),
        _ => Err(s3_error(resp).await),
    }
}

/// Removes a bucket's CORS configuration: no other site's page may use it.
#[utoipa::path(delete, path = "/buckets/{bucket}/cors", params(("bucket" = String, Path)), responses(
    (status = 204, description = "Removed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_bucket_cors(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
) -> Result<StatusCode> {
    // DeleteBucketCors is authorized as its put, in S3.
    actor.check(&app, "s3:PutBucketCORS", On::Bucket(bucket.clone())).await?;
    let resp = crate::s3::buckets::cors::delete_bucket_cors(&app, &bucket).await?;
    match resp.status() {
        s if s.is_success() => Ok(StatusCode::NO_CONTENT),
        _ => Err(s3_error(resp).await),
    }
}

// ─── Users ───────────────────────────────────────────────────────────────────

/// The account of the session's user `name` (the session's own), if the
/// user is there.
async fn account_of(app: &App, actor: &Actor, name: &str) -> Result<String> {
    let account = actor.account().to_owned();
    users::id_of(&app.pool.get().await?, &account, name).await?;
    Ok(account)
}

/// Refuses the request unless IAM's `action` on the session's user `name` is
/// allowed (by its ARN, tags and boundary: see `users::Target`): its
/// account.
async fn check_user(app: &Arc<App>, actor: &Actor, action: &'static str, name: &str) -> Result<String> {
    Ok(check_user_with(app, actor, action, name, Context::default()).await?.account)
}

/// As `check_user`, with the condition keys `extra` too: the user.
async fn check_user_with(app: &Arc<App>, actor: &Actor, action: &'static str, name: &str, extra: Context) -> Result<users::Target> {
    let account = account_of(app, actor, name).await?;
    let target = users::Target::load(&app.pool.get().await?, &account, name)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("no user named {name:?}")))?;
    let mut context = target.context(action);
    context.extend(&extra);
    actor.check_with(app, action, target.on(), &context).await?;
    Ok(target)
}

/// The condition key `key` set to `value`.
fn key(key: &str, value: &str) -> Context {
    let mut context = Context::default();
    context.set(key, value);
    context
}


/// A user, never with its secret.
#[derive(Serialize, ToSchema)]
pub(super) struct UserSummary {
    name: String,
    /// Its ID, which never changes or comes back: its name (alias) in the
    /// KMS's auth mount for Cairn.
    id: String,
    /// Its identity (entity) in the KMS, which key owners grant keys to;
    /// none until Cairn has logged in as it, or without a KMS.
    kms_entity_id: Option<String>,
    admin: bool,
    created_at: f64,
    /// Its attached managed policies (AdministratorAccess, if it's an admin).
    attached: Vec<AttachedPolicy>,
    /// Its access keys, oldest first (never their secrets).
    keys: Vec<AccessKey>,
    /// The names of its inline policies.
    policies: Vec<String>,
    /// How it signs in to the console, if it does (a person's); `None`:
    /// it doesn't, and no link for it is out (a service's).
    console: Option<ConsoleAccess>,
    /// Its path (`/`, or `/…/`), which its ARN has before its name.
    path: String,
    /// Its ARN.
    arn: String,
    /// Its tags, newest first.
    tags: Vec<Tag>,
    /// Its permissions boundary's ARN, which caps what its policies allow.
    boundary: Option<String>,
}



/// How a user signs in to the console (see `store::ConsoleAccess`).
#[derive(Serialize, ToSchema)]
struct ConsoleAccess {
    /// Whether it enrolled (a login is linked to it).
    enrolled: bool,
    passkeys: i64,
    /// The OIDC providers (their labels) it signs in at.
    providers: Vec<String>,
    last_sign_in: Option<f64>,
    /// Whether an enrollment link for it is out, and works still.
    link_pending: bool,
}

#[derive(Serialize, ToSchema)]
struct AccessKey {
    id: String,
    active: bool,
    created_at: f64,
}

#[derive(Serialize, ToSchema)]
struct AttachedPolicy {
    name: String,
    arn: String,
}

#[utoipa::path(get, path = "/users", responses(
    (status = 200, body = Vec<UserSummary>),
    (status = "5XX", body = ErrorBody),
))]
async fn list_users(State(app): AppState, Extension(actor): Extension<Actor>) -> Result<Json<Vec<UserSummary>>> {
    // The session's account's users, as ListUsers lists them: all of them,
    // or (a delegated admin's) those at the paths it may list.
    let all = actor.allows(&app, "iam:ListUsers", On::users(actor.account(), "/")).await?;
    let client = app.pool.get().await?;
    let mut console = super::store::console_access(&client, actor.account()).await?;
    let mut attached = crate::managed::attached_all(&client, actor.account()).await?;
    let mut listed = Vec::new();
    let mut paths: HashMap<String, bool> = HashMap::new();
    for r in users::list(&client).await?.into_iter().filter(|r| r.account_id == actor.account()) {
        let may = match paths.get(&r.path) {
            _ if all => true,
            Some(may) => *may,
            None => {
                let may = actor.allows(&app, "iam:ListUsers", On::users(actor.account(), &r.path)).await?;
                paths.insert(r.path.clone(), may);
                may
            }
        };
        if may {
            listed.push(r);
        }
    }
    if !all && listed.is_empty() {
        actor.check(&app, "iam:ListUsers", On::users(actor.account(), "/")).await?;
    }
    let users = listed
        .into_iter()
        .map(|r| UserSummary {
            arn: users::user_arn(&r.account_id, &r.path, &r.name),
            path: r.path,
            tags: r.tags.into_iter().map(|(key, value)| Tag { key, value }).collect(),
            boundary: r.boundary,
            console: console.remove(&r.id).map(|c| ConsoleAccess {
                enrolled: c.enrolled,
                passkeys: c.passkeys,
                providers: c.providers,
                last_sign_in: c.last_sign_in,
                link_pending: c.link_pending,
            }),
            name: r.name,
            id: r.id.to_string(),
            kms_entity_id: r.kms_entity_id,
            admin: r.admin,
            created_at: r.created_at,
            attached: attached
                .remove(&r.id)
                .unwrap_or_default()
                .into_iter()
                .map(|a| AttachedPolicy { name: a.name, arn: a.arn })
                .collect(),
            keys: r
                .keys
                .into_iter()
                .map(|k| AccessKey { id: k.id, active: k.active, created_at: k.created_at })
                .collect(),
            policies: r.policies,
        })
        .collect();
    Ok(Json(users))
}

#[derive(Deserialize, ToSchema)]
struct CreateUser {
    name: String,
    /// Whether it gets an access key (a service's), of a random ID; a person
    /// gets none, and signs in to the console through its link.
    #[serde(default)]
    access_key: bool,
    /// The access key's secret: at least 8 characters; one is generated if
    /// not given. Implies `access_key`.
    secret: Option<String>,
    #[serde(default)]
    admin: bool,
    /// Its path (`/`, or `/…/`); `/` if not given.
    path: Option<String>,
    /// Its tags.
    #[serde(default)]
    tags: Vec<Tag>,
    /// Its permissions boundary: a managed policy's ARN.
    boundary: Option<String>,
}

/// A new user: its access key's ID and secret, if it got one, which is
/// shown only this once.
#[derive(Serialize, ToSchema)]
struct NewUser {
    name: String,
    access_key: Option<Secret>,
}

/// A user's secret, which is shown only this once.
#[derive(Serialize, ToSchema)]
struct Secret {
    name: String,
    secret: String,
}

#[utoipa::path(post, path = "/users", request_body = CreateUser, responses(
    (status = 201, body = NewUser),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_user(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Json(body): Json<CreateUser>,
) -> Result<(StatusCode, Json<NewUser>)> {
    let client = app.pool.get().await?;
    let account = actor.account().to_owned();
    let path = body.path.clone().filter(|p| !p.is_empty()).unwrap_or_else(|| "/".to_owned());
    users::check_path(&path, "path", false).map_err(ApiError::BadRequest)?;
    let tags: Vec<(String, String)> = body.tags.iter().map(|t| (t.key.clone(), t.value.clone())).collect();
    users::check_tags(&tags).map_err(ApiError::BadRequest)?;
    let boundary_arn = body.boundary.clone().filter(|b| !b.is_empty());
    // Checked as IAM's CreateUser (with the boundary and tags asked for),
    // and the rest as what the new user would be (see `users::Target`).
    let new = users::Target {
        id: uuid::Uuid::nil(),
        account: account.clone(),
        name: body.name.clone(),
        path: path.clone(),
        admin: false,
        created: String::new(),
        tags: tags.clone(),
        boundary: boundary_arn.clone(),
    };
    let mut asked = users::request_tags_context(&tags);
    if let Some(arn) = &boundary_arn {
        asked.set("iam:PermissionsBoundary", arn);
    }
    actor.check_with(&app, "iam:CreateUser", new.on(), &asked).await?;
    if !tags.is_empty() {
        actor.check_with(&app, "iam:TagUser", new.on(), &asked).await?;
    }
    let secret = body.secret.filter(|s| !s.is_empty());
    let access_key = body.access_key || secret.is_some();
    if body.admin {
        let mut context = new.context("iam:AttachUserPolicy");
        context.extend(&key("iam:PolicyARN", &crate::managed::aws_arn(crate::managed::ADMINISTRATOR_ACCESS)));
        actor.check_with(&app, "iam:AttachUserPolicy", new.on(), &context).await?;
    }
    if access_key {
        actor.check_with(&app, "iam:CreateAccessKey", new.on(), &new.context("iam:CreateAccessKey")).await?;
    }
    let boundary = match &boundary_arn {
        Some(arn) => Some(crate::managed::boundary(&client, &account, arn).await?),
        None => None,
    };
    users::create_user(&client, &account, &body.name, &path, boundary.as_ref()).await?;
    let id = users::id_of(&client, &account, &body.name).await?;
    let made = async {
        if !tags.is_empty() {
            users::tag(&client, id, &tags).await?;
        }
        if body.admin {
            users::update(&client, &account, &body.name, Some(true), None).await?;
        }
        anyhow::Ok(match access_key {
            true => {
                let (key, secret) = users::create_key(&client, &account, &body.name, None, secret).await?;
                Some(Secret { name: key, secret })
            }
            false => None,
        })
    };
    let access_key = match made.await {
        Ok(key) => key,
        Err(e) => {
            // All or nothing, as before (the user, then its key, were one
            // statement).
            let _ = users::delete(&client, &account, &body.name).await;
            return Err(e.into());
        }
    };
    // Its identity in the KMS, so that key owners can grant it keys now; if
    // the KMS can't be reached, the next maintenance pass makes it. In the
    // background: a slow KMS mustn't hold up the user.
    let identifying = app.clone();
    tokio::spawn(async move {
        if let Err(e) = users::identify(&identifying).await {
            eprintln!("kms: identifying users: {e:#}");
        }
    });
    Ok((StatusCode::CREATED, Json(NewUser { name: body.name, access_key })))
}

#[utoipa::path(delete, path = "/users/{user}", params(("user" = String, Path)), responses(
    (status = 204, description = "Deleted, with its grants"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_user(State(app): AppState, Extension(actor): Extension<Actor>, Path(name): Path<String>) -> Result<StatusCode> {
    let account = check_user(&app, &actor, "iam:DeleteUser", &name).await?;
    users::delete(&app.pool.get().await?, &account, &name).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Logs in to the KMS as each user without an identity there yet, from this
/// node, now rather than at its next maintenance pass. Fails with what went
/// wrong.
#[utoipa::path(post, path = "/kms/identify", responses(
    (status = 204, description = "Every user has its identity in the KMS"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn identify_users(State(app): AppState, Extension(actor): Extension<Actor>) -> Result<StatusCode> {
    actor.check(&app, "cairn:IdentifyUsers", On::Cluster).await?;
    if app.kms.is_none() {
        return Err(ApiError::BadRequest("this node has no KMS".into()));
    }
    users::identify(&app).await.map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct NewSecret {
    /// At least 8 characters; one is generated if not given.
    secret: Option<String>,
}

/// Replaces a user's secret.
#[utoipa::path(post, path = "/users/{user}/secret", params(("user" = String, Path)),
    request_body = NewSecret, responses(
        (status = 200, body = Secret),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn rotate_secret(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<NewSecret>,
) -> Result<Json<Secret>> {
    let account = check_user(&app, &actor, "iam:UpdateAccessKey", &name).await?;
    let secret = match body.secret.filter(|s| !s.is_empty()) {
        Some(s) => s,
        None => users::generate_secret()?,
    };
    users::update(&app.pool.get().await?, &account, &name, None, Some(secret.clone())).await?;
    Ok(Json(Secret { name, secret }))
}

#[derive(Deserialize, ToSchema)]
struct UserChange {
    /// Its new name (unique in the account regardless of case).
    name: Option<String>,
    /// Its new path (`/`, or `/…/`).
    path: Option<String>,
}

/// Renames or moves a user, as IAM's UpdateUser: allowed on it, and on
/// where it goes (its new ARN; moved only, its new path: see `iam`).
#[utoipa::path(patch, path = "/users/{user}", params(("user" = String, Path)), request_body = UserChange, responses(
    (status = 204, description = "Changed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn update_user(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<UserChange>,
) -> Result<StatusCode> {
    let new_path = body.path.filter(|p| !p.is_empty());
    if let Some(path) = &new_path {
        users::check_path(path, "path", false).map_err(ApiError::BadRequest)?;
    }
    let user = check_user_with(&app, &actor, "iam:UpdateUser", &name, Context::default()).await?;
    let path = new_path.clone().unwrap_or_else(|| user.path.clone());
    let to = match &body.name {
        Some(name) => On::user(&user.account, &path, name),
        None => On::users(&user.account, &path),
    };
    actor.check(&app, "iam:UpdateUser", to).await?;
    let name = body.name.unwrap_or_else(|| user.name.clone());
    users::rename(&app.pool.get().await?, &user.account, user.id, &name, &path).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct BoundaryArn {
    /// A managed policy's ARN: the account's own, or one of Cairn's.
    arn: String,
}

/// Sets a user's permissions boundary, as IAM's
/// PutUserPermissionsBoundary (decided by the boundary asked for).
#[utoipa::path(put, path = "/users/{user}/boundary", params(("user" = String, Path)), request_body = BoundaryArn, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn set_boundary(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<BoundaryArn>,
) -> Result<StatusCode> {
    let extra = key("iam:PermissionsBoundary", &body.arn);
    let user = check_user_with(&app, &actor, "iam:PutUserPermissionsBoundary", &name, extra).await?;
    let client = app.pool.get().await?;
    let boundary = crate::managed::boundary(&client, &user.account, &body.arn).await?;
    users::set_boundary(&client, &user.account, user.id, Some(&boundary)).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Removes a user's permissions boundary.
#[utoipa::path(delete, path = "/users/{user}/boundary", params(("user" = String, Path)), responses(
    (status = 204, description = "Removed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_boundary(State(app): AppState, Extension(actor): Extension<Actor>, Path(name): Path<String>) -> Result<StatusCode> {
    let user = check_user_with(&app, &actor, "iam:DeleteUserPermissionsBoundary", &name, Context::default()).await?;
    if user.boundary.is_none() {
        return Err(ApiError::NotFound(format!("{name:?} has no permissions boundary")));
    }
    users::set_boundary(&app.pool.get().await?, &user.account, user.id, None).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct UserTags {
    /// All of its tags: those it has of other keys go (UntagUser), the
    /// rest are set (TagUser).
    tags: Vec<Tag>,
}

/// Sets a user's tags, as IAM's TagUser and UntagUser would.
#[utoipa::path(put, path = "/users/{user}/tags", params(("user" = String, Path)), request_body = UserTags, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn set_user_tags(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<UserTags>,
) -> Result<StatusCode> {
    let tags: Vec<(String, String)> = body.tags.into_iter().map(|t| (t.key, t.value)).collect();
    users::check_tags(&tags).map_err(ApiError::BadRequest)?;
    let account = account_of(&app, &actor, &name).await?;
    let client = app.pool.get().await?;
    let user = users::Target::load(&client, &account, &name)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("no user named {name:?}")))?;
    let gone: Vec<String> = user
        .tags
        .iter()
        .filter(|(k, _)| !tags.iter().any(|(key, _)| key.eq_ignore_ascii_case(k)))
        .map(|(k, _)| k.clone())
        .collect();
    let changed: Vec<(String, String)> = tags.iter().filter(|t| !user.tags.contains(t)).cloned().collect();
    if !gone.is_empty() {
        let mut extra = Context::default();
        extra.set_all("aws:TagKeys", gone.clone());
        check_user_with(&app, &actor, "iam:UntagUser", &name, extra).await?;
    }
    if !changed.is_empty() {
        check_user_with(&app, &actor, "iam:TagUser", &name, users::request_tags_context(&changed)).await?;
    }
    if !gone.is_empty() {
        users::untag(&client, user.id, &gone).await?;
    }
    if !changed.is_empty() {
        users::tag(&client, user.id, &changed).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct AdminFlag {
    admin: bool,
}

/// Makes a user an admin, or not.
#[utoipa::path(put, path = "/users/{user}/admin", params(("user" = String, Path)),
    request_body = AdminFlag, responses(
        (status = 204, description = "Changed"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn set_admin(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<AdminFlag>,
) -> Result<StatusCode> {
    // AdministratorAccess, attached or detached.
    let action = if body.admin { "iam:AttachUserPolicy" } else { "iam:DetachUserPolicy" };
    let arn = crate::managed::aws_arn(crate::managed::ADMINISTRATOR_ACCESS);
    let account = check_user_with(&app, &actor, action, &name, key("iam:PolicyARN", &arn)).await?.account;
    users::update(&app.pool.get().await?, &account, &name, Some(body.admin), None).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Managed policies ────────────────────────────────────────────────────────

/// A managed policy: one of Cairn's (AWS's names), or the account's own.
#[derive(Serialize, ToSchema)]
struct PolicySummary {
    name: String,
    arn: String,
    /// Whether it's one of Cairn's (AWS's), which can't be changed.
    aws: bool,
    description: String,
    document: String,
    /// Its default version's number (`v1`, ...).
    version: i32,
    updated_at: Option<f64>,
    /// The account's users it's attached to.
    users: Vec<String>,
    /// Its path (`/`, or `/…/`).
    path: String,
    /// The account's users whose permissions boundary it is.
    bounds: Vec<String>,
    /// Its tags (keys case-sensitive), oldest first.
    tags: Vec<Tag>,
}

#[utoipa::path(get, path = "/policies", responses(
    (status = 200, body = Vec<PolicySummary>),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn list_policies(State(app): AppState, Extension(actor): Extension<Actor>) -> Result<Json<Vec<PolicySummary>>> {
    actor.check(&app, "iam:ListPolicies", On::Account).await?;
    let client = app.pool.get().await?;
    let account = actor.account();
    let attached = crate::managed::attached_all(&client, account).await?;
    let names: HashMap<uuid::Uuid, String> = client
        .query_cached("SELECT id, name FROM users WHERE account_id = $1", &[&account])
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    // Who has which of Cairn's as a boundary.
    let mut aws_bounds: HashMap<String, Vec<String>> = HashMap::new();
    for row in client
        .query_cached(
            "SELECT boundary_aws, name FROM users WHERE account_id = $1 AND boundary_aws IS NOT NULL ORDER BY name",
            &[&account],
        )
        .await?
    {
        aws_bounds.entry(row.get(0)).or_default().push(row.get(1));
    }
    let users_of = |arn: &str| {
        let mut users: Vec<String> = attached
            .iter()
            .filter(|(_, policies)| policies.iter().any(|p| p.arn == arn))
            .filter_map(|(id, _)| names.get(id).cloned())
            .collect();
        users.sort();
        users
    };
    let mut policies: Vec<PolicySummary> = crate::managed::AWS_POLICIES
        .iter()
        .map(|p| {
            let arn = crate::managed::aws_arn(p.name);
            PolicySummary {
                users: users_of(&arn),
                name: p.name.to_owned(),
                arn,
                aws: true,
                description: p.description.to_owned(),
                document: p.document.to_owned(),
                version: 1,
                updated_at: None,
                path: "/".to_owned(),
                bounds: aws_bounds.remove(p.name).unwrap_or_default(),
                tags: Vec::new(),
            }
        })
        .collect();
    for p in crate::managed::list(&client, account).await? {
        policies.push(PolicySummary {
            arn: p.arn(account),
            name: p.name,
            aws: false,
            description: p.description,
            document: p.document,
            version: p.version,
            updated_at: Some(p.updated_at),
            users: p.users,
            path: p.path,
            bounds: p.bounds,
            tags: p.tags.into_iter().map(|(key, value)| Tag { key, value }).collect(),
        });
    }
    Ok(Json(policies))
}

#[derive(Deserialize, ToSchema)]
struct NewPolicy {
    name: String,
    document: String,
    #[serde(default)]
    description: String,
    /// Its path (`/`, or `/…/`); `/` if not given.
    path: Option<String>,
    /// Its tags (keys case-sensitive).
    #[serde(default)]
    tags: Vec<Tag>,
}

#[utoipa::path(post, path = "/policies", request_body = NewPolicy, responses(
    (status = 201, description = "Made"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_policy(State(app): AppState, Extension(actor): Extension<Actor>, Json(body): Json<NewPolicy>) -> Result<StatusCode> {
    let account = actor.account().to_owned();
    let path = body.path.clone().filter(|p| !p.is_empty()).unwrap_or_else(|| "/".to_owned());
    let tags: Vec<(String, String)> = body.tags.iter().map(|t| (t.key.clone(), t.value.clone())).collect();
    crate::managed::check_tags(&tags).map_err(ApiError::BadRequest)?;
    // With tags, as IAM's CreatePolicy, it takes TagPolicy too.
    let asked = users::request_tags_context(&tags);
    actor.check_with(&app, "iam:CreatePolicy", On::policy(&account, &path, &body.name), &asked).await?;
    if !tags.is_empty() {
        actor.check_with(&app, "iam:TagPolicy", On::policy(&account, &path, &body.name), &asked).await?;
    }
    let client = app.pool.get().await?;
    crate::managed::create_tagged(&client, &account, &body.name, &path, &body.document, &body.description, &tags).await?;
    Ok(StatusCode::CREATED)
}

/// The condition keys of IAM's actions on a managed policy: its tags, as
/// `aws:ResourceTag/…`.
fn policy_context(policy: &crate::managed::Managed) -> Context {
    let mut context = Context::default();
    for (key, value) in &policy.tags {
        context.set(&format!("aws:ResourceTag/{key}"), value);
    }
    context
}

/// One of a managed policy's versions.
#[derive(Serialize, ToSchema)]
struct PolicyVersion {
    /// Its number (`v1`, ...).
    version: i32,
    document: String,
    created_at: f64,
    /// Whether it's the default, which decides.
    default: bool,
}

/// The account's managed policy `name`, if IAM's `action` on it is allowed.
async fn checked_policy(app: &Arc<App>, actor: &Actor, action: &'static str, name: &str) -> Result<crate::managed::Managed> {
    let account = actor.account();
    let policy = crate::managed::get(&app.pool.get().await?, account, name).await?;
    actor.check_with(app, action, On::policy(account, &policy.path, &policy.name), &policy_context(&policy)).await?;
    Ok(policy)
}

/// A managed policy's versions (up to five), newest first.
#[utoipa::path(get, path = "/policies/{name}/versions", params(("name" = String, Path)), responses(
    (status = 200, body = Vec<PolicyVersion>),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn list_policy_versions(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
) -> Result<Json<Vec<PolicyVersion>>> {
    let policy = checked_policy(&app, &actor, "iam:ListPolicyVersions", &name).await?;
    let versions = crate::managed::versions(&app.pool.get().await?, policy.id).await?;
    Ok(Json(
        versions
            .into_iter()
            .map(|v| PolicyVersion { version: v.version, document: v.document, created_at: v.created_at, default: v.default })
            .collect(),
    ))
}

#[derive(Deserialize, ToSchema)]
struct DefaultVersion {
    version: i32,
}

/// Makes one of a managed policy's versions its default (a rollback, say).
#[utoipa::path(put, path = "/policies/{name}/default", params(("name" = String, Path)), request_body = DefaultVersion, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn set_default_version(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<DefaultVersion>,
) -> Result<StatusCode> {
    let policy = checked_policy(&app, &actor, "iam:SetDefaultPolicyVersion", &name).await?;
    let arn = policy.arn(actor.account());
    crate::managed::set_default(&app.pool.get().await?, policy.id, &arn, body.version).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes one of a managed policy's versions, but its default.
#[utoipa::path(delete, path = "/policies/{name}/versions/{version}", params(("name" = String, Path), ("version" = i32, Path)), responses(
    (status = 204, description = "Deleted"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_policy_version(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((name, version)): Path<(String, i32)>,
) -> Result<StatusCode> {
    let policy = checked_policy(&app, &actor, "iam:DeletePolicyVersion", &name).await?;
    let arn = policy.arn(actor.account());
    crate::managed::delete_version(&app.pool.get().await?, policy.id, &arn, version).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct PolicyTags {
    /// All of its tags (keys case-sensitive): those it has of other keys go
    /// (UntagPolicy), the rest are set (TagPolicy).
    tags: Vec<Tag>,
}

/// Sets a managed policy's tags, as IAM's TagPolicy and UntagPolicy would.
#[utoipa::path(put, path = "/policies/{name}/tags", params(("name" = String, Path)), request_body = PolicyTags, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn set_policy_tags(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<PolicyTags>,
) -> Result<StatusCode> {
    let tags: Vec<(String, String)> = body.tags.into_iter().map(|t| (t.key, t.value)).collect();
    crate::managed::check_tags(&tags).map_err(ApiError::BadRequest)?;
    let account = actor.account().to_owned();
    let client = app.pool.get().await?;
    let policy = crate::managed::get(&client, &account, &name).await?;
    let on = || On::policy(&account, &policy.path, &policy.name);
    let gone: Vec<String> =
        policy.tags.iter().filter(|(k, _)| !tags.iter().any(|(key, _)| key == k)).map(|(k, _)| k.clone()).collect();
    let changed: Vec<(String, String)> = tags.iter().filter(|t| !policy.tags.contains(t)).cloned().collect();
    if !gone.is_empty() {
        let mut context = policy_context(&policy);
        context.set_all("aws:TagKeys", gone.clone());
        actor.check_with(&app, "iam:UntagPolicy", on(), &context).await?;
    }
    if !changed.is_empty() {
        let mut context = policy_context(&policy);
        context.extend(&users::request_tags_context(&changed));
        actor.check_with(&app, "iam:TagPolicy", on(), &context).await?;
    }
    if !gone.is_empty() {
        crate::managed::untag(&client, policy.id, &gone).await?;
    }
    if !changed.is_empty() {
        crate::managed::tag(&client, policy.id, &changed).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct PolicyChange {
    /// Its new document (a new default version); unchanged if not given.
    document: Option<String>,
    /// Its new description; unchanged if not given.
    description: Option<String>,
}

#[utoipa::path(put, path = "/policies/{name}", params(("name" = String, Path)), request_body = PolicyChange, responses(
    (status = 204, description = "Changed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn update_policy(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<PolicyChange>,
) -> Result<StatusCode> {
    let account = actor.account().to_owned();
    let client = app.pool.get().await?;
    let policy = crate::managed::get(&client, &account, &name).await?;
    actor.check_with(&app, "iam:CreatePolicyVersion", On::policy(&account, &policy.path, &name), &policy_context(&policy)).await?;
    if let Some(document) = &body.document {
        crate::managed::update(&client, &account, &name, document).await?;
    }
    if let Some(description) = &body.description {
        crate::managed::describe(&client, &account, &name, description).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(delete, path = "/policies/{name}", params(("name" = String, Path)), responses(
    (status = 204, description = "Deleted"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_policy_managed(State(app): AppState, Extension(actor): Extension<Actor>, Path(name): Path<String>) -> Result<StatusCode> {
    let account = actor.account().to_owned();
    let client = app.pool.get().await?;
    let policy = crate::managed::get(&client, &account, &name).await?;
    actor.check_with(&app, "iam:DeletePolicy", On::policy(&account, &policy.path, &name), &policy_context(&policy)).await?;
    crate::managed::delete(&client, &account, &name).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
struct PolicyArn {
    arn: String,
}

/// Attaches a managed policy to a user.
#[utoipa::path(post, path = "/users/{user}/attached", params(("user" = String, Path)), request_body = PolicyArn, responses(
    (status = 204, description = "Attached"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn attach_policy(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<PolicyArn>,
) -> Result<StatusCode> {
    let account = check_user_with(&app, &actor, "iam:AttachUserPolicy", &name, key("iam:PolicyARN", &body.arn)).await?.account;
    crate::managed::attach(&app.pool.get().await?, &account, &name, &body.arn, true).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Detaches a managed policy from a user.
#[utoipa::path(delete, path = "/users/{user}/attached", params(("user" = String, Path), PolicyArn), responses(
    (status = 204, description = "Detached"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn detach_policy(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Query(params): Query<PolicyArn>,
) -> Result<StatusCode> {
    let account = check_user_with(&app, &actor, "iam:DetachUserPolicy", &name, key("iam:PolicyARN", &params.arn)).await?.account;
    crate::managed::attach(&app.pool.get().await?, &account, &name, &params.arn, false).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Console enrollment ──────────────────────────────────────────────────────

/// A one-time link for a user to register its first passkey for the
/// console, valid 24 hours.
#[derive(Serialize, ToSchema)]
struct EnrollmentLink {
    /// The link, if this node serves the console (and so knows its URL).
    url: Option<String>,
    /// The link's path, for the console's URL.
    path: String,
}

/// Makes a user an enrollment link for the console, replacing its last.
#[utoipa::path(post, path = "/users/{user}/enrollment", params(("user" = String, Path)), responses(
    (status = 201, body = EnrollmentLink),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_enrollment(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
) -> Result<(StatusCode, Json<EnrollmentLink>)> {
    // A way into the console: IAM's is a login profile.
    let account = check_user(&app, &actor, "iam:CreateLoginProfile", &name).await?;
    let token = crate::console::store::create_enrollment(&app.pool.get().await?, &account, &name).await?;
    let path = format!("/enroll#{token}");
    let url = app.console.origin.as_ref().map(|origin| format!("{origin}{path}"));
    Ok((StatusCode::CREATED, Json(EnrollmentLink { url, path })))
}

// ─── Access keys ─────────────────────────────────────────────────────────────

/// A new access key, whose secret is shown only this once.
#[derive(Serialize, ToSchema)]
struct NewKey {
    id: String,
    secret: String,
}

/// Makes a new access key for a user, with a random ID and secret; a user
/// has at most two.
#[utoipa::path(post, path = "/users/{user}/keys", params(("user" = String, Path)), responses(
    (status = 201, body = NewKey),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_key(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
) -> Result<(StatusCode, Json<NewKey>)> {
    let account = check_user(&app, &actor, "iam:CreateAccessKey", &name).await?;
    let (id, secret) = users::create_key(&app.pool.get().await?, &account, &name, None, None).await?;
    Ok((StatusCode::CREATED, Json(NewKey { id, secret })))
}

#[derive(Deserialize, ToSchema)]
struct KeyState {
    active: bool,
}

/// Lets one of the user's access keys sign requests, or stops it.
#[utoipa::path(put, path = "/users/{user}/keys/{key}", params(("user" = String, Path), ("key" = String, Path)),
    request_body = KeyState, responses(
        (status = 204, description = "Changed"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn set_key(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((name, key)): Path<(String, String)>,
    Json(body): Json<KeyState>,
) -> Result<StatusCode> {
    let account = check_user(&app, &actor, "iam:UpdateAccessKey", &name).await?;
    users::set_key_active(&app.pool.get().await?, Some((&account, &name)), &key, body.active).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes one of the user's access keys.
#[utoipa::path(delete, path = "/users/{user}/keys/{key}", params(("user" = String, Path), ("key" = String, Path)),
    responses(
        (status = 204, description = "Deleted"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn delete_key(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((name, key)): Path<(String, String)>,
) -> Result<StatusCode> {
    let account = check_user(&app, &actor, "iam:DeleteAccessKey", &name).await?;
    users::delete_key(&app.pool.get().await?, Some((&account, &name)), &key).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── Inline policies ─────────────────────────────────────────────────────────

/// An inline policy: a JSON document in IAM's policy language.
#[derive(Serialize, Deserialize, ToSchema)]
struct PolicyDocument {
    document: String,
}

/// One of the user's inline policies, as it was set.
#[utoipa::path(get, path = "/users/{user}/policies/{policy}",
    params(("user" = String, Path), ("policy" = String, Path)), responses(
        (status = 200, body = PolicyDocument),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn get_policy(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((name, policy)): Path<(String, String)>,
) -> Result<Json<PolicyDocument>> {
    let account = check_user(&app, &actor, "iam:GetUserPolicy", &name).await?;
    let document = users::get_policy(&app.pool.get().await?, &account, &name, &policy).await?;
    Ok(Json(PolicyDocument { document }))
}

/// Sets one of the user's inline policies, if it's a valid identity policy.
#[utoipa::path(put, path = "/users/{user}/policies/{policy}",
    params(("user" = String, Path), ("policy" = String, Path)), request_body = PolicyDocument, responses(
        (status = 204, description = "Set"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn put_policy(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((name, policy)): Path<(String, String)>,
    Json(body): Json<PolicyDocument>,
) -> Result<StatusCode> {
    let account = check_user(&app, &actor, "iam:PutUserPolicy", &name).await?;
    users::put_policy(&app.pool.get().await?, &account, &name, &policy, &body.document).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes one of the user's inline policies.
#[utoipa::path(delete, path = "/users/{user}/policies/{policy}",
    params(("user" = String, Path), ("policy" = String, Path)), responses(
        (status = 204, description = "Deleted"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn delete_policy(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((name, policy)): Path<(String, String)>,
) -> Result<StatusCode> {
    let account = check_user(&app, &actor, "iam:DeleteUserPolicy", &name).await?;
    users::delete_policy(&app.pool.get().await?, &account, &name, &policy).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod e2e {
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::super::e2e::{console_of, signed_in, superadmin};
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
        assert_eq!(o["versions"][0]["size"], 20);
        assert!(o["versions"][0]["encryption"].is_null());

        let c = serde_json::to_value(cluster(&app).await.unwrap()).unwrap();
        assert_eq!(c["nodes"][0]["stats"]["node"], app.node);
        assert!(c["nodes"][0]["stats"]["requests"]["ops"].is_array());
    }

    #[test]
    fn tells_how_a_version_is_encrypted() {
        use crate::s3::sse::{Envelope, Stored};
        assert!(EncryptionInfo::of(Stored::Plain).is_none());
        let sse_c = EncryptionInfo::of(Stored::Customer { sealed: vec![0; 72] }).unwrap();
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

    /// The redundancy settings, and removing nodes, as a superadmin
    /// changes them.
    #[tokio::test]
    async fn sets_redundancy_and_removes_nodes() {
        let Some(app) = node().await else { return };
        let client = app.pool.get().await.unwrap();
        let mut ops = superadmin(&console_of(&app), "super").await;
        let set = |name: &str| format!("/api/settings/{name}");
        let value = |value: Value| Some(json!({ "value": value }));
        // A single node: 3 copies take more than it has.
        let (status, body) = ops.send("PUT", &set("parity-shards"), value(2.into())).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["warnings"][0].as_str().unwrap().contains("uploads fail"), "{body}");
        assert_eq!(crate::settings::PARITY_SHARDS.get_set(&client).await.unwrap(), Some(2));
        assert_eq!(app.parity_shards(), 2, "the node answering goes by it at once");
        let storage = serde_json::to_value(storage(&app).await.unwrap()).unwrap();
        assert_eq!(storage["packer"]["parity_setting"], 2);
        assert_eq!(ops.send("PUT", &set("parity-shards"), value(Value::Null)).await.0, StatusCode::OK);
        assert_eq!(crate::settings::PARITY_SHARDS.get_set(&client).await.unwrap(), None);
        assert_eq!(app.parity_shards(), 0, "the flag again");
        assert_eq!(ops.send("PUT", &set("repair-after"), value(30.into())).await.0, StatusCode::OK);
        assert_eq!(crate::settings::REPAIR_AFTER.get(&client).await.unwrap(), 30);
        let (status, body) = ops.send("PUT", &set("data-shards"), value(0.into())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("from 1 to"), "{body}");
        assert_eq!(ops.send("PUT", &set("lifecycle-rate"), value(1.into())).await.0, StatusCode::NOT_FOUND);

        let node = app.node;
        let (status, body) = ops.send("POST", &format!("/api/nodes/{node}/remove"), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["shards"], 0);
        assert_eq!(ops.send("POST", &format!("/api/nodes/{node}/remove"), None).await.0, StatusCode::CONFLICT);
        assert_eq!(ops.send("POST", &format!("/api/nodes/{node}/keep"), None).await.0, StatusCode::NO_CONTENT);
        let cluster = serde_json::to_value(cluster(&app).await.unwrap()).unwrap();
        assert_eq!(cluster["nodes"][0]["state"], "active");
        assert_eq!(ops.send("POST", "/api/nodes/9999/keep", None).await.0, StatusCode::NOT_FOUND);
    }

    /// A bucket's lifecycle rules, as its account's admin edits them, and
    /// the sweeps' rate, as a superadmin sets it.
    #[tokio::test]
    async fn edits_lifecycle_rules() {
        let Some(app) = node().await else { return };
        let console = console_of(&app);
        let mut admin = signed_in(&console, "admin", true).await;
        let mut ops = superadmin(&console, "super").await;
        let path = format!("/api/buckets/{BUCKET}/lifecycle");
        let (status, body) = admin.send("GET", &path, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["configuration"], Value::Null);

        let rules = json!({"rules": [
            {"enabled": true, "filter": {"prefix": "tmp/"}, "expiration": {"days": 1}},
        ]});
        assert_eq!(admin.send("PUT", &path, Some(rules)).await.0, StatusCode::NO_CONTENT);
        let (_, stored) = admin.send("GET", &path, None).await;
        let rule = &stored["configuration"]["rules"][0];
        assert_eq!(rule["filter"]["prefix"], "tmp/");
        // It was given a name.
        assert_eq!(rule["id"].as_str().unwrap().len(), 32);
        // S3 sees the same rules.
        let xml = crate::s3::buckets::lifecycle::get_bucket_lifecycle(&app, BUCKET).await.unwrap();
        let xml = xml.into_body().collect().await.unwrap().to_bytes();
        assert!(std::str::from_utf8(&xml).unwrap().contains("<Prefix>tmp/</Prefix>"));
        // And the Jobs page lists the bucket.
        let (_, jobs) = ops.send("GET", "/api/lifecycle", None).await;
        assert_eq!(jobs["buckets"][0]["bucket"], BUCKET);
        assert_eq!(jobs["rate"], crate::settings::LIFECYCLE_RATE.default);

        // Rules S3 would refuse are refused, with why.
        let bad = json!({"rules": [
            {"id": "a", "enabled": true, "filter": {"size_less_than": 5}, "abort_upload_days": 1},
        ]});
        let (status, body) = admin.send("PUT", &path, Some(bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("cannot be specified with Object Size"), "{body}");
        let unknown = json!({"rules": [{"id": "a", "enabled": true, "filter": {"tag": "x"}}]});
        assert!(admin.send("PUT", &path, Some(unknown)).await.0.is_client_error());
        let rules = json!({"rules": [{"enabled": true, "filter": {}, "expiration": {"days": 1}}]});
        assert_eq!(admin.send("PUT", "/api/buckets/nope/lifecycle", Some(rules)).await.0, StatusCode::NOT_FOUND);

        // The rate, for the cluster: its operators' (`cairn:`).
        let rate = |rate: i64| Some(json!({ "rate": rate }));
        let mut user = signed_in(&console, "lifecycle-user", false).await;
        assert_eq!(user.send("PUT", "/api/lifecycle/rate", rate(5)).await.0, StatusCode::FORBIDDEN);
        assert_eq!(ops.send("PUT", "/api/lifecycle/rate", rate(5)).await.0, StatusCode::NO_CONTENT);
        assert_eq!(crate::settings::LIFECYCLE_RATE.get(&app.pool.get().await.unwrap()).await.unwrap(), 5);
        assert_eq!(ops.send("PUT", "/api/lifecycle/rate", rate(-1)).await.0, StatusCode::BAD_REQUEST);

        assert_eq!(admin.send("DELETE", &path, None).await.0, StatusCode::NO_CONTENT);
        let (_, body) = admin.send("GET", &path, None).await;
        assert_eq!(body["configuration"], Value::Null);
    }

    /// A bucket's policy and public access block, and its account's block,
    /// as the account's admin edits them (and a superadmin can't).
    #[tokio::test]
    async fn edits_bucket_access() {
        let Some(app) = node().await else { return };
        let console = console_of(&app);
        let mut admin = signed_in(&console, "admin", true).await;
        let mut ops = superadmin(&console, "super").await;
        let access = format!("/api/buckets/{BUCKET}/access");
        let all = json!({
            "block_public_acls": true, "ignore_public_acls": true,
            "block_public_policy": true, "restrict_public_buckets": true,
        });
        let (_, first) = admin.send("GET", &access, None).await;
        assert_eq!((&first["policy"], &first["public"]), (&Value::Null, &Value::Bool(false)));
        assert_eq!(first["public_access_block"], all);
        assert_eq!(first["account_public_access_block"], Value::Null);

        let document = format!(
            r#"{{"Statement":[{{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::{BUCKET}/*"}}]}}"#
        );
        let policy = format!("/api/buckets/{BUCKET}/policy");
        let public = || Some(json!({ "document": document }));
        let (status, body) = admin.send("PUT", &policy, public()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body["error"].as_str().unwrap().contains("BlockPublicPolicy"), "{body}");
        let block = format!("/api/buckets/{BUCKET}/public-access-block");
        let none = json!({
            "block_public_acls": false, "ignore_public_acls": false,
            "block_public_policy": false, "restrict_public_buckets": true,
        });
        assert_eq!(admin.send("PUT", &block, Some(none.clone())).await.0, StatusCode::NO_CONTENT);
        assert_eq!(admin.send("PUT", &policy, public()).await.0, StatusCode::NO_CONTENT);
        let (_, after) = admin.send("GET", &access, None).await;
        assert_eq!((&after["public"], &after["public_access_block"]), (&Value::Bool(true), &none));
        assert!(after["policy"].as_str().unwrap().contains(r#""Principal":"*""#));
        assert_eq!(admin.send("PUT", &policy, Some(json!({ "document": "{}" }))).await.0, StatusCode::BAD_REQUEST);
        // The bucket list tells too.
        let (_, listed) = admin.send("GET", "/api/buckets", None).await;
        assert_eq!(listed[0]["public"], true);

        // The account's block: its own, not the operator's.
        let account = "/api/account/public-access-block";
        let policies = json!({
            "block_public_acls": false, "ignore_public_acls": false,
            "block_public_policy": true, "restrict_public_buckets": false,
        });
        assert_eq!(admin.send("GET", account, None).await, (StatusCode::OK, Value::Null));
        assert_eq!(ops.send("PUT", account, Some(policies.clone())).await.0, StatusCode::FORBIDDEN);
        assert_eq!(ops.send("PUT", "/api/settings/block-public-policy", Some(json!({ "value": 1 }))).await.0, StatusCode::NOT_FOUND);
        assert_eq!(admin.send("PUT", account, Some(policies.clone())).await.0, StatusCode::NO_CONTENT);
        assert_eq!(admin.send("GET", account, None).await.1, policies);
        assert_eq!(admin.send("GET", &access, None).await.1["account_public_access_block"], policies);
        let (_, listed) = admin.send("GET", "/api/buckets", None).await;
        assert_eq!(listed[0]["account_public_access_block"], policies);
        assert_eq!(admin.send("DELETE", &policy, None).await.0, StatusCode::NO_CONTENT);
        assert_eq!(admin.send("PUT", &policy, public()).await.0, StatusCode::FORBIDDEN);
        assert_eq!(admin.send("DELETE", account, None).await.0, StatusCode::NO_CONTENT);
        assert_eq!(admin.send("GET", account, None).await.1, Value::Null);
        assert_eq!(admin.send("PUT", &policy, public()).await.0, StatusCode::NO_CONTENT);

        assert_eq!(admin.send("DELETE", &block, None).await.0, StatusCode::NO_CONTENT);
        assert_eq!(admin.send("GET", &access, None).await.1["public_access_block"], Value::Null);
        assert_eq!(admin.send("GET", "/api/buckets/nope/access", None).await.0, StatusCode::NOT_FOUND);
    }

    /// Buckets, objects and users, as an account's admin manages them.
    #[tokio::test]
    async fn manages_an_account() {
        let Some(app) = node().await else { return };
        put(&app, "dir/file.txt", b"hello".to_vec()).await;
        let mut admin = signed_in(&console_of(&app), "admin", true).await;

        let (status, headers, _) = admin.request("GET", "/api/buckets", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["content-type"], "application/json");
        assert_eq!(headers["cache-control"], "no-store");
        assert!(headers.contains_key("content-security-policy"));

        let create = |name: &str| Some(json!({ "name": name }));
        assert_eq!(admin.send("POST", "/api/buckets", create("new-bucket")).await.0, StatusCode::CREATED);
        assert_eq!(admin.send("POST", "/api/buckets", create("new-bucket")).await.0, StatusCode::CONFLICT);
        let (status, body) = admin.send("POST", "/api/buckets", create("Bad_Name")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("bucket name"), "{body}");
        assert_eq!(admin.send("DELETE", "/api/buckets/new-bucket", None).await.0, StatusCode::NO_CONTENT);
        assert_eq!(admin.send("DELETE", "/api/buckets/new-bucket", None).await.0, StatusCode::NOT_FOUND);
        assert_eq!(admin.send("DELETE", &format!("/api/buckets/{BUCKET}"), None).await.0, StatusCode::CONFLICT);

        let uri = format!("/api/buckets/{BUCKET}/objects?prefix=dir%2F&deleted=false");
        let (status, listing) = admin.send("GET", &uri, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listing["entries"][0]["key"], "dir/file.txt");

        let uri = format!("/api/buckets/{BUCKET}/download?key=dir%2Ffile.txt");
        let (status, headers, body) = admin.request("GET", &uri, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"hello");
        assert_eq!(headers["content-type"], "application/octet-stream");
        assert_eq!(headers["content-disposition"], "attachment; filename*=UTF-8''file%2Etxt");
        assert_eq!(headers["content-security-policy"], "sandbox");
        let uri = format!("/api/buckets/{BUCKET}/download?key=nope");
        assert_eq!(admin.send("GET", &uri, None).await.0, StatusCode::NOT_FOUND);

        let new = json!({ "name": "ui-role", "admin": false, "access_key": true });
        let (status, created) = admin.send("POST", "/api/users", Some(new)).await;
        assert_eq!(status, StatusCode::CREATED);
        let key = created["access_key"]["name"].as_str().unwrap();
        assert_eq!(key.len(), 20);
        assert_ne!(key, "ui-role");
        assert_eq!(created["access_key"]["secret"].as_str().unwrap().len(), 40);
        // A person: no key, and a console link, which lists them as one.
        let (status, created) = admin.send("POST", "/api/users", Some(json!({ "name": "ui-person" }))).await;
        assert_eq!((status, &created["access_key"]), (StatusCode::CREATED, &Value::Null));
        let person = |roles: Value| roles.as_array().unwrap().iter().find(|r| r["name"] == "ui-person").unwrap().clone();
        let listed = person(admin.send("GET", "/api/users", None).await.1);
        assert_eq!((&listed["keys"], &listed["console"]), (&json!([]), &Value::Null));
        assert_eq!(admin.send("POST", "/api/users/ui-person/enrollment", None).await.0, StatusCode::CREATED);
        let listed = person(admin.send("GET", "/api/users", None).await.1);
        assert_eq!(listed["console"]["link_pending"], true);
        assert_eq!(listed["console"]["enrolled"], false);
        // Managed policies: Cairn's (AWS's), and the account's own.
        let (_, policies) = admin.send("GET", "/api/policies", None).await;
        let names: Vec<_> = policies.as_array().unwrap().iter().map(|p| p["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["AdministratorAccess", "AmazonS3FullAccess", "AmazonS3ReadOnlyAccess", "CairnOperatorAccess"]);
        let read = format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":["s3:Get*","s3:List*"],"Resource":["arn:aws:s3:::{BUCKET}","arn:aws:s3:::{BUCKET}/*"]}}]}}"#
        );
        let new = json!({ "name": "bucket-read", "document": read, "description": "Reads the bucket" });
        assert_eq!(admin.send("POST", "/api/policies", Some(new.clone())).await.0, StatusCode::CREATED);
        assert_eq!(admin.send("POST", "/api/policies", Some(new)).await.0, StatusCode::CONFLICT);
        let bad = json!({ "name": "bad", "document": r#"{"Statement":[{"Effect":"Allow","Action":"s3:Nope","Resource":"*"}]}"# });
        assert_eq!(admin.send("POST", "/api/policies", Some(bad)).await.0, StatusCode::BAD_REQUEST);
        let account = users::account(&app.pool.get().await.unwrap()).await.unwrap();
        let arn = format!("arn:aws:iam::{account}:policy/bucket-read");
        let attach = |arn: &str| Some(json!({ "arn": arn }));
        assert_eq!(admin.send("POST", "/api/users/ui-role/attached", attach(&arn)).await.0, StatusCode::NO_CONTENT);
        let s3_read = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess";
        assert_eq!(admin.send("POST", "/api/users/ui-role/attached", attach(s3_read)).await.0, StatusCode::NO_CONTENT);
        let nope = "arn:aws:iam::aws:policy/AmazonEC2FullAccess";
        assert_eq!(admin.send("POST", "/api/users/ui-role/attached", attach(nope)).await.0, StatusCode::NOT_FOUND);
        let ui_role = |roles: Value| roles.as_array().unwrap().iter().find(|r| r["name"] == "ui-role").unwrap().clone();
        let role = ui_role(admin.send("GET", "/api/users", None).await.1);
        assert_eq!(
            role["attached"],
            json!([{ "name": "AmazonS3ReadOnlyAccess", "arn": s3_read }, { "name": "bucket-read", "arn": arn }])
        );
        // Who has access to the bucket, by their policies.
        let (_, access) = admin.send("GET", &format!("/api/buckets/{BUCKET}/access"), None).await;
        let ui = access["users"].as_array().unwrap().iter().find(|u| u["user"] == "ui-role").unwrap().clone();
        assert_eq!(ui["levels"], json!(["list", "read"]));
        // Attached, it can't be deleted; changed, it's a new version.
        assert_eq!(admin.send("DELETE", "/api/policies/bucket-read", None).await.0, StatusCode::CONFLICT);
        let (status, _) = admin.send("PUT", "/api/policies/bucket-read", Some(json!({ "description": "Reads it" }))).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let detach = format!("/api/users/ui-role/attached?arn={}", utf8_percent_encode(&arn, NON_ALPHANUMERIC));
        assert_eq!(admin.send("DELETE", &detach, None).await.0, StatusCode::NO_CONTENT);
        assert_eq!(admin.send("DELETE", &detach, None).await.0, StatusCode::NOT_FOUND);
        assert_eq!(admin.send("DELETE", "/api/policies/bucket-read", None).await.0, StatusCode::NO_CONTENT);
        // A link to enroll a passkey for the console (this node serves none).
        let (status, enrollment) = admin.send("POST", "/api/users/ui-role/enrollment", None).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(enrollment["url"], Value::Null);
        assert!(enrollment["path"].as_str().unwrap().starts_with("/enroll#"));
        // Its access keys and inline policies.
        let (status, key) = admin.send("POST", "/api/users/ui-role/keys", None).await;
        assert_eq!(status, StatusCode::CREATED);
        let key = key["id"].as_str().unwrap().to_owned();
        let uri = format!("/api/users/ui-role/keys/{key}");
        assert_eq!(admin.send("PUT", &uri, Some(json!({ "active": false }))).await.0, StatusCode::NO_CONTENT);
        let role = ui_role(admin.send("GET", "/api/users", None).await.1);
        assert_eq!(role["keys"][1]["id"], key.as_str());
        assert_eq!(role["keys"][1]["active"], false);
        // Only its own keys.
        assert_eq!(admin.send("DELETE", "/api/users/ui-role/keys/nobody", None).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(admin.send("DELETE", &uri, None).await.0, StatusCode::NO_CONTENT);
        let uri = "/api/users/ui-role/policies/nolist";
        let document = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:ListBucket","Resource":"*"}]}"#;
        assert_eq!(admin.send("PUT", uri, Some(json!({ "document": document }))).await.0, StatusCode::NO_CONTENT);
        let (status, body) = admin.send("GET", uri, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["document"], document);
        let bad = json!({ "document": r#"{"Statement":[{"Effect":"Allow"}]}"# });
        let (status, body) = admin.send("PUT", uri, Some(bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "MalformedPolicy: Missing required field Action");
        let role = ui_role(admin.send("GET", "/api/users", None).await.1);
        assert_eq!(role["policies"], json!(["nolist"]));
        assert_eq!(admin.send("DELETE", uri, None).await.0, StatusCode::NO_CONTENT);
        assert_eq!(admin.send("GET", uri, None).await.0, StatusCode::BAD_REQUEST);

        let (status, body) = admin.send("DELETE", "/api/users/nobody", None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "no user named \"nobody\"");

        // Unknown API routes are JSON 404s; everything else is the UI.
        let (status, body) = admin.send("GET", "/api/nope", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "no such API route");
        let (status, headers, _) = admin.request("GET", "/buckets/x", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["content-type"], "text/html; charset=utf-8");
        assert_eq!(admin.send("GET", "/assets/nope.js", None).await.0, StatusCode::NOT_FOUND);
        let (_, spec) = admin.send("GET", "/api/openapi.json", None).await;
        assert_eq!(spec["servers"][0]["url"], "/api");
    }

    /// The peer endpoint serves no UI: only the nodes' own routes.
    #[tokio::test]
    async fn the_peer_endpoint_has_no_ui() {
        let Some(app) = node().await else { return };
        let get = |path: &str| {
            let req = axum::http::Request::builder().uri(path).header("host", "127.0.0.1:9431").body(axum::body::Body::empty()).unwrap();
            let app = app.clone();
            async move { crate::peer::router(app).oneshot(req).await.unwrap().status() }
        };
        for path in ["/", "/_dashboard", "/_dashboard/api/roles"] {
            assert_eq!(get(path).await, StatusCode::NOT_FOUND, "{path}");
        }
        assert_eq!(get("/stats").await, StatusCode::OK);
        assert_eq!(get("/blobs/nope").await, StatusCode::BAD_REQUEST);
        assert_eq!(get(&format!("/blobs/{}", uuid::Uuid::new_v4())).await, StatusCode::NOT_FOUND);
    }

    /// S3's CreateBucket checks names the same way.
    #[tokio::test]
    async fn s3_refuses_invalid_bucket_names() {
        let Some(app) = node().await else { return };
        let account = users::account(&app.pool.get().await.unwrap()).await.unwrap();
        let resp = crate::s3::buckets::create::create_bucket(&app, "Bad_Name", &account, false)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let resp = crate::s3::buckets::create::create_bucket(&app, BUCKET, &account, false)
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
async fn get_lifecycle(State(app): AppState, Extension(actor): Extension<Actor>) -> Result<Json<Lifecycle>> {
    actor.check(&app, "cairn:GetCluster", On::Cluster).await?;
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

/// The settings that the console changes this way: those of how blobs are
/// stored, and repaired.
const REDUNDANCY: &[&crate::settings::Setting] = &[
    &crate::settings::DATA_SHARDS,
    &crate::settings::PARITY_SHARDS,
    &crate::settings::REPAIR_AFTER,
];

/// Sets one of the redundancy settings (`data-shards`, `parity-shards`,
/// `repair-after`) for the whole cluster, as `cairn config set` does. The
/// node answering goes by it right away, the others within a heartbeat.
#[utoipa::path(put, path = "/settings/{name}", params(("name" = String, Path)),
    request_body = NewSetting, responses(
        (status = 200, body = SettingChanged),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn set_setting(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<NewSetting>,
) -> Result<Json<SettingChanged>> {
    actor.check(&app, "cairn:PutSetting", On::Cluster).await?;
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
async fn remove_node(State(app): AppState, Extension(actor): Extension<Actor>, Path(id): Path<i32>) -> Result<Json<NodeRemoved>> {
    actor.check(&app, "cairn:RemoveNode", On::Cluster).await?;
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
async fn keep_node(State(app): AppState, Extension(actor): Extension<Actor>, Path(id): Path<i32>) -> Result<StatusCode> {
    actor.check(&app, "cairn:RemoveNode", On::Cluster).await?;
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
async fn set_lifecycle_rate(State(app): AppState, Extension(actor): Extension<Actor>, Json(body): Json<NewRate>) -> Result<StatusCode> {
    actor.check(&app, "cairn:PutSetting", On::Cluster).await?;
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
