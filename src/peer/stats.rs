//! What a node reports about itself at `/stats`, for the console's cluster
//! pages: whichever node answers asks every other one.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{App, metrics::MetricsReport, metrics::now_secs};

/// What a node reports about itself, for the console of any node (see
/// `peer`'s `/stats`).
#[derive(Serialize, Deserialize, ToSchema)]
pub struct NodeStats {
    pub node: i32,
    pub node_id: String,
    pub version: String,
    pub replication_factor: usize,
    /// How many bytes per second its scrubber reads; 0 if it's off.
    pub scrub_rate: u64,
    /// The node's clock, in seconds since the Unix epoch.
    pub now: f64,
    /// The filesystem of its data dir, if it could tell.
    pub disk: Option<Disk>,
    pub disk_error: Option<String>,
    /// Its KMS, if it has one (see `kms`).
    pub kms: Option<KmsStatus>,
    #[serde(flatten)]
    pub metrics: MetricsReport,
}

/// A node's KMS, as it sees it.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct KmsStatus {
    /// The KMS's URL.
    pub address: String,
    /// Where the KMS's JWT auth method for Cairn is mounted (under `auth/`),
    /// and the role of it that Cairn's logins use.
    pub auth_mount: String,
    pub auth_role: String,
    /// The public key of the key the node signs its logins with (PEM): what
    /// that auth method is to trust (`jwt_validation_pubkeys`). The same on
    /// every node.
    pub public_key: String,
    /// Whether the node could reach the KMS just now, and how it is.
    pub reachable: bool,
    pub initialized: Option<bool>,
    pub sealed: Option<bool>,
    pub standby: Option<bool>,
    pub version: Option<String>,
    /// Why it couldn't reach it.
    pub error: Option<String>,
    /// The node's last login as a role, if it made one since it started.
    pub last_login: Option<KmsLogin>,
    /// When its last login that worked was, in seconds since the Unix epoch.
    pub last_success: Option<f64>,
    /// SSE-S3's key, if Cairn has one: it uses it as itself.
    pub sse_s3_key: Option<String>,
    /// Cairn's own identity (entity) in the KMS, which is to be granted that
    /// key, once the node has logged in as itself.
    pub cairn_entity: Option<String>,
}

/// A login to the KMS as a role.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct KmsLogin {
    /// When, in seconds since the Unix epoch.
    pub at: f64,
    /// The role's ID, or `cairn` for Cairn itself (for SSE-S3).
    pub role: String,
    /// Why it failed, if it did: what's likely wrong with the KMS's setup.
    pub error: Option<String>,
}

/// The node's KMS, if it has one, as it sees it now.
async fn kms_status(app: &App) -> Option<KmsStatus> {
    let kms = app.kms.as_ref()?;
    let health = kms.health().await;
    let logins = kms.logins();
    let (auth_mount, auth_role) = kms.auth();
    Some(KmsStatus {
        address: kms.address().to_owned(),
        auth_mount: auth_mount.to_owned(),
        auth_role: auth_role.to_owned(),
        public_key: kms.public_key_pem(),
        reachable: health.reachable,
        initialized: health.initialized,
        sealed: health.sealed,
        standby: health.standby,
        version: health.version,
        error: health.error,
        last_login: logins.last.map(|login| KmsLogin {
            at: login.at,
            role: login.who.subject(),
            error: login.error,
        }),
        last_success: logins.last_success,
        sse_s3_key: kms.sse_s3_key().map(|key| key.as_string()),
        cairn_entity: kms.cairn_entity(),
    })
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct Disk {
    /// Bytes in all.
    pub total: u64,
    /// Bytes Cairn may still write.
    pub available: u64,
}

pub async fn node_stats(app: &App) -> NodeStats {
    let (disk, disk_error) = match app.store.disk_space() {
        Ok((total, available)) => (Some(Disk { total, available }), None),
        Err(e) => (None, Some(e.to_string())),
    };
    NodeStats {
        node: app.node,
        node_id: app.store.get_node_id().to_string(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        replication_factor: app.replication_factor(),
        scrub_rate: app.scrub_rate,
        now: now_secs(),
        disk,
        disk_error,
        kms: kms_status(app).await,
        metrics: app.metrics.report(),
    }
}

