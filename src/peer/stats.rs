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
    /// The filesystems of its data dirs, together (each counted once), if
    /// it could tell.
    pub disk: Option<Disk>,
    pub disk_error: Option<String>,
    /// Its pools (see `classes`), and their filesystems.
    pub pools: Vec<PoolDisk>,
    /// Its KMS, if it has one (see `kms`).
    pub kms: Option<KmsStatus>,
    #[serde(flatten)]
    pub metrics: MetricsReport,
}

/// A node's KMS, as it sees it (see `kms`).
#[derive(Serialize, Deserialize, ToSchema)]
pub struct KmsStatus {
    /// Where its root key is: `file` (`--kms-root-key-file`) or `openbao`.
    pub root: String,
    /// OpenBao's URL, and the Transit key that's the root key (`<mount>/<key>`).
    pub address: Option<String>,
    pub transit_key: Option<String>,
    /// Where OpenBao's JWT auth method for Cairn is mounted (under `auth/`),
    /// and the role of it that Cairn's logins use.
    pub auth_mount: Option<String>,
    pub auth_role: Option<String>,
    /// The public key of the key the node signs its logins with (PEM): what
    /// that auth method is to trust (`jwt_validation_pubkeys`). The same on
    /// every node.
    pub public_key: Option<String>,
    /// Whether the node could reach OpenBao just now, and how it is (a file
    /// root is always reachable).
    pub reachable: bool,
    pub initialized: Option<bool>,
    pub sealed: Option<bool>,
    pub standby: Option<bool>,
    pub version: Option<String>,
    /// Why it couldn't reach it.
    pub error: Option<String>,
    /// The node's last login to OpenBao, if it made one since it started.
    pub last_login: Option<KmsLogin>,
    /// When its last login that worked was, in seconds since the Unix epoch.
    pub last_success: Option<f64>,
}

/// A login to OpenBao.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct KmsLogin {
    /// When, in seconds since the Unix epoch.
    pub at: f64,
    /// Why it failed, if it did: what's likely wrong with OpenBao's setup.
    pub error: Option<String>,
}

/// The node's KMS, if it has one, as it sees it now.
async fn kms_status(app: &App) -> Option<KmsStatus> {
    let kms = app.kms.as_ref()?;
    let transit = match kms.root() {
        crate::kms::Root::File(_) => {
            return Some(KmsStatus {
                root: "file".to_owned(),
                address: None,
                transit_key: None,
                auth_mount: None,
                auth_role: None,
                public_key: None,
                reachable: true,
                initialized: None,
                sealed: None,
                standby: None,
                version: None,
                error: None,
                last_login: None,
                last_success: None,
            });
        }
        crate::kms::Root::Transit(transit) => transit,
    };
    let health = transit.health().await;
    let logins = transit.logins();
    let (auth_mount, auth_role) = transit.auth();
    Some(KmsStatus {
        root: "openbao".to_owned(),
        address: Some(transit.address().to_owned()),
        transit_key: Some(transit.key()),
        auth_mount: Some(auth_mount.to_owned()),
        auth_role: Some(auth_role.to_owned()),
        public_key: Some(transit.public_key_pem()),
        reachable: health.reachable,
        initialized: health.initialized,
        sealed: health.sealed,
        standby: health.standby,
        version: health.version,
        error: health.error,
        last_login: logins.last.map(|(at, error)| KmsLogin { at, error }),
        last_success: logins.last_success,
    })
}

/// A pool of a node, and the filesystem of its data dir.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct PoolDisk {
    pub name: String,
    pub disk: Option<Disk>,
    pub disk_error: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct Disk {
    /// Bytes in all.
    pub total: u64,
    /// Bytes Cairn may still write.
    pub available: u64,
}

pub async fn node_stats(app: &App) -> NodeStats {
    let mut pools = Vec::new();
    let mut sum = Disk {
        total: 0,
        available: 0,
    };
    let mut disk_error = None;
    let mut counted = Vec::new();
    for pool in app.store.pools() {
        let (disk, error) = match pool.disk_space() {
            Ok((total, available)) => {
                // Pools on one filesystem share its space.
                let device = std::fs::metadata(pool.data_dir())
                    .map(|m| std::os::unix::fs::MetadataExt::dev(&m))
                    .ok();
                if device.is_none() || !counted.contains(&device) {
                    counted.push(device);
                    sum.total += total;
                    sum.available += available;
                }
                (Some(Disk { total, available }), None)
            }
            Err(e) => {
                disk_error.get_or_insert_with(|| e.to_string());
                (None, Some(e.to_string()))
            }
        };
        pools.push(PoolDisk {
            name: pool.name.clone(),
            disk,
            disk_error: error,
        });
    }
    let disk = disk_error.is_none().then_some(sum);
    NodeStats {
        node: app.node,
        node_id: app.store.get_node_id().to_string(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        replication_factor: app.replication_factor(),
        scrub_rate: app.scrub_rate,
        now: now_secs(),
        disk,
        disk_error,
        pools,
        kms: kms_status(app).await,
        metrics: app.metrics.report(),
    }
}
