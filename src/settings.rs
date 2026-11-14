//! The cluster's settings: values every node goes by, kept in the database
//! (`settings`), so that they're the same everywhere, and a change reaches
//! every node at once. Set with `cairn config set`, or in the console. A
//! setting that was never set has its default.

use clap::{Args, Subcommand};
use deadpool_postgres::GenericClient;

use crate::db::Cached;

/// A setting: its name, default, and what it allows.
pub struct Setting {
    pub name: &'static str,
    pub default: i64,
    pub min: i64,
    pub max: i64,
    pub help: &'static str,
    /// What it means while it's not set, if not its default (see
    /// `get_set`).
    pub unset: Option<&'static str>,
}

/// How many object versions lifecycle sweeps may read an hour, across the
/// whole cluster (see `lifecycle`).
pub const LIFECYCLE_RATE: Setting = Setting {
    name: "lifecycle-rate",
    default: 1_000_000,
    min: 0,
    max: i64::MAX,
    help: "object versions lifecycle sweeps read per hour, across the cluster (0 pauses them)",
    unset: None,
};

/// How many data shards blobs larger than `packer::SMALL_SIZE` are coded
/// into (see `shards` and `packer`); 1 keeps every blob replicated. Smaller
/// ones are replicated until they're packed. Their parity shards are
/// `PARITY_SHARDS`, as a replicated blob's are, so coded data survives as
/// many lost nodes as replicated data. Only the operator knows how many nodes
/// the cluster will keep, so Cairn never picks this itself: coding needs as
/// many live nodes as data and parity shards, and with fewer, uploads are
/// replicated, and the packer leaves data as it is. A change applies to
/// uploads within a heartbeat, and the packer rewrites the blobs written
/// before it over time (see `packer::Layouts`).
pub const DATA_SHARDS: Setting = Setting {
    name: "data-shards",
    default: 1,
    min: 1,
    max: crate::shards::MAX_DATA_SHARDS as i64,
    help: "data shards that blobs over 64 MiB are erasure-coded into, plus the parity shards \
           (1 keeps replicas only)",
    unset: None,
};

/// How many parity shards every blob gets (see `shards`): the copies of a
/// replicated blob besides the first, the parity shards of a coded one. The
/// cluster survives losing that many nodes. Unset, each node goes by its
/// `--replication-factor` (less one), as before there was this setting;
/// once it's set, the flag is ignored. A change applies to blobs written from
/// then on (nodes pick it up within a heartbeat), and, while it's set, the
/// blobs written before it are brought to it over time: the mover adds or
/// drops copies of replicated ones, the packer rewrites coded ones (see
/// `mover`, `packer::Layouts`). Unset, they keep theirs, since nodes may go
/// by different flags.
pub const PARITY_SHARDS: Setting = Setting {
    name: "parity-shards",
    default: 0,
    min: 0,
    max: 16,
    help: "parity shards of every new blob, replicated or coded: the nodes it survives losing \
           (a replication factor of this plus 1)",
    unset: Some("each node's --replication-factor - 1"),
};

/// How many minutes a node may be down before its shards are rebuilt on
/// other nodes (see `mover`); 0, the default, waits for an operator to
/// remove it (`cairn node remove`). Rebuilding moves a lot of data, and a
/// node that's back after a reboot needs none of it, so it's the operator's
/// to turn on.
pub const REPAIR_AFTER: Setting = Setting {
    name: "repair-after",
    default: 0,
    min: 0,
    max: i64::MAX,
    help: "minutes a node may be down before its shards are rebuilt elsewhere \
           (0: only once it's removed with cairn node remove)",
    unset: None,
};

/// Every setting.
pub const ALL: &[&Setting] =
    &[&LIFECYCLE_RATE, &DATA_SHARDS, &PARITY_SHARDS, &REPAIR_AFTER];

/// The setting named `name`, if there's one.
pub fn named(name: &str) -> Option<&'static Setting> {
    ALL.iter().copied().find(|s| s.name == name)
}

impl Setting {
    /// Its value: what it was set to, or its default.
    pub async fn get<C: GenericClient>(&self, client: &C) -> anyhow::Result<i64> {
        Ok(self.get_set(client).await?.unwrap_or(self.default))
    }

    /// What it was set to, if it was.
    pub async fn get_set<C: GenericClient>(&self, client: &C) -> anyhow::Result<Option<i64>> {
        let row = client
            .query_opt_cached("SELECT value FROM settings WHERE name = $1", &[&self.name])
            .await?;
        match row {
            None => Ok(None),
            Some(row) => {
                let value: &str = row.get(0);
                let value = value
                    .parse()
                    .map_err(|_| anyhow::anyhow!("setting {} is {value:?}, not a number", self.name))?;
                Ok(Some(value))
            }
        }
    }

    /// Unsets it: it's its default again (or what `unset` says).
    pub async fn unset<C: GenericClient>(&self, client: &C) -> anyhow::Result<()> {
        client.execute_cached("DELETE FROM settings WHERE name = $1", &[&self.name]).await?;
        Ok(())
    }

    /// Sets it, if `value` is one it allows.
    pub async fn set<C: GenericClient>(&self, client: &C, value: i64) -> anyhow::Result<()> {
        anyhow::ensure!(value >= self.min, "{} must be at least {}", self.name, self.min);
        anyhow::ensure!(value <= self.max, "{} must be at most {}", self.name, self.max);
        client
            .execute_cached(
                "INSERT INTO settings (name, value) VALUES ($1, $2)
                 ON CONFLICT (name) DO UPDATE SET value = $2",
                &[&self.name, &value.to_string()],
            )
            .await?;
        Ok(())
    }
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Args, Debug, serde::Serialize, serde::Deserialize)]
pub struct ConfigArgs {
    #[command(flatten)]
    #[serde(skip)]
    pub remote: crate::admin::Remote,
    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(Subcommand, Debug, serde::Serialize, serde::Deserialize)]
enum ConfigCommand {
    /// Show every setting's value, or one's.
    Get { name: Option<String> },
    /// Set a setting, for the whole cluster.
    Set { name: String, value: i64 },
    /// Unset a setting: it's back to its default.
    Unset { name: String },
}

/// `cairn config …`, on a node (see `admin`).
pub async fn run(
    app: &std::sync::Arc<crate::App>,
    args: ConfigArgs,
    out: &mut crate::admin::Output,
) -> anyhow::Result<()> {
    use crate::admin::outln;
    let client = app.pool.get().await?;
    let find = |name: &str| {
        named(name).ok_or_else(|| {
            let known: Vec<&str> = ALL.iter().map(|s| s.name).collect();
            anyhow::anyhow!("no setting {name:?}; there are: {}", known.join(", "))
        })
    };
    match args.command {
        ConfigCommand::Get { name: Some(name) } => {
            let setting = find(&name)?;
            match (setting.get_set(&client).await?, setting.unset) {
                (Some(value), _) => outln!(out, "{value}"),
                (None, Some(unset)) => outln!(out, "unset: {unset}"),
                (None, None) => outln!(out, "{}", setting.default),
            }
        }
        ConfigCommand::Get { name: None } => {
            for setting in ALL {
                let value = match (setting.get_set(&client).await?, setting.unset) {
                    (Some(value), _) => value.to_string(),
                    (None, Some(unset)) => format!("unset: {unset}"),
                    (None, None) => setting.default.to_string(),
                };
                let default = setting.unset.map_or(setting.default.to_string(), |_| "unset".to_owned());
                outln!(out, "{} = {value}  # {} (default {default})", setting.name, setting.help);
            }
        }
        ConfigCommand::Set { name, value } => {
            let setting = find(&name)?;
            setting.set(&client, value).await?;
            if [DATA_SHARDS.name, PARITY_SHARDS.name].contains(&setting.name) {
                for warning in placement_warnings(&client).await? {
                    out.warn(warning);
                }
            }
        }
        ConfigCommand::Unset { name } => find(&name)?.unset(&client).await?,
    }
    // The node answering goes by it at once; the others at their next
    // heartbeat.
    crate::refresh_settings(app).await?;
    Ok(())
}

/// What's wrong with the layouts that `data-shards` and `parity-shards` ask
/// for: they take more active nodes than the cluster has, so uploads fail,
/// or coding waits, until it has. For whoever just changed them.
pub async fn placement_warnings<C: GenericClient>(client: &C) -> anyhow::Result<Vec<String>> {
    let active: i64 = client
        .query_one_cached("SELECT count(*) FROM nodes WHERE state = 'active'", &[])
        .await?
        .get(0);
    let Some(parity) = PARITY_SHARDS.get_set(client).await? else {
        return Ok(Vec::new());
    };
    let data = DATA_SHARDS.get(client).await?;
    let mut warnings = Vec::new();
    if active < 1 + parity {
        warnings.push(format!(
            "a blob takes {} nodes, but the cluster has {active} active: uploads fail until it has",
            1 + parity
        ));
    } else if data > 1 && parity > 0 && active < data + parity {
        warnings.push(format!(
            "coding {data}+{parity} takes {} nodes, but the cluster has {active} active: \
             blobs stay replicated until it has",
            data + parity
        ));
    } else if data > 1 && parity == 0 {
        warnings.push("with no parity shards, nothing is coded: it would survive no lost node".to_owned());
    }
    Ok(warnings)
}
