//! The cluster's settings: values every node goes by, kept in the database
//! (`settings`), so that they're the same everywhere, and a change reaches
//! every node at once. Set with `cairn config set`, or on the dashboard. A
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
}

/// How many object versions lifecycle sweeps may read an hour, across the
/// whole cluster (see `lifecycle`).
pub const LIFECYCLE_RATE: Setting = Setting {
    name: "lifecycle-rate",
    default: 1_000_000,
    min: 0,
    max: i64::MAX,
    help: "object versions lifecycle sweeps read per hour, across the cluster (0 pauses them)",
};

/// How many data shards the packer codes cold data into (see `shards` and
/// `packer`); 1 keeps every blob replicated. Its parity shards are the
/// replicas besides the one (`--replication-factor` − 1), so coded data
/// survives as many lost nodes as replicated data. Only the operator knows
/// how many nodes the cluster will keep, so Cairn never picks this itself:
/// coding needs data + parity shards' worth of live nodes, and with fewer,
/// the packer leaves data as it is. A change applies to data coded from then
/// on; blobs keep the layout they were written with.
pub const DATA_SHARDS: Setting = Setting {
    name: "data-shards",
    default: 1,
    min: 1,
    max: crate::shards::MAX_DATA_SHARDS as i64,
    help: "data shards that cold data is erasure-coded into, plus --replication-factor - 1 \
           parity shards (1 keeps replicas only)",
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
};

/// Every setting.
pub const ALL: &[&Setting] = &[&LIFECYCLE_RATE, &DATA_SHARDS, &REPAIR_AFTER];

/// The setting named `name`, if there's one.
pub fn named(name: &str) -> Option<&'static Setting> {
    ALL.iter().copied().find(|s| s.name == name)
}

impl Setting {
    /// Its value: what it was set to, or its default.
    pub async fn get<C: GenericClient>(&self, client: &C) -> anyhow::Result<i64> {
        let row = client
            .query_opt_cached("SELECT value FROM settings WHERE name = $1", &[&self.name])
            .await?;
        match row {
            None => Ok(self.default),
            Some(row) => {
                let value: &str = row.get(0);
                value.parse().map_err(|_| anyhow::anyhow!("setting {} is {value:?}, not a number", self.name))
            }
        }
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

#[derive(Args, Debug)]
pub struct ConfigArgs {
    /// PostgreSQL connection string (the same one the nodes use).
    #[arg(long, env = "CAIRN_DATABASE", hide_env_values = true)]
    database: String,
    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(Subcommand, Debug)]
enum ConfigCommand {
    /// Show every setting's value, or one's.
    Get { name: Option<String> },
    /// Set a setting, for the whole cluster.
    Set { name: String, value: i64 },
}

pub async fn config_main(args: ConfigArgs) -> anyhow::Result<()> {
    let pool = crate::db::connect(&args.database).await?;
    let client = pool.get().await?;
    let find = |name: &str| {
        named(name).ok_or_else(|| {
            let known: Vec<&str> = ALL.iter().map(|s| s.name).collect();
            anyhow::anyhow!("no setting {name:?}; there are: {}", known.join(", "))
        })
    };
    match args.command {
        ConfigCommand::Get { name: Some(name) } => println!("{}", find(&name)?.get(&client).await?),
        ConfigCommand::Get { name: None } => {
            for setting in ALL {
                let value = setting.get(&client).await?;
                println!("{} = {value}  # {} (default {})", setting.name, setting.help, setting.default);
            }
        }
        ConfigCommand::Set { name, value } => find(&name)?.set(&client, value).await?,
    }
    Ok(())
}
