//! `cairn node`: the cluster's nodes, and removing them (see `mover`).

use clap::{Args, Subcommand};

use crate::db::Cached;

#[derive(Args, Debug)]
pub struct NodeArgs {
    /// PostgreSQL connection string (the same one the nodes use).
    #[arg(long, env = "CAIRN_DATABASE", hide_env_values = true)]
    database: String,
    #[command(subcommand)]
    command: NodeCommand,
}

#[derive(Subcommand, Debug)]
enum NodeCommand {
    /// List the nodes: their state, whether they're live, and how many shards
    /// they hold.
    List,
    /// Remove a node: it gets no new shards, and its shards move to other
    /// nodes, copied from it while it's live, else rebuilt from the other
    /// shards. Once it holds none, it's removed, and can be shut down.
    Remove {
        /// The node's number (`cairn node list`).
        id: i32,
    },
    /// Keep a node that's being removed (or was): it gets shards again. Those
    /// that moved off it stay where they are.
    Keep {
        /// The node's number (`cairn node list`).
        id: i32,
    },
}

pub async fn node_main(args: NodeArgs) -> anyhow::Result<()> {
    let pool = crate::db::connect(&args.database).await?;
    let client = pool.get().await?;
    match args.command {
        NodeCommand::List => {
            let rows = client
                .query_cached(
                    "SELECT n.id, n.peer_url, n.state, n.last_seen > NOW() - INTERVAL '10 seconds',
                            (SELECT count(*) FROM blob_locations bl WHERE bl.node = n.id)
                     FROM nodes n ORDER BY n.id",
                    &[],
                )
                .await?;
            println!("{:>4}  {:<9} {:<5} {:>10}  peer URL", "id", "state", "live", "shards");
            for r in rows {
                let live = if r.get::<_, bool>(3) { "yes" } else { "no" };
                let (id, url, state, shards): (i32, String, String, i64) = (r.get(0), r.get(1), r.get(2), r.get(4));
                println!("{id:>4}  {state:<9} {live:<5} {shards:>10}  {url}");
            }
        }
        NodeCommand::Remove { id } => {
            let row = client
                .query_opt_cached(
                    "UPDATE nodes SET state = 'removing', state_since = NOW() WHERE id = $1 AND state = 'active'
                     RETURNING (SELECT count(*) FROM blob_locations bl WHERE bl.node = $1)",
                    &[&id],
                )
                .await?;
            match row {
                Some(row) => {
                    let shards: i64 = row.get(0);
                    println!(
                        "node {id} is being removed: its {shards} shards move to other nodes \
                         (`cairn node list` shows how many are left)"
                    );
                }
                None => anyhow::bail!("node {id} {}", not_active(&client, id).await?),
            }
        }
        NodeCommand::Keep { id } => {
            let updated = client
                .execute_cached("UPDATE nodes SET state = 'active', state_since = NOW() WHERE id = $1 AND state <> 'active'", &[&id])
                .await?;
            if updated == 0 {
                anyhow::bail!("node {id} {}", not_active(&client, id).await?);
            }
            println!("node {id} is kept: it gets new shards again");
        }
    }
    Ok(())
}

/// Why a node couldn't change its state.
async fn not_active(client: &deadpool_postgres::Object, id: i32) -> anyhow::Result<String> {
    let state = client.query_opt_cached("SELECT state FROM nodes WHERE id = $1", &[&id]).await?;
    Ok(match state {
        None => "doesn't exist".to_owned(),
        Some(row) => format!("is {} already", row.get::<_, String>(0)),
    })
}
