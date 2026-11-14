//! The account, as AWS's: Cairn has one (see `plans/single-account.md`),
//! which owns every user, bucket and policy; teams are told apart by IAM
//! (paths, permissions boundaries). `cairn account show` shows it.

use std::sync::Arc;

use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

use crate::{
    App,
    admin::{Output, outln},
    db::Cached,
};

#[derive(Args, Debug, Serialize, Deserialize)]
pub struct AccountArgs {
    #[command(flatten)]
    #[serde(skip)]
    pub remote: crate::admin::Remote,
    #[command(subcommand)]
    command: AccountCommand,
}

#[derive(Subcommand, Debug, Serialize, Deserialize)]
enum AccountCommand {
    /// Show the account: its ID, users and buckets.
    Show,
}

/// `cairn account …`, on a node (see `admin`).
pub async fn run(app: &Arc<App>, args: AccountArgs, out: &mut Output) -> anyhow::Result<()> {
    let client = app.pool.get().await?;
    match args.command {
        AccountCommand::Show => {
            let row = client
                .query_one_cached(
                    "SELECT a.id,
                            (SELECT count(*) FROM users r WHERE r.account_id = a.id),
                            (SELECT count(*) FROM buckets b WHERE b.account_id = a.id)
                     FROM accounts a WHERE NOT a.operator",
                    &[],
                )
                .await?;
            let (id, users, buckets): (String, i64, i64) = (row.get(0), row.get(1), row.get(2));
            outln!(out, "account {id}\n  {users} users, {buckets} buckets");
        }
    }
    Ok(())
}
