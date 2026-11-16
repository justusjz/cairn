//! The account, as AWS's: Cairn has one (see `plans/single-account.md`),
//! which owns every user, bucket and policy; teams are told apart by IAM
//! (paths, permissions boundaries). `cairn account show` shows it, and
//! `cairn account root-link` makes a link to sign in to the console as its
//! root user: the only way to be the root, and the way out of policies that
//! lock everyone else out.

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
    /// Print a one-time link (valid 15 minutes) to sign in to the console
    /// as the account's root user, whom no identity policy restricts (only
    /// buckets' policies' denies, but not of the policies themselves). The
    /// session lasts an hour at most. A new link replaces the last. Made
    /// from the node's console URL.
    RootLink,
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
        AccountCommand::RootLink => {
            let account = crate::users::account(&client).await?;
            let token = crate::console::store::create_root_link(&client, &account).await?;
            eprintln!("cairn account root-link: made a link to sign in as the root user of account {account}");
            out.warn("anyone with this link can sign in as the root user until it's used, or for 15 minutes");
            match app.console.origin() {
                Some(origin) => outln!(out, "{origin}/root#{token}"),
                None => {
                    out.warn("this node serves no console (--listen-console, --console-url): open this path there");
                    outln!(out, "/root#{token}");
                }
            }
        }
    }
    Ok(())
}
