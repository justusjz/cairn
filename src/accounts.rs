//! The account, as AWS's: Cairn has one (see `plans/single-account.md`),
//! which owns every user, bucket and policy; teams are told apart by IAM
//! (paths, permissions boundaries). `cairn account` shows it, and makes its
//! root's enrollment link for the console: its first, or one to recover
//! it, if the root's passkeys are lost.

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
    /// Show the account: its ID, users and buckets, and whether its root
    /// has signed in to the console.
    Show,
    /// Print a one-time link (valid 24 hours) for the account's root to set
    /// up a passkey for the console. A new link replaces the last. Made
    /// from the node's console URL.
    Enroll,
}

/// `cairn account …`, on a node (see `admin`).
pub async fn run(app: &Arc<App>, args: AccountArgs, out: &mut Output) -> anyhow::Result<()> {
    let client = app.pool.get().await?;
    match args.command {
        AccountCommand::Show => {
            let row = client
                .query_one_cached(
                    "SELECT a.id,
                            (SELECT count(*) FROM roles r WHERE r.account_id = a.id),
                            (SELECT count(*) FROM buckets b WHERE b.account_id = a.id),
                            EXISTS (SELECT 1 FROM login_identities i WHERE i.account_id = a.id AND i.role_id IS NULL)
                     FROM accounts a WHERE NOT a.operator",
                    &[],
                )
                .await?;
            let (id, users, buckets, root): (String, i64, i64, bool) = (row.get(0), row.get(1), row.get(2), row.get(3));
            let root = if root { "root enrolled" } else { "root not enrolled" };
            outln!(out, "account {id}\n  {users} users, {buckets} buckets, {root}");
        }
        AccountCommand::Enroll => {
            let token = crate::console::store::create_root_enrollment(&client).await?;
            crate::roles::enrollment_link(app, &token, out);
        }
    }
    Ok(())
}
