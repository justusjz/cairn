//! The account, as AWS's: Cairn has one (see `plans/single-account.md`),
//! which owns every user, bucket and policy; teams are told apart by IAM
//! (paths, permissions boundaries). `cairn account root-link` and
//! `root-key` make its root user, for a while: a link to sign in to the
//! console, or temporary credentials. They're the only ways to be the root,
//! and the way out of policies that lock everyone else out.

use std::sync::Arc;

use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

use crate::{
    App,
    admin::{Output, outln},
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
    /// Print a one-time link (valid 15 minutes) to sign in to the console
    /// as the account's root user, whom no identity policy restricts (only
    /// buckets' policies' denies, but not of the policies themselves). The
    /// session lasts an hour at most. A new link replaces the last. Made
    /// from the node's console URL.
    RootLink,
    /// Print temporary credentials (valid 15 minutes) of the account's root
    /// user, for the S3, IAM and STS APIs, as shell `export`s: whom no
    /// identity policy restricts (only buckets' policies' denies, but not
    /// of the policies themselves). `cairn sessions revoke-all` ends them.
    RootKey,
}

/// How long the root user's temporary credentials work, as AWS's
/// `AssumeRoot`'s at most.
const ROOT_KEY_SECONDS: u64 = 15 * 60;

/// `cairn account …`, on a node (see `admin`).
pub async fn run(app: &Arc<App>, args: AccountArgs, out: &mut Output) -> anyhow::Result<()> {
    let client = app.pool.get().await?;
    match args.command {
        AccountCommand::RootKey => {
            let account = crate::users::account(&client).await?;
            let now = crate::sessions::now();
            let mut session = crate::sessions::Session {
                key_id: crate::sessions::new_key_id()?,
                secret: String::new(),
                issued: now,
                expires: now + ROOT_KEY_SECONDS,
                who: crate::sessions::Who::Root { account: account.clone() },
                policy: None,
                policy_arns: Vec::new(),
                tags: Vec::new(),
                transitive: Vec::new(),
                source_identity: None,
                chained: false,
                provider: None,
                directory: None,
            };
            let token = app.sessions.seal(&client, &mut session).await?;
            eprintln!(
                "cairn account root-key: made {} for the root user of account {account}",
                session.key_id
            );
            out.warn("anyone with these credentials is the root user until they expire; `cairn sessions revoke-all` ends them sooner");
            let until = crate::sessions::iso(session.expires);
            outln!(out, "# the root user of account {account} (arn:aws:iam::{account}:root), until {until}");
            outln!(out, "export AWS_ACCESS_KEY_ID={}", session.key_id);
            outln!(out, "export AWS_SECRET_ACCESS_KEY={}", session.secret);
            outln!(out, "export AWS_SESSION_TOKEN={token}");
        }
        AccountCommand::RootLink => {
            let account = crate::users::account(&client).await?;
            let token = crate::console::store::create_root_link(&client, &account).await?;
            eprintln!("cairn account root-link: made a link to sign in as the root user of account {account}");
            out.warn("anyone with this link can sign in as the root user until it's used, or for 15 minutes");
            outln!(out, "# the root user of account {account} (arn:aws:iam::{account}:root)");
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
