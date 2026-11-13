//! Accounts, as AWS's (see `plans/policies.md`, "Accounts, root users and
//! logins"): tenants, each owning its users and buckets, and the operator
//! account, whose users are the superadmins. `cairn account` lists and makes
//! them, and makes a root's enrollment link for the console: a new account's
//! first, or one to recover it, if its root's passkeys are lost.

use std::sync::Arc;

use clap::{Args, Subcommand};
use deadpool_postgres::Object;
use serde::{Deserialize, Serialize};

use crate::{
    App,
    admin::{Output, outln},
    db::Cached,
    roles::Invalid,
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
    /// List the accounts: their IDs, names, users and buckets.
    List,
    /// Make a tenant account. Its root then signs in to the console through
    /// `cairn account enroll`.
    Create {
        /// Its name: lowercase letters, digits and hyphens.
        name: String,
    },
    /// Print a one-time link (valid 24 hours) for an account's root to set up
    /// a passkey for the console. A new link replaces the last. Made from
    /// the node's console URL.
    Enroll {
        /// The account's name (`operator` for the operator account).
        name: String,
    },
}

/// An account's name: what `accounts_name_check` takes.
fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    (1..=63).contains(&name.len())
        && chars.next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Makes a tenant account named `name`: its ID.
pub async fn create(client: &Object, name: &str) -> anyhow::Result<String> {
    if !valid_name(name) {
        return Err(Invalid("an account's name is 1 to 63 lowercase letters, digits and hyphens".into()).into());
    }
    // A random 12-digit ID, as AWS's; drawn again on the rare collision.
    for _ in 0..10 {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("generating an account ID: {e}"))?;
        let id = format!("{:012}", u64::from_le_bytes(bytes) % 1_000_000_000_000);
        let inserted = client
            .execute_cached("INSERT INTO accounts (id, name) VALUES ($1, $2) ON CONFLICT DO NOTHING", &[&id, &name])
            .await?;
        if inserted == 1 {
            return Ok(id);
        }
        if client.query_opt_cached("SELECT 1 FROM accounts WHERE name = $1", &[&name]).await?.is_some() {
            return Err(Invalid(format!("an account named {name:?} exists already")).into());
        }
    }
    anyhow::bail!("couldn't draw an unused account ID")
}

/// `cairn account …`, on a node (see `admin`).
pub async fn run(app: &Arc<App>, args: AccountArgs, out: &mut Output) -> anyhow::Result<()> {
    let client = app.pool.get().await?;
    match args.command {
        AccountCommand::List => {
            let rows = client
                .query_cached(
                    "SELECT a.id, a.name, a.operator,
                            (SELECT count(*) FROM roles r WHERE r.account_id = a.id),
                            (SELECT count(*) FROM buckets b WHERE b.account_id = a.id),
                            EXISTS (SELECT 1 FROM login_identities i WHERE i.account_id = a.id AND i.role_id IS NULL)
                     FROM accounts a ORDER BY a.operator, a.name",
                    &[],
                )
                .await?;
            for row in rows {
                let (id, name, operator): (String, String, bool) = (row.get(0), row.get(1), row.get(2));
                let (users, buckets, root): (i64, i64, bool) = (row.get(3), row.get(4), row.get(5));
                let kind = if operator { " (operator)" } else { "" };
                let root = if root { "root enrolled" } else { "root not enrolled" };
                outln!(out, "{name}{kind}\n  id {id}\n  {users} users, {buckets} buckets, {root}");
            }
        }
        AccountCommand::Create { name } => {
            let id = create(&client, &name).await?;
            outln!(out, "account {name}: {id}");
        }
        AccountCommand::Enroll { name } => {
            let token = crate::console::store::create_root_enrollment(&client, &name).await?;
            crate::roles::enrollment_link(app, &token, out);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn names_are_as_the_catalog_takes_them() {
        for good in ["acme", "a", "team-2", "0x"] {
            assert!(super::valid_name(good), "{good}");
        }
        for bad in ["", "-acme", "Acme", "a_b", "a.b", &"a".repeat(64)] {
            assert!(!super::valid_name(bad), "{bad}");
        }
    }
}
