//! Temporary credentials (STS's): an access key ID (`ASIA…`), a secret, and
//! a session token, which says everything about the session, sealed by the
//! cluster, so that issuing one writes nothing, and any node checks one
//! (see `plans/roles.md`).
//!
//! A token is `base64(version ‖ key ID ‖ payload ‖ tag)`, where the payload
//! is the `Session` (JSON, readable by whoever holds the token) and the tag
//! `HMAC-SHA256(key, "tag" ‖ version ‖ key ID ‖ payload)`, cut to 16 bytes.
//! The credentials' secret isn't in the token: it's
//! `HMAC-SHA256(key, "secret" ‖ version ‖ key ID ‖ payload)`, its first 30
//! bytes in base64, so only a node with the key can derive it and check a
//! request's signature. The payload says whose session it is (a role's, a
//! user's, a federated user's), by ID, so a role deleted and made again
//! with its name doesn't revive its sessions.
//!
//! The keys are the cluster's, in Postgres (`session_keys`, as a database
//! leak exposes users' long-term secrets anyway): a node seals with the
//! newest, and opens with any. The maintenance pass makes a new one every
//! day, and drops those older than the longest session and a day.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::db::Cached;

/// The token format's version (1's held the secret, encrypted; no node
/// takes those anymore).
const VERSION: u8 = 2;
/// The token's head: its version, and its key's ID.
const HEAD: usize = 1 + 4;
/// The tag's length (of HMAC-SHA256's 32 bytes).
const TAG: usize = 16;
/// How often a node makes a new key: the newest older than this is
/// replaced.
const KEY_LIFETIME: Duration = Duration::from_secs(24 * 3600);
/// The longest session (GetSessionToken's and GetFederationToken's
/// maximum, 36 hours): a key is kept at least this past its replacement.
pub const MAX_SESSION: u64 = 129_600;
/// How long a node trusts its cache of the keys before reading them again.
const CACHE: Duration = Duration::from_secs(60);

/// Whose a session is.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum Who {
    /// A role's (AssumeRole): the role, and the session's name.
    #[serde(rename = "r")]
    Role { id: Uuid, session: String },
    /// A user's own (GetSessionToken).
    #[serde(rename = "u")]
    User { id: Uuid },
    /// A federated user's (GetFederationToken): the user it's of, and its
    /// name.
    #[serde(rename = "f")]
    Federated { id: Uuid, name: String },
    /// An account's root user's (`cairn account root-key`, on a node): the
    /// account, by its ID. Older nodes don't know it, so refuse its token.
    #[serde(rename = "root")]
    Root { account: String },
}

/// Everything about a session, which its token holds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Session {
    /// Its access key ID (`ASIA…`): a token is its key's only.
    #[serde(rename = "k")]
    pub key_id: String,
    /// Its secret: derived from the token (see above), not in it; empty
    /// until the session is sealed or opened.
    #[serde(skip)]
    pub secret: String,
    /// When it was issued and when it expires (Unix seconds).
    #[serde(rename = "i")]
    pub issued: u64,
    #[serde(rename = "e")]
    pub expires: u64,
    #[serde(rename = "w")]
    pub who: Who,
    /// Its inline session policy, normalized.
    #[serde(rename = "p", default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// Its session policies' ARNs (managed policies), read as they are when
    /// it's used (probed).
    #[serde(rename = "a", default, skip_serializing_if = "Vec::is_empty")]
    pub policy_arns: Vec<String>,
    /// Its tags, and which of them pass on to a role it assumes.
    #[serde(rename = "g", default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<(String, String)>,
    #[serde(rename = "x", default, skip_serializing_if = "Vec::is_empty")]
    pub transitive: Vec<String>,
    #[serde(rename = "o", default, skip_serializing_if = "Option::is_none")]
    pub source_identity: Option<String>,
    /// Whether a role's session assumed it (role chaining).
    #[serde(rename = "c", default, skip_serializing_if = "std::ops::Not::not")]
    pub chained: bool,
    /// The OIDC provider (its ARN) of the web identity that assumed it
    /// (AssumeRoleWithWebIdentity), passed on to roles it assumes.
    #[serde(rename = "f", default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// A directory bucket's session (S3 Express's CreateSession), if it is
    /// one: then it's good for that bucket's zonal operations only, and
    /// its token is taken as `x-amz-s3session-token` only (see
    /// `s3::directory`).
    #[serde(rename = "d", default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<Directory>,
}

/// What a directory bucket's session is for: the bucket, in a mode, as
/// CreateSession authorized it, and who made it, so that its requests need
/// neither their principal's policies nor the bucket's (see
/// `s3::directory`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Directory {
    #[serde(rename = "b")]
    pub bucket: String,
    /// `ReadOnly`, rather than `ReadWrite`.
    #[serde(rename = "r", default, skip_serializing_if = "std::ops::Not::not")]
    pub read_only: bool,
    /// Authorized before the bucket existed (CreateSession on a bucket
    /// about to be created, as SDKs make one): then each request is
    /// authorized as if it had no session.
    #[serde(rename = "u", default, skip_serializing_if = "std::ops::Not::not")]
    pub unauthorized: bool,
    /// Whose it is: its principal's account, path and name (its role's,
    /// for a role's session), as its ARN names it.
    #[serde(rename = "a")]
    pub account: String,
    #[serde(rename = "p")]
    pub path: String,
    #[serde(rename = "n")]
    pub name: String,
}

/// Why a token isn't one.
#[derive(Debug, PartialEq, Eq)]
pub enum Bad {
    /// Not a token of ours, or not one any key opens.
    Malformed,
    /// Past its expiry.
    Expired,
}

/// The keys tokens are sealed with, as this node last read them.
#[derive(Default)]
pub struct Keys {
    cached: Mutex<Option<Loaded>>,
}

struct Loaded {
    keys: HashMap<i32, Zeroizing<[u8; 32]>>,
    /// The newest, and when it was made (Unix seconds).
    newest: Option<(i32, i64)>,
    read: Instant,
}

impl Keys {
    /// The keys, read again if they're older than `CACHE`, or `fresh`.
    async fn current(&self, client: &deadpool_postgres::Object, fresh: bool) -> anyhow::Result<()> {
        let stale = match &*self.cached.lock().unwrap() {
            Some(cached) => fresh || cached.read.elapsed() > CACHE,
            None => true,
        };
        if !stale {
            return Ok(());
        }
        let rows = client
            .query_cached("SELECT id, key, extract(epoch FROM created_at)::bigint FROM session_keys ORDER BY id", &[])
            .await?;
        let mut keys = HashMap::new();
        let mut newest = None;
        for row in rows {
            let id: i32 = row.get(0);
            let bytes: Vec<u8> = row.get(1);
            let Ok(key) = <[u8; 32]>::try_from(bytes.as_slice()) else { continue };
            keys.insert(id, Zeroizing::new(key));
            newest = Some((id, row.get::<_, i64>(2)));
        }
        *self.cached.lock().unwrap() = Some(Loaded { keys, newest, read: Instant::now() });
        Ok(())
    }

    /// Makes a new key (if `when_older` and the newest is younger than
    /// `KEY_LIFETIME`, not), and drops those no session can use anymore.
    pub async fn rotate(&self, client: &deadpool_postgres::Object, always: bool) -> anyhow::Result<()> {
        let lifetime = KEY_LIFETIME.as_secs() as f64;
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::fill(key.as_mut()).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
        // One statement: a key, unless one was made meanwhile (another
        // node's maintenance pass).
        client
            .execute_cached(
                "INSERT INTO session_keys (key) SELECT $1
                 WHERE $2 OR NOT EXISTS (SELECT 1 FROM session_keys WHERE created_at > now() - make_interval(secs => $3))",
                &[&key.as_slice(), &always, &lifetime],
            )
            .await?;
        // Kept the longest session and a day past their replacement.
        let kept = (MAX_SESSION + KEY_LIFETIME.as_secs()) as f64;
        client
            .execute_cached(
                "DELETE FROM session_keys k WHERE k.created_at < now() - make_interval(secs => $1)
                 AND EXISTS (SELECT 1 FROM session_keys n WHERE n.id > k.id AND n.created_at < now() - make_interval(secs => $1 - $2))",
                &[&kept, &lifetime],
            )
            .await?;
        self.current(client, true).await
    }

    /// Drops every key, and makes a new one: every session issued so far
    /// stops working (the break-glass).
    pub async fn revoke_all(&self, client: &deadpool_postgres::Object) -> anyhow::Result<()> {
        client.execute_cached("DELETE FROM session_keys", &[]).await?;
        self.rotate(client, true).await
    }

    /// `session`'s token; sets its secret.
    pub async fn seal(&self, client: &deadpool_postgres::Object, session: &mut Session) -> anyhow::Result<String> {
        self.current(client, false).await?;
        let usable = |c: &Option<Loaded>| {
            c.as_ref().and_then(|c| c.newest).is_some_and(|(_, made)| now() as i64 - made < KEY_LIFETIME.as_secs() as i64 * 2)
        };
        if !usable(&self.cached.lock().unwrap()) {
            self.rotate(client, false).await?;
        }
        let guard = self.cached.lock().unwrap();
        let cached = guard.as_ref().ok_or_else(|| anyhow::anyhow!("no session keys"))?;
        let (id, _) = cached.newest.ok_or_else(|| anyhow::anyhow!("no session keys"))?;
        let key = &cached.keys[&id];
        let mut token = vec![VERSION];
        token.extend_from_slice(&id.to_be_bytes());
        token.extend_from_slice(&serde_json::to_vec(session)?);
        let tag = mac(key, b"tag", &token);
        session.secret = secret(key, &token);
        token.extend_from_slice(&tag[..TAG]);
        Ok(STANDARD.encode(token))
    }

    /// The session `token` is (its secret set), if it's one of ours (any
    /// key's), and not expired.
    pub async fn open(&self, client: &deadpool_postgres::Object, token: &str) -> anyhow::Result<Result<Session, Bad>> {
        let Ok(bytes) = STANDARD.decode(token.trim()) else { return Ok(Err(Bad::Malformed)) };
        if bytes.len() < HEAD + TAG || bytes[0] != VERSION {
            return Ok(Err(Bad::Malformed));
        }
        let (signed, tag) = bytes.split_at(bytes.len() - TAG);
        let id = i32::from_be_bytes(bytes[1..HEAD].try_into().unwrap());
        self.current(client, false).await?;
        let known = self.cached.lock().unwrap().as_ref().is_some_and(|c| c.keys.contains_key(&id));
        if !known {
            // Made by another node since this one last read them.
            self.current(client, true).await?;
        }
        let secret = {
            let guard = self.cached.lock().unwrap();
            let Some(key) = guard.as_ref().and_then(|c| c.keys.get(&id)) else { return Ok(Err(Bad::Malformed)) };
            if keyed(key, b"tag", signed).verify_truncated_left(tag).is_err() {
                return Ok(Err(Bad::Malformed));
            }
            secret(key, signed)
        };
        let Ok(mut session) = serde_json::from_slice::<Session>(&signed[HEAD..]) else { return Ok(Err(Bad::Malformed)) };
        if session.expires <= now() {
            return Ok(Err(Bad::Expired));
        }
        session.secret = secret;
        Ok(Ok(session))
    }
}

/// HMAC-SHA256 under `key` of `label ‖ signed`, before it's finished.
fn keyed(key: &[u8; 32], label: &[u8], signed: &[u8]) -> Hmac<Sha256> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key");
    mac.update(label);
    mac.update(signed);
    mac
}

/// HMAC-SHA256 under `key` of `label ‖ signed`.
fn mac(key: &[u8; 32], label: &[u8], signed: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(keyed(key, label, signed).finalize().into_bytes().into())
}

/// The secret of the session whose token (without its tag) `signed` is: 40
/// characters of base64's alphabet, as AWS's.
fn secret(key: &[u8; 32], signed: &[u8]) -> String {
    STANDARD.encode(&mac(key, b"secret", signed)[..30])
}

/// `cairn sessions …`: temporary credentials (STS's), cluster-wide.
#[derive(clap::Args, Debug, Serialize, Deserialize)]
pub struct SessionsArgs {
    #[command(flatten)]
    #[serde(skip)]
    pub remote: crate::admin::Remote,
    #[command(subcommand)]
    command: SessionsCommand,
}

#[derive(clap::Subcommand, Debug, Serialize, Deserialize)]
enum SessionsCommand {
    /// End every session there is: the keys their tokens are sealed with go
    /// (a new one is made), so every temporary credential issued so far
    /// stops working, on every node within a minute. The break-glass; to
    /// end a role's sessions, deny them by `aws:TokenIssueTime`, as in AWS.
    RevokeAll,
}

/// Carries out a `cairn sessions` command on node `app`.
pub async fn run(app: &std::sync::Arc<crate::App>, args: SessionsArgs, out: &mut crate::admin::Output) -> anyhow::Result<()> {
    match args.command {
        SessionsCommand::RevokeAll => {
            app.sessions.revoke_all(&app.pool.get().await?).await?;
            crate::admin::outln!(out, "every session's token is void now (nodes that cached the old keys drop them within a minute)");
        }
    }
    Ok(())
}

/// Now, in Unix seconds.
pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// A new temporary access key ID: `ASIA`, then 16 random characters of
/// AWS's alphabet (as long as AWS's).
pub fn new_key_id() -> anyhow::Result<String> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
    Ok(format!("ASIA{}", bytes.iter().map(|b| ALPHABET[(b & 31) as usize] as char).collect::<String>()))
}

/// Whether `key_id` is a temporary one (STS's).
pub fn is_temporary(key_id: &str) -> bool {
    key_id.starts_with("ASIA")
}

/// An ISO 8601 time, as STS writes a session's expiry.
pub fn iso(seconds: u64) -> String {
    let days = (seconds / 86400) as i64;
    let rest = seconds % 86400;
    let (y, m, d) = civil(days);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rest / 3600, rest / 60 % 60, rest % 60)
}

/// The date `days` after 1970-01-01 (Howard Hinnant's `civil_from_days`).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_ids_look_like_awss() {
        let id = new_key_id().unwrap();
        assert_eq!(id.len(), 20);
        assert!(is_temporary(&id));
        assert!(id[4..].bytes().all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)));
    }

    #[tokio::test]
    async fn tokens_hold_no_secret_and_take_no_tampering() {
        let Some(pool) = crate::e2e::fresh_database_through(usize::MAX).await else { return };
        let client = pool.get().await.unwrap();
        let keys = Keys::default();
        let mut session = Session {
            key_id: new_key_id().unwrap(),
            secret: String::new(),
            issued: now(),
            expires: now() + 900,
            who: Who::User { id: Uuid::new_v4() },
            policy: None,
            policy_arns: Vec::new(),
            tags: Vec::new(),
            transitive: Vec::new(),
            source_identity: None,
            chained: false,
            provider: None,
            directory: None,
        };
        let token = keys.seal(&client, &mut session).await.unwrap();
        // The secret is AWS's shape, derived, not in the token.
        assert_eq!(session.secret.len(), 40);
        assert!(!String::from_utf8_lossy(&STANDARD.decode(&token).unwrap()).contains(&session.secret));
        assert_eq!(keys.open(&client, &token).await.unwrap(), Ok(session.clone()));
        // Another session of the same key ID gets another secret.
        let mut other = Session { expires: session.expires + 1, ..session.clone() };
        keys.seal(&client, &mut other).await.unwrap();
        assert_ne!(other.secret, session.secret);
        // Any byte changed (version, key ID, payload, tag) is no token.
        let bytes = STANDARD.decode(&token).unwrap();
        for i in [0, 4, HEAD + 5, bytes.len() - 1] {
            let mut forged = bytes.clone();
            forged[i] ^= 1;
            assert_eq!(keys.open(&client, &STANDARD.encode(forged)).await.unwrap(), Err(Bad::Malformed), "byte {i}");
        }
        // Expired, and its keys revoked.
        let mut old = Session { expires: now() - 1, ..session.clone() };
        let expired = keys.seal(&client, &mut old).await.unwrap();
        assert_eq!(keys.open(&client, &expired).await.unwrap(), Err(Bad::Expired));
        keys.revoke_all(&client).await.unwrap();
        assert_eq!(keys.open(&client, &token).await.unwrap(), Err(Bad::Malformed));
    }

    #[test]
    fn times_are_iso() {
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso(1_794_668_400), "2026-11-14T15:00:00Z");
        assert_eq!(iso(951_782_400), "2000-02-29T00:00:00Z");
    }
}
