//! The console's rows (migrations 30 and 34): logins, the identities they
//! act as, their passkeys, enrollment links, ceremonies' challenges and
//! sessions. Tokens (links' and sessions') are random, handed out once, and
//! kept as their SHA-256 only, so the database can't sign anyone in.
//!
//! A login is a person: its passkeys sign it in, and it's linked to at most
//! one identity per account, a user of the account, or the account's root;
//! an identity belongs to at most one login. A session acts as one of its
//! login's identities at a time, which it can switch.

use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use deadpool_postgres::Object;
use ring::digest;
use uuid::Uuid;

use crate::db::Cached;
use crate::roles::Invalid;

/// How long an enrollment link works.
pub const ENROLLMENT_TTL: Duration = Duration::from_secs(24 * 3600);
/// How long a ceremony may take, from its options to its response.
pub const CHALLENGE_TTL: Duration = Duration::from_secs(5 * 60);
/// How long a session lasts at most, and unused.
pub const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
pub const SESSION_IDLE: Duration = Duration::from_secs(3600);
/// How recently a session's passkey must have been used to act as the
/// operator account (a fresh assertion, else).
pub const OPERATOR_FRESHNESS: Duration = Duration::from_secs(5 * 60);
/// The most passkeys a login may have, as IAM's MFA devices (I10).
pub const MAX_PASSKEYS: i32 = 8;

/// A random token, URL-safe, and the hash it's kept as.
fn token() -> anyhow::Result<(String, Vec<u8>)> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("generating a token: {e}"))?;
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash(&token);
    Ok((token, hash))
}

/// What a token is kept as.
pub fn hash(token: &str) -> Vec<u8> {
    digest::digest(&digest::SHA256, token.as_bytes()).as_ref().to_vec()
}

fn secs(d: Duration) -> f64 {
    d.as_secs_f64()
}

/// A user, as the console knows it.
#[derive(Clone, Debug, PartialEq)]
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub admin: bool,
}

/// An identity: who a session acts as in an account.
#[derive(Clone, Debug, PartialEq)]
pub struct Identity {
    pub account_id: String,
    pub account: String,
    /// Whether it's the operator account (see `plans/policies.md`).
    pub operator: bool,
    /// The user; `None`: the account's root.
    pub user: Option<User>,
}

impl Identity {
    /// Its ARN.
    pub fn arn(&self) -> String {
        match &self.user {
            Some(user) => format!("arn:aws:iam::{}:user/{}", self.account_id, user.name),
            None => format!("arn:aws:iam::{}:root", self.account_id),
        }
    }

    /// How it's named to people: `user @ account`, or `root @ account`.
    pub fn label(&self) -> String {
        let who = self.user.as_ref().map_or("root", |u| u.name.as_str());
        format!("{who} @ {}", self.account)
    }
}

/// The columns an identity is read from, as `identity_of` takes them, from
/// `a` (accounts) and `r` (roles, left joined).
const IDENTITY: &str = "a.id, a.name, a.operator, r.id, r.name, r.admin";

fn identity_of(row: &tokio_postgres::Row, at: usize) -> Identity {
    let user = row.get::<_, Option<Uuid>>(at + 3).map(|id| User {
        id,
        name: row.get(at + 4),
        admin: row.get(at + 5),
    });
    Identity { account_id: row.get(at), account: row.get(at + 1), operator: row.get(at + 2), user }
}

/// Makes an enrollment link's token for user `user`, which replaces any it
/// had.
pub async fn create_enrollment(client: &Object, user: &str) -> anyhow::Result<String> {
    let (token, hash) = token()?;
    let made = client
        .execute_cached(
            "WITH r AS (SELECT id, account_id FROM roles WHERE name = $1),
                  d AS (DELETE FROM console_enrollments e USING r WHERE e.role_id = r.id)
             INSERT INTO console_enrollments (token_hash, role_id, account_id, expires_at)
             SELECT $2, r.id, r.account_id, now() + make_interval(secs => $3) FROM r",
            &[&user, &hash, &secs(ENROLLMENT_TTL)],
        )
        .await?;
    if made == 0 {
        return Err(Invalid(format!("no user named {user:?}")).into());
    }
    Ok(token)
}

/// Makes an enrollment link's token for the root of the account named
/// `account`, which replaces any it had: a new account's first, or its
/// recovery, if its passkeys are lost.
pub async fn create_root_enrollment(client: &Object, account: &str) -> anyhow::Result<String> {
    let (token, hash) = token()?;
    let made = client
        .execute_cached(
            "WITH a AS (SELECT id FROM accounts WHERE name = $1),
                  d AS (DELETE FROM console_enrollments e USING a WHERE e.account_id = a.id AND e.role_id IS NULL)
             INSERT INTO console_enrollments (token_hash, role_id, account_id, expires_at)
             SELECT $2, NULL, a.id, now() + make_interval(secs => $3) FROM a",
            &[&account, &hash, &secs(ENROLLMENT_TTL)],
        )
        .await?;
    if made == 0 {
        return Err(Invalid(format!("no account named {account:?}")).into());
    }
    Ok(token)
}

/// The identity enrollment link `token` is for, while it works.
pub async fn enrollment(client: &Object, token: &str) -> anyhow::Result<Option<Identity>> {
    let row = client
        .query_opt_cached(
            &format!(
                "SELECT {IDENTITY} FROM console_enrollments e
                 JOIN accounts a ON a.id = e.account_id LEFT JOIN roles r ON r.id = e.role_id
                 WHERE e.token_hash = $1 AND e.expires_at > now() AND (e.role_id IS NULL OR r.id IS NOT NULL)"
            ),
            &[&hash(token)],
        )
        .await?;
    Ok(row.map(|r| identity_of(&r, 0)))
}

/// What a challenge is for.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Purpose {
    Enroll,
    Add,
    Login,
}

impl Purpose {
    fn as_str(self) -> &'static str {
        match self {
            Purpose::Enroll => "enroll",
            Purpose::Add => "add",
            Purpose::Login => "login",
        }
    }
}

/// A new challenge for a ceremony (of `login`, adding a passkey): its ID
/// and bytes.
pub async fn create_challenge(client: &Object, purpose: Purpose, login: Option<Uuid>) -> anyhow::Result<(Uuid, Vec<u8>)> {
    let mut challenge = vec![0u8; 32];
    getrandom::fill(&mut challenge).map_err(|e| anyhow::anyhow!("generating a challenge: {e}"))?;
    let id = Uuid::new_v4();
    client
        .execute_cached(
            "INSERT INTO console_challenges (id, challenge, purpose, login_id, expires_at)
             VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))",
            &[&id, &challenge, &purpose.as_str(), &login, &secs(CHALLENGE_TTL)],
        )
        .await?;
    Ok((id, challenge))
}

/// Uses up challenge `id`, if it's for `purpose` and still works: its bytes,
/// and whose it is.
pub async fn take_challenge(client: &Object, id: Uuid, purpose: Purpose) -> anyhow::Result<Option<(Vec<u8>, Option<Uuid>)>> {
    let row = client
        .query_opt_cached(
            "DELETE FROM console_challenges WHERE id = $1 AND purpose = $2 AND expires_at > now()
             RETURNING challenge, login_id",
            &[&id, &purpose.as_str()],
        )
        .await?;
    Ok(row.map(|r| (r.get(0), r.get(1))))
}

/// A passkey to add.
pub struct NewPasskey<'a> {
    pub credential_id: &'a [u8],
    pub public_key: &'a [u8],
    pub sign_count: u32,
    pub name: &'a str,
    pub backup_eligible: bool,
    pub backed_up: bool,
}

fn no_enrollment() -> anyhow::Error {
    Invalid("this enrollment link has been used, or has expired".into()).into()
}

/// A new login `login`, named `name`, with passkey `key`, linked to the
/// identity of enrollment link `token`, which it uses up (T34): the
/// identity's account.
pub async fn new_login(client: &Object, login: Uuid, name: &str, token: &str, key: &NewPasskey<'_>) -> anyhow::Result<String> {
    let row = client
        .query_one_cached(
            "SELECT * FROM pg_temp.cairn_new_login($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            &[
                &login,
                &name,
                &hash(token),
                &key.credential_id,
                &key.public_key,
                &i64::from(key.sign_count),
                &key.name,
                &key.backup_eligible,
                &key.backed_up,
            ],
        )
        .await?;
    match row.get::<_, &str>(0) {
        "created" => Ok(row.get(2)),
        "no_enrollment" => Err(no_enrollment()),
        "account_taken" => unreachable!("a new login has no identities"),
        "taken" => Err(Invalid("this passkey is registered already: sign in with it, then open the link again".into()).into()),
        status => unreachable!("cairn_new_login: unknown status {status}"),
    }
}

/// Links the identity of enrollment link `token` to `login` (T33): the
/// identity's account.
pub async fn enroll(client: &Object, login: Uuid, token: &str) -> anyhow::Result<String> {
    let row = client.query_one_cached("SELECT * FROM pg_temp.cairn_enroll($1, $2)", &[&login, &hash(token)]).await?;
    match row.get::<_, &str>(0) {
        "linked" => Ok(row.get(1)),
        "no_enrollment" => Err(no_enrollment()),
        "account_taken" => Err(Invalid(
            "you're in this account as someone else already: an account has one identity per login".into(),
        )
        .into()),
        "no_such_login" => Err(Invalid("sign in again".into()).into()),
        status => unreachable!("cairn_enroll: unknown status {status}"),
    }
}

/// Gives `login` a passkey (T30), signed in.
pub async fn add_passkey(client: &Object, login: Uuid, key: &NewPasskey<'_>) -> anyhow::Result<()> {
    let status = client
        .query_one_cached(
            "SELECT pg_temp.cairn_add_passkey($1, $2, $3, $4, $5, $6, $7, $8)",
            &[
                &login,
                &key.credential_id,
                &key.public_key,
                &i64::from(key.sign_count),
                &key.name,
                &key.backup_eligible,
                &key.backed_up,
                &MAX_PASSKEYS,
            ],
        )
        .await?;
    match status.get::<_, &str>(0) {
        "added" => Ok(()),
        "no_such_login" => Err(Invalid("sign in again".into()).into()),
        "too_many" => Err(Invalid(format!("a login has at most {MAX_PASSKEYS} passkeys; remove one first")).into()),
        "taken" => Err(Invalid("this passkey is registered already".into()).into()),
        status => unreachable!("cairn_add_passkey: unknown status {status}"),
    }
}

/// A passkey, to check an assertion by.
pub struct Passkey {
    pub login: Uuid,
    pub public_key: Vec<u8>,
    pub sign_count: u32,
}

pub async fn passkey(client: &Object, credential_id: &[u8]) -> anyhow::Result<Option<Passkey>> {
    let row = client
        .query_opt_cached(
            "SELECT login_id, public_key, sign_count FROM passkeys WHERE credential_id = $1",
            &[&credential_id],
        )
        .await?;
    Ok(row.map(|r| Passkey { login: r.get(0), public_key: r.get(1), sign_count: r.get::<_, i64>(2) as u32 }))
}

/// Records a passkey's use, if its signature counter went forward (or it
/// doesn't count: both zero), as WebAuthn says (§7.2, step 21). Otherwise
/// the authenticator may have been cloned, and the use is refused: whether
/// it was recorded.
pub async fn record_use(client: &Object, credential_id: &[u8], sign_count: u32, backed_up: bool) -> anyhow::Result<bool> {
    let updated = client
        .execute_cached(
            "UPDATE passkeys SET sign_count = $2, backed_up = $3, last_used_at = now()
             WHERE credential_id = $1 AND (($2::bigint = 0 AND sign_count = 0) OR $2::bigint > sign_count)",
            &[&credential_id, &i64::from(sign_count), &backed_up],
        )
        .await?;
    Ok(updated == 1)
}

/// A login's identities, by account name.
pub async fn identities(client: &Object, login: Uuid) -> anyhow::Result<Vec<Identity>> {
    let rows = client
        .query_cached(
            &format!(
                "SELECT {IDENTITY} FROM login_identities i
                 JOIN accounts a ON a.id = i.account_id LEFT JOIN roles r ON r.id = i.role_id
                 WHERE i.login_id = $1 ORDER BY a.operator, a.name"
            ),
            &[&login],
        )
        .await?;
    Ok(rows.iter().map(|r| identity_of(r, 0)).collect())
}

/// How a session was signed in.
#[derive(Clone, Copy, Debug)]
pub enum Way<'a> {
    /// With this passkey (its credential ID).
    Passkey(&'a [u8]),
    /// At this OIDC provider (its name).
    Oidc(&'a str),
}

/// A session's token, for `login`, signed in `way`, acting as its identity
/// in `account` (by ID).
pub async fn create_session(client: &Object, login: Uuid, account: &str, way: Way<'_>) -> anyhow::Result<String> {
    let (token, hash) = token()?;
    let (credential, provider) = match way {
        Way::Passkey(credential) => (Some(credential), None),
        Way::Oidc(provider) => (None, Some(provider)),
    };
    client
        .execute_cached(
            "INSERT INTO console_sessions (token_hash, login_id, account_id, credential_id, oidc_provider, expires_at)
             VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))",
            &[&hash, &login, &account, &credential, &provider, &secs(SESSION_TTL)],
        )
        .await?;
    Ok(token)
}

/// A signed-in session.
#[derive(Clone, Debug)]
pub struct Session {
    pub login: Uuid,
    /// The login's name (its first identity's, when it was made).
    pub login_name: String,
    /// Who it acts as.
    pub identity: Identity,
    /// The passkey it was signed in with, if it was.
    pub credential_id: Option<Vec<u8>>,
    /// The OIDC provider it was signed in at, if it was.
    pub oidc_provider: Option<String>,
    /// Whether its passkey was used within `OPERATOR_FRESHNESS`.
    pub fresh: bool,
}

/// The session of `token`, while it lasts; it was used just now (noted at
/// most once a minute).
pub async fn session(client: &Object, token: &str) -> anyhow::Result<Option<Session>> {
    let row = client
        .query_opt_cached(
            &format!(
                "SELECT {IDENTITY}, s.login_id, l.name, s.credential_id,
                        s.verified_at > now() - make_interval(secs => $3),
                        s.last_seen_at < now() - interval '1 minute', s.oidc_provider
                 FROM console_sessions s
                 JOIN logins l ON l.id = s.login_id
                 JOIN login_identities i ON i.login_id = s.login_id AND i.account_id = s.account_id
                 JOIN accounts a ON a.id = i.account_id LEFT JOIN roles r ON r.id = i.role_id
                 WHERE s.token_hash = $1 AND s.expires_at > now()
                   AND s.last_seen_at > now() - make_interval(secs => $2)"
            ),
            &[&hash(token), &secs(SESSION_IDLE), &secs(OPERATOR_FRESHNESS)],
        )
        .await?;
    let Some(row) = row else { return Ok(None) };
    if row.get::<_, bool>(10) {
        client
            .execute_cached("UPDATE console_sessions SET last_seen_at = now() WHERE token_hash = $1", &[&hash(token)])
            .await?;
    }
    Ok(Some(Session {
        identity: identity_of(&row, 0),
        login: row.get(6),
        login_name: row.get(7),
        credential_id: row.get(8),
        fresh: row.get(9),
        oidc_provider: row.get(11),
    }))
}

/// Has session `token` act as its login's identity in account `account` (by
/// ID); `verified`: its login just signed in again (a passkey's assertion,
/// or at its provider), which acting as the operator account needs. Whether
/// the login has an identity there.
pub async fn switch(client: &Object, token: &str, account: &str, verified: bool) -> anyhow::Result<bool> {
    switch_hashed(client, &hash(token), account, verified).await
}

/// As `switch`, for the session whose token hashes to `token_hash`.
pub async fn switch_hashed(client: &Object, token_hash: &[u8], account: &str, verified: bool) -> anyhow::Result<bool> {
    let updated = client
        .execute_cached(
            "UPDATE console_sessions s
             SET account_id = $2, verified_at = CASE WHEN $3 THEN now() ELSE s.verified_at END
             WHERE s.token_hash = $1
               AND EXISTS (SELECT 1 FROM login_identities i WHERE i.login_id = s.login_id AND i.account_id = $2)",
            &[&token_hash, &account, &verified],
        )
        .await?;
    Ok(updated == 1)
}

pub async fn end_session(client: &Object, token: &str) -> anyhow::Result<()> {
    client.execute_cached("DELETE FROM console_sessions WHERE token_hash = $1", &[&hash(token)]).await?;
    Ok(())
}

/// A passkey, as its login sees it.
pub struct PasskeyInfo {
    pub credential_id: Vec<u8>,
    pub name: String,
    pub backed_up: bool,
    pub created_at: f64,
    pub last_used_at: Option<f64>,
}

/// `login`'s passkeys, oldest first.
pub async fn passkeys(client: &Object, login: Uuid) -> anyhow::Result<Vec<PasskeyInfo>> {
    let rows = client
        .query_cached(
            "SELECT credential_id, name, backed_up, extract(epoch FROM created_at)::float8,
                    extract(epoch FROM last_used_at)::float8
             FROM passkeys WHERE login_id = $1 ORDER BY created_at, credential_id",
            &[&login],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| PasskeyInfo {
            credential_id: r.get(0),
            name: r.get(1),
            backed_up: r.get(2),
            created_at: r.get(3),
            last_used_at: r.get(4),
        })
        .collect())
}

/// The credential IDs of `login`'s passkeys (for a new one not to be on the
/// same authenticator).
pub async fn credential_ids(client: &Object, login: Uuid) -> anyhow::Result<Vec<Vec<u8>>> {
    let rows = client.query_cached("SELECT credential_id FROM passkeys WHERE login_id = $1", &[&login]).await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}

/// Renames one of `login`'s passkeys.
pub async fn rename_passkey(client: &Object, login: Uuid, credential_id: &[u8], name: &str) -> anyhow::Result<()> {
    let updated = client
        .execute_cached(
            "UPDATE passkeys SET name = $3 WHERE login_id = $1 AND credential_id = $2",
            &[&login, &credential_id, &name],
        )
        .await?;
    if updated == 0 {
        return Err(Invalid("no such passkey".into()).into());
    }
    Ok(())
}

/// Removes one of `login`'s passkeys, and ends the sessions signed in with
/// it, unless it's the login's last (T31).
pub async fn delete_passkey(client: &Object, login: Uuid, credential_id: &[u8]) -> anyhow::Result<()> {
    let status = client
        .query_one_cached("SELECT pg_temp.cairn_delete_passkey($1, $2)", &[&login, &credential_id])
        .await?;
    match status.get::<_, &str>(0) {
        "deleted" => Ok(()),
        "no_such_passkey" => Err(Invalid("no such passkey".into()).into()),
        "last" => Err(Invalid("it's your last way to sign in: add another passkey or a provider first".into()).into()),
        status => unreachable!("cairn_delete_passkey: unknown status {status}"),
    }
}

/// Removes what has expired: challenges, enrollment links, sessions.
pub async fn reap(client: &Object) -> anyhow::Result<u64> {
    let mut reaped = 0;
    for table in ["console_challenges", "console_enrollments"] {
        reaped += client.execute_cached(&format!("DELETE FROM {table} WHERE expires_at <= now()"), &[]).await?;
    }
    reaped += client
        .execute_cached(
            "DELETE FROM console_sessions WHERE expires_at <= now() OR last_seen_at <= now() - make_interval(secs => $1)",
            &[&secs(SESSION_IDLE)],
        )
        .await?;
    Ok(reaped)
}

/// A passkey's name, as its login gives it.
pub fn check_name(name: &str) -> Result<&str, Invalid> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
        return Err(Invalid("a passkey's name must be 1 to 64 characters".into()));
    }
    Ok(name)
}
