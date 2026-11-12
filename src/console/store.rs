//! The console's rows (migration 30): enrollment links, ceremonies'
//! challenges, passkeys and sessions. Tokens (links' and sessions') are
//! random, handed out once, and kept as their SHA-256 only, so the database
//! can't sign anyone in.

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
/// The most passkeys a user may have, as IAM's MFA devices (I10).
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
#[derive(Clone, Debug)]
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub admin: bool,
}

/// Makes `user` an enrollment link's token, which replaces any it had.
pub async fn create_enrollment(client: &Object, user: &str) -> anyhow::Result<String> {
    let (token, hash) = token()?;
    let made = client
        .execute_cached(
            "WITH r AS (SELECT id FROM roles WHERE name = $1),
                  d AS (DELETE FROM console_enrollments e USING r WHERE e.role_id = r.id)
             INSERT INTO console_enrollments (token_hash, role_id, expires_at)
             SELECT $2, r.id, now() + make_interval(secs => $3) FROM r",
            &[&user, &hash, &secs(ENROLLMENT_TTL)],
        )
        .await?;
    if made == 0 {
        return Err(Invalid(format!("no user named {user:?}")).into());
    }
    Ok(token)
}

/// Whose enrollment link `token` is, while it works.
pub async fn enrollment(client: &Object, token: &str) -> anyhow::Result<Option<User>> {
    let row = client
        .query_opt_cached(
            "SELECT r.id, r.name, r.admin FROM console_enrollments e JOIN roles r ON r.id = e.role_id
             WHERE e.token_hash = $1 AND e.expires_at > now()",
            &[&hash(token)],
        )
        .await?;
    Ok(row.map(|r| User { id: r.get(0), name: r.get(1), admin: r.get(2) }))
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

/// A new challenge for a ceremony: its ID and bytes.
pub async fn create_challenge(client: &Object, purpose: Purpose, user: Option<Uuid>) -> anyhow::Result<(Uuid, Vec<u8>)> {
    let mut challenge = vec![0u8; 32];
    getrandom::fill(&mut challenge).map_err(|e| anyhow::anyhow!("generating a challenge: {e}"))?;
    let id = Uuid::new_v4();
    client
        .execute_cached(
            "INSERT INTO console_challenges (id, challenge, purpose, role_id, expires_at)
             VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))",
            &[&id, &challenge, &purpose.as_str(), &user, &secs(CHALLENGE_TTL)],
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
             RETURNING challenge, role_id",
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

/// Gives `user` a passkey (T30), through the enrollment link `enrollment`
/// (which it uses up), or signed in (`None`).
pub async fn add_passkey(client: &Object, user: Uuid, enrollment: Option<&str>, key: &NewPasskey<'_>) -> anyhow::Result<()> {
    let enrollment = enrollment.map(hash);
    let status = client
        .query_one_cached(
            "SELECT pg_temp.cairn_add_passkey($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            &[
                &user,
                &enrollment,
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
        "no_such_user" => Err(Invalid("the user no longer exists".into()).into()),
        "no_enrollment" => Err(Invalid("this enrollment link has been used, or has expired".into()).into()),
        "too_many" => Err(Invalid(format!("a user has at most {MAX_PASSKEYS} passkeys; remove one first")).into()),
        "taken" => Err(Invalid("this passkey is registered already".into()).into()),
        status => unreachable!("cairn_add_passkey: unknown status {status}"),
    }
}

/// A passkey, to check an assertion by.
pub struct Passkey {
    pub user: User,
    pub public_key: Vec<u8>,
    pub sign_count: u32,
}

pub async fn passkey(client: &Object, credential_id: &[u8]) -> anyhow::Result<Option<Passkey>> {
    let row = client
        .query_opt_cached(
            "SELECT r.id, r.name, r.admin, p.public_key, p.sign_count
             FROM passkeys p JOIN roles r ON r.id = p.role_id WHERE p.credential_id = $1",
            &[&credential_id],
        )
        .await?;
    Ok(row.map(|r| Passkey {
        user: User { id: r.get(0), name: r.get(1), admin: r.get(2) },
        public_key: r.get(3),
        sign_count: r.get::<_, i64>(4) as u32,
    }))
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

/// A session's token, for `user`, signed in with `credential_id`.
pub async fn create_session(client: &Object, user: Uuid, credential_id: &[u8]) -> anyhow::Result<String> {
    let (token, hash) = token()?;
    client
        .execute_cached(
            "INSERT INTO console_sessions (token_hash, role_id, credential_id, expires_at)
             VALUES ($1, $2, $3, now() + make_interval(secs => $4))",
            &[&hash, &user, &credential_id, &secs(SESSION_TTL)],
        )
        .await?;
    Ok(token)
}

/// A signed-in session.
#[derive(Clone, Debug)]
pub struct Session {
    pub user: User,
    /// The passkey it was signed in with.
    pub credential_id: Vec<u8>,
}

/// The session of `token`, while it lasts; it was used just now (noted at
/// most once a minute).
pub async fn session(client: &Object, token: &str) -> anyhow::Result<Option<Session>> {
    let row = client
        .query_opt_cached(
            "SELECT r.id, r.name, r.admin, s.credential_id, s.last_seen_at < now() - interval '1 minute'
             FROM console_sessions s JOIN roles r ON r.id = s.role_id
             WHERE s.token_hash = $1 AND s.expires_at > now()
               AND s.last_seen_at > now() - make_interval(secs => $2)",
            &[&hash(token), &secs(SESSION_IDLE)],
        )
        .await?;
    let Some(row) = row else { return Ok(None) };
    if row.get::<_, bool>(4) {
        client
            .execute_cached("UPDATE console_sessions SET last_seen_at = now() WHERE token_hash = $1", &[&hash(token)])
            .await?;
    }
    Ok(Some(Session {
        user: User { id: row.get(0), name: row.get(1), admin: row.get(2) },
        credential_id: row.get(3),
    }))
}

pub async fn end_session(client: &Object, token: &str) -> anyhow::Result<()> {
    client.execute_cached("DELETE FROM console_sessions WHERE token_hash = $1", &[&hash(token)]).await?;
    Ok(())
}

/// A passkey, as its user sees it.
pub struct PasskeyInfo {
    pub credential_id: Vec<u8>,
    pub name: String,
    pub backed_up: bool,
    pub created_at: f64,
    pub last_used_at: Option<f64>,
}

/// `user`'s passkeys, oldest first.
pub async fn passkeys(client: &Object, user: Uuid) -> anyhow::Result<Vec<PasskeyInfo>> {
    let rows = client
        .query_cached(
            "SELECT credential_id, name, backed_up, extract(epoch FROM created_at)::float8,
                    extract(epoch FROM last_used_at)::float8
             FROM passkeys WHERE role_id = $1 ORDER BY created_at, credential_id",
            &[&user],
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

/// The credential IDs of `user`'s passkeys (for a new one not to be on the
/// same authenticator).
pub async fn credential_ids(client: &Object, user: Uuid) -> anyhow::Result<Vec<Vec<u8>>> {
    let rows = client.query_cached("SELECT credential_id FROM passkeys WHERE role_id = $1", &[&user]).await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}

/// Renames one of `user`'s passkeys.
pub async fn rename_passkey(client: &Object, user: Uuid, credential_id: &[u8], name: &str) -> anyhow::Result<()> {
    let updated = client
        .execute_cached(
            "UPDATE passkeys SET name = $3 WHERE role_id = $1 AND credential_id = $2",
            &[&user, &credential_id, &name],
        )
        .await?;
    if updated == 0 {
        return Err(Invalid("no such passkey".into()).into());
    }
    Ok(())
}

/// Removes one of `user`'s passkeys, and ends the sessions signed in with
/// it, unless it's the user's last (T31).
pub async fn delete_passkey(client: &Object, user: Uuid, credential_id: &[u8]) -> anyhow::Result<()> {
    let status = client
        .query_one_cached("SELECT pg_temp.cairn_delete_passkey($1, $2)", &[&user, &credential_id])
        .await?;
    match status.get::<_, &str>(0) {
        "deleted" => Ok(()),
        "no_such_passkey" => Err(Invalid("no such passkey".into()).into()),
        "last" => Err(Invalid("this is your last passkey: add another before removing it".into()).into()),
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

/// A passkey's name, as its user gives it.
pub fn check_name(name: &str) -> Result<&str, Invalid> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
        return Err(Invalid("a passkey's name must be 1 to 64 characters".into()));
    }
    Ok(name)
}
