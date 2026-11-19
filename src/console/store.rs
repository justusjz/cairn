//! The console's rows: directory users' passkeys, setup links and
//! sessions, ceremonies' challenges, and the root user's links and
//! sessions. Tokens (links' and sessions') are random, handed out once, and
//! kept as their SHA-256 only, so the database can't sign anyone in.
//!
//! People sign in as directory users (see `identity_center`): a user of
//! Cairn's own directory with its passkeys, one of an identity source
//! there. The account's root user is no directory user: a one-time link
//! that the command line on a node makes (migration 58) starts a short
//! session as it.

use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use deadpool_postgres::Object;
use ring::digest;
use uuid::Uuid;

use crate::db::Cached;
use crate::users::Invalid;

/// How long a directory user's setup link works: as long as Identity
/// Center's invitations.
pub const SETUP_LINK_TTL: Duration = Duration::from_secs(7 * 24 * 3600);
/// How long a ceremony may take, from its options to its response.
pub const CHALLENGE_TTL: Duration = Duration::from_secs(5 * 60);
/// How long a session lasts at most, and unused.
pub const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
pub const SESSION_IDLE: Duration = Duration::from_secs(3600);
/// How long a link for the account's root user works, and how long the
/// session it starts lasts at most, and unused: the root is for getting
/// back in, not for every day.
pub const ROOT_LINK_TTL: Duration = Duration::from_secs(15 * 60);
pub const ROOT_SESSION_TTL: Duration = Duration::from_secs(3600);
pub const ROOT_SESSION_IDLE: Duration = Duration::from_secs(15 * 60);
/// The most passkeys a directory user may have, as IAM's MFA devices (I10).
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
    digest::digest(&digest::SHA256, token.as_bytes())
        .as_ref()
        .to_vec()
}

fn secs(d: Duration) -> f64 {
    d.as_secs_f64()
}

/// Whether anyone can sign in to the console: a directory user has a
/// passkey, or there's an identity source to sign in at.
pub async fn anyone_can_sign_in(client: &Object) -> anyhow::Result<bool> {
    let row = client
        .query_one_cached(
            "SELECT EXISTS (SELECT 1 FROM directory_passkeys) OR EXISTS (SELECT 1 FROM oidc_providers)",
            &[],
        )
        .await?;
    Ok(row.get(0))
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

/// A new challenge for a ceremony that's no one's yet (setting up a
/// passkey with a link, or signing in): its ID and bytes.
pub async fn create_challenge(
    client: &Object,
    purpose: Purpose,
) -> anyhow::Result<(Uuid, Vec<u8>)> {
    let mut challenge = vec![0u8; 32];
    getrandom::fill(&mut challenge).map_err(|e| anyhow::anyhow!("generating a challenge: {e}"))?;
    let id = Uuid::new_v4();
    client
        .execute_cached(
            "INSERT INTO console_challenges (id, challenge, purpose, expires_at)
             VALUES ($1, $2, $3, now() + make_interval(secs => $4))",
            &[&id, &challenge, &purpose.as_str(), &secs(CHALLENGE_TTL)],
        )
        .await?;
    Ok((id, challenge))
}

/// A new challenge for directory user `user` (of Cairn's own directory),
/// signed in, to add a passkey with: its ID and bytes.
pub async fn create_directory_challenge(
    client: &Object,
    user: Uuid,
) -> anyhow::Result<(Uuid, Vec<u8>)> {
    let mut challenge = vec![0u8; 32];
    getrandom::fill(&mut challenge).map_err(|e| anyhow::anyhow!("generating a challenge: {e}"))?;
    let id = Uuid::new_v4();
    client
        .execute_cached(
            "INSERT INTO console_challenges (id, challenge, purpose, directory_user_id, expires_at)
             VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))",
            &[
                &id,
                &challenge,
                &Purpose::Add.as_str(),
                &user,
                &secs(CHALLENGE_TTL),
            ],
        )
        .await?;
    Ok((id, challenge))
}

/// A challenge, used up: its bytes, and the directory user whose it is, if
/// anyone's.
pub struct Challenge {
    pub bytes: Vec<u8>,
    pub directory_user: Option<Uuid>,
}

/// Uses up challenge `id`, if it's for `purpose` and still works.
pub async fn take_challenge(
    client: &Object,
    id: Uuid,
    purpose: Purpose,
) -> anyhow::Result<Option<Challenge>> {
    let row = client
        .query_opt_cached(
            "DELETE FROM console_challenges WHERE id = $1 AND purpose = $2 AND expires_at > now()
             RETURNING challenge, directory_user_id",
            &[&id, &purpose.as_str()],
        )
        .await?;
    Ok(row.map(|r| Challenge {
        bytes: r.get(0),
        directory_user: r.get(1),
    }))
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

fn no_link() -> anyhow::Error {
    Invalid("this link has been used, or has expired".into()).into()
}

/// Ends the session of `token`: the root user's, or a directory user's.
pub async fn end_session(client: &Object, token: &str) -> anyhow::Result<()> {
    for table in [
        "console_root_sessions",
        "console_directory_sessions",
        "console_switched_roles",
    ] {
        client
            .execute_cached(
                &format!("DELETE FROM {table} WHERE token_hash = $1"),
                &[&hash(token)],
            )
            .await?;
    }
    Ok(())
}

// ─── Directory users ─────────────────────────────────────────────────────────

/// A session of directory user `user` (see `identity_center`), of the
/// instance of `account` (by ID), acting as permission set `chosen` in an
/// account (its ID and the account's; `None`: until it picks one), signed
/// in with passkey `credential` (just now), or at its identity source.
pub async fn create_directory_session(
    client: &Object,
    account: &str,
    user: Uuid,
    chosen: Option<(Uuid, &str)>,
    credential: Option<&[u8]>,
) -> anyhow::Result<String> {
    let (token, hash) = token()?;
    let (set, target) = chosen.unzip();
    client
        .execute_cached(
            "INSERT INTO console_directory_sessions (token_hash, account_id, user_id, permission_set_id, target_account_id, expires_at,
                                                     credential_id, verified_at)
             VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6), $7, CASE WHEN $7::bytea IS NULL THEN NULL ELSE now() END)",
            &[&hash, &account, &user, &set, &target, &secs(SESSION_TTL), &credential],
        )
        .await?;
    Ok(token)
}

/// A directory user's session.
#[derive(Clone, Debug)]
pub struct DirectorySession {
    /// Its instance's account's ID, and name.
    pub account_id: String,
    pub account: String,
    /// The user (its ID in the identity store), its identity source (its
    /// name and label) and its subject there (none, for a user of Cairn's
    /// own directory), and what the user is: its user name, name, e-mail
    /// and groups (their names).
    pub user_id: Uuid,
    pub provider: Option<String>,
    pub provider_label: Option<String>,
    pub subject: Option<String>,
    pub user_name: String,
    pub name: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    /// The permission set it acts as, and the account (by ID) it acts in, if
    /// it picked one.
    pub permission_set: Option<(Uuid, String)>,
    /// When it ends at the latest (seconds since the epoch).
    pub expires_at: f64,
    /// Seconds since it was signed in with a passkey, if it was (a user of
    /// Cairn's own directory): `aws:MultiFactorAuthAge`.
    pub mfa_age: Option<i64>,
    /// The passkey it was signed in with, if it was.
    pub credential_id: Option<Vec<u8>>,
}

/// The directory user's session of `token`, while it lasts; it was used just
/// now (noted at most once a minute).
pub async fn directory_session(
    client: &Object,
    token: &str,
) -> anyhow::Result<Option<DirectorySession>> {
    let row = client
        .query_opt_cached(
            "SELECT a.id, a.name, u.id, u.provider, p.label, u.subject, u.user_name, u.display_name, u.email,
                    ARRAY(SELECT g.name FROM identity_group_members m JOIN identity_groups g ON g.id = m.group_id
                          WHERE m.user_id = u.id ORDER BY g.name),
                    s.permission_set_id, extract(epoch FROM s.expires_at)::float8, s.last_seen_at < now() - interval '1 minute',
                    s.target_account_id,
                    -- Not greatest(0, …), which is 0 for NULL: signed in at a source, none.
                    CASE WHEN s.verified_at IS NULL THEN NULL ELSE greatest(0, extract(epoch FROM now() - s.verified_at))::bigint END,
                    s.credential_id
             FROM console_directory_sessions s JOIN accounts a ON a.id = s.account_id
             JOIN identity_users u ON u.id = s.user_id
             LEFT JOIN oidc_providers p ON p.name = u.provider
             WHERE s.token_hash = $1 AND s.expires_at > now()
               AND s.last_seen_at > now() - make_interval(secs => $2)",
            &[&hash(token), &secs(SESSION_IDLE)],
        )
        .await?;
    let Some(row) = row else { return Ok(None) };
    if row.get::<_, bool>(12) {
        client
            .execute_cached(
                "UPDATE console_directory_sessions SET last_seen_at = now() WHERE token_hash = $1",
                &[&hash(token)],
            )
            .await?;
    }
    Ok(Some(DirectorySession {
        account_id: row.get(0),
        account: row.get(1),
        user_id: row.get(2),
        provider: row.get(3),
        provider_label: row.get(4),
        subject: row.get(5),
        user_name: row.get(6),
        name: row.get(7),
        email: row.get(8),
        groups: row.get(9),
        permission_set: row
            .get::<_, Option<Uuid>>(10)
            .zip(row.get::<_, Option<String>>(13)),
        expires_at: row.get(11),
        mfa_age: row.get(14),
        credential_id: row.get(15),
    }))
}

/// Has the directory user's session of `token` act as `permission_set` in
/// account `account` (by ID).
pub async fn choose_permission_set(
    client: &Object,
    token: &str,
    permission_set: Uuid,
    account: &str,
) -> anyhow::Result<()> {
    client
        .execute_cached(
            "UPDATE console_directory_sessions SET permission_set_id = $2, target_account_id = $3 WHERE token_hash = $1",
            &[&hash(token), &permission_set, &account],
        )
        .await?;
    Ok(())
}

/// Makes a setup link's token for user `user` of Cairn's own directory, to
/// make a passkey with, within `SETUP_LINK_TTL`; it replaces any the user
/// had. Refused for a user of an identity source, which signs in there.
pub async fn create_setup_link(client: &Object, user: Uuid) -> anyhow::Result<String> {
    let (token, hash) = token()?;
    let made = client
        .execute_cached(
            "INSERT INTO directory_setup_links (token_hash, user_id, expires_at)
             SELECT $2, id, now() + make_interval(secs => $3) FROM identity_users WHERE id = $1 AND provider IS NULL
             ON CONFLICT (user_id) DO UPDATE SET token_hash = EXCLUDED.token_hash, expires_at = EXCLUDED.expires_at",
            &[&user, &hash, &secs(SETUP_LINK_TTL)],
        )
        .await?;
    if made == 0 {
        return Err(Invalid("only a user of Cairn's own directory has passkeys: one of an identity source signs in there".into()).into());
    }
    Ok(token)
}

/// The directory user setup link `token` is for, while it works: its ID
/// and user name.
pub async fn setup_link(client: &Object, token: &str) -> anyhow::Result<Option<(Uuid, String)>> {
    let row = client
        .query_opt_cached(
            "SELECT u.id, u.user_name FROM directory_setup_links l JOIN identity_users u ON u.id = l.user_id
             WHERE l.token_hash = $1 AND l.expires_at > now()",
            &[&hash(token)],
        )
        .await?;
    Ok(row.map(|r| (r.get(0), r.get(1))))
}

/// Gives the directory user of setup link `token` passkey `key`, using the
/// link up: the user's ID.
pub async fn new_directory_passkey(
    client: &Object,
    token: &str,
    key: &NewPasskey<'_>,
) -> anyhow::Result<Uuid> {
    add_directory_passkey_as(client, None, Some(token), key).await
}

/// Gives directory user `user`, signed in, passkey `key`.
pub async fn add_directory_passkey(
    client: &Object,
    user: Uuid,
    key: &NewPasskey<'_>,
) -> anyhow::Result<()> {
    add_directory_passkey_as(client, Some(user), None, key)
        .await
        .map(|_| ())
}

/// T65: gives a directory user a passkey, signed in (`user`) or with its
/// setup link (`token`): the user's ID.
async fn add_directory_passkey_as(
    client: &Object,
    user: Option<Uuid>,
    token: Option<&str>,
    key: &NewPasskey<'_>,
) -> anyhow::Result<Uuid> {
    let taken = || Invalid("this passkey is registered already".into());
    let row = client
        .query_one_cached(
            "SELECT * FROM pg_temp.cairn_add_directory_passkey($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            &[
                &user,
                &token.map(hash),
                &key.credential_id,
                &key.public_key,
                &i64::from(key.sign_count),
                &key.name,
                &key.backup_eligible,
                &key.backed_up,
                &MAX_PASSKEYS,
            ],
        )
        .await
        .map_err(|e| {
            match e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) {
                true => taken().into(),
                false => anyhow::Error::from(e),
            }
        })?;
    match row.get::<_, &str>(0) {
        "added" => Ok(row.get(1)),
        "no_link" => Err(no_link()),
        "no_such_user" => Err(Invalid("sign in again".into()).into()),
        "too_many" => Err(Invalid(format!(
            "a user has at most {MAX_PASSKEYS} passkeys; remove one first"
        ))
        .into()),
        "taken" => Err(taken().into()),
        status => unreachable!("cairn_add_directory_passkey: unknown status {status}"),
    }
}

/// Directory user `user`'s passkeys, oldest first.
pub async fn directory_passkeys(client: &Object, user: Uuid) -> anyhow::Result<Vec<PasskeyInfo>> {
    let rows = client
        .query_cached(
            "SELECT credential_id, name, backed_up, extract(epoch FROM created_at)::float8,
                    extract(epoch FROM last_used_at)::float8
             FROM directory_passkeys WHERE user_id = $1 ORDER BY created_at, credential_id",
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

/// The credential IDs of directory user `user`'s passkeys.
pub async fn directory_credential_ids(client: &Object, user: Uuid) -> anyhow::Result<Vec<Vec<u8>>> {
    let rows = client
        .query_cached(
            "SELECT credential_id FROM directory_passkeys WHERE user_id = $1",
            &[&user],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}

/// Renames one of directory user `user`'s passkeys.
pub async fn rename_directory_passkey(
    client: &Object,
    user: Uuid,
    credential_id: &[u8],
    name: &str,
) -> anyhow::Result<()> {
    let updated = client
        .execute_cached(
            "UPDATE directory_passkeys SET name = $3 WHERE user_id = $1 AND credential_id = $2",
            &[&user, &credential_id, &name],
        )
        .await?;
    if updated == 0 {
        return Err(Invalid("no such passkey".into()).into());
    }
    Ok(())
}

/// Removes one of directory user `user`'s passkeys, and ends the sessions
/// signed in with it, unless it's the user's last (T66).
pub async fn delete_directory_passkey(
    client: &Object,
    user: Uuid,
    credential_id: &[u8],
) -> anyhow::Result<()> {
    let status = client
        .query_one_cached(
            "SELECT pg_temp.cairn_delete_directory_passkey($1, $2)",
            &[&user, &credential_id],
        )
        .await?;
    match status.get::<_, &str>(0) {
        "deleted" => Ok(()),
        "no_such_passkey" => Err(Invalid("no such passkey".into()).into()),
        "last" => {
            Err(Invalid("it's your last way to sign in: add another passkey first".into()).into())
        }
        status => unreachable!("cairn_delete_directory_passkey: unknown status {status}"),
    }
}

/// A directory user's passkey, to check an assertion by.
pub struct DirectoryPasskey {
    pub user: Uuid,
    pub public_key: Vec<u8>,
    pub sign_count: u32,
}

pub async fn directory_passkey(
    client: &Object,
    credential_id: &[u8],
) -> anyhow::Result<Option<DirectoryPasskey>> {
    let row = client
        .query_opt_cached(
            "SELECT user_id, public_key, sign_count FROM directory_passkeys WHERE credential_id = $1",
            &[&credential_id],
        )
        .await?;
    Ok(row.map(|r| DirectoryPasskey {
        user: r.get(0),
        public_key: r.get(1),
        sign_count: r.get::<_, i64>(2) as u32,
    }))
}

/// Records a directory user's passkey's use, if its signature counter went
/// forward (or it doesn't count: both zero), as WebAuthn says (§7.2, step
/// 21). Otherwise the authenticator may have been cloned, and the use is
/// refused: whether it was recorded.
pub async fn record_directory_use(
    client: &Object,
    credential_id: &[u8],
    sign_count: u32,
    backed_up: bool,
) -> anyhow::Result<bool> {
    let updated = client
        .execute_cached(
            "UPDATE directory_passkeys SET sign_count = $2, backed_up = $3, last_used_at = now()
             WHERE credential_id = $1 AND (($2::bigint = 0 AND sign_count = 0) OR $2::bigint > sign_count)",
            &[&credential_id, &i64::from(sign_count), &backed_up],
        )
        .await?;
    Ok(updated == 1)
}

/// How a user of Cairn's own directory signs in: how many passkeys it
/// has, when it last used one, and whether a setup link for it is out.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DirectoryAccess {
    pub passkeys: i64,
    pub last_sign_in: Option<f64>,
    pub link_pending: bool,
}

/// How each user of Cairn's own directory signs in, by its ID.
pub async fn directory_access(
    client: &Object,
) -> anyhow::Result<std::collections::HashMap<Uuid, DirectoryAccess>> {
    let rows = client
        .query_cached(
            "SELECT u.id, (SELECT count(*) FROM directory_passkeys d WHERE d.user_id = u.id),
                    extract(epoch FROM (SELECT max(d.last_used_at) FROM directory_passkeys d WHERE d.user_id = u.id))::float8,
                    EXISTS (SELECT 1 FROM directory_setup_links l WHERE l.user_id = u.id AND l.expires_at > now())
             FROM identity_users u WHERE u.provider IS NULL",
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| {
            (
                r.get(0),
                DirectoryAccess {
                    passkeys: r.get(1),
                    last_sign_in: r.get(2),
                    link_pending: r.get(3),
                },
            )
        })
        .collect())
}

/// Removes all of a directory user's passkeys (signing it out): how many
/// it had.
pub async fn delete_directory_passkeys(client: &Object, user: Uuid) -> anyhow::Result<u64> {
    Ok(client
        .execute_cached(
            "DELETE FROM directory_passkeys WHERE user_id = $1",
            &[&user],
        )
        .await?)
}

// ─── The root user ───────────────────────────────────────────────────────────

/// Makes a link's token for the root user of account `account` (its ID) to
/// sign in to the console with, once, within `ROOT_LINK_TTL`; it replaces
/// any the account had. Only the command line on a node makes one (see
/// `accounts`): the root has no passkeys or keys, so that's its only way in.
pub async fn create_root_link(client: &Object, account: &str) -> anyhow::Result<String> {
    let (token, hash) = token()?;
    client
        .execute_cached(
            "WITH d AS (DELETE FROM console_root_links WHERE account_id = $1)
             INSERT INTO console_root_links (token_hash, account_id, expires_at)
             VALUES ($2, $1, now() + make_interval(secs => $3))",
            &[&account, &hash, &secs(ROOT_LINK_TTL)],
        )
        .await?;
    Ok(token)
}

/// Uses up the root user's link `link` (while it works), starting a
/// session as the root of its account: the session's token; `None` if the
/// link was used, or has expired. One statement: both, or neither.
pub async fn root_sign_in(client: &Object, link: &str) -> anyhow::Result<Option<String>> {
    let (token, session) = token()?;
    let made = client
        .execute_cached(
            "WITH l AS (DELETE FROM console_root_links WHERE token_hash = $1 AND expires_at > now() RETURNING account_id)
             INSERT INTO console_root_sessions (token_hash, account_id, expires_at)
             SELECT $2, l.account_id, now() + make_interval(secs => $3) FROM l",
            &[&hash(link), &session, &secs(ROOT_SESSION_TTL)],
        )
        .await?;
    Ok((made == 1).then_some(token))
}

/// A session of an account's root user.
#[derive(Clone, Debug)]
pub struct RootSession {
    /// Its account's ID, and name.
    pub account_id: String,
    pub account: String,
    /// When it ends at the latest (seconds since the epoch).
    pub expires_at: f64,
}

/// The root user's session of `token`, while it lasts; it was used just now
/// (noted at most once a minute).
pub async fn root_session(client: &Object, token: &str) -> anyhow::Result<Option<RootSession>> {
    let row = client
        .query_opt_cached(
            "SELECT a.id, a.name, extract(epoch FROM s.expires_at)::float8,
                    s.last_seen_at < now() - interval '1 minute'
             FROM console_root_sessions s JOIN accounts a ON a.id = s.account_id
             WHERE s.token_hash = $1 AND s.expires_at > now()
               AND s.last_seen_at > now() - make_interval(secs => $2)",
            &[&hash(token), &secs(ROOT_SESSION_IDLE)],
        )
        .await?;
    let Some(row) = row else { return Ok(None) };
    if row.get::<_, bool>(3) {
        client
            .execute_cached(
                "UPDATE console_root_sessions SET last_seen_at = now() WHERE token_hash = $1",
                &[&hash(token)],
            )
            .await?;
    }
    Ok(Some(RootSession {
        account_id: row.get(0),
        account: row.get(1),
        expires_at: row.get(2),
    }))
}

/// A passkey, as its user sees it.
pub struct PasskeyInfo {
    pub credential_id: Vec<u8>,
    pub name: String,
    pub backed_up: bool,
    pub created_at: f64,
    pub last_used_at: Option<f64>,
}

// ─── Switched roles ──────────────────────────────────────────────────────────

/// The role the session of `token` switched to (see `console::switch`).
#[derive(Clone, Debug)]
pub struct Switched {
    pub role_id: Uuid,
    pub session_name: String,
    /// When it ends (seconds since the epoch).
    pub expires_at: f64,
}

/// The role the session of `token` switched to, while that lasts.
pub async fn switched(client: &Object, token: &str) -> anyhow::Result<Option<Switched>> {
    let row = client
        .query_opt_cached(
            "SELECT role_id, session_name, extract(epoch FROM expires_at)::float8
             FROM console_switched_roles WHERE token_hash = $1 AND expires_at > now()",
            &[&hash(token)],
        )
        .await?;
    Ok(row.map(|r| Switched {
        role_id: r.get(0),
        session_name: r.get(1),
        expires_at: r.get(2),
    }))
}

/// Has the session of `token` act as a session of role `role`, named
/// `name`, for `seconds`, in place of any role it switched to before.
pub async fn switch_role(
    client: &Object,
    token: &str,
    role: Uuid,
    name: &str,
    seconds: i32,
) -> anyhow::Result<()> {
    client
        .execute_cached(
            "INSERT INTO console_switched_roles (token_hash, role_id, session_name, expires_at)
             VALUES ($1, $2, $3, now() + make_interval(secs => $4))
             ON CONFLICT (token_hash) DO UPDATE
                 SET role_id = EXCLUDED.role_id, session_name = EXCLUDED.session_name, expires_at = EXCLUDED.expires_at",
            &[&hash(token), &role, &name, &f64::from(seconds)],
        )
        .await?;
    Ok(())
}

/// Has the session of `token` act as who it was signed in as again.
pub async fn switch_back(client: &Object, token: &str) -> anyhow::Result<()> {
    client
        .execute_cached(
            "DELETE FROM console_switched_roles WHERE token_hash = $1",
            &[&hash(token)],
        )
        .await?;
    Ok(())
}

/// Removes what has expired: challenges, links, sessions.
pub async fn reap(client: &Object) -> anyhow::Result<u64> {
    let mut reaped = 0;
    for table in [
        "console_challenges",
        "console_root_links",
        "directory_setup_links",
        "console_switched_roles",
    ] {
        reaped += client
            .execute_cached(
                &format!("DELETE FROM {table} WHERE expires_at <= now()"),
                &[],
            )
            .await?;
    }
    reaped += client
        .execute_cached(
            "DELETE FROM console_root_sessions WHERE expires_at <= now() OR last_seen_at <= now() - make_interval(secs => $1)",
            &[&secs(ROOT_SESSION_IDLE)],
        )
        .await?;
    reaped += client
        .execute_cached(
            "DELETE FROM console_directory_sessions WHERE expires_at <= now() OR last_seen_at <= now() - make_interval(secs => $1)",
            &[&secs(SESSION_IDLE)],
        )
        .await?;
    Ok(reaped)
}

/// A passkey's name, as its user gives it.
pub fn check_name(name: &str) -> Result<&str, Invalid> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
        return Err(Invalid(
            "a passkey's name must be 1 to 64 characters".into(),
        ));
    }
    Ok(name)
}
