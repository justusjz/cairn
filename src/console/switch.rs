//! Switching roles in the console, as AWS's console does ("Switch role"):
//! a signed-in session (a login's user, or a directory user's permission
//! set's role's session) takes a role, in its own account or another of the
//! organization's, as STS's AssumeRole would let it: the role's trust
//! policy must allow it `sts:AssumeRole`, and so must its own policies when
//! the role is another account's (and the SCPs over it, a member account's
//! principal's), all as of when it switches. It then acts as a session of
//! the role, named after it, for an hour at most (a chain's longest, as
//! AWS's console has it), or until it switches back. The account's root
//! user assumes no role, as in AWS. It switches from who it signed in as,
//! never from a role it switched to, so that its own policies decide each
//! time. Who it signed in as is checked on each request still: a
//! directory user whose permission set is taken away loses the role too.

use deadpool_postgres::Object;

use super::{actor, store, web::ApiError};
use crate::{
    policy::{Context, Kind, Policy},
    roles::Role,
    sessions::{self, Session, Who},
    users::Principal,
};

/// A switched role's longest session, in seconds: a chain's (and AWS's
/// console's).
const MAX_SECONDS: i32 = 3600;

/// Who `base` (who a session signed in as) acts as: a session of the role
/// the session of `token` switched to, while that lasts and the role is
/// there; else `base` (and a role that's gone is forgotten).
pub async fn apply(client: &Object, token: &str, base: actor::User) -> Result<actor::User, ApiError> {
    let Some(switched) = store::switched(client, token).await? else { return Ok(base) };
    let now = sessions::now();
    let session = Session {
        key_id: sessions::new_key_id()?,
        secret: String::new(),
        issued: now,
        expires: switched.expires_at as u64,
        who: Who::Role { id: switched.role_id, session: switched.session_name },
        policy: None,
        policy_arns: Vec::new(),
        tags: Vec::new(),
        transitive: Vec::new(),
        source_identity: None,
        chained: base.principal.is_role_session(),
        provider: None,
        directory: None,
        access_grants: None,
    };
    match Principal::of_session(client, session).await? {
        Ok(principal) => {
            let account = principal.account.clone();
            Ok(actor::User { principal, account, ..base })
        }
        Err(_) => {
            store::switch_back(client, token).await?;
            Ok(base)
        }
    }
}

/// The name of a session `base` switches to a role in: its user's name, or
/// its own session's (a directory user's), as AWS's console names them.
fn session_name(base: &Principal) -> String {
    match base.session.as_ref().map(|s| &s.session.who) {
        Some(Who::Role { session, .. }) => session.clone(),
        _ => base.name.clone(),
    }
}

/// Has the session of `token`, signed in as `base`, act as a session of
/// role `role` (its name, after its path if it has one: `team/deployer`) of
/// account `account` (its ID), if `base` may assume it; refused as STS
/// refuses it, whether the role is there or not.
pub async fn switch(app: &std::sync::Arc<crate::App>, client: &Object, token: &str, base: actor::User, account: &str, role: &str) -> Result<(), ApiError> {
    if base.principal.root {
        return Err(ApiError::Forbidden("the root user can't switch roles, as in AWS: sign in as a user to".into()));
    }
    let (path, name) = match role.trim_matches('/').rsplit_once('/') {
        Some((path, name)) => (format!("/{path}/"), name),
        None => ("/".to_owned(), role.trim_matches('/')),
    };
    let arn = crate::roles::role_arn(account, &path, name);
    let caller = base.principal.arn();
    let denied = || ApiError::Forbidden(format!("{caller} may not assume role {arn} (sts:AssumeRole)"));
    let valid_account = account.len() == 12 && account.bytes().all(|b| b.is_ascii_digit());
    if !valid_account || !crate::roles::valid_name(name) {
        return Err(ApiError::BadRequest("an account is 12 digits, and a role its name (after its path, if it has one)".into()));
    }
    if !crate::organizations::open(client, account).await? {
        return Err(denied());
    }
    let Some(role) = Role::load(client, account, name).await?.filter(|r| r.path == path) else { return Err(denied()) };
    let trust = Policy::parse(&role.trust, Kind::Trust)
        .map_err(|e| anyhow::anyhow!("role {}'s trust policy doesn't parse: {}", role.name, e.message))?
        .with_ids(role.trust_principals.clone());
    let session = session_name(&base.principal);
    let mut context = Context::default();
    context.set("sts:RoleSessionName", &session);
    let actor = super::Actor(std::sync::Arc::new(base));
    let access = actor.access_for(app).await?;
    if !access.trusted("sts:AssumeRole", &role.arn(), &trust, &context) {
        return Err(denied());
    }
    store::switch_role(client, token, role.id, &session, MAX_SECONDS.min(role.max_session_duration)).await?;
    Ok(())
}
