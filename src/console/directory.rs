//! Directory users in the console (see `identity_center`): who signed in at
//! an identity source, acting as a session of the role of the permission set
//! it picked, among those assigned to it or its groups. The assignment is
//! checked again on every request, so that taking it away ends the
//! session's access at once; credentials handed out for the CLI last as
//! their own session does.

use std::net::IpAddr;

use axum::http::{HeaderMap, Method};
use deadpool_postgres::Object;

use super::{actor, store, web::ApiError};
use crate::{
    identity_center::{self, PermissionSet},
    sessions::{self, Session, Who},
    users::Principal,
};

/// The permission set `session` acts as, while it's still assigned to its
/// user (or a group of it); else why not.
pub async fn permission_set(client: &Object, session: &store::DirectorySession) -> Result<PermissionSet, ApiError> {
    let Some(chosen) = session.permission_set else {
        return Err(ApiError::Forbidden("pick a permission set first".into()));
    };
    let eligible = identity_center::eligible(client, &session.account_id, session.user_id).await?;
    eligible
        .into_iter()
        .find(|set| set.id == chosen)
        .ok_or_else(|| ApiError::Forbidden("that permission set isn't assigned to you anymore: pick another".into()))
}

/// A session of `set`'s role for the directory user of `session`, for the
/// permission set's session duration: named after the user, as Identity
/// Center names them.
pub fn role_session(set: &PermissionSet, session: &store::DirectorySession) -> anyhow::Result<Session> {
    let now = sessions::now();
    let name = identity_center::session_name(&[Some(&session.user_name), session.email.as_deref(), Some(&session.subject)]);
    Ok(Session {
        key_id: sessions::new_key_id()?,
        secret: String::new(),
        issued: now,
        expires: now + set.session_duration as u64,
        who: Who::Role { id: set.role_id, session: name },
        policy: None,
        policy_arns: Vec::new(),
        tags: Vec::new(),
        transitive: Vec::new(),
        source_identity: None,
        chained: false,
        provider: None,
        directory: None,
        access_grants: None,
    })
}

/// Who a directory user's `session` acts as, for a request (`method`,
/// `headers`, `query`, from `peer`): its permission set's role's session.
/// It signed in at an identity source, which Cairn takes as no second
/// factor: `aws:MultiFactorAuthPresent` is false.
pub async fn user(
    client: &Object,
    session: &store::DirectorySession,
    method: Method,
    headers: HeaderMap,
    query: String,
    peer: Option<IpAddr>,
) -> Result<actor::User, ApiError> {
    let set = permission_set(client, session).await?;
    let principal = match Principal::of_session(client, role_session(&set, session)?).await? {
        Ok(principal) => principal,
        Err(_) => return Err(ApiError::Forbidden("the permission set's role is gone: pick another".into())),
    };
    let account = session.account_id.clone();
    Ok(actor::User { principal, account, method, headers, query, peer, mfa_age: None })
}
