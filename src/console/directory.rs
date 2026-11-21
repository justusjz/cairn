//! Directory users in the console (see `identity_center`): who signed in at
//! an identity source, acting as a session of the role of the permission set
//! it picked in an account, among those assigned to it or its groups in
//! that account. The assignment is
//! checked again on every request, so that taking it away ends the
//! session's access at once; credentials handed out for the CLI last as
//! their own session does.

use std::net::IpAddr;

use axum::http::{HeaderMap, Method};
use deadpool_postgres::Object;

use super::{actor, store, web::ApiError};
use crate::{
    identity_center::{self, Eligible},
    sessions::{self, Session, Who},
    users::Principal,
};

/// The permission set `session` acts as, and the account it acts in, while
/// it's still assigned to its user (or a group of it) there; else why not.
pub async fn permission_set(
    client: &Object,
    session: &store::DirectorySession,
) -> Result<Eligible, ApiError> {
    let Some((chosen, account)) = &session.permission_set else {
        return Err(ApiError::Forbidden("pick a permission set first".into()));
    };
    let eligible = identity_center::eligible(client, &session.account_id, session.user_id).await?;
    eligible
        .into_iter()
        .find(|e| e.set.id == *chosen && e.account == *account)
        .ok_or_else(|| {
            ApiError::Forbidden(
                "that permission set isn't assigned to you anymore: pick another".into(),
            )
        })
}

/// A session of the permission set's role in its account for the directory
/// user of `session`, for the set's session duration: named after the
/// user, as Identity Center names them.
pub fn role_session(
    chosen: &Eligible,
    session: &store::DirectorySession,
) -> anyhow::Result<Session> {
    role_session_of(
        chosen,
        &session.user_name,
        session.email.as_deref(),
        session.subject.as_deref(),
    )
}

/// A session of the permission set's role in its account for the directory
/// user named `user_name` (with `email`, and `subject` at its identity
/// source), as `role_session`.
pub fn role_session_of(
    chosen: &Eligible,
    user_name: &str,
    email: Option<&str>,
    subject: Option<&str>,
) -> anyhow::Result<Session> {
    let now = sessions::now();
    let name = identity_center::session_name(&[Some(user_name), email, subject]);
    Ok(Session {
        key_id: sessions::new_key_id()?,
        secret: String::new(),
        issued: now,
        expires: now + chosen.set.session_duration as u64,
        who: Who::Role {
            id: chosen.role_id,
            session: name,
        },
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
/// `headers`, `query`, from `peer`): its permission set's role's session,
/// in the account it picked.
/// Signed in at an identity source, which Cairn takes as no second factor,
/// `aws:MultiFactorAuthPresent` is false; signed in with a passkey (a user
/// of Cairn's own directory), it's true.
pub async fn user(
    client: &Object,
    session: &store::DirectorySession,
    method: Method,
    headers: HeaderMap,
    query: String,
    peer: Option<IpAddr>,
) -> Result<actor::User, ApiError> {
    let chosen = permission_set(client, session).await?;
    let principal = match Principal::of_session(client, role_session(&chosen, session)?).await? {
        Ok(principal) => principal,
        Err(_) => {
            return Err(ApiError::Forbidden(
                "the permission set's role is gone: pick another".into(),
            ));
        }
    };
    let account = chosen.account;
    Ok(actor::User {
        principal,
        account,
        method,
        headers,
        query,
        peer,
        mfa_age: session.mfa_age,
    })
}
