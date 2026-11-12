//! Who a request of the bucket and object API acts as. That API is shared:
//! the dashboard serves it to the operator, who may do anything (the peer
//! endpoint is theirs), and the console to a signed-in user, whom it allows
//! exactly what the user's S3 requests would be: each call is checked as its
//! S3 operation's actions, by the same policies (the user's grants, admin
//! flag and inline policies, and the bucket's), as `s3::access` decides them.

use std::net::IpAddr;
use std::sync::Arc;

use axum::http::{HeaderMap, Method};

use super::ApiError;
use crate::{
    App,
    policy::Verdict,
    roles::Principal,
    s3::{
        access::{Access, Origin},
        actions::{Check, On},
    },
};

/// Who a request acts as (a request extension, which each app's router
/// sets).
#[derive(Clone)]
pub(crate) enum Actor {
    /// The dashboard's operator: everything is allowed, whatever policies
    /// say, as an AWS account's root user may.
    Operator,
    /// A console user, under its policies.
    User(Arc<User>),
}

/// A console user, and what its request's condition keys are made of.
pub(crate) struct User {
    pub principal: Principal,
    pub account: String,
    pub method: Method,
    pub headers: HeaderMap,
    pub query: String,
    pub peer: Option<IpAddr>,
}

impl Actor {
    /// The user's ID, which the KMS knows it by (`None` for the operator,
    /// who has no identity in the KMS).
    pub fn kms_role(&self) -> Option<uuid::Uuid> {
        match self {
            Actor::Operator => None,
            Actor::User(user) => Some(user.principal.id),
        }
    }

    /// Whether `bucket` is listed to the actor, as ListBuckets lists it: to
    /// those allowed `s3:ListAllMyBuckets`, every bucket; else those of the
    /// user's grants.
    pub fn lists(&self, all: bool, bucket: &str) -> bool {
        match self {
            Actor::Operator => true,
            Actor::User(user) => all || user.principal.can_see(bucket),
        }
    }

    /// The verdicts on `checks`, with the buckets' policies loaded.
    async fn verdicts(&self, app: &Arc<App>, checks: &[Check]) -> Result<Vec<Verdict>, ApiError> {
        let Actor::User(user) = self else {
            return Ok(vec![Verdict::Allow; checks.len()]);
        };
        let origin = Origin { peer: user.peer, trusted_proxies: &app.trusted_proxies, signed: None, form: false };
        let mut access =
            Access::new(Some(&user.principal), &user.account, &user.method, &user.headers, &user.query, &origin)?;
        access.load_all(app, checks).await?;
        Ok(checks.iter().map(|c| access.verdict(c)).collect())
    }

    /// Whether `action` on `on` is allowed.
    pub async fn allows(&self, app: &Arc<App>, action: &'static str, on: On) -> Result<bool, ApiError> {
        Ok(self.verdicts(app, &[Check { action, on }]).await?[0] == Verdict::Allow)
    }

    /// Refuses the request (403, saying what was denied, and why, as S3
    /// does) unless `action` on `on` is allowed.
    pub async fn check(&self, app: &Arc<App>, action: &'static str, on: On) -> Result<(), ApiError> {
        self.check_all(app, &[Check { action, on }]).await
    }

    /// Refuses the request unless every one of `checks` is allowed.
    pub async fn check_all(&self, app: &Arc<App>, checks: &[Check]) -> Result<(), ApiError> {
        let verdicts = self.verdicts(app, checks).await?;
        let Actor::User(user) = self else { return Ok(()) };
        match checks.iter().zip(verdicts).find(|(_, v)| *v != Verdict::Allow) {
            None => Ok(()),
            Some((check, verdict)) => Err(ApiError::Forbidden(denied(user, check, verdict))),
        }
    }
}

/// What S3 says when `check` is denied to `user` (see `Access::denied`).
fn denied(user: &User, check: &Check, verdict: Verdict) -> String {
    let on = match &check.on {
        On::Account => String::new(),
        on => format!(" on resource: \"{}\"", on.arn()),
    };
    let why = match verdict {
        Verdict::ExplicitDeny { identity: true } => "with an explicit deny in an identity-based policy".to_owned(),
        Verdict::ExplicitDeny { identity: false } => "with an explicit deny in a resource-based policy".to_owned(),
        _ => format!("because no identity-based policy allows the {} action", check.action),
    };
    format!(
        "User: arn:aws:iam::{}:user/{} is not authorized to perform: {}{on} {why}",
        user.account, user.principal.name, check.action
    )
}
