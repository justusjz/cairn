//! Who a request of the console's API (`manage`) acts as: its session's
//! identity, whom it allows exactly what the identity's S3 and IAM requests
//! would be: each call is checked as its operation's actions, by the same
//! policies (the user's grants, admin flag and inline policies, and the
//! bucket's), as `s3::access` decides them. The cluster's own calls are
//! checked as the operator's actions (`cairn:`), which only the operator
//! account's identities may be allowed.

use std::net::IpAddr;
use std::sync::Arc;

use axum::http::{HeaderMap, Method};

use super::web::ApiError;
use crate::{
    App,
    policy::Verdict,
    roles::Principal,
    s3::{
        access::{Access, Origin},
        actions::{Check, On},
    },
};

/// Who a request acts as (a request extension, which `as_user` sets): a
/// console session's identity, a user or an account's root, under the
/// policies that apply to it.
#[derive(Clone)]
pub(crate) struct Actor(pub Arc<User>);

/// Who a console session acts as.
pub(crate) enum Subject {
    /// A user of an account, under its policies.
    User(Principal),
    /// An account's root (see `policy::root_verdict`).
    Root,
}

/// A console session's identity, and what its request's condition keys are
/// made of.
pub(crate) struct User {
    pub subject: Subject,
    /// Its account.
    pub account: String,
    pub method: Method,
    pub headers: HeaderMap,
    pub query: String,
    pub peer: Option<IpAddr>,
}

impl User {
    /// Its ARN.
    fn arn(&self) -> String {
        match &self.subject {
            Subject::User(principal) => format!("arn:aws:iam::{}:user/{}", self.account, principal.name),
            Subject::Root => format!("arn:aws:iam::{}:root", self.account),
        }
    }
}

impl Actor {
    /// The user's ID, which the KMS knows it by (`None` for a root, which
    /// has no identity in the KMS).
    pub fn kms_role(&self) -> Option<uuid::Uuid> {
        match &self.0.subject {
            Subject::User(principal) => Some(principal.id),
            Subject::Root => None,
        }
    }

    /// The account the session acts in (its ID).
    pub fn account(&self) -> &str {
        &self.0.account
    }

    /// Which of `buckets` (name, owning account) are listed to the actor, as
    /// ListBuckets lists them: to those allowed `s3:ListAllMyBuckets` (and a
    /// root), their account's; else those whose policies name the user.
    pub async fn listed(&self, app: &Arc<App>, buckets: &[(&str, &str)]) -> Result<Vec<bool>, ApiError> {
        let user = &self.0;
        if self.allows(app, "s3:ListAllMyBuckets", On::Account).await? {
            return Ok(buckets.iter().map(|(_, account)| *account == user.account).collect());
        }
        let Subject::User(principal) = &user.subject else { return Ok(vec![false; buckets.len()]) };
        let visible = crate::grants::visible(&app.pool.get().await?, principal.id).await?;
        Ok(buckets.iter().map(|(name, _)| visible.contains(*name)).collect())
    }

    /// The verdicts on `checks`, with the buckets' policies loaded.
    async fn verdicts(&self, app: &Arc<App>, checks: &[Check]) -> Result<Vec<Verdict>, ApiError> {
        let user = &self.0;
        let origin = Origin { peer: user.peer, trusted_proxies: &app.trusted_proxies, signed: None, form: false };
        let mut access = match &user.subject {
            Subject::User(principal) => {
                Access::new(Some(principal), &user.account, &user.method, &user.headers, &user.query, &origin)?
            }
            Subject::Root => Access::root(&user.account, &user.method, &user.headers, &user.query, &origin),
        };
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
        match checks.iter().zip(verdicts).find(|(_, v)| *v != Verdict::Allow) {
            None => Ok(()),
            Some((check, verdict)) => Err(ApiError::Forbidden(denied(&self.0, check, verdict))),
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
    format!("User: {} is not authorized to perform: {}{on} {why}", user.arn(), check.action)
}
