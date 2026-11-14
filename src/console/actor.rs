//! Who a request of the console's API (`manage`) acts as: its session's
//! identity, whom it allows exactly what the identity's S3 and IAM requests
//! would be: each call is checked as its operation's actions, by the same
//! policies (the user's grants, admin flag and inline policies, and the
//! bucket's), as `s3::access` decides them. The cluster's own calls are
//! checked as Cairn's actions (`cairn:`), which operators' policies allow
//! (see `plans/single-account.md`).
//!
//! A session signed in with a passkey has `aws:MultiFactorAuthPresent` (and
//! `aws:MultiFactorAuthAge`, since it was); one signed in at an OIDC
//! provider has it `false`, as AWS's federated sessions without MFA.

use std::net::IpAddr;
use std::sync::Arc;

use axum::http::{HeaderMap, Method};

use super::web::ApiError;
use crate::{
    App,
    policy::{Context, Verdict},
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
    /// Seconds since the session was signed in with a passkey; `None`:
    /// it was signed in at an OIDC provider.
    pub mfa_age: Option<i64>,
}

impl User {
    /// Its ARN.
    fn arn(&self) -> String {
        match &self.subject {
            Subject::User(principal) => principal.arn(),
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
        let mut visible = crate::grants::visible(&app.pool.get().await?, principal.id).await?;
        let own: Vec<&str> = buckets.iter().filter(|(_, account)| *account == user.account).map(|(name, _)| *name).collect();
        visible.extend(crate::s3::access::listable(principal, &own)?);
        Ok(buckets.iter().map(|(name, _)| visible.contains(*name)).collect())
    }

    /// The verdicts on `checks`, with the buckets' policies loaded.
    async fn verdicts(&self, app: &Arc<App>, checks: &[Check]) -> Result<Vec<Verdict>, ApiError> {
        let access = self.access(app, checks).await?;
        Ok(checks.iter().map(|c| access.verdict(c)).collect())
    }

    /// The actor's access, with the buckets of `checks` loaded.
    async fn access(&self, app: &Arc<App>, checks: &[Check]) -> Result<Access, ApiError> {
        let user = &self.0;
        let origin = Origin { peer: user.peer, trusted_proxies: &app.trusted_proxies, signed: None, form: false };
        let mut access = match &user.subject {
            Subject::User(principal) => {
                Access::new(Some(principal), &user.account, &user.method, &user.headers, &user.query, &origin)?
            }
            Subject::Root => Access::root(&user.account, &user.method, &user.headers, &user.query, &origin),
        };
        match user.mfa_age {
            Some(age) => {
                access.context.set("aws:MultiFactorAuthPresent", "true");
                access.context.set("aws:MultiFactorAuthAge", age.to_string());
            }
            None => access.context.set("aws:MultiFactorAuthPresent", "false"),
        }
        access.load_all(app, checks).await?;
        Ok(access)
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

    /// As `check`, with the condition keys `extra` too (a user's tags, an
    /// IAM request's: see `Access::verdict_with`).
    pub async fn check_with(&self, app: &Arc<App>, action: &'static str, on: On, extra: &Context) -> Result<(), ApiError> {
        let check = Check { action, on };
        let access = self.access(app, std::slice::from_ref(&check)).await?;
        match access.verdict_with(&check, extra) {
            Verdict::Allow => Ok(()),
            verdict => Err(ApiError::Forbidden(denied(&self.0, &check, verdict, access.boundary()))),
        }
    }

    /// Refuses the request unless every one of `checks` is allowed.
    /// A bucket's policy is its account's alone (see `Access::foreign`).
    pub async fn check_all(&self, app: &Arc<App>, checks: &[Check]) -> Result<(), ApiError> {
        let access = self.access(app, checks).await?;
        if let Some((check, verdict)) = checks.iter().map(|c| (c, access.verdict(c))).find(|(_, v)| *v != Verdict::Allow) {
            return Err(ApiError::Forbidden(denied(&self.0, check, verdict, access.boundary())));
        }
        if let Some(check) = checks.iter().find(|c| access.foreign(c)) {
            return Err(ApiError::Forbidden(format!(
                "only the bucket's own account may {} (its policy's)",
                check.action
            )));
        }
        Ok(())
    }
}

/// What S3 says when `check` is denied to `user` (see `Access::denied`).
fn denied(user: &User, check: &Check, verdict: Verdict, boundary: Option<&str>) -> String {
    let on = match &check.on {
        On::Account => String::new(),
        on => format!(" on resource: \"{}\"", on.arn()),
    };
    let why = verdict.why(check.action, boundary);
    format!("User: {} is not authorized to perform: {}{on} {why}", user.arn(), check.action)
}
