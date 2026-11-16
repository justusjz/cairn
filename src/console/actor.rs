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
    users::Principal,
    s3::{
        access::{Access, Origin},
        actions::{Check, On},
    },
};

/// Who a request acts as (a request extension, which `as_user` sets): a
/// console session's user, under the policies that apply to it.
#[derive(Clone)]
pub(crate) struct Actor(pub Arc<User>);

/// A console session's user, and what its request's condition keys are
/// made of.
pub(crate) struct User {
    pub principal: Principal,
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
        self.principal.arn()
    }
}

impl Actor {
    /// The user's ID, which the KMS knows it by.
    pub fn kms_role(&self) -> Option<uuid::Uuid> {
        Some(self.0.principal.id)
    }

    /// The account the session acts in (its ID).
    pub fn account(&self) -> &str {
        &self.0.account
    }

    /// Which of `buckets` (name, owning account) are listed to the actor, as
    /// ListBuckets lists them: to those allowed `s3:ListAllMyBuckets`, their
    /// account's; else those whose policies name the user.
    pub async fn listed(&self, app: &Arc<App>, buckets: &[(&str, &str)]) -> Result<Vec<bool>, ApiError> {
        let user = &self.0;
        if self.allows(app, "s3:ListAllMyBuckets", On::Account).await? {
            return Ok(buckets.iter().map(|(_, account)| *account == user.account).collect());
        }
        let principal = &user.principal;
        let mut visible = crate::grants::visible(&app.pool.get().await?, principal.id).await?;
        let own: Vec<&str> = buckets.iter().filter(|(_, account)| *account == user.account).map(|(name, _)| *name).collect();
        visible.extend(crate::s3::access::listable(principal, &own)?);
        Ok(buckets.iter().map(|(name, _)| visible.contains(*name)).collect())
    }

    /// The verdicts on `checks`, with the buckets' policies loaded.
    async fn verdicts(&self, app: &Arc<App>, checks: &[Check]) -> Result<Vec<Verdict>, ApiError> {
        let access = self.access(app, checks).await?;
        Ok(checks.iter().map(|c| if on_directory(c) { Verdict::ImplicitDeny } else { access.verdict(c) }).collect())
    }

    /// The actor's access, with the buckets of `checks` loaded.
    async fn access(&self, app: &Arc<App>, checks: &[Check]) -> Result<Access, ApiError> {
        let user = &self.0;
        let origin = Origin { peer: user.peer, trusted_proxies: &app.trusted_proxies, signed: None, form: false };
        let mut access = Access::new(Some(&user.principal), &user.account, &user.method, &user.headers, &user.query, &origin)?;
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

    /// The actor's access, for checks a module of its own makes (see
    /// `console::sns`).
    pub async fn access_for(&self, app: &Arc<App>) -> Result<Access, ApiError> {
        self.access(app, &[]).await
    }

    /// Its principal.
    pub fn principal(&self) -> &crate::users::Principal {
        &self.0.principal
    }

    /// Whether each of `checks`, with its condition keys (a resource's tags,
    /// say: see `Access::verdict_with`), is allowed.
    pub async fn allows_each(&self, app: &Arc<App>, checks: &[(Check, Context)]) -> Result<Vec<bool>, ApiError> {
        let plain: Vec<Check> = checks.iter().map(|(c, _)| c.clone()).collect();
        let access = self.access(app, &plain).await?;
        Ok(checks.iter().map(|(c, extra)| !on_directory(c) && access.verdict_with(c, extra) == Verdict::Allow).collect())
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
        refuse_directory(std::slice::from_ref(&check))?;
        let access = self.access(app, std::slice::from_ref(&check)).await?;
        match access.verdict_with(&check, extra) {
            Verdict::Allow => Ok(()),
            verdict => Err(ApiError::Forbidden(denied(&self.0, &check, verdict, access.boundary()))),
        }
    }

    /// Refuses the request unless every one of `checks` is allowed.
    /// A bucket's policy is its account's alone (see `Access::foreign`).
    pub async fn check_all(&self, app: &Arc<App>, checks: &[Check]) -> Result<(), ApiError> {
        refuse_directory(checks)?;
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

/// Whether `check` is on a directory bucket (see `s3::directory`), which
/// the console doesn't manage: what it does to buckets (versioning, tags,
/// Object Lock, ...) a directory bucket can't have, and its own operations
/// are S3 Express's, which only the S3 API has.
fn on_directory(check: &Check) -> bool {
    check.on.bucket().is_some_and(crate::s3::directory::is_directory)
}

/// Refuses `checks` if any is on a directory bucket (see `on_directory`).
fn refuse_directory(checks: &[Check]) -> Result<(), ApiError> {
    match checks.iter().find(|c| on_directory(c)) {
        Some(check) => Err(ApiError::Forbidden(format!(
            "{} is a directory bucket, which the console doesn't manage: use the S3 API",
            check.on.bucket().unwrap_or_default()
        ))),
        None => Ok(()),
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
