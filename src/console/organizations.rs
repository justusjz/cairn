//! The console's API for the organization (see `organizations`): its
//! accounts, making member accounts and closing them. The management
//! account's only, as Organizations' API is, and checked as its actions
//! (`organizations:ListAccounts` on the organization, …), as the session's
//! identity.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::actor::Actor;
use super::manage::{AppState, Result};
use super::web::{ApiError, ErrorBody};
use crate::App;
use crate::organizations as org;
use crate::s3::actions::On;

pub(super) fn router() -> OpenApiRouter<Arc<App>> {
    OpenApiRouter::new().routes(routes!(list_accounts, create_account)).routes(routes!(close_account))
}

/// The management account, if the session is in it; else why not.
async fn management(app: &Arc<App>, actor: &Actor) -> Result<String> {
    let management = crate::users::account(&app.pool.get().await?).await?;
    if actor.account() != management {
        return Err(ApiError::Forbidden("the organization is its management account's".into()));
    }
    Ok(management)
}

/// An account of the organization.
#[derive(Serialize, ToSchema)]
struct AccountSummary {
    id: String,
    name: String,
    email: Option<String>,
    /// Whether it's the management account.
    management: bool,
    /// `ACTIVE`, or (closed) `SUSPENDED`.
    status: String,
    joined_at: f64,
    closed_at: Option<f64>,
    /// How many buckets it has (which keep it from being closed).
    buckets: i64,
}

#[utoipa::path(get, path = "/accounts", responses(
    (status = 200, body = Vec<AccountSummary>),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn list_accounts(State(app): AppState, Extension(actor): Extension<Actor>) -> Result<Json<Vec<AccountSummary>>> {
    let management = management(&app, &actor).await?;
    actor.check(&app, "organizations:ListAccounts", On::Arn(org::organization_arn(&management))).await?;
    let client = app.pool.get().await?;
    let mut out = Vec::new();
    for account in org::list(&client).await? {
        let buckets: i64 = {
            use crate::db::Cached as _;
            client.query_one_cached("SELECT count(*) FROM buckets WHERE account_id = $1", &[&account.id]).await?.get(0)
        };
        out.push(AccountSummary {
            status: account.status().to_owned(),
            id: account.id,
            name: account.name,
            email: account.email,
            management: account.management,
            joined_at: account.joined,
            closed_at: account.closed,
            buckets,
        });
    }
    Ok(Json(out))
}

#[derive(Deserialize, ToSchema)]
struct NewAccount {
    /// 1 to 50 printable characters.
    name: String,
    /// Unique among the organization's accounts.
    email: String,
}

/// A new account's ID.
#[derive(Serialize, ToSchema)]
struct NewAccountId {
    id: String,
    /// The role the management account's principals may assume into it.
    role_arn: String,
}

/// Makes a member account, with `OrganizationAccountAccessRole` (as
/// CreateAccount).
#[utoipa::path(post, path = "/accounts", request_body = NewAccount, responses(
    (status = 201, body = NewAccountId),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_account(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Json(body): Json<NewAccount>,
) -> Result<(StatusCode, Json<NewAccountId>)> {
    let management = management(&app, &actor).await?;
    actor.check(&app, "organizations:CreateAccount", On::Arn(org::organization_arn(&management))).await?;
    let status = org::create(&app.pool.get().await?, &management, &body.name, &body.email, org::ACCESS_ROLE).await?;
    match status.account_id {
        Some(id) => {
            let role_arn = format!("arn:aws:iam::{id}:role/{}", org::ACCESS_ROLE);
            Ok((StatusCode::CREATED, Json(NewAccountId { id, role_arn })))
        }
        None => Err(ApiError::Conflict(format!(
            "the account wasn't made: {}",
            status.failure.as_deref().unwrap_or("it failed")
        ))),
    }
}

/// Closes a member account, at once (it must have no buckets): its users,
/// roles and sessions are no one from then on.
#[utoipa::path(delete, path = "/accounts/{id}", params(("id" = String, Path)), responses(
    (status = 204, description = "Closed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn close_account(State(app): AppState, Extension(actor): Extension<Actor>, Path(id): Path<String>) -> Result<StatusCode> {
    let management = management(&app, &actor).await?;
    actor.check(&app, "organizations:CloseAccount", On::Arn(org::account_arn(&management, &id))).await?;
    org::close(&app.pool.get().await?, &management, &id).await.map_err(|e| ApiError::BadRequest(e.message().to_owned()))?;
    Ok(StatusCode::NO_CONTENT)
}
