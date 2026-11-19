//! The console's API for the organization (see `organizations`): its
//! accounts, making member accounts and closing them, its structure (the
//! root, organizational units, where each account is) and its service
//! control policies. The management account's only, as Organizations' API
//! is, and checked as its actions (`organizations:ListAccounts` on the
//! organization, …), as the session's identity; the structure's as the API
//! checks them, on the organization.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::actor::Actor;
use super::manage::{AppState, Result};
use super::web::{ApiError, ErrorBody};
use crate::App;
use crate::organizations as org;
use crate::s3::actions::On;

pub(super) fn router() -> OpenApiRouter<Arc<App>> {
    OpenApiRouter::new()
        .routes(routes!(list_accounts, create_account))
        .routes(routes!(close_account))
        .routes(routes!(move_account))
        .routes(routes!(get_organization))
        .routes(routes!(enable_scps, disable_scps))
        .routes(routes!(create_unit))
        .routes(routes!(rename_unit, delete_unit))
        .routes(routes!(create_scp))
        .routes(routes!(get_scp, update_scp, delete_scp))
        .routes(routes!(attach_scp))
        .routes(routes!(detach_scp))
}

/// The management account, if the session is in it; else why not.
async fn management(app: &Arc<App>, actor: &Actor) -> Result<String> {
    let management = crate::users::account(&app.pool.get().await?).await?;
    if actor.account() != management {
        return Err(ApiError::Forbidden(
            "the organization is its management account's".into(),
        ));
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
    /// The organizational unit it's in; none for the root.
    parent_id: Option<String>,
}

#[utoipa::path(get, path = "/accounts", responses(
    (status = 200, body = Vec<AccountSummary>),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn list_accounts(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
) -> Result<Json<Vec<AccountSummary>>> {
    let management = management(&app, &actor).await?;
    actor
        .check(
            &app,
            "organizations:ListAccounts",
            On::Arn(org::organization_arn(&management)),
        )
        .await?;
    let client = app.pool.get().await?;
    let mut out = Vec::new();
    for account in org::list(&client).await? {
        let buckets: i64 = {
            use crate::db::Cached as _;
            client
                .query_one_cached(
                    "SELECT count(*) FROM buckets WHERE account_id = $1",
                    &[&account.id],
                )
                .await?
                .get(0)
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
            parent_id: account.parent,
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
    actor
        .check(
            &app,
            "organizations:CreateAccount",
            On::Arn(org::organization_arn(&management)),
        )
        .await?;
    let status = org::create(
        &app.pool.get().await?,
        &management,
        &body.name,
        &body.email,
        org::ACCESS_ROLE,
    )
    .await?;
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
async fn close_account(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    let management = management(&app, &actor).await?;
    actor
        .check(
            &app,
            "organizations:CloseAccount",
            On::Arn(org::account_arn(&management, &id)),
        )
        .await?;
    org::close(&app.pool.get().await?, &management, &id)
        .await
        .map_err(|e| ApiError::BadRequest(e.message().to_owned()))?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── The structure and SCPs ──────────────────────────────────────────────────

/// Answers Organizations' `operation` of the structure (see
/// `organizations::structure`), as `input` asks, if the session is in the
/// management account and allowed `action` on the organization, as the API
/// checks it.
async fn structure(
    app: &Arc<App>,
    actor: &Actor,
    action: &'static str,
    operation: &str,
    input: Value,
) -> Result<Value> {
    let management = management(app, actor).await?;
    actor
        .check(app, action, On::Arn(org::organization_arn(&management)))
        .await?;
    let client = app.pool.get().await?;
    let input = org::structure::Input {
        client: &client,
        management: &management,
        input: &input,
    };
    org::structure::answer(operation, &input)
        .await
        .map_err(|e| ApiError::BadRequest(e.message().to_owned()))
}

/// The organization's structure and its SCPs.
#[derive(Serialize, ToSchema)]
struct OrganizationOverview {
    /// The root's ID (`r-…`), which units and accounts are under.
    root_id: String,
    /// Whether service control policies are enabled.
    scps_enabled: bool,
    units: Vec<UnitSummary>,
    /// FullAWSAccess first.
    policies: Vec<ScpSummary>,
    /// Which SCPs each target (the root, a unit, an account) has.
    attachments: Vec<ScpAttachment>,
}

/// An organizational unit.
#[derive(Serialize, ToSchema)]
struct UnitSummary {
    id: String,
    name: String,
    /// Its parent unit; none for the root.
    parent_id: Option<String>,
}

/// A service control policy.
#[derive(Serialize, ToSchema)]
struct ScpSummary {
    id: String,
    name: String,
    description: String,
    /// AWS's FullAWSAccess, which can't be changed or deleted.
    aws_managed: bool,
}

/// An SCP attached to a target.
#[derive(Serialize, ToSchema)]
struct ScpAttachment {
    target_id: String,
    policy_id: String,
}

#[utoipa::path(get, path = "/organization", responses(
    (status = 200, body = OrganizationOverview),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn get_organization(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
) -> Result<Json<OrganizationOverview>> {
    let management = management(&app, &actor).await?;
    let organization = On::Arn(org::organization_arn(&management));
    actor
        .check(
            &app,
            "organizations:ListOrganizationalUnitsForParent",
            organization.clone(),
        )
        .await?;
    actor
        .check(&app, "organizations:ListPolicies", organization)
        .await?;
    let overview = org::structure::overview(&app.pool.get().await?, &management).await?;
    Ok(Json(OrganizationOverview {
        root_id: overview.root_id,
        scps_enabled: overview.scps_enabled,
        units: overview
            .units
            .into_iter()
            .map(|u| UnitSummary {
                id: u.id,
                name: u.name,
                parent_id: u.parent,
            })
            .collect(),
        policies: overview
            .policies
            .into_iter()
            .map(|p| ScpSummary {
                id: p.id,
                name: p.name,
                description: p.description,
                aws_managed: p.aws_managed,
            })
            .collect(),
        attachments: overview
            .attachments
            .into_iter()
            .map(|(target_id, policy_id)| ScpAttachment {
                target_id,
                policy_id,
            })
            .collect(),
    }))
}

/// Enables service control policies: FullAWSAccess is attached to the
/// root, every unit and every account.
#[utoipa::path(put, path = "/organization/scps", responses(
    (status = 204, description = "Enabled"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn enable_scps(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
) -> Result<StatusCode> {
    let root = org::structure::root_id(&management(&app, &actor).await?);
    let input = json!({ "RootId": root, "PolicyType": org::structure::SCP });
    structure(
        &app,
        &actor,
        "organizations:EnablePolicyType",
        "EnablePolicyType",
        input,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Disables service control policies: every SCP is detached.
#[utoipa::path(delete, path = "/organization/scps", responses(
    (status = 204, description = "Disabled"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn disable_scps(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
) -> Result<StatusCode> {
    let root = org::structure::root_id(&management(&app, &actor).await?);
    let input = json!({ "RootId": root, "PolicyType": org::structure::SCP });
    structure(
        &app,
        &actor,
        "organizations:DisablePolicyType",
        "DisablePolicyType",
        input,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct NewUnit {
    /// 1 to 128 characters.
    name: String,
    /// The root's or a unit's ID.
    parent_id: String,
}

/// The ID of a new unit.
#[derive(Serialize, ToSchema)]
struct NewUnitId {
    id: String,
}

/// Makes an organizational unit, in the root or another unit (five deep at
/// most).
#[utoipa::path(post, path = "/organization/units", request_body = NewUnit, responses(
    (status = 201, body = NewUnitId),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_unit(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Json(body): Json<NewUnit>,
) -> Result<(StatusCode, Json<NewUnitId>)> {
    let input = json!({ "Name": body.name.trim(), "ParentId": body.parent_id });
    let made = structure(
        &app,
        &actor,
        "organizations:CreateOrganizationalUnit",
        "CreateOrganizationalUnit",
        input,
    )
    .await?;
    let id = made["OrganizationalUnit"]["Id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    Ok((StatusCode::CREATED, Json(NewUnitId { id })))
}

#[derive(Deserialize, ToSchema)]
struct UnitName {
    name: String,
}

/// Renames an organizational unit.
#[utoipa::path(put, path = "/organization/units/{id}", params(("id" = String, Path)), request_body = UnitName, responses(
    (status = 204, description = "Renamed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn rename_unit(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
    Json(body): Json<UnitName>,
) -> Result<StatusCode> {
    let input = json!({ "OrganizationalUnitId": id, "Name": body.name.trim() });
    structure(
        &app,
        &actor,
        "organizations:UpdateOrganizationalUnit",
        "UpdateOrganizationalUnit",
        input,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes an organizational unit, which must be empty.
#[utoipa::path(delete, path = "/organization/units/{id}", params(("id" = String, Path)), responses(
    (status = 204, description = "Deleted"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_unit(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    let input = json!({ "OrganizationalUnitId": id });
    structure(
        &app,
        &actor,
        "organizations:DeleteOrganizationalUnit",
        "DeleteOrganizationalUnit",
        input,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct AccountParent {
    /// The root's or a unit's ID.
    parent_id: String,
}

/// Moves an account to the root or a unit.
#[utoipa::path(put, path = "/accounts/{id}/parent", params(("id" = String, Path)), request_body = AccountParent, responses(
    (status = 204, description = "Moved"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn move_account(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
    Json(body): Json<AccountParent>,
) -> Result<StatusCode> {
    let management = management(&app, &actor).await?;
    let account = org::load(&app.pool.get().await?, &id)
        .await?
        .filter(|a| a.closed.is_none())
        .ok_or_else(|| ApiError::NotFound(format!("there's no open account {id}")))?;
    let source = account
        .parent
        .unwrap_or_else(|| org::structure::root_id(&management));
    let input =
        json!({ "AccountId": id, "SourceParentId": source, "DestinationParentId": body.parent_id });
    structure(
        &app,
        &actor,
        "organizations:MoveAccount",
        "MoveAccount",
        input,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// An SCP, as it's made or changed.
#[derive(Deserialize, ToSchema)]
struct ScpChange {
    /// 1 to 128 characters.
    name: String,
    /// At most 512 characters.
    #[serde(default)]
    description: String,
    /// The policy's JSON, at most 10,240 characters; an Allow statement's
    /// resource is `*` only.
    content: String,
}

/// The ID of a new SCP.
#[derive(Serialize, ToSchema)]
struct NewScpId {
    id: String,
}

/// Makes a service control policy (attached nowhere yet).
#[utoipa::path(post, path = "/organization/policies", request_body = ScpChange, responses(
    (status = 201, body = NewScpId),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_scp(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Json(body): Json<ScpChange>,
) -> Result<(StatusCode, Json<NewScpId>)> {
    let input = json!({
        "Type": org::structure::SCP, "Name": body.name.trim(), "Description": body.description, "Content": body.content,
    });
    let made = structure(
        &app,
        &actor,
        "organizations:CreatePolicy",
        "CreatePolicy",
        input,
    )
    .await?;
    let id = made["Policy"]["PolicySummary"]["Id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    Ok((StatusCode::CREATED, Json(NewScpId { id })))
}

/// An SCP's document.
#[derive(Serialize, ToSchema)]
struct ScpContent {
    content: String,
}

/// A service control policy's document.
#[utoipa::path(get, path = "/organization/policies/{id}", params(("id" = String, Path)), responses(
    (status = 200, body = ScpContent),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn get_scp(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
) -> Result<Json<ScpContent>> {
    let found = structure(
        &app,
        &actor,
        "organizations:DescribePolicy",
        "DescribePolicy",
        json!({ "PolicyId": id }),
    )
    .await?;
    Ok(Json(ScpContent {
        content: found["Policy"]["Content"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    }))
}

/// Changes a service control policy: at once, wherever it's attached.
#[utoipa::path(put, path = "/organization/policies/{id}", params(("id" = String, Path)), request_body = ScpChange, responses(
    (status = 204, description = "Changed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn update_scp(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
    Json(body): Json<ScpChange>,
) -> Result<StatusCode> {
    let input = json!({ "PolicyId": id, "Name": body.name.trim(), "Description": body.description, "Content": body.content });
    structure(
        &app,
        &actor,
        "organizations:UpdatePolicy",
        "UpdatePolicy",
        input,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes a service control policy, which must be attached nowhere.
#[utoipa::path(delete, path = "/organization/policies/{id}", params(("id" = String, Path)), responses(
    (status = 204, description = "Deleted"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_scp(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    structure(
        &app,
        &actor,
        "organizations:DeletePolicy",
        "DeletePolicy",
        json!({ "PolicyId": id }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct ScpTarget {
    /// The root's, a unit's or an account's ID.
    target_id: String,
}

/// Attaches a service control policy to the root, a unit or an account.
#[utoipa::path(post, path = "/organization/policies/{id}/targets", params(("id" = String, Path)), request_body = ScpTarget, responses(
    (status = 204, description = "Attached"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn attach_scp(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
    Json(body): Json<ScpTarget>,
) -> Result<StatusCode> {
    let input = json!({ "PolicyId": id, "TargetId": body.target_id });
    structure(
        &app,
        &actor,
        "organizations:AttachPolicy",
        "AttachPolicy",
        input,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Detaches a service control policy from a target, which must keep one.
#[utoipa::path(delete, path = "/organization/policies/{id}/targets/{target}", params(("id" = String, Path), ("target" = String, Path)), responses(
    (status = 204, description = "Detached"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn detach_scp(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((id, target)): Path<(String, String)>,
) -> Result<StatusCode> {
    let input = json!({ "PolicyId": id, "TargetId": target });
    structure(
        &app,
        &actor,
        "organizations:DetachPolicy",
        "DetachPolicy",
        input,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
