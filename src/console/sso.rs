//! The console's API for Identity Center (see `identity_center`): the
//! account's permission sets, their policies and assignments, and the
//! directory users that have signed in. Every handler checks what it does as
//! Identity Center's action (`sso:CreatePermissionSet` on the set's ARN,
//! `sso:CreateAccountAssignment`, …; `identitystore:ListUsers` to list
//! directory users), as the session's identity.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::actor::Actor;
use super::manage::{AppState, AttachedPolicy, PolicyArn, PolicyDocument, Result};
use super::web::{ApiError, ErrorBody};
use crate::App;
use crate::identity_center::{self as ic, PermissionSet, PrincipalType};
use crate::s3::actions::On;

pub(super) fn router() -> OpenApiRouter<Arc<App>> {
    OpenApiRouter::new()
        .routes(routes!(list_permission_sets, create_permission_set))
        .routes(routes!(update_permission_set, delete_permission_set))
        .routes(routes!(get_inline_policy, put_inline_policy, delete_inline_policy))
        .routes(routes!(attach_managed_policy, detach_managed_policy))
        .routes(routes!(list_assignments, create_assignment))
        .routes(routes!(delete_assignment))
        .routes(routes!(list_directory_users))
}

/// The instance's ARN, which listing and assigning are checked on.
fn instance(actor: &Actor) -> On {
    On::Arn(ic::instance_arn(actor.account()))
}

/// The session's permission set `name`, allowed `action` on it.
async fn check_set(app: &Arc<App>, actor: &Actor, action: &'static str, name: &str) -> Result<PermissionSet> {
    let set = ic::load(&app.pool.get().await?, actor.account(), name)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("no permission set named {name:?}")))?;
    actor.check(app, action, On::Arn(set.arn())).await?;
    Ok(set)
}

/// A permission set: the policies directory users act with, as its role.
#[derive(Serialize, ToSchema)]
struct PermissionSetSummary {
    name: String,
    arn: String,
    description: String,
    /// How long its sessions (and credentials) last, in seconds.
    session_duration: i32,
    /// The role it's provisioned as (which IAM can't change).
    role_name: String,
    role_arn: String,
    /// Whether it has an inline policy.
    inline_policy: bool,
    /// Its managed policies.
    attached: Vec<AttachedPolicy>,
    /// Its assignments.
    assignments: i64,
    created_at: f64,
}

#[utoipa::path(get, path = "/permission-sets", responses(
    (status = 200, body = Vec<PermissionSetSummary>),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn list_permission_sets(State(app): AppState, Extension(actor): Extension<Actor>) -> Result<Json<Vec<PermissionSetSummary>>> {
    actor.check(&app, "sso:ListPermissionSets", instance(&actor)).await?;
    let client = app.pool.get().await?;
    let assignments = ic::assignments(&client, actor.account()).await?;
    let mut out = Vec::new();
    for set in ic::list(&client, actor.account()).await? {
        out.push(PermissionSetSummary {
            arn: set.arn(),
            role_arn: set.role_arn(),
            inline_policy: ic::inline_policy(&client, &set).await?.is_some(),
            attached: ic::managed_policies(&client, &set)
                .await?
                .into_iter()
                .map(|a| AttachedPolicy { name: a.name, arn: a.arn })
                .collect(),
            assignments: assignments.iter().filter(|a| a.permission_set == set.name).count() as i64,
            name: set.name,
            description: set.description,
            session_duration: set.session_duration,
            role_name: set.role_name,
            created_at: set.created,
        });
    }
    Ok(Json(out))
}

#[derive(Deserialize, ToSchema)]
struct NewPermissionSet {
    name: String,
    #[serde(default)]
    description: String,
    /// In seconds, from 3600 to 43200; 3600 if not given.
    session_duration: Option<i32>,
}

/// Makes a permission set, and its role.
#[utoipa::path(post, path = "/permission-sets", request_body = NewPermissionSet, responses(
    (status = 201, description = "Made"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_permission_set(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Json(body): Json<NewPermissionSet>,
) -> Result<StatusCode> {
    actor.check(&app, "sso:CreatePermissionSet", instance(&actor)).await?;
    let duration = body.session_duration.unwrap_or(ic::DEFAULT_SESSION);
    ic::create(&app.pool.get().await?, actor.account(), &body.name, &body.description, duration).await?;
    Ok(StatusCode::CREATED)
}

#[derive(Deserialize, ToSchema)]
struct PermissionSetChange {
    description: String,
    /// In seconds, from 3600 to 43200.
    session_duration: i32,
}

/// Changes a permission set's description and session duration.
#[utoipa::path(put, path = "/permission-sets/{name}", params(("name" = String, Path)), request_body = PermissionSetChange, responses(
    (status = 204, description = "Changed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn update_permission_set(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<PermissionSetChange>,
) -> Result<StatusCode> {
    let set = check_set(&app, &actor, "sso:UpdatePermissionSet", &name).await?;
    ic::update(&app.pool.get().await?, &set, &body.description, body.session_duration).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes a permission set: its assignments and its role go too.
#[utoipa::path(delete, path = "/permission-sets/{name}", params(("name" = String, Path)), responses(
    (status = 204, description = "Deleted"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_permission_set(State(app): AppState, Extension(actor): Extension<Actor>, Path(name): Path<String>) -> Result<StatusCode> {
    let set = check_set(&app, &actor, "sso:DeletePermissionSet", &name).await?;
    ic::delete(&app.pool.get().await?, &set).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// A permission set's inline policy.
#[utoipa::path(get, path = "/permission-sets/{name}/inline-policy", params(("name" = String, Path)), responses(
    (status = 200, body = PolicyDocument),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn get_inline_policy(State(app): AppState, Extension(actor): Extension<Actor>, Path(name): Path<String>) -> Result<Json<PolicyDocument>> {
    let set = check_set(&app, &actor, "sso:GetInlinePolicyForPermissionSet", &name).await?;
    let document = ic::inline_policy(&app.pool.get().await?, &set)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("{name} has no inline policy")))?;
    Ok(Json(PolicyDocument { document }))
}

/// Sets a permission set's inline policy.
#[utoipa::path(put, path = "/permission-sets/{name}/inline-policy", params(("name" = String, Path)), request_body = PolicyDocument, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn put_inline_policy(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<PolicyDocument>,
) -> Result<StatusCode> {
    let set = check_set(&app, &actor, "sso:PutInlinePolicyToPermissionSet", &name).await?;
    ic::set_inline_policy(&app.pool.get().await?, &set, Some(&body.document)).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Removes a permission set's inline policy.
#[utoipa::path(delete, path = "/permission-sets/{name}/inline-policy", params(("name" = String, Path)), responses(
    (status = 204, description = "Removed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_inline_policy(State(app): AppState, Extension(actor): Extension<Actor>, Path(name): Path<String>) -> Result<StatusCode> {
    let set = check_set(&app, &actor, "sso:DeleteInlinePolicyFromPermissionSet", &name).await?;
    ic::set_inline_policy(&app.pool.get().await?, &set, None).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Attaches a managed policy (AWS's, or the account's) to a permission set.
#[utoipa::path(post, path = "/permission-sets/{name}/attached", params(("name" = String, Path)), request_body = PolicyArn, responses(
    (status = 204, description = "Attached"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn attach_managed_policy(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<PolicyArn>,
) -> Result<StatusCode> {
    let set = check_set(&app, &actor, "sso:AttachManagedPolicyToPermissionSet", &name).await?;
    ic::attach(&app.pool.get().await?, &set, &body.arn, true).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Detaches a managed policy from a permission set.
#[utoipa::path(delete, path = "/permission-sets/{name}/attached", params(("name" = String, Path), PolicyArn), responses(
    (status = 204, description = "Detached"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn detach_managed_policy(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Query(query): Query<PolicyArn>,
) -> Result<StatusCode> {
    let set = check_set(&app, &actor, "sso:DetachManagedPolicyFromPermissionSet", &name).await?;
    ic::attach(&app.pool.get().await?, &set, &query.arn, false).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// A permission set's assignment to a directory user or group.
#[derive(Serialize, ToSchema)]
struct AssignmentSummary {
    id: String,
    permission_set: String,
    /// `USER` or `GROUP`.
    principal_type: String,
    /// The identity source.
    provider: String,
    /// A user's subject (`sub`), or a group's name in the group claim.
    principal_id: String,
    /// A user's name and e-mail, as it last signed in, if it has.
    user_name: Option<String>,
    user_email: Option<String>,
    created_at: f64,
}

#[utoipa::path(get, path = "/assignments", responses(
    (status = 200, body = Vec<AssignmentSummary>),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn list_assignments(State(app): AppState, Extension(actor): Extension<Actor>) -> Result<Json<Vec<AssignmentSummary>>> {
    actor.check(&app, "sso:ListAccountAssignments", instance(&actor)).await?;
    let assignments = ic::assignments(&app.pool.get().await?, actor.account()).await?;
    Ok(Json(
        assignments
            .into_iter()
            .map(|a| AssignmentSummary {
                id: a.id.to_string(),
                permission_set: a.permission_set,
                principal_type: a.principal_type.as_str().to_owned(),
                provider: a.provider,
                principal_id: a.principal_id,
                user_name: a.user.as_ref().map(|(name, _)| name.clone()),
                user_email: a.user.and_then(|(_, email)| email),
                created_at: a.created,
            })
            .collect(),
    ))
}

#[derive(Deserialize, ToSchema)]
struct NewAssignment {
    permission_set: String,
    /// `USER` or `GROUP`.
    principal_type: String,
    /// The identity source.
    provider: String,
    /// A user's subject (`sub`), or a group's name in the group claim.
    principal_id: String,
}

/// Assigns a permission set to a directory user or group.
#[utoipa::path(post, path = "/assignments", request_body = NewAssignment, responses(
    (status = 201, description = "Assigned"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_assignment(State(app): AppState, Extension(actor): Extension<Actor>, Json(body): Json<NewAssignment>) -> Result<StatusCode> {
    let Some(kind) = PrincipalType::parse(&body.principal_type) else {
        return Err(ApiError::BadRequest("principal_type is USER or GROUP".into()));
    };
    let set = check_set(&app, &actor, "sso:CreateAccountAssignment", &body.permission_set).await?;
    ic::assign(&app.pool.get().await?, &set, kind, &body.provider, body.principal_id.trim()).await?;
    Ok(StatusCode::CREATED)
}

/// Removes an assignment: the sessions it let in lose the permission set at
/// once.
#[utoipa::path(delete, path = "/assignments/{id}", params(("id" = String, Path)), responses(
    (status = 204, description = "Removed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_assignment(State(app): AppState, Extension(actor): Extension<Actor>, Path(id): Path<String>) -> Result<StatusCode> {
    let id = Uuid::parse_str(&id).map_err(|_| ApiError::NotFound("no such assignment".into()))?;
    let client = app.pool.get().await?;
    let assignment = ic::assignments(&client, actor.account())
        .await?
        .into_iter()
        .find(|a| a.id == id)
        .ok_or_else(|| ApiError::NotFound("no such assignment".into()))?;
    let set = ic::load(&client, actor.account(), &assignment.permission_set)
        .await?
        .ok_or_else(|| ApiError::NotFound("no such assignment".into()))?;
    actor.check(&app, "sso:DeleteAccountAssignment", On::Arn(set.arn())).await?;
    if !ic::unassign(&client, actor.account(), id).await? {
        return Err(ApiError::NotFound("no such assignment".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// A directory user, as it last signed in.
#[derive(Serialize, ToSchema)]
struct DirectoryUserSummary {
    provider: String,
    subject: String,
    name: String,
    email: Option<String>,
    groups: Vec<String>,
    first_signed_in: f64,
    last_signed_in: f64,
}

/// The directory users that have signed in, most recent first.
#[utoipa::path(get, path = "/directory-users", responses(
    (status = 200, body = Vec<DirectoryUserSummary>),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn list_directory_users(State(app): AppState, Extension(actor): Extension<Actor>) -> Result<Json<Vec<DirectoryUserSummary>>> {
    actor.check(&app, "identitystore:ListUsers", instance(&actor)).await?;
    let users = ic::directory_users(&app.pool.get().await?).await?;
    Ok(Json(
        users
            .into_iter()
            .map(|u| DirectoryUserSummary {
                provider: u.provider,
                subject: u.subject,
                name: u.name,
                email: u.email,
                groups: u.groups,
                first_signed_in: u.created,
                last_signed_in: u.last_signed_in,
            })
            .collect(),
    ))
}
