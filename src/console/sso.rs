//! The console's API for Identity Center (see `identity_center`): the
//! account's permission sets, their policies and assignments, and the
//! identity store's users and groups (who has signed in, and the groups
//! their claims named). Every handler checks what it does as Identity
//! Center's action, on the resource sso-admin's and identitystore's would
//! (`sso:CreatePermissionSet` on the instance, `sso:CreateAccountAssignment`
//! on the permission set, `identitystore:ListUsers` on the identity store,
//! …), as the session's identity.

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
        .routes(routes!(put_permission_set_boundary, delete_permission_set_boundary))
        .routes(routes!(list_assignments, create_assignment))
        .routes(routes!(delete_assignment))
        .routes(routes!(list_directory_users))
        .routes(routes!(list_directory_groups))
}

/// The instance's ARN, which making permission sets is checked on.
fn instance(actor: &Actor) -> On {
    On::Arn(ic::instance_arn(actor.account()))
}

/// The identity store's ARN, which listing its users and groups is checked
/// on.
fn store(actor: &Actor) -> On {
    On::Arn(ic::identity_store_arn(actor.account()))
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
    /// Its managed policies: AWS's (Cairn's), and the account's (customer
    /// managed).
    attached: Vec<AttachedPolicy>,
    /// Its permissions boundary's ARN, if it has one.
    boundary: Option<String>,
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
    let assignments = ic::assignments(&client, actor.account(), None, None, None).await?;
    let mut out = Vec::new();
    for set in ic::list(&client, actor.account()).await? {
        let role = set.role(&client).await?;
        out.push(PermissionSetSummary {
            arn: set.arn(),
            role_arn: set.role_arn(),
            inline_policy: ic::inline_policy(&client, &set).await?.is_some(),
            attached: ic::managed_policies(&client, &set)
                .await?
                .into_iter()
                .map(|a| AttachedPolicy { name: a.name, arn: a.arn })
                .collect(),
            boundary: role.boundary,
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
    let new = ic::New {
        name: &body.name,
        description: &body.description,
        session_duration: body.session_duration.unwrap_or(ic::DEFAULT_SESSION),
        relay_state: None,
        tags: None,
    };
    ic::create(&app.pool.get().await?, actor.account(), &new).await?;
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
    let change = ic::Change { description: Some(&body.description), session_duration: Some(body.session_duration), relay_state: None };
    ic::update(&app.pool.get().await?, &set, &change).await?;
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

/// The action that attaches or detaches a managed policy: AWS's, or a
/// customer managed policy reference (the account's).
fn attach_action(arn: &str, attach: bool) -> &'static str {
    match (ic::is_aws(arn), attach) {
        (true, true) => "sso:AttachManagedPolicyToPermissionSet",
        (true, false) => "sso:DetachManagedPolicyFromPermissionSet",
        (false, true) => "sso:AttachCustomerManagedPolicyReferenceToPermissionSet",
        (false, false) => "sso:DetachCustomerManagedPolicyReferenceFromPermissionSet",
    }
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
    let set = check_set(&app, &actor, attach_action(&body.arn, true), &name).await?;
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
    let set = check_set(&app, &actor, attach_action(&query.arn, false), &name).await?;
    ic::attach(&app.pool.get().await?, &set, &query.arn, false).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Sets a permission set's permissions boundary: a managed policy (AWS's,
/// or the account's).
#[utoipa::path(put, path = "/permission-sets/{name}/boundary", params(("name" = String, Path)), request_body = PolicyArn, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn put_permission_set_boundary(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<PolicyArn>,
) -> Result<StatusCode> {
    let set = check_set(&app, &actor, "sso:PutPermissionsBoundaryToPermissionSet", &name).await?;
    ic::set_boundary(&app.pool.get().await?, &set, Some(&body.arn)).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Removes a permission set's permissions boundary.
#[utoipa::path(delete, path = "/permission-sets/{name}/boundary", params(("name" = String, Path)), responses(
    (status = 204, description = "Removed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_permission_set_boundary(State(app): AppState, Extension(actor): Extension<Actor>, Path(name): Path<String>) -> Result<StatusCode> {
    let set = check_set(&app, &actor, "sso:DeletePermissionsBoundaryFromPermissionSet", &name).await?;
    ic::set_boundary(&app.pool.get().await?, &set, None).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// A permission set's assignment to a directory user or group, in an
/// account.
#[derive(Serialize, ToSchema)]
struct AssignmentSummary {
    id: String,
    /// The account it gives the permission set in, by ID.
    account_id: String,
    permission_set: String,
    /// `USER` or `GROUP`.
    principal_type: String,
    /// The user's or group's ID in the identity store.
    principal_id: String,
    /// A user's user name, or a group's name.
    principal_name: String,
    /// Its identity source.
    provider: String,
    /// A user's e-mail.
    email: Option<String>,
    created_at: f64,
}

#[utoipa::path(get, path = "/assignments", responses(
    (status = 200, body = Vec<AssignmentSummary>),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn list_assignments(State(app): AppState, Extension(actor): Extension<Actor>) -> Result<Json<Vec<AssignmentSummary>>> {
    actor.check(&app, "sso:ListAccountAssignments", instance(&actor)).await?;
    let assignments = ic::assignments(&app.pool.get().await?, actor.account(), None, None, None).await?;
    Ok(Json(
        assignments
            .into_iter()
            .map(|a| AssignmentSummary {
                id: a.id.to_string(),
                account_id: a.account,
                permission_set: a.permission_set,
                principal_type: a.principal_type.as_str().to_owned(),
                principal_id: a.principal_id.to_string(),
                principal_name: a.principal_name,
                provider: a.provider,
                email: a.email,
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
    /// The user's or group's ID in the identity store.
    principal_id: String,
    /// The account to give it in, by ID: the instance's own, if not given
    /// (the only one so far).
    account_id: Option<String>,
}

/// Assigns a permission set to a directory user or group, in an account.
#[utoipa::path(post, path = "/assignments", request_body = NewAssignment, responses(
    (status = 201, description = "Assigned"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_assignment(State(app): AppState, Extension(actor): Extension<Actor>, Json(body): Json<NewAssignment>) -> Result<StatusCode> {
    let Some(kind) = PrincipalType::parse(&body.principal_type) else {
        return Err(ApiError::BadRequest("principal_type is USER or GROUP".into()));
    };
    let principal = Uuid::parse_str(&body.principal_id)
        .map_err(|_| ApiError::NotFound(format!("there's no {} {} in the identity store", kind.as_str().to_lowercase(), body.principal_id)))?;
    let set = check_set(&app, &actor, "sso:CreateAccountAssignment", &body.permission_set).await?;
    let account = body.account_id.as_deref().unwrap_or(actor.account());
    ic::assign(&app.pool.get().await?, &set, account, kind, principal).await?;
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
    let missing = || ApiError::NotFound("no such assignment".into());
    let id = Uuid::parse_str(&id).map_err(|_| missing())?;
    let client = app.pool.get().await?;
    let assignment = ic::assignments(&client, actor.account(), None, None, None)
        .await?
        .into_iter()
        .find(|a| a.id == id)
        .ok_or_else(missing)?;
    let set = check_set(&app, &actor, "sso:DeleteAccountAssignment", &assignment.permission_set).await?;
    if !ic::unassign(&client, &set, &assignment.account, assignment.principal_type, assignment.principal_id).await? {
        return Err(missing());
    }
    Ok(StatusCode::NO_CONTENT)
}

/// A directory user, as it last signed in.
#[derive(Serialize, ToSchema)]
struct DirectoryUserSummary {
    /// Its ID in the identity store.
    id: String,
    user_name: String,
    display_name: String,
    email: Option<String>,
    /// Its identity source, and its subject there.
    provider: String,
    subject: String,
    /// Its groups, by name, as its last sign-in said.
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
    actor.check(&app, "identitystore:ListUsers", store(&actor)).await?;
    let client = app.pool.get().await?;
    let groups = ic::groups(&client, None).await?;
    let memberships = ic::memberships(&client, None, None).await?;
    let mut users = ic::users(&client, None).await?;
    users.sort_by(|a, b| b.updated.total_cmp(&a.updated));
    Ok(Json(
        users
            .into_iter()
            .map(|u| {
                let mut names: Vec<String> = memberships
                    .iter()
                    .filter(|m| m.user_id == u.id)
                    .filter_map(|m| groups.iter().find(|g| g.id == m.group_id).map(|g| g.name.clone()))
                    .collect();
                names.sort();
                DirectoryUserSummary {
                    id: u.id.to_string(),
                    user_name: u.user_name,
                    display_name: u.display_name,
                    email: u.email,
                    provider: u.provider,
                    subject: u.subject,
                    groups: names,
                    first_signed_in: u.created,
                    last_signed_in: u.updated,
                }
            })
            .collect(),
    ))
}

/// A group, as its users' group claims named it.
#[derive(Serialize, ToSchema)]
struct DirectoryGroupSummary {
    /// Its ID in the identity store.
    id: String,
    name: String,
    provider: String,
    /// How many users it had, as their last sign-ins said.
    members: i64,
}

/// The identity store's groups.
#[utoipa::path(get, path = "/directory-groups", responses(
    (status = 200, body = Vec<DirectoryGroupSummary>),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn list_directory_groups(State(app): AppState, Extension(actor): Extension<Actor>) -> Result<Json<Vec<DirectoryGroupSummary>>> {
    actor.check(&app, "identitystore:ListGroups", store(&actor)).await?;
    let client = app.pool.get().await?;
    let memberships = ic::memberships(&client, None, None).await?;
    Ok(Json(
        ic::groups(&client, None)
            .await?
            .into_iter()
            .map(|g| DirectoryGroupSummary {
                members: memberships.iter().filter(|m| m.group_id == g.id).count() as i64,
                id: g.id.to_string(),
                name: g.name,
                provider: g.provider,
            })
            .collect(),
    ))
}
