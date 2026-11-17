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
use super::manage::{AppState, AttachedPolicy, EnrollmentLink, PolicyArn, PolicyDocument, Result};
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
        .routes(routes!(list_directory_users, create_directory_user))
        .routes(routes!(delete_directory_user))
        .routes(routes!(create_setup_link))
        .routes(routes!(delete_directory_passkeys))
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

/// Provisions `set`, just changed, to the accounts it's provisioned to, so
/// that saving it in the console takes effect there, if the session may
/// (`sso:ProvisionPermissionSet` on it); else their roles keep what they
/// hold, until it's provisioned. Saved, but not provisioned to one of them,
/// it answers why.
async fn reprovision(app: &Arc<App>, actor: &Actor, set: &PermissionSet) -> Result<StatusCode> {
    if !actor.allows(app, "sso:ProvisionPermissionSet", On::Arn(set.arn())).await? {
        return Ok(StatusCode::NO_CONTENT);
    }
    match ic::provision_all(&app.pool.get().await?, set).await? {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(why) => Err(ApiError::BadRequest(format!("saved, but not provisioned: {why}"))),
    }
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
    /// The name of its role in each account it's provisioned to (which IAM
    /// can't change).
    role_name: String,
    /// The accounts it's provisioned to (none until it's first assigned).
    provisioned: Vec<ProvisionSummary>,
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

/// A permission set's provisioning to an account.
#[derive(Serialize, ToSchema)]
struct ProvisionSummary {
    account_id: String,
    role_arn: String,
    /// Whether its role there holds the set as it is now.
    latest: bool,
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
        let provisioned = ic::provisions(&client, &set)
            .await?
            .into_iter()
            .map(|p| ProvisionSummary { role_arn: p.role_arn(), account_id: p.account, latest: p.latest })
            .collect();
        out.push(PermissionSetSummary {
            arn: set.arn(),
            role_name: set.role_name(),
            provisioned,
            inline_policy: ic::inline_policy(&client, &set).await?.is_some(),
            attached: ic::managed_policies(&client, &set)
                .await?
                .into_iter()
                .map(|a| AttachedPolicy { name: a.name, arn: a.arn })
                .collect(),
            boundary: ic::boundary(&client, &set).await?,
            assignments: assignments.iter().filter(|a| a.permission_set == set.name).count() as i64,
            name: set.name,
            description: set.description,
            session_duration: set.session_duration,
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
    reprovision(&app, &actor, &set).await
}

/// Deletes a permission set: its assignments and its roles go too.
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
    reprovision(&app, &actor, &set).await
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
    reprovision(&app, &actor, &set).await
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
    reprovision(&app, &actor, &set).await
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
    reprovision(&app, &actor, &set).await
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
    reprovision(&app, &actor, &set).await
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
    reprovision(&app, &actor, &set).await
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
    /// Its identity source; none for Cairn's own directory.
    provider: Option<String>,
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
    if let Err(why) = ic::assign(&app.pool.get().await?, &set, account, kind, principal).await? {
        return Err(ApiError::BadRequest(format!("{} can't be provisioned to {account}: {why}", set.name)));
    }
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
    /// Its identity source, and its subject there; none for a user of
    /// Cairn's own directory.
    provider: Option<String>,
    subject: Option<String>,
    /// Its groups, by name (a source's: as its last sign-in said).
    groups: Vec<String>,
    /// When it was first in the identity store, and when it last changed
    /// (a source's: signed in).
    first_signed_in: f64,
    last_signed_in: f64,
    /// A user of Cairn's own directory's passkeys, when it last signed in
    /// with one, and whether a setup link for it is out.
    passkeys: i64,
    last_passkey_use: Option<f64>,
    setup_link_pending: bool,
}

/// The identity store's users: Cairn's own directory's, and those of
/// identity sources that have signed in, most recent first.
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
    let access = crate::console::store::directory_access(&client).await?;
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
                let own = access.get(&u.id).cloned().unwrap_or_default();
                DirectoryUserSummary {
                    passkeys: own.passkeys,
                    last_passkey_use: own.last_sign_in,
                    setup_link_pending: own.link_pending,
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

#[derive(Deserialize, ToSchema)]
struct NewDirectoryUser {
    /// Its user name: 1 to 128 characters, no spaces.
    user_name: String,
    display_name: String,
    given_name: Option<String>,
    family_name: Option<String>,
    email: Option<String>,
}

/// The ID of a new directory user.
#[derive(Serialize, ToSchema)]
struct NewDirectoryUserId {
    id: String,
}

/// Makes a user of Cairn's own directory, as identitystore's CreateUser:
/// it signs in with passkeys, the first of which it makes with a setup
/// link.
#[utoipa::path(post, path = "/directory-users", request_body = NewDirectoryUser, responses(
    (status = 201, body = NewDirectoryUserId),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_directory_user(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Json(body): Json<NewDirectoryUser>,
) -> Result<(StatusCode, Json<NewDirectoryUserId>)> {
    actor.check(&app, "identitystore:CreateUser", store(&actor)).await?;
    let present = |text: &Option<String>| text.as_deref().map(str::trim).filter(|t| !t.is_empty()).map(str::to_owned);
    let mut name = serde_json::json!({ "Formatted": body.display_name });
    if let Some(given) = present(&body.given_name) {
        name["GivenName"] = given.into();
    }
    if let Some(family) = present(&body.family_name) {
        name["FamilyName"] = family.into();
    }
    let email = present(&body.email);
    let mut profile = serde_json::json!({ "Name": name });
    if let Some(email) = &email {
        profile["Emails"] = serde_json::json!([{ "Value": email, "Primary": true }]);
    }
    let new = ic::OwnUser { user_name: &body.user_name, display_name: &body.display_name, email: email.as_deref(), profile: &profile };
    let user = ic::create_user(&app.pool.get().await?, &new).await?;
    Ok((StatusCode::CREATED, Json(NewDirectoryUserId { id: user.id.to_string() })))
}

/// The directory user `id`, allowed `action` on it.
async fn check_user(app: &Arc<App>, actor: &Actor, action: &'static str, id: &str) -> Result<ic::User> {
    let missing = || ApiError::NotFound(format!("there's no directory user {id}"));
    let id = Uuid::parse_str(id).map_err(|_| missing())?;
    actor.check(app, action, On::Arn(ic::user_arn(id))).await?;
    ic::users(&app.pool.get().await?, Some(ic::Lookup::Id(id))).await?.pop().ok_or_else(missing)
}

/// Deletes a user of Cairn's own directory: its memberships, assignments,
/// passkeys and sessions go too.
#[utoipa::path(delete, path = "/directory-users/{id}", params(("id" = String, Path)), responses(
    (status = 204, description = "Deleted"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_directory_user(State(app): AppState, Extension(actor): Extension<Actor>, Path(id): Path<String>) -> Result<StatusCode> {
    let user = check_user(&app, &actor, "identitystore:DeleteUser", &id).await?;
    ic::delete_user(&app.pool.get().await?, &user, None).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Makes a user of Cairn's own directory a setup link, valid 7 days, to
/// make a passkey with (its first, or another): Cairn's way of Identity
/// Center's one-time password. It replaces the user's last link. Checked as
/// `identitystore:UpdateUser`, as a change of how the user signs in.
#[utoipa::path(post, path = "/directory-users/{id}/setup-link", params(("id" = String, Path)), responses(
    (status = 201, body = EnrollmentLink),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_setup_link(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<EnrollmentLink>)> {
    let user = check_user(&app, &actor, "identitystore:UpdateUser", &id).await?;
    let token = crate::console::store::create_setup_link(&app.pool.get().await?, user.id).await?;
    let path = format!("/enroll#{token}");
    let url = app.console.origin.as_ref().map(|origin| format!("{origin}{path}"));
    Ok((StatusCode::CREATED, Json(EnrollmentLink { url, path })))
}

/// Removes all of a directory user's passkeys, as when one is lost: its
/// sessions end, and it needs a setup link to sign in again.
#[utoipa::path(delete, path = "/directory-users/{id}/passkeys", params(("id" = String, Path)), responses(
    (status = 204, description = "Removed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_directory_passkeys(State(app): AppState, Extension(actor): Extension<Actor>, Path(id): Path<String>) -> Result<StatusCode> {
    let user = check_user(&app, &actor, "identitystore:UpdateUser", &id).await?;
    crate::console::store::delete_directory_passkeys(&app.pool.get().await?, user.id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// A group, as its users' group claims named it.
#[derive(Serialize, ToSchema)]
struct DirectoryGroupSummary {
    /// Its ID in the identity store.
    id: String,
    name: String,
    /// Its identity source; none for a group of Cairn's own directory.
    provider: Option<String>,
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
