//! The console's API for an account's IAM groups (see `groups`), as
//! `iam`'s for roles: every handler checks what it does as IAM's action
//! (`iam:CreateGroup` on the group's ARN, ...), as the session's identity.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::actor::Actor;
use super::manage::{AppState, AttachedPolicy, PolicyArn, PolicyDocument, Result, key};
use super::web::{ApiError, ErrorBody};
use crate::groups::{self, Group};
use crate::policy::Context;
use crate::s3::actions::On;
use crate::{App, users};

pub(super) fn router() -> OpenApiRouter<Arc<App>> {
    OpenApiRouter::new()
        .routes(routes!(list_groups, create_group))
        .routes(routes!(update_group, delete_group))
        .routes(routes!(add_member, remove_member))
        .routes(routes!(attach_group_policy, detach_group_policy))
        .routes(routes!(get_group_policy, put_group_policy, delete_group_policy))
}

/// The session's group `name`, allowed IAM's `action` on it (with `extra`).
async fn check_group(app: &Arc<App>, actor: &Actor, action: &'static str, name: &str, extra: Context) -> Result<Group> {
    let group = Group::load(&app.pool.get().await?, actor.account(), name)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("no group named {name:?}")))?;
    actor.check_with(app, action, group.on(), &extra).await?;
    Ok(group)
}

/// A group: users whose policies include the group's.
#[derive(Serialize, ToSchema)]
struct GroupSummary {
    name: String,
    /// Its unique ID (`AGPA…`), which never changes or comes back.
    id: String,
    arn: String,
    /// Its path (`/`, or `/…/`).
    path: String,
    /// When it was made (ISO 8601).
    created: String,
    /// Its members' names, by name; empty to whom may not `iam:GetGroup`
    /// it (`members_shown` false).
    members: Vec<String>,
    /// Whether `members` is its members (the session may `iam:GetGroup` it).
    members_shown: bool,
    /// Its attached managed policies.
    attached: Vec<AttachedPolicy>,
    /// The names of its inline policies.
    policies: Vec<String>,
}

#[utoipa::path(get, path = "/groups", responses(
    (status = 200, body = Vec<GroupSummary>),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn list_groups(State(app): AppState, Extension(actor): Extension<Actor>) -> Result<Json<Vec<GroupSummary>>> {
    // As ListGroups lists them: all, or those at paths the session may list.
    let account = actor.account().to_owned();
    let all = actor.allows(&app, "iam:ListGroups", On::groups(&account, "/")).await?;
    let client = app.pool.get().await?;
    let mut paths: HashMap<String, bool> = HashMap::new();
    let mut listed = Vec::new();
    for group in groups::list(&client, &account, "/", "", i64::MAX).await? {
        let may = match paths.get(&group.path) {
            _ if all => true,
            Some(may) => *may,
            None => {
                let may = actor.allows(&app, "iam:ListGroups", On::groups(&account, &group.path)).await?;
                paths.insert(group.path.clone(), may);
                may
            }
        };
        if may {
            listed.push(group);
        }
    }
    if !all && listed.is_empty() {
        actor.check(&app, "iam:ListGroups", On::groups(&account, "/")).await?;
    }
    let mut out = Vec::new();
    for group in listed {
        let attached = groups::attached(&client, group.id)
            .await?
            .into_iter()
            .map(|a| AttachedPolicy { name: a.name, arn: a.arn })
            .collect();
        // Its members, as GetGroup shows them.
        let members_shown = actor.allows(&app, "iam:GetGroup", group.on()).await?;
        let members = match members_shown {
            true => groups::members(&client, group.id, "", i64::MAX).await?.into_iter().map(|m| m.name).collect(),
            false => Vec::new(),
        };
        out.push(GroupSummary {
            id: groups::unique_id(group.id),
            arn: group.arn(),
            policies: groups::policy_names(&client, group.id).await?,
            attached,
            members,
            members_shown,
            name: group.name,
            path: group.path,
            created: group.created,
        });
    }
    Ok(Json(out))
}

#[derive(Deserialize, ToSchema)]
struct CreateGroup {
    name: String,
    /// Its path (`/`, or `/…/`); `/` if not given.
    path: Option<String>,
}

/// The name of a group, checked.
fn check_name(name: &str) -> Result<()> {
    match groups::valid_name(name) {
        true => Ok(()),
        false => Err(ApiError::BadRequest("a group's name is 1 to 128 letters, digits and +=,.@_- characters".into())),
    }
}

/// Makes a group, as IAM's CreateGroup.
#[utoipa::path(post, path = "/groups", request_body = CreateGroup, responses(
    (status = 201, description = "Made"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_group(State(app): AppState, Extension(actor): Extension<Actor>, Json(body): Json<CreateGroup>) -> Result<StatusCode> {
    let account = actor.account().to_owned();
    check_name(&body.name)?;
    let path = body.path.filter(|p| !p.is_empty()).unwrap_or_else(|| "/".to_owned());
    users::check_path(&path, "path", false).map_err(ApiError::BadRequest)?;
    actor.check(&app, "iam:CreateGroup", On::group(&account, &path, &body.name)).await?;
    groups::create(&app.pool.get().await?, &account, &body.name, &path).await?;
    Ok(StatusCode::CREATED)
}

#[derive(Deserialize, ToSchema)]
struct GroupChange {
    /// Its new name.
    name: Option<String>,
    /// Its new path (`/`, or `/…/`).
    path: Option<String>,
}

/// Renames or moves a group, as IAM's UpdateGroup: checked on it, and on
/// where it goes.
#[utoipa::path(patch, path = "/groups/{group}", params(("group" = String, Path)), request_body = GroupChange, responses(
    (status = 204, description = "Changed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn update_group(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<GroupChange>,
) -> Result<StatusCode> {
    if let Some(new) = &body.name {
        check_name(new)?;
    }
    if let Some(path) = &body.path {
        users::check_path(path, "path", false).map_err(ApiError::BadRequest)?;
    }
    let group = check_group(&app, &actor, "iam:UpdateGroup", &name, Context::default()).await?;
    let new_name = body.name.unwrap_or_else(|| group.name.clone());
    let new_path = body.path.unwrap_or_else(|| group.path.clone());
    actor.check(&app, "iam:UpdateGroup", On::group(&group.account, &new_path, &new_name)).await?;
    groups::update(&app.pool.get().await?, group.id, &new_name, &new_path).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes a group, unless it has members or policies left, as IAM's
/// DeleteGroup.
#[utoipa::path(delete, path = "/groups/{group}", params(("group" = String, Path)), responses(
    (status = 204, description = "Deleted"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_group(State(app): AppState, Extension(actor): Extension<Actor>, Path(name): Path<String>) -> Result<StatusCode> {
    let group = check_group(&app, &actor, "iam:DeleteGroup", &name, Context::default()).await?;
    groups::delete(&app.pool.get().await?, &group).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The user `name` of the session's account.
async fn user_id(app: &Arc<App>, actor: &Actor, name: &str) -> Result<(uuid::Uuid, String)> {
    let user = users::Target::load(&app.pool.get().await?, actor.account(), name)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("no user named {name:?}")))?;
    Ok((user.id, user.name))
}

/// Adds a user to a group, as IAM's AddUserToGroup (checked on the group).
#[utoipa::path(put, path = "/groups/{group}/members/{user}", params(("group" = String, Path), ("user" = String, Path)), responses(
    (status = 204, description = "Added"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn add_member(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((name, user)): Path<(String, String)>,
) -> Result<StatusCode> {
    let group = check_group(&app, &actor, "iam:AddUserToGroup", &name, Context::default()).await?;
    let (id, user) = user_id(&app, &actor, &user).await?;
    groups::add_member(&app.pool.get().await?, &group, id, &user).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Removes a user from a group, as IAM's RemoveUserFromGroup.
#[utoipa::path(delete, path = "/groups/{group}/members/{user}", params(("group" = String, Path), ("user" = String, Path)), responses(
    (status = 204, description = "Removed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn remove_member(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((name, user)): Path<(String, String)>,
) -> Result<StatusCode> {
    let group = check_group(&app, &actor, "iam:RemoveUserFromGroup", &name, Context::default()).await?;
    let (id, user) = user_id(&app, &actor, &user).await?;
    groups::remove_member(&app.pool.get().await?, &group, id, &user).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Attaches a managed policy to a group.
#[utoipa::path(post, path = "/groups/{group}/attached", params(("group" = String, Path)), request_body = PolicyArn, responses(
    (status = 204, description = "Attached"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn attach_group_policy(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<PolicyArn>,
) -> Result<StatusCode> {
    let group = check_group(&app, &actor, "iam:AttachGroupPolicy", &name, key("iam:PolicyARN", &body.arn)).await?;
    groups::attach(&app.pool.get().await?, &group.account, &group, &body.arn, true).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Detaches a managed policy from a group.
#[utoipa::path(delete, path = "/groups/{group}/attached", params(("group" = String, Path), PolicyArn), responses(
    (status = 204, description = "Detached"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn detach_group_policy(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Query(params): Query<PolicyArn>,
) -> Result<StatusCode> {
    let group = check_group(&app, &actor, "iam:DetachGroupPolicy", &name, key("iam:PolicyARN", &params.arn)).await?;
    groups::attach(&app.pool.get().await?, &group.account, &group, &params.arn, false).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// One of the group's inline policies.
#[utoipa::path(get, path = "/groups/{group}/policies/{policy}",
    params(("group" = String, Path), ("policy" = String, Path)), responses(
        (status = 200, body = PolicyDocument),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn get_group_policy(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((name, policy)): Path<(String, String)>,
) -> Result<Json<PolicyDocument>> {
    let group = check_group(&app, &actor, "iam:GetGroupPolicy", &name, Context::default()).await?;
    let document = groups::get_policy(&app.pool.get().await?, group.id, &policy)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("{name:?} has no policy {policy:?}")))?;
    Ok(Json(PolicyDocument { document }))
}

/// Sets one of the group's inline policies, if it's a valid identity policy.
#[utoipa::path(put, path = "/groups/{group}/policies/{policy}",
    params(("group" = String, Path), ("policy" = String, Path)), request_body = PolicyDocument, responses(
        (status = 204, description = "Set"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn put_group_policy(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((name, policy)): Path<(String, String)>,
    Json(body): Json<PolicyDocument>,
) -> Result<StatusCode> {
    let group = check_group(&app, &actor, "iam:PutGroupPolicy", &name, Context::default()).await?;
    groups::put_policy(&app.pool.get().await?, &group, &policy, &body.document).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes one of the group's inline policies.
#[utoipa::path(delete, path = "/groups/{group}/policies/{policy}",
    params(("group" = String, Path), ("policy" = String, Path)), responses(
        (status = 204, description = "Deleted"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn delete_group_policy(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((name, policy)): Path<(String, String)>,
) -> Result<StatusCode> {
    let group = check_group(&app, &actor, "iam:DeleteGroupPolicy", &name, Context::default()).await?;
    if !groups::delete_policy(&app.pool.get().await?, group.id, &policy).await? {
        return Err(ApiError::NotFound(format!("{name:?} has no policy {policy:?}")));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod e2e {
    use axum::http::StatusCode;
    use serde_json::json;

    use super::super::e2e::{console_of, signed_in};

    /// An admin manages groups from the console as with IAM's API: makes one,
    /// adds members and policies (which its members then have, as the Users
    /// and Policies pages show), renames it, and can't delete it while it
    /// has members or policies; a user without IAM's actions sees none.
    #[tokio::test]
    async fn manages_groups() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else { return };
        let console = console_of(&app);
        let mut admin = signed_in(&console, "ada", true).await;
        let mut bob = signed_in(&console, "bob", false).await;
        let account = crate::users::account(&app.pool.get().await.unwrap()).await.unwrap();

        let new = json!({"name": "readers", "path": "/finance/"});
        assert_eq!(admin.send("POST", "/api/groups", Some(new.clone())).await.0, StatusCode::CREATED);
        assert_eq!(admin.send("POST", "/api/groups", Some(json!({"name": "READERS"}))).await.0, StatusCode::CONFLICT);
        assert_eq!(admin.send("POST", "/api/groups", Some(json!({"name": "a/b"}))).await.0, StatusCode::BAD_REQUEST);

        assert_eq!(admin.send("PUT", "/api/groups/readers/members/bob", None).await.0, StatusCode::NO_CONTENT);
        assert_eq!(admin.send("PUT", "/api/groups/readers/members/nobody", None).await.0, StatusCode::NOT_FOUND);
        let read = json!({"document": r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#});
        assert_eq!(admin.send("PUT", "/api/groups/readers/policies/read", Some(read)).await.0, StatusCode::NO_CONTENT);
        let s3_read = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess";
        let attach = json!({"arn": s3_read});
        assert_eq!(admin.send("POST", "/api/groups/readers/attached", Some(attach)).await.0, StatusCode::NO_CONTENT);

        let (status, groups) = admin.send("GET", "/api/groups", None).await;
        assert_eq!(status, StatusCode::OK);
        let group = &groups[0];
        assert_eq!(group["arn"], format!("arn:aws:iam::{account}:group/finance/readers"));
        assert_eq!(group["members"], json!(["bob"]));
        assert_eq!(group["members_shown"], true);
        assert_eq!(group["policies"], json!(["read"]));
        assert_eq!(group["attached"][0]["arn"], s3_read);
        let (_, users) = admin.send("GET", "/api/users", None).await;
        let bob_row = users.as_array().unwrap().iter().find(|u| u["name"] == "bob").unwrap();
        assert_eq!(bob_row["groups"], json!(["readers"]));
        let (_, policies) = admin.send("GET", "/api/policies", None).await;
        let s3 = policies.as_array().unwrap().iter().find(|p| p["arn"] == s3_read).unwrap();
        assert_eq!(s3["groups"], json!(["readers"]));
        let (_, document) = admin.send("GET", "/api/groups/readers/policies/read", None).await;
        assert!(document["document"].as_str().unwrap().contains("s3:GetObject"));

        // Someone without IAM's actions.
        assert_eq!(bob.send("GET", "/api/groups", None).await.0, StatusCode::FORBIDDEN);
        assert_eq!(bob.send("DELETE", "/api/groups/readers/members/bob", None).await.0, StatusCode::FORBIDDEN);

        // Renamed and moved.
        let change = json!({"name": "invoice-readers", "path": "/"});
        assert_eq!(admin.send("PATCH", "/api/groups/readers", Some(change)).await.0, StatusCode::NO_CONTENT);
        let (_, groups) = admin.send("GET", "/api/groups", None).await;
        assert_eq!(groups[0]["arn"], format!("arn:aws:iam::{account}:group/invoice-readers"));

        // Deleted once its members and policies are gone.
        assert_eq!(admin.send("DELETE", "/api/groups/invoice-readers", None).await.0, StatusCode::CONFLICT);
        assert_eq!(admin.send("DELETE", "/api/groups/invoice-readers/members/bob", None).await.0, StatusCode::NO_CONTENT);
        assert_eq!(admin.send("DELETE", "/api/groups/invoice-readers", None).await.0, StatusCode::CONFLICT);
        assert_eq!(admin.send("DELETE", "/api/groups/invoice-readers/policies/read", None).await.0, StatusCode::NO_CONTENT);
        let detach = format!("/api/groups/invoice-readers/attached?arn={}", s3_read.replace(':', "%3A").replace('/', "%2F"));
        assert_eq!(admin.send("DELETE", &detach, None).await.0, StatusCode::NO_CONTENT);
        assert_eq!(admin.send("DELETE", "/api/groups/invoice-readers", None).await.0, StatusCode::NO_CONTENT);
        assert_eq!(admin.send("GET", "/api/groups", None).await.1, json!([]));
    }
}
