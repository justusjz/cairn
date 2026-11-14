//! The console's API for an account's IAM roles (see `roles`) and its
//! OpenID Connect providers for web identities (see `iam_oidc`), as
//! `manage`'s for users: every handler checks what it does as IAM's action
//! (`iam:CreateRole` on the role's ARN, ...), as the session's identity.

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
use super::manage::{AppState, AttachedPolicy, BoundaryArn, PolicyArn, PolicyDocument, Result, Tag, key};
use super::web::{ApiError, ErrorBody};
use crate::iam_oidc::{self, Provider};
use crate::policy::Context;
use crate::roles::{self, Role};
use crate::s3::actions::On;
use crate::{App, managed, users};

pub(super) fn router() -> OpenApiRouter<Arc<App>> {
    OpenApiRouter::new()
        .routes(routes!(list_roles, create_role))
        .routes(routes!(update_role, delete_role))
        .routes(routes!(set_trust))
        .routes(routes!(set_role_boundary, delete_role_boundary))
        .routes(routes!(set_role_tags))
        .routes(routes!(attach_role_policy, detach_role_policy))
        .routes(routes!(get_role_policy, put_role_policy, delete_role_policy))
        .routes(routes!(revoke_sessions))
        .routes(routes!(list_identity_providers, create_identity_provider))
        .routes(routes!(update_identity_provider, delete_identity_provider))
}

/// The inline policy that revokes a role's sessions issued before it was
/// set, as AWS's console names it.
const REVOKE_POLICY: &str = "AWSRevokeOlderSessions";

fn tags_of(tags: Vec<Tag>) -> Vec<(String, String)> {
    tags.into_iter().map(|t| (t.key, t.value)).collect()
}

fn tag_list(tags: &[(String, String)]) -> Vec<Tag> {
    tags.iter().map(|(key, value)| Tag { key: key.clone(), value: value.clone() }).collect()
}

/// The session's role `name`, allowed IAM's `action` on it (with its
/// condition keys, and `extra`).
async fn check_role(app: &Arc<App>, actor: &Actor, action: &'static str, name: &str, extra: Context) -> Result<Role> {
    let role = Role::load(&app.pool.get().await?, actor.account(), name)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("no role named {name:?}")))?;
    let mut context = role.context(action);
    context.extend(&extra);
    actor.check_with(app, action, role.on(), &context).await?;
    Ok(role)
}

// ─── Roles ───────────────────────────────────────────────────────────────────

/// A role: an identity no one signs as with keys of its own, but assumes
/// (STS's AssumeRole, AssumeRoleWithWebIdentity), as its trust policy
/// allows, for temporary credentials.
#[derive(Serialize, ToSchema)]
struct RoleSummary {
    name: String,
    /// Its unique ID (`AROA…`), which never changes or comes back.
    id: String,
    arn: String,
    /// Its path (`/`, or `/…/`).
    path: String,
    description: String,
    /// The longest session it allows, in seconds.
    max_session_duration: i32,
    /// When it was made (ISO 8601).
    created: String,
    /// Its trust policy: who may assume it (as GetRole shows it).
    trust: String,
    /// Its tags, oldest first.
    tags: Vec<Tag>,
    /// Its permissions boundary's ARN.
    boundary: Option<String>,
    /// Its attached managed policies.
    attached: Vec<AttachedPolicy>,
    /// The names of its inline policies.
    policies: Vec<String>,
}

#[utoipa::path(get, path = "/roles", responses(
    (status = 200, body = Vec<RoleSummary>),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn list_roles(State(app): AppState, Extension(actor): Extension<Actor>) -> Result<Json<Vec<RoleSummary>>> {
    // As ListRoles lists them: all, or those at paths the session may list.
    let account = actor.account().to_owned();
    let all = actor.allows(&app, "iam:ListRoles", On::roles(&account, "/")).await?;
    let client = app.pool.get().await?;
    let mut paths: HashMap<String, bool> = HashMap::new();
    let mut listed = Vec::new();
    for role in roles::list(&client, &account, "/", "", i64::MAX).await? {
        let may = match paths.get(&role.path) {
            _ if all => true,
            Some(may) => *may,
            None => {
                let may = actor.allows(&app, "iam:ListRoles", On::roles(&account, &role.path)).await?;
                paths.insert(role.path.clone(), may);
                may
            }
        };
        if may {
            listed.push(role);
        }
    }
    if !all && listed.is_empty() {
        actor.check(&app, "iam:ListRoles", On::roles(&account, "/")).await?;
    }
    let mut out = Vec::new();
    for role in listed {
        let attached = roles::attached(&client, role.id)
            .await?
            .into_iter()
            .map(|a| AttachedPolicy { name: a.name, arn: a.arn })
            .collect();
        out.push(RoleSummary {
            id: roles::unique_id(role.id),
            arn: role.arn(),
            trust: roles::shown_trust(&client, &role).await?,
            tags: tag_list(&role.tags),
            policies: roles::policy_names(&client, role.id).await?,
            attached,
            name: role.name,
            path: role.path,
            description: role.description,
            max_session_duration: role.max_session_duration,
            created: role.created,
            boundary: role.boundary,
        });
    }
    Ok(Json(out))
}

#[derive(Deserialize, ToSchema)]
struct CreateRole {
    name: String,
    /// Its path (`/`, or `/…/`); `/` if not given.
    path: Option<String>,
    /// Who may assume it: a trust policy.
    trust: String,
    #[serde(default)]
    description: String,
    /// Its longest session, in seconds (3600 to 43200); 3600 if not given.
    max_session_duration: Option<i32>,
    #[serde(default)]
    tags: Vec<Tag>,
    /// Its permissions boundary: a managed policy's ARN.
    boundary: Option<String>,
}

/// Makes a role, as IAM's CreateRole.
#[utoipa::path(post, path = "/roles", request_body = CreateRole, responses(
    (status = 201, description = "Made"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_role(State(app): AppState, Extension(actor): Extension<Actor>, Json(body): Json<CreateRole>) -> Result<StatusCode> {
    let account = actor.account().to_owned();
    if !roles::valid_name(&body.name) {
        return Err(ApiError::BadRequest(
            "a role's name is 1 to 64 letters, digits and +=,.@_- characters".into(),
        ));
    }
    let path = body.path.clone().filter(|p| !p.is_empty()).unwrap_or_else(|| "/".to_owned());
    users::check_path(&path, "path", false).map_err(ApiError::BadRequest)?;
    let max = body.max_session_duration.unwrap_or(*roles::SESSION_DURATIONS.start());
    if !roles::SESSION_DURATIONS.contains(&max) {
        return Err(ApiError::BadRequest("a role's longest session is from 3600 to 43200 seconds".into()));
    }
    if body.description.chars().count() > 1000 {
        return Err(ApiError::BadRequest("a role's description is at most 1000 characters".into()));
    }
    let tags = tags_of(body.tags);
    users::check_tags(&tags).map_err(ApiError::BadRequest)?;
    let boundary_arn = body.boundary.filter(|b| !b.is_empty());
    let on = On::role(&account, &path, &body.name);
    let mut context = users::request_tags_context(&tags);
    if let Some(arn) = &boundary_arn {
        context.set("iam:PermissionsBoundary", arn);
    }
    actor.check_with(&app, "iam:CreateRole", on.clone(), &context).await?;
    if !tags.is_empty() {
        actor.check_with(&app, "iam:TagRole", on, &context).await?;
    }
    let client = app.pool.get().await?;
    let trust = roles::check_trust(&client, &account, &body.trust).await?;
    let boundary = match &boundary_arn {
        Some(arn) => Some(managed::boundary(&client, &account, arn).await?),
        None => None,
    };
    let new = roles::New {
        name: &body.name,
        path: &path,
        trust: &trust,
        description: &body.description,
        max_session_duration: max,
        boundary: boundary.as_ref(),
        tags: &tags,
    };
    roles::create(&client, &account, &new).await?;
    // Its identity in the KMS, as a user's (see `users::identify`).
    if app.kms.is_some() {
        let app = app.clone();
        tokio::spawn(async move {
            if let Err(e) = users::identify(&app).await {
                eprintln!("kms: identifying roles: {e:#}");
            }
        });
    }
    Ok(StatusCode::CREATED)
}

#[derive(Deserialize, ToSchema)]
struct RoleChange {
    description: Option<String>,
    /// Its longest session, in seconds (3600 to 43200).
    max_session_duration: Option<i32>,
}

/// Changes a role's description or longest session, as IAM's UpdateRole.
#[utoipa::path(patch, path = "/roles/{role}", params(("role" = String, Path)), request_body = RoleChange, responses(
    (status = 204, description = "Changed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn update_role(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<RoleChange>,
) -> Result<StatusCode> {
    if body.max_session_duration.is_some_and(|m| !roles::SESSION_DURATIONS.contains(&m)) {
        return Err(ApiError::BadRequest("a role's longest session is from 3600 to 43200 seconds".into()));
    }
    if body.description.as_ref().is_some_and(|d| d.chars().count() > 1000) {
        return Err(ApiError::BadRequest("a role's description is at most 1000 characters".into()));
    }
    let role = check_role(&app, &actor, "iam:UpdateRole", &name, Context::default()).await?;
    roles::update(&app.pool.get().await?, role.id, body.description.as_deref(), body.max_session_duration).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes a role, unless it has policies left, as IAM's DeleteRole.
#[utoipa::path(delete, path = "/roles/{role}", params(("role" = String, Path)), responses(
    (status = 204, description = "Deleted"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_role(State(app): AppState, Extension(actor): Extension<Actor>, Path(name): Path<String>) -> Result<StatusCode> {
    let role = check_role(&app, &actor, "iam:DeleteRole", &name, Context::default()).await?;
    roles::delete(&app.pool.get().await?, &role).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Sets a role's trust policy, as IAM's UpdateAssumeRolePolicy.
#[utoipa::path(put, path = "/roles/{role}/trust", params(("role" = String, Path)), request_body = PolicyDocument, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn set_trust(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<PolicyDocument>,
) -> Result<StatusCode> {
    let role = check_role(&app, &actor, "iam:UpdateAssumeRolePolicy", &name, Context::default()).await?;
    let client = app.pool.get().await?;
    let trust = roles::check_trust(&client, &role.account, &body.document).await?;
    roles::set_trust(&client, role.id, &trust).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Sets a role's permissions boundary.
#[utoipa::path(put, path = "/roles/{role}/boundary", params(("role" = String, Path)), request_body = BoundaryArn, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn set_role_boundary(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<BoundaryArn>,
) -> Result<StatusCode> {
    let extra = key("iam:PermissionsBoundary", &body.arn);
    let role = check_role(&app, &actor, "iam:PutRolePermissionsBoundary", &name, extra).await?;
    let client = app.pool.get().await?;
    let boundary = managed::boundary(&client, &role.account, &body.arn).await?;
    roles::set_boundary(&client, role.id, Some(&boundary)).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Removes a role's permissions boundary.
#[utoipa::path(delete, path = "/roles/{role}/boundary", params(("role" = String, Path)), responses(
    (status = 204, description = "Removed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_role_boundary(State(app): AppState, Extension(actor): Extension<Actor>, Path(name): Path<String>) -> Result<StatusCode> {
    let role = check_role(&app, &actor, "iam:DeleteRolePermissionsBoundary", &name, Context::default()).await?;
    if role.boundary.is_none() {
        return Err(ApiError::NotFound(format!("{name:?} has no permissions boundary")));
    }
    roles::set_boundary(&app.pool.get().await?, role.id, None).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct RoleTags {
    /// All of its tags: those it has of other keys go (UntagRole), the
    /// rest are set (TagRole).
    tags: Vec<Tag>,
}

/// Sets a role's tags, as IAM's TagRole and UntagRole would.
#[utoipa::path(put, path = "/roles/{role}/tags", params(("role" = String, Path)), request_body = RoleTags, responses(
    (status = 204, description = "Set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn set_role_tags(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<RoleTags>,
) -> Result<StatusCode> {
    let tags = tags_of(body.tags);
    users::check_tags(&tags).map_err(ApiError::BadRequest)?;
    let role = Role::load(&app.pool.get().await?, actor.account(), &name)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("no role named {name:?}")))?;
    let gone: Vec<String> = role
        .tags
        .iter()
        .filter(|(k, _)| !tags.iter().any(|(key, _)| key.eq_ignore_ascii_case(k)))
        .map(|(k, _)| k.clone())
        .collect();
    let changed: Vec<(String, String)> = tags.iter().filter(|t| !role.tags.contains(t)).cloned().collect();
    if !gone.is_empty() {
        let mut extra = Context::default();
        extra.set_all("aws:TagKeys", gone.clone());
        check_role(&app, &actor, "iam:UntagRole", &name, extra).await?;
    }
    if !changed.is_empty() {
        check_role(&app, &actor, "iam:TagRole", &name, users::request_tags_context(&changed)).await?;
    }
    let client = app.pool.get().await?;
    if !gone.is_empty() {
        roles::untag(&client, role.id, &gone).await?;
    }
    if !changed.is_empty() {
        roles::tag(&client, role.id, &changed).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Attaches a managed policy to a role.
#[utoipa::path(post, path = "/roles/{role}/attached", params(("role" = String, Path)), request_body = PolicyArn, responses(
    (status = 204, description = "Attached"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn attach_role_policy(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Json(body): Json<PolicyArn>,
) -> Result<StatusCode> {
    let role = check_role(&app, &actor, "iam:AttachRolePolicy", &name, key("iam:PolicyARN", &body.arn)).await?;
    roles::attach(&app.pool.get().await?, &role.account, &role, &body.arn, true).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Detaches a managed policy from a role.
#[utoipa::path(delete, path = "/roles/{role}/attached", params(("role" = String, Path), PolicyArn), responses(
    (status = 204, description = "Detached"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn detach_role_policy(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(name): Path<String>,
    Query(params): Query<PolicyArn>,
) -> Result<StatusCode> {
    let role = check_role(&app, &actor, "iam:DetachRolePolicy", &name, key("iam:PolicyARN", &params.arn)).await?;
    roles::attach(&app.pool.get().await?, &role.account, &role, &params.arn, false).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// One of the role's inline policies.
#[utoipa::path(get, path = "/roles/{role}/policies/{policy}",
    params(("role" = String, Path), ("policy" = String, Path)), responses(
        (status = 200, body = PolicyDocument),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn get_role_policy(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((name, policy)): Path<(String, String)>,
) -> Result<Json<PolicyDocument>> {
    let role = check_role(&app, &actor, "iam:GetRolePolicy", &name, Context::default()).await?;
    let document = roles::get_policy(&app.pool.get().await?, role.id, &policy)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("{name:?} has no policy {policy:?}")))?;
    Ok(Json(PolicyDocument { document }))
}

/// Sets one of the role's inline policies, if it's a valid identity policy.
#[utoipa::path(put, path = "/roles/{role}/policies/{policy}",
    params(("role" = String, Path), ("policy" = String, Path)), request_body = PolicyDocument, responses(
        (status = 204, description = "Set"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn put_role_policy(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((name, policy)): Path<(String, String)>,
    Json(body): Json<PolicyDocument>,
) -> Result<StatusCode> {
    let role = check_role(&app, &actor, "iam:PutRolePolicy", &name, Context::default()).await?;
    roles::put_policy(&app.pool.get().await?, &role, &policy, &body.document).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes one of the role's inline policies.
#[utoipa::path(delete, path = "/roles/{role}/policies/{policy}",
    params(("role" = String, Path), ("policy" = String, Path)), responses(
        (status = 204, description = "Deleted"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn delete_role_policy(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((name, policy)): Path<(String, String)>,
) -> Result<StatusCode> {
    let role = check_role(&app, &actor, "iam:DeleteRolePolicy", &name, Context::default()).await?;
    if !roles::delete_policy(&app.pool.get().await?, role.id, &policy).await? {
        return Err(ApiError::NotFound(format!("{name:?} has no policy {policy:?}")));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Revokes the role's sessions issued until now, as AWS's console does: an
/// inline policy `AWSRevokeOlderSessions` that denies everything to
/// sessions whose token was issued before now (`aws:TokenIssueTime`). New
/// sessions aren't affected; doing it again moves the time.
#[utoipa::path(post, path = "/roles/{role}/revoke-sessions", params(("role" = String, Path)), responses(
    (status = 204, description = "Revoked"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn revoke_sessions(State(app): AppState, Extension(actor): Extension<Actor>, Path(name): Path<String>) -> Result<StatusCode> {
    let role = check_role(&app, &actor, "iam:PutRolePolicy", &name, Context::default()).await?;
    let now = crate::sessions::iso(crate::sessions::now());
    let document = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Action":["*"],"Resource":["*"],"Condition":{{"DateLessThan":{{"aws:TokenIssueTime":"{now}"}}}}}}]}}"#
    );
    roles::put_policy(&app.pool.get().await?, &role, REVOKE_POLICY, &document).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ─── OpenID Connect providers (web identities) ───────────────────────────────

/// An OpenID Connect provider whose ID tokens STS takes for roles that
/// trust it (AssumeRoleWithWebIdentity).
#[derive(Serialize, ToSchema)]
struct IdentityProvider {
    id: String,
    arn: String,
    /// Its issuer's URL without `https://`, as its ARN has it.
    url: String,
    /// The audiences its tokens may be for.
    client_ids: Vec<String>,
    /// SHA-1s of certificates its server is trusted by, besides the public
    /// roots.
    thumbprints: Vec<String>,
    /// When it was made (ISO 8601).
    created: String,
    tags: Vec<Tag>,
    /// The account's roles whose trust policies name it.
    roles: Vec<String>,
}

#[derive(Serialize, ToSchema)]
struct IdentityProviders {
    providers: Vec<IdentityProvider>,
    /// Whether providers may be at private addresses (the cluster's
    /// `oidc-private-issuers` setting).
    private_issuers: bool,
}

#[utoipa::path(get, path = "/identity-providers", responses(
    (status = 200, body = IdentityProviders),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn list_identity_providers(State(app): AppState, Extension(actor): Extension<Actor>) -> Result<Json<IdentityProviders>> {
    let account = actor.account().to_owned();
    actor.check(&app, "iam:ListOpenIDConnectProviders", On::Arn(format!("arn:aws:iam::{account}:oidc-provider/*"))).await?;
    let client = app.pool.get().await?;
    let trusts: Vec<Role> = roles::list(&client, &account, "/", "", i64::MAX).await?;
    let mut providers = Vec::new();
    for p in iam_oidc::list(&client, &account).await? {
        // Its details, as GetOpenIDConnectProvider shows them, if allowed.
        if !actor.allows(&app, "iam:GetOpenIDConnectProvider", On::Arn(p.arn())).await? {
            continue;
        }
        let arn = p.arn();
        let named = trusts.iter().filter(|r| r.trust.contains(&format!("\"{arn}\""))).map(|r| r.name.clone()).collect();
        providers.push(IdentityProvider {
            id: p.id.to_string(),
            tags: tag_list(&p.tags),
            roles: named,
            arn,
            url: p.url,
            client_ids: p.client_ids,
            thumbprints: p.thumbprints,
            created: p.created,
        });
    }
    let private_issuers = iam_oidc::private_allowed(&client).await?;
    Ok(Json(IdentityProviders { providers, private_issuers }))
}

#[derive(Deserialize, ToSchema)]
struct NewIdentityProvider {
    /// The issuer's URL (`https://…`), as its tokens' `iss` names it.
    url: String,
    /// The audiences its tokens may be for (`sts.amazonaws.com`, say).
    #[serde(default)]
    client_ids: Vec<String>,
    /// SHA-1s (40 hex digits) of certificates to trust its server by: for
    /// an issuer whose certificate isn't of a public CA.
    #[serde(default)]
    thumbprints: Vec<String>,
    #[serde(default)]
    tags: Vec<Tag>,
}

/// Checks a provider's client IDs and thumbprints: their lengths, how many,
/// and none twice (the first kept).
fn checked_lists(client_ids: Vec<String>, thumbprints: Vec<String>) -> Result<(Vec<String>, Vec<String>)> {
    let mut seen = std::collections::HashSet::new();
    let client_ids: Vec<String> =
        client_ids.into_iter().map(|c| c.trim().to_owned()).filter(|c| !c.is_empty()).filter(|c| seen.insert(c.clone())).collect();
    if client_ids.iter().any(|c| c.chars().count() > 255) {
        return Err(ApiError::BadRequest("a client ID is at most 255 characters".into()));
    }
    if client_ids.len() > iam_oidc::MAX_CLIENT_IDS {
        return Err(ApiError::BadRequest(format!("a provider has at most {} client IDs", iam_oidc::MAX_CLIENT_IDS)));
    }
    let mut seen = std::collections::HashSet::new();
    let thumbprints: Vec<String> = thumbprints
        .into_iter()
        .map(|t| t.trim().replace(':', ""))
        .filter(|t| !t.is_empty())
        .filter(|t| seen.insert(t.to_ascii_lowercase()))
        .collect();
    if thumbprints.len() > iam_oidc::MAX_THUMBPRINTS {
        return Err(ApiError::BadRequest(format!("a provider has at most {} thumbprints", iam_oidc::MAX_THUMBPRINTS)));
    }
    for t in &thumbprints {
        iam_oidc::check_thumbprint(t).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    }
    Ok((client_ids, thumbprints))
}

/// Adds a provider, as IAM's CreateOpenIDConnectProvider: after checking
/// its issuer can be reached (its discovery document and keys).
#[utoipa::path(post, path = "/identity-providers", request_body = NewIdentityProvider, responses(
    (status = 201, description = "Added"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_identity_provider(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Json(body): Json<NewIdentityProvider>,
) -> Result<StatusCode> {
    let account = actor.account().to_owned();
    let url = iam_oidc::url_of(body.url.trim()).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let (client_ids, thumbprints) = checked_lists(body.client_ids, body.thumbprints)?;
    let tags = tags_of(body.tags);
    users::check_tags(&tags).map_err(ApiError::BadRequest)?;
    let on = On::Arn(iam_oidc::provider_arn(&account, &url));
    let context = users::request_tags_context(&tags);
    actor.check_with(&app, "iam:CreateOpenIDConnectProvider", on.clone(), &context).await?;
    if !tags.is_empty() {
        actor.check_with(&app, "iam:TagOpenIDConnectProvider", on, &context).await?;
    }
    let client = app.pool.get().await?;
    if Provider::load(&client, &account, &url).await?.is_some() {
        return Err(ApiError::Conflict(format!("there's a provider of https://{url} already")));
    }
    match iam_oidc::check_new(&client, &url, &thumbprints).await? {
        Ok(()) => {}
        Err(iam_oidc::Unusable::Url(e) | iam_oidc::Unusable::Unreachable(e)) => return Err(ApiError::BadRequest(e)),
    }
    let new = iam_oidc::New { url: &url, client_ids: &client_ids, thumbprints: &thumbprints, tags: &tags };
    iam_oidc::create(&client, &account, &new).await?;
    Ok(StatusCode::CREATED)
}

/// The session's provider `id`, allowed `action` on it (with its tags,
/// and `extra`).
async fn check_provider(app: &Arc<App>, actor: &Actor, action: &'static str, id: &str, extra: Context) -> Result<Provider> {
    let missing = || ApiError::NotFound(format!("no provider {id:?}"));
    let id: uuid::Uuid = id.parse().map_err(|_| missing())?;
    let provider = Provider::load_id(&app.pool.get().await?, id).await?.filter(|p| p.account == actor.account()).ok_or_else(missing)?;
    let mut context = provider.context();
    context.extend(&extra);
    actor.check_with(app, action, On::Arn(provider.arn()), &context).await?;
    Ok(provider)
}

#[derive(Deserialize, ToSchema)]
struct IdentityProviderChange {
    /// All of its client IDs: those it has that aren't here are removed,
    /// the rest added.
    client_ids: Vec<String>,
    /// All of its thumbprints.
    thumbprints: Vec<String>,
    /// All of its tags.
    tags: Vec<Tag>,
}

/// Changes a provider's client IDs, thumbprints and tags, as IAM's
/// Add/RemoveClientIDToOpenIDConnectProvider,
/// UpdateOpenIDConnectProviderThumbprint and Tag/UntagOpenIDConnectProvider
/// would.
#[utoipa::path(put, path = "/identity-providers/{id}", params(("id" = String, Path)), request_body = IdentityProviderChange, responses(
    (status = 204, description = "Changed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn update_identity_provider(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
    Json(body): Json<IdentityProviderChange>,
) -> Result<StatusCode> {
    let (client_ids, thumbprints) = checked_lists(body.client_ids, body.thumbprints)?;
    let tags = tags_of(body.tags);
    users::check_tags(&tags).map_err(ApiError::BadRequest)?;
    let provider = check_provider(&app, &actor, "iam:GetOpenIDConnectProvider", &id, Context::default()).await?;
    let added: Vec<&String> = client_ids.iter().filter(|c| !provider.client_ids.contains(c)).collect();
    let removed: Vec<&String> = provider.client_ids.iter().filter(|c| !client_ids.contains(c)).collect();
    let rethumbed = thumbprints.iter().map(|t| t.to_ascii_lowercase()).collect::<Vec<_>>()
        != provider.thumbprints.iter().map(|t| t.to_ascii_lowercase()).collect::<Vec<_>>();
    let gone: Vec<String> = provider
        .tags
        .iter()
        .filter(|(k, _)| !tags.iter().any(|(key, _)| key.eq_ignore_ascii_case(k)))
        .map(|(k, _)| k.clone())
        .collect();
    let changed: Vec<(String, String)> = tags.iter().filter(|t| !provider.tags.contains(t)).cloned().collect();
    // Every change allowed first, then made.
    if !added.is_empty() {
        check_provider(&app, &actor, "iam:AddClientIDToOpenIDConnectProvider", &id, Context::default()).await?;
    }
    if !removed.is_empty() {
        check_provider(&app, &actor, "iam:RemoveClientIDFromOpenIDConnectProvider", &id, Context::default()).await?;
    }
    if rethumbed {
        check_provider(&app, &actor, "iam:UpdateOpenIDConnectProviderThumbprint", &id, Context::default()).await?;
    }
    if !gone.is_empty() {
        let mut extra = Context::default();
        extra.set_all("aws:TagKeys", gone.clone());
        check_provider(&app, &actor, "iam:UntagOpenIDConnectProvider", &id, extra).await?;
    }
    if !changed.is_empty() {
        check_provider(&app, &actor, "iam:TagOpenIDConnectProvider", &id, users::request_tags_context(&changed)).await?;
    }
    let client = app.pool.get().await?;
    for c in added {
        iam_oidc::add_client_id(&client, &provider, c).await?;
    }
    for c in removed {
        iam_oidc::remove_client_id(&client, provider.id, c).await?;
    }
    if rethumbed {
        iam_oidc::set_thumbprints(&client, &provider, &thumbprints).await?;
    }
    if !gone.is_empty() {
        iam_oidc::untag(&client, provider.id, &gone).await?;
    }
    if !changed.is_empty() {
        iam_oidc::tag(&client, &provider, &changed).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes a provider: its web identities assume no role any more (the
/// trust policies naming it stay, and match no one).
#[utoipa::path(delete, path = "/identity-providers/{id}", params(("id" = String, Path)), responses(
    (status = 204, description = "Deleted"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_identity_provider(State(app): AppState, Extension(actor): Extension<Actor>, Path(id): Path<String>) -> Result<StatusCode> {
    let provider = check_provider(&app, &actor, "iam:DeleteOpenIDConnectProvider", &id, Context::default()).await?;
    iam_oidc::delete(&app.pool.get().await?, provider.id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod e2e {
    use axum::http::StatusCode;
    use serde_json::json;

    use super::super::e2e::{console_of, signed_in, superadmin};
    use crate::oidc::mock::{CA_THUMBPRINT, Mock};

    /// An admin manages roles from the console as with IAM's API: makes one,
    /// changes it, gives it policies, revokes its sessions, and can't delete
    /// it while it has policies; a user without IAM's actions sees none.
    #[tokio::test]
    async fn manages_roles() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else { return };
        let console = console_of(&app);
        let mut admin = signed_in(&console, "ada", true).await;
        let account = crate::users::account(&app.pool.get().await.unwrap()).await.unwrap();
        let trust = json!({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": format!("arn:aws:iam::{account}:root")}, "Action": "sts:AssumeRole",
        }]})
        .to_string();
        let new = json!({"name": "deployer", "path": "/ci/", "trust": trust, "description": "deploys",
                         "max_session_duration": 7200, "tags": [{"key": "team", "value": "a"}]});
        let (status, body) = admin.send("POST", "/api/roles", Some(new.clone())).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(admin.send("POST", "/api/roles", Some(new)).await.0, StatusCode::CONFLICT);
        let bad = json!({"name": "bad", "trust": "{}"});
        assert_eq!(admin.send("POST", "/api/roles", Some(bad)).await.0, StatusCode::BAD_REQUEST);

        let (status, roles) = admin.send("GET", "/api/roles", None).await;
        assert_eq!(status, StatusCode::OK);
        let role = &roles[0];
        assert_eq!(role["name"], "deployer");
        assert_eq!(role["arn"], format!("arn:aws:iam::{account}:role/ci/deployer"));
        assert_eq!(role["max_session_duration"], 7200);
        assert_eq!(role["tags"], json!([{"key": "team", "value": "a"}]));
        assert!(role["trust"].as_str().unwrap().contains(":root"));

        let change = json!({"description": "deploys things", "max_session_duration": 3600});
        assert_eq!(admin.send("PATCH", "/api/roles/deployer", Some(change)).await.0, StatusCode::NO_CONTENT);
        let tags = json!({"tags": [{"key": "env", "value": "prod"}]});
        assert_eq!(admin.send("PUT", "/api/roles/deployer/tags", Some(tags)).await.0, StatusCode::NO_CONTENT);
        let read = json!({"document": r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#});
        assert_eq!(admin.send("PUT", "/api/roles/deployer/policies/read", Some(read)).await.0, StatusCode::NO_CONTENT);
        let s3_read = crate::managed::aws_arn("AmazonS3ReadOnlyAccess");
        let attach = json!({"arn": s3_read});
        assert_eq!(admin.send("POST", "/api/roles/deployer/attached", Some(attach)).await.0, StatusCode::NO_CONTENT);
        assert_eq!(admin.send("POST", "/api/roles/deployer/revoke-sessions", None).await.0, StatusCode::NO_CONTENT);
        let (_, roles) = admin.send("GET", "/api/roles", None).await;
        assert_eq!(roles[0]["description"], "deploys things");
        assert_eq!(roles[0]["tags"], json!([{"key": "env", "value": "prod"}]));
        assert_eq!(roles[0]["policies"], json!(["AWSRevokeOlderSessions", "read"]));
        assert_eq!(roles[0]["attached"][0]["name"], "AmazonS3ReadOnlyAccess");
        let (_, revoke) = admin.send("GET", "/api/roles/deployer/policies/AWSRevokeOlderSessions", None).await;
        assert!(revoke["document"].as_str().unwrap().contains("aws:TokenIssueTime"), "{revoke}");
        let (_, policies) = admin.send("GET", "/api/policies", None).await;
        let s3 = policies.as_array().unwrap().iter().find(|p| p["arn"] == s3_read.as_str()).unwrap();
        assert_eq!(s3["roles"], json!(["deployer"]));

        // A new trust policy, checked as IAM checks one.
        let nobody = json!({"document": trust.replace(":root", ":user/nobody")});
        assert_eq!(admin.send("PUT", "/api/roles/deployer/trust", Some(nobody)).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(admin.send("PUT", "/api/roles/deployer/trust", Some(json!({"document": trust}))).await.0, StatusCode::NO_CONTENT);

        // Someone without IAM's actions.
        let mut bob = signed_in(&console, "bob", false).await;
        assert_eq!(bob.send("GET", "/api/roles", None).await.0, StatusCode::FORBIDDEN);
        assert_eq!(bob.send("DELETE", "/api/roles/deployer", None).await.0, StatusCode::FORBIDDEN);

        // Deleted once its policies are gone.
        assert_eq!(admin.send("DELETE", "/api/roles/deployer", None).await.0, StatusCode::CONFLICT);
        for policy in ["read", "AWSRevokeOlderSessions"] {
            let path = format!("/api/roles/deployer/policies/{policy}");
            assert_eq!(admin.send("DELETE", &path, None).await.0, StatusCode::NO_CONTENT);
        }
        let detach = format!("/api/roles/deployer/attached?arn={}", s3_read.replace(':', "%3A").replace('/', "%2F"));
        assert_eq!(admin.send("DELETE", &detach, None).await.0, StatusCode::NO_CONTENT);
        assert_eq!(admin.send("DELETE", "/api/roles/deployer", None).await.0, StatusCode::NO_CONTENT);
        assert_eq!(admin.send("GET", "/api/roles", None).await.1, json!([]));
    }

    /// Identity providers: added once their issuer can be reached (on a
    /// private address only once the operator allows it, through a private
    /// CA by its thumbprint), changed and deleted; and the roles that trust
    /// them listed.
    #[tokio::test]
    async fn manages_identity_providers() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else { return };
        let console = console_of(&app);
        let mut admin = signed_in(&console, "ada", true).await;
        let mut ops = superadmin(&console, "op").await;
        let mock = Mock::start_https().await;
        let new = json!({"url": mock.issuer, "client_ids": ["sts.amazonaws.com", "sts.amazonaws.com"],
                         "thumbprints": [CA_THUMBPRINT], "tags": [{"key": "team", "value": "ci"}]});
        let (status, err) = admin.send("POST", "/api/identity-providers", Some(new.clone())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(err["error"].as_str().unwrap().contains("public address"), "{err}");
        let (_, list) = admin.send("GET", "/api/identity-providers", None).await;
        assert_eq!(list["private_issuers"], false);

        let (status, _) = ops.send("PUT", "/api/settings/oidc-private-issuers", Some(json!({"value": 1}))).await;
        assert_eq!(status, StatusCode::OK);
        let unpinned = json!({"url": mock.issuer, "client_ids": ["x"]});
        assert_eq!(admin.send("POST", "/api/identity-providers", Some(unpinned)).await.0, StatusCode::BAD_REQUEST);
        let (status, err) = admin.send("POST", "/api/identity-providers", Some(new.clone())).await;
        assert_eq!(status, StatusCode::CREATED, "{err}");
        assert_eq!(admin.send("POST", "/api/identity-providers", Some(new)).await.0, StatusCode::CONFLICT);

        let (_, list) = admin.send("GET", "/api/identity-providers", None).await;
        assert_eq!(list["private_issuers"], true);
        let provider = list["providers"][0].clone();
        let url = mock.issuer.strip_prefix("https://").unwrap();
        assert_eq!(provider["url"], url);
        assert_eq!(provider["client_ids"], json!(["sts.amazonaws.com"]));
        assert_eq!(provider["thumbprints"], json!([CA_THUMBPRINT]));
        let arn = provider["arn"].as_str().unwrap().to_owned();
        let trust = json!({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Federated": arn}, "Action": "sts:AssumeRoleWithWebIdentity",
        }]})
        .to_string();
        let role = json!({"name": "ci", "trust": trust});
        assert_eq!(admin.send("POST", "/api/roles", Some(role)).await.0, StatusCode::CREATED);
        let (_, list) = admin.send("GET", "/api/identity-providers", None).await;
        assert_eq!(list["providers"][0]["roles"], json!(["ci"]));

        let id = provider["id"].as_str().unwrap();
        let change = json!({"client_ids": ["a", "b"], "thumbprints": [CA_THUMBPRINT, "00".repeat(20)], "tags": []});
        let (status, err) = admin.send("PUT", &format!("/api/identity-providers/{id}"), Some(change)).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{err}");
        let (_, list) = admin.send("GET", "/api/identity-providers", None).await;
        assert_eq!(list["providers"][0]["client_ids"], json!(["a", "b"]));
        assert_eq!(list["providers"][0]["thumbprints"], json!([CA_THUMBPRINT, "00".repeat(20)]));
        assert_eq!(list["providers"][0]["tags"], json!([]));

        let mut bob = signed_in(&console, "bob", false).await;
        assert_eq!(bob.send("GET", "/api/identity-providers", None).await.0, StatusCode::FORBIDDEN);
        assert_eq!(bob.send("DELETE", &format!("/api/identity-providers/{id}"), None).await.0, StatusCode::FORBIDDEN);
        assert_eq!(admin.send("DELETE", &format!("/api/identity-providers/{id}"), None).await.0, StatusCode::NO_CONTENT);
        assert_eq!(admin.send("GET", "/api/identity-providers", None).await.1["providers"], json!([]));
    }
}
