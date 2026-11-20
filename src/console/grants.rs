//! The console's API for S3 Access Grants (see `s3::access_grants`): the
//! account's instance, its locations and its grants. Each call is S3
//! Control's own request (`access_grants::dispatch`), run as the session's
//! identity, so it's checked and validated exactly as S3 Control checks it
//! (its actions, `s3:AccessGrantScope`, `s3:AccessGrantsLocationScope`, and
//! `iam:PassRole` on a location's role); reads take what that answers
//! apart.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use http_body_util::BodyExt;
use hyper::{Method, body::Bytes};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::actor::Actor;
use super::manage::{AppState, Result, s3_error};
use super::web::{ApiError, ErrorBody};
use crate::{App, s3::access_grants, s3::util::xml_escape};

pub(super) fn router() -> OpenApiRouter<Arc<App>> {
    OpenApiRouter::new()
        .routes(routes!(get_access_grants))
        .routes(routes!(
            create_access_grants_instance,
            delete_access_grants_instance
        ))
        .routes(routes!(create_access_grants_location))
        .routes(routes!(
            update_access_grants_location,
            delete_access_grants_location
        ))
        .routes(routes!(create_access_grant))
        .routes(routes!(delete_access_grant))
}

/// Where S3 Control's Access Grants requests are.
const ROOT: &str = "/v20180820/accessgrantsinstance";

/// Runs S3 Control's request `method` to `ROOT` + `path`, as `actor`, with
/// `query` and `body` (XML, none if empty): its answer's body (XML).
async fn call(
    app: &Arc<App>,
    actor: &Actor,
    method: Method,
    path: &str,
    query: &str,
    body: String,
) -> Result<String> {
    let mut access = actor.access_for(app).await?;
    let body = (!body.is_empty()).then(|| Bytes::from(body));
    let resp = access_grants::dispatch(
        app,
        actor.principal(),
        &mut access,
        &method,
        &format!("{ROOT}{path}"),
        query,
        body,
    )
    .await?;
    if !resp.status().is_success() {
        return Err(s3_error(resp).await);
    }
    let body = resp
        .into_body()
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    Ok(String::from_utf8_lossy(&body).into_owned())
}

fn encode(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

fn element(name: &str, text: &str) -> String {
    format!("<{name}>{}</{name}>", xml_escape(text))
}

fn child<'a, 'i>(node: roxmltree::Node<'a, 'i>, name: &str) -> Option<roxmltree::Node<'a, 'i>> {
    node.children()
        .find(|n| n.is_element() && n.tag_name().name() == name)
}

fn text(node: roxmltree::Node, name: &str) -> String {
    child(node, name)
        .and_then(|n| n.text())
        .unwrap_or("")
        .to_owned()
}

/// The elements of the list `list` of an answer, each `item`.
fn items<'a, 'i>(
    doc: &'a roxmltree::Document<'i>,
    list: &str,
) -> impl Iterator<Item = roxmltree::Node<'a, 'i>> {
    child(doc.root_element(), list)
        .into_iter()
        .flat_map(|l| l.children().filter(|c| c.is_element()))
}

/// What may be read, or nothing if it may not be (`Forbidden`).
fn allowed<T>(result: Result<T>) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(ApiError::Forbidden(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// The account's instance.
#[derive(Serialize, ToSchema)]
struct GrantsInstance {
    arn: String,
    /// ISO 8601.
    created_at: String,
}

/// A location: a scope, and the role its grants' sessions are of.
#[derive(Serialize, ToSchema)]
struct GrantsLocation {
    id: String,
    arn: String,
    /// `s3://`, `s3://bucket`, `s3://bucket/prefix*`.
    scope: String,
    role_arn: String,
    created_at: String,
}

/// A grant: a grantee's permission on a scope within a location.
#[derive(Serialize, ToSchema)]
struct AccessGrant {
    id: String,
    arn: String,
    location_id: String,
    /// `IAM` (an IAM user's or role's ARN).
    grantee_type: String,
    grantee: String,
    /// `READ`, `WRITE` or `READWRITE`.
    permission: String,
    scope: String,
    created_at: String,
}

/// The account's Access Grants: its instance, if it has one, and its
/// locations and grants, each if they may be seen.
#[derive(Serialize, ToSchema)]
struct AccessGrants {
    instance: Option<GrantsInstance>,
    /// Whether the instance may be seen (`s3:GetAccessGrantsInstance`).
    visible: bool,
    locations: Option<Vec<GrantsLocation>>,
    grants: Option<Vec<AccessGrant>>,
}

/// Every page of the listing `path` (XML).
async fn listed(app: &Arc<App>, actor: &Actor, path: &str) -> Result<Vec<String>> {
    let mut pages = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let query = token
            .as_deref()
            .map(|t| format!("nextToken={}", encode(t)))
            .unwrap_or_default();
        let xml = call(app, actor, Method::GET, path, &query, String::new()).await?;
        let doc = roxmltree::Document::parse(&xml).map_err(anyhow::Error::from)?;
        token = Some(text(doc.root_element(), "NextToken")).filter(|t| !t.is_empty());
        pages.push(xml);
        if token.is_none() {
            break;
        }
    }
    Ok(pages)
}

#[utoipa::path(get, path = "/access-grants", responses(
    (status = 200, body = AccessGrants),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn get_access_grants(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
) -> Result<Json<AccessGrants>> {
    let instance = match call(&app, &actor, Method::GET, "", "", String::new()).await {
        Ok(xml) => {
            let doc = roxmltree::Document::parse(&xml).map_err(anyhow::Error::from)?;
            let root = doc.root_element();
            Some(Some(GrantsInstance {
                arn: text(root, "AccessGrantsInstanceArn"),
                created_at: text(root, "CreatedAt"),
            }))
        }
        Err(ApiError::NotFound(_)) => Some(None),
        Err(ApiError::Forbidden(_)) => None,
        Err(e) => return Err(e),
    };
    let (visible, instance) = (instance.is_some(), instance.flatten());
    let mut locations = None;
    let mut grants = None;
    if instance.is_some() {
        let pages = allowed(listed(&app, &actor, "/locations").await)?;
        locations = pages.map(|pages| {
            let mut out = Vec::new();
            for xml in pages {
                let Ok(doc) = roxmltree::Document::parse(&xml) else {
                    continue;
                };
                out.extend(
                    items(&doc, "AccessGrantsLocationsList").map(|l| GrantsLocation {
                        id: text(l, "AccessGrantsLocationId"),
                        arn: text(l, "AccessGrantsLocationArn"),
                        scope: text(l, "LocationScope"),
                        role_arn: text(l, "IAMRoleArn"),
                        created_at: text(l, "CreatedAt"),
                    }),
                );
            }
            out
        });
        let pages = allowed(listed(&app, &actor, "/grants").await)?;
        grants = pages.map(|pages| {
            let mut out = Vec::new();
            for xml in pages {
                let Ok(doc) = roxmltree::Document::parse(&xml) else {
                    continue;
                };
                out.extend(items(&doc, "AccessGrantsList").map(|g| {
                    let grantee = child(g, "Grantee");
                    AccessGrant {
                        id: text(g, "AccessGrantId"),
                        arn: text(g, "AccessGrantArn"),
                        location_id: text(g, "AccessGrantsLocationId"),
                        grantee_type: grantee.map(|n| text(n, "GranteeType")).unwrap_or_default(),
                        grantee: grantee
                            .map(|n| text(n, "GranteeIdentifier"))
                            .unwrap_or_default(),
                        permission: text(g, "Permission"),
                        scope: text(g, "GrantScope"),
                        created_at: text(g, "CreatedAt"),
                    }
                }));
            }
            out
        });
    }
    Ok(Json(AccessGrants {
        instance,
        visible,
        locations,
        grants,
    }))
}

/// Makes the account's instance, as CreateAccessGrantsInstance does.
#[utoipa::path(post, path = "/access-grants/instance", responses(
    (status = 201, description = "Made"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_access_grants_instance(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
) -> Result<StatusCode> {
    call(&app, &actor, Method::POST, "", "", String::new()).await?;
    Ok(StatusCode::CREATED)
}

/// Deletes the account's instance, as DeleteAccessGrantsInstance does:
/// one without locations only.
#[utoipa::path(delete, path = "/access-grants/instance", responses(
    (status = 204, description = "Deleted"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_access_grants_instance(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
) -> Result<StatusCode> {
    call(&app, &actor, Method::DELETE, "", "", String::new()).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct NewGrantsLocation {
    /// `s3://`, `s3://bucket` or `s3://bucket/prefix*`.
    scope: String,
    role_arn: String,
}

/// Registers a location, as CreateAccessGrantsLocation does.
#[utoipa::path(post, path = "/access-grants/locations", request_body = NewGrantsLocation, responses(
    (status = 201, description = "Made"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_access_grants_location(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Json(body): Json<NewGrantsLocation>,
) -> Result<StatusCode> {
    let request = format!(
        "<CreateAccessGrantsLocationRequest>{}{}</CreateAccessGrantsLocationRequest>",
        element("LocationScope", &body.scope),
        element("IAMRoleArn", &body.role_arn)
    );
    call(&app, &actor, Method::POST, "/location", "", request).await?;
    Ok(StatusCode::CREATED)
}

#[derive(Deserialize, ToSchema)]
struct GrantsLocationRole {
    role_arn: String,
}

/// Changes a location's role, as UpdateAccessGrantsLocation does.
#[utoipa::path(put, path = "/access-grants/locations/{id}", params(("id" = String, Path)),
    request_body = GrantsLocationRole, responses(
    (status = 204, description = "Changed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn update_access_grants_location(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
    Json(body): Json<GrantsLocationRole>,
) -> Result<StatusCode> {
    let request = format!(
        "<UpdateAccessGrantsLocationRequest>{}</UpdateAccessGrantsLocationRequest>",
        element("IAMRoleArn", &body.role_arn)
    );
    let path = format!("/location/{}", encode(&id));
    call(&app, &actor, Method::PUT, &path, "", request).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes a location, as DeleteAccessGrantsLocation does: one without
/// grants only.
#[utoipa::path(delete, path = "/access-grants/locations/{id}", params(("id" = String, Path)), responses(
    (status = 204, description = "Deleted"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_access_grants_location(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    let path = format!("/location/{}", encode(&id));
    call(&app, &actor, Method::DELETE, &path, "", String::new()).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct NewAccessGrant {
    location_id: String,
    /// Within the location's scope (empty: all of it).
    #[serde(default)]
    sub_prefix: String,
    /// Whether the sub-prefix is one object's key.
    #[serde(default)]
    object: bool,
    /// `IAM` (Cairn has no IAM Identity Center grantees).
    grantee_type: String,
    /// An IAM user's or role's ARN.
    grantee: String,
    /// `READ`, `WRITE` or `READWRITE`.
    permission: String,
}

/// Makes a grant, as CreateAccessGrant does.
#[utoipa::path(post, path = "/access-grants/grants", request_body = NewAccessGrant, responses(
    (status = 201, description = "Made"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn create_access_grant(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Json(body): Json<NewAccessGrant>,
) -> Result<StatusCode> {
    let configuration = match body.sub_prefix.is_empty() {
        true => String::new(),
        false => format!(
            "<AccessGrantsLocationConfiguration>{}</AccessGrantsLocationConfiguration>",
            element("S3SubPrefix", &body.sub_prefix)
        ),
    };
    let object = match body.object {
        true => "<S3PrefixType>Object</S3PrefixType>",
        false => "",
    };
    let request = format!(
        "<CreateAccessGrantRequest>{}{configuration}<Grantee>{}{}</Grantee>{}{object}</CreateAccessGrantRequest>",
        element("AccessGrantsLocationId", &body.location_id),
        element("GranteeType", &body.grantee_type),
        element("GranteeIdentifier", &body.grantee),
        element("Permission", &body.permission),
    );
    call(&app, &actor, Method::POST, "/grant", "", request).await?;
    Ok(StatusCode::CREATED)
}

/// Deletes a grant, as DeleteAccessGrant does.
#[utoipa::path(delete, path = "/access-grants/grants/{id}", params(("id" = String, Path)), responses(
    (status = 204, description = "Deleted"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_access_grant(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    let path = format!("/grant/{}", encode(&id));
    call(&app, &actor, Method::DELETE, &path, "", String::new()).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod e2e {
    use axum::http::StatusCode;
    use serde_json::{Value, json};

    use super::super::e2e::{console_of, signed_in};
    use crate::{e2e::BUCKET, roles, s3::access_grants::SERVICE};

    /// The account's instance, a location and a grant, as the console makes
    /// and deletes them: S3 Control's requests, checked as S3 Control checks
    /// them (`iam:PassRole` on a location's role too).
    #[tokio::test]
    async fn manages_access_grants() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let console = console_of(&app);
        let mut admin = signed_in(&console, "admin", true).await;
        let mut user = signed_in(&console, "reader", false).await;
        let client = app.pool.get().await.unwrap();
        let account = crate::users::account(&client).await.unwrap();
        let trust = format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"{SERVICE}"}},"Action":"sts:AssumeRole"}}]}}"#
        );
        let trust = roles::check_trust(&client, &account, &trust).await.unwrap();
        let new = roles::New {
            name: "grants",
            path: "/",
            trust: &trust,
            description: "",
            max_session_duration: 3600,
            boundary: None,
            tags: &[],
        };
        roles::create(&client, &account, &new).await.unwrap();
        let role = format!("arn:aws:iam::{account}:role/grants");

        // None yet; and the user may not see it.
        let (status, grants) = admin.send("GET", "/api/access-grants", None).await;
        assert_eq!(status, StatusCode::OK, "{grants}");
        assert_eq!(grants["visible"], true);
        assert_eq!(grants["instance"], Value::Null);
        let (_, grants) = user.send("GET", "/api/access-grants", None).await;
        assert_eq!(grants["visible"], false);
        assert_eq!(
            user.send("POST", "/api/access-grants/instance", None)
                .await
                .0,
            StatusCode::FORBIDDEN
        );

        assert_eq!(
            admin
                .send("POST", "/api/access-grants/instance", None)
                .await
                .0,
            StatusCode::CREATED
        );
        assert_eq!(
            admin
                .send("POST", "/api/access-grants/instance", None)
                .await
                .0,
            StatusCode::CONFLICT
        );

        let location = |scope: &str, role: &str| Some(json!({ "scope": scope, "role_arn": role }));
        let scope = format!("s3://{BUCKET}");
        let (status, _) = admin
            .send(
                "POST",
                "/api/access-grants/locations",
                location("s3:/x", &role),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let missing = format!("arn:aws:iam::{account}:role/missing");
        let (status, _) = admin
            .send(
                "POST",
                "/api/access-grants/locations",
                location(&scope, &missing),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, body) = admin
            .send(
                "POST",
                "/api/access-grants/locations",
                location(&scope, &role),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");

        let (_, grants) = admin.send("GET", "/api/access-grants", None).await;
        assert!(
            grants["instance"]["arn"]
                .as_str()
                .unwrap()
                .ends_with(&format!(":{account}:access-grants/default"))
        );
        assert_eq!(grants["locations"][0]["scope"], scope);
        assert_eq!(grants["locations"][0]["role_arn"], role);
        assert_eq!(grants["grants"], json!([]));
        let location_id = grants["locations"][0]["id"].as_str().unwrap().to_owned();

        let grantee = format!("arn:aws:iam::{account}:user/reader");
        let grant = |permission: &str| {
            Some(json!({
                "location_id": location_id,
                "sub_prefix": "reports/*",
                "grantee_type": "IAM",
                "grantee": grantee,
                "permission": permission,
            }))
        };
        let (status, _) = admin
            .send("POST", "/api/access-grants/grants", grant("ALL"))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, body) = admin
            .send("POST", "/api/access-grants/grants", grant("READ"))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let (_, grants) = admin.send("GET", "/api/access-grants", None).await;
        let made = &grants["grants"][0];
        assert_eq!(made["scope"], format!("s3://{BUCKET}/reports/*"));
        assert_eq!(made["grantee"], grantee);
        assert_eq!(made["grantee_type"], "IAM");
        assert_eq!(made["permission"], "READ");
        assert_eq!(made["location_id"], location_id);
        let grant_id = made["id"].as_str().unwrap().to_owned();

        // A location's role is passed: iam:PassRole on it too.
        let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*AccessGrant*"],"Resource":"*"}]}"#;
        crate::users::put_policy(&client, &account, "reader", "p", policy)
            .await
            .unwrap();
        let (status, body) = user
            .send(
                "PUT",
                &format!("/api/access-grants/locations/{location_id}"),
                Some(json!({ "role_arn": role })),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            body["error"].as_str().unwrap().contains("iam:PassRole"),
            "{body}"
        );
        let (status, _) = admin
            .send(
                "PUT",
                &format!("/api/access-grants/locations/{location_id}"),
                Some(json!({ "role_arn": role })),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Not while they have what's in them.
        let location_path = format!("/api/access-grants/locations/{location_id}");
        assert_eq!(
            admin.send("DELETE", &location_path, None).await.0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            admin
                .send("DELETE", "/api/access-grants/instance", None)
                .await
                .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            admin
                .send(
                    "DELETE",
                    &format!("/api/access-grants/grants/{grant_id}"),
                    None
                )
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            admin.send("DELETE", &location_path, None).await.0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            admin
                .send("DELETE", "/api/access-grants/instance", None)
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        let (_, grants) = admin.send("GET", "/api/access-grants", None).await;
        assert_eq!(grants["instance"], Value::Null);
    }
}
