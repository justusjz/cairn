//! The console's API for policy templates (see `templates`): what there are,
//! what one makes (a preview), and making it, as IAM's CreatePolicy and
//! TagPolicy by the session's identity, each checked as the IAM API checks
//! them. All of a use's policies are made, or none.

use std::sync::Arc;

use axum::{Json, extract::{Extension, State}, http::StatusCode};
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::actor::Actor;
use super::manage::{AppState, Result, Tag};
use super::web::{ApiError, ErrorBody};
use crate::s3::actions::On;
use crate::templates::{self, Made, Template, Use};
use crate::{App, managed, users};

pub(super) fn router() -> OpenApiRouter<Arc<App>> {
    OpenApiRouter::new()
        .routes(routes!(list_templates, use_template))
        .routes(routes!(preview_template))
}

/// A managed policy a template makes.
#[derive(Serialize, ToSchema)]
struct MadePolicy {
    arn: String,
    path: String,
    name: String,
    description: String,
    document: String,
    tags: Vec<Tag>,
}

fn shown(account: &str, made: Vec<Made>) -> Vec<MadePolicy> {
    made.into_iter()
        .map(|m| MadePolicy {
            arn: managed::arn(account, &m.path, &m.name),
            tags: m.tags.into_iter().map(|(key, value)| Tag { key, value }).collect(),
            path: m.path,
            name: m.name,
            description: m.description,
            document: m.document,
        })
        .collect()
}

/// The templates there are.
#[utoipa::path(get, path = "/templates", responses(
    (status = 200, body = Vec<Template>),
    (status = "4XX", body = ErrorBody),
))]
async fn list_templates() -> Json<&'static [Template]> {
    Json(templates::TEMPLATES)
}

/// What a template would make, used so: nothing is made.
#[utoipa::path(post, path = "/templates/preview", request_body = Use, responses(
    (status = 200, body = Vec<MadePolicy>),
    (status = "4XX", body = ErrorBody),
))]
async fn preview_template(Extension(actor): Extension<Actor>, Json(body): Json<Use>) -> Result<Json<Vec<MadePolicy>>> {
    let made = body.make(actor.account()).map_err(ApiError::BadRequest)?;
    Ok(Json(shown(actor.account(), made)))
}

/// Makes a template's policies, as IAM's CreatePolicy (with their tags,
/// TagPolicy too) would: all of them, or none.
#[utoipa::path(post, path = "/templates", request_body = Use, responses(
    (status = 201, body = Vec<MadePolicy>),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn use_template(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Json(body): Json<Use>,
) -> Result<(StatusCode, Json<Vec<MadePolicy>>)> {
    let account = actor.account().to_owned();
    let made = body.make(&account).map_err(ApiError::BadRequest)?;
    // Every one allowed first, so that none is made unless all may be.
    for m in &made {
        let on = || On::policy(&account, &m.path, &m.name);
        let asked = users::request_tags_context(&m.tags);
        actor.check_with(&app, "iam:CreatePolicy", on(), &asked).await?;
        actor.check_with(&app, "iam:TagPolicy", on(), &asked).await?;
    }
    let client = app.pool.get().await?;
    let mut done: Vec<String> = Vec::new();
    for m in &made {
        match managed::create_tagged(&client, &account, &m.name, &m.path, &m.document, &m.description, &m.tags).await {
            Ok(policy) => done.push(policy.name),
            Err(e) => {
                for name in &done {
                    if let Err(e) = managed::delete(&client, &account, name).await {
                        eprintln!("templates: taking back policy {name}: {e:#}");
                    }
                }
                return Err(e.into());
            }
        }
    }
    Ok((StatusCode::CREATED, Json(shown(&account, made))))
}

#[cfg(test)]
mod e2e {
    use axum::http::StatusCode;
    use serde_json::{Value, json};

    use super::super::e2e::{Browser, console_of, signed_in};
    use crate::{managed, users};

    /// `user` (made at `/`) moved to `path`, with the boundary `boundary`
    /// and the managed policies `attached`, as the account's admin would.
    async fn set_up(app: &crate::App, user: &str, path: &str, boundary: Option<&str>, attached: &[&str]) {
        let client = app.pool.get().await.unwrap();
        let account = users::account(&client).await.unwrap();
        let id = users::id_of(&client, &account, user).await.unwrap();
        users::rename(&client, &account, id, user, path).await.unwrap();
        if let Some(arn) = boundary {
            let boundary = managed::boundary(&client, &account, arn).await.unwrap();
            users::set_boundary(&client, &account, id, Some(&boundary)).await.unwrap();
        }
        for arn in attached {
            managed::attach(&client, &account, user, arn, true).await.unwrap();
        }
    }

    async fn allowed(who: &mut Browser, method: &str, path: &str, body: Option<Value>) {
        let (status, answer) = who.send(method, path, body).await;
        assert!(status.is_success(), "{method} {path}: {status} {answer}");
    }

    async fn denied(who: &mut Browser, method: &str, path: &str, body: Option<Value>) {
        let (status, answer) = who.send(method, path, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {answer}");
    }

    /// The team template: its admin manages the team's users, roles,
    /// policies and buckets, and can't get out of them; nor can a member it
    /// made an admin of everything (AdministratorAccess, capped by the
    /// boundary), nor an admin with the team's policy and no boundary.
    #[tokio::test]
    async fn a_team_stays_in_its_sandbox() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else { return };
        let console = console_of(&app);
        let client = app.pool.get().await.unwrap();
        let account = users::account(&client).await.unwrap();
        let mut root = signed_in(&console, "root-admin", true).await;

        // Only the account's admins may make a team: its policies are at
        // Cairn's path.
        let team = json!({ "template": "team", "team": "oneai", "bucket_prefix": "oneai-dev-" });
        let (status, preview) = root.send("POST", "/api/templates/preview", Some(team.clone())).await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        let names: Vec<&str> = preview.as_array().unwrap().iter().map(|p| p["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["oneai-team", "oneai-member"]);
        allowed(&mut root, "POST", "/api/templates", Some(team.clone())).await;
        let (status, _) = root.send("POST", "/api/templates", Some(team)).await;
        assert_eq!(status, StatusCode::CONFLICT);
        let policy = |name: &str| format!("arn:aws:iam::{account}:policy/cairn/teams/oneai/{name}");
        // The team's policy is its admins' and everyone's boundary.
        let (boundary, member) = (policy("oneai-team"), policy("oneai-member"));
        let admin = boundary.clone();
        let administrator = managed::aws_arn(managed::ADMINISTRATOR_ACCESS);

        let mut lead = signed_in(&console, "lead", false).await;
        set_up(&app, "lead", "/oneai/", Some(&boundary), &[&admin]).await;
        let _outsider = signed_in(&console, "outsider", false).await;
        let other = json!({ "template": "team", "team": "other" });
        allowed(&mut root, "POST", "/api/templates", Some(other)).await;
        allowed(&mut root, "POST", "/api/buckets", Some(json!({ "name": "other-data" }))).await;

        // What the team's admin may: its buckets, bounded users and roles
        // at its path, their keys and policies, policies at its path (by
        // template too).
        allowed(&mut lead, "POST", "/api/buckets", Some(json!({ "name": "oneai-dev-data" }))).await;
        let new_user = |name: &str, path: &str, boundary: Option<&str>| json!({ "name": name, "path": path, "boundary": boundary });
        allowed(&mut lead, "POST", "/api/users", Some(new_user("dev", "/oneai/", Some(&boundary)))).await;
        allowed(&mut lead, "POST", "/api/users/dev/attached", Some(json!({ "arn": member }))).await;
        allowed(&mut lead, "POST", "/api/users/dev/keys", None).await;
        let read = json!({ "template": "bucket-access", "buckets": "oneai-dev-data", "levels": ["read"], "path": "/oneai/" });
        allowed(&mut lead, "POST", "/api/templates", Some(read)).await;
        let trust = format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{account}:root"}},"Action":"sts:AssumeRole"}}]}}"#
        );
        let new_role = |name: &str, path: &str, boundary: Option<&str>| json!({ "name": name, "path": path, "trust": trust, "boundary": boundary });
        allowed(&mut lead, "POST", "/api/roles", Some(new_role("ci", "/oneai/", Some(&boundary)))).await;
        allowed(&mut lead, "POST", "/api/roles/ci/attached", Some(json!({ "arn": administrator }))).await;
        // A member made an admin of everything: capped by the boundary.
        allowed(&mut lead, "POST", "/api/users/dev/attached", Some(json!({ "arn": administrator }))).await;

        // The ways out, which the team's admin, a member it made an admin,
        // and an admin with the team's policy and no boundary all lack.
        let mut deputy = signed_in(&console, "deputy", false).await;
        set_up(&app, "deputy", "/oneai/", Some(&boundary), &[&administrator]).await;
        let mut unbounded = signed_in(&console, "unbounded", false).await;
        set_up(&app, "unbounded", "/oneai/", None, &[&admin]).await;
        let mut n = 0;
        for who in [&mut lead, &mut deputy, &mut unbounded] {
            n += 1;
            // Users and roles without the team's boundary, or elsewhere.
            denied(who, "POST", "/api/users", Some(new_user(&format!("free{n}"), "/oneai/", None))).await;
            let s3_full = managed::aws_arn("AmazonS3FullAccess");
            denied(who, "POST", "/api/users", Some(new_user(&format!("free{n}"), "/oneai/", Some(&s3_full)))).await;
            denied(who, "POST", "/api/users", Some(new_user(&format!("free{n}"), "/", Some(&boundary)))).await;
            denied(who, "POST", "/api/roles", Some(new_role(&format!("free{n}"), "/oneai/", None))).await;
            denied(who, "POST", "/api/roles", Some(new_role(&format!("free{n}"), "/", Some(&boundary)))).await;
            // Taking a boundary off, or changing it.
            denied(who, "DELETE", "/api/users/dev/boundary", None).await;
            denied(who, "PUT", "/api/users/dev/boundary", Some(json!({ "arn": s3_full }))).await;
            denied(who, "DELETE", "/api/roles/ci/boundary", None).await;
            // The team's own policies, and grants'.
            for name in ["oneai-team", "oneai-member"] {
                let document = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;
                denied(who, "PUT", &format!("/api/policies/{name}"), Some(json!({ "document": document }))).await;
                denied(who, "DELETE", &format!("/api/policies/{name}"), None).await;
                denied(who, "PUT", &format!("/api/policies/{name}/default"), Some(json!({ "version": 1 }))).await;
                denied(who, "PUT", &format!("/api/policies/{name}/tags"), Some(json!({ "tags": [] }))).await;
            }
            let anything = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;
            for path in ["/cairn/grants/", "/other/", "/"] {
                let body = json!({ "name": format!("planted{n}"), "path": path, "document": anything });
                denied(who, "POST", "/api/policies", Some(body)).await;
            }
            // Users outside the team: not moved in, nor out, nor given
            // anything.
            denied(who, "PATCH", "/api/users/outsider", Some(json!({ "path": "/oneai/" }))).await;
            denied(who, "PATCH", "/api/users/dev", Some(json!({ "path": "/" }))).await;
            denied(who, "POST", "/api/users/outsider/attached", Some(json!({ "arn": administrator }))).await;
            denied(who, "PUT", "/api/users/outsider/policies/p", Some(json!({ "document": anything }))).await;
            denied(who, "POST", "/api/users/outsider/keys", None).await;
            // Other buckets, the account's settings, the cluster.
            denied(who, "POST", "/api/buckets", Some(json!({ "name": format!("elsewhere-{n}") }))).await;
            denied(who, "DELETE", "/api/buckets/other-data", None).await;
            denied(who, "PUT", "/api/buckets/other-data/policy", Some(json!({ "document": "{}" }))).await;
            denied(who, "DELETE", "/api/account/public-access-block", None).await;
            denied(who, "GET", "/api/cluster", None).await;
            // Another team's templates.
            denied(who, "POST", "/api/templates", Some(json!({ "template": "team", "team": format!("rogue{n}") }))).await;
        }
        // The member made an admin works within the team.
        allowed(&mut deputy, "POST", "/api/buckets", Some(json!({ "name": "oneai-dev-more" }))).await;

        // What the team's admin sees: its users, its buckets, and the
        // policies it may read (Cairn's, the team's), not the others'.
        let (_, listed) = lead.send("GET", "/api/users", None).await;
        let mut names: Vec<&str> = listed.as_array().unwrap().iter().map(|u| u["name"].as_str().unwrap()).collect();
        names.sort();
        assert_eq!(names, ["deputy", "dev", "lead", "unbounded"]);
        let (_, buckets) = lead.send("GET", "/api/buckets", None).await;
        let mut names: Vec<&str> = buckets.as_array().unwrap().iter().map(|b| b["name"].as_str().unwrap()).collect();
        names.sort();
        assert_eq!(names, ["oneai-dev-data", "oneai-dev-more"]);
        let (status, policies) = lead.send("GET", "/api/policies", None).await;
        assert_eq!(status, StatusCode::OK, "{policies}");
        let names: Vec<&str> = policies.as_array().unwrap().iter().map(|p| p["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"oneai-team") && names.contains(&"oneai-dev-data-read"), "{names:?}");
        assert!(!names.contains(&"other-admin"), "{names:?}");

        // A member reads and writes the team's buckets, and its own keys.
        let mut dev = super::super::e2e::signed_in_as(&console, &account, "dev").await;
        let detach = format!("/api/users/dev/attached?arn={}", administrator.replace(':', "%3A").replace('/', "%2F"));
        allowed(&mut root, "DELETE", &detach, None).await;
        allowed(&mut dev, "POST", "/api/users/dev/keys", None).await;
        denied(&mut dev, "POST", "/api/users/lead/keys", None).await;
        denied(&mut dev, "POST", "/api/buckets", Some(json!({ "name": "oneai-dev-mine" }))).await;
    }
}
