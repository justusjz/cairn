//! IAM's actions on roles (see `roles`): as IAM answers them, probed
//! (`plans/roles.md`). Each is checked as IAM's own (`iam:CreateRole` on
//! the role's ARN, ...), as users' are.

use hyper::StatusCode;
use percent_encoding::utf8_percent_encode;

use super::{Error, Iam, Params, RFC3986, Result, Shown, Tagged, error, max_items, request_keys, request_tags, requested_boundary,
            requested_path, tags_context, tags_xml, validation};
use crate::{
    managed,
    policy::Context,
    roles::{self, Role},
    s3::{actions::On, util::xml_escape},
    users,
};

/// IAM's NoSuchEntity for role `name`.
fn no_such_role(name: &str) -> Error {
    error(StatusCode::NOT_FOUND, "NoSuchEntity", format!("The role with name {name} cannot be found."))
}

/// A role's name as a request gives it (`param`), checked as IAM checks it
/// (probed).
fn role_name<'p>(params: &'p Params, param: &str) -> Result<&'p str> {
    let name = params.required(param)?;
    if name.len() > 64 {
        return Err(validation(format!(
            "1 validation error detected: Value at '{}' failed to satisfy constraint: Member must have length less than or equal to 64",
            super::lower_first(param)
        )));
    }
    if !roles::valid_name(name) {
        return Err(validation(format!(
            "The specified value for {} is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
            super::lower_first(param)
        )));
    }
    Ok(name)
}

/// A document a request must give (`param`): IAM's message for one that's
/// missing (probed).
fn document<'p>(params: &'p Params, param: &str) -> Result<&'p str> {
    params.get(param).ok_or_else(|| {
        validation(format!(
            "1 validation error detected: Value at '{}' failed to satisfy constraint: Member must not be null",
            super::lower_first(param)
        ))
    })
}

/// `MaxSessionDuration`, if given, checked as IAM checks it (probed).
fn max_session_duration(params: &Params) -> Result<Option<i32>> {
    let Some(text) = params.get("MaxSessionDuration") else { return Ok(None) };
    let invalid = |bound: &str, n: i32| {
        validation(format!(
            "1 validation error detected: Value at 'maxSessionDuration' failed to satisfy constraint: Member must have value {bound} than or equal to {n}"
        ))
    };
    let (min, max) = (*roles::SESSION_DURATIONS.start(), *roles::SESSION_DURATIONS.end());
    match text.parse::<i64>() {
        Ok(n) if n < min as i64 => Err(invalid("greater", min)),
        Ok(n) if n > max as i64 => Err(invalid("less", max)),
        Ok(n) => Ok(Some(n as i32)),
        Err(_) => Err(validation(format!("Invalid value for parameter MaxSessionDuration: {text}"))),
    }
}

/// `Description`, if given, checked as IAM checks it (probed).
fn description(params: &Params) -> Result<Option<&str>> {
    match params.get("Description") {
        Some(d) if d.chars().count() > 1000 => Err(validation(
            "1 validation error detected: Value at 'description' failed to satisfy constraint: Member must have length less than or equal to 1000",
        )),
        d => Ok(d),
    }
}

/// A policy document as IAM gives one: URL-encoded (RFC 3986).
fn encoded(document: &str) -> String {
    xml_escape(&utf8_percent_encode(document, &RFC3986).to_string())
}

/// How much of a role a response shows (probed: each action shows its
/// own).
#[derive(Clone, Copy, PartialEq)]
enum Shows {
    /// CreateRole: its trust policy as given, its tags if any, its boundary.
    Created,
    /// GetRole: everything.
    Full,
    /// ListRoles: its description and longest session, no tags.
    Listed,
    /// UpdateRoleDescription: its description.
    Described,
}

impl Iam<'_> {
    /// The role a request names (`RoleName`), allowed `action` on it (with
    /// its condition keys, and `extra`): IAM's NoSuchEntity if there's none
    /// (`missing`), which is checked first as one would be, untagged.
    async fn role_with(&mut self, params: &Params, action: &'static str, extra: Context, missing: fn(&str) -> Error) -> Result<Role> {
        let name = params.required("RoleName")?.to_owned();
        let role = Role::load(self.client, self.account(), &name).await?;
        let (on, mut context) = match &role {
            Some(role) => (role.on(), role.context(action)),
            None => (On::role(self.account(), "/", &name), Context::default()),
        };
        context.extend(&extra);
        self.check_with(action, on, &context, Shown::Role(name.clone())).await?;
        role.ok_or_else(|| missing(&name))
    }

    async fn role(&mut self, params: &Params, action: &'static str) -> Result<Role> {
        self.role_with(params, action, Context::default(), no_such_role).await
    }

    /// A role as `shows` says, its trust policy `trust` (as given, or as
    /// GetRole shows it).
    fn role_xml(role: &Role, trust: &str, shows: Shows) -> String {
        let mut xml = format!(
            "<Path>{}</Path><RoleName>{}</RoleName><RoleId>{}</RoleId><Arn>{}</Arn><CreateDate>{}</CreateDate>\
             <AssumeRolePolicyDocument>{}</AssumeRolePolicyDocument>",
            xml_escape(&role.path),
            xml_escape(&role.name),
            roles::unique_id(role.id),
            xml_escape(&role.arn()),
            role.created,
            encoded(trust)
        );
        if shows != Shows::Created && !role.description.is_empty() {
            xml.push_str(&format!("<Description>{}</Description>", xml_escape(&role.description)));
        }
        if matches!(shows, Shows::Full | Shows::Listed) {
            xml.push_str(&format!("<MaxSessionDuration>{}</MaxSessionDuration>", role.max_session_duration));
        }
        if matches!(shows, Shows::Full | Shows::Created)
            && let Some(boundary) = &role.boundary
        {
            xml.push_str(&format!(
                "<PermissionsBoundary><PermissionsBoundaryType>Policy</PermissionsBoundaryType>\
                 <PermissionsBoundaryArn>{}</PermissionsBoundaryArn></PermissionsBoundary>",
                xml_escape(boundary)
            ));
        }
        if matches!(shows, Shows::Full | Shows::Created) && !role.tags.is_empty() {
            xml.push_str(&tags_xml("Tags", &role.tags));
        }
        if shows == Shows::Full {
            xml.push_str("<RoleLastUsed/>");
        }
        xml
    }

    pub(super) async fn create_role(&mut self, params: &Params) -> Result<Option<String>> {
        let name = role_name(params, "RoleName")?.to_owned();
        let path = requested_path(params, "Path")?;
        let trust = document(params, "AssumeRolePolicyDocument")?.to_owned();
        let description = description(params)?.unwrap_or("").to_owned();
        let max = max_session_duration(params)?.unwrap_or(*roles::SESSION_DURATIONS.start());
        let tags = request_tags(params, false, Tagged::User)?;
        let boundary = requested_boundary(params)?;
        // As CreateUser: the boundary asked for, and the tags (which take
        // TagRole too).
        let on = On::role(self.account(), &path, &name);
        let mut context = tags.as_deref().map(tags_context).unwrap_or_default();
        if let Some(arn) = &boundary {
            context.set("iam:PermissionsBoundary", arn);
        }
        self.check_with("iam:CreateRole", on.clone(), &context, Shown::Arn).await?;
        if tags.is_some() {
            self.check_with("iam:TagRole", on, &context, Shown::Arn).await?;
        }
        if Role::load(self.client, self.account(), &name).await?.is_some() {
            return Err(error(StatusCode::CONFLICT, "EntityAlreadyExists", format!("Role with name {name} already exists.")));
        }
        let normalized = roles::check_trust(self.client, self.account(), &trust).await?;
        let boundary = match &boundary {
            Some(arn) => Some(managed::boundary(self.client, self.account(), arn).await?),
            None => None,
        };
        let tags = tags.unwrap_or_default();
        let new = roles::New {
            name: &name,
            path: &path,
            trust: &normalized,
            description: &description,
            max_session_duration: max,
            boundary: boundary.as_ref(),
            tags: &tags,
        };
        let id = roles::create(self.client, self.account(), &new).await?;
        // Its identity in the KMS, so that key owners can grant its sessions
        // keys now; else the next maintenance pass makes it.
        if self.app.kms.is_some() {
            let app = self.app.clone();
            tokio::spawn(async move {
                if let Err(e) = users::identify(&app).await {
                    eprintln!("kms: identifying roles: {e:#}");
                }
            });
        }
        let role = Role::load_id(self.client, id).await?.ok_or_else(|| no_such_role(&name))?;
        Ok(Some(format!("<Role>{}</Role>", Self::role_xml(&role, &trust, Shows::Created))))
    }

    pub(super) async fn get_role(&mut self, params: &Params) -> Result<Option<String>> {
        let role = self.role(params, "iam:GetRole").await?;
        let trust = roles::shown_trust(self.client, &role).await?;
        Ok(Some(format!("<Role>{}</Role>", Self::role_xml(&role, &trust, Shows::Full))))
    }

    pub(super) async fn list_roles(&mut self, params: &Params) -> Result<Option<String>> {
        let prefix = params.get("PathPrefix").unwrap_or("/").to_owned();
        users::check_path(&prefix, "pathPrefix", true).map_err(validation)?;
        self.check("iam:ListRoles", On::roles(self.account(), &prefix)).await?;
        let max = max_items(params)?;
        let after = params.get("Marker").unwrap_or("");
        let mut listed = roles::list(self.client, self.account(), &prefix, after, max as i64 + 1).await?;
        let truncated = listed.len() > max;
        listed.truncate(max);
        let mut members = String::new();
        for role in &listed {
            let trust = roles::shown_trust(self.client, role).await?;
            members.push_str(&format!("<member>{}</member>", Self::role_xml(role, &trust, Shows::Listed)));
        }
        let marker = match (truncated, listed.last()) {
            (true, Some(last)) => format!("<Marker>{}</Marker>", xml_escape(&last.name)),
            _ => String::new(),
        };
        Ok(Some(format!("<Roles>{members}</Roles><IsTruncated>{truncated}</IsTruncated>{marker}")))
    }

    pub(super) async fn update_role(&mut self, params: &Params) -> Result<Option<String>> {
        let description = description(params)?.map(str::to_owned);
        let max = max_session_duration(params)?;
        let role = self.role(params, "iam:UpdateRole").await?;
        roles::update(self.client, role.id, description.as_deref(), max).await?;
        // An empty result, which UpdateRole has (botocore expects it).
        Ok(Some(String::new()))
    }

    pub(super) async fn update_role_description(&mut self, params: &Params) -> Result<Option<String>> {
        let description = description(params)?.map(str::to_owned);
        let Some(description) = description else {
            params.required("Description")?;
            unreachable!()
        };
        let role = self.role(params, "iam:UpdateRoleDescription").await?;
        roles::update(self.client, role.id, Some(&description), None).await?;
        let role = Role::load_id(self.client, role.id).await?.ok_or_else(|| no_such_role(&role.name))?;
        let trust = roles::shown_trust(self.client, &role).await?;
        Ok(Some(format!("<Role>{}</Role>", Self::role_xml(&role, &trust, Shows::Described))))
    }

    pub(super) async fn update_assume_role_policy(&mut self, params: &Params) -> Result<Option<String>> {
        let trust = document(params, "PolicyDocument")?.to_owned();
        let role = self.role(params, "iam:UpdateAssumeRolePolicy").await?;
        let normalized = roles::check_trust(self.client, self.account(), &trust).await?;
        roles::set_trust(self.client, role.id, &normalized).await?;
        Ok(None)
    }

    pub(super) async fn delete_role(&mut self, params: &Params) -> Result<Option<String>> {
        let role = self.role(params, "iam:DeleteRole").await?;
        roles::delete(self.client, &role).await?;
        Ok(None)
    }

    pub(super) async fn put_role_permissions_boundary(&mut self, params: &Params) -> Result<Option<String>> {
        params.required("RoleName")?;
        let Some(arn) = requested_boundary(params)? else {
            params.required("PermissionsBoundary")?;
            unreachable!()
        };
        let mut extra = Context::default();
        extra.set("iam:PermissionsBoundary", &arn);
        let role = self.role_with(params, "iam:PutRolePermissionsBoundary", extra, no_such_role).await?;
        let boundary = managed::boundary(self.client, self.account(), &arn).await?;
        roles::set_boundary(self.client, role.id, Some(&boundary)).await?;
        Ok(None)
    }

    pub(super) async fn delete_role_permissions_boundary(&mut self, params: &Params) -> Result<Option<String>> {
        let role = self.role(params, "iam:DeleteRolePermissionsBoundary").await?;
        if role.boundary.is_none() {
            return Err(error(
                StatusCode::NOT_FOUND,
                "NoSuchEntity",
                format!("Principal {} does not have scope", roles::unique_id(role.id)),
            ));
        }
        roles::set_boundary(self.client, role.id, None).await?;
        Ok(None)
    }

    pub(super) async fn tag_role(&mut self, params: &Params) -> Result<Option<String>> {
        params.required("RoleName")?;
        let tags = request_tags(params, true, Tagged::User)?.unwrap_or_default();
        let role = self.role_with(params, "iam:TagRole", tags_context(&tags), no_such_role).await?;
        roles::tag(self.client, role.id, &tags).await?;
        Ok(None)
    }

    pub(super) async fn untag_role(&mut self, params: &Params) -> Result<Option<String>> {
        params.required("RoleName")?;
        let keys = request_keys(params)?;
        let mut extra = Context::default();
        extra.set_all("aws:TagKeys", keys.clone());
        let role = self.role_with(params, "iam:UntagRole", extra, no_such_role).await?;
        roles::untag(self.client, role.id, &keys).await?;
        Ok(None)
    }

    pub(super) async fn list_role_tags(&mut self, params: &Params) -> Result<Option<String>> {
        let role = self.role(params, "iam:ListRoleTags").await?;
        let max = max_items(params)?;
        let start: usize = match params.get("Marker") {
            Some(m) => m.parse().map_err(|_| super::invalid("Invalid Marker."))?,
            None => 0,
        };
        let page: Vec<(String, String)> = role.tags.iter().skip(start).take(max).cloned().collect();
        let truncated = start + page.len() < role.tags.len();
        let marker = match truncated {
            true => format!("<Marker>{}</Marker>", start + page.len()),
            false => String::new(),
        };
        Ok(Some(format!("{}<IsTruncated>{truncated}</IsTruncated>{marker}", tags_xml("Tags", &page))))
    }

    pub(super) async fn put_role_policy(&mut self, params: &Params) -> Result<Option<String>> {
        params.required("RoleName")?;
        let name = params.required("PolicyName")?.to_owned();
        let document = params.required("PolicyDocument")?.to_owned();
        let role = self.role(params, "iam:PutRolePolicy").await?;
        roles::put_policy(self.client, &role, &name, &document).await?;
        Ok(None)
    }

    pub(super) async fn get_role_policy(&mut self, params: &Params) -> Result<Option<String>> {
        let role = self.role(params, "iam:GetRolePolicy").await?;
        let name = params.required("PolicyName")?;
        let document = roles::get_policy(self.client, role.id, name).await?.ok_or_else(|| {
            error(StatusCode::NOT_FOUND, "NoSuchEntity", format!("The role policy with name {name} cannot be found."))
        })?;
        Ok(Some(format!(
            "<RoleName>{}</RoleName><PolicyName>{}</PolicyName><PolicyDocument>{}</PolicyDocument>",
            xml_escape(&role.name),
            xml_escape(name),
            encoded(&document)
        )))
    }

    pub(super) async fn list_role_policies(&mut self, params: &Params) -> Result<Option<String>> {
        let role = self.role(params, "iam:ListRolePolicies").await?;
        let members: String = roles::policy_names(self.client, role.id)
            .await?
            .iter()
            .map(|n| format!("<member>{}</member>", xml_escape(n)))
            .collect();
        Ok(Some(format!("<PolicyNames>{members}</PolicyNames><IsTruncated>false</IsTruncated>")))
    }

    pub(super) async fn delete_role_policy(&mut self, params: &Params) -> Result<Option<String>> {
        let role = self.role(params, "iam:DeleteRolePolicy").await?;
        let name = params.required("PolicyName")?;
        if !roles::delete_policy(self.client, role.id, name).await? {
            return Err(error(StatusCode::NOT_FOUND, "NoSuchEntity", format!("The role policy with name {name} cannot be found.")));
        }
        Ok(None)
    }

    /// AttachRolePolicy (`attach`) and DetachRolePolicy.
    pub(super) async fn attach_role_policy(&mut self, params: &Params, attach: bool) -> Result<Option<String>> {
        params.required("RoleName")?;
        let arn = params.required("PolicyArn")?.to_owned();
        let action = if attach { "iam:AttachRolePolicy" } else { "iam:DetachRolePolicy" };
        let mut extra = Context::default();
        extra.set("iam:PolicyARN", &arn);
        let role = self.role_with(params, action, extra, no_such_role).await?;
        roles::attach(self.client, self.account(), &role, &arn, attach).await?;
        Ok(None)
    }

    pub(super) async fn list_attached_role_policies(&mut self, params: &Params) -> Result<Option<String>> {
        let role = self.role(params, "iam:ListAttachedRolePolicies").await?;
        let members: String = roles::attached(self.client, role.id)
            .await?
            .iter()
            .map(|p| {
                format!("<member><PolicyName>{}</PolicyName><PolicyArn>{}</PolicyArn></member>", xml_escape(&p.name), xml_escape(&p.arn))
            })
            .collect();
        Ok(Some(format!("<AttachedPolicies>{members}</AttachedPolicies><IsTruncated>false</IsTruncated>")))
    }
}
