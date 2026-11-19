//! IAM's actions on groups (see `groups`), as IAM answers them. Each is
//! checked as IAM's own (`iam:CreateGroup` on the group's ARN, ...), as
//! users' and roles' are; AddUserToGroup and RemoveUserFromGroup on the
//! group, ListGroupsForUser on the user.

use hyper::StatusCode;
use percent_encoding::utf8_percent_encode;

use super::{
    Error, Iam, Params, RFC3986, Result, Shown, error, max_items, no_such_user, requested_path,
    validation,
};
use crate::{
    groups::{self, Group},
    policy::Context,
    s3::{actions::On, util::xml_escape},
    users::{self, Target},
};

/// IAM's NoSuchEntity for group `name`.
fn no_such_group(name: &str) -> Error {
    error(
        StatusCode::NOT_FOUND,
        "NoSuchEntity",
        format!("The group with name {name} cannot be found."),
    )
}

fn no_such_group_policy(name: &str) -> Error {
    error(
        StatusCode::NOT_FOUND,
        "NoSuchEntity",
        format!("The group policy with name {name} cannot be found."),
    )
}

/// A group's name as a request gives it (`param`), checked as IAM checks
/// it.
fn group_name<'p>(params: &'p Params, param: &str) -> Result<&'p str> {
    let name = params.required(param)?;
    if name.len() > 128 {
        return Err(validation(format!(
            "1 validation error detected: Value at '{}' failed to satisfy constraint: Member must have length less than or equal to 128",
            super::lower_first(param)
        )));
    }
    if !groups::valid_name(name) {
        return Err(validation(format!(
            "The specified value for {} is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-",
            super::lower_first(param)
        )));
    }
    Ok(name)
}

/// A page's marker, if it's truncated after `last`.
fn marker(truncated: bool, last: Option<&str>) -> String {
    match (truncated, last) {
        (true, Some(last)) => format!("<Marker>{}</Marker>", xml_escape(last)),
        _ => String::new(),
    }
}

impl Iam<'_> {
    /// The group a request names (`GroupName`), allowed `action` on it
    /// (with `extra`): IAM's NoSuchEntity if there's none, which is checked
    /// first as one would be.
    async fn group_with(
        &mut self,
        params: &Params,
        action: &'static str,
        extra: Context,
    ) -> Result<Group> {
        let name = params.required("GroupName")?.to_owned();
        let group = Group::load(self.client, self.account(), &name).await?;
        let on = match &group {
            Some(group) => group.on(),
            None => On::group(self.account(), "/", &name),
        };
        self.check_with(action, on, &extra, Shown::Group(name.clone()))
            .await?;
        group.ok_or_else(|| no_such_group(&name))
    }

    async fn group(&mut self, params: &Params, action: &'static str) -> Result<Group> {
        self.group_with(params, action, Context::default()).await
    }

    /// A group as IAM shows it.
    fn group_xml(group: &Group) -> String {
        format!(
            "<Path>{}</Path><GroupName>{}</GroupName><GroupId>{}</GroupId><Arn>{}</Arn><CreateDate>{}</CreateDate>",
            xml_escape(&group.path),
            xml_escape(&group.name),
            groups::unique_id(group.id),
            xml_escape(&group.arn()),
            group.created
        )
    }

    pub(super) async fn create_group(&mut self, params: &Params) -> Result<Option<String>> {
        let name = group_name(params, "GroupName")?.to_owned();
        let path = requested_path(params, "Path")?;
        self.check_with(
            "iam:CreateGroup",
            On::group(self.account(), &path, &name),
            &Context::default(),
            Shown::Arn,
        )
        .await?;
        let id = groups::create(self.client, self.account(), &name, &path).await?;
        let group = Group::load_id(self.client, id)
            .await?
            .ok_or_else(|| no_such_group(&name))?;
        Ok(Some(format!("<Group>{}</Group>", Self::group_xml(&group))))
    }

    /// GetGroup: the group, and its members, paged by name.
    pub(super) async fn get_group(&mut self, params: &Params) -> Result<Option<String>> {
        let group = self.group(params, "iam:GetGroup").await?;
        let max = max_items(params)?;
        let after = params.get("Marker").unwrap_or("");
        let mut members = groups::members(self.client, group.id, after, max as i64 + 1).await?;
        let truncated = members.len() > max;
        members.truncate(max);
        let mut users = String::new();
        for member in &members {
            if let Some(user) = Target::load(self.client, self.account(), &member.name).await? {
                users.push_str(&format!(
                    "<member>{}</member>",
                    Self::user_xml(&user, false)
                ));
            }
        }
        Ok(Some(format!(
            "<Group>{}</Group><Users>{users}</Users><IsTruncated>{truncated}</IsTruncated>{}",
            Self::group_xml(&group),
            marker(truncated, members.last().map(|m| m.name.as_str()))
        )))
    }

    pub(super) async fn list_groups(&mut self, params: &Params) -> Result<Option<String>> {
        let prefix = params.get("PathPrefix").unwrap_or("/").to_owned();
        users::check_path(&prefix, "pathPrefix", true).map_err(validation)?;
        self.check("iam:ListGroups", On::groups(self.account(), &prefix))
            .await?;
        let max = max_items(params)?;
        let after = params.get("Marker").unwrap_or("");
        let mut listed =
            groups::list(self.client, self.account(), &prefix, after, max as i64 + 1).await?;
        let truncated = listed.len() > max;
        listed.truncate(max);
        let members: String = listed
            .iter()
            .map(|g| format!("<member>{}</member>", Self::group_xml(g)))
            .collect();
        Ok(Some(format!(
            "<Groups>{members}</Groups><IsTruncated>{truncated}</IsTruncated>{}",
            marker(truncated, listed.last().map(|g| g.name.as_str()))
        )))
    }

    /// UpdateGroup: moves (`NewPath`) or renames (`NewGroupName`) a group,
    /// which takes iam:UpdateGroup on it and on where it goes, as
    /// UpdateUser.
    pub(super) async fn update_group(&mut self, params: &Params) -> Result<Option<String>> {
        params.required("GroupName")?;
        let new_path = match params.get("NewPath") {
            Some(_) => Some(requested_path(params, "NewPath")?),
            None => None,
        };
        let new_name = match params.get("NewGroupName") {
            Some(_) => Some(group_name(params, "NewGroupName")?.to_owned()),
            None => None,
        };
        let group = self.group(params, "iam:UpdateGroup").await?;
        let path = new_path.clone().unwrap_or_else(|| group.path.clone());
        let name = new_name.clone().unwrap_or_else(|| group.name.clone());
        if new_path.is_some() || new_name.is_some() {
            self.check("iam:UpdateGroup", On::group(self.account(), &path, &name))
                .await?;
        }
        groups::update(self.client, group.id, &name, &path).await?;
        Ok(None)
    }

    pub(super) async fn delete_group(&mut self, params: &Params) -> Result<Option<String>> {
        let group = self.group(params, "iam:DeleteGroup").await?;
        groups::delete(self.client, &group).await?;
        Ok(None)
    }

    /// AddUserToGroup (`add`) and RemoveUserFromGroup: checked on the group,
    /// then the user must be there.
    pub(super) async fn add_user_to_group(
        &mut self,
        params: &Params,
        add: bool,
    ) -> Result<Option<String>> {
        let user_name = params.required("UserName")?.to_owned();
        let action = if add {
            "iam:AddUserToGroup"
        } else {
            "iam:RemoveUserFromGroup"
        };
        let group = self.group(params, action).await?;
        let user = Target::load(self.client, self.account(), &user_name)
            .await?
            .ok_or_else(|| no_such_user(&user_name))?;
        match add {
            true => groups::add_member(self.client, &group, user.id, &user.name).await?,
            false => groups::remove_member(self.client, &group, user.id, &user.name).await?,
        }
        Ok(None)
    }

    pub(super) async fn list_groups_for_user(&mut self, params: &Params) -> Result<Option<String>> {
        params.required("UserName")?;
        let user = self.user(params, "iam:ListGroupsForUser").await?;
        let max = max_items(params)?;
        let mut listed = groups::of_user(self.client, user.id).await?;
        if let Some(after) = params.get("Marker") {
            listed.retain(|g| g.name.as_str() > after);
        }
        let truncated = listed.len() > max;
        listed.truncate(max);
        let members: String = listed
            .iter()
            .map(|g| format!("<member>{}</member>", Self::group_xml(g)))
            .collect();
        Ok(Some(format!(
            "<Groups>{members}</Groups><IsTruncated>{truncated}</IsTruncated>{}",
            marker(truncated, listed.last().map(|g| g.name.as_str()))
        )))
    }

    pub(super) async fn put_group_policy(&mut self, params: &Params) -> Result<Option<String>> {
        params.required("GroupName")?;
        let name = params.required("PolicyName")?.to_owned();
        let document = params.required("PolicyDocument")?.to_owned();
        let group = self.group(params, "iam:PutGroupPolicy").await?;
        groups::put_policy(self.client, &group, &name, &document).await?;
        Ok(None)
    }

    pub(super) async fn get_group_policy(&mut self, params: &Params) -> Result<Option<String>> {
        let group = self.group(params, "iam:GetGroupPolicy").await?;
        let name = params.required("PolicyName")?;
        let document = groups::get_policy(self.client, group.id, name)
            .await?
            .ok_or_else(|| no_such_group_policy(name))?;
        // URL-encoded, as IAM gives policy documents (RFC 3986).
        let encoded = utf8_percent_encode(&document, &RFC3986).to_string();
        Ok(Some(format!(
            "<GroupName>{}</GroupName><PolicyName>{}</PolicyName><PolicyDocument>{}</PolicyDocument>",
            xml_escape(&group.name),
            xml_escape(name),
            xml_escape(&encoded)
        )))
    }

    pub(super) async fn list_group_policies(&mut self, params: &Params) -> Result<Option<String>> {
        let group = self.group(params, "iam:ListGroupPolicies").await?;
        Ok(Some(super::names_page(
            params,
            groups::policy_names(self.client, group.id).await?,
        )?))
    }

    pub(super) async fn delete_group_policy(&mut self, params: &Params) -> Result<Option<String>> {
        let group = self.group(params, "iam:DeleteGroupPolicy").await?;
        let name = params.required("PolicyName")?;
        if !groups::delete_policy(self.client, group.id, name).await? {
            return Err(no_such_group_policy(name));
        }
        Ok(None)
    }

    /// AttachGroupPolicy (`attach`) and DetachGroupPolicy.
    pub(super) async fn attach_group_policy(
        &mut self,
        params: &Params,
        attach: bool,
    ) -> Result<Option<String>> {
        params.required("GroupName")?;
        let arn = params.required("PolicyArn")?.to_owned();
        let action = if attach {
            "iam:AttachGroupPolicy"
        } else {
            "iam:DetachGroupPolicy"
        };
        let mut extra = Context::default();
        extra.set("iam:PolicyARN", &arn);
        let group = self.group_with(params, action, extra).await?;
        groups::attach(self.client, self.account(), &group, &arn, attach).await?;
        Ok(None)
    }

    pub(super) async fn list_attached_group_policies(
        &mut self,
        params: &Params,
    ) -> Result<Option<String>> {
        let group = self.group(params, "iam:ListAttachedGroupPolicies").await?;
        Ok(Some(super::attached_page(
            params,
            groups::attached(self.client, group.id).await?,
        )?))
    }
}
