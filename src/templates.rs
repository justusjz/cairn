//! Policy templates: managed policies for common setups, correct by
//! construction (see `plans/templates.md`). Above all, the team: a tenant
//! sharing the account, whose admin manages its own users, roles, policies
//! and buckets, and can't get out of them.
//!
//! A template is a function of its parameters, which makes managed policies
//! (no I/O here). Using one (`console::templates`) is IAM's CreatePolicy
//! and TagPolicy as the caller, checked as the IAM API checks them: a
//! template allows nothing by itself, so a team's admin may use one within
//! its team, and nothing outside it. What a template made is tagged with it
//! (`TEMPLATE_TAG`, `VERSION_TAG`), and is otherwise an ordinary policy,
//! which IAM tools see and change.
//!
//! Grants (`grants`, `cairn user grant`) are the bucket-access template's.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;

use crate::users::Permission;

/// The tag a template's policies have: the template's ID.
pub const TEMPLATE_TAG: &str = "cairn:template";
/// The tag a template's policies have: the template's version they're of.
pub const VERSION_TAG: &str = "cairn:template-version";

/// What the bucket-access template may allow on a bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Level {
    /// Reading objects and listing them (a grant's `read`).
    Read,
    /// Writing and deleting objects (in a versioned bucket, a delete adds a
    /// delete marker: a grant's `write`).
    Write,
    /// Deleting objects' versions for good (a grant's `delete-version`).
    DeleteVersion,
    /// Changing the bucket's configuration and policy, and deleting it.
    Manage,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Read => "read",
            Level::Write => "write",
            Level::DeleteVersion => "delete-version",
            Level::Manage => "manage",
        }
    }

    fn actions(self) -> Vec<&'static str> {
        match self {
            Level::Read => crate::s3::actions::grant_actions(Permission::Read),
            Level::Write => crate::s3::actions::grant_actions(Permission::Write),
            Level::DeleteVersion => crate::s3::actions::grant_actions(Permission::DeleteVersion),
            Level::Manage => crate::s3::actions::manage_actions(),
        }
    }
}

impl From<Permission> for Level {
    fn from(permission: Permission) -> Level {
        match permission {
            Permission::Read => Level::Read,
            Permission::Write => Level::Write,
            Permission::DeleteVersion => Level::DeleteVersion,
        }
    }
}

/// A template, as the console lists them.
#[derive(Serialize, ToSchema)]
pub struct Template {
    /// Its ID, as a use names it (`template`).
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    /// Its version, which changes when what it makes does.
    pub version: u32,
}

pub const TEMPLATES: &[Template] = &[
    Template {
        id: "team",
        title: "Team",
        description: "A team sharing the account: a policy for everything the team may do, which is both its admins' \
                      policy (attach it to a user or a role) and the permissions boundary of everyone in the team, and \
                      one for its members. The team has the buckets whose names start with its prefix, and the users, roles and policies at its path (`/<team>/`); its \
                      admins manage those, and the SNS topics named as its buckets are (for their event notifications), \
                      and every user or role they make or change has the team's boundary, so \
                      nothing the team does reaches past it. Made at `/cairn/teams/<team>/`, which the team can't change.",
        version: 2,
    },
    Template {
        id: "bucket-access",
        title: "Bucket access",
        description: "Access to a bucket, or to the buckets whose names match a pattern (`logs-*`): reading, writing, \
                      deleting versions for good, managing the bucket. What `cairn user grant` makes.",
        version: 2,
    },
    Template {
        id: "mfa-guard",
        title: "MFA guard",
        description: "Denies changing users, policies and the cluster (`iam:*`, `cairn:*`) without MFA: to directory \
                      users, signed in at an identity source, and to access keys, which never carry MFA (as in AWS).",
        version: 1,
    },
];

/// What a template is used with.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(tag = "template", rename_all = "kebab-case")]
pub enum Use {
    Team {
        /// The team's name: its path is `/<team>/`, its policies'
        /// names start with it.
        team: String,
        /// The names of its buckets start with this (default: the team's
        /// name, lowercase, and `-`).
        #[serde(default)]
        bucket_prefix: Option<String>,
        /// Whether the team sees every bucket's name
        /// (`s3:ListAllMyBuckets`, which can't be limited to some).
        #[serde(default)]
        list_all_buckets: bool,
        /// Whether its admins see every managed policy's name and path
        /// (`iam:ListPolicies`, which can't be limited to some).
        #[serde(default)]
        list_policies: bool,
    },
    BucketAccess {
        /// A bucket's name, or a pattern (`*` for any characters).
        buckets: String,
        levels: Vec<Level>,
        /// The policy's name (default: from the buckets and levels).
        #[serde(default)]
        name: Option<String>,
        /// Its path (default `/`).
        #[serde(default)]
        path: Option<String>,
    },
    MfaGuard {
        /// The policy's name (default `RequireMFA`).
        #[serde(default)]
        name: Option<String>,
        /// Its path (default `/`).
        #[serde(default)]
        path: Option<String>,
    },
}

/// A managed policy a template makes.
#[derive(Clone, Debug, PartialEq)]
pub struct Made {
    pub path: String,
    pub name: String,
    pub description: String,
    pub document: String,
    pub tags: Vec<(String, String)>,
}

impl Use {
    /// Its template's ID.
    pub fn template(&self) -> &'static Template {
        let id = match self {
            Use::Team { .. } => "team",
            Use::BucketAccess { .. } => "bucket-access",
            Use::MfaGuard { .. } => "mfa-guard",
        };
        TEMPLATES.iter().find(|t| t.id == id).expect("every use is a template's")
    }

    /// The policies it makes, in `account`; or why it can't.
    pub fn make(&self, account: &str) -> Result<Vec<Made>, String> {
        let template = self.template();
        let tags = vec![(TEMPLATE_TAG.to_owned(), template.id.to_owned()), (VERSION_TAG.to_owned(), template.version.to_string())];
        let made = |path: &str, name: String, description: String, document: String| Made {
            path: path.to_owned(),
            name,
            description,
            document,
            tags: tags.clone(),
        };
        match self {
            Use::Team { team, bucket_prefix, list_all_buckets, list_policies } => {
                check_team(team)?;
                let prefix = bucket_prefix.clone().unwrap_or_else(|| format!("{}-", team.to_lowercase()));
                check_prefix(&prefix)?;
                let team = Team { account, team, buckets: &format!("{prefix}*"), list_all_buckets: *list_all_buckets, list_policies: *list_policies };
                let path = team.path();
                Ok(vec![
                    made(
                        &path,
                        team.policy_name(),
                        format!("Everything team {} may do: its admins' policy, and its users' and roles' permissions boundary", team.team),
                        team.policy(),
                    ),
                    made(&path, format!("{}-member", team.team), format!("A member of team {}", team.team), team.member()),
                ])
            }
            Use::BucketAccess { buckets, levels, name, path } => {
                check_buckets(buckets)?;
                if levels.is_empty() {
                    return Err("give at least one level".to_owned());
                }
                let path = path.clone().unwrap_or_else(|| "/".to_owned());
                crate::users::check_path(&path, "path", false)?;
                let levels_text = levels.iter().map(|l| l.as_str()).collect::<Vec<_>>().join(", ");
                let name = name.clone().unwrap_or_else(|| bucket_access_name(buckets, levels));
                Ok(vec![made(
                    &path,
                    name,
                    format!("{levels_text} on bucket {buckets}"),
                    bucket_access_document(buckets, levels),
                )])
            }
            Use::MfaGuard { name, path } => {
                let path = path.clone().unwrap_or_else(|| "/".to_owned());
                crate::users::check_path(&path, "path", false)?;
                let document = json!({
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Sid": "RequireMFA",
                        "Effect": "Deny",
                        "Action": ["iam:*", "cairn:*"],
                        "Resource": "*",
                        "Condition": { "BoolIfExists": { "aws:MultiFactorAuthPresent": "false" } },
                    }],
                });
                Ok(vec![made(
                    &path,
                    name.clone().unwrap_or_else(|| "RequireMFA".to_owned()),
                    "Denies changing users, policies and the cluster without MFA".to_owned(),
                    document.to_string(),
                )])
            }
        }
    }
}

/// The bucket-access template's document: `levels` on `buckets` (a name or
/// a pattern) and their objects. For one level on one bucket, exactly a
/// grant's (see `grants::policy_for`).
pub fn bucket_access_document(buckets: &str, levels: &[Level]) -> String {
    json!({ "Version": "2012-10-17", "Statement": [bucket_statement(buckets, levels)] }).to_string()
}

/// One statement allowing `levels` on `buckets` and their objects.
fn bucket_statement(buckets: &str, levels: &[Level]) -> Value {
    let mut actions: Vec<&'static str> = Vec::new();
    for level in levels {
        for action in level.actions() {
            if !actions.contains(&action) {
                actions.push(action);
            }
        }
    }
    json!({
        "Effect": "Allow",
        "Action": actions,
        "Resource": [format!("arn:aws:s3:::{buckets}"), format!("arn:aws:s3:::{buckets}/*")],
    })
}

/// A bucket-access policy's name, if none is given: the buckets' (without
/// wildcards) and the levels'.
fn bucket_access_name(buckets: &str, levels: &[Level]) -> String {
    let buckets = buckets.replace(['*', '?'], "");
    let buckets = buckets.trim_matches(|c| c == '-' || c == '.');
    let buckets = if buckets.is_empty() { "all-buckets" } else { buckets };
    let levels: Vec<&str> = levels.iter().map(|l| l.as_str()).collect();
    format!("{buckets}-{}", levels.join("-"))
}

/// A team's policies.
struct Team<'a> {
    account: &'a str,
    team: &'a str,
    /// Its buckets' pattern (`<prefix>*`).
    buckets: &'a str,
    list_all_buckets: bool,
    list_policies: bool,
}

impl Team<'_> {
    /// Where its policies are: Cairn's path for teams, not the team's own,
    /// which its admins may change policies at.
    fn path(&self) -> String {
        format!("/cairn/teams/{}/", self.team)
    }

    /// The team's policy's name: `<team>-team`.
    fn policy_name(&self) -> String {
        format!("{}-team", self.team)
    }

    /// The team's policy's ARN, the boundary every one of its users and
    /// roles has.
    fn boundary_arn(&self) -> String {
        crate::managed::arn(self.account, &self.path(), &self.policy_name())
    }

    /// Everything the team may do, and the guardrails: both its admins'
    /// policy and its boundary. The two can't usefully differ: an admin
    /// may attach anything to the team's users and roles (a new one, if
    /// not its own), up to the boundary, so a narrower admin policy would
    /// only look narrower. The guardrails hold as either: for a member an
    /// admin gave AdministratorAccess (the boundary has them), and for an
    /// admin without the boundary (its policy has them).
    fn policy(&self) -> String {
        json!({ "Version": "2012-10-17", "Statement": self.statements() }).to_string()
    }

    /// Reading and writing the team's buckets, and its own access keys.
    fn member(&self) -> String {
        let mut buckets = bucket_statement(self.buckets, &[Level::Read, Level::Write]);
        buckets["Sid"] = json!("TeamBuckets");
        let mut statements = vec![
            buckets,
            json!({
                "Sid": "OwnAccessKeys",
                "Effect": "Allow",
                "Action": ["iam:GetUser", "iam:ListAccessKeys", "iam:CreateAccessKey", "iam:UpdateAccessKey", "iam:DeleteAccessKey"],
                "Resource": format!("arn:aws:iam::{}:user/{}/${{aws:username}}", self.account, self.team),
            }),
        ];
        if self.list_all_buckets {
            statements.push(json!({ "Sid": "ListAllBuckets", "Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*" }));
        }
        json!({ "Version": "2012-10-17", "Statement": statements }).to_string()
    }

    fn statements(&self) -> Vec<Value> {
        let (account, team) = (self.account, self.team);
        let iam = |what: &str| format!("arn:aws:iam::{account}:{what}/{team}/*");
        let mut statements = vec![
            json!({
                "Sid": "TeamBuckets",
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": [format!("arn:aws:s3:::{}", self.buckets), format!("arn:aws:s3:::{}/*", self.buckets)],
            }),
            json!({
                "Sid": "TeamIdentities",
                "Effect": "Allow",
                "Action": "iam:*",
                "Resource": [iam("user"), iam("role"), iam("policy")],
            }),
            // Cairn's policies, and the team's own templates', to attach.
            json!({
                "Sid": "ReadTeamPolicies",
                "Effect": "Allow",
                "Action": ["iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListPolicyVersions"],
                "Resource": ["arn:aws:iam::aws:policy/*", format!("arn:aws:iam::{account}:policy/cairn/teams/{team}/*")],
            }),
            json!({ "Sid": "AssumeTeamRoles", "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": iam("role") }),
            // SNS's topics named as its buckets are, for their events (see
            // `sns`): their subscriptions, policies, publishing.
            json!({
                "Sid": "TeamTopics",
                "Effect": "Allow",
                "Action": "sns:*",
                "Resource": format!("arn:aws:sns:*:{account}:{}", self.buckets),
            }),
        ];
        if self.list_all_buckets {
            statements.push(json!({ "Sid": "ListAllBuckets", "Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*" }));
            statements.push(json!({ "Sid": "ListAllTopics", "Effect": "Allow", "Action": "sns:ListTopics", "Resource": "*" }));
        }
        if self.list_policies {
            statements.push(json!({ "Sid": "ListAllPolicies", "Effect": "Allow", "Action": "iam:ListPolicies", "Resource": "*" }));
        }
        let unless_bounded = json!({ "StringNotEquals": { "iam:PermissionsBoundary": self.boundary_arn() } });
        statements.extend([
            // With a condition, DeleteUserPermissionsBoundary is decided by
            // the boundary it takes off: denied outright.
            json!({
                "Sid": "KeepBoundaries",
                "Effect": "Deny",
                "Action": ["iam:DeleteUserPermissionsBoundary", "iam:DeleteRolePermissionsBoundary"],
                "Resource": "*",
            }),
            // What's made or bounded gets the team's boundary.
            json!({
                "Sid": "BoundNewIdentities",
                "Effect": "Deny",
                "Action": ["iam:CreateUser", "iam:CreateRole", "iam:PutUserPermissionsBoundary", "iam:PutRolePermissionsBoundary"],
                "Resource": "*",
                "Condition": unless_bounded.clone(),
            }),
            // Only what has the team's boundary gets permissions.
            json!({
                "Sid": "ChangeOnlyBoundIdentities",
                "Effect": "Deny",
                "Action": [
                    "iam:AttachUserPolicy", "iam:DetachUserPolicy", "iam:PutUserPolicy", "iam:DeleteUserPolicy",
                    "iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy",
                ],
                "Resource": "*",
                "Condition": unless_bounded,
            }),
        ]);
        statements
    }
}

/// A team's name: a path's segment (IAM's path characters, but `/`), short
/// enough for its policies' names.
fn check_team(team: &str) -> Result<(), String> {
    let fine = |c: char| c.is_ascii_alphanumeric() || "+=,.@_-".contains(c);
    if team.is_empty() || team.len() > 64 || !team.chars().all(fine) {
        return Err("a team's name is 1 to 64 letters, digits and +=,.@_-".to_owned());
    }
    if team.eq_ignore_ascii_case("cairn") {
        return Err("a team can't be named cairn: its path is Cairn's own".to_owned());
    }
    Ok(())
}

/// A team's buckets' prefix: the start of a bucket's name, long enough that
/// it's the team's alone.
fn check_prefix(prefix: &str) -> Result<(), String> {
    let fine = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.';
    if prefix.len() < 3 || prefix.len() > 50 || !prefix.chars().all(fine) || !prefix.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return Err(
            "a bucket prefix is 3 to 50 lowercase letters, digits, dots and hyphens, starting with a letter or digit".to_owned(),
        );
    }
    Ok(())
}

/// A bucket's name or a pattern of them.
fn check_buckets(buckets: &str) -> Result<(), String> {
    let fine = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || "-.*?".contains(c);
    if buckets.is_empty() || buckets.len() > 63 || !buckets.chars().all(fine) {
        return Err("buckets are a bucket's name, or a pattern of them (lowercase letters, digits, dots, hyphens, * and ?)".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
