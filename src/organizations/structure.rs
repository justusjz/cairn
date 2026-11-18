//! The organization's structure and its service control policies (see
//! `organizations`), as AWS Organizations has them.
//!
//! **The root** (`r-…`) holds organizational units (`ou-…`), nested at
//! most five deep, and accounts; each account is in the root or one unit.
//!
//! **Service control policies** (SCPs), once enabled for the root
//! (EnablePolicyType), cap what each member account's principals may do,
//! its root user's too: a request is allowed only if, at every level from
//! the root down to the account (the root, each unit on the way, the
//! account), an SCP attached there allows it, and none denies it; whatever
//! IAM policies or resources' policies allow (see `policy::Caps`). They
//! grant nothing. The management account is under none. AWS's
//! `FullAWSAccess` (`p-FullAWSAccess`, allowing everything) is attached to
//! the root, every unit and every account when SCPs are enabled, and to
//! each made after; each must keep one SCP at least, and has ten at most.
//! Disabling SCPs detaches them all. An SCP is an identity policy's
//! language, with a `Version`, no `Principal`, and in an Allow only `*` as
//! its resource, within 10,240 characters.

use deadpool_postgres::Object;
use hyper::StatusCode;
use serde_json::{Value, json};

use super::{Error, Result, error, invalid};
use crate::db::Cached;

/// The type of SCPs, the only one Cairn has.
pub const SCP: &str = "SERVICE_CONTROL_POLICY";
/// AWS's FullAWSAccess, which allows everything.
pub const FULL_ACCESS: &str = "p-FullAWSAccess";
const FULL_ACCESS_ARN: &str = "arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess";
const FULL_ACCESS_DOCUMENT: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;
/// How deep units nest under the root, at most.
const MAX_DEPTH: usize = 5;
/// The most SCPs a target has.
const MAX_ATTACHED: usize = 10;
/// An SCP's longest content, in characters.
const MAX_CONTENT: usize = 10_240;

/// 4 hex digits of the management account's hash, for the root's ID.
fn root_hash(management: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, format!("root:{management}").as_bytes());
    digest.as_ref()[..2].iter().map(|b| format!("{b:02x}")).collect()
}

/// The organization's root's ID (`r-` and 4 characters).
pub fn root_id(management: &str) -> String {
    format!("r-{}", root_hash(management))
}

fn root_arn(management: &str) -> String {
    format!("arn:aws:organizations::{management}:root/{}/{}", super::organization_id(management), root_id(management))
}

fn unit_arn(management: &str, id: &str) -> String {
    format!("arn:aws:organizations::{management}:ou/{}/{id}", super::organization_id(management))
}

fn policy_arn(management: &str, id: &str) -> String {
    match id {
        FULL_ACCESS => FULL_ACCESS_ARN.to_owned(),
        id => format!("arn:aws:organizations::{management}:policy/{}/service_control_policy/{id}", super::organization_id(management)),
    }
}

/// 8 random lowercase letters and digits.
fn random_part() -> anyhow::Result<String> {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("generating an ID: {e}"))?;
    Ok(bytes.iter().map(|b| CHARS[*b as usize % CHARS.len()] as char).collect())
}

/// What a target (of a policy, or a child or parent) is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Root,
    Unit,
    Account,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Root => "ROOT",
            Kind::Unit => "ORGANIZATIONAL_UNIT",
            Kind::Account => "ACCOUNT",
        }
    }
}

/// Whether SCPs are enabled.
pub async fn scps_enabled(client: &Object) -> anyhow::Result<bool> {
    Ok(client.query_opt_cached("SELECT 1 FROM organization_policy_types WHERE type = $1", &[&SCP]).await?.is_some())
}

/// The units from the root down to `unit` (`unit` last), by ID.
async fn path_to(client: &Object, unit: &str) -> anyhow::Result<Vec<String>> {
    let rows = client
        .query_cached(
            "WITH RECURSIVE up(id, parent_id, depth) AS (
                 SELECT id, parent_id, 0 FROM organizational_units WHERE id = $1
                 UNION ALL
                 SELECT u.id, u.parent_id, up.depth + 1 FROM organizational_units u JOIN up ON u.id = up.parent_id
             )
             SELECT id FROM up ORDER BY depth DESC",
            &[&unit],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}

/// The documents of the SCPs attached to `target`.
async fn documents(client: &Object, target: &str) -> anyhow::Result<Vec<String>> {
    let rows = client
        .query_cached(
            "SELECT a.policy_id, p.content FROM organization_policy_attachments a
             LEFT JOIN organization_policies p ON p.id = a.policy_id WHERE a.target_id = $1 ORDER BY a.policy_id",
            &[&target],
        )
        .await?;
    Ok(rows
        .iter()
        .filter_map(|r| match r.get::<_, &str>(0) {
            FULL_ACCESS => Some(FULL_ACCESS_DOCUMENT.to_owned()),
            _ => r.get::<_, Option<String>>(1),
        })
        .collect())
}

/// The SCPs `account`'s principals are under, by level (the root's, each
/// unit's down to the account's, the account's own): none for the
/// management account, or with SCPs not enabled.
pub async fn scps(client: &Object, account: &str) -> anyhow::Result<Vec<Vec<String>>> {
    let row = client.query_opt_cached("SELECT management, parent_id FROM accounts WHERE id = $1", &[&account]).await?;
    let Some(row) = row else { return Ok(Vec::new()) };
    if row.get::<_, bool>(0) || !scps_enabled(client).await? {
        return Ok(Vec::new());
    }
    let management = crate::users::account(client).await?;
    let mut levels = vec![documents(client, &root_id(&management)).await?];
    if let Some(unit) = row.get::<_, Option<String>>(1) {
        for unit in path_to(client, &unit).await? {
            levels.push(documents(client, &unit).await?);
        }
    }
    levels.push(documents(client, account).await?);
    Ok(levels)
}

/// What `id` is in the organization (the root, a unit, an account), if it's
/// one of its: its kind and name.
async fn target(client: &Object, management: &str, id: &str) -> anyhow::Result<Option<(Kind, String)>> {
    if id == root_id(management) {
        return Ok(Some((Kind::Root, "Root".to_owned())));
    }
    if id.starts_with("ou-") {
        let row = client.query_opt_cached("SELECT name FROM organizational_units WHERE id = $1", &[&id]).await?;
        return Ok(row.map(|r| (Kind::Unit, r.get(0))));
    }
    Ok(super::load(client, id).await?.filter(|a| a.closed.is_none()).map(|a| (Kind::Account, a.name)))
}

fn target_arn(management: &str, kind: Kind, id: &str) -> String {
    match kind {
        Kind::Root => root_arn(management),
        Kind::Unit => unit_arn(management, id),
        Kind::Account => super::account_arn(management, id),
    }
}

/// Attaches FullAWSAccess to `target` if SCPs are enabled: what the root,
/// every unit and every account starts with.
pub async fn attach_default(client: &Object, target: &str) -> anyhow::Result<()> {
    if scps_enabled(client).await? {
        client
            .execute_cached(
                "INSERT INTO organization_policy_attachments (policy_id, target_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                &[&FULL_ACCESS, &target],
            )
            .await?;
    }
    Ok(())
}

/// An organizational unit, as the console shows it.
pub struct Unit {
    pub id: String,
    pub name: String,
    /// Its parent unit; `None` for the root.
    pub parent: Option<String>,
}

/// An SCP, as the console shows it.
pub struct Scp {
    pub id: String,
    pub name: String,
    pub description: String,
    /// Whether it's AWS's (FullAWSAccess), which can't be changed.
    pub aws_managed: bool,
}

/// The organization's structure at once, for the console: its root's ID,
/// whether SCPs are enabled, its units, its SCPs (FullAWSAccess first), and
/// which SCPs each target has (target ID, policy ID).
pub struct Overview {
    pub root_id: String,
    pub scps_enabled: bool,
    pub units: Vec<Unit>,
    pub policies: Vec<Scp>,
    pub attachments: Vec<(String, String)>,
}

pub async fn overview(client: &Object, management: &str) -> anyhow::Result<Overview> {
    let units = client
        .query_cached("SELECT id, name, parent_id FROM organizational_units ORDER BY name", &[])
        .await?
        .iter()
        .map(|r| Unit { id: r.get(0), name: r.get(1), parent: r.get(2) })
        .collect();
    let mut policies = vec![Scp {
        id: FULL_ACCESS.to_owned(),
        name: "FullAWSAccess".to_owned(),
        description: "Allows access to every operation".to_owned(),
        aws_managed: true,
    }];
    for r in client.query_cached("SELECT id, name, description FROM organization_policies ORDER BY name", &[]).await? {
        policies.push(Scp { id: r.get(0), name: r.get(1), description: r.get(2), aws_managed: false });
    }
    let attachments = client
        .query_cached("SELECT target_id, policy_id FROM organization_policy_attachments ORDER BY target_id, policy_id", &[])
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    Ok(Overview { root_id: root_id(management), scps_enabled: scps_enabled(client).await?, units, policies, attachments })
}

// ─── The API ─────────────────────────────────────────────────────────────────

/// The operations of this part, with their actions.
pub const OPERATIONS: &[(&str, &str)] = &[
    ("ListRoots", "organizations:ListRoots"),
    ("EnablePolicyType", "organizations:EnablePolicyType"),
    ("DisablePolicyType", "organizations:DisablePolicyType"),
    ("CreateOrganizationalUnit", "organizations:CreateOrganizationalUnit"),
    ("DescribeOrganizationalUnit", "organizations:DescribeOrganizationalUnit"),
    ("UpdateOrganizationalUnit", "organizations:UpdateOrganizationalUnit"),
    ("DeleteOrganizationalUnit", "organizations:DeleteOrganizationalUnit"),
    ("ListOrganizationalUnitsForParent", "organizations:ListOrganizationalUnitsForParent"),
    ("ListAccountsForParent", "organizations:ListAccountsForParent"),
    ("ListChildren", "organizations:ListChildren"),
    ("ListParents", "organizations:ListParents"),
    ("MoveAccount", "organizations:MoveAccount"),
    ("CreatePolicy", "organizations:CreatePolicy"),
    ("DescribePolicy", "organizations:DescribePolicy"),
    ("UpdatePolicy", "organizations:UpdatePolicy"),
    ("DeletePolicy", "organizations:DeletePolicy"),
    ("ListPolicies", "organizations:ListPolicies"),
    ("AttachPolicy", "organizations:AttachPolicy"),
    ("DetachPolicy", "organizations:DetachPolicy"),
    ("ListPoliciesForTarget", "organizations:ListPoliciesForTarget"),
    ("ListTargetsForPolicy", "organizations:ListTargetsForPolicy"),
];

fn not_found(code: &'static str, message: impl Into<String>) -> Error {
    error(StatusCode::BAD_REQUEST, code, message)
}

fn constraint(reason: &str, message: impl Into<String>) -> Error {
    let mut e = error(StatusCode::BAD_REQUEST, "ConstraintViolationException", message);
    e.reason = Some(reason.to_owned());
    e
}

/// What an operation may need of the request.
pub struct Input<'a> {
    pub client: &'a Object,
    pub management: &'a str,
    pub input: &'a Value,
}

impl Input<'_> {
    fn text(&self, name: &str) -> Option<&str> {
        self.input.get(name).and_then(Value::as_str)
    }

    fn required(&self, name: &str) -> Result<&str> {
        self.text(name).filter(|v| !v.is_empty()).ok_or_else(|| invalid(format!("You must specify {name}.")))
    }

    fn root_json(&self, enabled: bool) -> Value {
        let types: Vec<Value> = match enabled {
            true => vec![json!({ "Type": SCP, "Status": "ENABLED" })],
            false => Vec::new(),
        };
        json!({ "Id": root_id(self.management), "Arn": root_arn(self.management), "Name": "Root", "PolicyTypes": types })
    }

    /// The root `RootId` names.
    fn root(&self) -> Result<()> {
        match self.required("RootId")? == root_id(self.management) {
            true => Ok(()),
            false => Err(not_found("RootNotFoundException", "You specified a root that doesn't exist.")),
        }
    }

    /// The SCP type, as `PolicyType` (or `Type`, `Filter`) names it.
    fn policy_type(&self, field: &str) -> Result<()> {
        match self.required(field)? {
            SCP => Ok(()),
            other => Err(error(StatusCode::NOT_IMPLEMENTED, "NotImplemented", format!("Cairn has service control policies only, not {other}."))),
        }
    }

    /// A parent `field` names: the root (`None`), or a unit (its ID).
    async fn parent(&self, field: &str, missing: &'static str) -> Result<Option<String>> {
        let id = self.required(field)?;
        if id == root_id(self.management) {
            return Ok(None);
        }
        match target(self.client, self.management, id).await? {
            Some((Kind::Unit, _)) => Ok(Some(id.to_owned())),
            _ => Err(not_found(missing, "We can't find a root or OU with the ParentId that you specified.")),
        }
    }

    /// The unit `OrganizationalUnitId` names: its name and parent.
    async fn unit(&self) -> Result<(String, String, Option<String>)> {
        let id = self.required("OrganizationalUnitId")?;
        let row = self.client.query_opt_cached("SELECT name, parent_id FROM organizational_units WHERE id = $1", &[&id]).await?;
        let row = row.ok_or_else(|| not_found("OrganizationalUnitNotFoundException", "We can't find an OU with the OrganizationalUnitId that you specified."))?;
        Ok((id.to_owned(), row.get(0), row.get(1)))
    }

    async fn unit_json(&self, id: &str, name: &str) -> anyhow::Result<Value> {
        let mut path = format!("{}/{}/", super::organization_id(self.management), root_id(self.management));
        for unit in path_to(self.client, id).await? {
            path.push_str(&format!("{unit}/"));
        }
        Ok(json!({ "Id": id, "Arn": unit_arn(self.management, id), "Name": name, "Path": path }))
    }

    /// The policy `PolicyId` names: its summary and content.
    async fn policy(&self) -> Result<(Value, String)> {
        let id = self.required("PolicyId")?;
        policy(self.client, self.management, id)
            .await?
            .ok_or_else(|| not_found("PolicyNotFoundException", "We can't find a policy with the PolicyId that you specified."))
    }

    /// A page of `items`, as Organizations pages (20 at most).
    fn page(&self, key: &str, items: Vec<Value>) -> Result<Value> {
        let max = match self.input.get("MaxResults") {
            Some(n) => n.as_u64().filter(|n| (1..=20).contains(n)).ok_or_else(|| invalid("MaxResults must be from 1 to 20."))? as usize,
            None => 20,
        };
        let start = match self.text("NextToken") {
            Some(token) => token.parse::<usize>().map_err(|_| invalid("The NextToken isn't valid."))?,
            None => 0,
        };
        let total = items.len();
        let page: Vec<Value> = items.into_iter().skip(start).take(max).collect();
        let mut value = json!({ key: page });
        if start + max < total {
            value["NextToken"] = json!((start + max).to_string());
        }
        Ok(value)
    }
}

/// Policy `id`'s summary and content, if there's one (FullAWSAccess too).
async fn policy(client: &Object, management: &str, id: &str) -> anyhow::Result<Option<(Value, String)>> {
    if id == FULL_ACCESS {
        let summary = json!({
            "Id": FULL_ACCESS, "Arn": FULL_ACCESS_ARN, "Name": "FullAWSAccess", "Description": "Allows access to every operation",
            "Type": SCP, "AwsManaged": true,
        });
        return Ok(Some((summary, FULL_ACCESS_DOCUMENT.to_owned())));
    }
    let row = client.query_opt_cached("SELECT name, description, content FROM organization_policies WHERE id = $1", &[&id]).await?;
    Ok(row.map(|r| {
        let summary = json!({
            "Id": id, "Arn": policy_arn(management, id), "Name": r.get::<_, String>(0), "Description": r.get::<_, String>(1),
            "Type": SCP, "AwsManaged": false,
        });
        (summary, r.get(2))
    }))
}

/// Checks `content` as an SCP, as Organizations does: an identity policy
/// with a `Version`, whose Allow statements' only resource is `*`.
fn check_content(content: &str) -> Result<()> {
    let malformed = |why: &str| error(StatusCode::BAD_REQUEST, "MalformedPolicyDocumentException", why);
    if content.chars().count() > MAX_CONTENT {
        return Err(constraint("POLICY_CONTENT_LIMIT_EXCEEDED", format!("An SCP is at most {MAX_CONTENT} characters.")));
    }
    crate::policy::Policy::parse(content, crate::policy::Kind::Identity).map_err(|e| malformed(&e.message))?;
    let document: Value = serde_json::from_str(content).map_err(|_| malformed("The policy isn't JSON."))?;
    if document.get("Version").and_then(Value::as_str) != Some("2012-10-17") {
        return Err(malformed("Every SCP must have a Version of 2012-10-17."));
    }
    let statements = match document.get("Statement") {
        Some(Value::Array(list)) => list.clone(),
        Some(one) => vec![one.clone()],
        None => Vec::new(),
    };
    for statement in &statements {
        let allow = statement.get("Effect").and_then(Value::as_str).is_some_and(|e| e.eq_ignore_ascii_case("Allow"));
        let star = match statement.get("Resource") {
            Some(Value::String(r)) => r == "*",
            Some(Value::Array(list)) => list.iter().all(|r| r.as_str() == Some("*")),
            _ => false,
        };
        if allow && !star {
            return Err(malformed("In an SCP's Allow statement, the Resource can only be \"*\"."));
        }
    }
    Ok(())
}

/// The targets policy `id` is attached to.
async fn targets_of(client: &Object, id: &str) -> anyhow::Result<Vec<String>> {
    let rows = client
        .query_cached("SELECT target_id FROM organization_policy_attachments WHERE policy_id = $1 ORDER BY target_id", &[&id])
        .await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}

/// The policies attached to `target`.
async fn policies_of(client: &Object, target: &str) -> anyhow::Result<Vec<String>> {
    let rows = client
        .query_cached("SELECT policy_id FROM organization_policy_attachments WHERE target_id = $1 ORDER BY policy_id", &[&target])
        .await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}

/// Answers `operation`, already allowed, as `input` asks.
pub async fn answer(operation: &str, input: &Input<'_>) -> Result<Value> {
    let client = input.client;
    let management = input.management;
    match operation {
        "ListRoots" => {
            let enabled = scps_enabled(client).await?;
            input.page("Roots", vec![input.root_json(enabled)])
        }
        "EnablePolicyType" => {
            input.root()?;
            input.policy_type("PolicyType")?;
            if scps_enabled(client).await? {
                return Err(error(StatusCode::BAD_REQUEST, "PolicyTypeAlreadyEnabledException", "The specified policy type is already enabled."));
            }
            client.execute_cached("INSERT INTO organization_policy_types (type) VALUES ($1) ON CONFLICT DO NOTHING", &[&SCP]).await?;
            // FullAWSAccess everywhere: the root, every unit and account.
            attach_default(client, &root_id(management)).await?;
            for row in client.query_cached("SELECT id FROM organizational_units", &[]).await? {
                attach_default(client, row.get::<_, &str>(0)).await?;
            }
            for row in client.query_cached("SELECT id FROM accounts WHERE NOT operator AND closed_at IS NULL", &[]).await? {
                attach_default(client, row.get::<_, &str>(0)).await?;
            }
            Ok(json!({ "Root": input.root_json(true) }))
        }
        "DisablePolicyType" => {
            input.root()?;
            input.policy_type("PolicyType")?;
            if !scps_enabled(client).await? {
                return Err(error(StatusCode::BAD_REQUEST, "PolicyTypeNotEnabledException", "This policy type isn't enabled."));
            }
            // All SCPs come off: enabled again, it's FullAWSAccess anew.
            client.execute_cached("DELETE FROM organization_policy_attachments", &[]).await?;
            client.execute_cached("DELETE FROM organization_policy_types WHERE type = $1", &[&SCP]).await?;
            Ok(json!({ "Root": input.root_json(false) }))
        }
        "CreateOrganizationalUnit" => {
            let name = input.required("Name")?;
            if name.chars().count() > 128 {
                return Err(invalid("An OU's name is 1 to 128 characters."));
            }
            if input.input.get("Tags").and_then(Value::as_array).is_some_and(|t| !t.is_empty()) {
                return Err(error(StatusCode::NOT_IMPLEMENTED, "NotImplemented", "Cairn doesn't tag organizational units."));
            }
            let parent = input.parent("ParentId", "ParentNotFoundException").await?;
            let depth = match &parent {
                Some(unit) => path_to(client, unit).await?.len(),
                None => 0,
            };
            if depth >= MAX_DEPTH {
                return Err(constraint("OU_DEPTH_LIMIT_EXCEEDED", format!("OUs nest at most {MAX_DEPTH} deep.")));
            }
            let id = format!("ou-{}-{}", root_hash(management), random_part()?);
            let made = client
                .execute_cached("INSERT INTO organizational_units (id, parent_id, name) VALUES ($1, $2, $3)", &[&id, &parent, &name])
                .await;
            match made {
                Ok(_) => {}
                Err(e) if e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) => {
                    return Err(error(StatusCode::BAD_REQUEST, "DuplicateOrganizationalUnitException", "An OU with the same name already exists."));
                }
                Err(e) => return Err(anyhow::Error::from(e).into()),
            }
            attach_default(client, &id).await?;
            Ok(json!({ "OrganizationalUnit": input.unit_json(&id, name).await? }))
        }
        "DescribeOrganizationalUnit" => {
            let (id, name, _) = input.unit().await?;
            Ok(json!({ "OrganizationalUnit": input.unit_json(&id, &name).await? }))
        }
        "UpdateOrganizationalUnit" => {
            let (id, mut name, _) = input.unit().await?;
            if let Some(new) = input.text("Name") {
                if new.is_empty() || new.chars().count() > 128 {
                    return Err(invalid("An OU's name is 1 to 128 characters."));
                }
                let changed = client.execute_cached("UPDATE organizational_units SET name = $2 WHERE id = $1", &[&id, &new]).await;
                if let Err(e) = changed {
                    if e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) {
                        return Err(error(StatusCode::BAD_REQUEST, "DuplicateOrganizationalUnitException", "An OU with the same name already exists."));
                    }
                    return Err(anyhow::Error::from(e).into());
                }
                name = new.to_owned();
            }
            Ok(json!({ "OrganizationalUnit": input.unit_json(&id, &name).await? }))
        }
        "DeleteOrganizationalUnit" => {
            let (id, _, _) = input.unit().await?;
            let children: i64 = client
                .query_one_cached(
                    "SELECT (SELECT count(*) FROM organizational_units WHERE parent_id = $1)
                          + (SELECT count(*) FROM accounts WHERE parent_id = $1 AND closed_at IS NULL)",
                    &[&id],
                )
                .await?
                .get(0);
            if children > 0 {
                return Err(error(
                    StatusCode::BAD_REQUEST,
                    "OrganizationalUnitNotEmptyException",
                    "The specified OU is not empty. Move all accounts to another root or to other OUs, remove all child OUs, and try the operation again.",
                ));
            }
            // Closed accounts in it go to the root.
            client.execute_cached("UPDATE accounts SET parent_id = NULL WHERE parent_id = $1", &[&id]).await?;
            client.execute_cached("DELETE FROM organization_policy_attachments WHERE target_id = $1", &[&id]).await?;
            client.execute_cached("DELETE FROM organizational_units WHERE id = $1", &[&id]).await?;
            Ok(json!({}))
        }
        "ListOrganizationalUnitsForParent" => {
            let parent = input.parent("ParentId", "ParentNotFoundException").await?;
            let rows = client
                .query_cached("SELECT id, name FROM organizational_units WHERE parent_id IS NOT DISTINCT FROM $1 ORDER BY name", &[&parent])
                .await?;
            let mut units = Vec::new();
            for row in &rows {
                units.push(input.unit_json(row.get(0), row.get(1)).await?);
            }
            input.page("OrganizationalUnits", units)
        }
        "ListAccountsForParent" => {
            let parent = input.parent("ParentId", "ParentNotFoundException").await?;
            let accounts: Vec<Value> = super::list(client)
                .await?
                .iter()
                .filter(|a| a.parent == parent)
                .map(|a| a.json(management))
                .collect();
            input.page("Accounts", accounts)
        }
        "ListChildren" => {
            let parent = input.parent("ParentId", "ParentNotFoundException").await?;
            let children: Vec<Value> = match input.required("ChildType")? {
                "ACCOUNT" => super::list(client)
                    .await?
                    .iter()
                    .filter(|a| a.parent == parent)
                    .map(|a| json!({ "Id": a.id, "Type": "ACCOUNT" }))
                    .collect(),
                "ORGANIZATIONAL_UNIT" => client
                    .query_cached("SELECT id FROM organizational_units WHERE parent_id IS NOT DISTINCT FROM $1 ORDER BY name", &[&parent])
                    .await?
                    .iter()
                    .map(|r| json!({ "Id": r.get::<_, String>(0), "Type": "ORGANIZATIONAL_UNIT" }))
                    .collect(),
                _ => return Err(invalid("ChildType must be ACCOUNT or ORGANIZATIONAL_UNIT.")),
            };
            input.page("Children", children)
        }
        "ListParents" => {
            let child = input.required("ChildId")?;
            let parent: Option<String> = match target(client, management, child).await? {
                Some((Kind::Unit, _)) => {
                    client.query_one_cached("SELECT parent_id FROM organizational_units WHERE id = $1", &[&child]).await?.get(0)
                }
                Some((Kind::Account, _)) => client.query_one_cached("SELECT parent_id FROM accounts WHERE id = $1", &[&child]).await?.get(0),
                _ => return Err(not_found("ChildNotFoundException", "We can't find an organizational unit (OU) or AWS account with the ChildId that you specified.")),
            };
            let parent = match parent {
                Some(unit) => json!({ "Id": unit, "Type": "ORGANIZATIONAL_UNIT" }),
                None => json!({ "Id": root_id(management), "Type": "ROOT" }),
            };
            input.page("Parents", vec![parent])
        }
        "MoveAccount" => {
            let id = input.required("AccountId")?;
            let account = super::load(client, id).await?.filter(|a| a.closed.is_none());
            let account = account.ok_or_else(|| super::no_such_account(id))?;
            let source = input.parent("SourceParentId", "SourceParentNotFoundException").await?;
            let destination = input.parent("DestinationParentId", "DestinationParentNotFoundException").await?;
            if account.parent != source {
                return Err(not_found("SourceParentNotFoundException", "The account isn't in the SourceParentId that you specified."));
            }
            if source == destination {
                return Err(error(StatusCode::BAD_REQUEST, "DuplicateAccountException", "That account is already present in the specified destination."));
            }
            client.execute_cached("UPDATE accounts SET parent_id = $2 WHERE id = $1", &[&id, &destination]).await?;
            Ok(json!({}))
        }
        "CreatePolicy" => {
            input.policy_type("Type")?;
            let name = input.required("Name")?;
            let content = input.required("Content")?;
            let description = input.text("Description").unwrap_or("");
            if name.chars().count() > 128 || description.chars().count() > 512 {
                return Err(invalid("A policy's name is 1 to 128 characters, its description at most 512."));
            }
            if input.input.get("Tags").and_then(Value::as_array).is_some_and(|t| !t.is_empty()) {
                return Err(error(StatusCode::NOT_IMPLEMENTED, "NotImplemented", "Cairn doesn't tag policies."));
            }
            check_content(content)?;
            let id = format!("p-{}", random_part()?);
            let made = client
                .execute_cached(
                    "INSERT INTO organization_policies (id, type, name, description, content) VALUES ($1, $2, $3, $4, $5)",
                    &[&id, &SCP, &name, &description, &content],
                )
                .await;
            match made {
                Ok(_) => {}
                Err(e) if e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) => {
                    return Err(error(StatusCode::BAD_REQUEST, "DuplicatePolicyException", "A policy with the same name already exists."));
                }
                Err(e) => return Err(anyhow::Error::from(e).into()),
            }
            let (summary, content) = policy(client, management, &id).await?.ok_or_else(|| anyhow::anyhow!("a new policy is gone"))?;
            Ok(json!({ "Policy": { "PolicySummary": summary, "Content": content } }))
        }
        "DescribePolicy" => {
            let (summary, content) = input.policy().await?;
            Ok(json!({ "Policy": { "PolicySummary": summary, "Content": content } }))
        }
        "UpdatePolicy" => {
            let (summary, _) = input.policy().await?;
            let id = summary["Id"].as_str().unwrap_or_default().to_owned();
            if summary["AwsManaged"] == json!(true) {
                return Err(error(StatusCode::BAD_REQUEST, "PolicyChangesInProgressException", "An AWS managed policy can't be changed."));
            }
            if let Some(content) = input.text("Content") {
                check_content(content)?;
            }
            let (name, description) = (input.text("Name"), input.text("Description"));
            if name.is_some_and(|n| n.is_empty() || n.chars().count() > 128) || description.is_some_and(|d| d.chars().count() > 512) {
                return Err(invalid("A policy's name is 1 to 128 characters, its description at most 512."));
            }
            let changed = client
                .execute_cached(
                    "UPDATE organization_policies SET name = coalesce($2, name), description = coalesce($3, description),
                            content = coalesce($4, content) WHERE id = $1",
                    &[&id, &name, &description, &input.text("Content")],
                )
                .await;
            if let Err(e) = changed {
                if e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) {
                    return Err(error(StatusCode::BAD_REQUEST, "DuplicatePolicyException", "A policy with the same name already exists."));
                }
                return Err(anyhow::Error::from(e).into());
            }
            let (summary, content) = policy(client, management, &id).await?.ok_or_else(|| anyhow::anyhow!("a changed policy is gone"))?;
            Ok(json!({ "Policy": { "PolicySummary": summary, "Content": content } }))
        }
        "DeletePolicy" => {
            let (summary, _) = input.policy().await?;
            let id = summary["Id"].as_str().unwrap_or_default().to_owned();
            if summary["AwsManaged"] == json!(true) {
                return Err(invalid("An AWS managed policy can't be deleted."));
            }
            if !targets_of(client, &id).await?.is_empty() {
                return Err(error(
                    StatusCode::BAD_REQUEST,
                    "PolicyInUseException",
                    "The policy is attached to one or more entities. You must detach it from all roots, OUs, and accounts before performing this operation.",
                ));
            }
            client.execute_cached("DELETE FROM organization_policies WHERE id = $1", &[&id]).await?;
            Ok(json!({}))
        }
        "ListPolicies" => {
            input.policy_type("Filter")?;
            let mut policies = vec![policy(client, management, FULL_ACCESS).await?.expect("FullAWSAccess").0];
            for row in client.query_cached("SELECT id FROM organization_policies ORDER BY name", &[]).await? {
                if let Some((summary, _)) = policy(client, management, row.get::<_, &str>(0)).await? {
                    policies.push(summary);
                }
            }
            input.page("Policies", policies)
        }
        "AttachPolicy" | "DetachPolicy" => {
            let (summary, _) = input.policy().await?;
            let id = summary["Id"].as_str().unwrap_or_default().to_owned();
            let target_id = input.required("TargetId")?;
            if target(client, management, target_id).await?.is_none() {
                return Err(not_found("TargetNotFoundException", "We can't find a root, OU, or account with the TargetId that you specified."));
            }
            if !scps_enabled(client).await? {
                return Err(error(StatusCode::BAD_REQUEST, "PolicyTypeNotEnabledException", "This policy type isn't enabled."));
            }
            let attached = policies_of(client, target_id).await?;
            match operation {
                "AttachPolicy" => {
                    if attached.contains(&id) {
                        return Err(error(StatusCode::BAD_REQUEST, "DuplicatePolicyAttachmentException", "The selected policy is already attached to the specified target."));
                    }
                    if attached.len() >= MAX_ATTACHED {
                        return Err(constraint("MAX_POLICY_TYPE_ATTACHMENT_LIMIT_EXCEEDED", format!("A target has at most {MAX_ATTACHED} SCPs.")));
                    }
                    client
                        .execute_cached("INSERT INTO organization_policy_attachments (policy_id, target_id) VALUES ($1, $2)", &[&id, &target_id])
                        .await?;
                }
                _ => {
                    if !attached.contains(&id) {
                        return Err(error(StatusCode::BAD_REQUEST, "PolicyNotAttachedException", "The policy isn't attached to the specified target in the specified root."));
                    }
                    if attached.len() <= 1 {
                        return Err(constraint(
                            "MIN_POLICY_TYPE_ATTACHMENT_LIMIT_EXCEEDED",
                            "Every root, OU and account must have an SCP: attach another before detaching this one.",
                        ));
                    }
                    client
                        .execute_cached("DELETE FROM organization_policy_attachments WHERE policy_id = $1 AND target_id = $2", &[&id, &target_id])
                        .await?;
                }
            }
            Ok(json!({}))
        }
        "ListPoliciesForTarget" => {
            input.policy_type("Filter")?;
            let target_id = input.required("TargetId")?;
            if target(client, management, target_id).await?.is_none() {
                return Err(not_found("TargetNotFoundException", "We can't find a root, OU, or account with the TargetId that you specified."));
            }
            let mut policies = Vec::new();
            for id in policies_of(client, target_id).await? {
                if let Some((summary, _)) = policy(client, management, &id).await? {
                    policies.push(summary);
                }
            }
            input.page("Policies", policies)
        }
        "ListTargetsForPolicy" => {
            let (summary, _) = input.policy().await?;
            let id = summary["Id"].as_str().unwrap_or_default().to_owned();
            let mut targets = Vec::new();
            for target_id in targets_of(client, &id).await? {
                if let Some((kind, name)) = target(client, management, &target_id).await? {
                    targets.push(json!({
                        "TargetId": target_id, "Arn": target_arn(management, kind, &target_id), "Name": name, "Type": kind.as_str(),
                    }));
                }
            }
            input.page("Targets", targets)
        }
        other => Err(error(StatusCode::NOT_IMPLEMENTED, "NotImplemented", format!("Cairn doesn't implement {other}."))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_the_structure() {
        let root = root_id("123456789012");
        assert!(root.starts_with("r-") && root.len() == 6, "{root}");
        assert!(root_arn("123456789012").ends_with(&format!("/{root}")));
        assert_eq!(policy_arn("123456789012", FULL_ACCESS), FULL_ACCESS_ARN);
        assert!(policy_arn("123456789012", "p-abcdefgh").contains(":policy/o-") && policy_arn("123456789012", "p-abcdefgh").ends_with("/service_control_policy/p-abcdefgh"));
    }

    #[test]
    fn checks_scps() {
        let allow_all = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;
        assert!(check_content(allow_all).is_ok());
        let deny_bucket = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:DeleteBucket","Resource":"arn:aws:s3:::prod-*"}]}"#;
        assert!(check_content(deny_bucket).is_ok());
        for bad in [
            r#"{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#,
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::x"}]}"#,
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}"#,
            "not json",
        ] {
            assert!(check_content(bad).is_err(), "{bad}");
        }
        let long = format!(r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Action":"s3:{}","Resource":"*"}}]}}"#, "x".repeat(MAX_CONTENT));
        assert_eq!(check_content(&long).unwrap_err().code, "ConstraintViolationException");
    }
}
