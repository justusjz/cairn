//! IAM Identity Center's management APIs, on the S3 endpoint as IAM's and
//! SNS's are: **sso-admin** (signed for `sso`; `X-Amz-Target:
//! SWBExternalService.<Operation>`), for the instance, permission sets,
//! their policies and assignments, and **identitystore** (signed for
//! `identitystore`; `AWSIdentityStore.<Operation>`), for the identity
//! store's users, groups and memberships, which only reads it: users and
//! groups come from sign-ins (see `identity_center`). Both speak AWS's JSON
//! 1.1 protocol: a JSON body, answered with JSON, an error as its
//! `__type` and `message`.
//!
//! Every operation is decided as its action (`sso:CreatePermissionSet`,
//! `identitystore:DescribeUser`, …) on its resource: the instance, a
//! permission set, the identity store, a user or group. A cluster has one
//! account, so its instance is the only one, and the only target of
//! assignments; its changes apply at once, so its asynchronous requests
//! (assignments, provisioning) are done when they're answered, and their
//! statuses say so. Applications, trusted token issuers, attributes for
//! access control, regions, the instance's own lifecycle, and the identity
//! store's writes answer 501.

use std::net::IpAddr;
use std::sync::Arc;

use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode, body::Bytes};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    App,
    auth::Signed,
    identity_center::{self as ic, Group, Lookup, OperationKind, PermissionSet, PrincipalType, User},
    managed::Refused,
    policy::Verdict,
    s3::access::{Access, Origin},
    s3::actions::{Check, On},
    users::{self, Principal},
};

/// The most of a request's body that's read.
const MAX_BODY: usize = 256 * 1024;
/// A listing's longest page, and its default.
const MAX_RESULTS: usize = 100;

/// sso-admin's operations Cairn answers, with their actions.
const SSO: &[(&str, &str)] = &[
    ("ListInstances", "sso:ListInstances"),
    ("DescribeInstance", "sso:DescribeInstance"),
    ("CreatePermissionSet", "sso:CreatePermissionSet"),
    ("DescribePermissionSet", "sso:DescribePermissionSet"),
    ("UpdatePermissionSet", "sso:UpdatePermissionSet"),
    ("DeletePermissionSet", "sso:DeletePermissionSet"),
    ("ListPermissionSets", "sso:ListPermissionSets"),
    ("PutInlinePolicyToPermissionSet", "sso:PutInlinePolicyToPermissionSet"),
    ("GetInlinePolicyForPermissionSet", "sso:GetInlinePolicyForPermissionSet"),
    ("DeleteInlinePolicyFromPermissionSet", "sso:DeleteInlinePolicyFromPermissionSet"),
    ("AttachManagedPolicyToPermissionSet", "sso:AttachManagedPolicyToPermissionSet"),
    ("DetachManagedPolicyFromPermissionSet", "sso:DetachManagedPolicyFromPermissionSet"),
    ("ListManagedPoliciesInPermissionSet", "sso:ListManagedPoliciesInPermissionSet"),
    ("AttachCustomerManagedPolicyReferenceToPermissionSet", "sso:AttachCustomerManagedPolicyReferenceToPermissionSet"),
    ("DetachCustomerManagedPolicyReferenceFromPermissionSet", "sso:DetachCustomerManagedPolicyReferenceFromPermissionSet"),
    ("ListCustomerManagedPolicyReferencesInPermissionSet", "sso:ListCustomerManagedPolicyReferencesInPermissionSet"),
    ("PutPermissionsBoundaryToPermissionSet", "sso:PutPermissionsBoundaryToPermissionSet"),
    ("GetPermissionsBoundaryForPermissionSet", "sso:GetPermissionsBoundaryForPermissionSet"),
    ("DeletePermissionsBoundaryFromPermissionSet", "sso:DeletePermissionsBoundaryFromPermissionSet"),
    ("CreateAccountAssignment", "sso:CreateAccountAssignment"),
    ("DeleteAccountAssignment", "sso:DeleteAccountAssignment"),
    ("DescribeAccountAssignmentCreationStatus", "sso:DescribeAccountAssignmentCreationStatus"),
    ("DescribeAccountAssignmentDeletionStatus", "sso:DescribeAccountAssignmentDeletionStatus"),
    ("ListAccountAssignmentCreationStatus", "sso:ListAccountAssignmentCreationStatus"),
    ("ListAccountAssignmentDeletionStatus", "sso:ListAccountAssignmentDeletionStatus"),
    ("ListAccountAssignments", "sso:ListAccountAssignments"),
    ("ListAccountAssignmentsForPrincipal", "sso:ListAccountAssignmentsForPrincipal"),
    ("ProvisionPermissionSet", "sso:ProvisionPermissionSet"),
    ("DescribePermissionSetProvisioningStatus", "sso:DescribePermissionSetProvisioningStatus"),
    ("ListPermissionSetProvisioningStatus", "sso:ListPermissionSetProvisioningStatus"),
    ("ListPermissionSetsProvisionedToAccount", "sso:ListPermissionSetsProvisionedToAccount"),
    ("ListAccountsForProvisionedPermissionSet", "sso:ListAccountsForProvisionedPermissionSet"),
    ("TagResource", "sso:TagResource"),
    ("UntagResource", "sso:UntagResource"),
    ("ListTagsForResource", "sso:ListTagsForResource"),
];

/// identitystore's operations Cairn answers (its reads), with their actions.
const IDENTITY_STORE: &[(&str, &str)] = &[
    ("GetUserId", "identitystore:GetUserId"),
    ("DescribeUser", "identitystore:DescribeUser"),
    ("ListUsers", "identitystore:ListUsers"),
    ("GetGroupId", "identitystore:GetGroupId"),
    ("DescribeGroup", "identitystore:DescribeGroup"),
    ("ListGroups", "identitystore:ListGroups"),
    ("GetGroupMembershipId", "identitystore:GetGroupMembershipId"),
    ("DescribeGroupMembership", "identitystore:DescribeGroupMembership"),
    ("ListGroupMemberships", "identitystore:ListGroupMemberships"),
    ("ListGroupMembershipsForMember", "identitystore:ListGroupMembershipsForMember"),
    ("IsMemberInGroups", "identitystore:IsMemberInGroups"),
];

/// Whether a request signed as `signed` is one of these APIs'.
pub fn wants(signed: &Signed) -> bool {
    matches!(signed.service.as_str(), "sso" | "identitystore")
}

/// A failed request: its status, code and message.
#[derive(Debug)]
pub struct Error {
    status: StatusCode,
    code: &'static str,
    message: String,
}

type Result<T> = std::result::Result<T, Error>;

fn error(status: StatusCode, code: &'static str, message: impl Into<String>) -> Error {
    Error { status, code, message: message.into() }
}

fn validation(message: impl Into<String>) -> Error {
    error(StatusCode::BAD_REQUEST, "ValidationException", message)
}

fn not_found(message: impl Into<String>) -> Error {
    error(StatusCode::BAD_REQUEST, "ResourceNotFoundException", message)
}

fn conflict(message: impl Into<String>) -> Error {
    error(StatusCode::BAD_REQUEST, "ConflictException", message)
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Error {
        match e.downcast::<Refused>() {
            Ok(Refused::NoSuch(m)) => not_found(m),
            Ok(Refused::Exists(m) | Refused::Conflict(m)) => conflict(m),
            Ok(Refused::Limit(m)) => error(StatusCode::BAD_REQUEST, "ServiceQuotaExceededException", m),
            Ok(Refused::Malformed(m) | Refused::Invalid(m) | Refused::Validation(m) | Refused::Unmodifiable(m)) => validation(m),
            Ok(Refused::Unsupported(m)) => error(StatusCode::NOT_IMPLEMENTED, "NotImplemented", m),
            Err(e) => {
                eprintln!("sso: a request failed: {e:#}");
                error(StatusCode::INTERNAL_SERVER_ERROR, "InternalServerException", "We encountered an internal error. Please try again.")
            }
        }
    }
}

impl From<tokio_postgres::Error> for Error {
    fn from(e: tokio_postgres::Error) -> Error {
        anyhow::Error::from(e).into()
    }
}

impl From<deadpool_postgres::PoolError> for Error {
    fn from(e: deadpool_postgres::PoolError) -> Error {
        anyhow::Error::from(e).into()
    }
}

/// Handles a request `wants` says is one of these APIs'.
pub async fn handle(app: &Arc<App>, req: Request<crate::listen::ClientBody>, signed: Signed, peer: IpAddr) -> Response<Full<Bytes>> {
    let request_id = Uuid::new_v4().to_string();
    let (status, body) = match respond(app, req, &signed, peer).await {
        Ok(value) => (StatusCode::OK, value.to_string()),
        Err(e) => (e.status, json!({ "__type": e.code, "message": e.message }).to_string()),
    };
    Response::builder()
        .status(status)
        .header("content-type", "application/x-amz-json-1.1")
        .header("x-amzn-requestid", request_id)
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

async fn respond(app: &Arc<App>, req: Request<crate::listen::ClientBody>, signed: &Signed, peer: IpAddr) -> Result<Value> {
    let (parts, body) = req.into_parts();
    let body = Limited::new(body, MAX_BODY)
        .collect()
        .await
        .map_err(|_| validation("The request's body is too large, or broken."))?
        .to_bytes();
    let target = parts.headers.get("x-amz-target").and_then(|v| v.to_str().ok()).unwrap_or("");
    let (prefix, ops) = match signed.service.as_str() {
        "sso" => ("SWBExternalService.", SSO),
        _ => ("AWSIdentityStore.", IDENTITY_STORE),
    };
    let Some(operation) = target.strip_prefix(prefix) else {
        return Err(error(StatusCode::BAD_REQUEST, "UnknownOperationException", format!("No such operation: {target}")));
    };
    let Some(&(operation, action)) = ops.iter().find(|(op, _)| *op == operation) else {
        return Err(error(StatusCode::NOT_IMPLEMENTED, "NotImplemented", format!("Cairn doesn't implement {operation}.")));
    };
    let client = app.pool.get().await?;
    let principal = match Principal::authenticate(&client, &app.sessions, &signed.access_key, signed.token.as_deref()).await? {
        Ok(principal) => principal,
        Err(users::Unknown::Expired) => {
            return Err(error(StatusCode::BAD_REQUEST, "ExpiredTokenException", "The security token included in the request is expired"));
        }
        Err(_) => {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "UnrecognizedClientException",
                "The security token included in the request is invalid.",
            ));
        }
    };
    let query = parts.uri.query().unwrap_or("");
    crate::auth::verify_sigv4_with_body(parts.method.as_str(), parts.uri.path(), query, &parts.headers, &principal.secret, &body)
        .map_err(|r| error(StatusCode::BAD_REQUEST, if r.code == "SignatureDoesNotMatch" { "InvalidSignatureException" } else { "IncompleteSignature" }, r.message))?;
    let input: Value = match body.is_empty() {
        true => json!({}),
        false => serde_json::from_slice(&body).map_err(|_| error(StatusCode::BAD_REQUEST, "SerializationException", "The request's body isn't JSON."))?,
    };
    if !input.is_object() {
        return Err(error(StatusCode::BAD_REQUEST, "SerializationException", "The request's body isn't a JSON object."));
    }
    let origin = Origin { peer: Some(peer), trusted_proxies: &app.trusted_proxies, signed: Some(signed), form: false };
    let mut access = Access::new(Some(&principal), &principal.account, &parts.method, &parts.headers, "", &origin)?;
    dispatch(&client, &principal, &mut access, &signed.service, operation, action, &input).await
}

/// Answers `operation` (`action` its action) of `service` (`sso`, or
/// `identitystore`), with `input`, by `principal`, as `access` decides it.
async fn dispatch(
    client: &deadpool_postgres::Object,
    principal: &Principal,
    access: &mut Access,
    service: &str,
    operation: &str,
    action: &'static str,
    input: &Value,
) -> Result<Value> {
    let account = principal.account.clone();
    let mut ctx = Ctx { client, principal, access, account, action, input };
    match service {
        "sso" => ctx.sso(operation).await,
        _ => ctx.identity_store(operation).await,
    }
}

/// A request being answered.
struct Ctx<'a> {
    client: &'a deadpool_postgres::Object,
    principal: &'a Principal,
    access: &'a mut Access,
    account: String,
    /// Its operation's action.
    action: &'static str,
    input: &'a Value,
}

impl Ctx<'_> {
    /// Refuses the request unless its action on `resource` (an ARN; `*`:
    /// none) is allowed.
    fn check(&self, resource: &str) -> Result<()> {
        let on = match resource {
            "*" => On::Account,
            arn => On::Arn(arn.to_owned()),
        };
        let check = Check { action: self.action, on };
        match self.access.verdict(&check) {
            Verdict::Allow => Ok(()),
            verdict => Err(error(
                StatusCode::BAD_REQUEST,
                "AccessDeniedException",
                format!(
                    "User: {} is not authorized to perform: {} on resource: {resource} {}",
                    self.principal.arn(),
                    self.action,
                    verdict.why(self.action, self.access.boundary())
                ),
            )),
        }
    }

    fn text(&self, name: &str) -> Option<&str> {
        self.input.get(name).and_then(Value::as_str)
    }

    fn required(&self, name: &str) -> Result<&str> {
        match self.text(name) {
            Some(value) if !value.is_empty() => Ok(value),
            _ => Err(validation(format!("1 validation error detected: Value null at '{}' failed to satisfy constraint: Member must not be null", lower_first(name)))),
        }
    }

    /// The instance a request names (`InstanceArn`), which must be the
    /// account's.
    fn instance(&self) -> Result<String> {
        let arn = self.required("InstanceArn")?;
        let ours = ic::instance_arn(&self.account);
        match arn == ours {
            true => Ok(ours),
            false => Err(not_found(format!("Instance {arn} doesn't exist."))),
        }
    }

    /// The permission set a request names (`PermissionSetArn`), allowed the
    /// request's action.
    async fn permission_set(&self) -> Result<PermissionSet> {
        self.instance()?;
        let arn = self.required("PermissionSetArn")?.to_owned();
        self.check(&arn)?;
        ic::load_arn(self.client, &self.account, &arn).await?.ok_or_else(|| not_found(format!("Could not find PermissionSet with ARN {arn}.")))
    }

    /// The account a request targets (`TargetId` and `TargetType`, or
    /// `AccountId`), which must be the cluster's.
    fn target(&self, id: &str, kind: Option<&str>) -> Result<String> {
        let target = self.required(id)?;
        if let Some(kind) = kind
            && self.text(kind) != Some("AWS_ACCOUNT")
        {
            return Err(validation(format!("{kind} must be AWS_ACCOUNT.")));
        }
        match target == self.account {
            true => Ok(target.to_owned()),
            false => Err(validation(format!("Account {target} isn't this cluster's ({}): it's the only one.", self.account))),
        }
    }

    /// A page of `items`: `MaxResults` from `NextToken` (an offset), and the
    /// token of the next page.
    fn page<T>(&self, items: Vec<T>) -> Result<(Vec<T>, Option<String>)> {
        let max = match self.input.get("MaxResults") {
            Some(n) => n.as_u64().filter(|n| (1..=MAX_RESULTS as u64).contains(n)).ok_or_else(|| validation("MaxResults must be from 1 to 100."))? as usize,
            None => MAX_RESULTS,
        };
        let start = match self.text("NextToken") {
            Some(token) => token.parse::<usize>().map_err(|_| validation("The NextToken isn't valid."))?,
            None => 0,
        };
        let next = (items.len() > start + max).then(|| (start + max).to_string());
        Ok((items.into_iter().skip(start).take(max).collect(), next))
    }

    // ─── sso-admin ───────────────────────────────────────────────────────────

    async fn sso(&mut self, operation: &str) -> Result<Value> {
        match operation {
            "ListInstances" => {
                self.check("*")?;
                Ok(json!({ "Instances": [self.instance_json()] }))
            }
            "DescribeInstance" => {
                let arn = self.instance()?;
                self.check(&arn)?;
                Ok(self.instance_json())
            }
            "CreatePermissionSet" => {
                let instance = self.instance()?;
                self.check(&instance)?;
                let name = self.required("Name")?;
                let duration = self.duration()?.unwrap_or(ic::DEFAULT_SESSION);
                let tags = self.tags("Tags")?;
                let stored = (!tags.is_empty()).then(|| stored_tags(&tags));
                let new = ic::New {
                    name,
                    description: self.text("Description").unwrap_or(""),
                    session_duration: duration,
                    relay_state: self.text("RelayState"),
                    tags: stored.as_deref(),
                };
                let set = ic::create(self.client, &self.account, &new).await?;
                Ok(json!({ "PermissionSet": set_json(&set) }))
            }
            "DescribePermissionSet" => {
                let set = self.permission_set().await?;
                Ok(json!({ "PermissionSet": set_json(&set) }))
            }
            "UpdatePermissionSet" => {
                let set = self.permission_set().await?;
                let change = ic::Change {
                    description: self.text("Description"),
                    session_duration: self.duration()?,
                    relay_state: self.text("RelayState"),
                };
                ic::update(self.client, &set, &change).await?;
                Ok(json!({}))
            }
            "DeletePermissionSet" => {
                let set = self.permission_set().await?;
                ic::delete(self.client, &set).await?;
                Ok(json!({}))
            }
            "ListPermissionSets" => {
                let instance = self.instance()?;
                self.check(&instance)?;
                let sets: Vec<String> = ic::list(self.client, &self.account).await?.iter().map(PermissionSet::arn).collect();
                let (page, next) = self.page(sets)?;
                Ok(with_token(json!({ "PermissionSets": page }), next))
            }
            "PutInlinePolicyToPermissionSet" => {
                let set = self.permission_set().await?;
                let policy = self.required("InlinePolicy")?.to_owned();
                ic::set_inline_policy(self.client, &set, Some(&policy)).await?;
                Ok(json!({}))
            }
            "GetInlinePolicyForPermissionSet" => {
                let set = self.permission_set().await?;
                let policy = ic::inline_policy(self.client, &set).await?.unwrap_or_default();
                Ok(json!({ "InlinePolicy": policy }))
            }
            "DeleteInlinePolicyFromPermissionSet" => {
                let set = self.permission_set().await?;
                ic::set_inline_policy(self.client, &set, None).await?;
                Ok(json!({}))
            }
            "AttachManagedPolicyToPermissionSet" | "DetachManagedPolicyFromPermissionSet" => {
                let set = self.permission_set().await?;
                let arn = self.required("ManagedPolicyArn")?.to_owned();
                if !ic::is_aws(&arn) {
                    return Err(validation(format!(
                        "{arn} isn't an AWS managed policy: attach the account's own as a customer managed policy reference."
                    )));
                }
                let attach = operation.starts_with("Attach");
                if attach && ic::managed_policies(self.client, &set).await?.iter().any(|a| a.arn == arn) {
                    return Err(conflict(format!("Permission set {} already has the managed policy {arn}.", set.name)));
                }
                ic::attach(self.client, &set, &arn, attach).await?;
                Ok(json!({}))
            }
            "ListManagedPoliciesInPermissionSet" => {
                let set = self.permission_set().await?;
                let attached: Vec<Value> = ic::managed_policies(self.client, &set)
                    .await?
                    .into_iter()
                    .filter(|a| ic::is_aws(&a.arn))
                    .map(|a| json!({ "Name": a.name, "Arn": a.arn }))
                    .collect();
                let (page, next) = self.page(attached)?;
                Ok(with_token(json!({ "AttachedManagedPolicies": page }), next))
            }
            "AttachCustomerManagedPolicyReferenceToPermissionSet" | "DetachCustomerManagedPolicyReferenceFromPermissionSet" => {
                let set = self.permission_set().await?;
                let arn = self.reference(self.input.get("CustomerManagedPolicyReference"))?;
                let attach = operation.starts_with("Attach");
                if attach && ic::managed_policies(self.client, &set).await?.iter().any(|a| a.arn == arn) {
                    return Err(conflict(format!("Permission set {} already has the customer managed policy {arn}.", set.name)));
                }
                ic::attach(self.client, &set, &arn, attach).await?;
                Ok(json!({}))
            }
            "ListCustomerManagedPolicyReferencesInPermissionSet" => {
                let set = self.permission_set().await?;
                let references: Vec<Value> = ic::managed_policies(self.client, &set)
                    .await?
                    .into_iter()
                    .filter(|a| !ic::is_aws(&a.arn))
                    .filter_map(|a| ic::customer_policy_reference(&a.arn))
                    .map(|(name, path)| json!({ "Name": name, "Path": path }))
                    .collect();
                let (page, next) = self.page(references)?;
                Ok(with_token(json!({ "CustomerManagedPolicyReferences": page }), next))
            }
            "PutPermissionsBoundaryToPermissionSet" => {
                let set = self.permission_set().await?;
                let boundary = self.input.get("PermissionsBoundary").ok_or_else(|| validation("PermissionsBoundary is required."))?;
                let arn = match (boundary.get("ManagedPolicyArn").and_then(Value::as_str), boundary.get("CustomerManagedPolicyReference")) {
                    (Some(arn), None) => arn.to_owned(),
                    (None, Some(reference)) => self.reference(Some(reference))?,
                    _ => return Err(validation("A permissions boundary is a ManagedPolicyArn or a CustomerManagedPolicyReference.")),
                };
                ic::set_boundary(self.client, &set, Some(&arn)).await?;
                Ok(json!({}))
            }
            "GetPermissionsBoundaryForPermissionSet" => {
                let set = self.permission_set().await?;
                let Some(arn) = ic::boundary(self.client, &set).await? else {
                    return Err(not_found(format!("Permission set {} has no permissions boundary.", set.name)));
                };
                let boundary = match ic::is_aws(&arn) {
                    true => json!({ "ManagedPolicyArn": arn }),
                    false => {
                        let (name, path) = ic::customer_policy_reference(&arn).unwrap_or_default();
                        json!({ "CustomerManagedPolicyReference": { "Name": name, "Path": path } })
                    }
                };
                Ok(json!({ "PermissionsBoundary": boundary }))
            }
            "DeletePermissionsBoundaryFromPermissionSet" => {
                let set = self.permission_set().await?;
                ic::set_boundary(self.client, &set, None).await?;
                Ok(json!({}))
            }
            "CreateAccountAssignment" | "DeleteAccountAssignment" => {
                let target = self.target("TargetId", Some("TargetType"))?;
                let set = self.permission_set().await?;
                let principal = self.principal().await?;
                let create = operation == "CreateAccountAssignment";
                // Done at once; one there already (or gone already) is done too.
                let kind = match create {
                    true => {
                        match ic::assign(self.client, &set, &target, principal.0, principal.1).await {
                            Ok(()) => {}
                            Err(e) if matches!(e.downcast_ref::<Refused>(), Some(Refused::Exists(_))) => {}
                            Err(e) => return Err(e.into()),
                        }
                        OperationKind::Create
                    }
                    false => {
                        ic::unassign(self.client, &set, &target, principal.0, principal.1).await?;
                        OperationKind::Delete
                    }
                };
                let op = ic::record(self.client, &self.account, kind, &set.arn(), Some(&target), Some(principal), None).await?;
                let key = if create { "AccountAssignmentCreationStatus" } else { "AccountAssignmentDeletionStatus" };
                Ok(json!({ key: self.assignment_status(&op) }))
            }
            "DescribeAccountAssignmentCreationStatus" | "DescribeAccountAssignmentDeletionStatus" => {
                let instance = self.instance()?;
                self.check(&instance)?;
                let (kind, field, key) = match operation.contains("Creation") {
                    true => (OperationKind::Create, "AccountAssignmentCreationRequestId", "AccountAssignmentCreationStatus"),
                    false => (OperationKind::Delete, "AccountAssignmentDeletionRequestId", "AccountAssignmentDeletionStatus"),
                };
                let op = self.operation(kind, field).await?;
                Ok(json!({ key: self.assignment_status(&op) }))
            }
            "ListAccountAssignmentCreationStatus" | "ListAccountAssignmentDeletionStatus" => {
                let instance = self.instance()?;
                self.check(&instance)?;
                let (kind, key) = match operation.contains("Creation") {
                    true => (OperationKind::Create, "AccountAssignmentsCreationStatus"),
                    false => (OperationKind::Delete, "AccountAssignmentsDeletionStatus"),
                };
                let ops = ic::operations(self.client, &self.account, kind, None, self.status_filter()?).await?;
                let items: Vec<Value> = ops
                    .iter()
                    .map(|op| json!({ "Status": op.status, "RequestId": op.request_id.to_string(), "CreatedDate": op.created }))
                    .collect();
                let (page, next) = self.page(items)?;
                Ok(with_token(json!({ key: page }), next))
            }
            "ListAccountAssignments" => {
                let target = self.target("AccountId", None)?;
                let set = self.permission_set().await?;
                let items: Vec<Value> = ic::assignments(self.client, &self.account, Some(&target), Some(set.id), None)
                    .await?
                    .iter()
                    .map(|a| self.assignment_json(a))
                    .collect();
                let (page, next) = self.page(items)?;
                Ok(with_token(json!({ "AccountAssignments": page }), next))
            }
            "ListAccountAssignmentsForPrincipal" => {
                let instance = self.instance()?;
                self.check(&instance)?;
                let account = self.input.get("Filter").and_then(|f| f.get("AccountId")).and_then(Value::as_str);
                let principal = self.principal().await?;
                let items: Vec<Value> = ic::assignments(self.client, &self.account, account, None, Some(principal))
                    .await?
                    .iter()
                    .map(|a| self.assignment_json(a))
                    .collect();
                let (page, next) = self.page(items)?;
                Ok(with_token(json!({ "AccountAssignments": page }), next))
            }
            "ProvisionPermissionSet" => {
                let set = self.permission_set().await?;
                let target = match self.text("TargetType") {
                    Some("ALL_PROVISIONED_ACCOUNTS") => None,
                    Some("AWS_ACCOUNT") => Some(self.target("TargetId", None)?),
                    _ => return Err(validation("TargetType must be AWS_ACCOUNT or ALL_PROVISIONED_ACCOUNTS.")),
                };
                let op = ic::record(self.client, &self.account, OperationKind::Provision, &set.arn(), target.as_deref(), None, None).await?;
                Ok(json!({ "PermissionSetProvisioningStatus": self.provisioning_status(&op) }))
            }
            "DescribePermissionSetProvisioningStatus" => {
                let instance = self.instance()?;
                self.check(&instance)?;
                let op = self.operation(OperationKind::Provision, "ProvisionPermissionSetRequestId").await?;
                Ok(json!({ "PermissionSetProvisioningStatus": self.provisioning_status(&op) }))
            }
            "ListPermissionSetProvisioningStatus" => {
                let instance = self.instance()?;
                self.check(&instance)?;
                let ops = ic::operations(self.client, &self.account, OperationKind::Provision, None, self.status_filter()?).await?;
                let items: Vec<Value> = ops
                    .iter()
                    .map(|op| json!({ "Status": op.status, "RequestId": op.request_id.to_string(), "CreatedDate": op.created }))
                    .collect();
                let (page, next) = self.page(items)?;
                Ok(with_token(json!({ "PermissionSetsProvisioningStatus": page }), next))
            }
            "ListPermissionSetsProvisionedToAccount" => {
                let instance = self.instance()?;
                self.check(&instance)?;
                let target = self.target("AccountId", None)?;
                // Provisioned: assigned there (Cairn provisions at once).
                let assigned = ic::assignments(self.client, &self.account, Some(&target), None, None).await?;
                let stale = self.text("ProvisioningStatus") == Some("LATEST_PERMISSION_SET_NOT_PROVISIONED");
                let sets: Vec<String> = ic::list(self.client, &self.account)
                    .await?
                    .iter()
                    .filter(|s| !stale && assigned.iter().any(|a| a.permission_set == s.name))
                    .map(PermissionSet::arn)
                    .collect();
                let (page, next) = self.page(sets)?;
                Ok(with_token(json!({ "PermissionSets": page }), next))
            }
            "ListAccountsForProvisionedPermissionSet" => {
                let set = self.permission_set().await?;
                // Provisioned: assigned there (Cairn provisions at once).
                let mut accounts: Vec<String> =
                    ic::assignments(self.client, &self.account, None, Some(set.id), None).await?.into_iter().map(|a| a.account).collect();
                accounts.dedup();
                if self.text("ProvisioningStatus") == Some("LATEST_PERMISSION_SET_NOT_PROVISIONED") {
                    accounts.clear();
                }
                let (page, next) = self.page(accounts)?;
                Ok(with_token(json!({ "AccountIds": page }), next))
            }
            "TagResource" | "UntagResource" | "ListTagsForResource" => self.tagging(operation).await,
            other => Err(error(StatusCode::NOT_IMPLEMENTED, "NotImplemented", format!("Cairn doesn't implement {other}."))),
        }
    }

    fn instance_json(&self) -> Value {
        json!({
            "InstanceArn": ic::instance_arn(&self.account),
            "IdentityStoreId": ic::identity_store_id(&self.account),
            "IdentityStoreArn": ic::identity_store_arn(&self.account),
            "OwnerAccountId": self.account,
            "Name": "Cairn",
            "Status": "ACTIVE",
        })
    }

    /// `SessionDuration`, in seconds, if given.
    fn duration(&self) -> Result<Option<i32>> {
        let Some(text) = self.text("SessionDuration") else { return Ok(None) };
        let seconds = ic::parse_duration(text).ok_or_else(|| validation(format!("SessionDuration {text} isn't an ISO 8601 duration.")))?;
        i32::try_from(seconds).map(Some).map_err(|_| validation("SessionDuration is from PT1H to PT12H."))
    }

    /// A customer managed policy reference's policy's ARN (the account's,
    /// which must exist).
    fn reference(&self, reference: Option<&Value>) -> Result<String> {
        let name = reference.and_then(|r| r.get("Name")).and_then(Value::as_str).filter(|n| !n.is_empty());
        let Some(name) = name else {
            return Err(validation("CustomerManagedPolicyReference needs its Name."));
        };
        let path = reference.and_then(|r| r.get("Path")).and_then(Value::as_str).unwrap_or("/");
        if !path.starts_with('/') || !path.ends_with('/') {
            return Err(validation(format!("The path {path} must begin and end with /.")));
        }
        Ok(ic::customer_policy_arn(&self.account, name, path))
    }

    /// The user or group a request names (`PrincipalType`, `PrincipalId`),
    /// which must be in the identity store.
    async fn principal(&self) -> Result<(PrincipalType, Uuid)> {
        let kind = PrincipalType::parse(self.required("PrincipalType")?).ok_or_else(|| validation("PrincipalType must be USER or GROUP."))?;
        let text = self.required("PrincipalId")?;
        let id = principal_id(text).ok_or_else(|| validation(format!("PrincipalId {text} isn't an identity store ID.")))?;
        let found = match kind {
            PrincipalType::User => !ic::users(self.client, Some(Lookup::Id(id))).await?.is_empty(),
            PrincipalType::Group => !ic::groups(self.client, Some(Lookup::Id(id))).await?.is_empty(),
        };
        if !found {
            return Err(not_found(format!("There's no {} {text} in the identity store.", kind.as_str().to_lowercase())));
        }
        Ok((kind, id))
    }

    /// The request `field` names, of `kind`.
    async fn operation(&self, kind: OperationKind, field: &str) -> Result<ic::Operation> {
        let text = self.required(field)?;
        let id = Uuid::parse_str(text).map_err(|_| validation(format!("{field} {text} isn't a request ID.")))?;
        ic::operations(self.client, &self.account, kind, Some(id), None)
            .await?
            .pop()
            .ok_or_else(|| not_found(format!("There's no request {text}.")))
    }

    fn status_filter(&self) -> Result<Option<&str>> {
        match self.input.get("Filter").and_then(|f| f.get("Status")).and_then(Value::as_str) {
            None => Ok(None),
            Some(status @ ("IN_PROGRESS" | "FAILED" | "SUCCEEDED")) => Ok(Some(status)),
            Some(other) => Err(validation(format!("Status {other} isn't IN_PROGRESS, FAILED or SUCCEEDED."))),
        }
    }

    fn assignment_status(&self, op: &ic::Operation) -> Value {
        let mut status = json!({
            "Status": op.status,
            "RequestId": op.request_id.to_string(),
            "TargetId": op.target.as_deref().unwrap_or(&self.account),
            "TargetType": "AWS_ACCOUNT",
            "PermissionSetArn": op.permission_set_arn,
            "CreatedDate": op.created,
        });
        if let Some((kind, id)) = op.principal {
            status["PrincipalType"] = json!(kind.as_str());
            status["PrincipalId"] = json!(id.to_string());
        }
        if let Some(reason) = &op.failure_reason {
            status["FailureReason"] = json!(reason);
        }
        status
    }

    fn provisioning_status(&self, op: &ic::Operation) -> Value {
        json!({
            "Status": op.status,
            "RequestId": op.request_id.to_string(),
            "AccountId": op.target.as_deref().unwrap_or(&self.account),
            "PermissionSetArn": op.permission_set_arn,
            "CreatedDate": op.created,
        })
    }

    fn assignment_json(&self, a: &ic::Assignment) -> Value {
        json!({
            "AccountId": a.account,
            "PermissionSetArn": ic::permission_set_arn(&self.account, &a.permission_set_short_id),
            "PrincipalType": a.principal_type.as_str(),
            "PrincipalId": a.principal_id.to_string(),
        })
    }

    /// `name`'s tags, checked as Identity Center checks them.
    fn tags(&self, name: &str) -> Result<Vec<(String, String)>> {
        let Some(list) = self.input.get(name) else { return Ok(Vec::new()) };
        let list = list.as_array().ok_or_else(|| validation(format!("{name} is a list of tags.")))?;
        let mut tags: Vec<(String, String)> = Vec::new();
        for tag in list {
            let key = tag.get("Key").and_then(Value::as_str).unwrap_or("");
            let value = tag.get("Value").and_then(Value::as_str).unwrap_or("");
            check_tag(key, value)?;
            if tags.iter().any(|(k, _)| k == key) {
                return Err(validation(format!("The tag key {key} is given twice.")));
            }
            tags.push((key.to_owned(), value.to_owned()));
        }
        Ok(tags)
    }

    async fn tagging(&mut self, operation: &str) -> Result<Value> {
        let arn = self.required("ResourceArn")?.to_owned();
        self.check(&arn)?;
        let Some(set) = ic::load_arn(self.client, &self.account, &arn).await? else {
            return Err(match arn == ic::instance_arn(&self.account) {
                true => error(StatusCode::NOT_IMPLEMENTED, "NotImplemented", "Cairn doesn't tag its instance."),
                false => not_found(format!("Could not find resource {arn}.")),
            });
        };
        let mut tags = set.tags.as_deref().map(parse_tags).unwrap_or_default();
        match operation {
            "ListTagsForResource" => {
                let items: Vec<Value> = tags.iter().map(|(k, v)| json!({ "Key": k, "Value": v })).collect();
                let (page, next) = self.page(items)?;
                return Ok(with_token(json!({ "Tags": page }), next));
            }
            "TagResource" => {
                for (key, value) in self.tags("Tags")? {
                    match tags.iter_mut().find(|(k, _)| *k == key) {
                        Some(tag) => tag.1 = value,
                        None => tags.push((key, value)),
                    }
                }
                if tags.len() > 75 {
                    return Err(error(StatusCode::BAD_REQUEST, "ServiceQuotaExceededException", "A resource has at most 75 tags."));
                }
            }
            _ => {
                let keys: Vec<String> = self
                    .input
                    .get("TagKeys")
                    .and_then(Value::as_array)
                    .ok_or_else(|| validation("TagKeys is required."))?
                    .iter()
                    .filter_map(|k| k.as_str().map(str::to_owned))
                    .collect();
                tags.retain(|(k, _)| !keys.contains(k));
            }
        }
        let stored = (!tags.is_empty()).then(|| stored_tags(&tags));
        ic::set_tags(self.client, &set, stored.as_deref()).await?;
        Ok(json!({}))
    }

    // ─── identitystore ───────────────────────────────────────────────────────

    async fn identity_store(&mut self, operation: &str) -> Result<Value> {
        let store = self.required("IdentityStoreId")?;
        let ours = ic::identity_store_id(&self.account);
        if store != ours && store != ic::identity_store_arn(&self.account) {
            return Err(not_found(format!("Identity store {store} doesn't exist.")));
        }
        let store_arn = ic::identity_store_arn(&self.account);
        match operation {
            "GetUserId" => {
                self.check(&store_arn)?;
                let users = match self.alternate()? {
                    Alternate::External { issuer, id } => ic::users(self.client, Some(Lookup::External { issuer: &issuer, id: &id })).await?,
                    Alternate::Unique { path, value } => match path.to_ascii_lowercase().as_str() {
                        "username" => ic::users(self.client, Some(Lookup::Name(&value))).await?,
                        "emails.value" => {
                            ic::users(self.client, None).await?.into_iter().filter(|u| u.email.as_deref() == Some(value.as_str())).collect()
                        }
                        _ => return Err(validation(format!("A user can't be found by {path}: by UserName or emails.value."))),
                    },
                };
                let user = one(users, "user")?;
                Ok(json!({ "IdentityStoreId": ours, "UserId": user.id.to_string(), "UserArn": ic::user_arn(user.id) }))
            }
            "DescribeUser" => {
                let user = self.user("UserId").await?;
                Ok(user_json(&ours, &user))
            }
            "ListUsers" => {
                self.check(&store_arn)?;
                let mut users = ic::users(self.client, None).await?;
                if let Some((path, value)) = self.filter()? {
                    match path.to_ascii_lowercase().as_str() {
                        "username" => users.retain(|u| u.user_name == value),
                        _ => return Err(validation(format!("Users can't be filtered by {path}: by UserName."))),
                    }
                }
                let items: Vec<Value> = users.iter().map(|u| user_json(&ours, u)).collect();
                let (page, next) = self.page(items)?;
                Ok(with_token(json!({ "Users": page }), next))
            }
            "GetGroupId" => {
                self.check(&store_arn)?;
                let groups = match self.alternate()? {
                    Alternate::External { issuer, id } => ic::groups(self.client, Some(Lookup::External { issuer: &issuer, id: &id })).await?,
                    Alternate::Unique { path, value } => match path.to_ascii_lowercase().as_str() {
                        "displayname" => ic::groups(self.client, Some(Lookup::Name(&value))).await?,
                        _ => return Err(validation(format!("A group can't be found by {path}: by DisplayName."))),
                    },
                };
                let group = one(groups, "group")?;
                Ok(json!({ "IdentityStoreId": ours, "GroupId": group.id.to_string(), "GroupArn": ic::group_arn(group.id) }))
            }
            "DescribeGroup" => {
                let group = self.group("GroupId").await?;
                Ok(group_json(&ours, &group))
            }
            "ListGroups" => {
                self.check(&store_arn)?;
                let mut groups = ic::groups(self.client, None).await?;
                if let Some((path, value)) = self.filter()? {
                    match path.to_ascii_lowercase().as_str() {
                        "displayname" => groups.retain(|g| g.name == value),
                        _ => return Err(validation(format!("Groups can't be filtered by {path}: by DisplayName."))),
                    }
                }
                let items: Vec<Value> = groups.iter().map(|g| group_json(&ours, g)).collect();
                let (page, next) = self.page(items)?;
                Ok(with_token(json!({ "Groups": page }), next))
            }
            "ListGroupMemberships" => {
                let group = self.group("GroupId").await?;
                let items: Vec<Value> = ic::memberships(self.client, Some(group.id), None).await?.iter().map(|m| membership_json(&ours, m)).collect();
                let (page, next) = self.page(items)?;
                Ok(with_token(json!({ "GroupMemberships": page }), next))
            }
            "ListGroupMembershipsForMember" => {
                let user = self.member().await?;
                let items: Vec<Value> = ic::memberships(self.client, None, Some(user.id)).await?.iter().map(|m| membership_json(&ours, m)).collect();
                let (page, next) = self.page(items)?;
                Ok(with_token(json!({ "GroupMemberships": page }), next))
            }
            "GetGroupMembershipId" => {
                let group = self.group("GroupId").await?;
                let user = self.member().await?;
                let membership = ic::memberships(self.client, Some(group.id), Some(user.id))
                    .await?
                    .pop()
                    .ok_or_else(|| not_found("That user isn't in that group."))?;
                Ok(json!({ "IdentityStoreId": ours, "MembershipId": membership.id.to_string(), "MembershipArn": ic::membership_arn(membership.id) }))
            }
            "DescribeGroupMembership" => {
                let text = self.required("MembershipId")?;
                let id = principal_id(text).ok_or_else(|| validation(format!("MembershipId {text} isn't one.")))?;
                self.check(&ic::membership_arn(id))?;
                let membership = ic::memberships(self.client, None, None)
                    .await?
                    .into_iter()
                    .find(|m| m.id == id)
                    .ok_or_else(|| not_found(format!("There's no membership {text}.")))?;
                Ok(membership_json(&ours, &membership))
            }
            "IsMemberInGroups" => {
                let user = self.member().await?;
                let ids = self.input.get("GroupIds").and_then(Value::as_array).ok_or_else(|| validation("GroupIds is required."))?;
                let memberships = ic::memberships(self.client, None, Some(user.id)).await?;
                let results: Vec<Value> = ids
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|g| {
                        let exists = principal_id(g).is_some_and(|g| memberships.iter().any(|m| m.group_id == g));
                        json!({ "GroupId": g, "MemberId": { "UserId": user.id.to_string() }, "MembershipExists": exists })
                    })
                    .collect();
                Ok(json!({ "Results": results }))
            }
            other => Err(error(StatusCode::NOT_IMPLEMENTED, "NotImplemented", format!("Cairn doesn't implement {other}."))),
        }
    }

    /// `AlternateIdentifier`: an external ID, or a unique attribute.
    fn alternate(&self) -> Result<Alternate> {
        let alternate = self.input.get("AlternateIdentifier").ok_or_else(|| validation("AlternateIdentifier is required."))?;
        if let Some(external) = alternate.get("ExternalId") {
            let issuer = external.get("Issuer").and_then(Value::as_str);
            let id = external.get("Id").and_then(Value::as_str);
            return match issuer.zip(id) {
                Some((issuer, id)) => Ok(Alternate::External { issuer: issuer.to_owned(), id: id.to_owned() }),
                None => Err(validation("An ExternalId needs its Issuer and Id.")),
            };
        }
        let unique = alternate.get("UniqueAttribute").ok_or_else(|| validation("AlternateIdentifier is an ExternalId or a UniqueAttribute."))?;
        let path = unique.get("AttributePath").and_then(Value::as_str).ok_or_else(|| validation("A UniqueAttribute needs its AttributePath."))?;
        let value = unique.get("AttributeValue").and_then(Value::as_str).ok_or_else(|| validation("A UniqueAttribute's AttributeValue is a string."))?;
        Ok(Alternate::Unique { path: path.to_owned(), value: value.to_owned() })
    }

    /// `Filters`: at most one, an attribute and its value.
    fn filter(&self) -> Result<Option<(String, String)>> {
        let Some(filters) = self.input.get("Filters").and_then(Value::as_array) else { return Ok(None) };
        match filters.as_slice() {
            [] => Ok(None),
            [filter] => {
                let path = filter.get("AttributePath").and_then(Value::as_str);
                let value = filter.get("AttributeValue").and_then(Value::as_str);
                path.zip(value).map(|(p, v)| Some((p.to_owned(), v.to_owned()))).ok_or_else(|| validation("A filter needs its AttributePath and AttributeValue."))
            }
            _ => Err(validation("At most one filter.")),
        }
    }

    /// The user `field` names, allowed the request's action.
    async fn user(&self, field: &str) -> Result<User> {
        let text = self.required(field)?;
        let id = principal_id(text).ok_or_else(|| validation(format!("{field} {text} isn't a user's ID.")))?;
        self.check(&ic::user_arn(id))?;
        ic::users(self.client, Some(Lookup::Id(id))).await?.pop().ok_or_else(|| not_found(format!("There's no user {text}.")))
    }

    /// The group `field` names, allowed the request's action.
    async fn group(&self, field: &str) -> Result<Group> {
        let text = self.required(field)?;
        let id = principal_id(text).ok_or_else(|| validation(format!("{field} {text} isn't a group's ID.")))?;
        self.check(&ic::group_arn(id))?;
        ic::groups(self.client, Some(Lookup::Id(id))).await?.pop().ok_or_else(|| not_found(format!("There's no group {text}.")))
    }

    /// The user `MemberId` names.
    async fn member(&self) -> Result<User> {
        let text = self
            .input
            .get("MemberId")
            .and_then(|m| m.get("UserId"))
            .and_then(Value::as_str)
            .ok_or_else(|| validation("MemberId needs its UserId."))?;
        let id = principal_id(text).ok_or_else(|| validation(format!("UserId {text} isn't a user's ID.")))?;
        self.check(&ic::user_arn(id))?;
        ic::users(self.client, Some(Lookup::Id(id))).await?.pop().ok_or_else(|| not_found(format!("There's no user {text}.")))
    }
}

enum Alternate {
    External { issuer: String, id: String },
    Unique { path: String, value: String },
}

/// The one of `found`, or why not.
fn one<T>(mut found: Vec<T>, what: &str) -> Result<T> {
    match found.len() {
        0 => Err(not_found(format!("There's no such {what}."))),
        1 => Ok(found.pop().expect("one")),
        _ => Err(validation(format!("Several {what}s have that attribute: find it by its ExternalId (its source's issuer, and its ID there)."))),
    }
}

/// An identity store ID, as a request gives it: a UUID, maybe after a
/// store's prefix (`<10 hex>-`) or its ARN.
fn principal_id(text: &str) -> Option<Uuid> {
    let text = text.rsplit('/').next().unwrap_or(text);
    Uuid::parse_str(text).ok().or_else(|| text.get(11..).and_then(|rest| Uuid::parse_str(rest).ok()))
}

fn lower_first(name: &str) -> String {
    let mut chars = name.chars();
    chars.next().map(|c| c.to_lowercase().chain(chars).collect()).unwrap_or_default()
}

/// `value` with `NextToken`, if there's a next page.
fn with_token(mut value: Value, next: Option<String>) -> Value {
    if let Some(next) = next {
        value["NextToken"] = json!(next);
    }
    value
}

fn set_json(set: &PermissionSet) -> Value {
    let mut value = json!({
        "Name": set.name,
        "PermissionSetArn": set.arn(),
        "CreatedDate": set.created,
        "SessionDuration": ic::format_duration(set.session_duration as i64),
    });
    if !set.description.is_empty() {
        value["Description"] = json!(set.description);
    }
    if let Some(relay_state) = &set.relay_state {
        value["RelayState"] = json!(relay_state);
    }
    value
}

fn user_json(store: &str, user: &User) -> Value {
    let mut value = json!({
        "IdentityStoreId": store,
        "UserId": user.id.to_string(),
        "UserArn": ic::user_arn(user.id),
        "Revision": (user.updated as i64).to_string(),
        "UserName": user.user_name,
        "ExternalIds": [{ "Issuer": user.issuer, "Id": user.subject }],
        "DisplayName": user.display_name,
        "Name": { "Formatted": user.display_name },
        "UserStatus": "ENABLED",
        "CreatedAt": user.created,
        "UpdatedAt": user.updated,
    });
    if let Some(email) = &user.email {
        value["Emails"] = json!([{ "Value": email, "Primary": true }]);
    }
    value
}

fn group_json(store: &str, group: &Group) -> Value {
    json!({
        "IdentityStoreId": store,
        "GroupId": group.id.to_string(),
        "GroupArn": ic::group_arn(group.id),
        "Revision": (group.updated as i64).to_string(),
        "DisplayName": group.name,
        "ExternalIds": [{ "Issuer": group.issuer, "Id": group.name }],
        "CreatedAt": group.created,
        "UpdatedAt": group.updated,
    })
}

fn membership_json(store: &str, membership: &ic::Membership) -> Value {
    json!({
        "IdentityStoreId": store,
        "MembershipId": membership.id.to_string(),
        "MembershipArn": ic::membership_arn(membership.id),
        "GroupId": membership.group_id.to_string(),
        "MemberId": { "UserId": membership.user_id.to_string() },
        "CreatedAt": membership.created,
        "UpdatedAt": membership.created,
    })
}

/// A tag, checked as Identity Center checks them.
fn check_tag(key: &str, value: &str) -> Result<()> {
    let allowed = |c: char| c.is_alphanumeric() || c.is_whitespace() || "_.:/=+-@".contains(c);
    if key.is_empty() || key.chars().count() > 128 || !key.chars().all(allowed) {
        return Err(validation(format!("The tag key {key:?} isn't 1 to 128 letters, digits, spaces and _.:/=+-@.")));
    }
    if key.to_ascii_lowercase().starts_with("aws:") {
        return Err(validation("Tag keys beginning with aws: are reserved."));
    }
    if value.chars().count() > 256 || !value.chars().all(allowed) {
        return Err(validation(format!("The tag value {value:?} isn't up to 256 letters, digits, spaces and _.:/=+-@.")));
    }
    Ok(())
}

/// Tags as a permission set keeps them: a JSON list of pairs.
fn stored_tags(tags: &[(String, String)]) -> String {
    serde_json::to_string(tags).expect("strings serialize")
}

fn parse_tags(stored: &str) -> Vec<(String, String)> {
    serde_json::from_str(stored).unwrap_or_default()
}

#[cfg(test)]
mod e2e_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_principal_ids() {
        let id = Uuid::parse_str("0123abcd-0000-4000-8000-000000000001").unwrap();
        assert_eq!(principal_id("0123abcd-0000-4000-8000-000000000001"), Some(id));
        assert_eq!(principal_id("9067abcdef-0123abcd-0000-4000-8000-000000000001"), Some(id));
        assert_eq!(principal_id("arn:aws:identitystore:::user/0123abcd-0000-4000-8000-000000000001"), Some(id));
        assert_eq!(principal_id("nope"), None);
    }

    #[test]
    fn checks_tags() {
        assert!(check_tag("team", "data science").is_ok());
        assert!(check_tag("", "x").is_err());
        assert!(check_tag("aws:x", "x").is_err());
        assert!(check_tag("a", "<b>").is_err());
        assert_eq!(parse_tags(&stored_tags(&[("a".into(), "b".into())])), vec![("a".to_owned(), "b".to_owned())]);
    }
}
