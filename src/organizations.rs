//! AWS Organizations, as far as Cairn's accounts go: the organization is the
//! cluster's, its management account the account Cairn always had (see
//! `users::account`), and its members accounts made from that one
//! (`CreateAccount`), as AWS makes them. On the S3 endpoint as IAM's API is
//! (signed for `organizations`; `X-Amz-Target:
//! AWSOrganizationsV20161128.<Operation>`), in AWS's JSON 1.1 protocol.
//!
//! **Accounts.** Each is IAM's and S3's as the management account is: its
//! own users, roles, policies and buckets (whose names are global, as in
//! S3), its own public access block, and its own Identity Center
//! assignments (see `identity_center`). A member account has no root
//! credentials, as AWS recommends (centralized root access): its way in is
//! `OrganizationAccountAccessRole`, which `CreateAccount` makes in it,
//! trusting the management account and allowing everything, as AWS's does,
//! and the permission sets assigned in it. Only the management account owns
//! the cluster (`cairn:` actions). Its accounts' names are as AWS takes
//! them (1 to 50 characters, not unique); their e-mails are unique.
//!
//! **Closing** an account (`CloseAccount`) is at once: its status becomes
//! `SUSPENDED`, and its users, roles and sessions are no one from then on.
//! It must hold no buckets (which AWS's closing would keep for 90 days).
//!
//! Every operation is decided as its action (`organizations:CreateAccount`,
//! …) on its resource (the organization, or an account's ARN); all but
//! DescribeOrganization are the management account's only, as AWS's are.
//! Organizational units, policies (SCPs), invitations and delegated
//! administrators answer 501.

pub mod structure;

use std::net::IpAddr;
use std::sync::Arc;

use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode, body::Bytes};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    App,
    auth::Signed,
    db::Cached,
    managed::Refused,
    policy::Verdict,
    s3::access::{Access, Origin},
    s3::actions::{Check, On},
    users::{self, Principal},
};

/// The most of a request's body that's read.
const MAX_BODY: usize = 64 * 1024;
/// The role CreateAccount makes in a new account, unless it's told another.
pub const ACCESS_ROLE: &str = "OrganizationAccountAccessRole";
/// How long CreateAccount's requests' statuses are kept.
const REQUESTS_KEPT: std::time::Duration = std::time::Duration::from_secs(90 * 24 * 3600);

/// The operations Cairn answers, with their actions, and whether a member
/// account may make them.
const OPERATIONS: &[(&str, &str, bool)] = &[
    (
        "DescribeOrganization",
        "organizations:DescribeOrganization",
        true,
    ),
    ("ListAccounts", "organizations:ListAccounts", false),
    ("DescribeAccount", "organizations:DescribeAccount", false),
    ("CreateAccount", "organizations:CreateAccount", false),
    (
        "DescribeCreateAccountStatus",
        "organizations:DescribeCreateAccountStatus",
        false,
    ),
    (
        "ListCreateAccountStatus",
        "organizations:ListCreateAccountStatus",
        false,
    ),
    ("CloseAccount", "organizations:CloseAccount", false),
];

/// Operation `name`, with its action, and whether a member account may
/// make it: the accounts' and the structure's (the management account's
/// only).
fn operation_of(name: &str) -> Option<(&'static str, &'static str, bool)> {
    OPERATIONS
        .iter()
        .copied()
        .find(|(op, _, _)| *op == name)
        .or_else(|| {
            structure::OPERATIONS
                .iter()
                .find(|(op, _)| *op == name)
                .map(|&(op, action)| (op, action, false))
        })
}

/// Whether a request signed as `signed` is Organizations'.
pub fn wants(signed: &Signed) -> bool {
    signed.service == "organizations"
}

/// A failed request: its status, code and message.
#[derive(Debug)]
pub struct Error {
    status: StatusCode,
    code: &'static str,
    message: String,
    /// Why, as a ConstraintViolationException says (`OU_DEPTH_LIMIT_EXCEEDED`, …).
    reason: Option<String>,
}

type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// What went wrong, for whoever asked.
    pub fn message(&self) -> &str {
        &self.message
    }
}

fn error(status: StatusCode, code: &'static str, message: impl Into<String>) -> Error {
    Error {
        status,
        code,
        message: message.into(),
        reason: None,
    }
}

fn invalid(message: impl Into<String>) -> Error {
    error(StatusCode::BAD_REQUEST, "InvalidInputException", message)
}

fn denied() -> Error {
    error(
        StatusCode::BAD_REQUEST,
        "AccessDeniedException",
        "You don't have permissions to access this resource.",
    )
}

fn no_such_account(id: &str) -> Error {
    error(
        StatusCode::BAD_REQUEST,
        "AccountNotFoundException",
        format!("You specified an account that doesn't exist: {id}."),
    )
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Error {
        match e.downcast::<Refused>() {
            Ok(Refused::Unsupported(m)) => error(StatusCode::NOT_IMPLEMENTED, "NotImplemented", m),
            Ok(Refused::NoSuch(m)) => invalid(m),
            Ok(other) => invalid(other.to_string()),
            Err(e) => {
                eprintln!("organizations: a request failed: {e:#}");
                error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ServiceException",
                    "We encountered an internal error. Please try again.",
                )
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

/// Handles a request `wants` says is Organizations'.
pub async fn handle(
    app: &Arc<App>,
    req: Request<crate::listen::ClientBody>,
    signed: Signed,
    peer: IpAddr,
) -> Response<Full<Bytes>> {
    let request_id = Uuid::new_v4().to_string();
    let (status, body) = match respond(app, req, &signed, peer).await {
        Ok(value) => (StatusCode::OK, value.to_string()),
        Err(e) => {
            let mut body = json!({ "__type": e.code, "Message": e.message, "message": e.message });
            if let Some(reason) = &e.reason {
                body["Reason"] = json!(reason);
            }
            (e.status, body.to_string())
        }
    };
    Response::builder()
        .status(status)
        .header("content-type", "application/x-amz-json-1.1")
        .header("x-amzn-requestid", request_id)
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

async fn respond(
    app: &Arc<App>,
    req: Request<crate::listen::ClientBody>,
    signed: &Signed,
    peer: IpAddr,
) -> Result<Value> {
    let (parts, body) = req.into_parts();
    let body = Limited::new(body, MAX_BODY)
        .collect()
        .await
        .map_err(|_| invalid("The request's body is too large, or broken."))?
        .to_bytes();
    let target = parts
        .headers
        .get("x-amz-target")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let Some(operation) = target.strip_prefix("AWSOrganizationsV20161128.") else {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "UnknownOperationException",
            format!("No such operation: {target}"),
        ));
    };
    let Some((operation, action, members)) = operation_of(operation) else {
        return Err(error(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            format!("Cairn doesn't implement {operation}."),
        ));
    };
    let client = app.pool.get().await?;
    let principal = match Principal::authenticate(
        &client,
        &app.sessions,
        &signed.access_key,
        signed.token.as_deref(),
    )
    .await?
    {
        Ok(principal) => principal,
        Err(users::Unknown::Expired) => {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "ExpiredTokenException",
                "The security token included in the request is expired",
            ));
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
    crate::auth::verify_sigv4_with_body(
        parts.method.as_str(),
        parts.uri.path(),
        query,
        &parts.headers,
        &principal.secret,
        &body,
    )
    .map_err(|r| {
        error(
            StatusCode::BAD_REQUEST,
            if r.code == "SignatureDoesNotMatch" {
                "InvalidSignatureException"
            } else {
                "IncompleteSignature"
            },
            r.message,
        )
    })?;
    let input: Value = match body.is_empty() {
        true => json!({}),
        false => serde_json::from_slice(&body).map_err(|_| {
            error(
                StatusCode::BAD_REQUEST,
                "SerializationException",
                "The request's body isn't JSON.",
            )
        })?,
    };
    if !input.is_object() {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "SerializationException",
            "The request's body isn't a JSON object.",
        ));
    }
    let management = users::account(&client).await?;
    // A member account may only describe its organization, as in AWS.
    if principal.account != management && !members {
        return Err(denied());
    }
    let origin = Origin {
        peer: Some(peer),
        trusted_proxies: &app.trusted_proxies,
        signed: Some(signed),
        form: false,
    };
    let access = Access::new(
        Some(&principal),
        &principal.account,
        &parts.method,
        &parts.headers,
        "",
        &origin,
    )?;
    let ctx = Ctx {
        client: &client,
        access: &access,
        management,
        action,
        input: &input,
    };
    ctx.dispatch(operation).await
}

struct Ctx<'a> {
    client: &'a deadpool_postgres::Object,
    access: &'a Access,
    management: String,
    action: &'static str,
    input: &'a Value,
}

impl Ctx<'_> {
    /// Refuses the request unless its action on `resource` is allowed.
    fn check(&self, resource: &str) -> Result<()> {
        let check = Check {
            action: self.action,
            on: On::Arn(resource.to_owned()),
        };
        match self.access.verdict(&check) {
            Verdict::Allow => Ok(()),
            _ => Err(denied()),
        }
    }

    fn text(&self, name: &str) -> Option<&str> {
        self.input.get(name).and_then(Value::as_str)
    }

    fn required(&self, name: &str) -> Result<&str> {
        self.text(name)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| invalid(format!("You must specify {name}.")))
    }

    /// A page of `items`: `MaxResults` (at most 20, as AWS's) from
    /// `NextToken` (an offset), and the next page's token.
    fn page<T>(&self, items: Vec<T>) -> Result<(Vec<T>, Option<String>)> {
        let max = match self.input.get("MaxResults") {
            Some(n) => n
                .as_u64()
                .filter(|n| (1..=20).contains(n))
                .ok_or_else(|| invalid("MaxResults must be from 1 to 20."))?
                as usize,
            None => 20,
        };
        let start = match self.text("NextToken") {
            Some(token) => token
                .parse::<usize>()
                .map_err(|_| invalid("The NextToken isn't valid."))?,
            None => 0,
        };
        let total = items.len();
        let page: Vec<T> = items.into_iter().skip(start).take(max).collect();
        let next = (start + max < total).then(|| (start + max).to_string());
        Ok((page, next))
    }

    async fn dispatch(&self, operation: &str) -> Result<Value> {
        let organization = organization_arn(&self.management);
        match operation {
            "DescribeOrganization" => {
                self.check(&organization)?;
                let management = load(self.client, &self.management)
                    .await?
                    .ok_or_else(|| no_such_account(&self.management))?;
                let mut value = json!({
                    "Id": organization_id(&self.management),
                    "Arn": organization,
                    "FeatureSet": "ALL",
                    "MasterAccountArn": account_arn(&self.management, &self.management),
                    "MasterAccountId": self.management,
                    "AvailablePolicyTypes": [],
                });
                if let Some(email) = &management.email {
                    value["MasterAccountEmail"] = json!(email);
                }
                Ok(json!({ "Organization": value }))
            }
            "ListAccounts" => {
                self.check(&organization)?;
                let accounts: Vec<Value> = list(self.client)
                    .await?
                    .iter()
                    .map(|a| a.json(&self.management))
                    .collect();
                let (page, next) = self.page(accounts)?;
                let mut value = json!({ "Accounts": page });
                if let Some(next) = next {
                    value["NextToken"] = json!(next);
                }
                Ok(value)
            }
            "DescribeAccount" => {
                let id = self.required("AccountId")?;
                self.check(&account_arn(&self.management, id))?;
                let account = load(self.client, id)
                    .await?
                    .ok_or_else(|| no_such_account(id))?;
                Ok(json!({ "Account": account.json(&self.management) }))
            }
            "CreateAccount" => {
                self.check(&organization)?;
                let name = self.required("AccountName")?;
                let email = self.required("Email")?;
                let role = self.text("RoleName").unwrap_or(ACCESS_ROLE);
                if self
                    .input
                    .get("Tags")
                    .and_then(Value::as_array)
                    .is_some_and(|t| !t.is_empty())
                {
                    return Err(error(
                        StatusCode::NOT_IMPLEMENTED,
                        "NotImplemented",
                        "Cairn doesn't tag accounts.",
                    ));
                }
                let status = create(self.client, &self.management, name, email, role).await?;
                Ok(json!({ "CreateAccountStatus": status.json() }))
            }
            "DescribeCreateAccountStatus" => {
                self.check(&organization)?;
                let id = self.required("CreateAccountRequestId")?;
                let status = requests(self.client, Some(id))
                    .await?
                    .pop()
                    .ok_or_else(|| {
                        error(
                            StatusCode::BAD_REQUEST,
                            "CreateAccountStatusNotFoundException",
                            format!("There's no request {id}."),
                        )
                    })?;
                Ok(json!({ "CreateAccountStatus": status.json() }))
            }
            "ListCreateAccountStatus" => {
                self.check(&organization)?;
                let states: Option<Vec<&str>> = self
                    .input
                    .get("States")
                    .and_then(Value::as_array)
                    .map(|s| s.iter().filter_map(Value::as_str).collect());
                let statuses: Vec<Value> = requests(self.client, None)
                    .await?
                    .into_iter()
                    .filter(|r| {
                        states
                            .as_ref()
                            .is_none_or(|s| s.contains(&r.state.as_str()))
                    })
                    .map(|r| r.json())
                    .collect();
                let (page, next) = self.page(statuses)?;
                let mut value = json!({ "CreateAccountStatuses": page });
                if let Some(next) = next {
                    value["NextToken"] = json!(next);
                }
                Ok(value)
            }
            "CloseAccount" => {
                let id = self.required("AccountId")?;
                self.check(&account_arn(&self.management, id))?;
                close(self.client, &self.management, id).await?;
                Ok(json!({}))
            }
            // The structure's: checked on the organization (its root,
            // units and policies are its).
            other => {
                self.check(&organization)?;
                let input = structure::Input {
                    client: self.client,
                    management: &self.management,
                    input: self.input,
                };
                structure::answer(other, &input).await
            }
        }
    }
}

/// 10 hex digits of `account`'s hash, for the organization's IDs.
fn short_hash(account: &str) -> String {
    let digest = ring::digest::digest(
        &ring::digest::SHA256,
        format!("organization:{account}").as_bytes(),
    );
    digest.as_ref()[..5]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The organization's ID (`o-` and 10 characters), of its management account.
pub fn organization_id(management: &str) -> String {
    format!("o-{}", short_hash(management))
}

pub fn organization_arn(management: &str) -> String {
    format!(
        "arn:aws:organizations::{management}:organization/{}",
        organization_id(management)
    )
}

/// An account's ARN in the organization.
pub fn account_arn(management: &str, account: &str) -> String {
    format!(
        "arn:aws:organizations::{management}:account/{}/{account}",
        organization_id(management)
    )
}

/// An account of the organization.
#[derive(Clone, Debug)]
pub struct Account {
    pub id: String,
    pub name: String,
    pub email: Option<String>,
    pub management: bool,
    /// When it joined (was made), and when it was closed, if it was
    /// (seconds since the epoch).
    pub joined: f64,
    pub closed: Option<f64>,
    /// The organizational unit it's in (`None`: the root).
    pub parent: Option<String>,
}

impl Account {
    fn of(row: &tokio_postgres::Row) -> Account {
        Account {
            id: row.get(0),
            name: row.get(1),
            email: row.get(2),
            management: row.get(3),
            joined: row.get(4),
            closed: row.get(5),
            parent: row.get(6),
        }
    }

    /// Its status, as AWS says it: `ACTIVE`, or (closed) `SUSPENDED`.
    pub fn status(&self) -> &'static str {
        match self.closed {
            Some(_) => "SUSPENDED",
            None => "ACTIVE",
        }
    }

    pub(crate) fn json(&self, management: &str) -> Value {
        let mut value = json!({
            "Id": self.id,
            "Arn": account_arn(management, &self.id),
            "Name": self.name,
            "Status": self.status(),
            "State": if self.closed.is_some() { "CLOSED" } else { "ACTIVE" },
            "JoinedMethod": "CREATED",
            "JoinedTimestamp": self.joined,
        });
        if let Some(email) = &self.email {
            value["Email"] = json!(email);
        }
        value
    }
}

const ACCOUNT_COLUMNS: &str = "id, name, email, management, extract(epoch FROM created_at)::float8, extract(epoch FROM closed_at)::float8, parent_id";

/// The organization's accounts (closed ones too), the management account
/// first, then by name.
pub async fn list(client: &deadpool_postgres::Object) -> anyhow::Result<Vec<Account>> {
    let rows = client
        .query_cached(&format!("SELECT {ACCOUNT_COLUMNS} FROM accounts WHERE NOT operator AND NOT internal ORDER BY management DESC, name, id"), &[])
        .await?;
    Ok(rows.iter().map(Account::of).collect())
}

/// Account `id`, if the organization has it.
pub async fn load(client: &deadpool_postgres::Object, id: &str) -> anyhow::Result<Option<Account>> {
    let row = client.query_opt_cached(&format!("SELECT {ACCOUNT_COLUMNS} FROM accounts WHERE id = $1 AND NOT operator AND NOT internal"), &[&id]).await?;
    Ok(row.as_ref().map(Account::of))
}

/// Whether `id` is an account of the organization's that isn't closed.
pub async fn open(client: &deadpool_postgres::Object, id: &str) -> anyhow::Result<bool> {
    Ok(load(client, id).await?.is_some_and(|a| a.closed.is_none()))
}

/// A CreateAccount request, as it went.
#[derive(Clone, Debug)]
pub struct CreateStatus {
    pub id: String,
    pub account_name: String,
    pub account_id: Option<String>,
    /// `SUCCEEDED`, or `FAILED` (with why: `EMAIL_ALREADY_EXISTS`, …).
    pub state: String,
    pub failure: Option<String>,
    pub requested: f64,
    pub completed: Option<f64>,
}

impl CreateStatus {
    fn json(&self) -> Value {
        let mut value = json!({
            "Id": self.id,
            "AccountName": self.account_name,
            "State": self.state,
            "RequestedTimestamp": self.requested,
        });
        if let Some(completed) = self.completed {
            value["CompletedTimestamp"] = json!(completed);
        }
        if let Some(account) = &self.account_id {
            value["AccountId"] = json!(account);
        }
        if let Some(failure) = &self.failure {
            value["FailureReason"] = json!(failure);
        }
        value
    }
}

/// The CreateAccount requests (just `id`, if given), newest first.
pub async fn requests(
    client: &deadpool_postgres::Object,
    id: Option<&str>,
) -> anyhow::Result<Vec<CreateStatus>> {
    let rows = client
        .query_cached(
            "SELECT id, account_name, account_id, state, failure_reason, extract(epoch FROM requested_at)::float8,
                    extract(epoch FROM completed_at)::float8
             FROM organization_requests WHERE ($1::text IS NULL OR id = $1) ORDER BY requested_at DESC, id",
            &[&id],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| CreateStatus {
            id: r.get(0),
            account_name: r.get(1),
            account_id: r.get(2),
            state: r.get(3),
            failure: r.get(4),
            requested: r.get(5),
            completed: r.get(6),
        })
        .collect())
}

/// Forgets CreateAccount requests older than `REQUESTS_KEPT`.
pub async fn reap(client: &deadpool_postgres::Object) -> anyhow::Result<u64> {
    Ok(client
        .execute_cached(
            "DELETE FROM organization_requests WHERE requested_at < now() - make_interval(secs => $1)",
            &[&REQUESTS_KEPT.as_secs_f64()],
        )
        .await?)
}

/// Whether `email` is an e-mail as Organizations takes one.
fn valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    (6..=64).contains(&email.len())
        && !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !email.chars().any(char::is_whitespace)
        && !domain.contains('@')
}

/// Whether `name` is an account's name as Organizations takes one.
pub fn valid_name(name: &str) -> bool {
    (1..=50).contains(&name.chars().count()) && name.chars().all(|c| (' '..='~').contains(&c))
}

/// The trust policy of a new account's access role: the management
/// account's, as AWS's is.
fn access_trust(management: &str) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{management}:root"}},"Action":"sts:AssumeRole"}}]}}"#
    )
}

/// Makes a member account named `name`, with e-mail `email` and the access
/// role `role` (allowing everything, trusting the management account), as
/// CreateAccount does: its request, done at once (`SUCCEEDED`, or `FAILED`
/// with why, as AWS reports a duplicate e-mail).
pub async fn create(
    client: &deadpool_postgres::Object,
    management: &str,
    name: &str,
    email: &str,
    role: &str,
) -> anyhow::Result<CreateStatus> {
    if !valid_name(name) {
        return Err(
            Refused::Invalid("An account's name is 1 to 50 printable characters.".into()).into(),
        );
    }
    if !valid_email(email) {
        return Err(Refused::Invalid(format!("{email} isn't an e-mail address.")).into());
    }
    if !crate::roles::valid_name(role) {
        return Err(Refused::Invalid(format!("{role} isn't a role's name.")).into());
    }
    let request = format!("car-{}", Uuid::new_v4().simple());
    let taken = client
        .query_opt_cached(
            "SELECT 1 FROM accounts WHERE lower(email) = lower($1)",
            &[&email],
        )
        .await?
        .is_some();
    let (state, failure, account) = match taken {
        true => ("FAILED", Some("EMAIL_ALREADY_EXISTS"), None),
        false => {
            let id = new_account(client, name, email).await?;
            // In the root, with FullAWSAccess if SCPs are enabled.
            structure::attach_default(client, &id).await?;
            let trust = crate::roles::check_trust(client, &id, &access_trust(management)).await?;
            let new = crate::roles::New {
                name: role,
                path: "/",
                trust: &trust,
                description: "Lets the organization's management account into this account",
                max_session_duration: 3600,
                boundary: None,
                tags: &[],
            };
            let role_id = crate::roles::create(client, &id, &new).await?;
            let role = crate::roles::Role::load_id(client, role_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("a new role is gone"))?;
            crate::roles::attach(
                client,
                &id,
                &role,
                &crate::managed::aws_arn("AdministratorAccess"),
                true,
            )
            .await?;
            ("SUCCEEDED", None, Some(id))
        }
    };
    client
        .execute_cached(
            "INSERT INTO organization_requests (id, account_name, account_id, state, failure_reason, completed_at)
             VALUES ($1, $2, $3, $4, $5, now())",
            &[&request, &name, &account, &state, &failure],
        )
        .await?;
    requests(client, Some(&request))
        .await?
        .pop()
        .ok_or_else(|| anyhow::anyhow!("a new request is gone"))
}

/// Inserts an account named `name`: its new ID, 12 random digits.
async fn new_account(
    client: &deadpool_postgres::Object,
    name: &str,
    email: &str,
) -> anyhow::Result<String> {
    loop {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes)
            .map_err(|e| anyhow::anyhow!("generating an account's ID: {e}"))?;
        let id = format!("{:012}", u64::from_le_bytes(bytes) % 1_000_000_000_000);
        let made = client
            .execute_cached(
                "INSERT INTO accounts (id, name, email) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING",
                &[&id, &name, &email],
            )
            .await;
        match made {
            Ok(1) => return Ok(id),
            Ok(_) => continue,
            // Another made one with that e-mail meanwhile.
            Err(e) if e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) => {
                return Err(Refused::Exists(format!(
                    "An account with the e-mail {email} exists already."
                ))
                .into());
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Closes member account `id`, at once: its principals are no one from now
/// on. Refused for the management account, a closed one, and one with
/// buckets.
pub async fn close(client: &deadpool_postgres::Object, management: &str, id: &str) -> Result<()> {
    let account = load(client, id).await?.ok_or_else(|| no_such_account(id))?;
    if account.id == management {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "ConstraintViolationException",
            "The management account can't be closed.",
        ));
    }
    if account.closed.is_some() {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "AccountAlreadyClosedException",
            format!("Account {id} is closed already."),
        ));
    }
    let buckets: i64 = client
        .query_one_cached("SELECT count(*) FROM buckets WHERE account_id = $1", &[&id])
        .await?
        .get(0);
    if buckets > 0 {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "ConstraintViolationException",
            format!(
                "Account {id} has {buckets} bucket(s): delete them first, as Cairn closes accounts at once."
            ),
        ));
    }
    client
        .execute_cached(
            "UPDATE accounts SET closed_at = now() WHERE id = $1 AND closed_at IS NULL",
            &[&id],
        )
        .await?;
    Ok(())
}

/// `operation` with `input`, by `principal`, as a request would be
/// answered past its signature: its answer, or its error's code.
#[cfg(test)]
pub(crate) async fn call(
    app: &App,
    principal: &Principal,
    operation: &str,
    input: Value,
) -> std::result::Result<Value, String> {
    let client = app.pool.get().await.unwrap();
    let (operation, action, members) = operation_of(operation).expect("an operation of ours");
    let management = users::account(&client).await.unwrap();
    if principal.account != management && !members {
        return Err(denied().code.to_owned());
    }
    let origin = Origin {
        peer: None,
        trusted_proxies: &[],
        signed: None,
        form: false,
    };
    let access = Access::new(
        Some(principal),
        &principal.account,
        &hyper::Method::POST,
        &hyper::HeaderMap::new(),
        "",
        &origin,
    )
    .unwrap();
    let ctx = Ctx {
        client: &client,
        access: &access,
        management,
        action,
        input: &input,
    };
    ctx.dispatch(operation).await.map_err(|e| e.code.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_the_organization() {
        let id = organization_id("123456789012");
        assert!(id.starts_with("o-") && id.len() == 12, "{id}");
        assert_eq!(
            organization_arn("123456789012"),
            format!("arn:aws:organizations::123456789012:organization/{id}")
        );
        assert_eq!(
            account_arn("123456789012", "210987654321"),
            format!("arn:aws:organizations::123456789012:account/{id}/210987654321")
        );
    }

    #[test]
    fn checks_names_and_emails() {
        assert!(valid_name("Team A (prod)"));
        assert!(!valid_name(""));
        assert!(!valid_name(&"x".repeat(51)));
        assert!(!valid_name("tab\there"));
        assert!(valid_email("ops@example.com"));
        for bad in [
            "ops",
            "@example.com",
            "ops@example",
            "o p@example.com",
            "a@b.c",
        ] {
            assert!(!valid_email(bad), "{bad}");
        }
    }
}
