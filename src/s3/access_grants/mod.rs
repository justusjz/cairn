//! S3 Access Grants, as S3 Control's API has them: an account's instance
//! (one: `default`), its locations (a scope, and the IAM role whose
//! sessions it vends), and grants on them, each giving an IAM user or role
//! `READ`, `WRITE` or `READWRITE` on a scope within its location (see
//! `scope`).
//!
//! Grants are no policies: no request is decided by them. A grantee calls
//! GetDataAccess for a target (a prefix, or an object), and gets the
//! temporary credentials of a session of the matching grant's location's
//! role, with a session policy that allows what the grant does on its
//! scope (or, with `privilege=Minimal`, on the target only) and nothing
//! else; its requests are then decided as any of the role's sessions' are,
//! by the role's policies capped by that one, and the buckets' policies.
//! So the role must allow what its locations' grants do, and trust
//! `access-grants.s3.amazonaws.com` (`sts:AssumeRole`), whose requests
//! carry `aws:SourceAccount` and `aws:SourceArn` (the instance's ARN), as
//! S3's do. Its sessions' requests carry the instance's ARN as
//! `s3:AccessGrantsInstanceArn`.
//!
//! Every operation is on the instance of the account the request names
//! (`x-amz-account-id`), and needs its `s3:` action, on the instance's ARN,
//! a location's or a grant's; creating or changing a location needs
//! `iam:PassRole` on its role too. Grants' and locations' scopes are
//! `s3:AccessGrantScope` and `s3:AccessGrantsLocationScope`. The signer's
//! own account's, its own policies decide that; another account's (of the
//! organization's, open: see `organizations`), the instance's **resource
//! policy** must allow it too, as AWS's: so a grant may name another
//! account's user or role, which calls GetDataAccess on the instance's
//! account. Making or deleting an instance, and its resource policy, are
//! its own account's only.
//!
//! Not here: IAM Identity Center (directory users and groups as grantees,
//! applications): NotImplemented. `instanceScope=ALL` is taken as `SELF`:
//! the instance is the named account's, as there's no sharing (AWS RAM).

pub mod scope;
#[cfg(test)]
mod e2e_tests;

use deadpool_postgres::Object;
use http_body_util::Full;
use hyper::{Method, Request, Response, StatusCode, body::Bytes};
use tokio_postgres::error::SqlState;

use crate::{
    App,
    db::Cached,
    policy::{Context, Kind, Policy},
    roles::Role,
    s3::{
        access::Access,
        actions::{Check, On},
        buckets::head::REGION,
        tags::{self, Tags},
        util::{decode_continuation_token, encode_continuation_token, format_s3_error, query_param, rejection_response, xml_escape, xml_ok},
    },
    sessions::{self, Session, Who},
    users::Principal,
};
use scope::{Covered, Permission};

/// The service that assumes locations' roles, as their trust policies name
/// it.
pub const SERVICE: &str = "access-grants.s3.amazonaws.com";
/// An account's instance's ID: its only one.
pub const INSTANCE_ID: &str = "default";
/// The ID of the location whose scope is all of S3 (`s3://`).
const DEFAULT_LOCATION: &str = "default";
/// The paths of S3 Control's Access Grants requests.
const ROOT: &str = "/v20180820/accessgrantsinstance";
const INSTANCES: &str = "/v20180820/accessgrantsinstances";
const XMLNS: &str = "http://awss3control.amazonaws.com/doc/2018-08-20/";
/// The most a listing lists, and lists by default.
const MAX_RESULTS: i64 = 1000;
/// The most grants an instance has, as in S3.
pub const MAX_GRANTS: i64 = 100_000;
/// A vended session's shortest and longest, and its default (capped by
/// its role's longest), in seconds.
const DURATIONS: std::ops::RangeInclusive<i64> = 900..=43_200;
const DEFAULT_DURATION: i64 = 3600;

/// Whether a request to `path` (as sent) with `headers` is S3 Control's, on
/// Access Grants (see `buckets::public_access::is_control`).
pub fn is_control(path: &str, headers: &hyper::HeaderMap) -> bool {
    headers.contains_key("x-amz-account-id")
        && (path == ROOT || path == INSTANCES || path.strip_prefix(ROOT).is_some_and(|rest| rest.starts_with('/')))
}

/// `account`'s instance's ARN.
pub fn instance_arn(account: &str) -> String {
    format!("arn:aws:s3:{REGION}:{account}:access-grants/{INSTANCE_ID}")
}

fn location_arn(account: &str, id: &str) -> String {
    format!("{}/location/{id}", instance_arn(account))
}

fn grant_arn(account: &str, id: &str) -> String {
    format!("{}/grant/{id}", instance_arn(account))
}

/// An Access Grants resource, as an ARN names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resource {
    Instance,
    Location(String),
    Grant(String),
}

/// The account and resource `arn` names, if it names an instance, a
/// location or a grant (whether or not there's one).
pub fn resource_of(arn: &str) -> Option<(String, Resource)> {
    let rest = arn.strip_prefix(&format!("arn:aws:s3:{REGION}:"))?;
    let (account, rest) = rest.split_once(':')?;
    let rest = rest.strip_prefix(&format!("access-grants/{INSTANCE_ID}"))?;
    let resource = match rest {
        "" => Resource::Instance,
        _ => match rest.strip_prefix("/location/").map(|id| (id, true)).or_else(|| rest.strip_prefix("/grant/").map(|id| (id, false))) {
            Some((id, location)) if valid_id(id) => match location {
                true => Resource::Location(id.to_owned()),
                false => Resource::Grant(id.to_owned()),
            },
            _ => return None,
        },
    };
    (account.len() == 12 && account.bytes().all(|b| b.is_ascii_digit())).then(|| (account.to_owned(), resource))
}

/// Whether `id` is a location's or a grant's ID as S3's model has them.
fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// What a request is: its operation, which its action is named after.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Op {
    CreateInstance,
    GetInstance,
    DeleteInstance,
    ListInstances,
    InstanceForPrefix,
    CreateLocation,
    GetLocation(String),
    UpdateLocation(String),
    DeleteLocation(String),
    ListLocations,
    CreateGrant,
    GetGrant(String),
    DeleteGrant(String),
    ListGrants,
    GetDataAccess,
    ListCallerGrants,
    PutPolicy,
    GetPolicy,
    DeletePolicy,
    /// What Cairn doesn't do: IAM Identity Center.
    Unsupported(&'static str),
}

impl Op {
    /// Whether another account's principals may make it, if the instance's
    /// resource policy allows it: all but what's about the instance itself.
    fn shared(&self) -> bool {
        !matches!(self, Op::CreateInstance | Op::DeleteInstance | Op::ListInstances | Op::PutPolicy | Op::GetPolicy | Op::DeletePolicy)
    }
}

/// The operation a request with `method` to `path` is: `Err(true)` if the
/// path is one, but not with that method; `Err(false)` if it's none.
fn route(method: &Method, path: &str) -> Result<Op, bool> {
    if path == INSTANCES {
        return match *method {
            Method::GET => Ok(Op::ListInstances),
            _ => Err(true),
        };
    }
    let rest = path.strip_prefix(ROOT).ok_or(false)?;
    let id = |prefix: &str| rest.strip_prefix(prefix).map(crate::s3::util::decode_path_param).filter(|id| !id.is_empty() && !id.contains('/'));
    let op = match (method.clone(), rest) {
        (Method::POST, "") => Op::CreateInstance,
        (Method::GET, "") => Op::GetInstance,
        (Method::DELETE, "") => Op::DeleteInstance,
        (Method::GET, "/prefix") => Op::InstanceForPrefix,
        (Method::POST, "/location") => Op::CreateLocation,
        (Method::GET, "/locations") => Op::ListLocations,
        (Method::POST, "/grant") => Op::CreateGrant,
        (Method::GET, "/grants") => Op::ListGrants,
        (Method::GET, "/dataaccess") => Op::GetDataAccess,
        (Method::GET, "/caller/grants") => Op::ListCallerGrants,
        (Method::PUT, "/resourcepolicy") => Op::PutPolicy,
        (Method::GET, "/resourcepolicy") => Op::GetPolicy,
        (Method::DELETE, "/resourcepolicy") => Op::DeletePolicy,
        (Method::POST | Method::DELETE, "/identitycenter") => Op::Unsupported("IAM Identity Center"),
        (method, _) if id("/location/").is_some() => {
            let id = id("/location/").expect("just checked");
            match method {
                Method::GET => Op::GetLocation(id),
                Method::PUT => Op::UpdateLocation(id),
                Method::DELETE => Op::DeleteLocation(id),
                _ => return Err(true),
            }
        }
        (method, _) if id("/grant/").is_some() => {
            let id = id("/grant/").expect("just checked");
            match method {
                Method::GET => Op::GetGrant(id),
                Method::DELETE => Op::DeleteGrant(id),
                _ => return Err(true),
            }
        }
        (_, "" | "/prefix" | "/location" | "/locations" | "/grant" | "/grants" | "/dataaccess" | "/caller/grants" | "/resourcepolicy" | "/identitycenter") => {
            return Err(true);
        }
        _ => return Err(false),
    };
    Ok(op)
}

impl Op {
    /// Its action.
    fn action(&self) -> &'static str {
        match self {
            Op::CreateInstance => "s3:CreateAccessGrantsInstance",
            Op::GetInstance => "s3:GetAccessGrantsInstance",
            Op::DeleteInstance => "s3:DeleteAccessGrantsInstance",
            Op::ListInstances => "s3:ListAccessGrantsInstances",
            Op::InstanceForPrefix => "s3:GetAccessGrantsInstanceForPrefix",
            Op::CreateLocation => "s3:CreateAccessGrantsLocation",
            Op::GetLocation(_) => "s3:GetAccessGrantsLocation",
            Op::UpdateLocation(_) => "s3:UpdateAccessGrantsLocation",
            Op::DeleteLocation(_) => "s3:DeleteAccessGrantsLocation",
            Op::ListLocations => "s3:ListAccessGrantsLocations",
            Op::CreateGrant => "s3:CreateAccessGrant",
            Op::GetGrant(_) => "s3:GetAccessGrant",
            Op::DeleteGrant(_) => "s3:DeleteAccessGrant",
            Op::ListGrants => "s3:ListAccessGrants",
            Op::GetDataAccess => "s3:GetDataAccess",
            Op::ListCallerGrants => "s3:ListCallerAccessGrants",
            Op::PutPolicy => "s3:PutAccessGrantsInstanceResourcePolicy",
            Op::GetPolicy => "s3:GetAccessGrantsInstanceResourcePolicy",
            Op::DeletePolicy => "s3:DeleteAccessGrantsInstanceResourcePolicy",
            Op::Unsupported(_) => "",
        }
    }
}

fn invalid(message: impl AsRef<str>) -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::BAD_REQUEST, "InvalidRequest", message.as_ref())
}

fn malformed() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::BAD_REQUEST,
        "MalformedXML",
        "The XML you provided was not well-formed or did not validate against our published schema",
    )
}

fn not_implemented(what: &str) -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::NOT_IMPLEMENTED, "NotImplemented", &format!("Cairn doesn't implement {what}."))
}

fn no_instance() -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::NOT_FOUND, "AccessGrantsInstanceNotExistsError", "Access Grants Instance does not exist")
}

fn no_location() -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::NOT_FOUND, "AccessGrantsLocationNotExistsError", "Access Grants Location does not exist")
}

fn no_grant() -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::NOT_FOUND, "AccessGrantNotExistsError", "Access Grant does not exist")
}

fn conflict(code: &str, message: &str) -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::CONFLICT, code, message)
}

fn no_content() -> Response<Full<Bytes>> {
    Response::builder().status(StatusCode::NO_CONTENT).body(Full::new(Bytes::new())).unwrap()
}

/// Whether `e` is a foreign key's violation: a location or instance gone
/// meanwhile.
fn gone(e: &tokio_postgres::Error) -> bool {
    e.code() == Some(&SqlState::FOREIGN_KEY_VIOLATION)
}

/// A request's XML body, parsed: its root's children's texts, and the
/// elements it has (for `Grantee`, `Tags`, ...).
struct Body<'a> {
    root: roxmltree::Node<'a, 'a>,
}

impl<'a> Body<'a> {
    fn child(&self, name: &str) -> Option<roxmltree::Node<'a, 'a>> {
        child(self.root, name)
    }

    fn text(&self, name: &str) -> Option<String> {
        self.child(name).map(|n| n.text().unwrap_or("").to_owned())
    }

    /// Its `<Tags>`, checked as a resource's (none, if there are none).
    fn tags(&self) -> Result<Tags, Response<Full<Bytes>>> {
        match self.child("Tags") {
            Some(list) => {
                let tags = Tags::from_elements(list, tags::On::Resource)?;
                match tags.too_many() {
                    Some(refused) => Err(refused),
                    None => Ok(tags),
                }
            }
            None => Ok(Tags::default()),
        }
    }
}

fn child<'a>(node: roxmltree::Node<'a, 'a>, name: &str) -> Option<roxmltree::Node<'a, 'a>> {
    node.children().find(|n| n.is_element() && n.tag_name().name() == name)
}

fn child_text(node: roxmltree::Node, name: &str) -> Option<String> {
    child(node, name).map(|n| n.text().unwrap_or("").to_owned())
}

/// Tags as they're stored (NULL: none).
fn stored_tags(stored: Option<&str>) -> Tags {
    Tags::from_stored(stored.unwrap_or(""))
}

/// A location, as kept.
#[derive(Clone, Debug)]
pub struct Location {
    pub id: String,
    pub scope: String,
    pub role_arn: String,
    pub created: u64,
}

const LOCATION_COLUMNS: &str = "id, scope, role_arn, extract(epoch FROM created_at)::bigint";

impl Location {
    fn of(row: &tokio_postgres::Row) -> Location {
        Location { id: row.get(0), scope: row.get(1), role_arn: row.get(2), created: row.get::<_, i64>(3) as u64 }
    }

    async fn load(client: &Object, account: &str, id: &str) -> anyhow::Result<Option<Location>> {
        let row = client
            .query_opt_cached(
                &format!("SELECT {LOCATION_COLUMNS} FROM access_grants_locations WHERE account_id = $1 AND id = $2"),
                &[&account, &id],
            )
            .await?;
        Ok(row.as_ref().map(Location::of))
    }

    fn xml(&self, account: &str) -> String {
        format!(
            "<CreatedAt>{}</CreatedAt><AccessGrantsLocationId>{}</AccessGrantsLocationId>\
             <AccessGrantsLocationArn>{}</AccessGrantsLocationArn><LocationScope>{}</LocationScope><IAMRoleArn>{}</IAMRoleArn>",
            sessions::iso(self.created),
            xml_escape(&self.id),
            xml_escape(&location_arn(account, &self.id)),
            xml_escape(&self.scope),
            xml_escape(&self.role_arn),
        )
    }
}

/// A grant, as kept.
#[derive(Clone, Debug)]
pub struct Grant {
    pub id: String,
    pub location_id: String,
    pub sub_prefix: Option<String>,
    pub object: bool,
    pub grantee_type: String,
    pub grantee: String,
    pub permission: Permission,
    pub scope: String,
    pub created: u64,
}

const GRANT_COLUMNS: &str =
    "id, location_id, sub_prefix, object, grantee_type, grantee, permission, scope, extract(epoch FROM created_at)::bigint";

impl Grant {
    fn of(row: &tokio_postgres::Row) -> Grant {
        Grant {
            id: row.get(0),
            location_id: row.get(1),
            sub_prefix: row.get(2),
            object: row.get(3),
            grantee_type: row.get(4),
            grantee: row.get(5),
            permission: Permission::parse(row.get(6)).expect("the table checks it"),
            scope: row.get(7),
            created: row.get::<_, i64>(8) as u64,
        }
    }

    async fn load(client: &Object, account: &str, id: &str) -> anyhow::Result<Option<Grant>> {
        let row = client
            .query_opt_cached(&format!("SELECT {GRANT_COLUMNS} FROM access_grants WHERE account_id = $1 AND id = $2"), &[&account, &id])
            .await?;
        Ok(row.as_ref().map(Grant::of))
    }

    /// What it covers.
    pub fn covers(&self) -> Covered {
        scope::grant_covers(&self.scope, self.object)
    }

    fn grantee_xml(&self) -> String {
        format!(
            "<Grantee><GranteeType>{}</GranteeType><GranteeIdentifier>{}</GranteeIdentifier></Grantee>",
            self.grantee_type,
            xml_escape(&self.grantee)
        )
    }

    fn xml(&self, account: &str) -> String {
        let configuration = match &self.sub_prefix {
            Some(sub) => format!("<AccessGrantsLocationConfiguration><S3SubPrefix>{}</S3SubPrefix></AccessGrantsLocationConfiguration>", xml_escape(sub)),
            None => String::new(),
        };
        format!(
            "<CreatedAt>{}</CreatedAt><AccessGrantId>{}</AccessGrantId><AccessGrantArn>{}</AccessGrantArn>{}\
             <Permission>{}</Permission><AccessGrantsLocationId>{}</AccessGrantsLocationId>{configuration}<GrantScope>{}</GrantScope>",
            sessions::iso(self.created),
            xml_escape(&self.id),
            xml_escape(&grant_arn(account, &self.id)),
            self.grantee_xml(),
            self.permission.as_str(),
            xml_escape(&self.location_id),
            xml_escape(&self.scope),
        )
    }
}

/// When `account`'s instance was made, if it has one.
async fn instance(client: &Object, account: &str) -> anyhow::Result<Option<u64>> {
    let row = client
        .query_opt_cached("SELECT extract(epoch FROM created_at)::bigint FROM access_grants_instances WHERE account_id = $1", &[&account])
        .await?;
    Ok(row.map(|row| row.get::<_, i64>(0) as u64))
}

fn instance_xml(account: &str, created: u64) -> String {
    format!(
        "<AccessGrantsInstanceId>{INSTANCE_ID}</AccessGrantsInstanceId><AccessGrantsInstanceArn>{}</AccessGrantsInstanceArn>\
         <CreatedAt>{}</CreatedAt>",
        instance_arn(account),
        sessions::iso(created)
    )
}

fn result(name: &str, inner: &str) -> Response<Full<Bytes>> {
    xml_ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><{name} xmlns=\"{XMLNS}\">{inner}</{name}>"))
}

/// The role `arn` names, if it's one of `account`'s.
async fn role_named(client: &Object, account: &str, arn: &str) -> anyhow::Result<Option<Role>> {
    let Some(rest) = arn.strip_prefix("arn:aws:iam::").and_then(|r| r.strip_prefix(account)).and_then(|r| r.strip_prefix(":role/")) else {
        return Ok(None);
    };
    let (path, name) = match rest.rsplit_once('/') {
        Some((path, name)) => (format!("/{path}/"), name),
        None => ("/".to_owned(), rest),
    };
    Ok(Role::load(client, account, name).await?.filter(|r| r.path == path && r.name == name))
}

/// Whether `arn` is an IAM user's or role's of `account` that exists, as a
/// grantee must be.
async fn principal_exists(client: &Object, account: &str, arn: &str) -> anyhow::Result<bool> {
    // Of `account`, or another (open) account of the organization's.
    let named = arn.strip_prefix("arn:aws:iam::").and_then(|r| r.split(':').next()).unwrap_or("").to_owned();
    if named != account && !crate::organizations::open(client, &named).await? {
        return Ok(false);
    }
    let account = named.as_str();
    let Some(rest) = arn.strip_prefix("arn:aws:iam::").and_then(|r| r.strip_prefix(account)) else { return Ok(false) };
    let row = match (rest.strip_prefix(":user/"), rest.strip_prefix(":role/")) {
        (Some(user), _) => {
            client
                .query_opt_cached("SELECT 1 FROM users WHERE substring(path FROM 2) || name = $1 AND account_id = $2", &[&user, &account])
                .await?
        }
        (_, Some(role)) => {
            client
                .query_opt_cached("SELECT 1 FROM iam_roles WHERE substring(path FROM 2) || name = $1 AND account_id = $2", &[&role, &account])
                .await?
        }
        _ => None,
    };
    Ok(row.is_some())
}

/// Whether `role`'s trust policy lets Access Grants assume it for the
/// instance of `account`.
pub fn trusts_access_grants(role: &Role, account: &str) -> anyhow::Result<bool> {
    let trust = Policy::parse(&role.trust, Kind::Trust)
        .map_err(|e| anyhow::anyhow!("role {}'s trust policy doesn't parse: {}", role.name, e.message))?
        .with_ids(role.trust_principals.clone());
    let mut context = Context::default();
    context.set("aws:ResourceAccount", &role.account);
    context.set("aws:SourceAccount", account);
    context.set("aws:SourceArn", instance_arn(account));
    context.set("aws:PrincipalIsAWSService", "true");
    context.set("aws:PrincipalServiceName", SERVICE);
    let request = crate::policy::Request {
        principal: crate::policy::Principal::Service { name: SERVICE },
        action: "sts:AssumeRole",
        resource: &role.arn(),
        context: &context,
    };
    let caps = crate::policy::Caps { boundary: None, session: None };
    Ok(crate::policy::trust_allows(std::iter::empty(), caps, &trust, &request, false))
}

/// A request in progress: who makes it, in which account, as `access`
/// decides it.
struct Ctx<'a> {
    app: &'a App,
    client: Object,
    account: String,
    principal: &'a Principal,
    access: &'a mut Access,
}

impl Ctx<'_> {
    /// The refusal of `action` on `on`, with the condition keys `extra`, if
    /// it's denied.
    fn denied(&self, action: &'static str, on: On, extra: &Context) -> Option<Response<Full<Bytes>>> {
        let check = Check { action, on };
        match self.access.verdict_with(&check, extra) {
            crate::policy::Verdict::Allow => None,
            verdict => Some(self.access.denied(&check, verdict)),
        }
    }

    fn instance_on(&self) -> On {
        On::Arn(instance_arn(&self.account))
    }

    /// Checks a role a location is to have: it's the account's, and the
    /// caller may pass it (`iam:PassRole`, to Access Grants).
    async fn passed_role(&self, arn: &str) -> anyhow::Result<Result<Role, Response<Full<Bytes>>>> {
        let Some(role) = role_named(&self.client, &self.account, arn).await? else {
            return Ok(Err(invalid(format!("The IAM role {arn} doesn't exist in this account."))));
        };
        let mut extra = Context::default();
        extra.set("iam:PassedToService", SERVICE);
        if let Some(refused) = self.denied("iam:PassRole", role.on(), &extra) {
            return Ok(Err(refused));
        }
        Ok(Ok(role))
    }
}

/// Handles a request `is_control` says is one, by `principal`, as `access`
/// decides it; `secret` is what its body is signed with.
pub async fn handle(
    app: &App,
    req: Request<crate::listen::ClientBody>,
    principal: Option<&Principal>,
    access: &mut Access,
    secret: &str,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let denied = || Ok(format_s3_error(StatusCode::FORBIDDEN, "AccessDenied", "Access Denied"));
    let named = req.headers().get("x-amz-account-id").and_then(|v| v.to_str().ok()).map(str::to_owned);
    let (Some(principal), Some(named)) = (principal, named) else { return denied() };
    // Another account's instance: of the organization's, open.
    if named != principal.account && !crate::organizations::open(&app.pool.get().await?, &named).await? {
        return denied();
    }
    let op = match route(req.method(), req.uri().path()) {
        Ok(Op::Unsupported(what)) => return Ok(not_implemented(what)),
        Ok(op) if named != principal.account && !op.shared() => return denied(),
        Ok(op) => op,
        Err(true) => {
            return Ok(format_s3_error(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", "The specified method is not allowed against this resource."));
        }
        Err(false) => return Ok(format_s3_error(StatusCode::NOT_FOUND, "NoSuchResource", "The specified resource doesn't exist.")),
    };
    let query = req.uri().query().unwrap_or("").to_owned();
    let body = match *req.method() {
        Method::POST | Method::PUT => match crate::s3::read_body(req, secret, true).await? {
            Ok(body) => Some(body),
            Err(rejection) => return Ok(rejection_response(&rejection)),
        },
        _ => None,
    };
    answer(app, op, principal, &named, access, &query, body).await
}

/// Answers `op` on `account`'s instance, by `principal` (of that account,
/// or another), with its `query` and its `body` (a POST's or PUT's), as
/// `access` decides it, with the instance's resource policy.
async fn answer(
    app: &App,
    op: Op,
    principal: &Principal,
    account: &str,
    access: &mut Access,
    query: &str,
    body: Option<Bytes>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let query = query.to_owned();
    let text = body.as_ref().map(|b| std::str::from_utf8(b).map(str::to_owned));
    let text = match text {
        // Clients send none when there's nothing to say (no tags, say).
        Some(Ok(text)) if text.trim().is_empty() => None,
        Some(Ok(text)) => Some(text),
        Some(Err(_)) => return Ok(malformed()),
        None => None,
    };
    let document = match text.as_deref().map(roxmltree::Document::parse) {
        Some(Ok(document)) => Some(document),
        Some(Err(_)) => return Ok(malformed()),
        None => None,
    };
    let body = document.as_ref().map(|d| Body { root: d.root_element() });
    let client = app.pool.get().await?;
    let policy = resource_policy(&client, account).await?.map(|p| p.policy);
    let policy = match policy {
        Some(text) => Some(crate::s3::access::parsed(&text, Kind::AccessGrants(&instance_arn(account)), None)?),
        None => None,
    };
    access.set_grants_instance(&instance_arn(account), account, policy);
    let mut ctx = Ctx { app, client, account: account.to_owned(), principal, access };
    let action = op.action();
    match op {
        Op::CreateInstance => create_instance(&mut ctx, body.as_ref()).await,
        Op::GetInstance => {
            if let Some(refused) = ctx.denied(action, ctx.instance_on(), &Context::default()) {
                return Ok(refused);
            }
            Ok(match instance(&ctx.client, &ctx.account).await? {
                Some(created) => result("GetAccessGrantsInstanceResult", &instance_xml(&ctx.account, created)),
                None => no_instance(),
            })
        }
        Op::DeleteInstance => delete_instance(&mut ctx).await,
        Op::ListInstances => {
            if let Some(refused) = ctx.denied(action, On::Account, &Context::default()) {
                return Ok(refused);
            }
            let list = match instance(&ctx.client, &ctx.account).await? {
                Some(created) => format!("<AccessGrantsInstance>{}</AccessGrantsInstance>", instance_xml(&ctx.account, created)),
                None => String::new(),
            };
            Ok(result("ListAccessGrantsInstancesResult", &format!("<AccessGrantsInstancesList>{list}</AccessGrantsInstancesList>")))
        }
        Op::InstanceForPrefix => instance_for_prefix(&mut ctx, &query).await,
        Op::CreateLocation => create_location(&mut ctx, body.as_ref()).await,
        Op::GetLocation(id) => {
            let location = Location::load(&ctx.client, &ctx.account, &id).await?;
            let mut extra = Context::default();
            if let Some(location) = &location {
                extra.set("s3:AccessGrantsLocationScope", &location.scope);
            }
            if let Some(refused) = ctx.denied(action, On::Arn(location_arn(&ctx.account, &id)), &extra) {
                return Ok(refused);
            }
            Ok(match location {
                Some(location) => result("GetAccessGrantsLocationResult", &location.xml(&ctx.account)),
                None => no_location(),
            })
        }
        Op::UpdateLocation(id) => update_location(&mut ctx, &id, body.as_ref()).await,
        Op::DeleteLocation(id) => delete_location(&mut ctx, &id).await,
        Op::ListLocations => list_locations(&mut ctx, &query).await,
        Op::CreateGrant => create_grant(&mut ctx, body.as_ref()).await,
        Op::GetGrant(id) => {
            let grant = Grant::load(&ctx.client, &ctx.account, &id).await?;
            let mut extra = Context::default();
            if let Some(grant) = &grant {
                extra.set("s3:AccessGrantScope", &grant.scope);
            }
            if let Some(refused) = ctx.denied(action, On::Arn(grant_arn(&ctx.account, &id)), &extra) {
                return Ok(refused);
            }
            Ok(match grant {
                Some(grant) => result("GetAccessGrantResult", &grant.xml(&ctx.account)),
                None => no_grant(),
            })
        }
        Op::DeleteGrant(id) => {
            let grant = Grant::load(&ctx.client, &ctx.account, &id).await?;
            let mut extra = Context::default();
            if let Some(grant) = &grant {
                extra.set("s3:AccessGrantScope", &grant.scope);
            }
            if let Some(refused) = ctx.denied(action, On::Arn(grant_arn(&ctx.account, &id)), &extra) {
                return Ok(refused);
            }
            let deleted = ctx
                .client
                .execute_cached("DELETE FROM access_grants WHERE account_id = $1 AND id = $2", &[&ctx.account, &id])
                .await?;
            Ok(match deleted {
                0 => no_grant(),
                _ => no_content(),
            })
        }
        Op::ListGrants => list_grants(&mut ctx, &query).await,
        Op::GetDataAccess => get_data_access(&mut ctx, &query).await,
        Op::ListCallerGrants => list_caller_grants(&mut ctx, &query).await,
        Op::PutPolicy => put_policy(&mut ctx, body.as_ref()).await,
        Op::GetPolicy => {
            if let Some(refused) = ctx.denied(action, ctx.instance_on(), &Context::default()) {
                return Ok(refused);
            }
            if instance(&ctx.client, &ctx.account).await?.is_none() {
                return Ok(no_instance());
            }
            // None set: an empty result (AWS doesn't say).
            let inner = resource_policy(&ctx.client, &ctx.account).await?.map(|p| p.xml()).unwrap_or_default();
            Ok(result("GetAccessGrantsInstanceResourcePolicyResult", &inner))
        }
        Op::DeletePolicy => {
            if let Some(refused) = ctx.denied(action, ctx.instance_on(), &Context::default()) {
                return Ok(refused);
            }
            let changed = ctx
                .client
                .execute_cached(
                    "UPDATE access_grants_instances SET resource_policy = NULL, resource_policy_org = NULL, resource_policy_created_at = NULL
                     WHERE account_id = $1",
                    &[&ctx.account],
                )
                .await?;
            Ok(match changed {
                0 => no_instance(),
                // 200, with no body, as AWS's.
                _ => Response::builder().status(StatusCode::OK).body(Full::new(Bytes::new())).unwrap(),
            })
        }
        Op::Unsupported(what) => Ok(not_implemented(what)),
    }
}


/// The body a request must have.
fn required<'b, 'a>(body: Option<&'b Body<'a>>) -> Result<&'b Body<'a>, Response<Full<Bytes>>> {
    body.ok_or_else(malformed)
}

/// A required field of a body.
fn field(body: &Body, name: &str) -> Result<String, Response<Full<Bytes>>> {
    match body.text(name) {
        Some(text) if !text.is_empty() => Ok(text),
        _ => Err(invalid(format!("{name} is required."))),
    }
}

macro_rules! or_answer {
    ($e:expr) => {
        match $e {
            Ok(value) => value,
            Err(response) => return Ok(response),
        }
    };
}

/// An instance's resource policy, as it was set.
struct ResourcePolicy {
    policy: String,
    organization: Option<String>,
    created: u64,
}

impl ResourcePolicy {
    fn xml(&self) -> String {
        let organization = self.organization.as_deref().map(|o| format!("<Organization>{}</Organization>", xml_escape(o))).unwrap_or_default();
        format!("<Policy>{}</Policy>{organization}<CreatedAt>{}</CreatedAt>", xml_escape(&self.policy), sessions::iso(self.created))
    }
}

/// `account`'s instance's resource policy, if it has one.
async fn resource_policy(client: &Object, account: &str) -> anyhow::Result<Option<ResourcePolicy>> {
    let row = client
        .query_opt_cached(
            "SELECT resource_policy, resource_policy_org, extract(epoch FROM resource_policy_created_at)::bigint
             FROM access_grants_instances WHERE account_id = $1 AND resource_policy IS NOT NULL",
            &[&account],
        )
        .await?;
    Ok(row.map(|r| ResourcePolicy { policy: r.get(0), organization: r.get(1), created: r.get::<_, i64>(2) as u64 }))
}

/// PutAccessGrantsInstanceResourcePolicy: `Policy`, valid as an instance's
/// (naming the instance, its locations or grants, and Access Grants'
/// actions), and `Organization`, an organization's ID if given.
async fn put_policy(ctx: &mut Ctx<'_>, body: Option<&Body<'_>>) -> anyhow::Result<Response<Full<Bytes>>> {
    let body = or_answer!(required(body));
    let policy = or_answer!(field(body, "Policy"));
    let organization = body.text("Organization").filter(|o| !o.is_empty());
    if let Some(organization) = &organization {
        let valid = organization.strip_prefix("o-").is_some_and(|rest| {
            (10..=32).contains(&rest.len()) && rest.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        });
        if !valid {
            return Ok(invalid("Organization isn't an organization's ID."));
        }
    }
    if let Some(refused) = ctx.denied("s3:PutAccessGrantsInstanceResourcePolicy", ctx.instance_on(), &Context::default()) {
        return Ok(refused);
    }
    if policy.len() > 350_000 {
        return Ok(invalid("Policy is longer than 350000 characters."));
    }
    let arn = instance_arn(&ctx.account);
    if let Err(e) = Policy::parse(&policy, Kind::AccessGrants(&arn)) {
        return Ok(format_s3_error(StatusCode::BAD_REQUEST, "MalformedPolicy", &e.message));
    }
    // The other accounts it names must be the organization's.
    for named in Policy::parse(&policy, Kind::AccessGrants(&arn)).expect("just parsed").accounts() {
        if !crate::organizations::open(&ctx.client, named).await? {
            return Ok(format_s3_error(StatusCode::BAD_REQUEST, "MalformedPolicy", &format!("Invalid principal in policy: {named}")));
        }
    }
    let row = ctx
        .client
        .query_opt_cached(
            "UPDATE access_grants_instances SET resource_policy = $2, resource_policy_org = $3, resource_policy_created_at = now()
             WHERE account_id = $1 RETURNING extract(epoch FROM resource_policy_created_at)::bigint",
            &[&ctx.account, &policy, &organization],
        )
        .await?;
    let Some(row) = row else { return Ok(no_instance()) };
    let set = ResourcePolicy { policy, organization, created: row.get::<_, i64>(0) as u64 };
    Ok(result("PutAccessGrantsInstanceResourcePolicyResult", &set.xml()))
}

async fn create_instance(ctx: &mut Ctx<'_>, body: Option<&Body<'_>>) -> anyhow::Result<Response<Full<Bytes>>> {
    let tags = match body {
        Some(body) => {
            if body.child("IdentityCenterArn").is_some() {
                return Ok(not_implemented("IAM Identity Center"));
            }
            or_answer!(body.tags())
        }
        None => Tags::default(),
    };
    let mut extra = Context::default();
    tags.set_context(&mut extra, "aws:RequestTag", Some("aws:TagKeys"));
    if let Some(refused) = ctx.denied("s3:CreateAccessGrantsInstance", ctx.instance_on(), &extra) {
        return Ok(refused);
    }
    let stored = Some(tags).filter(|t| !t.is_empty()).map(|t| t.stored());
    let row = ctx
        .client
        .query_opt_cached(
            "INSERT INTO access_grants_instances (account_id, tags) VALUES ($1, $2) ON CONFLICT DO NOTHING
             RETURNING extract(epoch FROM created_at)::bigint",
            &[&ctx.account, &stored],
        )
        .await?;
    Ok(match row {
        Some(row) => result("CreateAccessGrantsInstanceResult", &instance_xml(&ctx.account, row.get::<_, i64>(0) as u64)),
        None => conflict("AccessGrantsInstanceAlreadyExists", "Access Grants Instance already exists"),
    })
}

async fn delete_instance(ctx: &mut Ctx<'_>) -> anyhow::Result<Response<Full<Bytes>>> {
    if let Some(refused) = ctx.denied("s3:DeleteAccessGrantsInstance", ctx.instance_on(), &Context::default()) {
        return Ok(refused);
    }
    // Not while it has locations, which keep it (their foreign key) even
    // against one made meanwhile.
    let deleted = ctx
        .client
        .execute_cached(
            "DELETE FROM access_grants_instances i WHERE account_id = $1
             AND NOT EXISTS (SELECT 1 FROM access_grants_locations l WHERE l.account_id = i.account_id)",
            &[&ctx.account],
        )
        .await;
    let not_empty = || conflict("AccessGrantsInstanceNotEmptyError", "Please clean up locations before deleting the access grants instance");
    match deleted {
        Ok(0) => Ok(match instance(&ctx.client, &ctx.account).await? {
            Some(_) => not_empty(),
            None => no_instance(),
        }),
        Ok(_) => Ok(no_content()),
        Err(e) if gone(&e) => Ok(not_empty()),
        Err(e) => Err(e.into()),
    }
}

async fn instance_for_prefix(ctx: &mut Ctx<'_>, query: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let Some(prefix) = query_param(query, "s3prefix").filter(|p| !p.is_empty()) else {
        return Ok(invalid("s3prefix is required."));
    };
    let target = or_answer!(scope::target_covers(&prefix, false).map_err(invalid));
    if let Some(refused) = ctx.denied("s3:GetAccessGrantsInstanceForPrefix", ctx.instance_on(), &Context::default()) {
        return Ok(refused);
    }
    if instance(&ctx.client, &ctx.account).await?.is_none() {
        return Ok(no_instance());
    }
    let scopes: Vec<String> = ctx
        .client
        .query_cached("SELECT scope FROM access_grants_locations WHERE account_id = $1", &[&ctx.account])
        .await?
        .iter()
        .map(|row| row.get(0))
        .collect();
    if !scopes.iter().any(|s| scope::location_covers(s).covers(&target)) {
        return Ok(no_instance());
    }
    Ok(result(
        "GetAccessGrantsInstanceForPrefixResult",
        &format!("<AccessGrantsInstanceArn>{}</AccessGrantsInstanceArn><AccessGrantsInstanceId>{INSTANCE_ID}</AccessGrantsInstanceId>", instance_arn(&ctx.account)),
    ))
}

async fn create_location(ctx: &mut Ctx<'_>, body: Option<&Body<'_>>) -> anyhow::Result<Response<Full<Bytes>>> {
    let body = or_answer!(required(body));
    let scope = or_answer!(field(body, "LocationScope"));
    let role_arn = or_answer!(field(body, "IAMRoleArn"));
    let tags = or_answer!(body.tags());
    if scope.chars().count() > 2000 {
        return Ok(invalid("LocationScope is longer than 2000 characters."));
    }
    or_answer!(scope::check_location(&scope).map_err(invalid));
    let mut extra = Context::default();
    extra.set("s3:AccessGrantsLocationScope", &scope);
    tags.set_context(&mut extra, "aws:RequestTag", Some("aws:TagKeys"));
    if let Some(refused) = ctx.denied("s3:CreateAccessGrantsLocation", ctx.instance_on(), &extra) {
        return Ok(refused);
    }
    if instance(&ctx.client, &ctx.account).await?.is_none() {
        return Ok(no_instance());
    }
    or_answer!(ctx.passed_role(&role_arn).await?);
    let id = match scope.as_str() {
        scope::SCHEME => DEFAULT_LOCATION.to_owned(),
        _ => uuid::Uuid::new_v4().to_string(),
    };
    let stored = Some(tags).filter(|t| !t.is_empty()).map(|t| t.stored());
    let row = ctx
        .client
        .query_opt_cached(
            &format!(
                "INSERT INTO access_grants_locations (account_id, id, scope, role_arn, tags) VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT DO NOTHING RETURNING {LOCATION_COLUMNS}"
            ),
            &[&ctx.account, &id, &scope, &role_arn, &stored],
        )
        .await;
    Ok(match row {
        Ok(Some(row)) => result("CreateAccessGrantsLocationResult", &Location::of(&row).xml(&ctx.account)),
        Ok(None) => conflict("AccessGrantsLocationAlreadyExistsError", "Access Grants Location already exists"),
        Err(e) if gone(&e) => no_instance(),
        Err(e) => return Err(e.into()),
    })
}

async fn update_location(ctx: &mut Ctx<'_>, id: &str, body: Option<&Body<'_>>) -> anyhow::Result<Response<Full<Bytes>>> {
    let body = or_answer!(required(body));
    let role_arn = or_answer!(field(body, "IAMRoleArn"));
    let location = Location::load(&ctx.client, &ctx.account, id).await?;
    let mut extra = Context::default();
    if let Some(location) = &location {
        extra.set("s3:AccessGrantsLocationScope", &location.scope);
    }
    if let Some(refused) = ctx.denied("s3:UpdateAccessGrantsLocation", On::Arn(location_arn(&ctx.account, id)), &extra) {
        return Ok(refused);
    }
    if location.is_none() {
        return Ok(no_location());
    }
    or_answer!(ctx.passed_role(&role_arn).await?);
    let row = ctx
        .client
        .query_opt_cached(
            &format!("UPDATE access_grants_locations SET role_arn = $3 WHERE account_id = $1 AND id = $2 RETURNING {LOCATION_COLUMNS}"),
            &[&ctx.account, &id, &role_arn],
        )
        .await?;
    Ok(match row {
        Some(row) => result("UpdateAccessGrantsLocationResult", &Location::of(&row).xml(&ctx.account)),
        None => no_location(),
    })
}

async fn delete_location(ctx: &mut Ctx<'_>, id: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let location = Location::load(&ctx.client, &ctx.account, id).await?;
    let mut extra = Context::default();
    if let Some(location) = &location {
        extra.set("s3:AccessGrantsLocationScope", &location.scope);
    }
    if let Some(refused) = ctx.denied("s3:DeleteAccessGrantsLocation", On::Arn(location_arn(&ctx.account, id)), &extra) {
        return Ok(refused);
    }
    // Not while it has grants, which keep it (their foreign key) even
    // against one made meanwhile.
    let deleted = ctx
        .client
        .execute_cached(
            "DELETE FROM access_grants_locations l WHERE account_id = $1 AND id = $2
             AND NOT EXISTS (SELECT 1 FROM access_grants g WHERE g.account_id = l.account_id AND g.location_id = l.id)",
            &[&ctx.account, &id],
        )
        .await;
    let not_empty = || conflict("AccessGrantsLocationNotEmptyError", "Please delete access grants before deleting access grants location");
    match deleted {
        Ok(0) => Ok(match Location::load(&ctx.client, &ctx.account, id).await? {
            Some(_) => not_empty(),
            None => no_location(),
        }),
        Ok(_) => Ok(no_content()),
        Err(e) if gone(&e) => Ok(not_empty()),
        Err(e) => Err(e.into()),
    }
}

/// A listing's page: `maxResults` (`MAX_RESULTS` if not given), and where
/// to resume (`nextToken`: after the ID it carries).
fn page(query: &str) -> Result<(i64, String), Response<Full<Bytes>>> {
    let max = match query_param(query, "maxResults") {
        Some(text) => match text.parse::<i64>() {
            Ok(0) => MAX_RESULTS,
            Ok(n) if (1..=MAX_RESULTS).contains(&n) => n,
            _ => return Err(invalid(format!("maxResults must be between 0 and {MAX_RESULTS}."))),
        },
        None => MAX_RESULTS,
    };
    let after = match query_param(query, "nextToken") {
        Some(token) if !token.is_empty() => decode_continuation_token(&token).ok_or_else(|| invalid("The nextToken isn't valid."))?,
        _ => String::new(),
    };
    Ok((max, after))
}

/// The `<NextToken>` of a page of `max` from `ids` (one more than `max`,
/// if there are more).
fn next_token(ids: &[String], max: i64) -> String {
    match ids.len() as i64 > max {
        true => format!("<NextToken>{}</NextToken>", encode_continuation_token(&ids[max as usize - 1])),
        false => String::new(),
    }
}

async fn list_locations(ctx: &mut Ctx<'_>, query: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let (max, after) = or_answer!(page(query));
    let scope = query_param(query, "locationscope").filter(|s| !s.is_empty());
    if let Some(refused) = ctx.denied("s3:ListAccessGrantsLocations", ctx.instance_on(), &Context::default()) {
        return Ok(refused);
    }
    if instance(&ctx.client, &ctx.account).await?.is_none() {
        return Ok(no_instance());
    }
    let rows = ctx
        .client
        .query_cached(
            &format!(
                "SELECT {LOCATION_COLUMNS} FROM access_grants_locations WHERE account_id = $1 AND id > $2
                 AND ($3::text IS NULL OR scope = $3) ORDER BY id LIMIT $4"
            ),
            &[&ctx.account, &after, &scope, &(max + 1)],
        )
        .await?;
    let locations: Vec<Location> = rows.iter().map(Location::of).collect();
    let ids: Vec<String> = locations.iter().map(|l| l.id.clone()).collect();
    let list: String = locations
        .iter()
        .take(max as usize)
        .map(|l| format!("<AccessGrantsLocation>{}</AccessGrantsLocation>", l.xml(&ctx.account)))
        .collect();
    Ok(result(
        "ListAccessGrantsLocationsResult",
        &format!("{}<AccessGrantsLocationsList>{list}</AccessGrantsLocationsList>", next_token(&ids, max)),
    ))
}

async fn create_grant(ctx: &mut Ctx<'_>, body: Option<&Body<'_>>) -> anyhow::Result<Response<Full<Bytes>>> {
    let body = or_answer!(required(body));
    let location_id = or_answer!(field(body, "AccessGrantsLocationId"));
    let permission = or_answer!(field(body, "Permission"));
    let Some(permission) = Permission::parse(&permission) else {
        return Ok(invalid(format!("Permission {permission} isn't READ, WRITE or READWRITE.")));
    };
    if body.child("ApplicationArn").is_some() {
        return Ok(not_implemented("IAM Identity Center applications"));
    }
    let object = match body.text("S3PrefixType").as_deref() {
        None => false,
        Some("Object") => true,
        Some(other) => return Ok(invalid(format!("S3PrefixType {other} isn't Object."))),
    };
    let sub_prefix = match body.child("AccessGrantsLocationConfiguration") {
        Some(configuration) => child_text(configuration, "S3SubPrefix").filter(|s| !s.is_empty()),
        None => None,
    };
    if sub_prefix.as_ref().is_some_and(|s| s.chars().count() > 2000) {
        return Ok(invalid("S3SubPrefix is longer than 2000 characters."));
    }
    let Some(grantee) = body.child("Grantee") else {
        return Ok(invalid("Grantee is required."));
    };
    let grantee_type = child_text(grantee, "GranteeType").unwrap_or_default();
    let grantee = child_text(grantee, "GranteeIdentifier").unwrap_or_default();
    match grantee_type.as_str() {
        "IAM" => {}
        "DIRECTORY_USER" | "DIRECTORY_GROUP" => return Ok(not_implemented("IAM Identity Center's directory users and groups as grantees")),
        _ => return Ok(invalid("GranteeType must be IAM, DIRECTORY_USER or DIRECTORY_GROUP.")),
    }
    let tags = or_answer!(body.tags());
    let Some(location) = Location::load(&ctx.client, &ctx.account, &location_id).await? else {
        // Authorized as on its ARN, before it's told that there's none.
        if let Some(refused) = ctx.denied("s3:CreateAccessGrant", On::Arn(location_arn(&ctx.account, &location_id)), &Context::default()) {
            return Ok(refused);
        }
        return Ok(match instance(&ctx.client, &ctx.account).await? {
            Some(_) => no_location(),
            None => no_instance(),
        });
    };
    let scope = or_answer!(scope::grant_scope(&location.scope, sub_prefix.as_deref(), object).map_err(invalid));
    let mut extra = Context::default();
    extra.set("s3:AccessGrantScope", &scope);
    tags.set_context(&mut extra, "aws:RequestTag", Some("aws:TagKeys"));
    for on in [ctx.instance_on(), On::Arn(location_arn(&ctx.account, &location.id))] {
        if let Some(refused) = ctx.denied("s3:CreateAccessGrant", on, &extra) {
            return Ok(refused);
        }
    }
    if !principal_exists(&ctx.client, &ctx.account, &grantee).await? {
        return Ok(invalid(format!("The grantee {grantee} isn't an IAM user or role of this account, or another of the organization's.")));
    }
    let count: i64 = ctx
        .client
        .query_one_cached("SELECT count(*) FROM access_grants WHERE account_id = $1", &[&ctx.account])
        .await?
        .get(0);
    if count >= MAX_GRANTS {
        return Ok(conflict("TooManyAccessGrants", &format!("An Access Grants instance has at most {MAX_GRANTS} grants.")));
    }
    let id = uuid::Uuid::new_v4().to_string();
    let stored = Some(tags).filter(|t| !t.is_empty()).map(|t| t.stored());
    let row = ctx
        .client
        .query_opt_cached(
            &format!(
                "INSERT INTO access_grants (account_id, id, location_id, sub_prefix, object, grantee_type, grantee, permission, scope, tags)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT DO NOTHING RETURNING {GRANT_COLUMNS}"
            ),
            &[&ctx.account, &id, &location.id, &sub_prefix, &object, &grantee_type, &grantee, &permission.as_str(), &scope, &stored],
        )
        .await;
    Ok(match row {
        Ok(Some(row)) => result("CreateAccessGrantResult", &Grant::of(&row).xml(&ctx.account)),
        Ok(None) => conflict("AccessGrantAlreadyExists", "Access Grant already exists"),
        Err(e) if gone(&e) => no_location(),
        Err(e) => return Err(e.into()),
    })
}

async fn list_grants(ctx: &mut Ctx<'_>, query: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let (max, after) = or_answer!(page(query));
    let param = |name| query_param(query, name).filter(|v| !v.is_empty());
    let (grantee_type, grantee, permission, scope) = (param("granteetype"), param("granteeidentifier"), param("permission"), param("grantscope"));
    if let Some(permission) = &permission
        && Permission::parse(permission).is_none()
    {
        return Ok(invalid(format!("Permission {permission} isn't READ, WRITE or READWRITE.")));
    }
    if let Some(refused) = ctx.denied("s3:ListAccessGrants", ctx.instance_on(), &Context::default()) {
        return Ok(refused);
    }
    if instance(&ctx.client, &ctx.account).await?.is_none() {
        return Ok(no_instance());
    }
    // No grant is an application's.
    let rows = match param("application_arn") {
        Some(_) => Vec::new(),
        None => {
            ctx.client
                .query_cached(
                    &format!(
                        "SELECT {GRANT_COLUMNS} FROM access_grants WHERE account_id = $1 AND id > $2
                         AND ($3::text IS NULL OR grantee_type = $3) AND ($4::text IS NULL OR grantee = $4)
                         AND ($5::text IS NULL OR permission = $5) AND ($6::text IS NULL OR scope = $6)
                         ORDER BY id LIMIT $7"
                    ),
                    &[&ctx.account, &after, &grantee_type, &grantee, &permission, &scope, &(max + 1)],
                )
                .await?
        }
    };
    let grants: Vec<Grant> = rows.iter().map(Grant::of).collect();
    let ids: Vec<String> = grants.iter().map(|g| g.id.clone()).collect();
    let list: String = grants.iter().take(max as usize).map(|g| format!("<AccessGrant>{}</AccessGrant>", g.xml(&ctx.account))).collect();
    Ok(result("ListAccessGrantsResult", &format!("{}<AccessGrantsList>{list}</AccessGrantsList>", next_token(&ids, max))))
}

/// The IAM grantee a principal is: a user's ARN, or a role session's
/// role's; a federated user, or the root user, is none.
fn grantee_of(principal: &Principal) -> Option<String> {
    match principal.session.as_ref().map(|s| &s.session.who) {
        Some(Who::Federated { .. } | Who::Root { .. }) => None,
        _ => Some(principal.principal_arn()),
    }
}

/// `grantee`'s grants (IAM), with their locations' roles, by ID.
async fn grants_of(client: &Object, account: &str, grantee: &str) -> anyhow::Result<Vec<(Grant, String)>> {
    let rows = client
        .query_cached(
            "SELECT g.id, g.location_id, g.sub_prefix, g.object, g.grantee_type, g.grantee, g.permission, g.scope,
                    extract(epoch FROM g.created_at)::bigint, l.role_arn
             FROM access_grants g JOIN access_grants_locations l ON l.account_id = g.account_id AND l.id = g.location_id
             WHERE g.account_id = $1 AND g.grantee_type = 'IAM' AND g.grantee = $2 ORDER BY g.id",
            &[&account, &grantee],
        )
        .await?;
    Ok(rows.iter().map(|row| (Grant::of(row), row.get(9))).collect())
}

async fn list_caller_grants(ctx: &mut Ctx<'_>, query: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let (max, after) = or_answer!(page(query));
    let within = match query_param(query, "grantscope").filter(|s| !s.is_empty()) {
        Some(scope) => Some(or_answer!(scope::target_covers(&scope, false).map_err(invalid))),
        None => None,
    };
    if let Some(refused) = ctx.denied("s3:ListCallerAccessGrants", ctx.instance_on(), &Context::default()) {
        return Ok(refused);
    }
    if instance(&ctx.client, &ctx.account).await?.is_none() {
        return Ok(no_instance());
    }
    let grants = match grantee_of(ctx.principal) {
        Some(grantee) => grants_of(&ctx.client, &ctx.account, &grantee).await?,
        None => Vec::new(),
    };
    let grants: Vec<Grant> = grants
        .into_iter()
        .map(|(grant, _)| grant)
        .filter(|g| g.id > after)
        .filter(|g| within.as_ref().is_none_or(|w| w.overlaps(&g.covers())))
        .take(max as usize + 1)
        .collect();
    let ids: Vec<String> = grants.iter().map(|g| g.id.clone()).collect();
    let instance = instance_arn(&ctx.account);
    let list: String = grants
        .iter()
        .take(max as usize)
        .map(|g| {
            format!(
                "<AccessGrant><Permission>{}</Permission><GrantScope>{}</GrantScope><AccessGrantsInstanceArn>{instance}</AccessGrantsInstanceArn></AccessGrant>",
                g.permission.as_str(),
                xml_escape(&g.scope)
            )
        })
        .collect();
    Ok(result(
        "ListCallerAccessGrantsResult",
        &format!("{}<CallerAccessGrantsList>{list}</CallerAccessGrantsList>", next_token(&ids, max)),
    ))
}

/// The grant of `grants` that gives `permission` on `target`, if one does:
/// the one whose scope is the narrowest, and of those, one of exactly
/// that permission.
pub fn matching<'g, T>(grants: &'g [(Grant, T)], target: &Covered, permission: Permission) -> Option<&'g (Grant, T)> {
    grants
        .iter()
        .filter(|(g, _)| g.permission.covers(permission) && g.covers().covers(target))
        .max_by_key(|(g, _)| (g.covers().path.len(), g.covers().object, g.permission == permission))
}

/// A session's name, from its caller's unique ID: of the characters STS
/// takes in one.
fn session_name(principal: &Principal) -> String {
    let name: String = principal
        .unique_id()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || "+=,.@_-".contains(c) { c } else { '.' })
        .take(64)
        .collect();
    name
}

async fn get_data_access(ctx: &mut Ctx<'_>, query: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let Some(target) = query_param(query, "target").filter(|t| !t.is_empty()) else {
        return Ok(invalid("target is required."));
    };
    let Some(asked) = query_param(query, "permission") else {
        return Ok(invalid("permission is required."));
    };
    let Some(permission) = Permission::parse(&asked) else {
        return Ok(invalid(format!("Permission {asked} isn't READ, WRITE or READWRITE.")));
    };
    let object = match query_param(query, "targetType").as_deref() {
        None | Some("") => false,
        Some("Object") => true,
        Some(other) => return Ok(invalid(format!("targetType {other} isn't Object."))),
    };
    let minimal = match query_param(query, "privilege").as_deref() {
        None | Some("" | "Default") => false,
        Some("Minimal") => true,
        Some(other) => return Ok(invalid(format!("privilege {other} isn't Minimal or Default."))),
    };
    if let Some(scope) = query_param(query, "instanceScope")
        && !matches!(scope.as_str(), "" | "SELF" | "ALL")
    {
        return Ok(invalid(format!("instanceScope {scope} isn't SELF or ALL.")));
    }
    let seconds = match query_param(query, "durationSeconds") {
        Some(text) => match text.parse::<i64>() {
            Ok(n) if DURATIONS.contains(&n) => Some(n),
            _ => return Ok(invalid(format!("durationSeconds must be between {} and {}.", DURATIONS.start(), DURATIONS.end()))),
        },
        None => None,
    };
    let covered = or_answer!(scope::target_covers(&target, object).map_err(invalid));
    if let Some(refused) = ctx.denied("s3:GetDataAccess", ctx.instance_on(), &Context::default()) {
        return Ok(refused);
    }
    if instance(&ctx.client, &ctx.account).await?.is_none() {
        return Ok(no_instance());
    }
    let grants = match grantee_of(ctx.principal) {
        Some(grantee) => grants_of(&ctx.client, &ctx.account, &grantee).await?,
        None => Vec::new(),
    };
    let Some((grant, role_arn)) = matching(&grants, &covered, permission) else {
        return Ok(format_s3_error(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            &format!("You don't have {} permission to the requested S3 prefix: {target}", permission.as_str()),
        ));
    };
    // The location's role, which Access Grants must be trusted to assume.
    let assumed = match role_named(&ctx.client, &ctx.account, role_arn).await? {
        Some(role) if trusts_access_grants(&role, &ctx.account)? => Ok(role),
        Some(_) => Err(format!("The IAM role {role_arn} of the grant's location doesn't trust {SERVICE} (sts:AssumeRole).")),
        None => Err(format!("The IAM role {role_arn} of the grant's location doesn't exist.")),
    };
    let role = match assumed {
        Ok(role) => role,
        Err(why) => return Ok(format_s3_error(StatusCode::FORBIDDEN, "AccessDenied", &why)),
    };
    let max = role.max_session_duration as i64;
    let seconds = seconds.unwrap_or(DEFAULT_DURATION.min(max));
    if seconds > max {
        return Ok(invalid(format!("durationSeconds {seconds} exceeds the MaxSessionDuration of the location's role ({max}).")));
    }
    let scoped = match minimal {
        true => covered,
        false => grant.covers(),
    };
    let policy = scope::session_policy(&scoped, permission);
    let policy = Policy::parse(&policy, Kind::Identity)
        .map_err(|e| anyhow::anyhow!("a vended session's policy doesn't parse: {}", e.message))?
        .normalized()
        .to_owned();
    let now = sessions::now();
    let instance = instance_arn(&ctx.account);
    let mut session = Session {
        key_id: sessions::new_key_id()?,
        secret: String::new(),
        issued: now,
        expires: now + seconds as u64,
        who: Who::Role { id: role.id, session: session_name(ctx.principal) },
        policy: Some(policy),
        policy_arns: Vec::new(),
        tags: Vec::new(),
        transitive: Vec::new(),
        source_identity: None,
        chained: false,
        provider: None,
        directory: None,
        access_grants: Some(instance.clone()),
    };
    let token = ctx.app.sessions.seal(&ctx.client, &mut session).await?;
    Ok(result(
        "GetDataAccessResult",
        &format!(
            "<Credentials><AccessKeyId>{}</AccessKeyId><SecretAccessKey>{}</SecretAccessKey><SessionToken>{}</SessionToken>\
             <Expiration>{}</Expiration></Credentials><MatchedGrantTarget>{}</MatchedGrantTarget>{}\
             <MatchedInstanceArn>{instance}</MatchedInstanceArn>",
            session.key_id,
            xml_escape(&session.secret),
            xml_escape(&token),
            sessions::iso(session.expires),
            xml_escape(&grant.scope),
            grant.grantee_xml(),
        ),
    ))
}

/// The table and key of `account`'s `resource`, whose tags are kept there.
fn tagged(resource: &Resource) -> (&'static str, &str) {
    match resource {
        Resource::Instance => ("access_grants_instances", ""),
        Resource::Location(id) => ("access_grants_locations", id),
        Resource::Grant(id) => ("access_grants", id),
    }
}

/// `resource`'s tags, as stored, or `None` if there's no such resource.
async fn stored(client: &Object, account: &str, resource: &Resource) -> anyhow::Result<Option<Option<String>>> {
    let (table, id) = tagged(resource);
    let sql = match resource {
        Resource::Instance => format!("SELECT tags FROM {table} WHERE account_id = $1 AND $2 = ''"),
        _ => format!("SELECT tags FROM {table} WHERE account_id = $1 AND id = $2"),
    };
    Ok(client.query_opt(&sql, &[&account, &id]).await?.map(|row| row.get(0)))
}

/// S3 Control's ListTagsForResource, TagResource and UntagResource on an
/// Access Grants resource of `account`, which `resource_tags` routes here,
/// with `change` (none: listing) its parsed request: as on a bucket's.
pub async fn tag_resource(
    app: &App,
    access: &Access,
    account: &str,
    arn: &str,
    resource: &Resource,
    action: &'static str,
    change: Option<crate::s3::buckets::resource_tags::Change>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    use crate::s3::buckets::resource_tags::Change;
    let client = app.pool.get().await?;
    let check = Check { action, on: On::Arn(arn.to_owned()) };
    let verdict = access.verdict(&check);
    if verdict != crate::policy::Verdict::Allow {
        return Ok(access.denied(&check, verdict));
    }
    let missing = || format_s3_error(StatusCode::NOT_FOUND, "NoSuchResource", "The specified resource doesn't exist.");
    let Some(old) = stored(&client, account, resource).await? else { return Ok(missing()) };
    let current = stored_tags(old.as_deref());
    let new = match change {
        None => {
            let tags: String = current
                .iter()
                .map(|(k, v)| format!("<Tag><Key>{}</Key><Value>{}</Value></Tag>", xml_escape(k), xml_escape(v)))
                .collect();
            return Ok(result("ListTagsForResourceResult", &format!("<Tags>{tags}</Tags>")));
        }
        Some(Change::Add(tags)) => current.merged(&tags),
        Some(Change::Remove(keys)) => current.without(&keys),
    };
    if let Some(refused) = new.too_many() {
        return Ok(refused);
    }
    let new = Some(new).filter(|t| !t.is_empty()).map(|t| t.stored());
    // Only if they're as they were read: else another change came first,
    // which this one is made on top of.
    let (table, id) = tagged(resource);
    let sql = match resource {
        Resource::Instance => format!("UPDATE {table} SET tags = $3 WHERE account_id = $1 AND $2 = '' AND tags IS NOT DISTINCT FROM $4"),
        _ => format!("UPDATE {table} SET tags = $3 WHERE account_id = $1 AND id = $2 AND tags IS NOT DISTINCT FROM $4"),
    };
    match client.execute(&sql, &[&account, &id, &new, &old]).await? {
        0 => Err(crate::Contended(format!("the tags of {arn} changed meanwhile")).into()),
        _ => Ok(no_content()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_s3_controls_paths() {
        assert_eq!(route(&Method::POST, ROOT), Ok(Op::CreateInstance));
        assert_eq!(route(&Method::GET, INSTANCES), Ok(Op::ListInstances));
        assert_eq!(route(&Method::GET, "/v20180820/accessgrantsinstance/location/default"), Ok(Op::GetLocation("default".into())));
        assert_eq!(route(&Method::PUT, "/v20180820/accessgrantsinstance/location/a-b"), Ok(Op::UpdateLocation("a-b".into())));
        assert_eq!(route(&Method::DELETE, "/v20180820/accessgrantsinstance/grant/x"), Ok(Op::DeleteGrant("x".into())));
        assert_eq!(route(&Method::GET, "/v20180820/accessgrantsinstance/dataaccess"), Ok(Op::GetDataAccess));
        assert_eq!(route(&Method::GET, "/v20180820/accessgrantsinstance/caller/grants"), Ok(Op::ListCallerGrants));
        assert_eq!(route(&Method::PUT, "/v20180820/accessgrantsinstance/grant/x"), Err(true));
        assert_eq!(route(&Method::PUT, "/v20180820/accessgrantsinstance/grants"), Err(true));
        assert_eq!(route(&Method::GET, "/v20180820/accessgrantsinstance/nothing"), Err(false));
        assert_eq!(route(&Method::PUT, "/v20180820/accessgrantsinstance/resourcepolicy"), Ok(Op::PutPolicy));
    }

    #[test]
    fn names_resources_by_their_arns() {
        let account = "123456789012";
        assert_eq!(resource_of(&instance_arn(account)), Some((account.to_owned(), Resource::Instance)));
        assert_eq!(resource_of(&location_arn(account, "default")), Some((account.to_owned(), Resource::Location("default".into()))));
        assert_eq!(resource_of(&grant_arn(account, "a-1")), Some((account.to_owned(), Resource::Grant("a-1".into()))));
        assert_eq!(resource_of("arn:aws:s3:::bucket"), None);
        assert_eq!(resource_of(&format!("{}/grant/", instance_arn(account))), None);
        assert_eq!(resource_of(&format!("{}/other/x", instance_arn(account))), None);
    }

    fn grant(id: &str, scope: &str, object: bool, permission: Permission) -> (Grant, ()) {
        let grant = Grant {
            id: id.into(),
            location_id: "default".into(),
            sub_prefix: None,
            object,
            grantee_type: "IAM".into(),
            grantee: "arn:aws:iam::123456789012:user/u".into(),
            permission,
            scope: scope.into(),
            created: 0,
        };
        (grant, ())
    }

    #[test]
    fn the_narrowest_grant_matches() {
        let grants = vec![
            grant("all", "s3://b/*", false, Permission::Read),
            grant("logs", "s3://b/logs/*", false, Permission::ReadWrite),
            grant("logs-read", "s3://b/logs/*", false, Permission::Read),
            grant("one", "s3://b/logs/x", true, Permission::Write),
        ];
        let target = |t: &str, object| scope::target_covers(t, object).unwrap();
        let id = |t: &Covered, p| matching(&grants, t, p).map(|(g, _)| g.id.as_str());
        assert_eq!(id(&target("s3://b/logs/2026/*", false), Permission::Read), Some("logs-read"));
        assert_eq!(id(&target("s3://b/logs/2026/*", false), Permission::Write), Some("logs"));
        assert_eq!(id(&target("s3://b/logs/x", true), Permission::Write), Some("one"));
        assert_eq!(id(&target("s3://b/other/*", false), Permission::Read), Some("all"));
        assert_eq!(id(&target("s3://b/other/*", false), Permission::Write), None);
        assert_eq!(id(&target("s3://c/*", false), Permission::Read), None);
    }
}
