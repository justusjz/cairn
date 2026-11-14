//! The IAM API, and STS's GetCallerIdentity, on the S3 port: requests
//! signed for the `iam` or `sts` service (SigV4's credential scope) are
//! these, whatever their path. So `aws iam ...`, Terraform's `aws_iam_*`
//! resources and SDKs manage an account's users, their access keys and
//! policies, pointed at Cairn's endpoint for IAM (the same as for S3).
//!
//! The query protocol, as AWS's (botocore's `iam/2010-05-08` and
//! `sts/2011-06-15` models): a form-encoded `Action` and its parameters, in
//! the body (or the query), answered in XML, errors as `<ErrorResponse>`.
//! Each request acts as its signer, in its account: every action is checked
//! as IAM's own (`iam:CreateUser` on the user's ARN, ...), by the same
//! policies as S3 requests (see `s3::access`), so an admin
//! (`AdministratorAccess`) may do all of it in its account, and a user what
//! its policies allow (its own keys, say). Another account's users are none.
//!
//! What's there: users, with paths, tags and permissions boundaries (see
//! `plans/boundaries.md`, probed), access keys, inline policies, and managed
//! policies (see `managed`): Cairn's, which have AWS's names, and an
//! account's own, with paths and tags, of which Cairn keeps one version,
//! the default; and roles (see `roles`, `plans/roles.md`). Groups aren't
//! (NotImplemented).

mod roles;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode, body::Bytes};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

use crate::{
    App,
    auth::Signed,
    managed::{self, Named},
    db::Cached,
    policy::{Context, Verdict},
    users::{self, Principal, Target},
    s3::{
        access::{Access, Origin},
        actions::{Check, On},
        util::{decode_path_param, xml_escape},
    },
};

const IAM_XMLNS: &str = "https://iam.amazonaws.com/doc/2010-05-08/";
const STS_XMLNS: &str = "https://sts.amazonaws.com/doc/2011-06-15/";

/// The most a request's body may hold: a policy (at most a few KiB), encoded.
const MAX_BODY: usize = 64 << 10;

/// Whether a request signed so is IAM's or STS's.
pub fn wants(signed: &Signed) -> bool {
    matches!(signed.service.as_str(), "iam" | "sts")
}

/// A failed request: its status, code and message.
struct Error {
    status: StatusCode,
    code: &'static str,
    message: String,
}

fn error(status: StatusCode, code: &'static str, message: impl Into<String>) -> Error {
    Error { status, code, message: message.into() }
}

fn no_such_user(name: &str) -> Error {
    error(StatusCode::NOT_FOUND, "NoSuchEntity", format!("The user with name {name} cannot be found."))
}

fn invalid(message: impl Into<String>) -> Error {
    error(StatusCode::BAD_REQUEST, "InvalidInput", message)
}

fn validation(message: impl Into<String>) -> Error {
    error(StatusCode::BAD_REQUEST, "ValidationError", message)
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Error {
        use crate::managed::Refused;
        let e = match e.downcast::<Refused>() {
            Ok(Refused::NoSuch(m)) => return error(StatusCode::NOT_FOUND, "NoSuchEntity", m),
            Ok(Refused::Exists(m)) => return error(StatusCode::CONFLICT, "EntityAlreadyExists", m),
            Ok(Refused::Conflict(m)) => return error(StatusCode::CONFLICT, "DeleteConflict", m),
            Ok(Refused::Limit(m)) => return error(StatusCode::CONFLICT, "LimitExceeded", m),
            Ok(Refused::Malformed(m)) => return error(StatusCode::BAD_REQUEST, "MalformedPolicyDocument", m),
            Ok(Refused::Invalid(m)) => return invalid(m),
            Ok(Refused::Validation(m)) => return validation(m),
            Ok(Refused::Unsupported(m)) => return error(StatusCode::NOT_IMPLEMENTED, "NotImplemented", m),
            Err(e) => e,
        };
        let e = match e.downcast::<users::TooManyTags>() {
            Ok(too_many) => return error(StatusCode::CONFLICT, "LimitExceeded", too_many.to_string()),
            Err(e) => e,
        };
        match e.downcast::<users::Invalid>() {
            Ok(invalid) => self::invalid(invalid.0),
            Err(e) => {
                eprintln!("iam: request failed: {e:#}");
                error(StatusCode::INTERNAL_SERVER_ERROR, "ServiceFailure", "internal error; the node's log has the details")
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

type Result<T> = std::result::Result<T, Error>;

/// A request's parameters, form-decoded.
struct Params(HashMap<String, String>);

impl Params {
    /// Adds `text`'s parameters to `into`. A parameter given twice (in the
    /// query and the body, say) is refused, rather than one overriding the
    /// other: the query's may be all a signature covers.
    fn parse(text: &str, into: &mut HashMap<String, String>) -> Result<()> {
        for pair in text.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let decode = |s: &str| decode_path_param(&s.replace('+', " "));
            let name = decode(k);
            if into.contains_key(&name) {
                return Err(error(StatusCode::BAD_REQUEST, "MalformedQueryString", format!("the parameter {name} is given more than once")));
            }
            into.insert(name, decode(v));
        }
        Ok(())
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    fn required(&self, name: &str) -> Result<&str> {
        self.get(name).ok_or_else(|| {
            validation(format!("1 validation error detected: Value null at '{}' failed to satisfy constraint: Member must not be null", lower_first(name)))
        })
    }

    /// Whether any parameter starts with `prefix` (a list's members:
    /// `Tags.member.1.Key`, ...).
    fn has_list(&self, prefix: &str) -> bool {
        self.0.keys().any(|k| k.starts_with(prefix))
    }
}

fn lower_first(name: &str) -> String {
    let mut chars = name.chars();
    chars.next().map(|c| c.to_ascii_lowercase().to_string() + chars.as_str()).unwrap_or_default()
}

/// An IAM or STS request, on the S3 port.
pub async fn handle(app: &Arc<App>, req: Request<crate::listen::ClientBody>, signed: Signed, peer: IpAddr) -> Response<Full<Bytes>> {
    let sts = signed.service == "sts";
    let request_id = uuid::Uuid::new_v4().to_string();
    let result = respond(app, req, &signed, peer, &request_id).await;
    let xmlns = if sts { STS_XMLNS } else { IAM_XMLNS };
    let (status, body) = match result {
        Ok((action, inner)) => {
            let result = inner.map(|inner| format!("<{action}Result>{inner}</{action}Result>")).unwrap_or_default();
            (
                StatusCode::OK,
                format!(
                    "<{action}Response xmlns=\"{xmlns}\">{result}<ResponseMetadata><RequestId>{request_id}</RequestId>\
                     </ResponseMetadata></{action}Response>"
                ),
            )
        }
        Err(e) => {
            let kind = if e.status.is_server_error() { "Receiver" } else { "Sender" };
            (
                e.status,
                format!(
                    "<ErrorResponse xmlns=\"{xmlns}\"><Error><Type>{kind}</Type><Code>{}</Code><Message>{}</Message>\
                     </Error><RequestId>{request_id}</RequestId></ErrorResponse>",
                    e.code,
                    xml_escape(&e.message)
                ),
            )
        }
    };
    Response::builder()
        .status(status)
        .header("content-type", "text/xml")
        .header("x-amzn-requestid", &request_id)
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// What a request's action answers: its name, and its result's elements.
type Answer = (String, Option<String>);

async fn respond(
    app: &Arc<App>,
    req: Request<crate::listen::ClientBody>,
    signed: &Signed,
    peer: IpAddr,
    _request_id: &str,
) -> Result<Answer> {
    let (parts, body) = req.into_parts();
    let body = Limited::new(body, MAX_BODY)
        .collect()
        .await
        .map_err(|_| error(StatusCode::BAD_REQUEST, "MalformedQueryString", "the request's body is too large, or broken"))?
        .to_bytes();
    let query = parts.uri.query().unwrap_or("");
    let client = app.pool.get().await?;
    let invalid_token = || error(StatusCode::FORBIDDEN, "InvalidClientTokenId", "The security token included in the request is invalid.");
    let principal = Principal::load(&client, &signed.access_key).await?.ok_or_else(invalid_token)?;
    crate::auth::verify_sigv4_with_body(parts.method.as_str(), parts.uri.path(), query, &parts.headers, &principal.secret, &body)
        .map_err(|r| error(r.status, if r.code == "SignatureDoesNotMatch" { "SignatureDoesNotMatch" } else { "AccessDenied" }, r.message))?;
    let mut params = HashMap::new();
    Params::parse(query, &mut params)?;
    if !body.is_empty() {
        let text = std::str::from_utf8(&body).map_err(|_| error(StatusCode::BAD_REQUEST, "MalformedQueryString", "the request's body isn't UTF-8"))?;
        Params::parse(text, &mut params)?;
    }
    let params = Params(params);
    let action = params.required("Action")?.to_owned();
    let origin = Origin { peer: Some(peer), trusted_proxies: &app.trusted_proxies, signed: Some(signed), form: false };
    let mut access = Access::new(Some(&principal), &principal.account, &parts.method, &parts.headers, "", &origin)?;
    let mut iam = Iam { app, client: &client, principal: &principal, access: &mut access };
    let inner = match (signed.service.as_str(), action.as_str()) {
        ("sts", "GetCallerIdentity") => Some(format!(
            "<Arn>{}</Arn><UserId>{}</UserId><Account>{}</Account>",
            xml_escape(&principal.arn()),
            user_id(principal.id),
            principal.account
        )),
        ("sts", other) => return Err(error(StatusCode::BAD_REQUEST, "InvalidAction", format!("Cairn's STS has no action {other}"))),
        (_, "GetUser") => iam.get_user(&params).await?,
        (_, "ListUsers") => iam.list_users(&params).await?,
        (_, "CreateUser") => iam.create_user(&params).await?,
        (_, "DeleteUser") => iam.delete_user(&params).await?,
        (_, "UpdateUser") => iam.update_user(&params).await?,
        (_, "PutUserPermissionsBoundary") => iam.put_user_permissions_boundary(&params).await?,
        (_, "DeleteUserPermissionsBoundary") => iam.delete_user_permissions_boundary(&params).await?,
        (_, "TagUser") => iam.tag_user(&params).await?,
        (_, "UntagUser") => iam.untag_user(&params).await?,
        (_, "ListUserTags") => iam.list_user_tags(&params).await?,
        (_, "CreateAccessKey") => iam.create_access_key(&params).await?,
        (_, "ListAccessKeys") => iam.list_access_keys(&params).await?,
        (_, "UpdateAccessKey") => iam.update_access_key(&params).await?,
        (_, "DeleteAccessKey") => iam.delete_access_key(&params).await?,
        (_, "PutUserPolicy") => iam.put_user_policy(&params).await?,
        (_, "GetUserPolicy") => iam.get_user_policy(&params).await?,
        (_, "ListUserPolicies") => iam.list_user_policies(&params).await?,
        (_, "DeleteUserPolicy") => iam.delete_user_policy(&params).await?,
        (_, "AttachUserPolicy") => iam.attach_user_policy(&params, true).await?,
        (_, "DetachUserPolicy") => iam.attach_user_policy(&params, false).await?,
        (_, "ListAttachedUserPolicies") => iam.list_attached_user_policies(&params).await?,
        (_, "CreatePolicy") => iam.create_policy(&params).await?,
        (_, "GetPolicy") => iam.get_policy(&params).await?,
        (_, "DeletePolicy") => iam.delete_policy(&params).await?,
        (_, "ListPolicies") => iam.list_policies(&params).await?,
        (_, "GetPolicyVersion") => iam.get_policy_version(&params).await?,
        (_, "CreatePolicyVersion") => iam.create_policy_version(&params).await?,
        (_, "ListPolicyVersions") => iam.list_policy_versions(&params).await?,
        (_, "DeletePolicyVersion") => iam.delete_policy_version(&params).await?,
        (_, "SetDefaultPolicyVersion") => iam.set_default_policy_version(&params).await?,
        (_, "ListEntitiesForPolicy") => iam.list_entities_for_policy(&params).await?,
        (_, "TagPolicy") => iam.tag_policy(&params).await?,
        (_, "UntagPolicy") => iam.untag_policy(&params).await?,
        (_, "ListPolicyTags") => iam.list_policy_tags(&params).await?,
        (_, "CreateRole") => iam.create_role(&params).await?,
        (_, "GetRole") => iam.get_role(&params).await?,
        (_, "ListRoles") => iam.list_roles(&params).await?,
        (_, "UpdateRole") => iam.update_role(&params).await?,
        (_, "UpdateRoleDescription") => iam.update_role_description(&params).await?,
        (_, "UpdateAssumeRolePolicy") => iam.update_assume_role_policy(&params).await?,
        (_, "DeleteRole") => iam.delete_role(&params).await?,
        (_, "PutRolePermissionsBoundary") => iam.put_role_permissions_boundary(&params).await?,
        (_, "DeleteRolePermissionsBoundary") => iam.delete_role_permissions_boundary(&params).await?,
        (_, "TagRole") => iam.tag_role(&params).await?,
        (_, "UntagRole") => iam.untag_role(&params).await?,
        (_, "ListRoleTags") => iam.list_role_tags(&params).await?,
        (_, "PutRolePolicy") => iam.put_role_policy(&params).await?,
        (_, "GetRolePolicy") => iam.get_role_policy(&params).await?,
        (_, "ListRolePolicies") => iam.list_role_policies(&params).await?,
        (_, "DeleteRolePolicy") => iam.delete_role_policy(&params).await?,
        (_, "AttachRolePolicy") => iam.attach_role_policy(&params, true).await?,
        (_, "DetachRolePolicy") => iam.attach_role_policy(&params, false).await?,
        (_, "ListAttachedRolePolicies") => iam.list_attached_role_policies(&params).await?,
        (_, other) => {
            return Err(error(
                StatusCode::NOT_IMPLEMENTED,
                "NotImplemented",
                format!("Cairn's IAM has users and roles (with paths, tags and permissions boundaries), access keys, inline and managed policies; not {other}"),
            ));
        }
    };
    Ok((action, inner))
}

/// A user's ID as IAM shows one (`AIDA`, then 17 characters), from its
/// Cairn ID, which never changes or comes back.
fn user_id(id: uuid::Uuid) -> String {
    users::unique_id("AIDA", id)
}

/// An ISO 8601 time from SQL (see `ISO`).
const ISO: &str = "to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')";

/// A request's actions, as its signer, in its account.
struct Iam<'a> {
    app: &'a Arc<App>,
    client: &'a deadpool_postgres::Object,
    principal: &'a Principal,
    access: &'a mut Access,
}

/// What a 403 says the resource was: a user that exists by its name (`user
/// NAME`), anything else by its ARN (probed).
enum Shown {
    Arn,
    User(String),
    /// A role, by its name (`role NAME`: probed).
    Role(String),
    /// A policy, by its ARN, or (one to make) its name.
    Policy(String),
}

/// Whose tags a request sets, which IAM checks differently (probed).
#[derive(Clone, Copy, PartialEq)]
enum Tagged {
    /// A user's: keys unique regardless of case.
    User,
    /// A policy's: keys case-sensitive.
    Policy,
}

/// The tags a request sets (`Tags.member.N.Key` and `.Value`), checked as
/// IAM checks them (probed): at most 50, keys of 1 to 128 characters, values
/// of at most 256, of letters, digits, spaces and `_.:/=+-@`, no `aws:` keys,
/// no key twice (a user's: regardless of case). `None` if it sets none; an
/// error if it must (`required`: a TagUser or TagPolicy).
fn request_tags(params: &Params, required: bool, of: Tagged) -> Result<Option<Vec<(String, String)>>> {
    let mut tags = Vec::new();
    for n in 1.. {
        let key = params.get(&format!("Tags.member.{n}.Key"));
        let value = params.get(&format!("Tags.member.{n}.Value"));
        if key.is_none() && value.is_none() {
            break;
        }
        tags.push((key.unwrap_or("").to_owned(), value.unwrap_or("").to_owned()));
    }
    if tags.is_empty() {
        return match (required, of) {
            (true, Tagged::Policy) => Err(invalid("The provided tag map must not be null/empty.")),
            (true, Tagged::User) if params.has_list("Tags") => Err(invalid("Error occurred while validating input. ")),
            (true, Tagged::User) => params.required("Tags").map(|_| None),
            (false, _) => Ok(None),
        };
    }
    if tags.len() > MAX_TAGS {
        return Err(validation(format!(
            "1 validation error detected: Value at 'tags' failed to satisfy constraint: Member must have length less than or equal to {MAX_TAGS}"
        )));
    }
    let mut errors = Vec::new();
    for (i, (key, value)) in tags.iter().enumerate() {
        let at = |what: &str| format!("Value at 'tags.{}.member.{what}' failed to satisfy constraint: Member must", i + 1);
        errors.extend(tag_errors(key, &at("key"), 1, 128));
        errors.extend(tag_errors(value, &at("value"), 0, 256));
    }
    if !errors.is_empty() {
        return Err(validation(validation_errors(&errors)));
    }
    if tags.iter().any(|(key, _)| key.to_ascii_lowercase().starts_with("aws:")) {
        return Err(invalid("Tag keys beginning with aws: are reserved for system use."));
    }
    let mut seen = std::collections::HashSet::new();
    let fold = |key: &str| if of == Tagged::User { key.to_lowercase() } else { key.to_owned() };
    if !tags.iter().all(|(key, _)| seen.insert(fold(key))) {
        return Err(invalid("Duplicate tag keys found. Please note that Tag keys are case insensitive."));
    }
    Ok(Some(tags))
}

use users::MAX_TAGS;

/// What's wrong with a tag's key or value (`text`), as IAM's validation
/// errors say it (`at`: where, and "Member must"): its length (`min` to
/// `max` characters), and its characters.
fn tag_errors(text: &str, at: &str, min: usize, max: usize) -> Vec<String> {
    let mut errors = Vec::new();
    let length = text.chars().count();
    if length < min {
        errors.push(format!("{at} have length greater than or equal to {min}"));
    }
    if length > max {
        errors.push(format!("{at} have length less than or equal to {max}"));
    }
    let fine = users::tag_char;
    let pattern = if min > 0 { "+" } else { "*" };
    if (min > 0 && text.is_empty()) || !text.chars().all(fine) {
        errors.push(format!("{at} satisfy regular expression pattern: [\\p{{L}}\\p{{Z}}\\p{{N}}_.:/=+\\-@]{pattern}"));
    }
    errors
}

/// Validation errors, as IAM lists them.
fn validation_errors(errors: &[String]) -> String {
    let s = if errors.len() == 1 { "" } else { "s" };
    format!("{} validation error{s} detected: {}", errors.len(), errors.join("; "))
}

/// The keys a request names (`TagKeys.member.N`).
fn request_keys(params: &Params) -> Result<Vec<String>> {
    let keys: Vec<String> = (1..).map_while(|n| params.get(&format!("TagKeys.member.{n}")).map(str::to_owned)).collect();
    if keys.is_empty() {
        params.required("TagKeys")?;
    }
    if keys.len() > MAX_TAGS {
        return Err(validation(format!(
            "1 validation error detected: Value at 'tagKeys' failed to satisfy constraint: Member must have length less than or equal to {MAX_TAGS}"
        )));
    }
    let mut errors = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        let at = format!("Value at 'tagKeys.{}.member' failed to satisfy constraint: Member must", i + 1);
        errors.extend(tag_errors(key, &at, 1, 128));
    }
    if !errors.is_empty() {
        return Err(validation(validation_errors(&errors)));
    }
    Ok(keys)
}

use users::request_tags_context as tags_context;

/// Tags as IAM writes them, in `element`.
fn tags_xml(element: &str, tags: &[(String, String)]) -> String {
    let members: String = tags
        .iter()
        .map(|(k, v)| format!("<member><Key>{}</Key><Value>{}</Value></member>", xml_escape(k), xml_escape(v)))
        .collect();
    format!("<{element}>{members}</{element}>")
}

/// A requested permissions boundary (`PermissionsBoundary`), checked as IAM
/// checks its length (probed): the ARN, or `None`.
fn requested_boundary(params: &Params) -> Result<Option<String>> {
    match params.get("PermissionsBoundary") {
        None => Ok(None),
        Some(arn) if arn.len() < 20 || arn.len() > 2048 => {
            let (bound, n) = if arn.len() < 20 { ("greater", 20) } else { ("less", 2048) };
            Err(validation(format!(
                "1 validation error detected: Value at 'permissionsBoundary' failed to satisfy constraint: Member must have length {bound} than or equal to {n}"
            )))
        }
        Some(arn) => Ok(Some(arn.to_owned())),
    }
}

/// A path a request gives as `param` (`Path`, ...), checked; `/` if none.
fn requested_path(params: &Params, param: &str) -> Result<String> {
    let path = params.get(param).unwrap_or("/");
    users::check_path(path, &lower_first(param), false).map_err(validation)?;
    Ok(path.to_owned())
}

impl Iam<'_> {
    fn account(&self) -> &str {
        &self.principal.account
    }

    /// Refuses the request unless `action` on `on` is allowed, as IAM says.
    async fn check(&mut self, action: &'static str, on: On) -> Result<()> {
        self.check_with(action, on, &Context::default(), Shown::Arn).await
    }

    /// As `check`, with the condition keys `extra` too, saying what the
    /// resource is as `shown`.
    async fn check_with(&mut self, action: &'static str, on: On, extra: &Context, shown: Shown) -> Result<()> {
        let check = Check { action, on };
        self.access.load_all(self.app, std::slice::from_ref(&check)).await?;
        let verdict = self.access.verdict_with(&check, extra);
        if verdict == Verdict::Allow {
            return Ok(());
        }
        let resource = match shown {
            Shown::Arn => check.on.arn(),
            Shown::User(name) => format!("user {name}"),
            Shown::Role(name) => format!("role {name}"),
            Shown::Policy(name) => format!("policy {name}"),
        };
        Err(error(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            format!(
                "User: {} is not authorized to perform: {action} on resource: {resource} {}",
                self.principal.arn(),
                verdict.why(action, self.access.boundary())
            ),
        ))
    }

    /// The user a request names (`UserName`), or its signer: allowed
    /// `action` on it (with its condition keys, and `extra`), and one of its
    /// account. `missing`: what a user that isn't there is.
    async fn target(&mut self, params: &Params, action: &'static str, extra: Context, missing: fn(&str) -> Error) -> Result<Target> {
        let name = params.get("UserName").unwrap_or(&self.principal.name).to_owned();
        let target = Target::load(self.client, self.account(), &name).await?;
        let (on, mut context) = match &target {
            Some(target) => (target.on(), target.context(action)),
            None => (On::user(self.account(), "/", &name), Context::default()),
        };
        context.extend(&extra);
        self.check_with(action, on, &context, Shown::User(name.clone())).await?;
        target.ok_or_else(|| missing(&name))
    }

    /// `target`, for a user that isn't there being IAM's usual NoSuchEntity.
    async fn user(&mut self, params: &Params, action: &'static str) -> Result<Target> {
        self.target(params, action, Context::default(), no_such_user).await
    }

    /// A user as IAM shows it: in lists (`full`: not), without its
    /// boundary and tags.
    fn user_xml(user: &Target, full: bool) -> String {
        let mut xml = format!(
            "<Path>{}</Path><UserName>{}</UserName><UserId>{}</UserId><Arn>{}</Arn><CreateDate>{}</CreateDate>",
            xml_escape(&user.path),
            xml_escape(&user.name),
            user_id(user.id),
            xml_escape(&user.arn()),
            user.created
        );
        if full {
            if let Some(boundary) = &user.boundary {
                xml.push_str(&format!(
                    "<PermissionsBoundary><PermissionsBoundaryType>Policy</PermissionsBoundaryType>\
                     <PermissionsBoundaryArn>{}</PermissionsBoundaryArn></PermissionsBoundary>",
                    xml_escape(boundary)
                ));
            }
            if !user.tags.is_empty() {
                xml.push_str(&tags_xml("Tags", &user.tags));
            }
        }
        xml
    }

    async fn get_user(&mut self, params: &Params) -> Result<Option<String>> {
        let user = self.user(params, "iam:GetUser").await?;
        Ok(Some(format!("<User>{}</User>", Self::user_xml(&user, true))))
    }

    async fn list_users(&mut self, params: &Params) -> Result<Option<String>> {
        let prefix = params.get("PathPrefix").unwrap_or("/").to_owned();
        users::check_path(&prefix, "pathPrefix", true).map_err(validation)?;
        self.check("iam:ListUsers", On::users(self.account(), &prefix)).await?;
        let max = max_items(params)?;
        let after = params.get("Marker").unwrap_or("");
        let rows = self
            .client
            .query_cached(
                "SELECT name FROM users WHERE account_id = $1 AND name > $2 AND starts_with(path, $3)
                 ORDER BY name LIMIT $4",
                &[&self.account(), &after, &prefix, &(max as i64 + 1)],
            )
            .await?;
        let mut users = Vec::new();
        for row in &rows {
            if let Some(user) = Target::load(self.client, self.account(), row.get(0)).await? {
                users.push(user);
            }
        }
        let truncated = users.len() > max;
        let listed = &users[..users.len().min(max)];
        let members: String = listed.iter().map(|u| format!("<member>{}</member>", Self::user_xml(u, false))).collect();
        let marker = match (truncated, listed.last()) {
            (true, Some(last)) => format!("<Marker>{}</Marker>", xml_escape(&last.name)),
            _ => String::new(),
        };
        Ok(Some(format!("<Users>{members}</Users><IsTruncated>{truncated}</IsTruncated>{marker}")))
    }

    async fn create_user(&mut self, params: &Params) -> Result<Option<String>> {
        let name = params.required("UserName")?.to_owned();
        let path = requested_path(params, "Path")?;
        let tags = request_tags(params, false, Tagged::User)?;
        let boundary = requested_boundary(params)?;
        let on = On::user(self.account(), &path, &name);
        // As IAM: the boundary asked for, and the tags (which take TagUser
        // too: probed).
        let mut context = tags.as_deref().map(tags_context).unwrap_or_default();
        if let Some(arn) = &boundary {
            context.set("iam:PermissionsBoundary", arn);
        }
        self.check_with("iam:CreateUser", on.clone(), &context, Shown::Arn).await?;
        if tags.is_some() {
            self.check_with("iam:TagUser", on, &context, Shown::Arn).await?;
        }
        let boundary = match &boundary {
            Some(arn) => Some(managed::boundary(self.client, self.account(), arn).await?),
            None => None,
        };
        let exists = self
            .client
            .query_opt_cached("SELECT 1 FROM users WHERE lower(name) = lower($1) AND account_id = $2", &[&name, &self.account()])
            .await?
            .is_some();
        if exists {
            return Err(error(StatusCode::CONFLICT, "EntityAlreadyExists", format!("User with name {name} already exists.")));
        }
        users::create_user(self.client, self.account(), &name, &path, boundary.as_ref()).await.map_err(|e| {
            match e.downcast::<users::Invalid>() {
                Ok(invalid) if invalid.0.contains("already") => {
                    error(StatusCode::CONFLICT, "EntityAlreadyExists", format!("User with name {name} already exists."))
                }
                Ok(invalid) => validation(invalid.0),
                Err(e) => e.into(),
            }
        })?;
        let user = Target::load(self.client, self.account(), &name).await?.ok_or_else(|| no_such_user(&name))?;
        if let Some(tags) = &tags {
            users::tag(self.client, user.id, tags).await?;
        }
        let user = Target::load(self.client, self.account(), &name).await?.ok_or_else(|| no_such_user(&name))?;
        Ok(Some(format!("<User>{}</User>", Self::user_xml(&user, true))))
    }

    /// UpdateUser: moves (`NewPath`) or renames (`NewUserName`) a user,
    /// which takes iam:UpdateUser on it and on where it goes: its new path
    /// (`user/<path>`), or, renamed, its new ARN (probed).
    async fn update_user(&mut self, params: &Params) -> Result<Option<String>> {
        params.required("UserName")?;
        let new_path = match params.get("NewPath") {
            Some(_) => Some(requested_path(params, "NewPath")?),
            None => None,
        };
        let new_name = params.get("NewUserName").map(str::to_owned);
        let user = self.user(params, "iam:UpdateUser").await?;
        let path = new_path.clone().unwrap_or_else(|| user.path.clone());
        let to = match &new_name {
            Some(name) => On::user(self.account(), &path, name),
            None => On::users(self.account(), &path),
        };
        if new_path.is_some() || new_name.is_some() {
            self.check("iam:UpdateUser", to).await?;
        }
        if let Some(name) = &new_name
            && !name.eq_ignore_ascii_case(&user.name)
        {
            let exists = self
                .client
                .query_opt_cached("SELECT 1 FROM users WHERE lower(name) = lower($1) AND account_id = $2", &[&name, &self.account()])
                .await?
                .is_some();
            if exists {
                return Err(error(StatusCode::CONFLICT, "EntityAlreadyExists", format!("User with name {name} already exists.")));
            }
        }
        let name = new_name.unwrap_or_else(|| user.name.clone());
        users::rename(self.client, self.account(), user.id, &name, &path).await.map_err(|e| match e.downcast::<users::Invalid>() {
            Ok(i) if i.0.contains("already") => {
                error(StatusCode::CONFLICT, "EntityAlreadyExists", format!("User with name {name} already exists."))
            }
            Ok(i) => validation(i.0),
            Err(e) => e.into(),
        })?;
        Ok(None)
    }

    async fn delete_user(&mut self, params: &Params) -> Result<Option<String>> {
        params.required("UserName")?;
        let user = self.user(params, "iam:DeleteUser").await?;
        // As IAM: what's attached to a user goes first (but its boundary and
        // tags: probed).
        let conflict = |what: &str| {
            error(StatusCode::CONFLICT, "DeleteConflict", format!("Cannot delete entity, must {what} first."))
        };
        let client = self.client;
        let count = async |sql: &'static str| -> Result<i64> {
            Ok(client.query_one_cached(sql, &[&user.id]).await?.get(0))
        };
        if count("SELECT count(*) FROM access_keys WHERE user_id = $1").await? > 0 {
            return Err(conflict("delete access keys"));
        }
        if count("SELECT count(*) FROM user_policies WHERE user_id = $1 AND name NOT LIKE 'cairn:%'").await? > 0 {
            return Err(conflict("delete policies"));
        }
        if user.admin || count("SELECT count(*) FROM user_attached_policies WHERE user_id = $1").await? > 0 {
            return Err(conflict("detach all policies"));
        }
        users::delete(self.client, self.account(), &user.name).await?;
        Ok(None)
    }

    async fn put_user_permissions_boundary(&mut self, params: &Params) -> Result<Option<String>> {
        params.required("UserName")?;
        let Some(arn) = requested_boundary(params)? else {
            params.required("PermissionsBoundary")?;
            unreachable!()
        };
        // Decided by the boundary asked for (probed).
        let mut extra = Context::default();
        extra.set("iam:PermissionsBoundary", &arn);
        let not_found = |name: &str| error(StatusCode::NOT_FOUND, "NoSuchEntity", format!("User {name} was not found."));
        let user = self.target(params, "iam:PutUserPermissionsBoundary", extra, not_found).await?;
        let boundary = managed::boundary(self.client, self.account(), &arn).await?;
        if !users::set_boundary(self.client, self.account(), user.id, Some(&boundary)).await? {
            return Err(not_found(&user.name));
        }
        Ok(None)
    }

    async fn delete_user_permissions_boundary(&mut self, params: &Params) -> Result<Option<String>> {
        params.required("UserName")?;
        let not_found = |name: &str| error(StatusCode::NOT_FOUND, "NoSuchEntity", format!("User {name} was not found."));
        let user = self.target(params, "iam:DeleteUserPermissionsBoundary", Context::default(), not_found).await?;
        if user.boundary.is_none() {
            return Err(error(StatusCode::NOT_FOUND, "NoSuchEntity", format!("Principal {} does not have scope", user_id(user.id))));
        }
        users::set_boundary(self.client, self.account(), user.id, None).await?;
        Ok(None)
    }

    async fn tag_user(&mut self, params: &Params) -> Result<Option<String>> {
        params.required("UserName")?;
        let tags = request_tags(params, true, Tagged::User)?.unwrap_or_default();
        let user = self.target(params, "iam:TagUser", tags_context(&tags), no_such_user).await?;
        users::tag(self.client, user.id, &tags).await?;
        Ok(None)
    }

    async fn untag_user(&mut self, params: &Params) -> Result<Option<String>> {
        params.required("UserName")?;
        let keys = request_keys(params)?;
        let mut extra = Context::default();
        extra.set_all("aws:TagKeys", keys.clone());
        let user = self.target(params, "iam:UntagUser", extra, no_such_user).await?;
        users::untag(self.client, user.id, &keys).await?;
        Ok(None)
    }

    async fn list_user_tags(&mut self, params: &Params) -> Result<Option<String>> {
        params.required("UserName")?;
        let user = self.user(params, "iam:ListUserTags").await?;
        let max = max_items(params)?;
        // A marker is where the next page starts.
        let start: usize = match params.get("Marker") {
            Some(m) => m.parse().map_err(|_| invalid("Invalid Marker."))?,
            None => 0,
        };
        let page: Vec<(String, String)> = user.tags.iter().skip(start).take(max).cloned().collect();
        let truncated = start + page.len() < user.tags.len();
        let marker = match truncated {
            true => format!("<Marker>{}</Marker>", start + page.len()),
            false => String::new(),
        };
        Ok(Some(format!("{}<IsTruncated>{truncated}</IsTruncated>{marker}", tags_xml("Tags", &page))))
    }

    async fn create_access_key(&mut self, params: &Params) -> Result<Option<String>> {
        let user = self.user(params, "iam:CreateAccessKey").await?;
        let (id, secret) = users::create_key(self.client, self.account(), &user.name, None, None).await.map_err(|e| {
            match e.downcast::<users::Invalid>() {
                Ok(i) if i.0.contains("access keys already") => error(
                    StatusCode::CONFLICT,
                    "LimitExceeded",
                    "Cannot exceed quota for AccessKeysPerUser: 2",
                ),
                Ok(i) => invalid(i.0),
                Err(e) => e.into(),
            }
        })?;
        let created: String = self
            .client
            .query_one_cached(&format!("SELECT {ISO} FROM access_keys WHERE access_key_id = $1"), &[&id])
            .await?
            .get(0);
        Ok(Some(format!(
            "<AccessKey><UserName>{}</UserName><AccessKeyId>{}</AccessKeyId><Status>Active</Status>\
             <SecretAccessKey>{}</SecretAccessKey><CreateDate>{created}</CreateDate></AccessKey>",
            xml_escape(&user.name),
            xml_escape(&id),
            xml_escape(&secret)
        )))
    }

    async fn list_access_keys(&mut self, params: &Params) -> Result<Option<String>> {
        let user = self.user(params, "iam:ListAccessKeys").await?;
        let rows = self
            .client
            .query_cached(
                &format!("SELECT access_key_id, active, {ISO} FROM access_keys WHERE user_id = $1 ORDER BY created_at, access_key_id"),
                &[&user.id],
            )
            .await?;
        let members: String = rows
            .iter()
            .map(|r| {
                let status = if r.get::<_, bool>(1) { "Active" } else { "Inactive" };
                format!(
                    "<member><UserName>{}</UserName><AccessKeyId>{}</AccessKeyId><Status>{status}</Status>\
                     <CreateDate>{}</CreateDate></member>",
                    xml_escape(&user.name),
                    xml_escape(r.get::<_, &str>(0)),
                    r.get::<_, String>(2)
                )
            })
            .collect();
        Ok(Some(format!("<AccessKeyMetadata>{members}</AccessKeyMetadata><IsTruncated>false</IsTruncated>")))
    }

    /// The access key a request names, of `user`.
    async fn key_of(&self, params: &Params, user: &Target) -> Result<String> {
        let id = params.required("AccessKeyId")?.to_owned();
        let mine = self
            .client
            .query_opt_cached("SELECT 1 FROM access_keys WHERE access_key_id = $1 AND user_id = $2", &[&id, &user.id])
            .await?
            .is_some();
        if !mine {
            return Err(error(StatusCode::NOT_FOUND, "NoSuchEntity", format!("The Access Key with id {id} cannot be found.")));
        }
        Ok(id)
    }

    async fn update_access_key(&mut self, params: &Params) -> Result<Option<String>> {
        let user = self.user(params, "iam:UpdateAccessKey").await?;
        let active = match params.required("Status")? {
            "Active" => true,
            "Inactive" => false,
            other => {
                return Err(validation(format!(
                    "1 validation error detected: Value '{other}' at 'status' failed to satisfy constraint: \
                     Member must satisfy enum value set: [Active, Inactive]"
                )));
            }
        };
        let id = self.key_of(params, &user).await?;
        users::set_key_active(self.client, Some((self.account(), &user.name)), &id, active).await?;
        Ok(None)
    }

    async fn delete_access_key(&mut self, params: &Params) -> Result<Option<String>> {
        let user = self.user(params, "iam:DeleteAccessKey").await?;
        let id = self.key_of(params, &user).await?;
        users::delete_key(self.client, Some((self.account(), &user.name)), &id).await?;
        Ok(None)
    }

    async fn put_user_policy(&mut self, params: &Params) -> Result<Option<String>> {
        params.required("UserName")?;
        let user = self.user(params, "iam:PutUserPolicy").await?;
        let name = params.required("PolicyName")?;
        let document = params.required("PolicyDocument")?;
        users::put_policy(self.client, self.account(), &user.name, name, document).await.map_err(|e| match e.downcast::<users::Invalid>() {
            Ok(i) if i.0.starts_with("Malformed") || i.0.contains("Policy") && i.0.contains(':') => {
                let message = i.0.split_once(": ").map_or(i.0.as_str(), |(_, m)| m).to_owned();
                error(StatusCode::BAD_REQUEST, "MalformedPolicyDocument", message)
            }
            Ok(i) if i.0.contains("together") => error(
                StatusCode::CONFLICT,
                "LimitExceeded",
                format!("Maximum policy size of 2048 bytes exceeded for user {}", user.name),
            ),
            Ok(i) => validation(i.0),
            Err(e) => e.into(),
        })?;
        Ok(None)
    }

    async fn get_user_policy(&mut self, params: &Params) -> Result<Option<String>> {
        params.required("UserName")?;
        let user = self.user(params, "iam:GetUserPolicy").await?;
        let name = params.required("PolicyName")?;
        let document = users::get_policy(self.client, self.account(), &user.name, name).await.map_err(|_| {
            error(StatusCode::NOT_FOUND, "NoSuchEntity", format!("The user policy with name {name} cannot be found."))
        })?;
        // URL-encoded, as IAM gives policy documents (RFC 3986).
        let encoded = utf8_percent_encode(&document, &RFC3986).to_string();
        Ok(Some(format!(
            "<UserName>{}</UserName><PolicyName>{}</PolicyName><PolicyDocument>{}</PolicyDocument>",
            xml_escape(&user.name),
            xml_escape(name),
            xml_escape(&encoded)
        )))
    }

    async fn list_user_policies(&mut self, params: &Params) -> Result<Option<String>> {
        params.required("UserName")?;
        let user = self.user(params, "iam:ListUserPolicies").await?;
        let rows = self
            .client
            .query_cached(
                "SELECT name FROM user_policies WHERE user_id = $1 AND name NOT LIKE 'cairn:%' ORDER BY name",
                &[&user.id],
            )
            .await?;
        let members: String = rows.iter().map(|r| format!("<member>{}</member>", xml_escape(r.get::<_, &str>(0)))).collect();
        Ok(Some(format!("<PolicyNames>{members}</PolicyNames><IsTruncated>false</IsTruncated>")))
    }

    async fn delete_user_policy(&mut self, params: &Params) -> Result<Option<String>> {
        params.required("UserName")?;
        let user = self.user(params, "iam:DeleteUserPolicy").await?;
        let name = params.required("PolicyName")?;
        users::delete_policy(self.client, self.account(), &user.name, name).await.map_err(|_| {
            error(StatusCode::NOT_FOUND, "NoSuchEntity", format!("The user policy with name {name} cannot be found."))
        })?;
        Ok(None)
    }

    /// AttachUserPolicy (`attach`) and DetachUserPolicy, of a managed
    /// policy: Cairn's, or the account's own.
    async fn attach_user_policy(&mut self, params: &Params, attach: bool) -> Result<Option<String>> {
        params.required("UserName")?;
        let arn = params.required("PolicyArn")?.to_owned();
        let action = if attach { "iam:AttachUserPolicy" } else { "iam:DetachUserPolicy" };
        let mut extra = Context::default();
        extra.set("iam:PolicyARN", &arn);
        let user = self.target(params, action, extra, no_such_user).await?;
        managed::attach(self.client, self.account(), &user.name, &arn, attach).await?;
        Ok(None)
    }

    async fn list_attached_user_policies(&mut self, params: &Params) -> Result<Option<String>> {
        params.required("UserName")?;
        let user = self.user(params, "iam:ListAttachedUserPolicies").await?;
        let members: String = managed::attached(self.client, self.account(), &user.name)
            .await?
            .iter()
            .map(|p| {
                format!(
                    "<member><PolicyName>{}</PolicyName><PolicyArn>{}</PolicyArn></member>",
                    xml_escape(&p.name),
                    xml_escape(&p.arn)
                )
            })
            .collect();
        Ok(Some(format!("<AttachedPolicies>{members}</AttachedPolicies><IsTruncated>false</IsTruncated>")))
    }

    /// The policy a request names (`PolicyArn`), allowed `action` on it.
    async fn policy(&mut self, params: &Params, action: &'static str) -> Result<Policy> {
        self.policy_with(params, action, Context::default()).await
    }

    /// As `policy`, with the condition keys `extra` too.
    async fn policy_with(&mut self, params: &Params, action: &'static str, extra: Context) -> Result<Policy> {
        let arn = params.required("PolicyArn")?.to_owned();
        let named = managed::named(&arn, self.account()).map_err(|_| {
            error(StatusCode::NOT_FOUND, "NoSuchEntity", format!("Policy {arn} does not exist or is not attachable."))
        })?;
        let on = match &named {
            Named::Aws(p) => On::policy("aws", "/", p.name),
            Named::Own { path, name } => On::policy(self.account(), path, name),
        };
        // Its tags are its `aws:ResourceTag`s (not `iam:ResourceTag`s, which
        // are users' and roles' only: probed). One that isn't there is
        // checked as it would be, untagged.
        let policy = self.load_policy(named).await;
        let mut context = extra;
        if let Ok(policy) = &policy {
            for (key, value) in &policy.tags {
                context.set(&format!("aws:ResourceTag/{key}"), value);
            }
        }
        self.check_with(action, on, &context, Shown::Policy(arn)).await?;
        policy
    }

    async fn load_policy(&self, named: Named) -> Result<Policy> {
        let account = self.account().to_owned();
        let users = |arn: String| async move {
            let attached = managed::attached_all(self.client, &account).await?;
            let ids: Vec<uuid::Uuid> = attached.into_iter().filter(|(_, ps)| ps.iter().any(|p| p.arn == arn)).map(|(id, _)| id).collect();
            Result::Ok(ids)
        };
        Ok(match named {
            Named::Aws(p) => {
                let arn = managed::aws_arn(p.name);
                let (roles, role_bounds) = crate::roles::of_policy(self.client, self.account(), &arn).await?;
                let bounds = self
                    .client
                    .query_cached(
                        "SELECT id FROM users WHERE account_id = $1 AND boundary_aws = $2 ORDER BY name",
                        &[&self.account(), &p.name],
                    )
                    .await?
                    .iter()
                    .map(|r| r.get(0))
                    .collect();
                Policy {
                    users: users(arn.clone()).await?,
                    bounds,
                    roles,
                    role_bounds,
                    arn,
                    id: managed::policy_id(None, p.name),
                    name: p.name.to_owned(),
                    path: "/".to_owned(),
                    description: p.description.to_owned(),
                    document: p.document.to_owned(),
                    version: 1,
                    // As AWS's own were made.
                    created: "2015-02-06T18:39:46Z".to_owned(),
                    updated: "2015-02-06T18:39:46Z".to_owned(),
                    aws: true,
                    tags: Vec::new(),
                    uuid: None,
                }
            }
            Named::Own { path, name } => {
                let not_found = || {
                    let arn = managed::arn(self.account(), &path, &name);
                    error(StatusCode::NOT_FOUND, "NoSuchEntity", format!("Policy {arn} was not found."))
                };
                let row = self
                    .client
                    .query_opt_cached(
                        "SELECT id, name, description, document, version,
                                to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
                                to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
                                ARRAY(SELECT r.id FROM users r WHERE r.boundary_policy_id = m.id ORDER BY r.name),
                                ARRAY(SELECT t.key FROM managed_policy_tags t WHERE t.policy_id = m.id ORDER BY t.seq),
                                ARRAY(SELECT t.value FROM managed_policy_tags t WHERE t.policy_id = m.id ORDER BY t.seq)
                         FROM managed_policies m WHERE account_id = $1 AND name = $2 AND path = $3",
                        &[&self.account(), &name, &path],
                    )
                    .await?
                    .ok_or_else(not_found)?;
                let arn = managed::arn(self.account(), &path, &name);
                let (roles, role_bounds) = crate::roles::of_policy(self.client, self.account(), &arn).await?;
                Policy {
                    users: users(arn.clone()).await?,
                    bounds: row.get(7),
                    roles,
                    role_bounds,
                    arn,
                    id: managed::policy_id(Some(row.get(0)), &name),
                    name: row.get(1),
                    path,
                    description: row.get(2),
                    document: row.get(3),
                    version: row.get(4),
                    created: row.get(5),
                    updated: row.get(6),
                    aws: false,
                    tags: users::tags_of(row.get(8), row.get(9)),
                    uuid: Some(row.get(0)),
                }
            }
        })
    }

    fn policy_xml(policy: &Policy) -> String {
        let description = match policy.description.is_empty() {
            true => String::new(),
            false => format!("<Description>{}</Description>", xml_escape(&policy.description)),
        };
        format!(
            "<PolicyName>{}</PolicyName><DefaultVersionId>v{}</DefaultVersionId><PolicyId>{}</PolicyId><Path>{}</Path>\
             <Arn>{}</Arn><AttachmentCount>{}</AttachmentCount><PermissionsBoundaryUsageCount>{}</PermissionsBoundaryUsageCount>\
             <IsAttachable>true</IsAttachable>{description}<CreateDate>{}</CreateDate><UpdateDate>{}</UpdateDate>",
            xml_escape(&policy.name),
            policy.version,
            policy.id,
            xml_escape(&policy.path),
            xml_escape(&policy.arn),
            policy.users.len() + policy.roles.len(),
            policy.bounds.len() + policy.role_bounds.len(),
            policy.created,
            policy.updated
        )
    }

    async fn create_policy(&mut self, params: &Params) -> Result<Option<String>> {
        let name = params.required("PolicyName")?.to_owned();
        let document = params.required("PolicyDocument")?;
        let path = requested_path(params, "Path")?;
        let tags = request_tags(params, false, Tagged::Policy)?;
        // With tags, it takes TagPolicy too (probed).
        let on = On::policy(self.account(), &path, &name);
        let context = tags.as_deref().map(tags_context).unwrap_or_default();
        self.check_with("iam:CreatePolicy", on.clone(), &context, Shown::Policy(name.clone())).await?;
        if tags.is_some() {
            self.check_with("iam:TagPolicy", on, &context, Shown::Policy(name.clone())).await?;
        }
        let description = params.get("Description").unwrap_or("");
        let tags = tags.unwrap_or_default();
        managed::create_tagged(self.client, self.account(), &name, &path, document, description, &tags).await?;
        let policy = self.load_policy(Named::Own { path, name }).await?;
        // Its tags, if it was given some (probed).
        let tags = if tags.is_empty() { String::new() } else { tags_xml("Tags", &policy.tags) };
        Ok(Some(format!("<Policy>{}{tags}</Policy>", Self::policy_xml(&policy))))
    }

    /// The account's own policy a request names, which TagPolicy and the like
    /// change (Cairn's can't be), allowed `action` on it, with `extra`.
    async fn own_policy_with(&mut self, params: &Params, action: &'static str, extra: Context) -> Result<Policy> {
        let arn = params.required("PolicyArn")?.to_owned();
        if arn.len() < 20 {
            return Err(validation(
                "1 validation error detected: Value at 'policyArn' failed to satisfy constraint: Member must have length greater than or equal to 20",
            ));
        }
        if !arn.starts_with("arn:aws:iam::") || !arn.contains(":policy/") {
            return Err(invalid(format!("ARN {arn} is not valid.")));
        }
        let policy = self.policy_with(params, action, extra).await.map_err(|e| match e.code {
            "NoSuchEntity" => error(StatusCode::NOT_FOUND, "NoSuchEntity", format!("Policy {arn} was not found.")),
            _ => e,
        })?;
        Self::own(&policy)?;
        Ok(policy)
    }

    async fn tag_policy(&mut self, params: &Params) -> Result<Option<String>> {
        let tags = request_tags(params, true, Tagged::Policy)?.unwrap_or_default();
        let policy = self.own_policy_with(params, "iam:TagPolicy", tags_context(&tags)).await?;
        managed::tag(self.client, policy.uuid.expect("an account's own"), &tags).await?;
        Ok(None)
    }

    async fn untag_policy(&mut self, params: &Params) -> Result<Option<String>> {
        let keys = request_keys(params)?;
        let mut extra = Context::default();
        extra.set_all("aws:TagKeys", keys.clone());
        let policy = self.own_policy_with(params, "iam:UntagPolicy", extra).await?;
        managed::untag(self.client, policy.uuid.expect("an account's own"), &keys).await?;
        Ok(None)
    }

    async fn list_policy_tags(&mut self, params: &Params) -> Result<Option<String>> {
        let policy = self.own_policy_with(params, "iam:ListPolicyTags", Context::default()).await?;
        let max = max_items(params)?;
        let start: usize = match params.get("Marker") {
            Some(m) => m.parse().map_err(|_| invalid("Invalid Marker."))?,
            None => 0,
        };
        let page: Vec<(String, String)> = policy.tags.iter().skip(start).take(max).cloned().collect();
        let truncated = start + page.len() < policy.tags.len();
        let marker = match truncated {
            true => format!("<Marker>{}</Marker>", start + page.len()),
            false => String::new(),
        };
        Ok(Some(format!("{}<IsTruncated>{truncated}</IsTruncated>{marker}", tags_xml("Tags", &page))))
    }

    async fn get_policy(&mut self, params: &Params) -> Result<Option<String>> {
        let policy = self.policy(params, "iam:GetPolicy").await?;
        // With its tags, which GetPolicy shows, even none, as ListPolicies
        // doesn't (probed).
        Ok(Some(format!("<Policy>{}{}</Policy>", Self::policy_xml(&policy), tags_xml("Tags", &policy.tags))))
    }

    /// Refuses changing one of Cairn's (AWS's) policies.
    fn own(policy: &Policy) -> Result<()> {
        match policy.aws {
            true => Err(invalid(format!("Policy {} is AWS's (Cairn's own copy): it can't be changed.", policy.arn))),
            false => Ok(()),
        }
    }

    async fn delete_policy(&mut self, params: &Params) -> Result<Option<String>> {
        let policy = self.policy(params, "iam:DeletePolicy").await?;
        Self::own(&policy)?;
        managed::delete(self.client, self.account(), &policy.name).await?;
        Ok(None)
    }

    async fn list_policies(&mut self, params: &Params) -> Result<Option<String>> {
        self.check("iam:ListPolicies", On::Account).await?;
        let scope = params.get("Scope").unwrap_or("All");
        if !["All", "AWS", "Local"].contains(&scope) {
            return Err(validation("Scope is All, AWS or Local"));
        }
        let only_attached = params.get("OnlyAttached") == Some("true");
        let prefix = params.get("PathPrefix").unwrap_or("/").to_owned();
        users::check_path(&prefix, "pathPrefix", true).map_err(validation)?;
        let mut policies = Vec::new();
        if scope != "Local" {
            for p in managed::AWS_POLICIES {
                policies.push(self.load_policy(Named::Aws(p)).await?);
            }
        }
        if scope != "AWS" {
            for p in managed::list(self.client, self.account()).await? {
                policies.push(self.load_policy(Named::Own { path: p.path, name: p.name }).await?);
            }
        }
        policies.retain(|p| p.path.starts_with(&prefix) && (!only_attached || !p.users.is_empty() || !p.roles.is_empty()));
        // Paged by ARN.
        policies.sort_by(|a, b| a.arn.cmp(&b.arn));
        if let Some(after) = params.get("Marker") {
            policies.retain(|p| p.arn.as_str() > after);
        }
        let max = max_items(params)?;
        let truncated = policies.len() > max;
        policies.truncate(max);
        let members: String = policies.iter().map(|p| format!("<member>{}</member>", Self::policy_xml(p))).collect();
        let marker = match (truncated, policies.last()) {
            (true, Some(last)) => format!("<Marker>{}</Marker>", xml_escape(&last.arn)),
            _ => String::new(),
        };
        Ok(Some(format!("<Policies>{members}</Policies><IsTruncated>{truncated}</IsTruncated>{marker}")))
    }

    /// The version a request names (`VersionId`: `v1`, ..., as IAM checks
    /// it, probed): its number.
    fn version_of(params: &Params) -> Result<i32> {
        let id = params.required("VersionId")?;
        let pattern = "v[1-9][0-9]*(\\.[A-Za-z0-9-]*)?";
        let invalid_id = || {
            validation(format!(
                "1 validation error detected: Value at 'versionId' failed to satisfy constraint: Member must satisfy regular expression pattern: {pattern}"
            ))
        };
        let rest = id.strip_prefix('v').ok_or_else(invalid_id)?;
        let (digits, suffix) = rest.split_once('.').map_or((rest, None), |(d, s)| (d, Some(s)));
        if digits.is_empty()
            || digits.starts_with('0')
            || !digits.bytes().all(|b| b.is_ascii_digit())
            || suffix.is_some_and(|s| !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        {
            return Err(invalid_id());
        }
        // Cairn's are only ever `vN` (a suffix names none of them), and none
        // past what an i32 holds.
        match (suffix, digits.parse::<i32>()) {
            (None, Ok(n)) => Ok(n),
            _ => Ok(0),
        }
    }

    /// The versions of `policy` (Cairn's own: its one, `v1`), newest first.
    async fn versions(&self, policy: &Policy) -> Result<Vec<managed::Version>> {
        match policy.uuid {
            Some(id) => Ok(managed::versions(self.client, id).await?),
            None => Ok(vec![managed::Version {
                version: policy.version,
                document: policy.document.clone(),
                created: policy.created.clone(),
                created_at: 0.0,
                default: true,
            }]),
        }
    }

    /// `policy`'s version `version`, as IAM refuses one that isn't there.
    async fn version(&self, policy: &Policy, version: i32) -> Result<managed::Version> {
        self.versions(policy).await?.into_iter().find(|v| v.version == version).ok_or_else(|| {
            error(
                StatusCode::NOT_FOUND,
                "NoSuchEntity",
                format!("Policy {} version v{version} does not exist or is not attachable.", policy.arn),
            )
        })
    }

    fn version_xml(version: &managed::Version, document: bool) -> String {
        let document = match document {
            // URL-encoded, as IAM gives policy documents (RFC 3986).
            true => format!("<Document>{}</Document>", xml_escape(&utf8_percent_encode(&version.document, &RFC3986).to_string())),
            false => String::new(),
        };
        format!(
            "{document}<VersionId>v{}</VersionId><IsDefaultVersion>{}</IsDefaultVersion><CreateDate>{}</CreateDate>",
            version.version, version.default, version.created
        )
    }

    async fn get_policy_version(&mut self, params: &Params) -> Result<Option<String>> {
        let policy = self.policy(params, "iam:GetPolicyVersion").await?;
        let version = self.version(&policy, Self::version_of(params)?).await?;
        Ok(Some(format!("<PolicyVersion>{}</PolicyVersion>", Self::version_xml(&version, true))))
    }

    /// ListPolicyVersions: newest first (probed), paged.
    async fn list_policy_versions(&mut self, params: &Params) -> Result<Option<String>> {
        let policy = self.policy(params, "iam:ListPolicyVersions").await?;
        let max = max_items(params)?;
        let mut versions = self.versions(&policy).await?;
        // A marker is the last version listed.
        if let Some(after) = params.get("Marker") {
            let after: i32 = after.parse().map_err(|_| invalid("Invalid Marker."))?;
            versions.retain(|v| v.version < after);
        }
        let truncated = versions.len() > max;
        versions.truncate(max);
        let members: String = versions.iter().map(|v| format!("<member>{}</member>", Self::version_xml(v, false))).collect();
        let marker = match (truncated, versions.last()) {
            (true, Some(last)) => format!("<Marker>{}</Marker>", last.version),
            _ => String::new(),
        };
        Ok(Some(format!("<Versions>{members}</Versions><IsTruncated>{truncated}</IsTruncated>{marker}")))
    }

    /// CreatePolicyVersion: the policy's default if `SetAsDefault`; refused
    /// at five versions, as IAM refuses it (probed).
    async fn create_policy_version(&mut self, params: &Params) -> Result<Option<String>> {
        let policy = self.policy(params, "iam:CreatePolicyVersion").await?;
        Self::own(&policy)?;
        let document = params.required("PolicyDocument")?;
        let default = params.get("SetAsDefault") == Some("true");
        let id = policy.uuid.expect("an account's own");
        let number = managed::create_version(self.client, id, &policy.arn, document, default, false).await?;
        let version = managed::versions(self.client, id).await?.into_iter().find(|v| v.version == number).ok_or_else(|| {
            error(StatusCode::CONFLICT, "ConcurrentModification", "the policy's versions changed meanwhile")
        })?;
        Ok(Some(format!("<PolicyVersion>{}</PolicyVersion>", Self::version_xml(&version, false))))
    }

    async fn delete_policy_version(&mut self, params: &Params) -> Result<Option<String>> {
        let policy = self.policy(params, "iam:DeletePolicyVersion").await?;
        Self::own(&policy)?;
        let version = Self::version_of(params)?;
        managed::delete_version(self.client, policy.uuid.expect("an account's own"), &policy.arn, version).await?;
        Ok(None)
    }

    async fn set_default_policy_version(&mut self, params: &Params) -> Result<Option<String>> {
        let policy = self.policy(params, "iam:SetDefaultPolicyVersion").await?;
        Self::own(&policy)?;
        let version = Self::version_of(params)?;
        managed::set_default(self.client, policy.uuid.expect("an account's own"), &policy.arn, version).await?;
        Ok(None)
    }

    /// ListEntitiesForPolicy: the users it's attached to, and those whose
    /// permissions boundary it is (`PolicyUsageFilter`: one or the other;
    /// probed).
    async fn list_entities_for_policy(&mut self, params: &Params) -> Result<Option<String>> {
        let policy = self.policy(params, "iam:ListEntitiesForPolicy").await?;
        let (attached, bounded) = match params.get("PolicyUsageFilter") {
            None => (true, true),
            Some("PermissionsPolicy") => (true, false),
            Some("PermissionsBoundary") => (false, true),
            Some(other) => {
                return Err(validation(format!(
                    "1 validation error detected: Value '{other}' at 'policyUsageFilter' failed to satisfy constraint: \
                     Member must satisfy enum value set: [PermissionsPolicy, PermissionsBoundary]"
                )));
            }
        };
        let entities = params.get("EntityFilter");
        let mut users = Vec::new();
        if matches!(entities, None | Some("User")) {
            if attached {
                users.extend(policy.users.iter().copied());
            }
            if bounded {
                let more: Vec<uuid::Uuid> = policy.bounds.iter().copied().filter(|id| !users.contains(id)).collect();
                users.extend(more);
            }
        }
        let mut members = String::new();
        for id in users {
            let name: String = self.client.query_one_cached("SELECT name FROM users WHERE id = $1", &[&id]).await?.get(0);
            members.push_str(&format!(
                "<member><UserName>{}</UserName><UserId>{}</UserId></member>",
                xml_escape(&name),
                user_id(id)
            ));
        }
        let mut roles: Vec<(uuid::Uuid, String)> = Vec::new();
        if matches!(entities, None | Some("Role")) {
            if attached {
                roles.extend(policy.roles.iter().cloned());
            }
            if bounded {
                let more: Vec<_> = policy.role_bounds.iter().filter(|(id, _)| !roles.iter().any(|(r, _)| r == id)).cloned().collect();
                roles.extend(more);
            }
        }
        let role_members: String = roles
            .iter()
            .map(|(id, name)| {
                format!("<member><RoleName>{}</RoleName><RoleId>{}</RoleId></member>", xml_escape(name), crate::roles::unique_id(*id))
            })
            .collect();
        Ok(Some(format!(
            "<PolicyGroups/><PolicyUsers>{members}</PolicyUsers><PolicyRoles>{role_members}</PolicyRoles><IsTruncated>false</IsTruncated>"
        )))
    }
}

/// A managed policy, as IAM shows it.
struct Policy {
    arn: String,
    id: String,
    name: String,
    /// Its path (`/`, or `/…/`).
    path: String,
    description: String,
    document: String,
    version: i32,
    created: String,
    updated: String,
    /// The users it's attached to (their IDs).
    users: Vec<uuid::Uuid>,
    /// The users whose permissions boundary it is (their IDs).
    bounds: Vec<uuid::Uuid>,
    /// The roles it's attached to, and those whose boundary it is: their
    /// IDs and names.
    roles: Vec<(uuid::Uuid, String)>,
    role_bounds: Vec<(uuid::Uuid, String)>,
    /// Whether it's one of Cairn's (AWS's).
    aws: bool,
    /// Its tags, oldest first.
    tags: Vec<(String, String)>,
    /// Its ID in Cairn (none for Cairn's own).
    uuid: Option<uuid::Uuid>,
}

/// `MaxItems`: 1 to 1000, 100 if not given, as IAM's.
fn max_items(params: &Params) -> Result<usize> {
    match params.get("MaxItems") {
        None => Ok(100),
        Some(n) => match n.parse::<usize>() {
            Ok(n) if (1..=1000).contains(&n) => Ok(n),
            _ => Err(validation("MaxItems is 1 to 1000")),
        },
    }
}

/// What RFC 3986 leaves unencoded: letters, digits and `-._~`.
const RFC3986: percent_encoding::AsciiSet = NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_ids_look_like_iams() {
        let id = user_id(uuid::Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef));
        assert_eq!(id.len(), 21);
        assert!(id.starts_with("AIDA"));
        assert!(id[4..].bytes().all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)));
        assert_eq!(id, user_id(uuid::Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef)));
    }

    #[test]
    fn decodes_forms() {
        let mut params = HashMap::new();
        Params::parse("Action=PutUserPolicy&PolicyDocument=%7B%22a%22%3A+1%7D&UserName=a%2Bb", &mut params).ok().unwrap();
        assert_eq!(params["PolicyDocument"], "{\"a\": 1}");
        assert_eq!(params["UserName"], "a+b");
        // Not given twice: the body can't override the (signed) query.
        assert!(Params::parse("Action=CreateAccessKey", &mut params).is_err());
    }
}
