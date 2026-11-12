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
//! What's there: users (no paths, tags or permissions boundaries: refused),
//! access keys, inline policies, and attaching the one built-in managed
//! policy, `AdministratorAccess`. Groups, roles, and managed policies of
//! one's own aren't (NotImplemented).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode, body::Bytes};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

use crate::{
    App,
    auth::Signed,
    db::Cached,
    policy::Verdict,
    roles::{self, Principal},
    s3::{
        access::{Access, Origin},
        actions::{Check, On},
        util::{decode_path_param, xml_escape},
    },
};

const IAM_XMLNS: &str = "https://iam.amazonaws.com/doc/2010-05-08/";
const STS_XMLNS: &str = "https://sts.amazonaws.com/doc/2011-06-15/";

/// The one managed policy there is: what `--admin` attaches.
const ADMINISTRATOR_ACCESS: &str = "arn:aws:iam::aws:policy/AdministratorAccess";

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
        match e.downcast::<roles::Invalid>() {
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
    fn parse(text: &str, into: &mut HashMap<String, String>) {
        for pair in text.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let decode = |s: &str| decode_path_param(&s.replace('+', " "));
            into.insert(decode(k), decode(v));
        }
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
pub async fn handle(app: &Arc<App>, req: Request<hyper::body::Incoming>, signed: Signed, peer: IpAddr) -> Response<Full<Bytes>> {
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
    req: Request<hyper::body::Incoming>,
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
    Params::parse(query, &mut params);
    if !body.is_empty() {
        let text = std::str::from_utf8(&body).map_err(|_| error(StatusCode::BAD_REQUEST, "MalformedQueryString", "the request's body isn't UTF-8"))?;
        Params::parse(text, &mut params);
    }
    let params = Params(params);
    let action = params.required("Action")?.to_owned();
    let origin = Origin { peer: Some(peer), trusted_proxies: &app.trusted_proxies, signed: Some(signed), form: false };
    let mut access = Access::new(Some(&principal), &principal.account, &parts.method, &parts.headers, "", &origin)?;
    let mut iam = Iam { app, client: &client, principal: &principal, access: &mut access };
    let inner = match (signed.service.as_str(), action.as_str()) {
        ("sts", "GetCallerIdentity") => Some(format!(
            "<Arn>{}</Arn><UserId>{}</UserId><Account>{}</Account>",
            xml_escape(&user_arn(&principal.account, &principal.name)),
            user_id(principal.id),
            principal.account
        )),
        ("sts", other) => return Err(error(StatusCode::BAD_REQUEST, "InvalidAction", format!("Cairn's STS has no action {other}"))),
        (_, "GetUser") => iam.get_user(&params).await?,
        (_, "ListUsers") => iam.list_users(&params).await?,
        (_, "CreateUser") => iam.create_user(&params).await?,
        (_, "DeleteUser") => iam.delete_user(&params).await?,
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
        (_, other) => {
            return Err(error(
                StatusCode::NOT_IMPLEMENTED,
                "NotImplemented",
                format!("Cairn's IAM has users, access keys, inline policies and AdministratorAccess; not {other}"),
            ));
        }
    };
    Ok((action, inner))
}

fn user_arn(account: &str, name: &str) -> String {
    format!("arn:aws:iam::{account}:user/{name}")
}

/// A user's ID as IAM shows one (`AIDA`, then 17 characters), from its
/// Cairn ID, which never changes or comes back.
fn user_id(id: uuid::Uuid) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = u128::from_be_bytes(*id.as_bytes());
    let tail: String = (0..17).map(|i| ALPHABET[((bits >> (5 * i)) & 31) as usize] as char).collect();
    format!("AIDA{tail}")
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

/// A user of the signer's account.
struct User {
    id: uuid::Uuid,
    name: String,
    admin: bool,
    created: String,
}

impl Iam<'_> {
    fn account(&self) -> &str {
        &self.principal.account
    }

    /// Refuses the request unless `action` on `on` is allowed, as IAM says.
    async fn check(&mut self, action: &'static str, on: On) -> Result<()> {
        let check = Check { action, on };
        self.access.load_all(self.app, std::slice::from_ref(&check)).await?;
        let verdict = self.access.verdict(&check);
        if verdict == Verdict::Allow {
            return Ok(());
        }
        let why = match verdict {
            Verdict::ExplicitDeny { .. } => "with an explicit deny in an identity-based policy".to_owned(),
            _ => format!("because no identity-based policy allows the {action} action"),
        };
        Err(error(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            format!(
                "User: {} is not authorized to perform: {action} on resource: {} {why}",
                user_arn(self.account(), &self.principal.name),
                check.on.arn()
            ),
        ))
    }

    /// The user a request names (`UserName`), or its signer: allowed
    /// `action` on it, and one of its account.
    async fn user(&mut self, params: &Params, action: &'static str) -> Result<User> {
        let name = params.get("UserName").unwrap_or(&self.principal.name).to_owned();
        self.check(action, On::User(self.account().to_owned(), name.clone())).await?;
        let row = self
            .client
            .query_opt_cached(
                &format!("SELECT id, name, admin, {ISO} FROM roles WHERE name = $1 AND account_id = $2"),
                &[&name, &self.account()],
            )
            .await?
            .ok_or_else(|| no_such_user(&name))?;
        Ok(User { id: row.get(0), name: row.get(1), admin: row.get(2), created: row.get(3) })
    }

    fn user_xml(&self, user: &User) -> String {
        format!(
            "<Path>/</Path><UserName>{}</UserName><UserId>{}</UserId><Arn>{}</Arn><CreateDate>{}</CreateDate>",
            xml_escape(&user.name),
            user_id(user.id),
            xml_escape(&user_arn(self.account(), &user.name)),
            user.created
        )
    }

    async fn get_user(&mut self, params: &Params) -> Result<Option<String>> {
        let user = self.user(params, "iam:GetUser").await?;
        Ok(Some(format!("<User>{}</User>", self.user_xml(&user))))
    }

    async fn list_users(&mut self, params: &Params) -> Result<Option<String>> {
        self.check("iam:ListUsers", On::Users(self.account().to_owned())).await?;
        // There are no paths: every user's is `/`.
        if params.get("PathPrefix").is_some_and(|p| !"/".starts_with(p) && !p.starts_with('/')) {
            return Err(validation("a path prefix starts with /"));
        }
        let none = params.get("PathPrefix").is_some_and(|p| p != "/" && !p.is_empty());
        let max = max_items(params)?;
        let after = params.get("Marker").unwrap_or("");
        let rows = self
            .client
            .query_cached(
                &format!(
                    "SELECT id, name, admin, {ISO} FROM roles WHERE account_id = $1 AND name > $2 ORDER BY name LIMIT $3"
                ),
                &[&self.account(), &after, &(max as i64 + 1)],
            )
            .await?;
        let users: Vec<User> = if none {
            Vec::new()
        } else {
            rows.iter().map(|r| User { id: r.get(0), name: r.get(1), admin: r.get(2), created: r.get(3) }).collect()
        };
        let truncated = users.len() > max;
        let listed = &users[..users.len().min(max)];
        let members: String = listed.iter().map(|u| format!("<member>{}</member>", self.user_xml(u))).collect();
        let marker = match (truncated, listed.last()) {
            (true, Some(last)) => format!("<Marker>{}</Marker>", xml_escape(&last.name)),
            _ => String::new(),
        };
        Ok(Some(format!("<Users>{members}</Users><IsTruncated>{truncated}</IsTruncated>{marker}")))
    }

    async fn create_user(&mut self, params: &Params) -> Result<Option<String>> {
        let name = params.required("UserName")?.to_owned();
        if params.get("Path").is_some_and(|p| p != "/") {
            return Err(error(StatusCode::NOT_IMPLEMENTED, "NotImplemented", "Cairn's users have no paths but /"));
        }
        if params.has_list("Tags.") {
            return Err(error(StatusCode::NOT_IMPLEMENTED, "NotImplemented", "Cairn's users have no tags"));
        }
        if params.get("PermissionsBoundary").is_some() {
            return Err(error(StatusCode::NOT_IMPLEMENTED, "NotImplemented", "Cairn has no permissions boundaries yet"));
        }
        self.check("iam:CreateUser", On::User(self.account().to_owned(), name.clone())).await?;
        let exists = self
            .client
            .query_opt_cached("SELECT 1 FROM roles WHERE name = $1 AND account_id = $2", &[&name, &self.account()])
            .await?
            .is_some();
        if exists {
            return Err(error(StatusCode::CONFLICT, "EntityAlreadyExists", format!("User with name {name} already exists.")));
        }
        roles::create_without_key(self.client, self.account(), &name).await.map_err(|e| match e.downcast::<roles::Invalid>() {
            Ok(invalid) if invalid.0.contains("already") => {
                error(StatusCode::CONFLICT, "EntityAlreadyExists", format!("User with name {name} already exists."))
            }
            Ok(invalid) => validation(invalid.0),
            Err(e) => e.into(),
        })?;
        let user = self.user(&Params([("UserName".to_owned(), name)].into()), "iam:CreateUser").await?;
        Ok(Some(format!("<User>{}</User>", self.user_xml(&user))))
    }

    async fn delete_user(&mut self, params: &Params) -> Result<Option<String>> {
        params.required("UserName")?;
        let user = self.user(params, "iam:DeleteUser").await?;
        // As IAM: what's attached to a user goes first.
        let conflict = |what: &str| {
            error(StatusCode::CONFLICT, "DeleteConflict", format!("Cannot delete entity, must {what} first."))
        };
        let client = self.client;
        let count = async |sql: &'static str| -> Result<i64> {
            Ok(client.query_one_cached(sql, &[&user.id]).await?.get(0))
        };
        if count("SELECT count(*) FROM access_keys WHERE role_id = $1").await? > 0 {
            return Err(conflict("delete access keys"));
        }
        if count("SELECT count(*) FROM role_policies WHERE role_id = $1").await? > 0 {
            return Err(conflict("delete policies"));
        }
        if user.admin {
            return Err(conflict("detach all policies"));
        }
        roles::delete(self.client, self.account(), &user.name).await?;
        Ok(None)
    }

    async fn create_access_key(&mut self, params: &Params) -> Result<Option<String>> {
        let user = self.user(params, "iam:CreateAccessKey").await?;
        let (id, secret) = roles::create_key(self.client, self.account(), &user.name, None, None).await.map_err(|e| {
            match e.downcast::<roles::Invalid>() {
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
                &format!("SELECT access_key_id, active, {ISO} FROM access_keys WHERE role_id = $1 ORDER BY created_at, access_key_id"),
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
    async fn key_of(&self, params: &Params, user: &User) -> Result<String> {
        let id = params.required("AccessKeyId")?.to_owned();
        let mine = self
            .client
            .query_opt_cached("SELECT 1 FROM access_keys WHERE access_key_id = $1 AND role_id = $2", &[&id, &user.id])
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
        roles::set_key_active(self.client, Some((self.account(), &user.name)), &id, active).await?;
        Ok(None)
    }

    async fn delete_access_key(&mut self, params: &Params) -> Result<Option<String>> {
        let user = self.user(params, "iam:DeleteAccessKey").await?;
        let id = self.key_of(params, &user).await?;
        roles::delete_key(self.client, Some((self.account(), &user.name)), &id).await?;
        Ok(None)
    }

    async fn put_user_policy(&mut self, params: &Params) -> Result<Option<String>> {
        params.required("UserName")?;
        let user = self.user(params, "iam:PutUserPolicy").await?;
        let name = params.required("PolicyName")?;
        let document = params.required("PolicyDocument")?;
        roles::put_policy(self.client, self.account(), &user.name, name, document).await.map_err(|e| match e.downcast::<roles::Invalid>() {
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
        let document = roles::get_policy(self.client, self.account(), &user.name, name).await.map_err(|_| {
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
            .query_cached("SELECT name FROM role_policies WHERE role_id = $1 ORDER BY name", &[&user.id])
            .await?;
        let members: String = rows.iter().map(|r| format!("<member>{}</member>", xml_escape(r.get::<_, &str>(0)))).collect();
        Ok(Some(format!("<PolicyNames>{members}</PolicyNames><IsTruncated>false</IsTruncated>")))
    }

    async fn delete_user_policy(&mut self, params: &Params) -> Result<Option<String>> {
        params.required("UserName")?;
        let user = self.user(params, "iam:DeleteUserPolicy").await?;
        let name = params.required("PolicyName")?;
        roles::delete_policy(self.client, self.account(), &user.name, name).await.map_err(|_| {
            error(StatusCode::NOT_FOUND, "NoSuchEntity", format!("The user policy with name {name} cannot be found."))
        })?;
        Ok(None)
    }

    /// AttachUserPolicy (`attach`) and DetachUserPolicy, of
    /// `AdministratorAccess`, the one managed policy there is.
    async fn attach_user_policy(&mut self, params: &Params, attach: bool) -> Result<Option<String>> {
        params.required("UserName")?;
        let arn = params.required("PolicyArn")?.to_owned();
        let action = if attach { "iam:AttachUserPolicy" } else { "iam:DetachUserPolicy" };
        let user = self.user(params, action).await?;
        if arn != ADMINISTRATOR_ACCESS {
            return Err(error(
                StatusCode::NOT_FOUND,
                "NoSuchEntity",
                format!("Policy {arn} does not exist or is not attachable."),
            ));
        }
        if !attach && !user.admin {
            return Err(error(StatusCode::NOT_FOUND, "NoSuchEntity", format!("Policy {arn} was not found.")));
        }
        roles::update(self.client, self.account(), &user.name, Some(attach), None).await?;
        Ok(None)
    }

    async fn list_attached_user_policies(&mut self, params: &Params) -> Result<Option<String>> {
        params.required("UserName")?;
        let user = self.user(params, "iam:ListAttachedUserPolicies").await?;
        let members = match user.admin {
            true => format!("<member><PolicyName>AdministratorAccess</PolicyName><PolicyArn>{ADMINISTRATOR_ACCESS}</PolicyArn></member>"),
            false => String::new(),
        };
        Ok(Some(format!("<AttachedPolicies>{members}</AttachedPolicies><IsTruncated>false</IsTruncated>")))
    }
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
        Params::parse("Action=PutUserPolicy&PolicyDocument=%7B%22a%22%3A+1%7D&UserName=a%2Bb", &mut params);
        assert_eq!(params["PolicyDocument"], "{\"a\": 1}");
        assert_eq!(params["UserName"], "a+b");
    }
}
