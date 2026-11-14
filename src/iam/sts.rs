//! STS's actions (see `sessions`, `plans/roles.md`): AssumeRole,
//! GetSessionToken, GetFederationToken, GetAccessKeyInfo and
//! GetCallerIdentity, answered as STS answers them (probed).

use hyper::StatusCode;

use super::{Error, Iam, Params, Result, error, request_keys_named, validation};
use crate::{
    db::Cached,
    iam_oidc::{self, Provider},
    managed,
    oidc::Rejected,
    s3::access::Access,
    policy::{Context, Kind, Policy},
    roles::{self, Role},
    s3::{actions::On, util::xml_escape},
    sessions::{self, Session, Who},
};

/// STS's shortest session, and its longest for GetSessionToken and
/// GetFederationToken (and their default), in seconds.
const MIN_DURATION: i64 = 900;
const MAX_DURATION: i64 = sessions::MAX_SESSION as i64;
const DEFAULT_LONG: i64 = 43_200;
/// AssumeRole's default, and a chained session's longest.
const ROLE_DEFAULT: i64 = 3600;
/// The most an inline session policy may hold.
const MAX_SESSION_POLICY: usize = 2048;
/// The most session policy ARNs.
const MAX_POLICY_ARNS: usize = 10;
/// What STS's utilization is a share of: a token's room (probed).
const TOKEN_ROOM: usize = 4096;

/// STS's validation errors: each names the value (unlike IAM's).
struct Checks(Vec<String>);

impl Checks {
    fn length(&mut self, value: &str, field: &str, min: usize, max: usize) {
        let n = value.chars().count();
        if n < min {
            self.0.push(format!("Value '{value}' at '{field}' failed to satisfy constraint: Member must have length greater than or equal to {min}"));
        } else if n > max {
            self.0.push(format!("Value '{value}' at '{field}' failed to satisfy constraint: Member must have length less than or equal to {max}"));
        }
    }

    /// `value` of the characters `extra` adds to `\w` (STS's patterns).
    fn pattern(&mut self, value: &str, field: &str, extra: &str, shown: &str) {
        if !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || extra.contains(c)) {
            self.0.push(format!("Value '{value}' at '{field}' failed to satisfy constraint: Member must satisfy regular expression pattern: {shown}"));
        }
    }

    fn range(&mut self, value: i64, field: &str, min: i64, max: i64) {
        if value < min {
            self.0.push(format!("Value '{value}' at '{field}' failed to satisfy constraint: Member must have value greater than or equal to {min}"));
        } else if value > max {
            self.0.push(format!("Value '{value}' at '{field}' failed to satisfy constraint: Member must have value less than or equal to {max}"));
        }
    }

    fn done(self) -> Result<()> {
        match self.0.len() {
            0 => Ok(()),
            n => Err(validation(format!("{n} validation error{} detected: {}", if n == 1 { "" } else { "s" }, self.0.join("; ")))),
        }
    }
}

/// `DurationSeconds`, if given (checked against `max` by `Checks`).
fn duration(params: &Params, checks: &mut Checks, max: i64) -> Result<Option<i64>> {
    let Some(text) = params.get("DurationSeconds") else { return Ok(None) };
    let n: i64 = text.parse().map_err(|_| validation(format!("Invalid value for parameter DurationSeconds: {text}")))?;
    checks.range(n, "durationSeconds", MIN_DURATION, max);
    Ok(Some(n))
}

fn invalid_parameter(message: impl Into<String>) -> Error {
    error(StatusCode::BAD_REQUEST, "InvalidParameterValue", message)
}

/// An MFA device's code, which Cairn has no devices to check (probed: AWS's
/// answer to one that isn't the caller's).
fn mfa_refused() -> Error {
    error(
        StatusCode::FORBIDDEN,
        "AccessDenied",
        "MultiFactorAuthentication failed, unable to validate MFA code.  Please verify your MFA serial number is valid and associated with this user.",
    )
}

/// What a session's policies are asked as: its inline policy (normalized)
/// and the managed policies' ARNs, checked as STS checks them (probed).
struct SessionPolicies {
    policy: Option<String>,
    arns: Vec<String>,
}

/// What issuing sessions needs: the node, a database connection, and the
/// account (an Iam's, or a web identity's role's).
pub(super) struct Sts<'a> {
    pub app: &'a std::sync::Arc<crate::App>,
    pub client: &'a deadpool_postgres::Object,
    pub account: &'a str,
}

impl Sts<'_> {
    /// The session policies a request asks for (`Policy`, `PolicyArns`).
    async fn session_policies(&self, params: &Params, checks: &mut Checks) -> Result<SessionPolicies> {
        let policy = params.get("Policy").map(str::to_owned);
        if let Some(policy) = &policy {
            checks.length(policy, "policy", 1, MAX_SESSION_POLICY);
        }
        let arns: Vec<String> = (1..).map_while(|n| params.get(&format!("PolicyArns.member.{n}.arn")).map(str::to_owned)).collect();
        Ok(SessionPolicies { policy, arns })
    }

    /// Checks the session policies, once the parameters are valid: the
    /// inline one parses as an identity policy (`Principal`, say, is
    /// STS's "prohibited field"), the ARNs name policies there are.
    async fn checked_session_policies(&self, asked: SessionPolicies) -> Result<SessionPolicies> {
        if asked.arns.len() > MAX_POLICY_ARNS {
            return Err(validation(
                "The limit of ARNs for the PolicyArns parameter was exceeded. 10 ARNs can be requested at most in an API request.",
            ));
        }
        let policy = match &asked.policy {
            Some(text) => match Policy::parse(text, Kind::Identity) {
                Ok(policy) => Some(policy.normalized().to_owned()),
                Err(e) if e.message == "Policy document should not specify a principal." => {
                    return Err(error(StatusCode::BAD_REQUEST, "MalformedPolicyDocument", "Has prohibited field Principal"));
                }
                Err(e) if e.code == "NotImplemented" => return Err(error(StatusCode::NOT_IMPLEMENTED, "NotImplemented", e.message)),
                Err(e) => return Err(error(StatusCode::BAD_REQUEST, "MalformedPolicyDocument", e.message)),
            },
            None => None,
        };
        for arn in &asked.arns {
            if managed::document(self.client, self.account, arn).await?.is_none() {
                return Err(validation(
                    "At least one Policy ARN in the PolicyArns parameter does not match an existing IAM Managed Policy ARN.",
                ));
            }
        }
        Ok(SessionPolicies { policy, arns: asked.arns })
    }

    /// A new session's credentials, sealed, as STS shows them, and its
    /// token's size and utilization (probed: STS's are of 4096 bytes, and
    /// AssumeRole's and GetFederationToken's PackedPolicySize is the same).
    async fn issue(&self, session: &Session) -> Result<(String, String)> {
        let token = self.app.sessions.seal(self.client, session).await?;
        let credentials = format!(
            "<Credentials><AccessKeyId>{}</AccessKeyId><SecretAccessKey>{}</SecretAccessKey><SessionToken>{}</SessionToken>\
             <Expiration>{}</Expiration></Credentials>",
            session.key_id,
            xml_escape(&session.secret),
            xml_escape(&token),
            sessions::iso(session.expires)
        );
        let size = format!(
            "<SessionTokenUtilization>{}</SessionTokenUtilization><SessionTokenSize>{}</SessionTokenSize>",
            token.len() * 100 / TOKEN_ROOM,
            token.len()
        );
        Ok((credentials, size))
    }

    /// A new session of `who`, for `seconds`.
    fn session(&self, who: Who, seconds: i64) -> Result<Session> {
        let now = sessions::now();
        Ok(Session {
            key_id: sessions::new_key_id()?,
            secret: sessions::new_secret()?,
            issued: now,
            expires: now + seconds as u64,
            who,
            policy: None,
            policy_arns: Vec::new(),
            tags: Vec::new(),
            transitive: Vec::new(),
            source_identity: None,
            chained: false,
            provider: None,
        })
    }
}

impl Iam<'_> {
    fn sts(&self) -> Sts<'_> {
        Sts { app: self.app, client: self.client, account: self.account() }
    }

    pub(super) fn get_caller_identity(&self) -> Option<String> {
        Some(format!(
            "<Arn>{}</Arn><UserId>{}</UserId><Account>{}</Account>",
            xml_escape(&self.principal.arn()),
            xml_escape(&self.principal.unique_id()),
            self.principal.account
        ))
    }

    pub(super) async fn assume_role(&mut self, params: &Params) -> Result<Option<String>> {
        let mut checks = Checks(Vec::new());
        let arn = params.required("RoleArn")?.to_owned();
        checks.length(&arn, "roleArn", 20, 2048);
        let name = params.required("RoleSessionName")?.to_owned();
        checks.length(&name, "roleSessionName", 2, 64);
        checks.pattern(&name, "roleSessionName", "+=,.@-", "[\\w+=,.@-]*");
        let external = params.get("ExternalId").map(str::to_owned);
        if let Some(external) = &external {
            checks.length(external, "externalId", 2, 1224);
            checks.pattern(external, "externalId", "+=,.@:/-", "[\\w+=,.@:\\/-]*");
        }
        let source = params.get("SourceIdentity").map(str::to_owned);
        if let Some(source) = &source {
            checks.length(source, "sourceIdentity", 2, 64);
            checks.pattern(source, "sourceIdentity", "+=,.@-", "[\\w+=,.@-]*");
        }
        let seconds = duration(params, &mut checks, roles::SESSION_DURATIONS.end().to_owned() as i64)?;
        let asked = self.sts().session_policies(params, &mut checks).await?;
        let tags = session_tags(params, &mut checks)?;
        let transitive = request_keys_named(params, "TransitiveTagKeys");
        checks.done()?;
        if params.get("SerialNumber").is_some() || params.get("TokenCode").is_some() {
            return Err(mfa_refused());
        }
        check_tags(&tags, &transitive)?;
        // Who assumes it: a user, or a role's session (chaining).
        let caller = self.principal.session.as_ref().map(|s| &s.session);
        if matches!(caller.map(|s| &s.who), Some(Who::Federated { .. })) {
            return Err(error(StatusCode::FORBIDDEN, "AccessDenied", "Roles may not be assumed by federated users"));
        }
        let chained = self.principal.is_role_session();
        // Tags and the source identity a chain passes on.
        let mut tags = tags;
        let mut transitive = transitive;
        let mut source = source;
        if let Some(caller) = caller.filter(|_| chained) {
            for (key, value) in caller.tags.iter().filter(|(k, _)| caller.transitive.iter().any(|t| t.eq_ignore_ascii_case(k))) {
                if tags.iter().any(|(k, _)| k.eq_ignore_ascii_case(key)) {
                    return Err(invalid_parameter(format!(
                        "The tag key {key} is a transitive tag of the calling session: it can't be set again."
                    )));
                }
                tags.push((key.clone(), value.clone()));
                transitive.push(key.clone());
            }
            if let Some(theirs) = &caller.source_identity {
                if source.as_ref().is_some_and(|ours| ours != theirs) {
                    return Err(invalid_parameter("A session's source identity can't be changed by a role it assumes."));
                }
                source = Some(theirs.clone());
            }
        }
        // The role, by its whole ARN; one that isn't there is refused as one
        // that may not be assumed (probed).
        let denied = |action: &str| {
            error(
                StatusCode::FORBIDDEN,
                "AccessDenied",
                format!("User: {} is not authorized to perform: {action} on resource: {arn}", self.principal.arn()),
            )
        };
        let role = match role_of_arn(&arn, self.account()) {
            Some((path, role_name)) => Role::load(self.client, self.account(), role_name)
                .await?
                .filter(|r| r.path == path && r.name == role_name),
            None => None,
        };
        let Some(role) = role else { return Err(denied("sts:AssumeRole")) };
        let trust = Policy::parse(&role.trust, Kind::Trust)
            .map_err(|e| anyhow::anyhow!("role {}'s trust policy doesn't parse: {}", role.name, e.message))?
            .with_ids(role.trust_principals.clone());
        let mut context = Context::default();
        context.set("sts:RoleSessionName", &name);
        if let Some(external) = &external {
            context.set("sts:ExternalId", external);
        }
        if let Some(source) = &source {
            context.set("sts:SourceIdentity", source);
        }
        for (key, value) in &tags {
            context.set(&format!("aws:RequestTag/{key}"), value);
        }
        if !tags.is_empty() {
            context.set_all("aws:TagKeys", tags.iter().map(|(k, _)| k.clone()).collect());
        }
        if !transitive.is_empty() {
            context.set_all("sts:TransitiveTagKeys", transitive.clone());
        }
        let role_arn = role.arn();
        if !self.access.trusted("sts:AssumeRole", &role_arn, &trust, &context) {
            return Err(denied("sts:AssumeRole"));
        }
        if !tags.is_empty() && !self.access.trusted("sts:TagSession", &role_arn, &trust, &context) {
            return Err(denied("sts:TagSession"));
        }
        if params.get("SourceIdentity").is_some() && !self.access.trusted("sts:SetSourceIdentity", &role_arn, &trust, &context) {
            return Err(denied("sts:SetSourceIdentity"));
        }
        let seconds = seconds.unwrap_or(ROLE_DEFAULT.min(role.max_session_duration as i64));
        if chained && seconds > ROLE_DEFAULT {
            return Err(validation("The requested DurationSeconds exceeds the 1 hour session limit for roles assumed by role chaining."));
        }
        if seconds > role.max_session_duration as i64 {
            return Err(validation("The requested DurationSeconds exceeds the MaxSessionDuration set for this role."));
        }
        let policies = self.sts().checked_session_policies(asked).await?;
        let mut session = self.sts().session(Who::Role { id: role.id, session: name.clone() }, seconds)?;
        session.policy = policies.policy;
        session.policy_arns = policies.arns;
        session.tags = tags;
        session.transitive = transitive;
        session.source_identity = source;
        session.chained = chained;
        // A web identity's provider passes on down a chain.
        session.provider = caller.filter(|_| chained).and_then(|c| c.provider.clone());
        let (mut xml, size) = self.sts().issue(&session).await?;
        xml.push_str(&format!(
            "<AssumedRoleUser><AssumedRoleId>{}:{}</AssumedRoleId><Arn>arn:aws:sts::{}:assumed-role/{}/{}</Arn></AssumedRoleUser>",
            roles::unique_id(role.id),
            xml_escape(&name),
            role.account,
            xml_escape(&role.name),
            xml_escape(&name)
        ));
        xml.push_str(&packed(&size));
        if let Some(source) = &session.source_identity {
            xml.push_str(&format!("<SourceIdentity>{}</SourceIdentity>", xml_escape(source)));
        }
        Ok(Some(xml))
    }

    pub(super) async fn get_session_token(&mut self, params: &Params) -> Result<Option<String>> {
        let mut checks = Checks(Vec::new());
        let seconds = duration(params, &mut checks, MAX_DURATION)?;
        checks.done()?;
        if self.principal.session.is_some() {
            return Err(error(StatusCode::FORBIDDEN, "AccessDenied", "Cannot call GetSessionToken with session credentials"));
        }
        if params.get("SerialNumber").is_some() || params.get("TokenCode").is_some() {
            return Err(mfa_refused());
        }
        let session = self.sts().session(Who::User { id: self.principal.id }, seconds.unwrap_or(DEFAULT_LONG))?;
        let (credentials, size) = self.sts().issue(&session).await?;
        Ok(Some(credentials + &size))
    }

    pub(super) async fn get_federation_token(&mut self, params: &Params) -> Result<Option<String>> {
        let mut checks = Checks(Vec::new());
        let name = params.required("Name")?.to_owned();
        checks.length(&name, "name", 2, 32);
        checks.pattern(&name, "name", "+=,.@-", "[\\w+=,.@-]*");
        let seconds = duration(params, &mut checks, MAX_DURATION)?;
        let asked = self.sts().session_policies(params, &mut checks).await?;
        let tags = session_tags(params, &mut checks)?;
        checks.done()?;
        check_tags(&tags, &[])?;
        let refused = || error(StatusCode::FORBIDDEN, "AccessDenied", "Cannot call GetFederationToken with session credentials");
        // A user's own session, or a federated user's, is refused first; a
        // role's session is checked first, as anyone (probed).
        if self.principal.session.is_some() && !self.principal.is_role_session() {
            return Err(refused());
        }
        let arn = format!("arn:aws:sts::{}:federated-user/{name}", self.account());
        let check = crate::s3::actions::Check { action: "sts:GetFederationToken", on: On::Arn(arn.clone()) };
        if !self.access.allows(&check) {
            return Err(error(
                StatusCode::FORBIDDEN,
                "AccessDenied",
                format!("User: {} is not authorized to perform: sts:GetFederationToken on resource: {arn}", self.principal.arn()),
            ));
        }
        if self.principal.session.is_some() {
            return Err(refused());
        }
        let policies = self.sts().checked_session_policies(asked).await?;
        let mut session = self.sts().session(Who::Federated { id: self.principal.id, name: name.clone() }, seconds.unwrap_or(DEFAULT_LONG))?;
        session.policy = policies.policy;
        session.policy_arns = policies.arns;
        session.tags = tags;
        let (mut xml, size) = self.sts().issue(&session).await?;
        xml.push_str(&format!(
            "<FederatedUser><FederatedUserId>{}:{}</FederatedUserId><Arn>{}</Arn></FederatedUser>",
            self.account(),
            xml_escape(&name),
            xml_escape(&arn),
        ));
        xml.push_str(&packed(&size));
        Ok(Some(xml))
    }

    pub(super) async fn get_access_key_info(&mut self, params: &Params) -> Result<Option<String>> {
        let mut checks = Checks(Vec::new());
        let id = params.required("AccessKeyId")?.to_owned();
        checks.length(&id, "accessKeyId", 16, 128);
        checks.done()?;
        let check = crate::s3::actions::Check { action: "sts:GetAccessKeyInfo", on: On::Account };
        let verdict = self.access.verdict(&check);
        if verdict != crate::policy::Verdict::Allow {
            return Err(error(
                StatusCode::FORBIDDEN,
                "AccessDenied",
                format!(
                    "User: {} is not authorized to perform: sts:GetAccessKeyInfo {}",
                    self.principal.arn(),
                    verdict.why("sts:GetAccessKeyInfo", self.access.boundary())
                ),
            ));
        }
        // A temporary key is the account's if it looks like one (Cairn keeps
        // no record of them); a long-term one if it's there.
        let known = sessions::is_temporary(&id) && id.len() == 20
            || self.client.query_opt_cached("SELECT 1 FROM access_keys WHERE access_key_id = $1", &[&id]).await?.is_some();
        if !known {
            return Err(validation("Access key ID is not valid."));
        }
        Ok(Some(format!("<Account>{}</Account>", self.account())))
    }
}

/// A web identity token's error, as STS's (`InvalidIdentityToken`).
fn invalid_identity(message: impl Into<String>) -> Error {
    error(StatusCode::BAD_REQUEST, "InvalidIdentityToken", message)
}

/// The session tags and transitive keys a web identity token carries
/// (`https://aws.amazon.com/tags`: `principal_tags`, each a list of one
/// value, and `transitive_tag_keys`), as AWS reads them.
fn token_tags(claims: &crate::oidc::Claims) -> Result<(Vec<(String, String)>, Vec<String>)> {
    let Some(value) = claims.get("https://aws.amazon.com/tags") else { return Ok((Vec::new(), Vec::new())) };
    let bad = || invalid_identity("The token's session tags (https://aws.amazon.com/tags) aren't valid.");
    let mut tags = Vec::new();
    if let Some(principal) = value.get("principal_tags") {
        let principal = principal.as_object().ok_or_else(bad)?;
        for (key, values) in principal {
            let value = match values {
                serde_json::Value::Array(values) if values.len() == 1 => values[0].as_str().ok_or_else(bad)?,
                serde_json::Value::String(value) => value.as_str(),
                _ => return Err(bad()),
            };
            tags.push((key.clone(), value.to_owned()));
        }
    }
    let transitive = match value.get("transitive_tag_keys") {
        Some(serde_json::Value::Array(keys)) => keys.iter().map(|k| k.as_str().map(str::to_owned).ok_or_else(bad)).collect::<Result<_>>()?,
        Some(_) => return Err(bad()),
        None => Vec::new(),
    };
    Ok((tags, transitive))
}

impl Sts<'_> {
    /// AssumeRoleWithWebIdentity: unsigned, the token (an OIDC provider's ID
    /// token) its authentication. The token's issuer must be one of the
    /// account's providers (matched before anything is fetched, so the
    /// caller never picks what Cairn fetches), its signature by the
    /// issuer's keys, its audience one of the provider's client IDs; then
    /// the role's trust policy must let the provider's web identities in,
    /// with the token's claims as condition keys (`<url>:sub`, `:aud`,
    /// `:amr`).
    pub(super) async fn assume_role_with_web_identity(&self, access: &Access, params: &Params) -> Result<Option<String>> {
        let mut checks = Checks(Vec::new());
        let arn = params.required("RoleArn")?.to_owned();
        checks.length(&arn, "roleArn", 20, 2048);
        let name = params.required("RoleSessionName")?.to_owned();
        checks.length(&name, "roleSessionName", 2, 64);
        checks.pattern(&name, "roleSessionName", "+=,.@-", "[\\w+=,.@-]*");
        let token = params.required("WebIdentityToken")?.to_owned();
        if token.chars().count() < 4 {
            checks.0.push("Value at 'webIdentityToken' failed to satisfy constraint: Member must have length greater than or equal to 4".into());
        } else if token.chars().count() > 20000 {
            checks.0.push("Value at 'webIdentityToken' failed to satisfy constraint: Member must have length less than or equal to 20000".into());
        }
        let seconds = duration(params, &mut checks, roles::SESSION_DURATIONS.end().to_owned() as i64)?;
        let asked = self.session_policies(params, &mut checks).await?;
        checks.done()?;
        if params.get("ProviderId").is_some() {
            return Err(invalid_parameter("Cairn takes OpenID Connect ID tokens only, not OAuth 2.0 access tokens (ProviderId)."));
        }
        // The provider, by the token's issuer.
        let jwt = crate::oidc::Jwt::parse(&token)
            .map_err(|_| invalid_identity("The ID token provided is not a valid JWT. (You may see this error if you sent an Access Token)"))?;
        let issuer = jwt.text("iss").unwrap_or("").to_owned();
        let url = issuer.strip_prefix("https://").map(|u| u.trim_end_matches('/'));
        let provider = match url {
            Some(url) if !url.is_empty() => Provider::load(self.client, self.account, url).await?,
            _ => None,
        };
        let Some(provider) = provider else {
            return Err(invalid_identity(format!("No OpenIDConnect provider found in your account for {issuer}")));
        };
        let reach = provider.reach(iam_oidc::private_allowed(self.client).await?);
        let unreachable = |e: anyhow::Error| {
            error(
                StatusCode::BAD_REQUEST,
                "IDPCommunicationError",
                format!("Couldn't retrieve verification key from your identity provider, please reference AssumeRoleWithWebIdentity documentation for requirements ({e:#})"),
            )
        };
        let found = crate::oidc::discovery(&provider.issuer(), &reach).await.map_err(unreachable)?;
        let expect = crate::oidc::Expect { found: &found, audiences: &provider.client_ids, nonce: None, party: false };
        let (jwt, audience) = match crate::oidc::verify(&token, &reach, &expect).await.map_err(unreachable)? {
            Ok(verified) => verified,
            Err(Rejected::Expired { exp, now }) => {
                return Err(error(
                    StatusCode::BAD_REQUEST,
                    "ExpiredTokenException",
                    format!("Token expired: current date/time {now} must be before the expiration date/time{exp}"),
                ));
            }
            Err(Rejected::Audience) => return Err(invalid_identity("Incorrect token audience")),
            Err(Rejected::Signature(_)) => return Err(invalid_identity("The token's signature isn't the identity provider's.")),
            Err(Rejected::Issuer) => return Err(invalid_identity("Issuer mismatch")),
            Err(Rejected::NotYet) => return Err(invalid_identity("The token isn't valid yet.")),
            Err(Rejected::Malformed(_) | Rejected::Party | Rejected::Nonce) => {
                return Err(invalid_identity("The ID token provided is not a valid JWT. (You may see this error if you sent an Access Token)"));
            }
        };
        let Some(subject) = jwt.text("sub").filter(|s| !s.is_empty()).map(str::to_owned) else {
            return Err(invalid_identity("The token has no subject (sub)."));
        };
        let (tags, transitive) = token_tags(&jwt.claims)?;
        check_tags(&tags, &transitive)?;
        let source = match jwt.claims.get("https://aws.amazon.com/source_identity") {
            Some(value) => {
                let source = value.as_str().unwrap_or("").to_owned();
                let mut checks = Checks(Vec::new());
                checks.length(&source, "sourceIdentity", 2, 64);
                checks.pattern(&source, "sourceIdentity", "+=,.@-", "[\\w+=,.@-]*");
                checks.done()?;
                Some(source)
            }
            None => None,
        };
        // The role, by its whole ARN; one that isn't there is refused as one
        // that may not be assumed.
        let denied = || error(StatusCode::FORBIDDEN, "AccessDenied", "Not authorized to perform sts:AssumeRoleWithWebIdentity");
        let role = match role_of_arn(&arn, self.account) {
            Some((path, role_name)) => Role::load(self.client, self.account, role_name)
                .await?
                .filter(|r| r.path == path && r.name == role_name),
            None => None,
        };
        let Some(role) = role else { return Err(denied()) };
        let trust = Policy::parse(&role.trust, Kind::Trust)
            .map_err(|e| anyhow::anyhow!("role {}'s trust policy doesn't parse: {}", role.name, e.message))?
            .with_ids(role.trust_principals.clone());
        let provider_arn = provider.arn();
        let mut context = Context::default();
        context.set("sts:RoleSessionName", &name);
        context.set("aws:FederatedProvider", &provider_arn);
        context.set(&format!("{}:sub", provider.url), &subject);
        context.set(&format!("{}:aud", provider.url), &audience);
        match jwt.claims.get("amr") {
            Some(serde_json::Value::Array(amr)) => {
                context.set_all(&format!("{}:amr", provider.url), amr.iter().filter_map(|a| a.as_str().map(str::to_owned)).collect());
            }
            Some(serde_json::Value::String(amr)) => context.set(&format!("{}:amr", provider.url), amr),
            _ => {}
        }
        if let Some(source) = &source {
            context.set("sts:SourceIdentity", source);
        }
        for (key, value) in &tags {
            context.set(&format!("aws:RequestTag/{key}"), value);
        }
        if !tags.is_empty() {
            context.set_all("aws:TagKeys", tags.iter().map(|(k, _)| k.clone()).collect());
        }
        if !transitive.is_empty() {
            context.set_all("sts:TransitiveTagKeys", transitive.clone());
        }
        let role_arn = role.arn();
        let trusted = |action: &str| access.web_identity_trusted(&provider_arn, action, &role_arn, &trust, &context);
        if !trusted("sts:AssumeRoleWithWebIdentity") {
            return Err(denied());
        }
        if !tags.is_empty() && !trusted("sts:TagSession") {
            return Err(error(StatusCode::FORBIDDEN, "AccessDenied", "Not authorized to perform sts:TagSession"));
        }
        if source.is_some() && !trusted("sts:SetSourceIdentity") {
            return Err(error(StatusCode::FORBIDDEN, "AccessDenied", "Not authorized to perform sts:SetSourceIdentity"));
        }
        let seconds = seconds.unwrap_or(ROLE_DEFAULT.min(role.max_session_duration as i64));
        if seconds > role.max_session_duration as i64 {
            return Err(validation("The requested DurationSeconds exceeds the MaxSessionDuration set for this role."));
        }
        let policies = self.checked_session_policies(asked).await?;
        let mut session = self.session(Who::Role { id: role.id, session: name.clone() }, seconds)?;
        session.policy = policies.policy;
        session.policy_arns = policies.arns;
        session.tags = tags;
        session.transitive = transitive;
        session.source_identity = source;
        session.provider = Some(provider_arn);
        let (mut xml, size) = self.issue(&session).await?;
        xml.push_str(&format!("<SubjectFromWebIdentityToken>{}</SubjectFromWebIdentityToken>", xml_escape(&subject)));
        xml.push_str(&format!(
            "<AssumedRoleUser><AssumedRoleId>{}:{}</AssumedRoleId><Arn>arn:aws:sts::{}:assumed-role/{}/{}</Arn></AssumedRoleUser>",
            roles::unique_id(role.id),
            xml_escape(&name),
            role.account,
            xml_escape(&role.name),
            xml_escape(&name)
        ));
        xml.push_str(&packed(&size));
        xml.push_str(&format!("<Provider>{}</Provider><Audience>{}</Audience>", xml_escape(&issuer), xml_escape(&audience)));
        if let Some(source) = &session.source_identity {
            xml.push_str(&format!("<SourceIdentity>{}</SourceIdentity>", xml_escape(source)));
        }
        Ok(Some(xml))
    }
}

/// The path and name of the role `arn` names, if it's one of `account`'s.
fn role_of_arn<'a>(arn: &'a str, account: &str) -> Option<(String, &'a str)> {
    let rest = arn.strip_prefix("arn:aws:iam::")?.strip_prefix(account)?.strip_prefix(":role/")?;
    match rest.rsplit_once('/') {
        Some((path, name)) => Some((format!("/{path}/"), name)),
        None => Some(("/".to_owned(), rest)),
    }
}

/// The tags a request asks a session for (`Tags.member.N.Key`, `.Value`).
fn session_tags(params: &Params, checks: &mut Checks) -> Result<Vec<(String, String)>> {
    let mut tags = Vec::new();
    for n in 1.. {
        let key = params.get(&format!("Tags.member.{n}.Key"));
        let value = params.get(&format!("Tags.member.{n}.Value"));
        if key.is_none() && value.is_none() {
            break;
        }
        let (key, value) = (key.unwrap_or("").to_owned(), value.unwrap_or("").to_owned());
        checks.length(&key, &format!("tags.{n}.member.key"), 1, 128);
        checks.length(&value, &format!("tags.{n}.member.value"), 0, 256);
        tags.push((key, value));
    }
    if tags.len() > crate::users::MAX_TAGS {
        let shown: Vec<String> = tags.iter().map(|(k, v)| format!("Tag(key={k}, value={v})")).collect();
        checks.0.push(format!(
            "Value '[{}]' at 'tags' failed to satisfy constraint: Member must have length less than or equal to {}",
            shown.join(", "),
            crate::users::MAX_TAGS
        ));
    }
    Ok(tags)
}

/// Checks a session's tags as STS does (probed): no `aws:` keys, no key
/// twice regardless of case, transitive keys among them.
fn check_tags(tags: &[(String, String)], transitive: &[String]) -> Result<()> {
    if tags.iter().any(|(k, _)| k.to_ascii_lowercase().starts_with("aws:")) {
        return Err(invalid_parameter("Tag keys beginning with aws: are reserved for system use."));
    }
    let mut seen = std::collections::HashSet::new();
    if !tags.iter().all(|(k, _)| seen.insert(k.to_lowercase())) {
        return Err(invalid_parameter("Duplicate tag keys found. Please note that Tag keys are case insensitive."));
    }
    if transitive.iter().any(|t| !tags.iter().any(|(k, _)| k.eq_ignore_ascii_case(t))) {
        return Err(invalid_parameter("The specified transitive tag key must be included in the requested tags."));
    }
    Ok(())
}

/// PackedPolicySize, then the token's size and utilization (`size`, as
/// `issue` gives them): STS's PackedPolicySize is its utilization now
/// (probed).
fn packed(size: &str) -> String {
    let utilization = size
        .strip_prefix("<SessionTokenUtilization>")
        .and_then(|rest| rest.split_once('<'))
        .map_or("0", |(n, _)| n);
    format!("<PackedPolicySize>{utilization}</PackedPolicySize>{size}")
}
