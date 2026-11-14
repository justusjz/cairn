//! IAM's policy language, as S3 takes it: identity policies, attached to
//! users, and bucket policies (see `plans/policies.md`). Parsing checks a
//! policy as S3 (or IAM) checks it when it's set; evaluating decides whether
//! one request is allowed. No I/O: what a request is, and which policies
//! apply to it, is the caller's.
//!
//! A request is allowed if some applicable policy allows it, and none denies
//! it: an explicit Deny wins (see `decide`). Within one account (Cairn has
//! one, until tenants), a user's identity policies and the bucket's policy
//! count alike, as in S3.

mod condition;
mod pattern;
pub mod s3_actions;

use std::collections::HashMap;

pub use condition::{Network, Support, date, support};
use condition::Condition;
use pattern::{Pattern, Syntax, arn_matches, arn_parts};
use s3_actions::{ACTIONS, Applies};

/// The most a bucket policy may be, in bytes, as in S3.
pub const MAX_BUCKET_POLICY: usize = 20 << 10;

/// Why a policy was refused.
#[derive(Clone, Debug, PartialEq)]
pub struct Invalid {
    /// `MalformedPolicy` (400), or `NotImplemented` (501) for what S3 has and
    /// Cairn doesn't.
    pub code: &'static str,
    pub message: String,
}

impl Invalid {
    fn malformed(message: impl Into<String>) -> Invalid {
        Invalid { code: "MalformedPolicy", message: message.into() }
    }

    fn unsupported(message: impl Into<String>) -> Invalid {
        Invalid { code: "NotImplemented", message: message.into() }
    }
}

/// The values of a request's condition keys (several, for a multivalued
/// key), by their names regardless of case.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Context {
    values: HashMap<String, Vec<String>>,
}

impl Context {
    pub fn set(&mut self, key: &str, value: impl Into<String>) {
        self.values.insert(key.to_ascii_lowercase(), vec![value.into()]);
    }

    /// A multivalued key's values (`aws:TagKeys`).
    pub fn set_all(&mut self, key: &str, values: Vec<String>) {
        self.values.insert(key.to_ascii_lowercase(), values);
    }

    /// Sets every key `other` has, as it has it.
    pub fn extend(&mut self, other: &Context) {
        for (key, values) in &other.values {
            self.values.insert(key.clone(), values.clone());
        }
    }

    pub fn get(&self, key: &str) -> Option<&[String]> {
        self.values.get(&key.to_ascii_lowercase()).map(Vec::as_slice)
    }

    /// The context `action` is decided in: every global (`aws:`) key, but
    /// of the `s3:` keys only those S3 sets for it (see `ACTIONS`). A
    /// request may carry `?prefix=` or `x-amz-acl` whatever it does; S3 has
    /// `s3:prefix` only for a listing, `s3:x-amz-acl` only for a write that
    /// takes an ACL, and so on, so a condition on such a key holds only
    /// where it's meant to.
    pub fn for_action(mut self, action: &str) -> Context {
        let name = action.split_once(':').filter(|(service, _)| service.eq_ignore_ascii_case("s3")).map(|(_, n)| n);
        let keys = name
            .and_then(|name| ACTIONS.iter().find(|(a, _, _)| a.eq_ignore_ascii_case(name)))
            .map_or(&[][..], |(_, _, keys)| *keys);
        self.values.retain(|key, _| !key.starts_with("s3:") || takes_key(keys, key));
        self
    }
}

/// Who makes a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Principal<'a> {
    /// An unsigned request.
    Anonymous,
    /// A user of `account` (its 12-digit ID), by its name and its ID
    /// (which a bucket policy names it by: see `Policy::with_ids`).
    User { account: &'a str, name: &'a str, id: &'a str },
    /// A role's session: its role, by its name and ID (which a policy names
    /// it by, as a user), and the session's name.
    Session { account: &'a str, role: &'a str, id: &'a str, session: &'a str },
    /// A federated user (GetFederationToken's), by its name.
    Federated { account: &'a str, name: &'a str },
    /// A web identity (AssumeRoleWithWebIdentity's caller), by its OIDC
    /// provider's ARN (`arn:aws:iam::<account>:oidc-provider/<url>`).
    WebIdentity { provider: &'a str },
}

/// How a statement is about a principal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reach {
    /// By naming it (or everyone): a resource policy's Allow so is the
    /// principal's, uncapped by its boundary or session policies.
    Direct,
    /// By naming the role a session is of: what it allows is capped by the
    /// role's boundary and the session's policies (probed).
    Role,
}

/// One check of a request: whether `principal` may do `action` (`s3:...`) to
/// `resource` (an ARN), in `context`.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    pub principal: Principal<'a>,
    pub action: &'a str,
    pub resource: &'a str,
    pub context: &'a Context,
}

/// What one policy says about a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    /// Neither: no statement applies.
    NotApplicable,
}

/// The verdict on a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// A statement denies it, in an identity policy (`identity`) or the
    /// bucket's.
    ExplicitDeny { identity: bool },
    /// A statement of the user's permissions boundary denies it.
    BoundaryDeny,
    /// Nothing allows it.
    ImplicitDeny,
    /// Its permissions boundary doesn't allow it (and no bucket policy
    /// allows it by itself).
    OutsideBoundary,
    /// A statement of a session policy denies it.
    SessionDeny,
    /// No session policy allows it (and no bucket policy allows it by
    /// itself).
    OutsideSession,
}

impl Verdict {
    /// Why a request for `action` was denied, as AWS's messages end
    /// (probed): `boundary` is the ARN of the user's permissions boundary.
    pub fn why(self, action: &str, boundary: Option<&str>) -> String {
        match self {
            Verdict::ExplicitDeny { identity: true } => "with an explicit deny in an identity-based policy".to_owned(),
            Verdict::ExplicitDeny { identity: false } => "with an explicit deny in a resource-based policy".to_owned(),
            Verdict::BoundaryDeny => {
                format!("with an explicit deny in a permissions boundary: {}", boundary.unwrap_or_default())
            }
            Verdict::OutsideBoundary => format!("because no permissions boundary allows the {action} action"),
            Verdict::SessionDeny => "with an explicit deny in a session policy".to_owned(),
            Verdict::OutsideSession => format!("because no session policy allows the {action} action"),
            _ => format!("because no identity-based policy allows the {action} action"),
        }
    }
}

/// The verdict on a request by `identity` (the user's policies; none count
/// for an anonymous request) and `bucket` (the bucket's policy, if it has
/// one): an explicit Deny in either denies; else an Allow in either allows;
/// else it's denied.
#[cfg(test)]
pub fn verdict<'p>(
    identity: impl IntoIterator<Item = &'p Policy>,
    bucket: Option<&'p Policy>,
    request: &Request,
) -> Verdict {
    verdict_across(identity, Caps::default(), bucket, request, false)
}

/// What caps a principal's identity policies, besides themselves.
#[derive(Clone, Copy, Debug, Default)]
pub struct Caps<'p> {
    /// Its permissions boundary.
    pub boundary: Option<&'p Policy>,
    /// A session's policies, if it has any (or must: a federated user's,
    /// which with none may do nothing): they allow only what one of them
    /// allows too.
    pub session: Option<&'p [&'p Policy]>,
}

/// As `verdict`, for a principal whose identity policies `caps` caps (a
/// permissions boundary, a session's policies), and a resource of another
/// account than the principal's (`cross`), when those are so. A cap allows
/// the identity policies only what it allows too, and a Deny in it denies.
/// Within the account, a bucket policy's Allow that names the principal
/// itself (a user, a session), or everyone, isn't capped (probed); one that
/// names the role a session is of is, by the role's boundary and the
/// session's policies (probed). Across accounts, an identity policy's Allow
/// alone isn't enough, nor the bucket's alone: both must allow it, as in
/// AWS.
pub fn verdict_across<'p>(
    identity: impl IntoIterator<Item = &'p Policy>,
    caps: Caps<'p>,
    bucket: Option<&'p Policy>,
    request: &Request,
    cross: bool,
) -> Verdict {
    let boundary = caps.boundary;
    let mut identity_allows = false;
    let anonymous = request.principal == Principal::Anonymous;
    for policy in identity.into_iter().filter(|_| !anonymous) {
        match policy.evaluate(request) {
            Decision::Deny => return Verdict::ExplicitDeny { identity: true },
            Decision::Allow => identity_allows = true,
            Decision::NotApplicable => {}
        }
    }
    let boundary_allows = match boundary.filter(|_| !anonymous).map(|policy| policy.evaluate(request)) {
        Some(Decision::Deny) => return Verdict::BoundaryDeny,
        Some(Decision::Allow) | None => true,
        Some(Decision::NotApplicable) => false,
    };
    let mut session_allows = true;
    if let Some(policies) = caps.session.filter(|_| !anonymous) {
        session_allows = false;
        for policy in policies {
            match policy.evaluate(request) {
                Decision::Deny => return Verdict::SessionDeny,
                Decision::Allow => session_allows = true,
                Decision::NotApplicable => {}
            }
        }
    }
    let (bucket_allows, bucket_direct) = match bucket.map(|policy| policy.evaluate_reach(request, cross)) {
        Some((Decision::Deny, _)) => return Verdict::ExplicitDeny { identity: false },
        Some((Decision::Allow, direct)) => (true, direct),
        _ => (false, false),
    };
    let capped = boundary_allows && session_allows;
    let allowed = match cross && !anonymous {
        true => identity_allows && capped && bucket_allows,
        false => identity_allows && capped || bucket_direct || bucket_allows && capped,
    };
    // A boundary that doesn't allow it is why, whether or not an identity
    // policy does; then the identity policies, then the session's (probed).
    // Allowed by the bucket's policy through the role, only the caps are.
    match allowed {
        true => Verdict::Allow,
        false if !boundary_allows => Verdict::OutsideBoundary,
        false if !identity_allows && !bucket_allows => Verdict::ImplicitDeny,
        false if !session_allows => Verdict::OutsideSession,
        false => Verdict::ImplicitDeny,
    }
}

/// Whether a role's trust policy lets `request`'s principal assume it (or
/// tag its session, ...), with the principal's identity policies (capped by
/// `caps`): a Deny anywhere denies; else the trust policy must allow it, by
/// naming the principal itself (or everyone), or by naming its account,
/// which leaves it to the identity policies (probed: a trust policy naming
/// someone else allows nothing, whatever the identity policies say).
pub fn trust_allows<'p>(
    identity: impl IntoIterator<Item = &'p Policy>,
    caps: Caps<'p>,
    trust: &Policy,
    request: &Request,
) -> bool {
    let mut identity_allows = false;
    for policy in identity {
        match policy.evaluate(request) {
            Decision::Deny => return false,
            Decision::Allow => identity_allows = true,
            Decision::NotApplicable => {}
        }
    }
    let boundary_allows = match caps.boundary.map(|policy| policy.evaluate(request)) {
        Some(Decision::Deny) => return false,
        Some(Decision::Allow) | None => true,
        Some(Decision::NotApplicable) => false,
    };
    let mut session_allows = true;
    if let Some(policies) = caps.session {
        session_allows = false;
        for policy in policies {
            match policy.evaluate(request) {
                Decision::Deny => return false,
                Decision::Allow => session_allows = true,
                Decision::NotApplicable => {}
            }
        }
    }
    match trust.evaluate_trust(request) {
        (Decision::Deny, _) => false,
        (Decision::Allow, true) => true,
        (Decision::Allow, false) => identity_allows && boundary_allows && session_allows,
        (Decision::NotApplicable, _) => false,
    }
}

/// The actions on a bucket's policy, which no other account may take,
/// whatever it allows (see `s3::access::Access::foreign`). (A policy that
/// denies everyone them is undone with `cairn bucket-policy delete`.)
pub const POLICY_ACTIONS: [&str; 3] = ["s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy"];

/// What a policy is attached to, which decides what it may say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind<'a> {
    /// A user's: no `Principal`, no `Id`.
    Identity,
    /// A bucket's: every statement names its principals, and only the
    /// bucket and its objects are resources.
    Bucket(&'a str),
    /// A role's trust policy (its AssumeRolePolicyDocument): every statement
    /// names its principals, no resources (it's about the role), and only
    /// the actions that assume a role (`TRUST_ACTIONS`).
    Trust,
}

/// The actions a trust policy may name (probed: no wildcards, not
/// `NotAction`).
pub const TRUST_ACTIONS: &[&str] = &[
    "sts:AssumeRole",
    "sts:AssumeRoleWithWebIdentity",
    "sts:AssumeRoleWithSAML",
    "sts:TagSession",
    "sts:SetSourceIdentity",
    "sts:SetContext",
];

/// The condition keys of STS's that Cairn decides, lowercase, in trust
/// policies.
const STS_KEYS: &[&str] = &["sts:externalid", "sts:rolesessionname", "sts:sourceidentity", "sts:transitivetagkeys"];

#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    /// `2012-10-17`: policy variables are variables. Before (`2008-10-17`,
    /// or none), they're text.
    variables: bool,
    statements: Vec<Statement>,
    /// The policy as S3 keeps it, and gives it back (see `normalized`).
    normalized: String,
    /// The IDs of the users a bucket policy names, by their ARNs, as they
    /// were when it was set (see `with_ids`).
    ids: HashMap<String, String>,
}

#[derive(Clone, Debug, PartialEq)]
struct Statement {
    allow: bool,
    /// `None` in identity policies.
    principals: Option<Principals>,
    actions: Matches,
    resources: Matches,
    conditions: Vec<Condition>,
}

/// A list of patterns, or `Not...`: everything but them.
#[derive(Clone, Debug, PartialEq)]
struct Matches {
    not: bool,
    patterns: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
struct Principals {
    not: bool,
    /// `"*"`, or `{"AWS": "*"}`: everyone, anonymous too.
    everyone: bool,
    /// Users, by their account, and path and name
    /// (`arn:aws:iam::<account>:user/<path…/name>`, without the path's
    /// leading `/`).
    users: Vec<(String, String)>,
    /// Accounts (an ID, or its root ARN).
    accounts: Vec<String>,
    /// Roles, by their account, and path and name, as users.
    roles: Vec<(String, String)>,
    /// Role sessions, by their account, role name and session name
    /// (`arn:aws:sts::<account>:assumed-role/<role>/<session>`).
    sessions: Vec<(String, String, String)>,
    /// Identity providers (`Federated`), by their ARNs: web identities of
    /// an OIDC provider of the account.
    federated: Vec<String>,
}

impl Principals {
    /// Whether the statement is about `principal`. A user it names is the
    /// one that had the name when the policy was set (`ids`), as in S3: not
    /// one made with the name later.
    fn about(&self, principal: Principal, allow: bool, ids: &HashMap<String, String>, cross: bool) -> Option<Reach> {
        let direct = |yes: bool| yes.then_some(Reach::Direct);
        let whole = |account: &str| self.accounts.iter().any(|a| a == account);
        match principal {
            Principal::Anonymous => direct(self.everyone != self.not),
            Principal::Session { account, role, id, session } => {
                let named = self.sessions.iter().any(|(a, r, s)| a == account && r == role && s == session);
                let by_role = self.roles.iter().any(|(a, n)| a == account && ids.get(&role_arn(a, n)).is_some_and(|named| named == id));
                if self.not {
                    return direct(!(self.everyone || named || by_role));
                }
                if self.everyone || named {
                    Some(Reach::Direct)
                } else if by_role {
                    Some(Reach::Role)
                } else {
                    direct(whole(account) && (!allow || cross))
                }
            }
            Principal::Federated { account, .. } => match self.not {
                true => direct(!self.everyone),
                false => direct(self.everyone || (whole(account) && (!allow || cross))),
            },
            // Only a statement naming its provider lets a web identity in;
            // everyone (`*`) only denies it. (Probe: whether `*` allows.)
            Principal::WebIdentity { provider } => {
                let named = self.federated.iter().any(|f| f == provider);
                match self.not {
                    true => direct(!(self.everyone || named)),
                    false => direct(named || (self.everyone && !allow)),
                }
            }
            Principal::User { account, id, .. } => {
                // By its ID: the user the ARN named when the policy was
                // set, renamed or moved since or not (probed), and not one
                // that has the ARN since.
                let user = self.users.iter().any(|(a, n)| {
                    a == account && ids.get(&user_arn(a, n)).is_some_and(|named| named == id)
                });
                let whole = whole(account);
                if self.not {
                    // NotPrincipal leaves out the users it names (as S3 does,
                    // probed), not an account's users for naming the account.
                    direct(!(self.everyone || user))
                } else {
                    // An account allows nothing by itself: it leaves it to the
                    // account's identity policies. It does deny all of the
                    // account's users (probed). For a request from another
                    // account than the bucket's (`cross`), naming the account
                    // is the bucket's side of what both sides must allow.
                    direct(self.everyone || user || (whole && (!allow || cross)))
                }
            }
        }
    }
}

impl Matches {
    fn any(&self, matches: impl Fn(&str) -> bool) -> bool {
        self.patterns.iter().any(|p| matches(p)) != self.not
    }
}

impl Statement {
    /// Whether it applies to `request`, and how it's about its principal.
    fn applies(&self, request: &Request, variables: bool, ids: &HashMap<String, String>, cross: bool) -> Option<Reach> {
        let reach = match &self.principals {
            Some(principals) => principals.about(request.principal, self.allow, ids, cross)?,
            None => Reach::Direct,
        };
        let syntax = Syntax { wildcards: true, variables: None };
        let action_matches = |p: &str| Pattern::new(p, syntax).is_some_and(|p| p.matches(request.action, true));
        let vars = variables.then_some(request.context);
        let applies = self.actions.any(action_matches)
            && self.resources.any(|p| arn_matches(p, request.resource, vars))
            && self.conditions.iter().all(|c| c.holds(request.context, variables));
        applies.then_some(reach)
    }
}

impl Policy {
    /// What the policy says about `request`.
    pub fn evaluate(&self, request: &Request) -> Decision {
        self.evaluate_across(request, false)
    }

    /// As `evaluate`, for a request from another account than the
    /// resource's (`cross`), when it's so.
    pub fn evaluate_across(&self, request: &Request, cross: bool) -> Decision {
        self.evaluate_reach(request, cross).0
    }

    /// As `evaluate_across`, and whether an Allow names the principal itself
    /// (or everyone), not only the role a session is of (see `Reach`).
    fn evaluate_reach(&self, request: &Request, cross: bool) -> (Decision, bool) {
        let mut decision = Decision::NotApplicable;
        let mut direct = false;
        for statement in &self.statements {
            let Some(reach) = statement.applies(request, self.variables, &self.ids, cross) else { continue };
            if !statement.allow {
                return (Decision::Deny, false);
            }
            decision = Decision::Allow;
            direct |= reach == Reach::Direct;
        }
        (decision, direct)
    }

    /// What it says about `request` as a role's trust policy: whether it
    /// denies it, allows it by naming the principal itself (or everyone),
    /// or allows it by naming the principal's account, which leaves the
    /// rest to the principal's identity policies (see `sts`).
    pub fn evaluate_trust(&self, request: &Request) -> (Decision, bool) {
        // Naming the account is an Allow too, as across accounts.
        let (decision, _) = self.evaluate_reach(request, true);
        let (_, direct) = self.evaluate_reach(request, false);
        (decision, direct)
    }

    /// The policy, naming by `ids` (ARN → ID) the users it names: as they
    /// were when it was set (`buckets.policy_principals`). A user it names
    /// that isn't in `ids` is none.
    pub fn with_ids(mut self, ids: HashMap<String, String>) -> Policy {
        self.ids = ids;
        self
    }

    /// The policy as GetBucketPolicy shows it: as `normalized`, but each
    /// user that `gone` gives an ID for (by its ARN) named by that ID, as S3
    /// shows a user that was deleted.
    pub fn shown(&self, kind: Kind, gone: &HashMap<String, String>) -> String {
        if gone.is_empty() {
            return self.normalized.clone();
        }
        let rename = |arn: &str| gone.get(arn).cloned();
        Policy::parse_as(&self.normalized, kind, &rename).map_or_else(|_| self.normalized.clone(), |p| p.normalized)
    }

    /// The users it names as principals, (account, name): they must exist.
    pub fn users(&self) -> impl Iterator<Item = (&str, &str)> {
        self.principals().flat_map(|p| p.users.iter().map(|(a, n)| (a.as_str(), n.as_str())))
    }

    /// The accounts it names as principals: they must exist.
    pub fn accounts(&self) -> impl Iterator<Item = &str> {
        self.principals().flat_map(|p| p.accounts.iter().map(String::as_str))
    }

    /// The roles it names as principals, (account, path and name): they
    /// must exist.
    pub fn roles(&self) -> impl Iterator<Item = (&str, &str)> {
        self.principals().flat_map(|p| p.roles.iter().map(|(a, n)| (a.as_str(), n.as_str())))
    }

    /// The role sessions it names as principals, (account, role name,
    /// session name): their roles must exist.
    pub fn sessions(&self) -> impl Iterator<Item = (&str, &str, &str)> {
        self.principals().flat_map(|p| p.sessions.iter().map(|(a, r, s)| (a.as_str(), r.as_str(), s.as_str())))
    }

    fn principals(&self) -> impl Iterator<Item = &Principals> {
        self.statements.iter().filter_map(|s| s.principals.as_ref())
    }

    /// Whether the policy makes its bucket public, as Block Public Access
    /// defines it: some Allow is for everyone, without a condition that
    /// limits it to fixed values of a key that only some principals or
    /// networks have (an address, a VPC endpoint, an account, ...).
    pub fn is_public(&self) -> bool {
        const LIMITING: &[&str] = &[
            "aws:SourceIp",
            "aws:SourceArn",
            "aws:SourceVpc",
            "aws:SourceVpce",
            "aws:SourceOwner",
            "aws:SourceAccount",
            "aws:PrincipalArn",
            "aws:PrincipalAccount",
            "aws:PrincipalOrgID",
            "aws:userid",
            "s3:x-amz-server-side-encryption-aws-kms-key-id",
            "s3:DataAccessPointArn",
            "s3:DataAccessPointAccount",
        ];
        self.statements.iter().any(|s| {
            let everyone = s.principals.as_ref().is_some_and(|p| p.everyone && !p.not);
            let limited = LIMITING.iter().any(|key| s.conditions.iter().any(|c| c.fixes(key)));
            s.allow && everyone && !limited
        })
    }

    /// The policy as S3 keeps it, and gives back: compact; with a version
    /// (`2008-10-17`, if it had none); its statements a list, in which each
    /// element's single values are values, not lists; `Effect` capitalized;
    /// accounts as their root ARNs; conditions by operator and key, and
    /// their values strings (probed).
    pub fn normalized(&self) -> &str {
        &self.normalized
    }

    /// Parses and checks a policy as S3 (for a bucket policy) or IAM (for
    /// an identity policy) checks it when it's set, with S3's messages
    /// (probed). What S3 would take but Cairn can't decide (see `Support`)
    /// is refused once the policy is otherwise valid.
    pub fn parse(text: &str, kind: Kind) -> Result<Policy, Invalid> {
        Policy::parse_as(text, kind, &|_| None)
    }

    /// `parse`, with each user principal that `rename` gives a name for (by
    /// its ARN) written as that in the normalized policy.
    fn parse_as(text: &str, kind: Kind, rename: &dyn Fn(&str) -> Option<String>) -> Result<Policy, Invalid> {
        let first_byte = || Invalid::malformed("Policies must be valid JSON and the first byte must be '{'");
        if !text.trim_start().starts_with('{') {
            return Err(first_byte());
        }
        let json: Json = serde_json::from_str(text).map_err(|e| {
            let e = e.to_string();
            match e.strip_prefix(DUPLICATE) {
                Some(rest) => Invalid::malformed(format!(
                    "Statement/policy already has instance of {}",
                    rest.split(" at line").next().unwrap_or(rest)
                )),
                // IAM's message, for an identity policy (probed); S3's, for
                // a bucket's.
                None if kind == Kind::Identity => Invalid::malformed("Syntax errors in policy."),
                None => Invalid::malformed("This policy contains invalid Json"),
            }
        })?;
        let Json::Object(top) = json else { return Err(first_byte()) };
        let mut version = None;
        let mut id = None;
        let mut statements = None;
        for (name, value) in &top {
            match (name.as_str(), value) {
                ("Version", Json::String(v)) if v == "2012-10-17" || v == "2008-10-17" => version = Some(v.clone()),
                ("Version", _) => return Err(Invalid::malformed("The policy must contain a valid version string")),
                ("Id", _) if kind == Kind::Identity => {
                    return Err(Invalid::malformed("Policy document should not specify an Id"));
                }
                ("Id", Json::String(v)) => id = Some(v.clone()),
                ("Id", _) => return Err(syntax()),
                ("Statement", value) => statements = Some(value),
                (name, _) => return Err(Invalid::malformed(format!("Unknown field {name}"))),
            }
        }
        let statements = match statements {
            None => return Err(Invalid::malformed("Missing required field Statement")),
            Some(Json::Array(statements)) => statements.iter().collect::<Vec<_>>(),
            Some(statement @ Json::Object(_)) => vec![statement],
            Some(_) => return Err(syntax()),
        };
        if statements.is_empty() {
            return Err(Invalid::malformed("Could not parse the policy: Statement is empty!"));
        }
        let mut sids = Vec::new();
        let mut unsupported = None;
        let mut parsed = Vec::new();
        let mut normalized = Vec::new();
        for statement in statements {
            let Json::Object(fields) = statement else { return Err(syntax()) };
            if matches!(kind, Kind::Identity | Kind::Trust)
                && let Some((_, Json::String(sid))) = fields.iter().find(|(name, _)| name == "Sid")
            {
                // IAM's; S3 takes the same Sid twice (probed).
                if sids.contains(sid) {
                    return Err(Invalid::malformed("Statement IDs (SID) in a single policy must be unique."));
                }
                sids.push(sid.clone());
            }
            let (statement, text) = Statement::parse(fields, kind, &mut unsupported, rename)?;
            parsed.push(statement);
            normalized.push(text);
        }
        let version = version.unwrap_or_else(|| "2008-10-17".to_owned());
        let mut out = format!("{{\"Version\":{}", string(&version));
        if let Some(id) = id {
            out.push_str(&format!(",\"Id\":{}", string(&id)));
        }
        out.push_str(&format!(",\"Statement\":[{}]}}", normalized.join(",")));
        if let Kind::Bucket(_) = kind
            && out.len() > MAX_BUCKET_POLICY
        {
            return Err(Invalid::malformed(format!(
                "Normalized policy document exceeds the maximum allowed size of {MAX_BUCKET_POLICY} bytes"
            )));
        }
        if let Some(key) = unsupported {
            return Err(Invalid::unsupported(format!("Cairn doesn't evaluate the condition key {key} yet")));
        }
        Ok(Policy { variables: version == "2012-10-17", statements: parsed, normalized: out, ids: HashMap::new() })
    }
}

/// S3's answer to what isn't the policy grammar's (a number for a `Sid`, a
/// principal that's a string but `*`, ...).
fn syntax() -> Invalid {
    Invalid::malformed("Invalid policy syntax.")
}

/// `text` as a JSON string.
fn string(text: &str) -> String {
    serde_json::to_string(text).expect("a string serializes")
}

/// Values as S3 writes them: one as itself, more as a list.
fn one_or_list(values: &[String]) -> String {
    match values {
        [one] => string(one),
        values => format!("[{}]", values.iter().map(|v| string(v)).collect::<Vec<_>>().join(",")),
    }
}

/// The values of a field that's a string or a list of strings.
fn strings(value: &Json) -> Result<Vec<String>, Invalid> {
    match value {
        Json::String(s) => Ok(vec![s.clone()]),
        Json::Array(items) => items
            .iter()
            .map(|item| match item {
                Json::String(s) => Ok(s.clone()),
                _ => Err(syntax()),
            })
            .collect(),
        _ => Err(syntax()),
    }
}

/// The S3 actions `name` (perhaps with wildcards; without the `s3:`) names
/// that a policy of `kind` may: a bucket policy only those on a bucket or
/// its objects, and not CreateBucket (probed).
fn s3_actions(name: &str, kind: Kind) -> Vec<&'static (&'static str, Applies, &'static [&'static str])> {
    let pattern = Pattern::new(name, Syntax { wildcards: true, variables: None }).expect("no variables");
    ACTIONS
        .iter()
        .filter(|(action, applies, _)| match kind {
            Kind::Identity | Kind::Trust => true,
            Kind::Bucket(_) => matches!(applies, Applies::Bucket | Applies::Object) && *action != "CreateBucket",
        })
        .filter(|(action, _, _)| pattern.matches(action, true))
        .collect()
}

/// Whether an action's `s3:` condition keys (as the action table writes
/// them) take `key`.
fn takes_key(keys: &[&str], key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    keys.iter().any(|k| {
        let k = k.to_ascii_lowercase();
        match k.split_once('/') {
            Some((prefix, _)) => key.strip_prefix(prefix).is_some_and(|rest| rest.len() > 1 && rest.starts_with('/')),
            None => k == key,
        }
    })
}

impl Statement {
    /// A statement, and its normalized text (see `Policy::normalized`).
    fn parse(
        fields: &[(String, Json)],
        kind: Kind,
        unsupported: &mut Option<String>,
        rename: &dyn Fn(&str) -> Option<String>,
    ) -> Result<(Statement, String), Invalid> {
        let field = |name: &str| fields.iter().find(|(n, _)| n == name).map(|(_, v)| v);
        const FIELDS: &[&str] =
            &["Sid", "Effect", "Principal", "NotPrincipal", "Action", "NotAction", "Resource", "NotResource", "Condition"];
        if let Some((name, _)) = fields.iter().find(|(name, _)| !FIELDS.contains(&name.as_str())) {
            return Err(Invalid::malformed(format!("Unknown field {name}")));
        }
        // A `Not...` is another instance of its element.
        for (name, not) in [("Principal", "NotPrincipal"), ("Action", "NotAction"), ("Resource", "NotResource")] {
            if field(name).is_some() && field(not).is_some() {
                return Err(Invalid::malformed(format!("Statement/policy already has instance of {name}")));
            }
        }
        let either = |name: &str| match (field(name), field(&format!("Not{name}"))) {
            (Some(v), None) => Some((false, v)),
            (None, Some(v)) => Some((true, v)),
            _ => None,
        };
        let mut out = Vec::new();
        match field("Sid") {
            Some(Json::String(sid)) => out.push(format!("\"Sid\":{}", string(sid))),
            Some(_) => return Err(syntax()),
            None => {}
        }
        // Either case (probed), though the IAM guide says otherwise.
        let allow = match field("Effect") {
            Some(Json::String(e)) if e.eq_ignore_ascii_case("Allow") => true,
            Some(Json::String(e)) if e.eq_ignore_ascii_case("Deny") => false,
            Some(_) => return Err(syntax()),
            None => return Err(Invalid::malformed("Missing required field Effect")),
        };
        out.push(format!("\"Effect\":\"{}\"", if allow { "Allow" } else { "Deny" }));
        let principals = match (kind, either("Principal")) {
            (Kind::Identity, Some(_)) => return Err(Invalid::malformed("Policy document should not specify a principal.")),
            (Kind::Identity, None) => None,
            (Kind::Bucket(_) | Kind::Trust, None) => return Err(Invalid::malformed("Missing required field Principal")),
            (Kind::Bucket(_) | Kind::Trust, Some((not, value))) => {
                if not && allow {
                    return Err(Invalid::malformed("Allow with NotPrincipal is not allowed."));
                }
                let (principals, text) = parse_principals(not, value, kind, rename)?;
                out.push(format!("\"{}Principal\":{text}", if not { "Not" } else { "" }));
                Some(principals)
            }
        };
        let Some((not, actions)) = either("Action") else {
            return Err(Invalid::malformed("Missing required field Action"));
        };
        let actions = Matches { not, patterns: strings(actions)? };
        if actions.patterns.is_empty() {
            return Err(Invalid::malformed("Missing required field Action cannot be empty!"));
        }
        if kind == Kind::Trust
            && (actions.not || !actions.patterns.iter().all(|a| TRUST_ACTIONS.iter().any(|t| t.eq_ignore_ascii_case(a))))
        {
            return Err(Invalid::malformed("AssumeRole policy may only specify STS AssumeRole actions."));
        }
        out.push(format!("\"{}Action\":{}", if not { "Not" } else { "" }, one_or_list(&actions.patterns)));
        // The actions each pattern names (with wildcards, several).
        let mut named = Vec::new();
        for action in &actions.patterns {
            let invalid = || Invalid::malformed("Policy has invalid action");
            let (service, name) = match action.as_str() {
                "*" => ("s3", "*"),
                action => action.split_once(':').ok_or_else(invalid)?,
            };
            if service.is_empty() || name.is_empty() || service.contains(['*', '?']) {
                return Err(invalid());
            }
            if service.eq_ignore_ascii_case("s3") {
                let actions = s3_actions(name, kind);
                if actions.is_empty() {
                    return Err(invalid());
                }
                named.push(actions);
            } else if let Kind::Bucket(_) = kind {
                // A bucket policy is about S3's actions only; an identity
                // policy may name other services' (which no request to
                // Cairn is).
                return Err(invalid());
            }
        }
        // A trust policy's statements are about the role whose it is.
        let resources = match (kind, either("Resource")) {
            (Kind::Trust, Some((not, _))) => {
                return Err(Invalid::malformed(format!("Has prohibited field {}Resource", if not { "Not" } else { "" })));
            }
            (Kind::Trust, None) => Matches { not: false, patterns: vec!["*".to_owned()] },
            (_, None) => return Err(Invalid::malformed("Statement is missing required element")),
            (_, Some((not, resources))) => Matches { not, patterns: strings(resources)? },
        };
        let mut kinds = Vec::new();
        if kind != Kind::Trust {
            for resource in &resources.patterns {
                kinds.push(resource_kind(resource, kind)?);
            }
            out.push(format!("\"{}Resource\":{}", if resources.not { "Not" } else { "" }, one_or_list(&resources.patterns)));
        }
        // As S3 checks a bucket policy: each action must apply to one of the
        // statement's resources (an object action to an object, ...).
        if let Kind::Bucket(_) = kind
            && !actions.not
            && !resources.not
        {
            let fits = |applies: &Applies| kinds.iter().any(|k| *k == Some(*applies) || k.is_none());
            if named.iter().any(|actions| !actions.iter().any(|(_, applies, _)| fits(applies))) {
                return Err(Invalid::malformed("Action does not apply to any resource(s) in statement"));
            }
        }
        let conditions = match field("Condition") {
            None => Vec::new(),
            Some(value) => {
                let (conditions, text) = parse_conditions(value, kind, unsupported)?;
                out.push(format!("\"Condition\":{text}"));
                conditions
            }
        };
        // As S3 checks a bucket policy: each action must take the
        // statement's `s3:` keys (`aws:` keys go with any).
        if let Kind::Bucket(_) = kind
            && !actions.not
        {
            let s3_keys = conditions.iter().map(|c| c.key()).filter(|k| k.to_ascii_lowercase().starts_with("s3:"));
            for key in s3_keys {
                if named.iter().any(|actions| !actions.iter().any(|(_, _, keys)| takes_key(keys, key))) {
                    return Err(Invalid::malformed(
                        "Conditions do not apply to combination of actions and resources in statement",
                    ));
                }
            }
        }
        let statement = Statement { allow, principals, actions, resources, conditions };
        Ok((statement, format!("{{{}}}", out.join(","))))
    }
}

/// What a resource is (`None`: it could be either, `*` say), or why it's not
/// one a policy of `kind` may name.
fn resource_kind(resource: &str, kind: Kind) -> Result<Option<Applies>, Invalid> {
    let invalid = || Invalid::malformed("Policy has invalid resource");
    if resource == "*" {
        return match kind {
            Kind::Identity | Kind::Trust => Ok(None),
            Kind::Bucket(_) => Err(invalid()),
        };
    }
    let [prefix, partition, service, region, account, path] = arn_parts(resource).ok_or_else(invalid)?;
    if prefix != "arn" || partition.is_empty() || service.is_empty() {
        return Err(invalid());
    }
    if let Kind::Bucket(bucket) = kind {
        // Only the bucket, and its objects.
        let ours = service == "s3" && region.is_empty() && account.is_empty() && partition == "aws";
        let named = path == bucket || path.strip_prefix(bucket).is_some_and(|rest| rest.starts_with('/'));
        if !ours || !named {
            return Err(invalid());
        }
    }
    if service != "s3" || !region.is_empty() || !account.is_empty() {
        return Ok(Some(Applies::Other));
    }
    Ok(match path.split_once('/') {
        Some(_) => Some(Applies::Object),
        // `bucket*` could be an object too.
        None if path.contains(['*', '?']) => None,
        None => Some(Applies::Bucket),
    })
}

/// Whether `id` is an account's: 12 digits.
/// A user's ARN.
pub fn user_arn(account: &str, name: &str) -> String {
    format!("arn:aws:iam::{account}:user/{name}")
}

/// A role's ARN, by its path and name.
pub fn role_arn(account: &str, name: &str) -> String {
    format!("arn:aws:iam::{account}:role/{name}")
}

fn is_account(id: &str) -> bool {
    id.len() == 12 && id.bytes().all(|b| b.is_ascii_digit())
}

/// A bucket policy statement's `Principal` (or, `not`, `NotPrincipal`), and
/// its normalized text.
fn parse_principals(
    not: bool,
    value: &Json,
    kind: Kind,
    rename: &dyn Fn(&str) -> Option<String>,
) -> Result<(Principals, String), Invalid> {
    let trust = kind == Kind::Trust;
    // IAM's message names the principal (probed); S3's doesn't.
    let invalid_one = |what: &str, id: &str| match trust {
        true => Invalid::malformed(format!("Invalid principal in policy: {}:{}", string(what), string(id))),
        false => Invalid::malformed("Invalid principal in policy"),
    };
    let mut principals =
        Principals {
        not,
        everyone: false,
        users: Vec::new(),
        accounts: Vec::new(),
        roles: Vec::new(),
        sessions: Vec::new(),
        federated: Vec::new(),
    };
    let entries = match value {
        Json::String(s) if s == "*" => {
            principals.everyone = true;
            return Ok((principals, "\"*\"".to_owned()));
        }
        Json::Object(entries) => entries,
        _ => return Err(syntax()),
    };
    let mut out = Vec::new();
    for (kind, ids) in entries {
        let mut ids = strings(ids)?;
        if ids.is_empty() {
            return Err(Invalid::malformed("Missing required field Principal cannot be empty!"));
        }
        match kind.as_str() {
            "AWS" => {
                for id in &mut ids {
                    if id == "*" {
                        principals.everyone = true;
                        continue;
                    }
                    if is_account(id) {
                        *id = format!("arn:aws:iam::{id}:root");
                    }
                    let shown = id.clone();
                    let invalid = || invalid_one("AWS", &shown);
                    // A role's session.
                    if let Some(rest) = id.strip_prefix("arn:aws:sts::") {
                        let (account, what) = rest.split_once(':').ok_or_else(invalid)?;
                        let session = what.strip_prefix("assumed-role/").and_then(|s| s.split_once('/'));
                        match session {
                            Some((role, session))
                                if is_account(account) && !role.is_empty() && !session.is_empty() && !id.contains(['*', '?']) =>
                            {
                                principals.sessions.push((account.to_owned(), role.to_owned(), session.to_owned()));
                            }
                            _ => return Err(invalid()),
                        }
                        continue;
                    }
                    let rest = id.strip_prefix("arn:aws:iam::").ok_or_else(invalid)?;
                    let (account, what) = rest.split_once(':').ok_or_else(invalid)?;
                    if !is_account(account) {
                        return Err(invalid());
                    }
                    let named = |prefix: &str| what.strip_prefix(prefix).filter(|n| !n.is_empty() && !n.contains(['*', '?']));
                    if what == "root" {
                        principals.accounts.push(account.to_owned());
                    } else if let Some(user) = named("user/") {
                        // A user, by its path and name.
                        principals.users.push((account.to_owned(), user.to_owned()));
                        if let Some(name) = rename(id) {
                            *id = name;
                        }
                    } else if let Some(role) = named("role/") {
                        principals.roles.push((account.to_owned(), role.to_owned()));
                        if let Some(name) = rename(id) {
                            *id = name;
                        }
                    } else {
                        return Err(invalid());
                    }
                }
                // IAM keeps them sorted (probed).
                if trust {
                    ids.sort();
                }
            }
            // AWS services never call Cairn: they're named, and never
            // match. Identity providers are: an OIDC provider's web
            // identities (AssumeRoleWithWebIdentity), by its ARN.
            "Service" | "Federated" => {
                if let Some(id) = ids.iter().find(|id| id.is_empty() || id.contains('*')) {
                    return Err(invalid_one(kind, id));
                }
                if kind == "Federated" {
                    principals.federated.extend(ids.iter().cloned());
                }
            }
            // There are no canonical user IDs in Cairn.
            "CanonicalUser" => return Err(invalid_one(kind, &ids[0])),
            _ => return Err(syntax()),
        }
        out.push(format!("{}:{}", string(kind), one_or_list(&ids)));
    }
    Ok((principals, format!("{{{}}}", out.join(","))))
}

/// The keys whose values must be IP addresses, whatever the operator
/// (probed).
const ADDRESS_KEYS: &[&str] = &["aws:sourceip", "aws:vpcsourceip"];

/// A statement's `Condition`: operator → key → value(s); and its normalized
/// text. Sets `unsupported` to the first key Cairn can't decide.
fn parse_conditions(
    value: &Json,
    kind: Kind,
    unsupported: &mut Option<String>,
) -> Result<(Vec<Condition>, String), Invalid> {
    let Json::Object(operators) = value else { return Err(syntax()) };
    let mut conditions = Vec::new();
    // Each operator's keys, and their values.
    type Keys = Vec<(String, Vec<String>)>;
    let mut out: Vec<(String, Keys)> = Vec::new();
    for (operator, keys) in operators {
        let Json::Object(keys) = keys else { return Err(syntax()) };
        condition::check_operator(operator)?;
        let mut normalized = Vec::new();
        for (key, values) in keys {
            let lower = key.to_ascii_lowercase();
            let invalid_key = || Invalid::malformed("Policy has an invalid condition key");
            match support(key) {
                Some(Support::Unsupported) => {
                    unsupported.get_or_insert_with(|| key.clone());
                }
                Some(Support::Evaluated | Support::Absent) => {}
                // An `aws:` key S3 doesn't know is taken (probed): no
                // request has it.
                None if lower.starts_with("aws:") => {}
                None if lower.starts_with("s3:") => return Err(invalid_key()),
                // STS's, in a trust policy: those Cairn decides, the rest
                // refused as undecidable.
                None if kind == Kind::Trust && lower.starts_with("sts:") => {
                    if !STS_KEYS.iter().any(|k| *k == lower) {
                        unsupported.get_or_insert_with(|| key.clone());
                    }
                }
                // Another service's: no request to Cairn has it. Only in
                // identity and trust policies (probed: IAM takes keys it
                // doesn't know).
                None if matches!(kind, Kind::Identity | Kind::Trust)
                    && lower.split_once(':').is_some_and(|(s, k)| !s.is_empty() && !k.is_empty()) => {}
                None => return Err(invalid_key()),
            }
            // Numbers and booleans may be written without quotes.
            let scalar = |v: &Json| match v {
                Json::String(s) => Ok(s.clone()),
                Json::Number(n) => Ok(n.to_string()),
                Json::Bool(b) => Ok(b.to_string()),
                _ => Err(syntax()),
            };
            let values = match values {
                Json::Array(items) => items.iter().map(scalar).collect::<Result<Vec<_>, _>>()?,
                value => vec![scalar(value)?],
            };
            if ADDRESS_KEYS.contains(&lower.as_str()) && values.iter().any(|v| !condition::is_cidr(v)) {
                return Err(Invalid::malformed("Invalid IP address in Conditions"));
            }
            conditions.push(Condition::new(operator, key, values.clone())?);
            normalized.push((key.clone(), values));
        }
        normalized.sort_by(|a, b| a.0.cmp(&b.0));
        out.push((operator.clone(), normalized));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    let text = out
        .iter()
        .map(|(operator, keys)| {
            let keys: Vec<String> = keys.iter().map(|(key, values)| format!("{}:{}", string(key), one_or_list(values))).collect();
            format!("{}:{{{}}}", string(operator), keys.join(","))
        })
        .collect::<Vec<_>>()
        .join(",");
    Ok((conditions, format!("{{{text}}}")))
}

/// The start of the error for a field an object has twice.
const DUPLICATE: &str = "duplicate field: ";

/// JSON as policies take it: objects keep their fields' order, and may not
/// have a field twice (which `serde_json::Value` would let the last win).
#[derive(Debug)]
enum Json {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl<'de> serde::Deserialize<'de> for Json {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Json, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Json;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("JSON")
            }
            fn visit_unit<E>(self) -> Result<Json, E> {
                Ok(Json::Null)
            }
            fn visit_bool<E>(self, v: bool) -> Result<Json, E> {
                Ok(Json::Bool(v))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Json, E> {
                Ok(Json::Number(v.into()))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Json, E> {
                Ok(Json::Number(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Json, E> {
                serde_json::Number::from_f64(v).map(Json::Number).ok_or_else(|| E::custom("not a number"))
            }
            fn visit_str<E>(self, v: &str) -> Result<Json, E> {
                Ok(Json::String(v.to_owned()))
            }
            fn visit_string<E>(self, v: String) -> Result<Json, E> {
                Ok(Json::String(v))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Json::Array(items))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
                let mut fields: Vec<(String, Json)> = Vec::new();
                while let Some((name, value)) = map.next_entry::<String, Json>()? {
                    if fields.iter().any(|(n, _)| *n == name) {
                        return Err(serde::de::Error::custom(format!("{DUPLICATE}{name}")));
                    }
                    fields.push((name, value));
                }
                Ok(Json::Object(fields))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

#[cfg(test)]
mod tests;
