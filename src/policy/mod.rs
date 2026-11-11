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

pub use condition::{Support, support};
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

    pub fn set_all(&mut self, key: &str, values: Vec<String>) {
        self.values.insert(key.to_ascii_lowercase(), values);
    }

    pub fn get(&self, key: &str) -> Option<&[String]> {
        self.values.get(&key.to_ascii_lowercase()).map(Vec::as_slice)
    }
}

/// Who makes a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Principal<'a> {
    /// An unsigned request.
    Anonymous,
    /// A user of `account` (its 12-digit ID).
    User { account: &'a str, name: &'a str },
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

/// Whether a request is allowed by `identity` (the user's policies; none for
/// an anonymous request) and `bucket` (the bucket's policy, if it has one):
/// an explicit Deny in either denies; else an Allow in either allows; else
/// it's denied.
pub fn decide<'p>(identity: impl IntoIterator<Item = &'p Policy>, bucket: Option<&'p Policy>, request: &Request) -> bool {
    let mut allowed = false;
    let anonymous = request.principal == Principal::Anonymous;
    // An anonymous request has no identity policies.
    let identity = identity.into_iter().filter(|_| !anonymous);
    for policy in identity.chain(bucket) {
        match policy.evaluate(request) {
            Decision::Deny => return false,
            Decision::Allow => allowed = true,
            Decision::NotApplicable => {}
        }
    }
    allowed
}

/// What a policy is attached to, which decides what it may say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind<'a> {
    /// A user's: no `Principal`, no `Id`.
    Identity,
    /// A bucket's: every statement names its principals, and only the
    /// bucket and its objects are resources.
    Bucket(&'a str),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    /// `2012-10-17`: policy variables are variables. Before (`2008-10-17`,
    /// or none), they're text.
    variables: bool,
    statements: Vec<Statement>,
    /// The policy as S3 keeps it, and gives it back (see `normalized`).
    normalized: String,
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
    /// Users, by their account and name (`arn:aws:iam::<account>:user/<name>`).
    users: Vec<(String, String)>,
    /// Accounts (an ID, or its root ARN).
    accounts: Vec<String>,
}

impl Principals {
    /// Whether the statement is about `principal`.
    fn about(&self, principal: Principal, allow: bool) -> bool {
        match principal {
            Principal::Anonymous => self.everyone != self.not,
            Principal::User { account, name } => {
                let user = self.users.iter().any(|(a, n)| a == account && n == name);
                let whole = self.accounts.iter().any(|a| a == account);
                if self.not {
                    // NotPrincipal leaves out the users it names (as S3 does,
                    // probed), not an account's users for naming the account.
                    !(self.everyone || user)
                } else {
                    // An account allows nothing by itself: it leaves it to the
                    // account's identity policies. It does deny all of the
                    // account's users (probed).
                    self.everyone || user || (whole && !allow)
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
    fn applies(&self, request: &Request, variables: bool) -> bool {
        if let Some(principals) = &self.principals
            && !principals.about(request.principal, self.allow)
        {
            return false;
        }
        let syntax = Syntax { wildcards: true, variables: None };
        let action_matches = |p: &str| Pattern::new(p, syntax).is_some_and(|p| p.matches(request.action, true));
        let vars = variables.then_some(request.context);
        self.actions.any(action_matches)
            && self.resources.any(|p| arn_matches(p, request.resource, vars))
            && self.conditions.iter().all(|c| c.holds(request.context, variables))
    }
}

impl Policy {
    /// What the policy says about `request`.
    pub fn evaluate(&self, request: &Request) -> Decision {
        let applying = self.statements.iter().filter(|s| s.applies(request, self.variables));
        let mut decision = Decision::NotApplicable;
        for statement in applying {
            if !statement.allow {
                return Decision::Deny;
            }
            decision = Decision::Allow;
        }
        decision
    }

    /// The users it names as principals, (account, name): they must exist.
    pub fn users(&self) -> impl Iterator<Item = (&str, &str)> {
        self.principals().flat_map(|p| p.users.iter().map(|(a, n)| (a.as_str(), n.as_str())))
    }

    /// The accounts it names as principals: they must exist.
    pub fn accounts(&self) -> impl Iterator<Item = &str> {
        self.principals().flat_map(|p| p.accounts.iter().map(String::as_str))
    }

    fn principals(&self) -> impl Iterator<Item = &Principals> {
        self.statements.iter().filter_map(|s| s.principals.as_ref())
    }

    /// Whether some statement allows everyone (`"Principal": "*"`), with or
    /// without conditions.
    pub fn allows_everyone(&self) -> bool {
        self.statements.iter().any(|s| s.allow && s.principals.as_ref().is_some_and(|p| p.everyone && !p.not))
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
            if kind == Kind::Identity
                && let Some((_, Json::String(sid))) = fields.iter().find(|(name, _)| name == "Sid")
            {
                // IAM's; S3 takes the same Sid twice (probed).
                if sids.contains(sid) {
                    return Err(Invalid::malformed("Statement IDs (SID) in a single policy must be unique."));
                }
                sids.push(sid.clone());
            }
            let (statement, text) = Statement::parse(fields, kind, &mut unsupported)?;
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
        Ok(Policy { variables: version == "2012-10-17", statements: parsed, normalized: out })
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
            Kind::Identity => true,
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
            (Kind::Bucket(_), None) => return Err(Invalid::malformed("Missing required field Principal")),
            (Kind::Bucket(_), Some((not, value))) => {
                if not && allow {
                    return Err(Invalid::malformed("Allow with NotPrincipal is not allowed."));
                }
                let (principals, text) = parse_principals(not, value)?;
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
        let Some((not, resources)) = either("Resource") else {
            return Err(Invalid::malformed("Statement is missing required element"));
        };
        let resources = Matches { not, patterns: strings(resources)? };
        let mut kinds = Vec::new();
        for resource in &resources.patterns {
            kinds.push(resource_kind(resource, kind)?);
        }
        out.push(format!("\"{}Resource\":{}", if not { "Not" } else { "" }, one_or_list(&resources.patterns)));
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
            Kind::Identity => Ok(None),
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
fn is_account(id: &str) -> bool {
    id.len() == 12 && id.bytes().all(|b| b.is_ascii_digit())
}

/// A bucket policy statement's `Principal` (or, `not`, `NotPrincipal`), and
/// its normalized text.
fn parse_principals(not: bool, value: &Json) -> Result<(Principals, String), Invalid> {
    let invalid = || Invalid::malformed("Invalid principal in policy");
    let mut principals = Principals { not, everyone: false, users: Vec::new(), accounts: Vec::new() };
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
                    let rest = id.strip_prefix("arn:aws:iam::").ok_or_else(invalid)?;
                    let (account, what) = rest.split_once(':').ok_or_else(invalid)?;
                    if !is_account(account) {
                        return Err(invalid());
                    }
                    match what.strip_prefix("user/") {
                        _ if what == "root" => principals.accounts.push(account.to_owned()),
                        // A user (Cairn's have no paths; one with a path is
                        // a user there isn't).
                        Some(user) if !user.is_empty() && !user.contains(['*', '?']) => {
                            principals.users.push((account.to_owned(), user.to_owned()));
                        }
                        // Roles and the rest: Cairn has none.
                        _ => return Err(invalid()),
                    }
                }
            }
            // AWS services and identity providers never call Cairn: they're
            // named, and never match.
            "Service" | "Federated" => {
                if ids.iter().any(|id| id.is_empty() || id.contains('*')) {
                    return Err(invalid());
                }
            }
            // There are no canonical user IDs in Cairn.
            "CanonicalUser" => return Err(invalid()),
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
                // Another service's: no request to Cairn has it. Only in
                // identity policies (probed).
                None if kind == Kind::Identity && lower.split_once(':').is_some_and(|(s, k)| !s.is_empty() && !k.is_empty()) => {}
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
