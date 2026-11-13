//! Who may do what: each request's checks (see `actions`) decided by the
//! policies that apply (see `policy`): the user's (its grants and admin flag
//! as their built-in policies, and its inline ones) and the buckets'. An
//! anonymous (unsigned) request has only the buckets' policies to allow it.
//! See `plans/policies.md`.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use http_body_util::Full;
use hyper::{HeaderMap, Method, Response, StatusCode, body::Bytes};

use crate::{
    App,
    auth::Signed,
    db::Cached,
    policy::{Context, Kind, Network, Policy, Principal as Who, Verdict},
    roles::Principal,
    s3::{
        actions::{self, Check, On},
        util::{format_s3_error, query_param},
    },
};

/// Parsed policies, by what they are and their text: each request would
/// otherwise parse its user's and buckets' policies again.
static PARSED: Mutex<Option<HashMap<Parsed, Arc<Policy>>>> = Mutex::new(None);

/// A parsed policy's key: its bucket (none for an identity policy), its
/// text, and (a bucket policy's) its users' IDs.
type Parsed = (Option<String>, String, Option<String>);

/// The most policies kept parsed; past it, they're parsed again.
const MAX_PARSED: usize = 10_000;

/// `text` parsed as a policy of `kind`, naming its users by `ids` (a bucket
/// policy's `policy_principals`: ARN → ID), from `PARSED` if it's been
/// parsed.
fn parsed(text: &str, kind: Kind, ids: Option<&str>) -> anyhow::Result<Arc<Policy>> {
    let key = (
        match kind {
            Kind::Identity => None,
            Kind::Bucket(bucket) => Some(bucket.to_owned()),
        },
        text.to_owned(),
        ids.map(str::to_owned),
    );
    if let Some(policy) = PARSED.lock().unwrap().as_ref().and_then(|p| p.get(&key)) {
        return Ok(policy.clone());
    }
    // A policy that was taken when it was set, but isn't now (a Cairn that
    // checks more), decides nothing: it fails the request, rather than
    // allowing what it might deny.
    let policy = Policy::parse(text, kind).map_err(|e| {
        anyhow::anyhow!("a stored policy doesn't parse ({}: {}): {text}", e.code, e.message)
    })?;
    let policy = Arc::new(match ids {
        Some(ids) => policy.with_ids(serde_json::from_str(ids)?),
        None => policy,
    });
    let mut cache = PARSED.lock().unwrap();
    let cache = cache.get_or_insert_with(HashMap::new);
    if cache.len() >= MAX_PARSED {
        cache.clear();
    }
    cache.insert(key, policy.clone());
    Ok(policy)
}

/// A bucket, as a request's checks see it.
struct Loaded {
    exists: bool,
    /// The account that owns it.
    account: Option<String>,
    policy: Option<Arc<Policy>>,
    /// Whether its policy is public, and RestrictPublicBuckets is on (the
    /// bucket's or the cluster's; see `public_access`): then it allows
    /// nothing to anyone outside the bucket's account, anonymous or not, not
    /// even what it allows another account by name (as in S3).
    restricted: bool,
}

/// Where a request comes from, as condition keys say it.
pub struct Origin<'a> {
    /// The connection's peer.
    pub peer: Option<IpAddr>,
    pub trusted_proxies: &'a [Network],
    /// How the request is signed (`None`: it isn't).
    pub signed: Option<&'a Signed>,
    /// A POST Object form's (`s3:authType` `POST`).
    pub form: bool,
}

/// What a request may do: the policies that decide it, and its condition
/// keys. Buckets' policies are loaded as checks need them.
pub struct Access {
    /// The user, by its account, name and ID; `None` if anonymous.
    user: Option<(String, String, String)>,
    /// An account's root (by its account) acts, rather than a user.
    root: Option<String>,
    /// The operator account, whose the cluster is (loaded for checks on it).
    operator: Option<String>,
    identity: Vec<Arc<Policy>>,
    pub context: Context,
    /// Each bucket loaded: whether it exists, and its policy (see `Loaded`).
    buckets: HashMap<String, Loaded>,
}

impl Access {
    /// The access of `principal` (`None`: anonymous), in the cluster's
    /// `account`, for a request with `headers` and `query`, from `origin`.
    pub fn new(
        principal: Option<&Principal>,
        account: &str,
        method: &Method,
        headers: &HeaderMap,
        query: &str,
        origin: &Origin,
    ) -> anyhow::Result<Access> {
        let mut identity = Vec::new();
        if let Some(principal) = principal {
            if principal.admin {
                identity.push(parsed(&actions::admin_policy(), Kind::Identity, None)?);
            }
            for document in &principal.policies {
                identity.push(parsed(document, Kind::Identity, None)?);
            }
        }
        Ok(Access {
            root: None,
            operator: None,
            user: principal.map(|p| (p.account.clone(), p.name.clone(), p.id.to_string())),
            identity,
            context: context(principal, account, method, headers, query, origin),
            buckets: HashMap::new(),
        })
    }

    /// The access of `account`'s root (see `policy::root_verdict`), for a
    /// request (the console's) with `headers` and `query`, from `origin`.
    pub fn root(account: &str, method: &Method, headers: &HeaderMap, query: &str, origin: &Origin) -> Access {
        let mut context = context(None, account, method, headers, query, origin);
        context.set("aws:userid", account);
        context.set("aws:PrincipalArn", format!("arn:aws:iam::{account}:root"));
        context.set("aws:PrincipalAccount", account);
        context.set("aws:PrincipalType", "Account");
        context.set("aws:PrincipalIsAWSService", "false");
        Access {
            user: None,
            root: Some(account.to_owned()),
            operator: None,
            identity: Vec::new(),
            context,
            buckets: HashMap::new(),
        }
    }

    /// Loads `bucket`'s policy, for the checks on it; whether it exists.
    pub async fn load(&mut self, app: &App, bucket: &str) -> anyhow::Result<bool> {
        if let Some(loaded) = self.buckets.get(bucket) {
            return Ok(loaded.exists);
        }
        let row = app
            .pool
            .get()
            .await?
            .query_opt_cached(
                "SELECT policy, policy_principals::text, account_id,
                        public_access_block & 8 <> 0
                        OR coalesce((SELECT value FROM settings WHERE name = 'restrict-public-buckets'), '0') <> '0'
                 FROM buckets WHERE name = $1",
                &[&bucket],
            )
            .await?;
        let policy = match row.as_ref().and_then(|row| row.get::<_, Option<String>>(0)) {
            Some(text) => {
                // Its users, by the IDs they had when it was set (see
                // `db::PRINCIPAL_IDS`).
                let ids = row.as_ref().and_then(|row| row.get::<_, Option<String>>(1));
                Some(parsed(&text, Kind::Bucket(bucket), Some(ids.as_deref().unwrap_or("{}")))?)
            }
            None => None,
        };
        let restrict = row.as_ref().and_then(|row| row.get::<_, Option<bool>>(3)).unwrap_or(false);
        let account = row.as_ref().map(|row| row.get::<_, String>(2));
        let restricted = restrict && policy.as_ref().is_some_and(|policy| policy.is_public());
        self.buckets.insert(bucket.to_owned(), Loaded { exists: row.is_some(), account, policy, restricted });
        Ok(row.is_some())
    }

    /// Loads the policies of the buckets `checks` are on.
    pub async fn load_all(&mut self, app: &App, checks: &[Check]) -> anyhow::Result<()> {
        for bucket in checks.iter().filter_map(|c| c.on.bucket()) {
            self.load(app, bucket).await?;
        }
        if self.operator.is_none() && checks.iter().any(|c| c.on == On::Cluster) {
            self.operator = Some(crate::roles::operator_account(&app.pool.get().await?).await?);
        }
        Ok(())
    }

    /// The verdict on `check`, whose bucket's policy is loaded (else the
    /// bucket is taken to have none).
    pub fn verdict(&self, check: &Check) -> Verdict {
        let resource = check.on.arn();
        let principal = match (&self.user, &self.root) {
            (Some((account, name, id)), _) => Who::User { account, name, id },
            (None, Some(account)) => Who::Root { account },
            (None, None) => Who::Anonymous,
        };
        let loaded = check.on.bucket().and_then(|b| self.buckets.get(b));
        // A restricted bucket's public policy is none to anyone outside its
        // account.
        let bucket = loaded
            .filter(|loaded| !(loaded.restricted && loaded.account.as_deref() != self.account()))
            .and_then(|loaded| loaded.policy.as_deref());
        // Whose the resource is: a bucket's owner; else (no bucket, or none
        // by its name) the principal's own account's. A bucket to create is
        // the principal's, whoever has its name (that's BucketAlreadyExists).
        let owner = match &check.on {
            On::User(account, _) | On::Users(account) => Some(account.as_str()),
            // The operator account's (an unknown one, if it wasn't loaded:
            // no one's).
            On::Cluster => Some(self.operator.as_deref().unwrap_or("")),
            _ => loaded.and_then(|loaded| loaded.account.as_deref()).filter(|_| check.action != "s3:CreateBucket"),
        };
        // `aws:ResourceAccount` is that account (else the principal's own;
        // anonymously, the one the request was made in).
        let resource_account = owner.or(self.account());
        let with_resource_account;
        let context = match resource_account {
            Some(account) if self.context.get("aws:ResourceAccount").is_none_or(|v| v != [account]) => {
                let mut context = self.context.clone();
                context.set("aws:ResourceAccount", account);
                context.set("s3:ResourceAccount", account);
                with_resource_account = context;
                &with_resource_account
            }
            _ => &self.context,
        };
        let request = crate::policy::Request { principal, action: check.action, resource: &resource, context };
        if let Some(account) = &self.root {
            return crate::policy::root_verdict(bucket, &request, owner.is_none_or(|owner| owner == account));
        }
        let cross = match (&self.user, owner) {
            (Some((account, _, _)), Some(owner)) => account != owner,
            _ => false,
        };
        crate::policy::verdict_across(self.identity.iter().map(|p| &**p), bucket, &request, cross)
    }

    /// The account the principal acts in; `None` if anonymous.
    fn account(&self) -> Option<&str> {
        match (&self.user, &self.root) {
            (Some((account, _, _)), _) => Some(account),
            (None, root) => root.as_deref(),
        }
    }

    /// Whether `check` is one only its bucket's own account may make (on
    /// the bucket's policy), and the principal is of another (or anonymous),
    /// whatever the policy allows it: S3 answers it 405 MethodNotAllowed.
    /// (Its bucket must be loaded.)
    pub fn foreign(&self, check: &Check) -> bool {
        let owner = check.on.bucket().and_then(|b| self.buckets.get(b)).and_then(|l| l.account.as_deref());
        crate::policy::POLICY_ACTIONS.contains(&check.action) && owner.is_some_and(|owner| self.account() != Some(owner))
    }

    /// Whether `check` is allowed.
    pub fn allows(&self, check: &Check) -> bool {
        self.verdict(check) == Verdict::Allow
    }

    /// The first of `checks` not allowed, and why; `None` if all are.
    pub fn first_denied<'c>(&self, checks: &'c [Check]) -> Option<(&'c Check, Verdict)> {
        checks.iter().map(|c| (c, self.verdict(c))).find(|(_, v)| *v != Verdict::Allow)
    }

    /// S3's 403 for `check`, denied by `verdict`: to a user, it says what
    /// was denied and why (probed); anonymously, just that it was.
    pub fn denied(&self, check: &Check, verdict: Verdict) -> Response<Full<Bytes>> {
        let Some((account, name, _)) = &self.user else {
            return format_s3_error(StatusCode::FORBIDDEN, "AccessDenied", "Access Denied");
        };
        let on = match &check.on {
            On::Account => String::new(),
            on => format!(" on resource: \"{}\"", on.arn()),
        };
        let why = match verdict {
            Verdict::ExplicitDeny { identity: true } => "with an explicit deny in an identity-based policy".to_owned(),
            Verdict::ExplicitDeny { identity: false } => "with an explicit deny in a resource-based policy".to_owned(),
            _ => format!("because no identity-based policy allows the {} action", check.action),
        };
        let message =
            format!("User: arn:aws:iam::{account}:user/{name} is not authorized to perform: {}{on} {why}", check.action);
        format_s3_error(StatusCode::FORBIDDEN, "AccessDenied", &message)
    }
}

/// The address a request comes from, as `aws:SourceIp` has it (see
/// `source`): its connection's `peer`, or what a trusted proxy says.
pub fn client_address(headers: &HeaderMap, peer: Option<IpAddr>, trusted_proxies: &[Network]) -> Option<IpAddr> {
    source(headers, &Origin { peer, trusted_proxies, signed: None, form: false }).0
}

/// Where a request comes from: its peer, or (from a trusted proxy) the
/// first address in `X-Forwarded-For` that isn't one; and whether it came
/// over HTTPS (Cairn speaks only HTTP, so that's a trusted proxy's word).
fn source(headers: &HeaderMap, origin: &Origin) -> (Option<IpAddr>, bool) {
    let trusted = |ip: IpAddr| origin.trusted_proxies.iter().any(|n| n.contains(ip));
    let Some(peer) = origin.peer.map(|ip| ip.to_canonical()) else { return (None, false) };
    if !trusted(peer) {
        return (Some(peer), false);
    }
    let forwarded: Vec<IpAddr> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|hop| hop.trim().parse::<IpAddr>().ok())
        .map(|ip| ip.to_canonical())
        .collect();
    // The nearest hop the proxies didn't add themselves, or the farthest.
    let client = forwarded.iter().rev().find(|ip| !trusted(**ip)).or(forwarded.first()).copied().unwrap_or(peer);
    (Some(client), crate::s3::sse_c::secure(headers, false))
}

/// The request's condition keys (see `policy::support` for which Cairn
/// knows, and `plans/policies.md` for what they hold, probed).
fn context(
    principal: Option<&Principal>,
    account: &str,
    method: &Method,
    headers: &HeaderMap,
    query: &str,
    origin: &Origin,
) -> Context {
    let mut context = Context::default();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    context.set("aws:CurrentTime", iso(now.as_secs()));
    context.set("aws:EpochTime", now.as_secs().to_string());
    let (source, secure) = source(headers, origin);
    if let Some(source) = source {
        context.set("aws:SourceIp", source.to_string());
    }
    context.set("aws:SecureTransport", secure.to_string());
    context.set("aws:ViaAWSService", "false");
    context.set("aws:ResourceAccount", account);
    context.set("s3:ResourceAccount", account);
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    for (key, name) in [("aws:UserAgent", "user-agent"), ("aws:Referer", "referer")] {
        if let Some(value) = header(name) {
            context.set(key, value);
        }
    }
    match principal {
        Some(principal) => {
            context.set("aws:username", &principal.name);
            context.set("aws:userid", principal.id.to_string());
            context.set("aws:PrincipalArn", format!("arn:aws:iam::{}:user/{}", principal.account, principal.name));
            context.set("aws:PrincipalAccount", &principal.account);
            context.set("aws:PrincipalType", "User");
            context.set("aws:PrincipalIsAWSService", "false");
        }
        None => {
            context.set("aws:userid", "anonymous");
            context.set("aws:PrincipalType", "Anonymous");
        }
    }
    if let Some(signed) = origin.signed {
        context.set("aws:RequestedRegion", &signed.region);
        context.set("s3:signatureversion", "AWS4-HMAC-SHA256");
        let auth_type = match (origin.form, signed.presigned) {
            (true, _) => "POST",
            (false, true) => "REST-QUERY-STRING",
            (false, false) => "REST-HEADER",
        };
        context.set("s3:authType", auth_type);
        // How old a presigned URL's signature is, in milliseconds.
        if signed.presigned
            && let Some(at) = signed.date.as_deref().and_then(amz_date)
        {
            let age = now.as_millis().saturating_sub(at as u128 * 1000);
            context.set("s3:signatureAge", age.to_string());
        }
    }
    // What a request's headers ask for, as S3's keys of the same names.
    for name in [
        "x-amz-acl",
        "x-amz-grant-full-control",
        "x-amz-grant-read",
        "x-amz-grant-read-acp",
        "x-amz-grant-write",
        "x-amz-grant-write-acp",
        "x-amz-copy-source",
        "x-amz-metadata-directive",
        "x-amz-server-side-encryption",
        "x-amz-server-side-encryption-aws-kms-key-id",
        "x-amz-server-side-encryption-customer-algorithm",
        "x-amz-storage-class",
        "x-amz-website-redirect-location",
        "x-amz-content-sha256",
    ] {
        if let Some(value) = header(name) {
            context.set(&format!("s3:{name}"), value);
        }
    }
    if *method == Method::PUT {
        for name in ["if-match", "if-none-match"] {
            if let Some(value) = header(name) {
                context.set(&format!("s3:{name}"), value);
            }
        }
    }
    if let Some(version) = query_param(query, "versionId") {
        context.set("s3:versionid", version);
    } else if let Some(version) = header("x-amz-copy-source")
        .and_then(|source| source.split_once('?'))
        .and_then(|(_, q)| query_param(q, "versionId"))
    {
        context.set("s3:versionid", version);
    }
    // A listing's: what it lists, and how much (always there).
    for name in ["prefix", "delimiter"] {
        if let Some(value) = query_param(query, name) {
            context.set(&format!("s3:{name}"), value);
        }
    }
    let max = query_param(query, "max-keys").unwrap_or_else(|| "1000".to_owned());
    context.set("s3:max-keys", max);
    context
}

/// Seconds since the epoch, as ISO 8601 (UTC).
fn iso(seconds: u64) -> String {
    let days = (seconds / 86400) as i64;
    let rest = seconds % 86400;
    // Howard Hinnant's civil-from-days.
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", rest / 3600, rest % 3600 / 60, rest % 60)
}

/// `X-Amz-Date` (`20261111T120000Z`), in seconds since the epoch.
fn amz_date(text: &str) -> Option<u64> {
    if text.len() != 16 || !text.is_ascii() {
        return None;
    }
    let iso = format!(
        "{}-{}-{}T{}:{}:{}Z",
        &text[0..4],
        &text[4..6],
        &text[6..8],
        &text[9..11],
        &text[11..13],
        &text[13..15]
    );
    crate::policy::date(&iso).filter(|s| *s >= 0.0).map(|s| s as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_times() {
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso(1794398400), "2026-11-11T12:00:00Z");
        assert_eq!(amz_date("20261111T120000Z"), Some(1794398400));
        assert_eq!(amz_date("2026-11-11"), None);
    }

    #[test]
    fn believes_only_trusted_proxies() {
        let proxy: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted = [Network::parse("10.0.0.0/8").unwrap()];
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9, 10.0.0.7".parse().unwrap());
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        let from = |peer: &str, trusted| Origin { peer: Some(peer.parse().unwrap()), trusted_proxies: trusted, signed: None, form: false };
        assert_eq!(source(&headers, &from("10.0.0.1", &trusted)), (Some("203.0.113.9".parse().unwrap()), true));
        // From anyone else, the headers are the client's own word.
        assert_eq!(source(&headers, &from("198.51.100.1", &trusted)), (Some("198.51.100.1".parse().unwrap()), false));
        assert_eq!(source(&headers, &from("10.0.0.1", &[])), (Some(proxy), false));
        // Only proxies: the farthest.
        headers.insert("x-forwarded-for", "10.0.0.8".parse().unwrap());
        assert_eq!(source(&headers, &from("10.0.0.1", &trusted)).0, Some("10.0.0.8".parse().unwrap()));
    }
}
