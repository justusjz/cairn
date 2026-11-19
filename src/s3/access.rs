//! Who may do what: each request's checks (see `actions`) decided by the
//! policies that apply (see `policy`): the user's (its grants and admin flag
//! as their built-in policies, and its inline ones) and the buckets'. An
//! anonymous (unsigned) request has only the buckets' policies to allow it.
//! See `plans/policies.md`. Checks on a bucket with ABAC enabled, and on its
//! objects, carry its tags; those on an object the version's tags it was
//! looked up with (see `s3::abac`, and `plans/abac.md`).

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
    s3::{
        actions::{self, Check, On},
        tags::Tags,
        util::{format_s3_error, query_param},
    },
    users::Principal,
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
pub(crate) fn parsed(text: &str, kind: Kind, ids: Option<&str>) -> anyhow::Result<Arc<Policy>> {
    let key = (
        match kind {
            Kind::Identity => None,
            Kind::Bucket(bucket) => Some(bucket.to_owned()),
            // No bucket's name has a NUL.
            Kind::Trust => Some("\0trust".to_owned()),
            Kind::Topic(arn) => Some(format!("\0topic {arn}")),
            Kind::AccessGrants(arn) => Some(format!("\0access-grants {arn}")),
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
        anyhow::anyhow!(
            "a stored policy doesn't parse ({}: {}): {text}",
            e.code,
            e.message
        )
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
    /// bucket's or its account's; see `public_access`): then it allows
    /// nothing to anyone outside the bucket's account, anonymous or not, not
    /// even what it allows another account by name (as in S3).
    restricted: bool,
    /// Its tags, if its ABAC is enabled (see `s3::buckets::abac`): then its
    /// and its objects' `aws:ResourceTag`s and `s3:BucketTag`s (probed).
    abac_tags: Option<Tags>,
    /// Whether its ACLs are enabled (see `s3::acl`).
    acls: bool,
    /// Whether its public ACLs are ignored (IgnorePublicAcls, its own or its
    /// account's).
    ignore_public_acls: bool,
    /// What its ACL allows, as a policy, if ACLs are enabled and it allows
    /// anyone but its owner anything.
    acl: Option<Arc<Policy>>,
}

/// A version's owner (an account), and what its ACL allows, as a policy.
type ObjectAcl = (String, Option<Arc<Policy>>);

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
    /// Who makes the request; `None` if anonymous.
    user: Option<Who_>,
    identity: Vec<Arc<Policy>>,
    /// A session's policies, if they cap its principal's (see
    /// `users::SessionOf`).
    session: Option<Vec<Arc<Policy>>>,
    /// The user's permissions boundary, and its ARN.
    boundary: Option<(Arc<Policy>, String)>,
    /// Its account's service control policies, by level (see
    /// `organizations`).
    scps: Vec<Vec<Arc<Policy>>>,
    /// The user's ARN (its path and all).
    arn: Option<String>,
    pub context: Context,
    /// Each bucket loaded: whether it exists, and its policy (see `Loaded`).
    buckets: HashMap<String, Loaded>,
    /// The tags of the versions the request is on, by bucket and key, as
    /// they were looked up (see `s3::abac`): their `s3:ExistingObjectTag`s.
    object_tags: HashMap<(String, String), Tags>,
    /// The owners of the versions the request is on, by bucket and key, and
    /// what their ACLs allow, as a policy (see `set_object_acl`).
    object_acls: HashMap<(String, String), ObjectAcl>,
    /// The directory bucket whose zonal operations the request may make,
    /// its session (or its checks) having said so (see `s3::directory`):
    /// every check on it is allowed but regional operations'.
    granted: Option<String>,
    /// The directory bucket the request writes to, if it does: its session
    /// must be a `ReadWrite` one.
    writes: Option<String>,
    /// The policies of the topics checks are on, by their ARNs (see
    /// `set_topic_policy`).
    topics: HashMap<String, Arc<Policy>>,
    /// The organization's management account, which owns the cluster (see
    /// `set_management`): unset, the cluster is no one's, and every check
    /// on it denied.
    management: Option<String>,
    /// An S3 Access Grants instance the checks may be on (see
    /// `set_grants_instance`): its ARN, its account, and its resource
    /// policy, if it has one.
    grants: Option<(String, String, Option<Arc<Policy>>)>,
}

/// Who makes a request, as policies see it (an owned `policy::Principal`).
enum Who_ {
    User {
        account: String,
        name: String,
        id: String,
    },
    /// An account's root user (see `policy::root_verdict`).
    Root {
        account: String,
    },
    Session {
        account: String,
        role: String,
        id: String,
        session: String,
    },
    Federated {
        account: String,
        name: String,
    },
}

impl Who_ {
    fn of(principal: &Principal) -> Who_ {
        use crate::sessions::Who as Session;
        let account = principal.account.clone();
        if principal.root {
            return Who_::Root { account };
        }
        match principal.session.as_ref().map(|s| &s.session.who) {
            Some(Session::Role { session, .. }) => Who_::Session {
                account,
                // By its path and name, as policies name roles.
                role: format!(
                    "{}{}",
                    principal.path.strip_prefix('/').unwrap_or(&principal.path),
                    principal.name
                ),
                id: principal.id.to_string(),
                session: session.clone(),
            },
            Some(Session::Federated { name, .. }) => Who_::Federated {
                account,
                name: name.clone(),
            },
            _ => Who_::User {
                account,
                name: principal.name.clone(),
                id: principal.id.to_string(),
            },
        }
    }

    fn as_policy(&self) -> Who<'_> {
        match self {
            Who_::User { account, name, id } => Who::User { account, name, id },
            Who_::Root { account } => Who::Root { account },
            // A session's role by its name only, as session ARNs name it.
            Who_::Session {
                account,
                role,
                id,
                session,
            } => Who::Session {
                account,
                role: role_name(role),
                id,
                session,
            },
            Who_::Federated { account, name } => Who::Federated { account, name },
        }
    }

    fn account(&self) -> &str {
        match self {
            Who_::User { account, .. }
            | Who_::Root { account }
            | Who_::Session { account, .. }
            | Who_::Federated { account, .. } => account,
        }
    }
}

/// The account of a role's ARN.
fn trust_account(role: &str) -> Option<&str> {
    role.strip_prefix("arn:aws:iam::")?.split(':').next()
}

/// A role's name, from its path and name.
fn role_name(path_name: &str) -> &str {
    path_name.rsplit('/').next().unwrap_or(path_name)
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
        let mut boundary = None;
        let mut session = None;
        let mut scps = Vec::new();
        if let Some(principal) = principal {
            for level in &principal.scps {
                let mut policies = Vec::new();
                for document in level {
                    policies.push(parsed(document, Kind::Identity, None)?);
                }
                scps.push(policies);
            }
            if let Some(of) = principal.session.as_ref().filter(|of| of.restricted) {
                let mut policies = Vec::new();
                for document in &of.policies {
                    policies.push(parsed(document, Kind::Identity, None)?);
                }
                session = Some(policies);
            }
            if principal.admin {
                identity.push(parsed(&actions::admin_policy(), Kind::Identity, None)?);
            }
            for document in &principal.policies {
                identity.push(parsed(document, Kind::Identity, None)?);
            }
            if let Some(b) = &principal.boundary {
                boundary = Some((parsed(&b.document, Kind::Identity, None)?, b.arn.clone()));
            }
        }
        Ok(Access {
            user: principal.map(Who_::of),
            arn: principal.map(Principal::arn),
            identity,
            session,
            boundary,
            scps,
            context: context(principal, account, method, headers, query, origin),
            buckets: HashMap::new(),
            object_tags: HashMap::new(),
            object_acls: HashMap::new(),
            granted: None,
            writes: None,
            topics: HashMap::new(),
            management: None,
            grants: None,
        })
    }

    /// Says that checks on the S3 Access Grants instance `arn` (and on its
    /// locations and grants) are on `account`'s, whose resource policy
    /// `policy` decides them as a bucket's policy decides its checks:
    /// across accounts, with the principal's own policies.
    pub fn set_grants_instance(&mut self, arn: &str, account: &str, policy: Option<Arc<Policy>>) {
        self.grants = Some((arn.to_owned(), account.to_owned(), policy));
    }

    /// The Access Grants instance (as `set_grants_instance` said) that
    /// `resource` (an ARN) is, or is a location or grant of.
    fn grants_of(&self, resource: &str) -> Option<&(String, String, Option<Arc<Policy>>)> {
        self.grants.as_ref().filter(|(arn, _, _)| {
            resource == arn
                || resource
                    .strip_prefix(arn.as_str())
                    .is_some_and(|r| r.starts_with('/'))
        })
    }

    /// Says which account is the organization's management account, which
    /// owns the cluster: its principals' policies may allow them `cairn:`
    /// actions, a member account's never do.
    pub fn set_management(&mut self, account: &str) {
        self.management = Some(account.to_owned());
    }

    /// Allows the request every check on directory bucket `bucket` but
    /// those of regional operations: it may make the bucket's zonal
    /// operations (see `s3::directory`).
    pub fn grant(&mut self, bucket: &str) {
        self.granted = Some(bucket.to_owned());
    }

    /// Says the request writes to directory bucket `bucket`: its
    /// `s3express:CreateSession` on it is checked in `ReadWrite` mode.
    pub fn writes(&mut self, bucket: &str) {
        self.writes = Some(bucket.to_owned());
    }

    /// Whether `check` is on the bucket `grant` allowed, and not a regional
    /// operation's.
    fn granted(&self, check: &Check) -> bool {
        let regional = check.action.starts_with("s3express:")
            && check.action != crate::s3::directory::CREATE_SESSION;
        self.granted.is_some() && check.on.bucket() == self.granted.as_deref() && !regional
    }

    /// The ARN of the user's permissions boundary, if it has one.
    pub fn boundary(&self) -> Option<&str> {
        self.boundary.as_ref().map(|(_, arn)| arn.as_str())
    }

    /// Loads `bucket`'s policy, for the checks on it; whether it exists.
    pub async fn load(&mut self, app: &App, bucket: &str) -> anyhow::Result<bool> {
        if let Some(loaded) = self.buckets.get(bucket) {
            return Ok(loaded.exists);
        }
        // A granted bucket's checks need no policy; whether it's there, its
        // operations tell.
        if self.granted.as_deref() == Some(bucket) {
            return Ok(true);
        }
        let row = app
            .pool
            .get()
            .await?
            .query_opt_cached(
                "SELECT b.policy, b.policy_principals::text, b.account_id,
                        coalesce(b.public_access_block, 0) & 8 <> 0 OR coalesce(a.public_access_block, 0) & 8 <> 0,
                        CASE WHEN b.abac THEN coalesce(b.tags, '') END,
                        b.object_ownership, b.acl,
                        coalesce(b.public_access_block, 0) & 2 <> 0 OR coalesce(a.public_access_block, 0) & 2 <> 0
                 FROM buckets b JOIN accounts a ON a.id = b.account_id WHERE b.name = $1",
                &[&bucket],
            )
            .await?;
        let policy = match row.as_ref().and_then(|row| row.get::<_, Option<String>>(0)) {
            Some(text) => {
                // Its users, by the IDs they had when it was set (see
                // `db::PRINCIPAL_IDS`).
                let ids = row.as_ref().and_then(|row| row.get::<_, Option<String>>(1));
                Some(parsed(
                    &text,
                    Kind::Bucket(bucket),
                    Some(ids.as_deref().unwrap_or("{}")),
                )?)
            }
            None => None,
        };
        let restrict = row
            .as_ref()
            .and_then(|row| row.get::<_, Option<bool>>(3))
            .unwrap_or(false);
        let account = row.as_ref().map(|row| row.get::<_, String>(2));
        let restricted = restrict && policy.as_ref().is_some_and(|policy| policy.is_public());
        let abac_tags = row
            .as_ref()
            .and_then(|row| row.get::<_, Option<&str>>(4))
            .map(Tags::from_stored);
        let ownership = crate::s3::acl::Ownership::from_stored(
            row.as_ref().and_then(|row| row.get::<_, Option<&str>>(5)),
        );
        let acls = row.is_some() && ownership.enabled();
        let ignore_public_acls = row.as_ref().is_some_and(|row| row.get::<_, bool>(7));
        let acl = match (&row, &account) {
            (Some(row), Some(owner)) if acls => {
                let acl = crate::s3::acl::Acl::from_stored(row.get(6), owner);
                match acl.policy(
                    crate::s3::acl::On::Bucket,
                    bucket,
                    owner,
                    ignore_public_acls,
                ) {
                    Some(text) => Some(parsed(&text, Kind::Bucket(bucket), None)?),
                    None => None,
                }
            }
            _ => None,
        };
        let loaded = Loaded {
            exists: row.is_some(),
            account,
            policy,
            restricted,
            abac_tags,
            acls,
            ignore_public_acls,
            acl,
        };
        self.buckets.insert(bucket.to_owned(), loaded);
        Ok(row.is_some())
    }

    /// Whether a policy that could decide a check on `bucket` (or one on no
    /// bucket) tests `key`, a condition key's name or prefix (lowercase):
    /// what's only worth looking up then (see `s3::abac`). Load the bucket
    /// first.
    pub fn tests(&self, bucket: Option<&str>, key: &str) -> bool {
        let tests = |policy: &Policy| policy.normalized().to_ascii_lowercase().contains(key);
        let bucket_policy = bucket
            .and_then(|b| self.buckets.get(b))
            .and_then(|l| l.policy.as_deref());
        self.identity.iter().any(|p| tests(p))
            || self.session.iter().flatten().any(|p| tests(p))
            || self.boundary.as_ref().is_some_and(|(p, _)| tests(p))
            || bucket_policy.is_some_and(tests)
    }

    /// Sets the tags of the version of `key` in `bucket` the request is on:
    /// its checks on the key carry them as `s3:ExistingObjectTag`s.
    pub fn set_object_tags(&mut self, bucket: &str, key: &str, tags: Tags) {
        self.object_tags
            .insert((bucket.to_owned(), key.to_owned()), tags);
    }

    /// Whether `bucket` (loaded) has ACLs enabled.
    pub fn acls_enabled(&self, bucket: &str) -> bool {
        self.buckets.get(bucket).is_some_and(|l| l.acls)
    }

    /// Sets the owner (an account) and ACL of the version of `key` in
    /// `bucket` (loaded) the request is on: its checks of what's about it
    /// (`acl::OWNED`) are its owner's, and what its ACL allows, allowed.
    pub fn set_object_acl(
        &mut self,
        bucket: &str,
        key: &str,
        owner: &str,
        acl: &crate::s3::acl::Acl,
    ) -> anyhow::Result<()> {
        let ignore_public = self
            .buckets
            .get(bucket)
            .is_some_and(|l| l.ignore_public_acls);
        let policy = match acl.policy(crate::s3::acl::On::Object, bucket, owner, ignore_public) {
            Some(text) => Some(parsed(&text, Kind::Bucket(bucket), None)?),
            None => None,
        };
        self.object_acls.insert(
            (bucket.to_owned(), key.to_owned()),
            (owner.to_owned(), policy),
        );
        Ok(())
    }

    /// Forgets the versions' tags `set_object_tags` set: for checks on
    /// other versions, made with the same access (a batch job's tasks, see
    /// `batch`).
    pub fn forget_object_tags(&mut self) {
        self.object_tags.clear();
        self.object_acls.clear();
    }

    /// Sets the policy of the topic `arn` (see `sns`), which checks on it
    /// are decided by as their resource's.
    pub fn set_topic_policy(&mut self, arn: &str, policy: Arc<Policy>) {
        self.topics.insert(arn.to_owned(), policy);
    }

    /// Loads the policies of the buckets `checks` are on.
    pub async fn load_all(&mut self, app: &App, checks: &[Check]) -> anyhow::Result<()> {
        for bucket in checks.iter().filter_map(|c| c.on.bucket()) {
            self.load(app, bucket).await?;
        }
        Ok(())
    }

    /// The verdict on `check`, whose bucket's policy is loaded (else the
    /// bucket is taken to have none).
    pub fn verdict(&self, check: &Check) -> Verdict {
        self.verdict_with(check, &Context::default())
    }

    /// As `verdict`, with the condition keys `extra` too: those of the
    /// resource (a user's tags, say) and of what an IAM request asks for
    /// (see `iam`).
    pub fn verdict_with(&self, check: &Check, extra: &Context) -> Verdict {
        if self.granted(check) {
            return Verdict::Allow;
        }
        // A zonal operation of a directory bucket needs a session's creation
        // to be allowed: in `ReadWrite` mode to write, in either to read
        // (see `s3::directory`). CreateSession says its mode itself.
        use crate::s3::directory::{CREATE_SESSION, SESSION_MODE};
        if check.action == CREATE_SESSION
            && self.context.get(SESSION_MODE).is_none()
            && extra.get(SESSION_MODE).is_none()
        {
            let in_mode = |mode: &str| {
                let mut extra = extra.clone();
                extra.set(SESSION_MODE, mode);
                self.verdict_with(check, &extra)
            };
            if check.on.bucket().is_some() && check.on.bucket() == self.writes.as_deref() {
                return in_mode("ReadWrite");
            }
            return match in_mode("ReadOnly") {
                Verdict::Allow => Verdict::Allow,
                verdict => match in_mode("ReadWrite") {
                    Verdict::Allow => Verdict::Allow,
                    _ => verdict,
                },
            };
        }
        let resource = check.on.arn();
        let principal = self.user.as_ref().map_or(Who::Anonymous, Who_::as_policy);
        let loaded = check.on.bucket().and_then(|b| self.buckets.get(b));
        // A restricted bucket's public policy is none to anyone outside its
        // account.
        // A directory bucket's regional operations are allowed by identity
        // policies only, never by its own (see `s3::directory`).
        let regional = check.action.starts_with("s3express:") && check.action != CREATE_SESSION;
        let bucket = loaded
            .filter(|loaded| !(loaded.restricted && loaded.account.as_deref() != self.account()))
            .filter(|_| !regional)
            .and_then(|loaded| loaded.policy.as_deref());
        // A topic's policy is its resource policy, as a bucket's is; and an
        // Access Grants instance's.
        let bucket = match &check.on {
            On::Topic(..) => self.topics.get(&resource).map(|p| &**p),
            On::Arn(arn) if self.grants_of(arn).is_some() => {
                self.grants_of(arn).and_then(|(_, _, p)| p.as_deref())
            }
            _ => bucket,
        };
        // What ACLs allow (see `s3::acl`), as the bucket's policy would: on
        // an object, what's about it its owner's ACL, and the bucket's
        // policy only denies it if that's another account; else the
        // bucket's ACL.
        let owned = match &check.on {
            On::Object(b, k) if crate::s3::acl::OWNED.contains(&check.action) => {
                self.object_acls.get(&(b.clone(), k.clone()))
            }
            _ => None,
        };
        let bucket_account = loaded.and_then(|l| l.account.as_deref());
        let (denials_only, acl) = match owned {
            Some((owner, acl)) => (Some(owner.as_str()) != bucket_account, acl.as_deref()),
            None => (false, loaded.and_then(|l| l.acl.as_deref())),
        };
        let replaced = matches!(check.on, On::Bucket(_) | On::Object(..))
            && !regional
            && (denials_only || acl.is_some());
        let merged = match replaced {
            false => None,
            true => {
                let base = bucket.map(|b| if denials_only { b.denials() } else { b.clone() });
                match (base, acl) {
                    (Some(base), Some(acl)) => Some(base.merged(acl)),
                    (base, None) => base,
                    (None, Some(acl)) => Some(acl.clone()),
                }
            }
        };
        let bucket = if replaced { merged.as_ref() } else { bucket };
        // Whose the resource is: a bucket's owner; else (no bucket, or none
        // by its name) the principal's own account's. A bucket to create is
        // the principal's, whoever has its name (that's BucketAlreadyExists).
        let owner = match &check.on {
            On::User(account, _)
            | On::Users(account, _)
            | On::Role(account, _)
            | On::Roles(account, _) => Some(account.as_str()),
            On::Topic(account, _) => Some(account.as_str()),
            // Cairn's (AWS's) policies are no account's: as the principal's own.
            On::Policy(account, _) if account != "aws" => Some(account.as_str()),
            // The management account's, whose operators' policies allow
            // them `cairn:` actions; never anonymously, nor to a member
            // account's (see `organizations`).
            On::Cluster => Some(self.management.as_deref().unwrap_or("")),
            On::Arn(arn) if self.grants_of(arn).is_some() => {
                self.grants_of(arn).map(|(_, account, _)| account.as_str())
            }
            // An object's owner's, what's about it.
            On::Object(..) if owned.is_some() => owned.map(|(owner, _)| owner.as_str()),
            _ => loaded
                .and_then(|loaded| loaded.account.as_deref())
                .filter(|_| !matches!(check.action, "s3:CreateBucket" | "s3express:CreateBucket")),
        };
        // `aws:ResourceAccount` is that account (else the principal's own;
        // anonymously, the one the request was made in).
        let resource_account = owner.or(self.account());
        let mut context = self.context.clone();
        context.extend(extra);
        // The bucket's tags, with its ABAC enabled: not to create it, as it's
        // not there yet (whoever has its name).
        if let Some(tags) = loaded
            .and_then(|l| l.abac_tags.as_ref())
            .filter(|_| !matches!(check.action, "s3:CreateBucket" | "s3express:CreateBucket"))
        {
            for (key, value) in tags.iter() {
                context.set(&format!("aws:ResourceTag/{key}"), value);
                context.set(&format!("s3:BucketTag/{key}"), value);
            }
        }
        if let On::Object(bucket, key) = &check.on
            && let Some(tags) = self.object_tags.get(&(bucket.clone(), key.clone()))
        {
            for (key, value) in tags.iter() {
                context.set(&format!("s3:ExistingObjectTag/{key}"), value);
            }
        }
        if let Some(account) = resource_account {
            context.set("aws:ResourceAccount", account);
            context.set("s3:ResourceAccount", account);
            if check.action.starts_with("s3express:") {
                context.set("s3express:ResourceAccount", account);
            }
        }
        // Only the `s3:` keys this action takes (see `Context::for_action`).
        let context = context.for_action(check.action);
        let request = crate::policy::Request {
            principal,
            action: check.action,
            resource: &resource,
            context: &context,
        };
        // An account's root user: no identity policy restricts it, only
        // resource policies (a bucket's, a topic's) may.
        if let Some(Who_::Root { account }) = &self.user {
            return crate::policy::root_verdict(
                bucket,
                &request,
                owner.is_none_or(|owner| owner == account),
            );
        }
        let cross = match (&self.user, owner) {
            (Some(who), Some(owner)) => who.account() != owner,
            _ => false,
        };
        let boundary = self.boundary.as_ref().map(|(policy, _)| &**policy);
        let session: Option<Vec<&Policy>> = self
            .session
            .as_ref()
            .map(|policies| policies.iter().map(|p| &**p).collect());
        let scps = self.scp_levels();
        let caps = crate::policy::Caps {
            boundary,
            session: session.as_deref(),
            scps: &scps,
        };
        crate::policy::verdict_across(
            self.identity.iter().map(|p| &**p),
            caps,
            bucket,
            &request,
            cross,
        )
    }

    /// Its account's SCPs, by level, as `Caps` takes them.
    fn scp_levels(&self) -> Vec<Vec<&Policy>> {
        self.scps
            .iter()
            .map(|level| level.iter().map(|p| &**p).collect())
            .collect()
    }

    /// Whether `trust` (a role's trust policy, its principals' IDs given)
    /// lets the principal take `action` (`sts:AssumeRole`, ...) on the role
    /// `role` (its ARN), with the condition keys `extra` too (see
    /// `policy::trust_allows`).
    pub fn trusted(&self, action: &str, role: &str, trust: &Policy, extra: &Context) -> bool {
        // An account's root user assumes no role, as in AWS.
        if matches!(self.user, Some(Who_::Root { .. })) {
            return false;
        }
        let principal = self.user.as_ref().map_or(Who::Anonymous, Who_::as_policy);
        let mut context = self.context.clone();
        context.extend(extra);
        // The role's account (which may be another than the principal's).
        let owner = trust_account(role).or(self.account());
        if let Some(account) = owner {
            context.set("aws:ResourceAccount", account);
        }
        let request = crate::policy::Request {
            principal,
            action,
            resource: role,
            context: &context,
        };
        let boundary = self.boundary.as_ref().map(|(policy, _)| &**policy);
        let session: Option<Vec<&Policy>> = self
            .session
            .as_ref()
            .map(|policies| policies.iter().map(|p| &**p).collect());
        let scps = self.scp_levels();
        let caps = crate::policy::Caps {
            boundary,
            session: session.as_deref(),
            scps: &scps,
        };
        let cross = owner.is_some_and(|owner| self.account() != Some(owner));
        crate::policy::trust_allows(
            self.identity.iter().map(|p| &**p),
            caps,
            trust,
            &request,
            cross,
        )
    }

    /// Whether `trust` lets a web identity of the OIDC provider `provider`
    /// (its ARN) take `action` on the role `role` (its ARN), with the
    /// condition keys `extra` too (the token's): it has no identity
    /// policies, so only a statement naming the provider allows it.
    pub fn web_identity_trusted(
        &self,
        provider: &str,
        action: &str,
        role: &str,
        trust: &Policy,
        extra: &Context,
    ) -> bool {
        let mut context = self.context.clone();
        context.extend(extra);
        if let Some(account) = trust_account(role) {
            context.set("aws:ResourceAccount", account);
        }
        let request = crate::policy::Request {
            principal: Who::WebIdentity { provider },
            action,
            resource: role,
            context: &context,
        };
        let caps = crate::policy::Caps {
            boundary: None,
            session: None,
            scps: &[],
        };
        crate::policy::trust_allows(std::iter::empty(), caps, trust, &request, false)
    }

    /// The account the principal acts in; `None` if anonymous.
    fn account(&self) -> Option<&str> {
        self.user.as_ref().map(Who_::account)
    }

    /// Whether `check` is one only its bucket's own account may make (on
    /// the bucket's policy), and the principal is of another (or anonymous),
    /// whatever the policy allows it: S3 answers it 405 MethodNotAllowed.
    /// (Its bucket must be loaded.)
    pub fn foreign(&self, check: &Check) -> bool {
        let owner = check
            .on
            .bucket()
            .and_then(|b| self.buckets.get(b))
            .and_then(|l| l.account.as_deref());
        crate::policy::POLICY_ACTIONS.contains(&check.action)
            && owner.is_some_and(|owner| self.account() != Some(owner))
    }

    /// Whether `check` is allowed.
    pub fn allows(&self, check: &Check) -> bool {
        self.verdict(check) == Verdict::Allow
    }

    /// The first of `checks` not allowed, and why; `None` if all are.
    pub fn first_denied<'c>(&self, checks: &'c [Check]) -> Option<(&'c Check, Verdict)> {
        checks
            .iter()
            .map(|c| (c, self.verdict(c)))
            .find(|(_, v)| *v != Verdict::Allow)
    }

    /// S3's 403 for `check`, denied by `verdict`: to a user, it says what
    /// was denied and why (probed); anonymously, just that it was.
    pub fn denied(&self, check: &Check, verdict: Verdict) -> Response<Full<Bytes>> {
        let Some(arn) = &self.arn else {
            return format_s3_error(StatusCode::FORBIDDEN, "AccessDenied", "Access Denied");
        };
        let on = match &check.on {
            On::Account => String::new(),
            on => format!(" on resource: \"{}\"", on.arn()),
        };
        let why = verdict.why(check.action, self.boundary());
        let message = format!(
            "User: {arn} is not authorized to perform: {}{on} {why}",
            check.action
        );
        format_s3_error(StatusCode::FORBIDDEN, "AccessDenied", &message)
    }
}

/// Which of `buckets` (names; its own account's) `principal`'s identity
/// policies allow it to list (`s3:ListBucket`), as ListBuckets shows them to
/// a user not allowed `s3:ListAllMyBuckets`: alongside those whose own
/// policies name it (`grants::visible`). Conditions on the request (its
/// address, say) are decided as for a request that has none.
pub fn listable(
    principal: &Principal,
    buckets: &[&str],
) -> anyhow::Result<std::collections::HashSet<String>> {
    let origin = Origin {
        peer: None,
        trusted_proxies: &[],
        signed: None,
        form: false,
    };
    let access = Access::new(
        Some(principal),
        &principal.account,
        &Method::GET,
        &HeaderMap::new(),
        "",
        &origin,
    )?;
    Ok(buckets
        .iter()
        .filter(|b| {
            access.allows(&Check {
                action: "s3:ListBucket",
                on: On::Bucket((**b).to_owned()),
            })
        })
        .map(|b| (*b).to_owned())
        .collect())
}

/// The address a request comes from, as `aws:SourceIp` has it (see
/// `source`): its connection's `peer`, or what a trusted proxy says.
pub fn client_address(
    headers: &HeaderMap,
    peer: Option<IpAddr>,
    trusted_proxies: &[Network],
) -> Option<IpAddr> {
    source(
        headers,
        &Origin {
            peer,
            trusted_proxies,
            signed: None,
            form: false,
        },
    )
    .0
}

/// Where a request comes from: its peer, or (from a trusted proxy) the
/// first address in `X-Forwarded-For` that isn't one; and whether it came
/// over HTTPS (Cairn speaks only HTTP, so that's a trusted proxy's word).
fn source(headers: &HeaderMap, origin: &Origin) -> (Option<IpAddr>, bool) {
    let trusted = |ip: IpAddr| origin.trusted_proxies.iter().any(|n| n.contains(ip));
    let Some(peer) = origin.peer.map(|ip| ip.to_canonical()) else {
        return (None, false);
    };
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
    let client = forwarded
        .iter()
        .rev()
        .find(|ip| !trusted(**ip))
        .or(forwarded.first())
        .copied()
        .unwrap_or(peer);
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
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
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
            use crate::sessions::Who as Session;
            let session = principal.session.as_ref().map(|of| &of.session);
            // A user's name, but a role session's or a federated user's
            // (probed).
            if !principal.root
                && !matches!(
                    session.map(|s| &s.who),
                    Some(Session::Role { .. } | Session::Federated { .. })
                )
            {
                context.set("aws:username", &principal.name);
            }
            context.set("aws:userid", principal.unique_id());
            context.set("aws:PrincipalArn", principal.principal_arn());
            for (key, value) in &principal.tags {
                context.set(&format!("aws:PrincipalTag/{key}"), value);
            }
            context.set("aws:PrincipalAccount", &principal.account);
            let kind = match session.map(|s| &s.who) {
                _ if principal.root => "Account",
                Some(Session::Role { .. }) => "AssumedRole",
                Some(Session::Federated { .. }) => "FederatedUser",
                _ => "User",
            };
            context.set("aws:PrincipalType", kind);
            context.set("aws:PrincipalIsAWSService", "false");
            // A session's: when it was issued, its source identity, and no
            // MFA (present, false: probed). Long-term keys carry none.
            if let Some(session) = session {
                context.set("aws:TokenIssueTime", crate::sessions::iso(session.issued));
                if let Some(source) = &session.source_identity {
                    context.set("aws:SourceIdentity", source);
                }
                if let Some(provider) = &session.provider {
                    context.set("aws:FederatedProvider", provider);
                }
                // Vended by S3 Access Grants (see `s3::access_grants`).
                if let Some(instance) = &session.access_grants {
                    context.set("s3:AccessGrantsInstanceArn", instance);
                }
                context.set("aws:MultiFactorAuthPresent", "false");
            }
        }
        None => {
            context.set("aws:userid", "anonymous");
            context.set("aws:PrincipalType", "Anonymous");
        }
    }
    if let Some(signed) = origin.signed {
        context.set("aws:RequestedRegion", &signed.region);
        context.set("s3:signatureversion", signed.signature_version());
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
    // A listing's: what it lists, and how much, as far as it says (an
    // empty `prefix=` is there, empty; no `max-keys`, no `s3:max-keys`:
    // probed). Only actions that take them see them (`for_action`).
    for name in ["prefix", "delimiter", "max-keys"] {
        if let Some(value) = query_param(query, name) {
            context.set(&format!("s3:{name}"), value);
        }
    }
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
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
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
    crate::policy::date(&iso)
        .filter(|s| *s >= 0.0)
        .map(|s| s as u64)
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
        let from = |peer: &str, trusted| Origin {
            peer: Some(peer.parse().unwrap()),
            trusted_proxies: trusted,
            signed: None,
            form: false,
        };
        assert_eq!(
            source(&headers, &from("10.0.0.1", &trusted)),
            (Some("203.0.113.9".parse().unwrap()), true)
        );
        // From anyone else, the headers are the client's own word.
        assert_eq!(
            source(&headers, &from("198.51.100.1", &trusted)),
            (Some("198.51.100.1".parse().unwrap()), false)
        );
        assert_eq!(
            source(&headers, &from("10.0.0.1", &[])),
            (Some(proxy), false)
        );
        // Only proxies: the farthest.
        headers.insert("x-forwarded-for", "10.0.0.8".parse().unwrap());
        assert_eq!(
            source(&headers, &from("10.0.0.1", &trusted)).0,
            Some("10.0.0.8".parse().unwrap())
        );
    }
}
