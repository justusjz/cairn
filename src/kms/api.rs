//! AWS KMS's API, on the S3 port: requests signed for the `kms` service
//! are these, whatever their path, as SNS's are (see `sns`). Its JSON
//! protocol (`X-Amz-Target: TrentService.<Operation>`, JSON 1.1), its
//! errors. Symmetric keys only (`SYMMETRIC_DEFAULT`): keys, aliases,
//! policies, tags, rotation, scheduled deletion; Encrypt, Decrypt,
//! ReEncrypt, GenerateDataKey(WithoutPlaintext), GenerateRandom. No grants,
//! no asymmetric, HMAC, imported, multi-Region keys or custom key stores.
//!
//! A request acts as its signer: each action is checked as KMS's own
//! (`kms:Decrypt` on the key's ARN, ...), by the key's policy and the
//! signer's own policies, as KMS checks it (see `policy::key_verdict`):
//! the key's policy must allow it, by naming the principal, or by naming
//! its account, which leaves it to its identity policies. Actions on no key
//! (CreateKey, ListKeys, ListAliases, GenerateRandom) and on aliases are the
//! identity policies' alone.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;

use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode, body::Bytes};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::keys::{self, KeyError, KeyRef, KmsKey, State};
use crate::{
    App,
    auth::Signed,
    policy::{Context, Kind, Policy, Verdict},
    s3::{
        access::{Access, Origin},
        actions::{Check, On},
    },
    users::{self, Principal},
};

/// The most a request's body may hold.
const MAX_BODY: usize = 1 << 20;
/// The most a key policy may be, as KMS takes them.
const MAX_POLICY: usize = 32 * 1024;
/// The most tags a key may have.
const MAX_TAGS: usize = 50;

/// Whether a request signed so is KMS's.
pub fn wants(signed: &Signed) -> bool {
    signed.service == "kms"
}

/// A failed request: its status, KMS's type for it, and a message.
#[derive(Debug)]
pub struct Error {
    status: StatusCode,
    kind: &'static str,
    message: String,
}

fn error(status: StatusCode, kind: &'static str, message: impl Into<String>) -> Error {
    Error {
        status,
        kind,
        message: message.into(),
    }
}

fn bad(kind: &'static str, message: impl Into<String>) -> Error {
    error(StatusCode::BAD_REQUEST, kind, message)
}

fn validation(message: impl Into<String>) -> Error {
    bad("ValidationException", message)
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Error {
        eprintln!("kms: request failed: {e:#}");
        error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "KMSInternalException",
            "internal error; the node's log has the details",
        )
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

impl From<super::RootError> for Error {
    fn from(e: super::RootError) -> Error {
        KeyError::from(e).into()
    }
}

impl From<KeyError> for Error {
    fn from(e: KeyError) -> Error {
        match e {
            KeyError::NotFound => bad("NotFoundException", "The key isn't there."),
            KeyError::Disabled => bad("DisabledException", "The key is disabled."),
            KeyError::PendingDeletion => {
                bad("KMSInvalidStateException", "The key is pending deletion.")
            }
            KeyError::InvalidCiphertext => bad("InvalidCiphertextException", ""),
            KeyError::Unavailable(e) => {
                eprintln!("kms: the root key is unavailable: {e:#}");
                error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "DependencyTimeoutException",
                    "The KMS's root key is unavailable; please try again later.",
                )
            }
            KeyError::Internal(e) => e.into(),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

/// A KMS request, on the S3 port.
pub async fn handle(
    app: &Arc<App>,
    req: Request<crate::listen::ClientBody>,
    signed: Signed,
    peer: IpAddr,
) -> Response<Full<Bytes>> {
    let request_id = Uuid::new_v4().to_string();
    let (status, body) = match respond(app, req, &signed, peer).await {
        Ok(answer) => (StatusCode::OK, answer.to_string()),
        Err(e) => (
            e.status,
            json!({ "__type": e.kind, "message": e.message }).to_string(),
        ),
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
        .map_err(|_| {
            bad(
                "SerializationException",
                "the request's body is too large, or broken",
            )
        })?
        .to_bytes();
    let operation = parts
        .headers
        .get("x-amz-target")
        .and_then(|v| v.to_str().ok())
        .and_then(|t| t.strip_prefix("TrentService."))
        .ok_or_else(|| bad("UnknownOperationException", ""))?
        .to_owned();
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
            return Err(bad(
                "ExpiredTokenException",
                "The security token included in the request is expired",
            ));
        }
        Err(_) => {
            return Err(bad(
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
        bad(
            if r.code == "SignatureDoesNotMatch" {
                "InvalidSignatureException"
            } else {
                "IncompleteSignature"
            },
            r.message,
        )
    })?;
    let params: Value = if body.is_empty() {
        Value::Object(Map::new())
    } else {
        serde_json::from_slice(&body)
            .map_err(|_| bad("SerializationException", "the request's body isn't JSON"))?
    };
    let Value::Object(params) = params else {
        return Err(bad(
            "SerializationException",
            "the request's body isn't a JSON object",
        ));
    };
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
    let Some(kms) = app.kms.clone() else {
        return Err(error(
            StatusCode::NOT_IMPLEMENTED,
            "UnsupportedOperationException",
            "Cairn has no KMS: give it a root key (--kms-root-key-file or --kms-address)",
        ));
    };
    let mut api = Api {
        kms: &kms,
        client: &client,
        principal: &principal,
        access: &access,
        params: Params(params),
    };
    api.dispatch(&operation).await
}

/// A request's parameters.
struct Params(Map<String, Value>);

impl Params {
    fn value(&self, name: &str) -> Option<&Value> {
        self.0.get(name).filter(|v| !v.is_null())
    }

    fn string(&self, name: &str) -> Result<Option<&str>> {
        match self.value(name) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s)),
            Some(_) => Err(bad(
                "SerializationException",
                format!("{name} must be a string"),
            )),
        }
    }

    fn required(&self, name: &str) -> Result<&str> {
        self.string(name)?.ok_or_else(|| {
            validation(format!(
                "1 validation error detected: Value null at '{}' failed to satisfy constraint: Member must not be null",
                lower_first(name)
            ))
        })
    }

    fn bool(&self, name: &str) -> Result<bool> {
        match self.value(name) {
            None => Ok(false),
            Some(Value::Bool(b)) => Ok(*b),
            Some(_) => Err(bad(
                "SerializationException",
                format!("{name} must be a boolean"),
            )),
        }
    }

    fn int(&self, name: &str) -> Result<Option<i64>> {
        match self.value(name) {
            None => Ok(None),
            Some(Value::Number(n)) => n.as_i64().map(Some).ok_or_else(|| {
                bad(
                    "SerializationException",
                    format!("{name} must be an integer"),
                )
            }),
            Some(_) => Err(bad(
                "SerializationException",
                format!("{name} must be an integer"),
            )),
        }
    }

    /// A blob: base64.
    fn blob(&self, name: &str) -> Result<Option<Vec<u8>>> {
        match self.string(name)? {
            None => Ok(None),
            Some(b64) => STANDARD
                .decode(b64)
                .map(Some)
                .map_err(|_| bad("SerializationException", format!("{name} isn't base64"))),
        }
    }

    /// An encryption context: a map of strings.
    fn context(&self, name: &str) -> Result<BTreeMap<String, String>> {
        match self.value(name) {
            None => Ok(BTreeMap::new()),
            Some(Value::Object(map)) => map
                .iter()
                .map(|(k, v)| match v {
                    Value::String(v) => Ok((k.clone(), v.clone())),
                    _ => Err(bad(
                        "SerializationException",
                        format!("{name}'s values must be strings"),
                    )),
                })
                .collect(),
            Some(_) => Err(bad(
                "SerializationException",
                format!("{name} must be a map of strings"),
            )),
        }
    }

    /// The paging limit (1 to `max`, `default` if not given).
    fn limit(&self, default: i64, max: i64) -> Result<i64> {
        match self.int("Limit")? {
            None => Ok(default),
            Some(n) if (1..=max).contains(&n) => Ok(n),
            Some(n) => Err(validation(format!(
                "1 validation error detected: Value '{n}' at 'limit' failed to satisfy constraint: Member must have value between 1 and {max}"
            ))),
        }
    }

    /// The encryption algorithm, which must be `SYMMETRIC_DEFAULT`.
    fn algorithm(&self, name: &str) -> Result<()> {
        match self.string(name)? {
            None | Some(keys::ALGORITHM) => Ok(()),
            Some(other) => Err(bad(
                "InvalidKeyUsageException",
                format!(
                    "Cairn's keys are symmetric: their algorithm is SYMMETRIC_DEFAULT, not {other}"
                ),
            )),
        }
    }

    /// Tags (`[{TagKey, TagValue}]`).
    fn tags(&self) -> Result<Vec<(String, String)>> {
        let Some(value) = self.value("Tags") else {
            return Ok(Vec::new());
        };
        let Value::Array(items) = value else {
            return Err(bad("SerializationException", "Tags must be a list"));
        };
        let mut tags: Vec<(String, String)> = Vec::new();
        for item in items {
            let key = item.get("TagKey").and_then(Value::as_str);
            let value = item.get("TagValue").and_then(Value::as_str);
            let (Some(key), Some(value)) = (key, value) else {
                return Err(bad(
                    "TagException",
                    "Each tag must have a TagKey and a TagValue",
                ));
            };
            check_tag(key, value)?;
            tags.retain(|(k, _)| k != key);
            tags.push((key.to_owned(), value.to_owned()));
        }
        Ok(tags)
    }
}

fn lower_first(name: &str) -> String {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) => c.to_ascii_lowercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

fn check_tag(key: &str, value: &str) -> Result<()> {
    if key.is_empty() || key.chars().count() > 128 || value.chars().count() > 256 {
        return Err(bad(
            "TagException",
            "A tag's key must be 1 to 128 characters, its value at most 256",
        ));
    }
    if key.starts_with("aws:") {
        return Err(bad("TagException", "Tags beginning with aws: are reserved"));
    }
    Ok(())
}

/// A request's actions, as its signer.
struct Api<'a> {
    kms: &'a super::Kms,
    client: &'a deadpool_postgres::Object,
    principal: &'a Principal,
    access: &'a Access,
    params: Params,
}

/// KMS's operations Cairn doesn't have (its symmetric keys need none of
/// them).
const OTHER_OPERATIONS: &[&str] = &[
    "ConnectCustomKeyStore",
    "CreateCustomKeyStore",
    "CreateGrant",
    "DeleteCustomKeyStore",
    "DeleteImportedKeyMaterial",
    "DeriveSharedSecret",
    "DescribeCustomKeyStores",
    "DisconnectCustomKeyStore",
    "GenerateDataKeyPair",
    "GenerateDataKeyPairWithoutPlaintext",
    "GenerateMac",
    "GetParametersForImport",
    "GetPublicKey",
    "ImportKeyMaterial",
    "ListGrants",
    "ListRetirableGrants",
    "ReplicateKey",
    "RetireGrant",
    "RevokeGrant",
    "Sign",
    "UpdateCustomKeyStore",
    "UpdatePrimaryRegion",
    "Verify",
    "VerifyMac",
];

impl Api<'_> {
    async fn dispatch(&mut self, operation: &str) -> Result<Value> {
        match operation {
            "CreateKey" => self.create_key().await,
            "DescribeKey" => self.describe_key().await,
            "ListKeys" => self.list_keys().await,
            "EnableKey" => self.set_enabled(true).await,
            "DisableKey" => self.set_enabled(false).await,
            "ScheduleKeyDeletion" => self.schedule_key_deletion().await,
            "CancelKeyDeletion" => self.cancel_key_deletion().await,
            "UpdateKeyDescription" => self.update_key_description().await,
            "GetKeyPolicy" => self.get_key_policy().await,
            "PutKeyPolicy" => self.put_key_policy().await,
            "ListKeyPolicies" => self.list_key_policies().await,
            "EnableKeyRotation" => self.enable_key_rotation().await,
            "DisableKeyRotation" => self.disable_key_rotation().await,
            "GetKeyRotationStatus" => self.get_key_rotation_status().await,
            "RotateKeyOnDemand" => self.rotate_key_on_demand().await,
            "ListKeyRotations" => self.list_key_rotations().await,
            "CreateAlias" => self.create_alias().await,
            "UpdateAlias" => self.update_alias().await,
            "DeleteAlias" => self.delete_alias().await,
            "ListAliases" => self.list_aliases().await,
            "TagResource" => self.tag_resource().await,
            "UntagResource" => self.untag_resource().await,
            "ListResourceTags" => self.list_resource_tags().await,
            "Encrypt" => self.encrypt().await,
            "Decrypt" => self.decrypt().await,
            "ReEncrypt" => self.re_encrypt().await,
            "GenerateDataKey" => self.generate_data_key(true).await,
            "GenerateDataKeyWithoutPlaintext" => self.generate_data_key(false).await,
            "GenerateRandom" => self.generate_random().await,
            other if OTHER_OPERATIONS.contains(&other) => Err(bad(
                "UnsupportedOperationException",
                format!(
                    "Cairn's KMS has symmetric keys, without grants, custom key stores or imported material: not {other}"
                ),
            )),
            _ => Err(bad("UnknownOperationException", "")),
        }
    }

    fn account(&self) -> &str {
        &self.principal.account
    }

    /// Refuses the request unless the identity policies allow `action` on
    /// `on` (no key's policy is about it).
    fn check_identity(&self, action: &'static str, on: On) -> Result<()> {
        let check = Check { action, on };
        let verdict = self.access.verdict_with(&check, &Context::default());
        if verdict == Verdict::Allow {
            return Ok(());
        }
        let resource = match &check.on {
            On::Account => "*".to_owned(),
            on => on.arn(),
        };
        Err(denied(format!(
            "User: {} is not authorized to perform: {action} on resource: {resource} {}",
            self.principal.arn(),
            verdict.why(action, self.access.boundary())
        )))
    }

    /// Refuses the request unless `action` on `key` is allowed, with the
    /// condition keys `extra` too.
    fn check_key(&self, action: &str, key: &KmsKey, extra: &Context) -> Result<()> {
        match keys::authorize(self.access, action, key, extra)? {
            Ok(()) => Ok(()),
            Err(message) => Err(denied(message)),
        }
    }

    /// The key a request's parameter `name` names, as `action` on it
    /// allows (with `extra` too): KMS's 400 if there's none.
    async fn key_for(&self, name: &str, action: &str, extra: &Context) -> Result<KmsKey> {
        let given = self.params.required(name)?;
        self.named_key(given, action, extra).await
    }

    async fn named_key(&self, given: &str, action: &str, extra: &Context) -> Result<KmsKey> {
        let Some(named) = KeyRef::parse(given) else {
            return Err(bad("NotFoundException", format!("Invalid keyId '{given}'")));
        };
        let key = self.resolve(&named, given).await?;
        let mut extra = extra.clone();
        if let Some(alias) = named.alias() {
            extra.set("kms:RequestAlias", alias);
        }
        self.check_key(action, &key, &extra)?;
        Ok(key)
    }

    /// The key `named` (given as `given`) names, of the caller's account
    /// or (by an ARN) another's of the organization, open.
    async fn resolve(&self, named: &KeyRef, given: &str) -> Result<KmsKey> {
        if let Some(account) = named.account()
            && account != self.account()
            && !crate::organizations::open(self.client, account).await?
        {
            return Err(not_found(named, given));
        }
        keys::resolve(self.client, self.account(), named)
            .await?
            .ok_or_else(|| not_found(named, given))
    }

    /// Refuses a change to an AWS managed key, which no one manages.
    fn customer_managed(&self, key: &KmsKey) -> Result<()> {
        match key.aws_managed {
            true => Err(bad(
                "UnsupportedOperationException",
                format!(
                    "{} is an AWS managed key, which can't be changed",
                    key.arn()
                ),
            )),
            false => Ok(()),
        }
    }

    /// Refuses a change to a key that's pending deletion.
    fn not_pending(&self, key: &KmsKey) -> Result<()> {
        match key.state {
            State::PendingDeletion => Err(bad(
                "KMSInvalidStateException",
                format!("{} is pending deletion.", key.arn()),
            )),
            _ => Ok(()),
        }
    }

    /// Refuses an operation with DryRun once it'd have been allowed.
    fn dry_run(&self) -> Result<()> {
        match self.params.bool("DryRun")? {
            true => Err(error(
                StatusCode::PRECONDITION_FAILED,
                "DryRunOperationException",
                "The request would have succeeded, but the DryRun option is set.",
            )),
            false => Ok(()),
        }
    }

    /// `text` as a key policy, normalized, if it's one KMS would take,
    /// and it'd still let the caller change it (unless
    /// `BypassPolicyLockoutSafetyCheck`).
    async fn checked_policy(&self, text: &str, arn: &str, key_account: &str) -> Result<String> {
        if text.len() > MAX_POLICY {
            return Err(bad(
                "MalformedPolicyDocumentException",
                format!("The key policy is longer than {MAX_POLICY} bytes"),
            ));
        }
        let checked = crate::s3::buckets::policy::check_as(self.client, Kind::Key(arn), text)
            .await?
            .map_err(|refused| match refused.status {
                StatusCode::NOT_IMPLEMENTED => error(
                    StatusCode::NOT_IMPLEMENTED,
                    "UnsupportedOperationException",
                    refused.message,
                ),
                _ => bad("MalformedPolicyDocumentException", refused.message),
            })?;
        if !self.params.bool("BypassPolicyLockoutSafetyCheck")? {
            let policy = Policy::parse(&checked.normalized, Kind::Key(arn))
                .map_err(|e| bad("MalformedPolicyDocumentException", e.message))?;
            // The names it gives users and roles by, as the database will
            // keep them (see `cairn_policy_principals`).
            let ids = self.principal_ids(&checked.normalized).await?;
            let policy = policy.with_ids(ids);
            let mut extra = Context::default();
            extra.set("kms:BypassPolicyLockoutSafetyCheck", "false");
            let verdict =
                self.access
                    .key_verdict("kms:PutKeyPolicy", arn, key_account, &policy, &extra);
            if verdict != Verdict::Allow {
                return Err(bad(
                    "MalformedPolicyDocumentException",
                    "The new key policy will not allow you to update the key policy in the future.",
                ));
            }
        }
        Ok(checked.normalized)
    }

    /// The users and roles a policy names, by their ARNs: their IDs.
    async fn principal_ids(
        &self,
        policy: &str,
    ) -> Result<std::collections::HashMap<String, String>> {
        let rows = self
            .client
            .query(
                "SELECT p.arn, coalesce(u.id, r.id)::text
                 FROM (
                     SELECT DISTINCT a #>> '{}' AS arn
                     FROM jsonb_path_query($1::text::jsonb, 'lax $.Statement[*].Principal.AWS[*]') a
                 ) p
                 LEFT JOIN users u ON u.account_id = substring(p.arn FROM '^arn:aws:iam::([0-9]{12}):user/')
                                  AND substring(u.path FROM 2) || u.name = substring(p.arn FROM '^arn:aws:iam::[0-9]{12}:user/(.+)$')
                 LEFT JOIN iam_roles r ON r.account_id = substring(p.arn FROM '^arn:aws:iam::([0-9]{12}):role/')
                                      AND substring(r.path FROM 2) || r.name = substring(p.arn FROM '^arn:aws:iam::[0-9]{12}:role/(.+)$')
                 WHERE u.id IS NOT NULL OR r.id IS NOT NULL",
                &[&policy],
            )
            .await?;
        Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
    }

    async fn reload(&self, id: Uuid) -> Result<KmsKey> {
        KmsKey::load(self.client, id)
            .await?
            .ok_or_else(|| bad("NotFoundException", "The key isn't there."))
    }

    // Keys.

    async fn create_key(&mut self) -> Result<Value> {
        self.check_identity("kms:CreateKey", On::Account)?;
        for (name, only) in [
            ("KeyUsage", keys::KEY_USAGE),
            ("KeySpec", keys::KEY_SPEC),
            ("CustomerMasterKeySpec", keys::KEY_SPEC),
            ("Origin", keys::ORIGIN),
        ] {
            if let Some(given) = self.params.string(name)?
                && given != only
            {
                return Err(bad(
                    "UnsupportedOperationException",
                    format!("Cairn's keys are {only} keys: not {name} {given}"),
                ));
            }
        }
        if self.params.string("CustomKeyStoreId")?.is_some() {
            return Err(bad(
                "UnsupportedOperationException",
                "Cairn has no custom key stores",
            ));
        }
        if self.params.bool("MultiRegion")? {
            return Err(bad(
                "UnsupportedOperationException",
                "Cairn has no multi-Region keys",
            ));
        }
        let description = self.params.string("Description")?.unwrap_or("").to_owned();
        if description.chars().count() > 8192 {
            return Err(validation("Description must be at most 8192 characters"));
        }
        let tags = self.params.tags()?;
        if tags.len() > MAX_TAGS {
            return Err(bad("TagException", "A key may have at most 50 tags"));
        }
        if !tags.is_empty() {
            self.check_identity("kms:TagResource", On::Account)?;
        }
        let account = self.account().to_owned();
        // A policy is checked as the key's, which has no ARN yet: `*` it
        // is, as a key's policy names it.
        let policy = match self.params.string("Policy")? {
            Some(text) => {
                let text = text.to_owned();
                self.checked_policy(&text, "*", &account).await?
            }
            None => Policy::parse(&keys::default_policy(&account), Kind::Key("*"))
                .map_err(|e| anyhow::anyhow!("the default key policy: {}", e.message))?
                .normalized()
                .to_owned(),
        };
        let new = keys::NewKey {
            account: &account,
            description: &description,
            policy: &policy,
            aws_managed: false,
            tags: &tags,
        };
        let key = keys::create(self.kms, self.client, &new).await??;
        Ok(json!({ "KeyMetadata": metadata(&key) }))
    }

    async fn describe_key(&mut self) -> Result<Value> {
        let key = self
            .key_for("KeyId", "kms:DescribeKey", &Context::default())
            .await?;
        Ok(json!({ "KeyMetadata": metadata(&key) }))
    }

    async fn list_keys(&mut self) -> Result<Value> {
        self.check_identity("kms:ListKeys", On::Account)?;
        let limit = self.params.limit(100, 1000)?;
        let after = marker_id(self.params.string("Marker")?)?;
        let mut keys = KmsKey::list(self.client, self.account(), after, limit + 1).await?;
        let truncated = keys.len() as i64 > limit;
        keys.truncate(limit as usize);
        let mut answer = json!({
            "Keys": keys.iter().map(|k| json!({ "KeyId": k.id, "KeyArn": k.arn() })).collect::<Vec<_>>(),
            "Truncated": truncated,
        });
        if truncated {
            answer["NextMarker"] = json!(keys.last().unwrap().id.to_string());
        }
        Ok(answer)
    }

    async fn set_enabled(&mut self, enabled: bool) -> Result<Value> {
        let action = if enabled {
            "kms:EnableKey"
        } else {
            "kms:DisableKey"
        };
        let key = self.key_for("KeyId", action, &Context::default()).await?;
        self.customer_managed(&key)?;
        self.not_pending(&key)?;
        let state = if enabled { "Enabled" } else { "Disabled" };
        self.client
            .execute(
                "UPDATE kms_keys SET state = $2 WHERE id = $1 AND state <> 'PendingDeletion'",
                &[&key.id, &state],
            )
            .await?;
        Ok(json!({}))
    }

    async fn schedule_key_deletion(&mut self) -> Result<Value> {
        let days = self.params.int("PendingWindowInDays")?.unwrap_or(30);
        if !(7..=30).contains(&days) {
            return Err(validation(format!(
                "1 validation error detected: Value '{days}' at 'pendingWindowInDays' failed to satisfy constraint: Member must have value between 7 and 30"
            )));
        }
        let mut extra = Context::default();
        extra.set(
            "kms:ScheduleKeyDeletionPendingWindowInDays",
            days.to_string(),
        );
        let key = self
            .key_for("KeyId", "kms:ScheduleKeyDeletion", &extra)
            .await?;
        self.customer_managed(&key)?;
        self.not_pending(&key)?;
        let days = days as i32;
        let row = self
            .client
            .query_one(
                "UPDATE kms_keys SET state = 'PendingDeletion', pending_days = $2,
                        deletion_date = now() + make_interval(days => $2)
                 WHERE id = $1 RETURNING extract(epoch FROM deletion_date)::float8",
                &[&key.id, &days],
            )
            .await?;
        let date: f64 = row.get(0);
        Ok(json!({
            "KeyId": key.arn(),
            "DeletionDate": date,
            "KeyState": "PendingDeletion",
            "PendingWindowInDays": days,
        }))
    }

    async fn cancel_key_deletion(&mut self) -> Result<Value> {
        let key = self
            .key_for("KeyId", "kms:CancelKeyDeletion", &Context::default())
            .await?;
        if key.state != State::PendingDeletion {
            return Err(bad(
                "KMSInvalidStateException",
                format!("{} is not pending deletion.", key.arn()),
            ));
        }
        // Disabled, as KMS leaves it.
        self.client
            .execute(
                "UPDATE kms_keys SET state = 'Disabled', deletion_date = NULL, pending_days = NULL WHERE id = $1",
                &[&key.id],
            )
            .await?;
        Ok(json!({ "KeyId": key.arn() }))
    }

    async fn update_key_description(&mut self) -> Result<Value> {
        let description = self.params.required("Description")?.to_owned();
        if description.chars().count() > 8192 {
            return Err(validation("Description must be at most 8192 characters"));
        }
        let key = self
            .key_for("KeyId", "kms:UpdateKeyDescription", &Context::default())
            .await?;
        self.customer_managed(&key)?;
        self.not_pending(&key)?;
        self.client
            .execute(
                "UPDATE kms_keys SET description = $2 WHERE id = $1",
                &[&key.id, &description],
            )
            .await?;
        Ok(json!({}))
    }

    fn policy_name(&self) -> Result<()> {
        match self.params.string("PolicyName")? {
            None | Some("default") => Ok(()),
            Some(_) => Err(bad("NotFoundException", "No such policy exists")),
        }
    }

    async fn get_key_policy(&mut self) -> Result<Value> {
        self.policy_name()?;
        let key = self
            .key_for("KeyId", "kms:GetKeyPolicy", &Context::default())
            .await?;
        Ok(json!({ "Policy": key.policy, "PolicyName": "default" }))
    }

    async fn put_key_policy(&mut self) -> Result<Value> {
        self.policy_name()?;
        let text = self.params.required("Policy")?.to_owned();
        let mut extra = Context::default();
        extra.set(
            "kms:BypassPolicyLockoutSafetyCheck",
            self.params
                .bool("BypassPolicyLockoutSafetyCheck")?
                .to_string(),
        );
        let key = self.key_for("KeyId", "kms:PutKeyPolicy", &extra).await?;
        self.customer_managed(&key)?;
        self.not_pending(&key)?;
        let policy = self.checked_policy(&text, &key.arn(), &key.account).await?;
        self.client
            .execute(
                "UPDATE kms_keys SET policy = $2 WHERE id = $1",
                &[&key.id, &policy],
            )
            .await?;
        Ok(json!({}))
    }

    async fn list_key_policies(&mut self) -> Result<Value> {
        self.key_for("KeyId", "kms:ListKeyPolicies", &Context::default())
            .await?;
        Ok(json!({ "PolicyNames": ["default"], "Truncated": false }))
    }

    // Rotation.

    async fn enable_key_rotation(&mut self) -> Result<Value> {
        let days = self.params.int("RotationPeriodInDays")?.unwrap_or(365);
        if !(90..=2560).contains(&days) {
            return Err(validation(format!(
                "1 validation error detected: Value '{days}' at 'rotationPeriodInDays' failed to satisfy constraint: Member must have value between 90 and 2560"
            )));
        }
        let mut extra = Context::default();
        extra.set("kms:RotationPeriodInDays", days.to_string());
        let key = self
            .key_for("KeyId", "kms:EnableKeyRotation", &extra)
            .await?;
        self.customer_managed(&key)?;
        key.usable()?;
        let days = days as i32;
        // A period that changes moves the next rotation, as from the last.
        self.client
            .execute(
                "UPDATE kms_keys SET rotation_days = $2,
                        next_rotation = coalesce(
                            (SELECT max(created_at) FROM kms_key_versions WHERE key_id = $1),
                            now()) + make_interval(days => $2)
                 WHERE id = $1",
                &[&key.id, &days],
            )
            .await?;
        Ok(json!({}))
    }

    async fn disable_key_rotation(&mut self) -> Result<Value> {
        let key = self
            .key_for("KeyId", "kms:DisableKeyRotation", &Context::default())
            .await?;
        self.customer_managed(&key)?;
        key.usable()?;
        self.client
            .execute(
                "UPDATE kms_keys SET rotation_days = NULL, next_rotation = NULL WHERE id = $1",
                &[&key.id],
            )
            .await?;
        Ok(json!({}))
    }

    async fn get_key_rotation_status(&mut self) -> Result<Value> {
        let key = self
            .key_for("KeyId", "kms:GetKeyRotationStatus", &Context::default())
            .await?;
        let mut answer = json!({
            "KeyId": key.id,
            "KeyRotationEnabled": key.rotation_days.is_some(),
        });
        if let Some(days) = key.rotation_days {
            answer["RotationPeriodInDays"] = json!(days);
        }
        if let Some(next) = key.next_rotation {
            answer["NextRotationDate"] = json!(next);
        }
        Ok(answer)
    }

    async fn rotate_key_on_demand(&mut self) -> Result<Value> {
        let key = self
            .key_for("KeyId", "kms:RotateKeyOnDemand", &Context::default())
            .await?;
        self.customer_managed(&key)?;
        key.usable()?;
        let rotations: i64 = self
            .client
            .query_one(
                "SELECT count(*) FROM kms_key_versions WHERE key_id = $1 AND rotation = 'ON_DEMAND'",
                &[&key.id],
            )
            .await?
            .get(0);
        if rotations >= 25 {
            return Err(bad(
                "LimitExceededException",
                "A key may be rotated on demand 25 times at most",
            ));
        }
        keys::rotate(self.kms, self.client, &key, false).await?;
        Ok(json!({ "KeyId": key.id }))
    }

    async fn list_key_rotations(&mut self) -> Result<Value> {
        let key = self
            .key_for("KeyId", "kms:ListKeyRotations", &Context::default())
            .await?;
        let limit = self.params.limit(100, 1000)?;
        let after: i32 = match self.params.string("Marker")? {
            None => 1,
            Some(marker) => marker
                .parse()
                .map_err(|_| validation("Marker isn't one of this operation's"))?,
        };
        let rows = self
            .client
            .query(
                "SELECT version, extract(epoch FROM created_at)::float8, rotation FROM kms_key_versions
                 WHERE key_id = $1 AND version > $2 ORDER BY version LIMIT $3",
                &[&key.id, &after, &(limit + 1)],
            )
            .await?;
        let truncated = rows.len() as i64 > limit;
        let rotations: Vec<Value> = rows
            .iter()
            .take(limit as usize)
            .map(|r| {
                json!({
                    "KeyId": key.id,
                    "RotationDate": r.get::<_, f64>(1),
                    "RotationType": r.get::<_, Option<String>>(2).unwrap_or_else(|| "AUTOMATIC".to_owned()),
                })
            })
            .collect();
        let mut answer = json!({ "Rotations": rotations, "Truncated": truncated });
        if truncated {
            let last: i32 = rows[limit as usize - 1].get(0);
            answer["NextMarker"] = json!(last.to_string());
        }
        Ok(answer)
    }

    // Aliases.

    /// An alias name a request gives, as one may be made: not `aws/`'s.
    fn new_alias(&self) -> Result<String> {
        let name = self.params.required("AliasName")?;
        if !keys::valid_alias(name) {
            return Err(validation(format!(
                "1 validation error detected: Value '{name}' at 'aliasName' failed to satisfy constraint: Member must satisfy regular expression pattern: ^alias/[a-zA-Z0-9/_-]+$"
            )));
        }
        if name.starts_with("alias/aws/") {
            return Err(bad(
                "NotAuthorizedException",
                "Aliases beginning with alias/aws/ are reserved for AWS managed keys.",
            ));
        }
        Ok(name.to_owned())
    }

    /// The key an alias is to name: of the caller's account, by its ID or
    /// ARN, not an alias.
    async fn alias_target(&self, action: &str) -> Result<KmsKey> {
        let given = self.params.required("TargetKeyId")?;
        let named = KeyRef::parse(given);
        if !matches!(named, Some(KeyRef::Id { .. })) {
            return Err(validation("TargetKeyId must be a key's ID or ARN"));
        }
        let key = self.named_key(given, action, &Context::default()).await?;
        if key.account != self.account() {
            return Err(bad("NotFoundException", format!("Invalid keyId '{given}'")));
        }
        self.not_pending(&key)?;
        if key.aws_managed {
            return Err(bad(
                "NotAuthorizedException",
                "An alias can't name an AWS managed key",
            ));
        }
        Ok(key)
    }

    async fn create_alias(&mut self) -> Result<Value> {
        let name = self.new_alias()?;
        self.check_identity(
            "kms:CreateAlias",
            On::Arn(keys::alias_arn(self.account(), &name)),
        )?;
        let key = self.alias_target("kms:CreateAlias").await?;
        let made = self
            .client
            .execute(
                "INSERT INTO kms_aliases (account_id, name, key_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                &[&self.account(), &name, &key.id],
            )
            .await?;
        if made == 0 {
            return Err(bad(
                "AlreadyExistsException",
                format!(
                    "An alias with the name {} already exists",
                    keys::alias_arn(self.account(), &name)
                ),
            ));
        }
        Ok(json!({}))
    }

    /// The caller's alias the request names, and the key it names now.
    async fn existing_alias(&self, action: &'static str) -> Result<(String, KmsKey)> {
        let name = self.params.required("AliasName")?.to_owned();
        let arn = keys::alias_arn(self.account(), &name);
        self.check_identity(action, On::Arn(arn.clone()))?;
        if name.starts_with("alias/aws/") {
            return Err(bad(
                "NotAuthorizedException",
                "Aliases beginning with alias/aws/ are reserved for AWS managed keys.",
            ));
        }
        let row = self
            .client
            .query_opt(
                "SELECT key_id FROM kms_aliases WHERE account_id = $1 AND name = $2",
                &[&self.account(), &name],
            )
            .await?;
        let Some(row) = row else {
            return Err(bad(
                "NotFoundException",
                format!("Alias {arn} is not found."),
            ));
        };
        let key = self.reload(row.get(0)).await?;
        self.check_key(action, &key, &Context::default())?;
        Ok((name, key))
    }

    async fn update_alias(&mut self) -> Result<Value> {
        let (name, _) = self.existing_alias("kms:UpdateAlias").await?;
        let key = self.alias_target("kms:UpdateAlias").await?;
        self.client
            .execute(
                "UPDATE kms_aliases SET key_id = $3, updated_at = now() WHERE account_id = $1 AND name = $2",
                &[&self.account(), &name, &key.id],
            )
            .await?;
        Ok(json!({}))
    }

    async fn delete_alias(&mut self) -> Result<Value> {
        let (name, _) = self.existing_alias("kms:DeleteAlias").await?;
        self.client
            .execute(
                "DELETE FROM kms_aliases WHERE account_id = $1 AND name = $2",
                &[&self.account(), &name],
            )
            .await?;
        Ok(json!({}))
    }

    async fn list_aliases(&mut self) -> Result<Value> {
        let limit = self.params.limit(50, 100)?;
        let key = match self.params.string("KeyId")? {
            Some(given) => Some(
                self.named_key(given, "kms:ListAliases", &Context::default())
                    .await?,
            ),
            None => {
                self.check_identity("kms:ListAliases", On::Account)?;
                None
            }
        };
        let after = self.params.string("Marker")?.unwrap_or("").to_owned();
        let owner = key
            .as_ref()
            .map_or(self.account().to_owned(), |k| k.account.clone());
        let key_id = key.as_ref().map(|k| k.id);
        let rows = self
            .client
            .query(
                "SELECT name, key_id, extract(epoch FROM created_at)::float8, extract(epoch FROM updated_at)::float8
                 FROM kms_aliases WHERE account_id = $1 AND ($2::uuid IS NULL OR key_id = $2) AND name > $3
                 ORDER BY name LIMIT $4",
                &[&owner, &key_id, &after, &(limit + 1)],
            )
            .await?;
        let truncated = rows.len() as i64 > limit;
        let aliases: Vec<Value> = rows
            .iter()
            .take(limit as usize)
            .map(|r| {
                let name: String = r.get(0);
                json!({
                    "AliasName": name,
                    "AliasArn": keys::alias_arn(&owner, &name),
                    "TargetKeyId": r.get::<_, Uuid>(1),
                    "CreationDate": r.get::<_, f64>(2),
                    "LastUpdatedDate": r.get::<_, f64>(3),
                })
            })
            .collect();
        let mut answer = json!({ "Aliases": aliases, "Truncated": truncated });
        if truncated {
            answer["NextMarker"] = json!(rows[limit as usize - 1].get::<_, String>(0));
        }
        Ok(answer)
    }

    // Tags.

    async fn tag_resource(&mut self) -> Result<Value> {
        let tags = self.params.tags()?;
        let key = self
            .key_for("KeyId", "kms:TagResource", &Context::default())
            .await?;
        self.customer_managed(&key)?;
        self.not_pending(&key)?;
        let mut all = key.tags.clone();
        for (k, v) in tags {
            all.retain(|(old, _)| *old != k);
            all.push((k, v));
        }
        if all.len() > MAX_TAGS {
            return Err(bad("TagException", "A key may have at most 50 tags"));
        }
        self.save_tags(&key, &all).await
    }

    async fn untag_resource(&mut self) -> Result<Value> {
        let names: Vec<String> = match self.params.value("TagKeys") {
            Some(Value::Array(items)) => items
                .iter()
                .map(|v| v.as_str().map(str::to_owned))
                .collect::<Option<_>>()
                .ok_or_else(|| bad("SerializationException", "TagKeys must be strings"))?,
            _ => return Err(validation("TagKeys must be a list")),
        };
        let key = self
            .key_for("KeyId", "kms:UntagResource", &Context::default())
            .await?;
        self.customer_managed(&key)?;
        self.not_pending(&key)?;
        let mut all = key.tags.clone();
        all.retain(|(k, _)| !names.contains(k));
        self.save_tags(&key, &all).await
    }

    async fn save_tags(&self, key: &KmsKey, tags: &[(String, String)]) -> Result<Value> {
        let tags = serde_json::to_string(tags).map_err(anyhow::Error::from)?;
        self.client
            .execute(
                "UPDATE kms_keys SET tags = $2::text::jsonb WHERE id = $1",
                &[&key.id, &tags],
            )
            .await?;
        Ok(json!({}))
    }

    async fn list_resource_tags(&mut self) -> Result<Value> {
        let key = self
            .key_for("KeyId", "kms:ListResourceTags", &Context::default())
            .await?;
        let limit = self.params.limit(50, 50)? as usize;
        let skip: usize = match self.params.string("Marker")? {
            None => 0,
            Some(m) => m
                .parse()
                .map_err(|_| validation("Marker isn't one of this operation's"))?,
        };
        let tags: Vec<Value> = key
            .tags
            .iter()
            .skip(skip)
            .take(limit)
            .map(|(k, v)| json!({ "TagKey": k, "TagValue": v }))
            .collect();
        let truncated = key.tags.len() > skip + limit;
        let mut answer = json!({ "Tags": tags, "Truncated": truncated });
        if truncated {
            answer["NextMarker"] = json!((skip + limit).to_string());
        }
        Ok(answer)
    }

    // Cryptography.

    /// The condition keys of a cryptographic operation with `context`.
    fn crypto_context(context: &BTreeMap<String, String>) -> Context {
        let mut extra = keys::context_keys(context);
        extra.set("kms:EncryptionAlgorithm", keys::ALGORITHM);
        extra
    }

    async fn encrypt(&mut self) -> Result<Value> {
        let plaintext = self.params.blob("Plaintext")?.unwrap_or_default();
        if plaintext.is_empty() || plaintext.len() > 4096 {
            return Err(validation(
                "1 validation error detected: Value at 'plaintext' failed to satisfy constraint: Member must have length between 1 and 4096",
            ));
        }
        let plaintext = zeroize::Zeroizing::new(plaintext);
        self.params.algorithm("EncryptionAlgorithm")?;
        let context = self.params.context("EncryptionContext")?;
        let key = self
            .key_for("KeyId", "kms:Encrypt", &Self::crypto_context(&context))
            .await?;
        self.dry_run()?;
        let blob = keys::encrypt(self.kms, self.client, &key, &plaintext, &context).await?;
        Ok(json!({
            "CiphertextBlob": STANDARD.encode(blob),
            "KeyId": key.arn(),
            "EncryptionAlgorithm": keys::ALGORITHM,
        }))
    }

    /// The key a ciphertext blob is of, as `action` on it allows; the key
    /// the request names (`key_param`), if it does, must be that one.
    async fn blob_key(
        &self,
        blob: &[u8],
        key_param: &str,
        action: &str,
        context: &BTreeMap<String, String>,
    ) -> Result<KmsKey> {
        let Some((id, _)) = keys::blob_key(blob) else {
            return Err(bad("InvalidCiphertextException", ""));
        };
        let key = KmsKey::load(self.client, id)
            .await?
            .ok_or_else(|| bad("InvalidCiphertextException", ""))?;
        if let Some(given) = self.params.string(key_param)? {
            let named = match KeyRef::parse(given) {
                Some(named) => self.resolve(&named, given).await?,
                None => return Err(bad("NotFoundException", format!("Invalid keyId '{given}'"))),
            };
            if named.id != key.id {
                return Err(bad(
                    "IncorrectKeyException",
                    "The key ID in the request does not identify a KMS key that can perform this operation.",
                ));
            }
        }
        self.check_key(action, &key, &Self::crypto_context(context))?;
        Ok(key)
    }

    async fn decrypt(&mut self) -> Result<Value> {
        let blob = self.params.blob("CiphertextBlob")?.unwrap_or_default();
        if blob.is_empty() || blob.len() > keys::MAX_BLOB {
            return Err(validation(
                "1 validation error detected: Value at 'ciphertextBlob' failed to satisfy constraint: Member must have length between 1 and 6144",
            ));
        }
        self.params.algorithm("EncryptionAlgorithm")?;
        if self.params.value("Recipient").is_some() {
            return Err(bad(
                "UnsupportedOperationException",
                "Cairn has no Nitro Enclaves",
            ));
        }
        let context = self.params.context("EncryptionContext")?;
        let key = self
            .blob_key(&blob, "KeyId", "kms:Decrypt", &context)
            .await?;
        self.dry_run()?;
        let plaintext = keys::decrypt(self.kms, self.client, &key, &blob, &context).await?;
        Ok(json!({
            "KeyId": key.arn(),
            "Plaintext": STANDARD.encode(&*plaintext),
            "EncryptionAlgorithm": keys::ALGORITHM,
        }))
    }

    async fn re_encrypt(&mut self) -> Result<Value> {
        let blob = self.params.blob("CiphertextBlob")?.unwrap_or_default();
        if blob.is_empty() || blob.len() > keys::MAX_BLOB {
            return Err(validation(
                "1 validation error detected: Value at 'ciphertextBlob' failed to satisfy constraint: Member must have length between 1 and 6144",
            ));
        }
        self.params.algorithm("SourceEncryptionAlgorithm")?;
        self.params.algorithm("DestinationEncryptionAlgorithm")?;
        let source_context = self.params.context("SourceEncryptionContext")?;
        let dest_context = self.params.context("DestinationEncryptionContext")?;
        let source = self
            .blob_key(&blob, "SourceKeyId", "kms:ReEncryptFrom", &source_context)
            .await?;
        let mut extra = Self::crypto_context(&dest_context);
        let dest_given = self.params.required("DestinationKeyId")?.to_owned();
        let same = KeyRef::parse(&dest_given)
            .is_some_and(|named| matches!(named, KeyRef::Id { id, .. } if id == source.id));
        extra.set("kms:ReEncryptOnSameKey", same.to_string());
        let dest = self
            .named_key(&dest_given, "kms:ReEncryptTo", &extra)
            .await?;
        self.dry_run()?;
        let plaintext =
            keys::decrypt(self.kms, self.client, &source, &blob, &source_context).await?;
        let blob = keys::encrypt(self.kms, self.client, &dest, &plaintext, &dest_context).await?;
        Ok(json!({
            "CiphertextBlob": STANDARD.encode(blob),
            "SourceKeyId": source.arn(),
            "KeyId": dest.arn(),
            "SourceEncryptionAlgorithm": keys::ALGORITHM,
            "DestinationEncryptionAlgorithm": keys::ALGORITHM,
        }))
    }

    async fn generate_data_key(&mut self, with_plaintext: bool) -> Result<Value> {
        let length = match (
            self.params.string("KeySpec")?,
            self.params.int("NumberOfBytes")?,
        ) {
            (Some(_), Some(_)) => {
                return Err(validation("Give KeySpec or NumberOfBytes, not both"));
            }
            (Some("AES_256"), None) => 32,
            (Some("AES_128"), None) => 16,
            (Some(other), None) => {
                return Err(validation(format!(
                    "1 validation error detected: Value '{other}' at 'keySpec' failed to satisfy constraint: Member must satisfy enum value set: [AES_256, AES_128]"
                )));
            }
            (None, Some(n)) if (1..=1024).contains(&n) => n as usize,
            (None, Some(n)) => {
                return Err(validation(format!(
                    "1 validation error detected: Value '{n}' at 'numberOfBytes' failed to satisfy constraint: Member must have value between 1 and 1024"
                )));
            }
            (None, None) => {
                return Err(validation("Give KeySpec or NumberOfBytes"));
            }
        };
        if self.params.value("Recipient").is_some() {
            return Err(bad(
                "UnsupportedOperationException",
                "Cairn has no Nitro Enclaves",
            ));
        }
        let context = self.params.context("EncryptionContext")?;
        let action = if with_plaintext {
            "kms:GenerateDataKey"
        } else {
            "kms:GenerateDataKeyWithoutPlaintext"
        };
        let key = self
            .key_for("KeyId", action, &keys::context_keys(&context))
            .await?;
        self.dry_run()?;
        let mut plain = zeroize::Zeroizing::new(vec![0u8; length]);
        getrandom::fill(plain.as_mut_slice()).expect("the OS random number generator failed");
        let blob = keys::encrypt(self.kms, self.client, &key, &plain, &context).await?;
        let mut answer = json!({
            "CiphertextBlob": STANDARD.encode(blob),
            "KeyId": key.arn(),
        });
        if with_plaintext {
            answer["Plaintext"] = json!(STANDARD.encode(&*plain));
        }
        Ok(answer)
    }

    async fn generate_random(&mut self) -> Result<Value> {
        self.check_identity("kms:GenerateRandom", On::Account)?;
        if self.params.string("CustomKeyStoreId")?.is_some() {
            return Err(bad(
                "UnsupportedOperationException",
                "Cairn has no custom key stores",
            ));
        }
        let n = match self.params.int("NumberOfBytes")? {
            Some(n) if (1..=1024).contains(&n) => n as usize,
            Some(n) => {
                return Err(validation(format!(
                    "1 validation error detected: Value '{n}' at 'numberOfBytes' failed to satisfy constraint: Member must have value between 1 and 1024"
                )));
            }
            None => return Err(validation("NumberOfBytes is required")),
        };
        let mut bytes = zeroize::Zeroizing::new(vec![0u8; n]);
        getrandom::fill(bytes.as_mut_slice()).expect("the OS random number generator failed");
        Ok(json!({ "Plaintext": STANDARD.encode(&*bytes) }))
    }
}

fn denied(message: String) -> Error {
    bad("AccessDeniedException", message)
}

fn not_found(named: &KeyRef, given: &str) -> Error {
    match named {
        KeyRef::Alias { name, account } => bad(
            "NotFoundException",
            format!(
                "Alias {} is not found.",
                match account {
                    Some(account) => keys::alias_arn(account, name),
                    None => given.to_owned(),
                }
            ),
        ),
        KeyRef::Id { .. } => bad("NotFoundException", format!("Key '{given}' does not exist")),
    }
}

/// A key's ID from a paging marker.
fn marker_id(marker: Option<&str>) -> Result<Option<Uuid>> {
    marker
        .map(|m| Uuid::parse_str(m).map_err(|_| validation("Marker isn't one of this operation's")))
        .transpose()
}

/// A key's metadata, as KMS answers with it.
fn metadata(key: &KmsKey) -> Value {
    let mut metadata = json!({
        "AWSAccountId": key.account,
        "KeyId": key.id,
        "Arn": key.arn(),
        "CreationDate": key.created_at,
        "Enabled": key.state == State::Enabled,
        "Description": key.description,
        "KeyUsage": keys::KEY_USAGE,
        "KeyState": key.state.as_str(),
        "Origin": keys::ORIGIN,
        "KeyManager": if key.aws_managed { "AWS" } else { "CUSTOMER" },
        "CustomerMasterKeySpec": keys::KEY_SPEC,
        "KeySpec": keys::KEY_SPEC,
        "EncryptionAlgorithms": [keys::ALGORITHM],
        "MultiRegion": false,
    });
    if let Some(date) = key.deletion_date {
        metadata["DeletionDate"] = json!(date);
    }
    metadata
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
