//! Audit logging: a record of each call to the APIs that are audited (the
//! KMS's and CloudTrail's own, so far), as CloudTrail's event records have
//! them: what CloudTrail's API answers (`LookupEvents`, see `lookup`), and
//! its trails will deliver.
//!
//! Each node logs its own records (see `log`) and ships them (see `ship`)
//! into the internal bucket (see `internal`), five minutes' worth an
//! object; the database sees an object's metadata, never an event of its
//! own. A request's event is logged once it's done, with its outcome, and
//! is durable before the request is answered: every answer a client got
//! has its record. (A request that changes nothing, Decrypt say, has its
//! effect in its answer, so its record is there before its effect is.) A
//! record that can't be made durable (the disk failing, or full) fails its
//! request (a 500), rather than letting it pass unrecorded.
//!
//! That's more than CloudTrail promises, which delivers its records
//! "typically within an average of about 5 minutes", without a guarantee,
//! sometimes twice, and in no particular order. What this doesn't cover: a
//! change whose node crashed after making it and before its record was
//! synced (its client got no answer), and the records a node logged but
//! hadn't shipped, which are lost with its disk: up to five minutes' worth.

pub mod log;
pub mod lookup;
pub mod ship;

use std::{
    io,
    net::IpAddr,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::users::Principal;
pub use log::Failed;

/// The version of CloudTrail's record format the events are of.
pub const EVENT_VERSION: &str = "1.11";

/// A node's audit logging.
#[derive(Default)]
pub struct Audit {
    /// None in tests that don't audit: then nothing is recorded.
    log: Option<log::Log>,
}

impl Audit {
    /// Logs into `dir`.
    pub fn start(dir: PathBuf) -> io::Result<Audit> {
        Ok(Audit {
            log: Some(log::Log::start(dir, log::Rotation::default())?),
        })
    }

    /// Logs into `dir`, closing files as `rotation` says.
    #[cfg(test)]
    pub fn start_with(dir: PathBuf, rotation: log::Rotation) -> io::Result<Audit> {
        Ok(Audit {
            log: Some(log::Log::start(dir, rotation)?),
        })
    }

    /// Where the log is, if there's one.
    pub fn dir(&self) -> Option<&Path> {
        self.log.as_ref().map(|l| l.dir())
    }

    /// Logs `event`, once its request is done, before it's answered.
    pub async fn record(&self, event: &Event) -> Result<(), Failed> {
        let Some(log) = &self.log else {
            return Ok(());
        };
        log.append(log::line(&event.to_json().to_string())).await
    }
}

/// A resource an event is about.
#[derive(Clone, Debug, PartialEq)]
pub struct Resource {
    pub arn: String,
    pub account: String,
    /// Its type, as CloudTrail names it (`AWS::KMS::Key`).
    pub kind: &'static str,
}

/// An audited request, as CloudTrail's record of it (see `to_json`).
#[derive(Clone, Debug)]
pub struct Event {
    /// Its ID (`eventID`).
    pub id: Uuid,
    pub time: SystemTime,
    /// The service it's to (`kms.amazonaws.com`).
    pub source: &'static str,
    /// Its operation (`Decrypt`).
    pub name: String,
    /// Who made it (`userIdentity`; see `identity`).
    pub identity: Value,
    /// The address it came from: its client's (as `aws:SourceIp` has it),
    /// or the service's that made it for someone.
    pub source_ip: Option<IpAddr>,
    pub user_agent: Option<String>,
    /// The request's ID, as its response has it.
    pub request_id: String,
    /// Its parameters, without secrets (see `parameters`).
    pub parameters: Value,
    /// What its response says, for one that changes something (null for
    /// one that doesn't, and for one that failed).
    pub response: Value,
    /// Why it failed, if it did: the error's code and message.
    pub error: Option<(String, String)>,
    /// Whether it only reads (`readOnly`).
    pub read_only: bool,
    pub resources: Vec<Resource>,
    /// The account the record is for (`recipientAccountId`).
    pub recipient_account: String,
    /// Whether it was made through the console, with a console session's
    /// credentials (`sessionCredentialFromConsole`).
    pub console: bool,
}

impl Event {
    /// A request of `identity` to `source`'s `name`, now.
    pub fn new(
        source: &'static str,
        name: &str,
        identity: Value,
        recipient_account: &str,
        read_only: bool,
    ) -> Event {
        Event {
            id: Uuid::new_v4(),
            time: SystemTime::now(),
            source,
            name: name.to_owned(),
            identity,
            source_ip: None,
            user_agent: None,
            request_id: String::new(),
            parameters: Value::Null,
            response: Value::Null,
            error: None,
            read_only,
            resources: Vec::new(),
            recipient_account: recipient_account.to_owned(),
            console: false,
        }
    }

    /// A request to `source`'s `name`, as `principal` signed it with
    /// `access_key` (none, "", for the console's), now: who made it, from
    /// where (as `aws:SourceIp` has it), with what, and the ID it's
    /// answered with.
    #[allow(clippy::too_many_arguments)]
    pub fn of_request(
        source: &'static str,
        name: &str,
        principal: &Principal,
        access_key: &str,
        headers: &hyper::HeaderMap,
        peer: Option<IpAddr>,
        trusted_proxies: &[crate::policy::Network],
        request_id: &str,
        read_only: bool,
    ) -> Event {
        let mut event = Event::new(
            source,
            name,
            identity(principal, access_key),
            &principal.account,
            read_only,
        );
        event.source_ip = crate::s3::access::client_address(headers, peer, trusted_proxies);
        event.user_agent = headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        event.request_id = request_id.to_owned();
        event
    }

    /// Adds a resource it's about, unless it's there.
    pub fn touch(&mut self, resource: Resource) {
        if !self.resources.contains(&resource) {
            self.resources.push(resource);
        }
    }

    /// As CloudTrail records it.
    pub fn to_json(&self) -> Value {
        let seconds = self
            .time
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let mut record = json!({
            "eventVersion": EVENT_VERSION,
            "userIdentity": self.identity,
            "eventTime": crate::sessions::iso(seconds),
            "eventSource": self.source,
            "eventName": self.name,
            "awsRegion": crate::s3::buckets::head::REGION,
            "sourceIPAddress": self.source_ip.map(|ip| ip.to_string()),
            "userAgent": self.user_agent,
            "requestParameters": self.parameters,
            "responseElements": self.response,
            "requestID": self.request_id,
            "eventID": self.id,
            "readOnly": self.read_only,
            "resources": self.resources.iter().map(|r| json!({
                "accountId": r.account,
                "type": r.kind,
                "ARN": r.arn,
            })).collect::<Vec<_>>(),
            "eventType": "AwsApiCall",
            "managementEvent": true,
            "recipientAccountId": self.recipient_account,
            "eventCategory": "Management",
        });
        if self.console {
            record["sessionCredentialFromConsole"] = json!("true");
        }
        if let Some((code, message)) = &self.error {
            record["errorCode"] = json!(code);
            if !message.is_empty() {
                record["errorMessage"] = json!(message);
            }
        }
        record
    }
}

/// Who made a request, signed with `access_key`, as CloudTrail's
/// `userIdentity` has it: a root user, an IAM user (with its own key or a
/// session's), a role's session, or a federated user's. A console session's
/// requests aren't signed with a key: their `access_key` is "", and they
/// have no `accessKeyId`.
pub fn identity(principal: &Principal, access_key: &str) -> Value {
    use crate::sessions::Who;
    let account = &principal.account;
    let session = principal.session.as_ref().map(|s| &s.session);
    let mut identity = match session.map(|s| &s.who) {
        _ if principal.root => json!({
            "type": "Root",
            "principalId": account,
            "arn": principal.arn(),
            "accountId": account,
        }),
        Some(Who::Role { .. }) => json!({
            "type": "AssumedRole",
            "principalId": principal.unique_id(),
            "arn": principal.arn(),
            "accountId": account,
        }),
        Some(Who::Federated { .. }) => json!({
            "type": "FederatedUser",
            "principalId": principal.unique_id(),
            "arn": principal.arn(),
            "accountId": account,
        }),
        _ => json!({
            "type": "IAMUser",
            "principalId": principal.unique_id(),
            "arn": principal.arn(),
            "accountId": account,
            "userName": principal.name,
        }),
    };
    if !access_key.is_empty() {
        identity["accessKeyId"] = json!(access_key);
    }
    if let Some(session) = session {
        let mut context = json!({
            "attributes": {
                "creationDate": crate::sessions::iso(session.issued),
                "mfaAuthenticated": "false",
            },
        });
        // Whose session it is, for a role's or a federated user's.
        let issuer = match &session.who {
            Who::Role { id, .. } => Some(json!({
                "type": "Role",
                "principalId": crate::roles::unique_id(*id),
                "arn": crate::roles::role_arn(account, &principal.path, &principal.name),
                "accountId": account,
                "userName": principal.name,
            })),
            Who::Federated { id, .. } => Some(json!({
                "type": "IAMUser",
                "principalId": crate::users::unique_id("AIDA", *id),
                "arn": crate::users::user_arn(account, &principal.path, &principal.name),
                "accountId": account,
                "userName": principal.name,
            })),
            Who::User { .. } | Who::Root { .. } => None,
        };
        if let Some(issuer) = issuer {
            context["sessionIssuer"] = issuer;
        }
        if let Some(source) = &session.source_identity {
            context["sourceIdentity"] = json!(source);
        }
        identity["sessionContext"] = context;
    }
    identity
}

/// A request's (or response's) members, as CloudTrail records them: their
/// names in camel case (`keyId`), and without the members `secret` names
/// (plaintexts, ciphertexts); the members `verbatim` names are kept as
/// they are (an encryption context's names are its user's).
pub fn parameters(members: &Map<String, Value>, secret: &[&str], verbatim: &[&str]) -> Value {
    fn camel(value: &Value) -> Value {
        match value {
            Value::Object(members) => Value::Object(
                members
                    .iter()
                    .map(|(name, value)| (lower_first(name), camel(value)))
                    .collect(),
            ),
            Value::Array(items) => Value::Array(items.iter().map(camel).collect()),
            other => other.clone(),
        }
    }
    Value::Object(
        members
            .iter()
            .filter(|(name, _)| !secret.contains(&name.as_str()))
            .map(|(name, value)| {
                let value = match verbatim.contains(&name.as_str()) {
                    true => value.clone(),
                    false => camel(value),
                };
                (lower_first(name), value)
            })
            .collect(),
    )
}

/// `name` with its first letter in lower case (`KeyId` → `keyId`), as
/// CloudTrail names members, mechanically: KMS's `AWSAccountId` is
/// `aWSAccountId` in its records.
fn lower_first(name: &str) -> String {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) => c.to_ascii_lowercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_camel_case() {
        assert_eq!(lower_first("KeyId"), "keyId");
        assert_eq!(lower_first("AWSAccountId"), "aWSAccountId");
        assert_eq!(lower_first("keyId"), "keyId");
        assert_eq!(lower_first(""), "");
    }

    #[test]
    fn parameters_keep_no_secrets() {
        let Value::Object(params) = json!({
            "KeyId": "alias/a",
            "Plaintext": "c2VjcmV0",
            "EncryptionContext": { "Department": "x" },
            "Tags": [{ "TagKey": "k", "TagValue": "v" }],
        }) else {
            unreachable!()
        };
        assert_eq!(
            parameters(&params, &["Plaintext"], &["EncryptionContext"]),
            json!({
                "keyId": "alias/a",
                "encryptionContext": { "Department": "x" },
                "tags": [{ "tagKey": "k", "tagValue": "v" }],
            })
        );
    }

    #[test]
    fn events_are_cloudtrails_records() {
        let mut event = Event::new(
            "kms.amazonaws.com",
            "Decrypt",
            json!({ "type": "Root" }),
            "111122223333",
            true,
        );
        event.time = UNIX_EPOCH + std::time::Duration::from_secs(1_794_805_567);
        event.source_ip = Some("192.0.2.1".parse().unwrap());
        event.touch(Resource {
            arn: "arn:aws:kms:us-east-1:111122223333:key/k".to_owned(),
            account: "111122223333".to_owned(),
            kind: "AWS::KMS::Key",
        });
        event.touch(event.resources[0].clone());
        let record = event.to_json();
        assert_eq!(record["eventTime"], "2026-11-16T05:06:07Z");
        assert_eq!(record["sourceIPAddress"], "192.0.2.1");
        assert_eq!(record["readOnly"], true);
        assert_eq!(record["resources"].as_array().unwrap().len(), 1);
        assert_eq!(record["resources"][0]["type"], "AWS::KMS::Key");
        assert!(record.get("errorCode").is_none());
        assert!(record.get("sessionCredentialFromConsole").is_none());
        event.console = true;
        assert_eq!(event.to_json()["sessionCredentialFromConsole"], "true");
        event.error = Some(("AccessDeniedException".to_owned(), "no".to_owned()));
        assert_eq!(event.to_json()["errorCode"], "AccessDeniedException");
        assert_eq!(event.to_json()["errorMessage"], "no");
    }
}
