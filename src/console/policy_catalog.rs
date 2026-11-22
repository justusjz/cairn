//! The console's policy catalog: IAM's policy language as Cairn knows it,
//! for the policy editor's visual builder. Each service's actions (S3's with
//! what each is about, and its condition keys), the condition operators, and
//! the condition keys, with how Cairn treats each. Static: what `policy`
//! checks policies against.

use std::sync::{Arc, LazyLock};

use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::web::ErrorBody;
use crate::App;
use crate::policy::{self, Support, s3_actions::Applies};

pub(super) fn router() -> OpenApiRouter<Arc<App>> {
    OpenApiRouter::new().routes(routes!(policy_catalog))
}

/// What an action is about: its resource.
#[derive(Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
enum ActionResource {
    /// A bucket: `arn:aws:s3:::bucket`.
    Bucket,
    /// An object: `arn:aws:s3:::bucket/key`.
    Object,
    /// No resource (`*`).
    Account,
    /// Something Cairn doesn't have (access points, jobs, ...).
    Other,
}

/// How Cairn treats a condition key.
#[derive(Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
enum KeySupport {
    /// Requests carry it, as AWS's would.
    Evaluated,
    /// No request to Cairn ever has it: it's always missing.
    Absent,
    /// AWS's requests would have it, and Cairn's don't yet: a policy that
    /// names it is refused.
    Unsupported,
}

impl From<Support> for KeySupport {
    fn from(support: Support) -> Self {
        match support {
            Support::Evaluated => KeySupport::Evaluated,
            Support::Absent => KeySupport::Absent,
            Support::Unsupported => KeySupport::Unsupported,
        }
    }
}

#[derive(Serialize, ToSchema)]
struct CatalogAction {
    /// Without the service's prefix: `GetObject`.
    name: &'static str,
    /// What it's about (S3's actions only).
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<ActionResource>,
    /// The service's condition keys it has (S3's actions only), as AWS
    /// writes them; a trailing `/` takes any tag key.
    keys: Vec<String>,
}

#[derive(Serialize, ToSchema)]
struct CatalogService {
    /// The actions' prefix: `s3`.
    prefix: &'static str,
    actions: Vec<CatalogAction>,
}

#[derive(Serialize, ToSchema)]
struct CatalogKey {
    /// As AWS writes it; a trailing `/` takes any tag key.
    name: String,
    support: KeySupport,
}

#[derive(Serialize, ToSchema)]
struct PolicyCatalog {
    /// The services whose actions Cairn knows. Others' (`iam:`, say) may be
    /// named too, in identity policies.
    services: Vec<CatalogService>,
    /// The operators' names, without `ForAllValues:`, `ForAnyValue:` or
    /// `IfExists` (which any but `Null` takes).
    operators: Vec<&'static str>,
    /// The condition keys: the global ones (`aws:`), S3's, and those of
    /// STS's that trust policies may name.
    keys: Vec<CatalogKey>,
}

/// A key as the action table writes it, with a tag key's placeholder
/// (`/<key>`, `/${TagKey}`) as a trailing `/`.
fn key(name: &str) -> String {
    match name.split_once('/') {
        Some((prefix, _)) => format!("{prefix}/"),
        None => name.to_string(),
    }
}

fn plain(prefix: &'static str, names: &'static [&'static str]) -> CatalogService {
    CatalogService {
        prefix,
        actions: names
            .iter()
            .map(|name| CatalogAction {
                name,
                resource: None,
                keys: Vec::new(),
            })
            .collect(),
    }
}

fn catalog() -> PolicyCatalog {
    let s3 = CatalogService {
        prefix: "s3",
        actions: policy::s3_actions::ACTIONS
            .iter()
            .map(|(name, applies, keys)| CatalogAction {
                name,
                resource: Some(match applies {
                    Applies::Bucket => ActionResource::Bucket,
                    Applies::Object => ActionResource::Object,
                    Applies::Account => ActionResource::Account,
                    Applies::Other => ActionResource::Other,
                }),
                keys: keys.iter().map(|k| key(k)).collect(),
            })
            .collect(),
    };
    let sts = CatalogService {
        prefix: "sts",
        actions: policy::TRUST_ACTIONS
            .iter()
            .map(|action| CatalogAction {
                name: action.strip_prefix("sts:").unwrap_or(action),
                resource: None,
                keys: Vec::new(),
            })
            .collect(),
    };
    let mut keys: Vec<CatalogKey> = policy::global_keys()
        .iter()
        .map(|(name, support)| CatalogKey {
            name: name.to_string(),
            support: (*support).into(),
        })
        .collect();
    for name in policy::s3_actions::CONDITION_KEYS {
        let name = key(name);
        if keys.iter().any(|k| k.name.eq_ignore_ascii_case(&name)) {
            continue;
        }
        // A tag key's placeholder, for `support`, which wants one.
        let probe = match name.ends_with('/') {
            true => format!("{name}x"),
            false => name.clone(),
        };
        if let Some(support) = policy::support(&probe) {
            keys.push(CatalogKey {
                name,
                support: support.into(),
            });
        }
    }
    keys.extend(policy::STS_KEYS.iter().map(|name| CatalogKey {
        name: name.to_string(),
        support: KeySupport::Evaluated,
    }));
    PolicyCatalog {
        services: vec![
            s3,
            plain("s3express", crate::s3::directory::ACTIONS),
            plain("s3tables", crate::tables::ACTIONS),
            plain("sns", policy::sns_actions::ACTIONS),
            plain("kms", policy::kms_actions::ACTIONS),
            sts,
        ],
        operators: policy::operators().collect(),
        keys,
    }
}

static CATALOG: LazyLock<PolicyCatalog> = LazyLock::new(catalog);

/// The policy language's actions, operators and condition keys, as Cairn
/// knows them.
#[utoipa::path(get, path = "/policy-catalog", responses(
    (status = 200, body = PolicyCatalog),
    (status = "4XX", body = ErrorBody),
))]
async fn policy_catalog() -> Json<&'static PolicyCatalog> {
    Json(&CATALOG)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_whole() {
        let c = catalog();
        let s3 = &c.services[0];
        let get = s3.actions.iter().find(|a| a.name == "GetObject").unwrap();
        assert!(matches!(get.resource, Some(ActionResource::Object)));
        assert!(get.keys.iter().any(|k| k == "s3:ExistingObjectTag/"));
        let list = s3.actions.iter().find(|a| a.name == "ListBucket").unwrap();
        assert!(list.keys.iter().any(|k| k == "s3:prefix"));
        // Every key the catalog names is one `policy` knows, as written.
        for k in &c.keys {
            let probe = match k.name.ends_with('/') {
                true => format!("{}x", k.name),
                false => k.name.clone(),
            };
            assert!(
                policy::support(&probe).is_some() || k.name.starts_with("sts:"),
                "{}",
                k.name
            );
        }
        assert!(c.keys.iter().any(|k| k.name == "aws:SourceIp"));
        assert!(c.keys.iter().any(|k| k.name == "s3:prefix"));
        assert!(c.keys.iter().any(|k| k.name == "aws:ResourceTag/"));
        assert_eq!(
            c.keys
                .iter()
                .filter(|k| k.name.eq_ignore_ascii_case("aws:resourcetag/"))
                .count(),
            1
        );
        assert!(c.operators.contains(&"StringLike"));
    }
}
