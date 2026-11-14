//! IAM's OpenID Connect providers: issuers whose ID tokens STS's
//! AssumeRoleWithWebIdentity takes, for roles whose trust policies name
//! them (`"Federated": "arn:aws:iam::<account>:oidc-provider/<url>"`). A
//! provider is its issuer's URL (kept as its ARN has it: host and path,
//! without `https://`), the client IDs (audiences) its tokens may be for,
//! the thumbprints of certificates to trust its server by (see
//! `oidc::Reach`), and tags. See `plans/roles.md`, step 5.
//!
//! Not the console's sign-in providers (`console::oidc`): those are
//! operators' OAuth clients, these are IAM resources any user with
//! `iam:CreateOpenIDConnectProvider` makes, so their issuers are reached
//! only at public addresses unless the operator says otherwise
//! (`settings::OIDC_PRIVATE_ISSUERS`).
//!
//! In Postgres: `iam_oidc_providers` and `iam_oidc_provider_…`
//! (`db::IAM_OIDC_PROVIDERS`), changed as the lock protocol says (D(d) in
//! `catalog.sql`).

use deadpool_postgres::Object;
use uuid::Uuid;

use crate::db::Cached;
use crate::managed::{Refused, refused};
use crate::oidc::Reach;

/// The most client IDs a provider may have, and thumbprints, as IAM's
/// quotas.
pub const MAX_CLIENT_IDS: usize = 100;
pub const MAX_THUMBPRINTS: usize = 5;

/// A provider, as IAM shows it.
#[derive(Clone, Debug)]
pub struct Provider {
    pub id: Uuid,
    pub account: String,
    /// Its URL without `https://`, as its ARN has it.
    pub url: String,
    pub client_ids: Vec<String>,
    /// Hex SHA-1s, as they were given.
    pub thumbprints: Vec<String>,
    /// When it was made (ISO 8601, as IAM writes times).
    pub created: String,
    /// Its tags, oldest first.
    pub tags: Vec<(String, String)>,
}

/// A provider's ARN.
pub fn provider_arn(account: &str, url: &str) -> String {
    format!("arn:aws:iam::{account}:oidc-provider/{url}")
}

/// The URL (without `https://`) that `arn` names a provider of `account`
/// by, if it names one.
pub fn url_of_arn<'a>(arn: &'a str, account: &str) -> Option<&'a str> {
    arn.strip_prefix("arn:aws:iam::")?.strip_prefix(account)?.strip_prefix(":oidc-provider/").filter(|u| !u.is_empty())
}

/// A URL as a request gives it (`https://host[:port][/path]`), as a
/// provider keeps it: without `https://`, or a trailing `/` (an issuer's
/// URL is matched to tokens' `iss` without it).
pub fn url_of(given: &str) -> Result<String, Refused> {
    let invalid = |why: &str| Refused::Invalid(format!("{why}: {given}"));
    let Some(rest) = given.strip_prefix("https://") else { return Err(invalid("The URL must begin with https://")) };
    let rest = rest.trim_end_matches('/');
    let host = rest.split('/').next().unwrap_or("");
    if host.is_empty() || rest.contains(['?', '#', ' ']) || rest.contains("//") || host.contains('@') {
        return Err(invalid("The URL is not valid"));
    }
    if given.parse::<hyper::Uri>().is_err() {
        return Err(invalid("The URL is not valid"));
    }
    Ok(rest.to_owned())
}

/// A thumbprint as a request gives it, checked: 40 hex digits.
pub fn check_thumbprint(thumbprint: &str) -> Result<[u8; 20], Refused> {
    let invalid = || Refused::Invalid(format!("Thumbprint {thumbprint} is not a 40-character hexadecimal SHA-1 hash."));
    if thumbprint.len() != 40 {
        return Err(invalid());
    }
    let mut out = [0u8; 20];
    for (i, pair) in thumbprint.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| invalid())?;
        out[i] = u8::from_str_radix(text, 16).map_err(|_| invalid())?;
    }
    Ok(out)
}

const COLUMNS: &str = "p.id, p.account_id, p.url,
     ARRAY(SELECT c.client_id FROM iam_oidc_provider_client_ids c WHERE c.provider_id = p.id ORDER BY c.seq),
     ARRAY(SELECT t.thumbprint FROM iam_oidc_provider_thumbprints t WHERE t.provider_id = p.id ORDER BY t.seq),
     to_char(p.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
     ARRAY(SELECT t.key FROM iam_oidc_provider_tags t WHERE t.provider_id = p.id ORDER BY t.seq),
     ARRAY(SELECT t.value FROM iam_oidc_provider_tags t WHERE t.provider_id = p.id ORDER BY t.seq)";

impl Provider {
    fn of(row: &tokio_postgres::Row) -> Provider {
        Provider {
            id: row.get(0),
            account: row.get(1),
            url: row.get(2),
            client_ids: row.get(3),
            thumbprints: row.get(4),
            created: row.get(5),
            tags: crate::users::tags_of(row.get(6), row.get(7)),
        }
    }

    /// `account`'s provider of `url` (without `https://`), if there's one.
    pub async fn load(client: &Object, account: &str, url: &str) -> anyhow::Result<Option<Provider>> {
        let row = client
            .query_opt_cached(&format!("SELECT {COLUMNS} FROM iam_oidc_providers p WHERE p.account_id = $1 AND p.url = $2"), &[&account, &url])
            .await?;
        Ok(row.as_ref().map(Provider::of))
    }

    /// The provider `arn` names, if it's one of `account`'s.
    pub async fn load_arn(client: &Object, account: &str, arn: &str) -> anyhow::Result<Option<Provider>> {
        match url_of_arn(arn, account) {
            Some(url) => Provider::load(client, account, url).await,
            None => Ok(None),
        }
    }

    pub fn arn(&self) -> String {
        provider_arn(&self.account, &self.url)
    }

    /// Its issuer, as tokens' `iss` names it.
    pub fn issuer(&self) -> String {
        format!("https://{}", self.url)
    }

    /// How its issuer is reached: at public addresses only, unless
    /// `private`; trusting its thumbprints.
    pub fn reach(&self, private: bool) -> Reach {
        Reach {
            public_only: !private,
            thumbprints: self.thumbprints.iter().filter_map(|t| check_thumbprint(t).ok()).collect(),
        }
    }

    /// The condition keys of IAM's actions on it: its tags.
    pub fn context(&self) -> crate::policy::Context {
        let mut context = crate::policy::Context::default();
        for (key, value) in &self.tags {
            context.set(&format!("aws:ResourceTag/{key}"), value);
            context.set(&format!("iam:ResourceTag/{key}"), value);
        }
        context
    }
}

/// How IAM's issuers may be reached now (see `settings::OIDC_PRIVATE_ISSUERS`).
pub async fn private_allowed(client: &Object) -> anyhow::Result<bool> {
    Ok(crate::settings::OIDC_PRIVATE_ISSUERS.get(client).await? == 1)
}

/// NoSuchEntity for the provider `arn`.
pub fn no_such(arn: &str) -> Refused {
    Refused::NoSuch(format!("OpenIDConnect Provider not found for arn {arn}"))
}

/// What a new provider is made with.
pub struct New<'a> {
    /// Its URL, as `url_of` gives it.
    pub url: &'a str,
    pub client_ids: &'a [String],
    pub thumbprints: &'a [String],
    pub tags: &'a [(String, String)],
}

/// Makes a provider of `account` (T53): its ID.
pub async fn create(client: &Object, account: &str, new: &New<'_>) -> anyhow::Result<Uuid> {
    let keys: Vec<&str> = new.tags.iter().map(|(k, _)| k.as_str()).collect();
    let values: Vec<&str> = new.tags.iter().map(|(_, v)| v.as_str()).collect();
    let made = client
        .query_one_cached(
            "SELECT pg_temp.cairn_create_oidc_provider($1, $2, $3, $4, $5, $6)",
            &[&account, &new.url, &new.client_ids, &new.thumbprints, &keys, &values],
        )
        .await;
    match made {
        Ok(row) => Ok(row.get(0)),
        Err(e) if e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) => {
            refused(Refused::Exists(format!("Provider with url https://{} already exists.", new.url)))
        }
        Err(e) => Err(e.into()),
    }
}

/// Deletes provider `id` (what it has goes with it). Trust policies naming
/// it stay as they are, and match no one.
pub async fn delete(client: &Object, id: Uuid) -> anyhow::Result<bool> {
    Ok(client.execute_cached("DELETE FROM iam_oidc_providers WHERE id = $1", &[&id]).await? > 0)
}

/// Adds `client_id` to provider `provider`'s (T50).
pub async fn add_client_id(client: &Object, provider: &Provider, client_id: &str) -> anyhow::Result<()> {
    let status: String = client
        .query_one_cached(
            "SELECT pg_temp.cairn_add_oidc_client_id($1, $2, $3)",
            &[&provider.id, &client_id, &(MAX_CLIENT_IDS as i32)],
        )
        .await?
        .get(0);
    match status.as_str() {
        "added" => Ok(()),
        "too_many" => refused(Refused::Limit(format!("Cannot exceed quota for ClientIdsPerOpenIdConnectProvider: {MAX_CLIENT_IDS}"))),
        _ => refused(no_such(&provider.arn())),
    }
}

/// Removes `client_id` from provider `id`'s (if it's there).
pub async fn remove_client_id(client: &Object, id: Uuid, client_id: &str) -> anyhow::Result<()> {
    client
        .execute_cached("DELETE FROM iam_oidc_provider_client_ids WHERE provider_id = $1 AND client_id = $2", &[&id, &client_id])
        .await?;
    Ok(())
}

/// Sets provider `provider`'s thumbprints (checked, none twice) (T52).
pub async fn set_thumbprints(client: &Object, provider: &Provider, thumbprints: &[String]) -> anyhow::Result<()> {
    let status: String = client
        .query_one_cached("SELECT pg_temp.cairn_set_oidc_thumbprints($1, $2)", &[&provider.id, &thumbprints])
        .await?
        .get(0);
    match status.as_str() {
        "set" => Ok(()),
        _ => refused(no_such(&provider.arn())),
    }
}

/// Sets `tags` on provider `provider` (T51).
pub async fn tag(client: &Object, provider: &Provider, tags: &[(String, String)]) -> anyhow::Result<()> {
    let keys: Vec<&str> = tags.iter().map(|(k, _)| k.as_str()).collect();
    let values: Vec<&str> = tags.iter().map(|(_, v)| v.as_str()).collect();
    let status: String = client
        .query_one_cached(
            "SELECT pg_temp.cairn_tag_oidc_provider($1, $2, $3, $4)",
            &[&provider.id, &keys, &values, &(crate::users::MAX_TAGS as i32)],
        )
        .await?
        .get(0);
    match status.as_str() {
        "tagged" => Ok(()),
        "too_many" => Err(crate::users::TooManyTags.into()),
        _ => refused(no_such(&provider.arn())),
    }
}

/// Takes the tags `keys` (regardless of case) off provider `id`.
pub async fn untag(client: &Object, id: Uuid, keys: &[String]) -> anyhow::Result<()> {
    client
        .execute_cached(
            "DELETE FROM iam_oidc_provider_tags WHERE provider_id = $1 AND lower(key) IN (SELECT lower(k) FROM unnest($2::text[]) k)",
            &[&id, &keys],
        )
        .await?;
    Ok(())
}

/// `account`'s providers, by URL.
pub async fn list(client: &Object, account: &str) -> anyhow::Result<Vec<Provider>> {
    let rows = client
        .query_cached(&format!("SELECT {COLUMNS} FROM iam_oidc_providers p WHERE p.account_id = $1 ORDER BY p.url"), &[&account])
        .await?;
    Ok(rows.iter().map(Provider::of).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        assert_eq!(url_of("https://token.actions.githubusercontent.com").unwrap(), "token.actions.githubusercontent.com");
        assert_eq!(url_of("https://oidc.example.com/id/ABC/").unwrap(), "oidc.example.com/id/ABC");
        assert_eq!(url_of("https://example.com:8443/x").unwrap(), "example.com:8443/x");
        for bad in ["http://example.com", "example.com", "https://", "https://a.com/x?y=1", "https://a.com/x#f", "https://u@a.com"] {
            assert!(url_of(bad).is_err(), "{bad}");
        }
        assert_eq!(url_of_arn("arn:aws:iam::123456789012:oidc-provider/a.com/x", "123456789012"), Some("a.com/x"));
        assert_eq!(url_of_arn("arn:aws:iam::123456789012:oidc-provider/a.com", "999999999999"), None);
        assert_eq!(url_of_arn("arn:aws:iam::123456789012:role/a", "123456789012"), None);
    }

    #[test]
    fn thumbprints() {
        assert_eq!(check_thumbprint("990F4193972F2BECF12DDEDA5237F9C952F20D9E").unwrap()[0], 0x99);
        assert!(check_thumbprint("990f4193972f2becf12ddeda5237f9c952f20d9e").is_ok());
        assert!(check_thumbprint("990F4193972F2BECF12DDEDA5237F9C952F20D9").is_err());
        assert!(check_thumbprint("Z90F4193972F2BECF12DDEDA5237F9C952F20D9E").is_err());
    }
}
