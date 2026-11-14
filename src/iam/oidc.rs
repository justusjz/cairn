//! IAM's actions on OpenID Connect providers (see `iam_oidc`): each is
//! checked as IAM's own (`iam:CreateOpenIDConnectProvider` on the
//! provider's ARN, ...), and answered as IAM answers it (botocore's model;
//! the messages: probe, `plans/roles.md` step 5).

use hyper::StatusCode;

use super::{Error, Iam, Params, Result, Shown, Tagged, error, invalid, max_items, request_keys, request_keys_named, request_tags,
            tags_context, tags_xml, validation};
use crate::{
    iam_oidc::{self, Provider},
    policy::Context,
    s3::{actions::On, util::xml_escape},
};

fn no_such_provider(arn: &str) -> Error {
    error(StatusCode::NOT_FOUND, "NoSuchEntity", format!("OpenIDConnect Provider not found for arn {arn}"))
}

/// A list's members a request gives (`<name>.member.N`), each of `min` to
/// `max` characters (IAM's validation errors otherwise), none twice (the
/// first kept; `fold` says which are the same).
fn members(params: &Params, name: &str, min: usize, max: usize, fold: fn(&str) -> String) -> Result<Vec<String>> {
    let given = request_keys_named(params, name);
    let field = super::lower_first(name);
    let mut errors = Vec::new();
    for (i, member) in given.iter().enumerate() {
        let n = member.chars().count();
        let at = format!("Value at '{field}.{}.member' failed to satisfy constraint: Member must", i + 1);
        if n < min {
            errors.push(format!("{at} have length greater than or equal to {min}"));
        } else if n > max {
            errors.push(format!("{at} have length less than or equal to {max}"));
        }
    }
    if !errors.is_empty() {
        return Err(validation(super::validation_errors(&errors)));
    }
    let mut seen = std::collections::HashSet::new();
    Ok(given.into_iter().filter(|m| seen.insert(fold(m))).collect())
}

/// The thumbprints a request gives (`ThumbprintList`), checked.
fn thumbprints(params: &Params) -> Result<Vec<String>> {
    let thumbprints = members(params, "ThumbprintList", 40, 40, |t| t.to_ascii_lowercase())?;
    if thumbprints.len() > iam_oidc::MAX_THUMBPRINTS {
        return Err(error(
            StatusCode::CONFLICT,
            "LimitExceeded",
            format!("Cannot exceed quota for ThumbprintsPerOpenIdConnectProvider: {}", iam_oidc::MAX_THUMBPRINTS),
        ));
    }
    for thumbprint in &thumbprints {
        iam_oidc::check_thumbprint(thumbprint).map_err(|e| invalid(e.to_string()))?;
    }
    Ok(thumbprints)
}

/// The client ID a request gives (`ClientID`), checked.
fn client_id(params: &Params) -> Result<String> {
    let id = params.required("ClientID")?;
    if id.chars().count() > 255 {
        return Err(validation(
            "1 validation error detected: Value at 'clientID' failed to satisfy constraint: Member must have length less than or equal to 255",
        ));
    }
    Ok(id.to_owned())
}

impl Iam<'_> {
    /// The ARN of the provider a request names (`OpenIDConnectProviderArn`).
    fn provider_arn(params: &Params) -> Result<String> {
        let arn = params.required("OpenIDConnectProviderArn")?;
        if arn.chars().count() < 20 {
            return Err(validation(
                "1 validation error detected: Value at 'openIDConnectProviderArn' failed to satisfy constraint: Member must have length greater than or equal to 20",
            ));
        }
        Ok(arn.to_owned())
    }

    /// The provider a request names, allowed `action` on it (with its tags,
    /// and `extra`): NoSuchEntity if there's none, which is checked first
    /// as one would be, untagged.
    async fn provider(&mut self, params: &Params, action: &'static str, extra: Context) -> Result<Provider> {
        let arn = Self::provider_arn(params)?;
        if iam_oidc::url_of_arn(&arn, self.account()).is_none() && !arn.starts_with("arn:aws:iam::") {
            return Err(invalid(format!("ARN {arn} is not valid.")));
        }
        let provider = Provider::load_arn(self.client, self.account(), &arn).await?;
        let mut context = provider.as_ref().map(Provider::context).unwrap_or_default();
        context.extend(&extra);
        self.check_with(action, On::Arn(arn.clone()), &context, Shown::Arn).await?;
        provider.ok_or_else(|| no_such_provider(&arn))
    }

    pub(super) async fn create_open_id_connect_provider(&mut self, params: &Params) -> Result<Option<String>> {
        let given = params.required("Url")?.to_owned();
        if given.chars().count() > 255 {
            return Err(validation(
                "1 validation error detected: Value at 'url' failed to satisfy constraint: Member must have length less than or equal to 255",
            ));
        }
        let client_ids = members(params, "ClientIDList", 1, 255, str::to_owned)?;
        if client_ids.len() > iam_oidc::MAX_CLIENT_IDS {
            return Err(error(
                StatusCode::CONFLICT,
                "LimitExceeded",
                format!("Cannot exceed quota for ClientIdsPerOpenIdConnectProvider: {}", iam_oidc::MAX_CLIENT_IDS),
            ));
        }
        let thumbprints = thumbprints(params)?;
        let tags = request_tags(params, false, Tagged::User)?;
        let url = iam_oidc::url_of(&given).map_err(anyhow::Error::from)?;
        let arn = iam_oidc::provider_arn(self.account(), &url);
        let context = tags.as_deref().map(tags_context).unwrap_or_default();
        self.check_with("iam:CreateOpenIDConnectProvider", On::Arn(arn.clone()), &context, Shown::Arn).await?;
        if tags.is_some() {
            self.check_with("iam:TagOpenIDConnectProvider", On::Arn(arn.clone()), &context, Shown::Arn).await?;
        }
        if Provider::load(self.client, self.account(), &url).await?.is_some() {
            return Err(error(StatusCode::CONFLICT, "EntityAlreadyExists", format!("Provider with url https://{url} already exists.")));
        }
        // Its issuer must be there, and reachable as IAM's issuers are.
        match iam_oidc::check_new(self.client, &url, &thumbprints).await? {
            Ok(()) => {}
            Err(iam_oidc::Unusable::Url(e)) => return Err(invalid(e)),
            Err(iam_oidc::Unusable::Unreachable(e)) => return Err(error(StatusCode::BAD_REQUEST, "OpenIdIdpCommunicationError", e)),
        }
        let tags = tags.unwrap_or_default();
        let new = iam_oidc::New { url: &url, client_ids: &client_ids, thumbprints: &thumbprints, tags: &tags };
        iam_oidc::create(self.client, self.account(), &new).await?;
        let mut xml = format!("<OpenIDConnectProviderArn>{}</OpenIDConnectProviderArn>", xml_escape(&arn));
        if !tags.is_empty() {
            let mut sorted = tags.clone();
            sorted.sort();
            xml.push_str(&tags_xml("Tags", &sorted));
        }
        Ok(Some(xml))
    }

    pub(super) async fn get_open_id_connect_provider(&mut self, params: &Params) -> Result<Option<String>> {
        let provider = self.provider(params, "iam:GetOpenIDConnectProvider", Context::default()).await?;
        let list = |items: &[String]| items.iter().map(|i| format!("<member>{}</member>", xml_escape(i))).collect::<String>();
        let mut xml = format!(
            "<Url>{}</Url><ClientIDList>{}</ClientIDList><ThumbprintList>{}</ThumbprintList><CreateDate>{}</CreateDate>",
            xml_escape(&provider.url),
            list(&provider.client_ids),
            list(&provider.thumbprints),
            provider.created
        );
        if !provider.tags.is_empty() {
            let mut sorted = provider.tags.clone();
            sorted.sort();
            xml.push_str(&tags_xml("Tags", &sorted));
        }
        Ok(Some(xml))
    }

    pub(super) async fn list_open_id_connect_providers(&mut self) -> Result<Option<String>> {
        let on = On::Arn(format!("arn:aws:iam::{}:oidc-provider/*", self.account()));
        self.check("iam:ListOpenIDConnectProviders", on).await?;
        let members: String = iam_oidc::list(self.client, self.account())
            .await?
            .iter()
            .map(|p| format!("<member><Arn>{}</Arn></member>", xml_escape(&p.arn())))
            .collect();
        Ok(Some(format!("<OpenIDConnectProviderList>{members}</OpenIDConnectProviderList>")))
    }

    pub(super) async fn delete_open_id_connect_provider(&mut self, params: &Params) -> Result<Option<String>> {
        let provider = self.provider(params, "iam:DeleteOpenIDConnectProvider", Context::default()).await?;
        if !iam_oidc::delete(self.client, provider.id).await? {
            return Err(no_such_provider(&provider.arn()));
        }
        Ok(None)
    }

    pub(super) async fn add_client_id_to_open_id_connect_provider(&mut self, params: &Params) -> Result<Option<String>> {
        Self::provider_arn(params)?;
        let id = client_id(params)?;
        let provider = self.provider(params, "iam:AddClientIDToOpenIDConnectProvider", Context::default()).await?;
        iam_oidc::add_client_id(self.client, &provider, &id).await?;
        Ok(None)
    }

    pub(super) async fn remove_client_id_from_open_id_connect_provider(&mut self, params: &Params) -> Result<Option<String>> {
        Self::provider_arn(params)?;
        let id = client_id(params)?;
        let provider = self.provider(params, "iam:RemoveClientIDFromOpenIDConnectProvider", Context::default()).await?;
        iam_oidc::remove_client_id(self.client, provider.id, &id).await?;
        Ok(None)
    }

    pub(super) async fn update_open_id_connect_provider_thumbprint(&mut self, params: &Params) -> Result<Option<String>> {
        Self::provider_arn(params)?;
        let thumbprints = thumbprints(params)?;
        let provider = self.provider(params, "iam:UpdateOpenIDConnectProviderThumbprint", Context::default()).await?;
        iam_oidc::set_thumbprints(self.client, &provider, &thumbprints).await?;
        Ok(None)
    }

    pub(super) async fn tag_open_id_connect_provider(&mut self, params: &Params) -> Result<Option<String>> {
        Self::provider_arn(params)?;
        let tags = request_tags(params, true, Tagged::User)?.unwrap_or_default();
        let provider = self.provider(params, "iam:TagOpenIDConnectProvider", tags_context(&tags)).await?;
        iam_oidc::tag(self.client, &provider, &tags).await?;
        Ok(None)
    }

    pub(super) async fn untag_open_id_connect_provider(&mut self, params: &Params) -> Result<Option<String>> {
        Self::provider_arn(params)?;
        let keys = request_keys(params)?;
        let mut extra = Context::default();
        extra.set_all("aws:TagKeys", keys.clone());
        let provider = self.provider(params, "iam:UntagOpenIDConnectProvider", extra).await?;
        iam_oidc::untag(self.client, provider.id, &keys).await?;
        Ok(None)
    }

    pub(super) async fn list_open_id_connect_provider_tags(&mut self, params: &Params) -> Result<Option<String>> {
        let provider = self.provider(params, "iam:ListOpenIDConnectProviderTags", Context::default()).await?;
        let max = max_items(params)?;
        let start: usize = match params.get("Marker") {
            Some(m) => m.parse().map_err(|_| invalid("Invalid Marker."))?,
            None => 0,
        };
        let page: Vec<(String, String)> = provider.tags.iter().skip(start).take(max).cloned().collect();
        let truncated = start + page.len() < provider.tags.len();
        let marker = match truncated {
            true => format!("<Marker>{}</Marker>", start + page.len()),
            false => String::new(),
        };
        Ok(Some(format!("{}<IsTruncated>{truncated}</IsTruncated>{marker}", tags_xml("Tags", &page))))
    }
}
