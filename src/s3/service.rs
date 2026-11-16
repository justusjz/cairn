//! What Cairn writes as one of AWS's services, on a bucket's behalf, to a
//! bucket: an inventory report (as `s3.amazonaws.com`, see `inventory`), or
//! a bucket's server access logs (as `logging.s3.amazonaws.com`). As in S3,
//! only the destination bucket's policy can allow such a write: a statement
//! naming the service (`"Principal": {"Service": …}`), or everyone, with the
//! bucket it's done for, and its account, in `aws:SourceArn` and
//! `aws:SourceAccount`.

use std::sync::Arc;

use crate::{
    App,
    db::Cached,
    policy::{Context, Decision, Kind, Policy, Principal, Request},
};

/// A bucket, as what a service writes to it is checked.
pub struct Destination {
    pub name: String,
    /// The account that owns it.
    pub owner: String,
    policy: Option<Arc<Policy>>,
}

impl Destination {
    /// The bucket `name`; `None` if there's no such bucket.
    pub async fn load(app: &App, name: &str) -> anyhow::Result<Option<Destination>> {
        let row = app
            .pool
            .get()
            .await?
            .query_opt_cached(
                "SELECT policy, policy_principals::text, account_id FROM buckets WHERE name = $1",
                &[&name],
            )
            .await?;
        let Some(row) = row else { return Ok(None) };
        let policy = match row.get::<_, Option<String>>(0) {
            None => None,
            Some(text) => {
                let ids: Option<String> = row.get(1);
                Some(crate::s3::access::parsed(&text, Kind::Bucket(name), Some(ids.as_deref().unwrap_or("{}")))?)
            }
        };
        Ok(Some(Destination { name: name.to_owned(), owner: row.get(2), policy }))
    }

    /// A bucket without a policy, for tests that need one but no database.
    #[cfg(test)]
    pub fn detached(name: &str, owner: &str) -> Destination {
        Destination { name: name.to_owned(), owner: owner.to_owned(), policy: None }
    }

    /// Whether its policy lets `service` write `key` to it (`s3:PutObject`)
    /// for the bucket `source`, of the account `source_account`. `context`
    /// has the condition keys of the write itself that S3's would have
    /// (`s3:x-amz-acl`, encryption's): this adds the rest.
    pub fn allows_put(&self, service: &str, source: &str, source_account: &str, key: &str, context: Context) -> bool {
        let Some(policy) = &self.policy else { return false };
        let mut context = context;
        context.set("aws:SourceAccount", source_account);
        context.set("aws:SourceArn", format!("arn:aws:s3:::{source}"));
        context.set("aws:PrincipalIsAWSService", "true");
        context.set("aws:SecureTransport", "true");
        context.set("aws:ResourceAccount", self.owner.clone());
        context.set("s3:ResourceAccount", self.owner.clone());
        let context = context.for_action("s3:PutObject");
        let resource = format!("arn:aws:s3:::{}/{key}", self.name);
        let request = Request { principal: Principal::Service { name: service }, action: "s3:PutObject", resource: &resource, context: &context };
        matches!(policy.evaluate(&request), Decision::Allow)
    }
}
