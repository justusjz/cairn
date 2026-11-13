//! Block Public Access (see `s3::buckets::public_access`): a bucket's block
//! and the cluster's, against a real Postgres.

use std::sync::Arc;

use hyper::{StatusCode, body::Bytes};

use super::{BUCKET, node_with};
use crate::{
    App, packer,
    s3::{
        access,
        actions::{Check, On},
        buckets::{
            create,
            policy::put_bucket_policy,
            public_access::{self, Block},
        },
    },
    settings,
};

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

/// Anyone may read `bucket`'s objects.
fn public_read(bucket: &str) -> Bytes {
    Bytes::from(format!(
        r#"{{"Statement":[{{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::{bucket}/*"}}]}}"#
    ))
}

/// Whether an anonymous request may read `bucket`'s `k`.
async fn anyone_reads(app: &App, bucket: &str) -> bool {
    let account = crate::roles::account(&app.pool.get().await.unwrap()).await.unwrap();
    let origin = access::Origin { peer: None, trusted_proxies: &[], signed: None, form: false };
    let headers = hyper::HeaderMap::new();
    let mut access = access::Access::new(None, &account, &hyper::Method::GET, &headers, "", &origin).unwrap();
    access.load(app, bucket).await.unwrap();
    access.allows(&Check { action: "s3:GetObject", on: On::Object(bucket.to_owned(), "k".to_owned()) })
}

/// A new bucket blocks everything, as S3's do; a public policy is refused
/// while a block (the bucket's or the cluster's) blocks it, and allows
/// anonymous reads only while none restricts it.
#[tokio::test]
async fn blocks_public_policies_and_restricts_public_buckets() {
    let Some(app) = node().await else { return };
    let bucket = format!("pab-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let account = crate::roles::account(&app.pool.get().await.unwrap()).await.unwrap();
    assert!(matches!(create::create(&app, &bucket, &account).await.unwrap(), create::Creation::Created));
    assert_eq!(public_access::get(&app, &bucket).await.unwrap(), Some(Some(Block::from_bits(15))));
    assert_eq!(put_bucket_policy(&app, &bucket, public_read(&bucket)).await.unwrap().status(), StatusCode::FORBIDDEN);
    // A policy that isn't public is no matter.
    let private = format!(
        r#"{{"Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{account}"}},"Action":"s3:GetObject","Resource":"arn:aws:s3:::{bucket}/*"}}]}}"#
    );
    assert_eq!(put_bucket_policy(&app, &bucket, Bytes::from(private)).await.unwrap().status(), StatusCode::NO_CONTENT);

    // Without the bucket's block, the public policy is taken, and allows.
    assert!(public_access::set(&app, &bucket, None).await.unwrap());
    assert_eq!(put_bucket_policy(&app, &bucket, public_read(&bucket)).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert!(anyone_reads(&app, &bucket).await);
    // RestrictPublicBuckets: the policy stays, but allows anonymous requests
    // nothing.
    let restrict = Block { restrict_public_buckets: true, ..Block::default() };
    assert!(public_access::set(&app, &bucket, Some(restrict)).await.unwrap());
    assert!(!anyone_reads(&app, &bucket).await);
    assert!(public_access::set(&app, &bucket, None).await.unwrap());
    assert!(anyone_reads(&app, &bucket).await);

    // The cluster's block, whatever the bucket's says.
    let client = app.pool.get().await.unwrap();
    settings::RESTRICT_PUBLIC_BUCKETS.set(&client, 1).await.unwrap();
    assert!(!anyone_reads(&app, &bucket).await);
    settings::RESTRICT_PUBLIC_BUCKETS.unset(&client).await.unwrap();
    settings::BLOCK_PUBLIC_POLICY.set(&client, 1).await.unwrap();
    assert_eq!(put_bucket_policy(&app, &bucket, public_read(&bucket)).await.unwrap().status(), StatusCode::FORBIDDEN);
    settings::BLOCK_PUBLIC_POLICY.unset(&client).await.unwrap();
    assert!(anyone_reads(&app, &bucket).await);

    // The e2e bucket was made with the column's default, as an older Cairn
    // would make one.
    assert_eq!(public_access::get(&app, BUCKET).await.unwrap(), Some(Some(Block::from_bits(15))));
}

/// Who asks, in `may`.
enum Asker<'a> {
    User(&'a crate::roles::Principal),
    Root(&'a str),
    Anonymous,
}

/// Whether `asker` may take `action` on `on` (its bucket's policy loaded),
/// and whether it's of another account than the bucket's, where that
/// matters (`Access::foreign`).
async fn may(app: &App, asker: Asker<'_>, action: &'static str, on: On) -> (bool, bool) {
    let origin = access::Origin { peer: None, trusted_proxies: &[], signed: None, form: false };
    let headers = hyper::HeaderMap::new();
    let method = hyper::Method::GET;
    let default = crate::roles::account(&app.pool.get().await.unwrap()).await.unwrap();
    let mut access = match asker {
        Asker::User(principal) => access::Access::new(Some(principal), &principal.account, &method, &headers, "", &origin).unwrap(),
        Asker::Root(account) => access::Access::root(account, &method, &headers, "", &origin),
        Asker::Anonymous => access::Access::new(None, &default, &method, &headers, "", &origin).unwrap(),
    };
    let check = Check { action, on };
    access.load(app, check.on.bucket().unwrap()).await.unwrap();
    (access.allows(&check), access.foreign(&check))
}

/// Another account gets nothing of a restricted bucket's public policy,
/// not even what it allows that account by name; the bucket's own account
/// still does (as in S3). And no other account may get, set or delete the
/// bucket's policy, whatever the policy allows it.
#[tokio::test]
async fn other_accounts_get_nothing_of_restricted_buckets_nor_their_policies() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let account = crate::roles::account(&client).await.unwrap();
    let acme = crate::accounts::create(&client, "acme").await.unwrap();
    let bucket = format!("pab-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    assert!(matches!(create::create(&app, &bucket, &account).await.unwrap(), create::Creation::Created));
    assert!(public_access::set(&app, &bucket, None).await.unwrap());
    let policy = format!(
        r#"{{"Statement":[
            {{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::{bucket}/*"}},
            {{"Effect":"Allow","Principal":{{"AWS":"{acme}"}},"Action":"s3:*","Resource":["arn:aws:s3:::{bucket}","arn:aws:s3:::{bucket}/*"]}}
        ]}}"#
    );
    assert_eq!(put_bucket_policy(&app, &bucket, Bytes::from(policy)).await.unwrap().status(), StatusCode::NO_CONTENT);
    // acme's eve may do anything, as far as acme is concerned; ada, of the
    // bucket's account, nothing but what the bucket's policy allows.
    crate::roles::create_for(&client, &acme, "eve", None, true).await.unwrap();
    crate::roles::create_for(&client, &account, "ada", None, false).await.unwrap();
    let eve = crate::roles::Principal::load(&client, "eve").await.unwrap().unwrap();
    let ada = crate::roles::Principal::load(&client, "ada").await.unwrap().unwrap();
    let object = || On::Object(bucket.clone(), "k".to_owned());
    let of_bucket = || On::Bucket(bucket.clone());

    // Not restricted: the policy allows each what it says.
    assert_eq!(may(&app, Asker::User(&eve), "s3:GetObject", object()).await, (true, false));
    assert_eq!(may(&app, Asker::User(&eve), "s3:PutObject", object()).await, (true, false));
    assert_eq!(may(&app, Asker::Root(&acme), "s3:PutObject", object()).await, (true, false));
    assert_eq!(may(&app, Asker::User(&ada), "s3:GetObject", object()).await, (true, false));
    assert_eq!(may(&app, Asker::Anonymous, "s3:GetObject", object()).await, (true, false));
    // But the policy is the bucket's account's alone.
    for action in ["s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy"] {
        assert_eq!(may(&app, Asker::User(&eve), action, of_bucket()).await, (true, true), "{action}");
        assert_eq!(may(&app, Asker::Root(&acme), action, of_bucket()).await, (true, true), "{action}");
        assert_eq!(may(&app, Asker::Root(&account), action, of_bucket()).await, (true, false), "{action}");
    }
    // Other things on the bucket another account may be allowed, as in S3.
    assert_eq!(may(&app, Asker::User(&eve), "s3:PutBucketPublicAccessBlock", of_bucket()).await, (true, false));

    // Restricted: only the bucket's account gets anything of the policy.
    let restrict = Block { restrict_public_buckets: true, ..Block::default() };
    assert!(public_access::set(&app, &bucket, Some(restrict)).await.unwrap());
    assert_eq!(may(&app, Asker::User(&eve), "s3:GetObject", object()).await.0, false);
    assert_eq!(may(&app, Asker::User(&eve), "s3:PutObject", object()).await.0, false);
    assert_eq!(may(&app, Asker::Root(&acme), "s3:GetObject", object()).await.0, false);
    assert_eq!(may(&app, Asker::Anonymous, "s3:GetObject", object()).await.0, false);
    assert_eq!(may(&app, Asker::User(&ada), "s3:GetObject", object()).await.0, true);
}
