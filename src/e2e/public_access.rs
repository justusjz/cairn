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
    assert!(matches!(create::create(&app, &bucket, None).await.unwrap(), create::Creation::Created));
    assert_eq!(public_access::get(&app, &bucket).await.unwrap(), Some(Some(Block::from_bits(15))));
    assert_eq!(put_bucket_policy(&app, &bucket, public_read(&bucket)).await.unwrap().status(), StatusCode::FORBIDDEN);
    // A policy that isn't public is no matter.
    let account = crate::roles::account(&app.pool.get().await.unwrap()).await.unwrap();
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
