//! ACLs and Object Ownership (see `s3::acl`), against a real Postgres: the
//! operations that set and read them, and what they allow, decided as
//! `s3::handle_request` decides it.

use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::{HeaderMap, Method, Response, StatusCode, body::Bytes};

use super::{node_with, put_to};
use crate::{
    App, packer,
    s3::{abac, access, acl, actions, buckets::public_access, util::canonical_id},
    users::Principal,
};

/// The other account the tests write from.
const OTHER: &str = "000000000042";

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

/// A new bucket of the cluster's account, with `ownership`, and without a
/// public access block; and the account.
async fn bucket(app: &App, ownership: Option<&str>) -> (String, String) {
    let client = app.pool.get().await.unwrap();
    let account = crate::users::account(&client).await.unwrap();
    client
        .execute(
            "INSERT INTO accounts (id, name) VALUES ($1, 'other') ON CONFLICT DO NOTHING",
            &[&OTHER],
        )
        .await
        .unwrap();
    let bucket = format!("acl-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let mut headers = HeaderMap::new();
    if let Some(ownership) = ownership {
        headers.insert("x-amz-object-ownership", ownership.parse().unwrap());
    }
    let acls = acl::for_bucket(app, &account, &headers)
        .await
        .unwrap()
        .unwrap();
    let created =
        crate::s3::buckets::create::create_bucket_with(app, &bucket, &account, false, None, acls)
            .await
            .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    assert!(public_access::set(app, &bucket, None).await.unwrap());
    (bucket, account)
}

fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.insert(*name, value.parse().unwrap());
    }
    map
}

async fn text(response: Response<http_body_util::Full<Bytes>>) -> (StatusCode, String) {
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// Whether `principal` (`None`: anonymous) may make the request on
/// `bucket`'s `key`: all its checks, with its objects' owners and ACLs
/// looked up as `s3::handle_request` looks them up.
async fn may(
    app: &App,
    principal: Option<&Principal>,
    method: Method,
    bucket: &str,
    key: &str,
    query: &str,
) -> bool {
    let account = crate::users::account(&app.pool.get().await.unwrap())
        .await
        .unwrap();
    let origin = access::Origin {
        peer: None,
        trusted_proxies: &[],
        signed: None,
        form: false,
    };
    let headers = HeaderMap::new();
    let mut access =
        access::Access::new(principal, &account, &method, &headers, query, &origin).unwrap();
    let operation = actions::operation(&method, bucket, key, query, &headers).unwrap();
    access.load(app, bucket).await.unwrap();
    access.load_all(app, &operation.checks).await.unwrap();
    abac::prepare(app, &mut access, &operation, bucket, key, query, &headers)
        .await
        .unwrap();
    acl::prepare(app, &mut access, &operation, bucket, key, query, &headers)
        .await
        .unwrap();
    access.first_denied(&operation.checks).is_none()
}

/// Writes `key` to `bucket` as `writer` (an account) would, with the ACL
/// `headers` ask for, as `s3::handle_request` writes it.
async fn write(app: &Arc<App>, bucket: &str, key: &str, writer: &str, headers: &HeaderMap) {
    let acl = acl::for_write(app, bucket, Some(writer), headers)
        .await
        .unwrap()
        .unwrap();
    crate::notifications::scope(async {
        crate::notifications::set_acl(acl);
        put_to(app, bucket, key, b"data".to_vec()).await;
    })
    .await;
}

/// A new bucket has ACLs disabled, as S3's do: ACLs are refused, and read
/// as the owner's. Its ownership controls enable them; then its ACL is
/// what PutBucketAcl sets, from headers or XML, and allows what it grants,
/// unless public access blocks it.
#[tokio::test]
async fn ownership_controls_enable_bucket_acls() {
    let Some(app) = node().await else { return };
    let (bucket, account) = bucket(&app, None).await;
    let (status, body) = text(acl::get_ownership_controls(&app, &bucket).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("<ObjectOwnership>BucketOwnerEnforced</ObjectOwnership>"),
        "{body}"
    );
    let public = headers(&[("x-amz-acl", "public-read")]);
    let (status, body) = text(
        acl::put_bucket_acl(&app, &bucket, &public, b"")
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("AccessControlListNotSupported"), "{body}");
    assert!(!may(&app, None, Method::GET, &bucket, "", "").await);

    let writer = b"<OwnershipControls><Rule><ObjectOwnership>ObjectWriter</ObjectOwnership></Rule></OwnershipControls>";
    assert_eq!(
        acl::set_ownership_controls(&app, &bucket, Some(writer))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        acl::put_bucket_acl(&app, &bucket, &public, b"")
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let (_, body) = text(acl::get_bucket_acl(&app, &bucket).await.unwrap()).await;
    assert!(
        body.contains(&format!(
            "<Owner><ID>{}</ID></Owner>",
            canonical_id(&account)
        )),
        "{body}"
    );
    assert!(body.contains("<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>READ</Permission>"), "{body}");
    // Anyone may list it, but not write to it, nor read its ACL.
    assert!(may(&app, None, Method::GET, &bucket, "", "").await);
    assert!(!may(&app, None, Method::PUT, &bucket, "k", "").await);
    assert!(!may(&app, None, Method::GET, &bucket, "", "acl").await);

    // IgnorePublicAcls: what's public allows nothing; BlockPublicAcls: it
    // can't be set.
    let ignore = public_access::Block {
        ignore_public_acls: true,
        ..Default::default()
    };
    assert!(
        public_access::set(&app, &bucket, Some(ignore))
            .await
            .unwrap()
    );
    assert!(!may(&app, None, Method::GET, &bucket, "", "").await);
    let block = public_access::Block {
        block_public_acls: true,
        ..Default::default()
    };
    assert!(
        public_access::set(&app, &bucket, Some(block))
            .await
            .unwrap()
    );
    assert!(may(&app, None, Method::GET, &bucket, "", "").await);
    let write = headers(&[("x-amz-acl", "public-read-write")]);
    assert_eq!(
        acl::put_bucket_acl(&app, &bucket, &write, b"")
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(public_access::set(&app, &bucket, None).await.unwrap());

    // An XML ACL, granting another account by its canonical ID: its root
    // may write, but not anonymously.
    let xml = format!(
        "<AccessControlPolicy><Owner><ID>{}</ID></Owner><AccessControlList>\
         <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\"><ID>{}</ID></Grantee>\
         <Permission>WRITE</Permission></Grant></AccessControlList></AccessControlPolicy>",
        canonical_id(&account),
        canonical_id(OTHER)
    );
    assert_eq!(
        acl::put_bucket_acl(&app, &bucket, &HeaderMap::new(), xml.as_bytes())
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let other = Principal::root(OTHER);
    assert!(may(&app, Some(&other), Method::PUT, &bucket, "k", "").await);
    assert!(may(&app, Some(&other), Method::DELETE, &bucket, "k", "").await);
    assert!(!may(&app, Some(&other), Method::GET, &bucket, "", "").await);
    assert!(!may(&app, None, Method::PUT, &bucket, "k", "").await);
    // Not both headers and a body; not an owner it isn't.
    let both = acl::put_bucket_acl(&app, &bucket, &public, xml.as_bytes())
        .await
        .unwrap();
    assert_eq!(both.status(), StatusCode::BAD_REQUEST);
    let wrong = xml.replace(&canonical_id(&account), &canonical_id(OTHER));
    assert_eq!(
        acl::put_bucket_acl(&app, &bucket, &HeaderMap::new(), wrong.as_bytes())
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );

    // ACLs can't be disabled while the bucket's grants anyone else
    // anything; once they don't, they can, and the bucket's read as its
    // owner's.
    let enforced = b"<OwnershipControls><Rule><ObjectOwnership>BucketOwnerEnforced</ObjectOwnership></Rule></OwnershipControls>";
    let (status, body) = text(
        acl::set_ownership_controls(&app, &bucket, Some(enforced))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body.contains("InvalidBucketAclWithObjectOwnership"),
        "{body}"
    );
    let private = headers(&[("x-amz-acl", "private")]);
    assert_eq!(
        acl::put_bucket_acl(&app, &bucket, &private, b"")
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        acl::set_ownership_controls(&app, &bucket, Some(enforced))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert!(!may(&app, Some(&other), Method::PUT, &bucket, "k", "").await);

    // Without controls: ObjectWriter's, and a 404 to read.
    assert_eq!(
        acl::set_ownership_controls(&app, &bucket, None)
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    let (status, body) = text(acl::get_ownership_controls(&app, &bucket).await.unwrap()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("OwnershipControlsNotFoundError"), "{body}");
    assert_eq!(
        acl::put_bucket_acl(&app, &bucket, &public, b"")
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}

/// CreateBucket takes its Object Ownership, and an ACL with ACLs enabled,
/// but not a public one (new buckets block public access), nor one with
/// them disabled.
#[tokio::test]
async fn create_bucket_takes_ownership_and_acls() {
    let Some(app) = node().await else { return };
    let account = crate::users::account(&app.pool.get().await.unwrap())
        .await
        .unwrap();
    let code = |result: Result<_, Response<_>>| result.err().map(|r| r.status().as_u16());
    let asked = |pairs: &[(&'static str, &str)]| headers(pairs);
    assert_eq!(
        code(
            acl::for_bucket(&app, &account, &asked(&[("x-amz-acl", "private")]))
                .await
                .unwrap()
        ),
        None
    );
    assert_eq!(
        code(
            acl::for_bucket(&app, &account, &asked(&[("x-amz-acl", "public-read")]))
                .await
                .unwrap()
        ),
        Some(400)
    );
    assert_eq!(
        code(
            acl::for_bucket(
                &app,
                &account,
                &asked(&[("x-amz-object-ownership", "Nope")])
            )
            .await
            .unwrap()
        ),
        Some(400)
    );
    let public = asked(&[
        ("x-amz-object-ownership", "ObjectWriter"),
        ("x-amz-acl", "public-read"),
    ]);
    assert_eq!(
        code(acl::for_bucket(&app, &account, &public).await.unwrap()),
        Some(400)
    );
    let delivery = asked(&[
        ("x-amz-object-ownership", "ObjectWriter"),
        ("x-amz-acl", "log-delivery-write"),
    ]);
    let (ownership, stored) = acl::for_bucket(&app, &account, &delivery)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ownership, acl::Ownership::Writer);
    assert!(stored.unwrap().contains("LogDelivery"));
}

/// An object written by another account to an `ObjectWriter` bucket is
/// that account's: its ACL decides what the bucket's owner may do with it
/// (but delete it), and its owner may do what its own policies allow.
/// Disabling ACLs makes it the bucket owner's.
#[tokio::test]
async fn objects_are_their_writers() {
    let Some(app) = node().await else { return };
    let (bucket, account) = bucket(&app, Some("ObjectWriter")).await;
    let owner = Principal::root(&account);
    let other = Principal::root(OTHER);
    write(
        &app,
        &bucket,
        "k",
        OTHER,
        &headers(&[("x-amz-acl", "bucket-owner-read")]),
    )
    .await;

    let (status, body) = text(acl::get_object_acl(&app, &bucket, "k", None).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(&format!("<Owner><ID>{}</ID></Owner>", canonical_id(OTHER))),
        "{body}"
    );
    assert!(
        body.contains(&format!(
            "<ID>{}</ID></Grantee><Permission>READ</Permission>",
            canonical_id(&account)
        )),
        "{body}"
    );
    // The bucket owner may read it (its ACL says so), and delete it, but
    // not read its ACL.
    assert!(may(&app, Some(&owner), Method::GET, &bucket, "k", "").await);
    assert!(may(&app, Some(&owner), Method::DELETE, &bucket, "k", "").await);
    assert!(!may(&app, Some(&owner), Method::GET, &bucket, "k", "acl").await);
    // Its owner may do anything with it; the public nothing.
    assert!(may(&app, Some(&other), Method::GET, &bucket, "k", "acl").await);
    assert!(may(&app, Some(&other), Method::PUT, &bucket, "k", "acl").await);
    assert!(!may(&app, None, Method::GET, &bucket, "k", "").await);
    // Listings tell its owner.
    let owners = acl::Owners::load(&app, &bucket, &["k"]).await.unwrap();
    assert_eq!(owners.of("k", None), OTHER);

    // Its owner makes it public: anyone may read it (the bucket owner
    // too, anyone being everyone), but no one else read its ACL.
    let public = headers(&[("x-amz-acl", "public-read")]);
    let set = acl::put_object_acl(&app, &bucket, "k", None, &public, b"")
        .await
        .unwrap();
    assert_eq!(set.status(), StatusCode::OK);
    assert!(may(&app, None, Method::GET, &bucket, "k", "").await);
    assert!(may(&app, Some(&owner), Method::GET, &bucket, "k", "").await);
    assert!(!may(&app, Some(&owner), Method::GET, &bucket, "k", "acl").await);

    // A write without an ACL is its writer's alone.
    write(&app, &bucket, "mine", OTHER, &HeaderMap::new()).await;
    assert!(!may(&app, Some(&owner), Method::GET, &bucket, "mine", "").await);

    // ACLs disabled: everything's the bucket owner's, with its full control
    // alone.
    let enforced = b"<OwnershipControls><Rule><ObjectOwnership>BucketOwnerEnforced</ObjectOwnership></Rule></OwnershipControls>";
    assert_eq!(
        acl::set_ownership_controls(&app, &bucket, Some(enforced))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert!(may(&app, Some(&owner), Method::GET, &bucket, "mine", "acl").await);
    assert!(!may(&app, None, Method::GET, &bucket, "k", "").await);
    let (_, body) = text(acl::get_object_acl(&app, &bucket, "k", None).await.unwrap()).await;
    assert!(
        body.contains(&format!(
            "<Owner><ID>{}</ID></Owner>",
            canonical_id(&account)
        )),
        "{body}"
    );
    assert_eq!(
        acl::put_object_acl(&app, &bucket, "k", None, &public, b"")
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        acl::Owners::load(&app, &bucket, &["k"])
            .await
            .unwrap()
            .of("k", None),
        account
    );
}

/// `BucketOwnerPreferred`: a write giving the bucket owner full control
/// makes its object the bucket owner's; any other, its writer's.
#[tokio::test]
async fn bucket_owners_are_preferred() {
    let Some(app) = node().await else { return };
    let (bucket, account) = bucket(&app, Some("BucketOwnerPreferred")).await;
    write(
        &app,
        &bucket,
        "given",
        OTHER,
        &headers(&[("x-amz-acl", "bucket-owner-full-control")]),
    )
    .await;
    write(
        &app,
        &bucket,
        "kept",
        OTHER,
        &headers(&[("x-amz-acl", "private")]),
    )
    .await;
    let owners = acl::Owners::load(&app, &bucket, &["given", "kept"])
        .await
        .unwrap();
    assert_eq!(owners.of("given", None), account);
    assert_eq!(owners.of("kept", None), OTHER);
    let (_, body) = text(
        acl::get_object_acl(&app, &bucket, "given", None)
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(body.matches("<Grant>").count(), 1, "{body}");
}

/// A public write to a bucket that blocks public ACLs is refused; an ACL
/// naming no account there is is refused.
#[tokio::test]
async fn writes_ask_for_acls_they_may_have() {
    let Some(app) = node().await else { return };
    let (bucket, account) = bucket(&app, Some("ObjectWriter")).await;
    let code = |result: Result<_, Response<_>>| result.err().map(|r| r.status().as_u16());
    let public = headers(&[("x-amz-acl", "public-read")]);
    assert_eq!(
        code(
            acl::for_write(&app, &bucket, Some(&account), &public)
                .await
                .unwrap()
        ),
        None
    );
    let block = public_access::Block {
        block_public_acls: true,
        ..Default::default()
    };
    assert!(
        public_access::set(&app, &bucket, Some(block))
            .await
            .unwrap()
    );
    assert_eq!(
        code(
            acl::for_write(&app, &bucket, Some(&account), &public)
                .await
                .unwrap()
        ),
        Some(403)
    );
    let nobody = headers(&[("x-amz-grant-read", "id=\"0123456789abcdef\"")]);
    assert_eq!(
        code(
            acl::for_write(&app, &bucket, Some(&account), &nobody)
                .await
                .unwrap()
        ),
        Some(400)
    );
    // The bucket owner's own private object is stored as every other is.
    assert_eq!(
        acl::for_write(&app, &bucket, Some(&account), &HeaderMap::new())
            .await
            .unwrap()
            .unwrap(),
        None
    );
}
