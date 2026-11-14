//! A bucket's website (see `s3::website`, `s3::buckets::website`): its
//! configuration set, read back and deleted, and its pages served as S3's
//! website endpoints serve them, against a real Postgres.

use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{HeaderMap, Method, Response, StatusCode, body::Bytes, header};

use super::{BUCKET, node_with};
use crate::{
    App, AttachTarget, UploadResult,
    body::ResBody,
    packer,
    payload::Payload,
    s3::{
        buckets::{
            policy::put_bucket_policy,
            website::{delete_bucket_website, get_bucket_website, put_bucket_website},
        },
        conditional::Preconditions,
        website::serve,
    },
};

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

/// Writes `key` with `body` and the request headers `pairs`' metadata, as
/// PutObject does.
async fn put(app: &Arc<App>, key: &str, body: &str, pairs: &[(&str, &str)]) {
    let attach = AttachTarget::Object {
        bucket: BUCKET.to_owned(),
        key: key.to_owned(),
        content_type: "text/html".to_owned(),
        metadata: super::metadata::stored(pairs),
        conditions: Preconditions::default(),
        sealing: None,
        checksum: crate::e2e::OBJECT_CHECKSUM,
        tags: String::new(),
        lock: Default::default(),
    };
    let body = Full::new(Bytes::from(body.to_owned()));
    let result = crate::upload_part(app, body, &attach, Payload::unchecked()).await.unwrap();
    assert!(matches!(result, UploadResult::Committed { .. }));
}

/// Anyone may read the bucket's objects (and, with `list`, list them): its
/// account and it block no public policies.
async fn make_public(app: &App, list: bool) {
    use crate::s3::buckets::public_access;
    let account = crate::users::account(&app.pool.get().await.unwrap()).await.unwrap();
    assert!(public_access::set_account(app, &account, None).await.unwrap());
    assert!(public_access::set(app, BUCKET, None).await.unwrap());
    let list = match list {
        true => format!(r#",{{"Effect":"Allow","Principal":"*","Action":"s3:ListBucket","Resource":"arn:aws:s3:::{BUCKET}"}}"#),
        false => String::new(),
    };
    let policy = format!(
        r#"{{"Statement":[{{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::{BUCKET}/*"}}{list}]}}"#
    );
    let response = put_bucket_policy(app, BUCKET, Bytes::from(policy)).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

async fn configure(app: &App, inner: &str) {
    let document = format!(
        "<WebsiteConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{inner}</WebsiteConfiguration>"
    );
    let response = put_bucket_website(app, BUCKET, Bytes::from(document)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// A request for `path` of the bucket's website.
async fn request(app: &Arc<App>, method: Method, path: &str, pairs: &[(&str, &str)]) -> Response<ResBody> {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "bucket.website.example:8080".parse().unwrap());
    for (name, value) in pairs {
        headers.insert(header::HeaderName::from_bytes(name.as_bytes()).unwrap(), value.parse().unwrap());
    }
    serve(app, &method, &headers, &format!("/{BUCKET}{path}"), "127.0.0.1".parse().unwrap()).await.unwrap()
}

/// A GET's status, `Location` and body.
async fn get(app: &Arc<App>, path: &str) -> (StatusCode, Option<String>, String) {
    let response = request(app, Method::GET, path, &[]).await;
    let status = response.status();
    let location = response.headers().get(header::LOCATION).map(|v| v.to_str().unwrap().to_owned());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, location, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn a_configuration_reads_back_until_deleted() {
    let Some(app) = node().await else { return };
    let body = |response: Response<Full<Bytes>>| async {
        String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
    };
    let response = get_bucket_website(&app, BUCKET).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(body(response).await.contains("<Code>NoSuchWebsiteConfiguration</Code>"));

    let inner = "<IndexDocument><Suffix>index.html</Suffix></IndexDocument><ErrorDocument><Key>404.html</Key></ErrorDocument>";
    configure(&app, inner).await;
    let response = get_bucket_website(&app, BUCKET).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(body(response).await.contains(inner));

    // A refused one leaves the one there was.
    let refused = put_bucket_website(&app, BUCKET, Bytes::from("<WebsiteConfiguration/>")).await.unwrap();
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert!(body(refused).await.contains("<ArgumentName>IndexDocument</ArgumentName>"));
    assert_eq!(get_bucket_website(&app, BUCKET).await.unwrap().status(), StatusCode::OK);

    assert_eq!(delete_bucket_website(&app, BUCKET).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(get_bucket_website(&app, BUCKET).await.unwrap().status(), StatusCode::NOT_FOUND);
    // Deleting none is no matter.
    assert_eq!(delete_bucket_website(&app, BUCKET).await.unwrap().status(), StatusCode::NO_CONTENT);
    for response in [
        get_bucket_website(&app, "nope").await.unwrap(),
        put_bucket_website(&app, "nope", Bytes::from(format!("<WebsiteConfiguration>{inner}</WebsiteConfiguration>")))
            .await
            .unwrap(),
        delete_bucket_website(&app, "nope").await.unwrap(),
    ] {
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn serves_index_and_error_documents() {
    let Some(app) = node().await else { return };
    // Without a configuration, there's no website.
    let (status, _, page) = get(&app, "/").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(page.contains("<li>Code: NoSuchWebsiteConfiguration</li>"), "{page}");

    configure(&app, "<IndexDocument><Suffix>index.html</Suffix></IndexDocument>").await;
    put(&app, "index.html", "home", &[]).await;
    put(&app, "docs/index.html", "docs", &[]).await;
    put(&app, "docs/a page.html", "a page", &[]).await;
    put(&app, "404.html", "not here", &[]).await;
    // Nothing's public yet.
    let (status, _, page) = get(&app, "/").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(page.contains("<li>Code: AccessDenied</li>"), "{page}");

    make_public(&app, false).await;
    assert_eq!(get(&app, "/").await, (StatusCode::OK, None, "home".to_owned()));
    assert_eq!(get(&app, "/docs/").await, (StatusCode::OK, None, "docs".to_owned()));
    assert_eq!(get(&app, "/docs/a%20page.html").await, (StatusCode::OK, None, "a page".to_owned()));
    // A "directory" without its `/` is redirected to it.
    assert_eq!(get(&app, "/docs").await, (StatusCode::FOUND, Some("/docs/".to_owned()), String::new()));
    // A key that isn't there is a 403 to whom may not list the bucket.
    let (status, _, page) = get(&app, "/missing.html").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(page.contains("<li>Code: AccessDenied</li>"), "{page}");
    make_public(&app, true).await;
    let (status, _, page) = get(&app, "/missing.html").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(page.contains("<li>Code: NoSuchKey</li>\n<li>Message: The specified key does not exist.</li>\n<li>Key: missing.html</li>"), "{page}");

    // The error document, with the error's status.
    configure(&app, "<IndexDocument><Suffix>index.html</Suffix></IndexDocument><ErrorDocument><Key>404.html</Key></ErrorDocument>").await;
    assert_eq!(get(&app, "/missing.html").await, (StatusCode::NOT_FOUND, None, "not here".to_owned()));
    // One that isn't there either is told about.
    configure(&app, "<IndexDocument><Suffix>index.html</Suffix></IndexDocument><ErrorDocument><Key>gone.html</Key></ErrorDocument>").await;
    let (status, _, page) = get(&app, "/missing.html").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(page.contains("Custom Error Document</h3>\n<ul>\n<li>Code: NoSuchKey</li>"), "{page}");
    assert!(page.contains("<li>Key: gone.html</li>"), "{page}");

    // A HEAD answers as a GET, without a body.
    let response = request(&app, Method::HEAD, "/", &[]).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_LENGTH], "4");
    let response = request(&app, Method::HEAD, "/missing.html", &[]).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.headers()["x-amz-error-code"], "NoSuchKey");
    assert!(response.into_body().collect().await.unwrap().to_bytes().is_empty());
    // A range, and conditions.
    let response = request(&app, Method::GET, "/", &[("range", "bytes=1-2")]).await;
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(&response.into_body().collect().await.unwrap().to_bytes()[..], b"om");
    let etag = request(&app, Method::GET, "/", &[]).await.headers()[header::ETAG].to_str().unwrap().to_owned();
    let response = request(&app, Method::GET, "/", &[("if-none-match", &etag)]).await;
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    // The API's own headers aren't a page's.
    assert!(request(&app, Method::GET, "/", &[]).await.headers().get("x-amz-checksum-crc64nvme").is_none());
    // Nothing but reads.
    let response = request(&app, Method::PUT, "/index.html", &[]).await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn redirects() {
    let Some(app) = node().await else { return };
    make_public(&app, true).await;
    put(&app, "index.html", "home", &[]).await;
    put(&app, "moved.html", "old", &[("x-amz-website-redirect-location", "/new.html")]).await;
    put(&app, "away.html", "old", &[("x-amz-website-redirect-location", "https://example.com/")]).await;
    configure(
        &app,
        "<IndexDocument><Suffix>index.html</Suffix></IndexDocument>\
         <RoutingRules>\
         <RoutingRule><Condition><KeyPrefixEquals>docs/</KeyPrefixEquals></Condition>\
         <Redirect><ReplaceKeyPrefixWith>documents/</ReplaceKeyPrefixWith></Redirect></RoutingRule>\
         <RoutingRule><Condition><HttpErrorCodeReturnedEquals>404</HttpErrorCodeReturnedEquals></Condition>\
         <Redirect><HostName>fallback.example</HostName><Protocol>https</Protocol>\
         <HttpRedirectCode>307</HttpRedirectCode></Redirect></RoutingRule>\
         </RoutingRules>",
    )
    .await;
    // An object's own redirect.
    assert_eq!(get(&app, "/moved.html").await.0, StatusCode::MOVED_PERMANENTLY);
    assert_eq!(get(&app, "/moved.html").await.1.as_deref(), Some("/new.html"));
    assert_eq!(get(&app, "/away.html").await.1.as_deref(), Some("https://example.com/"));
    // A rule on keys, before anything's looked up.
    assert_eq!(
        get(&app, "/docs/a.html").await,
        (StatusCode::MOVED_PERMANENTLY, Some("http://bucket.website.example:8080/documents/a.html".to_owned()), String::new())
    );
    // A rule on errors, once one happens.
    assert_eq!(
        get(&app, "/missing").await,
        (StatusCode::TEMPORARY_REDIRECT, Some("https://fallback.example/missing".to_owned()), String::new())
    );
    assert_eq!(get(&app, "/").await, (StatusCode::OK, None, "home".to_owned()));

    // Every request, elsewhere.
    configure(&app, "<RedirectAllRequestsTo><HostName>www.example.com</HostName></RedirectAllRequestsTo>").await;
    assert_eq!(get(&app, "/a/b%20c").await.1.as_deref(), Some("http://www.example.com/a/b%20c"));
    let response = request(&app, Method::GET, "/", &[("x-forwarded-proto", "https")]).await;
    assert_eq!(response.headers()[header::LOCATION], "https://www.example.com/");
}

/// What the peer endpoint tells Caddy's on-demand TLS (`/tls/ask`): a
/// certificate for each host Cairn serves something at, and none other.
#[tokio::test]
async fn certificates_only_for_what_is_served() {
    use tower::ServiceExt;
    let Some(app) = node().await else { return };
    let mut app = Arc::try_unwrap(app).ok().expect("the test's node is its own");
    app.domain = Some("s3.example.com".to_owned());
    app.website_domain = Some("s3-website.example.com".to_owned());
    let app = Arc::new(app);
    // The bucket `www.example.com`, with a website; `bucket` has none.
    app.pool.get().await.unwrap().execute("INSERT INTO buckets (name) VALUES ('www.example.com')", &[]).await.unwrap();
    let document = "<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument></WebsiteConfiguration>";
    let response = put_bucket_website(&app, "www.example.com", Bytes::from(document)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let ask = |query: &str| {
        let request = hyper::Request::get(format!("/tls/ask{query}"))
            .header(header::HOST, "127.0.0.1:9431")
            .body(axum::body::Body::empty())
            .unwrap();
        let router = crate::peer::router(app.clone());
        async move { router.oneshot(request).await.unwrap().status() }
    };
    for allowed in [
        "s3.example.com",
        "S3.Example.com.",
        // A bucket, virtual-hosted.
        "bucket.s3.example.com",
        // Websites: at the website domain, and a custom domain.
        "www.example.com.s3-website.example.com",
        "www.example.com",
    ] {
        assert_eq!(ask(&format!("?domain={allowed}")).await, StatusCode::OK, "{allowed}");
    }
    for refused in [
        // No such bucket, or no website.
        "nope.s3.example.com",
        "bucket.s3-website.example.com",
        "bucket",
        "example.org",
        // The website domain names no bucket itself.
        "s3-website.example.com",
        "127.0.0.1",
        "localhost",
        "www.example.com:443",
        "a/b",
    ] {
        assert_eq!(ask(&format!("?domain={refused}")).await, StatusCode::NOT_FOUND, "{refused}");
    }
    assert_eq!(ask("").await, StatusCode::BAD_REQUEST);
}
