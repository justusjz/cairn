//! A bucket's CORS configuration (see `s3::buckets::cors`): set, read back
//! and deleted, and what it answers preflights and other requests with.

use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{HeaderMap, Method, Response, StatusCode, body::Bytes};

use super::{BUCKET, node_with};
use crate::{
    App, packer,
    s3::buckets::cors::{Cross, delete_bucket_cors, get_bucket_cors, preflight, put_bucket_cors},
};

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

const RULES: &str = "<CORSConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
    <CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*suffix</AllowedOrigin></CORSRule>\
    <CORSRule><AllowedHeader>content-type</AllowedHeader><AllowedHeader>x-amz-*</AllowedHeader>\
    <AllowedMethod>PUT</AllowedMethod><AllowedMethod>POST</AllowedMethod>\
    <AllowedOrigin>https://app.example</AllowedOrigin><ExposeHeader>ETag</ExposeHeader>\
    <MaxAgeSeconds>600</MaxAgeSeconds></CORSRule>\
    </CORSConfiguration>";

async fn body(response: Response<Full<Bytes>>) -> String {
    String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
}

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        headers.append(hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(), value.parse().unwrap());
    }
    headers
}

/// A response's header `name`, if it has it.
fn header<B>(response: &Response<B>, name: &str) -> Option<String> {
    response.headers().get(name).map(|v| v.to_str().unwrap().to_owned())
}

/// A preflight of an object in `bucket`, with these headers.
async fn ask(app: &App, pairs: &[(&str, &str)], bucket: &str) -> Response<Full<Bytes>> {
    preflight(app, &headers(pairs), bucket, true).await.unwrap()
}

async fn configure(app: &App) {
    let response = put_bucket_cors(app, BUCKET, Bytes::from(RULES)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_configuration_reads_back_until_deleted() {
    let Some(app) = node().await else { return };
    let response = get_bucket_cors(&app, BUCKET).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(body(response).await.contains("<Code>NoSuchCORSConfiguration</Code>"));

    configure(&app).await;
    let response = get_bucket_cors(&app, BUCKET).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let read = body(response).await;
    assert!(read.ends_with(&RULES[RULES.find("<CORSRule>").unwrap()..]), "{read}");

    let response = put_bucket_cors(&app, BUCKET, Bytes::from("<CORSConfiguration/>")).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(body(response).await.contains("<Code>MalformedXML</Code>"));
    // A refused configuration leaves the one there was.
    assert_eq!(get_bucket_cors(&app, BUCKET).await.unwrap().status(), StatusCode::OK);

    assert_eq!(delete_bucket_cors(&app, BUCKET).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(get_bucket_cors(&app, BUCKET).await.unwrap().status(), StatusCode::NOT_FOUND);

    for response in [
        get_bucket_cors(&app, "nope").await.unwrap(),
        put_bucket_cors(&app, "nope", Bytes::from(RULES)).await.unwrap(),
        delete_bucket_cors(&app, "nope").await.unwrap(),
    ] {
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(body(response).await.contains("<Code>NoSuchBucket</Code>"));
    }
}

/// Preflights, as s3-tests' test_cors_origin_response makes them.
#[tokio::test]
async fn preflights_are_answered_by_the_rules() {
    let Some(app) = node().await else { return };
    let get = [("origin", "foo.suffix"), ("access-control-request-method", "GET")];

    // What the request must say, checked before there's a configuration.
    let response = ask(&app, &[], BUCKET).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(body(response).await.contains("Origin request header needed"));
    let response = ask(&app, &[("origin", "foo.suffix")], BUCKET).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(body(response).await.contains("Invalid Access-Control-Request-Method: null"));
    let response = ask(&app, &[("origin", "foo.suffix"), ("access-control-request-method", "PATCH")], BUCKET).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = ask(&app, &get, BUCKET).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let text = body(response).await;
    assert!(text.contains("<Code>AccessForbidden</Code>"), "{text}");
    assert!(text.contains("CORS is not enabled for this bucket"), "{text}");
    assert!(text.contains("<Method>GET</Method><ResourceType>OBJECT</ResourceType>"), "{text}");
    assert_eq!(ask(&app, &get, "nope").await.status(), StatusCode::NOT_FOUND);

    configure(&app).await;
    let response = ask(&app, &get, BUCKET).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(header(&response, "access-control-allow-origin").as_deref(), Some("foo.suffix"));
    assert_eq!(header(&response, "access-control-allow-methods").as_deref(), Some("GET"));
    assert_eq!(header(&response, "access-control-allow-credentials").as_deref(), Some("true"));
    assert_eq!(header(&response, "access-control-max-age"), None);
    assert!(header(&response, "vary").unwrap().contains("Origin"));

    // Not a method the rule for that origin allows.
    let response = ask(&app, &[("origin", "foo.suffix"), ("access-control-request-method", "PUT")], BUCKET).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(header(&response, "access-control-allow-origin"), None);
    assert!(body(response).await.contains("This CORS request is not allowed"));

    // Headers: all of them must be allowed.
    let put = [
        ("origin", "https://app.example"),
        ("access-control-request-method", "PUT"),
        ("access-control-request-headers", "Content-Type, x-amz-meta-name"),
        ("access-control-request-headers", "x-amz-date"),
    ];
    let response = ask(&app, &put, BUCKET).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(header(&response, "access-control-allow-methods").as_deref(), Some("PUT, POST"));
    assert_eq!(
        header(&response, "access-control-allow-headers").as_deref(),
        Some("Content-Type, x-amz-meta-name, x-amz-date")
    );
    assert_eq!(header(&response, "access-control-expose-headers").as_deref(), Some("ETag"));
    assert_eq!(header(&response, "access-control-max-age").as_deref(), Some("600"));
    let response = ask(&app, 
        &[
            ("origin", "https://app.example"),
            ("access-control-request-method", "PUT"),
            ("access-control-request-headers", "content-type, authorization"),
        ],
        BUCKET,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// Other requests' responses get the headers of the rule that allows them,
/// whatever the response; and none without an origin, or a configuration.
#[tokio::test]
async fn responses_to_allowed_origins_get_cors_headers() {
    let Some(app) = node().await else { return };
    let not_found = || Response::builder().status(StatusCode::NOT_FOUND).body(()).unwrap();
    let from = |origin: &str| headers(&[("origin", origin)]);

    let cross = Cross::of(&Method::GET, &from("foo.suffix"), BUCKET).unwrap();
    let mut response = not_found();
    cross.apply(&app, &mut response).await.unwrap();
    assert!(response.headers().is_empty(), "no configuration, no headers");

    configure(&app).await;
    let mut response = not_found();
    cross.apply(&app, &mut response).await.unwrap();
    assert_eq!(header(&response, "access-control-allow-origin").as_deref(), Some("foo.suffix"));
    assert_eq!(header(&response, "access-control-allow-methods").as_deref(), Some("GET"));

    // The rule for the origin allows PUT and POST, but not GET.
    let mut response = not_found();
    Cross::of(&Method::POST, &from("https://app.example"), BUCKET).unwrap().apply(&app, &mut response).await.unwrap();
    assert_eq!(header(&response, "access-control-allow-origin").as_deref(), Some("https://app.example"));
    assert_eq!(header(&response, "access-control-expose-headers").as_deref(), Some("ETag"));
    let mut response = not_found();
    Cross::of(&Method::GET, &from("https://app.example"), BUCKET).unwrap().apply(&app, &mut response).await.unwrap();
    assert_eq!(header(&response, "access-control-allow-origin"), None);
    // Caches still have to tell the responses to other origins apart.
    assert!(header(&response, "vary").is_some());

    assert!(Cross::of(&Method::GET, &HeaderMap::new(), BUCKET).is_none());
    assert!(Cross::of(&Method::GET, &from("foo.suffix"), "").is_none());
    assert!(Cross::of(&Method::OPTIONS, &from("foo.suffix"), BUCKET).is_none());
    let mut response = not_found();
    Cross::of(&Method::GET, &from("foo.suffix"), "nope").unwrap().apply(&app, &mut response).await.unwrap();
    assert!(response.headers().is_empty());
}
