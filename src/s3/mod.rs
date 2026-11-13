use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::{Method, Request, Response, StatusCode};

use crate::{
    App,
    auth::Rejection,
    body::{ResBody, box_response},
    payload::{self, Payload},
    roles::Principal,
    s3::{
        buckets::{
            cors::{self, delete_bucket_cors, get_bucket_cors, put_bucket_cors},
            policy, public_access,
            create::create_bucket,
            delete::delete_bucket,
            head::head_bucket,
            list::list_buckets,
            tagging::{delete_bucket_tagging, get_bucket_tagging, put_bucket_tagging},
            encryption::{default_request, delete_bucket_encryption, get_bucket_encryption, put_bucket_encryption},
            lifecycle::{delete_bucket_lifecycle, get_bucket_lifecycle, put_bucket_lifecycle},
            versioning::{get_bucket_versioning, put_bucket_versioning},
        },
        conditional::Preconditions,
        multipart::{
            abort::abort_multipart_upload, complete::{self, complete_multipart_upload},
            create::create_multipart_upload,
            list::list_multipart_uploads,
            list_parts::{MAX_PARTS, list_parts},
            upload_part::put_part,
        },
        objects::{
            attributes,
            copy::{CopyKeys, copy_object, copy_part, replaces_metadata},
            delete::{delete_object, delete_objects, missing_checksum},
            get::{get_object, head_object},
            list::{ListVersion, MAX_KEYS_LIMIT, list_objects},
            list_versions::list_object_versions,
            put::put_object,
            tagging::{delete_object_tagging, get_object_tagging, put_object_tagging},
        },
        util::{
            bucket_subresource_stub, decode_continuation_token, decode_path_param, format_s3_error,
            query_param, stub_acl,
        },
        hosting::Route,
        versions::{invalid_version_id, is_version_id},
    },
};

pub(crate) mod buckets;
pub(crate) mod checksums;
pub(crate) mod access;
pub(crate) mod acl;
pub(crate) mod actions;
pub(crate) mod conditional;
pub(crate) mod hosting;
pub(crate) mod metadata;
pub(crate) mod sse;
pub(crate) mod sse_c;
pub(crate) mod tags;
pub(crate) mod multipart;
pub(crate) mod object_lock;
pub(crate) mod objects;
pub(crate) mod post_policy;
pub(crate) mod util;
pub(crate) mod versions;

tokio::task_local! {
    /// The ID of the request being handled, which its error document names.
    static REQUEST_ID: String;
}

/// The ID of the request the current task handles, if it handles one.
pub fn request_id() -> Option<String> {
    REQUEST_ID.try_with(|id| id.clone()).ok()
}

/// Handles an S3 request, as S3 answers: every response has an ID of its own
/// (`x-amz-request-id`), which an error document names too, so a client can
/// tell which request it got. A handler that fails answers with a 500 (or a
/// 503), logged with `what` the request was. It goes where `route` says (see
/// `hosting`).
pub async fn handle(
    req: Request<crate::listen::ClientBody>,
    app: Arc<App>,
    what: &str,
    route: &Route,
    peer: std::net::IpAddr,
) -> Response<ResBody> {
    let mut id = [0u8; 8];
    getrandom::fill(&mut id).expect("the OS random number generator failed");
    let id: String = id.iter().map(|b| format!("{b:02X}")).collect();
    // A request from another origin gets CORS headers on its response,
    // whatever the response is, if its bucket allows it (see `cors`).
    let cross = cors::Cross::of(req.method(), req.headers(), &bucket_of(&route.path));
    let mut response = REQUEST_ID
        .scope(id.clone(), async {
            handle_request(req, app.clone(), route, peer).await.unwrap_or_else(|e| {
                eprintln!("{what} failed (request {id}): {e:#}");
                error_response(&e)
            })
        })
        .await;
    response.headers_mut().insert(
        "x-amz-request-id",
        id.parse().expect("hex is a header value"),
    );
    if let Some(cross) = cross
        && let Err(e) = cross.apply(&app, &mut response).await
    {
        eprintln!("{what}: CORS headers failed (request {id}): {e:#}");
    }
    response
}

/// The bucket a request's path names, decoded; empty if it names none.
fn bucket_of(path: &str) -> String {
    let path = path.trim_start_matches('/');
    decode_path_param(path.split_once('/').map_or(path, |(bucket, _)| bucket))
}

async fn handle_request(
    req: Request<crate::listen::ClientBody>,
    app: Arc<App>,
    route: &Route,
    peer: std::net::IpAddr,
) -> anyhow::Result<Response<ResBody>> {
    // A browser's CORS preflight, which is never signed (see `cors`).
    if req.method() == Method::OPTIONS {
        let path = route.path.trim_start_matches('/');
        let (bucket, key) = path.split_once('/').unwrap_or((path, ""));
        if !bucket.is_empty() {
            let bucket = decode_path_param(bucket);
            let response = cors::preflight(&app, req.headers(), &bucket, !key.is_empty()).await?;
            return Ok(box_response(response));
        }
    }
    // POST Object: a form posted to a bucket, which is signed in its body,
    // not its headers (see `objects::post`).
    if req.method() == Method::POST && objects::post::is_form(req.headers()) {
        let path = route.path.trim_start_matches('/').to_owned();
        return Ok(box_response(objects::post::post_object(&app, req, &path, route.virtual_host, Some(peer)).await?));
    }
    // Authenticate every other S3 request up front: look up the user whose
    // access key the SigV4 credential names, and verify the header signature
    // with its secret. Needs only the method/URI/query/headers, so it runs
    // before any body is read. A request without any signature is anonymous:
    // only buckets' policies can allow it. The peer endpoint is a separate
    // service and stays open for internal traffic.
    let signed = crate::auth::signed(req.headers(), req.uri().query().unwrap_or(""));
    // IAM's and STS's (signed for their service), on the same port.
    if let Some(signed) = signed.as_ref().filter(|s| crate::iam::wants(s)) {
        return Ok(box_response(crate::iam::handle(&app, req, signed.clone(), peer).await));
    }
    let principal = match &signed {
        Some(signed) => {
            let Some(principal) = Principal::load(&app.pool.get().await?, &signed.access_key).await? else {
                return Ok(forbidden("InvalidAccessKeyId", "the access key ID does not exist"));
            };
            // Against the path the client signed, which isn't the route's if
            // the bucket was in its host.
            if let Err(rejection) = crate::auth::verify_sigv4(
                req.method().as_str(),
                req.uri().path(),
                req.uri().query().unwrap_or(""),
                req.headers(),
                &principal.secret,
            ) {
                return Ok(box_response(util::rejection_response(&rejection)));
            }
            Some(principal)
        }
        // A signature that isn't one (not SigV4, or malformed).
        None if req.headers().contains_key(hyper::header::AUTHORIZATION)
            || query_param(req.uri().query().unwrap_or(""), "X-Amz-Signature").is_some() =>
        {
            return Ok(forbidden("AccessDenied", "request is not signed"));
        }
        None => None,
    };
    let account = crate::roles::account(&app.pool.get().await?).await?;
    let origin = access::Origin {
        peer: Some(peer),
        trusted_proxies: &app.trusted_proxies,
        signed: signed.as_ref(),
        form: false,
    };
    let mut access = access::Access::new(
        principal.as_ref(),
        &account,
        req.method(),
        req.headers(),
        req.uri().query().unwrap_or(""),
        &origin,
    )?;
    // The secret the request's body (aws-chunked, trailers) is signed with;
    // none for an anonymous one, whose body can't be signed.
    let secret = principal.as_ref().map(|p| p.secret.clone()).unwrap_or_default();
    // Every key, prefix, marker and delimiter must be well-formed, so check the
    // whole path and query once, before anything decodes them.
    let mut query_values =
        req.uri().query().unwrap_or("").split('&').map(|p| p.split_once('=').map_or("", |(_, v)| v));
    if !util::is_well_formed(&route.path) || !query_values.all(util::is_well_formed) {
        return Ok(box_response(util::unsupported_characters()));
    }
    let path = route.path.trim_start_matches('/');
    if path.is_empty() {
        let resp = match (req.method(), &principal) {
            // ListBuckets: every bucket, to whom `s3:ListAllMyBuckets` is
            // allowed; else those of the user's grants (as MinIO lists them).
            (&hyper::Method::GET, Some(principal)) => {
                let all = access.allows(&actions::Check { action: "s3:ListAllMyBuckets", on: actions::On::Account });
                list_buckets(&app, principal, req.uri().query().unwrap_or(""), all).await?
            }
            (&hyper::Method::GET, None) => format_s3_error(StatusCode::FORBIDDEN, "AccessDenied", "Access Denied"),
            _ => format_s3_error(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", ""),
        };
        return Ok(box_response(resp));
    }
    let (bucket, key) = match path.split_once('/') {
        Some((bucket, key)) => (decode_path_param(bucket), decode_path_param(key)),
        None => (decode_path_param(path), "".to_owned()),
    };
    let query = req.uri().query().unwrap_or("");
    if key.len() > util::MAX_KEY_LENGTH {
        return Ok(box_response(format_s3_error(
            StatusCode::BAD_REQUEST,
            "KeyTooLongError",
            "Your key is too long",
        )));
    }
    // GetObjectAttributes is a GET's only (probed).
    if !key.is_empty() && *req.method() != Method::GET && query_param(query, "attributes").is_some() {
        let mut response = format_s3_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "The specified method is not allowed against this resource.",
        );
        response.headers_mut().insert(hyper::header::ALLOW, hyper::header::HeaderValue::from_static("GET"));
        return Ok(box_response(response));
    }
    // Before anything routes on the method alone: an operation Cairn doesn't
    // implement would otherwise run as the plain PUT, DELETE or GET.
    if let Some(resp) = util::unsupported_subresource(req.method(), key.is_empty(), query) {
        return Ok(box_response(resp));
    }
    // What the request does, as policies see it, and whether they allow it.
    let Some(operation) = actions::operation(req.method(), &bucket, &key, query, req.headers()) else {
        return Ok(box_response(match principal {
            Some(_) => format_s3_error(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", ""),
            None => format_s3_error(StatusCode::FORBIDDEN, "AccessDenied", "Access Denied"),
        }));
    };
    let exists = access.load(&app, &bucket).await?;
    access.load_all(&app, &operation.checks).await?;
    // The Object Lock a write asks for, as policies may test it.
    if matches!(operation.name, "PutObject" | "CopyObject" | "CreateMultipartUpload") {
        let header = |name| req.headers().get(name).and_then(|v| v.to_str().ok());
        let (mode, until, hold) = (header(object_lock::MODE), header(object_lock::RETAIN_UNTIL), header(object_lock::LEGAL_HOLD));
        object_lock::set_context(&mut access.context, mode, until, hold);
    }
    // PutObjectRetention and PutObjectLegalHold: what they ask for is in
    // their bodies, which policies may test, so they're read before the
    // request is authorized. S3 requires a checksum of either.
    if matches!(operation.name, "PutObjectRetention" | "PutObjectLegalHold") {
        let version_id = query_param(query, "versionId");
        if let Some(v) = version_id.as_deref().filter(|v| !is_version_id(v)) {
            return Ok(box_response(invalid_version_id("versionId", v)));
        }
        if !payload::has_body_checksum(req.headers()) {
            return Ok(box_response(missing_checksum()));
        }
        let asks_to_bypass = object_lock::asks_to_bypass(req.headers());
        let body = match read_body(req, &secret, true).await? {
            Ok(body) => body,
            Err(rejection) => return Ok(box_response(util::rejection_response(&rejection))),
        };
        if operation.name == "PutObjectRetention" {
            if let Some((mode, until)) = object_lock::parse_retention(&body) {
                object_lock::set_context(&mut access.context, mode.as_deref(), until.as_deref(), None);
            }
        } else if let Some(status) = object_lock::parse_legal_hold(&body) {
            object_lock::set_context(&mut access.context, None, None, Some(&status));
        }
        if let Some(refused) = refusal(&access, &operation, exists) {
            return Ok(box_response(refused));
        }
        let version_id = version_id.as_deref();
        let resp = if operation.name == "PutObjectRetention" {
            let bypass = asks_to_bypass && access.allows(&bypass_check(&bucket, &key));
            object_lock::put_object_retention(&app, &bucket, &key, version_id, &body, bypass).await?
        } else {
            object_lock::put_object_legal_hold(&app, &bucket, &key, version_id, &body).await?
        };
        return Ok(box_response(resp));
    }
    if let Some(refused) = refusal(&access, &operation, exists) {
        return Ok(box_response(refused));
    }
    // A bucket's policy is its account's alone: another account's request
    // its policy allows is a 405, as S3 answers it.
    if operation.checks.iter().any(|c| access.foreign(c)) {
        return Ok(box_response(format_s3_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "The specified method is not allowed against this resource.",
        )));
    }
    // A key (or version) that isn't there is a 403 to whom may not list the
    // bucket, as in S3 (probed), so that keys can't be found by guessing.
    let hides_missing = |status: StatusCode| {
        let list = actions::Check { action: "s3:ListBucket", on: actions::On::Bucket(bucket.clone()) };
        status == StatusCode::NOT_FOUND && !access.allows(&list)
    };
    if key.is_empty() {
        // bucket operations. POST (DeleteObjects) consumes the body, so capture the
        // query up front and match on an owned method — mirroring the object branch
        // below — instead of borrowing `req` across the arms.
        let query = req.uri().query().unwrap_or("").to_owned();
        // Bucket sub-resource GETs: versioning, encryption, lifecycle, CORS,
        // policy, tagging and Object Lock are real; the rest (acl, location,
        // website, ...) are stubbed — Cairn implements none of
        // them, so answer as S3 does for an unconfigured bucket before
        // falling through to a listing. Each goes where `operation` says,
        // which is what was authorized: a request naming two subresources
        // must not be checked as one and handled as the other.
        if *req.method() == hyper::Method::GET {
            if operation.name == "GetBucketVersioning" {
                return Ok(box_response(get_bucket_versioning(&app, &bucket).await?));
            }
            if operation.name == "GetBucketEncryption" {
                return Ok(box_response(get_bucket_encryption(&app, &bucket).await?));
            }
            if operation.name == "GetBucketLifecycleConfiguration" {
                return Ok(box_response(get_bucket_lifecycle(&app, &bucket).await?));
            }
            if operation.name == "GetBucketCors" {
                return Ok(box_response(get_bucket_cors(&app, &bucket).await?));
            }
            if operation.name == "GetBucketPolicyStatus" {
                return Ok(box_response(policy::get_bucket_policy_status(&app, &bucket).await?));
            }
            if operation.name == "GetBucketPolicy" {
                return Ok(box_response(policy::get_bucket_policy(&app, &bucket).await?));
            }
            if operation.name == "GetPublicAccessBlock" {
                return Ok(box_response(public_access::get_public_access_block(&app, &bucket).await?));
            }
            if operation.name == "GetBucketTagging" {
                return Ok(box_response(get_bucket_tagging(&app, &bucket).await?));
            }
            if operation.name == "GetObjectLockConfiguration" {
                return Ok(box_response(object_lock::get_object_lock_configuration(&app, &bucket).await?));
            }
            if operation.name == "GetBucketOwnershipControls" {
                return Ok(box_response(acl::ownership_controls()));
            }
            if let Some(resp) = bucket_subresource_stub(&query) {
                return Ok(box_response(resp));
            }
        }
        // A listing's page size (max-keys, or max-uploads), and how it writes
        // keys (encoding-type), checked before anything's listed, as in S3. An
        // empty delimiter is none.
        let (max_keys, encoding) = match *req.method() {
            Method::GET => {
                let name = match query_param(&query, "uploads") {
                    Some(_) => "max-uploads",
                    None => "max-keys",
                };
                let max_keys = match util::page_size(&query, name, MAX_KEYS_LIMIT, MAX_KEYS_LIMIT) {
                    Ok(n) => n,
                    Err(refused) => return Ok(box_response(refused)),
                };
                match util::Encoding::from_query(&query) {
                    Ok(encoding) => (max_keys, encoding),
                    Err(refused) => return Ok(box_response(refused)),
                }
            }
            _ => (MAX_KEYS_LIMIT, util::Encoding::Plain),
        };
        let delimiter = util::delimiter(&query);
        let resp = match req.method().clone() {
            // ListObjectVersions: GET /{bucket}?versions, paginated by key-marker
            // and version-id-marker.
            hyper::Method::GET if query_param(&query, "versions").is_some() => {
                let marker = query_param(&query, "version-id-marker");
                if let Some(v) = marker.as_deref().filter(|v| !is_version_id(v)) {
                    return Ok(box_response(invalid_version_id("version-id-marker", v)));
                }
                list_object_versions(
                    &app,
                    &bucket,
                    &query_param(&query, "prefix").unwrap_or_default(),
                    delimiter.as_deref(),
                    &query_param(&query, "key-marker").unwrap_or_default(),
                    marker.as_deref(),
                    max_keys,
                    encoding,
                )
                .await?
            }
            // ListMultipartUploads: GET /{bucket}?uploads, paginated by
            // key-marker and upload-id-marker.
            hyper::Method::GET if query_param(&query, "uploads").is_some() => {
                list_multipart_uploads(
                    &app,
                    &bucket,
                    &query_param(&query, "prefix").unwrap_or_default(),
                    delimiter.as_deref(),
                    &query_param(&query, "key-marker").unwrap_or_default(),
                    query_param(&query, "upload-id-marker").as_deref(),
                    max_keys,
                    encoding,
                )
                .await?
            }
            hyper::Method::GET => {
                let prefix = query_param(&query, "prefix").unwrap_or_default();
                let is_v2 = query_param(&query, "list-type").as_deref() == Some("2");
                // Resolve the pagination cursor to a single "resume after this
                // key" marker. ListObjectsV2 carries it in an opaque
                // continuation-token (our base64 of the marker), or in start-after
                // on the first page; ListObjects (v1) uses a plain marker.
                let marker = if is_v2 {
                    match query_param(&query, "continuation-token") {
                        Some(token) => match decode_continuation_token(&token) {
                            Some(marker) => marker,
                            None => {
                                return Ok(box_response(format_s3_error(
                                    StatusCode::BAD_REQUEST,
                                    "InvalidArgument",
                                    "the continuation token is not valid",
                                )));
                            }
                        },
                        None => query_param(&query, "start-after").unwrap_or_default(),
                    }
                } else {
                    query_param(&query, "marker").unwrap_or_default()
                };
                // The response envelope differs by dialect; v2 also echoes the raw
                // (still-encoded) token and start-after it was given.
                let version = if is_v2 {
                    ListVersion::V2 {
                        continuation_token: query_param(&query, "continuation-token"),
                        start_after: query_param(&query, "start-after"),
                        fetch_owner: query_param(&query, "fetch-owner").as_deref() == Some("true"),
                    }
                } else {
                    ListVersion::V1
                };
                list_objects(
                    &app,
                    &bucket,
                    &prefix,
                    delimiter.as_deref(),
                    &marker,
                    max_keys,
                    version,
                    encoding,
                )
                .await?
            }
            hyper::Method::HEAD => head_bucket(&app, &bucket).await?,
            // PutBucketVersioning: PUT /{bucket}?versioning with a
            // <VersioningConfiguration> body.
            hyper::Method::PUT if operation.name == "PutBucketVersioning" => {
                match read_body(req, &secret, true).await? {
                    Ok(body) => put_bucket_versioning(&app, &bucket, body).await?,
                    Err(rejection) => util::rejection_response(&rejection),
                }
            }
            // PutBucketEncryption: PUT /{bucket}?encryption with a
            // <ServerSideEncryptionConfiguration> body.
            hyper::Method::PUT if operation.name == "PutBucketEncryption" => {
                match read_body(req, &secret, true).await? {
                    Ok(body) => {
                        let role = principal.as_ref().map_or(uuid::Uuid::nil(), |p| p.id);
                        put_bucket_encryption(&app, &bucket, body, role).await?
                    }
                    Err(rejection) => util::rejection_response(&rejection),
                }
            }
            // PutBucketLifecycleConfiguration: PUT /{bucket}?lifecycle with a
            // <LifecycleConfiguration> body, which must declare a checksum, as
            // in S3: it says what to delete.
            hyper::Method::PUT if operation.name == "PutBucketLifecycleConfiguration" => {
                if !payload::has_body_checksum(req.headers()) {
                    return Ok(box_response(missing_checksum()));
                }
                match read_body(req, &secret, true).await? {
                    Ok(body) => put_bucket_lifecycle(&app, &bucket, body).await?,
                    Err(rejection) => util::rejection_response(&rejection),
                }
            }
            // PutBucketCors: PUT /{bucket}?cors with a <CORSConfiguration>
            // body, which must declare a checksum, as in S3.
            hyper::Method::PUT if operation.name == "PutBucketCors" => {
                if !payload::has_body_checksum(req.headers()) {
                    return Ok(box_response(missing_checksum()));
                }
                match read_body(req, &secret, true).await? {
                    Ok(body) => put_bucket_cors(&app, &bucket, body).await?,
                    Err(rejection) => util::rejection_response(&rejection),
                }
            }
            // PutBucketTagging: PUT /{bucket}?tagging with a <Tagging> body,
            // which must declare a checksum, as in S3.
            hyper::Method::PUT if operation.name == "PutBucketTagging" => {
                if !payload::has_body_checksum(req.headers()) {
                    return Ok(box_response(missing_checksum()));
                }
                match read_body(req, &secret, true).await? {
                    Ok(body) => put_bucket_tagging(&app, &bucket, body).await?,
                    Err(rejection) => util::rejection_response(&rejection),
                }
            }
            // PutBucketPolicy: PUT /{bucket}?policy with the policy (JSON).
            hyper::Method::PUT if operation.name == "PutBucketPolicy" => {
                match read_body(req, &secret, true).await? {
                    Ok(body) => policy::put_bucket_policy(&app, &bucket, body).await?,
                    Err(rejection) => util::rejection_response(&rejection),
                }
            }
            // PutPublicAccessBlock: PUT /{bucket}?publicAccessBlock with a
            // <PublicAccessBlockConfiguration> body, which must declare a
            // checksum, as in S3.
            hyper::Method::PUT if operation.name == "PutPublicAccessBlock" => {
                if !payload::has_body_checksum(req.headers()) {
                    return Ok(box_response(missing_checksum()));
                }
                match read_body(req, &secret, true).await? {
                    Ok(body) => public_access::put_public_access_block(&app, &bucket, body).await?,
                    Err(rejection) => util::rejection_response(&rejection),
                }
            }
            // PutObjectLockConfiguration: PUT /{bucket}?object-lock with an
            // <ObjectLockConfiguration> body, which must declare a checksum,
            // as in S3.
            hyper::Method::PUT if operation.name == "PutObjectLockConfiguration" => {
                if !payload::has_body_checksum(req.headers()) {
                    return Ok(box_response(missing_checksum()));
                }
                match read_body(req, &secret, true).await? {
                    Ok(body) => object_lock::put_object_lock_configuration(&app, &bucket, body).await?,
                    Err(rejection) => util::rejection_response(&rejection),
                }
            }
            // PutBucketAcl: there are no ACLs (`acl`).
            hyper::Method::PUT if operation.name == "PutBucketAcl" => {
                acl::put_bucket_acl(&app, &bucket, req.headers()).await?
            }
            hyper::Method::PUT if operation.name == "CreateBucket" => match acl::check_write(req.headers(), acl::On::Bucket) {
                Ok(()) => match &principal {
                    Some(principal) => {
                        let object_lock = object_lock::asks_for_bucket(req.headers());
                        create_bucket(&app, &bucket, &principal.account, object_lock).await?
                    }
                    None => format_s3_error(StatusCode::FORBIDDEN, "AccessDenied", "Access Denied"),
                },
                Err(refused) => refused,
            },
            // DeleteObjects (batch): POST /{bucket}?delete with a <Delete> body,
            // which must declare a checksum.
            hyper::Method::POST if query_param(&query, "delete").is_some() => {
                if !payload::has_body_checksum(req.headers()) {
                    return Ok(box_response(missing_checksum()));
                }
                let asks_to_bypass = object_lock::asks_to_bypass(req.headers());
                match read_body(req, &secret, true).await? {
                    Ok(body) => {
                        // Each key on its own, as in S3.
                        let allowed = |key: &str, version: bool| {
                            let on = actions::On::Object(bucket.clone(), key.to_owned());
                            access.allows(&actions::Check { action: actions::delete(version), on })
                        };
                        let bypass = |key: &str| asks_to_bypass && access.allows(&bypass_check(&bucket, key));
                        delete_objects(&app, &bucket, body, &allowed, &bypass).await?
                    }
                    Err(rejection) => util::rejection_response(&rejection),
                }
            }
            hyper::Method::DELETE if operation.name == "DeleteBucketEncryption" => {
                delete_bucket_encryption(&app, &bucket).await?
            }
            hyper::Method::DELETE if operation.name == "DeleteBucketLifecycle" => {
                delete_bucket_lifecycle(&app, &bucket).await?
            }
            hyper::Method::DELETE if operation.name == "DeleteBucketPolicy" => {
                policy::delete_bucket_policy(&app, &bucket).await?
            }
            hyper::Method::DELETE if operation.name == "DeleteBucketCors" => {
                delete_bucket_cors(&app, &bucket).await?
            }
            hyper::Method::DELETE if operation.name == "DeletePublicAccessBlock" => {
                public_access::delete_public_access_block(&app, &bucket).await?
            }
            hyper::Method::DELETE if operation.name == "DeleteBucketTagging" => {
                delete_bucket_tagging(&app, &bucket).await?
            }
            hyper::Method::DELETE if operation.name == "DeleteBucket" => delete_bucket(&app, &bucket).await?,
            _ => format_s3_error(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", ""),
        };
        return Ok(box_response(resp));
    }

    // object operations. A plain GET streams its (possibly multi-part) body, so
    // it returns the streaming response directly; everything else is buffered and
    // boxed. `query` borrows `req`, so own it before the body-consuming arms.
    let query = req.uri().query().unwrap_or("").to_owned();
    let range = req
        .headers()
        .get(hyper::header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    // Conditional-request headers (If-Match / If-None-Match / If-[Un]Modified-Since)
    // gate GET and HEAD; read them before the body-consuming arms.
    let preconditions = Preconditions::from_headers(req.headers());
    // Whether a read asks for its object's checksum.
    let checksum_mode = req
        .headers()
        .get(checksums::MODE)
        .is_some_and(|mode| mode.as_bytes() == b"ENABLED");
    // GET, HEAD and DELETE may address one specific version of the object,
    // as may the tagging requests.
    let version_id = query_param(&query, "versionId");
    let tagging = matches!(operation.name, "GetObjectTagging" | "PutObjectTagging" | "DeleteObjectTagging");
    let addresses_version = tagging || matches!(*req.method(), Method::GET | Method::HEAD | Method::DELETE);
    // Whether the version's retention and legal hold may be told (GET and
    // HEAD tell them only then, as S3 does).
    let on_object = || actions::On::Object(bucket.clone(), key.clone());
    let tells_retention = access.allows(&actions::Check { action: "s3:GetObjectRetention", on: on_object() });
    let tells_legal_hold = access.allows(&actions::Check { action: "s3:GetObjectLegalHold", on: on_object() });
    // A delete's bypass of GOVERNANCE mode: asked for, and allowed.
    let bypass = object_lock::asks_to_bypass(req.headers()) && access.allows(&bypass_check(&bucket, &key));
    // The Object Lock a write asks for (see `object_lock`).
    let lock = match operation.name {
        "PutObject" | "CopyObject" | "CreateMultipartUpload" => match object_lock::Lock::from_headers(req.headers()) {
            Ok(lock) => lock,
            Err(refused) => return Ok(box_response(refused)),
        },
        _ => object_lock::Lock::default(),
    };
    if let Some(v) = version_id.as_deref().filter(|v| addresses_version && !is_version_id(v)) {
        return Ok(box_response(invalid_version_id("versionId", v)));
    }
    // A read of one part (`?partNumber=N`), checked before anything's looked
    // up, as S3 checks it (probed).
    let part_number = match operation.name {
        "GetObject" | "HeadObject" => match query_param(&query, "partNumber") {
            None => None,
            Some(number) => match util::part_number(&number) {
                Some(_) if range.is_some() => {
                    return Ok(box_response(format_s3_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidRequest",
                        "Cannot specify both Range header and partNumber query parameter",
                    )));
                }
                Some(number) => Some(number),
                None => return Ok(box_response(util::invalid_part_number(&number))),
            },
        },
        _ => None,
    };
    // GetObjectTagging, PutObjectTagging (with a <Tagging> body) and
    // DeleteObjectTagging: an SSE-C object's tags need no key, as in S3.
    if tagging {
        let version_id = version_id.as_deref();
        let resp = match req.method().clone() {
            Method::GET => get_object_tagging(&app, &bucket, &key, version_id).await?,
            Method::PUT => match read_body(req, &secret, true).await? {
                Ok(body) => put_object_tagging(&app, &bucket, &key, version_id, body).await?,
                Err(rejection) => util::rejection_response(&rejection),
            },
            _ => delete_object_tagging(&app, &bucket, &key, version_id).await?,
        };
        return Ok(box_response(resp));
    }
    // GetObjectRetention and GetObjectLegalHold (see `object_lock`).
    if operation.name == "GetObjectRetention" {
        let resp = object_lock::get_object_retention(&app, &bucket, &key, version_id.as_deref()).await?;
        return Ok(box_response(resp));
    }
    if operation.name == "GetObjectLegalHold" {
        let resp = object_lock::get_object_legal_hold(&app, &bucket, &key, version_id.as_deref()).await?;
        return Ok(box_response(resp));
    }
    // SSE-C: the key the request names for its object, if any. Refused if it's
    // malformed, or didn't come over HTTPS.
    let secure = sse_c::secure(req.headers(), app.allow_sse_c_over_http);
    let customer_key = match sse_c::requested(req.headers(), &sse_c::HEADERS, secure) {
        Ok(key) => key,
        Err(refused) => return Ok(box_response(refused)),
    };
    // A copy's source's, which has headers of its own.
    let source_key = match sse_c::requested(req.headers(), &sse_c::COPY_SOURCE_HEADERS, secure) {
        Ok(key) => key,
        Err(refused) => return Ok(box_response(refused)),
    };
    // The writes that make an object (or an upload): PutObject, CopyObject,
    // CreateMultipartUpload.
    let writes_object = match *req.method() {
        Method::PUT => query_param(&query, "uploadId").is_none() && query_param(&query, "acl").is_none(),
        Method::POST => query_param(&query, "uploads").is_some(),
        _ => false,
    };
    // SSE-KMS or SSE-S3: what such a write asks for. Its headers are refused
    // elsewhere.
    let server = match *req.method() {
        _ if writes_object => {
            let sse_s3 = app.kms.as_ref().is_some_and(|kms| kms.sse_s3_key().is_some());
            match sse::requested(req.headers(), customer_key.is_some(), app.kms.is_some(), sse_s3)
                .and_then(|request| sse::for_object(request, &bucket, &key))
            {
                Ok(request) => request,
                Err(refused) => return Ok(box_response(refused)),
            }
        }
        Method::GET | Method::HEAD => match sse::refuse_on_read(req.headers()) {
            Some(refused) => return Ok(box_response(refused)),
            None => None,
        },
        Method::PUT | Method::POST => match sse::refuse_on_other_writes(req.headers()) {
            Some(refused) => return Ok(box_response(refused)),
            None => None,
        },
        _ => None,
    };
    // A write that asks for no encryption of its own gets its bucket's
    // default, as in S3 (see `buckets::encryption`).
    let server = match server {
        None if writes_object && customer_key.is_none() => match default_request(&app, &bucket).await? {
            Ok(request) => request,
            Err(refused) => return Ok(box_response(refused)),
        },
        request => request,
    };
    // How an object write asks for its object to be encrypted.
    let wanted = sse::Wanted::new(customer_key.as_ref(), server.as_ref());
    // Who the KMS is asked as, for SSE-KMS (see `kms`).
    let role = principal.as_ref().map(|p| p.id);
    // An object write may only ask for the ACL there is (see `acl`).
    if writes_object && let Err(refused) = acl::check_write(req.headers(), acl::On::Object) {
        return Ok(box_response(refused));
    }
    // The headers a read's `response-*` parameters replace (GET and HEAD).
    let overrides = match *req.method() {
        Method::GET | Method::HEAD => match metadata::Overrides::from_query(&query) {
            Ok(overrides) => overrides,
            Err(refused) => return Ok(box_response(refused)),
        },
        _ => metadata::Overrides::default(),
    };
    // GetObjectAttributes (see `attributes`): not with a part number.
    if operation.name == "GetObjectAttributes" {
        if query_param(&query, "partNumber").is_some() {
            return Ok(box_response(attributes::with_part_number()));
        }
        let asked = match attributes::Asked::from_headers(req.headers()) {
            Ok(asked) => asked,
            Err(refused) => return Ok(box_response(refused)),
        };
        let response = attributes::get_object_attributes(
            &app,
            &bucket,
            &key,
            version_id.as_deref(),
            &asked,
            customer_key.as_ref(),
            role,
        )
        .await?;
        return Ok(box_response(match hides_missing(response.status()) {
            true => access.denied(&operation.checks[0], crate::policy::Verdict::ImplicitDeny),
            false => response,
        }));
    }
    if *req.method() == hyper::Method::GET {
        // ACL is stubbed; otherwise a `?acl` GET would stream object bytes and
        // break XML-parsing clients like `s3cmd info`.
        if query_param(&query, "acl").is_some() {
            return Ok(box_response(stub_acl()));
        }
        // ListParts: GET /{bucket}/{key}?uploadId=U, paginated by
        // part-number-marker.
        if let Some(upload_id) = query_param(&query, "uploadId") {
            let max_parts = match util::page_size(&query, "max-parts", MAX_PARTS, MAX_PARTS) {
                Ok(n) => n,
                Err(refused) => return Ok(box_response(refused)),
            };
            let marker = query_param(&query, "part-number-marker")
                .and_then(|v| v.parse::<i32>().ok())
                .unwrap_or(0);
            let resp =
                list_parts(&app, &bucket, &key, &upload_id, marker, max_parts, customer_key.as_ref(), role).await?;
            return Ok(box_response(resp));
        }
        let response = get_object(
            &app,
            &bucket,
            &key,
            version_id.as_deref(),
            range.as_deref(),
            part_number,
            &preconditions,
            customer_key.as_ref(),
            role,
            checksum_mode,
        )
        .await?;
        if hides_missing(response.status()) {
            return Ok(box_response(access.denied(&operation.checks[0], crate::policy::Verdict::ImplicitDeny)));
        }
        return Ok(overrides.apply(object_lock::strip(response, tells_retention, tells_legal_hold)));
    }
    let content_type = req
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();
    // A PUT carrying x-amz-copy-source is a CopyObject (server-side copy); its
    // metadata-directive decides whether the destination inherits the source's
    // metadata (COPY, default) or takes the request's own (REPLACE). Read both
    // before the body-consuming arms.
    let copy_source = req
        .headers()
        .get("x-amz-copy-source")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let metadata_directive = req
        .headers()
        .get("x-amz-metadata-directive")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    // UploadPartCopy narrows the copy to a byte range of the source object.
    let copy_source_range = req
        .headers()
        .get("x-amz-copy-source-range")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    // The copy endpoints gate on the *source* via x-amz-copy-source-if-* headers.
    let copy_source_preconditions = Preconditions::from_copy_source_headers(req.headers());
    // What the request claims about an uploaded body, checked as it streams.
    let payload = Payload::new(req.headers(), &secret, true);
    // The metadata a write stores with its object, or why it's refused. Only
    // the writes that take the request's metadata look at it.
    let metadata = metadata::from_request(req.headers());
    // Likewise its tags (stored form; see `tags`).
    let tags = match req.headers().get(tags::HEADER) {
        None => Ok(String::new()),
        Some(value) => tags::Tags::from_header(value.as_bytes()).map(|tags| tags.stored()),
    };
    // S3 refuses them where they can't go: an upload's are given when it's
    // created.
    let tags_out_of_place = || {
        format_s3_error(StatusCode::BAD_REQUEST, "InvalidArgument", "The specified header is not valid in this context")
    };
    // CopyObject's `x-amz-tagging-directive`: whether the copy takes the
    // request's tags (REPLACE) or keeps its source's (COPY, the default).
    // Case-sensitive, as in S3.
    let replaces_tags = match req.headers().get(tags::DIRECTIVE).map(|v| v.as_bytes()) {
        None | Some(b"COPY") => Ok(false),
        Some(b"REPLACE") => Ok(true),
        Some(_) => Err(format_s3_error(StatusCode::BAD_REQUEST, "InvalidArgument", "Unknown tagging directive.")),
    };
    let resp = match req.method().clone() {
        hyper::Method::HEAD => {
            let response = head_object(
                &app,
                &bucket,
                &key,
                version_id.as_deref(),
                range.as_deref(),
                part_number,
                &preconditions,
                customer_key.as_ref(),
                role,
                checksum_mode,
            )
            .await?;
            match hides_missing(response.status()) {
                true => access.denied(&operation.checks[0], crate::policy::Verdict::ImplicitDeny),
                false => overrides.apply(object_lock::strip(response, tells_retention, tells_legal_hold)),
            }
        }
        // AbortMultipartUpload
        hyper::Method::DELETE if query_param(&query, "uploadId").is_some() => {
            let upload_id = query_param(&query, "uploadId").unwrap_or_default();
            abort_multipart_upload(&app, &bucket, &key, &upload_id).await?
        }
        hyper::Method::DELETE => {
            delete_object(&app, &bucket, &key, version_id.as_deref(), bypass).await?
        }
        // CreateMultipartUpload
        hyper::Method::POST if query_param(&query, "uploads").is_some() => {
            match (metadata, tags) {
                (Ok(metadata), Ok(tags)) => match checksums::requested_upload(req.headers()) {
                    Ok(checksum) => {
                        create_multipart_upload(
                            &app, &bucket, &key, &content_type, &metadata, &tags, wanted, role, checksum, lock,
                        )
                        .await?
                    }
                    Err(refused) => refused,
                },
                (Err(refused), _) | (_, Err(refused)) => refused,
            }
        }
        // CompleteMultipartUpload
        // Its x-amz-checksum-* header is the object's, not the body's.
        hyper::Method::POST if query_param(&query, "uploadId").is_some() => {
            if req.headers().contains_key(tags::HEADER) {
                return Ok(box_response(tags_out_of_place()));
            }
            let claimed = match checksums::claimed(req.headers()) {
                Ok(claimed) => claimed,
                Err(refused) => return Ok(box_response(refused)),
            };
            let expected_size = match complete::expected_size(req.headers()) {
                Ok(size) => size,
                Err(refused) => return Ok(box_response(refused)),
            };
            match read_body(req, &secret, false).await? {
                Ok(body) => {
                    let upload_id = query_param(&query, "uploadId").unwrap_or_default();
                    let customer_key = customer_key.as_ref();
                    complete_multipart_upload(
                        &app, &bucket, &key, &upload_id, body, &preconditions, customer_key, role, expected_size, claimed,
                    )
                    .await?
                }
                Err(rejection) => util::rejection_response(&rejection),
            }
        }
        // PutObjectAcl: there are no ACLs (`acl`).
        hyper::Method::PUT if query_param(&query, "acl").is_some() => {
            acl::put_object_acl(&app, &bucket, &key, version_id.as_deref(), req.headers()).await?
        }
        // UploadPartCopy: an UploadPart whose bytes come from another object
        // (x-amz-copy-source) instead of the request body. Must precede UploadPart.
        hyper::Method::PUT
            if query_param(&query, "uploadId").is_some() && copy_source.is_some() =>
        {
            let upload_id = query_param(&query, "uploadId").unwrap_or_default();
            let part_number = query_param(&query, "partNumber").unwrap_or_default();
            copy_part(
                &app,
                &bucket,
                &key,
                &upload_id,
                &part_number,
                &copy_source.unwrap(),
                copy_source_range.as_deref(),
                &copy_source_preconditions,
                source_key.as_ref(),
                customer_key.as_ref(),
                role,
            )
            .await?
        }
        // UploadPart
        hyper::Method::PUT if query_param(&query, "uploadId").is_some() => {
            if req.headers().contains_key(tags::HEADER) {
                return Ok(box_response(tags_out_of_place()));
            }
            let upload_id = query_param(&query, "uploadId").unwrap_or_default();
            let part_number = query_param(&query, "partNumber").unwrap_or_default();
            match payload.and_then(|payload| payload.at_most(util::MAX_UPLOAD)) {
                Ok(payload) => {
                    let customer_key = customer_key.as_ref();
                    put_part(&app, &bucket, &key, &upload_id, &part_number, req.into_body(), payload, customer_key, role)
                        .await?
                }
                Err(rejection) => util::rejection_response(&rejection),
            }
        }
        // CopyObject: a PUT with x-amz-copy-source and no uploadId (the uploadId
        // variant, UploadPartCopy, is handled above). The source is read
        // server-side, so the request body is ignored.
        hyper::Method::PUT if copy_source.is_some() => {
            // The request's tags only matter if they replace the source's.
            let tags = match replaces_tags {
                Ok(false) => None,
                Ok(true) => match tags {
                    Ok(tags) => Some(tags),
                    Err(refused) => return Ok(box_response(refused)),
                },
                Err(refused) => return Ok(box_response(refused)),
            };
            // The request's metadata only matters if it replaces the source's.
            let metadata = match metadata {
                Err(refused) if replaces_metadata(metadata_directive.as_deref()) => {
                    return Ok(box_response(refused));
                }
                metadata => metadata.unwrap_or_default(),
            };
            // The algorithm of the checksum it asks for; S3's 400 for one it
            // doesn't know.
            let checksum = match req.headers().get(checksums::ALGORITHM) {
                None => None,
                Some(name) => match name.to_str().ok().and_then(checksums::Algorithm::from_name) {
                    Some(algorithm) => Some(algorithm),
                    None => return Ok(box_response(checksums::invalid())),
                },
            };
            copy_object(
                &app,
                &bucket,
                &key,
                &copy_source.unwrap(),
                metadata_directive.as_deref(),
                &content_type,
                &metadata,
                tags.as_deref(),
                &copy_source_preconditions,
                CopyKeys { source: source_key.as_ref(), dest: wanted, role, checksum, lock },
            )
            .await?
        }
        hyper::Method::PUT => match (payload.and_then(|payload| payload.at_most(util::MAX_UPLOAD)), metadata, tags) {
            (Ok(payload), Ok(metadata), Ok(tags)) => {
                if let Err(refused) = checksums::check_put_type(req.headers(), payload.declared_algorithm()) {
                    return Ok(box_response(refused));
                }
                // A retained object's body must declare a checksum, as in S3.
                if !object_lock::declares_checksum(req.headers()) && object_lock::needs_checksum(&app, &bucket, &lock).await? {
                    return Ok(box_response(object_lock::missing_checksum()));
                }
                let body = req.into_body();
                put_object(
                    &app, &bucket, &key, &content_type, &metadata, &tags, body, payload, &preconditions, wanted, role,
                    lock,
                )
                .await?
            }
            (Err(rejection), _, _) => util::rejection_response(&rejection),
            (_, Err(refused), _) | (_, _, Err(refused)) => refused,
        },
        _ => format_s3_error(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", ""),
    };
    Ok(box_response(resp))
}

/// The most a request body that's handled whole may hold. Such a body is an
/// XML document, which is kept in memory; the largest real one, a
/// CompleteMultipartUpload of 10,000 parts with their checksums, is a few MiB.
const MAX_WHOLE_BODY: usize = 8 << 20;

/// Reads a request body that's handled whole (an XML document), checked
/// against what the request claims about it, as an upload's is (see
/// `Payload`), and refused if it's larger than `MAX_WHOLE_BODY`, as S3
/// refuses one too large. `checksum_headers` says whether its
/// `x-amz-checksum-*` header is one of the body. `Err` holds why it was
/// refused.
async fn read_body(
    req: Request<crate::listen::ClientBody>,
    secret: &str,
    checksum_headers: bool,
) -> anyhow::Result<Result<hyper::body::Bytes, Rejection>> {
    let too_big = || {
        Rejection::new(StatusCode::BAD_REQUEST, "MaxMessageLengthExceeded", "Your request was too big.")
    };
    let declared = req
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|length| length > MAX_WHOLE_BODY as u64) {
        return Ok(Err(too_big()));
    }
    let mut payload = match Payload::new(req.headers(), secret, checksum_headers) {
        Ok(payload) => payload,
        Err(rejection) => return Ok(Err(rejection)),
    };
    let mut body = req.into_body();
    let mut data = Vec::new();
    while let Some(frame) = body.frame().await {
        let Ok(chunk) = frame?.into_data() else { continue };
        match payload.decode(chunk) {
            Ok(pieces) => pieces.iter().for_each(|piece| data.extend_from_slice(piece)),
            Err(rejection) => return Ok(Err(rejection)),
        }
        // Without a Content-Length (chunked transfer encoding), or with an
        // aws-chunked body, the length is only known as it arrives.
        if data.len() > MAX_WHOLE_BODY {
            return Ok(Err(too_big()));
        }
    }
    Ok(payload.finish().map(|_| data.into()))
}

/// The S3 error for a request whose handler failed: 503 if storage nodes are
/// down (retrying later can succeed), 500 otherwise. The details are logged, not
/// sent, as they can name internal hosts.
pub fn error_response(e: &anyhow::Error) -> Response<ResBody> {
    let resp = if e.downcast_ref::<crate::Contended>().is_some() {
        util::slow_down()
    } else if crate::listen::ClientTimedOut::caused(e) {
        format_s3_error(
            StatusCode::BAD_REQUEST,
            "RequestTimeout",
            "Your socket connection to the server was not read from or written to within the timeout period. Idle connections will be closed.",
        )
    } else if e.downcast_ref::<crate::Unavailable>().is_some() {
        format_s3_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            "not enough storage nodes are available; please try again later",
        )
    } else {
        format_s3_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "we encountered an internal error; please try again",
        )
    };
    box_response(resp)
}

/// Why a request is refused by policy, if it is: as S3 refuses it, a
/// bucket that doesn't exist is a 404 to anyone (bucket names aren't
/// secret, only what's in them is), but to CreateBucket, which is about a
/// bucket that isn't there yet.
fn refusal(
    access: &access::Access,
    operation: &actions::Operation,
    exists: bool,
) -> Option<hyper::Response<http_body_util::Full<hyper::body::Bytes>>> {
    let (check, verdict) = access.first_denied(&operation.checks)?;
    if !exists && operation.name != "CreateBucket" {
        return Some(format_s3_error(StatusCode::NOT_FOUND, "NoSuchBucket", "the specified bucket does not exist"));
    }
    Some(access.denied(check, verdict))
}

/// The check of bypassing a GOVERNANCE retention of a version of `key`.
fn bypass_check(bucket: &str, key: &str) -> actions::Check {
    actions::Check {
        action: "s3:BypassGovernanceRetention",
        on: actions::On::Object(bucket.to_owned(), key.to_owned()),
    }
}

/// A 403 with the given S3 error code.
fn forbidden(code: &str, message: &str) -> Response<ResBody> {
    box_response(format_s3_error(StatusCode::FORBIDDEN, code, message))
}

/// The subresources a bucket's configuration is read from, which a role that
/// may see the bucket may read.
pub(crate) const BUCKET_CONFIGURATION: &[&str] = &[
    "versioning",
    "encryption",
    "ownershipControls",
    "acl",
    "location",
    "object-lock",
    "policy",
    "policyStatus",
    "publicAccessBlock",
    "cors",
    "tagging",
    "lifecycle",
    "website",
    "replication",
    "accelerate",
    "requestPayment",
    "logging",
    "notification",
];

/// Whether `principal` may make this request against `bucket` (`key` empty for a
/// bucket-level request). Bucket management — creating, deleting, and
/// configuring versioning — is admin-only, while a bucket HEAD or reading its
/// configuration (`BUCKET_CONFIGURATION`) just needs the bucket to be visible
/// to the role. Everything
/// else needs a grant on the bucket: `read` for GET/HEAD (or `write`, to list
/// uploads and their parts), `delete-version` to delete a specific version,
/// `write` for the rest. A copy also needs `read` on
/// its source bucket. DeleteObjects only needs one of `write` / `delete-version`
/// here; it checks each entry against them itself.
#[cfg(test)]
pub(crate) fn authorize(
    principal: &Principal,
    method: &Method,
    bucket: &str,
    key: &str,
    query: &str,
    copy_source: Option<&str>,
) -> bool {
    use crate::{roles::Permission, s3::objects::copy::parse_copy_source};
    if key.is_empty() {
        return match *method {
            Method::PUT | Method::DELETE => principal.admin,
            Method::HEAD => principal.can_see(bucket),
            // The bucket's configuration, like its versioning state, rather
            // than anything in it.
            Method::GET if BUCKET_CONFIGURATION.iter().any(|c| query_param(query, c).is_some()) => {
                principal.can_see(bucket)
            }
            // ListMultipartUploads: what's being written, which a writer
            // needs to find, to resume or abort an upload of its own.
            Method::GET if query_param(query, "uploads").is_some() => {
                principal.can(Permission::Read, bucket) || principal.can(Permission::Write, bucket)
            }
            Method::GET => principal.can(Permission::Read, bucket),
            Method::POST if query_param(query, "delete").is_some() => {
                principal.can(Permission::Write, bucket)
                    || principal.can(Permission::DeleteVersion, bucket)
            }
            _ => principal.can(Permission::Write, bucket),
        };
    }
    match *method {
        // ListParts: likewise.
        Method::GET if query_param(query, "uploadId").is_some() => {
            principal.can(Permission::Read, bucket) || principal.can(Permission::Write, bucket)
        }
        Method::GET | Method::HEAD => principal.can(Permission::Read, bucket),
        Method::PUT => {
            // A malformed copy source is left for the handler to reject with 400.
            let source_ok = match copy_source.and_then(parse_copy_source) {
                Some((src_bucket, _, _)) => principal.can(Permission::Read, &src_bucket),
                None => true,
            };
            principal.can(Permission::Write, bucket) && source_ok
        }
        // (DeleteObjectTagging changes a version's tags, as PutObjectTagging
        // does: `write`.)
        Method::DELETE
            if query_param(query, "versionId").is_some()
                && query_param(query, "uploadId").is_none()
                && query_param(query, "tagging").is_none() =>
        {
            principal.can(Permission::DeleteVersion, bucket)
        }
        _ => principal.can(Permission::Write, bucket),
    }
}
