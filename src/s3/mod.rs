use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::{Method, Request, Response, StatusCode};

use crate::db::Cached;
use crate::{
    App,
    auth::Rejection,
    body::{ResBody, box_response},
    payload::{self, Payload},
    roles::{Permission, Principal},
    s3::{
        buckets::{
            create::create_bucket,
            delete::delete_bucket,
            head::head_bucket,
            list::list_buckets,
            encryption::{default_request, delete_bucket_encryption, get_bucket_encryption, put_bucket_encryption},
            versioning::{get_bucket_versioning, put_bucket_versioning},
        },
        conditional::Preconditions,
        multipart::{
            abort::abort_multipart_upload, complete::complete_multipart_upload,
            create::create_multipart_upload,
            list::list_multipart_uploads,
            list_parts::{MAX_PARTS, list_parts},
            upload_part::put_part,
        },
        objects::{
            copy::{CopyKeys, copy_object, copy_part, parse_copy_source, replaces_metadata},
            delete::{delete_object, delete_objects, missing_checksum},
            get::{get_object, head_object},
            list::{ListVersion, MAX_KEYS_LIMIT, list_objects},
            list_versions::list_object_versions,
            put::put_object,
        },
        util::{
            bucket_subresource_stub, decode_continuation_token, decode_path_param, format_s3_error,
            query_param, stub_acl,
        },
        versions::{invalid_version_id, is_version_id},
    },
};

pub(crate) mod buckets;
pub(crate) mod checksums;
pub(crate) mod acl;
pub(crate) mod conditional;
pub(crate) mod metadata;
pub(crate) mod sse;
pub(crate) mod sse_c;
pub(crate) mod multipart;
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
/// 503), logged with `what` the request was.
pub async fn handle(
    req: Request<hyper::body::Incoming>,
    app: Arc<App>,
    what: &str,
) -> Response<ResBody> {
    let mut id = [0u8; 8];
    getrandom::fill(&mut id).expect("the OS random number generator failed");
    let id: String = id.iter().map(|b| format!("{b:02X}")).collect();
    let mut response = REQUEST_ID
        .scope(id.clone(), async {
            handle_request(req, app).await.unwrap_or_else(|e| {
                eprintln!("{what} failed (request {id}): {e:#}");
                error_response(&e)
            })
        })
        .await;
    response.headers_mut().insert(
        "x-amz-request-id",
        id.parse().expect("hex is a header value"),
    );
    response
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    app: Arc<App>,
) -> anyhow::Result<Response<ResBody>> {
    // POST Object: a form posted to a bucket, which is signed in its body,
    // not its headers (see `objects::post`).
    if req.method() == Method::POST && objects::post::is_form(req.headers()) {
        let path = req.uri().path().trim_start_matches('/').to_owned();
        return Ok(box_response(objects::post::post_object(&app, req, &path).await?));
    }
    // Authenticate every other S3 request up front: look up the role the SigV4
    // credential names and verify the header signature with its secret. Needs
    // only the method/URI/query/headers, so it runs before any body is read. The
    // peer endpoint is a separate service and stays open for internal traffic.
    let Some(access_key) = crate::auth::access_key(req.headers(), req.uri().query().unwrap_or("")) else {
        return Ok(forbidden("AccessDenied", "request is not signed"));
    };
    let principal = Principal::load(&app.pool.get().await?, &access_key).await?;
    let Some(principal) = principal else {
        return Ok(forbidden(
            "InvalidAccessKeyId",
            "the access key ID does not exist",
        ));
    };
    if let Err(rejection) = crate::auth::verify_sigv4(
        req.method().as_str(),
        req.uri().path(),
        req.uri().query().unwrap_or(""),
        req.headers(),
        &principal.secret,
    ) {
        return Ok(box_response(util::rejection_response(&rejection)));
    }
    // Every key, prefix, marker and delimiter must be well-formed, so check the
    // whole path and query once, before anything decodes them.
    let mut query_values =
        req.uri().query().unwrap_or("").split('&').map(|p| p.split_once('=').map_or("", |(_, v)| v));
    if !util::is_well_formed(req.uri().path()) || !query_values.all(util::is_well_formed) {
        return Ok(box_response(util::unsupported_characters()));
    }
    let path = req.uri().path().trim_start_matches('/');
    if path.is_empty() {
        let resp = match req.method() {
            &hyper::Method::GET => {
                list_buckets(&app, &principal, req.uri().query().unwrap_or("")).await?
            }
            _ => format_s3_error(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", ""),
        };
        return Ok(box_response(resp));
    }
    let (bucket, key) = match path.split_once('/') {
        Some((bucket, key)) => (decode_path_param(bucket), decode_path_param(key)),
        None => (decode_path_param(path), "".to_owned()),
    };
    let copy_source_header = req
        .headers()
        .get("x-amz-copy-source")
        .and_then(|v| v.to_str().ok());
    let query = req.uri().query().unwrap_or("");
    if key.len() > util::MAX_KEY_LENGTH {
        return Ok(box_response(format_s3_error(
            StatusCode::BAD_REQUEST,
            "KeyTooLongError",
            "Your key is too long",
        )));
    }
    // Before anything routes on the method alone: an operation Cairn doesn't
    // implement would otherwise run as the plain PUT, DELETE or GET.
    if let Some(resp) = util::unsupported_subresource(req.method(), key.is_empty(), query) {
        return Ok(box_response(resp));
    }
    if !authorize(&principal, req.method(), &bucket, &key, query, copy_source_header) {
        // As in S3, a bucket that doesn't exist is a 404 to anyone: bucket
        // names aren't secret, only what's in them is. Except to CreateBucket,
        // which is about a bucket that isn't there yet.
        let creates_bucket = key.is_empty() && *req.method() == Method::PUT && query.is_empty();
        let exists = app
            .pool
            .get()
            .await?
            .query_opt_cached("SELECT 1 FROM buckets WHERE name = $1", &[&bucket])
            .await?
            .is_some();
        if !exists && !creates_bucket {
            return Ok(box_response(format_s3_error(
                StatusCode::NOT_FOUND,
                "NoSuchBucket",
                "the specified bucket does not exist",
            )));
        }
        return Ok(forbidden("AccessDenied", "Access Denied"));
    }
    if key.is_empty() {
        // bucket operations. POST (DeleteObjects) consumes the body, so capture the
        // query up front and match on an owned method — mirroring the object branch
        // below — instead of borrowing `req` across the arms.
        let query = req.uri().query().unwrap_or("").to_owned();
        // Bucket sub-resource GETs: versioning is real; the rest (acl/location/
        // policy/cors/tagging/lifecycle/object-lock) are stubbed — Cairn implements
        // none of them, so answer as S3 does for an unconfigured bucket before
        // falling through to a listing.
        if *req.method() == hyper::Method::GET {
            if query_param(&query, "versioning").is_some() {
                return Ok(box_response(get_bucket_versioning(&app, &bucket).await?));
            }
            if query_param(&query, "encryption").is_some() {
                return Ok(box_response(get_bucket_encryption(&app, &bucket).await?));
            }
            if query_param(&query, "ownershipControls").is_some() {
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
            hyper::Method::PUT if query_param(&query, "versioning").is_some() => {
                match read_body(req, &principal.secret, true).await? {
                    Ok(body) => put_bucket_versioning(&app, &bucket, body).await?,
                    Err(rejection) => util::rejection_response(&rejection),
                }
            }
            // PutBucketEncryption: PUT /{bucket}?encryption with a
            // <ServerSideEncryptionConfiguration> body.
            hyper::Method::PUT if query_param(&query, "encryption").is_some() => {
                match read_body(req, &principal.secret, true).await? {
                    Ok(body) => put_bucket_encryption(&app, &bucket, body, principal.id).await?,
                    Err(rejection) => util::rejection_response(&rejection),
                }
            }
            // PutBucketAcl: there are no ACLs (`acl`).
            hyper::Method::PUT if query_param(&query, "acl").is_some() => {
                acl::put_bucket_acl(&app, &bucket, req.headers()).await?
            }
            hyper::Method::PUT => match acl::check_write(req.headers(), acl::On::Bucket) {
                Ok(()) => create_bucket(&app, &bucket).await?,
                Err(refused) => refused,
            },
            // DeleteObjects (batch): POST /{bucket}?delete with a <Delete> body,
            // which must declare a checksum.
            hyper::Method::POST if query_param(&query, "delete").is_some() => {
                if !payload::has_body_checksum(req.headers()) {
                    return Ok(box_response(missing_checksum()));
                }
                match read_body(req, &principal.secret, true).await? {
                    Ok(body) => {
                        let may_write = principal.can(Permission::Write, &bucket);
                        let may_delete_versions = principal.can(Permission::DeleteVersion, &bucket);
                        delete_objects(&app, &bucket, body, may_write, may_delete_versions).await?
                    }
                    Err(rejection) => util::rejection_response(&rejection),
                }
            }
            hyper::Method::DELETE if query_param(&query, "encryption").is_some() => {
                delete_bucket_encryption(&app, &bucket).await?
            }
            hyper::Method::DELETE => delete_bucket(&app, &bucket).await?,
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
    // GET, HEAD and DELETE may address one specific version of the object.
    let version_id = query_param(&query, "versionId");
    let addresses_version = matches!(*req.method(), Method::GET | Method::HEAD | Method::DELETE);
    if let Some(v) = version_id.as_deref().filter(|v| addresses_version && !is_version_id(v)) {
        return Ok(box_response(invalid_version_id("versionId", v)));
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
            match sse::requested(req.headers(), customer_key.is_some(), app.kms.is_some(), sse_s3) {
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
    let role = Some(principal.id);
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
        return get_object(
            &app,
            &bucket,
            &key,
            version_id.as_deref(),
            range.as_deref(),
            &preconditions,
            customer_key.as_ref(),
            role,
            checksum_mode,
        )
        .await
        .map(|response| overrides.apply(response));
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
    let payload = Payload::new(req.headers(), &principal.secret, true);
    // The metadata a write stores with its object, or why it's refused. Only
    // the writes that take the request's metadata look at it.
    let metadata = metadata::from_request(req.headers());
    let resp = match req.method().clone() {
        hyper::Method::HEAD => overrides.apply(
            head_object(
                &app,
                &bucket,
                &key,
                version_id.as_deref(),
                range.as_deref(),
                &preconditions,
                customer_key.as_ref(),
                role,
                checksum_mode,
            )
            .await?,
        ),
        // AbortMultipartUpload
        hyper::Method::DELETE if query_param(&query, "uploadId").is_some() => {
            let upload_id = query_param(&query, "uploadId").unwrap_or_default();
            abort_multipart_upload(&app, &bucket, &key, &upload_id).await?
        }
        hyper::Method::DELETE => {
            delete_object(&app, &bucket, &key, version_id.as_deref()).await?
        }
        // CreateMultipartUpload
        hyper::Method::POST if query_param(&query, "uploads").is_some() => {
            match metadata {
                Ok(metadata) => match checksums::requested_upload(req.headers()) {
                    Ok(checksum) => {
                        create_multipart_upload(&app, &bucket, &key, &content_type, &metadata, wanted, role, checksum)
                            .await?
                    }
                    Err(refused) => refused,
                },
                Err(refused) => refused,
            }
        }
        // CompleteMultipartUpload
        // Its x-amz-checksum-* header is the object's, not the body's.
        hyper::Method::POST if query_param(&query, "uploadId").is_some() => {
            let claimed = match checksums::claimed(req.headers()) {
                Ok(claimed) => claimed,
                Err(refused) => return Ok(box_response(refused)),
            };
            match read_body(req, &principal.secret, false).await? {
                Ok(body) => {
                    let upload_id = query_param(&query, "uploadId").unwrap_or_default();
                    let customer_key = customer_key.as_ref();
                    complete_multipart_upload(
                        &app, &bucket, &key, &upload_id, body, &preconditions, customer_key, role, claimed,
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
                &copy_source_preconditions,
                CopyKeys { source: source_key.as_ref(), dest: wanted, role, checksum },
            )
            .await?
        }
        hyper::Method::PUT => match (payload.and_then(|payload| payload.at_most(util::MAX_UPLOAD)), metadata) {
            (Ok(payload), Ok(metadata)) => {
                if let Err(refused) = checksums::check_put_type(req.headers(), payload.declared_algorithm()) {
                    return Ok(box_response(refused));
                }
                let body = req.into_body();
                put_object(&app, &bucket, &key, &content_type, &metadata, body, payload, &preconditions, wanted, role)
                    .await?
            }
            (Err(rejection), _) => util::rejection_response(&rejection),
            (_, Err(refused)) => refused,
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
    req: Request<hyper::body::Incoming>,
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

/// A 403 with the given S3 error code.
fn forbidden(code: &str, message: &str) -> Response<ResBody> {
    box_response(format_s3_error(StatusCode::FORBIDDEN, code, message))
}

/// The subresources a bucket's configuration is read from, which a role that
/// may see the bucket may read.
const BUCKET_CONFIGURATION: &[&str] = &[
    "versioning",
    "encryption",
    "ownershipControls",
    "acl",
    "location",
    "object-lock",
    "policy",
    "cors",
    "tagging",
    "lifecycle",
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
fn authorize(
    principal: &Principal,
    method: &Method,
    bucket: &str,
    key: &str,
    query: &str,
    copy_source: Option<&str>,
) -> bool {
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
        Method::DELETE
            if query_param(query, "versionId").is_some()
                && query_param(query, "uploadId").is_none() =>
        {
            principal.can(Permission::DeleteVersion, bucket)
        }
        _ => principal.can(Permission::Write, bucket),
    }
}
