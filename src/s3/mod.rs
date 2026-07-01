use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::{Request, Response, StatusCode};

use crate::{
    App,
    body::{ResBody, box_response},
    s3::{
        buckets::{
            create::create_bucket, delete::delete_bucket, head::head_bucket, list::list_buckets,
        },
        multipart::{
            abort::abort_multipart_upload, complete::complete_multipart_upload,
            create::create_multipart_upload, upload_part::put_part,
        },
        objects::{
            copy::copy_object,
            delete::{delete_object, delete_objects},
            get::{get_object, head_object},
            list::{ListVersion, MAX_KEYS_LIMIT, list_objects},
            put::put_object,
        },
        util::{
            bucket_subresource_stub, decode_continuation_token, decode_path_param, format_s3_error,
            query_param, stub_acl,
        },
    },
};

mod buckets;
mod multipart;
mod objects;
mod util;

pub async fn handle(
    req: Request<hyper::body::Incoming>,
    app: Arc<App>,
) -> anyhow::Result<Response<ResBody>> {
    // Authenticate every S3 request up front (SigV4 header signature). Needs only
    // the method/URI/query/headers, so it runs before any body is read. The peer
    // endpoint is a separate service and stays open for internal traffic.
    if let Err(code) = crate::auth::verify_sigv4(
        req.method().as_str(),
        req.uri().path(),
        req.uri().query().unwrap_or(""),
        req.headers(),
        crate::auth::SECRET_KEY,
    ) {
        return Ok(box_response(format_s3_error(
            StatusCode::FORBIDDEN,
            code,
            "request authentication failed",
        )));
    }
    let path = req.uri().path().trim_start_matches('/');
    if path.is_empty() {
        let resp = match req.method() {
            &hyper::Method::GET => list_buckets(&app).await?,
            _ => format_s3_error(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", ""),
        };
        return Ok(box_response(resp));
    }
    let (bucket, key) = match path.split_once('/') {
        Some((bucket, key)) => (decode_path_param(bucket), decode_path_param(key)),
        None => (decode_path_param(path), "".to_owned()),
    };
    if key.is_empty() {
        // bucket operations. POST (DeleteObjects) consumes the body, so capture the
        // query up front and match on an owned method — mirroring the object branch
        // below — instead of borrowing `req` across the arms.
        let query = req.uri().query().unwrap_or("").to_owned();
        // Bucket sub-resource GETs (acl/location/versioning/policy/cors/tagging/
        // lifecycle/object-lock) are stubbed — Cairn implements none of them, so
        // answer as S3 does for an unconfigured bucket before falling through to a
        // listing.
        if *req.method() == hyper::Method::GET {
            if let Some(resp) = bucket_subresource_stub(&query) {
                return Ok(box_response(resp));
            }
        }
        let resp = match req.method().clone() {
            hyper::Method::GET => {
                let prefix = query_param(&query, "prefix").unwrap_or_default();
                let delimiter = query_param(&query, "delimiter");
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
                    }
                } else {
                    ListVersion::V1
                };
                // Clamp max-keys to [0, 1000]; absent or unparseable falls back to
                // the 1000 default (lenient — we don't 400 on a garbage value).
                let max_keys = query_param(&query, "max-keys")
                    .and_then(|v| v.parse::<i64>().ok())
                    .unwrap_or(MAX_KEYS_LIMIT)
                    .clamp(0, MAX_KEYS_LIMIT);
                list_objects(
                    &app,
                    &bucket,
                    &prefix,
                    delimiter.as_deref(),
                    &marker,
                    max_keys,
                    version,
                )
                .await?
            }
            hyper::Method::HEAD => head_bucket(&app, &bucket).await?,
            hyper::Method::PUT => create_bucket(&app, &bucket).await?,
            // DeleteObjects (batch): POST /{bucket}?delete with a <Delete> body.
            // Read the integrity headers before consuming the body to verify it.
            hyper::Method::POST if query_param(&query, "delete").is_some() => {
                let checksum = crate::auth::BodyChecksum::from_headers(req.headers());
                let body = req.into_body().collect().await?.to_bytes();
                delete_objects(&app, &bucket, body, checksum).await?
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
    if *req.method() == hyper::Method::GET {
        // ACL is stubbed; otherwise a `?acl` GET would stream object bytes and
        // break XML-parsing clients like `s3cmd info`.
        if query_param(&query, "acl").is_some() {
            return Ok(box_response(stub_acl()));
        }
        return get_object(&app, &bucket, &key, range.as_deref()).await;
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
    // Streaming-signature uploads (e.g. Mimir) frame the body as `aws-chunked`;
    // the upload path must decode it rather than store the framing verbatim.
    let aws_chunked = crate::aws_chunked::is_aws_chunked(req.headers());
    // The body-integrity claim the client makes (verified as the body streams).
    let content_sha256 = crate::auth::ContentSha256::from_headers(req.headers());
    // For a signed streaming body (mode 4), build the chunk-signature verifier
    // from the request's SigV4 auth + the server secret. Absent for unsigned
    // requests (no Authorization), which then stream without chunk verification.
    let chunk_verifier = match &content_sha256 {
        crate::auth::ContentSha256::Streaming => {
            crate::auth::StreamingChunkVerifier::from_headers(req.headers(), crate::auth::SECRET_KEY)
        }
        _ => None,
    };
    let resp = match req.method().clone() {
        hyper::Method::HEAD => head_object(&app, &bucket, &key, range.as_deref()).await?,
        // AbortMultipartUpload
        hyper::Method::DELETE if query_param(&query, "uploadId").is_some() => {
            let upload_id = query_param(&query, "uploadId").unwrap_or_default();
            abort_multipart_upload(&app, &upload_id).await?
        }
        hyper::Method::DELETE => delete_object(&app, &bucket, &key).await?,
        // CreateMultipartUpload
        hyper::Method::POST if query_param(&query, "uploads").is_some() => {
            create_multipart_upload(&app, &bucket, &key, &content_type).await?
        }
        // CompleteMultipartUpload
        hyper::Method::POST if query_param(&query, "uploadId").is_some() => {
            let body = req.into_body().collect().await?.to_bytes();
            let upload_id = query_param(&query, "uploadId").unwrap_or_default();
            complete_multipart_upload(&app, &upload_id, body).await?
        }
        // UploadPart
        hyper::Method::PUT if query_param(&query, "uploadId").is_some() => {
            let upload_id = query_param(&query, "uploadId").unwrap_or_default();
            let part_number = query_param(&query, "partNumber").unwrap_or_default();
            put_part(
                &app,
                &upload_id,
                &part_number,
                req.into_body(),
                aws_chunked,
                content_sha256,
                chunk_verifier,
            )
            .await?
        }
        // CopyObject: a PUT with x-amz-copy-source and no uploadId (the multipart
        // UploadPartCopy variant is not supported). The source is read server-side,
        // so the request body is ignored.
        hyper::Method::PUT if copy_source.is_some() => {
            copy_object(
                &app,
                &bucket,
                &key,
                &copy_source.unwrap(),
                metadata_directive.as_deref(),
                &content_type,
            )
            .await?
        }
        hyper::Method::PUT => {
            put_object(
                &app,
                &bucket,
                &key,
                &content_type,
                req.into_body(),
                aws_chunked,
                content_sha256,
                chunk_verifier,
            )
            .await?
        }
        _ => format_s3_error(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", ""),
    };
    Ok(box_response(resp))
}
