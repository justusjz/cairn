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
            delete::delete_object,
            get::{get_object, head_object},
            list::list_objects,
            put::put_object,
        },
        util::{decode_path_param, format_s3_error, query_param},
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
        // bucket operations
        let resp = match req.method() {
            &hyper::Method::GET => {
                let query = req.uri().query().unwrap_or("");
                let prefix = query_param(query, "prefix").unwrap_or_default();
                let delimiter = query_param(query, "delimiter");
                list_objects(&app, &bucket, &prefix, delimiter.as_deref()).await?
            }
            &hyper::Method::HEAD => head_bucket(&app, &bucket).await?,
            &hyper::Method::PUT => create_bucket(&app, &bucket).await?,
            &hyper::Method::DELETE => delete_bucket(&app, &bucket).await?,
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
        return get_object(&app, &bucket, &key, range.as_deref()).await;
    }
    let content_type = req
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();
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
            put_part(&app, &upload_id, &part_number, req.into_body()).await?
        }
        hyper::Method::PUT => put_object(&app, &bucket, &key, &content_type, req.into_body()).await?,
        _ => format_s3_error(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", ""),
    };
    Ok(box_response(resp))
}
