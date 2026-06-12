use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, body::Bytes};

use crate::{
    App,
    s3::{
        buckets::{create::create_bucket, delete::delete_bucket, list::list_buckets},
        objects::{
            delete::delete_object,
            get::{get_object, head_object},
            list::list_objects,
            multipart::{complete_multipart_upload, create_multipart_upload, put_part},
            put::put_object,
        },
        util::{decode_path_param, format_s3_error, query_param},
    },
};

mod buckets;
mod objects;
mod util;

pub async fn handle(
    req: Request<hyper::body::Incoming>,
    app: Arc<App>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let path = req.uri().path().trim_start_matches('/');
    if path.is_empty() {
        return match req.method() {
            &hyper::Method::GET => list_buckets(&app).await,
            _ => Ok(format_s3_error(
                StatusCode::METHOD_NOT_ALLOWED,
                "MethodNotAllowed",
                "",
            )),
        };
    }
    let (bucket, key) = match path.split_once('/') {
        Some((bucket, key)) => (decode_path_param(bucket), decode_path_param(key)),
        None => (decode_path_param(path), "".to_owned()),
    };
    if key.is_empty() {
        // bucket operations
        match req.method() {
            &hyper::Method::GET => {
                let query = req.uri().query().unwrap_or("");
                let prefix = query_param(query, "prefix").unwrap_or_default();
                let delimiter = query_param(query, "delimiter");
                list_objects(&app, &bucket, &prefix, delimiter.as_deref()).await
            }
            &hyper::Method::PUT => create_bucket(&app, &bucket).await,
            &hyper::Method::DELETE => delete_bucket(&app, &bucket).await,
            _ => Ok(format_s3_error(
                StatusCode::METHOD_NOT_ALLOWED,
                "MethodNotAllowed",
                "",
            )),
        }
    } else {
        // object operations. Pull query + content type out first (the latter
        // borrows `req`); clone the method so the body-consuming arms still can.
        let query = req.uri().query().unwrap_or("").to_owned();
        let content_type = req
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_owned();
        match req.method().clone() {
            hyper::Method::HEAD => head_object(&app, &bucket, &key).await,
            hyper::Method::GET => get_object(&app, &bucket, &key).await,
            hyper::Method::DELETE => delete_object(&app, &bucket, &key).await,
            // CreateMultipartUpload
            hyper::Method::POST if query_param(&query, "uploads").is_some() => {
                create_multipart_upload(&app, &bucket, &key, &content_type).await
            }
            // CompleteMultipartUpload
            hyper::Method::POST if query_param(&query, "uploadId").is_some() => {
                let body = req.into_body().collect().await?.to_bytes();
                let upload_id = query_param(&query, "uploadId").unwrap_or_default();
                complete_multipart_upload(&app, &upload_id, body).await
            }
            // UploadPart
            hyper::Method::PUT if query_param(&query, "uploadId").is_some() => {
                let data = req.into_body().collect().await?.to_bytes();
                let upload_id = query_param(&query, "uploadId").unwrap_or_default();
                let part_number = query_param(&query, "partNumber").unwrap_or_default();
                put_part(&app, &upload_id, &part_number, data).await
            }
            hyper::Method::PUT => {
                let data = req.into_body().collect().await?.to_bytes();
                put_object(&app, &bucket, &key, &content_type, data).await
            }
            _ => Ok(format_s3_error(
                StatusCode::METHOD_NOT_ALLOWED,
                "MethodNotAllowed",
                "",
            )),
        }
    }
}
