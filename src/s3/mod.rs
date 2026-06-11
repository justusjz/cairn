use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, body::Bytes};

use crate::{
    App,
    s3::{
        buckets::{create::create_bucket, delete::delete_bucket, list::list_buckets},
        objects::{
            get::{get_object, head_object},
            put::put_object,
        },
        util::{decode_path_param, format_s3_error},
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
            &hyper::Method::PUT => create_bucket(&app, &bucket).await,
            &hyper::Method::DELETE => delete_bucket(&app, &bucket).await,
            _ => Ok(format_s3_error(
                StatusCode::METHOD_NOT_ALLOWED,
                "MethodNotAllowed",
                "",
            )),
        }
    } else {
        // object operations. Clone the method so the PUT arm can still consume
        // `req`'s body.
        match req.method().clone() {
            hyper::Method::HEAD => head_object(&app, &bucket, &key).await,
            hyper::Method::GET => get_object(&app, &bucket, &key).await,
            hyper::Method::PUT => {
                let content_type = req
                    .headers()
                    .get(hyper::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("application/octet-stream")
                    .to_owned();
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
