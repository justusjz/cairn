use std::sync::Arc;

use http_body_util::Full;
use hyper::{Request, Response, StatusCode, body::Bytes};

use crate::{
    App,
    s3::{
        buckets::{create::create_bucket, list::list_buckets},
        util::{decode_path_param, format_s3_error},
    },
};

mod buckets;
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
            _ => Ok(format_s3_error(
                StatusCode::METHOD_NOT_ALLOWED,
                "MethodNotAllowed",
                "",
            )),
        }
    } else {
        // object operations
        Ok(Response::new(Full::new(Bytes::from("Object operations"))))
    }
}
