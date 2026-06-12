use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use percent_encoding::percent_decode_str;

pub fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn xml_ok(body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

pub fn format_s3_error(status: StatusCode, code: &str, message: &str) -> Response<Full<Bytes>> {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <Error><Code>{}</Code><Message>{}</Message></Error>",
        xml_escape(code),
        xml_escape(message)
    );
    Response::builder()
        .status(status)
        .header("content-type", "application/xml")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

pub fn decode_path_param(param: &str) -> String {
    percent_decode_str(param).decode_utf8_lossy().into_owned()
}

/// Extracts and percent-decodes a single parameter from a raw query string
/// (e.g. "prefix=dir%2F&delimiter=%2F").
pub fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (k == name).then(|| decode_path_param(&v.replace('+', " ")))
    })
}
