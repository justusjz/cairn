use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
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

/// A fixed AccessControlPolicy. Cairn doesn't model ACLs, so every bucket and
/// object reports owner "cairn" with FULL_CONTROL. This lets clients that probe
/// ACLs (e.g. `s3cmd info`, which issues a `?acl` GET) parse a valid response
/// instead of choking on object bytes.
pub fn stub_acl() -> Response<Full<Bytes>> {
    xml_ok(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Owner><ID>cairn</ID><DisplayName>cairn</DisplayName></Owner>\
         <AccessControlList><Grant>\
         <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">\
         <ID>cairn</ID><DisplayName>cairn</DisplayName></Grantee>\
         <Permission>FULL_CONTROL</Permission>\
         </Grant></AccessControlList>\
         </AccessControlPolicy>"
            .to_string(),
    )
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

/// Mints a ListObjectsV2 `continuation-token` carrying `marker` (the key to
/// resume after). URL-safe base64 has no `+`/`/`/`=`, so the token survives
/// `query_param` untouched on the way back. Inverse of
/// [`decode_continuation_token`].
pub fn encode_continuation_token(marker: &str) -> String {
    URL_SAFE_NO_PAD.encode(marker)
}

/// Decodes a ListObjectsV2 `continuation-token` back to the marker it carries
/// (the key to resume after). A token that doesn't decode is a malformed client
/// request.
pub fn decode_continuation_token(token: &str) -> Option<String> {
    let bytes = URL_SAFE_NO_PAD.decode(token).ok()?;
    String::from_utf8(bytes).ok()
}

/// Extracts and percent-decodes a single parameter from a raw query string
/// (e.g. "prefix=dir%2F&delimiter=%2F").
pub fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (k == name).then(|| decode_path_param(&v.replace('+', " ")))
    })
}
