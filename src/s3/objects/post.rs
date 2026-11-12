//! POST Object: an upload in a `multipart/form-data` form, posted to its
//! bucket, as S3 takes it. The form is signed instead of the request: its
//! `policy` field (see `post_policy`) says what it may hold, and is signed
//! with SigV4 by the role it's uploaded as (see `auth::PostSignature`), so
//! one server can let another upload under conditions (a size range, a key
//! prefix, the encryption to use) without giving it a key. A form without
//! any signature (and so without a policy) is anonymous, as in S3: only a
//! bucket policy can allow it.
//!
//! The fields before the file are read whole, at most `MAX_PRE_DATA` of
//! them, as S3 limits them; the file is streamed into the object, as a
//! PutObject's body is; what comes after it is never read. Its fields are
//! the headers a PutObject would have: they're turned into those, and read by
//! the same code (metadata, ACL, encryption, checksums).

use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use futures_core::Stream;
use http_body_util::Full;
use hyper::{
    HeaderMap, Method, Request, Response, StatusCode,
    body::{Body, Bytes, Frame},
    header::{self, HeaderName, HeaderValue},
};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

use crate::{
    App,
    auth::PostSignature,
    payload::Payload,
    roles::Principal,
    s3::{
        access, acl, actions,
        buckets::encryption::default_request,
        checksums,
        conditional::Preconditions,
        metadata,
        objects::put::put_object,
        post_policy::{Fields, Policy, field},
        sse, sse_c,
        tags::{On, Tags},
        util::{self, format_s3_error, rejection_response, xml_escape},
    },
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The most a form may hold before its file, boundaries and part headers
/// included: S3's 20 KB.
const MAX_PRE_DATA: usize = 20 * 1024;

/// The most of a request's body that's read before its file is found. More
/// than `MAX_PRE_DATA`, as it's counted as it arrives, a chunk at a time,
/// and a chunk may hold some of the file: this only bounds what the parser
/// buffers.
const MAX_PRE_FILE_READ: u64 = 1 << 20;

/// Whether a request's body is a form: then a POST to a bucket is POST
/// Object.
pub fn is_form(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim_start().to_ascii_lowercase().starts_with("multipart/form-data"))
}

fn malformed(detail: &str) -> Response<Full<Bytes>> {
    let message = match detail {
        "" => "The body of your POST request is not well-formed multipart/form-data.".to_owned(),
        _ => format!("The body of your POST request is not well-formed multipart/form-data. ({detail})"),
    };
    format_s3_error(StatusCode::BAD_REQUEST, "MalformedPOSTRequest", &message)
}

fn pre_data_too_large() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::BAD_REQUEST,
        "MaxPostPreDataLengthExceededError",
        "Your POST request fields preceding the upload file were too large.",
    )
}

/// The request's body, as the form parser reads it: refused once more than
/// `MAX_PRE_FILE_READ` of it has been read before the file was found.
struct RequestStream<B> {
    body: B,
    read: u64,
    in_file: Arc<AtomicBool>,
}

/// Why the request's body couldn't be read.
#[derive(Debug)]
enum ReadError {
    /// Too much came before the file.
    PreDataTooLarge,
    /// The body failed (the client went away, say).
    Body(BoxError),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::PreDataTooLarge => write!(f, "the form's fields before its file are too large"),
            ReadError::Body(e) => write!(f, "reading the request body: {e}"),
        }
    }
}

impl std::error::Error for ReadError {}

impl<B> Stream for RequestStream<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Item = Result<Bytes, ReadError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if self.read > MAX_PRE_FILE_READ && !self.in_file.load(Ordering::Relaxed) {
                return Poll::Ready(Some(Err(ReadError::PreDataTooLarge)));
            }
            let frame = match Pin::new(&mut self.body).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => frame,
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(ReadError::Body(e.into())))),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            };
            if let Ok(data) = frame.into_data() {
                self.read += data.len() as u64;
                return Poll::Ready(Some(Ok(data)));
            }
        }
    }
}

/// Why a form failed to parse: S3's error, or the body failing.
fn form_error(e: multer::Error) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    match e {
        multer::Error::StreamReadFailed(e) => match e.downcast::<ReadError>() {
            Ok(e) => match *e {
                ReadError::PreDataTooLarge => Ok(pre_data_too_large()),
                ReadError::Body(e) => Err(anyhow::anyhow!(e)),
            },
            Err(e) => Err(anyhow::anyhow!(e)),
        },
        _ => Ok(malformed("")),
    }
}

/// The form's file, as the body of the object it becomes.
struct FileBody(multer::Field<'static>);

/// Why the file couldn't be read: the form ended without it ending (or
/// otherwise wasn't one), or the body failed.
#[derive(Debug)]
enum FileError {
    Malformed,
    Body(BoxError),
}

impl std::fmt::Display for FileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileError::Malformed => write!(f, "the form is malformed"),
            FileError::Body(e) => write!(f, "reading the request body: {e}"),
        }
    }
}

impl std::error::Error for FileError {}

impl Body for FileBody {
    type Data = Bytes;
    type Error = FileError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, FileError>>> {
        match Pin::new(&mut self.0).poll_next(cx) {
            Poll::Ready(Some(Ok(data))) => Poll::Ready(Some(Ok(Frame::data(data)))),
            Poll::Ready(Some(Err(multer::Error::StreamReadFailed(e)))) => {
                Poll::Ready(Some(Err(FileError::Body(e))))
            }
            Poll::Ready(Some(Err(_))) => Poll::Ready(Some(Err(FileError::Malformed))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Handles a form posted to `/{bucket}` (or refuses one posted elsewhere).
/// `path` is the request's route (see `s3::hosting`), without its leading
/// `/`; `virtual_host` whether its bucket was in its host.
pub async fn post_object<B>(
    app: &Arc<App>,
    req: Request<B>,
    path: &str,
    virtual_host: bool,
    peer: Option<std::net::IpAddr>,
) -> anyhow::Result<Response<Full<Bytes>>>
where
    B: Body<Data = Bytes> + Unpin + Send + 'static,
    B::Error: Into<BoxError>,
{
    let (bucket, key) = path.split_once('/').unwrap_or((path, ""));
    if bucket.is_empty() || !key.is_empty() {
        return Ok(format_s3_error(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", ""));
    }
    if !util::is_well_formed(bucket) {
        return Ok(util::unsupported_characters());
    }
    let bucket = util::decode_path_param(bucket);
    let query = req.uri().query().unwrap_or("");
    if req.headers().contains_key(header::AUTHORIZATION) || util::query_param(query, "X-Amz-Algorithm").is_some() {
        return Ok(format_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "Only one auth mechanism allowed; only the policy form fields or the Authorization header \
             should be specified",
        ));
    }
    let content_type = req.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let Ok(boundary) = multer::parse_boundary(content_type) else { return Ok(malformed("")) };
    let secure = sse_c::secure(req.headers(), app.allow_sse_c_over_http);
    let location = object_location(req.headers(), &bucket, virtual_host);
    let in_file = Arc::new(AtomicBool::new(false));
    let stream = RequestStream { body: req.into_body(), read: 0, in_file: in_file.clone() };
    let mut form = multer::Multipart::new(stream, boundary.clone());

    // The fields, up to the file.
    let mut fields: Fields = Vec::new();
    let mut pre_data = 0;
    let file = loop {
        let mut part = match form.next_field().await {
            Ok(Some(part)) => part,
            Ok(None) => break None,
            Err(e) => return form_error(e),
        };
        let Some(name) = part.name().map(str::to_ascii_lowercase) else { return Ok(malformed("")) };
        // The part's boundary line, headers, and the empty line after them.
        pre_data += boundary.len() + 4 + 2;
        pre_data += part.headers().iter().map(|(n, v)| n.as_str().len() + v.len() + 4).sum::<usize>();
        if pre_data > MAX_PRE_DATA {
            return Ok(pre_data_too_large());
        }
        if name == "file" {
            in_file.store(true, Ordering::Relaxed);
            let file_name = part.file_name().unwrap_or("");
            // Only its name, as S3 takes it, whichever system it's from.
            let file_name = file_name.rsplit(['/', '\\']).next().unwrap_or("").to_owned();
            break Some((part, file_name));
        }
        let mut value = Vec::new();
        loop {
            match part.chunk().await {
                Ok(Some(chunk)) => {
                    value.extend_from_slice(&chunk);
                    if pre_data + value.len() > MAX_PRE_DATA {
                        return Ok(pre_data_too_large());
                    }
                }
                Ok(None) => break,
                Err(e) => return form_error(e),
            }
        }
        pre_data += value.len() + 2;
        let Ok(value) = String::from_utf8(value) else { return Ok(malformed("")) };
        if field(&fields, &name).is_some() {
            return Ok(malformed(&format!("The form has the field {name} more than once")));
        }
        fields.push((name, value));
    };
    let Some((file, file_name)) = file else { return Ok(malformed("The file or text content is missing")) };
    // `${filename}` is the file's name, in every field, before the policy's
    // checked.
    for (_, value) in &mut fields {
        if value.contains("${filename}") {
            *value = value.replace("${filename}", &file_name);
        }
    }

    // Who signed it, and what they allow; no one, if it isn't signed at all
    // (anonymous: only a bucket policy can allow it, as in S3).
    let client = app.pool.get().await?;
    let signed = match SIGNING_FIELDS.iter().any(|name| field(&fields, name).is_some()) {
        false => None,
        true => {
            let signature = match PostSignature::from_fields(|name| field(&fields, name)) {
                Ok(signature) => signature,
                Err(rejection) => return Ok(rejection_response(&rejection)),
            };
            let Some(principal) = Principal::load(&client, &signature.access_key).await? else {
                return Ok(format_s3_error(StatusCode::FORBIDDEN, "InvalidAccessKeyId", "the access key ID does not exist"));
            };
            if let Err(rejection) = signature.verify(&principal.secret) {
                return Ok(rejection_response(&rejection));
            }
            let document = field(&fields, "policy").unwrap_or("");
            let Ok(document) = STANDARD.decode(document.trim()) else { return Ok(malformed("")) };
            let policy = match Policy::parse(&document) {
                Ok(policy) => policy,
                Err(rejection) => return Ok(rejection_response(&rejection)),
            };
            let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock after 1970").as_secs() as i64;
            if let Err(rejection) = policy.check(&fields, &bucket, now) {
                return Ok(rejection_response(&rejection));
            }
            Some((signature, principal, policy))
        }
    };
    let account = crate::roles::account(&client).await?;
    drop(client);
    let key = match field(&fields, "key") {
        Some(key) if !key.is_empty() => key.to_owned(),
        _ => return Ok(malformed("The name of the uploaded key is missing")),
    };
    if key.len() > util::MAX_KEY_LENGTH {
        return Ok(format_s3_error(StatusCode::BAD_REQUEST, "KeyTooLongError", "Your key is too long"));
    }
    if key.contains('\0') {
        return Ok(util::unsupported_characters());
    }

    // The rest is a PutObject's, with the fields for headers.
    let headers = match headers(&fields) {
        Ok(headers) => headers,
        Err(refused) => return Ok(refused),
    };
    // As a PutObject (its tags and ACL too, if it sets them; see
    // `actions`), by the user's policies and the bucket's, and a bucket that
    // isn't there is a 404 to anyone.
    let mut tagged = headers.clone();
    if field(&fields, "tagging").is_some() {
        tagged.insert("x-amz-tagging", HeaderValue::from_static("form"));
    }
    let operation = actions::operation(&Method::PUT, &bucket, &key, "", &tagged).expect("a PUT is an operation");
    let signature = signed.as_ref().map(|(signature, _, _)| signature.signed());
    let principal = signed.as_ref().map(|(_, principal, _)| principal);
    let origin = access::Origin { peer, trusted_proxies: &app.trusted_proxies, signed: signature.as_ref(), form: true };
    let mut access = access::Access::new(principal, &account, &Method::POST, &headers, "", &origin)?;
    let exists = access.load(app, &bucket).await?;
    if let Some((check, verdict)) = access.first_denied(&operation.checks) {
        return Ok(match exists {
            true => access.denied(check, verdict),
            false => format_s3_error(StatusCode::NOT_FOUND, "NoSuchBucket", "the specified bucket does not exist"),
        });
    }
    let customer_key = match sse_c::requested(&headers, &sse_c::HEADERS, secure) {
        Ok(key) => key,
        Err(refused) => return Ok(refused),
    };
    let sse_s3 = app.kms.as_ref().is_some_and(|kms| kms.sse_s3_key().is_some());
    let server = match sse::requested(&headers, customer_key.is_some(), app.kms.is_some(), sse_s3) {
        Ok(None) if customer_key.is_none() => match default_request(app, &bucket).await? {
            Ok(request) => request,
            Err(refused) => return Ok(refused),
        },
        Ok(request) => request,
        Err(refused) => return Ok(refused),
    };
    let wanted = sse::Wanted::new(customer_key.as_ref(), server.as_ref());
    if let Err(refused) = acl::check_write(&headers, acl::On::Object) {
        return Ok(refused);
    }
    let metadata = match metadata::from_request(&headers) {
        Ok(metadata) => metadata,
        Err(refused) => return Ok(refused),
    };
    // Its tags: a `<Tagging>` document, as S3 takes them in a form (not a
    // header's form), with PutObjectTagging's errors.
    let tags = match field(&fields, "tagging") {
        None => String::new(),
        Some(document) => match Tags::from_xml(document.as_bytes(), On::Object) {
            Ok(tags) => tags.stored(),
            Err(refused) => return Ok(refused),
        },
    };
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();
    let (min, max) = signed.as_ref().and_then(|(_, _, policy)| policy.length_range()).unwrap_or((0, util::MAX_UPLOAD));
    let secret = principal.map_or("", |principal| principal.secret.as_str());
    let payload = match Payload::new(&headers, secret, true)
        .and_then(|payload| payload.at_most(max.min(util::MAX_UPLOAD)))
    {
        Ok(payload) => payload.at_least(min),
        Err(rejection) => return Ok(rejection_response(&rejection)),
    };
    if let Err(refused) = checksums::check_put_type(&headers, payload.declared_algorithm()) {
        return Ok(refused);
    }
    let conditions = Preconditions::default();
    let role = principal.map(|principal| principal.id);
    let body = FileBody(file);
    let response = match put_object(app, &bucket, &key, &content_type, &metadata, &tags, body, payload, &conditions, wanted, role)
        .await
    {
        Ok(response) => response,
        Err(e) => {
            return match e.downcast_ref::<FileError>() {
                Some(FileError::Malformed) => Ok(malformed("")),
                _ => Err(e),
            };
        }
    };
    if response.status() != StatusCode::OK {
        return Ok(response);
    }
    Ok(respond(response, &fields, &bucket, &key, location))
}

/// The fields that sign a form (SigV4's, and SigV2's, which Cairn refuses):
/// a form with none of them is anonymous.
const SIGNING_FIELDS: [&str; 7] =
    ["policy", "x-amz-signature", "x-amz-credential", "x-amz-algorithm", "x-amz-date", "awsaccesskeyid", "signature"];

/// The headers of a PutObject that the form's `fields` stand for. Fields
/// that aren't one are left out, as a PutObject's other headers are ignored:
/// none of them can say anything about how the body is framed or signed.
fn headers(fields: &Fields) -> Result<HeaderMap, Response<Full<Bytes>>> {
    const SAME: [&str; 17] = [
        "content-type",
        "cache-control",
        "content-disposition",
        "content-encoding",
        "content-language",
        "expires",
        "content-md5",
        sse::ENCRYPTION,
        sse::KMS_KEY_ID,
        sse::KMS_CONTEXT,
        sse::BUCKET_KEY_ENABLED,
        "x-amz-server-side-encryption-customer-algorithm",
        "x-amz-server-side-encryption-customer-key",
        "x-amz-server-side-encryption-customer-key-md5",
        checksums::TYPE,
        "x-amz-storage-class",
        "x-amz-acl",
    ];
    let mut headers = HeaderMap::new();
    for (name, value) in fields {
        let name = match name.as_str() {
            "acl" => "x-amz-acl",
            // A form names its checksum's algorithm as a PutObject's SDK
            // does: it has to send that one.
            checksums::ALGORITHM => checksums::SDK_ALGORITHM,
            "x-amz-acl" => continue,
            name if SAME.contains(&name) => name,
            name if name.starts_with("x-amz-meta-") => name,
            name if checksums::Algorithm::ALL.iter().any(|a| a.header() == name) => name,
            _ => continue,
        };
        let invalid = || {
            format_s3_error(StatusCode::BAD_REQUEST, "InvalidArgument", &format!("The value of the field {name} is invalid."))
        };
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| invalid())?;
        let value = HeaderValue::from_bytes(value.as_bytes()).map_err(|_| invalid())?;
        headers.insert(name, value);
    }
    Ok(headers)
}

/// Characters of a key that are escaped in its URL: all but unreserved ones
/// and `/`.
const KEY_ESCAPES: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~').remove(b'/');

/// Characters escaped in a query parameter's value.
const QUERY_ESCAPES: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');

/// The URL of `bucket`, as the client reached it, if it said how (`Host`):
/// the host itself if it's the bucket's (`virtual_host`), else the bucket's
/// path on it. The object's is this and its key.
fn object_location(headers: &HeaderMap, bucket: &str, virtual_host: bool) -> Option<String> {
    let host = headers.get(header::HOST)?.to_str().ok()?;
    let scheme = if sse_c::secure(headers, false) { "https" } else { "http" };
    Some(match virtual_host {
        true => format!("{scheme}://{host}"),
        false => format!("{scheme}://{host}/{}", utf8_percent_encode(bucket, KEY_ESCAPES)),
    })
}

/// The response to a successful upload, as the form asks for it: a redirect
/// (`success_action_redirect`, or the older `redirect`) to a URL with the
/// object's bucket, key and ETag in its query; else `success_action_status`:
/// 200 or 204, empty, or 201, with a `PostResponse` document; 204 by default.
/// With the headers a PutObject's has (the `put` response), and `Location`.
fn respond(
    put: Response<Full<Bytes>>,
    fields: &Fields,
    bucket: &str,
    key: &str,
    location: Option<String>,
) -> Response<Full<Bytes>> {
    let (mut parts, _) = put.into_parts();
    let etag = parts.headers.get(header::ETAG).and_then(|v| v.to_str().ok()).unwrap_or("").to_owned();
    let location = location.map(|bucket_url| format!("{bucket_url}/{}", utf8_percent_encode(key, KEY_ESCAPES)));
    let redirect = field(fields, "success_action_redirect")
        .or(field(fields, "redirect"))
        .and_then(|url| redirect_to(url, bucket, key, &etag));
    let (status, body) = match (redirect, field(fields, "success_action_status")) {
        (Some(url), _) => {
            parts.headers.insert(header::LOCATION, url);
            parts.status = StatusCode::SEE_OTHER;
            return Response::from_parts(parts, Full::new(Bytes::new()));
        }
        (None, Some("200")) => (StatusCode::OK, Bytes::new()),
        (None, Some("201")) => {
            let body = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<PostResponse><Location>{}</Location>\
                 <Bucket>{}</Bucket><Key>{}</Key><ETag>{}</ETag></PostResponse>",
                xml_escape(location.as_deref().unwrap_or("")),
                xml_escape(bucket),
                xml_escape(key),
                xml_escape(&etag),
            );
            parts.headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/xml"));
            (StatusCode::CREATED, Bytes::from(body))
        }
        (None, _) => (StatusCode::NO_CONTENT, Bytes::new()),
    };
    if let Some(value) = location.and_then(|l| HeaderValue::from_str(&l).ok()) {
        parts.headers.insert(header::LOCATION, value);
    }
    parts.status = status;
    Response::from_parts(parts, Full::new(body))
}

/// The URL a successful upload redirects to: `url`, with the object's
/// bucket, key and ETag added to its query; `None` if `url` isn't an
/// absolute http(s) URL, which S3 then acts as if it weren't there.
fn redirect_to(url: &str, bucket: &str, key: &str, etag: &str) -> Option<HeaderValue> {
    let uri: hyper::Uri = url.parse().ok()?;
    if !matches!(uri.scheme_str(), Some("http" | "https")) || uri.authority().is_none() {
        return None;
    }
    let separator = match uri.query() {
        None => "?",
        Some("") => "",
        Some(_) => "&",
    };
    let escape = |s| utf8_percent_encode(s, QUERY_ESCAPES);
    let url = format!("{url}{separator}bucket={}&key={}&etag={}", escape(bucket), escape(key), escape(etag));
    HeaderValue::from_str(&url).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirects() {
        let to = |url| redirect_to(url, "b", "a b/c", "\"e\"").map(|v| v.to_str().unwrap().to_owned());
        assert_eq!(to("https://example.com/done").unwrap(), "https://example.com/done?bucket=b&key=a%20b%2Fc&etag=%22e%22");
        assert_eq!(to("http://example.com/done?x=1").unwrap(), "http://example.com/done?x=1&bucket=b&key=a%20b%2Fc&etag=%22e%22");
        assert_eq!(to("http://example.com/?").unwrap(), "http://example.com/?bucket=b&key=a%20b%2Fc&etag=%22e%22");
        for bad in ["", "/done", "example.com/done", "ftp://example.com/", "http://exa mple.com/"] {
            assert_eq!(to(bad), None, "{bad}");
        }
    }

    #[test]
    fn turns_fields_into_headers() {
        let fields: Fields = [
            ("acl", "bucket-owner-full-control"),
            ("x-amz-acl", "public-read"),
            ("content-type", "image/png"),
            ("x-amz-meta-a", "b"),
            ("x-amz-checksum-algorithm", "CRC32"),
            ("x-amz-checksum-crc32", "AAAAAA=="),
            ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
            ("x-amz-decoded-content-length", "5"),
            ("x-amz-trailer", "x-amz-checksum-crc32"),
            ("content-length", "5"),
            ("key", "k"),
        ]
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect();
        let headers = headers(&fields).unwrap();
        let mut names: Vec<_> = headers.iter().map(|(n, v)| format!("{n}: {}", v.to_str().unwrap())).collect();
        names.sort();
        assert_eq!(
            names,
            [
                "content-type: image/png",
                "x-amz-acl: bucket-owner-full-control",
                "x-amz-checksum-crc32: AAAAAA==",
                "x-amz-meta-a: b",
                "x-amz-sdk-checksum-algorithm: CRC32",
            ]
        );
    }
}
