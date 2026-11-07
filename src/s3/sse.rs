//! Server-side encryption: how a stored object (or an upload) is encrypted, as
//! the catalog records it, and SSE-KMS's requests. SSE-C's are in `sse_c`.
//!
//! Every encrypted object's parts are in `encryption`'s format, under one key:
//!
//! - SSE-C: the client's own, which the object keeps only a check of;
//! - SSE-KMS: an object key of its own, random, which the object keeps sealed
//!   (XChaCha20-Poly1305) under a data key from the KMS (see `kms`). The data
//!   key is kept as its KMS ciphertext, which only the KMS can open, and only
//!   with the same associated data: the encryption context the client gave
//!   (if any), with `"aws:s3:arn": "arn:aws:s3:::<bucket>/<key>"` added
//!   (unless the client gave that entry itself), as canonical JSON. So a
//!   data key only opens for an object of the name it was made for. The KMS
//!   is asked as the role that made the request, so it decides which roles
//!   may use which keys (see `kms`); a request of no role (the dashboard's)
//!   may use none.
//!
//! The two levels are MinIO's, and let a copy share its source's parts under
//! another KMS key, or context: it takes a data key of its own, and seals the
//! same object key under it. That doesn't re-key the data: anyone who could
//! open the source's data key can read the copy's parts. Nor does SSE-C ever
//! share parts across keys, since that's what a client changing its key
//! wants to stop.

use std::collections::BTreeMap;

use anyhow::Context as _;
use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305, XNonce, aead::Tag};
use http_body_util::Full;
use hyper::{HeaderMap, Response, StatusCode, body::Bytes, http::response::Builder};
use tokio_postgres::Row;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    App,
    encryption::Key,
    kms::{KeyId, KmsError},
    s3::sse_c::CustomerKey,
    s3::util::format_s3_error,
};

/// The header naming a write's server-side encryption: `aws:kms` for SSE-KMS
/// (`AES256`, SSE-S3, isn't supported).
pub const ENCRYPTION: &str = "x-amz-server-side-encryption";
pub const KMS_KEY_ID: &str = "x-amz-server-side-encryption-aws-kms-key-id";
pub const KMS_CONTEXT: &str = "x-amz-server-side-encryption-context";
pub const BUCKET_KEY_ENABLED: &str = "x-amz-server-side-encryption-bucket-key-enabled";

/// SSE-KMS's value of `x-amz-server-side-encryption`.
pub const AWS_KMS: &str = "aws:kms";
/// What key IDs are reported with, and may be given with.
const ARN_PREFIX: &str = "arn:aws:kms:";

/// The associated data an object key is sealed with, under its data key.
const SEALED_KEY_AD: &[u8] = b"cairn sse-kms object key v1";
const NONCE_LEN: usize = 24;
/// Bytes of a sealed object key: nonce, ciphertext, tag.
pub const SEALED_LEN: usize = NONCE_LEN + 32 + 16;

/// How a stored object (or upload) is encrypted.
#[derive(Clone, Debug, PartialEq)]
pub enum Stored {
    Plain,
    /// SSE-C: a check of the client's key (see `sse_c`).
    Customer { check: Vec<u8> },
    Kms(Envelope),
}

/// An SSE-KMS object's key, as it's stored.
#[derive(Clone, Debug, PartialEq)]
pub struct Envelope {
    /// The KMS key (as `KeyId::as_string` has it; a bare name, from before
    /// key IDs named their mount, is in the mount `transit`).
    pub key_id: String,
    /// The data key, as the KMS's ciphertext.
    pub data_key: String,
    /// The object key, sealed under the data key.
    pub sealed: Vec<u8>,
    /// The client's encryption context, as canonical JSON.
    pub context: Option<String>,
}

/// A stored encryption's catalog columns (`sse_c_key, sse_kms_key_id,
/// sse_kms_data_key, sse_kms_sealed, sse_kms_context`), to pass as parameters.
pub struct Columns<'a> {
    pub sse_c_key: Option<&'a [u8]>,
    pub kms_key_id: Option<&'a str>,
    pub kms_data_key: Option<&'a str>,
    pub kms_sealed: Option<&'a [u8]>,
    pub kms_context: Option<&'a str>,
}

impl Stored {
    /// From a row's five catalog columns (as `Columns` lists them), from
    /// `first` on.
    pub fn from_row(row: &Row, first: usize) -> Stored {
        let check: Option<Vec<u8>> = row.get(first);
        let key_id: Option<String> = row.get(first + 1);
        match (check, key_id) {
            (Some(check), _) => Stored::Customer { check },
            (None, Some(key_id)) => Stored::Kms(Envelope {
                key_id,
                data_key: row.get(first + 2),
                sealed: row.get(first + 3),
                context: row.get(first + 4),
            }),
            (None, None) => Stored::Plain,
        }
    }

    pub fn columns(&self) -> Columns<'_> {
        let mut columns = Columns {
            sse_c_key: None,
            kms_key_id: None,
            kms_data_key: None,
            kms_sealed: None,
            kms_context: None,
        };
        match self {
            Stored::Plain => {}
            Stored::Customer { check } => columns.sse_c_key = Some(check),
            Stored::Kms(envelope) => {
                columns.kms_key_id = Some(&envelope.key_id);
                columns.kms_data_key = Some(&envelope.data_key);
                columns.kms_sealed = Some(&envelope.sealed);
                columns.kms_context = envelope.context.as_deref();
            }
        }
        columns
    }

    pub fn is_plain(&self) -> bool {
        matches!(self, Stored::Plain)
    }
}

/// What a new object (or upload) is to be encrypted with, and how that's
/// stored with it.
pub(crate) struct Sealing {
    pub key: Zeroizing<Key>,
    pub stored: Stored,
}

/// What an SSE-KMS write asks for.
#[derive(Clone, Debug, PartialEq)]
pub struct KmsRequest {
    /// The KMS key it names, if it names one (else the default key).
    pub key_id: Option<KeyId>,
    /// Its encryption context, if it gave one.
    pub context: Option<BTreeMap<String, String>>,
}

/// How a write asks for its object to be encrypted.
#[derive(Clone, Copy, Default)]
pub enum Wanted<'a> {
    #[default]
    Plain,
    Customer(&'a CustomerKey),
    Kms(&'a KmsRequest),
}

impl<'a> Wanted<'a> {
    /// From a write's SSE-C key and SSE-KMS request (which `mod.rs` made sure
    /// aren't both there).
    pub fn new(customer: Option<&'a CustomerKey>, kms: Option<&'a KmsRequest>) -> Wanted<'a> {
        match (customer, kms) {
            (Some(key), _) => Wanted::Customer(key),
            (None, Some(request)) => Wanted::Kms(request),
            (None, None) => Wanted::Plain,
        }
    }
}

impl<'a> Wanted<'a> {
    /// The SSE-C key, if that's what it is.
    pub fn customer(self) -> Option<&'a CustomerKey> {
        match self {
            Wanted::Customer(key) => Some(key),
            _ => None,
        }
    }
}

fn bad_request(code: &str, message: &str) -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::BAD_REQUEST, code, message)
}

/// Whether the request has any of SSE-S3's and SSE-KMS's headers (MinIO's
/// test: the key ID or context, or `x-amz-server-side-encryption`).
fn names_server_keys(headers: &HeaderMap) -> bool {
    headers.contains_key(ENCRYPTION) || headers.contains_key(KMS_KEY_ID) || headers.contains_key(KMS_CONTEXT)
}

/// The SSE-KMS a write (PutObject, CopyObject, CreateMultipartUpload) asks
/// for, if any, or why it's refused. `customer` is whether it has SSE-C
/// headers too, and `kms` whether there's a KMS.
pub fn requested_kms(
    headers: &HeaderMap,
    customer: bool,
    kms: bool,
) -> Result<Option<KmsRequest>, Response<Full<Bytes>>> {
    if !names_server_keys(headers) {
        return Ok(None);
    }
    let get = |name| headers.get(name).map(|v| v.to_str().unwrap_or("\u{0}"));
    let algorithm = get(ENCRYPTION);
    if algorithm.is_some_and(|a| a.eq_ignore_ascii_case("AES256")) && get(KMS_KEY_ID).is_none() && get(KMS_CONTEXT).is_none() {
        return Err(format_s3_error(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "Cairn has no SSE-S3; it encrypts with keys from its KMS (SSE-KMS) or its clients' (SSE-C)",
        ));
    }
    if customer {
        return Err(bad_request(
            "InvalidArgument",
            "Server Side Encryption with Customer provided key is incompatible with the encryption method specified",
        ));
    }
    if algorithm != Some(AWS_KMS) {
        return Err(bad_request(
            "InvalidArgument",
            "Server Side Encryption with AWS KMS managed key requires HTTP header x-amz-server-side-encryption : aws:kms",
        ));
    }
    if !kms {
        return Err(format_s3_error(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "Server side encryption specified but KMS is not configured",
        ));
    }
    let key_id = match get(KMS_KEY_ID) {
        None => None,
        Some(id) => {
            let id = id.strip_prefix(ARN_PREFIX).unwrap_or(id);
            let Some(id) = KeyId::parse(id) else {
                return Err(bad_request(
                    "InvalidRequest",
                    "The specified KMS KeyID contains unsupported characters",
                ));
            };
            Some(id)
        }
    };
    let context = match get(KMS_CONTEXT) {
        None => None,
        Some(b64) => {
            let parsed = STANDARD
                .decode(b64.trim())
                .ok()
                .and_then(|json| serde_json::from_slice::<BTreeMap<String, String>>(&json).ok());
            let Some(context) = parsed else {
                return Err(bad_request(
                    "InvalidArgument",
                    "The encryption context must be base64-encoded JSON of string keys and values.",
                ));
            };
            Some(context)
        }
    };
    match get(BUCKET_KEY_ENABLED) {
        // Accepted and ignored, as MinIO does: every object has keys of its own.
        None => {}
        Some(v) if v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("false") => {}
        Some(_) => {
            return Err(bad_request(
                "InvalidArgument",
                "x-amz-server-side-encryption-bucket-key-enabled must be true or false",
            ));
        }
    }
    Ok(Some(KmsRequest { key_id, context }))
}

/// A 400 for a read (GET, HEAD) with SSE-S3's or SSE-KMS's headers, as MinIO
/// refuses it: they apply to writes only.
pub fn refuse_on_read(headers: &HeaderMap) -> Option<Response<Full<Bytes>>> {
    names_server_keys(headers).then(|| {
        bad_request("BadRequest", "x-amz-server-side-encryption applies to writes, not reads")
    })
}

/// A 501 for the writes that take no SSE-S3 or SSE-KMS headers (UploadPart,
/// UploadPartCopy, CompleteMultipartUpload and the like), as MinIO refuses
/// them: an upload's encryption is its CreateMultipartUpload's.
pub fn refuse_on_other_writes(headers: &HeaderMap) -> Option<Response<Full<Bytes>>> {
    names_server_keys(headers).then(|| {
        format_s3_error(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "x-amz-server-side-encryption applies to PutObject, CopyObject and CreateMultipartUpload only",
        )
    })
}

/// Whether a stored object may be read with the SSE-C key `given` (if any),
/// or why not.
pub fn check(stored: &Stored, given: Option<&CustomerKey>) -> Result<(), Response<Full<Bytes>>> {
    match stored {
        Stored::Plain => crate::s3::sse_c::check_read(None, given),
        Stored::Customer { check } => crate::s3::sse_c::check_read(Some(check), given),
        Stored::Kms(_) if given.is_some() => Err(bad_request(
            "InvalidRequest",
            "The object was stored using a form of Server Side Encryption. The correct parameters must be provided to retrieve the object.",
        )),
        Stored::Kms(_) => Ok(()),
    }
}

/// The key a stored object at `bucket`/`key` (`check`ed already) is encrypted
/// with, if it is, or why it can't be had. Asks the KMS for an SSE-KMS one,
/// as the role `role` (see `kms`).
pub async fn open(
    app: &App,
    stored: &Stored,
    given: Option<&CustomerKey>,
    role: Option<Uuid>,
    bucket: &str,
    key: &str,
) -> anyhow::Result<Result<Option<Zeroizing<Key>>, Response<Full<Bytes>>>> {
    match stored {
        Stored::Plain => Ok(Ok(None)),
        Stored::Customer { .. } => {
            let given = given.expect("an SSE-C object is read with its key (`check`)");
            Ok(Ok(Some(Zeroizing::new(*given.key()))))
        }
        Stored::Kms(envelope) => Ok(open_envelope(app, envelope, role, bucket, key).await?.map(Some)),
    }
}

/// The object key `envelope` (of the object at `bucket`/`key`) holds.
async fn open_envelope(
    app: &App,
    envelope: &Envelope,
    role: Option<Uuid>,
    bucket: &str,
    key: &str,
) -> anyhow::Result<Result<Zeroizing<Key>, Response<Full<Bytes>>>> {
    let Some(kms) = &app.kms else {
        return Ok(Err(format_s3_error(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "the object is encrypted with a key from a KMS, but no KMS is configured",
        )));
    };
    let Some(role) = role else {
        return Ok(Err(no_role()));
    };
    let key_id = envelope.key_id()?;
    let ad = associated_data(envelope.context.as_deref(), bucket, key);
    let data_key = match kms.decrypt(role, &key_id, &envelope.data_key, &ad).await {
        Ok(data_key) => data_key,
        Err(e) => return kms_refusal(e, &key_id, role).map(Err),
    };
    match unseal_object_key(&data_key, &envelope.sealed) {
        Some(object_key) => Ok(Ok(object_key)),
        None => anyhow::bail!("the sealed key of {bucket}/{key} doesn't open under its data key"),
    }
}

/// What to encrypt a new object (or upload) at `bucket`/`key` with, as
/// `wanted`, and how to store it; `None` for a plain one. Asks the KMS for a
/// data key for an SSE-KMS one.
pub async fn seal(
    app: &App,
    wanted: Wanted<'_>,
    role: Option<Uuid>,
    bucket: &str,
    key: &str,
) -> anyhow::Result<Result<Option<Sealing>, Response<Full<Bytes>>>> {
    match wanted {
        Wanted::Plain => Ok(Ok(None)),
        Wanted::Customer(customer) => Ok(Ok(Some(Sealing {
            key: Zeroizing::new(*customer.key()),
            stored: Stored::Customer { check: customer.new_check() },
        }))),
        Wanted::Kms(request) => {
            let mut object_key = Zeroizing::new([0; 32]);
            getrandom::fill(object_key.as_mut_slice()).expect("the OS random number generator failed");
            Ok(reseal(app, &object_key, request, role, bucket, key)
                .await?
                .map(|envelope| Some(Sealing { key: object_key, stored: Stored::Kms(envelope) })))
        }
    }
}

/// Seals `object_key` under a new data key, as `request` asks, for the object
/// at `bucket`/`key`: for a new SSE-KMS object, or a copy that shares another
/// one's parts. Asks the KMS as the role `role` (see `kms`).
pub async fn reseal(
    app: &App,
    object_key: &Key,
    request: &KmsRequest,
    role: Option<Uuid>,
    bucket: &str,
    key: &str,
) -> anyhow::Result<Result<Envelope, Response<Full<Bytes>>>> {
    let kms = app.kms.as_ref().expect("an SSE-KMS request is refused without a KMS (`requested_kms`)");
    let Some(role) = role else {
        return Ok(Err(no_role()));
    };
    let key_id = request.key_id.as_ref().unwrap_or(kms.default_key());
    let context = request.context.as_ref().map(|c| serde_json::to_string(c).unwrap());
    let ad = associated_data(context.as_deref(), bucket, key);
    let data_key = match kms.generate(role, key_id, &ad).await {
        Ok(data_key) => data_key,
        Err(e) => return kms_refusal(e, key_id, role).map(Err),
    };
    Ok(Ok(Envelope {
        key_id: key_id.as_string(),
        data_key: data_key.ciphertext,
        sealed: seal_object_key(&data_key.plaintext, object_key),
        context,
    }))
}

impl Envelope {
    /// Its KMS key.
    fn key_id(&self) -> anyhow::Result<KeyId> {
        KeyId::parse(&self.key_id).with_context(|| format!("the stored KMS key ID {:?} isn't one", self.key_id))
    }
}

/// The 403 for a request that would need a KMS key without a role to ask
/// the KMS for it as: the dashboard's. The KMS decides which roles may use
/// a key, so a request of none may use none.
fn no_role() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::FORBIDDEN,
        "AccessDenied",
        "Only an S3 role may use a KMS key, as the KMS allows it.",
    )
}

/// The response to a request the KMS refused the role `role`, or the error,
/// which is a 500.
fn kms_refusal(e: KmsError, key_id: &KeyId, role: Uuid) -> anyhow::Result<Response<Full<Bytes>>> {
    let key_id = key_id.as_string();
    match e {
        KmsError::NoSuchKey => Ok(bad_request("KMS.NotFoundException", "Invalid keyId")),
        KmsError::Denied => Ok(format_s3_error(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "The KMS doesn't allow this role the use of the key.",
        )),
        KmsError::Unavailable(e) => {
            eprintln!("the KMS is unavailable: {e:#}");
            Ok(format_s3_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                "the KMS is unavailable; please try again later",
            ))
        }
        e @ KmsError::Failed(_) => {
            Err(anyhow::Error::new(e).context(format!("KMS key {key_id:?}, as role {role}")))
        }
    }
}

/// The associated data an object's data key is bound to: its client's
/// context (canonical JSON, if any), and the object's ARN.
fn associated_data(context: Option<&str>, bucket: &str, key: &str) -> Vec<u8> {
    let mut map: BTreeMap<String, String> = context
        .map(|c| serde_json::from_str(c).expect("a stored context is a JSON object of strings"))
        .unwrap_or_default();
    map.entry("aws:s3:arn".to_owned())
        .or_insert_with(|| format!("arn:aws:s3:::{bucket}/{key}"));
    serde_json::to_vec(&map).unwrap()
}

fn seal_object_key(data_key: &Key, object_key: &Key) -> Vec<u8> {
    let mut nonce = [0; NONCE_LEN];
    getrandom::fill(&mut nonce).expect("the OS random number generator failed");
    let mut sealed = Vec::with_capacity(SEALED_LEN);
    sealed.extend_from_slice(&nonce);
    let mut buffer = *object_key;
    let tag = XChaCha20Poly1305::new(data_key.into())
        .encrypt_inout_detached(&XNonce::from(nonce), SEALED_KEY_AD, buffer.as_mut_slice().into())
        .expect("a key is far shorter than XChaCha20-Poly1305's limit");
    sealed.extend_from_slice(&buffer);
    sealed.extend_from_slice(&tag);
    sealed
}

fn unseal_object_key(data_key: &Key, sealed: &[u8]) -> Option<Zeroizing<Key>> {
    if sealed.len() != SEALED_LEN {
        return None;
    }
    let (nonce, rest) = sealed.split_at(NONCE_LEN);
    let (ciphertext, tag) = rest.split_at(32);
    let nonce = XNonce::try_from(nonce).ok()?;
    let tag = Tag::<XChaCha20Poly1305>::try_from(tag).ok()?;
    let mut key = Zeroizing::new(Key::try_from(ciphertext).ok()?);
    XChaCha20Poly1305::new(data_key.into())
        .decrypt_inout_detached(&nonce, SEALED_KEY_AD, key.as_mut_slice().into(), &tag)
        .ok()?;
    Some(key)
}

/// The headers S3 answers about a stored object's encryption with: SSE-C's
/// (the algorithm and the key's MD5, `given` being the key) or SSE-KMS's (the
/// algorithm, the key's ARN, and the context, if there's one).
pub fn echo(builder: Builder, stored: &Stored, given: Option<&CustomerKey>) -> Builder {
    match stored {
        Stored::Plain => builder,
        Stored::Customer { .. } => match given {
            Some(key) => key.echo(builder),
            None => builder,
        },
        Stored::Kms(envelope) => {
            let builder = builder
                .header(ENCRYPTION, AWS_KMS)
                .header(KMS_KEY_ID, format!("{ARN_PREFIX}{}", envelope.key_id().map_or(envelope.key_id.clone(), |id| id.as_string())));
            match &envelope.context {
                Some(context) => builder.header(KMS_CONTEXT, STANDARD.encode(context)),
                None => builder,
            }
        }
    }
}

/// `echo`'s headers, onto a response that's already built.
pub fn echo_onto<B>(response: Response<B>, stored: &Stored, given: Option<&CustomerKey>) -> Response<B> {
    let (mut parts, body) = response.into_parts();
    let mut builder = Response::builder();
    *builder.headers_mut().unwrap() = std::mem::take(&mut parts.headers);
    let echoed = echo(builder, stored, given).body(()).unwrap();
    parts.headers = echoed.into_parts().0.headers;
    Response::from_parts(parts, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderName;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(HeaderName::from_bytes(name.as_bytes()).unwrap(), value.parse().unwrap());
        }
        map
    }

    fn status(result: Result<Option<KmsRequest>, Response<Full<Bytes>>>) -> u16 {
        result.err().map(|r| r.status().as_u16()).unwrap_or(200)
    }

    #[test]
    fn parses_kms_requests() {
        assert_eq!(requested_kms(&HeaderMap::new(), false, true).unwrap(), None);
        assert_eq!(
            requested_kms(&headers(&[(ENCRYPTION, "aws:kms")]), false, true).unwrap(),
            Some(KmsRequest { key_id: None, context: None })
        );
        let context = STANDARD.encode(r#"{"b":"2","a":"1"}"#);
        let request = requested_kms(
            &headers(&[
                (ENCRYPTION, "aws:kms"),
                (KMS_KEY_ID, "arn:aws:kms:my-key"),
                (KMS_CONTEXT, &context),
                (BUCKET_KEY_ENABLED, "true"),
            ]),
            false,
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(request.key_id.unwrap().as_string(), "transit/my-key");
        let context = request.context.unwrap();
        assert_eq!(serde_json::to_string(&context).unwrap(), r#"{"a":"1","b":"2"}"#);
    }

    #[test]
    fn refuses_bad_kms_requests() {
        let kms = |pairs: &[(&str, &str)]| headers(&[&[(ENCRYPTION, "aws:kms")], pairs].concat());
        // SSE-S3.
        assert_eq!(status(requested_kms(&headers(&[(ENCRYPTION, "AES256")]), false, true)), 501);
        // No KMS.
        assert_eq!(status(requested_kms(&kms(&[]), false, false)), 501);
        // With SSE-C.
        assert_eq!(status(requested_kms(&kms(&[]), true, true)), 400);
        // A key ID without asking for SSE-KMS.
        assert_eq!(status(requested_kms(&headers(&[(KMS_KEY_ID, "k")]), false, true)), 400);
        assert_eq!(status(requested_kms(&headers(&[(ENCRYPTION, "aws:kms:dsse")]), false, true)), 400);
        for id in [" k", "k ", "../k", "a//b", "a/../b", ""] {
            assert_eq!(status(requested_kms(&kms(&[(KMS_KEY_ID, id)]), false, true)), 400, "{id:?}");
        }
        for context in ["not base64!", &STANDARD.encode("[1]"), &STANDARD.encode(r#"{"a":1}"#)] {
            assert_eq!(status(requested_kms(&kms(&[(KMS_CONTEXT, context)]), false, true)), 400);
        }
        assert_eq!(status(requested_kms(&kms(&[(BUCKET_KEY_ENABLED, "yes")]), false, true)), 400);
    }

    #[test]
    fn object_keys_seal_and_open() {
        let (data_key, object_key) = ([7; 32], [9; 32]);
        let sealed = seal_object_key(&data_key, &object_key);
        assert_eq!(sealed.len(), SEALED_LEN);
        assert_ne!(sealed, seal_object_key(&data_key, &object_key));
        assert_eq!(*unseal_object_key(&data_key, &sealed).unwrap(), object_key);
        assert!(unseal_object_key(&[8; 32], &sealed).is_none());
        for i in 0..SEALED_LEN {
            let mut flipped = sealed.clone();
            flipped[i] ^= 1;
            assert!(unseal_object_key(&data_key, &flipped).is_none());
        }
        assert!(unseal_object_key(&data_key, &sealed[1..]).is_none());
    }

    #[test]
    fn associated_data_names_the_object() {
        let ad = |context, key| String::from_utf8(associated_data(context, "b", key)).unwrap();
        assert_eq!(ad(None, "k"), r#"{"aws:s3:arn":"arn:aws:s3:::b/k"}"#);
        assert_eq!(ad(Some(r#"{"z":"1","a":"2"}"#), "k"), r#"{"a":"2","aws:s3:arn":"arn:aws:s3:::b/k","z":"1"}"#);
        // The client's own entry stands.
        assert_eq!(ad(Some(r#"{"aws:s3:arn":"x"}"#), "k"), r#"{"aws:s3:arn":"x"}"#);
        assert_ne!(ad(None, "k"), ad(None, "k2"));
    }

    #[test]
    fn columns_round_trip_the_kinds() {
        let envelope = Envelope {
            key_id: "k".into(),
            data_key: "vault:v1:x".into(),
            sealed: vec![0; SEALED_LEN],
            context: Some("{}".into()),
        };
        let stored = Stored::Kms(envelope);
        let columns = stored.columns();
        assert!(columns.sse_c_key.is_none());
        assert_eq!(columns.kms_key_id, Some("k"));
        assert_eq!(columns.kms_context, Some("{}"));
        let stored = Stored::Customer { check: vec![1; 48] };
        let columns = stored.columns();
        assert!(columns.sse_c_key.is_some() && columns.kms_key_id.is_none());
    }
}
