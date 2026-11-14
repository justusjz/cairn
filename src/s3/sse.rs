//! Server-side encryption: how a stored object (or an upload) is encrypted, as
//! the catalog records it, and SSE-KMS's requests. SSE-C's are in `sse_c`.
//!
//! Every encrypted object's parts are in `encryption`'s format, under an
//! object key of its own, random, which the object keeps sealed under
//! another key (XChaCha20-Poly1305), as MinIO does for all three:
//!
//! - SSE-C: under the client's key, with the object's name as associated
//!   data (see `sse_c`). The client's key is never stored: a wrong one fails
//!   to open the object key;
//! - SSE-KMS: under a data key from the KMS (see `kms`). The data key is kept as its KMS ciphertext, which only the KMS can open, and only
//!   with the same associated data: the encryption context the client gave
//!   (if any), with `"aws:s3:arn": "arn:aws:s3:::<bucket>/<key>"` added, as
//!   canonical JSON. So a data key only opens for an object of the name it
//!   was made for. A client may name that entry itself, but only as the
//!   object's own ARN, as S3 has it (see `for_object`). The KMS
//!   is asked as the user that made the request, so it decides which users
//!   may use which keys (see `kms`); a request of no role (an account's root's,
//!   in the console) may use none.
//!
//! - SSE-S3: the same, but with a data key Cairn has from its own SSE-S3 key,
//!   as itself (see `kms`), which it shares among the objects a node writes
//!   in an hour. So the KMS can't bind it to an object's name: the object key
//!   is sealed with the object's name as associated data instead.
//!
//! An SSE-S3 object's ETag is its content's MD5, as in S3, which would let
//! whoever holds the database test guesses at the content. So it's stored
//! sealed under the object key, as MinIO stores it (see `encryption`), and
//! opened where it's answered with (`plain_etag`). Postgres never compares ETags: conditional writes and
//! CompleteMultipartUpload decide in Cairn, and the catalog only checks that
//! what they decided on is still there (see `catalog.sql`).
//!
//! The two levels let a copy share its source's parts under another key (an
//! SSE-C one, a KMS key, a context): it seals the same object key under its
//! own, so changing an object's key (a copy onto itself) is a matter of its
//! catalog row. That doesn't re-key the data, which is the copy's anyway: the
//! source's old key opens nothing of it once the source is gone.

use std::collections::BTreeMap;

use anyhow::Context as _;
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::Full;
use hyper::{HeaderMap, Response, StatusCode, body::Bytes, http::response::Builder};
use tokio_postgres::Row;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    App,
    encryption::{self, Field, Key, Owner},
    kms::{Identity, KeyId, KmsError},
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
/// SSE-S3's, S3's name for it. Underneath, it's XChaCha20-Poly1305, as SSE-C.
pub const AES256: &str = "AES256";
/// What key IDs are reported with, and may be given with.
const ARN_PREFIX: &str = "arn:aws:kms:";

/// The associated data an SSE-KMS object key is sealed with, under its data
/// key (the KMS binds the data key to the object).
const SEALED_KEY_AD: &[u8] = b"cairn sse-kms object key v1";
/// The start of the associated data an SSE-S3 object key is sealed with,
/// before the object's name, `<bucket>/<key>` (a bucket's name has no `/`).
const SSE_S3_SEALED_KEY_AD: &[u8] = b"cairn sse-s3 object key v1\0";
/// The same, for an SSE-C object key, sealed under the client's key.
const SSE_C_SEALED_KEY_AD: &[u8] = b"cairn sse-c object key v1\0";
const NONCE_LEN: usize = 24;
/// Bytes of a sealed object key: nonce, ciphertext, tag.
pub const SEALED_LEN: usize = NONCE_LEN + 32 + 16;

/// How a stored object (or upload) is encrypted.
#[derive(Clone, Debug, PartialEq)]
pub enum Stored {
    Plain,
    /// SSE-C: the object key, sealed under the client's key (see `sse_c`).
    Customer { sealed: Vec<u8> },
    Kms(Envelope),
    /// SSE-S3: as SSE-KMS, but under Cairn's key, without a context.
    S3(Envelope),
}

/// An SSE-KMS (or SSE-S3) object's key, as it's stored.
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
/// sse_kms_data_key, sse_kms_sealed, sse_kms_context, sse_s3`), to pass as
/// parameters.
pub struct Columns<'a> {
    pub sse_c_key: Option<&'a [u8]>,
    pub kms_key_id: Option<&'a str>,
    pub kms_data_key: Option<&'a str>,
    pub kms_sealed: Option<&'a [u8]>,
    pub kms_context: Option<&'a str>,
    /// Whether the KMS columns are SSE-S3's.
    pub sse_s3: bool,
}

impl Stored {
    /// From a row's six catalog columns (as `Columns` lists them), from
    /// `first` on.
    pub fn from_row(row: &Row, first: usize) -> Stored {
        let sealed: Option<Vec<u8>> = row.get(first);
        let key_id: Option<String> = row.get(first + 1);
        match (sealed, key_id) {
            (Some(sealed), _) => Stored::Customer { sealed },
            (None, Some(key_id)) => {
                let envelope = Envelope {
                    key_id,
                    data_key: row.get(first + 2),
                    sealed: row.get(first + 3),
                    context: row.get(first + 4),
                };
                match row.get(first + 5) {
                    true => Stored::S3(envelope),
                    false => Stored::Kms(envelope),
                }
            }
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
            sse_s3: false,
        };
        match self {
            Stored::Plain => {}
            Stored::Customer { sealed } => columns.sse_c_key = Some(sealed),
            Stored::Kms(envelope) | Stored::S3(envelope) => {
                columns.kms_key_id = Some(&envelope.key_id);
                columns.kms_data_key = Some(&envelope.data_key);
                columns.kms_sealed = Some(&envelope.sealed);
                columns.kms_context = envelope.context.as_deref();
                columns.sse_s3 = matches!(self, Stored::S3(_));
            }
        }
        columns
    }

    pub fn is_plain(&self) -> bool {
        matches!(self, Stored::Plain)
    }
}

/// The ETag of an object encrypted as `stored`, at `bucket`/`key`, whose ETag
/// is stored as `etag`, as it's answered with: decrypted, if it's SSE-S3's;
/// as it is, otherwise.
pub async fn plain_etag(
    app: &App,
    stored: &Stored,
    etag: &str,
    bucket: &str,
    key: &str,
) -> anyhow::Result<Result<String, Response<Full<Bytes>>>> {
    let Stored::S3(envelope) = stored else { return Ok(Ok(etag.to_owned())) };
    let object_key = match open_s3(app, envelope, bucket, key).await? {
        Ok(object_key) => object_key,
        Err(refused) => return Ok(Err(refused)),
    };
    match encryption::open_value(&object_key, Field::Etag, Owner::Object { bucket, key }, etag) {
        Some(etag) => Ok(Ok(etag)),
        None => anyhow::bail!("the stored ETag of {bucket}/{key} doesn't open under its key"),
    }
}

/// The key an SSE-S3 object (or upload) seals its ETags under, its object
/// key, opened once for many: its parts', say.
pub struct EtagKey(Zeroizing<Key>);

impl EtagKey {
    /// The ETag `stored`, the `owner`'s, holds.
    pub fn open(&self, owner: Owner, stored: &str) -> anyhow::Result<String> {
        encryption::open_value(&self.0, Field::Etag, owner, stored)
            .ok_or_else(|| anyhow::anyhow!("a stored ETag of {owner:?} doesn't open under its key"))
    }

    /// `etag`, the `owner`'s, sealed to store.
    pub fn seal(&self, owner: Owner, etag: &str) -> String {
        encryption::seal_value(&self.0, Field::Etag, owner, etag)
    }
}

/// The key an object (or upload) encrypted as `stored`, at `bucket`/`key`,
/// seals its ETags under: `None` unless it's SSE-S3, whose are.
pub async fn etag_key(
    app: &App,
    stored: &Stored,
    bucket: &str,
    key: &str,
) -> anyhow::Result<Result<Option<EtagKey>, Response<Full<Bytes>>>> {
    let Stored::S3(envelope) = stored else { return Ok(Ok(None)) };
    Ok(open_s3(app, envelope, bucket, key).await?.map(|object_key| Some(EtagKey(object_key))))
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
    /// The KMS key it names.
    pub key_id: KeyId,
    /// Its encryption context, if it gave one.
    pub context: Option<BTreeMap<String, String>>,
}

/// The encryption with keys of Cairn's KMS a write asks for: SSE-KMS (under a
/// key of the KMS), or SSE-S3 (`AES256`, under Cairn's own).
#[derive(Clone, Debug, PartialEq)]
pub enum ServerSide {
    Kms(KmsRequest),
    S3,
}

/// How a write asks for its object to be encrypted.
#[derive(Clone, Copy, Default)]
pub enum Wanted<'a> {
    #[default]
    Plain,
    Customer(&'a CustomerKey),
    Kms(&'a KmsRequest),
    S3,
}

impl<'a> Wanted<'a> {
    /// From a write's SSE-C key and its SSE-KMS or SSE-S3 request (which
    /// `mod.rs` made sure aren't both there).
    pub fn new(customer: Option<&'a CustomerKey>, server: Option<&'a ServerSide>) -> Wanted<'a> {
        match (customer, server) {
            (Some(key), _) => Wanted::Customer(key),
            (None, Some(ServerSide::Kms(request))) => Wanted::Kms(request),
            (None, Some(ServerSide::S3)) => Wanted::S3,
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

/// The SSE-KMS or SSE-S3 a write (PutObject, CopyObject,
/// CreateMultipartUpload) asks for, if any, or why it's refused. `customer`
/// is whether it has SSE-C headers too, `kms` whether there's a KMS, and
/// `sse_s3` whether it has a key for SSE-S3.
pub fn requested(
    headers: &HeaderMap,
    customer: bool,
    kms: bool,
    sse_s3: bool,
) -> Result<Option<ServerSide>, Response<Full<Bytes>>> {
    if !names_server_keys(headers) {
        return Ok(None);
    }
    let get = |name| headers.get(name).map(|v| v.to_str().unwrap_or("\u{0}"));
    let algorithm = get(ENCRYPTION);
    if algorithm == Some(AES256) && get(KMS_KEY_ID).is_none() && get(KMS_CONTEXT).is_none() {
        if customer {
            return Err(bad_request(
                "InvalidArgument",
                "Server Side Encryption with Customer provided key is incompatible with the encryption method specified",
            ));
        }
        if !kms || !sse_s3 {
            return Err(format_s3_error(
                StatusCode::NOT_IMPLEMENTED,
                "NotImplemented",
                "Server side encryption specified but KMS is not configured (for SSE-S3, with a key of Cairn's own)",
            ));
        }
        return Ok(Some(ServerSide::S3));
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
    // Cairn has no key every role may use: S3's is the account's `aws/s3`.
    // (A bucket's default key may come.)
    let Some(key_id) = get(KMS_KEY_ID) else {
        return Err(bad_request(
            "InvalidArgument",
            "Cairn has no default KMS key: name one with x-amz-server-side-encryption-aws-kms-key-id",
        ));
    };
    let key_id = key_id.strip_prefix(ARN_PREFIX).unwrap_or(key_id);
    let Some(key_id) = KeyId::parse(key_id) else {
        return Err(bad_request(
            "InvalidRequest",
            "The specified KMS KeyID contains unsupported characters",
        ));
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
    Ok(Some(ServerSide::Kms(KmsRequest { key_id, context })))
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

/// Whether a stored object, at `bucket`/`key`, may be read with the SSE-C key
/// `given` (if any), or why not: an SSE-C one only with the key its object
/// key opens under.
pub fn check(stored: &Stored, given: Option<&CustomerKey>, bucket: &str, key: &str) -> Result<(), Response<Full<Bytes>>> {
    match stored {
        Stored::Plain => crate::s3::sse_c::check_read(false, given.map(|_| false)),
        Stored::Customer { sealed } => {
            let opens = given.map(|given| open_customer(given, sealed, bucket, key).is_some());
            crate::s3::sse_c::check_read(true, opens)
        }
        Stored::Kms(_) | Stored::S3(_) if given.is_some() => Err(bad_request(
            "InvalidRequest",
            "The object was stored using a form of Server Side Encryption. The correct parameters must be provided to retrieve the object.",
        )),
        Stored::Kms(_) | Stored::S3(_) => Ok(()),
    }
}

/// The key a stored object at `bucket`/`key` (`check`ed already) is encrypted
/// with, if it is, or why it can't be had. Asks the KMS for an SSE-KMS one,
/// as the role `role` (see `kms`), and for an SSE-S3 one as Cairn, unless the
/// node has its data key already.
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
        Stored::Customer { sealed } => {
            let given = given.expect("an SSE-C object is read with its key (`check`)");
            match open_customer(given, sealed, bucket, key) {
                Some(object_key) => Ok(Ok(Some(object_key))),
                None => anyhow::bail!("the sealed key of {bucket}/{key} doesn't open under the key it was `check`ed with"),
            }
        }
        Stored::Kms(envelope) => Ok(open_envelope(app, envelope, role, bucket, key).await?.map(Some)),
        Stored::S3(envelope) => Ok(open_s3(app, envelope, bucket, key).await?.map(Some)),
    }
}

/// The object key the SSE-S3 `envelope` (of the object at `bucket`/`key`)
/// holds.
async fn open_s3(
    app: &App,
    envelope: &Envelope,
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
    let key_id = envelope.key_id()?;
    let data_key = match kms.sse_s3_open(&key_id, &envelope.data_key).await {
        Ok(data_key) => data_key,
        Err(e) => return sse_s3_refusal(e, &key_id).map(Err),
    };
    match unseal_object_key(&data_key, &envelope.sealed, &sse_s3_sealed_ad(bucket, key)) {
        Some(object_key) => Ok(Ok(object_key)),
        None => anyhow::bail!("the sealed key of {bucket}/{key} doesn't open under its data key"),
    }
}

/// The associated data an SSE-S3 object key is sealed with: the object's name.
fn sse_s3_sealed_ad(bucket: &str, key: &str) -> Vec<u8> {
    [SSE_S3_SEALED_KEY_AD, bucket.as_bytes(), b"/", key.as_bytes()].concat()
}

/// The associated data an SSE-C object key is sealed with: the object's name.
fn sse_c_sealed_ad(bucket: &str, key: &str) -> Vec<u8> {
    [SSE_C_SEALED_KEY_AD, bucket.as_bytes(), b"/", key.as_bytes()].concat()
}

/// `object_key` sealed under the client's key `customer`, for the object at
/// `bucket`/`key`: for a new SSE-C object, or a copy that shares another one's
/// parts (with another key, maybe: rotating it).
pub fn reseal_customer(customer: &CustomerKey, object_key: &Key, bucket: &str, key: &str) -> Stored {
    Stored::Customer { sealed: seal_object_key(customer.key(), object_key, &sse_c_sealed_ad(bucket, key)) }
}

/// A new SSE-C object's key, at `bucket`/`key`, and how it's stored: sealed
/// under the client's key `customer`.
pub(crate) fn seal_customer(customer: &CustomerKey, bucket: &str, key: &str) -> Sealing {
    let object_key = new_object_key();
    let stored = reseal_customer(customer, &object_key, bucket, key);
    Sealing { key: object_key, stored }
}

/// The object key `sealed` (an SSE-C object's, at `bucket`/`key`) holds, if
/// it opens under the client's key `customer`: whether that's its key.
fn open_customer(customer: &CustomerKey, sealed: &[u8], bucket: &str, key: &str) -> Option<Zeroizing<Key>> {
    unseal_object_key(customer.key(), sealed, &sse_c_sealed_ad(bucket, key))
}

/// Seals `object_key` under the node's SSE-S3 data key, for the object at
/// `bucket`/`key`: for a new SSE-S3 object, or a copy that shares another
/// one's parts.
pub async fn reseal_s3(
    app: &App,
    object_key: &Key,
    bucket: &str,
    key: &str,
) -> anyhow::Result<Result<Envelope, Response<Full<Bytes>>>> {
    let kms = app.kms.as_ref().expect("SSE-S3 is refused without a KMS (`requested`)");
    let key_id = kms.sse_s3_key().expect("SSE-S3 is refused without its key (`requested`)").clone();
    let (data_key, ciphertext) = match kms.sse_s3_data_key().await {
        Ok(data_key) => data_key,
        Err(e) => return sse_s3_refusal(e, &key_id).map(Err),
    };
    Ok(Ok(Envelope {
        key_id: key_id.as_string(),
        data_key: ciphertext,
        sealed: seal_object_key(&data_key, object_key, &sse_s3_sealed_ad(bucket, key)),
        context: None,
    }))
}

/// The response to a request the KMS refused Cairn's own SSE-S3 key, or the
/// error. Which isn't the client's doing: a KMS that can't be reached is a
/// 503, one that refuses Cairn the key (revoked, or deleted) a 500.
fn sse_s3_refusal(e: KmsError, key_id: &KeyId) -> anyhow::Result<Response<Full<Bytes>>> {
    match e {
        KmsError::Unavailable(_) | KmsError::LoginRefused(_) => {
            eprintln!("kms: SSE-S3: {e}");
            Ok(format_s3_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                "the KMS is unavailable; please try again later",
            ))
        }
        KmsError::NoSuchKey | KmsError::Denied | KmsError::Failed(_) => Err(anyhow::Error::new(e)
            .context(format!("SSE-S3's key {:?}, as Cairn", key_id.as_string()))),
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
    let data_key = match kms.decrypt(Identity::User(role), &key_id, &envelope.data_key, &ad).await {
        Ok(data_key) => data_key,
        Err(e) => return kms_refusal(e, &key_id, role).map(Err),
    };
    match unseal_object_key(&data_key, &envelope.sealed, SEALED_KEY_AD) {
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
        Wanted::Customer(customer) => Ok(Ok(Some(seal_customer(customer, bucket, key)))),
        Wanted::Kms(request) => {
            let object_key = new_object_key();
            Ok(reseal(app, &object_key, request, role, bucket, key)
                .await?
                .map(|envelope| Some(Sealing { key: object_key, stored: Stored::Kms(envelope) })))
        }
        Wanted::S3 => {
            let object_key = new_object_key();
            Ok(reseal_s3(app, &object_key, bucket, key)
                .await?
                .map(|envelope| Some(Sealing { key: object_key, stored: Stored::S3(envelope) })))
        }
    }
}

fn new_object_key() -> Zeroizing<Key> {
    let mut object_key = Zeroizing::new([0; 32]);
    getrandom::fill(object_key.as_mut_slice()).expect("the OS random number generator failed");
    object_key
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
    let key_id = &request.key_id;
    let context = request.context.as_ref().map(|c| serde_json::to_string(c).unwrap());
    let ad = associated_data(context.as_deref(), bucket, key);
    let data_key = match kms.generate(Identity::User(role), key_id, &ad).await {
        Ok(data_key) => data_key,
        Err(e) => return kms_refusal(e, key_id, role).map(Err),
    };
    Ok(Ok(Envelope {
        key_id: key_id.as_string(),
        data_key: data_key.ciphertext,
        sealed: seal_object_key(&data_key.plaintext, object_key, SEALED_KEY_AD),
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
/// the KMS for it as: an account's root's, in the console. The KMS decides which users may use
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
        KmsError::LoginRefused(why) => {
            eprintln!("the KMS refused Cairn's login as role {role}: {why}");
            Ok(format_s3_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                "the KMS is unavailable; please try again later",
            ))
        }
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
/// context (canonical JSON, if any), and the object's ARN, whatever the
/// context says it is.
fn associated_data(context: Option<&str>, bucket: &str, key: &str) -> Vec<u8> {
    let mut map: BTreeMap<String, String> = context
        .map(|c| serde_json::from_str(c).expect("a stored context is a JSON object of strings"))
        .unwrap_or_default();
    map.insert(ARN_KEY.to_owned(), object_arn(bucket, key));
    serde_json::to_vec(&map).unwrap()
}

/// The encryption context's entry S3 adds: the object's ARN.
const ARN_KEY: &str = "aws:s3:arn";

fn object_arn(bucket: &str, key: &str) -> String {
    format!("arn:aws:s3:::{bucket}/{key}")
}

/// What `requested` asks for, as a write of `bucket`/`key` takes it, or why
/// it's refused: an encryption context with pairs of the client's is the
/// object's, so it has the object's ARN (`aws:s3:arn`), as S3 answers with
/// it; one with no other pair is none. A client may name the ARN itself,
/// but no other one, nor have a key that's `aws:s3:arn` in another case,
/// which S3 (KMS) refuses as two keys that differ only in case (probed).
pub fn for_object(
    request: Option<ServerSide>,
    bucket: &str,
    key: &str,
) -> Result<Option<ServerSide>, Response<Full<Bytes>>> {
    let Some(ServerSide::Kms(KmsRequest { key_id, context: Some(mut context) })) = request else {
        return Ok(request);
    };
    if context.keys().any(|k| k != ARN_KEY && k.eq_ignore_ascii_case(ARN_KEY)) {
        return Err(bad_request(
            "KMS.ValidationException",
            "EncryptionContext must not contain multiple keys that only differ in case",
        ));
    }
    let arn = object_arn(bucket, key);
    if context.remove(ARN_KEY).is_some_and(|named| named != arn) {
        return Err(bad_request("InvalidArgument", "The context value for 'aws:s3:arn' shall be equal to object's ARN"));
    }
    let context = (!context.is_empty()).then(|| {
        context.insert(ARN_KEY.to_owned(), arn);
        context
    });
    Ok(Some(ServerSide::Kms(KmsRequest { key_id, context })))
}

fn seal_object_key(data_key: &Key, object_key: &Key, ad: &[u8]) -> Vec<u8> {
    encryption::seal_bytes(data_key, object_key, ad)
}

fn unseal_object_key(data_key: &Key, sealed: &[u8], ad: &[u8]) -> Option<Zeroizing<Key>> {
    if sealed.len() != SEALED_LEN {
        return None;
    }
    let plain = encryption::open_bytes(data_key, sealed, ad)?;
    Some(Zeroizing::new(Key::try_from(plain.as_slice()).ok()?))
}

/// The headers S3 answers about a stored object's encryption with: SSE-C's
/// (the algorithm and the key's MD5, `given` being the key), SSE-KMS's (the
/// algorithm, the key's ARN, and the context, if there's one), or SSE-S3's
/// (the algorithm).
pub fn echo(builder: Builder, stored: &Stored, given: Option<&CustomerKey>) -> Builder {
    match stored {
        Stored::Plain => builder,
        Stored::Customer { .. } => match given {
            Some(key) => key.echo(builder),
            None => builder,
        },
        Stored::S3(_) => builder.header(ENCRYPTION, AES256),
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

    fn status(result: Result<Option<ServerSide>, Response<Full<Bytes>>>) -> u16 {
        result.err().map(|r| r.status().as_u16()).unwrap_or(200)
    }

    #[test]
    fn parses_kms_requests() {
        assert_eq!(requested(&HeaderMap::new(), false, true, true).unwrap(), None);
        assert_eq!(requested(&headers(&[(ENCRYPTION, "AES256")]), false, true, true).unwrap(), Some(ServerSide::S3));
        assert_eq!(
            requested(&headers(&[(ENCRYPTION, "aws:kms"), (KMS_KEY_ID, "k")]), false, true, true).unwrap(),
            Some(ServerSide::Kms(KmsRequest { key_id: KeyId::parse("transit/k").unwrap(), context: None }))
        );
        let context = STANDARD.encode(r#"{"b":"2","a":"1"}"#);
        let request = requested(
            &headers(&[
                (ENCRYPTION, "aws:kms"),
                (KMS_KEY_ID, "arn:aws:kms:my-key"),
                (KMS_CONTEXT, &context),
                (BUCKET_KEY_ENABLED, "true"),
            ]),
            false,
            true,
            true,
        )
        .unwrap()
        .unwrap();
        let ServerSide::Kms(request) = request else { panic!("not SSE-KMS") };
        assert_eq!(request.key_id.as_string(), "transit/my-key");
        let context = request.context.unwrap();
        assert_eq!(serde_json::to_string(&context).unwrap(), r#"{"a":"1","b":"2"}"#);
    }

    #[test]
    fn refuses_bad_kms_requests() {
        // A valid request, but for `pairs` (which replace its headers).
        let kms = |pairs: &[(&str, &str)]| headers(&[&[(ENCRYPTION, "aws:kms"), (KMS_KEY_ID, "k")], pairs].concat());
        // No key ID: Cairn has no default key.
        assert_eq!(status(requested(&headers(&[(ENCRYPTION, "aws:kms")]), false, true, true)), 400);
        // SSE-S3, without Cairn's own key, or without a KMS, or with SSE-C.
        let aes = headers(&[(ENCRYPTION, "AES256")]);
        assert_eq!(status(requested(&aes, false, true, false)), 501);
        assert_eq!(status(requested(&aes, false, false, true)), 501);
        assert_eq!(status(requested(&aes, true, true, true)), 400);
        // With a key ID or context, it isn't SSE-S3, nor SSE-KMS.
        assert_eq!(status(requested(&headers(&[(ENCRYPTION, "AES256"), (KMS_KEY_ID, "k")]), false, true, true)), 400);
        // No KMS.
        assert_eq!(status(requested(&kms(&[]), false, false, true)), 501);
        // With SSE-C.
        assert_eq!(status(requested(&kms(&[]), true, true, true)), 400);
        // A key ID without asking for SSE-KMS.
        assert_eq!(status(requested(&headers(&[(KMS_KEY_ID, "k")]), false, true, true)), 400);
        assert_eq!(status(requested(&headers(&[(ENCRYPTION, "aws:kms:dsse")]), false, true, true)), 400);
        for id in [" k", "k ", "../k", "a//b", "a/../b", ""] {
            assert_eq!(status(requested(&kms(&[(KMS_KEY_ID, id)]), false, true, true)), 400, "{id:?}");
        }
        for context in ["not base64!", &STANDARD.encode("[1]"), &STANDARD.encode(r#"{"a":1}"#)] {
            assert_eq!(status(requested(&kms(&[(KMS_CONTEXT, context)]), false, true, true)), 400);
        }
        assert_eq!(status(requested(&kms(&[(BUCKET_KEY_ENABLED, "yes")]), false, true, true)), 400);
    }

    #[test]
    fn object_keys_seal_and_open() {
        let (data_key, object_key) = ([7; 32], [9; 32]);
        let sealed = seal_object_key(&data_key, &object_key, b"ad");
        assert_eq!(sealed.len(), SEALED_LEN);
        assert_ne!(sealed, seal_object_key(&data_key, &object_key, b"ad"));
        assert_eq!(*unseal_object_key(&data_key, &sealed, b"ad").unwrap(), object_key);
        assert!(unseal_object_key(&[8; 32], &sealed, b"ad").is_none());
        assert!(unseal_object_key(&data_key, &sealed, b"other").is_none());
        // SSE-S3's names the object, which no other object shares.
        assert_ne!(sse_s3_sealed_ad("b", "k/x"), sse_s3_sealed_ad("b", "k/y"));
        assert_ne!(sse_s3_sealed_ad("b", "k"), sse_s3_sealed_ad("bk", ""));
        for i in 0..SEALED_LEN {
            let mut flipped = sealed.clone();
            flipped[i] ^= 1;
            assert!(unseal_object_key(&data_key, &flipped, b"ad").is_none());
        }
        assert!(unseal_object_key(&data_key, &sealed[1..], b"ad").is_none());
    }

    #[test]
    fn associated_data_names_the_object() {
        let ad = |context, key| String::from_utf8(associated_data(context, "b", key)).unwrap();
        assert_eq!(ad(None, "k"), r#"{"aws:s3:arn":"arn:aws:s3:::b/k"}"#);
        assert_eq!(ad(Some(r#"{"z":"1","a":"2"}"#), "k"), r#"{"a":"2","aws:s3:arn":"arn:aws:s3:::b/k","z":"1"}"#);
        // Whatever a stored context says it is.
        assert_eq!(ad(Some(r#"{"aws:s3:arn":"x"}"#), "k"), r#"{"aws:s3:arn":"arn:aws:s3:::b/k"}"#);
        assert_ne!(ad(None, "k"), ad(None, "k2"));
    }

    /// A write's context, as S3 takes it (probed: plans/probes/kms_context_probe.py).
    #[test]
    fn a_context_is_the_objects() {
        let kms = |context: Option<&str>| {
            Some(ServerSide::Kms(KmsRequest {
                key_id: KeyId::parse("transit/k").unwrap(),
                context: context.map(|c| serde_json::from_str(c).unwrap()),
            }))
        };
        let context = |request: Result<Option<ServerSide>, _>| match request.unwrap() {
            Some(ServerSide::Kms(request)) => request.context.map(|c| serde_json::to_string(&c).unwrap()),
            _ => panic!("not SSE-KMS"),
        };
        assert_eq!(context(for_object(kms(None), "b", "k")), None);
        // Pairs of the client's, with the object's ARN, which it answers with.
        let own = for_object(kms(Some(r#"{"a":"1"}"#)), "b", "k");
        assert_eq!(context(own).as_deref(), Some(r#"{"a":"1","aws:s3:arn":"arn:aws:s3:::b/k"}"#));
        // The object's own ARN alone is no context.
        assert_eq!(context(for_object(kms(Some(r#"{"aws:s3:arn":"arn:aws:s3:::b/k"}"#)), "b", "k")), None);
        let named = for_object(kms(Some(r#"{"aws:s3:arn":"arn:aws:s3:::b/k","a":"1"}"#)), "b", "k");
        assert_eq!(context(named).as_deref(), Some(r#"{"a":"1","aws:s3:arn":"arn:aws:s3:::b/k"}"#));
        // Not another's, nor anything else.
        for arn in ["arn:aws:s3:::b/other", "arn:aws:s3:::other/k", "arn:aws:s3:::b", "hello"] {
            let refused = for_object(kms(Some(&format!(r#"{{"aws:s3:arn":"{arn}"}}"#))), "b", "k").unwrap_err();
            assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "{arn}");
        }
        // Nor the key in another case.
        let refused = for_object(kms(Some(r#"{"AWS:S3:ARN":"arn:aws:s3:::b/k"}"#)), "b", "k").unwrap_err();
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        // SSE-S3, none: as they are.
        assert_eq!(for_object(Some(ServerSide::S3), "b", "k").unwrap(), Some(ServerSide::S3));
        assert_eq!(for_object(None, "b", "k").unwrap(), None);
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
        let stored = Stored::Customer { sealed: vec![1; SEALED_LEN] };
        let columns = stored.columns();
        assert!(columns.sse_c_key.is_some() && columns.kms_key_id.is_none());
    }

    /// An SSE-C object's key opens only under its client's key, and only as
    /// the object it was sealed for; a copy seals it under its own.
    #[test]
    fn sse_c_object_keys_open_under_their_key_and_name() {
        let key = crate::e2e::customer_key(&[1; 32]);
        let other = crate::e2e::customer_key(&[2; 32]);
        let sealing = seal_customer(&key, "b", "k");
        let Stored::Customer { sealed } = &sealing.stored else { panic!("not SSE-C") };
        assert_eq!(sealed.len(), SEALED_LEN);
        assert_eq!(open_customer(&key, sealed, "b", "k").as_deref(), Some(&*sealing.key));
        assert!(check(&sealing.stored, Some(&key), "b", "k").is_ok());
        // Not the client's key itself, nor the same key twice.
        assert_ne!(&*sealing.key, key.key());
        assert_ne!(sealing.key, seal_customer(&key, "b", "k").key);
        // Another key, another name: refused.
        assert!(open_customer(&other, sealed, "b", "k").is_none());
        assert!(open_customer(&key, sealed, "b", "k2").is_none());
        assert!(open_customer(&key, sealed, "bk", "").is_none());
        assert!(check(&sealing.stored, Some(&other), "b", "k").is_err());
        assert!(check(&sealing.stored, None, "b", "k").is_err());
        assert!(check(&Stored::Plain, Some(&key), "b", "k").is_err());
        // A copy under another key, elsewhere: the same object key.
        let copy = reseal_customer(&other, &sealing.key, "b", "c");
        let Stored::Customer { sealed: copied } = &copy else { panic!("not SSE-C") };
        assert_eq!(open_customer(&other, copied, "b", "c").as_deref(), Some(&*sealing.key));
        assert!(open_customer(&key, copied, "b", "c").is_none());
    }
}
