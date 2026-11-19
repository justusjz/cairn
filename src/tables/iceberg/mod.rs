//! Apache Iceberg, as S3 Tables has it: tables' metadata (`metadata`), its
//! files in tables' storage (here), and Iceberg's REST catalog (`rest`).

pub mod avro;
pub mod metadata;
pub(crate) mod rest;

use std::io::Read as _;
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{StatusCode, body::Bytes};
use serde_json::{Map, Value};
use uuid::Uuid;

use super::Table;
use crate::{
    App,
    payload::Payload,
    s3::{
        conditional::Preconditions,
        object_lock::Lock,
        sse::{KmsRequest, ServerSide, Wanted},
        util::MAX_UPLOAD,
    },
};

/// The largest metadata file the catalog reads, as S3 Tables' (50 MB).
pub const MAX_METADATA: u64 = 50 * 1024 * 1024;

/// Why a metadata file couldn't be read or written.
#[derive(Debug)]
pub enum FileError {
    /// It isn't there, isn't JSON, or is too large: the table's broken (or
    /// a client wrote it so).
    Unusable(String),
    /// Writing it was refused (its encryption, say).
    Refused(String),
}

/// The key of `location` (an `s3://` URI) in `table`'s storage, if it's in
/// it.
pub fn key_of<'a>(table: &Table, location: &'a str) -> Option<&'a str> {
    location
        .strip_prefix("s3://")?
        .strip_prefix(table.storage.as_str())?
        .strip_prefix('/')
        .filter(|key| !key.is_empty())
}

/// What a write to `table`'s storage asks for: its encryption.
fn server_side(app: &App, table: &Table) -> anyhow::Result<Option<ServerSide>> {
    let Some(kms) = &app.kms else {
        return Ok(None);
    };
    Ok(match (table.sse_algorithm.as_str(), &table.kms_key) {
        ("aws:kms", Some(arn)) => {
            let id = super::storage::kms_key_id(arn);
            let key_id = crate::kms::KeyId::parse(&id)
                .ok_or_else(|| anyhow::anyhow!("the table's KMS key {id:?} isn't one"))?;
            Some(ServerSide::Kms(KmsRequest {
                key_id,
                context: None,
            }))
        }
        _ if kms.sse_s3_key().is_some() => Some(ServerSide::S3),
        _ => None,
    })
}

/// Writes `metadata` to `location` in `table`'s storage, as the principal
/// `role` (whose KMS keys it uses).
pub async fn write(
    app: &Arc<App>,
    table: &Table,
    role: Option<Uuid>,
    location: &str,
    metadata: &Map<String, Value>,
) -> anyhow::Result<Result<(), FileError>> {
    let Some(key) = key_of(table, location) else {
        anyhow::bail!("{location} isn't in the table's storage");
    };
    let body = serde_json::to_vec(metadata)?;
    let server = server_side(app, table)?;
    let payload = Payload::unchecked()
        .at_most(MAX_UPLOAD)
        .map_err(|_| anyhow::anyhow!("an unchecked payload has no length"))?;
    let response = crate::s3::objects::put::put_object(
        app,
        &table.storage,
        key,
        "application/json",
        "",
        "",
        Full::new(Bytes::from(body)),
        payload,
        &Preconditions::default(),
        Wanted::new(None, server.as_ref()),
        role,
        Lock::default(),
        &table.storage_class,
    )
    .await?;
    match response.status() {
        StatusCode::OK => Ok(Ok(())),
        status if status.is_server_error() => {
            anyhow::bail!(
                "writing {location}: {}",
                crate::inventory::refusal(response).await
            )
        }
        _ => Ok(Err(FileError::Refused(format!(
            "Writing {location} was refused: {}",
            crate::inventory::refusal(response).await
        )))),
    }
}

/// Reads the file at `location` in `table`'s storage, as the principal
/// `role` (none: Cairn itself, which can't open SSE-KMS files), if it's at
/// most `max` bytes.
pub async fn read_file(
    app: &Arc<App>,
    table: &Table,
    role: Option<Uuid>,
    location: &str,
    max: u64,
) -> anyhow::Result<Result<Bytes, FileError>> {
    let unusable = |why: String| Ok(Err(FileError::Unusable(why)));
    let Some(key) = key_of(table, location) else {
        return unusable(format!("{location} isn't in the table's storage."));
    };
    let response = crate::s3::objects::get::get_object(
        app,
        &table.storage,
        key,
        None,
        None,
        None,
        &Preconditions::default(),
        None,
        role,
        false,
    )
    .await?;
    if response.status() != StatusCode::OK {
        let status = response.status();
        let why = crate::inventory::refusal(box_full(response).await).await;
        return unusable(format!("{location} can't be read: {status} {why}"));
    }
    let length = response
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    if length > max {
        return unusable(format!(
            "{location} is larger than {} MB.",
            max / 1024 / 1024
        ));
    }
    Ok(Ok(response.into_body().collect().await?.to_bytes()))
}

/// A response's body, whole, as `refusal` takes it.
async fn box_full(response: hyper::Response<crate::body::ResBody>) -> hyper::Response<Full<Bytes>> {
    let (parts, body) = response.into_parts();
    let body = body
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    hyper::Response::from_parts(parts, Full::new(body))
}

/// Reads the metadata file at `location` in `table`'s storage (gzipped, if
/// its name says so), as the principal `role`.
pub async fn read(
    app: &Arc<App>,
    table: &Table,
    role: Option<Uuid>,
    location: &str,
) -> anyhow::Result<Result<Map<String, Value>, FileError>> {
    let unusable = |why: String| Ok(Err(FileError::Unusable(why)));
    let body = match read_file(app, table, role, location, MAX_METADATA).await? {
        Ok(body) => body,
        Err(e) => return Ok(Err(e)),
    };
    let text = match location.ends_with(".gz") {
        false => body.to_vec(),
        true => {
            let mut out = Vec::new();
            let read = flate2::read::GzDecoder::new(&body[..])
                .take(MAX_METADATA + 1)
                .read_to_end(&mut out);
            if read.is_err() || out.len() as u64 > MAX_METADATA {
                return unusable(format!(
                    "The table's metadata file {location} isn't gzip, or is too large."
                ));
            }
            out
        }
    };
    match serde_json::from_slice(&text) {
        Ok(Value::Object(metadata)) => Ok(Ok(metadata)),
        _ => unusable(format!("The table's metadata file {location} isn't JSON.")),
    }
}
