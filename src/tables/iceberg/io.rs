//! Iceberg's file I/O (`iceberg::io::FileIO`) over a table's storage: what
//! Cairn reads and writes of a table itself (its metadata files, its
//! manifests, and maintenance's files), straight through the object store,
//! as the table's: in its storage class, encrypted as it says. Only the
//! table's own storage (`s3://<storage>/…`, or `s3a://`, `s3n://`).
//!
//! As a principal (the requester's, for the catalog), or as Cairn itself
//! (`role` none, for maintenance), which can open SSE-S3 objects but not
//! SSE-KMS ones (see `kms`).

use std::ops::Range;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::StreamExt;
use futures_util::stream::BoxStream;
use http_body_util::{BodyExt, Full};
use hyper::{StatusCode, body::Bytes};
use iceberg::io::{
    FileIO, FileIOBuilder, FileMetadata, FileRead, FileWrite, InputFile, OutputFile, Storage,
    StorageConfig, StorageFactory,
};
use iceberg::{Error, ErrorKind, Result};
use uuid::Uuid;

use crate::{
    App,
    payload::Payload,
    s3::{
        conditional::Preconditions,
        object_lock::Lock,
        sse::{KmsRequest, ServerSide, Wanted},
        util::MAX_UPLOAD,
    },
    tables::Table,
};

/// A table's storage, as `iceberg` reads and writes it.
#[derive(Clone)]
pub struct TableStorage {
    app: Arc<App>,
    /// The storage bucket.
    bucket: String,
    /// What its writes are stored as.
    class: String,
    sse_algorithm: String,
    kms_key: Option<String>,
    /// Whom it reads and writes as (see the module's docs).
    role: Option<Uuid>,
}

impl std::fmt::Debug for TableStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TableStorage({})", self.bucket)
    }
}

// `iceberg` wants storages serializable (to send them elsewhere): a
// table's, which holds the node, never is.
impl serde::Serialize for TableStorage {
    fn serialize<S: serde::Serializer>(&self, _: S) -> std::result::Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom(
            "a table's storage can't be serialized",
        ))
    }
}

impl<'de> serde::Deserialize<'de> for TableStorage {
    fn deserialize<D: serde::Deserializer<'de>>(_: D) -> std::result::Result<Self, D::Error> {
        Err(serde::de::Error::custom(
            "a table's storage can't be deserialized",
        ))
    }
}

/// `table`'s file I/O, as `role`.
pub fn file_io(app: &Arc<App>, table: &Table, role: Option<Uuid>) -> FileIO {
    let storage = TableStorage {
        app: app.clone(),
        bucket: table.storage.clone(),
        class: table.storage_class.clone(),
        sse_algorithm: table.sse_algorithm.clone(),
        kms_key: table.kms_key.clone(),
        role,
    };
    FileIOBuilder::new(Arc::new(Factory(storage))).build()
}

/// Makes `TableStorage`s, for `FileIOBuilder`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Factory(TableStorage);

#[typetag::serde]
impl StorageFactory for Factory {
    fn build(&self, _: &StorageConfig) -> Result<Arc<dyn Storage>> {
        Ok(Arc::new(self.0.clone()))
    }
}

fn unexpected(e: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Unexpected, e.to_string())
}

/// What a failed request said, for an error.
async fn refusal(response: hyper::Response<crate::body::ResBody>) -> String {
    let status = response.status();
    let (parts, body) = response.into_parts();
    let body = body
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let why = crate::inventory::refusal(hyper::Response::from_parts(parts, Full::new(body))).await;
    format!("{status} {why}")
}

impl TableStorage {
    /// The key of `path` in the storage.
    fn key<'a>(&self, path: &'a str) -> Result<&'a str> {
        ["s3://", "s3a://", "s3n://"]
            .iter()
            .find_map(|scheme| path.strip_prefix(scheme))
            .and_then(|rest| rest.strip_prefix(self.bucket.as_str()))
            .and_then(|rest| rest.strip_prefix('/'))
            .filter(|key| !key.is_empty())
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::DataInvalid,
                    format!("{path} isn't in the table's storage"),
                )
            })
    }

    /// What a write asks for: the table's encryption.
    fn server_side(&self) -> Result<Option<ServerSide>> {
        let Some(kms) = &self.app.kms else {
            return Ok(None);
        };
        Ok(match (self.sse_algorithm.as_str(), &self.kms_key) {
            ("aws:kms", Some(arn)) => {
                let id = crate::tables::storage::kms_key_id(arn);
                let key_id = crate::kms::KeyId::parse(&id).ok_or_else(|| {
                    Error::new(
                        ErrorKind::DataInvalid,
                        format!("the KMS key {id:?} isn't one"),
                    )
                })?;
                Some(ServerSide::Kms(KmsRequest {
                    key_id,
                    context: None,
                }))
            }
            _ if kms.sse_s3_key().is_some() => Some(ServerSide::S3),
            _ => None,
        })
    }

    async fn get(&self, path: &str, range: Option<Range<u64>>) -> Result<Bytes> {
        let key = self.key(path)?;
        let range = range
            .filter(|r| r.end > r.start)
            .map(|r| format!("bytes={}-{}", r.start, r.end - 1));
        let response = crate::s3::objects::get::get_object(
            &self.app,
            &self.bucket,
            key,
            None,
            range.as_deref(),
            None,
            &Preconditions::default(),
            None,
            self.role,
            false,
        )
        .await
        .map_err(unexpected)?;
        match response.status() {
            StatusCode::OK | StatusCode::PARTIAL_CONTENT => {}
            StatusCode::NOT_FOUND => {
                return Err(Error::new(
                    ErrorKind::DataInvalid,
                    format!("{path} doesn't exist"),
                ));
            }
            _ => {
                let why = refusal(response).await;
                return Err(unexpected(format!("{path} can't be read: {why}")));
            }
        }
        response
            .into_body()
            .collect()
            .await
            .map(|b| b.to_bytes())
            .map_err(unexpected)
    }

    async fn head(&self, path: &str) -> Result<Option<u64>> {
        let key = self.key(path)?;
        let response = crate::s3::objects::get::head_object(
            &self.app,
            &self.bucket,
            key,
            None,
            None,
            None,
            &Preconditions::default(),
            None,
            self.role,
            false,
        )
        .await
        .map_err(unexpected)?;
        match response.status() {
            StatusCode::OK => Ok(Some(
                response
                    .headers()
                    .get(hyper::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0),
            )),
            StatusCode::NOT_FOUND => Ok(None),
            status => Err(unexpected(format!("{path} can't be looked at: {status}"))),
        }
    }

    async fn put(&self, path: &str, bytes: Bytes) -> Result<()> {
        let key = self.key(path)?;
        let server = self.server_side()?;
        let payload = Payload::unchecked()
            .at_most(MAX_UPLOAD)
            .map_err(|_| unexpected("an unchecked payload has no length"))?;
        let response = crate::s3::objects::put::put_object(
            &self.app,
            &self.bucket,
            key,
            "application/octet-stream",
            "",
            "",
            Full::new(bytes),
            payload,
            &Preconditions::default(),
            Wanted::new(None, server.as_ref()),
            self.role,
            Lock::default(),
            &self.class,
        )
        .await
        .map_err(unexpected)?;
        match response.status() {
            StatusCode::OK => Ok(()),
            _ => {
                let why = crate::inventory::refusal(response).await;
                Err(unexpected(format!("{path} can't be written: {why}")))
            }
        }
    }

    async fn remove(&self, keys: &[String]) -> Result<()> {
        for chunk in keys.chunks(1000) {
            let body: String = chunk
                .iter()
                .map(|k| {
                    format!(
                        "<Object><Key>{}</Key></Object>",
                        crate::s3::util::xml_escape(k)
                    )
                })
                .collect();
            let response = crate::s3::objects::delete::delete_objects(
                &self.app,
                &self.bucket,
                Bytes::from(format!("<Delete><Quiet>true</Quiet>{body}</Delete>")),
                &|_, _| true,
                &|_| false,
                crate::mfa::Presented::Absent,
            )
            .await
            .map_err(unexpected)?;
            if !response.status().is_success() {
                return Err(unexpected(format!("deleting files: {}", response.status())));
            }
        }
        Ok(())
    }
}

#[async_trait]
#[typetag::serde]
impl Storage for TableStorage {
    async fn exists(&self, path: &str) -> Result<bool> {
        Ok(self.head(path).await?.is_some())
    }

    async fn metadata(&self, path: &str) -> Result<FileMetadata> {
        match self.head(path).await? {
            Some(size) => Ok(FileMetadata { size }),
            None => Err(Error::new(
                ErrorKind::DataInvalid,
                format!("{path} doesn't exist"),
            )),
        }
    }

    async fn read(&self, path: &str) -> Result<Bytes> {
        self.get(path, None).await
    }

    async fn reader(&self, path: &str) -> Result<Box<dyn FileRead>> {
        self.key(path)?;
        Ok(Box::new(Reader {
            storage: self.clone(),
            path: path.to_owned(),
        }))
    }

    async fn write(&self, path: &str, bs: Bytes) -> Result<()> {
        self.put(path, bs).await
    }

    async fn writer(&self, path: &str) -> Result<Box<dyn FileWrite>> {
        self.key(path)?;
        Ok(Box::new(Writer {
            storage: self.clone(),
            path: path.to_owned(),
            buffer: Vec::new(),
            closed: false,
        }))
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let key = self.key(path)?.to_owned();
        self.remove(&[key]).await
    }

    async fn delete_prefix(&self, path: &str) -> Result<()> {
        Err(Error::new(
            ErrorKind::FeatureUnsupported,
            format!("a table's files are deleted one by one, not by prefix ({path})"),
        ))
    }

    async fn delete_stream(&self, mut paths: BoxStream<'static, String>) -> Result<()> {
        let mut keys = Vec::new();
        while let Some(path) = paths.next().await {
            keys.push(self.key(&path)?.to_owned());
        }
        self.remove(&keys).await
    }

    fn new_input(&self, path: &str) -> Result<InputFile> {
        self.key(path)?;
        Ok(InputFile::new(Arc::new(self.clone()), path.to_owned()))
    }

    fn new_output(&self, path: &str) -> Result<OutputFile> {
        self.key(path)?;
        Ok(OutputFile::new(Arc::new(self.clone()), path.to_owned()))
    }
}

/// Reads ranges of a file.
struct Reader {
    storage: TableStorage,
    path: String,
}

#[async_trait]
impl FileRead for Reader {
    async fn read(&self, range: Range<u64>) -> Result<Bytes> {
        if range.end <= range.start {
            return Ok(Bytes::new());
        }
        self.storage.get(&self.path, Some(range)).await
    }
}

/// Writes a file: what's written is kept, and stored as it's closed.
struct Writer {
    storage: TableStorage,
    path: String,
    buffer: Vec<u8>,
    closed: bool,
}

#[async_trait]
impl FileWrite for Writer {
    async fn write(&mut self, bs: Bytes) -> Result<()> {
        if self.closed {
            return Err(unexpected("the file is closed"));
        }
        self.buffer.extend_from_slice(&bs);
        Ok(())
    }

    async fn close(&mut self) -> Result<FileMetadata> {
        if self.closed {
            return Err(unexpected("the file is closed already"));
        }
        self.closed = true;
        let bytes = Bytes::from(std::mem::take(&mut self.buffer));
        let size = bytes.len() as u64;
        self.storage.put(&self.path, bytes).await?;
        Ok(FileMetadata { size })
    }
}
