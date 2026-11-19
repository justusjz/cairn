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

    /// Writes `body`, `length` bytes, to `path`: streamed into the object
    /// store, which lays it out as it comes, knowing its size.
    async fn put<B>(&self, path: &str, body: B, length: u64) -> Result<()>
    where
        B: hyper::body::Body<Data = Bytes> + Unpin + Send,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        let key = self.key(path)?;
        let server = self.server_side()?;
        let payload = Payload::unchecked_of(length)
            .at_most(MAX_UPLOAD)
            .map_err(|_| unexpected(format!("{path} is larger than an object may be")))?;
        let response = crate::s3::objects::put::put_object(
            &self.app,
            &self.bucket,
            key,
            "application/octet-stream",
            "",
            "",
            body,
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
        let length = bs.len() as u64;
        self.put(path, Full::new(bs), length).await
    }

    async fn writer(&self, path: &str) -> Result<Box<dyn FileWrite>> {
        self.key(path)?;
        Ok(Box::new(Writer {
            storage: self.clone(),
            path: path.to_owned(),
            buffer: Vec::new(),
            spool: None,
            size: 0,
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

/// What a file being written keeps in memory, at most: beyond it, it's
/// spooled to disk (see `Writer`).
const IN_MEMORY: usize = 8 << 20;

/// The directory (in the node's first data dir) files being written are
/// spooled in, emptied as the node starts (see `clean`).
const SPOOL: &str = "table-writes";

/// Empties the directories tables' writes and compaction leave on the
/// node's disk while they run (a crash's leftovers): as the node starts.
pub fn clean(app: &App) {
    for dir in [SPOOL, crate::tables::compaction::SPILL] {
        let path = app.store.data_dir().join(dir);
        if let Err(e) = std::fs::remove_dir_all(&path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!("tables: emptying {}: {e}", path.display());
        }
    }
}

/// A file being written. What's written is kept in memory up to
/// `IN_MEMORY` bytes (metadata files, manifests); a larger file (data
/// files, up to the table's target size and more) goes to a spool file on
/// the node's disk instead, so a writer takes little memory whatever it
/// writes. As it's closed, it's stored, streamed from the spool, and the
/// spool file is removed (also if it's never closed: see `Drop`).
struct Writer {
    storage: TableStorage,
    path: String,
    buffer: Vec<u8>,
    /// The spool file, and its path, once there's one.
    spool: Option<(tokio::fs::File, std::path::PathBuf)>,
    size: u64,
    closed: bool,
}

impl Writer {
    /// Moves what's in memory to a new spool file.
    async fn spill(&mut self) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        let dir = self.storage.app.store.data_dir().join(SPOOL);
        tokio::fs::create_dir_all(&dir).await.map_err(unexpected)?;
        let path = dir.join(Uuid::new_v4().to_string());
        let mut file = tokio::fs::File::create(&path).await.map_err(unexpected)?;
        file.write_all(&self.buffer).await.map_err(unexpected)?;
        self.buffer = Vec::new();
        self.spool = Some((file, path));
        Ok(())
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        if let Some((_, path)) = &self.spool {
            let _ = std::fs::remove_file(path);
        }
    }
}

type Frames = std::pin::Pin<
    Box<dyn futures_core::Stream<Item = std::io::Result<hyper::body::Frame<Bytes>>> + Send>,
>;

/// The body of a spool file: read in chunks of a MiB.
fn spooled(file: tokio::fs::File) -> http_body_util::StreamBody<Frames> {
    let stream = futures_util::stream::unfold(file, |mut file| async move {
        use tokio::io::AsyncReadExt;
        let mut chunk = vec![0u8; 1 << 20];
        match file.read(&mut chunk).await {
            Ok(0) => None,
            Ok(n) => {
                chunk.truncate(n);
                Some((Ok(hyper::body::Frame::data(Bytes::from(chunk))), file))
            }
            Err(e) => Some((Err(e), file)),
        }
    });
    http_body_util::StreamBody::new(Box::pin(stream))
}

#[async_trait]
impl FileWrite for Writer {
    async fn write(&mut self, bs: Bytes) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        if self.closed {
            return Err(unexpected("the file is closed"));
        }
        self.size += bs.len() as u64;
        match &mut self.spool {
            Some((file, _)) => file.write_all(&bs).await.map_err(unexpected)?,
            None => {
                self.buffer.extend_from_slice(&bs);
                if self.buffer.len() > IN_MEMORY {
                    self.spill().await?;
                }
            }
        }
        Ok(())
    }

    async fn close(&mut self) -> Result<FileMetadata> {
        use tokio::io::AsyncWriteExt;
        if self.closed {
            return Err(unexpected("the file is closed already"));
        }
        self.closed = true;
        let size = self.size;
        match &mut self.spool {
            None => {
                let bytes = Bytes::from(std::mem::take(&mut self.buffer));
                self.storage.put(&self.path, Full::new(bytes), size).await?;
            }
            Some((file, path)) => {
                file.flush().await.map_err(unexpected)?;
                let reader = tokio::fs::File::open(&path).await.map_err(unexpected)?;
                self.storage.put(&self.path, spooled(reader), size).await?;
            }
        }
        Ok(FileMetadata { size })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn writes_large_files_through_a_spool() {
        let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        let bucket = format!(
            "w{}{}",
            uuid::Uuid::new_v4().simple(),
            crate::tables::names::STORAGE_SUFFIX
        )
        .chars()
        .take(63 - 10)
        .collect::<String>()
            + crate::tables::names::STORAGE_SUFFIX;
        let account = crate::users::account(&app.pool.get().await.unwrap())
            .await
            .unwrap();
        crate::tables::storage::create(&app.pool.get().await.unwrap(), &bucket, &account)
            .await
            .unwrap();
        let storage = TableStorage {
            app: app.clone(),
            bucket: bucket.clone(),
            class: crate::classes::STANDARD.to_owned(),
            sse_algorithm: "AES256".to_owned(),
            kms_key: None,
            role: None,
        };
        let spool = app.store.data_dir().join(SPOOL);
        for size in [100, IN_MEMORY * 2 + 12345] {
            let path = format!("s3://{bucket}/data/f-{size}");
            let mut writer = storage.writer(&path).await.unwrap();
            let data: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
            for chunk in data.chunks(1 << 20) {
                writer.write(Bytes::copy_from_slice(chunk)).await.unwrap();
            }
            let spooled = std::fs::read_dir(&spool).map_or(0, |d| d.count());
            assert_eq!(spooled, usize::from(size > IN_MEMORY), "{size}");
            assert_eq!(writer.close().await.unwrap().size, size as u64);
            drop(writer);
            // The spool file is gone, and the file is as written.
            assert_eq!(std::fs::read_dir(&spool).map_or(0, |d| d.count()), 0);
            assert_eq!(storage.read(&path).await.unwrap().as_ref(), &data[..]);
            assert_eq!(storage.metadata(&path).await.unwrap().size, size as u64);
        }
        // Not closed: its spool goes all the same.
        let mut writer = storage
            .writer(&format!("s3://{bucket}/data/abandoned"))
            .await
            .unwrap();
        writer
            .write(Bytes::from(vec![0u8; IN_MEMORY + 1]))
            .await
            .unwrap();
        drop(writer);
        assert_eq!(std::fs::read_dir(&spool).map_or(0, |d| d.count()), 0);
        // What a crash leaves is emptied as the node starts.
        std::fs::write(spool.join("leftover"), b"x").unwrap();
        clean(&app);
        assert!(!spool.exists());
    }
}
