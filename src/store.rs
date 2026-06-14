use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use tokio::fs;
use uuid::Uuid;

pub struct Store {
    node_id: Uuid,
    data_dir: PathBuf,
}

impl Store {
    pub fn new(data_dir: String) -> anyhow::Result<Store> {
        let data_dir = PathBuf::from(data_dir);
        std::fs::create_dir_all(&data_dir)?;
        // A node's identity is bound to its data dir: read it back if present,
        // otherwise mint one and persist it so it's stable across restarts.
        let id_path = data_dir.join("node_id");
        let node_id = match std::fs::read_to_string(&id_path) {
            Ok(s) => Uuid::parse_str(s.trim())?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let id = Uuid::new_v4();
                std::fs::write(&id_path, id.to_string())?;
                id
            }
            Err(e) => return Err(e.into()),
        };
        Ok(Store { node_id, data_dir })
    }

    pub fn get_node_id(&self) -> Uuid {
        self.node_id
    }

    /// Bytes available on the filesystem backing the data dir (what an
    /// unprivileged process may write). Reported in heartbeats for replica
    /// selection.
    pub fn available_space(&self) -> anyhow::Result<u64> {
        let path = CString::new(self.data_dir.as_os_str().as_bytes())?;
        // SAFETY: `path` is a valid NUL-terminated C string and `statvfs` only
        // writes into the zeroed-out `stat`.
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok((stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64))
    }

    fn get_part_dir(&self, file_id: &str) -> PathBuf {
        let level1 = &file_id[0..2];
        let level2 = &file_id[2..4];
        self.data_dir.join(level1).join(level2)
    }

    /// Creates (truncating) the on-disk file for a part, making its sharded
    /// directory if needed. The caller streams the bytes in and fsyncs before
    /// announcing this node as a durable location.
    pub async fn create_part(&self, part_id: Uuid) -> anyhow::Result<fs::File> {
        let part_id = part_id.to_string();
        let part_dir = self.get_part_dir(&part_id);
        let path = part_dir.join(&part_id);
        // `create_dir_all` and `File::create` aren't atomic: a concurrent prune can
        // rmdir the just-made (empty) shard between them, so the create can hit
        // NotFound. Recreate the dir and retry rather than failing the upload. A
        // single prune pass touches a dir once, so one retry covers it; the bound
        // guards against pathological overlapping prunes.
        let mut last_err = None;
        for _ in 0..4 {
            fs::create_dir_all(&part_dir).await?;
            match fs::File::create(&path).await {
                Ok(file) => return Ok(file),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => last_err = Some(e),
                Err(e) => return Err(e.into()),
            }
        }
        Err(last_err.expect("loop runs at least once").into())
    }

    /// Opens a part for reading, or `None` if this node doesn't have it.
    pub async fn open_part(&self, part_id: Uuid) -> anyhow::Result<Option<fs::File>> {
        let part_id = part_id.to_string();
        let part_dir = self.get_part_dir(&part_id);
        match fs::File::open(part_dir.join(part_id)).await {
            Ok(file) => Ok(Some(file)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Deletes a part's on-disk file. Idempotent: a missing file is not an error.
    pub async fn remove_part(&self, part_id: Uuid) -> anyhow::Result<()> {
        let part_id = part_id.to_string();
        let part_dir = self.get_part_dir(&part_id);
        match fs::remove_file(part_dir.join(part_id)).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Walks the sharded data directory and returns every part_id with a local
    /// file. Used only by the prune/repair full scan.
    pub async fn list_local_parts(&self) -> anyhow::Result<Vec<Uuid>> {
        let mut parts = Vec::new();
        let mut level1 = fs::read_dir(&self.data_dir).await?;
        while let Some(e1) = level1.next_entry().await? {
            // Skip non-directories at the top level (e.g. the node_id file).
            if !e1.file_type().await?.is_dir() {
                continue;
            }
            let mut level2 = fs::read_dir(e1.path()).await?;
            while let Some(e2) = level2.next_entry().await? {
                if !e2.file_type().await?.is_dir() {
                    continue;
                }
                let mut files = fs::read_dir(e2.path()).await?;
                while let Some(f) = files.next_entry().await? {
                    if let Some(id) = f.file_name().to_str().and_then(|n| Uuid::parse_str(n).ok()) {
                        parts.push(id);
                    }
                }
            }
        }
        Ok(parts)
    }

    /// Reclaims empty shard directories (both sharding levels) left behind once
    /// their parts are gone. `apply` performs the removals; otherwise it only
    /// reports which directories are empty. Returns the affected paths.
    ///
    /// `rmdir` is the safety net: it removes a directory *only* if it's empty, so
    /// a part is never at risk — a non-empty or concurrently-repopulated shard
    /// simply isn't removed, and `create_part` recreates shards on demand.
    pub async fn prune_empty_dirs(&self, apply: bool) -> anyhow::Result<Vec<String>> {
        let mut removed = Vec::new();
        let mut level1 = fs::read_dir(&self.data_dir).await?;
        while let Some(e1) = level1.next_entry().await? {
            if !e1.file_type().await?.is_dir() {
                continue; // skip the node_id file
            }
            let l1 = e1.path();
            let mut level2 = fs::read_dir(&l1).await?;
            while let Some(e2) = level2.next_entry().await? {
                if e2.file_type().await?.is_dir() {
                    self.try_rmdir(&e2.path(), apply, &mut removed).await?;
                }
            }
            // With its leaf shards gone, the level-1 directory may now be empty too.
            self.try_rmdir(&l1, apply, &mut removed).await?;
        }
        Ok(removed)
    }

    /// Removes `dir` if empty (apply), or records it as removable (dry-run).
    async fn try_rmdir(&self, dir: &Path, apply: bool, removed: &mut Vec<String>) -> anyhow::Result<()> {
        if apply {
            // rmdir only succeeds on an empty directory, so this never risks a
            // part; a non-empty or concurrently-recreated dir just isn't removed.
            if fs::remove_dir(dir).await.is_ok() {
                removed.push(dir.display().to_string());
            }
        } else if fs::read_dir(dir).await?.next_entry().await?.is_none() {
            removed.push(dir.display().to_string());
        }
        Ok(())
    }
}
