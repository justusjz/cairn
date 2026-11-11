use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use uuid::Uuid;

/// Process-global set of blob_ids currently being written to local disk. It
/// closes the write→announce gap for the GC: a blob is in the set from *before*
/// its bytes are written until *after* its `blob_locations` row is committed, so
/// a file with no location that's in the set is an in-flight write, not an
/// orphan. A process crash leaves the set empty — which is correct, since a write
/// that died before announcing its location genuinely failed.
#[derive(Default)]
pub struct WritingSet {
    ids: Mutex<HashSet<Uuid>>,
    /// The blobs whose files are locked (see `lock_file`).
    files: Mutex<HashMap<Uuid, Arc<tokio::sync::Mutex<()>>>>,
}

impl WritingSet {
    /// Marks `blob_id` as being written; the returned guard removes it on drop
    /// (including on error or panic).
    pub fn begin(&self, blob_id: Uuid) -> WritingGuard<'_> {
        self.ids.lock().unwrap().insert(blob_id);
        WritingGuard { set: self, blob_id }
    }

    pub fn contains(&self, blob_id: Uuid) -> bool {
        self.ids.lock().unwrap().contains(&blob_id)
    }
}

pub struct WritingGuard<'a> {
    set: &'a WritingSet,
    blob_id: Uuid,
}

impl Drop for WritingGuard<'_> {
    fn drop(&mut self) {
        self.set.ids.lock().unwrap().remove(&self.blob_id);
    }
}

/// A lock on what a blob's file on this node is (see `WritingSet::lock_file`).
pub struct FileLock<'a> {
    set: &'a WritingSet,
    blob_id: Uuid,
    guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl WritingSet {
    /// Locks what blob `blob_id`'s file on this node is. A shard moving here
    /// holds it while its location moves and its file takes the blob's name
    /// (see `mover`); a deletion of the file for having no location holds it
    /// while it checks that, and deletes. So a deletion that found no location
    /// can't take a file whose location was recorded meanwhile.
    pub async fn lock_file(&self, blob_id: Uuid) -> FileLock<'_> {
        let lock = self.files.lock().unwrap().entry(blob_id).or_default().clone();
        FileLock {
            set: self,
            blob_id,
            guard: Some(lock.lock_owned().await),
        }
    }
}

impl Drop for FileLock<'_> {
    fn drop(&mut self) {
        drop(self.guard.take());
        let mut files = self.set.files.lock().unwrap();
        // Forget the lock once nobody holds or waits for it.
        if files.get(&self.blob_id).is_some_and(|lock| Arc::strong_count(lock) == 1) {
            files.remove(&self.blob_id);
        }
    }
}
