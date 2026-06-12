use std::collections::HashSet;
use std::sync::Mutex;

use uuid::Uuid;

/// Process-global set of part_ids currently being written to local disk. It
/// closes the write→announce gap for the GC: a part is in the set from *before*
/// its bytes are written until *after* its `part_locations` row is committed, so
/// a file with no location that's in the set is an in-flight write, not an
/// orphan. A process crash leaves the set empty — which is correct, since a write
/// that died before announcing its location genuinely failed.
#[derive(Default)]
pub struct WritingSet {
    ids: Mutex<HashSet<Uuid>>,
}

impl WritingSet {
    /// Marks `part_id` as being written; the returned guard removes it on drop
    /// (including on error or panic).
    pub fn begin(&self, part_id: Uuid) -> WritingGuard<'_> {
        self.ids.lock().unwrap().insert(part_id);
        WritingGuard { set: self, part_id }
    }

    pub fn contains(&self, part_id: Uuid) -> bool {
        self.ids.lock().unwrap().contains(&part_id)
    }
}

pub struct WritingGuard<'a> {
    set: &'a WritingSet,
    part_id: Uuid,
}

impl Drop for WritingGuard<'_> {
    fn drop(&mut self) {
        self.set.ids.lock().unwrap().remove(&self.part_id);
    }
}
