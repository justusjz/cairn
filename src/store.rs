use std::path::PathBuf;

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
        fs::create_dir_all(&part_dir).await?;
        Ok(fs::File::create(part_dir.join(part_id)).await?)
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
}
