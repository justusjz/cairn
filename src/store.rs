use std::path::PathBuf;

use tokio::{fs, io::AsyncWriteExt};
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

    pub async fn write_part<B: AsRef<[u8]>>(&self, part_id: Uuid, data: B) -> anyhow::Result<()> {
        let part_id = part_id.to_string();
        let part_dir = self.get_part_dir(&part_id);
        fs::create_dir_all(&part_dir).await?;
        // Write *and fsync* before returning: the caller announces this node as a
        // durable location for the part right after, so the bytes must survive a
        // crash by the time we report success.
        let mut file = fs::File::create(part_dir.join(part_id)).await?;
        file.write_all(data.as_ref()).await?;
        file.sync_all().await?;
        Ok(())
    }

    /// Reads a part from local disk, or `None` if this node doesn't have it.
    pub async fn read_part_opt(&self, part_id: Uuid) -> anyhow::Result<Option<Vec<u8>>> {
        let part_id = part_id.to_string();
        let part_dir = self.get_part_dir(&part_id);
        match fs::read(part_dir.join(part_id)).await {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}
