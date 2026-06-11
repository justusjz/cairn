use std::{path::PathBuf, str::FromStr};

use tokio::{fs, io::AsyncWriteExt};
use uuid::Uuid;

pub struct Store {
    node_id: Uuid,
    data_dir: PathBuf,
}

impl Store {
    pub fn new(data_dir: String) -> Store {
        // TODO: we need to actually read the store of course
        Store {
            node_id: Uuid::new_v4(),
            data_dir: PathBuf::from_str(&data_dir).unwrap(),
        }
    }

    pub fn get_node_id(&self) -> Uuid {
        self.node_id
    }

    fn get_part_dir(&self, file_id: &str) -> PathBuf {
        let level1 = &file_id[0..2];
        let level2 = &file_id[2..4];
        let level3 = &file_id[4..6];
        self.data_dir.join(level1).join(level2).join(level3)
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

    pub async fn read_part(&self, part_id: Uuid) -> anyhow::Result<Vec<u8>> {
        let part_id = part_id.to_string();
        let part_dir = self.get_part_dir(&part_id);
        let data = fs::read(part_dir.join(part_id)).await?;
        Ok(data)
    }
}
