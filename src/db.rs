use std::str::FromStr;

use deadpool_postgres::{Manager, ManagerConfig, Pool};
use tokio_postgres::NoTls;

pub async fn connect(url: &str) -> anyhow::Result<Pool> {
    let conf = tokio_postgres::Config::from_str(url)?;
    let mgr = Manager::from_config(
        conf,
        NoTls,
        ManagerConfig {
            recycling_method: deadpool_postgres::RecyclingMethod::Fast,
        },
    );
    let pool = Pool::builder(mgr).max_size(16).build()?;
    let client = pool.get().await?;
    client.batch_execute(SCHEMA).await?;
    Ok(pool)
}

const SCHEMA: &str = r#"
-- Cluster membership: each node self-registers and heartbeats `last_seen`.
-- node_id is a UUID bound to the node's data dir (never operator-supplied).
CREATE TABLE IF NOT EXISTS nodes (
    node_id     TEXT PRIMARY KEY,
    peer_url    TEXT NOT NULL,
    last_seen   TIMESTAMPTZ NOT NULL,
    free_space  BIGINT NOT NULL            -- Free space available in bytes
);

CREATE TABLE IF NOT EXISTS buckets (
    name        TEXT PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS parts (
    part_id       UUID PRIMARY KEY,
    size          BIGINT NOT NULL,
    state         TEXT NOT NULL,            -- 'pending' | 'committed'
    created_at    TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS part_locations (
    part_id     UUID NOT NULL REFERENCES parts(part_id) ON DELETE CASCADE,
    node_id     TEXT NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE,
    PRIMARY KEY (part_id, node_id)
);

CREATE TABLE IF NOT EXISTS objects (
    bucket        TEXT NOT NULL REFERENCES buckets(name) ON DELETE CASCADE,
    key           TEXT NOT NULL,
    size          BIGINT NOT NULL,          -- total object size in bytes
    etag          TEXT NOT NULL,            -- S3 ETag
    content_type  TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (bucket, key)
);

CREATE TABLE IF NOT EXISTS object_parts (
    bucket        TEXT NOT NULL,
    key           TEXT NOT NULL,
    part_number   INT NOT NULL,
    part_id       UUID NOT NULL REFERENCES parts(part_id),
    PRIMARY KEY (bucket, key, part_number),
    FOREIGN KEY (bucket, key) REFERENCES objects(bucket, key) ON DELETE CASCADE
);
"#;
