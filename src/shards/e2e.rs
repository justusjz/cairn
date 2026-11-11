//! End-to-end tests of erasure coding (see `crate::e2e`): blobs that the
//! packer codes, read with shards missing, damaged or on nodes that are
//! down, and repaired by the scrubber.

use std::{sync::Arc, time::Duration};

use http_body_util::BodyExt;
use hyper::StatusCode;
use uuid::Uuid;

use crate::{
    App,
    blob_file::{self, ShardFile},
    blobs::{LAYOUT_COLUMNS, layout_at},
    e2e::{BUCKET, Cluster, assert_reaped, cluster_with, delete, get, put, query_i64},
    packer::{self, Config, Hook, Stage},
    s3::{conditional::Preconditions, objects},
    scrub::{Pacer, Report, Scope},
    shards::Layout,
};

const MIB: usize = 1024 * 1024;

/// Packs into blobs of 8 MiB, and codes blobs over 1 MiB as soon as they're
/// written.
fn pack() -> Config {
    Config {
        target_size: 8 * MIB as u64,
        small_size: MIB as u64,
        cold_age: Duration::ZERO,
        ..Config::default()
    }
}

/// A cluster of `n` nodes writing blobs with `replication_factor` replicas,
/// and so `replication_factor` − 1 parity shards, that codes cold data into
/// `data_shards` data shards. `None` if there's no database to test against.
async fn coding(n: usize, replication_factor: usize, data_shards: i64, hook: Option<Hook>) -> Option<Cluster> {
    let cluster = cluster_with(n, replication_factor, pack(), hook).await?;
    set_data_shards(&cluster.nodes[0], data_shards).await;
    Some(cluster)
}

async fn set_data_shards(app: &App, data_shards: i64) {
    let client = app.pool.get().await.unwrap();
    crate::settings::DATA_SHARDS.set(&client, data_shards).await.unwrap();
}

/// Bytes that don't repeat at the scale of a stripe unit, so that a cell put
/// in the wrong place shows.
fn data(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// The blob holding an object's data.
async fn blob_of(app: &App, key: &str) -> Uuid {
    let client = app.pool.get().await.unwrap();
    client
        .query_one(
            "SELECT p.blob_id FROM parts p JOIN objects o ON o.id = p.object_id
             WHERE o.bucket = $1 AND o.key = $2",
            &[&BUCKET, &key],
        )
        .await
        .unwrap()
        .get(0)
}

/// A blob's layout, and which of the cluster's nodes holds each shard.
async fn shards_of(cluster: &Cluster, blob_id: Uuid) -> (Layout, Vec<usize>) {
    let client = cluster.nodes[0].pool.get().await.unwrap();
    let row = client
        .query_one(&format!("SELECT {LAYOUT_COLUMNS} FROM blobs b WHERE b.blob_id = $1"), &[&blob_id])
        .await
        .unwrap();
    let layout = layout_at(&row, 0).unwrap();
    let holders = client
        .query("SELECT node, shard FROM blob_locations WHERE blob_id = $1 ORDER BY shard", &[&blob_id])
        .await
        .unwrap()
        .iter()
        .enumerate()
        .map(|(i, r)| {
            assert_eq!(r.get::<_, i16>(1) as usize, i, "one location per shard");
            let node: i32 = r.get(0);
            cluster.nodes.iter().position(|n| n.node == node).unwrap()
        })
        .collect();
    (layout, holders)
}

/// Checks every shard's file of a blob against the catalog's CRC of it.
async fn assert_intact(cluster: &Cluster, blob_id: Uuid) {
    let (layout, holders) = shards_of(cluster, blob_id).await;
    let client = cluster.nodes[0].pool.get().await.unwrap();
    let crcs: Vec<i64> = client
        .query_one("SELECT shard_crcs FROM blobs WHERE blob_id = $1", &[&blob_id])
        .await
        .unwrap()
        .get(0);
    for (shard, &i) in holders.iter().enumerate() {
        let path = cluster.nodes[i].store.blob_path(blob_id);
        let mut file = tokio::fs::File::open(path).await.unwrap();
        let expected = ShardFile {
            blob_id,
            layout,
            shard: shard as u32,
        };
        let crc = blob_file::verify(&mut file, &expected).await.unwrap();
        assert_eq!(crc, crcs[shard] as u64, "shard {shard}");
    }
}

/// Reads (the `range` of) an object: its status, and its body if it came
/// whole.
async fn read(app: &Arc<App>, key: &str, range: Option<&str>) -> (StatusCode, Option<Vec<u8>>) {
    let response = objects::get::get_object(app, BUCKET, key, None, range, &Preconditions::default(), None, None, false)
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.ok().map(|b| b.to_bytes().to_vec());
    (status, body)
}

/// Reads an object whole, and in ranges that cross cells, rows and the end.
async fn assert_reads(app: &Arc<App>, key: &str, body: &[u8]) {
    assert_eq!(get(app, key).await.unwrap(), body, "{key}");
    let last = body.len() - 1;
    for (from, to) in [(0, 10), (MIB - 5, MIB + 5), (3 * MIB - 1, 4 * MIB + 2), (last - 3, last)] {
        let (status, got) = read(app, key, Some(&format!("bytes={from}-{to}"))).await;
        assert_eq!(status, StatusCode::PARTIAL_CONTENT);
        assert!(got.unwrap() == body[from..=to], "{key}: bytes {from}-{to}");
    }
}

/// Flips a bit of the file a node holds of a blob.
fn flip(app: &App, blob_id: Uuid, at: usize) {
    let path = app.store.blob_path(blob_id);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[at] ^= 1;
    std::fs::write(&path, bytes).unwrap();
}

async fn scrub(app: &Arc<App>, scope: Scope) -> Report {
    crate::scrub::pass(app, scope, &Pacer::new(None)).await.unwrap()
}

/// The lost ranges of a blob, by start.
async fn lost(app: &App, blob_id: Uuid) -> Vec<(i64, i64)> {
    let client = app.pool.get().await.unwrap();
    client
        .query("SELECT start, stop FROM lost_ranges WHERE blob_id = $1 ORDER BY start", &[&blob_id])
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect()
}

/// Waits until a read has flagged a node's shard of a blob for its scrubber.
async fn wait_flagged(app: &App, blob_id: Uuid) {
    let sql = format!(
        "SELECT count(*) FROM blob_locations
         WHERE blob_id = '{blob_id}' AND node = {} AND checked_at = '-infinity'",
        app.node
    );
    for _ in 0..100 {
        if query_i64(app, &sql).await == 1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("blob {blob_id} wasn't flagged on node {}", app.node);
}

/// A cluster of 4 nodes coding 3+1, with one object of a little over 5 MiB
/// coded: six rows of 3 MiB, the last one short. The object's data, and its
/// blob.
async fn coded_object(hook: Option<Hook>) -> Option<(Cluster, Vec<u8>, Uuid)> {
    let cluster = coding(4, 2, 3, hook).await?;
    let a = &cluster.nodes[0];
    let body = data(1, 5 * MIB + 12345);
    put(a, "k", body.clone()).await;
    let reports = packer::pass(a).await.unwrap();
    assert_eq!(reports.len(), 1, "one conversion: {:?}", reports.iter().map(ToString::to_string).collect::<Vec<_>>());
    let blob_id = blob_of(a, "k").await;
    Some((cluster, body, blob_id))
}

/// Cold replicated blobs are coded, one shard per node, and read back as they
/// were, through any node; the replicas' files go.
#[tokio::test]
async fn cold_blobs_are_coded() {
    let Some(cluster) = coding(4, 2, 3, None).await else { return };
    let a = &cluster.nodes[0];
    let body = data(1, 5 * MIB + 12345);
    put(a, "k", body.clone()).await;
    let replicated = blob_of(a, "k").await;
    let (layout, holders) = shards_of(&cluster, replicated).await;
    assert_eq!((layout.data_shards, layout.parity_shards, holders.len()), (1, 1, 2), "uploads are replicated");
    assert_intact(&cluster, replicated).await;

    let reports = packer::pass(a).await.unwrap();
    assert_eq!(reports.len(), 1);
    assert!(reports[0].to_string().starts_with("erasure-coded 1 blobs"), "{}", reports[0]);
    let coded = blob_of(a, "k").await;
    assert_ne!(coded, replicated);
    let (layout, mut holders) = shards_of(&cluster, coded).await;
    assert_eq!((layout.data_shards, layout.parity_shards, layout.size), (3, 1, body.len() as u64));
    holders.sort();
    holders.dedup();
    assert_eq!(holders.len(), 4, "every shard on a node of its own");
    assert_intact(&cluster, coded).await;
    for app in &cluster.nodes {
        assert_reads(app, "k", &body).await;
        assert_reaped(app, replicated).await;
    }
    // Nothing is left to do.
    assert!(packer::pass(a).await.unwrap().is_empty());
}

/// Data is coded only once it's cold, and only while coding is on.
#[tokio::test]
async fn only_cold_data_is_coded() {
    let config = Config {
        cold_age: Duration::from_secs(3600),
        ..pack()
    };
    let Some(cluster) = cluster_with(4, 2, config, None).await else { return };
    let a = &cluster.nodes[0];
    put(a, "k", data(2, 2 * MIB)).await;
    let client = a.pool.get().await.unwrap();
    client
        .batch_execute(
            "UPDATE blobs SET created_at = created_at - INTERVAL '2 hours';
             UPDATE parts SET created_at = created_at - INTERVAL '2 hours';",
        )
        .await
        .unwrap();
    assert!(packer::pass(a).await.unwrap().is_empty(), "coding is off");
    set_data_shards(a, 3).await;
    put(a, "young", data(3, 2 * MIB)).await;
    let reports = packer::pass(a).await.unwrap();
    assert_eq!(reports.len(), 1, "the old blob only");
    assert_eq!(shards_of(&cluster, blob_of(a, "k").await).await.0.data_shards, 3);
    assert_eq!(shards_of(&cluster, blob_of(a, "young").await).await.0.data_shards, 1);
}

/// Coding needs a node for every shard: with fewer live, data stays as it
/// is.
#[tokio::test]
async fn coding_waits_for_nodes_enough() {
    let Some(cluster) = coding(4, 2, 3, None).await else { return };
    let a = &cluster.nodes[0];
    put(a, "k", data(4, 2 * MIB)).await;
    cluster.stop(3).await;
    assert!(packer::pass(a).await.unwrap().is_empty());
    assert_eq!(shards_of(&cluster, blob_of(a, "k").await).await.0.data_shards, 1);
}

/// A read decodes the cells of a data shard whose file is gone, and flags
/// it; the scrubber rebuilds it from the other shards.
#[tokio::test]
async fn a_missing_shard_is_decoded_and_rebuilt() {
    let Some((cluster, body, blob_id)) = coded_object(None).await else { return };
    let (_, holders) = shards_of(&cluster, blob_id).await;
    let holder = &cluster.nodes[holders[0]];
    std::fs::remove_file(holder.store.blob_path(blob_id)).unwrap();
    let reader = &cluster.nodes[holders[1]];
    assert_reads(reader, "k", &body).await;
    wait_flagged(holder, blob_id).await;
    let report = scrub(holder, Scope::Due).await;
    assert_eq!((report.missing, report.repaired), (1, 1), "{report}");
    assert_intact(&cluster, blob_id).await;
    assert_reads(holder, "k", &body).await;
}

/// A damaged block of a data shard is decoded around, and a damaged parity
/// shard doesn't matter to reads; the scrubber rebuilds both.
#[tokio::test]
async fn damaged_shards_are_decoded_around_and_rebuilt() {
    let Some((cluster, body, blob_id)) = coded_object(None).await else { return };
    let (_, holders) = shards_of(&cluster, blob_id).await;
    // Row 0 of data shard 1, and row 1 of the parity shard.
    let (data_holder, parity_holder) = (&cluster.nodes[holders[1]], &cluster.nodes[holders[3]]);
    flip(data_holder, blob_id, 70_000);
    flip(parity_holder, blob_id, MIB + 70_000);
    assert_reads(&cluster.nodes[holders[0]], "k", &body).await;
    wait_flagged(data_holder, blob_id).await;
    for holder in [data_holder, parity_holder] {
        let report = scrub(holder, Scope::Everything).await;
        assert_eq!((report.damaged, report.repaired), (1, 1), "{report}");
    }
    assert_intact(&cluster, blob_id).await;
    assert_reads(data_holder, "k", &body).await;
}

/// A shard on a node that's down is decoded around.
#[tokio::test]
async fn a_node_down_is_read_around() {
    let Some((cluster, body, blob_id)) = coded_object(None).await else { return };
    let (_, holders) = shards_of(&cluster, blob_id).await;
    cluster.stop(holders[2]).await;
    let reader = &cluster.nodes[holders[0]];
    assert_reads(reader, "k", &body).await;
}

/// Bytes of a data shard that neither it nor a decoding of its row holds
/// intact are lost: reads of them fail up front, reads of the rest work. Once
/// a shard turns out to hold its bytes after all, they aren't, and the others
/// are rebuilt.
#[tokio::test]
async fn rows_that_cant_be_decoded_are_lost() {
    let Some((cluster, body, blob_id)) = coded_object(None).await else { return };
    let (_, holders) = shards_of(&cluster, blob_id).await;
    let (first, second) = (&cluster.nodes[holders[0]], &cluster.nodes[holders[1]]);
    // Block 1 of row 0 on two data shards: with one parity shard, the row
    // can't be decoded for either.
    let intact = std::fs::read(first.store.blob_path(blob_id)).unwrap();
    flip(first, blob_id, 70_000);
    flip(second, blob_id, 70_000);
    for holder in [first, second] {
        let report = scrub(holder, Scope::Everything).await;
        assert_eq!((report.damaged, report.repaired, report.lost), (1, 0, 1), "{report}");
    }
    let block = 64 * 1024;
    let mib = MIB as i64;
    assert_eq!(lost(first, blob_id).await, [(block, 2 * block), (mib + block, mib + 2 * block)]);
    let (status, _) = read(first, "k", Some("bytes=70000-70010")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let (status, got) = read(first, "k", Some("bytes=0-1000")).await;
    assert_eq!((status, got.unwrap()), (StatusCode::PARTIAL_CONTENT, body[..=1000].to_vec()));

    // The first shard's file turns up intact (it was on a disk that came
    // back, say).
    std::fs::write(first.store.blob_path(blob_id), &intact).unwrap();
    let report = scrub(first, Scope::Everything).await;
    assert_eq!(report.damaged, 0, "{report}");
    assert_eq!(lost(first, blob_id).await, [(mib + block, mib + 2 * block)]);
    // The second is due for a check again, and can be rebuilt now.
    let report = scrub(second, Scope::Due).await;
    assert_eq!((report.damaged, report.repaired), (1, 1), "{report}");
    assert!(lost(first, blob_id).await.is_empty());
    assert_intact(&cluster, blob_id).await;
    assert_reads(first, "k", &body).await;
}

/// Coded data that's compacted stays coded, and cold data that's consolidated
/// is coded as it's packed.
#[tokio::test]
async fn packing_keeps_cold_data_coded() {
    let Some(cluster) = coding(4, 2, 3, None).await else { return };
    let a = &cluster.nodes[0];
    let bodies: Vec<Vec<u8>> = (0..6).map(|i| data(10 + i, 3 * MIB / 2)).collect();
    for (i, body) in bodies.iter().enumerate() {
        put(a, &format!("o{i}"), body.clone()).await;
    }
    // Small ones, which are consolidated: 12 of 600 KiB fill a blob.
    let small: Vec<Vec<u8>> = (0..14).map(|i| data(20 + i, 600 * 1024)).collect();
    for (i, body) in small.iter().enumerate() {
        put(a, &format!("s{i}"), body.clone()).await;
    }
    packer::pass(a).await.unwrap();
    let coded = "SELECT count(*) FROM blobs WHERE state = 'committed' AND data_shards = 3";
    let all = "SELECT count(*) FROM blobs WHERE state = 'committed'";
    assert_eq!(query_i64(a, coded).await, query_i64(a, all).await, "everything is coded");
    // A third of each blob of the larger ones goes, which compaction frees.
    delete(a, "o1").await;
    delete(a, "o4").await;
    let reports: Vec<String> = packer::pass(a).await.unwrap().iter().map(ToString::to_string).collect();
    assert!(reports.iter().any(|r| r.starts_with("compacted")), "{reports:?}");
    assert_eq!(query_i64(a, coded).await, query_i64(a, all).await, "everything is still coded");
    for (i, body) in bodies.iter().enumerate().filter(|(i, _)| ![1, 4].contains(i)) {
        assert_eq!(get(a, &format!("o{i}")).await.unwrap(), *body);
    }
    for (i, body) in small.iter().enumerate() {
        assert_eq!(get(a, &format!("s{i}")).await.unwrap(), *body);
    }
}

/// A conversion that an object's deletion overtakes leaves its bytes in the
/// coded blob as garbage, and moves the rest.
#[tokio::test]
async fn a_conversion_racing_a_delete_moves_the_rest() {
    let hook: Hook = Arc::new(|app, stage| {
        Box::pin(async move {
            if stage == Stage::Copied {
                delete(&app, "gone").await;
            }
        })
    });
    let Some(cluster) = coding(4, 2, 3, Some(hook)).await else { return };
    let a = &cluster.nodes[0];
    let (kept, gone) = (data(30, 3 * MIB / 2), data(31, 3 * MIB / 2));
    put(a, "kept", kept.clone()).await;
    put(a, "gone", gone).await;
    packer::pass(a).await.unwrap();
    assert!(get(a, "gone").await.is_none());
    assert_eq!(get(a, "kept").await.unwrap(), kept);
    let blob_id = blob_of(a, "kept").await;
    let (layout, _) = shards_of(&cluster, blob_id).await;
    assert_eq!(layout.data_shards, 3);
    let dead = format!("SELECT dead_size FROM blobs WHERE blob_id = '{blob_id}'");
    assert_eq!(query_i64(a, &dead).await, 3 * MIB as i64 / 2, "the deleted object's bytes");
}

/// Every coded shard's file holds a copy of every shard's table: a damaged
/// copy in one file is passed over, by reads that decode and by repairs, and
/// the file holding it is repaired from its own data.
#[tokio::test]
async fn damaged_table_copies_are_passed_over() {
    let Some((cluster, body, blob_id)) = coded_object(None).await else { return };
    let (layout, holders) = shards_of(&cluster, blob_id).await;
    let (first, second) = (&cluster.nodes[holders[0]], &cluster.nodes[holders[1]]);
    // In the second shard's file, its copies of the first shard's table
    // (block 1) and of the third's: the tables follow the data, in order.
    let tables_start = layout.shard_size(1) as usize;
    let table_len = |shard: u32| 4 * layout.shard_size(shard).div_ceil(layout.block_size) as usize;
    flip(second, blob_id, tables_start + 4);
    flip(second, blob_id, tables_start + table_len(0) + table_len(1) + 4);
    std::fs::remove_file(first.store.blob_path(blob_id)).unwrap();
    assert_reads(&cluster.nodes[holders[2]], "k", &body).await;
    wait_flagged(second, blob_id).await;
    let report = scrub(first, Scope::Everything).await;
    assert_eq!((report.missing, report.repaired), (1, 1), "{report}");
    let report = scrub(second, Scope::Everything).await;
    assert_eq!((report.damaged, report.repaired), (1, 1), "{report}");
    assert_intact(&cluster, blob_id).await;
}

/// A shard's lost bytes are what its last repair couldn't rebuild: rows that
/// can be decoded again aren't lost anymore.
#[tokio::test]
async fn lost_bytes_shrink_as_rows_can_be_decoded() {
    let Some((cluster, body, blob_id)) = coded_object(None).await else { return };
    let (_, holders) = shards_of(&cluster, blob_id).await;
    let [first, second, third] = [0, 1, 2].map(|s| &cluster.nodes[holders[s]]);
    // The first shard is damaged in rows 0 and 1, the second in row 0, and
    // the third shard's file is away for a while.
    flip(first, blob_id, 70_000);
    flip(first, blob_id, MIB + 70_000);
    flip(second, blob_id, 70_000);
    let path = third.store.blob_path(blob_id);
    let away = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    let report = scrub(first, Scope::Everything).await;
    assert_eq!((report.damaged, report.lost), (1, 1), "{report}");
    let block = 64 * 1024;
    let row1 = 3 * MIB as i64;
    assert_eq!(lost(first, blob_id).await, [(block, 2 * block), (row1 + block, row1 + 2 * block)]);
    std::fs::write(&path, &away).unwrap();
    // Row 1 decodes now; row 0 doesn't, with the second shard damaged there.
    let report = scrub(first, Scope::Everything).await;
    assert_eq!((report.damaged, report.lost), (1, 1), "{report}");
    assert_eq!(lost(first, blob_id).await, [(block, 2 * block)]);
    let (status, got) = read(first, "k", Some(&format!("bytes={}-{}", row1 + block, row1 + block + 10))).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    let at = (row1 + block) as usize;
    assert_eq!(got.unwrap(), body[at..=at + 10]);
}

/// A shard has one location: a node that stores a shard another node holds
/// fails to record it, and deletes its file.
#[tokio::test]
async fn a_shard_has_one_location() {
    let Some(cluster) = cluster_with(2, 1, pack(), None).await else { return };
    let a = &cluster.nodes[0];
    put(a, "k", vec![1; 10]).await;
    let blob_id = blob_of(a, "k").await;
    let (_, holders) = shards_of(&cluster, blob_id).await;
    let other = &cluster.nodes[1 - holders[0]];
    let write = crate::ShardWrite::Replica { blob_id, shard: 0 };
    let body = http_body_util::Full::new(hyper::body::Bytes::from(vec![1; 10]));
    assert!(crate::write_blob_streaming(other, &write, body).await.is_err());
    assert!(other.store.open_blob(blob_id).await.unwrap().is_none(), "its file is gone");
    let locations = format!("SELECT count(*) FROM blob_locations WHERE blob_id = '{blob_id}'");
    assert_eq!(query_i64(a, &locations).await, 1);
}
