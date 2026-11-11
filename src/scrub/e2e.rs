//! End-to-end tests of the scrubber (see `crate::e2e`).

use std::{sync::Arc, time::Duration};

use http_body_util::BodyExt;
use uuid::Uuid;

use super::{Pacer, Report, Scope, pass, tidy_findings};
use crate::{
    App,
    e2e::{BUCKET, Cluster, cluster, delete, get, node_with, put, query_i64},
    packer,
    s3::{conditional::Preconditions, objects},
};

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

async fn scrub(app: &Arc<App>, scope: Scope) -> Report {
    pass(app, scope, &Pacer::new(None)).await.unwrap()
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

/// Flips a bit of a blob's file on this node.
fn flip(app: &App, blob_id: Uuid, at: usize) {
    let path = app.store.blob_path(blob_id);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[at] ^= 1;
    std::fs::write(&path, bytes).unwrap();
}

/// Sets when this node's copy of a blob was last checked, as SQL.
async fn set_checked(app: &App, blob_id: Uuid, checked_at: &str) {
    let client = app.pool.get().await.unwrap();
    client
        .execute(
            &format!("UPDATE blob_locations SET checked_at = {checked_at} WHERE blob_id = $1"),
            &[&blob_id],
        )
        .await
        .unwrap();
}

/// The findings for a blob: (problem, bad blocks, outcome), oldest first.
async fn findings(app: &App, blob_id: Uuid) -> Vec<(String, Option<Vec<i64>>, Option<String>)> {
    let client = app.pool.get().await.unwrap();
    client
        .query(
            "SELECT problem, bad_blocks, outcome FROM scrub_findings WHERE blob_id = $1 ORDER BY id",
            &[&blob_id],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect()
}

/// New copies are known intact as written, and only checked once due; every
/// copy can be checked at once on request.
#[tokio::test]
async fn checks_what_is_due() {
    let Some(app) = node().await else { return };
    for i in 0..5 {
        put(&app, &format!("k{i}"), vec![i as u8; 200_000]).await;
    }
    let unchecked = "SELECT count(*) FROM blob_locations WHERE checked_at IS NULL";
    assert_eq!(query_i64(&app, unchecked).await, 0, "replicas mark their copies");
    assert_eq!(scrub(&app, Scope::Due).await.copies, 0);

    let report = scrub(&app, Scope::Everything).await;
    assert_eq!((report.copies, report.bytes), (5, 5 * 200_000), "{report}");
    assert_eq!((report.damaged, report.missing), (0, 0));

    // Copies from before scrubbing, and those checked over a week ago.
    set_checked(&app, blob_of(&app, "k0").await, "NULL").await;
    set_checked(&app, blob_of(&app, "k1").await, "NOW() - INTERVAL '8 days'").await;
    set_checked(&app, blob_of(&app, "k2").await, "NOW() - INTERVAL '6 days'").await;
    assert_eq!(scrub(&app, Scope::Due).await.copies, 2);
    assert_eq!(scrub(&app, Scope::Due).await.copies, 0, "now they're checked");
    assert_eq!(query_i64(&app, "SELECT count(*) FROM scrub_findings").await, 0);
}

/// Damage is found and recorded once per copy, and resolved once the copy is
/// intact again.
#[tokio::test]
async fn finds_damage() {
    let Some(app) = node().await else { return };
    put(&app, "damaged", vec![7; 200_000]).await;
    put(&app, "intact", vec![8; 200_000]).await;
    let blob_id = blob_of(&app, "damaged").await;
    // A bit in the second block (of 64 KiB), and one of the fourth's checksum.
    flip(&app, blob_id, 70_000);
    flip(&app, blob_id, 200_000 + 4 * 3);

    // There's no other replica to repair it from: those blocks are lost.
    let report = scrub(&app, Scope::Everything).await;
    assert_eq!((report.copies, report.damaged, report.lost), (2, 1, 1), "{report}");
    assert_eq!(findings(&app, blob_id).await, [damaged(Some(vec![1, 3]), "lost")]);
    assert_eq!(lost(&app, blob_id).await, [(65536, 131072), (196608, 200000)]);
    // Found again, it's still the one finding, and only what's lost now.
    flip(&app, blob_id, 200_000 + 4 * 3);
    assert_eq!(scrub(&app, Scope::Everything).await.damaged, 1);
    assert_eq!(findings(&app, blob_id).await, [damaged(Some(vec![1]), "lost")]);
    assert_eq!(lost(&app, blob_id).await, [(65536, 131072)]);

    flip(&app, blob_id, 70_000);
    assert_eq!(scrub(&app, Scope::Everything).await.damaged, 0);
    assert_eq!(findings(&app, blob_id).await, [damaged(Some(vec![1]), "repaired")]);
    assert_eq!(lost(&app, blob_id).await, []);
    assert_eq!(get(&app, "damaged").await.unwrap(), vec![7; 200_000]);
}

/// A copy whose file is gone, or isn't the blob's, is at fault as a whole.
#[tokio::test]
async fn finds_missing_and_wrong_files() {
    let Some(app) = node().await else { return };
    put(&app, "missing", vec![1; 1000]).await;
    put(&app, "truncated", vec![2; 1000]).await;
    let missing = blob_of(&app, "missing").await;
    let truncated = blob_of(&app, "truncated").await;
    std::fs::remove_file(app.store.blob_path(missing)).unwrap();
    let path = app.store.blob_path(truncated);
    let bytes = std::fs::read(&path).unwrap();
    std::fs::write(&path, &bytes[..bytes.len() - 1]).unwrap();

    let report = scrub(&app, Scope::Everything).await;
    assert_eq!((report.missing, report.damaged), (1, 1), "{report}");
    let lost_whole = |problem: &str| (problem.to_owned(), None, Some("lost".to_owned()));
    assert_eq!(findings(&app, missing).await, [lost_whole("missing")]);
    assert_eq!(findings(&app, truncated).await, [lost_whole("damaged")]);
    assert_eq!(lost(&app, truncated).await, [(0, 1000)]);

    // Once its blob is deleted, a copy's finding is resolved.
    delete(&app, "missing").await;
    tidy_findings(&app).await.unwrap();
    assert_eq!(
        findings(&app, missing).await,
        [("missing".to_owned(), None, Some("gone".to_owned()))]
    );
    assert_eq!(query_i64(&app, "SELECT count(*) FROM lost_ranges").await, 1, "with its blob");
}

/// A read that runs into a damaged copy has it checked next, even though it
/// isn't due; once it's known damaged, reads don't flag it again.
#[tokio::test]
async fn reads_flag_damage() {
    let Some(app) = node().await else { return };
    put(&app, "k", vec![3; 200_000]).await;
    let blob_id = blob_of(&app, "k").await;
    flip(&app, blob_id, 100);
    let response = objects::get::get_object(&app, BUCKET, "k", None, None, &Preconditions::default(), None, None, false)
        .await
        .unwrap();
    // No replica has the block intact, so the body is cut off.
    assert!(response.into_body().collect().await.is_err());
    let flagged = format!(
        "SELECT count(*) FROM blob_locations WHERE blob_id = '{blob_id}' AND checked_at = '-infinity'"
    );
    wait_for(&app, &flagged, 1).await;

    let report = scrub(&app, Scope::Due).await;
    assert_eq!((report.copies, report.damaged), (1, 1), "{report}");
    assert_eq!(query_i64(&app, &flagged).await, 0);

    let response = objects::get::get_object(&app, BUCKET, "k", None, None, &Preconditions::default(), None, None, false)
        .await
        .unwrap();
    assert!(response.into_body().collect().await.is_err());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(query_i64(&app, &flagged).await, 0, "known damage isn't flagged again");
}

/// Blobs from before checksums can't be checked: they're skipped, and not
/// taken again until they're due.
#[tokio::test]
async fn skips_blobs_from_before_checksums() {
    let Some(app) = node().await else { return };
    put(&app, "old", vec![4; 1000]).await;
    let blob_id = blob_of(&app, "old").await;
    let client = app.pool.get().await.unwrap();
    client
        .execute(
            "UPDATE blobs SET block_size = NULL, crc64nvme = NULL WHERE blob_id = $1",
            &[&blob_id],
        )
        .await
        .unwrap();
    set_checked(&app, blob_id, "NULL").await;
    let report = scrub(&app, Scope::Due).await;
    assert_eq!((report.copies, report.legacy), (0, 1), "{report}");
    assert_eq!(scrub(&app, Scope::Due).await.legacy, 0);
}

/// A finding of damage, as `findings` lists it.
fn damaged(bad_blocks: Option<Vec<i64>>, outcome: &str) -> (String, Option<Vec<i64>>, Option<String>) {
    ("damaged".to_owned(), bad_blocks, Some(outcome.to_owned()))
}

/// The lost ranges of a blob.
pub async fn lost(app: &App, blob_id: Uuid) -> Vec<(i64, i64)> {
    let client = app.pool.get().await.unwrap();
    client
        .query(
            "SELECT start, stop FROM lost_ranges WHERE blob_id = $1 ORDER BY start",
            &[&blob_id],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect()
}

/// Waits until `sql` counts `n`.
async fn wait_for(app: &App, sql: &str, n: i64) {
    for _ in 0..100 {
        if query_i64(app, sql).await == n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("{sql} never counted {n}");
}

/// Every node's file of a blob, as bytes.
fn files(cluster: &Cluster, blob_id: Uuid) -> Vec<Vec<u8>> {
    cluster
        .nodes
        .iter()
        .map(|app| std::fs::read(app.store.blob_path(blob_id)).unwrap())
        .collect()
}

/// A damaged copy is repaired from another replica, whatever the damage: its
/// file ends up as the other's, byte for byte.
#[tokio::test]
async fn repairs_from_other_replicas() {
    let Some(cluster) = cluster(2, 2).await else { return };
    let [a, _] = &cluster.nodes[..] else { unreachable!() };
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    put(a, "k", data.clone()).await;
    let blob_id = blob_of(a, "k").await;
    let intact = files(&cluster, blob_id)[1].clone();
    let path = a.store.blob_path(blob_id);
    type Damage = Box<dyn Fn(&mut Vec<u8>)>;
    let damage: [(&str, Damage); 5] = [
        ("a flipped bit", Box::new(|b| b[100_000] ^= 1)),
        ("a damaged checksum", Box::new(|b| b[300_000 + 4] ^= 1)),
        ("another blob's ID", Box::new(|b| *b.last_mut().unwrap() ^= 1)),
        ("a truncated file", Box::new(|b| b.truncate(1000))),
        ("a missing file", Box::new(|b| b.clear())),
    ];
    for (what, damage) in damage {
        let mut bytes = intact.clone();
        damage(&mut bytes);
        if bytes.is_empty() {
            std::fs::remove_file(&path).unwrap();
        } else {
            std::fs::write(&path, &bytes).unwrap();
        }
        let report = scrub(a, Scope::Everything).await;
        assert_eq!((report.damaged + report.missing, report.repaired), (1, 1), "{what}: {report}");
        assert_eq!(std::fs::read(&path).unwrap(), intact, "{what}");
    }
    let found = findings(a, blob_id).await;
    assert_eq!(found.len(), 5);
    assert!(found.iter().all(|(_, _, outcome)| outcome.as_deref() == Some("repaired")));
    assert_eq!(get(a, "k").await.unwrap(), data);
    assert_eq!(scrub(a, Scope::Everything).await.damaged, 0);
}

/// Two copies damaged in different blocks are each repaired from the other.
#[tokio::test]
async fn copies_repair_each_other() {
    let Some(cluster) = cluster(2, 2).await else { return };
    let [a, b] = &cluster.nodes[..] else { unreachable!() };
    put(a, "k", vec![5; 300_000]).await;
    let blob_id = blob_of(a, "k").await;
    let intact = files(&cluster, blob_id)[0].clone();
    flip(a, blob_id, 10);
    flip(b, blob_id, 200_000);
    assert_eq!(scrub(a, Scope::Everything).await.repaired, 1);
    assert_eq!(scrub(b, Scope::Everything).await.repaired, 1);
    assert_eq!(files(&cluster, blob_id), [intact.clone(), intact]);
}

/// A block damaged on every copy is lost: the copies are left as they are,
/// until a copy turns up intact, which the others are then repaired from.
#[tokio::test]
async fn data_intact_nowhere_is_lost() {
    let Some(cluster) = cluster(2, 2).await else { return };
    let [a, b] = &cluster.nodes[..] else { unreachable!() };
    put(a, "k", vec![6; 300_000]).await;
    let blob_id = blob_of(a, "k").await;
    let intact = files(&cluster, blob_id)[0].clone();
    flip(a, blob_id, 70_000);
    flip(a, blob_id, 200_000);
    flip(b, blob_id, 70_000);
    let damaged_a = files(&cluster, blob_id)[0].clone();
    let report = scrub(a, Scope::Everything).await;
    assert_eq!((report.lost, report.repaired), (1, 0), "{report}");
    assert_eq!(lost(a, blob_id).await, [(65536, 131072)], "block 3 was fetched");
    assert_eq!(files(&cluster, blob_id)[0], damaged_a, "left as it is");
    assert_eq!(scrub(b, Scope::Everything).await.lost, 1);
    assert_eq!(findings(a, blob_id).await.len(), 2);

    // The bytes turn up, on b (restored from a backup, say).
    std::fs::write(b.store.blob_path(blob_id), &intact).unwrap();
    let report = scrub(b, Scope::Everything).await;
    assert_eq!((report.damaged, report.copies), (0, 1), "{report}");
    assert_eq!(lost(a, blob_id).await, []);
    // a's copy was flagged, so it's repaired next, though it isn't due.
    let report = scrub(a, Scope::Due).await;
    assert_eq!(report.repaired, 1, "{report}");
    assert_eq!(files(&cluster, blob_id), [intact.clone(), intact]);
    let outcomes: Vec<_> = findings(a, blob_id).await.into_iter().map(|f| f.2).collect();
    assert_eq!(outcomes, [Some("repaired".to_owned()), Some("repaired".to_owned())]);
}

/// With the other replica's node down, damage can't be repaired, and is only
/// lost as far as can be told: it's tried again within the hour.
#[tokio::test]
async fn a_node_down_is_retried_soon() {
    let Some(cluster) = cluster(2, 2).await else { return };
    let [a, _] = &cluster.nodes[..] else { unreachable!() };
    put(a, "k", vec![9; 1000]).await;
    let blob_id = blob_of(a, "k").await;
    flip(a, blob_id, 10);
    cluster.stop(1).await;
    set_checked(a, blob_id, "NULL").await;
    let report = scrub(a, Scope::Due).await;
    assert_eq!(report.lost, 1, "{report}");
    let soon = format!(
        "SELECT count(*) FROM blob_locations
         WHERE blob_id = '{blob_id}' AND node = {}
           AND checked_at BETWEEN NOW() - INTERVAL '7 days' + INTERVAL '59 minutes'
                              AND NOW() - INTERVAL '7 days' + INTERVAL '61 minutes'",
        a.node
    );
    assert_eq!(query_i64(a, &soon).await, 1);
}

/// A repair whose blob goes away meanwhile leaves no file behind, and one a
/// crash cut short leaves a file the GC deletes after a day.
#[tokio::test]
async fn repairs_leave_nothing_behind() {
    let Some(cluster) = cluster(2, 2).await else { return };
    let [a, _] = &cluster.nodes[..] else { unreachable!() };
    put(a, "k", vec![1; 1000]).await;
    let blob_id = blob_of(a, "k").await;
    let client = a.pool.get().await.unwrap();
    let (size, crc): (i64, i64) = {
        let row = client
            .query_one("SELECT size, crc64nvme FROM blobs WHERE blob_id = $1", &[&blob_id])
            .await
            .unwrap();
        (row.get(0), row.get(1))
    };
    client
        .batch_execute(&format!(
            "SET cairn.protocol = '{}';
             DELETE FROM blob_locations WHERE blob_id = '{blob_id}' AND node = {}",
            crate::db::PROTOCOL,
            a.node
        ))
        .await
        .unwrap();
    std::fs::remove_file(a.store.blob_path(blob_id)).unwrap();
    let layout = crate::checksum::BlockLayout {
        block_size: crate::checksum::BLOCK_SIZE as u64,
        blob_size: size as u64,
    };
    let outcome = super::repair::repair(a, blob_id, layout, crc as u64, None, &Pacer::new(None))
        .await
        .unwrap();
    assert_eq!(outcome, super::repair::Outcome::Repaired);
    assert!(a.store.open_blob(blob_id).await.unwrap().is_none(), "it's not a's anymore");

    let leftover = a.store.blob_path(blob_id).with_file_name(format!("{blob_id}.repair"));
    std::fs::write(&leftover, b"half a copy").unwrap();
    crate::gc::pass(a, crate::gc::Scope::everything()).await;
    assert!(leftover.exists(), "it may be a repair in progress");
    let file = std::fs::File::options().write(true).open(&leftover).unwrap();
    file.set_modified(std::time::SystemTime::now() - Duration::from_secs(25 * 3600))
        .unwrap();
    let report = crate::gc::pass(a, crate::gc::Scope::everything()).await;
    assert!(!leftover.exists(), "{report}");
}
