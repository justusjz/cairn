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
    let response = objects::get::get_object(&app, BUCKET, "k", None, None, None, &Preconditions::default(), None, None, false)
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

    // Known to be lost now, so the read fails up front, flagging nothing.
    let response = objects::get::get_object(&app, BUCKET, "k", None, None, None, &Preconditions::default(), None, None, false)
        .await
        .unwrap();
    assert_eq!(response.status(), hyper::StatusCode::INTERNAL_SERVER_ERROR);
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
            "UPDATE blobs SET block_size = NULL, shard_crcs = NULL WHERE blob_id = $1",
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
    let (size, crc, shard): (i64, i64, i16) = {
        let row = client
            .query_one(
                "SELECT b.size, b.shard_crcs[bl.shard + 1], bl.shard
                 FROM blobs b JOIN blob_locations bl USING (blob_id)
                 WHERE b.blob_id = $1 AND bl.node = $2",
                &[&blob_id, &a.node],
            )
            .await
            .unwrap();
        (row.get(0), row.get(1), row.get(2))
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
    let file = crate::blob_file::ShardFile {
        blob_id,
        layout: crate::shards::Layout::new(size as u64, 1, 1),
        shard: shard as u32,
    };
    let outcome = super::repair::repair(a, &file, crc as u64, None, &Pacer::new(None))
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

/// Reads (the `range` of) an object through GetObject: its status, and its
/// body, if it arrived whole.
async fn read(app: &Arc<App>, key: &str, range: Option<&str>) -> (hyper::StatusCode, Option<Vec<u8>>) {
    let response = objects::get::get_object(app, BUCKET, key, None, range, None, &Preconditions::default(), None, None, false)
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.ok().map(|b| b.to_bytes().to_vec());
    (status, body)
}

/// Once bytes are known to be lost, reads of them fail up front, and so do
/// copies of them; reads of the rest, and HEAD, work as before.
#[tokio::test]
async fn lost_data_fails_up_front() {
    use hyper::StatusCode;
    let Some(app) = node().await else { return };
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
    put(&app, "k", data.clone()).await;
    let blob_id = blob_of(&app, "k").await;
    flip(&app, blob_id, 70_000);
    // Before the scrubber knows, a read is cut off at the damage, and flags
    // the copy (waited for, since a flag that lands while the scrubber
    // records what it found has it check the copy again).
    assert_eq!(read(&app, "k", None).await, (StatusCode::OK, None));
    let flagged = format!(
        "SELECT count(*) FROM blob_locations WHERE blob_id = '{blob_id}' AND checked_at = '-infinity'"
    );
    wait_for(&app, &flagged, 1).await;
    assert_eq!(scrub(&app, Scope::Everything).await.lost, 1);

    let (status, body) = read(&app, "k", None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(String::from_utf8(body.unwrap()).unwrap().contains("InternalError"));
    let (status, _) = read(&app, "k", Some("bytes=60000-70000")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "it overlaps block 1");
    let (status, body) = read(&app, "k", Some("bytes=0-65535")).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT, "block 0 is intact");
    assert_eq!(body.unwrap(), data[..65536]);
    let (status, body) = read(&app, "k", Some("bytes=131072-")).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(body.unwrap(), data[131072..]);
    let head = objects::get::head_object(&app, BUCKET, "k", None, None, None, &Preconditions::default(), None, None, false)
        .await
        .unwrap();
    assert_eq!(head.status(), StatusCode::OK);

    let source = format!("{BUCKET}/k");
    let copy = objects::copy::copy_object(&app, BUCKET, "copy", &source, None, "text/plain", "", None, &Preconditions::default(), Default::default())
        .await
        .unwrap();
    assert_eq!(copy.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(get(&app, "copy").await.is_none());
    let upload = crate::s3::multipart::create::create_multipart_upload(&app, BUCKET, "assembled", "application/octet-stream", "", "", crate::s3::sse::Wanted::Plain, None, None, Default::default())
        .await
        .unwrap();
    let body = upload.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8(body.to_vec()).unwrap();
    let upload_id = body.split("<UploadId>").nth(1).unwrap().split("</UploadId>").next().unwrap();
    let copy_part = |range: &'static str| {
        let (app, source, upload_id) = (app.clone(), source.clone(), upload_id.to_owned());
        async move {
            objects::copy::copy_part(&app, BUCKET, "assembled", &upload_id, "1", &source, Some(range), &Preconditions::default(), None, None, None)
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(copy_part("bytes=60000-70000").await, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(copy_part("bytes=0-60000").await, StatusCode::OK);

    // Once the bytes are back, so are the reads.
    flip(&app, blob_id, 70_000);
    assert_eq!(scrub(&app, Scope::Everything).await.damaged, 0);
    assert_eq!(read(&app, "k", None).await, (StatusCode::OK, Some(data)));
}

/// The packer leaves blobs whose parts are on lost data alone: those would
/// fail its verification. Once no part is, the blob is packed as any other,
/// and its lost data goes with it.
#[tokio::test]
async fn the_packer_leaves_lost_data_alone() {
    let pack = packer::Config {
        target_size: 1_000_000,
        small_size: 250_000,
        ..packer::Config::default()
    };
    let Some(app) = node_with(pack, None).await else { return };
    let data = |i: u8| vec![i; 200_000];
    for i in 0..6 {
        put(&app, &format!("k{i}"), data(i)).await;
    }
    let damaged = blob_of(&app, "k0").await;
    flip(&app, damaged, 10);
    assert_eq!(scrub(&app, Scope::Everything).await.lost, 1);
    let jobs = packer::pass(&app).await.unwrap();
    assert_eq!(jobs.iter().map(|j| j.counts().0).sum::<usize>(), 5, "all but k0's");
    assert_eq!(blob_of(&app, "k0").await, damaged, "still where it was");
    let packed = blob_of(&app, "k1").await;
    assert_ne!(packed, damaged);

    // A block within k1's part of the packed blob is lost.
    let offset: i64 = app
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT p.blob_offset FROM parts p JOIN objects o ON o.id = p.object_id WHERE o.key = 'k1'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let block = (offset as usize).div_ceil(65536);
    flip(&app, packed, block * 65536 + 10);
    assert_eq!(scrub(&app, Scope::Everything).await.lost, 2);
    // Deleting k2 and k3 makes the blob worth compacting, but k1 is on lost
    // data.
    delete(&app, "k2").await;
    delete(&app, "k3").await;
    assert!(packer::pass(&app).await.unwrap().is_empty());
    // Without k1, it's compacted.
    delete(&app, "k1").await;
    let jobs = packer::pass(&app).await.unwrap();
    assert_eq!(jobs.len(), 1);
    assert_ne!(blob_of(&app, "k4").await, packed);
    assert_eq!(get(&app, "k4").await.unwrap(), data(4));
    assert_eq!(get(&app, "k5").await.unwrap(), data(5));
    assert_eq!(lost(&app, packed).await, [], "they went with the blob");
    assert_eq!(lost(&app, damaged).await.len(), 1, "k0's are still there");
}

/// Makes an object's blob one from before checksums, as an old version of
/// Cairn wrote it: its files bare data, and no checksums in the catalog but
/// its parts' MD5s (their ETags).
pub(crate) async fn make_legacy(nodes: &[Arc<App>], key: &str) -> Uuid {
    let app = &nodes[0];
    let blob_id = blob_of(app, key).await;
    let client = app.pool.get().await.unwrap();
    let size: i64 = client
        .query_one("SELECT size FROM blobs WHERE blob_id = $1", &[&blob_id])
        .await
        .unwrap()
        .get(0);
    client
        .batch_execute(&format!(
            "SET cairn.protocol = '{}';
             UPDATE blobs SET block_size = NULL, shard_crcs = NULL WHERE blob_id = '{blob_id}';
             UPDATE parts SET crc64nvme = NULL WHERE blob_id = '{blob_id}';",
            crate::db::PROTOCOL
        ))
        .await
        .unwrap();
    for node in nodes {
        let path = node.store.blob_path(blob_id);
        if let Ok(bytes) = std::fs::read(&path) {
            std::fs::write(&path, &bytes[..size as usize]).unwrap();
        }
    }
    blob_id
}

/// Whether a blob is checksummed.
async fn checksummed(app: &App, blob_id: Uuid) -> bool {
    let client = app.pool.get().await.unwrap();
    client
        .query_one("SELECT block_size IS NOT NULL FROM blobs WHERE blob_id = $1", &[&blob_id])
        .await
        .unwrap()
        .get(0)
}

/// Blobs from before checksums are upgraded, oldest first, as many as the
/// budget allows, and then scrubbed like any other.
#[tokio::test]
async fn upgrades_blobs_from_before_checksums() {
    let Some(app) = node().await else { return };
    let mut old = Vec::new();
    for i in 0..3u8 {
        let data: Vec<u8> = (0..300_000u32).map(|j| (j % 241) as u8 ^ i).collect();
        put(&app, &format!("old{i}"), data.clone()).await;
        old.push((make_legacy(std::slice::from_ref(&app), &format!("old{i}")).await, data));
    }
    assert_eq!(scrub(&app, Scope::Everything).await.legacy, 3, "skipped, can't be checked");
    // With scrubbing off (as in tests), a pass doesn't upgrade.
    assert!(packer::pass(&app).await.unwrap().is_empty());

    // A budget smaller than a blob still upgrades one: the oldest.
    let reports = packer::upgrade(&app, 1).await.unwrap();
    assert_eq!(reports.len(), 1);
    assert!(checksummed(&app, blob_of(&app, "old0").await).await);
    assert!(!checksummed(&app, old[1].0).await);
    assert_eq!(packer::upgrade(&app, u64::MAX).await.unwrap().len(), 2);
    for (i, (blob_id, data)) in old.iter().enumerate() {
        let key = format!("old{i}");
        assert_ne!(blob_of(&app, &key).await, *blob_id, "{key} moved");
        assert_eq!(get(&app, &key).await.unwrap(), *data);
    }
    assert!(packer::upgrade(&app, u64::MAX).await.unwrap().is_empty());
    let report = scrub(&app, Scope::Everything).await;
    assert_eq!((report.copies, report.legacy, report.damaged), (3, 0, 0), "{report}");
}

/// A replica whose copy doesn't match its parts' MD5s is passed over for the
/// next; with none that does, the parts are lost.
#[tokio::test]
async fn upgrades_from_an_intact_replica() {
    let Some(cluster) = cluster(2, 2).await else { return };
    let [a, b] = &cluster.nodes[..] else { unreachable!() };
    let data: Vec<u8> = (0..300_000u32).map(|j| (j % 239) as u8).collect();
    put(a, "repairable", data.clone()).await;
    put(a, "lost", data.clone()).await;
    let repairable = make_legacy(&cluster.nodes, "repairable").await;
    let lost_blob = make_legacy(&cluster.nodes, "lost").await;
    flip(a, repairable, 1000);
    flip(a, lost_blob, 1000);
    flip(b, lost_blob, 2000);

    let reports = packer::upgrade(a, u64::MAX).await.unwrap();
    assert_eq!(reports.len(), 1, "only one could be upgraded");
    assert!(checksummed(a, blob_of(a, "repairable").await).await);
    assert_eq!(get(a, "repairable").await.unwrap(), data);
    let report = scrub(b, Scope::Everything).await;
    assert_eq!((report.copies, report.damaged), (1, 0), "b's new copy is intact: {report}");

    assert_eq!(blob_of(a, "lost").await, lost_blob, "left as it is");
    assert_eq!(lost(a, lost_blob).await, [(0, 300_000)]);
    let (status, _) = read(a, "lost", None).await;
    assert_eq!(status, hyper::StatusCode::INTERNAL_SERVER_ERROR);
    // It isn't tried again, even once its lease runs out.
    a.pool
        .get()
        .await
        .unwrap()
        .batch_execute(&format!(
            "SET cairn.protocol = '{}'; UPDATE blobs SET pack_lease_until = NULL",
            crate::db::PROTOCOL
        ))
        .await
        .unwrap();
    assert!(packer::upgrade(a, u64::MAX).await.unwrap().is_empty());
}
