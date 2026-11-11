//! End-to-end tests of the scrubber (see `crate::e2e`).

use std::{sync::Arc, time::Duration};

use http_body_util::BodyExt;
use uuid::Uuid;

use super::{Pacer, Report, Scope, pass, tidy_findings};
use crate::{
    App,
    e2e::{BUCKET, delete, get, node_with, put, query_i64},
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

    let report = scrub(&app, Scope::Everything).await;
    assert_eq!((report.copies, report.damaged), (2, 1), "{report}");
    assert_eq!(
        findings(&app, blob_id).await,
        [("damaged".to_owned(), Some(vec![1, 3]), None)]
    );
    // Found again, it's still the one finding.
    flip(&app, blob_id, 200_000 + 4 * 3);
    assert_eq!(scrub(&app, Scope::Everything).await.damaged, 1);
    assert_eq!(
        findings(&app, blob_id).await,
        [("damaged".to_owned(), Some(vec![1]), None)]
    );

    flip(&app, blob_id, 70_000);
    assert_eq!(scrub(&app, Scope::Everything).await.damaged, 0);
    assert_eq!(
        findings(&app, blob_id).await,
        [("damaged".to_owned(), Some(vec![1]), Some("repaired".to_owned()))]
    );
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
    assert_eq!(findings(&app, missing).await, [("missing".to_owned(), None, None)]);
    assert_eq!(findings(&app, truncated).await, [("damaged".to_owned(), None, None)]);

    // Once its blob is deleted, a copy's finding is resolved.
    delete(&app, "missing").await;
    tidy_findings(&app).await.unwrap();
    assert_eq!(
        findings(&app, missing).await,
        [("missing".to_owned(), None, Some("gone".to_owned()))]
    );
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
