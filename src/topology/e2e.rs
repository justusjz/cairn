//! End-to-end tests of spreading shards over failure domains (see
//! `crate::e2e`): uploads that keep a class's tolerance or fail, repairs
//! that take the best place there is, and the mover's sweep, which moves
//! shards where the tolerance takes them.

use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use uuid::Uuid;

use crate::{
    App, AttachTarget, UploadResult,
    classes::{Change, STANDARD},
    e2e::{Cluster, cluster_at, get, put},
    payload::Payload,
    s3::conditional::Preconditions,
    shards::e2e::{assert_intact, blob_of, data, pack, shards_of},
    topology::Tolerance,
};

/// Gives STANDARD tolerance `text`, which every node goes by at once.
async fn tolerate(cluster: &Cluster, text: &str) {
    let change = Change {
        tolerance: Some(Tolerance::parse(text).unwrap()),
        ..Change::default()
    };
    crate::classes::set(&cluster.nodes[0], STANDARD, change)
        .await
        .unwrap();
    for node in &cluster.nodes {
        crate::refresh_settings(node).await.unwrap();
    }
}

/// The regions of a blob's shards' nodes, by shard, as `locations` named
/// them for the cluster's nodes.
async fn regions(cluster: &Cluster, locations: &[&str], blob_id: Uuid) -> Vec<String> {
    let (_, holders) = shards_of(cluster, blob_id).await;
    holders
        .iter()
        .map(|&i| locations[i].split('/').next().unwrap().to_owned())
        .collect()
}

/// How many of `regions` there are of the region holding the most.
fn most_in_a_region(regions: &[String]) -> usize {
    regions
        .iter()
        .map(|r| regions.iter().filter(|o| *o == r).count())
        .max()
        .unwrap_or(0)
}

/// Sets node `i`'s state, as `cairn node remove` and `keep` do.
async fn set_state(cluster: &Cluster, i: usize, state: &str) {
    let app = &cluster.nodes[i];
    app.pool
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE nodes SET state = $2, state_since = NOW() WHERE id = $1",
            &[&app.node, &state],
        )
        .await
        .unwrap();
}

/// Uploads an object into STANDARD: whether it was committed, or the error.
async fn try_put(app: &Arc<App>, key: &str, body: Vec<u8>) -> anyhow::Result<()> {
    let attach = AttachTarget::Object {
        storage_class: STANDARD.to_owned(),
        bucket: crate::e2e::BUCKET.to_owned(),
        key: key.to_owned(),
        content_type: "application/octet-stream".to_owned(),
        metadata: String::new(),
        conditions: Preconditions::default(),
        sealing: None,
        checksum: crate::e2e::OBJECT_CHECKSUM,
        tags: String::new(),
        lock: Default::default(),
    };
    let result = crate::upload_part(
        app,
        Full::new(Bytes::from(body)),
        &attach,
        Payload::unchecked(),
    )
    .await?;
    match result {
        UploadResult::Committed { .. } => Ok(()),
        _ => anyhow::bail!("the write wasn't committed"),
    }
}

/// Runs every node's mover once.
async fn move_all(cluster: &Cluster) -> u64 {
    let mut spread = 0;
    for node in &cluster.nodes {
        let report = crate::mover::pass(node).await.unwrap();
        assert_eq!(report.failed, 0, "{report}");
        spread += report.spread;
    }
    spread
}

const SIX: &[&str] = &["a/z1", "a/z2", "b/z1", "b/z2", "c/z1", "c/z1"];

/// With three copies surviving any two regions, each copy is in a region of
/// its own; with a region down, there aren't regions enough, and uploads
/// fail rather than keep less.
#[tokio::test]
async fn uploads_keep_the_tolerance_or_fail() {
    let Some(cluster) = cluster_at(SIX, 3, pack()).await else {
        return;
    };
    tolerate(&cluster, "region=2").await;
    for k in 0..4 {
        let key = format!("k{k}");
        put(&cluster.nodes[0], &key, data(k, 1000)).await;
        let blob_id = blob_of(&cluster.nodes[0], &key).await;
        let regions = regions(&cluster, SIX, blob_id).await;
        assert_eq!(most_in_a_region(&regions), 1, "{regions:?}");
    }
    // Region c down: four live nodes, but in two regions.
    cluster.stop(4).await;
    cluster.stop(5).await;
    let refused = try_put(&cluster.nodes[0], "x", data(9, 1000)).await;
    let error = refused.expect_err("an upload that can't keep the tolerance");
    assert!(
        error.downcast_ref::<crate::Unavailable>().is_some(),
        "{error:#}"
    );
    // Surviving one region still holds, with two regions.
    tolerate(&cluster, "region=1").await;
    try_put(&cluster.nodes[0], "x", data(9, 1000))
        .await
        .unwrap();
    let blob_id = blob_of(&cluster.nodes[0], "x").await;
    assert!(most_in_a_region(&regions(&cluster, SIX, blob_id).await) <= 2);
}

/// Blobs written before their class had a tolerance are moved by the mover
/// until they keep it, and stay put once they do.
#[tokio::test]
async fn the_mover_spreads_what_breaks_the_tolerance() {
    let Some(cluster) = cluster_at(SIX, 3, pack()).await else {
        return;
    };
    let mut blobs = Vec::new();
    for k in 0..4 {
        let key = format!("k{k}");
        put(&cluster.nodes[0], &key, data(k, 1000)).await;
        blobs.push((key.clone(), blob_of(&cluster.nodes[0], &key).await));
    }
    // Without a tolerance, nothing moves.
    assert_eq!(move_all(&cluster).await, 0);
    tolerate(&cluster, "region=2").await;
    move_all(&cluster).await;
    for (key, blob_id) in &blobs {
        let regions = regions(&cluster, SIX, *blob_id).await;
        assert_eq!(most_in_a_region(&regions), 1, "{key}: {regions:?}");
        assert_intact(&cluster, *blob_id).await;
        assert_eq!(get(&cluster.nodes[3], key).await.unwrap().len(), 1000);
    }
    assert_eq!(move_all(&cluster).await, 0, "it's spread as asked");
}

/// A repair takes the best place there is, even if it breaks the
/// tolerance; once a better one is there, the mover moves the shard on.
#[tokio::test]
async fn a_repair_breaks_the_tolerance_least_until_there_is_better() {
    let locations = &["a", "b", "c", "c", "d"];
    let Some(cluster) = cluster_at(locations, 3, pack()).await else {
        return;
    };
    // d is out of the cluster for now.
    set_state(&cluster, 4, "removing").await;
    tolerate(&cluster, "region=2").await;
    put(&cluster.nodes[0], "k", data(1, 1000)).await;
    let blob_id = blob_of(&cluster.nodes[0], "k").await;
    let (_, holders) = shards_of(&cluster, blob_id).await;
    let a = holders
        .iter()
        .position(|&i| locations[i] == "a")
        .expect("a shard in a");
    // a is lost: its shard can only go to c's other node.
    cluster.stop(holders[a]).await;
    set_state(&cluster, holders[a], "removing").await;
    let report = crate::mover::pass(&cluster.nodes[1]).await.unwrap();
    assert_eq!((report.moved, report.failed), (1, 0), "{report}");
    let now = regions(&cluster, locations, blob_id).await;
    assert_eq!(most_in_a_region(&now), 2, "{now:?}");
    assert_intact(&cluster, blob_id).await;
    // d comes back: one of c's shards moves there.
    set_state(&cluster, 4, "active").await;
    let spread = move_all(&cluster).await;
    assert_eq!(spread, 1);
    let now = regions(&cluster, locations, blob_id).await;
    assert_eq!(most_in_a_region(&now), 1, "{now:?}");
    assert!(now.contains(&"d".to_owned()), "{now:?}");
    assert_intact(&cluster, blob_id).await;
}

/// A dropped copy is one whose loss keeps the tolerance, so nothing has to
/// move after.
#[tokio::test]
async fn dropping_a_copy_keeps_the_tolerance() {
    let locations = &["a", "a", "b", "c", "b"];
    let Some(cluster) = cluster_at(locations, 4, pack()).await else {
        return;
    };
    put(&cluster.nodes[0], "k", data(1, 1000)).await;
    let blob_id = blob_of(&cluster.nodes[0], "k").await;
    let mut before = regions(&cluster, locations, blob_id).await;
    before.sort();
    assert_eq!(before, ["a", "a", "b", "c"], "the first four nodes");
    // Down to three copies, surviving any two regions: only dropping one of
    // a's does, which isn't the fullest node's by any means.
    let client = cluster.nodes[0].pool.get().await.unwrap();
    client
        .execute("UPDATE storage_classes SET parity_shards = 2", &[])
        .await
        .unwrap();
    drop(client);
    tolerate(&cluster, "region=2").await;
    let report = crate::mover::pass(&cluster.nodes[0]).await.unwrap();
    assert_eq!(
        (report.dropped, report.spread, report.failed),
        (1, 0, 0),
        "{report}"
    );
    assert_eq!(move_all(&cluster).await, 0);
    let now = regions(&cluster, locations, blob_id).await;
    assert_eq!(most_in_a_region(&now), 1, "{now:?}");
    assert_intact(&cluster, blob_id).await;
}

/// A class tolerates no more losses at a level than its parity shards, and
/// is warned of a domain whose loss it survives but that stops its uploads.
#[tokio::test]
async fn a_class_tolerates_no_more_than_its_parity() {
    let Some(cluster) = cluster_at(&["a", "b", "c"], 3, pack()).await else {
        return;
    };
    let set = |text: &str| Change {
        tolerance: Some(Tolerance::parse(text).unwrap()),
        ..Change::default()
    };
    let app = &cluster.nodes[0];
    let refused = crate::classes::set(app, STANDARD, set("region=3")).await;
    assert!(refused.is_err(), "three of two parity shards");
    // Three copies in three regions survive any two, but uploads stop with
    // one of them down.
    let changed = crate::classes::set(app, STANDARD, set("region=2"))
        .await
        .unwrap();
    assert!(
        changed.warnings.iter().any(|w| w.contains("region a down")),
        "{:?}",
        changed.warnings
    );
    // And the parity shards can't drop below it either.
    let fewer = Change {
        parity_shards: Some(Some(1)),
        ..Change::default()
    };
    assert!(crate::classes::set(app, STANDARD, fewer).await.is_err());
}
