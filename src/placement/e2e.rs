//! End-to-end tests of placement (see `crate::e2e`): blobs spread over the
//! nodes' locations as they're written, as the mover moves their shards,
//! and once the nodes change.

use std::sync::Arc;

use uuid::Uuid;

use crate::{
    App,
    e2e::{Cluster, cluster_at, get, put},
    mover,
    shards::e2e::{assert_intact, blob_of, data, pack, shards_of},
};

/// The regions (first domains) of the nodes holding a blob's shards, sorted.
async fn regions(cluster: &Cluster, locations: &[&str], blob_id: Uuid) -> Vec<String> {
    let (_, holders) = shards_of(cluster, blob_id).await;
    let mut regions: Vec<String> = holders
        .iter()
        .map(|&i| locations[i].split('/').next().unwrap().to_owned())
        .collect();
    regions.sort();
    regions
}

async fn uneven(app: &App, blob_id: Uuid) -> bool {
    app.pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT uneven FROM blobs WHERE blob_id = $1", &[&blob_id])
        .await
        .unwrap()
        .get(0)
}

async fn moves(app: &Arc<App>) -> mover::Report {
    mover::pass(app).await.unwrap()
}

/// However many nodes a region has, it gets one copy of a blob, as long as
/// there are other regions to take the rest.
#[tokio::test]
async fn new_blobs_are_spread_over_regions() {
    let locations = ["eu/1/a", "eu/1/b", "eu/2/a", "eu/2/b", "us/1/a", "ap/1/a"];
    let Some(cluster) = cluster_at(&locations, 3, pack()).await else {
        return;
    };
    for i in 0..8 {
        let key = format!("k{i}");
        put(
            &cluster.nodes[i % locations.len()],
            &key,
            data(i as u64, 50_000),
        )
        .await;
        let blob_id = blob_of(&cluster.nodes[0], &key).await;
        assert_eq!(
            regions(&cluster, &locations, blob_id).await,
            ["ap", "eu", "us"]
        );
        assert!(!uneven(&cluster.nodes[0], blob_id).await);
    }
}

/// A blob written while a region is down is spread as well as the others
/// allow, and is uneven: the mover leaves it until the region is back.
#[tokio::test]
async fn a_blob_written_while_a_region_is_down_is_uneven() {
    let locations = ["a", "a", "b", "c"];
    let Some(cluster) = cluster_at(&locations, 3, pack()).await else {
        return;
    };
    cluster.stop(3).await;
    put(&cluster.nodes[0], "k", data(1, 50_000)).await;
    let blob_id = blob_of(&cluster.nodes[0], "k").await;
    assert_eq!(
        regions(&cluster, &locations, blob_id).await,
        ["a", "a", "b"]
    );
    assert!(uneven(&cluster.nodes[0], blob_id).await);
    let report = moves(&cluster.nodes[0]).await;
    assert_eq!((report.spread, report.failed), (0, 0), "{report}");
    assert!(report.waiting > 0, "{report}");
    assert!(uneven(&cluster.nodes[0], blob_id).await);
    // Not tried again until the live nodes change.
    assert!(moves(&cluster.nodes[0]).await.is_empty());
}

/// A new region (a node moved to it) gets a shard of the blobs that have
/// two in one region: every blob is checked once the nodes change.
#[tokio::test]
async fn blobs_are_spread_into_a_new_region() {
    let mut locations = vec!["a", "a", "b", "b"];
    let Some(cluster) = cluster_at(&locations, 3, pack()).await else {
        return;
    };
    let body = data(1, 300_000);
    put(&cluster.nodes[0], "k", body.clone()).await;
    let blob_id = blob_of(&cluster.nodes[0], "k").await;
    let (_, holders) = shards_of(&cluster, blob_id).await;
    let spare = (0..4).find(|i| !holders.contains(i)).unwrap();
    let mover = &cluster.nodes[holders[0]];
    // Nothing to do while the nodes are as they were.
    assert!(moves(mover).await.is_empty());
    locations[spare] = "c";
    cluster.locate(&cluster.nodes[spare], "c").await;
    let report = moves(mover).await;
    assert_eq!(
        (report.uneven, report.spread, report.failed),
        (1, 1, 0),
        "{report}"
    );
    assert_eq!(
        regions(&cluster, &locations, blob_id).await,
        ["a", "b", "c"]
    );
    assert!(!uneven(&cluster.nodes[0], blob_id).await);
    assert_intact(&cluster, blob_id).await;
    assert_eq!(get(&cluster.nodes[spare], "k").await.unwrap(), body);
    // Checked against these nodes already.
    assert!(moves(mover).await.is_empty());
}

/// A node that's removed hands its shard to a node of its own region, not
/// to one of a region that has a shard already.
#[tokio::test]
async fn a_removed_nodes_shards_stay_in_its_region() {
    let locations = ["a", "a", "b", "b", "c", "c"];
    let Some(cluster) = cluster_at(&locations, 3, pack()).await else {
        return;
    };
    put(&cluster.nodes[0], "k", data(1, 50_000)).await;
    let blob_id = blob_of(&cluster.nodes[0], "k").await;
    let (_, holders) = shards_of(&cluster, blob_id).await;
    let leaving = holders[0];
    let sibling = if leaving % 2 == 0 {
        leaving + 1
    } else {
        leaving - 1
    };
    crate::nodes::remove(
        &cluster.nodes[0].pool.get().await.unwrap(),
        cluster.nodes[leaving].node,
    )
    .await
    .unwrap()
    .unwrap();
    let report = moves(&cluster.nodes[holders[1]]).await;
    assert_eq!((report.moved, report.failed), (1, 0), "{report}");
    let (_, now) = shards_of(&cluster, blob_id).await;
    assert_eq!(now[0], sibling);
    assert_eq!(
        regions(&cluster, &locations, blob_id).await,
        ["a", "b", "c"]
    );
    assert!(!uneven(&cluster.nodes[0], blob_id).await);
}

/// 4 + 2 over 5 datacenters, two of them with two racks: the datacenter
/// that gets two shards is one with two racks, so that no rack holds two,
/// even though the single-rack datacenters' nodes are emptier.
#[tokio::test]
async fn a_coded_blob_doubles_up_in_a_datacenter_with_two_racks() {
    let locations = [
        "a/r1/h1", "b/r1/h1", "c/r1/h1", "c/r1/h2", "d/r1/h1", "d/r2/h1", "e/r1/h1", "e/r2/h1",
    ];
    let Some(cluster) = cluster_at(&locations, 3, pack()).await else {
        return;
    };
    crate::shards::e2e::set_data_shards(&cluster.nodes[0], 4).await;
    for app in &cluster.nodes {
        crate::refresh_settings(app).await.unwrap();
    }
    let body = data(1, 5 * 1024 * 1024);
    crate::e2e::put_sized(&cluster.nodes[0], "k", body.clone()).await;
    let blob_id = blob_of(&cluster.nodes[0], "k").await;
    let (layout, holders) = shards_of(&cluster, blob_id).await;
    assert_eq!((layout.data_shards, layout.parity_shards), (4, 2));
    let mut racks: Vec<&str> = holders
        .iter()
        .map(|&i| &locations[i][..locations[i].rfind('/').unwrap()])
        .collect();
    racks.sort();
    racks.dedup();
    assert_eq!(racks.len(), 6, "{racks:?}");
    assert!(!uneven(&cluster.nodes[0], blob_id).await);
    assert_eq!(get(&cluster.nodes[0], "k").await.unwrap(), body);
}
