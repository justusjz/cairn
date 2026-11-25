//! End-to-end tests of placement by failure domains (see `crate::e2e`):
//! new blobs keep to their class's caps, or are refused; the mover moves
//! the shards of blobs that don't anymore; the catalog refuses a move that
//! would crowd a domain.

use std::sync::Arc;

use uuid::Uuid;

use super::{Caps, Location};
use crate::{
    App,
    classes::{self, Change},
    e2e::{Cluster, cluster_located, get, put, put_sized},
    shards::e2e::{assert_intact, blob_of, data, pack, set_data_shards, shards_of},
};

const MIB: usize = 1024 * 1024;

/// A node in `region`, on `rack`, if it's given.
fn at(region: &str, rack: Option<&str>) -> Location {
    let mut location = Location::default();
    location.0[1] = Some(region.to_owned());
    location.0[3] = rack.map(str::to_owned);
    location
}

/// A cluster of a node at each of `locations`, in the pool `default`,
/// writing `replication_factor` copies of every blob.
async fn cluster_at(locations: &[Location], replication_factor: usize) -> Option<Cluster> {
    let pools: &[&str] = &[classes::DEFAULT_POOL];
    let nodes: Vec<(&[&str], Location)> = locations.iter().map(|l| (pools, l.clone())).collect();
    cluster_located(&nodes, replication_factor, pack(), None).await
}

/// Caps STANDARD as `cairn class set STANDARD --max-per` does; its
/// warnings.
async fn cap(app: &App, caps: &str) -> Vec<String> {
    let change = Change {
        max_per: Some(Caps::parse(caps).unwrap()),
        ..Change::default()
    };
    classes::set(app, classes::STANDARD, change)
        .await
        .unwrap()
        .warnings
}

/// The regions of the nodes that hold a blob's shards, sorted.
async fn regions_of(cluster: &Cluster, blob_id: Uuid) -> Vec<String> {
    let (_, holders) = shards_of(cluster, blob_id).await;
    let mut regions: Vec<String> = holders
        .iter()
        .map(|&i| cluster.nodes[i].location.0[1].clone().unwrap())
        .collect();
    regions.sort();
    regions
}

/// Sets a node's state, as `cairn node remove` and `keep` do.
async fn set_state(app: &Arc<App>, state: &str) {
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

/// With one copy a region, every blob's copies are in regions of their
/// own, though one region has more nodes (and racks) than the others; and
/// with too few regions live, uploads are refused rather than doubled up.
#[tokio::test]
async fn copies_go_to_regions_of_their_own() {
    let Some(cluster) = cluster_at(
        &[
            at("fsn", Some("r1")),
            at("fsn", Some("r2")),
            at("fsn", Some("r3")),
            at("hel", None),
            at("ams", None),
        ],
        3,
    )
    .await
    else {
        return;
    };
    let a = &cluster.nodes[0];
    // Three copies, a region each, in three regions: one down, and
    // uploads are refused.
    let warnings = cap(a, "region=1").await;
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("while the region fsn, hel, ams is down")
                || w.contains("while the region ams, fsn, hel is down")),
        "{warnings:?}"
    );
    for i in 0..8 {
        let key = format!("k{i}");
        put(a, &key, data(i, 10_000)).await;
        let blob_id = blob_of(a, &key).await;
        assert_eq!(regions_of(&cluster, blob_id).await, ["ams", "fsn", "hel"]);
    }
    // ams is going: two regions are left for three copies.
    set_state(&cluster.nodes[4], "removing").await;
    let refused = put_refused(a, "late").await;
    assert!(refused.contains("at most region=1"), "{refused}");
    // Caps on a level some nodes have no label at: those take none.
    set_state(&cluster.nodes[4], "active").await;
    let warnings = cap(a, "region=1,rack=1").await;
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("2 active nodes") && w.contains("no rack label")),
        "{warnings:?}"
    );
    let refused = put_refused(a, "unracked").await;
    assert!(refused.contains("can only take 1"), "{refused}");
}

/// 4+2 across five regions, two of which have two racks: at most two
/// shards a region and one a rack, so the region with two is always one
/// with two racks.
#[tokio::test]
async fn a_second_shard_goes_only_where_there_is_a_second_rack() {
    let Some(cluster) = cluster_at(
        &[
            at("fsn", Some("r1")),
            at("fsn", Some("r2")),
            at("hel", Some("r1")),
            at("hel", Some("r2")),
            at("ams", Some("r1")),
            at("ams", Some("r1")),
            at("par", Some("r1")),
            at("waw", Some("r1")),
        ],
        3,
    )
    .await
    else {
        return;
    };
    let a = &cluster.nodes[0];
    set_data_shards(a, 4).await;
    // 2 + 2 + 1 + 1 + 1 nodes can take a shard: without fsn or hel, only 5.
    let warnings = cap(a, "region=2,rack=1").await;
    assert_eq!(
        warnings,
        [
            "while the region fsn, hel is down, the rest can't take all 6 of a blob's shards: \
          uploads into STANDARD fail until it's back"
        ],
    );
    for i in 0..4 {
        let key = format!("big{i}");
        put_sized(a, &key, data(i, 5 * MIB)).await;
        let blob_id = blob_of(a, &key).await;
        let (layout, holders) = shards_of(&cluster, blob_id).await;
        assert_eq!((layout.data_shards, layout.parity_shards), (4, 2));
        let regions = regions_of(&cluster, blob_id).await;
        for region in ["ams", "par", "waw"] {
            assert!(
                regions.iter().filter(|r| *r == region).count() <= 1,
                "{regions:?}"
            );
        }
        let racks: std::collections::HashSet<_> = holders
            .iter()
            .map(|&i| cluster.nodes[i].location.clone())
            .collect();
        assert_eq!(racks.len(), 6, "a rack each: {regions:?}");
    }
}

/// A blob written before its class was capped, with two copies in one
/// region, has one of them moved to another region by the mover's sweep;
/// the catalog refuses to crowd the region again.
#[tokio::test]
async fn new_caps_move_crowded_shards() {
    let Some(cluster) = cluster_at(&[at("fsn", None), at("fsn", None), at("hel", None)], 2).await
    else {
        return;
    };
    let a = &cluster.nodes[0];
    // hel takes nothing while it's being removed: both copies go to fsn.
    set_state(&cluster.nodes[2], "removing").await;
    let body = data(7, 300_000);
    put(a, "k", body.clone()).await;
    let blob_id = blob_of(a, "k").await;
    assert_eq!(regions_of(&cluster, blob_id).await, ["fsn", "fsn"]);
    set_state(&cluster.nodes[2], "active").await;
    // Nothing to sweep for without caps.
    let report = crate::mover::pass(a).await.unwrap();
    assert_eq!(report.respread, 0, "{report}");

    cap(a, "region=1").await;
    let report = crate::mover::pass(a).await.unwrap();
    assert_eq!((report.respread, report.failed), (1, 0), "{report}");
    assert_eq!(regions_of(&cluster, blob_id).await, ["fsn", "hel"]);
    assert_intact(&cluster, blob_id).await;
    assert_eq!(get(a, "k").await.unwrap(), body);
    // The sweep is done, and finds nothing more.
    let report = crate::mover::pass(a).await.unwrap();
    assert_eq!(report.respread, 0, "{report}");

    // The other fsn node can't take a copy: fsn has one.
    let (_, holders) = shards_of(&cluster, blob_id).await;
    let fsn = holders.iter().copied().find(|&i| i < 2).unwrap();
    let spare = 1 - fsn;
    let client = a.pool.get().await.unwrap();
    let crowds = |to: usize, from: Option<usize>| {
        let client = &client;
        let to = cluster.nodes[to].node;
        let from = from.map(|f| cluster.nodes[f].node);
        async move {
            client
                .query_one(
                    "SELECT pg_temp.cairn_crowds($1, $2, $3)",
                    &[&blob_id, &to, &from],
                )
                .await
                .unwrap()
                .get::<_, bool>(0)
        }
    };
    assert!(crowds(spare, None).await);
    // But the fsn copy may move there: it leaves fsn as it comes.
    assert!(!crowds(spare, Some(fsn)).await);
}

/// Writes an object that its class's caps can't place; the error.
async fn put_refused(app: &Arc<App>, key: &str) -> String {
    let attach = crate::AttachTarget::Object {
        storage_class: classes::STANDARD.to_owned(),
        bucket: crate::e2e::BUCKET.to_owned(),
        key: key.to_owned(),
        content_type: "application/octet-stream".to_owned(),
        metadata: String::new(),
        conditions: Default::default(),
        sealing: None,
        checksum: crate::e2e::OBJECT_CHECKSUM,
        tags: String::new(),
        lock: Default::default(),
    };
    // A heartbeat first, so the node knows the caps.
    crate::refresh_settings(app).await.unwrap();
    let body = http_body_util::Full::new(hyper::body::Bytes::from(data(1, 1000)));
    match crate::upload_part(app, body, &attach, crate::payload::Payload::unchecked()).await {
        Ok(_) => panic!("{key} was written"),
        Err(e) => format!("{e:#}"),
    }
}
