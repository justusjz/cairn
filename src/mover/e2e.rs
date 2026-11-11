//! End-to-end tests of the mover (see `crate::e2e`): shards moved off nodes
//! that are removed, drained or down, onto the others.

use std::{sync::Arc, time::Duration};

use uuid::Uuid;

use super::{Report, pass};
use crate::{
    App,
    e2e::{Cluster, assert_reaped, cluster_with, get, put, query_i64},
    shards::e2e::{assert_intact, assert_reads, blob_of, coded_object_on, data, pack, shards_of},
};

async fn moves(app: &Arc<App>) -> Report {
    pass(app).await.unwrap()
}

/// Sets a node's state, as `cairn node remove` and `keep` do.
async fn set_state(cluster: &Cluster, i: usize, state: &str) {
    let app = &cluster.nodes[i];
    app.pool
        .get()
        .await
        .unwrap()
        .execute("UPDATE nodes SET state = $2, state_since = NOW() WHERE id = $1", &[&app.node, &state])
        .await
        .unwrap();
}

async fn state(cluster: &Cluster, i: usize) -> String {
    let app = &cluster.nodes[i];
    let client = app.pool.get().await.unwrap();
    client.query_one("SELECT state FROM nodes WHERE id = $1", &[&app.node]).await.unwrap().get(0)
}

/// A node of the cluster other than those in `not`.
fn other(cluster: &Cluster, not: &[usize]) -> usize {
    (0..cluster.nodes.len()).find(|i| !not.contains(i)).unwrap()
}

/// A replicated blob's copy on a node that's gone is copied from the other
/// one onto a third, and the node is removed once it holds nothing.
#[tokio::test]
async fn a_removed_dead_node_is_rebuilt_elsewhere() {
    let Some(cluster) = cluster_with(3, 2, pack(), None).await else { return };
    let body = data(1, 300_000);
    put(&cluster.nodes[0], "k", body.clone()).await;
    let blob_id = blob_of(&cluster.nodes[0], "k").await;
    let (_, holders) = shards_of(&cluster, blob_id).await;
    let gone = holders[0];
    cluster.stop(gone).await;
    set_state(&cluster, gone, "removing").await;
    let mover = &cluster.nodes[other(&cluster, &[gone])];
    let report = moves(mover).await;
    assert_eq!((report.moved, report.failed, report.removed), (1, 0, 1), "{report}");
    let (_, now) = shards_of(&cluster, blob_id).await;
    assert!(!now.contains(&gone), "{now:?}");
    assert_eq!(now[1], holders[1], "the other shard stays");
    assert_intact(&cluster, blob_id).await;
    assert_eq!(get(mover, "k").await.unwrap(), body);
    assert_eq!(state(&cluster, gone).await, "removed");
    assert!(moves(mover).await.is_empty());
}

/// A coded shard on a node that's gone is decoded from the others onto a
/// spare node, and reads go there again, without decoding.
#[tokio::test]
async fn a_coded_shard_is_decoded_onto_a_spare_node() {
    let Some((cluster, body, blob_id)) = coded_object_on(5, None).await else { return };
    let (_, holders) = shards_of(&cluster, blob_id).await;
    let gone = holders[1];
    let spare = other(&cluster, &holders);
    cluster.stop(gone).await;
    set_state(&cluster, gone, "removing").await;
    let report = moves(&cluster.nodes[holders[0]]).await;
    assert_eq!((report.moved, report.failed), (1, 0), "{report}");
    let (_, now) = shards_of(&cluster, blob_id).await;
    assert_eq!(now[1], spare);
    assert_intact(&cluster, blob_id).await;
    assert_reads(&cluster.nodes[spare], "k", &body).await;
}

/// A live node that's removed is drained: its shards are copied from it onto
/// the other nodes, and its files are reaped.
#[tokio::test]
async fn a_live_node_is_drained() {
    let Some((cluster, body, coded)) = coded_object_on(5, None).await else { return };
    let (_, holders) = shards_of(&cluster, coded).await;
    let draining = holders[3];
    put(&cluster.nodes[0], "r", data(2, 200_000)).await;
    let replicated = blob_of(&cluster.nodes[0], "r").await;
    set_state(&cluster, draining, "removing").await;
    let report = moves(&cluster.nodes[holders[0]]).await;
    assert_eq!(report.failed, 0, "{report}");
    assert_eq!(state(&cluster, draining).await, "removed");
    for blob_id in [coded, replicated] {
        let (_, now) = shards_of(&cluster, blob_id).await;
        assert!(!now.contains(&draining), "{now:?}");
        assert_intact(&cluster, blob_id).await;
        assert_reaped(&cluster.nodes[draining], blob_id).await;
    }
    assert_reads(&cluster.nodes[holders[0]], "k", &body).await;
}

/// A replicated blob whose only other copy is missing is drained from the
/// node being removed itself.
#[tokio::test]
async fn draining_copies_from_the_node_itself() {
    let Some(cluster) = cluster_with(3, 2, pack(), None).await else { return };
    let body = data(3, 200_000);
    put(&cluster.nodes[0], "k", body.clone()).await;
    let blob_id = blob_of(&cluster.nodes[0], "k").await;
    let (_, holders) = shards_of(&cluster, blob_id).await;
    let (draining, staying) = (holders[0], holders[1]);
    std::fs::remove_file(cluster.nodes[staying].store.blob_path(blob_id)).unwrap();
    set_state(&cluster, draining, "removing").await;
    let report = moves(&cluster.nodes[staying]).await;
    assert_eq!((report.moved, report.failed), (1, 0), "{report}");
    let target = other(&cluster, &holders);
    let mut file = tokio::fs::File::open(cluster.nodes[target].store.blob_path(blob_id)).await.unwrap();
    let (layout, _) = shards_of(&cluster, blob_id).await;
    let expected = crate::blob_file::ShardFile { blob_id, layout, shard: 0 };
    crate::blob_file::verify(&mut file, &expected).await.unwrap();
}

/// A node that's down only has its shards rebuilt once it's been down for
/// longer than `repair-after`, if that's on; it stays active.
#[tokio::test]
async fn repair_after_rebuilds_a_node_down_long_enough() {
    let Some(cluster) = cluster_with(3, 2, pack(), None).await else { return };
    let mover = &cluster.nodes[0];
    put(mover, "k", data(4, 100_000)).await;
    let blob_id = blob_of(mover, "k").await;
    let (_, holders) = shards_of(&cluster, blob_id).await;
    let down = other(&cluster, &[0]);
    let down = if holders.contains(&down) { down } else { other(&cluster, &[0, down]) };
    cluster.stop(down).await;
    let client = mover.pool.get().await.unwrap();
    client
        .execute(
            "UPDATE nodes SET last_seen = NOW() - INTERVAL '10 minutes' WHERE id = $1",
            &[&cluster.nodes[down].node],
        )
        .await
        .unwrap();
    assert!(moves(mover).await.is_empty(), "repair-after is off");
    crate::settings::REPAIR_AFTER.set(&client, 15).await.unwrap();
    assert!(moves(mover).await.is_empty(), "not down for long enough");
    crate::settings::REPAIR_AFTER.set(&client, 5).await.unwrap();
    let report = moves(mover).await;
    assert_eq!((report.moved, report.removed), (1, 0), "{report}");
    assert_eq!(state(&cluster, down).await, "active");
    assert_intact(&cluster, blob_id).await;
}

/// With no node to move a shard to, it stays where it is, and is tried
/// again.
#[tokio::test]
async fn a_shard_waits_for_a_node_to_move_to() {
    let Some((cluster, body, blob_id)) = coded_object_on(4, None).await else { return };
    let (_, holders) = shards_of(&cluster, blob_id).await;
    set_state(&cluster, holders[2], "removing").await;
    let report = moves(&cluster.nodes[holders[0]]).await;
    assert_eq!((report.moved, report.waiting), (0, 1), "{report}");
    assert_eq!(shards_of(&cluster, blob_id).await.1, holders);
    assert_eq!(state(&cluster, holders[2]).await, "removing");
    assert_reads(&cluster.nodes[holders[0]], "k", &body).await;
}

/// A blob from before checksums on a removed node is upgraded instead,
/// onto active nodes.
#[tokio::test]
async fn blobs_from_before_checksums_are_upgraded_off() {
    let Some(cluster) = cluster_with(3, 2, pack(), None).await else { return };
    let body = data(5, 100_000);
    put(&cluster.nodes[0], "old", body.clone()).await;
    let blob_id = crate::scrub::e2e::make_legacy(&cluster.nodes, "old").await;
    // It has no layout to read: where its copies are, directly.
    let client = cluster.nodes[0].pool.get().await.unwrap();
    let holders: Vec<usize> = client
        .query("SELECT node FROM blob_locations WHERE blob_id = $1", &[&blob_id])
        .await
        .unwrap()
        .iter()
        .map(|r| cluster.nodes.iter().position(|n| n.node == r.get::<_, i32>(0)).unwrap())
        .collect();
    set_state(&cluster, holders[0], "removing").await;
    let report = moves(&cluster.nodes[holders[1]]).await;
    assert_eq!((report.upgraded, report.removed), (1, 1), "{report}");
    let new = blob_of(&cluster.nodes[0], "old").await;
    assert_ne!(new, blob_id);
    let (_, now) = shards_of(&cluster, new).await;
    assert!(!now.contains(&holders[0]));
    assert_eq!(get(&cluster.nodes[0], "old").await.unwrap(), body);
}

/// A move that a deletion of its blob overtakes waits for it, then finds
/// the blob gone, and the new node deletes the file it stored.
#[tokio::test]
async fn a_move_racing_a_delete_moves_nothing() {
    let Some(cluster) = cluster_with(3, 2, pack(), None).await else { return };
    let body = data(6, 100_000);
    put(&cluster.nodes[0], "k", body.clone()).await;
    let blob_id = blob_of(&cluster.nodes[0], "k").await;
    let (_, holders) = shards_of(&cluster, blob_id).await;
    let target = cluster.nodes[other(&cluster, &holders)].clone();
    let from = cluster.nodes[holders[0]].node;
    // A deletion holds the blob exclusively, as `cairn_drop_unreferenced_blobs`
    // has it.
    let mut client = cluster.nodes[0].pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    tx.execute("SELECT 1 FROM blobs WHERE blob_id = $1 FOR UPDATE", &[&blob_id]).await.unwrap();
    tx.execute("DELETE FROM objects WHERE key = 'k'", &[]).await.unwrap();
    tx.execute("DELETE FROM blobs WHERE blob_id = $1", &[&blob_id]).await.unwrap();
    let moving = tokio::spawn({
        let target = target.clone();
        async move {
            let write = crate::ShardWrite::Replica { blob_id, shard: 0 };
            let body = http_body_util::Full::new(hyper::body::Bytes::from(body));
            crate::write_blob_streaming(&target, &write, crate::Placement::Move { from }, body).await
        }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!moving.is_finished(), "the move waits for the deletion");
    tx.commit().await.unwrap();
    let result = moving.await.unwrap();
    assert!(result.unwrap_err().to_string().contains("gone"));
    assert!(target.store.open_blob(blob_id).await.unwrap().is_none(), "its file is gone");
    let locations = format!("SELECT count(*) FROM blob_locations WHERE blob_id = '{blob_id}'");
    assert_eq!(query_i64(&target, &locations).await, 0);
}

/// A shard moving onto a node that holds another shard of its blob is
/// refused, and the shard the node holds stays as it was: a moving shard is
/// written to a file of its own.
#[tokio::test]
async fn a_move_never_touches_another_shards_file() {
    let Some((cluster, body, blob_id)) = coded_object_on(4, None).await else { return };
    let (layout, holders) = shards_of(&cluster, blob_id).await;
    let target = &cluster.nodes[holders[0]];
    let write = crate::ShardWrite::Coded(crate::blob_file::ShardFile { blob_id, layout, shard: 1 });
    let shard = std::fs::read(cluster.nodes[holders[1]].store.blob_path(blob_id)).unwrap();
    let body_of_shard = http_body_util::Full::new(hyper::body::Bytes::from(shard));
    let from = cluster.nodes[holders[1]].node;
    let result = crate::write_blob_streaming(target, &write, crate::Placement::Move { from }, body_of_shard).await;
    assert!(result.is_err());
    assert_intact(&cluster, blob_id).await;
    assert_reads(target, "k", &body).await;
}

/// A removal finishes only once the uploads that may have chosen the node
/// before are done.
#[tokio::test]
async fn a_removal_waits_for_older_uploads() {
    let Some(cluster) = cluster_with(3, 2, pack(), None).await else { return };
    let app = &cluster.nodes[0];
    let client = app.pool.get().await.unwrap();
    let pending = Uuid::now_v7();
    client
        .execute(
            "INSERT INTO blobs (blob_id, size, state, created_at) VALUES ($1, 0, 'pending', NOW())",
            &[&pending],
        )
        .await
        .unwrap();
    set_state(&cluster, 2, "removing").await;
    moves(app).await;
    assert_eq!(state(&cluster, 2).await, "removing");
    client.execute("DELETE FROM blobs WHERE blob_id = $1", &[&pending]).await.unwrap();
    assert_eq!(moves(app).await.removed, 1);
    assert_eq!(state(&cluster, 2).await, "removed");
}

/// A reap leaves a file alone that the catalog places on its node: a shard
/// of the blob may have moved there since the reap was sent.
#[tokio::test]
async fn a_reap_spares_a_placed_file() {
    let Some(cluster) = cluster_with(2, 2, pack(), None).await else { return };
    let app = &cluster.nodes[0];
    put(app, "k", data(7, 1000)).await;
    let blob_id = blob_of(app, "k").await;
    crate::blobs::remove_unplaced(app, blob_id).await.unwrap();
    assert!(app.store.open_blob(blob_id).await.unwrap().is_some());
}

/// Once `parity-shards` is set, every replicated blob gets as many copies:
/// the mover adds them, and drops them again when it's lowered, reaping
/// their files. Unset, it leaves them be.
#[tokio::test]
async fn copies_follow_the_parity_shards_setting() {
    let Some(cluster) = cluster_with(4, 2, pack(), None).await else { return };
    let a = &cluster.nodes[0];
    let body = data(60, 300_000);
    put(a, "k", body.clone()).await;
    let blob_id = blob_of(a, "k").await;
    let client = a.pool.get().await.unwrap();
    crate::settings::PARITY_SHARDS.unset(&client).await.unwrap();
    assert!(moves(a).await.is_empty(), "the setting isn't set");
    crate::settings::PARITY_SHARDS.set(&client, 3).await.unwrap();
    let report = moves(a).await;
    assert_eq!((report.added, report.failed), (2, 0), "{report}");
    let (layout, holders) = shards_of(&cluster, blob_id).await;
    assert_eq!((layout.parity_shards, holders.len()), (3, 4));
    assert_intact(&cluster, blob_id).await;
    assert!(moves(a).await.is_empty());

    crate::settings::PARITY_SHARDS.set(&client, 1).await.unwrap();
    let report = moves(a).await;
    assert_eq!((report.dropped, report.failed), (2, 0), "{report}");
    let (layout, now) = shards_of(&cluster, blob_id).await;
    assert_eq!((layout.parity_shards, now.len()), (1, 2));
    assert_intact(&cluster, blob_id).await;
    for (i, node) in cluster.nodes.iter().enumerate() {
        if !now.contains(&i) {
            assert_reaped(node, blob_id).await;
        }
        assert_eq!(get(node, "k").await.unwrap(), body);
    }
    assert!(moves(a).await.is_empty());
}

/// A dropped copy is one on a node being removed, rather than one the
/// mover would keep.
#[tokio::test]
async fn a_copy_on_a_node_being_removed_is_dropped_first() {
    let Some(cluster) = cluster_with(3, 3, pack(), None).await else { return };
    let a = &cluster.nodes[0];
    put(a, "k", data(61, 1000)).await;
    let blob_id = blob_of(a, "k").await;
    let (_, holders) = shards_of(&cluster, blob_id).await;
    let leaving = holders[1];
    set_state(&cluster, leaving, "removing").await;
    let client = a.pool.get().await.unwrap();
    crate::settings::PARITY_SHARDS.set(&client, 1).await.unwrap();
    // A move would wait for a node to move to: there's none spare.
    let report = moves(a).await;
    assert_eq!((report.moved, report.dropped), (0, 1), "{report}");
    let (_, now) = shards_of(&cluster, blob_id).await;
    assert!(!now.contains(&leaving), "{now:?}");
    assert_eq!(state(&cluster, leaving).await, "removed");
}

/// The copies of a replicated blob the packer is about to code are the
/// packer's to add: it codes it with the parity shards.
#[tokio::test]
async fn blobs_to_be_coded_are_left_to_the_packer() {
    let Some(cluster) = crate::shards::e2e::coding(5, 2, 3, None).await else { return };
    let a = &cluster.nodes[0];
    let large = data(62, 2 * 1024 * 1024);
    put(a, "large", large.clone()).await;
    put(a, "small", data(63, 1000)).await;
    let client = a.pool.get().await.unwrap();
    crate::settings::PARITY_SHARDS.set(&client, 2).await.unwrap();
    for node in &cluster.nodes {
        crate::refresh_settings(node).await.unwrap();
    }
    let report = moves(a).await;
    assert_eq!((report.added, report.failed), (1, 0), "the small one's: {report}");
    let (layout, _) = shards_of(&cluster, blob_of(a, "large").await).await;
    assert_eq!((layout.data_shards, layout.parity_shards), (1, 1));
    crate::packer::pass(a).await.unwrap();
    let (layout, _) = shards_of(&cluster, blob_of(a, "large").await).await;
    assert_eq!((layout.data_shards, layout.parity_shards), (3, 2));
    assert_eq!(get(a, "large").await.unwrap(), large);
    assert!(moves(a).await.is_empty());
}
