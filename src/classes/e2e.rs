//! End-to-end tests of storage classes (see `crate::e2e`): objects written
//! in their class's pool and layout, copied between classes, and moved when
//! a class changes.

use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{StatusCode, body::Bytes};
use uuid::Uuid;

use crate::{
    App, AttachTarget, UploadResult,
    e2e::{BUCKET, Cluster, OBJECT_CHECKSUM, cluster_of_pools, get},
    payload::Payload,
    s3::{
        conditional::Preconditions,
        objects::{copy::{CopyKeys, copy_object}, get::head_object},
        sse::Wanted,
    },
    shards::e2e::{assert_intact, blob_of, data, pack, shards_of},
};

/// Defines (or changes) class `name`, as `cairn class set` does, and has
/// every node of `cluster` go by it.
async fn set_class(cluster: &Cluster, name: &str, pool: &str, data: Option<i16>, parity: Option<i16>) {
    let app = &cluster.nodes[0];
    app.pool
        .get()
        .await
        .unwrap()
        .execute(
            "INSERT INTO storage_classes (name, pool, data_shards, parity_shards) VALUES ($1, $2, $3, $4)
             ON CONFLICT (name) DO UPDATE SET pool = $2, data_shards = $3, parity_shards = $4",
            &[&name, &pool, &data, &parity],
        )
        .await
        .unwrap();
    for node in &cluster.nodes {
        crate::refresh_settings(node).await.unwrap();
    }
}

/// Writes `key` in class `class`, as PutObject does: whether it committed.
async fn put_in(app: &Arc<App>, key: &str, class: &str, body: Vec<u8>) -> anyhow::Result<()> {
    let attach = AttachTarget::Object {
        storage_class: class.to_owned(),
        bucket: BUCKET.to_owned(),
        key: key.to_owned(),
        content_type: "application/octet-stream".to_owned(),
        metadata: String::new(),
        conditions: Preconditions::default(),
        sealing: None,
        checksum: OBJECT_CHECKSUM,
        tags: String::new(),
        lock: Default::default(),
    };
    let result = crate::upload_part(app, Full::new(Bytes::from(body)), &attach, Payload::unchecked()).await?;
    anyhow::ensure!(matches!(result, UploadResult::Committed { .. }), "not committed");
    Ok(())
}

/// A blob's class and pool.
async fn class_of_blob(app: &App, blob_id: Uuid) -> (String, String) {
    let row = app
        .pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT storage_class, pool FROM blobs WHERE blob_id = $1", &[&blob_id])
        .await
        .unwrap();
    (row.get(0), row.get(1))
}

/// The `x-amz-storage-class` a HEAD of `key` tells, if any.
async fn head_class(app: &App, key: &str) -> Option<String> {
    let response = head_object(app, BUCKET, key, None, None, None, &Preconditions::default(), None, None, false)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.headers().get("x-amz-storage-class").map(|v| v.to_str().unwrap().to_owned())
}

/// The storage classes ListObjectsV2 tells, in key order.
async fn listed_classes(app: &App) -> Vec<String> {
    let query = crate::s3::objects::list::ListQuery {
        prefix: "",
        delimiter: None,
        marker: "",
        max_keys: 1000,
        delete_markers: false,
        totals: false,
    };
    let listing = crate::s3::objects::list::list(app, BUCKET, &query).await.unwrap().unwrap();
    listing
        .entries
        .into_iter()
        .filter_map(|entry| match entry {
            crate::s3::objects::list::ListEntry::Object { storage_class, .. } => Some(storage_class),
            _ => None,
        })
        .collect()
}

/// Copies `source` to `dest` as CopyObject does, into `class` (`None`: as a
/// request that names none).
async fn copy_into(app: &Arc<App>, source: &str, dest: &str, class: Option<&str>) {
    let keys = CopyKeys {
        storage_class: class,
        restates: class.is_some(),
        ..Default::default()
    };
    let source = format!("/{BUCKET}/{source}");
    let response = copy_object(app, BUCKET, dest, &source, None, "", "", None, &Preconditions::default(), keys)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// Three nodes with the pool `default`, two of which also have `hdd`; and
/// the class COLD there, with a copy besides the first.
async fn tiered() -> Option<Cluster> {
    let cluster = cluster_of_pools(&[&["default", "hdd"], &["default", "hdd"], &["default"]], 2, pack(), None).await?;
    set_class(&cluster, "COLD", "hdd", None, Some(1)).await;
    Some(cluster)
}

/// An object of a class is stored in its pool, on the nodes that have it,
/// and tells its class; STANDARD's go where they always did.
#[tokio::test]
async fn objects_are_stored_in_their_classs_pool() {
    let Some(cluster) = tiered().await else { return };
    let app = &cluster.nodes[2];
    let cold = data(1, 300_000);
    put_in(app, "cold", "COLD", cold.clone()).await.unwrap();
    put_in(app, "warm", "STANDARD", data(2, 1000)).await.unwrap();

    let blob_id = blob_of(app, "cold").await;
    assert_eq!(class_of_blob(app, blob_id).await, ("COLD".to_owned(), "hdd".to_owned()));
    let (layout, holders) = shards_of(&cluster, blob_id).await;
    assert_eq!(layout.parity_shards, 1);
    let mut holders = holders.clone();
    holders.sort();
    assert_eq!(holders, [0, 1], "only nodes with the pool hold it");
    assert_intact(&cluster, blob_id).await;
    for &i in &holders {
        let store = &cluster.nodes[i].store;
        assert!(store.pool("hdd").unwrap().blob_path(blob_id).exists());
        assert!(!store.pool("default").unwrap().blob_path(blob_id).exists());
    }
    assert_eq!(get(app, "cold").await.unwrap(), cold, "read from the others' hdd pools");

    let warm = blob_of(app, "warm").await;
    assert_eq!(class_of_blob(app, warm).await, ("STANDARD".to_owned(), "default".to_owned()));
    assert_eq!(head_class(app, "cold").await.as_deref(), Some("COLD"));
    assert_eq!(head_class(app, "warm").await, None, "S3 tells no class for STANDARD");
    assert_eq!(listed_classes(app).await, ["COLD", "STANDARD"]);
}

/// A class whose pool has fewer nodes than its blobs take shards can't be
/// written to, as with too few nodes for STANDARD.
#[tokio::test]
async fn a_class_needs_nodes_enough_in_its_pool() {
    let Some(cluster) = tiered().await else { return };
    set_class(&cluster, "COLD", "hdd", None, Some(2)).await;
    let error = put_in(&cluster.nodes[0], "k", "COLD", data(1, 1000)).await.unwrap_err();
    assert!(error.downcast_ref::<crate::Unavailable>().is_some(), "{error:#}");
    set_class(&cluster, "NOWHERE", "ssd", None, None).await;
    assert!(put_in(&cluster.nodes[0], "k", "NOWHERE", data(1, 1000)).await.is_err());
}

/// Classes differ in their redundancy: one with no parity shards keeps a
/// single copy, in the same pool as STANDARD's two.
#[tokio::test]
async fn classes_have_redundancy_of_their_own() {
    let Some(cluster) = tiered().await else { return };
    set_class(&cluster, "REDUCED_REDUNDANCY", "default", None, Some(0)).await;
    let app = &cluster.nodes[0];
    put_in(app, "reduced", "REDUCED_REDUNDANCY", data(1, 1000)).await.unwrap();
    put_in(app, "standard", "STANDARD", data(2, 1000)).await.unwrap();
    let (reduced, _) = shards_of(&cluster, blob_of(app, "reduced").await).await;
    let (standard, _) = shards_of(&cluster, blob_of(app, "standard").await).await;
    assert_eq!((reduced.parity_shards, standard.parity_shards), (0, 1));

    // More redundancy for the class: the mover adds the copy.
    set_class(&cluster, "REDUCED_REDUNDANCY", "default", None, Some(1)).await;
    let report = crate::mover::pass(app).await.unwrap();
    assert_eq!((report.added, report.failed), (1, 0), "{report}");
    let blob_id = blob_of(app, "reduced").await;
    let (layout, _) = shards_of(&cluster, blob_id).await;
    assert_eq!(layout.parity_shards, 1);
    assert_intact(&cluster, blob_id).await;
}

/// A copy into another class writes the data again, there; a copy that names
/// no class is STANDARD, as in S3, whatever its source's.
#[tokio::test]
async fn copies_change_class() {
    let Some(cluster) = tiered().await else { return };
    let app = &cluster.nodes[0];
    let body = data(1, 200_000);
    put_in(app, "k", "STANDARD", body.clone()).await.unwrap();
    let standard = blob_of(app, "k").await;

    copy_into(app, "k", "k", Some("COLD")).await;
    let cold = blob_of(app, "k").await;
    assert_ne!(cold, standard, "written again");
    assert_eq!(class_of_blob(app, cold).await, ("COLD".to_owned(), "hdd".to_owned()));
    assert_eq!(head_class(app, "k").await.as_deref(), Some("COLD"));
    assert_eq!(get(app, "k").await.unwrap(), body);
    assert_intact(&cluster, cold).await;

    // Within the class, the bytes are shared.
    copy_into(app, "k", "same", Some("COLD")).await;
    assert_eq!(blob_of(app, "same").await, cold);

    copy_into(app, "k", "back", None).await;
    let back = blob_of(app, "back").await;
    assert_eq!(class_of_blob(app, back).await, ("STANDARD".to_owned(), "default".to_owned()));
    assert_eq!(head_class(app, "back").await, None);
    assert_eq!(get(app, "back").await.unwrap(), body);
}

/// A multipart upload's parts, and so its object, are of the class it was
/// created in, as ListMultipartUploads and ListParts tell.
#[tokio::test]
async fn uploads_are_of_their_class() {
    use crate::s3::multipart::{complete::complete_multipart_upload, create::create_multipart_upload};
    let Some(cluster) = tiered().await else { return };
    let app = &cluster.nodes[0];
    let response = create_multipart_upload(app, BUCKET, "big", "x", "", "", Wanted::Plain, None, None, Default::default(), None, "COLD")
        .await
        .unwrap();
    let body = String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    let start = body.find("<UploadId>").unwrap() + "<UploadId>".len();
    let upload_id = body[start..body.find("</UploadId>").unwrap()].to_owned();
    let listed = crate::s3::multipart::list::list_multipart_uploads(app, BUCKET, "", None, "", None, 1000, Default::default())
        .await
        .unwrap();
    let listed = String::from_utf8(listed.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(listed.contains("<StorageClass>COLD</StorageClass>"), "{listed}");

    let upload = crate::s3::multipart::upload(app, &upload_id.parse().unwrap(), BUCKET, "big").await.unwrap().unwrap();
    let attach = AttachTarget::MultipartPart {
        storage_class: upload.storage_class.clone(),
        upload_id: upload_id.parse().unwrap(),
        part_number: 1,
        key: None,
        sse_s3: false,
        checksum: crate::e2e::PART_CHECKSUM,
    };
    let part = data(3, 1000);
    let UploadResult::Committed { etag, .. } =
        crate::upload_part(app, Full::new(Bytes::from(part.clone())), &attach, Payload::unchecked()).await.unwrap()
    else {
        panic!("the part wasn't committed");
    };
    let body = format!("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"{etag}\"</ETag></Part></CompleteMultipartUpload>");
    let response = complete_multipart_upload(app, BUCKET, "big", &upload_id, Bytes::from(body), &Preconditions::default(), None, None, None, None)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(head_class(app, "big").await.as_deref(), Some("COLD"));
    assert_eq!(class_of_blob(app, blob_of(app, "big").await).await.1, "hdd");
    assert_eq!(get(app, "big").await.unwrap(), part);
}

/// A class moved to another pool has its data rewritten there by the
/// packer, and its old files reaped.
#[tokio::test]
async fn a_class_moved_to_another_pool_is_rewritten_there() {
    let Some(cluster) = tiered().await else { return };
    let app = &cluster.nodes[0];
    let body = data(1, 300_000);
    put_in(app, "k", "COLD", body.clone()).await.unwrap();
    let before = blob_of(app, "k").await;
    let (_, holders) = shards_of(&cluster, before).await;

    set_class(&cluster, "COLD", "default", None, Some(1)).await;
    let reports = crate::packer::pass(app).await.unwrap();
    assert!(!reports.is_empty(), "converted");
    let after = blob_of(app, "k").await;
    assert_ne!(after, before);
    assert_eq!(class_of_blob(app, after).await, ("COLD".to_owned(), "default".to_owned()));
    assert_intact(&cluster, after).await;
    assert_eq!(get(app, "k").await.unwrap(), body);
    for i in holders {
        crate::e2e::assert_reaped(&cluster.nodes[i], before).await;
        assert!(!cluster.nodes[i].store.pool("hdd").unwrap().blob_path(before).exists());
    }
    // Nothing more to do.
    assert!(crate::packer::pass(app).await.unwrap().is_empty());
}

/// The packer packs a class's small blobs only with one another, in the
/// class's pool.
#[tokio::test]
async fn packing_keeps_classes_apart() {
    // Small enough a target that a dozen small blobs fill one.
    let config = crate::packer::Config { target_size: 8000, small_size: 2000, ..pack() };
    let pools: &[&[&str]] = &[&["default", "hdd"], &["default", "hdd"], &["default"]];
    let Some(cluster) = cluster_of_pools(pools, 2, config, None).await else { return };
    set_class(&cluster, "COLD", "hdd", None, Some(1)).await;
    let app = &cluster.nodes[0];
    for i in 0..12 {
        put_in(app, &format!("cold{i}"), "COLD", data(i, 1000)).await.unwrap();
        put_in(app, &format!("warm{i}"), "STANDARD", data(100 + i, 1000)).await.unwrap();
    }
    crate::packer::pass(app).await.unwrap();
    let client = app.pool.get().await.unwrap();
    let mixed: i64 = client
        .query_one(
            "SELECT count(*) FROM parts p JOIN objects o ON o.id = p.object_id JOIN blobs b ON b.blob_id = p.blob_id
             WHERE o.storage_class <> b.storage_class OR b.pool <> (SELECT pool FROM storage_classes WHERE name = b.storage_class)",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(mixed, 0, "a part is in a blob of its object's class, in its pool");
    let packed: i64 = client.query_one("SELECT count(DISTINCT blob_id) FROM parts", &[]).await.unwrap().get(0);
    assert!(packed <= 6, "packed into {packed} blobs");
    for i in 0..12 {
        assert_eq!(get(app, &format!("cold{i}")).await.unwrap(), data(i, 1000));
        assert_eq!(get(app, &format!("warm{i}")).await.unwrap(), data(100 + i, 1000));
    }
}

/// What a write's `x-amz-storage-class` names: a defined class, STANDARD
/// for none or for one of S3's that isn't defined, else nothing.
#[tokio::test]
async fn writes_name_defined_classes() {
    let Some(cluster) = tiered().await else { return };
    let app = &cluster.nodes[0];
    let resolve = |name: Option<&'static str>| super::resolve(app, name);
    assert_eq!(resolve(None).await.unwrap(), Ok("STANDARD".to_owned()));
    assert_eq!(resolve(Some("COLD")).await.unwrap(), Ok("COLD".to_owned()));
    assert_eq!(resolve(Some("GLACIER")).await.unwrap(), Ok("STANDARD".to_owned()));
    assert_eq!(resolve(Some("LUKEWARM")).await.unwrap(), Err("LUKEWARM".to_owned()));
    // Defined on another node since this one last read them.
    cluster.nodes[1]
        .pool
        .get()
        .await
        .unwrap()
        .execute("INSERT INTO storage_classes (name, pool) VALUES ('LUKEWARM', 'hdd')", &[])
        .await
        .unwrap();
    assert_eq!(resolve(Some("LUKEWARM")).await.unwrap(), Ok("LUKEWARM".to_owned()));
}

/// A store of one fresh data dir, of the pool `default`, of the node
/// `node_id`.
fn store_of(node_id: Uuid) -> crate::store::Store {
    let dir = std::env::temp_dir().join(format!("cairn-e2e-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("node_id"), node_id.to_string()).unwrap();
    crate::store::Store::new(vec![("default".to_owned(), dir)]).unwrap()
}

/// A node won't start without a pool it holds shards in; one that holds
/// none there may.
#[tokio::test]
async fn a_node_keeps_the_pools_it_holds_shards_in() {
    let Some(cluster) = tiered().await else { return };
    let app = &cluster.nodes[0];
    put_in(app, "cold", "COLD", data(1, 1000)).await.unwrap();
    for i in [0, 1] {
        let store = store_of(cluster.nodes[i].store.get_node_id());
        let error = crate::check_pools(&app.pool, &store).await.unwrap_err();
        assert!(error.to_string().contains("pool hdd"), "{error}");
    }
    // Once it's gone, the nodes may drop the pool.
    crate::e2e::delete(app, "cold").await;
    crate::packer::pass(app).await.unwrap();
    for i in [0, 1] {
        let store = store_of(cluster.nodes[i].store.get_node_id());
        crate::check_pools(&app.pool, &store).await.unwrap();
    }
}

/// A node's data dirs are its own: they can't be another node's.
#[test]
fn data_dirs_belong_to_one_node() {
    let dir = |id: Option<Uuid>| {
        let dir = std::env::temp_dir().join(format!("cairn-e2e-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(id) = id {
            std::fs::write(dir.join("node_id"), id.to_string()).unwrap();
        }
        dir
    };
    let id = Uuid::new_v4();
    let (ssd, hdd) = (dir(Some(id)), dir(None));
    let store = crate::store::Store::new(vec![("ssd".to_owned(), ssd.clone()), ("hdd".to_owned(), hdd.clone())]).unwrap();
    assert_eq!(store.get_node_id(), id);
    assert_eq!(std::fs::read_to_string(hdd.join("node_id")).unwrap(), id.to_string(), "a new dir is the node's");
    let other = dir(Some(Uuid::new_v4()));
    assert!(crate::store::Store::new(vec![("ssd".to_owned(), ssd.clone()), ("hdd".to_owned(), other)]).is_err());
    assert!(crate::store::Store::new(vec![("ssd".to_owned(), ssd.clone()), ("ssd".to_owned(), hdd)]).is_err());
    assert!(crate::store::Store::new(vec![("SSD".to_owned(), ssd.clone())]).is_err());
    // Pools' dirs can't overlap.
    assert!(crate::store::Store::new(vec![("ssd".to_owned(), ssd.clone()), ("hdd".to_owned(), ssd.join("hdd"))]).is_err());
    assert!(crate::store::Store::new(vec![("ssd".to_owned(), ssd.clone()), ("hdd".to_owned(), ssd.join("."))]).is_err());
}

// ─── Lifecycle transitions (see `lifecycle`) ─────────────────────────────────

/// Ranks class `name` at `rank`, and has every node of `cluster` go by it.
async fn set_rank(cluster: &Cluster, name: &str, rank: i32) {
    cluster.nodes[0]
        .pool
        .get()
        .await
        .unwrap()
        .execute("UPDATE storage_classes SET rank = $2 WHERE name = $1", &[&name, &rank])
        .await
        .unwrap();
    for node in &cluster.nodes {
        crate::refresh_settings(node).await.unwrap();
    }
}

/// `tiered`, with COLD ranked below STANDARD.
async fn ranked() -> Option<Cluster> {
    let cluster = tiered().await?;
    set_rank(&cluster, "COLD", -10).await;
    Some(cluster)
}

/// Sets the bucket's lifecycle rules to `rules`: the answer.
async fn set_rules(app: &App, rules: &str) -> hyper::Response<Full<Bytes>> {
    let body = format!("<LifecycleConfiguration>{rules}</LifecycleConfiguration>");
    crate::s3::buckets::lifecycle::put_bucket_lifecycle(app, BUCKET, Bytes::from(body), None).await.unwrap()
}

/// Transitions the objects under `prefix` into COLD the day after they're
/// written.
async fn transition_to_cold(app: &App, prefix: &str) {
    let rule = format!(
        "<Rule><ID>cold</ID><Filter><Prefix>{prefix}</Prefix></Filter><Status>Enabled</Status>\
         <Transition><Days>1</Days><StorageClass>COLD</StorageClass></Transition></Rule>"
    );
    assert_eq!(set_rules(app, &rule).await.status(), StatusCode::OK);
}

/// Takes the lifecycle steps due `days` from now: how many versions they
/// transitioned.
async fn sweep_in(app: &Arc<App>, days: u64) -> i64 {
    let at = std::time::SystemTime::now() + std::time::Duration::from_secs(days * 24 * 3600);
    crate::lifecycle::pass(app, at).await.into_iter().map(|r| r.map_err(|(_, e)| e).unwrap().transitioned).sum()
}

/// A blob's misplaced bytes, as the last fold worked them out.
async fn misplaced(app: &App, blob_id: Uuid) -> i64 {
    let client = app.pool.get().await.unwrap();
    client.query_one("SELECT misplaced_size FROM blobs WHERE blob_id = $1", &[&blob_id]).await.unwrap().get(0)
}

/// A transition changes only the object's class; its bytes stay in their
/// blob, misplaced, until the packer moves them into the class's pool.
#[tokio::test]
async fn transitions_leave_the_bytes_for_the_packer() {
    let Some(cluster) = ranked().await else { return };
    let app = &cluster.nodes[0];
    let body = data(1, 300_000);
    put_in(app, "logs/a", "STANDARD", body.clone()).await.unwrap();
    put_in(app, "other", "STANDARD", data(2, 300_000)).await.unwrap();
    transition_to_cold(app, "logs/").await;
    let before = blob_of(app, "logs/a").await;

    // Not on the day it was written.
    assert_eq!(sweep_in(app, 0).await, 0);
    assert_eq!(sweep_in(app, 2).await, 1);
    assert_eq!(head_class(app, "logs/a").await.as_deref(), Some("COLD"));
    assert_eq!(head_class(app, "other").await, None);
    assert_eq!(blob_of(app, "logs/a").await, before, "the bytes stay where they were");
    assert_eq!(get(app, "logs/a").await.unwrap(), body);

    // The packer's fold finds them misplaced, and it moves them.
    let reports = crate::packer::pass(app).await.unwrap();
    let relocated: usize = reports.iter().map(|r| r.relocated.parts).sum();
    assert_eq!(relocated, 1, "{}", reports.iter().map(|r| r.to_string()).collect::<Vec<_>>().join("; "));
    let after = blob_of(app, "logs/a").await;
    assert_ne!(after, before);
    assert_eq!(class_of_blob(app, after).await, ("COLD".to_owned(), "hdd".to_owned()));
    assert_eq!(misplaced(app, after).await, 0);
    assert_intact(&cluster, after).await;
    assert_eq!(get(app, "logs/a").await.unwrap(), body);
    assert_eq!(class_of_blob(app, blob_of(app, "other").await).await.0, "STANDARD");
    // Nothing more to do, and nothing more to transition.
    assert!(crate::packer::pass(app).await.unwrap().is_empty());
    assert_eq!(sweep_in(app, 4).await, 0);
}

/// Bytes a version of the blob's own class still shares stay where they
/// are: until it's gone.
#[tokio::test]
async fn shared_bytes_stay_in_the_highest_class_they_serve() {
    let Some(cluster) = ranked().await else { return };
    let app = &cluster.nodes[0];
    let body = data(1, 300_000);
    put_in(app, "logs/a", "STANDARD", body.clone()).await.unwrap();
    copy_into(app, "logs/a", "copy", None).await;
    let blob = blob_of(app, "logs/a").await;
    assert_eq!(blob_of(app, "copy").await, blob, "shared");
    transition_to_cold(app, "logs/").await;
    assert_eq!(sweep_in(app, 2).await, 1);

    crate::packer::pass(app).await.unwrap();
    assert_eq!(misplaced(app, blob).await, 0, "the copy is STANDARD's");
    assert_eq!(blob_of(app, "logs/a").await, blob);

    crate::e2e::delete(app, "copy").await;
    crate::packer::pass(app).await.unwrap();
    let after = blob_of(app, "logs/a").await;
    assert_eq!(class_of_blob(app, after).await.0, "COLD");
    assert_eq!(get(app, "logs/a").await.unwrap(), body);
}

/// A copy into a lower class shares its source's bytes, which stand in for
/// it; a copy into a higher one than its source's writes them again.
#[tokio::test]
async fn copies_into_lower_classes_share_bytes() {
    let Some(cluster) = ranked().await else { return };
    let app = &cluster.nodes[0];
    let body = data(1, 200_000);
    put_in(app, "k", "STANDARD", body.clone()).await.unwrap();
    let standard = blob_of(app, "k").await;
    copy_into(app, "k", "cold", Some("COLD")).await;
    assert_eq!(blob_of(app, "cold").await, standard);
    assert_eq!(head_class(app, "cold").await.as_deref(), Some("COLD"));
    // A copy of the COLD one that names no class is STANDARD: written again,
    // though its bytes are in STANDARD's blob, as its source's are only
    // COLD's.
    copy_into(app, "cold", "warm", None).await;
    let warm = blob_of(app, "warm").await;
    assert_ne!(warm, standard);
    assert_eq!(head_class(app, "warm").await, None);
    // A copy that keeps its class shares them.
    copy_into(app, "cold", "cold2", Some("COLD")).await;
    assert_eq!(blob_of(app, "cold2").await, standard);
    assert_eq!(get(app, "cold2").await.unwrap(), body);
    // Once the STANDARD ones are gone, the COLD ones' bytes move to COLD.
    crate::e2e::delete(app, "k").await;
    crate::packer::pass(app).await.unwrap();
    let moved = blob_of(app, "cold").await;
    assert_eq!(class_of_blob(app, moved).await.0, "COLD");
    assert_eq!(blob_of(app, "cold2").await, moved, "still shared");
    assert_eq!(get(app, "cold2").await.unwrap(), body);
}

/// Rules may only transition into classes that are defined, and ranked; and
/// an object under 128 KiB isn't transitioned, unless the rule says so.
#[tokio::test]
async fn transitions_go_to_ranked_classes() {
    let Some(cluster) = tiered().await else { return };
    let app = &cluster.nodes[0];
    let rule = |class: &str| {
        format!(
            "<Rule><ID>r</ID><Filter/><Status>Enabled</Status>\
             <Transition><Days>1</Days><StorageClass>{class}</StorageClass></Transition></Rule>"
        )
    };
    for class in ["COLD", "GLACIER"] {
        let response = set_rules(app, &rule(class)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{class}");
        let body = String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert!(body.contains("InvalidStorageClass"), "{body}");
    }
    // Ranked on another node since this one read the classes.
    cluster.nodes[1]
        .pool
        .get()
        .await
        .unwrap()
        .execute("UPDATE storage_classes SET rank = -10 WHERE name = 'COLD'", &[])
        .await
        .unwrap();
    let response = set_rules(app, &rule("COLD")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["x-amz-transition-default-minimum-object-size"],
        "all_storage_classes_128K"
    );
    put_in(app, "small", "STANDARD", data(1, 1000)).await.unwrap();
    put_in(app, "large", "STANDARD", data(2, 200_000)).await.unwrap();
    assert_eq!(sweep_in(app, 2).await, 1);
    assert_eq!(head_class(app, "small").await, None);
    assert_eq!(head_class(app, "large").await.as_deref(), Some("COLD"));
}

/// Noncurrent versions transition too, and a lifecycle event tells of it.
#[tokio::test]
async fn noncurrent_versions_transition() {
    let Some(cluster) = ranked().await else { return };
    let app = &cluster.nodes[0];
    let body = "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";
    let response = crate::s3::buckets::versioning::put_bucket_versioning(
        app,
        BUCKET,
        Bytes::from(body),
        crate::mfa::Presented::Absent,
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    put_in(app, "k", "STANDARD", data(1, 200_000)).await.unwrap();
    put_in(app, "k", "STANDARD", data(2, 200_000)).await.unwrap();
    let rule = "<Rule><ID>r</ID><Filter/><Status>Enabled</Status><NoncurrentVersionTransition>\
                <NoncurrentDays>1</NoncurrentDays><StorageClass>COLD</StorageClass>\
                </NoncurrentVersionTransition></Rule>";
    assert_eq!(set_rules(app, rule).await.status(), StatusCode::OK);
    assert_eq!(sweep_in(app, 2).await, 1);
    let client = app.pool.get().await.unwrap();
    let classes: Vec<(bool, String)> = client
        .query("SELECT is_latest, storage_class FROM objects WHERE key = 'k' ORDER BY id", &[])
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    assert_eq!(classes, [(false, "COLD".to_owned()), (true, "STANDARD".to_owned())]);
    assert_eq!(head_class(app, "k").await, None);
    assert_eq!(get(app, "k").await.unwrap(), data(2, 200_000));
}
