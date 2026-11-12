//! A stress test of the lock protocol's claim that there are no deadlocks
//! (see "Deadlocks" in `catalog.sql`): many workers run the mixes of requests
//! that could deadlock without it, against a few keys, alongside the packer
//! and the GC.

use std::sync::{Arc, Mutex, atomic::Ordering};

use http_body_util::{BodyExt, Full};
use hyper::{StatusCode, body::Bytes};
use tokio::task::JoinSet;

use super::{BUCKET, node_with, put, query_i64};
use crate::{
    App, AttachTarget, UploadResult,
    payload::Payload,
    db, gc, packer,
    s3::{
        conditional::Preconditions,
        multipart::{
            abort::abort_multipart_upload, complete::complete_multipart_upload,
            create::create_multipart_upload,
        },
        objects::{copy::copy_object, delete::delete_object},
    },
};
use crate::s3::sse::Wanted;

const KEYS: usize = 8;
const WORKERS: usize = 16;
const OPS_PER_WORKER: usize = 30;

/// A small, fast pseudo-random sequence, seeded per worker, so that a failure
/// can be reproduced.
struct Rng(u64);

impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % n as u64) as usize
    }
}

fn key(i: usize) -> String {
    format!("k{i}")
}

async fn text(response: hyper::Response<Full<Bytes>>) -> (StatusCode, String) {
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// Uploads `data` as part `number` of the upload; its ETag.
async fn upload_part(app: &Arc<App>, upload_id: &str, number: i32, data: Vec<u8>) -> anyhow::Result<String> {
    let attach = AttachTarget::MultipartPart {
        upload_id: upload_id.parse().unwrap(),
        part_number: number,
        key: None,
        sse_s3: false,
        checksum: crate::e2e::PART_CHECKSUM,
    };
    let body = Full::new(Bytes::from(data));
    match crate::upload_part(app, body, &attach, Payload::unchecked()).await? {
        UploadResult::Committed { etag, .. } => Ok(etag),
        _ => anyhow::bail!("the part wasn't committed"),
    }
}

/// One random request, or a packing or GC pass. Returns what went wrong, if
/// anything did.
async fn step(app: &Arc<App>, rng: &mut Rng) -> anyhow::Result<()> {
    let (a, b) = (key(rng.below(KEYS)), key(rng.below(KEYS)));
    let fill = rng.below(256) as u8;
    match rng.below(20) {
        0..=3 => put(app, &a, vec![fill; 1000 + rng.below(1000)]).await,
        // Crossing copies, and copies of an object onto itself.
        4..=8 => {
            let directive = (a == b).then_some("REPLACE");
            let response = match copy_object(app, BUCKET, &b, &format!("{BUCKET}/{a}"), directive, "x", "", None, &Preconditions::default(), Default::default()).await {
                Ok(response) => response,
                // With this much churn on so few keys, a copy's source can keep
                // changing under it, and the copy gives up (with SlowDown).
                Err(e) if e.is::<crate::Contended>() => return Ok(()),
                Err(e) => return Err(e),
            };
            let (status, body) = text(response).await;
            // The source may have just been deleted.
            anyhow::ensure!(
                status == StatusCode::OK || status == StatusCode::NOT_FOUND,
                "copy {a} -> {b}: {status} {body}"
            );
        }
        9 | 10 => {
            let status = delete_object(app, BUCKET, &a, None).await?.status();
            anyhow::ensure!(status == StatusCode::NO_CONTENT, "delete {a}: {status}");
        }
        // A DeleteObjects of a few keys (locked one by one) or of many
        // (locked by stripe), with repeats.
        11 => {
            let keys: Vec<String> = (0..1 + rng.below(16)).map(|_| key(rng.below(2 * KEYS))).collect();
            let versions: Vec<Option<&str>> = keys.iter().map(|_| None).collect();
            let markers: Vec<String> = keys.iter().map(|_| crate::s3::versions::new_version_id()).collect();
            let client = app.pool.get().await?;
            loop {
                match client
                    .query_one(
                        "SELECT status FROM pg_temp.cairn_delete_objects($1, $2, $3, $4)",
                        &[&BUCKET, &keys, &versions, &markers],
                    )
                    .await
                {
                    Ok(_) => break,
                    Err(e) if db::is_conflict(&e) => continue,
                    Err(e) => return Err(e.into()),
                }
            }
        }
        // Part re-uploads racing each other, then a complete or an abort.
        12..=16 => {
            let (_, body) = text(create_multipart_upload(app, BUCKET, &a, "x", "", "", Wanted::Plain, None, None).await?).await;
            let start = body.find("<UploadId>").unwrap() + "<UploadId>".len();
            let upload_id = body[start..body.find("</UploadId>").unwrap()].to_owned();
            let mut parts = JoinSet::new();
            for n in [1, 1, 2] {
                let (app, upload_id) = (app.clone(), upload_id.clone());
                // Part 1 as small as a part that isn't the last may be.
                let len = if n == 1 { crate::s3::util::MIN_PART as usize } else { 700 };
                parts.spawn(async move { (n, upload_part(&app, &upload_id, n, vec![n as u8; len]).await) });
            }
            let mut etags = std::collections::BTreeMap::new();
            while let Some(result) = parts.join_next().await {
                let (n, etag) = result.unwrap();
                etags.insert(n, etag?);
            }
            if rng.below(3) == 0 {
                let status = abort_multipart_upload(app, BUCKET, &a, &upload_id).await?.status();
                anyhow::ensure!(status == StatusCode::NO_CONTENT, "abort: {status}");
            } else {
                // Both uploads of part 1 have the same ETag, so it doesn't
                // matter which one won.
                let listed: String = etags
                    .iter()
                    .map(|(n, etag)| format!("<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>"))
                    .collect();
                let request = Bytes::from(format!("<CompleteMultipartUpload>{listed}</CompleteMultipartUpload>"));
                let response = complete_multipart_upload(app, BUCKET, &a, &upload_id, request, &Preconditions::default(), None, None, None, None).await?;
                let (status, body) = text(response).await;
                anyhow::ensure!(status == StatusCode::OK, "complete: {status} {body}");
            }
        }
        17 | 18 => {
            packer::pass(app).await?;
        }
        _ => {
            let report = gc::pass(app, gc::Scope::everything()).await;
            anyhow::ensure!(report.error_count() == 0, "gc: {report}");
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_lock_protocol_has_no_deadlocks() {
    // Small blobs, so that the packer packs and compacts all the time.
    let pack = packer::Config {
        target_size: 8_000,
        small_size: 2_000,
        compact_threshold: 0.1,
        max_sources: 50,
        ..packer::Config::default()
    };
    let Some(app) = node_with(pack, None).await else { return };
    for i in 0..KEYS {
        put(&app, &key(i), vec![i as u8; 1500]).await;
    }
    // The test node has no heartbeat of its own, and this runs for longer than
    // a node counts as live without one.
    let beating = app.clone();
    let heartbeat = tokio::spawn(async move {
        loop {
            let client = beating.pool.get().await.unwrap();
            client.execute("UPDATE nodes SET last_seen = NOW()", &[]).await.unwrap();
            drop(client);
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    });
    let deadlocks_before = db::DEADLOCKS.load(Ordering::Relaxed);
    let failures = Arc::new(Mutex::new(Vec::new()));
    let mut workers = JoinSet::new();
    for w in 0..WORKERS {
        let (app, failures) = (app.clone(), failures.clone());
        workers.spawn(async move {
            let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ ((w as u64 + 1) * 0x1000_0000_01b3));
            for _ in 0..OPS_PER_WORKER {
                if let Err(e) = step(&app, &mut rng).await {
                    failures.lock().unwrap().push(format!("{e:#}"));
                }
            }
        });
    }
    while let Some(result) = workers.join_next().await {
        result.unwrap();
    }
    heartbeat.abort();
    let failures = failures.lock().unwrap().clone();
    assert!(failures.is_empty(), "{} failed: {:?}", failures.len(), &failures[..failures.len().min(10)]);
    assert_eq!(db::DEADLOCKS.load(Ordering::Relaxed), deadlocks_before, "deadlocks happened");

    // And everything is still consistent: every object reads back in full, and
    // every committed blob is referenced, or logged for the packer to drop.
    for i in 0..KEYS {
        if let Some(data) = super::get(&app, &key(i)).await {
            let size = query_i64(&app, &format!(
                "SELECT size FROM objects WHERE key = '{}' AND is_latest", key(i)
            ))
            .await;
            assert_eq!(data.len() as i64, size, "{}", key(i));
        }
    }
    let unaccounted = "SELECT count(*) FROM blobs b WHERE state = 'committed'
                       AND NOT EXISTS (SELECT 1 FROM parts p WHERE p.blob_id = b.blob_id)
                       AND NOT EXISTS (SELECT 1 FROM blob_garbage g WHERE g.blob_id = b.blob_id)";
    assert_eq!(query_i64(&app, unaccounted).await, 0, "unreferenced blobs nobody will drop");
    let unlocated = "SELECT count(*) FROM blobs b WHERE state = 'committed'
                     AND NOT EXISTS (SELECT 1 FROM blob_locations l WHERE l.blob_id = b.blob_id)";
    assert_eq!(query_i64(&app, unlocated).await, 0, "committed blobs without a replica");
}
