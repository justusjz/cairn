//! The catalog's view of encrypted parts: a part's stored size and salt, its
//! plaintext's size, which objects are made of, and an SSE-C object's key
//! check, carried through commits, completions and copies.

use std::sync::Arc;

use uuid::Uuid;

use super::{BUCKET, locking::pending_blob, node_with};
use crate::{App, packer};

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

const KEY_CHECK: [u8; 48] = [3; 48];

/// Commits an encrypted part of `plain` bytes, stored in `stored`, with
/// `salt`: as the object `key`, or as part `part_number` of `upload`.
async fn commit(
    app: &App,
    target: Result<&str, (Uuid, i32)>,
    stored: i64,
    plain: i64,
    salt: &[u8],
) -> String {
    let blob = pending_blob(app, 0.0).await;
    let etag: String = salt.iter().map(|b| format!("{b:02x}")).collect();
    let client = app.pool.get().await.unwrap();
    let row = match target {
        Ok(key) => {
            client
                .query_one(
                    "SELECT status FROM pg_temp.cairn_commit_object(
                     $1, ARRAY[$2::int], $3, 0, 65536, 0, $4, $5, $6,
                     $7, $8, 'application/octet-stream', '', $9, NULL, NULL, $10)",
                    &[
                        &blob,
                        &app.node,
                        &stored,
                        &etag,
                        &plain,
                        &salt,
                        &BUCKET,
                        &key,
                        &&KEY_CHECK[..],
                        &crate::s3::versions::new_version_id(),
                    ],
                )
                .await
        }
        Err((upload, part_number)) => {
            client
                .query_one(
                    "SELECT status FROM pg_temp.cairn_commit_upload_part(
                     $1, ARRAY[$2::int], $3, 0, 65536, 0, $4, $5, $6, $7, $8)",
                    &[
                        &blob,
                        &app.node,
                        &stored,
                        &etag,
                        &plain,
                        &salt,
                        &upload,
                        &part_number,
                    ],
                )
                .await
        }
    };
    row.unwrap().get(0)
}

async fn row_i64(app: &App, sql: &str, key: &str) -> i64 {
    let client = app.pool.get().await.unwrap();
    client
        .query_one(sql, &[&BUCKET, &key])
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
async fn sizes_salts_and_key_checks_carry_through() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();

    // A single-part object: the object's size is the plaintext's, the part's
    // what it takes in the blob.
    assert_eq!(
        commit(&app, Ok("k"), 1016, 1000, &[1; 16]).await,
        "committed"
    );
    assert_eq!(
        row_i64(
            &app,
            "SELECT size FROM objects WHERE bucket = $1 AND key = $2",
            "k"
        )
        .await,
        1000
    );
    let part = client
        .query_one(
            "SELECT p.id, p.size, p.plain_size, p.enc_salt, o.id, o.sse_c_key
             FROM parts p JOIN objects o ON o.id = p.object_id WHERE o.key = 'k'",
            &[],
        )
        .await
        .unwrap();
    let (part_id, object_id): (i64, i64) = (part.get(0), part.get(4));
    assert_eq!((part.get::<_, i64>(1), part.get::<_, i64>(2)), (1016, 1000));
    assert_eq!(part.get::<_, Vec<u8>>(3), vec![1; 16]);
    assert_eq!(part.get::<_, Vec<u8>>(5), KEY_CHECK.to_vec());

    // A copy shares the part's bytes, so it has its salt and sizes too.
    let status: String = client
        .query_one(
            "SELECT status FROM pg_temp.cairn_copy_object(
                 $1, ARRAY[$2::bigint], ARRAY[1016::bigint], $3, 'c', 1000, 'etag', 'x', '', $4, $5)",
            &[&object_id, &part_id, &BUCKET, &&KEY_CHECK[..], &crate::s3::versions::new_version_id()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(status, "committed");
    let copied = client
        .query_one(
            "SELECT p.size, p.plain_size, p.enc_salt, o.size, o.sse_c_key
             FROM parts p JOIN objects o ON o.id = p.object_id WHERE o.key = 'c'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        (
            copied.get::<_, i64>(0),
            copied.get::<_, i64>(1),
            copied.get::<_, i64>(3)
        ),
        (1016, 1000, 1000)
    );
    assert_eq!(copied.get::<_, Vec<u8>>(2), vec![1; 16]);
    assert_eq!(copied.get::<_, Vec<u8>>(4), KEY_CHECK.to_vec());

    // A multipart object: its size is its parts' plaintext, and its key check
    // the upload's.
    let upload = Uuid::now_v7();
    client
        .execute(
            "INSERT INTO multipart_uploads (upload_id, bucket, key, content_type, sse_c_key, initiated_at)
             VALUES ($1, $2, 'm', 'x', $3, NOW())",
            &[&upload, &BUCKET, &&KEY_CHECK[..]],
        )
        .await
        .unwrap();
    assert_eq!(
        commit(&app, Err((upload, 1)), 65552, 65536, &[2; 16]).await,
        "committed"
    );
    assert_eq!(
        commit(&app, Err((upload, 2)), 21, 5, &[4; 16]).await,
        "committed"
    );
    let etags = ["02".repeat(16), "04".repeat(16)];
    let status: String = client
        .query_one(
            "SELECT status FROM pg_temp.cairn_complete_upload(
                 $1, $2, 'm', ARRAY[1, 2], $3, NULL, NULL, $4)",
            &[
                &upload,
                &BUCKET,
                &etags.to_vec(),
                &crate::s3::versions::new_version_id(),
            ],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(status, "done");
    assert_eq!(
        row_i64(
            &app,
            "SELECT size FROM objects WHERE bucket = $1 AND key = $2",
            "m"
        )
        .await,
        65541
    );
    let key_check: Vec<u8> = client
        .query_one("SELECT sse_c_key FROM objects WHERE key = 'm'", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(key_check, KEY_CHECK.to_vec());

    // A range of an encrypted part can't be staged in place.
    let upload = Uuid::now_v7();
    client
        .execute(
            "INSERT INTO multipart_uploads (upload_id, bucket, key, content_type, initiated_at)
             VALUES ($1, $2, 'r', 'x', NOW())",
            &[&upload, &BUCKET],
        )
        .await
        .unwrap();
    let refused = client
        .query_one(
            "SELECT status FROM pg_temp.cairn_copy_part(
                 $1, ARRAY[$2::bigint], ARRAY[1016::bigint], 1, 0, 10, 'etag', 0, $3, 1)",
            &[&object_id, &part_id, &upload],
        )
        .await;
    assert!(refused.is_err());

    // A salt is 16 bytes, and goes with a plaintext size, and the other way round.
    for (plain, salt) in [
        (Some(1000i64), Some(vec![1u8; 15])),
        (None, Some(vec![1; 16])),
        (Some(1000), None),
    ] {
        let blob = pending_blob(&app, 0.0).await;
        let refused = client
            .query_one(
                "SELECT status FROM pg_temp.cairn_commit_object(
                     $1, ARRAY[$2::int], 1016, 0, 65536, 0, 'etag', $3, $4,
                     $5, 'bad', 'x', '', NULL, NULL, NULL, $6)",
                &[
                    &blob,
                    &app.node,
                    &plain,
                    &salt,
                    &BUCKET,
                    &crate::s3::versions::new_version_id(),
                ],
            )
            .await;
        assert!(refused.is_err(), "{plain:?} {salt:?}");
    }
}
