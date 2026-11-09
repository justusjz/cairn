//! The catalog's view of encrypted parts: a part's stored size and salt, its
//! plaintext's size, which objects are made of, and an SSE-C object's key
//! check, carried through commits, completions and copies.

use std::sync::Arc;

use hyper::{StatusCode, body::Bytes};
use uuid::Uuid;

use super::{BUCKET, customer_key, get_sealed, locking::pending_blob, node_with, put, put_sealed};
use crate::{
    App,
    encryption::stored_len,
    packer,
    s3::{
        conditional::Preconditions,
        multipart::{complete::complete_multipart_upload, create::create_multipart_upload},
        objects::{
            copy::{CopyKeys, copy_object, copy_part},
            get::head_object,
        },
    },
};
use crate::s3::sse::Wanted;

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
                     $7, $8, 'application/octet-stream', '', $9, NULL, NULL, NULL, NULL, false,
                     NULL, NULL, $10)",
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
                 $1, ARRAY[$2::bigint], ARRAY[1016::bigint], $3, 'c', 1000, 'etag', 'x', '', $4,
                 NULL, NULL, NULL, NULL, false, $5)",
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
    let min = crate::s3::util::MIN_PART;
    assert_eq!(
        commit(
            &app,
            Err((upload, 1)),
            stored_len(min) as i64,
            min as i64,
            &[2; 16]
        )
        .await,
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
        min as i64 + 5
    );
    let key_check: Vec<u8> = client
        .query_one("SELECT sse_c_key FROM objects WHERE key = 'm'", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(key_check, KEY_CHECK.to_vec());

    // A part's plaintext is what must be 5 MiB: one whose ciphertext is, but
    // not its plaintext, is too small.
    let upload = Uuid::now_v7();
    client
        .execute(
            "INSERT INTO multipart_uploads (upload_id, bucket, key, content_type, initiated_at)
             VALUES ($1, $2, 's', 'x', NOW())",
            &[&upload, &BUCKET],
        )
        .await
        .unwrap();
    let short = min - 10;
    assert!(stored_len(short) >= min);
    assert_eq!(
        commit(
            &app,
            Err((upload, 1)),
            stored_len(short) as i64,
            short as i64,
            &[5; 16]
        )
        .await,
        "committed"
    );
    assert_eq!(
        commit(&app, Err((upload, 2)), 21, 5, &[6; 16]).await,
        "committed"
    );
    let etags = ["05".repeat(16), "06".repeat(16)];
    let status: String = client
        .query_one(
            "SELECT status FROM pg_temp.cairn_complete_upload(
                 $1, $2, 's', ARRAY[1, 2], $3, NULL, NULL, $4)",
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
    assert_eq!(status, "too_small");

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
                     $5, 'bad', 'x', '', NULL, NULL, NULL, NULL, NULL, false, NULL, NULL, $6)",
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

fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 253) as u8).collect()
}

/// An SSE-C object reads back whole, and in any range, with its key; it's
/// stored as ciphertext, and its ETag isn't its MD5.
#[tokio::test]
async fn an_sse_c_object_reads_back_with_its_key() {
    let Some(app) = node().await else { return };
    let key = customer_key(&[5; 32]);
    for len in [0, 1, 65535, 65536, 65537, 200_000] {
        let name = format!("o{len}");
        let plain = data(len);
        let etag = put_sealed(&app, &name, plain.clone(), &key).await;
        assert_eq!(etag.len(), 32);
        let md5: String = {
            use md5::Digest;
            md5::Md5::digest(&plain)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        };
        assert_ne!(etag, md5, "the ETag of {name} gives its content away");
        assert_eq!(
            get_sealed(&app, &name, None, Some(&key)).await,
            (StatusCode::OK, plain.clone()),
            "{name}"
        );

        // What's stored: the ciphertext, which doesn't hold the plaintext.
        let client = app.pool.get().await.unwrap();
        let row = client
            .query_one(
                "SELECT p.size, p.blob_id FROM parts p JOIN objects o ON o.id = p.object_id
                 WHERE o.key = $1",
                &[&name],
            )
            .await
            .unwrap();
        assert_eq!(
            row.get::<_, i64>(0) as u64,
            stored_len(len as u64),
            "{name}"
        );
        let file = std::fs::read(app.store.blob_path(row.get(1))).unwrap();
        if len >= 64 {
            assert!(
                !file.windows(64).any(|w| w == &plain[..64]),
                "{name} is stored in the clear"
            );
        }

        // HEAD: the plaintext's size.
        let head = head_object(
            &app,
            BUCKET,
            &name,
            None,
            None,
            &Preconditions::default(),
            Some(&key),
        )
        .await
        .unwrap();
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(head.headers()["content-length"], len.to_string().as_str());
        assert_eq!(
            head.headers()["x-amz-server-side-encryption-customer-algorithm"],
            "AES256"
        );
    }
    // Ranges: within a segment, across segments, the last bytes, open-ended.
    let plain = data(200_000);
    for (range, start, end) in [
        ("bytes=0-0", 0, 1),
        ("bytes=10-99", 10, 100),
        ("bytes=65530-65545", 65530, 65546),
        ("bytes=65536-131071", 65536, 131072),
        ("bytes=1000-199999", 1000, 200_000),
        ("bytes=-5", 199_995, 200_000),
        ("bytes=131072-", 131072, 200_000),
    ] {
        let (status, body) = get_sealed(&app, "o200000", Some(range), Some(&key)).await;
        assert_eq!(status, StatusCode::PARTIAL_CONTENT, "{range}");
        assert_eq!(body, &plain[start..end], "{range}");
    }
}

/// Without its key, or with another, an SSE-C object isn't read, and a key
/// for a plain object is refused too. Conditions tell nothing without the key.
#[tokio::test]
async fn an_sse_c_object_needs_its_key() {
    let Some(app) = node().await else { return };
    let key = customer_key(&[5; 32]);
    let other = customer_key(&[6; 32]);
    let etag = put_sealed(&app, "sealed", data(100), &key).await;
    put(&app, "plain", data(100)).await;
    assert_eq!(
        get_sealed(&app, "sealed", None, None).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        get_sealed(&app, "sealed", None, Some(&other)).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        get_sealed(&app, "plain", None, Some(&key)).await.0,
        StatusCode::BAD_REQUEST
    );
    for customer in [None, Some(&other)] {
        let head = head_object(
            &app,
            BUCKET,
            "sealed",
            None,
            None,
            &Preconditions::default(),
            customer,
        )
        .await
        .unwrap();
        assert_eq!(head.status(), StatusCode::BAD_REQUEST);
    }
    // If-None-Match with the right ETag: without the key, still a 400, not a 304.
    let mut headers = hyper::HeaderMap::new();
    headers.insert("if-none-match", format!("\"{etag}\"").parse().unwrap());
    let conditions = Preconditions::from_headers(&headers);
    let head = head_object(&app, BUCKET, "sealed", None, None, &conditions, None)
        .await
        .unwrap();
    assert_eq!(head.status(), StatusCode::BAD_REQUEST);
    let head = head_object(&app, BUCKET, "sealed", None, None, &conditions, Some(&key))
        .await
        .unwrap();
    assert_eq!(head.status(), StatusCode::NOT_MODIFIED);
}

/// Ciphertext altered past the block CRCs (rewritten to match, as only someone
/// tampering would) is caught by the segment's tag: the read fails instead of
/// serving what it decrypts to.
#[tokio::test]
async fn tampering_past_the_crcs_is_caught() {
    let Some(app) = node().await else { return };
    let key = customer_key(&[5; 32]);
    put_sealed(&app, "k", data(200_000), &key).await;
    let client = app.pool.get().await.unwrap();
    let row = client
        .query_one("SELECT b.blob_id, b.size, b.block_size FROM blobs b JOIN parts p ON p.blob_id = b.blob_id", &[])
        .await
        .unwrap();
    let (blob_id, size, block_size): (Uuid, i64, i32) = (row.get(0), row.get(1), row.get(2));
    let path = app.store.blob_path(blob_id);
    let mut file = std::fs::read(&path).unwrap();
    // A byte in the second segment, and its block's checksum to match.
    let at = 70_000;
    file[at] ^= 1;
    let block = at / block_size as usize;
    let start = block * block_size as usize;
    let end = (start + block_size as usize).min(size as usize);
    let crc = crc32c::crc32c(&file[start..end]).to_be_bytes();
    let entry = size as usize + 4 * block;
    file[entry..entry + 4].copy_from_slice(&crc);
    std::fs::write(&path, &file).unwrap();

    let response = crate::s3::objects::get::get_object(
        &app,
        BUCKET,
        "k",
        None,
        None,
        &Preconditions::default(),
        Some(&key),
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the headers go out before the damage is reached"
    );
    use http_body_util::BodyExt;
    assert!(
        response.into_body().collect().await.is_err(),
        "a tampered segment must fail the read"
    );
    // The first segment is still intact.
    let (status, body) = get_sealed(&app, "k", Some("bytes=0-65535"), Some(&key)).await;
    assert_eq!(
        (status, body),
        (StatusCode::PARTIAL_CONTENT, data(200_000)[..65536].to_vec())
    );
}

/// The ETag a copy reports.
async fn copy(app: &Arc<App>, src: &str, dst: &str, keys: CopyKeys<'_>) -> (StatusCode, String) {
    let response = copy_object(
        app,
        BUCKET,
        dst,
        &format!("{BUCKET}/{src}"),
        None,
        "x",
        "",
        &Preconditions::default(),
        keys,
    )
    .await
    .unwrap();
    let status = response.status();
    use http_body_util::BodyExt;
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8(body.to_vec()).unwrap();
    let etag = body
        .find("<ETag>\"")
        .map(|i| body[i + 7..i + 39].to_owned())
        .unwrap_or_default();
    (status, etag)
}

async fn blob_and_salt(app: &App, key: &str) -> (Uuid, Option<Vec<u8>>) {
    let client = app.pool.get().await.unwrap();
    let row = client
        .query_one(
            "SELECT p.blob_id, p.enc_salt FROM parts p JOIN objects o ON o.id = p.object_id
             WHERE o.key = $1 AND o.is_latest",
            &[&key],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1))
}

/// A copy shares the source's bytes if both have the same key (or neither has
/// one); otherwise it decrypts and encrypts again. Either way, it reads back
/// with its own key only.
#[tokio::test]
async fn copies_keep_or_change_encryption() {
    let Some(app) = node().await else { return };
    let (k1, k2) = (customer_key(&[1; 32]), customer_key(&[2; 32]));
    let plain = data(200_000);
    let etag = put_sealed(&app, "src", plain.clone(), &k1).await;
    put(&app, "plain", plain.clone()).await;

    // The same key: shared bytes, and the source's ETag.
    let same = CopyKeys {
        source: Some(&k1),
        dest: Wanted::Customer(&k1), role: None,
    };
    assert_eq!(
        copy(&app, "src", "same", same).await,
        (StatusCode::OK, etag.clone())
    );
    assert_eq!(
        blob_and_salt(&app, "same").await,
        blob_and_salt(&app, "src").await
    );
    assert_eq!(
        get_sealed(&app, "same", None, Some(&k1)).await,
        (StatusCode::OK, plain.clone())
    );
    assert_eq!(
        get_sealed(&app, "same", None, None).await.0,
        StatusCode::BAD_REQUEST
    );

    // Another key, none, or one where there was none: new bytes.
    for (name, src, keys, read_with) in [
        (
            "rekeyed",
            "src",
            CopyKeys {
                source: Some(&k1),
                dest: Wanted::Customer(&k2), role: None,
            },
            Some(&k2),
        ),
        (
            "decrypted",
            "src",
            CopyKeys {
                source: Some(&k1),
                dest: Wanted::Plain, role: None,
            },
            None,
        ),
        (
            "encrypted",
            "plain",
            CopyKeys {
                source: None,
                dest: Wanted::Customer(&k2), role: None,
            },
            Some(&k2),
        ),
    ] {
        let (status, etag) = copy(&app, src, name, keys).await;
        assert_eq!(status, StatusCode::OK, "{name}");
        assert_ne!(
            blob_and_salt(&app, name).await.0,
            blob_and_salt(&app, src).await.0,
            "{name}"
        );
        assert_eq!(
            get_sealed(&app, name, None, read_with).await,
            (StatusCode::OK, plain.clone()),
            "{name}"
        );
        let wrong = if read_with.is_some() {
            Some(&k1)
        } else {
            Some(&k2)
        };
        assert_eq!(
            get_sealed(&app, name, None, wrong).await.0,
            StatusCode::BAD_REQUEST,
            "{name}"
        );
        let md5: String = {
            use md5::Digest;
            md5::Md5::digest(&plain)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        };
        // Only a plain copy's ETag is its MD5.
        assert_eq!(etag == md5, read_with.is_none(), "{name}");
    }

    // The source's key is needed, and must be right.
    for source in [None, Some(&k2)] {
        let keys = CopyKeys {
            source,
            dest: Wanted::Customer(&k1), role: None,
        };
        assert_eq!(
            copy(&app, "src", "nope", keys).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    // Onto itself: changing the key is a change; keeping it isn't.
    assert_eq!(
        copy(&app, "src", "src", same).await.0,
        StatusCode::BAD_REQUEST
    );
    let rotate = CopyKeys {
        source: Some(&k1),
        dest: Wanted::Customer(&k2), role: None,
    };
    assert_eq!(copy(&app, "src", "src", rotate).await.0, StatusCode::OK);
    assert_eq!(
        get_sealed(&app, "src", None, Some(&k2)).await,
        (StatusCode::OK, plain.clone())
    );
    assert_eq!(
        get_sealed(&app, "src", None, Some(&k1)).await.0,
        StatusCode::BAD_REQUEST
    );
}

/// UploadPartCopy streams any range of an SSE-C source, or into an SSE-C
/// upload, which needs its key as an UploadPart does.
#[tokio::test]
async fn part_copies_of_and_into_sse_c() {
    let Some(app) = node().await else { return };
    let (k1, k2) = (customer_key(&[1; 32]), customer_key(&[2; 32]));
    let plain = data(200_000);
    put_sealed(&app, "src", plain.clone(), &k1).await;
    put(&app, "plain", plain.clone()).await;
    let upload = |customer: Option<&crate::s3::sse_c::CustomerKey>| {
        let app = app.clone();
        let customer = customer.map(|c| customer_key(c.key()));
        async move {
            let response = create_multipart_upload(&app, BUCKET, "dst", "x", "", Wanted::new(customer.as_ref(), None), None)
                .await
                .unwrap();
            use http_body_util::BodyExt;
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let body = String::from_utf8(body.to_vec()).unwrap();
            let start = body.find("<UploadId>").unwrap() + "<UploadId>".len();
            body[start..body.find("</UploadId>").unwrap()].to_owned()
        }
    };
    let part_copy =
        |upload_id: String, src: &'static str, range: &'static str, keys: CopyKeys<'_>| {
            let app = app.clone();
            let (source, dest) = (
                keys.source.map(|k| customer_key(k.key())),
                keys.dest.customer().map(|k| customer_key(k.key())),
            );
            async move {
                let response = copy_part(
                    &app,
                    BUCKET,
                    "dst",
                    &upload_id,
                    "1",
                    &format!("{BUCKET}/{src}"),
                    Some(range),
                    &Preconditions::default(),
                    source.as_ref(),
                    dest.as_ref(),
                    None,
                )
                .await
                .unwrap();
                response.status()
            }
        };
    let complete = |upload_id: String| {
        let app = app.clone();
        async move {
            let client = app.pool.get().await.unwrap();
            let etag: String = client
                .query_one(
                    "SELECT etag FROM parts WHERE upload_id = $1::text::uuid",
                    &[&upload_id],
                )
                .await
                .unwrap()
                .get(0);
            let body = Bytes::from(format!(
                "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"{etag}\"</ETag></Part></CompleteMultipartUpload>"
            ));
            complete_multipart_upload(
                &app,
                BUCKET,
                "dst",
                &upload_id,
                body,
                &Preconditions::default(),
                None,
            )
            .await
            .unwrap()
            .status()
        }
    };

    // A range of an SSE-C source, into a plain upload.
    let id = upload(None).await;
    assert_eq!(
        part_copy(
            id.clone(),
            "src",
            "bytes=60000-70000",
            CopyKeys {
                source: None,
                dest: Wanted::Plain, role: None,
            }
        )
        .await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        part_copy(
            id.clone(),
            "src",
            "bytes=60000-70000",
            CopyKeys {
                source: Some(&k1),
                dest: Wanted::Plain, role: None,
            }
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(complete(id).await, StatusCode::OK);
    assert_eq!(
        get_sealed(&app, "dst", None, None).await,
        (StatusCode::OK, plain[60_000..70_001].to_vec())
    );

    // A plain source's range, into an SSE-C upload: only with its key.
    let id = upload(Some(&k2)).await;
    assert_eq!(
        part_copy(
            id.clone(),
            "plain",
            "bytes=10-99999",
            CopyKeys {
                source: None,
                dest: Wanted::Plain, role: None,
            }
        )
        .await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        part_copy(
            id.clone(),
            "plain",
            "bytes=10-99999",
            CopyKeys {
                source: None,
                dest: Wanted::Customer(&k1), role: None,
            }
        )
        .await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        part_copy(
            id.clone(),
            "plain",
            "bytes=10-99999",
            CopyKeys {
                source: None,
                dest: Wanted::Customer(&k2), role: None,
            }
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(complete(id).await, StatusCode::OK);
    assert_eq!(
        get_sealed(&app, "dst", None, Some(&k2)).await,
        (StatusCode::OK, plain[10..100_000].to_vec())
    );
}
