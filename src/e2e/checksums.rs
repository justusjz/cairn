//! S3's checksums of objects and parts (see `s3::checksums`): stored as
//! they're written, and told back.

use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{HeaderMap, Response, StatusCode, body::Bytes};
use uuid::Uuid;

use super::{BUCKET, customer_key, node_with, put, put_sealed};
use crate::{
    App, AttachTarget, UploadResult,
    encryption::{self, Field, Owner, Salt},
    packer,
    payload::Payload,
    s3::{
        checksums::{self, Algorithm, Type, Wanted},
        conditional::Preconditions,
        multipart::{
            complete::complete_multipart_upload, create::create_multipart_upload, list_parts::list_parts,
            upload,
        },
        objects::{
            copy::{CopyKeys, copy_object, copy_part},
            get::head_object,
        },
        sse,
        sse_c::CustomerKey,
    },
};

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 + i / 7) as u8).collect()
}

/// The base64 checksum of `data`.
fn b64(algorithm: Algorithm, data: &[u8]) -> String {
    checksums::encode(&checksums::digest(algorithm, data))
}

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.insert(hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(), value.parse().unwrap());
    }
    map
}

async fn text(response: Response<Full<Bytes>>) -> (StatusCode, HeaderMap, String) {
    let (parts, body) = response.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    (parts.status, parts.headers, String::from_utf8(body.to_vec()).unwrap())
}

/// The checksum a HEAD with `x-amz-checksum-mode: ENABLED` tells: the
/// algorithm's header's value, and the type.
async fn told(app: &Arc<App>, key: &str, customer: Option<&CustomerKey>, range: Option<&str>) -> Option<(String, String)> {
    let response =
        head_object(app, BUCKET, key, None, range, None, &Preconditions::default(), customer, None, true).await.unwrap();
    assert!(response.status().is_success(), "{}", response.status());
    let kind = response.headers().get(checksums::TYPE)?.to_str().unwrap().to_owned();
    let value = Algorithm::ALL
        .into_iter()
        .find_map(|a| response.headers().get(a.header()).map(|v| format!("{}:{}", a.name(), v.to_str().unwrap())))?;
    Some((value, kind))
}

/// Writes `data` as `key` with the request `pairs` a PUT would have.
async fn put_with(app: &Arc<App>, key: &str, data: Vec<u8>, pairs: &[(&str, &str)]) -> UploadResult {
    let attach = AttachTarget::Object {
        bucket: BUCKET.to_owned(),
        key: key.to_owned(),
        content_type: "x".to_owned(),
        metadata: String::new(),
        conditions: Preconditions::default(),
        sealing: None,
        checksum: Wanted::ClientsOr(Algorithm::Crc64Nvme),
        tags: String::new(),
        lock: Default::default(),
    };
    let unsigned = [&[("x-amz-content-sha256", "UNSIGNED-PAYLOAD")], pairs].concat();
    let payload = Payload::new(&headers(&unsigned), "secret", true).unwrap();
    crate::upload_part(app, Full::new(Bytes::from(data)), &attach, payload).await.unwrap()
}

/// What the catalog stores of the current version of `key`: its checksum's
/// algorithm, type and value.
async fn stored(app: &App, key: &str) -> (Option<String>, Option<String>, Option<String>) {
    let client = app.pool.get().await.unwrap();
    let row = client
        .query_one(
            "SELECT checksum_algorithm, checksum_type, checksum FROM objects
             WHERE bucket = $1 AND key = $2 AND is_latest",
            &[&BUCKET, &key],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1), row.get(2))
}

/// A PUT gets the client's checksum, or S3's default, CRC64NVME; a read tells
/// it only when asked, and not for a range.
#[tokio::test]
async fn puts_store_the_clients_checksum_or_crc64nvme() {
    let Some(app) = node().await else { return };
    let body = data(100_000);
    put(&app, "default", body.clone()).await;
    let crc64 = b64(Algorithm::Crc64Nvme, &body);
    assert_eq!(told(&app, "default", None, None).await, Some((format!("CRC64NVME:{crc64}"), "FULL_OBJECT".into())));
    assert_eq!(told(&app, "default", None, Some("bytes=0-9")).await, None);
    let response = head_object(&app, BUCKET, "default", None, None, None, &Preconditions::default(), None, None, false)
        .await
        .unwrap();
    assert!(response.headers().get(checksums::TYPE).is_none());

    // The client's, sent in a header.
    let sha = b64(Algorithm::Sha256, &body);
    let result = put_with(&app, "sha", body.clone(), &[("x-amz-checksum-sha256", &sha)]).await;
    let UploadResult::Committed { checksum: Some(checksum), .. } = result else { panic!("not committed") };
    assert_eq!(checksum, checksums::Checksum::full(Algorithm::Sha256, &checksums::digest(Algorithm::Sha256, &body)));
    assert_eq!(told(&app, "sha", None, None).await, Some((format!("SHA256:{sha}"), "FULL_OBJECT".into())));
    assert_eq!(stored(&app, "sha").await, (Some("SHA256".into()), Some("FULL_OBJECT".into()), Some(sha)));
}

/// An encrypted object's checksum is stored sealed, and told only with its
/// key.
#[tokio::test]
async fn an_sse_c_objects_checksum_is_sealed() {
    let Some(app) = node().await else { return };
    let customer = customer_key(&[5; 32]);
    let body = data(70_000);
    put_sealed(&app, "c", body.clone(), &customer).await;
    let crc64 = b64(Algorithm::Crc64Nvme, &body);
    let (algorithm, _, value) = stored(&app, "c").await;
    assert_eq!(algorithm.as_deref(), Some("CRC64NVME"));
    assert_ne!(value.as_deref(), Some(crc64.as_str()), "stored sealed");
    assert_eq!(told(&app, "c", Some(&customer), None).await, Some((format!("CRC64NVME:{crc64}"), "FULL_OBJECT".into())));
    // Without the key, the object can't be read at all.
    let response =
        head_object(&app, BUCKET, "c", None, None, None, &Preconditions::default(), None, None, true).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// A new upload asking for `checksum`, encrypted with `customer`'s key if
/// it's given. Its ID.
async fn create(app: &Arc<App>, key: &str, checksum: Option<(Algorithm, Type)>, customer: Option<&CustomerKey>) -> String {
    let wanted = sse::Wanted::new(customer, None);
    let response = create_multipart_upload(app, BUCKET, key, "x", "", "", wanted, None, checksum, Default::default()).await.unwrap();
    let (status, headers, body) = text(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(checksums::ALGORITHM).map(|v| v.to_str().unwrap().to_owned()),
        checksum.map(|(a, _)| a.name().to_owned())
    );
    let start = body.find("<UploadId>").unwrap() + "<UploadId>".len();
    body[start..body.find("</UploadId>").unwrap()].to_owned()
}

/// Uploads part `number` of `upload_id` with `data`, the client sending a
/// checksum of `sent` (in a header). Its ETag, or the rejection's code.
async fn upload_part(
    app: &Arc<App>,
    key: &str,
    upload_id: &str,
    number: i32,
    data: &[u8],
    sent: Option<Algorithm>,
    customer: Option<&CustomerKey>,
) -> Result<String, String> {
    let id: Uuid = upload_id.parse().unwrap();
    let upload = upload(app, &id, BUCKET, key).await.unwrap().unwrap();
    // As `put_part` checks it.
    if upload.mismatch(sent).is_some() {
        return Err("InvalidRequest".into());
    }
    let upload_key = sse::open(app, &upload.encryption, customer, None, BUCKET, key).await.unwrap().ok().unwrap();
    let attach = AttachTarget::MultipartPart {
        upload_id: id,
        part_number: number,
        key: upload_key,
        sse_s3: false,
        checksum: upload.part_checksum(),
    };
    let value = sent.map(|a| (a.header(), b64(a, data)));
    let mut pairs = vec![("x-amz-content-sha256", "UNSIGNED-PAYLOAD".to_owned())];
    pairs.extend(value.clone());
    let pairs: Vec<(&str, &str)> = pairs.iter().map(|(n, v)| (*n, v.as_str())).collect();
    let payload = Payload::new(&headers(&pairs), "secret", true).unwrap();
    match crate::upload_part(app, Full::new(Bytes::from(data.to_vec())), &attach, payload).await.unwrap() {
        UploadResult::Committed { etag, .. } => Ok(etag),
        UploadResult::Rejected(rejection) => Err(rejection.code.to_owned()),
        _ => panic!("neither committed nor rejected"),
    }
}

/// Completes `upload_id` with `parts` (number, ETag, listed checksums), and
/// the request `pairs`: the status, headers and body.
async fn complete(
    app: &Arc<App>,
    key: &str,
    upload_id: &str,
    parts: &[(i32, &str, &[(Algorithm, String)])],
    pairs: &[(&str, &str)],
    customer: Option<&CustomerKey>,
) -> (StatusCode, HeaderMap, String) {
    let listed: String = parts
        .iter()
        .map(|(n, etag, checksums)| {
            let checksums: String = checksums
                .iter()
                .map(|(a, v)| format!("<{0}>{v}</{0}>", a.element()))
                .collect();
            format!("<Part><PartNumber>{n}</PartNumber><ETag>\"{etag}\"</ETag>{checksums}</Part>")
        })
        .collect();
    let body = Bytes::from(format!("<CompleteMultipartUpload>{listed}</CompleteMultipartUpload>"));
    let claimed = checksums::claimed(&headers(pairs)).ok().unwrap();
    let response = complete_multipart_upload(
        app,
        BUCKET,
        key,
        upload_id,
        body,
        &Preconditions::default(),
        customer,
        None,
        None,
        claimed,
    )
    .await
    .unwrap();
    text(response).await
}

const MIN: usize = crate::s3::util::MIN_PART as usize;

/// A COMPOSITE upload: its parts must carry its algorithm's checksums, and be
/// listed with them; its object's is the checksum of theirs, with `-N`.
#[tokio::test]
async fn composite_uploads() {
    let Some(app) = node().await else { return };
    let (one, two) = (data(MIN), data(1000));
    let id = create(&app, "m", Some((Algorithm::Sha256, Type::Composite)), None).await;
    // A part without its checksum, or of another algorithm, is refused.
    assert_eq!(upload_part(&app, "m", &id, 1, &one, None, None).await, Err("InvalidRequest".into()));
    assert_eq!(upload_part(&app, "m", &id, 1, &one, Some(Algorithm::Crc32), None).await, Err("InvalidRequest".into()));
    let e1 = upload_part(&app, "m", &id, 1, &one, Some(Algorithm::Sha256), None).await.unwrap();
    let e2 = upload_part(&app, "m", &id, 2, &two, Some(Algorithm::Sha256), None).await.unwrap();
    let (c1, c2) = (b64(Algorithm::Sha256, &one), b64(Algorithm::Sha256, &two));

    // ListParts tells them, and the upload's algorithm and type.
    let (_, _, listed) = text(list_parts(&app, BUCKET, "m", &id, 0, 1000, None, None).await.unwrap()).await;
    assert!(listed.contains("<ChecksumAlgorithm>SHA256</ChecksumAlgorithm><ChecksumType>COMPOSITE</ChecksumType>"));
    assert!(listed.contains(&format!("<ChecksumSHA256>{c2}</ChecksumSHA256>")), "{listed}");

    // A part listed without its checksum is refused; one with a wrong one
    // isn't the part.
    let sha = |v: &str| vec![(Algorithm::Sha256, v.to_owned())];
    let (good1, good2, wrong) = (sha(&c1), sha(&c2), sha(&c1));
    let (status, _, body) = complete(&app, "m", &id, &[(1, &e1, &good1), (2, &e2, &[])], &[], None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("InvalidRequest") && body.contains("missing for part 2"), "{body}");
    let (status, _, body) = complete(&app, "m", &id, &[(1, &e1, &good1), (2, &e2, &wrong)], &[], None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("InvalidPart"), "{body}");

    // A wrong object checksum claimed: BadDigest, and nothing's published.
    let parts = [(1, e1.as_str(), good1.as_slice()), (2, e2.as_str(), good2.as_slice())];
    let claim = [("x-amz-checksum-sha256", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")];
    let (status, _, body) = complete(&app, "m", &id, &parts, &claim, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("BadDigest"));
    assert!(super::get(&app, "m").await.is_none());

    let raws = vec![checksums::digest(Algorithm::Sha256, &one), checksums::digest(Algorithm::Sha256, &two)];
    let composite = checksums::composite(Algorithm::Sha256, &raws);
    let claim = [("x-amz-checksum-sha256", composite.as_str()), ("x-amz-checksum-type", "COMPOSITE")];
    let (status, _, body) = complete(&app, "m", &id, &parts, &claim, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains(&format!("<ChecksumSHA256>{composite}</ChecksumSHA256><ChecksumType>COMPOSITE</ChecksumType>")), "{body}");
    assert_eq!(told(&app, "m", None, None).await, Some((format!("SHA256:{composite}"), "COMPOSITE".into())));
    // A retry, whose upload is gone, is answered the same.
    let (status, _, again) = complete(&app, "m", &id, &parts, &[], None).await;
    assert_eq!((status, again), (StatusCode::OK, body));
}

/// A FULL_OBJECT upload's object checksum is its parts' combined: of the
/// algorithm asked for, or, without one, S3's default, CRC64NVME. Its parts
/// may come without their checksums, and be listed without them, as in S3.
#[tokio::test]
async fn full_object_uploads() {
    let Some(app) = node().await else { return };
    let (one, two) = (data(MIN), data(70_001));
    let whole = [one.clone(), two.clone()].concat();
    for (key, checksum, sent) in [
        ("crc32c", Some((Algorithm::Crc32c, Type::FullObject)), true),
        ("crc64", Some((Algorithm::Crc64Nvme, Type::FullObject)), true),
        ("default", None, false),
        ("crc32-unsent", Some((Algorithm::Crc32, Type::FullObject)), false),
        ("crc64-unsent", Some((Algorithm::Crc64Nvme, Type::FullObject)), false),
    ] {
        let algorithm = checksum.map_or(Algorithm::Crc64Nvme, |(a, _)| a);
        let id = create(&app, key, checksum, None).await;
        // Another algorithm's is refused, though.
        if let Some((a, _)) = checksum {
            let other = if a == Algorithm::Crc32 { Algorithm::Crc32c } else { Algorithm::Crc32 };
            assert_eq!(upload_part(&app, key, &id, 1, &one, Some(other), None).await, Err("InvalidRequest".into()));
        }
        let sent = checksum.filter(|_| sent).map(|(a, _)| a);
        let e1 = upload_part(&app, key, &id, 1, &one, sent, None).await.unwrap();
        let e2 = upload_part(&app, key, &id, 2, &two, sent, None).await.unwrap();
        // Listed, the parts' checksums are checked.
        if let Some((a, _)) = checksum {
            let wrong = [(a, b64(a, &two))];
            let (status, _, body) = complete(&app, key, &id, &[(1, &e1, &wrong), (2, &e2, &[])], &[], None).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(body.contains("InvalidPart"), "{body}");
        }
        let listed = |data: &[u8]| match sent {
            Some(a) => vec![(a, b64(a, data))],
            None => vec![],
        };
        let (l1, l2) = (listed(&one), listed(&two));
        let (status, _, body) = complete(&app, key, &id, &[(1, &e1, &l1), (2, &e2, &l2)], &[], None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let expected = b64(algorithm, &whole);
        assert_eq!(told(&app, key, None, None).await, Some((format!("{}:{expected}", algorithm.name()), "FULL_OBJECT".into())), "{key}");
    }
}

/// An SSE-C upload of an algorithm needs its key to complete (its checksums
/// are sealed under it); one without an algorithm gets no checksum.
#[tokio::test]
async fn sse_c_uploads() {
    let Some(app) = node().await else { return };
    let customer = customer_key(&[9; 32]);
    let (one, two) = (data(MIN), data(10));
    let id = create(&app, "c", Some((Algorithm::Crc32, Type::Composite)), Some(&customer)).await;
    let e1 = upload_part(&app, "c", &id, 1, &one, Some(Algorithm::Crc32), Some(&customer)).await.unwrap();
    let e2 = upload_part(&app, "c", &id, 2, &two, Some(Algorithm::Crc32), Some(&customer)).await.unwrap();
    let (l1, l2) = (vec![(Algorithm::Crc32, b64(Algorithm::Crc32, &one))], vec![(Algorithm::Crc32, b64(Algorithm::Crc32, &two))]);
    let parts = [(1, e1.as_str(), l1.as_slice()), (2, e2.as_str(), l2.as_slice())];
    // ListParts tells the parts' checksums only with the key.
    let (_, _, without) = text(list_parts(&app, BUCKET, "c", &id, 0, 1000, None, None).await.unwrap()).await;
    assert!(!without.contains("<ChecksumCRC32>"), "{without}");
    let (_, _, with) = text(list_parts(&app, BUCKET, "c", &id, 0, 1000, Some(&customer), None).await.unwrap()).await;
    assert!(with.contains(&format!("<ChecksumCRC32>{}</ChecksumCRC32>", l2[0].1)), "{with}");
    let (status, _, body) = complete(&app, "c", &id, &parts, &[], None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("InvalidArgument"), "{body}");
    let (status, _, body) = complete(&app, "c", &id, &parts, &[], Some(&customer)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let raws = vec![checksums::digest(Algorithm::Crc32, &one), checksums::digest(Algorithm::Crc32, &two)];
    let composite = checksums::composite(Algorithm::Crc32, &raws);
    assert_eq!(told(&app, "c", Some(&customer), None).await, Some((format!("CRC32:{composite}"), "COMPOSITE".into())));
    assert_ne!(stored(&app, "c").await.2, Some(composite), "stored sealed");
    // Nor are its parts': none of them is stored as it's told.
    let parts: Vec<(String, Vec<u8>)> = app
        .pool
        .get()
        .await
        .unwrap()
        .query(
            "SELECT p.checksum, p.enc_salt FROM parts p JOIN objects o ON o.id = p.object_id
             WHERE o.key = 'c' ORDER BY p.part_number",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    assert_eq!(parts.len(), 2);
    let salts: Vec<Salt> = parts.iter().map(|(_, salt)| salt.as_slice().try_into().unwrap()).collect();
    // The object's key, which the client's opens.
    let sealed: Vec<u8> = app.pool.get().await.unwrap().query_one("SELECT sse_c_key FROM objects WHERE key = 'c'", &[]).await.unwrap().get(0);
    let stored = sse::Stored::Customer { sealed };
    let object_key = sse::open(&app, &stored, Some(&customer), None, BUCKET, "c").await.unwrap().ok().unwrap().unwrap();
    for (i, (part, _)) in parts.iter().enumerate() {
        assert!(*part != l1[0].1 && *part != l2[0].1, "a part's checksum is stored in plaintext");
        let open = |salt| encryption::open_value(&object_key, Field::Checksum, Owner::Part(salt), part);
        assert!(open(&salts[i]).is_some(), "sealed under the object's key, as the part's");
        assert!(open(&salts[1 - i]).is_none(), "not as another part's");
    }

    // Without an algorithm: no checksum, and no key needed.
    let id = create(&app, "n", None, Some(&customer)).await;
    let e1 = upload_part(&app, "n", &id, 1, &one, None, Some(&customer)).await.unwrap();
    let (status, _, body) = complete(&app, "n", &id, &[(1, &e1, &[])], &[], None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(told(&app, "n", Some(&customer), None).await, None);
}

/// A copy gets the checksum it asks for, else its source's (a COMPOSITE
/// one's as FULL_OBJECT), else CRC64NVME; UploadPartCopy's part its upload's.
#[tokio::test]
async fn copies() {
    let Some(app) = node().await else { return };
    let body = data(100_000);
    let sha = b64(Algorithm::Sha256, &body);
    put_with(&app, "sha", body.clone(), &[("x-amz-checksum-sha256", &sha)]).await;
    let copy = |dest: &'static str, checksum: Option<Algorithm>| {
        let app = app.clone();
        async move {
            let keys = CopyKeys { checksum, ..CopyKeys::default() };
            let response = copy_object(&app, BUCKET, dest, &format!("{BUCKET}/sha"), None, "x", "", None, &Preconditions::default(), keys)
                .await
                .unwrap();
            text(response).await
        }
    };
    let (status, _, result) = copy("same", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(result.contains(&format!("<ChecksumSHA256>{sha}</ChecksumSHA256><ChecksumType>FULL_OBJECT</ChecksumType>")), "{result}");
    assert_eq!(told(&app, "same", None, None).await, Some((format!("SHA256:{sha}"), "FULL_OBJECT".into())));
    let (status, _, _) = copy("crc32", Some(Algorithm::Crc32)).await;
    assert_eq!(status, StatusCode::OK);
    let crc32 = b64(Algorithm::Crc32, &body);
    assert_eq!(told(&app, "crc32", None, None).await, Some((format!("CRC32:{crc32}"), "FULL_OBJECT".into())));

    // A COMPOSITE source: the copy's is FULL_OBJECT, of the same algorithm.
    let (one, two) = (data(MIN), data(1000));
    let id = create(&app, "multi", Some((Algorithm::Crc32c, Type::Composite)), None).await;
    let e1 = upload_part(&app, "multi", &id, 1, &one, Some(Algorithm::Crc32c), None).await.unwrap();
    let e2 = upload_part(&app, "multi", &id, 2, &two, Some(Algorithm::Crc32c), None).await.unwrap();
    let (l1, l2) = (vec![(Algorithm::Crc32c, b64(Algorithm::Crc32c, &one))], vec![(Algorithm::Crc32c, b64(Algorithm::Crc32c, &two))]);
    let (status, _, _) = complete(&app, "multi", &id, &[(1, &e1, &l1), (2, &e2, &l2)], &[], None).await;
    assert_eq!(status, StatusCode::OK);
    let keys = CopyKeys::default();
    let response = copy_object(&app, BUCKET, "flat", &format!("{BUCKET}/multi"), None, "x", "", None, &Preconditions::default(), keys)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let whole = [one.clone(), two.clone()].concat();
    let crc32c = b64(Algorithm::Crc32c, &whole);
    assert_eq!(told(&app, "flat", None, None).await, Some((format!("CRC32C:{crc32c}"), "FULL_OBJECT".into())));

    // UploadPartCopy into an upload of SHA1: the part's checksum is worked
    // out, whole part or range.
    let id = create(&app, "parts", Some((Algorithm::Sha1, Type::Composite)), None).await;
    let source = format!("{BUCKET}/multi");
    let mut etags = Vec::new();
    for (number, range, bytes) in [("1", "bytes=0-5242879", &one[..]), ("2", "bytes=5242880-5242979", &two[..100])] {
        let response =
            copy_part(&app, BUCKET, "parts", &id, number, &source, Some(range), &Preconditions::default(), None, None, None)
                .await
                .unwrap();
        let (status, _, body) = text(response).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let checksum = b64(Algorithm::Sha1, bytes);
        assert!(body.contains(&format!("<ChecksumSHA1>{checksum}</ChecksumSHA1>")), "{body}");
        let start = body.find("<ETag>\"").unwrap() + 7;
        etags.push((body[start..start + 32].to_owned(), vec![(Algorithm::Sha1, checksum)]));
    }
    let parts: Vec<(i32, &str, &[(Algorithm, String)])> =
        etags.iter().enumerate().map(|(i, (e, c))| (i as i32 + 1, e.as_str(), c.as_slice())).collect();
    let (status, _, body) = complete(&app, "parts", &id, &parts, &[], None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// The checksums of objects from before them: none, and nothing told.
#[tokio::test]
async fn objects_from_before_have_none() {
    let Some(app) = node().await else { return };
    put(&app, "old", data(10)).await;
    app.pool
        .get()
        .await
        .unwrap()
        .execute("UPDATE objects SET checksum_algorithm = NULL, checksum_type = NULL, checksum = NULL", &[])
        .await
        .unwrap();
    assert_eq!(told(&app, "old", None, None).await, None);
    // A copy of it works its checksum out: CRC64NVME, from its part's CRC.
    let keys = CopyKeys::default();
    let response = copy_object(&app, BUCKET, "new", &format!("{BUCKET}/old"), None, "x", "", None, &Preconditions::default(), keys)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let crc64 = b64(Algorithm::Crc64Nvme, &data(10));
    assert_eq!(told(&app, "new", None, None).await, Some((format!("CRC64NVME:{crc64}"), "FULL_OBJECT".into())));
}
