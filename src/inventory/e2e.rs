//! Inventory reports against a real Postgres (see `e2e`), with the clock
//! moved ahead instead of waiting.

use std::{
    collections::{BTreeMap, HashSet},
    io::Read,
    sync::Arc,
    time::{Duration, SystemTime},
};

use http_body_util::BodyExt;
use hyper::{StatusCode, body::Bytes};

use crate::{
    App,
    e2e::{BUCKET, node_with, put},
    lifecycle::pass,
    packer,
    s3::{
        buckets::{inventory, lifecycle::put_bucket_lifecycle, policy::put_bucket_policy},
        conditional::Preconditions,
        objects::get::get_object,
    },
};

/// The destination bucket.
const REPORTS: &str = "reports";
const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(3600);

async fn node() -> Option<Arc<App>> {
    let app = node_with(packer::Config::default(), None).await?;
    app.pool.get().await.unwrap().execute("INSERT INTO buckets (name) VALUES ($1)", &[&REPORTS]).await.unwrap();
    Some(app)
}

/// The destination policy S3's user guide gives, for reports of `BUCKET`.
fn destination_policy(account: &str) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Sid":"InventoryExamplePolicy","Effect":"Allow",
            "Principal":{{"Service":"s3.amazonaws.com"}},"Action":"s3:PutObject",
            "Resource":["arn:aws:s3:::{REPORTS}/*"],
            "Condition":{{"ArnLike":{{"aws:SourceArn":"arn:aws:s3:::{BUCKET}"}},
                "StringEquals":{{"aws:SourceAccount":"{account}","s3:x-amz-acl":"bucket-owner-full-control"}}}}}}]}}"#
    )
}

async fn allow_delivery(app: &App) {
    let account = crate::users::account(&app.pool.get().await.unwrap()).await.unwrap();
    let response = put_bucket_policy(app, REPORTS, Bytes::from(destination_policy(&account))).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT, "{:?}", response.into_body());
}

fn configuration(id: &str, versions: &str, extra: &str) -> String {
    format!(
        "<InventoryConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Destination><S3BucketDestination><Bucket>arn:aws:s3:::{REPORTS}</Bucket>\
         <Format>CSV</Format><Prefix>inv</Prefix></S3BucketDestination></Destination>\
         <IsEnabled>true</IsEnabled><Id>{id}</Id>\
         <IncludedObjectVersions>{versions}</IncludedObjectVersions>\
         <Schedule><Frequency>Daily</Frequency></Schedule>{extra}</InventoryConfiguration>"
    )
}

async fn configure(app: &App, id: &str, body: String) -> StatusCode {
    let response = inventory::put(app, BUCKET, &format!("inventory&id={id}"), Bytes::from(body), None).await.unwrap();
    response.status()
}

async fn body_of(response: hyper::Response<http_body_util::Full<Bytes>>) -> String {
    String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
}

async fn set_rate(app: &App, rate: i64) {
    crate::settings::LIFECYCLE_RATE.set(&app.pool.get().await.unwrap(), rate).await.unwrap();
}

/// Takes the step due `after` from now.
async fn step_at(app: &Arc<App>, after: Duration) {
    for result in pass(app, SystemTime::now() + after).await {
        result.map_err(|(_, e)| e).unwrap();
    }
}

/// The destination bucket's keys.
async fn reports(app: &App) -> Vec<String> {
    let rows = app
        .pool
        .get()
        .await
        .unwrap()
        .query("SELECT key FROM objects WHERE bucket = $1 AND is_latest ORDER BY key", &[&REPORTS])
        .await
        .unwrap();
    rows.iter().map(|row| row.get(0)).collect()
}

async fn read(app: &Arc<App>, key: &str) -> Vec<u8> {
    let response = get_object(app, REPORTS, key, None, None, None, &Preconditions::default(), None, None, false)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{key}");
    response.into_body().collect().await.unwrap().to_bytes().to_vec()
}

fn md5_hex(data: &[u8]) -> String {
    use md5::Digest;
    super::hex(&md5::Md5::digest(data))
}

/// The report's manifest (by its key) and data files' lines, checked
/// against the manifest's sizes and MD5s, its checksum file and its symlink
/// file.
async fn delivered(app: &Arc<App>) -> (String, serde_json::Value, Vec<String>) {
    let keys = reports(app).await;
    let manifest_key = keys.iter().find(|k| k.ends_with("/manifest.json")).expect("a manifest").clone();
    let manifest = read(app, &manifest_key).await;
    let checksum = read(app, &manifest_key.replace("manifest.json", "manifest.checksum")).await;
    assert_eq!(String::from_utf8(checksum).unwrap(), md5_hex(&manifest));
    let manifest: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
    let symlink_key = keys.iter().find(|k| k.ends_with("/symlink.txt")).expect("a symlink file");
    let symlink = String::from_utf8(read(app, symlink_key).await).unwrap();
    let mut lines = Vec::new();
    let mut urls = Vec::new();
    for file in manifest["files"].as_array().unwrap() {
        let key = file["key"].as_str().unwrap();
        let data = read(app, key).await;
        assert_eq!(data.len() as u64, file["size"].as_u64().unwrap());
        assert_eq!(md5_hex(&data), file["MD5checksum"].as_str().unwrap());
        let mut text = String::new();
        flate2::read::MultiGzDecoder::new(&data[..]).read_to_string(&mut text).unwrap();
        lines.extend(text.lines().map(str::to_owned));
        urls.push(format!("s3://{REPORTS}/{key}"));
    }
    assert_eq!(symlink.lines().collect::<Vec<_>>(), urls);
    (manifest_key, manifest, lines)
}

#[tokio::test]
async fn configurations_are_set_read_listed_and_deleted() {
    let Some(app) = node().await else { return };
    let none = inventory::get(&app, BUCKET, "inventory&id=daily").await.unwrap();
    assert_eq!(none.status(), StatusCode::NOT_FOUND);
    assert!(body_of(none).await.contains("<Code>NoSuchConfiguration</Code>"));
    let body = configuration("daily", "Current", "<OptionalFields><Field>Size</Field></OptionalFields>");
    assert_eq!(configure(&app, "daily", body.clone()).await, StatusCode::OK);
    let got = body_of(inventory::get(&app, BUCKET, "inventory&id=daily").await.unwrap()).await;
    assert!(got.contains("<Id>daily</Id>") && got.contains("<Field>Size</Field>"), "{got}");
    assert!(got.contains("<Bucket>arn:aws:s3:::reports</Bucket>"), "{got}");
    // The request's ID must be the body's.
    assert_eq!(configure(&app, "other", body).await, StatusCode::BAD_REQUEST);
    // Only CSV.
    let parquet = configuration("p", "All", "").replace("<Format>CSV</Format>", "<Format>Parquet</Format>");
    assert_eq!(configure(&app, "p", parquet).await, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(configure(&app, "weekly", configuration("weekly", "All", "")).await, StatusCode::OK);
    let listed = body_of(inventory::get(&app, BUCKET, "inventory").await.unwrap()).await;
    assert!(listed.contains("<Id>daily</Id>") && listed.contains("<Id>weekly</Id>"), "{listed}");
    assert!(listed.contains("<IsTruncated>false</IsTruncated>"), "{listed}");
    let deleted = inventory::delete(&app, BUCKET, "inventory&id=daily").await.unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    let again = inventory::delete(&app, BUCKET, "inventory&id=daily").await.unwrap();
    assert_eq!(again.status(), StatusCode::NOT_FOUND);
    let missing = inventory::get(&app, "nope", "inventory").await.unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn lists_are_paged_and_a_bucket_has_at_most_a_thousand() {
    let Some(app) = node().await else { return };
    for i in 0..1000 {
        let id = format!("c{i:04}");
        assert_eq!(configure(&app, &id, configuration(&id, "Current", "")).await, StatusCode::OK);
    }
    let response = inventory::put(&app, BUCKET, "inventory&id=more", Bytes::from(configuration("more", "All", "")), None)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(body_of(response).await.contains("TooManyConfigurations"));
    // Replacing one is fine.
    assert_eq!(configure(&app, "c0001", configuration("c0001", "All", "")).await, StatusCode::OK);
    let mut ids = Vec::new();
    let mut query = "inventory".to_owned();
    loop {
        let page = body_of(inventory::get(&app, BUCKET, &query).await.unwrap()).await;
        ids.extend(page.match_indices("<Id>").map(|(i, _)| page[i + 4..i + 9].to_owned()));
        let Some(start) = page.find("<NextContinuationToken>") else { break };
        let token = &page[start + 23..page.find("</NextContinuationToken>").unwrap()];
        query = format!("inventory&continuation-token={token}");
    }
    assert_eq!(ids.len(), 1000);
    assert_eq!(ids.first().unwrap(), "c0000");
    assert_eq!(ids.last().unwrap(), "c0999");
}

#[tokio::test]
async fn a_report_is_delivered_as_s3_delivers_it() {
    let Some(app) = node().await else { return };
    allow_delivery(&app).await;
    put(&app, "photos/a b.jpg", b"hello".to_vec()).await;
    put(&app, "photos/c.jpg", b"hi".to_vec()).await;
    put(&app, "other.txt", b"x".to_vec()).await;
    let fields = "<Filter><Prefix>photos/</Prefix></Filter><OptionalFields><Field>ETag</Field>\
                  <Field>Size</Field><Field>EncryptionStatus</Field><Field>StorageClass</Field>\
                  <Field>IsMultipartUploaded</Field></OptionalFields>";
    assert_eq!(configure(&app, "daily", configuration("daily", "Current", fields)).await, StatusCode::OK);
    step_at(&app, Duration::ZERO).await;
    let (manifest_key, manifest, lines) = delivered(&app).await;
    assert!(manifest_key.starts_with(&format!("inv/{BUCKET}/daily/")), "{manifest_key}");
    assert_eq!(manifest["sourceBucket"], BUCKET);
    assert_eq!(manifest["destinationBucket"], "arn:aws:s3:::reports");
    assert_eq!(manifest["fileFormat"], "CSV");
    assert_eq!(manifest["fileSchema"], "Bucket, Key, Size, ETag, StorageClass, IsMultipartUploaded, EncryptionStatus");
    let files = manifest["files"].as_array().unwrap();
    assert_eq!(files.len(), 1);
    assert!(files[0]["key"].as_str().unwrap().starts_with(&format!("inv/{BUCKET}/daily/data/")));
    assert!(files[0]["key"].as_str().unwrap().ends_with(".csv.gz"));
    // Keys URL-encoded, values quoted, ETags as MD5s.
    assert_eq!(
        lines,
        [
            format!("\"{BUCKET}\",\"photos/a+b.jpg\",\"5\",\"{}\",\"STANDARD\",\"false\",\"NOT-SSE\"", md5_hex(b"hello")),
            format!("\"{BUCKET}\",\"photos/c.jpg\",\"2\",\"{}\",\"STANDARD\",\"false\",\"NOT-SSE\"", md5_hex(b"hi")),
        ]
    );
    // The report is done: its files' rows are gone, and the next is due a
    // day after it started.
    let client = app.pool.get().await.unwrap();
    let row = client.query_one("SELECT started, last, due - now() > interval '23 hours' FROM inventories", &[]).await.unwrap();
    assert_eq!(row.get::<_, Option<SystemTime>>(0), None);
    let last: super::LastReport = serde_json::from_str(row.get(1)).unwrap();
    assert_eq!((last.read, last.files, last.manifest), (2, 1, manifest_key));
    assert!(row.get::<_, bool>(2));
    assert_eq!(client.query_one("SELECT count(*) FROM inventory_files", &[]).await.unwrap().get::<_, i64>(0), 0);
    // Nothing more today.
    let before = reports(&app).await;
    step_at(&app, MINUTE * 2).await;
    assert_eq!(reports(&app).await, before);
}

#[tokio::test]
async fn an_empty_bucket_gets_a_manifest_without_files() {
    let Some(app) = node().await else { return };
    allow_delivery(&app).await;
    assert_eq!(configure(&app, "daily", configuration("daily", "All", "")).await, StatusCode::OK);
    step_at(&app, Duration::ZERO).await;
    let (_, manifest, lines) = delivered(&app).await;
    assert_eq!(manifest["files"].as_array().unwrap().len(), 0);
    assert_eq!(manifest["fileSchema"], "Bucket, Key, VersionId, IsLatest, IsDeleteMarker");
    assert!(lines.is_empty());
}

#[tokio::test]
async fn delivery_needs_the_destination_policy() {
    let Some(app) = node().await else { return };
    put(&app, "a", b"a".to_vec()).await;
    assert_eq!(configure(&app, "daily", configuration("daily", "Current", "")).await, StatusCode::OK);
    step_at(&app, Duration::ZERO).await;
    assert!(reports(&app).await.is_empty());
    let client = app.pool.get().await.unwrap();
    let failure: Option<String> = client.query_one("SELECT failure FROM inventories", &[]).await.unwrap().get(0);
    assert!(failure.unwrap().contains("doesn't allow s3.amazonaws.com"));
    // A policy for another source bucket doesn't do.
    let account = crate::users::account(&client).await.unwrap();
    let other = destination_policy(&account).replace(&format!(":::{BUCKET}\""), ":::elsewhere\"");
    put_bucket_policy(&app, REPORTS, Bytes::from(other)).await.unwrap();
    step_at(&app, HOUR + MINUTE).await;
    assert!(reports(&app).await.is_empty());
    // It's tried again an hour later.
    allow_delivery(&app).await;
    step_at(&app, MINUTE * 5).await;
    assert!(reports(&app).await.is_empty(), "not before the hour is up");
    step_at(&app, HOUR * 3).await;
    let (_, _, lines) = delivered(&app).await;
    assert_eq!(lines, [format!("\"{BUCKET}\",\"a\"")]);
    let failure: Option<String> = client.query_one("SELECT failure FROM inventories", &[]).await.unwrap().get(0);
    assert_eq!(failure, None);
}

/// Gives `BUCKET` `n` keys, `k00001` on, of three versions each (the
/// newest current), straight in the catalog.
async fn versions(app: &App, n: i32) {
    app.pool
        .get()
        .await
        .unwrap()
        .execute(
            "INSERT INTO objects (bucket, key, version_id, is_latest, is_delete_marker, size, etag,
                                  content_type, last_modified)
             SELECT $1, 'k' || lpad(n::text, 5, '0'), 'v' || n || '-' || v, v = 3, false, v, 'e', 'text/plain', now()
             FROM generate_series(1, $2::int) AS n, generate_series(1, 3) AS v
             ORDER BY n, v",
            &[&BUCKET, &n],
        )
        .await
        .unwrap();
}

async fn debt(app: &App) -> i64 {
    app.pool.get().await.unwrap().query_one("SELECT debt FROM lifecycle_runs", &[]).await.unwrap().get(0)
}

async fn files_written(app: &App) -> i32 {
    app.pool.get().await.unwrap().query_one("SELECT files FROM inventories", &[]).await.unwrap().get(0)
}

#[tokio::test]
async fn reports_resume_file_by_file_at_the_rate() {
    let Some(app) = node().await else { return };
    allow_delivery(&app).await;
    // 25,002 versions; files of 10,000, which end within keys.
    versions(&app, 8334).await;
    // 1,000 versions a minute: a file is ten minutes of it.
    set_rate(&app, 60_000).await;
    assert_eq!(configure(&app, "all", configuration("all", "All", "")).await, StatusCode::OK);
    step_at(&app, Duration::ZERO).await;
    assert_eq!(files_written(&app).await, 1);
    // It read 9,000 more than its share: the next steps pay that off first.
    assert_eq!(debt(&app).await, 9000);
    // A step reads at most five minutes' share.
    step_at(&app, MINUTE * 5).await;
    assert_eq!((files_written(&app).await, debt(&app).await), (1, 4000));
    step_at(&app, MINUTE * 10).await;
    assert_eq!((files_written(&app).await, debt(&app).await), (2, 9000));
    // A step on another node, much later, carries on where it got to.
    step_at(&app, HOUR).await;
    step_at(&app, HOUR * 2).await;
    let (_, manifest, lines) = delivered(&app).await;
    assert_eq!(manifest["files"].as_array().unwrap().len(), 3);
    assert_eq!(lines.len(), 25_002);
    let unique: HashSet<&String> = lines.iter().collect();
    assert_eq!(unique.len(), 25_002, "no version twice");
    // Keys in order, each key's versions newest first.
    assert_eq!(lines[0], format!("\"{BUCKET}\",\"k00001\",\"v1-3\",\"true\",\"false\""));
    assert_eq!(lines[1], format!("\"{BUCKET}\",\"k00001\",\"v1-2\",\"false\",\"false\""));
    assert_eq!(lines[9999], format!("\"{BUCKET}\",\"k03334\",\"v3334-3\",\"true\",\"false\""));
    assert_eq!(lines[10000], format!("\"{BUCKET}\",\"k03334\",\"v3334-2\",\"false\",\"false\""));
    let mut per_key: BTreeMap<&str, usize> = BTreeMap::new();
    for line in &lines {
        *per_key.entry(line.split(',').nth(1).unwrap()).or_default() += 1;
    }
    assert!(per_key.values().all(|n| *n == 3));
}

#[tokio::test]
async fn a_changed_configuration_starts_its_report_over() {
    let Some(app) = node().await else { return };
    allow_delivery(&app).await;
    versions(&app, 5000).await;
    set_rate(&app, 60_000).await;
    assert_eq!(configure(&app, "all", configuration("all", "All", "")).await, StatusCode::OK);
    step_at(&app, Duration::ZERO).await;
    assert_eq!(files_written(&app).await, 1);
    // Current objects only now: a new report, from the start.
    assert_eq!(configure(&app, "all", configuration("all", "Current", "")).await, StatusCode::OK);
    assert_eq!(files_written(&app).await, 0);
    // (The first step pays off the debt of the first file.)
    step_at(&app, HOUR).await;
    step_at(&app, HOUR * 2).await;
    let manifest_key = reports(&app).await.into_iter().find(|k| k.ends_with("manifest.json")).unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&read(&app, &manifest_key).await).unwrap();
    let files = manifest["files"].as_array().unwrap();
    assert_eq!(files.len(), 1, "only the new report's file");
}

#[tokio::test]
async fn reports_and_lifecycle_sweeps_take_turns() {
    let Some(app) = node().await else { return };
    allow_delivery(&app).await;
    versions(&app, 5000).await;
    set_rate(&app, 60_000).await;
    // A sweep (that expires nothing), due first, then a report.
    let rule = "<LifecycleConfiguration><Rule><ID>r</ID><Filter><Prefix>none/</Prefix></Filter>\
                <Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>";
    assert_eq!(put_bucket_lifecycle(&app, BUCKET, Bytes::from(rule)).await.unwrap().status(), StatusCode::OK);
    assert_eq!(configure(&app, "all", configuration("all", "All", "")).await, StatusCode::OK);
    // The sweep reads nothing (no keys under its prefix) and is done; the
    // report gets the rest of the step.
    step_at(&app, Duration::ZERO).await;
    let client = app.pool.get().await.unwrap();
    let swept: Option<String> = client.query_one("SELECT last FROM lifecycle_sweeps", &[]).await.unwrap().get(0);
    assert!(swept.is_some());
    assert_eq!(files_written(&app).await, 1);
    // While the report's debt is paid off, no sweep reads anything either.
    assert_eq!(debt(&app).await, 9000);
}

#[tokio::test]
async fn disabled_configurations_make_no_reports() {
    let Some(app) = node().await else { return };
    allow_delivery(&app).await;
    put(&app, "a", b"a".to_vec()).await;
    let body = configuration("off", "Current", "").replace("<IsEnabled>true</IsEnabled>", "<IsEnabled>false</IsEnabled>");
    assert_eq!(configure(&app, "off", body).await, StatusCode::OK);
    step_at(&app, Duration::ZERO).await;
    assert!(reports(&app).await.is_empty());
}
