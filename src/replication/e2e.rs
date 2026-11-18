//! Replication against a real Postgres (see `e2e`): configured through
//! PutBucketReplication, and run by the worker's rounds, called directly.

use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{HeaderMap, Method, StatusCode, body::Bytes};

use crate::{
    App, AttachTarget, UploadResult,
    e2e::{BUCKET, node_with, put},
    packer,
    payload::Payload,
    roles,
    s3::{
        access::{Access, Origin},
        buckets::{replication, versioning::put_bucket_versioning},
        conditional::Preconditions,
        objects::{delete::delete_object, get::head_object},
    },
    users::{self, Principal},
};

/// The destination bucket.
const BACKUP: &str = "backup";
const ROLE: &str = "replication";
/// What the role may do, by default.
const REPLICATING: &str =
    r#"["s3:GetObjectVersionForReplication","s3:ReplicateObject","s3:ReplicateDelete","s3:ReplicateTags"]"#;

async fn node() -> Option<Arc<App>> {
    let app = node_with(packer::Config::default(), None).await?;
    app.pool.get().await.unwrap().execute("INSERT INTO buckets (name) VALUES ($1)", &[&BACKUP]).await.unwrap();
    for bucket in [BUCKET, BACKUP] {
        assert_eq!(versioning(&app, bucket, "Enabled").await, StatusCode::OK);
    }
    role(&app, REPLICATING).await;
    Some(app)
}

async fn versioning(app: &App, bucket: &str, status: &str) -> StatusCode {
    let body = format!("<VersioningConfiguration><Status>{status}</Status></VersioningConfiguration>");
    put_bucket_versioning(app, bucket, Bytes::from(body), crate::mfa::Presented::Absent).await.unwrap().status()
}

async fn account(app: &App) -> String {
    users::account(&app.pool.get().await.unwrap()).await.unwrap()
}

/// The role replication acts as: trusting S3, and allowed `actions` on
/// both buckets' objects.
async fn role(app: &App, actions: &str) {
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"s3.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    let trust = roles::check_trust(&client, &account, trust).await.unwrap();
    let new = roles::New { name: ROLE, path: "/", trust: &trust, description: "", max_session_duration: 3600, boundary: None, tags: &[] };
    let id = roles::create(&client, &account, &new).await.unwrap();
    let role = roles::Role::load_id(&client, id).await.unwrap().unwrap();
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":{actions},"Resource":["arn:aws:s3:::{BUCKET}/*","arn:aws:s3:::{BACKUP}/*"]}}]}}"#
    );
    roles::put_policy(&client, &role, "p", &policy).await.unwrap();
}

/// A user named `name`: an admin, or with the identity policy `statements`.
async fn user(app: &App, name: &str, statements: Option<&str>) -> Principal {
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let (key, _) = users::create_for(&client, &account, name, None, statements.is_none()).await.unwrap();
    if let Some(statements) = statements {
        let policy = format!(r#"{{"Version":"2012-10-17","Statement":[{statements}]}}"#);
        users::put_policy(&client, &account, name, "p", &policy).await.unwrap();
    }
    Principal::load(&client, &key).await.unwrap().unwrap()
}

fn access(principal: &Principal) -> Access {
    let origin = Origin { peer: Some("127.0.0.1".parse().unwrap()), trusted_proxies: &[], signed: None, form: false };
    Access::new(Some(principal), &principal.account, &Method::PUT, &HeaderMap::new(), "", &origin).unwrap()
}

/// A configuration of the test role, with `rules`.
async fn configuration(app: &App, rules: &str) -> String {
    let account = account(app).await;
    format!(
        "<ReplicationConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Role>arn:aws:iam::{account}:role/{ROLE}</Role>{rules}</ReplicationConfiguration>"
    )
}

/// A rule replicating what's under `prefix` to the backup bucket, and
/// delete markers if `markers`.
fn rule(id: &str, prefix: &str, markers: bool) -> String {
    let markers = if markers { "Enabled" } else { "Disabled" };
    format!(
        "<Rule><ID>{id}</ID><Priority>1</Priority><Filter><Prefix>{prefix}</Prefix></Filter><Status>Enabled</Status>\
         <Destination><Bucket>arn:aws:s3:::{BACKUP}</Bucket></Destination>\
         <DeleteMarkerReplication><Status>{markers}</Status></DeleteMarkerReplication></Rule>"
    )
}

/// PutBucketReplication of `body` on `bucket`, by an admin.
async fn configure_on(app: &App, bucket: &str, body: String) -> (StatusCode, String) {
    let admin = user(app, &format!("admin-{}", uuid::Uuid::new_v4().simple()), None).await;
    let response = replication::put(app, bucket, Bytes::from(body), &access(&admin)).await.unwrap();
    let status = response.status();
    (status, text(response).await)
}

async fn configure(app: &App, rules: &str) {
    let body = configuration(app, rules).await;
    let (status, text) = configure_on(app, BUCKET, body).await;
    assert_eq!(status, StatusCode::OK, "{text}");
}

async fn text(response: hyper::Response<Full<Bytes>>) -> String {
    String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
}

/// Runs the worker until nothing's due.
async fn replicate(app: &Arc<App>) {
    while super::round(app).await.unwrap() > 0 {}
}

/// A version of `key` in `bucket`, as replication sees it: its version
/// ID, last-modified time, ETag, status, and its parts' blobs and offsets.
#[derive(Debug, PartialEq)]
struct Version {
    version_id: String,
    last_modified: String,
    etag: Option<String>,
    status: Option<String>,
    marker: bool,
    parts: Vec<(uuid::Uuid, i64)>,
}

async fn versions(app: &App, bucket: &str, key: &str) -> Vec<Version> {
    let client = app.pool.get().await.unwrap();
    let rows = client
        .query(
            "SELECT o.id, o.version_id, o.last_modified::text, o.etag, o.replication_status, o.is_delete_marker
             FROM objects o WHERE o.bucket = $1 AND o.key = $2 ORDER BY o.id DESC",
            &[&bucket, &key],
        )
        .await
        .unwrap();
    let mut versions = Vec::new();
    for row in rows {
        let parts = client
            .query("SELECT blob_id, blob_offset FROM parts WHERE object_id = $1 ORDER BY part_number", &[&row.get::<_, i64>(0)])
            .await
            .unwrap();
        versions.push(Version {
            version_id: row.get(1),
            last_modified: row.get(2),
            etag: row.get(3),
            status: row.get(4),
            marker: row.get(5),
            parts: parts.iter().map(|p| (p.get(0), p.get(1))).collect(),
        });
    }
    versions
}

async fn status(app: &App, key: &str) -> Option<String> {
    versions(app, BUCKET, key).await.into_iter().next().and_then(|v| v.status)
}

async fn queued(app: &App) -> i64 {
    app.pool.get().await.unwrap().query_one("SELECT count(*) FROM replication_queue", &[]).await.unwrap().get(0)
}

/// PUTs `data` at `key` with `tags` (stored form).
async fn put_tagged(app: &Arc<App>, key: &str, data: &[u8], tags: &str) {
    let attach = AttachTarget::Object {
        storage_class: crate::classes::STANDARD.to_owned(),
        bucket: BUCKET.to_owned(),
        key: key.to_owned(),
        content_type: "text/plain".to_owned(),
        metadata: String::new(),
        conditions: Preconditions::default(),
        sealing: None,
        checksum: crate::e2e::OBJECT_CHECKSUM,
        tags: tags.to_owned(),
        lock: Default::default(),
    };
    let body = Full::new(Bytes::copy_from_slice(data));
    let result = crate::upload_part(app, body, &attach, Payload::unchecked()).await.unwrap();
    assert!(matches!(result, UploadResult::Committed { .. }));
}

/// A replica is the same version, of the same bytes: no data is written
/// for it, and it has its source's version ID, last-modified time and
/// ETag. The source is PENDING until it's replicated, COMPLETED after,
/// and the replica is REPLICA, as GET and HEAD tell.
#[tokio::test]
async fn a_version_is_replicated_onto_its_bytes() {
    let Some(app) = node().await else { return };
    configure(&app, &rule("all", "", false)).await;
    put(&app, "a", b"hello".to_vec()).await;
    assert_eq!(status(&app, "a").await.as_deref(), Some("PENDING"));
    let blobs: i64 = app.pool.get().await.unwrap().query_one("SELECT count(*) FROM blobs", &[]).await.unwrap().get(0);
    replicate(&app).await;
    let source = versions(&app, BUCKET, "a").await.remove(0);
    let replica = versions(&app, BACKUP, "a").await.remove(0);
    assert_eq!(source.status.as_deref(), Some("COMPLETED"));
    assert_eq!(replica.status.as_deref(), Some("REPLICA"));
    assert_eq!((&replica.version_id, &replica.last_modified, &replica.etag), (&source.version_id, &source.last_modified, &source.etag));
    assert_eq!(replica.parts, source.parts);
    let after: i64 = app.pool.get().await.unwrap().query_one("SELECT count(*) FROM blobs", &[]).await.unwrap().get(0);
    assert_eq!(after, blobs, "a replica shares its source's bytes");
    assert_eq!(queued(&app).await, 0);
    for (bucket, status) in [(BUCKET, "COMPLETED"), (BACKUP, "REPLICA")] {
        let head = head_object(&app, bucket, "a", None, None, None, &Preconditions::default(), None, None, false).await.unwrap();
        assert_eq!(head.headers()["x-amz-replication-status"], status);
    }
    // Deleting the source leaves the replica.
    let deleted = delete_object(&app, BUCKET, "a", Some(&source.version_id), false, None, crate::mfa::Presented::Absent).await.unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    replicate(&app).await;
    assert_eq!(versions(&app, BACKUP, "a").await.len(), 1);
    let response = crate::s3::objects::get::get_object(&app, BACKUP, "a", None, None, None, &Preconditions::default(), None, None, false)
        .await
        .unwrap();
    assert_eq!(response.into_body().collect().await.unwrap().to_bytes(), &b"hello"[..]);
}

/// A key's versions are replicated in the order they were written, so the
/// replica's current version is the source's.
#[tokio::test]
async fn versions_are_replicated_in_order() {
    let Some(app) = node().await else { return };
    configure(&app, &rule("all", "", false)).await;
    for data in [&b"one"[..], b"two", b"three"] {
        put(&app, "k", data.to_vec()).await;
    }
    replicate(&app).await;
    let ids = |versions: Vec<Version>| versions.into_iter().map(|v| v.version_id).collect::<Vec<_>>();
    assert_eq!(ids(versions(&app, BACKUP, "k").await), ids(versions(&app, BUCKET, "k").await));
    let current = crate::s3::objects::get::get_object(&app, BACKUP, "k", None, None, None, &Preconditions::default(), None, None, false)
        .await
        .unwrap();
    assert_eq!(current.into_body().collect().await.unwrap().to_bytes(), &b"three"[..]);
}

/// Delete markers go where their rule says, keeping their version IDs.
#[tokio::test]
async fn delete_markers_are_replicated_where_their_rule_says() {
    let Some(app) = node().await else { return };
    configure(&app, &(rule("markers", "m/", true) + &rule("plain", "p/", false).replace("<Priority>1", "<Priority>2"))).await;
    for key in ["m/a", "p/a"] {
        put(&app, key, b"x".to_vec()).await;
        let deleted = delete_object(&app, BUCKET, key, None, false, None, crate::mfa::Presented::Absent).await.unwrap();
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    }
    replicate(&app).await;
    let marked = versions(&app, BACKUP, "m/a").await;
    assert_eq!(marked.len(), 2);
    assert!(marked[0].marker);
    assert_eq!(marked[0].version_id, versions(&app, BUCKET, "m/a").await[0].version_id);
    assert_eq!(marked[0].status.as_deref(), Some("REPLICA"));
    let unmarked = versions(&app, BACKUP, "p/a").await;
    assert_eq!(unmarked.len(), 1);
    assert!(!unmarked[0].marker);
}

/// Only what a rule's filter picks is replicated: by prefix, and by tags.
#[tokio::test]
async fn filters_pick_what_is_replicated() {
    let Some(app) = node().await else { return };
    let tagged = format!(
        "<Rule><ID>tagged</ID><Priority>1</Priority><Filter><And><Prefix>docs/</Prefix>\
         <Tag><Key>keep</Key><Value>yes please</Value></Tag></And></Filter><Status>Enabled</Status>\
         <Destination><Bucket>arn:aws:s3:::{BACKUP}</Bucket></Destination>\
         <DeleteMarkerReplication><Status>Disabled</Status></DeleteMarkerReplication></Rule>"
    );
    configure(&app, &tagged).await;
    put_tagged(&app, "docs/kept", b"1", "keep=yes%20please&other=x").await;
    put_tagged(&app, "docs/untagged", b"2", "").await;
    put_tagged(&app, "docs/other", b"3", "keep=no").await;
    put_tagged(&app, "elsewhere", b"4", "keep=yes%20please").await;
    assert_eq!(status(&app, "docs/kept").await.as_deref(), Some("PENDING"));
    for key in ["docs/untagged", "docs/other", "elsewhere"] {
        assert_eq!(status(&app, key).await, None, "{key}");
    }
    replicate(&app).await;
    let rows = app.pool.get().await.unwrap().query("SELECT key, tags FROM objects WHERE bucket = $1", &[&BACKUP]).await.unwrap();
    let replicated: Vec<(String, String)> = rows.iter().map(|r| (r.get(0), r.get(1))).collect();
    assert_eq!(replicated, vec![("docs/kept".to_owned(), "keep=yes%20please&other=x".to_owned())]);
}

/// A replica isn't replicated again, even where its bucket replicates back.
#[tokio::test]
async fn replicas_are_not_replicated_again() {
    let Some(app) = node().await else { return };
    configure(&app, &rule("all", "", true)).await;
    let back = configuration(&app, &rule("back", "", true).replace(BACKUP, BUCKET)).await;
    let (status_code, body) = configure_on(&app, BACKUP, back).await;
    assert_eq!(status_code, StatusCode::OK, "{body}");
    put(&app, "a", b"x".to_vec()).await;
    replicate(&app).await;
    assert_eq!(versions(&app, BUCKET, "a").await.len(), 1);
    assert_eq!(versions(&app, BACKUP, "a").await.len(), 1);
    assert_eq!(queued(&app).await, 0);
}

/// A version the role may not replicate is FAILED, and isn't tried again.
#[tokio::test]
async fn what_the_role_may_not_replicate_fails() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    let role = roles::Role::load(&client, &account(&app).await, ROLE).await.unwrap().unwrap();
    let deny = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Action":"s3:ReplicateObject","Resource":"arn:aws:s3:::{BACKUP}/secret/*"}}]}}"#
    );
    roles::put_policy(&client, &role, "deny", &deny).await.unwrap();
    drop(client);
    configure(&app, &rule("all", "", false)).await;
    put(&app, "secret/a", b"x".to_vec()).await;
    put(&app, "open/a", b"x".to_vec()).await;
    replicate(&app).await;
    assert_eq!(status(&app, "secret/a").await.as_deref(), Some("FAILED"));
    assert_eq!(status(&app, "open/a").await.as_deref(), Some("COMPLETED"));
    assert!(versions(&app, BACKUP, "secret/a").await.is_empty());
    assert_eq!(queued(&app).await, 0);
}

/// As in S3: both buckets must be versioned, and the source then stays so;
/// the destination must exist, and be another bucket; the caller must be
/// allowed to pass the role. GetBucketReplication answers what was set,
/// and DeleteBucketReplication removes it.
#[tokio::test]
async fn configurations_are_checked_as_s3_checks_them() {
    let Some(app) = node().await else { return };
    let body = |rules: String| { let app = app.clone(); async move { configuration(&app, &rules).await } };
    let refused = |result: (StatusCode, String), code: &str| {
        assert_eq!(result.0, StatusCode::BAD_REQUEST, "{}", result.1);
        assert!(result.1.contains(code), "{}", result.1);
    };
    refused(configure_on(&app, BUCKET, body(rule("r", "", false).replace(BACKUP, BUCKET)).await).await, "InvalidRequest");
    refused(configure_on(&app, BUCKET, body(rule("r", "", false).replace(BACKUP, "nowhere")).await).await, "InvalidRequest");
    assert_eq!(versioning(&app, BACKUP, "Suspended").await, StatusCode::OK);
    refused(configure_on(&app, BUCKET, body(rule("r", "", false)).await).await, "InvalidRequest");
    assert_eq!(versioning(&app, BACKUP, "Enabled").await, StatusCode::OK);
    // A role of another account.
    let other = rule("r", "", false);
    let foreign = body(other).await.replace(&account(&app).await, "999999999999");
    refused(configure_on(&app, BUCKET, foreign).await, "InvalidArgument");
    // Not without iam:PassRole.
    let writer = user(&app, "writer", Some(r#"{"Effect":"Allow","Action":"s3:*","Resource":"*"}"#)).await;
    let denied = replication::put(&app, BUCKET, Bytes::from(body(rule("r", "", false)).await), &access(&writer)).await.unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert!(text(replication::get(&app, BUCKET).await.unwrap()).await.contains("ReplicationConfigurationNotFoundError"));

    configure(&app, &rule("r", "logs/", false)).await;
    let got = text(replication::get(&app, BUCKET).await.unwrap()).await;
    assert!(got.contains("<ID>r</ID>") && got.contains("<Prefix>logs/</Prefix>") && got.contains(ROLE), "{got}");
    // Versioning stays on.
    assert_eq!(versioning(&app, BUCKET, "Suspended").await, StatusCode::CONFLICT);
    let deleted = replication::delete(&app, BUCKET).await.unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    assert_eq!(replication::get(&app, BUCKET).await.unwrap().status(), StatusCode::NOT_FOUND);
    assert_eq!(versioning(&app, BUCKET, "Suspended").await, StatusCode::OK);
    // And a bucket that isn't versioned takes none.
    refused(configure_on(&app, BUCKET, body(rule("r", "", false)).await).await, "InvalidRequest");
}

/// Versions queued under a rule that's gone since fail.
#[tokio::test]
async fn versions_of_a_removed_configuration_fail() {
    let Some(app) = node().await else { return };
    configure(&app, &rule("all", "", false)).await;
    put(&app, "a", b"x".to_vec()).await;
    replication::delete(&app, BUCKET).await.unwrap();
    replicate(&app).await;
    assert_eq!(status(&app, "a").await.as_deref(), Some("FAILED"));
    put(&app, "b", b"x".to_vec()).await;
    assert_eq!(status(&app, "b").await, None);
}

/// A multipart version's replica keeps its ETag (its parts', not its
/// data's MD5), without its data being read.
#[tokio::test]
async fn a_multipart_version_keeps_its_etag() {
    use crate::s3::multipart::{complete::complete_multipart_upload, create::create_multipart_upload};
    let Some(app) = node().await else { return };
    configure(&app, &rule("all", "", false)).await;
    let response = create_multipart_upload(
        &app, BUCKET, "big", "x", "", "", crate::s3::sse::Wanted::Plain, None, None, Default::default(), None,
        crate::classes::STANDARD,
    )
    .await
    .unwrap();
    let body = text(response).await;
    let upload_id = body[body.find("<UploadId>").unwrap() + 10..body.find("</UploadId>").unwrap()].to_owned();
    let mut listed = String::new();
    for n in 1..=2 {
        let attach = AttachTarget::MultipartPart {
            storage_class: crate::classes::STANDARD.to_owned(),
            upload_id: upload_id.parse().unwrap(),
            part_number: n,
            key: None,
            sse_s3: false,
            checksum: crate::e2e::PART_CHECKSUM,
        };
        let len = if n == 1 { crate::s3::util::MIN_PART as usize } else { 100 };
        let body = Full::new(Bytes::from(vec![n as u8; len]));
        let UploadResult::Committed { etag, .. } = crate::upload_part(&app, body, &attach, Payload::unchecked()).await.unwrap()
        else {
            panic!("the part wasn't committed");
        };
        listed.push_str(&format!("<Part><PartNumber>{n}</PartNumber><ETag>\"{etag}\"</ETag></Part>"));
    }
    let body = Bytes::from(format!("<CompleteMultipartUpload>{listed}</CompleteMultipartUpload>"));
    let completed =
        complete_multipart_upload(&app, BUCKET, "big", &upload_id, body, &Preconditions::default(), None, None, None, None)
            .await
            .unwrap();
    assert_eq!(completed.status(), StatusCode::OK);
    replicate(&app).await;
    let source = versions(&app, BUCKET, "big").await.remove(0);
    let replica = versions(&app, BACKUP, "big").await.remove(0);
    assert!(source.etag.as_deref().unwrap().ends_with("-2"), "{:?}", source.etag);
    assert_eq!(replica.etag, source.etag);
    assert_eq!(replica.parts, source.parts);
}

/// Defines class `name` in pool `pool`, and has every node of `cluster`
/// go by it.
async fn set_class(cluster: &crate::e2e::Cluster, name: &str, pool: &str) {
    let app = &cluster.nodes[0];
    app.pool
        .get()
        .await
        .unwrap()
        .execute("INSERT INTO storage_classes (name, pool, parity_shards) VALUES ($1, $2, 1)", &[&name, &pool])
        .await
        .unwrap();
    for node in &cluster.nodes {
        crate::refresh_settings(node).await.unwrap();
    }
}

/// A replica is stored in the class its rule names, written again there,
/// and otherwise in its source's, sharing its bytes.
#[tokio::test]
async fn replicas_are_stored_in_their_rules_class() {
    let pools: &[&[&str]] = &[&["default", "hdd"], &["default", "hdd"], &["default"]];
    let Some(cluster) = crate::e2e::cluster_of_pools(pools, 2, crate::shards::e2e::pack(), None).await else { return };
    set_class(&cluster, "COLD", "hdd").await;
    let app = cluster.nodes[0].clone();
    app.pool.get().await.unwrap().execute("INSERT INTO buckets (name) VALUES ($1)", &[&BACKUP]).await.unwrap();
    for bucket in [BUCKET, BACKUP] {
        assert_eq!(versioning(&app, bucket, "Enabled").await, StatusCode::OK);
    }
    role(&app, REPLICATING).await;
    let cold = |id: &str, prefix: &str, priority: u8| {
        rule(id, prefix, false)
            .replace("<Priority>1", &format!("<Priority>{priority}"))
            .replace("</Bucket></Destination>", "</Bucket><StorageClass>COLD</StorageClass></Destination>")
    };
    configure(&app, &(cold("cold", "cold/", 1) + &rule("same", "same/", false).replace("<Priority>1", "<Priority>2"))).await;
    let data = crate::shards::e2e::data(7, 300_000);
    put(&app, "cold/a", data.clone()).await;
    put(&app, "same/a", data.clone()).await;
    replicate(&app).await;
    let class = |bucket: &'static str, key: &'static str| {
        let app = app.clone();
        async move {
            let row = app.pool.get().await.unwrap()
                .query_one("SELECT storage_class FROM objects WHERE bucket = $1 AND key = $2", &[&bucket, &key])
                .await
                .unwrap();
            row.get::<_, String>(0)
        }
    };
    assert_eq!(class(BACKUP, "cold/a").await, "COLD");
    assert_eq!(class(BACKUP, "same/a").await, "STANDARD");
    let (source, replica) = (versions(&app, BUCKET, "cold/a").await.remove(0), versions(&app, BACKUP, "cold/a").await.remove(0));
    assert_ne!(replica.parts, source.parts, "written again, in the class's pool");
    assert_eq!((&replica.version_id, &replica.etag, &replica.last_modified), (&source.version_id, &source.etag, &source.last_modified));
    assert_eq!(replica.status.as_deref(), Some("REPLICA"));
    assert_eq!(source.status.as_deref(), Some("COMPLETED"));
    let (source, replica) = (versions(&app, BUCKET, "same/a").await.remove(0), versions(&app, BACKUP, "same/a").await.remove(0));
    assert_eq!(replica.parts, source.parts);
    let read = crate::s3::objects::get::get_object(&app, BACKUP, "cold/a", None, None, None, &Preconditions::default(), None, None, false)
        .await
        .unwrap();
    assert_eq!(read.into_body().collect().await.unwrap().to_bytes().to_vec(), data);
}
