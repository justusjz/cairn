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
const REPLICATING: &str = r#"["s3:GetObjectVersionForReplication","s3:ReplicateObject","s3:ReplicateDelete","s3:ReplicateTags"]"#;

async fn node() -> Option<Arc<App>> {
    let app = node_with(packer::Config::default(), None).await?;
    app.pool
        .get()
        .await
        .unwrap()
        .execute("INSERT INTO buckets (name) VALUES ($1)", &[&BACKUP])
        .await
        .unwrap();
    for bucket in [BUCKET, BACKUP] {
        assert_eq!(versioning(&app, bucket, "Enabled").await, StatusCode::OK);
    }
    role(&app, REPLICATING).await;
    Some(app)
}

async fn versioning(app: &App, bucket: &str, status: &str) -> StatusCode {
    let body =
        format!("<VersioningConfiguration><Status>{status}</Status></VersioningConfiguration>");
    put_bucket_versioning(
        app,
        bucket,
        Bytes::from(body),
        crate::mfa::Presented::Absent,
    )
    .await
    .unwrap()
    .status()
}

async fn account(app: &App) -> String {
    users::account(&app.pool.get().await.unwrap())
        .await
        .unwrap()
}

/// The role replication acts as: trusting S3, and allowed `actions` on
/// both buckets' objects.
async fn role(app: &App, actions: &str) {
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"s3.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    let trust = roles::check_trust(&client, &account, trust).await.unwrap();
    let new = roles::New {
        name: ROLE,
        path: "/",
        trust: &trust,
        description: "",
        max_session_duration: 3600,
        boundary: None,
        tags: &[],
    };
    let id = roles::create(&client, &account, &new).await.unwrap();
    let role = roles::Role::load_id(&client, id).await.unwrap().unwrap();
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":{actions},"Resource":["arn:aws:s3:::{BUCKET}/*","arn:aws:s3:::{BACKUP}/*"]}}]}}"#
    );
    roles::put_policy(&client, &role, "p", &policy)
        .await
        .unwrap();
}

/// A user named `name`: an admin, or with the identity policy `statements`.
async fn user(app: &App, name: &str, statements: Option<&str>) -> Principal {
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let (key, _) = users::create_for(&client, &account, name, None, statements.is_none())
        .await
        .unwrap();
    if let Some(statements) = statements {
        let policy = format!(r#"{{"Version":"2012-10-17","Statement":[{statements}]}}"#);
        users::put_policy(&client, &account, name, "p", &policy)
            .await
            .unwrap();
    }
    Principal::load(&client, &key).await.unwrap().unwrap()
}

fn access(principal: &Principal) -> Access {
    let origin = Origin {
        peer: Some("127.0.0.1".parse().unwrap()),
        trusted_proxies: &[],
        signed: None,
        form: false,
    };
    Access::new(
        Some(principal),
        &principal.account,
        &Method::PUT,
        &HeaderMap::new(),
        "",
        &origin,
    )
    .unwrap()
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
    let admin = user(
        app,
        &format!("admin-{}", uuid::Uuid::new_v4().simple()),
        None,
    )
    .await;
    let response = replication::put(app, bucket, Bytes::from(body), &access(&admin))
        .await
        .unwrap();
    let status = response.status();
    (status, text(response).await)
}

async fn configure(app: &App, rules: &str) {
    let body = configuration(app, rules).await;
    let (status, text) = configure_on(app, BUCKET, body).await;
    assert_eq!(status, StatusCode::OK, "{text}");
}

async fn text(response: hyper::Response<Full<Bytes>>) -> String {
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
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
             FROM objects o WHERE o.bucket = $1 AND o.key = $2 ORDER BY o.last_modified DESC, o.id DESC",
            &[&bucket, &key],
        )
        .await
        .unwrap();
    let mut versions = Vec::new();
    for row in rows {
        let parts = client
            .query(
                "SELECT blob_id, blob_offset FROM parts WHERE object_id = $1 ORDER BY part_number",
                &[&row.get::<_, i64>(0)],
            )
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
    versions(app, BUCKET, key)
        .await
        .into_iter()
        .next()
        .and_then(|v| v.status)
}

async fn queued(app: &App) -> i64 {
    app.pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT count(*) FROM replication_queue", &[])
        .await
        .unwrap()
        .get(0)
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
    let result = crate::upload_part(app, body, &attach, Payload::unchecked())
        .await
        .unwrap();
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
    let blobs: i64 = app
        .pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT count(*) FROM blobs", &[])
        .await
        .unwrap()
        .get(0);
    replicate(&app).await;
    let source = versions(&app, BUCKET, "a").await.remove(0);
    let replica = versions(&app, BACKUP, "a").await.remove(0);
    assert_eq!(source.status.as_deref(), Some("COMPLETED"));
    assert_eq!(replica.status.as_deref(), Some("REPLICA"));
    assert_eq!(
        (&replica.version_id, &replica.last_modified, &replica.etag),
        (&source.version_id, &source.last_modified, &source.etag)
    );
    assert_eq!(replica.parts, source.parts);
    let after: i64 = app
        .pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT count(*) FROM blobs", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(after, blobs, "a replica shares its source's bytes");
    assert_eq!(queued(&app).await, 0);
    for (bucket, status) in [(BUCKET, "COMPLETED"), (BACKUP, "REPLICA")] {
        let head = head_object(
            &app,
            bucket,
            "a",
            None,
            None,
            None,
            &Preconditions::default(),
            None,
            None,
            false,
        )
        .await
        .unwrap();
        assert_eq!(head.headers()["x-amz-replication-status"], status);
    }
    // Deleting the source leaves the replica.
    let deleted = delete_object(
        &app,
        BUCKET,
        "a",
        Some(&source.version_id),
        false,
        None,
        crate::mfa::Presented::Absent,
    )
    .await
    .unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    replicate(&app).await;
    assert_eq!(versions(&app, BACKUP, "a").await.len(), 1);
    let response = crate::s3::objects::get::get_object(
        &app,
        BACKUP,
        "a",
        None,
        None,
        None,
        &Preconditions::default(),
        None,
        None,
        false,
    )
    .await
    .unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        &b"hello"[..]
    );
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
    let ids = |versions: Vec<Version>| {
        versions
            .into_iter()
            .map(|v| v.version_id)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        ids(versions(&app, BACKUP, "k").await),
        ids(versions(&app, BUCKET, "k").await)
    );
    let current = crate::s3::objects::get::get_object(
        &app,
        BACKUP,
        "k",
        None,
        None,
        None,
        &Preconditions::default(),
        None,
        None,
        false,
    )
    .await
    .unwrap();
    assert_eq!(
        current.into_body().collect().await.unwrap().to_bytes(),
        &b"three"[..]
    );
}

/// A replica lands among the destination's versions by its time, as S3
/// orders them: below a version written to the destination after its
/// source was, which stays current; and so does a delete marker's.
#[tokio::test]
async fn replicas_land_in_the_order_of_their_times() {
    let Some(app) = node().await else { return };
    configure(&app, &rule("all", "", true)).await;
    put(&app, "k", b"source".to_vec()).await;
    put(&app, "m", b"source".to_vec()).await;
    let deleted = delete_object(
        &app,
        BUCKET,
        "m",
        None,
        false,
        None,
        crate::mfa::Presented::Absent,
    )
    .await
    .unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    // Written to the destination before the source's versions get there.
    let direct = crate::e2e::put_to(&app, BACKUP, "k", b"direct".to_vec()).await;
    crate::e2e::put_to(&app, BACKUP, "m", b"direct".to_vec()).await;
    replicate(&app).await;
    let replicated = versions(&app, BACKUP, "k").await;
    assert_eq!(replicated.len(), 2);
    assert_eq!(replicated[0].version_id, direct);
    assert_eq!(replicated[1].status.as_deref(), Some("REPLICA"));
    let current = crate::s3::objects::get::get_object(
        &app,
        BACKUP,
        "k",
        None,
        None,
        None,
        &Preconditions::default(),
        None,
        None,
        false,
    )
    .await
    .unwrap();
    assert_eq!(
        current.into_body().collect().await.unwrap().to_bytes(),
        &b"direct"[..]
    );
    // The marker is below the direct write too: the key isn't deleted.
    let marked = versions(&app, BACKUP, "m").await;
    assert_eq!(marked.len(), 3);
    assert!(!marked[0].marker && marked[1].marker);
    let head = head_object(
        &app,
        BACKUP,
        "m",
        None,
        None,
        None,
        &Preconditions::default(),
        None,
        None,
        false,
    )
    .await
    .unwrap();
    assert_eq!(head.status(), StatusCode::OK);
    // Deleting the current version makes the next by time current: the
    // replica, though it was written last.
    let removed = delete_object(
        &app,
        BACKUP,
        "k",
        Some(&direct),
        false,
        None,
        crate::mfa::Presented::Absent,
    )
    .await
    .unwrap();
    assert_eq!(removed.status(), StatusCode::NO_CONTENT);
    let current = crate::s3::objects::get::get_object(
        &app,
        BACKUP,
        "k",
        None,
        None,
        None,
        &Preconditions::default(),
        None,
        None,
        false,
    )
    .await
    .unwrap();
    assert_eq!(
        current.into_body().collect().await.unwrap().to_bytes(),
        &b"source"[..]
    );
}

/// Delete markers go where their rule says, keeping their version IDs.
#[tokio::test]
async fn delete_markers_are_replicated_where_their_rule_says() {
    let Some(app) = node().await else { return };
    configure(
        &app,
        &(rule("markers", "m/", true)
            + &rule("plain", "p/", false).replace("<Priority>1", "<Priority>2")),
    )
    .await;
    for key in ["m/a", "p/a"] {
        put(&app, key, b"x".to_vec()).await;
        let deleted = delete_object(
            &app,
            BUCKET,
            key,
            None,
            false,
            None,
            crate::mfa::Presented::Absent,
        )
        .await
        .unwrap();
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    }
    replicate(&app).await;
    let marked = versions(&app, BACKUP, "m/a").await;
    assert_eq!(marked.len(), 2);
    assert!(marked[0].marker);
    assert_eq!(
        marked[0].version_id,
        versions(&app, BUCKET, "m/a").await[0].version_id
    );
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
    let rows = app
        .pool
        .get()
        .await
        .unwrap()
        .query(
            "SELECT key, tags FROM objects WHERE bucket = $1",
            &[&BACKUP],
        )
        .await
        .unwrap();
    let replicated: Vec<(String, String)> = rows.iter().map(|r| (r.get(0), r.get(1))).collect();
    assert_eq!(
        replicated,
        vec![(
            "docs/kept".to_owned(),
            "keep=yes%20please&other=x".to_owned()
        )]
    );
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
    let role = roles::Role::load(&client, &account(&app).await, ROLE)
        .await
        .unwrap()
        .unwrap();
    let deny = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Action":"s3:ReplicateObject","Resource":"arn:aws:s3:::{BACKUP}/secret/*"}}]}}"#
    );
    roles::put_policy(&client, &role, "deny", &deny)
        .await
        .unwrap();
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
    let body = |rules: String| {
        let app = app.clone();
        async move { configuration(&app, &rules).await }
    };
    let refused = |result: (StatusCode, String), code: &str| {
        assert_eq!(result.0, StatusCode::BAD_REQUEST, "{}", result.1);
        assert!(result.1.contains(code), "{}", result.1);
    };
    refused(
        configure_on(
            &app,
            BUCKET,
            body(rule("r", "", false).replace(BACKUP, BUCKET)).await,
        )
        .await,
        "InvalidRequest",
    );
    refused(
        configure_on(
            &app,
            BUCKET,
            body(rule("r", "", false).replace(BACKUP, "nowhere")).await,
        )
        .await,
        "InvalidRequest",
    );
    assert_eq!(versioning(&app, BACKUP, "Suspended").await, StatusCode::OK);
    refused(
        configure_on(&app, BUCKET, body(rule("r", "", false)).await).await,
        "InvalidRequest",
    );
    assert_eq!(versioning(&app, BACKUP, "Enabled").await, StatusCode::OK);
    // A role of another account.
    let other = rule("r", "", false);
    let foreign = body(other)
        .await
        .replace(&account(&app).await, "999999999999");
    refused(configure_on(&app, BUCKET, foreign).await, "InvalidArgument");
    // Not without iam:PassRole.
    let writer = user(
        &app,
        "writer",
        Some(r#"{"Effect":"Allow","Action":"s3:*","Resource":"*"}"#),
    )
    .await;
    let denied = replication::put(
        &app,
        BUCKET,
        Bytes::from(body(rule("r", "", false)).await),
        &access(&writer),
    )
    .await
    .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert!(
        text(replication::get(&app, BUCKET).await.unwrap())
            .await
            .contains("ReplicationConfigurationNotFoundError")
    );

    configure(&app, &rule("r", "logs/", false)).await;
    let got = text(replication::get(&app, BUCKET).await.unwrap()).await;
    assert!(
        got.contains("<ID>r</ID>") && got.contains("<Prefix>logs/</Prefix>") && got.contains(ROLE),
        "{got}"
    );
    // Versioning stays on.
    assert_eq!(
        versioning(&app, BUCKET, "Suspended").await,
        StatusCode::CONFLICT
    );
    let deleted = replication::delete(&app, BUCKET).await.unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        replication::get(&app, BUCKET).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(versioning(&app, BUCKET, "Suspended").await, StatusCode::OK);
    // And a bucket that isn't versioned takes none.
    refused(
        configure_on(&app, BUCKET, body(rule("r", "", false)).await).await,
        "InvalidRequest",
    );
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
    use crate::s3::multipart::{
        complete::complete_multipart_upload, create::create_multipart_upload,
    };
    let Some(app) = node().await else { return };
    configure(&app, &rule("all", "", false)).await;
    let response = create_multipart_upload(
        &app,
        BUCKET,
        "big",
        "x",
        "",
        "",
        crate::s3::sse::Wanted::Plain,
        None,
        None,
        Default::default(),
        None,
        crate::classes::STANDARD,
    )
    .await
    .unwrap();
    let body = text(response).await;
    let upload_id =
        body[body.find("<UploadId>").unwrap() + 10..body.find("</UploadId>").unwrap()].to_owned();
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
        let len = if n == 1 {
            crate::s3::util::MIN_PART as usize
        } else {
            100
        };
        let body = Full::new(Bytes::from(vec![n as u8; len]));
        let UploadResult::Committed { etag, .. } =
            crate::upload_part(&app, body, &attach, Payload::unchecked())
                .await
                .unwrap()
        else {
            panic!("the part wasn't committed");
        };
        listed.push_str(&format!(
            "<Part><PartNumber>{n}</PartNumber><ETag>\"{etag}\"</ETag></Part>"
        ));
    }
    let body = Bytes::from(format!(
        "<CompleteMultipartUpload>{listed}</CompleteMultipartUpload>"
    ));
    let completed = complete_multipart_upload(
        &app,
        BUCKET,
        "big",
        &upload_id,
        body,
        &Preconditions::default(),
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(completed.status(), StatusCode::OK);
    replicate(&app).await;
    let source = versions(&app, BUCKET, "big").await.remove(0);
    let replica = versions(&app, BACKUP, "big").await.remove(0);
    assert!(
        source.etag.as_deref().unwrap().ends_with("-2"),
        "{:?}",
        source.etag
    );
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
        .execute(
            "INSERT INTO storage_classes (name, pool, parity_shards) VALUES ($1, $2, 1)",
            &[&name, &pool],
        )
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
    let Some(cluster) =
        crate::e2e::cluster_of_pools(pools, 2, crate::shards::e2e::pack(), None).await
    else {
        return;
    };
    set_class(&cluster, "COLD", "hdd").await;
    let app = cluster.nodes[0].clone();
    app.pool
        .get()
        .await
        .unwrap()
        .execute("INSERT INTO buckets (name) VALUES ($1)", &[&BACKUP])
        .await
        .unwrap();
    for bucket in [BUCKET, BACKUP] {
        assert_eq!(versioning(&app, bucket, "Enabled").await, StatusCode::OK);
    }
    role(&app, REPLICATING).await;
    let cold = |id: &str, prefix: &str, priority: u8| {
        rule(id, prefix, false)
            .replace("<Priority>1", &format!("<Priority>{priority}"))
            .replace(
                "</Bucket></Destination>",
                "</Bucket><StorageClass>COLD</StorageClass></Destination>",
            )
    };
    configure(
        &app,
        &(cold("cold", "cold/", 1)
            + &rule("same", "same/", false).replace("<Priority>1", "<Priority>2")),
    )
    .await;
    let data = crate::shards::e2e::data(7, 300_000);
    put(&app, "cold/a", data.clone()).await;
    put(&app, "same/a", data.clone()).await;
    replicate(&app).await;
    let class = |bucket: &'static str, key: &'static str| {
        let app = app.clone();
        async move {
            let row = app
                .pool
                .get()
                .await
                .unwrap()
                .query_one(
                    "SELECT storage_class FROM objects WHERE bucket = $1 AND key = $2",
                    &[&bucket, &key],
                )
                .await
                .unwrap();
            row.get::<_, String>(0)
        }
    };
    assert_eq!(class(BACKUP, "cold/a").await, "COLD");
    assert_eq!(class(BACKUP, "same/a").await, "STANDARD");
    let (source, replica) = (
        versions(&app, BUCKET, "cold/a").await.remove(0),
        versions(&app, BACKUP, "cold/a").await.remove(0),
    );
    assert_ne!(
        replica.parts, source.parts,
        "written again, in the class's pool"
    );
    assert_eq!(
        (&replica.version_id, &replica.etag, &replica.last_modified),
        (&source.version_id, &source.etag, &source.last_modified)
    );
    assert_eq!(replica.status.as_deref(), Some("REPLICA"));
    assert_eq!(source.status.as_deref(), Some("COMPLETED"));
    let (source, replica) = (
        versions(&app, BUCKET, "same/a").await.remove(0),
        versions(&app, BACKUP, "same/a").await.remove(0),
    );
    assert_eq!(replica.parts, source.parts);
    let read = crate::s3::objects::get::get_object(
        &app,
        BACKUP,
        "cold/a",
        None,
        None,
        None,
        &Preconditions::default(),
        None,
        None,
        false,
    )
    .await
    .unwrap();
    assert_eq!(
        read.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
        data
    );
}

/// An SSE-C version is replicated without its client's key: the replica
/// keeps its sealed key and checksum, sealed for the source's name, and
/// shares its bytes, and the client's key opens it as it opens the source
/// (its checksum too), and a copy of it.
#[tokio::test]
async fn sse_c_versions_are_replicated_without_their_key() {
    use crate::s3::objects::{
        copy::{CopyKeys, copy_object},
        get::get_object,
    };
    let Some(app) = node().await else { return };
    configure(&app, &rule("all", "", false)).await;
    let customer = crate::e2e::customer_key(&[7; 32]);
    let other = crate::e2e::customer_key(&[8; 32]);
    let data = crate::shards::e2e::data(3, 200_000);
    crate::e2e::put_sealed(&app, "secret", data.clone(), &customer).await;
    replicate(&app).await;
    let (source, replica) = (
        versions(&app, BUCKET, "secret").await.remove(0),
        versions(&app, BACKUP, "secret").await.remove(0),
    );
    assert_eq!(source.status.as_deref(), Some("COMPLETED"));
    assert_eq!(replica.status.as_deref(), Some("REPLICA"));
    assert_eq!(
        (&replica.version_id, &replica.etag, &replica.parts),
        (&source.version_id, &source.etag, &source.parts)
    );
    let row = app
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT sse_c_bucket FROM objects WHERE bucket = $1 AND key = 'secret'",
            &[&BACKUP],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, Option<String>>(0).as_deref(), Some(BUCKET));

    let read = |key: Option<&'static crate::s3::sse_c::CustomerKey>, checksums: bool| {
        let app = app.clone();
        async move {
            let response = get_object(
                &app,
                BACKUP,
                "secret",
                None,
                None,
                None,
                &Preconditions::default(),
                key,
                None,
                checksums,
            )
            .await
            .unwrap();
            let status = response.status();
            let checksum = response
                .headers()
                .get("x-amz-checksum-crc64nvme")
                .map(|v| v.to_str().unwrap().to_owned());
            (
                status,
                checksum,
                response
                    .into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes()
                    .to_vec(),
            )
        }
    };
    let customer: &'static _ = Box::leak(Box::new(customer));
    let other: &'static _ = Box::leak(Box::new(other));
    let (status, checksum, body) = read(Some(customer), true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, data);
    let source_checksum = get_object(
        &app,
        BUCKET,
        "secret",
        None,
        None,
        None,
        &Preconditions::default(),
        Some(customer),
        None,
        true,
    )
    .await
    .unwrap()
    .headers()
    .get("x-amz-checksum-crc64nvme")
    .map(|v| v.to_str().unwrap().to_owned());
    assert!(checksum.is_some());
    assert_eq!(checksum, source_checksum);
    // Refused without its key, or with another, as its source is.
    for key in [None, Some(other)] {
        let source = get_object(
            &app,
            BUCKET,
            "secret",
            None,
            None,
            None,
            &Preconditions::default(),
            key,
            None,
            false,
        )
        .await
        .unwrap();
        assert_ne!(source.status(), StatusCode::OK);
        assert_eq!(read(key, false).await.0, source.status());
    }

    // A copy of the replica, under another key, is sealed for its own name.
    let keys = CopyKeys {
        source: Some(customer),
        dest: crate::s3::sse::Wanted::Customer(other),
        ..CopyKeys::default()
    };
    let copied = copy_object(
        &app,
        BACKUP,
        "copy",
        &format!("/{BACKUP}/secret"),
        None,
        "",
        "",
        None,
        &Preconditions::default(),
        keys,
    )
    .await
    .unwrap();
    assert_eq!(copied.status(), StatusCode::OK);
    let response = get_object(
        &app,
        BACKUP,
        "copy",
        None,
        None,
        None,
        &Preconditions::default(),
        Some(other),
        None,
        false,
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
        data
    );
}

// ─── Other clusters ──────────────────────────────────────────────────────────

/// A client of bucket `bucket` of `target`'s S3 API, as its admin.
fn client_of(target: &crate::backup::e2e::Target, bucket: &str) -> crate::backup::s3::Target {
    crate::backup::s3::Target::new(crate::backup::s3::Location {
        endpoint: format!("http://{}", target.address),
        region: "us-east-1".to_owned(),
        bucket: bucket.to_owned(),
        prefix: String::new(),
        path_style: true,
        access_key_id: target.key_id.clone(),
        secret_access_key: target.secret.clone(),
    })
    .unwrap()
}

/// Another cluster, whose bucket `BUCKET` is versioned, registered with
/// `app` as remote `dc2` of `kind`.
async fn other_cluster(app: &Arc<App>, kind: &str) -> crate::backup::e2e::Target {
    let target = crate::backup::e2e::target().await.unwrap();
    assert_eq!(
        versioning(&target.app, BUCKET, "Enabled").await,
        StatusCode::OK
    );
    let endpoint = format!("http://{}", target.address);
    let out = crate::admin::e2e::cairn(
        app,
        &[
            "remote",
            "add",
            "dc2",
            "--endpoint",
            &endpoint,
            "--path-style",
            "--kind",
            kind,
            "--access-key-id",
            &target.key_id,
            "--secret-access-key",
            &target.secret,
        ],
    )
    .await;
    assert_eq!(out.error, None, "{}", out.stderr);
    target
}

/// A rule replicating everything to the other cluster's `BUCKET`, with
/// delete markers and deletions of versions.
fn remote_rule() -> String {
    format!(
        "<Rule><ID>dc2</ID><Priority>1</Priority><Filter/><Status>Enabled</Status>\
         <Destination><Bucket>arn:cairn:replication::dc2:{BUCKET}</Bucket></Destination>\
         <DeleteMarkerReplication><Status>Enabled</Status></DeleteMarkerReplication>\
         <DeleteReplication><Status>Enabled</Status></DeleteReplication></Rule>"
    )
}

/// The bytes of version `version_id` of `key` in `app`'s `BUCKET`.
async fn read_version(app: &Arc<App>, key: &str, version_id: &str) -> Vec<u8> {
    let response = crate::s3::objects::get::get_object(
        app,
        BUCKET,
        key,
        Some(version_id),
        None,
        None,
        &Preconditions::default(),
        None,
        None,
        false,
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}

/// Versions, their delete markers, and deletions of versions are
/// replicated to another Cairn, which keeps their version IDs, times and
/// ETags, and marks them replicas; a large version as a multipart upload.
#[tokio::test]
async fn versions_are_replicated_to_another_cluster() {
    let Some(app) = node().await else { return };
    let other = other_cluster(&app, "cairn").await;
    configure(&app, &remote_rule()).await;
    put_tagged(&app, "small", b"hello", "team=a%20b").await;
    let large: Vec<u8> = (0..(17u32 << 20)).map(|i| (i % 251) as u8).collect();
    put(&app, "large", large.clone()).await;
    replicate(&app).await;
    assert_eq!(queued(&app).await, 0);
    for (key, body) in [("small", b"hello".to_vec()), ("large", large)] {
        let source = versions(&app, BUCKET, key).await.remove(0);
        let replica = versions(&other.app, BUCKET, key).await.remove(0);
        assert_eq!(source.status.as_deref(), Some("COMPLETED"), "{key}");
        assert_eq!(replica.version_id, source.version_id, "{key}");
        assert_eq!(replica.last_modified, source.last_modified, "{key}");
        assert_eq!(replica.etag, source.etag, "{key}");
        assert_eq!(replica.status.as_deref(), Some("REPLICA"), "{key}");
        assert_eq!(
            read_version(&other.app, key, &replica.version_id).await,
            body
        );
    }
    let tags: Option<String> = other
        .app
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT tags FROM objects WHERE bucket = $1 AND key = 'small'",
            &[&BUCKET],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(tags.as_deref(), Some("team=a%20b"));
    // A delete marker, of the same ID.
    crate::e2e::delete(&app, "small").await;
    replicate(&app).await;
    let marker = versions(&app, BUCKET, "small").await.remove(0);
    assert!(marker.marker);
    let replica = versions(&other.app, BUCKET, "small").await.remove(0);
    assert!(replica.marker);
    assert_eq!(replica.version_id, marker.version_id);
    assert_eq!(replica.last_modified, marker.last_modified);
    // A deletion of a version.
    let large = versions(&app, BUCKET, "large").await.remove(0);
    let deleted = delete_object(
        &app,
        BUCKET,
        "large",
        Some(&large.version_id),
        false,
        None,
        crate::mfa::Presented::Absent,
    )
    .await
    .unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    replicate(&app).await;
    assert_eq!(queued(&app).await, 0);
    assert!(versions(&other.app, BUCKET, "large").await.is_empty());
    // Replicas aren't replicated again: the other cluster queued nothing.
    assert_eq!(queued(&other.app).await, 0);
}

/// To MinIO and RustFS, a version is known by its ID's UUID form, which a
/// deletion of it finds it by again.
#[tokio::test]
async fn minio_is_sent_uuids() {
    let Some(app) = node().await else { return };
    let other = other_cluster(&app, "minio").await;
    configure(&app, &remote_rule()).await;
    put(&app, "k", b"data".to_vec()).await;
    replicate(&app).await;
    let source = versions(&app, BUCKET, "k").await.remove(0);
    let replica = versions(&other.app, BUCKET, "k").await.remove(0);
    assert_eq!(
        replica.version_id,
        crate::s3::versions::uuid_form(&source.version_id)
    );
    assert_eq!(replica.etag, source.etag);
    let deleted = delete_object(
        &app,
        BUCKET,
        "k",
        Some(&source.version_id),
        false,
        None,
        crate::mfa::Presented::Absent,
    )
    .await
    .unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    replicate(&app).await;
    assert!(versions(&other.app, BUCKET, "k").await.is_empty());
}

/// A rule can't name a remote that isn't registered, nor a bucket there
/// that isn't versioned.
#[tokio::test]
async fn remote_destinations_are_checked() {
    let Some(app) = node().await else { return };
    let body = configuration(&app, &remote_rule()).await;
    let (status, text) = configure_on(&app, BUCKET, body.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert!(text.contains("no remote dc2"), "{text}");
    let other = other_cluster(&app, "cairn").await;
    assert_eq!(
        versioning(&other.app, BUCKET, "Suspended").await,
        StatusCode::OK
    );
    let (status, text) = configure_on(&app, BUCKET, body.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert!(text.contains("versioning"), "{text}");
    // Nor can a remote that's named be deleted.
    assert_eq!(
        versioning(&other.app, BUCKET, "Enabled").await,
        StatusCode::OK
    );
    let (status, text) = configure_on(&app, BUCKET, body).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let out = crate::admin::e2e::cairn(&app, &["remote", "delete", "dc2"]).await;
    assert!(out.error.unwrap().contains(BUCKET));
}

/// The requests MinIO's replication makes (see `inbound`) land as
/// replicas, of the versions, times and ETags they name.
#[tokio::test]
async fn minio_requests_land_as_replicas() {
    use crate::backup::s3::Failed;
    use hyper::Method;
    let Some(source) = node().await else { return };
    let other = other_cluster(&source, "minio").await;
    let client = client_of(&other, BUCKET);
    let minio = |extra: &[(&'static str, &'static str)]| {
        let mut headers = vec![
            ("x-amz-replication-status", "REPLICA"),
            ("x-minio-source-replication-request", "true"),
        ];
        headers.extend_from_slice(extra);
        headers
    };
    let v1 = "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    async fn put(
        client: &crate::backup::s3::Target,
        v1: &str,
    ) -> anyhow::Result<crate::backup::s3::Answer> {
        client
            .call(
                Method::PUT,
                Some("k"),
                &[("versionId", v1)],
                &[
                    ("x-amz-replication-status", "REPLICA"),
                    ("x-minio-source-replication-request", "true"),
                    ("x-minio-source-mtime", "2024-05-06T07:08:09.123456789Z"),
                    ("x-minio-source-etag", "0123456789abcdef0123456789abcdef-3"),
                    ("x-amz-tagging", "a=b"),
                    ("x-amz-meta-colour", "blue"),
                ],
                Bytes::from_static(b"replica"),
            )
            .await
    }
    let answer = put(&client, v1).await.unwrap();
    assert_eq!(
        answer
            .headers
            .get("x-amz-version-id")
            .unwrap()
            .to_str()
            .unwrap(),
        v1
    );
    // Again: as written.
    put(&client, v1).await.unwrap();
    let replica = versions(&other.app, BUCKET, "k").await;
    assert_eq!(replica.len(), 1);
    let replica = &replica[0];
    assert_eq!(replica.version_id, v1);
    assert_eq!(replica.status.as_deref(), Some("REPLICA"));
    assert_eq!(
        replica.etag.as_deref(),
        Some("0123456789abcdef0123456789abcdef-3")
    );
    assert!(
        replica
            .last_modified
            .starts_with("2024-05-06 07:08:09.123456"),
        "{}",
        replica.last_modified
    );
    // Written after it, but older: it lands below.
    let v2 = "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c";
    client
        .call(
            Method::PUT,
            Some("k"),
            &[],
            &[
                ("x-amz-replication-status", "REPLICA"),
                ("x-rustfs-source-replication-request", "true"),
                ("x-rustfs-source-version-id", v2),
                ("x-rustfs-source-mtime", "2020-01-01T00:00:00Z"),
            ],
            Bytes::from_static(b"older"),
        )
        .await
        .unwrap();
    let all = versions(&other.app, BUCKET, "k").await;
    assert_eq!(all[1].version_id, v2);
    // A delete marker of the ID given.
    let v3 = "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5d";
    for _ in 0..2 {
        client
            .call(
                Method::DELETE,
                Some("k"),
                &[("versionId", v3)],
                &minio(&[
                    ("x-minio-source-deletemarker", "true"),
                    ("x-minio-source-mtime", "2025-01-01T00:00:00Z"),
                ]),
                Bytes::new(),
            )
            .await
            .unwrap();
    }
    let all = versions(&other.app, BUCKET, "k").await;
    assert_eq!(all.len(), 3);
    assert!(all[0].marker && all[0].version_id == v3);
    // Its tags changed, as MinIO replicates them: a copy onto itself.
    client
        .call(
            Method::PUT,
            Some("k"),
            &[("versionId", v1)],
            &minio(&[
                (
                    "x-amz-copy-source",
                    "/bucket/k?versionId=0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b",
                ),
                ("x-amz-metadata-directive", "REPLACE"),
                ("x-amz-tagging-directive", "REPLACE"),
                ("x-amz-tagging", "c=d"),
            ]),
            Bytes::new(),
        )
        .await
        .unwrap();
    let tags: Option<String> = other
        .app
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT tags FROM objects WHERE bucket = $1 AND version_id = $2",
            &[&BUCKET, &v1],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(tags.as_deref(), Some("c=d"));
    assert_eq!(versions(&other.app, BUCKET, "k").await.len(), 3);
    // A multipart upload, of the version ID it started with.
    let v4 = "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5e";
    let started = client
        .call(
            Method::POST,
            Some("mp"),
            &[("uploads", ""), ("versionId", v4)],
            &minio(&[]),
            Bytes::new(),
        )
        .await
        .unwrap();
    let body = String::from_utf8(started.body.to_vec()).unwrap();
    let upload_id =
        body[body.find("<UploadId>").unwrap() + 10..body.find("</UploadId>").unwrap()].to_owned();
    let part = client
        .call(
            Method::PUT,
            Some("mp"),
            &[("partNumber", "1"), ("uploadId", &upload_id)],
            &minio(&[]),
            Bytes::from_static(b"part"),
        )
        .await
        .unwrap();
    let etag = part
        .headers
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    client
        .call(
            Method::POST,
            Some("mp"),
            &[("uploadId", &upload_id)],
            &minio(&[
                ("x-minio-source-mtime", "2024-02-03T04:05:06Z"),
                ("x-minio-source-etag", "fedcba9876543210fedcba9876543210-1"),
            ]),
            Bytes::from(format!(
                "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part>\
                 </CompleteMultipartUpload>"
            )),
        )
        .await
        .unwrap();
    let mp = versions(&other.app, BUCKET, "mp").await.remove(0);
    assert_eq!(mp.version_id, v4);
    assert_eq!(mp.status.as_deref(), Some("REPLICA"));
    assert_eq!(
        mp.etag.as_deref(),
        Some("fedcba9876543210fedcba9876543210-1")
    );
    assert!(mp.last_modified.starts_with("2024-02-03 04:05:06"));
    // A deletion of a version, by the UUID a version of Cairn's is known
    // by.
    put_tagged(&other.app, "own", b"x", "").await;
    let own = versions(&other.app, BUCKET, "own").await.remove(0);
    let uuid = crate::s3::versions::uuid_form(&own.version_id);
    client
        .call(
            Method::DELETE,
            Some("own"),
            &[("versionId", &uuid)],
            &minio(&[]),
            Bytes::new(),
        )
        .await
        .unwrap();
    assert!(versions(&other.app, BUCKET, "own").await.is_empty());
    // MinIO's check of its permissions.
    let checked = client
        .call(
            Method::PUT,
            Some("check"),
            &[],
            &[("x-minio-source-replication-check", "true")],
            Bytes::from_static(b"x"),
        )
        .await
        .unwrap_err();
    let failed = checked.downcast_ref::<Failed>().unwrap();
    assert_eq!(failed.code, "ReplicationPermissionCheck");
    assert!(versions(&other.app, BUCKET, "check").await.is_empty());
    // A replica's ID needs a versioned bucket.
    assert_eq!(
        versioning(&other.app, BUCKET, "Suspended").await,
        StatusCode::OK
    );
    let refused = client
        .call(
            Method::PUT,
            Some("k2"),
            &[("versionId", v1)],
            &minio(&[]),
            Bytes::from_static(b"x"),
        )
        .await
        .unwrap_err();
    assert_eq!(
        refused.downcast_ref::<Failed>().unwrap().status,
        StatusCode::BAD_REQUEST
    );
}

/// A replication request is authorized as replication's: a user allowed
/// `s3:PutObject` alone may not write a replica, and one allowed
/// `s3:ReplicateObject` may.
#[tokio::test]
async fn replicas_need_replication_permissions() {
    use hyper::Method;
    let Some(source) = node().await else { return };
    let other = other_cluster(&source, "cairn").await;
    let mut clients = Vec::new();
    for (name, action) in [
        ("writer", "s3:PutObject"),
        ("replicator", "s3:ReplicateObject"),
    ] {
        let statements = format!(
            r#"{{"Effect":"Allow","Action":"{action}","Resource":"arn:aws:s3:::{BUCKET}/*"}}"#
        );
        let client = other.app.pool.get().await.unwrap();
        let account = users::account(&client).await.unwrap();
        let (key, secret) = users::create_for(&client, &account, name, None, false)
            .await
            .unwrap();
        let policy = format!(r#"{{"Version":"2012-10-17","Statement":[{statements}]}}"#);
        users::put_policy(&client, &account, name, "p", &policy)
            .await
            .unwrap();
        clients.push(
            crate::backup::s3::Target::new(crate::backup::s3::Location {
                endpoint: format!("http://{}", other.address),
                region: "us-east-1".to_owned(),
                bucket: BUCKET.to_owned(),
                prefix: String::new(),
                path_style: true,
                access_key_id: key,
                secret_access_key: secret,
            })
            .unwrap(),
        );
    }
    async fn replica(
        client: &crate::backup::s3::Target,
    ) -> anyhow::Result<crate::backup::s3::Answer> {
        client
            .call(
                Method::PUT,
                Some("k"),
                &[("versionId", "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b")],
                &[("x-amz-replication-status", "REPLICA")],
                Bytes::from_static(b"x"),
            )
            .await
    }
    let denied = replica(&clients[0]).await.unwrap_err();
    assert_eq!(
        denied
            .downcast_ref::<crate::backup::s3::Failed>()
            .unwrap()
            .status,
        StatusCode::FORBIDDEN
    );
    replica(&clients[1]).await.unwrap();
}
