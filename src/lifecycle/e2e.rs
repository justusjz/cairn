//! Lifecycle sweeps against a real Postgres (see `e2e`), with the clock moved
//! ahead instead of waiting for days.

use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use http_body_util::BodyExt;
use hyper::{StatusCode, body::Bytes};

use super::{Report, expire, page, pass};
use crate::{
    App,
    e2e::{BUCKET, assert_files, get, node_with, put, query_i64},
    packer,
    s3::{
        buckets::{
            lifecycle::{delete_bucket_lifecycle, get_bucket_lifecycle, put_bucket_lifecycle},
            versioning::put_bucket_versioning,
        },
        multipart::create::create_multipart_upload,
        sse::Wanted,
    },
};

const DAY: Duration = Duration::from_secs(24 * 3600);

/// The prefixes of rules for every key.
fn everything() -> Vec<String> {
    vec![String::new()]
}

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

/// Sets the bucket's configuration to `rules`.
async fn configure(app: &App, rules: &str) {
    let body = format!(
        "<LifecycleConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{rules}</LifecycleConfiguration>"
    );
    let response = put_bucket_lifecycle(app, BUCKET, Bytes::from(body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

async fn enable_versioning(app: &App) {
    let body = "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";
    let response = put_bucket_versioning(app, BUCKET, Bytes::from(body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// Takes the step due `after` from now, if there's one; its report.
async fn step_at(app: &Arc<App>, after: Duration) -> Option<Report> {
    let results = pass(app, SystemTime::now() + after).await;
    assert!(results.len() <= 1, "one bucket's step");
    results.into_iter().next().map(|result| result.map_err(|(_, e)| e).unwrap())
}

/// Takes the step due `days` from now, which finishes its sweep (the
/// buckets here are small); its report.
async fn run_in(app: &Arc<App>, days: u32) -> Option<Report> {
    let report = step_at(app, DAY * days).await;
    if let Some(report) = &report {
        assert!(report.finished || report.interrupted, "{report:?}");
    }
    report
}

/// The bucket's sweep state: its cursor, versions read so far, and how many
/// the last whole sweep read.
async fn sweep_state(app: &App) -> (Option<String>, i64, Option<i64>) {
    let row = app
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT lifecycle_cursor, lifecycle_seen, lifecycle_last FROM buckets WHERE name = $1",
            &[&BUCKET],
        )
        .await
        .unwrap();
    let last: Option<String> = row.get(2);
    let last = last.map(|last| serde_json::from_str::<super::LastSweep>(&last).unwrap().read);
    (row.get(0), row.get(1), last)
}

async fn set_rate(app: &App, rate: i64) {
    crate::settings::LIFECYCLE_RATE.set(&app.pool.get().await.unwrap(), rate).await.unwrap();
}

/// Gives `bucket` `n` keys, `k00001` on, each only a delete marker.
async fn lone_markers(app: &App, bucket: &str, n: i32) {
    app.pool
        .get()
        .await
        .unwrap()
        .execute(
            "INSERT INTO objects (bucket, key, version_id, is_latest, is_delete_marker, size, etag,
                                  content_type, last_modified)
             SELECT $1, 'k' || lpad(n::text, 5, '0'), 'v', true, true, 0, NULL, NULL, now()
             FROM generate_series(1, $2::int) AS n",
            &[&bucket, &n],
        )
        .await
        .unwrap();
}

const MARKERS: &str = "<Rule><ID>r</ID><Filter/><Status>Enabled</Status>\
     <Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule>";

const MINUTE: Duration = Duration::from_secs(60);

#[tokio::test]
async fn sweeps_go_at_the_rate() {
    let Some(app) = node().await else { return };
    lone_markers(&app, BUCKET, 2500).await;
    configure(&app, MARKERS).await;
    // 1,000 versions a minute. The first step reads a minute's worth.
    set_rate(&app, 60_000).await;
    let first = step_at(&app, Duration::ZERO).await.unwrap();
    assert_eq!((first.read, first.removed, first.finished), (1000, 1000, false));
    assert_eq!(sweep_state(&app).await, (Some("k01000".to_owned()), 1000, None));
    // The next step is a minute later at the earliest, and reads the share
    // of the time since the last one began.
    assert_eq!(step_at(&app, MINUTE / 2).await, None);
    let second = step_at(&app, MINUTE * 2).await.unwrap();
    assert_eq!((second.read, second.removed, second.finished), (1500, 1500, true));
    assert_eq!(sweep_state(&app).await, (None, 0, Some(2500)));
    // The next sweep is a day after this one started.
    assert_eq!(step_at(&app, DAY - MINUTE).await, None);
    assert!(step_at(&app, DAY + MINUTE).await.unwrap().finished);
}

#[tokio::test]
async fn a_rate_of_0_pauses_sweeps() {
    let Some(app) = node().await else { return };
    lone_markers(&app, BUCKET, 10).await;
    configure(&app, MARKERS).await;
    set_rate(&app, 0).await;
    assert_eq!(step_at(&app, MINUTE).await, None);
    assert_eq!(query_i64(&app, "SELECT count(*) FROM objects").await, 10);
    set_rate(&app, 60_000).await;
    assert_eq!(step_at(&app, MINUTE * 2).await.unwrap().removed, 10);
}

#[tokio::test]
async fn buckets_take_turns() {
    let Some(app) = node().await else { return };
    let client = app.pool.get().await.unwrap();
    client.execute("INSERT INTO buckets (name) VALUES ('other')", &[]).await.unwrap();
    for bucket in [BUCKET, "other"] {
        lone_markers(&app, bucket, 1500).await;
        let body = format!("<LifecycleConfiguration>{MARKERS}</LifecycleConfiguration>");
        put_bucket_lifecycle(&app, bucket, Bytes::from(body)).await.unwrap();
    }
    set_rate(&app, 60_000).await;
    let step = |after| {
        let app = app.clone();
        async move {
            let results = pass(&app, SystemTime::now() + after).await;
            results.into_iter().map(|r| r.map_err(|(_, e)| e).unwrap()).collect::<Vec<_>>()
        }
    };
    let buckets = |reports: &[Report]| reports.iter().map(|r| r.bucket.clone()).collect::<Vec<_>>();
    // Each gets a step's worth (about 1,000) in turn, rather than the first
    // all it needs.
    let first = step(MINUTE).await;
    assert_eq!(buckets(&first), [BUCKET]);
    let second = step(MINUTE * 2).await;
    assert_eq!(buckets(&second), ["other"]);
    assert!((1000..1010).contains(&second[0].read), "{second:?}");
    // Then what's left of each.
    let third = step(MINUTE * 3).await;
    assert_eq!(buckets(&third), [BUCKET, "other"]);
    assert!(third.iter().all(|r| r.finished), "{third:?}");
    assert_eq!(query_i64(&app, "SELECT count(*) FROM objects").await, 0);
}

#[tokio::test]
async fn a_failed_step_is_taken_up_where_it_got_to() {
    let Some(app) = node().await else { return };
    lone_markers(&app, BUCKET, 1500).await;
    configure(&app, MARKERS).await;
    // A step that read the first page, and whose node died.
    let client = app.pool.get().await.unwrap();
    client
        .execute(
            "UPDATE buckets SET lifecycle_started = now(), lifecycle_cursor = 'k01000', lifecycle_seen = 1000",
            &[],
        )
        .await
        .unwrap();
    client
        .execute(
            "UPDATE lifecycle_runs SET last_step = now(), lease_until = now() + interval '10 minutes'",
            &[],
        )
        .await
        .unwrap();
    // No other node takes a step until its lease runs out.
    assert_eq!(step_at(&app, MINUTE).await, None);
    let report = step_at(&app, MINUTE * 11).await.unwrap();
    // Then only what was after where it got to.
    assert_eq!((report.read, report.finished), (500, true));
    assert_eq!(sweep_state(&app).await, (None, 0, Some(1500)));
    // A new configuration starts a new sweep, from the start.
    configure(&app, MARKERS).await;
    let report = step_at(&app, MINUTE * 13).await.unwrap();
    assert_eq!((report.removed, report.finished), (1000, true));
}

async fn versions(app: &App, key: &str) -> i64 {
    query_i64(app, &format!("SELECT count(*) FROM objects WHERE key = '{key}'")).await
}

#[tokio::test]
async fn objects_expire_after_their_days() {
    let Some(app) = node().await else { return };
    put(&app, "logs/a", vec![1; 10]).await;
    put(&app, "keep/b", vec![2; 10]).await;
    configure(
        &app,
        "<Rule><ID>logs</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status>\
         <Expiration><Days>1</Days></Expiration></Rule>",
    )
    .await;
    // Due right away, but nothing is a day old yet. It only read the keys
    // under the rule's prefix.
    let report = run_in(&app, 0).await.unwrap();
    assert!(report.is_empty(), "{report}");
    assert_eq!(sweep_state(&app).await, (None, 0, Some(1)));
    // Not due again until a day after.
    assert_eq!(step_at(&app, MINUTE * 10).await, None);
    let report = run_in(&app, 2).await.unwrap();
    assert_eq!((report.expired, report.removed), (1, 0));
    assert_eq!(get(&app, "logs/a").await, None);
    assert_eq!(get(&app, "keep/b").await, Some(vec![2; 10]));
    assert_eq!(versions(&app, "logs/a").await, 0);
    assert_files(&app, 1).await;
}

#[tokio::test]
async fn versions_expire_step_by_step() {
    let Some(app) = node().await else { return };
    enable_versioning(&app).await;
    put(&app, "a", vec![1]).await;
    put(&app, "a", vec![2]).await;
    configure(
        &app,
        "<Rule><ID>current</ID><Filter/><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>\
         <Rule><ID>markers</ID><Filter/><Status>Enabled</Status>\
         <Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule>\
         <Rule><ID>noncurrent</ID><Filter/><Status>Enabled</Status>\
         <NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration></Rule>",
    )
    .await;
    // The current version gets a delete marker, and the one it replaced goes.
    let report = run_in(&app, 3).await.unwrap();
    assert_eq!((report.expired, report.removed), (1, 1));
    assert_eq!(get(&app, "a").await, None);
    assert_eq!(versions(&app, "a").await, 2);
    // Then the version the marker hides, which leaves the marker alone.
    let report = run_in(&app, 6).await.unwrap();
    assert_eq!((report.expired, report.removed), (0, 1));
    assert_eq!(versions(&app, "a").await, 1);
    // And then the marker.
    let report = run_in(&app, 9).await.unwrap();
    assert_eq!((report.expired, report.removed), (0, 1));
    assert_eq!(versions(&app, "a").await, 0);
    assert_files(&app, 0).await;
}

#[tokio::test]
async fn newer_noncurrent_versions_are_kept() {
    let Some(app) = node().await else { return };
    enable_versioning(&app).await;
    for i in 0..5 {
        put(&app, "a", vec![i]).await;
    }
    configure(
        &app,
        "<Rule><ID>r</ID><Filter/><Status>Enabled</Status><NoncurrentVersionExpiration>\
         <NoncurrentDays>1</NoncurrentDays><NewerNoncurrentVersions>2</NewerNoncurrentVersions>\
         </NoncurrentVersionExpiration></Rule>",
    )
    .await;
    let report = run_in(&app, 3).await.unwrap();
    assert_eq!(report.removed, 2);
    // The current version, and the two newest noncurrent ones.
    assert_eq!(versions(&app, "a").await, 3);
    assert_eq!(get(&app, "a").await, Some(vec![4]));
}

#[tokio::test]
async fn a_version_written_since_is_not_expired() {
    let Some(app) = node().await else { return };
    put(&app, "a", vec![1]).await;
    configure(
        &app,
        "<Rule><ID>r</ID><Filter/><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>",
    )
    .await;
    let config: String = app
        .pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT lifecycle FROM buckets WHERE name = $1", &[&BUCKET])
        .await
        .unwrap()
        .get(0);
    let rules = super::Configuration::from_json(&config).unwrap();
    let client = app.pool.get().await.unwrap();
    let (versions, _, _) = page(&client, BUCKET, "", &everything(), super::PAGE).await.unwrap().unwrap();
    let due: Vec<_> = rules
        .due("a", &versions["a"], super::Day::of(SystemTime::now() + DAY * 3))
        .into_iter()
        .map(|due| ("a".to_owned(), due))
        .collect();
    assert_eq!(due.len(), 1);
    // Overwritten after the run read it: the new object isn't the one that
    // was due.
    put(&app, "a", vec![2]).await;
    let mut report = Report::default();
    assert!(expire(&app, &client, BUCKET, &config, &due, &mut report).await.unwrap());
    assert_eq!(report.expired, 0);
    assert_eq!(get(&app, "a").await, Some(vec![2]));
    // Nor is anything expired under a configuration that has changed since.
    configure(
        &app,
        "<Rule><ID>r</ID><Filter/><Status>Enabled</Status><Expiration><Days>2</Days></Expiration></Rule>",
    )
    .await;
    let (versions, _, _) = page(&client, BUCKET, "", &everything(), super::PAGE).await.unwrap().unwrap();
    let due: Vec<_> = rules
        .due("a", &versions["a"], super::Day::of(SystemTime::now() + DAY * 3))
        .into_iter()
        .map(|due| ("a".to_owned(), due))
        .collect();
    assert!(!expire(&app, &client, BUCKET, &config, &due, &mut report).await.unwrap());
    assert_eq!(get(&app, "a").await, Some(vec![2]));
}

#[tokio::test]
async fn deleting_the_configuration_stops_expirations() {
    let Some(app) = node().await else { return };
    put(&app, "a", vec![1]).await;
    configure(
        &app,
        "<Rule><ID>r</ID><Filter/><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>",
    )
    .await;
    let response = get_bucket_lifecycle(&app, BUCKET).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(std::str::from_utf8(&body).unwrap().contains("<Days>1</Days>"));
    let response = delete_bucket_lifecycle(&app, BUCKET).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(get_bucket_lifecycle(&app, BUCKET).await.unwrap().status(), StatusCode::NOT_FOUND);
    assert_eq!(run_in(&app, 30).await, None);
    assert_eq!(get(&app, "a").await, Some(vec![1]));
}

#[tokio::test]
async fn incomplete_uploads_are_aborted() {
    let Some(app) = node().await else { return };
    for key in ["tmp/a", "b"] {
        let response = create_multipart_upload(&app, BUCKET, key, "x", "", Wanted::Plain, None, None).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    configure(
        &app,
        "<Rule><ID>r</ID><Prefix>tmp/</Prefix><Status>Enabled</Status><AbortIncompleteMultipartUpload>\
         <DaysAfterInitiation>1</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule>",
    )
    .await;
    let report = run_in(&app, 2).await.unwrap();
    assert_eq!(report.aborted, 1);
    assert_eq!(query_i64(&app, "SELECT count(*) FROM multipart_uploads WHERE key = 'b'").await, 1);
    assert_eq!(query_i64(&app, "SELECT count(*) FROM multipart_uploads").await, 1);
}

#[tokio::test]
async fn a_page_holds_whole_keys() {
    let Some(app) = node().await else { return };
    enable_versioning(&app).await;
    // More versions of one key than a page holds, and a key after them.
    let client = app.pool.get().await.unwrap();
    client
        .execute(
            "INSERT INTO objects (bucket, key, version_id, is_latest, is_delete_marker, size, etag,
                                  content_type, last_modified)
             SELECT $1, 'a', 'v' || n, n = $2, true, 0, NULL, NULL, now()
             FROM generate_series(1, $2::int) AS n",
            &[&BUCKET, &(super::PAGE as i32 + 5)],
        )
        .await
        .unwrap();
    put(&app, "b", vec![1]).await;
    let (versions, last, last_page) = page(&client, BUCKET, "", &everything(), super::PAGE).await.unwrap().unwrap();
    assert_eq!((last.as_str(), last_page), ("a", false));
    assert_eq!(versions["a"].len(), super::PAGE as usize + 5);
    let (versions, last, last_page) = page(&client, BUCKET, "a", &everything(), super::PAGE).await.unwrap().unwrap();
    assert_eq!((versions.len(), last.as_str(), last_page), (1, "b", true));
    assert!(page(&client, BUCKET, "b", &everything(), super::PAGE).await.unwrap().is_none());
}

#[tokio::test]
async fn a_walk_goes_from_prefix_to_prefix() {
    let Some(app) = node().await else { return };
    for key in ["a/1", "b/1", "c/1", "c/2", "d/1"] {
        put(&app, key, vec![1]).await;
    }
    let client = app.pool.get().await.unwrap();
    let prefixes = ["a/".to_owned(), "c/".to_owned(), "e/".to_owned()];
    let keys = |page: &super::Page| page.keys().cloned().collect::<Vec<_>>();
    let (first, last, last_page) = page(&client, BUCKET, "", &prefixes, super::PAGE).await.unwrap().unwrap();
    assert_eq!((keys(&first), last.as_str(), last_page), (vec!["a/1".to_owned()], "a/1", false));
    let (second, last, last_page) = page(&client, BUCKET, &last, &prefixes, super::PAGE).await.unwrap().unwrap();
    assert_eq!(keys(&second), ["c/1", "c/2"]);
    // "e/" may have keys yet.
    assert!(!last_page);
    assert!(page(&client, BUCKET, &last, &prefixes, super::PAGE).await.unwrap().is_none());
    assert!(page(&client, BUCKET, "", &[], super::PAGE).await.unwrap().is_none());
}
