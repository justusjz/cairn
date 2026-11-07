//! Listing keys: the walk in `cairn_list_current` (see "LISTINGS" in
//! `catalog.sql`), its byte order, and its markers, which work as in MinIO.

use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::StatusCode;

use super::{BUCKET, delete, node_with, put};
use crate::{
    App, packer,
    s3::{
        multipart::{
            abort::abort_multipart_upload, create::create_multipart_upload,
            list::list_multipart_uploads,
        },
        objects::{
            delete::delete_object,
            list::{ListEntry, ListQuery, list},
            list_versions::list_object_versions,
        },
    },
};
use crate::s3::sse::Wanted;

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

/// One page: its entries' names (a common prefix as itself) and its next
/// marker, if it's truncated.
async fn page(
    app: &App,
    prefix: &str,
    delimiter: &str,
    marker: &str,
    max_keys: i64,
) -> (Vec<String>, Option<String>) {
    let query = ListQuery {
        prefix,
        delimiter: (!delimiter.is_empty()).then_some(delimiter),
        marker,
        max_keys,
        delete_markers: false,
        totals: true,
    };
    let listing = list(app, BUCKET, &query).await.unwrap().unwrap();
    let names = listing
        .entries
        .into_iter()
        .map(|entry| match entry {
            ListEntry::Object { key, .. } => key,
            ListEntry::Prefix { prefix, .. } => prefix,
        })
        .collect();
    (names, listing.next_marker)
}

/// Every entry, page by page, `max_keys` at a time, checking that each page's
/// marker is its last entry.
async fn all(app: &App, prefix: &str, delimiter: &str, max_keys: i64) -> Vec<String> {
    let mut names = Vec::new();
    let mut marker = String::new();
    loop {
        let (mut got, next) = page(app, prefix, delimiter, &marker, max_keys).await;
        assert!(got.len() as i64 <= max_keys);
        let Some(next) = next else {
            names.append(&mut got);
            return names;
        };
        assert_eq!(Some(&next), got.last(), "a page's marker is its last entry");
        names.append(&mut got);
        marker = next;
    }
}

const KEYS: [&str; 10] = [
    "a", "b/1", "b/2", "b/3", "c", "d/x/1", "d/x/2", "d/y", "e", "_",
];

#[tokio::test]
async fn walks_keys_and_common_prefixes() {
    let Some(app) = node().await else { return };
    for key in KEYS {
        put(&app, key, key.as_bytes().to_vec()).await;
    }
    let all_keys = ["_", "a", "b/1", "b/2", "b/3", "c", "d/x/1", "d/x/2", "d/y", "e"];
    let rolled_up = ["_", "a", "b/", "c", "d/", "e"];
    for max_keys in [1, 2, 3, 1000] {
        assert_eq!(all(&app, "", "", max_keys).await, all_keys, "max-keys {max_keys}");
        assert_eq!(all(&app, "", "/", max_keys).await, rolled_up, "max-keys {max_keys}");
    }
    assert_eq!(all(&app, "d/", "/", 1).await, ["d/x/", "d/y"]);
    assert_eq!(all(&app, "b", "", 2).await, ["b/1", "b/2", "b/3"]);
    // A delimiter of several characters.
    assert_eq!(all(&app, "d", "/x/", 1).await, ["d/x/", "d/y"]);
    // A common prefix's totals: its keys, and their bytes.
    let query = ListQuery {
        prefix: "",
        delimiter: Some("/"),
        marker: "a",
        max_keys: 1,
        delete_markers: false,
        totals: true,
    };
    let listing = list(&app, BUCKET, &query).await.unwrap().unwrap();
    let ListEntry::Prefix { prefix, totals: Some(totals) } = &listing.entries[0] else {
        panic!("b/ is a common prefix, with totals");
    };
    assert_eq!((prefix.as_str(), totals.objects, totals.bytes), ("b/", 3, 9));
}

/// As in MinIO, an entry is listed only if it sorts after the marker: a marker
/// naming a common prefix resumes past all of its keys, and so does one
/// within it, since the common prefix sorts before it.
#[tokio::test]
async fn markers_work_as_in_minio() {
    let Some(app) = node().await else { return };
    for key in KEYS {
        put(&app, key, key.as_bytes().to_vec()).await;
    }
    for marker in ["b/", "b/1", "b/3", "b/zzz"] {
        let (names, next) = page(&app, "", "/", marker, 1000).await;
        assert_eq!(names, ["c", "d/", "e"], "marker {marker}");
        assert_eq!(next, None);
    }
    // Without a delimiter, the keys within it follow.
    assert_eq!(page(&app, "", "", "b/1", 2).await.0, ["b/2", "b/3"]);
    // A marker before the prefix starts at it, one after it ends the listing.
    assert_eq!(page(&app, "d/", "/", "a", 1000).await.0, ["d/x/", "d/y"]);
    assert!(page(&app, "b/", "/", "c", 1000).await.0.is_empty());
}

/// Keys sort by their UTF-8 bytes, and the walk jumps past a common prefix
/// even where its last character is the largest there is.
#[tokio::test]
async fn walks_in_byte_order() {
    let Some(app) = node().await else { return };
    let top = '\u{10FFFF}';
    let keys = [
        "u/é".to_owned(),
        "u/B".to_owned(),
        "u/a".to_owned(),
        format!("u/{top}x"),
        format!("u/{top}{top}"),
        format!("u/{top}/1"),
        format!("u{top}"),
        "v".to_owned(),
    ];
    for key in &keys {
        put(&app, key, b"x".to_vec()).await;
    }
    let under_u: Vec<String> = all(&app, "u/", "", 1).await;
    let expected = ["u/B", "u/a", "u/é"]
        .map(str::to_owned)
        .into_iter()
        .chain([format!("u/{top}/1"), format!("u/{top}x"), format!("u/{top}{top}")])
        .collect::<Vec<_>>();
    assert_eq!(under_u, expected);
    // Rolled up at the largest character, past which nothing sorts.
    let by_top = all(&app, "u/", &top.to_string(), 1).await;
    assert_eq!(by_top, ["u/B", "u/a", "u/é", &format!("u/{top}")]);
    let all_top: Vec<String> = all(&app, &format!("u/{top}"), "", 1).await;
    assert_eq!(all_top.len(), 3);
}

/// Every entry of ListObjectVersions' walk, `limit` at a time, resuming after
/// each page's last entry: names, with a common prefix as itself.
async fn all_versions(app: &App, prefix: &str, delimiter: &str, limit: i32) -> Vec<String> {
    let client = app.pool.get().await.unwrap();
    let mut names: Vec<String> = Vec::new();
    let (mut key_marker, mut id_marker) = (String::new(), None::<i64>);
    loop {
        let rows = client
            .query(
                "SELECT l.name, l.is_prefix,
                        (SELECT o.id FROM objects o WHERE o.bucket = $1 AND o.key = l.name
                         AND o.version_id = l.version_id)
                 FROM pg_temp.cairn_list_versions($1, $2, $3, $4, $5, $6) AS l",
                &[&BUCKET, &prefix, &delimiter, &key_marker, &id_marker, &(limit + 1)],
            )
            .await
            .unwrap();
        let more = rows.len() > limit as usize;
        for row in rows.iter().take(limit as usize) {
            names.push(row.get(0));
            key_marker = row.get(0);
            id_marker = if row.get::<_, bool>(1) { None } else { row.get(2) };
        }
        if !more {
            return names;
        }
    }
}

#[tokio::test]
async fn walks_versions_and_common_prefixes() {
    let Some(app) = node().await else { return };
    for key in KEYS {
        put(&app, key, key.as_bytes().to_vec()).await;
    }
    let all_keys = ["_", "a", "b/1", "b/2", "b/3", "c", "d/x/1", "d/x/2", "d/y", "e"];
    let rolled_up = ["_", "a", "b/", "c", "d/", "e"];
    for limit in [1, 2, 1000] {
        assert_eq!(all_versions(&app, "", "", limit).await, all_keys, "limit {limit}");
        assert_eq!(all_versions(&app, "", "/", limit).await, rolled_up, "limit {limit}");
    }
    assert_eq!(all_versions(&app, "d/", "/", 1).await, ["d/x/", "d/y"]);
}

/// One page of ListObjectVersions, as the handler answers it: its versions'
/// keys and IDs.
async fn versions_page(
    app: &App,
    key_marker: &str,
    version_id_marker: &str,
    max_keys: i64,
) -> Vec<(String, String)> {
    let response = list_object_versions(
        app,
        BUCKET,
        "",
        None,
        key_marker,
        Some(version_id_marker),
        max_keys,
        Default::default(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = std::str::from_utf8(&body).unwrap();
    let between = |s: &str, open: &str, close: &str| {
        let start = s.find(open).unwrap() + open.len();
        s[start..start + s[start..].find(close).unwrap()].to_owned()
    };
    body.split("<Version>")
        .skip(1)
        .map(|v| (between(v, "<Key>", "</Key>"), between(v, "<VersionId>", "</VersionId>")))
        .collect()
}

async fn version_ids(app: &App, key: &str) -> Vec<String> {
    let client = app.pool.get().await.unwrap();
    let rows = client
        .query(
            "SELECT version_id FROM objects WHERE bucket = $1 AND key = $2 ORDER BY id DESC",
            &[&BUCKET, &key],
        )
        .await
        .unwrap();
    rows.iter().map(|row| row.get(0)).collect()
}

/// A page can follow one whose last version was deleted since, as a client
/// emptying a bucket page by page deletes it: it starts at that key's newest
/// version that's left, so nothing is skipped.
#[tokio::test]
async fn a_version_marker_may_be_gone() {
    let Some(app) = node().await else { return };
    let pair = |k: &str, v: &str| (k.to_owned(), v.to_owned());
    // Unversioned: the key's only version was the marker, so the next key follows.
    for key in ["a", "b"] {
        put(&app, key, b"x".to_vec()).await;
    }
    delete(&app, "a").await;
    assert_eq!(versions_page(&app, "a", "null", 1000).await, [pair("b", "null")]);
    delete(&app, "b").await;

    // Versioned: k has versions v3, v2, v1 (newest first), then comes l.
    app.pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT pg_temp.cairn_set_versioning($1, 'enabled')", &[&BUCKET])
        .await
        .unwrap();
    for (key, data) in [("k", "1"), ("k", "2"), ("k", "3"), ("l", "1")] {
        put(&app, key, data.as_bytes().to_vec()).await;
    }
    let k = version_ids(&app, "k").await;
    let l = version_ids(&app, "l").await;
    // A page ended at v2, which is still there: the rest of k follows it.
    assert_eq!(
        versions_page(&app, "k", &k[1], 1000).await,
        [pair("k", &k[2]), pair("l", &l[0])]
    );
    // v2 is deleted, as a page's versions are when emptying the bucket.
    let delete_version = |v: String| {
        let app = app.clone();
        async move {
            let response = delete_object(&app, BUCKET, "k", Some(&v)).await.unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        }
    };
    delete_version(k[1].clone()).await;
    // v3 is still there, so it's listed again, then v1 and l: nothing is skipped.
    assert_eq!(
        versions_page(&app, "k", &k[1], 1000).await,
        [pair("k", &k[0]), pair("k", &k[2]), pair("l", &l[0])]
    );
    // With v3 deleted too, as it is in that case, the page is exactly the rest.
    delete_version(k[0].clone()).await;
    assert_eq!(
        versions_page(&app, "k", &k[1], 1000).await,
        [pair("k", &k[2]), pair("l", &l[0])]
    );
}

/// One page of ListMultipartUploads: its entries, an upload as `key@id` and a
/// common prefix as itself, in key order (the response lists uploads before
/// common prefixes), and its next markers, if it's truncated.
async fn uploads_page(
    app: &App,
    delimiter: &str,
    key_marker: &str,
    upload_id_marker: Option<&str>,
    max_uploads: i64,
) -> (Vec<String>, Option<(String, Option<String>)>) {
    let delimiter = (!delimiter.is_empty()).then_some(delimiter);
    let response = list_multipart_uploads(
        app,
        BUCKET,
        "",
        delimiter,
        key_marker,
        upload_id_marker,
        max_uploads,
        Default::default(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = std::str::from_utf8(&body).unwrap().to_owned();
    let between = |s: &str, open: &str, close: &str| {
        let start = s.find(open)? + open.len();
        Some(s[start..start + s[start..].find(close)?].to_owned())
    };
    let mut entries: Vec<String> = body
        .split("<Upload>")
        .skip(1)
        .map(|u| format!("{}@{}", between(u, "<Key>", "</Key>").unwrap(), between(u, "<UploadId>", "</UploadId>").unwrap()))
        .collect();
    entries.extend(
        body.split("<CommonPrefixes>").skip(1).map(|p| between(p, "<Prefix>", "</Prefix>").unwrap()),
    );
    // Stable, so each key's uploads keep their order.
    entries.sort_by(|a, b| a.split('@').next().cmp(&b.split('@').next()));
    let next = between(&body, "<NextKeyMarker>", "</NextKeyMarker>")
        .map(|key| (key, between(&body, "<NextUploadIdMarker>", "</NextUploadIdMarker>")));
    (entries, next)
}

/// Every entry, page by page, `max_uploads` at a time.
async fn all_uploads(app: &App, delimiter: &str, max_uploads: i64) -> Vec<String> {
    let (mut names, mut key_marker, mut upload_marker) = (Vec::new(), String::new(), None::<String>);
    loop {
        let (mut got, next) =
            uploads_page(app, delimiter, &key_marker, upload_marker.as_deref(), max_uploads).await;
        assert!(got.len() as i64 <= max_uploads);
        names.append(&mut got);
        let Some((key, upload)) = next else { return names };
        (key_marker, upload_marker) = (key, upload);
    }
}

#[tokio::test]
async fn walks_uploads_and_common_prefixes() {
    let Some(app) = node().await else { return };
    let mut ids = std::collections::HashMap::<&str, Vec<String>>::new();
    // Created out of key order: each key's uploads list in the order they
    // were created, after the keys before it.
    for key in ["c", "b/2", "a", "b/1", "a"] {
        let response = create_multipart_upload(&app, BUCKET, key, "x", "", Wanted::Plain).await.unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = std::str::from_utf8(&body).unwrap();
        let start = body.find("<UploadId>").unwrap() + "<UploadId>".len();
        ids.entry(key).or_default().push(body[start..body.find("</UploadId>").unwrap()].to_owned());
    }
    let upload = |key: &str, i: usize| format!("{key}@{}", ids[key][i]);
    let all = [upload("a", 0), upload("a", 1), upload("b/1", 0), upload("b/2", 0), upload("c", 0)];
    let rolled_up = [upload("a", 0), upload("a", 1), "b/".to_owned(), upload("c", 0)];
    for max_uploads in [1, 2, 1000] {
        assert_eq!(all_uploads(&app, "", max_uploads).await, all, "max-uploads {max_uploads}");
        assert_eq!(all_uploads(&app, "/", max_uploads).await, rolled_up, "max-uploads {max_uploads}");
    }
    // A key marker alone resumes after all of its key's uploads, and an upload
    // marker without a key marker is ignored.
    assert_eq!(uploads_page(&app, "", "a", None, 1000).await.0, all[2..]);
    assert_eq!(uploads_page(&app, "", "", Some(&ids["a"][0]), 1000).await.0, all);
    // An upload marker resumes after that upload, even once it's aborted.
    let response = abort_multipart_upload(&app, BUCKET, "a", &ids["a"][0]).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(uploads_page(&app, "", "a", Some(&ids["a"][0]), 1000).await.0, all[1..]);
    // An upload marker that can't be an upload ID is refused.
    let response = list_multipart_uploads(
        &app,
        BUCKET,
        "",
        None,
        "a",
        Some("nope"),
        1000,
        Default::default(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// ListObjects as S3 writes it: `encoding-type=url` percent-encodes keys and
/// common prefixes (but `/`), v1 lists each key's owner and v2 only with
/// `fetch-owner`, and a page of none isn't truncated.
#[tokio::test]
async fn lists_as_s3_writes_listings() {
    use crate::s3::{
        objects::list::{ListVersion, list_objects},
        util::Encoding,
    };
    let Some(app) = node().await else { return };
    for key in ["foo+1/bar", "foo/bar/xyzzy", "quux ab/thud", "asdf+b"] {
        put(&app, key, b"x".to_vec()).await;
    }
    let body = |response: hyper::Response<http_body_util::Full<hyper::body::Bytes>>| async move {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    };
    let v2 = |fetch_owner| ListVersion::V2 {
        continuation_token: None,
        start_after: None,
        fetch_owner,
    };
    let listed = body(
        list_objects(
            &app,
            BUCKET,
            "",
            Some("/"),
            "",
            1000,
            ListVersion::V1,
            Encoding::Url,
        )
        .await
        .unwrap(),
    )
    .await;
    assert!(
        listed.contains("<EncodingType>url</EncodingType>"),
        "{listed}"
    );
    assert!(listed.contains("<Key>asdf%2Bb</Key>"), "{listed}");
    for prefix in ["foo%2B1/", "foo/", "quux%20ab/"] {
        assert!(
            listed.contains(&format!("<Prefix>{prefix}</Prefix>")),
            "{prefix}: {listed}"
        );
    }
    assert!(
        listed.contains("<Owner><ID>cairn</ID>"),
        "v1 lists owners: {listed}"
    );
    let listed = body(
        list_objects(&app, BUCKET, "", None, "", 1000, v2(false), Encoding::Plain)
            .await
            .unwrap(),
    )
    .await;
    assert!(
        listed.contains("<Key>quux ab/thud</Key>") && !listed.contains("<Owner>"),
        "{listed}"
    );
    assert!(!listed.contains("<EncodingType>"), "{listed}");
    let listed = body(
        list_objects(&app, BUCKET, "", None, "", 1000, v2(true), Encoding::Plain)
            .await
            .unwrap(),
    )
    .await;
    assert!(listed.contains("<Owner><ID>cairn</ID>"), "{listed}");
    let listed = body(
        list_objects(
            &app,
            BUCKET,
            "",
            None,
            "",
            0,
            ListVersion::V1,
            Encoding::Plain,
        )
        .await
        .unwrap(),
    )
    .await;
    assert!(
        listed.contains("<IsTruncated>false</IsTruncated>") && !listed.contains("<Contents>"),
        "{listed}"
    );
}
