//! Listing keys: the walk in `cairn_list_current` (see "LISTINGS" in
//! `catalog.sql`), its byte order, and its markers, which work as in MinIO.

use std::sync::Arc;

use super::{BUCKET, node_with, put};
use crate::{
    App, packer,
    s3::objects::list::{ListEntry, ListQuery, list},
};

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
