//! Looking events up (CloudTrail's `LookupEvents`), in what the nodes
//! shipped into the internal bucket (see `ship`): an account's events of a
//! time, newest first, with at most one attribute to match, a page at a
//! time.
//!
//! The objects are read a five-minute window at a time (by when their
//! files were opened, which their keys say), newest first: a window's
//! objects, every node's, are read together, and their events ordered by
//! time, then by where they are (an object's key, and their place in it:
//! so a node's events of a second are in the order it logged them), so
//! that a page goes on where the one before ended (`Cursor`: the window,
//! and where the last event given is) whatever was shipped meanwhile. An event of a window that was shipped after its pages were
//! read (its node was down) isn't found by the paging that's past it; a
//! new lookup finds it. Which objects may have an account's events, or an
//! event's name, the database says, from the index each object's metadata
//! has (see `ship::index`), so the others aren't read at all.
//!
//! What a node logged and hasn't shipped yet (up to five minutes, and a
//! few seconds) isn't found until it is, as CloudTrail's event history has
//! its events "within 5 minutes" or so. Events are ordered by their time,
//! to the second (as CloudTrail records it), and a request's event has the
//! time it was made, while it's logged once it's done: so an event may be
//! in a window after its time's. A lookup reads a window either side of
//! its times for that, and orders events only within a window.
//!
//! A lookup reads at most `MAX_FILES` objects (and finishes the window it's
//! in): one over a long time with few matches can answer fewer events than
//! asked for, none even, with a cursor to go on with, as CloudTrail's can.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::ship::{ACCOUNTS, EVENTS, PREFIX};
use crate::{App, db::Cached, lifecycle::rules::Day};

/// The windows the objects are read in, in milliseconds: as often as nodes
/// close their files (see `log::Rotation`).
const WINDOW: i64 = 300_000;
/// The most objects a lookup reads, besides finishing its last window.
const MAX_FILES: usize = 200;
/// How many bytes of objects' records are kept in memory, so that paging
/// through a window doesn't read its objects again for each page.
const CACHE_BYTES: usize = 64 << 20;

/// What an event may be looked up by (`LookupAttribute`'s `AttributeKey`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Attribute {
    EventId,
    EventName,
    ReadOnly,
    Username,
    ResourceType,
    ResourceName,
    EventSource,
    AccessKeyId,
}

impl Attribute {
    pub const ALL: [(&str, Attribute); 8] = [
        ("EventId", Attribute::EventId),
        ("EventName", Attribute::EventName),
        ("ReadOnly", Attribute::ReadOnly),
        ("Username", Attribute::Username),
        ("ResourceType", Attribute::ResourceType),
        ("ResourceName", Attribute::ResourceName),
        ("EventSource", Attribute::EventSource),
        ("AccessKeyId", Attribute::AccessKeyId),
    ];

    pub fn parse(name: &str) -> Option<Attribute> {
        Self::ALL.iter().find(|(n, _)| *n == name).map(|(_, a)| *a)
    }

    fn name(self) -> &'static str {
        Self::ALL.iter().find(|(_, a)| *a == self).unwrap().0
    }

    /// Whether `record` has `value` for it, exactly (as CloudTrail matches).
    fn matches(self, record: &Value, value: &str) -> bool {
        let is = |v: &Value| v.as_str() == Some(value);
        let resources = || record["resources"].as_array().into_iter().flatten();
        match self {
            Attribute::EventId => is(&record["eventID"]),
            Attribute::EventName => is(&record["eventName"]),
            Attribute::ReadOnly => {
                record["readOnly"].as_bool().map(|b| b.to_string()) == Some(value.to_owned())
            }
            Attribute::Username => username(record).as_deref() == Some(value),
            Attribute::ResourceType => resources().any(|r| is(&r["type"])),
            Attribute::ResourceName => resources().any(|r| is(&r["ARN"])),
            Attribute::EventSource => is(&record["eventSource"]),
            Attribute::AccessKeyId => is(&record["userIdentity"]["accessKeyId"]),
        }
    }
}

/// A lookup.
#[derive(Clone, Debug)]
pub struct Query {
    /// The account whose events are looked up (`recipientAccountId`).
    pub account: String,
    pub attribute: Option<(Attribute, String)>,
    /// The times the events must be between, inclusive, in seconds.
    pub start: i64,
    pub end: i64,
    /// Whether the times were given, rather than the defaults (the last 90
    /// days): a cursor is for the same lookup.
    pub given: (bool, bool),
    /// The most events to answer.
    pub max: usize,
}

impl Query {
    /// What a cursor is for: the lookup's own parameters, but not its
    /// times' defaults, which are a later request's own.
    fn fingerprint(&self) -> String {
        let attribute = self.attribute.as_ref().map(|(a, v)| (a.name(), v));
        let start = self.given.0.then_some(self.start);
        let end = self.given.1.then_some(self.end);
        let what = serde_json::to_string(&(&self.account, attribute, start, end)).unwrap();
        Sha256::digest(what.as_bytes())[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

/// Where an event is, in a window's order: its time, its object's key,
/// and its place in that.
type Place = (String, String, u64);

/// Where a lookup goes on: in `window` (its start, in milliseconds), after
/// the event at `after`, or with all of it.
#[derive(Clone, Debug, PartialEq)]
pub struct Cursor {
    window: i64,
    after: Option<Place>,
}

impl Cursor {
    /// As a `NextToken`, for `query` alone.
    pub fn token(&self, query: &Query) -> String {
        let token = json!({
            "q": query.fingerprint(),
            "w": self.window,
            "a": self.after,
        });
        URL_SAFE_NO_PAD.encode(token.to_string())
    }

    /// A `NextToken`'s, if it's one of `query`'s.
    pub fn parse(token: &str, query: &Query) -> Option<Cursor> {
        let token: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token).ok()?).ok()?;
        if token["q"].as_str()? != query.fingerprint() {
            return None;
        }
        let after = match &token["a"] {
            Value::Null => None,
            a => Some((
                a[0].as_str()?.to_owned(),
                a[1].as_str()?.to_owned(),
                a[2].as_u64()?,
            )),
        };
        Some(Cursor {
            window: token["w"].as_i64()?,
            after,
        })
    }
}

/// A page of a lookup's events: CloudTrail's records, newest first.
#[derive(Debug)]
pub struct Page {
    pub events: Vec<Value>,
    pub next: Option<Cursor>,
}

/// The events `query` finds, from `cursor` on (from the newest if none).
pub async fn lookup(app: &Arc<App>, query: &Query, cursor: Option<Cursor>) -> anyhow::Result<Page> {
    let lowest = window_of(query.start.saturating_mul(1000)) - WINDOW;
    let mut at = match cursor {
        Some(cursor) => Some((cursor.window, cursor.after)),
        None => {
            let above = window_of(query.end.saturating_mul(1000)) + 2 * WINDOW;
            newest(app, query, lowest, above).await?.map(|w| (w, None))
        }
    };
    let mut events: Vec<Value> = Vec::new();
    let mut read = 0;
    while let Some((window, after)) = at {
        if events.len() == query.max || read >= MAX_FILES {
            return Ok(Page {
                events,
                next: Some(Cursor { window, after }),
            });
        }
        let keys = keys(app, query, window, window + WINDOW).await?;
        read += keys.len();
        let mut found: Vec<(Place, Value)> = Vec::new();
        for key in keys {
            let Some(data) = read_object(app, &key).await? else {
                continue;
            };
            for (time, line, record) in matching(&data, query) {
                found.push(((time, key.clone(), line), record));
            }
        }
        // Newest first; those after the cursor alone.
        found.sort_by(|a, b| b.0.cmp(&a.0));
        let rest = found
            .into_iter()
            .filter(|(place, _)| after.as_ref().is_none_or(|after| place < after));
        let mut last = None;
        for (place, record) in rest {
            if events.len() == query.max {
                return Ok(Page {
                    events,
                    next: Some(Cursor {
                        window,
                        after: last,
                    }),
                });
            }
            events.push(record);
            last = Some(place);
        }
        at = newest(app, query, lowest, window).await?.map(|w| (w, None));
    }
    Ok(Page { events, next: None })
}

/// The window `millis` is in: its start.
pub(crate) fn window_of(millis: i64) -> i64 {
    millis.div_euclid(WINDOW) * WINDOW
}

/// Where the objects of files opened at `millis` or later are, in order of
/// keys (see `ship::object_key`): the key before any of theirs, and after
/// any of those opened before.
pub(crate) fn key_at(millis: i64) -> String {
    let millis = millis.max(0);
    let opened = std::time::UNIX_EPOCH + std::time::Duration::from_millis(millis as u64);
    let day = Day::of(opened);
    let (year, month, date) = day.civil();
    let hour = opened
        .duration_since(day.midnight())
        .map_or(0, |d| d.as_secs() / 3600);
    format!("{PREFIX}{year:04}/{month:02}/{date:02}/{hour:02}/{millis:013}")
}

/// When the file an object's key names was opened, in milliseconds.
fn opened(key: &str) -> Option<i64> {
    key.rsplit('/').next()?.split('-').next()?.parse().ok()
}

/// The objects' conditions on their indexes (see `ship::index`), as SQL,
/// with `$4` the account and `$5` an event's name (or null): an object
/// without an index (or without a list, which was too long) may have any.
fn indexed() -> String {
    format!(
        "(metadata NOT LIKE '%{ACCOUNTS}: %' OR strpos(metadata, ',' || $4 || ',') > 0)
         AND ($5::text IS NULL OR metadata NOT LIKE '%{EVENTS}: %'
              OR strpos(metadata, ',' || $5 || ',') > 0)"
    )
}

/// The event's name the objects' indexes may be looked in for `query`.
fn indexed_name(query: &Query) -> Option<&str> {
    match &query.attribute {
        Some((Attribute::EventName, name)) if !name.contains([',', '\n', '\r']) => Some(name),
        _ => None,
    }
}

/// The newest window from `lowest` and before `before` with an object that
/// may have `query`'s events.
async fn newest(
    app: &Arc<App>,
    query: &Query,
    lowest: i64,
    before: i64,
) -> anyhow::Result<Option<i64>> {
    if before <= lowest {
        return Ok(None);
    }
    let sql = format!(
        "SELECT key FROM objects
         WHERE bucket = $1 AND key >= $2 AND key < $3 AND is_latest AND {}
         ORDER BY key DESC LIMIT 1",
        indexed()
    );
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached(
            &sql,
            &[
                &crate::internal::BUCKET,
                &key_at(lowest),
                &key_at(before),
                &query.account,
                &indexed_name(query),
            ],
        )
        .await?;
    Ok(row.and_then(|row| opened(row.get(0))).map(window_of))
}

/// The keys of the objects of files opened from `from` and before `to`
/// that may have `query`'s events.
async fn keys(app: &Arc<App>, query: &Query, from: i64, to: i64) -> anyhow::Result<Vec<String>> {
    let sql = format!(
        "SELECT key FROM objects
         WHERE bucket = $1 AND key >= $2 AND key < $3 AND is_latest AND {}
         ORDER BY key",
        indexed()
    );
    let rows = app
        .pool
        .get()
        .await?
        .query_cached(
            &sql,
            &[
                &crate::internal::BUCKET,
                &key_at(from),
                &key_at(to),
                &query.account,
                &indexed_name(query),
            ],
        )
        .await?;
    Ok(rows.iter().map(|row| row.get(0)).collect())
}

/// The objects' records read lately, newest last.
static CACHE: Mutex<VecDeque<(String, Arc<Vec<u8>>)>> = Mutex::new(VecDeque::new());

/// An object's records (its file's, unzipped), if it's there.
pub(crate) async fn read_object(app: &Arc<App>, key: &str) -> anyhow::Result<Option<Arc<Vec<u8>>>> {
    {
        let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(at) = cache.iter().position(|(k, _)| k == key) {
            let entry = cache.remove(at).unwrap();
            let data = entry.1.clone();
            cache.push_back(entry);
            return Ok(Some(data));
        }
    }
    let response = crate::s3::objects::get::get_object(
        app,
        crate::internal::BUCKET,
        key,
        None,
        None,
        None,
        &Default::default(),
        None,
        None,
        false,
    )
    .await?;
    // Expired since it was listed.
    if response.status() == hyper::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        anyhow::bail!("reading {key}: {}", response.status());
    }
    let gz = response
        .into_body()
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("reading {key}: {e}"))?
        .to_bytes();
    let data = tokio::task::spawn_blocking(move || {
        let mut data = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&gz[..]), &mut data)
            .map(|_| data)
    })
    .await??;
    let data = Arc::new(data);
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    cache.push_back((key.to_owned(), data.clone()));
    let mut total: usize = cache.iter().map(|(_, d)| d.len()).sum();
    while total > CACHE_BYTES && cache.len() > 1 {
        let (_, old) = cache.pop_front().unwrap();
        total -= old.len();
    }
    Ok(Some(data))
}

/// The records of a file's `data` that `query` finds, with their times
/// and their places in it (to order them by).
fn matching(data: &[u8], query: &Query) -> Vec<(String, u64, Value)> {
    // A record is compact JSON, as `Event::to_json` wrote it: one that
    // doesn't have its account's member as text isn't the account's, and
    // isn't parsed.
    let account = format!(r#""recipientAccountId":{}"#, json!(query.account));
    let mut found = Vec::new();
    for (line, record) in super::log::records(data).enumerate() {
        if !contains(record, account.as_bytes()) {
            continue;
        }
        let Ok(record) = serde_json::from_slice::<Value>(record) else {
            continue;
        };
        if record["recipientAccountId"].as_str() != Some(&query.account) {
            continue;
        }
        let Some(time) = record["eventTime"].as_str().and_then(seconds) else {
            continue;
        };
        if time < query.start || time > query.end {
            continue;
        }
        if let Some((attribute, value)) = &query.attribute
            && !attribute.matches(&record, value)
        {
            continue;
        }
        let time = record["eventTime"].as_str().unwrap_or("").to_owned();
        found.push((time, line as u64, record));
    }
    found
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// An event's time (`2026-11-16T05:06:07Z`) in seconds.
pub fn seconds(time: &str) -> Option<i64> {
    let compact: String = time.chars().filter(|c| *c != '-' && *c != ':').collect();
    crate::auth::parse_amz_date(&compact)
}

/// Who made an event, as `LookupEvents` names them (`Username`): an IAM
/// user's name, a session's (a role's, a federated user's), or `root`.
pub fn username(record: &Value) -> Option<String> {
    let identity = &record["userIdentity"];
    match identity["type"].as_str()? {
        "Root" => Some("root".to_owned()),
        "IAMUser" => identity["userName"].as_str().map(str::to_owned),
        _ => identity["arn"]
            .as_str()
            .and_then(|arn| arn.rsplit('/').next())
            .map(str::to_owned),
    }
}

/// An event as `LookupEvents` answers it: what it's looked up by, and its
/// record (`CloudTrailEvent`), as JSON in a string.
pub fn summary(record: &Value) -> Value {
    let mut event = json!({
        "EventId": record["eventID"],
        "EventName": record["eventName"],
        "ReadOnly": record["readOnly"].as_bool().map(|b| b.to_string()),
        "EventTime": record["eventTime"].as_str().and_then(seconds),
        "EventSource": record["eventSource"],
        "Username": username(record),
        "Resources": record["resources"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|r| json!({ "ResourceType": r["type"], "ResourceName": r["ARN"] }))
            .collect::<Vec<_>>(),
        "CloudTrailEvent": record.to_string(),
    });
    if let Some(key) = record["userIdentity"]["accessKeyId"].as_str() {
        event["AccessKeyId"] = json!(key);
    }
    if let Value::Object(members) = &mut event {
        members.retain(|_, v| !v.is_null());
    }
    event
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> Query {
        Query {
            account: "111".to_owned(),
            attribute: None,
            start: 0,
            end: i64::MAX / 1000,
            given: (false, false),
            max: 50,
        }
    }

    #[test]
    fn keys_order_as_files_were_opened() {
        // 2026-11-16T05:06:07.890Z, as `ship::object_key` names it.
        let key = "audit/2026/11/16/05/1794805567890-3-0a0b0c0d-00000000-0000-0000-0000-000000000000.log.gz";
        assert_eq!(opened(key), Some(1_794_805_567_890));
        assert_eq!(
            key_at(1_794_805_567_890),
            "audit/2026/11/16/05/1794805567890"
        );
        assert!(key_at(1_794_805_567_890).as_str() <= key);
        assert!(key_at(1_794_805_567_891).as_str() > key);
        // The next hour's are after every one of this hour's.
        assert!(key_at(1_794_808_800_000).as_str() > key);
        assert_eq!(window_of(1_794_805_567_890), 1_794_805_500_000);
    }

    #[test]
    fn records_are_matched() {
        let records = [
            json!({
                "eventID": "a", "eventName": "Decrypt", "eventTime": "2026-11-16T05:06:07Z",
                "eventSource": "kms.amazonaws.com", "readOnly": true,
                "recipientAccountId": "111",
                "userIdentity": { "type": "IAMUser", "userName": "alice", "accessKeyId": "AKIA1" },
                "resources": [{ "type": "AWS::KMS::Key", "ARN": "arn:k" }],
            }),
            json!({
                "eventID": "b", "eventName": "CreateKey", "eventTime": "2026-11-16T05:06:09Z",
                "eventSource": "kms.amazonaws.com", "readOnly": false,
                "recipientAccountId": "111",
                "userIdentity": {
                    "type": "AssumedRole",
                    "arn": "arn:aws:sts::111:assumed-role/r/session-1",
                },
                "resources": [],
            }),
            json!({
                "eventID": "c", "eventName": "Decrypt", "eventTime": "2026-11-16T05:06:08Z",
                "recipientAccountId": "222", "userIdentity": { "type": "Root" },
            }),
        ];
        let data: String = records.iter().map(|r| format!("{r}\n")).collect();
        let ids = |q: &Query| -> Vec<String> {
            matching(data.as_bytes(), q)
                .into_iter()
                .map(|(_, _, r)| r["eventID"].as_str().unwrap().to_owned())
                .collect()
        };
        assert_eq!(ids(&query()), ["a", "b"]);
        let with = |a: Attribute, v: &str| Query {
            attribute: Some((a, v.to_owned())),
            ..query()
        };
        assert_eq!(ids(&with(Attribute::EventName, "Decrypt")), ["a"]);
        assert_eq!(ids(&with(Attribute::ReadOnly, "false")), ["b"]);
        assert_eq!(ids(&with(Attribute::Username, "alice")), ["a"]);
        assert_eq!(ids(&with(Attribute::Username, "session-1")), ["b"]);
        assert_eq!(ids(&with(Attribute::ResourceName, "arn:k")), ["a"]);
        assert_eq!(ids(&with(Attribute::ResourceType, "AWS::KMS::Key")), ["a"]);
        assert_eq!(ids(&with(Attribute::AccessKeyId, "AKIA1")), ["a"]);
        assert_eq!(ids(&with(Attribute::EventId, "c")), Vec::<String>::new());
        assert_eq!(
            ids(&with(Attribute::EventSource, "kms.amazonaws.com")),
            ["a", "b"]
        );
        let start = seconds("2026-11-16T05:06:08Z").unwrap();
        assert_eq!(ids(&Query { start, ..query() }), ["b"]);
        assert_eq!(
            ids(&Query {
                end: start,
                ..query()
            }),
            ["a"]
        );
        let other = Query {
            account: "222".to_owned(),
            ..query()
        };
        assert_eq!(ids(&other), ["c"]);
        assert_eq!(username(&records[2]).as_deref(), Some("root"));

        let summary = summary(&records[0]);
        assert_eq!(summary["ReadOnly"], "true");
        assert_eq!(summary["EventTime"], 1_794_805_567);
        assert_eq!(summary["Username"], "alice");
        assert_eq!(summary["AccessKeyId"], "AKIA1");
        assert_eq!(
            summary["Resources"],
            json!([{ "ResourceType": "AWS::KMS::Key", "ResourceName": "arn:k" }])
        );
        let event: Value =
            serde_json::from_str(summary["CloudTrailEvent"].as_str().unwrap()).unwrap();
        assert_eq!(event, records[0]);
    }

    #[test]
    fn cursors_are_their_lookups() {
        let cursor = Cursor {
            window: 1_794_805_500_000,
            after: Some(("2026-11-16T05:06:07Z".to_owned(), "audit/k".to_owned(), 3)),
        };
        let q = query();
        let token = cursor.token(&q);
        assert_eq!(Cursor::parse(&token, &q), Some(cursor.clone()));
        // The defaults of the times are each request's own.
        let later = Query { end: 5, ..query() };
        assert_eq!(Cursor::parse(&token, &later), Some(cursor));
        let other = Query {
            attribute: Some((Attribute::EventName, "Decrypt".to_owned())),
            ..query()
        };
        assert_eq!(Cursor::parse(&token, &other), None);
        let given = Query {
            given: (true, false),
            ..query()
        };
        assert_eq!(Cursor::parse(&token, &given), None);
        assert_eq!(Cursor::parse("not a token", &q), None);
    }
}
