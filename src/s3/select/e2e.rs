//! SelectObjectContent against a real Postgres (see `e2e`): objects stored
//! as any are, read back as they stream.

use std::{io::Write, sync::Arc};

use http_body_util::BodyExt;
use hyper::StatusCode;

use super::{eventstream, prepare, select_object_content};
use crate::{
    App,
    e2e::{BUCKET, customer_key, node_with, put, put_sealed, put_sized},
    packer,
    s3::sse_c::CustomerKey,
};

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

/// A request for `sql`, with `input` and `output` serialization elements.
fn request(sql: &str, input: &str, output: &str) -> Vec<u8> {
    format!(
        "<SelectObjectContentRequest xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Expression>{}</Expression><ExpressionType>SQL</ExpressionType>\
         <InputSerialization>{input}</InputSerialization>\
         <OutputSerialization>{output}</OutputSerialization>\
         </SelectObjectContentRequest>",
        crate::s3::util::xml_escape(sql)
    )
    .into_bytes()
}

/// What a select answered.
#[derive(Debug, Default)]
struct Answer {
    status: u16,
    records: String,
    /// The events' types (and errors' codes), in order, Records once.
    events: Vec<String>,
    stats: String,
}

async fn select(app: &Arc<App>, key: &str, body: &[u8], customer: Option<&CustomerKey>) -> Answer {
    let prepared = match prepare("select&select-type=2", body) {
        Ok(prepared) => prepared,
        Err(refused) => {
            return Answer {
                status: refused.status().as_u16(),
                ..Answer::default()
            };
        }
    };
    let response = select_object_content(app, BUCKET, key, prepared, customer, None)
        .await
        .unwrap();
    let mut answer = Answer {
        status: response.status().as_u16(),
        ..Answer::default()
    };
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    if answer.status != 200 {
        return answer;
    }
    let mut rest = &bytes[..];
    while !rest.is_empty() {
        let (headers, payload, next) = eventstream::decode(rest);
        rest = next;
        let header = |name: &str| {
            headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        let event = match header(":message-type").as_str() {
            "error" => header(":error-code"),
            _ => header(":event-type"),
        };
        match event.as_str() {
            "Records" => answer
                .records
                .push_str(std::str::from_utf8(&payload).unwrap()),
            "Stats" => answer.stats = String::from_utf8(payload).unwrap(),
            _ => {}
        }
        if answer.events.last() != Some(&event) {
            answer.events.push(event);
        }
    }
    answer
}

const CSV_USE: &str = "<CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV>";

#[tokio::test]
async fn selects_from_csv_and_gzipped_csv() {
    let Some(app) = node().await else { return };
    let csv = b"name,age\nAda,36\nAlan,41\nGrace,85\n".to_vec();
    put(&app, "people.csv", csv.clone()).await;
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&csv).unwrap();
    put(&app, "people.csv.gz", gz.finish().unwrap()).await;
    let sql = "SELECT s.name FROM S3Object s WHERE CAST(s.age AS INT) > 40";
    let plain = select(&app, "people.csv", &request(sql, CSV_USE, "<CSV/>"), None).await;
    assert_eq!(plain.status, 200);
    assert_eq!(plain.records, "Alan\nGrace\n");
    assert_eq!(plain.events, ["Records", "Stats", "End"]);
    assert!(
        plain.stats.contains("<BytesScanned>33</BytesScanned>"),
        "{}",
        plain.stats
    );
    assert!(
        plain.stats.contains("<BytesReturned>11</BytesReturned>"),
        "{}",
        plain.stats
    );
    let gzipped = request(
        sql,
        "<CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV><CompressionType>GZIP</CompressionType>",
        "<JSON/>",
    );
    let answer = select(&app, "people.csv.gz", &gzipped, None).await;
    assert_eq!(
        answer.records,
        "{\"name\":\"Alan\"}\n{\"name\":\"Grace\"}\n"
    );
    assert!(answer.stats.contains("<BytesProcessed>33</BytesProcessed>"));
    // Not gzip: an error event, once the response has started.
    let answer = select(&app, "people.csv", &gzipped, None).await;
    assert_eq!(answer.events, ["InvalidCompressionFormat"]);
}

#[tokio::test]
async fn streams_a_large_object() {
    let Some(app) = node().await else { return };
    let mut csv = b"n\n".to_vec();
    for i in 0..400_000 {
        csv.extend_from_slice(format!("{i}\n").as_bytes());
    }
    let size = csv.len();
    put_sized(&app, "big.csv", csv).await;
    let count = request(
        "SELECT COUNT(*), SUM(CAST(n AS INT)) FROM S3Object",
        CSV_USE,
        "<CSV/>",
    );
    let answer = select(&app, "big.csv", &count, None).await;
    assert_eq!(answer.records, "400000,79999800000\n");
    assert!(
        answer
            .stats
            .contains(&format!("<BytesScanned>{size}</BytesScanned>"))
    );
    // A LIMIT stops reading.
    let limited = request("SELECT * FROM S3Object LIMIT 2", CSV_USE, "<CSV/>");
    let answer = select(&app, "big.csv", &limited, None).await;
    assert_eq!(answer.records, "0\n1\n");
    assert!(
        !answer
            .stats
            .contains(&format!("<BytesScanned>{size}</BytesScanned>"))
    );
}

#[tokio::test]
async fn selects_from_json_lines() {
    let Some(app) = node().await else { return };
    let json = b"{\"id\":1,\"user\":{\"name\":\"x\"}}\n{\"id\":2,\"user\":{\"name\":\"y\"}}\n";
    put(&app, "events.json", json.to_vec()).await;
    let body = request(
        "SELECT s.user.name AS n FROM S3Object[*] s WHERE s.id = 2",
        "<JSON><Type>LINES</Type></JSON>",
        "<JSON/>",
    );
    let answer = select(&app, "events.json", &body, None).await;
    assert_eq!(answer.records, "{\"n\":\"y\"}\n");
    assert_eq!(answer.events, ["Records", "Stats", "End"]);
}

#[tokio::test]
async fn reads_only_what_a_read_may() {
    let Some(app) = node().await else { return };
    let body = request("SELECT * FROM S3Object", "<CSV/>", "<CSV/>");
    // Not there.
    assert_eq!(select(&app, "nope.csv", &body, None).await.status, 404);
    // SSE-C: only with its key.
    let customer = customer_key(&[7; 32]);
    put_sealed(&app, "sealed.csv", b"a,b\n".to_vec(), &customer).await;
    let refused = select(&app, "sealed.csv", &body, None).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST.as_u16());
    let answer = select(&app, "sealed.csv", &body, Some(&customer)).await;
    assert_eq!(answer.records, "a,b\n");
}

#[tokio::test]
async fn refuses_what_it_does_not_take() {
    let Some(app) = node().await else { return };
    put(&app, "x.csv", b"1\n".to_vec()).await;
    let parquet = request("SELECT * FROM S3Object", "<Parquet/>", "<CSV/>");
    assert_eq!(select(&app, "x.csv", &parquet, None).await.status, 501);
    let bad_sql = request("SELECT FROM S3Object", "<CSV/>", "<CSV/>");
    assert_eq!(select(&app, "x.csv", &bad_sql, None).await.status, 400);
    let failing = request("SELECT CAST(_1 AS BOOL) FROM S3Object", "<CSV/>", "<CSV/>");
    assert_eq!(
        select(&app, "x.csv", &failing, None).await.events,
        ["CastFailed"]
    );
}

/// `request`'s, with a `<ScanRange>` of `range`.
fn ranged(sql: &str, input: &str, range: &str) -> Vec<u8> {
    let body = String::from_utf8(request(sql, input, "<CSV/>")).unwrap();
    body.replace(
        "<InputSerialization>",
        &format!("<ScanRange>{range}</ScanRange><InputSerialization>"),
    )
    .into_bytes()
}

#[tokio::test]
async fn scan_ranges_split_an_object_as_awswrangler_does() {
    let Some(app) = node().await else { return };
    let mut csv = b"n,label\n".to_vec();
    for i in 0..20_000 {
        csv.extend_from_slice(format!("{i},row {i}\n").as_bytes());
    }
    let size = csv.len() as u64;
    put_sized(&app, "split.csv", csv).await;
    let sql = "SELECT s.n FROM S3Object s";
    let whole = select(&app, "split.csv", &request(sql, CSV_USE, "<CSV/>"), None).await;
    assert_eq!(whole.records.lines().count(), 20_000);
    // Consecutive ranges of 64 KiB, each read by its own request: every
    // range past the first reads the header from the object's start.
    let chunk = 64 * 1024;
    let mut split = String::new();
    for start in (0..size).step_by(chunk) {
        let end = (start + chunk as u64 - 1).min(size - 1);
        let range = format!("<Start>{start}</Start><End>{end}</End>");
        let answer = select(&app, "split.csv", &ranged(sql, CSV_USE, &range), None).await;
        assert_eq!(answer.events, ["Records", "Stats", "End"], "{range}");
        split += &answer.records;
    }
    assert_eq!(split, whole.records);
    // The last bytes: the last record ("19999,row 19999\n", 16 bytes) if
    // its first byte is in them.
    for (range, want) in [("<End>16</End>", "19999\n"), ("<End>15</End>", "")] {
        let last = select(&app, "split.csv", &ranged(sql, CSV_USE, range), None).await;
        assert_eq!(last.records, want, "{range}");
    }
    // Past the end: no records, but an answer.
    let past = format!("<Start>{size}</Start>");
    let count = "SELECT COUNT(*) FROM S3Object";
    let answer = select(&app, "split.csv", &ranged(count, CSV_USE, &past), None).await;
    assert_eq!(answer.records, "0\n");
    assert_eq!(answer.events, ["Records", "Stats", "End"]);
}

#[tokio::test]
async fn scan_ranges_of_json_lines() {
    let Some(app) = node().await else { return };
    let json = b"{\"id\":1}\n{\"id\":2}\n{\"id\":3}\n";
    put(&app, "ids.json", json.to_vec()).await;
    let lines = "<JSON><Type>LINES</Type></JSON>";
    let sql = "SELECT s.id FROM S3Object s";
    // "{\"id\":2}\n" is bytes 9 to 17.
    for (range, want) in [
        ("<Start>9</Start><End>9</End>", "2\n"),
        ("<Start>10</Start><End>18</End>", "3\n"),
        ("<Start>0</Start><End>8</End>", "1\n"),
    ] {
        let answer = select(&app, "ids.json", &ranged(sql, lines, range), None).await;
        assert_eq!(answer.records, want, "{range}");
    }
    let gzip = "<JSON><Type>LINES</Type></JSON><CompressionType>GZIP</CompressionType>";
    let refused = ranged(sql, gzip, "<Start>1</Start>");
    assert_eq!(select(&app, "ids.json", &refused, None).await.status, 400);
}

#[tokio::test]
async fn filters_and_formats_timestamps() {
    let Some(app) = node().await else { return };
    let log = b"time,level\n\
        2024-03-01T10:15:00Z,INFO\n\
        2024-03-01T11:45:30.250+01:00,WARN\n\
        2024-03-02T08:00:00-05:00,ERROR\n";
    put(&app, "log.csv", log.to_vec()).await;
    let sql = "SELECT TO_STRING(TO_TIMESTAMP(s.time), 'MMM d HH:mm X') AS at, s.level \
               FROM S3Object s \
               WHERE TO_TIMESTAMP(s.time) >= `2024-03-01T10:30Z` \
               AND DATE_DIFF(hour, TO_TIMESTAMP(s.time), UTCNOW()) > 0";
    let answer = select(&app, "log.csv", &request(sql, CSV_USE, "<CSV/>"), None).await;
    // 11:45 at +01:00 is 10:45 UTC: in.
    assert_eq!(
        answer.records,
        "Mar 1 11:45 +01,WARN\nMar 2 08:00 -05,ERROR\n"
    );
    let sql = "SELECT MIN(TO_TIMESTAMP(s.time)), MAX(EXTRACT(day FROM s.time)) FROM S3Object s";
    let answer = select(&app, "log.csv", &request(sql, CSV_USE, "<JSON/>"), None).await;
    assert_eq!(
        answer.records,
        "{\"_1\":\"2024-03-01T10:15:00Z\",\"_2\":2}\n"
    );
}
