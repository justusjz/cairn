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
