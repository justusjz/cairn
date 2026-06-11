use http_body_util::Full;
use hyper::{Response, body::Bytes};

use crate::{
    App,
    s3::util::{xml_escape, xml_ok},
};

pub async fn list_buckets(app: &App) -> anyhow::Result<Response<Full<Bytes>>> {
    let client = app.pool.get().await?;
    let rows = client
        .query(
            "SELECT name, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')
             FROM buckets ORDER BY name",
            &[],
        )
        .await?;
    let mut body = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <ListAllMyBucketsResult><Owner><ID>cairn</ID>\
             <DisplayName>cairn</DisplayName></Owner><Buckets>",
    );
    for r in &rows {
        let name: String = r.get(0);
        let created: String = r.get(1);
        body.push_str(&format!(
            "<Bucket><Name>{}</Name><CreationDate>{}</CreationDate></Bucket>",
            xml_escape(&name),
            created
        ));
    }
    body.push_str("</Buckets></ListAllMyBucketsResult>");
    Ok(xml_ok(body))
}
