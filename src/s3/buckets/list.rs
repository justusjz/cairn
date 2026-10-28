use http_body_util::Full;
use hyper::{Response, body::Bytes};

use crate::{
    App,
    roles::Principal,
    s3::util::{Timestamp, timestamp_sql, xml_escape, xml_ok},
    s3::versions::Versioning,
};

pub struct BucketInfo {
    pub name: String,
    pub created_at: Timestamp,
    pub versioning: Versioning,
}

/// Every bucket, by name. Shared by ListBuckets and the dashboard.
pub async fn buckets(app: &App) -> anyhow::Result<Vec<BucketInfo>> {
    let client = app.pool.get().await?;
    let rows = client
        .query(
            &format!(
                "SELECT name, versioning, {} FROM buckets ORDER BY name",
                timestamp_sql("created_at")
            ),
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| BucketInfo {
            name: r.get(0),
            versioning: Versioning::from_db(r.get(1)),
            created_at: Timestamp {
                iso: r.get(2),
                epoch: r.get(3),
            },
        })
        .collect())
}

/// ListBuckets: `GET /`. Lists the buckets the role can see: every bucket for an
/// admin, otherwise only those it holds a grant on.
pub async fn list_buckets(
    app: &App,
    principal: &Principal,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let mut body = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <ListAllMyBucketsResult><Owner><ID>cairn</ID>\
             <DisplayName>cairn</DisplayName></Owner><Buckets>",
    );
    for bucket in buckets(app).await? {
        if !principal.can_see(&bucket.name) {
            continue;
        }
        body.push_str(&format!(
            "<Bucket><Name>{}</Name><CreationDate>{}</CreationDate></Bucket>",
            xml_escape(&bucket.name),
            bucket.created_at.iso
        ));
    }
    body.push_str("</Buckets></ListAllMyBucketsResult>");
    Ok(xml_ok(body))
}
