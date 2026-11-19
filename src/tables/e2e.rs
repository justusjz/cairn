//! S3 Tables against a real Postgres: table buckets, namespaces and tables,
//! what's kept and refused, and who may do what, by identity policies and
//! the buckets' and tables' own.

use std::sync::Arc;

use hyper::{HeaderMap, Method, StatusCode};
use serde_json::{Value, json};

use super::{Answer, Ctx};
use crate::{
    App,
    e2e::node_with,
    packer,
    s3::access::{Access, Origin},
    users::{self, Principal},
};

async fn node() -> Option<Arc<App>> {
    node_with(packer::Config::default(), None).await
}

/// A user named `name` (made unique), with the identity policy
/// `statements` (none, if empty).
async fn user(app: &App, name: &str, statements: &str) -> Principal {
    let client = app.pool.get().await.unwrap();
    let account = users::account(&client).await.unwrap();
    let name = format!("{name}-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let (key, _) = users::create_for(&client, &account, &name, None, false)
        .await
        .unwrap();
    if !statements.is_empty() {
        let policy = format!(r#"{{"Version":"2012-10-17","Statement":[{statements}]}}"#);
        users::put_policy(&client, &account, &name, "p", &policy)
            .await
            .unwrap();
    }
    Principal::load(&client, &key).await.unwrap().unwrap()
}

const ADMIN: &str = r#"{"Effect":"Allow","Action":"s3tables:*","Resource":"*"}"#;

/// What `principal` was answered for `method` on `path` (with ARNs in it
/// as they are: they're encoded here), with `query` and `body`: its
/// status, and its body (`null` for none).
async fn call(
    app: &Arc<App>,
    principal: &Principal,
    method: Method,
    path: &str,
    query: &str,
    body: Value,
) -> (StatusCode, Value) {
    let origin = Origin {
        peer: None,
        trusted_proxies: &[],
        signed: None,
        form: false,
    };
    let mut access = Access::new(
        Some(principal),
        &principal.account,
        &method,
        &HeaderMap::new(),
        "",
        &origin,
    )
    .unwrap();
    let mut ctx = Ctx {
        app,
        client: app.pool.get().await.unwrap(),
        principal,
        access: &mut access,
        endpoint: None,
    };
    // Each segment encoded, an ARN (with its `/`s) as one.
    let mut segments = Vec::new();
    let mut parts = path.split('/').peekable();
    while let Some(part) = parts.next() {
        let mut segment = part.to_owned();
        if part.starts_with("arn:") {
            segment = format!("{segment}/{}", parts.next().unwrap());
            if parts.peek() == Some(&"table") {
                let table = parts.next().unwrap();
                segment = format!("{segment}/{table}/{}", parts.next().unwrap());
            }
        }
        segments.push(urlencode(&segment));
    }
    let path = segments.join("/");
    let body = match body {
        Value::Null => Vec::new(),
        body => body.to_string().into_bytes(),
    };
    match ctx.dispatch(&method, &path, query, &body).await {
        Ok(Answer::Json(value)) => (StatusCode::OK, value),
        Ok(Answer::NoContent) => (StatusCode::NO_CONTENT, Value::Null),
        Ok(Answer::Raw(status, body)) => (status, body.unwrap_or(Value::Null)),
        Err(e) => (e.status, json!({ "code": e.code, "message": e.message })),
    }
}

/// A fresh table bucket name.
fn bucket_name() -> String {
    format!("tb-{}", &uuid::Uuid::new_v4().simple().to_string()[..10])
}

/// Makes table bucket `name` as `principal`, and returns its ARN.
async fn bucket(app: &Arc<App>, principal: &Principal, name: &str) -> String {
    let (status, body) = call(
        app,
        principal,
        Method::PUT,
        "/buckets",
        "",
        json!({ "name": name }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["arn"].as_str().unwrap().to_owned()
}

/// Makes namespace `namespace` and table `table` in it, and returns the
/// table's ARN and version token.
async fn table(
    app: &Arc<App>,
    principal: &Principal,
    arn: &str,
    namespace: &str,
    table: &str,
) -> (String, String) {
    let (status, body) = call(
        app,
        principal,
        Method::PUT,
        &format!("/namespaces/{arn}"),
        "",
        json!({ "namespace": [namespace] }),
    )
    .await;
    assert!(
        status == StatusCode::OK || body["code"] == "ConflictException",
        "{body}"
    );
    let (status, body) = call(
        app,
        principal,
        Method::PUT,
        &format!("/tables/{arn}/{namespace}"),
        "",
        json!({ "name": table, "format": "ICEBERG" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    (
        body["tableARN"].as_str().unwrap().to_owned(),
        body["versionToken"].as_str().unwrap().to_owned(),
    )
}

#[tokio::test]
async fn buckets_namespaces_and_tables() {
    let Some(app) = node().await else { return };
    let admin = user(&app, "admin", ADMIN).await;
    let name = bucket_name();
    let arn = bucket(&app, &admin, &name).await;
    assert_eq!(arn, super::names::bucket_arn(&admin.account, &name));
    // Its name is taken, in this account.
    let (status, body) = call(
        &app,
        &admin,
        Method::PUT,
        "/buckets",
        "",
        json!({ "name": name }),
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::CONFLICT, Some("ConflictException"))
    );
    let (status, body) = call(
        &app,
        &admin,
        Method::PUT,
        "/buckets",
        "",
        json!({ "name": "aws-x" }),
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("BadRequestException"))
    );
    let (status, body) = call(
        &app,
        &admin,
        Method::GET,
        &format!("/buckets/{arn}"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], json!(name));
    assert_eq!(body["ownerAccountId"], json!(admin.account));
    assert_eq!(body["type"], "customer");
    let (_, body) = call(
        &app,
        &admin,
        Method::GET,
        "/buckets",
        &format!("prefix={name}"),
        Value::Null,
    )
    .await;
    assert_eq!(body["tableBuckets"].as_array().unwrap().len(), 1);

    let (table_arn, token) = table(&app, &admin, &arn, "sales", "orders").await;
    assert!(table_arn.starts_with(&format!("{arn}/table/")));
    let (status, got) = call(
        &app,
        &admin,
        Method::GET,
        "/get-table",
        &format!("tableArn={}", urlencode(&table_arn)),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(got["name"], "orders");
    assert_eq!(got["namespace"], json!(["sales"]));
    assert_eq!(got["versionToken"], json!(token));
    assert!(got.get("metadataLocation").is_none());
    let warehouse = got["warehouseLocation"].as_str().unwrap().to_owned();
    assert!(warehouse.starts_with("s3://") && warehouse.ends_with("--table-s3"));
    assert_eq!(warehouse.len(), "s3://".len() + 63);
    let base = format!("/tables/{arn}/sales/orders");

    // The pointer, swapped against its token.
    let location = format!("{warehouse}/metadata/00000-a.metadata.json");
    let (status, body) = call(
        &app,
        &admin,
        Method::PUT,
        &format!("{base}/metadata-location"),
        "",
        json!({ "versionToken": "stale", "metadataLocation": location }),
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::CONFLICT, Some("ConflictException"))
    );
    let (status, _) = call(
        &app,
        &admin,
        Method::PUT,
        &format!("{base}/metadata-location"),
        "",
        json!({ "versionToken": token, "metadataLocation": "s3://elsewhere/m.metadata.json" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, updated) = call(
        &app,
        &admin,
        Method::PUT,
        &format!("{base}/metadata-location"),
        "",
        json!({ "versionToken": token, "metadataLocation": location }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    let token2 = updated["versionToken"].as_str().unwrap().to_owned();
    assert_ne!(token2, token);
    let (_, got) = call(
        &app,
        &admin,
        Method::GET,
        &format!("{base}/metadata-location"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(got["metadataLocation"], json!(location));
    assert_eq!(got["versionToken"], json!(token2));
    // The old token is stale now.
    let (status, _) = call(
        &app,
        &admin,
        Method::PUT,
        &format!("{base}/metadata-location"),
        "",
        json!({ "versionToken": token, "metadataLocation": location }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Listed, by namespace too; a table's name is unique in its namespace.
    let (_, list) = call(
        &app,
        &admin,
        Method::GET,
        &format!("/tables/{arn}"),
        "namespace=sales",
        Value::Null,
    )
    .await;
    assert_eq!(list["tables"].as_array().unwrap().len(), 1);
    assert_eq!(list["tables"][0]["tableARN"], json!(table_arn));
    let (status, _) = call(
        &app,
        &admin,
        Method::PUT,
        &format!("/tables/{arn}/sales"),
        "",
        json!({ "name": "orders", "format": "ICEBERG" }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Renamed into another namespace: the same table (ARN), elsewhere.
    let (status, _) = call(
        &app,
        &admin,
        Method::PUT,
        &format!("{base}/rename"),
        "",
        json!({ "newNamespaceName": "archive", "newName": "old_orders" }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    call(
        &app,
        &admin,
        Method::PUT,
        &format!("/namespaces/{arn}"),
        "",
        json!({ "namespace": ["archive"] }),
    )
    .await;
    let (status, body) = call(
        &app,
        &admin,
        Method::PUT,
        &format!("{base}/rename"),
        "",
        json!({ "newNamespaceName": "archive", "newName": "old_orders", "versionToken": token2 }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, _) = call(
        &app,
        &admin,
        Method::GET,
        &format!("{base}/metadata-location"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let moved = format!("/tables/{arn}/archive/old_orders");
    let (_, got) = call(
        &app,
        &admin,
        Method::GET,
        "/get-table",
        &format!(
            "tableBucketARN={}&namespace=archive&name=old_orders",
            urlencode(&arn)
        ),
        Value::Null,
    )
    .await;
    assert_eq!(got["tableARN"], json!(table_arn));
    assert_eq!(got["metadataLocation"], json!(location));

    // Deleting: a bucket or namespace with something in it can't be.
    let (status, _) = call(
        &app,
        &admin,
        Method::DELETE,
        &format!("/namespaces/{arn}/archive"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = call(
        &app,
        &admin,
        Method::DELETE,
        &format!("/buckets/{arn}"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = call(
        &app,
        &admin,
        Method::DELETE,
        &moved,
        "versionToken=stale",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = call(&app, &admin, Method::DELETE, &moved, "", Value::Null).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    for namespace in ["sales", "archive"] {
        let (status, _) = call(
            &app,
            &admin,
            Method::DELETE,
            &format!("/namespaces/{arn}/{namespace}"),
            "",
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
    let (status, _) = call(
        &app,
        &admin,
        Method::DELETE,
        &format!("/buckets/{arn}"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = call(
        &app,
        &admin,
        Method::GET,
        &format!("/buckets/{arn}"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("NotFoundException"))
    );
}

fn urlencode(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

#[tokio::test]
async fn listings_page() {
    let Some(app) = node().await else { return };
    let admin = user(&app, "admin", ADMIN).await;
    let arn = bucket(&app, &admin, &bucket_name()).await;
    for (namespace, name) in [
        ("a", "t1"),
        ("a", "t2"),
        ("b", "t1"),
        ("b", "t3"),
        ("c", "t1"),
    ] {
        table(&app, &admin, &arn, namespace, name).await;
    }
    let mut seen = Vec::new();
    let mut query = "maxTables=2".to_owned();
    loop {
        let (status, page) = call(
            &app,
            &admin,
            Method::GET,
            &format!("/tables/{arn}"),
            &query,
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        for t in page["tables"].as_array().unwrap() {
            seen.push(format!(
                "{}.{}",
                t["namespace"][0].as_str().unwrap(),
                t["name"].as_str().unwrap()
            ));
        }
        match page["continuationToken"].as_str() {
            Some(token) => query = format!("maxTables=2&continuationToken={token}"),
            None => break,
        }
    }
    assert_eq!(seen, ["a.t1", "a.t2", "b.t1", "b.t3", "c.t1"]);
    let (_, page) = call(
        &app,
        &admin,
        Method::GET,
        &format!("/tables/{arn}"),
        "prefix=t1",
        Value::Null,
    )
    .await;
    assert_eq!(page["tables"].as_array().unwrap().len(), 3);
    let (_, page) = call(
        &app,
        &admin,
        Method::GET,
        &format!("/namespaces/{arn}"),
        "maxNamespaces=2",
        Value::Null,
    )
    .await;
    assert_eq!(page["namespaces"].as_array().unwrap().len(), 2);
    assert!(page["continuationToken"].is_string());
    let (status, _) = call(
        &app,
        &admin,
        Method::GET,
        &format!("/tables/{arn}"),
        "maxTables=0",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn identity_policies_decide() {
    let Some(app) = node().await else { return };
    let admin = user(&app, "admin", ADMIN).await;
    let name = bucket_name();
    let arn = bucket(&app, &admin, &name).await;
    let (table_arn, _) = table(&app, &admin, &arn, "sales", "orders").await;
    table(&app, &admin, &arn, "hr", "salaries").await;

    // Nothing allowed: denied, saying why; even what isn't there.
    let nobody = user(&app, "nobody", "").await;
    let (status, body) = call(
        &app,
        &nobody,
        Method::GET,
        &format!("/buckets/{arn}"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "AccessDeniedException");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("s3tables:GetTableBucket"),
        "{body}"
    );
    let (status, _) = call(
        &app,
        &nobody,
        Method::GET,
        &format!("/tables/{arn}/sales/nope/metadata-location"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A namespace's tables only, by `s3tables:namespace`.
    let sales = user(
        &app,
        "sales",
        &format!(
            r#"{{"Effect":"Allow","Action":["s3tables:GetTableMetadataLocation","s3tables:ListTables"],"Resource":["{arn}","{arn}/table/*"],
                "Condition":{{"StringEquals":{{"s3tables:namespace":"sales"}}}}}}"#
        ),
    )
    .await;
    let (status, _) = call(
        &app,
        &sales,
        Method::GET,
        &format!("/tables/{arn}/sales/orders/metadata-location"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(
        &app,
        &sales,
        Method::GET,
        &format!("/tables/{arn}/hr/salaries/metadata-location"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call(
        &app,
        &sales,
        Method::GET,
        &format!("/tables/{arn}"),
        "namespace=sales",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(
        &app,
        &sales,
        Method::GET,
        &format!("/tables/{arn}"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // One table, by its ARN and `s3tables:tableName`.
    let one = user(
        &app,
        "one",
        &format!(r#"{{"Effect":"Allow","Action":"s3tables:GetTable","Resource":"{table_arn}"}}"#),
    )
    .await;
    let (status, _) = call(
        &app,
        &one,
        Method::GET,
        "/get-table",
        &format!("tableArn={}", urlencode(&table_arn)),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(
        &app,
        &one,
        Method::GET,
        "/get-table",
        &format!(
            "tableBucketARN={}&namespace=hr&name=salaries",
            urlencode(&arn)
        ),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Tagging needs its request tags allowed.
    let tagger = user(
        &app,
        "tagger",
        &format!(
            r#"{{"Effect":"Allow","Action":"s3tables:TagResource","Resource":"{arn}",
                "Condition":{{"ForAllValues:StringEquals":{{"aws:TagKeys":["team"]}}}}}}"#
        ),
    )
    .await;
    let (status, _) = call(
        &app,
        &tagger,
        Method::POST,
        &format!("/tag/{arn}"),
        "",
        json!({ "tags": { "team": "data" } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(
        &app,
        &tagger,
        Method::POST,
        &format!("/tag/{arn}"),
        "",
        json!({ "tags": { "cost": "x" } }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (_, tags) = call(
        &app,
        &admin,
        Method::GET,
        &format!("/tag/{arn}"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(tags["tags"], json!({ "team": "data" }));

    // The bucket's tags are its tables' `s3tables:TableBucketTag`s.
    let by_tag = user(
        &app,
        "bytag",
        r#"{"Effect":"Allow","Action":"s3tables:GetTable","Resource":"*",
            "Condition":{"StringEquals":{"s3tables:TableBucketTag/team":"data"}}}"#,
    )
    .await;
    let (status, _) = call(
        &app,
        &by_tag,
        Method::GET,
        "/get-table",
        &format!("tableArn={}", urlencode(&table_arn)),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(
        &app,
        &admin,
        Method::DELETE,
        &format!("/tag/{arn}"),
        "tagKeys=team",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = call(
        &app,
        &by_tag,
        Method::GET,
        "/get-table",
        &format!("tableArn={}", urlencode(&table_arn)),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn resource_policies_decide() {
    let Some(app) = node().await else { return };
    let admin = user(&app, "admin", ADMIN).await;
    let arn = bucket(&app, &admin, &bucket_name()).await;
    let (table_arn, _) = table(&app, &admin, &arn, "sales", "orders").await;
    let base = format!("/tables/{arn}/sales/orders");
    let reader = user(&app, "reader", "").await;
    let reader_arn = reader.arn();

    // The bucket's policy allows a user what its own policies don't.
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{reader_arn}"}},
            "Action":"s3tables:GetTableMetadataLocation","Resource":"{arn}/table/*"}}]}}"#
    );
    let (status, body) = call(
        &app,
        &admin,
        Method::PUT,
        &format!("/buckets/{arn}/policy"),
        "",
        json!({ "resourcePolicy": policy }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = call(
        &app,
        &reader,
        Method::GET,
        &format!("{base}/metadata-location"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, got) = call(
        &app,
        &admin,
        Method::GET,
        &format!("/buckets/{arn}/policy"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got["resourcePolicy"], json!(policy));

    // The table's policy denies it.
    let deny = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Principal":"*",
            "Action":"s3tables:*","Resource":"{table_arn}"}}]}}"#
    );
    let (status, body) = call(
        &app,
        &admin,
        Method::PUT,
        &format!("{base}/policy"),
        "",
        json!({ "resourcePolicy": deny }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = call(
        &app,
        &reader,
        Method::GET,
        &format!("{base}/metadata-location"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // And everyone, the admin too: it can't take it back. Its root can't
    // be locked out by identity policies, but a Deny in the table's policy
    // holds for it too, as in AWS.
    let (status, _) = call(
        &app,
        &admin,
        Method::DELETE,
        &format!("{base}/policy"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Not a policy of S3 Tables': other services' actions, other resources,
    // or public.
    for bad in [
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{reader_arn}"}},"Action":"s3:GetObject","Resource":"{arn}"}}]}}"#
        ),
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{reader_arn}"}},"Action":"s3tables:GetTable","Resource":"arn:aws:s3tables:us-east-1:{}:bucket/other"}}]}}"#,
            admin.account
        ),
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{reader_arn}"}},"Action":"s3tables:GetTable","Resource":"{arn}","Condition":{{"StringEquals":{{"s3tables:nope":"x"}}}}}}]}}"#
        ),
    ] {
        let (status, body) = call(
            &app,
            &admin,
            Method::PUT,
            &format!("/buckets/{arn}/policy"),
            "",
            json!({ "resourcePolicy": bad }),
        )
        .await;
        assert_eq!(
            (status, body["code"].as_str()),
            (StatusCode::BAD_REQUEST, Some("BadRequestException")),
            "{bad}"
        );
    }
    let public = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":"*","Action":"s3tables:GetTable","Resource":"{arn}/table/*"}}]}}"#
    );
    let (status, _) = call(
        &app,
        &admin,
        Method::PUT,
        &format!("/buckets/{arn}/policy"),
        "",
        json!({ "resourcePolicy": public }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call(
        &app,
        &admin,
        Method::DELETE,
        &format!("/buckets/{arn}/policy"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = call(
        &app,
        &admin,
        Method::GET,
        &format!("/buckets/{arn}/policy"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn configurations() {
    let Some(app) = node().await else { return };
    let admin = user(&app, "admin", ADMIN).await;
    let name = bucket_name();
    let (status, body) = call(
        &app,
        &admin,
        Method::PUT,
        "/buckets",
        "",
        json!({ "name": name, "storageClassConfiguration": { "storageClass": "INTELLIGENT_TIERING" },
                "tags": { "team": "data" } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let arn = body["arn"].as_str().unwrap().to_owned();
    // Not a class the operator has defined: STANDARD, as an object's.
    let (_, class) = call(
        &app,
        &admin,
        Method::GET,
        &format!("/buckets/{arn}/storage-class"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(
        class["storageClassConfiguration"]["storageClass"],
        "STANDARD"
    );
    let (_, encryption) = call(
        &app,
        &admin,
        Method::GET,
        &format!("/buckets/{arn}/encryption"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(
        encryption["encryptionConfiguration"]["sseAlgorithm"],
        "AES256"
    );
    let (status, _) = call(
        &app,
        &admin,
        Method::PUT,
        &format!("/buckets/{arn}/encryption"),
        "",
        json!({ "encryptionConfiguration": { "sseAlgorithm": "aws:kms" } }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (_, maintenance) = call(
        &app,
        &admin,
        Method::GET,
        &format!("/buckets/{arn}/maintenance"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(
        maintenance["configuration"]["icebergUnreferencedFileRemoval"]["settings"]["icebergUnreferencedFileRemoval"],
        json!({ "unreferencedDays": 3, "nonCurrentDays": 10 })
    );
    let (status, _) = call(
        &app,
        &admin,
        Method::PUT,
        &format!("/buckets/{arn}/maintenance/icebergUnreferencedFileRemoval"),
        "",
        json!({ "value": { "status": "enabled", "settings": { "icebergUnreferencedFileRemoval": { "unreferencedDays": 5 } } } }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, maintenance) = call(
        &app,
        &admin,
        Method::GET,
        &format!("/buckets/{arn}/maintenance"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(
        maintenance["configuration"]["icebergUnreferencedFileRemoval"]["settings"]["icebergUnreferencedFileRemoval"],
        json!({ "unreferencedDays": 5, "nonCurrentDays": 10 })
    );

    let (table_arn, _) = table(&app, &admin, &arn, "sales", "orders").await;
    let base = format!("/tables/{arn}/sales/orders");
    let (_, tags) = call(
        &app,
        &admin,
        Method::GET,
        &format!("/tag/{table_arn}"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(tags["tags"], json!({}));
    let (_, maintenance) = call(
        &app,
        &admin,
        Method::GET,
        &format!("{base}/maintenance"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(
        maintenance["configuration"]["icebergCompaction"]["status"],
        "disabled"
    );
    assert_eq!(
        maintenance["configuration"]["icebergSnapshotManagement"]["status"],
        "enabled"
    );
    let (status, body) = call(
        &app,
        &admin,
        Method::PUT,
        &format!("{base}/maintenance/icebergCompaction"),
        "",
        json!({ "value": { "status": "enabled" } }),
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::NOT_IMPLEMENTED, Some("NotImplemented"))
    );
    let (status, _) = call(
        &app,
        &admin,
        Method::PUT,
        &format!("{base}/maintenance/icebergSnapshotManagement"),
        "",
        json!({ "value": { "status": "disabled" } }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, status) = call(
        &app,
        &admin,
        Method::GET,
        &format!("{base}/maintenance-job-status"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(
        status["status"]["icebergSnapshotManagement"]["status"],
        "Disabled"
    );
    assert_eq!(
        status["status"]["icebergUnreferencedFileRemoval"]["status"],
        "Not_Yet_Run"
    );

    // Metrics: kept, without effect.
    let (status, _) = call(
        &app,
        &admin,
        Method::GET,
        &format!("/buckets/{arn}/metrics"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(
        &app,
        &admin,
        Method::PUT,
        &format!("/buckets/{arn}/metrics"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = call(
        &app,
        &admin,
        Method::GET,
        &format!("/buckets/{arn}/metrics"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // What Cairn doesn't have.
    let (status, _) = call(
        &app,
        &admin,
        Method::GET,
        "/table-replication",
        &format!("tableArn={}", urlencode(&table_arn)),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    let (status, _) = call(
        &app,
        &admin,
        Method::GET,
        "/table-record-expiration",
        &format!("tableArn={}", urlencode(&table_arn)),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

// ─── Iceberg's REST catalog ─────────────────────────────────────────────────

/// A table's schema, as clients send it.
fn iceberg_schema() -> Value {
    json!({ "type": "struct", "schema-id": 0, "fields": [
        { "id": 1, "name": "id", "required": true, "type": "long" },
        { "id": 2, "name": "name", "required": false, "type": "string" },
    ]})
}

/// An append's updates: a snapshot (`id`, after `parent`), and main at it.
fn append(id: i64, parent: Option<i64>, sequence: i64) -> Value {
    json!([
        { "action": "add-snapshot", "snapshot": {
            "snapshot-id": id, "parent-snapshot-id": parent, "sequence-number": sequence,
            "timestamp-ms": 1_700_000_000_000i64 + id, "manifest-list": format!("s3://x/snap-{id}.avro"),
            "summary": { "operation": "append" }, "schema-id": 0 } },
        { "action": "set-snapshot-ref", "ref-name": "main", "type": "branch", "snapshot-id": id },
    ])
}

#[tokio::test]
async fn the_iceberg_catalog() {
    let Some(app) = node().await else { return };
    let admin = user(&app, "admin", ADMIN).await;
    let arn = bucket(&app, &admin, &bucket_name()).await;
    let v1 = format!("/iceberg/v1/{arn}");

    let (status, config) = call(
        &app,
        &admin,
        Method::GET,
        "/iceberg/v1/config",
        &format!("warehouse={}", urlencode(&arn)),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{config}");
    assert_eq!(config["overrides"]["prefix"], json!(urlencode(&arn)));
    assert!(
        config["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e == "POST /v1/{prefix}/tables/rename")
    );

    let (status, body) = call(
        &app,
        &admin,
        Method::POST,
        &format!("{v1}/namespaces"),
        "",
        json!({ "namespace": ["sales"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = call(
        &app,
        &admin,
        Method::POST,
        &format!("{v1}/namespaces"),
        "",
        json!({ "namespace": ["sales"] }),
    )
    .await;
    assert_eq!(
        (status, body["error"]["type"].as_str()),
        (StatusCode::CONFLICT, Some("AlreadyExistsException"))
    );
    let (status, body) = call(
        &app,
        &admin,
        Method::POST,
        &format!("{v1}/namespaces"),
        "",
        json!({ "namespace": ["a", "b"] }),
    )
    .await;
    assert_eq!(
        (status, body["error"]["type"].as_str()),
        (StatusCode::BAD_REQUEST, Some("BadRequestException"))
    );
    let (_, list) = call(
        &app,
        &admin,
        Method::GET,
        &format!("{v1}/namespaces"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(list["namespaces"], json!([["sales"]]));
    let (status, _) = call(
        &app,
        &admin,
        Method::HEAD,
        &format!("{v1}/namespaces/nope"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Created with its first metadata file, in its own storage.
    let (status, created) = call(
        &app,
        &admin,
        Method::POST,
        &format!("{v1}/namespaces/sales/tables"),
        "",
        json!({ "name": "orders", "schema": iceberg_schema(), "properties": { "owner": "me" } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let location = created["metadata-location"].as_str().unwrap().to_owned();
    assert!(
        location.contains("--table-s3/metadata/00000-"),
        "{location}"
    );
    assert_eq!(created["metadata"]["format-version"], 2);
    assert_eq!(created["metadata"]["properties"]["owner"], "me");
    let (status, body) = call(
        &app,
        &admin,
        Method::POST,
        &format!("{v1}/namespaces/sales/tables"),
        "",
        json!({ "name": "orders", "schema": iceberg_schema() }),
    )
    .await;
    assert_eq!(
        (status, body["error"]["type"].as_str()),
        (StatusCode::CONFLICT, Some("AlreadyExistsException"))
    );
    let (status, body) = call(
        &app,
        &admin,
        Method::POST,
        &format!("{v1}/namespaces/sales/tables"),
        "",
        json!({ "name": "staged", "schema": iceberg_schema(), "stage-create": true }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    // The s3tables API sees the same table.
    let (_, pointer) = call(
        &app,
        &admin,
        Method::GET,
        &format!("/tables/{arn}/sales/orders/metadata-location"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(pointer["metadataLocation"], json!(location));

    // Loaded: the file it points at.
    let table = format!("{v1}/namespaces/sales/tables/orders");
    let (status, loaded) = call(&app, &admin, Method::GET, &table, "", Value::Null).await;
    assert_eq!(status, StatusCode::OK, "{loaded}");
    assert_eq!(
        loaded["metadata"]["table-uuid"],
        created["metadata"]["table-uuid"]
    );

    // Commits, against requirements.
    let uuid = loaded["metadata"]["table-uuid"].clone();
    let first = json!({
        "requirements": [{ "type": "assert-table-uuid", "uuid": uuid }, { "type": "assert-ref-snapshot-id", "ref": "main", "snapshot-id": null }],
        "updates": append(10, None, 1),
    });
    let (status, committed) = call(&app, &admin, Method::POST, &table, "", first.clone()).await;
    assert_eq!(status, StatusCode::OK, "{committed}");
    assert!(
        committed["metadata-location"]
            .as_str()
            .unwrap()
            .contains("/metadata/00001-")
    );
    assert_eq!(committed["metadata"]["current-snapshot-id"], 10);
    assert_eq!(
        committed["metadata"]["metadata-log"][0]["metadata-file"],
        json!(location)
    );
    // The same commit again: its requirement doesn't hold any more.
    let (status, body) = call(&app, &admin, Method::POST, &table, "", first).await;
    assert_eq!(
        (status, body["error"]["type"].as_str()),
        (StatusCode::CONFLICT, Some("CommitFailedException"))
    );
    let (status, body) = call(&app, &admin, Method::POST, &table, "", json!({ "requirements": [], "updates": [{ "action": "set-location", "location": "s3://elsewhere" }] })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // Who may: loading needs GetTableData too, committing PutTableData.
    let pointer_only = user(&app, "pointer", r#"{"Effect":"Allow","Action":["s3tables:GetTableMetadataLocation","s3tables:UpdateTableMetadataLocation"],"Resource":"*"}"#).await;
    let (status, body) = call(&app, &pointer_only, Method::GET, &table, "", Value::Null).await;
    assert_eq!(
        (status, body["error"]["type"].as_str()),
        (StatusCode::FORBIDDEN, Some("ForbiddenException"))
    );
    let reader = user(&app, "reader", r#"{"Effect":"Allow","Action":["s3tables:GetTableMetadataLocation","s3tables:GetTableData","s3tables:UpdateTableMetadataLocation"],"Resource":"*"}"#).await;
    let (status, _) = call(&app, &reader, Method::GET, &table, "", Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(
        &app,
        &reader,
        Method::POST,
        &table,
        "",
        json!({ "requirements": [], "updates": append(11, Some(10), 2) }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Listed, renamed, dropped (purged only).
    let (_, tables) = call(
        &app,
        &admin,
        Method::GET,
        &format!("{v1}/namespaces/sales/tables"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(
        tables["identifiers"],
        json!([{ "namespace": ["sales"], "name": "orders" }])
    );
    let (status, _) = call(
        &app,
        &admin,
        Method::GET,
        &format!("{v1}/namespaces/nope/tables"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = call(
        &app,
        &admin,
        Method::POST,
        &format!("{v1}/tables/rename"),
        "",
        json!({ "source": { "namespace": ["sales"], "name": "orders" }, "destination": { "namespace": ["sales"], "name": "orders2" } }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = call(&app, &admin, Method::GET, &table, "", Value::Null).await;
    assert_eq!(
        (status, body["error"]["type"].as_str()),
        (StatusCode::NOT_FOUND, Some("NoSuchTableException"))
    );
    let renamed = format!("{v1}/namespaces/sales/tables/orders2");
    let (status, _) = call(&app, &admin, Method::DELETE, &renamed, "", Value::Null).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = call(
        &app,
        &admin,
        Method::DELETE,
        &format!("{v1}/namespaces/sales"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(
        (status, body["error"]["type"].as_str()),
        (StatusCode::CONFLICT, Some("NamespaceNotEmptyException"))
    );
    let (status, _) = call(
        &app,
        &admin,
        Method::DELETE,
        &renamed,
        "purgeRequested=true",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = call(
        &app,
        &admin,
        Method::DELETE,
        &format!("{v1}/namespaces/sales"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = call(
        &app,
        &admin,
        Method::GET,
        &format!("{v1}/namespaces/x/views"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(
        (status, body["error"]["type"].as_str()),
        (
            StatusCode::NOT_ACCEPTABLE,
            Some("UnsupportedOperationException")
        )
    );
}

#[tokio::test]
async fn racing_commits() {
    let Some(app) = node().await else { return };
    let admin = user(&app, "admin", ADMIN).await;
    let arn = bucket(&app, &admin, &bucket_name()).await;
    let v1 = format!("/iceberg/v1/{arn}");
    call(
        &app,
        &admin,
        Method::POST,
        &format!("{v1}/namespaces"),
        "",
        json!({ "namespace": ["n"] }),
    )
    .await;
    let (status, _) = call(
        &app,
        &admin,
        Method::POST,
        &format!("{v1}/namespaces/n/tables"),
        "",
        json!({ "name": "t", "schema": iceberg_schema() }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let table = format!("{v1}/namespaces/n/tables/t");
    let admin = Arc::new(admin);
    // Many writers that each saw no snapshot: one wins.
    let commits = (0..8).map(|i| {
        let (app, admin, table) = (app.clone(), admin.clone(), table.clone());
        tokio::spawn(async move {
            call(&app, &admin, Method::POST, &table, "", json!({
                "requirements": [{ "type": "assert-ref-snapshot-id", "ref": "main", "snapshot-id": null }],
                "updates": append(100 + i, None, 1),
            }))
            .await
            .0
        })
    });
    let mut won = 0;
    for commit in commits {
        match commit.await.unwrap() {
            StatusCode::OK => won += 1,
            status => assert_eq!(status, StatusCode::CONFLICT),
        }
    }
    assert_eq!(won, 1);
    let (_, loaded) = call(&app, &admin, Method::GET, &table, "", Value::Null).await;
    assert_eq!(loaded["metadata"]["snapshots"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn create_table_with_metadata() {
    let Some(app) = node().await else { return };
    let admin = user(&app, "admin", ADMIN).await;
    let arn = bucket(&app, &admin, &bucket_name()).await;
    call(
        &app,
        &admin,
        Method::PUT,
        &format!("/namespaces/{arn}"),
        "",
        json!({ "namespace": ["n"] }),
    )
    .await;
    let (status, body) = call(
        &app,
        &admin,
        Method::PUT,
        &format!("/tables/{arn}/n"),
        "",
        json!({ "name": "t", "format": "ICEBERG", "metadata": { "iceberg": { "schema": { "fields": [
            { "name": "id", "type": "long", "required": true }, { "name": "at", "type": "timestamp" },
        ]}}}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, pointer) = call(
        &app,
        &admin,
        Method::GET,
        &format!("/tables/{arn}/n/t/metadata-location"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(pointer["versionToken"], body["versionToken"]);
    assert!(
        pointer["metadataLocation"]
            .as_str()
            .unwrap()
            .ends_with(".metadata.json")
    );
    let (_, loaded) = call(
        &app,
        &admin,
        Method::GET,
        &format!("/iceberg/v1/{arn}/namespaces/n/tables/t"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(loaded["metadata"]["schemas"][0]["fields"][1]["name"], "at");
    // A schema that isn't one: refused, and no table is left behind.
    let (status, _) = call(
        &app,
        &admin,
        Method::PUT,
        &format!("/tables/{arn}/n"),
        "",
        json!({ "name": "bad", "format": "ICEBERG", "metadata": { "iceberg": {} } }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(
        &app,
        &admin,
        Method::GET,
        &format!("/tables/{arn}/n/bad/metadata-location"),
        "",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
