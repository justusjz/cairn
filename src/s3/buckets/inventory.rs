//! A bucket's inventory configurations: PutBucketInventoryConfiguration,
//! GetBucketInventoryConfiguration, DeleteBucketInventoryConfiguration
//! (`?inventory&id=`) and ListBucketInventoryConfigurations (`?inventory`).
//! What a configuration is, is `inventory::config`'s; its reports,
//! `inventory`'s.

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use uuid::Uuid;

use crate::db::Cached;
use crate::{
    App,
    inventory::config::{Configuration, Encryption, Invalid, MAX_PER_BUCKET, valid_id},
    s3::util::{decode_continuation_token, encode_continuation_token, format_s3_error, query_param, xml_ok},
};

/// How many configurations ListBucketInventoryConfigurations answers at a
/// time, as S3.
const PAGE: i64 = 100;

/// The configuration a PutBucketInventoryConfiguration's body holds, as
/// policies may test it (`s3:InventoryAccessibleOptionalFields`): its
/// optional fields' names. `None` if it isn't one.
pub fn requested_fields(body: &[u8]) -> Option<Vec<String>> {
    let config = Configuration::parse(std::str::from_utf8(body).ok()?).ok()?;
    Some(config.fields.iter().map(|f| f.name().to_owned()).collect())
}

/// GetBucketInventoryConfiguration (`?inventory&id=`), or, without an ID,
/// ListBucketInventoryConfigurations.
pub async fn get(app: &App, bucket: &str, query: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let client = app.pool.get().await?;
    if client.query_opt_cached("SELECT 1 FROM buckets WHERE name = $1", &[&bucket]).await?.is_none() {
        return Ok(no_such_bucket());
    }
    let Some(id) = query_param(query, "id") else {
        return list(app, bucket, query).await;
    };
    let row = client
        .query_opt_cached("SELECT config FROM inventories WHERE bucket = $1 AND id = $2", &[&bucket, &id])
        .await?;
    let Some(row) = row else { return Ok(no_such_configuration()) };
    Ok(xml_ok(parse_stored(bucket, row.get(0))?.to_xml()))
}

/// ListBucketInventoryConfigurations: a page of the bucket's configurations,
/// by ID, after the one the continuation token names.
async fn list(app: &App, bucket: &str, query: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let token = query_param(query, "continuation-token");
    let after = match &token {
        None => String::new(),
        Some(token) => match decode_continuation_token(token) {
            Some(after) => after,
            None => {
                return Ok(format_s3_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidArgument",
                    "The continuation token provided is incorrect",
                ));
            }
        },
    };
    let rows = app
        .pool
        .get()
        .await?
        .query_cached(
            "SELECT id, config FROM inventories WHERE bucket = $1 AND id > $2 ORDER BY id LIMIT $3",
            &[&bucket, &after, &(PAGE + 1)],
        )
        .await?;
    let more = rows.len() as i64 > PAGE;
    let rows = &rows[..rows.len().min(PAGE as usize)];
    let configs = rows.iter().map(|row| parse_stored(bucket, row.get(1))).collect::<anyhow::Result<Vec<_>>>()?;
    let next = more.then(|| encode_continuation_token(rows.last().expect("a full page").get(0)));
    Ok(xml_ok(Configuration::list_xml(&configs, token.as_deref(), next.as_deref())))
}

/// PutBucketInventoryConfiguration: `PUT /{bucket}?inventory&id=` with an
/// `<InventoryConfiguration>` body of that ID. Replaces the configuration of
/// the ID, if there's one, and makes its next report due now. `setter` is
/// the user that sets it, as whom an SSE-KMS report asks the KMS for keys.
pub async fn put(
    app: &App,
    bucket: &str,
    query: &str,
    body: Bytes,
    setter: Option<Uuid>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let Some(id) = query_param(query, "id").filter(|id| !id.is_empty()) else {
        return Ok(invalid_argument("An inventory configuration needs an id"));
    };
    let parsed = std::str::from_utf8(&body)
        .map_err(|_| Invalid::Malformed("not UTF-8".to_owned()))
        .and_then(Configuration::parse);
    let config = match parsed {
        Ok(config) => config,
        Err(Invalid::Malformed(_)) => {
            return Ok(format_s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "The XML you provided was not well-formed or did not validate against our published schema",
            ));
        }
        Err(Invalid::Argument(why)) => return Ok(invalid_argument(&why)),
        Err(Invalid::Unsupported(why)) => {
            return Ok(format_s3_error(StatusCode::NOT_IMPLEMENTED, "NotImplemented", &why));
        }
    };
    if config.id != id {
        return Ok(invalid_argument("The inventory configuration's Id is not the id of the request"));
    }
    // Encrypted reports need the KMS, as encrypted writes do.
    match &config.destination.encryption {
        Some(Encryption::Kms(_)) if app.kms.is_none() => {
            return Ok(format_s3_error(
                StatusCode::NOT_IMPLEMENTED,
                "NotImplemented",
                "Server side encryption specified but KMS is not configured",
            ));
        }
        Some(Encryption::S3) if !app.kms.as_ref().is_some_and(|kms| kms.sse_s3_key().is_some()) => {
            return Ok(format_s3_error(
                StatusCode::NOT_IMPLEMENTED,
                "NotImplemented",
                "SSE-S3 needs a key of Cairn's own in the KMS (--kms-sse-s3-key)",
            ));
        }
        _ => {}
    }
    let status: String = app
        .pool
        .get()
        .await?
        .query_one_cached(
            "SELECT pg_temp.cairn_put_inventory($1, $2, $3, $4, $5, $6)",
            &[&bucket, &id, &config.to_json(), &config.enabled, &setter, &MAX_PER_BUCKET],
        )
        .await?
        .get(0);
    Ok(match status.as_str() {
        "set" => Response::builder().status(StatusCode::OK).body(Full::new(Bytes::new())).unwrap(),
        "too_many" => format_s3_error(
            StatusCode::BAD_REQUEST,
            "TooManyConfigurations",
            "You are attempting to create a new configuration but have already reached the 1,000-configuration limit.",
        ),
        "no_such_bucket" => no_such_bucket(),
        status => unreachable!("cairn_put_inventory: unknown status {status}"),
    })
}

/// DeleteBucketInventoryConfiguration: `DELETE /{bucket}?inventory&id=`.
/// A report of it in progress stops before its next data file.
pub async fn delete(app: &App, bucket: &str, query: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let Some(id) = query_param(query, "id").filter(|id| !id.is_empty()) else {
        return Ok(invalid_argument("An inventory configuration needs an id"));
    };
    let client = app.pool.get().await?;
    if client.query_opt_cached("SELECT 1 FROM buckets WHERE name = $1", &[&bucket]).await?.is_none() {
        return Ok(no_such_bucket());
    }
    let deleted = client
        .execute_cached("DELETE FROM inventories WHERE bucket = $1 AND id = $2", &[&bucket, &id])
        .await?;
    Ok(match deleted {
        0 if !valid_id(&id) => invalid_argument("The configuration ID is not valid"),
        0 => no_such_configuration(),
        _ => Response::builder().status(StatusCode::NO_CONTENT).body(Full::new(Bytes::new())).unwrap(),
    })
}

fn parse_stored(bucket: &str, json: String) -> anyhow::Result<Configuration> {
    Configuration::from_json(&json).map_err(|e| {
        anyhow::anyhow!("an inventory configuration of bucket {bucket} doesn't parse (written by a newer Cairn?): {e}")
    })
}

fn invalid_argument(message: &str) -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::BAD_REQUEST, "InvalidArgument", message)
}

fn no_such_configuration() -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::NOT_FOUND, "NoSuchConfiguration", "The specified configuration does not exist.")
}

fn no_such_bucket() -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::NOT_FOUND, "NoSuchBucket", "The specified bucket does not exist")
}
