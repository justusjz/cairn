//! The admin UI's JSON API. Every route here needs a logged-in admin (see the
//! module above); `route` gets the role's name.
//!
//! The numbers come from the catalog, as of the request, and from each node's
//! own metrics (see `metrics`), which every live node reports through its peer
//! endpoint. Some of the catalog's numbers take a scan of a whole table, which
//! is fine for a page an operator looks at, but not for anything that runs on
//! its own.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Empty, Limited};
use hyper::{Method, Request, Response, StatusCode, body::Incoming, header};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use serde_json::{Value, json};
use tokio::task::JoinSet;

use super::{error, json_response, node_stats, read_json};
use crate::{
    App,
    body::ResBody,
    roles::{self, Invalid, Permission},
    s3::{conditional::Preconditions, util::query_param},
};

/// How long another node may take to report its metrics.
const STATS_TIMEOUT: Duration = Duration::from_secs(2);
/// The most a node's metrics may take up.
const MAX_STATS: usize = 4 * 1024 * 1024;
/// How many entries a page of a bucket listing has.
const PAGE: i64 = 200;
/// How many versions of a key are shown.
const MAX_VERSIONS: i64 = 200;

fn ok(value: Value) -> anyhow::Result<Response<ResBody>> {
    Ok(json_response(StatusCode::OK, &value))
}

fn invalid(message: impl Into<String>) -> anyhow::Error {
    Invalid(message.into()).into()
}

pub(super) async fn route(
    req: Request<Incoming>,
    app: &Arc<App>,
    role: &str,
    route: &str,
) -> anyhow::Result<Response<ResBody>> {
    let query = req.uri().query().unwrap_or("").to_owned();
    let param = |name: &str| query_param(&query, name);
    let segments: Vec<String> = route
        .split('/')
        .map(|s| percent_decode_str(s).decode_utf8_lossy().into_owned())
        .collect();
    let segments: Vec<&str> = segments.iter().map(String::as_str).collect();
    match (req.method().clone(), segments.as_slice()) {
        (Method::GET, ["session"]) => ok(json!({ "role": role, "node": app.node })),
        (Method::GET, ["cluster"]) => ok(cluster(app).await?),
        (Method::GET, ["storage"]) => ok(storage(app).await?),
        (Method::GET, ["buckets"]) => ok(buckets(app).await?),
        (Method::POST, ["buckets"]) => {
            let body = read_json(req).await?.unwrap_or_default();
            create_bucket(app, body["name"].as_str().unwrap_or("")).await?;
            ok(json!({}))
        }
        (Method::DELETE, ["buckets", bucket]) => {
            delete_bucket(app, bucket).await?;
            ok(json!({}))
        }
        (Method::GET, ["buckets", bucket, "objects"]) => {
            let prefix = param("prefix").unwrap_or_default();
            let after = param("after").unwrap_or_default();
            let deleted = param("deleted").is_some_and(|v| v == "1");
            ok(list_objects(app, bucket, &prefix, &after, deleted).await?)
        }
        (Method::GET, ["buckets", bucket, "object"]) => {
            ok(object(app, bucket, &param("key").unwrap_or_default()).await?)
        }
        (Method::GET, ["buckets", bucket, "download"]) => {
            let key = param("key").unwrap_or_default();
            download(app, bucket, &key, param("version").as_deref()).await
        }
        (Method::GET, ["roles"]) => ok(list_roles(app).await?),
        (Method::POST, ["roles"]) => {
            let body = read_json(req).await?.unwrap_or_default();
            let name = body["name"].as_str().unwrap_or("");
            let secret = body["secret"].as_str().filter(|s| !s.is_empty());
            let admin = body["admin"].as_bool().unwrap_or(false);
            let client = app.pool.get().await?;
            let secret = roles::create(&client, name, secret.map(str::to_owned), admin).await?;
            ok(json!({ "name": name, "secret": secret }))
        }
        (Method::DELETE, ["roles", name]) => {
            if *name == role {
                return Err(invalid("you can't delete the role you're logged in as"));
            }
            roles::delete(&app.pool.get().await?, name).await?;
            ok(json!({}))
        }
        (Method::POST, ["roles", name, "secret"]) => {
            let body = read_json(req).await?.unwrap_or_default();
            let secret = match body["secret"].as_str().filter(|s| !s.is_empty()) {
                Some(s) => s.to_owned(),
                None => roles::generate_secret()?,
            };
            let client = app.pool.get().await?;
            roles::update(&client, name, None, Some(secret.clone())).await?;
            ok(json!({ "name": name, "secret": secret }))
        }
        (Method::POST, ["roles", name, "admin"]) => {
            let body = read_json(req).await?.unwrap_or_default();
            let Some(admin) = body["admin"].as_bool() else {
                return Err(invalid("expected {\"admin\": true|false}"));
            };
            if *name == role && !admin {
                return Err(invalid(
                    "you can't revoke admin from the role you're logged in as",
                ));
            }
            roles::update(&app.pool.get().await?, name, Some(admin), None).await?;
            ok(json!({}))
        }
        (Method::POST, ["roles", name, "grants"]) => {
            let body = read_json(req).await?.unwrap_or_default();
            let bucket = body["bucket"].as_str().unwrap_or("");
            let permissions = permissions(&body["permissions"])?;
            if permissions.is_empty() {
                return Err(invalid("pick at least one permission"));
            }
            roles::grant(&app.pool.get().await?, name, bucket, &permissions).await?;
            ok(json!({}))
        }
        (Method::DELETE, ["roles", name, "grants"]) => {
            let bucket = param("bucket").unwrap_or_default();
            let permissions = match param("permission") {
                Some(p) => permissions(&json!([p]))?,
                None => Vec::new(),
            };
            roles::revoke(&app.pool.get().await?, name, &bucket, &permissions).await?;
            ok(json!({}))
        }
        _ => Ok(error(StatusCode::NOT_FOUND, "no such API route")),
    }
}

fn permissions(value: &Value) -> anyhow::Result<Vec<Permission>> {
    let Some(names) = value.as_array() else {
        return Err(invalid("expected a list of permissions"));
    };
    names
        .iter()
        .map(|p| {
            p.as_str()
                .and_then(Permission::parse)
                .ok_or_else(|| invalid(format!("no permission named {p}")))
        })
        .collect()
}

/// The nodes, each with the metrics it reports, if it's live.
async fn cluster(app: &Arc<App>) -> anyhow::Result<Value> {
    let client = app.pool.get().await?;
    // Live as `choose_replicas` counts it: seen within the last 10 seconds.
    let rows = client
        .query(
            "SELECT id, node_id, peer_url, extract(epoch FROM last_seen)::float8, free_space,
                    last_seen > NOW() - INTERVAL '10 seconds'
             FROM nodes ORDER BY id",
            &[],
        )
        .await?;
    drop(client);
    let mut fetches = JoinSet::new();
    for (index, row) in rows.iter().enumerate() {
        let (id, peer_url, live): (i32, String, bool) = (row.get(0), row.get(2), row.get(5));
        if id == app.node {
            let stats = node_stats(app);
            fetches.spawn(async move { (index, Ok(stats)) });
        } else if live {
            fetches.spawn(async move { (index, fetch_stats(&peer_url).await) });
        }
    }
    let mut stats = vec![None; rows.len()];
    while let Some(result) = fetches.join_next().await {
        let (index, result) = result?;
        stats[index] = Some(result.unwrap_or_else(|e| json!({ "error": format!("{e:#}") })));
    }
    let nodes: Vec<Value> = rows
        .iter()
        .zip(stats)
        .map(|(row, stats)| {
            json!({
                "id": row.get::<_, i32>(0),
                "node_id": row.get::<_, String>(1),
                "peer_url": row.get::<_, String>(2),
                "last_seen": row.get::<_, f64>(3),
                "free_space": row.get::<_, i64>(4),
                "live": row.get::<_, bool>(5),
                "stats": stats,
            })
        })
        .collect();
    Ok(json!({
        "this_node": app.node,
        "replication_factor": app.replication_factor,
        "now": crate::metrics::now_secs(),
        "nodes": nodes,
    }))
}

/// Asks another node for its metrics, through its peer endpoint.
async fn fetch_stats(peer_url: &str) -> anyhow::Result<Value> {
    let client = Client::builder(TokioExecutor::new()).build_http::<Empty<hyper::body::Bytes>>();
    let fetch = async {
        let res = client.get(format!("{peer_url}/stats").parse()?).await?;
        if res.status() != StatusCode::OK {
            anyhow::bail!("{peer_url} answered with status {}", res.status());
        }
        let body = Limited::new(res.into_body(), MAX_STATS)
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(serde_json::from_slice(&body.to_bytes())?)
    };
    tokio::time::timeout(STATS_TIMEOUT, fetch)
        .await
        .map_err(|_| anyhow::anyhow!("{peer_url} didn't answer in time"))?
}

/// What's stored where, how well it's replicated, and what the background jobs
/// still have to do.
async fn storage(app: &App) -> anyhow::Result<Value> {
    let client = app.pool.get().await?;
    let per_node: Vec<Value> = client
        .query(
            "SELECT l.node, count(*), coalesce(sum(b.size), 0)::bigint
             FROM blob_locations l JOIN blobs b USING (blob_id)
             WHERE b.state = 'committed'
             GROUP BY l.node ORDER BY l.node",
            &[],
        )
        .await?
        .iter()
        .map(|r| json!({ "node": r.get::<_, i32>(0), "blobs": r.get::<_, i64>(1), "bytes": r.get::<_, i64>(2) }))
        .collect();
    // How many copies each committed blob has, and how many of them are on
    // live nodes.
    let replicas: Vec<Value> = client
        .query(
            "SELECT live, copies, count(*), coalesce(sum(size), 0)::bigint FROM (
                 SELECT b.size, count(l.node) AS copies,
                        count(l.node) FILTER (WHERE n.last_seen > NOW() - INTERVAL '10 seconds')
                            AS live
                 FROM blobs b
                 LEFT JOIN blob_locations l ON l.blob_id = b.blob_id
                 LEFT JOIN nodes n ON n.id = l.node
                 WHERE b.state = 'committed'
                 GROUP BY b.blob_id, b.size
             ) t
             GROUP BY live, copies ORDER BY live, copies",
            &[],
        )
        .await?
        .iter()
        .map(|r| {
            json!({
                "live": r.get::<_, i64>(0),
                "copies": r.get::<_, i64>(1),
                "blobs": r.get::<_, i64>(2),
                "bytes": r.get::<_, i64>(3),
            })
        })
        .collect();
    let small_size = app.pack.small_size as i64;
    let threshold = app.pack.compact_threshold;
    let b = client
        .query_one(
            "SELECT count(*) FILTER (WHERE state = 'committed'),
                    coalesce(sum(size) FILTER (WHERE state = 'committed'), 0)::bigint,
                    coalesce(sum(dead_size), 0)::bigint,
                    count(*) FILTER (WHERE state = 'pending'),
                    extract(epoch FROM min(created_at) FILTER (WHERE state = 'pending'))::float8,
                    count(*) FILTER (WHERE pack_lease_until > NOW()),
                    coalesce(sum(size) FILTER (WHERE pack_lease_until > NOW()), 0)::bigint,
                    count(*) FILTER (WHERE state = 'committed' AND size <= $1
                                     AND (pack_lease_until IS NULL OR pack_lease_until < NOW())),
                    coalesce(sum(size) FILTER (WHERE state = 'committed' AND size <= $1
                                     AND (pack_lease_until IS NULL OR pack_lease_until < NOW())),
                             0)::bigint,
                    count(*) FILTER (WHERE state = 'committed' AND dead_size > 0
                                     AND dead_size >= size * $2::float8),
                    coalesce(sum(dead_size) FILTER (WHERE state = 'committed' AND dead_size > 0
                                     AND dead_size >= size * $2::float8), 0)::bigint
             FROM blobs",
            &[&small_size, &threshold],
        )
        .await?;
    let o = client
        .query_one(
            "SELECT count(*) FILTER (WHERE is_latest AND NOT is_delete_marker),
                    coalesce(sum(size) FILTER (WHERE is_latest AND NOT is_delete_marker), 0)::bigint,
                    count(*) FILTER (WHERE NOT is_latest AND NOT is_delete_marker),
                    coalesce(sum(size) FILTER (WHERE NOT is_latest AND NOT is_delete_marker),
                             0)::bigint,
                    count(*) FILTER (WHERE is_delete_marker)
             FROM objects",
            &[],
        )
        .await?;
    let m = client
        .query_one(
            "SELECT (SELECT count(*) FROM multipart_uploads),
                    (SELECT extract(epoch FROM min(initiated_at))::float8 FROM multipart_uploads),
                    (SELECT coalesce(sum(size), 0)::bigint FROM parts WHERE upload_id IS NOT NULL),
                    (SELECT count(*) FROM blob_garbage),
                    (SELECT count(*) FROM buckets)",
            &[],
        )
        .await?;
    Ok(json!({
        "replication_factor": app.replication_factor,
        "nodes": per_node,
        "replicas": replicas,
        "blobs": {
            "committed": b.get::<_, i64>(0),
            "bytes": b.get::<_, i64>(1),
            "garbage_bytes": b.get::<_, i64>(2),
            "pending": b.get::<_, i64>(3),
            "oldest_pending": b.get::<_, Option<f64>>(4),
        },
        "objects": {
            "buckets": m.get::<_, i64>(4),
            "current": o.get::<_, i64>(0),
            "current_bytes": o.get::<_, i64>(1),
            "noncurrent": o.get::<_, i64>(2),
            "noncurrent_bytes": o.get::<_, i64>(3),
            "delete_markers": o.get::<_, i64>(4),
        },
        "backlog": {
            "packing": b.get::<_, i64>(5),
            "packing_bytes": b.get::<_, i64>(6),
            "consolidate": b.get::<_, i64>(7),
            "consolidate_bytes": b.get::<_, i64>(8),
            "compact": b.get::<_, i64>(9),
            "compact_garbage_bytes": b.get::<_, i64>(10),
            "garbage_log": m.get::<_, i64>(3),
            "uploads": m.get::<_, i64>(0),
            "oldest_upload": m.get::<_, Option<f64>>(1),
            "upload_bytes": m.get::<_, i64>(2),
        },
        "packer": {
            "target_size": app.pack.target_size,
            "small_size": app.pack.small_size,
            "compact_threshold": app.pack.compact_threshold,
            "max_sources": app.pack.max_sources,
        },
    }))
}

async fn buckets(app: &App) -> anyhow::Result<Value> {
    let rows = app
        .pool
        .get()
        .await?
        .query(
            "SELECT b.name, extract(epoch FROM b.created_at)::float8, b.versioning,
                    count(o.id) FILTER (WHERE o.is_latest AND NOT o.is_delete_marker),
                    coalesce(sum(o.size) FILTER (WHERE o.is_latest AND NOT o.is_delete_marker),
                             0)::bigint,
                    count(o.id),
                    coalesce(sum(o.size), 0)::bigint,
                    (SELECT count(*) FROM multipart_uploads m WHERE m.bucket = b.name),
                    (SELECT count(DISTINCT g.role) FROM role_grants g WHERE g.bucket = b.name)
             FROM buckets b LEFT JOIN objects o ON o.bucket = b.name
             GROUP BY b.name ORDER BY b.name",
            &[],
        )
        .await?;
    let buckets: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "name": r.get::<_, String>(0),
                "created_at": r.get::<_, f64>(1),
                "versioning": r.get::<_, String>(2),
                "objects": r.get::<_, i64>(3),
                "bytes": r.get::<_, i64>(4),
                "versions": r.get::<_, i64>(5),
                "version_bytes": r.get::<_, i64>(6),
                "uploads": r.get::<_, i64>(7),
                "roles": r.get::<_, i64>(8),
            })
        })
        .collect();
    Ok(json!({ "buckets": buckets }))
}

/// Whether `name` is a valid S3 bucket name: 3 to 63 lowercase letters, digits,
/// dots and hyphens, starting and ending with a letter or digit.
fn valid_bucket_name(name: &str) -> bool {
    let edge = |c: Option<char>| c.is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    (3..=63).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
        && edge(name.chars().next())
        && edge(name.chars().last())
        && !name.contains("..")
}

async fn create_bucket(app: &App, name: &str) -> anyhow::Result<()> {
    if !valid_bucket_name(name) {
        return Err(invalid(
            "a bucket name has 3 to 63 lowercase letters, digits, dots and hyphens, \
             and starts and ends with a letter or digit",
        ));
    }
    let inserted = app
        .pool
        .get()
        .await?
        .execute(
            "INSERT INTO buckets (name) VALUES ($1) ON CONFLICT DO NOTHING",
            &[&name],
        )
        .await?;
    if inserted == 0 {
        return Err(invalid(format!("a bucket named {name:?} already exists")));
    }
    Ok(())
}

async fn delete_bucket(app: &App, name: &str) -> anyhow::Result<()> {
    let resp = crate::s3::buckets::delete::delete_bucket(app, name).await?;
    match resp.status() {
        StatusCode::NO_CONTENT => Ok(()),
        StatusCode::NOT_FOUND => Err(invalid(format!("no bucket named {name:?}"))),
        StatusCode::CONFLICT => Err(invalid(format!(
            "bucket {name:?} isn't empty: delete its objects, versions and uploads first"
        ))),
        _ => Err(crate::Contended(format!("deleting bucket {name:?}")).into()),
    }
}

/// A page of a bucket's keys under `prefix`, rolled up at the next `/` like a
/// directory listing, after the key `after`. With `deleted`, keys whose current
/// version is a delete marker are listed too.
async fn list_objects(
    app: &App,
    bucket: &str,
    prefix: &str,
    after: &str,
    deleted: bool,
) -> anyhow::Result<Value> {
    let client = app.pool.get().await?;
    if client
        .query_opt("SELECT 1 FROM buckets WHERE name = $1", &[&bucket])
        .await?
        .is_none()
    {
        return Err(invalid(format!("no bucket named {bucket:?}")));
    }
    // As in ListObjects (see `s3::objects::list`), with `/` as the delimiter.
    let rows = client
        .query(
            "SELECT token, bool_or(is_prefix), max(key), count(*), sum(size)::bigint, max(etag),
                    extract(epoch FROM max(last_modified))::float8, bool_or(is_delete_marker)
             FROM (
                 SELECT key, size, etag, last_modified, is_delete_marker,
                        CASE WHEN position('/' IN substr(key, length($2) + 1)) > 0
                             THEN $2 || substr(substr(key, length($2) + 1), 1,
                                               position('/' IN substr(key, length($2) + 1)))
                             ELSE key
                        END AS token,
                        position('/' IN substr(key, length($2) + 1)) > 0 AS is_prefix
                 FROM objects
                 WHERE bucket = $1 AND is_latest AND (NOT is_delete_marker OR $5)
                   AND starts_with(key, $2) AND key > $3
             ) t
             GROUP BY token
             ORDER BY token
             LIMIT $4",
            &[&bucket, &prefix, &after, &(PAGE + 1), &deleted],
        )
        .await?;
    let truncated = rows.len() as i64 > PAGE;
    let rows = &rows[..rows.len().min(PAGE as usize)];
    let entries: Vec<Value> = rows
        .iter()
        .map(|r| {
            if r.get::<_, bool>(1) {
                json!({
                    "prefix": r.get::<_, String>(0),
                    "objects": r.get::<_, i64>(3),
                    "bytes": r.get::<_, i64>(4),
                    "last_modified": r.get::<_, f64>(6),
                })
            } else {
                json!({
                    "key": r.get::<_, String>(0),
                    "size": r.get::<_, i64>(4),
                    "etag": r.get::<_, Option<String>>(5),
                    "last_modified": r.get::<_, f64>(6),
                    "delete_marker": r.get::<_, bool>(7),
                })
            }
        })
        .collect();
    let next = truncated.then(|| rows.last().map(|r| r.get::<_, String>(2)));
    Ok(json!({ "entries": entries, "next": next.flatten() }))
}

/// Every version of a key, newest first, each with its parts and where their
/// blobs are stored.
async fn object(app: &App, bucket: &str, key: &str) -> anyhow::Result<Value> {
    let client = app.pool.get().await?;
    let versions = client
        .query(
            "SELECT id, version_id, is_latest, is_delete_marker, size, etag, content_type,
                    extract(epoch FROM last_modified)::float8
             FROM objects WHERE bucket = $1 AND key = $2
             ORDER BY id DESC LIMIT $3",
            &[&bucket, &key, &MAX_VERSIONS],
        )
        .await?;
    let ids: Vec<i64> = versions.iter().map(|r| r.get(0)).collect();
    let parts = client
        .query(
            "SELECT p.object_id, p.part_number, p.size, p.etag, p.crc64nvme, p.blob_id,
                    p.blob_offset, b.size, b.state, extract(epoch FROM p.created_at)::float8,
                    ARRAY(SELECT l.node FROM blob_locations l
                          WHERE l.blob_id = p.blob_id ORDER BY l.node)
             FROM parts p JOIN blobs b ON b.blob_id = p.blob_id
             WHERE p.object_id = ANY($1)
             ORDER BY p.object_id, p.part_number",
            &[&ids],
        )
        .await?;
    let versions: Vec<Value> = versions
        .iter()
        .map(|v| {
            let id: i64 = v.get(0);
            let parts: Vec<Value> = parts
                .iter()
                .filter(|p| p.get::<_, i64>(0) == id)
                .map(|p| {
                    json!({
                        "number": p.get::<_, i32>(1),
                        "size": p.get::<_, i64>(2),
                        "etag": p.get::<_, String>(3),
                        "crc64nvme": p.get::<_, Option<i64>>(4)
                            .map(|c| format!("{:016x}", c as u64)),
                        "blob_id": p.get::<_, uuid::Uuid>(5).to_string(),
                        "blob_offset": p.get::<_, i64>(6),
                        "blob_size": p.get::<_, i64>(7),
                        "blob_state": p.get::<_, String>(8),
                        "created_at": p.get::<_, f64>(9),
                        "nodes": p.get::<_, Vec<i32>>(10),
                    })
                })
                .collect();
            json!({
                "version_id": v.get::<_, String>(1),
                "latest": v.get::<_, bool>(2),
                "delete_marker": v.get::<_, bool>(3),
                "size": v.get::<_, i64>(4),
                "etag": v.get::<_, Option<String>>(5),
                "content_type": v.get::<_, Option<String>>(6),
                "last_modified": v.get::<_, f64>(7),
                "parts": parts,
            })
        })
        .collect();
    Ok(json!({ "bucket": bucket, "key": key, "versions": versions }))
}

/// An object's data, as a file to save. It's always sent as an attachment of
/// no particular type, so that a browser never renders it as part of the UI.
async fn download(
    app: &Arc<App>,
    bucket: &str,
    key: &str,
    version: Option<&str>,
) -> anyhow::Result<Response<ResBody>> {
    let preconditions = Preconditions::default();
    let resp = crate::s3::objects::get::get_object(app, bucket, key, version, None, &preconditions)
        .await?;
    if resp.status() != StatusCode::OK {
        return Ok(error(resp.status(), "the object can't be read"));
    }
    let (mut parts, body) = resp.into_parts();
    let name = key
        .rsplit('/')
        .next()
        .filter(|n| !n.is_empty())
        .unwrap_or("download");
    let headers = &mut parts.headers;
    headers.insert(header::CONTENT_TYPE, "application/octet-stream".parse()?);
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!(
            "attachment; filename*=UTF-8''{}",
            utf8_percent_encode(name, NON_ALPHANUMERIC)
        )
        .parse()?,
    );
    headers.insert("content-security-policy", "sandbox".parse()?);
    headers.insert("x-content-type-options", "nosniff".parse()?);
    Ok(Response::from_parts(parts, body))
}

async fn list_roles(app: &App) -> anyhow::Result<Value> {
    let roles: Vec<Value> = roles::list(&app.pool.get().await?)
        .await?
        .into_iter()
        .map(|r| {
            let grants: Vec<Value> = r
                .grants
                .into_iter()
                .map(|(bucket, permission)| json!({ "bucket": bucket, "permission": permission }))
                .collect();
            json!({
                "name": r.name,
                "admin": r.admin,
                "created_at": r.created_at,
                "grants": grants,
            })
        })
        .collect();
    Ok(json!({ "roles": roles }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_bucket_names() {
        for name in ["abc", "my-bucket", "my.bucket.2", &"a".repeat(63)] {
            assert!(valid_bucket_name(name), "{name}");
        }
        for name in [
            "ab",
            "My-Bucket",
            "-abc",
            "abc-",
            "a..b",
            "a_b",
            "a/b",
            &"a".repeat(64),
        ] {
            assert!(!valid_bucket_name(name), "{name}");
        }
    }
}

#[cfg(test)]
mod e2e {
    use super::*;
    use crate::e2e::{BUCKET, delete, node_with, put};

    #[tokio::test]
    async fn reports_the_catalog() {
        let Some(app) = node_with(crate::packer::Config::default(), None).await else {
            return;
        };
        put(&app, "a/one", vec![1; 10]).await;
        put(&app, "a/two", vec![2; 20]).await;
        put(&app, "b", vec![3; 30]).await;
        put(&app, "gone", vec![4; 40]).await;
        delete(&app, "gone").await;

        let storage = storage(&app).await.unwrap();
        assert_eq!(storage["objects"]["current"], 3);
        assert_eq!(storage["objects"]["current_bytes"], 60);
        assert_eq!(storage["blobs"]["committed"], 3);
        assert_eq!(
            storage["replicas"],
            json!([{ "live": 1, "copies": 1, "blobs": 3, "bytes": 60 }])
        );
        assert_eq!(storage["nodes"][0]["bytes"], 60);
        assert_eq!(storage["backlog"]["consolidate"], 3);

        let buckets = buckets(&app).await.unwrap();
        assert_eq!(buckets["buckets"][0]["name"], BUCKET);
        assert_eq!(buckets["buckets"][0]["objects"], 3);

        // Rolled up at `/`, with each directory's count and size.
        let listing = list_objects(&app, BUCKET, "", "", false).await.unwrap();
        let entries = listing["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["prefix"], "a/");
        assert_eq!(entries[0]["objects"], 2);
        assert_eq!(entries[0]["bytes"], 30);
        assert_eq!(entries[1]["key"], "b");
        assert!(listing["next"].is_null());
        let listing = list_objects(&app, BUCKET, "a/", "a/one", false)
            .await
            .unwrap();
        assert_eq!(listing["entries"], json!([listing["entries"][0]]));
        assert_eq!(listing["entries"][0]["key"], "a/two");
        assert!(list_objects(&app, "nope", "", "", false).await.is_err());

        let object = object(&app, BUCKET, "a/two").await.unwrap();
        let versions = object["versions"].as_array().unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0]["parts"][0]["size"], 20);
        assert_eq!(versions[0]["parts"][0]["nodes"], json!([app.node]));

        let cluster = cluster(&app).await.unwrap();
        assert_eq!(cluster["nodes"][0]["stats"]["node"], app.node);
    }
}
