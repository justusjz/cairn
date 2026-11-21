//! Shipping a node's closed log files (see `log`) into the internal bucket
//! (see `internal`), where the cluster keeps them: replicated as its
//! objects are, and readable by any node. Each file is one object, gzipped,
//! at
//!
//! ```text
//! audit/<year>/<month>/<day>/<hour>/<file>-<node>.log.gz
//! ```
//!
//! dated by when the file was opened, so that a time's records are under
//! its prefix (or the one before, for a file opened just before the hour).
//! A file is removed once its object is written. Its key is its name's, so
//! a file shipped again (a crash between the write and the removal) is
//! written over the same object: never twice. A file that fails to ship is
//! kept, and tried again with the next pass, for as long as it takes: an
//! audit record isn't dropped.
//!
//! The objects are kept for 90 days, as CloudTrail's event history keeps
//! events, then deleted (see `expire`). With a KMS, they're encrypted with
//! SSE-S3, as the root key wraps it.

use std::{
    io::Write,
    path::Path,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use http_body_util::{BodyExt, Full};
use hyper::{StatusCode, body::Bytes};
use uuid::Uuid;

use super::log::Log;
use crate::{
    App,
    db::Cached,
    lifecycle::rules::Day,
    payload::Payload,
    s3::{
        conditional::Preconditions,
        object_lock::Lock,
        sse::{ServerSide, Wanted},
        util::MAX_UPLOAD,
    },
};

/// How often a node ships its closed files.
const SHIP: Duration = Duration::from_secs(2);
/// How often a node deletes the objects that are past their retention.
const EXPIRE: Duration = Duration::from_secs(3600);
/// How long records are kept.
pub const RETENTION_DAYS: u64 = 90;
/// What the objects' keys start with.
pub const PREFIX: &str = "audit/";

/// Ships the node's closed files, and expires old objects, for as long as
/// the node runs.
pub async fn run(app: Arc<App>) {
    let Some(dir) = app.audit.dir().map(Path::to_owned) else {
        return;
    };
    let mut expired: Option<Instant> = None;
    loop {
        tokio::time::sleep(SHIP).await;
        if let Err(e) = ship_all(&app, &dir).await {
            complain(&format_args!("shipping failed: {e:#}"));
        }
        if expired.is_none_or(|t| t.elapsed() >= EXPIRE) {
            expired = Some(Instant::now());
            if let Err(e) = expire(&app, SystemTime::now()).await {
                eprintln!("audit log: deleting old records failed: {e:#}");
            }
        }
    }
}

/// Complains at most once a minute, so that a cluster that can't take the
/// records (its storage down) doesn't flood the log.
fn complain(what: &dyn std::fmt::Display) {
    static LAST: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
    if last.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
        *last = Some(Instant::now());
        eprintln!("audit log: {what}");
    }
}

/// Ships every closed file in `dir`, oldest first; stops at the first that
/// fails (the next would likely fail too). How many it shipped.
pub async fn ship_all(app: &Arc<App>, dir: &Path) -> anyhow::Result<usize> {
    let files = {
        let dir = dir.to_owned();
        tokio::task::spawn_blocking(move || Log::closed(&dir)).await??
    };
    let mut shipped = 0;
    for file in files {
        ship_file(app, &file).await?;
        shipped += 1;
    }
    Ok(shipped)
}

/// The key of the object a file of the log is shipped as.
pub fn object_key(node: Uuid, file: &Path) -> Option<String> {
    let opened = Log::opened(file)?;
    let stem = file.file_stem()?.to_str()?;
    let day = Day::of(opened);
    let (year, month, date) = day.civil();
    let hour = opened
        .duration_since(day.midnight())
        .map_or(0, |d| d.as_secs() / 3600);
    Some(format!(
        "{PREFIX}{year:04}/{month:02}/{date:02}/{hour:02}/{stem}-{node}.log.gz"
    ))
}

/// Ships a closed file, and removes it once it's shipped.
async fn ship_file(app: &Arc<App>, path: &Path) -> anyhow::Result<()> {
    let data = tokio::fs::read(path).await?;
    if data.is_empty() {
        tokio::fs::remove_file(path).await?;
        return Ok(());
    }
    let key = object_key(app.store.get_node_id(), path)
        .ok_or_else(|| anyhow::anyhow!("{} isn't a log file's name", path.display()))?;
    let body = tokio::task::spawn_blocking(move || {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&data)?;
        gz.finish()
    })
    .await??;
    let payload = Payload::unchecked()
        .at_most(MAX_UPLOAD)
        .map_err(|_| anyhow::anyhow!("an unchecked payload has no length"))?;
    let sse_s3 = ServerSide::S3;
    let server = app.kms.as_ref().map(|_| &sse_s3);
    let response = crate::s3::objects::put::put_object(
        app,
        crate::internal::BUCKET,
        &key,
        "application/gzip",
        "",
        "",
        Full::new(Bytes::from(body)),
        payload,
        &Preconditions::default(),
        Wanted::new(None, server),
        None,
        Lock::default(),
        crate::classes::STANDARD,
    )
    .await?;
    let status = response.status();
    if status != StatusCode::OK {
        let answer = response
            .into_body()
            .collect()
            .await
            .map(|b| b.to_bytes())
            .unwrap_or_default();
        anyhow::bail!(
            "writing {key}: {status}: {}",
            String::from_utf8_lossy(&answer)
        );
    }
    tokio::fs::remove_file(path).await?;
    Ok(())
}

/// Deletes the shipped records that are past their retention at `now`: the
/// objects of the days before it, a thousand at a time.
pub async fn expire(app: &Arc<App>, now: SystemTime) -> anyhow::Result<()> {
    let cutoff = Day::of(now - Duration::from_secs(RETENTION_DAYS * 86400));
    let (year, month, date) = cutoff.civil();
    let before = format!("{PREFIX}{year:04}/{month:02}/{date:02}/");
    loop {
        let rows = app
            .pool
            .get()
            .await?
            .query_cached(
                "SELECT key FROM objects
                 WHERE bucket = $1 AND key >= $2 AND key < $3 AND is_latest
                 ORDER BY key LIMIT 1000",
                &[&crate::internal::BUCKET, &PREFIX, &before],
            )
            .await?;
        if rows.is_empty() {
            return Ok(());
        }
        for row in rows {
            let key: &str = row.get(0);
            let response = crate::s3::objects::delete::delete_object(
                app,
                crate::internal::BUCKET,
                key,
                None,
                false,
                None,
                crate::mfa::Presented::Absent,
            )
            .await?;
            if !response.status().is_success() {
                anyhow::bail!("deleting {key}: {}", response.status());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_dated_by_their_files() {
        let node = Uuid::nil();
        // 2026-11-16T05:06:07.890Z.
        let file = Path::new("/d/1794805567890-3-0a0b0c0d.closed");
        assert_eq!(
            object_key(node, file).unwrap(),
            format!("audit/2026/11/16/05/1794805567890-3-0a0b0c0d-{node}.log.gz")
        );
        assert_eq!(object_key(node, Path::new("/d/other")), None);
    }
}
