//! Streams: append-only logs of records, as Kinesis Data Streams has them
//! (its API is `kinesis`), kept in the cluster's storage as its objects are.
//! See `plans/streams.md` for where this is headed (Kafka's protocol).
//!
//! A stream has a fixed number of shards, each a log of its own whose
//! records are numbered from 0 (their sequence numbers): a record's shard
//! is chosen by its partition key's hash, so records with one key are in
//! one shard, in order. A shard is a row in the database (`stream_shards`)
//! holding its next sequence number, and has no node of its own: any node
//! takes records for any shard.
//!
//! **Writing.** A node gathers the records it's given, from every stream,
//! for up to `LINGER` (or until it has `FLUSH_BYTES` of them), and then
//! *flushes* them: writes them as one object to the internal bucket (see
//! `internal`), under `streams/`, replicated as every object is, and
//! then, in one transaction (`cairn_stream_append`), draws each shard's
//! sequence numbers and adds a row per shard to the index
//! (`stream_batches`): the shard's batch of records, where in the object
//! it is. Only then is each record's writer answered, with its sequence
//! number. So an answered record is on as many nodes as the bucket's
//! objects are, and in the index; a shard's numbers are drawn under its
//! row's lock, so its batches commit in the order of their numbers, and a
//! reader never sees a later one without the earlier ones. Up to
//! `FLUSHES` flushes are in flight at once.
//!
//! **Reading.** A shard's records from a sequence number are found in the
//! index, and read from their objects' byte ranges, as any object's data
//! is (verified against its checksums, from whichever node holds it).
//!
//! **Cleaning up.** Every node, every `SWEEP`: deletes the index's rows
//! that are past their stream's retention, and then the objects no row
//! refers to any more (those of deleted streams too, and those of flushes
//! that failed after writing their object), once they're older than
//! `ORPHANED`. A flush whose object is older than `STALE` by the time it's
//! appended gives up instead, so it never refers to an object being
//! deleted as an orphan.
//!
//! Not yet: packing a shard's batches together (old records are read a
//! batch at a time, from objects shared with every other shard flushed at
//! the time), resharding, consumers (enhanced fan-out), and encryption with
//! a stream's own KMS key (with a KMS, the objects are SSE-S3, as the audit
//! log's are).

pub mod kinesis;
#[cfg(test)]
mod tests;

use std::{
    collections::BTreeMap,
    sync::{Arc, OnceLock, Weak},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use http_body_util::{BodyExt, Full};
use hyper::{StatusCode, body::Bytes};
use tokio::sync::{Semaphore, mpsc, oneshot};
use uuid::Uuid;

use crate::{
    App,
    db::Cached,
    payload::Payload,
    s3::{
        conditional::Preconditions,
        object_lock::Lock,
        sse::{ServerSide, Wanted},
        util::MAX_UPLOAD,
    },
};

/// How long a node waits for more records before it flushes.
const LINGER: Duration = Duration::from_millis(10);
/// How many bytes of records a node flushes at most at once.
const FLUSH_BYTES: usize = 4 * 1024 * 1024;
/// How many flushes a node has in flight at once.
const FLUSHES: usize = 4;
/// How long a flush may take from its object's write to its append.
const STALE: Duration = Duration::from_secs(5 * 60);
/// How old an object no index row refers to must be to be deleted.
const ORPHANED: &str = "10 minutes";
/// How often a node cleans up.
const SWEEP: Duration = Duration::from_secs(60);
/// What the objects' keys start with.
pub const PREFIX: &str = "streams/";

/// The most a record's data may hold, as Kinesis has it.
pub const MAX_DATA: usize = 1024 * 1024;
/// The longest a partition key may be, in characters.
pub const MAX_KEY: usize = 256;

/// A record, as it's written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub key: String,
    pub data: Vec<u8>,
    /// When its node was given it, in milliseconds since the epoch.
    pub arrived: i64,
}

impl Record {
    /// A record given now.
    pub fn new(key: String, data: Vec<u8>) -> Record {
        Record {
            key,
            data,
            arrived: now_millis(),
        }
    }

    fn encoded_len(&self) -> usize {
        8 + 2 + self.key.len() + 4 + self.data.len()
    }

    /// Appends it to `out`: its time, its key and its data, each length
    /// first (little-endian).
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.arrived.to_le_bytes());
        out.extend_from_slice(&(self.key.len() as u16).to_le_bytes());
        out.extend_from_slice(self.key.as_bytes());
        out.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.data);
    }
}

/// The records encoded in `data`, `count` of them.
fn decode(mut data: &[u8], count: usize) -> anyhow::Result<Vec<Record>> {
    fn take<'a>(data: &mut &'a [u8], n: usize) -> anyhow::Result<&'a [u8]> {
        anyhow::ensure!(data.len() >= n, "a batch of records is cut short");
        let (head, rest) = data.split_at(n);
        *data = rest;
        Ok(head)
    }
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let arrived = i64::from_le_bytes(take(&mut data, 8)?.try_into().unwrap());
        let key_len = u16::from_le_bytes(take(&mut data, 2)?.try_into().unwrap()) as usize;
        let key = String::from_utf8(take(&mut data, key_len)?.to_vec())?;
        let data_len = u32::from_le_bytes(take(&mut data, 4)?.try_into().unwrap()) as usize;
        let payload = take(&mut data, data_len)?.to_vec();
        records.push(Record {
            key,
            data: payload,
            arrived,
        });
    }
    anyhow::ensure!(data.is_empty(), "a batch of records runs on past its count");
    Ok(records)
}

pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Why records weren't appended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failed {
    /// Their stream was deleted.
    Gone,
    /// Something else: the node's log has the details. They may have been
    /// appended anyway (if the append's commit was cut off).
    Internal,
}

/// Records for a shard, waiting to be flushed, and who's waiting for their
/// first sequence number.
struct Pending {
    stream: Uuid,
    shard: i32,
    records: Vec<Record>,
    reply: oneshot::Sender<Result<i64, Failed>>,
}

/// A node's records waiting to be flushed (see the module's docs).
#[derive(Default)]
pub struct Appender {
    queue: OnceLock<mpsc::UnboundedSender<Pending>>,
}

impl Appender {
    /// Appends `records` to the shard, in their order; returns the first's
    /// sequence number (the others' follow it) once they're written.
    pub async fn append(
        &self,
        app: &Arc<App>,
        stream: Uuid,
        shard: i32,
        records: Vec<Record>,
    ) -> Result<i64, Failed> {
        let queue = self.queue.get_or_init(|| {
            let (tx, rx) = mpsc::unbounded_channel();
            tokio::spawn(gather(Arc::downgrade(app), rx));
            tx
        });
        let (reply, answer) = oneshot::channel();
        let pending = Pending {
            stream,
            shard,
            records,
            reply,
        };
        if queue.send(pending).is_err() {
            return Err(Failed::Internal);
        }
        answer.await.unwrap_or(Err(Failed::Internal))
    }
}

/// Gathers what's queued into flushes, for as long as the node runs.
async fn gather(app: Weak<App>, mut queue: mpsc::UnboundedReceiver<Pending>) {
    let flushes = Arc::new(Semaphore::new(FLUSHES));
    while let Some(first) = queue.recv().await {
        let mut bytes: usize = first.records.iter().map(Record::encoded_len).sum();
        let mut batch = vec![first];
        let deadline = tokio::time::Instant::now() + LINGER;
        while bytes < FLUSH_BYTES {
            tokio::select! {
                next = queue.recv() => match next {
                    Some(next) => {
                        bytes += next.records.iter().map(Record::encoded_len).sum::<usize>();
                        batch.push(next);
                    }
                    None => break,
                },
                () = tokio::time::sleep_until(deadline) => break,
            }
        }
        let Ok(permit) = flushes.clone().acquire_owned().await else {
            return;
        };
        let Some(app) = app.upgrade() else { return };
        tokio::spawn(async move {
            flush(&app, batch).await;
            drop(permit);
        });
    }
}

/// A shard's records in a flush: whose they are, in their order.
struct Group {
    /// The pendings' indexes, and where each one's records start.
    members: Vec<(usize, i64)>,
    count: i64,
    offset: i64,
    length: i64,
}

/// Writes `batch` as an object, appends it, and answers its writers.
async fn flush(app: &Arc<App>, batch: Vec<Pending>) {
    // Each shard's records together, in (stream, shard) order: the order
    // the append locks the shards in.
    let mut shards: BTreeMap<(Uuid, i32), Group> = BTreeMap::new();
    let mut body = Vec::new();
    let mut order: Vec<(Uuid, i32)> = batch.iter().map(|p| (p.stream, p.shard)).collect();
    order.sort();
    order.dedup();
    for &(stream, shard) in &order {
        let offset = body.len() as i64;
        let mut group = Group {
            members: Vec::new(),
            count: 0,
            offset,
            length: 0,
        };
        for (i, pending) in batch.iter().enumerate() {
            if (pending.stream, pending.shard) != (stream, shard) {
                continue;
            }
            group.members.push((i, group.count));
            group.count += pending.records.len() as i64;
            for record in &pending.records {
                record.encode(&mut body);
            }
        }
        group.length = body.len() as i64 - offset;
        shards.insert((stream, shard), group);
    }
    let outcome = write_and_append(app, body, &shards).await;
    let mut replies: Vec<Option<oneshot::Sender<Result<i64, Failed>>>> =
        batch.into_iter().map(|p| Some(p.reply)).collect();
    for (at, group) in &shards {
        let answer = match &outcome {
            Ok(firsts) => firsts.get(at).copied().ok_or(Failed::Gone),
            Err(e) => {
                eprintln!("streams: flushing failed: {e:#}");
                Err(Failed::Internal)
            }
        };
        for &(i, skip) in &group.members {
            if let Some(reply) = replies[i].take() {
                let _ = reply.send(answer.map(|first| first + skip));
            }
        }
    }
}

/// Writes the object, and appends its batches: the first sequence number
/// of each shard's that was appended.
async fn write_and_append(
    app: &Arc<App>,
    body: Vec<u8>,
    shards: &BTreeMap<(Uuid, i32), Group>,
) -> anyhow::Result<BTreeMap<(Uuid, i32), i64>> {
    let key = format!("{PREFIX}{}/{}", app.store.get_node_id(), Uuid::now_v7());
    let written = Instant::now();
    put(app, &key, body).await?;
    anyhow::ensure!(
        written.elapsed() < STALE,
        "writing {key} took too long to append it"
    );
    let streams: Vec<Uuid> = shards.keys().map(|(s, _)| *s).collect();
    let shard_numbers: Vec<i32> = shards.keys().map(|(_, n)| *n).collect();
    let counts: Vec<i32> = shards.values().map(|g| g.count as i32).collect();
    let offsets: Vec<i64> = shards.values().map(|g| g.offset).collect();
    let lengths: Vec<i64> = shards.values().map(|g| g.length).collect();
    let rows = app
        .pool
        .get()
        .await?
        .query_cached(
            "SELECT stream_id, shard, first_sequence
             FROM pg_temp.cairn_stream_append($1, $2, $3, $4, $5, $6)",
            &[&key, &streams, &shard_numbers, &counts, &offsets, &lengths],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| ((row.get(0), row.get(1)), row.get(2)))
        .collect())
}

/// Writes an object of the internal bucket.
async fn put(app: &Arc<App>, key: &str, body: Vec<u8>) -> anyhow::Result<()> {
    let payload = Payload::unchecked()
        .at_most(MAX_UPLOAD)
        .map_err(|_| anyhow::anyhow!("an unchecked payload has no length"))?;
    let sse_s3 = ServerSide::S3;
    let server = app.kms.as_ref().map(|_| &sse_s3);
    let response = crate::s3::objects::put::put_object(
        app,
        crate::internal::BUCKET,
        key,
        "application/octet-stream",
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
    Ok(())
}

/// A shard's records read from a sequence number.
pub struct Read {
    /// The records, each with its sequence number.
    pub records: Vec<(i64, Record)>,
    /// The sequence number to read from next.
    pub next: i64,
    /// The shard's next sequence number, as of the read.
    pub end: i64,
}

/// Reads a shard's records from sequence number `from` on: up to `limit`
/// of them, and as many more as fill `max_bytes` with their data, past
/// the first (which is always read). From the oldest the shard still
/// keeps, if `from` is older.
pub async fn read(
    app: &Arc<App>,
    stream: Uuid,
    shard: i32,
    from: i64,
    limit: usize,
    max_bytes: usize,
) -> anyhow::Result<Read> {
    let client = app.pool.get().await?;
    let rows = client
        .query_cached(
            "(SELECT first_sequence, count, object_key, byte_offset, byte_length
              FROM stream_batches
              WHERE stream_id = $1 AND shard = $2 AND first_sequence <= $3
              ORDER BY first_sequence DESC LIMIT 1)
             UNION ALL
             (SELECT first_sequence, count, object_key, byte_offset, byte_length
              FROM stream_batches
              WHERE stream_id = $1 AND shard = $2 AND first_sequence > $3
              ORDER BY first_sequence LIMIT $4)",
            &[&stream, &shard, &from, &(limit.min(10_000) as i64)],
        )
        .await?;
    let end: i64 = client
        .query_opt_cached(
            "SELECT next_sequence FROM stream_shards WHERE stream_id = $1 AND shard = $2",
            &[&stream, &shard],
        )
        .await?
        .map(|row| row.get(0))
        .unwrap_or(from);
    drop(client);
    let mut batches: Vec<(i64, i32, String, i64, i64)> = rows
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4)))
        .filter(|(first, count, ..)| first + *count as i64 > from)
        .collect();
    batches.sort_by_key(|b| b.0);
    let mut records = Vec::new();
    let mut bytes = 0;
    let mut next = from;
    'batches: for (first, count, key, offset, length) in batches {
        let Some(data) = read_range(app, &key, offset, length).await? else {
            // Expired since it was listed.
            continue;
        };
        for (i, record) in decode(&data, count as usize)?.into_iter().enumerate() {
            let sequence = first + i as i64;
            if sequence < from {
                continue;
            }
            if records.len() >= limit
                || (!records.is_empty() && bytes + record.data.len() > max_bytes)
            {
                break 'batches;
            }
            bytes += record.data.len();
            next = sequence + 1;
            records.push((sequence, record));
        }
    }
    Ok(Read { records, next, end })
}

/// The bytes of an object of the internal bucket from `offset` on, if it's
/// still there.
async fn read_range(
    app: &Arc<App>,
    key: &str,
    offset: i64,
    length: i64,
) -> anyhow::Result<Option<Bytes>> {
    let range = format!("bytes={offset}-{}", offset + length - 1);
    let response = crate::s3::objects::get::get_object(
        app,
        crate::internal::BUCKET,
        key,
        None,
        Some(&range),
        None,
        &Default::default(),
        None,
        None,
        false,
    )
    .await?;
    if response.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        anyhow::bail!("reading {key}: {}", response.status());
    }
    let data = response
        .into_body()
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("reading {key}: {e}"))?
        .to_bytes();
    anyhow::ensure!(
        data.len() as i64 == length,
        "reading {key}: got {} bytes of {length}",
        data.len()
    );
    Ok(Some(data))
}

/// The sequence number of the first record of a shard's batches that
/// arrived at `millis` or later (by their batches' times), or the shard's
/// next one if none did.
pub async fn sequence_at(
    app: &Arc<App>,
    stream: Uuid,
    shard: i32,
    millis: i64,
) -> anyhow::Result<i64> {
    let client = app.pool.get().await?;
    let at = UNIX_EPOCH + Duration::from_millis(millis.max(0) as u64);
    let row = client
        .query_opt_cached(
            "SELECT first_sequence FROM stream_batches
             WHERE stream_id = $1 AND shard = $2 AND arrived_at >= $3
             ORDER BY first_sequence LIMIT 1",
            &[&stream, &shard, &at],
        )
        .await?;
    if let Some(row) = row {
        return Ok(row.get(0));
    }
    next_sequence(app, stream, shard).await
}

/// A shard's next sequence number (0 if it's gone).
pub async fn next_sequence(app: &Arc<App>, stream: Uuid, shard: i32) -> anyhow::Result<i64> {
    Ok(app
        .pool
        .get()
        .await?
        .query_opt_cached(
            "SELECT next_sequence FROM stream_shards WHERE stream_id = $1 AND shard = $2",
            &[&stream, &shard],
        )
        .await?
        .map(|row| row.get(0))
        .unwrap_or(0))
}

/// Cleans up, for as long as the node runs.
pub async fn run(app: Arc<App>) {
    loop {
        tokio::time::sleep(SWEEP).await;
        if let Err(e) = sweep(&app).await {
            eprintln!("streams: cleaning up failed: {e:#}");
        }
    }
}

/// Deletes the index's rows past their streams' retention, then the
/// objects no row refers to that are older than `ORPHANED`.
pub async fn sweep(app: &Arc<App>) -> anyhow::Result<()> {
    let client = app.pool.get().await?;
    loop {
        let deleted = client
            .execute_cached(
                "DELETE FROM stream_batches WHERE ctid IN (
                     SELECT b.ctid FROM stream_batches b JOIN streams s ON s.id = b.stream_id
                     WHERE b.arrived_at < now() - s.retention_hours * interval '1 hour'
                     LIMIT 10000)",
                &[],
            )
            .await?;
        if deleted < 10_000 {
            break;
        }
    }
    let end = format!("{}0", PREFIX.trim_end_matches('/'));
    loop {
        let rows = client
            .query_cached(
                &format!(
                    "SELECT o.key FROM objects o
                     WHERE o.bucket = $1 AND o.key >= $2 AND o.key < $3 AND o.is_latest
                       AND o.last_modified < now() - interval '{ORPHANED}'
                       AND NOT EXISTS (SELECT 1 FROM stream_batches b WHERE b.object_key = o.key)
                     ORDER BY o.key LIMIT 1000"
                ),
                &[&crate::internal::BUCKET, &PREFIX, &end],
            )
            .await?;
        if rows.is_empty() {
            return Ok(());
        }
        for row in &rows {
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
        if rows.len() < 1000 {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn records_round_trip() {
        let records = vec![
            Record {
                key: "a".into(),
                data: b"one".to_vec(),
                arrived: 1,
            },
            Record {
                key: "ключ".into(),
                data: Vec::new(),
                arrived: -5,
            },
        ];
        let mut out = Vec::new();
        for r in &records {
            r.encode(&mut out);
        }
        assert_eq!(
            out.len(),
            records.iter().map(Record::encoded_len).sum::<usize>()
        );
        assert_eq!(decode(&out, 2).unwrap(), records);
        assert!(decode(&out, 3).is_err());
        assert!(decode(&out, 1).is_err());
        assert!(decode(&out[..out.len() - 1], 2).is_err());
    }
}
