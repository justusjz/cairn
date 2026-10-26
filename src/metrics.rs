//! What a node keeps track of for the dashboard: the S3 requests it served, and
//! how its maintenance passes went. Kept in memory only, so it starts over when
//! the node restarts, and each node only knows its own. The dashboard asks every
//! live node for its share (see `peer`'s `/stats`).

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http_body_util::BodyExt;
use hyper::{
    HeaderMap, Method, StatusCode,
    body::{Body, Bytes, Frame, SizeHint},
};
use serde_json::{Value, json};

use crate::body::ResBody;

/// How much time a slot of the request history covers.
pub const SLOT: Duration = Duration::from_secs(10);
/// How many slots of request history are kept: an hour's worth.
const SLOTS: usize = 360;
/// How many maintenance events are kept.
const EVENTS: usize = 100;

/// Seconds since the Unix epoch.
pub fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// The S3 operations requests are counted by. Coarser than S3's own list: every
/// multipart call is one, and so is every bucket-level call but the listings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    ListBuckets,
    ListObjects,
    GetObject,
    HeadObject,
    PutObject,
    CopyObject,
    DeleteObject,
    DeleteObjects,
    Multipart,
    Bucket,
}

impl Op {
    const ALL: [Op; 10] = [
        Op::ListBuckets,
        Op::ListObjects,
        Op::GetObject,
        Op::HeadObject,
        Op::PutObject,
        Op::CopyObject,
        Op::DeleteObject,
        Op::DeleteObjects,
        Op::Multipart,
        Op::Bucket,
    ];

    fn name(self) -> &'static str {
        match self {
            Op::ListBuckets => "ListBuckets",
            Op::ListObjects => "ListObjects",
            Op::GetObject => "GetObject",
            Op::HeadObject => "HeadObject",
            Op::PutObject => "PutObject",
            Op::CopyObject => "CopyObject",
            Op::DeleteObject => "DeleteObject",
            Op::DeleteObjects => "DeleteObjects",
            Op::Multipart => "Multipart",
            Op::Bucket => "Bucket",
        }
    }

    /// Which operation an S3 request is, along the lines of `s3::handle`'s
    /// routing.
    pub fn classify(method: &Method, path: &str, query: &str, headers: &HeaderMap) -> Op {
        let has = |name: &str| crate::s3::util::query_param(query, name).is_some();
        let path = path.trim_start_matches('/');
        if path.is_empty() {
            return Op::ListBuckets;
        }
        let key = path.split_once('/').map(|(_, key)| key).unwrap_or("");
        if key.is_empty() {
            return match *method {
                Method::GET if has("versions") => Op::ListObjects,
                Method::GET if has("versioning") => Op::Bucket,
                Method::GET if crate::s3::util::bucket_subresource_stub(query).is_some() => {
                    Op::Bucket
                }
                Method::GET => Op::ListObjects,
                Method::POST if has("delete") => Op::DeleteObjects,
                _ => Op::Bucket,
            };
        }
        if has("uploadId") || has("uploads") {
            return Op::Multipart;
        }
        match *method {
            Method::GET => Op::GetObject,
            Method::HEAD => Op::HeadObject,
            Method::PUT if headers.contains_key("x-amz-copy-source") => Op::CopyObject,
            Method::PUT => Op::PutObject,
            Method::DELETE => Op::DeleteObject,
            _ => Op::Bucket,
        }
    }
}

/// Counts of requests, by how they ended, and of what they moved.
#[derive(Clone, Copy, Default)]
struct Counts {
    requests: u64,
    /// Answered with a 4xx: the client's fault (including denied requests).
    client_errors: u64,
    /// Answered with a 5xx: a fault, or too few nodes.
    server_errors: u64,
    bytes_in: u64,
    bytes_out: u64,
    /// The sum of the times until the response's head was ready.
    latency_us: u64,
}

impl Counts {
    fn count(&mut self, status: StatusCode, bytes_in: u64, latency: Duration) {
        self.requests += 1;
        if status.is_client_error() {
            self.client_errors += 1;
        } else if status.is_server_error() {
            self.server_errors += 1;
        }
        self.bytes_in += bytes_in;
        self.latency_us += latency.as_micros() as u64;
    }

    fn to_json(self) -> Value {
        json!({
            "requests": self.requests,
            "client_errors": self.client_errors,
            "server_errors": self.server_errors,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "latency_us": self.latency_us,
        })
    }
}

#[derive(Default)]
struct Requests {
    /// Since the node started, by operation (in `Op::ALL`'s order).
    ops: [Counts; Op::ALL.len()],
    /// The most recent slots, oldest first, each with the slot number it
    /// covers (Unix time divided by `SLOT`). Slots without requests are left
    /// out. The numbers are the same on every node, so the slots of several
    /// nodes add up.
    history: VecDeque<(u64, Counts)>,
}

impl Requests {
    /// The current slot, created if need be, with older ones dropped.
    fn slot(&mut self) -> &mut Counts {
        let slot = (now_secs() / SLOT.as_secs_f64()) as u64;
        if self.history.back().is_none_or(|&(s, _)| s < slot) {
            self.history.push_back((slot, Counts::default()));
        }
        while self
            .history
            .front()
            .is_some_and(|&(s, _)| s + SLOTS as u64 <= slot)
        {
            self.history.pop_front();
        }
        &mut self.history.back_mut().unwrap().1
    }
}

/// How a node's maintenance passes have gone.
#[derive(Default)]
struct Maintenance {
    passes: u64,
    /// When the pass that's running started.
    running_since: Option<f64>,
    last_started: Option<f64>,
    last_duration: Option<f64>,
    /// Where the GC's file sweep is, of `store::SHARDS`.
    sweep_shard: u32,
    gc_pending: u64,
    gc_files: u64,
    gc_dirs: u64,
    gc_errors: u64,
    pack_jobs: u64,
    pack_failed: u64,
    pack_blobs: u64,
    pack_parts: u64,
    pack_bytes: u64,
    /// The most recent things a pass did or failed at, oldest first.
    events: VecDeque<Event>,
}

struct Event {
    time: f64,
    source: &'static str,
    error: bool,
    message: String,
}

/// A node's own metrics. Recording takes a brief lock.
pub struct Metrics {
    started: f64,
    /// Requests whose response hasn't been sent in full yet.
    in_flight: AtomicI64,
    requests: Mutex<Requests>,
    maintenance: Mutex<Maintenance>,
}

impl Default for Metrics {
    fn default() -> Self {
        Metrics {
            started: now_secs(),
            in_flight: AtomicI64::new(0),
            requests: Mutex::default(),
            maintenance: Mutex::default(),
        }
    }
}

impl Metrics {
    /// Counts a request as in flight until the returned guard is dropped.
    pub fn begin(self: &Arc<Self>) -> InFlight {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        InFlight(self.clone())
    }

    /// Records a request whose response head is ready, and wraps its body, so
    /// that the bytes sent are counted too. `guard` is held until the body has
    /// been sent (or dropped).
    pub fn record(
        self: &Arc<Self>,
        op: Op,
        status: StatusCode,
        bytes_in: u64,
        latency: Duration,
        body: ResBody,
        guard: InFlight,
    ) -> ResBody {
        let mut requests = self.requests.lock().unwrap();
        let index = Op::ALL.iter().position(|&o| o == op).unwrap();
        requests.ops[index].count(status, bytes_in, latency);
        requests.slot().count(status, bytes_in, latency);
        drop(requests);
        CountedBody {
            inner: body,
            metrics: self.clone(),
            op: index,
            _guard: guard,
        }
        .boxed_unsync()
    }

    fn sent(&self, op: usize, bytes: u64) {
        let mut requests = self.requests.lock().unwrap();
        requests.ops[op].bytes_out += bytes;
        requests.slot().bytes_out += bytes;
    }

    pub fn pass_started(&self, sweep_shard: u32) {
        let mut m = self.maintenance.lock().unwrap();
        let now = now_secs();
        m.running_since = Some(now);
        m.last_started = Some(now);
        m.sweep_shard = sweep_shard;
    }

    pub fn pass_finished(&self) {
        let mut m = self.maintenance.lock().unwrap();
        m.passes += 1;
        if let Some(started) = m.running_since.take() {
            m.last_duration = Some(now_secs() - started);
        }
    }

    pub fn gc_done(&self, report: &crate::gc::Report) {
        let mut m = self.maintenance.lock().unwrap();
        let (pending, files, dirs) = report.counts();
        m.gc_pending += pending as u64;
        m.gc_files += files as u64;
        m.gc_dirs += dirs as u64;
        m.gc_errors += report.error_count() as u64;
        if !report.is_empty() {
            let error = report.error_count() > 0;
            m.event("gc", error, report.to_string());
        }
    }

    pub fn pack_done(&self, report: &crate::packer::JobReport) {
        let mut m = self.maintenance.lock().unwrap();
        let (sources, parts, bytes) = report.counts();
        m.pack_jobs += 1;
        m.pack_blobs += sources as u64;
        m.pack_parts += parts as u64;
        m.pack_bytes += bytes;
        m.event("packer", false, report.to_string());
    }

    pub fn pack_failed(&self, message: String) {
        let mut m = self.maintenance.lock().unwrap();
        m.pack_failed += 1;
        m.event("packer", true, message);
    }

    pub fn maintenance_failed(&self, message: String) {
        self.maintenance
            .lock()
            .unwrap()
            .event("maintenance", true, message);
    }

    /// Everything, as the dashboard reports it.
    pub fn to_json(&self) -> Value {
        let requests = self.requests.lock().unwrap();
        let ops: Vec<Value> = Op::ALL
            .iter()
            .zip(&requests.ops)
            .map(|(op, counts)| {
                let mut v = counts.to_json();
                v["op"] = op.name().into();
                v
            })
            .collect();
        let history: Vec<Value> = requests
            .history
            .iter()
            .map(|&(slot, counts)| {
                let mut v = counts.to_json();
                v["t"] = (slot * SLOT.as_secs()).into();
                v
            })
            .collect();
        drop(requests);
        let m = self.maintenance.lock().unwrap();
        let events: Vec<Value> = m
            .events
            .iter()
            .map(|e| {
                json!({"time": e.time, "source": e.source, "error": e.error, "message": e.message})
            })
            .collect();
        json!({
            "started_at": self.started,
            "in_flight": self.in_flight.load(Ordering::Relaxed),
            "requests": {
                "slot_secs": SLOT.as_secs(),
                "ops": ops,
                "history": history,
            },
            "maintenance": {
                "interval_secs": crate::MAINTENANCE_INTERVAL.as_secs(),
                "passes": m.passes,
                "running_since": m.running_since,
                "last_started": m.last_started,
                "last_duration": m.last_duration,
                "sweep_shard": m.sweep_shard,
                "shards": crate::store::SHARDS,
                "gc": {
                    "pending": m.gc_pending,
                    "files": m.gc_files,
                    "dirs": m.gc_dirs,
                    "errors": m.gc_errors,
                },
                "packer": {
                    "jobs": m.pack_jobs,
                    "failed": m.pack_failed,
                    "blobs": m.pack_blobs,
                    "parts": m.pack_parts,
                    "bytes": m.pack_bytes,
                },
                "events": events,
            },
        })
    }
}

impl Maintenance {
    fn event(&mut self, source: &'static str, error: bool, message: String) {
        if self.events.len() == EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(Event {
            time: now_secs(),
            source,
            error,
            message,
        });
    }
}

/// A request in flight, until dropped.
pub struct InFlight(Arc<Metrics>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A response body that counts the bytes it sends.
struct CountedBody {
    inner: ResBody,
    metrics: Arc<Metrics>,
    op: usize,
    _guard: InFlight,
}

impl Body for CountedBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &poll
            && let Some(data) = frame.data_ref()
        {
            this.metrics.sent(this.op, data.len() as u64);
        }
        poll
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// How many bytes of payload a request brings, going by its headers: the
/// decoded length of an `aws-chunked` body, else its Content-Length.
pub fn bytes_in(headers: &HeaderMap) -> u64 {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
    };
    header("x-amz-decoded-content-length")
        .or_else(|| header("content-length"))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(method: Method, path: &str, query: &str) -> Op {
        Op::classify(&method, path, query, &HeaderMap::new())
    }

    #[test]
    fn classifies_requests() {
        assert_eq!(classify(Method::GET, "/", ""), Op::ListBuckets);
        assert_eq!(classify(Method::GET, "/b", "list-type=2"), Op::ListObjects);
        assert_eq!(classify(Method::GET, "/b", "versions"), Op::ListObjects);
        assert_eq!(classify(Method::GET, "/b", "versioning"), Op::Bucket);
        assert_eq!(classify(Method::GET, "/b", "location"), Op::Bucket);
        assert_eq!(classify(Method::PUT, "/b", ""), Op::Bucket);
        assert_eq!(classify(Method::POST, "/b", "delete"), Op::DeleteObjects);
        assert_eq!(classify(Method::GET, "/b/k", ""), Op::GetObject);
        assert_eq!(classify(Method::HEAD, "/b/k/x", ""), Op::HeadObject);
        assert_eq!(classify(Method::PUT, "/b/k", ""), Op::PutObject);
        assert_eq!(
            classify(Method::DELETE, "/b/k", "versionId=1"),
            Op::DeleteObject
        );
        assert_eq!(classify(Method::POST, "/b/k", "uploads"), Op::Multipart);
        assert_eq!(
            classify(Method::PUT, "/b/k", "uploadId=1&partNumber=1"),
            Op::Multipart
        );
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-copy-source", "a/b".parse().unwrap());
        assert_eq!(
            Op::classify(&Method::PUT, "/b/k", "", &headers),
            Op::CopyObject
        );
    }

    #[tokio::test]
    async fn counts_requests_and_bytes() {
        let metrics = Arc::new(Metrics::default());
        let guard = metrics.begin();
        let body = http_body_util::Full::new(Bytes::from_static(b"hello"))
            .map_err(|never| match never {})
            .boxed_unsync();
        let body = metrics.record(
            Op::GetObject,
            StatusCode::OK,
            3,
            Duration::from_millis(2),
            body,
            guard,
        );
        assert_eq!(metrics.in_flight.load(Ordering::Relaxed), 1);
        assert_eq!(body.collect().await.unwrap().to_bytes(), "hello");
        assert_eq!(metrics.in_flight.load(Ordering::Relaxed), 0);
        let json = metrics.to_json();
        let get = &json["requests"]["ops"][2];
        assert_eq!(get["op"], "GetObject");
        assert_eq!(get["requests"], 1);
        assert_eq!(get["bytes_in"], 3);
        assert_eq!(get["bytes_out"], 5);
        assert_eq!(get["latency_us"], 2000);
        assert_eq!(json["requests"]["history"][0]["bytes_out"], 5);
    }
}
