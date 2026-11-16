//! Server access logs: a record of each request to a bucket that logs (see
//! `s3::buckets::logging`), written as S3 writes them (see `record`) to the
//! bucket its configuration names, as the `logging.s3.amazonaws.com`
//! service (see `s3::service`).
//!
//! Each node spools its own records (see `spool`) and delivers them (see
//! `delivery`): a request costs no more than the spool's write, and none for
//! a bucket that doesn't log. Which buckets do, each node rereads every few
//! seconds. Delivery is best effort, as S3's: records still in the queue
//! when Cairn ends, and those of a bucket whose target doesn't take them,
//! are lost.

pub mod delivery;
pub mod record;
pub mod spool;

use std::{
    collections::HashMap,
    io,
    net::IpAddr,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime},
};

use http_body_util::BodyExt;
use hyper::{
    HeaderMap, Method, Response, Uri, Version,
    body::{Body, Bytes, Frame, SizeHint},
};

use crate::{App, body::ResBody, db::Cached, s3::util::ErrorCode};
use record::Record;
use spool::{Line, Rotation, Spool};

/// The service a bucket's logs are written as, which its target's policy
/// must allow to write them.
pub const SERVICE: &str = "logging.s3.amazonaws.com";
/// How often a node rereads which buckets log.
const REFRESH: Duration = Duration::from_secs(10);
/// How often a node delivers its closed spool files.
const DELIVER: Duration = Duration::from_secs(60);

/// A node's access logging.
#[derive(Default)]
pub struct Logs {
    /// The buckets that log, and their owners' canonical IDs, as last read.
    buckets: RwLock<HashMap<String, String>>,
    /// None in tests that don't log.
    spool: Option<Spool>,
}

impl Logs {
    /// Logs into a spool in `dir`.
    pub fn start(dir: PathBuf, rotation: Rotation) -> io::Result<Logs> {
        Ok(Logs { buckets: RwLock::default(), spool: Some(Spool::start(dir, rotation)?) })
    }

    /// The canonical ID of the owner of `bucket`, if it logs.
    fn owner(&self, bucket: &str) -> Option<String> {
        self.spool.as_ref()?;
        self.buckets.read().unwrap().get(bucket).cloned()
    }

    /// Rereads which buckets log.
    pub async fn refresh(&self, app: &App) -> anyhow::Result<()> {
        let rows = app
            .pool
            .get()
            .await?
            .query_cached("SELECT name, account_id FROM buckets WHERE logging IS NOT NULL", &[])
            .await?;
        let buckets = rows.iter().map(|r| (r.get(0), crate::s3::util::canonical_id(r.get(1)))).collect();
        *self.buckets.write().unwrap() = buckets;
        Ok(())
    }
}

/// Rereads which buckets log, and delivers the node's records, for as long
/// as the node runs.
pub async fn run(app: Arc<App>) {
    let refreshing = async {
        loop {
            if let Err(e) = app.access_logs.refresh(&app).await {
                eprintln!("access logs: reading which buckets log failed: {e:#}");
            }
            tokio::time::sleep(REFRESH).await;
        }
    };
    let delivering = async {
        let Some(spool) = &app.access_logs.spool else { return };
        loop {
            tokio::time::sleep(DELIVER).await;
            if let Err(e) = delivery::deliver_all(&app, spool.dir()).await {
                eprintln!("access logs: delivery failed: {e:#}");
            }
        }
    };
    tokio::join!(refreshing, delivering);
}

tokio::task_local! {
    /// Who made the request the task handles, once it's authenticated.
    static REQUESTER: Mutex<Option<String>>;
}

/// Runs `f` as a request's task: what it returns, and the requester
/// `set_requester` set, if it set one.
pub async fn scope<F: Future>(f: F) -> (F::Output, Option<String>) {
    REQUESTER
        .scope(Mutex::new(None), async {
            let out = f.await;
            (out, REQUESTER.with(|r| r.lock().unwrap().take()))
        })
        .await
}

/// Sets who makes the task's request: its principal's ARN.
pub fn set_requester(arn: String) {
    let _ = REQUESTER.try_with(|r| *r.lock().unwrap() = Some(arn));
}

/// A request's record, from when it's received until its response's last
/// byte is sent.
pub struct Pending {
    record: Record,
    started: Instant,
    app: Arc<App>,
}

/// What a request is, as its record has it.
pub struct Received<'a> {
    pub method: &'a Method,
    pub uri: &'a Uri,
    pub version: Version,
    pub headers: &'a HeaderMap,
    /// The bucket it's to, and the key (as the path has it, URL-encoded).
    pub bucket: &'a str,
    pub key: &'a str,
    /// Whether it's to the bucket's website endpoint.
    pub website: bool,
    pub peer: IpAddr,
}

impl Pending {
    /// The record of a request, if its bucket logs.
    pub fn begin(app: &Arc<App>, received: Received<'_>) -> Option<Pending> {
        let owner = app.access_logs.owner(received.bucket)?;
        let headers = received.headers;
        let header = |name: hyper::header::HeaderName| headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned);
        let query = received.uri.query().unwrap_or("");
        let (signature_version, authentication_type) = record::signing(headers, query);
        let target = received.uri.path_and_query().map_or_else(|| received.uri.path(), |p| p.as_str());
        // A write's object is as large as its body.
        let object_size = match *received.method {
            Method::PUT | Method::POST if !received.key.is_empty() => headers
                .get("x-amz-decoded-content-length")
                .or_else(|| headers.get(hyper::header::CONTENT_LENGTH))
                .and_then(|v| v.to_str().ok()?.parse().ok()),
            _ => None,
        };
        let record = Record {
            owner,
            bucket: received.bucket.to_owned(),
            time: Some(SystemTime::now()),
            remote_ip: crate::s3::access::client_address(headers, Some(received.peer), &app.trusted_proxies)
                .map(|ip| ip.to_string()),
            operation: record::operation(received.method, !received.key.is_empty(), query, headers, received.website),
            key: Some(received.key.to_owned()).filter(|k| !k.is_empty()),
            request_uri: format!("{} {target} {:?}", received.method, received.version),
            object_size,
            referer: header(hyper::header::REFERER),
            user_agent: header(hyper::header::USER_AGENT),
            signature_version,
            authentication_type,
            host: header(hyper::header::HOST),
            ..Record::default()
        };
        Some(Pending { record, started: Instant::now(), app: app.clone() })
    }

    /// Records the response, once its body has been sent (or dropped): who
    /// made the request (`requester`, if it was authenticated), and its ID.
    pub fn finish(mut self, response: Response<ResBody>, requester: Option<String>, request_id: &str) -> Response<ResBody> {
        let (parts, body) = response.into_parts();
        let record = &mut self.record;
        record.requester = requester;
        record.request_id = request_id.to_owned();
        record.status = parts.status.as_u16();
        record.error_code = parts.extensions.get::<ErrorCode>().map(|c| c.0.clone());
        let header = |name: &str| parts.headers.get(name).and_then(|v| v.to_str().ok());
        record.version_id = header("x-amz-version-id").map(str::to_owned);
        // A read's object: as large as the range's whole, or the body.
        if record.object_size.is_none() && record.key.is_some() && parts.status.is_success() {
            let whole = header("content-range").and_then(|r| r.rsplit_once('/')).and_then(|(_, n)| n.parse().ok());
            record.object_size = whole.or_else(|| header("content-length").and_then(|n| n.parse().ok()));
        }
        record.turn_around_time = self.started.elapsed().as_millis() as u64;
        let body = LoggedBody { inner: body, pending: Some(self), sent: 0 }.boxed_unsync();
        Response::from_parts(parts, body)
    }

    fn done(mut self, sent: u64) {
        let Some(spool) = &self.app.access_logs.spool else { return };
        self.record.bytes_sent = sent;
        self.record.total_time = self.started.elapsed().as_millis() as u64;
        let time = self.record.time.unwrap_or_else(SystemTime::now);
        spool.append(Line::encode(&self.record.bucket, time, &self.record.line()));
    }
}

/// A response body that records its request once it's done.
struct LoggedBody {
    inner: ResBody,
    pending: Option<Pending>,
    sent: u64,
}

impl Drop for LoggedBody {
    fn drop(&mut self) {
        if let Some(pending) = self.pending.take() {
            pending.done(self.sent);
        }
    }
}

impl Body for LoggedBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &poll
            && let Some(data) = frame.data_ref()
        {
            this.sent += data.len() as u64;
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
