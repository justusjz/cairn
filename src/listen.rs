//! Serving HTTP to clients that may be hostile: the S3 API and the console.
//! A client can't hold more than its share of the node by connecting and
//! going quiet: a connection may sit idle, or take its time over a request's
//! head, for `HEAD_TIMEOUT`; a request's body may stall for `BODY_TIMEOUT`,
//! and a response, unread, for `WRITE_TIMEOUT` (as S3 closes a connection
//! that's "not read from or written to within the timeout period"). At most
//! so many connections are served at once; more wait to be accepted. And a
//! failure to accept one (no file descriptors left, say) is waited out, not
//! the end of the server.

use std::error::Error as StdError;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{Sleep, sleep};

/// How long a connection may wait for a request's head, from when it's ready
/// for one: idle between requests too. (Tests wait less.)
const HEAD_TIMEOUT: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 30 });
/// How long a request's body may send nothing while it's read.
const BODY_TIMEOUT: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 30 });
/// How long a response may wait for the client to take any of it.
const WRITE_TIMEOUT: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 60 });
/// How long to wait before accepting again, after accepting failed.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(250);

type BoxError = Box<dyn StdError + Send + Sync>;

/// Serves `listener`'s connections, at most `max_connections` at once, each
/// with the service `service` makes for its client's address, until
/// `shutdown` resolves; then waits for the requests in flight to finish.
pub async fn serve<F, S, B>(
    listener: TcpListener,
    max_connections: usize,
    shutdown: impl Future<Output = ()>,
    mut service: F,
) where
    F: FnMut(SocketAddr) -> S,
    S: Service<Request<Incoming>, Response = Response<B>> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<BoxError>,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    let graceful = GracefulShutdown::new();
    let connections = Arc::new(Semaphore::new(max_connections));
    tokio::pin!(shutdown);
    loop {
        let permit = tokio::select! {
            permit = connections.clone().acquire_owned() => permit.expect("the semaphore is never closed"),
            () = &mut shutdown => break,
        };
        let (stream, addr) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(e) => {
                    eprintln!("accepting a connection on {:?}: {e}", listener.local_addr().ok());
                    sleep(ACCEPT_BACKOFF).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let conn = http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(HEAD_TIMEOUT)
            .serve_connection(TokioIo::new(Stalling::new(stream)), service(addr));
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            if let Err(e) = watcher.watch(conn).await
                && !timed_out(&e)
            {
                eprintln!("Error serving connection: {e:?}");
            }
            drop(permit);
        });
    }
    drop(listener);
    graceful.shutdown().await;
}

/// Whether a connection ended because its client was too slow: nothing
/// worth logging.
fn timed_out(e: &hyper::Error) -> bool {
    e.is_timeout()
        || e.source()
            .and_then(|s| s.downcast_ref::<io::Error>())
            .is_some_and(|e| e.kind() == io::ErrorKind::TimedOut)
}

/// A client's request body, which fails with `ClientTimedOut` if the client
/// sends none of it for `BODY_TIMEOUT` while it's read.
pub struct ClientBody {
    body: Incoming,
    waiting: Option<Pin<Box<Sleep>>>,
}

impl ClientBody {
    pub fn new(body: Incoming) -> Self {
        ClientBody { body, waiting: None }
    }
}

/// Why a request failed: its client sent (or took) nothing for too long.
/// Answered with S3's 400 RequestTimeout.
#[derive(Debug)]
pub struct ClientTimedOut;

impl std::fmt::Display for ClientTimedOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the client sent nothing for too long")
    }
}

impl StdError for ClientTimedOut {}

impl ClientTimedOut {
    /// Whether `e` is (or was caused by) a client's timing out.
    pub fn caused(e: &anyhow::Error) -> bool {
        e.chain().any(|e| {
            e.is::<ClientTimedOut>()
                || e.downcast_ref::<io::Error>().and_then(|e| e.get_ref()).is_some_and(|e| e.is::<ClientTimedOut>())
        })
    }
}

impl Body for ClientBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.body).poll_frame(cx) {
            Poll::Ready(frame) => {
                this.waiting = None;
                Poll::Ready(frame.map(|f| f.map_err(io::Error::other)))
            }
            Poll::Pending => {
                let waiting = this.waiting.get_or_insert_with(|| Box::pin(sleep(BODY_TIMEOUT)));
                ready!(waiting.as_mut().poll(cx));
                this.waiting = None;
                Poll::Ready(Some(Err(io::Error::new(io::ErrorKind::TimedOut, ClientTimedOut))))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

/// A connection whose writes fail if the client takes nothing for
/// `WRITE_TIMEOUT`. (Its reads can't: hyper reads while a request is being
/// handled, to notice the client leaving, and that may take long.)
struct Stalling {
    stream: TcpStream,
    stalled: Option<Pin<Box<Sleep>>>,
}

impl Stalling {
    fn new(stream: TcpStream) -> Self {
        Stalling { stream, stalled: None }
    }

    /// `poll`'s result, unless the client has taken nothing for too long.
    fn timed<T>(&mut self, cx: &mut Context<'_>, poll: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        if poll.is_ready() {
            self.stalled = None;
            return poll;
        }
        let stalled = self.stalled.get_or_insert_with(|| Box::pin(sleep(WRITE_TIMEOUT)));
        ready!(stalled.as_mut().poll(cx));
        self.stalled = None;
        Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, ClientTimedOut)))
    }
}

impl AsyncRead for Stalling {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stalling {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.stream).poll_write(cx, buf);
        self.timed(cx, poll)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.stream).poll_write_vectored(cx, bufs);
        self.timed(cx, poll)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let poll = Pin::new(&mut self.stream).poll_flush(cx);
        self.timed(cx, poll)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let poll = Pin::new(&mut self.stream).poll_shutdown(cx);
        self.timed(cx, poll)
    }
}

/// Raises the process's soft limit on open files to its hard limit, as a
/// server that holds a file descriptor per connection needs; returns the
/// limit it has now.
pub fn raise_open_files_limit() -> io::Result<u64> {
    let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit and setrlimit only access `limit`, which outlives them.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
            return Err(io::Error::last_os_error());
        }
        if limit.rlim_cur < limit.rlim_max {
            limit.rlim_cur = limit.rlim_max;
            if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(limit.rlim_cur as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A server answering "ok" to anything, whose body it reads first.
    async fn server(max_connections: usize) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, max_connections, std::future::pending(), |_| {
            hyper::service::service_fn(|req: Request<Incoming>| async move {
                use http_body_util::BodyExt;
                let read = ClientBody::new(req.into_body()).collect().await;
                let answer = if read.is_ok() { "ok" } else { "timed out" };
                Ok::<_, std::convert::Infallible>(Response::new(http_body_util::Full::new(Bytes::from(answer))))
            })
        }));
        addr
    }

    /// Waits for the server to close `stream`, which it must within `within`.
    async fn closed(stream: &mut TcpStream, within: Duration) -> Vec<u8> {
        let mut answer = Vec::new();
        tokio::time::timeout(within, stream.read_to_end(&mut answer)).await.expect("closed").unwrap();
        answer
    }

    #[tokio::test]
    async fn closes_a_connection_that_sends_no_head() {
        let addr = server(10).await;
        let mut quiet = TcpStream::connect(addr).await.unwrap();
        quiet.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").await.unwrap();
        closed(&mut quiet, HEAD_TIMEOUT + Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn fails_a_body_that_stalls() {
        let addr = server(10).await;
        let mut slow = TcpStream::connect(addr).await.unwrap();
        slow.write_all(b"PUT / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nab").await.unwrap();
        let answer = closed(&mut slow, BODY_TIMEOUT + HEAD_TIMEOUT + Duration::from_secs(1)).await;
        assert!(String::from_utf8_lossy(&answer).ends_with("timed out"), "{answer:?}");
    }

    /// Past the cap, a connection waits to be served until one closes.
    #[tokio::test]
    async fn serves_at_most_so_many_connections() {
        let addr = server(1).await;
        let mut first = TcpStream::connect(addr).await.unwrap();
        let mut second = TcpStream::connect(addr).await.unwrap();
        second.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut byte = [0u8; 1];
        assert!(tokio::time::timeout(Duration::from_millis(300), second.read(&mut byte)).await.is_err());
        first.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await.unwrap();
        closed(&mut first, Duration::from_secs(1)).await;
        let answer = closed(&mut second, Duration::from_secs(1)).await;
        assert!(String::from_utf8_lossy(&answer).ends_with("ok"), "{answer:?}");
    }
}
