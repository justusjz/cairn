use std::io::{self, SeekFrom};
use std::pin::Pin;
use std::task::{Context, Poll};

use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::{
    Response,
    body::{Body, Bytes, Frame, Incoming},
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt},
    sync::mpsc,
};

/// Unified response body for the client and peer servers: a boxed body that may
/// be a buffered `Full` or a stream of chunks fed over a channel.
pub type ResBody = UnsyncBoxBody<Bytes, io::Error>;

/// Sender half feeding a [`channel_body`].
pub type FrameSender = mpsc::Sender<io::Result<Frame<Bytes>>>;

const CHUNK_SIZE: usize = 64 * 1024;

/// Boxes a buffered `Full` response into the streaming-capable [`ResBody`].
pub fn box_response(resp: Response<Full<Bytes>>) -> Response<ResBody> {
    resp.map(|body| body.map_err(|never| match never {}).boxed_unsync())
}

/// A response body fed by an mpsc channel of frames.
struct ChannelBody {
    rx: mpsc::Receiver<io::Result<Frame<Bytes>>>,
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        self.get_mut().rx.poll_recv(cx)
    }
}

/// A streaming body plus the channel sender that feeds it. Send `Ok(frame)`s to
/// stream data, drop the sender to finish cleanly, or send `Err` to fault it.
pub fn channel_body() -> (FrameSender, ResBody) {
    let (tx, rx) = mpsc::channel(4);
    (tx, ChannelBody { rx }.boxed_unsync())
}

/// Reads a file — or, with `Some((offset, length))`, just that byte range of it —
/// and forwards it to `tx` in chunks, until done or the receiver is dropped.
pub async fn send_file(
    mut file: File,
    range: Option<(u64, u64)>,
    tx: &FrameSender,
) -> io::Result<()> {
    // Bytes still to send; u64::MAX means "to EOF" (the whole file).
    let mut remaining = match range {
        Some((offset, length)) => {
            file.seek(SeekFrom::Start(offset)).await?;
            length
        }
        None => u64::MAX,
    };
    let mut buf = vec![0u8; CHUNK_SIZE];
    while remaining > 0 {
        let cap = remaining.min(CHUNK_SIZE as u64) as usize;
        let n = file.read(&mut buf[..cap]).await?;
        if n == 0 {
            break; // EOF (or offset past end)
        }
        remaining -= n as u64;
        if tx
            .send(Ok(Frame::data(Bytes::copy_from_slice(&buf[..n]))))
            .await
            .is_err()
        {
            break; // receiver gone (client hung up)
        }
    }
    Ok(())
}

/// Forwards a response body's data frames to `tx`, until the body ends or the
/// receiver is dropped.
pub async fn send_incoming(mut body: Incoming, tx: &FrameSender) -> io::Result<()> {
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(io::Error::other)?;
        if let Ok(data) = frame.into_data() {
            if tx.send(Ok(Frame::data(data))).await.is_err() {
                return Ok(());
            }
        }
    }
    Ok(())
}
