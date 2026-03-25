// crates/phalanx-transport/src/counting.rs
//
// Socket-level I/O counters for the libp2p transport layer. Wraps the
// muxer output so that every `AsyncRead::poll_read` and `AsyncWrite::poll_write`
// on a substream increments shared atomic counters. The wrapper sits between
// the transport and the swarm — all protocol traffic flows through it.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::{AsyncRead, AsyncWrite};
use libp2p::core::muxing::{StreamMuxer, StreamMuxerBox, StreamMuxerEvent, SubstreamBox};

/// Shared counters for socket-level I/O. Created once in the factory,
/// cloned into every `CountingMuxer`, and stored on the adapter for
/// external read-out.
#[derive(Clone, Debug)]
pub struct IoCounters {
    pub bytes_sent: Arc<AtomicU64>,
    pub bytes_received: Arc<AtomicU64>,
    pub io_ops: Arc<AtomicU64>,
}

impl IoCounters {
    pub fn new() -> Self {
        Self {
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            io_ops: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl IoCounters {
    pub fn diagnostic(&self) -> String {
        format!(
            "IoCounters {{ bytes_sent: {}, bytes_received: {}, io_ops: {} }}",
            self.bytes_sent.load(Ordering::Relaxed),
            self.bytes_received.load(Ordering::Relaxed),
            self.io_ops.load(Ordering::Relaxed),
        )
    }
}

impl Default for IoCounters {
    fn default() -> Self {
        Self::new()
    }
}

/// A stream wrapper that counts bytes read/written and increments
/// a shared `io_ops` counter on each successful I/O operation.
pub struct CountingStream {
    inner: SubstreamBox,
    bytes_sent: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    io_ops: Arc<AtomicU64>,
}

impl CountingStream {
    fn new(
        inner: SubstreamBox,
        bytes_sent: Arc<AtomicU64>,
        bytes_received: Arc<AtomicU64>,
        io_ops: Arc<AtomicU64>,
    ) -> Self {
        Self {
            inner,
            bytes_sent,
            bytes_received,
            io_ops,
        }
    }
}

impl AsyncRead for CountingStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            let prev = self.bytes_received.fetch_add(*n as u64, Ordering::Relaxed);
            self.io_ops.fetch_add(1, Ordering::Relaxed);
            if prev == 0 {
                eprintln!("[CountingStream] first read: {n} bytes");
            }
        }
        result
    }
}

impl AsyncWrite for CountingStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            self.bytes_sent.fetch_add(*n as u64, Ordering::Relaxed);
            self.io_ops.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

/// A muxer wrapper that intercepts substream creation and wraps each
/// substream with `CountingStream`. `StreamMuxerBox` is `Unpin`, so
/// we can use `Pin::new()` for delegation.
pub struct CountingMuxer {
    inner: StreamMuxerBox,
    bytes_sent: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    io_ops: Arc<AtomicU64>,
    /// Diagnostic: counts how many substreams have been opened through this muxer.
    pub substreams_opened: Arc<AtomicU64>,
}

impl CountingMuxer {
    /// Wrap a `StreamMuxerBox` with counting. The returned muxer can be
    /// re-boxed via `StreamMuxerBox::new(counting_muxer)`.
    pub fn wrap(inner: StreamMuxerBox, counters: &IoCounters) -> Self {
        Self {
            inner,
            bytes_sent: counters.bytes_sent.clone(),
            bytes_received: counters.bytes_received.clone(),
            io_ops: counters.io_ops.clone(),
            substreams_opened: Arc::new(AtomicU64::new(0)),
        }
    }

    fn wrap_substream(&self, substream: SubstreamBox) -> CountingStream {
        CountingStream::new(
            substream,
            self.bytes_sent.clone(),
            self.bytes_received.clone(),
            self.io_ops.clone(),
        )
    }
}

impl StreamMuxer for CountingMuxer {
    type Substream = CountingStream;
    type Error = io::Error;

    fn poll_inbound(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        let counter = self.substreams_opened.clone();
        Pin::new(&mut self.inner).poll_inbound(cx).map_ok(|sub| {
            let n = counter.fetch_add(1, Ordering::Relaxed);
            eprintln!("[CountingMuxer] poll_inbound substream #{n}");
            self.wrap_substream(sub)
        })
    }

    fn poll_outbound(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        let counter = self.substreams_opened.clone();
        Pin::new(&mut self.inner).poll_outbound(cx).map_ok(|sub| {
            let n = counter.fetch_add(1, Ordering::Relaxed);
            eprintln!("[CountingMuxer] poll_outbound substream #{n}");
            self.wrap_substream(sub)
        })
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<StreamMuxerEvent, Self::Error>> {
        Pin::new(&mut self.inner).poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_counters_start_at_zero() {
        let counters = IoCounters::new();
        assert_eq!(counters.bytes_sent.load(Ordering::Relaxed), 0);
        assert_eq!(counters.bytes_received.load(Ordering::Relaxed), 0);
        assert_eq!(counters.io_ops.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn io_counters_clone_shares_state() {
        let a = IoCounters::new();
        let b = a.clone();
        a.bytes_sent.fetch_add(42, Ordering::Relaxed);
        assert_eq!(b.bytes_sent.load(Ordering::Relaxed), 42);
    }
}
