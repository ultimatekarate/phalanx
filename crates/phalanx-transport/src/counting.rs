// crates/phalanx-transport/src/counting.rs
//
// Socket-level I/O counters for the libp2p transport layer. Wraps the
// muxer output so that every `AsyncRead::poll_read` and `AsyncWrite::poll_write`
// on a substream increments shared atomic counters. The wrapper sits between
// the transport and the swarm — all protocol traffic flows through it.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use futures::{AsyncRead, AsyncWrite};
use libp2p::core::muxing::{StreamMuxer, StreamMuxerBox, StreamMuxerEvent, SubstreamBox};
use tokio::time::Instant;

/// Direction tag for a single `IoLogEntry`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoKind {
    Read,
    Write,
}

/// A single socket-level IO event. Recorded when `AdapterConfig::enable_io_log`
/// is set; used by benchmark tests to measure inter-IO gaps, per-substream
/// attribution, and write-size distributions. Uses `tokio::time::Instant`
/// so timestamps are directly comparable to those in `swarm_wake_log`.
#[derive(Clone, Copy, Debug)]
pub struct IoLogEntry {
    pub at: Instant,
    pub kind: IoKind,
    pub bytes: u64,
    pub substream_id: u64,
}

/// Shared counters for socket-level I/O. Created once in the factory,
/// cloned into every `CountingMuxer`, and stored on the adapter for
/// external read-out. When `io_log` is `Some`, every `poll_read` /
/// `poll_write` on any substream appends to the shared log.
#[derive(Clone, Debug, Default)]
pub struct IoCounters {
    pub bytes_sent: Arc<AtomicU64>,
    pub bytes_received: Arc<AtomicU64>,
    pub io_ops: Arc<AtomicU64>,
    pub io_log: Option<Arc<Mutex<Vec<IoLogEntry>>>>,
}

impl IoCounters {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct with an empty, ready-to-populate `io_log`. Benchmark use only.
    pub fn with_io_log() -> Self {
        Self {
            io_log: Some(Arc::new(Mutex::new(Vec::new()))),
            ..Self::default()
        }
    }

    pub fn diagnostic(&self) -> String {
        format!(
            "IoCounters {{ bytes_sent: {}, bytes_received: {}, io_ops: {} }}",
            self.bytes_sent.load(Ordering::Relaxed),
            self.bytes_received.load(Ordering::Relaxed),
            self.io_ops.load(Ordering::Relaxed),
        )
    }
}

/// A stream wrapper that counts bytes read/written and increments
/// a shared `io_ops` counter on each successful I/O operation. When
/// `io_log` is `Some`, each successful op also appends an `IoLogEntry`.
pub struct CountingStream {
    inner: SubstreamBox,
    bytes_sent: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    io_ops: Arc<AtomicU64>,
    io_log: Option<Arc<Mutex<Vec<IoLogEntry>>>>,
    substream_id: u64,
}

impl CountingStream {
    fn new(
        inner: SubstreamBox,
        bytes_sent: Arc<AtomicU64>,
        bytes_received: Arc<AtomicU64>,
        io_ops: Arc<AtomicU64>,
        io_log: Option<Arc<Mutex<Vec<IoLogEntry>>>>,
        substream_id: u64,
    ) -> Self {
        Self {
            inner,
            bytes_sent,
            bytes_received,
            io_ops,
            io_log,
            substream_id,
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
            if let Some(ref log) = self.io_log {
                if let Ok(mut guard) = log.lock() {
                    guard.push(IoLogEntry {
                        at: Instant::now(),
                        kind: IoKind::Read,
                        bytes: *n as u64,
                        substream_id: self.substream_id,
                    });
                }
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
            if let Some(ref log) = self.io_log {
                if let Ok(mut guard) = log.lock() {
                    guard.push(IoLogEntry {
                        at: Instant::now(),
                        kind: IoKind::Write,
                        bytes: *n as u64,
                        substream_id: self.substream_id,
                    });
                }
            }
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
/// we can use `Pin::new()` for delegation. Threads the shared `io_log`
/// handle into each substream it creates, so a single log aggregates
/// IO events across all muxers (QUIC, TCP, Relay) and all substreams.
pub struct CountingMuxer {
    inner: StreamMuxerBox,
    bytes_sent: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    io_ops: Arc<AtomicU64>,
    io_log: Option<Arc<Mutex<Vec<IoLogEntry>>>>,
    /// Counts how many substreams have been opened through this muxer.
    /// The fetched pre-increment value is passed through as each substream's
    /// `substream_id`, giving a faithful per-protocol IO breakdown (each libp2p
    /// substream carries one protocol for its lifetime).
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
            io_log: counters.io_log.clone(),
            substreams_opened: Arc::new(AtomicU64::new(0)),
        }
    }

    fn wrap_substream(&self, substream: SubstreamBox, substream_id: u64) -> CountingStream {
        CountingStream::new(
            substream,
            self.bytes_sent.clone(),
            self.bytes_received.clone(),
            self.io_ops.clone(),
            self.io_log.clone(),
            substream_id,
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
            self.wrap_substream(sub, n)
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
            self.wrap_substream(sub, n)
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
        assert!(counters.io_log.is_none());
    }

    #[test]
    fn io_counters_clone_shares_state() {
        let a = IoCounters::new();
        let b = a.clone();
        a.bytes_sent.fetch_add(42, Ordering::Relaxed);
        assert_eq!(b.bytes_sent.load(Ordering::Relaxed), 42);
    }

    #[test]
    fn io_counters_with_log_shares_log_across_clones() {
        let a = IoCounters::with_io_log();
        let b = a.clone();
        let a_log = a.io_log.as_ref().expect("with_io_log initializes Some");
        a_log.lock().unwrap().push(IoLogEntry {
            at: Instant::now(),
            kind: IoKind::Read,
            bytes: 7,
            substream_id: 0,
        });
        let b_log = b.io_log.expect("clone should share Some log");
        assert_eq!(b_log.lock().unwrap().len(), 1);
    }
}
