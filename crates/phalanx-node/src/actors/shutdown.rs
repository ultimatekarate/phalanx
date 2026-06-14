// crates/phalanx-node/src/actors/shutdown.rs

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Notify;

/// Broadcast-style cancellation signal shared by every MeshSentinel-spawned task.
///
/// # Why not `tokio_util::CancellationToken`?
///
/// `CancellationToken` is the canonical tool for this job and supports
/// hierarchical child tokens — nicer than what's implemented here. We
/// deliberately do not add the `tokio-util` workspace dependency for a
/// single-task need. The vitals daemon already uses a `tokio::sync::oneshot`
/// for shutdown, and `Arc<Notify>` is the natural multi-consumer extension
/// of that idiom. If a second consumer of structured cancellation ever
/// appears, the right move is to adopt `tokio-util` and delete this type —
/// not to grow it into a reimplementation of `CancellationToken`.
///
/// # Race-free usage
///
/// `Notify::notify_waiters()` only wakes waiters registered at the moment
/// of the call. A naive `if flag { return } else { notify.notified().await }`
/// races: `cancel()` may fire between the flag check and the `.await`,
/// leaving the waiter blocked forever. The `AtomicBool` closes that race
/// by acting as a durable record of cancellation; `cancelled()` rechecks
/// the flag after registering with `Notify` but before awaiting.
pub struct ShutdownSignal {
    cancelled: AtomicBool,
    notify: Notify,
}

impl ShutdownSignal {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            cancelled: AtomicBool::new(false),
            notify: Notify::new(),
        })
    }

    /// Fire the signal. Idempotent — subsequent calls are no-ops.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    /// Non-blocking check. Safe to call from any context, including hot loops.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// Resolves when `cancel()` has been called (or was already called
    /// before this future was awaited). Race-free: the waiter registers
    /// with `Notify` before re-checking the flag, so a concurrent
    /// `cancel()` cannot be missed.
    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let notified = self.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Guards the enable()-before-recheck invariant in `cancelled()`.
    /// A waiter registered after `cancel()` fires must still observe the
    /// cancellation via the `AtomicBool` flag — without that recheck, a
    /// race between the flag load and `notified.await` would leave the
    /// waiter blocked forever.
    #[tokio::test]
    async fn cancel_wakes_concurrent_waiter() {
        let signal = ShutdownSignal::new();
        let waiter_signal = signal.clone();

        let waiter = tokio::spawn(async move {
            waiter_signal.cancelled().await;
        });

        // Let the waiter register before we fire cancel. A small yield is
        // enough; we don't need a synchronous handshake because the
        // enable()-before-recheck pattern closes the race even if cancel
        // fires before the waiter registers.
        tokio::task::yield_now().await;
        signal.cancel();

        tokio::time::timeout(std::time::Duration::from_millis(100), waiter)
            .await
            .expect("waiter must resolve within 100ms of cancel()")
            .expect("waiter task must not panic");
    }

    #[tokio::test]
    async fn cancelled_returns_immediately_if_already_cancelled() {
        let signal = ShutdownSignal::new();
        signal.cancel();
        tokio::time::timeout(std::time::Duration::from_millis(10), signal.cancelled())
            .await
            .expect("cancelled() must return immediately when flag is already set");
    }

    #[test]
    fn cancel_is_idempotent() {
        let signal = ShutdownSignal::new();
        assert!(!signal.is_cancelled());
        signal.cancel();
        assert!(signal.is_cancelled());
        signal.cancel();
        assert!(signal.is_cancelled());
    }
}
