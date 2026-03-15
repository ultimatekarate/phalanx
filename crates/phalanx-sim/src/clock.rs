// crates/phalanx-sim/src/clock.rs
//
// Virtual clock for deterministic time control in simulations.
// Wraps Tokio's `test-util` time pausing to allow the simulation harness
// to advance time manually, ensuring reproducible test outcomes.

use std::time::Duration;

/// Deterministic time control for simulations.
///
/// Wraps Tokio's `test-util` `pause()`/`advance()` to give the harness
/// explicit control over virtual time. Without this, `tokio::time::sleep()`
/// and `tokio::time::interval()` inside actors would block indefinitely
/// or race nondeterministically.
///
/// # Usage
///
/// ```ignore
/// VirtualClock::pause();  // Call once at simulation start
/// // ... spawn nodes, inject events ...
/// VirtualClock::advance(Duration::from_secs(5)).await;  // Trigger interval ticks
/// ```
pub struct VirtualClock;

impl VirtualClock {
    /// Pause the Tokio time driver.
    ///
    /// After calling this, all `tokio::time::sleep()` and `interval()` calls
    /// will only progress when `advance()` is called. Must be called before
    /// any async work begins (typically at the start of `init_mesh()`).
    pub fn pause() {
        tokio::time::pause();
    }

    /// Advance virtual time by the given duration.
    ///
    /// The `yield_now()` after `advance()` forces the executor to poll
    /// all waking background tasks — critical for `select!` loops in
    /// MeshSentinel and StorageActor to process their interval ticks.
    pub async fn advance(duration: Duration) {
        tokio::time::advance(duration).await;
        tokio::task::yield_now().await;
    }
}
