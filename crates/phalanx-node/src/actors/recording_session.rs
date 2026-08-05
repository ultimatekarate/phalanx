// crates/phalanx-node/src/actors/recording_session.rs
//
// Recording-session state container. Owned by `MeshSentinel` as a single
// `session: RecordingSessionState` field. FFI mutates via `MeshSentinel`
// methods (`start_recording`, `stop_recording`) rather than reaching into
// individual fields.

use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::identity::RecordingId;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::watch;

/// State for the currently-active recording, if any. Recording is enabled
/// when `active_recording_id` is `Some`. The fields are only mutated through
/// the methods on this struct so the invariants (content-key channel
/// signalled on every transition, recording-active flag kept in sync)
/// cannot drift.
pub struct RecordingSessionState {
    /// The active recording id. `Some` ⇔ a recording is in progress.
    active_recording_id: Option<RecordingId>,
    /// Watch sender driving the per-recording content key for `MediaEgressActor`.
    /// FFI also holds a clone of this sender so it can push the content key
    /// independently of `start_recording` / `stop_recording`. The watch
    /// channel keeps the latest value, so simultaneous senders do not
    /// conflict.
    content_key_tx: watch::Sender<Option<SymmetricKey>>,
    /// Cheap-to-read "is a recording in progress?" flag. The engine flips
    /// this in `start` / `stop`; FFI consumers obtain an `Arc` clone via
    /// `recording_active_handle()` and read it lock-free. This is the
    /// single source of truth — under the post-refactor design FFI never
    /// writes the flag directly; it sends a `SentinelCommand` and the
    /// engine flips this atomic as a side effect.
    recording_active: Arc<AtomicBool>,
}

impl RecordingSessionState {
    #[must_use]
    pub fn new(content_key_tx: watch::Sender<Option<SymmetricKey>>) -> Self {
        Self {
            active_recording_id: None,
            content_key_tx,
            recording_active: Arc::new(AtomicBool::new(false)),
        }
    }

    /// True when a recording is in progress.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active_recording_id.is_some()
    }

    /// The active recording id, if any.
    #[must_use]
    pub fn recording_id(&self) -> Option<RecordingId> {
        self.active_recording_id.clone()
    }

    /// Mark a recording as active. The content key is delivered to
    /// `MediaEgressActor` separately by the FFI's `phalanx_start_recording`,
    /// which pushes it on its own `content_key_tx` clone — so `start` only
    /// flips the active-recording state.
    pub fn start(&mut self, id: RecordingId) {
        self.active_recording_id = Some(id);
        self.recording_active.store(true, Ordering::Release);
    }

    /// Stop the recording. Clears the active recording id and signals
    /// `MediaEgressActor` to revert to vault-key encryption (`None` on the
    /// watch channel).
    pub fn stop(&mut self) {
        self.active_recording_id = None;
        let _ = self.content_key_tx.send(None);
        self.recording_active.store(false, Ordering::Release);
    }

    /// Clone of the content-key watch sender, for the FFI handle. The handle
    /// retains its own clone so FFI can drive the key independently of the
    /// recording-session state machine.
    #[must_use]
    pub fn content_key_tx_clone(&self) -> watch::Sender<Option<SymmetricKey>> {
        self.content_key_tx.clone()
    }

    /// `Arc` clone of the recording-active flag. FFI readers acquire this
    /// once at engine-handle construction time and observe transitions via
    /// `AtomicBool::load(Ordering::Acquire)`. The engine is the sole
    /// writer; readers never store.
    #[must_use]
    pub fn recording_active_handle(&self) -> Arc<AtomicBool> {
        self.recording_active.clone()
    }
}
