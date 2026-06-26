// crates/phalanx-node/src/actors/recording_session.rs
//
// Recording-session state container. Owned by `MeshSentinel` as a single
// `session: RecordingSessionState` field. FFI mutates via `MeshSentinel`
// methods (`start_recording`, `stop_recording`) rather than reaching into
// individual fields.

use phalanx_proto::corroboration::ProximityWitness;
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::identity::RecordingId;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{mpsc, watch};

/// State for the currently-active recording, if any. Recording is enabled
/// when `active_recording_id` is `Some`. The fields are only mutated through
/// the methods on this struct so the invariants (witnesses cleared on stop,
/// content-key channel signalled on every transition, recording-active flag
/// kept in sync) cannot drift.
pub struct RecordingSessionState {
    /// Single source of truth for the active recording id, held as a watch so
    /// the FFI handle can read it lock-free off-thread (`make_ble_challenge`
    /// binds it into BLE challenges). `Some` ⇔ a recording is in progress.
    active_recording_id: watch::Sender<Option<RecordingId>>,
    active_recording_key: Option<[u8; 32]>,
    proximity_witnesses: Vec<ProximityWitness>,
    /// Watch sender driving the per-recording content key for `MediaEgressActor`.
    /// FFI also holds a clone of this sender so it can push the content key
    /// independently of `start_recording` / `stop_recording`. The watch
    /// channel keeps the latest value, so simultaneous senders do not
    /// conflict.
    content_key_tx: watch::Sender<Option<SymmetricKey>>,
    /// Egress sender to `MediaEgressActor` for captured proximity witnesses.
    /// On `stop`, drained witnesses are handed off here to be sealed into signed
    /// `Evidence::Proximity` envelopes and fountain-published with the recording.
    /// The session owns this so the witness lifecycle stays out of
    /// `MeshSentinel` — the orchestrator only wires the channel at construction.
    proximity_tx: mpsc::Sender<ProximityWitness>,
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
    pub fn new(
        content_key_tx: watch::Sender<Option<SymmetricKey>>,
        proximity_tx: mpsc::Sender<ProximityWitness>,
    ) -> Self {
        Self {
            active_recording_id: watch::channel(None).0,
            active_recording_key: None,
            proximity_witnesses: Vec::new(),
            content_key_tx,
            proximity_tx,
            recording_active: Arc::new(AtomicBool::new(false)),
        }
    }

    /// True when a recording is in progress (proximity-witness capture enabled).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active_recording_id.borrow().is_some()
    }

    /// The active recording id, if any (cloned from the watch).
    #[must_use]
    pub fn recording_id(&self) -> Option<RecordingId> {
        self.active_recording_id.borrow().clone()
    }

    /// A `watch::Receiver` on the active recording id, for the FFI handle.
    /// `make_ble_challenge` reads it to bind a BLE challenge to the same
    /// recording the witness will bind — engine-sourced, never plugin-supplied.
    #[must_use]
    pub fn recording_id_receiver(&self) -> watch::Receiver<Option<RecordingId>> {
        self.active_recording_id.subscribe()
    }

    /// Mark a recording as active. If `key` is provided, also pushes it via
    /// the content-key watch channel so `MediaEgressActor` switches to
    /// per-recording encryption. The FFI's `phalanx_start_recording` may
    /// alternatively push the key directly via its own watch sender clone.
    pub fn start(&mut self, id: RecordingId, key: Option<[u8; 32]>) {
        self.active_recording_id.send_replace(Some(id));
        self.active_recording_key = key;
        if let Some(k) = key {
            let _ = self.content_key_tx.send(Some(SymmetricKey::from_bytes(k)));
        }
        self.recording_active.store(true, Ordering::Release);
    }

    /// Stop the recording. Hands every proximity witness captured during the
    /// recording to `MediaEgressActor` (via `proximity_tx`) to be sealed into a
    /// signed `Evidence::Proximity` envelope and fountain-published with the
    /// recording, where a custody Stronghold's `collect_proximity` folds it into
    /// the `CorroborationProof`. Also clears the active recording id and signals
    /// `MediaEgressActor` to revert to vault-key encryption (`None` on the watch
    /// channel).
    pub fn stop(&mut self) {
        self.active_recording_id.send_replace(None);
        self.active_recording_key = None;
        let _ = self.content_key_tx.send(None);
        self.recording_active.store(false, Ordering::Release);

        // Hand captured witnesses to the egress specialist. Dropped on
        // backpressure (full) or after the actor has shut down (closed), like
        // media shards — proximity is supporting evidence, never a gate.
        for witness in self.proximity_witnesses.drain(..) {
            if let Err(e) = self.proximity_tx.try_send(witness) {
                tracing::warn!(
                    target: "phalanx::mesh",
                    error = %e,
                    "Proximity witness dropped — egress channel full or closed"
                );
            }
        }
    }

    /// Append a proximity witness captured during the current recording.
    pub fn push_witness(&mut self, witness: ProximityWitness) {
        self.proximity_witnesses.push(witness);
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
