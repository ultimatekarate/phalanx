// crates/phalanx-node/src/engine.rs
//
// Public façade for driving `MeshSentinel` from outside `phalanx-node`.
//
// `MeshSentinel` is the live, mutable engine state — it owns the run loop's
// `&mut self` borrow for its entire lifetime, so it cannot be shared via
// `Arc<Mutex<…>>` without creating the deadlock surface described in
// `linguistic-code-model.md` § Governance Command #5.
//
// This module provides three types that bracket the sentinel's lifecycle:
//
// * `UnspawnedEngine` — a bootstrapped-but-not-running engine. Wraps
//   `MeshSentinel` privately so downstream crates cannot name the inner
//   type or wrap it in a Mutex.
// * `EngineHandle` — a struct of `Clone`-friendly channel senders. The
//   only legal way for external code to drive the running engine.
// * `EngineLifecycle` — owns the shutdown signal and the run-loop
//   `JoinHandle`. Consume-by-value `shutdown` enforces single-shot
//   semantics at the type level.
//
// Together they encode "linear ownership of the engine" in the type
// system: there is no way to construct an `Arc<MeshSentinel>` from
// outside `phalanx-node`, because the type is `pub(crate)` and never
// surfaces through any public signature.

use crate::actors::meshsentinel::{MeshSentinel, SentinelCommand, SentinelDependencies};
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::{AudioShard, VideoShard};
use phalanx_proto::identity::RecordingId;
use phalanx_proto::network::{EgressPort, IngressPort};
use phalanx_proto::storage::TransientJournal;
use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinError, JoinHandle};

use crate::actors::egress::EgressCommand;
use crate::actors::storage::StorageCommand;
use crate::actors::trust_actor::TrustCommand;

/// A bootstrapped `MeshSentinel` that hasn't started its run loop yet.
///
/// The only way to obtain one is through `UnspawnedEngine::build`. The
/// only way to consume one is `UnspawnedEngine::spawn`, which takes
/// `self` by value and moves the inner sentinel into the spawned task.
/// After spawn, no caller can hold a reference to the sentinel — the
/// run loop has exclusive ownership for life.
#[must_use = "an UnspawnedEngine that is dropped without spawn() never runs"]
pub struct UnspawnedEngine<I: IngressPort> {
    sentinel: MeshSentinel<I>,
}

impl<I: IngressPort + 'static> UnspawnedEngine<I> {
    /// Construct an engine from its dependencies.
    ///
    /// Identical effect to `MeshSentinel::new(deps).await`, but the
    /// resulting value is opaque to callers outside `phalanx-node`.
    pub async fn build<E, J>(deps: SentinelDependencies<I, E, J>) -> Result<Self, Box<dyn Error>>
    where
        E: EgressPort + 'static,
        J: TransientJournal + Send + 'static,
    {
        Ok(Self {
            sentinel: MeshSentinel::new(deps).await?,
        })
    }

    // -- Pre-spawn channel accessors ------------------------------------------
    //
    // The sentinel's actor tasks are spawned inside `MeshSentinel::new`, so
    // their channels are alive before the orchestrator run loop starts.
    // FFI bootstrap clones these into `PhalanxHandle` flat fields so calls
    // made between `phalanx_create` and `phalanx_start` (e.g. preview FFIs
    // that don't need the orchestrator) can still send commands.
    //
    // After `spawn`, `EngineHandle` exposes the same surface for callers
    // that started from `phalanx_start` directly.

    #[must_use]
    pub fn trust_tx(&self) -> mpsc::Sender<TrustCommand> {
        self.sentinel.trust_tx.clone()
    }
    #[must_use]
    pub fn storage_tx(&self) -> mpsc::Sender<StorageCommand> {
        self.sentinel.storage_tx.clone()
    }
    #[must_use]
    pub fn egress_tx(&self) -> mpsc::Sender<EgressCommand> {
        self.sentinel.egress_tx.clone()
    }
    #[must_use]
    pub fn sentinel_cmd_tx(&self) -> mpsc::Sender<SentinelCommand> {
        self.sentinel.sentinel_cmd_tx.clone()
    }
    #[must_use]
    pub fn content_key_tx(&self) -> watch::Sender<Option<SymmetricKey>> {
        self.sentinel.session.content_key_tx_clone()
    }
    #[must_use]
    pub fn video_tx(&self) -> mpsc::Sender<VideoShard> {
        self.sentinel.video_tx.clone()
    }
    #[must_use]
    pub fn audio_tx(&self) -> mpsc::Sender<AudioShard> {
        self.sentinel.audio_tx.clone()
    }
    #[must_use]
    pub fn recording_active(&self) -> Arc<AtomicBool> {
        self.sentinel.session.recording_active_handle()
    }
    /// Watch receiver on the active recording id, for the FFI handle.
    /// `make_ble_challenge` reads it to bind a challenge to the recording the
    /// witness will bind — engine-sourced, never plugin-supplied.
    #[must_use]
    pub fn recording_id_receiver(&self) -> watch::Receiver<Option<RecordingId>> {
        self.sentinel.session.recording_id_receiver()
    }

    /// Spawn the engine's run loop on `runtime`, returning the channel
    /// handle and the lifecycle controller.
    ///
    /// Consumes `self`. The inner `MeshSentinel` moves into the spawned
    /// task; after this call there is no surviving reference to it
    /// anywhere in the program. That's the structural property the
    /// linguistic model requires: no shared, lockable engine state.
    pub fn spawn(self, runtime: &Runtime) -> (EngineHandle, EngineLifecycle) {
        let UnspawnedEngine { mut sentinel } = self;

        // Clone everything `EngineHandle` exposes before moving the
        // sentinel into the run-loop task.
        let trust_tx = sentinel.trust_tx.clone();
        let storage_tx = sentinel.storage_tx.clone();
        let egress_tx = sentinel.egress_tx.clone();
        let sentinel_cmd_tx = sentinel.sentinel_cmd_tx.clone();
        let content_key_tx = sentinel.session.content_key_tx_clone();
        let video_tx = sentinel.video_tx.clone();
        let audio_tx = sentinel.audio_tx.clone();
        let recording_active = sentinel.session.recording_active_handle();

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let join_handle = runtime.spawn(async move {
            tokio::select! {
                result = sentinel.run() => {
                    if let Err(e) = result {
                        tracing::error!(target: "phalanx::engine", error = %e, "MeshSentinel run() returned error");
                    }
                }
                _ = shutdown_rx => {
                    tracing::info!(target: "phalanx::engine", "EngineLifecycle::shutdown signal observed");
                }
            }
            sentinel.shutdown().await;
        });

        let handle = EngineHandle {
            trust_tx,
            storage_tx,
            egress_tx,
            sentinel_cmd_tx,
            content_key_tx,
            video_tx,
            audio_tx,
            recording_active,
        };
        let lifecycle = EngineLifecycle {
            shutdown_tx: Some(shutdown_tx),
            join_handle: Some(join_handle),
            shutdown_called: false,
        };
        (handle, lifecycle)
    }
}

/// Channel bundle exposing every operation the FFI (or any other driver)
/// can perform against a running engine.
///
/// Each accessor returns an owned, cloneable handle (`mpsc::Sender` /
/// `watch::Sender` / `Arc<AtomicBool>`) so the caller can release any
/// outer lock before invoking it. This is necessary for the FFI to send
/// commands without holding its `Mutex<EngineState>` across an `.await`.
#[derive(Clone)]
pub struct EngineHandle {
    trust_tx: mpsc::Sender<TrustCommand>,
    storage_tx: mpsc::Sender<StorageCommand>,
    egress_tx: mpsc::Sender<EgressCommand>,
    sentinel_cmd_tx: mpsc::Sender<SentinelCommand>,
    content_key_tx: watch::Sender<Option<SymmetricKey>>,
    video_tx: mpsc::Sender<VideoShard>,
    audio_tx: mpsc::Sender<AudioShard>,
    recording_active: Arc<AtomicBool>,
}

impl EngineHandle {
    #[must_use]
    pub fn trust_tx(&self) -> mpsc::Sender<TrustCommand> {
        self.trust_tx.clone()
    }
    #[must_use]
    pub fn storage_tx(&self) -> mpsc::Sender<StorageCommand> {
        self.storage_tx.clone()
    }
    #[must_use]
    pub fn egress_tx(&self) -> mpsc::Sender<EgressCommand> {
        self.egress_tx.clone()
    }
    #[must_use]
    pub fn sentinel_cmd_tx(&self) -> mpsc::Sender<SentinelCommand> {
        self.sentinel_cmd_tx.clone()
    }
    #[must_use]
    pub fn content_key_tx(&self) -> watch::Sender<Option<SymmetricKey>> {
        self.content_key_tx.clone()
    }
    #[must_use]
    pub fn video_tx(&self) -> mpsc::Sender<VideoShard> {
        self.video_tx.clone()
    }
    #[must_use]
    pub fn audio_tx(&self) -> mpsc::Sender<AudioShard> {
        self.audio_tx.clone()
    }
    /// Shared atomic flipped by the engine on `start_recording` /
    /// `stop_recording`. FFI readers acquire one `Arc` clone at handle
    /// construction time and read lock-free.
    #[must_use]
    pub fn recording_active(&self) -> Arc<AtomicBool> {
        self.recording_active.clone()
    }
}

/// Lifecycle controller. Owns the shutdown signal and the run-loop
/// `JoinHandle`. The `shutdown` method consumes `self` — the type system
/// enforces single-shot shutdown — and `Drop` logs a warning if the
/// handle is dropped without a prior `shutdown`.
#[must_use = "an EngineLifecycle that is dropped without shutdown() forfeits in-flight drain"]
pub struct EngineLifecycle {
    shutdown_tx: Option<oneshot::Sender<()>>,
    join_handle: Option<JoinHandle<()>>,
    shutdown_called: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ShutdownError {
    /// The run-loop task panicked or was aborted; the join handle reported the failure.
    #[error("engine join failed: {0}")]
    Join(#[from] JoinError),
    /// The shutdown deadline elapsed before the run-loop task drained.
    #[error("engine shutdown timed out after {0:?}")]
    Timeout(Duration),
}

impl EngineLifecycle {
    /// Signal the engine to stop, wait for it to drain (bounded by `deadline`),
    /// and consume `self` so the caller can't shut down twice.
    pub async fn shutdown(mut self, deadline: Duration) -> Result<(), ShutdownError> {
        self.shutdown_called = true;
        // Dropping the sender — or sending an explicit `()` — wakes the
        // run loop's `shutdown_rx` arm. Send for explicitness so the run
        // loop's log line ("shutdown signal observed") is the path taken.
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let Some(handle) = self.join_handle.take() else {
            return Ok(()); // Already drained (defensive — should not happen).
        };
        match tokio::time::timeout(deadline, handle).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(join_err)) => Err(ShutdownError::Join(join_err)),
            Err(_) => Err(ShutdownError::Timeout(deadline)),
        }
    }
}

impl Drop for EngineLifecycle {
    fn drop(&mut self) {
        if !self.shutdown_called {
            tracing::error!(
                target: "phalanx::engine",
                "EngineLifecycle dropped without shutdown(); engine task is being abandoned mid-flight"
            );
            // Still send the shutdown signal so the task exits cleanly
            // when the runtime is dropped, rather than being force-cancelled.
            if let Some(tx) = self.shutdown_tx.take() {
                let _ = tx.send(());
            }
        }
    }
}
