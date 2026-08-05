#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
//! Phase 1 verification: exercise the engine-façade public surface
//! end-to-end.
//!
//! What this test pins down:
//! 1. `UnspawnedEngine::build(deps).await` produces a bootstrapped engine
//!    that we cannot reach into (the inner `MeshSentinel` is private).
//! 2. `UnspawnedEngine::spawn(&runtime)` consumes by value, returns the
//!    channel handle and lifecycle controller.
//! 3. The run loop services `SentinelCommand::SetRecordingState` via its
//!    `select!` arm — sending the command flips `recording_active` and
//!    fires the reply oneshot.
//! 4. `EngineLifecycle::shutdown(self, deadline)` consumes by value,
//!    drains the run loop within the deadline, and returns `Ok`.
//!
//! Together these are the structural property the audit-driven plan
//! requires: no `Arc<Mutex<MeshSentinel>>`, no FFI lock on the engine,
//! all sentinel mutation flows through the command mailbox.

mod common;

use common::{TestEgress, TestIngress};
use phalanx_node::actors::meshsentinel::{AlreadyPlaying, SentinelCommand, SentinelDependencies};
use phalanx_node::actors::storage::NoOpJournal;
use phalanx_node::config::NodeConfig;
use phalanx_node::persistence::vault::derive_vault_key;
use phalanx_node::trust::TrustRegistry;
use phalanx_node::vitals::SystemGovernor;
use phalanx_node::{UnspawnedEngine, VideoPlayerSink};
use phalanx_proto::identity::{PhalanxIdentity, RecordingId};
use phalanx_proto::playback::PlaybackSink;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// Build a `SentinelDependencies<TestIngress, TestEgress, NoOpJournal>` for
/// the new engine-façade tests. Returns the deps plus the tempdir handle
/// (must outlive the engine — drop would yank the vault path).
async fn build_test_deps() -> (
    SentinelDependencies<TestIngress, TestEgress, NoOpJournal>,
    tempfile::TempDir,
    mpsc::Sender<phalanx_proto::network::NetworkEvent>,
) {
    let temp = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::default();
    config.storage.vault_path = temp.path().to_string_lossy().to_string();

    let (ingress_tx, ingress_rx) = mpsc::channel(1);

    let identity = PhalanxIdentity::new_ephemeral();
    let vault_key = derive_vault_key(&identity, &[0u8; 32]);
    let dek_master = identity.dek_master.clone();
    let trust_registry = TrustRegistry::build(&config).await;

    let mesh_identity_address =
        phalanx_transport::identity_ext::Libp2pExt::to_mesh_address(&identity);

    let deps = SentinelDependencies {
        config,
        identity,
        ingress: TestIngress::new(ingress_rx),
        egress: TestEgress,
        journal: NoOpJournal,
        trust_registry,
        system_governor: Arc::new(SystemGovernor::new()),
        vault_key,
        dek_master,
        prnu_posterior: Arc::new(std::sync::Mutex::new(
            phalanx_proto::evidence::PrnuPosterior::new_uninformed(),
        )),
        extra_community_ids: Vec::new(),
        mesh_identity_address,
    };

    (deps, temp, ingress_tx)
}

#[test]
fn engine_facade_end_to_end_phase1_landing() {
    // Drive everything on an explicit multi-thread runtime so we can:
    //   - block_on the async build/shutdown
    //   - pass `&runtime` to `UnspawnedEngine::spawn`
    //   - use `blocking_send`/`blocking_recv` from this sync test body
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("multi_thread runtime builds");

    let (deps, _temp, _ingress_tx) = runtime.block_on(build_test_deps());

    // (1) UnspawnedEngine::build wraps MeshSentinel privately.
    let unspawned = runtime
        .block_on(UnspawnedEngine::build(deps))
        .expect("UnspawnedEngine::build succeeds for a healthy test bootstrap");

    // (2) spawn consumes by value, returns (EngineHandle, EngineLifecycle).
    let (engine, lifecycle) = unspawned.spawn(&runtime);

    // Pre-condition: no recording is active.
    let recording_active = engine.recording_active();
    assert!(
        !recording_active.load(Ordering::Acquire),
        "recording_active starts false"
    );

    // (3) Send SentinelCommand::SetRecordingState(Some(id)) via the
    //     handle's sender. Wait for the reply oneshot — that proves the
    //     run loop's select! arm serviced the command.
    let cmd_tx = engine.sentinel_cmd_tx();
    let (reply_tx, reply_rx) = oneshot::channel::<()>();
    cmd_tx
        .blocking_send(SentinelCommand::SetRecordingState {
            id: Some(RecordingId::new("phase1-test-recording")),
            reply_to: reply_tx,
        })
        .expect("sentinel command channel is open");

    // Reply must arrive within a generous deadline — the engine's run
    // loop should process this within milliseconds.
    runtime
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(3), reply_rx)
                .await
                .expect("reply within deadline")
        })
        .expect("reply oneshot delivered");

    assert!(
        recording_active.load(Ordering::Acquire),
        "recording_active flips to true after SetRecordingState(Some(..))"
    );

    // Now stop the recording — verify the atomic flips back.
    let (reply_tx, reply_rx) = oneshot::channel::<()>();
    cmd_tx
        .blocking_send(SentinelCommand::SetRecordingState {
            id: None,
            reply_to: reply_tx,
        })
        .expect("sentinel command channel is open");
    runtime
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(3), reply_rx)
                .await
                .expect("stop reply within deadline")
        })
        .expect("stop reply oneshot delivered");

    assert!(
        !recording_active.load(Ordering::Acquire),
        "recording_active flips back to false after SetRecordingState(None)"
    );

    // (4) Lifecycle shutdown consumes self and drains the run loop.
    runtime
        .block_on(async {
            tokio::time::timeout(
                Duration::from_secs(5),
                lifecycle.shutdown(Duration::from_secs(3)),
            )
            .await
            .expect("shutdown returns within outer 5s window")
        })
        .expect("EngineLifecycle::shutdown returns Ok within deadline");
}

/// Build a `Box<dyn PlaybackSink + Send + Sync + 'static>` backed by a fresh
/// mpsc receiver. Returns the receiver so the test can drop it when needed
/// to signal session-end to the coordinator. Used by the SpawnPlayback tests.
fn make_test_sink() -> (
    Box<dyn PlaybackSink + Send + Sync + 'static>,
    mpsc::Receiver<Vec<u8>>,
) {
    let (tx, rx) = mpsc::channel::<Vec<u8>>(8);
    let sink: Box<dyn PlaybackSink + Send + Sync + 'static> = Box::new(VideoPlayerSink::new(tx));
    (sink, rx)
}

/// Verification item 3 of the mesh-playback-wiring plan: dispatching
/// `SentinelCommand::SpawnPlayback` through the engine handle succeeds when
/// no prior playback is live. Proves the FFI-side wiring path works without
/// the FFI itself: command in, `Ok(())` out, coordinator task installed in
/// the sentinel's `playback_slot`.
#[test]
fn engine_facade_spawn_playback_dispatches() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("multi_thread runtime builds");

    let (deps, _temp, _ingress_tx) = runtime.block_on(build_test_deps());
    let unspawned = runtime
        .block_on(UnspawnedEngine::build(deps))
        .expect("UnspawnedEngine::build succeeds");
    let (engine, lifecycle) = unspawned.spawn(&runtime);

    let cmd_tx = engine.sentinel_cmd_tx();
    let (video_sink, _video_rx) = make_test_sink();
    let (audio_sink, _audio_rx) = make_test_sink();

    let (reply_tx, reply_rx) = oneshot::channel::<Result<(), AlreadyPlaying>>();
    cmd_tx
        .blocking_send(SentinelCommand::SpawnPlayback {
            recording_id: RecordingId::new("playback-dispatch-test"),
            video_sink,
            audio_sink,
            reply_to: reply_tx,
        })
        .expect("sentinel command channel is open");

    let result = runtime
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(3), reply_rx)
                .await
                .expect("reply within deadline")
        })
        .expect("reply oneshot delivered");
    assert!(
        result.is_ok(),
        "first SpawnPlayback dispatch should succeed (got {result:?})"
    );

    // Lifecycle shutdown aborts any in-flight coordinator task as part of
    // runtime drop. The 10-second coordinator gap-timeout doesn't elongate
    // the test because shutdown doesn't wait for the playback task — only
    // for `background_tasks`.
    runtime
        .block_on(async {
            tokio::time::timeout(
                Duration::from_secs(5),
                lifecycle.shutdown(Duration::from_secs(3)),
            )
            .await
            .expect("shutdown returns within outer 5s window")
        })
        .expect("EngineLifecycle::shutdown returns Ok within deadline");
}

/// Verification item 4 of the mesh-playback-wiring plan: the `playback_slot`
/// singleton rejects a second concurrent dispatch with `Err(AlreadyPlaying)`.
/// This is the structural property the plan introduces — "at most one
/// playback at a time" enforced by type, not by an FFI runtime gate.
#[test]
fn engine_facade_spawn_playback_singleton_rejection() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("multi_thread runtime builds");

    let (deps, _temp, _ingress_tx) = runtime.block_on(build_test_deps());
    let unspawned = runtime
        .block_on(UnspawnedEngine::build(deps))
        .expect("UnspawnedEngine::build succeeds");
    let (engine, lifecycle) = unspawned.spawn(&runtime);

    let cmd_tx = engine.sentinel_cmd_tx();

    // First dispatch: succeeds and installs the JoinHandle in the slot.
    // We deliberately keep _video_rx_1 / _audio_rx_1 alive so the
    // coordinator's sinks remain open and the task is still considered
    // running by the slot check.
    let (video_sink_1, _video_rx_1) = make_test_sink();
    let (audio_sink_1, _audio_rx_1) = make_test_sink();
    let (rt1, rr1) = oneshot::channel::<Result<(), AlreadyPlaying>>();
    cmd_tx
        .blocking_send(SentinelCommand::SpawnPlayback {
            recording_id: RecordingId::new("singleton-test-first"),
            video_sink: video_sink_1,
            audio_sink: audio_sink_1,
            reply_to: rt1,
        })
        .expect("first send");
    let r1 = runtime
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(3), rr1)
                .await
                .expect("first reply within deadline")
        })
        .expect("first oneshot delivered");
    assert!(r1.is_ok(), "first dispatch should succeed (got {r1:?})");

    // Second dispatch while the first is still live: rejected.
    let (video_sink_2, _video_rx_2) = make_test_sink();
    let (audio_sink_2, _audio_rx_2) = make_test_sink();
    let (rt2, rr2) = oneshot::channel::<Result<(), AlreadyPlaying>>();
    cmd_tx
        .blocking_send(SentinelCommand::SpawnPlayback {
            recording_id: RecordingId::new("singleton-test-second"),
            video_sink: video_sink_2,
            audio_sink: audio_sink_2,
            reply_to: rt2,
        })
        .expect("second send");
    let r2 = runtime
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(3), rr2)
                .await
                .expect("second reply within deadline")
        })
        .expect("second oneshot delivered");
    assert!(
        matches!(r2, Err(AlreadyPlaying)),
        "second dispatch should be rejected with AlreadyPlaying (got {r2:?})"
    );

    runtime
        .block_on(async {
            tokio::time::timeout(
                Duration::from_secs(5),
                lifecycle.shutdown(Duration::from_secs(3)),
            )
            .await
            .expect("shutdown returns within outer 5s window")
        })
        .expect("EngineLifecycle::shutdown returns Ok within deadline");
}
