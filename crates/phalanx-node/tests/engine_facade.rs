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
use phalanx_node::actors::meshsentinel::{SentinelCommand, SentinelDependencies};
use phalanx_node::actors::storage::NoOpJournal;
use phalanx_node::config::NodeConfig;
use phalanx_node::persistence::vault::derive_vault_key;
use phalanx_node::trust::TrustRegistry;
use phalanx_node::vitals::SystemGovernor;
use phalanx_node::UnspawnedEngine;
use phalanx_proto::identity::{PhalanxIdentity, RecordingId};
use std::sync::atomic::Ordering;
use std::sync::Arc;
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

    let local_mesh_address = phalanx_transport::identity_ext::Libp2pExt::to_mesh_address(&identity);

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
        local_mesh: None,
        prnu_posterior: Arc::new(std::sync::Mutex::new(
            phalanx_proto::evidence::PrnuPosterior::new_uninformed(),
        )),
        extra_community_ids: Vec::new(),
        local_mesh_address,
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
