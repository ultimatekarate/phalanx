#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
//! Integration tests for the recovery orchestrator (PR D, Phase D5).
//!
//! Each test stands up:
//! - A real recovering `Guardian` + `StorageActor` (where shards land).
//! - An in-memory `RemoteStore` (where pre-built envelopes live).
//! - A mock egress responder that translates `EgressCommand` events into
//!   either provider-list pushes (FindProviders) or `WriteShard` injections
//!   (RequestShards) into the recovering StorageActor.
//!
//! The orchestrator runs against this synthetic mesh — no transport, no
//! libp2p, no SimulationWorld. Validates the manifest-walk control flow
//! end-to-end up to (but not including) the wire.

use phalanx_forensics::Reassembler;
use phalanx_forensics::crucible::EnvelopeHashExt;
use phalanx_forensics::cryptography::dek::derive_manifest_recording_id;
use phalanx_forensics::witness::WitnessAuthority;
use phalanx_node::actors::egress::EgressCommand;
use phalanx_node::actors::recovery::{RecoveryContext, run_recovery};
use phalanx_node::actors::shutdown::ShutdownSignal;
use phalanx_node::actors::storage::{NoOpJournal, StorageActor, StorageCommand};
use phalanx_node::config::NodeConfig;
use phalanx_node::identity::PhalanxNodeIdentityExt;
use phalanx_node::persistence::vault::{Guardian, derive_vault_key};
use phalanx_node::vitals::SystemGovernor;
use phalanx_proto::evidence::{
    Evidence, ManifestEntry, SignatureHash, StorageSequence, WitnessEnvelope,
};
use phalanx_proto::identity::{MeshAddress, PhalanxIdentity, RecordingId};
use phalanx_proto::recovery::{RecoveryState, RecoveryStatus};
use phalanx_proto::time::{SystemClock, TrustedClock};
use phalanx_test_fixtures::shards::video_shard_for_recording;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

// ── Test scaffolding ───────────────────────────────────────────────────

/// Per-recording remote store: the synthetic "what other Strongholds have".
type RemoteStore = HashMap<RecordingId, Vec<WitnessEnvelope>>;

/// Stand up a real `StorageActor` backed by a real `Guardian` + tempdir.
fn spawn_recovering_storage(
    identity: &PhalanxIdentity,
) -> (
    mpsc::Sender<StorageCommand>,
    JoinHandle<()>,
    tempfile::TempDir,
) {
    let temp = tempdir().unwrap();
    let mut config = NodeConfig::test_defaults();
    config.storage.vault_path = temp.path().to_string_lossy().into_owned();

    let vault_key = derive_vault_key(identity, &[0u8; 32]);
    let guardian = Guardian::new(
        &config.storage.vault_path,
        &config,
        identity.did.clone(),
        Arc::new(SystemClock),
        vault_key,
        identity.dek_master.clone(),
    );

    let actor = StorageActor {
        reassembler: Reassembler::new(),
        guardian,
        journal: NoOpJournal,
        config: config.clone(),
        identity: identity.clone(),
        current_tolerance: Duration::from_millis(1000),
        system_governor: Arc::new(SystemGovernor::new()),
        commit_notify_tx: None,
        replay_filter: phalanx_forensics::bloom::RotatingBloomFilter::new(
            phalanx_forensics::bloom::RotatingBloomFilter::DEFAULT_CAPACITY,
        ),
        shutdown: ShutdownSignal::new(),
        used_bytes_gauge: Arc::new(std::sync::atomic::AtomicU64::new(0)),
    };

    let (storage_tx, storage_rx) = mpsc::channel::<StorageCommand>(64);
    let handle = tokio::spawn(async move {
        actor.run(storage_rx).await;
    });
    (storage_tx, handle, temp)
}

/// Synthesize a manifest catalog + N child recordings, all signed by
/// `identity`. Returns the populated remote store and the ordered list of
/// child rids.
fn synthesize_remote(
    identity: &PhalanxIdentity,
    n_children: u32,
) -> (RemoteStore, Vec<RecordingId>) {
    let manifest_id = derive_manifest_recording_id(&identity.dek_master);
    let now = SystemClock.now();

    let mut remote: RemoteStore = HashMap::new();
    let mut child_rids = Vec::new();

    let mut prev_hash: Option<SignatureHash> = None;
    for i in 0..n_children {
        let child_rid = RecordingId::new(format!("child-{i}"));
        child_rids.push(child_rid.clone());

        let entry = ManifestEntry {
            timestamp: now,
            sequence_id: StorageSequence(i.saturating_add(1)),
            recording_id: manifest_id.clone(),
            child_recording_id: child_rid.clone(),
        };
        let env = WitnessEnvelope::sign_envelope(
            Evidence::ManifestEntry(entry),
            identity,
            identity.witness_id.clone(),
            prev_hash,
        )
        .expect("sign manifest entry");
        prev_hash = Some(env.signature_hash());
        remote.entry(manifest_id.clone()).or_default().push(env);

        // Each child gets two video shards.
        let mut child_prev: Option<SignatureHash> = None;
        for seq in 1u32..=2 {
            let shard = video_shard_for_recording(&child_rid, seq, now);
            let child_env = WitnessEnvelope::sign_envelope(
                Evidence::Video(shard),
                identity,
                identity.witness_id.clone(),
                child_prev,
            )
            .expect("sign child shard");
            child_prev = Some(child_env.signature_hash());
            remote.entry(child_rid.clone()).or_default().push(child_env);
        }
    }

    (remote, child_rids)
}

/// Configuration for the mock egress responder. `defer_rids` lets a test
/// pretend specific children aren't yet reachable on the mesh — the
/// responder swallows `RequestShards` for those rids until the test
/// flips the flag.
#[derive(Default)]
struct MockEgressConfig {
    /// RIDs the responder should NOT inject shards for. Used to keep
    /// recovery in stage 3 long enough for cancellation tests.
    defer_rids: HashSet<RecordingId>,
}

/// Runs a mock egress task that:
/// - Replies to `FindProviders(rid)` with `(rid, [random_addr])`.
/// - On `RequestShards { request, .. }`, copies all envelopes for
///   `request.recording_id` from the remote store into the recovering
///   StorageActor via `WriteShard` (one command per envelope).
///
/// The `requested_rids` Mutex tracks every rid the orchestrator
/// requested — tests assert on it to verify idempotent skipping.
fn spawn_mock_egress(
    mut egress_rx: mpsc::Receiver<EgressCommand>,
    providers_tx: mpsc::Sender<(RecordingId, Vec<MeshAddress>)>,
    storage_tx: mpsc::Sender<StorageCommand>,
    remote: RemoteStore,
    config: Arc<StdMutex<MockEgressConfig>>,
    requested_rids: Arc<StdMutex<HashSet<RecordingId>>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(cmd) = egress_rx.recv().await {
            match cmd {
                EgressCommand::FindProviders(rid) => {
                    let _ = providers_tx.send((rid, vec![MeshAddress::random()])).await;
                }
                EgressCommand::RequestShards { request, .. } => {
                    let rid = request.recording_id.clone();
                    requested_rids
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(rid.clone());

                    let deferred = config
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .defer_rids
                        .contains(&rid);
                    if deferred {
                        continue;
                    }

                    if let Some(envelopes) = remote.get(&rid) {
                        for env in envelopes {
                            let (reply_to, _ack) = oneshot::channel();
                            let _ = storage_tx
                                .send(StorageCommand::WriteShard {
                                    envelope: env.clone(),
                                    reply_to,
                                })
                                .await;
                        }
                    }
                }
                _ => {
                    // Other egress commands are no-ops in the mock.
                }
            }
        }
    })
}

/// Wait for `predicate(snapshot)` to hold or `timeout` to elapse. Polls
/// the shared status mutex every 50ms.
async fn wait_for_status(
    status: &Arc<StdMutex<RecoveryStatus>>,
    timeout: Duration,
    predicate: impl Fn(&RecoveryStatus) -> bool,
) -> RecoveryStatus {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let snap = status.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if predicate(&snap) {
            return snap;
        }
        if tokio::time::Instant::now() >= deadline {
            return snap;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Build the orchestrator's RecoveryContext + a cancel sender. Spawns the
/// mock egress task, the recovering StorageActor, and returns everything
/// the test needs. The TempDir guard is returned so the vault directory
/// outlives the test.
struct Harness {
    identity: Arc<PhalanxIdentity>,
    storage_tx: mpsc::Sender<StorageCommand>,
    status: Arc<StdMutex<RecoveryStatus>>,
    cancel_tx: oneshot::Sender<()>,
    requested_rids: Arc<StdMutex<HashSet<RecordingId>>>,
    egress_config: Arc<StdMutex<MockEgressConfig>>,
    ctx: Option<RecoveryContext>,
    cancel_rx: Option<oneshot::Receiver<()>>,
    _storage_handle: JoinHandle<()>,
    _egress_handle: JoinHandle<()>,
    _temp: tempfile::TempDir,
}

fn build_harness(identity: Arc<PhalanxIdentity>, remote: RemoteStore) -> Harness {
    let (storage_tx, storage_handle, temp) = spawn_recovering_storage(&identity);

    let (egress_tx, egress_rx) = mpsc::channel(64);
    let (providers_tx, providers_rx) = mpsc::channel(64);

    let (cancel_tx, cancel_rx) = oneshot::channel();
    let status = Arc::new(StdMutex::new(RecoveryStatus::default()));
    let requested_rids = Arc::new(StdMutex::new(HashSet::new()));
    let egress_config = Arc::new(StdMutex::new(MockEgressConfig::default()));

    let egress_handle = spawn_mock_egress(
        egress_rx,
        providers_tx,
        storage_tx.clone(),
        remote,
        egress_config.clone(),
        requested_rids.clone(),
    );

    let ctx = RecoveryContext {
        identity: identity.clone(),
        storage_tx: storage_tx.clone(),
        egress_tx,
        providers_rx,
        status: status.clone(),
    };

    Harness {
        identity,
        storage_tx,
        status,
        cancel_tx,
        requested_rids,
        egress_config,
        ctx: Some(ctx),
        cancel_rx: Some(cancel_rx),
        _storage_handle: storage_handle,
        _egress_handle: egress_handle,
        _temp: temp,
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

/// Load-bearing end-to-end: synthesize a manifest cataloging 3 children +
/// the 3 child recordings; run recovery; assert all children land locally
/// and the orchestrator declares Complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovery_walks_manifest_and_fetches_children() {
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let identity = Arc::new(identity);
    let (remote, child_rids) = synthesize_remote(&identity, 3);

    let mut harness = build_harness(identity.clone(), remote);
    let ctx = harness.ctx.take().unwrap();
    let cancel_rx = harness.cancel_rx.take().unwrap();

    let recovery_handle = tokio::spawn(run_recovery(ctx, cancel_rx));

    let final_status = wait_for_status(&harness.status, Duration::from_secs(30), |s| {
        s.state == RecoveryState::Complete
    })
    .await;

    assert_eq!(
        final_status.state,
        RecoveryState::Complete,
        "recovery did not reach Complete: got {final_status:?}"
    );
    assert_eq!(final_status.total, 3, "expected 3 cataloged children");
    assert_eq!(
        final_status.recovered, 3,
        "expected all 3 children recovered"
    );

    // Verify each child is queryable from the recovering side.
    let (reply_to, rx) = oneshot::channel();
    harness
        .storage_tx
        .send(StorageCommand::ListRecordings { reply_to })
        .await
        .unwrap();
    let listed: HashSet<RecordingId> = rx.await.unwrap().into_iter().collect();
    for rid in &child_rids {
        assert!(
            listed.contains(rid),
            "child {} not found locally after recovery",
            rid.as_str()
        );
    }

    let _ = recovery_handle.await;
    drop(harness.cancel_tx); // unused — recovery completed naturally
}

/// Resume invariant: pre-populate one child on the recovering side. Recovery
/// must skip that child (no `RequestShards` for it) and still reach
/// `recovered == 3` (the pre-populated child counts).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovery_skips_already_on_disk_children() {
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let identity = Arc::new(identity);
    let (remote, child_rids) = synthesize_remote(&identity, 3);

    let mut harness = build_harness(identity.clone(), remote.clone());

    // Pre-populate child-0 on the recovering Guardian by writing its
    // envelopes through the storage actor before recovery starts.
    let preloaded_rid = child_rids[0].clone();
    for env in remote.get(&preloaded_rid).unwrap() {
        let (reply_to, ack) = oneshot::channel();
        harness
            .storage_tx
            .send(StorageCommand::WriteShard {
                envelope: env.clone(),
                reply_to,
            })
            .await
            .unwrap();
        let _ = ack.await;
    }

    let ctx = harness.ctx.take().unwrap();
    let cancel_rx = harness.cancel_rx.take().unwrap();

    let recovery_handle = tokio::spawn(run_recovery(ctx, cancel_rx));

    let final_status = wait_for_status(&harness.status, Duration::from_secs(30), |s| {
        s.state == RecoveryState::Complete
    })
    .await;

    assert_eq!(final_status.state, RecoveryState::Complete);
    assert_eq!(final_status.total, 3);
    assert_eq!(final_status.recovered, 3);

    let requested = harness
        .requested_rids
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    assert!(
        !requested.contains(&preloaded_rid),
        "orchestrator issued RequestShards for already-on-disk child {}",
        preloaded_rid.as_str()
    );

    let _ = recovery_handle.await;
    drop(harness.cancel_tx);
}

/// No manifest reachable: empty remote store. The mock egress responds to
/// `FindProviders` with provider lists, but `RequestShards` finds no
/// envelopes — nothing ever lands locally. Expect `NoManifestFound`
/// after the manifest budget elapses.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn no_manifest_yields_no_manifest_found() {
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let identity = Arc::new(identity);
    let empty: RemoteStore = HashMap::new();

    let mut harness = build_harness(identity, empty);
    let ctx = harness.ctx.take().unwrap();
    let cancel_rx = harness.cancel_rx.take().unwrap();

    let recovery_handle = tokio::spawn(run_recovery(ctx, cancel_rx));

    // Advance past the 60s manifest budget. start_paused keeps the wall
    // clock from advancing on its own; advance() yields between steps so
    // the spawned tasks process queued events.
    for _ in 0..70 {
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
    }

    let final_status = wait_for_status(&harness.status, Duration::from_secs(5), |s| {
        s.state == RecoveryState::NoManifestFound
    })
    .await;

    assert_eq!(
        final_status.state,
        RecoveryState::NoManifestFound,
        "expected NoManifestFound, got {final_status:?}"
    );

    let _ = recovery_handle.await;
    drop(harness.cancel_tx);
}

/// Cancel mid-walk: defer two of the three children so recovery sits in
/// FetchingChildren. Fire cancel. Assert state transitions to Cancelled
/// within a few seconds and a follow-up `run_recovery` resumes the
/// remaining children.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_during_children_stage_yields_cancelled() {
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let identity = Arc::new(identity);
    let (remote, child_rids) = synthesize_remote(&identity, 3);

    // Defer children 1 and 2 — only child-0 will land before cancel.
    let deferred: HashSet<RecordingId> = vec![child_rids[1].clone(), child_rids[2].clone()]
        .into_iter()
        .collect();

    let mut harness = build_harness(identity.clone(), remote.clone());
    harness
        .egress_config
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .defer_rids
        .clone_from(&deferred);

    let ctx = harness.ctx.take().unwrap();
    let cancel_rx = harness.cancel_rx.take().unwrap();
    let recovery_handle = tokio::spawn(run_recovery(ctx, cancel_rx));

    // Wait until the orchestrator is in stage 3 (FetchingChildren)
    // before firing cancel.
    let _ = wait_for_status(&harness.status, Duration::from_secs(30), |s| {
        s.state == RecoveryState::FetchingChildren
    })
    .await;

    let _ = harness.cancel_tx.send(());

    let cancelled = wait_for_status(&harness.status, Duration::from_secs(10), |s| {
        s.state == RecoveryState::Cancelled
    })
    .await;
    assert_eq!(
        cancelled.state,
        RecoveryState::Cancelled,
        "expected Cancelled, got {cancelled:?}"
    );

    let _ = recovery_handle.await;

    // ── Resume: stop deferring, run recovery again, watch it finish. ──

    {
        let mut cfg = harness
            .egress_config
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        cfg.defer_rids.clear();
    }
    // Reset status so the next run_recovery starts fresh.
    {
        let mut s = harness.status.lock().unwrap_or_else(|e| e.into_inner());
        *s = RecoveryStatus::default();
    }

    let (egress_tx, egress_rx) = mpsc::channel(64);
    let (providers_tx, providers_rx) = mpsc::channel(64);
    let _resume_egress = spawn_mock_egress(
        egress_rx,
        providers_tx,
        harness.storage_tx.clone(),
        remote,
        harness.egress_config.clone(),
        harness.requested_rids.clone(),
    );

    let (cancel_tx2, cancel_rx2) = oneshot::channel();
    let resume_ctx = RecoveryContext {
        identity: harness.identity.clone(),
        storage_tx: harness.storage_tx.clone(),
        egress_tx,
        providers_rx,
        status: harness.status.clone(),
    };
    let resume_handle = tokio::spawn(run_recovery(resume_ctx, cancel_rx2));

    let resumed = wait_for_status(&harness.status, Duration::from_secs(30), |s| {
        s.state == RecoveryState::Complete
    })
    .await;
    assert_eq!(resumed.state, RecoveryState::Complete);
    assert_eq!(resumed.total, 3);
    assert_eq!(resumed.recovered, 3);

    // Confirm every child rid is queryable.
    let (reply_to, rx) = oneshot::channel();
    harness
        .storage_tx
        .send(StorageCommand::ListRecordings { reply_to })
        .await
        .unwrap();
    let listed: HashSet<RecordingId> = rx.await.unwrap().into_iter().collect();
    for rid in &child_rids {
        assert!(
            listed.contains(rid),
            "child {} missing after resume",
            rid.as_str()
        );
    }

    let _ = resume_handle.await;
    drop(cancel_tx2);
}
