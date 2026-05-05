// crates/phalanx-node/src/actors/recovery.rs
//
// Recovery orchestrator: drives the manifest-walk consumer side of
// mesh-recoverable recordings.
//
// The realization: manifest recovery is the same as recording recovery.
// The Crucible already handles "shards arrive over time, recording
// assembles" for any RecordingId. The orchestrator's job is just to fire
// `EgressCommand::FindProviders`, let the receive pipeline
// (`ShardResponseReceived → WriteShard → append_shard → ingest_envelope →
// Crucible`) deposit shards into the local recording log, then read them
// back via `StorageCommand::Retrieval` to discover what to fetch next.
//
// Stage 1 (FetchingManifest): find providers for the manifest, wait for it
//                              to land locally.
// Stage 2 (WalkingManifest):   read manifest envelopes, extract child rids.
// Stage 3 (FetchingChildren):  fire FindProviders for every unrecovered
//                              child, poll ListRecordings until they all
//                              arrive (or the stage budget elapses).
//
// All three stages reuse the same single `providers_rx`, fed by a private
// `consume_providers` task that converts `(rid, providers)` pairs into
// signed `EgressCommand::RequestShards` events using the same
// `build_recording_request` helper that PlaybackCoordinator uses.

use crate::actors::egress::EgressCommand;
use crate::actors::retrieval_request::build_recording_request;
use crate::actors::storage::StorageCommand;

use phalanx_forensics::cryptography::dek::{derive_manifest_recording_id, derive_recording_dek};
use phalanx_proto::evidence::{Evidence, WitnessEnvelope};
use phalanx_proto::identity::{MeshAddress, PhalanxIdentity, RecordingId};
use phalanx_proto::recovery::{RecoveryState, RecoveryStatus};

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::sleep;

/// Manifest-stage budget. If the manifest hasn't landed locally within this
/// window, recovery declares `NoManifestFound`. 60s comfortably accommodates
/// initial DHT walk + `RecordingRequest` round-trip on a cold mesh.
const MANIFEST_STAGE_TIMEOUT: Duration = Duration::from_secs(60);

/// Children-stage budget. After this elapses, recovery exits `Complete`
/// with `recovered < total` — an honest partial result the user can
/// resume from. 600s is a soft cap; the bottleneck is per-Stronghold
/// response round-trips, not orchestrator overhead.
const CHILDREN_STAGE_TIMEOUT: Duration = Duration::from_secs(600);

/// `ListRecordings` polling cadence.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Re-issue `FindProviders` every N polls. Strongholds may come online
/// during the wait; keep nudging the DHT.
const REFIND_EVERY_TICKS: u32 = 10;

/// Buffered providers fan-in capacity. Mirrors `MeshSentinel::spawn_playback`'s
/// channel for the same kind.
pub(crate) const PROVIDERS_CHANNEL_BUFFER: usize = 100;

/// Dependencies handed to the orchestrator. Built by
/// `MeshSentinel::spawn_recovery`; consumed by `run_recovery`.
pub struct RecoveryContext {
    pub identity: Arc<PhalanxIdentity>,
    pub storage_tx: mpsc::Sender<StorageCommand>,
    pub egress_tx: mpsc::Sender<EgressCommand>,
    pub providers_rx: mpsc::Receiver<(RecordingId, Vec<MeshAddress>)>,
    pub status: Arc<Mutex<RecoveryStatus>>,
}

/// Outcome of a per-recording wait. Drives stage transitions.
enum WaitOutcome {
    ArrivedLocally,
    TimedOut,
    Cancelled,
}

/// Drive a recovery walk to completion.
///
/// Single entry point. Called from `MeshSentinel::spawn_recovery`. Updates
/// `ctx.status` at every stage transition and on every poll iteration so
/// the FFI's `phalanx_recovery_status` always sees a fresh snapshot.
///
/// Honors `cancel_rx` at every poll: a fired cancel exits with state
/// `Cancelled` and partial state on disk is preserved (a subsequent
/// `run_recovery` will skip already-on-disk children).
pub async fn run_recovery(ctx: RecoveryContext, mut cancel_rx: oneshot::Receiver<()>) {
    let RecoveryContext {
        identity,
        storage_tx,
        egress_tx,
        providers_rx,
        status,
    } = ctx;

    let consumer_handle =
        spawn_consume_providers(providers_rx, egress_tx.clone(), identity.clone());

    // ── Stage 1: FetchingManifest ────────────────────────────────────────
    let manifest_id = derive_manifest_recording_id(&identity.dek_master);
    set_state(&status, RecoveryState::FetchingManifest);

    match wait_for_recording_locally(
        &manifest_id,
        &storage_tx,
        &egress_tx,
        &mut cancel_rx,
        MANIFEST_STAGE_TIMEOUT,
    )
    .await
    {
        WaitOutcome::TimedOut => {
            set_state(&status, RecoveryState::NoManifestFound);
            consumer_handle.abort();
            return;
        }
        WaitOutcome::Cancelled => {
            set_state(&status, RecoveryState::Cancelled);
            consumer_handle.abort();
            return;
        }
        WaitOutcome::ArrivedLocally => {}
    }

    // ── Stage 2: WalkingManifest ─────────────────────────────────────────
    set_state(&status, RecoveryState::WalkingManifest);
    let expected = match read_manifest_children(&manifest_id, &identity, &storage_tx).await {
        Some(set) => set,
        None => {
            // Storage actor dropped the reply. Treat as no manifest — the
            // user can re-run.
            set_state(&status, RecoveryState::NoManifestFound);
            consumer_handle.abort();
            return;
        }
    };

    {
        let mut s = status.lock().unwrap_or_else(|e| e.into_inner());
        s.total = u32::try_from(expected.len()).unwrap_or(u32::MAX);
        s.recovered = 0;
        s.failed = 0;
        s.current = None;
    }

    // ── Stage 3: FetchingChildren ────────────────────────────────────────
    set_state(&status, RecoveryState::FetchingChildren);

    let on_disk_initial = list_recordings(&storage_tx).await.unwrap_or_default();
    let mut unrecovered: BTreeSet<RecordingId> =
        expected.difference(&on_disk_initial).cloned().collect();

    {
        let mut s = status.lock().unwrap_or_else(|e| e.into_inner());
        let already = expected.len().saturating_sub(unrecovered.len());
        s.recovered = u32::try_from(already).unwrap_or(u32::MAX);
    }

    // Initial parallel fan-out for the unrecovered set. The bounded mpsc
    // (capacity 100 in `EgressCommand` channel) provides natural
    // backpressure if the recovering identity has more than 100 unfetched
    // recordings; remaining sends queue at the await boundary.
    for rid in &unrecovered {
        let _ = egress_tx
            .send(EgressCommand::FindProviders(rid.clone()))
            .await;
    }

    let mut tick: u32 = 0;
    let stage_deadline = tokio::time::Instant::now()
        .checked_add(CHILDREN_STAGE_TIMEOUT)
        .unwrap_or_else(tokio::time::Instant::now);

    while !unrecovered.is_empty() {
        if cancel_rx.try_recv().is_ok() {
            set_state(&status, RecoveryState::Cancelled);
            consumer_handle.abort();
            return;
        }

        if tokio::time::Instant::now() >= stage_deadline {
            // Stage budget exhausted — exit Complete with partial recovery.
            break;
        }

        sleep(POLL_INTERVAL).await;
        tick = tick.saturating_add(1);

        let on_disk = list_recordings(&storage_tx).await.unwrap_or_default();
        unrecovered.retain(|rid| !on_disk.contains(rid));

        {
            let mut s = status.lock().unwrap_or_else(|e| e.into_inner());
            let recovered_count = expected.len().saturating_sub(unrecovered.len());
            s.recovered = u32::try_from(recovered_count).unwrap_or(u32::MAX);
        }

        if tick.is_multiple_of(REFIND_EVERY_TICKS) {
            for rid in &unrecovered {
                let _ = egress_tx
                    .send(EgressCommand::FindProviders(rid.clone()))
                    .await;
            }
        }
    }

    set_state(&status, RecoveryState::Complete);
    consumer_handle.abort();
}

/// Update only the `state` field on the shared status snapshot. Other
/// fields are preserved across stage transitions.
fn set_state(status: &Arc<Mutex<RecoveryStatus>>, new: RecoveryState) {
    let mut s = status.lock().unwrap_or_else(|e| e.into_inner());
    s.state = new;
}

/// Spawn the providers-consumer task. It owns `providers_rx` for the
/// lifetime of the recovery and converts each `(rid, providers)` tuple
/// into one signed `EgressCommand::RequestShards` per provider.
///
/// Aborted at recovery exit so the providers channel returns to a quiescent
/// state for the next recovery / playback session.
fn spawn_consume_providers(
    mut providers_rx: mpsc::Receiver<(RecordingId, Vec<MeshAddress>)>,
    egress_tx: mpsc::Sender<EgressCommand>,
    identity: Arc<PhalanxIdentity>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some((rid, providers)) = providers_rx.recv().await {
            let dek = derive_recording_dek(&identity.dek_master, &rid);
            let request = match build_recording_request(&rid, &dek, &identity) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        rid = %rid.as_str(),
                        error = %e,
                        "recovery: build_recording_request failed",
                    );
                    continue;
                }
            };
            for provider in providers {
                let _ = egress_tx
                    .send(EgressCommand::RequestShards {
                        target: provider,
                        request: request.clone(),
                    })
                    .await;
            }
        }
    })
}

/// Wait for a single `rid` to appear in the local recording log. Polls
/// `ListRecordings` every `POLL_INTERVAL`; re-issues `FindProviders` every
/// `REFIND_EVERY_TICKS` polls. Honors `cancel_rx`. Returns after
/// `total_timeout` if the recording never arrives.
///
/// Used for Stage 1 (manifest). Stage 3 has its own multi-rid loop.
async fn wait_for_recording_locally(
    rid: &RecordingId,
    storage_tx: &mpsc::Sender<StorageCommand>,
    egress_tx: &mpsc::Sender<EgressCommand>,
    cancel_rx: &mut oneshot::Receiver<()>,
    total_timeout: Duration,
) -> WaitOutcome {
    // Initial FindProviders kick.
    let _ = egress_tx
        .send(EgressCommand::FindProviders(rid.clone()))
        .await;

    let deadline = tokio::time::Instant::now()
        .checked_add(total_timeout)
        .unwrap_or_else(tokio::time::Instant::now);
    let mut tick: u32 = 0;

    loop {
        if cancel_rx.try_recv().is_ok() {
            return WaitOutcome::Cancelled;
        }
        if tokio::time::Instant::now() >= deadline {
            return WaitOutcome::TimedOut;
        }

        let on_disk = list_recordings(storage_tx).await.unwrap_or_default();
        if on_disk.contains(rid) {
            return WaitOutcome::ArrivedLocally;
        }

        sleep(POLL_INTERVAL).await;
        tick = tick.saturating_add(1);

        if tick.is_multiple_of(REFIND_EVERY_TICKS) {
            let _ = egress_tx
                .send(EgressCommand::FindProviders(rid.clone()))
                .await;
        }
    }
}

/// Query `StorageActor` for the full recording-id set. Returns a
/// `BTreeSet` so set-difference / intersection are cheap.
async fn list_recordings(
    storage_tx: &mpsc::Sender<StorageCommand>,
) -> Option<BTreeSet<RecordingId>> {
    let (reply_to, rx) = oneshot::channel();
    storage_tx
        .send(StorageCommand::ListRecordings { reply_to })
        .await
        .ok()?;
    rx.await.ok().map(|v| v.into_iter().collect())
}

/// Read the manifest's envelopes back from the local vault and extract
/// every `Evidence::ManifestEntry::child_recording_id`. Caller has already
/// verified the manifest is on disk (Stage 1 wait succeeded).
///
/// Returns `None` only on storage-actor failure; an empty manifest yields
/// `Some(empty_set)` and recovery transitions to Complete with `total == 0`.
async fn read_manifest_children(
    manifest_id: &RecordingId,
    identity: &PhalanxIdentity,
    storage_tx: &mpsc::Sender<StorageCommand>,
) -> Option<BTreeSet<RecordingId>> {
    let (reply_to, rx) = oneshot::channel();
    storage_tx
        .send(StorageCommand::Retrieval {
            recording_id: manifest_id.clone(),
            owner_did: Some(identity.did.clone()),
            reply_to,
        })
        .await
        .ok()?;

    let envelopes: Vec<WitnessEnvelope> = rx.await.ok()?;
    let mut children = BTreeSet::new();
    for env in envelopes {
        if let Evidence::ManifestEntry(entry) = env.evidence {
            children.insert(entry.child_recording_id);
        }
    }
    Some(children)
}
