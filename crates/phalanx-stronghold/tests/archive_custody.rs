#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
// Receiver-side integration tests for the directed archive PUSH custody path:
// the AggregationActor's PersistEnvelopes (fairness gate + persist), the TTL
// sweep, and the membership/quota refusals. Drives the actor over its mailbox
// with real signed envelopes and a real (temp) EvidenceStore — no swarm.

use std::collections::HashMap;
use std::sync::Arc;

use phalanx_proto::community::CommunityId;
use phalanx_proto::identity::{PhalanxIdentity, RecordingId};
use phalanx_stronghold::actors::aggregation::{AggregationActor, AggregationCommand, ArchiveAdmit};
use phalanx_stronghold::config::StrongholdConfig;
use phalanx_stronghold::governor::StrongholdGovernor;
use phalanx_stronghold::persistence::evidence_store::EvidenceStore;
use phalanx_test_fixtures::envelope::witness_envelope_for_recording;
use tempfile::tempdir;
use tokio::sync::mpsc;

/// Spawn an AggregationActor over a temp EvidenceStore with the given config.
/// Returns the command sender, the actor's JoinHandle, and an independent
/// reader EvidenceStore over the same vault for on-disk assertions.
fn spawn_actor(
    config: Arc<StrongholdConfig>,
    vault: std::path::PathBuf,
) -> (
    mpsc::Sender<AggregationCommand>,
    tokio::task::JoinHandle<()>,
    EvidenceStore,
) {
    let store = EvidenceStore::new(vault.clone());
    let reader = EvidenceStore::new(vault);
    let governor = Arc::new(StrongholdGovernor::new());
    let (tx, rx) = mpsc::channel(64);
    let actor = AggregationActor::new(store, governor, config, rx);
    let handle = tokio::spawn(actor.run());
    (tx, handle, reader)
}

/// Send PersistEnvelopes and await the admission outcome.
async fn push(
    tx: &mpsc::Sender<AggregationCommand>,
    recording_id: RecordingId,
    envelopes: Vec<phalanx_proto::evidence::WitnessEnvelope>,
    owner_did: phalanx_proto::identity::Did,
) -> ArchiveAdmit {
    let (rtx, rrx) = oneshot::channel();
    tx.send(AggregationCommand::PersistEnvelopes {
        recording_id,
        envelopes,
        owner_did,
        reply_to: rtx,
    })
    .await
    .unwrap();
    rrx.await.unwrap()
}

/// Flush the actor's mailbox up to this point: the actor processes commands
/// sequentially, so a round-tripped FetchProximity guarantees all prior
/// fire-and-forget commands (RefreshRouting, SweepExpired) have been applied.
async fn flush(tx: &mpsc::Sender<AggregationCommand>, community: CommunityId) {
    let (ptx, prx) = oneshot::channel();
    tx.send(AggregationCommand::FetchProximity {
        community_id: community,
        reply_to: ptx,
    })
    .await
    .unwrap();
    let _ = prx.await.unwrap();
}

fn base_config(vault: &std::path::Path) -> StrongholdConfig {
    let mut config = StrongholdConfig::default();
    config.storage.vault_path = vault.to_string_lossy().to_string();
    config
}

#[tokio::test]
async fn archive_push_persists_then_sweeps_on_expiry() {
    let dir = tempdir().unwrap();
    let mut config = base_config(dir.path());
    config.storage.custody_ttl_secs = 0; // held_until == stored_at → immediately expirable
    let config = Arc::new(config);

    let (tx, handle, reader) = spawn_actor(config, dir.path().to_path_buf());

    let owner = PhalanxIdentity::new_ephemeral();
    let community = CommunityId([7u8; 32]);
    let mut routing = HashMap::new();
    routing.insert(owner.did.clone(), vec![community]);
    tx.send(AggregationCommand::RefreshRouting { routing })
        .await
        .unwrap();

    let rid = RecordingId::new("rec-custody");
    let envelopes: Vec<_> = (0..3)
        .map(|seq| witness_envelope_for_recording(&owner, &rid, seq, None))
        .collect();

    let outcome = push(&tx, rid.clone(), envelopes, owner.did.clone()).await;
    assert!(
        matches!(
            outcome,
            ArchiveAdmit::Stored {
                envelope_count: 3,
                ..
            }
        ),
        "expected Stored(3), got {outcome:?}"
    );

    // Persisted on disk.
    let recs = reader.list_recordings(&community).await.unwrap();
    assert!(
        recs.contains(&rid),
        "recording should be persisted: {recs:?}"
    );

    // Sweep — with ttl=0 the recording is already expired.
    tx.send(AggregationCommand::SweepExpired).await.unwrap();
    flush(&tx, community).await;

    let recs_after = reader.list_recordings(&community).await.unwrap();
    assert!(
        !recs_after.contains(&rid),
        "recording should be reclaimed by the custody sweep: {recs_after:?}"
    );

    drop(tx);
    let _ = handle.await;
}

#[tokio::test]
async fn archive_push_refused_when_per_owner_cap_exceeded() {
    let dir = tempdir().unwrap();
    let mut config = base_config(dir.path());
    // Tiny caps: any real envelope exceeds 1 byte → the fairness gate must fire.
    config.storage.max_bytes_per_owner = 1;
    config.storage.max_per_community_bytes = 1;
    config.storage.owner_fair_share_ratio = 1.0;
    let config = Arc::new(config);

    let (tx, handle, reader) = spawn_actor(config, dir.path().to_path_buf());

    let owner = PhalanxIdentity::new_ephemeral();
    let community = CommunityId([9u8; 32]);
    let mut routing = HashMap::new();
    routing.insert(owner.did.clone(), vec![community]);
    tx.send(AggregationCommand::RefreshRouting { routing })
        .await
        .unwrap();

    let rid = RecordingId::new("rec-flood");
    let envelopes = vec![witness_envelope_for_recording(&owner, &rid, 0, None)];

    let outcome = push(&tx, rid.clone(), envelopes, owner.did.clone()).await;
    assert!(
        matches!(outcome, ArchiveAdmit::QuotaExceeded),
        "expected QuotaExceeded, got {outcome:?}"
    );

    let recs = reader.list_recordings(&community).await.unwrap_or_default();
    assert!(
        recs.is_empty(),
        "nothing should persist when admission is refused: {recs:?}"
    );

    drop(tx);
    let _ = handle.await;
}

#[tokio::test]
async fn re_pushing_same_recording_does_not_leak_ledger_bytes() {
    // Differential regression for the idempotent-re-push ledger leak: the
    // per-owner cap is sized to exactly TWO copies. We push A, re-push A
    // (identical), then push a DISTINCT recording B. With the leak, A+re-A would
    // occupy 2 copies of ledger budget and B would be refused; with the fix,
    // re-pushing A releases its prior bytes first, so the owner holds one copy
    // for A and B still fits.
    let dir = tempdir().unwrap();

    let owner = PhalanxIdentity::new_ephemeral();
    let rid_a = RecordingId::new("rec-a");
    let env_a = witness_envelope_for_recording(&owner, &rid_a, 0, None);
    let one_copy = postcard::to_allocvec(&env_a).unwrap().len() as u64;

    let mut config = base_config(dir.path());
    config.storage.max_bytes_per_owner = 2 * one_copy; // room for exactly two copies
    config.storage.max_per_community_bytes = 2 * one_copy;
    config.storage.owner_fair_share_ratio = 1.0;
    let config = Arc::new(config);

    let (tx, handle, _reader) = spawn_actor(config, dir.path().to_path_buf());

    let community = CommunityId([5u8; 32]);
    let mut routing = HashMap::new();
    routing.insert(owner.did.clone(), vec![community]);
    tx.send(AggregationCommand::RefreshRouting { routing })
        .await
        .unwrap();

    // Push A, then re-push the identical recording A.
    let a1 = push(&tx, rid_a.clone(), vec![env_a.clone()], owner.did.clone()).await;
    assert!(
        matches!(a1, ArchiveAdmit::Stored { .. }),
        "A should store: {a1:?}"
    );
    let a2 = push(&tx, rid_a.clone(), vec![env_a], owner.did.clone()).await;
    assert!(
        matches!(a2, ArchiveAdmit::Stored { .. }),
        "re-pushing A should still store (prior released): {a2:?}"
    );

    // A distinct recording B must still fit — proving A's budget wasn't leaked.
    let rid_b = RecordingId::new("rec-b");
    let env_b = witness_envelope_for_recording(&owner, &rid_b, 0, None);
    let b = push(&tx, rid_b, vec![env_b], owner.did.clone()).await;
    assert!(
        matches!(b, ArchiveAdmit::Stored { .. }),
        "B must fit; if it is QuotaExceeded the re-push leaked ledger bytes: {b:?}"
    );

    drop(tx);
    let _ = handle.await;
}

#[tokio::test]
async fn archive_push_from_unknown_did_is_rejected() {
    let dir = tempdir().unwrap();
    let config = Arc::new(base_config(dir.path()));

    let (tx, handle, _reader) = spawn_actor(config, dir.path().to_path_buf());

    // No RefreshRouting → the owner DID is not a member of any served community.
    let owner = PhalanxIdentity::new_ephemeral();
    let rid = RecordingId::new("rec-stranger");
    let envelopes = vec![witness_envelope_for_recording(&owner, &rid, 0, None)];

    let outcome = push(&tx, rid, envelopes, owner.did.clone()).await;
    assert!(
        matches!(outcome, ArchiveAdmit::Rejected),
        "non-member push must be Rejected, got {outcome:?}"
    );

    drop(tx);
    let _ = handle.await;
}

#[tokio::test]
async fn archive_push_with_forged_owner_did_is_rejected() {
    let dir = tempdir().unwrap();
    let config = Arc::new(base_config(dir.path()));

    let (tx, handle, _reader) = spawn_actor(config, dir.path().to_path_buf());

    // Envelopes are signed by `signer`, but the push claims a different,
    // routed owner DID — the per-envelope signer check must reject it.
    let signer = PhalanxIdentity::new_ephemeral();
    let claimed = PhalanxIdentity::new_ephemeral();
    let community = CommunityId([3u8; 32]);
    let mut routing = HashMap::new();
    routing.insert(claimed.did.clone(), vec![community]);
    tx.send(AggregationCommand::RefreshRouting { routing })
        .await
        .unwrap();

    let rid = RecordingId::new("rec-spoof");
    let envelopes = vec![witness_envelope_for_recording(&signer, &rid, 0, None)];

    let outcome = push(&tx, rid, envelopes, claimed.did.clone()).await;
    assert!(
        matches!(outcome, ArchiveAdmit::Rejected),
        "envelope signer != claimed owner must be Rejected, got {outcome:?}"
    );

    drop(tx);
    let _ = handle.await;
}
