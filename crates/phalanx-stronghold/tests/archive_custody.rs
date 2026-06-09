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
    let identity = Arc::new(PhalanxIdentity::new_ephemeral());
    let actor = AggregationActor::new(store, governor, config, identity, tx.downgrade(), rx);
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
        grant: None,
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

#[tokio::test]
async fn revoked_recording_is_refused_and_releases_quota() {
    let dir = tempdir().unwrap();
    let config = Arc::new(base_config(dir.path()));
    let (tx, handle, reader) = spawn_actor(config, dir.path().to_path_buf());

    let owner = PhalanxIdentity::new_ephemeral();
    let community = CommunityId([4u8; 32]);
    let mut routing = HashMap::new();
    routing.insert(owner.did.clone(), vec![community]);
    tx.send(AggregationCommand::RefreshRouting { routing })
        .await
        .unwrap();

    let rid = RecordingId::new("rec-revoke");
    let env = witness_envelope_for_recording(&owner, &rid, 0, None);
    let stored = push(&tx, rid.clone(), vec![env.clone()], owner.did.clone()).await;
    assert!(matches!(stored, ArchiveAdmit::Stored { .. }), "{stored:?}");

    // Cryptographic forgetting.
    tx.send(AggregationCommand::Revoke {
        recording_id: rid.clone(),
    })
    .await
    .unwrap();
    flush(&tx, community).await;

    // The persisted copy is gone.
    let recs = reader.list_recordings(&community).await.unwrap_or_default();
    assert!(!recs.contains(&rid), "revoked recording should be deleted");

    // And a re-push of the same recording_id is refused — never resurrected.
    let again = push(&tx, rid.clone(), vec![env], owner.did.clone()).await;
    assert!(
        matches!(again, ArchiveAdmit::Rejected),
        "revoked recording must not be re-admitted: {again:?}"
    );

    drop(tx);
    let _ = handle.await;
}

#[tokio::test]
async fn restart_reconciles_custody_ledger_from_disk() {
    // Restart durability: the fairness ledger and custody deadlines are rebuilt
    // from on-disk sidecars on startup. We size the per-owner cap to exactly ONE
    // copy: push A (fills the cap), restart the actor over the SAME vault, then a
    // DISTINCT recording B from the same owner must be refused — proving A's
    // bytes were re-occupied on reconcile (without it, the ledger resets to empty
    // and B would be admitted, silently doubling the owner's footprint).
    let dir = tempdir().unwrap();
    let owner = PhalanxIdentity::new_ephemeral();
    let rid_a = RecordingId::new("rec-a");
    let env_a = witness_envelope_for_recording(&owner, &rid_a, 0, None);
    let one_copy = postcard::to_allocvec(&env_a).unwrap().len() as u64;

    let mut config = base_config(dir.path());
    config.storage.max_bytes_per_owner = one_copy;
    config.storage.max_per_community_bytes = one_copy;
    config.storage.owner_fair_share_ratio = 1.0;
    config.storage.custody_ttl_secs = 3600; // not expired during the test
    let config = Arc::new(config);

    let community = CommunityId([6u8; 32]);
    let mut routing = HashMap::new();
    routing.insert(owner.did.clone(), vec![community]);

    // First lifetime: push A (fills the cap), then shut the actor down cleanly.
    {
        let (tx, handle, _reader) = spawn_actor(config.clone(), dir.path().to_path_buf());
        tx.send(AggregationCommand::RefreshRouting {
            routing: routing.clone(),
        })
        .await
        .unwrap();
        let a = push(&tx, rid_a.clone(), vec![env_a.clone()], owner.did.clone()).await;
        assert!(matches!(a, ArchiveAdmit::Stored { .. }), "{a:?}");
        drop(tx);
        handle.await.unwrap();
    }

    // Second lifetime over the SAME vault: reconcile must restore the ledger.
    {
        let (tx, handle, _reader) = spawn_actor(config.clone(), dir.path().to_path_buf());
        tx.send(AggregationCommand::RefreshRouting { routing })
            .await
            .unwrap();
        let rid_b = RecordingId::new("rec-b");
        let env_b = witness_envelope_for_recording(&owner, &rid_b, 0, None);
        let b = push(&tx, rid_b, vec![env_b], owner.did.clone()).await;
        assert!(
            matches!(b, ArchiveAdmit::QuotaExceeded),
            "after restart the ledger must be restored so the owner is still at cap: {b:?}"
        );
        drop(tx);
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn restart_self_heals_orphan_custody_sidecar() {
    // A custody sidecar whose shards were lost (crash between sidecar write and
    // shard write, or a partial reclaim) must NOT inflate the fairness ledger on
    // restart. Size the cap to one copy: push A, delete A's shards (leaving the
    // sidecar), restart, then a DISTINCT B from the same owner must still fit —
    // proving reconcile dropped the orphan sidecar instead of re-counting it.
    let dir = tempdir().unwrap();
    let owner = PhalanxIdentity::new_ephemeral();
    let rid_a = RecordingId::new("rec-a");
    let env_a = witness_envelope_for_recording(&owner, &rid_a, 0, None);
    let one_copy = postcard::to_allocvec(&env_a).unwrap().len() as u64;

    let mut config = base_config(dir.path());
    config.storage.max_bytes_per_owner = one_copy;
    config.storage.max_per_community_bytes = one_copy;
    config.storage.owner_fair_share_ratio = 1.0;
    config.storage.custody_ttl_secs = 3600;
    let config = Arc::new(config);

    let community = CommunityId([8u8; 32]);
    let mut routing = HashMap::new();
    routing.insert(owner.did.clone(), vec![community]);

    {
        let (tx, handle, reader) = spawn_actor(config.clone(), dir.path().to_path_buf());
        tx.send(AggregationCommand::RefreshRouting {
            routing: routing.clone(),
        })
        .await
        .unwrap();
        let a = push(&tx, rid_a.clone(), vec![env_a], owner.did.clone()).await;
        assert!(matches!(a, ArchiveAdmit::Stored { .. }), "{a:?}");
        // Simulate the shards being lost while the sidecar survives (orphan).
        reader.reclaim_recording(&community, &rid_a).await.unwrap();
        drop(tx);
        handle.await.unwrap();
    }

    {
        let (tx, handle, _reader) = spawn_actor(config.clone(), dir.path().to_path_buf());
        tx.send(AggregationCommand::RefreshRouting { routing })
            .await
            .unwrap();
        let rid_b = RecordingId::new("rec-b");
        let env_b = witness_envelope_for_recording(&owner, &rid_b, 0, None);
        let b = push(&tx, rid_b, vec![env_b], owner.did.clone()).await;
        assert!(
            matches!(b, ArchiveAdmit::Stored { .. }),
            "orphan sidecar (shards gone) must not occupy the ledger after restart: {b:?}"
        );
        drop(tx);
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn revocation_survives_restart() {
    // Cryptographic forgetting must persist: revoke a recording, restart, and a
    // re-push of the same recording_id is still refused.
    let dir = tempdir().unwrap();
    let config = Arc::new(base_config(dir.path()));
    let owner = PhalanxIdentity::new_ephemeral();
    let community = CommunityId([2u8; 32]);
    let mut routing = HashMap::new();
    routing.insert(owner.did.clone(), vec![community]);
    let rid = RecordingId::new("rec-forget");
    let env = witness_envelope_for_recording(&owner, &rid, 0, None);

    {
        let (tx, handle, _r) = spawn_actor(config.clone(), dir.path().to_path_buf());
        tx.send(AggregationCommand::RefreshRouting {
            routing: routing.clone(),
        })
        .await
        .unwrap();
        let stored = push(&tx, rid.clone(), vec![env.clone()], owner.did.clone()).await;
        assert!(matches!(stored, ArchiveAdmit::Stored { .. }), "{stored:?}");
        tx.send(AggregationCommand::Revoke {
            recording_id: rid.clone(),
        })
        .await
        .unwrap();
        flush(&tx, community).await;
        drop(tx);
        handle.await.unwrap();
    }

    {
        let (tx, handle, _r) = spawn_actor(config.clone(), dir.path().to_path_buf());
        tx.send(AggregationCommand::RefreshRouting { routing })
            .await
            .unwrap();
        let again = push(&tx, rid, vec![env], owner.did.clone()).await;
        assert!(
            matches!(again, ArchiveAdmit::Rejected),
            "revocation must survive restart (persisted revoked set): {again:?}"
        );
        drop(tx);
        handle.await.unwrap();
    }
}

#[test]
fn clamp_floors_raises_zero_custody_ttl() {
    let mut config = StrongholdConfig::default();
    config.storage.custody_ttl_secs = 0;
    let clamped = config.storage.clamp_floors();
    assert_eq!(
        config.storage.custody_ttl_secs,
        phalanx_stronghold::config::MIN_CUSTODY_TTL_SECS
    );
    assert!(clamped.contains(&"custody_ttl_secs"));
}
