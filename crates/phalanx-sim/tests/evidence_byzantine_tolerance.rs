#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::float_cmp
)]
// crates/phalanx-sim/tests/evidence_byzantine_tolerance.rs
//
// Byzantine-tolerance test suite: "evidence survives compromise of k peers".
//
// Adversarial audit reading of `coordinated_kill_attempt` showed that
// "survives" was only defined as "inject_event returns Ok". This suite
// defines survival precisely (retrieved envelope passes
// `WitnessEnvelope::verify_envelope` AND carries the expected signer's
// DID) and parametrises k across four compromise modes plus a soundness
// sweep over all k from 0 to N-1.
//
// Ordering in every test is load-bearing:
//   1. Spawn N peers, no chaos.
//   2. Ad-hoc signer identity (NOT a spawned peer — spawn_node does not
//      expose its internal `PhalanxIdentity`).
//   3. `seed_authentic_recording` — fan-out chunk injection.
//   4. `await_replication` — confirm all peers have the envelope while
//      still honest.
//   5. `inject_chaos` on k peers.
//   6. `retrieve_evidence` across all N, aggregate, soundness-filter,
//      assert.
//
// Single-chunk recordings only (MTU chosen > serialized envelope size).
// Multi-chunk reassembly under Byzantine conditions is out of scope.

use phalanx_forensics::pipeline::witness::WitnessAuthority;
use phalanx_node::config::NodeConfig;
use phalanx_proto::evidence::{Evidence, VideoShard, WitnessEnvelope};
use phalanx_proto::identity::{Did, NodeRole, PhalanxIdentity, RecordingId};
use phalanx_proto::telemetry::ChaosMode;
use phalanx_proto::time::PhalanxTimestamp;
use phalanx_sim::physics::PhalanxPhysics;
use phalanx_sim::SimulationHarness;

use std::collections::HashSet;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const N_PEERS: usize = 7;
const K_COMPROMISED: usize = 3;
const SEED_SEQ: u32 = 0;
const REPLICATION_STEP: Duration = Duration::from_millis(50);
const REPLICATION_ATTEMPTS: usize = 40;

/// Real wall-clock millis, so the guardian's temporal-tolerance filter
/// in `append_shard` (rejects shards older than `current_tolerance`)
/// admits our seed. A hard-coded constant from 2023 would fail.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_millis() as u64
}

/// Spawn `n` peers and return their DIDs in spawn order.
async fn spawn_n(harness: &mut SimulationHarness, n: usize) -> Vec<Did> {
    let mut dids = Vec::with_capacity(n);
    for i in 0..n {
        let did = harness
            .spawn_node(&format!("peer-{i}"), NodeRole::Guardian)
            .await
            .expect("spawn_node succeeds");
        dids.push(did);
    }
    dids
}

/// Build an ad-hoc signer identity, sign a single-shard video envelope,
/// and fan-out `StorageCommand::WriteShard` to every peer's storage
/// via the harness `seed_envelope` helper (bypasses the ingestion
/// trust gate for seeding).
///
/// The signer is NOT a spawned peer — `spawn_node` does not expose its
/// internal identity, so the signer and the storing peers are orthogonal.
/// Returns `(envelope, recording_id, signer_did)`.
async fn seed_authentic_recording(
    harness: &mut SimulationHarness,
) -> (WitnessEnvelope, RecordingId, Did) {
    let signer = PhalanxIdentity::new_ephemeral();
    let recording_id = RecordingId::new("byz-tolerance-r0");

    let shard = VideoShard {
        timestamp: PhalanxTimestamp::from_millis(now_ms()),
        recording_id: recording_id.clone(),
        sequence_id: phalanx_proto::evidence::StorageSequence(SEED_SEQ),
        ..Default::default()
    };
    let evidence = Evidence::Video(shard);
    let envelope =
        WitnessEnvelope::sign_envelope(evidence, &signer, signer.witness_id.clone(), None)
            .expect("sign_envelope");

    // Sanity: the envelope we produce must itself pass verification,
    // otherwise the whole test harness rests on a bad primitive.
    assert!(
        envelope.verify_envelope(),
        "seed envelope fails verify_envelope — test harness invariant broken"
    );

    let accepted = harness.seed_envelope(envelope.clone()).await;
    let all_peers = harness.node_dids();
    assert_eq!(
        accepted.len(),
        all_peers.len(),
        "seed_envelope: {} of {} peers accepted the write",
        accepted.len(),
        all_peers.len()
    );

    (envelope, recording_id, signer.did.clone())
}

/// Tests' canonical soundness filter.
///
/// An envelope survives iff:
///   1. It passes `verify_envelope()` — signature matches DID, hash
///      matches evidence.
///   2. Its `did` equals the expected legitimate signer — so a
///      fresh-identity forgery that self-verifies is still rejected.
fn soundness_pass(env: &WitnessEnvelope, expected_signer: &Did) -> bool {
    env.verify_envelope() && &env.did == expected_signer
}

/// Collect envelopes from all peers, apply the soundness filter, then
/// dedupe by `evidence_hash`.
///
/// **Order is load-bearing.** Corrupted envelopes share `evidence_hash`
/// with their honest originals (CorruptStored only mangles the
/// signature). If we deduped first, a corrupted envelope arriving
/// earlier in HashMap iteration would claim the hash slot and the
/// honest copies would be silently dropped. Filter first guarantees
/// only well-formed, signer-attributed envelopes can occupy slots.
async fn retrieve_all_filtered_deduped(
    harness: &SimulationHarness,
    recording_id: &RecordingId,
    expected_signer: &Did,
) -> Vec<WitnessEnvelope> {
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut out = Vec::new();
    for did in harness.node_dids() {
        for env in harness.retrieve_evidence(&did, recording_id).await {
            if !soundness_pass(&env, expected_signer) {
                continue;
            }
            if seen.insert(env.evidence_hash) {
                out.push(env);
            }
        }
    }
    out
}

/// Collect envelopes from all peers WITHOUT dedupe — used when tests
/// need to count per-peer contributions.
async fn retrieve_all_flat(
    harness: &SimulationHarness,
    recording_id: &RecordingId,
) -> Vec<WitnessEnvelope> {
    let mut out = Vec::new();
    for did in harness.node_dids() {
        out.extend(harness.retrieve_evidence(&did, recording_id).await);
    }
    out
}

// ---------------------------------------------------------------------------
// Test 1 — k silent peers
// ---------------------------------------------------------------------------

/// Liveness: with k < N silent peers (`OmitStored`), the honest seed
/// envelope is still retrievable from at least one honest peer.
#[tokio::test]
async fn evidence_survives_k_silent_peers() {
    let (mut harness, _collector) =
        SimulationHarness::init_mesh(NodeConfig::default(), PhalanxPhysics::test_profile());

    let peer_dids = spawn_n(&mut harness, N_PEERS).await;
    let (seed_env, rid, signer_did) = seed_authentic_recording(&mut harness).await;

    // Await replication while all peers are still honest.
    let counts = harness
        .await_replication(&rid, 1, REPLICATION_ATTEMPTS, REPLICATION_STEP)
        .await;
    for did in &peer_dids {
        assert!(
            counts.get(did).copied().unwrap_or(0) >= 1,
            "peer {did} failed to replicate seed before chaos injection"
        );
    }

    // Compromise k peers.
    for did in peer_dids.iter().take(K_COMPROMISED) {
        harness.inject_chaos(did, ChaosMode::OmitStored).await;
    }

    // Retrieve, soundness-filter, dedupe.
    let surviving = retrieve_all_filtered_deduped(&harness, &rid, &signer_did).await;

    assert_eq!(
        surviving.len(),
        1,
        "exactly one deduped honest envelope should survive"
    );
    assert_eq!(surviving[0].evidence_hash, seed_env.evidence_hash);
}

// ---------------------------------------------------------------------------
// Test 2 — k corrupting peers
// ---------------------------------------------------------------------------

/// Liveness + partial soundness: with k peers returning tampered
/// envelopes, the N-k honest returns still carry the seed, and every
/// tampered envelope fails `verify_envelope()`.
#[tokio::test]
async fn evidence_survives_k_corrupting_peers() {
    let (mut harness, _collector) =
        SimulationHarness::init_mesh(NodeConfig::default(), PhalanxPhysics::test_profile());

    let peer_dids = spawn_n(&mut harness, N_PEERS).await;
    let (seed_env, rid, signer_did) = seed_authentic_recording(&mut harness).await;

    let counts = harness
        .await_replication(&rid, 1, REPLICATION_ATTEMPTS, REPLICATION_STEP)
        .await;
    for did in &peer_dids {
        assert!(counts.get(did).copied().unwrap_or(0) >= 1);
    }

    for did in peer_dids.iter().take(K_COMPROMISED) {
        harness.inject_chaos(did, ChaosMode::CorruptStored).await;
    }

    let flat = retrieve_all_flat(&harness, &rid).await;
    // Single-chunk recording: each peer returns at most 1 envelope.
    // N_PEERS returns total; K_COMPROMISED are corrupted.
    let (honest_passes, tampered_passes): (Vec<_>, Vec<_>) =
        flat.iter().partition(|e| e.verify_envelope());

    // Every honest pass must additionally match the signer DID; and the
    // honest pass count should equal N - k.
    let n_honest = N_PEERS - K_COMPROMISED;
    assert_eq!(
        honest_passes.len(),
        n_honest,
        "expected {} honest (verify-passing) envelopes, got {}",
        n_honest,
        honest_passes.len()
    );
    for e in &honest_passes {
        assert_eq!(e.did, signer_did);
        assert_eq!(e.evidence_hash, seed_env.evidence_hash);
    }

    // Every tampered return must fail `verify_envelope`.
    assert_eq!(
        tampered_passes.len(),
        K_COMPROMISED,
        "expected {} tampered envelopes, got {}",
        K_COMPROMISED,
        tampered_passes.len()
    );
}

// ---------------------------------------------------------------------------
// Test 3 — k forging peers
// ---------------------------------------------------------------------------

/// Soundness under active forgery: each forger returns two forgeries
/// (one pass-verify, one fail-verify). After the double filter the
/// only surviving envelope is the deduped honest seed.
#[tokio::test]
async fn evidence_survives_k_forging_peers() {
    let (mut harness, _collector) =
        SimulationHarness::init_mesh(NodeConfig::default(), PhalanxPhysics::test_profile());

    let peer_dids = spawn_n(&mut harness, N_PEERS).await;
    let (seed_env, rid, signer_did) = seed_authentic_recording(&mut harness).await;

    let counts = harness
        .await_replication(&rid, 1, REPLICATION_ATTEMPTS, REPLICATION_STEP)
        .await;
    for did in &peer_dids {
        assert!(counts.get(did).copied().unwrap_or(0) >= 1);
    }

    for did in peer_dids.iter().take(K_COMPROMISED) {
        harness.inject_chaos(did, ChaosMode::ForgeSigner).await;
    }

    let flat = retrieve_all_flat(&harness, &rid).await;

    // Expected composition, single-chunk regime:
    //   N - k = 4 honest envelopes (verify-pass, did matches signer)
    //   k     = 3 fresh-identity forgeries (verify-pass, did != signer)
    //   k     = 3 did/sig-mismatch forgeries (verify-fail)
    let n_honest = N_PEERS - K_COMPROMISED;

    let verify_pass: Vec<_> = flat.iter().filter(|e| e.verify_envelope()).collect();
    let verify_fail_count = flat.len() - verify_pass.len();

    assert_eq!(
        verify_fail_count, K_COMPROMISED,
        "expected {} verify-failing forgeries, got {}",
        K_COMPROMISED, verify_fail_count
    );

    let did_match: Vec<_> = verify_pass.iter().filter(|e| e.did == signer_did).collect();
    let did_mismatch_count = verify_pass.len() - did_match.len();

    assert_eq!(
        did_mismatch_count, K_COMPROMISED,
        "expected {} fresh-identity forgeries (verify-pass, did-mismatch), got {}",
        K_COMPROMISED, did_mismatch_count
    );
    assert_eq!(
        did_match.len(),
        n_honest,
        "expected {} honest envelopes surviving double-filter, got {}",
        n_honest,
        did_match.len()
    );

    // Dedupe: every honest envelope has the same evidence_hash as the seed.
    let mut hashes: HashSet<[u8; 32]> = HashSet::new();
    for e in &did_match {
        hashes.insert(e.evidence_hash);
    }
    assert_eq!(hashes.len(), 1);
    assert!(hashes.contains(&seed_env.evidence_hash));
}

// ---------------------------------------------------------------------------
// Test 4 — k colluding / mode-hopping peers
// ---------------------------------------------------------------------------

/// A mode-hopping adversary switches the same k peers between compromise
/// modes. For each mode the deduped, soundness-filtered aggregate must
/// still contain the honest seed.
#[tokio::test]
async fn evidence_survives_k_colluding_peers() {
    let (mut harness, _collector) =
        SimulationHarness::init_mesh(NodeConfig::default(), PhalanxPhysics::test_profile());

    let peer_dids = spawn_n(&mut harness, N_PEERS).await;
    let (seed_env, rid, signer_did) = seed_authentic_recording(&mut harness).await;

    let counts = harness
        .await_replication(&rid, 1, REPLICATION_ATTEMPTS, REPLICATION_STEP)
        .await;
    for did in &peer_dids {
        assert!(counts.get(did).copied().unwrap_or(0) >= 1);
    }

    let compromised: Vec<Did> = peer_dids.iter().take(K_COMPROMISED).cloned().collect();

    for mode in [
        ChaosMode::OmitStored,
        ChaosMode::CorruptStored,
        ChaosMode::ForgeSigner,
    ] {
        for did in &compromised {
            harness.inject_chaos(did, mode.clone()).await;
        }

        let surviving = retrieve_all_filtered_deduped(&harness, &rid, &signer_did).await;

        assert_eq!(
            surviving.len(),
            1,
            "mode {:?}: expected exactly one deduped surviving honest envelope",
            mode
        );
        assert_eq!(surviving[0].evidence_hash, seed_env.evidence_hash);
    }
}

// ---------------------------------------------------------------------------
// Test 5 — soundness at every k from 0 to N-1
// ---------------------------------------------------------------------------

/// Soundness invariant. For every k in 0..N, no forgery survives the
/// double filter. Strictly stronger than the liveness tests above —
/// if this fails at ANY k the system is broken.
#[tokio::test]
async fn forgery_rejected_at_all_k() {
    let (mut harness, _collector) =
        SimulationHarness::init_mesh(NodeConfig::default(), PhalanxPhysics::test_profile());

    let peer_dids = spawn_n(&mut harness, N_PEERS).await;
    let (seed_env, rid, signer_did) = seed_authentic_recording(&mut harness).await;

    let counts = harness
        .await_replication(&rid, 1, REPLICATION_ATTEMPTS, REPLICATION_STEP)
        .await;
    for did in &peer_dids {
        assert!(counts.get(did).copied().unwrap_or(0) >= 1);
    }

    for k in 0..N_PEERS {
        // Tag exactly k peers as ForgeSigner, reset the rest to Stable.
        for (i, did) in peer_dids.iter().enumerate() {
            let mode = if i < k {
                ChaosMode::ForgeSigner
            } else {
                ChaosMode::Stable
            };
            harness.inject_chaos(did, mode).await;
        }

        let flat = retrieve_all_flat(&harness, &rid).await;
        let surviving: Vec<_> = flat
            .into_iter()
            .filter(|e| soundness_pass(e, &signer_did))
            .collect();

        // Every surviving envelope must be a bit-identical copy of the seed.
        for e in &surviving {
            assert_eq!(
                e.evidence_hash, seed_env.evidence_hash,
                "k={}: surviving envelope hash differs from seed — forgery slipped through",
                k
            );
            assert_eq!(
                e.did, signer_did,
                "k={}: surviving envelope DID differs from signer — forgery slipped through",
                k
            );
        }

        // Liveness side-note: for k < N the seed should still survive at
        // least once. For k == N-1 we keep 1 honest peer so this still
        // holds; we only drop below 1 if all peers are forgers.
        if k < N_PEERS {
            assert!(
                !surviving.is_empty(),
                "k={}: every honest envelope was wrongly rejected",
                k
            );
        }
    }
}
