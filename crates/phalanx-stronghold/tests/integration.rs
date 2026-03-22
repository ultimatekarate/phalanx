// Integration tests for phalanx-stronghold persistence and actor layers.

use phalanx_proto::community::{
    Community, CommunityGrants, CommunityId, MemberEntry, Quorum, Vouch, VouchSignature,
};
use phalanx_proto::corroboration::{
    CorroborationProof, DeviceAttestation, EventWindow, PrnuProfile, SensorDivergence,
};
use phalanx_proto::evidence::{
    DataPayload, Evidence, ForensicMetrics, StorageSequence, VideoShard, WitnessEnvelope,
};
use phalanx_proto::identity::{Did, NetworkId, PhalanxIdentity, RecordingId};
use phalanx_proto::time::PhalanxTimestamp;
use phalanx_proto::trust::TrustLevel;

use phalanx_stronghold::persistence::evidence_store::EvidenceStore;
use phalanx_stronghold::persistence::proof_store::ProofStore;

use phalanx_stronghold::actors::community::{CommunityActor, CommunityCommand};

use ed25519_dalek::Signer;
use tempfile::tempdir;

// ── Helpers ────────────────────────────────────────────────────────────

fn make_envelope(seq: u32, recording_id: &str, did_str: &str) -> WitnessEnvelope {
    WitnessEnvelope {
        evidence: Evidence::Video(VideoShard {
            timestamp: PhalanxTimestamp(1000 + seq as u64 * 33),
            sequence_id: StorageSequence(seq),
            fps: phalanx_proto::types::Fps::new(30),
            recording_id: RecordingId::new(recording_id),
            payload: DataPayload::Clear(vec![0u8; 100]),
            lens_metrics: ForensicMetrics {
                prnu_var: 150.0,
                h_energy: 5.0,
                v_energy: 3.0,
                mean_luminance: 128.0,
            },
        }),
        evidence_hash: {
            let mut h = [0u8; 32];
            h[0] = seq as u8;
            h
        },
        witness_peer_id: NetworkId("peer1".to_string()),
        witness_signature: vec![0u8; 64],
        did: Did::new(did_str),
        prev_hash: None,
    }
}

fn make_community_id(seed: u8) -> CommunityId {
    CommunityId([seed; 32])
}

/// Build a Community with real Ed25519 vouches so CommunityActor::import
/// passes signature verification.
fn make_community_with_real_vouches(
    community_id_seed: u8,
    member_identities: &[&PhalanxIdentity],
    voucher_identities: &[&PhalanxIdentity],
    name: &str,
) -> Community {
    let community_id = make_community_id(community_id_seed);
    let quorum = Quorum::new(1).unwrap();
    let joined_at = PhalanxTimestamp(1000);

    let members: Vec<MemberEntry> = member_identities
        .iter()
        .map(|member| {
            let vouches: Vec<Vouch> = voucher_identities
                .iter()
                .map(|voucher| {
                    // Build message: member_did || community_fingerprint || joined_at
                    let mut msg = Vec::new();
                    msg.extend_from_slice(member.did.as_ref().as_bytes());
                    msg.extend_from_slice(&community_id.0);
                    msg.extend_from_slice(&joined_at.0.to_le_bytes());

                    let sig = voucher.keypair.sign(&msg);

                    Vouch {
                        voucher_did: voucher.did.clone(),
                        signature: VouchSignature::new(sig.to_bytes()),
                    }
                })
                .collect();

            MemberEntry::new_validated(member.did.clone(), joined_at, vouches, quorum).unwrap()
        })
        .collect();

    Community {
        fingerprint: community_id,
        name: phalanx_proto::trust::PetName::new(name).unwrap(),
        quorum,
        members,
        stronghold_did: None,
        baseline_trust: TrustLevel::Verified,
        grants: CommunityGrants::default(),
        expires_at: PhalanxTimestamp(u64::MAX), // far future
    }
}

fn make_corroboration_proof(proof_hash: [u8; 32]) -> CorroborationProof {
    CorroborationProof {
        event_window: EventWindow {
            start: PhalanxTimestamp(1000),
            end: PhalanxTimestamp(5000),
            overlap_start: PhalanxTimestamp(2000),
            overlap_end: PhalanxTimestamp(4000),
        },
        attestations: vec![DeviceAttestation {
            did: Did::new("did:key:zdevice1"),
            recording_id: RecordingId::new("rec-1"),
            frame_count: 30,
            prnu_profile: PrnuProfile {
                mean_prnu_var: 150.0,
                std_prnu_var: 5.0,
                mean_h_energy: 5.0,
                mean_v_energy: 3.0,
                sample_count: 30,
            },
            chain_head: [1u8; 32],
            chain_tail: [2u8; 32],
        }],
        divergences: vec![SensorDivergence {
            device_a: Did::new("did:key:zdevice1"),
            device_b: Did::new("did:key:zdevice2"),
            ks_statistic: 0.95,
            p_value: 0.001,
        }],
        proximity_evidence: vec![],
        producer_did: Did::new("did:key:zstronghold"),
        producer_signature: vec![0u8; 64],
        proof_hash,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Test 1: EvidenceStore round-trip persistence
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn evidence_store_round_trip() {
    let dir = tempdir().unwrap();
    let store = EvidenceStore::new(dir.path().to_path_buf());

    let community_id = make_community_id(1);
    let recording_id = RecordingId::new("test-rec-roundtrip");

    // Append 5 envelopes
    for seq in 0..5u32 {
        let env = make_envelope(seq, "test-rec-roundtrip", "did:key:zalice");
        store
            .append_envelope(&community_id, &recording_id, &env)
            .await
            .unwrap();
    }

    // Read back the recording
    let recording = store
        .read_recording(&community_id, &recording_id)
        .await
        .unwrap();
    assert_eq!(
        recording.artifacts.len(),
        5,
        "Expected 5 artifacts, got {}",
        recording.artifacts.len()
    );
    assert!(
        recording.is_complete,
        "Recording should be complete with no gaps"
    );
    assert!(
        recording.gaps.is_empty(),
        "Expected no gaps in sequential recording"
    );

    // list_recordings should contain our recording
    let recordings = store.list_recordings(&community_id).await.unwrap();
    assert!(
        recordings
            .iter()
            .any(|r| r.as_str() == "test-rec-roundtrip"),
        "list_recordings should contain the recording ID, got: {:?}",
        recordings
    );

    // community_bytes should be > 0
    let bytes = store.community_bytes(&community_id).await.unwrap();
    assert!(
        bytes > 0,
        "community_bytes should be positive after storing evidence"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Test 2: EvidenceStore gap detection
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn evidence_store_gap_detection() {
    let dir = tempdir().unwrap();
    let store = EvidenceStore::new(dir.path().to_path_buf());

    let community_id = make_community_id(2);
    let recording_id = RecordingId::new("test-rec-gap");

    // Append sequences 0, 1, 3 (skip 2)
    for seq in [0u32, 1, 3] {
        let env = make_envelope(seq, "test-rec-gap", "did:key:zbob");
        store
            .append_envelope(&community_id, &recording_id, &env)
            .await
            .unwrap();
    }

    let recording = store
        .read_recording(&community_id, &recording_id)
        .await
        .unwrap();

    assert!(
        !recording.gaps.is_empty(),
        "Gaps should be detected when sequence 2 is missing"
    );
    assert!(
        !recording.is_complete,
        "Recording with gaps should not be marked complete"
    );
    assert_eq!(
        recording.artifacts.len(),
        3,
        "Should still have the 3 stored shards"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Test 3: ProofStore round-trip
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn proof_store_round_trip() {
    let dir = tempdir().unwrap();
    let store = ProofStore::new(dir.path().to_path_buf());

    let community_id = make_community_id(3);
    let proof_hash = [42u8; 32];
    let proof = make_corroboration_proof(proof_hash);

    store.store_proof(&community_id, &proof).await.unwrap();

    let loaded = store.load_proof(&community_id, &proof_hash).await.unwrap();

    assert_eq!(loaded.proof_hash, proof_hash);
    assert_eq!(loaded.attestations.len(), 1);
    assert_eq!(loaded.divergences.len(), 1);
    assert_eq!(loaded.producer_did, Did::new("did:key:zstronghold"));
    assert_eq!(loaded.event_window.start.0, 1000);
    assert_eq!(loaded.event_window.end.0, 5000);

    // list_proofs should contain our proof hash
    let hashes = store.list_proofs(&community_id).await.unwrap();
    assert!(
        hashes.contains(&proof_hash),
        "list_proofs should contain the stored proof hash"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Test 4: CommunityActor import and lookup
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn community_actor_import_and_lookup() {
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let actor = CommunityActor::new(rx);
    tokio::spawn(actor.run());

    // Create identities with real keys so vouch verification passes
    let alice = PhalanxIdentity::new_ephemeral();
    let bob = PhalanxIdentity::new_ephemeral();

    // Alice vouches for Bob, Bob vouches for Alice (cross-vouch with quorum=1)
    let community =
        make_community_with_real_vouches(10, &[&alice, &bob], &[&alice], "Test Community");

    // Import
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(CommunityCommand::Import {
        community,
        reply_to: reply_tx,
    })
    .await
    .unwrap();
    let result = reply_rx.await.unwrap();
    let imported_id = result.expect("Import should succeed");
    assert_eq!(imported_id, make_community_id(10));

    // Lookup alice — should find the community
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(CommunityCommand::LookupMember {
        did: alice.did.clone(),
        reply_to: reply_tx,
    })
    .await
    .unwrap();
    let communities = reply_rx.await.unwrap();
    assert!(
        communities.contains(&imported_id),
        "Alice should be found in the imported community"
    );

    // Lookup unknown DID — should return empty
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(CommunityCommand::LookupMember {
        did: Did::new("did:key:zunknown"),
        reply_to: reply_tx,
    })
    .await
    .unwrap();
    let communities = reply_rx.await.unwrap();
    assert!(
        communities.is_empty(),
        "Unknown DID should not be in any community"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Test 5: Community isolation — recordings are scoped per community
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn community_isolation() {
    let dir = tempdir().unwrap();
    let store = EvidenceStore::new(dir.path().to_path_buf());

    let community_a = make_community_id(100);
    let community_b = make_community_id(200);

    let rec_a = RecordingId::new("rec-community-a");
    let rec_b = RecordingId::new("rec-community-b");

    // Store envelopes under community A
    for seq in 0..3u32 {
        let env = make_envelope(seq, "rec-community-a", "did:key:zalice");
        store
            .append_envelope(&community_a, &rec_a, &env)
            .await
            .unwrap();
    }

    // Store envelopes under community B
    for seq in 0..2u32 {
        let env = make_envelope(seq, "rec-community-b", "did:key:zbob");
        store
            .append_envelope(&community_b, &rec_b, &env)
            .await
            .unwrap();
    }

    // list_recordings for A should NOT contain B's recording
    let list_a = store.list_recordings(&community_a).await.unwrap();
    let list_b = store.list_recordings(&community_b).await.unwrap();

    assert!(
        list_a.iter().any(|r| r.as_str() == "rec-community-a"),
        "Community A should contain rec-community-a"
    );
    assert!(
        !list_a.iter().any(|r| r.as_str() == "rec-community-b"),
        "Community A should NOT contain rec-community-b"
    );

    assert!(
        list_b.iter().any(|r| r.as_str() == "rec-community-b"),
        "Community B should contain rec-community-b"
    );
    assert!(
        !list_b.iter().any(|r| r.as_str() == "rec-community-a"),
        "Community B should NOT contain rec-community-a"
    );

    // Verify artifact counts are independent
    let recording_a = store.read_recording(&community_a, &rec_a).await.unwrap();
    let recording_b = store.read_recording(&community_b, &rec_b).await.unwrap();
    assert_eq!(recording_a.artifacts.len(), 3);
    assert_eq!(recording_b.artifacts.len(), 2);
}
