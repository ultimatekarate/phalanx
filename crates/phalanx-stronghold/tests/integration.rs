#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
// Integration tests for phalanx-stronghold persistence and actor layers.

use phalanx_proto::community::{
    Community, CommunityGrants, CommunityId, MemberEntry, Quorum, Vouch, VouchSignature,
};
use phalanx_proto::corroboration::{
    CorroborationProof, DeviceAttestation, EventWindow, PrnuProfile, SensorDivergence,
};
use phalanx_proto::crypto::{GrantPermissions, SealedLocator, SymmetricKey};
use phalanx_proto::evidence::{
    DataPayload, Evidence, ForensicMetrics, StorageSequence, VideoShard, WitnessEnvelope,
};
use phalanx_proto::identity::{Did, PhalanxIdentity, RecordingId, WitnessId};
use phalanx_proto::time::PhalanxTimestamp;
use phalanx_proto::trust::TrustLevel;

use phalanx_forensics::cryptography::grant::GrantAuthority;
use phalanx_forensics::judge::{JudgeExt, PayloadCipher};
use phalanx_forensics::witness::WitnessAuthority;

use phalanx_stronghold::config::CorroborationConfig;
use phalanx_stronghold::ops::corroborate::run_corroboration;
use phalanx_stronghold::ops::export::run_export;
use phalanx_stronghold::persistence::evidence_store::EvidenceStore;
use phalanx_stronghold::persistence::proof_store::ProofStore;

use phalanx_stronghold::actors::community::{CommunityActor, CommunityCommand};

use ed25519_dalek::Signer;
use tempfile::tempdir;

// ── Helpers ────────────────────────────────────────────────────────────

/// Constructs an *unsigned* WitnessEnvelope with hand-crafted hashes.
/// Not using the Phrasebook's signed envelopes because these tests exercise
/// persistence (struct serialization), not forensic workflow. The unsigned
/// construction is intentional — it isolates the storage layer from signing.
fn make_envelope(seq: u32, recording_id: &str, did_str: &str) -> WitnessEnvelope {
    WitnessEnvelope {
        evidence: Evidence::Video(VideoShard {
            timestamp: PhalanxTimestamp(1000 + seq as u64 * 33),
            sequence_id: StorageSequence(seq),
            fps: phalanx_proto::types::Fps::new(30),
            recording_id: RecordingId::new(recording_id),
            payload: DataPayload::Clear(vec![0u8; 100]),
            lens_metrics: phalanx_test_fixtures::metrics::forensic_metrics_synthetic(),
        }),
        evidence_hash: {
            let mut h = [0u8; 32];
            h[0] = seq as u8;
            h
        },
        witness_peer_id: WitnessId::new("peer1"),
        witness_signature: vec![0u8; 64],
        did: Did::new(did_str),
        prev_hash: None,
        revocation_key: phalanx_proto::revocation::RevocationKey::default(),
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

    // Both alice and bob vouch for each other (cross-vouch with quorum=1)
    let community =
        make_community_with_real_vouches(10, &[&alice, &bob], &[&alice, &bob], "Test Community");

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

// ═══════════════════════════════════════════════════════════════════════
// Test 6: End-to-end corroboration pipeline
//
// Exercises: signed+encrypted envelopes → EvidenceStore → grant-based
// decryption → Corroboration Gate → signed proof verification.
// ═══════════════════════════════════════════════════════════════════════

/// Build a signed, encrypted WitnessEnvelope for a single video frame.
fn make_signed_encrypted_envelope(
    seq: u32,
    recording_id: &RecordingId,
    identity: &PhalanxIdentity,
    recording_key: &SymmetricKey,
    base_prnu: f32,
    base_timestamp_ms: u64,
) -> WitnessEnvelope {
    // 1. Build a VideoShard with cleartext payload
    let mut shard = VideoShard {
        timestamp: PhalanxTimestamp(base_timestamp_ms + seq as u64 * 33),
        sequence_id: StorageSequence(seq),
        fps: phalanx_proto::types::Fps::new(30),
        recording_id: recording_id.clone(),
        payload: DataPayload::Clear(vec![0xCAu8; 100]),
        lens_metrics: ForensicMetrics {
            prnu_var: base_prnu + (seq as f32 * 0.1),
            h_energy: 5.0,
            v_energy: 3.0,
            mean_luminance: 128.0,
        },
    };

    // 2. Encrypt the payload BEFORE signing (phone capture flow)
    shard
        .payload
        .apply_encryption(recording_key)
        .expect("payload encryption failed");

    // 3. Sign the encrypted evidence
    let prev_hash = None;
    let peer_id = identity.witness_id.clone();
    WitnessEnvelope::sign_envelope(Evidence::Video(shard), identity, peer_id, prev_hash)
        .expect("envelope signing failed")
}

#[tokio::test]
async fn end_to_end_corroboration() {
    // ── 1. Create identities ─────────────────────────────────────────
    let alice_id = PhalanxIdentity::new_ephemeral();
    let bob_id = PhalanxIdentity::new_ephemeral();
    let stronghold_id = PhalanxIdentity::new_ephemeral();

    // ── 2. Create a community with real vouch signatures ─────────────
    let community = make_community_with_real_vouches(
        42,
        &[&alice_id, &bob_id],
        &[&alice_id, &bob_id],
        "Corroboration Test Community",
    );
    let community_id = community.fingerprint;

    // ── 3. Create signed, encrypted video envelopes ──────────────────
    let alice_key = SymmetricKey::from_bytes([0x11u8; 32]);
    let bob_key = SymmetricKey::from_bytes([0x22u8; 32]);

    let alice_rec_id = RecordingId::new("rec-alice-e2e");
    let bob_rec_id = RecordingId::new("rec-bob-e2e");

    let frame_count = 30u32;
    // Alice: prnu_var baseline 150.0, starts at 1000ms
    // Bob:   prnu_var baseline 220.0, starts at 1100ms — overlapping timestamps
    let alice_envelopes: Vec<WitnessEnvelope> = (0..frame_count)
        .map(|seq| {
            make_signed_encrypted_envelope(seq, &alice_rec_id, &alice_id, &alice_key, 150.0, 1000)
        })
        .collect();

    let bob_envelopes: Vec<WitnessEnvelope> = (0..frame_count)
        .map(|seq| make_signed_encrypted_envelope(seq, &bob_rec_id, &bob_id, &bob_key, 220.0, 1100))
        .collect();

    // Verify that payloads are actually encrypted
    match &alice_envelopes[0].evidence {
        Evidence::Video(s) => assert!(
            matches!(s.payload, DataPayload::Encrypted { .. }),
            "Alice's payload should be encrypted"
        ),
        _ => panic!("Expected Video evidence"),
    }

    // ── 4. Store envelopes in EvidenceStore ──────────────────────────
    let dir = tempdir().unwrap();
    let evidence_store = EvidenceStore::new(dir.path().to_path_buf());
    let proof_store = ProofStore::new(dir.path().join("proofs"));

    for env in &alice_envelopes {
        evidence_store
            .append_envelope(&community_id, &alice_rec_id, env)
            .await
            .unwrap();
    }
    for env in &bob_envelopes {
        evidence_store
            .append_envelope(&community_id, &bob_rec_id, env)
            .await
            .unwrap();
    }

    // Confirm both recordings are stored
    let stored = evidence_store.list_recordings(&community_id).await.unwrap();
    assert_eq!(stored.len(), 2, "Both recordings should be listed");

    // ── 5. Create grant files ────────────────────────────────────────
    //
    // Each device seals its recording key for the Stronghold.
    let alice_locator = SealedLocator::seal(
        alice_rec_id.clone(),
        alice_key.as_bytes(),
        &alice_id,
        stronghold_id.did.clone(),
        GrantPermissions {
            export: true,
            playback: false,
        },
    )
    .expect("Alice grant seal failed");

    let bob_locator = SealedLocator::seal(
        bob_rec_id.clone(),
        bob_key.as_bytes(),
        &bob_id,
        stronghold_id.did.clone(),
        GrantPermissions {
            export: true,
            playback: false,
        },
    )
    .expect("Bob grant seal failed");

    // Serialize grants with postcard and write to temp files
    let grants_dir = dir.path().join("grants");
    tokio::fs::create_dir_all(&grants_dir).await.unwrap();

    let alice_grant_path = grants_dir.join("alice.grant");
    let bob_grant_path = grants_dir.join("bob.grant");

    let alice_grant_bytes =
        postcard::to_allocvec(&alice_locator).expect("Alice grant serialization failed");
    let bob_grant_bytes =
        postcard::to_allocvec(&bob_locator).expect("Bob grant serialization failed");

    tokio::fs::write(&alice_grant_path, &alice_grant_bytes)
        .await
        .unwrap();
    tokio::fs::write(&bob_grant_path, &bob_grant_bytes)
        .await
        .unwrap();

    // ── 6. Run corroboration ─────────────────────────────────────────
    let config = CorroborationConfig {
        min_overlap_ms: 100,
        divergence_alpha: 0.05,
        c2pa_cert_path: None,
        c2pa_key_path: None,
    };

    let grant_paths = vec![alice_grant_path.clone(), bob_grant_path.clone()];
    let recording_ids = vec![alice_rec_id.clone(), bob_rec_id.clone()];

    let proof = run_corroboration(
        &stronghold_id,
        &evidence_store,
        &proof_store,
        &config,
        &community_id,
        &grant_paths,
        &recording_ids,
    )
    .await
    .expect("run_corroboration should succeed");

    // ── 7. Verify the proof ──────────────────────────────────────────

    // 7a. Attestation count: one per device
    assert_eq!(
        proof.attestations.len(),
        2,
        "Expected 2 attestations (Alice + Bob)"
    );

    // 7b. Divergence count: one pairwise comparison for 2 devices
    assert_eq!(proof.divergences.len(), 1, "Expected 1 pairwise divergence");

    // 7c. KS p-value < 0.05 (different sensors → statistically distinct PRNU)
    assert!(
        proof.divergences[0].p_value < 0.05,
        "Different sensors should produce p < 0.05, got {}",
        proof.divergences[0].p_value
    );

    // 7d. Producer DID matches the Stronghold identity
    assert_eq!(
        proof.producer_did, stronghold_id.did,
        "Proof producer should be the Stronghold"
    );

    // 7e. Verify the proof signature with Ed25519
    let stronghold_pubkey = stronghold_id.keypair.verifying_key().to_bytes();
    let sig_valid = PhalanxIdentity::verify(
        &stronghold_pubkey,
        &proof.proof_hash,
        &proof.producer_signature,
    );
    assert!(
        sig_valid,
        "Proof signature must verify against the Stronghold's public key"
    );

    // 7f. Verify proof_hash matches blake3 of the serialized proof body
    let proof_body = (
        &proof.event_window,
        &proof.attestations,
        &proof.divergences,
        &proof.proximity_evidence,
    );
    let body_bytes = postcard::to_allocvec(&proof_body).expect("proof body serialization failed");
    let expected_hash: [u8; 32] = blake3::hash(&body_bytes).into();
    assert_eq!(
        proof.proof_hash, expected_hash,
        "proof_hash should match blake3 of the serialized proof body"
    );

    // 7g. Proof should be persisted — load it back from the ProofStore
    let loaded = proof_store
        .load_proof(&community_id, &proof.proof_hash)
        .await
        .expect("Proof should be loadable from ProofStore");
    assert_eq!(loaded.proof_hash, proof.proof_hash);
    assert_eq!(loaded.attestations.len(), 2);
    assert_eq!(loaded.producer_did, stronghold_id.did);
}

// ─── Additional Integration Tests ─────────────────────────────────────────

#[tokio::test]
async fn evidence_store_persistence_across_reopen() {
    let temp = tempdir().expect("create temp dir");
    let community_id = make_community_id(0xAA);
    let rid = RecordingId::new("reopen_test");

    // Write 10 envelopes
    {
        let store = EvidenceStore::new(temp.path().to_path_buf());
        for seq in 0..10u32 {
            let env = make_envelope(seq, "reopen_test", "did:key:zReopen");
            store
                .append_envelope(&community_id, &rid, &env)
                .await
                .expect("append should succeed");
        }
    }
    // Store dropped — simulates process exit

    // Reopen from same path
    let store = EvidenceStore::new(temp.path().to_path_buf());
    let recording = store
        .read_recording(&community_id, &rid)
        .await
        .expect("read should succeed after reopen");

    assert_eq!(
        recording.artifacts.len(),
        10,
        "All 10 envelopes should survive reopen"
    );
}

#[tokio::test]
async fn proof_store_duplicate_is_idempotent() {
    let temp = tempdir().expect("create temp dir");
    let community_id = make_community_id(0xBB);
    let proof_store = ProofStore::new(temp.path().to_path_buf());

    let proof = make_corroboration_proof([0x42; 32]);

    // Write twice
    proof_store
        .store_proof(&community_id, &proof)
        .await
        .expect("first store should succeed");
    proof_store
        .store_proof(&community_id, &proof)
        .await
        .expect("second store should also succeed (idempotent)");

    // Should only have one proof on disk
    let proofs = proof_store
        .list_proofs(&community_id)
        .await
        .expect("list should succeed");
    assert_eq!(
        proofs.len(),
        1,
        "Duplicate proof should not create extra entry"
    );
}

#[tokio::test]
async fn community_concurrent_imports() {
    let temp = tempdir().expect("create temp dir");
    let _store_path = temp.path().to_path_buf();

    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(32);
    let actor = CommunityActor::new(cmd_rx);
    let handle = tokio::spawn(actor.run());

    // Import 5 communities concurrently
    let mut import_handles = Vec::new();
    for i in 0..5u32 {
        let tx = cmd_tx.clone();
        // Each community needs its own identity pair for real vouches
        let member_id = PhalanxIdentity::new_ephemeral();
        let voucher_id = PhalanxIdentity::new_ephemeral();
        let community = make_community_with_real_vouches(
            i as u8,
            &[&member_id],
            &[&voucher_id],
            &format!("concurrent_community_{i}"),
        );

        let h = tokio::spawn(async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(CommunityCommand::Import {
                community,
                reply_to: reply_tx,
            })
            .await
            .expect("send import command");
            reply_rx.await.expect("receive reply")
        });
        import_handles.push(h);
    }

    // Wait for all imports to complete
    let mut errors = 0;
    for h in import_handles {
        match h.await.expect("join handle") {
            Ok(_community_id) => {}
            Err(_) => errors += 1,
        }
    }

    drop(cmd_tx);
    let _ = handle.await;

    assert_eq!(errors, 0, "All concurrent imports should succeed");
}

// ═══════════════════════════════════════════════════════════════════════
// Test 9: End-to-end export with C2PA manifest, ingredient references,
//         and content-addressed filenames
// ═══════════════════════════════════════════════════════════════════════

fn hex_hash(hash: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in hash {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[tokio::test]
async fn export_end_to_end_c2pa() {
    // ── 1. Create identities ────────────────────────────────────────
    let alice_id = PhalanxIdentity::new_ephemeral();
    let bob_id = PhalanxIdentity::new_ephemeral();
    let stronghold_id = PhalanxIdentity::new_ephemeral();

    // ── 2. Community with real vouches ──────────────────────────────
    let community = make_community_with_real_vouches(
        50,
        &[&alice_id, &bob_id],
        &[&alice_id, &bob_id],
        "Export Test Community",
    );
    let community_id = community.fingerprint;

    // ── 3. Signed+encrypted video envelopes ─────────────────────────
    let alice_key = SymmetricKey::from_bytes([0x33u8; 32]);
    let bob_key = SymmetricKey::from_bytes([0x44u8; 32]);

    let alice_rec_id = RecordingId::new("rec-alice-export");
    let bob_rec_id = RecordingId::new("rec-bob-export");

    let frame_count = 30u32;
    let alice_envelopes: Vec<WitnessEnvelope> = (0..frame_count)
        .map(|seq| {
            make_signed_encrypted_envelope(seq, &alice_rec_id, &alice_id, &alice_key, 150.0, 1000)
        })
        .collect();

    let bob_envelopes: Vec<WitnessEnvelope> = (0..frame_count)
        .map(|seq| make_signed_encrypted_envelope(seq, &bob_rec_id, &bob_id, &bob_key, 220.0, 1100))
        .collect();

    // ── 4. Store envelopes in EvidenceStore ──────────────────────────
    let dir = tempdir().unwrap();
    let evidence_store = EvidenceStore::new(dir.path().to_path_buf());
    let proof_store = ProofStore::new(dir.path().join("proofs"));

    for env in &alice_envelopes {
        evidence_store
            .append_envelope(&community_id, &alice_rec_id, env)
            .await
            .unwrap();
    }
    for env in &bob_envelopes {
        evidence_store
            .append_envelope(&community_id, &bob_rec_id, env)
            .await
            .unwrap();
    }

    // ── 5. Create grant files ───────────────────────────────────────
    let alice_locator = SealedLocator::seal(
        alice_rec_id.clone(),
        alice_key.as_bytes(),
        &alice_id,
        stronghold_id.did.clone(),
        GrantPermissions {
            export: true,
            playback: false,
        },
    )
    .expect("Alice grant seal failed");

    let bob_locator = SealedLocator::seal(
        bob_rec_id.clone(),
        bob_key.as_bytes(),
        &bob_id,
        stronghold_id.did.clone(),
        GrantPermissions {
            export: true,
            playback: false,
        },
    )
    .expect("Bob grant seal failed");

    let grants_dir = dir.path().join("grants");
    tokio::fs::create_dir_all(&grants_dir).await.unwrap();

    let alice_grant_path = grants_dir.join("alice.grant");
    let bob_grant_path = grants_dir.join("bob.grant");

    tokio::fs::write(
        &alice_grant_path,
        postcard::to_allocvec(&alice_locator).unwrap(),
    )
    .await
    .unwrap();
    tokio::fs::write(
        &bob_grant_path,
        postcard::to_allocvec(&bob_locator).unwrap(),
    )
    .await
    .unwrap();

    // ── 6. Run corroboration to produce a proof ─────────────────────
    let config = CorroborationConfig {
        min_overlap_ms: 100,
        divergence_alpha: 0.05,
        c2pa_cert_path: None,
        c2pa_key_path: None,
    };

    let grant_paths = vec![alice_grant_path, bob_grant_path];
    let recording_ids = vec![alice_rec_id.clone(), bob_rec_id.clone()];

    let proof = run_corroboration(
        &stronghold_id,
        &evidence_store,
        &proof_store,
        &config,
        &community_id,
        &grant_paths,
        &recording_ids,
    )
    .await
    .expect("run_corroboration should succeed");

    // ── 7. Run export ───────────────────────────────────────────────
    let export_output = tempdir().unwrap();
    let written = run_export(
        &stronghold_id,
        &evidence_store,
        &proof_store,
        &config,
        &community_id,
        &proof.proof_hash,
        &grant_paths,
        export_output.path(),
    )
    .await
    .expect("export should succeed");

    // ── 8. Assertions ───────────────────────────────────────────────

    // 8a. Content-addressed subdirectory exists
    let hash_prefix = hex_hash(&proof.proof_hash)[..16].to_string();
    let export_dir = export_output.path().join(&hash_prefix);
    assert!(
        export_dir.is_dir(),
        "Content-addressed subdirectory should exist: {}",
        export_dir.display()
    );

    // 8b. Correct file count: 2 evidence + 1 proof + 1 C2PA = 4
    assert_eq!(
        written.len(),
        4,
        "Expected 4 files (2 evidence + proof + C2PA), got {}",
        written.len()
    );

    // 8c. All files are inside the content-addressed subdirectory
    for path in &written {
        assert!(
            path.starts_with(&export_dir),
            "All files should be under {}: got {}",
            export_dir.display(),
            path.display()
        );
    }

    // 8d. Evidence files exist and are non-empty
    let alice_evidence = export_dir.join("rec-alice-export.evidence.bin");
    let bob_evidence = export_dir.join("rec-bob-export.evidence.bin");
    assert!(alice_evidence.exists(), "Alice evidence file should exist");
    assert!(bob_evidence.exists(), "Bob evidence file should exist");
    assert!(
        tokio::fs::metadata(&alice_evidence).await.unwrap().len() > 0,
        "Alice evidence should be non-empty"
    );
    assert!(
        tokio::fs::metadata(&bob_evidence).await.unwrap().len() > 0,
        "Bob evidence should be non-empty"
    );

    // 8e. Proof file exists and round-trips via postcard
    let proof_path = export_dir.join("proof.bin");
    let proof_bytes = tokio::fs::read(&proof_path).await.unwrap();
    let loaded_proof: CorroborationProof =
        postcard::from_bytes(&proof_bytes).expect("proof.bin should deserialize");
    assert_eq!(loaded_proof.proof_hash, proof.proof_hash);
    assert_eq!(loaded_proof.attestations.len(), 2);

    // 8f. C2PA manifest exists and is non-empty (proves fatal-on-failure works)
    let c2pa_path = export_dir.join("proof.c2pa");
    assert!(
        c2pa_path.exists(),
        "C2PA manifest must exist (fatal on failure)"
    );
    assert!(
        tokio::fs::metadata(&c2pa_path).await.unwrap().len() > 0,
        "C2PA manifest should be non-empty"
    );

    // 8g. Re-export is idempotent (same directory, no error)
    let written2 = run_export(
        &stronghold_id,
        &evidence_store,
        &proof_store,
        &config,
        &community_id,
        &proof.proof_hash,
        &grant_paths,
        export_output.path(),
    )
    .await
    .expect("re-export should succeed (idempotent)");
    assert_eq!(
        written2.len(),
        4,
        "Re-export should produce same file count"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Test 10: Envelope roundtrip — `stronghold create-community` emits a
//          wrapped envelope; `stronghold import-community` reads it back.
//
// Phase 7.A.1 regression guard. Before the fix, the two CLI subcommands
// disagreed on envelope presence (create wrote wrapped bytes, import
// called `postcard::from_bytes` directly) so the shell pipeline failed.
// This test drives the real binary both ways and asserts the vault ends
// up with the same wrapped bytes on disk.
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn create_and_import_community_envelope_roundtrip() {
    use phalanx_forensics::identity::sign_vouch;
    use phalanx_proto::community::{CommunityId, Quorum, COMMUNITY_PAYLOAD_VERSION};
    use phalanx_proto::time::PhalanxTimestamp;
    use phalanx_proto::trust::PetName;
    use std::process::Command;

    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault");
    std::fs::create_dir_all(&vault).unwrap();

    // ── Identities: one member, two external vouchers ─────────────────
    let member = PhalanxIdentity::new_ephemeral();
    let voucher_a = PhalanxIdentity::new_ephemeral();
    let voucher_b = PhalanxIdentity::new_ephemeral();

    // ── Ceremony timestamps ────────────────────────────────────────────
    // joined_at must be within VOUCH_FRESHNESS_WINDOW_SECS (3600) of now;
    // expires_at must be in [MIN_EXPIRES_SECS (300), MAX_EXPIRES_SECS (30d)].
    let now_utc = chrono::Utc::now();
    let joined_utc = now_utc - chrono::Duration::seconds(30);
    let expires_utc = now_utc + chrono::Duration::minutes(30);
    let joined_at_rfc = joined_utc.to_rfc3339();
    let expires_at_rfc = expires_utc.to_rfc3339();
    let joined_ms = PhalanxTimestamp(u64::try_from(joined_utc.timestamp_millis()).unwrap());

    // ── Fingerprint cmd_create_community will recompute inside
    //    `assemble_community`. Vouches must sign over this exact value. ──
    let pet = PetName::new("RoundtripTest").unwrap();
    let quorum = Quorum::new(2).unwrap();
    let tentative = CommunityId::compute(&pet, quorum, std::slice::from_ref(&member.did));

    let vouch_a = sign_vouch(
        &voucher_a.keypair,
        &voucher_a.did,
        &member.did,
        &tentative,
        joined_ms,
    );
    let vouch_b = sign_vouch(
        &voucher_b.keypair,
        &voucher_b.did,
        &member.did,
        &tentative,
        joined_ms,
    );

    // ── Vouches TOML consumed by cmd_create_community ─────────────────
    let vouches_toml = format!(
        "[[members]]\n\
         did = \"{member_did}\"\n\
         \n\
         [[members.vouches]]\n\
         voucher_did = \"{voucher_a_did}\"\n\
         signature = \"{sig_a}\"\n\
         \n\
         [[members.vouches]]\n\
         voucher_did = \"{voucher_b_did}\"\n\
         signature = \"{sig_b}\"\n",
        member_did = member.did.as_str(),
        voucher_a_did = voucher_a.did.as_str(),
        sig_a = hex_hash_bytes(vouch_a.signature.as_bytes()),
        voucher_b_did = voucher_b.did.as_str(),
        sig_b = hex_hash_bytes(vouch_b.signature.as_bytes()),
    );
    let toml_path = dir.path().join("vouches.toml");
    std::fs::write(&toml_path, vouches_toml).unwrap();

    // ── Config TOML pointing the vault at our tempdir ─────────────────
    // Forward-slashes inside the TOML string avoid Windows backslash-escape
    // confusion; both OSes accept them through `tokio::fs`.
    let vault_for_toml = vault.display().to_string().replace('\\', "/");
    let config_toml = format!(
        "[storage]\n\
         vault_path = \"{vault_for_toml}\"\n\
         max_storage_bytes = 10485760\n\
         max_per_community_bytes = 1048576\n\
         \n\
         [network]\n\
         listen_addresses = [\"/ip4/0.0.0.0/tcp/0\"]\n\
         bootstrap_peers = []\n\
         \n\
         [corroboration]\n\
         min_overlap_ms = 5000\n\
         divergence_alpha = 0.05\n"
    );
    let config_path = dir.path().join("stronghold.toml");
    std::fs::write(&config_path, config_toml).unwrap();

    let bin = env!("CARGO_BIN_EXE_stronghold");
    let x_bin = dir.path().join("x.bin");

    // ── Pass 1: create-community ───────────────────────────────────────
    let create_out = Command::new(bin)
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "create-community",
            "--name",
            "RoundtripTest",
            "--quorum",
            "2",
            "--vouches",
            toml_path.to_str().unwrap(),
            "--joined-at",
            &joined_at_rfc,
            "--expires-at",
            &expires_at_rfc,
            "--output",
            x_bin.to_str().unwrap(),
        ])
        .output()
        .expect("spawn create-community");

    assert!(
        create_out.status.success(),
        "create-community failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&create_out.stdout),
        String::from_utf8_lossy(&create_out.stderr),
    );
    assert!(x_bin.exists(), "create-community did not produce x.bin");

    // The emitted file must be envelope-wrapped.
    let wrapped = std::fs::read(&x_bin).unwrap();
    assert_eq!(
        wrapped.first().copied(),
        Some(COMMUNITY_PAYLOAD_VERSION),
        "create-community output is not envelope-wrapped"
    );

    // ── Pass 2: import-community ───────────────────────────────────────
    let import_out = Command::new(bin)
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "import-community",
            "-f",
            x_bin.to_str().unwrap(),
        ])
        .output()
        .expect("spawn import-community");

    assert!(
        import_out.status.success(),
        "import-community failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&import_out.stdout),
        String::from_utf8_lossy(&import_out.stderr),
    );

    // ── Verify the vault now holds the wrapped roster ──────────────────
    let communities_dir = vault.join("communities");
    assert!(
        communities_dir.is_dir(),
        "vault/communities/ was not created"
    );
    let mut saw_community = false;
    for entry in std::fs::read_dir(&communities_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("bin") {
            continue;
        }
        let persisted = std::fs::read(&path).unwrap();
        assert_eq!(
            persisted.first().copied(),
            Some(COMMUNITY_PAYLOAD_VERSION),
            "vault file {} is not envelope-wrapped",
            path.display()
        );
        saw_community = true;
    }
    assert!(saw_community, "no .community.bin in vault after import");
}

fn hex_hash_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
