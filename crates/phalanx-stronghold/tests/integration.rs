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
use phalanx_proto::identity::{Did, NetworkId, PhalanxIdentity, RecordingId};
use phalanx_proto::time::PhalanxTimestamp;
use phalanx_proto::trust::TrustLevel;

use phalanx_forensics::cryptography::grant::GrantAuthority;
use phalanx_forensics::judge::{JudgeExt, PayloadCipher};
use phalanx_forensics::witness::WitnessAuthority;

use phalanx_stronghold::config::CorroborationConfig;
use phalanx_stronghold::ops::corroborate::run_corroboration;
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
    let peer_id = identity.network_id.clone();
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
    let alice_key = SymmetricKey([0x11u8; 32]);
    let bob_key = SymmetricKey([0x22u8; 32]);

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
