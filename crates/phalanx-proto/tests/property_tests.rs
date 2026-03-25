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
//! Property-based and determinism tests for phalanx-proto core types.
//!
//! The proptest dev-dep existed but was unused. These tests verify serialization
//! roundtrips, identity determinism, and causality chain integrity.

use std::sync::Arc;

use phalanx_proto::evidence::{
    DataPayload, Evidence, ForensicMetrics, ShardChunk, StorageSequence, VideoShard,
    WitnessEnvelope,
};
use phalanx_proto::identity::PhalanxIdentity;
use phalanx_proto::prelude::EncodingSymbolId;
use phalanx_proto::prelude::ShardId;
use phalanx_proto::time::{CausalitySession, PhalanxTimestamp, SystemClock, TrustedClock};
use phalanx_proto::types::Fps;

use phalanx_forensics::witness::WitnessAuthority;

// ─── Serialization Roundtrips ─────────────────────────────────────────────

fn make_test_envelope(seq: u32, recording_id: &str) -> WitnessEnvelope {
    let identity = PhalanxIdentity::new_ephemeral();
    let evidence = Evidence::Video(VideoShard {
        timestamp: SystemClock.now(),
        sequence_id: StorageSequence(seq),
        fps: Fps::new(30),
        recording_id: recording_id.into(),
        payload: DataPayload::Clear(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        lens_metrics: ForensicMetrics::default(),
    });
    WitnessEnvelope::sign_envelope(evidence, &identity, identity.network_id.clone(), None)
        .expect("signing should not fail")
}

#[test]
fn witness_envelope_postcard_roundtrip() {
    // Test with various evidence types
    for seq in 0..10u32 {
        let original = make_test_envelope(seq, &format!("roundtrip_{seq}"));
        let serialized = postcard::to_allocvec(&original).expect("serialize");
        let recovered: WitnessEnvelope = postcard::from_bytes(&serialized).expect("deserialize");

        // No PartialEq on WitnessEnvelope — compare fields manually
        assert_eq!(recovered.did, original.did);
        assert_eq!(recovered.witness_signature, original.witness_signature);
        assert_eq!(recovered.evidence_hash, original.evidence_hash);
        assert_eq!(recovered.witness_peer_id, original.witness_peer_id);
        assert_eq!(recovered.prev_hash, original.prev_hash);
    }
}

#[test]
fn shard_chunk_postcard_roundtrip() {
    for i in 0..10u32 {
        let original = ShardChunk {
            shard_id: ShardId(i as u64),
            encoding_symbol_id: EncodingSymbolId(i),
            is_terminal: i % 3 == 0,
            data: vec![i as u8; (i as usize + 1) * 100],
            owner_did: PhalanxIdentity::new_ephemeral().did,
            chunk_type: phalanx_proto::evidence::ChunkType::Witnessed,
            timestamp: PhalanxTimestamp::from_millis(1_700_000_000_000 + i as u64),
        };

        let serialized = postcard::to_allocvec(&original).expect("serialize");
        let recovered: ShardChunk = postcard::from_bytes(&serialized).expect("deserialize");

        assert_eq!(recovered.shard_id, original.shard_id);
        assert_eq!(recovered.encoding_symbol_id, original.encoding_symbol_id);
        assert_eq!(recovered.is_terminal, original.is_terminal);
        assert_eq!(recovered.data, original.data);
        assert_eq!(recovered.owner_did, original.owner_did);
        assert_eq!(recovered.timestamp, original.timestamp);
    }
}

// ─── Identity Determinism ─────────────────────────────────────────────────

#[test]
fn did_derive_deterministic() {
    // Same keypair bytes → same DID
    let identity_a = PhalanxIdentity::new_ephemeral();
    let did_a = identity_a.did.clone();

    // Re-derive from same keypair bytes
    let disk_format = phalanx_proto::identity::IdentityDiskFormat::from_identity(&identity_a);
    let identity_b = disk_format.into_identity();

    assert_eq!(
        identity_b.did, did_a,
        "Same key bytes must produce same DID"
    );

    // Different ephemeral identities should produce different DIDs
    let identity_c = PhalanxIdentity::new_ephemeral();
    assert_ne!(
        identity_c.did, did_a,
        "Different keys must produce different DIDs"
    );
}

#[test]
fn phalanx_timestamp_ordering_preserved() {
    // Ordering must be preserved through serialization
    let ts_a = PhalanxTimestamp::from_millis(1000);
    let ts_b = PhalanxTimestamp::from_millis(2000);
    assert!(ts_a < ts_b);

    let ser_a = postcard::to_allocvec(&ts_a).expect("serialize");
    let ser_b = postcard::to_allocvec(&ts_b).expect("serialize");
    let de_a: PhalanxTimestamp = postcard::from_bytes(&ser_a).expect("deserialize");
    let de_b: PhalanxTimestamp = postcard::from_bytes(&ser_b).expect("deserialize");

    assert!(de_a < de_b, "Ordering must survive serialization roundtrip");
    assert_eq!(de_a.as_u64(), 1000);
    assert_eq!(de_b.as_u64(), 2000);
}

#[test]
fn identity_did_key_prefix() {
    let identity = PhalanxIdentity::new_ephemeral();
    assert!(
        identity.did.0.starts_with("did:key:z"),
        "DID should start with 'did:key:z', got: {}",
        identity.did.0
    );
}

// ─── Causality Chain Integrity ────────────────────────────────────────────

#[test]
fn causality_session_chain_integrity() {
    let identity = PhalanxIdentity::new_ephemeral();
    let identity_arc = Arc::new(PhalanxIdentity::new_ephemeral());
    let mut session = CausalitySession::new(identity_arc, identity.network_id.clone());

    let rid = phalanx_proto::identity::RecordingId::new("causality_test");

    // Produce 3 envelopes in a chain.
    // CausalitySession tracks evidence_hash as the chain head, so prev_hash
    // on each new envelope must be SignatureHash(previous.evidence_hash).
    let mut prev_hash = None;
    for seq in 0..3u32 {
        let evidence = Evidence::Video(VideoShard {
            timestamp: SystemClock.now(),
            sequence_id: StorageSequence(seq),
            fps: Fps::new(30),
            recording_id: rid.clone(),
            payload: DataPayload::Clear(vec![seq as u8]),
            lens_metrics: ForensicMetrics::default(),
        });
        let env = WitnessEnvelope::sign_envelope(
            evidence,
            &identity,
            identity.network_id.clone(),
            prev_hash,
        )
        .expect("sign");

        // Verify the causality session accepts this envelope
        let result = session.verify_next(&env);
        assert!(
            result.is_ok(),
            "Envelope {seq} should pass causality check: {result:?}"
        );

        // Chain head advances to evidence_hash (not signature_hash)
        prev_hash = Some(phalanx_proto::evidence::SignatureHash(env.evidence_hash));
    }
}
