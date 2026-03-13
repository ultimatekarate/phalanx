#![cfg(any())]

/// Helper to bundle the complex pipeline requirements for simulation
#[ignore = "Not done."]
struct TestSetup<'a, J: TransientJournal> {
    pub ctx: IngressContext<'a>,
    pub pipeline: SecurityPipeline<'a, J>,
    pub topic: MeshTopic,
    pub journal: J,
}

use phalanx_core::primitives::identity::PhalanxIdentity;
use phalanx_core::primitives::shards::{
    Evidence, HandoverProof, RecordingId, StorageSequence, WitnessEnvelope,
};
use phalanx_core::primitives::shards::{ShardChunk, ShardId};
#[ignore = "Not done."]
fn create_mock_chunks(
    identity: &PhalanxIdentity,
    shard_id: ShardId,
    count: usize,
) -> Vec<ShardChunk> {
    (0..count)
        .map(|i| {
            let payload = format!("chunk_data_{}", i).into_bytes();
            // The signature must be valid for the Reassembler's internal checks
            let signature = identity.sign(&payload);

            ShardChunk {
                shard_id,
                chunk_index: i as u32,
                total_chunks: count as u32,
                owner_did: identity.did.clone(),
                data: payload,
                signature,
            }
        })
        .collect()
}
#[ignore = "Not done."]
fn create_signed_envelope(
    identity: &PhalanxIdentity,
    sequence: u64,
    prev_hash: [u8; 32],
) -> WitnessEnvelope {
    // We create HandoverProof as a standard form of Evidence for simulation
    let evidence = Evidence::Handover(HandoverProof {
        recording_id: RecordingId::new("sim_recording"),
        sequence_id: StorageSequence(sequence),
        old_did: identity.did.clone(),
        new_did: identity.did.clone(),
        anchor_hash: SignatureHash(prev_hash), // This is the link we test!
        old_signature: identity.sign(b"prev_link"),
        new_signature: identity.sign(b"new_link"),
    });

    WitnessEnvelope::new(
        evidence,
        identity,
        identity.to_network_id(),
        None, // No additional context needed for baseline tests
    )
    .expect("Failed to create signed envelope")
}
#[ignore = "Not done."]
fn envelope_to_chunk(envelope: WitnessEnvelope) -> ShardChunk {
    // Serialize using postcard to match the Crucible's internal deserializer
    let data = postcard::to_stdvec(&envelope).expect("Failed to serialize envelope");
    let identity_of_owner = envelope.identity.clone(); // Reusing identity for signature

    ShardChunk {
        shard_id: ShardId(999), // Generic ID for envelope-chunks
        chunk_index: 0,
        total_chunks: 1,
        owner_did: envelope.did.clone(),
        signature: identity_of_owner.sign(&data),
        data,
    }
}
