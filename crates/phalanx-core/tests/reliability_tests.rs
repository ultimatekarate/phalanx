#![cfg(any())]
use std::collections::HashSet;
use std::time::Duration;
use tokio;
use tracing::info;

// Phalanx Core Traits and Orchestration
use phalanx_core::security::ingress::{
    IngressContext, IngressError, IngressOrchestrator, SecurityPipeline,
};
use phalanx_core::storage::reassembler::{Reassembler, TransientJournal};
use phalanx_core::storage::vault::{Guardian, GuardianError};

use phalanx_core::base::types::MeshTopic;
use phalanx_core::primitives::identity::{Did, NetworkId, PhalanxIdentity};
use phalanx_core::primitives::shards::{EnvelopeState, ShardChunk, ShardId};
use phalanx_core::primitives::time::TrustedClock;

use phalanx_core::security::trust::{Offense, TrustLevel, TrustRegistry};

#[tokio::test]
async fn test_reliability_swiss_cheese_recovery() {
    let mut setup = TestSetup::new().await;
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let shard_id = ShardId(101);

    // 1. Create a 3-chunk Shard, but drop Chunk #1 (the middle)
    let chunks = create_mock_chunks(&identity, shard_id, 3);
    let swiss_cheese = vec![chunks[0].clone(), chunks[2].clone()];

    // 2. Process incomplete set
    for chunk in swiss_cheese {
        let result = IngressOrchestrator::process_chunk(
            chunk,
            &setup.topic,
            &setup.ctx,
            &mut setup.pipeline,
        )
        .await
        .unwrap();
        // Should be None because the shard is fragmented
        assert!(result.is_none());
    }

    // 3. Audit Reassembler state: Should report missing index [1]
    // (This assumes the Guardian/Engine caught the Fragmented state)

    // 4. Provide the "Missing" piece (Chunk #1)
    let final_chunk = chunks[1].clone();
    let result = IngressOrchestrator::process_chunk(
        final_chunk,
        &setup.topic,
        &setup.ctx,
        &mut setup.pipeline,
    )
    .await
    .unwrap();

    // 5. SUCCESS: The hole is filled, the Crucible seals, and Guardian accepts it.
    assert!(result.is_some());
}

#[tokio::test]
async fn test_reliability_deduplication_gate() {
    // 1. Initialize the node state and security context
    let mut setup = TestSetup::new().await;
    let (identity, _) = PhalanxIdentity::generate().unwrap();

    // 2. Create a single valid ShardChunk
    let shard_id = ShardId(202);
    let chunk = ShardChunk {
        shard_id,
        chunk_index: 0,
        total_chunks: 1,
        owner_did: identity.did.clone(),
        data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        signature: identity.sign(b"chunk_payload"),
    };

    let chunk_id = (chunk.shard_id, chunk.chunk_index);
    let iterations = 50;

    // 3. BLAST the orchestrator with the same chunk repeatedly
    // This simulates a malicious actor or a very redundant P2P gossip mesh.
    for i in 0..iterations {
        let result = IngressOrchestrator::process_chunk(
            chunk.clone(),
            &setup.topic,
            &setup.ctx,
            &mut setup.pipeline,
        )
        .await;

        if i == 0 {
            // The first attempt should be processed (Ok(Some) or Ok(None) depending on assembly)
            assert!(result.is_ok(), "First chunk should be accepted");
        } else {
            // Every subsequent attempt must be dropped at the deduplication gate.
            // In our implementation, this returns Ok(None) to signify "No action taken"
            match result {
                Ok(None) => {} // Correct: Silent drop
                _ => panic!("Iteration {} failed: Chunk was not deduplicated", i),
            }
        }
    }

    // 4. VERIFY: The seen_cache must contain exactly ONE entry
    // If it contains 50, the deduplication logic is broken.
    assert_eq!(
        setup.pipeline.seen_cache.len(),
        1,
        "Deduplication cache should only store unique chunk identifiers"
    );

    // 5. VERIFY: Internal State Check
    // We check if the Reassembler's internal crucible workbench only has 1 chunk's worth of data.
    // This ensures we didn't just 'accept' it and then double-count the data inside the strategy.
    let reassembler_state = setup.pipeline.reassembler.inspect_shard(shard_id);
    assert_eq!(
        reassembler_state.received_count, 1,
        "Reassembler received_count must be idempotent"
    );

    info!(
        "Reliability: Deduplication gate successfully blocked {} redundant chunks.",
        iterations - 1
    );
}

#[tokio::test]
async fn test_reliability_journal_persistence() {
    // 1. SETUP: Initialize context and a persistent mock journal
    let mut setup = TestSetup::new().await;
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let shard_id = ShardId(303);

    // 2. PREPARE: A 4-chunk Shard
    let total_chunks = 4;
    let chunks = (0..total_chunks)
        .map(|i| ShardChunk {
            shard_id,
            chunk_index: i as u32,
            total_chunks,
            owner_did: identity.did.clone(),
            data: vec![i as u8; 10], // Mock payload
            signature: identity.sign(b"forensic_chunk"),
        })
        .collect::<Vec<_>>();

    // 3. PHASE 1: Ingest the first 2 chunks.
    // These will be written to setup.journal during reassembler.ingest_chunk()
    for i in 0..2 {
        IngressOrchestrator::process_chunk(
            chunks[i].clone(),
            &setup.topic,
            &setup.ctx,
            &mut setup.pipeline,
        )
        .await
        .expect("Initial ingestion failed");
    }

    // 4. SIMULATE CRASH:
    // We destroy the reassembler instance currently in the pipeline.
    // This wipes the Crucible's BTreeMap (RAM), but the Journal (Disk) remains.
    let mut recovered_reassembler = Reassembler::new(
        setup.ctx.config.clone(),
        setup.ctx.identity.clone(),
        setup.ctx.network_id,
    );

    // 5. RECOVERY:
    // The new reassembler scans the journal and "rehydrates" its internal Crucible.
    // It should find the 2 chunks we processed in Phase 1.
    recovered_reassembler
        .recover_from_journal(&mut setup.journal)
        .await
        .expect("Reassembler failed to recover from WAL");

    // Replace the reassembler in the active security pipeline
    setup.pipeline.reassembler = &mut recovered_reassembler;

    // 6. PHASE 2: Ingest chunk 3 (Assembly still incomplete)
    let mid_result = IngressOrchestrator::process_chunk(
        chunks[2].clone(),
        &setup.topic,
        &setup.ctx,
        &mut setup.pipeline,
    )
    .await
    .expect("Post-recovery ingestion failed");

    assert!(
        mid_result.is_none(),
        "Should be fragmented after 3 total chunks"
    );

    // 7. FINALIZATION: Ingest chunk 4
    let final_result = IngressOrchestrator::process_chunk(
        chunks[3].clone(),
        &setup.topic,
        &setup.ctx,
        &mut setup.pipeline,
    )
    .await
    .expect("Final chunk processing failed");

    // 8. VERIFICATION:
    // Success proves that the Crucible didn't just 'forget' the first 2 chunks.
    // It correctly combined the recovered WAL data with the new network data.
    assert!(
        final_result.is_some(),
        "Shard assembly should be successful after recovering partial state from Journal"
    );

    info!(?shard_id, "Reliability: Persistence recovery verified.");
}

#[tokio::test]
async fn test_reliability_timeline_integrity() {
    let mut setup = TestSetup::new().await;
    let (identity, _) = PhalanxIdentity::generate().unwrap();

    // 1. Successfully ingest Volley #1 (The Anchor)

    // 2. Attempt to ingest Volley #2 with a forged "prev_hash"
    // Even if identity.sign() is valid, the Guardian must check the chain.

    let result = IngressOrchestrator::process_chunk(hijacked_chunk, ..).await;

    // 3. EXPECT FAILURE: GuardianError::ChainIntegrityViolation
    assert!(matches!(result, Err(IngressError::GuardianRejected(_))));
}

#[tokio::test]
async fn test_reliability_timeline_integrity() {
    let mut setup = TestSetup::new().await;
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let (attacker, _) = PhalanxIdentity::generate().unwrap();

    // 1. ANCHOR: Establish the legitimate start of the timeline (Volley 0)
    let first_envelope = create_signed_envelope(&identity, 0, [0; 32]);
    let result = IngressOrchestrator::process_chunk(
        envelope_to_chunk(first_envelope),
        &setup.topic,
        &setup.ctx,
        &mut setup.pipeline,
    )
    .await;
    assert!(result.is_ok(), "Baseline anchor should be accepted");

    // 2. THE ATTACK: Attempt a "Hash Link Collision"
    // We create an envelope that has a valid signature from the correct identity,
    // BUT we intentionally point it to a bogus previous hash (ignoring the actual hash of Volley 0).
    let bogus_prev_hash = [0xFF; 32];
    let hijacked_envelope = create_signed_envelope(&identity, 1, bogus_prev_hash);

    let attack_result = IngressOrchestrator::process_chunk(
        envelope_to_chunk(hijacked_envelope),
        &setup.topic,
        &setup.ctx,
        &mut setup.pipeline,
    )
    .await;

    // 3. VERIFICATION: The Guardian must catch the chain break.
    // Even though the signature is valid, the anchor hash check fails.
    match attack_result {
        Err(IngressError::GuardianRejected(GuardianError::ChainIntegrityViolation)) => {
            info!("Reliability: Guardian successfully detected and rejected timeline hijack.");
        }
        other => panic!("Expected ChainIntegrityViolation, got {:?}", other),
    }

    // 4. REPUTATION CHECK:
    // The attacker (or in this case, the identity owner) should have an offense recorded.
    let trust = setup.pipeline.trust_registry.check_trust(&identity.did);
    assert!(matches!(
        trust,
        TrustLevel::Suspicious | TrustLevel::Blocked
    ));
}
