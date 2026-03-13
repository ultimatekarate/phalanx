use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use phalanx_forensics::gate::WitnessGate;
use phalanx_forensics::prelude::TransientJournal;
use phalanx_forensics::reassembler::FountainChunkifier;
use phalanx_forensics::Reassembler;
use phalanx_node::actors::storage::{NoOpJournal, StorageActor, StorageCommand};
use phalanx_node::config::NodeConfig;
use phalanx_node::identity::PhalanxNodeIdentityExt;
use phalanx_node::persistence::journal::FileJournal;
use phalanx_node::persistence::vault::{derive_vault_key, Guardian};
use phalanx_node::vitals::SystemGovernor;
use phalanx_proto::evidence::{
    ChunkType, DataPayload, Evidence, ForensicMetrics, StorageSequence, VideoShard,
};
use phalanx_proto::identity::{NetworkId, PhalanxIdentity, RecordingId, ShardId};
use phalanx_proto::prelude::{
    EncodingSymbolId, PendingEgress, RepairRatio, ShardChunk, ShardError, SymbolSize,
};
use phalanx_proto::retrieval::RecordingResponse;
use phalanx_proto::storage::GuardianError;
use phalanx_proto::time::{PhalanxTimestamp, SystemClock};
use phalanx_proto::types::{ForensicUnit, Fps, Verified};
use phalanx_transport::identity_ext::Libp2pExt;
use tokio::sync::{mpsc, oneshot};

fn build_test_actor<J: TransientJournal + Send + 'static>(
    config: NodeConfig,
    identity: PhalanxIdentity,
    journal: J,
    guardian: Guardian,
) -> (
    StorageActor<J>,
    mpsc::Receiver<StorageCommand>,
    mpsc::Sender<StorageCommand>,
) {
    let (storage_tx, storage_rx) = mpsc::channel::<StorageCommand>(10);

    let actor = StorageActor {
        reassembler: Reassembler::new(),
        guardian,
        journal,
        config: config.clone(),
        identity: identity.clone(),
        current_tolerance: Duration::from_millis(1000),
        system_governor: Arc::new(SystemGovernor::new()),
        commit_notify_tx: None,
    };

    (actor, storage_rx, storage_tx)
}

// ADDED: The missing mock storage setup helper
async fn setup_mock_storage() -> (
    StorageActor<NoOpJournal>,
    mpsc::Receiver<StorageCommand>,
    mpsc::Sender<StorageCommand>,
    tempfile::TempDir, // Returned to prevent the vault directory from dropping mid-test
) {
    let temp = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::test_defaults();
    config.storage.vault_path = temp.path().to_string_lossy().into_owned();

    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let vault_key = derive_vault_key(&identity, &[0u8; 32]);
    let guardian = Guardian::new(
        &config.storage.vault_path,
        &config,
        identity.did.clone(),
        Arc::new(SystemClock),
        vault_key,
    );

    let (actor, cmd_rx, cmd_tx) = build_test_actor(config, identity, NoOpJournal, guardian);

    (actor, cmd_rx, cmd_tx, temp)
}

#[tokio::test]
async fn test_pillar_salvage_under_disk_pressure() {
    // --- CLINICAL MOCK: THE CRUMBLING JOURNAL ---
    struct BrokenJournal;

    #[async_trait::async_trait]
    impl TransientJournal for BrokenJournal {
        async fn record_pending_egress(&mut self, _: &[PendingEgress]) -> Result<(), ShardError> {
            // Pillar 1 Failure: Simulated Disk Full / IO Error
            Err(ShardError::Io(
                "DISK FULL: Phalanx cannot salvage egress state".into(),
            ))
        }
        async fn read_all_pending_egress(&mut self) -> Result<Vec<PendingEgress>, ShardError> {
            Ok(vec![])
        }
        async fn record_chunk(&mut self, _: &ShardChunk) -> Result<(), ShardError> {
            Ok(())
        }
        async fn sync(&mut self) -> Result<(), ShardError> {
            Ok(())
        }
        async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError> {
            Ok(vec![])
        }
        async fn clear(&mut self) -> Result<(), ShardError> {
            Ok(())
        }
    }

    // 1. Setup Engine with the Broken Pillar
    let temp = tempfile::tempdir().unwrap();
    let config = NodeConfig::test_defaults();
    let (identity, _) = PhalanxIdentity::generate().unwrap();

    // 2. Prepare Real Forensic Evidence via WitnessGate
    let video_shard = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(1),
        fps: Fps::new(30),
        recording_id: RecordingId::new("v1"),
        payload: DataPayload::Clear(vec![0xCA, 0xFE, 0xBA, 0xBE]),
        lens_metrics: ForensicMetrics::default(),
    };

    let envelope = Evidence::Video(video_shard)
        .seal(&identity, identity.to_network_id(), None)
        .expect("Failed to seal forensic evidence");

    // 3. Setup the Guardian & Actor
    let vault_key = derive_vault_key(&identity, &[0u8; 32]);
    let guardian = Guardian::new(
        &temp.path().to_string_lossy(),
        &config,
        identity.did.clone(),
        Arc::new(SystemClock),
        vault_key,
    );

    let (actor, storage_rx, storage_tx) =
        build_test_actor(config.clone(), identity.clone(), BrokenJournal, guardian);

    // 4. Trigger Salvage with Evidence
    let unit = ForensicUnit::<_, Verified>::new_verified(envelope).seal();

    let salvage_data = vec![PendingEgress {
        channel_id: "ch_broken_pillar".into(),
        response: RecordingResponse::Success(vec![unit]),
        attempt_count: 0,
        next_attempt: PhalanxTimestamp::now(),
    }];

    storage_tx
        .send(StorageCommand::EmergencySalvage(salvage_data))
        .await
        .unwrap();
    drop(storage_tx); // Close the channel to signal shutdown after processing

    // 5. Verification: Ensure no deadlock
    let actor_handle = tokio::spawn(async move {
        actor.run(storage_rx).await;
    });

    let result = tokio::time::timeout(Duration::from_millis(500), actor_handle).await;

    assert!(
        result.is_ok(),
        "The StorageActor deadlocked when the Journal failed to salvage evidence!"
    );
}

#[tokio::test]
async fn test_reputation_gate_signature_mismatch() {
    // 1. Setup Environment
    let temp = tempfile::tempdir().unwrap();
    let config = NodeConfig::test_defaults();
    let (my_identity, _) = PhalanxIdentity::generate().unwrap();
    let (attacker_identity, _) = PhalanxIdentity::generate().unwrap();
    let attacker_net_id = attacker_identity.to_network_id();

    // 2. Create "Poisoned" Evidence
    let video_shard = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(1),
        fps: Fps::new(30),
        recording_id: RecordingId::new("v1"),
        payload: DataPayload::Clear(vec![0xBA, 0xAD, 0xF0, 0x0D]),
        lens_metrics: ForensicMetrics::default(),
    };

    // Seal it legitimately first
    let mut envelope = Evidence::Video(video_shard)
        .seal(&attacker_identity, attacker_net_id.clone(), None)
        .expect("Failed to seal initial envelope");

    // POISON: Flip a bit in the signature to invalidate it
    if let Some(sig_byte) = envelope.witness_signature.as_mut_slice().get_mut(0) {
        *sig_byte ^= 0xFF;
    }

    // 3. Fountain-encode the poisoned envelope into real RaptorQ symbols
    let poisoned_data = postcard::to_allocvec(&envelope).expect("Serialization failed");
    let chunks = poisoned_data
        .fountain_chunkify(
            ShardId(666),
            attacker_identity.did.clone(),
            SymbolSize(128),
            ChunkType::Witnessed,
            RepairRatio::new(1.0), // Source only — all symbols needed to trigger decode
        )
        .unwrap();

    // 4. Setup Channels and Actor
    let vault_key = derive_vault_key(&my_identity, &[0u8; 32]);
    let guardian = Guardian::new(
        &temp.path().to_string_lossy(),
        &config,
        my_identity.did.clone(),
        Arc::new(SystemClock),
        vault_key,
    );
    let (actor, storage_rx, storage_tx) =
        build_test_actor(config.clone(), my_identity.clone(), NoOpJournal, guardian);

    // 5. Start Actor
    let actor_handle = tokio::spawn(async move {
        actor.run(storage_rx).await;
    });

    // 6. Send all fountain symbols. The last one triggers decode → integrity gate
    // catches the poisoned signature. Earlier symbols return Ok(()) (still accumulating).
    for chunk in chunks.iter().take(chunks.len() - 1) {
        let (tx, _) = oneshot::channel(); // Ignore intermediate replies
        let unit = ForensicUnit::<_, Verified>::new_verified(chunk.clone());
        storage_tx
            .send(StorageCommand::Ingest {
                unit,
                reply_to: tx,
                ttl: Duration::from_secs(1),
            })
            .await
            .unwrap();
    }

    // Send the final symbol and keep its reply channel
    let (reply_tx, reply_rx) = oneshot::channel();
    let unit = ForensicUnit::<_, Verified>::new_verified(chunks.last().unwrap().clone());
    storage_tx
        .send(StorageCommand::Ingest {
            unit,
            reply_to: reply_tx,
            ttl: Duration::from_secs(1),
        })
        .await
        .unwrap();

    // 7. Verification: Listen for the Forensic Escalation
    let result = tokio::time::timeout(Duration::from_millis(500), reply_rx).await;

    // Cleanup
    drop(storage_tx);
    actor_handle.abort();

    // 7. Assertions
    let error = result
        .expect("Timeout: Actor failed to reply")
        .expect("Reply channel closed")
        .expect_err("Expected error for poisoned signature");

    // Check that the error is specifically a Cryptographic/Signature failure
    match error {
        GuardianError::VerificationFailed(ref msg) => {
            assert!(
                msg.contains("Signature")
                    || msg.contains("signature")
                    || msg.contains("verification"),
                "Unexpected verification error: {}",
                msg
            );
            println!("Gatekeepers held! Signature mismatch detected: {}", msg);
        }
        GuardianError::InvalidSignature(..) => {
            println!("Gatekeepers held! Invalid signature detected.");
        }
        _ => panic!(
            "Expected VerificationFailed/InvalidSignature, got: {:?}",
            error
        ),
    }
}

#[tokio::test]
async fn test_salvage_on_node_death() {
    let temp = tempfile::tempdir().unwrap();
    let wal_path = temp.path().join("storage.wal");
    let vault_path = temp.path().join("vault");
    std::fs::create_dir_all(&vault_path).expect("Failed to create test vault");

    let mut config = NodeConfig::test_salvage_on_node_death();
    config.storage.vault_path = vault_path.to_string_lossy().into_owned();

    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let vault_key = derive_vault_key(&identity, &[0u8; 32]);
    let identity_did = identity.did.clone();

    // 1. Create a valid envelope and chunkify it into 4 pieces
    let real_shard = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(999),
        fps: Fps::new(30),
        recording_id: RecordingId::new("salvage_recording_01"),
        payload: DataPayload::Clear(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        lens_metrics: ForensicMetrics::default(),
    };

    let envelope = Evidence::Video(real_shard)
        .seal(&identity, NetworkId::random(), None)
        .unwrap();

    let serialized_envelope = postcard::to_allocvec(&envelope).unwrap();
    // Fountain-encode with no repair symbols (RepairRatio 1.0) so we need ALL
    // source symbols. Small symbol size → multiple symbols for partial-send test.
    let chunks = serialized_envelope
        .fountain_chunkify(
            ShardId(999),
            identity_did.clone(),
            SymbolSize(128),
            ChunkType::Witnessed,
            RepairRatio::new(1.0), // Source only — every symbol is needed
        )
        .unwrap();
    let total_chunks = chunks.len();
    assert!(
        total_chunks >= 2,
        "Need at least 2 fountain symbols for salvage test"
    );

    // 2. PHASE 1: First actor ingests 3 of 4 chunks, then "dies"
    {
        let journal = FileJournal::new(&wal_path, vault_key.clone())
            .await
            .unwrap();
        let guardian = Guardian::new(
            &vault_path.to_string_lossy(),
            &config,
            identity.did.clone(),
            Arc::new(SystemClock),
            vault_key.clone(),
        );

        let (actor, storage_rx, storage_tx) =
            build_test_actor(config.clone(), identity.clone(), journal, guardian);

        // Start actor in background
        let actor_handle = tokio::spawn(async move {
            actor.run(storage_rx).await;
        });

        // Send all but the last chunk (not enough for decoder without repair)
        for chunk in chunks.iter().take(total_chunks - 1) {
            let (tx, _) = oneshot::channel();
            let unit = ForensicUnit::<_, Verified>::new_verified(chunk.clone());
            storage_tx
                .send(StorageCommand::Ingest {
                    unit,
                    reply_to: tx,
                    ttl: Duration::from_secs(1),
                })
                .await
                .unwrap();
        }

        // Give the actor time to process and write to WAL
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Simulate death: drop the sender and abort the actor
        drop(storage_tx);
        actor_handle.abort();
        let _ = actor_handle.await;
    }
    // Actor is now dead. WAL should contain N-1 fountain symbols on disk.

    // 3. PHASE 2: "Reboot" — new actor recovers from WAL, receives final chunk
    {
        let journal2 = FileJournal::new(&wal_path, vault_key.clone())
            .await
            .unwrap();
        let guardian2 = Guardian::new(
            &vault_path.to_string_lossy(),
            &config,
            identity.did.clone(),
            Arc::new(SystemClock),
            vault_key.clone(),
        );

        let (actor2, storage_rx2, storage_tx2) =
            build_test_actor(config.clone(), identity.clone(), journal2, guardian2);

        let actor_handle2 = tokio::spawn(async move {
            // run() calls recover_from_journal internally during bootstrap
            actor2.run(storage_rx2).await;
        });

        // Send the final chunk (triggers fountain decode completion)
        let (tx, _) = oneshot::channel();
        let unit = ForensicUnit::<_, Verified>::new_verified(chunks[total_chunks - 1].clone());
        storage_tx2
            .send(StorageCommand::Ingest {
                unit,
                reply_to: tx,
                ttl: Duration::from_secs(1),
            })
            .await
            .unwrap();

        // Give time for reassembly + Guardian flush (crucible TTL is 1s for test config)
        tokio::time::sleep(Duration::from_millis(2500)).await;

        drop(storage_tx2);
        actor_handle2.abort();
        let _ = actor_handle2.await;
    }

    // 4. VERIFICATION: Check that the recording was committed to disk
    let evidence_dir = vault_path.join(identity_did.to_safe_name());
    let mut found_file = false;
    if evidence_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&evidence_dir) {
            for entry in entries.flatten() {
                if entry.file_name().to_string_lossy().ends_with(".recording") {
                    found_file = true;
                    break;
                }
            }
        }
    }

    assert!(
        found_file,
        "Salvage failed: Node rebooted but failed to finish reassembly from the FileJournal WAL."
    );
}

#[tokio::test]
async fn test_stronghold_ingestion_and_persistence() {
    // 1. Setup Environment
    let temp_dir = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::test_defaults();
    config.storage.vault_path = temp_dir.path().to_string_lossy().into_owned();

    let (identity, _) = PhalanxIdentity::generate().unwrap();

    // 2. Prepare Mock Data (A legitimate chunk from an external peer)
    let (peer_identity, _) = PhalanxIdentity::generate().unwrap();
    let peer_net_id = peer_identity.to_network_id();

    let video_shard = phalanx_forensics::reassembler::create_video_shard(
        vec![vec![0xDE, 0xAD, 0xBE, 0xEF]],
        StorageSequence(1),
        Fps::new(30),
        RecordingId::new("v1"),
        ForensicMetrics::default(),
    )
    .expect("Failed to create video shard");

    let envelope = Evidence::Video(video_shard)
        .seal(&peer_identity, peer_net_id.clone(), None)
        .expect("Failed to seal evidence");

    // Fountain-encode the envelope into real RaptorQ symbols
    let valid_envelope_data = postcard::to_allocvec(&envelope).expect("Serialization failed");
    let chunks = valid_envelope_data
        .fountain_chunkify(
            ShardId(101),
            peer_identity.did.clone(),
            SymbolSize(128),
            ChunkType::Witnessed,
            RepairRatio::new(1.0),
        )
        .unwrap();

    // 3. Wire up a StorageActor directly (no harness needed)
    let vault_key = derive_vault_key(&identity, &[0u8; 32]);
    let guardian = Guardian::new(
        &config.storage.vault_path,
        &config,
        identity.did.clone(),
        Arc::new(SystemClock),
        vault_key,
    );

    let (actor, storage_rx, storage_tx) =
        build_test_actor(config.clone(), identity.clone(), NoOpJournal, guardian);

    let actor_handle = tokio::spawn(async move {
        actor.run(storage_rx).await;
    });

    // 4. Inject all fountain symbols via StorageCommand::Ingest
    for chunk in &chunks {
        let (tx, _) = oneshot::channel();
        let unit = ForensicUnit::<_, Verified>::new_verified(chunk.clone());
        storage_tx
            .send(StorageCommand::Ingest {
                unit,
                reply_to: tx,
                ttl: Duration::from_secs(1),
            })
            .await
            .expect("Injection failed");
    }

    // 5. Wait for the Crucible TTL to flush the recording to disk
    // test_defaults uses cleanup_interval_secs=5, but the crucible has a 1s internal TTL
    tokio::time::sleep(Duration::from_millis(2200)).await;

    drop(storage_tx);
    actor_handle.abort();

    // 6. Verify the .recording file was written to disk
    fn find_file_recursive(path: &std::path::Path, target: &str) -> bool {
        if path.is_file() {
            return path.file_name().map(|n| n == target).unwrap_or(false);
        }
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                if find_file_recursive(&entry.path(), target) {
                    return true;
                }
            }
        }
        false
    }

    assert!(
        find_file_recursive(temp_dir.path(), "v1.recording"),
        "Stronghold failed to create persistent shard in vault within the flush window"
    );
}

#[tokio::test]
async fn test_storage_actor_metric_pipeline() {
    // --- MetricJournal: A decorator that counts record_chunk calls ---
    struct MetricJournal<J: TransientJournal> {
        inner: J,
        counter: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl<J: TransientJournal + Send> TransientJournal for MetricJournal<J> {
        async fn record_chunk(&mut self, chunk: &ShardChunk) -> Result<(), ShardError> {
            self.inner.record_chunk(chunk).await?;
            self.counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn sync(&mut self) -> Result<(), ShardError> {
            self.inner.sync().await
        }
        async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError> {
            self.inner.read_all_chunks().await
        }
        async fn clear(&mut self) -> Result<(), ShardError> {
            self.inner.clear().await
        }
        async fn record_pending_egress(
            &mut self,
            pending: &[PendingEgress],
        ) -> Result<(), ShardError> {
            self.inner.record_pending_egress(pending).await
        }
        async fn read_all_pending_egress(&mut self) -> Result<Vec<PendingEgress>, ShardError> {
            self.inner.read_all_pending_egress().await
        }
    }

    // 1. Setup Component Dependencies
    let temp = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::default();
    config.storage.vault_path = temp.path().to_string_lossy().into_owned();

    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let local_peer_id = identity.to_network_id();

    let storage_load = Arc::new(AtomicUsize::new(0));

    // 2. MetricJournal Wrapper
    let journal = MetricJournal {
        inner: NoOpJournal,
        counter: Arc::clone(&storage_load),
    };

    let vault_key = derive_vault_key(&identity, &[0u8; 32]);
    let guardian = Guardian::new(
        &config.storage.vault_path,
        &config,
        identity.did.clone(),
        Arc::new(SystemClock),
        vault_key,
    );
    // 3. Initialize StorageActor
    let (storage_actor, command_rx, command_tx) =
        build_test_actor(config.clone(), identity.clone(), journal, guardian);

    let actor_handle = tokio::spawn(async move {
        storage_actor.run(command_rx).await;
    });

    assert_eq!(storage_load.load(Ordering::Relaxed), 0);

    // 4. Generate and Sign Test Evidence
    let video_shard = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(1),
        fps: Fps::new(30),
        recording_id: RecordingId::new("v1"),
        payload: DataPayload::Clear(vec![0xBA, 0xAD, 0xF0, 0x0D]),
        lens_metrics: ForensicMetrics::default(),
    };

    // Seal via WitnessGate
    let envelope = Evidence::Video(video_shard)
        .seal(&identity, local_peer_id.clone(), None)
        .expect("Failed to seal evidence");

    let valid_data = postcard::to_allocvec(&envelope).expect("Serialization failed");

    let timestamp = PhalanxTimestamp::now();
    let chunk = ShardChunk {
        shard_id: ShardId(101),
        encoding_symbol_id: EncodingSymbolId(0),
        chunk_type: ChunkType::Witnessed,
        is_terminal: true,
        data: valid_data,
        owner_did: identity.did.clone(),
        timestamp,
    };

    // 5. Inject via Ingest Command
    let (tx, _) = oneshot::channel();
    let unit = ForensicUnit::<_, Verified>::new_verified(chunk);
    command_tx
        .send(StorageCommand::Ingest {
            unit,
            reply_to: tx,
            ttl: Duration::from_secs(1),
        })
        .await
        .unwrap();

    // 6. Wait for reassembly and journal commit
    tokio::time::sleep(Duration::from_millis(250)).await;

    let final_load = storage_load.load(Ordering::SeqCst);

    // Cleanup
    actor_handle.abort();

    // 7. Assert metric update
    assert!(
        final_load > 0,
        "StorageActor failed to update metric via the Journal conduit. Load: {}",
        final_load
    );
}

// FIXED: Cleaned up the Pure Vault Retrieval Contract Test
#[tokio::test]
async fn test_pure_vault_retrieval_contract() {
    // Rely on the new mock helper
    let (actor, cmd_rx, cmd_tx, _temp) = setup_mock_storage().await;

    // Spawn the actor
    tokio::spawn(async move {
        actor.run(cmd_rx).await;
    });

    let (reply_tx, reply_rx) = oneshot::channel();
    let recording_id = RecordingId::new("v_test_123");

    // 1. Send the pure command
    cmd_tx
        .send(StorageCommand::Retrieval {
            recording_id,
            owner_did: None,
            reply_to: reply_tx,
        })
        .await
        .unwrap();

    // 2. Await the response
    let envelopes = reply_rx.await.expect("Vault dropped the channel");

    // 3. Verify the Vault returned raw vectors, not Network Types
    assert!(
        envelopes.is_empty(),
        "Expected empty vector from fresh vault"
    );
}

// FIXED: Cleaned up the Pure Vault Ingest Contract Test
#[tokio::test]
async fn test_pure_vault_ingest_contract() {
    let (actor, cmd_rx, cmd_tx, _temp) = setup_mock_storage().await;

    tokio::spawn(async move {
        actor.run(cmd_rx).await;
    });

    // 1. Prepare REAL evidence so the reassembler doesn't choke on raw [0x00]
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let video_shard = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(1),
        fps: Fps::new(30),
        recording_id: RecordingId::new("v_pure_ingest"),
        payload: DataPayload::Clear(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        lens_metrics: ForensicMetrics::default(),
    };

    let envelope = Evidence::Video(video_shard)
        .seal(&identity, NetworkId::random(), None)
        .expect("Failed to seal forensic evidence");

    let valid_envelope_data = postcard::to_allocvec(&envelope).expect("Serialization failed");

    // 2. Wrap that data in a ShardChunk
    let timestamp = PhalanxTimestamp::now();
    let chunk = ShardChunk {
        shard_id: ShardId(1),
        encoding_symbol_id: EncodingSymbolId(0),
        chunk_type: ChunkType::Witnessed,
        is_terminal: true,
        data: valid_envelope_data, // Use valid serialized envelope
        owner_did: identity.did.clone(),
        timestamp,
    };

    let (reply_tx, reply_rx) = oneshot::channel();
    let unit = ForensicUnit::<_, Verified>::new_verified(chunk);

    // 3. Send and Await
    cmd_tx
        .send(StorageCommand::Ingest {
            unit,
            reply_to: reply_tx,
            ttl: Duration::from_secs(1),
        })
        .await
        .unwrap();

    let result = reply_rx
        .await
        .expect("Vault died - check for panic in reassembler.rs");

    assert!(result.is_ok(), "Vault failed ingestion: {:?}", result.err());
}

#[cfg(test)]
mod ingress_boundary_tests {
    use super::*;
    use phalanx_forensics::witness::WitnessAuthority;
    use phalanx_proto::evidence::{
        DataPayload, Evidence, StorageSequence, VideoShard, WitnessEnvelope,
    };
    use phalanx_proto::identity::{NetworkId, PhalanxIdentity, RecordingId, ShardId};
    use phalanx_proto::prelude::ShardChunk;
    use phalanx_proto::time::PhalanxTimestamp;
    use phalanx_proto::types::{ForensicUnit, Unverified, Verified};
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn test_vault_rejects_unverified_ingress_by_design() {
        let (actor, cmd_rx, cmd_tx, _temp) = setup_mock_storage().await;

        tokio::spawn(async move {
            actor.run(cmd_rx).await;
        });

        // 1. Create a valid Forensic Payload
        let (identity, _) = PhalanxIdentity::generate().unwrap();
        let video_shard = VideoShard {
            timestamp: PhalanxTimestamp::now(),
            sequence_id: StorageSequence(1),
            fps: Fps::new(30),
            recording_id: RecordingId::new("v_secure_ingress"),
            payload: DataPayload::Clear(vec![0xAA, 0xBB, 0xCC]),
            lens_metrics: ForensicMetrics::default(),
        };

        let envelope = WitnessEnvelope::sign_envelope(
            Evidence::Video(video_shard),
            &identity,
            NetworkId::random(),
            None,
        )
        .expect("Failed to seal evidence");

        let valid_data = postcard::to_allocvec(&envelope).expect("Serialization failed");

        // 2. The Raw Data off the wire
        let timestamp = PhalanxTimestamp::now();
        let raw_chunk = ShardChunk {
            shard_id: ShardId(1),
            encoding_symbol_id: EncodingSymbolId(0),
            chunk_type: ChunkType::Witnessed,
            is_terminal: true,
            data: valid_data,
            owner_did: identity.did.clone(),
            timestamp,
        };

        // 3. SENTINEL BOUNDARY: Wrap as Unverified
        let unverified_unit = ForensicUnit::<_, Unverified>::new(raw_chunk);

        // --- COMPILER ENFORCEMENT ZONE ---
        // If you uncomment the following line, the test WILL NOT COMPILE:
        // let BAD_COMMAND = StorageCommand::Ingest { unit: unverified_unit.clone(), reply_to: ... };
        // ---------------------------------

        // 4. THE PROMOTION: Simulate passing the Reputation & Quota gates
        let verified_unit = ForensicUnit::<_, Verified>::new_verified(unverified_unit.unpack());

        // 5. THE VAULT: Now it mathematically accepts the command
        let (reply_tx, reply_rx) = oneshot::channel();
        cmd_tx
            .send(StorageCommand::Ingest {
                unit: verified_unit,
                reply_to: reply_tx,
                ttl: Duration::from_secs(1),
            })
            .await
            .expect("Failed to send verified chunk to Vault");

        // 6. VERIFICATION
        let result = reply_rx.await.expect("Vault died during secure ingest");
        assert!(
            result.is_ok(),
            "Vault rejected a cryptographically valid, typestate-verified chunk"
        );
    }
}
