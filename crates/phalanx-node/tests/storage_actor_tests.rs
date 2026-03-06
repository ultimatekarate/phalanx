use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use phalanx_forensics::gate::WitnessGate;
use phalanx_forensics::prelude::TransientJournal;
use phalanx_forensics::reassembler::Chunkifier;
use phalanx_forensics::Reassembler;
use phalanx_node::actors::storage::{NoOpJournal, StorageActor, StorageCommand};
use phalanx_node::config::NodeConfig;
use phalanx_node::identity::PhalanxNodeIdentityExt;
use phalanx_node::persistence::journal::FileJournal;
use phalanx_node::persistence::vault::Guardian;
use phalanx_proto::evidence::{ChunkType, DataPayload, Evidence, StorageSequence, VideoShard};
use phalanx_proto::identity::{NetworkId, PhalanxIdentity, ShardId, VolleyId};
use phalanx_proto::prelude::{PendingEgress, ShardChunk, ShardError};
use phalanx_proto::retrieval::VolleyResponse;
use phalanx_proto::storage::GuardianError;
use phalanx_proto::time::PhalanxTimestamp;
use phalanx_proto::types::{ForensicUnit, Verified};
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
    let guardian = Guardian::new(&config.storage.vault_path, &config, identity.did.clone());

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
        fps: 30,
        volley_id: VolleyId::new("v1"),
        payload: DataPayload::Clear(vec![0xCA, 0xFE, 0xBA, 0xBE]),
    };

    let envelope = Evidence::Video(video_shard)
        .seal(&identity, identity.to_network_id(), None)
        .expect("Failed to seal forensic evidence");

    // 3. Setup the Guardian & Actor
    let guardian = Guardian::new(
        &temp.path().to_string_lossy(),
        &config,
        identity.did.clone(),
    );

    let (actor, storage_rx, storage_tx) =
        build_test_actor(config.clone(), identity.clone(), BrokenJournal, guardian);

    // 4. Trigger Salvage with Evidence
    let unit = ForensicUnit::<_, Verified>::new_verified(envelope).seal();

    let salvage_data = vec![PendingEgress {
        channel_id: "ch_broken_pillar".into(),
        response: VolleyResponse::Success(vec![unit]),
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
        fps: 30,
        volley_id: VolleyId::new("v1"),
        payload: DataPayload::Clear(vec![0xBA, 0xAD, 0xF0, 0x0D]),
    };

    // Seal it legitimately first
    let mut envelope = Evidence::Video(video_shard)
        .seal(&attacker_identity, attacker_net_id.clone(), None)
        .expect("Failed to seal initial envelope");

    // POISON: Flip a bit in the signature to invalidate it
    if let Some(sig_byte) = envelope.witness_signature.as_mut_slice().get_mut(0) {
        *sig_byte ^= 0xFF;
    }

    let poisoned_data = postcard::to_allocvec(&envelope).expect("Serialization failed");

    let chunk = ShardChunk {
        shard_id: ShardId(666),
        chunk_index: 0,
        total_chunks: 1,
        data: poisoned_data,
        owner_did: attacker_identity.did.clone(),
        chunk_type: ChunkType::Witnessed,
    };

    // 3. Setup Channels and Actor
    let guardian = Guardian::new(
        &temp.path().to_string_lossy(),
        &config,
        my_identity.did.clone(),
    );
    let (actor, storage_rx, storage_tx) =
        build_test_actor(config.clone(), my_identity.clone(), NoOpJournal, guardian);

    // 4. Inject Poisoned Chunk via Ingest Command
    let (reply_tx, reply_rx) = oneshot::channel();
    storage_tx
        .send(StorageCommand::Ingest {
            chunk,
            reply_to: reply_tx,
        })
        .await
        .unwrap();

    // 5. Start Actor
    let actor_handle = tokio::spawn(async move {
        actor.run(storage_rx).await;
    });

    // 6. Verification: Listen for the Forensic Escalation
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
                msg.contains("Signature verification failed"),
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
    let identity_did = identity.did.clone();

    // 1. Create a valid envelope and chunkify it into 4 pieces
    let real_shard = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(999),
        fps: 30,
        volley_id: VolleyId::new("salvage_volley_01"),
        payload: DataPayload::Clear(vec![0xDE, 0xAD, 0xBE, 0xEF]),
    };

    let envelope = Evidence::Video(real_shard)
        .seal(&identity, NetworkId::random(), None)
        .unwrap();

    let serialized_envelope = postcard::to_allocvec(&envelope).unwrap();
    let chunk_size = serialized_envelope.len().div_ceil(4);
    let chunks = serialized_envelope
        .chunkify(
            ShardId(999),
            identity_did.clone(),
            chunk_size,
            ChunkType::Witnessed,
        )
        .unwrap();
    assert_eq!(chunks.len(), 4, "Expected exactly 4 chunks");

    // 2. PHASE 1: First actor ingests 3 of 4 chunks, then "dies"
    {
        let journal = FileJournal::new(&wal_path).await.unwrap();
        let guardian = Guardian::new(&vault_path.to_string_lossy(), &config, identity.did.clone());

        let (actor, storage_rx, storage_tx) =
            build_test_actor(config.clone(), identity.clone(), journal, guardian);

        // Start actor in background
        let actor_handle = tokio::spawn(async move {
            actor.run(storage_rx).await;
        });

        // Send 3 of 4 chunks
        for chunk in chunks.iter().take(3) {
            let (tx, _) = oneshot::channel();
            storage_tx
                .send(StorageCommand::Ingest {
                    chunk: chunk.clone(),
                    reply_to: tx,
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
    // Actor is now dead. WAL should contain 3 chunks on disk.

    // 3. PHASE 2: "Reboot" — new actor recovers from WAL, receives final chunk
    {
        let journal2 = FileJournal::new(&wal_path).await.unwrap();
        let guardian2 = Guardian::new(&vault_path.to_string_lossy(), &config, identity.did.clone());

        let (actor2, storage_rx2, storage_tx2) =
            build_test_actor(config.clone(), identity.clone(), journal2, guardian2);

        let actor_handle2 = tokio::spawn(async move {
            // run() calls recover_from_journal internally during bootstrap
            actor2.run(storage_rx2).await;
        });

        // Send the 4th and final chunk
        let (tx, _) = oneshot::channel();
        storage_tx2
            .send(StorageCommand::Ingest {
                chunk: chunks[3].clone(),
                reply_to: tx,
            })
            .await
            .unwrap();

        // Give time for reassembly + Guardian flush (crucible TTL is 1s for test config)
        tokio::time::sleep(Duration::from_millis(2500)).await;

        drop(storage_tx2);
        actor_handle2.abort();
        let _ = actor_handle2.await;
    }

    // 4. VERIFICATION: Check that the volley was committed to disk
    let evidence_dir = vault_path.join(identity_did.to_safe_name());
    let mut found_file = false;
    if evidence_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&evidence_dir) {
            for entry in entries.flatten() {
                if entry.file_name().to_string_lossy().ends_with(".volley") {
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
        30,
        VolleyId::new("v1"),
    )
    .expect("Failed to create video shard");

    let envelope = Evidence::Video(video_shard)
        .seal(&peer_identity, peer_net_id.clone(), None)
        .expect("Failed to seal evidence");

    // Serialize the envelope into a single-chunk ShardChunk
    let valid_envelope_data = postcard::to_allocvec(&envelope).expect("Serialization failed");

    let chunk = ShardChunk {
        shard_id: ShardId(101),
        chunk_index: 0,
        total_chunks: 1,
        data: valid_envelope_data,
        owner_did: peer_identity.did.clone(),
        chunk_type: ChunkType::Witnessed,
    };

    // 3. Wire up a StorageActor directly (no harness needed)
    let guardian = Guardian::new(&config.storage.vault_path, &config, identity.did.clone());

    let (actor, storage_rx, storage_tx) =
        build_test_actor(config.clone(), identity.clone(), NoOpJournal, guardian);

    let actor_handle = tokio::spawn(async move {
        actor.run(storage_rx).await;
    });

    // 4. Inject the chunk via StorageCommand::Ingest
    let (tx, _) = oneshot::channel();
    storage_tx
        .send(StorageCommand::Ingest {
            chunk,
            reply_to: tx,
        })
        .await
        .expect("Injection failed");

    // 5. Wait for the Crucible TTL to flush the volley to disk
    // test_defaults uses cleanup_interval_secs=5, but the crucible has a 1s internal TTL
    tokio::time::sleep(Duration::from_millis(2200)).await;

    drop(storage_tx);
    actor_handle.abort();

    // 6. Verify the .volley file was written to disk
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
        find_file_recursive(temp_dir.path(), "v1.volley"),
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

    let guardian = Guardian::new(&config.storage.vault_path, &config, identity.did.clone());
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
        fps: 30,
        volley_id: VolleyId::new("v1"),
        payload: DataPayload::Clear(vec![0xBA, 0xAD, 0xF0, 0x0D]),
    };

    // Seal via WitnessGate
    let envelope = Evidence::Video(video_shard)
        .seal(&identity, local_peer_id.clone(), None)
        .expect("Failed to seal evidence");

    let valid_data = postcard::to_allocvec(&envelope).expect("Serialization failed");

    let chunk = ShardChunk {
        shard_id: ShardId(101),
        chunk_index: 0,
        total_chunks: 1,
        data: valid_data,
        owner_did: identity.did.clone(),
        chunk_type: ChunkType::Witnessed,
    };

    // 5. Inject via Ingest Command
    let (tx, _) = oneshot::channel();
    command_tx
        .send(StorageCommand::Ingest {
            chunk,
            reply_to: tx,
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
    let volley_id = VolleyId::new("v_test_123");

    // 1. Send the pure command
    cmd_tx
        .send(StorageCommand::Retrieval {
            volley_id,
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
        fps: 30,
        volley_id: VolleyId::new("v_pure_ingest"),
        payload: DataPayload::Clear(vec![0xDE, 0xAD, 0xBE, 0xEF]),
    };

    let envelope = Evidence::Video(video_shard)
        .seal(&identity, NetworkId::random(), None)
        .expect("Failed to seal forensic evidence");

    let valid_envelope_data = postcard::to_allocvec(&envelope).expect("Serialization failed");

    // 2. Wrap that data in a ShardChunk
    let chunk = ShardChunk {
        shard_id: ShardId(1),
        chunk_index: 0,
        total_chunks: 1,
        data: valid_envelope_data, // Use valid serialized envelope
        owner_did: identity.did.clone(),
        chunk_type: ChunkType::Witnessed,
    };

    let (reply_tx, reply_rx) = oneshot::channel();

    // 3. Send and Await
    cmd_tx
        .send(StorageCommand::Ingest {
            chunk,
            reply_to: reply_tx,
        })
        .await
        .unwrap();

    let result = reply_rx
        .await
        .expect("Vault died - check for panic in reassembler.rs");

    assert!(result.is_ok(), "Vault failed ingestion: {:?}", result.err());
}
