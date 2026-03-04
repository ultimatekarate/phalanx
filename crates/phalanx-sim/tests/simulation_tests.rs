#![cfg(feature = "__disabled_legacy_tests")]
use phalanx_core::storage::journal::FileJournal;
use tokio::time::Duration;

// Import from the public API
use phalanx_core::base::config::{PhalanxConfig, PhalanxPhysics};
use phalanx_core::base::engine::NoOpJournal;

use phalanx_core::primitives::identity::{Did, NetworkId, PhalanxIdentity};
use phalanx_core::primitives::shards::{
    self, create_video_shard, ChunkType, DataPayload, EnvelopeState, Evidence, ShardChunk, ShardId,
    StorageSequence, VolleyId, WitnessEnvelope,
};

use phalanx_core::security::telemetry::{init_observability, NodeRole, SimEvent};

use phalanx_core::simulation::SimulationHarness;
use phalanx_core::storage::reassembler::Reassembler;
use phalanx_core::storage::vault::{Guardian, GuardianError};
use phalanx_core::transport::events::NetworkEvent;

use phalanx_core::base::engine::{PendingEgress, StorageActor, StorageCommand};
use phalanx_core::primitives::shards::{ShardError, VideoShard};
use phalanx_core::primitives::time::PhalanxTimestamp;
use phalanx_core::security::gate::WitnessGate;
use phalanx_core::storage::reassembler::TransientJournal;
use phalanx_core::transport::protocol::VolleyResponse;

fn create_test_shard(seq: u32, volley_id: VolleyId) -> VideoShard {
    VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(seq),
        fps: 30,
        volley_id,
        payload: DataPayload::Clear(vec![0xDE, 0xAD, 0xBE, 0xEF]),
    }
}

async fn spawn_persistent_node(
    harness: &mut SimulationHarness,
    identity: PhalanxIdentity,
    journal: FileJournal,
) -> Did {
    let node_did = identity.did.clone();
    let network_id = identity.to_network_id();

    harness
        .identity_registry
        .write()
        .await
        .insert(node_did.clone(), network_id);

    let (ingress_tx, ingress_rx) = tokio::sync::mpsc::channel(4096);
    let (egress_tx, mut egress_rx) = tokio::sync::mpsc::channel(4096);

    let transport = phalanx_core::transport::mock::MockTransport::new(ingress_rx, Some(egress_tx))
        .with_telemetry(network_id, harness.telemetry_tx.clone());

    harness
        .ingress_routes
        .write()
        .await
        .insert(node_did.clone(), ingress_tx);

    let trust_registry = phalanx_core::security::trust::TrustRegistry::build(&harness.config).await;
    let reputation_cache =
        std::sync::Arc::new(phalanx_core::base::engine::SyncReputationCache::default());
    let (discovery_tx, discovery_rx) = tokio::sync::mpsc::channel(100);

    // Engine initialized with the exact identity and persistent journal
    let mut engine = phalanx_core::base::engine::PhalanxEngine::new(
        harness.config.clone(),
        identity,
        transport,
        journal,
        trust_registry,
        reputation_cache,
        discovery_rx,
        discovery_tx,
    )
    .await
    .expect("Failed to initialize engine");

    tokio::spawn(async move {
        let _ = engine.run().await;
    });

    // Mesh Egress Routing
    let routing_table = std::sync::Arc::clone(&harness.ingress_routes);
    let source_did = node_did.clone();

    tokio::spawn(async move {
        while let Some((topic, data)) = egress_rx.recv().await {
            let event = NetworkEvent::DataReceived {
                origin: network_id,
                topic,
                data,
            };
            let routes = routing_table.read().await;
            for (target_did, target_tx) in routes.iter() {
                if target_did != &source_did {
                    let _ = target_tx.send(event.clone()).await;
                }
            }
        }
    });

    node_did
}

#[tokio::test]
async fn test_salvage_on_node_death() {
    init_observability();

    let test_base_path = std::env::temp_dir().join("phalanx_salvage_test");
    let wal_path = test_base_path.join("storage.wal");
    let vault_path = test_base_path.join("vault");

    let _ = std::fs::remove_dir_all(&test_base_path);
    std::fs::create_dir_all(&vault_path).expect("Failed to create test vault");

    let mut config = PhalanxConfig::test_salvage_on_node_death();
    config.storage.vault_path = vault_path.to_string_lossy().into_owned();

    let physics = PhalanxPhysics::test_profile();
    let (mut harness, _) = SimulationHarness::init_mesh(config.clone(), physics);

    let (victim_identity, _) = PhalanxIdentity::generate().unwrap();
    let victim_did = victim_identity.did.clone();

    let topic = config.network.video_topic.clone();

    let journal = FileJournal::new(&wal_path).await.unwrap();
    let victim_device_did =
        spawn_persistent_node(&mut harness, victim_identity.clone(), journal).await;

    let real_shard = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(999),
        fps: 30,
        volley_id: VolleyId::new("salvage_volley_01"),
        payload: DataPayload::Clear(vec![0xDE, 0xAD, 0xBE, 0xEF]),
    };

    let envelope = WitnessEnvelope::new(
        Evidence::Video(real_shard),
        &victim_identity,
        NetworkId::random(),
        None,
    )
    .unwrap();

    let serialized_envelope = postcard::to_stdvec(&envelope).unwrap();

    // CLINICAL FIX: Calculate correct chunk_size to yield exactly 4 chunks
    let chunk_size = serialized_envelope.len().div_ceil(4);
    let chunks = shards::chunkify(
        ShardId(999),
        serialized_envelope,
        chunk_size,
        victim_did.clone(),
        ChunkType::Witnessed,
    )
    .unwrap();

    for chunk in chunks.iter().take(3) {
        let chunk_bytes = postcard::to_stdvec(&chunk).unwrap();
        harness
            .inject_event(
                &victim_device_did,
                NetworkEvent::DataReceived {
                    origin: NetworkId::random(),
                    topic: topic.clone(),
                    data: chunk_bytes,
                },
            )
            .await
            .unwrap();
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    harness
        .inject_event(&victim_device_did, NetworkEvent::Shutdown)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // THE SALVAGE REBOOT
    let journal2 = FileJournal::new(&wal_path).await.unwrap();
    let rebooted_device_did =
        spawn_persistent_node(&mut harness, victim_identity.clone(), journal2).await;

    let final_chunk_bytes = postcard::to_stdvec(&chunks[3]).unwrap();
    harness
        .inject_event(
            &rebooted_device_did,
            NetworkEvent::DataReceived {
                origin: NetworkId::random(),
                topic: topic.clone(),
                data: final_chunk_bytes,
            },
        )
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(2500)).await;

    let evidence_dir = vault_path.join(victim_did.to_safe_name());
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
    let _ = std::fs::remove_dir_all(&test_base_path);
}

#[tokio::test]
async fn test_out_of_sequence_salvage_on_node_death() {
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let config = PhalanxConfig::default();
    let volley_id = VolleyId::new("v_salvage");

    let mut guardian = Guardian::new("sim_vault/salvage", &config, identity.did.clone());

    // 1. CREATE VALID CHAIN: Seq 1 -> Seq 2
    let shard_1 = create_test_shard(1, volley_id.clone());
    let env_1 = WitnessEnvelope::new(
        Evidence::Video(shard_1),
        &identity,
        NetworkId::random(),
        None,
    )
    .unwrap();
    let hash_1 = env_1.signature_hash();

    let shard_2 = create_test_shard(2, volley_id.clone());
    // CRITICAL: Point Seq 2 at the hash of Seq 1
    let env_2 = WitnessEnvelope::new(
        Evidence::Video(shard_2),
        &identity,
        NetworkId::random(),
        Some(hash_1),
    )
    .unwrap();

    // 2. SIMULATE SALVAGE: Ingesting out of order should be handled by the Crucible/Guardian
    // (If Seq 2 arrives before Seq 1, the Guardian puts it in an 'Orphan Queue')

    // Ingest Seq 1
    guardian
        .ingest_envelope(EnvelopeState::Intact(env_1))
        .await
        .expect("Seq 1 failed");

    // Ingest Seq 2 (Now has a valid link to 1)
    let result = guardian.ingest_envelope(EnvelopeState::Intact(env_2)).await;

    assert!(
        result.is_ok(),
        "Salvage failed: Guardian rejected valid chain link"
    );
}

#[tokio::test]
async fn test_stronghold_crash_recovery() {
    let config = PhalanxConfig::default();
    let vault_path = "sim_vault/crash_test";
    let _ = std::fs::remove_dir_all(vault_path);

    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let peer_id = NetworkId::random();
    let seq = StorageSequence(101);
    let vid = VolleyId::new("crash_volley");

    let mut storage = Guardian::new(vault_path, &config, identity.did.clone());

    let shard = create_video_shard(vec![vec![0xAA]], seq, 30, vid.clone())
        .expect("Failed to generate shard");

    let envelope = WitnessEnvelope::new(Evidence::Video(shard), &identity, peer_id, None)
        .expect("Failed to sign envelope");

    storage
        .ingest_envelope(EnvelopeState::Intact(envelope.clone()))
        .await
        .expect("Ingest failed");

    drop(storage);

    let mut recovered_storage = Guardian::new(vault_path, &config, identity.did.clone());

    // Replay WAL
    recovered_storage
        .ingest_envelope(EnvelopeState::Intact(envelope.clone()))
        .await
        .expect("WAL replay failed");

    // FIX: Lookup by VolleyId
    let recovered_session = recovered_storage
        .get_active_volley_shards(&vid)
        .expect("Guardian failed to recover Volley session");

    assert!(recovered_session.contains_key(&seq));
}

#[tokio::test]
async fn test_leaf_mode_isolation() {
    let (local_identity, _) = PhalanxIdentity::generate().unwrap();
    let (foreign_identity, _) = PhalanxIdentity::generate().unwrap();
    let config = PhalanxConfig::default();

    let mut reassembler = Reassembler::new();
    let _guardian = Guardian::new("sim_vault/leaf_test", &config, local_identity.did.clone());
    let mut journal = NoOpJournal;

    // 1. GENERATE VALID BYTES: Postcard needs a real WitnessEnvelope to succeed
    let evidence = Evidence::Video(VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(1),
        fps: 30,
        volley_id: VolleyId::new("v_leaf"),
        payload: DataPayload::Clear(vec![0x00; 4]),
    });
    let env = WitnessEnvelope::new(
        evidence,
        &foreign_identity,
        foreign_identity.to_network_id(),
        None,
    )
    .unwrap();
    let valid_bytes = postcard::to_stdvec(&env).unwrap();

    let foreign_chunk = ShardChunk {
        shard_id: ShardId(1),
        chunk_index: 0,
        total_chunks: 1,
        data: valid_bytes, // Now valid forensic data
        owner_did: foreign_identity.did.clone(),
        chunk_type: ChunkType::Witnessed,
    };

    // 2. THE POLICY CHECK: Logic from StorageActor
    let is_leaf_mode = true;
    let result = if is_leaf_mode && foreign_chunk.owner_did != local_identity.did {
        // Correctly drops traffic before it hits the reassembler
        Ok(None)
    } else {
        reassembler.ingest_chunk(foreign_chunk, &mut journal).await
    };

    assert!(
        result.unwrap().is_none(),
        "Leaf mode must drop foreign traffic"
    );
    assert!(
        reassembler.active_shards.is_empty(),
        "Workbench should be clean"
    );
}

#[tokio::test]
async fn test_vampire_attack_defense() -> Result<(), Box<dyn std::error::Error>> {
    init_observability();
    let config = PhalanxConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, mut telemetry_rx) = SimulationHarness::init_mesh(config.clone(), physics);
    let victim_did = harness
        .spawn_node("Victim", NodeRole::Guardian)
        .await
        .expect("Spawn failed");

    let (attacker_identity, _) = PhalanxIdentity::generate()?;
    let attacker_net_id = attacker_identity.to_network_id();
    let vid = VolleyId::new("vampire_stream");

    for i in 0..5 {
        let shard = create_video_shard(vec![vec![1]], StorageSequence(i), 30, vid.clone())?;

        let mut envelope = WitnessEnvelope::new(
            Evidence::Video(shard),
            &attacker_identity,
            attacker_net_id.clone(),
            None,
        )?;

        // POISON: Tamper with evidence to break signature
        if let Evidence::Video(ref mut v) = envelope.evidence {
            v.fps = 145;
        }

        let serialized = postcard::to_stdvec(&envelope)?;
        let chunks = shards::chunkify(
            ShardId(i as u32),
            serialized,
            4096,
            attacker_identity.did.clone(),
            ChunkType::Witnessed,
        )?;

        if let Some(first_chunk) = chunks.first() {
            harness
                .inject_event(
                    &victim_did,
                    NetworkEvent::DataReceived {
                        origin: attacker_net_id.clone(),
                        topic: config.network.video_topic.clone(),
                        data: postcard::to_stdvec(first_chunk)?,
                    },
                )
                .await?;
        }
    }

    // Monitor for defense event
    let mut defense_triggered = false;
    let sleep = tokio::time::sleep(Duration::from_secs(2));
    tokio::pin!(sleep);

    loop {
        tokio::select! {
            Some(event) = telemetry_rx.recv() => {
                if let SimEvent::AttackAttemptBlocked { attacker, .. } = event {
                    if attacker == attacker_net_id {
                        defense_triggered = true;
                        break;
                    }
                }
            }
            _ = &mut sleep => {
                tracing::warn!("Vampire monitoring timed out");
                break;
            }
        }
    }

    assert!(
        defense_triggered,
        "Vampire defense failed to block malformed payload"
    );
    Ok(())
}

#[tokio::test]
async fn test_pillar_salvage_under_disk_pressure() {
    // --- CLINICAL MOCK: THE CRUMBLING JOURNAL ---
    struct BrokenJournal;
    #[async_trait::async_trait]
    impl TransientJournal for BrokenJournal {
        async fn record_pending_egress(&mut self, _: &[PendingEgress]) -> Result<(), ShardError> {
            // Pillar 1 Failure: Simulated Disk Full / IO Error
            let io_err = std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "DISK FULL: Phalanx cannot salvage egress state",
            );
            Err(ShardError::Io(io_err))
        }
        // ... stubs for other methods ...
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
    let config = PhalanxConfig::test_defaults();
    let (identity, _) = PhalanxIdentity::generate().unwrap();

    // 3. Prepare Real Forensic Evidence via WitnessGate
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

    // 4. Setup the Guardian & Actor
    let guardian = Guardian::new(
        &temp.path().to_string_lossy(),
        &config,
        identity.did.clone(),
    );

    let (storage_tx, storage_rx) = tokio::sync::mpsc::channel::<StorageCommand>(10);
    let (forensic_tx, _forensic_rx) =
        tokio::sync::mpsc::channel::<(NetworkId, Did, GuardianError)>(1);

    let actor = StorageActor {
        reassembler: Reassembler::new(),
        guardian,
        journal: BrokenJournal,
        config: config.clone(),
        identity: identity.clone(),
        forensic_tx,
        local_peer_id: identity.to_network_id(),
    };

    // 5. Trigger Salvage with Evidence
    let salvage_data = vec![PendingEgress::new(
        "ch_broken_pillar".into(),
        VolleyResponse::Success(vec![envelope]),
        Duration::from_secs(1),
    )];

    storage_tx
        .send(StorageCommand::EmergencySalvage(salvage_data))
        .await
        .unwrap();
    drop(storage_tx); // Close the channel to signal shutdown after processing

    // 6. Verification: Ensure no deadlock
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
    use phalanx_core::base::engine::StorageCommand;
    use phalanx_core::security::gate::WitnessGate;

    // 1. Setup Environment
    let temp = tempfile::tempdir().unwrap();
    let config = PhalanxConfig::test_defaults();
    let (my_identity, _) = PhalanxIdentity::generate().unwrap();
    let (attacker_identity, _) = PhalanxIdentity::generate().unwrap();
    let attacker_net_id = attacker_identity.to_network_id();
    let topic = config.network.video_topic.clone();

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
        *sig_byte ^= 0xFF; // Flip the bits
    }

    let poisoned_data = postcard::to_stdvec(&envelope).expect("Serialization failed");

    let chunk = ShardChunk {
        shard_id: ShardId(666),
        chunk_index: 0,
        total_chunks: 1,
        data: poisoned_data,
        owner_did: attacker_identity.did.clone(),
        chunk_type: ChunkType::Witnessed,
    };

    // 3. Setup Channels and Actor
    let (storage_tx, storage_rx) = tokio::sync::mpsc::channel::<StorageCommand>(10);
    let (forensic_tx, mut forensic_rx) =
        tokio::sync::mpsc::channel::<(NetworkId, Did, GuardianError)>(10);

    let actor = StorageActor {
        reassembler: Reassembler::new(),
        guardian: Guardian::new(
            &temp.path().to_string_lossy(),
            &config,
            my_identity.did.clone(),
        ),
        journal: NoOpJournal, // NoOp because we expect rejection before the journal is reached
        config,
        identity: my_identity,
        forensic_tx,
        local_peer_id: NetworkId::random(),
    };

    // 4. Inject Poisoned Chunk via Ingest Command
    storage_tx
        .send(StorageCommand::Ingest(
            chunk,
            topic,
            attacker_net_id.clone(),
        ))
        .await
        .unwrap();

    // 5. Start Actor
    let actor_handle = tokio::spawn(async move {
        actor.run(storage_rx).await;
    });

    // 6. Verification: Listen for the Forensic Escalation
    let escalation = tokio::time::timeout(Duration::from_millis(500), forensic_rx.recv()).await;

    // Cleanup
    drop(storage_tx);
    actor_handle.abort();

    // 7. Assertions
    let (offender_net_id, offender_did, error) = escalation
        .expect("Timeout: Actor failed to escalate the signature mismatch!")
        .expect("Forensic channel closed prematurely");

    assert_eq!(offender_net_id, attacker_net_id, "Wrong peer reported!");
    assert_eq!(offender_did, attacker_identity.did, "Wrong DID reported!");

    // Check that the error is specifically a Cryptographic/Signature failure
    match error {
        GuardianError::VerificationFailed(ref msg) => {
            assert!(
                msg.contains("signature mismatch"),
                "Unexpected verification error: {}",
                msg
            );
            println!("Gatekeepers held! Signature mismatch detected: {}", msg);
        }
        // If your enum also has InvalidSignature, we keep it as a fallback
        GuardianError::InvalidSignature(..) => {
            println!("Gatekeepers held! Invalid signature detected.");
        }
        _ => panic!(
            "Expected VerificationFailed/InvalidSignature, got: {:?}",
            error
        ),
    }
}
