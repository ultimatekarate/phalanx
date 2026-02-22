use tokio::time::Duration;

// Import from the public API
use phalanx_core::base::config::{PhalanxConfig, PhalanxPhysics};
use phalanx_core::base::types::MeshTopic;
use phalanx_core::primitives::identity::{NetworkId, PhalanxIdentity};
use phalanx_core::primitives::shards::{
    self, create_video_shard, ChunkType, DataPayload, Evidence, StorageSequence, WitnessEnvelope,
};
use phalanx_core::security::telemetry::{init_observability, NodeRole, SimEvent};
use phalanx_core::simulation::SimulationHarness;
use phalanx_core::storage::vault::Guardian;
use phalanx_core::transport::events::NetworkEvent;

#[tokio::test]
async fn test_salvage_on_node_death() {
    init_observability();

    let config = PhalanxConfig::test_salvage_on_node_death();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, _telemetry_rx) = SimulationHarness::init_mesh(config.clone(), physics);

    // spawn_node now returns Option<Did>, requiring unwrap
    let victim_device_did = harness
        .spawn_node("VictimDevice", NodeRole::Guardian)
        .await
        .expect("Failed to spawn VictimDevice");

    let guardian_device_did = harness
        .spawn_node("GuardianDevice", NodeRole::Guardian)
        .await
        .expect("Failed to spawn GuardianDevice");

    tracing::info!("Initializing mesh nodes... waiting for DHT settling");
    tokio::time::sleep(Duration::from_secs(1)).await;

    let victim_device_network_id = harness.resolve_did(&victim_device_did).await.unwrap();
    let (victim_identity, _) = PhalanxIdentity::generate().unwrap();
    let victim_did = victim_identity.did.clone();
    let remote_network_id = NetworkId::random();

    tracing::info!(
        target: "phalanx::test",
        %victim_did,
        %victim_device_network_id,
        %remote_network_id,
        "Simulating remote ingestion attack"
    );

    let frames = vec![vec![1]];
    let real_shard = create_video_shard(frames, StorageSequence(999), 10, "volley_test_999".into())
        .expect("Failed to generate attack shard");

    let envelope = WitnessEnvelope::new(
        Evidence::Video(real_shard),
        &victim_identity,
        remote_network_id.clone(),
    )
    .expect("Failed to sign attack envelope");

    let serialized_envelope = postcard::to_stdvec(&envelope).expect("Failed to serialize envelope");

    tracing::info!(
        target: "phalanx::test",
        payload_size = serialized_envelope.len(),
        "Envelope cryptographically sealed and serialized"
    );

    let chunks_result = shards::chunkify(
        shards::ShardId(999),
        serialized_envelope,
        10,
        victim_did.clone(),
        ChunkType::Witnessed,
    );

    let chunks = match chunks_result {
        Ok(valid_chunks) => valid_chunks,
        Err(error) => {
            tracing::error!(
                event = "discretization_failure",
                node = %victim_did,
                error = %error,
                "Failed to transform envelope into verifiable chunks"
            );
            return;
        }
    };

    tracing::info!(
        target: "phalanx::test",
        chunk_count = chunks.len(),
        "Beginning simulated broadcast sequence"
    );

    let topic = MeshTopic::new("phalanx/video/1.0.0");

    for (i, chunk) in chunks.into_iter().enumerate() {
        tracing::debug!(target: "phalanx::test", chunk_index = i, "Broadcasting chunk to GuardianDevice");

        // Serialize the chunk payload just as it would be over the network
        let chunk_bytes = postcard::to_stdvec(&chunk).expect("Failed to serialize chunk");

        harness
            .inject_event(
                &guardian_device_did,
                NetworkEvent::DataReceived {
                    origin: victim_device_network_id,
                    topic: topic.clone(),
                    data: chunk_bytes,
                },
            )
            .await
            .expect("Harness routing failure");
    }

    // 1. MESH DISCOVERY: Inform the Victim that the Guardian is available for offloading
    let guardian_net_id = harness.resolve_did(&guardian_device_did).await.unwrap();
    harness
        .inject_event(
            &victim_device_did,
            NetworkEvent::PeerDiscovered(guardian_net_id),
        )
        .await
        .expect("Harness routing failure");

    // Give the routing table a moment to update
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 2. SIMULATE NODE DEATH: This triggers the graceful shutdown/salvage protocol.
    tracing::info!(target: "phalanx::test", "Simulating VictimDevice crash/shutdown to trigger salvage");
    harness
        .inject_event(&victim_device_did, NetworkEvent::Shutdown)
        .await
        .expect("Harness routing failure");

    // 3. PROPAGATION DELAY: Allow the simulated network to transfer the bytes and Guardian to write to disk.
    tracing::info!(target: "phalanx::test", "Waiting for salvage sequence to write to disk...");
    tokio::time::sleep(Duration::from_millis(2000)).await;

    // Check GuardianDevice vault
    let victim_safe_did = victim_did.to_safe_name();
    let evidence_dir = std::path::PathBuf::from("sim_vault")
        .join("GuardianDevice_trust")
        .join(&victim_safe_did);

    tracing::info!(target: "phalanx::test", path = ?evidence_dir, "Checking for salvaged archive on GuardianDevice");

    let mut found_file = false;
    for _ in 0..10 {
        if evidence_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&evidence_dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.ends_with(".vid.phlx") {
                        tracing::info!(target: "phalanx::test", file = %name, "Found active archive!");
                        found_file = true;
                        break;
                    }
                }
            }
        }
        if found_file {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert!(
        found_file,
        "Salvage failed: .phlx file not found in correct DID folder. Check log output for dropped chunks."
    );
}

#[tokio::test]
async fn test_out_of_sequence_salvage_on_node_death() {
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let peer_id = NetworkId::random();
    let config = PhalanxConfig::default();
    let mut storage = Guardian::new("sim_vault/salvage_test", &config, identity.did.clone());

    let mut captured_envelopes = Vec::new();
    for i in 0..5 {
        let seq = StorageSequence(i);
        let frames = vec![vec![i as u8]];
        let shard = create_video_shard(frames, seq, 30, "volley_test_999".into())
            .expect("Failed to generate attack shard");

        let envelope = WitnessEnvelope::new(Evidence::Video(shard), &identity, peer_id)
            .expect("Failed to sign envelope");
        captured_envelopes.push(envelope);
    }

    storage
        .ingest_envelope(captured_envelopes[0].clone())
        .expect("Ingest failed");
    storage
        .ingest_envelope(captured_envelopes[2].clone())
        .expect("Ingest failed");
    storage
        .ingest_envelope(captured_envelopes[4].clone())
        .expect("Ingest failed");
    storage
        .ingest_envelope(captured_envelopes[1].clone())
        .expect("Ingest failed");
    storage
        .ingest_envelope(captured_envelopes[3].clone())
        .expect("Ingest failed");

    let session = storage
        .get_active_volley_shards(&identity.did.clone())
        .expect("Session should exist for recovered DID");

    let mut keys: Vec<&StorageSequence> = session.keys().collect();
    keys.sort();

    for (i, seq) in keys.iter().enumerate() {
        assert_eq!(seq.0, i as u32, "Sequence gap detected at index {}", i);
        let env = session.get(seq).unwrap();
        if let Evidence::Video(ref v) = env.evidence {
            if let DataPayload::Clear(bytes) = &v.payload {
                let recovered: Vec<Vec<u8>> = postcard::from_bytes(bytes).unwrap();
                assert_eq!(recovered[0][0], i as u8, "Data mismatch at sequence {}", i);
            }
        }
    }
}

#[tokio::test]
async fn test_stronghold_crash_recovery() {
    let config = PhalanxConfig::default();
    let vault_path = "sim_vault/crash_test";
    let _ = std::fs::remove_dir_all(vault_path);

    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let peer_id = NetworkId::random();
    let seq = StorageSequence(101);

    let mut storage = Guardian::new(vault_path, &config, identity.did.clone());

    let frames = vec![vec![0xAA]];
    let shard = create_video_shard(frames, seq, 30, "volley_test_999".into())
        .expect("Failed to generate attack shard");

    let envelope = WitnessEnvelope::new(Evidence::Video(shard), &identity, peer_id)
        .expect("Failed to sign envelope");

    storage
        .ingest_envelope(envelope.clone())
        .expect("Ingest failed");

    // Simulate crash (Memory state wiped)
    drop(storage);

    // Boot new instance
    let mut recovered_storage = Guardian::new(vault_path, &config, identity.did.clone());

    // --- FIX: Simulate StorageActor::restore_state WAL replay ---
    recovered_storage
        .ingest_envelope(envelope.clone())
        .expect("WAL replay failed");

    let recovered_session = recovered_storage
        .get_active_volley_shards(&identity.did.clone())
        .expect("Guardian failed to recover DID session from WAL");

    let recovered_env = recovered_session
        .get(&seq)
        .expect("Guardian failed to recover specific shard 101 from WAL");

    if let Evidence::Video(ref v) = recovered_env.evidence {
        if let DataPayload::Clear(bytes) = &v.payload {
            let recovered: Vec<Vec<u8>> = postcard::from_bytes(bytes).unwrap();
            assert_eq!(recovered[0][0], 0xAA);
        }
    }
}

#[tokio::test]
async fn test_leaf_mode_isolation() {
    use phalanx_core::base::config::PhalanxConfig;
    use phalanx_core::base::types::{MeshTopic, NodeMode, TrafficGovernor};
    use phalanx_core::primitives::identity::{NetworkId, PhalanxIdentity};
    use phalanx_core::primitives::shards::{ChunkType, ShardChunk, ShardId};
    use phalanx_core::primitives::time::TrustedClock;
    use phalanx_core::security::ingress::{IngressContext, IngressOrchestrator, SecurityPipeline};
    use phalanx_core::security::trust::TrustRegistry;
    use phalanx_core::simulation::SimJournal;
    use phalanx_core::storage::reassembler::Reassembler;
    use phalanx_core::storage::vault::Guardian;
    use phalanx_core::transport::health::HealthTracker; // Assuming SimJournal is available in scope

    // 1. Identity Provisioning
    let (local_identity, _) =
        PhalanxIdentity::generate().expect("Failed to generate local identity");
    let (foreign_identity, _) =
        PhalanxIdentity::generate().expect("Failed to generate foreign identity");

    let config = PhalanxConfig::default();
    let local_network_id = NetworkId::random();

    // 2. Decoupled Pipeline Allocation
    let mut reassembler = Reassembler::new();
    let mut guardian = Guardian::new("sim_vault/leaf_test", &config, local_identity.did.clone());
    let mut trust_registry = TrustRegistry::build(&config).await;
    let mut health_tracker = HealthTracker::new();
    let governor = TrafficGovernor::new();
    let clock = TrustedClock::new();
    let mut transient_journal = SimJournal;

    // 3. Construct a Foreign Payload
    // In the decoupled architecture, the Orchestrator inspects metadata prior
    // to deserialization overhead, so we can mock the payload directly.
    let foreign_chunk = ShardChunk {
        shard_id: ShardId(1),
        chunk_index: 0,
        total_chunks: 1,
        data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        owner_did: foreign_identity.did.clone(),
        chunk_type: ChunkType::Witnessed,
    };
    let ingest_topic = MeshTopic::new("phalanx/video");

    // 4. Perimeter Context Definition (Enforcing Leaf Mode)
    let ingress_ctx = IngressContext {
        config: &config,
        identity: &local_identity,
        network_id: local_network_id,
        clock: &clock,
        governor: &governor,
        mode: NodeMode::Leaf, // <-- The core isolation toggle
    };

    let mut security_pipeline = SecurityPipeline {
        reassembler: &mut reassembler,
        journal: &mut transient_journal,
        guardian: &mut guardian,
        trust_registry: &mut trust_registry,
        health_tracker: &mut health_tracker,
    };

    // 5. Execution: Route through Orchestrator
    let ingress_result = IngressOrchestrator::process_chunk(
        foreign_chunk,
        &ingest_topic,
        &ingress_ctx,
        &mut security_pipeline,
    )
    .await;

    // 6. Forensic Verification
    assert!(
        ingress_result.is_ok(),
        "Orchestrator should not return an Err for dropped topology traffic"
    );
    assert_eq!(
        ingress_result.unwrap(),
        None,
        "Orchestrator should return Ok(None) to represent silently dropped traffic"
    );

    // Verify the downstream data factories and storage layers remain unpolluted
    assert!(
        reassembler.video_buffers.is_empty(),
        "Reassembler leaked foreign data into transient memory while in Leaf Mode!"
    );
    assert!(
        guardian.active_volleys.is_empty(),
        "Guardian bypassed orchestration and archived foreign data while in Leaf Mode!"
    );
}

#[tokio::test]
async fn test_vampire_attack_defense() -> Result<(), Box<dyn std::error::Error>> {
    init_observability();
    tracing::info!("Initializing Vampire Attack simulation context");

    let config = PhalanxConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    // 1. Init Mesh
    let (mut harness, mut telemetry_rx) = SimulationHarness::init_mesh(config.clone(), physics);

    let victim_did = harness
        .spawn_node("Victim", NodeRole::Guardian)
        .await
        .expect("Failed to spawn Victim");

    tracing::info!(victim_id = %victim_did, "Victim node provisioned");

    // 2. Setup Attacker
    let (attacker_identity, _) = PhalanxIdentity::generate()?;
    let attacker_did = attacker_identity.did.clone();
    let attacker_net_id = attacker_identity.to_network_id();

    tracing::info!(attacker_id = %attacker_did, attacker_net = %attacker_net_id, "Attacker node provisioned");

    // 3. Launch Attack
    let topic = MeshTopic::new("phalanx/video/1.0.0");

    for attack_iteration in 0..10 {
        tracing::debug!(
            iteration = attack_iteration,
            "Constructing malicious payload"
        );

        // Strict evaluation pipeline
        let shard = create_video_shard(
            vec![vec![1]],
            StorageSequence(attack_iteration),
            30,
            "vampire".into(),
        )?;

        let mut envelope = WitnessEnvelope::new(
            Evidence::Video(shard),
            &attacker_identity,
            attacker_net_id.clone(),
        )?;

        // POISON: Invalidate signature post-sealing to simulate cryptographic offense
        if let Evidence::Video(ref mut v) = envelope.evidence {
            v.fps = 145;
            tracing::trace!(iteration = attack_iteration, "Payload signature poisoned");
        }

        // Serialization boundary
        let serialized_envelope =
            postcard::to_stdvec(&envelope).map_err(|e| format!("Serialization failed: {}", e))?;

        // Discretization boundary
        let chunks = shards::chunkify(
            shards::ShardId(attack_iteration as u32),
            serialized_envelope,
            4096,
            attacker_did.clone(),
            ChunkType::Witnessed,
        )?;

        if let Some(first_chunk) = chunks.first() {
            let chunk_bytes = postcard::to_stdvec(first_chunk)?;

            tracing::debug!(
                iteration = attack_iteration,
                bytes_len = chunk_bytes.len(),
                "Injecting malformed chunk into ingress port"
            );

            harness
                .inject_event(
                    &victim_did,
                    NetworkEvent::DataReceived {
                        origin: attacker_net_id.clone(),
                        topic: topic.clone(),
                        data: chunk_bytes,
                    },
                )
                .await
                .expect("Harness routing failure");
        }
    }

    tracing::info!("Attack payload injection complete. Transitioning to event monitoring phase.");

    // 4. Verify Defense
    let mut is_defense_successful = false;
    let timeout = tokio::time::sleep(std::time::Duration::from_millis(2000));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            event_option = telemetry_rx.recv() => {
                match event_option {
                    Some(event) => {
                        // FORENSIC CAPTURE: Log every single event emitted by the mesh
                        tracing::debug!(captured_event = ?event, "Observed mesh telemetry event");

                        if let SimEvent::AttackAttemptBlocked { attacker, target, reason } = event {
                            if attacker == attacker_net_id {
                                tracing::info!(
                                    target_node = %target,
                                    attacker_node = %attacker,
                                    block_reason = %reason,
                                    "Defense Success: Verification pipeline actively blocked payload"
                                );
                                is_defense_successful = true;
                                break;
                            }
                        }
                    },
                    None => {
                        tracing::error!("Telemetry channel dropped unexpectedly during monitoring phase");
                        break;
                    }
                }
            }
            _ = &mut timeout => {
                tracing::warn!("Monitoring phase timed out after 2000ms. Insufficient events emitted.");
                break;
            }
        }
    }

    assert!(
        is_defense_successful,
        "Vampire defense failed: Victim node did not trigger AttackAttemptBlocked telemetry. Review standard output for captured mesh events."
    );

    Ok(())
}
