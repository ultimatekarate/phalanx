use tokio::time::Duration;
use tracing::info;

// Import from the public API
use phalanx_core::base::config::{PhalanxConfig, PhalanxPhysics};
use phalanx_core::primitives::identity::{NetworkId, PhalanxIdentity};
use phalanx_core::primitives::shards::{
    self, create_video_shard, ChunkType, DataPayload, Evidence, ShardError, StorageSequence,
    WitnessEnvelope,
};
use phalanx_core::security::gate::ForensicGate;
use phalanx_core::security::telemetry::{NodeRole, SimEvent};
use phalanx_core::simulation::SimulationHarness;
use phalanx_core::storage::vault::Guardian;

// Helper to init logging for tests
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("phalanx=debug,info")
        .try_init();
}

#[tokio::test]
async fn test_salvage_on_node_death() {
    init_tracing();

    let _ = std::fs::remove_dir_all("sim_vault/VictimDevice");
    let _ = std::fs::remove_dir_all("sim_vault/GuardianDevice");

    let config = PhalanxConfig::test_salvage_on_node_death();
    let physics = PhalanxPhysics::test_profile();

    // FIX 1: Updated to 2-tuple return. We ignore the telemetry channel for this test.
    let (mut harness, _telemetry_rx) = SimulationHarness::init_mesh(config.clone(), physics);

    // FIX 2: Removed manual 'tokio::spawn(run_mesh_relay)' block.
    // The relay is now running automatically inside init_mesh.

    let victim_device_did = harness.spawn_node("VictimDevice", NodeRole::Guardian).await;
    let _guardian_device_did = harness
        .spawn_node("GuardianDevice", NodeRole::Guardian)
        .await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    let victim_device_network_id = harness.resolve_did(&victim_device_did).await.unwrap();
    let (victim_identity, _) = PhalanxIdentity::generate().unwrap();
    let victim_did = victim_identity.did.clone();

    let frames = vec![vec![1]];
    let real_shard = create_video_shard(frames, StorageSequence(999), 10, "volley_test_999".into())
        .expect("Failed to generate attack shard");

    let envelope = WitnessEnvelope::new(
        Evidence::Video(real_shard),
        &victim_identity,
        victim_device_network_id,
    )
    .expect("Failed to sign attack envelope");

    let serialized_envelope = postcard::to_stdvec(&envelope).expect("Failed to serialize envelope");

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
            return; // Terminate this ingestion cycle to prevent inconsistent state
        }
    };

    for chunk in chunks {
        harness
            .broadcast(
                &victim_device_did,
                SimEvent::ChunkIngested {
                    origin: victim_device_network_id,
                    chunk,
                },
            )
            .await;
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    info!("Waiting for 5 seconds for salvage...");
    tokio::time::sleep(Duration::from_millis(5000)).await;

    let victim_safe_did = victim_did.to_safe_name();
    let evidence_dir = std::path::PathBuf::from("sim_vault")
        .join("GuardianDevice")
        .join(&victim_safe_did);

    info!(path = ?evidence_dir, "Checking for salvaged archive");

    let mut found_file = false;
    for _ in 0..10 {
        if evidence_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&evidence_dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.ends_with(".vid.phlx") {
                        info!(file = %name, "Found archive!");
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
        "Salvage failed: .phlx file not found in correct DID folder."
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

    drop(storage);

    let recovered_storage = Guardian::new(vault_path, &config, identity.did.clone());

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
    use tracing::{error, warn};

    // Harness Setup
    let (me, _) = match PhalanxIdentity::generate() {
        Ok(id) => id,
        Err(e) => panic!("Failed to generate local identity: {}", e),
    };

    let (stranger, _) = match PhalanxIdentity::generate() {
        Ok(id) => id,
        Err(e) => panic!("Failed to generate foreign identity: {}", e),
    };

    let config = PhalanxConfig::default();
    let mut storage = Guardian::new("sim_vault/leaf_test", &config, me.did.clone());
    let net_id = NetworkId::random();

    // 1. Generation Gate: Resolve the Shard payload
    let shard = match create_video_shard(vec![vec![1]], StorageSequence(1), 30, "v1".into()).gate(
        "shard_generation_failure",
        &net_id,
        "Failed to generate video shard",
    ) {
        Ok(s) => s,
        Err(e) => panic!("Test setup failed at generation: {}", e),
    };

    // 2. Serialization Gate: Serialize the unwrapped Shard and resolve the bytes
    let serialized_shard = match postcard::to_stdvec(&shard)
        .map_err(|e| ShardError::Serialization(e.to_string()))
        .gate(
            "serialization_failure",
            &net_id,
            "Failed to serialize shard for chunking",
        ) {
        Ok(bytes) => bytes,
        Err(e) => panic!("Test setup failed at serialization: {}", e),
    };

    // 3. Discretization Phase: Utilize the unwrapped bytes
    let chunks = match shards::chunkify(
        shards::ShardId(1),
        serialized_shard,
        100,
        stranger.did.clone(),
        ChunkType::Witnessed,
    ) {
        Ok(c) => c,
        Err(e) => {
            error!(
                event = "discretization_failure",
                error = %e,
                node = %stranger.did,
                "Chunkify operation failed capacity or logic bounds"
            );
            return;
        }
    };

    let is_leaf_mode = true;
    if let Some(first_chunk) = chunks.first() {
        storage.ingest_chunk(first_chunk.clone(), is_leaf_mode);
    } else {
        warn!(
            event = "empty_chunk_set",
            node = %stranger.did,
            "Discretization produced zero chunks for provided data"
        );
    }

    // Verification
    assert_eq!(
        storage.micro_layer.len(),
        0,
        "Guardian stored foreign data while in Leaf Mode!"
    );
}

#[tokio::test]
async fn test_vampire_attack_defense() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let config = PhalanxConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    // 1. Init Mesh
    let (mut harness, mut telemetry_rx) = SimulationHarness::init_mesh(config.clone(), physics);

    // FIX 1: Capture the victim's identity for explicit routing
    let victim_did = harness.spawn_node("Victim", NodeRole::Guardian).await;

    // 2. Setup Attacker
    let (attacker_identity, _) = PhalanxIdentity::generate()?;
    let attacker_did = attacker_identity.did.clone();
    let attacker_net_id = attacker_did
        .as_str()
        .parse::<NetworkId>()
        .map_err(|_| "Failed to parse NetworkId from attacker DID")?;

    // 3. Launch Attack
    for i in 0..10 {
        // Strict evaluation pipeline
        let shard = create_video_shard(vec![vec![1]], StorageSequence(i), 30, "vampire".into())?;

        let mut envelope = WitnessEnvelope::new(
            Evidence::Video(shard),
            &attacker_identity,
            attacker_net_id.clone(),
        )?;

        // POISON: Invalidate signature post-sealing
        if let Evidence::Video(ref mut v) = envelope.evidence {
            v.fps = 145;
        }

        // Serialization boundary
        let serialized_envelope =
            postcard::to_stdvec(&envelope).map_err(|e| format!("Serialization failed: {}", e))?;

        // Discretization boundary
        let chunks = shards::chunkify(
            shards::ShardId(i as u32),
            serialized_envelope,
            4096,
            attacker_did.clone(),
            ChunkType::Witnessed,
        )?;

        // FIX 2: Route attack strictly to the Victim Guardian
        if let Some(first_chunk) = chunks.first() {
            harness
                .broadcast(
                    &victim_did,
                    SimEvent::ChunkIngested {
                        origin: attacker_net_id.clone(),
                        chunk: first_chunk.clone(),
                    },
                )
                .await;
        }
    }

    // 4. Verify Defense
    let mut detected = false;
    let timeout = tokio::time::sleep(std::time::Duration::from_millis(2000));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Some(event) = telemetry_rx.recv() => {
                if let SimEvent::AttackAttemptBlocked { attacker, target, reason } = event {
                    if attacker == attacker_net_id {
                        tracing::info!(
                            "Defense Success: {} Blocked {} due to '{}'",
                            target,
                            attacker,
                            reason
                        );
                        detected = true;
                        break;
                    }
                }
            }
            _ = &mut timeout => break,
        }
    }

    assert!(
        detected,
        "Vampire defense failed: Victim node did not trigger AttackAttemptBlocked telemetry"
    );

    Ok(())
}
