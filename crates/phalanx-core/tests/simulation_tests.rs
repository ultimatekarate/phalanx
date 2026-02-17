use tokio::time::Duration;
use tracing::info;

// Import from the public API
use phalanx_core::base::config::{PhalanxConfig, PhalanxPhysics};
use phalanx_core::primitives::identity::{NetworkId, PhalanxIdentity};
use phalanx_core::primitives::shards::{
    self, create_video_shard, ChunkType, DataPayload, Evidence, StorageSequence, WitnessEnvelope,
};
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
    let (victim_identity, _) = PhalanxIdentity::generate();
    let victim_did = victim_identity.did.clone();

    let frames = vec![vec![1]];
    let real_shard = create_video_shard(frames, StorageSequence(999), 10, "volley_test_999".into());

    let envelope = WitnessEnvelope::new(
        Evidence::Video(real_shard),
        &victim_identity,
        victim_device_network_id,
    );

    let serialized_envelope = postcard::to_stdvec(&envelope).expect("Failed to serialize envelope");

    let chunks = shards::chunkify(
        shards::ShardId(999),
        serialized_envelope,
        10,
        victim_did.clone(),
        ChunkType::Witnessed,
    );

    info!(victim = %victim_did, chunk_count = chunks.len(), "Broadcasting Signed Envelope Chunks");

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
    let (identity, _) = PhalanxIdentity::generate();
    let peer_id = NetworkId::random();
    let config = PhalanxConfig::default();
    let mut storage = Guardian::new("sim_vault/salvage_test", &config, identity.did.clone());

    let mut captured_envelopes = Vec::new();
    for i in 0..5 {
        let seq = StorageSequence(i);
        let frames = vec![vec![i as u8]];
        let shard = create_video_shard(frames, seq, 30, "volley_test_999".into());

        let envelope = WitnessEnvelope::new(Evidence::Video(shard), &identity, peer_id);
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

    let (identity, _) = PhalanxIdentity::generate();
    let peer_id = NetworkId::random();
    let seq = StorageSequence(101);

    let mut storage = Guardian::new(vault_path, &config, identity.did.clone());

    let frames = vec![vec![0xAA]];
    let shard = create_video_shard(frames, seq, 30, "volley_test_999".into());

    let envelope = WitnessEnvelope::new(Evidence::Video(shard), &identity, peer_id);
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
    // Unaffected by Harness changes.
    let (me, _) = PhalanxIdentity::generate();
    let (stranger, _) = PhalanxIdentity::generate();
    let config = PhalanxConfig::default();
    let mut storage = Guardian::new("sim_vault/leaf_test", &config, me.did.clone());

    let shard = create_video_shard(vec![vec![1]], StorageSequence(1), 30, "v1".into());
    let chunk = shards::chunkify(
        shards::ShardId(1),
        postcard::to_stdvec(&shard).unwrap(),
        100,
        stranger.did.clone(),
        ChunkType::Witnessed,
    );

    let is_leaf_mode = true;
    storage.ingest_chunk(chunk[0].clone(), is_leaf_mode);

    assert_eq!(
        storage.micro_layer.len(),
        0,
        "Guardian stored foreign data while in Leaf Mode!"
    );
}

#[tokio::test]
async fn test_vampire_attack_defense() {
    init_tracing();
    let config = PhalanxConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    // 1. Init Mesh
    let (mut harness, mut telemetry_rx) = SimulationHarness::init_mesh(config.clone(), physics);

    let _victim_did = harness.spawn_node("Victim", NodeRole::Guardian).await;

    // 2. Setup Attacker (Use ONE identity for both Transport and Application layers)
    let (attacker_identity, _) = PhalanxIdentity::generate();
    let attacker_did = attacker_identity.did.clone(); // DID B
    let attacker_net_id = NetworkId::random();

    // 3. Launch Attack
    for i in 0..10 {
        let shard = create_video_shard(vec![vec![1]], StorageSequence(i), 30, "vampire".into());
        let mut envelope =
            WitnessEnvelope::new(Evidence::Video(shard), &attacker_identity, attacker_net_id);

        // POISON: Set FPS to 145 (Illegal)
        if let Evidence::Video(ref mut v) = envelope.evidence {
            v.fps = 145;
        }

        let chunk = shards::chunkify(
            shards::ShardId(i as u32),
            postcard::to_stdvec(&envelope).unwrap(),
            4096,                 // Large size to force immediate reassembly
            attacker_did.clone(), // FIX: Chunk Owner == Envelope Signer
            ChunkType::Witnessed,
        );

        // Broadcast from the Attacker DID
        harness
            .broadcast(
                &attacker_did,
                SimEvent::ChunkIngested {
                    origin: attacker_net_id,
                    chunk: chunk[0].clone(),
                },
            )
            .await;
    }

    // 4. Verify Defense
    let mut detected = false;
    let timeout = tokio::time::sleep(Duration::from_millis(2000));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Some(event) = telemetry_rx.recv() => {
                if let SimEvent::AttackAttemptBlocked { attacker, reason } = event {
                    // The event uses 'origin' (NetworkId) which matches attacker_net_id
                    if attacker == attacker_net_id {
                        info!("Defense Success: Blocked {} due to '{}'", attacker, reason);
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
        "Vampire defense failed: No block event detected (Identity Mismatch?)"
    );
}
