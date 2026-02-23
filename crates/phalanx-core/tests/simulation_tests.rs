use tokio::time::Duration;

// Import from the public API
use phalanx_core::base::config::{PhalanxConfig, PhalanxPhysics};
use phalanx_core::base::types::{MeshTopic, NodeMode, TrafficGovernor};
use phalanx_core::primitives::identity::{NetworkId, PhalanxIdentity};
use phalanx_core::primitives::shards::{
    self, create_video_shard, ChunkType, DataPayload, EnvelopeState, Evidence, ShardChunk, ShardId,
    StorageSequence, VolleyId, WitnessEnvelope,
};
use phalanx_core::primitives::time::TrustedClock;
use phalanx_core::security::ingress::{IngressContext, IngressOrchestrator, SecurityPipeline};
use phalanx_core::security::telemetry::{init_observability, NodeRole, SimEvent};
use phalanx_core::security::trust::TrustRegistry;
use phalanx_core::simulation::{SimJournal, SimulationHarness};
use phalanx_core::storage::reassembler::Reassembler;
use phalanx_core::storage::vault::Guardian;
use phalanx_core::transport::events::NetworkEvent;
use phalanx_core::transport::health::HealthTracker;

#[tokio::test]
async fn test_salvage_on_node_death() {
    init_observability();

    let config = PhalanxConfig::test_salvage_on_node_death();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, _telemetry_rx) = SimulationHarness::init_mesh(config.clone(), physics);

    let victim_device_did = harness
        .spawn_node("VictimDevice", NodeRole::Guardian)
        .await
        .expect("Failed to spawn VictimDevice");

    let guardian_device_did = harness
        .spawn_node("GuardianDevice", NodeRole::Guardian)
        .await
        .expect("Failed to spawn GuardianDevice");

    tokio::time::sleep(Duration::from_secs(1)).await;

    let victim_device_network_id = harness.resolve_did(&victim_device_did).await.unwrap();
    let (victim_identity, _) = PhalanxIdentity::generate().unwrap();
    let victim_did = victim_identity.did.clone();
    let remote_network_id = NetworkId::random();
    let vid = VolleyId::new("salvage_volley_01");

    let frames = vec![vec![1]];
    let real_shard = create_video_shard(frames, StorageSequence(999), 10, vid.clone())
        .expect("Failed to generate attack shard");

    // FIX: Added 'None' for causality anchor
    let envelope = WitnessEnvelope::new(
        Evidence::Video(real_shard),
        &victim_identity,
        remote_network_id.clone(),
        None,
    )
    .expect("Failed to sign attack envelope");

    let serialized_envelope = postcard::to_stdvec(&envelope).expect("Failed to serialize envelope");

    // FIX: Corrected chunkify signature
    let chunks = shards::chunkify(
        ShardId(999),
        serialized_envelope,
        10,
        victim_did.clone(),
        ChunkType::Witnessed,
    )
    .expect("Failed to transform envelope into verifiable chunks");

    let topic = MeshTopic::new("phalanx/video/1.0.0");

    for chunk in chunks {
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

    let guardian_net_id = harness.resolve_did(&guardian_device_did).await.unwrap();
    harness
        .inject_event(
            &victim_device_did,
            NetworkEvent::PeerDiscovered(guardian_net_id),
        )
        .await
        .expect("Harness routing failure");

    tokio::time::sleep(Duration::from_millis(100)).await;

    harness
        .inject_event(&victim_device_did, NetworkEvent::Shutdown)
        .await
        .expect("Harness routing failure");

    tokio::time::sleep(Duration::from_millis(2000)).await;

    // Verify disk persistence
    let victim_safe_did = victim_did.to_safe_name();
    let evidence_dir = std::path::PathBuf::from("sim_vault").join(&victim_safe_did);

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
        "Salvage failed: Volley file not found in vault."
    );
}

#[tokio::test]
async fn test_out_of_sequence_salvage_on_node_death() {
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let peer_id = NetworkId::random();
    let config = PhalanxConfig::default();
    let mut storage = Guardian::new("sim_vault/salvage_test", &config, identity.did.clone());
    let vid = VolleyId::new("seq_test");

    let mut captured_envelopes = Vec::new();
    for i in 0..5 {
        let shard = create_video_shard(vec![vec![i as u8]], StorageSequence(i), 30, vid.clone())
            .expect("Failed to generate shard");

        // FIX: 4-argument constructor
        let envelope = WitnessEnvelope::new(Evidence::Video(shard), &identity, peer_id, None)
            .expect("Failed to sign envelope");
        captured_envelopes.push(envelope);
    }

    // Ingest out of order
    for idx in [0, 2, 4, 1, 3] {
        storage
            .ingest_envelope(EnvelopeState::Intact(captured_envelopes[idx].clone()))
            .await
            .expect("Ingest failed");
    }

    // FIX: Lookup by VolleyId, not Did
    let session = storage
        .get_active_volley_shards(&vid)
        .expect("Session should exist for recovered VolleyId");

    for i in 0..5 {
        let seq = StorageSequence(i);
        let env = session.get(&seq).expect("Missing sequence");
        if let Evidence::Video(ref v) = env.evidence {
            if let DataPayload::Clear(bytes) = &v.payload {
                let recovered: Vec<Vec<u8>> = postcard::from_bytes(bytes).unwrap();
                assert_eq!(recovered[0][0], i as u8);
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
    let local_net_id = NetworkId::random();

    let mut reassembler = Reassembler::new();
    let mut guardian = Guardian::new("sim_vault/leaf_test", &config, local_identity.did.clone());
    let mut trust_registry = TrustRegistry::build(&config).await;
    let mut health_tracker = HealthTracker::new();
    let governor = TrafficGovernor::new();
    let clock = TrustedClock::new();
    let mut transient_journal = SimJournal;

    let foreign_chunk = ShardChunk {
        shard_id: ShardId(1),
        chunk_index: 0,
        total_chunks: 1,
        data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        owner_did: foreign_identity.did.clone(),
        chunk_type: ChunkType::Witnessed,
    };

    let ingress_ctx = IngressContext {
        config: &config,
        identity: &local_identity,
        network_id: local_net_id,
        clock: &clock,
        governor: &governor,
        mode: NodeMode::Leaf,
    };

    let mut security_pipeline = SecurityPipeline {
        reassembler: &mut reassembler,
        journal: &mut transient_journal,
        guardian: &mut guardian,
        trust_registry: &mut trust_registry,
        health_tracker: &mut health_tracker,
    };

    let result = IngressOrchestrator::process_chunk(
        foreign_chunk,
        &MeshTopic::new("phalanx/video"),
        &ingress_ctx,
        &mut security_pipeline,
    )
    .await;

    assert_eq!(
        result.unwrap(),
        None,
        "Leaf mode should drop foreign traffic"
    );
    assert!(reassembler.crucible.contexts.is_empty());
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

        // FIX: 4-argument constructor
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
                        topic: MeshTopic::new("phalanx/video/1.0.0"),
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
