use tempfile::tempdir;
use tokio::sync::mpsc;

use phalanx_core::base::config::PhalanxConfig;
use phalanx_core::base::engine::StorageCommand;
use phalanx_core::playback::coordinator::PlaybackCoordinator;
use phalanx_core::playback::sink::VideoPlayerSink;
use phalanx_core::primitives::identity::NetworkId;
use phalanx_core::primitives::shards::{
    DataPayload, EnvelopeState, Evidence, StorageSequence, VideoShard, VolleyId, WitnessEnvelope,
};
use phalanx_core::primitives::time::PhalanxTimestamp;
use phalanx_core::storage::vault::Guardian;
use phalanx_core::PhalanxIdentity;

#[tokio::test]
async fn test_exodus_resurrection_logic() {
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let vault_path = temp_dir.path().to_string_lossy().to_string();

    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let config = PhalanxConfig::default();

    let (storage_tx, mut storage_rx) = mpsc::channel::<StorageCommand>(100);
    let (disc_tx, mut disc_rx) = mpsc::channel(1);
    let (ui_tx, mut ui_rx) = mpsc::channel(10);

    // Spawn Test Storage Actor
    let identity_clone = identity.clone();
    tokio::spawn(async move {
        let mut guardian = Guardian::new(&vault_path, &config, identity_clone.did);
        while let Some(cmd) = storage_rx.recv().await {
            match cmd {
                StorageCommand::GetShard {
                    volley_id,
                    sequence_id,
                    reply_to,
                } => {
                    let _ = reply_to.send(guardian.get_shard(&volley_id, sequence_id));
                }
                StorageCommand::IngestEnvelope(state) => {
                    if let Err(e) = guardian.ingest_envelope(state).await {
                        tracing::error!("Test Actor Ingestion Reject: {:?}", e);
                    }
                }
                _ => {
                    tracing::debug!("Mock StorageActor ignored unsupported command");
                }
            }
        }
    });

    let sink = VideoPlayerSink::new(ui_tx);
    let volley_id = VolleyId::new("v_exodus_test");

    let mut coordinator = PlaybackCoordinator::new(storage_tx.clone(), None, sink, disc_tx);

    // Pre-load Shard 1
    let shard_1 = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(1),
        fps: 30,
        volley_id: volley_id.clone(),
        payload: DataPayload::Clear(b"Frame 1".to_vec()),
    };
    let envelope_1 = WitnessEnvelope::new(
        Evidence::Video(shard_1),
        &identity,
        NetworkId::random(),
        None,
    )
    .unwrap();
    let hash_1 = envelope_1.signature_hash();

    let state_1 = EnvelopeState::Intact(envelope_1);
    storage_tx
        .send(StorageCommand::IngestEnvelope(state_1))
        .await
        .unwrap();

    // Start Coordinator
    let v_id_clone = volley_id.clone();
    let _handle = tokio::spawn(async move {
        coordinator.run(v_id_clone).await.unwrap();
    });

    // Verify Immediate Resurrection (Shard 1)
    let frame = ui_rx.recv().await.expect("Should receive Frame 1");
    assert_eq!(frame, b"Frame 1");

    // Verify Gap Discovery
    let (volley_id, missing_id) = disc_rx
        .recv()
        .await
        .expect("Should signal discovery for Shard 2");
    assert_eq!(missing_id, StorageSequence(2));

    // Mesh provides Shard 2
    let shard_2 = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(2),
        fps: 30,
        volley_id: volley_id.clone(),
        payload: DataPayload::Clear(b"Frame 2".to_vec()),
    };
    let envelope_2 = WitnessEnvelope::new(
        Evidence::Video(shard_2),
        &identity,
        NetworkId::random(),
        Some(hash_1),
    )
    .unwrap();

    let state_2 = EnvelopeState::Intact(envelope_2);
    storage_tx
        .send(StorageCommand::IngestEnvelope(state_2))
        .await
        .unwrap();

    let frame_2 = ui_rx.recv().await.expect("Should receive Frame 2");
    assert_eq!(frame_2, b"Frame 2");
}

#[tokio::test]
async fn test_playback_resurrection_with_mesh_gap() {
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let vault_path = temp_dir.path().to_string_lossy().to_string();
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let config = PhalanxConfig::default();

    let (storage_tx, mut storage_rx) = mpsc::channel::<StorageCommand>(100);
    let (disc_tx, mut disc_rx) = mpsc::channel::<(VolleyId, StorageSequence)>(100);
    let (ui_tx, mut ui_rx) = mpsc::channel(10);

    // 1. Storage Actor (Resilient Mock)
    let identity_clone = identity.clone();
    tokio::spawn(async move {
        let mut guardian = Guardian::new(&vault_path, &config, identity_clone.did);
        while let Some(cmd) = storage_rx.recv().await {
            match cmd {
                StorageCommand::GetShard {
                    volley_id,
                    sequence_id,
                    reply_to,
                } => {
                    let _ = reply_to.send(guardian.get_shard(&volley_id, sequence_id));
                }
                StorageCommand::IngestEnvelope(state) => {
                    // Graceful handling prevents the test actor from panicking
                    if let Err(e) = guardian.ingest_envelope(state).await {
                        tracing::error!("Test Ingestion Error: {:?}", e);
                    }
                }
                _ => {}
            }
        }
    });

    let sink = VideoPlayerSink::new(ui_tx);
    let volley_id = VolleyId::new("v_resurrection");

    let mut coordinator = PlaybackCoordinator::new(storage_tx.clone(), None, sink, disc_tx);

    // 2. CHAINING: Create Shard 1
    let shard_1 = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(1),
        fps: 30,
        volley_id: volley_id.clone(),
        payload: DataPayload::Clear(b"Frame 1 Data".to_vec()),
    };
    let envelope_1 = WitnessEnvelope::new(
        Evidence::Video(shard_1),
        &identity,
        NetworkId::random(),
        None,
    )
    .unwrap();
    let hash_1 = envelope_1.signature_hash(); // Capture hash for chaining

    storage_tx
        .send(StorageCommand::IngestEnvelope(EnvelopeState::Intact(
            envelope_1,
        )))
        .await
        .unwrap();

    // 3. Start Coordinator
    let v_id_clone = volley_id.clone();
    tokio::spawn(async move {
        let _ = coordinator.run(v_id_clone).await;
    });

    // Verify Frame 1
    let frame_1 = ui_rx
        .recv()
        .await
        .expect("Playback should start with Frame 1");
    assert_eq!(frame_1, b"Frame 1 Data");

    // Verify Gap Signal
    let (v_id, missing_seq) = disc_rx.recv().await.expect("Should signal for Shard 2");
    assert_eq!(missing_seq, StorageSequence(2));

    // 4. CHAINING: Create Shard 2 pointing to Shard 1
    let shard_2 = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(2),
        fps: 30,
        volley_id: v_id,
        payload: DataPayload::Clear(b"Frame 2 Data".to_vec()),
    };
    // CRITICAL FIX: Pass Some(hash_1)
    let envelope_2 = WitnessEnvelope::new(
        Evidence::Video(shard_2),
        &identity,
        NetworkId::random(),
        Some(hash_1),
    )
    .unwrap();
    storage_tx
        .send(StorageCommand::IngestEnvelope(EnvelopeState::Intact(
            envelope_2,
        )))
        .await
        .unwrap();

    // Verify Resumption
    let frame_2 = ui_rx
        .recv()
        .await
        .expect("Playback should resume with Frame 2");
    assert_eq!(frame_2, b"Frame 2 Data");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_horrendous_stuttering_mesh_resurrection() {
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let vault_path = temp_dir.path().to_string_lossy().to_string();
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let config = PhalanxConfig::default();

    let (storage_tx, mut storage_rx) = mpsc::channel::<StorageCommand>(100);
    let (disc_tx, mut disc_rx) = mpsc::channel::<(VolleyId, StorageSequence)>(100);
    let (ui_tx, mut ui_rx) = mpsc::channel(100);

    tokio::spawn(async move {
        let mut guardian = Guardian::new(&vault_path, &config, identity.did);
        while let Some(cmd) = storage_rx.recv().await {
            match cmd {
                StorageCommand::GetShard {
                    volley_id,
                    sequence_id,
                    reply_to,
                } => {
                    let _ = reply_to.send(guardian.get_shard(&volley_id, sequence_id));
                }
                StorageCommand::IngestEnvelope(state) => {
                    let _ = guardian.ingest_envelope(state).await;
                }
                _ => {}
            }
        }
    });

    let (identity_main, _) = PhalanxIdentity::generate().unwrap();
    let volley_id = VolleyId::new("v_chaos_monkey");

    // 1. Pre-calculate the entire cryptographic chain 1..10
    let mut chain = std::collections::HashMap::new();
    let mut last_hash = None;

    for i in 1..=10 {
        let shard = VideoShard {
            timestamp: PhalanxTimestamp::now(),
            sequence_id: StorageSequence(i),
            fps: 30,
            volley_id: volley_id.clone(),
            payload: DataPayload::Clear(format!("Frame {}", i).into_bytes()),
        };
        let envelope = WitnessEnvelope::new(
            Evidence::Video(shard),
            &identity_main,
            NetworkId::random(),
            last_hash,
        )
        .unwrap();
        last_hash = Some(envelope.signature_hash());
        chain.insert(i, envelope);
    }

    // 2. Pre-load Sequence 1 and 10 (Swiss Cheese)
    storage_tx
        .send(StorageCommand::IngestEnvelope(EnvelopeState::Intact(
            chain.get(&1).unwrap().clone(),
        )))
        .await
        .unwrap();
    storage_tx
        .send(StorageCommand::IngestEnvelope(EnvelopeState::Intact(
            chain.get(&10).unwrap().clone(),
        )))
        .await
        .unwrap();

    // 3. Chaos Monkey: Heals by providing the missing pieces from our pre-calculated chain
    let chaos_storage_tx = storage_tx.clone();
    tokio::spawn(async move {
        while let Some((_, missing_seq)) = disc_rx.recv().await {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            if let Some(env) = chain.get(&missing_seq.0) {
                let _ = chaos_storage_tx
                    .send(StorageCommand::IngestEnvelope(EnvelopeState::Intact(
                        env.clone(),
                    )))
                    .await;
            }
        }
    });

    // 4. Run Coordinator
    let mut coordinator = PlaybackCoordinator::new(
        storage_tx.clone(),
        None,
        VideoPlayerSink::new(ui_tx),
        disc_tx,
    );
    let v_id_clone = volley_id.clone();
    tokio::spawn(async move {
        let _ = coordinator.run(v_id_clone).await;
    });

    // 5. Assert 1..10 in order
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        for i in 1..=10 {
            let frame = ui_rx.recv().await.unwrap();
            assert_eq!(frame, format!("Frame {}", i).into_bytes());
        }
    })
    .await;

    assert!(
        result.is_ok(),
        "Chaos test timed out - chain probably broke"
    );
}
