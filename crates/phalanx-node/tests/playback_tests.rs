use tempfile::tempdir;
use tokio::sync::mpsc;

use phalanx_forensics::crucible::EnvelopeHashExt;
use phalanx_forensics::witness::WitnessAuthority;
use phalanx_node::actors::playback::PlaybackCoordinator;
use phalanx_node::actors::storage::StorageCommand;
use phalanx_node::config::NodeConfig;
use phalanx_node::identity::PhalanxNodeIdentityExt;
use phalanx_node::persistence::vault::Guardian;
use phalanx_node::playback::sink::VideoPlayerSink;
use phalanx_proto::evidence::{
    DataPayload, EnvelopeState, Evidence, StorageSequence, VideoShard, WitnessEnvelope,
};
use phalanx_proto::identity::{NetworkId, PhalanxIdentity, VolleyId};
use phalanx_proto::time::PhalanxTimestamp;

#[tokio::test]
async fn test_exodus_resurrection_logic() {
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let vault_path = temp_dir.path().to_string_lossy().to_string();

    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let config = NodeConfig::default();

    let (storage_tx, mut storage_rx) = mpsc::channel::<StorageCommand>(100);
    let (disc_tx, mut disc_rx) = mpsc::channel(1);
    let (ui_tx, mut ui_rx) = mpsc::channel(10);

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

    let shard_1 = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(1),
        fps: 30,
        volley_id: volley_id.clone(),
        payload: DataPayload::Clear(b"Frame 1".to_vec()),
    };
    let envelope_1 = WitnessEnvelope::sign_envelope(
        Evidence::Video(shard_1),
        &identity,
        NetworkId::random(),
        None,
    )
    .unwrap();
    let hash_1 = envelope_1.signature_hash();

    storage_tx
        .send(StorageCommand::IngestEnvelope(EnvelopeState::Intact(
            envelope_1,
        )))
        .await
        .unwrap();

    let v_id_clone = volley_id.clone();
    let _handle = tokio::spawn(async move {
        coordinator.run(v_id_clone).await.unwrap();
    });

    let frame = ui_rx.recv().await.expect("Should receive Frame 1");
    assert_eq!(frame, b"Frame 1");

    let (volley_id, missing_id) = disc_rx
        .recv()
        .await
        .expect("Should signal discovery for Shard 2");
    assert_eq!(missing_id, StorageSequence(2));

    let shard_2 = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(2),
        fps: 30,
        volley_id: volley_id.clone(),
        payload: DataPayload::Clear(b"Frame 2".to_vec()),
    };
    let envelope_2 = WitnessEnvelope::sign_envelope(
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

    let frame_2 = ui_rx.recv().await.expect("Should receive Frame 2");
    assert_eq!(frame_2, b"Frame 2");
}

#[tokio::test]
async fn test_playback_resurrection_with_mesh_gap() {
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let vault_path = temp_dir.path().to_string_lossy().to_string();
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let config = NodeConfig::default();

    let (storage_tx, mut storage_rx) = mpsc::channel::<StorageCommand>(100);
    let (disc_tx, mut disc_rx) = mpsc::channel::<(VolleyId, StorageSequence)>(100);
    let (ui_tx, mut ui_rx) = mpsc::channel(10);

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

    let shard_1 = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(1),
        fps: 30,
        volley_id: volley_id.clone(),
        payload: DataPayload::Clear(b"Frame 1 Data".to_vec()),
    };
    let envelope_1 = WitnessEnvelope::sign_envelope(
        Evidence::Video(shard_1),
        &identity,
        NetworkId::random(),
        None,
    )
    .unwrap();
    let hash_1 = envelope_1.signature_hash();

    storage_tx
        .send(StorageCommand::IngestEnvelope(EnvelopeState::Intact(
            envelope_1,
        )))
        .await
        .unwrap();

    let v_id_clone = volley_id.clone();
    tokio::spawn(async move {
        let _ = coordinator.run(v_id_clone).await;
    });

    let frame_1 = ui_rx
        .recv()
        .await
        .expect("Playback should start with Frame 1");
    assert_eq!(frame_1, b"Frame 1 Data");

    let (_v_id, missing_seq) = disc_rx.recv().await.expect("Should signal for Shard 2");
    assert_eq!(missing_seq, StorageSequence(2));

    let shard_2 = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(2),
        fps: 30,
        volley_id: _v_id,
        payload: DataPayload::Clear(b"Frame 2 Data".to_vec()),
    };
    let envelope_2 = WitnessEnvelope::sign_envelope(
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
    let config = NodeConfig::default();

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
        let envelope = WitnessEnvelope::sign_envelope(
            Evidence::Video(shard),
            &identity_main,
            NetworkId::random(),
            last_hash,
        )
        .unwrap();
        last_hash = Some(envelope.signature_hash());
        chain.insert(i, envelope);
    }

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
