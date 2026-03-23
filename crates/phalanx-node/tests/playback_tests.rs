use tempfile::tempdir;
use tokio::sync::mpsc;

use phalanx_forensics::crucible::EnvelopeHashExt;
use phalanx_forensics::witness::WitnessAuthority;
use phalanx_node::actors::egress::EgressCommand;
use phalanx_node::actors::playback::PlaybackCoordinator;
use phalanx_node::actors::storage::StorageCommand;
use phalanx_node::config::NodeConfig;
use phalanx_node::identity::PhalanxNodeIdentityExt;
use phalanx_node::persistence::vault::{derive_vault_key, Guardian};
use phalanx_node::playback::sink::{ArtifactSink, VideoPlayerSink};
use phalanx_proto::evidence::{
    DataPayload, EnvelopeState, Evidence, ForensicMetrics, StorageSequence, VideoShard,
    WitnessEnvelope,
};
use phalanx_proto::identity::{NetworkId, PhalanxIdentity, RecordingId};
use phalanx_proto::playback::PlaybackSink;
use phalanx_proto::time::{SystemClock, TrustedClock};
use phalanx_proto::types::Fps;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn test_exodus_resurrection_logic() {
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let vault_path = temp_dir.path().to_string_lossy().to_string();

    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let config = NodeConfig::default();

    let (storage_tx, mut storage_rx) = mpsc::channel::<StorageCommand>(100);
    let (disc_tx, mut disc_rx) = mpsc::channel(1);
    let (ui_tx, mut ui_rx) = mpsc::channel(10);

    let vault_key = derive_vault_key(&identity, &[0u8; 32]);
    let identity_clone = identity.clone();
    tokio::spawn(async move {
        let mut guardian = Guardian::new(
            &vault_path,
            &config,
            identity_clone.did,
            Arc::new(SystemClock),
            vault_key,
        );
        while let Some(cmd) = storage_rx.recv().await {
            match cmd {
                StorageCommand::GetShard {
                    recording_id,
                    sequence_id,
                    reply_to,
                } => {
                    let _ = reply_to.send(guardian.get_shard(&recording_id, sequence_id));
                }
                StorageCommand::IngestEnvelope {
                    state,
                    reply_to,
                    ttl,
                } => {
                    let result = guardian.ingest_envelope(state, ttl).await;
                    if let Err(ref e) = result {
                        tracing::error!("Test Actor Ingestion Reject: {:?}", e);
                    }
                    let _ = reply_to.send(result);
                }
                _ => {
                    tracing::debug!("Mock StorageActor ignored unsupported command");
                }
            }
        }
    });

    let video_sink = VideoPlayerSink::new(ui_tx);
    let (audio_ui_tx, _audio_ui_rx) = mpsc::channel(10);
    let audio_sink = VideoPlayerSink::new(audio_ui_tx);
    let recording_id = RecordingId::new("v_exodus_test");
    let (egress_tx, _egress_rx) = mpsc::channel::<EgressCommand>(10);
    let (_providers_tx, providers_rx) = mpsc::channel(1);
    let mut coordinator = PlaybackCoordinator::new(
        storage_tx.clone(),
        egress_tx,
        None,
        video_sink,
        audio_sink,
        disc_tx,
        providers_rx,
        Arc::new(identity.clone()),
    );

    let shard_1 = VideoShard {
        timestamp: SystemClock.now(),
        sequence_id: StorageSequence(1),
        fps: Fps::new(30),
        recording_id: recording_id.clone(),
        payload: DataPayload::Clear(b"Frame 1".to_vec()),
        lens_metrics: ForensicMetrics::default(),
    };
    let envelope_1 = WitnessEnvelope::sign_envelope(
        Evidence::Video(shard_1),
        &identity,
        NetworkId::random(),
        None,
    )
    .unwrap();
    let hash_1 = envelope_1.signature_hash();

    let (tx, rx) = tokio::sync::oneshot::channel();
    storage_tx
        .send(StorageCommand::IngestEnvelope {
            state: EnvelopeState::Intact(envelope_1),
            reply_to: tx,
            ttl: Duration::from_secs(1),
        })
        .await
        .unwrap();
    rx.await.unwrap().unwrap();

    let v_id_clone = recording_id.clone();
    let _handle = tokio::spawn(async move {
        coordinator.run(v_id_clone).await.unwrap();
    });

    let frame = ui_rx.recv().await.expect("Should receive Frame 1");
    assert_eq!(frame, b"Frame 1");

    let (recording_id, missing_id) = disc_rx
        .recv()
        .await
        .expect("Should signal discovery for Shard 2");
    assert_eq!(missing_id, StorageSequence(2));

    let shard_2 = VideoShard {
        timestamp: SystemClock.now(),
        sequence_id: StorageSequence(2),
        fps: Fps::new(30),
        recording_id: recording_id.clone(),
        payload: DataPayload::Clear(b"Frame 2".to_vec()),
        lens_metrics: ForensicMetrics::default(),
    };
    let envelope_2 = WitnessEnvelope::sign_envelope(
        Evidence::Video(shard_2),
        &identity,
        NetworkId::random(),
        Some(hash_1),
    )
    .unwrap();

    let (tx2, rx2) = tokio::sync::oneshot::channel();
    storage_tx
        .send(StorageCommand::IngestEnvelope {
            state: EnvelopeState::Intact(envelope_2),
            reply_to: tx2,
            ttl: Duration::from_secs(1),
        })
        .await
        .unwrap();
    rx2.await.unwrap().unwrap();

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
    let (disc_tx, mut disc_rx) = mpsc::channel::<(RecordingId, StorageSequence)>(100);
    let (ui_tx, mut ui_rx) = mpsc::channel(10);

    let vault_key = derive_vault_key(&identity, &[0u8; 32]);
    let identity_clone = identity.clone();
    tokio::spawn(async move {
        let mut guardian = Guardian::new(
            &vault_path,
            &config,
            identity_clone.did,
            Arc::new(SystemClock),
            vault_key,
        );
        while let Some(cmd) = storage_rx.recv().await {
            match cmd {
                StorageCommand::GetShard {
                    recording_id,
                    sequence_id,
                    reply_to,
                } => {
                    let _ = reply_to.send(guardian.get_shard(&recording_id, sequence_id));
                }
                StorageCommand::IngestEnvelope {
                    state,
                    reply_to,
                    ttl,
                } => {
                    let result = guardian.ingest_envelope(state, ttl).await;
                    if let Err(ref e) = result {
                        tracing::error!("Test Ingestion Error: {:?}", e);
                    }
                    let _ = reply_to.send(result);
                }
                _ => {}
            }
        }
    });

    let video_sink = VideoPlayerSink::new(ui_tx);
    let (audio_ui_tx, _audio_ui_rx) = mpsc::channel(10);
    let audio_sink = VideoPlayerSink::new(audio_ui_tx);
    let recording_id = RecordingId::new("v_resurrection");
    let (egress_tx, _egress_rx) = mpsc::channel::<EgressCommand>(10);
    let (_providers_tx, providers_rx) = mpsc::channel(1);
    let mut coordinator = PlaybackCoordinator::new(
        storage_tx.clone(),
        egress_tx,
        None,
        video_sink,
        audio_sink,
        disc_tx,
        providers_rx,
        Arc::new(identity.clone()),
    );

    let shard_1 = VideoShard {
        timestamp: SystemClock.now(),
        sequence_id: StorageSequence(1),
        fps: Fps::new(30),
        recording_id: recording_id.clone(),
        payload: DataPayload::Clear(b"Frame 1 Data".to_vec()),
        lens_metrics: ForensicMetrics::default(),
    };
    let envelope_1 = WitnessEnvelope::sign_envelope(
        Evidence::Video(shard_1),
        &identity,
        NetworkId::random(),
        None,
    )
    .unwrap();
    let hash_1 = envelope_1.signature_hash();

    let (tx, rx) = tokio::sync::oneshot::channel();
    storage_tx
        .send(StorageCommand::IngestEnvelope {
            state: EnvelopeState::Intact(envelope_1),
            reply_to: tx,
            ttl: Duration::from_secs(1),
        })
        .await
        .unwrap();
    rx.await.unwrap().unwrap();

    let v_id_clone = recording_id.clone();
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
        timestamp: SystemClock.now(),
        sequence_id: StorageSequence(2),
        fps: Fps::new(30),
        recording_id: _v_id,
        payload: DataPayload::Clear(b"Frame 2 Data".to_vec()),
        lens_metrics: ForensicMetrics::default(),
    };
    let envelope_2 = WitnessEnvelope::sign_envelope(
        Evidence::Video(shard_2),
        &identity,
        NetworkId::random(),
        Some(hash_1),
    )
    .unwrap();
    let (tx2, rx2) = tokio::sync::oneshot::channel();
    storage_tx
        .send(StorageCommand::IngestEnvelope {
            state: EnvelopeState::Intact(envelope_2),
            reply_to: tx2,
            ttl: Duration::from_secs(1),
        })
        .await
        .unwrap();
    rx2.await.unwrap().unwrap();

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
    let (disc_tx, mut disc_rx) = mpsc::channel::<(RecordingId, StorageSequence)>(100);
    let (ui_tx, mut ui_rx) = mpsc::channel(100);

    let vault_key = derive_vault_key(&identity, &[0u8; 32]);
    tokio::spawn(async move {
        let mut guardian = Guardian::new(
            &vault_path,
            &config,
            identity.did,
            Arc::new(SystemClock),
            vault_key,
        );
        while let Some(cmd) = storage_rx.recv().await {
            match cmd {
                StorageCommand::GetShard {
                    recording_id,
                    sequence_id,
                    reply_to,
                } => {
                    let _ = reply_to.send(guardian.get_shard(&recording_id, sequence_id));
                }
                StorageCommand::IngestEnvelope {
                    state,
                    reply_to,
                    ttl,
                } => {
                    let result = guardian.ingest_envelope(state, ttl).await;
                    let _ = reply_to.send(result);
                }
                _ => {}
            }
        }
    });

    let (identity_main, _) = PhalanxIdentity::generate().unwrap();
    let recording_id = RecordingId::new("v_chaos_monkey");

    let mut chain = std::collections::HashMap::new();
    let mut last_hash = None;

    for i in 1..=10 {
        let shard = VideoShard {
            timestamp: SystemClock.now(),
            sequence_id: StorageSequence(i),
            fps: Fps::new(30),
            recording_id: recording_id.clone(),
            payload: DataPayload::Clear(format!("Frame {}", i).into_bytes()),
            lens_metrics: ForensicMetrics::default(),
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

    let (tx1, rx1) = tokio::sync::oneshot::channel();
    storage_tx
        .send(StorageCommand::IngestEnvelope {
            state: EnvelopeState::Intact(chain.get(&1).unwrap().clone()),
            reply_to: tx1,
            ttl: Duration::from_secs(1),
        })
        .await
        .unwrap();
    rx1.await.unwrap().unwrap();

    let (tx10, rx10) = tokio::sync::oneshot::channel();
    storage_tx
        .send(StorageCommand::IngestEnvelope {
            state: EnvelopeState::Intact(chain.get(&10).unwrap().clone()),
            reply_to: tx10,
            ttl: Duration::from_secs(1),
        })
        .await
        .unwrap();
    rx10.await.unwrap().unwrap();

    let chaos_storage_tx = storage_tx.clone();
    tokio::spawn(async move {
        while let Some((_, missing_seq)) = disc_rx.recv().await {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            if let Some(env) = chain.get(&missing_seq.0) {
                let (tx, _) = tokio::sync::oneshot::channel();
                let _ = chaos_storage_tx
                    .send(StorageCommand::IngestEnvelope {
                        state: EnvelopeState::Intact(env.clone()),
                        reply_to: tx,
                        ttl: Duration::from_secs(1),
                    })
                    .await;
            }
        }
    });

    let (egress_tx, _egress_rx) = mpsc::channel::<EgressCommand>(10);
    let (_providers_tx, providers_rx) = mpsc::channel(1);
    let (audio_ui_tx, _audio_ui_rx) = mpsc::channel(100);
    let mut coordinator = PlaybackCoordinator::new(
        storage_tx.clone(),
        egress_tx,
        None,
        VideoPlayerSink::new(ui_tx),
        VideoPlayerSink::new(audio_ui_tx),
        disc_tx,
        providers_rx,
        Arc::new(identity_main.clone()),
    );
    let v_id_clone = recording_id.clone();
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

#[tokio::test]
async fn test_artifact_sink_unsigned_export() {
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let output_path = temp_dir.path().join("export.mp4");

    let mut sink = ArtifactSink::new(
        output_path.clone(),
        "test-node-001".to_string(),
        ForensicMetrics::default(),
        None,
        None,
    );

    // Feed three chunks
    sink.handle_chunk(StorageSequence(1), b"chunk-one-".to_vec())
        .await
        .unwrap();
    sink.handle_chunk(StorageSequence(2), b"chunk-two-".to_vec())
        .await
        .unwrap();
    sink.handle_chunk(StorageSequence(3), b"chunk-three".to_vec())
        .await
        .unwrap();

    sink.finalize().await.unwrap();

    let contents = tokio::fs::read(&output_path).await.unwrap();
    assert_eq!(contents, b"chunk-one-chunk-two-chunk-three");
}

#[tokio::test]
async fn test_artifact_sink_empty_finalize() {
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let output_path = temp_dir.path().join("empty.mp4");

    let mut sink = ArtifactSink::new(
        output_path.clone(),
        "test-node-empty".to_string(),
        ForensicMetrics::default(),
        None,
        None,
    );

    // Finalize with no chunks — should produce an empty file
    sink.finalize().await.unwrap();

    let contents = tokio::fs::read(&output_path).await.unwrap();
    assert!(contents.is_empty());
}
