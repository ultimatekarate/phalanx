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
async fn test_playback_resurrection_with_mesh_gap() {
    // 1. Setup our "Safe Room" components using actual physical paths
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let vault_path = temp_dir.path().to_string_lossy().to_string();

    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let config = PhalanxConfig::default();

    // 2. Setup Actor Mailboxes
    let (storage_tx, mut storage_rx) = mpsc::channel::<StorageCommand>(100);
    let (disc_tx, mut disc_rx) = mpsc::channel(1);
    let (ui_tx, mut ui_rx) = mpsc::channel(10);

    // 3. Spawn the Storage Actor (Holds exclusive ownership of the Guardian)
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
                    let shard = guardian.get_shard(&volley_id, sequence_id);
                    let _ = reply_to.send(shard);
                }
                StorageCommand::IngestEnvelope(state) => {
                    guardian
                        .ingest_envelope(state)
                        .await
                        .expect("Vault rejected explicit envelope");
                }
                _ => {
                    tracing::debug!("Mock StorageActor ignored unsupported command");
                }
            }
        }
    });

    // 4. Initialize the Coordinator with the Storage Mailbox
    let sink = VideoPlayerSink::new(ui_tx);
    let volley_id = VolleyId::new("v_resurrection");

    let mut coordinator = PlaybackCoordinator::new(
        storage_tx.clone(),
        None, // No SymmetricKey for Clear payloads
        sink,
        disc_tx,
    );

    // 5. Scenario: Shard 1 arrived via Gossip before Node A died.
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
    .expect("WitnessEnvelope construction failed");

    let state_1 = EnvelopeState::Intact(envelope_1);

    // Send ingestion command to the Storage Actor
    storage_tx
        .send(StorageCommand::IngestEnvelope(state_1))
        .await
        .unwrap();

    // 6. Start the Playback Brain
    let v_id_clone = volley_id.clone();
    let _handle = tokio::spawn(async move {
        coordinator.run(v_id_clone).await.unwrap();
    });

    // 7. Verification: Frame 1 plays instantly (JIT Decrypted/Extracted)
    let frame_1 = ui_rx
        .recv()
        .await
        .expect("Playback should start with Frame 1");
    assert_eq!(frame_1, b"Frame 1 Data");

    // 8. Verification: Gap Detection
    let (volley_id_2, missing_seq) = disc_rx
        .recv()
        .await
        .expect("Coordinator should signal for Shard 2");
    assert_eq!(missing_seq, StorageSequence(2));

    // 9. Scenario: Mesh heals. Shard 2 is retrieved from Node C.
    let shard_2 = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(2),
        fps: 30,
        volley_id: volley_id_2.clone(),
        payload: DataPayload::Clear(b"Frame 2 Data".to_vec()),
    };

    let envelope_2 = WitnessEnvelope::new(
        Evidence::Video(shard_2),
        &identity,
        NetworkId::random(),
        None,
    )
    .expect("WitnessEnvelope construction failed");

    let state_2 = EnvelopeState::Intact(envelope_2);

    // Send second ingestion command to the Storage Actor
    storage_tx
        .send(StorageCommand::IngestEnvelope(state_2))
        .await
        .unwrap();

    // 10. Verification: Playback resumes automatically
    let frame_2 = ui_rx
        .recv()
        .await
        .expect("Playback should resume with Frame 2");
    assert_eq!(frame_2, b"Frame 2 Data");
}

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
                    guardian.ingest_envelope(state).await.unwrap();
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
        None,
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
