#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
use tempfile::tempdir;

/// Strip the 8-byte LE timestamp prefix that the coordinator prepends to video frames.
/// Audio frames are NOT prefixed — only use this for video channel assertions.
fn video_payload(frame: &[u8]) -> &[u8] {
    &frame[8..]
}
use tokio::sync::mpsc;

use phalanx_forensics::crucible::EnvelopeHashExt;
use phalanx_forensics::reassembler::{create_audio_shard, create_video_shard};
use phalanx_forensics::witness::WitnessAuthority;
use phalanx_forensics::PayloadCipher;
use phalanx_node::actors::egress::EgressCommand;
use phalanx_node::actors::playback::PlaybackCoordinator;
use phalanx_node::actors::storage::StorageCommand;
use phalanx_node::config::NodeConfig;
use phalanx_node::identity::PhalanxNodeIdentityExt;
use phalanx_node::persistence::vault::{derive_vault_key, Guardian};
use phalanx_node::playback::sink::{ArtifactSink, VideoPlayerSink};
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::{
    DataPayload, EnvelopeState, Evidence, ForensicMetrics, StorageSequence, VideoShard,
    WitnessEnvelope,
};
use phalanx_proto::identity::{NetworkId, PhalanxIdentity, RecordingId};
use phalanx_proto::playback::PlaybackSink;
use phalanx_proto::time::{PhalanxTimestamp, SystemClock, TrustedClock};
use phalanx_proto::types::{ChannelCount, Fps, SampleRate};
use std::sync::Arc;
use std::time::Duration;

// ═══════════════════════════════════════════════════════════════════════
// HELPERS — reduce boilerplate across production-format tests
// ═══════════════════════════════════════════════════════════════════════

/// Spawn a Guardian task that handles WriteShard + GetShard via the real disk path.
/// This exercises the production storage AEAD layer (encrypt on write, decrypt on read).
fn spawn_disk_guardian_actor(
    identity: &PhalanxIdentity,
    vault_path: String,
) -> mpsc::Sender<StorageCommand> {
    let (storage_tx, mut storage_rx) = mpsc::channel::<StorageCommand>(100);
    let config = NodeConfig::default();
    let vault_key = derive_vault_key(identity, &[0u8; 32]);
    let did = identity.did.clone();
    tokio::spawn(async move {
        let mut guardian =
            Guardian::new(&vault_path, &config, did, Arc::new(SystemClock), vault_key);
        while let Some(cmd) = storage_rx.recv().await {
            match cmd {
                StorageCommand::WriteShard { envelope, reply_to } => {
                    let result = guardian.append_shard(&envelope).await;
                    let _ = reply_to.send(result);
                }
                StorageCommand::GetShard {
                    recording_id,
                    sequence_id,
                    reply_to,
                } => {
                    let result = guardian
                        .read_shard(&recording_id, sequence_id, None)
                        .await
                        .ok();
                    let _ = reply_to.send(result);
                }
                StorageCommand::GetContentKey {
                    recording_id,
                    reply_to,
                } => {
                    let key = guardian
                        .get_content_key(&recording_id)
                        .map(|k| *k.as_bytes());
                    let _ = reply_to.send(key);
                }
                StorageCommand::StartRecording {
                    recording_id,
                    reply_to,
                } => {
                    let key = guardian.generate_content_key(&recording_id);
                    let _ = guardian.persist_keyring().await;
                    let _ = reply_to.send(Ok(*key.as_bytes()));
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
    storage_tx
}

/// Write a shard through the production disk path (WriteShard → append_shard → storage AEAD).
async fn write_shard(storage_tx: &mpsc::Sender<StorageCommand>, envelope: WitnessEnvelope) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    storage_tx
        .send(StorageCommand::WriteShard {
            envelope,
            reply_to: tx,
        })
        .await
        .unwrap();
    rx.await.unwrap().unwrap();
}

/// Create a production-format video envelope:
/// create_video_shard(frames) → apply_encryption(key) → sign_envelope.
/// Returns (envelope, signature_hash) for chaining.
fn make_video_envelope(
    frames: Vec<Vec<u8>>,
    seq: u32,
    recording_id: &RecordingId,
    key: &SymmetricKey,
    identity: &PhalanxIdentity,
    prev_hash: Option<phalanx_proto::evidence::SignatureHash>,
) -> (WitnessEnvelope, phalanx_proto::evidence::SignatureHash) {
    let mut shard = create_video_shard(
        frames,
        StorageSequence(seq),
        Fps::new(30),
        recording_id.clone(),
        ForensicMetrics::default(),
        PhalanxTimestamp::from_millis(1_700_000_000_000 + u64::from(seq) * 33),
    )
    .unwrap();
    shard
        .payload
        .apply_encryption(key)
        .expect("Encryption must succeed");

    let envelope = WitnessEnvelope::sign_envelope(
        Evidence::Video(shard),
        identity,
        NetworkId::random(),
        prev_hash,
    )
    .unwrap();
    let hash = envelope.signature_hash();
    (envelope, hash)
}

/// Create a production-format audio envelope:
/// create_audio_shard(data) → apply_encryption(key) → sign_envelope.
fn make_audio_envelope(
    data: Vec<u8>,
    seq: u32,
    recording_id: &RecordingId,
    key: &SymmetricKey,
    identity: &PhalanxIdentity,
    prev_hash: Option<phalanx_proto::evidence::SignatureHash>,
) -> (WitnessEnvelope, phalanx_proto::evidence::SignatureHash) {
    let mut shard = create_audio_shard(
        data,
        StorageSequence(seq),
        SampleRate::new(16000),
        ChannelCount::new(1),
        recording_id.clone(),
        PhalanxTimestamp::from_millis(1_700_000_000_000 + u64::from(seq) * 33),
    )
    .unwrap();
    shard
        .payload
        .apply_encryption(key)
        .expect("Encryption must succeed");

    let envelope = WitnessEnvelope::sign_envelope(
        Evidence::Audio(shard),
        identity,
        NetworkId::random(),
        prev_hash,
    )
    .unwrap();
    let hash = envelope.signature_hash();
    (envelope, hash)
}

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
    assert_eq!(video_payload(&frame), b"Frame 1");

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
    assert_eq!(video_payload(&frame_2), b"Frame 2");
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
    assert_eq!(video_payload(&frame_1), b"Frame 1 Data");

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
    assert_eq!(video_payload(&frame_2), b"Frame 2 Data");
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
            assert_eq!(video_payload(&frame), format!("Frame {}", i).into_bytes());
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

/// Round-trip test: compress → encrypt → ingest → playback (decode_payload decrypts + decompresses).
/// This test would have caught the original split-brain bug where playback returned raw ciphertext.
#[tokio::test]
async fn test_encrypted_playback_round_trip() {
    use phalanx_forensics::reassembler::compress_payload;
    use phalanx_forensics::PayloadCipher;

    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let vault_path = temp_dir.path().to_string_lossy().to_string();

    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let config = NodeConfig::default();

    let (storage_tx, mut storage_rx) = mpsc::channel::<StorageCommand>(100);
    let (disc_tx, _disc_rx) = mpsc::channel(1);
    let (ui_tx, mut ui_rx) = mpsc::channel(10);

    let vault_key = derive_vault_key(&identity, &[0u8; 32]);
    let session_key = phalanx_forensics::generate_session_key();

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
                    let _ = reply_to.send(result);
                }
                _ => {}
            }
        }
    });

    let recording_id = RecordingId::new("v_encrypted_test");
    let original_data = b"JPEG frame payload for encryption test";

    // Production pipeline: compress → encrypt
    let compressed = compress_payload(original_data);
    let mut payload = DataPayload::Compressed(compressed);
    payload
        .apply_encryption(&session_key)
        .expect("Encryption must succeed");

    // Payload is now DataPayload::Encrypted { nonce, ciphertext }
    assert!(matches!(payload, DataPayload::Encrypted { .. }));

    let shard = VideoShard {
        timestamp: SystemClock.now(),
        sequence_id: StorageSequence(1),
        fps: Fps::new(30),
        recording_id: recording_id.clone(),
        payload,
        lens_metrics: ForensicMetrics::default(),
    };

    let envelope = WitnessEnvelope::sign_envelope(
        Evidence::Video(shard),
        &identity,
        NetworkId::random(),
        None,
    )
    .unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();
    storage_tx
        .send(StorageCommand::IngestEnvelope {
            state: EnvelopeState::Intact(envelope),
            reply_to: tx,
            ttl: Duration::from_secs(1),
        })
        .await
        .unwrap();
    rx.await.unwrap().unwrap();

    // Create coordinator WITH the decryption key
    let video_sink = VideoPlayerSink::new(ui_tx);
    let (audio_ui_tx, _audio_ui_rx) = mpsc::channel(10);
    let audio_sink = VideoPlayerSink::new(audio_ui_tx);
    let (egress_tx, _egress_rx) = mpsc::channel::<EgressCommand>(10);
    let (_providers_tx, providers_rx) = mpsc::channel(1);

    let mut coordinator = PlaybackCoordinator::new(
        storage_tx.clone(),
        egress_tx,
        Some(session_key),
        video_sink,
        audio_sink,
        disc_tx,
        providers_rx,
        Arc::new(identity.clone()),
    );

    let v_id_clone = recording_id.clone();
    let _handle = tokio::spawn(async move {
        coordinator.run(v_id_clone).await.unwrap();
    });

    // The coordinator should decrypt + decompress and deliver the original cleartext
    let frame = ui_rx.recv().await.expect("Should receive decrypted frame");
    assert_eq!(
        video_payload(&frame),
        original_data,
        "Decrypted playback must match original cleartext"
    );
}

/// Verify that playback with the wrong key produces an error, not raw ciphertext.
#[tokio::test]
async fn test_encrypted_playback_wrong_key_fails() {
    use phalanx_forensics::reassembler::compress_payload;
    use phalanx_forensics::PayloadCipher;

    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let vault_path = temp_dir.path().to_string_lossy().to_string();

    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let config = NodeConfig::default();

    let (storage_tx, mut storage_rx) = mpsc::channel::<StorageCommand>(100);
    let (disc_tx, _disc_rx) = mpsc::channel(1);
    let (ui_tx, mut ui_rx) = mpsc::channel(10);

    let vault_key = derive_vault_key(&identity, &[0u8; 32]);
    let correct_key = phalanx_forensics::generate_session_key();
    let wrong_key = SymmetricKey([0xBB; 32]);

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
                    let _ = reply_to.send(result);
                }
                _ => {}
            }
        }
    });

    let recording_id = RecordingId::new("v_wrong_key_test");
    let compressed = compress_payload(b"secret data");
    let mut payload = DataPayload::Compressed(compressed);
    payload
        .apply_encryption(&correct_key)
        .expect("Encryption must succeed");

    let shard = VideoShard {
        timestamp: SystemClock.now(),
        sequence_id: StorageSequence(1),
        fps: Fps::new(30),
        recording_id: recording_id.clone(),
        payload,
        lens_metrics: ForensicMetrics::default(),
    };

    let envelope = WitnessEnvelope::sign_envelope(
        Evidence::Video(shard),
        &identity,
        NetworkId::random(),
        None,
    )
    .unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();
    storage_tx
        .send(StorageCommand::IngestEnvelope {
            state: EnvelopeState::Intact(envelope),
            reply_to: tx,
            ttl: Duration::from_secs(1),
        })
        .await
        .unwrap();
    rx.await.unwrap().unwrap();

    // Create coordinator with the WRONG key
    let video_sink = VideoPlayerSink::new(ui_tx);
    let (audio_ui_tx, _audio_ui_rx) = mpsc::channel(10);
    let audio_sink = VideoPlayerSink::new(audio_ui_tx);
    let (egress_tx, _egress_rx) = mpsc::channel::<EgressCommand>(10);
    let (_providers_tx, providers_rx) = mpsc::channel(1);

    let mut coordinator = PlaybackCoordinator::new(
        storage_tx.clone(),
        egress_tx,
        Some(wrong_key),
        video_sink,
        audio_sink,
        disc_tx,
        providers_rx,
        Arc::new(identity.clone()),
    );

    let v_id_clone = recording_id.clone();
    let handle = tokio::spawn(async move { coordinator.run(v_id_clone).await });

    // With the wrong key, decode_payload should return an AEAD error.
    // The coordinator now skips failed frames (continue, not ?), so it
    // won't crash — but it should never deliver ciphertext to the sink.
    let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
    match result {
        Ok(Ok(Err(_))) => {} // Expected: run() returns a decode error
        Ok(Err(_)) => panic!("Task panicked"),
        Ok(Ok(Ok(_stats))) => {
            // Coordinator finished (gap-skip terminated it) — verify no frames leaked
            assert!(
                ui_rx.try_recv().is_err(),
                "Wrong key must NOT deliver ciphertext to the sink"
            );
        }
        Err(_) => {
            // Timeout — check that no frame was delivered
            assert!(
                ui_rx.try_recv().is_err(),
                "Wrong key must NOT deliver ciphertext to the sink"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// PRODUCTION-FORMAT TESTS — exercise the real capture→playback pipeline
// ═══════════════════════════════════════════════════════════════════════
//
// These tests use create_video_shard() (postcard serialization + LZ4 compression)
// followed by apply_encryption(), matching the exact format produced by the
// capture pipeline. The existing tests above use DataPayload::Clear or manually
// compressed raw bytes, which bypass the postcard Vec<Vec<u8>> deserialization
// step in the PlaybackCoordinator.

/// Test 1: Full production pipeline with a single JPEG frame through disk storage.
///
/// Pipeline: create_video_shard(vec![jpeg]) → encrypt → sign → WriteShard (disk AEAD)
///   → PlaybackCoordinator → GetShard (disk AEAD) → decode_payload → postcard deser → sink
///
/// This is the test that was missing. If decode_payload fails, the coordinator
/// skips the frame and ui_rx gets nothing. If postcard deser is broken, we get
/// the serialized blob instead of the JPEG.
#[tokio::test]
async fn test_production_format_encrypted_round_trip() {
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let vault_path = temp_dir.path().to_string_lossy().to_string();
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let session_key = phalanx_forensics::generate_session_key();

    let storage_tx = spawn_disk_guardian_actor(&identity, vault_path);
    let recording_id = RecordingId::new("v_prod_format_1");

    // Fake JPEG — starts with JPEG SOI marker for realism
    let jpeg_frame = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46];

    let (envelope, _hash) = make_video_envelope(
        vec![jpeg_frame.clone()],
        1,
        &recording_id,
        &session_key,
        &identity,
        None,
    );

    // Ensure the payload is actually encrypted (not Clear)
    assert!(
        matches!(envelope.evidence, Evidence::Video(ref v) if matches!(v.payload, DataPayload::Encrypted { .. })),
        "Payload must be Encrypted after apply_encryption"
    );

    write_shard(&storage_tx, envelope).await;

    // Set up coordinator with matching decryption key
    let (ui_tx, mut ui_rx) = mpsc::channel(10);
    let (audio_tx, _audio_rx) = mpsc::channel(10);
    let (disc_tx, _disc_rx) = mpsc::channel(1);
    let (egress_tx, _egress_rx) = mpsc::channel::<EgressCommand>(10);
    let (_providers_tx, providers_rx) = mpsc::channel(1);

    let mut coordinator = PlaybackCoordinator::new(
        storage_tx.clone(),
        egress_tx,
        Some(session_key),
        VideoPlayerSink::new(ui_tx),
        VideoPlayerSink::new(audio_tx),
        disc_tx,
        providers_rx,
        Arc::new(identity),
    );

    let rid = recording_id.clone();
    tokio::spawn(async move {
        let _ = coordinator.run(rid).await;
    });

    let frame = tokio::time::timeout(Duration::from_secs(3), ui_rx.recv())
        .await
        .expect("Timed out waiting for frame")
        .expect("Channel closed without delivering frame");

    assert_eq!(
        video_payload(&frame),
        jpeg_frame,
        "Playback must deliver the original JPEG bytes, not the postcard/compressed/encrypted blob"
    );
}

/// Test 2: Multi-frame video shard — Vec<Vec<u8>> with 3 JPEGs.
///
/// The coordinator must postcard-deserialize the payload and send each JPEG
/// as a separate handle_chunk call. If postcard deser fails (fallback path),
/// the sink gets 1 blob instead of 3 individual frames.
#[tokio::test]
async fn test_production_format_multi_frame_shard() {
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let vault_path = temp_dir.path().to_string_lossy().to_string();
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let session_key = phalanx_forensics::generate_session_key();

    let storage_tx = spawn_disk_guardian_actor(&identity, vault_path);
    let recording_id = RecordingId::new("v_multi_frame");

    let jpeg_a = vec![0xFF, 0xD8, 0x01, 0xAA];
    let jpeg_b = vec![0xFF, 0xD8, 0x02, 0xBB];
    let jpeg_c = vec![0xFF, 0xD8, 0x03, 0xCC];

    let (envelope, _hash) = make_video_envelope(
        vec![jpeg_a.clone(), jpeg_b.clone(), jpeg_c.clone()],
        1,
        &recording_id,
        &session_key,
        &identity,
        None,
    );

    write_shard(&storage_tx, envelope).await;

    let (ui_tx, mut ui_rx) = mpsc::channel(10);
    let (audio_tx, _audio_rx) = mpsc::channel(10);
    let (disc_tx, _disc_rx) = mpsc::channel(1);
    let (egress_tx, _egress_rx) = mpsc::channel::<EgressCommand>(10);
    let (_providers_tx, providers_rx) = mpsc::channel(1);

    let mut coordinator = PlaybackCoordinator::new(
        storage_tx.clone(),
        egress_tx,
        Some(session_key),
        VideoPlayerSink::new(ui_tx),
        VideoPlayerSink::new(audio_tx),
        disc_tx,
        providers_rx,
        Arc::new(identity),
    );

    let rid = recording_id.clone();
    tokio::spawn(async move {
        let _ = coordinator.run(rid).await;
    });

    let timeout = Duration::from_secs(3);

    let frame_1 = tokio::time::timeout(timeout, ui_rx.recv())
        .await
        .expect("Timed out on frame 1")
        .expect("Channel closed before frame 1");
    let frame_2 = tokio::time::timeout(timeout, ui_rx.recv())
        .await
        .expect("Timed out on frame 2")
        .expect("Channel closed before frame 2");
    let frame_3 = tokio::time::timeout(timeout, ui_rx.recv())
        .await
        .expect("Timed out on frame 3")
        .expect("Channel closed before frame 3");

    assert_eq!(video_payload(&frame_1), jpeg_a, "Frame 1 must match jpeg_a");
    assert_eq!(video_payload(&frame_2), jpeg_b, "Frame 2 must match jpeg_b");
    assert_eq!(video_payload(&frame_3), jpeg_c, "Frame 3 must match jpeg_c");
}

/// Test 3: Audio + video interleaved with unified sequence numbering.
///
/// seq 1 = video (postcard Vec<Vec<u8>> format)
/// seq 2 = audio (raw compressed bytes, no postcard wrapping)
/// seq 3 = video
///
/// Verifies correct demux: video frames arrive on video_rx (postcard-deserialized),
/// audio arrives on audio_rx (raw decompressed). No cross-contamination.
#[tokio::test]
async fn test_production_format_audio_video_interleaved() {
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let vault_path = temp_dir.path().to_string_lossy().to_string();
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let session_key = phalanx_forensics::generate_session_key();

    let storage_tx = spawn_disk_guardian_actor(&identity, vault_path);
    let recording_id = RecordingId::new("v_av_interleaved");

    let jpeg_1 = vec![0xFF, 0xD8, 0x10, 0x01];
    let audio_pcm = vec![0x80, 0x00, 0x7F, 0xFF, 0x80, 0x00]; // fake PCM
    let jpeg_2 = vec![0xFF, 0xD8, 0x10, 0x02];

    // seq 1: video
    let (env1, hash1) = make_video_envelope(
        vec![jpeg_1.clone()],
        1,
        &recording_id,
        &session_key,
        &identity,
        None,
    );
    write_shard(&storage_tx, env1).await;

    // seq 2: audio
    let (env2, hash2) = make_audio_envelope(
        audio_pcm.clone(),
        2,
        &recording_id,
        &session_key,
        &identity,
        Some(hash1),
    );
    write_shard(&storage_tx, env2).await;

    // seq 3: video
    let (env3, _hash3) = make_video_envelope(
        vec![jpeg_2.clone()],
        3,
        &recording_id,
        &session_key,
        &identity,
        Some(hash2),
    );
    write_shard(&storage_tx, env3).await;

    let (video_tx, mut video_rx) = mpsc::channel(10);
    let (audio_tx, mut audio_rx) = mpsc::channel(10);
    let (disc_tx, _disc_rx) = mpsc::channel(1);
    let (egress_tx, _egress_rx) = mpsc::channel::<EgressCommand>(10);
    let (_providers_tx, providers_rx) = mpsc::channel(1);

    let mut coordinator = PlaybackCoordinator::new(
        storage_tx.clone(),
        egress_tx,
        Some(session_key),
        VideoPlayerSink::new(video_tx),
        VideoPlayerSink::new(audio_tx),
        disc_tx,
        providers_rx,
        Arc::new(identity),
    );

    let rid = recording_id.clone();
    tokio::spawn(async move {
        let _ = coordinator.run(rid).await;
    });

    let timeout = Duration::from_secs(3);

    // Video channel should get jpeg_1, then jpeg_2 (postcard-deserialized individual frames)
    let v1 = tokio::time::timeout(timeout, video_rx.recv())
        .await
        .expect("Timed out on video 1")
        .expect("Video channel closed before frame 1");
    assert_eq!(
        video_payload(&v1),
        jpeg_1,
        "First video frame must be jpeg_1"
    );

    // Audio channel should get the raw decompressed PCM
    let a1 = tokio::time::timeout(timeout, audio_rx.recv())
        .await
        .expect("Timed out on audio")
        .expect("Audio channel closed before audio frame");
    assert_eq!(
        a1, audio_pcm,
        "Audio frame must be raw PCM (no postcard wrapping)"
    );

    // Second video frame
    let v2 = tokio::time::timeout(timeout, video_rx.recv())
        .await
        .expect("Timed out on video 2")
        .expect("Video channel closed before frame 2");
    assert_eq!(
        video_payload(&v2),
        jpeg_2,
        "Second video frame must be jpeg_2"
    );

    // No cross-contamination: audio_rx should be empty (only 1 audio shard)
    assert!(
        audio_rx.try_recv().is_err(),
        "Audio channel should have no extra frames"
    );
}

/// Test 4: Coordinator survives a decode failure (wrong key on one shard).
///
/// seq 1 = valid encrypted shard (correct key)
/// seq 2 = encrypted with WRONG key → decode_payload fails
/// seq 3 = valid encrypted shard (correct key)
///
/// Before the resilience fix, the ? operator killed the coordinator on seq 2.
/// After the fix, it continues to seq 3.
#[tokio::test]
async fn test_coordinator_survives_decode_failure() {
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let vault_path = temp_dir.path().to_string_lossy().to_string();
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let correct_key = phalanx_forensics::generate_session_key();
    let wrong_key = SymmetricKey([0xDD; 32]);

    let storage_tx = spawn_disk_guardian_actor(&identity, vault_path);
    let recording_id = RecordingId::new("v_survive_failure");

    let jpeg_ok_1 = vec![0xFF, 0xD8, 0xAA, 0x01];
    let jpeg_ok_3 = vec![0xFF, 0xD8, 0xAA, 0x03];

    // seq 1: valid shard with correct key
    let (env1, hash1) = make_video_envelope(
        vec![jpeg_ok_1.clone()],
        1,
        &recording_id,
        &correct_key,
        &identity,
        None,
    );
    write_shard(&storage_tx, env1).await;

    // seq 2: shard encrypted with WRONG key — decode will fail
    let (env2, hash2) = make_video_envelope(
        vec![vec![0xFF, 0xD8, 0xBB, 0x02]],
        2,
        &recording_id,
        &wrong_key,
        &identity,
        Some(hash1),
    );
    write_shard(&storage_tx, env2).await;

    // seq 3: valid shard with correct key
    let (env3, _hash3) = make_video_envelope(
        vec![jpeg_ok_3.clone()],
        3,
        &recording_id,
        &correct_key,
        &identity,
        Some(hash2),
    );
    write_shard(&storage_tx, env3).await;

    let (ui_tx, mut ui_rx) = mpsc::channel(10);
    let (audio_tx, _audio_rx) = mpsc::channel(10);
    let (disc_tx, _disc_rx) = mpsc::channel(1);
    let (egress_tx, _egress_rx) = mpsc::channel::<EgressCommand>(10);
    let (_providers_tx, providers_rx) = mpsc::channel(1);

    let mut coordinator = PlaybackCoordinator::new(
        storage_tx.clone(),
        egress_tx,
        Some(correct_key), // coordinator has the correct key
        VideoPlayerSink::new(ui_tx),
        VideoPlayerSink::new(audio_tx),
        disc_tx,
        providers_rx,
        Arc::new(identity),
    );

    let rid = recording_id.clone();
    let handle = tokio::spawn(async move { coordinator.run(rid).await });

    let timeout = Duration::from_secs(5);

    // Should receive frame 1 (correct key)
    let frame_1 = tokio::time::timeout(timeout, ui_rx.recv())
        .await
        .expect("Timed out on frame 1")
        .expect("Channel closed before frame 1");
    assert_eq!(
        video_payload(&frame_1),
        jpeg_ok_1,
        "Frame 1 should be delivered"
    );

    // Frame 2 is skipped (wrong key → decode_payload fails → continue)
    // Should receive frame 3 (correct key)
    let frame_3 = tokio::time::timeout(timeout, ui_rx.recv())
        .await
        .expect("Timed out on frame 3 — coordinator likely died on frame 2")
        .expect("Channel closed before frame 3 — coordinator crashed");
    assert_eq!(
        video_payload(&frame_3),
        jpeg_ok_3,
        "Frame 3 should be delivered after skipping frame 2"
    );

    // Coordinator should finish without error (gap-skip terminates)
    let result = tokio::time::timeout(Duration::from_secs(15), handle)
        .await
        .expect("Coordinator didn't terminate");
    assert!(result.is_ok(), "Coordinator task should not panic");
}

/// Test 5: Direct storage round-trip — verify the disk AEAD layer preserves
/// the encrypted payload format.
///
/// This exercises the Guardian's append_shard → read_shard path independently
/// from the coordinator. If WitnessEnvelope with DataPayload::Encrypted doesn't
/// survive the storage AEAD encrypt → disk → decrypt → postcard deser cycle,
/// this test catches it.
#[tokio::test]
async fn test_disk_storage_production_round_trip() {
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let vault_path = temp_dir.path().to_string_lossy().to_string();
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let config = NodeConfig::default();
    let vault_key = derive_vault_key(&identity, &[0u8; 32]);

    let mut guardian = Guardian::new(
        &vault_path,
        &config,
        identity.did.clone(),
        Arc::new(SystemClock),
        vault_key,
    );

    let recording_id = RecordingId::new("v_disk_roundtrip");
    let content_key = guardian.generate_content_key(&recording_id);

    let jpeg_original = vec![0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x42, 0x45, 0x78, 0x69, 0x66];

    let (envelope, _hash) = make_video_envelope(
        vec![jpeg_original.clone()],
        1,
        &recording_id,
        &content_key,
        &identity,
        None,
    );

    // Verify the envelope payload is encrypted before writing
    match &envelope.evidence {
        Evidence::Video(v) => assert!(
            matches!(v.payload, DataPayload::Encrypted { .. }),
            "Payload must be Encrypted before disk write"
        ),
        _ => panic!("Expected Video evidence"),
    }

    // Write to disk (storage AEAD encryption)
    guardian.append_shard(&envelope).await.unwrap();

    // Read back from disk (storage AEAD decryption)
    let read_back = guardian
        .read_shard(&recording_id, StorageSequence(1), None)
        .await
        .expect("read_shard should succeed — storage AEAD round-trip failed");

    // Verify the payload is still Encrypted (storage AEAD is transparent to content encryption)
    let payload = match read_back.evidence {
        Evidence::Video(v) => {
            assert!(
                matches!(v.payload, DataPayload::Encrypted { .. }),
                "Payload must still be Encrypted after disk round-trip"
            );
            v.payload
        }
        _ => panic!("Expected Video evidence after read_shard"),
    };

    // Now do what the coordinator does: decode_payload → postcard deser
    let decoded = phalanx_forensics::decode_payload(payload, Some(&content_key))
        .expect("decode_payload should succeed with matching content key");

    let frames: Vec<Vec<u8>> = postcard::from_bytes(&decoded)
        .expect("postcard deserialization of Vec<Vec<u8>> should succeed");

    assert_eq!(frames.len(), 1, "Should have exactly 1 frame");
    assert_eq!(
        frames[0], jpeg_original,
        "Decoded frame must match original JPEG bytes"
    );
}

/// Test 6: Hydration round-trip — write shards, then simulate app restart
/// by creating a new Guardian from the same vault path and hydrating from disk.
/// This is the exact flow that fails on Android after app restart.
#[tokio::test]
async fn test_hydration_restores_recording_logs() {
    let tmp = tempdir().unwrap();
    let vault_path = tmp.path().to_str().unwrap().to_string();

    let identity = PhalanxIdentity::new_ephemeral();
    let vault_key = derive_vault_key(&identity, &[0u8; 32]);
    let config = NodeConfig::default();
    let rec_id = RecordingId::new("hydration-test-rec");

    let jpeg_a = vec![0xFF, 0xD8, 0xFF, 0xE0, 1, 2, 3];
    let jpeg_b = vec![0xFF, 0xD8, 0xFF, 0xE0, 4, 5, 6];

    // Phase 1: "First app session" — create Guardian, generate key, write 2 shards
    {
        let mut guardian = Guardian::new(
            &vault_path,
            &config,
            identity.did.clone(),
            Arc::new(SystemClock),
            vault_key.clone(),
        );

        let content_key = guardian.generate_content_key(&rec_id);
        guardian.persist_keyring().await.unwrap();

        let (env1, hash1) = make_video_envelope(
            vec![jpeg_a.clone()],
            1,
            &rec_id,
            &content_key,
            &identity,
            None,
        );
        guardian.append_shard(&env1).await.unwrap();

        let (env2, _hash2) = make_video_envelope(
            vec![jpeg_b.clone()],
            2,
            &rec_id,
            &content_key,
            &identity,
            Some(hash1),
        );
        guardian.append_shard(&env2).await.unwrap();

        // Verify in-memory state before "restart"
        let recordings = guardian.list_recordings();
        assert_eq!(recordings.len(), 1, "Should have 1 recording in-memory");
        let info = guardian.debug_recording_info(&rec_id);
        assert_eq!(info.0, 2, "Should have 2 shards in-memory");

        // Guardian drops here — simulates app shutdown
    }

    // Phase 2: "App restart" — create FRESH Guardian, hydrate from disk
    {
        let mut guardian = Guardian::new(
            &vault_path,
            &config,
            identity.did.clone(),
            Arc::new(SystemClock),
            vault_key.clone(),
        );

        // Before hydration: should be empty
        assert_eq!(
            guardian.list_recordings().len(),
            0,
            "Fresh Guardian should have 0 recordings before hydration"
        );

        // Load keyring (like StorageActor bootstrap does)
        guardian.load_keyring().await.unwrap();

        // Hydrate recording logs from disk
        guardian.hydrate_recording_logs().await.unwrap();

        // After hydration: should find the recording with 2 shards
        let recordings = guardian.list_recordings();
        assert!(
            !recordings.is_empty(),
            "Hydration should have found at least 1 recording log"
        );

        let info = guardian.debug_recording_info(&rec_id);
        assert_eq!(
            info.0, 2,
            "Hydrated recording should have 2 shards (got {})",
            info.0
        );
        assert!(info.1, "Content key should exist after keyring load");

        // Verify actual shard content round-trips through hydration
        let env1_back = guardian
            .read_shard(&rec_id, StorageSequence(1), None)
            .await
            .expect("read_shard(1) should succeed after hydration");

        let payload1 = match &env1_back.evidence {
            Evidence::Video(v) => &v.payload,
            _ => panic!("Expected Video evidence"),
        };

        let content_key = guardian
            .get_content_key(&rec_id)
            .expect("Content key should exist");
        let decoded1 = phalanx_forensics::decode_payload(payload1.clone(), Some(&content_key))
            .expect("decode_payload should succeed");
        let frames1: Vec<Vec<u8>> =
            postcard::from_bytes(&decoded1).expect("postcard deser should succeed");
        assert_eq!(frames1.len(), 1);
        assert_eq!(
            frames1[0], jpeg_a,
            "Frame 1 should match original after hydration"
        );

        // Read shard 2
        let env2_back = guardian
            .read_shard(&rec_id, StorageSequence(2), None)
            .await
            .expect("read_shard(2) should succeed after hydration");

        let payload2 = match &env2_back.evidence {
            Evidence::Video(v) => &v.payload,
            _ => panic!("Expected Video evidence"),
        };
        let decoded2 = phalanx_forensics::decode_payload(payload2.clone(), Some(&content_key))
            .expect("decode_payload should succeed");
        let frames2: Vec<Vec<u8>> =
            postcard::from_bytes(&decoded2).expect("postcard deser should succeed");
        assert_eq!(frames2.len(), 1);
        assert_eq!(
            frames2[0], jpeg_b,
            "Frame 2 should match original after hydration"
        );
    }
}
