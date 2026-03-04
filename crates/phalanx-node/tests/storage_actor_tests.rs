use std::time::Duration;

use phalanx_forensics::gate::WitnessGate;
use phalanx_forensics::prelude::TransientJournal;

use phalanx_forensics::Reassembler;
use phalanx_node::actors::storage::{NoOpJournal, StorageActor, StorageCommand};
use phalanx_node::config::NodeConfig;
use phalanx_node::identity::PhalanxNodeIdentityExt;
use phalanx_node::persistence::vault::Guardian;
use phalanx_proto::evidence::{ChunkType, DataPayload, Evidence, StorageSequence, VideoShard};
use phalanx_proto::identity::{Did, NetworkId, PhalanxIdentity, ShardId, VolleyId};
use phalanx_proto::prelude::{PendingEgress, ShardChunk, ShardError};
use phalanx_proto::retrieval::VolleyResponse;
use phalanx_proto::storage::GuardianError;
use phalanx_proto::time::PhalanxTimestamp;
use phalanx_transport::identity_ext::Libp2pExt;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_pillar_salvage_under_disk_pressure() {
    // --- CLINICAL MOCK: THE CRUMBLING JOURNAL ---
    struct BrokenJournal;

    #[async_trait::async_trait]
    impl TransientJournal for BrokenJournal {
        async fn record_pending_egress(&mut self, _: &[PendingEgress]) -> Result<(), ShardError> {
            // Pillar 1 Failure: Simulated Disk Full / IO Error
            Err(ShardError::Io(
                "DISK FULL: Phalanx cannot salvage egress state".into(),
            ))
        }
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
    let config = NodeConfig::test_defaults();
    let (identity, _) = PhalanxIdentity::generate().unwrap();

    // 2. Prepare Real Forensic Evidence via WitnessGate
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

    // 3. Setup the Guardian & Actor
    let guardian = Guardian::new(
        &temp.path().to_string_lossy(),
        &config,
        identity.did.clone(),
    );

    let (storage_tx, storage_rx) = mpsc::channel::<StorageCommand>(10);
    let (forensic_tx, _forensic_rx) = mpsc::channel::<(NetworkId, Did, GuardianError)>(1);

    let actor = StorageActor {
        reassembler: Reassembler::new(),
        guardian,
        journal: BrokenJournal,
        config: config.clone(),
        identity: identity.clone(),
        forensic_tx,
        local_peer_id: identity.to_network_id(),
    };

    // 4. Trigger Salvage with Evidence
    let salvage_data = vec![PendingEgress {
        channel_id: "ch_broken_pillar".into(),
        response: VolleyResponse::Success(vec![envelope]),
        attempt_count: 0,
        next_attempt: PhalanxTimestamp::now(),
    }];

    storage_tx
        .send(StorageCommand::EmergencySalvage(salvage_data))
        .await
        .unwrap();
    drop(storage_tx); // Close the channel to signal shutdown after processing

    // 5. Verification: Ensure no deadlock
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
    // 1. Setup Environment
    let temp = tempfile::tempdir().unwrap();
    let config = NodeConfig::test_defaults();
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
        *sig_byte ^= 0xFF;
    }

    let poisoned_data = postcard::to_allocvec(&envelope).expect("Serialization failed");

    let chunk = ShardChunk {
        shard_id: ShardId(666),
        chunk_index: 0,
        total_chunks: 1,
        data: poisoned_data,
        owner_did: attacker_identity.did.clone(),
        chunk_type: ChunkType::Witnessed,
    };

    // 3. Setup Channels and Actor
    let (storage_tx, storage_rx) = mpsc::channel::<StorageCommand>(10);
    let (forensic_tx, mut forensic_rx) = mpsc::channel::<(NetworkId, Did, GuardianError)>(10);

    let actor = StorageActor {
        reassembler: Reassembler::new(),
        guardian: Guardian::new(
            &temp.path().to_string_lossy(),
            &config,
            my_identity.did.clone(),
        ),
        journal: NoOpJournal,
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
        GuardianError::InvalidSignature(..) => {
            println!("Gatekeepers held! Invalid signature detected.");
        }
        _ => panic!(
            "Expected VerificationFailed/InvalidSignature, got: {:?}",
            error
        ),
    }
}
