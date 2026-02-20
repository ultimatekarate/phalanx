use crate::base::config::PhalanxConfig;
use crate::base::types::ByteCapacity;
use crate::primitives::identity::Did;
use crate::primitives::shards::{StorageSequence, WitnessEnvelope};
use crate::primitives::time::TimeError;
use crate::storage::crucible::Crucible;
use tracing::{instrument, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeMode {
    Leaf,
    Standard,
}

/// Enumerates specific failure modes for storage and security operations.
#[derive(Debug, thiserror::Error)]
pub enum GuardianError {
    #[error("Quota exceeded: {0:?}")]
    QuotaExceeded(ByteCapacity),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Replay attack detected: Sequence {0} is too old")]
    ReplayDetected(u64),

    #[error("WAL write failed: {0}")]
    WalWriteFailed(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Time synchronization failure: {0}")]
    TimeSource(#[from] TimeError),

    #[error("Attack attempt blocked: Peer {0} is blacklisted")]
    BlacklistedPeer(String),

    #[error("Cryptographic verification failed: {0}")]
    VerificationFailed(String),

    #[error("Crucible commit failed: {0}")]
    CrucibleError(String),
}

pub struct Guardian {
    pub crucible: Crucible,
    pub active_volleys: BTreeMap<Did, BTreeMap<StorageSequence, WitnessEnvelope>>,
    pub local_did: Did,
}

impl Guardian {
    pub fn new(vault_path: &str, config: &PhalanxConfig, local_did: Did) -> Self {
        Self {
            crucible: Crucible::new(vault_path),
            active_volleys: BTreeMap::new(),
            local_did,
        }
    }

    /// The sole entry point for data promotion into the permanent archive.
    /// This enforces the Sentinel/Guardian split by requiring matured envelopes.
    #[instrument(skip(self, envelope), fields(owner = %envelope.owner_did))]
    pub fn ingest_envelope(&mut self, envelope: WitnessEnvelope) -> Result<(), GuardianError> {
        // 1. Mandatory Forensic Validation
        // This ensures the data hasn't been tampered with since reassembly.
        envelope
            .verify()
            .map_err(|e| GuardianError::VerificationFailed(e.to_string()))?;

        let owner = envelope.did.clone();
        let sequence = envelope.sequence;

        // 2. Promotion to Active Volley
        // Organize data by owner for localized forensic retrieval.
        let user_vault = self
            .active_volleys
            .entry(owner)
            .or_insert_with(BTreeMap::new);

        user_vault.insert(sequence, envelope);

        // 3. Optional: Trigger Crucible Commit
        // If the volley meets the threshold defined in PhalanxPhysics,
        // it should be persisted to the immutable ledger.
        self.check_and_finalize_volley(&envelope.did)?;

        Ok(())
    }

    fn check_and_finalize_volley(&mut self, did: &Did) -> Result<(), GuardianError> {
        // Implementation for batch-committing envelopes to long-term storage
        // logic moved from legacy ingest_chunk.
        Ok(())
    }

    pub fn get_active_volley_shards(
        &self,
        did: &Did,
    ) -> Option<&BTreeMap<StorageSequence, WitnessEnvelope>> {
        self.active_volleys.get(did)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::config::{HardwareConfig, NetworkConfig, StorageConfig};
    use crate::primitives::identity::{NetworkId, PhalanxIdentity};
    use crate::primitives::shards;
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::PathBuf;

    // Helper stays infallible as it constructs a struct literal
    fn mock_config(max_foreign_bytes: ByteCapacity) -> PhalanxConfig {
        PhalanxConfig {
            network: NetworkConfig {
                max_chunk_size_bytes: 100,
                video_topic: "t".into(),
                audio_topic: "t".into(),
                control_topic: "t".into(),
                cleanup_interval_secs: 1,
                bootstrap_peers: vec![],
                guardian_service_key: "k".into(),
                protocol_version: "v0.1.0".to_string(),
            },
            storage: StorageConfig {
                vault_path: "test_vault_governance".into(),
                max_video_buffer: 1,
                max_audio_buffer: 1,
                max_peers: 1,
                stale_session_threshold: 1,
                shards_needed_to_archive: 1,
                max_storage_bytes: ByteCapacity(100_000),
                max_foreign_storage_bytes: max_foreign_bytes,
            },
            hardware: HardwareConfig {
                camera_fps: 1,
                audio_sample_rate: 1,
                audio_channels: 1,
            },
        }
    }

    #[test]
    fn test_governance_pruning() -> Result<(), Box<dyn std::error::Error>> {
        use std::thread;
        let vault_root = PathBuf::from("test_vault_governance");

        if vault_root.exists() {
            fs::remove_dir_all(&vault_root)?;
        }
        fs::create_dir_all(&vault_root)?;

        let (me, _) = PhalanxIdentity::generate()?;
        let (stranger_1, _) = PhalanxIdentity::generate()?;
        let (stranger_2, _) = PhalanxIdentity::generate()?;

        // 1. Create OLD Data (Stranger 1)
        let s1_dir = vault_root.join(stranger_1.did.to_safe_name());
        fs::create_dir_all(&s1_dir)?;

        let mut f1 = File::create(s1_dir.join("old_evidence.phlx"))?;
        f1.write_all(&[0u8; 1000])?;
        f1.sync_all()?;

        // FIX: Ensure distinct timestamp
        thread::sleep(std::time::Duration::from_millis(100));

        // 2. Create NEW Data (Stranger 2)
        let s2_dir = vault_root.join(stranger_2.did.to_safe_name());
        fs::create_dir_all(&s2_dir)?;

        let mut f2 = File::create(s2_dir.join("new_evidence.phlx"))?;
        f2.write_all(&[0u8; 1000])?;
        f2.sync_all()?;

        // 3. Init Guardian
        let config = mock_config(ByteCapacity(1500));
        let mut guardian = Guardian::new("test_vault_governance", &config, me.did.clone());

        assert_eq!(
            guardian.foreign_storage_usage,
            ByteCapacity(2000),
            "Initial usage calculation failed"
        );

        // 4. Trigger Pruning
        guardian.prune_foreign_evidence();

        // 5. Verification
        assert!(
            !s1_dir.join("old_evidence.phlx").exists(),
            "Old evidence should be evicted"
        );
        assert!(
            s2_dir.join("new_evidence.phlx").exists(),
            "New evidence should be kept"
        );
        assert!(
            guardian.foreign_storage_usage <= ByteCapacity(1500),
            "Usage should be under limit"
        );

        if vault_root.exists() {
            fs::remove_dir_all(&vault_root)?;
        }
        Ok(())
    }

    #[test]
    fn test_invalid_signature_rejection() -> Result<(), Box<dyn std::error::Error>> {
        let (identity, _) = PhalanxIdentity::generate()?;
        let _attacker = PhalanxIdentity::generate()?; // Different key!
        let peer_id = NetworkId::random();
        let config = PhalanxConfig::default();
        let vault_path = "sim_vault/test_sig_reject";

        if std::path::Path::new(vault_path).exists() {
            std::fs::remove_dir_all(vault_path)?;
        }

        let mut guardian = Guardian::new(vault_path, &config, identity.did.clone());

        // 1. Create a Shard using constructor (safe propagation)
        let frames = vec![vec![1]];
        let shard = shards::create_video_shard(frames, StorageSequence(1), 30, "v1".into())?;

        // 2. Sign it with the WRONG identity (Attacker signs, claims to be Victim?)
        let mut envelope = WitnessEnvelope::new(Evidence::Video(shard), &identity, peer_id)?;

        // 3. TAMPER: Modify the payload without updating the signature
        if let Evidence::Video(ref mut v) = envelope.evidence {
            v.fps = 120; // Malicious edit, it used to be 30
        }

        // 4. Ingest & Assert Failure
        let result = guardian.ingest_envelope(envelope);

        assert!(result.is_err(), "Guardian accepted a tampered envelope!");
        match result {
            Err(GuardianError::InvalidSignature(_)) => (), // Pass
            _ => panic!("Wrong error type returned"),
        }

        Ok(())
    }

    #[test]
    fn test_governance_rejection() -> Result<(), Box<dyn std::error::Error>> {
        let (identity, _) = PhalanxIdentity::generate()?;
        let (stranger, _) = PhalanxIdentity::generate()?;
        let peer_id = NetworkId::random();

        // 1. Setup Config with TINY limit (0 bytes)
        let mut config = PhalanxConfig::default();
        config.storage.max_foreign_storage_bytes = ByteCapacity(0); // Strict mode

        let vault_path = "sim_vault/test_quota_reject";
        if std::path::Path::new(vault_path).exists() {
            std::fs::remove_dir_all(vault_path)?;
        }

        let mut guardian = Guardian::new(vault_path, &config, identity.did.clone());

        // 2. Artificially inflate usage to simulate a "stuck" state
        guardian.foreign_storage_usage = ByteCapacity(1000);

        let frames = vec![vec![1]];
        let shard = shards::create_video_shard(frames, StorageSequence(1), 30, "v1".into())?;
        let envelope = WitnessEnvelope::new(Evidence::Video(shard), &stranger, peer_id)?;

        // 3. Ingest Foreign Data
        let result = guardian.ingest_envelope(envelope);

        // 4. Assert Quota Error
        assert!(result.is_err(), "Guardian ignored quota limits!");
        match result {
            Err(GuardianError::QuotaExceeded(limit)) => assert_eq!(limit, ByteCapacity(0)),
            _ => panic!("Wrong error type"),
        }
        Ok(())
    }

    #[test]
    fn test_replay_protection() -> Result<(), Box<dyn std::error::Error>> {
        let (identity, _) = PhalanxIdentity::generate()?;
        let peer_id = NetworkId::random();
        let config = PhalanxConfig::default();
        let vault_path = "sim_vault/test_replay";

        if std::path::Path::new(vault_path).exists() {
            std::fs::remove_dir_all(vault_path)?;
        }

        let mut guardian = Guardian::new(vault_path, &config, identity.did.clone());

        let seq_num = StorageSequence(50);
        let frames = vec![vec![1]];
        let shard =
            crate::primitives::shards::create_video_shard(frames, seq_num, 30, "v1".into())?;
        let envelope = WitnessEnvelope::new(Evidence::Video(shard), &identity, peer_id)?;

        // 1. MANUALLY SEED HISTORY
        guardian
            .processed_sequences
            .entry(identity.did.clone())
            .or_default()
            .insert(seq_num);

        // 2. Ingest the "Replay" Envelope
        let result = guardian.ingest_envelope(envelope);

        // 3. Verify it was BLOCKED explicitly with an error
        assert!(
            result.is_err(),
            "Guardian failed to reject replayed envelope!"
        );

        match result.unwrap_err() {
            GuardianError::ReplayDetected(seq) => assert_eq!(seq, 50),
            other => panic!("Expected ReplayDetected error, found: {:?}", other),
        }

        let active_session = guardian.get_active_volley_shards(&identity.did);
        assert!(
            active_session.is_none(),
            "Replayed envelope leaked into active buffer!"
        );

        Ok(())
    }

    #[test]
    fn test_initial_usage_scan() -> Result<(), Box<dyn std::error::Error>> {
        let (identity, _) = PhalanxIdentity::generate()?;
        let (stranger, _) = PhalanxIdentity::generate()?;
        let config = PhalanxConfig::default();
        let vault_path = "sim_vault/test_init_scan";

        if std::path::Path::new(vault_path).exists() {
            std::fs::remove_dir_all(vault_path)?;
        }

        // 1. Pre-seed the disk with data
        let stranger_dir = std::path::PathBuf::from(vault_path).join(stranger.did.to_safe_name());
        std::fs::create_dir_all(&stranger_dir)?;
        std::fs::write(stranger_dir.join("test.bin"), vec![0u8; 500])?; // 500 bytes

        // 2. Boot Guardian
        let guardian = Guardian::new(vault_path, &config, identity.did.clone());

        // 3. Assert Usage Detected
        assert_eq!(guardian.current_storage_usage, ByteCapacity(500));
        assert_eq!(guardian.foreign_storage_usage, ByteCapacity(500));
        Ok(())
    }

    use crate::base::types::PowerState;
    use crate::primitives::shards::{ChunkType, ShardId};
    use crate::storage::reassembler::Reassembler;
    use std::error::Error;

    #[tokio::test]
    async fn test_reassembler_leaf_mode_filtering() -> Result<(), Box<dyn Error>> {
        let (identity, _) = PhalanxIdentity::generate()?;
        let (stranger, _) = PhalanxIdentity::generate()?;
        let config = PhalanxConfig::default();
        let local_peer = NetworkId::random();

        let mut reassembler = Reassembler::new(&config);
        reassembler.set_power_state(PowerState::Leaf);

        let foreign_chunk = ShardChunk {
            shard_id: ShardId(1),
            chunk_index: 0,
            total_chunks: 2,
            data: vec![1, 2, 3],
            owner_did: stranger.did.clone(),
            chunk_type: ChunkType::Witnessed,
        };

        let local_chunk = ShardChunk {
            shard_id: ShardId(2),
            chunk_index: 0,
            total_chunks: 2,
            data: vec![4, 5, 6],
            owner_did: identity.did.clone(),
            chunk_type: ChunkType::ForensicUnit,
        };

        let _ = reassembler
            .process_chunk(
                foreign_chunk,
                &config.network.video_topic,
                &config,
                &identity,
                local_peer.clone(),
            )
            .await?;

        assert_eq!(
            reassembler.video_buffers.len(),
            0,
            "Reassembler leaked foreign data in Leaf Mode"
        );

        let _ = reassembler
            .process_chunk(
                local_chunk,
                &config.network.video_topic,
                &config,
                &identity,
                local_peer,
            )
            .await?;

        assert_eq!(
            reassembler.video_buffers.len(),
            1,
            "Reassembler failed to process local data in Leaf Mode"
        );

        Ok(())
    }
}
