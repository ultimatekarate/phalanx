use crate::base::config::PhalanxConfig;
use crate::base::types::{ByteCapacity, TrafficGovernor, UnitInterval};
use crate::primitives::identity::{Did, NetworkId};
use crate::primitives::shards::{Evidence, ShardChunk, StorageSequence, Volley, WitnessEnvelope};
use crate::primitives::time::TrustedClock;
use crate::storage::crucible::Crucible;
use crate::storage::strategies::{ShardAmalgam, VolleyAmalgam};

// IMPORT GATES
use crate::security::gate::{CapacityGate, ForensicGate, IntegrityGate};

use crate::primitives::time::TimeError;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use tokio::time::Instant;
use tracing::{debug, error, info, instrument, warn};

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
}

pub struct Guardian {
    pub vault_storage: PathBuf,
    pub wal_directory: PathBuf,

    // Reassembly layers
    pub micro_layer: Crucible<ShardAmalgam>,
    pub macro_layer: Crucible<VolleyAmalgam>,

    // --- THE POLICY STATE ---
    pub processed_sequences: HashMap<Did, HashSet<StorageSequence>>,
    pub session_activity: HashMap<Did, Instant>,

    pub stale_threshold: std::time::Duration,
    pub max_buffers_per_peer: usize,

    // --- GOVERNANCE & QUOTAS ---
    pub local_did: Did,
    pub max_storage_bytes: ByteCapacity,
    pub max_foreign_storage_bytes: ByteCapacity,
    pub current_storage_usage: ByteCapacity,
    pub foreign_storage_usage: ByteCapacity,

    pub clock: TrustedClock,
    pub governor: TrafficGovernor,
}

impl Guardian {
    #[must_use]
    pub fn new(vault_path: &str, config: &PhalanxConfig, local_did: Did) -> Self {
        let root = PathBuf::from(vault_path);
        let wal = root.join("wal");
        let _ = fs::create_dir_all(&root);
        let _ = fs::create_dir_all(&wal);

        let mut guardian = Self {
            vault_storage: root,
            wal_directory: wal,
            micro_layer: Crucible::new(),
            macro_layer: Crucible::new(),
            processed_sequences: HashMap::new(),
            session_activity: HashMap::new(),
            stale_threshold: std::time::Duration::from_secs(config.storage.stale_session_threshold),
            max_buffers_per_peer: config.storage.max_peers,

            local_did: local_did.clone(),
            max_storage_bytes: config.storage.max_storage_bytes,
            max_foreign_storage_bytes: config.storage.max_foreign_storage_bytes,
            current_storage_usage: ByteCapacity(0),
            foreign_storage_usage: ByteCapacity(0),
            clock: TrustedClock::new(),
            governor: TrafficGovernor::new(),
        };

        guardian.calculate_initial_usage();
        guardian.recover_from_wal();
        guardian
    }

    fn calculate_initial_usage(&mut self) {
        let mut total = 0;
        let mut foreign = 0;
        let safe_local_did = self.local_did.to_safe_name();

        if let Ok(entries) = fs::read_dir(&self.vault_storage) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let folder_name = path.file_name().unwrap_or_default().to_string_lossy();
                    let is_foreign = folder_name != safe_local_did && folder_name != "wal";

                    if let Ok(sub_entries) = fs::read_dir(&path) {
                        for sub in sub_entries.flatten() {
                            if let Ok(meta) = sub.metadata() {
                                let size = meta.len();
                                total += size;
                                if is_foreign {
                                    foreign += size;
                                }
                            }
                        }
                    }
                }
            }
        }
        self.current_storage_usage = ByteCapacity(total);
        self.foreign_storage_usage = ByteCapacity(foreign);
        info!(
            total_mb = total / 1_000_000,
            foreign_mb = foreign / 1_000_000,
            "Storage governance initialized"
        );
    }

    fn prune_foreign_evidence(&mut self) {
        if self.foreign_storage_usage <= self.max_foreign_storage_bytes {
            return;
        }

        warn!(
            usage = %self.foreign_storage_usage,
            limit = %self.max_foreign_storage_bytes,
            "Foreign storage quota exceeded. Pruning..."
        );

        let mut foreign_files = Vec::new();
        let safe_local_did = self.local_did.to_safe_name();

        if let Ok(entries) = fs::read_dir(&self.vault_storage) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let folder_name = path.file_name().unwrap_or_default().to_string_lossy();
                    if folder_name == safe_local_did || folder_name == "wal" {
                        continue;
                    }

                    if let Ok(sub_entries) = fs::read_dir(&path) {
                        for sub in sub_entries.flatten() {
                            let sub_path = sub.path();
                            if let Ok(meta) = sub.metadata() {
                                if let Ok(modified) = meta.modified() {
                                    foreign_files.push((sub_path, meta.len(), modified));
                                }
                            }
                        }
                    }
                }
            }
        }

        foreign_files.sort_by_key(|k| k.2);

        for (path, size, _) in foreign_files {
            if self.foreign_storage_usage <= self.max_foreign_storage_bytes {
                break;
            }

            // Forensic Gate: Log Pruning Failures
            if let Err(e) = fs::remove_file(&path) {
                error!(file = ?path, error = %e, "Failed to prune file");
            } else {
                warn!(file = ?path, size = size, "Evicted foreign evidence");
                self.foreign_storage_usage = self.foreign_storage_usage.saturating_sub(size);
                self.current_storage_usage = self.current_storage_usage.saturating_sub(size);
            }
        }
    }

    /// Stage 1: Micro-Layer (Chunk Ingestion)
    #[instrument(skip(self, chunk), level = "debug")]
    pub fn ingest_chunk(&mut self, chunk: ShardChunk, mode: NodeMode) {
        // 1. Governance State Sync
        match mode {
            NodeMode::Leaf => {
                self.governor
                    .set_state(crate::base::types::PowerState::Leaf);
            }
            NodeMode::Standard => {
                self.governor
                    .set_state(crate::base::types::PowerState::Normal);
            }
        }

        // 2. Security Check (Governance Gate)
        if !self
            .governor
            .should_accept(&chunk.owner_did, &self.local_did)
        {
            warn!(did = %chunk.owner_did, "TrafficGovernor: Shedding foreign storage task");
            return;
        }

        if matches!(mode, NodeMode::Leaf) && chunk.owner_did != self.local_did {
            warn!(did = %chunk.owner_did, "Leaf Mode Active: Shedding foreign chunk");
            return;
        }

        // 3. Circuit Breaker (Manual Capacity Check)
        let load_factor = self.calculate_load();
        if load_factor > 0.8 && chunk.owner_did != self.local_did {
            warn!(load = %load_factor, did = %chunk.owner_did, "Circuit Breaker: Shedding foreign load");
            return;
        }

        // 4. Processing
        if let Some(envelope) = self.micro_layer.process(chunk) {
            info!(
                shard_id = %envelope.evidence.sequence_id(),
                "Micro-layer reassembly complete. Promoting to envelope."
            );

            // Forensic Gate: Log failures during promotion
            if let Err(e) = self.ingest_envelope(envelope) {
                warn!(error = ?e, "Guardian rejected reassembled chunk");
            }
        }
    }

    /// Stage 2: Macro-Layer (Envelope Ingestion)
    pub fn ingest_envelope(&mut self, envelope: WitnessEnvelope) -> Result<(), GuardianError> {
        let local_network_id = self
            .local_did
            .as_str()
            .parse::<NetworkId>()
            .unwrap_or_else(|_| NetworkId::random());

        // 1. Foreign Data Pruning (Pre-Check)
        if envelope.did != self.local_did
            && self.foreign_storage_usage > self.max_foreign_storage_bytes
        {
            self.prune_foreign_evidence();
        }

        // GATE 1: CAPACITY GATE
        let limit = if envelope.did == self.local_did {
            self.max_storage_bytes.0 as usize
        } else {
            self.max_foreign_storage_bytes.0 as usize
        };

        let current_usage = if envelope.did == self.local_did {
            self.current_storage_usage.0 as usize
        } else {
            self.foreign_storage_usage.0 as usize
        };

        let peer_id = envelope.witness_peer_id;

        let envelope = envelope
            .check_capacity(&peer_id, current_usage, limit)
            .map_err(|_| GuardianError::QuotaExceeded(ByteCapacity(limit as u64)))?;

        // GATE 2: INTEGRITY GATE
        let envelope = envelope
            .check_integrity(&local_network_id, &self.clock, 10)
            .map_err(|e| GuardianError::InvalidSignature(e.to_string()))?;

        // GATE 3: FORENSIC GATE
        self.write_to_wal(&envelope)
            .gate(
                "wal_write_failed",
                &local_network_id,
                "CRITICAL: WAL Persistence Failure",
            )
            .map_err(|e| GuardianError::WalWriteFailed(e.to_string()))?;

        // --- Post-Gating Logic (In-Memory Updates) ---
        let did = envelope.did.clone();
        let seq = envelope.evidence.sequence_id();

        if self
            .processed_sequences
            .get(&did)
            .is_some_and(|set| set.contains(&seq))
        {
            debug!(%seq, "Replay protection: Dropping already archived shard.");
            return Err(GuardianError::ReplayDetected(seq.0 as u64));
        }

        self.session_activity.insert(did.clone(), Instant::now());

        if let Some(volley) = self.macro_layer.process(envelope) {
            info!(volley = %volley.id, "Volley sealed. Archiving.");
            self.archive_volley(volley);
        }

        Ok(())
    }

    fn calculate_load(&self) -> UnitInterval {
        let micro_len = self.micro_layer.len() as f64;
        let macro_len = self.macro_layer.len() as f64;
        let micro_cap = (self.max_buffers_per_peer as f64) * 5.0;
        let macro_cap = self.max_buffers_per_peer as f64;

        let micro_load = if micro_cap > 0.0 {
            micro_len / micro_cap
        } else {
            1.0
        };
        let macro_load = if macro_cap > 0.0 {
            macro_len / macro_cap
        } else {
            1.0
        };

        let total_raw = micro_load + macro_load;
        UnitInterval::new(total_raw.min(1.0) as f32)
    }

    #[must_use]
    pub fn get_active_volley_shards(
        &self,
        did: &Did,
    ) -> Option<&std::collections::BTreeMap<StorageSequence, WitnessEnvelope>> {
        self.macro_layer
            .get(&did.to_string())
            .map(|buffer| &buffer.artifacts)
    }

    /// Archive Volley (Gated)
    fn archive_volley(&mut self, volley: Volley) {
        let safe_did = volley.owner_did.replace(":", "_");
        let archive_dir = self.vault_storage.join(&safe_did);
        let local_network_id = self
            .local_did
            .as_str()
            .parse::<NetworkId>()
            .unwrap_or_else(|_| NetworkId::random());

        // Forensic Gate: Directory Creation
        if fs::create_dir_all(&archive_dir)
            .gate(
                "fs_create_err",
                &local_network_id,
                "Archive Dir Create Failed",
            )
            .is_err()
        {
            return;
        }

        let mut wal_files_to_delete = Vec::new();
        for artifact in &volley.artifacts {
            let did = Did(volley.owner_did.clone());
            self.processed_sequences
                .entry(did)
                .or_default()
                .insert(artifact.evidence.sequence_id());

            let safe_did_artifact = artifact.did.to_safe_name();
            let seq = artifact.evidence.sequence_id().0;
            wal_files_to_delete.push(
                self.wal_directory
                    .join(format!("{}_{}.wal", safe_did_artifact, seq)),
            );
        }

        let extension = match volley.artifacts[0].evidence {
            Evidence::Video(_) => "vid.phlx",
            Evidence::Audio(_) => "aud.phlx",
        };
        let final_path = archive_dir.join(format!("{}.{}", volley.id, extension));
        let tmp_path = archive_dir.join(format!("{}.tmp", volley.id));

        // Forensic Gate: Serialization
        let bytes = match postcard::to_stdvec(&volley).gate(
            "serialize_err",
            &local_network_id,
            "Volley Serialization Failed",
        ) {
            Ok(b) => b,
            Err(_) => return,
        };
        let file_size = bytes.len() as u64;

        // Forensic Gate: Write Temp
        if fs::write(&tmp_path, bytes)
            .gate(
                "fs_write_err",
                &local_network_id,
                "Archive Temp Write Failed",
            )
            .is_err()
        {
            return;
        }

        // Forensic Gate: Atomic Rename
        if fs::rename(&tmp_path, &final_path)
            .gate("fs_rename_err", &local_network_id, "Archive Rename Failed")
            .is_err()
        {
            return;
        }

        info!(path = ?final_path, size = file_size, "Volley successfully archived");

        // Governance Update
        self.current_storage_usage = self.current_storage_usage.saturating_add(file_size);
        if safe_did != self.local_did.to_safe_name() {
            self.foreign_storage_usage = self.foreign_storage_usage.saturating_add(file_size);
        }

        // Cleanup WAL (Best effort, no gating needed)
        for wal_path in wal_files_to_delete {
            let _ = fs::remove_file(&wal_path);
        }
    }

    pub fn archive_stale_sessions(&mut self, ttl: std::time::Duration) {
        info!(
            ttl_ms = ttl.as_millis(),
            "Guardian: Running governance cleanup cycle"
        );
        let recovered_envelopes = self.micro_layer.flush_stale(ttl);

        // Use a dummy gate for internal cyclic recovery
        for env in recovered_envelopes {
            // Re-ingest (will hit replay protection or archive logic)
            let _ = self.ingest_envelope(env);
        }

        let recovered_volleys = self.macro_layer.flush_stale(ttl);
        for volley in recovered_volleys {
            self.archive_volley(volley);
        }
    }

    fn write_to_wal(&self, envelope: &WitnessEnvelope) -> std::io::Result<()> {
        let safe_did = envelope.did.to_safe_name();
        let file_name = format!("{}_{}.wal", safe_did, envelope.evidence.sequence_id().0);
        let wal_path = self.wal_directory.join(file_name);

        let bytes = postcard::to_stdvec(envelope).map_err(std::io::Error::other)?;
        let mut file = File::create(wal_path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }

    fn recover_from_wal(&mut self) {
        let local_network_id = self
            .local_did
            .as_str()
            .parse::<NetworkId>()
            .unwrap_or_else(|_| NetworkId::random());

        // Forensic Gate: Directory Read
        let entries = match fs::read_dir(&self.wal_directory).gate(
            "wal_read_err",
            &local_network_id,
            "WAL Dir Read Failed",
        ) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if fs::metadata(&path).map(|m| m.len()).unwrap_or(0) == 0 {
                continue;
            }

            if let Ok(bytes) = fs::read(&path) {
                if let Ok(envelope) = postcard::from_bytes::<WitnessEnvelope>(&bytes) {
                    if let Some(volley) = self.macro_layer.process(envelope) {
                        info!(id = %volley.id, "Recovered sealed volley from WAL. Archiving.");
                        self.archive_volley(volley);
                    }
                }
            }
        }
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
    use crate::security::sentinel::Sentinel;
    use std::error::Error;

    #[tokio::test]
    async fn test_sentinel_leaf_mode_filtering() -> Result<(), Box<dyn Error>> {
        let (identity, _) = PhalanxIdentity::generate()?;
        let (stranger, _) = PhalanxIdentity::generate()?;
        let config = PhalanxConfig::default();
        let local_peer = NetworkId::random();

        let mut sentinel = Sentinel::new(&config);
        sentinel.set_power_state(PowerState::Leaf);

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

        let _ = sentinel
            .process_chunk(
                foreign_chunk,
                &config.network.video_topic,
                &config,
                &identity,
                local_peer.clone(),
            )
            .await?;

        assert_eq!(
            sentinel.video_buffers.len(),
            0,
            "Sentinel leaked foreign data in Leaf Mode"
        );

        let _ = sentinel
            .process_chunk(
                local_chunk,
                &config.network.video_topic,
                &config,
                &identity,
                local_peer,
            )
            .await?;

        assert_eq!(
            sentinel.video_buffers.len(),
            1,
            "Sentinel failed to process local data in Leaf Mode"
        );

        Ok(())
    }
}
