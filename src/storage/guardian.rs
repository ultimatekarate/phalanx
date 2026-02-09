use crate::protocol::shards::{StorageSequence, Evidence, WitnessEnvelope, ShardChunk};
use crate::storage::crucible::{Crucible};
use crate::storage::strategies::{ShardAmalgam, VolleyAmalgam, Volley}; 
use crate::core::config::PhalanxConfig;
use crate::security::identity::Did;

use std::collections::{HashSet, HashMap};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use tokio::time::Instant;
use tracing::{info, error, warn, debug, instrument};

// Error handling because people are going to be assholes.
#[derive(Debug)]
pub enum GuardianError {
    QuotaExceeded(u64),      // Peer is spamming
    InvalidSignature(String), // Peer is lying
    ReplayDetected(u32),      // Peer is replaying old data
    WalWriteFailed(String),   // Disk IO failure
    SerializationError(String),
}

pub struct Guardian {
    pub vault_storage: PathBuf,
    pub wal_directory: PathBuf,

    // Tier 1: Reassembles Packets -> Evidence (Key: ShardId)
    pub micro_layer: Crucible<ShardAmalgam>,
    
    // Tier 2: Reassembles Evidence -> Volleys (Key: DID)
    pub macro_layer: Crucible<VolleyAmalgam>,
    
    // --- THE POLICY STATE ---
    pub processed_sequences: HashMap<Did, HashSet<StorageSequence>>,
    pub session_activity: HashMap<Did, Instant>,
    
    pub stale_threshold: std::time::Duration,

    // --- GOVERNANCE & QUOTAS ---
    pub local_did: Did,                     // "My" Identity
    pub max_storage_bytes: u64,                   // Total Limit
    pub max_foreign_storage_bytes: u64,           // Foreign Limit
    pub current_storage_usage: u64,         // Current Total Usage
    pub foreign_storage_usage: u64,         // Current Foreign Usage
}

impl Guardian {
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
            
            // Governance Init
            local_did,
            max_storage_bytes: config.storage.max_storage_bytes,
            max_foreign_storage_bytes: config.storage.max_foreign_storage_bytes,
            current_storage_usage: 0,
            foreign_storage_usage: 0,
        };
        
        guardian.calculate_initial_usage();
        guardian.recover_from_wal();
        guardian
    }

    /// Recursively calculate usage on startup
    fn calculate_initial_usage(&mut self) {
        let mut total = 0;
        let mut foreign = 0;
        let safe_local_did = self.local_did.to_safe_name();

        if let Ok(entries) = fs::read_dir(&self.vault_storage) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    // Check if this folder belongs to a foreigner
                    let folder_name = path.file_name().unwrap_or_default().to_string_lossy();
                    let is_foreign = folder_name != safe_local_did && folder_name != "wal";

                    // Sum files in this folder
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
        self.current_storage_usage = total;
        self.foreign_storage_usage = foreign;
        info!(
            total_mb = total / 1_000_000, 
            foreign_mb = foreign / 1_000_000, 
            "Storage governance initialized"
        );
    }

    /// Enforce Quotas: Delete oldest foreign data if limits exceeded
    fn prune_foreign_evidence(&mut self) {
        if self.foreign_storage_usage <= self.max_foreign_storage_bytes {
            info!(max_store = %self.max_foreign_storage_bytes, "No evidence to prune.");
            return;
        }

        warn!(
            usage = self.foreign_storage_usage, 
            limit = self.max_foreign_storage_bytes, 
            "Foreign storage quota exceeded. Pruning..."
        );

        // 1. Collect all foreign files with metadata
        let mut foreign_files = Vec::new();
        let safe_local_did = self.local_did.to_safe_name();

        if let Ok(entries) = fs::read_dir(&self.vault_storage) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let folder_name = path.file_name().unwrap_or_default().to_string_lossy();
                    // Skip My Data and WAL
                    if folder_name == safe_local_did || folder_name == "wal" { continue; }

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

        // 2. Sort by Age (Oldest First)
        foreign_files.sort_by_key(|k| k.2);

        // 3. Delete until under limit
        for (path, size, _) in foreign_files {
            if self.foreign_storage_usage <= self.max_foreign_storage_bytes {
                break;
            }

            if let Err(e) = fs::remove_file(&path) {
                error!(file = ?path, error = %e, "Failed to prune file");
            } else {
                warn!(file = ?path, size = size, "Evicted foreign evidence");
                self.foreign_storage_usage = self.foreign_storage_usage.saturating_sub(size);
                self.current_storage_usage = self.current_storage_usage.saturating_sub(size);
            }
        }
    }

    #[instrument(skip(self, chunk), level = "debug")]
    pub fn ingest_chunk(&mut self, chunk: ShardChunk) {

        info!(
            shard_id = %chunk.shard_id, 
            index = chunk.chunk_index, 
            total = chunk.total_chunks,
            "Micro-Layer receiving chunk"
        );

        if let Some(envelope) = self.micro_layer.process(chunk) {
            info!(
                shard_id = %envelope.evidence.sequence_id(), 
                "Micro-layer reassembly complete. Promoting to envelope."
            );

            if let Err(e) = self.ingest_envelope(envelope) {
                warn!(error = ?e, "Guardian rejected reassembled chunk");
            }
        }
    }

    pub fn ingest_envelope(&mut self, envelope: WitnessEnvelope) -> Result<(), GuardianError> {
        // 0. GOVERNANCE CHECK
        // If this is foreign data, ensure we have space.
        if envelope.did != self.local_did {
            // Trigger pruning if we are over limit (or close to it)
            if self.foreign_storage_usage > self.max_foreign_storage_bytes {
                self.prune_foreign_evidence();
                
                // Hard Reject if pruning failed to free enough space
                if self.foreign_storage_usage > self.max_foreign_storage_bytes {
                    warn!(did = %envelope.did, "Rejected foreign evidence: Storage Full");
                    return Err(GuardianError::QuotaExceeded(self.max_foreign_storage_bytes));
                }
            }
        }

        if let Err(e) = self.write_to_wal(&envelope) {
            error!(error = %e, "CRITICAL: WAL write failed.");
            return Err(GuardianError::WalWriteFailed(e.to_string()));
        }

        if !envelope.verify() { 
            error!(did = %envelope.did, "Rejected invalid signature"); 
            return Err(GuardianError::InvalidSignature(envelope.did.to_string()));
        }
        
        let did = envelope.did.clone();
        let seq = envelope.evidence.sequence_id();

        if self.processed_sequences.get(&did).is_some_and(|set| set.contains(&seq)) {
            debug!(%seq, "Replay protection: Dropping already archived shard.");
            return Ok(());
        }

        self.session_activity.insert(did.clone(), Instant::now());

        if let Some(volley) = self.macro_layer.process(envelope) {
            info!(volley = %volley.id, "Volley sealed. Archiving.");
            self.archive_volley(volley);
        }

        Ok(())
    }

    pub fn get_active_volley_shards(&self, did: &Did) -> Option<&std::collections::BTreeMap<StorageSequence, WitnessEnvelope>> {
        self.macro_layer.get(&did.to_string())
            .map(|buffer| &buffer.artifacts)
    }

    fn archive_volley(&mut self, volley: Volley) {
        info!(id = %volley.id, artifacts = volley.artifacts.len(), "Guardian: archive_volley called");

        if volley.artifacts.is_empty() { 
            warn!(id = %volley.id, "Guardian: Volley is empty! Aborting archive.");
            return; 
        }

        let safe_did = volley.owner_did.replace(":", "_");
        let archive_dir = self.vault_storage.join(&safe_did);

        if let Err(e) = fs::create_dir_all(&archive_dir) {
            error!(error = %e, path = ?archive_dir, "Failed to create archive directory");
            return;
        }

        let _ = fs::create_dir_all(&archive_dir);

        let did = Did(volley.owner_did.clone());
        let history = self.processed_sequences.entry(did).or_default();
        
        let mut wal_files_to_delete = Vec::new();

        for artifact in &volley.artifacts {
            history.insert(artifact.evidence.sequence_id());
            let safe_did_artifact = artifact.did.to_safe_name();
            let seq = artifact.evidence.sequence_id().0;
            let wal_filename = format!("{}_{}.wal", safe_did_artifact, seq);
            wal_files_to_delete.push(self.wal_directory.join(wal_filename));
        }

        let extension = match volley.artifacts[0].evidence {
            Evidence::Video(_) => "vid.phlx",
            Evidence::Audio(_) => "aud.phlx",
        };

        let final_filename = format!("{}.{}", volley.id, extension);
        let tmp_filename = format!("{}.tmp", volley.id);

        let final_path = archive_dir.join(&final_filename);
        let tmp_path = archive_dir.join(&tmp_filename);

        match postcard::to_stdvec(&volley) {
            Ok(bytes) => {
                let file_size = bytes.len() as u64;

                // 1. Write to .tmp
                if let Err(e) = fs::write(&tmp_path, bytes) {
                    error!(%e, "Failed to write temp archive file");
                } else {
                    // 2. Atomic Rename
                    if let Err(e) = fs::rename(&tmp_path, &final_path) {
                        error!(%e, "Failed to rename archive file");
                    } else {
                        info!(path = ?final_path, size = file_size, "Volley successfully archived");
                        
                        // 3. Update Governance Counters
                        self.current_storage_usage += file_size;
                        if safe_did != self.local_did.to_safe_name() {
                            self.foreign_storage_usage += file_size;
                        }

                        // 4. Cleanup WAL
                        for wal_path in wal_files_to_delete {
                            let _ = fs::remove_file(&wal_path);
                        }
                    }
                }
            }
            Err(e) => error!(%e, "Serialization error"),
        }
        info!(path = ?archive_dir, "Guardian: Archive Write Success");
    }

    pub fn archive_stale_sessions(&mut self, ttl: std::time::Duration) {
        // 1. Flush Micro Layer

        info!(ttl_ms = ttl.as_millis(), "Guardian: Running governance cleanup cycle");

        let recovered_envelopes = self.micro_layer.flush_stale(ttl);
        if !recovered_envelopes.is_empty() {
            warn!(count = recovered_envelopes.len(), "Guardian: Recovered stale micro-shards");
        }

        for env in recovered_envelopes {
            warn!(seq = %env.evidence.sequence_id(), "Salvaged incomplete shard.");
            // Swallow errors during internal clean up.
            _ = self.ingest_envelope(env);
        }

        // 2. Flush Macro Layer
        info!("Guardian: Checking Macro Layer for stale volleys...");
        let recovered_volleys = self.macro_layer.flush_stale(ttl);

        if !recovered_volleys.is_empty() {
            warn!(count = recovered_volleys.len(), "Guardian: Recovered stale VOLLEYS!");
        }

        for volley in recovered_volleys {
            warn!(id = %volley.id, "Force-archiving stale volley");
            self.archive_volley(volley);
        }
    }

    fn write_to_wal(&self, envelope: &WitnessEnvelope) -> std::io::Result<()> {
        let safe_did = envelope.did.to_safe_name();
        let file_name = format!("{}_{}.wal", safe_did, envelope.evidence.sequence_id().0);
        let wal_path = self.wal_directory.join(file_name);
        let bytes = postcard::to_stdvec(envelope).map_err(|e| 
            std::io::Error::new(std::io::ErrorKind::Other, e))?;
        
        let mut file = File::create(wal_path)?;
        file.write_all(&bytes)?;
        file.sync_all()?; // <--- Critical for test_guardian_crash_recovery
        Ok(())
    }

    fn recover_from_wal(&mut self) {
        if let Ok(entries) = fs::read_dir(&self.wal_directory) {
            for entry in entries.flatten() {
                let path = entry.path();
                if fs::metadata(&path).map(|m| m.len()).unwrap_or(0) == 0 { continue; }

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::{StorageConfig, NetworkConfig, HardwareConfig};
    use crate::security::identity::{PhalanxIdentity, NetworkId};
    use crate::protocol::shards::VideoShard;
    use std::fs::File;
    use std::io::Write;

    fn mock_config(max_foreign_bytes: u64) -> PhalanxConfig {
        PhalanxConfig {
            network: NetworkConfig { 
                heartbeat_interval_secs: 1, pulse_timeout_secs: 1, chunk_size_bytes: 100, 
                video_topic: "t".into(), audio_topic: "t".into(), control_topic: "t".into(), 
                grace_period: 1, cleanup_interval_secs: 1, 
                bootstrap_peers: vec![], guardian_service_key: "k".into() 
            },
            storage: StorageConfig {
                vault_path: "test_vault_governance".into(),
                max_video_buffer: 1, max_audio_buffer: 1, max_peers: 1, 
                stale_session_threshold: 1, shards_needed_to_archive: 1,
                max_storage_bytes: 100_000,
                max_foreign_storage_bytes: max_foreign_bytes, 
            },
            hardware: HardwareConfig { camera_fps: 1, audio_sample_rate: 1, audio_channels: 1 },
        }
    }

    #[test]
    fn test_governance_pruning() {
        use std::thread;
        let vault_root = PathBuf::from("test_vault_governance");
        let _ = fs::remove_dir_all(&vault_root);
        fs::create_dir_all(&vault_root).expect("Failed to create root");

        let me = PhalanxIdentity::generate();
        let stranger_1 = PhalanxIdentity::generate();
        let stranger_2 = PhalanxIdentity::generate();

        // 1. Create OLD Data (Stranger 1)
        let s1_dir = vault_root.join(stranger_1.did.to_safe_name());
        fs::create_dir_all(&s1_dir).expect("Failed to create s1 dir");
        let mut f1 = File::create(s1_dir.join("old_evidence.phlx")).expect("Failed to create f1");
        f1.write_all(&[0u8; 1000]).unwrap(); 
        f1.sync_all().unwrap(); 

        // FIX: Ensure distinct timestamp
        thread::sleep(std::time::Duration::from_millis(100));

        // 2. Create NEW Data (Stranger 2)
        let s2_dir = vault_root.join(stranger_2.did.to_safe_name());
        fs::create_dir_all(&s2_dir).expect("Failed to create s2 dir");
        let mut f2 = File::create(s2_dir.join("new_evidence.phlx")).expect("Failed to create f2");
        f2.write_all(&[0u8; 1000]).unwrap(); 
        f2.sync_all().unwrap(); 

        // 3. Init Guardian
        let config = mock_config(1500); 
        let mut guardian = Guardian::new("test_vault_governance", &config, me.did.clone());

        assert_eq!(guardian.foreign_storage_usage, 2000, "Initial usage calculation failed");

        // 4. Trigger Pruning
        guardian.prune_foreign_evidence(); 

        // 5. Verification
        assert!(!s1_dir.join("old_evidence.phlx").exists(), "Old evidence should be evicted");
        assert!(s2_dir.join("new_evidence.phlx").exists(), "New evidence should be kept");
        assert!(guardian.foreign_storage_usage <= 1500, "Usage should be under limit");
        
        let _ = fs::remove_dir_all(&vault_root);
    }

    #[test]
    fn test_invalid_signature_rejection() {
        let identity = PhalanxIdentity::generate();
        let _attacker = PhalanxIdentity::generate(); // Different key!
        let peer_id = NetworkId::random();
        let config = PhalanxConfig::default();
        let vault_path = "sim_vault/test_sig_reject";
        let _ = std::fs::remove_dir_all(vault_path);

        let mut guardian = Guardian::new(vault_path, &config, identity.did.clone());

        // 1. Create a Shard
        let shard = VideoShard {
            volley_id: "v1".to_string(),
            timestamp: 100,
            frames: vec![vec![1]],
            sequence_id: StorageSequence(1),
            fps: 30,
        };

        // 2. Sign it with the WRONG identity (Attacker signs, claims to be Victim?)
        // Actually, WitnessEnvelope::new signs with the 'owner' passed in.
        // To forge it, we need to tamper with the payload AFTER signing.
        let mut envelope = WitnessEnvelope::new(Evidence::Video(shard), &identity, peer_id);
        
        // 3. TAMPER: Modify the payload without updating the signature
        if let Evidence::Video(ref mut v) = envelope.evidence {
            v.timestamp = 999999; // Malicious timestamp edit
        }

        // 4. Ingest & Assert Failure
        let result = guardian.ingest_envelope(envelope);
        
        assert!(result.is_err(), "Guardian accepted a tampered envelope!");
        match result {
            Err(GuardianError::InvalidSignature(_)) => (), // Pass
            _ => panic!("Wrong error type returned"),
        }
    }

    #[test]
    fn test_governance_rejection() {
        let identity = PhalanxIdentity::generate();
        let stranger = PhalanxIdentity::generate();
        let peer_id = NetworkId::random();
        
        // 1. Setup Config with TINY limit (0 bytes)
        let mut config = PhalanxConfig::default();
        config.storage.max_foreign_storage_bytes = 0; // Strict mode
        
        let vault_path = "sim_vault/test_quota_reject";
        let _ = std::fs::remove_dir_all(vault_path);
        
        let mut guardian = Guardian::new(vault_path, &config, identity.did.clone());

        // 2. Artificially inflate usage to simulate a "stuck" state
        // (Simulating a state where pruning failed to free space)
        guardian.foreign_storage_usage = 1000; 

        let shard = VideoShard {
            volley_id: "v1".to_string(),
            timestamp: 100,
            frames: vec![vec![1]],
            sequence_id: StorageSequence(1),
            fps: 30,
        };
        let envelope = WitnessEnvelope::new(Evidence::Video(shard), &stranger, peer_id);

        // 3. Ingest Foreign Data
        let result = guardian.ingest_envelope(envelope);

        // 4. Assert Quota Error
        assert!(result.is_err(), "Guardian ignored quota limits!");
        match result {
            Err(GuardianError::QuotaExceeded(limit)) => assert_eq!(limit, 0),
            _ => panic!("Wrong error type"),
        }
    }

    #[test]
    fn test_replay_protection() {
        let identity = PhalanxIdentity::generate();
        let peer_id = NetworkId::random();
        let config = PhalanxConfig::default();
        let vault_path = "sim_vault/test_replay";
        let _ = std::fs::remove_dir_all(vault_path);

        let mut guardian = Guardian::new(vault_path, &config, identity.did.clone());

        let seq_num = StorageSequence(50);
        let shard = VideoShard {
            volley_id: "v1".to_string(),
            timestamp: 100,
            frames: vec![vec![1]],
            sequence_id: seq_num, 
            fps: 30,
        };
        let envelope = WitnessEnvelope::new(Evidence::Video(shard), &identity, peer_id);

        // 1. MANUALLY SEED HISTORY
        // Simulate that Sequence #50 was already archived in the past.
        guardian.processed_sequences
            .entry(identity.did.clone())
            .or_default()
            .insert(seq_num);

        // 2. Ingest the "Replay" Envelope
        // The Replay Guard should catch this and return Ok() immediately.
        assert!(guardian.ingest_envelope(envelope).is_ok());

        // 3. Verify it was BLOCKED
        // If it was blocked, it should NOT be in the active macro layer buffer.
        let active_session = guardian.get_active_volley_shards(&identity.did);
        assert!(active_session.is_none(), "Replayed envelope leaked into active buffer!");
    }

    #[test]
    fn test_initial_usage_scan() {
        let identity = PhalanxIdentity::generate();
        let stranger = PhalanxIdentity::generate();
        let config = PhalanxConfig::default();
        let vault_path = "sim_vault/test_init_scan";
        let _ = std::fs::remove_dir_all(vault_path);
        
        // 1. Pre-seed the disk with data
        let stranger_dir = std::path::PathBuf::from(vault_path).join(stranger.did.to_safe_name());
        std::fs::create_dir_all(&stranger_dir).unwrap();
        std::fs::write(stranger_dir.join("test.bin"), vec![0u8; 500]).unwrap(); // 500 bytes

        // 2. Boot Guardian
        let guardian = Guardian::new(vault_path, &config, identity.did.clone());

        // 3. Assert Usage Detected
        assert_eq!(guardian.current_storage_usage, 500);
        assert_eq!(guardian.foreign_storage_usage, 500);
    }
}