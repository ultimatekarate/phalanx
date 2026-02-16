use crate::base::types::{ByteCapacity, TrafficGovernor};
use crate::primitives::shards::{StorageSequence, Evidence, WitnessEnvelope, ShardChunk};
use crate::storage::crucible::{Crucible};
use crate::storage::strategies::{ShardAmalgam, VolleyAmalgam, Volley}; 
use crate::base::config::PhalanxConfig;
use crate::primitives::identity::Did;
use crate::primitives::time::TrustedClock;

use std::collections::{HashSet, HashMap};
use std::fs::{self, File};
use std::io::Write;
use std::fmt;
use std::path::PathBuf;
use tokio::time::Instant;
use tracing::{info, error, warn, debug, instrument};

// Error handling because people are going to be assholes.
#[derive(Debug)]
pub enum GuardianError {
    QuotaExceeded(ByteCapacity),      // Peer is spamming
    InvalidSignature(String), // Peer is lying
    ReplayDetected(u32),      // Peer is replaying old data
    WalWriteFailed(String),   // Disk IO failure
    SerializationError(String),
}

impl fmt::Display for GuardianError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QuotaExceeded(cap) => write!(f, "Storage quota exceeded. Current usage: {:?}", cap),
            Self::InvalidSignature(did) => write!(f, "Invalid signature detected from DID: {}", did),
            Self::ReplayDetected(seq) => write!(f, "Replay attack prevented. Sequence ID: {}", seq),
            Self::WalWriteFailed(path) => write!(f, "Write Ahead Log failure at path: {}", path),
            Self::SerializationError(msg) => write!(f, "Serialization failure: {}", msg),
        }
    }
}

impl std::error::Error for GuardianError {}

#[derive(Debug, Default, Clone)]
pub struct PeerReputation {
    pub invalid_sigs: u32,
    pub is_blacklisted: bool,
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

    // --- ANTI-VAMPIRE STATE ---
    // This is a no shithead zone.
    pub peer_registry: HashMap<Did, PeerReputation>,
    pub max_buffers_per_peer: usize, // concurrent reassembly sessions
    pub max_sig_failures: u32,       // threshold before blacklisting

    // --- GOVERNANCE & QUOTAS ---
    pub local_did: Did,                     // "My" Identity
    pub max_storage_bytes: ByteCapacity,                   // Total Limit
    pub max_foreign_storage_bytes: ByteCapacity,           // Foreign Limit
    pub current_storage_usage: ByteCapacity,         // Current Total Usage
    pub foreign_storage_usage: ByteCapacity,         // Current Foreign Usage

    pub clock: TrustedClock,

    pub governor: TrafficGovernor,
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
            
            peer_registry: HashMap::new(),
            max_buffers_per_peer: config.storage.max_peers,
            max_sig_failures: 5, // magic constant for now

            // Governance Init
            local_did,
            max_storage_bytes: config.storage.max_storage_bytes,
            max_foreign_storage_bytes: config.storage.max_foreign_storage_bytes,
            current_storage_usage: ByteCapacity(0),
            foreign_storage_usage: ByteCapacity(0),
            clock: TrustedClock::new(),

            governor: TrafficGovernor::new()
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
        self.current_storage_usage = ByteCapacity(total);
        self.foreign_storage_usage = ByteCapacity(foreign);
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
            usage = %self.foreign_storage_usage, 
            limit = %self.max_foreign_storage_bytes, 
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
    pub fn ingest_chunk(&mut self, chunk: ShardChunk, is_leaf_mode: bool) {

        debug!(
            is_leaf = %is_leaf_mode,
            chunk_owner = %chunk.owner_did,
            local_identity = %self.local_did,
            match_found = %(chunk.owner_did == self.local_did),
            "Ingestion Decision Gate"
        );

        // 1. SYNC STATE
        // Ensure Governor matches the Sentinel's decision from the main loop
        if is_leaf_mode {
            self.governor.set_state(crate::base::types::PowerState::Leaf);
        } else {
            self.governor.set_state(crate::base::types::PowerState::Normal);
        }

        // 2. CENTRALIZED SECURITY CHECK
        // "Method Injection": We provide the subject (chunk owner) and context (self)
        if !self.governor.should_accept(&chunk.owner_did, &self.local_did) {
            warn!(did = %chunk.owner_did, "TrafficGovernor: Shedding foreign storage task");
            return;
        }
        // Leaf-mode circuit breaker
        if is_leaf_mode && chunk.owner_did != self.local_did {
            warn!(
                did = %chunk.owner_did, 
                "Leaf Mode Active: Shedding foreign chunk"
            );
            return; 
        }

        let owner = chunk.owner_did.clone();

        info!(
            shard_id = %chunk.shard_id, 
            index = chunk.chunk_index, 
            total = chunk.total_chunks,
            "Micro-Layer receiving chunk"
        );
        
        let micro_load = self.micro_layer.len() as f32 / (self.max_buffers_per_peer * 5) as f32;
        let macro_load = self.macro_layer.len() as f32 / self.max_buffers_per_peer as f32;
        let load_factor = (micro_load + macro_load).clamp(0.0, 1.0);

        // 2. CIRCUIT BREAKER
        // If load is > 80%, stop accepting new foreign reassemblies to save local resources.
        if load_factor > 0.8 && chunk.owner_did != self.local_did {
            warn!(load = %load_factor, did = %chunk.owner_did, "Circuit Breaker: Shedding foreign load");
            return;
        }
        
        if let Some(rep) = self.peer_registry.get(&owner) {
            if rep.is_blacklisted {
                debug!(did = %owner, "Dropping chunk: Peer is blacklisted.");
                return;
            }
        }

        let active_sessions = self.processed_sequences.get(&owner).map(|s| s.len()).unwrap_or(0);
        if active_sessions >= self.max_buffers_per_peer {
            warn!(did = %owner, "Dropping chunk: Peer exceeded concurrent session quota.");
            return;
        }

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
        
        // Verify that the signature is valid before doing anything else
        if !envelope.verify() { 
            self.penalize_peer(envelope.did.clone(), "Invalid Signature");
            error!(did = %envelope.did, "Rejected invalid signature."); 
            return Err(GuardianError::InvalidSignature(envelope.did.to_string()));
        }
        

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

        // Allow +/- 10 seconds drift (generous for WAN, tight enough to stop replay)
        let tolerance = 10; 
        if !self.clock.is_valid(envelope.evidence.timestamp(), tolerance) {
            warn!(
                did = %envelope.did, 
                claim = envelope.evidence.timestamp(), 
                now = self.clock.now(),
                "Rejected Time-Travel/Replay Attack"
            );
            // We reuse InvalidSignature for now, or add a new variant TimeSyncFailure
            return Err(GuardianError::ReplayDetected(envelope.evidence.sequence_id().0));
        }

        if let Err(e) = self.write_to_wal(&envelope) {
            error!(error = %e, "CRITICAL: WAL write failed.");
            return Err(GuardianError::WalWriteFailed(e.to_string()));
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

    pub fn penalize_peer(&mut self, did: Did, reason: &str) {
        let rep = self.peer_registry.entry(did.clone()).or_default();
        rep.invalid_sigs += 1;
        
        warn!(%did, %reason, count = rep.invalid_sigs, "Peer penalized for bad behavior.");

        if rep.invalid_sigs >= self.max_sig_failures {
            rep.is_blacklisted = true;
            warn!(%did, "PEER BLACKLISTED: Vampire attack detected.");
        }
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
    use crate::base::config::{StorageConfig, NetworkConfig, HardwareConfig};
    use crate::primitives::identity::{PhalanxIdentity, NetworkId};
    use crate::primitives::shards;
    use std::fs::File;
    use std::io::Write;

    fn mock_config(max_foreign_bytes: ByteCapacity) -> PhalanxConfig {
        PhalanxConfig {
            network: NetworkConfig { 
                max_chunk_size_bytes: 100, 
                video_topic: "t".into(), 
                audio_topic: "t".into(), 
                control_topic: "t".into(), 
                cleanup_interval_secs: 1, 
                bootstrap_peers: vec![], guardian_service_key: "k".into() ,
                protocol_version: "v0.1.0".to_string(),

            },
            storage: StorageConfig {
                vault_path: "test_vault_governance".into(),
                max_video_buffer: 1, max_audio_buffer: 1, max_peers: 1, 
                stale_session_threshold: 1, shards_needed_to_archive: 1,
                max_storage_bytes: ByteCapacity(100_000),
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

        let (me, _) = PhalanxIdentity::generate();
        let (stranger_1, _) = PhalanxIdentity::generate();
        let (stranger_2, _) = PhalanxIdentity::generate();

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
        let config = mock_config(ByteCapacity(1500)); 
        let mut guardian = Guardian::new("test_vault_governance", &config, me.did.clone());

        assert_eq!(guardian.foreign_storage_usage, ByteCapacity(2000), "Initial usage calculation failed");

        // 4. Trigger Pruning
        guardian.prune_foreign_evidence(); 

        // 5. Verification
        assert!(!s1_dir.join("old_evidence.phlx").exists(), "Old evidence should be evicted");
        assert!(s2_dir.join("new_evidence.phlx").exists(), "New evidence should be kept");
        assert!(guardian.foreign_storage_usage <= ByteCapacity(1500), "Usage should be under limit");
        
        let _ = fs::remove_dir_all(&vault_root);
    }

    #[test]
    fn test_invalid_signature_rejection() {
        let (identity, _) = PhalanxIdentity::generate();
        let _attacker = PhalanxIdentity::generate(); // Different key!
        let peer_id = NetworkId::random();
        let config = PhalanxConfig::default();
        let vault_path = "sim_vault/test_sig_reject";
        let _ = std::fs::remove_dir_all(vault_path);

        let mut guardian = Guardian::new(vault_path, &config, identity.did.clone());

        // 1. Create a Shard using constructor
        let frames = vec![vec![1]];
        let shard = shards::create_video_shard(
            frames, 
            StorageSequence(1), 
            30, 
            "v1".into()
        );

        // 2. Sign it with the WRONG identity (Attacker signs, claims to be Victim?)
        let mut envelope = WitnessEnvelope::new(Evidence::Video(shard), &identity, peer_id);
        
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
    }

    #[test]
    fn test_governance_rejection() {
        let (identity, _) = PhalanxIdentity::generate();
        let (stranger, _) = PhalanxIdentity::generate();
        let peer_id = NetworkId::random();
        
        // 1. Setup Config with TINY limit (0 bytes)
        let mut config = PhalanxConfig::default();
        config.storage.max_foreign_storage_bytes = ByteCapacity(0); // Strict mode
        
        let vault_path = "sim_vault/test_quota_reject";
        let _ = std::fs::remove_dir_all(vault_path);
        
        let mut guardian = Guardian::new(vault_path, &config, identity.did.clone());

        // 2. Artificially inflate usage to simulate a "stuck" state
        guardian.foreign_storage_usage = ByteCapacity(1000); 

        let frames = vec![vec![1]];
        let shard = shards::create_video_shard(
            frames, 
            StorageSequence(1), 
            30, 
            "v1".into()
        );
        let envelope = WitnessEnvelope::new(Evidence::Video(shard), &stranger, peer_id);

        // 3. Ingest Foreign Data
        let result = guardian.ingest_envelope(envelope);

        // 4. Assert Quota Error
        assert!(result.is_err(), "Guardian ignored quota limits!");
        match result {
            Err(GuardianError::QuotaExceeded(limit)) => assert_eq!(limit, ByteCapacity(0)),
            _ => panic!("Wrong error type"),
        }
    }

    #[test]
    fn test_replay_protection() {
        let (identity, _) = PhalanxIdentity::generate();
        let peer_id = NetworkId::random();
        let config = PhalanxConfig::default();
        let vault_path = "sim_vault/test_replay";
        let _ = std::fs::remove_dir_all(vault_path);

        let mut guardian = Guardian::new(vault_path, &config, identity.did.clone());

        let seq_num = StorageSequence(50);
        let frames = vec![vec![1]];
        let shard = shards::create_video_shard(
            frames,
            seq_num,
            30,
            "v1".into()
        );
        let envelope = WitnessEnvelope::new(Evidence::Video(shard), &identity, peer_id);

        // 1. MANUALLY SEED HISTORY
        guardian.processed_sequences
            .entry(identity.did.clone())
            .or_default()
            .insert(seq_num);

        // 2. Ingest the "Replay" Envelope
        assert!(guardian.ingest_envelope(envelope).is_ok());

        // 3. Verify it was BLOCKED
        let active_session = guardian.get_active_volley_shards(&identity.did);
        assert!(active_session.is_none(), "Replayed envelope leaked into active buffer!");
    }

    #[test]
    fn test_initial_usage_scan() {
        let (identity, _) = PhalanxIdentity::generate();
        let (stranger, _) = PhalanxIdentity::generate();
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
        assert_eq!(guardian.current_storage_usage, ByteCapacity(500));
        assert_eq!(guardian.foreign_storage_usage, ByteCapacity(500));
    }

    #[test]
    fn test_vampire_blacklisting() {
        let (me, _) = PhalanxIdentity::generate();
        let (vampire, _) = PhalanxIdentity::generate();
        let config = PhalanxConfig::default();
        let mut guardian = Guardian::new("sim_vault/vampire_test", &config, me.did.clone());

        // 1. Send multiple invalid signatures
        for _ in 0..6 {
            let shard = crate::primitives::shards::create_video_shard(
                vec![vec![1]], StorageSequence(1), 30, "v1".into()
            );
            let mut envelope = WitnessEnvelope::new(Evidence::Video(shard), &vampire, NetworkId::random());
            
            // TAMPER
            if let Evidence::Video(ref mut v) = envelope.evidence { v.fps = 99; }
            
            _ = guardian.ingest_envelope(envelope);
        }

        // 2. Verify blacklisted
        let rep = guardian.peer_registry.get(&vampire.did).unwrap();
        assert!(rep.is_blacklisted);
    }
}

#[cfg(test)]
mod guardian_leaf_tests {
    use super::*;
    use crate::primitives::identity::{PhalanxIdentity, NetworkId};
    use crate::primitives::shards::{self, ShardId, StorageSequence, Evidence, WitnessEnvelope, ChunkType};

    #[tokio::test] // Use tokio::test for Instant::now() compatibility
    async fn test_guardian_leaf_mode_ingestion() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();

        let (identity, _) = PhalanxIdentity::generate();
        let config = PhalanxConfig::default();
        let vault_path = "sim_vault/leaf_unit_test";
        
        let _ = std::fs::remove_dir_all(vault_path);
        let mut guardian = Guardian::new(vault_path, &config, identity.did.clone());

        // 1. Create a REAL forensic unit (Video Shard)
        let frames = vec![vec![1, 2, 3]];
        let shard = shards::create_video_shard(
            frames, 
            StorageSequence(200), 
            30, 
            "volley_test".into()
        );

        // 2. WRAP in an Envelope
        // ShardAmalgam strategy expects to deserialize a WitnessEnvelope, not a Shard
        let envelope = WitnessEnvelope::new(
            Evidence::Video(shard), 
            &identity, 
            NetworkId::random()
        );

        // 3. Serialize the FULL ENVELOPE
        let envelope_bytes = postcard::to_stdvec(&envelope)
            .expect("Failed to serialize envelope");

        // 4. Create chunks from the ENVELOPE bytes
        let local_chunk = shards::ShardChunk {
            shard_id: ShardId(200),
            chunk_index: 0,
            total_chunks: 1,
            data: envelope_bytes, // This is now the full signed data
            owner_did: identity.did.clone(),
            chunk_type: ChunkType::Witnessed,
        };

        // 5. Ingest while Leaf Mode is ACTIVE
        let is_leaf_mode = true;
        guardian.ingest_chunk(local_chunk, is_leaf_mode);

        // 6. Verification
        // If successful, the Crucible seals it and the micro_layer length returns to 0
        assert_eq!(
            guardian.micro_layer.len(), 
            0, 
            "Micro-layer should be empty after successful sealing and promotion"
        );

        let _ = std::fs::remove_dir_all(vault_path);
    }
}
