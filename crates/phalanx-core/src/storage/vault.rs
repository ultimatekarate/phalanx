use crate::base::config::PhalanxConfig;
use crate::base::types::{ByteCapacity, TrafficGovernor, UnitInterval};
use crate::primitives::identity::Did;
use crate::primitives::shards::{Evidence, ShardChunk, StorageSequence, Volley, WitnessEnvelope};
use crate::primitives::time::TrustedClock;
use crate::storage::crucible::Crucible;
use crate::storage::strategies::{ShardAmalgam, VolleyAmalgam};

use crate::primitives::time::TimeError;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use tokio::time::Instant;
use tracing::{debug, error, info, instrument, warn};

/// Enumerates specific failure modes for storage and security operations.
///
/// * `QuotaExceeded`: A foreign peer has pushed the node over its `max_foreign_storage_bytes`.
/// * `InvalidSignature`: Cryptographic verification failed (potential tampering).
/// * `ReplayDetected`: The sequence ID or timestamp indicates an attempt to reuse old data.
/// * `WalWriteFailed`: Critical IO failure (disk full or permissions).
#[derive(Debug, thiserror::Error)]
pub enum GuardianError {
    #[error("Quota exceeded: {0:?}")]
    QuotaExceeded(ByteCapacity),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Replay attack detected: Sequence {0} is too old")]
    ReplayDetected(u64), // Updated to u64 to match standard sequence_id()

    #[error("WAL write failed: {0}")]
    WalWriteFailed(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    // The Sentinel Bridge for Time
    #[error("Time synchronization failure: {0}")]
    TimeSource(#[from] TimeError),
}

/// Tracks the behavior of remote peers to prevent "Vampire Attacks" (Resource Exhaustion).
///
/// If `invalid_sigs` exceeds `max_sig_failures`, `is_blacklisted` becomes true,
/// causing the Guardian to silently drop all future traffic from that DID.
#[derive(Debug, Default, Clone)]
pub struct PeerReputation {
    pub invalid_sigs: u32,
    pub is_blacklisted: bool,
}

/// The central storage controller and policy enforcer.
///
/// Responsibilities:
/// 1. **Reassembly**: Manages `Crucible` instances for Micro (Chunk) and Macro (Volley) layers.
/// 2. **Governance**: Enforces storage quotas and evicts old foreign data.
/// 3. **Security**: Verifies signatures and tracks peer reputation.
/// 4. **Persistence**: Manages the Write-Ahead Log (WAL) and final archiving.
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
    pub local_did: Did,                          // "My" Identity
    pub max_storage_bytes: ByteCapacity,         // Total Limit
    pub max_foreign_storage_bytes: ByteCapacity, // Foreign Limit
    pub current_storage_usage: ByteCapacity,     // Current Total Usage
    pub foreign_storage_usage: ByteCapacity,     // Current Foreign Usage

    pub clock: TrustedClock,

    pub governor: TrafficGovernor,
}

impl Guardian {
    /// Initializes the storage vault, recovers state from the Write-Ahead Log (WAL),
    /// and performs an initial filesystem scan to calculate current usage.
    ///
    /// # Side Effects
    /// * Creates `vault_path` and `vault_path/wal` if they do not exist.
    /// * Populates `current_storage_usage` and `foreign_storage_usage` by scanning disk.
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

            governor: TrafficGovernor::new(),
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

    /// Enforces storage limits by evicting the oldest foreign data.
    ///
    /// *Strategy*: "Oldest-File-First" eviction.
    /// *Constraint*: Never deletes "Local" (Own) data or WAL files.
    /// *Trigger*: Called automatically by `ingest_envelope` when `foreign_storage_usage` exceeds limits.
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

    /// Stage 1: Ingests raw network chunks (Micro-Layer).
    ///
    /// This method acts as the primary firewall for the storage layer. It applies:
    /// 1. **Power Governance**: Checks `TrafficGovernor` to see if we should accept foreign data.
    /// 2. **Leaf Mode**: If active, rejects all foreign chunks to save battery.
    /// 3. **Circuit Breaking**: If memory load > 80%, sheds foreign load.
    /// 4. **Reputation Check**: Silently drops chunks from blacklisted peers.
    ///
    /// If a chunk completes a shard, it is promoted to `ingest_envelope`.
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
            self.governor
                .set_state(crate::base::types::PowerState::Leaf);
        } else {
            self.governor
                .set_state(crate::base::types::PowerState::Normal);
        }

        // 2. CENTRALIZED SECURITY CHECK
        // "Method Injection": We provide the subject (chunk owner) and context (self)
        if !self
            .governor
            .should_accept(&chunk.owner_did, &self.local_did)
        {
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

        let load_factor = self.calculate_load();

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

        let active_sessions = self
            .processed_sequences
            .get(&owner)
            .map(|s| s.len())
            .unwrap_or(0);
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

    /// Stage 2: Ingests reassembled Witness Envelopes (Macro-Layer).
    ///
    /// Performed on full, reassembled shards. It applies:
    /// 1. **Cryptographic Verification**: Checks Ed25519 signatures.
    /// 2. **Quota Enforcement**: Prunes old foreign data if limits are hit.
    /// 3. **Replay Protection**: Checks timestamps and sequence IDs against history.
    /// 4. **WAL Persistence**: Writes the verified envelope to the Write-Ahead Log.
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
        let clock = TrustedClock::new();
        let is_valid_time = envelope
            .evidence
            .timestamp()
            .verify_freshness(&clock, tolerance)
            .is_ok();

        if !is_valid_time {
            // 2. Safe Time Retrieval for Logging
            // We attempt to get the current time for the log, but if it fails,
            // we use a placeholder to avoid crashing inside the error handler.
            let current_time_log = self.clock.now().unwrap_or(0);

            warn!(
                did = %envelope.did,
                claim = envelope.evidence.timestamp().as_u64(),
                now = current_time_log,
                "Rejected Time-Travel/Replay Attack"
            );

            // 3. Specific Error Variant
            return Err(GuardianError::ReplayDetected(
                envelope.evidence.sequence_id().0 as u64,
            ));
        }

        if let Err(e) = self.write_to_wal(&envelope) {
            error!(error = %e, "CRITICAL: WAL write failed.");
            return Err(GuardianError::WalWriteFailed(e.to_string()));
        }

        let did = envelope.did.clone();
        let seq = envelope.evidence.sequence_id();

        if self
            .processed_sequences
            .get(&did)
            .is_some_and(|set| set.contains(&seq))
        {
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

    /// Calculates the current storage pressure.
    /// Returns a strictly bounded `UnitInterval` (0.0 to 1.0).
    fn calculate_load(&self) -> UnitInterval {
        // Numerical precision matters. Let's not be lazy.
        let micro_len = self.micro_layer.len() as f64;
        let macro_len = self.macro_layer.len() as f64;

        // Use f64 constants for calculation precision
        let micro_cap = (self.max_buffers_per_peer as f64) * 5.0;
        let macro_cap = self.max_buffers_per_peer as f64;

        // Prevent division by zero
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

        // Combine logic (Simple Sum for now)
        let total_raw = micro_load + macro_load;

        // Combine and clamp to 1.0
        UnitInterval::new(total_raw.min(1.0) as f32)
    }

    /// Increments the violation count for a specific Peer DID.
    ///
    /// If the count exceeds `max_sig_failures`, the peer is permanently blacklisted
    /// in memory, preventing further resource consumption.
    pub fn penalize_peer(&mut self, did: Did, reason: &str) {
        let rep = self.peer_registry.entry(did.clone()).or_default();
        rep.invalid_sigs += 1;

        warn!(%did, %reason, count = rep.invalid_sigs, "Peer penalized for bad behavior.");

        if rep.invalid_sigs >= self.max_sig_failures {
            rep.is_blacklisted = true;
            warn!(%did, "PEER BLACKLISTED: Vampire attack detected.");
        }
    }

    pub fn get_active_volley_shards(
        &self,
        did: &Did,
    ) -> Option<&std::collections::BTreeMap<StorageSequence, WitnessEnvelope>> {
        self.macro_layer
            .get(&did.to_string())
            .map(|buffer| &buffer.artifacts)
    }

    /// Finalizes a `Volley` (collection of shards) into a permanent archive file.
    ///
    /// 1. Serializes the Volley to a temporary file (`.tmp`).
    /// 2. Performs an atomic rename to the final `.phlx` extension.
    /// 3. Deletes the corresponding entries from the WAL.
    /// 4. Updates governance counters.
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

    /// Maintenance cycle to clean up incomplete or abandoned upload sessions.
    ///
    /// 1. Checks both Micro and Macro layers for items older than `ttl`.
    /// 2. Flushes them from memory.
    /// 3. Attempts to salvage/archive whatever data is present (even if incomplete).
    pub fn archive_stale_sessions(&mut self, ttl: std::time::Duration) {
        // 1. Flush Micro Layer

        info!(
            ttl_ms = ttl.as_millis(),
            "Guardian: Running governance cleanup cycle"
        );

        let recovered_envelopes = self.micro_layer.flush_stale(ttl);
        if !recovered_envelopes.is_empty() {
            warn!(
                count = recovered_envelopes.len(),
                "Guardian: Recovered stale micro-shards"
            );
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
            warn!(
                count = recovered_volleys.len(),
                "Guardian: Recovered stale VOLLEYS!"
            );
        }

        for volley in recovered_volleys {
            warn!(id = %volley.id, "Force-archiving stale volley");
            self.archive_volley(volley);
        }
    }

    /// Writes a verified envelope to the Write-Ahead Log (WAL).
    ///
    /// Uses `file.sync_all()` to ensure physical disk persistence before acknowledging
    /// receipt, protecting against power loss during ingestion.
    fn write_to_wal(&self, envelope: &WitnessEnvelope) -> std::io::Result<()> {
        let safe_did = envelope.did.to_safe_name();
        let file_name = format!("{}_{}.wal", safe_did, envelope.evidence.sequence_id().0);
        let wal_path = self.wal_directory.join(file_name);
        let bytes = postcard::to_stdvec(envelope).map_err(std::io::Error::other)?;

        let mut file = File::create(wal_path)?;
        file.write_all(&bytes)?;
        file.sync_all()?; // <--- Critical for test_guardian_crash_recovery
        Ok(())
    }

    fn recover_from_wal(&mut self) {
        if let Ok(entries) = fs::read_dir(&self.wal_directory) {
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
        let shard = shards::create_video_shard(frames, seq_num, 30, "v1".into())?;
        let envelope = WitnessEnvelope::new(Evidence::Video(shard), &identity, peer_id)?;

        // 1. MANUALLY SEED HISTORY
        guardian
            .processed_sequences
            .entry(identity.did.clone())
            .or_default()
            .insert(seq_num);

        // 2. Ingest the "Replay" Envelope
        assert!(guardian.ingest_envelope(envelope).is_ok());

        // 3. Verify it was BLOCKED
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

    #[test]
    fn test_vampire_blacklisting() -> Result<(), Box<dyn std::error::Error>> {
        let (me, _) = PhalanxIdentity::generate()?;
        let (vampire, _) = PhalanxIdentity::generate()?;
        let config = PhalanxConfig::default();
        let mut guardian = Guardian::new("sim_vault/vampire_test", &config, me.did.clone());

        // 1. Send multiple invalid signatures
        for _ in 0..6 {
            let shard = crate::primitives::shards::create_video_shard(
                vec![vec![1]],
                StorageSequence(1),
                30,
                "v1".into(),
            )?;
            let mut envelope =
                WitnessEnvelope::new(Evidence::Video(shard), &vampire, NetworkId::random())?;

            // TAMPER
            if let Evidence::Video(ref mut v) = envelope.evidence {
                v.fps = 99;
            }

            let _ = guardian.ingest_envelope(envelope);
        }

        // 2. Verify blacklisted
        // Safe Option unwrap
        let rep = guardian
            .peer_registry
            .get(&vampire.did)
            .ok_or("Expected vampire DID in registry")?;

        assert!(rep.is_blacklisted);
        Ok(())
    }
}

#[cfg(test)]
mod guardian_leaf_tests {
    use super::*;
    use crate::primitives::identity::{NetworkId, PhalanxIdentity};
    use crate::primitives::shards::{
        self, ChunkType, Evidence, ShardId, StorageSequence, WitnessEnvelope,
    };

    #[tokio::test]
    async fn test_guardian_leaf_mode_ingestion() -> Result<(), Box<dyn std::error::Error>> {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init(); // Safe to ignore if init fails (already init)

        let (identity, _) = PhalanxIdentity::generate()?;
        let config = PhalanxConfig::default();
        let vault_path = "sim_vault/leaf_unit_test";

        if std::path::Path::new(vault_path).exists() {
            std::fs::remove_dir_all(vault_path)?;
        }

        let mut guardian = Guardian::new(vault_path, &config, identity.did.clone());

        // 1. Create a REAL forensic unit (Video Shard)
        let frames = vec![vec![1, 2, 3]];
        let shard =
            shards::create_video_shard(frames, StorageSequence(200), 30, "volley_test".into())?;

        // 2. WRAP in an Envelope
        let envelope =
            WitnessEnvelope::new(Evidence::Video(shard), &identity, NetworkId::random())?;

        // 3. Serialize the FULL ENVELOPE (Safe Propagation)
        let envelope_bytes = postcard::to_stdvec(&envelope)?;

        // 4. Create chunks from the ENVELOPE bytes
        let local_chunk = shards::ShardChunk {
            shard_id: ShardId(200),
            chunk_index: 0,
            total_chunks: 1,
            data: envelope_bytes,
            owner_did: identity.did.clone(),
            chunk_type: ChunkType::Witnessed,
        };

        // 5. Ingest while Leaf Mode is ACTIVE
        let is_leaf_mode = true;
        guardian.ingest_chunk(local_chunk, is_leaf_mode);

        // 6. Verification
        assert_eq!(
            guardian.micro_layer.len(),
            0,
            "Micro-layer should be empty after successful sealing and promotion"
        );

        if std::path::Path::new(vault_path).exists() {
            std::fs::remove_dir_all(vault_path)?;
        }
        Ok(())
    }
}
