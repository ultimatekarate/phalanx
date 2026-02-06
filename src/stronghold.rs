use crate::shards::{StorageSequence, Evidence, WitnessEnvelope, ShardChunk};
use crate::crucible::{Crucible};
use crate::strategies::{ShardAmalgam, VolleyAmalgam, Volley}; 
use crate::config::PhalanxConfig;
use crate::identity::Did;

use std::collections::{HashSet, HashMap};
use std::fs;
use std::path::PathBuf;
use tokio::time::Instant;
use tracing::{info, error, warn, debug, instrument};

pub struct Stronghold {
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
    pub max_storage: u64,                   // Total Limit
    pub max_foreign_storage: u64,           // Foreign Limit
    pub current_storage_usage: u64,         // Current Total Usage
    pub foreign_storage_usage: u64,         // Current Foreign Usage
}

impl Stronghold {
    pub fn new(vault_path: &str, config: &PhalanxConfig, local_did: Did) -> Self {
        let root = PathBuf::from(vault_path);
        let wal = root.join("wal");
        let _ = fs::create_dir_all(&root);
        let _ = fs::create_dir_all(&wal);

        let mut stronghold = Self {
            vault_storage: root,
            wal_directory: wal,
            micro_layer: Crucible::new(),
            macro_layer: Crucible::new(),
            processed_sequences: HashMap::new(),
            session_activity: HashMap::new(),
            stale_threshold: std::time::Duration::from_secs(config.storage.stale_session_threshold),
            
            // Governance Init
            local_did,
            max_storage: config.storage.max_storage_bytes,
            max_foreign_storage: config.storage.max_foreign_storage_bytes,
            current_storage_usage: 0,
            foreign_storage_usage: 0,
        };
        
        stronghold.calculate_initial_usage();
        stronghold.recover_from_wal();
        stronghold
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
        if self.foreign_storage_usage <= self.max_foreign_storage {
            return;
        }

        warn!(
            usage = self.foreign_storage_usage, 
            limit = self.max_foreign_storage, 
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
            if self.foreign_storage_usage <= self.max_foreign_storage {
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
        if let Some(envelope) = self.micro_layer.process(chunk) {
            self.ingest_envelope(envelope);
        }
    }

    pub fn ingest_envelope(&mut self, envelope: WitnessEnvelope) {
        // 0. GOVERNANCE CHECK
        // If this is foreign data, ensure we have space.
        if envelope.did != self.local_did {
            // Trigger pruning if we are over limit (or close to it)
            if self.foreign_storage_usage > self.max_foreign_storage {
                self.prune_foreign_evidence();
                
                // Hard Reject if pruning failed to free enough space
                if self.foreign_storage_usage > self.max_foreign_storage {
                    warn!(did = %envelope.did, "Rejected foreign evidence: Storage Full");
                    return; 
                }
            }
        }

        if let Err(e) = self.write_to_wal(&envelope) {
             error!(error = %e, "CRITICAL: WAL write failed.");
             return;
        }

        if !envelope.verify() { 
            error!(did = %envelope.did, "Rejected invalid signature"); 
            return; 
        }
        
        let did = envelope.did.clone();
        let seq = envelope.evidence.sequence_id();

        if self.processed_sequences.get(&did).is_some_and(|set| set.contains(&seq)) {
            debug!(%seq, "Replay protection: Dropping already archived shard.");
            return;
        }

        self.session_activity.insert(did.clone(), Instant::now());

        if let Some(volley) = self.macro_layer.process(envelope) {
            info!(volley = %volley.id, "Volley sealed. Archiving.");
            self.archive_volley(volley);
        }
    }

    pub fn get_active_volley_shards(&self, did: &Did) -> Option<&std::collections::BTreeMap<StorageSequence, WitnessEnvelope>> {
        self.macro_layer.contexts.get(&did.to_string())
            .map(|ctx| &ctx.accumulator.artifacts)
    }

    fn archive_volley(&mut self, volley: Volley) {
        if volley.artifacts.is_empty() { return; }

        let safe_did = volley.owner_did.replace(":", "_");
        let archive_dir = self.vault_storage.join(&safe_did);
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
    }

    pub fn archive_stale_sessions(&mut self, ttl: std::time::Duration) {
        // 1. Flush Micro Layer
        let recovered_envelopes = self.micro_layer.flush_stale(ttl);
        for env in recovered_envelopes {
            warn!(seq = %env.evidence.sequence_id(), "Salvaged incomplete shard.");
            // Pushes data to Macro Layer (Governance checks apply here too)
            self.ingest_envelope(env);
        }

        // 2. Flush Macro Layer
        let recovered_volleys = self.macro_layer.flush_stale(ttl);
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
        fs::write(wal_path, bytes)?;
        Ok(())
    }

    fn recover_from_wal(&mut self) {
        if let Ok(entries) = fs::read_dir(&self.wal_directory) {
            for entry in entries.flatten() {
                let path = entry.path();
                if fs::metadata(&path).map(|m| m.len()).unwrap_or(0) == 0 { continue; }
                if let Ok(bytes) = fs::read(&path) {
                    if let Ok(envelope) = postcard::from_bytes::<WitnessEnvelope>(&bytes) {
                        self.macro_layer.process(envelope);
                    }
                }
            }
        }
    }
}