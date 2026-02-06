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
}

impl Stronghold {
    pub fn new(vault_path: &str, config: &PhalanxConfig) -> Self {
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
        };
        
        stronghold.recover_from_wal();
        stronghold
    }

    /// ENTRY POINT 1: Raw Network Data (Recursive Flow)
    #[instrument(skip(self, chunk), level = "debug")]
    pub fn ingest_chunk(&mut self, chunk: ShardChunk) {
        // 1. Put chunk on the Micro Workbench
        if let Some(envelope) = self.micro_layer.process(chunk) {
            debug!(seq = %envelope.evidence.sequence_id(), "Micro-assembly complete. Promoting.");
            // 2. If finished, promote to the macro Layer
            self.ingest_envelope(envelope);
        }
    }

    // --- STATE INSPECTION (The Bridge) ---
    // Look into the Workbench to see what is currently happening
    pub fn get_active_volley_shards(&self, did: &Did) -> Option<&std::collections::BTreeMap<StorageSequence, WitnessEnvelope>> {
        self.macro_layer.contexts.get(&did.to_string())
            .map(|ctx| &ctx.accumulator.artifacts)
    }

    // --- PERSISTENCE ---
    fn archive_volley(&mut self, volley: Volley) {
        if volley.artifacts.is_empty() { return; }

        let safe_did = volley.owner_did.replace(":", "_");
        let archive_dir = self.vault_storage.join(&safe_did);
        let _ = fs::create_dir_all(&archive_dir);

        // Update Replay History
        let did = Did(volley.owner_did.clone());
        let history = self.processed_sequences.entry(did).or_default();

        // Track artifacts for cleanup
        let mut wal_files_to_delete = Vec::new();

        for artifact in &volley.artifacts {
            history.insert(artifact.evidence.sequence_id());
            // Calculate the WAL path for this artifact
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
        let tmp_filename = format!("{}.tmp", volley.id); // 1. Create .tmp name

        let final_path = archive_dir.join(&final_filename);
        let tmp_path = archive_dir.join(&tmp_filename);

        match postcard::to_stdvec(&volley) {
            Ok(bytes) => {
                // 2. Write to .tmp first
                if let Err(e) = fs::write(&tmp_path, bytes) {
                    error!(%e, "Failed to write temp archive file");
                } else {
                    // 3. Atomically rename .tmp -> .phlx
                    if let Err(e) = fs::rename(&tmp_path, &final_path) {
                        error!(%e, "Failed to rename archive file");
                        // Optional: Attempt cleanup of tmp file here
                    } else {
                        info!(path = ?final_path, "Volley successfully archived via atomic rename");
                        
                        // 4. NOW delete the WAL entries
                        for wal_path in wal_files_to_delete {
                            if let Err(e) = fs::remove_file(&wal_path) {
                                warn!(file = ?wal_path, err = %e, "Failed to cleanup WAL file");
                            }
                        }
                    }
                }
            }
            Err(e) => error!(%e, "Serialization error"),
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
                        // RECOVERY: Load directly into Macro Workbench
                        self.macro_layer.process(envelope);
                    }
                }
            }
        }
    }

    pub fn ingest_envelope(&mut self, envelope: WitnessEnvelope) {
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

        let output = self.macro_layer.process(envelope);
        
        if let Some(volley) = output {
            info!(volley = %volley.id, "Volley sealed (Natural). Archiving.");
            self.archive_volley(volley);
        } 
    }

    pub fn archive_stale_sessions(&mut self, ttl: std::time::Duration) {
        // 1. Flush Micro Layer
        let recovered_envelopes = self.micro_layer.flush_stale(ttl);
        for env in recovered_envelopes {
            warn!(seq = %env.evidence.sequence_id(), "Salvaged incomplete shard.");
            self.ingest_envelope(env);
        }

        // 2. Flush Macro Layer (for any data that was already sitting there)
        let recovered_volleys = self.macro_layer.flush_stale(ttl);
        for volley in recovered_volleys {
            warn!(id = %volley.id, "Force-archiving stale volley");
            self.archive_volley(volley);
        }
    }
}