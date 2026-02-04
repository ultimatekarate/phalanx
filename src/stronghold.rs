use crate::shards::{StorageSequence, Evidence, WitnessEnvelope};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
//use std::time::Instant;

use tokio::time::Instant;
use crate::identity::Did;

use tracing::{info, debug, warn, error, instrument,};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Volley {
    pub volley_id: String,           // Unique ID for this specific burst
    pub owner_did: Did,              // The Identity this volley belongs to
    pub start_time: u64,             // Unix timestamp of the first shard
    pub shards: Vec<WitnessEnvelope>,
    pub is_complete: bool,           // Marked true on a 'Seal' command
}

impl Volley {
    pub fn new(id: String, did: Did) -> Self {
        Self {
            volley_id: id,
            owner_did: did,
            start_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            shards: Vec::new(),
            is_complete: false,
        }
    }

    /// Adds a shard and ensures logical sequence ordering
    pub fn push(&mut self, envelope: WitnessEnvelope) {
        self.shards.push(envelope);
        // We sort by StorageSequence to ensure the Volley is continuous
        self.shards.sort_by_key(|e| e.evidence.sequence_id());
    }
}

// Stronghold is a Personal Data Server. Sentinels gather information 
// and store it in a stronghold.

pub struct Stronghold {
    pub vault_storage: PathBuf,
    pub wal_directory: PathBuf,
    pub active_sessions: HashMap<Did, HashMap<StorageSequence, WitnessEnvelope>>, 
    pub session_activity: HashMap<Did, tokio::time::Instant>,
    pub processed_sequences: HashMap<Did, HashSet<StorageSequence>>,
    pub shards_needed_to_archive: usize,
    pub active_volleys: HashMap<Did, Volley>,
}

impl Stronghold {
    pub fn new(vault_path: &str, config: &crate::config::PhalanxConfig) -> Self {
        // Ensure the vault directory exists
        let root = PathBuf::from(vault_path);
        let wal = root.join("wal");
        let _ = fs::create_dir_all(&root);
        let _ = fs::create_dir_all(&wal);

        let mut stronghold = Self {
            vault_storage: root,
            wal_directory: wal,
            active_sessions: HashMap::new(),
            session_activity: HashMap::new(),
            processed_sequences: HashMap::new(),
            shards_needed_to_archive: config.storage.shards_needed_to_archive,
            active_volleys: HashMap::new(),
        };

        stronghold.recover_from_wal();
        stronghold
    }

    fn write_to_wal(&self, envelope: &WitnessEnvelope) -> std::io::Result<()> {
        let safe_did = envelope.did.to_safe_name();
        // Use .0 to avoid potential Display trait formatting issues in filenames
        let file_name = format!("{}_{}.wal", safe_did, envelope.evidence.sequence_id().0);
        let wal_path = self.wal_directory.join(file_name);

        let bytes = postcard::to_stdvec(envelope).map_err(|e| 
            std::io::Error::new(std::io::ErrorKind::Other, e))?;
        
        fs::write(wal_path, bytes)?;
        Ok(())
    }

    fn clear_session_wal(&self, did_full: &Did, sequence_ids: &[StorageSequence]) {
        let safe_did = did_full.to_safe_name();
        for seq in sequence_ids {
            let file_name = format!("{}_{}.tmp", safe_did, seq);
            let _ = fs::remove_file(self.wal_directory.join(file_name));
        }
    }

    /// Scans the WAL directory and populates active_sessions with unarchived data.
    #[instrument(skip(self), level = "info")]
    fn recover_from_wal(&mut self) {
        let span = tracing::info_span!("wal_recovery");
        let _enter = span.enter();
        
        if let Ok(entries) = fs::read_dir(&self.wal_directory) {
            let mut recovered_count = 0;
            let now = Instant::now();

            for entry in entries.flatten() {
                let path = entry.path();
                
                // Skip zero-byte files (remnants of the Windows ADS/Colon bug)
                if fs::metadata(&path).map(|m| m.len()).unwrap_or(0) == 0 {
                    let _ = fs::remove_file(path);
                    continue;
                }

                if let Ok(bytes) = fs::read(&path) {
                    if let Ok(envelope) = postcard::from_bytes::<WitnessEnvelope>(&bytes) {
                        let did = envelope.did.clone();
                        let seq = envelope.evidence.sequence_id();

                        self.active_sessions.entry(did.clone()).or_default().insert(seq, envelope);
                        self.processed_sequences.entry(did.clone()).or_default().insert(seq);
                        self.session_activity.insert(did, now);
                        
                        recovered_count += 1;
                    }
                }
            }
            if recovered_count > 0 {
                info!(count = recovered_count, "Successfully restored state from WAL");
            }
        }
    }

    /// The PDS validates the signature against the DID before storing
    #[instrument(
        level = "info", 
        skip(self, envelope)
    )]
    pub fn ingest_envelope(&mut self, envelope: WitnessEnvelope) {
        // 1. Durability: Write to WAL first
        if let Err(e) = self.write_to_wal(&envelope) {
            error!(error = %e, "CRITICAL: WAL write failed. Data loss risk.");
            return;
        }
        
        // 2. Cryptographic Validation
        if !envelope.verify() {
            error!(did = %envelope.did, "Rejected invalid signature");
            return;
        }

        let did_key = envelope.did.clone(); 
        let seq_id = envelope.evidence.sequence_id();

        // 3. Replay Protection
        if self.processed_sequences.get(&did_key).is_some_and(|s| s.contains(&seq_id)) {
            debug!(%seq_id, "Replay protection: Shard already archived. Skipping.");
            return;
        }

        // 4. In-Memory Tracking
        self.session_activity.insert(did_key.clone(), Instant::now());
        let session = self.active_sessions.entry(did_key.clone()).or_default();
        session.insert(seq_id, envelope);

        // 5. Threshold Check
        if session.len() >= self.shards_needed_to_archive { 
            info!(%did_key, "Threshold met. Archiving session.");
            self.archive_session(&did_key); 
        }
    }

    pub fn archive_stale_sessions(&mut self, timeout: std::time::Duration) {
        let now = Instant::now();
        let stale_dids: Vec<Did> = self.session_activity
            .iter()
            .filter_map(|(did, &last_active)| {
                if now.duration_since(last_active) > timeout { Some(did.clone()) } else { None }
            })
            .collect();

        for did in stale_dids {
            info!(did = %did, "Force-archiving stale session");
            self.archive_session(&did);
        }
    }

    #[instrument(level = "info", skip(self))]
    fn archive_session(&mut self, did: &Did) {
        let session = match self.active_sessions.remove(did) {
            Some(s) => s,
            None => return,
        };

        let mut keys: Vec<StorageSequence> = session.keys().cloned().collect();
        keys.sort();

        // Map envelopes to Evidence variant for archival
        let sorted_evidence: Vec<Evidence> = keys.iter()
            .filter_map(|k| {
                session.get(k).map(|env| {
                    self.processed_sequences.entry(did.clone()).or_default().insert(*k);
                    env.evidence.clone()
                })
            })
            .collect();

        if sorted_evidence.is_empty() { return; }

        // Determine file type based on the first shard in the bundle
        let extension = match sorted_evidence[0] {
            Evidence::Video(_) => "vid.phlx",
            Evidence::Audio(_) => "aud.phlx",
        };

        let safe_did = did.to_safe_name();
        let archive_dir = self.vault_storage.join(&safe_did);
        let _ = std::fs::create_dir_all(&archive_dir);

        let file_name = format!("session_{}.{}", sorted_evidence[0].timestamp(), extension);
        let save_path = archive_dir.join(file_name);

        match postcard::to_stdvec(&sorted_evidence) {
            Ok(encoded) => {
                if let Err(e) = std::fs::write(&save_path, encoded) {
                    error!(err = %e, "Archival write failed");
                } else {
                    info!(path = ?save_path, "Archive successful. Clearing WAL.");
                    self.clear_session_wal(did, &keys);
                    self.session_activity.remove(did);
                }
            }
            Err(e) => error!(err = %e, "Archival serialization failed"),
        }
    }
}