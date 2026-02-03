use crate::shards::{WitnessEnvelope, VideoShard};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
//use std::time::Instant;

use tokio::time::Instant;
use crate::identity::Did;

use tracing::{info, debug, warn, error, instrument, trace, debug_span};


// Stronghold is a Personal Data Server. Sentinels gather information 
// and store it in a stronghold.

pub struct Stronghold {
    pub vault_storage: PathBuf,
    pub wal_directory: PathBuf,
    pub active_sessions: HashMap<Did, HashMap<u32, WitnessEnvelope>>, 
    pub session_activity: HashMap<Did, tokio::time::Instant>,
    pub processed_sequences: HashMap<Did, HashSet<u32>>,
    pub shards_needed_to_archive: usize,
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
        };

        stronghold.recover_from_wal();
        stronghold
    }

    fn write_to_wal(&self, envelope: &WitnessEnvelope) -> std::io::Result<()> {
        let safe_did = envelope.did.to_safe_name();
        let file_name = format!("{}_{}.tmp", safe_did, envelope.original_shard.sequence_id);
        let wal_path = self.wal_directory.join(file_name);

        if !self.wal_directory.exists() {
            fs::create_dir_all(&self.wal_directory)?;
        }

        let bytes = postcard::to_stdvec(envelope).unwrap();
        
        fs::write(wal_path, bytes)?;

        tracing::trace!(
            seq = %envelope.original_shard.sequence_id, 
            did = %envelope.did, 
            "WAL: Entry committed to disk"
        );
        
        Ok(())
    }

    fn clear_session_wal(&self, did_full: &Did, sequence_ids: &[u32]) {
        let safe_did = did_full.to_safe_name();
        for seq in sequence_ids {
            let file_name = format!("{}_{}.tmp", safe_did, seq);
            let _ = fs::remove_file(self.wal_directory.join(file_name));
        }
    }

    /// Scans the WAL directory and populates active_sessions with unarchived data.
    #[tracing::instrument(skip(self))]
    fn recover_from_wal(&mut self) {
        let span = tracing::info_span!("wal_recovery");
        let _enter = span.enter();
        
        if let Ok(entries) = fs::read_dir(&self.wal_directory) {
            let mut recovered_count = 0;
            for entry in entries.flatten() {
                if let Ok(bytes) = fs::read(entry.path()) {
                    if let Ok(envelope) = postcard::from_bytes::<WitnessEnvelope>(&bytes) {
                        let did = envelope.did.clone();
                        let seq = envelope.original_shard.sequence_id;
                        
                        self.active_sessions
                            .entry(did)
                            .or_default()
                            .insert(seq, envelope);
                        
                        recovered_count += 1;
                    }
                }
            }
            if recovered_count > 0 {
                tracing::info!(count = recovered_count, "Successfully restored state from WAL.");
            }
        }
    }

    /// The PDS validates the signature against the DID before storing
    #[instrument(
        level = "info", 
        skip(self, envelope), 
        fields(
            did = %envelope.did, 
            seq = %envelope.original_shard.sequence_id,
            partial = envelope.is_partial
        )
    )]
    pub fn ingest_envelope(&mut self, envelope: WitnessEnvelope) {
        if let Err(e) = self.write_to_wal(&envelope) {
            tracing::error!(error = %e, "CRITICAL: Failed to write to WAL. Potential data loss.");
        }

        let span = tracing::span!(tracing::Level::INFO, "stronghold_ingest", 
            sender = %envelope.did, 
            seq = envelope.original_shard.sequence_id,
            partial = envelope.is_partial
        );
        let _enter = span.enter();
        
        let should_ingest = if envelope.is_partial {
            tracing::warn!("Bypassing signature check for forensic salvage shard");
            true
        } else {
            envelope.verify()
        };

        if should_ingest {
            let did_key = envelope.did.clone(); 
            let seq_id = envelope.original_shard.sequence_id;

            // Replay protection: Don't ingest if already processed
            if self.processed_sequences.get(&did_key).is_some_and(|s| s.contains(&seq_id)) {
                debug!("Replay protection: Shard already in vault. Skipping.");
                return;
            }

            self.session_activity.insert(did_key.clone(), Instant::now());

            let session = self.active_sessions
                .entry(did_key.clone())
                .or_default();

            session.insert(seq_id, envelope);
            
            tracing::debug!("Verified and cached in memory");

            // Archive session every 10 shards
            if session.len() >= self.shards_needed_to_archive { 
                tracing::info!(%self.shards_needed_to_archive, "Archival threshold met. Sealing shard bundle.");
                self.archive_session(&did_key); 
                self.session_activity.remove(&did_key);
            }
        } else {
            tracing::error!("Warning: Rejected invalid signature from DID: {}", envelope.did);
        }
    }

    #[instrument(level = "debug", skip(self))]
    pub fn archive_stale_sessions(&mut self, timeout: std::time::Duration) {
        let now = tokio::time::Instant::now();
        let span = debug_span!("stale_cleanup");
        let _enter = span.enter();

        // Identify DIDs that have timed out
        let stale_dids: Vec<Did> = self.session_activity
            .iter()
            .filter_map(|(did, &last_active)| {
                let age = now.duration_since(last_active);
                if age > timeout {
                    debug!(did = %did, age = ?age, "Found stale session for archival");
                    Some(did.clone())
                } else {
                    None
                }
            })
            .collect();

        if stale_dids.is_empty() {
            trace!("No stale sessions found in this tick.");
            return;
        }

        for did in stale_dids {
            info!(did = %did, "Triggering force-archive for stale session");
            self.archive_session(&did);
            self.session_activity.remove(&did);
        }
    }

    #[instrument(level = "info", skip(self))]
    fn archive_session(&mut self, did_full: &Did) {
        // 1. Attempt to pull session from RAM
        let session = match self.active_sessions.remove(did_full) {
            Some(s) => s,
            None => {
                warn!(did = %did_full, "Archival requested but no active session found in memory");
                return;
            }
        };

        let mut keys: Vec<_> = session.keys().cloned().collect();
        keys.sort();

        let sorted_shards: Vec<VideoShard> = keys.iter()
            .filter_map(|k| {
                session.get(k).map(|env| {
                    // Record that we've processed this to prevent replays
                    self.processed_sequences
                        .entry(did_full.clone())
                        .or_default()
                        .insert(*k);
                    env.original_shard.clone()
                })
            })
            .collect();

        if sorted_shards.is_empty() {
            warn!(did = %did_full, "Session contained no valid shards. Aborting archive.");
            return;
        }

        // 2. Prepare Directory
        let safe_did = did_full.to_safe_name();
        let archive_dir = self.vault_storage.join(&safe_did);
        
        if let Err(e) = std::fs::create_dir_all(&archive_dir) {
            error!(err = %e, path = ?archive_dir, "CRITICAL: Could not create peer archive directory");
            return;
        }

        // 3. Determine File Identity
        let is_audio = sorted_shards.iter().any(|s| s.fps == 0);
        let extension = if is_audio { "aud.phlx" } else { "vid.phlx" };
        let file_name = format!("session_{}.{}", sorted_shards[0].timestamp, extension);
        let save_path = archive_dir.join(file_name);

        // 4. Commit to Disk
        match postcard::to_stdvec(&sorted_shards) {
            Ok(encoded) => {
                if let Err(e) = std::fs::write(&save_path, encoded) {
                    error!(err = %e, path = ?save_path, "IO ERROR: Archival write failed");
                } else {
                    info!(path = ?save_path, count = %sorted_shards.len(), "Archive successful. Purging WAL.");
                    self.clear_session_wal(did_full, &keys);
                }
            }
            Err(e) => error!(err = %e, "Serialization failed during archival"),
        }
    }
}