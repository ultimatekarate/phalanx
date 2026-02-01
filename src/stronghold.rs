use crate::vid::{WitnessEnvelope, VideoShard};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

// Stronghold is a Personal Data Server. Sentinels gather information 
// and store it in a stronghold.

pub struct Stronghold {
    pub vault_storage: PathBuf,
    pub wal_directory: PathBuf,
    pub active_sessions: HashMap<String, HashMap<u32, WitnessEnvelope>>, 
    pub session_activity: HashMap<String, Instant>,
    pub processed_sequences: HashMap<String, HashSet<u32>>,
}

impl Stronghold {
    pub fn new(vault_path: &str) -> Self {
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
        };

        stronghold.recover_from_wal();
        stronghold
    }

    fn write_to_wal(&self, envelope: &WitnessEnvelope) -> std::io::Result<()> {
        let mut wal_path = self.vault_storage.clone();
        wal_path.push("wal");
        fs::create_dir_all(&wal_path)?;
        
        // Save as individual shard for crash recovery
        wal_path.push(format!("{}_{}.tmp", envelope.did.replace(":", "_"), envelope.original_shard.sequence_id));
        let bytes = postcard::to_stdvec(envelope).unwrap();
        fs::write(wal_path, bytes)
    }

    fn clear_session_wal(&self, did_full: &str, sequence_ids: &[u32]) {
        let safe_did = did_full.replace(":", "_");
        for seq in sequence_ids {
            let file_name = format!("{}_{}.tmp", safe_did, seq);
            let _ = fs::remove_file(self.wal_directory.join(file_name));
        }
    }

    /// Scans the WAL directory and populates active_sessions with unarchived data.
    fn recover_from_wal(&mut self) {
        if let Ok(entries) = fs::read_dir(&self.wal_directory) {
            let mut recovered_count = 0;
            for entry in entries.flatten() {
                if let Ok(bytes) = fs::read(entry.path()) {
                    if let Ok(envelope) = postcard::from_bytes::<WitnessEnvelope>(&bytes) {
                        let did = envelope.did.clone();
                        let seq = envelope.original_shard.sequence_id;
                        
                        self.active_sessions
                            .entry(did)
                            .or_insert_with(HashMap::new)
                            .insert(seq, envelope);
                        
                        recovered_count += 1;
                    }
                }
            }
            if recovered_count > 0 {
                println!("Stronghold: Recovered {} shards from WAL.", recovered_count);
            }
        }
    }

    /// The PDS validates the signature against the DID before storing
    pub fn ingest_envelope(&mut self, envelope: WitnessEnvelope) {
        if envelope.verify() {
            let did_key = envelope.did.clone(); 
            let seq_id = envelope.original_shard.sequence_id;

            // Replay protection: Don't ingest if already processed
            if self.processed_sequences.get(&did_key).map_or(false, |s| s.contains(&seq_id)) {
                return;
            }

            if let Err(e) = self.write_to_wal(&envelope) {
                eprintln!("Stronghold WAL Error: {}. Dropping shard.", e);
                return; 
            }

            self.session_activity.insert(did_key.clone(), Instant::now());

            let session = self.active_sessions
                .entry(did_key.clone())
                .or_insert_with(HashMap::new);

            session.insert(seq_id, envelope);
            
            // Archive session every 10 shards
            if session.len() >= 10 { 
                self.archive_session(&did_key); 
                self.session_activity.remove(&did_key);
            }
        } else {
            eprintln!("Warning: Rejected invalid signature from DID: {}", envelope.did);
        }
    }

    pub fn archive_stale_sessions(&mut self, timeout: Duration) {
        let now = Instant::now();
        
        // Identify DIDs that have timed out
        let stale_dids: Vec<String> = self.session_activity
            .iter()
            .filter(|(_, &last_active)| now.duration_since(last_active) > timeout)
            .map(|(did, _)| did.clone())
            .collect();

        for did in stale_dids {
            println!("Stronghold: Force-archiving stale session for {}", did);
            // Calling the existing archive logic even if len < 10
            self.archive_session(&did);
            self.session_activity.remove(&did);
        }
    }

    fn archive_session(&mut self, did_full: &str) {
        if let Some(mut session) = self.active_sessions.remove(did_full) {
            let mut keys: Vec<_> = session.keys().cloned().collect();
            keys.sort();

            let sorted_shards: Vec<VideoShard> = keys.iter()
                .map(|k| {
                    let env = session.remove(k).unwrap();
                    self.processed_sequences.entry(did_full.to_string()).or_default().insert(*k);
                    env.original_shard
                })
                .collect();

            let safe_did = did_full.replace(":", "_");
            let mut save_path = self.vault_storage.join(&safe_did);
            let _ = fs::create_dir_all(&save_path);

            save_path.push(format!("session_{}.phlx", sorted_shards[0].timestamp));
            
            if let Ok(encoded) = postcard::to_stdvec(&sorted_shards) {
                if let Ok(_) = fs::write(&save_path, encoded) {
                    println!("Stronghold: Archived session to {:?}", save_path);
                    // 3. Success! Clear the WAL logs for this session
                    self.clear_session_wal(did_full, &keys);
                }
            }
        }
    }
}