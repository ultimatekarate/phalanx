use crate::vid::{WitnessEnvelope, VideoShard};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;


// Stronghold is a Personal Data Server. Sentinels gather information 
// and store it in a stronghold.

pub struct Stronghold {
    pub vault_storage: PathBuf,
    pub active_sessions: HashMap<String, HashMap<u32, WitnessEnvelope>>, 
    pub processed_sequences: HashMap<String, HashSet<u32>>,
}

impl Stronghold {
    pub fn new(vault_path: &str) -> Self {
        // Ensure the vault directory exists
        let root = PathBuf::from(vault_path);
        let _ = fs::create_dir_all(&root);
        
        Self {
            vault_storage: root,
            active_sessions: HashMap::new(),
            processed_sequences: HashMap::new(),
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

            let session = self.active_sessions
                .entry(did_key.clone())
                .or_insert_with(HashMap::new);

            session.insert(seq_id, envelope);
            
            // Archive session every 10 shards
            if session.len() >= 10 { 
                self.archive_session(&did_key); 
            }
        } else {
            eprintln!("Warning: Rejected invalid signature from DID: {}", envelope.did);
        }
    }

    fn archive_session(&mut self, did_full: &str) {
        if let Some(mut session) = self.active_sessions.remove(did_full) {
            println!("Stronghold: Sealing archive for {}", did_full);
            
            let mut keys: Vec<_> = session.keys().cloned().collect();
            keys.sort();

            let sorted_shards: Vec<VideoShard> = keys.into_iter()
                .map(|k| {
                    let env = session.remove(&k).unwrap();
                    self.processed_sequences.entry(did_full.to_string()).or_default().insert(k);
                    env.original_shard
                })
                .collect();

            let safe_did = did_full.replace(":", "_");
            let mut save_path = self.vault_storage.clone();
            save_path.push(safe_did);
            
            let _ = fs::create_dir_all(&save_path);

            // Save the reassembled shards as a single Postcard bundle
            save_path.push(format!("session_{}.phlx", sorted_shards[0].timestamp));
            
            if let Ok(encoded) = postcard::to_stdvec(&sorted_shards) {
                if let Err(e) = fs::write(save_path, encoded) {
                    eprintln!("Stronghold Error: Failed to write archive: {}", e);
                }
            }
            
        }
    }
}