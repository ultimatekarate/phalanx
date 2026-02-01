use crate::vid::{WitnessEnvelope, VideoShard};
use std::collections::{HashMap, HashSet};
use std::fs;


// Stronghold is a Personal Data Server. Sentinels gather information 
// and store it in a stronghold.

pub struct Stronghold {
    pub vault_storage: String,
    // Maps DID -> Map<SequenceID, Envelope> to ensure order and prevent duplicates
    pub active_sessions: HashMap<String, HashMap<u32, WitnessEnvelope>>, 
    // Track processed sequence IDs to prevent replay attacks
    pub processed_sequences: HashMap<String, HashSet<u32>>,
}

impl Stronghold {
    pub fn new(vault_path: &str) -> Self {
        // Ensure the vault directory exists
        let _ = fs::create_dir_all(vault_path);
        
        Self {
            vault_storage: vault_path.to_string(),
            active_sessions: HashMap::new(),
            processed_sequences: HashMap::new(),
        }
    }

    /// The PDS validates the signature against the DID before storing
    pub fn ingest_envelope(&mut self, envelope: WitnessEnvelope) {
        if envelope.verify() { // This now does real cryptographic work
            let did_key = envelope.did.clone(); 
            let safe_did = did_key.replace(":", "_");
            let seq_id = envelope.original_shard.sequence_id;

            let session = self.active_sessions
                .entry(did_key.clone()) // did_key is used here
                .or_insert_with(HashMap::new);

            session.insert(seq_id, envelope);
            
            if session.len() >= 10 { self.archive_session(&did_key, &safe_did); }

        } else {
            eprintln!("Warning: Received invalid signature from DID: {}", envelope.did);
        }
    }

    fn archive_session(&mut self, did_full: &str, safe_did: &str) {
        if let Some(mut session) = self.active_sessions.remove(did_full) {
            println!("Stronghold: Sealing archive for {}", did_full);
            
            let mut keys: Vec<_> = session.keys().cloned().collect();
            keys.sort();

            let sorted_shards: Vec<VideoShard> = keys.into_iter()
                .map(|k| {
                    let env = session.remove(&k).unwrap();
                    // Mark as processed to prevent re-archiving
                    self.processed_sequences.entry(did_full.to_string()).or_default().insert(k);
                    env.original_shard
                })
                .collect();

            // Offload to vault logic using sanitized DID
            let _ = crate::vid::seal_to_vault_from_vec(safe_did, sorted_shards);
        }
    }
}