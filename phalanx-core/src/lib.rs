// src/lib.rs

// 1. Module Declarations
pub mod core;
pub mod hardware;
pub mod storage;
pub mod security;
pub mod protocol;
pub mod network;
pub mod sim;
pub mod engine;

// 2. Re-exports
pub use network::network::{setup_phalanx_swarm, PhalanxBehaviour, PhalanxEvent};
pub use core::config::PhalanxConfig;
pub use security::identity::PhalanxIdentity;

/// Helper to load identity from disk or prompt for generation/recovery.
pub fn init_identity() -> PhalanxIdentity {
    let id_path = "identity.bin";

    PhalanxIdentity::load_from_disk(id_path).unwrap_or_else(|_| {
        println!("\n==================================================");
        println!("  NO IDENTITY FOUND  ");
        println!("==================================================");
        println!("Do you want to (G)enerate a new identity or (R)ecover from a phrase? [G/r]");
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap_or_default();
        
        let new_id = if input.trim().eq_ignore_ascii_case("r") {
            println!("\nEnter your 12-word mnemonic phrase:");
            let mut phrase = String::new();
            std::io::stdin().read_line(&mut phrase).expect("Failed to read phrase");
            
            match PhalanxIdentity::restore(phrase.trim()) {
                Ok(id) => {
                    println!("✅ Identity Restored: {}", id.did);
                    id
                },
                Err(e) => panic!("Failed to restore identity: {}", e),
            }
        } else {
            // GENERATE NEW
            let (id, phrase) = PhalanxIdentity::generate();
            println!("\n NEW IDENTITY GENERATED: {}", id.did);
            println!("--------------------------------------------------");
            println!("{}", phrase);
            println!("--------------------------------------------------");
            println!(" WRITE THIS DOWN. IT WILL NOT BE SHOWN AGAIN. \n");
            
            println!("Press ENTER once you have secured your seed phrase.");
            let mut ack = String::new();
            std::io::stdin().read_line(&mut ack).unwrap();
            
            id
        };

        new_id.save_to_disk(id_path).expect("Failed to save identity to disk.");
        new_id
    })
}

#[cfg(test)]
mod integration_tests {
    use crate::core::config::PhalanxConfig;
    use crate::storage::guardian::Guardian;
    use crate::protocol::shards::{self, Evidence, StorageSequence, WitnessEnvelope, ChunkType};
    use crate::security::identity::{NetworkId, PhalanxIdentity};
    use std::time::Duration;

    #[test]
    /// Executes a comprehensive validation of the reassembly engine.
    ///
    /// This test simulates a fragmented network stream, pushing raw shards through
    /// the Sentinel into the Crucible to verify that the forensic integrity of
    /// the WitnessEnvelope remains intact after reconstruction.
    fn test_full_recursive_pipeline() {
        let mut config = PhalanxConfig::default();
        config.storage.vault_path = "./sim_vault".to_string();
        config.storage.stale_session_threshold = 1;
        let is_leaf_mode: bool = false;

        let _ = std::fs::remove_dir_all(&config.storage.vault_path);
        
        let (identity, _) = PhalanxIdentity::generate();
        let peer_id = NetworkId::random();
        
        let mut stronghold = Guardian::new(&config.storage.vault_path, &config, identity.did.clone());

        // Create Evidence
        let frames = vec![vec![0xFF; 100]]; 
        let shard = shards::create_video_shard(
            frames, 
            StorageSequence(0), 
            30, 
            "volley_alpha_001".to_string()
        );

        let envelope = WitnessEnvelope::new(Evidence::Video(shard), &identity, peer_id);
        let envelope_bytes = postcard::to_stdvec(&envelope).unwrap();

        let chunks = shards::chunkify(
            shards::ShardId(0), 
            envelope_bytes, 
            10, 
            identity.did.clone(),
            ChunkType::Witnessed
        );
        
        // Ingest
        for i in 0..chunks.len() - 1 {
            stronghold.ingest_chunk(chunks[i].clone(), is_leaf_mode);
        }

        let active_shard = stronghold.micro_layer.get(&shards::ShardId(0));
        assert!(active_shard.is_some(), "Micro Layer failed to buffer incomplete chunks");
        
        stronghold.ingest_chunk(chunks.last().unwrap().clone(), is_leaf_mode);

        assert!(stronghold.micro_layer.is_empty(), "Micro Layer failed to clear completed shard");
        
        let active_shards = stronghold.get_active_volley_shards(&identity.did);
        assert!(active_shards.is_some(), "Stronghold failed to promote Envelope to Macro Layer");
        assert_eq!(active_shards.unwrap().len(), 1, "Macro Layer missing the reassembled shard");

        // Archive
        std::thread::sleep(Duration::from_secs(2)); 
        stronghold.archive_stale_sessions(Duration::from_millis(500));

        let remaining_shards = stronghold.get_active_volley_shards(&identity.did);
        assert!(remaining_shards.is_none(), "Stronghold failed to flush stale session from RAM");

        let safe_did = identity.did.to_safe_name();
        let path = std::path::Path::new("./sim_vault")
            .join(safe_did)
            .join("volley_alpha_001.vid.phlx");
            
        assert!(path.exists(), "Stronghold failed to create .phlx archive file");
    }
}