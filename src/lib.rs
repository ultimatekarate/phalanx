// src/lib.rs

// 1. Module Declarations
pub mod audio;
pub mod camera;
pub mod config;
pub mod identity;
pub mod network; 
pub mod obs;
pub mod sentinel;
pub mod shards;
pub mod sim;
pub mod stronghold;
pub mod crucible;
pub mod strategies; 
// 2. Re-exports
// We expose the network logic so main.rs can use it without importing `crate::network::*`
pub use network::{setup_phalanx_swarm, PhalanxBehaviour, PhalanxEvent};

// 3. Helpers
use crate::identity::PhalanxIdentity;

/// Helper to load identity from disk or generate a new one.
pub fn init_identity() -> PhalanxIdentity {
    let id_path = "identity.bin";

    PhalanxIdentity::load_from_disk(id_path).unwrap_or_else(|_| {
        println!("Status: Generating new Phalanx Identity...");

        let new_id = PhalanxIdentity::generate();
        new_id.save_to_disk(id_path).expect("Failed to save identity to disk.");

        new_id
    })
}

#[cfg(test)]
mod integration_tests {
    use crate::config::PhalanxConfig;
    use crate::stronghold::Stronghold;
    use crate::shards::{self, Evidence, VideoShard, StorageSequence, WitnessEnvelope};
    use crate::identity::{PhalanxIdentity, NetworkId};
    use std::time::Duration;

    #[test]
    fn test_full_recursive_pipeline() {
        // 1. SETUP: Configure Stronghold (The Vault)
        let mut config = PhalanxConfig::default();
        config.storage.vault_path = "./test_vault".to_string();
        config.storage.stale_session_threshold = 1; // 1 second for fast testing
        
        // Clean up previous runs
        let _ = std::fs::remove_dir_all(&config.storage.vault_path);
        
        let mut stronghold = Stronghold::new(&config.storage.vault_path, &config);
        let identity = PhalanxIdentity::generate();
        let peer_id = NetworkId::random();

        // 2. CREATE EVIDENCE: A mock video frame
        let shard = VideoShard {
            volley_id: "volley_alpha_001".to_string(),
            timestamp: 1000,
            sequence_id: StorageSequence(0),
            frames: vec![vec![0xFF; 100]], // Mock pixel data
            fps: 30,
        };

        // 3. ENVELOPE IT (Simulate local hardware capture)
        let envelope = WitnessEnvelope::new(Evidence::Video(shard), &identity, peer_id);
        let envelope_bytes = postcard::to_stdvec(&envelope).unwrap();

        // 4. CHUNK IT (Simulate Network Fragmentation)
        // Split into tiny 10-byte chunks to force reassembly
        let chunks = shards::chunkify(
            shards::ShardId(0), 
            envelope_bytes, 
            10, 
            identity.did.clone()
        );
        
        println!("Generated {} chunks for transmission.", chunks.len());

        // 5. INGESTION (The Recursive Flow)
        
        // Feed all chunks EXCEPT the last one
        for i in 0..chunks.len() - 1 {
            stronghold.ingest_chunk(chunks[i].clone());
        }

        // VERIFY 1: Micro Layer State
        // The Micro Crucible should be holding the incomplete shard
        let active_shard = stronghold.micro_layer.contexts.get(&shards::ShardId(0));
        assert!(active_shard.is_some(), "Micro Layer failed to buffer incomplete chunks");
        
        // Feed the final chunk
        stronghold.ingest_chunk(chunks.last().unwrap().clone());

        // VERIFY 2: Promotion to Macro Layer
        // Micro layer should be empty (shard completed and moved up)
        assert!(stronghold.micro_layer.contexts.is_empty(), "Micro Layer failed to clear completed shard");
        
        // Macro layer (Crucible) should now hold the WIP Volley
        let active_shards = stronghold.get_active_volley_shards(&identity.did);
        assert!(active_shards.is_some(), "Stronghold failed to promote Envelope to Macro Layer");
        assert_eq!(active_shards.unwrap().len(), 1, "Macro Layer missing the reassembled shard");

        println!("Success: Data flowed Chunk -> Micro -> Macro.");

        // 6. ARCHIVAL (The Gatekeeper)
        
        // Manually trigger archival by simulating a stale session timeout
        std::thread::sleep(Duration::from_secs(2)); 
        stronghold.archive_stale_sessions(Duration::from_millis(500));

        // VERIFY 3: Persistence
        // Macro layer should be empty (flushed to disk)
        let remaining_shards = stronghold.get_active_volley_shards(&identity.did);
        assert!(remaining_shards.is_none(), "Stronghold failed to flush stale session from RAM");

        // Check Disk
        let safe_did = identity.did.to_safe_name();
        let path = std::path::Path::new("./test_vault")
            .join(safe_did)
            .join("volley_alpha_001.vid.phlx");
            
        assert!(path.exists(), "Stronghold failed to create .phlx archive file");
        
        println!("Success: Pipeline complete. Archive verified at {:?}", path);
    }
}