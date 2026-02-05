// src/lib.rs

// 1. Module Declarations
pub mod audio;
pub mod camera;
pub mod config;
pub mod identity;
pub mod network; // <--- Now handles all libp2p logic
pub mod obs;
pub mod sentinel;
pub mod shards;
pub mod sim;
pub mod stronghold;

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