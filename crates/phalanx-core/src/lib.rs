// src/lib.rs

// --- 1. BASE DOMAIN ---
pub mod base {
    pub mod types;
    pub mod config;
    pub mod governor;
    pub mod engine;
}

// --- 2. PRIMITIVES ---
pub mod primitives {
    pub mod identity;
    pub mod time;
    pub mod shards;
}

// --- 3. STORAGE ---
pub mod storage {
    pub mod vault;
    pub mod crucible;
    pub mod strategies;
}

// --- 4. TRANSPORT ---
pub mod transport {
    pub mod swarm;
}

// --- 5. SECURITY ---
pub mod security {
    pub mod e2ee;
    pub mod sentinel;
    pub mod telemetry;
    pub mod grant;
    pub mod locator;
    pub mod trust;
}

pub mod simulation;

// --- 6. DRIVERS (Conditional) ---
#[cfg(feature = "edge")]
pub mod drivers {
    pub mod sensors {
        pub mod audio;
        pub mod camera;
        pub mod sensors;
    }
    pub mod optics {
        pub mod capture_physics;
        pub mod moire;
    }
}

// --- 7. RE-EXPORTS ---
pub use transport::swarm::{setup_phalanx_swarm, PhalanxBehaviour, PhalanxEvent};
pub use base::config::PhalanxConfig;
pub use primitives::identity::PhalanxIdentity;

// --- 8. SHARED LOGIC ---
pub fn init_identity() -> PhalanxIdentity {
    let id_path = "identity.bin";
    PhalanxIdentity::load_from_disk(id_path).unwrap_or_else(|_| {
        // ... (Keep your existing init_identity logic here)
        let (id, _) = PhalanxIdentity::generate();
        id.save_to_disk(id_path).unwrap();
        id
    })
}

// --- 9. INTEGRATION TESTS ---
#[cfg(test)]
mod integration_tests {
    // Note the path change: storage::vault instead of storage::guardian
    // use crate::storage::vault::Guardian; 
}