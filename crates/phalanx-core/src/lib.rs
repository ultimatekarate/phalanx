// src/lib.rs

// --- 1. BASE DOMAIN ---
pub mod base {
    pub mod config;
    pub mod engine;
    pub mod governor;
    pub mod types;
}

// --- 2. PRIMITIVES ---
pub mod primitives {
    pub mod identity;
    pub mod shards;
    pub mod time;
}

// --- 3. STORAGE ---
pub mod storage {
    pub mod crucible;
    pub mod strategies;
    pub mod vault;
}

// --- 4. TRANSPORT ---
pub mod transport {
    pub mod swarm;
}

// --- 5. SECURITY ---
pub mod security {
    pub mod e2ee;
    pub mod grant;
    pub mod locator;
    pub mod sentinel;
    pub mod telemetry;
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
pub use base::config::PhalanxConfig;
pub use primitives::identity::PhalanxIdentity;
pub use transport::swarm::{setup_phalanx_swarm, PhalanxBehaviour, PhalanxEvent};

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
