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
    pub mod journal;
    pub mod kademlia;
    pub mod reassembler;
    pub mod strategies;
    pub mod vault;
}

// --- 4. TRANSPORT ---
pub mod transport {
    pub mod health;
    pub mod protocol;
    pub mod swarm;
}

// --- 5. SECURITY ---
pub mod security {
    pub mod e2ee;
    pub mod gate;
    pub mod grant;
    pub mod ingress;
    pub mod locator;
    pub mod retrieval;
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
pub use primitives::identity::{init_identity, IdentityError, PhalanxIdentity};
pub use transport::swarm::{setup_phalanx_swarm, PhalanxBehaviour, PhalanxEvent};
