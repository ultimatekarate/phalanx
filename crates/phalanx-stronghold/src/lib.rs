// crates/phalanx-stronghold/src/lib.rs
//
// The Stronghold: Hands-layer crate for desktop/server.
// Aggregates recordings from the gossip mesh, runs the Corroboration Gate,
// and produces signed proofs of multi-device sensor independence.
//
// Consumes Dictionary (phalanx-proto) and Laboratory (phalanx-forensics) unchanged.
// No Volterra mobile power management. No BLE. No FPS regulation.

pub mod actors {
    pub mod aggregation;
    pub mod community;
}
pub mod config;
pub mod custody; // Per-owner storage fairness (the balancing ratio)
pub mod error;
pub mod governor;
pub mod paths;
pub mod ops {
    pub mod corroborate;
    pub mod export;
}
pub mod persistence {
    mod atomic;
    pub mod evidence_store;
    pub mod proof_store;
}
pub mod sentinel;
pub mod signing;
pub mod swarm;

#[cfg(feature = "gui")]
pub mod gui;

pub use config::StrongholdConfig;
pub use error::StrongholdError;
pub use governor::StrongholdGovernor;
pub use sentinel::{StrongholdDependencies, StrongholdSentinel};
