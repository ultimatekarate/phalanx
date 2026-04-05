pub mod clock; // The "Tense Control": Management of virtual time
pub mod harness; // The "Pen": Your API for writing simulation scripts
pub mod physics; // The Physical Laws of the Simulation
pub mod world; // The "Ether": Shared state where nodes meet // The "Adverbs": Logic for dropping/delaying packets

pub use clock::VirtualClock;
pub use harness::{
    NodeMetrics, RecoveryJournal, SimConfig, SimEgress, SimIngress, SimulationHarness,
    TelemetryCollector,
};
pub use world::SimulationWorld;

/// High-level errors that occur during the "Authoring" of a simulation.
#[derive(Debug, thiserror::Error)]
pub enum SimError {
    #[error("Node {0} not found in simulation world")]
    NodeNotFound(phalanx_proto::prelude::Did),

    #[error("Simulation timeout after {0:?}")]
    Timeout(std::time::Duration),

    #[error("Internal transport failure: {0}")]
    Transport(String),
}
