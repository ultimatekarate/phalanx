// The Narrators: StorageActor, Sentinel
pub mod actors{
    pub mod meshsentinel;
    pub mod storage;
}      
pub mod orchestrator; // The Logic: Wiring Transport to Actors
pub mod state;        // The Context: Shared node state
pub mod config;

// Re-export the Narrators for the Simulation Author
pub use actors::storage::StorageActor;
pub use actors::sentinel::Sentinel;
pub use orchestrator::run_node;

/// The "Sentence" Result type
pub type NodeResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;