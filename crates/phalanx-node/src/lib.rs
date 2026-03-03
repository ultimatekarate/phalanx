// crates/phalanx-node/src/lib.rs

pub mod actors {
    pub mod ingress;
    pub mod meshsentinel;
    pub mod playback;
    pub mod retrieval;
    pub mod storage;
}

pub mod artifacts;
pub mod clock;
pub mod config;
pub mod hardware {
    pub mod audio;
    pub mod camera;
}
pub mod identity;

pub mod state;
pub mod storage {
    pub mod journal;
    pub mod kademlia;
    pub mod vault;
}

pub mod trust;
pub mod vitals;

#[macro_use]
extern crate tracing;

// Re-export the Narrators and Physical Hooks
pub use actors::meshsentinel::MeshSentinel;
pub use actors::storage::StorageActor;
pub use clock::TrustedClock;
pub use config::PhalanxConfig;
pub use storage::journal::FileJournal;
pub use storage::vault::Guardian;

pub mod prelude {
    pub use crate::actors::meshsentinel::MeshSentinel;
    pub use crate::clock::TrustedClock;
    pub use crate::storage::journal::FileJournal;
    pub use crate::storage::vault::Guardian;
    pub use crate::NodeResult;
}

pub type NodeResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
