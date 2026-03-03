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

pub mod playback {
    pub mod sink;
}
pub mod hardware {
    pub mod audio;
    pub mod camera;
}
pub mod identity;

pub mod state;
pub mod persistence {
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
pub use config::NodeConfig;
pub use persistence::journal::FileJournal;
pub use persistence::vault::Guardian;

// Playback re-exports
pub use actors::playback::PlaybackCoordinator;
pub use playback::sink::{ArtifactSink, VideoPlayerSink};

pub mod prelude {
    pub use crate::actors::meshsentinel::MeshSentinel;
    pub use crate::clock::TrustedClock;
    pub use crate::config::NodeConfig;
    pub use crate::persistence::journal::FileJournal;
    pub use crate::persistence::vault::Guardian;
    pub use crate::NodeResult;
}

pub type NodeResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
