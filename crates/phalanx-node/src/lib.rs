// crates/phalanx-node/src/lib.rs

pub mod actors {
    pub mod canary_supervisor;
    pub mod eclipse_router;
    pub mod egress;
    pub mod ingestion;
    pub mod media_egress;
    pub mod mesh_policy;
    pub mod meshsentinel;
    pub mod playback;
    pub mod recording_session;
    pub mod recovery;
    pub mod retrieval;
    pub mod retrieval_request;
    pub mod shutdown;
    pub mod storage;
    pub mod trust_actor;

    pub use shutdown::ShutdownSignal;
}

pub mod clock;
pub mod config;
pub mod engine;

pub mod playback {
    pub mod sink;
}
pub mod hardware {
    pub mod audio;
    pub mod camera;
}
pub mod identity;

pub mod network {
    pub mod orchestrator;
}
pub mod psk;
pub mod persistence {
    pub mod journal;
    pub mod kademlia;
    pub mod outbound;
    pub mod vault;
}

pub mod trust;

pub mod vitals {
    pub mod canary;
    pub mod config;
    pub mod governor;
    pub mod hardware;
    pub mod health;
    pub mod spectral;
    pub mod types;

    pub use canary::*;
    pub use config::*;
    pub use governor::*;
    pub use hardware::*;
    pub use health::*;
    pub use spectral::*;
    pub use types::*;
}

#[cfg(feature = "stability-analysis")]
pub mod stability {
    pub mod config;
    pub mod contractivity;
    pub mod dyson;
    pub mod eigenvalues;
    pub mod integrators;
    pub mod jacobian;
    pub mod nonlinear;
    pub mod pade;
    pub mod spectral;

    pub use config::*;
    pub use dyson::*;
    pub use eigenvalues::*;
    pub use integrators::*;
    pub use jacobian::*;
    pub use nonlinear::*;
    pub use pade::*;
    pub use spectral::*;
}

#[macro_use]
extern crate tracing;

// Re-export the Narrators and Physical Hooks
//
// `MeshSentinel` is *deliberately not* re-exported at the crate root or in
// the prelude. The audit-driven structural refactor in `engine.rs` forces
// all external consumers (especially `phalanx-ffi`) through
// `UnspawnedEngine` / `EngineHandle` / `EngineLifecycle`, so they cannot
// construct an `Arc<Mutex<MeshSentinel>>` and re-introduce the H1/H2/H3
// deadlock class. The type is still reachable inside `phalanx-node`
// (e.g. `phalanx-sim` driver and the in-crate sentinel binary) via the
// fully-qualified `actors::meshsentinel::MeshSentinel` path; that's a
// deliberately-uglier import, since those callers also drive the run
// loop directly and are signing up for the linear-ownership contract.
pub use actors::storage::StorageActor;
pub use clock::TrustedClock;
pub use config::NodeConfig;
pub use engine::{EngineHandle, EngineLifecycle, ShutdownError, UnspawnedEngine};
pub use persistence::journal::FileJournal;
pub use persistence::vault::Guardian;

// Playback re-exports
pub use actors::playback::{PlaybackCoordinator, PlaybackStats};
pub use playback::sink::{ArtifactSink, VideoPlayerSink};

pub mod prelude {
    pub use crate::clock::TrustedClock;
    pub use crate::config::NodeConfig;
    pub use crate::persistence::journal::FileJournal;
    pub use crate::persistence::vault::Guardian;
    pub use crate::NodeResult;
}

pub type NodeResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
