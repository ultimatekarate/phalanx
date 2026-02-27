// crates/phalanx-forensics/src/lib.rs

pub mod chain;
pub mod crucible;
pub mod cryptography; // Pointing to src/cryptography/mod.rs
pub mod judge;
pub mod kademlia;
pub mod policy;
pub mod reassembler;
pub mod trust;

// Re-export primary structures for ergonomic use
pub use chain::{Decryptor, VolleyAmalgam};
pub use crucible::{BufferCapacityGate, ChronosGate, Crucible, Mold};
pub use cryptography::{decrypt_bytes, encrypt_bytes, generate_session_key};
pub use judge::HandoverJudge;
pub use policy::TrafficGovernor;
pub use reassembler::{
    AudioWeaver, Chunkifier, Reassembler, ReassemblyBuffer, ShardAmalgam, ShardFactory, ShardMold,
    TransientJournal, VideoWeaver, Weaver,
};
pub use trust::{PeerEvaluator, ReputationGate};

/// The Laboratory Prelude: Bringing the Verbs into scope for the Actors.
pub mod prelude {
    pub use crate::chain::{Decryptor, VolleyAmalgam};
    pub use crate::crucible::{Crucible, Mold};
    pub use crate::cryptography::{decrypt_bytes, encrypt_bytes};
    pub use crate::judge::HandoverJudge;
    pub use crate::policy::TrafficGovernor;
    pub use crate::reassembler::{
        Reassembler, ShardAmalgam, ShardMold, TransientJournal,
    };
    pub use crate::trust::PeerEvaluator;
    pub use crate::ForensicError;
}

/// A common error type for Forensic operations
#[derive(Debug, thiserror::Error)]
pub enum ForensicError {
    #[error("Assembly failure: {0}")]
    Assembly(String),

    #[error("Integrity failure: {0}")]
    Validation(String),

    #[error("Cryptographic failure: {0}")]
    Crypto(String),

    #[error("Decompression failure: {0}")]
    Decompression(String),
}