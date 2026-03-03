// crates/phalanx-forensics/src/lib.rs

pub mod crucible;
pub mod cryptography;
pub mod identity;
pub mod judge;
pub mod kademlia;
pub mod policy;
pub mod reassembler;
pub mod trust;
pub mod witness;

pub mod storage {
    pub mod handover;
    pub mod journal;
}

// Re-export primary structures for ergonomic use

pub use crucible::{Crucible, Mold, VolleyAmalgam};
pub use cryptography::{decrypt_bytes, encrypt_bytes, generate_session_key};
pub use judge::{Decryptor, HandoverJudge};
pub use policy::TrafficGovernor;
pub use reassembler::{
    AudioWeaver, Chunkifier, Reassembler, ReassemblyBuffer, ShardAmalgam, ShardMold, VideoWeaver,
};
pub use trust::{PeerEvaluator, ReputationGate};

/// The Laboratory Prelude: Bringing the Verbs into scope for the Actors.
pub mod prelude {
    pub use crate::crucible::{Crucible, Mold, VolleyAmalgam};
    pub use crate::cryptography::{decrypt_bytes, encrypt_bytes};
    pub use crate::judge::{Decryptor, HandoverJudge};
    pub use crate::policy::TrafficGovernor;
    pub use crate::reassembler::{Reassembler, ShardAmalgam, ShardMold};
    pub use crate::storage::journal::TransientJournal;
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
