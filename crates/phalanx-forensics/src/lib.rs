pub mod weaver;   // The Verb "To Assemble" (Reassembler logic)
pub mod judge;    // The Verb "To Verify" (Signature/Integrity logic)
pub mod crucible; // The Verb "To Stage" (Hot-path storage logic)

// Re-export primary structures
pub use weaver::{Weaver, WeaverStatus, ReassemblyBuffer};
pub use crucible::{Crucible, TransientJournal};

/// The Laboratory Prelude: Bringing the Verbs into scope for the Actors.
pub mod prelude {
    pub use crate::weaver::{Weaver, WeaverStatus, Chunkifier, ShardFactory};
    pub use crate::judge::{HandoverJudge, JudgeExt};
    pub use crate::crucible::{Crucible, TransientJournal};
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