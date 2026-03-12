// crates/phalanx-forensics/src/lib.rs
pub mod c2pa_ext;
pub mod crucible;
pub mod cryptography;
pub mod errors;
pub mod gate;
pub mod identity;
pub mod judge;
pub mod kademlia;
pub mod policy;
pub mod reassembler;
pub mod test_utils;
pub mod trust;
pub mod witness;
pub mod storage {
    pub mod handover;
    pub mod journal;
}

// Re-export primary structures for ergonomic use

pub use crucible::{Crucible, Mold, VolleyAmalgam};
pub use cryptography::{decrypt_bytes, encrypt_bytes, generate_session_key};
pub use judge::{Decryptor, HandoverJudge, PayloadCipher};
pub use policy::TrafficGovernor;
pub use reassembler::{AudioWeaver, FountainChunkifier, Reassembler, ShardMold, VideoWeaver};
pub use trust::{PeerEvaluator, ReputationGate};

/// The Laboratory Prelude: Bringing the Verbs into scope for the Actors.
pub mod prelude {
    pub use crate::crucible::{Crucible, Mold, VolleyAmalgam};
    pub use crate::cryptography::{decrypt_bytes, encrypt_bytes};
    pub use crate::judge::{Decryptor, HandoverJudge, PayloadCipher};
    pub use crate::policy::TrafficGovernor;
    pub use crate::reassembler::{Reassembler, ShardMold};
    pub use crate::storage::journal::TransientJournal;
    pub use crate::trust::PeerEvaluator;
}
