// crates/phalanx-forensics/src/lib.rs
pub mod bloom;
pub mod c2pa_ext;
pub mod calibrate;
pub mod corroboration;
pub mod crucible;
pub mod cryptography;
pub mod eclipse;
pub mod errors;
pub mod gate;
pub mod identity;
pub mod judge;
pub mod kademlia;
pub mod policy;
pub mod reassembler;
pub mod test_utils;
pub mod topology_gate;
pub mod transcode;
pub mod trust;
pub mod witness;
pub mod storage {
    pub mod handover;
}

// Re-export primary structures for ergonomic use

pub use crucible::{Crucible, Mold, RecordingAmalgam};
pub use cryptography::{decrypt_bytes, encrypt_bytes, generate_session_key};
pub use judge::{Decryptor, HandoverJudge, PayloadCipher};
pub use policy::TrafficGovernor;
pub use policy::{
    BandwidthScale, ConnectionScale, DecayingIntegral, FinalizationScale, Homeostasis,
    HomeostaticConfig, IngestionScale, MemoryScale, ResourceIntegrals, StorageScale,
    SybilEndowment,
};
pub use reassembler::{AudioWeaver, FountainChunkifier, Reassembler, ShardMold, VideoWeaver};
pub use trust::{PeerEvaluator, ReputationGate};

/// The Laboratory Prelude: Bringing the Verbs into scope for the Actors.
pub mod prelude {
    pub use crate::crucible::{Crucible, Mold, RecordingAmalgam};
    pub use crate::cryptography::{decrypt_bytes, encrypt_bytes};
    pub use crate::judge::{Decryptor, HandoverJudge, PayloadCipher};
    pub use crate::policy::TrafficGovernor;
    pub use crate::reassembler::{Reassembler, ShardMold};
    // TransientJournal is now in phalanx_proto::storage (canonical location).
    // Import directly: `use phalanx_proto::storage::TransientJournal;`
    pub use crate::trust::PeerEvaluator;

    // Eclipse & Topology
    pub use crate::eclipse::{EclipseProbe, MeshFingerprint};
    pub use crate::topology_gate::{
        AdmissionDenied, AdmissionTicket, AnchorEligible, TopologyGate, TransportBalance,
    };
}
