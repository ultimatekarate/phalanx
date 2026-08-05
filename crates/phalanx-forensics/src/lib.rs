// crates/phalanx-forensics/src/lib.rs

// ─── Domain modules ──────────────────────────────────────────────────
pub mod cryptography;
pub mod pipeline; // Evidence Assembly — crucible, reassembler, witness, transcode, calibrate, c2pa
pub mod trust; // Integrity — evaluation, corroboration, eclipse, revocation
pub mod verification; // The Gates — gate, topology_gate, judge, bloom // Crypto primitives — encrypt, decrypt, grants, bridge

// ─── Cross-cutting ───────────────────────────────────────────────────
pub mod archive; // Custody Verbs — sign/verify archive push request + receipt
pub mod errors;
pub mod identity;
pub mod kademlia;
pub mod policy;
pub mod test_utils;
pub mod unit; // The ForensicUnit typestate — in-process verification states
pub mod storage {
    pub mod handover;
}

// ─── Backward-compatible re-exports ──────────────────────────────────
// Every module that moved into a subdirectory is re-exported at the old
// path so that `crate::gate::X` still resolves. New code should prefer
// the grouped paths (e.g. `crate::verification::gate::X`).

// verification/*
pub use verification::bloom;
pub use verification::gate;
pub use verification::judge;
pub use verification::topology_gate;

// pipeline/*
pub use pipeline::c2pa_ext;
pub use pipeline::calibrate;
pub use pipeline::crucible;
pub use pipeline::export;
pub use pipeline::reassembler;
pub use pipeline::transcode;
pub use pipeline::witness;

// trust/*
pub use trust::corroboration;
pub use trust::eclipse;
pub use trust::revocation;

// Re-export primary structures for ergonomic use

pub use crucible::{Crucible, Mold, RecordingAmalgam};
pub use cryptography::dek::{
    derive_dek_master, derive_manifest_recording_id, derive_recording_dek,
};
pub use cryptography::{decrypt_bytes, encrypt_bytes, generate_session_key};
pub use export::{ExportError, ExportedArtifact, export_recording_to_signed_mp4, identity_signer};
pub use judge::{HandoverJudge, PayloadCipher, decode_payload};
pub use policy::TrafficGovernor;
pub use policy::{
    BandwidthScale, ConnectionScale, DecayingIntegral, FinalizationScale, Homeostasis,
    HomeostaticConfig, IngestionScale, MemoryScale, ResourceIntegrals, StorageScale,
    SybilEndowment,
};
pub use reassembler::{AudioWeaver, FountainChunkifier, Reassembler, ShardMold, VideoWeaver};
#[cfg(feature = "software-transcode")]
pub use transcode::SoftwareTranscoder;
pub use transcode::{EncodedMedia, MediaTranscoder, transcode_recording};
pub use trust::{PeerEvaluator, ReputationGate};
pub use unit::{ForensicUnit, Sealed, Unverified, ValidationState, Verified};

/// The Laboratory Prelude: Bringing the Verbs into scope for the Actors.
pub mod prelude {
    pub use crate::crucible::{Crucible, Mold, RecordingAmalgam};
    pub use crate::cryptography::{decrypt_bytes, encrypt_bytes};
    pub use crate::judge::{HandoverJudge, PayloadCipher, decode_payload};
    pub use crate::policy::TrafficGovernor;
    pub use crate::reassembler::{Reassembler, ShardMold};
    // TransientJournal is now in phalanx_proto::storage (canonical location).
    // Import directly: `use phalanx_proto::storage::TransientJournal;`
    pub use crate::trust::PeerEvaluator;

    // Eclipse & Topology
    pub use crate::eclipse::{EclipseProbe, MeshFingerprint};
    pub use crate::topology_gate::{
        AdmissionDenied, AdmissionTicket, AnchorEligible, TopologyGate,
    };
}
