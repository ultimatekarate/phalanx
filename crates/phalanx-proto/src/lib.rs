// crates/phalanx-proto/src/lib.rs

pub mod constants;
pub mod crypto;
pub mod error; // The Oops
pub mod evidence; // The What
pub mod identity; // The Who
pub mod kademlia; // The Ledger Nouns
pub mod network;
pub mod playback;
pub mod retrieval;
pub mod storage; // The Vault Nouns
pub mod telemetry;
pub mod time; // The When
pub mod topic; // The Where
pub mod trust; // The Social Graph
pub mod types;
pub mod vitals; // The Health Nouns
pub mod prelude {
    // Identity Nouns
    pub use crate::identity::{
        Did, NetworkId, PhalanxIdentity, RecordingId, ShardId, IDENTITY_VERSION,
    };

    // Evidence Nouns
    pub use crate::evidence::{
        AudioFrame, DataPayload, EnvelopeState, ForensicMetrics, ShardChunk, SignatureHash,
        VideoFrame,
    };

    pub use crate::constants::{RECORDING_SIZE_THRESHOLD, RECORDING_TIME_THRESHOLD};
    // Contextual Nouns
    pub use crate::time::{PhalanxTimestamp, TimeError, TrustedClock};
    pub use crate::topic::MeshTopic;
    pub use crate::types::PhalanxPhysics;

    // Four Pillars Newtypes
    pub use crate::types::{
        BlackLevel, ChannelCount, EncodingSymbolId, Fps, RepairRatio, SampleRate, SymbolSize,
    };

    // Error Nouns
    pub use crate::error::*;
    pub use crate::retrieval::RecordingResponse;
    pub use crate::storage::{GuardianError, PendingEgress};

    // Trust & Networking Nouns
    pub use crate::kademlia::{DhtPayload, PayloadKind};
    pub use crate::network::{NetworkEvent, DISCOVERY_TOPIC_ID, RETRIEVAL_PROTOCOL_ID};
    pub use crate::trust::{MonotonicClock, PetName, TrustLevel};
    pub use crate::vitals::ControlMessage;

    // Playback Nouns
    pub use crate::playback::PlaybackSink;
}

// Re-export the canonical Retrieval Nouns from their home modules.
pub use retrieval::{RecordingRequest, RecordingResponse};

pub const MAX_PAYLOAD_SIZE: usize = 10_000_000;
