// crates/phalanx-proto/src/lib.rs

// ─── Domain modules ──────────────────────────────────────────────────
pub mod evidence; // The What — envelope, corroboration, revocation, playback, retrieval
pub mod identity; // The Who — DID, community, trust, crypto
pub mod network; // The Mesh — events, topology, kademlia, wire, topic

// ─── Cross-cutting ───────────────────────────────────────────────────
pub mod constants;
pub mod error; // The Oops
pub mod storage; // The Vault Nouns
pub mod telemetry;
pub mod time; // The When
pub mod types;
pub mod vitals; // The Health Nouns

// ─── Backward-compatible re-exports ──────────────────────────────────
// Every module that moved into a subdirectory is re-exported at the old
// path so that `crate::corroboration::X` still resolves. New code should
// prefer the grouped paths (e.g. `crate::evidence::corroboration::X`).

// evidence/*
pub use evidence::corroboration;
pub use evidence::playback;
pub use evidence::retrieval;
pub use evidence::revocation;

// identity/*
pub use identity::community;
pub use identity::crypto;
pub use identity::trust;

// network/*
pub use network::kademlia;
pub use network::topic;
pub use network::topology;
pub use network::wire;

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
    pub use crate::network::topic::MeshTopic;
    pub use crate::time::{PhalanxTimestamp, TimeError, TrustedClock};
    pub use crate::types::PhalanxPhysics;

    // Four Pillars Newtypes
    pub use crate::types::{
        BlackLevel, ChannelCount, EncodingSymbolId, Fps, RepairRatio, SampleRate, SymbolBundleSize,
        SymbolSize,
    };

    // Error Nouns
    pub use crate::error::*;
    pub use crate::evidence::retrieval::RecordingResponse;
    pub use crate::storage::GuardianError;

    // Trust & Networking Nouns
    pub use crate::identity::trust::{PetName, TrustLevel};
    pub use crate::network::kademlia::{DhtPayload, PayloadKind};
    pub use crate::network::topology::{EclipseRisk, SubnetBucket, SubnetQuota, TransportClass};
    pub use crate::network::{NetworkEvent, DISCOVERY_TOPIC_ID, RETRIEVAL_PROTOCOL_ID};
    pub use crate::time::MonotonicClock;
    pub use crate::vitals::ControlMessage;

    // Playback Nouns
    pub use crate::evidence::playback::PlaybackSink;

    // Wire Contract
    pub use crate::network::wire::WireBound;
}

// Re-export the canonical Retrieval Nouns from their home modules.
pub use evidence::retrieval::{RecordingRequest, RecordingResponse};

pub const MAX_PAYLOAD_SIZE: usize = 10_000_000;
