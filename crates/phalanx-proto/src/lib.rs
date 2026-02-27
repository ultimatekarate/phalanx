// crates/phalanx-proto/src/lib.rs

pub mod identity;   // The Who
pub mod evidence;   // The What
pub mod topic;      // The Where
pub mod time;       // The When
pub mod error;

// Re-export the core Nouns for ergonomic "Sentence" construction
pub use identity::*;
pub use evidence::*;
pub use topic::*;
pub use time::*;

pub mod prelude {
    // Identity Nouns
    pub use crate::identity::{Did, ShardId, VolleyId};
    
    // Evidence Nouns
    pub use crate::evidence::{
        ShardChunk, 
        DataPayload, 
        HandoverProof, 
        SignatureHash,
        ShardGapReport,
        FragmentedEnvelope,
        EnvelopeState
    };
    
    // Contextual Nouns
    pub use crate::topic::MeshTopic;
    pub use crate::time::{PhalanxTimestamp, TrustedClock};
    
    // Error Nouns
    pub use crate::error::{ShardError, TimeError};
}

use serde::{Serialize, Deserialize};

// Nouns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolleyRequest {
    pub target_did: Did,
    pub volley_id: VolleyId,
    pub locator: PhalanxLocator,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VolleyResponse {
    Success(Vec<WitnessEnvelope>),
    Throttled,
    NotFound,
    Unauthorized,
}

pub const MAX_PAYLOAD_SIZE: usize = 10_000_000;