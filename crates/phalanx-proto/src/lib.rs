// crates/phalanx-proto/src/lib.rs

pub mod constants;
pub mod crypto;
pub mod error; // The Oops
pub mod evidence; // The What
pub mod identity; // The Who
pub mod kademlia; // The Ledger Nouns
pub mod network;
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
    pub use crate::identity::{Did, NetworkId, PhalanxIdentity, ShardId, VolleyId};

    // Evidence Nouns
    pub use crate::evidence::{
        DataPayload, EnvelopeState, FragmentedEnvelope, ShardChunk, ShardGapReport, SignatureHash,
    };

    pub use crate::constants::{VOLLEY_SIZE_THRESHOLD, VOLLEY_TIME_THRESHOLD};
    // Contextual Nouns
    pub use crate::time::{PhalanxTimestamp, TrustedClock};
    pub use crate::topic::MeshTopic;
    pub use crate::types::PhalanxPhysics;

    // Error Nouns
    pub use crate::error::{ShardError, TimeError};
    pub use crate::storage::{GuardianError, PendingEgress, VolleyResponse};

    // Trust & Networking Nouns
    pub use crate::kademlia::{DhtPayload, PayloadKind};
    pub use crate::network::NetworkEvent;
    pub use crate::trust::{PetName, TrustLevel};
    pub use crate::vitals::ControlMessage;
}

use crate::evidence::WitnessEnvelope;
use crate::identity::PhalanxLocator;
use crate::prelude::Did;
use crate::prelude::VolleyId;

use serde::{Deserialize, Serialize};

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
