use crate::evidence::WitnessEnvelope;
use serde::{Deserialize, Serialize};

use crate::crypto::SealedLocator;
use crate::identity::{Did, VolleyId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolleyRequest {
    pub target_did: Did,        // The owner of the forensic data
    pub volley_id: VolleyId,    // Specific collection identifier
    pub locator: SealedLocator, // Forensic grant
    pub signature: Vec<u8>,     // Proof of requester identity
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VolleyResponse {
    Success(Vec<WitnessEnvelope>),
    Busy,         // Resource-based shedding
    NotFound,     // Data missing from local Guardian
    Unauthorized, // Cryptographic proof failed
}
