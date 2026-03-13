use crate::evidence::WitnessEnvelope;
use serde::{Deserialize, Serialize};

use crate::crypto::SealedLocator;
use crate::identity::{Did, RecordingId};
use crate::types::{ForensicUnit, Sealed};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingRequest {
    pub target_did: Did,           // The owner of the forensic data
    pub recording_id: RecordingId, // Specific collection identifier
    pub locator: SealedLocator,    // Forensic grant
    pub signature: Vec<u8>,        // Proof of requester identity
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecordingResponse {
    Success(Vec<ForensicUnit<WitnessEnvelope, Sealed>>),
    Busy,         // Resource-based shedding
    NotFound,     // Data missing from local Guardian
    Unauthorized, // Cryptographic proof failed
}
