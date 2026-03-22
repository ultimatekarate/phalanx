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

impl RecordingResponse {
    /// S4: Maximum envelope count in a single response.
    pub const MAX_RESPONSE_ENVELOPES: usize = 256;
}

impl crate::wire::WireBound for RecordingResponse {
    fn enforce_wire_bounds(&mut self) {
        if let RecordingResponse::Success(ref mut units) = self {
            if units.len() > Self::MAX_RESPONSE_ENVELOPES {
                tracing::warn!(
                    count = units.len(),
                    limit = Self::MAX_RESPONSE_ENVELOPES,
                    "S4: Wire bound — response envelope count truncated"
                );
                units.truncate(Self::MAX_RESPONSE_ENVELOPES);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{Evidence, ForensicGap, StorageSequence};
    use crate::identity::NetworkId;
    use crate::time::PhalanxTimestamp;
    use crate::types::{ForensicUnit, Verified};
    use crate::wire::WireBound;

    fn dummy_sealed_unit() -> ForensicUnit<WitnessEnvelope, Sealed> {
        let envelope = WitnessEnvelope {
            evidence: Evidence::Gap(ForensicGap {
                recording_id: RecordingId::new("test_rec"),
                start_seq: StorageSequence(0),
                end_seq: StorageSequence(1),
                detected_at: PhalanxTimestamp::now(),
            }),
            evidence_hash: [0u8; 32],
            witness_peer_id: NetworkId("test_peer".into()),
            witness_signature: vec![0u8; 64],
            did: Did::new("did:test:dummy"),
            prev_hash: None,
        };
        ForensicUnit::<_, Verified>::new_verified(envelope).seal()
    }

    #[test]
    fn s4_wire_bound_truncates_oversized_response() {
        let units: Vec<_> = (0..500).map(|_| dummy_sealed_unit()).collect();
        let mut response = RecordingResponse::Success(units);

        response.enforce_wire_bounds();

        if let RecordingResponse::Success(ref units) = response {
            assert_eq!(units.len(), RecordingResponse::MAX_RESPONSE_ENVELOPES);
        } else {
            panic!("Expected Success variant");
        }
    }

    #[test]
    fn s4_wire_bound_noop_on_non_success_variants() {
        let mut busy = RecordingResponse::Busy;
        busy.enforce_wire_bounds();

        let mut not_found = RecordingResponse::NotFound;
        not_found.enforce_wire_bounds();

        let mut unauthorized = RecordingResponse::Unauthorized;
        unauthorized.enforce_wire_bounds();
    }

    #[test]
    fn s4_wire_bound_noop_within_limit() {
        let units: Vec<_> = (0..10).map(|_| dummy_sealed_unit()).collect();
        let mut response = RecordingResponse::Success(units);

        response.enforce_wire_bounds();

        if let RecordingResponse::Success(ref units) = response {
            assert_eq!(units.len(), 10);
        } else {
            panic!("Expected Success variant");
        }
    }
}
