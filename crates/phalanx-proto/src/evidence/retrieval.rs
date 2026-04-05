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

impl RecordingRequest {
    /// H1: Maximum byte length for the Ed25519 signature field.
    const MAX_SIGNATURE_LEN: usize = 64;
}

/// H3: Wire-bound enforcement for inbound retrieval requests.
/// Truncates oversized string identifiers and signature fields to prevent
/// amplification via multi-megabyte DIDs or RecordingIds.
impl crate::wire::WireBound for RecordingRequest {
    fn enforce_wire_bounds(&mut self) {
        if self.target_did.0.len() > Did::MAX_WIRE_LEN {
            tracing::warn!(
                len = self.target_did.0.len(),
                limit = Did::MAX_WIRE_LEN,
                "H1: Wire bound — target_did truncated"
            );
            self.target_did.0.truncate(Did::MAX_WIRE_LEN);
        }
        if self.recording_id.0.len() > RecordingId::MAX_WIRE_LEN {
            tracing::warn!(
                len = self.recording_id.0.len(),
                limit = RecordingId::MAX_WIRE_LEN,
                "H1: Wire bound — recording_id truncated"
            );
            self.recording_id.0.truncate(RecordingId::MAX_WIRE_LEN);
        }
        if self.locator.recipient.0.len() > Did::MAX_WIRE_LEN {
            self.locator.recipient.0.truncate(Did::MAX_WIRE_LEN);
        }
        if self.locator.sender.0.len() > Did::MAX_WIRE_LEN {
            self.locator.sender.0.truncate(Did::MAX_WIRE_LEN);
        }
        if self.locator.target.0.len() > RecordingId::MAX_WIRE_LEN {
            self.locator.target.0.truncate(RecordingId::MAX_WIRE_LEN);
        }
        if self.signature.len() > Self::MAX_SIGNATURE_LEN {
            self.signature.truncate(Self::MAX_SIGNATURE_LEN);
        }
    }
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
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
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
            revocation_key: crate::revocation::RevocationKey::default(),
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
