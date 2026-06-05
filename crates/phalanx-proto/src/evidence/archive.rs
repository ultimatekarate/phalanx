// crates/phalanx-proto/src/evidence/archive.rs
//
// The Custody Nouns: directed push of evidence to an archival Stronghold,
// and the signed receipt acknowledging custody.
//
// Unlike `retrieval.rs` (a PULL: the responder returns envelopes), the archive
// protocol is a PUSH — the *initiator* carries the shards in `ArchiveRequest`,
// and the responder returns an `ArchiveReceipt` attesting it took custody until
// `held_until`. Custody is transient by design (the receipt names its own
// expiry); Phalanx is export-staging, not long-term storage.

use crate::evidence::WitnessEnvelope;
use crate::identity::{Did, RecordingId};
use crate::time::PhalanxTimestamp;
use crate::wire::WireBound;
use serde::{Deserialize, Serialize};

/// A directed push of a recording's envelopes to an archival peer.
///
/// The initiator carries the shards. Each envelope is already individually
/// signed by its owner (`witness_signature`); the request-level `signature`
/// authenticates the *pusher* (`sender_did`) over the recording id + the set of
/// envelope hashes, so custody/quota can be attributed to a real identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveRequest {
    pub recording_id: RecordingId,
    pub envelopes: Vec<WitnessEnvelope>,
    pub sender_did: Did,
    /// Ed25519 signature by `sender_did` over [`ArchiveRequest::signing_bytes`].
    pub signature: Vec<u8>,
}

impl ArchiveRequest {
    /// Maximum envelope count in a single push (mirrors `RecordingResponse`).
    pub const MAX_ENVELOPES: usize = 256;
    /// Maximum byte length for the Ed25519 signature field.
    const MAX_SIGNATURE_LEN: usize = 64;

    /// Canonical bytes the sender signs: `recording_id || sender_did ||
    /// evidence_hash*`. Pure byte concatenation (Dictionary-layer; no crypto).
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.recording_id.0.as_bytes());
        buf.extend_from_slice(self.sender_did.0.as_bytes());
        for env in &self.envelopes {
            buf.extend_from_slice(&env.evidence_hash);
        }
        buf
    }
}

/// H-bound: cap envelope count and string/signature lengths so a malicious
/// push cannot amplify memory on the wire.
impl WireBound for ArchiveRequest {
    fn enforce_wire_bounds(&mut self) {
        if self.envelopes.len() > Self::MAX_ENVELOPES {
            self.envelopes.truncate(Self::MAX_ENVELOPES);
        }
        if self.recording_id.0.len() > RecordingId::MAX_WIRE_LEN {
            self.recording_id.0.truncate(RecordingId::MAX_WIRE_LEN);
        }
        if self.sender_did.0.len() > Did::MAX_WIRE_LEN {
            self.sender_did.0.truncate(Did::MAX_WIRE_LEN);
        }
        if self.signature.len() > Self::MAX_SIGNATURE_LEN {
            self.signature.truncate(Self::MAX_SIGNATURE_LEN);
        }
    }
}

/// The Stronghold's reply to an archive push.
///
/// `Stored` is a signed, self-verifiable custody receipt: it names the replica
/// (`replica_did`), when custody began (`stored_at`), and the deadline the
/// replica commits to hold until (`held_until`) — the publisher's export-by
/// time. Non-`Stored` variants are admission/throttle rejections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArchiveReceipt {
    Stored {
        recording_id: RecordingId,
        replica_did: Did,
        stored_at: PhalanxTimestamp,
        held_until: PhalanxTimestamp,
        envelope_count: u32,
        /// Ed25519 signature by `replica_did` over
        /// [`ArchiveReceipt::stored_signing_bytes`]. Self-verifiable.
        signature: Vec<u8>,
    },
    /// Transient resource shedding — retry later.
    Busy,
    /// The owner's per-owner custody share (or a community/global cap) is full.
    QuotaExceeded,
    /// Structurally/cryptographically rejected (bad signature, non-member, …).
    Rejected,
}

impl ArchiveReceipt {
    /// Maximum byte length for the Ed25519 signature field.
    const MAX_SIGNATURE_LEN: usize = 64;

    /// Canonical bytes the replica signs for a `Stored` receipt:
    /// `recording_id || replica_did || stored_at || held_until || envelope_count`.
    /// Pure byte concatenation (Dictionary-layer; no crypto).
    #[must_use]
    pub fn stored_signing_bytes(
        recording_id: &RecordingId,
        replica_did: &Did,
        stored_at: PhalanxTimestamp,
        held_until: PhalanxTimestamp,
        envelope_count: u32,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(recording_id.0.as_bytes());
        buf.extend_from_slice(replica_did.0.as_bytes());
        buf.extend_from_slice(&stored_at.as_u64().to_le_bytes());
        buf.extend_from_slice(&held_until.as_u64().to_le_bytes());
        buf.extend_from_slice(&envelope_count.to_le_bytes());
        buf
    }
}

impl WireBound for ArchiveReceipt {
    fn enforce_wire_bounds(&mut self) {
        if let ArchiveReceipt::Stored {
            recording_id,
            replica_did,
            signature,
            ..
        } = self
        {
            if recording_id.0.len() > RecordingId::MAX_WIRE_LEN {
                recording_id.0.truncate(RecordingId::MAX_WIRE_LEN);
            }
            if replica_did.0.len() > Did::MAX_WIRE_LEN {
                replica_did.0.truncate(Did::MAX_WIRE_LEN);
            }
            if signature.len() > Self::MAX_SIGNATURE_LEN {
                signature.truncate(Self::MAX_SIGNATURE_LEN);
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
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use crate::evidence::{Evidence, ForensicGap, StorageSequence};
    use crate::identity::WitnessId;
    use crate::revocation::RevocationKey;

    fn envelope(seq: u32) -> WitnessEnvelope {
        WitnessEnvelope {
            evidence: Evidence::Gap(ForensicGap {
                recording_id: RecordingId::new("rec"),
                start_seq: StorageSequence(seq),
                end_seq: StorageSequence(seq + 1),
                detected_at: PhalanxTimestamp::from_millis(1),
            }),
            evidence_hash: [seq as u8; 32],
            witness_peer_id: WitnessId::new("peer"),
            witness_signature: vec![0u8; 64],
            did: Did::new("did:test:owner"),
            prev_hash: None,
            revocation_key: RevocationKey::default(),
        }
    }

    #[test]
    fn request_wire_bound_caps_envelope_count() {
        let mut req = ArchiveRequest {
            recording_id: RecordingId::new("rec"),
            envelopes: (0..(ArchiveRequest::MAX_ENVELOPES as u32 + 50))
                .map(envelope)
                .collect(),
            sender_did: Did::new("did:test:owner"),
            signature: vec![0u8; 200],
        };
        req.enforce_wire_bounds();
        assert_eq!(req.envelopes.len(), ArchiveRequest::MAX_ENVELOPES);
        assert_eq!(req.signature.len(), 64);
    }

    #[test]
    fn request_signing_bytes_are_deterministic_and_content_bound() {
        let req = ArchiveRequest {
            recording_id: RecordingId::new("rec"),
            envelopes: vec![envelope(1), envelope(2)],
            sender_did: Did::new("did:test:owner"),
            signature: vec![],
        };
        let a = req.signing_bytes();
        let b = req.signing_bytes();
        assert_eq!(a, b);

        // A different envelope set must change the signing bytes.
        let mut req2 = req.clone();
        req2.envelopes = vec![envelope(1), envelope(9)];
        assert_ne!(req.signing_bytes(), req2.signing_bytes());
    }

    #[test]
    fn receipt_wire_bound_caps_signature_on_stored_only() {
        let mut stored = ArchiveReceipt::Stored {
            recording_id: RecordingId::new("rec"),
            replica_did: Did::new("did:test:replica"),
            stored_at: PhalanxTimestamp::from_millis(10),
            held_until: PhalanxTimestamp::from_millis(20),
            envelope_count: 3,
            signature: vec![7u8; 128],
        };
        stored.enforce_wire_bounds();
        if let ArchiveReceipt::Stored { signature, .. } = &stored {
            assert_eq!(signature.len(), 64);
        } else {
            panic!("expected Stored");
        }

        // Non-Stored variants are a no-op.
        let mut busy = ArchiveReceipt::Busy;
        busy.enforce_wire_bounds();
    }

    #[test]
    fn receipt_signing_bytes_bind_all_fields() {
        let base = ArchiveReceipt::stored_signing_bytes(
            &RecordingId::new("rec"),
            &Did::new("did:test:replica"),
            PhalanxTimestamp::from_millis(10),
            PhalanxTimestamp::from_millis(20),
            3,
        );
        // Changing held_until must change the bytes (no receipt-deadline forgery).
        let moved = ArchiveReceipt::stored_signing_bytes(
            &RecordingId::new("rec"),
            &Did::new("did:test:replica"),
            PhalanxTimestamp::from_millis(10),
            PhalanxTimestamp::from_millis(999),
            3,
        );
        assert_ne!(base, moved);
    }
}
