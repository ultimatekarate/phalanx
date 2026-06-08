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
use crate::identity::crypto::SealedLocator;
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
    /// Optional **export grant**: a `SealedLocator` sealed to the archival
    /// peer's DID, authorizing it to decrypt this recording and export it to
    /// durable storage (escrow-for-export). `None` = custody-only — the peer
    /// holds ciphertext it cannot export, and the recording ages out at
    /// `held_until`. Bound into [`ArchiveRequest::signing_bytes`], so a MITM
    /// can neither strip nor substitute it without breaking `signature`.
    pub grant: Option<SealedLocator>,
    /// Ed25519 signature by `sender_did` over [`ArchiveRequest::signing_bytes`].
    pub signature: Vec<u8>,
}

impl ArchiveRequest {
    /// Maximum envelope count in a single push (mirrors `RecordingResponse`).
    pub const MAX_ENVELOPES: usize = 256;
    /// Maximum byte length for the Ed25519 signature field.
    const MAX_SIGNATURE_LEN: usize = 64;
    /// Wire cap for a grant's sealed key (a sealed 32-byte DEK + AEAD tag is
    /// ~48 bytes; 256 is generous headroom without enabling amplification).
    const MAX_GRANT_KEY_LEN: usize = 256;
    /// Wire cap for a grant's nonce (XChaCha20 uses 24 bytes).
    const MAX_GRANT_NONCE_LEN: usize = 64;

    /// Canonical bytes the sender signs: `recording_id || sender_did ||
    /// evidence_hash* || grant`. Pure byte concatenation (Dictionary-layer; no
    /// crypto). The trailing grant region is a presence tag (`0` = none, `1` =
    /// some) followed, when present, by the locator's fields — so stripping the
    /// grant (some→none) or substituting a different locator changes the bytes
    /// and invalidates the signature.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.recording_id.0.as_bytes());
        buf.extend_from_slice(self.sender_did.0.as_bytes());
        for env in &self.envelopes {
            buf.extend_from_slice(&env.evidence_hash);
        }
        match &self.grant {
            None => buf.push(0u8),
            Some(g) => {
                buf.push(1u8);
                buf.extend_from_slice(g.target.0.as_bytes());
                buf.extend_from_slice(g.recipient.0.as_bytes());
                buf.extend_from_slice(g.sender.0.as_bytes());
                buf.extend_from_slice(&g.sealed_key);
                buf.extend_from_slice(&g.nonce);
                buf.push(u8::from(g.permissions.playback));
                buf.push(u8::from(g.permissions.export));
            }
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
        // Bound the optional grant so an oversized "grant" can't amplify memory.
        // Truncating a real sealed locator only makes it fail to unlock later
        // (the honest failure mode for a malformed/oversized grant).
        if let Some(g) = &mut self.grant {
            if g.target.0.len() > RecordingId::MAX_WIRE_LEN {
                g.target.0.truncate(RecordingId::MAX_WIRE_LEN);
            }
            if g.recipient.0.len() > Did::MAX_WIRE_LEN {
                g.recipient.0.truncate(Did::MAX_WIRE_LEN);
            }
            if g.sender.0.len() > Did::MAX_WIRE_LEN {
                g.sender.0.truncate(Did::MAX_WIRE_LEN);
            }
            if g.sealed_key.len() > Self::MAX_GRANT_KEY_LEN {
                g.sealed_key.truncate(Self::MAX_GRANT_KEY_LEN);
            }
            if g.nonce.len() > Self::MAX_GRANT_NONCE_LEN {
                g.nonce.truncate(Self::MAX_GRANT_NONCE_LEN);
            }
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

/// A signed attestation that a Stronghold exported `recording_id` to durable
/// storage. Self-verifiable against `exported_by` (like `RevocationToken`): its
/// existence is the durability proof. A *failed* export produces no receipt —
/// absence is the alarm, never a forged "Failed" variant — so this is a plain
/// struct, not an enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportReceipt {
    pub recording_id: RecordingId,
    /// blake3 of the exported artifact bytes (the C2PA MP4) — binds the receipt
    /// to exactly what landed in the sink.
    pub artifact_hash: [u8; 32],
    pub exported_at: PhalanxTimestamp,
    /// DID of the Stronghold that performed and signed the export.
    pub exported_by: Did,
    /// Ed25519 signature by `exported_by` over [`ExportReceipt::signing_bytes`].
    pub signature: Vec<u8>,
}

impl ExportReceipt {
    /// Maximum byte length for the Ed25519 signature field.
    const MAX_SIGNATURE_LEN: usize = 64;

    /// Canonical bytes the exporter signs:
    /// `recording_id || artifact_hash || exported_at || exported_by`.
    /// Pure byte concatenation (Dictionary-layer; no crypto).
    #[must_use]
    pub fn signing_bytes(
        recording_id: &RecordingId,
        artifact_hash: &[u8; 32],
        exported_at: PhalanxTimestamp,
        exported_by: &Did,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(recording_id.0.as_bytes());
        buf.extend_from_slice(artifact_hash);
        buf.extend_from_slice(&exported_at.as_u64().to_le_bytes());
        buf.extend_from_slice(exported_by.0.as_bytes());
        buf
    }
}

impl WireBound for ExportReceipt {
    fn enforce_wire_bounds(&mut self) {
        if self.recording_id.0.len() > RecordingId::MAX_WIRE_LEN {
            self.recording_id.0.truncate(RecordingId::MAX_WIRE_LEN);
        }
        if self.exported_by.0.len() > Did::MAX_WIRE_LEN {
            self.exported_by.0.truncate(Did::MAX_WIRE_LEN);
        }
        if self.signature.len() > Self::MAX_SIGNATURE_LEN {
            self.signature.truncate(Self::MAX_SIGNATURE_LEN);
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
            grant: None,
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
            grant: None,
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

    fn dummy_grant(export: bool) -> SealedLocator {
        SealedLocator {
            target: RecordingId::new("rec"),
            recipient: Did::new("did:test:stronghold"),
            sender: Did::new("did:test:owner"),
            sealed_key: vec![1u8; 48],
            nonce: vec![2u8; 24],
            permissions: crate::identity::crypto::GrantPermissions {
                playback: false,
                export,
            },
        }
    }

    #[test]
    fn signing_bytes_bind_the_grant() {
        let base = ArchiveRequest {
            recording_id: RecordingId::new("rec"),
            envelopes: vec![envelope(1)],
            sender_did: Did::new("did:test:owner"),
            grant: None,
            signature: vec![],
        };
        // Presence flips the bytes (a stripped grant cannot pass the old sig).
        let mut with_grant = base.clone();
        with_grant.grant = Some(dummy_grant(true));
        assert_ne!(base.signing_bytes(), with_grant.signing_bytes());

        // Substituting a *different* grant changes the bytes too.
        let mut other_grant = base.clone();
        other_grant.grant = Some(dummy_grant(false)); // permissions differ
        assert_ne!(with_grant.signing_bytes(), other_grant.signing_bytes());
    }

    #[test]
    fn request_wire_bound_caps_oversized_grant_fields() {
        let mut req = ArchiveRequest {
            recording_id: RecordingId::new("rec"),
            envelopes: vec![],
            sender_did: Did::new("did:test:owner"),
            grant: Some(SealedLocator {
                target: RecordingId::new("rec"),
                recipient: Did::new("did:test:stronghold"),
                sender: Did::new("did:test:owner"),
                sealed_key: vec![0u8; 4096],
                nonce: vec![0u8; 4096],
                permissions: crate::identity::crypto::GrantPermissions::default(),
            }),
            signature: vec![],
        };
        req.enforce_wire_bounds();
        let g = req.grant.expect("grant present");
        assert!(g.sealed_key.len() <= ArchiveRequest::MAX_GRANT_KEY_LEN);
        assert!(g.nonce.len() <= ArchiveRequest::MAX_GRANT_NONCE_LEN);
    }

    #[test]
    fn export_receipt_signing_bytes_bind_all_fields() {
        let base = ExportReceipt::signing_bytes(
            &RecordingId::new("rec"),
            &[3u8; 32],
            PhalanxTimestamp::from_millis(100),
            &Did::new("did:test:stronghold"),
        );
        // A different artifact hash must change the signed bytes.
        let other = ExportReceipt::signing_bytes(
            &RecordingId::new("rec"),
            &[4u8; 32],
            PhalanxTimestamp::from_millis(100),
            &Did::new("did:test:stronghold"),
        );
        assert_ne!(base, other);
    }

    #[test]
    fn export_receipt_wire_bound_caps_signature() {
        let mut r = ExportReceipt {
            recording_id: RecordingId::new("rec"),
            artifact_hash: [0u8; 32],
            exported_at: PhalanxTimestamp::from_millis(1),
            exported_by: Did::new("did:test:stronghold"),
            signature: vec![9u8; 200],
        };
        r.enforce_wire_bounds();
        assert_eq!(r.signature.len(), 64);
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
