// crates/phalanx-forensics/src/archive.rs
//
// The Custody Verbs (Laboratory): sign and verify the archive PUSH request and
// the Stronghold's custody receipt. Pure crypto over the canonical byte layouts
// defined on the proto Nouns — no IO.

use ed25519_dalek::{Signature, Signer, Verifier};
use phalanx_proto::archive::{ArchiveReceipt, ArchiveRequest};
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::identity::{PhalanxIdentity, RecordingId};
use phalanx_proto::time::PhalanxTimestamp;

use crate::cryptography::bridge::resolve_did_pk;

/// Builds an `ArchiveRequest` signed by `identity` over its canonical bytes.
/// The pusher attests it is pushing this recording's envelope set; each envelope
/// remains independently owner-signed.
#[must_use]
pub fn build_archive_request(
    identity: &PhalanxIdentity,
    recording_id: RecordingId,
    envelopes: Vec<WitnessEnvelope>,
) -> ArchiveRequest {
    let mut req = ArchiveRequest {
        recording_id,
        envelopes,
        sender_did: identity.did.clone(),
        signature: Vec::new(),
    };
    let sig = identity.keypair.sign(&req.signing_bytes());
    req.signature = sig.to_bytes().to_vec();
    req
}

/// Verifies the pusher's signature on an `ArchiveRequest` against `sender_did`.
#[must_use]
pub fn verify_archive_request(req: &ArchiveRequest) -> bool {
    let Ok(verifying_key) = resolve_did_pk(&req.sender_did) else {
        return false;
    };
    let Ok(sig_bytes) = <[u8; 64]>::try_from(req.signature.as_slice()) else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify(&req.signing_bytes(), &signature)
        .is_ok()
}

/// Builds a signed `ArchiveReceipt::Stored` custody receipt from the replica's
/// identity, committing to hold the recording until `held_until`.
#[must_use]
pub fn build_archive_receipt(
    identity: &PhalanxIdentity,
    recording_id: RecordingId,
    stored_at: PhalanxTimestamp,
    held_until: PhalanxTimestamp,
    envelope_count: u32,
) -> ArchiveReceipt {
    let replica_did = identity.did.clone();
    let bytes = ArchiveReceipt::stored_signing_bytes(
        &recording_id,
        &replica_did,
        stored_at,
        held_until,
        envelope_count,
    );
    let sig = identity.keypair.sign(&bytes);
    ArchiveReceipt::Stored {
        recording_id,
        replica_did,
        stored_at,
        held_until,
        envelope_count,
        signature: sig.to_bytes().to_vec(),
    }
}

/// Verifies a `Stored` receipt's self-signature against `replica_did`.
/// Non-`Stored` variants are rejections, not custody proofs, so they verify
/// to `false`.
#[must_use]
pub fn verify_archive_receipt(receipt: &ArchiveReceipt) -> bool {
    let ArchiveReceipt::Stored {
        recording_id,
        replica_did,
        stored_at,
        held_until,
        envelope_count,
        signature,
    } = receipt
    else {
        return false;
    };
    let Ok(verifying_key) = resolve_did_pk(replica_did) else {
        return false;
    };
    let Ok(sig_bytes) = <[u8; 64]>::try_from(signature.as_slice()) else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_bytes);
    let bytes = ArchiveReceipt::stored_signing_bytes(
        recording_id,
        replica_did,
        *stored_at,
        *held_until,
        *envelope_count,
    );
    verifying_key.verify(&bytes, &signature).is_ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use phalanx_proto::identity::Did;

    #[test]
    fn request_roundtrip_signs_and_verifies() {
        let id = PhalanxIdentity::new_ephemeral();
        let req = build_archive_request(&id, RecordingId::new("rec"), vec![]);
        assert!(verify_archive_request(&req));
    }

    #[test]
    fn request_tamper_fails() {
        let id = PhalanxIdentity::new_ephemeral();
        let mut req = build_archive_request(&id, RecordingId::new("rec"), vec![]);
        req.recording_id = RecordingId::new("other");
        assert!(!verify_archive_request(&req));
    }

    #[test]
    fn receipt_roundtrip_signs_and_verifies() {
        let id = PhalanxIdentity::new_ephemeral();
        let r = build_archive_receipt(
            &id,
            RecordingId::new("rec"),
            PhalanxTimestamp::from_millis(10),
            PhalanxTimestamp::from_millis(20),
            5,
        );
        assert!(verify_archive_receipt(&r));
    }

    #[test]
    fn receipt_tamper_on_held_until_fails() {
        let id = PhalanxIdentity::new_ephemeral();
        let r = build_archive_receipt(
            &id,
            RecordingId::new("rec"),
            PhalanxTimestamp::from_millis(10),
            PhalanxTimestamp::from_millis(20),
            5,
        );
        let ArchiveReceipt::Stored {
            recording_id,
            replica_did,
            stored_at,
            envelope_count,
            signature,
            ..
        } = r
        else {
            panic!("expected Stored");
        };
        // Re-wrap with a forged later deadline but the original signature.
        let forged = ArchiveReceipt::Stored {
            recording_id,
            replica_did,
            stored_at,
            held_until: PhalanxTimestamp::from_millis(9_999),
            envelope_count,
            signature,
        };
        assert!(!verify_archive_receipt(&forged));
    }

    #[test]
    fn non_stored_variants_do_not_verify() {
        assert!(!verify_archive_receipt(&ArchiveReceipt::Busy));
        assert!(!verify_archive_receipt(&ArchiveReceipt::QuotaExceeded));
        assert!(!verify_archive_receipt(&ArchiveReceipt::Rejected));
    }

    #[test]
    fn receipt_signed_by_other_did_fails() {
        let id = PhalanxIdentity::new_ephemeral();
        let r = build_archive_receipt(
            &id,
            RecordingId::new("rec"),
            PhalanxTimestamp::from_millis(10),
            PhalanxTimestamp::from_millis(20),
            5,
        );
        let ArchiveReceipt::Stored {
            recording_id,
            stored_at,
            held_until,
            envelope_count,
            signature,
            ..
        } = r
        else {
            panic!("expected Stored");
        };
        // Claim a different replica DID than the one that signed.
        let impostor = ArchiveReceipt::Stored {
            recording_id,
            replica_did: Did::new("did:key:zImPoStEr"),
            stored_at,
            held_until,
            envelope_count,
            signature,
        };
        assert!(!verify_archive_receipt(&impostor));
    }
}
