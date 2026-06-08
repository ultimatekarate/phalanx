// crates/phalanx-forensics/src/archive.rs
//
// The Custody Verbs (Laboratory): sign and verify the archive PUSH request and
// the Stronghold's custody receipt. Pure crypto over the canonical byte layouts
// defined on the proto Nouns — no IO.

use ed25519_dalek::{Signature, Signer, Verifier};
use phalanx_proto::archive::{ArchiveReceipt, ArchiveRequest, ExportReceipt};
use phalanx_proto::crypto::SealedLocator;
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
    build_archive_request_with_grant(identity, recording_id, envelopes, None)
}

/// Like [`build_archive_request`] but carries an **export grant** — a
/// `SealedLocator` sealed to the archival peer's DID authorizing it to decrypt
/// and export this recording (escrow-for-export). The grant is bound into the
/// signature via [`ArchiveRequest::signing_bytes`], so it cannot be stripped or
/// substituted in flight.
#[must_use]
pub fn build_archive_request_with_grant(
    identity: &PhalanxIdentity,
    recording_id: RecordingId,
    envelopes: Vec<WitnessEnvelope>,
    grant: Option<SealedLocator>,
) -> ArchiveRequest {
    let mut req = ArchiveRequest {
        recording_id,
        envelopes,
        sender_did: identity.did.clone(),
        grant,
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

/// Builds a signed `ExportReceipt` from the exporting Stronghold's identity,
/// attesting that `recording_id` was exported to durable storage as the
/// artifact hashing to `artifact_hash`.
#[must_use]
pub fn build_export_receipt(
    identity: &PhalanxIdentity,
    recording_id: RecordingId,
    artifact_hash: [u8; 32],
    exported_at: PhalanxTimestamp,
) -> ExportReceipt {
    let exported_by = identity.did.clone();
    let bytes =
        ExportReceipt::signing_bytes(&recording_id, &artifact_hash, exported_at, &exported_by);
    let sig = identity.keypair.sign(&bytes);
    ExportReceipt {
        recording_id,
        artifact_hash,
        exported_at,
        exported_by,
        signature: sig.to_bytes().to_vec(),
    }
}

/// Verifies an `ExportReceipt`'s self-signature against `exported_by`.
#[must_use]
pub fn verify_export_receipt(receipt: &ExportReceipt) -> bool {
    let Ok(verifying_key) = resolve_did_pk(&receipt.exported_by) else {
        return false;
    };
    let Ok(sig_bytes) = <[u8; 64]>::try_from(receipt.signature.as_slice()) else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_bytes);
    let bytes = ExportReceipt::signing_bytes(
        &receipt.recording_id,
        &receipt.artifact_hash,
        receipt.exported_at,
        &receipt.exported_by,
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

    fn grant(export: bool) -> SealedLocator {
        use phalanx_proto::crypto::GrantPermissions;
        SealedLocator {
            target: RecordingId::new("rec"),
            recipient: Did::new("did:test:stronghold"),
            sender: Did::new("did:test:owner"),
            sealed_key: vec![1u8; 48],
            nonce: vec![2u8; 24],
            permissions: GrantPermissions {
                playback: false,
                export,
            },
        }
    }

    #[test]
    fn request_with_grant_roundtrips_and_verifies() {
        let id = PhalanxIdentity::new_ephemeral();
        let req = build_archive_request_with_grant(
            &id,
            RecordingId::new("rec"),
            vec![],
            Some(grant(true)),
        );
        assert!(verify_archive_request(&req));
    }

    #[test]
    fn request_grant_strip_fails_verification() {
        // A MITM that drops the grant (some → none) must break the signature.
        let id = PhalanxIdentity::new_ephemeral();
        let mut req = build_archive_request_with_grant(
            &id,
            RecordingId::new("rec"),
            vec![],
            Some(grant(true)),
        );
        req.grant = None;
        assert!(!verify_archive_request(&req));
    }

    #[test]
    fn request_grant_substitute_fails_verification() {
        // Swapping the grant for a different one must break the signature.
        let id = PhalanxIdentity::new_ephemeral();
        let mut req = build_archive_request_with_grant(
            &id,
            RecordingId::new("rec"),
            vec![],
            Some(grant(true)),
        );
        req.grant = Some(grant(false)); // permissions differ
        assert!(!verify_archive_request(&req));
    }

    #[test]
    fn export_receipt_roundtrips_and_verifies() {
        let id = PhalanxIdentity::new_ephemeral();
        let r = build_export_receipt(
            &id,
            RecordingId::new("rec"),
            [7u8; 32],
            PhalanxTimestamp::from_millis(42),
        );
        assert!(verify_export_receipt(&r));
    }

    #[test]
    fn export_receipt_tamper_on_artifact_hash_fails() {
        let id = PhalanxIdentity::new_ephemeral();
        let mut r = build_export_receipt(
            &id,
            RecordingId::new("rec"),
            [7u8; 32],
            PhalanxTimestamp::from_millis(42),
        );
        r.artifact_hash = [8u8; 32];
        assert!(!verify_export_receipt(&r));
    }

    #[test]
    fn export_receipt_signed_by_other_did_fails() {
        let id = PhalanxIdentity::new_ephemeral();
        let mut r = build_export_receipt(
            &id,
            RecordingId::new("rec"),
            [7u8; 32],
            PhalanxTimestamp::from_millis(42),
        );
        r.exported_by = Did::new("did:key:zImPoStEr");
        assert!(!verify_export_receipt(&r));
    }
}
