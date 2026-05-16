// crates/phalanx-forensics/src/evidence/witness.rs

use ed25519_dalek::{Signature, Signer};
use phalanx_proto::evidence::{Evidence, SignatureHash, WitnessEnvelope};
use phalanx_proto::prelude::ShardError;
use phalanx_proto::prelude::*;

pub trait WitnessAuthority {
    /// The Verb "To Sign": Anchors evidence into a signed envelope.
    fn sign_envelope(
        evidence: Evidence,
        identity: &PhalanxIdentity,
        peer_id: WitnessId,
        prev_hash: Option<SignatureHash>,
    ) -> Result<WitnessEnvelope, ShardError>;

    /// The Verb "To Verify": Mathematically audits the envelope's integrity.
    fn verify_envelope(&self) -> bool;

    /// The Verb "To Anchor": Generates a unique hash of the signature for timeline chaining.
    fn calculate_anchor(&self) -> SignatureHash;
}

impl WitnessAuthority for WitnessEnvelope {
    fn sign_envelope(
        evidence: Evidence,
        identity: &PhalanxIdentity,
        peer_id: WitnessId,
        prev_hash: Option<SignatureHash>,
    ) -> Result<Self, ShardError> {
        let data_to_sign = postcard::to_allocvec(&evidence)?;

        // Compute the fast hash
        let evidence_hash: [u8; 32] = blake3::hash(&data_to_sign).into();

        // Sign the hash (or data_to_sign)
        let signature = identity.keypair.sign(&data_to_sign);

        Ok(Self {
            evidence,
            evidence_hash,
            witness_peer_id: peer_id,
            witness_signature: signature.to_bytes().to_vec(),
            did: identity.did.clone(),
            prev_hash,
            revocation_key: identity.revocation_key,
        })
    }

    fn verify_envelope(&self) -> bool {
        // Resolve Public Key from DID Noun
        // (Assuming bridge::resolve_did_pk handles the multibase decoding)
        let Ok(verifying_key) = crate::cryptography::bridge::resolve_did_pk(&self.did) else {
            return false;
        };

        // Reconstruct serialized evidence for verification
        let Ok(data_bytes) = postcard::to_allocvec(&self.evidence) else {
            return false;
        };

        // R3-1 FIX: Verify evidence_hash matches the actual evidence content.
        // Without this, an attacker can modify evidence_hash (used for replay
        // detection in the Bloom filter) without invalidating the signature,
        // allowing the same evidence to bypass deduplication.
        let computed_hash: [u8; 32] = blake3::hash(&data_bytes).into();
        if computed_hash != self.evidence_hash {
            return false;
        }

        // Verify Signature
        let Ok(sig_bytes) = self.witness_signature.as_slice().try_into() else {
            return false;
        };
        let signature = Signature::from_bytes(sig_bytes);

        verifying_key.verify_strict(&data_bytes, &signature).is_ok()
    }

    fn calculate_anchor(&self) -> SignatureHash {
        SignatureHash(blake3::hash(&self.witness_signature).into())
    }
}

// ── Adversarial tests ───────────────────────────────────────────────────
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use phalanx_proto::evidence::Evidence;
    use phalanx_proto::identity::{PhalanxIdentity, RecordingId};
    use phalanx_proto::time::{PhalanxTimestamp, SystemClock, TrustedClock};
    use phalanx_test_fixtures::shards::video_shard_for_recording;

    fn make_signed_envelope() -> (WitnessEnvelope, PhalanxIdentity) {
        let identity = PhalanxIdentity::new_ephemeral();
        let rid = RecordingId::new("adversarial-test");
        let shard = video_shard_for_recording(&rid, 0, SystemClock.now());
        let env = WitnessEnvelope::sign_envelope(
            Evidence::Video(shard),
            &identity,
            identity.witness_id.clone(),
            None,
        )
        .expect("signing should succeed");
        (env, identity)
    }

    /// R3-1: A valid envelope should pass verification.
    #[test]
    fn valid_envelope_passes_verification() {
        let (env, _) = make_signed_envelope();
        assert!(env.verify_envelope(), "Valid envelope should verify");
    }

    /// R3-1: Tampering with evidence_hash should cause verification failure.
    /// Before the R3-1 fix, this would pass because the signature was only
    /// checked against the evidence bytes, not the hash field.
    #[test]
    fn tampered_evidence_hash_rejected() {
        let (mut env, _) = make_signed_envelope();

        // Flip every byte of the evidence_hash — signature is still over original evidence
        for byte in &mut env.evidence_hash {
            *byte = byte.wrapping_add(1);
        }

        assert!(
            !env.verify_envelope(),
            "Envelope with tampered evidence_hash must fail verification"
        );
    }

    /// An envelope with a zeroed-out evidence_hash should fail.
    #[test]
    fn zeroed_evidence_hash_rejected() {
        let (mut env, _) = make_signed_envelope();
        env.evidence_hash = [0u8; 32];
        assert!(
            !env.verify_envelope(),
            "Envelope with zeroed evidence_hash must fail"
        );
    }

    /// Tampering with the signature should fail verification.
    #[test]
    fn tampered_signature_rejected() {
        let (mut env, _) = make_signed_envelope();
        if let Some(byte) = env.witness_signature.first_mut() {
            *byte = byte.wrapping_add(1);
        }
        assert!(
            !env.verify_envelope(),
            "Envelope with tampered signature must fail"
        );
    }

    /// Signing with one identity, then swapping the DID to another, should fail.
    #[test]
    fn wrong_did_rejected() {
        let (mut env, _) = make_signed_envelope();
        let impostor = PhalanxIdentity::new_ephemeral();
        env.did = impostor.did;
        assert!(!env.verify_envelope(), "Envelope with wrong DID must fail");
    }

    /// The evidence_hash field should match BLAKE3(serialized evidence).
    #[test]
    fn evidence_hash_is_blake3_of_serialized_evidence() {
        let (env, _) = make_signed_envelope();
        let serialized = postcard::to_allocvec(&env.evidence).unwrap();
        let expected: [u8; 32] = blake3::hash(&serialized).into();
        assert_eq!(env.evidence_hash, expected);
    }

    /// Swapping evidence content (keeping the original hash and signature) should fail.
    #[test]
    fn swapped_evidence_rejected() {
        let (mut env, _identity) = make_signed_envelope();

        // Create different evidence
        let different_shard = video_shard_for_recording(
            &RecordingId::new("different-recording"),
            99,
            PhalanxTimestamp::from_millis(9_999_999_999_999),
        );
        env.evidence = Evidence::Video(different_shard);

        // evidence_hash and signature are from the original evidence — mismatch
        assert!(
            !env.verify_envelope(),
            "Envelope with swapped evidence must fail"
        );
    }
}
