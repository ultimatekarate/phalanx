// crates/phalanx-forensics/src/evidence/witness.rs

use ed25519_dalek::{Signature, Signer};
use phalanx_proto::evidence::{ChunkType, Evidence, ShardChunk, SignatureHash, WitnessEnvelope};
use phalanx_proto::prelude::ShardError;
use phalanx_proto::prelude::*;
use sha2::{Digest, Sha256};

pub trait WitnessAuthority {
    /// The Verb "To Sign": Anchors evidence into a signed envelope.
    fn sign_envelope(
        evidence: Evidence,
        identity: &PhalanxIdentity,
        peer_id: NetworkId,
        prev_hash: Option<SignatureHash>,
    ) -> Result<WitnessEnvelope, ShardError>;

    /// The Verb "To Verify": Mathematically audits the envelope's integrity.
    fn verify_envelope(&self) -> bool;

    /// The Verb "To Anchor": Generates a unique hash of the signature for timeline chaining.
    fn calculate_anchor(&self) -> SignatureHash;

    /// The Verb "To Chunkify": Slices the envelope for physical transmission.
    fn into_chunks(
        self,
        shard_id: ShardId,
        mtu: usize,
        now: PhalanxTimestamp,
    ) -> Result<Vec<ShardChunk>, ShardError>;
}

impl WitnessAuthority for WitnessEnvelope {
    fn sign_envelope(
        evidence: Evidence,
        identity: &PhalanxIdentity,
        peer_id: NetworkId,
        prev_hash: Option<SignatureHash>,
    ) -> Result<Self, ShardError> {
        let data_to_sign = postcard::to_allocvec(&evidence)?;

        // Compute the fast hash
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, &data_to_sign);
        let evidence_hash: [u8; 32] = hasher.finalize().into();

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
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, &data_bytes);
        let computed_hash: [u8; 32] = hasher.finalize().into();
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
        let mut hasher = Sha256::new();
        hasher.update(&self.witness_signature);
        let result = hasher.finalize();

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        SignatureHash(hash)
    }

    #[allow(clippy::cast_possible_truncation)] // Chunk index as u32 — bounded by MAX_SYMBOLS_PER_CONTEXT.
    fn into_chunks(
        self,
        shard_id: ShardId,
        mtu: usize,
        now: PhalanxTimestamp,
    ) -> Result<Vec<ShardChunk>, ShardError> {
        let owner_did = self.did.clone();

        // Serialize the entire signed envelope
        let full_data = postcard::to_allocvec(&self)?;
        let timestamp = now;

        // Slice into physical MTU-sized chunks
        let slices: Vec<&[u8]> = full_data.chunks(mtu).collect();
        let last_index = slices.len().saturating_sub(1);
        let chunks = slices
            .into_iter()
            .enumerate()
            .map(|(i, slice)| ShardChunk {
                shard_id,
                encoding_symbol_id: phalanx_proto::types::EncodingSymbolId(i as u32),
                chunk_type: ChunkType::Witnessed,
                is_terminal: i == last_index,
                data: slice.to_vec(),
                owner_did: owner_did.clone(),
                timestamp,
            })
            .collect();

        Ok(chunks)
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
            identity.network_id.clone(),
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

    /// The evidence_hash field should match SHA256(serialized evidence).
    #[test]
    fn evidence_hash_is_sha256_of_serialized_evidence() {
        let (env, _) = make_signed_envelope();
        let serialized = postcard::to_allocvec(&env.evidence).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        let expected: [u8; 32] = hasher.finalize().into();
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
