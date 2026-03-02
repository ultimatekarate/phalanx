// crates/phalanx-forensics/src/storage/handover.rs

use crate::judge::JudgeExt;
use ed25519_dalek::Verifier;
use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::prelude::*;
use phalanx_proto::storage::HandoverProof;

pub trait HandoverAuthority {
    fn generate(
        old_identity: &PhalanxIdentity,
        new_identity: &PhalanxIdentity,
        volley_id: VolleyId,
        sequence_id: StorageSequence,
        anchor_hash: SignatureHash,
    ) -> Result<HandoverProof, ShardError>;

    fn verify(&self) -> Result<(), ShardError>;
}

impl HandoverAuthority for HandoverProof {
    fn generate(
        old_identity: &PhalanxIdentity,
        new_identity: &PhalanxIdentity,
        volley_id: VolleyId,
        sequence_id: StorageSequence,
        anchor_hash: SignatureHash,
    ) -> Result<Self, ShardError> {
        // 1. Create deterministic manifest (ordered tuple)
        let transfer_manifest = (
            &volley_id,
            &sequence_id,
            &old_identity.did,
            &new_identity.did,
            &anchor_hash,
        );

        // 2. Serialize Manifest (Using 2026 stable postcard idiom)
        let manifest_bytes = postcard::to_allocvec(&transfer_manifest)
            .map_err(|e| ShardError::SerializationError(e.to_string()))?;

        // 3. Hash with BLAKE3
        let shared_hash = blake3::hash(&manifest_bytes);
        let hash_bytes: [u8; 32] = shared_hash.into();

        // 4. Co-signing: Both identities anchor the transfer
        // Note: We use the signature logic provided by the Laboratory's bridge
        let old_signature = old_identity.sign(&hash_bytes);
        let new_signature = new_identity.sign(&hash_bytes);

        Ok(Self {
            volley_id,
            sequence_id,
            old_did: old_identity.did.clone(),
            new_did: new_identity.did.clone(),
            anchor_hash,
            old_signature,
            new_signature,
        })
    }

    fn verify(&self) -> Result<(), ShardError> {
        // 1. Re-manifest: Reconstruct the exact tuple used during generation
        let transfer_manifest = (
            &self.volley_id,
            &self.sequence_id,
            &self.old_did,
            &self.new_did,
            &self.anchor_hash,
        );

        // 2. Deterministic Serialization
        let manifest_bytes = postcard::to_allocvec(&transfer_manifest)
            .map_err(|e| ShardError::SerializationError(e.to_string()))?;

        // 3. Re-hash
        let shared_hash = blake3::hash(&manifest_bytes);
        let hash_bytes: [u8; 32] = shared_hash.into();

        // 4. Resolve Public Keys from DIDs
        // Assuming your bridge provides a way to extract the Ed25519 public key from a did:key string
        let old_pk = crate::cryptography::bridge::resolve_did_pk(&self.old_did).map_err(|_| {
            ShardError::InvalidConfiguration("Could not resolve old_did".to_string())
        })?;
        let new_pk = crate::cryptography::bridge::resolve_did_pk(&self.new_did).map_err(|_| {
            ShardError::InvalidConfiguration("Could not resolve new_did".to_string())
        })?;

        // 5. Verify Signatures
        old_pk
            .verify(&hash_bytes, &self.old_signature)
            .map_err(|_| {
                ShardError::InvalidConfiguration("Old identity signature mismatch".to_string())
            })?;

        new_pk
            .verify(&hash_bytes, &self.new_signature)
            .map_err(|_| {
                ShardError::InvalidConfiguration("New identity signature mismatch".to_string())
            })?;

        Ok(())
    }
}
