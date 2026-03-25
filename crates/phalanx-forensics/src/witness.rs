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
