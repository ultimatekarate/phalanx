// crates/phalanx-forensics/src/cryptography/bridge.rs
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{SigningKey, VerifyingKey};
use phalanx_proto::crypto::CryptoError;
use phalanx_proto::prelude::Did;
use sha2::{Digest, Sha512};

/// THE BRIDGE VERB: Ed25519 PK -> X25519 PK
pub fn ed_to_x25519_pk(ed_key: &VerifyingKey) -> Result<[u8; 32], CryptoError> {
    // FIX: Extract bytes using the dalek API
    let bytes = ed_key.to_bytes();

    let ed_point =
        CompressedEdwardsY::from_slice(&bytes).map_err(|_| CryptoError::DidResolutionFailure)?;

    let mont_point = ed_point
        .decompress()
        .ok_or(CryptoError::DidResolutionFailure)?
        .to_montgomery();

    Ok(mont_point.to_bytes())
}

/// THE BRIDGE VERB: Ed25519 SK -> X25519 SK
pub fn ed_to_x25519_sk(ed_key: &SigningKey) -> Result<x25519_dalek::StaticSecret, CryptoError> {
    let mut hasher = Sha512::new();
    // FIX: Pass the bytes, not the struct reference
    hasher.update(ed_key.to_bytes());
    let hash_result = hasher.finalize();

    let x25519_bytes: [u8; 32] = hash_result[0..32]
        .try_into()
        .map_err(|_| CryptoError::EncodingError("Scalar derivation failed".into()))?;

    Ok(x25519_dalek::StaticSecret::from(x25519_bytes))
}

/// Mock resolution for the DID-to-Key mapping.
/// In a live system, this queries the Kademlia DHT or a local TrustRegistry.
pub fn resolve_did_pk(did: &Did) -> Result<VerifyingKey, CryptoError> {
    // FIX: Mock logic that compiles until you hook up your DHT
    let did_str = did.as_ref();
    if did_str.starts_with("did:key:z") {
        Err(CryptoError::DidResolutionFailure)
    } else {
        Err(CryptoError::DidResolutionFailure)
    }
}
