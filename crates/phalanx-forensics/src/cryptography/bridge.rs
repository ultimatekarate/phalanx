// crates/phalanx-forensics/src/cryptography/bridge.rs

use phalanx_proto::crypto::CryptoError;
use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha512};

/// THE BRIDGE VERB: Ed25519 PK -> X25519 PK
pub fn ed_to_x25519_pk(ed_bytes: &[u8]) -> Result<[u8; 32], CryptoError> {
    let bytes: [u8; 32] = ed_bytes.get(0..32)
        .and_then(|s| s.try_into().ok())
        .ok_or(CryptoError::IdentityResolutionError)?;

    let ed_point = CompressedEdwardsY::from_slice(&bytes)
        .map_err(|_| CryptoError::IdentityResolutionError)?;

    let mont_point = ed_point.decompress()
        .ok_or(CryptoError::IdentityResolutionError)?
        .to_montgomery();

    Ok(mont_point.to_bytes())
}

/// THE BRIDGE VERB: Ed25519 SK -> X25519 SK
pub fn ed_to_x25519_sk(ed_bytes: &[u8]) -> Result<x25519_dalek::StaticSecret, CryptoError> {
    let mut hasher = Sha512::new();
    hasher.update(ed_bytes);
    let hash_result = hasher.finalize();
    
    let x25519_bytes: [u8; 32] = hash_result[0..32].try_into()
        .map_err(|_| CryptoError::EncodingError("Scalar derivation failed".into()))?;

    Ok(x25519_dalek::StaticSecret::from(x25519_bytes))
}

/// Mock resolution for the DID-to-Key mapping.
/// In a live system, this queries the Kademlia DHT or a local TrustRegistry.
pub fn resolve_did_pk(did: &Did) -> Result<VerifyingKey, CryptoError> {
    // Logic to extract public key from 'did:key:z...' format
    // This assumes the multibase-encoded Ed25519 format.
    let pub_bytes = did.resolve_raw_public_key()
        .map_err(|_| CryptoError::DidResolutionFailure)?;
    
    VerifyingKey::from_bytes(&pub_bytes)
        .map_err(|_| CryptoError::DidResolutionFailure)
}