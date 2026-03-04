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
    hasher.update(ed_key.to_bytes());
    let hash_result = hasher.finalize();

    let x25519_bytes: [u8; 32] = hash_result[0..32]
        .try_into()
        .map_err(|_| CryptoError::EncodingError("Scalar derivation failed".into()))?;

    Ok(x25519_dalek::StaticSecret::from(x25519_bytes))
}

/// Resolves a `did:key:z...` DID to an Ed25519 VerifyingKey.
///
/// The DID format is: `did:key:z<bs58(0xed01 ++ ed25519_public_key)>`
/// This function reverses that encoding to recover the public key.
pub fn resolve_did_pk(did: &Did) -> Result<VerifyingKey, CryptoError> {
    let did_str = did.as_ref();
    let multibase_str = did_str
        .strip_prefix("did:key:z")
        .ok_or(CryptoError::DidResolutionFailure)?;

    let decoded = bs58::decode(multibase_str)
        .into_vec()
        .map_err(|_| CryptoError::DidResolutionFailure)?;

    // Expect 2-byte multicodec prefix (0xed, 0x01) + 32-byte Ed25519 public key
    if decoded.len() != 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
        return Err(CryptoError::DidResolutionFailure);
    }

    let key_bytes: [u8; 32] = decoded[2..34]
        .try_into()
        .map_err(|_| CryptoError::DidResolutionFailure)?;

    VerifyingKey::from_bytes(&key_bytes).map_err(|_| CryptoError::DidResolutionFailure)
}
