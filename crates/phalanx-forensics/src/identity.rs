use phalanx_proto::crypto::CryptoError;
use phalanx_proto::prelude::*;

#[allow(dead_code)]
fn resolve_did_public_key(did: &Did) -> Result<[u8; 32], CryptoError> {
    // 1. Safe Prefix Handling (Zero-Panic)
    // Replaces: let multibase_str = &s["did:key:".len()..];
    let multibase_str = did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or(CryptoError::DidResolutionFailure)?;

    // 2. Safe Multibase Detection
    // Replaces: if !multibase_str.starts_with('z') ... decode(&multibase_str[1..])
    let encoded_key = multibase_str
        .strip_prefix('z')
        .ok_or(CryptoError::DidResolutionFailure)?;

    let bytes = bs58::decode(encoded_key)
        .into_vec()
        .map_err(|_| CryptoError::DidResolutionFailure)?;

    // 3. Safe Multicodec Extraction (Zero-Panic)
    // Replaces: if bytes.len() == 34 && bytes[0] == 0xed ... copy_from_slice(&bytes[2..])
    match bytes.as_slice() {
        [0xed, 0x01, key_bytes @ ..] if key_bytes.len() == 32 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(key_bytes);
            Ok(key)
        }
        _ => Err(CryptoError::DidResolutionFailure),
    }
}
