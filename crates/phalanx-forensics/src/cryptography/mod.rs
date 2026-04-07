pub mod bridge;
pub mod grant;
pub mod identity;

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use phalanx_proto::crypto::{CryptoError, SymmetricKey};

pub fn generate_session_key() -> SymmetricKey {
    SymmetricKey::from_bytes(XChaCha20Poly1305::generate_key(&mut OsRng).into())
}

pub fn encrypt_bytes(
    key: &SymmetricKey,
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailure)?;

    Ok((nonce.to_vec(), ciphertext))
}

pub fn decrypt_bytes(
    key: &SymmetricKey,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if nonce.len() != 24 {
        return Err(CryptoError::DecryptionFailure);
    }

    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let xnonce = XNonce::from_slice(nonce);

    cipher
        .decrypt(xnonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailure)
}
