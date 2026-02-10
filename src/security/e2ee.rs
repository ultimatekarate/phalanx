/// Keep cryptography logic in here for now.
/// It should probably go in a dedicated file.
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce
};
use std::fmt;

#[derive(Debug)]
pub enum CryptoError {
    EncryptionFailure,
    DecryptionFailure,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for CryptoError {}

/// Generates a random 32-byte key for session encryption.
/// this will eventually be derived from a shared secret (ECDH) or a password.
pub fn generate_session_key() -> [u8; 32] {
    XChaCha20Poly1305::generate_key(&mut OsRng).into()
}

pub fn encrypt_bytes(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng); // 24-bytes (random is safe for XChaCha)
    
    let ciphertext = cipher.encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailure)?;
        
    Ok((nonce.to_vec(), ciphertext))
}

pub fn decrypt_bytes(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let xnonce = XNonce::from_slice(nonce);
    
    cipher.decrypt(xnonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailure)
}

