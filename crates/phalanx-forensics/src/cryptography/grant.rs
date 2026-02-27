// crates/phalanx-forensics/src/cryptography/grants.rs

use phalanx_proto::prelude::*;
use crate::cryptography::bridge::*;
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce};

pub trait GrantAuthority {
    fn seal(
        target: VolleyId,
        key: &[u8; 32],
        sender: &PhalanxIdentity,
        recipient_did: Did,
    ) -> Result<SealedLocator, CryptoError>;

    fn unlock(&self, my_identity: &PhalanxIdentity) -> Result<[u8; 32], CryptoError>;
}

impl GrantAuthority for SealedLocator {
    fn seal(target: VolleyId, key: &[u8; 32], sender: &PhalanxIdentity, recipient_did: Did) -> Result<Self, CryptoError> {
        // 1. Resolve Recipient & Bridge Keys
        let recipient_ed = resolve_did_pk(&recipient_did)?; 
        let recipient_x = x25519_dalek::PublicKey::from(ed_to_x25519_pk(&recipient_ed)?);
        let sender_x = ed_to_x25519_sk(&sender.keypair.to_bytes())?;

        // 2. ECDH + XChaCha20 encryption
        let shared = sender_x.diffie_hellman(&recipient_x);
        let cipher = XChaCha20Poly1305::new(shared.as_bytes().into());
        let nonce_bytes = rand::random::<[u8; 24]>();
        
        let sealed = cipher.encrypt(XNonce::from_slice(&nonce_bytes), Payload {
            msg: key,
            aad: sender.did.as_ref().as_bytes(),
        }).map_err(|_| CryptoError::EncryptionFailure)?;

        Ok(SealedLocator { target, recipient: recipient_did, sender: sender.did.clone(), sealed_key: sealed, nonce: nonce_bytes.to_vec() })
    }

    fn unlock(&self, me: &PhalanxIdentity) -> Result<[u8; 32], CryptoError> {
        // Reverse the ECDH and Decrypt
        // ... (Logic from the original unlock method) ...
    }
}